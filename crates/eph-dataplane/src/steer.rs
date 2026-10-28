//! Which worker a packet lands on, worked out the way the network card does
//! it, so that the router can arrange for replies to land where their
//! session is.
//!
//! A card spreads arriving packets over its receive queues by hashing their
//! addresses and ports (RSS: a Toeplitz hash with the card's secret key),
//! then looking the hash up in its *indirection table*. Worker *w* reads
//! queue *w* of every card. Each worker keeps its own sessions, so both
//! directions of a conversation must land on the same worker.
//!
//! Source NAT breaks that: the reply comes back to the NAT address and
//! port, not to the inside host, so it hashes differently from the request.
//! But the NAT port is ours to choose: [`Steering::queue`] predicts the
//! reply's queue, and the worker picks a port whose reply lands on itself.
//! Nothing is shared and nothing is copied, so throughput grows with
//! workers.
//!
//! Correctness never depends on the prediction. A reply that lands on
//! another worker anyway (ICMP, which is hashed on addresses only; a PPPoE
//! link, which cards can't hash inside; a card whose settings can't be read,
//! or that hashes differently than we think) is handed to the worker that
//! owns it (see `Pipeline::handoffs`): slower, never lost.

use std::net::Ipv4Addr;

/// How one card spreads packets, as read from it (`ethtool -x`, `-n`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardRss {
    /// The Toeplitz key (usually 40 or 52 bytes).
    pub key: Vec<u8>,
    /// Hash (low bits) -> queue.
    pub indir: Vec<u16>,
    /// "symmetric-xor": each source and destination field is replaced by
    /// their XOR first, so both directions hash alike.
    pub symmetric: bool,
    /// Whether ports are part of the hash for TCP and for UDP (else only
    /// the addresses are, and the port choice can't steer).
    pub tcp_ports: bool,
    pub udp_ports: bool,
}

/// The Toeplitz hash of `input` with `key` (Microsoft's RSS definition):
/// for every input bit that's set, XOR in the 32 key bits starting there.
pub fn toeplitz(key: &[u8], input: &[u8]) -> u32 {
    let mut hash = 0u32;
    for (i, &byte) in input.iter().enumerate() {
        for bit in 0..8 {
            if byte & (0x80 >> bit) != 0 {
                hash ^= key_window(key, i * 8 + bit);
            }
        }
    }
    hash
}

/// The 32 key bits starting at bit `at` (zeros past the key's end).
fn key_window(key: &[u8], at: usize) -> u32 {
    let mut w = 0u32;
    for k in 0..32 {
        let b = at + k;
        let set = key.get(b / 8).is_some_and(|&x| x & (0x80 >> (b % 8)) != 0);
        w = (w << 1) | set as u32;
    }
    w
}

/// A card's hash, precomputed: the hash is linear (XOR) in the input bits,
/// so the contribution of each input byte's 256 values is a table lookup.
/// 12 input bytes for IPv4 with ports: source and destination address,
/// source and destination port.
#[derive(Debug, Clone)]
struct Tables {
    bytes: Box<[[u32; 256]; 12]>,
    indir: Vec<u16>,
    symmetric: bool,
    tcp_ports: bool,
    udp_ports: bool,
}

impl Tables {
    fn new(rss: &CardRss) -> Option<Self> {
        if rss.indir.is_empty() || rss.key.len() < 16 {
            return None; // 12 input bytes need 12 + 4 key bytes
        }
        let mut bytes = Box::new([[0u32; 256]; 12]);
        for (pos, table) in bytes.iter_mut().enumerate() {
            let windows: Vec<u32> = (0..8)
                .map(|bit| key_window(&rss.key, pos * 8 + bit))
                .collect();
            for (v, slot) in table.iter_mut().enumerate() {
                *slot = (0..8)
                    .filter(|bit| v & (0x80 >> bit) != 0)
                    .fold(0, |h, bit| h ^ windows[bit]);
            }
        }
        Some(Tables {
            bytes,
            indir: rss.indir.clone(),
            symmetric: rss.symmetric,
            tcp_ports: rss.tcp_ports,
            udp_ports: rss.udp_ports,
        })
    }

    fn hash(&self, src: Ipv4Addr, dst: Ipv4Addr, ports: Option<(u16, u16)>) -> u32 {
        let (s, d) = (u32::from(src), u32::from(dst));
        let (s, d) = if self.symmetric {
            (s ^ d, s ^ d)
        } else {
            (s, d)
        };
        let mut input = [0u8; 12];
        input[0..4].copy_from_slice(&s.to_be_bytes());
        input[4..8].copy_from_slice(&d.to_be_bytes());
        let n = match ports {
            Some((sp, dp)) => {
                let (sp, dp) = if self.symmetric {
                    (sp ^ dp, sp ^ dp)
                } else {
                    (sp, dp)
                };
                input[8..10].copy_from_slice(&sp.to_be_bytes());
                input[10..12].copy_from_slice(&dp.to_be_bytes());
                12
            }
            None => 8,
        };
        input[..n]
            .iter()
            .enumerate()
            .fold(0, |h, (i, &b)| h ^ self.bytes[i][b as usize])
    }
}

/// Every card's spreading, where it could be read.
#[derive(Debug, Clone, Default)]
pub struct Steering {
    /// Per card (index = `Port::card`).
    cards: Vec<Option<Tables>>,
}

impl Steering {
    /// `cards[i]`: card i's settings, or `None` if they couldn't be read
    /// (a virtio NIC without RSS, say). Unusable settings count as unread.
    pub fn new(cards: &[Option<CardRss>]) -> Self {
        Steering {
            cards: cards
                .iter()
                .map(|c| c.as_ref().and_then(Tables::new))
                .collect(),
        }
    }

    /// Can a packet's queue on `card` be predicted, and does the port choice
    /// change it (ports in the hash) for `proto`?
    pub fn steers_ports(&self, card: u16, proto: u8) -> bool {
        self.tables(card).is_some_and(|t| match proto {
            6 => t.tcp_ports,
            17 => t.udp_ports,
            _ => false,
        })
    }

    pub fn knows(&self, card: u16) -> bool {
        self.tables(card).is_some()
    }

    fn tables(&self, card: u16) -> Option<&Tables> {
        self.cards.get(card as usize)?.as_ref()
    }

    /// The queue (= worker) a packet `src:sport -> dst:dport` of `proto`
    /// arrives on at `card`, or `None` if that card's settings are unknown.
    /// Ports count for TCP and UDP if the card hashes them; ICMP and the
    /// rest are hashed on addresses alone.
    pub fn queue(
        &self,
        card: u16,
        proto: u8,
        (src, sport): (Ipv4Addr, u16),
        (dst, dport): (Ipv4Addr, u16),
    ) -> Option<u16> {
        let t = self.tables(card)?;
        let ports = match proto {
            6 if t.tcp_ports => Some((sport, dport)),
            17 if t.udp_ports => Some((sport, dport)),
            _ => None,
        };
        let h = t.hash(src, dst, ports);
        Some(t.indir[h as usize % t.indir.len()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Microsoft's RSS verification key and vectors ("Verifying the RSS
    /// Hash Calculation"): (destination, source, IPv4 hash, with TCP ports).
    const KEY: [u8; 40] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f,
        0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];
    const VECTORS: [(&str, u16, &str, u16, u32, u32); 5] = [
        (
            "161.142.100.80",
            1766,
            "66.9.149.187",
            2794,
            0x323e8fc2,
            0x51ccc178,
        ),
        (
            "65.69.140.83",
            4739,
            "199.92.111.2",
            14230,
            0xd718262a,
            0xc626b0ea,
        ),
        (
            "12.22.207.184",
            38024,
            "24.19.198.95",
            12898,
            0xd2d0a5de,
            0x5c2b394a,
        ),
        (
            "209.142.163.6",
            2217,
            "38.27.205.30",
            48228,
            0x82989176,
            0xafc7327f,
        ),
        (
            "202.188.127.2",
            1303,
            "153.39.163.191",
            44251,
            0x5d1809c5,
            0x10e828a2,
        ),
    ];

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn input(src: &str, dst: &str, ports: Option<(u16, u16)>) -> Vec<u8> {
        let mut v = ip(src).octets().to_vec();
        v.extend(ip(dst).octets());
        if let Some((s, d)) = ports {
            v.extend(s.to_be_bytes());
            v.extend(d.to_be_bytes());
        }
        v
    }

    #[test]
    fn toeplitz_matches_the_published_vectors() {
        for (dst, dport, src, sport, h_ip, h_tcp) in VECTORS {
            assert_eq!(
                toeplitz(&KEY, &input(src, dst, None)),
                h_ip,
                "{src} -> {dst}"
            );
            assert_eq!(
                toeplitz(&KEY, &input(src, dst, Some((sport, dport)))),
                h_tcp,
                "{src}:{sport} -> {dst}:{dport}"
            );
        }
    }

    fn card(symmetric: bool, udp_ports: bool) -> CardRss {
        CardRss {
            key: KEY.to_vec(),
            // 128 entries over 4 queues, round robin: what drivers default to.
            indir: (0..128).map(|i| i % 4).collect(),
            symmetric,
            tcp_ports: true,
            udp_ports,
        }
    }

    #[test]
    fn the_tables_agree_with_the_plain_hash() {
        let t = Tables::new(&card(false, true)).unwrap();
        for (dst, dport, src, sport, h_ip, h_tcp) in VECTORS {
            assert_eq!(t.hash(ip(src), ip(dst), None), h_ip);
            assert_eq!(t.hash(ip(src), ip(dst), Some((sport, dport))), h_tcp);
        }
    }

    #[test]
    fn queues_follow_the_indirection_table() {
        let s = Steering::new(&[Some(card(false, true)), None]);
        let (dst, dport, src, sport, _, h_tcp) = VECTORS[0];
        let q = s.queue(0, 6, (ip(src), sport), (ip(dst), dport));
        assert_eq!(q, Some((h_tcp as usize % 128 % 4) as u16));
        assert_eq!(
            s.queue(1, 6, (ip(src), sport), (ip(dst), dport)),
            None,
            "unknown card"
        );
        assert!(s.steers_ports(0, 6) && s.steers_ports(0, 17) && !s.steers_ports(0, 1));
        assert!(!s.steers_ports(1, 6));
    }

    #[test]
    fn ports_only_count_where_the_card_hashes_them() {
        let s = Steering::new(&[Some(card(false, false))]);
        let a = s.queue(0, 17, (ip("8.8.8.8"), 53), (ip("192.0.2.1"), 40000));
        let b = s.queue(0, 17, (ip("8.8.8.8"), 53), (ip("192.0.2.1"), 40001));
        assert_eq!(a, b, "UDP hashed on addresses only");
        assert!(!s.steers_ports(0, 17));
    }

    #[test]
    fn symmetric_hashing_is_the_same_both_ways() {
        let s = Steering::new(&[Some(card(true, true))]);
        let there = s.queue(0, 6, (ip("10.0.0.5"), 40000), (ip("8.8.8.8"), 443));
        let back = s.queue(0, 6, (ip("8.8.8.8"), 443), (ip("10.0.0.5"), 40000));
        assert_eq!(there, back);
    }

    #[test]
    fn reply_ports_spread_evenly_over_the_queues() {
        // A NAT worker can find a port for itself quickly: about one in four
        // ports lands on each of four queues.
        let s = Steering::new(&[Some(card(false, true))]);
        let mut per_queue = [0u32; 4];
        for port in 1024..9216u16 {
            let q = s
                .queue(0, 17, (ip("8.8.8.8"), 53), (ip("192.0.2.1"), port))
                .unwrap();
            per_queue[q as usize] += 1;
        }
        for n in per_queue {
            assert!((1800..2300).contains(&n), "{per_queue:?}");
        }
    }

    #[test]
    fn settings_that_cant_be_used_count_as_unknown() {
        let mut short = card(false, true);
        short.key.truncate(8);
        let mut empty = card(false, true);
        empty.indir.clear();
        let s = Steering::new(&[Some(short), Some(empty)]);
        assert!(!s.knows(0) && !s.knows(1));
    }
}
