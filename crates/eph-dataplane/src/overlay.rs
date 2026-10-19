//! The SD-WAN overlay: tethers to other sites over one or more WAN links,
//! continuously probed, with per-application path selection.
//!
//! On the wire, an overlay packet is the original IP packet behind a small
//! encapsulation, sent as UDP between the two routers' WAN addresses. The
//! payload is encrypted and everything after the UDP header is
//! authenticated with ChaCha20-Poly1305 (RFC 8439) under the tether's
//! pre-shared key:
//!
//! ```text
//! | Ethernet | IPv4 (WAN → WAN) | UDP (→ 4800) | Ephemeris (16) | encrypted IP packet ... | tag (16) |
//!                                               │
//!   byte 0: version (high nibble, 2) | type (low nibble: 1 data, 2 probe, 3 probe reply)
//!   byte 1: application class (data)
//!   bytes 2-3: sender's site id
//!   bytes 4-5: sender's tether id
//!   byte 6: sender's worker
//!   byte 7: reserved (0)
//!   bytes 8-15: counter: run (16 bits) | packet number (48 bits)
//! ```
//!
//! The whole 16-byte header is the AEAD's associated data, so none of it can
//! be changed in transit. The nonce is (sender site, sender worker, counter):
//! the two sites of a tether share its key but have different site ids, each
//! worker counts on its own, and the *run* is a number the router persists
//! and raises every time it starts (see ephemerisd), so a nonce is never used
//! twice under one key, not even across restarts.
//!
//! The receiver accepts each counter once ([`ReplayGuard`]): a captured
//! packet replayed later, or one from an earlier run, is dropped.
//!
//! Probes carry a sequence number and the sender's timestamp; the far side
//! echoes them, so the sender measures round-trip time, jitter and loss per
//! tether, i.e. per WAN path. They are sealed like data, so path health
//! can't be faked either.

use crate::config::PortId;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Mutex;

pub type TetherId = u16;

pub const HDR_LEN: usize = 16;
pub const VERSION: u8 = 2;
pub const TYPE_DATA: u8 = 1;
pub const TYPE_PROBE: u8 = 2;
pub const TYPE_PROBE_REPLY: u8 = 3;
/// Probe payload: sequence number (4) + sender timestamp in ns (8).
pub const PROBE_LEN: usize = 12;
/// Everything in front of the inner IP packet: Ethernet + IPv4 + UDP + ours.
pub const OUTER_LEN: usize = 14 + 20 + 8 + HDR_LEN;
/// The authentication tag after the encrypted payload.
pub const TAG_LEN: usize = 16;
/// Default largest inner packet: a 1500-byte underlay MTU minus IPv4, UDP,
/// our header and the tag.
pub const DEFAULT_MTU: u16 = 1500 - 20 - 8 - HDR_LEN as u16 - TAG_LEN as u16;
/// Packet numbers per worker per run (48 bits).
pub const COUNTER_LIMIT: u64 = 1 << 48;
/// Sender workers the receiver keeps replay state for (worker ids are a byte).
pub const MAX_SENDER_WORKERS: usize = 256;
/// Probe interval; a tether with no reply for `DOWN_AFTER_NS` is down.
pub const PROBE_INTERVAL_NS: u64 = 200_000_000;
pub const DOWN_AFTER_NS: u64 = 1_000_000_000;

/// Where tethers to peers without a fixed address send: learned from the
/// peer's authenticated packets (its address and UDP port, so a peer behind
/// NAT works too). One slot per tether, shared by all workers.
pub struct Endpoints {
    slots: Vec<std::sync::atomic::AtomicU64>,
}

impl Endpoints {
    const KNOWN: u64 = 1 << 48;

    pub fn new(tethers: usize) -> Self {
        Endpoints {
            slots: (0..tethers)
                .map(|_| std::sync::atomic::AtomicU64::new(0))
                .collect(),
        }
    }

    pub fn get(&self, tether: TetherId) -> Option<(Ipv4Addr, u16)> {
        let v = self
            .slots
            .get(tether as usize)?
            .load(std::sync::atomic::Ordering::Relaxed);
        (v & Self::KNOWN != 0).then(|| (Ipv4Addr::from((v >> 16) as u32), v as u16))
    }

    /// Remember where the peer was last heard from. Only ever called after
    /// the packet was authenticated.
    pub fn learn(&self, tether: TetherId, ip: Ipv4Addr, port: u16) {
        if let Some(s) = self.slots.get(tether as usize) {
            let v = Self::KNOWN | (u32::from(ip) as u64) << 16 | port as u64;
            if s.load(std::sync::atomic::Ordering::Relaxed) != v {
                s.store(v, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// One overlay path: a WAN interface plus the far router's WAN address.
#[derive(Debug, Clone, PartialEq)]
pub struct Tether {
    pub id: TetherId,
    pub name: String,
    /// The local WAN port it leaves from.
    pub port: PortId,
    /// The far router's WAN address. Unspecified (0.0.0.0): the peer has no
    /// fixed address; it's learned from the peer's packets ([`Endpoints`]).
    pub remote: Ipv4Addr,
    /// Underlay next hop, if the far end isn't on the same link.
    pub gateway: Option<Ipv4Addr>,
    pub peer_site: u16,
    /// Index of `peer_site` in [`Overlay::sites`].
    pub site_idx: usize,
    /// Pre-shared key, the same at both ends. `None`: the tether has no key
    /// configured and stays down (never sends, accepts nothing).
    pub key: Option<TetherKey>,
}

/// An application class and its path policy. Class 0 is "default" and
/// matches everything the others don't.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Class {
    pub name: String,
    pub proto: Option<u8>,
    /// Inclusive destination (server) port range.
    pub ports: Option<(u16, u16)>,
    pub dscp: Option<u8>,
    /// Tethers in order of preference; empty = lowest latency first.
    pub prefer: Vec<TetherId>,
    /// SLA: a path is only "good enough" within these limits.
    pub max_latency_ms: Option<u32>,
    pub max_jitter_ms: Option<u32>,
    pub max_loss_pct: Option<f32>,
}

impl Class {
    fn matches(&self, proto: u8, dport: u16, dscp: u8) -> bool {
        self.proto.is_none_or(|p| p == proto)
            && self.ports.is_none_or(|(lo, hi)| (lo..=hi).contains(&dport))
            && self.dscp.is_none_or(|d| d == dscp)
    }
}

/// Static overlay configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Overlay {
    pub site_id: u16,
    pub udp_port: u16,
    /// Largest inner IP packet that fits in one underlay packet.
    pub mtu: u16,
    /// May traffic arriving from other sites start sessions here?
    pub allow_new_sessions: bool,
    /// Peer site ids (index = site_idx).
    pub sites: Vec<u16>,
    pub tethers: Vec<Tether>,
    /// classes[0] is the default class.
    pub classes: Vec<Class>,
}

impl Overlay {
    pub fn disabled() -> Self {
        Overlay {
            site_id: 0,
            udp_port: 4800,
            mtu: DEFAULT_MTU,
            allow_new_sessions: true,
            sites: vec![],
            tethers: vec![],
            classes: vec![Class {
                name: "default".into(),
                ..Default::default()
            }],
        }
    }

    pub fn enabled(&self) -> bool {
        !self.tethers.is_empty()
    }

    /// Which application class a packet (or a session's first packet) is in.
    pub fn classify(&self, proto: u8, dport: u16, dscp: u8) -> u8 {
        self.classes
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, c)| c.matches(proto, dport, dscp))
            .map_or(0, |(i, _)| i as u8)
    }
}

/// A tether's 256-bit pre-shared key. Printing it (logs, debug output) never
/// shows the key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TetherKey(pub [u8; 32]);

impl fmt::Debug for TetherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TetherKey(redacted)")
    }
}

impl TetherKey {
    fn nonce(sender_site: u16, worker: u8, counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0..2].copy_from_slice(&sender_site.to_be_bytes());
        n[2] = worker;
        n[4..12].copy_from_slice(&counter.to_be_bytes());
        n
    }

    /// Encrypt `payload` in place, authenticating `hdr` too; returns the tag.
    /// `hdr` holds the sender's site, worker and counter (see the module docs).
    pub fn seal(&self, hdr: &[u8; HDR_LEN], payload: &mut [u8]) -> [u8; TAG_LEN] {
        let (site, worker, counter) = header_nonce_parts(hdr);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let nonce = Self::nonce(site, worker, counter);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), hdr, payload)
            .expect("payload within the AEAD's size limit");
        tag.into()
    }

    /// Check `tag` and decrypt `payload` in place. On failure the payload is
    /// left untouched and must be dropped.
    pub fn open(&self, hdr: &[u8; HDR_LEN], payload: &mut [u8], tag: &[u8]) -> bool {
        if tag.len() != TAG_LEN {
            return false;
        }
        let (site, worker, counter) = header_nonce_parts(hdr);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let nonce = Self::nonce(site, worker, counter);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                hdr,
                payload,
                Tag::from_slice(tag),
            )
            .is_ok()
    }
}

fn header_nonce_parts(hdr: &[u8; HDR_LEN]) -> (u16, u8, u64) {
    let site = u16::from_be_bytes([hdr[2], hdr[3]]);
    let counter = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
    (site, hdr[6], counter)
}

/// Replay protection for received overlay packets, shared by all workers
/// (a peer's packets can arrive on any of them). One sliding window per
/// sending (site, worker): each counter is accepted once, and anything more
/// than [`REPLAY_WINDOW`] packets behind the newest, or from an older run, is
/// refused.
pub struct ReplayGuard {
    windows: Vec<Mutex<Window>>,
}

/// How far behind the newest packet a late (reordered) one may be.
pub const REPLAY_WINDOW: u64 = 1024;

#[derive(Default)]
struct Window {
    run: u16,
    /// Newest packet number seen in `run`.
    top: u64,
    started: bool,
    /// Bit `n % REPLAY_WINDOW` set: packet `n` seen.
    seen: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl Window {
    fn bit(n: u64) -> (usize, u64) {
        let i = n % REPLAY_WINDOW;
        ((i / 64) as usize, 1 << (i % 64))
    }

    fn begin(&mut self, run: u16, n: u64) {
        *self = Window {
            run,
            top: n,
            started: true,
            seen: Default::default(),
        };
        let (w, b) = Self::bit(n);
        self.seen[w] |= b;
    }

    fn accept(&mut self, run: u16, n: u64) -> bool {
        if run < self.run {
            return false;
        }
        if run > self.run || !self.started {
            self.begin(run, n);
            return true;
        }
        if n > self.top {
            let ahead = n - self.top;
            if ahead >= REPLAY_WINDOW {
                self.seen = Default::default();
            } else {
                // Forget the slots the window slides over.
                for k in self.top + 1..n {
                    let (w, b) = Self::bit(k);
                    self.seen[w] &= !b;
                }
            }
            self.top = n;
            let (w, b) = Self::bit(n);
            self.seen[w] |= b;
            return true;
        }
        if self.top - n >= REPLAY_WINDOW {
            return false;
        }
        let (w, b) = Self::bit(n);
        if self.seen[w] & b != 0 {
            return false;
        }
        self.seen[w] |= b;
        true
    }
}

impl ReplayGuard {
    pub fn new(sites: usize) -> Self {
        ReplayGuard {
            windows: (0..sites * MAX_SENDER_WORKERS)
                .map(|_| Mutex::new(Window::default()))
                .collect(),
        }
    }

    fn window(&self, site_idx: usize, worker: u8) -> Option<&Mutex<Window>> {
        self.windows
            .get(site_idx * MAX_SENDER_WORKERS + worker as usize)
    }

    /// Accept `counter` from `worker` at site `site_idx`, once. Only call it
    /// for packets that authenticated, so forged ones can't move the window.
    pub fn accept(&self, site_idx: usize, worker: u8, counter: u64) -> bool {
        let Some(w) = self.window(site_idx, worker) else {
            return false;
        };
        let run = (counter >> 48) as u16;
        let n = counter & (COUNTER_LIMIT - 1);
        w.lock().unwrap_or_else(|e| e.into_inner()).accept(run, n)
    }

    /// The newest run seen from each (site index, worker) that has sent
    /// anything, so a restarted router can refuse older runs.
    pub fn runs(&self) -> Vec<(usize, u8, u16)> {
        self.windows
            .iter()
            .enumerate()
            .filter_map(|(i, w)| {
                let w = w.lock().unwrap_or_else(|e| e.into_inner());
                w.started.then(|| {
                    let site = i / MAX_SENDER_WORKERS;
                    (site, (i % MAX_SENDER_WORKERS) as u8, w.run)
                })
            })
            .collect()
    }

    /// Refuse runs older than `run` from this sender (restored after a
    /// restart). Packets of `run` itself are still accepted.
    pub fn restore(&self, site_idx: usize, worker: u8, run: u16) {
        if let Some(w) = self.window(site_idx, worker) {
            let mut w = w.lock().unwrap_or_else(|e| e.into_inner());
            if !w.started && run > w.run {
                w.run = run;
            }
        }
    }
}

/// Which tether each (site, class) uses right now. Built by the control plane
/// from probe results; swapped into workers like a FIB.
#[derive(Debug, Clone, PartialEq)]
pub struct PathTable {
    pub gen: u64,
    /// choice[site_idx][class]
    pub choice: Vec<Vec<Option<TetherId>>>,
}

impl PathTable {
    pub fn empty(o: &Overlay) -> Self {
        PathTable {
            gen: 0,
            choice: vec![vec![None; o.classes.len()]; o.sites.len()],
        }
    }

    #[inline]
    pub fn get(&self, site_idx: usize, class: u8) -> Option<TetherId> {
        self.choice
            .get(site_idx)?
            .get(class as usize)
            .copied()
            .flatten()
    }
}

/// Per-worker, per-tether counters and probe measurements.
#[derive(Debug, Clone, Copy, Default)]
pub struct TetherStats {
    pub probes_sent: u64,
    pub replies: u64,
    pub last_reply_ns: u64,
    /// Smoothed round-trip time (EWMA, 1/8 weight like TCP's SRTT).
    pub rtt_ns: u64,
    /// Smoothed variation between consecutive RTTs (RFC 3550 style).
    pub jitter_ns: u64,
    pub last_rtt_ns: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

impl TetherStats {
    pub fn record_rtt(&mut self, rtt: u64, now: u64) {
        if self.replies == 0 {
            self.rtt_ns = rtt;
        } else {
            self.rtt_ns = (self.rtt_ns * 7 + rtt) / 8;
            self.jitter_ns = (self.jitter_ns * 15 + rtt.abs_diff(self.last_rtt_ns)) / 16;
        }
        self.last_rtt_ns = rtt;
        self.last_reply_ns = now;
        self.replies += 1;
    }
}

/// A tether's health as the control plane sees it (merged across workers).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TetherHealth {
    pub up: bool,
    pub rtt_ns: u64,
    pub jitter_ns: u64,
    pub loss_pct: f32,
}

impl TetherHealth {
    fn meets(&self, c: &Class) -> bool {
        self.up
            && c.max_latency_ms
                .is_none_or(|m| self.rtt_ns <= m as u64 * 1_000_000)
            && c.max_jitter_ms
                .is_none_or(|m| self.jitter_ns <= m as u64 * 1_000_000)
            && c.max_loss_pct.is_none_or(|m| self.loss_pct <= m)
    }
}

/// The SD-WAN decision: for every site and application class, which tether.
///
/// 1. Candidates are the tethers to that site that are up, ordered by the
///    class's preference list (or by latency if it has none).
/// 2. Pick the first one that meets the class's SLA; if none does, the best
///    available one ("best effort") rather than nothing.
/// 3. Hysteresis: keep the previous choice while it still meets the SLA and
///    is about as good, so sessions don't flap between paths on every small
///    change in latency.
pub fn select_paths(o: &Overlay, health: &[TetherHealth], prev: &PathTable) -> PathTable {
    let mut out = PathTable::empty(o);
    out.gen = prev.gen;
    for (site_idx, row) in out.choice.iter_mut().enumerate() {
        for (class_idx, slot) in row.iter_mut().enumerate() {
            let class = &o.classes[class_idx];
            let mut cands: Vec<&Tether> = o
                .tethers
                .iter()
                .filter(|t| t.site_idx == site_idx && health[t.id as usize].up)
                .collect();
            let rank = |t: &Tether| {
                class
                    .prefer
                    .iter()
                    .position(|&p| p == t.id)
                    .unwrap_or(usize::MAX)
            };
            cands.sort_by_key(|t| (rank(t), health[t.id as usize].rtt_ns));
            let best = cands
                .iter()
                .find(|t| health[t.id as usize].meets(class))
                .or(cands.first())
                .map(|t| t.id);
            let keep = prev.get(site_idx, class_idx as u8).filter(|&p| {
                let (Some(b), Some(pt)) = (best, o.tethers.get(p as usize)) else {
                    return false;
                };
                let (hp, hb) = (health[p as usize], health[b as usize]);
                hp.meets(class)
                    && rank(pt) <= rank(&o.tethers[b as usize])
                    && hp.rtt_ns <= hb.rtt_ns + hb.rtt_ns / 5 + 2_000_000
            });
            *slot = keep.or(best);
        }
    }
    if out.choice != prev.choice {
        out.gen = prev.gen + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(run: u16, n: u64) -> u64 {
        (run as u64) << 48 | n
    }

    #[test]
    fn replay_window_accepts_each_counter_once() {
        let g = ReplayGuard::new(1);
        assert!(g.accept(0, 0, c(1, 10)));
        assert!(!g.accept(0, 0, c(1, 10)), "duplicate");
        assert!(g.accept(0, 0, c(1, 12)));
        assert!(g.accept(0, 0, c(1, 11)), "late but within the window");
        assert!(!g.accept(0, 0, c(1, 11)));
        assert!(g.accept(0, 0, c(1, 12 + REPLAY_WINDOW)));
        assert!(!g.accept(0, 0, c(1, 12)), "too far behind");
        // 11 + WINDOW shares a slot with 11, which was seen: the slot was
        // cleared when the window moved past it.
        assert!(
            g.accept(0, 0, c(1, 11 + REPLAY_WINDOW)),
            "slot reused for a new number"
        );
        assert!(
            !g.accept(0, 0, c(1, 12 + REPLAY_WINDOW)),
            "the top itself, again"
        );
        // Each sending worker counts on its own.
        assert!(g.accept(0, 1, c(1, 10)));
    }

    #[test]
    fn replay_window_follows_runs() {
        let g = ReplayGuard::new(2);
        assert!(g.accept(1, 0, c(3, 500)));
        assert!(
            g.accept(1, 0, c(4, 0)),
            "a restarted sender starts again at 0"
        );
        assert!(!g.accept(1, 0, c(3, 501)), "older run");
        assert_eq!(g.runs(), vec![(1, 0, 4)]);
        // After our own restart: runs below what we saw are refused, even
        // before the sender's first new packet.
        let g = ReplayGuard::new(2);
        g.restore(1, 0, 4);
        assert!(!g.accept(1, 0, c(3, 9)));
        assert!(g.accept(1, 0, c(4, 9)));
        assert!(!g.accept(5, 0, c(4, 9)), "no such site");
    }

    #[test]
    fn keys_never_show_in_debug_output() {
        assert_eq!(
            format!("{:?}", TetherKey([0xab; 32])),
            "TetherKey(redacted)"
        );
    }

    fn overlay() -> Overlay {
        let mut o = Overlay::disabled();
        o.site_id = 1;
        o.sites = vec![2];
        o.tethers = vec![
            Tether {
                id: 0,
                name: "fibre".into(),
                port: 1,
                remote: "192.0.2.2".parse().unwrap(),
                gateway: None,
                peer_site: 2,
                site_idx: 0,
                key: None,
            },
            Tether {
                id: 1,
                name: "lte".into(),
                port: 2,
                remote: "198.51.100.2".parse().unwrap(),
                gateway: None,
                peer_site: 2,
                site_idx: 0,
                key: None,
            },
        ];
        o.classes.push(Class {
            name: "voice".into(),
            proto: Some(17),
            ports: Some((10000, 20000)),
            max_latency_ms: Some(100),
            max_loss_pct: Some(1.0),
            ..Default::default()
        });
        o.classes.push(Class {
            name: "bulk".into(),
            proto: Some(6),
            ports: Some((5201, 5201)),
            prefer: vec![1, 0],
            ..Default::default()
        });
        o
    }

    fn h(up: bool, rtt_ms: u64, loss: f32) -> TetherHealth {
        TetherHealth {
            up,
            rtt_ns: rtt_ms * 1_000_000,
            jitter_ns: 0,
            loss_pct: loss,
        }
    }

    #[test]
    fn classifies_by_protocol_and_port() {
        let o = overlay();
        assert_eq!(o.classify(17, 12000, 0), 1);
        assert_eq!(o.classify(6, 5201, 0), 2);
        assert_eq!(o.classify(6, 443, 0), 0);
        assert_eq!(o.classify(17, 53, 0), 0);
    }

    #[test]
    fn lowest_latency_by_default_and_preference_wins() {
        let o = overlay();
        let p = select_paths(
            &o,
            &[h(true, 5, 0.0), h(true, 50, 0.0)],
            &PathTable::empty(&o),
        );
        assert_eq!(p.get(0, 0), Some(0), "default: lowest latency (fibre)");
        assert_eq!(p.get(0, 2), Some(1), "bulk prefers lte");
        assert_eq!(p.gen, 1);
    }

    #[test]
    fn failover_and_sla() {
        let o = overlay();
        let start = select_paths(
            &o,
            &[h(true, 5, 0.0), h(true, 50, 0.0)],
            &PathTable::empty(&o),
        );
        // Fibre goes down: everything moves to LTE.
        let p = select_paths(&o, &[h(false, 5, 0.0), h(true, 50, 0.0)], &start);
        assert_eq!(
            (p.get(0, 0), p.get(0, 1), p.get(0, 2)),
            (Some(1), Some(1), Some(1))
        );
        assert!(p.gen > start.gen);
        // Fibre up but lossy: voice (SLA 1% loss) avoids it, default doesn't care.
        let p = select_paths(&o, &[h(true, 5, 5.0), h(true, 50, 0.0)], &start);
        assert_eq!(p.get(0, 1), Some(1));
        assert_eq!(p.get(0, 0), Some(0));
        // Both down: no path.
        let p = select_paths(&o, &[h(false, 0, 0.0), h(false, 0, 0.0)], &start);
        assert_eq!(p.get(0, 0), None);
    }

    #[test]
    fn hysteresis_avoids_flapping() {
        let o = overlay();
        let p1 = select_paths(
            &o,
            &[h(true, 10, 0.0), h(true, 11, 0.0)],
            &PathTable::empty(&o),
        );
        assert_eq!(p1.get(0, 0), Some(0));
        // LTE becomes marginally faster: stay on fibre, no new generation.
        let p2 = select_paths(&o, &[h(true, 11, 0.0), h(true, 10, 0.0)], &p1);
        assert_eq!(p2.get(0, 0), Some(0));
        assert_eq!(p2.gen, p1.gen);
        // LTE becomes much faster: switch.
        let p3 = select_paths(&o, &[h(true, 40, 0.0), h(true, 10, 0.0)], &p2);
        assert_eq!(p3.get(0, 0), Some(1));
    }
}
