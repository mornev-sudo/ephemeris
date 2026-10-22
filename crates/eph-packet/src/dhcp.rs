//! DHCP (RFC 2131/2132): message parsing and building, and the
//! Ethernet/IPv4/UDP framing around it.
//!
//! DHCP is a control-plane protocol: a handful of packets per client per
//! day. So unlike the rest of this crate it allocates freely and favours
//! clarity over speed.

use crate::{checksum, eth, ipv4, Mac};
use std::net::Ipv4Addr;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

pub const OP_REQUEST: u8 = 1;
pub const OP_REPLY: u8 = 2;
/// "Please answer by broadcast": the client can't receive unicast yet.
pub const FLAG_BROADCAST: u16 = 0x8000;

// Message types (option 53).
pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const DECLINE: u8 = 4;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;
pub const RELEASE: u8 = 7;
pub const INFORM: u8 = 8;

/// A message type's name, for logs: "DISCOVER", "ACK"...
pub fn type_name(t: Option<u8>) -> &'static str {
    match t {
        Some(DISCOVER) => "DISCOVER",
        Some(OFFER) => "OFFER",
        Some(REQUEST) => "REQUEST",
        Some(DECLINE) => "DECLINE",
        Some(ACK) => "ACK",
        Some(NAK) => "NAK",
        Some(RELEASE) => "RELEASE",
        Some(INFORM) => "INFORM",
        Some(_) => "unknown type",
        None => "BOOTP (no type)",
    }
}

// Options (RFC 2132).
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_DOMAIN: u8 = 15;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_MSG_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
/// A text message, e.g. why a server sent a NAK.
pub const OPT_MESSAGE: u8 = 56;
pub const OPT_PARAM_LIST: u8 = 55;
pub const OPT_RENEWAL_TIME: u8 = 58;
pub const OPT_REBINDING_TIME: u8 = 59;
pub const OPT_CLIENT_ID: u8 = 61;
/// Classless static routes (RFC 3442).
pub const OPT_CLASSLESS_ROUTES: u8 = 121;
/// Microsoft's pre-standard copy of option 121, same format.
pub const OPT_MS_CLASSLESS_ROUTES: u8 = 249;
pub const OPT_END: u8 = 255;
pub const OPT_PAD: u8 = 0;

const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// Fixed BOOTP part before the options.
const FIXED_LEN: usize = 236;
/// Some old clients ignore replies shorter than a full BOOTP packet.
const MIN_LEN: usize = 300;

/// A DHCP message, with options kept in order as (code, value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub op: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: Mac,
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Message {
    /// A fresh message with no addresses and no options.
    pub fn new(op: u8, xid: u32, chaddr: Mac) -> Self {
        Message {
            op,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            options: vec![],
        }
    }

    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    pub fn set(&mut self, code: u8, value: Vec<u8>) -> &mut Self {
        self.options.retain(|(c, _)| *c != code);
        self.options.push((code, value));
        self
    }

    pub fn set_ip(&mut self, code: u8, ip: Ipv4Addr) -> &mut Self {
        self.set(code, ip.octets().to_vec())
    }

    pub fn set_ips(&mut self, code: u8, ips: &[Ipv4Addr]) -> &mut Self {
        self.set(code, ips.iter().flat_map(|i| i.octets()).collect())
    }

    pub fn set_u32(&mut self, code: u8, v: u32) -> &mut Self {
        self.set(code, v.to_be_bytes().to_vec())
    }

    pub fn msg_type(&self) -> Option<u8> {
        self.option(OPT_MSG_TYPE).and_then(|v| v.first().copied())
    }

    pub fn ip(&self, code: u8) -> Option<Ipv4Addr> {
        let v = self.option(code)?;
        (v.len() >= 4).then(|| Ipv4Addr::new(v[0], v[1], v[2], v[3]))
    }

    pub fn ips(&self, code: u8) -> Vec<Ipv4Addr> {
        self.option(code)
            .map(|v| {
                v.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| Ipv4Addr::from(*c))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn u32(&self, code: u8) -> Option<u32> {
        let v = self.option(code)?;
        (v.len() == 4).then(|| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    pub fn text(&self, code: u8) -> Option<String> {
        self.option(code).map(|v| {
            String::from_utf8_lossy(v)
                .trim_end_matches('\0')
                .to_string()
        })
    }

    /// Prefix length from the subnet mask option.
    pub fn prefix_len(&self) -> Option<u8> {
        let m = u32::from(self.ip(OPT_SUBNET_MASK)?);
        // Only contiguous masks are valid.
        (m.leading_ones() + m.trailing_zeros() == 32).then(|| m.leading_ones() as u8)
    }

    /// Classless static routes (RFC 3442) from `code` (121, or 249 from
    /// older Microsoft servers): (destination, prefix length, router), with
    /// router 0.0.0.0 meaning "on this link". `None` if absent or malformed:
    /// a malformed option is ignored as a whole, as the RFC asks.
    pub fn classless_routes(&self, code: u8) -> Option<Vec<(Ipv4Addr, u8, Ipv4Addr)>> {
        let v = self.option(code)?;
        let mut out = Vec::new();
        let mut i = 0;
        while i < v.len() {
            let width = v[i];
            if width > 32 {
                return None;
            }
            let sig = (width as usize).div_ceil(8);
            let dest = v.get(i + 1..i + 1 + sig)?;
            let gw = v.get(i + 1 + sig..i + 5 + sig)?;
            let mut d = [0u8; 4];
            d[..sig].copy_from_slice(dest);
            let mask = if width == 0 {
                0
            } else {
                u32::MAX << (32 - width)
            };
            let dest = Ipv4Addr::from(u32::from_be_bytes(d) & mask);
            out.push((dest, width, Ipv4Addr::new(gw[0], gw[1], gw[2], gw[3])));
            i += 5 + sig;
        }
        (!out.is_empty()).then_some(out)
    }

    /// Parse the UDP payload of a DHCP packet.
    pub fn parse(p: &[u8]) -> Option<Message> {
        if p.len() < FIXED_LEN + 4 || p[FIXED_LEN..FIXED_LEN + 4] != MAGIC {
            return None;
        }
        // Ethernet only (htype 1, hlen 6).
        if p[1] != 1 || p[2] != 6 {
            return None;
        }
        let ip = |o: usize| Ipv4Addr::new(p[o], p[o + 1], p[o + 2], p[o + 3]);
        let mut m = Message {
            op: p[0],
            xid: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
            secs: u16::from_be_bytes([p[8], p[9]]),
            flags: u16::from_be_bytes([p[10], p[11]]),
            ciaddr: ip(12),
            yiaddr: ip(16),
            siaddr: ip(20),
            giaddr: ip(24),
            chaddr: p[28..34].try_into().unwrap(),
            options: vec![],
        };
        let mut i = FIXED_LEN + 4;
        while i < p.len() {
            match p[i] {
                OPT_PAD => i += 1,
                OPT_END => break,
                code => {
                    let len = *p.get(i + 1)? as usize;
                    let v = p.get(i + 2..i + 2 + len)?;
                    m.options.push((code, v.to_vec()));
                    i += 2 + len;
                }
            }
        }
        Some(m)
    }

    /// Encode as a UDP payload (padded to the classic 300-byte minimum).
    pub fn encode(&self) -> Vec<u8> {
        let mut p = vec![0u8; FIXED_LEN];
        p[0] = self.op;
        p[1] = 1; // Ethernet
        p[2] = 6;
        p[4..8].copy_from_slice(&self.xid.to_be_bytes());
        p[8..10].copy_from_slice(&self.secs.to_be_bytes());
        p[10..12].copy_from_slice(&self.flags.to_be_bytes());
        p[12..16].copy_from_slice(&self.ciaddr.octets());
        p[16..20].copy_from_slice(&self.yiaddr.octets());
        p[20..24].copy_from_slice(&self.siaddr.octets());
        p[24..28].copy_from_slice(&self.giaddr.octets());
        p[28..34].copy_from_slice(&self.chaddr);
        p.extend_from_slice(&MAGIC);
        // Message type first: some clients expect it.
        let mut opts: Vec<&(u8, Vec<u8>)> = self.options.iter().collect();
        opts.sort_by_key(|(c, _)| *c != OPT_MSG_TYPE);
        for (code, v) in opts {
            // Values over 255 bytes would need splitting (RFC 3396); nothing
            // we send is that long.
            let v = &v[..v.len().min(255)];
            p.push(*code);
            p.push(v.len() as u8);
            p.extend_from_slice(v);
        }
        p.push(OPT_END);
        if p.len() < MIN_LEN {
            p.resize(MIN_LEN, 0);
        }
        p
    }
}

/// The parts of a received DHCP frame the protocol logic needs.
#[derive(Debug, Clone)]
pub struct Received {
    pub src_mac: Mac,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub msg: Message,
}

/// Parse an Ethernet frame carrying DHCP (either direction). Returns `None`
/// for anything else or anything malformed, including a bad UDP checksum.
pub fn parse_frame(f: &[u8]) -> Option<Received> {
    if f.len() < eth::HDR_LEN + ipv4::MIN_HDR_LEN + 8 || eth::ethertype(f) != eth::TYPE_IPV4 {
        return None;
    }
    let ip = &f[eth::HDR_LEN..];
    let h = ipv4::parse(ip).ok()?;
    if h.proto != ipv4::PROTO_UDP || ipv4::is_fragment(ip) {
        return None;
    }
    let udp = ip.get(h.hdr_len..h.total_len)?;
    let (sport, dport) = (
        u16::from_be_bytes([udp[0], udp[1]]),
        u16::from_be_bytes([udp[2], udp[3]]),
    );
    let ulen = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if ulen < 8 || ulen > udp.len() {
        return None;
    }
    let udp = &udp[..ulen];
    let ok_ports = (sport == CLIENT_PORT && dport == SERVER_PORT)
        || (sport == SERVER_PORT && dport == CLIENT_PORT);
    if !ok_ports {
        return None;
    }
    let csum = u16::from_be_bytes([udp[6], udp[7]]);
    if csum != 0 && udp_checksum(h.src, h.dst, udp) != 0 {
        return None;
    }
    Some(Received {
        src_mac: eth::src(f),
        src_ip: h.src,
        dst_ip: h.dst,
        msg: Message::parse(&udp[8..])?,
    })
}

/// Build an Ethernet + IPv4 + UDP frame around `payload`.
pub fn build_frame(
    src_mac: Mac,
    dst_mac: Mac,
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_len = ipv4::MIN_HDR_LEN + udp_len;
    let mut f = vec![0u8; eth::HDR_LEN + ip_len];
    eth::write(&mut f, dst_mac, src_mac, eth::TYPE_IPV4);
    let ip = &mut f[eth::HDR_LEN..];
    ipv4::write_header(ip, ip_len as u16, 0, 64, ipv4::PROTO_UDP, src.0, dst.0);
    // Clear Don't Fragment (write_header sets it) and redo the checksum:
    // DHCP is classically sent without it.
    ip[6] = 0;
    ip[10..12].fill(0);
    let c = checksum::checksum(&ip[..ipv4::MIN_HDR_LEN]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let u = &mut ip[ipv4::MIN_HDR_LEN..];
    u[0..2].copy_from_slice(&src.1.to_be_bytes());
    u[2..4].copy_from_slice(&dst.1.to_be_bytes());
    u[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    u[8..].copy_from_slice(payload);
    let mut c = udp_checksum(src.0, dst.0, u);
    if c == 0 {
        c = 0xffff; // 0 means "no checksum" in UDP
    }
    u[6..8].copy_from_slice(&c.to_be_bytes());
    f
}

/// UDP checksum over the pseudo-header and `udp` (whose checksum field is
/// either 0, when computing, or filled in, when verifying: then the result
/// is 0 for a correct packet).
fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = ipv4::PROTO_UDP;
    pseudo[10..12].copy_from_slice(&(udp.len() as u16).to_be_bytes());
    let acc = checksum::sum(&pseudo, 0);
    !checksum::fold(checksum::sum(udp, acc))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: Mac = [0x02, 0, 0, 0, 0, 0x42];

    #[test]
    fn classless_routes_rfc3442() {
        let mut m = Message::new(OP_REPLY, 1, MAC);
        // The RFC's examples: 0/0 via 10.0.0.1, 10.17.0.0/16 via 10.0.0.2,
        // and 192.0.2.1/32 on-link (router 0.0.0.0).
        m.set(
            OPT_CLASSLESS_ROUTES,
            vec![
                0, 10, 0, 0, 1, //
                16, 10, 17, 10, 0, 0, 2, //
                32, 192, 0, 2, 1, 0, 0, 0, 0,
            ],
        );
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            m.classless_routes(OPT_CLASSLESS_ROUTES),
            Some(vec![
                (ip("0.0.0.0"), 0, ip("10.0.0.1")),
                (ip("10.17.0.0"), 16, ip("10.0.0.2")),
                (ip("192.0.2.1"), 32, ip("0.0.0.0")),
            ])
        );
        // Truncated or a width over 32: the whole option is ignored.
        m.set(OPT_CLASSLESS_ROUTES, vec![24, 10, 1, 2, 10, 0]);
        assert_eq!(m.classless_routes(OPT_CLASSLESS_ROUTES), None);
        m.set(OPT_CLASSLESS_ROUTES, vec![33, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(m.classless_routes(OPT_CLASSLESS_ROUTES), None);
        assert_eq!(m.classless_routes(OPT_MS_CLASSLESS_ROUTES), None);
    }

    #[test]
    fn message_round_trip() {
        let mut m = Message::new(OP_REQUEST, 0xdead_beef, MAC);
        m.flags = FLAG_BROADCAST;
        m.set(OPT_MSG_TYPE, vec![DISCOVER])
            .set_ip(OPT_REQUESTED_IP, Ipv4Addr::new(10, 0, 0, 7))
            .set(OPT_HOSTNAME, b"laptop".to_vec());
        let p = m.encode();
        assert!(p.len() >= MIN_LEN);
        let back = Message::parse(&p).unwrap();
        assert_eq!(back.msg_type(), Some(DISCOVER));
        assert_eq!(back.ip(OPT_REQUESTED_IP), Some(Ipv4Addr::new(10, 0, 0, 7)));
        assert_eq!(back.text(OPT_HOSTNAME).as_deref(), Some("laptop"));
        assert_eq!(back.xid, 0xdead_beef);
        assert_eq!(back.chaddr, MAC);
        assert_eq!(back.flags, FLAG_BROADCAST);
    }

    #[test]
    fn frame_round_trip_with_valid_checksum() {
        let mut m = Message::new(OP_REPLY, 1, MAC);
        m.yiaddr = Ipv4Addr::new(192, 168, 1, 50);
        m.set(OPT_MSG_TYPE, vec![OFFER])
            .set_ip(OPT_SUBNET_MASK, Ipv4Addr::new(255, 255, 255, 0))
            .set_ips(
                OPT_DNS,
                &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)],
            );
        let f = build_frame(
            [2; 6],
            eth::BROADCAST,
            (Ipv4Addr::new(192, 168, 1, 1), SERVER_PORT),
            (Ipv4Addr::BROADCAST, CLIENT_PORT),
            &m.encode(),
        );
        let r = parse_frame(&f).unwrap();
        assert_eq!(r.src_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(r.dst_ip, Ipv4Addr::BROADCAST);
        assert_eq!(r.msg.yiaddr, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(r.msg.prefix_len(), Some(24));
        assert_eq!(r.msg.ips(OPT_DNS).len(), 2);
        // The IP header checksum is valid too.
        assert!(ipv4::parse(&f[eth::HDR_LEN..]).is_ok());
        // A corrupted byte fails the UDP checksum.
        let mut bad = f.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        assert!(parse_frame(&bad).is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Message::parse(&[0u8; 100]).is_none());
        let mut p = Message::new(OP_REQUEST, 1, MAC).encode();
        p[1] = 6; // not Ethernet
        assert!(Message::parse(&p).is_none());
        // An option running past the end.
        let mut p = Message::new(OP_REQUEST, 1, MAC).encode();
        p.truncate(FIXED_LEN + 4);
        p.extend_from_slice(&[OPT_HOSTNAME, 50, b'x']);
        assert!(Message::parse(&p).is_none());
    }

    #[test]
    fn non_contiguous_mask_is_rejected() {
        let mut m = Message::new(OP_REPLY, 1, MAC);
        m.set_ip(OPT_SUBNET_MASK, Ipv4Addr::new(255, 0, 255, 0));
        assert_eq!(m.prefix_len(), None);
    }
}
