//! Source NAT: making many inside hosts appear as one (or a few) outside
//! addresses.
//!
//! The common case is **PAT** ("port address translation", "masquerade",
//! "NAT overload"): every inside host's connections leave with the outside
//! interface's address, and a different *source port* per connection tells
//! them apart. When a reply comes back to `outside-address:port`, that port
//! leads back to the right inside host and port.
//!
//! The translation is stored in the connection's session (see
//! [`crate::session::NatBinding`]), with the translated 5-tuple as a second
//! key. So NAT costs no extra lookup: the same hash lookup that finds a
//! session also finds its translation, and when the session expires, the
//! port is free again.

use crate::config::{Port, PortId, Role};
use eph_fib::Prefix;
use eph_packet::{checksum, icmp, ipv4};
use std::net::Ipv4Addr;

/// What a rule does with matching traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatAction {
    /// PAT to the outbound interface's own address.
    Interface,
    /// PAT to an address from pool `n`.
    Pool(usize),
    /// Don't translate (e.g. traffic to a partner network over a VPN).
    Exempt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRule {
    pub name: String,
    pub source: Option<Prefix>,
    pub destination: Option<Prefix>,
    pub outbound: Option<PortId>,
    pub action: NatAction,
}

impl NatRule {
    fn matches(&self, src: Ipv4Addr, dst: Ipv4Addr, egress: PortId) -> bool {
        self.source.is_none_or(|p| p.contains(src))
            && self.destination.is_none_or(|p| p.contains(dst))
            && self.outbound.is_none_or(|p| p == egress)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatConfig {
    /// Inside → outside traffic not matched by a rule: PAT to the outside
    /// interface address.
    pub masquerade: bool,
    /// Address pools (each a list of addresses).
    pub pools: Vec<Vec<Ipv4Addr>>,
    /// Checked in order; the first match wins.
    pub rules: Vec<NatRule>,
}

impl Default for NatConfig {
    fn default() -> Self {
        NatConfig {
            masquerade: true,
            pools: vec![],
            rules: vec![],
        }
    }
}

impl NatConfig {
    pub fn off() -> Self {
        NatConfig {
            masquerade: false,
            pools: vec![],
            rules: vec![],
        }
    }

    /// The address a new session from `src` to `dst`, entering on `ingress`
    /// and leaving on `egress`, should appear to come from. None: untranslated.
    pub fn decide(
        &self,
        ports: &[Port],
        ingress: PortId,
        egress: PortId,
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        for r in &self.rules {
            if r.matches(src, dst, egress) {
                return match r.action {
                    NatAction::Interface => Some(ports[egress as usize].addr),
                    NatAction::Pool(i) => pick(&self.pools[i], src),
                    NatAction::Exempt => None,
                };
            }
        }
        let inside_to_outside = ports[ingress as usize].role == Role::Inside
            && ports[egress as usize].role == Role::Outside;
        (self.masquerade && inside_to_outside).then(|| ports[egress as usize].addr)
    }

    /// Is `ip` a pool address the router must answer ARP for?
    pub fn owns(&self, ip: Ipv4Addr) -> bool {
        self.pools.iter().any(|p| p.contains(&ip))
    }
}

/// Keep each inside host on the same pool address for all its sessions
/// ("paired" pooling: some services break if one client's connections come
/// from different addresses).
fn pick(pool: &[Ipv4Addr], src: Ipv4Addr) -> Option<Ipv4Addr> {
    if pool.is_empty() {
        return None;
    }
    let h = u32::from(src).wrapping_mul(0x9e37_79b1);
    Some(pool[(h >> 16) as usize % pool.len()])
}

/// The checksum field (offset within the L4 header) that covers the ports and
/// addresses, if any. UDP's is optional: 0 means "none", leave it alone.
fn l4_checksum_offset(proto: u8, l4: &[u8]) -> Option<usize> {
    match proto {
        ipv4::PROTO_TCP if l4.len() >= 18 => Some(16),
        ipv4::PROTO_UDP if l4.len() >= 8 && (l4[6] != 0 || l4[7] != 0) => Some(6),
        _ => None,
    }
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn wr16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_be_bytes());
}

/// Replace a 32-bit address at `ip[off..off+4]`, patching the IP header
/// checksum and (because of the pseudo-header) the TCP/UDP checksum.
fn set_addr(ip: &mut [u8], hl: usize, off: usize, new: Ipv4Addr) {
    let proto = ip[9];
    let csum_l4 = l4_checksum_offset(proto, &ip[hl..]);
    let n = new.octets();
    for half in 0..2 {
        let o = off + half * 2;
        let old = rd16(ip, o);
        let new = u16::from_be_bytes([n[half * 2], n[half * 2 + 1]]);
        let hc = rd16(ip, 10);
        wr16(ip, 10, checksum::update16(hc, old, new));
        if let Some(c) = csum_l4 {
            let lc = rd16(ip, hl + c);
            wr16(ip, hl + c, checksum::update16(lc, old, new));
        }
        wr16(ip, o, new);
    }
}

/// Replace a port (or ICMP echo identifier), patching the L4 checksum.
fn set_port(ip: &mut [u8], hl: usize, proto: u8, which: Which, new: u16) {
    let (field, csum) = match proto {
        ipv4::PROTO_TCP | ipv4::PROTO_UDP => {
            let f = hl + if which == Which::Src { 0 } else { 2 };
            (f, l4_checksum_offset(proto, &ip[hl..]).map(|c| hl + c))
        }
        // ICMP echo: the identifier plays the port's role in both directions.
        ipv4::PROTO_ICMP
            if ip.len() >= hl + 8 && matches!(ip[hl], icmp::ECHO_REQUEST | icmp::ECHO_REPLY) =>
        {
            (hl + 4, Some(hl + 2))
        }
        _ => return,
    };
    let old = rd16(ip, field);
    if let Some(c) = csum {
        let lc = rd16(ip, c);
        wr16(ip, c, checksum::update16(lc, old, new));
    }
    wr16(ip, field, new);
}

#[derive(PartialEq, Clone, Copy)]
enum Which {
    Src,
    Dst,
}

/// Outbound: make the packet come from `addr:port`. `ip` is exactly the
/// IP packet.
pub fn translate_src(ip: &mut [u8], addr: Ipv4Addr, port: u16) {
    let hl = ((ip[0] & 0x0f) as usize) * 4;
    let proto = ip[9];
    set_port(ip, hl, proto, Which::Src, port);
    set_addr(ip, hl, 12, addr);
}

/// Inbound reply: send the packet back to the original inside `addr:port`.
pub fn translate_dst(ip: &mut [u8], addr: Ipv4Addr, port: u16) {
    let hl = ((ip[0] & 0x0f) as usize) * 4;
    let proto = ip[9];
    set_port(ip, hl, proto, Which::Dst, port);
    set_addr(ip, hl, 16, addr);
}

/// An ICMP error (e.g. Time Exceeded from a router on the internet) about a
/// translated packet: send it to the inside host, and restore the quoted
/// packet's source as that host knows it, or it can't match the error to its
/// connection (and `traceroute` through NAT wouldn't work).
pub fn translate_icmp_error(ip: &mut [u8], addr: Ipv4Addr, port: u16) {
    let hl = ((ip[0] & 0x0f) as usize) * 4;
    let total = rd16(ip, 2) as usize;
    // Outer destination: our outside address -> the inside host. ICMP has no
    // pseudo-header, so only the IP checksum changes.
    set_addr(ip, hl, 16, addr);
    // Quoted packet, starting 8 bytes into the ICMP message.
    let q = hl + icmp::HDR_LEN;
    if total < q + ipv4::MIN_HDR_LEN {
        return;
    }
    let qhl = ((ip[q] & 0x0f) as usize) * 4;
    let quoted = &mut ip[q..total];
    if qhl < ipv4::MIN_HDR_LEN || quoted.len() < qhl {
        return;
    }
    if quoted.len() >= qhl + 4 {
        let proto = quoted[9];
        if matches!(proto, ipv4::PROTO_TCP | ipv4::PROTO_UDP) {
            wr16(quoted, qhl, port); // quoted L4 checksums are often truncated: leave them
        } else if proto == ipv4::PROTO_ICMP && quoted.len() >= qhl + 6 {
            wr16(quoted, qhl + 4, port);
        }
    }
    quoted[12..16].copy_from_slice(&addr.octets());
    quoted[10..12].fill(0);
    let c = checksum::checksum(&quoted[..qhl]);
    wr16(quoted, 10, c);
    // The ICMP checksum covers the quote: recompute it.
    ip[hl + 2..hl + 4].fill(0);
    let c = checksum::checksum(&ip[hl..total]);
    wr16(ip, hl + 2, c);
}

/// An ICMP error an inside host sends about a packet of a translated
/// session (e.g. Port Unreachable for a late reply): it leaves with the
/// outside `addr`, and the quoted packet shows the translated destination
/// the far side used, so the error can be matched to its connection and
/// the inside address doesn't leak.
pub fn translate_icmp_error_out(ip: &mut [u8], addr: Ipv4Addr, port: u16) {
    let hl = ((ip[0] & 0x0f) as usize) * 4;
    let total = rd16(ip, 2) as usize;
    set_addr(ip, hl, 12, addr);
    let q = hl + icmp::HDR_LEN;
    if total < q + ipv4::MIN_HDR_LEN {
        return;
    }
    let qhl = ((ip[q] & 0x0f) as usize) * 4;
    let quoted = &mut ip[q..total];
    if qhl < ipv4::MIN_HDR_LEN || quoted.len() < qhl {
        return;
    }
    if quoted.len() >= qhl + 4 {
        let proto = quoted[9];
        if matches!(proto, ipv4::PROTO_TCP | ipv4::PROTO_UDP) {
            wr16(quoted, qhl + 2, port);
        } else if proto == ipv4::PROTO_ICMP && quoted.len() >= qhl + 6 {
            wr16(quoted, qhl + 4, port);
        }
    }
    quoted[16..20].copy_from_slice(&addr.octets());
    quoted[10..12].fill(0);
    let c = checksum::checksum(&quoted[..qhl]);
    wr16(quoted, 10, c);
    ip[hl + 2..hl + 4].fill(0);
    let c = checksum::checksum(&ip[hl..total]);
    wr16(ip, hl + 2, c);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet(csum: bool) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8 + 4];
        ipv4::write_header(
            &mut p,
            32,
            1,
            64,
            ipv4::PROTO_UDP,
            "10.0.0.5".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        );
        p[20..22].copy_from_slice(&5353u16.to_be_bytes());
        p[22..24].copy_from_slice(&53u16.to_be_bytes());
        p[24..26].copy_from_slice(&12u16.to_be_bytes());
        p[28..32].copy_from_slice(b"ping");
        if csum {
            let c = udp_sum(&p);
            p[26..28].copy_from_slice(&c.to_be_bytes());
        }
        p
    }

    fn udp_sum(p: &[u8]) -> u16 {
        let mut pseudo = p[12..20].to_vec();
        pseudo.extend_from_slice(&[0, 17, 0, 12]);
        let mut seg = p[20..].to_vec();
        if p[26..28] != [0, 0] {
            seg[6..8].copy_from_slice(&p[26..28]);
        }
        checksum::checksum(&[pseudo, seg].concat())
    }

    #[test]
    fn checksums_stay_valid_through_translation() {
        let mut p = udp_packet(true);
        translate_src(&mut p, "203.0.113.7".parse().unwrap(), 40000);
        assert_eq!(&p[12..16], &[203, 0, 113, 7]);
        assert_eq!(u16::from_be_bytes([p[20], p[21]]), 40000);
        assert_eq!(checksum::checksum(&p[..20]), 0, "IP header checksum");
        assert_eq!(udp_sum(&p), 0, "UDP checksum incl. pseudo-header");
        translate_dst(&mut p, "10.0.0.9".parse().unwrap(), 53);
        assert_eq!(checksum::checksum(&p[..20]), 0);
        assert_eq!(udp_sum(&p), 0);
    }

    #[test]
    fn zero_udp_checksum_stays_zero() {
        let mut p = udp_packet(false);
        translate_src(&mut p, "203.0.113.7".parse().unwrap(), 40000);
        assert_eq!(&p[26..28], &[0, 0]);
        assert_eq!(checksum::checksum(&p[..20]), 0);
    }

    fn port(id: u16, addr: &str, role: Role) -> Port {
        Port {
            id,
            card: id,
            vlan: None,
            host: Default::default(),
            name: format!("p{id}"),
            mac: [2, 0, 0, 0, 0, id as u8],
            addr: addr.parse().unwrap(),
            subnet: format!("{addr}/24").parse().unwrap(),
            allow_new_sessions: role == Role::Inside,
            role,
            mss_adjust: None,
            dhcp: crate::config::Dhcp::Off,
            gateway: None,
            pppoe: crate::config::Pppoe::Off,
            onlink: vec![],
            mtu: 1500,
        }
    }

    #[test]
    fn default_masquerade_rules_and_pools() {
        let ports = [
            port(0, "10.0.0.1", Role::Inside),
            port(1, "203.0.113.1", Role::Outside),
            port(2, "10.9.0.1", Role::Inside),
        ];
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let mut n = NatConfig::default();
        assert_eq!(
            n.decide(&ports, 0, 1, ip("10.0.0.5"), ip("8.8.8.8")),
            Some(ip("203.0.113.1")),
            "inside→outside"
        );
        assert_eq!(
            n.decide(&ports, 0, 2, ip("10.0.0.5"), ip("10.9.0.5")),
            None,
            "inside→inside"
        );
        assert_eq!(
            n.decide(&ports, 1, 0, ip("8.8.8.8"), ip("10.0.0.5")),
            None,
            "outside→inside"
        );
        n.pools.push(vec![ip("203.0.113.10"), ip("203.0.113.11")]);
        n.rules.push(NatRule {
            name: "vpn".into(),
            source: None,
            destination: Some("172.16.0.0/12".parse().unwrap()),
            outbound: None,
            action: NatAction::Exempt,
        });
        n.rules.push(NatRule {
            name: "servers".into(),
            source: Some("10.0.0.128/25".parse().unwrap()),
            destination: None,
            outbound: Some(1),
            action: NatAction::Pool(0),
        });
        assert_eq!(
            n.decide(&ports, 0, 1, ip("10.0.0.5"), ip("172.16.1.1")),
            None,
            "exempt"
        );
        let a = n
            .decide(&ports, 0, 1, ip("10.0.0.200"), ip("8.8.8.8"))
            .unwrap();
        assert!(n.owns(a), "pool address");
        assert_eq!(
            n.decide(&ports, 0, 1, ip("10.0.0.200"), ip("1.1.1.1")),
            Some(a),
            "same host, same pool address"
        );
        assert_eq!(
            n.decide(&ports, 0, 1, ip("10.0.0.5"), ip("8.8.8.8")),
            Some(ip("203.0.113.1")),
            "falls through to masquerade"
        );
        n.masquerade = false;
        assert_eq!(n.decide(&ports, 0, 1, ip("10.0.0.5"), ip("8.8.8.8")), None);
    }
}
