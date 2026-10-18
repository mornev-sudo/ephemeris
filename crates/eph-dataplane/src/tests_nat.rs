//! Source NAT at the network edge.
//!
//! ```text
//!  host A 10.0.0.10 ┐                                         ┌ ISP gateway 203.0.113.254
//!  host B 10.0.0.11 ┴ lan (inside) 10.0.0.1 [R] wan (outside) 203.0.113.1/24 ─┴─ the internet (8.8.8.8 ...)
//! ```

use crate::nat::{NatAction, NatConfig, NatRule};
use crate::overlay::Overlay;
use crate::*;
use eph_packet::{checksum, eth, icmp, ipv4, l4, Mac};
use std::net::Ipv4Addr;
use std::sync::Arc;

const R_LAN: Mac = [2, 0, 0, 0, 0, 1];
const R_WAN: Mac = [2, 0, 0, 0, 0, 2];
const HOST_A: Mac = [0x52, 0, 0, 0, 0, 0x0a];
const HOST_B: Mac = [0x52, 0, 0, 0, 0, 0x0b];
const ISP: Mac = [0x52, 0, 0, 0, 0, 0xfe];
const OFF: usize = 128;

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn router(nat: NatConfig) -> Pipeline {
    let ports: Arc<[Port]> = Arc::new([
        Port {
            id: 0,
            name: "lan".into(),
            mac: R_LAN,
            addr: ip("10.0.0.1"),
            subnet: "10.0.0.0/24".parse().unwrap(),
            allow_new_sessions: true,
            role: Role::Inside,
            mss_adjust: None,
        },
        Port {
            id: 1,
            name: "wan".into(),
            mac: R_WAN,
            addr: ip("203.0.113.1"),
            subnet: "203.0.113.0/24".parse().unwrap(),
            allow_new_sessions: false,
            role: Role::Outside,
            mss_adjust: None,
        },
    ]);
    let routes = [StaticRoute {
        prefix: "0.0.0.0/0".parse().unwrap(),
        via: ip("203.0.113.254"),
    }];
    let fib = build_fib(&ports, &routes, &[]).unwrap();
    let mut r = Pipeline::new(
        ports,
        Arc::new(fib),
        SessionConfig::default(),
        Arc::new(Overlay::disabled()),
    );
    r.set_nat(Arc::new(nat));
    r.set_time(1_000_000_000);
    r.learn(Neighbor {
        port: 0,
        ip: ip("10.0.0.10"),
        mac: HOST_A,
    });
    r.learn(Neighbor {
        port: 0,
        ip: ip("10.0.0.11"),
        mac: HOST_B,
    });
    r.learn(Neighbor {
        port: 1,
        ip: ip("203.0.113.254"),
        mac: ISP,
    });
    r
}

enum L4 {
    Echo(u8, u16), // type, identifier
    Tcp(u16, u16, u8),
    Udp(u16, u16),
}

/// A frame with an IPv4 packet at OFF.
fn packet(dst_mac: Mac, src_mac: Mac, src: &str, dst: &str, l4: L4) -> (Vec<u8>, usize) {
    let mut f = vec![0u8; 4096];
    let p = &mut f[OFF..];
    eth::write(p, dst_mac, src_mac, eth::TYPE_IPV4);
    let (proto, len) = match l4 {
        L4::Echo(..) => (ipv4::PROTO_ICMP, 16),
        L4::Tcp(..) => (ipv4::PROTO_TCP, 20),
        L4::Udp(..) => (ipv4::PROTO_UDP, 12),
    };
    ipv4::write_header(
        &mut p[14..],
        (20 + len) as u16,
        1,
        64,
        proto,
        ip(src),
        ip(dst),
    );
    let x = &mut p[34..34 + len];
    match l4 {
        L4::Echo(t, id) => {
            x[0] = t;
            x[4..6].copy_from_slice(&id.to_be_bytes());
            x[6..8].copy_from_slice(&[0, 1]);
            let c = checksum::checksum(x);
            x[2..4].copy_from_slice(&c.to_be_bytes());
        }
        L4::Tcp(s, d, flags) => {
            x[0..2].copy_from_slice(&s.to_be_bytes());
            x[2..4].copy_from_slice(&d.to_be_bytes());
            x[12] = 5 << 4;
            x[13] = flags;
            let c = l4_sum(&p[14..14 + 20 + len]);
            p[14 + 20 + 16..14 + 20 + 18].copy_from_slice(&c.to_be_bytes());
        }
        L4::Udp(s, d) => {
            x[0..2].copy_from_slice(&s.to_be_bytes());
            x[2..4].copy_from_slice(&d.to_be_bytes());
            x[4..6].copy_from_slice(&(len as u16).to_be_bytes());
            let c = l4_sum(&p[14..14 + 20 + len]);
            p[14 + 20 + 6..14 + 20 + 8].copy_from_slice(&c.to_be_bytes());
        }
    }
    (f, 14 + 20 + len)
}

/// TCP/UDP checksum over pseudo-header + segment (0 = valid when verifying).
fn l4_sum(ip_pkt: &[u8]) -> u16 {
    let seg = &ip_pkt[20..];
    let mut pseudo = ip_pkt[12..20].to_vec();
    pseudo.extend_from_slice(&[0, ip_pkt[9]]);
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    checksum::checksum(&[pseudo.as_slice(), seg].concat())
}

fn tx(v: Verdict) -> (PortId, usize, usize) {
    match v {
        Verdict::Tx { port, off, len } => (port, off, len),
        Verdict::Drop(r) => panic!("expected Tx, got {r:?}"),
    }
}

fn hdr(f: &[u8], off: usize, len: usize) -> ipv4::Header {
    ipv4::parse(&f[off + 14..off + len]).expect("valid IP header")
}
fn ports_of(f: &[u8], off: usize) -> (u16, u16) {
    (
        u16::from_be_bytes([f[off + 34], f[off + 35]]),
        u16::from_be_bytes([f[off + 36], f[off + 37]]),
    )
}

#[test]
fn ping_to_the_internet_is_masqueraded() {
    let mut r = router(NatConfig::default());
    let (mut f, n) = packet(
        R_LAN,
        HOST_A,
        "10.0.0.10",
        "8.8.8.8",
        L4::Echo(icmp::ECHO_REQUEST, 77),
    );
    let (port, off, len) = tx(r.process(0, &mut f, OFF, n));
    assert_eq!(port, 1);
    assert_eq!(eth::dst(&f[off..]), ISP, "via the ISP gateway");
    let h = hdr(&f, off, len);
    assert_eq!(
        (h.src, h.dst),
        (ip("203.0.113.1"), ip("8.8.8.8")),
        "source is the outside address"
    );
    let id = u16::from_be_bytes([f[off + 38], f[off + 39]]);
    assert_eq!(
        checksum::checksum(&f[off + 34..off + len]),
        0,
        "ICMP checksum valid"
    );

    // The reply comes back to the outside address...
    let (mut f, n) = packet(
        R_WAN,
        ISP,
        "8.8.8.8",
        "203.0.113.1",
        L4::Echo(icmp::ECHO_REPLY, id),
    );
    let (port, off, len) = tx(r.process(1, &mut f, OFF, n));
    // ...and goes to host A, with its original identifier.
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_A));
    let h = hdr(&f, off, len);
    assert_eq!((h.src, h.dst), (ip("8.8.8.8"), ip("10.0.0.10")));
    assert_eq!(u16::from_be_bytes([f[off + 38], f[off + 39]]), 77);
    assert_eq!(checksum::checksum(&f[off + 34..off + len]), 0);
}

#[test]
fn two_hosts_same_source_port_get_different_outside_ports() {
    let mut r = router(NatConfig::default());
    let mut out = vec![];
    for (mac, src) in [(HOST_A, "10.0.0.10"), (HOST_B, "10.0.0.11")] {
        let (mut f, n) = packet(R_LAN, mac, src, "8.8.8.8", L4::Tcp(40000, 443, l4::TCP_SYN));
        let (_, off, len) = tx(r.process(0, &mut f, OFF, n));
        assert_eq!(hdr(&f, off, len).src, ip("203.0.113.1"));
        assert_eq!(
            l4_sum(&f[off + 14..off + len]),
            0,
            "TCP checksum valid after NAT"
        );
        out.push(ports_of(&f, off).0);
    }
    assert_eq!(out[0], 40000, "first one keeps its port");
    assert_ne!(out[0], out[1], "second one gets another");
    // Each SYN+ACK finds its way back to the right host and port.
    for (port, mac) in [(out[0], HOST_A), (out[1], HOST_B)] {
        let (mut f, n) = packet(
            R_WAN,
            ISP,
            "8.8.8.8",
            "203.0.113.1",
            L4::Tcp(443, port, l4::TCP_SYN | l4::TCP_ACK),
        );
        let (p, off, len) = tx(r.process(1, &mut f, OFF, n));
        assert_eq!((p, eth::dst(&f[off..])), (0, mac));
        assert_eq!(ports_of(&f, off), (443, 40000));
        assert_eq!(l4_sum(&f[off + 14..off + len]), 0);
    }
}

#[test]
fn unsolicited_traffic_to_the_outside_address_is_not_forwarded() {
    let mut r = router(NatConfig::default());
    let (mut f, n) = packet(
        R_WAN,
        ISP,
        "8.8.8.8",
        "203.0.113.1",
        L4::Tcp(443, 40000, l4::TCP_SYN),
    );
    assert_eq!(
        r.process(1, &mut f, OFF, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
    let (mut f, n) = packet(
        R_WAN,
        ISP,
        "8.8.8.8",
        "10.0.0.10",
        L4::Tcp(443, 40000, l4::TCP_SYN),
    );
    assert_eq!(
        r.process(1, &mut f, OFF, n),
        Verdict::Drop(DropReason::NoSession),
        "outside is replies-only"
    );
}

#[test]
fn pool_rule_exemption_and_proxy_arp() {
    let mut nat = NatConfig::default();
    nat.pools.push(vec![ip("203.0.113.50"), ip("203.0.113.51")]);
    nat.rules.push(NatRule {
        name: "partner".into(),
        source: None,
        destination: Some("8.8.4.0/24".parse().unwrap()),
        outbound: None,
        action: NatAction::Exempt,
    });
    nat.rules.push(NatRule {
        name: "servers".into(),
        source: Some("10.0.0.11/32".parse().unwrap()),
        destination: None,
        outbound: Some(1),
        action: NatAction::Pool(0),
    });
    let mut r = router(nat);
    let (mut f, n) = packet(R_LAN, HOST_B, "10.0.0.11", "8.8.8.8", L4::Udp(5000, 53));
    let (_, off, len) = tx(r.process(0, &mut f, OFF, n));
    let pool_addr = hdr(&f, off, len).src;
    assert!(
        pool_addr == ip("203.0.113.50") || pool_addr == ip("203.0.113.51"),
        "{pool_addr}"
    );
    assert_eq!(l4_sum(&f[off + 14..off + len]), 0);
    // The ISP's router asks who has the pool address; we answer.
    let mut a = vec![0u8; 4096];
    eth::write(&mut a, eth::BROADCAST, ISP, eth::TYPE_ARP);
    eph_packet::arp::write(
        &mut a[14..],
        &eph_packet::arp::Arp {
            op: eph_packet::arp::OP_REQUEST,
            sha: ISP,
            spa: ip("203.0.113.254"),
            tha: eth::ZERO,
            tpa: pool_addr,
        },
    );
    let (port, off, _) = tx(r.process(1, &mut a, 0, 60));
    let reply = eph_packet::arp::parse(&a[off + 14..]).unwrap();
    assert_eq!(
        (port, reply.op, reply.spa, reply.sha),
        (1, eph_packet::arp::OP_REPLY, pool_addr, R_WAN)
    );
    // Exempt destination: no translation.
    let (mut f, n) = packet(R_LAN, HOST_A, "10.0.0.10", "8.8.4.4", L4::Udp(5000, 53));
    let (_, off, len) = tx(r.process(0, &mut f, OFF, n));
    assert_eq!(hdr(&f, off, len).src, ip("10.0.0.10"));
}

#[test]
fn icmp_errors_about_translated_packets_reach_the_inside_host() {
    let mut r = router(NatConfig::default());
    let (mut f, n) = packet(R_LAN, HOST_A, "10.0.0.10", "8.8.8.8", L4::Udp(33434, 33434));
    let (_, off, len) = tx(r.process(0, &mut f, OFF, n));
    let quoted = f[off + 14..off + len].to_vec(); // what the internet saw
                                                  // A router on the path says "TTL exceeded", quoting the translated packet.
    let mut e = vec![0u8; 4096];
    let ip_len = 20 + 8 + quoted.len();
    eth::write(&mut e[OFF..], R_WAN, ISP, eth::TYPE_IPV4);
    ipv4::write_header(
        &mut e[OFF + 14..],
        ip_len as u16,
        3,
        64,
        ipv4::PROTO_ICMP,
        ip("198.51.100.1"),
        ip("203.0.113.1"),
    );
    e[OFF + 42..OFF + 42 + quoted.len()].copy_from_slice(&quoted);
    icmp::write_error(
        &mut e[OFF + 34..],
        8 + quoted.len(),
        icmp::TIME_EXCEEDED,
        0,
        0,
    );
    let (port, off, len) = tx(r.process(1, &mut e, OFF, 14 + ip_len));
    assert_eq!((port, eth::dst(&e[off..])), (0, HOST_A));
    assert_eq!(hdr(&e, off, len).dst, ip("10.0.0.10"));
    let inner = ipv4::parse(&e[off + 42..off + len]).expect("quoted header checksum fixed");
    assert_eq!(inner.src, ip("10.0.0.10"), "quote shows what host A sent");
    assert_eq!(u16::from_be_bytes([e[off + 62], e[off + 63]]), 33434);
    assert_eq!(
        checksum::checksum(&e[off + 34..off + len]),
        0,
        "ICMP checksum"
    );
}

#[test]
fn ports_are_split_between_workers_and_freed_on_expiry() {
    let mut r = router(NatConfig::default());
    r.set_worker(1, 2);
    let (mut f, n) = packet(R_LAN, HOST_A, "10.0.0.10", "8.8.8.8", L4::Udp(5000, 53));
    let (_, off, _) = tx(r.process(0, &mut f, OFF, n));
    let p = ports_of(&f, off).0;
    assert_eq!(p % 2, 1, "worker 1 of 2 uses odd ports");
    // 31 s later the UDP session (and its port) is gone; replies are refused.
    r.set_time(32_000_000_000);
    r.housekeeping();
    let (mut f, n) = packet(R_WAN, ISP, "8.8.8.8", "203.0.113.1", L4::Udp(53, p));
    assert_eq!(
        r.process(1, &mut f, OFF, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
}

// ------------------------------------------------- going around the NAT

/// An ICMP Port Unreachable from `src` to `dst` quoting `quoted` (an IP
/// packet), arriving on `port`.
fn unreachable(port: PortId, src: &str, dst: &str, quoted: &[u8]) -> (Vec<u8>, usize) {
    let (dst_mac, src_mac) = if port == 0 {
        (R_LAN, HOST_A)
    } else {
        (R_WAN, ISP)
    };
    let mut e = vec![0u8; 4096];
    let ip_len = 20 + 8 + quoted.len();
    eth::write(&mut e[OFF..], dst_mac, src_mac, eth::TYPE_IPV4);
    ipv4::write_header(
        &mut e[OFF + 14..],
        ip_len as u16,
        3,
        64,
        ipv4::PROTO_ICMP,
        ip(src),
        ip(dst),
    );
    e[OFF + 42..OFF + 42 + quoted.len()].copy_from_slice(quoted);
    icmp::write_error(
        &mut e[OFF + 34..],
        8 + quoted.len(),
        icmp::DEST_UNREACHABLE,
        3,
        0,
    );
    (e, 14 + ip_len)
}

/// Host A's UDP query to 8.8.8.8:53 from port 40000: returns the outside port.
fn query(r: &mut Pipeline) -> u16 {
    let (mut f, n) = packet(R_LAN, HOST_A, "10.0.0.10", "8.8.8.8", L4::Udp(40000, 53));
    let (_, off, _) = tx(r.process(0, &mut f, OFF, n));
    ports_of(&f, off).0
}

fn dropped(v: Verdict) -> DropReason {
    match v {
        Verdict::Drop(r) => r,
        v => panic!("expected a drop, got {v:?}"),
    }
}

#[test]
fn replies_must_come_to_the_translated_address() {
    let mut r = router(NatConfig::default());
    query(&mut r);
    // The reply's tuple, but sent to host A's own (private) address.
    let (mut f, n) = packet(R_WAN, ISP, "8.8.8.8", "10.0.0.10", L4::Udp(53, 40000));
    assert_eq!(
        dropped(r.process(1, &mut f, OFF, n)),
        DropReason::SessionMismatch
    );
}

#[test]
fn inside_addresses_arriving_from_outside_are_spoofed() {
    let mut r = router(NatConfig::default());
    query(&mut r);
    let (mut f, n) = packet(R_WAN, ISP, "10.0.0.10", "8.8.8.8", L4::Udp(40000, 53));
    assert_eq!(
        dropped(r.process(1, &mut f, OFF, n)),
        DropReason::SpoofedSource
    );
}

#[test]
fn icmp_errors_only_reach_the_sender_of_the_quoted_packet() {
    let mut r = router(NatConfig::default());
    query(&mut r);
    // Host A's packet as A sent it (untranslated).
    let (f, n) = packet(R_LAN, HOST_A, "10.0.0.10", "8.8.8.8", L4::Udp(40000, 53));
    let quoted = f[OFF + 14..OFF + n].to_vec();
    // From the internet to host B, using A's session.
    let (mut e, n) = unreachable(1, "198.51.100.66", "10.0.0.11", &quoted);
    assert_eq!(
        dropped(r.process(1, &mut e, OFF, n)),
        DropReason::IcmpMismatch
    );
    // To host A itself, but nobody outside saw that untranslated packet.
    let (mut e, n) = unreachable(1, "198.51.100.66", "10.0.0.10", &quoted);
    assert_eq!(
        dropped(r.process(1, &mut e, OFF, n)),
        DropReason::SessionMismatch
    );
}

#[test]
fn icmp_errors_from_inside_leave_translated() {
    let mut r = router(NatConfig::default());
    let xport = query(&mut r);
    // The reply reaches host A...
    let (mut f, n) = packet(R_WAN, ISP, "8.8.8.8", "203.0.113.1", L4::Udp(53, xport));
    let (port, off, len) = tx(r.process(1, &mut f, OFF, n));
    assert_eq!(port, 0);
    let delivered = f[off + 14..off + len].to_vec();
    // ...whose socket is gone: Port Unreachable back to 8.8.8.8.
    let (mut e, n) = unreachable(0, "10.0.0.10", "8.8.8.8", &delivered);
    let (port, off, len) = tx(r.process(0, &mut e, OFF, n));
    assert_eq!(port, 1);
    assert_eq!(hdr(&e, off, len).src, ip("203.0.113.1"), "outer source");
    let quote = ipv4::parse(&e[off + 42..off + len]).expect("quoted header checksum fixed");
    assert_eq!(
        quote.dst,
        ip("203.0.113.1"),
        "quote shows the translated packet"
    );
    assert_eq!(u16::from_be_bytes([e[off + 64], e[off + 65]]), xport);
    assert_eq!(
        checksum::checksum(&e[off + 34..off + len]),
        0,
        "ICMP checksum"
    );
}

#[test]
fn later_fragments_that_need_nat_are_not_leaked() {
    let mut r = router(NatConfig::default());
    let (mut f, n) = packet(R_LAN, HOST_A, "10.0.0.10", "8.8.8.8", L4::Udp(40000, 53));
    // Make it a later fragment (offset 24 bytes): no ports to translate.
    let ip_hdr = &mut f[OFF + 14..OFF + 34];
    ip_hdr[6..8].copy_from_slice(&3u16.to_be_bytes());
    ip_hdr[10..12].fill(0);
    let c = checksum::checksum(ip_hdr);
    ip_hdr[10..12].copy_from_slice(&c.to_be_bytes());
    assert_eq!(
        dropped(r.process(0, &mut f, OFF, n)),
        DropReason::NatUntranslatable
    );
}
