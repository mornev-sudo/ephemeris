//! Scenario tests: a two-port router with a static route behind port 1.
//!
//! ```text
//!  host A 10.10.1.10 ──[p0 10.10.1.1]── ROUTER ──[p1 10.10.2.1]── host B 10.10.2.10
//!                                                     └── gw 10.10.2.254 → 192.168.50.0/24
//! ```

use crate::overlay::Overlay;
use crate::*;
use eph_packet::{arp, checksum, eth, icmp, ipv4, pppoe, Mac};
use std::net::Ipv4Addr;
use std::sync::Arc;

const R0: Mac = [0x02, 0, 0, 0, 0, 0x01];
const R1: Mac = [0x02, 0, 0, 0, 0, 0x02];
const HOST_A: Mac = [0x52, 0x54, 0, 0, 0, 0x0a];
const HOST_B: Mac = [0x52, 0x54, 0, 0, 0, 0x0b];
const GW: Mac = [0x52, 0x54, 0, 0, 0, 0xfe];

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn router() -> Pipeline {
    router_with(true, SessionConfig::default())
}

/// `b_open`: may hosts behind lan-b start sessions?
fn router_with(b_open: bool, sessions: SessionConfig) -> Pipeline {
    let ports: Arc<[Port]> = Arc::new([
        Port {
            id: 0,
            card: 0,
            vlan: None,
            host: Default::default(),
            name: "lan-a".into(),
            mac: R0,
            addr: ip("10.10.1.1"),
            subnet: "10.10.1.0/24".parse().unwrap(),
            allow_new_sessions: true,
            role: Role::Inside,
            mss_adjust: None,
            dhcp: crate::config::Dhcp::Off,
            gateway: None,
            pppoe: crate::config::Pppoe::Off,
            onlink: vec![],
            mtu: 1500,
        },
        Port {
            id: 1,
            card: 1,
            vlan: None,
            host: Default::default(),
            name: "lan-b".into(),
            mac: R1,
            addr: ip("10.10.2.1"),
            subnet: "10.10.2.0/24".parse().unwrap(),
            allow_new_sessions: b_open,
            role: Role::Inside,
            mss_adjust: None,
            dhcp: crate::config::Dhcp::Off,
            gateway: None,
            pppoe: crate::config::Pppoe::Off,
            onlink: vec![],
            mtu: 1500,
        },
    ]);
    let statics = [StaticRoute {
        prefix: "192.168.50.0/24".parse().unwrap(),
        via: ip("10.10.2.254"),
    }];
    let fib = build_fib(&ports, &statics, &[]).unwrap();
    let mut p = Pipeline::new(
        ports,
        Arc::new(fib),
        sessions,
        Arc::new(Overlay::disabled()),
    );
    p.set_time(10_000_000_000);
    p
}

/// Ethernet + IPv4 + ICMP echo request in a 2 KiB buffer, like a UMEM frame.
fn ping(dst_mac: Mac, src_mac: Mac, src: &str, dst: &str, ttl: u8) -> (Vec<u8>, usize) {
    let mut buf = vec![0u8; 2048];
    let payload = b"payload!";
    let icmp_len = icmp::HDR_LEN + payload.len();
    let ip_len = ipv4::MIN_HDR_LEN + icmp_len;
    eth::write(&mut buf, dst_mac, src_mac, eth::TYPE_IPV4);
    ipv4::write_header(
        &mut buf[14..],
        ip_len as u16,
        1,
        ttl,
        ipv4::PROTO_ICMP,
        ip(src),
        ip(dst),
    );
    let m = &mut buf[34..34 + icmp_len];
    m[0] = icmp::ECHO_REQUEST;
    m[4..8].copy_from_slice(&[0x12, 0x34, 0, 1]);
    m[8..].copy_from_slice(payload);
    let c = checksum::checksum(m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    (buf, 14 + ip_len)
}

fn arp_frame(op: u16, src_mac: Mac, spa: &str, tpa: &str, dst_mac: Mac) -> (Vec<u8>, usize) {
    let mut buf = vec![0u8; 2048];
    eth::write(&mut buf, dst_mac, src_mac, eth::TYPE_ARP);
    arp::write(
        &mut buf[14..],
        &arp::Arp {
            op,
            sha: src_mac,
            spa: ip(spa),
            tha: eth::ZERO,
            tpa: ip(tpa),
        },
    );
    (buf, 60)
}

fn learn(r: &mut Pipeline, port: PortId, mac: Mac, addr: &str) {
    r.learn(Neighbor {
        port,
        ip: ip(addr),
        mac,
    });
}

/// On a /32 lease the gateway is outside the subnet but on the link: its
/// ARP request to us is answered and it's learned as a neighbour.
#[test]
fn arp_from_an_on_link_gateway_outside_the_subnet() {
    let mut r = router();
    let mut ports = r.ports().to_vec();
    ports[1].addr = ip("100.64.12.34");
    ports[1].subnet = "100.64.12.34/32".parse().unwrap();
    ports[1].onlink = vec!["100.64.0.1/32".parse().unwrap()];
    r.set_ports(ports.into());
    let (mut b, n) = arp_frame(
        arp::OP_REQUEST,
        HOST_B,
        "100.64.0.1",
        "100.64.12.34",
        eth::BROADCAST,
    );
    assert!(matches!(
        r.process(1, &mut b, 0, n),
        Verdict::Tx { port: 1, .. }
    ));
    assert!(r
        .neighbors()
        .any(|x| x.ip == ip("100.64.0.1") && x.mac == HOST_B));
    // Anyone else off the subnet is still ignored.
    let (mut b, n) = arp_frame(
        arp::OP_REQUEST,
        HOST_A,
        "100.64.0.9",
        "100.64.12.34",
        eth::BROADCAST,
    );
    r.process(1, &mut b, 0, n);
    assert!(!r.neighbors().any(|x| x.ip == ip("100.64.0.9")));
}

#[test]
fn answers_arp_for_own_address_and_learns_sender() {
    let mut r = router();
    let (mut b, n) = arp_frame(
        arp::OP_REQUEST,
        HOST_A,
        "10.10.1.10",
        "10.10.1.1",
        eth::BROADCAST,
    );
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Tx {
            port: 0,
            off: 0,
            len: 60
        }
    );
    assert_eq!(eth::dst(&b), HOST_A);
    assert_eq!(eth::src(&b), R0);
    let a = arp::parse(&b[14..]).unwrap();
    assert_eq!(
        (a.op, a.sha, a.spa, a.tpa),
        (arp::OP_REPLY, R0, ip("10.10.1.1"), ip("10.10.1.10"))
    );
    assert_eq!(
        r.learned,
        vec![Neighbor {
            port: 0,
            ip: ip("10.10.1.10"),
            mac: HOST_A
        }]
    );
}

#[test]
fn ignores_arp_for_other_hosts() {
    let mut r = router();
    let (mut b, n) = arp_frame(
        arp::OP_REQUEST,
        HOST_A,
        "10.10.1.10",
        "10.10.1.99",
        eth::BROADCAST,
    );
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::ArpConsumed)
    );
    assert!(
        r.learned.is_empty(),
        "must not learn from requests not aimed at us"
    );
}

#[test]
fn neighbor_miss_sends_one_arp_per_second() {
    let mut r = router();
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::NeighborMiss)
    );
    assert_eq!(r.emits.len(), 1);
    let e = &r.emits[0];
    assert_eq!(e.port, 1);
    let a = arp::parse(&e.frame[14..]).unwrap();
    assert_eq!(
        (a.op, a.spa, a.tpa),
        (arp::OP_REQUEST, ip("10.10.2.1"), ip("10.10.2.10"))
    );

    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    r.process(0, &mut b, 0, n);
    assert_eq!(r.emits.len(), 1, "retry suppressed within 1s");

    r.set_time(11_500_000_000);
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    r.process(0, &mut b, 0, n);
    assert_eq!(r.emits.len(), 2, "retried after 1s");
}

#[test]
fn arp_reply_resolves_neighbor_then_forwarding_works() {
    let mut r = router();
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    r.process(0, &mut b, 0, n);
    // Host B answers the router's ARP request.
    let (mut b, n) = arp_frame(arp::OP_REPLY, HOST_B, "10.10.2.10", "10.10.2.1", R1);
    assert_eq!(
        r.process(1, &mut b, 0, n),
        Verdict::Drop(DropReason::ArpConsumed)
    );

    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Tx {
            port: 1,
            off: 0,
            len: n
        }
    );
    assert_eq!(eth::dst(&b), HOST_B);
    assert_eq!(eth::src(&b), R1);
    let h = ipv4::parse(&b[14..n]).expect("checksum still valid after TTL patch");
    assert_eq!(h.ttl, 63);
    assert_eq!(r.stats.forwarded, 1);
}

#[test]
fn static_route_uses_gateway_mac() {
    let mut r = router();
    learn(&mut r, 1, GW, "10.10.2.254");
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "192.168.50.7", 64);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Tx {
            port: 1,
            off: 0,
            len: n
        }
    );
    assert_eq!(eth::dst(&b), GW);
}

#[test]
fn ttl_expiry_sends_time_exceeded_with_quote() {
    let mut r = router();
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    let (orig, _) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 1);
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 1);
    let Verdict::Tx { port, len, .. } = r.process(0, &mut b, 0, n) else {
        panic!()
    };
    assert_eq!(port, 0);
    assert_eq!(eth::dst(&b), HOST_A);
    let h = ipv4::parse(&b[14..len]).unwrap();
    assert_eq!(
        (h.src, h.dst, h.proto),
        (ip("10.10.1.1"), ip("10.10.1.10"), ipv4::PROTO_ICMP)
    );
    let m = &b[34..len];
    assert_eq!((m[0], m[1]), (icmp::TIME_EXCEEDED, 0));
    assert_eq!(checksum::checksum(m), 0);
    // Quoted: the original IP header + 8 bytes (the original ICMP header).
    assert_eq!(&m[8..], &orig[14..14 + 28]);
    assert_eq!(r.stats.drops[DropReason::TtlExceeded as usize], 1);
}

#[test]
fn no_route_sends_net_unreachable() {
    let mut r = router();
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "8.8.8.8", 64);
    let Verdict::Tx { port: 0, len, .. } = r.process(0, &mut b, 0, n) else {
        panic!()
    };
    assert_eq!(
        (b[34], b[35]),
        (icmp::DEST_UNREACHABLE, icmp::CODE_NET_UNREACHABLE)
    );
    assert!(ipv4::parse(&b[14..len]).is_ok());
}

#[test]
fn icmp_errors_are_rate_limited() {
    let mut r = router();
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    let mut sent = 0;
    for _ in 0..200 {
        let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "8.8.8.8", 64);
        if matches!(r.process(0, &mut b, 0, n), Verdict::Tx { .. }) {
            sent += 1;
        }
    }
    assert_eq!(sent, 50, "burst size");
    assert_eq!(r.stats.drops[DropReason::NoRoute as usize], 200);
    assert_eq!(r.stats.drops[DropReason::IcmpRateLimited as usize], 150);
}

#[test]
fn pings_to_router_interfaces_get_replies() {
    let mut r = router();
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    // Host A pings the router's *far* interface; reply still goes out p0.
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.1", 64);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Tx {
            port: 0,
            off: 0,
            len: n
        }
    );
    let h = ipv4::parse(&b[14..n]).unwrap();
    assert_eq!(
        (h.src, h.dst, h.ttl),
        (ip("10.10.2.1"), ip("10.10.1.10"), 64)
    );
    assert_eq!(b[34], icmp::ECHO_REPLY);
    assert_eq!(checksum::checksum(&b[34..n]), 0);
    assert_eq!(&b[42..n], b"payload!");
}

#[test]
fn drops_frames_for_other_macs_and_martians() {
    let mut r = router();
    let (mut b, n) = ping(HOST_B, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::NotForUs)
    );
    let (mut b, n) = ping(R0, HOST_A, "127.0.0.1", "10.10.2.10", 64);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::Martian)
    );
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.255", 64);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::Martian),
        "directed broadcast"
    );
}

#[test]
fn corrupted_header_is_dropped() {
    let mut r = router();
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    b[14 + 10] ^= 0xff;
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::BadIpHeader)
    );
}

#[test]
fn static_route_gateway_must_be_connected() {
    let ports = [Port {
        id: 0,
        card: 0,
        vlan: None,
        host: Default::default(),
        name: "x".into(),
        mac: R0,
        addr: ip("10.0.0.1"),
        subnet: "10.0.0.0/24".parse().unwrap(),
        allow_new_sessions: true,
        role: Role::Inside,
        mss_adjust: None,
        dhcp: crate::config::Dhcp::Off,
        gateway: None,
        pppoe: crate::config::Pppoe::Off,
        onlink: vec![],
        mtu: 1500,
    }];
    let bad = [StaticRoute {
        prefix: "0.0.0.0/0".parse().unwrap(),
        via: ip("172.16.0.1"),
    }];
    assert!(build_fib(&ports, &bad, &[]).is_err());
}

/// A /32 lease with its gateway outside it (ISPs, clouds): the gateway is
/// on-link, so routes through it resolve, and a port still waiting for its
/// address adds no 0.0.0.0/32 "connected" route.
#[test]
fn on_link_gateway_outside_the_subnet() {
    let wan = |addr: &str, subnet: &str, onlink: Vec<eph_fib::Prefix>| Port {
        id: 0,
        card: 0,
        vlan: None,
        host: Default::default(),
        name: "wan".into(),
        mac: R0,
        addr: ip(addr),
        subnet: subnet.parse().unwrap(),
        allow_new_sessions: false,
        role: Role::Outside,
        mss_adjust: None,
        dhcp: crate::config::Dhcp::Client,
        gateway: Some(ip("100.64.0.1")),
        pppoe: crate::config::Pppoe::Off,
        onlink,
        mtu: 1500,
    };
    let default = [StaticRoute {
        prefix: "0.0.0.0/0".parse().unwrap(),
        via: ip("100.64.0.1"),
    }];
    // Without the on-link /32 the gateway can't be resolved...
    let bare = [wan("100.64.12.34", "100.64.12.34/32", vec![])];
    assert!(build_fib(&bare, &default, &[]).is_err());
    // ...with it, it can, and the gateway itself is a connected host.
    let ports = [wan(
        "100.64.12.34",
        "100.64.12.34/32",
        vec!["100.64.0.1/32".parse().unwrap()],
    )];
    let fib = build_fib(&ports, &default, &[]).unwrap();
    assert_eq!(
        fib.lookup(ip("8.8.8.8")),
        Some(&NextHop::Ip {
            port: 0,
            gateway: Some(ip("100.64.0.1"))
        })
    );
    assert_eq!(
        fib.lookup(ip("100.64.0.1")),
        Some(&NextHop::Ip {
            port: 0,
            gateway: None
        })
    );
    assert!(ports[0].reaches(ip("100.64.0.1")));
    // Waiting for a lease: no route at all, not 0.0.0.0/32.
    let waiting = [wan("0.0.0.0", "0.0.0.0/32", vec![])];
    let fib = build_fib(&waiting, &[], &[]).unwrap();
    assert!(fib.routes().is_empty(), "{:?}", fib.routes());
    assert!(!waiting[0].reaches(ip("0.0.0.0")));
}

// ------------------------------------------------------------- Phase 1: sessions

use eph_packet::l4::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

/// Ethernet + IPv4 + TCP (or UDP if `tcp_flags` is None) in a 2 KiB buffer.
/// L4 checksums are left at zero: the router never looks at them.
fn seg(
    dst_mac: Mac,
    src_mac: Mac,
    src: (&str, u16),
    dst: (&str, u16),
    tcp_flags: Option<u8>,
) -> (Vec<u8>, usize) {
    let mut buf = vec![0u8; 2048];
    let (proto, l4_len) = match tcp_flags {
        Some(_) => (ipv4::PROTO_TCP, 20),
        None => (ipv4::PROTO_UDP, 8),
    };
    let ip_len = ipv4::MIN_HDR_LEN + l4_len;
    eth::write(&mut buf, dst_mac, src_mac, eth::TYPE_IPV4);
    ipv4::write_header(
        &mut buf[14..],
        ip_len as u16,
        1,
        64,
        proto,
        ip(src.0),
        ip(dst.0),
    );
    let l4 = &mut buf[34..];
    l4[0..2].copy_from_slice(&src.1.to_be_bytes());
    l4[2..4].copy_from_slice(&dst.1.to_be_bytes());
    match tcp_flags {
        Some(f) => {
            l4[12] = 5 << 4;
            l4[13] = f;
        }
        None => l4[4..6].copy_from_slice(&8u16.to_be_bytes()),
    }
    (buf, 14 + ip_len)
}

/// Router with both hosts' MACs already known.
fn resolved(b_open: bool) -> Pipeline {
    let mut r = router_with(b_open, SessionConfig::default());
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    r
}

fn a_to_b(r: &mut Pipeline, flags: u8) -> Verdict {
    let (mut b, n) = seg(
        R0,
        HOST_A,
        ("10.10.1.10", 40000),
        ("10.10.2.10", 80),
        Some(flags),
    );
    r.process(0, &mut b, 0, n)
}

fn b_to_a(r: &mut Pipeline, flags: u8) -> Verdict {
    let (mut b, n) = seg(
        R1,
        HOST_B,
        ("10.10.2.10", 80),
        ("10.10.1.10", 40000),
        Some(flags),
    );
    r.process(1, &mut b, 0, n)
}

fn session_state(r: &Pipeline) -> State {
    let s: Vec<_> = r.sessions().iter().collect();
    assert_eq!(s.len(), 1);
    s[0].state
}

#[test]
fn tcp_session_tracks_both_directions() {
    let mut r = resolved(false);
    assert!(matches!(
        a_to_b(&mut r, TCP_SYN),
        Verdict::Tx { port: 1, .. }
    ));
    assert_eq!(session_state(&r), State::SynSent);
    assert!(
        matches!(
            b_to_a(&mut r, TCP_SYN | TCP_ACK),
            Verdict::Tx { port: 0, .. }
        ),
        "reply enters the closed side"
    );
    assert!(matches!(a_to_b(&mut r, TCP_ACK), Verdict::Tx { .. }));
    assert_eq!(session_state(&r), State::Established);
    for _ in 0..10 {
        a_to_b(&mut r, TCP_ACK);
        b_to_a(&mut r, TCP_ACK);
    }
    let s = r.sessions().iter().next().unwrap();
    assert_eq!(s.packets, [12, 11]);
    let ((ia, pa), (ib, pb)) = s.endpoints();
    assert_eq!(
        (ia, pa, ib, pb),
        (ip("10.10.1.10"), 40000, ip("10.10.2.10"), 80),
        "initiator is A"
    );
    a_to_b(&mut r, TCP_FIN | TCP_ACK);
    b_to_a(&mut r, TCP_FIN | TCP_ACK);
    assert_eq!(session_state(&r), State::TimeWait);
}

#[test]
fn closed_side_cannot_start_sessions() {
    let mut r = resolved(false);
    assert_eq!(
        b_to_a(&mut r, TCP_SYN),
        Verdict::Drop(DropReason::NoSession)
    );
    let (mut b, n) = seg(R1, HOST_B, ("10.10.2.10", 5353), ("10.10.1.10", 53), None);
    assert_eq!(
        r.process(1, &mut b, 0, n),
        Verdict::Drop(DropReason::NoSession)
    );
    let (mut b, n) = ping(R1, HOST_B, "10.10.2.10", "10.10.1.10", 64);
    assert_eq!(
        r.process(1, &mut b, 0, n),
        Verdict::Drop(DropReason::NoSession)
    );
    assert!(r.sessions().is_empty());
    // ...but with an open policy the same packet is fine.
    let mut r = resolved(true);
    assert!(matches!(
        b_to_a(&mut r, TCP_SYN),
        Verdict::Tx { port: 0, .. }
    ));
}

#[test]
fn ping_through_closed_side_works_one_way() {
    let mut r = resolved(false);
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    assert!(matches!(
        r.process(0, &mut b, 0, n),
        Verdict::Tx { port: 1, .. }
    ));
    // B's echo reply (same identifier) matches A's session.
    let (mut b, n) = ping(R1, HOST_B, "10.10.2.10", "10.10.1.10", 64);
    b[34] = icmp::ECHO_REPLY;
    b[36..38].fill(0);
    let c = checksum::checksum(&b[34..n]);
    b[36..38].copy_from_slice(&c.to_be_bytes());
    assert!(matches!(
        r.process(1, &mut b, 0, n),
        Verdict::Tx { port: 0, .. }
    ));
    assert_eq!(session_state(&r), State::Established);
}

#[test]
fn related_icmp_error_passes_for_known_session() {
    let mut r = resolved(false);
    // A sends UDP to B; B answers "port unreachable" (an ICMP error quoting A's packet).
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 5000), ("10.10.2.10", 9999), None);
    let quoted = b[14..n].to_vec();
    assert!(matches!(r.process(0, &mut b, 0, n), Verdict::Tx { .. }));

    let mut e = vec![0u8; 2048];
    let ip_len = 20 + 8 + quoted.len();
    eth::write(&mut e, R1, HOST_B, eth::TYPE_IPV4);
    ipv4::write_header(
        &mut e[14..],
        ip_len as u16,
        9,
        64,
        ipv4::PROTO_ICMP,
        ip("10.10.2.10"),
        ip("10.10.1.10"),
    );
    e[42..42 + quoted.len()].copy_from_slice(&quoted);
    icmp::write_error(&mut e[34..], 8 + quoted.len(), icmp::DEST_UNREACHABLE, 3, 0);
    // The same error for a flow nobody started is refused.
    let mut e2 = e.clone();
    e2[42 + 20..42 + 22].copy_from_slice(&5001u16.to_be_bytes());
    icmp::write_error(
        &mut e2[34..],
        8 + quoted.len(),
        icmp::DEST_UNREACHABLE,
        3,
        0,
    );
    assert!(matches!(
        r.process(1, &mut e, 0, 14 + ip_len),
        Verdict::Tx { port: 0, .. }
    ));
    assert_eq!(
        r.process(1, &mut e2, 0, 14 + ip_len),
        Verdict::Drop(DropReason::NoSession)
    );
}

#[test]
fn rst_and_stray_acks_do_not_open_sessions() {
    let mut r = resolved(true);
    assert_eq!(
        a_to_b(&mut r, TCP_RST),
        Verdict::Drop(DropReason::InvalidTcpState)
    );
    // Loose mode (default) picks up a mid-stream ACK...
    assert!(matches!(a_to_b(&mut r, TCP_ACK), Verdict::Tx { .. }));
    // ...strict mode refuses it.
    let mut r = router_with(
        true,
        SessionConfig {
            tcp_strict: true,
            ..Default::default()
        },
    );
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    assert_eq!(
        a_to_b(&mut r, TCP_ACK),
        Verdict::Drop(DropReason::InvalidTcpState)
    );
}

#[test]
fn responder_must_answer_syn_with_syn_ack() {
    let mut r = resolved(true);
    a_to_b(&mut r, TCP_SYN);
    assert_eq!(
        b_to_a(&mut r, TCP_ACK),
        Verdict::Drop(DropReason::InvalidTcpState)
    );
}

#[test]
fn sessions_expire_and_close_the_door_behind_them() {
    let mut r = resolved(false);
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 5000), ("10.10.2.10", 53), None);
    r.process(0, &mut b, 0, n);
    r.housekeeping();
    assert_eq!(r.stats.sessions_active, 1);
    // 31 s of silence: the UDP session times out.
    r.set_time(10_000_000_000 + 31_000_000_000);
    r.housekeeping();
    assert_eq!(r.stats.sessions_active, 0);
    assert_eq!(r.stats.sessions_expired, 1);
    let (mut b, n) = seg(R1, HOST_B, ("10.10.2.10", 53), ("10.10.1.10", 5000), None);
    assert_eq!(
        r.process(1, &mut b, 0, n),
        Verdict::Drop(DropReason::NoSession),
        "late reply refused"
    );
}

#[test]
fn full_table_refuses_new_flows_but_keeps_old_ones() {
    let mut r = router_with(
        true,
        SessionConfig {
            max_sessions: 2,
            early_drop: false,
            ..Default::default()
        },
    );
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    for port in [1000u16, 1001] {
        let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", port), ("10.10.2.10", 53), None);
        assert!(matches!(r.process(0, &mut b, 0, n), Verdict::Tx { .. }));
    }
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 1002), ("10.10.2.10", 53), None);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::SessionTableFull)
    );
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 1000), ("10.10.2.10", 53), None);
    assert!(matches!(r.process(0, &mut b, 0, n), Verdict::Tx { .. }));
}

#[test]
fn a_host_over_its_session_limit_is_refused_others_are_not() {
    let mut r = router_with(
        true,
        SessionConfig {
            max_sessions: 64,
            max_per_host: 2,
            ..Default::default()
        },
    );
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    for port in [1000u16, 1001] {
        let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", port), ("10.10.2.10", 53), None);
        assert!(matches!(r.process(0, &mut b, 0, n), Verdict::Tx { .. }));
    }
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 1002), ("10.10.2.10", 53), None);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::HostSessionLimit)
    );
    // Its existing flows carry on, and another host starts its own.
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 1000), ("10.10.2.10", 53), None);
    assert!(matches!(r.process(0, &mut b, 0, n), Verdict::Tx { .. }));
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.11", 1000), ("10.10.2.10", 53), None);
    assert!(matches!(r.process(0, &mut b, 0, n), Verdict::Tx { .. }));
}

/// Assert the router forwarded the packet.
fn sent(v: Verdict) {
    assert!(matches!(v, Verdict::Tx { .. }), "expected Tx, got {v:?}");
}

#[test]
fn a_full_table_makes_room_by_dropping_unanswered_sessions() {
    let mut r = router_with(
        true,
        SessionConfig {
            max_sessions: 2,
            ..Default::default()
        },
    );
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    // One conversation that's answered, one that never is.
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 1000), ("10.10.2.10", 53), None);
    sent(r.process(0, &mut b, 0, n));
    let (mut b, n) = seg(R1, HOST_B, ("10.10.2.10", 53), ("10.10.1.10", 1000), None);
    sent(r.process(1, &mut b, 0, n));
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 1001), ("10.10.2.10", 53), None);
    sent(r.process(0, &mut b, 0, n));
    // A third: the unanswered one makes room.
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 1002), ("10.10.2.10", 53), None);
    sent(r.process(0, &mut b, 0, n));
    r.housekeeping();
    assert_eq!(
        (r.stats.sessions_early_dropped, r.stats.sessions_unanswered),
        (1, 1)
    );
    // The answered one still works; another newcomer can't push it out.
    let (mut b, n) = seg(R1, HOST_B, ("10.10.2.10", 53), ("10.10.1.10", 1000), None);
    sent(r.process(1, &mut b, 0, n));
    let (mut b, n) = seg(R1, HOST_B, ("10.10.2.10", 53), ("10.10.1.10", 1002), None);
    sent(r.process(1, &mut b, 0, n)); // now both are answered
    let (mut b, n) = seg(R0, HOST_A, ("10.10.1.10", 1003), ("10.10.2.10", 53), None);
    assert_eq!(
        r.process(0, &mut b, 0, n),
        Verdict::Drop(DropReason::SessionTableFull)
    );
}

#[test]
fn next_hop_is_cached_per_session_and_invalidated_by_new_fib() {
    let mut r = resolved(true);
    a_to_b(&mut r, TCP_SYN);
    let s = r.sessions().iter().next().unwrap();
    assert_eq!(s.next_hop[Dir::Forward as usize].map(port_of), Some(1));
    assert_eq!(
        s.next_hop[Dir::Reverse as usize],
        None,
        "filled by the first reply"
    );
    b_to_a(&mut r, TCP_SYN | TCP_ACK);
    let s = r.sessions().iter().next().unwrap();
    assert_eq!(s.next_hop[Dir::Reverse as usize].map(port_of), Some(0));
}

fn port_of(nh: NextHop) -> PortId {
    match nh {
        NextHop::Ip { port, .. } => port,
        NextHop::Site(_) => u16::MAX,
    }
}

// ------------------------------------------------- spoofing and blind attacks

fn dropped(v: Verdict) -> DropReason {
    match v {
        Verdict::Drop(r) => r,
        v => panic!("expected a drop, got {v:?}"),
    }
}

fn port_of_tx(v: Verdict) -> PortId {
    match v {
        Verdict::Tx { port, .. } => port,
        Verdict::Drop(reason) => panic!("expected forwarding, got drop {reason:?}"),
    }
}

#[test]
fn sessions_only_accept_each_direction_where_it_arrived() {
    let mut r = resolved(true);
    learn(&mut r, 1, GW, "10.10.2.254");
    // A talks to a host behind the gateway on lan-b.
    let (mut b, n) = seg(
        R0,
        HOST_A,
        ("10.10.1.10", 40000),
        ("192.168.50.5", 80),
        None,
    );
    assert_eq!(port_of_tx(r.process(0, &mut b, 0, n)), 1);
    // The "reply" turns up on lan-a instead: spoofed.
    let (mut b, n) = seg(
        R0,
        HOST_A,
        ("192.168.50.5", 80),
        ("10.10.1.10", 40000),
        None,
    );
    assert_eq!(
        dropped(r.process(0, &mut b, 0, n)),
        DropReason::SessionMismatch
    );
    // The real one comes from the gateway on lan-b.
    let (mut b, n) = seg(R1, GW, ("192.168.50.5", 80), ("10.10.1.10", 40000), None);
    assert_eq!(port_of_tx(r.process(1, &mut b, 0, n)), 0);
}

#[test]
fn connected_subnets_are_only_accepted_on_their_own_port() {
    let mut r = resolved(true);
    let (mut b, n) = ping(R1, HOST_B, "10.10.1.10", "10.10.2.10", 64);
    assert_eq!(
        dropped(r.process(1, &mut b, 0, n)),
        DropReason::SpoofedSource
    );
}

/// A TCP segment between A (port 0) and B (port 1) with real sequence
/// numbers, a 64 KiB window and, optionally, a window scale option.
fn tcp_with(
    r: &mut Pipeline,
    from_a: bool,
    flags: u8,
    (seq, ack): (u32, u32),
    wscale: Option<u8>,
) -> Verdict {
    let (mut b, mut n) = if from_a {
        seg(
            R0,
            HOST_A,
            ("10.10.1.10", 40000),
            ("10.10.2.10", 80),
            Some(flags),
        )
    } else {
        seg(
            R1,
            HOST_B,
            ("10.10.2.10", 80),
            ("10.10.1.10", 40000),
            Some(flags),
        )
    };
    b[38..42].copy_from_slice(&seq.to_be_bytes());
    b[42..46].copy_from_slice(&ack.to_be_bytes());
    b[48..50].copy_from_slice(&65535u16.to_be_bytes());
    if let Some(ws) = wscale {
        b[46] = 6 << 4; // 24-byte header: NOP + window scale
        b[54..58].copy_from_slice(&[1, 3, 3, ws]);
        n += 4;
        let total = (n - 14) as u16;
        b[16..18].copy_from_slice(&total.to_be_bytes());
        b[24..26].fill(0);
        let c = checksum::checksum(&b[14..34]);
        b[24..26].copy_from_slice(&c.to_be_bytes());
    }
    r.process(if from_a { 0 } else { 1 }, &mut b, 0, n)
}

fn tcp_at(r: &mut Pipeline, from_a: bool, flags: u8, seq: u32, ack: u32) -> Verdict {
    tcp_with(r, from_a, flags, (seq, ack), None)
}

fn handshake(r: &mut Pipeline) {
    assert!(matches!(
        tcp_at(r, true, TCP_SYN, 1000, 0),
        Verdict::Tx { .. }
    ));
    let syn_ack = tcp_at(r, false, TCP_SYN | TCP_ACK, 5000, 1001);
    assert!(matches!(syn_ack, Verdict::Tx { .. }));
    assert!(matches!(
        tcp_at(r, true, TCP_ACK, 1001, 5001),
        Verdict::Tx { .. }
    ));
    assert_eq!(session_state(r), State::Established);
}

#[test]
fn blind_resets_do_not_close_sessions() {
    let mut r = resolved(false);
    handshake(&mut r);
    // A guessed sequence number: passed on (the endpoint ignores it), but
    // the session stays open.
    let guess = tcp_at(&mut r, false, TCP_RST, 5001 + 10_000_000, 0);
    assert!(matches!(guess, Verdict::Tx { .. }));
    assert_eq!(session_state(&r), State::Established);
    assert_eq!(r.sessions().blind, 1);
    // Same for a blind FIN.
    tcp_at(&mut r, false, TCP_FIN | TCP_ACK, 3_000_000_000, 1001);
    assert_eq!(session_state(&r), State::Established);
    // A reset in the window is genuine.
    tcp_at(&mut r, false, TCP_RST, 5001, 0);
    assert_eq!(session_state(&r), State::Closed);
}

#[test]
fn a_reset_answering_a_syn_must_acknowledge_it() {
    let mut r = resolved(false);
    assert!(matches!(
        tcp_at(&mut r, true, TCP_SYN, 1000, 0),
        Verdict::Tx { .. }
    ));
    let wrong = tcp_at(&mut r, false, TCP_RST | TCP_ACK, 0, 77);
    assert_eq!(dropped(wrong), DropReason::InvalidTcpState);
    assert_eq!(session_state(&r), State::SynSent);
    tcp_at(&mut r, false, TCP_RST | TCP_ACK, 0, 1001);
    assert_eq!(session_state(&r), State::Closed);
}

#[test]
fn window_scaling_counts_in_reset_checks() {
    let mut r = resolved(false);
    tcp_with(&mut r, true, TCP_SYN, (1000, 0), Some(7));
    tcp_with(&mut r, false, TCP_SYN | TCP_ACK, (5000, 1001), Some(7));
    // A advertises 65535 << 7: about 8 MiB.
    tcp_at(&mut r, true, TCP_ACK, 1001, 5001);
    // 4 MiB ahead of where B is: inside A's window, so genuine.
    tcp_at(&mut r, false, TCP_RST, 5001 + (4 << 20), 0);
    assert_eq!(session_state(&r), State::Closed);
}

#[test]
fn spoofed_arp_cannot_take_over_a_neighbor() {
    const EVE: Mac = [0x52, 0x54, 0, 0, 0, 0xee];
    let mut r = router();
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    let mac = |r: &Pipeline| r.neighbors().find(|x| x.port == 0).map(|x| x.mac);
    // Eve claims host A's address.
    let (mut b, n) = arp_frame(
        arp::OP_REQUEST,
        EVE,
        "10.10.1.10",
        "10.10.1.1",
        eth::BROADCAST,
    );
    r.process(0, &mut b, 0, n);
    assert_eq!(mac(&r), Some(HOST_A), "not believed");
    assert_eq!(r.stats.arp_conflicts, 1);
    // The router asks who really has 10.10.1.10, and A answers first.
    let asked = r
        .emits
        .iter()
        .any(|e| arp::parse(&e.frame[14..]).is_some_and(|a| a.tpa == ip("10.10.1.10")));
    assert!(asked);
    let (mut b, n) = arp_frame(arp::OP_REPLY, HOST_A, "10.10.1.10", "10.10.1.1", R0);
    r.process(0, &mut b, 0, n);
    // Eve's answer is too late: there's no question open any more.
    let (mut b, n) = arp_frame(arp::OP_REPLY, EVE, "10.10.1.10", "10.10.1.1", R0);
    r.process(0, &mut b, 0, n);
    assert_eq!(mac(&r), Some(HOST_A));
}

#[test]
fn a_moved_host_is_learned_after_checking() {
    const NEW: Mac = [0x52, 0x54, 0, 0, 0, 0x99];
    let mut r = router();
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    // Gratuitous ARP for the address with a new MAC (e.g. a failover).
    let (mut b, n) = arp_frame(
        arp::OP_REQUEST,
        NEW,
        "10.10.1.10",
        "10.10.1.10",
        eth::BROADCAST,
    );
    r.process(0, &mut b, 0, n);
    // Only the new owner answers the check.
    let (mut b, n) = arp_frame(arp::OP_REPLY, NEW, "10.10.1.10", "10.10.1.1", R0);
    r.process(0, &mut b, 0, n);
    let mac = r.neighbors().find(|x| x.port == 0).map(|x| x.mac);
    assert_eq!(mac, Some(NEW));
}

#[test]
fn neighbors_are_rechecked_and_forgotten() {
    let mut r = router();
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    // Five minutes on: still used, but an ARP request re-checks it.
    r.set_time(10_000_000_000 + 301_000_000_000);
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    assert_eq!(port_of_tx(r.process(0, &mut b, 0, n)), 1);
    assert_eq!(r.emits.len(), 1);
    // Twenty minutes without an answer: forgotten.
    r.set_time(10_000_000_000 + 1_201_000_000_000);
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    assert_eq!(
        dropped(r.process(0, &mut b, 0, n)),
        DropReason::NeighborMiss
    );
}

#[test]
fn icmp_errors_quoting_a_short_header_are_not_related() {
    let mut r = resolved(true);
    // Destination Unreachable quoting a "header" with IHL 1.
    let (mut b, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    b[34] = icmp::DEST_UNREACHABLE;
    b[42] = 0x41;
    b[36..38].fill(0);
    let c = checksum::checksum(&b[34..n]);
    b[36..38].copy_from_slice(&c.to_be_bytes());
    // Handled as unrelated ICMP: forwarded from a port that may start sessions.
    assert_eq!(port_of_tx(r.process(0, &mut b, 0, n)), 1);
}

#[test]
fn the_neighbor_table_is_bounded() {
    let mut r = router();
    for i in 0..16384u32 {
        let ip = Ipv4Addr::from(0x0a40_0000 + i);
        r.learn(Neighbor {
            port: 0,
            ip,
            mac: HOST_A,
        });
    }
    assert_eq!(r.neighbors().count(), 16384);
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    assert_eq!(r.neighbors().count(), 16384, "full: nothing new is learned");
    // Once the old entries have been forgotten, there is room again.
    r.set_time(10_000_000_000 + 1_201_000_000_000);
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    assert!(r.neighbors().any(|n| n.mac == HOST_B));
}

// ---------------------------------------------------------------- DHCP

/// A DHCP DISCOVER as a client sends it: no address yet, to everyone.
fn dhcp_discover(src_mac: Mac) -> (Vec<u8>, usize) {
    use eph_packet::dhcp;
    let mut m = dhcp::Message::new(dhcp::OP_REQUEST, 7, src_mac);
    m.set(dhcp::OPT_MSG_TYPE, vec![dhcp::DISCOVER]);
    let f = dhcp::build_frame(
        src_mac,
        eth::BROADCAST,
        (Ipv4Addr::UNSPECIFIED, dhcp::CLIENT_PORT),
        (Ipv4Addr::BROADCAST, dhcp::SERVER_PORT),
        &m.encode(),
    );
    let n = f.len();
    (f, n)
}

#[test]
fn dhcp_goes_to_the_control_plane_only_where_enabled() {
    let mut r = router();
    // Not enabled: an ordinary (dropped) broadcast, nothing handed over.
    let (mut f, n) = dhcp_discover(HOST_A);
    assert_ne!(
        r.process(0, &mut f, 0, n),
        Verdict::Drop(DropReason::DhcpToControl)
    );
    assert!(r.punts.is_empty());

    // Serving DHCP on lan-a: the DISCOVER is handed over, whole.
    let mut ports = r.ports().to_vec();
    ports[0].dhcp = Dhcp::Server;
    r.set_ports(ports.into());
    let (mut f, n) = dhcp_discover(HOST_A);
    assert_eq!(
        r.process(0, &mut f, 0, n),
        Verdict::Drop(DropReason::DhcpToControl)
    );
    assert_eq!(r.punts.len(), 1);
    assert_eq!(r.punts[0].port, 0);
    assert_eq!(r.punts[0].frame, f[..n]);
    // ...but not on the other port.
    let (mut f, n) = dhcp_discover(HOST_B);
    r.process(1, &mut f, 0, n);
    assert_eq!(r.punts.len(), 1);
}

// ---------------------------------------------------------------- PPPoE

const AC: Mac = [0x02, 0, 0, 0, 0, 0xac];

/// lan-b as a PPPoE link: our address 203.0.113.50/32, the ISP's end
/// 203.0.113.1, session 0x42, default route through it.
fn pppoe_router(state: Pppoe) -> Pipeline {
    let mut r = router();
    let mut ports = r.ports().to_vec();
    ports[1].addr = ip("203.0.113.50");
    ports[1].subnet = "203.0.113.50/32".parse().unwrap();
    ports[1].gateway = Some(ip("203.0.113.1"));
    ports[1].role = Role::Outside;
    ports[1].pppoe = state;
    if let Pppoe::Up { mtu, .. } = state {
        // As the config builds it: the far end is on-link, the MTU 1492.
        ports[1].onlink = vec!["203.0.113.1/32".parse().unwrap()];
        ports[1].mtu = mtu;
    }
    // The default route through the ISP exists once the session is up.
    let statics: Vec<StaticRoute> = match state {
        Pppoe::Up { .. } => vec![StaticRoute {
            prefix: "0.0.0.0/0".parse().unwrap(),
            via: ip("203.0.113.1"),
        }],
        _ => vec![],
    };
    let fib = build_fib(&ports, &statics, &[]).unwrap();
    r.set_ports(ports.into());
    r.set_fib(Arc::new(fib));
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    r
}

const UP: Pppoe = Pppoe::Up {
    session: 0x42,
    peer: AC,
    mtu: 1492,
};

#[test]
fn pppoe_wraps_outgoing_and_unwraps_incoming() {
    let mut r = pppoe_router(UP);
    // Out: host A pings the internet. Leaves wrapped, to the AC, no ARP.
    let mut f = vec![0u8; 2048];
    let (p, n) = ping(R0, HOST_A, "10.10.1.10", "8.8.8.8", 64);
    f[256..256 + n].copy_from_slice(&p[..n]);
    let Verdict::Tx { port, off, len } = r.process(0, &mut f, 256, n) else {
        panic!("not sent")
    };
    assert_eq!(
        (port, off, len),
        (1, 256 - 8, n + 8),
        "8 bytes in front, nothing copied"
    );
    let o = &f[off..off + len];
    assert_eq!(
        (eth::dst(o), eth::src(o), eth::ethertype(o)),
        (AC, R1, pppoe::TYPE_SESSION)
    );
    assert_eq!(
        &o[14..22],
        &[
            0x11,
            0x00,
            0x00,
            0x42,
            ((n - 14 + 2) >> 8) as u8,
            (n - 14 + 2) as u8,
            0x00,
            0x21
        ]
    );
    let inner = ipv4::parse(&o[22..]).unwrap();
    assert_eq!(
        (inner.src, inner.dst, inner.ttl),
        (ip("203.0.113.50"), ip("8.8.8.8"), 63),
        "NATed, one hop"
    );

    // In: the reply, wrapped by the ISP, reaches host A as plain Ethernet.
    let mut reply = o.to_vec();
    let ip_off = 22;
    reply[ip_off + 12..ip_off + 16].copy_from_slice(&[8, 8, 8, 8]);
    reply[ip_off + 16..ip_off + 20].copy_from_slice(&[203, 0, 113, 50]);
    reply[ip_off + 20] = icmp::ECHO_REPLY;
    reply[ip_off + 22..ip_off + 24].fill(0);
    let c = checksum::checksum(&reply[ip_off + 20..]);
    reply[ip_off + 22..ip_off + 24].copy_from_slice(&c.to_be_bytes());
    reply[ip_off + 10..ip_off + 12].fill(0);
    let c = checksum::checksum(&reply[ip_off..ip_off + 20]);
    reply[ip_off + 10..ip_off + 12].copy_from_slice(&c.to_be_bytes());
    eth::write(&mut reply, R1, AC, pppoe::TYPE_SESSION);
    let mut g = vec![0u8; 2048];
    g[256..256 + reply.len()].copy_from_slice(&reply);
    let Verdict::Tx { port, off, .. } = r.process(1, &mut g, 256, reply.len()) else {
        panic!("reply not forwarded")
    };
    assert_eq!(
        (port, eth::dst(&g[off..]), eth::ethertype(&g[off..])),
        (0, HOST_A, eth::TYPE_IPV4)
    );
    assert_eq!(
        ipv4::parse(&g[off + 14..]).unwrap().dst,
        ip("10.10.1.10"),
        "un-NATed"
    );
    // Counted per interface.
    assert_eq!(r.stats.ports[1].rx_packets, 1);
}

/// An interface MTU below 1500 (e.g. a tunnel or a provider's limit):
/// bigger packets with DF get "fragmentation needed" with that MTU.
#[test]
fn interface_mtu_is_enforced() {
    let mut r = router();
    let mut ports = r.ports().to_vec();
    ports[1].mtu = 1400;
    r.set_ports(ports.into());
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    let big = |len: u16| {
        let (mut f, _) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
        let n = 14 + len as usize;
        f.resize(n + 256, 0);
        f[14 + 2..14 + 4].copy_from_slice(&len.to_be_bytes());
        f[14 + 6] |= 0x40; // DF
        f[14 + 10..14 + 12].fill(0);
        let c = checksum::checksum(&f[14..34]);
        f[14 + 10..14 + 12].copy_from_slice(&c.to_be_bytes());
        (f, n)
    };
    let (mut f, n) = big(1450);
    let v = r.process(0, &mut f, 0, n);
    let Verdict::Tx { port, off, len } = v else {
        panic!("expected an ICMP error, got {v:?}")
    };
    assert_eq!(port, 0, "back to the sender");
    let e = &f[off + 14..off + len];
    assert_eq!(
        (e[20], e[21]),
        (icmp::DEST_UNREACHABLE, icmp::CODE_FRAG_NEEDED)
    );
    assert_eq!(u16::from_be_bytes([e[26], e[27]]), 1400);
    // Exactly the MTU fits (no error; it waits for ARP or goes out).
    let (mut f, n) = big(1400);
    assert!(!matches!(
        r.process(0, &mut f, 0, n),
        Verdict::Tx { port: 0, .. }
    ));
}

#[test]
fn pppoe_mtu_and_control_traffic() {
    let mut r = pppoe_router(UP);
    // 1500 bytes with DF doesn't fit 1492: "fragmentation needed, MTU 1492".
    let (mut f, n) = ping(R0, HOST_A, "10.10.1.10", "8.8.8.8", 64);
    let big = 14 + 1500;
    f.resize(big + 256, 0);
    f[14 + 2..14 + 4].copy_from_slice(&1500u16.to_be_bytes());
    f[14 + 10..14 + 12].fill(0);
    let c = checksum::checksum(&f[14..34]);
    f[14 + 10..14 + 12].copy_from_slice(&c.to_be_bytes());
    let _ = n;
    let Verdict::Tx { port, off, len } = r.process(0, &mut f, 0, big) else {
        panic!()
    };
    assert_eq!(port, 0, "an ICMP error back to the sender");
    let e = &f[off + 14..off + len];
    assert_eq!(
        (e[20], e[21]),
        (icmp::DEST_UNREACHABLE, icmp::CODE_FRAG_NEEDED)
    );
    assert_eq!(u16::from_be_bytes([e[26], e[27]]), 1492);

    // Discovery and PPP control go to the control plane.
    let padt = pppoe::discovery(AC, R1, pppoe::PADT, 0x42, &[]);
    let mut f = padt.clone();
    assert_eq!(
        r.process(1, &mut f, 0, padt.len()),
        Verdict::Drop(DropReason::PppoeToControl)
    );
    let echo = pppoe::session(AC, R1, 0x42, pppoe::PROTO_LCP, &[9, 1, 0, 8, 1, 2, 3, 4]);
    let mut f = echo.clone();
    assert_eq!(
        r.process(1, &mut f, 0, echo.len()),
        Verdict::Drop(DropReason::PppoeToControl)
    );
    assert_eq!(r.punts.len(), 2);

    // Still dialling: nothing leaves, and no ARP is tried on the link.
    let mut r = pppoe_router(Pppoe::Dialing);
    let (mut f, n) = ping(R0, HOST_A, "10.10.1.10", "8.8.8.8", 64);
    // (Host A hears "network unreachable"; nothing goes out of lan-b.)
    assert!(!matches!(
        r.process(0, &mut f, 0, n),
        Verdict::Tx { port: 1, .. }
    ));
    assert!(r.emits.is_empty(), "no ARP request on a PPPoE link");
}

/// Packet tracing: switched-on categories record what happened to a
/// packet, only for the filtered host, and nothing at all when off.
#[test]
fn tracing_records_what_happened_to_packets() {
    use crate::trace::{TraceCat, TraceConfig, TraceKind};
    let mut r = router();
    // Known, so the ICMP errors back to A go straight out.
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    let kinds = |r: &mut Pipeline| -> Vec<(TraceCat, TraceKind)> {
        r.tracer
            .events
            .drain(..)
            .map(|e| (e.cat(), e.kind))
            .collect()
    };
    // Off: nothing recorded.
    let (mut f, n) = ping(R0, HOST_A, "10.10.1.10", "8.8.8.8", 64);
    r.process(0, &mut f, 0, n);
    assert!(r.tracer.events.is_empty());

    let all = [
        TraceCat::Route,
        TraceCat::Icmp,
        TraceCat::Arp,
        TraceCat::Session,
    ]
    .iter()
    .fold(0, |m, c| m | c.bit());
    r.set_trace(TraceConfig {
        mask: all,
        host: Some("10.10.1.10/32".parse().unwrap()),
        per_sec: 100,
    });
    // No route to 8.8.8.8: the drop, and the ICMP error sent instead.
    let (mut f, n) = ping(R0, HOST_A, "10.10.1.10", "8.8.8.8", 64);
    r.process(0, &mut f, 0, n);
    assert_eq!(
        kinds(&mut r),
        [
            (TraceCat::Route, TraceKind::Drop(DropReason::NoRoute)),
            (
                TraceCat::Icmp,
                TraceKind::IcmpSent {
                    kind: icmp::DEST_UNREACHABLE,
                    code: 0
                }
            ),
        ]
    );
    // To host B, not yet resolved: a new session, then an ARP request for B
    // and the drop waiting for it.
    let (mut f, n) = ping(R0, HOST_A, "10.10.1.10", "10.10.2.10", 64);
    r.process(0, &mut f, 0, n);
    let k = kinds(&mut r);
    assert!(
        k.contains(&(TraceCat::Session, TraceKind::SessionNew)),
        "{k:?}"
    );
    assert!(
        k.contains(&(TraceCat::Arp, TraceKind::Drop(DropReason::NeighborMiss))),
        "{k:?}"
    );
    // The ARP request has no host in it the filter matches (it's for B).
    // Another host's traffic isn't traced at all.
    let (mut f, n) = ping(R0, [0x52, 0x54, 0, 0, 0, 0x99], "10.10.1.99", "8.8.8.8", 64);
    r.process(0, &mut f, 0, n);
    assert!(r.tracer.events.is_empty());
    // The flow is the packet's.
    r.set_trace(TraceConfig {
        mask: all,
        host: None,
        per_sec: 100,
    });
    let (mut f, n) = ping(R0, HOST_A, "10.10.1.10", "8.8.8.8", 64);
    r.process(0, &mut f, 0, n);
    let e = r.tracer.events[0];
    assert_eq!(
        (e.port, e.flow.proto, e.flow.src, e.flow.dst),
        (0, 1, ip("10.10.1.10"), ip("8.8.8.8"))
    );
    assert_eq!(
        (e.flow.sport, e.flow.dport),
        (icmp::ECHO_REQUEST as u16, 0),
        "ICMP type/code"
    );
}

// ------------------------------------------------------------ host path

/// A TCP segment with a correct checksum (seg leaves it zero).
fn tcp_ok(
    dst_mac: Mac,
    src_mac: Mac,
    src: (&str, u16),
    dst: (&str, u16),
    flags: u8,
) -> (Vec<u8>, usize) {
    let (mut b, n) = seg(dst_mac, src_mac, src, dst, Some(flags));
    let c = tcp_checksum(&b[14..n]);
    b[34 + 16..34 + 18].copy_from_slice(&c.to_be_bytes());
    (b, n)
}

/// The TCP checksum over pseudo-header and segment (0 if it's already right).
fn tcp_checksum(ip: &[u8]) -> u16 {
    let h = ipv4::parse(ip).unwrap();
    let seg = &ip[h.hdr_len..h.total_len];
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&ip[12..20]);
    pseudo.extend_from_slice(&[0, ipv4::PROTO_TCP]);
    pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    let mut s = checksum::sum(&pseudo, 0);
    s = checksum::sum(seg, s);
    // Inverted: the value for the field, or (with a correct field in place)
    // zero.
    !checksum::fold(s)
}

/// lan-a offers SSH and the portal; lan-b is outside and (wrongly, as if
/// the config had slipped) claims to offer them too.
fn host_router() -> Pipeline {
    let mut r = router();
    let mut ports = r.ports().to_vec();
    ports[0].host = host::HostAccess {
        https: true,
        ssh: true,
        from: vec![],
    };
    ports[1].role = Role::Outside;
    ports[1].host = ports[0].host.clone();
    r.set_ports(ports.into());
    learn(&mut r, 0, HOST_A, "10.10.1.10");
    r
}

const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;

#[test]
fn ssh_and_the_portal_reach_the_host_on_an_inside_port() {
    let mut r = host_router();
    for port in [host::SSH_PORT, host::HTTPS_PORT] {
        let (mut f, n) = tcp_ok(R0, HOST_A, ("10.10.1.10", 50000), ("10.10.1.1", port), SYN);
        assert_eq!(
            r.process(0, &mut f, 0, n),
            Verdict::Drop(DropReason::ToHost)
        );
        let p = r.host_out.pop().expect("handed to the host");
        let h = ipv4::parse(&p).unwrap();
        assert_eq!(
            (h.src, h.dst),
            (ip("10.10.1.10"), ip("169.254.240.1")),
            "the client stays visible"
        );
        assert_eq!(tcp_checksum(&p), 0, "checksums still right");
        assert_eq!(u16::from_be_bytes([p[22], p[23]]), port);
    }
    // Other ports on the router stay closed.
    let (mut f, n) = tcp_ok(R0, HOST_A, ("10.10.1.10", 50000), ("10.10.1.1", 80), SYN);
    assert_eq!(
        r.process(0, &mut f, 0, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
    assert!(r.host_out.is_empty());
}

#[test]
fn never_from_the_outside() {
    let mut r = host_router();
    // To the outside port's own address, on the outside port.
    let (mut f, n) = tcp_ok(
        R1,
        HOST_B,
        ("10.10.2.10", 50000),
        ("10.10.2.1", host::SSH_PORT),
        SYN,
    );
    assert_eq!(
        r.process(1, &mut f, 0, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
    // To the inside address, arriving on the outside port.
    let (mut f, n) = tcp_ok(
        R1,
        HOST_B,
        ("10.10.2.10", 50000),
        ("10.10.1.1", host::HTTPS_PORT),
        SYN,
    );
    assert_ne!(
        r.process(1, &mut f, 0, n),
        Verdict::Drop(DropReason::ToHost)
    );
    // An inside client, but to the outside port's address.
    let (mut f, n) = tcp_ok(
        R0,
        HOST_A,
        ("10.10.1.10", 50000),
        ("10.10.2.1", host::SSH_PORT),
        SYN,
    );
    assert_ne!(
        r.process(0, &mut f, 0, n),
        Verdict::Drop(DropReason::ToHost)
    );
    assert!(r.host_out.is_empty());
}

#[test]
fn only_from_the_allowed_sources() {
    let mut r = host_router();
    let mut ports = r.ports().to_vec();
    ports[0].host.from = vec!["10.10.1.0/28".parse().unwrap()];
    r.set_ports(ports.into());
    let (mut f, n) = tcp_ok(
        R0,
        HOST_A,
        ("10.10.1.10", 50000),
        ("10.10.1.1", host::SSH_PORT),
        SYN,
    );
    assert_eq!(
        r.process(0, &mut f, 0, n),
        Verdict::Drop(DropReason::ToHost)
    );
    let (mut f, n) = tcp_ok(
        R0,
        HOST_A,
        ("10.10.1.20", 50000),
        ("10.10.1.1", host::SSH_PORT),
        SYN,
    );
    assert_eq!(
        r.process(0, &mut f, 0, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
}

#[test]
fn replies_go_back_with_the_port_address_and_nothing_else_gets_out() {
    let mut r = host_router();
    let reply = |src: (&str, u16), dst: (&str, u16), flags: u8| {
        let (b, n) = tcp_ok([0; 6], [0; 6], src, dst, flags);
        let mut f = vec![0u8; 2048];
        f[256..256 + n].copy_from_slice(&b[..n]);
        (f, n)
    };
    // sshd's SYN-ACK: leaves lan-a as 10.10.1.1, to host A's MAC.
    let (mut f, n) = reply(
        ("169.254.240.1", host::SSH_PORT),
        ("10.10.1.10", 50000),
        SYN_ACK,
    );
    let Verdict::Tx { port, off, len } = r.inject_host(&mut f, 256, n) else {
        panic!("not sent")
    };
    assert_eq!(port, 0);
    let o = &f[off..off + len];
    assert_eq!((eth::dst(o), eth::src(o)), (HOST_A, R0));
    let h = ipv4::parse(&o[14..]).unwrap();
    assert_eq!((h.src, h.dst), (ip("10.10.1.1"), ip("10.10.1.10")));
    assert_eq!(tcp_checksum(&o[14..]), 0);

    // Not from SSH or the portal (the host starting something of its own).
    let (mut f, n) = reply(("169.254.240.1", 80), ("10.10.1.10", 50000), SYN);
    assert_eq!(
        r.inject_host(&mut f, 256, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
    // As the outside port.
    let (mut f, n) = reply(
        ("169.254.240.2", host::SSH_PORT),
        ("10.10.2.10", 50000),
        SYN_ACK,
    );
    assert_eq!(
        r.inject_host(&mut f, 256, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
    // Towards the outside, even as an inside port.
    let (mut f, n) = reply(
        ("169.254.240.1", host::SSH_PORT),
        ("10.10.2.10", 50000),
        SYN_ACK,
    );
    assert_eq!(
        r.inject_host(&mut f, 256, n),
        Verdict::Drop(DropReason::NoRoute)
    );
    // Not a host-side address at all.
    let (mut f, n) = reply(
        ("10.10.1.1", host::SSH_PORT),
        ("10.10.1.10", 50000),
        SYN_ACK,
    );
    assert_eq!(
        r.inject_host(&mut f, 256, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
}

/// The router's own connections out through the data plane (see
/// `host::SELF_ADDR`): host packets at offset 256 of a frame.
fn from_host(src: (&str, u16), dst: (&str, u16), flags: u8) -> (Vec<u8>, usize) {
    let (b, n) = tcp_ok([0; 6], [0; 6], src, dst, flags);
    let mut f = vec![0u8; 2048];
    f[256..256 + n].copy_from_slice(&b[..n]);
    (f, n)
}

const ACK: u8 = 0x10;

#[test]
fn the_routers_own_connections_go_out_through_the_data_plane() {
    let mut r = host_router();
    learn(&mut r, 1, HOST_B, "10.10.2.10");
    let me = ("169.254.255.254", 40000);
    // Off unless asked for.
    let (mut f, n) = from_host(me, ("10.10.2.10", 443), SYN);
    assert_eq!(
        r.inject_host(&mut f, 256, n),
        Verdict::Drop(DropReason::LocalUnhandled)
    );
    r.set_host_outbound(true);

    // Out of lan-b with lan-b's address, like a LAN host behind NAT.
    let Verdict::Tx { port, off, len } = r.inject_host(&mut f, 256, n) else {
        panic!("not sent")
    };
    assert_eq!(port, 1);
    let o = f[off..off + len].to_vec();
    assert_eq!((eth::dst(&o), eth::src(&o)), (HOST_B, R1));
    let h = ipv4::parse(&o[14..]).unwrap();
    assert_eq!((h.src, h.dst), (ip("10.10.2.1"), ip("10.10.2.10")));
    assert_eq!(tcp_checksum(&o[14..]), 0);
    let nat_port = u16::from_be_bytes([o[34], o[35]]);

    // The reply goes into the host path, back to the router's address.
    let (mut b, n) = tcp_ok(
        R1,
        HOST_B,
        ("10.10.2.10", 443),
        ("10.10.2.1", nat_port),
        SYN_ACK,
    );
    assert_eq!(
        r.process(1, &mut b, 0, n),
        Verdict::Drop(DropReason::ToHost)
    );
    let p = r.host_out.pop().expect("handed to the host");
    let h = ipv4::parse(&p).unwrap();
    assert_eq!((h.src, h.dst), (ip("10.10.2.10"), ip("169.254.255.254")));
    assert_eq!(u16::from_be_bytes([p[22], p[23]]), 40000);
    assert_eq!(tcp_checksum(&p), 0);

    // The rest of the connection follows its session.
    let (mut f, n) = from_host(me, ("10.10.2.10", 443), ACK);
    assert!(matches!(
        r.inject_host(&mut f, 256, n),
        Verdict::Tx { port: 1, .. }
    ));

    // Nobody outside can start a connection to the router this way...
    let (mut b, n) = tcp_ok(
        R1,
        HOST_B,
        ("10.10.2.10", 443),
        ("10.10.2.1", nat_port ^ 1),
        SYN,
    );
    assert_ne!(
        r.process(1, &mut b, 0, n),
        Verdict::Drop(DropReason::ToHost)
    );
    assert!(r.host_out.is_empty());
    // ...nor reach its address directly.
    let (mut b, n) = tcp_ok(
        R1,
        HOST_B,
        ("10.10.2.10", 443),
        ("169.254.255.254", 40000),
        ACK,
    );
    assert_eq!(
        r.process(1, &mut b, 0, n),
        Verdict::Drop(DropReason::Martian)
    );
    // And the host can't send to the router's own addresses or link-local
    // ones through it.
    for dst in ["10.10.1.1", "169.254.1.1", "10.10.2.255", "224.0.0.1"] {
        let (mut f, n) = from_host(me, (dst, 443), SYN);
        assert_eq!(
            r.inject_host(&mut f, 256, n),
            Verdict::Drop(DropReason::LocalUnhandled),
            "{dst}"
        );
    }
}
