//! Port forwards (destination NAT) and firewall rules, on the network of
//! `tests_nat`: a web server, host A (10.0.0.10), behind the router's
//! outside address 203.0.113.1.

use crate::nat::{FirewallRule, Forward, NatConfig, Side};
use crate::tests_nat::*;
use crate::*;
use eph_packet::{eth, ipv4, l4};

const CLIENT: &str = "198.51.100.7";

fn web() -> Forward {
    Forward {
        name: "web".into(),
        port: 1,
        proto: ipv4::PROTO_TCP,
        ports: (8080, 8080),
        to: ip("10.0.0.10"),
        to_port: 80,
        from: vec![],
    }
}

fn with(forwards: Vec<Forward>, firewall: Vec<FirewallRule>) -> NatConfig {
    NatConfig {
        forwards,
        firewall,
        ..NatConfig::default()
    }
}

fn from_client(dport: u16, flags: u8) -> (Vec<u8>, usize) {
    packet(
        R_WAN,
        ISP,
        CLIENT,
        "203.0.113.1",
        L4::Tcp(40000, dport, flags),
    )
}

#[test]
fn a_forward_carries_a_session_in_and_its_replies_out() {
    let mut r = router(with(vec![web()], vec![]));
    let (mut f, n) = from_client(8080, l4::TCP_SYN);
    let (port, off, len) = tx(r.process(1, &mut f, OFF, n));
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_A));
    let h = hdr(&f, off, len);
    assert_eq!((h.src, h.dst), (ip(CLIENT), ip("10.0.0.10")));
    assert_eq!(ports_of(&f, off), (40000, 80));
    assert_eq!(l4_sum(&f[off + 14..off + len]), 0, "TCP checksum valid");

    // The server's answer leaves as the router's address and public port.
    let (mut f, n) = packet(
        R_LAN,
        HOST_A,
        "10.0.0.10",
        CLIENT,
        L4::Tcp(80, 40000, l4::TCP_SYN | l4::TCP_ACK),
    );
    let (port, off, len) = tx(r.process(0, &mut f, OFF, n));
    assert_eq!(port, 1);
    let h = hdr(&f, off, len);
    assert_eq!((h.src, h.dst), (ip("203.0.113.1"), ip(CLIENT)));
    assert_eq!(ports_of(&f, off), (8080, 40000));
    assert_eq!(l4_sum(&f[off + 14..off + len]), 0);

    // The rest of the connection follows the session.
    let (mut f, n) = from_client(8080, l4::TCP_ACK);
    let (port, off, _) = tx(r.process(1, &mut f, OFF, n));
    assert_eq!((port, ports_of(&f, off)), (0, (40000, 80)));
    // Straight to the server's own address, around the forward: no.
    let (mut f, n) = packet(
        R_WAN,
        ISP,
        CLIENT,
        "10.0.0.10",
        L4::Tcp(40000, 80, l4::TCP_ACK),
    );
    assert_eq!(
        dropped(r.process(1, &mut f, OFF, n)),
        DropReason::SessionMismatch
    );
}

#[test]
fn a_forward_takes_only_its_ports_and_sources() {
    let range = Forward {
        name: "game".into(),
        proto: ipv4::PROTO_UDP,
        ports: (27015, 27020),
        to: ip("10.0.0.11"),
        to_port: 37015,
        from: vec!["198.51.100.0/24".parse().unwrap()],
        ..web()
    };
    let mut r = router(with(vec![web(), range], vec![]));
    // An offset into the range lands at the same offset there.
    let (mut f, n) = packet(R_WAN, ISP, CLIENT, "203.0.113.1", L4::Udp(5000, 27017));
    let (port, off, _) = tx(r.process(1, &mut f, OFF, n));
    assert_eq!(
        (port, eth::dst(&f[off..]), ports_of(&f, off)),
        (0, HOST_B, (5000, 37017))
    );
    // From outside the allowed sources, or to another port: for the
    // router, which has nothing there.
    let (mut f, n) = packet(R_WAN, ISP, "192.0.2.9", "203.0.113.1", L4::Udp(5000, 27017));
    assert!(matches!(r.process(1, &mut f, OFF, n), Verdict::Drop(_)));
    let (mut f, n) = from_client(8081, l4::TCP_SYN);
    assert!(matches!(r.process(1, &mut f, OFF, n), Verdict::Drop(_)));
    // UDP to the TCP forward's port: not it either.
    let (mut f, n) = packet(R_WAN, ISP, CLIENT, "203.0.113.1", L4::Udp(5000, 8080));
    assert!(matches!(r.process(1, &mut f, OFF, n), Verdict::Drop(_)));
}

#[test]
fn firewall_rules_decide_new_sessions() {
    let rules = vec![
        // No mail out from the LAN.
        FirewallRule {
            name: "no smtp".into(),
            allow: false,
            from: Side::Port(0),
            to: Side::Port(1),
            proto: Some(ipv4::PROTO_TCP),
            ports: Some((25, 25)),
        },
        // The forward only from one network.
        FirewallRule {
            name: "web from partners".into(),
            allow: false,
            from: Side::Prefix("192.0.2.0/24".parse().unwrap()),
            to: Side::Prefix("10.0.0.10/32".parse().unwrap()),
            proto: None,
            ports: None,
        },
        // SSH straight to host B (routed, no NAT), which the outside
        // interface alone wouldn't allow.
        FirewallRule {
            name: "ssh to b".into(),
            allow: true,
            from: Side::Port(1),
            to: Side::Prefix("10.0.0.11/32".parse().unwrap()),
            proto: Some(ipv4::PROTO_TCP),
            ports: Some((22, 22)),
        },
    ];
    let mut r = router(with(vec![web()], rules));
    let (mut f, n) = packet(
        R_LAN,
        HOST_A,
        "10.0.0.10",
        "8.8.8.8",
        L4::Tcp(40000, 25, l4::TCP_SYN),
    );
    assert_eq!(dropped(r.process(0, &mut f, OFF, n)), DropReason::Firewall);
    let (mut f, n) = packet(
        R_LAN,
        HOST_A,
        "10.0.0.10",
        "8.8.8.8",
        L4::Tcp(40000, 443, l4::TCP_SYN),
    );
    assert_eq!(tx(r.process(0, &mut f, OFF, n)).0, 1, "the rest goes out");

    let (mut f, n) = packet(
        R_WAN,
        ISP,
        "192.0.2.9",
        "203.0.113.1",
        L4::Tcp(40000, 8080, l4::TCP_SYN),
    );
    assert_eq!(dropped(r.process(1, &mut f, OFF, n)), DropReason::Firewall);
    let (mut f, n) = from_client(8080, l4::TCP_SYN);
    assert_eq!(tx(r.process(1, &mut f, OFF, n)).0, 0);

    let (mut f, n) = packet(
        R_WAN,
        ISP,
        CLIENT,
        "10.0.0.11",
        L4::Tcp(40000, 22, l4::TCP_SYN),
    );
    assert_eq!(tx(r.process(1, &mut f, OFF, n)).0, 0);
    let (mut f, n) = packet(
        R_WAN,
        ISP,
        CLIENT,
        "10.0.0.11",
        L4::Tcp(40000, 23, l4::TCP_SYN),
    );
    assert_eq!(dropped(r.process(1, &mut f, OFF, n)), DropReason::NoSession);
}

/// Two workers, cards that can't be steered: a forward's session is made
/// on the worker a fixed hash picks, and both directions are handed there.
#[test]
fn a_forwards_session_lives_on_one_worker() {
    let mut workers: Vec<Pipeline> = (0..2)
        .map(|w| {
            let mut r = router(with(vec![web()], vec![]));
            r.set_worker(w, 2);
            r
        })
        .collect();
    let verdicts: Vec<Verdict> = workers
        .iter_mut()
        .map(|r| {
            let (mut f, n) = from_client(8080, l4::TCP_SYN);
            r.process(1, &mut f, OFF, n)
        })
        .collect();
    let owner = verdicts
        .iter()
        .position(|v| matches!(v, Verdict::Tx { .. }))
        .expect("one worker makes the session");
    assert_eq!(verdicts[1 - owner], Verdict::Drop(DropReason::HandedOff));
    // The server's reply, wherever it lands, reaches that worker.
    let reply = || {
        packet(
            R_LAN,
            HOST_A,
            "10.0.0.10",
            CLIENT,
            L4::Tcp(80, 40000, l4::TCP_SYN | l4::TCP_ACK),
        )
    };
    let (mut f, n) = reply();
    assert_eq!(
        workers[1 - owner].process(0, &mut f, OFF, n),
        Verdict::Drop(DropReason::HandedOff)
    );
    let (mut f, n) = reply();
    let (port, off, _) = tx(workers[owner].process(0, &mut f, OFF, n));
    assert_eq!((port, ports_of(&f, off)), (1, (8080, 40000)));
}
