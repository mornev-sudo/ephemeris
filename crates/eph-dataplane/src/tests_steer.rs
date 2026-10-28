//! Several workers behind one network card: NAT ports chosen so replies
//! land on the worker that made the translation, and packets that land
//! elsewhere anyway handed to it (see `steer`).

use crate::nat::NatConfig;
use crate::steer::{CardRss, Steering};
use crate::tests_nat::{packet, ports_of, router, tx, HOST_A, ISP, L4, OFF, R_LAN, R_WAN};
use crate::*;
use eph_packet::{eth, icmp, ipv4};
use std::sync::Arc;

const WORKERS: u16 = 4;

/// A WAN card (card 1) that spreads over 4 queues, as a real NIC does.
fn steering(udp_ports: bool) -> Arc<Steering> {
    let key: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(37) ^ 0x6d).collect();
    Arc::new(Steering::new(&[
        None,
        Some(CardRss {
            key,
            indir: (0..128).map(|i| i % WORKERS).collect(),
            symmetric: false,
            tcp_ports: true,
            udp_ports,
        }),
    ]))
}

fn worker(id: u16, steer: &Arc<Steering>) -> Pipeline {
    let mut r = router(NatConfig::default());
    r.set_worker(id, WORKERS);
    r.set_steering(steer.clone());
    r
}

/// Host A's packet out through worker `r`: its translated source port.
fn out_port(r: &mut Pipeline, l4: L4) -> u16 {
    let (mut f, n) = packet(R_LAN, HOST_A, "10.0.0.10", "8.8.8.8", l4);
    let (port, off, _) = tx(r.process(0, &mut f, OFF, n));
    assert_eq!(port, 1);
    ports_of(&f, off).0
}

fn reply_queue(s: &Steering, proto: u8, nat_port: u16) -> u16 {
    s.queue(1, proto, (ip("8.8.8.8"), 53), (ip("203.0.113.1"), nat_port))
        .unwrap()
}

fn ip(s: &str) -> std::net::Ipv4Addr {
    s.parse().unwrap()
}

#[test]
fn nat_ports_are_chosen_so_replies_come_back_to_their_worker() {
    let s = steering(true);
    let mut kept = 0;
    for w in 0..WORKERS {
        let mut r = worker(w, &s);
        for i in 0..64u16 {
            let sport = 30000 + i;
            let p = out_port(&mut r, L4::Udp(sport, 53));
            assert_eq!(reply_queue(&s, 17, p), w, "UDP port {p} from worker {w}");
            kept += (p == sport) as u32;
            let p = out_port(&mut r, L4::Tcp(sport, 53, eph_packet::l4::TCP_SYN));
            assert_eq!(reply_queue(&s, 6, p), w, "TCP port {p} from worker {w}");
        }
    }
    // The client's own port is kept when its reply lands here anyway:
    // about a quarter of the time.
    assert!((30..100).contains(&kept), "kept {kept} of 256");
}

#[test]
fn a_reply_lands_on_its_worker_and_is_delivered() {
    let s = steering(true);
    let mut r = worker(2, &s);
    let p = out_port(&mut r, L4::Udp(5000, 53));
    let (mut f, n) = packet(R_WAN, ISP, "8.8.8.8", "203.0.113.1", L4::Udp(53, p));
    let (port, off, _) = tx(r.process(1, &mut f, OFF, n));
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_A));
    assert!(r.handoffs.is_empty());
}

/// Whatever lands on the wrong worker: handed to `owner`, which delivers it
/// to host A.
fn handed_and_delivered(wrong: &mut Pipeline, owner: &mut Pipeline, (mut f, n): (Vec<u8>, usize)) {
    assert_eq!(
        wrong.process(1, &mut f, OFF, n),
        Verdict::Drop(DropReason::HandedOff)
    );
    let h = wrong.handoffs.pop().unwrap();
    assert_eq!(h.worker, owner.worker_id());
    let mut g = vec![0u8; 4096];
    g[OFF..OFF + h.frame.len()].copy_from_slice(&h.frame);
    let (port, off, _) = tx(owner.process_handed(h.ingress, h.via, &mut g, OFF, h.frame.len()));
    assert_eq!((port, eth::dst(&g[off..])), (0, HOST_A));
}

#[test]
fn icmp_errors_about_a_translated_packet_reach_its_worker() {
    // ICMP is hashed on addresses only: an error about a translated UDP
    // packet lands wherever, and is handed to the worker that owns it.
    let s = steering(true);
    let (mut owner, mut other) = (worker(2, &s), worker(0, &s));
    let (mut f, n) = packet(R_LAN, HOST_A, "10.0.0.10", "8.8.8.8", L4::Udp(5000, 53));
    let (_, off, len) = tx(owner.process(0, &mut f, OFF, n));
    let quoted = f[off + 14..off + len].to_vec();
    let ip_len = 20 + 8 + quoted.len();
    let mut e = vec![0u8; 4096];
    eth::write(&mut e[OFF..], R_WAN, ISP, eth::TYPE_IPV4);
    ipv4::write_header(
        &mut e[OFF + 14..],
        ip_len as u16,
        3,
        64,
        ipv4::PROTO_ICMP,
        ip("8.8.8.8"),
        ip("203.0.113.1"),
    );
    e[OFF + 42..OFF + 42 + quoted.len()].copy_from_slice(&quoted);
    icmp::write_error(
        &mut e[OFF + 34..],
        8 + quoted.len(),
        icmp::DEST_UNREACHABLE,
        3,
        0,
    );
    handed_and_delivered(&mut other, &mut owner, (e, 14 + ip_len));
}

#[test]
fn ping_replies_reach_their_worker() {
    let s = steering(true);
    let (mut owner, mut other) = (worker(3, &s), worker(1, &s));
    let (mut f, n) = packet(
        R_LAN,
        HOST_A,
        "10.0.0.10",
        "8.8.8.8",
        L4::Echo(icmp::ECHO_REQUEST, 7),
    );
    let (_, off, _) = tx(owner.process(0, &mut f, OFF, n));
    let id = u16::from_be_bytes([f[off + 38], f[off + 39]]);
    assert_eq!(id % WORKERS, 3, "ICMP can't be steered: the old split");
    let reply = packet(
        R_WAN,
        ISP,
        "8.8.8.8",
        "203.0.113.1",
        L4::Echo(icmp::ECHO_REPLY, id),
    );
    handed_and_delivered(&mut other, &mut owner, reply);
}

#[test]
fn a_reply_the_card_sends_elsewhere_still_arrives() {
    // The card hashes UDP on addresses only, so the port can't steer: the
    // old split by port, and hand-offs.
    let s = steering(false);
    let mut owner = worker(1, &s);
    let p = out_port(&mut owner, L4::Udp(5000, 53));
    assert_eq!(p % WORKERS, 1);
    let mut other = worker(2, &s);
    let reply = packet(R_WAN, ISP, "8.8.8.8", "203.0.113.1", L4::Udp(53, p));
    handed_and_delivered(&mut other, &mut owner, reply);
}

#[test]
fn without_card_settings_nothing_changes() {
    let none = Arc::new(Steering::default());
    for w in 0..WORKERS {
        let mut r = worker(w, &none);
        for i in 0..16 {
            assert_eq!(out_port(&mut r, L4::Udp(40000 + i, 53)) % WORKERS, w);
        }
    }
}

#[test]
fn junk_to_the_nat_address_is_handed_off_at_most_once() {
    let s = steering(true);
    let mut r = worker(0, &s);
    // Find a port another worker owns; nobody has a session for it.
    let p = (1024..).find(|&p| reply_queue(&s, 17, p) == 3).unwrap();
    let (mut f, n) = packet(R_WAN, ISP, "8.8.8.8", "203.0.113.1", L4::Udp(53, p));
    assert_eq!(
        r.process(1, &mut f, OFF, n),
        Verdict::Drop(DropReason::HandedOff)
    );
    let h = r.handoffs.pop().unwrap();
    let mut owner = worker(3, &s);
    let mut g = vec![0u8; 4096];
    g[OFF..OFF + h.frame.len()].copy_from_slice(&h.frame);
    assert_eq!(
        owner.process_handed(h.ingress, h.via, &mut g, OFF, h.frame.len()),
        Verdict::Drop(DropReason::NatNoSession)
    );
    assert!(owner.handoffs.is_empty());
}

#[test]
fn tether_traffic_goes_to_the_worker_its_lan_replies_reach() {
    use crate::tests_overlay as ov;
    // Site 2 with two workers; its LAN card (card 0) spreads like a real NIC.
    let key: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(53) ^ 0x5a).collect();
    let s = Arc::new(Steering::new(&[Some(CardRss {
        key,
        indir: (0..128).map(|i| i % 2).collect(),
        symmetric: true,
        tcp_ports: true,
        udp_ports: true,
    })]));
    let site2 = |w: u16| {
        let mut r = ov::router_full(2, Some(ov::KEY), false, false);
        r.set_worker(w, 2);
        r.set_steering(s.clone());
        r
    };
    let (mut w0, mut w1) = (site2(0), site2(1));
    let mut r1 = ov::router_full(1, Some(ov::KEY), false, false);
    // A connection from site 1 whose LAN-side replies land on worker 1, but
    // whose tether packet arrived at worker 0.
    let dport = (1..)
        .find(|&p| s.queue(0, 6, (ip("10.2.0.10"), p), (ip("10.1.0.10"), 40000)) == Some(1))
        .unwrap();
    let (mut f, n) = ov::packet(
        ov::mac(1, 0),
        ov::HOST_A,
        "10.1.0.10",
        "10.2.0.10",
        Some(dport),
        0,
        true,
    );
    let (_, off, len) = tx(r1.process(0, &mut f, OFF, n));
    assert_eq!(
        w0.process(1, &mut f, off, len),
        Verdict::Drop(DropReason::HandedOff)
    );
    let h = w0.handoffs.pop().unwrap();
    assert_eq!((h.worker, h.via), (1, Some(0)));
    let mut g = vec![0u8; 4096];
    g[OFF..OFF + h.frame.len()].copy_from_slice(&h.frame);
    let (port, off, _) = tx(w1.process_handed(h.ingress, h.via, &mut g, OFF, h.frame.len()));
    assert_eq!((port, eth::dst(&g[off..])), (0, ov::HOST_B));
    // The session is on worker 1, where host B's answer will arrive.
    w1.housekeeping();
    assert_eq!(w1.stats.sessions_active, 1);
}
