//! VLANs: several interfaces on one network card, told apart by their
//! 802.1Q tag.
//!
//! ```text
//!  card 0 (R0) ─┬─ p0 lan    untagged  10.10.1.1/24
//!               └─ p1 guest  VLAN 10   10.10.10.1/24
//!  card 1 (R1) ─┬─ p2 iot    VLAN 20   10.10.20.1/24
//!               └─ p3 wan    VLAN 7    PPPoE, 203.0.113.50/32
//! ```
//!
//! Card 1 has no untagged interface: untagged frames there are dropped.

use crate::overlay::Overlay;
use crate::*;
use eph_packet::{arp, checksum, eth, icmp, ipv4, pppoe, Mac};
use std::net::Ipv4Addr;
use std::sync::Arc;

const R0: Mac = [0x02, 0, 0, 0, 0, 0x01];
const R1: Mac = [0x02, 0, 0, 0, 0, 0x02];
const LAN_HOST: Mac = [0x52, 0x54, 0, 0, 0, 0x0a];
const GUEST: Mac = [0x52, 0x54, 0, 0, 0, 0x10];
const IOT: Mac = [0x52, 0x54, 0, 0, 0, 0x20];
const AC: Mac = [0x02, 0, 0, 0, 0, 0xac];
/// Where received packets start in a frame (the driver's headroom).
const HEAD: usize = 256;

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn port(id: u16, name: &str, card: u16, vlan: Option<u16>, mac: Mac, addr: &str) -> Port {
    Port {
        id,
        card,
        vlan,
        host: Default::default(),
        name: name.into(),
        mac,
        addr: ip(addr),
        subnet: eph_fib::Prefix::new(ip(addr), if vlan == Some(7) { 32 } else { 24 }).unwrap(),
        allow_new_sessions: vlan != Some(7),
        role: if vlan == Some(7) {
            Role::Outside
        } else {
            Role::Inside
        },
        mss_adjust: None,
        dhcp: Dhcp::Off,
        gateway: None,
        pppoe: Pppoe::Off,
        onlink: vec![],
        mtu: 1500,
    }
}

fn router(wan: Pppoe) -> Pipeline {
    let mut wan_port = port(3, "wan", 1, Some(7), R1, "203.0.113.50");
    wan_port.pppoe = wan;
    wan_port.onlink = vec!["203.0.113.1/32".parse().unwrap()];
    wan_port.mtu = 1492;
    let ports: Arc<[Port]> = Arc::new([
        port(0, "lan", 0, None, R0, "10.10.1.1"),
        port(1, "guest", 0, Some(10), R0, "10.10.10.1"),
        port(2, "iot", 1, Some(20), R1, "10.10.20.1"),
        wan_port,
    ]);
    let statics = [StaticRoute {
        prefix: "0.0.0.0/0".parse().unwrap(),
        via: ip("203.0.113.1"),
    }];
    let fib = build_fib(&ports, &statics, &[]).unwrap();
    let mut p = Pipeline::new(
        ports,
        Arc::new(fib),
        SessionConfig::default(),
        Arc::new(Overlay::disabled()),
    );
    p.set_time(10_000_000_000);
    for (port, mac, addr) in [
        (0, LAN_HOST, "10.10.1.10"),
        (1, GUEST, "10.10.10.10"),
        (2, IOT, "10.10.20.10"),
    ] {
        p.learn(Neighbor {
            port,
            ip: ip(addr),
            mac,
        });
    }
    p
}

const UP: Pppoe = Pppoe::Up {
    session: 0x42,
    peer: AC,
    mtu: 1492,
};

/// An Ethernet frame (`n` bytes in `buf`) placed in a UMEM-like frame at
/// [`HEAD`], tagged for `vlan` if given. Returns the frame and its offset
/// and length.
fn on_wire(buf: &[u8], n: usize, vlan: Option<u16>) -> (Vec<u8>, usize, usize) {
    let mut f = vec![0u8; 4096];
    f[HEAD..HEAD + n].copy_from_slice(&buf[..n]);
    match vlan {
        Some(vid) => {
            let off = eth::push_vlan(&mut f, HEAD, vid);
            (f, off, n + eth::VLAN_TAG_LEN)
        }
        None => (f, HEAD, n),
    }
}

fn ping(dst_mac: Mac, src_mac: Mac, src: &str, dst: &str) -> (Vec<u8>, usize) {
    let mut buf = vec![0u8; 2048];
    let payload = b"payload!";
    let icmp_len = icmp::HDR_LEN + payload.len();
    let ip_len = ipv4::MIN_HDR_LEN + icmp_len;
    eth::write(&mut buf, dst_mac, src_mac, eth::TYPE_IPV4);
    ipv4::write_header(
        &mut buf[14..],
        ip_len as u16,
        1,
        64,
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

#[test]
fn routes_between_vlans_on_one_card() {
    let mut r = router(UP);
    // Guest (VLAN 10) to the LAN (untagged), both on card 0.
    let (b, n) = ping(R0, GUEST, "10.10.10.10", "10.10.1.10");
    let (mut f, off, len) = on_wire(&b, n, Some(10));
    let v = r.process(0, &mut f, off, len);
    let Verdict::Tx { port, off, len } = v else {
        panic!("not forwarded: {v:?}")
    };
    assert_eq!((port, r.card_of(port)), (0, 0));
    assert_eq!(len, n, "the tag is gone");
    let o = &f[off..off + len];
    assert_eq!(
        (eth::dst(o), eth::src(o), eth::ethertype(o)),
        (LAN_HOST, R0, eth::TYPE_IPV4)
    );
    assert_eq!(ipv4::parse(&o[14..]).unwrap().ttl, 63);

    // The other way: the LAN to the IoT VLAN on card 1 gets tagged 20,
    // in the headroom (nothing copied).
    let (b, n) = ping(R0, LAN_HOST, "10.10.1.10", "10.10.20.10");
    let (mut f, off, len) = on_wire(&b, n, None);
    let Verdict::Tx { port, off, len } = r.process(0, &mut f, off, len) else {
        panic!("not forwarded")
    };
    assert_eq!((port, r.card_of(port)), (2, 1));
    assert_eq!((off, len), (HEAD - 4, n + 4));
    let o = &f[off..off + len];
    assert_eq!(
        (eth::dst(o), eth::src(o), eth::ethertype(o), eth::vlan_id(o)),
        (IOT, R1, eth::TYPE_VLAN, 20)
    );
    assert_eq!(u16::from_be_bytes([o[16], o[17]]), eth::TYPE_IPV4);
    assert_eq!(ipv4::parse(&o[18..]).unwrap().dst, ip("10.10.20.10"));

    // Counted on the logical interfaces.
    assert_eq!(r.stats.ports[1].rx_packets, 1);
    assert_eq!(r.stats.ports[0].rx_packets, 1);
}

#[test]
fn unknown_and_missing_tags_are_dropped() {
    let mut r = router(UP);
    // VLAN 30 isn't configured on card 0.
    let (b, n) = ping(R0, GUEST, "10.10.10.10", "10.10.1.10");
    let (mut f, off, len) = on_wire(&b, n, Some(30));
    assert_eq!(
        r.process(0, &mut f, off, len),
        Verdict::Drop(DropReason::Vlan)
    );
    // VLAN 20 is, but on card 1, not card 0.
    let (mut f, off, len) = on_wire(&b, n, Some(20));
    assert_eq!(
        r.process(0, &mut f, off, len),
        Verdict::Drop(DropReason::Vlan)
    );
    // Card 1 has only VLAN interfaces: untagged frames have nowhere to go.
    let (b, n) = ping(R1, IOT, "10.10.20.10", "10.10.1.10");
    let (mut f, off, len) = on_wire(&b, n, None);
    assert_eq!(
        r.process(1, &mut f, off, len),
        Verdict::Drop(DropReason::Vlan)
    );
    // A card the router doesn't have.
    let (mut f, off, len) = on_wire(&b, n, None);
    assert_eq!(
        r.process(9, &mut f, off, len),
        Verdict::Drop(DropReason::Vlan)
    );
    // A tag cut short.
    let mut f = vec![0u8; 64];
    eth::write(&mut f, R0, GUEST, eth::TYPE_VLAN);
    assert_eq!(
        r.process(0, &mut f, 0, 16),
        Verdict::Drop(DropReason::Malformed)
    );
    assert_eq!(r.stats.drops[DropReason::Vlan as usize], 4);
}

#[test]
fn priority_tagged_frames_belong_to_the_untagged_interface() {
    let mut r = router(UP);
    // VLAN 0: only a priority, no VLAN. A ping to the router is answered.
    let (b, n) = ping(R0, LAN_HOST, "10.10.1.10", "10.10.1.1");
    let (mut f, off, len) = on_wire(&b, n, Some(0));
    let v = r.process(0, &mut f, off, len);
    let Verdict::Tx { port, off, .. } = v else {
        panic!("no reply: {v:?}")
    };
    assert_eq!(port, 0);
    assert_eq!(
        eth::ethertype(&f[off..]),
        eth::TYPE_IPV4,
        "answered untagged"
    );
}

#[test]
fn arp_works_inside_a_vlan() {
    let mut r = router(UP);
    // A request on VLAN 20 for the router's address there: answered on
    // VLAN 20, and the sender learned on that interface.
    let mut b = vec![0u8; 64];
    eth::write(&mut b, eth::BROADCAST, IOT, eth::TYPE_ARP);
    arp::write(
        &mut b[14..],
        &arp::Arp {
            op: arp::OP_REQUEST,
            sha: IOT,
            spa: ip("10.10.20.11"),
            tha: eth::ZERO,
            tpa: ip("10.10.20.1"),
        },
    );
    let (mut f, off, len) = on_wire(&b, 60, Some(20));
    let v = r.process(1, &mut f, off, len);
    let Verdict::Tx { port, off, len } = v else {
        panic!("not answered: {v:?}")
    };
    assert_eq!((port, off, len), (2, HEAD - 4, 64));
    let o = &f[off..off + len];
    assert_eq!((eth::dst(o), eth::src(o), eth::vlan_id(o)), (IOT, R1, 20));
    assert_eq!(u16::from_be_bytes([o[16], o[17]]), eth::TYPE_ARP);
    let a = arp::parse(&o[18..]).unwrap();
    assert_eq!((a.op, a.sha, a.spa), (arp::OP_REPLY, R1, ip("10.10.20.1")));
    assert!(r
        .neighbors()
        .any(|x| x.port == 2 && x.ip == ip("10.10.20.11") && x.mac == IOT));

    // A neighbour the router doesn't know yet: its ARP request goes out
    // tagged too.
    let (b, n) = ping(R0, LAN_HOST, "10.10.1.10", "10.10.20.99");
    let (mut f, off, len) = on_wire(&b, n, None);
    assert_eq!(
        r.process(0, &mut f, off, len),
        Verdict::Drop(DropReason::NeighborMiss)
    );
    let e = r.emits.pop().expect("an ARP request");
    let o = &e.frame[..e.len];
    assert_eq!(
        (e.port, e.len),
        (2, 60 + 4),
        "padded to the minimum, then tagged"
    );
    assert_eq!(
        (eth::dst(o), eth::ethertype(o), eth::vlan_id(o)),
        (eth::BROADCAST, eth::TYPE_VLAN, 20)
    );
    let a = arp::parse(&o[18..]).unwrap();
    assert_eq!((a.op, a.tpa), (arp::OP_REQUEST, ip("10.10.20.99")));
}

/// Many ISPs deliver PPPoE on a VLAN: the session header goes inside the tag.
#[test]
fn pppoe_over_a_vlan() {
    let mut r = router(UP);
    let (b, n) = ping(R0, LAN_HOST, "10.10.1.10", "8.8.8.8");
    let (mut f, off, len) = on_wire(&b, n, None);
    let Verdict::Tx { port, off, len } = r.process(0, &mut f, off, len) else {
        panic!("not sent")
    };
    assert_eq!((port, r.card_of(port)), (3, 1));
    assert_eq!(
        (off, len),
        (HEAD - 12, n + 12),
        "tag and PPPoE in the headroom"
    );
    let o = &f[off..off + len];
    assert_eq!((eth::dst(o), eth::src(o), eth::vlan_id(o)), (AC, R1, 7));
    assert_eq!(u16::from_be_bytes([o[16], o[17]]), pppoe::TYPE_SESSION);
    assert_eq!(&o[18..22], &[0x11, 0x00, 0x00, 0x42]);
    let inner = ipv4::parse(&o[26..]).unwrap();
    assert_eq!((inner.src, inner.dst), (ip("203.0.113.50"), ip("8.8.8.8")));

    // The reply, tagged and wrapped by the ISP, reaches the LAN host plain.
    let mut reply = o.to_vec();
    let ip_off = 26;
    reply[ip_off + 12..ip_off + 16].copy_from_slice(&[8, 8, 8, 8]);
    reply[ip_off + 16..ip_off + 20].copy_from_slice(&[203, 0, 113, 50]);
    reply[ip_off + 20] = icmp::ECHO_REPLY;
    reply[ip_off + 22..ip_off + 24].fill(0);
    let c = checksum::checksum(&reply[ip_off + 20..]);
    reply[ip_off + 22..ip_off + 24].copy_from_slice(&c.to_be_bytes());
    reply[ip_off + 10..ip_off + 12].fill(0);
    let c = checksum::checksum(&reply[ip_off..ip_off + 20]);
    reply[ip_off + 10..ip_off + 12].copy_from_slice(&c.to_be_bytes());
    reply[0..6].copy_from_slice(&R1);
    reply[6..12].copy_from_slice(&AC);
    let mut g = vec![0u8; 4096];
    g[HEAD..HEAD + reply.len()].copy_from_slice(&reply);
    let v = r.process(1, &mut g, HEAD, reply.len());
    let Verdict::Tx { port, off, .. } = v else {
        panic!("reply not forwarded: {v:?}")
    };
    assert_eq!(
        (port, eth::dst(&g[off..]), eth::ethertype(&g[off..])),
        (0, LAN_HOST, eth::TYPE_IPV4)
    );
    assert_eq!(ipv4::parse(&g[off + 14..]).unwrap().dst, ip("10.10.1.10"));

    // PPP control from the ISP (here an LCP echo) reaches the control plane
    // as a plain, untagged frame.
    let echo = pppoe::session(AC, R1, 0x42, pppoe::PROTO_LCP, &[9, 1, 0, 8, 1, 2, 3, 4]);
    let (mut f, off, len) = on_wire(&echo, echo.len(), Some(7));
    assert_eq!(
        r.process(1, &mut f, off, len),
        Verdict::Drop(DropReason::PppoeToControl)
    );
    let p = r.punts.pop().unwrap();
    assert_eq!((p.port, p.frame), (3, echo));
}

#[test]
fn control_plane_frames_are_tagged_for_their_interface() {
    let r = router(UP);
    let echo = pppoe::session(R1, AC, 0x42, pppoe::PROTO_LCP, &[10, 1, 0, 8, 1, 2, 3, 4]);
    let mut buf = vec![0u8; 256];
    buf[4..4 + echo.len()].copy_from_slice(&echo);
    let (off, len) = r.tag_for(3, &mut buf, 4, echo.len()).unwrap();
    assert_eq!((off, len), (0, echo.len() + 4));
    assert_eq!((eth::vlan_id(&buf), eth::dst(&buf)), (7, AC));
    assert_eq!(&buf[16..len], &echo[12..]);
    // Untagged interface: left alone.
    let mut buf2 = vec![0u8; 256];
    buf2[4..4 + echo.len()].copy_from_slice(&echo);
    assert_eq!(
        r.tag_for(0, &mut buf2, 4, echo.len()),
        Some((4, echo.len()))
    );
    // No headroom: the frame moves back to make some.
    let mut buf3 = vec![0u8; 256];
    buf3[..echo.len()].copy_from_slice(&echo);
    assert_eq!(
        r.tag_for(3, &mut buf3, 0, echo.len()),
        Some((0, echo.len() + 4))
    );
    assert_eq!(eth::vlan_id(&buf3), 7);
    assert_eq!(&buf3[16..echo.len() + 4], &echo[12..]);
}
