//! Peers whose addresses change: a spoke with several WAN links behind
//! NAT (each link followed on its own), and a peer whose public address
//! changes (a PPPoE redial), followed when it turns up elsewhere or when it
//! announces the change.

use crate::overlay::{
    self, select_paths, Overlay, PathTable, Tether, ANNOUNCE_MAX, STALE_SECS, TYPE_ADDRESSES,
    TYPE_DATA,
};
use crate::tests_overlay::{
    drop_reason, health, ip, mac, packet, port, router, tx, HOST_A, KEY, OFF,
};
use crate::*;
use eph_packet::{eth, icmp, ipv4};
use std::sync::Arc;

const NOW: u64 = 1_000_000_000;

/// A hub (site 2) with one WAN, 192.0.2.2, and `links` slots for site 1,
/// which has no fixed address.
fn hub(links: u16) -> Pipeline {
    let ports: Arc<[Port]> = Arc::new([
        port(0, "lan", mac(2, 0), "10.2.0.1/24"),
        port(1, "wan", mac(2, 1), "192.0.2.2/24"),
    ]);
    let mut o = Overlay::disabled();
    o.site_id = 2;
    o.sites = vec![1];
    o.tethers = (0..links)
        .map(|i| Tether {
            id: i,
            name: format!("spoke-wan-{}", i + 1),
            port: 1,
            remote: std::net::Ipv4Addr::UNSPECIFIED,
            gateway: Some(ip("192.0.2.254")),
            peer_site: 1,
            site_idx: 0,
            key: Some(KEY),
        })
        .collect();
    let routes = [OverlayRoute {
        prefix: "10.1.0.0/24".parse().unwrap(),
        site_idx: 0,
    }];
    let fib = build_fib(&ports, &[], &routes).unwrap();
    let o = Arc::new(o);
    let mut r = Pipeline::new(ports, Arc::new(fib), SessionConfig::default(), o.clone());
    r.set_time(NOW);
    r.learn(Neighbor {
        port: 1,
        ip: ip("192.0.2.254"),
        mac: [0x52, 0, 0, 0, 0, 0xfe],
    });
    r.learn(Neighbor {
        port: 0,
        ip: ip("10.2.0.10"),
        mac: [0x52, 0, 0, 0, 0, 0x0b],
    });
    let all_up = vec![health(true, 5); links as usize];
    r.set_paths(Arc::new(select_paths(&o, &all_up, &PathTable::empty(&o))));
    r
}

/// An overlay packet from `site`, its tether `sender`, at `src:sport`, to
/// `dst` (arriving at MAC `to`), sealed with KEY: (frame, len) at OFF.
#[allow(clippy::too_many_arguments)]
fn from_peer(
    site: u16,
    sender: u16,
    (src, sport): (&str, u16),
    dst: &str,
    to: eph_packet::Mac,
    counter: u64,
    typ: u8,
    body: &[u8],
) -> (Vec<u8>, usize) {
    let mut f = vec![0u8; 4096];
    let p = &mut f[OFF..];
    eth::write(p, to, [0x52, 0, 0, 0, 0, 0x77], eth::TYPE_IPV4);
    let udp_len = 8 + overlay::HDR_LEN + body.len() + overlay::TAG_LEN;
    ipv4::write_header(
        &mut p[14..],
        (20 + udp_len) as u16,
        9,
        64,
        ipv4::PROTO_UDP,
        ip(src),
        ip(dst),
    );
    p[34..36].copy_from_slice(&sport.to_be_bytes());
    p[36..38].copy_from_slice(&4800u16.to_be_bytes());
    p[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let mut hdr = [0u8; overlay::HDR_LEN];
    hdr[0] = (overlay::VERSION << 4) | typ;
    hdr[2..4].copy_from_slice(&site.to_be_bytes());
    hdr[4..6].copy_from_slice(&sender.to_be_bytes());
    hdr[8..16].copy_from_slice(&(7u64 << 48 | counter).to_be_bytes());
    p[42..58].copy_from_slice(&hdr);
    p[58..58 + body.len()].copy_from_slice(body);
    let tag = KEY.seal(&hdr, &mut p[58..58 + body.len()]);
    let end = 58 + body.len();
    p[end..end + overlay::TAG_LEN].copy_from_slice(&tag);
    (f, end + overlay::TAG_LEN)
}

/// A ping from the spoke's LAN, carried by its tether `sender` at `src`.
fn spoke_ping(sender: u16, src: (&str, u16), counter: u64) -> (Vec<u8>, usize) {
    let (inner, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let ip_pkt = inner[OFF + 14..OFF + n].to_vec();
    from_peer(
        1,
        sender,
        src,
        "192.0.2.2",
        mac(2, 1),
        counter,
        TYPE_DATA,
        &ip_pkt,
    )
}

fn delivered(r: &mut Pipeline, (mut f, n): (Vec<u8>, usize)) {
    let (port, _, _) = tx(r.process(1, &mut f, OFF, n));
    assert_eq!(port, 0, "delivered to the hub's LAN");
}

#[test]
fn each_link_of_a_spoke_keeps_its_own_address() {
    let mut r = hub(2);
    // Fibre (the spoke's tether 0) and LTE (its tether 1), each behind NAT.
    delivered(&mut r, spoke_ping(0, ("203.0.113.10", 61000), 1));
    delivered(&mut r, spoke_ping(1, ("198.18.0.20", 50123), 2));
    let e = r.endpoints().clone();
    assert_eq!(e.get(0), Some((ip("203.0.113.10"), 61000)));
    assert_eq!(e.get(1), Some((ip("198.18.0.20"), 50123)));
    assert_eq!((e.sender(0), e.sender(1)), (Some(0), Some(1)));
    // Each keeps following its own link, also when its address changes.
    delivered(&mut r, spoke_ping(1, ("198.18.0.99", 50999), 3));
    delivered(&mut r, spoke_ping(0, ("203.0.113.10", 61000), 4));
    assert_eq!(e.get(1), Some((ip("198.18.0.99"), 50999)));
    assert_eq!(e.get(0), Some((ip("203.0.113.10"), 61000)));
}

#[test]
fn more_links_than_slots_are_counted_and_a_quiet_slot_is_taken_over() {
    let mut r = hub(2);
    delivered(&mut r, spoke_ping(0, ("203.0.113.10", 61000), 1));
    delivered(&mut r, spoke_ping(1, ("198.18.0.20", 50123), 2));
    let (mut f, n) = spoke_ping(2, ("100.64.0.5", 40000), 3);
    assert_eq!(
        drop_reason(r.process(1, &mut f, OFF, n)),
        DropReason::OverlayLinksFull
    );
    // Link 0 goes quiet; after a while its slot can be reused (the spoke's
    // tethers were renumbered, say).
    r.set_time(NOW + STALE_SECS * 1_000_000_000 - 1);
    delivered(&mut r, spoke_ping(1, ("198.18.0.20", 50123), 4));
    r.set_time(NOW + STALE_SECS * 1_000_000_000 + 1);
    delivered(&mut r, spoke_ping(2, ("100.64.0.5", 40000), 5));
    let e = r.endpoints().clone();
    assert_eq!(e.sender(0), Some(2));
    assert_eq!(e.get(0), Some((ip("100.64.0.5"), 40000)));
    assert_eq!(e.sender(1), Some(1), "the busy link keeps its slot");
}

#[test]
fn only_authentic_fresh_packets_move_a_link() {
    let mut r = hub(1);
    let first = spoke_ping(0, ("203.0.113.10", 61000), 1);
    delivered(&mut r, first.clone());
    // Replayed from somewhere else: refused, nothing moves.
    let (mut f, n) = first;
    f[OFF + 26..OFF + 30].copy_from_slice(&[203, 0, 113, 66]);
    f[OFF + 24..OFF + 26].fill(0);
    let c = eph_packet::checksum::checksum(&f[OFF + 14..OFF + 34]);
    f[OFF + 24..OFF + 26].copy_from_slice(&c.to_be_bytes());
    assert_eq!(
        drop_reason(r.process(1, &mut f, OFF, n)),
        DropReason::OverlayReplay
    );
    // Forged (another key): refused too.
    let (mut f, n) = spoke_ping(0, ("203.0.113.66", 61000), 9);
    f[OFF + n - 1] ^= 1;
    assert_eq!(
        drop_reason(r.process(1, &mut f, OFF, n)),
        DropReason::OverlayAuth
    );
    assert_eq!(r.endpoints().get(0), Some((ip("203.0.113.10"), 61000)));
}

/// Host A's ping through the spoke (site 1, configured with the hub at
/// 192.0.2.2 / 198.51.100.2): where its fibre tether sends it.
fn spoke_sends_to(r: &mut Pipeline) -> std::net::Ipv4Addr {
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let (_, off, len) = tx(r.process(0, &mut f, OFF, n));
    ipv4::parse(&f[off + 14..off + len]).unwrap().dst
}

/// A reply from the hub (site 2, its tether 0) arriving over the spoke's
/// fibre from `src`.
fn from_hub(src: &str, counter: u64, typ: u8, body: &[u8]) -> (Vec<u8>, usize) {
    from_peer(
        2,
        0,
        (src, 4800),
        "192.0.2.1",
        mac(1, 1),
        counter,
        typ,
        body,
    )
}

fn hub_reply_ip() -> Vec<u8> {
    let (mut f, n) = packet(
        mac(2, 0),
        [0x52, 0, 0, 0, 0, 0x0b],
        "10.2.0.10",
        "10.1.0.10",
        None,
        8,
        true,
    );
    f[OFF + 34] = icmp::ECHO_REPLY;
    f[OFF + 14..OFF + n].to_vec()
}

#[test]
fn a_configured_peer_is_followed_to_its_new_address() {
    let mut r = router(1);
    // A ping out first: the reply that comes back is part of its session.
    assert_eq!(spoke_sends_to(&mut r), ip("192.0.2.2"));
    r.learn(Neighbor {
        port: 1,
        ip: ip("203.0.113.77"),
        mac: [0x52, 0, 0, 0, 0, 0x33],
    });
    let reply = hub_reply_ip();
    // The hub, from the address configured for it.
    let (mut f, n) = from_hub("192.0.2.2", 1, TYPE_DATA, &reply);
    tx(r.process(1, &mut f, OFF, n));
    // Its PPPoE line redials: same tether, new address. Followed.
    let (mut f, n) = from_hub("203.0.113.77", 2, TYPE_DATA, &reply);
    let (port, off, _) = tx(r.process(1, &mut f, OFF, n));
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_A));
    assert_eq!(spoke_sends_to(&mut r), ip("203.0.113.77"));
}

#[test]
fn an_announced_address_change_is_followed() {
    let mut r = router(1);
    assert_eq!(spoke_sends_to(&mut r), ip("192.0.2.2"));
    // Over the LTE path (still working), the hub says its fibre address
    // moved. (A NAT in front of us might drop packets from the new
    // address until we send there first.)
    let mut body = vec![1u8];
    body.extend_from_slice(&[192, 0, 2, 2, 203, 0, 113, 77]);
    let (mut f, n) = from_peer(
        2,
        1,
        ("198.51.100.2", 4800),
        "198.51.100.1",
        mac(1, 2),
        1,
        TYPE_ADDRESSES,
        &body,
    );
    assert_eq!(
        drop_reason(r.process(2, &mut f, OFF, n)),
        DropReason::OverlayControl
    );
    r.learn(Neighbor {
        port: 1,
        ip: ip("203.0.113.77"),
        mac: [0x52, 0, 0, 0, 0, 0x33],
    });
    assert_eq!(spoke_sends_to(&mut r), ip("203.0.113.77"));
    assert_eq!(
        r.endpoints().get(1),
        Some((ip("198.51.100.2"), 4800)),
        "the LTE tether still goes to the hub's LTE address"
    );
    // Malformed announcements are refused whole.
    for (counter, bad) in [
        (2, vec![2u8, 1, 2, 3, 4, 5, 6, 7, 8]),
        (3, vec![(ANNOUNCE_MAX + 1) as u8]),
    ] {
        let (mut f, n) = from_peer(
            2,
            1,
            ("198.51.100.2", 4800),
            "198.51.100.1",
            mac(1, 2),
            counter,
            TYPE_ADDRESSES,
            &bad,
        );
        assert_eq!(
            drop_reason(r.process(2, &mut f, OFF, n)),
            DropReason::BadOverlay
        );
    }
}

#[test]
fn a_changed_address_is_announced_to_every_peer() {
    let mut r = router(1);
    r.set_prober(true);
    r.set_announce(Arc::from([(ip("192.0.2.1"), ip("192.0.2.9"))]));
    let mut announced = 0;
    for k in 0..10u64 {
        r.set_time(NOW + k * overlay::PROBE_INTERVAL_NS);
        r.housekeeping();
        for e in r.emits.drain(..) {
            let hdr = &e.frame[overlay::OUTER_LEN - overlay::HDR_LEN..];
            if hdr[0] & 0x0f == TYPE_ADDRESSES {
                announced += 1;
            }
        }
    }
    assert_eq!(announced, 4, "once a second on each of the two tethers");
}
