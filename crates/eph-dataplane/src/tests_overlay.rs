//! Two routers, two sites, two WAN paths, wired back to back in memory.
//!
//! ```text
//!  host A 10.1.0.10 ─ lan [R1 site 1] wan1 192.0.2.1 ═══ "fibre" ═══ 192.0.2.2 wan1 [R2 site 2] lan ─ host B 10.2.0.10
//!                                     wan2 198.51.100.1 ═ "lte" ═══ 198.51.100.2 wan2
//! ```

use crate::overlay::{
    self, select_paths, Class, Overlay, PathTable, Tether, TetherHealth, TetherKey,
};
use crate::*;
use eph_packet::{checksum, eth, icmp, ipv4, l4, Mac};
use std::net::Ipv4Addr;
use std::sync::Arc;

pub(crate) const HOST_A: Mac = [0x52, 0, 0, 0, 0, 0x0a];
pub(crate) const HOST_B: Mac = [0x52, 0, 0, 0, 0, 0x0b];
pub(crate) const OFF: usize = 128; // headroom, like a real UMEM frame
/// The pre-shared key both routers' tethers use.
pub(crate) const KEY: TetherKey = TetherKey([7; 32]);

pub(crate) fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}
pub(crate) fn mac(site: u8, port: u8) -> Mac {
    [0x02, 0, 0, 0, site, port]
}

/// Router for `site` (1 or 2).
pub(crate) fn router(site: u8) -> Pipeline {
    router_with_key(site, Some(KEY))
}

/// Router for `site` whose tethers use `key`.
fn router_with_key(site: u8, key: Option<TetherKey>) -> Pipeline {
    router_opts(site, key, false)
}

/// `dynamic`: this router doesn't know the other's WAN addresses; it learns
/// them from the other's packets.
fn router_opts(site: u8, key: Option<TetherKey>, dynamic: bool) -> Pipeline {
    router_full(site, key, dynamic, false)
}

/// `handshake`: the other site uses session keys from a handshake (its
/// "public key" is 32 bytes of its site number); `key`, if any, is then
/// only the handshake's extra pre-shared key.
pub(crate) fn router_full(
    site: u8,
    key: Option<TetherKey>,
    dynamic: bool,
    handshake: bool,
) -> Pipeline {
    let other = 3 - site;
    let lan = format!("10.{site}.0.1/24");
    let ports: Arc<[Port]> = Arc::new([
        port(0, "lan", mac(site, 0), &lan),
        port(1, "wan1", mac(site, 1), &format!("192.0.2.{site}/30")),
        port(2, "wan2", mac(site, 2), &format!("198.51.100.{site}/30")),
    ]);
    let mut o = Overlay::disabled();
    o.site_id = site as u16;
    o.sites = vec![other as u16];
    if handshake {
        o.peers = vec![overlay::PeerCrypto::Handshake {
            public: [other; 32],
        }];
    }
    o.tethers = vec![
        Tether {
            id: 0,
            name: "fibre".into(),
            port: 1,
            remote: if dynamic {
                Ipv4Addr::UNSPECIFIED
            } else {
                ip(&format!("192.0.2.{other}"))
            },
            gateway: None,
            peer_site: other as u16,
            site_idx: 0,
            key,
        },
        Tether {
            id: 1,
            name: "lte".into(),
            port: 2,
            remote: if dynamic {
                Ipv4Addr::UNSPECIFIED
            } else {
                ip(&format!("198.51.100.{other}"))
            },
            gateway: None,
            peer_site: other as u16,
            site_idx: 0,
            key,
        },
    ];
    o.classes.push(Class {
        name: "bulk".into(),
        proto: Some(6),
        ports: Some((5201, 5201)),
        prefer: vec![1, 0],
        ..Default::default()
    });
    let routes = [OverlayRoute {
        prefix: format!("10.{other}.0.0/24").parse().unwrap(),
        site_idx: 0,
    }];
    let fib = build_fib(&ports, &[], &routes).unwrap();
    let o = Arc::new(o);
    let mut r = Pipeline::new(ports, Arc::new(fib), SessionConfig::default(), o.clone());
    r.set_time(1_000_000_000);
    // Neighbours: the other router's WAN ports, and our LAN host.
    r.learn(Neighbor {
        port: 1,
        ip: ip(&format!("192.0.2.{other}")),
        mac: mac(other, 1),
    });
    r.learn(Neighbor {
        port: 2,
        ip: ip(&format!("198.51.100.{other}")),
        mac: mac(other, 2),
    });
    let host = if site == 1 { HOST_A } else { HOST_B };
    r.learn(Neighbor {
        port: 0,
        ip: ip(&format!("10.{site}.0.10")),
        mac: host,
    });
    // Both paths up; fibre faster.
    r.set_paths(Arc::new(select_paths(
        &o,
        &[health(true, 5), health(true, 50)],
        &PathTable::empty(&o),
    )));
    r
}

pub(crate) fn port(id: u16, name: &str, mac: Mac, addr: &str) -> Port {
    let (a, l) = addr.split_once('/').unwrap();
    Port {
        id,
        card: id,
        vlan: None,
        host: Default::default(),
        name: name.into(),
        mac,
        addr: ip(a),
        subnet: format!("{a}/{l}").parse().unwrap(),
        allow_new_sessions: true,
        role: Role::Inside,
        mss_adjust: None,
        dhcp: crate::config::Dhcp::Off,
        gateway: None,
        pppoe: crate::config::Pppoe::Off,
        onlink: vec![],
        mtu: 1500,
    }
}

pub(crate) fn health(up: bool, rtt_ms: u64) -> TetherHealth {
    TetherHealth {
        up,
        rtt_ns: rtt_ms * 1_000_000,
        jitter_ns: 0,
        loss_pct: 0.0,
    }
}

/// A frame buffer with an IPv4 packet at OFF: ICMP echo, or TCP SYN to `dport`.
pub(crate) fn packet(
    dst_mac: Mac,
    src_mac: Mac,
    src: &str,
    dst: &str,
    tcp_dport: Option<u16>,
    size: usize,
    df: bool,
) -> (Vec<u8>, usize) {
    let mut f = vec![0u8; 4096];
    let p = &mut f[OFF..];
    eth::write(p, dst_mac, src_mac, eth::TYPE_IPV4);
    let (proto, l4_len) = match tcp_dport {
        Some(_) => (ipv4::PROTO_TCP, 24),
        None => (ipv4::PROTO_ICMP, size.max(8)),
    };
    let ip_len = 20 + l4_len;
    ipv4::write_header(&mut p[14..], ip_len as u16, 7, 64, proto, ip(src), ip(dst));
    if !df {
        p[14 + 6] = 0;
        p[14 + 10..14 + 12].fill(0);
        let c = checksum::checksum(&p[14..34]);
        p[14 + 10..14 + 12].copy_from_slice(&c.to_be_bytes());
    }
    let l = &mut p[34..34 + l4_len];
    match tcp_dport {
        Some(dport) => {
            l[0..2].copy_from_slice(&40000u16.to_be_bytes());
            l[2..4].copy_from_slice(&dport.to_be_bytes());
            l[12] = 6 << 4; // 24-byte header: one option
            l[13] = l4::TCP_SYN;
            l[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460
            set_tcp_checksum(&mut p[14..14 + ip_len]);
        }
        None => {
            l[0] = icmp::ECHO_REQUEST;
            l[4..8].copy_from_slice(&[0, 9, 0, 1]);
            let c = checksum::checksum(l);
            l[2..4].copy_from_slice(&c.to_be_bytes());
        }
    }
    (f, 14 + ip_len)
}

fn tcp_sum(ip_pkt: &[u8]) -> u16 {
    let tcp = &ip_pkt[20..];
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&ip_pkt[12..20]);
    pseudo.extend_from_slice(&[0, ipv4::PROTO_TCP]);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    checksum::checksum(&[pseudo.as_slice(), tcp].concat())
}

fn set_tcp_checksum(ip_pkt: &mut [u8]) {
    ip_pkt[36..38].fill(0);
    let c = tcp_sum(ip_pkt);
    ip_pkt[36..38].copy_from_slice(&c.to_be_bytes());
}

pub(crate) fn tx(v: Verdict) -> (PortId, usize, usize) {
    match v {
        Verdict::Tx { port, off, len } => (port, off, len),
        Verdict::Drop(r) => panic!("expected Tx, got drop {r:?}"),
    }
}

#[test]
fn ping_crosses_the_overlay_both_ways() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let (port, off, len) = tx(r1.process(0, &mut f, OFF, n));
    assert_eq!(port, 1, "default class: lowest latency path (fibre)");
    assert_eq!(len, n + overlay::OUTER_LEN - 14 + overlay::TAG_LEN);
    assert_eq!(
        off,
        OFF + 14 - overlay::OUTER_LEN,
        "headers prepended in place"
    );
    let outer = ipv4::parse(&f[off + 14..off + len]).unwrap();
    assert_eq!(
        (outer.src, outer.dst, outer.proto),
        (ip("192.0.2.1"), ip("192.0.2.2"), ipv4::PROTO_UDP)
    );
    assert_eq!(&f[off..off + 6], &mac(2, 1), "to the far router's WAN MAC");

    // Over the "fibre" into R2's wan1.
    let (port, off, len) = tx(r2.process(1, &mut f, off, len));
    assert_eq!(port, 0);
    assert_eq!(eth::dst(&f[off..]), HOST_B);
    let inner = ipv4::parse(&f[off + 14..off + len]).unwrap();
    assert_eq!(
        (inner.src, inner.dst, inner.ttl),
        (ip("10.1.0.10"), ip("10.2.0.10"), 62),
        "one hop per router"
    );

    // The reply goes back the same way.
    let (mut f, n) = packet(mac(2, 0), HOST_B, "10.2.0.10", "10.1.0.10", None, 8, true);
    f[OFF + 34] = icmp::ECHO_REPLY;
    let (port, off, len) = tx(r2.process(0, &mut f, OFF, n));
    assert_eq!(port, 1);
    let (port, off, _) = tx(r1.process(1, &mut f, off, len));
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_A));
    assert_eq!(r1.tether_stats()[0].tx_packets, 1);
    assert_eq!(r1.tether_stats()[0].rx_packets, 1);
}

#[test]
fn application_class_picks_its_preferred_path() {
    let mut r1 = router(1);
    let (mut f, n) = packet(
        mac(1, 0),
        HOST_A,
        "10.1.0.10",
        "10.2.0.10",
        Some(5201),
        0,
        true,
    );
    let (port, _, _) = tx(r1.process(0, &mut f, OFF, n));
    assert_eq!(port, 2, "bulk (tcp/5201) prefers lte");
    let (mut f, n) = packet(
        mac(1, 0),
        HOST_A,
        "10.1.0.10",
        "10.2.0.10",
        Some(443),
        0,
        true,
    );
    let (port, _, _) = tx(r1.process(0, &mut f, OFF, n));
    assert_eq!(port, 1, "everything else: fibre");
}

#[test]
fn sessions_fail_over_when_a_path_dies() {
    let mut r1 = router(1);
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    assert_eq!(tx(r1.process(0, &mut f, OFF, n)).0, 1);
    // Fibre goes down; the control plane publishes a new path table.
    let o = r1.overlay().clone();
    let p = select_paths(&o, &[health(false, 5), health(true, 50)], r1.paths());
    r1.set_paths(Arc::new(p));
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    assert_eq!(
        tx(r1.process(0, &mut f, OFF, n)).0,
        2,
        "same session, now on lte"
    );
    // Both down: no path.
    let p = select_paths(&o, &[health(false, 5), health(false, 50)], r1.paths());
    r1.set_paths(Arc::new(p));
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    assert_eq!(
        r1.process(0, &mut f, OFF, n),
        Verdict::Drop(DropReason::NoPath)
    );
}

#[test]
fn probes_measure_round_trip_time() {
    let (mut r1, mut r2) = (router(1), router(2));
    r1.set_prober(true);
    r1.housekeeping();
    assert_eq!(r1.emits.len(), 2, "one probe per tether");
    let probes: Vec<Emit> = std::mem::take(&mut r1.emits);
    // 7 ms later the far side answers...
    r2.set_time(1_007_000_000);
    r1.set_time(1_007_000_000);
    for e in probes {
        let mut f = vec![0u8; 2048];
        f[..e.len].copy_from_slice(&e.frame[..e.len]);
        let (port, off, len) = tx(r2.process(e.port, &mut f, 0, e.len));
        assert_eq!(port, e.port, "reply leaves on the same WAN link");
        assert_eq!(
            r1.process(port, &mut f, off, len),
            Verdict::Drop(DropReason::OverlayControl)
        );
    }
    for t in r1.tether_stats() {
        assert_eq!((t.probes_sent, t.replies), (1, 1));
        assert_eq!(t.rtt_ns, 7_000_000);
    }
}

#[test]
fn oversized_packets_get_frag_needed_with_the_overlay_mtu() {
    let mut r1 = router(1);
    let (mut f, n) = packet(
        mac(1, 0),
        HOST_A,
        "10.1.0.10",
        "10.2.0.10",
        None,
        1480,
        true,
    );
    let (port, off, len) = tx(r1.process(0, &mut f, OFF, n));
    assert_eq!(port, 0, "ICMP goes back to the sender");
    let m = &f[off + 34..off + len];
    assert_eq!(
        (m[0], m[1]),
        (icmp::DEST_UNREACHABLE, icmp::CODE_FRAG_NEEDED)
    );
    assert_eq!(
        u16::from_be_bytes([m[6], m[7]]),
        overlay::DEFAULT_MTU,
        "next-hop MTU"
    );
    assert_eq!(checksum::checksum(m), 0);
    // Without DF: dropped (no fragmentation yet).
    let (mut f, n) = packet(
        mac(1, 0),
        HOST_A,
        "10.1.0.10",
        "10.2.0.10",
        None,
        1480,
        false,
    );
    assert_eq!(
        r1.process(0, &mut f, OFF, n),
        Verdict::Drop(DropReason::TooBig)
    );
}

#[test]
fn tcp_mss_is_clamped_into_the_tether() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (mut f, n) = packet(
        mac(1, 0),
        HOST_A,
        "10.1.0.10",
        "10.2.0.10",
        Some(443),
        0,
        true,
    );
    let (_, off, len) = tx(r1.process(0, &mut f, OFF, n));
    let (_, off, len) = tx(r2.process(1, &mut f, off, len));
    let ip_pkt = &f[off + 14..off + len];
    assert_eq!(
        u16::from_be_bytes([ip_pkt[42], ip_pkt[43]]),
        overlay::DEFAULT_MTU - 40,
        "overlay MTU - 40"
    );
    assert_eq!(tcp_sum(ip_pkt), 0, "TCP checksum still valid");
}

#[test]
fn overlay_packets_from_strangers_are_dropped() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let (_, off, len) = tx(r1.process(0, &mut f, OFF, n));
    // Arrives on the wrong link (wan2) for its source address.
    assert_eq!(
        r2.process(2, &mut f, off, len),
        Verdict::Drop(DropReason::NotForUs)
    );
    // Spoofed source address on the right link. (Not 192.0.2.3: that's the
    // link's broadcast address, which the filter drops before this check.)
    f[off + 26..off + 30].copy_from_slice(&[203, 0, 113, 9]);
    f[off + 24..off + 26].fill(0);
    let c = checksum::checksum(&f[off + 14..off + 34]);
    f[off + 24..off + 26].copy_from_slice(&c.to_be_bytes());
    assert_eq!(
        r2.process(1, &mut f, off, len),
        Verdict::Drop(DropReason::UnknownTether)
    );
}

// ------------------------------------------------------------ crypto

/// Host A's ping, sealed by R1 for the fibre tether: (frame, off, len).
fn sealed(r1: &mut Pipeline) -> (Vec<u8>, usize, usize) {
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let (port, off, len) = tx(r1.process(0, &mut f, OFF, n));
    assert_eq!(port, 1);
    (f, off, len)
}

/// A data packet from site 1 over the fibre tether carrying `inner` (an IP
/// packet), sealed here directly with `KEY`: (frame, len) at OFF.
fn seal_by_hand(inner: &[u8], counter: u64) -> (Vec<u8>, usize) {
    let mut f = vec![0u8; 4096];
    let p = &mut f[OFF..];
    eth::write(p, mac(2, 1), mac(1, 1), eth::TYPE_IPV4);
    let udp_len = 8 + overlay::HDR_LEN + inner.len() + overlay::TAG_LEN;
    ipv4::write_header(
        &mut p[14..],
        (20 + udp_len) as u16,
        9,
        64,
        ipv4::PROTO_UDP,
        ip("192.0.2.1"),
        ip("192.0.2.2"),
    );
    p[34..36].copy_from_slice(&4800u16.to_be_bytes());
    p[36..38].copy_from_slice(&4800u16.to_be_bytes());
    p[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let mut hdr = [0u8; overlay::HDR_LEN];
    hdr[0] = (overlay::VERSION << 4) | overlay::TYPE_DATA;
    hdr[2..4].copy_from_slice(&1u16.to_be_bytes()); // site 1
    hdr[8..16].copy_from_slice(&counter.to_be_bytes());
    p[42..58].copy_from_slice(&hdr);
    p[58..58 + inner.len()].copy_from_slice(inner);
    let tag = KEY.seal(&hdr, &mut p[58..58 + inner.len()]);
    let end = 58 + inner.len();
    p[end..end + overlay::TAG_LEN].copy_from_slice(&tag);
    (f, end + overlay::TAG_LEN)
}

pub(crate) fn drop_reason(v: Verdict) -> DropReason {
    match v {
        Verdict::Drop(r) => r,
        v => panic!("expected a drop, got {v:?}"),
    }
}

#[test]
fn the_inner_packet_is_encrypted() {
    let mut r1 = router(1);
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let (port, off, len) = tx(r1.process(0, &mut f.clone(), OFF, n));
    assert_eq!(port, 1);
    let plain = f[OFF + 14..OFF + n].to_vec();
    let (_, off2, len2) = tx(router(1).process(0, &mut f, OFF, n));
    assert_eq!((off, len), (off2, len2));
    let body = &f[off + overlay::OUTER_LEN..off + len - overlay::TAG_LEN];
    assert_eq!(body.len(), plain.len());
    assert_ne!(body, &plain[..], "the inner packet isn't sent in the clear");
}

#[test]
fn modified_packets_are_rejected() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (f, off, len) = sealed(&mut r1);
    // A flipped bit in the payload, in our header, or in the tag.
    for at in [off + overlay::OUTER_LEN + 3, off + 42 + 1, off + len - 1] {
        let mut g = f.clone();
        g[at] ^= 0x01;
        assert_eq!(
            drop_reason(r2.process(1, &mut g, off, len)),
            DropReason::OverlayAuth,
            "byte {at}"
        );
    }
    // The untouched packet still gets through.
    let mut g = f.clone();
    assert_eq!(tx(r2.process(1, &mut g, off, len)).0, 0);
}

#[test]
fn a_different_key_is_rejected() {
    let mut r1 = router(1);
    let mut r2 = router_with_key(2, Some(TetherKey([8; 32])));
    let (mut f, off, len) = sealed(&mut r1);
    assert_eq!(
        drop_reason(r2.process(1, &mut f, off, len)),
        DropReason::OverlayAuth
    );
}

#[test]
fn replayed_packets_are_rejected() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (f, off, len) = sealed(&mut r1);
    let mut first = f.clone();
    assert_eq!(tx(r2.process(1, &mut first, off, len)).0, 0);
    let mut again = f.clone();
    assert_eq!(
        drop_reason(r2.process(1, &mut again, off, len)),
        DropReason::OverlayReplay
    );
}

#[test]
fn packets_from_an_older_run_are_rejected() {
    let (mut r1, mut r2) = (router(1), router(2));
    let guard = Arc::new(overlay::ReplayGuard::new(1));
    r1.set_overlay_run(4, guard.clone());
    let (mut old, off, len) = sealed(&mut r1);
    // R1 restarts: run 5. Its new packets are fine...
    r1.set_overlay_run(5, guard);
    let (mut f, off2, len2) = sealed(&mut r1);
    assert_eq!(tx(r2.process(1, &mut f, off2, len2)).0, 0);
    // ...and a packet captured before the restart is refused.
    assert_eq!(
        drop_reason(r2.process(1, &mut old, off, len)),
        DropReason::OverlayReplay
    );
}

#[test]
fn a_tether_without_a_key_stays_down() {
    let mut r1 = router_with_key(1, None);
    r1.set_prober(true);
    r1.housekeeping();
    assert!(r1.emits.is_empty(), "no probes");
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    assert_eq!(
        drop_reason(r1.process(0, &mut f, OFF, n)),
        DropReason::NoPath
    );
    // And it accepts nothing.
    let (mut f, off, len) = sealed(&mut router(1));
    let mut r2 = router_with_key(2, None);
    assert_eq!(
        drop_reason(r2.process(1, &mut f, off, len)),
        DropReason::OverlayAuth
    );
}

#[test]
fn probes_are_sealed_too() {
    let (mut r1, mut r2) = (router(1), router(2));
    r1.set_prober(true);
    r1.housekeeping();
    let e = r1.emits.iter().find(|e| e.port == 1).unwrap().clone();
    let probe = || {
        let mut f = vec![0u8; 4096];
        f[..e.len].copy_from_slice(&e.frame[..e.len]);
        f
    };
    // A peer with the wrong key can't answer for the path.
    let mut forged = router_with_key(2, Some(TetherKey([9; 32])));
    let v = forged.process(1, &mut probe(), 0, e.len);
    assert_eq!(drop_reason(v), DropReason::OverlayAuth);
    // The real peer answers, and R1 measures the round trip.
    let mut f = probe();
    let (port, off, len) = tx(r2.process(1, &mut f, 0, e.len));
    assert_eq!(port, 1);
    r1.set_time(1_002_000_000);
    assert_eq!(
        drop_reason(r1.process(1, &mut f, off, len)),
        DropReason::OverlayControl
    );
    assert_eq!(r1.tether_stats()[0].replies, 1);
    assert_eq!(r1.tether_stats()[0].last_rtt_ns, 2_000_000);
}

#[test]
fn tethers_only_carry_the_peer_sites_addresses() {
    let mut r2 = router(2);
    // Sealed correctly, but the inner source isn't one of site 1's.
    let (inner, n) = packet(mac(1, 0), HOST_A, "172.16.9.9", "10.2.0.10", None, 8, true);
    let (mut f, len) = seal_by_hand(&inner[OFF + 14..OFF + n], 1);
    assert_eq!(
        drop_reason(r2.process(1, &mut f, OFF, len)),
        DropReason::SpoofedSource
    );
    // The same from a site 1 address is delivered.
    let (inner, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let (mut f, len) = seal_by_hand(&inner[OFF + 14..OFF + n], 2);
    assert_eq!(tx(r2.process(1, &mut f, OFF, len)).0, 0);
}

#[test]
fn a_tether_inside_a_tether_is_rejected() {
    let mut r2 = router(2);
    // The payload is itself an overlay packet for R2's WAN address.
    let (nested, n) = seal_by_hand(&[0x45; 28], 1);
    let mut inner = nested[OFF + 14..OFF + n].to_vec();
    inner[12..16].copy_from_slice(&[10, 1, 0, 10]); // from site 1's LAN
    inner[10..12].fill(0);
    let c = checksum::checksum(&inner[..20]);
    inner[10..12].copy_from_slice(&c.to_be_bytes());
    let (mut f, len) = seal_by_hand(&inner, 2);
    assert_eq!(
        drop_reason(r2.process(1, &mut f, OFF, len)),
        DropReason::BadOverlay
    );
}

#[test]
fn a_peer_without_a_fixed_address_is_learned_from_its_packets() {
    // R2 (a hub) doesn't know R1's (a spoke's) WAN addresses.
    let (mut r1, mut r2) = (router(1), router_opts(2, Some(KEY), true));
    // Before R1 says anything, R2 has nowhere to send.
    let (mut f, n) = packet(mac(2, 0), HOST_B, "10.2.0.10", "10.1.0.10", None, 8, true);
    assert_eq!(
        r2.process(0, &mut f, OFF, n),
        Verdict::Drop(DropReason::NoPath)
    );

    // R1 sends over the fibre (from a NAT-like source port: R1 picks it).
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let (_, off, len) = tx(r1.process(0, &mut f, OFF, n));
    let sport = u16::from_be_bytes([f[off + 34], f[off + 35]]);
    tx(r2.process(1, &mut f, off, len));

    // Now R2 replies to exactly that address and port.
    let (mut f, n) = packet(mac(2, 0), HOST_B, "10.2.0.10", "10.1.0.10", None, 8, true);
    f[OFF + 34] = icmp::ECHO_REPLY;
    let (port, off, len) = tx(r2.process(0, &mut f, OFF, n));
    assert_eq!(port, 1);
    let outer = ipv4::parse(&f[off + 14..off + len]).unwrap();
    assert_eq!(outer.dst, ip("192.0.2.1"));
    assert_eq!(u16::from_be_bytes([f[off + 36], f[off + 37]]), sport);
    tx(r1.process(1, &mut f, off, len));

    // Someone without the key can't redirect it: a forged packet claiming
    // site 1 from another address is refused and changes nothing.
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let (_, off, len) = tx(router_with_key(1, Some(TetherKey([9; 32]))).process(0, &mut f, OFF, n));
    f[off + 14 + 12..off + 14 + 16].copy_from_slice(&[192, 0, 2, 99]);
    let c = {
        f[off + 14 + 10..off + 14 + 12].fill(0);
        checksum::checksum(&f[off + 14..off + 34])
    };
    f[off + 14 + 10..off + 14 + 12].copy_from_slice(&c.to_be_bytes());
    assert_eq!(
        r2.process(1, &mut f, off, len),
        Verdict::Drop(DropReason::OverlayAuth)
    );
    let (mut f, n) = packet(mac(2, 0), HOST_B, "10.2.0.10", "10.1.0.10", None, 8, true);
    let (_, off, len) = tx(r2.process(0, &mut f, OFF, n));
    assert_eq!(
        ipv4::parse(&f[off + 14..off + len]).unwrap().dst,
        ip("192.0.2.1")
    );
}
