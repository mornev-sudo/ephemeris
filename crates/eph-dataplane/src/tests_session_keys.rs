//! Tethers to a site that uses session keys from a handshake (version 3).
//! The control plane agrees the keys; here they're installed by hand, as
//! the control plane would, to check what the data plane does with them.

use crate::overlay::{
    self, Cipher, KeyTable, Session, TetherKey, REJECT_AFTER_NS, TYPE_HANDSHAKE_INIT,
};
use crate::tests_overlay::{drop_reason, ip, mac, packet, router_full, tx, HOST_A, HOST_B, OFF};
use crate::*;
use eph_packet::{eth, icmp, ipv4};
use std::sync::Arc;

const NOW: u64 = 1_000_000_000;

fn router(site: u8) -> Pipeline {
    router_full(site, None, false, true)
}

/// One handshake's keys, as each side holds them: R1 started it (so may
/// send at once), R2 answered (so waits for R1's first packet).
fn sessions(serial: u64, ids: (u8, u8), created: u64) -> (Arc<Session>, Arc<Session>) {
    sessions_with(Cipher::ChaCha20Poly1305, serial, ids, created)
}

fn sessions_with(
    cipher: Cipher,
    serial: u64,
    ids: (u8, u8),
    created: u64,
) -> (Arc<Session>, Arc<Session>) {
    let (to_r2, to_r1) = (
        TetherKey([serial as u8; 32]),
        TetherKey([0x80 | serial as u8; 32]),
    );
    (
        Arc::new(Session::new(
            serial, ids.0, ids.1, cipher, to_r2, to_r1, created, true,
        )),
        Arc::new(Session::new(
            serial, ids.1, ids.0, cipher, to_r1, to_r2, created, false,
        )),
    )
}

#[test]
fn aes_gcm_sessions_carry_traffic_both_ways() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (s1, s2) = sessions_with(Cipher::Aes256Gcm, 1, (5, 9), NOW);
    install(&mut r1, vec![s1]);
    install(&mut r2, vec![s2]);
    let (v, mut f) = ping_from_a(&mut r1);
    let (_, off, len) = tx(v);
    let plain = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true).0;
    assert_ne!(
        &f[off + overlay::OUTER_LEN..off + overlay::OUTER_LEN + 20],
        &plain[OFF + 14..OFF + 34],
        "encrypted"
    );
    let (port, off, _) = tx(r2.process(1, &mut f, off, len));
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_B));
    let (v, mut f) = reply_from_b(&mut r2);
    let (_, off, len) = tx(v);
    let (port, off, _) = tx(r1.process(1, &mut f, off, len));
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_A));
}

#[test]
fn the_two_ciphers_never_open_each_others_packets() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (s1, _) = sessions_with(Cipher::Aes256Gcm, 1, (5, 9), NOW);
    let (_, s2) = sessions_with(Cipher::ChaCha20Poly1305, 1, (5, 9), NOW);
    install(&mut r1, vec![s1]);
    install(&mut r2, vec![s2]);
    let (v, mut f) = ping_from_a(&mut r1);
    let (_, off, len) = tx(v);
    assert_eq!(
        drop_reason(r2.process(1, &mut f, off, len)),
        DropReason::OverlayAuth
    );
}

fn install(r: &mut Pipeline, newest_first: Vec<Arc<Session>>) {
    r.set_keys(Arc::new(KeyTable {
        peers: vec![newest_first],
    }));
}

/// Host A's ping through R1: the verdict.
fn ping_from_a(r1: &mut Pipeline) -> (Verdict, Vec<u8>) {
    let (mut f, n) = packet(mac(1, 0), HOST_A, "10.1.0.10", "10.2.0.10", None, 8, true);
    let v = r1.process(0, &mut f, OFF, n);
    (v, f)
}

/// Host B's reply through R2: the verdict.
fn reply_from_b(r2: &mut Pipeline) -> (Verdict, Vec<u8>) {
    let (mut f, n) = packet(mac(2, 0), HOST_B, "10.2.0.10", "10.1.0.10", None, 8, true);
    f[OFF + 34] = icmp::ECHO_REPLY;
    let v = r2.process(0, &mut f, OFF, n);
    (v, f)
}

#[test]
fn without_a_session_the_tethers_stay_down() {
    let mut r1 = router(1);
    r1.set_prober(true);
    r1.housekeeping();
    assert!(r1.emits.is_empty(), "no probes");
    assert_eq!(drop_reason(ping_from_a(&mut r1).0), DropReason::NoPath);
    // A router still using the pre-shared key (version 2) isn't accepted.
    let mut psk = router_full(1, Some(TetherKey([7; 32])), false, false);
    let (v, mut f) = ping_from_a(&mut psk);
    let (_, off, len) = tx(v);
    assert_eq!(
        drop_reason(router(2).process(1, &mut f, off, len)),
        DropReason::BadOverlay
    );
}

#[test]
fn traffic_flows_once_keys_are_agreed() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (s1, s2) = sessions(1, (5, 9), NOW);
    install(&mut r1, vec![s1]);
    install(&mut r2, vec![s2.clone()]);

    // R2 answered the handshake: it waits for proof R1 has the keys.
    assert_eq!(drop_reason(reply_from_b(&mut r2).0), DropReason::NoPath);

    let (v, mut f) = ping_from_a(&mut r1);
    let (port, off, len) = tx(v);
    assert_eq!(port, 1);
    let hdr = &f[off + overlay::OUTER_LEN - overlay::HDR_LEN..];
    assert_eq!(hdr[0] >> 4, overlay::VERSION_HANDSHAKE);
    assert_eq!(hdr[7], 9, "R2's id for the session");
    let (port, off, _) = tx(r2.process(1, &mut f, off, len));
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_B));
    assert!(s2.confirmed(), "the first packet confirms it");

    // Now R2 sends too.
    let (v, mut f) = reply_from_b(&mut r2);
    let (_, off, len) = tx(v);
    assert_eq!(f[off + overlay::OUTER_LEN - overlay::HDR_LEN + 7], 5);
    let (port, off, _) = tx(r1.process(1, &mut f, off, len));
    assert_eq!((port, eth::dst(&f[off..])), (0, HOST_A));
}

#[test]
fn probes_use_the_session_too() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (s1, s2) = sessions(1, (5, 9), NOW);
    install(&mut r1, vec![s1]);
    install(&mut r2, vec![s2]);
    r1.set_prober(true);
    r1.housekeeping();
    assert_eq!(r1.emits.len(), 2, "one probe per tether");
    let e = r1.emits[0].clone();
    let mut f = e.frame.to_vec();
    f.resize(4096, 0);
    // R2 echoes it, sealed with the same session (now confirmed).
    let (port, off, len) = tx(r2.process(e.port, &mut f, 0, e.len));
    r1.set_time(NOW + 3_000_000);
    r1.process(port, &mut f, off, len);
    assert_eq!(r1.tether_stats()[e.port as usize - 1].replies, 1);
}

#[test]
fn a_rekey_loses_nothing() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (old1, old2) = sessions(1, (5, 9), NOW);
    install(&mut r1, vec![old1.clone()]);
    install(&mut r2, vec![old2.clone()]);
    let (v, mut f) = ping_from_a(&mut r1);
    let (_, off, len) = tx(v);
    tx(r2.process(1, &mut f, off, len)); // old2 confirmed

    // A packet sealed with the old keys is still on the wire...
    let (v, mut in_flight) = ping_from_a(&mut r1);
    let (_, flight_off, flight_len) = tx(v);

    // ...when a new handshake completes: newest first, the old kept.
    let (new1, new2) = sessions(2, (6, 10), NOW + 1);
    install(&mut r1, vec![new1, old1]);
    install(&mut r2, vec![new2.clone(), old2]);

    // R2 keeps sending with the old one until R1 uses the new one.
    let (v, f2) = reply_from_b(&mut r2);
    let (_, off, _) = tx(v);
    assert_eq!(f2[off + overlay::OUTER_LEN - overlay::HDR_LEN + 7], 5);

    // The packet from before still arrives, and so does one with the new keys.
    tx(r2.process(1, &mut in_flight, flight_off, flight_len));
    let (v, mut f) = ping_from_a(&mut r1);
    let (_, off, len) = tx(v);
    assert_eq!(f[off + overlay::OUTER_LEN - overlay::HDR_LEN + 7], 10);
    tx(r2.process(1, &mut f, off, len));
    assert!(new2.confirmed());
    let (v, f2) = reply_from_b(&mut r2);
    let (_, off, _) = tx(v);
    assert_eq!(
        f2[off + overlay::OUTER_LEN - overlay::HDR_LEN + 7],
        6,
        "R2 moved over"
    );
}

#[test]
fn old_and_unknown_keys_are_refused() {
    let (mut r1, mut r2) = (router(1), router(2));
    let (s1, s2) = sessions(1, (5, 9), NOW);
    install(&mut r1, vec![s1]);
    install(&mut r2, vec![s2]);
    let (v, f) = ping_from_a(&mut r1);
    let (_, off, len) = tx(v);

    // Replayed.
    tx(r2.process(1, &mut f.clone(), off, len));
    assert_eq!(
        drop_reason(r2.process(1, &mut f.clone(), off, len)),
        DropReason::OverlayReplay
    );
    // A key id R2 never gave out (say, from before R2 restarted).
    let mut g = f.clone();
    g[off + overlay::OUTER_LEN - overlay::HDR_LEN + 7] = 77;
    assert_eq!(
        drop_reason(r2.process(1, &mut g, off, len)),
        DropReason::OverlayNoKey
    );
    // Too old: neither side uses a session past its lifetime.
    let (v, mut late) = ping_from_a(&mut r1);
    let (_, off, len) = tx(v);
    r1.set_time(NOW + REJECT_AFTER_NS);
    r2.set_time(NOW + REJECT_AFTER_NS);
    assert_eq!(drop_reason(ping_from_a(&mut r1).0), DropReason::NoPath);
    assert_eq!(
        drop_reason(r2.process(1, &mut late, off, len)),
        DropReason::OverlayNoKey
    );
}

/// A handshake initiation from site 1, as R1's control plane would send it
/// over the fibre: (frame, len) at OFF.
fn initiation(len: usize) -> (Vec<u8>, usize) {
    let mut r1 = router(1);
    let mut payload = vec![0u8; len];
    payload[0] = (overlay::VERSION_HANDSHAKE << 4) | TYPE_HANDSHAKE_INIT;
    payload[2..4].copy_from_slice(&1u16.to_be_bytes());
    assert!(r1.send_handshake(0, None, &payload));
    let e = r1.emits.pop().unwrap();
    let mut f = vec![0u8; 4096];
    f[OFF..OFF + e.len].copy_from_slice(&e.frame[..e.len]);
    (f, e.len)
}

#[test]
fn handshake_messages_go_to_the_control_plane() {
    let (f, n) = initiation(129);
    let outer = ipv4::parse(&f[OFF + 14..OFF + n]).unwrap();
    assert_eq!((outer.src, outer.dst), (ip("192.0.2.1"), ip("192.0.2.2")));
    assert_eq!(
        (
            u16::from_be_bytes([f[OFF + 34], f[OFF + 35]]),
            u16::from_be_bytes([f[OFF + 36], f[OFF + 37]])
        ),
        (4800, 4800),
        "from and to the overlay port"
    );

    let mut r2 = router(2);
    assert_eq!(
        drop_reason(r2.process(1, &mut f.clone(), OFF, n)),
        DropReason::OverlayHandshake
    );
    let h = r2.handshakes.pop().unwrap();
    assert_eq!((h.tether, h.src, h.sport), (0, ip("192.0.2.1"), 4800));
    assert_eq!(h.payload, f[OFF + 42..OFF + n].to_vec());

    // At most 20 a second per worker reach it.
    let mut handed = 0;
    for _ in 0..50 {
        if r2.process(1, &mut f.clone(), OFF, n) == Verdict::Drop(DropReason::OverlayHandshake) {
            handed += 1;
        }
    }
    assert_eq!(handed, 19);
    r2.set_time(NOW + 1_000_000_000);
    assert_eq!(
        drop_reason(r2.process(1, &mut f.clone(), OFF, n)),
        DropReason::OverlayHandshake,
        "and more a second later"
    );

    // Oversized: dropped right away.
    let (f, n) = initiation(129);
    let mut r2 = router(2);
    let mut f = f;
    f.truncate(OFF + n);
    f.extend(std::iter::repeat_n(0, 100));
    let n = n + 100;
    f[OFF + 16..OFF + 18].copy_from_slice(&((n - 14) as u16).to_be_bytes());
    f[OFF + 38..OFF + 40].copy_from_slice(&((n - 34) as u16).to_be_bytes());
    f[OFF + 24..OFF + 26].fill(0);
    let c = eph_packet::checksum::checksum(&f[OFF + 14..OFF + 34]);
    f[OFF + 24..OFF + 26].copy_from_slice(&c.to_be_bytes());
    f.resize(4096, 0);
    assert_eq!(
        drop_reason(r2.process(1, &mut f, OFF, n)),
        DropReason::BadOverlay
    );
}

#[test]
fn a_handshake_reply_goes_where_the_initiation_came_from() {
    let mut r2 = router(2);
    let payload = [0x35u8; 49 + 32];
    // An address and port behind NAT: R2 only knows them from the message.
    r2.learn(Neighbor {
        port: 1,
        ip: ip("192.0.2.1"),
        mac: mac(1, 1),
    });
    assert!(r2.send_handshake(0, Some((ip("192.0.2.1"), 61000)), &payload));
    let e = r2.emits.pop().unwrap();
    assert_eq!(e.port, 1);
    let f = &e.frame[..e.len];
    assert_eq!(ipv4::parse(&f[14..]).unwrap().dst, ip("192.0.2.1"));
    assert_eq!(u16::from_be_bytes([f[36], f[37]]), 61000);
    assert_eq!(&f[42..], &payload[..]);
    // No next hop known yet: it's resolved, and the control plane retries.
    let mut r2 = router(2);
    assert!(!r2.send_handshake(0, Some((ip("192.0.2.9"), 4800)), &payload));
    assert!(!r2.emits.is_empty(), "an ARP request went out");
}
