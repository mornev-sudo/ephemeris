//! The always-on packet filter and per-interface TCP MSS adjust.
//!
//! ```text
//!  host A 10.10.1.10 ──[p0 10.10.1.1]── ROUTER ──[p1 10.10.2.1]── host B 10.10.2.10
//!                                          └──[p2 192.0.2.0/31]── peer 192.0.2.1
//! ```

use crate::overlay::Overlay;
use crate::*;
use eph_packet::ipv4::{PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use eph_packet::l4::{TCP_ACK, TCP_SYN};
use eph_packet::{checksum, eth, icmp, ipv4, Mac};
use std::net::Ipv4Addr;
use std::sync::Arc;

const MACS: [Mac; 3] = [
    [0x02, 0, 0, 0, 0, 0x01],
    [0x02, 0, 0, 0, 0, 0x02],
    [0x02, 0, 0, 0, 0, 0x03],
];
const HOST: Mac = [0x52, 0x54, 0, 0, 0, 0x0a];
const A: &str = "10.10.1.10";
const B: &str = "10.10.2.10";
const AB: (&str, &str) = (A, B);

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn port(id: u16, addr: &str, subnet: &str, mss_adjust: Option<u16>) -> Port {
    Port {
        id,
        name: format!("p{id}"),
        mac: MACS[id as usize],
        addr: ip(addr),
        subnet: subnet.parse().unwrap(),
        allow_new_sessions: true,
        role: Role::Inside,
        mss_adjust,
        dhcp: crate::config::Dhcp::Off,
        gateway: None,
        pppoe: crate::config::Pppoe::Off,
        onlink: vec![],
        mtu: 1500,
    }
}

/// Router with every host's MAC already known. `mss`: MSS adjust of p0, p1.
fn router(mss: [Option<u16>; 2]) -> Pipeline {
    let ports: Arc<[Port]> = Arc::new([
        port(0, "10.10.1.1", "10.10.1.0/24", mss[0]),
        port(1, "10.10.2.1", "10.10.2.0/24", mss[1]),
        port(2, "192.0.2.0", "192.0.2.0/31", None),
    ]);
    let fib = build_fib(&ports, &[], &[]).unwrap();
    let mut r = Pipeline::new(
        ports,
        Arc::new(fib),
        SessionConfig::default(),
        Arc::new(Overlay::disabled()),
    );
    r.set_time(10_000_000_000);
    for (port, addr) in [(0, A), (1, B), (2, "192.0.2.1")] {
        r.learn(Neighbor {
            port,
            ip: ip(addr),
            mac: HOST,
        });
    }
    r
}

/// Ethernet + IPv4 with `opts` as its options, then `l4`, in a 2 KiB buffer
/// like a UMEM frame, addressed to `ingress`'s MAC. `frag` is the flags and
/// fragment offset word.
fn frame(
    ingress: PortId,
    (src, dst): (&str, &str),
    proto: u8,
    opts: &[u8],
    frag: u16,
    l4: &[u8],
) -> (Vec<u8>, usize) {
    assert!(opts.len().is_multiple_of(4));
    let hl = ipv4::MIN_HDR_LEN + opts.len();
    let total = hl + l4.len();
    let mut b = vec![0u8; 2048];
    eth::write(&mut b, MACS[ingress as usize], HOST, eth::TYPE_IPV4);
    let p = &mut b[14..14 + total];
    p[0] = 0x40 | (hl / 4) as u8;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6..8].copy_from_slice(&frag.to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&ip(src).octets());
    p[16..20].copy_from_slice(&ip(dst).octets());
    p[20..hl].copy_from_slice(opts);
    let c = checksum::checksum(&p[..hl]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[hl..].copy_from_slice(l4);
    (b, 14 + total)
}

fn echo() -> Vec<u8> {
    let mut m = vec![icmp::ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0, 1];
    m.extend_from_slice(b"payload!");
    let c = checksum::checksum(&m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    m
}

/// A UDP header plus `data` bytes of payload.
fn udp(data: usize) -> Vec<u8> {
    let mut u = vec![0u8; 8 + data];
    u[0..2].copy_from_slice(&5000u16.to_be_bytes());
    u[2..4].copy_from_slice(&53u16.to_be_bytes());
    u[4..6].copy_from_slice(&((8 + data) as u16).to_be_bytes());
    u
}

/// Run one packet through the router.
fn send(r: &mut Pipeline, ingress: PortId, f: (Vec<u8>, usize)) -> Verdict {
    let (mut b, n) = f;
    r.process(ingress, &mut b, 0, n)
}

fn dropped(r: &mut Pipeline, ingress: PortId, f: (Vec<u8>, usize)) -> DropReason {
    match send(r, ingress, f) {
        Verdict::Drop(reason) => reason,
        v => panic!("expected a drop, got {v:?}"),
    }
}

/// The port it was sent out of.
fn forwarded(r: &mut Pipeline, ingress: PortId, f: (Vec<u8>, usize)) -> PortId {
    match send(r, ingress, f) {
        Verdict::Tx { port, .. } => port,
        Verdict::Drop(reason) => panic!("expected forwarding, got drop {reason:?}"),
    }
}

fn ping(ingress: PortId, src: &str, dst: &str) -> (Vec<u8>, usize) {
    frame(ingress, (src, dst), PROTO_ICMP, &[], 0, &echo())
}

// ------------------------------------------------------------ addresses

#[test]
fn drops_broadcast_multicast_and_loopback_sources() {
    let mut r = router([None; 2]);
    for src in [
        "255.255.255.255",
        "10.10.2.255", // lan-b's broadcast address
        "224.0.0.5",
        "239.1.2.3",
        "127.0.0.1",
        "127.10.0.1",
    ] {
        assert_eq!(
            dropped(&mut r, 0, ping(0, src, B)),
            DropReason::Martian,
            "{src}"
        );
    }
}

#[test]
fn drops_unspecified_and_reserved_addresses() {
    let mut r = router([None; 2]);
    for (src, dst) in [
        ("0.0.0.0", B),
        ("0.1.2.3", B),
        ("240.0.0.1", B),
        (A, "0.0.0.0"),
        (A, "240.0.0.1"),
        (A, "254.1.1.1"),
        (A, "224.0.0.1"),
    ] {
        assert_eq!(
            dropped(&mut r, 0, ping(0, src, dst)),
            DropReason::Martian,
            "{src} -> {dst}"
        );
    }
}

#[test]
fn a_31_has_no_broadcast_address() {
    let mut r = router([None; 2]);
    assert_eq!(forwarded(&mut r, 2, ping(2, "192.0.2.1", A)), 0);
}

#[test]
fn drops_the_routers_own_addresses_as_source() {
    let mut r = router([None; 2]);
    for src in ["10.10.1.1", "10.10.2.1", "192.0.2.0"] {
        assert_eq!(
            dropped(&mut r, 1, ping(1, src, A)),
            DropReason::SpoofedSource,
            "{src}"
        );
    }
    // LAND: source and destination the same.
    assert_eq!(dropped(&mut r, 0, ping(0, B, B)), DropReason::SpoofedSource);
    assert_eq!(forwarded(&mut r, 1, ping(1, B, A)), 0);
}

// ------------------------------------------------------------ IP options

fn ping_with(opts: &[u8]) -> (Vec<u8>, usize) {
    frame(0, AB, PROTO_ICMP, opts, 0, &echo())
}

#[test]
fn drops_source_route_record_route_and_timestamp_options() {
    let mut r = router([None; 2]);
    let lsrr = [ipv4::OPT_LOOSE_SOURCE_ROUTE, 7, 4, 10, 10, 2, 10, 0];
    let ssrr = [ipv4::OPT_STRICT_SOURCE_ROUTE, 7, 4, 10, 10, 2, 10, 0];
    let rr = [ipv4::OPT_NOP, ipv4::OPT_RECORD_ROUTE, 7, 4, 0, 0, 0, 0];
    let ts = [ipv4::OPT_TIMESTAMP, 8, 5, 0, 0, 0, 0, 0];
    let stream = [ipv4::OPT_STREAM_ID, 4, 0, 1];
    let all: [&[u8]; 5] = [&lsrr, &ssrr, &rr, &ts, &stream];
    for opts in all {
        assert_eq!(
            dropped(&mut r, 0, ping_with(opts)),
            DropReason::IpOption,
            "{opts:?}"
        );
    }
}

#[test]
fn drops_malformed_options_but_forwards_harmless_ones() {
    let mut r = router([None; 2]);
    // Router Alert (RFC 2113), and padding.
    assert_eq!(forwarded(&mut r, 0, ping_with(&[148, 4, 0, 0])), 1);
    assert_eq!(forwarded(&mut r, 0, ping_with(&[1, 1, 1, 0])), 1);
    // A length running past the header, and a length of 0.
    for opts in [[148u8, 12, 0, 0], [148, 0, 0, 0]] {
        assert_eq!(dropped(&mut r, 0, ping_with(&opts)), DropReason::IpOption);
    }
}

// ------------------------------------------------------------ fragments

const MF: u16 = ipv4::FLAG_MF;

/// A UDP fragment from A to B carrying `payload`.
fn fragment(frag: u16, payload: &[u8]) -> (Vec<u8>, usize) {
    frame(0, AB, PROTO_UDP, &[], frag, payload)
}

/// A TCP fragment from A to B with `len` bytes of payload.
fn tcp_fragment(frag: u16, len: usize) -> (Vec<u8>, usize) {
    frame(0, AB, PROTO_TCP, &[], frag, &vec![0; len])
}

#[test]
fn forwards_valid_fragments() {
    let mut r = router([None; 2]);
    assert_eq!(forwarded(&mut r, 0, fragment(MF, &udp(16))), 1, "first");
    assert_eq!(forwarded(&mut r, 0, fragment(MF | 3, &[0; 24])), 1);
    assert_eq!(forwarded(&mut r, 0, fragment(6, &[0; 5])), 1, "last");
    assert_eq!(forwarded(&mut r, 0, tcp_fragment(2, 8)), 1, "offset 16");
}

#[test]
fn drops_invalid_fragments() {
    let mut r = router([None; 2]);
    let cases = [
        ("not a multiple of 8", fragment(MF | 3, &[0; 20])),
        ("empty", fragment(MF | 3, &[])),
        ("past 65535 bytes", fragment(8189, &[0; 24])),
        // RFC 1858 "tiny fragment": TCP flags pushed out of the first one.
        ("TCP header split", tcp_fragment(MF, 16)),
        // RFC 1858 "overlapping fragment": rewrites the first one's flags.
        ("TCP at offset 8", tcp_fragment(1, 16)),
    ];
    for (what, f) in cases {
        assert_eq!(dropped(&mut r, 0, f), DropReason::BadFragment, "{what}");
    }
}

#[test]
fn drops_the_reserved_flag() {
    let mut r = router([None; 2]);
    let f = frame(0, AB, PROTO_ICMP, &[], ipv4::FLAG_RESERVED, &echo());
    assert_eq!(dropped(&mut r, 0, f), DropReason::BadIpHeader);
}

#[test]
fn drops_every_fragment_addressed_to_the_router() {
    let mut r = router([None; 2]);
    for frag in [MF, MF | 2, 2] {
        let f = frame(0, (A, "10.10.1.1"), PROTO_ICMP, &[], frag, &echo());
        assert_eq!(
            dropped(&mut r, 0, f),
            DropReason::FragmentToRouter,
            "{frag:#x}"
        );
    }
    // The same ping, unfragmented, gets its reply.
    assert_eq!(forwarded(&mut r, 0, ping(0, A, "10.10.1.1")), 0);
}

// ------------------------------------------------------------ MSS adjust

const MSS_1460: [u8; 4] = [2, 4, 0x05, 0xb4];

/// A TCP header with `flags` and `opts` (a multiple of 4 bytes).
fn tcp(flags: u8, opts: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&40000u16.to_be_bytes());
    t[2..4].copy_from_slice(&443u16.to_be_bytes());
    t[12] = (((20 + opts.len()) / 4) << 4) as u8;
    t[13] = flags;
    t.extend_from_slice(opts);
    t
}

fn tcp_sum(ip_pkt: &[u8]) -> u16 {
    let tcp = &ip_pkt[20..];
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&ip_pkt[12..20]);
    pseudo.extend_from_slice(&[0, PROTO_TCP]);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    checksum::checksum(&[pseudo.as_slice(), tcp].concat())
}

/// A TCP segment with a valid checksum, from `ingress`'s host to the other.
fn segment(ingress: PortId, flags: u8, opts: &[u8]) -> (Vec<u8>, usize) {
    let mut t = tcp(flags, opts);
    let addrs = if ingress == 0 { AB } else { (B, A) };
    if ingress != 0 {
        t[0..4].rotate_left(2); // server port first
    }
    let (mut b, n) = frame(ingress, addrs, PROTO_TCP, &[], 0, &t);
    let c = tcp_sum(&b[14..n]);
    b[14 + 36..14 + 38].copy_from_slice(&c.to_be_bytes());
    (b, n)
}

/// Forward `f` and return the MSS it carries now, after checking that the
/// TCP checksum is still right.
fn mss_after(r: &mut Pipeline, ingress: PortId, f: (Vec<u8>, usize)) -> u16 {
    let (mut b, n) = f;
    assert!(matches!(
        r.process(ingress, &mut b, 0, n),
        Verdict::Tx { .. }
    ));
    let ip_pkt = &b[14..n];
    assert_eq!(tcp_sum(ip_pkt), 0, "TCP checksum still valid");
    let opts = &ip_pkt[40..];
    let at = opts.iter().position(|&kind| kind != 1).unwrap(); // skip NOPs
    assert_eq!(opts[at], 2, "MSS option");
    u16::from_be_bytes([opts[at + 2], opts[at + 3]])
}

#[test]
fn mss_adjust_lowers_syns_leaving_the_interface() {
    let mut r = router([None, Some(1400)]);
    assert_eq!(mss_after(&mut r, 0, segment(0, TCP_SYN, &MSS_1460)), 1400);
}

#[test]
fn mss_adjust_lowers_syn_acks_entering_the_interface() {
    let mut r = router([None, Some(1400)]);
    assert_eq!(mss_after(&mut r, 0, segment(0, TCP_SYN, &MSS_1460)), 1400);
    let syn_ack = segment(1, TCP_SYN | TCP_ACK, &MSS_1460);
    assert_eq!(mss_after(&mut r, 1, syn_ack), 1400);
}

#[test]
fn mss_adjust_uses_the_smaller_of_both_interfaces() {
    let mut r = router([Some(1380), Some(1400)]);
    assert_eq!(mss_after(&mut r, 0, segment(0, TCP_SYN, &MSS_1460)), 1380);
}

#[test]
fn mss_adjust_never_raises_and_only_touches_syns() {
    let mut r = router([None, Some(1400)]);
    let mss_1300: [u8; 4] = [2, 4, 0x05, 0x14];
    assert_eq!(mss_after(&mut r, 0, segment(0, TCP_SYN, &mss_1300)), 1300);
    // A plain ACK (picked up mid-stream) whose options look like an MSS.
    let mut r = router([None, Some(1400)]);
    assert_eq!(mss_after(&mut r, 0, segment(0, TCP_ACK, &MSS_1460)), 1460);
    // No MSS adjust anywhere.
    let mut r = router([None; 2]);
    assert_eq!(mss_after(&mut r, 0, segment(0, TCP_SYN, &MSS_1460)), 1460);
}

#[test]
fn mss_adjust_handles_an_mss_option_at_an_odd_offset() {
    let mut r = router([None, Some(1400)]);
    let opts: [u8; 8] = [1, 2, 4, 0x05, 0xb4, 1, 1, 0]; // NOP, MSS 1460, NOP, NOP, EOL
    assert_eq!(mss_after(&mut r, 0, segment(0, TCP_SYN, &opts)), 1400);
}

#[test]
fn mss_adjust_leaves_later_fragments_alone() {
    let mut r = router([None, Some(1400)]);
    // Data in a later fragment that happens to look like a SYN with MSS
    // 1460: it must arrive unchanged.
    let data = tcp(TCP_SYN, &MSS_1460);
    let (mut b, n) = frame(0, AB, PROTO_TCP, &[], 2, &data);
    assert!(matches!(r.process(0, &mut b, 0, n), Verdict::Tx { .. }));
    assert_eq!(&b[14 + 20..n], &data[..]);
}
