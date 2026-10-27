//! Fuzzing support: a router with every feature switched on, and a way to
//! drive it from arbitrary bytes. Used by the `cargo-fuzz` targets in
//! `fuzz/` and by the random-packet test that runs with every `cargo test`.
//!
//! The property under test is simple: **no packet, however malformed, may
//! make the pipeline panic** (a release build aborts on panic, so a panic
//! would restart the router and drop every session), and every packet it
//! sends stays inside its buffer.
//!
//! ```text
//!  card 0 ─┬─ lan    inside, untagged   10.10.1.1/24   DHCP server, SSH + portal
//!          └─ guest  inside, VLAN 10    10.10.10.1/24
//!  card 1 ─── wan    outside            192.0.2.1/29   NAT, SD-WAN tether to 192.0.2.6
//!  card 2 ─── isp    outside, VLAN 7    PPPoE up, 203.0.113.50/32, MSS 1452
//! ```

use crate::host::HostAccess;
use crate::overlay::{select_paths, Overlay, PathTable, Tether, TetherHealth, TetherKey};
use crate::trace::{TraceCat, TraceConfig};
use crate::{
    build_fib, Dhcp, Neighbor, OverlayRoute, Pipeline, Port, Pppoe, Role, SessionConfig,
    StaticRoute, Verdict,
};
use eph_packet::{arp, dhcp, eth, ipv4, pppoe, Mac};
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Where received packets start in a frame (the driver's headroom).
pub const HEADROOM: usize = 256;
/// A UMEM frame.
pub const FRAME: usize = 4096;
/// Cards the router has (frames arrive on one of these).
pub const CARDS: u16 = 3;

fn ip(s: &str) -> Ipv4Addr {
    s.parse().expect("a valid address")
}

fn port(id: u16, name: &str, card: u16, vlan: Option<u16>, addr: &str, len: u8) -> Port {
    let addr = ip(addr);
    Port {
        id,
        name: name.into(),
        mac: [0x02, 0, 0, 0, card as u8, id as u8],
        addr,
        subnet: eph_fib::Prefix::new(addr, len).expect("a valid prefix"),
        allow_new_sessions: true,
        role: Role::Inside,
        mss_adjust: None,
        dhcp: Dhcp::Off,
        gateway: None,
        pppoe: Pppoe::Off,
        onlink: vec![],
        mtu: 1500,
        card,
        vlan,
        host: HostAccess::default(),
    }
}

/// The router's fixed parts: built once (the forwarding table alone is
/// 32 MiB), shared by every router made from them.
struct Parts {
    ports: Arc<[Port]>,
    fib: Arc<eph_fib::Fib<crate::NextHop>>,
    overlay: Arc<Overlay>,
}

static PARTS: std::sync::OnceLock<Parts> = std::sync::OnceLock::new();

/// The router described above, fresh (no sessions, the neighbours below),
/// with every trace category on (so tracing is exercised too, at a high
/// rate limit).
pub fn router() -> Pipeline {
    let p = PARTS.get_or_init(parts);
    let sessions = SessionConfig {
        max_sessions: 1024,
        ..SessionConfig::default()
    };
    let mut r = Pipeline::new(p.ports.clone(), p.fib.clone(), sessions, p.overlay.clone());
    r.set_time(1_000_000_000);
    let up = TetherHealth {
        up: true,
        rtt_ns: 5_000_000,
        jitter_ns: 0,
        loss_pct: 0.0,
    };
    r.set_paths(Arc::new(select_paths(
        &p.overlay,
        &[up],
        &PathTable::empty(&p.overlay),
    )));
    for (port, mac, addr) in [
        (0, 0x0a, "10.10.1.10"),
        (1, 0x10, "10.10.10.10"),
        (2, 0x66, "192.0.2.6"),
    ] {
        r.learn(Neighbor {
            port,
            ip: ip(addr),
            mac: [0x52, 0x54, 0, 0, 0, mac],
        });
    }
    r.set_trace(TraceConfig {
        mask: TraceCat::ALL.iter().fold(0, |m, c| m | c.bit()),
        host: None,
        per_sec: 1_000_000,
    });
    r
}

fn parts() -> Parts {
    let mut lan = port(0, "lan", 0, None, "10.10.1.1", 24);
    lan.dhcp = Dhcp::Server;
    lan.host = HostAccess {
        https: true,
        ssh: true,
        from: vec![],
    };
    let guest = port(1, "guest", 0, Some(10), "10.10.10.1", 24);
    let mut wan = port(2, "wan", 1, None, "192.0.2.1", 29);
    wan.role = Role::Outside;
    wan.allow_new_sessions = false;
    wan.gateway = Some(ip("192.0.2.6"));
    let mut isp = port(3, "isp", 2, Some(7), "203.0.113.50", 32);
    isp.role = Role::Outside;
    isp.allow_new_sessions = false;
    isp.pppoe = Pppoe::Up {
        session: 0x42,
        peer: [0x02, 0, 0, 0, 0, 0xac],
        mtu: 1492,
    };
    isp.mtu = 1492;
    isp.mss_adjust = Some(1452);
    isp.onlink = vec!["203.0.113.1/32".parse().expect("a valid prefix")];
    let ports: Arc<[Port]> = Arc::new([lan, guest, wan, isp]);

    let mut o = Overlay::disabled();
    o.site_id = 1;
    o.sites = vec![2];
    o.tethers = vec![Tether {
        id: 0,
        name: "t".into(),
        port: 2,
        remote: ip("192.0.2.6"),
        gateway: None,
        peer_site: 2,
        site_idx: 0,
        key: Some(TetherKey([7; 32])),
    }];
    let o = Arc::new(o);
    let statics = [StaticRoute {
        prefix: "0.0.0.0/0".parse().expect("a valid prefix"),
        via: ip("203.0.113.1"),
    }];
    let overlay_routes = [OverlayRoute {
        prefix: "10.2.0.0/16".parse().expect("a valid prefix"),
        site_idx: 0,
    }];
    let fib = build_fib(&ports, &statics, &overlay_routes).expect("a valid table");
    Parts {
        ports,
        fib: Arc::new(fib),
        overlay: o,
    }
}

/// Feed one input to the router. The first bytes choose what happens
/// (which card, where in the frame, whether it comes from the host path,
/// how much time passes); the rest is the frame. Panics only if the
/// pipeline breaks a promise: a verdict pointing outside the buffer.
pub fn run(r: &mut Pipeline, input: &[u8]) {
    let [mode, card, off_hi, off_lo, tick, data @ ..] = input else {
        return;
    };
    let mut frame = vec![0u8; FRAME];
    // Anywhere from no headroom at all to the usual 256 bytes.
    let off = (u16::from_be_bytes([*off_hi, *off_lo]) as usize) % (HEADROOM + 1);
    let len = data.len().min(FRAME - off);
    frame[off..off + len].copy_from_slice(&data[..len]);
    let now = 1_000_000_000 + *tick as u64 * 250_000_000;
    r.set_time(now.max(1));
    let v = if mode & 1 == 0 {
        r.process(*card as u16 % (CARDS + 1), &mut frame, off, len)
    } else {
        // A packet from the router's own host (an IP packet after room
        // for an Ethernet header).
        let off = off.max(64);
        let n = len.min(FRAME - off);
        r.inject_host(&mut frame, off - 14, 14 + n)
    };
    if let Verdict::Tx { port, off, len } = v {
        assert!(off + len <= FRAME, "sent past the end of the buffer");
        assert!(
            (port as usize) < r.ports().len(),
            "sent out of a port that doesn't exist"
        );
    }
    if mode & 2 != 0 {
        r.housekeeping();
    }
    for e in r.emits.drain(..) {
        assert!(e.len <= e.frame.len());
    }
    r.punts.clear();
    r.host_out.clear();
    r.learned.clear();
    r.tracer.events.clear();
}

/// A MAC address for test frames.
pub fn mac(n: u8) -> Mac {
    [0x52, 0x54, 0, 0, 0, n]
}

const R_LAN: Mac = [0x02, 0, 0, 0, 0, 0];
const R_WAN: Mac = [0x02, 0, 0, 0, 1, 2];
const R_ISP: Mac = [0x02, 0, 0, 0, 2, 3];
const AC: Mac = [0x02, 0, 0, 0, 0, 0xac];

/// A TCP segment (`flags`), Ethernet framed.
fn tcp(dst_mac: Mac, src: (&str, u16), dst: (&str, u16), flags: u8, opts: &[u8]) -> Vec<u8> {
    let tcp_len = 20 + opts.len();
    let ip_len = ipv4::MIN_HDR_LEN + tcp_len;
    let mut f = vec![0u8; eth::HDR_LEN + ip_len];
    eth::write(&mut f, dst_mac, mac(0x0a), eth::TYPE_IPV4);
    ipv4::write_header(
        &mut f[14..],
        ip_len as u16,
        7,
        64,
        ipv4::PROTO_TCP,
        ip(src.0),
        ip(dst.0),
    );
    let t = &mut f[34..];
    t[0..2].copy_from_slice(&src.1.to_be_bytes());
    t[2..4].copy_from_slice(&dst.1.to_be_bytes());
    t[12] = ((tcp_len / 4) as u8) << 4;
    t[13] = flags;
    t[20..].copy_from_slice(opts);
    f
}

fn udp(dst_mac: Mac, src: (&str, u16), dst: (&str, u16), payload: &[u8]) -> Vec<u8> {
    dhcp::build_frame(
        mac(0x0a),
        dst_mac,
        (ip(src.0), src.1),
        (ip(dst.0), dst.1),
        payload,
    )
}

fn icmp(dst_mac: Mac, src: &str, dst: &str, kind: u8, quote: &[u8]) -> Vec<u8> {
    let ip_len = ipv4::MIN_HDR_LEN + 8 + quote.len();
    let mut f = vec![0u8; eth::HDR_LEN + ip_len];
    eth::write(&mut f, dst_mac, mac(0x0a), eth::TYPE_IPV4);
    ipv4::write_header(
        &mut f[14..],
        ip_len as u16,
        9,
        64,
        ipv4::PROTO_ICMP,
        ip(src),
        ip(dst),
    );
    f[34] = kind;
    f[42..].copy_from_slice(quote);
    f
}

fn vlan(mut f: Vec<u8>, vid: u16) -> Vec<u8> {
    let mut out = vec![0u8; 4];
    out.append(&mut f);
    eth::push_vlan(&mut out, 4, vid);
    out
}

/// Valid frames of every kind the router deals with, each with the card
/// it arrives on: starting points for mutation.
pub fn templates() -> Vec<(u8, Vec<u8>)> {
    let mss = [2, 4, 0x05, 0xb4, 1, 3, 3, 7, 4, 2, 0, 0];
    let quoted = tcp(R_WAN, ("192.0.2.1", 40000), ("8.8.8.8", 443), 0x02, &[]);
    let mut dhcp_msg = dhcp::Message::new(dhcp::OP_REQUEST, 1, mac(0x0a));
    dhcp_msg.set(dhcp::OPT_MSG_TYPE, vec![dhcp::DISCOVER]);
    let mut arp_req = vec![0u8; 64];
    let n = arp::build_request(&mut arp_req, mac(0x0a), ip("10.10.1.10"), ip("10.10.1.1"));
    arp_req.truncate(n);
    let lan_out = tcp(R_LAN, ("10.10.1.10", 40000), ("8.8.8.8", 443), 0x02, &mss);
    vec![
        // card, frame
        (0, lan_out.clone()),
        (
            0,
            tcp(R_LAN, ("10.10.1.10", 40001), ("10.10.1.1", 22), 0x02, &mss),
        ),
        (
            0,
            tcp(R_LAN, ("10.10.1.10", 40002), ("10.10.1.1", 8443), 0x02, &[]),
        ),
        (
            0,
            tcp(R_LAN, ("10.10.1.10", 40003), ("10.2.0.9", 5201), 0x02, &mss),
        ),
        (
            0,
            udp(R_LAN, ("10.10.1.10", 5353), ("10.10.10.10", 53), b"query"),
        ),
        (
            0,
            udp(
                eth::BROADCAST,
                ("0.0.0.0", 68),
                ("255.255.255.255", 67),
                &dhcp_msg.encode(),
            ),
        ),
        (0, icmp(R_LAN, "10.10.1.10", "10.10.1.1", 8, b"ping")),
        (0, arp_req.clone()),
        (
            0,
            vlan(
                tcp(R_LAN, ("10.10.10.10", 40004), ("10.10.1.10", 80), 0x02, &[]),
                10,
            ),
        ),
        (0, vlan(arp_req, 10)),
        (0, vlan(lan_out, 99)),
        (
            1,
            tcp(R_WAN, ("8.8.8.8", 443), ("192.0.2.1", 40000), 0x12, &mss),
        ),
        (
            1,
            udp(R_WAN, ("192.0.2.6", 4800), ("192.0.2.1", 4800), &[0u8; 80]),
        ),
        (1, icmp(R_WAN, "8.8.4.4", "192.0.2.1", 3, &quoted[14..42])),
        (1, icmp(R_WAN, "8.8.4.4", "192.0.2.1", 11, &quoted[14..])),
        (
            2,
            vlan(
                pppoe::session(
                    AC,
                    R_ISP,
                    0x42,
                    pppoe::PROTO_IPV4,
                    &tcp(R_ISP, ("1.1.1.1", 443), ("203.0.113.50", 40000), 0x12, &[])[14..],
                ),
                7,
            ),
        ),
        (
            2,
            vlan(
                pppoe::session(AC, R_ISP, 0x42, pppoe::PROTO_LCP, &[9, 1, 0, 8, 1, 2, 3, 4]),
                7,
            ),
        ),
        (
            2,
            vlan(pppoe::discovery(AC, R_ISP, pppoe::PADT, 0x42, &[]), 7),
        ),
    ]
}

/// One fuzz input, on a fresh router, so every crash reproduces from its
/// input alone. The input is a series of packets, so state built by
/// earlier ones (sessions, NAT, neighbours) is exercised too:
///
/// - a first byte below 0x80 starts from template `byte % n` (see
///   [`templates`]), then: a count, that many (position, value) edits, and
///   a length cut;
/// - otherwise: two bytes of length, then that many bytes for [`run`].
pub fn fuzz_input(data: &[u8]) {
    let mut r = router();
    let t = templates();
    let mut rest = data;
    for _ in 0..16 {
        let Some((&first, tail)) = rest.split_first() else {
            return;
        };
        if first < 0x80 {
            let (card, base) = &t[first as usize % t.len()];
            let n = (tail.first().copied().unwrap_or(0) as usize % 8) * 2;
            let edits = tail.get(1..1 + n).unwrap_or(&[]);
            let mut f = base.clone();
            for e in edits.chunks(2) {
                if let [at, v] = e {
                    if !f.is_empty() {
                        let i = *at as usize % f.len();
                        f[i] = *v;
                    }
                }
            }
            if let Some(c) = tail.get(1 + n).copied().filter(|c| *c < 0x40) {
                f.truncate(f.len() * c as usize / 0x40);
            }
            let mut input = vec![0, *card, 1, 0, first];
            input.extend_from_slice(&f);
            run(&mut r, &input);
            rest = tail.get(2 + n..).unwrap_or(&[]);
        } else {
            let n = tail
                .get(..2)
                .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]) as usize % 2048);
            let body = tail.get(2..).unwrap_or(&[]);
            let n = n.min(body.len());
            run(&mut r, &body[..n]);
            rest = &body[n..];
        }
    }
}
