//! How fast the pipeline itself is: packets through [`Pipeline::process`]
//! on one core, with no network card, so the number is the CPU's ceiling
//! per worker, before AF_XDP, the NIC and the wire take their share.
//! `ephemerisd --bench-pipeline` runs it on the machine at hand.
//!
//! The router is a plain edge router: a LAN (10.0.0.0/24, 256 hosts) and a
//! WAN (203.0.113.1/24, default route via .254). Each case cycles through
//! 1024 flows of small UDP packets (64 bytes on the wire), copying each one
//! into the buffer first, as a receive ring would hand it over.

use crate::config::{Dhcp, Pppoe, Role};
use crate::nat::{FirewallRule, Forward, NatConfig, Side};
use crate::overlay::Overlay;
use crate::{build_fib, Neighbor, Pipeline, Port, SessionConfig, StaticRoute, Verdict};
use eph_packet::{eth, ipv4, Mac};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const OFF: usize = 128;
const FLOWS: u16 = 1024;
const R_LAN: Mac = [2, 0, 0, 0, 0, 1];
const R_WAN: Mac = [2, 0, 0, 0, 0, 2];
const ISP: Mac = [0x52, 0, 0, 0, 0, 0xfe];
const WAN_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

/// One case's result.
#[derive(Debug, Clone)]
pub struct Measure {
    pub name: &'static str,
    pub what: &'static str,
    pub ns_per_packet: f64,
}

impl Measure {
    pub fn mpps(&self) -> f64 {
        1e3 / self.ns_per_packet
    }
}

/// Every case, each run for about `budget`.
pub fn run(budget: Duration) -> Vec<Measure> {
    let mut out = Vec::new();

    // Routed, no NAT: LAN to WAN on established sessions.
    let mut r = router(NatConfig::off(), 1 << 16);
    let t = outbound();
    out.push(measure(
        "routed",
        "established, no NAT",
        &mut r,
        0,
        &t,
        budget,
    ));

    // Source NAT out, and its replies in.
    let mut r = router(NatConfig::default(), 1 << 16);
    let t = outbound();
    out.push(measure(
        "nat-out",
        "established, source NAT",
        &mut r,
        0,
        &t,
        budget,
    ));
    let replies = replies_to(&mut r, &t);
    out.push(measure(
        "nat-in",
        "replies to source NAT",
        &mut r,
        1,
        &replies,
        budget,
    ));

    // A port forward's established sessions, from 1024 clients.
    let fwd = NatConfig {
        forwards: vec![Forward {
            name: "web".into(),
            port: 1,
            proto: ipv4::PROTO_UDP,
            ports: (8080, 8080),
            to: Ipv4Addr::new(10, 0, 0, 10),
            to_port: 80,
            from: vec![],
        }],
        ..NatConfig::default()
    };
    let mut r = router(fwd, 1 << 16);
    let t: Vec<Vec<u8>> = (0..FLOWS)
        .map(|i| udp(R_WAN, ISP, client(i), 40000 + i, WAN_ADDR, 8080))
        .collect();
    out.push(measure(
        "forward-in",
        "established, port forward",
        &mut r,
        1,
        &t,
        budget,
    ));

    // New sessions: every packet a flow the table hasn't seen.
    let n = 200_000u32;
    let mut r = router(NatConfig::default(), n.next_power_of_two() * 2);
    out.push(new_sessions("new", "new sessions, source NAT", &mut r, n));
    let rules = (0..20)
        .map(|i| FirewallRule {
            name: format!("rule {i}"),
            allow: false,
            from: Side::Prefix(format!("172.16.{i}.0/24").parse().expect("a prefix")),
            to: Side::Any,
            proto: Some(ipv4::PROTO_TCP),
            ports: Some((25, 25)),
        })
        .collect();
    let fw = NatConfig {
        firewall: rules,
        ..NatConfig::default()
    };
    let mut r = router(fw, n.next_power_of_two() * 2);
    out.push(new_sessions(
        "new-fw20",
        "new sessions, 20 firewall rules",
        &mut r,
        n,
    ));
    out
}

fn host(i: u16) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, 10 + (i % 240) as u8)
}

fn client(i: u16) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100 + (i / 250) as u8, 1 + (i % 250) as u8)
}

fn router(nat: NatConfig, max_sessions: u32) -> Pipeline {
    let port = |id: u16, name: &str, mac: Mac, addr: &str, subnet: &str, role: Role| Port {
        id,
        card: id,
        vlan: None,
        host: Default::default(),
        name: name.into(),
        mac,
        addr: addr.parse().expect("an address"),
        subnet: subnet.parse().expect("a prefix"),
        allow_new_sessions: role == Role::Inside,
        role,
        mss_adjust: None,
        dhcp: Dhcp::Off,
        gateway: None,
        pppoe: Pppoe::Off,
        onlink: vec![],
        strict_source: role == Role::Inside,
        mtu: 1500,
    };
    let ports: Arc<[Port]> = Arc::new([
        port(0, "lan", R_LAN, "10.0.0.1", "10.0.0.0/24", Role::Inside),
        port(
            1,
            "wan",
            R_WAN,
            "203.0.113.1",
            "203.0.113.0/24",
            Role::Outside,
        ),
    ]);
    let routes = [StaticRoute {
        prefix: "0.0.0.0/0".parse().expect("a prefix"),
        via: Ipv4Addr::new(203, 0, 113, 254),
    }];
    let fib = build_fib(&ports, &routes, &[]).expect("a valid table");
    let sessions = SessionConfig {
        max_sessions,
        ..SessionConfig::default()
    };
    let mut r = Pipeline::new(
        ports,
        Arc::new(fib),
        sessions,
        Arc::new(Overlay::disabled()),
    );
    r.set_nat(Arc::new(nat));
    r.set_time(1_000_000_000);
    for i in 0..240 {
        r.learn(Neighbor {
            port: 0,
            ip: host(i),
            mac: [0x52, 0, 0, 0, 1, i as u8],
        });
    }
    r.learn(Neighbor {
        port: 1,
        ip: Ipv4Addr::new(203, 0, 113, 254),
        mac: ISP,
    });
    r
}

/// A UDP packet with 18 bytes of payload (64 bytes with the FCS), at OFF.
fn udp(
    dst_mac: Mac,
    src_mac: Mac,
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
) -> Vec<u8> {
    let len = 20 + 8 + 18;
    let mut f = vec![0u8; OFF + 14 + len];
    eth::write(&mut f[OFF..], dst_mac, src_mac, eth::TYPE_IPV4);
    ipv4::write_header(
        &mut f[OFF + 14..],
        len as u16,
        1,
        64,
        ipv4::PROTO_UDP,
        src,
        dst,
    );
    let u = &mut f[OFF + 34..];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&((8 + 18) as u16).to_be_bytes());
    // Checksum 0: none (UDP over IPv4 allows it), so NAT leaves it alone.
    f
}

/// 1024 flows from LAN hosts to internet servers.
fn outbound() -> Vec<Vec<u8>> {
    (0..FLOWS)
        .map(|i| {
            let mac = [0x52, 0, 0, 0, 1, (i % 240) as u8];
            udp(R_LAN, mac, host(i), 40000 + i, client(i), 443)
        })
        .collect()
}

/// The replies to `out`'s flows, as they come back to the NAT address.
fn replies_to(r: &mut Pipeline, out: &[Vec<u8>]) -> Vec<Vec<u8>> {
    out.iter()
        .map(|t| {
            let mut f = t.clone();
            let Verdict::Tx { off, .. } = r.process(0, &mut f, OFF, t.len() - OFF) else {
                panic!("an outbound packet wasn't sent");
            };
            let ip = &f[off + 14..];
            let src = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
            let sport = u16::from_be_bytes([ip[20], ip[21]]);
            let dport = u16::from_be_bytes([ip[22], ip[23]]);
            let to = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
            udp(R_WAN, ISP, src, dport, to, sport)
        })
        .collect()
}

/// Run `templates` through `r`, arriving on `card`, round and round for
/// about `budget`. Each must be sent: anything else means the case isn't
/// measuring what it says.
fn measure(
    name: &'static str,
    what: &'static str,
    r: &mut Pipeline,
    card: u16,
    templates: &[Vec<u8>],
    budget: Duration,
) -> Measure {
    let mut buf = vec![0u8; 2048];
    for t in templates {
        buf[..t.len()].copy_from_slice(t);
        let v = r.process(card, &mut buf, OFF, t.len() - OFF);
        assert!(matches!(v, Verdict::Tx { .. }), "{name}: {v:?}");
    }
    let (mut n, start) = (0u64, Instant::now());
    while start.elapsed() < budget {
        for t in templates {
            buf[..t.len()].copy_from_slice(t);
            black_box(r.process(card, &mut buf, OFF, t.len() - OFF));
        }
        n += templates.len() as u64;
        clear(r);
    }
    Measure {
        name,
        what,
        ns_per_packet: start.elapsed().as_secs_f64() * 1e9 / n as f64,
    }
}

/// `n` packets, each starting a session (into an empty table at least
/// twice that big, so none is refused): one host, a new pair of ports
/// each time (UDP without a checksum, so only the ports change).
fn new_sessions(name: &'static str, what: &'static str, r: &mut Pipeline, n: u32) -> Measure {
    let t = udp(R_LAN, [0x52, 0, 0, 0, 1, 0], host(0), 0, client(0), 0);
    let mut buf = vec![0u8; 2048];
    let start = Instant::now();
    for i in 0..n {
        let sport = 1024 + (i % 64_000) as u16;
        let dport = 443 + (i / 64_000) as u16;
        buf[..t.len()].copy_from_slice(&t);
        buf[OFF + 34..OFF + 36].copy_from_slice(&sport.to_be_bytes());
        buf[OFF + 36..OFF + 38].copy_from_slice(&dport.to_be_bytes());
        let v = r.process(0, &mut buf, OFF, t.len() - OFF);
        debug_assert!(matches!(v, Verdict::Tx { .. }), "{name}: {v:?}");
        black_box(v);
        if i % 1024 == 0 {
            clear(r);
        }
    }
    Measure {
        name,
        what,
        ns_per_packet: start.elapsed().as_secs_f64() * 1e9 / n as f64,
    }
}

fn clear(r: &mut Pipeline) {
    r.emits.clear();
    r.punts.clear();
    r.handoffs.clear();
    r.learned.clear();
    r.host_out.clear();
    r.tracer.events.clear();
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_case_sends_its_packets() {
        // Short: this checks the cases are set up right, not the speed.
        let m = super::run(std::time::Duration::from_millis(5));
        assert_eq!(m.len(), 6);
        assert!(m.iter().all(|m| m.ns_per_packet > 0.0));
    }
}
