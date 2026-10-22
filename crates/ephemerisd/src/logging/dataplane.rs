//! Packet trace events from the workers, as log lines.
//!
//! The pipeline records [`TraceEvent`]s (see `eph_dataplane::trace`); the
//! worker hands them here after each batch. Each becomes one debug line in
//! its category, e.g.
//!
//! ```text
//! DEBUG route       drop no-route: udp 10.10.1.10:5353 -> 8.8.8.8:53 in lan
//! DEBUG nat         tcp 10.10.1.10:51000 -> 1.1.1.1:443 in lan: translated to 203.0.113.2:40001
//! DEBUG arp         10.10.1.10 is 52:54:00:00:00:0a on lan (new)
//! ```

use eph_dataplane::trace::{TraceCat, TraceEvent, TraceFlow, TraceKind};
use eph_dataplane::Port;
use eph_packet::eth::fmt_mac;
use eph_packet::icmp;

/// A debug line in `cat`'s category. (`target:` has to be a constant, so
/// one arm per category.)
macro_rules! at {
    ($cat:expr, $($arg:tt)+) => {
        match $cat {
            TraceCat::Interface => tracing::debug!(target: "interface", $($arg)+),
            TraceCat::Arp => tracing::debug!(target: "arp", $($arg)+),
            TraceCat::Route => tracing::debug!(target: "route", $($arg)+),
            TraceCat::Session => tracing::debug!(target: "session", $($arg)+),
            TraceCat::Nat => tracing::debug!(target: "nat", $($arg)+),
            TraceCat::Filter => tracing::debug!(target: "filter", $($arg)+),
            TraceCat::Icmp => tracing::debug!(target: "icmp", $($arg)+),
            TraceCat::Sdwan => tracing::debug!(target: "sdwan", $($arg)+),
            TraceCat::Dataplane => tracing::debug!(target: "dataplane", $($arg)+),
        }
    };
}

/// "tcp 10.0.0.1:1234 -> 1.1.1.1:443", "icmp 10.0.0.1 -> 8.8.8.8 type 8/0".
pub fn flow(f: &TraceFlow) -> String {
    match f.proto {
        0 => format!("{} -> {}", f.src, f.dst),
        6 | 17 => format!(
            "{} {}:{} -> {}:{}",
            if f.proto == 6 { "tcp" } else { "udp" },
            f.src,
            f.sport,
            f.dst,
            f.dport
        ),
        1 => format!("icmp {} -> {} type {}/{}", f.src, f.dst, f.sport, f.dport),
        p => format!("proto {p} {} -> {}", f.src, f.dst),
    }
}

fn icmp_name(kind: u8, code: u8) -> &'static str {
    match (kind, code) {
        (icmp::TIME_EXCEEDED, _) => "time-exceeded",
        (icmp::DEST_UNREACHABLE, icmp::CODE_FRAG_NEEDED) => "fragmentation-needed",
        (icmp::DEST_UNREACHABLE, 0) => "net-unreachable",
        (icmp::DEST_UNREACHABLE, 1) => "host-unreachable",
        (icmp::DEST_UNREACHABLE, 3) => "port-unreachable",
        (icmp::DEST_UNREACHABLE, _) => "unreachable",
        _ => "error",
    }
}

/// The interface name for a trace's port (or the card, when the frame
/// matched no interface: `PortId::MAX - card`).
fn port_name(ports: &[Port], id: u16) -> String {
    match ports.get(id as usize) {
        Some(p) => p.name.clone(),
        None => format!("card {}", u16::MAX - id),
    }
}

/// Log one event (as the worker that recorded it).
pub fn emit(ev: &TraceEvent, ports: &[Port], worker: usize) {
    let on = port_name(ports, ev.port);
    let f = &ev.flow;
    let cat = ev.cat();
    match ev.kind {
        TraceKind::Drop(r) => at!(cat, worker, "drop {}: {} in {on}", r.name(), flow(f)),
        TraceKind::SessionNew => at!(cat, worker, "new session: {} in {on}", flow(f)),
        TraceKind::NatBound { addr, port } => {
            at!(
                cat,
                worker,
                "{} in {on}: translated to {addr}:{port}",
                flow(f)
            )
        }
        TraceKind::ArpLearned { mac, changed } => at!(
            cat,
            worker,
            "{} is {} on {on} ({})",
            f.src,
            fmt_mac(&mac),
            if changed { "moved" } else { "new" }
        ),
        TraceKind::ArpConflict { claimed, known } => at!(
            cat,
            worker,
            "{} claimed by {} on {on}, but known as {}: not believed, asking again",
            f.src,
            fmt_mac(&claimed),
            fmt_mac(&known)
        ),
        TraceKind::ArpRequest => at!(cat, worker, "who has {}? (ARP request on {on})", f.dst),
        TraceKind::IcmpSent { kind, code } => at!(
            cat,
            worker,
            "sent {} ({kind}/{code}) to {} about {}",
            icmp_name(kind, code),
            f.src,
            flow(f)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flows_read_like_a_router_would_say_them() {
        let f = |proto, sport, dport| TraceFlow {
            proto,
            src: "10.0.0.1".parse().unwrap(),
            dst: "8.8.8.8".parse().unwrap(),
            sport,
            dport,
        };
        assert_eq!(flow(&f(17, 5353, 53)), "udp 10.0.0.1:5353 -> 8.8.8.8:53");
        assert_eq!(flow(&f(1, 8, 0)), "icmp 10.0.0.1 -> 8.8.8.8 type 8/0");
        assert_eq!(flow(&f(47, 0, 0)), "proto 47 10.0.0.1 -> 8.8.8.8");
        assert_eq!(icmp_name(3, 4), "fragmentation-needed");
        assert_eq!(port_name(&[], u16::MAX - 2), "card 2");
    }
}
