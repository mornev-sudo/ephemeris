//! Packet tracing: what the data plane did with individual packets, for
//! debugging, only while someone asks.
//!
//! The pipeline never formats text or takes a lock. When a trace category
//! is switched on, it records a small fixed-size [`TraceEvent`] into a list
//! the worker drains after each batch (and turns into log lines). Three
//! things keep this cheap and safe on a busy router:
//!
//! - **Off costs one bit test.** Each category is a bit in
//!   [`TraceConfig::mask`]; with the bit clear nothing else happens.
//! - **A host filter** ([`TraceConfig::host`]): only packets to or from that
//!   prefix are traced, like a router's conditional debug.
//! - **A rate limit** per worker ([`TraceConfig::per_sec`]): beyond it,
//!   events are counted as suppressed, not recorded.

use crate::config::PortId;
use crate::stats::DropReason;
use eph_fib::Prefix;
use eph_packet::Mac;
use std::net::Ipv4Addr;

/// What can be traced, one bit each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TraceCat {
    /// Frames the router can't use: wrong MAC, unknown VLAN, not IPv4/ARP.
    Interface = 1 << 0,
    /// Neighbours: learned, changed, conflicts, ARP requests sent.
    Arp = 1 << 1,
    /// Routing decisions that fail: no route, TTL, too big for the MTU.
    Route = 1 << 2,
    /// Sessions: created, refused (no session, TCP state, table full).
    Session = 1 << 3,
    /// Source NAT: translations made, ports exhausted.
    Nat = 1 << 4,
    /// The packet filter: martians, spoofed sources, bad headers, options.
    Filter = 1 << 5,
    /// ICMP errors the router sends, and those it holds back (rate limit).
    Icmp = 1 << 6,
    /// SD-WAN tether traffic the router refuses.
    Sdwan = 1 << 7,
    /// The worker itself: TX ring full, control-plane queue full.
    Dataplane = 1 << 8,
}

impl TraceCat {
    pub const ALL: [TraceCat; 9] = [
        TraceCat::Interface,
        TraceCat::Arp,
        TraceCat::Route,
        TraceCat::Session,
        TraceCat::Nat,
        TraceCat::Filter,
        TraceCat::Icmp,
        TraceCat::Sdwan,
        TraceCat::Dataplane,
    ];

    /// The log category it's reported under (see ephemerisd's `logging`).
    pub fn name(self) -> &'static str {
        match self {
            TraceCat::Interface => "interface",
            TraceCat::Arp => "arp",
            TraceCat::Route => "route",
            TraceCat::Session => "session",
            TraceCat::Nat => "nat",
            TraceCat::Filter => "filter",
            TraceCat::Icmp => "icmp",
            TraceCat::Sdwan => "sdwan",
            TraceCat::Dataplane => "dataplane",
        }
    }

    pub fn bit(self) -> u32 {
        self as u32
    }

    /// Which category a drop belongs to. `None`: not worth tracing (handed
    /// to the control plane, which logs it, or not really a drop).
    pub fn of_drop(r: DropReason) -> Option<TraceCat> {
        use DropReason::*;
        Some(match r {
            NotForUs | Vlan | UnsupportedEthertype => TraceCat::Interface,
            NeighborMiss => TraceCat::Arp,
            NoRoute | TtlExceeded | TooBig | LocalUnhandled => TraceCat::Route,
            NoSession | InvalidTcpState | SessionTableFull | SessionMismatch => TraceCat::Session,
            NatExhausted | NatUntranslatable => TraceCat::Nat,
            Malformed | BadIpHeader | BadL4Header | Martian | SpoofedSource | IpOption
            | BadFragment | FragmentToRouter | IcmpMismatch => TraceCat::Filter,
            IcmpRateLimited => TraceCat::Icmp,
            NoPath | UnknownTether | BadOverlay | OverlayAuth | OverlayReplay => TraceCat::Sdwan,
            TxRingFull | ControlQueueFull => TraceCat::Dataplane,
            ArpConsumed | OverlayControl | DhcpToControl | PppoeToControl | ToHost => return None,
        })
    }
}

/// What to trace, set by the control plane (`Control::SetTrace`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceConfig {
    /// [`TraceCat`] bits switched on.
    pub mask: u32,
    /// Only packets with a source or destination in here.
    pub host: Option<Prefix>,
    /// Events per second per worker, at most (bursts of as many).
    pub per_sec: u32,
}

impl Default for TraceConfig {
    fn default() -> Self {
        TraceConfig {
            mask: 0,
            host: None,
            per_sec: 100,
        }
    }
}

/// A packet's addresses, as far as they're known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceFlow {
    /// IP protocol (6 TCP, 17 UDP, 1 ICMP); 0 for frames that aren't IPv4.
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// Ports for TCP/UDP; ICMP: type and code.
    pub sport: u16,
    pub dport: u16,
}

impl Default for TraceFlow {
    fn default() -> Self {
        TraceFlow {
            proto: 0,
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
            sport: 0,
            dport: 0,
        }
    }
}

impl Default for TraceKind {
    fn default() -> Self {
        TraceKind::Drop(DropReason::Malformed)
    }
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceKind {
    /// Not forwarded, and why.
    Drop(DropReason),
    /// A new session.
    SessionNew,
    /// A session's source was translated to `addr:port`.
    NatBound { addr: Ipv4Addr, port: u16 },
    /// A neighbour learned, or its MAC changed (`changed`).
    ArpLearned { mac: Mac, changed: bool },
    /// An ARP packet disagreed with what's known: not believed, re-checked.
    ArpConflict { claimed: Mac, known: Mac },
    /// An ARP request was sent for `flow.dst`.
    ArpRequest,
    /// The router sent an ICMP error (type, code) about this packet.
    IcmpSent { kind: u8, code: u8 },
}

/// One traced event. Copy, fixed size: recording one never allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TraceEvent {
    pub cat_bit: u32,
    pub kind: TraceKind,
    /// The interface it arrived on (or, for ARP requests, left by).
    pub port: PortId,
    pub flow: TraceFlow,
}

impl TraceEvent {
    pub fn cat(&self) -> TraceCat {
        TraceCat::ALL
            .into_iter()
            .find(|c| c.bit() == self.cat_bit)
            .unwrap_or(TraceCat::Dataplane)
    }
}

/// Recorded events per batch at most, whatever the rate limit says.
pub const TRACE_BATCH_MAX: usize = 256;

/// The pipeline's tracing state.
#[derive(Debug, Clone, Default)]
pub struct Tracer {
    pub cfg: TraceConfig,
    tokens: u64,
    last_refill_ns: u64,
    /// Events over the rate limit since the worker last reported them.
    pub suppressed: u64,
    pub events: Vec<TraceEvent>,
}

impl Tracer {
    pub fn set(&mut self, cfg: TraceConfig) {
        self.cfg = cfg;
        self.tokens = cfg.per_sec as u64;
        if cfg.mask != 0 && self.events.capacity() < TRACE_BATCH_MAX {
            self.events.reserve(TRACE_BATCH_MAX);
        }
    }

    /// Is `cat` switched on at all? (The cheap check before building an
    /// event.)
    #[inline(always)]
    pub fn on(&self, cat: TraceCat) -> bool {
        self.cfg.mask & cat.bit() != 0
    }

    /// Record an event if its category is on, it matches the host filter,
    /// and the rate limit allows.
    pub fn record(
        &mut self,
        now_ns: u64,
        cat: TraceCat,
        kind: TraceKind,
        port: PortId,
        flow: TraceFlow,
    ) {
        if !self.on(cat) {
            return;
        }
        if let Some(h) = self.cfg.host {
            if !h.contains(flow.src) && !h.contains(flow.dst) {
                return;
            }
        }
        let per_sec = self.cfg.per_sec as u64;
        let elapsed = now_ns.saturating_sub(self.last_refill_ns);
        if per_sec > 0 && elapsed >= 1_000_000_000 / per_sec {
            let add = elapsed * per_sec / 1_000_000_000;
            self.tokens = (self.tokens + add).min(per_sec);
            self.last_refill_ns = now_ns;
        }
        if self.tokens == 0 || self.events.len() >= TRACE_BATCH_MAX {
            self.suppressed += 1;
            return;
        }
        self.tokens -= 1;
        self.events.push(TraceEvent {
            cat_bit: cat.bit(),
            kind,
            port,
            flow,
        });
    }
}

/// The addresses of the IPv4 packet in an Ethernet frame (zeros if it
/// isn't one). Only called once tracing is known to be wanted.
pub fn flow_of_frame(f: &[u8]) -> TraceFlow {
    use eph_packet::{eth, ipv4};
    if f.len() < eth::HDR_LEN + ipv4::MIN_HDR_LEN || eth::ethertype(f) != eth::TYPE_IPV4 {
        return TraceFlow::default();
    }
    let ip = &f[eth::HDR_LEN..];
    let ihl = (ip[0] & 0x0f) as usize * 4;
    let rd = |o: usize| u16::from_be_bytes([ip[o], ip[o + 1]]);
    let mut fl = TraceFlow {
        proto: ip[9],
        src: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        sport: 0,
        dport: 0,
    };
    // Ports (or ICMP type/code) only in a first fragment that has them.
    let first = rd(6) & 0x1fff == 0;
    if first && ihl >= ipv4::MIN_HDR_LEN && ip.len() >= ihl + 4 {
        match fl.proto {
            ipv4::PROTO_TCP | ipv4::PROTO_UDP => {
                fl.sport = rd(ihl);
                fl.dport = rd(ihl + 2);
            }
            ipv4::PROTO_ICMP => {
                fl.sport = ip[ihl] as u16;
                fl.dport = ip[ihl + 1] as u16;
            }
            _ => {}
        }
    }
    fl
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(dst: &str) -> TraceFlow {
        TraceFlow {
            proto: 17,
            src: "10.0.0.1".parse().unwrap(),
            dst: dst.parse().unwrap(),
            sport: 1,
            dport: 2,
        }
    }

    #[test]
    fn off_filtered_and_rate_limited() {
        let mut t = Tracer::default();
        let drop = TraceKind::Drop(DropReason::NoRoute);
        t.record(0, TraceCat::Route, drop, 0, flow("8.8.8.8"));
        assert!(t.events.is_empty(), "off by default");

        t.set(TraceConfig {
            mask: TraceCat::Route.bit(),
            host: Some("8.8.8.0/24".parse().unwrap()),
            per_sec: 3,
        });
        t.record(0, TraceCat::Session, drop, 0, flow("8.8.8.8"));
        t.record(0, TraceCat::Route, drop, 0, flow("1.1.1.1"));
        assert!(t.events.is_empty(), "other category, other host");
        for _ in 0..5 {
            t.record(0, TraceCat::Route, drop, 0, flow("8.8.8.8"));
        }
        assert_eq!((t.events.len(), t.suppressed), (3, 2), "a burst of 3");
        // A second later, 3 more.
        t.events.clear();
        for _ in 0..5 {
            t.record(1_000_000_000, TraceCat::Route, drop, 0, flow("8.8.8.8"));
        }
        assert_eq!(t.events.len(), 3);
        assert_eq!(t.events[0].cat(), TraceCat::Route);
    }

    #[test]
    fn every_drop_reason_has_a_place() {
        // Adding a reason means deciding where it's traced (the match is
        // exhaustive); this just checks the names line up.
        for r in DropReason::ALL {
            if let Some(c) = TraceCat::of_drop(r) {
                assert!(TraceCat::ALL.contains(&c), "{r:?}");
            }
        }
        assert_eq!(TraceCat::of_drop(DropReason::DhcpToControl), None);
    }
}
