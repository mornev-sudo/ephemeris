//! What workers publish about themselves, and what they can be told.
//! Portable (no Linux types) so the management code builds and tests anywhere.

use eph_dataplane::nat::NatConfig;
use eph_dataplane::overlay::{PathTable, TetherStats};
use eph_dataplane::{Dir, Neighbor, NextHop, Port, PortId, Session, Stats};
use eph_fib::Fib;
use std::fmt;
use std::sync::Arc;

/// Messages to a worker. Workers poll their channel once per loop iteration,
/// so a control-plane change reaches the data plane within microseconds,
/// and never in the middle of a packet.
pub enum Control {
    /// A neighbour another worker learned.
    Neighbor(Neighbor),
    /// A new forwarding table (built by the control plane, swapped by pointer).
    SetFib(Arc<Fib<NextHop>>),
    /// New port settings (addresses, policy) for the same interfaces.
    SetPorts(Arc<[Port]>),
    /// New SD-WAN path decisions.
    SetPaths(Arc<PathTable>),
    /// New source-NAT rules (existing sessions keep their translation).
    SetNat(Arc<NatConfig>),
    /// Send this frame out of `port` (DHCP replies and requests).
    Transmit { port: PortId, frame: Vec<u8> },
}

/// AF_XDP socket counters kept by the kernel.
#[derive(Default, Clone, Copy)]
pub struct KernelStats {
    /// Dropped because our RX ring was full or the frame was invalid.
    pub rx_dropped: u64,
    /// The NIC had a packet but we hadn't given it a free frame.
    pub fill_empty: u64,
}

/// A worker's published state, refreshed about once a second.
#[derive(Default, Clone)]
pub struct Report {
    pub stats: Stats,
    pub neighbors: Vec<Neighbor>,
    pub kernel: KernelStats,
    /// A sample of live sessions.
    pub sessions: Vec<SessionView>,
    /// Per overlay tether: counters and probe measurements.
    pub tethers: Vec<TetherStats>,
    /// Time spent on loop rounds that had packets to handle (ns, since the
    /// worker started): divided by the time passed, how busy it really is,
    /// even with busy polling (which shows 100% CPU regardless).
    pub busy_ns: u64,
    pub sessions_max: u64,
    pub nat_active: u64,
    pub neighbor_count: u64,
    /// When `sessions` and `neighbors` were last filled in (Unix ms; 0 =
    /// never). They're only gathered while someone is looking at them.
    pub detail_ms: u64,
}

/// Session and neighbour lists are only gathered while someone looks:
/// the API sets this (Unix ms) a few seconds ahead, workers check it.
pub type DetailWanted = std::sync::Arc<std::sync::atomic::AtomicU64>;

/// The newest sessions a view shows, per worker and in total.
pub const SESSION_DETAIL: usize = 1000;

pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A copy of a session, detached from the worker's table.
#[derive(Clone)]
pub struct SessionView {
    pub session: Session,
    pub now_ns: u64,
}

impl SessionView {
    pub fn proto_name(&self) -> String {
        match self.session.key.proto {
            6 => "tcp".into(),
            17 => "udp".into(),
            1 => "icmp".into(),
            p => format!("proto{p}"),
        }
    }
    pub fn age_secs(&self) -> u64 {
        self.now_ns.saturating_sub(self.session.created_ns) / 1_000_000_000
    }
    pub fn idle_secs(&self) -> u64 {
        self.now_ns.saturating_sub(self.session.last_seen_ns) / 1_000_000_000
    }
}

impl fmt::Display for SessionView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = &self.session;
        let ((ia, ip), (ra, rp)) = s.endpoints();
        let (fwd, rev) = (Dir::Forward as usize, Dir::Reverse as usize);
        write!(
            f,
            "{:<5} {ia}:{ip} -> {ra}:{rp}  {:<12} pkts {}/{} bytes {}/{} age {}s idle {}s",
            self.proto_name(),
            s.state.name(),
            s.packets[fwd],
            s.packets[rev],
            s.bytes[fwd],
            s.bytes[rev],
            self.age_secs(),
            self.idle_secs(),
        )
    }
}
