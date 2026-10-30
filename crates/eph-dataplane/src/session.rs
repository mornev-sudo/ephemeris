//! The session table: what makes the router *stateful*.
//!
//! A session (also called a flow or a connection) is one conversation between
//! two endpoints, identified by its **5-tuple**: protocol, source IP, source
//! port, destination IP, destination port. The first packet creates an entry;
//! every later packet, in **either direction**, finds the same entry.
//!
//! Both directions finding the same entry is the interesting part. A→B carries
//! (A, pa, B, pb) and the reply B→A carries (B, pb, A, pa). We make one
//! *canonical* key by always putting the numerically smaller (ip, port)
//! endpoint first, and remember separately which way this packet was going.
//! The session records which side spoke first (the *initiator*), so every
//! packet can be labelled [`Dir::Forward`] (same way as the first packet) or
//! [`Dir::Reverse`] (a reply).
//!
//! Sessions are per worker. Nothing is locked: this only works if both
//! directions of a session are delivered to the same worker, which is what
//! *symmetric RSS* is for (see docs/learn/07-sessions.md).

use crate::config::{NextHop, PortId};
use eph_packet::l4;
use rustc_hash::FxSeededState;
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::Ipv4Addr;
use std::sync::Arc;

const NS: u64 = 1_000_000_000;

/// The "port" packets coming out of an overlay tether arrive on. Tethers to a
/// site are interchangeable (a session moves to another WAN path on
/// failover), so they all count as one ingress.
pub const OVERLAY_INGRESS: PortId = PortId::MAX;

/// The "port" the router's own outbound packets arrive on (see
/// `host::SELF_ADDR`).
pub const HOST_INGRESS: PortId = PortId::MAX - 1;

/// The fields of a TCP segment that sequence tracking needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpSegment {
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub win: u16,
    /// Payload length.
    pub len: u32,
    /// Window scale option, if this is a SYN that carries one.
    pub wscale: Option<u8>,
}

/// Just enough sequence tracking per direction to tell a genuine RST or FIN
/// from a blind one: an attacker who knows a connection's addresses and
/// ports, but not where its sequence numbers are, can't close it.
#[derive(Debug, Clone, Copy, Default)]
struct TcpTrack {
    /// The sequence number each direction sends next (`None`: not seen).
    end: [Option<u32>; 2],
    /// Largest window each direction has advertised, scaled.
    max_win: [u32; 2],
    /// Window scale each side's SYN announced; used only if both did.
    wscale: [Option<u8>; 2],
}

/// Window assumed while the receiver hasn't advertised one yet.
const DEFAULT_WINDOW: u32 = 65535;

impl TcpTrack {
    /// Could `seg`, sent in direction `d`, belong to this connection?
    fn plausible(&self, d: usize, seg: &TcpSegment, state: State) -> bool {
        let other = 1 - d;
        match self.end[d] {
            Some(end) => {
                // Within the receiver's window either side of where the
                // sender is now (retransmits sit before it).
                let win = match self.max_win[other] {
                    0 => DEFAULT_WINDOW,
                    w => w,
                } as i64;
                let rel = seg.seq.wrapping_sub(end) as i32 as i64;
                (-win..=win).contains(&rel)
            }
            // The responder's first answer to a SYN must acknowledge it.
            None if state == State::SynSent && d == Dir::Reverse as usize => {
                seg.flags & l4::TCP_ACK != 0 && Some(seg.ack) == self.end[other]
            }
            // Picked up mid-stream: nothing to compare with yet.
            None => true,
        }
    }

    fn learn(&mut self, d: usize, seg: &TcpSegment) {
        let syn = seg.flags & l4::TCP_SYN != 0;
        let fin = seg.flags & l4::TCP_FIN != 0;
        if syn {
            self.wscale[d] = seg.wscale;
        }
        let end = seg
            .seq
            .wrapping_add(seg.len)
            .wrapping_add(syn as u32 + fin as u32);
        // Keep the furthest point reached (a retransmit doesn't move it back).
        self.end[d] = match self.end[d] {
            Some(e) if (end.wrapping_sub(e) as i32) < 0 => Some(e),
            _ => Some(end),
        };
        // A side's windows are scaled by the shift its own SYN announced, if
        // both SYNs carried the option. Windows in SYNs are never scaled.
        let shift = match self.wscale {
            [Some(_), Some(_)] if !syn => self.wscale[d].unwrap_or(0) as u32,
            _ => 0,
        };
        self.max_win[d] = self.max_win[d].max((seg.win as u32) << shift);
    }
}

/// Canonical 5-tuple: the (ip, port) pair that compares lower comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub lo_ip: u32,
    pub hi_ip: u32,
    pub lo_port: u16,
    pub hi_port: u16,
    pub proto: u8,
}

impl FlowKey {
    /// Build the key for a packet. The bool is true if the packet travels
    /// from the `lo` endpoint to the `hi` endpoint.
    #[inline]
    pub fn new(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, proto: u8) -> (Self, bool) {
        let s = (u32::from(src), sport);
        let d = (u32::from(dst), dport);
        let (lo, hi, lo_to_hi) = if s <= d { (s, d, true) } else { (d, s, false) };
        let key = FlowKey {
            lo_ip: lo.0,
            hi_ip: hi.0,
            lo_port: lo.1,
            hi_port: hi.1,
            proto,
        };
        (key, lo_to_hi)
    }
}

/// Direction of a packet relative to the session's first packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Forward = 0,
    Reverse = 1,
}

/// Session state. TCP gets a real (simplified) state machine; everything
/// else is just "have we seen one direction, or both?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Non-TCP: only the initiator has spoken.
    New,
    /// TCP: initiator sent SYN.
    SynSent,
    /// TCP: responder answered SYN+ACK.
    SynReceived,
    /// TCP: handshake done. Non-TCP: both sides have spoken.
    Established,
    /// TCP: one side sent FIN.
    FinWait,
    /// TCP: both sides sent FIN; linger briefly for stray retransmits.
    TimeWait,
    /// TCP: someone sent RST.
    Closed,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::New => "new",
            State::SynSent => "syn-sent",
            State::SynReceived => "syn-received",
            State::Established => "established",
            State::FinWait => "fin-wait",
            State::TimeWait => "time-wait",
            State::Closed => "closed",
        }
    }
}

/// No session lingers idle for longer than this: a day (configured
/// timeouts above it are capped). The defaults stay well below it.
pub const MAX_IDLE_SECS: u64 = 86_400;
/// Closing and closed TCP sessions are gone within ten minutes.
pub const MAX_CLOSING_SECS: u64 = 600;

/// Idle timeouts in seconds. A session expires this long after its last packet.
///
/// The defaults follow the NAT behaviour RFCs where an application would
/// otherwise break, and Linux conntrack for the rest:
///
/// - TCP established: 2 h 4 min, RFC 5382 REQ-5 (longer than TCP's own 2 h
///   keepalive, so an idle SSH session with keepalives survives).
/// - UDP once answered: 3 min (RFC 4787 REQ-5: at least 2).
/// - ICMP: 60 s (RFC 5508 REQ-1: at least 60).
/// - Unanswered UDP and TCP handshakes: 30 s. Shorter than RFC 4787 asks for
///   unanswered UDP, as conntrack does: these are what fills a table during
///   a scan or flood, and anything real gets its answer within seconds.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub tcp_handshake: u64,
    pub tcp_established: u64,
    pub tcp_closing: u64,
    pub tcp_closed: u64,
    pub udp: u64,
    pub udp_stream: u64,
    pub icmp: u64,
    pub other: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            tcp_handshake: 30,
            tcp_established: 7440,
            tcp_closing: 120,
            tcp_closed: 10,
            udp: 30,
            udp_stream: 180,
            icmp: 60,
            other: 60,
        }
    }
}

/// Timeouts for one application: sessions to these server ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppTimeout {
    /// IP protocol (6 TCP, 17 UDP).
    pub proto: u8,
    /// Inclusive server (destination) port range.
    pub ports: (u16, u16),
    /// Once answered (TCP: established), instead of the protocol's.
    pub idle_secs: u64,
    /// Before the first answer (TCP: the handshake), if different.
    pub unanswered_secs: Option<u64>,
}

/// At most this many [`AppTimeout`]s (a session keeps its rule's number in
/// a byte).
pub const MAX_APP_TIMEOUTS: usize = 64;

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Hard cap per worker. All memory is reserved up front, so the fast path
    /// never allocates, and a flood of new flows can't exhaust RAM.
    pub max_sessions: u32,
    /// Only a TCP SYN may create a session. When false, a mid-stream TCP
    /// packet is "picked up" as established (handy after a router restart).
    pub tcp_strict: bool,
    pub timeouts: Timeouts,
    /// Per-application timeouts, first match wins (by protocol and server
    /// port, decided when the session starts).
    pub apps: Arc<[AppTimeout]>,
    /// Table full: make room by dropping a session that never got an answer
    /// (or a closing TCP one), instead of refusing the new one.
    pub early_drop: bool,
    /// Most sessions one address may have started at once, in this table
    /// (0: no limit). Stops one host (a scan, malware, a runaway client)
    /// from filling the table for everyone else (RFC 6888, REQ-4).
    pub max_per_host: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            max_sessions: 262_144,
            tcp_strict: false,
            timeouts: Timeouts::default(),
            apps: Arc::from([]),
            early_drop: true,
            max_per_host: 0,
        }
    }
}

/// A session that just expired without ever being answered, for tracing:
/// what was tried, and how it was translated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unanswered {
    pub proto: u8,
    pub initiator: (Ipv4Addr, u16),
    pub responder: (Ipv4Addr, u16),
    pub ingress: Option<PortId>,
    pub packets: u64,
    pub age_secs: u64,
    pub nat: Option<(Ipv4Addr, u16)>,
}

/// Unanswered sessions kept for tracing between two housekeeping calls.
const UNANSWERED_LOG_MAX: usize = 256;

/// A source-NAT translation: the session's initiator `orig_addr:orig_port`
/// appears to the outside as `addr:port`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatBinding {
    /// The 5-tuple as the outside sees it.
    pub xkey: FlowKey,
    pub orig_addr: Ipv4Addr,
    pub orig_port: u16,
    pub addr: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub key: FlowKey,
    /// Did the `lo` endpoint send the first packet?
    pub initiator_lo: bool,
    pub state: State,
    pub created_ns: u64,
    pub last_seen_ns: u64,
    /// Indexed by [`Dir`].
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    fin_seen: [bool; 2],
    /// Forwarding decision cached per direction, valid for FIB generation
    /// `fib_gen`. The first packet each way pays for the route lookup; the
    /// rest reuse it. (Later phases cache the SD-WAN path choice here too.)
    pub next_hop: [Option<NextHop>; 2],
    pub fib_gen: u64,
    /// SD-WAN application class, decided by the first packet.
    pub class: u8,
    /// Its [`AppTimeout`] (index + 1), or 0: the protocol's timeouts.
    pub app: u8,
    /// Overlay tether this session uses, valid for path table `path_gen`.
    /// Sticky: a session stays on its path until the path table changes.
    pub tether: Option<u16>,
    pub path_gen: u64,
    /// Source NAT applied to this session, if any.
    pub nat: Option<NatBinding>,
    /// The port each direction's packets arrive on (indexed by [`Dir`]),
    /// learned from its first packet: the same tuple arriving anywhere else
    /// is spoofed. [`OVERLAY_INGRESS`] for packets out of a tether.
    pub ingress: [Option<PortId>; 2],
    tcp: TcpTrack,
    /// Bumped whenever this slot is freed, so stale timer entries for an old
    /// occupant can be recognised and ignored.
    generation: u32,
    alive: bool,
}

impl Session {
    /// The initiator's (ip, port) and the responder's (ip, port).
    pub fn endpoints(&self) -> ((Ipv4Addr, u16), (Ipv4Addr, u16)) {
        let lo = (Ipv4Addr::from(self.key.lo_ip), self.key.lo_port);
        let hi = (Ipv4Addr::from(self.key.hi_ip), self.key.hi_port);
        if self.initiator_lo {
            (lo, hi)
        } else {
            (hi, lo)
        }
    }

    #[inline]
    pub fn dir(&self, lo_to_hi: bool) -> Dir {
        if lo_to_hi == self.initiator_lo {
            Dir::Forward
        } else {
            Dir::Reverse
        }
    }
}

/// Outcome of offering a packet to the session table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    /// Belongs to session `idx`, travelling in `dir`.
    Ok { idx: u32, dir: Dir },
    /// The packet makes no sense for this session's TCP state.
    Invalid,
}

/// Seconds covered by one turn of the timer wheel.
const WHEEL_SLOTS: u64 = 1024;

pub struct SessionTable {
    cfg: SessionConfig,
    map: HashMap<FlowKey, u32, FxSeededState>,
    slab: Vec<Session>,
    free: Vec<u32>,
    wheel: Vec<Vec<(u32, u32)>>,
    /// Next wheel second to process.
    wheel_sec: u64,
    wheel_started: bool,
    pub created: u64,
    pub expired: u64,
    /// TCP segments whose sequence number didn't fit their connection; any
    /// RST or FIN in them was ignored.
    pub blind: u64,
    /// Sessions with a NAT translation right now.
    pub nat_active: u64,
    /// Expired without a single packet back.
    pub unanswered: u64,
    /// Dropped early to make room in a full table.
    pub early_dropped: u64,
    /// Sessions started per initiating address, while `max_per_host` is
    /// set. Room for [`HOSTS_TRACKED`] addresses is reserved up front;
    /// beyond that, new addresses aren't counted (and so not limited)
    /// rather than the map growing on the fast path.
    hosts: HashMap<u32, u32, FxSeededState>,
    /// While set (a session trace is on), expiring unanswered sessions are
    /// also kept in `unanswered_log` for the pipeline to trace.
    pub log_unanswered: bool,
    pub unanswered_log: Vec<Unanswered>,
}

/// Keys a session can have in the map: its 5-tuple, plus its translated
/// one while it's source-NATed.
const KEYS_PER_SESSION: usize = 2;
/// Timer entries looked at, at most, to find a session to drop early.
const EARLY_DROP_SCAN: usize = 256;
/// Initiating addresses counted for `max_per_host`, at most, per table.
pub const HOSTS_TRACKED: usize = 65_536;

/// The timer wheel holds about one (index, generation) entry per session,
/// sometimes a stale one more; it grows as needed rather than up front.
const WHEEL_BYTES_PER_SESSION: u64 = 2 * std::mem::size_of::<(u32, u32)>() as u64;

impl SessionTable {
    /// Memory a table for `max` sessions takes once full: what [`new`]
    /// reserves (the slab and the hash map) plus the free list and the timer
    /// wheel, which grow into their share as sessions come and go.
    ///
    /// The map's part is exact: Rust's `HashMap` (hashbrown) keeps 1/8 of
    /// its buckets empty, rounds the bucket count up to a power of two, and
    /// stores one control byte per bucket (plus one group of 16).
    ///
    /// [`new`]: SessionTable::new
    pub fn reserved_bytes(max: u32) -> u64 {
        let keys = max as u64 * KEYS_PER_SESSION as u64;
        let buckets = match keys {
            0 => 0,
            1..=3 => 4,
            4..=7 => 8,
            k => (k * 8 / 7).next_power_of_two(),
        };
        let entry = std::mem::size_of::<(FlowKey, u32)>() as u64;
        let map = buckets * (entry + 1) + 16;
        let slab = max as u64 * std::mem::size_of::<Session>() as u64;
        let free = max as u64 * std::mem::size_of::<u32>() as u64;
        map + slab + free + max as u64 * WHEEL_BYTES_PER_SESSION
    }

    /// The most sessions whose table fits in `bytes` (see
    /// [`reserved_bytes`](SessionTable::reserved_bytes)).
    pub fn max_for_bytes(bytes: u64) -> u32 {
        let (mut lo, mut hi) = (0u32, u32::MAX);
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if Self::reserved_bytes(mid) <= bytes {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    }

    /// How many sessions the table can hold (allocated up front).
    pub fn capacity(&self) -> u32 {
        self.cfg.max_sessions
    }

    pub fn new(cfg: SessionConfig) -> Self {
        // A per-process random seed, so an attacker can't precompute flows
        // that all land in the same hash bucket. (FxHash is fast but not a
        // cryptographic hash; a hardened build would use SipHash or similar.)
        let seed = RandomState::new().hash_one(0x5ed5u16) as usize;
        let max = cfg.max_sessions as usize;
        let hosts = if cfg.max_per_host > 0 {
            HOSTS_TRACKED.min(max)
        } else {
            0
        };
        SessionTable {
            cfg,
            // Room for both keys of every session (its own and, NATed, its
            // translated one): the map never grows on the fast path.
            map: HashMap::with_capacity_and_hasher(
                max * KEYS_PER_SESSION,
                FxSeededState::with_seed(seed),
            ),
            slab: Vec::with_capacity(max),
            free: Vec::new(),
            wheel: (0..WHEEL_SLOTS).map(|_| Vec::new()).collect(),
            wheel_sec: 0,
            wheel_started: false,
            created: 0,
            expired: 0,
            blind: 0,
            nat_active: 0,
            unanswered: 0,
            early_dropped: 0,
            hosts: HashMap::with_capacity_and_hasher(hosts, FxSeededState::with_seed(seed)),
            log_unanswered: false,
            unanswered_log: Vec::new(),
        }
    }

    pub fn config(&self) -> &SessionConfig {
        &self.cfg
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[inline]
    pub fn lookup(&self, key: &FlowKey) -> Option<u32> {
        self.map.get(key).copied()
    }

    #[inline]
    pub fn get(&self, idx: u32) -> &Session {
        &self.slab[idx as usize]
    }

    #[inline]
    pub fn get_mut(&mut self, idx: u32) -> &mut Session {
        &mut self.slab[idx as usize]
    }

    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.slab.iter().filter(|s| s.alive)
    }

    /// Would this packet be allowed to *start* a session?
    pub fn can_create(&self, proto: u8, tcp_flags: u8) -> bool {
        if proto != eph_packet::ipv4::PROTO_TCP {
            return true;
        }
        if tcp_flags & l4::TCP_RST != 0 {
            return false; // never open a session for a reset
        }
        let pure_syn = tcp_flags & (l4::TCP_SYN | l4::TCP_ACK) == l4::TCP_SYN;
        pure_syn || !self.cfg.tcp_strict
    }

    /// Has the host starting this session (`lo_to_hi`: the `lo` end) got
    /// `max_per_host` sessions already?
    pub fn host_full(&self, key: &FlowKey, lo_to_hi: bool) -> bool {
        let limit = self.cfg.max_per_host;
        limit > 0
            && self
                .hosts
                .get(&initiator(key, lo_to_hi))
                .is_some_and(|&n| n >= limit)
    }

    fn count_host(&mut self, ip: u32) {
        if self.cfg.max_per_host == 0 {
            return;
        }
        if let Some(n) = self.hosts.get_mut(&ip) {
            *n += 1;
        } else if self.hosts.len() < self.hosts.capacity().min(HOSTS_TRACKED) {
            self.hosts.insert(ip, 1);
        }
    }

    fn uncount_host(&mut self, ip: u32) {
        if let Some(n) = self.hosts.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                self.hosts.remove(&ip);
            }
        }
    }

    /// Sessions `ip` has started that are in the table now (counted only
    /// while `max_per_host` is set).
    pub fn host_sessions(&self, ip: Ipv4Addr) -> u32 {
        self.hosts.get(&u32::from(ip)).copied().unwrap_or(0)
    }

    /// Create a session for its first packet. `None` if the table is full.
    pub fn create(
        &mut self,
        key: FlowKey,
        lo_to_hi: bool,
        tcp_flags: u8,
        bytes: u64,
        now_ns: u64,
    ) -> Option<u32> {
        let state = if key.proto != eph_packet::ipv4::PROTO_TCP {
            State::New
        } else if tcp_flags & l4::TCP_SYN != 0 && tcp_flags & l4::TCP_ACK == 0 {
            State::SynSent
        } else {
            State::Established // mid-stream pickup (loose mode)
        };
        let fresh = Session {
            key,
            initiator_lo: lo_to_hi,
            state,
            created_ns: now_ns,
            last_seen_ns: now_ns,
            packets: [1, 0],
            bytes: [bytes, 0],
            fin_seen: [false; 2],
            next_hop: [None; 2],
            fib_gen: 0,
            class: 0,
            app: self.app_of(key, lo_to_hi),
            tether: None,
            path_gen: 0,
            nat: None,
            ingress: [None; 2],
            tcp: TcpTrack::default(),
            generation: 0,
            alive: true,
        };
        let idx = if let Some(i) = self.free.pop() {
            let generation = self.slab[i as usize].generation;
            self.slab[i as usize] = Session {
                generation,
                ..fresh
            };
            i
        } else if self.slab.len() < self.cfg.max_sessions as usize {
            self.slab.push(fresh);
            (self.slab.len() - 1) as u32
        } else if self.cfg.early_drop && self.drop_early(now_ns) {
            let i = self.free.pop().expect("a slot was just freed");
            let generation = self.slab[i as usize].generation;
            self.slab[i as usize] = Session {
                generation,
                ..fresh
            };
            i
        } else {
            return None;
        };
        self.map.insert(key, idx);
        self.count_host(initiator(&key, lo_to_hi));
        self.created += 1;
        let at = self.expiry_ns(idx);
        self.schedule(idx, at, now_ns);
        Some(idx)
    }

    /// Account a packet to an existing session and advance its state.
    /// Note: this never touches the timer wheel; see [`SessionTable::expire`].
    #[inline]
    pub fn update(
        &mut self,
        idx: u32,
        lo_to_hi: bool,
        tcp_flags: u8,
        bytes: u64,
        now_ns: u64,
    ) -> Track {
        let dir = self.slab[idx as usize].dir(lo_to_hi);
        self.update_dir(idx, dir, tcp_flags, bytes, now_ns)
    }

    /// Like [`SessionTable::update`] when the caller already knows the
    /// direction (a NATed reply is matched by its translated key).
    #[inline]
    pub fn update_dir(
        &mut self,
        idx: u32,
        dir: Dir,
        tcp_flags: u8,
        bytes: u64,
        now_ns: u64,
    ) -> Track {
        let before = self.timeout_secs(&self.slab[idx as usize]);
        let s = &mut self.slab[idx as usize];
        if s.key.proto == eph_packet::ipv4::PROTO_TCP {
            match tcp_transition(s.state, dir, tcp_flags, &mut s.fin_seen) {
                Some(next) => {
                    if next == State::SynSent && s.state != State::SynSent {
                        // A new connection reusing the same ports: start fresh.
                        s.packets = [0; 2];
                        s.bytes = [0; 2];
                        s.created_ns = now_ns;
                    }
                    s.state = next;
                }
                None => return Track::Invalid,
            }
        } else if dir == Dir::Reverse {
            s.state = State::Established;
        }
        s.packets[dir as usize] += 1;
        s.bytes[dir as usize] += bytes;
        s.last_seen_ns = now_ns;
        // Moved to a shorter timeout (closing, closed): its wheel slot is
        // still the old, later one, so file it again at the new expiry.
        // Otherwise a reset connection could sit in the table until the old
        // slot came round (up to one wheel turn, ~17 minutes).
        if self.timeout_secs(&self.slab[idx as usize]) < before {
            let at = self.expiry_ns(idx);
            self.schedule(idx, at, now_ns);
        }
        Track::Ok { idx, dir }
    }

    /// Which [`AppTimeout`] a new session falls under (index + 1), or 0.
    fn app_of(&self, key: FlowKey, lo_to_hi: bool) -> u8 {
        if self.cfg.apps.is_empty() {
            return 0;
        }
        let server_port = if lo_to_hi { key.hi_port } else { key.lo_port };
        self.cfg
            .apps
            .iter()
            .take(MAX_APP_TIMEOUTS)
            .position(|a| a.proto == key.proto && (a.ports.0..=a.ports.1).contains(&server_port))
            .map_or(0, |i| i as u8 + 1)
    }

    fn timeout_secs(&self, s: &Session) -> u64 {
        let t = &self.cfg.timeouts;
        if let Some(a) = (s.app as usize)
            .checked_sub(1)
            .and_then(|i| self.cfg.apps.get(i))
        {
            match s.state {
                State::Established => return a.idle_secs,
                State::New | State::SynSent | State::SynReceived => {
                    if let Some(u) = a.unanswered_secs {
                        return u;
                    }
                }
                _ => {}
            }
        }
        match s.key.proto {
            eph_packet::ipv4::PROTO_TCP => match s.state {
                State::SynSent | State::SynReceived | State::New => t.tcp_handshake,
                State::Established => t.tcp_established,
                State::FinWait | State::TimeWait => t.tcp_closing,
                State::Closed => t.tcp_closed,
            },
            eph_packet::ipv4::PROTO_UDP if s.state == State::Established => t.udp_stream,
            eph_packet::ipv4::PROTO_UDP => t.udp,
            eph_packet::ipv4::PROTO_ICMP => t.icmp,
            _ => t.other,
        }
    }

    fn expiry_ns(&self, idx: u32) -> u64 {
        let s = &self.slab[idx as usize];
        s.last_seen_ns + self.timeout_secs(s) * NS
    }

    /// Put `idx` in the wheel slot for second `at_ns` (clamped to one turn
    /// from now: the wheel may be behind if `expire` wasn't called for a
    /// while, and a slot behind now would only come round a turn later).
    fn schedule(&mut self, idx: u32, at_ns: u64, now_ns: u64) {
        if !self.wheel_started {
            self.wheel_started = true;
            self.wheel_sec = now_ns / NS;
        }
        let base = self.wheel_sec.max(now_ns / NS);
        let sec = (at_ns / NS).clamp(base, base + WHEEL_SLOTS - 1);
        let generation = self.slab[idx as usize].generation;
        self.wheel[(sec % WHEEL_SLOTS) as usize].push((idx, generation));
    }

    /// Remove sessions that have been idle past their timeout. Call regularly
    /// (the worker does it once per loop); it does real work at most once a
    /// second.
    ///
    /// This is a *hashed timer wheel* with *lazy rescheduling*: a session sits
    /// in the slot for the second it was due to expire *when last scheduled*.
    /// Packets don't move it (that would be a write per packet). When its slot
    /// comes round we check the real expiry; if traffic kept it alive, we just
    /// file it under its new expiry second. Removed: O(1). Kept: O(1).
    pub fn expire(&mut self, now_ns: u64) -> usize {
        let now_sec = now_ns / NS;
        if !self.wheel_started {
            self.wheel_started = true;
            self.wheel_sec = now_sec;
        }
        let mut removed = 0;
        let mut turns = 0;
        // Everything filed under second s is due by s+1, so process up to
        // (but not including) the current second.
        while self.wheel_sec < now_sec && turns < WHEEL_SLOTS {
            let slot = (self.wheel_sec % WHEEL_SLOTS) as usize;
            let mut entries = std::mem::take(&mut self.wheel[slot]);
            self.wheel_sec += 1;
            for &(idx, generation) in &entries {
                let s = &self.slab[idx as usize];
                if !s.alive || s.generation != generation {
                    continue; // slot was freed (and maybe reused) since
                }
                let at = self.expiry_ns(idx);
                if at <= now_ns {
                    self.note_if_unanswered(idx, now_ns);
                    self.remove(idx);
                    removed += 1;
                } else {
                    self.schedule(idx, at, now_ns);
                }
            }
            entries.clear();
            if self.wheel[slot].is_empty() {
                self.wheel[slot] = entries; // keep the allocation
            }
            turns += 1;
        }
        if self.wheel_sec < now_sec {
            self.wheel_sec = now_sec; // fell a whole turn behind: every entry was seen once
        }
        self.expired += removed as u64;
        removed
    }

    /// Learn from a TCP segment in direction `dir` and return the flags the
    /// state machine should act on: RST and FIN are left out if the segment's
    /// sequence number isn't plausible for the connection (a blind reset).
    /// The segment itself is still forwarded; the endpoint decides.
    pub fn observe_tcp(&mut self, idx: u32, dir: Dir, seg: &TcpSegment) -> u8 {
        let s = &mut self.slab[idx as usize];
        let d = dir as usize;
        // A new connection reusing a closed one's ports starts from a new
        // initial sequence number.
        let new_syn = seg.flags & (l4::TCP_SYN | l4::TCP_ACK) == l4::TCP_SYN;
        if new_syn && dir == Dir::Forward && matches!(s.state, State::TimeWait | State::Closed) {
            s.tcp = TcpTrack::default();
        }
        if !s.tcp.plausible(d, seg, s.state) {
            self.blind += 1;
            return seg.flags & !(l4::TCP_RST | l4::TCP_FIN);
        }
        s.tcp.learn(d, seg);
        seg.flags
    }

    /// Attach a source-NAT translation: its translated 5-tuple becomes a
    /// second key for the same session, so replies (which carry the
    /// translated addresses) find it. False if that tuple is already taken.
    pub fn bind_nat(&mut self, idx: u32, nat: NatBinding) -> bool {
        if self.map.contains_key(&nat.xkey) {
            return false;
        }
        self.map.insert(nat.xkey, idx);
        if self.slab[idx as usize].nat.replace(nat).is_none() {
            self.nat_active += 1;
        }
        true
    }

    /// Count (and, while asked, keep for tracing) a session that's going
    /// without ever having been answered.
    fn note_if_unanswered(&mut self, idx: u32, now_ns: u64) {
        let s = &self.slab[idx as usize];
        if s.packets[Dir::Reverse as usize] != 0 {
            return;
        }
        self.unanswered += 1;
        if self.log_unanswered && self.unanswered_log.len() < UNANSWERED_LOG_MAX {
            let (initiator, responder) = s.endpoints();
            self.unanswered_log.push(Unanswered {
                proto: s.key.proto,
                initiator,
                responder,
                ingress: s.ingress[Dir::Forward as usize],
                packets: s.packets[Dir::Forward as usize],
                age_secs: now_ns.saturating_sub(s.created_ns) / NS,
                nat: s.nat.map(|n| (n.addr, n.port)),
            });
        }
    }

    /// The table is full: drop the session that's due soonest among those
    /// that never got an answer or are closing (TCP), looking at most at
    /// [`EARLY_DROP_SCAN`] timer entries. False if there's none: established
    /// conversations are never dropped to make room.
    fn drop_early(&mut self, now_ns: u64) -> bool {
        let Some(idx) = self.early_drop_victim() else {
            return false;
        };
        self.note_if_unanswered(idx, now_ns);
        self.remove(idx);
        self.early_dropped += 1;
        true
    }

    fn early_drop_victim(&self) -> Option<u32> {
        let mut seen = 0;
        for k in 0..WHEEL_SLOTS {
            let slot = ((self.wheel_sec + k) % WHEEL_SLOTS) as usize;
            for &(idx, generation) in &self.wheel[slot] {
                let s = &self.slab[idx as usize];
                let droppable = s.packets[Dir::Reverse as usize] == 0
                    || matches!(s.state, State::FinWait | State::TimeWait | State::Closed);
                if s.alive && s.generation == generation && droppable {
                    return Some(idx);
                }
                seen += 1;
                if seen >= EARLY_DROP_SCAN {
                    return None;
                }
            }
        }
        None
    }

    fn remove(&mut self, idx: u32) {
        let s = &mut self.slab[idx as usize];
        s.alive = false;
        s.generation = s.generation.wrapping_add(1);
        let (key, nat, lo_to_hi) = (s.key, s.nat.take(), s.initiator_lo);
        self.map.remove(&key);
        self.uncount_host(initiator(&key, lo_to_hi));
        if let Some(n) = nat {
            self.map.remove(&n.xkey);
            self.nat_active = self.nat_active.saturating_sub(1);
        }
        self.free.push(idx);
    }
}

/// The address that started a session.
fn initiator(key: &FlowKey, lo_to_hi: bool) -> u32 {
    if lo_to_hi {
        key.lo_ip
    } else {
        key.hi_ip
    }
}

/// The TCP state machine (simplified from Linux conntrack). Returns the next
/// state, or `None` if the packet is invalid for the current state.
fn tcp_transition(state: State, dir: Dir, flags: u8, fin_seen: &mut [bool; 2]) -> Option<State> {
    let syn = flags & l4::TCP_SYN != 0;
    let ack = flags & l4::TCP_ACK != 0;
    let fin = flags & l4::TCP_FIN != 0;
    if flags & l4::TCP_RST != 0 {
        return Some(State::Closed);
    }
    let fwd = dir == Dir::Forward;
    Some(match state {
        State::SynSent => {
            if !fwd && syn && ack {
                State::SynReceived
            } else if fwd {
                State::SynSent // SYN retransmit
            } else {
                return None; // responder must answer a SYN with SYN+ACK first
            }
        }
        State::SynReceived => {
            if fwd && ack && !syn {
                State::Established
            } else {
                State::SynReceived // retransmits of SYN or SYN+ACK
            }
        }
        State::Established | State::FinWait => {
            if fin {
                fin_seen[dir as usize] = true;
            }
            match fin_seen {
                [true, true] => State::TimeWait,
                [false, false] => State::Established,
                _ => State::FinWait,
            }
        }
        State::TimeWait | State::Closed => {
            if fwd && syn && !ack {
                *fin_seen = [false; 2];
                State::SynSent // port reuse: a brand new connection
            } else {
                state
            }
        }
        State::New => State::Established, // not used for TCP
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use eph_packet::ipv4::{PROTO_TCP, PROTO_UDP};
    use eph_packet::l4::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn both_directions_share_one_key() {
        let (k1, a) = FlowKey::new(ip("10.0.1.10"), 40000, ip("10.0.2.10"), 443, PROTO_TCP);
        let (k2, b) = FlowKey::new(ip("10.0.2.10"), 443, ip("10.0.1.10"), 40000, PROTO_TCP);
        assert_eq!(k1, k2);
        assert_ne!(a, b);
        let (k3, _) = FlowKey::new(ip("10.0.1.10"), 40001, ip("10.0.2.10"), 443, PROTO_TCP);
        assert_ne!(k1, k3);
    }

    fn table() -> SessionTable {
        SessionTable::new(SessionConfig {
            max_sessions: 4,
            ..Default::default()
        })
    }

    #[test]
    fn tcp_lifecycle() {
        let mut t = table();
        let (k, fwd) = FlowKey::new(ip("10.0.1.10"), 40000, ip("10.0.2.10"), 80, PROTO_TCP);
        let i = t.create(k, fwd, TCP_SYN, 60, 0).unwrap();
        assert_eq!(t.get(i).state, State::SynSent);
        let rev = !fwd;
        let step = |t: &mut SessionTable, lo_to_hi, f| {
            assert!(matches!(t.update(i, lo_to_hi, f, 60, 1), Track::Ok { .. }));
            t.get(i).state
        };
        assert_eq!(step(&mut t, rev, TCP_SYN | TCP_ACK), State::SynReceived);
        assert_eq!(step(&mut t, fwd, TCP_ACK), State::Established);
        assert_eq!(step(&mut t, rev, TCP_ACK), State::Established);
        assert_eq!(step(&mut t, fwd, TCP_FIN | TCP_ACK), State::FinWait);
        assert_eq!(step(&mut t, rev, TCP_FIN | TCP_ACK), State::TimeWait);
        assert_eq!(step(&mut t, fwd, TCP_SYN), State::SynSent, "port reuse");
        assert_eq!(step(&mut t, rev, TCP_RST), State::Closed);
    }

    #[test]
    fn nothing_lingers_idle_past_its_limits() {
        // The defaults keep within the caps the config also enforces.
        let t = Timeouts::default();
        for v in [
            t.tcp_handshake,
            t.tcp_established,
            t.udp,
            t.udp_stream,
            t.icmp,
            t.other,
        ] {
            assert!(v <= MAX_IDLE_SECS);
        }
        assert!(t.tcp_closing <= MAX_CLOSING_SECS && t.tcp_closed <= MAX_CLOSING_SECS);

        // An established TCP session idle for 2 h 4 min is gone; a closed
        // one within seconds; one still passing traffic stays.
        let mut tb = table();
        let s = 1_000_000_000u64;
        let (k, fwd) = FlowKey::new(ip("10.0.1.10"), 40000, ip("10.0.2.10"), 80, PROTO_TCP);
        let idle = tb.create(k, fwd, TCP_ACK, 60, 0).unwrap(); // picked up: established
        let (k2, f2) = FlowKey::new(ip("10.0.1.10"), 40001, ip("10.0.2.10"), 80, PROTO_TCP);
        let busy = tb.create(k2, f2, TCP_ACK, 60, 0).unwrap();
        let (k3, f3) = FlowKey::new(ip("10.0.1.10"), 40002, ip("10.0.2.10"), 80, PROTO_TCP);
        let closed = tb.create(k3, f3, TCP_ACK, 60, 0).unwrap();
        tb.update(closed, !f3, TCP_RST, 60, s);
        assert_eq!(tb.get(closed).state, State::Closed);
        tb.expire(30 * s);
        assert_eq!(tb.len(), 2, "closed: gone within its 10 s");
        for t in (60..7440).step_by(60) {
            tb.update(busy, f2, TCP_ACK, 60, t * s);
            tb.expire(t * s);
        }
        tb.expire(7441 * s);
        assert!(tb.lookup(&k).is_none(), "idle 2 h 4 min: gone");
        assert!(tb.lookup(&k2).is_some(), "still in use: kept");
        let _ = idle;
    }

    #[test]
    fn responder_cannot_skip_the_handshake() {
        let mut t = table();
        let (k, fwd) = FlowKey::new(ip("10.0.1.10"), 40000, ip("10.0.2.10"), 80, PROTO_TCP);
        let i = t.create(k, fwd, TCP_SYN, 60, 0).unwrap();
        assert_eq!(t.update(i, !fwd, TCP_ACK, 60, 1), Track::Invalid);
    }

    #[test]
    fn strict_mode_only_syn_creates() {
        let mut t = SessionTable::new(SessionConfig {
            tcp_strict: true,
            ..Default::default()
        });
        assert!(t.can_create(PROTO_TCP, TCP_SYN));
        assert!(!t.can_create(PROTO_TCP, TCP_ACK));
        assert!(!t.can_create(PROTO_TCP, TCP_SYN | TCP_ACK));
        t.cfg.tcp_strict = false;
        assert!(t.can_create(PROTO_TCP, TCP_ACK));
        assert!(!t.can_create(PROTO_TCP, TCP_RST));
        assert!(t.can_create(PROTO_UDP, 0));
    }

    #[test]
    fn table_full_and_slot_reuse() {
        let mut t = table();
        t.cfg.early_drop = false;
        for p in 0..4 {
            let (k, d) = FlowKey::new(ip("10.0.1.10"), 1000 + p, ip("10.0.2.10"), 53, PROTO_UDP);
            t.create(k, d, 0, 60, 0).unwrap();
        }
        let (k, d) = FlowKey::new(ip("10.0.1.10"), 2000, ip("10.0.2.10"), 53, PROTO_UDP);
        assert_eq!(t.create(k, d, 0, 60, 0), None);
        // All four expire after 30s, freeing room.
        assert_eq!(t.expire(31 * NS), 4);
        assert!(t.is_empty());
        assert!(t.create(k, d, 0, 60, 31 * NS).is_some());
    }

    #[test]
    fn one_host_cannot_fill_the_table() {
        let mut t = SessionTable::new(SessionConfig {
            max_sessions: 16,
            max_per_host: 3,
            ..Default::default()
        });
        let flow = |host: &str, p: u16| FlowKey::new(ip(host), p, ip("10.0.2.10"), 53, PROTO_UDP);
        for p in 0..3 {
            let (k, d) = flow("10.0.1.10", 1000 + p);
            assert!(!t.host_full(&k, d));
            t.create(k, d, 0, 60, 0).unwrap();
        }
        let (k, d) = flow("10.0.1.10", 2000);
        assert!(t.host_full(&k, d), "a fourth from the same host");
        // Counted by who started it: replies don't count, nor do others.
        let (k2, d2) = flow("10.0.1.11", 2000);
        assert!(!t.host_full(&k2, d2));
        assert!(!t.host_full(&k, !d), "the server's side of it");
        assert_eq!(t.host_sessions(ip("10.0.1.10")), 3);
        // Expired sessions free the host's share again.
        assert_eq!(t.expire(31 * NS), 3);
        assert_eq!(t.host_sessions(ip("10.0.1.10")), 0);
        assert!(!t.host_full(&k, d));
        // No limit: nothing counted.
        let mut t = table();
        let (k, d) = flow("10.0.1.10", 1000);
        t.create(k, d, 0, 60, 0).unwrap();
        assert!(!t.host_full(&k, d));
        assert_eq!(t.host_sessions(ip("10.0.1.10")), 0);
    }

    #[test]
    fn traffic_keeps_sessions_alive_and_idle_ones_expire() {
        let mut t = table();
        let (k, d) = FlowKey::new(ip("10.0.1.10"), 5000, ip("10.0.2.10"), 53, PROTO_UDP);
        let i = t.create(k, d, 0, 60, 0).unwrap();
        // Keep talking every 10 s for 100 s: never expires.
        for s in (10..=100).step_by(10) {
            t.update(i, d, 0, 60, s * NS);
            assert_eq!(t.expire(s * NS), 0, "at {s}s");
        }
        // One reply makes it a "stream": 180 s timeout instead of 30.
        t.update(i, !d, 0, 60, 100 * NS);
        assert_eq!(t.get(i).state, State::Established);
        assert_eq!(t.expire(200 * NS), 0);
        assert_eq!(t.expire(282 * NS), 1);
        assert_eq!(t.lookup(&k), None);
    }

    #[test]
    fn long_idle_gap_does_not_lose_sessions() {
        let mut t = table();
        let (k, d) = FlowKey::new(ip("10.0.1.10"), 40000, ip("10.0.2.10"), 80, PROTO_TCP);
        let i = t.create(k, d, TCP_ACK, 60, 0).unwrap(); // picked up: 7440 s timeout
        assert_eq!(t.get(i).state, State::Established);
        // Called rarely and far beyond one wheel turn (1024 s).
        assert_eq!(t.expire(3000 * NS), 0);
        assert_eq!(t.expire(7439 * NS), 0);
        assert_eq!(t.expire(7442 * NS), 1);
    }

    #[test]
    fn application_timeouts_replace_the_protocols() {
        let mut t = SessionTable::new(SessionConfig {
            apps: Arc::from([
                AppTimeout {
                    proto: PROTO_UDP,
                    ports: (53, 53),
                    idle_secs: 5,
                    unanswered_secs: Some(3),
                },
                AppTimeout {
                    proto: PROTO_UDP,
                    ports: (3478, 3481),
                    idle_secs: 600,
                    unanswered_secs: None,
                },
            ]),
            ..Default::default()
        });
        let udp =
            |sport, dport| FlowKey::new(ip("10.0.1.10"), sport, ip("8.8.8.8"), dport, PROTO_UDP);
        let (dns, d) = udp(5000, 53);
        let dns_i = t.create(dns, d, 0, 60, 0).unwrap();
        let (stun, d2) = udp(5001, 3479);
        let stun_i = t.create(stun, d2, 0, 60, 0).unwrap();
        let (other, d3) = udp(5002, 443);
        t.create(other, d3, 0, 60, 0).unwrap();
        // Unanswered: DNS after its 3 s, STUN and the rest after UDP's 30 s.
        assert_eq!(t.expire(4 * NS), 1);
        assert!(t.lookup(&dns).is_none());
        // Answered: STUN keeps 10 minutes, not UDP's stream 3.
        t.update(stun_i, !d2, 0, 60, 10 * NS);
        assert_eq!(t.expire(31 * NS), 1, "the other one");
        assert_eq!(t.expire(400 * NS), 0);
        assert_eq!(t.expire(611 * NS), 1);
        let _ = dns_i;
        // The client's port doesn't count, only the server's.
        let (k, d) = FlowKey::new(ip("10.0.1.10"), 53, ip("8.8.8.8"), 9999, PROTO_UDP);
        let i = t.create(k, d, 0, 60, 611 * NS).unwrap();
        assert_eq!(t.get(i).app, 0);
    }

    #[test]
    fn unanswered_sessions_are_counted_and_kept_for_tracing() {
        let mut t = table();
        t.log_unanswered = true;
        let (k, d) = FlowKey::new(ip("10.0.1.10"), 5000, ip("8.8.8.8"), 53, PROTO_UDP);
        let i = t.create(k, d, 0, 60, 0).unwrap();
        t.update(i, d, 0, 60, NS);
        let (k2, d2) = FlowKey::new(ip("10.0.1.10"), 5001, ip("8.8.8.8"), 53, PROTO_UDP);
        let j = t.create(k2, d2, 0, 60, 0).unwrap();
        t.update(j, !d2, 0, 60, NS); // answered
        t.expire(200 * NS);
        assert_eq!((t.expired, t.unanswered), (2, 1));
        let u = t.unanswered_log[0];
        assert_eq!(u.initiator, (ip("10.0.1.10"), 5000));
        assert_eq!(u.responder, (ip("8.8.8.8"), 53));
        assert_eq!(u.packets, 2);
        assert_eq!(t.unanswered_log.len(), 1);
    }

    #[test]
    fn early_drop_takes_the_unanswered_due_soonest() {
        let mut t = table(); // room for 4
        let udp = |p| FlowKey::new(ip("10.0.1.10"), p, ip("8.8.8.8"), 53, PROTO_UDP);
        let mut ids = vec![];
        for (n, p) in [1000, 1001, 1002, 1003].into_iter().enumerate() {
            let (k, d) = udp(p);
            ids.push(t.create(k, d, 0, 60, n as u64 * NS).unwrap());
        }
        // 1000 and 1002 got answers; of the others, 1001 is due first.
        t.update(ids[0], !udp(1000).1, 0, 60, 5 * NS);
        t.update(ids[2], !udp(1002).1, 0, 60, 5 * NS);
        let (k, d) = udp(2000);
        assert!(t.create(k, d, 0, 60, 6 * NS).is_some());
        assert!(
            t.lookup(&udp(1001).0).is_none(),
            "the oldest unanswered went"
        );
        assert!(t.lookup(&udp(1003).0).is_some());
        assert_eq!((t.early_dropped, t.unanswered), (1, 1));
    }
}

#[cfg(test)]
mod sizing {
    use super::*;

    #[test]
    fn the_map_is_sized_for_nat_keys_and_counted_exactly() {
        for max in [1u32, 5, 100, 1000, 262_144] {
            let t = SessionTable::new(SessionConfig {
                max_sessions: max,
                ..SessionConfig::default()
            });
            assert!(t.map.capacity() >= 2 * max as usize, "max {max}");
            // hashbrown's capacity is 7/8 of its buckets (all of them when
            // tiny): the bucket count reserved_bytes assumes.
            let keys = 2 * max as u64;
            let buckets = if keys < 8 {
                if keys < 4 {
                    4
                } else {
                    8
                }
            } else {
                (keys * 8 / 7).next_power_of_two()
            };
            let usable = if buckets < 8 {
                buckets - 1
            } else {
                buckets / 8 * 7
            };
            assert_eq!(t.map.capacity() as u64, usable, "max {max}");
        }
    }

    #[test]
    fn max_for_bytes_inverts_reserved_bytes() {
        assert_eq!(SessionTable::max_for_bytes(0), 0);
        for budget in [1u64 << 20, 40 << 20, 1 << 30, 7 << 30] {
            let n = SessionTable::max_for_bytes(budget);
            assert!(SessionTable::reserved_bytes(n) <= budget);
            assert!(SessionTable::reserved_bytes(n + 1) > budget);
        }
        // The default table: about 300 bytes a session, 80 MB once full.
        let mb = SessionTable::reserved_bytes(262_144) as f64 / 1e6;
        assert!((60.0..100.0).contains(&mb), "{mb} MB");
    }
}
