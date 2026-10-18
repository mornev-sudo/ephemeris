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

const NS: u64 = 1_000_000_000;

/// The "port" packets coming out of an overlay tether arrive on. Tethers to a
/// site are interchangeable (a session moves to another WAN path on
/// failover), so they all count as one ingress.
pub const OVERLAY_INGRESS: PortId = PortId::MAX;

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

/// Idle timeouts in seconds. A session expires this long after its last packet.
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
            tcp_established: 3600,
            tcp_closing: 120,
            tcp_closed: 10,
            udp: 30,
            udp_stream: 180,
            icmp: 30,
            other: 60,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Hard cap per worker. All memory is reserved up front, so the fast path
    /// never allocates, and a flood of new flows can't exhaust RAM.
    pub max_sessions: u32,
    /// Only a TCP SYN may create a session. When false, a mid-stream TCP
    /// packet is "picked up" as established (handy after a router restart).
    pub tcp_strict: bool,
    pub timeouts: Timeouts,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            max_sessions: 262_144,
            tcp_strict: false,
            timeouts: Timeouts::default(),
        }
    }
}

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
}

impl SessionTable {
    pub fn new(cfg: SessionConfig) -> Self {
        // A per-process random seed, so an attacker can't precompute flows
        // that all land in the same hash bucket. (FxHash is fast but not a
        // cryptographic hash; a hardened build would use SipHash or similar.)
        let seed = RandomState::new().hash_one(0x5ed5u16) as usize;
        let max = cfg.max_sessions as usize;
        SessionTable {
            cfg,
            map: HashMap::with_capacity_and_hasher(max, FxSeededState::with_seed(seed)),
            slab: Vec::with_capacity(max),
            free: Vec::new(),
            wheel: (0..WHEEL_SLOTS).map(|_| Vec::new()).collect(),
            wheel_sec: 0,
            wheel_started: false,
            created: 0,
            expired: 0,
            blind: 0,
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
        } else {
            return None;
        };
        self.map.insert(key, idx);
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
        Track::Ok { idx, dir }
    }

    fn timeout_secs(&self, s: &Session) -> u64 {
        let t = &self.cfg.timeouts;
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

    /// Put `idx` in the wheel slot for second `at_ns` (clamped to one turn).
    fn schedule(&mut self, idx: u32, at_ns: u64, now_ns: u64) {
        if !self.wheel_started {
            self.wheel_started = true;
            self.wheel_sec = now_ns / NS;
        }
        let sec = (at_ns / NS).clamp(self.wheel_sec, self.wheel_sec + WHEEL_SLOTS - 1);
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
        self.slab[idx as usize].nat = Some(nat);
        true
    }

    fn remove(&mut self, idx: u32) {
        let s = &mut self.slab[idx as usize];
        s.alive = false;
        s.generation = s.generation.wrapping_add(1);
        let (key, nat) = (s.key, s.nat.take());
        self.map.remove(&key);
        if let Some(n) = nat {
            self.map.remove(&n.xkey);
        }
        self.free.push(idx);
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
        let i = t.create(k, d, TCP_ACK, 60, 0).unwrap(); // picked up: 3600 s timeout
        assert_eq!(t.get(i).state, State::Established);
        // Called rarely and far beyond one wheel turn (1024 s).
        assert_eq!(t.expire(3000 * NS), 0);
        assert_eq!(t.expire(3599 * NS), 0);
        assert_eq!(t.expire(3602 * NS), 1);
    }
}
