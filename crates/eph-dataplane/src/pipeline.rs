use crate::config::{Dhcp, NextHop, Port, PortId, Pppoe, Role};
use crate::filter;
use crate::nat::{self, NatConfig};
use crate::overlay::{
    self, Endpoints, Overlay, PathTable, ReplayGuard, TetherId, TetherStats, OUTER_LEN, TAG_LEN,
};
use crate::session::{
    Dir, FlowKey, NatBinding, SessionConfig, SessionTable, TcpSegment, Track, OVERLAY_INGRESS,
};
use crate::stats::{DropReason, Stats};
use crate::trace::{self, TraceCat, TraceConfig, TraceFlow, TraceKind, Tracer};
use eph_fib::Fib;
use eph_packet::{arp, checksum, eth, icmp, ipv4, l4, pppoe, Mac};
use rustc_hash::FxSeededState;
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::Ipv4Addr;
use std::sync::Arc;

/// What the I/O layer should do with the frame it handed to [`Pipeline::process`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Give the buffer back to the free pool.
    Drop(DropReason),
    /// Transmit `len` bytes starting at `off` in the frame, on `port`. `off`
    /// can differ from the received offset: encapsulation grows the packet
    /// *forwards* into the frame's headroom instead of copying it.
    Tx {
        port: PortId,
        off: usize,
        len: usize,
    },
}

/// Largest frame the router generates on its own (ARP, overlay probes).
pub const EMIT_MAX: usize = 128;

/// A frame the router generated on its own, to be copied into a free buffer
/// and sent. Fixed-size, so producing one never allocates.
#[derive(Clone)]
pub struct Emit {
    pub port: PortId,
    pub len: usize,
    pub frame: [u8; EMIT_MAX],
}

/// A packet for the control plane (DHCP), copied out of the frame. Rare, so
/// it may allocate.
#[derive(Debug, Clone)]
pub struct Punt {
    pub port: PortId,
    /// The whole Ethernet frame.
    pub frame: Vec<u8>,
}

/// A learned IP → MAC binding on a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Neighbor {
    pub port: PortId,
    pub ip: Ipv4Addr,
    pub mac: Mac,
}

/// Don't ARP for the same address more than once per second.
const ARP_RETRY_NS: u64 = 1_000_000_000;
/// A neighbour confirmed longer ago than this is re-checked with an ARP
/// request (it keeps being used meanwhile)...
const NEIGHBOR_REFRESH_NS: u64 = 300 * 1_000_000_000;
/// ...and forgotten if nothing confirms it for this long.
const NEIGHBOR_FORGET_NS: u64 = 1200 * 1_000_000_000;
/// Neighbours per worker. A large subnet full of ARP senders can't grow the
/// table without bound.
pub const NEIGHBOR_MAX: usize = 16384;
/// Tell sibling workers about a re-confirmed neighbour at most this often.
const NEIGHBOR_SHARE_NS: u64 = 60 * 1_000_000_000;
/// Cap on outstanding ARP attempts, so a scan of a /8 can't eat memory.
const ARP_PENDING_MAX: usize = 4096;
/// RFC 1812 4.3.2.8: ICMP errors MUST be rate limited. 100/s per worker,
/// bursts of up to 50.
const ICMP_RATE_PER_SEC: u64 = 100;
const ICMP_BURST: u64 = 50;
const ICMP_TOKEN_NS: u64 = 1_000_000_000 / ICMP_RATE_PER_SEC;
/// TTL for packets the router originates.
const LOCAL_TTL: u8 = 64;

const ETH: usize = eth::HDR_LEN;
/// Control-plane packets queued per batch at most (a DHCP flood can't eat
/// memory; the worker drains them every loop).
const PUNT_MAX: usize = 256;

#[derive(Debug, Clone, Copy)]
struct NeighborEntry {
    mac: Mac,
    /// When this binding was last confirmed.
    confirmed_ns: u64,
    /// When siblings were last told about it.
    shared_ns: u64,
}

fn seeded() -> FxSeededState {
    FxSeededState::with_seed(RandomState::new().hash_one(0x4e16u16) as usize)
}

/// Per-worker forwarding state.
pub struct Pipeline {
    ports: Arc<[Port]>,
    /// Per network card, which port each arriving frame belongs to (by its
    /// VLAN tag, or the lack of one).
    cards: Vec<CardPorts>,
    /// The smallest MTU of any port: packets up to this size skip the check.
    min_mtu: usize,
    fib: Arc<Fib<NextHop>>,
    /// Bumped whenever the FIB is replaced, invalidating next hops cached
    /// in sessions.
    fib_gen: u64,
    overlay: Arc<Overlay>,
    paths: Arc<PathTable>,
    nat: Arc<NatConfig>,
    /// This worker's index and the worker count: NAT ports are split between
    /// workers so two cores never hand out the same one.
    worker_id: u16,
    workers: u16,
    tether_stats: Vec<TetherStats>,
    /// Only one worker sends overlay probes.
    prober: bool,
    /// This router's current run (see [`overlay`]) and the next packet
    /// number to seal with: together they keep every nonce unique.
    overlay_run: u16,
    tx_counter: u64,
    /// Received counters, shared by all workers.
    replay: Arc<ReplayGuard>,
    /// Learned addresses of peers without a fixed one, shared by all workers.
    endpoints: Arc<Endpoints>,
    next_probe_ns: u64,
    probe_seq: u32,
    sessions: SessionTable,
    neighbors: HashMap<(PortId, Ipv4Addr), NeighborEntry, FxSeededState>,
    arp_pending: HashMap<(PortId, Ipv4Addr), u64, FxSeededState>,
    next_neighbor_sweep_ns: u64,
    /// Last time a full table was swept for room (at most once a second, so
    /// a flood of new ARP senders can't make every packet scan the table).
    last_full_sweep_ns: u64,
    icmp_tokens: u64,
    icmp_last_refill: u64,
    ip_ident: u16,
    now_ns: u64,
    pub stats: Stats,
    /// Frames generated during `process` calls; the I/O layer drains this.
    pub emits: Vec<Emit>,
    /// Neighbours learned during `process` calls; the worker broadcasts these
    /// to its siblings, which feed them to [`Pipeline::learn`].
    pub learned: Vec<Neighbor>,
    /// Packets for the control plane (DHCP); the worker forwards these.
    pub punts: Vec<Punt>,
    /// Packet tracing (debug logging), off unless asked for; the worker
    /// drains `tracer.events`.
    pub tracer: Tracer,
}

impl Pipeline {
    pub fn new(
        ports: Arc<[Port]>,
        fib: Arc<Fib<NextHop>>,
        sessions: SessionConfig,
        overlay: Arc<Overlay>,
    ) -> Self {
        let nports = ports.len();
        let replay = Arc::new(ReplayGuard::new(overlay.sites.len()));
        let endpoints = Arc::new(Endpoints::new(overlay.tethers.len()));
        Pipeline {
            min_mtu: min_mtu(&ports),
            cards: card_ports(&ports),
            ports,
            fib,
            fib_gen: 1,
            paths: Arc::new(PathTable::empty(&overlay)),
            tether_stats: vec![TetherStats::default(); overlay.tethers.len()],
            overlay,
            nat: Arc::new(NatConfig::default()),
            worker_id: 0,
            workers: 1,
            prober: false,
            overlay_run: 0,
            tx_counter: 0,
            replay,
            endpoints,
            next_probe_ns: 0,
            probe_seq: 0,
            sessions: SessionTable::new(sessions),
            // Seeded like the session table: the keys come from the network.
            neighbors: HashMap::with_hasher(seeded()),
            arp_pending: HashMap::with_hasher(seeded()),
            next_neighbor_sweep_ns: 0,
            last_full_sweep_ns: 0,
            icmp_tokens: ICMP_BURST,
            icmp_last_refill: 0,
            ip_ident: 0,
            now_ns: 0,
            stats: Stats {
                ports: vec![Default::default(); nports],
                ..Stats::default()
            },
            emits: Vec::with_capacity(64),
            learned: Vec::with_capacity(16),
            punts: Vec::new(),
            tracer: Tracer::default(),
        }
    }

    /// What to trace (see [`trace`]).
    pub fn set_trace(&mut self, cfg: TraceConfig) {
        self.tracer.set(cfg);
    }

    /// Trace a drop, if its category is on.
    #[inline]
    fn trace_drop(&mut self, r: DropReason, port: PortId, frame: &[u8]) {
        if let Some(cat) = TraceCat::of_drop(r) {
            if self.tracer.on(cat) {
                let flow = trace::flow_of_frame(frame);
                self.tracer
                    .record(self.now_ns, cat, TraceKind::Drop(r), port, flow);
            }
        }
    }

    /// Reading the clock costs ~20 ns, a third of our per-packet budget at
    /// 10G, so the worker sets the time once per batch of packets instead.
    #[inline]
    pub fn set_time(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
    }

    /// Make this worker the one that sends overlay probes.
    pub fn set_prober(&mut self, prober: bool) {
        self.prober = prober;
    }

    /// Periodic work outside the per-packet path: expire idle sessions,
    /// refresh counters, send overlay probes. Called once per worker loop.
    pub fn housekeeping(&mut self) {
        self.sessions.expire(self.now_ns);
        self.stats.sessions_active = self.sessions.len() as u64;
        self.stats.sessions_created = self.sessions.created;
        self.stats.sessions_expired = self.sessions.expired;
        self.stats.tcp_blind = self.sessions.blind;
        if self.now_ns >= self.next_neighbor_sweep_ns {
            let now = self.now_ns;
            self.neighbors
                .retain(|_, e| now.saturating_sub(e.confirmed_ns) < NEIGHBOR_FORGET_NS);
            self.next_neighbor_sweep_ns = now + 10 * 1_000_000_000;
        }
        if self.prober && self.overlay.enabled() && self.now_ns >= self.next_probe_ns {
            self.send_probes();
            self.next_probe_ns = self.now_ns + overlay::PROBE_INTERVAL_NS;
        }
    }

    /// Swap in a new port table (addresses, session policy). The ports must be
    /// the same interfaces in the same order; neighbours and sessions stay.
    pub fn ports(&self) -> &Arc<[Port]> {
        &self.ports
    }

    pub fn set_ports(&mut self, ports: Arc<[Port]>) {
        debug_assert_eq!(ports.len(), self.ports.len());
        self.min_mtu = min_mtu(&ports);
        self.cards = card_ports(&ports);
        self.ports = ports;
    }

    /// Swap in a new forwarding table. Sessions keep running; their cached
    /// next hops are refreshed on their next packet (see `fib_gen`).
    pub fn set_fib(&mut self, fib: Arc<Fib<NextHop>>) {
        self.fib = fib;
        self.fib_gen += 1;
    }

    /// Swap in a new SD-WAN path table. Sessions move to their class's new
    /// tether on their next packet if its generation changed.
    /// Swap in new source-NAT rules. Existing sessions keep their translation.
    pub fn set_nat(&mut self, nat: Arc<NatConfig>) {
        self.nat = nat;
    }

    /// Overlay crypto state from the control plane: this start's run number
    /// (persisted and raised on every start) and the replay guard all
    /// workers share.
    pub fn set_overlay_run(&mut self, run: u16, replay: Arc<ReplayGuard>) {
        self.overlay_run = run;
        self.tx_counter = 0;
        self.replay = replay;
    }

    /// Share one learned-endpoints table between all workers.
    pub fn set_endpoints(&mut self, endpoints: Arc<Endpoints>) {
        self.endpoints = endpoints;
    }

    pub fn set_worker(&mut self, id: u16, count: u16) {
        self.worker_id = id;
        self.workers = count.max(1);
    }

    pub fn set_paths(&mut self, paths: Arc<PathTable>) {
        self.paths = paths;
    }

    pub fn overlay(&self) -> &Arc<Overlay> {
        &self.overlay
    }

    pub fn paths(&self) -> &Arc<PathTable> {
        &self.paths
    }

    pub fn tether_stats(&self) -> &[TetherStats] {
        &self.tether_stats
    }

    pub fn sessions(&self) -> &SessionTable {
        &self.sessions
    }

    /// Install a neighbour learned (and verified) by another worker.
    pub fn learn(&mut self, n: Neighbor) {
        let k = (n.port, n.ip);
        if !self.neighbors.contains_key(&k) && !self.neighbor_room() {
            return;
        }
        let now = self.now_ns;
        self.neighbors.insert(
            k,
            NeighborEntry {
                mac: n.mac,
                confirmed_ns: now,
                shared_ns: now,
            },
        );
        self.arp_pending.remove(&k);
    }

    pub fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }

    pub fn neighbors(&self) -> impl Iterator<Item = Neighbor> + '_ {
        self.neighbors.iter().map(|(&(port, ip), e)| Neighbor {
            port,
            ip,
            mac: e.mac,
        })
    }

    /// Space for one more neighbour (forgetting stale ones if needed)?
    fn neighbor_room(&mut self) -> bool {
        if self.neighbors.len() < NEIGHBOR_MAX {
            return true;
        }
        let now = self.now_ns;
        if now.saturating_sub(self.last_full_sweep_ns) < ARP_RETRY_NS {
            return false;
        }
        self.last_full_sweep_ns = now;
        self.neighbors
            .retain(|_, e| now.saturating_sub(e.confirmed_ns) < NEIGHBOR_FORGET_NS);
        self.neighbors.len() < NEIGHBOR_MAX
    }

    /// The MAC to send to `ip` on `port`, if known. An old entry is still
    /// used while an ARP request re-checks it; a very old one is forgotten.
    fn neighbor(&mut self, port: PortId, ip: Ipv4Addr) -> Option<Mac> {
        // On a PPPoE link everything goes to the access concentrator.
        match self.ports[port as usize].pppoe {
            Pppoe::Up { peer, .. } => return Some(peer),
            Pppoe::Dialing => return None,
            Pppoe::Off => {}
        }
        let e = *self.neighbors.get(&(port, ip))?;
        let age = self.now_ns.saturating_sub(e.confirmed_ns);
        if age >= NEIGHBOR_FORGET_NS {
            self.neighbors.remove(&(port, ip));
            return None;
        }
        if age >= NEIGHBOR_REFRESH_NS {
            self.resolve(port, ip);
        }
        Some(e.mac)
    }

    /// Process one frame received on network card `card`.
    ///
    /// `frame` is the whole packet buffer (a 4 KiB UMEM frame) and the packet
    /// is the `len` bytes starting at `off`. The space before `off` is
    /// headroom for encapsulation; the space after the packet lets replies
    /// that are bigger than the request (ICMP errors) be built in place.
    ///
    /// A [`Verdict::Tx`] names the *port* to send on; [`Pipeline::card_of`]
    /// says which card that is.
    #[inline]
    pub fn process(&mut self, card: u16, frame: &mut [u8], off: usize, len: usize) -> Verdict {
        self.stats.rx += 1;
        let v = match self.ingress(card, frame, off, len) {
            Ok((ingress, off, len)) => {
                let v = self.classify(ingress, frame, off, len);
                if let (Verdict::Drop(r), true) = (v, self.tracer.cfg.mask != 0) {
                    self.trace_drop(r, ingress, &frame[off..off + len]);
                }
                self.wrap_for_link(frame, v)
            }
            Err(r) => {
                if self.tracer.cfg.mask != 0 && off + len <= frame.len() {
                    // No interface yet: reported against the card.
                    self.trace_drop(r, PortId::MAX - card, &frame[off..off + len]);
                }
                Verdict::Drop(r)
            }
        };
        if let Verdict::Drop(r) = v {
            self.stats.drop(r);
        }
        v
    }

    /// The network card port `port` sends on.
    #[inline]
    pub fn card_of(&self, port: PortId) -> usize {
        self.ports[port as usize].card as usize
    }

    /// Which port a frame arriving on `card` belongs to, by its 802.1Q tag
    /// (taken off here, so everything after sees a plain Ethernet frame).
    /// Returns the port and the frame's new offset and length.
    #[inline]
    fn ingress(
        &mut self,
        card: u16,
        frame: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<(PortId, usize, usize), DropReason> {
        if len < ETH || off + len > frame.len() {
            return Err(DropReason::Malformed);
        }
        let ports = self.cards.get(card as usize).ok_or(DropReason::Vlan)?;
        let (port, off, len) = if eth::ethertype(&frame[off..]) != eth::TYPE_VLAN {
            (ports.untagged.ok_or(DropReason::Vlan)?, off, len)
        } else {
            if len < ETH + eth::VLAN_TAG_LEN {
                return Err(DropReason::Malformed);
            }
            let port = match eth::vlan_id(&frame[off..]) {
                0 => ports.untagged, // priority tag only
                vid => ports.tagged.iter().find(|t| t.0 == vid).map(|t| t.1),
            }
            .ok_or(DropReason::Vlan)?;
            (port, eth::pop_vlan(frame, off), len - eth::VLAN_TAG_LEN)
        };
        let c = &mut self.stats.ports[port as usize];
        c.rx_packets += 1;
        c.rx_bytes += len as u64;
        Ok((port, off, len))
    }

    /// Wrap a frame for the link it leaves on: PPPoE, then the VLAN tag
    /// (PPPoE over a VLAN is how many ISPs deliver fibre and DSL).
    #[inline]
    fn wrap_for_link(&mut self, frame: &mut [u8], mut v: Verdict) -> Verdict {
        if let Verdict::Tx { port, off, len } = v {
            if self.ports[port as usize].pppoe != Pppoe::Off {
                v = self.pppoe_wrap(frame, port, off, len);
            }
        }
        if let Verdict::Tx { port, off, len } = v {
            if let Some(vid) = self.ports[port as usize].vlan {
                v = match make_room(frame, off, len, eth::VLAN_TAG_LEN) {
                    Some(off) => Verdict::Tx {
                        port,
                        off: eth::push_vlan(frame, off, vid),
                        len: len + eth::VLAN_TAG_LEN,
                    },
                    None => Verdict::Drop(DropReason::TooBig),
                };
            }
        }
        v
    }

    /// Tag a frame the control plane built (DHCP, PPPoE discovery and PPP
    /// control) for `port`'s VLAN, if it has one. The frame is the `len`
    /// bytes at `off` in `buf`; returns its new offset and length.
    pub fn tag_for(
        &self,
        port: PortId,
        buf: &mut [u8],
        off: usize,
        len: usize,
    ) -> Option<(usize, usize)> {
        let Some(vid) = self.ports.get(port as usize)?.vlan else {
            return Some((off, len));
        };
        if len < ETH {
            return None;
        }
        let off = make_room(buf, off, len, eth::VLAN_TAG_LEN)?;
        Some((eth::push_vlan(buf, off, vid), len + eth::VLAN_TAG_LEN))
    }

    fn classify(&mut self, ingress: PortId, frame: &mut [u8], off: usize, len: usize) -> Verdict {
        if len < ETH || off + len > frame.len() {
            return Verdict::Drop(DropReason::Malformed);
        }
        let pkt = &frame[off..off + len];
        let port = &self.ports[ingress as usize];
        let dst = eth::dst(pkt);
        if dst != port.mac && dst != eth::BROADCAST {
            return Verdict::Drop(DropReason::NotForUs);
        }
        match eth::ethertype(pkt) {
            eth::TYPE_IPV4 => self.ipv4(ingress, frame, off, len, None),
            eth::TYPE_ARP => self.arp(ingress, frame, off, len),
            pppoe::TYPE_DISCOVERY | pppoe::TYPE_SESSION if port.pppoe != Pppoe::Off => {
                self.pppoe_rx(ingress, frame, off, len)
            }
            eth::TYPE_VLAN => Verdict::Drop(DropReason::Vlan),
            _ => Verdict::Drop(DropReason::UnsupportedEthertype),
        }
    }

    /// PPPoE in: IPv4 in our session is unwrapped and routed like any
    /// other packet; discovery and PPP control go to the control plane.
    fn pppoe_rx(&mut self, ingress: PortId, frame: &mut [u8], off: usize, len: usize) -> Verdict {
        const H: usize = ETH + pppoe::SESSION_HDR_LEN;
        let p = &self.ports[ingress as usize];
        let data = &frame[off..off + len];
        let is_session_ipv4 = eth::ethertype(data) == pppoe::TYPE_SESSION
            && len >= H
            && data[ETH] == 0x11
            && data[ETH + 1] == pppoe::CODE_SESSION
            && u16::from_be_bytes([data[ETH + 6], data[ETH + 7]]) == pppoe::PROTO_IPV4;
        if let (true, Some((session, peer, _))) = (is_session_ipv4, p.pppoe_up()) {
            if u16::from_be_bytes([data[ETH + 2], data[ETH + 3]]) != session
                || eth::src(data) != peer
            {
                return Verdict::Drop(DropReason::NotForUs);
            }
            // PPPoE length counts the 2-byte PPP protocol field.
            let ip_len = (u16::from_be_bytes([data[ETH + 4], data[ETH + 5]]) as usize)
                .saturating_sub(2)
                .min(len - H);
            // Turn it back into a plain Ethernet frame 8 bytes further on.
            let mac = p.mac;
            let new_off = off + pppoe::SESSION_HDR_LEN;
            eth::write(&mut frame[new_off..], mac, peer, eth::TYPE_IPV4);
            return self.ipv4(ingress, frame, new_off, ETH + ip_len, None);
        }
        if self.punts.len() < PUNT_MAX {
            self.punts.push(Punt {
                port: ingress,
                frame: frame[off..off + len].to_vec(),
            });
        }
        Verdict::Drop(DropReason::PppoeToControl)
    }

    /// PPPoE out: put the session header in front of the IPv4 packet (in the
    /// frame's headroom; the packet itself doesn't move).
    fn pppoe_wrap(&mut self, frame: &mut [u8], port: PortId, off: usize, len: usize) -> Verdict {
        let Some((session, peer, _)) = self.ports[port as usize].pppoe_up() else {
            return Verdict::Drop(DropReason::NoRoute); // still dialling
        };
        if eth::ethertype(&frame[off..]) != eth::TYPE_IPV4 {
            return Verdict::Drop(DropReason::UnsupportedEthertype);
        }
        const N: usize = pppoe::SESSION_HDR_LEN;
        let Some(off) = make_room(frame, off, len, N) else {
            return Verdict::Drop(DropReason::TooBig);
        };
        let new_off = off - N;
        let mac = self.ports[port as usize].mac;
        let f = &mut frame[new_off..];
        eth::write(f, peer, mac, pppoe::TYPE_SESSION);
        f[ETH] = 0x11;
        f[ETH + 1] = pppoe::CODE_SESSION;
        f[ETH + 2..ETH + 4].copy_from_slice(&session.to_be_bytes());
        f[ETH + 4..ETH + 6].copy_from_slice(&((len - ETH + 2) as u16).to_be_bytes());
        f[ETH + 6..ETH + 8].copy_from_slice(&pppoe::PROTO_IPV4.to_be_bytes());
        Verdict::Tx {
            port,
            off: new_off,
            len: len + N,
        }
    }

    /// The MTU of the port `dst` is routed out of, if a packet of `len`
    /// bytes might not fit it. (The overlay checks its own MTU.)
    fn mtu_towards(&self, dst: Ipv4Addr, len: usize) -> Option<usize> {
        if len <= self.min_mtu {
            return None; // the common case: fits every port, no lookup
        }
        match self.fib.lookup(dst)? {
            NextHop::Ip { port, .. } => Some(self.ports[*port as usize].ip_mtu() as usize),
            NextHop::Site(_) => None,
        }
    }

    /// Queue a frame the router made itself, wrapped for PPPoE and tagged
    /// for a VLAN as needed.
    fn push_emit(&mut self, mut e: Emit) {
        let p = &self.ports[e.port as usize];
        let n = if p.pppoe != Pppoe::Off {
            pppoe::SESSION_HDR_LEN
        } else {
            0
        } + if p.vlan.is_some() {
            eth::VLAN_TAG_LEN
        } else {
            0
        };
        if n > 0 {
            if e.len + n > EMIT_MAX {
                return;
            }
            e.frame.copy_within(0..e.len, n);
            let v = Verdict::Tx {
                port: e.port,
                off: n,
                len: e.len,
            };
            match self.wrap_for_link(&mut e.frame, v) {
                Verdict::Tx { off: 0, len, .. } => e.len = len,
                _ => return,
            }
        }
        self.emits.push(e);
    }

    /// UDP to the DHCP server port on a serving port, or to the client port
    /// on a port that gets its address by DHCP.
    fn is_dhcp(&self, ingress: PortId, ip: &[u8], h: &ipv4::Header) -> bool {
        let want = match self.ports[ingress as usize].dhcp {
            Dhcp::Off => return false,
            Dhcp::Server => eph_packet::dhcp::SERVER_PORT,
            Dhcp::Client => eph_packet::dhcp::CLIENT_PORT,
        };
        h.proto == ipv4::PROTO_UDP
            && !ipv4::is_fragment(ip)
            && ip.len() >= h.hdr_len + 4
            && u16::from_be_bytes([ip[h.hdr_len + 2], ip[h.hdr_len + 3]]) == want
    }

    // ---------------------------------------------------------------- ARP

    fn arp(&mut self, ingress: PortId, frame: &mut [u8], off: usize, len: usize) -> Verdict {
        let buf = &mut frame[off..];
        let Some(a) = arp::parse(&buf[ETH..len]) else {
            return Verdict::Drop(DropReason::Malformed);
        };
        let port = &self.ports[ingress as usize];
        let (my_mac, my_ip) = (port.mac, port.addr);

        // RFC 826 "merge": if we already know the sender, refresh it; if the
        // packet is aimed at us, add it. Only accept senders on this link
        // (its subnet, or an on-link gateway outside it).
        // Ours: the port's address, or (on an outside port) a NAT pool
        // address, which nothing else on that link would answer for.
        let for_us = a.tpa == my_ip || (port.role == Role::Outside && self.nat.owns(a.tpa));
        if port.reaches(a.spa)
            && a.spa != my_ip
            && !eth::is_multicast(&a.sha)
            && (for_us || self.neighbors.contains_key(&(ingress, a.spa)))
        {
            // A reply to a request we sent is trusted to change a binding;
            // anything else that disagrees with what we know only triggers
            // a fresh request, so a spoofed ARP can't redirect traffic.
            let answer = a.op == arp::OP_REPLY
                && a.tpa == my_ip
                && self.arp_pending.contains_key(&(ingress, a.spa));
            self.insert_neighbor(
                Neighbor {
                    port: ingress,
                    ip: a.spa,
                    mac: a.sha,
                },
                answer,
            );
        }

        if a.op == arp::OP_REQUEST && for_us {
            // Answer in place: turn the request around.
            eth::write(buf, a.sha, my_mac, eth::TYPE_ARP);
            arp::write(
                &mut buf[ETH..],
                &arp::Arp {
                    op: arp::OP_REPLY,
                    sha: my_mac,
                    spa: a.tpa,
                    tha: a.sha,
                    tpa: a.spa,
                },
            );
            self.stats.originated += 1;
            return Verdict::Tx {
                port: ingress,
                off,
                len,
            };
        }
        Verdict::Drop(DropReason::ArpConsumed)
    }

    fn insert_neighbor(&mut self, n: Neighbor, answer: bool) {
        let k = (n.port, n.ip);
        let now = self.now_ns;
        let prev = self.neighbors.get(&k).copied();
        let shared_ns = match prev {
            Some(e) if e.mac != n.mac && !answer => {
                self.stats.arp_conflicts += 1;
                let flow = TraceFlow {
                    src: n.ip,
                    ..TraceFlow::default()
                };
                self.tracer.record(
                    now,
                    TraceCat::Arp,
                    TraceKind::ArpConflict {
                        claimed: n.mac,
                        known: e.mac,
                    },
                    n.port,
                    flow,
                );
                self.resolve(n.port, n.ip);
                return;
            }
            Some(e) if e.mac == n.mac => e.shared_ns,
            Some(_) => 0, // changed: tell the siblings now
            None if !self.neighbor_room() => return,
            None => 0,
        };
        if prev.is_none_or(|e| e.mac != n.mac) {
            let flow = TraceFlow {
                src: n.ip,
                ..TraceFlow::default()
            };
            let changed = prev.is_some();
            self.tracer.record(
                now,
                TraceCat::Arp,
                TraceKind::ArpLearned {
                    mac: n.mac,
                    changed,
                },
                n.port,
                flow,
            );
        }
        let share = now.saturating_sub(shared_ns) >= NEIGHBOR_SHARE_NS || shared_ns == 0;
        self.neighbors.insert(
            k,
            NeighborEntry {
                mac: n.mac,
                confirmed_ns: now,
                shared_ns: if share { now } else { shared_ns },
            },
        );
        if share {
            self.learned.push(n);
        }
        self.arp_pending.remove(&k);
    }

    /// Queue an ARP request for `ip` out of `port`, at most once per second.
    fn resolve(&mut self, port: PortId, ip: Ipv4Addr) {
        if self.ports[port as usize].pppoe != Pppoe::Off {
            return; // no ARP on a PPPoE link
        }
        let now = self.now_ns;
        if let Some(&last) = self.arp_pending.get(&(port, ip)) {
            if now.saturating_sub(last) < ARP_RETRY_NS {
                return;
            }
        }
        if self.arp_pending.len() >= ARP_PENDING_MAX {
            self.arp_pending
                .retain(|_, t| now.saturating_sub(*t) < ARP_RETRY_NS);
            if self.arp_pending.len() >= ARP_PENDING_MAX {
                return;
            }
        }
        self.arp_pending.insert((port, ip), now);
        let flow = TraceFlow {
            dst: ip,
            ..TraceFlow::default()
        };
        self.tracer
            .record(now, TraceCat::Arp, TraceKind::ArpRequest, port, flow);
        let p = &self.ports[port as usize];
        let mut e = Emit {
            port,
            len: 0,
            frame: [0; EMIT_MAX],
        };
        e.len = arp::build_request(&mut e.frame, p.mac, p.addr, ip);
        self.push_emit(e);
        self.stats.originated += 1;
    }

    // --------------------------------------------------------------- IPv4

    /// `via` is set when the packet just came out of an overlay tether.
    fn ipv4(
        &mut self,
        ingress: PortId,
        frame: &mut [u8],
        off: usize,
        len: usize,
        via: Option<TetherId>,
    ) -> Verdict {
        let mut h = match ipv4::parse(&frame[off + ETH..off + len]) {
            Ok(h) => h,
            Err(_) => return Verdict::Drop(DropReason::BadIpHeader),
        };
        // Trim Ethernet padding: from here on the frame is exactly the packet.
        let len = ETH + h.total_len;
        // DHCP on a port where the router serves or requests leases goes to
        // the control plane, before any checks: a client asking for an
        // address has none yet (source 0.0.0.0, destination broadcast).
        if via.is_none() && self.is_dhcp(ingress, &frame[off + ETH..off + len], &h) {
            if self.punts.len() < PUNT_MAX {
                self.punts.push(Punt {
                    port: ingress,
                    frame: frame[off..off + len].to_vec(),
                });
            }
            return Verdict::Drop(DropReason::DhcpToControl);
        }
        if let Err(r) = filter::check(&frame[off + ETH..off + len], &h, &self.ports, &self.nat) {
            return Verdict::Drop(r);
        }
        if !self.source_ok(ingress, via, h.src) {
            return Verdict::Drop(DropReason::SpoofedSource);
        }

        // Addressed to one of the router's own interfaces?
        // ...unless it's a reply to a NATed session (those come back to the
        // outside interface's address or a pool address).
        let ours = self.ports.iter().any(|p| p.addr == h.dst) || self.nat.owns(h.dst);
        // Nothing the router answers is ever fragmented, and it doesn't
        // reassemble. That includes fragmented replies to NATed sessions:
        // later fragments carry no ports to find their session by.
        if ours && ipv4::is_fragment(&frame[off + ETH..]) {
            return Verdict::Drop(DropReason::FragmentToRouter);
        }
        if ours && !self.is_nat_reply(frame, off, &h) {
            return self.local(ingress, frame, off, len, &h, via);
        }

        if h.ttl <= 1 {
            return self.icmp_error(
                ingress,
                frame,
                off,
                &h,
                icmp::TIME_EXCEEDED,
                0,
                0,
                DropReason::TtlExceeded,
            );
        }

        // The way out may carry less (PPPoE: 1492, or a configured MTU).
        // Checked before NAT, so the "too big" error goes to the real sender.
        if let Some(mtu) = self.mtu_towards(h.dst, h.total_len) {
            if h.total_len > mtu {
                if frame[off + ETH + 6] & 0x40 == 0 {
                    return Verdict::Drop(DropReason::TooBig); // fragmentation not implemented
                }
                return self.icmp_error(
                    ingress,
                    frame,
                    off,
                    &h,
                    icmp::DEST_UNREACHABLE,
                    icmp::CODE_FRAG_NEEDED,
                    mtu as u32,
                    DropReason::TooBig,
                );
            }
        }

        let allow_new = match via {
            Some(_) => self.overlay.allow_new_sessions,
            None => self.ports[ingress as usize].allow_new_sessions,
        };
        // Sessions remember where each direction arrives. Tethers to a site
        // are interchangeable, so they share one ingress.
        let at = if via.is_some() {
            OVERLAY_INGRESS
        } else {
            ingress
        };
        let (nh, sess) = match self.track(ingress, at, frame, off, &mut h, allow_new) {
            Ok(x) => x,
            Err(v) => return v,
        };
        match nh {
            // RFC 2644: don't forward directed broadcasts.
            NextHop::Ip {
                port,
                gateway: None,
            } if h.dst == self.ports[port as usize].broadcast() => {
                return Verdict::Drop(DropReason::Martian);
            }
            // Path MTU: the tether adds headers, so the overlay carries
            // smaller packets than the LAN. Tell the sender (RFC 1191).
            NextHop::Site(_) if h.total_len > self.overlay.mtu as usize => {
                let dont_fragment = frame[off + ETH + 6] & 0x40 != 0;
                if !dont_fragment {
                    return Verdict::Drop(DropReason::TooBig); // fragmentation not implemented
                }
                let mtu = self.overlay.mtu as u32;
                return self.icmp_error(
                    ingress,
                    frame,
                    off,
                    &h,
                    icmp::DEST_UNREACHABLE,
                    icmp::CODE_FRAG_NEEDED,
                    mtu,
                    DropReason::TooBig,
                );
            }
            _ => {}
        }
        // MSS adjust: shrink the MSS announced in SYNs so segments fit the
        // smallest link on the way, without fragmentation. Both directions of
        // the handshake count: the SYN-ACK coming back in through a port
        // sizes what the inside host sends out through it.
        if h.proto == ipv4::PROTO_TCP {
            if let Some(max) = self.mss_limit(ingress, nh, via.is_some()) {
                clamp_mss(&mut frame[off + ETH..off + len], &h, max);
            }
        }

        // The actual forwarding work: two MAC addresses and one TTL (plus a
        // tether header for the overlay).
        ipv4::decrement_ttl(&mut frame[off + ETH..]);
        self.deliver(frame, off, len, nh, sess, true)
    }

    /// Session tracking and policy, then the route decision. Returns the next
    /// hop (and the session, if any), or the verdict to give instead. `at`
    /// is the ingress the session table sees (see [`OVERLAY_INGRESS`]).
    #[allow(clippy::too_many_arguments)]
    fn track(
        &mut self,
        ingress: PortId,
        at: PortId,
        frame: &mut [u8],
        off: usize,
        h: &mut ipv4::Header,
        allow_new: bool,
    ) -> Result<(NextHop, Option<u32>), Verdict> {
        let bytes = h.total_len as u64;
        let now = self.now_ns;
        let ip = off + ETH..off + ETH + h.total_len;
        match flow_of(&frame[off + ETH..off + ETH + h.total_len], h)? {
            Flow::Tracked { key, lo_to_hi, tcp } => {
                let tcp_flags = tcp.map_or(0, |t| t.flags);
                if let Some(idx) = self.sessions.lookup(&key) {
                    // Known session: the common case. A packet carrying the
                    // *translated* tuple is a reply from the outside.
                    let s = self.sessions.get(idx);
                    let nat = s.nat;
                    let translated_side = nat.is_some_and(|n| n.xkey == key);
                    let dir = if translated_side {
                        Dir::Reverse
                    } else {
                        s.dir(lo_to_hi)
                    };
                    // Replies to a NATed session come to the translated
                    // address. The same reply sent straight to the inside
                    // host's own address is someone going around the NAT.
                    if nat.is_some() && !translated_side && dir == Dir::Reverse {
                        return Err(Verdict::Drop(DropReason::SessionMismatch));
                    }
                    // Each direction keeps arriving where it first did (until
                    // the routes change), or the packet is spoofed.
                    let fib_changed = s.fib_gen != self.fib_gen;
                    if !fib_changed && s.ingress[dir as usize].is_some_and(|p| p != at) {
                        return Err(Verdict::Drop(DropReason::SessionMismatch));
                    }
                    let flags = match tcp {
                        Some(seg) => self.sessions.observe_tcp(idx, dir, &seg),
                        None => tcp_flags,
                    };
                    let Track::Ok { idx, dir } =
                        self.sessions.update_dir(idx, dir, flags, bytes, now)
                    else {
                        return Err(Verdict::Drop(DropReason::InvalidTcpState));
                    };
                    match nat {
                        // Reply: back to the original inside address and
                        // port, *before* routing (that's where it goes now).
                        Some(n) if translated_side => {
                            nat::translate_dst(&mut frame[ip.clone()], n.orig_addr, n.orig_port);
                            h.dst = n.orig_addr;
                        }
                        // Outbound: rewrite the source. Routing only looks at
                        // the destination, so the order doesn't matter here.
                        Some(n) if dir == Dir::Forward => {
                            nat::translate_src(&mut frame[ip.clone()], n.addr, n.port);
                            h.src = n.addr;
                        }
                        _ => {}
                    }
                    let s = self.sessions.get_mut(idx);
                    if s.fib_gen != self.fib_gen {
                        s.next_hop = [None; 2];
                        s.ingress = [None; 2];
                        s.fib_gen = self.fib_gen;
                    }
                    s.ingress[dir as usize] = Some(at);
                    if let Some(nh) = s.next_hop[dir as usize] {
                        return Ok((nh, Some(idx))); // cached: no FIB lookup at all
                    }
                    let nh = self.route(ingress, frame, off, h)?;
                    let s = self.sessions.get_mut(idx);
                    s.next_hop[dir as usize] = Some(nh);
                    // The other direction comes back from where this one goes.
                    let other = 1 - dir as usize;
                    s.ingress[other] = s.ingress[other].or(Some(egress_of(nh)));
                    return Ok((nh, Some(idx)));
                }
                // First packet of a new session.
                if !allow_new {
                    return Err(Verdict::Drop(DropReason::NoSession));
                }
                if !self.sessions.can_create(key.proto, tcp_flags) {
                    return Err(Verdict::Drop(DropReason::InvalidTcpState));
                }
                let nh = self.route(ingress, frame, off, h)?;
                // Source NAT for this new session? Decide and reserve the
                // translated tuple *before* creating the session, so a session
                // never exists half-translated.
                let mut binding = None;
                if let NextHop::Ip { port: egress, .. } = nh {
                    if let Some(addr) = self.nat.decide(&self.ports, ingress, egress, h.src, h.dst)
                    {
                        let (sport, dport) = if lo_to_hi {
                            (key.lo_port, key.hi_port)
                        } else {
                            (key.hi_port, key.lo_port)
                        };
                        let Some((port, xkey)) =
                            self.alloc_nat(key.proto, addr, h.dst, sport, dport)
                        else {
                            return Err(Verdict::Drop(DropReason::NatExhausted));
                        };
                        binding = Some(NatBinding {
                            xkey,
                            orig_addr: h.src,
                            orig_port: sport,
                            addr,
                            port,
                        });
                    }
                }
                let Some(idx) = self.sessions.create(key, lo_to_hi, tcp_flags, bytes, now) else {
                    return Err(Verdict::Drop(DropReason::SessionTableFull));
                };
                if let Some(seg) = tcp {
                    self.sessions.observe_tcp(idx, Dir::Forward, &seg);
                }
                if self.tracer.on(TraceCat::Session) || self.tracer.on(TraceCat::Nat) {
                    let (sport, dport) = if lo_to_hi {
                        (key.lo_port, key.hi_port)
                    } else {
                        (key.hi_port, key.lo_port)
                    };
                    let flow = TraceFlow {
                        proto: key.proto,
                        src: h.src,
                        dst: h.dst,
                        sport,
                        dport,
                    };
                    self.tracer.record(
                        now,
                        TraceCat::Session,
                        TraceKind::SessionNew,
                        ingress,
                        flow,
                    );
                    if let Some(b) = binding {
                        let kind = TraceKind::NatBound {
                            addr: b.addr,
                            port: b.port,
                        };
                        self.tracer.record(now, TraceCat::Nat, kind, ingress, flow);
                    }
                }
                if let Some(b) = binding {
                    self.sessions.bind_nat(idx, b);
                    nat::translate_src(&mut frame[ip.clone()], b.addr, b.port);
                    h.src = b.addr;
                }
                // The first packet decides the session's application class:
                // the server port is its destination port.
                let dport = if lo_to_hi { key.hi_port } else { key.lo_port };
                let class = self
                    .overlay
                    .classify(key.proto, dport, frame[off + ETH + 1] >> 2);
                let s = self.sessions.get_mut(idx);
                s.next_hop[0] = Some(nh);
                s.fib_gen = self.fib_gen;
                s.class = class;
                // Replies must come back from where this packet goes.
                s.ingress = [Some(at), Some(egress_of(nh))];
                Ok((nh, Some(idx)))
            }
            // An ICMP error about a session we know ("RELATED" in Linux terms):
            // e.g. Port Unreachable coming back for a UDP flow. Let it through
            // so the sender learns about the problem.
            Flow::Related { key, quoted_src } => {
                // An error goes back to whoever sent the packet it quotes.
                // Anything else is someone using a session they can see to
                // reach other hosts.
                if h.dst != quoted_src {
                    return Err(Verdict::Drop(DropReason::IcmpMismatch));
                }
                let found = self.sessions.lookup(&key);
                if !allow_new && found.is_none() {
                    return Err(Verdict::Drop(DropReason::NoSession));
                }
                if let Some(i) = found {
                    let s = self.sessions.get(i);
                    let (nat, seen) = (s.nat, s.ingress);
                    match nat {
                        // About a translated packet: to the inside host, with
                        // the quoted packet restored to what that host sent.
                        Some(n) if n.xkey == key => {
                            nat::translate_icmp_error(
                                &mut frame[ip.clone()],
                                n.orig_addr,
                                n.orig_port,
                            );
                            h.dst = n.orig_addr;
                        }
                        // About the inside host's own, untranslated packet:
                        // only something between that host and us saw it, so
                        // it comes in where the host's packets do...
                        Some(_) if seen[Dir::Forward as usize] != Some(at) => {
                            return Err(Verdict::Drop(DropReason::SessionMismatch));
                        }
                        // ...and leaves translated, like the session.
                        Some(n) => {
                            nat::translate_icmp_error_out(&mut frame[ip.clone()], n.addr, n.port);
                            h.src = n.addr;
                        }
                        // Once both sides are known, it must come from one.
                        None if seen.iter().all(Option::is_some) && !seen.contains(&Some(at)) => {
                            return Err(Verdict::Drop(DropReason::SessionMismatch));
                        }
                        None => {}
                    }
                }
                Ok((self.route(ingress, frame, off, h)?, None))
            }
            // Non-first fragments carry no ports, so they can't be matched to
            // a session. Forwarded only from ports that may start sessions.
            Flow::Untracked => {
                if !allow_new {
                    return Err(Verdict::Drop(DropReason::NoSession));
                }
                let nh = self.route(ingress, frame, off, h)?;
                // ...and can't be translated either: one that needs source NAT
                // must not leave with the inside address.
                if let NextHop::Ip { port: egress, .. } = nh {
                    let nat = self.nat.decide(&self.ports, ingress, egress, h.src, h.dst);
                    if nat.is_some() {
                        return Err(Verdict::Drop(DropReason::NatUntranslatable));
                    }
                }
                Ok((nh, None))
            }
        }
    }

    /// Anti-spoofing (RFC 3704): a source on one of our connected subnets
    /// must arrive on that subnet's port, and a packet out of a tether must
    /// come from the site the tether leads to.
    fn source_ok(&self, ingress: PortId, via: Option<TetherId>, src: Ipv4Addr) -> bool {
        match via {
            Some(t) => {
                let site = self.overlay.tethers[t as usize].site_idx;
                matches!(self.fib.lookup(src), Some(&NextHop::Site(s)) if s == site)
            }
            None => self
                .ports
                .iter()
                .all(|p| p.id == ingress || !p.subnet.contains(src)),
        }
    }

    /// Is this packet, addressed to one of our own (outside or pool)
    /// addresses, actually a reply belonging to a NATed session?
    fn is_nat_reply(&self, frame: &[u8], off: usize, h: &ipv4::Header) -> bool {
        let key = match flow_of(&frame[off + ETH..off + ETH + h.total_len], h) {
            Ok(Flow::Tracked { key, .. }) | Ok(Flow::Related { key, .. }) => key,
            _ => return false,
        };
        self.sessions
            .lookup(&key)
            .and_then(|i| self.sessions.get(i).nat)
            .is_some_and(|n| n.xkey == key)
    }

    /// Pick a free outside port for a new translation of `addr` towards
    /// `dst:dport`. Keeps the original port when possible (some protocols
    /// care), otherwise searches this worker's share of 1024-65535. A port
    /// only has to be unique per destination, so the same outside port can
    /// serve many sessions at once.
    fn alloc_nat(
        &self,
        proto: u8,
        addr: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
    ) -> Option<(u16, FlowKey)> {
        let icmp = proto == ipv4::PROTO_ICMP;
        // ICMP echo's identifier is both "ports"; other protocols have none.
        let key = |p: u16| FlowKey::new(addr, p, dst, if icmp { p } else { dport }, proto).0;
        let free = |p: u16| self.sessions.lookup(&key(p)).is_none();
        if !matches!(proto, ipv4::PROTO_TCP | ipv4::PROTO_UDP) && !icmp {
            return free(0).then(|| (0, key(0)));
        }
        let (w, id) = (self.workers as u32, self.worker_id as u32);
        if (icmp || sport >= 1024) && sport as u32 % w == id && free(sport) {
            return Some((sport, key(sport)));
        }
        let slots = (65536 - 1024) / w;
        let start = (u32::from(dst) ^ sport as u32).wrapping_mul(0x9e37_79b1) % slots;
        (0..slots.min(8192))
            .map(|i| 1024 + ((start + i) % slots) * w + id)
            .filter(|&p| p <= 65535)
            .map(|p| p as u16)
            .find(|&p| free(p))
            .map(|p| (p, key(p)))
    }

    /// FIB lookup; on a miss, answer with ICMP Net Unreachable.
    fn route(
        &mut self,
        ingress: PortId,
        frame: &mut [u8],
        off: usize,
        h: &ipv4::Header,
    ) -> Result<NextHop, Verdict> {
        match self.fib.lookup(h.dst) {
            Some(&nh) => Ok(nh),
            None => Err(self.icmp_error(
                ingress,
                frame,
                off,
                h,
                icmp::DEST_UNREACHABLE,
                icmp::CODE_NET_UNREACHABLE,
                0,
                DropReason::NoRoute,
            )),
        }
    }

    /// The largest TCP MSS a SYN on this path may announce: the smallest of
    /// the ingress and egress ports' MSS adjust and, through a tether, what
    /// fits in the overlay MTU. `None`: no limit.
    fn mss_limit(&self, ingress: PortId, nh: NextHop, from_tether: bool) -> Option<u16> {
        let egress = match nh {
            NextHop::Ip { port, .. } => self.ports[port as usize].mss_adjust,
            NextHop::Site(_) => None,
        };
        let tether = if from_tether || matches!(nh, NextHop::Site(_)) {
            Some(self.overlay.mtu - 40)
        } else {
            None
        };
        [self.ports[ingress as usize].mss_adjust, egress, tether]
            .into_iter()
            .flatten()
            .min()
    }

    /// Is this UDP datagram tether traffic? Either to our overlay port, or
    /// from a peer's overlay port: a peer that learned our address (we have
    /// no fixed one, e.g. behind NAT) replies to whichever port we sent
    /// from, and from its overlay port, so a NAT along the way lets it in.
    fn is_overlay(&self, ingress: PortId, src: Ipv4Addr, udp: &[u8]) -> bool {
        let (sport, dport) = (
            u16::from_be_bytes([udp[0], udp[1]]),
            u16::from_be_bytes([udp[2], udp[3]]),
        );
        let port = self.overlay.udp_port;
        dport == port
            || (sport == port
                && self
                    .overlay
                    .tethers
                    .iter()
                    .any(|t| t.port == ingress && t.remote == src))
    }

    /// Packets addressed to the router: ping, and overlay tether traffic.
    /// Everything else will later be punted to the control plane.
    fn local(
        &mut self,
        ingress: PortId,
        frame: &mut [u8],
        off: usize,
        len: usize,
        h: &ipv4::Header,
        via: Option<TetherId>,
    ) -> Verdict {
        let l4 = off + ETH + h.hdr_len;
        if h.proto == ipv4::PROTO_UDP
            && self.overlay.enabled()
            && len >= ETH + h.hdr_len + l4::UDP_HDR_LEN
            && self.is_overlay(ingress, h.src, &frame[l4..l4 + 4])
        {
            // A tether packet inside a tether packet is never legitimate.
            if via.is_some() {
                return Verdict::Drop(DropReason::BadOverlay);
            }
            return self.overlay_rx(ingress, frame, off, len, h);
        }
        let is_echo = h.proto == ipv4::PROTO_ICMP
            && len >= ETH + h.hdr_len + icmp::HDR_LEN
            && frame[l4] == icmp::ECHO_REQUEST
            && checksum::checksum(&frame[l4..off + len]) == 0;
        if !is_echo {
            return Verdict::Drop(DropReason::LocalUnhandled);
        }
        if !self.take_icmp_token() {
            return Verdict::Drop(DropReason::IcmpRateLimited);
        }
        // Swap addresses, reset TTL. Options (if any) are kept; we redo the
        // full header checksum since several fields changed.
        let ip = &mut frame[off + ETH..];
        ip[12..16].copy_from_slice(&h.dst.octets());
        ip[16..20].copy_from_slice(&h.src.octets());
        ip[8] = LOCAL_TTL;
        ip[10..12].fill(0);
        let c = checksum::checksum(&ip[..h.hdr_len]);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        icmp::echo_request_to_reply(&mut frame[l4..off + len]);
        self.output(frame, off, len, h.src)
    }

    /// Build an ICMP error about the packet in the frame, in place, and send
    /// it back towards the packet's source. `rest` fills bytes 4-7 of the
    /// ICMP header (the next-hop MTU for Fragmentation Needed).
    #[allow(clippy::too_many_arguments)]
    fn icmp_error(
        &mut self,
        ingress: PortId,
        frame: &mut [u8],
        off: usize,
        h: &ipv4::Header,
        typ: u8,
        code: u8,
        rest: u32,
        reason: DropReason,
    ) -> Verdict {
        let buf = &mut frame[off..];
        // RFC 1812 4.3.2.7: never send an error about an ICMP error, and only
        // about the first fragment of a packet.
        if h.proto == ipv4::PROTO_ICMP {
            let t = buf.get(ETH + h.hdr_len).copied().unwrap_or(0xff);
            if t != icmp::ECHO_REQUEST && t != icmp::ECHO_REPLY {
                return Verdict::Drop(reason);
            }
        }
        let frag_offset = u16::from_be_bytes([buf[ETH + 6], buf[ETH + 7]]) & 0x1fff;
        if frag_offset != 0 {
            return Verdict::Drop(reason);
        }
        // Quote: original IP header + first 8 bytes of payload.
        let quote = h.total_len.min(h.hdr_len + icmp::ERROR_QUOTE_PAYLOAD);
        let new_ip_len = ipv4::MIN_HDR_LEN + icmp::HDR_LEN + quote;
        if ETH + new_ip_len > buf.len() {
            return Verdict::Drop(reason);
        }
        // The original packet is dropped either way; `reason` is counted once
        // here or by `process`. The ICMP we send instead may fail on its own
        // (rate limit, ARP miss), which bumps a second counter.
        if !self.take_icmp_token() {
            self.stats.drop(DropReason::IcmpRateLimited);
            if self.tracer.on(TraceCat::Icmp) {
                let flow = trace::flow_of_frame(&frame[off..off + ETH + h.total_len]);
                let kind = TraceKind::Drop(DropReason::IcmpRateLimited);
                self.tracer
                    .record(self.now_ns, TraceCat::Icmp, kind, ingress, flow);
            }
            return Verdict::Drop(reason);
        }
        // The packet is dropped (traced under its reason's category), and
        // an ICMP error goes back instead (traced under icmp).
        if self.tracer.cfg.mask != 0 {
            let flow = trace::flow_of_frame(&frame[off..off + ETH + h.total_len]);
            if let Some(cat) = TraceCat::of_drop(reason) {
                self.tracer
                    .record(self.now_ns, cat, TraceKind::Drop(reason), ingress, flow);
            }
            let kind = TraceKind::IcmpSent { kind: typ, code };
            self.tracer
                .record(self.now_ns, TraceCat::Icmp, kind, ingress, flow);
        }
        let buf = &mut frame[off..];
        let quote_dst = ETH + ipv4::MIN_HDR_LEN + icmp::HDR_LEN;
        buf.copy_within(ETH..ETH + quote, quote_dst);
        icmp::write_error(
            &mut buf[ETH + ipv4::MIN_HDR_LEN..],
            icmp::HDR_LEN + quote,
            typ,
            code,
            rest,
        );
        self.ip_ident = self.ip_ident.wrapping_add(1);
        let src = self.ports[ingress as usize].addr;
        ipv4::write_header(
            &mut buf[ETH..],
            new_ip_len as u16,
            self.ip_ident,
            LOCAL_TTL,
            ipv4::PROTO_ICMP,
            src,
            h.src,
        );
        self.stats.drop(reason);
        self.output(frame, off, ETH + new_ip_len, h.src)
    }

    /// Route a packet the router itself originated. No TTL decrement: we're
    /// the source.
    fn output(&mut self, frame: &mut [u8], off: usize, len: usize, dst: Ipv4Addr) -> Verdict {
        let Some(&nh) = self.fib.lookup(dst) else {
            return Verdict::Drop(DropReason::NoRoute);
        };
        self.deliver(frame, off, len, nh, None, false)
    }

    /// Hand an IP packet (with room for an Ethernet header at `off`) to its
    /// next hop: a neighbour on a local port, or a tether to another site.
    fn deliver(
        &mut self,
        frame: &mut [u8],
        off: usize,
        len: usize,
        nh: NextHop,
        session: Option<u32>,
        forwarded: bool,
    ) -> Verdict {
        let verdict = match nh {
            NextHop::Ip { port, gateway } => {
                let ip = &frame[off + ETH..];
                let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
                let neighbor_ip = gateway.unwrap_or(dst);
                let Some(mac) = self.neighbor(port, neighbor_ip) else {
                    // Keep it simple: drop the packet and ARP. Linux instead
                    // queues a few packets per neighbour until the reply arrives.
                    self.resolve(port, neighbor_ip);
                    return Verdict::Drop(DropReason::NeighborMiss);
                };
                eth::write(
                    &mut frame[off..],
                    mac,
                    self.ports[port as usize].mac,
                    eth::TYPE_IPV4,
                );
                Verdict::Tx { port, off, len }
            }
            NextHop::Site(site_idx) => {
                let class = match session {
                    Some(i) => self.sessions.get(i).class,
                    None => self.packet_class(&frame[off + ETH..off + len]),
                };
                let Some(tether) = self.pick_tether(site_idx, class, session) else {
                    return Verdict::Drop(DropReason::NoPath);
                };
                self.encap(frame, off, len, tether, class)
            }
        };
        if let Verdict::Tx { .. } = verdict {
            if forwarded {
                self.stats.forwarded += 1;
            } else {
                self.stats.originated += 1;
            }
        }
        verdict
    }

    // ------------------------------------------------------------ overlay

    /// Class of a packet without a session (originated, ICMP errors...).
    fn packet_class(&self, ip: &[u8]) -> u8 {
        let hl = ((ip[0] & 0x0f) as usize) * 4;
        let proto = ip[9];
        let dport = match proto {
            ipv4::PROTO_TCP | ipv4::PROTO_UDP if ip.len() >= hl + 4 => {
                u16::from_be_bytes([ip[hl + 2], ip[hl + 3]])
            }
            _ => 0,
        };
        self.overlay.classify(proto, dport, ip[1] >> 2)
    }

    /// Which tether this packet uses: the session's (sticky until the path
    /// table changes), else the path table's choice for its site and class.
    fn pick_tether(
        &mut self,
        site_idx: usize,
        class: u8,
        session: Option<u32>,
    ) -> Option<TetherId> {
        let gen = self.paths.gen;
        if let Some(i) = session {
            let s = self.sessions.get(i);
            if s.path_gen == gen && s.tether.is_some() {
                return s.tether;
            }
        }
        let t = self.paths.get(site_idx, class)?;
        if let Some(i) = session {
            let s = self.sessions.get_mut(i);
            s.tether = Some(t);
            s.path_gen = gen;
        }
        Some(t)
    }

    /// Wrap the IP packet at `off + ETH` in Ethernet/IPv4/UDP/Ephemeris headers
    /// for `tether`, encrypted. The headers go into the headroom in front of
    /// the packet and the tag after it, so the packet itself doesn't move.
    fn encap(
        &mut self,
        frame: &mut [u8],
        off: usize,
        len: usize,
        tether: TetherId,
        class: u8,
    ) -> Verdict {
        let inner = len - ETH;
        let new_off = if off + ETH >= OUTER_LEN {
            off + ETH - OUTER_LEN
        } else {
            // Not enough headroom (unusual): move the packet back instead.
            if OUTER_LEN + inner + TAG_LEN > frame.len() {
                return Verdict::Drop(DropReason::TooBig);
            }
            frame.copy_within(off + ETH..off + len, OUTER_LEN);
            0
        };
        if new_off + OUTER_LEN + inner + TAG_LEN > frame.len() {
            return Verdict::Drop(DropReason::TooBig);
        }
        let Some((port, remote, dport, neighbor_ip)) = self.tether_dest(tether) else {
            return Verdict::Drop(DropReason::NoPath); // peer not heard from yet
        };
        let Some(mac) = self.neighbor(port, neighbor_ip) else {
            self.resolve(port, neighbor_ip);
            return Verdict::Drop(DropReason::NeighborMiss);
        };
        // Vary the outer source port by flow, so multi-queue NICs and ECMP
        // routers along the path spread tethers traffic like normal traffic.
        // The hash is symmetric: both directions of a flow get the same port.
        // ...except towards a peer whose address we learned: it may be behind
        // NAT, which only lets replies in from the port it sent to.
        let sport = if self.overlay.tethers[tether as usize]
            .remote
            .is_unspecified()
        {
            self.overlay.udp_port
        } else {
            49152
                | (flow_hash(&frame[new_off + OUTER_LEN..new_off + OUTER_LEN + inner]) & 0x3fff)
                    as u16
        };
        let Some(total) = self.write_outer(
            &mut frame[new_off..],
            port,
            remote,
            mac,
            (sport, dport),
            overlay::TYPE_DATA,
            class,
            tether,
            inner,
        ) else {
            return Verdict::Drop(DropReason::NoPath);
        };
        let st = &mut self.tether_stats[tether as usize];
        st.tx_packets += 1;
        st.tx_bytes += inner as u64;
        Verdict::Tx {
            port,
            off: new_off,
            len: total,
        }
    }

    /// Where a tether's packets go: (port, remote address, remote UDP port,
    /// next hop to ARP for). `None` for a peer without a fixed address that
    /// hasn't been heard from yet.
    fn tether_dest(&self, tether: TetherId) -> Option<(PortId, Ipv4Addr, u16, Ipv4Addr)> {
        let t = &self.overlay.tethers[tether as usize];
        let (remote, dport) = if t.remote.is_unspecified() {
            self.endpoints.get(tether)?
        } else {
            (t.remote, self.overlay.udp_port)
        };
        let p = &self.ports[t.port as usize];
        // Explicit gateway; else the peer itself if it's on this link; else
        // the link's gateway (configured, or from DHCP).
        let next_hop = t
            .gateway
            .or_else(|| (!p.reaches(remote)).then_some(p.gateway).flatten())
            .unwrap_or(remote);
        Some((t.port, remote, dport, next_hop))
    }

    /// Write Ethernet + IPv4 + UDP + Ephemeris headers at the start of `buf`,
    /// in front of `payload_len` bytes that are already in place, then
    /// encrypt the payload and append the tag. Returns the frame length, or
    /// `None` if the tether has no key or this run's packet numbers are used
    /// up (a nonce must never repeat).
    #[allow(clippy::too_many_arguments)]
    fn write_outer(
        &mut self,
        buf: &mut [u8],
        port: PortId,
        remote: Ipv4Addr,
        mac: Mac,
        (sport, dport): (u16, u16),
        typ: u8,
        class: u8,
        tether: TetherId,
        payload_len: usize,
    ) -> Option<usize> {
        let key = self.overlay.tethers[tether as usize].key?;
        if self.tx_counter >= overlay::COUNTER_LIMIT {
            return None;
        }
        let counter = (self.overlay_run as u64) << 48 | self.tx_counter;
        self.tx_counter += 1;
        let p = &self.ports[port as usize];
        eth::write(buf, mac, p.mac, eth::TYPE_IPV4);
        self.ip_ident = self.ip_ident.wrapping_add(1);
        let udp_len = l4::UDP_HDR_LEN + overlay::HDR_LEN + payload_len + TAG_LEN;
        ipv4::write_header(
            &mut buf[ETH..],
            (ipv4::MIN_HDR_LEN + udp_len) as u16,
            self.ip_ident,
            LOCAL_TTL,
            ipv4::PROTO_UDP,
            p.addr,
            remote,
        );
        let u = ETH + ipv4::MIN_HDR_LEN;
        buf[u..u + 2].copy_from_slice(&sport.to_be_bytes());
        buf[u + 2..u + 4].copy_from_slice(&dport.to_be_bytes());
        buf[u + 4..u + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        buf[u + 6..u + 8].fill(0); // UDP checksum is optional over IPv4 (the AEAD covers us)
        let mut hdr = [0u8; overlay::HDR_LEN];
        hdr[0] = (overlay::VERSION << 4) | typ;
        hdr[1] = class;
        hdr[2..4].copy_from_slice(&self.overlay.site_id.to_be_bytes());
        hdr[4..6].copy_from_slice(&tether.to_be_bytes());
        hdr[6] = self.worker_id as u8;
        hdr[8..16].copy_from_slice(&counter.to_be_bytes());
        let r = u + l4::UDP_HDR_LEN;
        buf[r..r + overlay::HDR_LEN].copy_from_slice(&hdr);
        let body = r + overlay::HDR_LEN;
        let tag = key.seal(&hdr, &mut buf[body..body + payload_len]);
        buf[body + payload_len..body + payload_len + TAG_LEN].copy_from_slice(&tag);
        Some(body + payload_len + TAG_LEN)
    }

    /// An overlay packet addressed to us: data to decapsulate, or a probe.
    fn overlay_rx(
        &mut self,
        ingress: PortId,
        frame: &mut [u8],
        off: usize,
        len: usize,
        h: &ipv4::Header,
    ) -> Verdict {
        // We never send IP options, so neither does a real peer.
        if h.hdr_len != ipv4::MIN_HDR_LEN || len < OUTER_LEN + TAG_LEN {
            return Verdict::Drop(DropReason::BadOverlay);
        }
        // Which tether: the one to this sender's address, or else the one
        // to a peer without a fixed address whose site id the header claims
        // (the claim is checked when the packet is authenticated below).
        let claimed = u16::from_be_bytes([
            frame[off + OUTER_LEN - overlay::HDR_LEN + 2],
            frame[off + OUTER_LEN - overlay::HDR_LEN + 3],
        ]);
        let tethers = &self.overlay.tethers;
        let Some(tether) = tethers
            .iter()
            .position(|t| t.port == ingress && t.remote == h.src)
            .or_else(|| {
                tethers.iter().position(|t| {
                    t.port == ingress && t.remote.is_unspecified() && t.peer_site == claimed
                })
            })
        else {
            return Verdict::Drop(DropReason::UnknownTether);
        };
        let dynamic = tethers[tether].remote.is_unspecified();
        let t = &self.overlay.tethers[tether];
        let (peer_site, site_idx) = (t.peer_site, t.site_idx);
        let Some(key) = t.key else {
            return Verdict::Drop(DropReason::OverlayAuth);
        };
        let r = off + OUTER_LEN - overlay::HDR_LEN;
        let hdr: [u8; overlay::HDR_LEN] = frame[r..r + overlay::HDR_LEN].try_into().unwrap();
        let (version, typ) = (hdr[0] >> 4, hdr[0] & 0x0f);
        let site = u16::from_be_bytes([hdr[2], hdr[3]]);
        if version != overlay::VERSION || site != peer_site {
            return Verdict::Drop(DropReason::BadOverlay);
        }
        // Authenticate (and decrypt) before believing anything else in it.
        let body = off + OUTER_LEN..off + len - TAG_LEN;
        let (payload, tag) = frame[..off + len].split_at_mut(body.end);
        if !key.open(&hdr, &mut payload[body.clone()], tag) {
            return Verdict::Drop(DropReason::OverlayAuth);
        }
        let counter = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
        if !self.replay.accept(site_idx, hdr[6], counter) {
            return Verdict::Drop(DropReason::OverlayReplay);
        }
        let tid = tether as TetherId;
        if dynamic {
            // Authentic and fresh: the peer is (now) at this address/port.
            let u = off + ETH + ipv4::MIN_HDR_LEN;
            let sport = u16::from_be_bytes([frame[u], frame[u + 1]]);
            self.endpoints.learn(tid, h.src, sport);
        }
        let inner = body.len();
        match typ {
            overlay::TYPE_DATA => {
                let st = &mut self.tether_stats[tether];
                st.rx_packets += 1;
                st.rx_bytes += inner as u64;
                // The inner packet becomes a frame of its own: its (fake)
                // Ethernet header starts 14 bytes before the inner IP header.
                let new_off = off + OUTER_LEN - ETH;
                self.ipv4(ingress, frame, new_off, ETH + inner, Some(tid))
            }
            overlay::TYPE_PROBE if inner == overlay::PROBE_LEN => {
                // Echo it straight back, in place, to whoever sent it.
                let mac = eth::src(&frame[off..]);
                let u = off + ETH + ipv4::MIN_HDR_LEN;
                let sport = u16::from_be_bytes([frame[u], frame[u + 1]]);
                let dport = u16::from_be_bytes([frame[u + 2], frame[u + 3]]);
                let Some(total) = self.write_outer(
                    &mut frame[off..],
                    ingress,
                    h.src,
                    mac,
                    (dport, sport),
                    overlay::TYPE_PROBE_REPLY,
                    0,
                    tid,
                    overlay::PROBE_LEN,
                ) else {
                    return Verdict::Drop(DropReason::OverlayControl);
                };
                self.stats.originated += 1;
                Verdict::Tx {
                    port: ingress,
                    off,
                    len: total,
                }
            }
            overlay::TYPE_PROBE_REPLY if inner == overlay::PROBE_LEN => {
                let p = off + OUTER_LEN;
                let sent = u64::from_be_bytes(frame[p + 4..p + 12].try_into().unwrap());
                let rtt = self.now_ns.saturating_sub(sent);
                self.tether_stats[tether].record_rtt(rtt, self.now_ns);
                Verdict::Drop(DropReason::OverlayControl)
            }
            _ => Verdict::Drop(DropReason::BadOverlay),
        }
    }

    /// One probe per tether: sequence number + our clock. Every worker shares
    /// the same clock origin, so whichever worker receives the reply can
    /// compute the round-trip time.
    fn send_probes(&mut self) {
        self.probe_seq = self.probe_seq.wrapping_add(1);
        for i in 0..self.overlay.tethers.len() {
            let t = &self.overlay.tethers[i];
            if t.key.is_none() {
                continue; // no key: the tether stays down
            }
            let Some((port, remote, dport, neighbor_ip)) = self.tether_dest(i as TetherId) else {
                continue; // peer not heard from yet: it will probe us
            };
            let Some(mac) = self.neighbor(port, neighbor_ip) else {
                self.resolve(port, neighbor_ip);
                continue;
            };
            let mut e = Emit {
                port,
                len: 0,
                frame: [0; EMIT_MAX],
            };
            e.frame[OUTER_LEN..OUTER_LEN + 4].copy_from_slice(&self.probe_seq.to_be_bytes());
            e.frame[OUTER_LEN + 4..OUTER_LEN + 12].copy_from_slice(&self.now_ns.to_be_bytes());
            let udp = self.overlay.udp_port;
            let Some(total) = self.write_outer(
                &mut e.frame,
                port,
                remote,
                mac,
                (udp, dport),
                overlay::TYPE_PROBE,
                0,
                i as TetherId,
                overlay::PROBE_LEN,
            ) else {
                continue;
            };
            e.len = total;
            self.push_emit(e);
            self.tether_stats[i].probes_sent += 1;
            self.stats.originated += 1;
        }
    }

    /// Token bucket: refill at ICMP_RATE_PER_SEC, cap at ICMP_BURST.
    fn take_icmp_token(&mut self) -> bool {
        let elapsed = self.now_ns.saturating_sub(self.icmp_last_refill);
        let new = elapsed / ICMP_TOKEN_NS;
        if new > 0 {
            self.icmp_tokens = (self.icmp_tokens + new).min(ICMP_BURST);
            self.icmp_last_refill += new * ICMP_TOKEN_NS;
        }
        if self.icmp_tokens == 0 {
            return false;
        }
        self.icmp_tokens -= 1;
        true
    }
}

/// Where packets to `nh` leave, as the session table names ingresses.
fn egress_of(nh: NextHop) -> PortId {
    match nh {
        NextHop::Ip { port, .. } => port,
        NextHop::Site(_) => OVERLAY_INGRESS,
    }
}

/// Symmetric flow hash of an IP packet's addresses, protocol and ports:
/// A→B and B→A hash the same (XOR doesn't care about order).
fn flow_hash(ip: &[u8]) -> u32 {
    let hl = ((ip[0] & 0x0f) as usize) * 4;
    let rd32 = |o: usize| u32::from_be_bytes([ip[o], ip[o + 1], ip[o + 2], ip[o + 3]]);
    let mut x = rd32(12) ^ rd32(16) ^ ip[9] as u32;
    if matches!(ip[9], ipv4::PROTO_TCP | ipv4::PROTO_UDP) && ip.len() >= hl + 4 {
        x ^= u16::from_be_bytes([ip[hl], ip[hl + 1]]) as u32
            ^ u16::from_be_bytes([ip[hl + 2], ip[hl + 3]]) as u32;
    }
    x.wrapping_mul(0x9e37_79b1) >> 16
}

/// If this is a TCP SYN (or SYN-ACK) announcing an MSS above `max`, lower it
/// to `max` and patch the TCP checksum (RFC 1624 again). A SYN without an MSS
/// option is left alone, like other routers do. `ip` is exactly the IP packet.
fn clamp_mss(ip: &mut [u8], h: &ipv4::Header, max: u16) {
    // A later fragment's payload isn't a TCP header, whatever it looks like.
    if ipv4::frag_word(ip) & ipv4::FRAG_OFFSET_MASK != 0 {
        return;
    }
    let tcp = &mut ip[h.hdr_len..];
    if tcp.len() < l4::TCP_MIN_HDR_LEN || tcp[13] & l4::TCP_SYN == 0 {
        return;
    }
    let doff = ((tcp[12] >> 4) as usize * 4).min(tcp.len());
    let mut i = l4::TCP_MIN_HDR_LEN;
    while i + 1 < doff {
        match tcp[i] {
            0 => return, // end of options
            1 => i += 1, // no-op padding
            2 if tcp[i + 1] == 4 && i + 4 <= doff => {
                let old = u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]);
                if old > max {
                    tcp[i + 2..i + 4].copy_from_slice(&max.to_be_bytes());
                    // The checksum sums 16-bit words from the start of the
                    // header. At an odd offset the value straddles two words,
                    // contributing its bytes swapped (the sum is linear).
                    let (old, new) = if i.is_multiple_of(2) {
                        (old, max)
                    } else {
                        (old.swap_bytes(), max.swap_bytes())
                    };
                    let hc = u16::from_be_bytes([tcp[16], tcp[17]]);
                    tcp[16..18].copy_from_slice(&checksum::update16(hc, old, new).to_be_bytes());
                }
                return;
            }
            _ => {
                let l = tcp[i + 1] as usize;
                if l < 2 {
                    return;
                }
                i += l;
            }
        }
    }
}

/// What the session layer makes of a packet.
enum Flow {
    Tracked {
        key: FlowKey,
        lo_to_hi: bool,
        /// TCP only.
        tcp: Option<TcpSegment>,
    },
    Related {
        key: FlowKey,
        /// Source of the quoted packet: who the error is for.
        quoted_src: Ipv4Addr,
    },
    Untracked,
}

/// Extract the session key from an IPv4 packet (`ip` = exactly the packet).
fn flow_of(ip: &[u8], h: &ipv4::Header) -> Result<Flow, Verdict> {
    let frag_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    if frag_offset != 0 {
        return Ok(Flow::Untracked);
    }
    let l4 = &ip[h.hdr_len..];
    let short = || Verdict::Drop(DropReason::BadL4Header);
    let (sport, dport, tcp) = match h.proto {
        ipv4::PROTO_TCP => {
            if l4.len() < l4::TCP_MIN_HDR_LEN {
                return Err(short());
            }
            let (s, d) = l4::ports(l4);
            let flags = l4::tcp_flags(l4);
            let (seq, ack, win) = l4::tcp_seq_ack_win(l4);
            let seg = TcpSegment {
                flags,
                seq,
                ack,
                win,
                len: (l4.len() - l4::tcp_header_len(l4)) as u32,
                wscale: if flags & l4::TCP_SYN != 0 {
                    l4::tcp_window_scale(l4)
                } else {
                    None
                },
            };
            (s, d, Some(seg))
        }
        ipv4::PROTO_UDP => {
            if l4.len() < l4::UDP_HDR_LEN {
                return Err(short());
            }
            let (s, d) = l4::ports(l4);
            (s, d, None)
        }
        ipv4::PROTO_ICMP => {
            if l4.len() < icmp::HDR_LEN {
                return Err(short());
            }
            match l4[0] {
                // Echo request and reply carry the same identifier, which
                // plays the role of a port in both directions.
                icmp::ECHO_REQUEST | icmp::ECHO_REPLY => {
                    let id = u16::from_be_bytes([l4[4], l4[5]]);
                    (id, id, None)
                }
                icmp::DEST_UNREACHABLE | icmp::TIME_EXCEEDED => {
                    return Ok(related_key(&l4[icmp::HDR_LEN..]).map_or(
                        Flow::Untracked,
                        |(key, quoted_src)| Flow::Related { key, quoted_src },
                    ));
                }
                _ => (0, 0, None),
            }
        }
        _ => (0, 0, None),
    };
    let (key, lo_to_hi) = FlowKey::new(h.src, sport, h.dst, dport, h.proto);
    Ok(Flow::Tracked { key, lo_to_hi, tcp })
}

/// The session an ICMP error refers to, and the quoted packet's source,
/// from the packet it quotes.
fn related_key(quoted: &[u8]) -> Option<(FlowKey, Ipv4Addr)> {
    if quoted.len() < ipv4::MIN_HDR_LEN || quoted[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((quoted[0] & 0x0f) as usize) * 4;
    if ihl < ipv4::MIN_HDR_LEN {
        return None;
    }
    let inner = quoted.get(ihl..ihl + 8)?;
    let proto = quoted[9];
    let src = Ipv4Addr::new(quoted[12], quoted[13], quoted[14], quoted[15]);
    let dst = Ipv4Addr::new(quoted[16], quoted[17], quoted[18], quoted[19]);
    let (sp, dp) = match proto {
        ipv4::PROTO_TCP | ipv4::PROTO_UDP => l4::ports(inner),
        ipv4::PROTO_ICMP if inner[0] == icmp::ECHO_REQUEST || inner[0] == icmp::ECHO_REPLY => {
            let id = u16::from_be_bytes([inner[4], inner[5]]);
            (id, id)
        }
        _ => (0, 0),
    };
    Some((FlowKey::new(src, sp, dst, dp, proto).0, src))
}

/// The smallest MTU of any port (a PPPoE session's own MTU while it's up).
fn min_mtu(ports: &[Port]) -> usize {
    ports
        .iter()
        .map(|p| p.ip_mtu() as usize)
        .min()
        .unwrap_or(1500)
}

/// The ports on one network card: which one an arriving frame belongs to.
#[derive(Debug, Clone, Default)]
struct CardPorts {
    /// The port for untagged (and priority-tagged, VLAN 0) frames.
    untagged: Option<PortId>,
    /// (VLAN ID, port). A handful at most, so a scan beats a hash.
    tagged: Vec<(u16, PortId)>,
}

fn card_ports(ports: &[Port]) -> Vec<CardPorts> {
    let n = ports.iter().map(|p| p.card as usize + 1).max().unwrap_or(0);
    let mut cards = vec![CardPorts::default(); n];
    for p in ports {
        let c = &mut cards[p.card as usize];
        match p.vlan {
            None => c.untagged = Some(p.id),
            Some(vid) => c.tagged.push((vid, p.id)),
        }
    }
    cards
}

/// Make `n` bytes of room in front of the `len`-byte frame at `off`: there
/// already is in a received frame (the driver's headroom); otherwise move the
/// frame back. Returns the frame's (possibly new) offset, or `None` if the
/// buffer can't hold it.
#[inline]
fn make_room(buf: &mut [u8], off: usize, len: usize, n: usize) -> Option<usize> {
    if off >= n {
        return Some(off);
    }
    if off + len + n > buf.len() {
        return None;
    }
    buf.copy_within(off..off + len, off + n);
    Some(off + n)
}
