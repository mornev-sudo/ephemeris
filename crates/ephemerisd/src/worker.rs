//! A data-plane worker: one thread, one CPU core, one RX queue per network
//! card. (VLAN interfaces share their card's queue; the pipeline tells them
//! apart by their tag.)
//!
//! The loop is "run to completion": each packet is received, fully processed
//! and queued for transmission by the same thread, in batches of up to
//! [`BATCH`]. Nothing is shared with other workers except neighbour updates,
//! which arrive as messages.

use crate::report::{
    unix_ms, Control, DetailWanted, KernelStats, Report, SessionView, SESSION_DETAIL,
};
use eph_dataplane::{DropReason, Pipeline, PortId, Punt, Verdict};
use eph_packet::eth;
use eph_xdp::{Umem, XdpDesc, Xsk};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Packets taken from one RX ring per loop iteration. Batching amortises the
/// fixed costs (ring index loads, the TX kick syscall) over many packets.
const BATCH: usize = 64;
/// Empty loop iterations before falling back to sleeping in poll().
const IDLE_SPINS: u32 = 1000;
const IDLE_POLL_MS: i32 = 10;
// Often enough that SD-WAN failover (which reads tether probe results from
// these reports) reacts within about a second.
const REPORT_EVERY: Duration = Duration::from_millis(250);
/// Session and neighbour lists, while someone looks: at most once a second.
const DETAIL_EVERY: Duration = Duration::from_secs(1);
/// "N trace events not logged": at most this often.
const SUPPRESSED_EVERY: Duration = Duration::from_secs(10);

pub struct Worker {
    pub id: usize,
    // Field order matters: sockets must be dropped before the UMEM they use.
    /// One socket per network card, in the order of [`Port::card`].
    ///
    /// [`Port::card`]: eph_dataplane::Port::card
    pub socks: Vec<Xsk>,
    pub umem: Umem,
    pub pipeline: Pipeline,
    /// Neighbour updates from sibling workers and changes from the control plane.
    pub control: Receiver<Control>,
    /// Sibling workers' control channels, for sharing learned neighbours.
    pub siblings: Vec<Sender<Control>>,
    pub report: Arc<Mutex<Report>>,
    /// Where DHCP / PPPoE packets for the control plane go (bounded: a
    /// flood is dropped here, not queued without end).
    pub punt: SyncSender<Punt>,
    /// Until when (Unix ms) someone wants the session and neighbour lists.
    pub detail: DetailWanted,
    /// Where packets for the router's own SSH and portal go (the host
    /// path); `None` if it isn't running.
    pub host: Option<SyncSender<Vec<u8>>>,
    pub busy_poll: bool,
    pub cpu: Option<usize>,
}

impl Worker {
    pub fn run(mut self, stop: &AtomicBool, epoch: Instant) {
        if let Some(cpu) = self.cpu {
            pin_to_cpu(cpu);
        }
        // Every frame starts in our free list; then we hand some to each
        // card's fill ring so the NIC has somewhere to put packets.
        let mut free: Vec<u64> = (0..self.umem.frames())
            .map(|i| self.umem.frame_addr(i))
            .collect();
        let ncards = self.socks.len();
        let mut tx_pending = vec![false; ncards];
        let mut idle = 0u32;
        let mut last_report = Instant::now();
        // Busy time: a round that handled packets counts from its start to
        // the next round's start.
        let mut busy_ns = 0u64;
        let mut round_start = 0u64;
        let mut round_busy = false;
        let mut last_detail = Instant::now()
            .checked_sub(DETAIL_EVERY)
            .unwrap_or_else(Instant::now);
        let mut pollfds: Vec<libc::pollfd> = self
            .socks
            .iter()
            .map(|s| libc::pollfd {
                fd: s.fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let mut batch = [XdpDesc::default(); BATCH];
        let mut last_suppressed = Instant::now();
        // Frames the control plane asked us to send.
        let mut outbox: Vec<(PortId, Vec<u8>)> = Vec::new();
        // Replies from the router's own SSH and portal.
        let mut host_in: Vec<Vec<u8>> = Vec::new();

        while !stop.load(Ordering::Relaxed) {
            let now_ns = epoch.elapsed().as_nanos() as u64;
            if round_busy {
                busy_ns += now_ns.saturating_sub(round_start);
            }
            round_start = now_ns;
            self.pipeline.set_time(now_ns);
            self.pipeline.housekeeping();
            while let Ok(msg) = self.control.try_recv() {
                match msg {
                    Control::Neighbor(n) => self.pipeline.learn(n),
                    Control::SetFib(fib) => self.pipeline.set_fib(fib),
                    Control::SetPorts(ports) => self.pipeline.set_ports(ports),
                    Control::SetPaths(paths) => self.pipeline.set_paths(paths),
                    Control::SetNat(nat) => self.pipeline.set_nat(nat),
                    Control::SetTrace(t) => self.pipeline.set_trace(t),
                    Control::Transmit { port, frame } => outbox.push((port, frame)),
                    Control::InjectHost(p) => host_in.push(p),
                }
            }
            let mut work = 0usize;

            // 1. Frames the NIC finished transmitting come back to us.
            for s in &mut self.socks {
                while let Some(addr) = s.comp.pop() {
                    free.push(self.umem.frame_base(addr));
                    work += 1;
                }
                s.comp.release();
            }

            // 2. Keep every fill ring topped up.
            for s in &mut self.socks {
                let n = (s.fill.free() as usize).min(free.len());
                for _ in 0..n {
                    s.fill.push(free.pop().unwrap());
                }
                if n > 0 {
                    s.fill.commit();
                }
            }

            // 3. Receive and process.
            for rx_card in 0..ncards {
                let mut count = 0;
                while count < BATCH {
                    match self.socks[rx_card].rx.pop() {
                        Some(d) => {
                            batch[count] = d;
                            count += 1;
                        }
                        None => break,
                    }
                }
                if count == 0 {
                    self.socks[rx_card].kick_rx();
                    continue;
                }
                self.socks[rx_card].rx.release();
                work += count;

                for d in &batch[..count] {
                    // The pipeline gets the whole 4 KiB frame plus the packet's
                    // offset in it: the space before the packet is headroom,
                    // where SD-WAN encapsulation prepends its headers.
                    let base = self.umem.frame_base(d.addr);
                    let off = (d.addr - base) as usize;
                    // SAFETY: the kernel handed this frame to us via the RX
                    // ring; nothing else references it until we give it
                    // away (TX ring or free list), and `frame` ends before.
                    let frame = unsafe { self.umem.frame_mut(base) };
                    match self
                        .pipeline
                        .process(rx_card as u16, frame, off, d.len as usize)
                    {
                        Verdict::Tx { port, off, len } => {
                            // Zero-copy forwarding: the *same frame* goes onto
                            // the egress card's TX ring.
                            let desc = XdpDesc {
                                addr: base + off as u64,
                                len: len as u32,
                                options: 0,
                            };
                            let card = self.pipeline.card_of(port);
                            if self.socks[card].tx.push(desc) {
                                tx_pending[card] = true;
                                self.pipeline.stats.sent(port, len);
                            } else {
                                self.pipeline.stats.drop(DropReason::TxRingFull);
                                free.push(base);
                            }
                        }
                        Verdict::Drop(_) => free.push(base),
                    }
                }
            }

            // 4. Frames the router generated itself (ARP requests, overlay probes).
            let mut emits = std::mem::take(&mut self.pipeline.emits);
            for e in emits.drain(..) {
                let Some(addr) = free.pop() else { break };
                // SAFETY: frames on the free list belong to this worker alone;
                // `buf` ends before the frame goes onto a TX ring.
                let buf = unsafe { self.umem.frame_mut(addr) };
                buf[..e.len].copy_from_slice(&e.frame[..e.len]);
                let card = self.pipeline.card_of(e.port);
                if self.socks[card].tx.push(XdpDesc {
                    addr,
                    len: e.len as u32,
                    options: 0,
                }) {
                    tx_pending[card] = true;
                    self.pipeline.stats.sent(e.port, e.len);
                } else {
                    free.push(addr);
                }
            }
            self.pipeline.emits = emits; // keep its capacity

            // ...and frames from the control plane (DHCP, PPPoE), tagged
            // here for a VLAN interface (room for the tag left in front).
            for (port, frame) in outbox.drain(..) {
                let Some(addr) = free.pop() else { break };
                // SAFETY: as above, a frame from this worker's free list.
                let buf = unsafe { self.umem.frame_mut(addr) };
                const ROOM: usize = eth::VLAN_TAG_LEN;
                if ROOM + frame.len() > buf.len() || port as usize >= self.pipeline.ports().len() {
                    free.push(addr);
                    continue;
                }
                buf[ROOM..ROOM + frame.len()].copy_from_slice(&frame);
                let Some((off, len)) = self.pipeline.tag_for(port, buf, ROOM, frame.len()) else {
                    free.push(addr);
                    continue;
                };
                let card = self.pipeline.card_of(port);
                if self.socks[card].tx.push(XdpDesc {
                    addr: addr + off as u64,
                    len: len as u32,
                    options: 0,
                }) {
                    tx_pending[card] = true;
                    self.pipeline.stats.originated += 1;
                    self.pipeline.stats.sent(port, len);
                } else {
                    free.push(addr);
                }
            }
            // ...and replies from the router's own SSH and portal, given the
            // interface's address and routed back out (inside ports only).
            for p in host_in.drain(..) {
                let Some(addr) = free.pop() else { break };
                // SAFETY: a frame from this worker's free list; `buf` ends
                // before the frame goes onto a TX ring.
                let buf = unsafe { self.umem.frame_mut(addr) };
                const HEAD: usize = 128; // room for Ethernet, a VLAN tag, PPPoE
                if HEAD + eth::HDR_LEN + p.len() > buf.len() {
                    free.push(addr);
                    continue;
                }
                buf[HEAD + eth::HDR_LEN..HEAD + eth::HDR_LEN + p.len()].copy_from_slice(&p);
                match self.pipeline.inject_host(buf, HEAD, eth::HDR_LEN + p.len()) {
                    Verdict::Tx { port, off, len } => {
                        let card = self.pipeline.card_of(port);
                        if self.socks[card].tx.push(XdpDesc {
                            addr: addr + off as u64,
                            len: len as u32,
                            options: 0,
                        }) {
                            tx_pending[card] = true;
                            self.pipeline.stats.sent(port, len);
                        } else {
                            self.pipeline.stats.drop(DropReason::TxRingFull);
                            free.push(addr);
                        }
                    }
                    Verdict::Drop(_) => free.push(addr),
                }
            }
            // ...and packets for the router's own SSH and portal go to the
            // host path (bounded: a flood is dropped and counted here).
            for p in self.pipeline.host_out.drain(..) {
                let sent = self.host.as_ref().is_some_and(|h| h.try_send(p).is_ok());
                if !sent {
                    self.pipeline.stats.drop(DropReason::ControlQueueFull);
                }
            }
            // ...and packets for the control plane go to it.
            for p in self.pipeline.punts.drain(..) {
                // Full (the control plane is behind, e.g. a DHCP flood):
                // drop it here rather than queue without end.
                if self.punt.try_send(p).is_err() {
                    self.pipeline.stats.drop(DropReason::ControlQueueFull);
                }
            }

            // ...and packet trace events become log lines (only while a
            // packet category is at debug; rate-limited by the pipeline).
            if !self.pipeline.tracer.events.is_empty() {
                let ports = self.pipeline.ports().clone();
                for ev in self.pipeline.tracer.events.drain(..) {
                    crate::logging::dataplane::emit(&ev, &ports, self.id);
                }
            }
            if self.pipeline.tracer.suppressed > 0 && last_suppressed.elapsed() >= SUPPRESSED_EVERY
            {
                last_suppressed = Instant::now();
                let n = std::mem::take(&mut self.pipeline.tracer.suppressed);
                tracing::info!(
                    target: "dataplane",
                    worker = self.id,
                    "packet trace: {n} event(s) over the limit of {}/s were not logged",
                    self.pipeline.tracer.cfg.per_sec
                );
            }

            // 5. Tell sibling workers about neighbours we learned.
            for n in self.pipeline.learned.drain(..) {
                for tx in &self.siblings {
                    let _ = tx.send(Control::Neighbor(n));
                }
            }

            // 6. Publish TX descriptors and kick the kernel. In copy mode the
            //    kernel only sends a limited batch per kick, so keep kicking
            //    while anything is outstanding.
            for (i, s) in self.socks.iter_mut().enumerate() {
                if tx_pending[i] {
                    s.tx.commit();
                    tx_pending[i] = false;
                    s.kick_tx();
                } else if !s.zero_copy && s.tx.outstanding() > 0 {
                    s.kick_tx();
                }
            }

            round_busy = work > 0;
            if last_report.elapsed() >= REPORT_EVERY {
                last_report = Instant::now();
                let wanted = unix_ms() < self.detail.load(Ordering::Relaxed);
                let detail = wanted && last_detail.elapsed() >= DETAIL_EVERY;
                if detail {
                    last_detail = Instant::now();
                }
                self.publish(now_ns, busy_ns, detail, wanted);
            }

            // 7. Nothing to do? Spin a little (cheap, lowest latency), then
            //    sleep in poll() so an idle router doesn't burn a core.
            if work == 0 {
                idle += 1;
                if !self.busy_poll && idle >= IDLE_SPINS {
                    idle = 0;
                    // SAFETY: `pollfds` is a live Vec and the count passed is
                    // its length; the kernel writes only `revents` in it.
                    unsafe {
                        libc::poll(
                            pollfds.as_mut_ptr(),
                            pollfds.len() as libc::nfds_t,
                            IDLE_POLL_MS,
                        )
                    };
                }
            } else {
                idle = 0;
            }
        }
        self.publish(epoch.elapsed().as_nanos() as u64, busy_ns, false, false);
    }

    /// Publish counters (always) and, when `detail`, the newest sessions and
    /// the neighbour list. When nobody wants them (`!wanted`) those lists are
    /// dropped, so a busy worker never spends time copying them for no one.
    fn publish(&self, now_ns: u64, busy_ns: u64, detail: bool, wanted: bool) {
        // try_lock: a worker never waits on the stats reader.
        if let Ok(mut r) = self.report.try_lock() {
            r.stats = self.pipeline.stats.clone();
            r.busy_ns = busy_ns;
            r.sessions_max = self.pipeline.sessions().capacity() as u64;
            r.nat_active = self.pipeline.sessions().nat_active;
            r.neighbor_count = self.pipeline.neighbor_count() as u64;
            let mut k = KernelStats::default();
            for s in &self.socks {
                let x = s.statistics().unwrap_or_default();
                k.rx_dropped += x.rx_dropped + x.rx_ring_full + x.rx_invalid_descs;
                k.fill_empty += x.rx_fill_ring_empty_descs;
            }
            r.kernel = k;
            r.tethers.clear();
            r.tethers.extend_from_slice(self.pipeline.tether_stats());
            if detail {
                r.neighbors = self.pipeline.neighbors().collect();
                r.sessions = newest_sessions(&self.pipeline, now_ns);
                r.detail_ms = unix_ms();
            } else if !wanted && r.detail_ms != 0 {
                r.neighbors = Vec::new(); // free the memory, not just the contents
                r.sessions = Vec::new();
                r.detail_ms = 0;
            }
        }
    }
}

/// The [`SESSION_DETAIL`] most recently created sessions, newest first:
/// one pass with a small heap, copying only the ones kept.
fn newest_sessions(p: &Pipeline, now_ns: u64) -> Vec<SessionView> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::with_capacity(SESSION_DETAIL + 1);
    for (i, s) in p.sessions().iter().enumerate() {
        heap.push(Reverse((s.created_ns, i)));
        if heap.len() > SESSION_DETAIL {
            heap.pop(); // drop the oldest
        }
    }
    let keep: std::collections::HashSet<usize> = heap.iter().map(|Reverse((_, i))| *i).collect();
    let mut out: Vec<SessionView> = p
        .sessions()
        .iter()
        .enumerate()
        .filter(|(i, _)| keep.contains(i))
        .map(|(_, s)| SessionView {
            session: s.clone(),
            now_ns,
        })
        .collect();
    out.sort_by_key(|v| Reverse(v.session.created_ns));
    out
}

fn pin_to_cpu(cpu: usize) {
    // cpu_set_t holds CPUs 0..CPU_SETSIZE; CPU_SET panics past that (the
    // config refuses such numbers; this keeps the worker alive regardless).
    if cpu >= libc::CPU_SETSIZE as usize {
        tracing::warn!(target: crate::logging::cat::DATAPLANE, "can't pin a worker to CPU {cpu}: too high");
        return;
    }
    // SAFETY: cpu_set_t is a plain bit array; all zeros is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `cpu` is below CPU_SETSIZE (checked above), so the bit is
    // inside `set`.
    unsafe { libc::CPU_SET(cpu, &mut set) };
    // SAFETY: `set` is a live cpu_set_t and the size passed is its size; 0
    // means the calling thread.
    let r = unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
    if r != 0 {
        tracing::warn!(target: crate::logging::cat::DATAPLANE,
            "could not pin worker to CPU {cpu}: {}",
            std::io::Error::last_os_error()
        );
    }
}
