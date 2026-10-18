//! A data-plane worker: one thread, one CPU core, one RX queue per interface.
//!
//! The loop is "run to completion": each packet is received, fully processed
//! and queued for transmission by the same thread, in batches of up to
//! [`BATCH`]. Nothing is shared with other workers except neighbour updates,
//! which arrive as messages.

use crate::report::{Control, KernelStats, Report, SessionView};
use eph_dataplane::{DropReason, Pipeline, PortId, Verdict};
use eph_xdp::{Umem, XdpDesc, Xsk};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
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
/// Sessions sampled per worker per report (for the API and logs).
const SESSION_SAMPLE: usize = 1024;

pub struct Worker {
    pub id: usize,
    // Field order matters: sockets must be dropped before the UMEM they use.
    pub socks: Vec<Xsk>,
    pub umem: Umem,
    pub pipeline: Pipeline,
    /// Neighbour updates from sibling workers and changes from the control plane.
    pub control: Receiver<Control>,
    /// Sibling workers' control channels, for sharing learned neighbours.
    pub siblings: Vec<Sender<Control>>,
    pub report: Arc<Mutex<Report>>,
    pub busy_poll: bool,
    pub cpu: Option<usize>,
}

impl Worker {
    pub fn run(mut self, stop: &AtomicBool, epoch: Instant) {
        if let Some(cpu) = self.cpu {
            pin_to_cpu(cpu);
        }
        // Every frame starts in our free list; then we hand some to each
        // interface's fill ring so the NIC has somewhere to put packets.
        let mut free: Vec<u64> = (0..self.umem.frames())
            .map(|i| self.umem.frame_addr(i))
            .collect();
        let nports = self.socks.len();
        let mut tx_pending = vec![false; nports];
        let mut idle = 0u32;
        let mut last_report = Instant::now();
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

        while !stop.load(Ordering::Relaxed) {
            let now_ns = epoch.elapsed().as_nanos() as u64;
            self.pipeline.set_time(now_ns);
            self.pipeline.housekeeping();
            while let Ok(msg) = self.control.try_recv() {
                match msg {
                    Control::Neighbor(n) => self.pipeline.learn(n),
                    Control::SetFib(fib) => self.pipeline.set_fib(fib),
                    Control::SetPorts(ports) => self.pipeline.set_ports(ports),
                    Control::SetPaths(paths) => self.pipeline.set_paths(paths),
                    Control::SetNat(nat) => self.pipeline.set_nat(nat),
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
            for rx_port in 0..nports {
                let mut count = 0;
                while count < BATCH {
                    match self.socks[rx_port].rx.pop() {
                        Some(d) => {
                            batch[count] = d;
                            count += 1;
                        }
                        None => break,
                    }
                }
                if count == 0 {
                    self.socks[rx_port].kick_rx();
                    continue;
                }
                self.socks[rx_port].rx.release();
                work += count;

                for d in &batch[..count] {
                    // The pipeline gets the whole 4 KiB frame plus the packet's
                    // offset in it: the space before the packet is headroom,
                    // where SD-WAN encapsulation prepends its headers.
                    let base = self.umem.frame_base(d.addr);
                    let off = (d.addr - base) as usize;
                    // SAFETY: the kernel handed this frame to us via the RX
                    // ring; nothing else references it until we give it away.
                    let frame = unsafe { self.umem.frame_mut(base) };
                    match self
                        .pipeline
                        .process(rx_port as PortId, frame, off, d.len as usize)
                    {
                        Verdict::Tx { port, off, len } => {
                            // Zero-copy forwarding: the *same frame* goes onto
                            // the egress port's TX ring.
                            let desc = XdpDesc {
                                addr: base + off as u64,
                                len: len as u32,
                                options: 0,
                            };
                            if self.socks[port as usize].tx.push(desc) {
                                tx_pending[port as usize] = true;
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
            for e in self.pipeline.emits.drain(..) {
                let Some(addr) = free.pop() else { break };
                let buf = unsafe { self.umem.frame_mut(addr) };
                buf[..e.len].copy_from_slice(&e.frame[..e.len]);
                let s = &mut self.socks[e.port as usize];
                if s.tx.push(XdpDesc {
                    addr,
                    len: e.len as u32,
                    options: 0,
                }) {
                    tx_pending[e.port as usize] = true;
                } else {
                    free.push(addr);
                }
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

            if last_report.elapsed() >= REPORT_EVERY {
                last_report = Instant::now();
                self.publish(now_ns);
            }

            // 7. Nothing to do? Spin a little (cheap, lowest latency), then
            //    sleep in poll() so an idle router doesn't burn a core.
            if work == 0 {
                idle += 1;
                if !self.busy_poll && idle >= IDLE_SPINS {
                    idle = 0;
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
        self.publish(epoch.elapsed().as_nanos() as u64);
    }

    fn publish(&self, now_ns: u64) {
        // try_lock: a worker never waits on the stats reader.
        if let Ok(mut r) = self.report.try_lock() {
            r.stats = self.pipeline.stats.clone();
            r.neighbors = self.pipeline.neighbors().collect();
            let mut k = KernelStats::default();
            for s in &self.socks {
                let x = s.statistics().unwrap_or_default();
                k.rx_dropped += x.rx_dropped + x.rx_ring_full + x.rx_invalid_descs;
                k.fill_empty += x.rx_fill_ring_empty_descs;
            }
            r.kernel = k;
            r.tethers.clear();
            r.tethers.extend_from_slice(self.pipeline.tether_stats());
            r.sessions.clear();
            r.sessions.extend(
                self.pipeline
                    .sessions()
                    .iter()
                    .take(SESSION_SAMPLE)
                    .map(|s| SessionView {
                        session: s.clone(),
                        now_ns,
                    }),
            );
        }
    }
}

fn pin_to_cpu(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            tracing::warn!(
                "could not pin worker to CPU {cpu}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}
