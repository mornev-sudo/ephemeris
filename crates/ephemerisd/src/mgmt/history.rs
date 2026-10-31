//! Traffic history for the Reporting graphs: every [`INTERVAL_SECS`] the
//! counters the workers publish become rates (packets/s, bits/s, drops/s),
//! and [`KEEP`] samples (an hour) are kept in memory.
//!
//! Sampling is a handful of additions every few seconds, so it runs whether
//! or not anyone is looking; a page that opens the Reporting tab then has
//! the last hour straight away.

use super::Summary;
use serde::Serialize;
use std::collections::VecDeque;

pub const INTERVAL_SECS: u64 = 5;
/// One hour of samples.
pub const KEEP: usize = 3600 / INTERVAL_SECS as usize;

/// One point on the graphs. Rates are averages over the interval before
/// `t` (Unix seconds).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Sample {
    pub t: u64,
    pub sessions: u64,
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub drops_per_sec: f64,
    pub drops_total: u64,
    /// Per interface, in port order.
    pub ports: Vec<PortRate>,
    /// The machine: all CPUs (0-100) and memory in use (bytes).
    pub cpu_pct: f64,
    pub mem_used: u64,
    pub mem_total: u64,
    /// ephemerisd's CPU (100 = one core) and how busy each worker really
    /// was handling packets (0-100, time-based).
    pub process_cpu_pct: f64,
    pub workers_busy_pct: Vec<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PortRate {
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

/// Counter totals at one moment.
#[derive(Debug, Clone, Default)]
struct Totals {
    at: f64,
    ports: Vec<eph_dataplane::PortCounters>,
    drops: u64,
    busy_ns: Vec<u64>,
}

#[derive(Default)]
pub struct History {
    samples: VecDeque<Sample>,
    last: Option<Totals>,
}

impl History {
    /// Turn the counters now into a sample. `at` is a monotonic time in
    /// seconds, `unix` the wall clock for the graph's time axis.
    pub fn record(
        &mut self,
        at: f64,
        unix: u64,
        s: &Summary,
        sys: Option<&super::sysinfo::Snapshot>,
    ) {
        let now = Totals {
            at,
            ports: s.ports.clone(),
            drops: drops_total(s),
            busy_ns: s.workers.iter().map(|w| w.busy_ns).collect(),
        };
        let Some(prev) = self.last.replace(now.clone()) else {
            return; // rates need two readings
        };
        let dt = now.at - prev.at;
        if dt <= 0.0 {
            return;
        }
        // Counters restart at zero when the data plane does: never negative.
        let rate = |new: u64, old: u64| new.saturating_sub(old) as f64 / dt;
        let ports: Vec<PortRate> = now
            .ports
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let o = prev.ports.get(i).copied().unwrap_or_default();
                PortRate {
                    rx_pps: rate(p.rx_packets, o.rx_packets),
                    tx_pps: rate(p.tx_packets, o.tx_packets),
                    rx_bps: rate(p.rx_bytes, o.rx_bytes) * 8.0,
                    tx_bps: rate(p.tx_bytes, o.tx_bytes) * 8.0,
                }
            })
            .collect();
        let sum = |f: fn(&PortRate) -> f64| ports.iter().map(f).sum::<f64>();
        let workers_busy_pct = now
            .busy_ns
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let p = prev.busy_ns.get(i).copied().unwrap_or(b);
                (b.saturating_sub(p) as f64 / (dt * 1e9) * 100.0).min(100.0)
            })
            .collect();
        self.samples.push_back(Sample {
            t: unix,
            sessions: s.sessions_active,
            rx_pps: sum(|p| p.rx_pps),
            tx_pps: sum(|p| p.tx_pps),
            rx_bps: sum(|p| p.rx_bps),
            tx_bps: sum(|p| p.tx_bps),
            drops_per_sec: rate(now.drops, prev.drops),
            drops_total: now.drops,
            ports,
            cpu_pct: sys.map_or(0.0, |x| x.cpu_pct),
            mem_used: sys.map_or(0, |x| x.memory.used),
            mem_total: sys.map_or(0, |x| x.memory.total),
            process_cpu_pct: sys.map_or(0.0, |x| x.process_cpu_pct),
            workers_busy_pct,
        });
        while self.samples.len() > KEEP {
            self.samples.pop_front();
        }
    }

    /// Samples from the last `secs` seconds (by their timestamps).
    pub fn since(&self, secs: u64) -> Vec<Sample> {
        let newest = self.samples.back().map_or(0, |s| s.t);
        self.samples
            .iter()
            .filter(|s| s.t.saturating_add(secs) >= newest)
            .cloned()
            .collect()
    }

    /// The samples newer than `t`, oldest first.
    pub fn after(&self, t: u64) -> Vec<Sample> {
        self.samples.iter().filter(|s| s.t > t).cloned().collect()
    }

    pub fn latest(&self) -> Option<&Sample> {
        self.samples.back()
    }
}

/// The dropped-packet counter the dashboard has always shown: every packet
/// the data plane didn't send on, plus what the kernel dropped before we
/// saw it.
pub fn drops_total(s: &Summary) -> u64 {
    s.drops.values().sum::<u64>() + s.kernel_drops
}

#[cfg(test)]
mod tests {
    use super::*;
    use eph_dataplane::PortCounters;

    fn summary(rx_pkts: u64, rx_bytes: u64, drops: u64, sessions: u64) -> Summary {
        let mut s = Summary {
            sessions_active: sessions,
            ports: vec![
                PortCounters {
                    rx_packets: rx_pkts,
                    rx_bytes,
                    tx_packets: rx_pkts / 2,
                    tx_bytes: rx_bytes / 2,
                },
                PortCounters::default(),
            ],
            ..Default::default()
        };
        s.drops.insert("no-route", drops);
        s
    }

    #[test]
    fn counters_become_rates() {
        let mut h = History::default();
        h.record(0.0, 1000, &summary(0, 0, 0, 0), None);
        assert!(h.latest().is_none(), "one reading isn't a rate yet");
        h.record(5.0, 1005, &summary(5000, 625_000, 50, 12), None);
        let s = h.latest().unwrap();
        assert_eq!(s.t, 1005);
        assert_eq!(s.sessions, 12);
        assert_eq!(s.rx_pps, 1000.0);
        assert_eq!(s.tx_pps, 500.0);
        assert_eq!(s.rx_bps, 1_000_000.0, "625 kB in 5 s = 1 Mbit/s");
        assert_eq!(s.drops_per_sec, 10.0);
        assert_eq!(s.drops_total, 50);
        assert_eq!(s.ports[0].rx_bps, 1_000_000.0);
        assert_eq!(s.ports[1].rx_bps, 0.0);
    }

    #[test]
    fn worker_busy_time_becomes_a_percentage() {
        let mut h = History::default();
        let mut s = summary(0, 0, 0, 0);
        s.workers = vec![Default::default(), Default::default()];
        h.record(0.0, 0, &s, None);
        s.workers[0].busy_ns = 2_500_000_000; // 2.5 s of 5 s
        s.workers[1].busy_ns = 50_000_000;
        h.record(5.0, 5, &s, None);
        assert_eq!(h.latest().unwrap().workers_busy_pct, vec![50.0, 1.0]);
    }

    #[test]
    fn a_restart_never_gives_negative_rates() {
        let mut h = History::default();
        h.record(0.0, 0, &summary(1_000_000, 1_000_000, 100, 5), None);
        h.record(5.0, 5, &summary(10, 10, 0, 5), None);
        let s = h.latest().unwrap();
        assert_eq!((s.rx_pps, s.drops_per_sec), (0.0, 0.0));
    }

    #[test]
    fn keeps_an_hour() {
        let mut h = History::default();
        for i in 0..(KEEP as u64 + 50) {
            h.record(i as f64 * 5.0, i * 5, &summary(i, i, 0, 0), None);
        }
        assert_eq!(h.since(u64::MAX).len(), KEEP);
        assert_eq!(
            h.since(60).len(),
            13,
            "the last minute: 12 intervals + the newest"
        );
    }
}
