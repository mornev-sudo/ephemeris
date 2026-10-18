//! The SD-WAN control loop. Twice a second:
//!
//! 1. merge every worker's per-tether probe results,
//! 2. judge each tether: up or down, latency, jitter, loss,
//! 3. run [`select_paths`] (which tether for each site and application class),
//! 4. if any decision changed, publish a new path table to the workers.
//!
//! The data plane never makes these decisions itself: it only measures (the
//! probes) and obeys (the path table). That split, measure in the fast path,
//! decide in the slow path, is the essence of SD-WAN.

use eph_dataplane::overlay::{
    select_paths, Overlay, PathTable, TetherHealth, TetherStats, DOWN_AFTER_NS,
};
use std::collections::VecDeque;
use std::sync::Arc;

pub const TICK_MS: u64 = 500;
/// Loss is measured over this many ticks (5 s).
const LOSS_WINDOW: usize = 10;

pub struct PathSelector {
    overlay: Arc<Overlay>,
    /// Per tether: (probes sent, replies received) at each tick.
    history: Vec<VecDeque<(u64, u64)>>,
    pub table: PathTable,
}

impl PathSelector {
    pub fn new(overlay: Arc<Overlay>) -> Self {
        PathSelector {
            history: vec![VecDeque::new(); overlay.tethers.len()],
            table: PathTable::empty(&overlay),
            overlay,
        }
    }

    /// Health of every tether from the merged statistics.
    pub fn health(&mut self, merged: &[TetherStats], now_ns: u64) -> Vec<TetherHealth> {
        merged
            .iter()
            .zip(&mut self.history)
            .map(|(t, hist)| {
                hist.push_back((t.probes_sent, t.replies));
                if hist.len() > LOSS_WINDOW + 2 {
                    hist.pop_front();
                }
                // Replies trail probes by one round trip, so compare probes
                // sent in a window that ends one tick earlier.
                let loss_pct = if hist.len() >= 3 {
                    let sent = hist[hist.len() - 2].0 - hist[0].0;
                    let got = hist[hist.len() - 1].1 - hist[1].1;
                    if sent > 0 {
                        ((1.0 - got as f32 / sent as f32) * 100.0).clamp(0.0, 100.0)
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };
                TetherHealth {
                    up: t.last_reply_ns > 0
                        && now_ns.saturating_sub(t.last_reply_ns) < DOWN_AFTER_NS,
                    rtt_ns: t.rtt_ns,
                    jitter_ns: t.jitter_ns,
                    loss_pct,
                }
            })
            .collect()
    }

    /// New path table if any decision changed. Also returns human-readable
    /// descriptions of what moved, for the log.
    pub fn decide(&mut self, health: &[TetherHealth]) -> Option<(PathTable, Vec<String>)> {
        let next = select_paths(&self.overlay, health, &self.table);
        if next.gen == self.table.gen {
            return None;
        }
        let name = |t: Option<u16>| {
            t.map_or("none".to_string(), |t| {
                self.overlay.tethers[t as usize].name.clone()
            })
        };
        let mut changes = Vec::new();
        for (site_idx, row) in next.choice.iter().enumerate() {
            for (class, &choice) in row.iter().enumerate() {
                let before = self.table.get(site_idx, class as u8);
                if before != choice {
                    changes.push(format!(
                        "site {} class {}: {} -> {}",
                        self.overlay.sites[site_idx],
                        self.overlay.classes[class].name,
                        name(before),
                        name(choice)
                    ));
                }
            }
        }
        self.table = next.clone();
        Some((next, changes))
    }
}

/// Add up per-worker tether statistics. Counters are summed; the latest
/// measurements come from whichever worker saw the most recent reply.
pub fn merge(per_worker: &[Vec<TetherStats>]) -> Vec<TetherStats> {
    let n = per_worker.iter().map(Vec::len).max().unwrap_or(0);
    (0..n)
        .map(|i| {
            let mut m = TetherStats::default();
            for w in per_worker.iter().filter_map(|w| w.get(i)) {
                m.probes_sent += w.probes_sent;
                m.replies += w.replies;
                m.tx_packets += w.tx_packets;
                m.tx_bytes += w.tx_bytes;
                m.rx_packets += w.rx_packets;
                m.rx_bytes += w.rx_bytes;
                if w.last_reply_ns > m.last_reply_ns {
                    m.last_reply_ns = w.last_reply_ns;
                    m.rtt_ns = w.rtt_ns;
                    m.jitter_ns = w.jitter_ns;
                    m.last_rtt_ns = w.last_rtt_ns;
                }
            }
            m
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use eph_dataplane::overlay::Tether;

    const S: u64 = 1_000_000_000;

    fn overlay() -> Arc<Overlay> {
        let mut o = Overlay::disabled();
        o.site_id = 1;
        o.sites = vec![2];
        for (id, name) in ["fibre", "lte"].iter().enumerate() {
            o.tethers.push(Tether {
                id: id as u16,
                name: name.to_string(),
                port: id as u16 + 1,
                remote: "192.0.2.2".parse().unwrap(),
                gateway: None,
                peer_site: 2,
                site_idx: 0,
                key: None,
            });
        }
        Arc::new(o)
    }

    fn stats(sent: u64, replies: u64, last_reply_ns: u64, rtt_ms: u64) -> TetherStats {
        TetherStats {
            probes_sent: sent,
            replies,
            last_reply_ns,
            rtt_ns: rtt_ms * 1_000_000,
            ..Default::default()
        }
    }

    #[test]
    fn down_after_a_second_without_replies() {
        let mut p = PathSelector::new(overlay());
        let h = p.health(
            &[stats(10, 10, 10 * S, 5), stats(10, 10, 10 * S, 50)],
            10 * S + S / 2,
        );
        assert!(h[0].up && h[1].up);
        let h = p.health(
            &[stats(15, 10, 10 * S, 5), stats(15, 15, 11 * S, 50)],
            11 * S + S / 10,
        );
        assert!(!h[0].up, "1.1 s since the last fibre reply");
        assert!(h[1].up);
    }

    #[test]
    fn loss_is_measured_over_the_window() {
        let mut p = PathSelector::new(overlay());
        let mut h = vec![];
        // 5 probes per tick (200 ms interval, 500 ms ticks ~ 2.5), half answered.
        for tick in 0..12u64 {
            let sent = tick * 5;
            h = p.health(
                &[
                    stats(sent, sent / 2, tick * S / 2, 5),
                    stats(sent, sent, tick * S / 2, 50),
                ],
                tick * S / 2,
            );
        }
        assert!((h[0].loss_pct - 50.0).abs() < 1.0, "{}", h[0].loss_pct);
        assert!(h[1].loss_pct < 1.0);
    }

    #[test]
    fn failover_is_reported_once() {
        let mut p = PathSelector::new(overlay());
        let up = |rtt: u64| TetherHealth {
            up: true,
            rtt_ns: rtt * 1_000_000,
            ..Default::default()
        };
        let (t, changes) = p.decide(&[up(5), up(50)]).unwrap();
        assert_eq!(t.get(0, 0), Some(0));
        assert_eq!(changes, ["site 2 class default: none -> fibre"]);
        assert!(p.decide(&[up(5), up(50)]).is_none(), "nothing changed");
        let (t, changes) = p.decide(&[TetherHealth::default(), up(50)]).unwrap();
        assert_eq!(t.get(0, 0), Some(1));
        assert_eq!(changes, ["site 2 class default: fibre -> lte"]);
    }

    #[test]
    fn merge_sums_counters_and_keeps_latest_rtt() {
        let m = merge(&[vec![stats(10, 4, 5 * S, 5)], vec![stats(0, 5, 6 * S, 7)]]);
        assert_eq!(
            (m[0].probes_sent, m[0].replies, m[0].rtt_ns),
            (10, 9, 7_000_000)
        );
    }
}
