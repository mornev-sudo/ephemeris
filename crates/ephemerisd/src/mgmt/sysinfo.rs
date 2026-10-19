//! The router's own resources: CPU, memory, huge pages, disk, load, and
//! how much CPU each of ephemerisd's threads uses.
//!
//! Everything comes from `/proc` and `statvfs`, read every few seconds by
//! [`Sampler`]. CPU figures are percentages over the interval since the
//! previous reading (the kernel only gives running totals). The parsers are
//! pure functions of the files' text, so they're tested anywhere.

use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

/// Time a CPU (or all of them) spent busy, and in total, in clock ticks.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CpuTimes {
    pub busy: u64,
    pub total: u64,
}

/// `/proc/stat`: the "cpu" line (all CPUs), then "cpu0", "cpu1"...
pub fn parse_proc_stat(text: &str) -> (CpuTimes, Vec<CpuTimes>) {
    let mut all = CpuTimes::default();
    let mut each = vec![];
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let Some(name) = f.next().filter(|n| n.starts_with("cpu")) else {
            continue;
        };
        // user nice system idle iowait irq softirq steal (guest is in user)
        let v: Vec<u64> = f.take(8).filter_map(|x| x.parse().ok()).collect();
        if v.len() < 4 {
            continue;
        }
        let idle = v[3] + v.get(4).copied().unwrap_or(0);
        let total: u64 = v.iter().sum();
        let t = CpuTimes {
            busy: total - idle,
            total,
        };
        if name == "cpu" {
            all = t;
        } else {
            each.push(t);
        }
    }
    (all, each)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Memory {
    pub total: u64,
    pub available: u64,
    pub used: u64,
    pub hugepages_total: u64,
    pub hugepages_free: u64,
    pub hugepage_size: u64,
}

/// `/proc/meminfo` (values in kB, page counts for huge pages) -> bytes.
pub fn parse_meminfo(text: &str) -> Memory {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let (total, available) = (get("MemTotal") * 1024, get("MemAvailable") * 1024);
    Memory {
        total,
        available,
        used: total.saturating_sub(available),
        hugepages_total: get("HugePages_Total"),
        hugepages_free: get("HugePages_Free"),
        hugepage_size: get("Hugepagesize") * 1024,
    }
}

/// `/proc/loadavg`: the 1, 5 and 15 minute averages.
pub fn parse_loadavg(text: &str) -> [f64; 3] {
    let mut f = text.split_whitespace().map(|x| x.parse().unwrap_or(0.0));
    [
        f.next().unwrap_or(0.0),
        f.next().unwrap_or(0.0),
        f.next().unwrap_or(0.0),
    ]
}

/// `/proc/<pid>/task/<tid>/stat`: user + system time in ticks. The thread
/// name (field 2) is in parentheses and may contain spaces, so fields are
/// counted from after the closing one.
pub fn parse_thread_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After the name: state is field 3, utime 14, stime 15 -> index 11, 12.
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// `/proc/self/status`: resident memory, in bytes.
pub fn parse_rss(status: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .map_or(0, |kb| kb * 1024)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Disk {
    pub path: String,
    pub total: u64,
    pub free: u64,
    pub used: u64,
}

pub fn disk(path: &str) -> Option<Disk> {
    use std::ffi::CString;
    let c = CString::new(path).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let block = s.f_frsize as u64;
    let total = s.f_blocks as u64 * block;
    let free = s.f_bavail as u64 * block;
    Some(Disk {
        path: path.into(),
        total,
        free,
        used: total.saturating_sub(s.f_bfree as u64 * block),
    })
}

/// A thread's share of one CPU over the last interval.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ThreadCpu {
    pub name: String,
    pub cpu_pct: f64,
}

/// What one reading turns into.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Snapshot {
    /// All CPUs, 0-100.
    pub cpu_pct: f64,
    pub cpu_each_pct: Vec<f64>,
    pub memory: Memory,
    pub load: [f64; 3],
    pub uptime_secs: u64,
    /// ephemerisd: resident memory and CPU (100 = one whole core).
    pub process_rss: u64,
    pub process_cpu_pct: f64,
    /// Its threads, busiest first, grouped by name (eph-worker-0, ...).
    pub threads: Vec<ThreadCpu>,
    pub disks: Vec<Disk>,
}

/// Keeps the previous readings to turn running totals into percentages.
#[derive(Default)]
pub struct Sampler {
    prev_all: Option<CpuTimes>,
    prev_each: Vec<CpuTimes>,
    prev_threads: HashMap<String, u64>,
    prev_at: Option<f64>,
}

impl Sampler {
    /// Read everything now (`at`: a monotonic time in seconds).
    pub fn sample(&mut self, at: f64, disks: &[&str]) -> Snapshot {
        let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        let (all, each) = parse_proc_stat(&read("/proc/stat"));
        let pct = |now: CpuTimes, prev: Option<CpuTimes>| {
            let Some(p) = prev else { return 0.0 };
            let (b, t) = (
                now.busy.saturating_sub(p.busy),
                now.total.saturating_sub(p.total),
            );
            if t == 0 {
                0.0
            } else {
                100.0 * b as f64 / t as f64
            }
        };
        let cpu_pct = pct(all, self.prev_all);
        let cpu_each_pct = each
            .iter()
            .enumerate()
            .map(|(i, c)| pct(*c, self.prev_each.get(i).copied()))
            .collect();
        self.prev_all = Some(all);
        self.prev_each = each;

        // Threads: ticks per name since the last reading, as % of one core.
        let hz = ticks_per_sec();
        let dt = self.prev_at.map_or(0.0, |p| at - p);
        self.prev_at = Some(at);
        let mut now_threads: HashMap<String, u64> = HashMap::new();
        if let Ok(rd) = std::fs::read_dir("/proc/self/task") {
            for e in rd.flatten() {
                let dir = e.path();
                let name = read(&format!("{}/comm", dir.display())).trim().to_string();
                if let Some(t) = parse_thread_ticks(&read(&format!("{}/stat", dir.display()))) {
                    *now_threads.entry(name).or_default() += t;
                }
            }
        }
        let mut threads: Vec<ThreadCpu> = now_threads
            .iter()
            .map(|(name, &t)| {
                let prev = self.prev_threads.get(name).copied().unwrap_or(t);
                let cpu_pct = if dt > 0.0 {
                    100.0 * t.saturating_sub(prev) as f64 / hz / dt
                } else {
                    0.0
                };
                ThreadCpu {
                    name: name.clone(),
                    cpu_pct,
                }
            })
            .collect();
        threads.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct).then(a.name.cmp(&b.name)));
        self.prev_threads = now_threads;

        Snapshot {
            cpu_pct,
            cpu_each_pct,
            memory: parse_meminfo(&read("/proc/meminfo")),
            load: parse_loadavg(&read("/proc/loadavg")),
            uptime_secs: read("/proc/uptime")
                .split('.')
                .next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0),
            process_rss: parse_rss(&read("/proc/self/status")),
            process_cpu_pct: threads.iter().map(|t| t.cpu_pct).sum(),
            threads,
            disks: disks
                .iter()
                .filter(|p| Path::new(p).exists())
                .filter_map(|p| disk(p))
                .collect(),
        }
    }
}

fn ticks_per_sec() -> f64 {
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 {
        t as f64
    } else {
        100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_stat() {
        let text = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 60 0 30 400 10 0 0 0 0 0\ncpu1 40 0 20 400 40 0 0 0 0 0\nintr 1 2 3\n";
        let (all, each) = parse_proc_stat(text);
        assert_eq!(
            all,
            CpuTimes {
                busy: 150,
                total: 1000
            },
            "iowait counts as idle"
        );
        assert_eq!(each.len(), 2);
        assert_eq!(
            each[0],
            CpuTimes {
                busy: 90,
                total: 500
            }
        );
    }

    #[test]
    fn meminfo_and_load() {
        let text = "MemTotal:        2000000 kB\nMemFree:          100000 kB\nMemAvailable:     500000 kB\nHugePages_Total:      64\nHugePages_Free:       48\nHugepagesize:       2048 kB\n";
        let m = parse_meminfo(text);
        assert_eq!(m.total, 2_048_000_000);
        assert_eq!(m.used, 1_536_000_000);
        assert_eq!(
            (m.hugepages_total, m.hugepages_free, m.hugepage_size),
            (64, 48, 2 * 1024 * 1024)
        );
        assert_eq!(
            parse_loadavg("0.52 0.40 0.31 2/180 1234\n"),
            [0.52, 0.40, 0.31]
        );
    }

    #[test]
    fn thread_stat_with_a_space_in_the_name() {
        // pid (comm) state ppid ... utime=14 stime=15
        let stat = "123 (eph worker 0) S 1 123 123 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 1 0";
        assert_eq!(parse_thread_ticks(stat), Some(300));
        assert_eq!(parse_rss("Name:\tx\nVmRSS:\t  51200 kB\n"), 51200 * 1024);
    }

    #[test]
    fn disk_space_of_a_real_path() {
        let d = disk("/").expect("statvfs on /");
        assert!(d.total > 0 && d.free <= d.total && d.used <= d.total);
    }
}
