//! What the data plane reserves at start, and whether the machine has it.
//!
//! Three big tables are allocated before the first packet, so the fast path
//! never allocates:
//!
//! - **packet buffers** (UMEM): per worker, enough 4 KiB frames to fill
//!   every card's fill and TX rings;
//! - **session tables**: per worker, `sessions.max_per_worker` sessions
//!   ([`SessionTable::reserved_bytes`]);
//! - **the forwarding table** (DIR-24-8): shared, 32 MiB plus 512 bytes per
//!   /24 holding longer routes.
//!
//! [`plan`] adds them up against the memory the machine has free at start,
//! sizes the session tables when `max_per_worker = "auto"`, and refuses a
//! plan that can't fit. Pure arithmetic on numbers from `/proc/meminfo`, so
//! it's tested anywhere.

use crate::config::{Config, SessionsMax};
use crate::mgmt::sysinfo::Memory;
use anyhow::{bail, Result};
use eph_dataplane::session::SessionTable;

/// UMEM frame size: one page per packet buffer.
pub const FRAME_SIZE: u32 = 4096;
/// Kept free for everything else: the OS, nginx, management, DHCP, logs.
pub const HEADROOM: u64 = 256 << 20;
/// With `"auto"`, the session tables get this share of what's left once
/// the packet buffers, the forwarding table and [`HEADROOM`] are set aside.
/// Not all of it: the page cache and the management plane need some, and
/// most routers never come near a full table.
const AUTO_SHARE: (u64, u64) = (1, 2);
/// `"auto"` never goes below or above these, per worker.
pub const AUTO_MIN: u32 = 16_384;
pub const SESSIONS_MAX: u32 = 16_000_000;
/// `"auto"` without knowing the machine's memory (`--check` on a laptop).
pub const AUTO_FALLBACK: u32 = 262_144;
/// Huge pages, as Linux reserves them for UMEM.
const HUGE_PAGE: u64 = 2 << 20;

/// Packet buffers per worker: enough to fill every card's fill ring and TX
/// ring, rounded to a whole number of 2 MiB huge pages (512 frames).
pub fn umem_frames(cards: usize, ring: u32) -> u32 {
    (cards as u32 * ring * 2).div_ceil(512) * 512
}

/// What the data plane will reserve, all workers together.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub workers: u32,
    pub sessions_per_worker: u32,
    /// `sessions_per_worker` was sized from memory (`"auto"`).
    pub auto: bool,
    pub packet_buffers: u64,
    /// The part of `packet_buffers` that fits in free huge pages, which
    /// don't count as available memory (the kernel keeps them apart).
    pub on_huge_pages: u64,
    pub session_tables: u64,
    pub forwarding_table: u64,
    /// The machine's available memory at start, if known.
    pub available: Option<u64>,
    /// Said once at start, if the plan only just fits.
    pub warning: Option<String>,
}

impl Plan {
    /// What comes out of ordinary (non-huge-page) memory.
    pub fn ordinary_memory(&self) -> u64 {
        self.packet_buffers - self.on_huge_pages + self.session_tables + self.forwarding_table
    }
}

fn mib(b: u64) -> String {
    format!("{} MiB", b.div_ceil(1 << 20))
}

/// Size and check the data plane's tables for `cfg` on a machine with
/// `mem` (`None`: unknown, nothing is checked). `fib_bytes` is the built
/// forwarding table's size.
pub fn plan(cfg: &Config, fib_bytes: u64, mem: Option<&Memory>) -> Result<Plan> {
    let workers = cfg.dataplane.workers;
    let umem_per_worker =
        umem_frames(cfg.cards().len(), cfg.dataplane.ring_size) as u64 * FRAME_SIZE as u64;
    let packet_buffers = umem_per_worker * workers as u64;
    // Each worker's UMEM is one allocation: on huge pages only if it fits
    // in what's free, worker by worker.
    let on_huge_pages = mem.map_or(0, |m| {
        if m.hugepage_size != HUGE_PAGE {
            return 0;
        }
        let free = m.hugepages_free * m.hugepage_size;
        (free / umem_per_worker).min(workers as u64) * umem_per_worker
    });
    let fixed = packet_buffers - on_huge_pages + fib_bytes;
    let available = mem.map(|m| m.available);

    let (sessions_per_worker, auto) = match cfg.sessions.max_per_worker {
        SessionsMax::Fixed(n) => (n, false),
        SessionsMax::Auto => match available {
            None => (AUTO_FALLBACK, true),
            Some(avail) => {
                let spare = avail.saturating_sub(fixed + HEADROOM);
                let share = spare / AUTO_SHARE.1 * AUTO_SHARE.0 / workers as u64;
                let n = SessionTable::max_for_bytes(share).min(SESSIONS_MAX);
                if n < AUTO_MIN {
                    bail!(
                        "not enough memory for the session tables: {} available, {} for packet \
                         buffers and the forwarding table, {} kept for the system, leaves room for \
                         only {n} sessions per worker (at least {AUTO_MIN}). Use fewer workers, or \
                         give the router more memory.",
                        mib(avail),
                        mib(fixed),
                        mib(HEADROOM)
                    );
                }
                (n, true)
            }
        },
    };
    let mut p = Plan {
        workers,
        sessions_per_worker,
        auto,
        packet_buffers,
        on_huge_pages,
        session_tables: SessionTable::reserved_bytes(sessions_per_worker) * workers as u64,
        forwarding_table: fib_bytes,
        available,
        warning: None,
    };
    if let Some(avail) = available {
        let need = p.ordinary_memory();
        let parts = format!(
            "packet buffers {}{}, session tables {} ({} per worker x {workers}), forwarding table {}",
            mib(p.packet_buffers),
            if p.on_huge_pages > 0 {
                format!(" ({} on huge pages)", mib(p.on_huge_pages))
            } else {
                String::new()
            },
            mib(p.session_tables),
            p.sessions_per_worker,
            mib(p.forwarding_table)
        );
        if need > avail {
            bail!(
                "the data plane needs {} but only {} is available ({parts}). Lower \
                 sessions.max_per_worker (or set it to \"auto\"), use fewer workers or a smaller \
                 ring_size, or give the router more memory.",
                mib(need),
                mib(avail)
            );
        }
        if need + HEADROOM > avail {
            p.warning = Some(format!(
                "the data plane reserves {} of the {} available ({parts}), leaving less than {} \
                 for everything else: the router may run out of memory under load",
                mib(need),
                mib(avail),
                mib(HEADROOM)
            ));
        }
    }
    Ok(p)
}

/// This machine's memory now, from `/proc/meminfo` (`None` elsewhere).
pub fn machine() -> Option<Memory> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let m = crate::mgmt::sysinfo::parse_meminfo(&text);
    (m.total > 0).then_some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const FIB: u64 = 32 << 20;

    fn cfg(max: &str, workers: u32) -> Config {
        Config::parse(&format!(
            "[dataplane]\nworkers = {workers}\n[sessions]\nmax_per_worker = {max}\n\
             [[interface]]\nname = \"lan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\n\
             [[interface]]\nname = \"wan\"\ndevice = \"eth2\"\naddress = \"10.0.1.1/24\"\n"
        ))
        .unwrap()
    }

    fn mem(available: u64, huge_free: u64) -> Memory {
        Memory {
            total: available + GIB / 2,
            available,
            used: GIB / 2,
            hugepages_total: huge_free,
            hugepages_free: huge_free,
            hugepage_size: HUGE_PAGE,
        }
    }

    #[test]
    fn auto_takes_half_of_what_is_left_per_worker() {
        let p = plan(&cfg("\"auto\"", 1), FIB, Some(&mem(2 * GIB, 0))).unwrap();
        assert!(p.auto);
        // Two cards, ring 2048: 8192 frames, 32 MiB of packet buffers.
        assert_eq!(p.packet_buffers, 32 << 20);
        let left = 2 * GIB - (32 << 20) - FIB - HEADROOM;
        assert!(p.session_tables <= left / 2);
        assert!(
            p.session_tables > left / 2 - (1 << 20) * 64,
            "most of the half"
        );
        assert!(p.warning.is_none());
        // Twice the workers: each gets about half as many.
        let p2 = plan(&cfg("\"auto\"", 2), FIB, Some(&mem(2 * GIB, 0))).unwrap();
        assert!(p2.sessions_per_worker < p.sessions_per_worker * 6 / 10);
        // Unknown machine: the old default.
        let p3 = plan(&cfg("\"auto\"", 1), FIB, None).unwrap();
        assert_eq!(p3.sessions_per_worker, AUTO_FALLBACK);
        // Lots of memory: capped.
        let p4 = plan(&cfg("\"auto\"", 1), FIB, Some(&mem(64 * GIB, 0))).unwrap();
        assert_eq!(p4.sessions_per_worker, SESSIONS_MAX);
    }

    #[test]
    fn auto_refuses_when_hardly_anything_is_left() {
        let e = plan(&cfg("\"auto\"", 4), FIB, Some(&mem(400 << 20, 0))).unwrap_err();
        assert!(
            e.to_string()
                .contains("not enough memory for the session tables"),
            "{e}"
        );
    }

    #[test]
    fn a_fixed_size_that_does_not_fit_is_refused_and_a_tight_one_warned() {
        let e = plan(&cfg("16000000", 1), FIB, Some(&mem(2 * GIB, 0))).unwrap_err();
        let e = e.to_string();
        assert!(
            e.contains("the data plane needs") && e.contains("only 2048 MiB is available"),
            "{e}"
        );
        assert!(plan(&cfg("262144", 1), FIB, Some(&mem(2 * GIB, 0)))
            .unwrap()
            .warning
            .is_none());
        // 80 MB of sessions + 64 MiB fixed in 300 MiB: fits, but tight.
        let p = plan(&cfg("262144", 1), FIB, Some(&mem(300 << 20, 0))).unwrap();
        assert!(p.warning.unwrap().contains("may run out of memory"));
        // Nothing known about the machine: nothing to check.
        assert!(plan(&cfg("16000000", 1), FIB, None).is_ok());
    }

    #[test]
    fn packet_buffers_on_huge_pages_do_not_count() {
        // 16 free huge pages = 32 MiB: exactly one worker's packet buffers.
        let p = plan(&cfg("262144", 2), FIB, Some(&mem(2 * GIB, 16))).unwrap();
        assert_eq!(p.on_huge_pages, 32 << 20, "one of the two workers");
        assert_eq!(p.ordinary_memory(), (32 << 20) + p.session_tables + FIB);
    }

    #[test]
    fn umem_is_whole_huge_pages() {
        assert_eq!(umem_frames(2, 2048), 8192);
        assert_eq!(umem_frames(3, 64), 512);
        assert_eq!(umem_frames(1, 4096), 8192);
    }
}
