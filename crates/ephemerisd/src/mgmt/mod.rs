//! The management plane: REST API, web portal, and config lifecycle.
//!
//! It runs on its own thread with its own async runtime, completely apart
//! from the data-plane workers. The two sides meet in exactly two places:
//!
//! * workers *publish* a [`Report`] about once a second (read here), and
//! * the control plane *sends* [`Control`] messages (new FIB, new ports) that
//!   workers pick up between packet batches.
//!
//! Neither side ever waits for the other.

pub mod api;
pub mod auth;
pub mod configmgr;
#[cfg(not(target_os = "linux"))]
pub mod dev;
pub mod diff;
pub mod history;
pub mod nics;
pub mod paths;

use crate::config::Config;
use crate::report::{Control, Report, SessionView};
use anyhow::{Context, Result};
use configmgr::ConfigManager;
use eph_dataplane::overlay::{Overlay, PathTable, TetherHealth, TetherStats};
use eph_dataplane::{DropReason, Neighbor, NextHop, Port};
use eph_fib::Fib;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

/// How each port ended up attached at startup.
#[derive(Debug, Clone)]
pub struct PortRuntime {
    pub device: String,
    pub xdp_mode: String,
    pub zero_copy: bool,
}

#[derive(Default)]
pub struct UpdateCache {
    /// The version an install was started for.
    pub target: Option<String>,
    /// (when, key, the boot loader's default version): `key` is the update
    /// job's state, so a finished install is seen straight away.
    pub default_entry: Option<(std::time::Instant, String, Option<String>)>,
}

pub struct Shared {
    pub build: String,
    pub started: Instant,
    pub runtime: Vec<PortRuntime>,
    pub workers: usize,
    pub ports: RwLock<Arc<[Port]>>,
    pub fib: RwLock<Arc<Fib<NextHop>>>,
    /// SD-WAN: static overlay config, current path decisions, tether health.
    pub overlay: Arc<Overlay>,
    pub paths: RwLock<Arc<PathTable>>,
    pub health: RwLock<Vec<TetherHealth>>,
    pub reports: Vec<Arc<Mutex<Report>>>,
    pub control: Mutex<Vec<Sender<Control>>>,
    pub config: Mutex<ConfigManager>,
    pub token: String,
    pub auth: auth::Auth,
    /// Whether the data plane is running, and whether this start fell back
    /// to an earlier config.
    pub startup: crate::startup::StartupState,
    /// DHCP: what the router's own clients were given, and the leases it
    /// hands out (kept by the DHCP service, read by the API).
    pub dhcp: Arc<Mutex<crate::dhcp::DhcpState>>,
    /// Where SD-WAN peers without a fixed address were last heard from.
    pub endpoints: Arc<eph_dataplane::overlay::Endpoints>,
    /// Rates sampled every few seconds, for the Reporting graphs.
    pub history: Mutex<history::History>,
    /// What the software-update buttons know: the version being installed
    /// and the boot loader's view (cached: the System tab polls).
    pub update: Mutex<UpdateCache>,
    /// Set to stop the daemon (systemd then starts it again).
    pub stop: &'static AtomicBool,
}

impl Shared {
    /// Push a new configuration into the running data plane. Only valid for
    /// changes [`Config::live_applicable`] accepts (same interfaces).
    pub fn apply_live(&self, cfg: &Config) -> Result<()> {
        // Interfaces on DHCP use whatever their lease currently says.
        let cfg = &cfg.with_links(&self.dhcp.lock().unwrap());
        let old = self.ports.read().unwrap().clone();
        let ports: Arc<[Port]> = cfg
            .ports(|i| {
                old.iter()
                    .find(|p| p.name == i.name)
                    .map(|p| p.mac)
                    .context("interface set changed; restart required")
            })?
            .into();
        let fib = Arc::new(cfg.fib(&ports)?);
        let nat = Arc::new(cfg.nat()?);
        for tx in self.control.lock().unwrap().iter() {
            // A worker that has exited (shutdown) just doesn't get it.
            let _ = tx.send(Control::SetPorts(ports.clone()));
            let _ = tx.send(Control::SetFib(fib.clone()));
            let _ = tx.send(Control::SetNat(nat.clone()));
        }
        *self.ports.write().unwrap() = ports;
        *self.fib.write().unwrap() = fib;
        Ok(())
    }

    pub fn summary(&self) -> Summary {
        Summary::collect(&self.reports)
    }
}

/// All workers' reports added up.
#[derive(Default)]
pub struct Summary {
    pub rx: u64,
    pub forwarded: u64,
    pub originated: u64,
    pub kernel_drops: u64,
    pub fill_empty: u64,
    pub drops: BTreeMap<&'static str, u64>,
    pub sessions_active: u64,
    pub sessions_created: u64,
    pub sessions_expired: u64,
    pub tcp_blind: u64,
    pub arp_conflicts: u64,
    pub sessions: Vec<SessionView>,
    pub neighbors: Vec<Neighbor>,
    pub tethers: Vec<TetherStats>,
    /// Per interface (index = port id).
    pub ports: Vec<eph_dataplane::PortCounters>,
}

impl Summary {
    pub fn collect(reports: &[Arc<Mutex<Report>>]) -> Self {
        let mut s = Summary::default();
        let mut drops = [0u64; DropReason::COUNT];
        let mut neighbors = BTreeMap::new();
        let mut tethers = Vec::new();
        for r in reports {
            let r = r.lock().unwrap();
            s.rx += r.stats.rx;
            s.forwarded += r.stats.forwarded;
            s.originated += r.stats.originated;
            s.kernel_drops += r.kernel.rx_dropped;
            s.fill_empty += r.kernel.fill_empty;
            for (t, d) in drops.iter_mut().zip(r.stats.drops) {
                *t += d;
            }
            s.sessions_active += r.stats.sessions_active;
            s.sessions_created += r.stats.sessions_created;
            s.sessions_expired += r.stats.sessions_expired;
            s.tcp_blind += r.stats.tcp_blind;
            s.arp_conflicts += r.stats.arp_conflicts;
            if s.ports.len() < r.stats.ports.len() {
                s.ports.resize(r.stats.ports.len(), Default::default());
            }
            for (t, p) in s.ports.iter_mut().zip(&r.stats.ports) {
                t.rx_packets += p.rx_packets;
                t.rx_bytes += p.rx_bytes;
                t.tx_packets += p.tx_packets;
                t.tx_bytes += p.tx_bytes;
            }
            s.sessions.extend(r.sessions.iter().cloned());
            for n in &r.neighbors {
                neighbors.insert((n.port, n.ip), *n);
            }
            tethers.push(r.tethers.clone());
        }
        s.tethers = paths::merge(&tethers);
        s.drops = DropReason::ALL
            .iter()
            .filter(|r| drops[**r as usize] > 0)
            .map(|r| (r.name(), drops[*r as usize]))
            .collect();
        s.neighbors = neighbors.into_values().collect();
        s
    }
}

/// Compare without exiting early on the first different byte, so response
/// timing doesn't reveal how much of a secret a guess got right.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Read the API token, or create one (32 random bytes, hex) on first start.
pub fn load_or_create_token(path: &str) -> Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(t) = std::fs::read_to_string(path) {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    if let Some(dir) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {path}"))?
        .write_all(format!("{token}\n").as_bytes())?;
    Ok(token)
}
