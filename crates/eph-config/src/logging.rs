//! `[logging]` in the config: levels per category, and the log files.
//! (The router's logging itself lives in ephemerisd.)

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Category names, for `target:` in log calls.
pub mod cat {
    pub const SYSTEM: &str = "system";
    pub const CONFIG: &str = "config";
    pub const AUDIT: &str = "audit";
    pub const MGMT: &str = "mgmt";
    pub const UPDATE: &str = "update";
    pub const INTERFACE: &str = "interface";
    pub const ARP: &str = "arp";
    pub const ROUTE: &str = "route";
    pub const SESSION: &str = "session";
    pub const NAT: &str = "nat";
    pub const FILTER: &str = "filter";
    pub const ICMP: &str = "icmp";
    pub const DHCP_SERVER: &str = "dhcp-server";
    pub const DHCP_CLIENT: &str = "dhcp-client";
    pub const PPPOE: &str = "pppoe";
    pub const SDWAN: &str = "sdwan";
    pub const DATAPLANE: &str = "dataplane";
}

/// Every category, in the router's order.
pub const CATEGORY_NAMES: &[&str] = &[
    cat::SYSTEM,
    cat::CONFIG,
    cat::AUDIT,
    cat::MGMT,
    cat::UPDATE,
    cat::INTERFACE,
    cat::ARP,
    cat::ROUTE,
    cat::SESSION,
    cat::NAT,
    cat::FILTER,
    cat::ICMP,
    cat::DHCP_SERVER,
    cat::DHCP_CLIENT,
    cat::PPPOE,
    cat::SDWAN,
    cat::DATAPLANE,
];

/// A log level. Ordered from least to most detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum Lvl {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl Lvl {
    pub const ALL: [Lvl; 5] = [Lvl::Error, Lvl::Warn, Lvl::Info, Lvl::Debug, Lvl::Trace];

    pub fn name(self) -> &'static str {
        match self {
            Lvl::Error => "error",
            Lvl::Warn => "warn",
            Lvl::Info => "info",
            Lvl::Debug => "debug",
            Lvl::Trace => "trace",
        }
    }

    pub fn parse(s: &str) -> Option<Lvl> {
        Lvl::ALL
            .into_iter()
            .find(|l| l.name().eq_ignore_ascii_case(s.trim()))
            .or_else(|| {
                s.trim()
                    .eq_ignore_ascii_case("warning")
                    .then_some(Lvl::Warn)
            })
    }

    pub fn from_u8(v: u8) -> Lvl {
        Lvl::ALL[(v.clamp(1, 5) - 1) as usize]
    }
}

/// `[logging]` in the config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingCfg {
    /// Levels for categories that shouldn't use their default, e.g.
    /// `levels = { dhcp-client = "debug" }`. Set here, they stay (no timer).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub levels: BTreeMap<String, Lvl>,
    /// How long `ephctl log set <category> debug` lasts unless told
    /// otherwise.
    pub debug_minutes: u64,
    /// Packet tracing events per second per worker, at most.
    pub trace_per_sec: u32,
    /// Where debug.log and audit.log go.
    pub dir: String,
    /// debug.log: every line kept, at any level; two files of half this.
    pub debug_file_mb: u64,
    /// audit.log: two files of half this.
    pub audit_file_mb: u64,
}

pub const DEFAULT_DIR: &str = "/var/log/ephemeris";

impl Default for LoggingCfg {
    fn default() -> Self {
        LoggingCfg {
            levels: BTreeMap::new(),
            debug_minutes: 10,
            trace_per_sec: 100,
            dir: DEFAULT_DIR.into(),
            debug_file_mb: 64,
            audit_file_mb: 16,
        }
    }
}

impl LoggingCfg {
    pub fn validate(&self) -> Result<()> {
        for name in self.levels.keys() {
            if !CATEGORY_NAMES.contains(&name.as_str()) {
                bail!(
                    "logging.levels: no category {name:?} (there are: {})",
                    CATEGORY_NAMES.join(", ")
                );
            }
        }
        if !(1..=24 * 60).contains(&self.debug_minutes) {
            bail!("logging.debug_minutes must be between 1 and 1440");
        }
        if !(1..=10_000).contains(&self.trace_per_sec) {
            bail!("logging.trace_per_sec must be between 1 and 10000");
        }
        if !(2..=1024).contains(&self.debug_file_mb) || !(2..=1024).contains(&self.audit_file_mb) {
            bail!("logging.debug_file_mb and audit_file_mb must be between 2 and 1024");
        }
        if !self.dir.starts_with('/') {
            bail!("logging.dir must be an absolute path");
        }
        Ok(())
    }
}
