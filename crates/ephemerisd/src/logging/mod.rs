//! Logging: categories with their own levels, changed while the router
//! runs, and where the lines go.
//!
//! Every log line belongs to a **category** (its `tracing` target, e.g.
//! `tracing::info!(target: cat::DHCP_CLIENT, ...)`), and every category has
//! a **level**: error, warn, info, debug or trace. A line is kept if its
//! level is at or above its category's. The levels come from the config's
//! `[logging]` section, and `ephctl log set` raises one for a while (debug
//! switches itself off again: [`Control::set`]).
//!
//! Where lines go ([`sink`]):
//!
//! - **the journal**: info and above, as structured entries (`journalctl
//!   TARGET=dhcp-client`), within journald's own size and age limits;
//! - **`/var/log/ephemeris/debug.log`**: everything kept, any level, in two
//!   rotating files with a fixed total size: the detailed record, for when
//!   something is being debugged;
//! - **`/var/log/ephemeris/audit.log`**: the `audit` category only (logins,
//!   changes, restarts), in files of its own, so nothing else can push it
//!   out;
//! - **memory**: the most recent lines, for `ephctl log show` and the API.
//!
//! Packet-level categories (session, nat, filter...) are also switches in
//! the data plane: at debug, the workers record what they do with packets
//! (see `eph_dataplane::trace`), filtered by host and rate-limited.

pub mod dataplane;
pub mod sink;

use anyhow::{bail, Result};
pub use eph_config::logging::{cat, LoggingCfg, Lvl};
use eph_dataplane::trace::{TraceCat, TraceConfig};
use eph_fib::Prefix;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::Level;

/// The audit category's name (lines with it also go to audit.log).
pub const AUDIT_TARGET: &str = cat::AUDIT;

/// A category: what it covers and how much it logs by default.
pub struct Category {
    pub name: &'static str,
    pub group: &'static str,
    pub default: Lvl,
    pub about: &'static str,
    /// Its switch in the data plane's packet tracing, if it has one.
    pub trace: Option<TraceCat>,
}

const fn c(
    name: &'static str,
    group: &'static str,
    default: Lvl,
    about: &'static str,
    trace: Option<TraceCat>,
) -> Category {
    Category {
        name,
        group,
        default,
        about,
        trace,
    }
}

pub const CATEGORIES: &[Category] = &[
    c(
        cat::SYSTEM,
        "system",
        Lvl::Info,
        "start-up, shutdown, memory, NIC setup",
        None,
    ),
    c(
        cat::CONFIG,
        "system",
        Lvl::Info,
        "commits, rollbacks, falling back to the last good config",
        None,
    ),
    c(
        cat::AUDIT,
        "system",
        Lvl::Info,
        "who did what: logins, changes, restarts (also in audit.log)",
        None,
    ),
    c(cat::MGMT, "system", Lvl::Info, "the API and portal", None),
    c(cat::UPDATE, "system", Lvl::Info, "software updates", None),
    c(
        cat::INTERFACE,
        "links",
        Lvl::Info,
        "interfaces: addresses, MTU, VLANs; frames the router can't use",
        Some(TraceCat::Interface),
    ),
    c(
        cat::ARP,
        "links",
        Lvl::Warn,
        "neighbours: learned, moved, conflicts, ARP requests",
        Some(TraceCat::Arp),
    ),
    c(
        cat::ROUTE,
        "links",
        Lvl::Info,
        "the forwarding table; packets with no route, TTL or MTU problems",
        Some(TraceCat::Route),
    ),
    c(
        cat::SESSION,
        "packets",
        Lvl::Warn,
        "sessions created, and packets refused for having none",
        Some(TraceCat::Session),
    ),
    c(
        cat::NAT,
        "packets",
        Lvl::Warn,
        "source NAT translations, ports running out",
        Some(TraceCat::Nat),
    ),
    c(
        cat::FILTER,
        "packets",
        Lvl::Warn,
        "the packet filter: martians, spoofed sources, bad headers",
        Some(TraceCat::Filter),
    ),
    c(
        cat::ICMP,
        "packets",
        Lvl::Warn,
        "ICMP errors the router sends or holds back",
        Some(TraceCat::Icmp),
    ),
    c(
        cat::DHCP_SERVER,
        "services",
        Lvl::Info,
        "leases handed out on inside interfaces",
        None,
    ),
    c(
        cat::DHCP_CLIENT,
        "services",
        Lvl::Info,
        "getting an address from the ISP by DHCP",
        None,
    ),
    c(
        cat::PPPOE,
        "services",
        Lvl::Info,
        "dialling the ISP: discovery, LCP, login, IPCP",
        None,
    ),
    c(
        cat::SDWAN,
        "services",
        Lvl::Info,
        "tethers, probes, path changes",
        Some(TraceCat::Sdwan),
    ),
    c(
        cat::DATAPLANE,
        "engine",
        Lvl::Info,
        "workers, XDP and AF_XDP sockets, rings",
        Some(TraceCat::Dataplane),
    ),
];

/// The level of a `tracing` line.
pub fn lvl_of(l: &Level) -> Lvl {
    match *l {
        Level::ERROR => Lvl::Error,
        Level::WARN => Lvl::Warn,
        Level::INFO => Lvl::Info,
        Level::DEBUG => Lvl::Debug,
        Level::TRACE => Lvl::Trace,
    }
}

/// The index of a category by name.
pub fn category(name: &str) -> Option<usize> {
    CATEGORIES.iter().position(|c| c.name == name)
}

/// Lines from targets that aren't categories: other crates (the web
/// server's, say) only when they warn; ephemerisd's own untargeted lines
/// count as `system`.
fn category_of_target(target: &str) -> Option<usize> {
    category(target).or_else(|| target.starts_with("ephemerisd").then_some(0))
}

/// A level raised (or lowered) at run time, possibly for a while.
#[derive(Debug, Clone)]
pub struct Override {
    pub level: Lvl,
    pub until: Option<Instant>,
}

/// The run-time state: shared by everything that logs.
pub struct Control {
    /// Each category's level now (config, or an override): read for every
    /// log call, so atomics.
    current: [AtomicU8; CATEGORIES.len()],
    inner: Mutex<Inner>,
    /// Bumped whenever the data plane's tracing should change.
    trace_version: AtomicU64,
}

struct Inner {
    cfg: LoggingCfg,
    overrides: BTreeMap<usize, Override>,
    host: Option<Prefix>,
}

static CONTROL: OnceLock<Control> = OnceLock::new();

/// The one logging state of this process.
pub fn control() -> &'static Control {
    CONTROL.get_or_init(Control::new)
}

/// One category as `ephctl log levels` shows it.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryState {
    pub name: &'static str,
    pub group: &'static str,
    pub about: &'static str,
    pub level: Lvl,
    /// From the config (or the built-in default).
    pub configured: Lvl,
    /// Seconds until a temporary level ends; `None` with `overridden`:
    /// until reset.
    pub expires_in_secs: Option<u64>,
    pub overridden: bool,
    /// Also traces packets in the data plane at debug.
    pub packets: bool,
}

impl Control {
    fn new() -> Control {
        Control {
            current: std::array::from_fn(|i| AtomicU8::new(CATEGORIES[i].default as u8)),
            inner: Mutex::new(Inner {
                cfg: LoggingCfg::default(),
                overrides: BTreeMap::new(),
                host: None,
            }),
            trace_version: AtomicU64::new(0),
        }
    }

    /// Would a line at `level` for `target` be kept?
    #[inline]
    pub fn enabled(&self, target: &str, level: &Level) -> bool {
        let l = lvl_of(level) as u8;
        match category_of_target(target) {
            Some(i) => l <= self.current[i].load(Ordering::Relaxed),
            None => l <= Lvl::Warn as u8,
        }
    }

    pub fn level(&self, i: usize) -> Lvl {
        Lvl::from_u8(self.current[i].load(Ordering::Relaxed))
    }

    /// Take the config's `[logging]` (at start, and on every commit), and
    /// point the files at its directory. Run-time overrides stay until
    /// they run out.
    pub fn apply_config(&self, cfg: &LoggingCfg) {
        let mut g = self.inner.lock().unwrap();
        g.cfg = cfg.clone();
        self.recompute(&g);
        drop(g);
        if let Some(logs) = sink::logs() {
            logs.set_files(sink::FileSettings {
                dir: cfg.dir.clone().into(),
                debug_bytes: cfg.debug_file_mb << 20,
                audit_bytes: cfg.audit_file_mb << 20,
            });
        }
    }

    /// Set `category` to `level`. Debug and trace last `for_` (`None`: the
    /// config's `debug_minutes`; zero: until reset); other levels stay
    /// until reset.
    pub fn set(
        &self,
        category: &str,
        level: Lvl,
        for_: Option<Duration>,
    ) -> Result<Option<Duration>> {
        let Some(i) = self::category(category) else {
            bail!("no log category {category:?}");
        };
        let mut g = self.inner.lock().unwrap();
        let dur = if level >= Lvl::Debug {
            match for_ {
                None => Some(Duration::from_secs(g.cfg.debug_minutes * 60)),
                Some(d) if d.is_zero() => None,
                Some(d) => Some(d),
            }
        } else {
            for_.filter(|d| !d.is_zero())
        };
        g.overrides.insert(
            i,
            Override {
                level,
                until: dur.map(|d| Instant::now() + d),
            },
        );
        self.recompute(&g);
        Ok(dur)
    }

    /// Back to the config's levels, no packet filter.
    pub fn reset(&self) {
        let mut g = self.inner.lock().unwrap();
        g.overrides.clear();
        g.host = None;
        self.recompute(&g);
    }

    /// Only trace packets to or from `host` (`None`: all).
    pub fn set_host(&self, host: Option<Prefix>) {
        let mut g = self.inner.lock().unwrap();
        g.host = host;
        self.trace_version.fetch_add(1, Ordering::Relaxed);
    }

    pub fn host(&self) -> Option<Prefix> {
        self.inner.lock().unwrap().host
    }

    /// End overrides whose time is up. Returns the categories that ended.
    pub fn expire(&self, now: Instant) -> Vec<&'static str> {
        let mut g = self.inner.lock().unwrap();
        let ended: Vec<usize> = g
            .overrides
            .iter()
            .filter(|(_, o)| o.until.is_some_and(|t| t <= now))
            .map(|(&i, _)| i)
            .collect();
        if ended.is_empty() {
            return vec![];
        }
        for i in &ended {
            g.overrides.remove(i);
        }
        // The packet filter goes with the last packet trace using it.
        let tracing = g
            .overrides
            .iter()
            .any(|(&i, o)| CATEGORIES[i].trace.is_some() && o.level >= Lvl::Debug);
        if !tracing {
            g.host = None;
        }
        self.recompute(&g);
        ended.into_iter().map(|i| CATEGORIES[i].name).collect()
    }

    /// The data plane's tracing settings now.
    pub fn trace_config(&self) -> TraceConfig {
        let g = self.inner.lock().unwrap();
        let mask = CATEGORIES
            .iter()
            .enumerate()
            .filter(|(i, _)| self.level(*i) >= Lvl::Debug)
            .filter_map(|(_, c)| c.trace)
            .fold(0, |m, t| m | t.bit());
        TraceConfig {
            mask,
            host: g.host,
            per_sec: g.cfg.trace_per_sec,
        }
    }

    /// Changes the data plane hasn't seen yet: compare with the version it
    /// was last given.
    pub fn trace_version(&self) -> u64 {
        self.trace_version.load(Ordering::Relaxed)
    }

    pub fn states(&self) -> Vec<CategoryState> {
        let g = self.inner.lock().unwrap();
        let now = Instant::now();
        CATEGORIES
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let o = g.overrides.get(&i);
                CategoryState {
                    name: c.name,
                    group: c.group,
                    about: c.about,
                    level: self.level(i),
                    configured: g.cfg.levels.get(c.name).copied().unwrap_or(c.default),
                    expires_in_secs: o
                        .and_then(|o| o.until)
                        .map(|t| t.saturating_duration_since(now).as_secs()),
                    overridden: o.is_some(),
                    packets: c.trace.is_some(),
                }
            })
            .collect()
    }

    pub fn config(&self) -> LoggingCfg {
        self.inner.lock().unwrap().cfg.clone()
    }

    fn recompute(&self, g: &Inner) {
        for (i, c) in CATEGORIES.iter().enumerate() {
            let l = g
                .overrides
                .get(&i)
                .map(|o| o.level)
                .or_else(|| g.cfg.levels.get(c.name).copied())
                .unwrap_or(c.default);
            self.current[i].store(l as u8, Ordering::Relaxed);
        }
        self.trace_version.fetch_add(1, Ordering::Relaxed);
    }
}

/// The other way round, exactly: "90s", "10m", "2h30m".
pub fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    let mut out = String::new();
    for (v, unit) in [(s / 3600, "h"), (s % 3600 / 60, "m"), (s % 60, "s")] {
        if v > 0 {
            out += &format!("{v}{unit}");
        }
    }
    if out.is_empty() {
        out = "0s".into();
    }
    out
}

/// Control characters escaped (`\n` becomes `\\n`, ESC becomes
/// `\\u{1b}`): a log line stays one line, and nothing reaches a terminal
/// as an escape sequence.
pub fn escape_controls(s: &str) -> String {
    if !s.chars().any(char::is_control) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Longest text from the network kept as is.
pub const UNTRUSTED_MAX: usize = 64;

/// Text from the network (a DHCP client's hostname, an ISP's name or error
/// message): made safe to log, store and show. Control characters are
/// escaped and it's cut to [`UNTRUSTED_MAX`] characters, so whoever sent it
/// can't forge log lines, send escape sequences to a terminal, or fill the
/// log with one field (ASVS V16.4.1).
pub fn untrusted(s: &str) -> String {
    let cut: String = s.chars().take(UNTRUSTED_MAX).collect();
    let mut out = escape_controls(&cut);
    if s.chars().count() > UNTRUSTED_MAX {
        out.push('…');
    }
    out
}

/// "10m", "2h", "90s", "1d", or "forever" (zero: until reset).
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("forever") {
        return Some(Duration::ZERO);
    }
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().ok()?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Control {
        Control::new()
    }

    #[test]
    fn levels_come_from_defaults_config_and_overrides() {
        let c = fresh();
        assert!(c.enabled(cat::DHCP_CLIENT, &Level::INFO));
        assert!(!c.enabled(cat::DHCP_CLIENT, &Level::DEBUG));
        assert!(
            !c.enabled(cat::SESSION, &Level::INFO),
            "packet categories: warn"
        );
        assert!(
            c.enabled("ephemerisd::run", &Level::INFO),
            "untargeted: system"
        );
        assert!(
            !c.enabled("hyper::proto", &Level::INFO),
            "other crates: warn and up"
        );
        assert!(c.enabled("hyper::proto", &Level::WARN));

        let mut cfg = LoggingCfg::default();
        cfg.levels.insert("dhcp-client".into(), Lvl::Debug);
        c.apply_config(&cfg);
        assert!(
            c.enabled(cat::DHCP_CLIENT, &Level::DEBUG),
            "from the config, no timer"
        );

        let d = c.set("session", Lvl::Debug, None).unwrap();
        assert_eq!(
            d,
            Some(Duration::from_secs(600)),
            "debug: 10 minutes by default"
        );
        assert!(c.enabled(cat::SESSION, &Level::DEBUG));
        assert_eq!(c.trace_config().mask, TraceCat::Session.bit());
        assert_eq!(
            c.set("pppoe", Lvl::Trace, Some(Duration::ZERO)).unwrap(),
            None,
            "forever"
        );
        assert_eq!(
            c.set("nat", Lvl::Error, None).unwrap(),
            None,
            "non-debug: until reset"
        );
        assert!(c.set("nope", Lvl::Debug, None).is_err());

        // Time's up for session (but not the others).
        c.set_host(Some("10.0.0.0/24".parse().unwrap()));
        let ended = c.expire(Instant::now() + Duration::from_secs(601));
        assert_eq!(ended, vec!["session"]);
        assert!(!c.enabled(cat::SESSION, &Level::DEBUG));
        assert_eq!(
            c.host(),
            None,
            "the packet filter ends with the last packet trace"
        );
        assert!(c.enabled(cat::PPPOE, &Level::TRACE));
        assert!(!c.enabled(cat::NAT, &Level::WARN));

        c.reset();
        assert!(c.enabled(cat::NAT, &Level::WARN));
        assert!(
            c.enabled(cat::DHCP_CLIENT, &Level::DEBUG),
            "config levels stay"
        );
    }

    #[test]
    fn the_config_knows_every_category() {
        // `[logging] levels` is checked against eph-config's list.
        let names: Vec<&str> = CATEGORIES.iter().map(|c| c.name).collect();
        assert_eq!(names, eph_config::logging::CATEGORY_NAMES);
    }

    #[test]
    fn every_trace_category_is_a_log_category() {
        for t in TraceCat::ALL {
            let i = category(t.name()).unwrap();
            assert_eq!(CATEGORIES[i].trace, Some(t));
        }
    }

    #[test]
    fn config_is_checked() {
        let bad = |f: fn(&mut LoggingCfg)| {
            let mut c = LoggingCfg::default();
            f(&mut c);
            c.validate().unwrap_err().to_string()
        };
        assert!(bad(|c| {
            c.levels.insert("dhcp".into(), Lvl::Debug);
        })
        .contains("no category \"dhcp\""));
        assert!(bad(|c| c.debug_minutes = 0).contains("debug_minutes"));
        assert!(bad(|c| c.debug_file_mb = 1).contains("debug_file_mb"));
        assert!(bad(|c| c.dir = "logs".into()).contains("absolute"));
        assert!(LoggingCfg::default().validate().is_ok());
    }

    #[test]
    fn network_text_cannot_forge_lines_or_reach_a_terminal() {
        let forged = "laptop\n2026-10-27T10:00:00.000Z INFO  audit       admin password changed";
        let s = untrusted(forged);
        assert!(!s.contains('\n'), "{s}");
        assert!(s.starts_with("laptop\\n2026"));
        assert_eq!(
            untrusted("evil\x1b[2J"),
            "evil\\u{1b}[2J",
            "no terminal escapes"
        );
        assert_eq!(
            untrusted("printer-2nd-floor"),
            "printer-2nd-floor",
            "ordinary names untouched"
        );
        assert_eq!(untrusted("café"), "café");
        let long = "x".repeat(500);
        assert_eq!(
            untrusted(&long).chars().count(),
            UNTRUSTED_MAX + 1,
            "cut, with an ellipsis"
        );
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("45"), Some(Duration::from_secs(45)));
        assert_eq!(parse_duration("forever"), Some(Duration::ZERO));
        assert_eq!(parse_duration("10x"), None);
        assert_eq!(fmt_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(fmt_duration(Duration::from_secs(9000)), "2h30m");
        assert_eq!(fmt_duration(Duration::ZERO), "0s");
        assert_eq!(Lvl::parse("WARNING"), Some(Lvl::Warn));
    }
}
