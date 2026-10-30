//! Configuration lifecycle, network-OS style: edit a *candidate*, look at the
//! diff, *commit* it (optionally "commit confirmed", which rolls itself back
//! unless confirmed), and *roll back* to any earlier version.
//!
//! The config file on disk is the single source of truth. The API's
//! convenience operations ("add a route") are just candidate edits, so every
//! change goes through the same validate → diff → commit → history path.

use super::diff::diff;
use crate::config::{Config, Live};
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

/// Older versions kept in the history directory.
const HISTORY_KEEP: usize = 20;

/// How a committed change reaches the running router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Apply {
    /// Nothing changed.
    Unchanged,
    /// Routes, addresses or policy: pushed into the running data plane.
    Live,
    /// Interfaces, workers, table sizes...: saved, takes effect after a restart.
    RestartRequired,
}

#[derive(Debug, Clone, Serialize)]
pub struct Preview {
    pub diff: String,
    pub apply: Apply,
}

#[derive(Debug, Clone)]
pub struct Committed {
    pub diff: String,
    pub apply: Apply,
    pub config: Config,
    /// Set for a confirmed commit: the id to confirm (or to time out).
    pub confirm_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    /// 1 = the version before the current one.
    pub index: usize,
    pub saved_unix: u64,
    pub file: String,
}

struct Pending {
    id: u64,
    deadline_unix: u64,
    previous_text: String,
}

/// Largest configuration accepted for staging.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_CONFIG_LINES: usize = 5000;

pub struct ConfigManager {
    path: PathBuf,
    history_dir: PathBuf,
    running_text: String,
    running: Config,
    candidate: Option<(String, Config)>,
    pending: Option<Pending>,
    next_id: u64,
    /// Lists the router's NICs, to refuse interfaces on cards that don't
    /// exist. None (tests, `--check`) skips that check.
    nics: Option<fn() -> Vec<super::nics::Nic>>,
    /// The router's current DHCP leases: a new config is also checked as it
    /// would apply with them (e.g. a route via the ISP's gateway).
    leases: Option<std::sync::Arc<std::sync::Mutex<crate::dhcp::DhcpState>>>,
}

impl ConfigManager {
    pub fn open(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let running = Config::parse(&text)?;
        let dir = path.parent().unwrap_or(Path::new("."));
        let history_dir = dir.join("config-history");
        // Versions before 0.4.2 wrote these world-readable; they can hold
        // tether keys now.
        let mut state = vec![path.to_owned(), dir.join("last-good.toml")];
        for d in [&history_dir, &dir.to_path_buf()] {
            if let Ok(rd) = std::fs::read_dir(d) {
                state.extend(rd.flatten().map(|e| e.path()).filter(|p| {
                    let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    n.ends_with(".toml") || n.contains(".toml.failed-")
                }));
            }
        }
        crate::files::tighten(state);
        Ok(ConfigManager {
            path: path.to_owned(),
            history_dir,
            running_text: text,
            running,
            candidate: None,
            pending: None,
            next_id: 1,
            nics: None,
            leases: None,
        })
    }

    /// Also check new configs with the router's current DHCP leases applied.
    pub fn check_with_leases(
        mut self,
        leases: std::sync::Arc<std::sync::Mutex<crate::dhcp::DhcpState>>,
    ) -> Self {
        self.leases = Some(leases);
        self
    }

    /// Also check new configs against the NICs this router actually has.
    pub fn check_nics(mut self, list: fn() -> Vec<super::nics::Nic>) -> Self {
        self.nics = Some(list);
        self
    }

    /// The parts of validation that depend on this machine, not just the
    /// file: every interface's card exists, and isn't the management NIC.
    fn check_devices(&self, cfg: &Config) -> Result<()> {
        let Some(list) = self.nics else { return Ok(()) };
        if !cfg.ssh.password_login && !super::ssh::key_installed() {
            bail!(
                "ssh.password_login = false needs an SSH key for root first \
                 (/var/lib/ephemeris/ssh/authorized_keys.root): without one, \
                 SSH would let nobody in"
            );
        }
        let nics = list();
        for i in &cfg.interfaces {
            match nics.iter().find(|n| n.name == i.device) {
                None => {
                    let free: Vec<&str> = nics
                        .iter()
                        .filter(|n| !n.kernel)
                        .map(|n| n.name.as_str())
                        .collect();
                    bail!(
                        "interface {}: this router has no network card named {:?} (available: {})",
                        i.name,
                        i.device,
                        if free.is_empty() {
                            "none".into()
                        } else {
                            free.join(", ")
                        }
                    )
                }
                // Only refuse it as a change: if it's already running this
                // way, the router got there somehow and stays editable.
                Some(n)
                    if n.kernel && !self.running.interfaces.iter().any(|r| r.device == n.name) =>
                {
                    bail!(
                    "interface {}: {} is the management NIC (the router's own address is on it); \
                     giving it to the data plane would cut off management",
                    i.name,
                    i.device
                )
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn running_text(&self) -> &str {
        &self.running_text
    }

    pub fn running(&self) -> &Config {
        &self.running
    }

    pub fn candidate_text(&self) -> Option<&str> {
        self.candidate.as_ref().map(|(t, _)| t.as_str())
    }

    /// Seconds until a confirmed commit rolls back, if one is pending.
    pub fn pending_confirm_secs(&self) -> Option<u64> {
        self.pending
            .as_ref()
            .map(|p| p.deadline_unix.saturating_sub(now_unix()))
    }

    fn classify(&self, new: &Config, new_text: &str) -> Apply {
        if new_text == self.running_text || *new == self.running {
            Apply::Unchanged
        } else if self.running.live_applicable(new) {
            Apply::Live
        } else {
            Apply::RestartRequired
        }
    }

    /// Validate `text` and stage it. Errors explain what's wrong with it.
    pub fn set_candidate(&mut self, text: String) -> Result<Preview> {
        // A real router config is a few KiB; these bounds keep parsing and
        // diffing cheap whatever is sent.
        if text.len() > MAX_CONFIG_BYTES || text.lines().count() > MAX_CONFIG_LINES {
            bail!(
                "configuration too large (at most {} KiB and {MAX_CONFIG_LINES} lines)",
                MAX_CONFIG_BYTES / 1024
            );
        }
        let cfg = Config::parse(&text)?;
        self.check_devices(&cfg)?;
        if let Some(l) = &self.leases {
            let st = l.lock().unwrap().clone();
            if !st.clients.is_empty() || !st.pppoe.is_empty() {
                let now = cfg.with_links(&st);
                now.fib(&now.ports(|_| Ok([0; 6]))?)
                    .context("with the router's current DHCP lease")?;
            }
        }
        let preview = Preview {
            diff: diff(&self.running_text, &text),
            apply: self.classify(&cfg, &text),
        };
        self.candidate = Some((text, cfg));
        Ok(preview)
    }

    pub fn clear_candidate(&mut self) {
        self.candidate = None;
    }

    /// Make the candidate the running config: save the old one to history,
    /// write the new one atomically. `confirm_secs` makes it provisional.
    pub fn commit(&mut self, confirm_secs: Option<u64>) -> Result<Committed> {
        if self.pending.is_some() {
            bail!("a confirmed commit is pending: confirm it (or wait for its rollback) first");
        }
        let (text, cfg) = self
            .candidate
            .take()
            .ok_or_else(|| anyhow!("no candidate configuration to commit"))?;
        // `apply` may be Unchanged for a comment-only edit: still saved, it
        // just has no effect on the data plane.
        let apply = self.classify(&cfg, &text);
        let d = diff(&self.running_text, &text);
        if text == self.running_text {
            return Ok(Committed {
                diff: d,
                apply,
                config: cfg,
                confirm_id: None,
            });
        }
        let previous = std::mem::replace(&mut self.running_text, text);
        self.save_history(&previous)?;
        write_atomic(&self.path, &self.running_text)?;
        self.running = cfg.clone();
        let confirm_id = confirm_secs.map(|secs| {
            let id = self.next_id;
            self.next_id += 1;
            self.pending = Some(Pending {
                id,
                deadline_unix: now_unix() + secs,
                previous_text: previous,
            });
            id
        });
        Ok(Committed {
            diff: d,
            apply,
            config: cfg,
            confirm_id,
        })
    }

    /// Keep a confirmed commit.
    pub fn confirm(&mut self) -> Result<()> {
        self.pending
            .take()
            .map(drop)
            .ok_or_else(|| anyhow!("no commit is waiting for confirmation"))
    }

    /// Called when a confirmed commit's timer fires: if commit `id` still
    /// isn't confirmed, restore the previous configuration.
    pub fn expire_pending(&mut self, id: u64) -> Option<Result<Committed>> {
        if self.pending.as_ref().map(|p| p.id) != Some(id) {
            return None; // confirmed, or superseded
        }
        let p = self.pending.take().unwrap();
        // Restoring what ran before must not be blocked by this machine's
        // checks (e.g. a card that has since gone): skip them.
        let nics = self.nics.take();
        let r = self
            .set_candidate(p.previous_text)
            .and_then(|_| self.commit(None));
        self.nics = nics;
        Some(r)
    }

    /// Restore version `index` from history (1 = the previous one).
    pub fn rollback(&mut self, index: usize) -> Result<Committed> {
        let entries = self.history()?;
        let e = entries
            .iter()
            .find(|e| e.index == index)
            .ok_or_else(|| anyhow!("no history entry {index} ({} saved)", entries.len()))?;
        let text = std::fs::read_to_string(self.history_dir.join(&e.file))?;
        self.set_candidate(text)?;
        self.commit(None)
    }

    pub fn history(&self) -> Result<Vec<HistoryEntry>> {
        let mut files: Vec<String> = match std::fs::read_dir(&self.history_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".toml"))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(e.into()),
        };
        files.sort_unstable_by(|a, b| b.cmp(a)); // newest first
        Ok(files
            .into_iter()
            .enumerate()
            .map(|(i, file)| HistoryEntry {
                index: i + 1,
                saved_unix: file
                    .split('-')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                file,
            })
            .collect())
    }

    fn save_history(&mut self, text: &str) -> Result<()> {
        std::fs::create_dir_all(&self.history_dir)?;
        // Zero-padded, so names sort in time order; the counter breaks ties
        // between commits in the same second.
        let name = format!("{:012}-{:06}.toml", now_unix(), self.next_id);
        self.next_id += 1;
        crate::files::write_private(&self.history_dir.join(name), text.as_bytes())?;
        for old in self.history()?.into_iter().skip(HISTORY_KEEP) {
            let _ = std::fs::remove_file(self.history_dir.join(old.file));
        }
        Ok(())
    }

    /// The configuration being edited: the candidate if one is staged, else
    /// the running one.
    pub fn working(&self) -> (&str, &Config) {
        match &self.candidate {
            Some((t, c)) => (t, c),
            None => (&self.running_text, &self.running),
        }
    }

    /// Turn an edited configuration (from the web GUI's forms) back into
    /// config-file text. Starts from the working text and rewrites only the
    /// sections that changed, so comments elsewhere survive.
    pub fn text_from_model(&self, new: &Config) -> Result<String> {
        let (base_text, base) = self.working();
        let mut doc: DocumentMut = base_text.parse()?;
        // Where each section sits in the file now (toml_edit orders tables by
        // a position number), so a rewritten section stays in its place.
        let old_pos: Vec<(String, Option<isize>)> = doc
            .iter()
            .map(|(k, v)| (k.to_string(), min_position(v)))
            .collect();
        let mut changed = Vec::new();
        fn put<T: serde::Serialize + PartialEq>(
            doc: &mut DocumentMut,
            changed: &mut Vec<&'static str>,
            key: &'static str,
            old: &T,
            new: &T,
        ) -> Result<()> {
            if old == new {
                return Ok(());
            }
            changed.push(key);
            let mut t = toml::Value::Table(toml::Table::new());
            t.as_table_mut()
                .unwrap()
                .insert(key.to_string(), toml::Value::try_from(new)?);
            // An empty list would be written as `route = []`, which is not
            // the `[[route]]` form people (and `with_route`) expect: drop it.
            prune_empty_arrays(&mut t);
            let rendered: DocumentMut = toml::to_string(&t)?.parse()?;
            match rendered.get(key) {
                Some(item) if !item.is_none() => {
                    let mut item = item.clone();
                    // Keep the comments written above the section.
                    if let Some(prefix) = doc.get(key).and_then(leading_comment) {
                        set_leading_comment(&mut item, prefix);
                    }
                    doc.insert(key, item);
                }
                _ => {
                    doc.remove(key);
                }
            }
            Ok(())
        }
        let c = &mut changed;
        put(&mut doc, c, "dataplane", &base.dataplane, &new.dataplane)?;
        put(&mut doc, c, "sessions", &base.sessions, &new.sessions)?;
        put(&mut doc, c, "management", &base.management, &new.management)?;
        put(&mut doc, c, "interface", &base.interfaces, &new.interfaces)?;
        put(&mut doc, c, "route", &base.routes, &new.routes)?;
        put(&mut doc, c, "nat", &base.nat, &new.nat)?;
        put(&mut doc, c, "overlay", &base.overlay, &new.overlay)?;
        put(&mut doc, c, "site", &base.sites, &new.sites)?;
        put(&mut doc, c, "tether", &base.tethers, &new.tethers)?;
        put(
            &mut doc,
            c,
            "overlay_route",
            &base.overlay_routes,
            &new.overlay_routes,
        )?;
        put(&mut doc, c, "class", &base.classes, &new.classes)?;

        // Order: unchanged sections where they are, rewritten ones where they
        // were, new ones right after the section that canonically precedes
        // them. Then number every table in that order, so sub-tables (e.g.
        // [[nat.pool]]) sit right under their parent.
        const CANONICAL: [&str; 11] = [
            "dataplane",
            "management",
            "sessions",
            "interface",
            "route",
            "nat",
            "overlay",
            "site",
            "tether",
            "overlay_route",
            "class",
        ];
        let pos_of = |k: &str| old_pos.iter().find(|(x, _)| x == k).and_then(|(_, p)| *p);
        let mut order: Vec<(String, f64)> = Vec::new();
        for (k, item) in doc.iter() {
            let key = match pos_of(k).or_else(|| {
                (!changed.contains(&k))
                    .then(|| min_position(item))
                    .flatten()
            }) {
                Some(p) => p as f64,
                None => {
                    // New section: after its nearest existing canonical predecessor.
                    let idx = CANONICAL
                        .iter()
                        .position(|c| *c == k)
                        .unwrap_or(CANONICAL.len());
                    CANONICAL[..idx]
                        .iter()
                        .rev()
                        .find_map(|c| pos_of(c))
                        .map(|p| p as f64 + 0.5 + idx as f64 / 100.0)
                        .unwrap_or(f64::MAX)
                }
            };
            order.push((k.to_string(), key));
        }
        order.sort_by(|a, b| a.1.total_cmp(&b.1));
        let mut next: isize = 0;
        for (k, _) in order {
            if let Some(item) = doc.get_mut(&k) {
                renumber(item, &mut next);
            }
        }
        Ok(doc.to_string())
    }

    // ---- convenience edits, applied to the running text (comments survive)

    /// The running config with a static route added (or its gateway changed).
    /// The running config with a `[controller]` section (after enrolment).
    pub fn with_controller(&self, c: &crate::config::ControllerCfg) -> Result<String> {
        let mut doc: DocumentMut = self.running_text.parse()?;
        let mut t = Table::new();
        t["url"] = value(c.url.as_str());
        t["pin"] = value(c.pin.as_str());
        doc.insert("controller", Item::Table(t));
        Ok(doc.to_string())
    }

    pub fn with_route(&self, prefix: &str, via: &str) -> Result<String> {
        let mut doc: DocumentMut = self.running_text.parse()?;
        // `route = []` means no routes, like a missing key.
        if doc
            .get("route")
            .and_then(|r| r.as_array())
            .is_some_and(|a| a.is_empty())
        {
            doc.remove("route");
        }
        let routes = doc
            .entry("route")
            .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
            .as_array_of_tables_mut()
            .ok_or_else(|| anyhow!("`route` is not an array of tables"))?;
        let existing = routes
            .iter()
            .position(|t| t.get("prefix").and_then(|v| v.as_str()) == Some(prefix));
        if let Some(t) = existing.and_then(|i| routes.get_mut(i)) {
            t["via"] = value(via);
        } else {
            let mut t = Table::new();
            t["prefix"] = value(prefix);
            t["via"] = value(via);
            routes.push(t);
        }
        Ok(doc.to_string())
    }

    /// The running config without the static route for `prefix`.
    pub fn without_route(&self, prefix: &str) -> Result<String> {
        let mut doc: DocumentMut = self.running_text.parse()?;
        let routes = doc
            .get_mut("route")
            .and_then(|r| r.as_array_of_tables_mut())
            .ok_or_else(|| anyhow!("no static route for {prefix}"))?;
        let idx = routes
            .iter()
            .position(|t| t.get("prefix").and_then(|v| v.as_str()) == Some(prefix))
            .ok_or_else(|| anyhow!("no static route for {prefix}"))?;
        routes.remove(idx);
        if routes.is_empty() {
            doc.remove("route");
        }
        Ok(doc.to_string())
    }
}

/// The comment lines (decor) in front of a section's first table header.
fn leading_comment(item: &Item) -> Option<String> {
    let decor = match item {
        Item::Table(t) => t.decor(),
        Item::ArrayOfTables(a) => a.iter().next()?.decor(),
        _ => return None,
    };
    decor
        .prefix()
        .and_then(|p| p.as_str())
        .map(str::to_string)
        .filter(|p| p.contains('#'))
}

fn set_leading_comment(item: &mut Item, prefix: String) {
    match item {
        Item::Table(t) => t.decor_mut().set_prefix(prefix),
        Item::ArrayOfTables(a) => {
            if let Some(t) = a.iter_mut().next() {
                t.decor_mut().set_prefix(prefix);
            }
        }
        _ => {}
    }
}

/// Smallest table position inside an item (toml_edit's ordering key).
fn min_position(item: &Item) -> Option<isize> {
    match item {
        Item::Table(t) => t
            .position()
            .into_iter()
            .chain(t.iter().filter_map(|(_, v)| min_position(v)))
            .min(),
        Item::ArrayOfTables(a) => a
            .iter()
            .filter_map(|t| {
                t.position()
                    .into_iter()
                    .chain(t.iter().filter_map(|(_, v)| min_position(v)))
                    .min()
            })
            .min(),
        _ => None,
    }
}

/// Give every table in `item` consecutive positions, parents before children.
fn renumber(item: &mut Item, next: &mut isize) {
    fn table(t: &mut Table, next: &mut isize) {
        t.set_position(Some(*next));
        *next += 1;
        for (_, v) in t.iter_mut() {
            renumber(v, next);
        }
    }
    match item {
        Item::Table(t) => table(t, next),
        Item::ArrayOfTables(a) => {
            for t in a.iter_mut() {
                table(t, next);
            }
        }
        _ => {}
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write via a temporary file + rename, so a crash or power cut leaves either
/// the old file or the new one, never half of each.
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    crate::files::write_private_atomic(path, text.as_bytes())
}

/// Remove empty arrays from every table, recursively.
fn prune_empty_arrays(v: &mut toml::Value) {
    match v {
        toml::Value::Table(t) => {
            t.retain(|_, x| !matches!(x, toml::Value::Array(a) if a.is_empty()));
            t.iter_mut().for_each(|(_, x)| prune_empty_arrays(x));
        }
        toml::Value::Array(a) => a.iter_mut().for_each(prune_empty_arrays),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const BASE: &str = r#"# lab router
[management]
listen = "127.0.0.1:0"

# the LAN-facing port
[[interface]]
name = "lan-a"
device = "eth1"
address = "10.10.1.1/24"

[[interface]]
name = "lan-b"
device = "eth2"
address = "10.10.2.1/24"
"#;

    fn manager(tag: &str) -> ConfigManager {
        let dir = std::env::temp_dir().join(format!("eph-cfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ephemeris.toml");
        std::fs::write(&path, BASE).unwrap();
        ConfigManager::open(&path).unwrap()
    }

    #[test]
    fn route_edits_keep_comments_and_apply_live() {
        let mut m = manager("route");
        let text = m.with_route("192.168.50.0/24", "10.10.2.254").unwrap();
        assert!(text.starts_with("# lab router"), "comments preserved");
        let p = m.set_candidate(text).unwrap();
        assert_eq!(p.apply, Apply::Live);
        assert!(
            p.diff.contains("+ prefix = \"192.168.50.0/24\""),
            "{}",
            p.diff
        );
        let c = m.commit(None).unwrap();
        assert_eq!(c.config.routes.len(), 1);
        // On disk, and the old version is in history.
        assert!(std::fs::read_to_string(&m.path)
            .unwrap()
            .contains("192.168.50.0/24"));
        assert_eq!(m.history().unwrap().len(), 1);
        // Remove it again.
        let text = m.without_route("192.168.50.0/24").unwrap();
        m.set_candidate(text).unwrap();
        assert!(m.commit(None).unwrap().config.routes.is_empty());
        assert!(m.without_route("192.168.50.0/24").is_err());
    }

    #[test]
    fn invalid_candidates_are_rejected_and_nothing_changes() {
        let mut m = manager("invalid");
        let bad = m.with_route("192.168.50.0/24", "172.16.0.1").unwrap();
        let err = m.set_candidate(bad).unwrap_err().to_string();
        assert!(err.contains("not on any connected subnet"), "{err}");
        assert!(m.commit(None).is_err(), "nothing staged");
        assert_eq!(m.running_text(), BASE);
    }

    #[test]
    fn structural_changes_need_a_restart() {
        let mut m = manager("restart");
        let p = m
            .set_candidate(BASE.replace("[management]", "[dataplane]\nworkers = 2\n\n[management]"))
            .unwrap();
        assert_eq!(p.apply, Apply::RestartRequired);
        let p = m
            .set_candidate(BASE.replace("10.10.2.1/24", "10.10.2.2/24"))
            .unwrap();
        assert_eq!(p.apply, Apply::Live, "readdressing is live");
        let p = m
            .set_candidate(BASE.replace("# lab router", "# renamed"))
            .unwrap();
        assert_eq!(
            p.apply,
            Apply::Unchanged,
            "comment-only edits change nothing"
        );
    }

    #[test]
    fn confirmed_commit_rolls_back_unless_confirmed() {
        let mut m = manager("confirm");
        let text = m.with_route("0.0.0.0/0", "10.10.1.254").unwrap();
        m.set_candidate(text).unwrap();
        let id = m.commit(Some(60)).unwrap().confirm_id.unwrap();
        assert!(m.pending_confirm_secs().is_some());
        // Timer fires without confirmation: back to the base config.
        let back = m.expire_pending(id).unwrap().unwrap();
        assert!(back.config.routes.is_empty());
        assert_eq!(m.running_text(), BASE);

        // Same again, but confirmed in time: the timer does nothing.
        let text = m.with_route("0.0.0.0/0", "10.10.1.254").unwrap();
        m.set_candidate(text).unwrap();
        let id = m.commit(Some(60)).unwrap().confirm_id.unwrap();
        m.confirm().unwrap();
        assert!(m.expire_pending(id).is_none());
        assert_eq!(m.running().routes.len(), 1);
    }

    #[test]
    fn gui_model_edits_only_touch_changed_sections() {
        let mut m = manager("model");
        let mut cfg = m.running().clone();
        cfg.interfaces[1].role = crate::config::RoleCfg::Outside;
        cfg.routes.push(crate::config::RouteCfg {
            prefix: "0.0.0.0/0".into(),
            via: "10.10.2.254".into(),
        });
        cfg.nat.masquerade = false;
        let text = m.text_from_model(&cfg).unwrap();
        assert!(
            text.starts_with("# lab router"),
            "comments outside changed sections survive:\n{text}"
        );
        assert!(
            text.contains("# the LAN-facing port"),
            "comment above a rewritten section survives:\n{text}"
        );
        assert!(text.contains("role = \"outside\""), "{text}");
        assert!(text.contains("masquerade = false"), "{text}");
        let p = m.set_candidate(text).unwrap();
        assert_eq!(p.apply, Apply::Live);
        let c = m.commit(None).unwrap().config;
        assert_eq!(c, cfg, "round-trips exactly");
        // No change -> identical text.
        assert_eq!(m.text_from_model(&cfg).unwrap(), m.running_text());
    }

    fn lab_nics() -> Vec<crate::mgmt::nics::Nic> {
        [
            ("eth0", true),
            ("eth1", false),
            ("eth2", false),
            ("eth3", false),
        ]
        .iter()
        .map(|&(n, k)| crate::mgmt::nics::Nic {
            name: n.into(),
            mac: String::new(),
            driver: String::new(),
            link: "up".into(),
            kernel: k,
        })
        .collect()
    }

    #[test]
    fn oversized_configs_are_refused() {
        let mut m = manager("huge");
        let big = BASE.to_string() + &"# padding\n".repeat(MAX_CONFIG_LINES);
        let e = m.set_candidate(big).unwrap_err().to_string();
        assert!(e.contains("too large"), "{e}");
        assert!(m
            .set_candidate(BASE.replace("# lab router", "# ok"))
            .is_ok());
    }

    #[test]
    fn interfaces_must_use_a_card_this_router_has() {
        let m = manager("nics").check_nics(lab_nics);
        let with = |device: &str| {
            let mut cfg = m.running().clone();
            cfg.interfaces.push(crate::config::InterfaceCfg {
                name: "lan-c".into(),
                device: device.into(),
                vlan: None,
                management: vec![],
                management_from: vec![],
                address: "10.10.3.1/24".into(),
                role: Default::default(),
                allow_new_sessions: None,
                mss_adjust: None,
                mtu: None,
                gateway: None,
                dhcp: None,
                pppoe: None,
                pppoe_session: None,
                addr_now: None,
                onlink: vec![],
            });
            m.text_from_model(&cfg).unwrap()
        };
        let mut m2 = manager("nics2").check_nics(lab_nics);
        let e = m2.set_candidate(with("eth9")).unwrap_err().to_string();
        assert!(
            e.contains("no network card named \"eth9\" (available: eth1, eth2, eth3)"),
            "{e}"
        );
        let e = m2.set_candidate(with("eth0")).unwrap_err().to_string();
        assert!(e.contains("eth0 is the management NIC"), "{e}");
        assert!(m2.set_candidate(with("eth3")).is_ok());
        // Without a NIC list (e.g. `ephemerisd --check`), only the file is checked.
        let mut m3 = manager("nics3");
        assert!(m3.set_candidate(with("eth9")).is_ok());
    }

    #[test]
    fn removing_the_last_route_in_the_gui_leaves_no_empty_list() {
        let mut m = manager("lastroute");
        let mut cfg = m.running().clone();
        cfg.routes.push(crate::config::RouteCfg {
            prefix: "192.168.77.0/24".into(),
            via: "10.10.2.10".into(),
        });
        let text = m.text_from_model(&cfg).unwrap();
        m.set_candidate(text).unwrap();
        m.commit(None).unwrap();
        cfg.routes.clear();
        let text = m.text_from_model(&cfg).unwrap();
        assert!(
            !text.contains("[[route]]") && !text.contains("route ="),
            "{text}"
        );
        assert!(!text.contains("[]"), "no empty lists anywhere:\n{text}");
        m.set_candidate(text).unwrap();
        m.commit(None).unwrap();
        // ...so the CLI's route add still works afterwards.
        let text = m.with_route("0.0.0.0/0", "10.10.2.10").unwrap();
        m.set_candidate(text).unwrap();
        assert_eq!(m.commit(None).unwrap().config.routes.len(), 1);
        // And a file that already says `route = []` is fine too.
        let mut doc: DocumentMut = BASE.parse().unwrap();
        doc["route"] = value(toml_edit::Array::new());
        m.set_candidate(doc.to_string()).unwrap();
        m.commit(None).unwrap();
        assert!(m.with_route("0.0.0.0/0", "10.10.2.10").is_ok());
    }

    #[test]
    fn new_sections_land_in_a_sensible_place() {
        let m = manager("layout");
        let mut cfg = m.running().clone();
        cfg.routes.push(crate::config::RouteCfg {
            prefix: "0.0.0.0/0".into(),
            via: "10.10.2.254".into(),
        });
        cfg.nat.pools.push(crate::config::NatPoolCfg {
            name: "public".into(),
            addresses: vec!["203.0.113.10".into()],
        });
        cfg.nat.rules.push(crate::config::NatRuleCfg {
            name: "servers".into(),
            source: Some("10.10.1.128/25".into()),
            destination: None,
            outbound: None,
            translate: "pool".into(),
            pool: Some("public".into()),
        });
        let text = m.text_from_model(&cfg).unwrap();
        let at = |s: &str| {
            text.find(s)
                .unwrap_or_else(|| panic!("{s} missing in:\n{text}"))
        };
        // interfaces, then routes, then nat with its pool and rule under it
        assert!(at("[[interface]]") < at("[[route]]"), "{text}");
        assert!(at("[[route]]") < at("[nat]"), "{text}");
        assert!(
            at("[nat]") < at("[[nat.pool]]") && at("[[nat.pool]]") < at("[[nat.rule]]"),
            "{text}"
        );
        assert!(
            at("[management]") < at("[[interface]]"),
            "existing order kept:\n{text}"
        );
        let back = Config::parse(&text).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn rollback_restores_previous_versions() {
        let mut m = manager("rollback");
        for gw in ["10.10.1.2", "10.10.1.3"] {
            let t = m.with_route("0.0.0.0/0", gw).unwrap();
            m.set_candidate(t).unwrap();
            m.commit(None).unwrap();
        }
        assert_eq!(m.running().routes[0].via, "10.10.1.3");
        m.rollback(1).unwrap();
        assert_eq!(m.running().routes[0].via, "10.10.1.2");
        assert!(m.rollback(99).is_err());
    }
}
