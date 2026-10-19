//! Surviving a configuration the data plane can't start with.
//!
//! Validation catches most mistakes, but some only show up when the data
//! plane starts (a card that was removed, a driver that refuses XDP). Without
//! help, ephemerisd would exit, systemd would start it again with the same
//! file, and the API and portal (which live in ephemerisd) would never come up.
//!
//! So: once the data plane has started, that config is saved as the *last
//! good* one. If a different config later fails, it's set aside and the last
//! good one is put back, then ephemerisd exits so systemd restarts it (which
//! also re-runs NIC setup for the restored config). If the last good config
//! itself fails, there's nothing better to go back to: ephemerisd runs the
//! management plane alone and reports why the data plane isn't running.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const LAST_GOOD: &str = "last-good.toml";
const NOTE: &str = "fallback.json";

/// Shown in status after a fallback, until ephemerisd next restarts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fallback {
    pub failed_unix: u64,
    pub error: String,
    /// Where the config that failed was kept.
    pub failed_file: String,
}

/// What the management plane reports about how this start went.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StartupState {
    /// The data plane isn't running (management only): why.
    pub dataplane_error: Option<String>,
    /// This run uses the last good config because a newer one failed.
    pub fallback: Option<Fallback>,
}

fn state_dir(config: &Path) -> PathBuf {
    config.parent().unwrap_or(Path::new(".")).to_path_buf()
}

/// The data plane started with `text`: remember it.
pub fn mark_good(config: &Path, text: &str) -> Result<()> {
    let p = state_dir(config).join(LAST_GOOD);
    if std::fs::read_to_string(&p).ok().as_deref() == Some(text) {
        return Ok(());
    }
    write_atomic(&p, text)
}

/// The data plane failed with `text`. If an earlier config is known to work
/// and differs, put it back and return true: the caller should exit so the
/// router restarts with it. False means there's nothing better to go back to.
pub fn fall_back(config: &Path, text: &str, error: &str, now_unix: u64) -> Result<bool> {
    let dir = state_dir(config);
    let Ok(good) = std::fs::read_to_string(dir.join(LAST_GOOD)) else {
        return Ok(false);
    };
    if good == text {
        return Ok(false);
    }
    let name = config
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ephemeris.toml");
    let failed = dir.join(format!("{name}.failed-{now_unix}"));
    crate::files::write_private(&failed, text.as_bytes())
        .with_context(|| format!("saving {}", failed.display()))?;
    prune_failed(&dir, name);
    let note = Fallback {
        failed_unix: now_unix,
        error: error.to_string(),
        failed_file: failed.display().to_string(),
    };
    write_atomic(&dir.join(NOTE), &serde_json::to_string(&note)?)?;
    write_atomic(config, &good)?;
    Ok(true)
}

/// How many failed configs to keep for inspection.
pub const FAILED_KEEP: usize = 5;

/// Remove all but the newest [`FAILED_KEEP`] `<name>.failed-<unix>` files, so
/// a config that keeps failing can't fill the disk.
fn prune_failed(dir: &Path, name: &str) {
    let prefix = format!("{name}.failed-");
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut kept: Vec<(u64, PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            let at = n.strip_prefix(&prefix)?.parse().ok()?;
            Some((at, e.path()))
        })
        .collect();
    kept.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    for (_, p) in kept.into_iter().skip(FAILED_KEEP) {
        let _ = std::fs::remove_file(p);
    }
}

/// A fallback that happened just before this start, if any. Read once: the
/// next restart starts with a clean slate.
pub fn take_note(config: &Path) -> Option<Fallback> {
    let p = state_dir(config).join(NOTE);
    let note = std::fs::read_to_string(&p).ok()?;
    let _ = std::fs::remove_file(&p);
    serde_json::from_str(&note).ok()
}

/// Owner-only, and a power cut leaves either the old or the new file.
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    crate::files::write_private_atomic(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("eph-startup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("ephemeris.toml")
    }

    #[test]
    fn a_failing_new_config_is_replaced_by_the_last_good_one() {
        let cfg = dir("fallback");
        std::fs::write(&cfg, "good").unwrap();
        mark_good(&cfg, "good").unwrap();
        std::fs::write(&cfg, "bad").unwrap();
        assert!(fall_back(&cfg, "bad", "device ens16 is down", 1000).unwrap());
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "good");
        let kept = cfg.with_file_name("ephemeris.toml.failed-1000");
        assert_eq!(std::fs::read_to_string(kept).unwrap(), "bad");
        let note = take_note(&cfg).unwrap();
        assert_eq!(note.error, "device ens16 is down");
        assert!(take_note(&cfg).is_none(), "shown for one start only");
    }

    #[test]
    fn only_the_newest_failed_configs_are_kept() {
        let cfg = dir("prune");
        std::fs::write(&cfg, "good").unwrap();
        mark_good(&cfg, "good").unwrap();
        for at in 1..=8 {
            std::fs::write(&cfg, format!("bad {at}")).unwrap();
            assert!(fall_back(&cfg, &format!("bad {at}"), "e", at).unwrap());
        }
        let d = cfg.parent().unwrap();
        let mut left: Vec<String> = std::fs::read_dir(d)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.contains(".failed-"))
            .collect();
        left.sort();
        let want: Vec<String> = (4..=8)
            .map(|n| format!("ephemeris.toml.failed-{n}"))
            .collect();
        assert_eq!(left, want);
    }

    #[test]
    fn no_fallback_without_something_better() {
        let cfg = dir("nothing");
        std::fs::write(&cfg, "only").unwrap();
        // Never started: nothing known to work.
        assert!(!fall_back(&cfg, "only", "e", 1).unwrap());
        // The last good config itself fails (e.g. a NIC was removed): no
        // loop, the caller runs management only.
        mark_good(&cfg, "only").unwrap();
        assert!(!fall_back(&cfg, "only", "e", 2).unwrap());
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), "only");
        assert!(take_note(&cfg).is_none());
    }
}
