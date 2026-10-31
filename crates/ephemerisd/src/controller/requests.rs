//! What a controller may ask of the router (docs/controller-api.md,
//! Config): its config, read and pushed. Everything goes through the same
//! candidate → check → commit path as a change in the portal, and a push is
//! always a confirmed commit, so a bad one undoes itself.

use super::link::Refused;
use crate::mgmt::configmgr::Apply;
use crate::mgmt::Shared;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use toml_edit::{value, DocumentMut, Item, Table};

/// How long a push may wait for its confirmation.
const CONFIRM_SECS: std::ops::RangeInclusive<u64> = 30..=3600;

/// A config's SHA-256, in hex: what a controller knows it by.
fn sha256(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
    crate::sdwan::hex(&digest)
}

fn refused(code: &str, message: impl Into<String>) -> Refused {
    Refused {
        code: code.into(),
        message: message.into(),
    }
}

/// Answer request `typ` (`ok`, or what to refuse it with).
pub fn handle(s: &Arc<Shared>, typ: &str, msg: &Value) -> Result<Value, Refused> {
    match typ {
        "config.get" => {
            let m = s.config.lock().unwrap();
            Ok(json!({
                "config": m.running_text(),
                "version": m.version(),
                "sha256": sha256(m.running_text()),
            }))
        }
        "config.history" => {
            let m = s.config.lock().unwrap();
            let h = m
                .history()
                .map_err(|e| refused("failed", format!("{e:#}")))?;
            Ok(json!({ "version": m.version(), "history": h }))
        }
        "config.push" => push(s, msg),
        "config.confirm" => {
            let mut m = s.config.lock().unwrap();
            m.confirm()
                .map_err(|e| refused("not_pending", format!("{e:#}")))?;
            tracing::info!(target: "audit", "controller: confirmed config version {}", m.version());
            Ok(json!({ "version": m.version() }))
        }
        _ => Err(refused(
            "unknown_type",
            format!("this router doesn't know {typ:?}"),
        )),
    }
}

/// `config.push`: a complete config, made from the running one
/// (`base_sha256`), committed as a confirmed commit.
fn push(s: &Arc<Shared>, msg: &Value) -> Result<Value, Refused> {
    let text = msg["config"]
        .as_str()
        .ok_or_else(|| refused("bad_request", "config: the complete ephemeris.toml"))?;
    let base = msg["base_sha256"]
        .as_str()
        .ok_or_else(|| refused("bad_request", "base_sha256: the config it was made from"))?;
    let secs = msg["confirm_within_secs"]
        .as_u64()
        .filter(|n| CONFIRM_SECS.contains(n))
        .ok_or_else(|| refused("bad_request", "confirm_within_secs: 30 to 3600"))?;
    let restart = msg["restart"].as_bool().unwrap_or(false);
    let comment = msg["comment"].as_str().unwrap_or("");
    let committed = {
        let mut m = s.config.lock().unwrap();
        let running = sha256(m.running_text());
        if base != running {
            return Err(refused(
                "conflict",
                format!(
                    "the router runs config version {} ({running}), not the one this push was made from",
                    m.version()
                ),
            ));
        }
        if m.pending_confirm().is_some() {
            return Err(refused("conflict", "a confirmed commit is still waiting"));
        }
        let text = keep_controller(text, m.running().controller.as_ref())
            .map_err(|e| refused("bad_request", format!("{e:#}")))?;
        m.set_candidate(text)
            .map_err(|e| refused("bad_request", format!("{e:#}")))?;
        m.commit(Some(secs))
            .map_err(|e| refused("bad_request", format!("{e:#}")))?
    };
    let apply = committed.apply;
    let mut v = crate::mgmt::api::commit_done(s, committed, Some(secs), "config.committed")
        .map_err(|e| refused("failed", format!("{e:#}")))?;
    let (version, sha256) = {
        let m = s.config.lock().unwrap();
        (m.version(), sha256(m.running_text()))
    };
    let note = if comment.is_empty() {
        String::new()
    } else {
        format!(": {comment}")
    };
    tracing::info!(target: "audit",
        "controller: config pushed (version {version}, confirm within {secs}s){note}");
    v["version"] = version.into();
    v["sha256"] = sha256.into();
    // A change that only takes effect after a restart, asked to restart:
    // shortly, so the answer goes out first. The confirm deadline goes on
    // across it (it's saved), so a push that breaks the start is undone.
    let restarting = restart && apply == Apply::RestartRequired;
    if restarting {
        tracing::warn!(target: crate::logging::cat::CONFIG, "restarting for the pushed config");
        let s = s.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            s.stop.store(true, Ordering::Relaxed);
        });
    }
    v["restarting"] = restarting.into();
    Ok(v)
}

/// The pushed config with the router's own `[controller]` section: a push
/// can't hand the router to another controller, nor unenrol it.
fn keep_controller(
    text: &str,
    mine: Option<&crate::config::ControllerCfg>,
) -> anyhow::Result<String> {
    let mut doc: DocumentMut = text.parse()?;
    doc.remove("controller");
    if let Some(c) = mine {
        let mut t = Table::new();
        t["url"] = value(c.url.as_str());
        t["pin"] = value(c.pin.as_str());
        doc.insert("controller", Item::Table(t));
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_keeps_the_routers_own_controller_section() {
        let mine = crate::config::ControllerCfg {
            url: "https://mine.example.net/".into(),
            pin: format!("sha256:{}", "ab".repeat(32)),
        };
        let pushed = "[dataplane]\nworkers = 2\n\n[controller]\nurl = \"https://evil.example.net/\"\npin = \"x\"\n";
        let kept = keep_controller(pushed, Some(&mine)).unwrap();
        assert!(
            kept.contains("mine.example.net") && !kept.contains("evil"),
            "{kept}"
        );
        assert!(kept.contains("workers = 2"));
        // Not enrolled: a push can't enrol it either.
        let none = keep_controller(pushed, None).unwrap();
        assert!(!none.contains("[controller]"), "{none}");
    }
}
