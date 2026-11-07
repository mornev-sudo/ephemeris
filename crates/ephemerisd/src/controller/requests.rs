//! What a controller may ask of the router (docs/controller-api.md):
//!
//! - **Config:** read and pushed. Everything goes through the same
//!   candidate → check → commit path as a change in the portal, and a push
//!   is always a confirmed commit, so a bad one undoes itself.
//! - **Live tables:** what the portal's pages show, for a controller's
//!   page someone has open.
//! - **Operations:** the router's SD-WAN key, software updates, a reboot
//!   (now or at a set time), restarting ephemerisd: what the portal's
//!   buttons do, audited as the controller's.

use super::link::Refused;
use crate::mgmt::configmgr::Apply;
use crate::mgmt::Shared;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use toml_edit::{value, DocumentMut, Item, Table};

/// Items in a live table's answer, at most (and by default).
const TABLE_MAX: usize = 1000;

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

fn failed(e: crate::mgmt::api::ApiError) -> Refused {
    refused("failed", e.1)
}

/// Answer request `typ` (`ok`, or what to refuse it with).
pub async fn handle(s: &Arc<Shared>, typ: &str, msg: &Value) -> Result<Value, Refused> {
    use crate::mgmt::api;
    // Lists: at most `limit` items (1000 at most), and how many there are.
    let limit = msg["limit"]
        .as_u64()
        .map_or(TABLE_MAX, |n| (n as usize).min(TABLE_MAX));
    let list = |v: Value, total: Option<usize>| {
        let all = v.as_array().cloned().unwrap_or_default();
        let total = total.unwrap_or(all.len());
        json!({ "items": all.into_iter().take(limit).collect::<Vec<_>>(), "total": total })
    };
    match typ {
        "sessions.get" => {
            let total = s.summary().sessions_active as usize;
            Ok(list(api::sessions_body(s, Some(limit)).await, Some(total)))
        }
        "routes.get" => Ok(list(api::routes_body(s), None)),
        "neighbors.get" => Ok(list(api::neighbors_body(s).await, None)),
        "dhcp.get" => Ok(api::dhcp_body(s)),
        "wan.get" => Ok(api::wan_body(s)),
        "overlay.get" => Ok(api::overlay_body(s)),
        "overlay.identity" => Ok(crate::mgmt::api::overlay_identity_body(s)),
        "system.update.check" => crate::mgmt::api::update_check_body().await.map_err(failed),
        "system.update" => {
            tracing::info!(target: "audit", "controller: software update started");
            crate::mgmt::api::update_start_body(s).await.map_err(failed)
        }
        "system.reboot" => reboot(msg).await,
        "restart" => {
            tracing::warn!(target: "audit", "controller: restart requested");
            later(s, Duration::from_secs(1));
            Ok(json!({ "restarting": true }))
        }
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

/// `system.reboot`: now, or at `"at"` (RFC 3339, in the next week).
async fn reboot(msg: &Value) -> Result<Value, Refused> {
    let secs = match msg["at"].as_str() {
        None => None,
        Some(at) => {
            use time::format_description::well_known::Rfc3339;
            let when = time::OffsetDateTime::parse(at, &Rfc3339)
                .map_err(|e| refused("bad_request", format!("at: an RFC 3339 time ({e})")))?;
            let secs = (when - time::OffsetDateTime::now_utc()).whole_seconds();
            if !(0..=7 * 86_400).contains(&secs) {
                return Err(refused("bad_request", "at: within the next week"));
            }
            Some(secs as u64)
        }
    };
    match secs {
        Some(n) if n > 0 => tracing::warn!(target: "audit", "controller: reboot in {n}s"),
        _ => tracing::warn!(target: "audit", "controller: reboot now"),
    }
    crate::mgmt::api::reboot_in(secs).await.map_err(failed)?;
    Ok(json!({ "in_secs": secs.unwrap_or(0) }))
}

/// Restart ephemerisd after `delay` (so the answer goes out first).
fn later(s: &Arc<Shared>, delay: Duration) {
    let s = s.clone();
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        s.stop.store(true, Ordering::Relaxed);
    });
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
        let text =
            keep_local(text, m.running()).map_err(|e| refused("bad_request", format!("{e:#}")))?;
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
        later(s, Duration::from_secs(1));
    }
    v["restarting"] = restarting.into();
    Ok(v)
}

/// The pushed config with what stays the router's own: its `[controller]`
/// section, so a push can't hand the router to another controller nor
/// unenrol it; and `[management] token_file`, so a push can't point the API
/// token at a file whose contents the controller knows (the config version,
/// say) and then use that token to reset the admin password.
fn keep_local(text: &str, running: &crate::config::Config) -> anyhow::Result<String> {
    let mut doc: DocumentMut = text.parse()?;
    doc.remove("controller");
    if let Some(c) = &running.controller {
        let mut t = Table::new();
        t["url"] = value(c.url.as_str());
        t["pin"] = value(c.pin.as_str());
        doc.insert("controller", Item::Table(t));
    }
    let token_file = running.management.token_file.as_str();
    match doc.get_mut("management").and_then(Item::as_table_like_mut) {
        Some(t) => {
            t.insert("token_file", value(token_file));
        }
        None if token_file != eph_config::ManagementCfg::default().token_file => {
            let mut t = Table::new();
            t["token_file"] = value(token_file);
            doc.insert("management", Item::Table(t));
        }
        None => {}
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFACE: &str =
        "[[interface]]\nname = \"lan\"\ndevice = \"eth1\"\naddress = \"10.0.0.1/24\"\n";

    #[test]
    fn a_push_keeps_the_routers_own_controller_section_and_token_file() {
        let parse = |t: &str| -> crate::config::Config { toml::from_str(t).unwrap() };
        let mut mine = parse(IFACE);
        mine.controller = Some(crate::config::ControllerCfg {
            url: "https://mine.example.net/".into(),
            pin: format!("sha256:{}", "ab".repeat(32)),
        });
        let pushed = format!(
            "[dataplane]\nworkers = 2\n\n[controller]\nurl = \"https://evil.example.net/\"\npin = \"x\"\n\n\
             [management]\nhostnames = [\"r1.example.net\"]\ntoken_file = \"/var/lib/ephemeris/config-version\"\n\n{IFACE}"
        );
        let kept = keep_local(&pushed, &mine).unwrap();
        assert!(
            kept.contains("mine.example.net") && !kept.contains("evil"),
            "{kept}"
        );
        let cfg = parse(&kept);
        assert_eq!(cfg.dataplane.workers, 2);
        // The rest of [management] is the push's; the token file isn't.
        assert_eq!(cfg.management.hostnames, ["r1.example.net"]);
        assert_eq!(cfg.management.token_file, "/var/lib/ephemeris/api-token");
        // Not enrolled: a push can't enrol it either.
        mine.controller = None;
        mine.management.token_file = "/var/lib/ephemeris/other-token".into();
        let none = keep_local(IFACE, &mine).unwrap();
        assert!(!none.contains("[controller]"), "{none}");
        // Without [management], the router's own token file is kept too.
        assert_eq!(
            parse(&none).management.token_file,
            "/var/lib/ephemeris/other-token"
        );
    }
}
