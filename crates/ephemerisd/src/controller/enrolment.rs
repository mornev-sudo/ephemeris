//! Enrolling with a controller: asked for (`ephctl controller enrol`, the
//! portal, the API), or by itself at start from a string handed over when
//! it was deployed (zero-touch: a router plugged in at a site enrols with no
//! one logging in). That string comes from the `ephemeris.controller`
//! credential (a VM's SMBIOS strings, say) or the file [`FILE`] (written by
//! an installer, or by hand). Either way, the same steps: connect with the
//! string's pin, register this router's key with its token, commit the
//! `[controller]` section.
//!
//! A token works once, so the router remembers which credential it enrolled
//! with ([`USED_FILE`]): unenrolled later, it doesn't try the spent token
//! again at every boot.

use crate::mgmt::Shared;
use eph_config::Enrolment;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// The systemd credential with an enrolment string.
pub const CREDENTIAL: &str = "ephemeris.controller";
/// In the state directory: an enrolment string, removed once used.
pub const FILE: &str = "enrolment";
/// Next to the config: the SHA-256 of the credential last enrolled with.
pub const USED_FILE: &str = "controller-enrolled";

#[derive(Debug)]
pub enum EnrolError {
    /// Already managed by this controller.
    Managed(String),
    /// No management key pair (see the log).
    NoIdentity,
    /// Connecting, or the controller refused.
    Controller(anyhow::Error),
    /// Enrolled, but committing `[controller]` failed.
    Commit(anyhow::Error),
}

impl std::fmt::Display for EnrolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrolError::Managed(url) => {
                write!(f, "already managed by {url}: remove [controller] first")
            }
            EnrolError::NoIdentity => {
                write!(f, "no controller key pair: see `ephctl log show -c mgmt`")
            }
            EnrolError::Controller(e) => write!(f, "{e:#}"),
            EnrolError::Commit(e) => write!(f, "enrolled, but saving [controller] failed: {e:#}"),
        }
    }
}

/// Enrol, then commit `[controller]`: what enrolling got (the controller's
/// id for this router; whether it waits for approval), and the commit's
/// outcome (as the API answers commits). A router waiting for approval is
/// committed too: it keeps connecting until it's let in.
pub async fn enrol(
    s: &Arc<Shared>,
    e: &Enrolment,
) -> Result<(super::link::Enrolled, Value), EnrolError> {
    if let Some(c) = &s.config.lock().unwrap().running().controller {
        return Err(EnrolError::Managed(c.url.clone()));
    }
    let id = s
        .controller_identity
        .clone()
        .ok_or(EnrolError::NoIdentity)?;
    let hello = super::link::hello(s);
    let enrolled = super::link::enrol(e, &id, hello)
        .await
        .map_err(EnrolError::Controller)?;
    let waiting = if enrolled.pending {
        ", waiting for approval"
    } else {
        ""
    };
    tracing::info!(target: "audit",
        "enrolled with controller {} as router {}{waiting}", e.url, enrolled.router_id);
    let committed = {
        let mut cfg = s.config.lock().unwrap();
        cfg.with_controller(&e.controller())
            .and_then(|text| cfg.set_candidate(text))
            .and_then(|_| cfg.commit(None))
            .map_err(EnrolError::Commit)?
    };
    let v = crate::mgmt::api::commit_done(s, committed, None, "config.committed")
        .map_err(EnrolError::Commit)?;
    Ok((enrolled, v))
}

fn digest(text: &str) -> String {
    crate::sdwan::hex(&<[u8; 32]>::from(Sha256::digest(text.trim().as_bytes())))
}

/// The enrolment string handed over at deployment, if there is one this
/// router hasn't already enrolled with: the credential, else the file. A
/// string that doesn't parse is logged and ignored.
pub fn handed_over(state_dir: &Path) -> Option<Enrolment> {
    let credential = std::env::var_os("CREDENTIALS_DIRECTORY")
        .and_then(|d| std::fs::read_to_string(Path::new(&d).join(CREDENTIAL)).ok())
        .and_then(|text| from_text(&text, state_dir));
    credential.or_else(|| {
        let text = std::fs::read_to_string(state_dir.join(FILE)).ok()?;
        from_text(&text, state_dir)
    })
}

fn from_text(text: &str, state_dir: &Path) -> Option<Enrolment> {
    let used = std::fs::read_to_string(state_dir.join(USED_FILE)).unwrap_or_default();
    if used.trim() == digest(text) {
        return None;
    }
    match Enrolment::parse(text) {
        Ok(e) => Some(e),
        Err(err) => {
            tracing::error!(target: crate::logging::cat::MGMT,
                "the {CREDENTIAL} credential isn't an enrolment string ({err:#}): ignored");
            None
        }
    }
}

/// Remember that this string was used (successfully), and remove the file
/// it may have come from: its token is spent.
pub fn mark_used(state_dir: &Path, e: &Enrolment) {
    let line = format!("{}\n", digest(&e.to_string()));
    if let Err(err) =
        crate::files::write_private_atomic(&state_dir.join(USED_FILE), line.as_bytes())
    {
        tracing::warn!(target: crate::logging::cat::MGMT, "remembering the used enrolment: {err:#}");
    }
    let file = state_dir.join(FILE);
    if std::fs::read_to_string(&file).is_ok_and(|t| digest(&t) == digest(&e.to_string())) {
        let _ = std::fs::remove_file(file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_used_credential_isnt_tried_again() {
        let d = std::env::temp_dir().join(format!("eph-enrol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let text = format!(
            "eph-enrol:v1:https://c.example.net/#{}@{}\n",
            "A".repeat(43),
            "ab".repeat(32)
        );
        let e = from_text(&text, &d).expect("not used yet");
        assert_eq!(e.url, "https://c.example.net/");
        mark_used(&d, &e);
        assert!(from_text(&text, &d).is_none(), "spent");
        // Another string (a new token) is tried.
        let other = text.replace(&"A".repeat(43), &"B".repeat(43));
        assert!(from_text(&other, &d).is_some());
        // Nonsense is ignored, not an error.
        assert!(from_text("hello", &d).is_none());

        // From the file (an installer's): used, then removed.
        std::fs::write(d.join(FILE), &other).unwrap();
        let e = handed_over(&d).expect("the file");
        assert_eq!(e.token, "B".repeat(43));
        mark_used(&d, &e);
        assert!(!d.join(FILE).exists(), "the spent token is gone");
        assert!(handed_over(&d).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
