//! SSH policy from the config (`[ssh]`): whether passwords may be used to
//! log in over SSH, or only keys.
//!
//! sshd's own config is in the read-only image. Its first line includes
//! `/run/ephemeris-ssh/*.conf`, which ephemerisd writes here; sshd takes the
//! first value it reads for each setting, so these win. The console always
//! accepts the password: it's the way back in.

use crate::config::SshCfg;
use crate::logging::cat;
use std::path::Path;

/// systemd creates it for ephemerisd (RuntimeDirectory=ephemeris-ssh).
pub const DIR: &str = "/run/ephemeris-ssh";
const FILE: &str = "50-ephemeris.conf";
/// Where SSH keys for root come from (the deployment credential, or added
/// by hand).
const KEY_FILES: &[&str] = &[
    "/var/lib/ephemeris/ssh/authorized_keys.root",
    "/root/.ssh/authorized_keys",
];

/// The sshd settings for `cfg`.
pub fn policy(cfg: &SshCfg) -> String {
    let mut s = String::from("# Written by ephemerisd from [ssh] in the router config.\n");
    if !cfg.password_login {
        s.push_str("PasswordAuthentication no\nKbdInteractiveAuthentication no\n");
    }
    s
}

/// Is at least one SSH key installed for root? (Turning passwords off
/// without one would leave only the console.)
pub fn key_installed() -> bool {
    KEY_FILES.iter().any(|f| {
        std::fs::read_to_string(f).is_ok_and(|t| {
            t.lines()
                .map(str::trim)
                .any(|l| !l.is_empty() && !l.starts_with('#'))
        })
    })
}

/// Write the policy and, if it changed, have sshd reload it. Problems are
/// logged, not fatal: SSH keeps its previous settings.
pub fn apply(cfg: &SshCfg) {
    let dir = Path::new(DIR);
    if !dir.is_dir() {
        return; // not on a router (development, tests)
    }
    let path = dir.join(FILE);
    let text = policy(cfg);
    if std::fs::read_to_string(&path).is_ok_and(|t| t == text) {
        return;
    }
    let tmp = dir.join(format!(".{FILE}.new"));
    if let Err(e) = std::fs::write(&tmp, &text).and_then(|()| std::fs::rename(&tmp, &path)) {
        tracing::warn!(target: cat::MGMT, "SSH policy not written: {e}");
        return;
    }
    let ok = std::process::Command::new("systemctl")
        .args(["reload-or-restart", "--no-block", "ssh.service"])
        .status()
        .is_ok_and(|s| s.success());
    let what = if cfg.password_login {
        "keys and passwords"
    } else {
        "keys only"
    };
    if ok {
        tracing::info!(target: cat::AUDIT, "SSH logins: {what}");
    } else {
        tracing::warn!(target: cat::MGMT, "SSH logins set to {what}, but sshd didn't reload");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_only_turns_passwords_off() {
        assert!(!policy(&SshCfg {
            password_login: true
        })
        .contains("PasswordAuthentication"));
        let p = policy(&SshCfg {
            password_login: false,
        });
        assert!(p.contains("PasswordAuthentication no\n"));
        assert!(p.contains("KbdInteractiveAuthentication no\n"));
    }
}
