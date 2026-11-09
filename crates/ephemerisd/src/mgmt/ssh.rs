//! SSH policy from the config (`[ssh]`): whether passwords may be used to
//! log in over SSH, or only keys.
//!
//! sshd's own config is in the read-only image. Its first line includes
//! `/run/ephemeris-ssh/*.conf`, which ephemerisd writes here; sshd takes the
//! first value it reads for each setting, so these win. The console always
//! accepts the password: it's the way back in.
//!
//! At boot the policy is written before sshd starts (`ephemerisd
//! --ssh-policy`, from ssh.service), so sshd never starts with passwords a
//! key-only router refuses. A change while running restarts sshd rather
//! than reloading it: sshd gets port 22 from ssh.socket, and after a
//! reload (SIGHUP, it re-executes itself) it tries to bind the port itself,
//! fails, and SSH is down until systemd notices. A restart hands it the
//! socket again; logged-in sessions stay (KillMode=process).

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

/// The SSH settings sshd should start with, from the config file as it
/// stands (not yet checked: the router may still fall back to an earlier
/// one). Keys only without a key would be refused, so that's passwords.
fn before_start(text: &str, key_installed: bool) -> anyhow::Result<SshCfg> {
    let cfg: crate::config::Config = toml::from_str(text)?;
    Ok(SshCfg {
        password_login: cfg.ssh.password_login || !key_installed,
    })
}

/// Write the policy into `dir`; whether it changed.
fn write(dir: &Path, cfg: &SshCfg) -> std::io::Result<bool> {
    let path = dir.join(FILE);
    let text = policy(cfg);
    if std::fs::read_to_string(&path).is_ok_and(|t| t == text) {
        return Ok(false);
    }
    let tmp = dir.join(format!(".{FILE}.new"));
    std::fs::write(&tmp, &text).and_then(|()| std::fs::rename(&tmp, &path))?;
    Ok(true)
}

/// Before sshd starts: write the policy for the config file at `config`.
pub fn write_before_start(config: &Path) -> anyhow::Result<()> {
    let cfg = before_start(&std::fs::read_to_string(config)?, key_installed())?;
    std::fs::create_dir_all(DIR)?;
    write(Path::new(DIR), &cfg)?;
    Ok(())
}

/// Write the policy and, if it changed, restart sshd (if it's running).
/// Problems are logged, not fatal: SSH keeps its previous settings.
pub fn apply(cfg: &SshCfg) {
    let dir = Path::new(DIR);
    if !dir.is_dir() {
        return; // not on a router (development, tests)
    }
    match write(dir, cfg) {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            tracing::warn!(target: cat::MGMT, "SSH policy not written: {e}");
            return;
        }
    }
    let ok = std::process::Command::new("systemctl")
        .args(["try-restart", "--no-block", "ssh.service"])
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
        tracing::warn!(target: cat::MGMT, "SSH logins set to {what}, but sshd didn't restart");
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

    const IFACE: &str = "[[interface]]\nname = \"lan\"\ndevice = \"ens19\"\nrole = \"inside\"\naddress = \"10.0.0.1/24\"\n";

    #[test]
    fn sshd_starts_with_the_config_files_policy() {
        let keys_only = format!("[ssh]\npassword_login = false\n{IFACE}");
        assert!(!before_start(&keys_only, true).unwrap().password_login);
        assert!(before_start(IFACE, true).unwrap().password_login);
        // Without a key the config would be refused: passwords stay.
        assert!(before_start(&keys_only, false).unwrap().password_login);
        assert!(before_start("not toml [", true).is_err());
    }

    #[test]
    fn an_unchanged_policy_isnt_written_again() {
        let dir = std::env::temp_dir().join(format!("eph-ssh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let keys_only = SshCfg {
            password_login: false,
        };
        assert!(write(&dir, &keys_only).unwrap());
        assert!(!write(&dir, &keys_only).unwrap());
        assert!(write(&dir, &SshCfg::default()).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
