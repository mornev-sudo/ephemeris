//! Overlay crypto state that has to survive restarts (see the nonce and
//! replay rules in `eph_dataplane::overlay`):
//!
//! * `overlay-run`: this router's run number. Raised and saved *before* any
//!   packet is sealed with it, so a nonce is never used twice under a key.
//! * `overlay-peers`: the newest run seen from each peer sender, so after a
//!   restart packets captured from a peer's earlier runs are still refused.
//! * `overlay-moved`: peers found at another address than the one
//!   configured (a hub's PPPoE address changed), so a restart doesn't send
//!   to the stale one again.

use anyhow::{bail, Context, Result};
use std::path::Path;

const RUN_FILE: &str = "overlay-run";
const PEERS_FILE: &str = "overlay-peers";
const MOVED_FILE: &str = "overlay-moved";

/// A tether whose peer moved: (tether name, its configured address, where
/// the peer is now, its port).
pub type Moved = (String, std::net::Ipv4Addr, std::net::Ipv4Addr, u16);

pub fn load_moved(dir: &Path) -> Vec<Moved> {
    let Ok(text) = std::fs::read_to_string(dir.join(MOVED_FILE)) else {
        return vec![];
    };
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((
                f.next()?.to_string(),
                f.next()?.parse().ok()?,
                f.next()?.parse().ok()?,
                f.next()?.parse().ok()?,
            ))
        })
        .collect()
}

pub fn save_moved(dir: &Path, moved: &[Moved]) -> Result<()> {
    let text: String = moved
        .iter()
        .map(|(n, conf, now, port)| format!("{n} {conf} {now} {port}\n"))
        .collect();
    crate::files::write_private_atomic(&dir.join(MOVED_FILE), text.as_bytes())
}

/// Claim this start's run number (1, 2, ...).
pub fn claim_run(dir: &Path) -> Result<u16> {
    let p = dir.join(RUN_FILE);
    let last: u16 = match std::fs::read_to_string(&p) {
        Ok(s) => s
            .trim()
            .parse()
            .with_context(|| format!("{} is damaged", p.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    let Some(run) = last.checked_add(1) else {
        bail!(
            "overlay run numbers are used up (65535 restarts): set new tether keys on both \
             sites, then delete {}",
            p.display()
        );
    };
    crate::files::write_private_atomic(&p, format!("{run}\n").as_bytes())?;
    Ok(run)
}

/// (peer site id, sender worker, newest run) as last saved.
pub fn load_peers(dir: &Path) -> Vec<(u16, u8, u16)> {
    let Ok(text) = std::fs::read_to_string(dir.join(PEERS_FILE)) else {
        return vec![];
    };
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace().map(str::parse::<u32>);
            let (site, worker, run) = (f.next()?.ok()?, f.next()?.ok()?, f.next()?.ok()?);
            Some((
                u16::try_from(site).ok()?,
                u8::try_from(worker).ok()?,
                u16::try_from(run).ok()?,
            ))
        })
        .collect()
}

pub fn save_peers(dir: &Path, peers: &[(u16, u8, u16)]) -> Result<()> {
    let text: String = peers
        .iter()
        .map(|(s, w, r)| format!("{s} {w} {r}\n"))
        .collect();
    crate::files::write_private_atomic(&dir.join(PEERS_FILE), text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("eph-ovl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn runs_only_go_up() {
        let d = dir("run");
        assert_eq!(claim_run(&d).unwrap(), 1);
        assert_eq!(claim_run(&d).unwrap(), 2);
        std::fs::write(d.join(RUN_FILE), "65535\n").unwrap();
        assert!(claim_run(&d).unwrap_err().to_string().contains("used up"));
        std::fs::write(d.join(RUN_FILE), "garbage").unwrap();
        assert!(
            claim_run(&d).is_err(),
            "never guess: a reused run reuses nonces"
        );
    }

    #[test]
    fn moved_peers_round_trip() {
        let d = dir("moved");
        assert!(load_moved(&d).is_empty());
        let m = vec![(
            "jhb-wan".to_string(),
            "192.0.2.2".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
            4800,
        )];
        save_moved(&d, &m).unwrap();
        assert_eq!(load_moved(&d), m);
        std::fs::write(d.join(MOVED_FILE), "jhb-wan 192.0.2.2 nonsense 1\n").unwrap();
        assert!(load_moved(&d).is_empty());
    }

    #[test]
    fn peer_runs_round_trip() {
        let d = dir("peers");
        assert!(load_peers(&d).is_empty());
        save_peers(&d, &[(2, 0, 7), (3, 1, 9)]).unwrap();
        assert_eq!(load_peers(&d), vec![(2, 0, 7), (3, 1, 9)]);
        std::fs::write(d.join(PEERS_FILE), "2 0 7\nbad line\n2 999 1\n").unwrap();
        assert_eq!(load_peers(&d), vec![(2, 0, 7)]);
    }
}
