//! This router's identity towards a controller (docs/controller-api.md): an
//! Ed25519 key pair, made on first use and kept in
//! `/var/lib/ephemeris/controller-identity` as its 32-byte seed in hex. Its
//! public key is the router's id to the controller: the key of the TLS
//! client certificate the router presents, and what enrolment registers.
//!
//! It's separate from the SD-WAN identity (`sdwan::Identity`), which is an
//! X25519 key for Noise handshakes and can't sign.

use crate::sdwan::{hex, parse_hex32};
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::path::Path;

/// Where the seed is kept, in the router's state directory.
pub const FILE: &str = "controller-identity";

/// This router's management key pair.
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| anyhow::anyhow!("no randomness for a new key: {e}"))?;
        Ok(Self::from_seed(seed))
    }

    /// The public key: 32 bytes, shown as 64 lowercase hex characters.
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The identity kept in `dir`, made on first use. A damaged file is an
    /// error, never silently replaced: a new key would be a different
    /// router to the controller. Only the public half leaves the router.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let p = dir.join(FILE);
        match std::fs::read_to_string(&p) {
            Ok(s) => {
                let seed =
                    parse_hex32(s.trim()).with_context(|| format!("{} is damaged", p.display()))?;
                Ok(Self::from_seed(seed))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = Self::generate()?;
                crate::files::write_private_atomic(
                    &p,
                    format!("{}\n", hex(id.key.as_bytes())).as_bytes(),
                )?;
                Ok(id)
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity(public {})", hex(&self.public()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_is_kept_and_never_printed() {
        let d = std::env::temp_dir().join(format!("eph-ctl-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let a = Identity::load_or_create(&d).unwrap();
        let b = Identity::load_or_create(&d).unwrap();
        assert_eq!(a.public(), b.public());
        let seed = std::fs::read_to_string(d.join(FILE)).unwrap();
        assert!(
            !format!("{a:?}").contains(seed.trim()),
            "the seed never prints"
        );
        // Not the SD-WAN identity's file, nor its key.
        let sdwan = crate::sdwan::Identity::load_or_create(&d).unwrap();
        assert_ne!(sdwan.public, a.public());
        std::fs::write(d.join(FILE), "nonsense").unwrap();
        assert!(
            Identity::load_or_create(&d).is_err(),
            "never replaced silently"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_public_key_follows_from_the_seed() {
        // RFC 8032, section 7.1, test 1.
        let seed = parse_hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        assert_eq!(
            hex(&Identity::from_seed(seed).public()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }
}
