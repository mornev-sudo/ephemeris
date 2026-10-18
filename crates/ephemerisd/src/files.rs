//! Writing the router's state files. They can hold tether keys and password
//! hashes, so every file is owner-only (0600), and replaced atomically: a
//! crash or power cut leaves either the old or the new version.

use anyhow::{Context, Result};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Create or truncate `path` (mode 0600 if new) and write `data`, synced.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    // An existing file keeps its mode on open: tighten it.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Replace `path` with `data` atomically: a private temporary file, synced,
/// renamed over it, then the directory synced so the rename itself survives.
pub fn write_private_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    write_private(&tmp, data)?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Make existing state files owner-only (they were 0644 before tether keys
/// lived in the config). Errors are ignored: a file that's gone is fine.
pub fn tighten(paths: impl IntoIterator<Item = std::path::PathBuf>) {
    for p in paths {
        if let Ok(m) = std::fs::metadata(&p) {
            if m.is_file() && m.permissions().mode() & 0o077 != 0 {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_private_and_replaced_whole() {
        let dir = std::env::temp_dir().join(format!("eph-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.toml");
        std::fs::write(&p, "old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_atomic(&p, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!dir.join(".x.toml.tmp").exists());
        let q = dir.join("y.toml");
        std::fs::write(&q, "k").unwrap();
        std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o644)).unwrap();
        tighten([q.clone(), dir.join("missing")]);
        let mode = std::fs::metadata(&q).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
