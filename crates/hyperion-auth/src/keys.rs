//! Secret key file management.
//!
//! Loads a 32-byte Ed25519 secret from a path. If the file is absent,
//! generates a fresh one and persists it with mode 0600. Idempotent
//! and safe across process restarts.

use base64::Engine;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Load or initialize a 32-byte secret at `path`. Returns the bytes.
pub fn load_or_init(path: &Path) -> io::Result<[u8; 32]> {
    if let Ok(s) = std::fs::read_to_string(path) {
        let trimmed = s.trim();
        let bytes = B64
            .decode(trimmed)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if bytes.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected 32 bytes, got {}", bytes.len()),
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    let encoded = B64.encode(bytes);
    std::fs::write(path, encoded)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_creates_file_with_0600() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("sess.key");
        let bytes = load_or_init(&p).expect("first");
        assert_eq!(bytes.len(), 32);
        let m = std::fs::metadata(&p).expect("md").permissions().mode() & 0o777;
        assert_eq!(m, 0o600);
    }

    #[test]
    fn second_call_returns_same_bytes() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("sess.key");
        let a = load_or_init(&p).expect("first");
        let b = load_or_init(&p).expect("second");
        assert_eq!(a, b);
    }

    #[test]
    fn corrupt_file_returns_error() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("sess.key");
        std::fs::write(&p, "not base64!!!").expect("write");
        assert!(load_or_init(&p).is_err());
    }
}
