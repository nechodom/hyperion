//! Single-user admin record on disk.

use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminUser {
    /// Numeric ID, conventionally 1 for the bootstrap user.
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("password: {0}")]
    Password(#[from] lm_auth::PasswordError),
    #[error("not found")]
    NotFound,
}

/// Load the admin user, or return NotFound if the file is absent.
pub fn load(path: &Path) -> Result<AdminUser, UserError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(UserError::NotFound),
        Err(e) => return Err(e.into()),
    };
    Ok(serde_json::from_slice(&bytes)?)
}

/// Persist the admin user at `path`. Mode 0600.
pub fn save(path: &Path, user: &AdminUser) -> Result<(), UserError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let bytes = serde_json::to_vec_pretty(user)?;
    let tmp = with_ext(path, "tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Create a new admin user with the given username + plaintext password.
pub fn create(username: &str, password: &str) -> Result<AdminUser, UserError> {
    let phc = lm_auth::hash_password(password)?;
    Ok(AdminUser {
        id: 1,
        username: username.to_string(),
        password_hash: phc,
        created_at: lm_types::now_secs(),
    })
}

/// Verify a password against the loaded user. Returns Ok(true) on match.
pub fn verify(user: &AdminUser, password: &str) -> Result<bool, UserError> {
    Ok(lm_auth::verify_password(password, &user.password_hash)?)
}

fn with_ext(p: &Path, ext: &str) -> std::path::PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    s.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_perms_0600() {
        let d = tempfile::tempdir().expect("dir");
        let path = d.path().join("u.json");
        let u = create("kevin", "hunter2").expect("create");
        save(&path, &u).expect("save");
        let back = load(&path).expect("load");
        assert_eq!(back, u);
        let m = std::fs::metadata(&path).expect("md").permissions().mode() & 0o777;
        assert_eq!(m, 0o600);
    }

    #[test]
    fn verify_works() {
        let u = create("k", "hunter2").expect("create");
        assert!(verify(&u, "hunter2").expect("ok"));
        assert!(!verify(&u, "wrong").expect("ok"));
    }

    #[test]
    fn load_missing_returns_not_found() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("missing.json");
        match load(&p).unwrap_err() {
            UserError::NotFound => {}
            other => panic!("wrong: {other:?}"),
        }
    }
}
