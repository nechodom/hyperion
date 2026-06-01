//! Argon2id password hash + verify.

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("hash error: {0}")]
    Hash(String),
    #[error("verify error: {0}")]
    Verify(String),
}

fn argon2() -> Argon2<'static> {
    // m=64MiB, t=3, p=1 — OWASP recommended for interactive use.
    let params = Params::new(64 * 1024, 3, 1, None).unwrap_or_else(|_| Params::default());
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password. Returns a PHC-encoded string suitable for storage.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    if password.is_empty() {
        return Err(PasswordError::Hash("empty password".into()));
    }
    let salt = SaltString::generate(&mut OsRng);
    let h = argon2()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PasswordError::Hash(e.to_string()))?;
    Ok(h.to_string())
}

/// Verify a password against a stored PHC string. Constant-time on success.
pub fn verify_password(password: &str, phc: &str) -> Result<bool, PasswordError> {
    let parsed = argon2::password_hash::PasswordHash::new(phc)
        .map_err(|e| PasswordError::Verify(e.to_string()))?;
    match argon2().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::Verify(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ok() {
        let phc = hash_password("hunter2").expect("hash");
        assert!(phc.starts_with("$argon2id"));
        assert!(verify_password("hunter2", &phc).expect("verify"));
    }

    #[test]
    fn wrong_password_rejected() {
        let phc = hash_password("hunter2").expect("hash");
        assert!(!verify_password("hunter3", &phc).expect("verify"));
    }

    #[test]
    fn empty_password_refused_at_hash() {
        let r = hash_password("");
        assert!(r.is_err());
    }

    #[test]
    fn malformed_phc_is_error() {
        let r = verify_password("x", "not-a-phc-string");
        assert!(r.is_err());
    }

    #[test]
    fn each_hash_has_different_salt() {
        let a = hash_password("same").expect("hash");
        let b = hash_password("same").expect("hash");
        assert_ne!(a, b, "salts should differ");
        assert!(verify_password("same", &a).expect("v"));
        assert!(verify_password("same", &b).expect("v"));
    }
}
