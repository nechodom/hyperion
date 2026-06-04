//! Authentication primitives shared between hyperion-web (Foundation) and the
//! future controller's admin UI / client portal.
//!
//! - [`password`] — argon2id hash & verify
//! - [`session`] — Ed25519-signed session tokens carried in cookies
//! - [`csrf`] — HMAC-based CSRF tokens scoped to a session id
//! - [`keys`] — load/persist secret keys from disk
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod bundle_sig;
pub mod csrf;
pub mod keys;
pub mod password;
pub mod session;
pub mod totp;

pub use password::{hash_password, verify_password, PasswordError};
pub use session::{Session, SessionError, SessionSigner, PURPOSE_PENDING_2FA, PURPOSE_SESSION};
pub use totp::{
    code_at, generate_backup_codes, generate_secret_base32, hash_backup_code, otpauth_url,
    verify_code, verify_code_at, TotpError,
};
