//! Authentication primitives shared between hyperion-web (Foundation) and the
//! future controller's admin UI / client portal.
//!
//! - [`password`] — argon2id hash & verify
//! - [`session`] — Ed25519-signed session tokens carried in cookies
//! - [`csrf`] — HMAC-based CSRF tokens scoped to a session id
//! - [`keys`] — load/persist secret keys from disk
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod csrf;
pub mod keys;
pub mod password;
pub mod session;

pub use password::{hash_password, verify_password, PasswordError};
pub use session::{Session, SessionError, SessionSigner};
