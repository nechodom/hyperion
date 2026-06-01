//! Input validation primitives. Every public type carries proof that
//! its value matches a strict whitelist regex.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

pub mod domain;
pub mod sysuser;

pub use domain::Domain;
pub use sysuser::SystemUserName;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("invalid domain '{0}': {1}")]
    InvalidDomain(String, &'static str),
    #[error("invalid system user '{0}': {1}")]
    InvalidSystemUser(String, &'static str),
}
