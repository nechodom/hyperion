//! Input validation primitives. Every public type carries proof that
//! its value matches a strict whitelist regex.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod certname;
pub mod domain;
pub mod ftplogin;
pub mod sysuser;

pub use certname::{name_matches, uncovered_names};
pub use domain::Domain;
pub use ftplogin::{compose_extra_login, validate_login_name};
pub use sysuser::SystemUserName;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("invalid domain '{0}': {1}")]
    InvalidDomain(String, &'static str),
    #[error("invalid system user '{0}': {1}")]
    InvalidSystemUser(String, &'static str),
    /// Carries an owned message: an FTP login refusal has to name the
    /// operator's own input and the budget it blew, which no `&'static str`
    /// can do.
    #[error("{0}")]
    InvalidFtpLogin(String),
}
