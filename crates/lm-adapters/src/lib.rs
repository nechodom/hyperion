//! Thin, typed wrappers around the system tools `lm-agent` needs to call.
//!
//! Every public function in this crate:
//! - takes pre-validated typed arguments,
//! - shells out only via `Command::new(..).arg(..)` (no `sh -c`),
//! - is idempotent (ensure-X style, no-ops if state already matches),
//! - returns a `RollbackToken` for any state-mutating step.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod acme;
pub mod cmd;
pub mod fs;
pub mod mariadb;
pub mod nginx;
pub mod phpfpm;
pub mod postgres;
pub mod rollback;
pub mod users;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("command {cmd} failed with exit {code}: {stderr_tail}")]
    Command {
        cmd: String,
        code: i32,
        stderr_tail: String,
    },
    #[error("template render: {0}")]
    Render(#[from] askama::Error),
    #[error("validation: {0}")]
    Validation(#[from] lm_validate::ValidationError),
    #[error("acme: {0}")]
    Acme(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("other: {0}")]
    Other(String),
}

impl From<AdapterError> for lm_rpc::RpcError {
    fn from(e: AdapterError) -> Self {
        match e {
            AdapterError::Command {
                cmd,
                code,
                stderr_tail,
            } => lm_rpc::RpcError::SystemCommand {
                cmd,
                code,
                stderr_tail,
            },
            AdapterError::Conflict(m) => lm_rpc::RpcError::Conflict { message: m },
            AdapterError::Validation(v) => v.into(),
            AdapterError::Render(e) => lm_rpc::RpcError::ProvisioningFailed {
                stage: "template".into(),
                reason: e.to_string(),
            },
            AdapterError::Acme(m) => lm_rpc::RpcError::ProvisioningFailed {
                stage: "acme".into(),
                reason: m,
            },
            AdapterError::Io(e) => lm_rpc::RpcError::ProvisioningFailed {
                stage: "io".into(),
                reason: e.to_string(),
            },
            AdapterError::Other(m) => lm_rpc::RpcError::ProvisioningFailed {
                stage: "other".into(),
                reason: m,
            },
        }
    }
}

/// Random password generator: 32 chars from [A-Za-z0-9].
pub fn random_password() -> String {
    use rand::Rng;
    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(32);
    for _ in 0..32 {
        let idx = rng.gen_range(0..alphabet.len());
        s.push(alphabet[idx] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_password_is_32_alnum() {
        let p = random_password();
        assert_eq!(p.len(), 32);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn random_passwords_differ() {
        let a = random_password();
        let b = random_password();
        assert_ne!(a, b);
    }

    #[test]
    fn adapter_error_to_rpc_error_command() {
        let a = AdapterError::Command {
            cmd: "useradd".into(),
            code: 1,
            stderr_tail: "boom".into(),
        };
        let r: lm_rpc::RpcError = a.into();
        match r {
            lm_rpc::RpcError::SystemCommand { cmd, code, .. } => {
                assert_eq!(cmd, "useradd");
                assert_eq!(code, 1);
            }
            other => panic!("wrong: {other:?}"),
        }
    }
}
