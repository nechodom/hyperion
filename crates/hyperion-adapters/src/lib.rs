//! Thin, typed wrappers around the system tools `hyperion-agent` needs to call.
//!
//! Every public function in this crate:
//! - takes pre-validated typed arguments,
//! - shells out only via `Command::new(..).arg(..)` (no `sh -c`),
//! - is idempotent (ensure-X style, no-ops if state already matches),
//! - returns a `RollbackToken` for any state-mutating step.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod acme;
pub mod backup;
pub mod cmd;
pub mod email;
pub mod fs;
pub mod ftp;
pub mod mariadb;
pub mod nginx;
pub mod nodejs;
pub mod phpfpm;
pub mod postgres;
pub mod rollback;
pub mod users;
pub mod wpcli;

/// Probe one systemd unit's status. Returns (active, enabled, sub_state).
/// Never panics; on any error returns `(false, false, "?")`.
/// Used by both the health-check page and the dashboard widget.
pub async fn systemctl_status(unit: &str) -> (bool, bool, String) {
    let active = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    let enabled = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["is-enabled", "--quiet", unit])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    // SubState gives nicer detail than the boolean: "running",
    // "failed", "dead", "exited"… empty/"?" if probe failed.
    let sub_state = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["show", "-p", "SubState", "--value", unit])
        .output()
        .await
        .ok()
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        })
        .unwrap_or_else(|| "?".into());
    (active, enabled, sub_state)
}

/// Is a unit file present at all on the system?
pub async fn systemctl_unit_present(unit: &str) -> bool {
    let out = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["list-unit-files", "--no-pager", unit])
        .output()
        .await;
    let Ok(o) = out else { return false };
    let stdout = String::from_utf8_lossy(&o.stdout);
    stdout.lines().any(|l| l.starts_with(unit))
}

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
    Validation(#[from] hyperion_validate::ValidationError),
    #[error("acme: {0}")]
    Acme(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("other: {0}")]
    Other(String),
}

impl From<AdapterError> for hyperion_rpc::RpcError {
    fn from(e: AdapterError) -> Self {
        match e {
            AdapterError::Command {
                cmd,
                code,
                stderr_tail,
            } => hyperion_rpc::RpcError::SystemCommand {
                cmd,
                code,
                stderr_tail,
            },
            AdapterError::Conflict(m) => hyperion_rpc::RpcError::Conflict { message: m },
            AdapterError::Validation(v) => v.into(),
            AdapterError::Render(e) => hyperion_rpc::RpcError::ProvisioningFailed {
                stage: "template".into(),
                reason: e.to_string(),
            },
            AdapterError::Acme(m) => hyperion_rpc::RpcError::ProvisioningFailed {
                stage: "acme".into(),
                reason: m,
            },
            AdapterError::Io(e) => hyperion_rpc::RpcError::ProvisioningFailed {
                stage: "io".into(),
                reason: e.to_string(),
            },
            AdapterError::Other(m) => hyperion_rpc::RpcError::ProvisioningFailed {
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
        let r: hyperion_rpc::RpcError = a.into();
        match r {
            hyperion_rpc::RpcError::SystemCommand { cmd, code, .. } => {
                assert_eq!(cmd, "useradd");
                assert_eq!(code, 1);
            }
            other => panic!("wrong: {other:?}"),
        }
    }
}
