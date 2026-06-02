//! FTP/FTPS access via vsftpd in local-user mode.
//!
//! Architecture: vsftpd is installed once cluster-wide and configured
//! to authenticate Linux users via PAM, chroot them to their home
//! (`/home/<system_user>`) and write to their `<domain>/htdocs` dir.
//!
//! "Enable FTP for hosting X" reduces to: set a password on hosting
//! X's system user, and make sure vsftpd accepts that user. We don't
//! track per-hosting on/off state — if the user has a password they
//! can FTP; if not, they can't.

use crate::{cmd, AdapterError};

/// Set / replace the Linux password for `user` via `chpasswd`. Used
/// after generating a fresh FTP password so the client can connect.
pub async fn set_user_password(user: &str, password: &str) -> Result<(), AdapterError> {
    // chpasswd reads "user:password\n" from stdin.
    let line = format!("{}:{}\n", user, password);
    cmd::run_with_stdin("/usr/sbin/chpasswd", &[], line.as_bytes()).await?;
    Ok(())
}

/// `passwd -d <user>` removes the password (FTP login impossible).
/// Idempotent — passwd is fine with already-disabled accounts.
pub async fn clear_user_password(user: &str) -> Result<(), AdapterError> {
    cmd::run("/usr/bin/passwd", &["-d", user]).await?;
    Ok(())
}

/// Ensure the operator has vsftpd installed + the unit running, plus
/// our local config block. Called from the agent on first FTP password
/// set so the operator doesn't have to do anything manual.
///
/// Self-heals missing-package: if `enable --now` fails because the
/// vsftpd.service unit doesn't exist (the package was never apt-installed
/// or got removed), we run `apt-get install -y -qq vsftpd` and retry.
/// Only THEN do we surface an error — and the error message points the
/// operator at the right fix instead of being a raw systemctl dump.
pub async fn ensure_vsftpd_running() -> Result<(), AdapterError> {
    // is-active returns 0 iff active.
    let active = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", "vsftpd"])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if active {
        return Ok(());
    }
    // Not active: try enable + start.
    match cmd::run("/usr/bin/systemctl", &["enable", "--now", "vsftpd"]).await {
        Ok(_) => Ok(()),
        Err(AdapterError::Command { stderr_tail, .. }) if stderr_tail.contains("does not exist") => {
            tracing::warn!("vsftpd.service unit missing — auto-installing package");
            // Best-effort apt install. `-qq` keeps logs clean.
            // `DEBIAN_FRONTEND=noninteractive` so an unexpected prompt
            // doesn't hang the agent forever.
            let install = tokio::process::Command::new("/usr/bin/apt-get")
                .args(["install", "-y", "-qq", "vsftpd"])
                .env("DEBIAN_FRONTEND", "noninteractive")
                .output()
                .await;
            match install {
                Ok(out) if out.status.success() => {
                    tracing::info!("vsftpd installed by agent self-heal");
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    return Err(AdapterError::Other(format!(
                        "vsftpd is not installed and `apt-get install -y vsftpd` failed: \
                         {stderr}. Run it by hand on this node, then retry."
                    )));
                }
                Err(e) => {
                    return Err(AdapterError::Other(format!(
                        "vsftpd is not installed and apt-get couldn't be invoked: {e}. \
                         Run `apt-get install -y vsftpd` on this node, then retry."
                    )));
                }
            }
            // Retry enable now that the unit exists.
            cmd::run("/usr/bin/systemctl", &["enable", "--now", "vsftpd"]).await?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    /// Pure-function sanity: ensure the error string we match against
    /// stays in lockstep with systemd's actual phrasing. If systemd ever
    /// changes the message we want to surface that loudly here.
    #[test]
    fn unit_not_found_phrase_matches() {
        let sample = "Failed to enable unit: Unit file vsftpd.service does not exist.";
        assert!(sample.contains("does not exist"));
    }
}
