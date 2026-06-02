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
    // Not active: try enable + start. If the unit doesn't exist (vsftpd
    // not installed) this fails with a clear error pointing the operator
    // at `apt-get install -y vsftpd`.
    cmd::run("/usr/bin/systemctl", &["enable", "--now", "vsftpd"]).await?;
    Ok(())
}
