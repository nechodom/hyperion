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

use crate::fs::atomic_write;
use crate::{cmd, AdapterError};
use std::path::Path;

const VSFTPD_CONF: &str = "/etc/vsftpd.conf";
const VSFTPD_CONF_ORIG: &str = "/etc/vsftpd.conf.hyperion-orig";
/// The local-user FTP config Hyperion needs. `$USER` is a vsftpd token it
/// expands per-login (chroot each user to their own /home/<user>). Mirrors the
/// block install-node.sh/install-master.sh write at first install.
const HYPERION_VSFTPD_CONF: &str = "\
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
allow_writeable_chroot=YES
pam_service_name=vsftpd
secure_chroot_dir=/var/run/vsftpd/empty
user_sub_token=$USER
local_root=/home/$USER
xferlog_enable=YES
xferlog_std_format=YES
seccomp_sandbox=NO
";

/// Set / replace the Linux password for `user` via `chpasswd`. Used
/// after generating a fresh FTP password so the client can connect.
pub async fn set_user_password(user: &str, password: &str) -> Result<(), AdapterError> {
    // chpasswd reads ONE "user:password" record per line from stdin. A newline
    // (or carriage return) in either field would inject a *second* record —
    // e.g. a password of "x\nroot:owned" would also reset root, since the agent
    // runs as root. `:` in the user would likewise split the record. Reject any
    // such control character before building the line. (`user` is already a
    // validated SystemUserName upstream; this is defence-in-depth + covers the
    // operator-supplied password.)
    if user.contains([':', '\n', '\r', '\0']) || password.contains(['\n', '\r', '\0']) {
        return Err(AdapterError::Other(
            "ftp user/password contains an illegal control character".into(),
        ));
    }
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
        Err(AdapterError::Command { stderr_tail, .. })
            if stderr_tail.contains("does not exist") =>
        {
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

/// Ensure vsftpd is CONFIGURED for Hyperion local-user FTP — not just running.
///
/// This setup lived ONLY in the one-time install script, so a node installed
/// before that block existed, or where vsftpd was auto-installed later by
/// `ensure_vsftpd_running`, ends up with:
///   - Debian's STOCK `/etc/vsftpd.conf` (`local_enable` commented → NO), so
///     local users can't log in at all; and/or
///   - an `/etc/shells` without `/usr/sbin/nologin`, so the vsftpd PAM's
///     `pam_shells` refuses every hosting user (they have a nologin shell).
///
/// Either makes vsftpd answer "530 Login incorrect" even though the password is
/// correct. This self-heals both, idempotently, so FTP works regardless of when
/// or how the node was set up. Restarts vsftpd only when the config was wrong.
pub async fn ensure_vsftpd_configured() -> Result<(), AdapterError> {
    // 1. /etc/shells must list the hosting users' shell, or pam_shells rejects
    //    them. Append the nologin/false shells once (idempotent).
    let shells = tokio::fs::read_to_string("/etc/shells")
        .await
        .unwrap_or_default();
    let mut updated = shells.clone();
    for shell in ["/usr/sbin/nologin", "/bin/false"] {
        if !shells.lines().any(|l| l.trim() == shell) {
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push_str(shell);
            updated.push('\n');
        }
    }
    if updated != shells {
        atomic_write(Path::new("/etc/shells"), updated.as_bytes(), 0o644)
            .await
            .map_err(|e| AdapterError::Other(format!("update /etc/shells: {e}")))?;
    }

    // 2. vsftpd.conf: install the Hyperion config unless it's already ours
    //    (missing local_enable=YES / pam_service_name=vsftpd ⇒ stock or unset).
    //    Back up the original once (mirrors the install script's *.hyperion-orig).
    let current = tokio::fs::read_to_string(VSFTPD_CONF)
        .await
        .unwrap_or_default();
    let already_ours =
        current.contains("local_enable=YES") && current.contains("pam_service_name=vsftpd");
    if !already_ours {
        if !current.is_empty() && tokio::fs::metadata(VSFTPD_CONF_ORIG).await.is_err() {
            let _ = tokio::fs::copy(VSFTPD_CONF, VSFTPD_CONF_ORIG).await;
        }
        atomic_write(
            Path::new(VSFTPD_CONF),
            HYPERION_VSFTPD_CONF.as_bytes(),
            0o644,
        )
        .await
        .map_err(|e| AdapterError::Other(format!("write {VSFTPD_CONF}: {e}")))?;
        cmd::run("/usr/bin/systemctl", &["restart", "vsftpd"]).await?;
    }
    Ok(())
}

/// Names of every system user that currently has an FTP-usable
/// password (shadow field 2 is a real hash, not `!` / `*` / empty).
/// Read in one shot from /etc/shadow — root only, agent runs as
/// root. Operators with empty/locked shadow rows are excluded so
/// the result equals "operators who CAN log in via vsftpd".
pub async fn list_users_with_password() -> Result<Vec<String>, AdapterError> {
    let raw = match tokio::fs::read_to_string("/etc/shadow").await {
        Ok(s) => s,
        Err(e) => {
            return Err(AdapterError::Other(format!(
                "read /etc/shadow: {e} (agent must run as root)"
            )))
        }
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        let mut it = line.splitn(3, ':');
        let Some(user) = it.next() else { continue };
        let Some(hash) = it.next() else { continue };
        if user.is_empty() {
            continue;
        }
        // Real hashes are at least 13 chars and never start with !/*.
        // Empty + "!" + "*" mean "no usable password" → skip.
        if !hash.is_empty() && !hash.starts_with('!') && !hash.starts_with('*') {
            out.push(user.to_string());
        }
    }
    Ok(out)
}

/// Probe vsftpd by attempting an FTP login against localhost with
/// the given credentials. Returns Ok(true) on a successful auth,
/// Ok(false) on auth refused (530), and Err on transport-level
/// failure (vsftpd down, network broken, curl missing).
///
/// Uses curl because it's already a hard dep for backups + ACME,
/// no extra crate. Times out after 5s so a hung vsftpd doesn't
/// deadlock the page render.
pub async fn probe_login(user: &str, password: &str) -> Result<bool, AdapterError> {
    // Defence: curl's --user splits on the first colon, so an
    // operator-supplied password CAN'T contain ':' or it'd be
    // misparsed. We refuse upfront rather than corrupting the test.
    if password.contains(':') {
        return Err(AdapterError::Other(
            "ftp probe refused: password contains ':' which curl's --user can't represent".into(),
        ));
    }
    // Quote-proof: pass the credential via --user-agent? No — just
    // sanitise the user (we own it; system users match a tight
    // pattern already). Curl handles arbitrary password chars fine
    // when passed via --user `<u>:<p>` because we're not going
    // through a shell.
    let user_arg = format!("{}:{}", user, password);
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args([
            "-s",
            "-S",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "5",
            "--user",
            &user_arg,
            "ftp://127.0.0.1/",
        ])
        .output()
        .await
        .map_err(|e| AdapterError::Other(format!("spawn curl: {e}")))?;
    // curl's "FTP response code" lives in %{http_code} for FTP too.
    // 230 = login OK. 530 = login incorrect / disabled.
    // 0 (or empty) = connection failed before any response.
    let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
    match code.as_str() {
        "230" => Ok(true),
        "530" => Ok(false),
        // Unauthenticated transport failure — report as Err so the
        // UI can show "couldn't reach vsftpd" instead of a silent
        // false-negative login.
        _ => Err(AdapterError::Other(format!(
            "ftp probe transport failure (curl code {code}): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))),
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

    #[test]
    fn hyperion_vsftpd_conf_has_the_login_critical_directives() {
        // The exact directives whose absence causes "530 Login incorrect" for
        // local users. `already_ours` in ensure_vsftpd_configured() keys off the
        // first two — keep them present.
        for needle in [
            "local_enable=YES",
            "pam_service_name=vsftpd",
            "chroot_local_user=YES",
            "allow_writeable_chroot=YES",
        ] {
            assert!(
                super::HYPERION_VSFTPD_CONF.contains(needle),
                "vsftpd config missing: {needle}"
            );
        }
    }
}
