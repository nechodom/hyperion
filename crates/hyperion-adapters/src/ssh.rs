//! Per-hosting key-only, chrooted SFTP via OpenSSH.
//!
//! Each hosting's Linux system user can be opted into SFTP. Opted-in
//! users join the `hyperion-sftp` group, which an sshd drop-in
//! (`/etc/ssh/sshd_config.d/hyperion-sftp.conf`) matches to force
//! `internal-sftp`, chroot the session to the user's home, and disable
//! shells, password auth and forwarding. Access is by SSH public key
//! only — the operator pastes keys into the UI and we write them to the
//! user's `authorized_keys`.
//!
//! Chroot needs the home directory itself owned `root:root` and not
//! group/world-writable (OpenSSH `StrictModes`). The writable area is
//! the per-hosting `<domain>/htdocs` tree below it, which stays owned by
//! the user — so the customer lands in their site root and can upload.

use crate::cmd;
use crate::AdapterError;
use std::path::Path;

const SFTP_GROUP: &str = "hyperion-sftp";
const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/hyperion-sftp.conf";

/// The sshd drop-in we manage. Self-contained `Match` block — modern
/// OpenSSH (Debian 12 ships 9.2) scopes a Match in an included file to
/// that file, so this can't leak its restrictions onto ordinary SSH
/// logins. Still gated by `sshd -t` before every reload.
const DROPIN_BODY: &str = "\
# Managed by Hyperion — do not edit by hand.
# Key-only, chrooted SFTP for hosting system users.
Match Group hyperion-sftp
    ChrootDirectory %h
    ForceCommand internal-sftp
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PasswordAuthentication no
    AuthenticationMethods publickey
";

/// Accepted SSH public-key algorithms. The first whitespace token of a
/// valid `authorized_keys` line must be one of these — which also means
/// a line can't begin with an `options` field (e.g. `command=`), closing
/// off the only injection vector into the file.
const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Validate + canonicalise a single public-key line. Returns the trimmed
/// line on success. Rejects anything that isn't `<type> <base64> [comment]`
/// so nothing dangerous can be smuggled into `authorized_keys`.
pub fn validate_public_key(line: &str) -> Result<String, AdapterError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(AdapterError::Other("empty key line".into()));
    }
    if line.contains('\n') || line.contains('\r') {
        return Err(AdapterError::Other("key must be a single line".into()));
    }
    let mut parts = line.split_whitespace();
    let kind = parts.next().unwrap_or("");
    if !KEY_TYPES.contains(&kind) {
        return Err(AdapterError::Other(format!(
            "unsupported key type {kind:?} (expected ssh-ed25519 / ssh-rsa / ecdsa-…)"
        )));
    }
    let blob = parts.next().unwrap_or("");
    if blob.len() < 16
        || !blob
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(AdapterError::Other("key body is not valid base64".into()));
    }
    // Comment (the remainder) is free text but already newline-free.
    Ok(line.to_string())
}

/// Parse a free-form textarea (one key per line) into validated keys.
/// Skips blank lines; the first invalid key aborts with its error so the
/// operator gets a precise message instead of a silent drop.
pub fn parse_keys(raw: &str) -> Result<Vec<String>, AdapterError> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        out.push(validate_public_key(t)?);
    }
    Ok(out)
}

/// Ensure the group + sshd drop-in exist and ssh is reloaded. Idempotent
/// — only reloads ssh when the drop-in actually changed, and only after
/// `sshd -t` accepts the new config.
pub async fn ensure_sftp_infra() -> Result<(), AdapterError> {
    // groupadd -f is a no-op when the group already exists.
    cmd::run("/usr/sbin/groupadd", &["-f", SFTP_GROUP]).await?;

    let want = DROPIN_BODY;
    let have = tokio::fs::read_to_string(SSHD_DROPIN)
        .await
        .unwrap_or_default();
    if have != want {
        crate::fs::atomic_write(Path::new(SSHD_DROPIN), want.as_bytes(), 0o644).await?;
        // Validate the WHOLE sshd config (including this drop-in) before
        // reloading. If it's bad, pull the drop-in back out so a broken
        // file can never wedge sshd on the next restart, and surface the
        // verbatim error.
        if let Err(e) = cmd::run("/usr/sbin/sshd", &["-t"]).await {
            let _ = tokio::fs::remove_file(SSHD_DROPIN).await;
            return Err(AdapterError::Other(format!(
                "sshd rejected the SFTP config (left untouched): {e}"
            )));
        }
        // reload, not restart — keeps existing SSH sessions (incl. the
        // operator's own) alive.
        cmd::run("/usr/bin/systemctl", &["reload", "ssh"]).await?;
    }
    Ok(())
}

/// Enable SFTP for `user`: join the group, root-own the home for chroot,
/// and install the validated keys into `~/.ssh/authorized_keys`.
pub async fn enable_sftp(user: &str, home_dir: &str, keys: &[String]) -> Result<(), AdapterError> {
    ensure_sftp_infra().await?;
    cmd::run("/usr/sbin/usermod", &["-aG", SFTP_GROUP, user]).await?;

    // Chroot prerequisite: the home itself must be root-owned and not
    // writable by the user. The user's writable site tree lives one level
    // down (<domain>/htdocs) and keeps its own ownership.
    cmd::run("/usr/bin/chown", &["root:root", home_dir]).await?;
    cmd::run("/usr/bin/chmod", &["0755", home_dir]).await?;

    // ~/.ssh owned by the user so StrictModes is satisfied and the
    // customer "owns" their key list.
    let ssh_dir = format!("{home_dir}/.ssh");
    crate::fs::ensure_dir(Path::new(&ssh_dir), 0o700).await?;
    cmd::run("/usr/bin/chown", &[&format!("{user}:{user}"), &ssh_dir]).await?;
    cmd::run("/usr/bin/chmod", &["0700", &ssh_dir]).await?;

    let ak = format!("{ssh_dir}/authorized_keys");
    let body = if keys.is_empty() {
        String::new()
    } else {
        format!("{}\n", keys.join("\n"))
    };
    crate::fs::atomic_write(Path::new(&ak), body.as_bytes(), 0o600).await?;
    cmd::run("/usr/bin/chown", &[&format!("{user}:{user}"), &ak]).await?;
    cmd::run("/usr/bin/chmod", &["0600", &ak]).await?;
    Ok(())
}

/// Disable SFTP: drop the user from the group and clear their keys. The
/// home is left root-owned (harmless — vsftpd is happy with a non-writable
/// chroot root too, and reverting risks races with an in-flight upload).
pub async fn disable_sftp(user: &str, home_dir: &str) -> Result<(), AdapterError> {
    // gpasswd -d fails if the user isn't a member; treat that as success.
    let _ = cmd::run("/usr/bin/gpasswd", &["-d", user, SFTP_GROUP]).await;
    let ak = format!("{home_dir}/.ssh/authorized_keys");
    if Path::new(&ak).exists() {
        crate::fs::atomic_write(Path::new(&ak), b"", 0o600).await?;
        let _ = cmd::run("/usr/bin/chown", &[&format!("{user}:{user}"), &ak]).await;
    }
    Ok(())
}

/// Read the current SFTP status for a user: whether they're in the group
/// and the public keys currently installed.
pub async fn read_status(user: &str, home_dir: &str) -> Result<(bool, Vec<String>), AdapterError> {
    let groups = cmd::run("/usr/bin/id", &["-nG", user])
        .await
        .unwrap_or_default();
    let enabled = groups.split_whitespace().any(|g| g == SFTP_GROUP);
    let ak = format!("{home_dir}/.ssh/authorized_keys");
    let keys = match tokio::fs::read_to_string(&ak).await {
        Ok(content) => content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect(),
        Err(_) => Vec::new(),
    };
    Ok((enabled, keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_good_keys() {
        let k = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij user@host";
        assert!(validate_public_key(k).is_ok());
        assert!(validate_public_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB").is_ok());
    }

    #[test]
    fn rejects_injection_and_garbage() {
        // Leading options field (would let a command sneak in) — rejected
        // because the line doesn't start with a key type.
        assert!(validate_public_key("command=\"sh\" ssh-rsa AAAA").is_err());
        assert!(validate_public_key("not-a-key whatever").is_err());
        assert!(validate_public_key("ssh-ed25519 has spaces!!!").is_err());
        assert!(validate_public_key("").is_err());
        assert!(validate_public_key("ssh-rsa short").is_err());
    }

    #[test]
    fn parse_keys_skips_blanks() {
        let raw = "\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij a\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB b\n";
        let ks = parse_keys(raw).expect("parse");
        assert_eq!(ks.len(), 2);
    }
}
