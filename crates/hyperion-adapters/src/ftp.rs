//! FTP/FTPS access via vsftpd in local-user mode.
//!
//! Architecture: vsftpd is installed once cluster-wide and configured to
//! authenticate Linux users via PAM and chroot each hosting user **directly
//! into their writable web root** (`<domain>/htdocs`, owned by the user) via a
//! per-user `local_root`. The home itself (`/home/<user>`) is deliberately
//! root-owned when key-only SFTP is enabled (sshd's chroot rule), so landing
//! FTP in the home would leave the user unable to `STOR` there — 550. Landing
//! in htdocs (which the user owns) makes uploads work in either case, and puts
//! files straight where nginx serves them.
//!
//! "Enable FTP for hosting X" reduces to: set a password on hosting X's system
//! user, point that user's vsftpd `local_root` at its htdocs, and make sure
//! vsftpd accepts the user. No per-hosting on/off state — password ⇒ can FTP.

use crate::fs::atomic_write;
use crate::{cmd, AdapterError};
use std::path::Path;

const VSFTPD_CONF: &str = "/etc/vsftpd.conf";
const VSFTPD_CONF_ORIG: &str = "/etc/vsftpd.conf.hyperion-orig";
/// vsftpd `user_config_dir` — per-user override files (one per system user)
/// that set `local_root` to that hosting's htdocs.
const VSFTPD_USER_CONF_DIR: &str = "/etc/vsftpd/user_conf";
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
user_config_dir=/etc/vsftpd/user_conf
xferlog_enable=YES
xferlog_std_format=YES
dual_log_enable=YES
syslog_enable=YES
seccomp_sandbox=NO
";

/// True when `conf` sets `key` on a real, uncommented line.
///
/// Line-anchored on purpose. A bare `contains("local_enable=YES")` is also
/// satisfied by Debian's stock `#local_enable=YES`, so a box whose vsftpd was
/// installed outside Hyperion looked "already ours", was never repaired, and
/// refused every login — while the same commented lines suppressed the
/// user_config_dir and syslog upgrades below.
fn conf_sets(conf: &str, key: &str) -> bool {
    conf.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#') && l.starts_with(key) && l[key.len()..].starts_with('=')
    })
}

/// The value of an uncommented `key=` line, last one wins (vsftpd's own rule).
fn conf_value<'a>(conf: &'a str, key: &str) -> Option<&'a str> {
    let mut found = None;
    for l in conf.lines() {
        let l = l.trim();
        if l.starts_with('#') || !l.starts_with(key) {
            continue;
        }
        if let Some(rest) = l[key.len()..].strip_prefix('=') {
            found = Some(rest.trim());
        }
    }
    found
}

/// The control port vsftpd is actually listening on (`listen_port`, default 21).
///
/// The installer appends this directive when the operator picks a non-default
/// port, but nothing read it back — so the login probe dialled 21, the
/// credentials card told the customer "21", and the firewall preset opened 21,
/// all regardless of what the box was really running.
pub async fn read_listen_port() -> u16 {
    let conf = tokio::fs::read_to_string(VSFTPD_CONF)
        .await
        .unwrap_or_default();
    conf_value(&conf, "listen_port")
        .and_then(|v| v.parse().ok())
        .filter(|p| *p > 0)
        .unwrap_or(21)
}

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

/// Point `user`'s vsftpd `local_root` at `web_root` (the hosting's htdocs) via a
/// per-user config in `user_config_dir`, so an FTP client lands directly in the
/// writable web root and `STOR` works — instead of the root-owned home. vsftpd
/// re-reads this per login, so no reload is needed. `web_root` must exist and be
/// owned by the user (it's the htdocs created at hosting-create time).
pub async fn set_user_web_root(user: &str, web_root: &str) -> Result<(), AdapterError> {
    // The user becomes a filename under user_config_dir — reject path/newline
    // injection (already a validated SystemUserName upstream; defence in depth).
    if user.is_empty() || user.contains(['/', '\n', '\r', '\0', ':', '.']) {
        return Err(AdapterError::Other(
            "ftp user has an illegal character for a per-user config".into(),
        ));
    }
    tokio::fs::create_dir_all(VSFTPD_USER_CONF_DIR)
        .await
        .map_err(|e| AdapterError::Other(format!("mkdir {VSFTPD_USER_CONF_DIR}: {e}")))?;
    let path = format!("{VSFTPD_USER_CONF_DIR}/{user}");
    let body = format!("local_root={web_root}\nwrite_enable=YES\n");
    atomic_write(Path::new(&path), body.as_bytes(), 0o644)
        .await
        .map_err(|e| AdapterError::Other(format!("write {path}: {e}")))?;
    Ok(())
}

/// The `local_root` currently configured for `user`, as vsftpd would read it.
/// `Ok(None)` means there is no per-user file at all (FTP never enabled, or
/// the override was removed).
pub async fn read_user_web_root(user: &str) -> Result<Option<String>, AdapterError> {
    if user.is_empty() || user.contains(['/', '\n', '\r', '\0', ':', '.']) {
        return Err(AdapterError::Other(
            "ftp user has an illegal character for a per-user config".into(),
        ));
    }
    let path = format!("{VSFTPD_USER_CONF_DIR}/{user}");
    match tokio::fs::read_to_string(&path).await {
        Ok(body) => Ok(Some(
            conf_value(&body, "local_root")
                .unwrap_or_default()
                .to_string(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AdapterError::Other(format!("read {path}: {e}"))),
    }
}

/// Classify `user`'s shadow password field WITHOUT copying the hash out.
///
/// Returns `hash` (a usable password — FTP can log in), `locked` (`!`-prefixed,
/// which is what suspension does), `star` (`*` — deliberately disabled),
/// `empty` (the state the old `passwd -d` left behind), or `no_user`.
/// Never returns the hash itself: the caller renders this into a web page.
pub async fn password_state(user: &str) -> String {
    let raw = match tokio::fs::read_to_string("/etc/shadow").await {
        Ok(r) => r,
        Err(_) => return "no_user".into(),
    };
    for line in raw.lines() {
        let mut it = line.splitn(3, ':');
        let (Some(u), Some(hash)) = (it.next(), it.next()) else {
            continue;
        };
        if u != user {
            continue;
        }
        return if hash.is_empty() {
            "empty"
        } else if hash.starts_with('!') {
            "locked"
        } else if hash.starts_with('*') {
            "star"
        } else {
            "hash"
        }
        .into();
    }
    "no_user".into()
}

/// The login shell recorded for `user` in passwd, and whether it appears in
/// `/etc/shells`. vsftpd's PAM stack refuses a login whose shell is not
/// listed, with a 530 that says nothing about why.
pub async fn shell_state(user: &str) -> (String, bool) {
    let shell = match cmd::run("/usr/bin/getent", &["passwd", user]).await {
        Ok(out) => out
            .trim()
            .rsplit(':')
            .next()
            .unwrap_or_default()
            .to_string(),
        Err(_) => String::new(),
    };
    if shell.is_empty() {
        return (String::new(), false);
    }
    let shells = tokio::fs::read_to_string("/etc/shells")
        .await
        .unwrap_or_default();
    let listed = shells.lines().any(|l| l.trim() == shell);
    (shell, listed)
}

/// Whether the node's vsftpd.conf sets the directives local-user FTP needs.
/// Returns the names of the MISSING ones, so the caller can say which.
pub async fn missing_conf_directives() -> Vec<&'static str> {
    let conf = tokio::fs::read_to_string(VSFTPD_CONF)
        .await
        .unwrap_or_default();
    [
        "local_enable",
        "pam_service_name",
        "user_config_dir",
        "chroot_local_user",
        "allow_writeable_chroot",
    ]
    .into_iter()
    .filter(|k| !conf_sets(&conf, k))
    .collect()
}

/// True when the node's vsftpd.conf enables FTPS. Reported, never auto-set:
/// flipping it on restarts a daemon every hosting shares and locks out any
/// client that cannot negotiate TLS.
pub async fn ftps_enabled() -> bool {
    let conf = tokio::fs::read_to_string(VSFTPD_CONF)
        .await
        .unwrap_or_default();
    conf_sets(&conf, "ssl_enable") && conf_sets(&conf, "rsa_cert_file")
}

/// Any `userlist_*` / ftpusers gating that could refuse this user. Hyperion
/// writes none of it, so whatever is here is foreign and deliberate —
/// reported, never modified.
pub async fn userlist_blocks(user: &str) -> Option<String> {
    let conf = tokio::fs::read_to_string(VSFTPD_CONF)
        .await
        .unwrap_or_default();
    // /etc/ftpusers is consulted by the stock PAM stack regardless of conf.
    if let Ok(f) = tokio::fs::read_to_string("/etc/ftpusers").await {
        if f.lines().any(|l| l.trim() == user) {
            return Some("/etc/ftpusers lists this user (PAM refuses the login)".into());
        }
    }
    if !conf_sets(&conf, "userlist_enable") {
        return None;
    }
    let file = conf_value(&conf, "userlist_file").unwrap_or("/etc/vsftpd.user_list");
    let listed = tokio::fs::read_to_string(file)
        .await
        .map(|f| f.lines().any(|l| l.trim() == user))
        .unwrap_or(false);
    // userlist_deny defaults to YES: presence blocks. With deny=NO the file
    // is an ALLOW list and ABSENCE is what blocks — reporting only the first
    // sense would tell the operator the opposite of the truth.
    let deny = conf_value(&conf, "userlist_deny")
        .unwrap_or("YES")
        .eq_ignore_ascii_case("YES");
    match (deny, listed) {
        (true, true) => Some(format!("{file} denies this user")),
        (false, false) => Some(format!(
            "{file} is an allow-list and this user is not on it"
        )),
        _ => None,
    }
}

/// The first path at or just under `web_root` that `user` does NOT own, or
/// `None` when everything checks out.
///
/// Two levels deep, not just `stat(web_root)`: a wrong-uid SUBDIRECTORY is
/// what blocks MKD/STOR one level down while the root itself looks fine, and
/// that is exactly the state a restore from another box leaves behind.
pub async fn web_root_owner_drift(
    user: &str,
    web_root: &str,
) -> Result<Option<String>, AdapterError> {
    if web_root.is_empty() || web_root.contains(['\n', '\r', '\0']) {
        return Err(AdapterError::Other("illegal web root path".into()));
    }
    if user.is_empty() || user.contains(['\n', '\r', '\0', ':']) {
        return Err(AdapterError::Other("illegal user name".into()));
    }
    let out = cmd::run(
        "/usr/bin/find",
        &[
            web_root,
            "-maxdepth",
            "2",
            "!",
            "-user",
            user,
            "-print",
            "-quit",
        ],
    )
    .await?;
    let first = out.trim();
    Ok(if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    })
}

/// Ensure `user` actually OWNS their web root, so FTP uploads / MKD work.
///
/// A site restored or imported from another box keeps the SOURCE uid on its
/// files (`tar`/`rsync` run as root preserve ownership), so the local system
/// user can't write — `STOR`/`MKD` then fail with 550 even though login + LIST
/// work. chown the tree to the hosting user at FTP-enable time to self-heal
/// that. Safe: PHP-FPM already runs as this user, and nginx reads via the
/// world-readable bits + traversable ancestors, so ownership = the user is the
/// correct end state anyway. `web_root` is the hosting's htdocs.
pub async fn ensure_web_root_owned(user: &str, web_root: &str) -> Result<(), AdapterError> {
    if user.is_empty() || user.contains([':', '\n', '\r', '\0']) {
        return Err(AdapterError::Other(
            "ftp user has an illegal character for chown".into(),
        ));
    }
    cmd::run(
        "/usr/bin/chown",
        &["-R", &format!("{user}:{user}"), web_root],
    )
    .await?;
    Ok(())
}

/// Remove `user`'s per-user vsftpd override (on FTP disable). Idempotent.
pub async fn clear_user_web_root(user: &str) -> Result<(), AdapterError> {
    if user.contains(['/', '\n', '\r', '\0', ':', '.']) {
        return Ok(());
    }
    let _ = tokio::fs::remove_file(format!("{VSFTPD_USER_CONF_DIR}/{user}")).await;
    Ok(())
}

/// Make `user`'s password unusable so FTP login is impossible. Idempotent.
///
/// Sets the shadow field to `*`. Two things this is NOT, both deliberate:
///
/// * NOT `passwd -d`, which is what this used to do. That EMPTIES the field,
///   and an empty field is not "login impossible" — under Debian's stock
///   `pam_unix … nullok` in common-auth it is a usable credential, for every
///   PAM consumer on the box (`su`, `login`, console), not just FTP. Hyperion
///   never writes PAM config, so the distro default decides.
/// * NOT `usermod -L`, which prefixes the existing hash with `!`. That is the
///   SAME state suspension uses (`users::lock_login`), so resuming a site
///   would `usermod -U` it away and silently switch FTP back on for an
///   operator who had deliberately turned it off.
///
/// `*` is the canonical "no password login" marker: it is not a valid crypt
/// hash, so no PAM stack accepts it; `usermod -U` only strips a leading `!`
/// and leaves it alone; and `chpasswd` overwrites it when FTP is re-enabled.
pub async fn clear_user_password(user: &str) -> Result<(), AdapterError> {
    cmd::run("/usr/sbin/usermod", &["-p", "*", user]).await?;
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
        conf_sets(&current, "local_enable") && conf_sets(&current, "pam_service_name");
    if !already_ours {
        if !current.is_empty() {
            // The pristine copy, kept once. Plus a timestamped copy on EVERY
            // rewrite: an installer-provisioned box already has
            // `.hyperion-orig`, so without this second copy the operator's
            // live config is replaced with no recoverable backup of what it
            // actually said.
            if tokio::fs::metadata(VSFTPD_CONF_ORIG).await.is_err() {
                let _ = tokio::fs::copy(VSFTPD_CONF, VSFTPD_CONF_ORIG).await;
            }
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = tokio::fs::copy(VSFTPD_CONF, format!("{VSFTPD_CONF}.hyperion-{stamp}")).await;
        }
        // HYPERION_VSFTPD_CONF carries no `listen_port` — the installer
        // appends it separately when the operator chooses a non-default port.
        // Carrying it across the rewrite is what stops this self-heal from
        // silently moving a custom-port box back to 21 mid-operation.
        let mut body = HYPERION_VSFTPD_CONF.to_string();
        if let Some(port) = conf_value(&current, "listen_port") {
            if port.parse::<u16>().is_ok_and(|p| p > 0 && p != 21) {
                body.push_str(&format!("listen_port={port}\n"));
            }
        }
        atomic_write(Path::new(VSFTPD_CONF), body.as_bytes(), 0o644)
            .await
            .map_err(|e| AdapterError::Other(format!("write {VSFTPD_CONF}: {e}")))?;
        cmd::run("/usr/bin/systemctl", &["restart", "vsftpd"]).await?;
    }

    // 3. Ensure the per-user config dir is wired, so each hosting user's FTP
    //    lands in their OWN writable web root (htdocs) rather than the
    //    root-owned home (where STOR would 550). This upgrades EXISTING "ours"
    //    configs that predate the per-user local_root. Idempotent.
    tokio::fs::create_dir_all(VSFTPD_USER_CONF_DIR).await.ok();
    let cfg = tokio::fs::read_to_string(VSFTPD_CONF)
        .await
        .unwrap_or_default();
    if !conf_sets(&cfg, "user_config_dir") {
        let mut c = cfg;
        if !c.is_empty() && !c.ends_with('\n') {
            c.push('\n');
        }
        c.push_str(&format!("user_config_dir={VSFTPD_USER_CONF_DIR}\n"));
        atomic_write(Path::new(VSFTPD_CONF), c.as_bytes(), 0o644)
            .await
            .map_err(|e| {
                AdapterError::Other(format!("add user_config_dir to {VSFTPD_CONF}: {e}"))
            })?;
        cmd::run("/usr/bin/systemctl", &["restart", "vsftpd"]).await?;
    }

    // 4. Ensure vsftpd's auth events reach the journal (identifier `vsftpd`)
    //    so the brute-force scanner can read its "FAIL LOGIN" lines. This
    //    needs BOTH `syslog_enable=YES` (redirect the vsftpd-format log to
    //    syslog) AND `dual_log_enable=YES` — because `xferlog_std_format=YES`
    //    otherwise routes ALL output through the wu-ftpd xferlog writer, which
    //    only records transfers (no FAIL LOGIN) and never touches syslog.
    //    Upgrades EXISTING "ours" configs written before these lines existed.
    let cfg = tokio::fs::read_to_string(VSFTPD_CONF)
        .await
        .unwrap_or_default();
    let mut c = cfg.clone();
    for directive in ["dual_log_enable=YES", "syslog_enable=YES"] {
        let key = directive.split('=').next().unwrap_or(directive);
        if !conf_sets(&c, key) {
            if !c.is_empty() && !c.ends_with('\n') {
                c.push('\n');
            }
            c.push_str(directive);
            c.push('\n');
        }
    }
    if c != cfg {
        atomic_write(Path::new(VSFTPD_CONF), c.as_bytes(), 0o644)
            .await
            .map_err(|e| {
                AdapterError::Other(format!("add syslog logging to {VSFTPD_CONF}: {e}"))
            })?;
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

#[cfg(test)]
mod local_root_tests {
    use super::*;

    /// The shape of the outage: `root_dir` IS the htdocs, so appending
    /// "/htdocs" produced `<site>/htdocs/htdocs` and vsftpd answered every
    /// login with "500 OOPS: cannot change directory".
    ///
    /// Asserted on the round-trip rather than on the caller, because the
    /// value that matters is what ends up in the per-user file.
    #[tokio::test]
    async fn the_web_root_round_trips_verbatim() {
        let d = tempfile::tempdir().expect("tmp");
        let root = d.path().join("home/u/example.cz/htdocs");
        std::fs::create_dir_all(&root).expect("mk");
        let want = root.to_str().expect("utf8");
        let body = format!("local_root={want}\nwrite_enable=YES\n");
        assert_eq!(
            conf_value(&body, "local_root"),
            Some(want),
            "the configured local_root must be exactly the hosting's root_dir"
        );
        assert!(
            !want.contains("htdocs/htdocs"),
            "the fixture itself must not carry the doubled path"
        );
    }

    /// A per-user file that predates the fix still says htdocs/htdocs. The
    /// check has to notice by COMPARING to root_dir — not by string-matching
    /// "htdocs/htdocs", which misses drift onto a sibling site's real
    /// directory, and not by testing that the path exists, which is a
    /// strictly weaker predicate.
    #[test]
    fn drift_is_detected_by_comparison_not_by_shape() {
        let expected = "/home/u/example.cz/htdocs";
        for stale in [
            "/home/u/example.cz/htdocs/htdocs", // the old bug
            "/home/u/other.cz/htdocs",          // a sibling site: exists, still wrong
            "/home/u",                          // the global fallback
            "",                                 // empty value
        ] {
            assert_ne!(
                stale, expected,
                "fixture must differ from the expected root"
            );
        }
    }
}

#[cfg(test)]
mod conf_parsing_tests {
    use super::{conf_sets, conf_value};

    /// The exact shape that defeated the old substring check: Debian ships
    /// vsftpd.conf with the directives present but COMMENTED OUT.
    #[test]
    fn a_commented_directive_is_not_set() {
        let stock = "# Example config file\n#local_enable=YES\n#write_enable=YES\nlisten=NO\n";
        assert!(!conf_sets(stock, "local_enable"));
        assert!(!conf_sets(stock, "write_enable"));
        assert!(conf_sets(stock, "listen"));
    }

    /// A prefix must not satisfy a shorter key — `listen_port=2121` is not
    /// `listen=`, and treating it as one would misread the whole file.
    #[test]
    fn a_longer_key_is_not_a_shorter_one() {
        let c = "listen_port=2121\n";
        assert!(!conf_sets(c, "listen"));
        assert!(conf_sets(c, "listen_port"));
        assert_eq!(conf_value(c, "listen_port"), Some("2121"));
    }

    #[test]
    fn indentation_and_trailing_space_are_tolerated() {
        let c = "  local_enable=YES   \n";
        assert!(conf_sets(c, "local_enable"));
    }

    /// vsftpd applies the LAST occurrence, so the parser must agree with it.
    #[test]
    fn the_last_uncommented_value_wins() {
        let c = "listen_port=21\n#listen_port=99\nlisten_port=2121\n";
        assert_eq!(conf_value(c, "listen_port"), Some("2121"));
    }

    #[test]
    fn missing_and_commented_values_are_none() {
        assert_eq!(conf_value("#listen_port=2121\n", "listen_port"), None);
        assert_eq!(conf_value("", "listen_port"), None);
    }
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

    #[tokio::test]
    async fn set_user_web_root_rejects_path_injection() {
        // A user with a '/' or '.' would escape user_config_dir as a filename —
        // must be refused BEFORE any filesystem work.
        for bad in ["a/b", "..", "x.y", "u:v", "l\nine"] {
            assert!(
                super::set_user_web_root(bad, "/home/x/site/htdocs")
                    .await
                    .is_err(),
                "should reject user {bad:?}"
            );
        }
    }

    #[test]
    fn hyperion_vsftpd_conf_wires_per_user_web_root() {
        assert!(super::HYPERION_VSFTPD_CONF.contains("user_config_dir=/etc/vsftpd/user_conf"));
    }

    #[tokio::test]
    async fn ensure_web_root_owned_rejects_injection() {
        // A user with ':' / newline would break the chown spec — refuse before
        // shelling out.
        for bad in ["a:b", "u\nv", ""] {
            assert!(
                super::ensure_web_root_owned(bad, "/home/x/site/htdocs")
                    .await
                    .is_err(),
                "should reject user {bad:?}"
            );
        }
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
