//! Linux user provisioning via `useradd` / `userdel`.

use crate::{cmd, AdapterError};
use hyperion_validate::SystemUserName;

#[derive(Debug, Clone)]
pub struct UserSpec {
    pub name: SystemUserName,
    pub home_dir: String,
    pub shell: String,
}

impl UserSpec {
    pub fn new_with_default_shell(name: SystemUserName, home_dir: String) -> Self {
        Self {
            name,
            home_dir,
            shell: "/usr/sbin/nologin".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub home_dir: String,
    pub shell: String,
}

/// Idempotent `useradd`. Returns the user's uid.
///
/// If the user already exists and the home/shell match, no-op. If the
/// user exists with different home or shell, returns `AdapterError::Conflict`
/// — operators must resolve mismatches manually.
pub async fn ensure_user(spec: &UserSpec) -> Result<UserInfo, AdapterError> {
    if let Some(info) = lookup(&spec.name).await? {
        if info.home_dir != spec.home_dir {
            return Err(AdapterError::Conflict(format!(
                "user {} exists with home {} (expected {})",
                spec.name, info.home_dir, spec.home_dir
            )));
        }
        if info.shell != spec.shell {
            return Err(AdapterError::Conflict(format!(
                "user {} exists with shell {} (expected {})",
                spec.name, info.shell, spec.shell
            )));
        }
        return Ok(info);
    }
    cmd::run(
        "/usr/sbin/useradd",
        &[
            "-m",
            "-d",
            &spec.home_dir,
            "-s",
            &spec.shell,
            "-U",
            spec.name.as_str(),
        ],
    )
    .await?;
    lookup(&spec.name)
        .await?
        .ok_or_else(|| AdapterError::Other(format!("user {} not found after useradd", spec.name)))
}

/// `usermod -L` to lock the password and swap shell to `/usr/sbin/nologin`.
/// Idempotent — running on an already-locked account is a no-op.
pub async fn lock_login(name: &SystemUserName) -> Result<(), AdapterError> {
    if lookup(name).await?.is_none() {
        return Ok(());
    }
    cmd::run("/usr/sbin/usermod", &["-L", name.as_str()]).await?;
    cmd::run(
        "/usr/sbin/usermod",
        &["-s", "/usr/sbin/nologin", name.as_str()],
    )
    .await?;
    Ok(())
}

/// `usermod -U` to unlock the password. The shell stays at /usr/sbin/nologin
/// because the agent's user spec sets it that way by default.
pub async fn unlock_login(name: &SystemUserName) -> Result<(), AdapterError> {
    if lookup(name).await?.is_none() {
        return Ok(());
    }
    cmd::run("/usr/sbin/usermod", &["-U", name.as_str()]).await?;
    Ok(())
}

/// The account-expiry field (shadow field 8) of `login`, verbatim: days since
/// the epoch, or empty for "never expires". `Ok(None)` when there is no such
/// account.
///
/// Read so it can be put back exactly. Suspension and the trash disable a
/// site's logins by expiring them (see [`set_login_expiry`]), and an operator
/// may have set an expiry of their own that a resume must not erase.
pub async fn login_expiry(login: &str) -> Result<Option<String>, AdapterError> {
    hyperion_validate::validate_login_name(login)
        .map_err(|e| AdapterError::Other(e.to_string()))?;
    let raw = tokio::fs::read_to_string("/etc/shadow")
        .await
        .map_err(|e| AdapterError::Other(format!("read /etc/shadow: {e}")))?;
    Ok(shadow_expiry_field(&raw, login).map(str::to_string))
}

/// Field 8 of `login`'s line in a shadow file, if the line exists.
fn shadow_expiry_field<'a>(shadow: &'a str, login: &str) -> Option<&'a str> {
    shadow.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.first() == Some(&login)).then(|| fields.get(7).copied().unwrap_or(""))
    })
}

/// Set `login`'s account expiry: `"1"` to disable every login, or a value
/// read earlier with [`login_expiry`] to put it back. A missing account is
/// success — an extra FTP login may have been deleted in the meantime.
///
/// Why expiry, and not `usermod -L`:
///
/// * `-L` only prefixes the password hash. OpenSSH skips its own
///   locked-account check when `UsePAM yes` (Debian's default), so a site's
///   SFTP key kept working on a suspended site. An expired account is refused
///   by PAM's account stage, which sshd, vsftpd, `su` and cron all run.
/// * `-U` strips a `!` whoever put it there, so resuming a site unlocked a
///   login that had been locked for some other reason. Expiry leaves the
///   password field alone.
/// * root's `sudo -u <user>` and `runuser` do not run the account stage for
///   the target, so wp-cli and the other maintenance Hyperion runs as the
///   site user keep working on a suspended site.
///
/// All three verified against Debian 12 (OpenSSH 9.2, vsftpd 3.0.3, sudo 1.9).
pub async fn set_login_expiry(login: &str, expiry: &str) -> Result<(), AdapterError> {
    hyperion_validate::validate_login_name(login)
        .map_err(|e| AdapterError::Other(e.to_string()))?;
    // Only what shadow itself stores: empty, or a (possibly negative) day count.
    let well_formed = expiry.is_empty()
        || expiry
            .strip_prefix('-')
            .unwrap_or(expiry)
            .bytes()
            .all(|b| b.is_ascii_digit());
    if !well_formed || expiry == "-" {
        return Err(AdapterError::Other(format!(
            "refusing account expiry {expiry:?} for {login}: not a shadow day count"
        )));
    }
    if lookup_raw(login).await?.is_none() {
        return Ok(());
    }
    cmd::run("/usr/sbin/usermod", &["-e", expiry, "--", login]).await?;
    Ok(())
}

/// Is a shadow expiry field in the past (or today) — is the account expired?
pub fn expiry_field_is_past(field: &str, now_secs: i64) -> bool {
    match field.trim().parse::<i64>() {
        // Exactly pam_unix's rule (`sp_expire >= 0 && curdays >= sp_expire`),
        // because PAM is what refuses the login: 0 is expired, -1 and empty
        // are never.
        Ok(days) if days >= 0 => days * 86_400 <= now_secs,
        _ => false,
    }
}

/// `pkill -KILL -u <name>`. Best-effort: not-found / no-procs return Ok.
pub async fn kill_user_procs(name: &SystemUserName) -> Result<(), AdapterError> {
    match cmd::run("/usr/bin/pkill", &["-KILL", "-u", name.as_str()]).await {
        Ok(_) => Ok(()),
        // pkill exits 1 when no matching processes; treat as no-op.
        Err(AdapterError::Command { code: 1, .. }) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Delete a Linux user and their home directory.
pub async fn delete_user(name: &SystemUserName) -> Result<(), AdapterError> {
    if lookup(name).await?.is_none() {
        return Ok(());
    }
    cmd::run("/usr/sbin/userdel", &["-r", name.as_str()]).await?;
    Ok(())
}

/// Look up a user by name via `getent passwd`. Returns `None` when absent.
/// Does an account with this raw login exist?
///
/// Takes a `&str` rather than a validated `SystemUserName` because extra FTP
/// logins are operator-chosen and are checked against their own, narrower
/// rule — but they still occupy the node-wide passwd namespace, so a
/// collision has to be caught before `useradd` reports it as a shell error.
pub async fn lookup_raw(login: &str) -> Result<Option<UserInfo>, AdapterError> {
    if login.is_empty() || login.contains([':', '\n', '\r', '\0', '/']) {
        return Err(AdapterError::Other(format!("illegal login {login:?}")));
    }
    let out = match cmd::run("/usr/bin/getent", &["passwd", login]).await {
        Ok(s) => s,
        Err(AdapterError::Command { code: 2, .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    parse_passwd_line(out.trim())
}

/// Parse one `getent passwd` line: `name:x:uid:gid:gecos:home:shell`.
fn parse_passwd_line(line: &str) -> Result<Option<UserInfo>, AdapterError> {
    if line.is_empty() {
        return Ok(None);
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return Err(AdapterError::Other(format!(
            "malformed getent line: {line}"
        )));
    }
    let uid: u32 = parts[2]
        .parse()
        .map_err(|e| AdapterError::Other(format!("bad uid: {e}")))?;
    let gid: u32 = parts[3]
        .parse()
        .map_err(|e| AdapterError::Other(format!("bad gid: {e}")))?;
    Ok(Some(UserInfo {
        uid,
        gid,
        home_dir: parts[5].to_string(),
        shell: parts[6].to_string(),
    }))
}

pub async fn lookup(name: &SystemUserName) -> Result<Option<UserInfo>, AdapterError> {
    let out = match cmd::run("/usr/bin/getent", &["passwd", name.as_str()]).await {
        Ok(s) => s,
        Err(AdapterError::Command { code: 2, .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    // getent passwd line: name:x:uid:gid:gecos:home:shell
    let line = out.trim();
    if line.is_empty() {
        return Ok(None);
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return Err(AdapterError::Other(format!(
            "malformed getent line: {line}"
        )));
    }
    let uid: u32 = parts[2]
        .parse()
        .map_err(|e| AdapterError::Other(format!("bad uid: {e}")))?;
    let gid: u32 = parts[3]
        .parse()
        .map_err(|e| AdapterError::Other(format!("bad gid: {e}")))?;
    Ok(Some(UserInfo {
        uid,
        gid,
        home_dir: parts[5].into(),
        shell: parts[6].into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_validate::SystemUserName;

    #[test]
    fn shadow_expiry_field_is_read_per_login() {
        let shadow = "root:*:19000:0:99999:7:::\n\
                      kos_cz:$y$abc:19000:0:99999:7:::\n\
                      ftp.kos.cz:!$y$def:19000:0:99999:7::1:\n\
                      short:x:1";
        assert_eq!(shadow_expiry_field(shadow, "kos_cz"), Some(""));
        assert_eq!(shadow_expiry_field(shadow, "ftp.kos.cz"), Some("1"));
        assert_eq!(
            shadow_expiry_field(shadow, "short"),
            Some(""),
            "a short line is 'never'"
        );
        assert_eq!(
            shadow_expiry_field(shadow, "kos"),
            None,
            "a prefix is not a match"
        );
    }

    #[test]
    fn expiry_in_the_past_disables_the_account() {
        let now = 20_000 * 86_400;
        assert!(expiry_field_is_past("1", now));
        assert!(expiry_field_is_past("20000", now));
        assert!(!expiry_field_is_past("20001", now));
        assert!(!expiry_field_is_past("", now));
        assert!(!expiry_field_is_past("-1", now));
        assert!(
            expiry_field_is_past("0", now),
            "pam_unix treats 0 as expired"
        );
    }

    fn spec(name: &str) -> UserSpec {
        UserSpec::new_with_default_shell(
            SystemUserName::parse(name).expect("name"),
            format!("/home/{name}"),
        )
    }

    #[tokio::test]
    #[ignore = "requires root + Debian system tools"]
    async fn ensure_user_creates_then_idempotent() {
        let s = spec("lm_test_aaa");
        let info = ensure_user(&s).await.expect("ensure");
        assert!(info.uid >= 1000);
        let info2 = ensure_user(&s).await.expect("idempotent");
        assert_eq!(info.uid, info2.uid);
        delete_user(&s.name).await.expect("cleanup");
    }

    #[tokio::test]
    async fn lookup_for_unknown_user_does_not_panic() {
        let n = SystemUserName::parse("lm_no_such_user_xyz").expect("name");
        // On macOS this path will produce an error (getent doesn't exist); on Linux it returns None.
        // Either is OK — but we don't want a panic.
        let _ = lookup(&n).await;
    }
}
