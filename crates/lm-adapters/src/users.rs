//! Linux user provisioning via `useradd` / `userdel`.

use crate::{cmd, AdapterError};
use lm_validate::SystemUserName;

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

/// Delete a Linux user and their home directory.
pub async fn delete_user(name: &SystemUserName) -> Result<(), AdapterError> {
    if lookup(name).await?.is_none() {
        return Ok(());
    }
    cmd::run("/usr/sbin/userdel", &["-r", name.as_str()]).await?;
    Ok(())
}

/// Look up a user by name via `getent passwd`. Returns `None` when absent.
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
    use lm_validate::SystemUserName;

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
