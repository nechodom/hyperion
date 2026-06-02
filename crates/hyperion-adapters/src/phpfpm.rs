//! PHP-FPM pool generation + reload.

use crate::{cmd, fs::atomic_write, AdapterError};
use askama::Template;
use hyperion_types::PhpVersion;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct PoolInput<'a> {
    pub system_user: &'a str,
    pub domain: &'a str,
    pub php_version: PhpVersion,
    pub max_children: u32,
    pub max_requests: u32,
    pub memory_mb: u32,
    pub max_exec_secs: u32,
}

impl<'a> PoolInput<'a> {
    pub fn defaults(system_user: &'a str, domain: &'a str, php_version: PhpVersion) -> Self {
        Self {
            system_user,
            domain,
            php_version,
            max_children: 5,
            max_requests: 1000,
            memory_mb: 256,
            max_exec_secs: 60,
        }
    }
}

#[derive(Template)]
#[template(path = "phpfpm-pool.conf.j2", escape = "none")]
struct PoolTpl<'a> {
    system_user: &'a str,
    domain: &'a str,
    php_version: &'a str,
    max_children: u32,
    max_requests: u32,
    memory_mb: u32,
    max_exec_secs: u32,
}

pub fn render(input: &PoolInput<'_>) -> Result<String, AdapterError> {
    let tpl = PoolTpl {
        system_user: input.system_user,
        domain: input.domain,
        php_version: input.php_version.as_str(),
        max_children: input.max_children,
        max_requests: input.max_requests,
        memory_mb: input.memory_mb,
        max_exec_secs: input.max_exec_secs,
    };
    Ok(tpl.render()?)
}

pub fn pool_path(input: &PoolInput<'_>) -> PathBuf {
    PathBuf::from(input.php_version.pool_dir()).join(format!("{}.conf", input.system_user))
}

/// Render + atomic-write + reload. Idempotent.
pub async fn ensure_pool(input: &PoolInput<'_>) -> Result<PathBuf, AdapterError> {
    let body = render(input)?;
    let path = pool_path(input);
    atomic_write(&path, body.as_bytes(), 0o644).await?;
    reload(input.php_version).await?;
    Ok(path)
}

/// Remove the pool file and reload. Idempotent.
pub async fn delete_pool(system_user: &str, php_version: PhpVersion) -> Result<(), AdapterError> {
    let path = PathBuf::from(php_version.pool_dir()).join(format!("{system_user}.conf"));
    if tokio::fs::metadata(&path).await.is_ok() {
        tokio::fs::remove_file(&path).await?;
    }
    reload(php_version).await
}

/// Reload php-fpm — and if the service isn't running, enable + start it
/// first. On a brand-new install this is the difference between "first
/// hosting create works" and "first hosting create fails because the
/// operator forgot `systemctl enable php8.3-fpm`".
pub async fn reload(php_version: PhpVersion) -> Result<(), AdapterError> {
    let svc = php_version.service_name();
    // Liveness probe — systemctl is-active returns 0 iff the unit is
    // active. We don't propagate the error here (some systems lack the
    // unit entirely; that case will surface as a clearer reload error).
    let active = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", &svc])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if !active {
        tracing::warn!(service = %svc, "php-fpm not active — enabling + starting");
        // enable --now is idempotent: enable + start in one shot.
        if let Err(e) = cmd::run("/usr/bin/systemctl", &["enable", "--now", &svc]).await {
            return Err(AdapterError::Other(format!(
                "{svc} is inactive and `systemctl enable --now {svc}` failed: {e}. \
                 Install it with: apt-get install -y {pkg}",
                pkg = svc.trim_end_matches(".service"),
            )));
        }
        // After enable --now the daemon is already running; skip reload
        // since the just-started process picked up our pool file at boot.
        return Ok(());
    }
    cmd::run("/usr/bin/systemctl", &["reload", &svc]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_key_fields() {
        let out = render(&PoolInput::defaults(
            "alice_cz",
            "alice.cz",
            PhpVersion::V8_3,
        ))
        .expect("render");
        assert!(out.contains("[alice_cz]"));
        assert!(out.contains("user = alice_cz"));
        assert!(out.contains("listen = /run/php/8.3/alice_cz.sock"));
        assert!(out.contains("pm.max_children = 5"));
        assert!(out.contains("php_admin_value[memory_limit] = 256M"));
        assert!(out.contains("open_basedir] = /home/alice_cz/alice.cz:/tmp"));
    }

    #[test]
    fn render_respects_overridden_limits() {
        let mut input = PoolInput::defaults("u", "u.cz", PhpVersion::V8_4);
        input.max_children = 25;
        input.memory_mb = 1024;
        input.max_exec_secs = 120;
        input.max_requests = 5000;
        let out = render(&input).expect("render");
        assert!(out.contains("pm.max_children = 25"));
        assert!(out.contains("memory_limit] = 1024M"));
        assert!(out.contains("max_execution_time] = 120"));
        assert!(out.contains("pm.max_requests = 5000"));
    }

    #[test]
    fn pool_path_shape() {
        let p = pool_path(&PoolInput::defaults("x", "x.cz", PhpVersion::V8_2));
        assert_eq!(p.to_string_lossy(), "/etc/php/8.2/fpm/pool.d/x.conf");
    }
}
