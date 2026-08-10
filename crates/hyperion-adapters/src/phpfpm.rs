//! PHP-FPM pool generation + reload.

use crate::{cmd, fs::atomic_write, AdapterError};
use askama::Template;
use hyperion_types::PhpVersion;
use std::os::unix::fs::PermissionsExt;
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
    /// Owner of the FPM listen socket — MUST be the user nginx workers
    /// run as, otherwise `nginx → fastcgi_pass unix:...` returns 502
    /// with `connect() failed (13: Permission denied)`. Resolved at
    /// runtime via `crate::nginx::detect_user()` so an existing nginx
    /// with `user vito;` (CloudPanel inheritance) works without
    /// editing nginx.conf.
    pub listen_owner: &'a str,
    pub listen_group: &'a str,
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
            listen_owner: crate::nginx::DEFAULT_NGINX_USER,
            listen_group: crate::nginx::DEFAULT_NGINX_USER,
        }
    }

    /// Convenience: copy `defaults()` but override socket owner/group.
    pub fn defaults_with_owner(
        system_user: &'a str,
        domain: &'a str,
        php_version: PhpVersion,
        listen_owner: &'a str,
        listen_group: &'a str,
    ) -> Self {
        Self {
            listen_owner,
            listen_group,
            ..Self::defaults(system_user, domain, php_version)
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
    listen_owner: &'a str,
    listen_group: &'a str,
    /// pm.* spare-server knobs DERIVED from max_children (below). FPM
    /// refuses to start when `pm.max_spare_servers > pm.max_children`,
    /// so hardcoding start=2/min=1/max=3 breaks any pool whose operator
    /// set max_children to 1 or 2.
    start_servers: u32,
    min_spare_servers: u32,
    max_spare_servers: u32,
    /// request_terminate_timeout — the FPM backstop, kept ABOVE
    /// max_execution_time so PHP's own limit fires first.
    request_terminate_secs: u32,
}

pub fn render(input: &PoolInput<'_>) -> Result<String, AdapterError> {
    // Clamp the pm.* family so the pool is valid for ANY max_children ≥ 1:
    // max_spare ≤ max_children, min_spare ≥ 1, min ≤ start ≤ max_spare.
    let max_children = input.max_children.max(1);
    let max_spare_servers = max_children.min(3);
    let min_spare_servers = 1;
    let start_servers = max_spare_servers.min(2);
    // FPM backstop above PHP's own max_execution_time (+30s headroom) so a
    // worker blocked in a syscall past its exec limit still gets reaped.
    let request_terminate_secs = input.max_exec_secs.saturating_add(30);
    let tpl = PoolTpl {
        system_user: input.system_user,
        domain: input.domain,
        php_version: input.php_version.as_str(),
        max_children,
        max_requests: input.max_requests,
        memory_mb: input.memory_mb,
        max_exec_secs: input.max_exec_secs,
        listen_owner: input.listen_owner,
        listen_group: input.listen_group,
        start_servers,
        min_spare_servers,
        max_spare_servers,
        request_terminate_secs,
    };
    Ok(tpl.render()?)
}

pub fn pool_path(input: &PoolInput<'_>) -> PathBuf {
    PathBuf::from(input.php_version.pool_dir()).join(format!("{}.conf", input.system_user))
}

/// Self-heal: ensure `/run/php/<ver>/` exists with mode 0755 for
/// every supported PHP version. Best-effort, never errors. Called from
/// the agent's startup so an upgrade via `update.sh` (which restarts
/// the agent) is enough to recover from the previous "missing dir →
/// 502" bug on existing installs — no manual systemd-tmpfiles run
/// required. Idempotent: running twice on a healthy system is a no-op.
pub async fn ensure_socket_dirs() {
    for v in PhpVersion::all() {
        let dir = socket_parent_dir(*v);
        if let Err(e) = tokio::fs::create_dir_all(&dir).await {
            tracing::warn!(
                error = %e,
                path = %dir.display(),
                "could not create FPM socket parent dir at startup"
            );
            continue;
        }
        let _ = tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).await;
    }
}

/// Parent dir for the per-pool listen socket — e.g. `/run/php/8.3/`.
///
/// The pool template declares
/// `listen = /run/php/<ver>/<user>.sock`, and the socket's parent dir
/// must exist for PHP-FPM to bind successfully. Debian's php-fpm package
/// creates `/run/php` but NOT per-version subdirs, and `/run` is a
/// tmpfs that's wiped on reboot — without our tmpfiles.d snippet + this
/// runtime mkdir, every fresh boot leaves PHP-FPM unable to open its
/// socket and nginx returns 502 Bad Gateway.
pub fn socket_parent_dir(php_version: PhpVersion) -> PathBuf {
    PathBuf::from(format!("/run/php/{}", php_version.as_str()))
}

/// Render + atomic-write + reload. Idempotent.
///
/// Before writing the pool config we create `/run/php/<ver>/` (if it
/// doesn't already exist) at mode 0755, owned by root. PHP-FPM master
/// runs as root and opens the listen socket — we then chown the socket
/// file itself to www-data:www-data via the `listen.owner/listen.group`
/// directives in the pool template.
pub async fn ensure_pool(input: &PoolInput<'_>) -> Result<PathBuf, AdapterError> {
    // Make sure the socket's parent dir exists BEFORE we hand the pool
    // config to PHP-FPM. Mode 0755 = world-traversable; nginx
    // (www-data) needs the x-bit to reach the socket file inside.
    let sock_parent = socket_parent_dir(input.php_version);
    if let Err(e) = tokio::fs::create_dir_all(&sock_parent).await {
        // Don't bail — log + continue. On a system with a healthy
        // tmpfiles.d setup the dir already exists and this is a no-op;
        // on a broken setup the FPM reload below will surface the real
        // error with full context.
        tracing::warn!(
            error = %e,
            path = %sock_parent.display(),
            "could not pre-create FPM socket parent dir; FPM may fail to open its socket"
        );
    } else {
        // Force 0755 even if the dir already existed — defends against
        // an operator who restricted it manually.
        let _ =
            tokio::fs::set_permissions(&sock_parent, std::fs::Permissions::from_mode(0o755)).await;
    }

    let body = render(input)?;
    let path = pool_path(input);
    // Backup the existing pool (if any) so we can roll back when our
    // new file fails `php-fpm -t`. Without this, an `ensure_pool`
    // that ends up writing a malformed file would brick the entire
    // php<ver>-fpm service on the next reload.
    let backup = match tokio::fs::read(&path).await {
        Ok(prev) => Some(prev),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(AdapterError::Io(e)),
    };
    atomic_write(&path, body.as_bytes(), 0o644).await?;
    // Defense in depth: `php-fpm<ver> -t` parses the WHOLE pool dir
    // and exits non-zero on any syntax error, with the file path +
    // line number in stderr. If our just-written file is bad, restore
    // the previous one (or remove it on fresh creates) so the live
    // FPM daemon keeps serving every other hosting on this version.
    if let Err(e) = test_config(input.php_version).await {
        match backup {
            Some(prev) => {
                let _ = atomic_write(&path, &prev, 0o644).await;
            }
            None => {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        return Err(e);
    }
    reload(input.php_version).await?;
    Ok(path)
}

/// Run `php-fpm<ver> -t` and return an error with the exact
/// stderr if the configuration doesn't validate. We use this as
/// a gate before reloading FPM — a bad pool would otherwise
/// crash the daemon (exit 78 EX_CONFIG) and take every hosting
/// on this PHP version with it.
///
/// Returns `Ok(())` for valid configs; `Err(AdapterError::Command)`
/// with stderr verbatim otherwise. If the `php-fpm<ver>` binary
/// itself isn't installed (rare — FPM service is present but no
/// CLI) we return `Ok(())` so we don't block normal operation on
/// a missing diagnostic tool.
pub async fn test_config(php_version: PhpVersion) -> Result<(), AdapterError> {
    let bin = format!("/usr/sbin/php-fpm{}", php_version.as_str());
    let out = match tokio::process::Command::new(&bin)
        .args(["-t"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(
                bin = %bin,
                "test_config: binary not found — skipping validation"
            );
            return Ok(());
        }
        Err(e) => return Err(AdapterError::Io(e)),
    };
    if out.status.success() {
        return Ok(());
    }
    // FPM prints errors on stderr; some distros also dump them to
    // stdout. Combine both so the operator sees the full picture.
    let mut tail = String::new();
    tail.push_str(&String::from_utf8_lossy(&out.stderr));
    if !out.stdout.is_empty() {
        if !tail.is_empty() && !tail.ends_with('\n') {
            tail.push('\n');
        }
        tail.push_str(&String::from_utf8_lossy(&out.stdout));
    }
    Err(AdapterError::Command {
        cmd: format!("{bin} -t"),
        code: out.status.code().unwrap_or(-1),
        stderr_tail: tail,
    })
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
/// Install one PHP version's FPM plus the SAME extension set the
/// installer ships for the default version — mirrored from
/// install-master.sh, with the version substituted.
///
/// The full set, not bare `phpX.Y-fpm`, deliberately: a WordPress site
/// switched onto a version that lacks php-mysql greets its visitors with
/// "error establishing a database connection", which reads as a worse
/// failure than the 502 this install is fixing. Same `policy-rc.d`
/// inhibitor as the OpenDKIM install — maintainer scripts must not start
/// services mid-transaction — and the same recovery for a half-configured
/// dpkg state from an earlier interrupted attempt.
async fn install_php_version(php_version: PhpVersion) -> Result<(), AdapterError> {
    let v = php_version.as_str();
    let policy = std::path::Path::new("/usr/sbin/policy-rc.d");
    let created_policy = if policy.exists() {
        false
    } else {
        crate::fs::atomic_write(policy, b"#!/bin/sh\nexit 101\n", 0o755)
            .await
            .is_ok()
    };
    let apt = |args: Vec<String>| async move {
        let mut argv: Vec<&str> = vec!["DEBIAN_FRONTEND=noninteractive", "apt-get"];
        let owned: Vec<String> = args;
        argv.extend(owned.iter().map(|s| s.as_str()));
        cmd::run_capturing_all("/usr/bin/env", &argv).await
    };
    let _ = cmd::run_capturing_all(
        "/usr/bin/env",
        &[
            "DEBIAN_FRONTEND=noninteractive",
            "dpkg",
            "--configure",
            "-a",
        ],
    )
    .await;
    let _ = apt(vec!["update".into(), "-qq".into()]).await;
    let mut install: Vec<String> = vec!["install".into(), "-y".into(), "-qq".into()];
    for ext in [
        "fpm", "cli", "mysql", "pgsql", "curl", "gd", "mbstring", "xml", "zip",
    ] {
        install.push(format!("php{v}-{ext}"));
    }
    let res = apt(install).await;
    if created_policy {
        let _ = tokio::fs::remove_file(policy).await;
    }
    res.map(|_| ()).map_err(|e| {
        let raw = e.to_string();
        match cmd::explain_apt_failure(&raw) {
            Some(reason) => AdapterError::Other(format!(
                "PHP {v} could not be installed — {reason}\n\nOriginal output:\n{raw}"
            )),
            None => AdapterError::Other(format!("PHP {v} could not be installed: {raw}")),
        }
    })
}

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
        // Belt-and-braces recovery for the "Start request repeated
        // too quickly" trap. After 5 failed restart cycles, systemd
        // marks the unit "failed" and refuses every subsequent
        // start until `reset-failed` clears the counter. A bare
        // `enable --now` on such a unit returns exit 1 with no
        // useful clue — we'd just see "Job for X failed". So when
        // is-failed is true (or even when it's ambiguous), clear
        // the counter first. `reset-failed` is a no-op on healthy
        // units, so this is always safe.
        if is_failed(&svc).await {
            tracing::warn!(service = %svc, "php-fpm is in failed state — resetting before start");
            let _ = cmd::run("/usr/bin/systemctl", &["reset-failed", &svc]).await;
        }
        tracing::warn!(service = %svc, "php-fpm not active — enabling + starting");
        // enable --now is idempotent: enable + start in one shot.
        if let Err(e) = cmd::run("/usr/bin/systemctl", &["enable", "--now", &svc]).await {
            // The unit does not exist ⇒ this PHP version was never
            // installed on this node. The panel's version picker offers
            // every supported version, so this is a NORMAL path, not an
            // error to bounce back at the operator: the installer only
            // ships one version, and the sury repo every node already has
            // carries the rest. Telling the operator to go run apt by
            // hand — which the old message did — punted OUR job to them,
            // and left the hosting row already pointing at a version with
            // no pool behind it: a 502 with homework attached.
            let unit_missing = format!("{e}")
                .to_ascii_lowercase()
                .contains("does not exist");
            if !unit_missing {
                return Err(AdapterError::Other(format!(
                    "{svc} is inactive and `systemctl enable --now {svc}` failed: {e}"
                )));
            }
            tracing::warn!(
                service = %svc,
                "php-fpm unit missing — installing this PHP version from the configured repos"
            );
            install_php_version(php_version).await?;
            cmd::run("/usr/bin/systemctl", &["enable", "--now", &svc])
                .await
                .map_err(|e| {
                    AdapterError::Other(format!(
                        "{svc} still failed to start after installing it: {e}"
                    ))
                })?;
        }
        // After enable --now the daemon is already running; skip reload
        // since the just-started process picked up our pool file at boot.
        return Ok(());
    }
    cmd::run("/usr/bin/systemctl", &["reload", &svc]).await?;
    Ok(())
}

/// `systemctl is-failed <svc>` — returns true if the unit is in
/// "failed" sub-state (typical after Start request repeated too
/// quickly). Returns false on any other state including activating,
/// inactive, active, or when systemctl itself errors (we don't want
/// to confuse "couldn't check" with "definitely failed").
async fn is_failed(svc: &str) -> bool {
    tokio::process::Command::new("/usr/bin/systemctl")
        .args(["is-failed", "--quiet", svc])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
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
        // Default owner is www-data (the Debian convention) when no
        // override is supplied.
        assert!(out.contains("listen.owner = www-data"));
        assert!(out.contains("listen.group = www-data"));
    }

    /// Regression test for the "exit 78 EX_CONFIG via `#` comment"
    /// bug: PHP-FPM's Zend INI parser only treats `;` as a comment
    /// character. Lines starting with `#` get parsed as bare keys
    /// without values and crash the daemon at load time. The pool
    /// template MUST NOT contain any line beginning with `#` (after
    /// trimming whitespace) or we'll brick the whole php<ver>-fpm
    /// service.
    #[test]
    fn render_uses_only_semicolon_comments() {
        let out = render(&PoolInput::defaults(
            "alice_cz",
            "alice.cz",
            PhpVersion::V8_3,
        ))
        .expect("render");
        for (lineno, raw) in out.lines().enumerate() {
            let trimmed = raw.trim_start();
            assert!(
                !trimmed.starts_with('#'),
                "pool template line {} starts with `#` — \
                 Zend INI parser would reject this as a bare key. Use `;` instead. \
                 Offending line: {raw:?}",
                lineno + 1
            );
        }
    }

    /// Regression test for the "502 nginx user mismatch" bug.
    /// When the operator's nginx is configured `user vito;`, we MUST
    /// render `listen.owner = vito` (not www-data), otherwise nginx
    /// can't open the FPM socket and every PHP request 502s.
    #[test]
    fn render_uses_overridden_socket_owner() {
        let input = PoolInput::defaults_with_owner(
            "alice_cz",
            "alice.cz",
            PhpVersion::V8_3,
            "vito",
            "vito",
        );
        let out = render(&input).expect("render");
        assert!(
            out.contains("listen.owner = vito"),
            "pool must declare listen.owner = vito. got: {out}"
        );
        assert!(out.contains("listen.group = vito"));
        // www-data must NOT appear anywhere as the owner.
        assert!(
            !out.contains("listen.owner = www-data"),
            "rendering with overridden owner must NOT leak the default"
        );
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
        // Hardening + FPM backstop.
        assert!(out.contains("clear_env = yes"));
        assert!(out.contains("expose_php] = Off"));
        // request_terminate_timeout = max_exec + 30 headroom.
        assert!(
            out.contains("request_terminate_timeout = 150"),
            "terminate must sit above max_execution_time. got: {out}"
        );
    }

    /// FPM refuses to start when `pm.max_spare_servers > pm.max_children`
    /// (and start/min must fit inside). The spare-server family must
    /// therefore be DERIVED from max_children, or an operator setting
    /// max_children=1 kills their pool on the next reload.
    #[test]
    fn render_clamps_spare_servers_to_max_children() {
        // Tiny pool: everything collapses to 1.
        let mut input = PoolInput::defaults("u", "u.cz", PhpVersion::V8_3);
        input.max_children = 1;
        let out = render(&input).expect("render");
        assert!(out.contains("pm.max_children = 1"));
        assert!(out.contains("pm.start_servers = 1"));
        assert!(out.contains("pm.min_spare_servers = 1"));
        assert!(out.contains("pm.max_spare_servers = 1"));

        // max_children = 2 → max_spare 2, start 2.
        input.max_children = 2;
        let out = render(&input).expect("render");
        assert!(out.contains("pm.max_spare_servers = 2"));
        assert!(out.contains("pm.start_servers = 2"));

        // Default 5 keeps the historical 2/1/3 shape.
        input.max_children = 5;
        let out = render(&input).expect("render");
        assert!(out.contains("pm.start_servers = 2"));
        assert!(out.contains("pm.min_spare_servers = 1"));
        assert!(out.contains("pm.max_spare_servers = 3"));

        // A zero from a bad caller is clamped to a working 1-child pool.
        input.max_children = 0;
        let out = render(&input).expect("render");
        assert!(out.contains("pm.max_children = 1"));
    }

    #[test]
    fn pool_path_shape() {
        let p = pool_path(&PoolInput::defaults("x", "x.cz", PhpVersion::V8_2));
        assert_eq!(p.to_string_lossy(), "/etc/php/8.2/fpm/pool.d/x.conf");
    }

    /// The socket parent dir is derived directly from the version. If
    /// this drifts away from what the pool template writes into
    /// `listen = ...`, FPM would try to bind in a different directory
    /// than what we mkdir → 502. Lock the two together.
    #[test]
    fn socket_parent_dir_matches_rendered_listen() {
        for v in PhpVersion::all() {
            let parent = socket_parent_dir(*v);
            let rendered = render(&PoolInput::defaults("user1", "u.cz", *v)).expect("render");
            // The template emits `listen = /run/php/<ver>/user1.sock`.
            // The first '/' of /user1.sock starts immediately after the
            // dir. Strip it and compare.
            let expected_listen = format!("listen = {}/user1.sock", parent.display());
            assert!(
                rendered.contains(&expected_listen),
                "pool config must declare `{expected_listen}`. got: {rendered}"
            );
        }
    }
}
