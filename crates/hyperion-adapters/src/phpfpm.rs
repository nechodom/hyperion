//! PHP-FPM pool generation + reload.

use crate::{cmd, fs::atomic_write, AdapterError};
use askama::Template;
use hyperion_types::PhpVersion;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct PoolInput<'a> {
    pub system_user: &'a str,
    pub domain: &'a str,
    /// Other sites served by this pool. A pool is per system user and PHP
    /// version, so hostings sharing both share one file and it has to let
    /// all of them in. Order does not matter: any of them writes the same
    /// paths.
    pub also_serves: &'a [String],
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
            also_serves: &[],
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
    open_basedir: String,
    session_domain: &'a str,
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
    slowlog_path: String,
    slowlog_secs: u32,
}

/// Root-owned directory holding one slow-request log per pool.
pub const SLOWLOG_DIR: &str = "/var/log/hyperion/php-slow";

/// A request running longer than this gets its PHP stack trace logged.
/// Long enough that an ordinary uncached page never trips it, short enough
/// that five of them in a row are what empties a five-worker pool.
pub const SLOWLOG_SECS: u32 = 5;

/// Rotation for the slow logs. `copytruncate` because FPM keeps the file
/// open and only reopens it on USR1, which nothing here sends.
const SLOWLOG_LOGROTATE: &str = "/etc/logrotate.d/hyperion-php-slow";
const SLOWLOG_LOGROTATE_BODY: &str = r#"# Auto-managed by Hyperion.
/var/log/hyperion/php-slow/*.log {
    daily
    rotate 7
    maxsize 20M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
"#;

/// The slow-request log of one pool.
pub fn slowlog_path(system_user: &str) -> PathBuf {
    PathBuf::from(SLOWLOG_DIR).join(format!("{system_user}.log"))
}

/// Each pool's running workers, measured from `/proc`, by pool name. Needs
/// root for another user's `smaps_rollup`; a process it cannot read, or one
/// that exited meanwhile, is skipped. Empty off Linux.
pub async fn pool_memory(
) -> std::collections::HashMap<String, hyperion_types::phpworkers::PoolMemory> {
    use hyperion_types::phpworkers;
    tokio::task::spawn_blocking(|| {
        let mut out: std::collections::HashMap<String, phpworkers::PoolMemory> = Default::default();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for e in entries.flatten() {
            let name = e.file_name();
            if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(cmdline) = std::fs::read(e.path().join("cmdline")) else {
                continue;
            };
            let cmdline = String::from_utf8_lossy(&cmdline);
            let Some(pool) = phpworkers::pool_of_cmdline(&cmdline) else {
                continue;
            };
            let Some(pss) = std::fs::read_to_string(e.path().join("smaps_rollup"))
                .ok()
                .as_deref()
                .and_then(phpworkers::pss_mb)
            else {
                continue;
            };
            let m = out.entry(pool.to_string()).or_default();
            m.workers += 1;
            m.largest_mb = m.largest_mb.max(pss);
        }
        out
    })
    .await
    .unwrap_or_default()
}

/// The slowlog directory (0750 root) and its logrotate rule. FPM refuses
/// to start a pool whose slowlog directory is missing, so this runs before
/// every pool write. Idempotent on content.
async fn ensure_slowlog_dir() -> Result<(), AdapterError> {
    let dir = std::path::Path::new(SLOWLOG_DIR);
    tokio::fs::create_dir_all(dir).await?;
    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750)).await?;
    let current = tokio::fs::read_to_string(SLOWLOG_LOGROTATE).await.ok();
    if current.as_deref() != Some(SLOWLOG_LOGROTATE_BODY) {
        // Best effort: a box without logrotate still gets its slow log,
        // just unrotated.
        if let Err(e) = atomic_write(
            std::path::Path::new(SLOWLOG_LOGROTATE),
            SLOWLOG_LOGROTATE_BODY.as_bytes(),
            0o644,
        )
        .await
        {
            tracing::warn!(error = %e, "could not write the slowlog logrotate rule");
        }
    }
    Ok(())
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
    let mut domains: Vec<&str> = input.also_serves.iter().map(String::as_str).collect();
    domains.push(input.domain);
    domains.sort_unstable();
    domains.dedup();
    let mut open_basedir = String::new();
    for domain in &domains {
        open_basedir.push_str(&format!("/home/{}/{domain}:", input.system_user));
    }
    open_basedir.push_str("/tmp");
    let tpl = PoolTpl {
        system_user: input.system_user,
        open_basedir,
        session_domain: domains[0],
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
        slowlog_path: slowlog_path(input.system_user).display().to_string(),
        slowlog_secs: SLOWLOG_SECS,
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

    ensure_slowlog_dir().await?;
    // Node-wide OPcache sizing for this PHP version. Best-effort: a node
    // that cannot write it keeps the distro defaults, which still work.
    if let Err(e) = ensure_opcache_ini(input.php_version).await {
        tracing::warn!(error = %e, version = input.php_version.as_str(), "opcache ini not written");
    }
    // Startup only covers versions installed at the time; a version installed
    // later gets this with its first pool. Best-effort like the OPcache ini.
    if let Err(e) = ensure_oom_policy_dropin(input.php_version).await {
        tracing::warn!(error = %e, version = input.php_version.as_str(), "FPM OOM policy drop-in not written");
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

/// `/etc/php/<ver>/fpm/conf.d/90-hyperion-opcache.ini`. Loaded after the
/// distro's `10-opcache.ini` (which loads the extension), so these win.
pub fn opcache_ini_path(php_version: PhpVersion) -> PathBuf {
    PathBuf::from(format!(
        "/etc/php/{}/fpm/conf.d/90-hyperion-opcache.ini",
        php_version.as_str()
    ))
}

/// OPcache for a box that hosts many sites under ONE FPM master per PHP
/// version — every pool of that version shares one OPcache.
///
/// * Size: Debian's defaults (128 MB, 10 000 scripts) are sized for one
///   application. A single WordPress with a page builder and a shop is
///   several thousand scripts; a dozen of them overflow it, and a full
///   OPcache stops caching new scripts (or restarts, dropping everything)
///   — every request then compiles PHP again. Memory scales with the box.
/// * `validate_permission`: with one cache shared by many tenants, a script
///   is only served from it to a pool that can read the file itself, so a
///   site can never run another site's cached code it could not open.
/// * Timestamps stay validated (every 2 s): tenants edit their own files
///   over SFTP and must see the change without a reload.
pub fn render_opcache_ini(mem_total_kib: u64) -> String {
    let memory_mb = if mem_total_kib >= 3 * 1024 * 1024 {
        256
    } else {
        128
    };
    format!(
        "; Auto-managed by Hyperion. Do not edit — rewritten on every pool write.\n\
         opcache.enable=1\n\
         opcache.memory_consumption={memory_mb}\n\
         opcache.interned_strings_buffer=16\n\
         opcache.max_accelerated_files=50000\n\
         opcache.validate_timestamps=1\n\
         opcache.revalidate_freq=2\n\
         opcache.validate_permission=1\n"
    )
}

/// Write [`render_opcache_ini`] for this version. Idempotent on content;
/// returns whether it changed (the caller's FPM reload applies it). Skipped
/// when the version's FPM is not installed (no conf.d to write into).
pub async fn ensure_opcache_ini(php_version: PhpVersion) -> Result<bool, AdapterError> {
    let path = opcache_ini_path(php_version);
    let Some(dir) = path.parent() else {
        return Ok(false);
    };
    if !tokio::fs::try_exists(dir).await.unwrap_or(false) {
        return Ok(false);
    }
    let want = render_opcache_ini(crate::redis::mem_total_kib().await);
    if tokio::fs::read_to_string(&path).await.ok().as_deref() == Some(want.as_str()) {
        return Ok(false);
    }
    atomic_write(&path, want.as_bytes(), 0o644).await?;
    Ok(true)
}

/// `/etc/systemd/system/php<ver>-fpm.service.d/90-hyperion-oom-policy.conf`.
pub fn oom_policy_dropin_path(php_version: PhpVersion) -> PathBuf {
    PathBuf::from(format!(
        "/etc/systemd/system/{}.service.d/90-hyperion-oom-policy.conf",
        php_version.service_name()
    ))
}

/// Every site on a PHP version shares one FPM unit, and systemd's default
/// `OOMPolicy=stop` stops the whole unit when the OOM killer takes any one
/// process in it: one site's oversized worker cuts every neighbour's
/// in-flight requests and returns 502 until something restarts the unit
/// (Debian 12's package never does). With `continue` the FPM master just
/// replaces the worker. A master killed outright still takes the unit down;
/// no OOM policy changes that.
pub fn render_oom_policy_dropin() -> &'static str {
    "# Auto-managed by Hyperion. Do not edit.\n\
     [Service]\n\
     OOMPolicy=continue\n"
}

/// Write [`render_oom_policy_dropin`] for this version and `daemon-reload`.
/// Idempotent on content; returns whether it changed. Skipped when the
/// version's FPM unit is not installed. Applies to the running unit without
/// restarting it, so this never touches a live site.
pub async fn ensure_oom_policy_dropin(php_version: PhpVersion) -> Result<bool, AdapterError> {
    let path = oom_policy_dropin_path(php_version);
    let want = render_oom_policy_dropin();
    if tokio::fs::read_to_string(&path).await.ok().as_deref() == Some(want) {
        return Ok(false);
    }
    let svc = format!("{}.service", php_version.service_name());
    let load_state = cmd::run(
        "/usr/bin/systemctl",
        &["show", "--property=LoadState", "--value", &svc],
    )
    .await?;
    if load_state.trim() != "loaded" {
        return Ok(false);
    }
    atomic_write(&path, want.as_bytes(), 0o644).await?;
    if let Err(e) = cmd::run("/usr/bin/systemctl", &["daemon-reload"]).await {
        // systemd has not seen the file; removing it makes the next run retry
        // rather than find matching content and call it done.
        let _ = tokio::fs::remove_file(&path).await;
        return Err(e);
    }
    Ok(true)
}

/// [`ensure_oom_policy_dropin`] for every supported version. Best-effort,
/// never errors. Called from the agent's startup so `update.sh` (which
/// restarts the agent) is enough to cover existing nodes.
pub async fn ensure_oom_policy_dropins() {
    for v in PhpVersion::all() {
        if let Err(e) = ensure_oom_policy_dropin(*v).await {
            tracing::warn!(error = %e, version = v.as_str(), "FPM OOM policy drop-in not written");
        }
    }
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
        "fpm", "cli", "mysql", "pgsql", "curl", "gd", "mbstring", "xml", "zip", "soap",
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

/// First wait after trying to recover a failed FPM unit, doubled per attempt.
const RECOVERY_BACKOFF_MIN_SECS: i64 = 60;
const RECOVERY_BACKOFF_MAX_SECS: i64 = 30 * 60;

/// Paces the attempts to bring failed FPM units back. A unit that fails again
/// straight after a start (a pool `php-fpm -t` accepts but the master rejects,
/// a box out of memory) must not be restarted every tick: `reset-failed`
/// clears systemd's own start limit, so nothing else would stop that loop.
///
/// Whether the attempt worked does not matter here, since a start that
/// succeeds can still die a second later. What ends the streak is the unit
/// staying out of `failed` for the whole wait: [`Self::note_not_failed`].
#[derive(Debug, Default)]
pub struct RecoveryBackoff {
    /// Version → (attempts in a row, unix time the next one may run).
    streaks: HashMap<PhpVersion, (u32, i64)>,
}

impl RecoveryBackoff {
    pub fn may_attempt(&self, version: PhpVersion, now: i64) -> bool {
        self.streaks
            .get(&version)
            .map_or(true, |(_, retry_at)| now >= *retry_at)
    }

    pub fn record_attempt(&mut self, version: PhpVersion, now: i64) {
        let (attempts, retry_at) = self.streaks.entry(version).or_insert((0, 0));
        let wait = RECOVERY_BACKOFF_MIN_SECS
            .saturating_mul(1i64.checked_shl(*attempts).unwrap_or(i64::MAX))
            .min(RECOVERY_BACKOFF_MAX_SECS);
        *attempts = attempts.saturating_add(1);
        *retry_at = now + wait;
    }

    pub fn note_not_failed(&mut self, version: PhpVersion, now: i64) {
        if self.may_attempt(version, now) {
            self.streaks.remove(&version);
        }
    }
}

/// What `/proc/meminfo` says that the preflight needs.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct MemInfo {
    pub mem_total_mb: Option<i64>,
    pub mem_available_mb: Option<i64>,
    pub swap_total_kib: i64,
}

/// Read `MemTotal`, `MemAvailable` and `SwapTotal` out of `/proc/meminfo`
/// text. RAM that is missing stays `None` (the verdict then skips the RAM
/// bound rather than guess one); no swap line means no swap.
pub fn parse_meminfo(meminfo: &str) -> MemInfo {
    let kib = |key: &str| -> Option<i64> {
        meminfo
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse::<i64>().ok())
    };
    MemInfo {
        mem_total_mb: kib("MemTotal:").map(|k| k / 1024).filter(|&mb| mb > 0),
        mem_available_mb: kib("MemAvailable:").map(|k| k / 1024),
        swap_total_kib: kib("SwapTotal:").unwrap_or(0),
    }
}

/// The major version in `systemctl --version`'s first line
/// (`systemd 252 (252.31-1~deb12u1)`).
pub fn parse_systemd_major(version_output: &str) -> Option<u32> {
    version_output
        .lines()
        .next()?
        .strip_prefix("systemd ")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// What this node reports about running a PHP-FPM master per site user. Plain
/// readings only; `hyperion_types::fpm_own::judge` decides. `php_users` and
/// `own_users` are the service's to fill (they come from the database).
pub async fn preflight_facts() -> hyperion_types::fpm_own::PreflightFacts {
    let cgroup_controllers = tokio::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .await
        .ok();
    let systemd_version = cmd::run("/usr/bin/systemctl", &["--version"])
        .await
        .ok()
        .and_then(|out| parse_systemd_major(&out));
    let mem = tokio::fs::read_to_string("/proc/meminfo")
        .await
        .map(|m| parse_meminfo(&m))
        .unwrap_or_default();
    hyperion_types::fpm_own::PreflightFacts {
        cgroup_controllers,
        systemd_version,
        swap_total_kib: mem.swap_total_kib,
        mem_total_mb: mem.mem_total_mb,
        mem_available_mb: mem.mem_available_mb,
        php_users: 0,
        own_users: 0,
    }
}

#[cfg(test)]
mod tests {

    /// One OOM-killed worker must not stop the FPM master every other site
    /// on this version depends on. Exact match: a stray `MemoryMax=` or
    /// `Restart=` here would change every node's shared master.
    #[test]
    fn oom_policy_dropin_keeps_the_master_running() {
        assert_eq!(
            render_oom_policy_dropin(),
            "# Auto-managed by Hyperion. Do not edit.\n\
             [Service]\n\
             OOMPolicy=continue\n"
        );
        assert_eq!(
            oom_policy_dropin_path(PhpVersion::V8_3).to_string_lossy(),
            "/etc/systemd/system/php8.3-fpm.service.d/90-hyperion-oom-policy.conf"
        );
    }

    #[test]
    fn opcache_ini_scales_with_the_box_and_isolates_tenants() {
        let small = render_opcache_ini(2 * 1024 * 1024);
        let big = render_opcache_ini(8 * 1024 * 1024);
        assert!(small.contains("opcache.memory_consumption=128\n"));
        assert!(big.contains("opcache.memory_consumption=256\n"));
        for ini in [&small, &big] {
            assert!(ini.contains("opcache.validate_permission=1\n"));
            assert!(ini.contains("opcache.validate_timestamps=1\n"));
            assert!(ini.contains("opcache.max_accelerated_files=50000\n"));
        }
        assert_eq!(
            opcache_ini_path(PhpVersion::V8_3).to_string_lossy(),
            "/etc/php/8.3/fpm/conf.d/90-hyperion-opcache.ini"
        );
    }
    use super::*;

    /// A unit that keeps failing is retried on a growing schedule, capped,
    /// and never by every tick. A first failure is tried at once: that is
    /// the master OOM kill the tick exists for.
    #[test]
    fn recovery_backs_off_while_a_unit_keeps_failing() {
        let v = PhpVersion::V8_2;
        let mut b = RecoveryBackoff::default();
        assert!(b.may_attempt(v, 1000));

        let mut now = 1000;
        for wait in [60, 120, 240, 480, 960, 1800, 1800] {
            b.record_attempt(v, now);
            assert!(!b.may_attempt(v, now));
            assert!(!b.may_attempt(v, now + wait - 1), "wait {wait}");
            now += wait;
            assert!(b.may_attempt(v, now), "wait {wait}");
        }
        // Each version keeps its own streak.
        b.record_attempt(v, now);
        assert!(b.may_attempt(PhpVersion::V8_3, now));

        // A very long streak must not overflow the shift.
        for _ in 0..200 {
            b.record_attempt(v, now);
        }
        assert!(!b.may_attempt(v, now + 1799));
        assert!(b.may_attempt(v, now + 1800));
    }

    /// Only a unit that stayed out of `failed` for its whole wait is forgiven.
    /// A start that succeeds and dies within the wait keeps its streak, or a
    /// master crashing right after start would restart every tick.
    #[test]
    fn recovery_streak_ends_only_after_the_unit_stays_up_through_the_wait() {
        let v = PhpVersion::V8_2;
        let mut b = RecoveryBackoff::default();
        b.record_attempt(v, 0);
        b.note_not_failed(v, 30);
        assert!(!b.may_attempt(v, 30));
        // Failed again before the wait ran out: the next wait is the longer one.
        b.record_attempt(v, 60);
        b.note_not_failed(v, 179);
        assert!(!b.may_attempt(v, 179));
        // Survived the whole wait: the next failure starts over at 60 s.
        b.note_not_failed(v, 180);
        b.record_attempt(v, 500);
        assert!(!b.may_attempt(v, 559));
        assert!(b.may_attempt(v, 560));
    }

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
    /// Every pool logs its slow requests, into the ROOT-owned slowlog
    /// directory — never the site's own logs/, which the site user can
    /// swap for a link the root-run FPM master would then write through.
    #[test]
    fn render_logs_slow_requests_outside_the_tenant_tree() {
        let input = PoolInput::defaults("alice_cz", "alice.cz", PhpVersion::V8_3);
        let out = render(&input).expect("render");
        assert!(out.contains("slowlog = /var/log/hyperion/php-slow/alice_cz.log\n"));
        assert!(out.contains("request_slowlog_timeout = 5s\n"));
        assert!(!out.contains("slowlog = /home/"));
        assert!(SLOWLOG_LOGROTATE_BODY.contains("    copytruncate\n"));
    }

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

    /// Sites on one system user and PHP version share the pool file. Written
    /// for the last of them alone, PHP refused to open the others' scripts:
    /// "open_basedir restriction in effect", and nginx answered 404.
    #[test]
    fn a_shared_pool_lets_in_every_site_whichever_of_them_wrote_it() {
        let others = ["b.cz".to_string(), "c.cz".to_string()];
        let mut from_a = PoolInput::defaults("shared", "a.cz", PhpVersion::V8_3);
        from_a.also_serves = &others;
        let out = render(&from_a).expect("render");
        assert!(out.contains(
            "open_basedir] = /home/shared/a.cz:/home/shared/b.cz:/home/shared/c.cz:/tmp\n"
        ));
        assert!(out.contains("session.save_path] = /home/shared/a.cz/tmp\n"));

        let others = ["a.cz".to_string(), "b.cz".to_string()];
        let mut from_c = PoolInput::defaults("shared", "c.cz", PhpVersion::V8_3);
        from_c.also_serves = &others;
        assert_eq!(render(&from_c).expect("render"), out);
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

    #[test]
    fn systemd_major_is_the_number_after_the_name() {
        assert_eq!(
            parse_systemd_major("systemd 252 (252.31-1~deb12u1)\n+PAM +AUDIT -SELINUX\n"),
            Some(252)
        );
        assert_eq!(
            parse_systemd_major("systemd 257 (257.9-1~deb13u1)"),
            Some(257)
        );
        assert_eq!(parse_systemd_major("systemd 215"), Some(215));
        assert_eq!(parse_systemd_major(""), None);
        assert_eq!(parse_systemd_major("not systemd at all"), None);
        assert_eq!(parse_systemd_major("systemd (252)"), None);
    }

    #[test]
    fn meminfo_gives_mib_for_ram_and_kib_for_swap() {
        let m = parse_meminfo(
            "MemTotal:        8167848 kB\nMemFree:          200000 kB\n\
             MemAvailable:    6144000 kB\nSwapTotal:       2097148 kB\nSwapFree: 2097148 kB\n",
        );
        assert_eq!(m.mem_total_mb, Some(7976));
        assert_eq!(m.mem_available_mb, Some(6000));
        assert_eq!(m.swap_total_kib, 2_097_148);
        // No swap line, no available line: unknown RAM is None, no swap is 0.
        let bare = parse_meminfo("MemTotal: 1024 kB\n");
        assert_eq!(bare.mem_total_mb, Some(1));
        assert_eq!(bare.mem_available_mb, None);
        assert_eq!(bare.swap_total_kib, 0);
        let empty = parse_meminfo("");
        assert_eq!(empty.mem_total_mb, None);
        assert_eq!(empty.swap_total_kib, 0);
    }
}
