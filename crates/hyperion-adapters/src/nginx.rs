//! nginx vhost generation + reload.

use crate::{cmd, fs::atomic_write, AdapterError};
use askama::Template;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct VhostInput<'a> {
    pub domain: &'a str,
    pub aliases: &'a [String],
    pub root_dir: &'a str,
    pub logs_dir: &'a str,
    pub system_user: &'a str,
    pub php_version: Option<&'a str>,
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub acme_challenge_root: &'a str,
    /// Stable hosting id — drives per-hosting include filenames
    /// (.htpasswd, fastcgi_cache zone name, etc.). Sanitised to
    /// alphanumeric + dash at the call site.
    pub hosting_id: &'a str,
    /// Operator-controlled vhost knobs from migration 020.
    pub options: &'a hyperion_types::VhostOptions,
}

#[derive(Template)]
#[template(path = "nginx-vhost.conf.j2", escape = "none")]
struct VhostTpl<'a> {
    domain: &'a str,
    aliases: &'a [String],
    root_dir: &'a str,
    logs_dir: &'a str,
    system_user: &'a str,
    has_php: bool,
    php_version: &'a str,
    cert_path: &'a str,
    key_path: &'a str,
    acme_challenge_root: &'a str,
    hosting_id: &'a str,
    // Vhost option toggles — flattened into the template scope
    // because askama doesn't auto-deref nested structs in
    // `{% if %}` conditions.
    basic_auth_enabled: bool,
    hsts_max_age: i64,
    custom_nginx_snippet: &'a str,
    maintenance_mode: bool,
    fastcgi_cache_enabled: bool,
    fastcgi_cache_ttl: i64,
}

/// Render the vhost file's contents without writing.
#[derive(askama::Template)]
#[template(path = "nginx-vhost-suspended.conf.j2", escape = "none")]
struct SuspendedTpl<'a> {
    domain: &'a str,
    cert_path: &'a str,
    key_path: &'a str,
    reason_message: &'a str,
}

#[derive(Debug, Clone)]
pub struct SuspendedInput<'a> {
    pub domain: &'a str,
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub reason_message: &'a str,
}

/// Redirect-only hosting variant. Every request gets a 301/302 to
/// the configured target. No FPM pool, no DB, no htdocs. The
/// `redirect_preserve_path` flag at the input level decides whether
/// `/foo/bar` lands at `<target>/foo/bar` or just `<target>/`.
#[derive(Debug, Clone)]
pub struct RedirectVhostInput<'a> {
    pub domain: &'a str,
    pub aliases: &'a [String],
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub acme_challenge_root: &'a str,
    /// Where to redirect. Should start with http:// or https://.
    pub redirect_url: &'a str,
    /// 301 or 302 (operator's choice — 301 caches in browsers
    /// indefinitely, 302 is the safer default for "we might
    /// reverse this later").
    pub redirect_code: i64,
    /// When true, the request path is appended to the target.
    pub redirect_preserve_path: bool,
}

#[derive(askama::Template)]
#[template(path = "nginx-vhost-redirect.conf.j2", escape = "none")]
struct RedirectVhostTpl<'a> {
    domain: &'a str,
    aliases: &'a [String],
    cert_path: &'a str,
    key_path: &'a str,
    acme_challenge_root: &'a str,
    redirect_code: i64,
    /// Rendered redirect target — `nginx_safe_target` for the HTTP
    /// (:80) listener; if `preserve_path` is on, this is the bare
    /// target and nginx appends $request_uri via the `return`
    /// statement.
    redirect_target_http: String,
    redirect_target_https: String,
}

pub fn render_redirect(input: &RedirectVhostInput<'_>) -> Result<String, AdapterError> {
    if !(input.redirect_url.starts_with("http://")
        || input.redirect_url.starts_with("https://"))
    {
        return Err(AdapterError::Other(format!(
            "redirect_url must start with http:// or https://, got {}",
            input.redirect_url
        )));
    }
    let target = input.redirect_url.trim_end_matches('/').to_string();
    let (http_t, https_t) = if input.redirect_preserve_path {
        (format!("{target}$request_uri"), format!("{target}$request_uri"))
    } else {
        (target.clone(), target.clone())
    };
    let tpl = RedirectVhostTpl {
        domain: input.domain,
        aliases: input.aliases,
        cert_path: input.cert_path,
        key_path: input.key_path,
        acme_challenge_root: input.acme_challenge_root,
        redirect_code: input.redirect_code,
        redirect_target_http: http_t,
        redirect_target_https: https_t,
    };
    Ok(tpl.render()?)
}

/// Write the redirect vhost file + ensure the symlink + reload.
pub async fn write_redirect_vhost(
    paths: &Paths,
    input: &RedirectVhostInput<'_>,
) -> Result<(), AdapterError> {
    let body = render_redirect(input)?;
    let vhost = paths.vhost_file(input.domain);
    crate::fs::atomic_write(&vhost, body.as_bytes(), 0o644).await?;
    let symlink = paths.symlink_file(input.domain);
    ensure_symlink(&vhost, &symlink).await?;
    reload().await
}

/// Hyperion master panel vhost — `panel.example.com` → local
/// hyperion-web on 127.0.0.1:8443. Specialised template (separate
/// from `nginx-vhost-proxy.conf.j2`) because the panel always
/// proxies to LOCALHOST self-signed and needs `proxy_ssl_verify
/// off` — we don't want that knob bleeding into operator-defined
/// reverse_proxy hostings.
#[derive(Debug, Clone)]
pub struct PanelVhostInput<'a> {
    pub domain: &'a str,
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub acme_challenge_root: &'a str,
}

#[derive(askama::Template)]
#[template(path = "nginx-panel.conf.j2", escape = "none")]
struct PanelVhostTpl<'a> {
    domain: &'a str,
    cert_path: &'a str,
    key_path: &'a str,
    acme_challenge_root: &'a str,
}

pub fn render_panel(input: &PanelVhostInput<'_>) -> Result<String, AdapterError> {
    let tpl = PanelVhostTpl {
        domain: input.domain,
        cert_path: input.cert_path,
        key_path: input.key_path,
        acme_challenge_root: input.acme_challenge_root,
    };
    Ok(tpl.render()?)
}

/// Atomic-write + nginx-test + reload. Filename pinned to
/// `hyperion-panel.conf` so the boot-time orphan-vhost sweep
/// recognises it and never auto-cleans it.
pub async fn write_panel_vhost(
    paths: &Paths,
    input: &PanelVhostInput<'_>,
) -> Result<(), AdapterError> {
    let body = render_panel(input)?;
    let vhost = paths.sites_available.join("hyperion-panel.conf");
    let backup = backup_existing(&vhost).await?;
    atomic_write(&vhost, body.as_bytes(), 0o644).await?;
    let symlink = paths.sites_enabled.join("hyperion-panel.conf");
    ensure_symlink(&vhost, &symlink).await?;
    if let Err(e) = cmd::run("/usr/sbin/nginx", &["-t"]).await {
        restore_or_remove(&vhost, backup.as_deref()).await;
        let _ = tokio::fs::remove_file(&symlink).await;
        return Err(e);
    }
    reload().await
}

/// Reverse-proxy variant: forwards every request to a single upstream
/// URL. WebSocket upgrade is on by default per MVP spec. No PHP-FPM,
/// no static root.
#[derive(Debug, Clone)]
pub struct ProxyVhostInput<'a> {
    pub domain: &'a str,
    pub aliases: &'a [String],
    pub logs_dir: &'a str,
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub acme_challenge_root: &'a str,
    /// Upstream URL — e.g. "http://localhost:3000" or "https://api.internal:8443".
    pub upstream_url: &'a str,
}

#[derive(askama::Template)]
#[template(path = "nginx-vhost-proxy.conf.j2", escape = "none")]
struct ProxyVhostTpl<'a> {
    domain: &'a str,
    aliases: &'a [String],
    logs_dir: &'a str,
    cert_path: &'a str,
    key_path: &'a str,
    acme_challenge_root: &'a str,
    upstream_url: &'a str,
}

pub fn render_proxy(input: &ProxyVhostInput<'_>) -> Result<String, AdapterError> {
    let tpl = ProxyVhostTpl {
        domain: input.domain,
        aliases: input.aliases,
        logs_dir: input.logs_dir,
        cert_path: input.cert_path,
        key_path: input.key_path,
        acme_challenge_root: input.acme_challenge_root,
        upstream_url: input.upstream_url,
    };
    Ok(tpl.render()?)
}

/// Write reverse-proxy vhost — same shape as `write_vhost` but uses
/// the proxy template. Atomic + reload + restore-on-failure.
pub async fn write_vhost_proxy(
    paths: &Paths,
    input: &ProxyVhostInput<'_>,
) -> Result<(), AdapterError> {
    let body = render_proxy(input)?;
    let vhost = paths.vhost_file(input.domain);
    let backup = backup_existing(&vhost).await?;
    atomic_write(&vhost, body.as_bytes(), 0o644).await?;
    let symlink = paths.symlink_file(input.domain);
    ensure_symlink(&vhost, &symlink).await?;
    if let Err(e) = cmd::run("/usr/sbin/nginx", &["-t"]).await {
        restore_or_remove(&vhost, backup.as_deref()).await;
        let _ = tokio::fs::remove_file(&symlink).await;
        return Err(e);
    }
    reload().await
}

/// Render the suspended-state vhost.
pub fn render_suspended(input: &SuspendedInput<'_>) -> Result<String, AdapterError> {
    let tpl = SuspendedTpl {
        domain: input.domain,
        cert_path: input.cert_path,
        key_path: input.key_path,
        reason_message: input.reason_message,
    };
    Ok(tpl.render()?)
}

/// Swap the vhost to the suspended variant.
pub async fn apply_suspended(
    paths: &Paths,
    input: &SuspendedInput<'_>,
) -> Result<(), AdapterError> {
    let body = render_suspended(input)?;
    let vhost = paths.vhost_file(input.domain);
    crate::fs::atomic_write(&vhost, body.as_bytes(), 0o644).await?;
    let symlink = paths.symlink_file(input.domain);
    ensure_symlink(&vhost, &symlink).await?;
    reload().await
}

pub fn render(input: &VhostInput<'_>) -> Result<String, AdapterError> {
    let tpl = VhostTpl {
        domain: input.domain,
        aliases: input.aliases,
        root_dir: input.root_dir,
        logs_dir: input.logs_dir,
        system_user: input.system_user,
        has_php: input.php_version.is_some(),
        php_version: input.php_version.unwrap_or(""),
        cert_path: input.cert_path,
        key_path: input.key_path,
        acme_challenge_root: input.acme_challenge_root,
        hosting_id: input.hosting_id,
        basic_auth_enabled: input.options.basic_auth_enabled
            && input.options.basic_auth_set,
        hsts_max_age: input.options.hsts_max_age,
        custom_nginx_snippet: &input.options.custom_nginx_snippet,
        maintenance_mode: input.options.maintenance_mode,
        fastcgi_cache_enabled: input.options.fastcgi_cache_enabled,
        fastcgi_cache_ttl: input.options.fastcgi_cache_ttl,
    };
    Ok(tpl.render()?)
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub sites_available: PathBuf,
    pub sites_enabled: PathBuf,
}

impl Paths {
    pub fn debian_defaults() -> Self {
        Self {
            sites_available: PathBuf::from("/etc/nginx/sites-available"),
            sites_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
        }
    }
    pub fn vhost_file(&self, domain: &str) -> PathBuf {
        self.sites_available.join(format!("{domain}.conf"))
    }
    pub fn symlink_file(&self, domain: &str) -> PathBuf {
        self.sites_enabled.join(format!("{domain}.conf"))
    }
}

/// Write vhost + create symlink + `nginx -t` + reload. Idempotent.
///
/// When the operator has flipped on the per-hosting FastCGI cache,
/// this also writes `/etc/nginx/conf.d/hyperion-cache-<id>.conf`
/// with the `fastcgi_cache_path` directive (must live at http{}
/// level — can't be in a server{} block). When the operator turns
/// the cache off, that file is removed.
pub async fn write_vhost(paths: &Paths, input: &VhostInput<'_>) -> Result<(), AdapterError> {
    let body = render(input)?;
    let vhost = paths.vhost_file(input.domain);
    let backup = backup_existing(&vhost).await?;
    atomic_write(&vhost, body.as_bytes(), 0o644).await?;
    let symlink = paths.symlink_file(input.domain);
    ensure_symlink(&vhost, &symlink).await?;
    // Cache-zone sidecar: written/removed alongside the vhost so the
    // two stay in sync. If the cache toggle is off, any stale sidecar
    // from a previous "on" state is cleaned up here.
    let cache_path = cache_zone_file(input.hosting_id);
    if input.options.fastcgi_cache_enabled {
        let cache_body = render_cache_zone(input.hosting_id);
        atomic_write(&cache_path, cache_body.as_bytes(), 0o644).await?;
    } else {
        let _ = tokio::fs::remove_file(&cache_path).await;
    }
    if let Err(e) = cmd::run("/usr/sbin/nginx", &["-t"]).await {
        // Restore previous state.
        restore_or_remove(&vhost, backup.as_deref()).await;
        let _ = tokio::fs::remove_file(&symlink).await;
        // Pull the cache sidecar too — bad vhost + sidecar would
        // half-survive an aborted apply otherwise.
        let _ = tokio::fs::remove_file(&cache_path).await;
        return Err(e);
    }
    reload().await
}

/// `/etc/nginx/conf.d/hyperion-cache-<id>.conf` — operator-toggled
/// sidecar containing the `fastcgi_cache_path` directive for one
/// hosting. Lives in conf.d so nginx picks it up at the http{}
/// level (server{}-level fastcgi_cache_path is a config error).
fn cache_zone_file(hosting_id: &str) -> PathBuf {
    PathBuf::from(format!("/etc/nginx/conf.d/hyperion-cache-{hosting_id}.conf"))
}

fn render_cache_zone(hosting_id: &str) -> String {
    format!(
        "# Auto-managed by Hyperion. Do not edit — toggle via the\n\
         # hosting detail page (FastCGI cache section).\n\
         fastcgi_cache_path /var/cache/nginx/hyperion-{id}\n\
         \x20\x20\x20\x20levels=1:2\n\
         \x20\x20\x20\x20keys_zone=hyperion_{id}:16m\n\
         \x20\x20\x20\x20max_size=512m\n\
         \x20\x20\x20\x20inactive=60m\n\
         \x20\x20\x20\x20use_temp_path=off;\n",
        id = hosting_id
    )
}

/// `/etc/nginx/.htpasswd-<id>` — written when basic auth is on.
/// Format is `user:bcrypt-hash\n`. nginx supports bcrypt natively
/// (no need for `htpasswd`/apache utils to be installed).
pub fn htpasswd_file(hosting_id: &str) -> PathBuf {
    PathBuf::from(format!("/etc/nginx/.htpasswd-{hosting_id}"))
}

/// Write the htpasswd file. Mode 0o640 so nginx (www-data) can read it
/// but others can't.
pub async fn write_htpasswd(
    hosting_id: &str,
    user: &str,
    bcrypt_hash: &str,
) -> Result<(), AdapterError> {
    if user.is_empty() {
        return Err(AdapterError::Other("basic auth user cannot be empty".into()));
    }
    if user.contains(':') || user.contains('\n') {
        return Err(AdapterError::Other(
            "basic auth user contains illegal character".into(),
        ));
    }
    if !bcrypt_hash.starts_with("$2") {
        return Err(AdapterError::Other(
            "basic auth hash must be bcrypt (starts with $2)".into(),
        ));
    }
    let body = format!("{user}:{bcrypt_hash}\n");
    let path = htpasswd_file(hosting_id);
    crate::fs::atomic_write(&path, body.as_bytes(), 0o640).await
}

pub async fn delete_htpasswd(hosting_id: &str) -> Result<(), AdapterError> {
    let _ = tokio::fs::remove_file(htpasswd_file(hosting_id)).await;
    Ok(())
}

/// Remove vhost + symlink + reload. Safe if files already absent.
///
/// `hosting_id` is optional because legacy call sites (and the
/// fallback "I don't have the id handy" branch in delete-cancelled
/// flows) only know the domain. When provided, the per-hosting
/// cache zone sidecar + htpasswd are also cleaned up so a future
/// hosting on the same id can't inherit them.
pub async fn delete_vhost(
    paths: &Paths,
    domain: &str,
    hosting_id: Option<&str>,
) -> Result<(), AdapterError> {
    let _ = tokio::fs::remove_file(paths.symlink_file(domain)).await;
    let _ = tokio::fs::remove_file(paths.vhost_file(domain)).await;
    if let Some(id) = hosting_id {
        let _ = tokio::fs::remove_file(cache_zone_file(id)).await;
        let _ = tokio::fs::remove_file(htpasswd_file(id)).await;
    }
    reload().await
}

/// Reload nginx, self-healing the common "not active, cannot reload"
/// failure mode that bites worker nodes the first time master
/// dispatches a HostingCreate to them.
///
/// Failure modes covered:
///   - nginx is installed but not started (Debian sometimes does this
///     when apt-get is interrupted mid-install, or when a `systemctl
///     mask` leftover from an earlier panel survives). We try to
///     start + retry the reload.
///   - nginx isn't installed at all (worker provisioned without the
///     hosting prerequisites). We surface a clear error pointing at
///     `apt-get install nginx` so the operator doesn't have to grep
///     journalctl to understand what's missing.
///   - reload fails for a config error (bad vhost we just wrote).
///     Returned verbatim — caller's nginx_test handles that path.
pub async fn reload() -> Result<(), AdapterError> {
    match cmd::run("/usr/bin/systemctl", &["reload", "nginx"]).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if reload_error_means_inactive(&msg) {
                tracing::warn!(
                    error = %msg,
                    "nginx not running before reload — attempting start + reload"
                );
                // `start` is idempotent: it's a no-op if already
                // running, brings it up otherwise. If start ALSO
                // fails the unit either doesn't exist (not
                // installed) or fails to come up (bad config /
                // port conflict) — both worth surfacing verbatim.
                if let Err(start_err) =
                    cmd::run("/usr/bin/systemctl", &["start", "nginx"]).await
                {
                    let s = start_err.to_string();
                    if s.contains("not loaded") || s.contains("not found") {
                        return Err(AdapterError::Command {
                            cmd: "/usr/bin/systemctl start nginx".into(),
                            code: 1,
                            stderr_tail: "nginx is not installed on this node. \
                                Install it with `apt-get install -y nginx` (the hyperion \
                                node installer should have done this — see \
                                /opt/hyperion/packaging/install/install-node.sh, or just \
                                re-run /opt/hyperion/packaging/install/update.sh which \
                                self-heals missing packages)."
                                .into(),
                        });
                    }
                    // Start failed for a reason that's NOT "not
                    // installed". Most likely: bad nginx config
                    // (vhost syntax error, port conflict, missing
                    // upstream, etc.). Run `nginx -t` to capture
                    // the precise error message + grab the
                    // last 30 journalctl lines so the operator
                    // sees the actual cause instead of just the
                    // useless "Job for nginx.service failed" wrapper.
                    let nginx_test = capture_diagnostics(
                        "/usr/sbin/nginx",
                        &["-t"],
                    )
                    .await;
                    let journal = capture_diagnostics(
                        "/usr/bin/journalctl",
                        &["-u", "nginx.service", "-n", "30", "--no-pager"],
                    )
                    .await;
                    return Err(AdapterError::Command {
                        cmd: "/usr/bin/systemctl start nginx".into(),
                        code: 1,
                        stderr_tail: format!(
                            "nginx failed to start. systemd said:\n{}\n\
                             \n──── nginx -t ────\n{}\n\
                             \n──── last 30 lines of journalctl -u nginx ────\n{}",
                            s.trim(),
                            nginx_test.trim(),
                            journal.trim()
                        ),
                    });
                }
                // Started — now try the reload again. (We could
                // skip this since `start` already brought a fresh
                // process up with the new vhost, but reload is the
                // cheaper signal and matches the master's audit
                // trail expectations.)
                cmd::run("/usr/bin/systemctl", &["reload", "nginx"]).await?;
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

/// Run a diagnostic command and return its combined stdout+stderr.
/// Never errors — on spawn failure / non-zero exit the message is
/// what the operator gets to see (which is exactly what we want
/// for diagnostic output). Used by the start-failure path above to
/// give the operator the REAL nginx error, not just systemd's
/// "Job failed" wrapper.
async fn capture_diagnostics(cmd: &str, args: &[&str]) -> String {
    match tokio::process::Command::new(cmd).args(args).output().await {
        Ok(out) => {
            let mut s = String::new();
            s.push_str(&String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                if !s.is_empty() && !s.ends_with('\n') {
                    s.push('\n');
                }
                s.push_str(&String::from_utf8_lossy(&out.stderr));
            }
            if s.is_empty() {
                format!("(no output from {cmd})")
            } else {
                s
            }
        }
        Err(e) => format!("(could not run {cmd}: {e})"),
    }
}

/// Decide whether a systemctl-reload failure looks like
/// "nginx is just not running" (recoverable by `systemctl start`)
/// vs. a real reload failure (bad config, etc., which we surface).
///
/// systemd's exact phrasing varies between releases — Debian 12
/// emits "Job for nginx.service failed because the unit nginx.service
/// is not active" / "Unit nginx.service is not active, cannot reload."
/// We match the stable substring "is not active" plus the
/// "not loaded" variant for cases where the unit was masked or
/// removed.
fn reload_error_means_inactive(msg: &str) -> bool {
    msg.contains("is not active") || msg.contains("Unit nginx.service not loaded")
}

/// The Unix user that nginx worker processes run as. PHP-FPM pool sockets
/// must be owned by THIS user (via `listen.owner = ...`) so nginx can
/// `connect(2)` to them — otherwise every request to a `.php` URL returns
/// 502 Bad Gateway with `connect() failed (13: Permission denied)` in
/// the error log.
///
/// Fresh Debian installs have `user www-data;` in `/etc/nginx/nginx.conf`,
/// so the historical hardcoded default works. But if the operator
/// inherited nginx from a previous panel (CloudPanel, RunCloud, etc.) the
/// user directive may be something else (e.g. `vito`). This module is
/// the single source of truth for the answer.
pub const DEFAULT_NGINX_USER: &str = "www-data";

/// Try to detect the user nginx workers run as.
///
/// Order:
///   1. Parse `nginx -T` output for a top-level `user <name>;` directive.
///      This is most reliable because it reflects the effective config
///      including includes.
///   2. If `nginx -T` isn't available (nginx not installed, or test env),
///      fall back to grepping a worker process via `ps`.
///   3. Last resort: the Debian default `www-data`.
///
/// Always returns a non-empty string. Never panics. Best-effort.
pub async fn detect_user() -> String {
    // 1. Authoritative: ask nginx itself what it parsed.
    if let Some(u) = detect_user_via_nginx_t().await {
        if is_valid_user_token(&u) {
            return u;
        }
    }
    // 2. Fallback: snoop a running worker.
    if let Some(u) = detect_user_via_ps().await {
        if is_valid_user_token(&u) {
            return u;
        }
    }
    // 3. Give up, return the Debian default.
    DEFAULT_NGINX_USER.to_string()
}

async fn detect_user_via_nginx_t() -> Option<String> {
    let out = tokio::process::Command::new("/usr/sbin/nginx")
        .args(["-T"])
        .output()
        .await
        .ok()?;
    // nginx -T prints config to stdout. The directive can also appear
    // with a group as second arg: "user www-data www-data;".
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    parse_user_directive(&stdout).or_else(|| parse_user_directive(&stderr))
}

fn parse_user_directive(text: &str) -> Option<String> {
    for raw_line in text.lines() {
        let line = raw_line.trim_start();
        let Some(rest) = line.strip_prefix("user ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';').trim();
        let Some(first) = rest.split_whitespace().next() else {
            continue;
        };
        if !first.is_empty() {
            return Some(first.to_string());
        }
    }
    None
}

async fn detect_user_via_ps() -> Option<String> {
    // `nginx: worker process` is the conventional comm string.
    let out = tokio::process::Command::new("/bin/ps")
        .args(["-eo", "user=,comm="])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        // ps formats columns separated by whitespace; comm is last.
        let mut it = line.split_whitespace();
        let user = it.next()?;
        let comm = it.next().unwrap_or("");
        if comm == "nginx" && user != "root" {
            return Some(user.to_string());
        }
    }
    None
}

fn is_valid_user_token(s: &str) -> bool {
    // Defensive: avoid pathological values. POSIX user names are
    // [A-Za-z0-9._-] and must not start with -. Limit length too.
    !s.is_empty()
        && s.len() <= 32
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Self-heal companion: if `/etc/nginx/nginx.conf` lists a `user`
/// directive whose target Unix user doesn't actually exist on the
/// system, that's the operator's misconfiguration — log loud and
/// continue using the value anyway. Returns `Ok(())` regardless; the
/// caller can still use the detected user for FPM socket ownership
/// (where `listen.owner` would fail clearly at FPM reload).
pub async fn warn_if_user_missing(detected_user: &str) {
    let out = tokio::process::Command::new("/usr/bin/getent")
        .args(["passwd", detected_user])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {}
        _ => {
            tracing::warn!(
                user = %detected_user,
                "nginx is configured to run as `{detected_user}` but that user is not in /etc/passwd. \
                 PHP-FPM pools will fail to bind. Fix /etc/nginx/nginx.conf or create the user."
            );
        }
    }
}

async fn backup_existing(path: &Path) -> Result<Option<PathBuf>, AdapterError> {
    if tokio::fs::metadata(path).await.is_ok() {
        let mut backup = path.as_os_str().to_owned();
        backup.push(".lm-bak");
        let backup = PathBuf::from(backup);
        tokio::fs::copy(path, &backup).await?;
        Ok(Some(backup))
    } else {
        Ok(None)
    }
}

async fn restore_or_remove(target: &Path, backup: Option<&Path>) {
    if let Some(b) = backup {
        let _ = tokio::fs::rename(b, target).await;
    } else {
        let _ = tokio::fs::remove_file(target).await;
    }
}

async fn ensure_symlink(target: &Path, link: &Path) -> Result<(), AdapterError> {
    if let Some(parent) = link.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    if tokio::fs::symlink_metadata(link).await.is_ok() {
        // Already exists. Re-point (best effort).
        let _ = tokio::fs::remove_file(link).await;
    }
    tokio::fs::symlink(target, link).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: nginx ≥ 1.25 deprecated `listen 443 ssl http2;`
    /// in favour of separate `http2 on;` directive. Every rendered
    /// vhost variant must use the new form so `nginx -t` doesn't
    /// emit a stderr warning on every reload (operators read those
    /// warnings as errors).
    #[test]
    fn rendered_vhosts_use_modern_http2_directive() {
        let aliases: Vec<String> = vec![];
        let opts = hyperion_types::VhostOptions::default();
        let out = render(&VhostInput {
            domain: "example.cz",
            aliases: &aliases,
            root_dir: "/srv/x/htdocs",
            logs_dir: "/srv/x/logs",
            system_user: "x",
            php_version: None,
            cert_path: "/etc/lm/certs/example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            hosting_id: "01HMOD",
            options: &opts,
        })
        .expect("render");
        assert!(
            !out.contains("ssl http2;"),
            "vhost still uses the deprecated `listen ... ssl http2;` directive: \n{out}"
        );
        assert!(
            out.contains("http2 on;"),
            "vhost is missing the modern `http2 on;` directive: \n{out}"
        );
    }

    #[test]
    fn render_static_no_php() {
        let aliases: Vec<String> = vec![];
        let opts = hyperion_types::VhostOptions {
            hsts_max_age: 15_768_000,
            ..Default::default()
        };
        let out = render(&VhostInput {
            domain: "example.cz",
            aliases: &aliases,
            root_dir: "/home/example_cz/example.cz/htdocs",
            logs_dir: "/home/example_cz/example.cz/logs",
            system_user: "example_cz",
            php_version: None,
            cert_path: "/etc/lm/certs/example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            hosting_id: "01H0000000000000000000",
            options: &opts,
        })
        .expect("render");
        assert!(out.contains("server_name example.cz;"));
        assert!(!out.contains("fastcgi_pass"));
        assert!(out.contains("try_files $uri $uri/ =404"));
        assert!(out.contains("Strict-Transport-Security"));
        assert!(out.contains("ssl_certificate     /etc/lm/certs/example.cz/fullchain.pem"));
        assert!(out.contains("/var/lib/lm/acme-challenges"));
        // CRITICAL: the well-known challenge location MUST use `alias`,
        // not `root`. With `root`, nginx would serve files from
        // <acme_root>/.well-known/acme-challenge/<token>, but our ACME
        // client writes them flat at <acme_root>/<token> — so LE would
        // 404 and mark the order Invalid. Regression test for the
        // "ACME order status=Invalid" bug.
        assert!(
            out.contains("location /.well-known/acme-challenge/ {")
                && out.contains("alias /var/lib/lm/acme-challenges/;"),
            "vhost must use `alias` (with trailing slash) for the ACME challenge location, not `root`. \
             Rendered output:\n{out}"
        );
        assert!(
            !out.contains("root /var/lib/lm/acme-challenges"),
            "vhost MUST NOT use `root` for the ACME challenge location"
        );
    }

    #[test]
    fn render_php_with_aliases() {
        let aliases = vec!["www.example.cz".to_string(), "example.com".to_string()];
        let opts = hyperion_types::VhostOptions::default();
        let out = render(&VhostInput {
            domain: "example.cz",
            aliases: &aliases,
            root_dir: "/home/example_cz/example.cz/htdocs",
            logs_dir: "/home/example_cz/example.cz/logs",
            system_user: "example_cz",
            php_version: Some("8.3"),
            cert_path: "/etc/lm/certs/example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            hosting_id: "01H0000000000000000000",
            options: &opts,
        })
        .expect("render");
        assert!(out.contains("server_name example.cz www.example.cz example.com;"));
        assert!(out.contains("fastcgi_pass unix:/run/php/8.3/example_cz.sock"));
        assert!(out.contains("try_files $uri $uri/ /index.php?$args"));
    }

    #[test]
    fn render_with_basic_auth_and_hsts() {
        // Operator turned basic auth on + set HSTS to 1 year + dropped
        // a custom snippet. The rendered vhost should contain all
        // three, and the ACME challenge MUST still bypass basic auth.
        let aliases: Vec<String> = vec![];
        let opts = hyperion_types::VhostOptions {
            basic_auth_enabled: true,
            basic_auth_user: "preview".into(),
            basic_auth_set: true,
            hsts_max_age: 31_536_000,
            custom_nginx_snippet: "# operator extra\nclient_max_body_size 64M;".into(),
            ..Default::default()
        };
        let out = render(&VhostInput {
            domain: "example.cz",
            aliases: &aliases,
            root_dir: "/home/example_cz/example.cz/htdocs",
            logs_dir: "/home/example_cz/example.cz/logs",
            system_user: "example_cz",
            php_version: Some("8.3"),
            cert_path: "/etc/lm/certs/example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            hosting_id: "01HVHOST",
            options: &opts,
        })
        .expect("render");
        assert!(out.contains("auth_basic           \"Restricted\";"));
        assert!(out.contains("auth_basic_user_file /etc/nginx/.htpasswd-01HVHOST;"));
        assert!(out.contains("auth_basic off;"));
        assert!(out.contains("max-age=31536000"));
        assert!(out.contains("client_max_body_size 64M;"));
    }

    #[test]
    fn render_maintenance_mode() {
        // Maintenance mode returns 503 with a generic page. ACME
        // challenges still served so renewals don't break.
        let aliases: Vec<String> = vec![];
        let opts = hyperion_types::VhostOptions {
            maintenance_mode: true,
            ..Default::default()
        };
        let out = render(&VhostInput {
            domain: "example.cz",
            aliases: &aliases,
            root_dir: "/home/example_cz/example.cz/htdocs",
            logs_dir: "/home/example_cz/example.cz/logs",
            system_user: "example_cz",
            php_version: Some("8.3"),
            cert_path: "/etc/lm/certs/example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            hosting_id: "01HMAINT",
            options: &opts,
        })
        .expect("render");
        assert!(out.contains("location / { return 503; }"));
        assert!(out.contains("/var/lib/hyperion/maintenance"));
        // ACME must still work even in maintenance mode.
        assert!(out.contains("location /.well-known/acme-challenge/"));
        // PHP block MUST NOT be emitted when in maintenance.
        assert!(!out.contains("fastcgi_pass"));
    }

    #[test]
    fn render_fastcgi_cache_per_hosting_zone() {
        // Per-hosting cache zone name must include hosting_id so two
        // hostings on the same node don't collide.
        let aliases: Vec<String> = vec![];
        let opts = hyperion_types::VhostOptions {
            fastcgi_cache_enabled: true,
            fastcgi_cache_ttl: 300,
            ..Default::default()
        };
        let out = render(&VhostInput {
            domain: "example.cz",
            aliases: &aliases,
            root_dir: "/home/example_cz/example.cz/htdocs",
            logs_dir: "/home/example_cz/example.cz/logs",
            system_user: "example_cz",
            php_version: Some("8.3"),
            cert_path: "/etc/lm/certs/example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            hosting_id: "01HCACHE",
            options: &opts,
        })
        .expect("render");
        assert!(out.contains("fastcgi_cache hyperion_01HCACHE;"));
        assert!(out.contains("fastcgi_cache_valid 200 301 302 300s;"));
        assert!(out.contains("fastcgi_no_cache $cookie_wordpress_logged_in"));
    }

    #[test]
    fn render_redirect_vhost_basic() {
        let aliases: Vec<String> = vec![];
        let input = RedirectVhostInput {
            domain: "old.example.cz",
            aliases: &aliases,
            cert_path: "/etc/lm/certs/old.example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/old.example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            redirect_url: "https://new.example.cz",
            redirect_code: 301,
            redirect_preserve_path: false,
        };
        let out = render_redirect(&input).expect("render redirect");
        assert!(out.contains("server_name old.example.cz;"));
        assert!(out.contains("return 301 https://new.example.cz;"));
        // No path appended when preserve=false.
        assert!(!out.contains("$request_uri"));
        // ACME location still works for cert renewals.
        assert!(out.contains("location /.well-known/acme-challenge/"));
    }

    #[test]
    fn render_redirect_vhost_preserve_path() {
        let aliases: Vec<String> = vec![];
        let input = RedirectVhostInput {
            domain: "old.example.cz",
            aliases: &aliases,
            cert_path: "/etc/lm/certs/old.example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/old.example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            redirect_url: "https://new.example.cz/",
            redirect_code: 302,
            redirect_preserve_path: true,
        };
        let out = render_redirect(&input).expect("render redirect");
        assert!(out.contains("return 302 https://new.example.cz$request_uri;"));
    }

    #[test]
    fn render_redirect_rejects_bad_scheme() {
        let aliases: Vec<String> = vec![];
        let input = RedirectVhostInput {
            domain: "old.example.cz",
            aliases: &aliases,
            cert_path: "/etc/lm/certs/old.example.cz/fullchain.pem",
            key_path: "/etc/lm/certs/old.example.cz/privkey.pem",
            acme_challenge_root: "/var/lib/lm/acme-challenges",
            // Missing scheme — must be rejected.
            redirect_url: "new.example.cz",
            redirect_code: 301,
            redirect_preserve_path: false,
        };
        assert!(render_redirect(&input).is_err());
    }

    /// Regression test for the "502 because nginx runs as vito but the
    /// FPM socket is owned by www-data" bug. parse_user_directive must
    /// pick up whatever name is between `user ` and `;`.
    #[test]
    fn parse_user_directive_real_world_samples() {
        // Debian default (single arg).
        assert_eq!(
            parse_user_directive("user www-data;\nhttp { ... }"),
            Some("www-data".to_string())
        );
        // nginx -T emits config with leading whitespace + comments before
        // the user directive.
        let sample = "# configuration file /etc/nginx/nginx.conf:\n\
                      user vito;\n\
                      worker_processes auto;\n";
        assert_eq!(parse_user_directive(sample), Some("vito".to_string()));
        // Two-arg form (user + group).
        assert_eq!(
            parse_user_directive("user nginx nginx;"),
            Some("nginx".to_string())
        );
        // No user directive → None (caller falls back).
        assert_eq!(parse_user_directive("http { server { } }"), None);
    }

    /// is_valid_user_token rejects injection attempts and absurd values
    /// so we never paste garbage straight into FPM's `listen.owner =`.
    #[test]
    fn is_valid_user_token_accepts_real_users_rejects_garbage() {
        assert!(is_valid_user_token("www-data"));
        assert!(is_valid_user_token("vito"));
        assert!(is_valid_user_token("nginx"));
        assert!(is_valid_user_token("user_42"));
        assert!(is_valid_user_token("a.b"));
        assert!(!is_valid_user_token(""));
        assert!(!is_valid_user_token("-rm"));
        assert!(!is_valid_user_token("foo bar"));
        assert!(!is_valid_user_token("foo;rm -rf /"));
        assert!(!is_valid_user_token("foo\nbar"));
        // 33 chars — over the limit.
        assert!(!is_valid_user_token(&"a".repeat(33)));
    }

    #[test]
    fn paths_helpers() {
        let p = Paths::debian_defaults();
        assert_eq!(
            p.vhost_file("example.cz"),
            Path::new("/etc/nginx/sites-available/example.cz.conf")
        );
        assert_eq!(
            p.symlink_file("example.cz"),
            Path::new("/etc/nginx/sites-enabled/example.cz.conf")
        );
    }

    /// Self-heal trigger: only the "not active / not loaded" family
    /// should switch us into start+retry mode. Anything else (config
    /// errors, permission denied, etc.) must propagate verbatim so
    /// the operator sees the actual failure.
    #[test]
    fn reload_error_means_inactive_matches_systemd_phrasings() {
        // Debian 12 — "is not active, cannot reload"
        assert!(reload_error_means_inactive(
            "command /usr/bin/systemctl failed with exit 1: \
             nginx.service is not active, cannot reload."
        ));
        // Masked / removed unit
        assert!(reload_error_means_inactive(
            "Unit nginx.service not loaded."
        ));
    }

    #[test]
    fn reload_error_means_inactive_ignores_real_failures() {
        // Real reload failure (bad config) — must propagate, not retry.
        assert!(!reload_error_means_inactive(
            "command /usr/bin/systemctl failed with exit 1: \
             nginx: [emerg] open() \"/etc/nginx/sites-enabled/x.conf\" failed (13: Permission denied)"
        ));
        // Random IO error from cmd::run
        assert!(!reload_error_means_inactive("io: broken pipe"));
        // nginx running, just refused to reload for some other reason
        assert!(!reload_error_means_inactive(
            "Job for nginx.service failed: reload-success timeout"
        ));
    }
}
