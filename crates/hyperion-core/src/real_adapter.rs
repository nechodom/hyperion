//! Production `AdapterPort` implementation. Glues the orchestrator to
//! `hyperion-adapters`. Runs on Debian as root via the hyperion-agent systemd service.

use crate::service::AdapterPort;
use async_trait::async_trait;
use hyperion_adapters::AdapterError;
use hyperion_rpc::wire::DbCredentials;
use hyperion_types::{CertInfo, DbProvision, HostingDetail, HostingId, PhpVersion, WpInstallRequest};
use hyperion_validate::SystemUserName;
use std::path::PathBuf;

const HOSTING_PLACEHOLDER_HTML: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Hyperion · site ready</title>
<style>
:root { color-scheme: light dark; --fg:#0d1117; --bg:#fafbfc; --accent:#34d399; --dim:#666; }
@media (prefers-color-scheme: dark) { :root { --fg:#e7e9ee; --bg:#0a0b0e; --dim:#9aa0ab; } }
html, body { margin:0; padding:0; height:100%; font:16px/1.55 -apple-system,BlinkMacSystemFont,"Inter","Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--fg); }
.wrap { min-height:100vh; display:grid; place-items:center; padding:2rem; }
.card { max-width:32rem; text-align:center; }
.brand { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-weight:800; letter-spacing:.04em; font-size:1.05rem; margin-bottom:2rem; }
.brand .a { color:var(--accent); text-shadow:0 0 18px color-mix(in oklab, var(--accent) 55%, transparent); }
h1 { font-size:1.6rem; margin:0 0 .6rem; letter-spacing:-.02em; }
p { color:var(--dim); margin:.4rem 0; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; background:rgba(127,127,127,.12); padding:.12em .4em; border-radius:6px; font-size:.9em; }
</style></head>
<body>
<div class="wrap"><div class="card">
<div class="brand"><span class="a">HY</span>·PERION</div>
<h1>Your site is ready.</h1>
<p>Drop your files into <code>htdocs/</code> and they show up here.</p>
<p style="margin-top:1.4rem;font-size:.85rem">FTP into the system user from the hosting admin, or SCP your code up.</p>
</div></div></body></html>
"##;

pub struct RealAdapter {
    pub nginx_paths: hyperion_adapters::nginx::Paths,
    pub certs_root: PathBuf,
    pub acme_challenge_root: PathBuf,
    pub acme_email: String,
    pub acme_directory_url: String,
    /// User nginx workers run as — detected once at adapter
    /// construction time and used as the FPM pool's `listen.owner`
    /// so nginx can `connect(2)` to the socket. Defaults to
    /// "www-data" until `detect_nginx_user_blocking()` runs.
    pub nginx_user: String,
}

impl Default for RealAdapter {
    fn default() -> Self {
        Self {
            nginx_paths: hyperion_adapters::nginx::Paths::debian_defaults(),
            certs_root: PathBuf::from("/etc/hyperion/certs"),
            acme_challenge_root: PathBuf::from("/var/lib/hyperion/acme-challenges"),
            acme_email: "admin@example.com".into(),
            acme_directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            nginx_user: hyperion_adapters::nginx::DEFAULT_NGINX_USER.to_string(),
        }
    }
}

impl RealAdapter {
    /// Replace the default www-data with whatever nginx is actually
    /// running as on this node. Called once at agent startup.
    pub async fn detect_nginx_user(&mut self) {
        let detected = hyperion_adapters::nginx::detect_user().await;
        if detected != self.nginx_user {
            tracing::info!(
                detected = %detected,
                "nginx is running as `{detected}`, will use it as FPM listen.owner"
            );
        }
        hyperion_adapters::nginx::warn_if_user_missing(&detected).await;
        self.nginx_user = detected;
    }
}

#[async_trait]
impl AdapterPort for RealAdapter {
    fn nginx_user(&self) -> String {
        self.nginx_user.clone()
    }

    async fn ensure_user(&self, name: &str, home_dir: &str) -> Result<u32, AdapterError> {
        let spec = hyperion_adapters::users::UserSpec::new_with_default_shell(
            SystemUserName::parse(name)?,
            home_dir.to_string(),
        );
        let info = hyperion_adapters::users::ensure_user(&spec).await?;
        Ok(info.uid)
    }

    async fn delete_user(&self, name: &str) -> Result<(), AdapterError> {
        let n = SystemUserName::parse(name)?;
        hyperion_adapters::users::delete_user(&n).await
    }

    async fn ensure_dirs(
        &self,
        htdocs: &str,
        logs: &str,
        tmp: &str,
        owner_uid: u32,
    ) -> Result<(), AdapterError> {
        // htdocs must be world-readable so nginx (www-data, NOT in the
        // hosting user's group) can serve static files — without the
        // x-for-others bit nginx returns 403. logs + tmp stay tight
        // because only PHP-FPM (running AS the hosting user) writes to
        // them. Also: every ancestor dir up to /home needs x-for-others
        // so nginx can traverse — but useradd -m defaults home to 0755
        // so that's already fine.
        for (p, mode) in [(htdocs, 0o755u32), (logs, 0o750), (tmp, 0o750)] {
            hyperion_adapters::fs::ensure_dir(std::path::Path::new(p), mode).await?;
            let res = tokio::process::Command::new("/usr/bin/chown")
                .arg(format!("{}:{}", owner_uid, owner_uid))
                .arg(p)
                .output()
                .await;
            if let Err(e) = res {
                tracing::warn!(error=%e, path=%p, "chown failed (non-fatal on non-root)");
            }
        }
        // The hosting-root directory (parent of htdocs/logs/tmp) also
        // needs world-x so nginx can descend into htdocs. useradd makes
        // /home/<user> 0755 by default; we only need to tighten / fix
        // <hosting_root> here. Best-effort: derive it as htdocs's parent.
        if let Some(host_root) = std::path::Path::new(htdocs).parent() {
            let _ = tokio::process::Command::new("/usr/bin/chmod")
                .arg("0755")
                .arg(host_root)
                .output()
                .await;
        }

        // Drop a placeholder index.html so a fresh site shows a friendly
        // "Hello from Hyperion" page instead of an nginx 403 (which is
        // what happens when the directory is empty + autoindex is off).
        // Operator/client replaces it with real content.
        let index_path = std::path::Path::new(htdocs).join("index.html");
        if !index_path.exists() {
            let body = HOSTING_PLACEHOLDER_HTML;
            if let Err(e) = tokio::fs::write(&index_path, body).await {
                tracing::warn!(error=%e, "could not write placeholder index.html");
            } else {
                let _ = tokio::process::Command::new("/usr/bin/chown")
                    .arg(format!("{}:{}", owner_uid, owner_uid))
                    .arg(&index_path)
                    .output()
                    .await;
                let _ = tokio::process::Command::new("/usr/bin/chmod")
                    .arg("0644")
                    .arg(&index_path)
                    .output()
                    .await;
            }
        }
        Ok(())
    }

    async fn remove_hosting_tree(&self, root: &str) -> Result<(), AdapterError> {
        hyperion_adapters::fs::remove_dir_all(std::path::Path::new(root)).await
    }

    async fn fpm_ensure(
        &self,
        system_user: &str,
        domain: &str,
        version: PhpVersion,
    ) -> Result<(), AdapterError> {
        let input = hyperion_adapters::phpfpm::PoolInput::defaults_with_owner(
            system_user,
            domain,
            version,
            &self.nginx_user,
            &self.nginx_user,
        );
        hyperion_adapters::phpfpm::ensure_pool(&input).await?;
        Ok(())
    }

    async fn fpm_delete(&self, system_user: &str, version: PhpVersion) -> Result<(), AdapterError> {
        hyperion_adapters::phpfpm::delete_pool(system_user, version).await
    }

    async fn db_create(
        &self,
        engine: DbProvision,
        hosting_id: &HostingId,
        domain: &str,
    ) -> Result<DbCredentials, AdapterError> {
        match engine {
            DbProvision::MariaDB => {
                let r = hyperion_adapters::mariadb::create_db_and_user(hosting_id, domain).await?;
                Ok(DbCredentials {
                    engine,
                    db_name: r.db_name,
                    db_user: r.db_user,
                    password: r.password,
                })
            }
            DbProvision::Postgres => {
                let r = hyperion_adapters::postgres::create_db_and_role(hosting_id, domain).await?;
                Ok(DbCredentials {
                    engine,
                    db_name: r.db_name,
                    db_user: r.db_user,
                    password: r.password,
                })
            }
        }
    }

    async fn db_drop(
        &self,
        engine: DbProvision,
        db_name: &str,
        db_user: &str,
    ) -> Result<(), AdapterError> {
        match engine {
            DbProvision::MariaDB => {
                hyperion_adapters::mariadb::drop_db_and_user(db_name, db_user).await
            }
            DbProvision::Postgres => {
                hyperion_adapters::postgres::drop_db_and_role(db_name, db_user).await
            }
        }
    }

    async fn acme_issue(&self, domain: &str, sans: &[String]) -> Result<CertInfo, AdapterError> {
        // Foundation note: a full ACME HTTP-01 flow with nginx temp vhost
        // coordination is deferred to sub-project 9 hardening / a follow-up
        // task. For now we generate a self-signed cert via rcgen and write
        // it to disk so the rest of the pipeline (DB row + nginx vhost)
        // works end-to-end on first boot. Operators replace via
        // `hctl cert renew` once the ACME loop ships.
        let mut all_names = vec![domain.to_string()];
        all_names.extend(sans.iter().cloned());
        let params = rcgen::CertificateParams::new(all_names.clone())
            .map_err(|e| AdapterError::Acme(format!("rcgen params: {e}")))?;
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| AdapterError::Acme(format!("rcgen keypair: {e}")))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| AdapterError::Acme(format!("rcgen sign: {e}")))?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let domain_dir = self.certs_root.join(domain);
        hyperion_adapters::fs::ensure_dir(&domain_dir, 0o700).await?;
        hyperion_adapters::fs::atomic_write(
            &domain_dir.join("fullchain.pem"),
            cert_pem.as_bytes(),
            0o644,
        )
        .await?;
        hyperion_adapters::fs::atomic_write(
            &domain_dir.join("privkey.pem"),
            key_pem.as_bytes(),
            0o600,
        )
        .await?;
        // not_after = now + 365 days as rcgen default
        let not_after = hyperion_types::now_secs() + 365 * 24 * 3600;
        Ok(CertInfo {
            domain: domain.to_string(),
            sans: sans.to_vec(),
            issuer: "self-signed".into(),
            not_after,
            fingerprint_sha256: hyperion_adapters::acme::fingerprint_sha256_der(
                cert_pem.as_bytes(),
            ),
        })
    }

    async fn acme_delete(&self, domain: &str) -> Result<(), AdapterError> {
        let domain_dir = self.certs_root.join(domain);
        hyperion_adapters::fs::remove_dir_all(&domain_dir).await
    }

    async fn nginx_write_vhost(&self, detail: &HostingDetail) -> Result<(), AdapterError> {
        let cert_path = format!(
            "{}/{}/fullchain.pem",
            self.certs_root.display(),
            detail.domain
        );
        let key_path = format!(
            "{}/{}/privkey.pem",
            self.certs_root.display(),
            detail.domain
        );
        let logs_dir = detail.root_dir.replace("/htdocs", "/logs");
        let acme_root = self.acme_challenge_root.display().to_string();
        // Dispatch on hosting kind. Reverse-proxy uses a completely
        // different template (proxy_pass instead of root + PHP-FPM);
        // static = same as php template but with no fastcgi_pass.
        if detail.kind == "reverse_proxy" {
            let upstream = detail
                .proxy_upstream_url
                .as_deref()
                .unwrap_or("http://127.0.0.1:0");
            let input = hyperion_adapters::nginx::ProxyVhostInput {
                domain: &detail.domain,
                aliases: &detail.aliases,
                logs_dir: &logs_dir,
                cert_path: &cert_path,
                key_path: &key_path,
                acme_challenge_root: &acme_root,
                upstream_url: upstream,
            };
            return hyperion_adapters::nginx::write_vhost_proxy(&self.nginx_paths, &input).await;
        }
        // Redirect-only hosting: completely separate template, no
        // FPM/root/htdocs/PHP. The vhost_options struct holds the
        // target URL + code + preserve-path flag the operator set.
        if detail.kind == "redirect" {
            // Empty redirect_url defaults to a placeholder so nginx -t
            // still passes; operator is expected to fill it in via
            // the vhost-options form right after creating the hosting.
            let target = if detail.vhost_options.redirect_url.is_empty() {
                "https://example.com/"
            } else {
                detail.vhost_options.redirect_url.as_str()
            };
            let code = if detail.vhost_options.redirect_code == 0 {
                302
            } else {
                detail.vhost_options.redirect_code
            };
            let input = hyperion_adapters::nginx::RedirectVhostInput {
                domain: &detail.domain,
                aliases: &detail.aliases,
                cert_path: &cert_path,
                key_path: &key_path,
                acme_challenge_root: &acme_root,
                redirect_url: target,
                redirect_code: code,
                redirect_preserve_path: detail.vhost_options.redirect_preserve_path,
            };
            return hyperion_adapters::nginx::write_redirect_vhost(&self.nginx_paths, &input).await;
        }
        let php = detail.php_version.map(|v| v.as_str());
        let input = hyperion_adapters::nginx::VhostInput {
            domain: &detail.domain,
            aliases: &detail.aliases,
            root_dir: &detail.root_dir,
            logs_dir: &logs_dir,
            system_user: &detail.system_user,
            php_version: php,
            cert_path: &cert_path,
            key_path: &key_path,
            acme_challenge_root: &acme_root,
            hosting_id: detail.id.as_str(),
            options: &detail.vhost_options,
        };
        hyperion_adapters::nginx::write_vhost(&self.nginx_paths, &input).await
    }

    async fn nginx_delete_vhost(
        &self,
        domain: &str,
        hosting_id: Option<String>,
    ) -> Result<(), AdapterError> {
        hyperion_adapters::nginx::delete_vhost(
            &self.nginx_paths,
            domain,
            hosting_id.as_deref(),
        )
        .await
    }

    async fn nginx_write_htpasswd(
        &self,
        hosting_id: &str,
        user: &str,
        bcrypt_hash: &str,
    ) -> Result<(), AdapterError> {
        hyperion_adapters::nginx::write_htpasswd(hosting_id, user, bcrypt_hash).await
    }

    async fn nginx_delete_htpasswd(&self, hosting_id: &str) -> Result<(), AdapterError> {
        hyperion_adapters::nginx::delete_htpasswd(hosting_id).await
    }

    async fn nginx_apply_suspended(
        &self,
        domain: &str,
        reason_message: Option<String>,
    ) -> Result<(), AdapterError> {
        let cert_path = format!("{}/{}/fullchain.pem", self.certs_root.display(), domain);
        let key_path = format!("{}/{}/privkey.pem", self.certs_root.display(), domain);
        let msg =
            reason_message.unwrap_or_else(|| "This site is temporarily unavailable.".to_string());
        let input = hyperion_adapters::nginx::SuspendedInput {
            domain,
            cert_path: &cert_path,
            key_path: &key_path,
            reason_message: &msg,
        };
        hyperion_adapters::nginx::apply_suspended(&self.nginx_paths, &input).await
    }

    async fn apply_php_limits(
        &self,
        system_user: &str,
        domain: &str,
        version: Option<PhpVersion>,
        php_memory_mb: i64,
        php_max_exec_secs: i64,
        php_max_children: i64,
        php_max_requests: i64,
    ) -> Result<(), AdapterError> {
        let Some(ver) = version else {
            return Ok(());
        };
        let mut input = hyperion_adapters::phpfpm::PoolInput::defaults_with_owner(
            system_user,
            domain,
            ver,
            &self.nginx_user,
            &self.nginx_user,
        );
        input.memory_mb = php_memory_mb.max(16) as u32;
        input.max_exec_secs = php_max_exec_secs.max(1) as u32;
        input.max_children = php_max_children.max(1) as u32;
        input.max_requests = php_max_requests.max(0) as u32;
        hyperion_adapters::phpfpm::ensure_pool(&input).await?;
        Ok(())
    }

    async fn db_lock(&self, engine: DbProvision, db_user: &str) -> Result<(), AdapterError> {
        match engine {
            DbProvision::MariaDB => hyperion_adapters::mariadb::lock_user(db_user).await,
            DbProvision::Postgres => hyperion_adapters::postgres::lock_role(db_user).await,
        }
    }

    async fn db_unlock(&self, engine: DbProvision, db_user: &str) -> Result<(), AdapterError> {
        match engine {
            DbProvision::MariaDB => hyperion_adapters::mariadb::unlock_user(db_user).await,
            DbProvision::Postgres => hyperion_adapters::postgres::unlock_role(db_user).await,
        }
    }

    async fn linux_lock_login(&self, name: &str) -> Result<(), AdapterError> {
        let n = SystemUserName::parse(name)?;
        hyperion_adapters::users::lock_login(&n).await
    }

    async fn linux_unlock_login(&self, name: &str) -> Result<(), AdapterError> {
        let n = SystemUserName::parse(name)?;
        hyperion_adapters::users::unlock_login(&n).await
    }

    async fn kill_user_procs(&self, name: &str) -> Result<(), AdapterError> {
        let n = SystemUserName::parse(name)?;
        hyperion_adapters::users::kill_user_procs(&n).await
    }

    async fn wp_install_run(
        &self,
        system_user: &str,
        htdocs: &str,
        db_name: &str,
        db_user: &str,
        db_password: &str,
        db_host: &str,
        req: &WpInstallRequest,
    ) -> Result<String, AdapterError> {
        let db = hyperion_adapters::wpcli::WpDbCreds {
            name: db_name,
            user: db_user,
            password: db_password,
            host: db_host,
        };
        hyperion_adapters::wpcli::install_wordpress(system_user, htdocs, db, req).await
    }

    async fn wp_plugin_list(
        &self,
        system_user: &str,
        htdocs: &str,
    ) -> Result<(Vec<hyperion_types::WpPlugin>, String), AdapterError> {
        hyperion_adapters::wpcli::plugin_list(system_user, htdocs).await
    }

    async fn wp_plugin_action(
        &self,
        system_user: &str,
        htdocs: &str,
        slug: &str,
        action: &hyperion_types::WpPluginAction,
    ) -> Result<hyperion_types::WpPluginActionResult, AdapterError> {
        hyperion_adapters::wpcli::plugin_action(system_user, htdocs, slug, action).await
    }

    async fn wp_cli(
        &self,
        system_user: &str,
        htdocs: &str,
        kind: &str,
        source: &str,
        activate: bool,
    ) -> Result<(), AdapterError> {
        if kind != "plugin" && kind != "theme" {
            return Err(AdapterError::Other(format!(
                "wp_cli kind must be plugin|theme, got {kind:?}"
            )));
        }
        hyperion_adapters::wpcli::install_item(system_user, htdocs, kind, source, activate).await
    }

    async fn wp_theme_list(
        &self,
        system_user: &str,
        htdocs: &str,
    ) -> Result<(Vec<hyperion_types::WpTheme>, String), AdapterError> {
        hyperion_adapters::wpcli::theme_list(system_user, htdocs).await
    }

    async fn wp_theme_action(
        &self,
        system_user: &str,
        htdocs: &str,
        slug: &str,
        action: &hyperion_types::WpThemeAction,
    ) -> Result<hyperion_types::WpThemeActionResult, AdapterError> {
        hyperion_adapters::wpcli::theme_action(system_user, htdocs, slug, action).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_adapter_default_paths() {
        let a = RealAdapter::default();
        assert_eq!(
            a.nginx_paths.vhost_file("x.cz").to_string_lossy(),
            "/etc/nginx/sites-available/x.cz.conf"
        );
        assert_eq!(a.certs_root.display().to_string(), "/etc/hyperion/certs");
    }

    /// Regression test for the "403 Forbidden on fresh hosting" bug.
    ///
    /// Two failures had to be fixed simultaneously:
    /// 1. htdocs was created with mode 0o750 → nginx (www-data) is in
    ///    "others" and had no rx access → 403 even with a valid index.
    /// 2. htdocs was empty → nginx with autoindex off returns 403 on
    ///    an empty dir even when it CAN read the dir.
    ///
    /// This test verifies that after ensure_dirs:
    ///   - htdocs exists and is world-readable+executable (others can rx)
    ///   - logs + tmp are owner-only (0o750)
    ///   - htdocs/index.html exists, is non-empty, and is world-readable
    ///
    /// We run as the current (non-root) UID — chown will fail
    /// best-effort and that's fine; we only assert MODE bits here.
    #[tokio::test]
    async fn ensure_dirs_makes_htdocs_world_readable_and_writes_index() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let htdocs = root.path().join("site").join("htdocs");
        let logs = root.path().join("site").join("logs");
        let tmp = root.path().join("site").join("tmp");

        let a = RealAdapter::default();
        let uid = nix_uid();
        a.ensure_dirs(
            htdocs.to_str().unwrap(),
            logs.to_str().unwrap(),
            tmp.to_str().unwrap(),
            uid,
        )
        .await
        .expect("ensure_dirs");

        // htdocs: world rx required (others execute → 0o005 minimum).
        let m = std::fs::metadata(&htdocs).expect("htdocs metadata").permissions().mode() & 0o777;
        assert_eq!(m, 0o755, "htdocs mode must be 0755, got {:o}", m);

        // logs + tmp: must NOT be world-readable.
        for p in [&logs, &tmp] {
            let m = std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(m, 0o750, "{} mode must be 0750, got {:o}", p.display(), m);
        }

        // index.html exists, non-empty, world-readable.
        let idx = htdocs.join("index.html");
        let body = std::fs::read_to_string(&idx).expect("read index.html");
        assert!(!body.is_empty(), "index.html must not be empty");
        assert!(
            body.contains("Hyperion"),
            "placeholder should be the hyperion branded one"
        );
        let im = std::fs::metadata(&idx).expect("idx meta").permissions().mode() & 0o777;
        assert_eq!(im, 0o644, "index.html mode must be 0644, got {:o}", im);
    }

    /// Re-running ensure_dirs on a hosting that already has a real
    /// index.html (operator uploaded their own) MUST NOT overwrite it.
    /// Idempotency matters because the service flow can re-run this on
    /// edit / repair operations.
    #[tokio::test]
    async fn ensure_dirs_does_not_clobber_existing_index() {
        let root = tempfile::tempdir().expect("tempdir");
        let htdocs = root.path().join("htdocs");
        let logs = root.path().join("logs");
        let tmp = root.path().join("tmp");
        std::fs::create_dir_all(&htdocs).unwrap();
        let idx = htdocs.join("index.html");
        std::fs::write(&idx, "<h1>my real site</h1>").unwrap();

        let a = RealAdapter::default();
        a.ensure_dirs(
            htdocs.to_str().unwrap(),
            logs.to_str().unwrap(),
            tmp.to_str().unwrap(),
            nix_uid(),
        )
        .await
        .expect("ensure_dirs");

        let body = std::fs::read_to_string(&idx).expect("read");
        assert_eq!(body, "<h1>my real site</h1>", "existing index was overwritten");
    }

    /// Current process UID — we use it for ensure_dirs so chown becomes
    /// a no-op (we already own everything in the tempdir).
    fn nix_uid() -> u32 {
        // SAFETY-free path: read from /proc on linux, fall back to env.
        // We avoid pulling in the nix crate just for getuid().
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(first) = rest.split_whitespace().next() {
                        if let Ok(u) = first.parse::<u32>() {
                            return u;
                        }
                    }
                }
            }
        }
        // macOS / fallback: USER → id -u via env not reliable; just use 1000.
        // chown of a non-existent uid will fail best-effort, which is fine.
        std::env::var("UID").ok().and_then(|s| s.parse().ok()).unwrap_or(1000)
    }

    #[tokio::test]
    async fn acme_issue_writes_self_signed_files() {
        let d = tempfile::tempdir().expect("tempdir");
        let a = RealAdapter {
            certs_root: d.path().to_path_buf(),
            ..Default::default()
        };
        let info = a
            .acme_issue("example.cz", &["www.example.cz".to_string()])
            .await
            .expect("issue");
        assert_eq!(info.domain, "example.cz");
        assert_eq!(info.issuer, "self-signed");
        let cert_path = d.path().join("example.cz/fullchain.pem");
        let key_path = d.path().join("example.cz/privkey.pem");
        assert!(cert_path.exists());
        assert!(key_path.exists());
        // verify PEM markers
        let cert = std::fs::read_to_string(&cert_path).expect("read");
        assert!(cert.contains("BEGIN CERTIFICATE"));
        let key = std::fs::read_to_string(&key_path).expect("read");
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }
}
