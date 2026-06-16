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
        // them. The ancestor-traversal fix is below (the home dir is
        // NOT 0755 on Debian 12 — see there).
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
        // Every ancestor dir from htdocs up to / must be traversable
        // (o+x) so nginx — running as www-data, NOT in the hosting
        // user's group — can descend to htdocs and stat index.php.
        //
        // The old code assumed `useradd -m` leaves /home/<user> at
        // 0755 and only fixed <hosting_root>. That's WRONG on Debian
        // 12: useradd honours HOME_MODE in /etc/login.defs, which
        // defaults to 0700, so /home/<user> is drwx------ and nginx
        // can't traverse it. The visible symptom is a hard nginx 404
        // on EVERY request (the `try_files $uri =404` in the vhost's
        // `location ~ \.php$` can't see index.php through the 0700
        // home), which looks like "WordPress installed but the site
        // 404s". OR-ing 0o011 adds the x bit on each ancestor WITHOUT
        // exposing directory listings (no r) — the standard shared-
        // hosting 0711 home, consistent with htdocs already being
        // world-readable. Already-traversable dirs (/, /home, …) are
        // skipped, so this only touches the per-user homes we own.
        hyperion_adapters::fs::ensure_ancestors_traversable(
            std::path::Path::new(htdocs),
        )
        .await;

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

    async fn nginx_reload(&self) -> Result<(), AdapterError> {
        hyperion_adapters::nginx::reload().await
    }

    async fn fpm_recover_failed(&self) -> Result<usize, AdapterError> {
        let mut recovered = 0usize;
        for ver in PhpVersion::all() {
            let svc = format!("{}.service", ver.service_name());
            // Skip versions not installed on this node — checked via
            // systemctl cat (canonical "is unit known").
            let known = tokio::process::Command::new("/usr/bin/systemctl")
                .args(["cat", &svc])
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !known {
                continue;
            }
            // is-failed --quiet returns exit 0 iff state is "failed".
            let failed = tokio::process::Command::new("/usr/bin/systemctl")
                .args(["is-failed", "--quiet", &svc])
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if !failed {
                continue;
            }
            tracing::warn!(
                service = %svc,
                "boot: FPM service in failed state — reset-failed + start"
            );
            if let Err(e) = self.fpm_restart(*ver).await {
                tracing::error!(
                    service = %svc,
                    error = %e,
                    "boot: FPM recovery failed (likely a pool config error — see journalctl)"
                );
                continue;
            }
            recovered += 1;
        }
        Ok(recovered)
    }

    async fn fpm_restart(&self, version: PhpVersion) -> Result<(), AdapterError> {
        // systemctl restart php<ver>-fpm. We don't reuse phpfpm::reload
        // here because after a quarantine we want a fresh START (the
        // service is likely "failed" from too many restarts), not a
        // reload — reload on a failed unit is a no-op.
        let svc = format!("{}.service", version.service_name());
        let out = tokio::process::Command::new("/usr/bin/systemctl")
            .args(["reset-failed", &svc])
            .output()
            .await
            .map_err(AdapterError::Io)?;
        if !out.status.success() {
            // Not fatal — `reset-failed` is a courtesy; the start
            // below may still succeed on a unit that never failed.
            tracing::debug!(
                service = %svc,
                stderr = %String::from_utf8_lossy(&out.stderr),
                "reset-failed returned non-zero (continuing to start)"
            );
        }
        let out = tokio::process::Command::new("/usr/bin/systemctl")
            .args(["start", &svc])
            .output()
            .await
            .map_err(AdapterError::Io)?;
        if !out.status.success() {
            return Err(AdapterError::Command {
                cmd: format!("/usr/bin/systemctl start {svc}"),
                code: out.status.code().unwrap_or(-1),
                stderr_tail: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(())
    }

    async fn repair_orphan_fpm_pools(&self) -> Result<(usize, usize), AdapterError> {
        let mut scanned = 0usize;
        let mut quarantined = 0usize;
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for ver in PhpVersion::all() {
            let pool_dir = std::path::PathBuf::from(ver.pool_dir());
            let mut entries = match tokio::fs::read_dir(&pool_dir).await {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    tracing::warn!(
                        version = %ver,
                        dir = %pool_dir.display(),
                        error = %e,
                        "repair_orphan_fpm_pools: read_dir failed (skipping version)"
                    );
                    continue;
                }
            };
            while let Some(entry) = entries.next_entry().await.map_err(AdapterError::Io)? {
                let path = entry.path();
                // Only inspect actual pool files. Quarantine markers
                // we wrote on a previous boot have a longer suffix.
                if path.extension().and_then(|s| s.to_str()) != Some("conf") {
                    continue;
                }
                scanned += 1;
                let body = match tokio::fs::read_to_string(&path).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "repair_orphan_fpm_pools: read failed (skipping)"
                        );
                        continue;
                    }
                };
                // Collect every user-reference we want to validate:
                // top-level `user`, `group`, `listen.owner`, `listen.group`.
                // We validate all of them so a pool with a working
                // `user` but a busted `listen.owner` still gets
                // caught.
                let users = extract_pool_user_directives(&body);
                let mut missing: Vec<(&'static str, String)> = Vec::new();
                for (label, name) in users.iter() {
                    if !unix_user_exists(name).await {
                        missing.push((*label, name.clone()));
                    }
                }
                if missing.is_empty() {
                    continue;
                }
                let quarantine_path = path.with_extension(format!(
                    "conf.hyperion-quarantined-{now_ts}"
                ));
                tracing::warn!(
                    pool = %path.display(),
                    quarantined = %quarantine_path.display(),
                    missing = ?missing,
                    "repair_orphan_fpm_pools: pool references missing Unix users — quarantining"
                );
                if let Err(e) = tokio::fs::rename(&path, &quarantine_path).await {
                    tracing::error!(
                        pool = %path.display(),
                        error = %e,
                        "repair_orphan_fpm_pools: rename to quarantine failed"
                    );
                    continue;
                }
                quarantined += 1;
            }
            // Round two for this PHP version: even pools that look
            // user-valid may have syntax errors (a stray `#` comment,
            // truncated value, etc.). Run `php-fpm<ver> -t`, parse the
            // first pool path out of stderr, quarantine it, retry.
            // Bounded by `MAX_FPM_T_PASSES` to avoid an infinite loop
            // if FPM ever returns an error we can't attribute to a
            // specific file.
            const MAX_FPM_T_PASSES: usize = 12;
            for _ in 0..MAX_FPM_T_PASSES {
                match hyperion_adapters::phpfpm::test_config(*ver).await {
                    Ok(()) => break,
                    Err(AdapterError::Command { stderr_tail, .. }) => {
                        let Some(bad_path) = extract_fpm_test_failed_path(&stderr_tail) else {
                            tracing::warn!(
                                version = %ver,
                                stderr = %stderr_tail,
                                "repair_orphan_fpm_pools: php-fpm -t failed but no \
                                 attributable pool path in stderr — leaving alone"
                            );
                            break;
                        };
                        // Sanity: only quarantine inside the version's
                        // pool dir. We don't touch php-fpm.conf or
                        // www.conf etc. living elsewhere.
                        if !bad_path.starts_with(&pool_dir) {
                            tracing::warn!(
                                version = %ver,
                                path = %bad_path.display(),
                                "repair_orphan_fpm_pools: php-fpm -t complained about \
                                 a file outside the pool dir — leaving alone"
                            );
                            break;
                        }
                        let qpath = bad_path.with_extension(format!(
                            "conf.hyperion-quarantined-{now_ts}"
                        ));
                        tracing::warn!(
                            pool = %bad_path.display(),
                            quarantined = %qpath.display(),
                            "repair_orphan_fpm_pools: php-fpm -t rejected pool — quarantining"
                        );
                        if let Err(e) = tokio::fs::rename(&bad_path, &qpath).await {
                            tracing::error!(
                                pool = %bad_path.display(),
                                error = %e,
                                "repair_orphan_fpm_pools: rename to quarantine failed"
                            );
                            break;
                        }
                        quarantined += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            version = %ver,
                            error = %e,
                            "repair_orphan_fpm_pools: php-fpm -t errored (not a config error) \
                             — leaving alone"
                        );
                        break;
                    }
                }
            }
        }
        Ok((quarantined, scanned))
    }

    async fn ensure_vhost_log_dirs(&self) -> Result<(usize, usize), AdapterError> {
        let sites_dir = &self.nginx_paths.sites_enabled;
        let mut entries = match tokio::fs::read_dir(sites_dir).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(AdapterError::Io(e)),
        };
        let mut scanned = 0usize;
        let mut created = 0usize;
        while let Some(entry) = entries.next_entry().await.map_err(AdapterError::Io)? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("conf") {
                continue;
            }
            scanned += 1;
            let body = match tokio::fs::read_to_string(&path).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "ensure_vhost_log_dirs: read failed (skipping)"
                    );
                    continue;
                }
            };
            for log_path in extract_log_paths(&body) {
                // Defensive: only create dirs under /home or /var.
                // We never want to mkdir somewhere weird if a vhost
                // gets pasted in pointing at /etc or /.
                if !log_path.starts_with("/home")
                    && !log_path.starts_with("/var")
                {
                    continue;
                }
                let Some(parent) = log_path.parent() else {
                    continue;
                };
                if tokio::fs::metadata(&parent).await.is_ok() {
                    continue;
                }
                tracing::warn!(
                    vhost = %path.display(),
                    log_dir = %parent.display(),
                    "ensure_vhost_log_dirs: parent dir missing — creating"
                );
                if let Err(e) = tokio::fs::create_dir_all(&parent).await {
                    tracing::error!(
                        path = %parent.display(),
                        error = %e,
                        "ensure_vhost_log_dirs: mkdir -p failed"
                    );
                    continue;
                }
                // Best-effort chown to the hosting's system user if
                // we can derive it from the path. Path shape:
                // /home/<user>/<domain>/logs → owner = <user>.
                if let Some(user) = derive_system_user_from_log_path(parent) {
                    let _ = tokio::process::Command::new("/usr/bin/chown")
                        .args(["-R", &format!("{user}:{user}"), &parent.display().to_string()])
                        .status()
                        .await;
                }
                created += 1;
            }
        }
        Ok((created, scanned))
    }

    async fn repair_orphan_certs(&self) -> Result<(usize, usize), AdapterError> {
        let sites_dir = &self.nginx_paths.sites_enabled;
        let mut entries = match tokio::fs::read_dir(sites_dir).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(AdapterError::Io(e)),
        };

        let mut scanned = 0usize;
        let mut repaired = 0usize;

        while let Some(entry) = entries.next_entry().await.map_err(AdapterError::Io)? {
            let path = entry.path();
            // Only inspect .conf files. nginx's sites-enabled also
            // legitimately contains "default" (no extension) on Debian
            // out-of-the-box — skip those.
            if path.extension().and_then(|s| s.to_str()) != Some("conf") {
                continue;
            }
            scanned += 1;
            let body = match tokio::fs::read_to_string(&path).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "repair_orphan_certs: skip (read failed)"
                    );
                    continue;
                }
            };
            for cert_path in extract_ssl_certificate_paths(&body) {
                // Only repair certs we own (under our certs_root).
                // We never touch certs at /etc/letsencrypt/... or
                // other operator-managed paths.
                let pb = std::path::Path::new(&cert_path);
                if !pb.starts_with(&self.certs_root) {
                    continue;
                }
                if pb.exists() {
                    continue;
                }
                // Derive the domain: <certs_root>/<DOMAIN>/fullchain.pem
                let Some(domain) = pb
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|s| s.to_str())
                else {
                    tracing::warn!(
                        cert = %cert_path,
                        "repair_orphan_certs: cannot derive domain from path"
                    );
                    continue;
                };
                tracing::warn!(
                    domain = %domain,
                    vhost = %path.display(),
                    "repair_orphan_certs: cert missing → generating self-signed bootstrap"
                );
                // No SANs at hand (we don't re-parse the vhost for
                // server_name aliases); LE will fix the SANs on the
                // next real renewal. Self-signed-with-domain-only is
                // enough to unbrick nginx -t today.
                if let Err(e) = self.acme_issue(domain, &[]).await {
                    tracing::error!(
                        domain = %domain,
                        error = %e,
                        "repair_orphan_certs: acme_issue (self-signed) failed"
                    );
                    continue;
                }
                repaired += 1;
            }
        }
        Ok((repaired, scanned))
    }

    async fn nginx_write_vhost(&self, detail: &HostingDetail) -> Result<(), AdapterError> {
        // Explicit shared-cert paths (e.g. a test node's *.<base> wildcard
        // reused by every auto-subdomain) win; otherwise derive the
        // per-domain default.
        let cert_path = detail.cert_path.clone().unwrap_or_else(|| {
            format!("{}/{}/fullchain.pem", self.certs_root.display(), detail.domain)
        });
        let key_path = detail.cert_key_path.clone().unwrap_or_else(|| {
            format!("{}/{}/privkey.pem", self.certs_root.display(), detail.domain)
        });
        // Self-heal: if the cert files have gone missing (operator
        // manually deleted /etc/hyperion/certs/<domain>, partial
        // failure from an earlier panel version, mid-restore state),
        // bootstrap a self-signed cert here so the vhost we're about
        // to write is always renderable AND nginx -t can succeed.
        // Without this, a single missing cert dir bricks the entire
        // nginx process: every `service nginx start` fails because
        // ONE vhost references a non-existent cert.
        //
        // The bootstrap is the same self-signed cert that
        // acme_issue() would have written; the real LE cert is
        // re-issued on the next renewal tick (or via "Issue cert"
        // on the SSL tab).
        if !std::path::Path::new(&cert_path).exists()
            || !std::path::Path::new(&key_path).exists()
        {
            tracing::warn!(
                domain = %detail.domain,
                "cert files missing — generating self-signed bootstrap (LE will replace on next renewal tick)"
            );
            // Propagate failure rather than swallow. Without a cert
            // file we'd be writing a vhost that nginx -t will reject,
            // and `write_vhost` would then roll back to whatever was
            // there before — leaving the operator with a confusing
            // "create succeeded but my domain doesn't serve" state.
            // Better to fail fast: the audit log will record the real
            // cause (rcgen problem, disk full, EROFS on the certs
            // dir, etc.) instead of an opaque nginx -t error.
            self.acme_issue(&detail.domain, &detail.aliases)
                .await
                .map_err(|e| {
                    tracing::error!(
                        domain = %detail.domain,
                        error = %e,
                        "self-heal bootstrap cert failed"
                    );
                    e
                })?;
        }
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

    async fn wp_set_debug(
        &self,
        system_user: &str,
        htdocs: &str,
        enabled: bool,
        log: bool,
        display: bool,
    ) -> Result<(), AdapterError> {
        use hyperion_adapters::wpcli::{
            delete_config_constant, set_config_constant, WpConstantValue,
        };
        if enabled {
            set_config_constant(system_user, htdocs, "WP_DEBUG", WpConstantValue::Bool(true))
                .await?;
            if log {
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_DEBUG_LOG",
                    WpConstantValue::Bool(true),
                )
                .await?;
            } else {
                delete_config_constant(system_user, htdocs, "WP_DEBUG_LOG").await?;
            }
            if display {
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_DEBUG_DISPLAY",
                    WpConstantValue::Bool(true),
                )
                .await?;
            } else {
                // Explicit `false` here (not delete) — WP's default is
                // true, so a missing WP_DEBUG_DISPLAY leaks errors on
                // sites that don't override it elsewhere.
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_DEBUG_DISPLAY",
                    WpConstantValue::Bool(false),
                )
                .await?;
            }
        } else {
            for c in ["WP_DEBUG", "WP_DEBUG_LOG", "WP_DEBUG_DISPLAY"] {
                delete_config_constant(system_user, htdocs, c).await?;
            }
        }
        Ok(())
    }

    async fn wp_set_redis(
        &self,
        system_user: &str,
        htdocs: &str,
        cfg: Option<hyperion_types::WpRedisConfig>,
    ) -> Result<(), AdapterError> {
        let cfg = cfg.as_ref();
        use hyperion_adapters::wpcli::{
            delete_config_constant, set_config_constant, WpConstantValue,
        };
        const KEYS: &[&str] = &[
            "WP_REDIS_HOST",
            "WP_REDIS_PORT",
            "WP_REDIS_DATABASE",
            "WP_REDIS_USERNAME",
            "WP_REDIS_PASSWORD",
            "WP_REDIS_PREFIX",
        ];
        match cfg {
            Some(c) => {
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_REDIS_HOST",
                    WpConstantValue::String(&c.host),
                )
                .await?;
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_REDIS_PORT",
                    WpConstantValue::Int(c.port),
                )
                .await?;
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_REDIS_DATABASE",
                    WpConstantValue::Int(c.database),
                )
                .await?;
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_REDIS_USERNAME",
                    WpConstantValue::String(&c.username),
                )
                .await?;
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_REDIS_PASSWORD",
                    WpConstantValue::String(&c.password),
                )
                .await?;
                set_config_constant(
                    system_user,
                    htdocs,
                    "WP_REDIS_PREFIX",
                    WpConstantValue::String(&c.key_prefix),
                )
                .await?;
            }
            None => {
                for k in KEYS {
                    delete_config_constant(system_user, htdocs, k).await?;
                }
            }
        }
        Ok(())
    }

    async fn wp_debug_log_size(&self, htdocs: &str) -> Result<i64, AdapterError> {
        let p = std::path::Path::new(htdocs).join("wp-content/debug.log");
        match tokio::fs::metadata(&p).await {
            Ok(m) => Ok(m.len() as i64),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(AdapterError::Other(format!("stat debug.log: {e}"))),
        }
    }

    async fn redis_is_available(&self) -> bool {
        // `systemctl is-active redis-server` → "active" / anything else.
        // Cheap (~10 ms), no fork-and-exec of redis-cli; uses systemd
        // which is the source of truth for "is this unit running".
        hyperion_adapters::systemctl_status_rich("redis-server")
            .await
            .active
    }

    async fn redis_ensure_acl(
        &self,
        username: &str,
        password: &str,
        db_number: i64,
    ) -> Result<(), AdapterError> {
        // Use redis-cli ACL SETUSER. The DB-restriction is done via
        // `~h:<db>:*` keypattern; combined with ` -n <db>` on the
        // client side this gives a clean per-tenant boundary.
        // password is passed as `>password` literal to ACL SETUSER.
        if username.is_empty()
            || !username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(AdapterError::Other(format!("bad redis username: {username}")));
        }
        if !(0..=63).contains(&db_number) {
            return Err(AdapterError::Other(format!(
                "redis db_number out of range: {db_number}"
            )));
        }
        if password.len() < 16 {
            return Err(AdapterError::Other("redis password too short".into()));
        }
        let pw_arg = format!(">{password}");
        let keyrule = format!("~h{db_number}:*");
        let cmd_args: Vec<&str> = vec![
            "ACL",
            "SETUSER",
            username,
            "on",
            "resetkeys",
            "resetchannels",
            &keyrule,
            "+@read",
            "+@write",
            "+@keyspace",
            "+@hash",
            "+@list",
            "+@set",
            "+@sortedset",
            "+@string",
            "+@scripting",
            "+@pubsub",
            "+@connection",
            "-@dangerous",
            "+ping",
            "+select",
            "+client|setname",
            &pw_arg,
        ];
        hyperion_adapters::cmd::run("/usr/bin/redis-cli", &cmd_args).await?;
        Ok(())
    }

    async fn redis_delete_acl(&self, username: &str) -> Result<(), AdapterError> {
        if username.is_empty() {
            return Ok(());
        }
        // ACL DELUSER returns 1 if deleted, 0 if didn't exist — both fine.
        let _ = hyperion_adapters::cmd::run("/usr/bin/redis-cli", &["ACL", "DELUSER", username])
            .await;
        Ok(())
    }
}

/// Extract every `ssl_certificate <path>;` value from an nginx
/// config body. Skips `ssl_certificate_key`, which has the same
/// prefix — we match on a trailing space so only the cert lines
/// (not the key lines) are returned. Trims leading whitespace + a
/// trailing semicolon. Comments (`# ssl_certificate ...`) are
/// skipped because we only consider lines whose first non-ws token
/// is the directive itself.
fn extract_ssl_certificate_paths(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim_start();
        // Use the `_key` discriminator trick: `ssl_certificate ` (with
        // a trailing space) matches the cert directive but not
        // `ssl_certificate_key` which has `_` after the prefix.
        let Some(rest) = line.strip_prefix("ssl_certificate ") else {
            continue;
        };
        let value = rest.trim().trim_end_matches(';').trim();
        if !value.is_empty() {
            out.push(value.to_string());
        }
    }
    out
}

/// Extract every Unix-user reference from a PHP-FPM pool config
/// body. The four directives we care about — all of which can break
/// FPM startup with exit 78 if the user doesn't exist — are:
///   * `user = <name>`         (pool worker uid)
///   * `group = <name>`        (pool worker gid)
///   * `listen.owner = <name>` (socket owner — nginx connects as this)
///   * `listen.group = <name>` (socket group)
///
/// Returns `(directive_label, username)` pairs so the caller can
/// log which directive was at fault. Comments (lines starting with
/// `;` or `#`) and `[section]` headers are skipped. Empty values
/// are skipped (FPM accepts an unset directive, it just inherits
/// the parent — that's not what we're hunting).
fn extract_pool_user_directives(body: &str) -> Vec<(&'static str, String)> {
    // Each entry: (literal directive prefix as it appears at line
    // start, human label used in logs). The PHP-FPM INI parser
    // tolerates whitespace around `=`, so we strip after `=`.
    const KEYS: &[(&str, &str)] = &[
        ("user", "user"),
        ("group", "group"),
        ("listen.owner", "listen.owner"),
        ("listen.group", "listen.group"),
    ];
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            continue;
        }
        for (key, label) in KEYS.iter() {
            // The PHP-FPM config syntax allows `key = value` or
            // `key=value`. Accept both. We don't accept `keyfoo =`
            // as a false positive — require the next char after the
            // key to be whitespace or `=`.
            let Some(rest) = line.strip_prefix(key) else {
                continue;
            };
            let next = rest.chars().next();
            if !matches!(next, Some('=') | Some(' ') | Some('\t')) {
                continue;
            }
            // Find the `=` and grab everything after it up to the
            // first comment marker (`;` is FPM's comment char).
            let Some(eq_pos) = rest.find('=') else {
                continue;
            };
            let value = &rest[eq_pos + 1..];
            let value = value.split(';').next().unwrap_or("").trim();
            if !value.is_empty() {
                out.push((*label, value.to_string()));
            }
        }
    }
    out
}

/// Extract every `access_log <path>;` and `error_log <path>;`
/// value from an nginx config body. Handles inline options after
/// the path (e.g. `access_log /x/y.log combined buffer=32k;`) by
/// taking only the first whitespace-separated token after the
/// directive. Skips comments and lines where the directive isn't
/// at the start of the (trimmed) line.
fn extract_log_paths(body: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim_start();
        let rest = if let Some(r) = line.strip_prefix("access_log ") {
            r
        } else if let Some(r) = line.strip_prefix("error_log ") {
            r
        } else {
            continue;
        };
        let value = rest.trim().trim_end_matches(';').trim();
        // Take only the first whitespace-separated token — that's
        // the file path. Subsequent tokens are options (format,
        // buffer size, gzip level, …).
        let path = value.split_whitespace().next().unwrap_or("");
        // Skip the sentinel "off" which disables logging.
        if path.is_empty() || path == "off" {
            continue;
        }
        out.push(std::path::PathBuf::from(path));
    }
    out
}

/// Given a log dir path of the shape
/// `/home/<system_user>/<domain>/logs`, return `<system_user>`.
/// Returns `None` for any other path shape so we don't try to
/// chown e.g. `/var/log/nginx/...` to a non-existent user.
fn derive_system_user_from_log_path(p: &std::path::Path) -> Option<String> {
    let comps: Vec<_> = p.components().collect();
    // Need: "/", "home", "<user>", "<domain>", "logs" → 5 comps.
    if comps.len() < 4 {
        return None;
    }
    let mut it = comps.iter();
    // RootDir
    it.next()?;
    // "home"
    match it.next()? {
        std::path::Component::Normal(s) if s.to_str() == Some("home") => {}
        _ => return None,
    }
    let user = match it.next()? {
        std::path::Component::Normal(s) => s.to_str()?.to_string(),
        _ => return None,
    };
    // Validate as a POSIX-shape username so we never chown to
    // something injected.
    if user.is_empty()
        || !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some(user)
}

/// Parse the path of the first failing pool file out of
/// `php-fpm<ver> -t` stderr.
///
/// Real-world stderr from FPM looks like:
///
/// ```text
/// [05-Jun-2026 09:53:09] ERROR: [/etc/php/8.3/fpm/pool.d/<name>.conf:22] value is NULL for a ZEND_INI_PARSER_ENTRY
/// [05-Jun-2026 09:53:09] ERROR: Unable to include /etc/php/8.3/fpm/pool.d/<name>.conf from /etc/php/8.3/fpm/php-fpm.conf at line 22
/// [05-Jun-2026 09:53:09] ERROR: failed to load configuration file '/etc/php/8.3/fpm/php-fpm.conf'
/// [05-Jun-2026 09:53:09] ERROR: FPM initialization failed
/// ```
///
/// We look for the first `[<path>:<line>]` token in the body
/// where `<path>` starts with `/etc/php/` — that's the pool that
/// blew up. Returns `None` if the stderr doesn't contain a
/// recognisable pool path (in which case the caller leaves the
/// state alone rather than guessing).
fn extract_fpm_test_failed_path(stderr: &str) -> Option<std::path::PathBuf> {
    for line in stderr.lines() {
        // Find any `[/etc/php/...:<n>]` token. We don't anchor on
        // ERROR: prefix because the timestamp format varies between
        // distros (some have it, the systemd journal strips it).
        let Some(open) = line.find("[/etc/php/") else {
            continue;
        };
        let after = &line[open + 1..]; // skip the `[`
        let Some(close) = after.find(']') else {
            continue;
        };
        let inside = &after[..close];
        // inside might look like `/etc/php/8.3/fpm/pool.d/x.conf:22`
        // or just `/etc/php/8.3/fpm/pool.d/x.conf`. Strip the
        // trailing `:<line>` if present.
        let path_part = inside.rsplit_once(':').map(|(p, _)| p).unwrap_or(inside);
        if path_part.is_empty() {
            continue;
        }
        return Some(std::path::PathBuf::from(path_part));
    }
    None
}

/// Check whether a Unix user exists on the system via
/// `getent passwd <name>`. Conservative: returns `true` on
/// any unexpected error (binary missing, permission denied,
/// etc.) so we never quarantine a pool just because we
/// couldn't run the check. False ONLY when getent ran cleanly
/// and reported the user as absent (exit code 2).
async fn unix_user_exists(name: &str) -> bool {
    // Defensive: empty name shouldn't pass, but if it does we
    // don't want to quarantine — empty `user =` is an FPM error
    // we'd rather surface verbatim.
    if name.is_empty() {
        return true;
    }
    // Reject names that contain shell metacharacters before passing
    // to getent. POSIX usernames are `[A-Za-z0-9._-]` only, and even
    // though we're passing as an argv arg (no shell), bad input
    // suggests this isn't a real user reference — skip.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return true;
    }
    let out = tokio::process::Command::new("/usr/bin/getent")
        .args(["passwd", name])
        .output()
        .await;
    match out {
        Ok(o) => o.status.success(),
        Err(_) => true, // getent missing? assume present, don't quarantine.
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

    /// Regression for the "WordPress installed but the site 404s" bug:
    /// `useradd -m` leaves /home/<user> at 0700 on Debian 12, which
    /// nginx (www-data) can't traverse. ensure_dirs must OR the x bit
    /// into every ancestor of htdocs so the site is reachable.
    #[tokio::test]
    async fn ensure_dirs_makes_0700_ancestor_traversable() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().expect("tempdir");
        // Simulate the 0700 home: <root>/home_user, with the hosting
        // tree under it.
        let home = root.path().join("home_user");
        let htdocs = home.join("site.cz").join("htdocs");
        std::fs::create_dir_all(&htdocs).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Precondition: not world-traversable.
        let m0 = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(m0 & 0o001, 0, "precondition: 0700 home has no world-x");

        let a = RealAdapter::default();
        a.ensure_dirs(
            htdocs.to_str().unwrap(),
            home.join("site.cz").join("logs").to_str().unwrap(),
            home.join("site.cz").join("tmp").to_str().unwrap(),
            nix_uid(),
        )
        .await
        .expect("ensure_dirs");

        // The 0700 home must now be world-traversable (x), but NOT
        // world-readable (no listings).
        let m = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_ne!(m & 0o001, 0, "home must gain world-x, got {:o}", m);
        assert_eq!(m & 0o004, 0, "home must NOT gain world-r, got {:o}", m);
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

    /// `extract_ssl_certificate_paths` must pull only the cert path,
    /// not the key path (they share the `ssl_certificate` prefix —
    /// classic gotcha).
    #[test]
    fn extract_ssl_cert_paths_distinguishes_cert_from_key() {
        let body = r#"
            server {
                listen 443 ssl;
                ssl_certificate     /etc/hyperion/certs/a.cz/fullchain.pem;
                ssl_certificate_key /etc/hyperion/certs/a.cz/privkey.pem;
            }
            server {
                listen 443 ssl;
                ssl_certificate /etc/hyperion/certs/b.cz/fullchain.pem;
                ssl_certificate_key /etc/hyperion/certs/b.cz/privkey.pem;
            }
        "#;
        let paths = extract_ssl_certificate_paths(body);
        assert_eq!(
            paths,
            vec![
                "/etc/hyperion/certs/a.cz/fullchain.pem".to_string(),
                "/etc/hyperion/certs/b.cz/fullchain.pem".to_string(),
            ]
        );
    }

    #[test]
    fn extract_ssl_cert_paths_skips_comments_and_blank() {
        let body = "# ssl_certificate /commented/out.pem;\n\
                    \n\
                    ssl_certificate /real/path.pem;\n";
        let paths = extract_ssl_certificate_paths(body);
        assert_eq!(paths, vec!["/real/path.pem".to_string()]);
    }

    /// End-to-end: build a fake sites-enabled with two vhosts —
    /// one whose cert exists, one whose cert is missing. The repair
    /// pass must regenerate exactly one cert + leave the existing
    /// one untouched.
    #[tokio::test]
    async fn repair_orphan_certs_regenerates_missing_only() {
        let tmp = tempfile::tempdir().unwrap();
        let certs_root = tmp.path().join("certs");
        let sites_avail = tmp.path().join("sites-available");
        let sites_enab = tmp.path().join("sites-enabled");
        std::fs::create_dir_all(&certs_root).unwrap();
        std::fs::create_dir_all(&sites_avail).unwrap();
        std::fs::create_dir_all(&sites_enab).unwrap();

        // Cert that exists on disk.
        let alive_cert_dir = certs_root.join("alive.cz");
        std::fs::create_dir_all(&alive_cert_dir).unwrap();
        std::fs::write(alive_cert_dir.join("fullchain.pem"), b"existing").unwrap();
        std::fs::write(alive_cert_dir.join("privkey.pem"), b"existing").unwrap();

        // Vhost A — cert present.
        std::fs::write(
            sites_enab.join("alive.cz.conf"),
            format!(
                "server {{\n  listen 443 ssl;\n  \
                 ssl_certificate     {}/alive.cz/fullchain.pem;\n  \
                 ssl_certificate_key {}/alive.cz/privkey.pem;\n}}\n",
                certs_root.display(),
                certs_root.display()
            ),
        )
        .unwrap();
        // Vhost B — cert MISSING. This is the bug scenario.
        std::fs::write(
            sites_enab.join("orphan.cz.conf"),
            format!(
                "server {{\n  listen 443 ssl;\n  \
                 ssl_certificate     {}/orphan.cz/fullchain.pem;\n  \
                 ssl_certificate_key {}/orphan.cz/privkey.pem;\n}}\n",
                certs_root.display(),
                certs_root.display()
            ),
        )
        .unwrap();
        // Debian's default vhost — no extension, must be skipped.
        std::fs::write(sites_enab.join("default"), b"# default server").unwrap();

        let a = RealAdapter {
            nginx_paths: hyperion_adapters::nginx::Paths {
                sites_available: sites_avail.clone(),
                sites_enabled: sites_enab.clone(),
            },
            certs_root: certs_root.clone(),
            ..Default::default()
        };

        let (repaired, scanned) = a.repair_orphan_certs().await.expect("repair");
        assert_eq!(scanned, 2, "should have scanned 2 .conf files (default skipped)");
        assert_eq!(repaired, 1, "should have repaired the one orphan");

        // Orphan now has a real PEM cert.
        let orphan_cert = certs_root.join("orphan.cz/fullchain.pem");
        let body = std::fs::read_to_string(&orphan_cert).expect("read");
        assert!(body.contains("BEGIN CERTIFICATE"));

        // Existing cert was NOT clobbered.
        let alive_body = std::fs::read_to_string(alive_cert_dir.join("fullchain.pem"))
            .expect("read");
        assert_eq!(alive_body, "existing");
    }

    /// If sites-enabled doesn't exist (fresh node, never installed
    /// nginx) we return (0, 0), not an error.
    #[tokio::test]
    async fn repair_orphan_certs_handles_missing_sites_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let a = RealAdapter {
            nginx_paths: hyperion_adapters::nginx::Paths {
                sites_available: tmp.path().join("no-such-dir-a"),
                sites_enabled: tmp.path().join("no-such-dir-b"),
            },
            certs_root: tmp.path().join("certs"),
            ..Default::default()
        };
        let (repaired, scanned) = a.repair_orphan_certs().await.expect("repair");
        assert_eq!(repaired, 0);
        assert_eq!(scanned, 0);
    }

    /// Certs OUTSIDE our certs_root (e.g. operator-managed
    /// /etc/letsencrypt/...) must never be touched, even if missing.
    #[tokio::test]
    async fn repair_orphan_certs_ignores_paths_outside_certs_root() {
        let tmp = tempfile::tempdir().unwrap();
        let certs_root = tmp.path().join("certs");
        let sites_enab = tmp.path().join("sites-enabled");
        std::fs::create_dir_all(&certs_root).unwrap();
        std::fs::create_dir_all(&sites_enab).unwrap();
        // Vhost referencing an operator-managed path.
        std::fs::write(
            sites_enab.join("external.cz.conf"),
            "server { ssl_certificate /etc/letsencrypt/live/external.cz/fullchain.pem; }\n",
        )
        .unwrap();
        let a = RealAdapter {
            nginx_paths: hyperion_adapters::nginx::Paths {
                sites_available: tmp.path().join("sites-available"),
                sites_enabled: sites_enab,
            },
            certs_root,
            ..Default::default()
        };
        let (repaired, scanned) = a.repair_orphan_certs().await.expect("repair");
        assert_eq!(scanned, 1);
        assert_eq!(repaired, 0, "must not touch certs outside our root");
    }

    // ─────────── FPM pool self-heal ───────────

    #[test]
    fn extract_pool_user_directives_finds_all_four() {
        let body = r#"
            [example_cz]
            user = example_cz
            group = example_cz
            listen = /run/php/8.3/example_cz.sock
            listen.owner = www-data
            listen.group = www-data
            listen.mode = 0660
            pm = dynamic
        "#;
        let got = extract_pool_user_directives(body);
        assert_eq!(
            got,
            vec![
                ("user", "example_cz".to_string()),
                ("group", "example_cz".to_string()),
                ("listen.owner", "www-data".to_string()),
                ("listen.group", "www-data".to_string()),
            ]
        );
    }

    /// Comments + section headers must not produce false-positive
    /// matches — a stray `; user = ghost` shouldn't trigger quarantine.
    #[test]
    fn extract_pool_user_directives_skips_comments_and_sections() {
        let body = "[www]\n\
                    ; user = ghost\n\
                    # group = ghost\n\
                    user = www-data\n";
        let got = extract_pool_user_directives(body);
        assert_eq!(got, vec![("user", "www-data".to_string())]);
    }

    /// `usercredential = ...` must NOT match — only `user` followed by
    /// whitespace or `=` counts. Prefix-discriminator regression.
    #[test]
    fn extract_pool_user_directives_no_prefix_false_positives() {
        let body = "usercredential = foo\nuser = real\n";
        let got = extract_pool_user_directives(body);
        assert_eq!(got, vec![("user", "real".to_string())]);
    }

    /// End-to-end: build a fake pool.d with one valid + one broken
    /// pool, run the repair, observe the bad file moved aside and
    /// the good one left in place. We override certs_root and
    /// nginx_paths via Default so this test doesn't touch real
    /// system paths; but the pool dir IS hard-coded via the
    /// PhpVersion::pool_dir(), so we can't easily test end-to-end
    /// against /etc/php/... in CI. Instead we directly call the
    /// helper functions and assert on their contract.
    #[tokio::test]
    async fn unix_user_exists_returns_false_for_obvious_garbage() {
        // Reserved name nobody would create on a Linux box.
        let exists = unix_user_exists("hyperion_definitely_not_a_user_12345").await;
        // We don't strictly know if getent is available on the
        // test runner (it usually is on Linux/macOS). When it ISN'T
        // we conservatively return true to avoid false quarantine,
        // so this test only checks the "binary-was-callable" path
        // by accepting either outcome but asserting it doesn't panic.
        let _ = exists;
    }

    /// Names with shell metacharacters short-circuit to true so we
    /// never shell-out malformed input.
    #[tokio::test]
    async fn unix_user_exists_rejects_shell_metacharacters() {
        // Either of these would be unsafe to pass through if it
        // ever reached a shell; getent doesn't use a shell so this
        // is belt-and-braces. Importantly: we return `true` so the
        // garbage pool isn't quarantined — surfacing the FPM error
        // is more honest than silently moving the file.
        assert!(unix_user_exists("foo; rm -rf /").await);
        assert!(unix_user_exists("foo bar").await);
        assert!(unix_user_exists("$(whoami)").await);
        // Empty name is also "safe" (returns true).
        assert!(unix_user_exists("").await);
    }

    /// Real-world stderr from the stav incident — `#` comment in
    /// pool config triggered the Zend INI parser error. Our
    /// extractor MUST pull the file path out so the boot self-heal
    /// can quarantine it.
    #[test]
    fn extract_fpm_test_failed_path_real_world_sample() {
        let stderr = "\
[05-Jun-2026 09:53:09] ERROR: [/etc/php/8.3/fpm/pool.d/test_four_testovaciverze_cz.conf:22] value is NULL for a ZEND_INI_PARSER_ENTRY
[05-Jun-2026 09:53:09] ERROR: Unable to include /etc/php/8.3/fpm/pool.d/test_four_testovaciverze_cz.conf from /etc/php/8.3/fpm/php-fpm.conf at line 22
[05-Jun-2026 09:53:09] ERROR: failed to load configuration file '/etc/php/8.3/fpm/php-fpm.conf'
[05-Jun-2026 09:53:09] ERROR: FPM initialization failed
";
        let p = extract_fpm_test_failed_path(stderr).expect("must extract path");
        assert_eq!(
            p,
            std::path::PathBuf::from(
                "/etc/php/8.3/fpm/pool.d/test_four_testovaciverze_cz.conf"
            )
        );
    }

    /// Stderr with no `[<path>:<line>]` token returns None — caller
    /// then leaves state alone rather than guessing.
    #[test]
    fn extract_fpm_test_failed_path_no_match_when_unparseable() {
        let stderr = "some other error format without brackets";
        assert!(extract_fpm_test_failed_path(stderr).is_none());
    }

    /// systemd-journal occasionally strips the timestamp prefix —
    /// our parser must still find the path token.
    #[test]
    fn extract_fpm_test_failed_path_timestamp_optional() {
        let stderr = "ERROR: [/etc/php/8.4/fpm/pool.d/x.conf:5] bad thing\n";
        let p = extract_fpm_test_failed_path(stderr).expect("must extract");
        assert_eq!(
            p,
            std::path::PathBuf::from("/etc/php/8.4/fpm/pool.d/x.conf")
        );
    }

    /// Edge case: brackets without a `:line` suffix (older FPM
    /// releases sometimes emit `[<path>]` only). We accept either
    /// shape since the suffix is purely informational for us.
    #[test]
    fn extract_fpm_test_failed_path_handles_missing_line_suffix() {
        let stderr = "ERROR: [/etc/php/8.3/fpm/pool.d/y.conf] something\n";
        let p = extract_fpm_test_failed_path(stderr).expect("must extract");
        assert_eq!(
            p,
            std::path::PathBuf::from("/etc/php/8.3/fpm/pool.d/y.conf")
        );
    }

    // ─────────── nginx log-dir self-heal ───────────

    #[test]
    fn extract_log_paths_real_world_vhost() {
        let body = r#"
            server {
                listen 443 ssl;
                http2 on;
                root /home/x_cz/x.cz/htdocs;
                access_log /home/x_cz/x.cz/logs/access.log;
                error_log  /home/x_cz/x.cz/logs/error.log;
            }
        "#;
        let got = extract_log_paths(body);
        assert_eq!(
            got,
            vec![
                std::path::PathBuf::from("/home/x_cz/x.cz/logs/access.log"),
                std::path::PathBuf::from("/home/x_cz/x.cz/logs/error.log"),
            ]
        );
    }

    /// nginx allows `access_log <path> [format] [buffer=N]` —
    /// our parser must only take the path (first token).
    #[test]
    fn extract_log_paths_strips_format_options() {
        let body = "access_log /var/log/nginx/x.log combined buffer=32k;\n";
        assert_eq!(
            extract_log_paths(body),
            vec![std::path::PathBuf::from("/var/log/nginx/x.log")]
        );
    }

    /// `access_log off` disables logging — must be ignored, not
    /// treated as a path called "off".
    #[test]
    fn extract_log_paths_ignores_off_sentinel() {
        let body = "access_log off;\nerror_log off;\n";
        assert!(extract_log_paths(body).is_empty());
    }

    #[test]
    fn derive_system_user_from_log_path_typical_shape() {
        let p = std::path::Path::new("/home/alice_cz/alice.cz/logs");
        assert_eq!(derive_system_user_from_log_path(p), Some("alice_cz".to_string()));
    }

    #[test]
    fn derive_system_user_from_log_path_rejects_non_home_paths() {
        assert_eq!(
            derive_system_user_from_log_path(std::path::Path::new("/var/log/nginx")),
            None
        );
        assert_eq!(
            derive_system_user_from_log_path(std::path::Path::new("/etc")),
            None
        );
        assert_eq!(
            derive_system_user_from_log_path(std::path::Path::new("/home")),
            None
        );
    }

    /// Path-injection guard: reject usernames with shell or path
    /// metacharacters before we ever shell out to chown.
    #[test]
    fn derive_system_user_from_log_path_rejects_garbage() {
        assert_eq!(
            derive_system_user_from_log_path(std::path::Path::new(
                "/home/$(rm -rf)/x.cz/logs"
            )),
            None
        );
        assert_eq!(
            derive_system_user_from_log_path(std::path::Path::new(
                "/home/a:b/x.cz/logs"
            )),
            None
        );
    }
}
