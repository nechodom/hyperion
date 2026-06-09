//! `HostingService` — the orchestrator. Single-node, no transport.

use async_trait::async_trait;
use hyperion_adapters::rollback::{Rollback, RollbackStack};
use hyperion_adapters::AdapterError;
use hyperion_rpc::wire::{
    DbCredentials, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
};
use hyperion_rpc::RpcError;
use hyperion_state::{
    certificates, databases, hostings, metrics, profiles, system_users, wordpress,
};
use hyperion_types::{
    now_secs, CertInfo, CertIssueRequest, CertRenewOutcome, CertRenewResult, ClusterStats,
    DashboardAlert, DbProvision, DbSummary, DnsCheckResult, HostingDetail, HostingId,
    HostingProfile, HostingState, HostingStats, HostingSummary, NodeStats, PhpVersion,
    ProfileApply, ProfileInput, SecretId, WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::{Domain, SystemUserName};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;

/// External-effects boundary for `HostingService`.
///
/// In production this is implemented by a thin wrapper around `hyperion-adapters`.
/// In tests we use `MockAdapterPort` via `mockall::automock`.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AdapterPort: Send + Sync {
    /// User nginx workers run as (detected at agent startup).
    /// Default impl returns "www-data" so MockAdapterPort tests
    /// don't need to override.
    fn nginx_user(&self) -> String {
        "www-data".to_string()
    }

    /// Whether `redis-server` is installed + active right now.
    /// Default impl returns true so tests don't need to override
    /// (mocked adapters don't have systemd). Real adapter hits
    /// `systemctl is-active redis-server`. Used by set_redis as a
    /// preflight so a clear error appears before we'd otherwise
    /// fail at the ACL-write step.
    async fn redis_is_available(&self) -> bool {
        true
    }

    async fn ensure_user(&self, name: &str, home_dir: &str) -> Result<u32, AdapterError>;
    async fn delete_user(&self, name: &str) -> Result<(), AdapterError>;
    async fn ensure_dirs(
        &self,
        htdocs: &str,
        logs: &str,
        tmp: &str,
        owner_uid: u32,
    ) -> Result<(), AdapterError>;
    async fn remove_hosting_tree(&self, root: &str) -> Result<(), AdapterError>;

    async fn fpm_ensure(
        &self,
        system_user: &str,
        domain: &str,
        version: PhpVersion,
    ) -> Result<(), AdapterError>;
    async fn fpm_delete(&self, system_user: &str, version: PhpVersion) -> Result<(), AdapterError>;

    async fn db_create(
        &self,
        engine: DbProvision,
        hosting_id: &HostingId,
        domain: &str,
    ) -> Result<DbCredentials, AdapterError>;
    async fn db_drop(
        &self,
        engine: DbProvision,
        db_name: &str,
        db_user: &str,
    ) -> Result<(), AdapterError>;

    async fn acme_issue(&self, domain: &str, sans: &[String]) -> Result<CertInfo, AdapterError>;
    async fn acme_delete(&self, domain: &str) -> Result<(), AdapterError>;

    /// Walk every enabled nginx vhost on this node, parse out the
    /// `ssl_certificate` paths, and for each path that doesn't exist
    /// on disk generate a self-signed bootstrap so `nginx -t` passes.
    ///
    /// Why this exists: a single vhost referencing a missing cert
    /// bricks the ENTIRE nginx process — `nginx -t` rejects the whole
    /// config, every reload fails, no other hosting can be touched
    /// until the cert is restored. Possible causes: operator manually
    /// rm'd /etc/hyperion/certs/<domain>, partial failure from an
    /// older agent build without the per-vhost self-heal, restore
    /// from a backup that excluded /etc/hyperion. This sweep is the
    /// belt-and-braces fix that runs at agent boot.
    ///
    /// Returns (repaired, scanned) so the caller can log a useful
    /// number — `(0, N)` means "checked N vhosts, all fine".
    ///
    /// Default impl returns (0, 0) so MockAdapterPort tests don't
    /// have to override.
    async fn repair_orphan_certs(&self) -> Result<(usize, usize), AdapterError> {
        Ok((0, 0))
    }

    /// Walk every enabled nginx vhost on this node, parse out the
    /// `access_log` / `error_log` paths, and mkdir -p the parent
    /// directory for each path that doesn't exist. A vhost
    /// referencing a non-existent log dir makes `nginx -t` exit 1
    /// with `[emerg] open() ".../access.log" failed (2: No such
    /// file or directory)` — which bricks ALL nginx reloads the
    /// same way the missing-cert bug did. Returns (created,
    /// scanned). Default impl returns (0, 0).
    async fn ensure_vhost_log_dirs(&self) -> Result<(usize, usize), AdapterError> {
        Ok((0, 0))
    }

    /// Walk every PHP-FPM pool file on this node, parse out the
    /// `user`, `group`, `listen.owner`, `listen.group` directives,
    /// and quarantine pools whose referenced Unix user doesn't
    /// exist on the system. A single bad pool brings DOWN the
    /// whole php<ver>-fpm service (FPM exits 78 EX_CONFIG and
    /// systemd gives up after 5 retries) — quarantining lets the
    /// service start and surface the issue without burying every
    /// other hosting on the same PHP version.
    ///
    /// "Quarantine" = rename `<pool>.conf` → `<pool>.conf.hyperion-
    /// quarantined-<unix-ts>`. FPM only loads `*.conf`, so the
    /// renamed file is ignored at next reload; the operator can
    /// inspect or recover it manually.
    ///
    /// Returns `(quarantined, scanned)` so the boot path can log
    /// a useful number and trigger an FPM reload only when there
    /// was actual work. Default impl returns (0, 0).
    async fn repair_orphan_fpm_pools(&self) -> Result<(usize, usize), AdapterError> {
        Ok((0, 0))
    }

    /// `systemctl reload nginx` with self-heal (auto-promotes to
    /// `start` if nginx is not running). Used by the boot-time
    /// orphan-cert sweep to recover the live process after a repair.
    /// Default impl is a no-op (mocks don't manage systemd).
    async fn nginx_reload(&self) -> Result<(), AdapterError> {
        Ok(())
    }

    /// `systemctl restart php<ver>-fpm` for one version, with
    /// "not active → start" self-heal. Used by the boot-time
    /// FPM-pool repair to recover after quarantining a broken
    /// pool. Default impl is a no-op.
    async fn fpm_restart(&self, _version: PhpVersion) -> Result<(), AdapterError> {
        Ok(())
    }

    /// Walk every installed php<ver>-fpm service and recover any
    /// that's in systemd "failed" state. Runs unconditionally at
    /// boot — when an OLD broken pool brought FPM down hard
    /// (restart counter at 5), even after the operator fixes the
    /// pool file systemd refuses to start without `reset-failed`.
    /// Returns the count of services we kicked back up.
    /// Default impl returns 0.
    async fn fpm_recover_failed(&self) -> Result<usize, AdapterError> {
        Ok(0)
    }

    async fn nginx_write_vhost(&self, detail: &HostingDetail) -> Result<(), AdapterError>;
    /// Remove vhost + symlink for this domain. When `hosting_id` is
    /// supplied the adapter also drops the per-hosting cache zone +
    /// htpasswd sidecars so they don't survive into a future hosting
    /// reusing the id slot.
    async fn nginx_delete_vhost(
        &self,
        domain: &str,
        hosting_id: Option<String>,
    ) -> Result<(), AdapterError>;
    /// Write the per-hosting basic-auth htpasswd file. Bcrypt hash
    /// only (nginx supports it natively, so we don't need apache's
    /// htpasswd binary installed).
    async fn nginx_write_htpasswd(
        &self,
        hosting_id: &str,
        user: &str,
        bcrypt_hash: &str,
    ) -> Result<(), AdapterError>;
    /// Drop the htpasswd file (operator turned basic auth off).
    async fn nginx_delete_htpasswd(&self, hosting_id: &str) -> Result<(), AdapterError>;
    async fn nginx_apply_suspended(
        &self,
        domain: &str,
        reason_message: Option<String>,
    ) -> Result<(), AdapterError>;

    /// Apply per-pool PHP limits (memory, max_children, …). No-op if hosting
    /// has no PHP-FPM pool (static site).
    async fn apply_php_limits(
        &self,
        system_user: &str,
        domain: &str,
        version: Option<PhpVersion>,
        php_memory_mb: i64,
        php_max_exec_secs: i64,
        php_max_children: i64,
        php_max_requests: i64,
    ) -> Result<(), AdapterError>;

    /// Lock the DB user/role so the hosting cannot reach its database.
    async fn db_lock(&self, engine: DbProvision, db_user: &str) -> Result<(), AdapterError>;
    async fn db_unlock(&self, engine: DbProvision, db_user: &str) -> Result<(), AdapterError>;

    /// `usermod -L` / `-U` and shell swap to /usr/sbin/nologin.
    async fn linux_lock_login(&self, name: &str) -> Result<(), AdapterError>;
    async fn linux_unlock_login(&self, name: &str) -> Result<(), AdapterError>;

    /// `pkill -KILL -u <name>` to kill any process owned by the suspended user.
    async fn kill_user_procs(&self, name: &str) -> Result<(), AdapterError>;

    /// Run wp-cli's full install pipeline (download → config create →
    /// core install) under `system_user` against the hosting's existing
    /// MariaDB. Returns the installed core version string.
    #[allow(clippy::too_many_arguments)]
    async fn wp_install_run(
        &self,
        system_user: &str,
        htdocs: &str,
        db_name: &str,
        db_user: &str,
        db_password: &str,
        db_host: &str,
        req: &WpInstallRequest,
    ) -> Result<String, AdapterError>;

    /// List installed WP plugins for `htdocs` under `system_user`.
    /// Returns the plugin table + parsed wp-version, ready for
    /// `WpPluginListResponse` after the service adds bulk-auto-update
    /// from `wp_installs`.
    async fn wp_plugin_list(
        &self,
        system_user: &str,
        htdocs: &str,
    ) -> Result<(Vec<hyperion_types::WpPlugin>, String), AdapterError>;

    /// Apply one whitelisted plugin action via wp-cli. `slug` is the
    /// plugin folder name (or empty for `UpdateAll`). Returns the
    /// stdout/stderr tail so the UI can show what happened.
    async fn wp_plugin_action(
        &self,
        system_user: &str,
        htdocs: &str,
        slug: &str,
        action: &hyperion_types::WpPluginAction,
    ) -> Result<hyperion_types::WpPluginActionResult, AdapterError>;

    /// Install a plugin or theme via wp-cli, with `source` either a
    /// wordpress.org slug or a local ZIP path. `kind` ∈ {"plugin",
    /// "theme"}. Used by profile-apply's wp-items installer.
    async fn wp_cli(
        &self,
        system_user: &str,
        htdocs: &str,
        kind: &str,
        source: &str,
        activate: bool,
    ) -> Result<(), AdapterError>;

    /// `wp theme list --format=json` — parallel to wp_plugin_list.
    /// Returns the theme table + the core version string.
    async fn wp_theme_list(
        &self,
        system_user: &str,
        htdocs: &str,
    ) -> Result<(Vec<hyperion_types::WpTheme>, String), AdapterError>;

    /// One whitelisted theme action via wp-cli. Same shape as
    /// wp_plugin_action.
    async fn wp_theme_action(
        &self,
        system_user: &str,
        htdocs: &str,
        slug: &str,
        action: &hyperion_types::WpThemeAction,
    ) -> Result<hyperion_types::WpThemeActionResult, AdapterError>;

    /// Apply WP_DEBUG + WP_DEBUG_LOG + WP_DEBUG_DISPLAY to wp-config.php.
    /// When `enabled` is false, the constants are deleted (not set to
    /// false — see WpExtras docstring).
    async fn wp_set_debug(
        &self,
        system_user: &str,
        htdocs: &str,
        enabled: bool,
        log: bool,
        display: bool,
    ) -> Result<(), AdapterError>;

    /// Apply WP_REDIS_* constants to wp-config.php. When `cfg` is
    /// None, the constants are deleted.
    async fn wp_set_redis(
        &self,
        system_user: &str,
        htdocs: &str,
        cfg: Option<hyperion_types::WpRedisConfig>,
    ) -> Result<(), AdapterError>;

    /// Read the size of wp-content/debug.log in bytes (0 if missing).
    /// Used by the agent tick to refresh `wp_debug_log_size_bytes`.
    async fn wp_debug_log_size(
        &self,
        htdocs: &str,
    ) -> Result<i64, AdapterError>;

    /// Provision a per-hosting Redis ACL user. Idempotent — re-running
    /// with the same username + new password rotates the password.
    /// Returns Ok on success regardless of whether the user existed.
    async fn redis_ensure_acl(
        &self,
        username: &str,
        password: &str,
        db_number: i64,
    ) -> Result<(), AdapterError>;

    /// Delete a per-hosting Redis ACL user. Idempotent — Ok if absent.
    async fn redis_delete_acl(&self, username: &str) -> Result<(), AdapterError>;
}

#[derive(Clone)]
pub struct HostingService<A: AdapterPort + 'static> {
    pub pool: SqlitePool,
    pub adapters: Arc<A>,
    pub secrets: Arc<crate::SecretsStore>,
    pub paths: HostingPaths,
    pub remote_backup: Option<RemoteBackupConfig>,
    pub retention: BackupRetention,
    /// Cluster-wide default Slack webhook for notifications.
    /// Per-profile webhooks override this.
    pub slack_default_webhook: Option<String>,
    /// Contact email used as the ACME account address. Let's Encrypt
    /// refuses common placeholder domains (example.com, etc.), so the
    /// operator MUST set a real one in agent.toml.
    pub acme_contact_email: String,
    /// Optional SMTP relay for transactional email. None = email
    /// notifications are skipped (Slack still fires if configured).
    pub email_config: Option<hyperion_adapters::email::EmailConfig>,
    /// Default operator address for cluster-wide notifications.
    pub email_default_to: Option<String>,
    /// Path to agent.toml on disk, for the per-section settings editor.
    /// None disables UI-driven config writes (operator hand-edits only).
    pub agent_config_path: Option<std::path::PathBuf>,
    /// In-memory cache of the last upstream `rolling` release check.
    /// Shared across `HostingService` clones so every RPC sees the
    /// same answer. Re-probed every `UPDATE_CHECK_TTL_SECS`.
    pub update_cache: Arc<tokio::sync::RwLock<Option<hyperion_types::UpdateStatus>>>,
    /// Compile-time git SHA of the running binary — set via build.rs
    /// in `bin/hyperion-agent`. Used by `update_check` to compare
    /// against the upstream rolling release.
    pub current_git_sha: String,
    /// Per-domain mutex map used to serialize cert issuance + renewal
    /// per domain. Two parallel "Issue Cert" clicks on the same
    /// hosting (or a renewal racing a manual issuance) would otherwise
    /// write cert + key from different ACME runs, leaving nginx
    /// serving a fullchain.pem whose public key doesn't match the
    /// privkey.pem.
    pub cert_issue_locks: Arc<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Ed25519 signing key for master→node remote RPC. `Some` on
    /// masters where /etc/hyperion/master-rpc.key was successfully
    /// loaded or auto-generated; `None` on workers, or on masters
    /// where key init failed (logged, remote RPC disabled).
    ///
    /// The PUBLIC half is piggy-backed in enrollment and heartbeat
    /// responses so every node ends up holding it; the PRIVATE half
    /// is only ever held by the master and used to sign outbound
    /// remote-RPC requests.
    pub master_rpc_signer: Option<Arc<crate::master_rpc::MasterRpcSigner>>,
    /// Path to the node-id state file (typically
    /// `/etc/hyperion/node-id.json`). Used as a "is this node a
    /// worker?" tell — workers have the file (written at enrollment),
    /// masters don't. services_health() uses this to decide whether
    /// hyperion-web should be flagged as a critical service.
    /// `None` means "treat as master" (no file to check).
    pub node_state_file: Option<std::path::PathBuf>,
    /// In-memory state of the most-recent / in-progress node
    /// update job. Polled via `NodeUpdateStatus` so the operator
    /// can watch apt-get / update.sh progress without ssh-ing in.
    /// A single shared slot per agent — concurrent updates are
    /// refused with a "another update is already running" error.
    pub node_update: Arc<tokio::sync::Mutex<hyperion_types::NodeUpdateStatus>>,
    /// In-memory state of the most-recent / in-progress
    /// service-install job (apt-get install + systemctl enable
    /// for a whitelisted unit like php8.4-fpm). Polled via
    /// `ServiceInstallStatus`. Single slot — apt would dpkg-lock
    /// concurrent jobs anyway.
    pub service_install_progress:
        Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
}

/// Default renewal window — matches Let's Encrypt's recommended
/// 30-day buffer before `not_after`. Operators override via
/// `[acme] renewal_window_days` in agent.toml.
pub const CERT_RENEWAL_WINDOW_DAYS: i64 = 30;

/// Cache TTL for the GitHub release check. One hour is enough to
/// keep the dashboard banner fresh without hammering the API or
/// hitting their unauthenticated rate limit (60 req/hour/IP).
pub const UPDATE_CHECK_TTL_SECS: i64 = 3600;

/// Outcome of `check_spf_authorizes` — how (or whether) the SPF
/// record authorizes our public IP.
#[derive(Debug, Clone)]
enum SpfMatch {
    /// A specific mechanism matched our IP (e.g. "ip4:1.2.3.4").
    Match { mechanism: String },
    /// The record ends in `+all` or `?all` — pass anything.
    CatchAll { mechanism: String },
    /// No public IPv4 was discoverable for the agent, so we can't
    /// decide. Surfaces as "differs" upstream with a clarifying
    /// reason.
    NoIp,
    /// The record exists but doesn't authorize us.
    None,
}

/// Decide whether an SPF record authorizes `our_ip`. Implements the
/// `ip4` / `ip6` / `a` / `mx` / `include` / `redirect` / `+all` /
/// `?all` mechanisms — enough to cover the common cases an operator
/// sets up by hand. Doesn't fully implement RFC 7208 (no `exists:`,
/// no recursion past one `include:`), but the failure mode is
/// always conservative: we say "differs" when in doubt, never
/// "matches" wrongly.
async fn check_spf_authorizes(
    record: &str,
    domain: &str,
    our_ip: Option<&str>,
) -> SpfMatch {
    let our_ip_parsed = match our_ip.and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()) {
        Some(ip) => ip,
        None => return SpfMatch::NoIp,
    };

    // Tokenize — SPF mechanisms are whitespace-separated. Drop the
    // leading version tag.
    let mut tokens: Vec<&str> = record.split_whitespace().collect();
    if tokens.first().map(|s| s.to_ascii_lowercase()) != Some("v=spf1".into()) {
        return SpfMatch::None;
    }
    tokens.remove(0);

    // First pass — scan for `redirect=`. If present, replace the
    // whole evaluation with the redirect target's SPF (one level
    // only — recursion would need a depth counter and we'd rather
    // refuse complexity than infinite-loop).
    for tok in &tokens {
        if let Some(target) = tok.strip_prefix("redirect=") {
            return check_spf_redirect(target, our_ip_parsed).await;
        }
    }

    for tok in &tokens {
        // Strip the qualifier prefix; we treat +/?/~/- the same for
        // pass detection — only `-` (Fail) would actively REJECT us,
        // but we don't model that since the operator's question is
        // "does my IP pass" not "would a strict receiver bounce".
        let tok_l = tok.to_ascii_lowercase();
        let (qualifier, mech) = match tok_l.chars().next() {
            Some('+') | Some('-') | Some('~') | Some('?') => {
                let q = tok_l.chars().next().unwrap();
                (q, &tok_l[1..])
            }
            _ => ('+', tok_l.as_str()),
        };

        // Catch-all — `+all` or `?all` count as match-everything.
        // `~all` (softfail) and `-all` (fail) do not — those mean
        // "anyone NOT explicitly listed above is unauthorized".
        if mech == "all" {
            if qualifier == '+' || qualifier == '?' {
                return SpfMatch::CatchAll {
                    mechanism: tok.to_string(),
                };
            }
            continue;
        }

        // ip4:<addr> or ip4:<addr>/<prefix>
        if let Some(rest) = mech.strip_prefix("ip4:") {
            if ip4_matches(rest, our_ip_parsed) {
                return SpfMatch::Match {
                    mechanism: format!("ip4:{}", rest),
                };
            }
            continue;
        }

        // a / a:<domain> / a/<prefix> — resolve A records and check.
        if mech == "a" || mech.starts_with("a:") || mech.starts_with("a/") {
            let lookup_domain = if let Some(rest) = mech.strip_prefix("a:") {
                rest.split('/').next().unwrap_or(domain)
            } else {
                domain
            };
            for ip_str in dig_records(lookup_domain, "A").await.unwrap_or_default() {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    if ip == our_ip_parsed {
                        return SpfMatch::Match {
                            mechanism: format!("a ({lookup_domain})"),
                        };
                    }
                }
            }
            continue;
        }

        // mx / mx:<domain> — resolve MX targets, then their A
        // records.
        if mech == "mx" || mech.starts_with("mx:") || mech.starts_with("mx/") {
            let lookup_domain = if let Some(rest) = mech.strip_prefix("mx:") {
                rest.split('/').next().unwrap_or(domain)
            } else {
                domain
            };
            let mx_targets = dig_records(lookup_domain, "MX").await.unwrap_or_default();
            for line in mx_targets {
                // dig MX output: "10 mail.example.com." — strip
                // priority + trailing dot.
                let target = line
                    .split_whitespace()
                    .last()
                    .map(|s| s.trim_end_matches('.'))
                    .unwrap_or("");
                if target.is_empty() {
                    continue;
                }
                for ip_str in dig_records(target, "A").await.unwrap_or_default() {
                    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                        if ip == our_ip_parsed {
                            return SpfMatch::Match {
                                mechanism: format!("mx ({target})"),
                            };
                        }
                    }
                }
            }
            continue;
        }

        // include:<domain> — fetch the included domain's SPF and
        // evaluate it for our IP (one level of recursion only).
        if let Some(target) = mech.strip_prefix("include:") {
            if let SpfMatch::Match { mechanism } = check_spf_include(target, our_ip_parsed).await {
                return SpfMatch::Match {
                    mechanism: format!("include:{target} → {mechanism}"),
                };
            }
            if let SpfMatch::CatchAll { mechanism } =
                check_spf_include(target, our_ip_parsed).await
            {
                return SpfMatch::CatchAll {
                    mechanism: format!("include:{target} → {mechanism}"),
                };
            }
            continue;
        }
        // ip6:, ptr:, exists: — not implemented; skip silently.
    }
    SpfMatch::None
}

/// Resolve `target`'s SPF and evaluate it for `our_ip`. One level
/// only — `include` of an `include` is treated as no-match to avoid
/// pathological chains (Office365 / Google Workspace alone have
/// 3-4 levels deep, which is exactly what burns SPF's 10-DNS-lookup
/// budget at receive time — we surface it as "not matched" so the
/// operator notices and adds their IP directly).
fn check_spf_include<'a>(
    target: &'a str,
    our_ip: std::net::Ipv4Addr,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = SpfMatch> + Send + 'a>> {
    Box::pin(async move {
        let txts = dig_records(target, "TXT").await.unwrap_or_default();
        for raw in txts {
            let stitched = stitch_dig_txt(&raw);
            if stitched.to_ascii_lowercase().starts_with("v=spf1") {
                // Pass false_to_string() so the redirect path doesn't
                // recursively await on Future<Future> — we resolve
                // one level synchronously below.
                return check_spf_authorizes_no_recurse(&stitched, target, our_ip).await;
            }
        }
        SpfMatch::None
    })
}

/// Same as `check_spf_redirect`, but cap recursion explicitly at the
/// caller (we only call into this from the top-level evaluator).
async fn check_spf_redirect(target: &str, our_ip: std::net::Ipv4Addr) -> SpfMatch {
    let txts = dig_records(target, "TXT").await.unwrap_or_default();
    for raw in txts {
        let stitched = stitch_dig_txt(&raw);
        if stitched.to_ascii_lowercase().starts_with("v=spf1") {
            return check_spf_authorizes_no_recurse(&stitched, target, our_ip).await;
        }
    }
    SpfMatch::None
}

/// Single-pass SPF eval that does NOT chase further `include:` /
/// `redirect=` references. Used by include/redirect handlers to
/// bound the recursion.
async fn check_spf_authorizes_no_recurse(
    record: &str,
    domain: &str,
    our_ip: std::net::Ipv4Addr,
) -> SpfMatch {
    let mut tokens: Vec<&str> = record.split_whitespace().collect();
    if tokens.first().map(|s| s.to_ascii_lowercase()) != Some("v=spf1".into()) {
        return SpfMatch::None;
    }
    tokens.remove(0);
    for tok in &tokens {
        let tok_l = tok.to_ascii_lowercase();
        let (qualifier, mech) = match tok_l.chars().next() {
            Some('+') | Some('-') | Some('~') | Some('?') => {
                let q = tok_l.chars().next().unwrap();
                (q, &tok_l[1..])
            }
            _ => ('+', tok_l.as_str()),
        };
        if mech == "all" {
            if qualifier == '+' || qualifier == '?' {
                return SpfMatch::CatchAll { mechanism: tok.to_string() };
            }
            continue;
        }
        if let Some(rest) = mech.strip_prefix("ip4:") {
            if ip4_matches(rest, our_ip) {
                return SpfMatch::Match { mechanism: format!("ip4:{rest}") };
            }
            continue;
        }
        if mech == "a" || mech.starts_with("a:") {
            let lookup = mech.strip_prefix("a:").unwrap_or(domain);
            for ip_str in dig_records(lookup, "A").await.unwrap_or_default() {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    if ip == our_ip {
                        return SpfMatch::Match { mechanism: format!("a ({lookup})") };
                    }
                }
            }
            continue;
        }
        // include: inside an include is not resolved.
    }
    SpfMatch::None
}

/// Check whether `spec` (an `ip4:` value — either bare IPv4 or
/// `IPv4/prefix`) covers `ip`. Returns false on malformed input.
fn ip4_matches(spec: &str, ip: std::net::Ipv4Addr) -> bool {
    if let Some((addr, prefix_s)) = spec.split_once('/') {
        let Ok(net_ip) = addr.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        let Ok(prefix) = prefix_s.parse::<u8>() else {
            return false;
        };
        if prefix > 32 {
            return false;
        }
        if prefix == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - prefix);
        let net_u = u32::from(net_ip) & mask;
        let ip_u = u32::from(ip) & mask;
        net_u == ip_u
    } else {
        spec.parse::<std::net::Ipv4Addr>()
            .map(|a| a == ip)
            .unwrap_or(false)
    }
}

/// `dig +short TXT` returns each TXT record on one line, with each
/// 255-char-or-less string segment in its own quoted block:
///
///   "v=spf1 ip4:1.2.3.4 " "ip4:5.6.7.8 ~all"
///
/// Stitch those segments back into a single string. Drops the
/// quotes, joins consecutive segments with no separator (per RFC
/// 7208 §3.3 — TXT continuation strings are concatenated as-is).
fn stitch_dig_txt(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_quote = false;
    for c in raw.chars() {
        if c == '"' {
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            out.push(c);
        }
    }
    // If the raw line had no quotes at all (older dig versions),
    // just trim it.
    if out.is_empty() {
        return raw.trim().to_string();
    }
    out
}

/// Stream-download a URL to disk via curl. Returns Ok on HTTP 2xx,
/// Err with a useful message otherwise. Used by the migration
/// import-from-url path; cheap to call because curl is already a
/// hard dependency of the installer.
/// On-disk path of an uploaded WP asset's ZIP file. Mirrors the
/// layout `wp_asset_upload` writes — `/var/lib/hyperion/wp-assets/<id>/<filename>`.
fn wp_asset_disk_path(id: i64, stored_filename: &str) -> String {
    format!("/var/lib/hyperion/wp-assets/{id}/{stored_filename}")
}

/// Count `@asset:<id>` references for a given asset id across all
/// profiles' wp_plugins + wp_themes text fields. Uses substring
/// search rather than a regex because the syntax is narrow
/// (`@asset:<digits>` with optional trailing `!`) and the
/// substring + boundary check is faster + dependency-free.
fn count_profile_asset_refs(
    profiles: &[hyperion_state::profiles::ProfileRow],
    asset_id: i64,
) -> i64 {
    let needle = format!("@asset:{asset_id}");
    let needle_len = needle.len();
    let mut count: i64 = 0;
    for p in profiles {
        for text in [&p.wp_plugins, &p.wp_themes] {
            for line in text.lines() {
                let stripped = line.trim();
                if let Some(pos) = stripped.find(&needle) {
                    // Boundary check: next char (if any) must be one
                    // of: end-of-string, '!', whitespace, or '#'.
                    // Otherwise `@asset:7` would match @asset:70.
                    let after = stripped[pos + needle_len..]
                        .chars()
                        .next();
                    let ok = match after {
                        None => true,
                        Some(c) => c == '!' || c.is_whitespace() || c == '#',
                    };
                    if ok {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}


/// Drive a service-install job (apt-get install + systemctl
/// enable --now) and stream output into the shared status slot.
///
/// Notable changes vs. the old synchronous service_install path:
///   - Drops `-qq` from apt-get so we actually see the real
///     diagnostic. The old "dpkg returned an error code (1)"
///     bubble-up was useless — the actual cause (postinst script
///     failure, missing dep, etc.) was suppressed.
///   - Uses `-q -o Dpkg::Options::=--force-confold` so apt is
///     non-interactive but still emits status lines.
///   - Streams stdout/stderr line-by-line into log_tail (capped
///     at ~8 kB) so the UI can show live progress instead of
///     hanging the operator's browser for minutes.
async fn run_service_install(
    slot: std::sync::Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
    service_name: String,
    pkg: String,
) {
    use tokio::io::AsyncBufReadExt;
    const LOG_TAIL_BYTES: usize = 8 * 1024;

    async fn append_line(
        slot: &std::sync::Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
        line: &str,
    ) {
        let mut g = slot.lock().await;
        g.log_tail.push_str(line);
        g.log_tail.push('\n');
        if g.log_tail.len() > LOG_TAIL_BYTES {
            let drop = g.log_tail.len() - LOG_TAIL_BYTES;
            let mut cut = drop;
            while !g.log_tail.is_char_boundary(cut) && cut < g.log_tail.len() {
                cut += 1;
            }
            g.log_tail.drain(..cut);
        }
    }

    async fn run_one(
        slot: &std::sync::Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
        label: &str,
        cmd: &str,
        args: &[&str],
    ) -> i32 {
        append_line(slot, &format!("──── {label}: {cmd} {} ────", args.join(" "))).await;
        let mut child = match tokio::process::Command::new(cmd)
            .args(args)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                append_line(slot, &format!("spawn {cmd} failed: {e}")).await;
                return 127;
            }
        };
        if let Some(stdout) = child.stdout.take() {
            let s = slot.clone();
            let label = label.to_string();
            tokio::spawn(async move {
                let r = tokio::io::BufReader::new(stdout);
                let mut lines = r.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    append_line(&s, &format!("[{label}] {line}")).await;
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let s = slot.clone();
            let label = label.to_string();
            tokio::spawn(async move {
                let r = tokio::io::BufReader::new(stderr);
                let mut lines = r.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    append_line(&s, &format!("[{label}!] {line}")).await;
                }
            });
        }
        match child.wait().await {
            Ok(status) => status.code().unwrap_or(-1),
            Err(e) => {
                append_line(slot, &format!("wait {label} failed: {e}")).await;
                -1
            }
        }
    }

    // Per-package debconf preseeding — without this, packages with
    // interactive postinst questions (postfix's "type of mail server",
    // "mailname", iptables-persistent, mariadb-server root password,
    // etc.) hang forever even with DEBIAN_FRONTEND=noninteractive
    // because the question is mandatory.
    if pkg == "postfix" {
        // Internet Site = direct MX delivery. Same default as
        // update.sh's MTA install block. Operators on networks
        // where outbound TCP/25 is blocked can switch to smart-host
        // mode manually after install (postconf -e relayhost=...).
        let mailname = match tokio::process::Command::new("/bin/hostname")
            .arg("-f")
            .output()
            .await
        {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    "localhost".to_string()
                } else {
                    s
                }
            }
            _ => "localhost".to_string(),
        };
        let selections = format!(
            "postfix postfix/main_mailer_type select Internet Site\n\
             postfix postfix/mailname string {mailname}\n",
        );
        // Pipe selections via stdin to debconf-set-selections. The
        // child process exits 0 even if input is malformed (it just
        // doesn't apply), so we treat any non-zero as a real spawn
        // failure rather than a config problem.
        let mut child = match tokio::process::Command::new("/usr/bin/debconf-set-selections")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                append_line(
                    &slot,
                    &format!("debconf-set-selections spawn failed: {e}"),
                )
                .await;
                let mut g = slot.lock().await;
                g.state = "failed".to_string();
                g.finished_at = now_secs();
                g.exit_code = 127;
                return;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(selections.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }
        let _ = child.wait().await;
        append_line(
            &slot,
            &format!("──── preseeded postfix: Internet Site, mailname={mailname} ────"),
        )
        .await;
    }

    // Step 1: apt-get install. Hard-cap at 10 min via timeout above
    // (tokio::spawn'd, so we wrap with timeout here).
    let install_code = tokio::time::timeout(
        std::time::Duration::from_secs(10 * 60),
        run_one(
            &slot,
            "apt-install",
            "/usr/bin/apt-get",
            &[
                "install",
                "-y",
                "-q",
                "-o",
                "Dpkg::Options::=--force-confold",
                &pkg,
            ],
        ),
    )
    .await
    .unwrap_or_else(|_| {
        // The timeout fired — log it and treat as failure.
        let s = slot.clone();
        let _ = tokio::spawn(async move {
            append_line(
                &s,
                "apt-install timed out after 10 min — check dpkg lock or mirror outage",
            )
            .await;
        });
        124 // GNU `timeout`-style exit code
    });

    let mut final_code = install_code;

    // Step 2: systemctl enable --now (only if install succeeded).
    if install_code == 0 {
        final_code = run_one(
            &slot,
            "systemctl-enable",
            "/usr/bin/systemctl",
            &["enable", "--now", &service_name],
        )
        .await;
    }

    let final_state = if final_code == 0 { "succeeded" } else { "failed" };
    let mut g = slot.lock().await;
    g.state = final_state.to_string();
    g.finished_at = now_secs();
    g.exit_code = final_code;
    tracing::info!(
        service = %service_name,
        pkg = %pkg,
        exit_code = final_code,
        state = final_state,
        "service install job finished"
    );
}

/// Drive a node-update job: run `apt-get upgrade -y` and/or the
/// hyperion `update.sh` script, streaming combined stdout+stderr
/// into the given shared status slot. Caller has already marked
/// the slot as `state="running"`. We update `log_tail` (capped at
/// ~8 kB) as output arrives so the UI polling sees live progress.
///
/// Failure of either step sets `state="failed"`; both ok sets
/// `state="succeeded"`. Exit code is the last failing step's code,
/// or 0.
async fn run_update_script(
    slot: std::sync::Arc<tokio::sync::Mutex<hyperion_types::NodeUpdateStatus>>,
    do_apt: bool,
    do_hyperion: bool,
) {
    use tokio::io::AsyncBufReadExt;
    /// Roughly 8 kB of tail — enough to see what's currently
    /// happening without ballooning agent memory if some step
    /// emits megabytes of output.
    const LOG_TAIL_BYTES: usize = 8 * 1024;

    async fn append_line(
        slot: &std::sync::Arc<tokio::sync::Mutex<hyperion_types::NodeUpdateStatus>>,
        line: &str,
    ) {
        let mut g = slot.lock().await;
        g.log_tail.push_str(line);
        g.log_tail.push('\n');
        if g.log_tail.len() > LOG_TAIL_BYTES {
            // Drop oldest data — find a char boundary above the
            // overrun.
            let drop = g.log_tail.len() - LOG_TAIL_BYTES;
            let mut cut = drop;
            while !g.log_tail.is_char_boundary(cut) && cut < g.log_tail.len() {
                cut += 1;
            }
            g.log_tail.drain(..cut);
        }
    }

    async fn run_one(
        slot: &std::sync::Arc<tokio::sync::Mutex<hyperion_types::NodeUpdateStatus>>,
        label: &str,
        cmd: &str,
        args: &[&str],
    ) -> i32 {
        append_line(slot, &format!("\n──── {label}: {cmd} {} ────", args.join(" "))).await;
        let mut child = match tokio::process::Command::new(cmd)
            .args(args)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                append_line(slot, &format!("spawn {cmd} failed: {e}")).await;
                return 127;
            }
        };
        if let Some(stdout) = child.stdout.take() {
            let s = slot.clone();
            let label = label.to_string();
            tokio::spawn(async move {
                let r = tokio::io::BufReader::new(stdout);
                let mut lines = r.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    append_line(&s, &format!("[{label}] {line}")).await;
                }
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let s = slot.clone();
            let label = label.to_string();
            tokio::spawn(async move {
                let r = tokio::io::BufReader::new(stderr);
                let mut lines = r.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    append_line(&s, &format!("[{label}!] {line}")).await;
                }
            });
        }
        match child.wait().await {
            Ok(status) => status.code().unwrap_or(-1),
            Err(e) => {
                append_line(slot, &format!("wait {label} failed: {e}")).await;
                -1
            }
        }
    }

    let mut last_code: i32 = 0;

    if do_apt {
        let upd = run_one(&slot, "apt-update", "/usr/bin/apt-get", &["update", "-qq"]).await;
        if upd == 0 {
            last_code = run_one(
                &slot,
                "apt-upgrade",
                "/usr/bin/apt-get",
                &[
                    "dist-upgrade",
                    "-y",
                    "-qq",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                ],
            )
            .await;
        } else {
            last_code = upd;
        }
    }

    if do_hyperion && last_code == 0 {
        // update.sh path is hardcoded — install-master.sh and
        // install-node.sh both drop it here. Bail with a clear log
        // line if it's missing rather than spawning into the void.
        let script = std::path::PathBuf::from(
            "/opt/hyperion/packaging/install/update.sh",
        );
        if !script.exists() {
            append_line(
                &slot,
                &format!("update.sh missing at {} — node was not installed via install-node.sh / install-master.sh", script.display()),
            )
            .await;
            last_code = 2;
        } else {
            last_code = run_one(
                &slot,
                "hyperion-update",
                "/bin/bash",
                &[script.to_str().unwrap_or("/opt/hyperion/packaging/install/update.sh")],
            )
            .await;
        }
    }

    let final_state = if last_code == 0 { "succeeded" } else { "failed" };
    let mut g = slot.lock().await;
    g.state = final_state.to_string();
    g.finished_at = now_secs();
    g.exit_code = last_code;
    tracing::info!(
        exit_code = last_code,
        state = final_state,
        "node update job finished"
    );
}

/// Remove `mig_*` sub-dirs under `root` whose mtime is older than
/// `max_age`. Returns the count removed. Extracted as a free
/// function so it has a fs-only signature that's easy to unit-test
/// with `tempfile::tempdir`. Caller (`prune_old_migration_bundles`)
/// is responsible for passing the real `/var/lib/hyperion/migration`
/// root.
async fn prune_migration_bundle_dir(
    root: &std::path::Path,
    max_age: std::time::Duration,
) -> Result<u32, RpcError> {
    let mut dir = match tokio::fs::read_dir(root).await {
        Ok(d) => d,
        // Root doesn't exist yet (no exports ever run) — nothing to
        // do, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(RpcError::Internal_with(format!(
                "read migration root: {e}"
            )));
        }
    };
    let cutoff = std::time::SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut removed: u32 = 0;
    while let Ok(Some(entry)) = dir.next_entry().await {
        let path = entry.path();
        // Only prune mig_* sub-dirs we created. Don't touch anything
        // else an operator may have stashed there.
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.starts_with("mig_") {
            continue;
        }
        let Ok(meta) = entry.metadata().await else { continue };
        if !meta.is_dir() {
            continue;
        }
        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        if mtime < cutoff {
            match tokio::fs::remove_dir_all(&path).await {
                Ok(()) => {
                    tracing::info!(bundle=%name, "pruned stale migration bundle");
                    removed = removed.saturating_add(1);
                }
                Err(e) => {
                    tracing::warn!(bundle=%name, error=%e, "could not prune bundle");
                }
            }
        }
    }
    Ok(removed)
}

/// Resolve a sensible mail-FQDN for the suggested From address.
/// /etc/mailname is postfix's canonical source; fall back to
/// /etc/hostname. Returns None for non-FQDN inputs (no dot, or
/// the well-known duds "localhost" / "localhost.localdomain") so
/// the autodetect doesn't suggest a from-address that every
/// external relay will reject with "550 sender domain not FQDN".
fn read_mail_fqdn() -> Option<String> {
    for path in &["/etc/mailname", "/etc/hostname"] {
        let v = std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(s) = v {
            if !s.contains('.') {
                continue;
            }
            if s == "localhost.localdomain" {
                continue;
            }
            return Some(s);
        }
    }
    None
}

/// Hard cap on imported migration archives. 8 GB is far past any
/// reasonable hosting archive (real ones land at 10s–100s of MB,
/// the largest ever seen in dev was ~3 GB on a WP site with a 2-GB
/// uploads dir). Without a cap, a malicious or accidentally-huge
/// upstream can fill /var/lib partition.
const MIGRATION_MAX_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Rewrite a freshly-downloaded migration manifest in place to
/// substitute `new_domain` (and optionally `new_aliases`) for the
/// ones captured at export time. Powers the `hosting clone` flow:
/// the archive stays bit-for-bit identical (its sha256 still
/// matches the manifest's archive_sha256) but the importer creates
/// a new hosting under the new domain.
///
/// Validates the new domain via the same parser the wizard uses —
/// a malformed `staging..example.cz` is rejected here, NOT after
/// the importer has half-created a hosting.
async fn rewrite_manifest_domain(
    manifest_path: &std::path::Path,
    new_domain: &str,
    new_aliases: &[String],
) -> Result<(), RpcError> {
    // Parse-check first so a typo doesn't burn the archive download.
    let _ok = hyperion_validate::Domain::parse(new_domain).map_err(|e| {
        RpcError::Validation {
            message: format!("clone override_domain invalid: {e}"),
        }
    })?;
    for a in new_aliases {
        let _ = hyperion_validate::Domain::parse(a).map_err(|e| RpcError::Validation {
            message: format!("clone override_aliases entry '{a}' invalid: {e}"),
        })?;
    }
    let raw = tokio::fs::read(manifest_path).await.map_err(|e| {
        RpcError::Internal_with(format!("read manifest for rewrite: {e}"))
    })?;
    let mut json: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| {
        RpcError::Validation {
            message: format!("manifest is not valid JSON: {e}"),
        }
    })?;
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "domain".into(),
            serde_json::Value::String(new_domain.to_string()),
        );
        if !new_aliases.is_empty() {
            obj.insert(
                "aliases".into(),
                serde_json::Value::Array(
                    new_aliases
                        .iter()
                        .map(|a| serde_json::Value::String(a.clone()))
                        .collect(),
                ),
            );
        }
    } else {
        return Err(RpcError::Validation {
            message: "manifest must be a JSON object".into(),
        });
    }
    let bytes = serde_json::to_vec_pretty(&json).map_err(|e| {
        RpcError::Internal_with(format!("re-serialize manifest: {e}"))
    })?;
    tokio::fs::write(manifest_path, bytes).await.map_err(|e| {
        RpcError::Internal_with(format!("write rewritten manifest: {e}"))
    })?;
    Ok(())
}

async fn curl_to_file(url: &str, dest: &std::path::Path) -> Result<(), RpcError> {
    // -f: fail with non-zero exit on 4xx/5xx (otherwise curl happily
    //     writes the error body to disk and we'd "import" garbage).
    // --max-time 1800: 30-minute hard cap for multi-GB archives.
    // --max-filesize: refuse downloads larger than 8 GB. Without
    //   this a malicious upstream could fill the disk.
    // --max-redirs 0: do NOT follow redirects. With -L set, an
    //   attacker who got the operator to paste their URL into the
    //   import form could 302 us to file:// / DNS-rebind /
    //   internal IP, opening a SSRF pivot. The legitimate source
    //   serves the bundle on a known URL and doesn't need
    //   redirects; if a future deployment does, the operator can
    //   set up a proxy.
    // --proto =https,http: refuse file:// / gopher:// / dict://
    //   even if the URL parser somehow accepts them.
    // -k upfront, not inserted later. The previous version called
    // args.insert(2, "-k") AFTER building the vec — index 2 was the
    // "1800" slot, so the insertion left curl seeing `--max-time -k`
    // and the import failed with
    //   "curl: option --max-time: expected a proper numerical parameter"
    // every single migration. Spot the bug by listing the indices:
    // vec is [-fsS, --max-time, 1800, --max-filesize, …], so
    // insert(2, "-k") yields [-fsS, --max-time, -k, 1800, …].
    //
    // -k is required because the migration source serves on a
    // self-signed cert (same chicken-egg as enrollment — no DNS at
    // install). Trust on first use: the bundle's signed token +
    // BLAKE3 digest are the integrity guarantees, NOT TLS.
    let args: Vec<String> = vec![
        "-fsS".into(),
        "-k".into(),
        "--max-time".into(), "1800".into(),
        "--max-filesize".into(), MIGRATION_MAX_DOWNLOAD_BYTES.to_string(),
        "--max-redirs".into(), "0".into(),
        "--proto".into(), "=https,http".into(),
        "-o".into(), dest.display().to_string(),
        url.to_string(),
    ];
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args(&arg_refs)
        .output()
        .await
        .map_err(|e| RpcError::Internal_with(format!("spawn curl: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        // Curl exit 63 is "Maximum file size exceeded" — surface it
        // with a friendlier error than the bare exit code.
        let hint = if out.status.code() == Some(63) {
            " (archive larger than 8 GB — refusing to download)"
        } else {
            ""
        };
        return Err(RpcError::Validation {
            message: format!(
                "download failed (exit {}): {stderr}{hint}",
                out.status.code().unwrap_or(-1),
            ),
        });
    }
    Ok(())
}

/// Compute the BLAKE3 digest of a file by streaming 64 KiB chunks
/// through the hasher. Used by the migration export/import path to
/// detect tampering or transport corruption without ever loading
/// the whole archive into memory. Returns hex-encoded.
///
/// The field is named "sha256" in the manifest for historical
/// reasons; the actual algorithm is BLAKE3. Both sides recompute
/// with the same code, so cross-tool verification is a non-goal.
async fn compute_sha256(path: &std::path::Path) -> Result<String, RpcError> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| RpcError::Internal_with(format!("digest open: {e}")))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .await
            .map_err(|e| RpcError::Internal_with(format!("digest read: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize().as_bytes()))
}

/// Result of `ahead_of_remote` — whether the local HEAD is at or
/// past the remote SHA, behind it, or whether we couldn't tell
/// because there's no local git checkout to inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AheadResult {
    /// Local HEAD == remote OR remote is reachable from HEAD via
    /// first-parent ancestry. We're at-or-after the remote.
    AheadOrEqual,
    /// Local HEAD is behind the remote — a `git pull` would
    /// fast-forward. This is the "update available" case.
    Behind,
    /// No usable local git checkout (typical: `cargo install`
    /// without a clone, or a dev machine where the binary's build
    /// SHA doesn't correspond to /opt/hyperion/.git). Caller should
    /// fall back to the naive string compare.
    Unknown,
}

/// Check whether `/opt/hyperion`'s git HEAD is at or past `latest`.
///
/// The classic false positive this fixes: `update.sh` does
/// `git pull origin main` and rebuilds. The just-built agent's
/// `current_git_sha` is now main HEAD, which may be ahead of the
/// `rolling` tag because the GitHub Action that fast-forwards the
/// tag hasn't run yet. Without this check the dashboard nags about
/// "update available" pointing at a SHA the operator just installed
/// past.
///
/// Runs as the agent (typically root), reads `/opt/hyperion/.git`
/// directly via `git -C /opt/hyperion merge-base --is-ancestor
/// <latest> HEAD`. Exit 0 means "yes, latest is reachable from HEAD"
/// → we're at-or-after latest. Exit 1 means the opposite. Anything
/// else → Unknown.
async fn ahead_of_remote(latest: &str) -> AheadResult {
    // If /opt/hyperion/.git doesn't exist, we can't tell — common on
    // dev boxes where the binary was `cargo run`'d from somewhere
    // else. Return Unknown so the caller falls back to string compare.
    if !std::path::Path::new("/opt/hyperion/.git").exists() {
        return AheadResult::Unknown;
    }
    // Trim noise the caller might have included — exact 40-char hex
    // please.
    let latest = latest.trim();
    if latest.is_empty() || !latest.chars().all(|c| c.is_ascii_hexdigit()) {
        return AheadResult::Unknown;
    }
    let out = tokio::process::Command::new("/usr/bin/git")
        .args(["-C", "/opt/hyperion", "merge-base", "--is-ancestor", latest, "HEAD"])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => AheadResult::AheadOrEqual,
        Ok(o) if o.status.code() == Some(1) => AheadResult::Behind,
        // Status 128 = "fatal: Not a valid commit name" — the remote
        // SHA isn't in our local object store. That happens after a
        // shallow clone or after a force-push. Try `git fetch` once
        // to make the SHA reachable, then retry.
        Ok(o) if o.status.code() == Some(128) => {
            let _ = tokio::process::Command::new("/usr/bin/git")
                .args(["-C", "/opt/hyperion", "fetch", "--tags", "origin"])
                .output()
                .await;
            let retry = tokio::process::Command::new("/usr/bin/git")
                .args(["-C", "/opt/hyperion", "merge-base", "--is-ancestor", latest, "HEAD"])
                .output()
                .await;
            match retry {
                Ok(o) if o.status.success() => AheadResult::AheadOrEqual,
                Ok(o) if o.status.code() == Some(1) => AheadResult::Behind,
                _ => AheadResult::Unknown,
            }
        }
        _ => AheadResult::Unknown,
    }
}

/// Decide whether `current` and `latest` git SHAs identify the same
/// commit. Both sides are lowercased, then compared on the shorter
/// length (a 7-char short SHA vs. a 40-char full SHA from the remote
/// must match if the short is a prefix of the long).
///
/// "dev-unknown" / empty `current` always reports "no update" — a
/// developer running an unversioned local build shouldn't see a nag
/// banner just because their SHA isn't known.
///
/// Returns (`update_available`, `message_suffix`).
pub fn compare_git_shas(current: &str, latest: &str) -> (bool, &'static str) {
    let cur = current.to_lowercase();
    let lat = latest.to_lowercase();
    if cur == "dev-unknown" || cur.is_empty() {
        return (false, "running an unversioned dev build");
    }
    if lat.is_empty() {
        return (false, "probe failed: empty latest sha");
    }
    let n = cur.len().min(lat.len());
    if n > 0 && cur[..n] == lat[..n] {
        (false, "up to date")
    } else {
        (true, "update available")
    }
}

/// Cluster-wide remote backup destination. When set, every successful
/// `backup_now` also pushes the archive over FTP/FTPS/SFTP via curl.
#[derive(Debug, Clone)]
pub struct RemoteBackupConfig {
    /// "ftp" | "ftps" | "sftp"
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    /// Per-hosting subdirectory is appended automatically.
    pub base_path: String,
}

/// Backup retention policy: archives older than `max_age_days` are
/// pruned BUT we always keep the newest `keep_latest_n` per hosting,
/// so an operator who hasn't backed up in 6 months still has SOMETHING
/// to roll back to.
#[derive(Debug, Clone)]
pub struct BackupRetention {
    pub max_age_days: i64,
    pub keep_latest_n: i64,
}

impl Default for BackupRetention {
    fn default() -> Self {
        Self {
            max_age_days: 30,
            keep_latest_n: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostingPaths {
    pub home_root: String,           // e.g. "/home"
    pub acme_challenge_root: String, // e.g. "/var/lib/hyperion/acme-challenges"
    pub backup_root: String,         // e.g. "/var/lib/hyperion/backups/local"
}

impl Default for HostingPaths {
    fn default() -> Self {
        Self {
            home_root: "/home".into(),
            acme_challenge_root: "/var/lib/hyperion/acme-challenges".into(),
            backup_root: "/var/lib/hyperion/backups/local".into(),
        }
    }
}

impl<A: AdapterPort + 'static> HostingService<A> {
    pub fn new(pool: SqlitePool, adapters: Arc<A>, secrets: Arc<crate::SecretsStore>) -> Self {
        Self {
            pool,
            adapters,
            secrets,
            paths: HostingPaths::default(),
            remote_backup: None,
            retention: BackupRetention::default(),
            slack_default_webhook: None,
            acme_contact_email: "admin@hyperion.invalid".into(),
            email_config: None,
            email_default_to: None,
            agent_config_path: None,
            update_cache: Arc::new(tokio::sync::RwLock::new(None)),
            current_git_sha: "dev-unknown".into(),
            cert_issue_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            master_rpc_signer: None,
            node_state_file: None,
            node_update: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::NodeUpdateStatus::default(),
            )),
            service_install_progress: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::ServiceInstallStatus::default(),
            )),
        }
    }

    /// Tell the service where node-id.json lives. Existence of the
    /// file at services_health time → this is a worker; absence →
    /// this is the master. Called from hyperion-agent's startup.
    pub fn with_node_state_file(mut self, path: std::path::PathBuf) -> Self {
        self.node_state_file = Some(path);
        self
    }

    /// True when this Service is running on an enrolled WORKER node
    /// (node-id.json exists), false when on the master (no file).
    /// The check is filesystem-level on every call — cheap, and
    /// reflects the current state if the operator removes the file
    /// to force re-enrollment.
    pub fn is_worker_node(&self) -> bool {
        match &self.node_state_file {
            Some(p) => p.exists(),
            // Without a configured path we assume master (the
            // historical default for single-node setups).
            None => false,
        }
    }

    /// Wire a master-RPC signing key. Called from hyperion-agent's
    /// startup on every node — workers will simply not propagate
    /// the pubkey (they don't process inbound enrollments /
    /// heartbeats), so leaving this on for everyone is a no-op for
    /// non-master nodes.
    pub fn with_master_rpc_signer(
        mut self,
        signer: Arc<crate::master_rpc::MasterRpcSigner>,
    ) -> Self {
        self.master_rpc_signer = Some(signer);
        self
    }

    /// Convenience: returns the master's Ed25519 pubkey in base64
    /// suitable for embedding in enrollment / heartbeat responses.
    /// Returns `None` when remote-RPC isn't initialized on this
    /// node (workers, or masters whose key file failed to load).
    pub fn master_rpc_pubkey_b64(&self) -> Option<String> {
        self.master_rpc_signer
            .as_ref()
            .map(|s| s.pubkey_b64().to_string())
    }

    /// Wire the compile-time git SHA so `update_check` knows what
    /// version is actually running. Called from `hyperion-agent`'s
    /// startup with `env!("HYPERION_GIT_SHA")`.
    pub fn with_git_sha(mut self, sha: impl Into<String>) -> Self {
        self.current_git_sha = sha.into();
        self
    }

    /// Wire the on-disk agent.toml path so the /settings page can
    /// write back to it. Called from `bin/hyperion-agent/src/main.rs`
    /// at startup.
    pub fn with_agent_config_path(mut self, path: std::path::PathBuf) -> Self {
        self.agent_config_path = Some(path);
        self
    }

    pub fn with_acme_email(mut self, email: impl Into<String>) -> Self {
        self.acme_contact_email = email.into();
        self
    }

    pub fn with_email(
        mut self,
        cfg: Option<hyperion_adapters::email::EmailConfig>,
        default_to: Option<String>,
    ) -> Self {
        self.email_config = cfg;
        self.email_default_to = default_to.filter(|s| !s.trim().is_empty());
        self
    }

    pub fn with_slack_webhook(mut self, webhook: Option<String>) -> Self {
        self.slack_default_webhook = webhook.filter(|s| !s.trim().is_empty());
        self
    }

    pub fn with_paths(mut self, paths: HostingPaths) -> Self {
        self.paths = paths;
        self
    }

    pub fn with_remote_backup(mut self, cfg: Option<RemoteBackupConfig>) -> Self {
        self.remote_backup = cfg;
        self
    }

    pub fn with_retention(mut self, retention: BackupRetention) -> Self {
        self.retention = retention;
        self
    }

    /// Provision a hosting end-to-end with LIFO rollback on partial failure.
    pub async fn create(&self, req: HostingCreateReq) -> Result<HostingCreated, RpcError> {
        // 1. Validate (parse already did most). Derive system user if absent.
        let system_user = match req.system_user.clone() {
            Some(u) => u,
            None => SystemUserName::derive_from_domain(req.domain.as_str())?,
        };
        let domain = req.domain.as_str();
        let home_dir = format!("{}/{}", self.paths.home_root, system_user);
        let hosting_root = format!("{}/{}", home_dir, domain);
        let htdocs = format!("{}/htdocs", hosting_root);
        let logs = format!("{}/logs", hosting_root);
        let tmp = format!("{}/tmp", hosting_root);

        let mut stack = RollbackStack::new();

        // 2. ensure_user
        let uid = match self
            .adapters
            .ensure_user(system_user.as_str(), &home_dir)
            .await
        {
            Ok(u) => u,
            Err(e) => return Err(e.into()),
        };
        stack.push(Box::new(DeleteUser {
            adapters: self.adapters.clone(),
            name: system_user.as_str().to_string(),
        }));

        // 3. ensure_dirs
        if let Err(e) = self.adapters.ensure_dirs(&htdocs, &logs, &tmp, uid).await {
            let _ = stack.rollback_all().await;
            return Err(e.into());
        }
        stack.push(Box::new(RemoveTree {
            adapters: self.adapters.clone(),
            root: hosting_root.clone(),
        }));

        // 4. INSERT hosting row (now we have system_user_id)
        let suid_row = match system_users::insert(
            &self.pool,
            system_user.as_str(),
            uid as i64,
            &home_dir,
            "/usr/sbin/nologin",
            now_secs(),
        )
        .await
        {
            Ok(id) => id,
            Err(e) => {
                // Failure cases worth recovering from automatically:
                //   (a) Same NAME already in the DB — we're re-running a
                //       partial create; reuse the existing row.
                //   (b) Same UID already in the DB but DIFFERENT name —
                //       stale orphan from a previous hosting delete that
                //       predated the system_users cleanup fix. Verify
                //       nothing references it, drop it, retry.
                let by_name = system_users::get_by_name(&self.pool, system_user.as_str())
                    .await
                    .ok()
                    .flatten();
                if let Some(row) = by_name {
                    row.id
                } else {
                    let by_uid = system_users::get_by_uid(&self.pool, uid as i64)
                        .await
                        .ok()
                        .flatten();
                    // Orphan detection: a system_users row whose
                    // referencing hostings are either (a) absent or
                    // (b) ALL in non-active states (failed,
                    // provisioning, deleting) is safe to clean — no
                    // real hosting depends on it. Only an `active`
                    // hosting locks the row.
                    let orphan = match &by_uid {
                        Some(r) => {
                            let rows: Vec<(String,)> = sqlx::query_as(
                                "SELECT state FROM hostings WHERE system_user_id = ?",
                            )
                            .bind(r.id)
                            .fetch_all(&self.pool)
                            .await
                            .unwrap_or_default();
                            let any_active = rows.iter().any(|(s,)| s == "active");
                            if any_active {
                                None
                            } else {
                                Some(r.clone())
                            }
                        }
                        None => None,
                    };
                    if let Some(orphan) = orphan {
                        tracing::warn!(
                            uid = uid,
                            old_name = %orphan.name,
                            new_name = %system_user.as_str(),
                            "dropping orphan system_users row to free UID"
                        );
                        // Also drop any hostings rows that
                        // referenced the orphan — they're necessarily
                        // stale because has_hostings already returned
                        // false (the orphan check above gates on that).
                        // No-op when there are none, which is the
                        // common case.
                        let _ = sqlx::query("DELETE FROM hostings WHERE system_user_id = ?")
                            .bind(orphan.id)
                            .execute(&self.pool)
                            .await;
                        let _ = system_users::delete(&self.pool, orphan.id).await;
                        match system_users::insert(
                            &self.pool,
                            system_user.as_str(),
                            uid as i64,
                            &home_dir,
                            "/usr/sbin/nologin",
                            now_secs(),
                        )
                        .await
                        {
                            Ok(id) => id,
                            Err(e2) => {
                                let _ = stack.rollback_all().await;
                                return Err(RpcError::Internal_with(format!(
                                    "system_users insert (retry after orphan cleanup): {e2}"
                                )));
                            }
                        }
                    } else {
                        // The orphan-detection branch wasn't reached
                        // EITHER because by_uid is None (the UID
                        // legitimately belongs to a hosting we
                        // shouldn't nuke) OR has_hostings returned
                        // true (a real hosting references it). In
                        // both cases the operator has to investigate
                        // by hand — but surface the row id so they
                        // can grep the DB.
                        if let Some(by_uid_row) = by_uid {
                            tracing::error!(
                                uid = uid,
                                existing_name = %by_uid_row.name,
                                "system_users UID conflict + the conflicting row IS referenced by \
                                 a hostings record — refusing to auto-clean. Inspect with: \
                                 sqlite3 /var/lib/hyperion/state.db \
                                 'SELECT * FROM hostings WHERE system_user_id = {row_id};'",
                                row_id = by_uid_row.id
                            );
                        }
                        let _ = stack.rollback_all().await;
                        return Err(RpcError::Internal_with(format!(
                            "system_users insert: {e}"
                        )));
                    }
                }
            }
        };
        // Now that the system_users row exists, push a rollback step
        // that removes it on later failures. Without this, the
        // DeleteUser rollback (Linux user) runs but the DB row keeps
        // the UID, claiming it permanently. The next create's
        // useradd reuses the freed UID and trips UNIQUE(uid).
        stack.push(Box::new(DeleteSystemUsersRow {
            pool: self.pool.clone(),
            row_id: suid_row,
        }));
        // For reverse_proxy validate upstream URL is present + parseable
        // before we touch system_users / DB / nginx. Bail clean.
        if req.kind == "reverse_proxy" {
            let upstream = req
                .proxy_upstream_url
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| RpcError::Validation {
                    message: "reverse_proxy requires proxy_upstream_url".into(),
                })?;
            if !(upstream.starts_with("http://") || upstream.starts_with("https://")) {
                return Err(RpcError::Validation {
                    message: "proxy_upstream_url must start with http:// or https://".into(),
                });
            }
        }
        let hosting_id = HostingId::new_v7();
        let node_id_str = self.current_node_id();
        if let Err(e) = hostings::insert_with_kind(
            &self.pool,
            &hosting_id,
            domain,
            suid_row,
            req.php_version,
            &htdocs,
            &req.kind,
            req.proxy_upstream_url.as_deref(),
            now_secs(),
            Some(node_id_str.as_str()),
        )
        .await
        {
            let _ = stack.rollback_all().await;
            return Err(RpcError::AlreadyExists {
                kind: "hosting".into(),
                id: format!("{} ({})", domain, e),
            });
        }
        let hosting_id_for_rollback = hosting_id.clone();
        stack.push(Box::new(MarkFailedOrDeleteRow {
            pool: self.pool.clone(),
            id: hosting_id_for_rollback,
        }));

        // 4b. aliases
        for alias in &req.aliases {
            if let Err(e) = hostings::insert_alias(&self.pool, &hosting_id, alias.as_str()).await {
                let _ = stack.rollback_all().await;
                return Err(RpcError::AlreadyExists {
                    kind: "alias".into(),
                    id: format!("{} ({})", alias, e),
                });
            }
        }

        // 5. PHP-FPM pool — only for kind=php hostings.
        if req.kind == "php" {
            if let Some(ver) = req.php_version {
                if let Err(e) = self
                    .adapters
                    .fpm_ensure(system_user.as_str(), domain, ver)
                    .await
                {
                    let _ = stack.rollback_all().await;
                    return Err(e.into());
                }
                stack.push(Box::new(FpmDelete {
                    adapters: self.adapters.clone(),
                    system_user: system_user.as_str().to_string(),
                    version: ver,
                }));
            }
        }

        // 6. database
        let mut db_creds: Option<DbCredentials> = None;
        if let Some(engine) = req.database {
            let creds = match self.adapters.db_create(engine, &hosting_id, domain).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = stack.rollback_all().await;
                    return Err(e.into());
                }
            };
            let secret_id = SecretId::new();
            if let Err(e) = self
                .secrets
                .put(
                    &secret_id,
                    &serde_json::json!({
                        "engine": engine.as_str(),
                        "db_name": creds.db_name,
                        "db_user": creds.db_user,
                        "password": creds.password,
                    }),
                )
                .await
            {
                let _ = stack.rollback_all().await;
                return Err(RpcError::Internal_with(format!("secret write: {e}")));
            }
            if let Err(e) = databases::insert(
                &self.pool,
                &hosting_id,
                engine,
                &creds.db_name,
                &creds.db_user,
                &secret_id,
                now_secs(),
            )
            .await
            {
                let _ = stack.rollback_all().await;
                return Err(RpcError::Internal_with(format!("databases row: {e}")));
            }
            let db_name_for_rb = creds.db_name.clone();
            let db_user_for_rb = creds.db_user.clone();
            stack.push(Box::new(DbDrop {
                adapters: self.adapters.clone(),
                engine,
                db_name: db_name_for_rb,
                db_user: db_user_for_rb,
            }));
            db_creds = Some(creds);
        }

        // 7. ACME cert
        let sans: Vec<String> = req.aliases.iter().map(|d| d.to_string()).collect();
        let cert = match self.adapters.acme_issue(domain, &sans).await {
            Ok(c) => c,
            Err(e) => {
                let _ = stack.rollback_all().await;
                return Err(e.into());
            }
        };
        let cert_path = format!("/etc/hyperion/certs/{}/fullchain.pem", domain);
        let key_path = format!("/etc/hyperion/certs/{}/privkey.pem", domain);
        let _ = certificates::upsert(
            &self.pool,
            domain,
            now_secs(),
            cert.not_after,
            &cert_path,
            &key_path,
            &cert.issuer,
        )
        .await;
        stack.push(Box::new(AcmeDelete {
            adapters: self.adapters.clone(),
            domain: domain.to_string(),
        }));

        // 8. nginx vhost
        let detail = HostingDetail {
            id: hosting_id.clone(),
            domain: domain.to_string(),
            aliases: sans.clone(),
            state: HostingState::Provisioning,
            system_user: system_user.as_str().to_string(),
            php_version: req.php_version,
            root_dir: htdocs.clone(),
            database: db_creds.as_ref().map(|c| DbSummary {
                engine: c.engine,
                db_name: c.db_name.clone(),
                db_user: c.db_user.clone(),
            }),
            cert: Some(cert.clone()),
            created_at: now_secs(),
            updated_at: now_secs(),
            acme_contact_email: None,
            kind: req.kind.clone(),
            proxy_upstream_url: req.proxy_upstream_url.clone(),
            node_id: Some(node_id_str.clone()),
            vhost_options: hyperion_types::VhostOptions::default(),
            wp_extras: hyperion_types::WpExtras::default(),
        };
        if let Err(e) = self.adapters.nginx_write_vhost(&detail).await {
            let _ = stack.rollback_all().await;
            return Err(e.into());
        }

        // 9. transition to active
        if let Err(e) =
            hostings::set_state(&self.pool, &hosting_id, HostingState::Active, now_secs()).await
        {
            // We were so close.
            let _ = stack.rollback_all().await;
            return Err(RpcError::Internal_with(format!("set_state: {e}")));
        }

        // success — discard rollback
        stack.forget();

        Ok(HostingCreated {
            id: hosting_id,
            system_user: system_user.as_str().to_string(),
            root_dir: htdocs,
            db: db_creds,
            cert: Some(cert),
            wp: None,
        })
    }

    pub async fn list(&self) -> Result<Vec<HostingSummary>, RpcError> {
        hostings::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))
    }

    /// Boot-time self-heal: re-render the FPM pool config for every
    /// active hosting that has PHP. We do this because the pool
    /// template's `listen.owner` depends on the nginx user, which is
    /// detected dynamically at startup — old pool files on disk may
    /// hard-code an outdated owner (e.g. `www-data` when nginx now
    /// runs as `vito`).
    ///
    /// IMPORTANT: after the pools are re-written we issue a `systemctl
    /// restart php<ver>-fpm` for every PHP version that owned at least
    /// one rewritten pool. `reload` alone is not enough — FPM keeps
    /// the existing UNIX socket open even when the pool config's
    /// `listen.owner` changes, and `chown(2)` is not re-applied to an
    /// already-bound socket. Only a full restart re-creates the
    /// socket with the new ownership. We accept the (~50ms per
    /// version) brief PHP availability gap on agent startup as a
    /// worthy trade — without it 502 persists until manual fix.
    ///
    /// Errors per-hosting are logged but never propagated — one bad
    /// hosting must not block agent startup. Returns the count of
    /// pools successfully re-rendered.
    pub async fn rerender_fpm_pools(&self) -> usize {
        let summaries = match self.list().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error=%e, "rerender_fpm_pools: list failed");
                return 0;
            }
        };
        let mut ok = 0;
        let mut touched_versions: std::collections::HashSet<PhpVersion> = Default::default();
        for s in summaries {
            let Some(ver) = s.php_version else {
                continue;
            };
            if !matches!(s.state, hyperion_types::HostingState::Active) {
                continue;
            }
            // We need the system_user for fpm_ensure. Pull the detail.
            let detail = match self
                .get(crate::service::HostingSelector::Id(s.id.clone()))
                .await
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        domain = %s.domain,
                        error = %e,
                        "rerender_fpm_pools: could not fetch detail"
                    );
                    continue;
                }
            };
            if detail.system_user.is_empty() {
                tracing::warn!(
                    domain = %detail.domain,
                    "rerender_fpm_pools: skipping (empty system_user)"
                );
                continue;
            }
            if let Err(e) = self
                .adapters
                .fpm_ensure(&detail.system_user, &detail.domain, ver)
                .await
            {
                tracing::warn!(
                    domain = %detail.domain,
                    error = %e,
                    "rerender_fpm_pools: fpm_ensure failed"
                );
                continue;
            }
            touched_versions.insert(ver);
            ok += 1;
        }

        // Full restart per touched version — see doc comment above for
        // why reload isn't enough. We swallow errors: if FPM can't be
        // restarted by us, the operator will see the pool config is
        // correct on disk and can fix manually.
        for ver in touched_versions {
            let svc = format!("{}.service", ver.service_name());
            let res = tokio::process::Command::new("/usr/bin/systemctl")
                .args(["restart", &svc])
                .output()
                .await;
            match res {
                Ok(out) if out.status.success() => {
                    tracing::info!(service = %svc, "boot self-heal: restarted FPM to apply new listen.owner");
                }
                Ok(out) => {
                    tracing::warn!(
                        service = %svc,
                        stderr = %String::from_utf8_lossy(&out.stderr),
                        "boot self-heal: systemctl restart failed"
                    );
                }
                Err(e) => {
                    tracing::warn!(error=%e, service=%svc, "boot self-heal: could not invoke systemctl");
                }
            }
        }

        ok
    }

    pub async fn get(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError> {
        let row = match sel {
            HostingSelector::Id(id) => hostings::get_by_id(&self.pool, &id).await,
            HostingSelector::Domain(d) => hostings::get_by_domain(&self.pool, d.as_str()).await,
        }
        .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
        .ok_or_else(|| RpcError::NotFound {
            kind: "hosting".into(),
            id: "selector".into(),
        })?;

        let aliases = hostings::aliases(&self.pool, &row.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("aliases: {e}")))?;
        let db = databases::get_for_hosting(&self.pool, &row.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("databases: {e}")))?
            .map(|d| DbSummary {
                engine: d.engine,
                db_name: d.db_name,
                db_user: d.db_user,
            });
        let cert_row = certificates::get(&self.pool, &row.domain)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cert: {e}")))?;
        let cert = cert_row.map(|c| CertInfo {
            domain: c.domain,
            sans: aliases.clone(),
            issuer: c.issuer,
            not_after: c.not_after,
            fingerprint_sha256: String::new(),
        });
        let suser = system_users::get_by_name(&self.pool, "")
            .await
            .ok()
            .flatten();
        let system_user_name = match suser {
            Some(_) => String::new(),
            None => {
                match sqlx::query_as::<_, (String,)>("SELECT name FROM system_users WHERE id = ?")
                    .bind(row.system_user_id)
                    .fetch_optional(&self.pool)
                    .await
                {
                    Ok(Some((s,))) => s,
                    _ => String::new(),
                }
            }
        };
        Ok(HostingDetail {
            id: row.id,
            domain: row.domain,
            aliases,
            state: row.state,
            system_user: system_user_name,
            php_version: row.php_version,
            root_dir: row.root_dir,
            database: db,
            cert,
            created_at: row.created_at,
            updated_at: row.updated_at,
            acme_contact_email: row.acme_contact_email,
            kind: row.kind,
            proxy_upstream_url: row.proxy_upstream_url,
            node_id: row.node_id,
            vhost_options: row.vhost_options,
            wp_extras: row.wp_extras,
        })
    }

    pub async fn delete(&self, sel: HostingSelector, opts: DeleteOpts) -> Result<(), RpcError> {
        let detail = self.get(sel.clone()).await?;

        // Soft-delete branch: when cluster.trash_enabled = true,
        // route to trash() which preserves files / DB / user and
        // flips the row to state=trashed. The scheduler GCs it
        // to a hard delete after retention_days.
        let cluster_cfg = read_cluster_section(self.agent_config_path.as_deref());
        if cluster_cfg.trash_enabled {
            return self.trash_hosting(detail).await;
        }

        hostings::set_state(&self.pool, &detail.id, HostingState::Deleting, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set deleting: {e}")))?;

        // best-effort nginx delete (also drops per-hosting cache zone +
        // htpasswd sidecar so the slot is fully clean for a future
        // hosting reusing this ULID).
        let _ = self
            .adapters
            .nginx_delete_vhost(&detail.domain, Some(detail.id.to_string()))
            .await;
        // best-effort cert delete
        let _ = self.adapters.acme_delete(&detail.domain).await;
        let _ = certificates::delete(&self.pool, &detail.domain).await;
        // db drop
        if let Some(db) = detail.database.as_ref() {
            if !opts.keep_database {
                let _ = self
                    .adapters
                    .db_drop(db.engine, &db.db_name, &db.db_user)
                    .await;
            }
        }
        // fpm pool delete
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        // remove tree
        let hosting_root = format!(
            "{}/{}/{}",
            self.paths.home_root, detail.system_user, detail.domain
        );
        let _ = self.adapters.remove_hosting_tree(&hosting_root).await;

        if !opts.keep_user {
            // delete user only if no other hostings reference them
            let (others,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM hostings WHERE system_user_id = (SELECT id FROM system_users WHERE name = ?) AND id != ?")
                    .bind(&detail.system_user)
                    .bind(detail.id.as_str())
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("count: {e}")))?;
            if others == 0 {
                let _ = self.adapters.delete_user(&detail.system_user).await;
                // Also drop the system_users row so the UID can be reused
                // for a future hosting (Linux frees the UID via userdel;
                // without this cleanup the next useradd allocates the same
                // UID and `system_users` INSERT hits its UNIQUE(uid)
                // constraint).
                if let Ok(Some(row)) =
                    system_users::get_by_name(&self.pool, &detail.system_user).await
                {
                    let _ = system_users::delete(&self.pool, row.id).await;
                }
            }
        }

        hostings::delete(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete row: {e}")))?;
        Ok(())
    }

    // ────────────────────────── Trash / recycle bin ──────────────────────────

    /// Move a hosting to the trash. Same side-effects as suspend
    /// (nginx 503, FPM stop, DB lock, OS user locked, processes
    /// killed) PLUS set state=Trashed + stamp `trashed_at`. Files /
    /// DB / OS user / certs are PRESERVED — the scheduler GC's
    /// them later, or the operator can purge / restore explicitly
    /// from /trash.
    ///
    /// Internal: called from `delete()` when cluster.trash_enabled.
    async fn trash_hosting(&self, detail: HostingDetail) -> Result<(), RpcError> {
        // Mirror the suspend side-effects.
        let _ = self
            .adapters
            .nginx_apply_suspended(&detail.domain, Some("Hosting is in trash".into()))
            .await;
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_lock(db.engine, &db.db_user).await;
        }
        let _ = self.adapters.linux_lock_login(&detail.system_user).await;
        let _ = self.adapters.kill_user_procs(&detail.system_user).await;

        hostings::mark_trashed(&self.pool, &detail.id, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("mark trashed: {e}")))?;

        self.append_audit(
            "hosting.trash",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        // Notify admins so the bell catches "this site went to trash".
        self.notify_admins(
            "warn",
            "Hosting moved to trash",
            &format!("{} will be GC'd after the trash retention window.", detail.domain),
            "/trash",
            "hosting.trash",
        )
        .await;
        Ok(())
    }

    /// Restore a trashed hosting back to Active. Reverses the
    /// suspend side-effects (unlock OS user, unlock DB, restart
    /// FPM, write the real vhost back). Refuses if state isn't
    /// Trashed.
    pub async fn restore_from_trash(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Trashed {
            return Err(RpcError::Conflict {
                message: format!(
                    "hosting must be in trash to restore (current state: {})",
                    detail.state.as_str()
                ),
            });
        }
        let _ = self.adapters.linux_unlock_login(&detail.system_user).await;
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_unlock(db.engine, &db.db_user).await;
        }
        if let Some(ver) = detail.php_version {
            let _ = self
                .adapters
                .fpm_ensure(&detail.system_user, &detail.domain, ver)
                .await;
        }
        let _ = self.adapters.nginx_write_vhost(&detail).await;
        hostings::unmark_trashed(&self.pool, &detail.id, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("unmark: {e}")))?;
        self.append_audit(
            "hosting.trash.restore",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Permanently delete a trashed hosting NOW (skips waiting for
    /// the GC). Operator-driven. Hosting state must be Trashed —
    /// refuses on Active so the caller doesn't bypass the trash
    /// flow by accident.
    pub async fn purge_from_trash(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel.clone()).await?;
        if detail.state != HostingState::Trashed {
            return Err(RpcError::Conflict {
                message: format!(
                    "purge_from_trash refuses non-trashed hosting (state: {})",
                    detail.state.as_str()
                ),
            });
        }
        // First need to flip back to Deleting (the delete() guard
        // refuses to re-trash a trashed row). We bypass delete() and
        // call the hard-delete machinery directly here so the trash
        // setting doesn't redirect us back into trash().
        self.hard_delete_internal(detail, DeleteOpts::default()).await?;
        Ok(())
    }

    /// Tick: iterate trashed rows past their retention window and
    /// hard-delete each. Called by the scheduler. Returns the
    /// number of rows GC'd.
    pub async fn trash_gc_tick(&self) -> Result<i64, RpcError> {
        let cluster_cfg = read_cluster_section(self.agent_config_path.as_deref());
        if !cluster_cfg.trash_enabled {
            return Ok(0);
        }
        let retention_secs = cluster_cfg.trash_retention_days * 24 * 3600;
        let expired = hostings::list_trashed_expired(&self.pool, now_secs(), retention_secs)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list expired: {e}")))?;
        let mut purged = 0i64;
        for row in expired {
            let id = row.id.clone();
            // Build a HostingDetail from the row (mirror service::get).
            let sel = HostingSelector::Id(id.clone());
            if let Ok(detail) = self.get(sel).await {
                if self
                    .hard_delete_internal(detail, DeleteOpts::default())
                    .await
                    .is_ok()
                {
                    purged += 1;
                }
            }
        }
        if purged > 0 {
            tracing::info!(count = purged, "trash GC: purged expired hostings");
        }
        Ok(purged)
    }

    /// The hard-delete pipeline extracted so both `delete()` (when
    /// trash is off) and `purge_from_trash()` / GC (when trash is
    /// on) can share it. Keeps the existing public delete() body
    /// readable instead of branching deep inside.
    async fn hard_delete_internal(
        &self,
        detail: HostingDetail,
        opts: DeleteOpts,
    ) -> Result<(), RpcError> {
        hostings::set_state(&self.pool, &detail.id, HostingState::Deleting, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set deleting: {e}")))?;
        let _ = self
            .adapters
            .nginx_delete_vhost(&detail.domain, Some(detail.id.to_string()))
            .await;
        let _ = self.adapters.acme_delete(&detail.domain).await;
        let _ = certificates::delete(&self.pool, &detail.domain).await;
        if let Some(db) = detail.database.as_ref() {
            if !opts.keep_database {
                let _ = self
                    .adapters
                    .db_drop(db.engine, &db.db_name, &db.db_user)
                    .await;
            }
        }
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        let hosting_root = format!(
            "{}/{}/{}",
            self.paths.home_root, detail.system_user, detail.domain
        );
        let _ = self.adapters.remove_hosting_tree(&hosting_root).await;
        if !opts.keep_user {
            let (others,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM hostings WHERE system_user_id = (SELECT id FROM system_users WHERE name = ?) AND id != ?")
                    .bind(&detail.system_user)
                    .bind(detail.id.as_str())
                    .fetch_one(&self.pool)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("count: {e}")))?;
            if others == 0 {
                let _ = self.adapters.delete_user(&detail.system_user).await;
                if let Ok(Some(row)) =
                    system_users::get_by_name(&self.pool, &detail.system_user).await
                {
                    let _ = system_users::delete(&self.pool, row.id).await;
                }
            }
        }
        hostings::delete(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete row: {e}")))?;
        self.append_audit(
            "hosting.purge",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Read all trashed hostings + compute the "days remaining"
    /// for the /trash list. Returns the wire-friendly summary.
    pub async fn list_trash(&self) -> Result<Vec<hyperion_types::TrashEntry>, RpcError> {
        let cluster_cfg = read_cluster_section(self.agent_config_path.as_deref());
        let retention_secs = cluster_cfg.trash_retention_days * 24 * 3600;
        let now = now_secs();
        let rows = hostings::list_trashed(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list trashed: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let trashed_at = r.trashed_at.unwrap_or(0);
                let purge_at = trashed_at + retention_secs;
                let secs_remaining = (purge_at - now).max(0);
                hyperion_types::TrashEntry {
                    id: r.id.as_str().to_string(),
                    domain: r.domain,
                    trashed_at,
                    purge_at,
                    seconds_remaining: secs_remaining,
                    node_id: r.node_id.unwrap_or_default(),
                }
            })
            .collect())
    }

    /// Apply / replace the per-hosting limits. Persists the row, then asks the
    /// adapter to apply the PHP-FPM side effects. Returns the canonical row
    /// (so callers see exactly what was stored after defaults / clamping).
    pub async fn set_limits(
        &self,
        sel: HostingSelector,
        limits: hyperion_types::HostingLimits,
    ) -> Result<hyperion_types::HostingLimits, RpcError> {
        let detail = self.get(sel).await?;
        let limits = clamp_limits(limits);
        let row = limits_to_row(&detail.id, &limits, now_secs());
        hyperion_state::limits::upsert(&self.pool, &row)
            .await
            .map_err(|e| RpcError::Internal_with(format!("limits upsert: {e}")))?;
        if let Err(e) = self
            .adapters
            .apply_php_limits(
                &detail.system_user,
                &detail.domain,
                detail.php_version,
                limits.php_memory_mb,
                limits.php_max_exec_secs,
                limits.php_max_children,
                limits.php_max_requests,
            )
            .await
        {
            return Err(e.into());
        }
        Ok(limits)
    }

    pub async fn get_limits(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingLimits, RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::limits::get(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("limits get: {e}")))?;
        Ok(row
            .map(row_to_limits)
            .unwrap_or_else(hyperion_types::HostingLimits::defaults))
    }

    /// Switch a hosting's PHP version. Orchestrates:
    /// 1. Validation — hosting must be PHP (not static / proxy /
    ///    redirect), target version must differ from current, hosting
    ///    must not be suspended/deleting (use suspend/resume for that).
    /// 2. Tear down the OLD FPM pool (`fpm_delete`) so the old socket
    ///    file gets removed and the previous php<ver>-fpm pool config
    ///    file is dropped.
    /// 3. Persist the new `php_version` on the hostings row.
    /// 4. Ensure the NEW FPM pool exists (`fpm_ensure`) — this
    ///    creates the pool config under /etc/php/<new>/fpm/pool.d
    ///    and reloads php<new>-fpm.
    /// 5. Re-apply the persisted per-hosting PHP limits to the new
    ///    pool (memory, max_children, max_exec, max_requests), so a
    ///    plan limit set on PHP 8.3 carries over to PHP 8.4.
    /// 6. Re-render the nginx vhost so the `fastcgi_pass` socket
    ///    points at the new path (`/run/php/<new>/<user>.sock`).
    ///    `nginx -t` runs inside `nginx_write_vhost` and rolls back
    ///    on failure.
    /// 7. Audit log line so the operator can trace the change.
    ///
    /// On nginx -t failure the new pool is left in place but the
    /// vhost still points at the OLD socket — site keeps serving via
    /// the old FPM, the operator sees the vhost write error in the
    /// flash. This is the safe direction: NEW pool is up, old pool
    /// is gone, but vhost is unchanged → site keeps working off
    /// whichever socket the OS still considers valid. Operator then
    /// fixes the underlying config issue and retries.
    pub async fn set_php_version(
        &self,
        sel: HostingSelector,
        new_version: PhpVersion,
    ) -> Result<PhpVersion, RpcError> {
        let detail = self.get(sel).await?;

        // Validation — only PHP hostings can have their version changed.
        // A static / proxy / redirect hosting would need a kind
        // change first, which is a much bigger surgery (different
        // template, different lifecycle).
        let current = detail.php_version.ok_or_else(|| RpcError::Conflict {
            message: format!(
                "hosting kind `{}` has no PHP runtime — can't change version. \
                 Delete and recreate as a PHP hosting if you need PHP.",
                detail.kind
            ),
        })?;
        if current == new_version {
            // No-op early-return so the operator can click the same
            // version twice without churn. Return Ok with the
            // current value so the UI flash can still confirm.
            return Ok(current);
        }
        if matches!(detail.state, HostingState::Suspended) {
            return Err(RpcError::Conflict {
                message: "hosting is suspended — resume first, then change PHP version".into(),
            });
        }
        if matches!(detail.state, HostingState::Deleting | HostingState::Trashed) {
            return Err(RpcError::Conflict {
                message: "hosting is being deleted or in trash".into(),
            });
        }

        // 1. Tear down old FPM pool. Best-effort: a missing pool file
        //    or already-stopped service is fine — we're about to
        //    replace it with the new version anyway. The new pool
        //    create below is what actually has to succeed.
        if let Err(e) = self.adapters.fpm_delete(&detail.system_user, current).await {
            tracing::warn!(
                domain = %detail.domain,
                from_version = %current,
                error = %e,
                "set_php_version: fpm_delete of old version failed (continuing)"
            );
        }

        // 2. Persist the new version. If subsequent steps fail, the
        //    hostings row reflects intent — the boot-time FPM self-heal
        //    + vhost rewrite will re-converge on next agent restart.
        hyperion_state::hostings::set_php_version(
            &self.pool,
            &detail.id,
            Some(new_version),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set_php_version persist: {e}")))?;

        // 3. Ensure the new pool. If this fails we leave the row at
        //    the new version (intent) but rollback the FPM-pool-only
        //    side: there's nothing to rollback because step 1 already
        //    deleted the old pool. Operator retries; agent self-heal
        //    will re-converge.
        if let Err(e) = self
            .adapters
            .fpm_ensure(&detail.system_user, &detail.domain, new_version)
            .await
        {
            return Err(RpcError::Internal_with(format!(
                "fpm_ensure for PHP {new_version} failed: {e} \
                 (the hostings row was updated; retry to converge)"
            )));
        }

        // 4. Re-apply persisted PHP limits to the new pool so a plan
        //    limit set on PHP 8.3 (memory, children, etc.) survives
        //    the switch to 8.4. Best-effort — operator can re-apply
        //    via the Limits card if needed.
        if let Ok(Some(row)) = hyperion_state::limits::get(&self.pool, &detail.id).await {
            let l = row_to_limits(row);
            if let Err(e) = self
                .adapters
                .apply_php_limits(
                    &detail.system_user,
                    &detail.domain,
                    Some(new_version),
                    l.php_memory_mb,
                    l.php_max_exec_secs,
                    l.php_max_children,
                    l.php_max_requests,
                )
                .await
            {
                tracing::warn!(
                    domain = %detail.domain,
                    error = %e,
                    "set_php_version: re-apply limits to new pool failed (best-effort)"
                );
            }
        }

        // 5. Re-render vhost so fastcgi_pass points at the new socket.
        //    Pull the FRESH detail (with new php_version) for rendering.
        let new_detail = self
            .get(HostingSelector::Id(detail.id.clone()))
            .await?;
        if let Err(e) = self.adapters.nginx_write_vhost(&new_detail).await {
            return Err(RpcError::Internal_with(format!(
                "nginx_write_vhost after PHP version change failed: {e} \
                 (FPM pool for PHP {new_version} is up; site still serves via the old socket \
                 until the vhost is rewritten — retry once the underlying config error is fixed)"
            )));
        }

        // 6. Audit log so we can reconstruct who/when/from→to.
        self.append_audit(
            "hosting.set_php_version",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "from": current.as_str(),
                "to": new_version.as_str(),
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(new_version)
    }

    /// Best-effort suspend. State row goes to 'suspended'; cascading effects
    /// (nginx swap, FPM stop, DB lock, login lock, kill procs) run as
    /// best-effort — failures are logged but don't revert state. Suspended is
    /// the safer state; operators retry to converge.
    pub async fn suspend(
        &self,
        sel: HostingSelector,
        reason: hyperion_types::SuspendReason,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state == HostingState::Suspended {
            return Ok(());
        }
        if detail.state == HostingState::Deleting {
            return Err(RpcError::Conflict {
                message: "hosting is being deleted".into(),
            });
        }
        hostings::set_state(&self.pool, &detail.id, HostingState::Suspended, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set suspended: {e}")))?;
        let susp = hyperion_state::limits::SuspensionRow {
            hosting_id: detail.id.clone(),
            suspended_at: now_secs(),
            suspended_by: reason.label().to_string(),
            reason_message: reason.message().map(|s| s.to_string()),
            custom_page_html: None,
        };
        hyperion_state::limits::insert_suspension(&self.pool, &susp)
            .await
            .map_err(|e| RpcError::Internal_with(format!("insert suspension: {e}")))?;

        let _ = self
            .adapters
            .nginx_apply_suspended(&detail.domain, reason.message().map(|s| s.to_string()))
            .await;
        if let Some(ver) = detail.php_version {
            let _ = self.adapters.fpm_delete(&detail.system_user, ver).await;
        }
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_lock(db.engine, &db.db_user).await;
        }
        let _ = self.adapters.linux_lock_login(&detail.system_user).await;
        let _ = self.adapters.kill_user_procs(&detail.system_user).await;

        self.append_audit(
            "hosting.suspend",
            Some(detail.id.as_str()),
            &serde_json::json!({"reason": reason.label()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Undo a suspend. Brings the hosting back to 'active'.
    pub async fn resume(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Suspended {
            return Ok(());
        }
        // Re-apply effects in resume order.
        let _ = self.adapters.linux_unlock_login(&detail.system_user).await;
        if let Some(db) = detail.database.as_ref() {
            let _ = self.adapters.db_unlock(db.engine, &db.db_user).await;
        }
        if let Some(ver) = detail.php_version {
            let _ = self
                .adapters
                .fpm_ensure(&detail.system_user, &detail.domain, ver)
                .await;
            // Re-apply persisted limits to FPM pool.
            if let Ok(Some(row)) = hyperion_state::limits::get(&self.pool, &detail.id).await {
                let _ = self
                    .adapters
                    .apply_php_limits(
                        &detail.system_user,
                        &detail.domain,
                        Some(ver),
                        row.php_memory_mb,
                        row.php_max_exec_secs,
                        row.php_max_children,
                        row.php_max_requests,
                    )
                    .await;
            }
        }
        let _ = self.adapters.nginx_write_vhost(&detail).await;
        hostings::set_state(&self.pool, &detail.id, HostingState::Active, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set active: {e}")))?;
        hyperion_state::limits::delete_suspension(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete suspension: {e}")))?;
        self.append_audit("hosting.resume", Some(detail.id.as_str()), "{}", "ok")
            .await;
        Ok(())
    }

    /// Apply per-hosting vhost options. Validates fields, writes the
    /// htpasswd file (if basic auth password supplied), persists the
    /// new options row, re-renders the vhost with `nginx -t` running
    /// inside `nginx_write_vhost` — rollback on any failure.
    ///
    /// Returns the persisted options (with `basic_auth_set = true`
    /// when a password was supplied, regardless of whether it was
    /// just set or already on file).
    pub async fn set_vhost_options(
        &self,
        sel: HostingSelector,
        mut options: hyperion_types::VhostOptions,
        basic_auth_password: Option<String>,
    ) -> Result<hyperion_types::VhostOptions, RpcError> {
        let detail = self.get(sel).await?;

        // ─── Validation ─────────────────────────────────────────────
        // HSTS bounds. 0 = disabled; anything above ~2y is silly.
        if options.hsts_max_age < 0 || options.hsts_max_age > 63_072_000 {
            return Err(RpcError::Validation {
                message: "hsts_max_age must be 0..=63072000 (2 years)".into(),
            });
        }
        // FastCGI cache TTL. 0 = use a sane default; cap at 1 day
        // (caching dynamic PHP for longer is almost never right).
        if options.fastcgi_cache_ttl < 0 || options.fastcgi_cache_ttl > 86_400 {
            return Err(RpcError::Validation {
                message: "fastcgi_cache_ttl must be 0..=86400 (24h)".into(),
            });
        }
        if options.fastcgi_cache_enabled && options.fastcgi_cache_ttl == 0 {
            options.fastcgi_cache_ttl = 300; // 5 min default.
        }
        // Redirect: validated by the adapter at render time too, but
        // catch obvious mistakes early so the operator gets a clean
        // error in the UI rather than an nginx -t failure.
        if !options.redirect_url.is_empty()
            && !(options.redirect_url.starts_with("http://")
                || options.redirect_url.starts_with("https://"))
        {
            return Err(RpcError::Validation {
                message: "redirect_url must start with http:// or https://".into(),
            });
        }
        if options.redirect_code != 0
            && options.redirect_code != 301
            && options.redirect_code != 302
            && options.redirect_code != 307
            && options.redirect_code != 308
        {
            return Err(RpcError::Validation {
                message: "redirect_code must be 301, 302, 307, or 308".into(),
            });
        }
        // Basic auth: empty username with the toggle on is nonsense.
        if options.basic_auth_enabled && options.basic_auth_user.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "basic_auth_user is required when basic auth is enabled".into(),
            });
        }
        // Custom snippet length bound: prevents an operator pasting
        // a 10MB nginx config blob.
        if options.custom_nginx_snippet.len() > 32 * 1024 {
            return Err(RpcError::Validation {
                message: "custom_nginx_snippet must be ≤ 32 KiB".into(),
            });
        }

        // ─── htpasswd write (before persist, so a failed bcrypt is
        //     surfaced before we change DB state) ─────────────────────
        let pw_provided = basic_auth_password
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let mut new_hash_for_db: Option<String> = None;
        if pw_provided {
            // Unwrap safe — pw_provided implies Some(non-empty).
            let pw = basic_auth_password.as_deref().unwrap();
            // Cost 10 — same as nginx auth_basic_user_file examples;
            // bcrypt-12 starts noticeably hurting RPS on the first
            // request after a worker boot.
            let hash = bcrypt::hash(pw, 10).map_err(|e| {
                RpcError::Internal_with(format!("bcrypt hash basic-auth password: {e}"))
            })?;
            self.adapters
                .nginx_write_htpasswd(detail.id.as_str(), &options.basic_auth_user, &hash)
                .await
                .map_err(|e| RpcError::Internal_with(format!("write htpasswd: {e}")))?;
            new_hash_for_db = Some(hash);
            options.basic_auth_set = true;
        } else if !options.basic_auth_enabled {
            // Operator turned basic auth off — drop the htpasswd
            // file so it can't be re-used if they turn it back on
            // without setting a new password.
            let _ = self
                .adapters
                .nginx_delete_htpasswd(detail.id.as_str())
                .await;
            options.basic_auth_set = false;
            new_hash_for_db = Some(String::new()); // sentinel: clear
        } else {
            // basic_auth_enabled && no new password → keep existing
            // hash (set by a previous call). basic_auth_set carries
            // the truth from DB into the form.
            options.basic_auth_set = detail.vhost_options.basic_auth_set;
        }

        // ─── Persist ───────────────────────────────────────────────
        hyperion_state::hostings::set_vhost_options(
            &self.pool,
            &detail.id,
            &options,
            new_hash_for_db.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("persist vhost options: {e}")))?;

        // ─── Re-render vhost (nginx -t inside write_vhost) ─────────
        let mut new_detail = detail.clone();
        new_detail.vhost_options = options.clone();
        if let Err(e) = self.adapters.nginx_write_vhost(&new_detail).await {
            // nginx -t rejected the new vhost. Roll the DB back to
            // the old options so the persisted state matches what
            // nginx is actually serving.
            let _ = hyperion_state::hostings::set_vhost_options(
                &self.pool,
                &detail.id,
                &detail.vhost_options,
                None, // don't touch hash on rollback
                now_secs(),
            )
            .await;
            // Roll back htpasswd too if we just wrote it.
            if pw_provided {
                if detail.vhost_options.basic_auth_set {
                    // we don't have the previous hash here; the safest
                    // move is to leave the now-overwritten file in
                    // place — operator just gets to keep the new pw
                    // they typed, which they can type again. They
                    // wanted to change it anyway.
                } else {
                    let _ = self
                        .adapters
                        .nginx_delete_htpasswd(detail.id.as_str())
                        .await;
                }
            }
            return Err(RpcError::Validation {
                message: format!("nginx config rejected: {e}. No changes applied."),
            });
        }

        let audit_payload = serde_json::json!({
            "domain": detail.domain,
            "basic_auth_enabled": options.basic_auth_enabled,
            "basic_auth_user": options.basic_auth_user,
            "basic_auth_password_changed": pw_provided,
            "hsts_max_age": options.hsts_max_age,
            "maintenance_mode": options.maintenance_mode,
            "fastcgi_cache_enabled": options.fastcgi_cache_enabled,
            "fastcgi_cache_ttl": options.fastcgi_cache_ttl,
            "custom_nginx_snippet_len": options.custom_nginx_snippet.len(),
            "redirect_url_set": !options.redirect_url.is_empty(),
            "redirect_code": options.redirect_code,
        });
        self.append_audit(
            "hosting.set_vhost_options",
            Some(detail.id.as_str()),
            &audit_payload.to_string(),
            "ok",
        )
        .await;

        Ok(options)
    }

    // ───────────── WP debug + Redis ─────────────

    pub async fn set_wp_debug(
        &self,
        sel: HostingSelector,
        enabled: bool,
        log: bool,
        display: bool,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        let detail = self.get(sel).await?;
        // WP install required.
        if detail.php_version.is_none() {
            return Err(RpcError::Validation {
                message: "WP_DEBUG toggle requires a PHP hosting".into(),
            });
        }
        self.adapters
            .wp_set_debug(&detail.system_user, &detail.root_dir, enabled, log, display)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp set debug: {e}")))?;
        hyperion_state::hostings::set_wp_debug(
            &self.pool,
            &detail.id,
            enabled,
            log,
            display,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("persist wp debug: {e}")))?;
        let mut wp_extras = detail.wp_extras.clone();
        wp_extras.wp_debug_enabled = enabled;
        wp_extras.wp_debug_log = log;
        wp_extras.wp_debug_display = display;
        self.append_audit(
            "hosting.set_wp_debug",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "enabled": enabled,
                "log": log,
                "display": display,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(wp_extras)
    }

    pub async fn set_redis(
        &self,
        sel: HostingSelector,
        enabled: bool,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        let detail = self.get(sel).await?;
        if detail.php_version.is_none() {
            return Err(RpcError::Validation {
                message: "Redis cache requires a PHP hosting".into(),
            });
        }

        if !enabled {
            // Turn off: drop WP constants, delete ACL, clear DB row.
            self.adapters
                .wp_set_redis(&detail.system_user, &detail.root_dir, None)
                .await
                .map_err(|e| RpcError::Internal_with(format!("wp unset redis: {e}")))?;
            let username = redis_username_for(detail.id.as_str());
            let _ = self.adapters.redis_delete_acl(&username).await;
            hyperion_state::hostings::set_redis(
                &self.pool,
                &detail.id,
                false,
                None,
                false,
                now_secs(),
            )
            .await
            .map_err(|e| RpcError::Internal_with(format!("persist redis off: {e}")))?;
            // Clear stored password secret.
            let _ = self
                .secrets
                .delete(&hyperion_types::SecretId(format!("redis-{}", detail.id.as_str())))
                .await;
            self.append_audit(
                "hosting.set_redis",
                Some(detail.id.as_str()),
                &serde_json::json!({"domain": detail.domain, "enabled": false}).to_string(),
                "ok",
            )
            .await;
            let mut wpe = detail.wp_extras.clone();
            wpe.redis_enabled = false;
            wpe.redis_db_number = None;
            wpe.redis_password_set = false;
            return Ok(wpe);
        }

        // Preflight: redis-server must be installed + running, else
        // the ACL write would fail with a cryptic redis-cli error
        // and wp-config would still point at a host that refuses
        // connections. Detect early + surface a clear actionable
        // message pointing the operator at /services.
        if !self.adapters.redis_is_available().await {
            return Err(RpcError::Conflict {
                message: "redis-server is not installed or not active on this node. \
                          Install + start it from /services first."
                    .into(),
            });
        }

        // Turn on. Allocate a DB slot (idempotent — reuse existing on re-enable).
        let db_number = match detail.wp_extras.redis_db_number {
            Some(n) => n,
            None => {
                let n = hyperion_state::hostings::next_free_redis_db(&self.pool, 16)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("alloc redis db: {e}")))?
                    .ok_or_else(|| RpcError::Conflict {
                        message: "no free Redis DB slot (all 16 in use). Bump `databases` in \
                                  /etc/redis/redis.conf and reload."
                            .into(),
                    })?;
                n
            }
        };
        let password = generate_redis_password();
        let username = redis_username_for(detail.id.as_str());

        // Provision ACL on the local redis-server.
        self.adapters
            .redis_ensure_acl(&username, &password, db_number)
            .await
            .map_err(|e| RpcError::Internal_with(format!("redis ACL: {e}")))?;

        // Persist secret BEFORE writing wp-config — so a partial
        // failure doesn't leave wp-config pointing at a password we
        // can't recover. (Re-enabling later regenerates anyway, but
        // the operator might want to grep the secret out for an
        // external tool meanwhile.)
        let secret_id = hyperion_types::SecretId(format!("redis-{}", detail.id.as_str()));
        self.secrets
            .put(&secret_id, &password)
            .await
            .map_err(|e| RpcError::Internal_with(format!("store redis secret: {e}")))?;

        // Write WP_REDIS_* into wp-config.
        let cfg = hyperion_types::WpRedisConfig {
            host: "127.0.0.1".into(),
            port: 6379,
            database: db_number,
            username: username.clone(),
            password,
            key_prefix: format!("h{}_", db_number),
        };
        self.adapters
            .wp_set_redis(&detail.system_user, &detail.root_dir, Some(cfg))
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp set redis: {e}")))?;

        hyperion_state::hostings::set_redis(
            &self.pool,
            &detail.id,
            true,
            Some(db_number),
            true,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("persist redis: {e}")))?;
        self.append_audit(
            "hosting.set_redis",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "enabled": true,
                "db_number": db_number,
            })
            .to_string(),
            "ok",
        )
        .await;
        let mut wpe = detail.wp_extras.clone();
        wpe.redis_enabled = true;
        wpe.redis_db_number = Some(db_number);
        wpe.redis_password_set = true;
        Ok(wpe)
    }

    pub async fn rotate_redis_password(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        let detail = self.get(sel).await?;
        if !detail.wp_extras.redis_enabled {
            return Err(RpcError::Validation {
                message: "Redis not enabled for this hosting".into(),
            });
        }
        let Some(db_number) = detail.wp_extras.redis_db_number else {
            return Err(RpcError::Validation {
                message: "Redis enabled but no DB number — re-enable Redis first".into(),
            });
        };
        let password = generate_redis_password();
        let username = redis_username_for(detail.id.as_str());
        self.adapters
            .redis_ensure_acl(&username, &password, db_number)
            .await
            .map_err(|e| RpcError::Internal_with(format!("redis ACL rotate: {e}")))?;
        let secret_id = hyperion_types::SecretId(format!("redis-{}", detail.id.as_str()));
        self.secrets
            .put(&secret_id, &password)
            .await
            .map_err(|e| RpcError::Internal_with(format!("store redis secret: {e}")))?;
        let cfg = hyperion_types::WpRedisConfig {
            host: "127.0.0.1".into(),
            port: 6379,
            database: db_number,
            username,
            password,
            key_prefix: format!("h{}_", db_number),
        };
        self.adapters
            .wp_set_redis(&detail.system_user, &detail.root_dir, Some(cfg))
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp re-set redis: {e}")))?;
        self.append_audit(
            "hosting.rotate_redis_password",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        Ok(detail.wp_extras)
    }

    pub async fn rotate_wp_debug_log(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // truncate via Linux only. Caller's responsibility to verify
        // hosting exists (.get already does).
        let p = std::path::Path::new(&detail.root_dir).join("wp-content/debug.log");
        // best-effort — if file is missing, we Ok anyway.
        match tokio::fs::File::create(&p).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(RpcError::Internal_with(format!(
                    "truncate debug.log: {e}"
                )));
            }
        }
        // Update sampled size in DB so the UI reflects the new state.
        let _ = hyperion_state::hostings::set_wp_debug_log_size(&self.pool, &detail.id, 0).await;
        self.append_audit(
            "hosting.rotate_wp_debug_log",
            Some(detail.id.as_str()),
            &serde_json::json!({"domain": detail.domain}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn usage(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<hyperion_types::HostingUsageBucket>, RpcError> {
        let detail = self.get(sel).await?;
        let rows = hyperion_state::limits::usage_for(&self.pool, &detail.id, limit.max(1).min(744))
            .await
            .map_err(|e| RpcError::Internal_with(format!("usage: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|b| hyperion_types::HostingUsageBucket {
                period: b.period,
                disk_used_bytes: b.disk_used_bytes,
                inodes_used: b.inodes_used,
                bw_in_bytes: b.bw_in_bytes,
                bw_out_bytes: b.bw_out_bytes,
                php_requests: b.php_requests,
            })
            .collect())
    }

    pub async fn set_expiry(
        &self,
        sel: HostingSelector,
        expiry: hyperion_types::HostingExpiry,
    ) -> Result<hyperion_types::HostingExpiry, RpcError> {
        let detail = self.get(sel).await?;
        let grace = expiry.grace_days.clamp(1, 365);
        let offsets = hyperion_state::scheduler::parse_offsets(&expiry.warning_offsets_days);
        let csv = if offsets.is_empty() {
            "30,7,1".to_string()
        } else {
            offsets
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        hyperion_state::scheduler::set_expiry(
            &self.pool,
            &detail.id,
            expiry.expires_at,
            expiry.owner_email.as_deref(),
            grace,
            &csv,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set_expiry: {e}")))?;
        // Cancel any previously-queued actions and re-schedule from scratch.
        hyperion_state::scheduler::cancel_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cancel: {e}")))?;
        if let Some(exp) = expiry.expires_at {
            self.reschedule_actions_for(&detail.id, exp, grace, &offsets)
                .await?;
        }
        self.append_audit(
            "hosting.set_expiry",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "expires_at": expiry.expires_at,
                "grace_days": grace,
            })
            .to_string(),
            "ok",
        )
        .await;
        let updated = hyperion_state::scheduler::get_expiry(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get_expiry: {e}")))?
            .ok_or(RpcError::Internal)?;
        Ok(expiry_row_to_dto(updated))
    }

    pub async fn get_expiry(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingExpiry, RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::scheduler::get_expiry(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get_expiry: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.0.clone(),
            })?;
        Ok(expiry_row_to_dto(row))
    }

    pub async fn clear_expiry(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        hyperion_state::scheduler::set_expiry(
            &self.pool,
            &detail.id,
            None,
            None,
            30,
            "30,7,1",
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("clear: {e}")))?;
        hyperion_state::scheduler::cancel_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cancel: {e}")))?;
        self.append_audit("hosting.clear_expiry", Some(detail.id.as_str()), "{}", "ok")
            .await;
        Ok(())
    }

    pub async fn upcoming_expiries(
        &self,
        within_seconds: i64,
    ) -> Result<Vec<hyperion_types::ExpiringHosting>, RpcError> {
        let rows = hyperion_state::scheduler::list_with_expiry(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        let cutoff = now_secs() + within_seconds.max(0);
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let exp = r.expires_at?;
                if exp <= cutoff {
                    Some(hyperion_types::ExpiringHosting {
                        id: r.id,
                        domain: r.domain,
                        expires_at: exp,
                        owner_email: r.owner_email,
                        grace_days: r.grace_days,
                    })
                } else {
                    None
                }
            })
            .collect())
    }

    /// Drive one tick of the scheduler. Returns the number of actions
    /// processed (success + failed). Designed to be called both manually
    /// and from a tokio interval task in hyperion-agent.
    pub async fn scheduler_tick(&self) -> Result<i64, RpcError> {
        // 1. Make sure every hosting with an expires_at has its scheduled rows.
        self.reconcile_scheduled_rows()
            .await
            .map_err(|e| RpcError::Internal_with(format!("reconcile: {e}")))?;

        // 2. Take a slice of due, pending actions.
        let now = now_secs();
        let due = hyperion_state::scheduler::pending_due(&self.pool, now, 100)
            .await
            .map_err(|e| RpcError::Internal_with(format!("pending_due: {e}")))?;
        let mut processed = 0i64;
        for action in due {
            hyperion_state::scheduler::mark_running(&self.pool, action.id, now)
                .await
                .map_err(|e| RpcError::Internal_with(format!("mark_running: {e}")))?;
            let result = self.run_action(&action).await;
            match result {
                Ok(()) => {
                    hyperion_state::scheduler::mark_done(&self.pool, action.id)
                        .await
                        .map_err(|e| RpcError::Internal_with(format!("mark_done: {e}")))?;
                }
                Err(e) => {
                    tracing::warn!(action_id=action.id, error=%e, "scheduled action failed");
                    hyperion_state::scheduler::mark_failed_or_retry(&self.pool, action.id, &e, 3)
                        .await
                        .map_err(|e| RpcError::Internal_with(format!("mark_failed: {e}")))?;
                }
            }
            processed += 1;
        }

        // Best-effort housekeeping: wipe migration bundle dirs older
        // than 7 days. Operators frequently forget to clean these up
        // after a migration completes, and they can be many GB
        // (entire wp-content trees). Failure here is non-fatal — log
        // and continue.
        if let Err(e) = self.prune_old_migration_bundles().await {
            tracing::warn!(error=%e, "migration bundle prune failed");
        }
        // Trash GC: hard-delete any trashed hosting past the
        // retention window. No-op when cluster.trash_enabled = false.
        if let Err(e) = self.trash_gc_tick().await {
            tracing::warn!(error=%e, "trash GC failed");
        }
        // Audit retention: purge audit_log entries older than the
        // configured window. No-op when audit_retention_days = 0
        // (the default — keep forever). Updates the chain anchor
        // so verify_chain keeps working on the truncated chain.
        if let Err(e) = self.audit_retention_tick().await {
            tracing::warn!(error=%e, "audit retention failed");
        }
        Ok(processed)
    }

    /// Purge audit_log entries older than `cluster.audit_retention_days`.
    /// No-op when the setting is 0. Logs an info line each time entries
    /// are actually purged so operators see "I lost N audit rows on
    /// 2026-06-09" in journald — important context if anyone ever
    /// challenges the chain.
    pub(crate) async fn audit_retention_tick(&self) -> Result<(), RpcError> {
        let cluster_cfg = read_cluster_section(self.agent_config_path.as_deref());
        if cluster_cfg.audit_retention_days <= 0 {
            return Ok(());
        }
        let cutoff = now_secs() - cluster_cfg.audit_retention_days * 86_400;
        let (deleted, new_anchor) =
            hyperion_state::audit::purge_older_than(&self.pool, cutoff, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("audit purge: {e}")))?;
        if deleted > 0 {
            tracing::info!(
                deleted,
                retention_days = cluster_cfg.audit_retention_days,
                anchor_set = new_anchor.is_some(),
                "audit retention purge"
            );
        }
        Ok(())
    }

    /// Remove `/var/lib/hyperion/migration/<id>/` directories whose
    /// mtime is older than 7 days. The bundle download URL also
    /// expires after ~1h, so anything older than a week is dead
    /// inventory the operator clearly no longer needs.
    pub(crate) async fn prune_old_migration_bundles(&self) -> Result<u32, RpcError> {
        prune_migration_bundle_dir(
            &std::path::PathBuf::from("/var/lib/hyperion/migration"),
            std::time::Duration::from_secs(7 * 86_400),
        )
        .await
    }

    async fn reconcile_scheduled_rows(&self) -> Result<(), hyperion_state::StateError> {
        let rows = hyperion_state::scheduler::list_with_expiry(&self.pool).await?;
        let now = now_secs();
        for r in rows {
            let Some(exp) = r.expires_at else { continue };
            let offsets = hyperion_state::scheduler::parse_offsets(&r.warning_offsets_days);
            // Map each offset to a notification kind. Beyond the spec's
            // 30/7/1-day defaults we still queue extras, but we tag any
            // offset >= 30 as Notify30d, 7..30 as Notify7d, <7 as Notify1d
            // (good-enough bucketing for v1).
            for offset_days in &offsets {
                let kind = if *offset_days >= 30 {
                    hyperion_state::scheduler::ScheduledKind::Notify30d
                } else if *offset_days >= 7 {
                    hyperion_state::scheduler::ScheduledKind::Notify7d
                } else {
                    hyperion_state::scheduler::ScheduledKind::Notify1d
                };
                let due = exp - offset_days * 86_400;
                if due > now - 7 * 86_400 {
                    hyperion_state::scheduler::upsert(&self.pool, &r.id, kind, due, now).await?;
                }
            }
            hyperion_state::scheduler::upsert(
                &self.pool,
                &r.id,
                hyperion_state::scheduler::ScheduledKind::SuspendExpired,
                exp,
                now,
            )
            .await?;
            let delete_at = exp + r.grace_days.max(1) * 86_400;
            hyperion_state::scheduler::upsert(
                &self.pool,
                &r.id,
                hyperion_state::scheduler::ScheduledKind::DeleteExpired,
                delete_at,
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn reschedule_actions_for(
        &self,
        id: &HostingId,
        expires_at: i64,
        grace_days: i64,
        offsets: &[i64],
    ) -> Result<(), RpcError> {
        let now = now_secs();
        for offset_days in offsets {
            let kind = if *offset_days >= 30 {
                hyperion_state::scheduler::ScheduledKind::Notify30d
            } else if *offset_days >= 7 {
                hyperion_state::scheduler::ScheduledKind::Notify7d
            } else {
                hyperion_state::scheduler::ScheduledKind::Notify1d
            };
            let due = expires_at - offset_days * 86_400;
            if due > now - 7 * 86_400 {
                hyperion_state::scheduler::upsert(&self.pool, id, kind, due, now)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
            }
        }
        hyperion_state::scheduler::upsert(
            &self.pool,
            id,
            hyperion_state::scheduler::ScheduledKind::SuspendExpired,
            expires_at,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
        let delete_at = expires_at + grace_days.max(1) * 86_400;
        hyperion_state::scheduler::upsert(
            &self.pool,
            id,
            hyperion_state::scheduler::ScheduledKind::DeleteExpired,
            delete_at,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("upsert: {e}")))?;
        Ok(())
    }

    async fn run_action(
        &self,
        action: &hyperion_state::scheduler::ScheduledRow,
    ) -> Result<(), String> {
        use hyperion_state::scheduler::ScheduledKind;
        match action.action {
            ScheduledKind::Notify30d | ScheduledKind::Notify7d | ScheduledKind::Notify1d => {
                // Foundation: we log the notification. Real SMTP integration
                // is config-gated and ships with the controller (sub-project 4).
                let row = hyperion_state::scheduler::get_expiry(&self.pool, &action.hosting_id)
                    .await
                    .map_err(|e| e.to_string())?;
                let email = row.as_ref().and_then(|r| r.owner_email.as_deref());
                tracing::info!(
                    hosting=%action.hosting_id, action=action.action.as_str(),
                    owner=email.unwrap_or("<none>"),
                    "expiry notification due",
                );
                self.append_audit(
                    "scheduler.notify",
                    Some(action.hosting_id.as_str()),
                    &serde_json::json!({"kind": action.action.as_str()}).to_string(),
                    "ok",
                )
                .await;
                Ok(())
            }
            ScheduledKind::SuspendExpired => self
                .suspend(
                    HostingSelector::Id(action.hosting_id.clone()),
                    hyperion_types::SuspendReason::Expired,
                )
                .await
                .map_err(|e| e.to_string()),
            ScheduledKind::DeleteExpired => self
                .delete(
                    HostingSelector::Id(action.hosting_id.clone()),
                    hyperion_rpc::wire::DeleteOpts::default(),
                )
                .await
                .map_err(|e| e.to_string()),
        }
    }

    /// Produce a tar.gz + DB dump backup. Single 'local' target for v1.
    pub async fn backup_now(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::BackupRunWire, RpcError> {
        let detail = self.get(sel).await?;
        let backup_root = self.paths.backup_root.clone();
        let run_id = hyperion_state::backups::start(&self.pool, &detail.id, "local", now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup start: {e}")))?;
        // Build target dir
        let ts = now_secs();
        let archive_dir = std::path::PathBuf::from(&backup_root).join(&detail.system_user);
        let archive_name = format!("{}-{}.tar.gz", detail.domain, ts);
        let archive_path = archive_dir.join(&archive_name);
        let db_dump_path = detail
            .database
            .as_ref()
            .map(|_| archive_dir.join(format!("{}-{}.sql", detail.domain, ts)));

        // Run the backup. Failures roll the row to 'failed'.
        let result: Result<(u64, Option<u64>), String> = async {
            // 1. Archive htdocs (parent of htdocs)
            let host_root = std::path::PathBuf::from(&self.paths.home_root)
                .join(&detail.system_user)
                .join(&detail.domain);
            let archive_bytes =
                hyperion_adapters::backup::make_archive(&host_root, "htdocs", &archive_path)
                    .await
                    .map_err(|e| format!("archive: {e}"))?;
            // 2. Optional DB dump.
            let dump_bytes = if let (Some(db), Some(dump_p)) =
                (detail.database.as_ref(), db_dump_path.as_ref())
            {
                let n = match db.engine {
                    hyperion_types::DbProvision::MariaDB => {
                        hyperion_adapters::backup::dump_mariadb(&db.db_name, dump_p).await
                    }
                    hyperion_types::DbProvision::Postgres => {
                        hyperion_adapters::backup::dump_postgres(&db.db_name, dump_p).await
                    }
                };
                Some(n.map_err(|e| format!("db dump: {e}"))?)
            } else {
                None
            };
            // 3. Write manifest next to archive.
            let manifest = hyperion_adapters::backup::BackupManifest {
                hosting_id: detail.id.0.clone(),
                domain: detail.domain.clone(),
                system_user: detail.system_user.clone(),
                php_version: detail.php_version.map(|v| v.as_str().to_string()),
                database: detail.database.as_ref().map(|db| {
                    hyperion_adapters::backup::ManifestDb {
                        engine: hyperion_adapters::backup::engine_str(db.engine).to_string(),
                        name: db.db_name.clone(),
                        user: db.db_user.clone(),
                    }
                }),
                started_at: ts,
                schema_version: 1,
            };
            let manifest_path = archive_dir.join(format!("{}-{}.manifest.json", detail.domain, ts));
            hyperion_adapters::backup::write_manifest(&manifest, &manifest_path)
                .await
                .map_err(|e| format!("manifest: {e}"))?;
            Ok((archive_bytes, dump_bytes))
        }
        .await;

        match result {
            Ok((archive_bytes, dump_bytes)) => {
                let total = archive_bytes as i64 + dump_bytes.unwrap_or(0) as i64;
                let dump_str = db_dump_path.as_ref().map(|p| p.display().to_string());
                hyperion_state::backups::mark_ok(
                    &self.pool,
                    run_id,
                    &archive_path.display().to_string(),
                    dump_str.as_deref(),
                    total,
                    now_secs(),
                )
                .await
                .map_err(|e| RpcError::Internal_with(format!("mark_ok: {e}")))?;
                self.append_audit(
                    "hosting.backup",
                    Some(detail.id.as_str()),
                    &serde_json::json!({"target":"local","bytes":total}).to_string(),
                    "ok",
                )
                .await;

                // Optional remote push. Failures don't roll back the
                // local backup row — operator still has the local copy.
                if let Some(remote) = &self.remote_backup {
                    let hosting_dir = format!(
                        "{}/{}",
                        remote.base_path.trim_end_matches('/'),
                        detail.system_user
                    );
                    let upload = hyperion_adapters::backup::RemoteUpload {
                        scheme: &remote.scheme,
                        host: &remote.host,
                        port: remote.port,
                        user: &remote.user,
                        password: &remote.password,
                        remote_dir: &hosting_dir,
                    };
                    let archive_result =
                        hyperion_adapters::backup::upload_remote(&archive_path, &upload).await;
                    let dump_result = if let Some(p) = db_dump_path.as_ref() {
                        Some(hyperion_adapters::backup::upload_remote(p, &upload).await)
                    } else {
                        None
                    };
                    let (ok, note) = match (&archive_result, &dump_result) {
                        (Ok(_), None) => (true, "archive pushed".to_string()),
                        (Ok(_), Some(Ok(_))) => (true, "archive + dump pushed".into()),
                        (Ok(_), Some(Err(e))) => {
                            (false, format!("archive ok, dump failed: {e}"))
                        }
                        (Err(e), _) => (false, format!("archive push failed: {e}")),
                    };
                    self.append_audit(
                        "hosting.backup.remote",
                        Some(detail.id.as_str()),
                        &serde_json::json!({
                            "scheme": remote.scheme,
                            "host": remote.host,
                            "dir": hosting_dir,
                            "note": note,
                        })
                        .to_string(),
                        if ok { "ok" } else { "failed" },
                    )
                    .await;
                    if !ok {
                        tracing::warn!(domain=%detail.domain, note=%note, "remote backup push failed");
                    }
                }
            }
            Err(e) => {
                let trimmed: String = e.chars().take(2000).collect();
                hyperion_state::backups::mark_failed(&self.pool, run_id, &trimmed, now_secs())
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("mark_failed: {e}")))?;
                return Err(RpcError::ProvisioningFailed {
                    stage: "backup".into(),
                    reason: trimmed,
                });
            }
        }
        // Apply retention policy. Failures are audit-logged but don't
        // propagate — operator still has the just-made backup.
        if let Err(e) = self.prune_old_backups(&detail.id).await {
            tracing::warn!(domain=%detail.domain, error=%e, "backup retention prune failed");
        }

        let rows = hyperion_state::backups::list_for(&self.pool, &detail.id, 1)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list_for: {e}")))?;
        let r = rows.into_iter().next().ok_or(RpcError::Internal)?;
        Ok(run_to_wire(r))
    }

    /// Drop backup archives older than `retention.max_age_days` from disk
    /// AND from the backup_runs table, keeping the newest
    /// `retention.keep_latest_n` per hosting regardless of age.
    pub(crate) async fn prune_old_backups(
        &self,
        hosting_id: &HostingId,
    ) -> Result<u64, RpcError> {
        let rows = hyperion_state::backups::list_for(&self.pool, hosting_id, 1000)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list_for: {e}")))?;
        let cutoff = now_secs() - self.retention.max_age_days.max(1) * 24 * 3600;
        let mut pruned = 0u64;
        // Newest-first; skip the first keep_latest_n.
        for r in rows.into_iter().skip(self.retention.keep_latest_n.max(1) as usize) {
            if r.started_at >= cutoff {
                continue;
            }
            if let Some(p) = r.archive_path.as_deref() {
                let _ = tokio::fs::remove_file(p).await;
            }
            if let Some(p) = r.db_dump_path.as_deref() {
                let _ = tokio::fs::remove_file(p).await;
            }
            if let Err(e) = hyperion_state::backups::delete_by_id(&self.pool, r.id).await {
                tracing::warn!(id = r.id, error=%e, "delete backup row");
                continue;
            }
            pruned += 1;
        }
        if pruned > 0 {
            self.append_audit(
                "hosting.backup.prune",
                Some(hosting_id.as_str()),
                &serde_json::json!({"pruned": pruned}).to_string(),
                "ok",
            )
            .await;
        }
        Ok(pruned)
    }

    pub async fn backup_list(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<hyperion_types::BackupRunWire>, RpcError> {
        let detail = self.get(sel).await?;
        let rows = hyperion_state::backups::list_for(&self.pool, &detail.id, limit.max(1).min(500))
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        Ok(rows.into_iter().map(run_to_wire).collect())
    }

    /// Install WordPress into an existing hosting.
    ///
    /// Preconditions: hosting state is Active, hosting has a MariaDB
    /// (Postgres is rejected — WordPress doesn't support it natively),
    /// admin credentials are well-formed.
    ///
    /// Side effects: downloads WP core into `htdocs`, writes
    /// `wp-config.php`, populates the DB with WP tables, records a row
    /// in `wp_installs`, appends an audit entry.
    pub async fn install_wordpress(
        &self,
        sel: HostingSelector,
        req: WpInstallRequest,
    ) -> Result<WpInstallStatus, RpcError> {
        // Light validation here. Adapter does locale/version regex.
        if req.site_url.trim().is_empty()
            || req.title.trim().is_empty()
            || req.admin_user.trim().is_empty()
            || req.admin_email.trim().is_empty()
        {
            return Err(RpcError::Validation {
                message: "site_url, title, admin_user, admin_email must all be non-empty".into(),
            });
        }
        if req.admin_password.is_empty() {
            return Err(RpcError::Validation {
                message: "admin_password must be non-empty".into(),
            });
        }
        if !req.admin_email.contains('@') {
            return Err(RpcError::Validation {
                message: "admin_email must be a valid address".into(),
            });
        }
        if !req.site_url.starts_with("http://") && !req.site_url.starts_with("https://") {
            return Err(RpcError::Validation {
                message: "site_url must include http(s):// scheme".into(),
            });
        }

        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: format!(
                    "hosting {} is in state {:?}; resume it before installing WordPress",
                    detail.domain, detail.state
                ),
            });
        }
        let db_row = databases::get_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("db lookup: {e}")))?
            .ok_or(RpcError::Conflict {
                message: format!(
                    "hosting {} has no database — WordPress needs MariaDB",
                    detail.domain
                ),
            })?;
        if db_row.engine != DbProvision::MariaDB {
            return Err(RpcError::Conflict {
                message: format!(
                    "WordPress requires MariaDB; hosting {} uses {:?}",
                    detail.domain, db_row.engine
                ),
            });
        }

        // Read the plaintext DB password from the secrets store.
        #[derive(serde::Deserialize)]
        struct StoredDbCred {
            password: String,
        }
        let stored: StoredDbCred = self
            .secrets
            .get(&db_row.secret_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("secret read: {e}")))?;

        // Reject re-install for now — operator must manually clear
        // wp_installs + wipe DB to redo. This avoids stomping on a live
        // site through fat-fingered UI.
        if wordpress::get_install(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp lookup: {e}")))?
            .is_some()
        {
            return Err(RpcError::Conflict {
                message: format!(
                    "WordPress already installed on {} — drop the row from wp_installs first",
                    detail.domain
                ),
            });
        }
        // Belt-and-braces: even if the DB row is missing, an
        // existing wp-config.php on disk means WP IS installed
        // (Hyperion-managed install that lost its row, SSH
        // install, migration). Refuse the install rather than
        // wipe the DB + clobber the directory with `wp core
        // download`. wp_status() would have already adopted it
        // into the row on the previous page load, but a stale
        // tab whose form was authored before adoption could
        // still land here.
        if let Some(ver) = detect_wp_install_on_disk(&detail.root_dir).await {
            return Err(RpcError::Conflict {
                message: format!(
                    "WordPress is already on disk at {} (version {ver}). \
                     Refresh the hosting detail page — the install was \
                     adopted into the panel and the install form should \
                     no longer be shown.",
                    detail.root_dir
                ),
            });
        }

        let installed_version = self
            .adapters
            .wp_install_run(
                &detail.system_user,
                &detail.root_dir,
                &db_row.db_name,
                &db_row.db_user,
                &stored.password,
                "localhost",
                &req,
            )
            .await
            .map_err(|e| match e {
                AdapterError::Command { code, .. } => RpcError::ProvisioningFailed {
                    stage: "wp_install".into(),
                    reason: format!("wp-cli failed with exit {code}: {e}"),
                },
                other => other.into(),
            })?;

        // Stable hash describing what we installed. Without an app_pack
        // this is just "vanilla-<version>-<locale>" so re-applying the
        // same options is detectable later.
        let manifest_marker = format!(
            "vanilla-{}-{}",
            installed_version.trim(),
            req.locale.trim()
        );
        let pack_hash = wordpress::pack_hash(&manifest_marker);
        let now = now_secs();
        wordpress::record_install(
            &self.pool,
            &detail.id,
            &req.site_url,
            &installed_version,
            &pack_hash,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("record_install: {e}")))?;

        self.append_audit(
            "wordpress.install",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "site_url": req.site_url,
                "locale": req.locale,
                "version": installed_version.trim(),
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok(WpInstallStatus {
            hosting_id: detail.id.clone(),
            site_url: req.site_url,
            wp_version: installed_version.trim().to_string(),
            installed_at: now,
            last_pack_hash: pack_hash,
        })
    }

    /// Reset the WordPress admin password via `wp user update --user_pass`.
    pub async fn wp_reset_password(
        &self,
        sel: HostingSelector,
        wp_user: String,
        new_password: String,
    ) -> Result<(), RpcError> {
        if new_password.len() < 8 {
            return Err(RpcError::Validation {
                message: "new password must be at least 8 characters".into(),
            });
        }
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to reset WP password".into(),
            });
        }
        // Use wp user update <user> --user_pass=<pw> ... but feed password
        // through stdin via --prompt if wp-cli supports it. For simplicity
        // pass --user_pass=<pw> directly; arg array prevents shell injection.
        let user_arg = format!("--user_pass={new_password}");
        let wp_args: [&str; 5] = [
            "user",
            "update",
            &wp_user,
            &user_arg,
            "--skip-email",
        ];
        let argv = hyperion_adapters::wpcli::build_argv(
            &detail.system_user,
            &detail.root_dir,
            &wp_args,
        );
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        hyperion_adapters::cmd::run("/usr/bin/sudo", &argv_refs)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_reset_password".into(),
                reason: e.to_string(),
            })?;
        self.append_audit(
            "wordpress.reset_password",
            Some(detail.id.as_str()),
            &serde_json::json!({"wp_user": wp_user}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Set / replace the FTP (Linux) password for the hosting's
    /// system user. Empty input → generate a random 20-char password
    /// and return it. Caller is expected to show the returned password
    /// to the operator exactly once.
    pub async fn ftp_set_password(
        &self,
        sel: HostingSelector,
        new_password: String,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state == HostingState::Deleting {
            return Err(RpcError::Conflict {
                message: "cannot set FTP password on a deleting hosting".into(),
            });
        }
        let password = if new_password.trim().is_empty() {
            hyperion_adapters::random_password()
        } else {
            if new_password.len() < 12 {
                return Err(RpcError::Validation {
                    message: "FTP password must be at least 12 characters".into(),
                });
            }
            new_password
        };
        hyperion_adapters::ftp::ensure_vsftpd_running()
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "vsftpd".into(),
                reason: e.to_string(),
            })?;
        hyperion_adapters::ftp::set_user_password(&detail.system_user, &password)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "chpasswd".into(),
                reason: e.to_string(),
            })?;
        self.append_audit(
            "hosting.ftp.set_password",
            Some(detail.id.as_str()),
            &serde_json::json!({"user": detail.system_user}).to_string(),
            "ok",
        )
        .await;
        Ok(password)
    }

    /// Disable FTP for the hosting's system user (`passwd -d <user>`).
    pub async fn ftp_disable(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        hyperion_adapters::ftp::clear_user_password(&detail.system_user)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "passwd_disable".into(),
                reason: e.to_string(),
            })?;
        self.append_audit(
            "hosting.ftp.disable",
            Some(detail.id.as_str()),
            &serde_json::json!({"user": detail.system_user}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Reset the DB password for a hosting, persisting the new secret.
    pub async fn db_reset_password(
        &self,
        sel: HostingSelector,
        new_password: String,
    ) -> Result<(), RpcError> {
        if new_password.len() < 12 {
            return Err(RpcError::Validation {
                message: "new password must be at least 12 characters".into(),
            });
        }
        let detail = self.get(sel).await?;
        let db_row = databases::get_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("db lookup: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "database".into(),
                id: detail.domain.clone(),
            })?;

        match db_row.engine {
            DbProvision::MariaDB => {
                hyperion_adapters::mariadb::reset_password(&db_row.db_user, &new_password)
                    .await
                    .map_err(|e| RpcError::ProvisioningFailed {
                        stage: "mariadb_reset".into(),
                        reason: e.to_string(),
                    })?;
            }
            DbProvision::Postgres => {
                hyperion_adapters::postgres::reset_password(&db_row.db_user, &new_password)
                    .await
                    .map_err(|e| RpcError::ProvisioningFailed {
                        stage: "postgres_reset".into(),
                        reason: e.to_string(),
                    })?;
            }
        }

        // Re-persist the secret. We re-fetch & overwrite the existing
        // record so the password matches what the operator now wants.
        self.secrets
            .put(
                &db_row.secret_id,
                &serde_json::json!({
                    "engine": db_row.engine.as_str(),
                    "db_name": db_row.db_name,
                    "db_user": db_row.db_user,
                    "password": new_password,
                }),
            )
            .await
            .map_err(|e| RpcError::Internal_with(format!("secret update: {e}")))?;

        self.append_audit(
            "database.reset_password",
            Some(detail.id.as_str()),
            &serde_json::json!({"engine": db_row.engine.as_str()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Return the recorded WordPress install for a hosting, if any.
    ///
    /// Self-healing: when the `wp_installs` row is missing but
    /// `<root_dir>/wp-config.php` + `<root_dir>/wp-includes/
    /// version.php` are both present on disk, WordPress IS installed
    /// (most likely Hyperion's record_install lost the write to a
    /// network glitch / DB lock; or the operator installed via SSH /
    /// migrated from another panel). We:
    ///   1. Parse `$wp_version` out of `wp-includes/version.php`
    ///      with a regex (no shell-out — fast, no wp-cli dep).
    ///   2. Insert the recovered row into `wp_installs` so the
    ///      next call hits the fast DB path.
    ///   3. Append an audit entry so the operator can trace the
    ///      adoption back to a specific moment.
    /// This means a fresh-create that "lost" the install record
    /// recovers transparently on the very next page load — the
    /// operator never sees a spurious "Install WordPress" form
    /// for an already-installed site.
    pub async fn wp_status(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<WpInstallStatus>, RpcError> {
        let detail = self.get(sel).await?;
        if let Some(row) = wordpress::get_install(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp lookup: {e}")))?
        {
            return Ok(Some(WpInstallStatus {
                hosting_id: row.hosting_id,
                site_url: row.site_url,
                wp_version: row.wp_version,
                installed_at: row.installed_at,
                last_pack_hash: row.last_pack_hash,
            }));
        }
        // Filesystem fallback. Skip for non-php hostings (no WP
        // possible) and for empty root_dir (provisioning state).
        if detail.root_dir.is_empty() {
            return Ok(None);
        }
        let Some(detected_version) = detect_wp_install_on_disk(&detail.root_dir).await
        else {
            return Ok(None);
        };
        // Self-heal: record the detected install so subsequent
        // page loads don't re-probe the filesystem.
        let site_url = format!("https://{}", detail.domain);
        let pack_hash = wordpress::pack_hash(&format!(
            "detected-{}-{}",
            detected_version.trim(),
            detail.id.as_str()
        ));
        let now = now_secs();
        if let Err(e) = wordpress::record_install(
            &self.pool,
            &detail.id,
            &site_url,
            &detected_version,
            &pack_hash,
            now,
        )
        .await
        {
            tracing::warn!(
                hosting_id = %detail.id.as_str(),
                error = %e,
                "wp_status: detected WP on disk but record_install failed (will retry next call)"
            );
        } else {
            self.append_audit(
                "wordpress.detected",
                Some(detail.id.as_str()),
                &serde_json::json!({
                    "site_url": site_url,
                    "version": detected_version.trim(),
                    "reason": "filesystem fallback in wp_status",
                })
                .to_string(),
                "ok",
            )
            .await;
            tracing::info!(
                hosting_id = %detail.id.as_str(),
                version = %detected_version,
                "wp_status: adopted on-disk WP install into wp_installs"
            );
        }
        Ok(Some(WpInstallStatus {
            hosting_id: detail.id.clone(),
            site_url,
            wp_version: detected_version,
            installed_at: now,
            last_pack_hash: pack_hash,
        }))
    }

    /// List installed WordPress plugins for a hosting. Returns the
    /// plugin table + wp version + Hyperion's bulk auto-update flag
    /// (which controls whether the daily updater touches plugins at
    /// all; per-plugin auto-update is a separate WP-level setting).
    pub async fn wp_plugin_list(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpPluginListResponse, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to list plugins".into(),
            });
        }
        let (plugins, wp_version) = self
            .adapters
            .wp_plugin_list(&detail.system_user, &detail.root_dir)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_plugin_list".into(),
                reason: e.to_string(),
            })?;
        let bulk_auto_update = wordpress::get_install(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp lookup: {e}")))?
            .map(|r| r.auto_update_plugins)
            .unwrap_or(false);
        let updates_pending = plugins.iter().filter(|p| p.update_available).count() as i64;
        Ok(hyperion_types::WpPluginListResponse {
            plugins,
            wp_version,
            updates_pending,
            bulk_auto_update,
        })
    }

    /// Apply one plugin action (install/activate/deactivate/update/
    /// delete/auto-update toggle) via wp-cli. Every action is
    /// audit-logged with the action kind + slug (never the source URL
    /// when it carries auth).
    pub async fn wp_plugin_action(
        &self,
        sel: HostingSelector,
        slug: String,
        action: hyperion_types::WpPluginAction,
    ) -> Result<hyperion_types::WpPluginActionResult, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to manage plugins".into(),
            });
        }
        let out = self
            .adapters
            .wp_plugin_action(&detail.system_user, &detail.root_dir, &slug, &action)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_plugin_action".into(),
                reason: e.to_string(),
            })?;
        let action_label = match &action {
            hyperion_types::WpPluginAction::Install { .. } => "install",
            hyperion_types::WpPluginAction::Activate => "activate",
            hyperion_types::WpPluginAction::Deactivate => "deactivate",
            hyperion_types::WpPluginAction::Update => "update",
            hyperion_types::WpPluginAction::UpdateAll => "update_all",
            hyperion_types::WpPluginAction::Delete => "delete",
            hyperion_types::WpPluginAction::SetAutoUpdate { enabled } => {
                if *enabled { "auto_update_enable" } else { "auto_update_disable" }
            }
        };
        self.append_audit(
            "wp.plugin.action",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "action": action_label,
                "slug": slug,
                "state": out.state,
            }).to_string(),
            &out.state,
        )
        .await;
        Ok(out)
    }

    /// `wp theme list` for a hosting. Mirrors wp_plugin_list shape.
    pub async fn wp_theme_list(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpThemeListResponse, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to list themes".into(),
            });
        }
        let (themes, wp_version) = self
            .adapters
            .wp_theme_list(&detail.system_user, &detail.root_dir)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_theme_list".into(),
                reason: e.to_string(),
            })?;
        let updates_pending = themes.iter().filter(|t| t.update_available).count() as i64;
        Ok(hyperion_types::WpThemeListResponse {
            themes,
            wp_version,
            updates_pending,
        })
    }

    /// Apply one theme action (install / activate / update / delete /
    /// update-all) via wp-cli. Audit-logged with the action label +
    /// slug.
    pub async fn wp_theme_action(
        &self,
        sel: HostingSelector,
        slug: String,
        action: hyperion_types::WpThemeAction,
    ) -> Result<hyperion_types::WpThemeActionResult, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to manage themes".into(),
            });
        }
        let out = self
            .adapters
            .wp_theme_action(&detail.system_user, &detail.root_dir, &slug, &action)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "wp_theme_action".into(),
                reason: e.to_string(),
            })?;
        let action_label = match &action {
            hyperion_types::WpThemeAction::Install { .. } => "install",
            hyperion_types::WpThemeAction::Activate => "activate",
            hyperion_types::WpThemeAction::Update => "update",
            hyperion_types::WpThemeAction::UpdateAll => "update_all",
            hyperion_types::WpThemeAction::Delete => "delete",
        };
        self.append_audit(
            "wp.theme.action",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "action": action_label,
                "slug": slug,
                "state": out.state,
            })
            .to_string(),
            &out.state,
        )
        .await;
        Ok(out)
    }

    /// Export a hosting as a self-contained migration bundle: an
    /// archive (tar+gz of htdocs + optional DB dump) plus a JSON
    /// manifest describing how to recreate the hosting on a different
    /// node. The bundle lives at `/var/lib/hyperion/migration/<id>/`
    /// — the operator transfers it out-of-band (scp/rsync/S3) and
    /// runs `hctl hosting import --bundle <file>` on the target.
    /// Read one whitelisted file from
    /// `/var/lib/hyperion/migration/<bundle_id>/` and return its
    /// bytes as base64. Used by the master to pull a bundle off
    /// a worker source during worker-to-X migration.
    ///
    /// Whitelist: "manifest.json" or "archive.tar.gz" only. Both
    /// the bundle_id and the filename are validated to refuse
    /// path traversal — ULID-shape for bundle_id, exact match for
    /// filename.
    pub async fn hosting_migration_fetch_bundle_file(
        &self,
        bundle_id: String,
        filename: String,
    ) -> Result<String, RpcError> {
        use base64::Engine;
        // bundle_id must be all-alphanumeric (ULID/timestamp shape).
        if bundle_id.is_empty()
            || !bundle_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(RpcError::Validation {
                message: format!("bundle_id has illegal chars: {bundle_id:?}"),
            });
        }
        if !matches!(filename.as_str(), "manifest.json" | "archive.tar.gz") {
            return Err(RpcError::Validation {
                message: format!(
                    "filename must be `manifest.json` or `archive.tar.gz`, got {filename:?}"
                ),
            });
        }
        let path = std::path::PathBuf::from("/var/lib/hyperion/migration")
            .join(&bundle_id)
            .join(&filename);
        let md = tokio::fs::metadata(&path)
            .await
            .map_err(|e| RpcError::NotFound {
                kind: "migration_bundle_file".into(),
                id: format!("{bundle_id}/{filename}: {e}"),
            })?;
        // Defense in depth — same 64 MiB cap as the file manager.
        const MAX: u64 = 1024 * 1024 * 1024; // 1 GiB cap for archives
        if md.len() > MAX {
            return Err(RpcError::Validation {
                message: format!("bundle file {} bytes exceeds 1 GiB cap", md.len()),
            });
        }
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| RpcError::Internal_with(format!("read: {e}")))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok(b64)
    }

    pub async fn hosting_export(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingMigrationBundle, RpcError> {
        let detail = self.get(sel.clone()).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: format!(
                    "hosting must be active to export (current state: {})",
                    detail.state.as_str()
                ),
            });
        }
        // Reuse backup_now to produce the archive — it's already the
        // most-tested code path for "snapshot this hosting to disk".
        let run = self.backup_now(sel.clone()).await?;
        let archive_path_str = run.archive_path.as_ref().ok_or_else(|| {
            RpcError::Internal_with("backup did not produce an archive".into())
        })?;
        let archive_path = std::path::PathBuf::from(archive_path_str);
        if !archive_path.exists() {
            return Err(RpcError::Internal_with(
                "backup ran but archive missing on disk".into(),
            ));
        }

        // Bundle dir + paths.
        let bundle_id = format!("mig_{}", ulid::Ulid::new());
        let bundle_dir = std::path::PathBuf::from("/var/lib/hyperion/migration").join(&bundle_id);
        tokio::fs::create_dir_all(&bundle_dir)
            .await
            .map_err(|e| RpcError::Internal_with(format!("mkdir migration: {e}")))?;
        let archive_dest = bundle_dir.join("archive.tar.gz");
        // Hardlink the archive into the migration dir — keeps a stable
        // path while costing zero disk (same inode). Fall back to copy
        // if the FS doesn't support hardlinks (NFS, certain overlayfs).
        if tokio::fs::hard_link(&archive_path, &archive_dest).await.is_err() {
            tokio::fs::copy(&archive_path, &archive_dest).await.map_err(|e| {
                RpcError::Internal_with(format!("copy archive into bundle: {e}"))
            })?;
        }

        // Compute SHA-256 of the archive for the manifest. The full
        // archive can be many GB — do it via a streaming hasher rather
        // than loading the file into memory.
        let sha = compute_sha256(&archive_dest).await?;
        let archive_bytes = tokio::fs::metadata(&archive_dest)
            .await
            .map(|m| m.len() as i64)
            .unwrap_or(0);

        // Pull the per-hosting cron tab + WP version best-effort. The
        // operator doesn't need these to succeed for migration to work
        // — they're nice-to-have metadata.
        let crontab = self.cron_list(sel.clone()).await.unwrap_or_default();
        let wp_version = self
            .wp_status(sel.clone())
            .await
            .ok()
            .flatten()
            .map(|w| w.wp_version);

        let manifest = hyperion_types::HostingMigrationManifest {
            schema_version: hyperion_types::HostingMigrationManifest::CURRENT_SCHEMA_VERSION,
            source_hosting_id: detail.id.clone(),
            source_node_id: self.current_node_id(),
            source_hyperion_version: self.current_git_sha.clone(),
            exported_at: now_secs(),
            domain: detail.domain.clone(),
            aliases: detail.aliases.clone(),
            kind: detail.kind.clone(),
            php_version: detail.php_version,
            db_engine: detail.database.as_ref().map(|d| match d.engine {
                hyperion_types::DbProvision::MariaDB => "mariadb".to_string(),
                hyperion_types::DbProvision::Postgres => "postgres".to_string(),
            }),
            had_real_cert: detail
                .cert
                .as_ref()
                .map(|c| !c.issuer.contains("self-signed"))
                .unwrap_or(false),
            wp_version,
            crontab,
            archive_sha256: sha.clone(),
            proxy_upstream_url: detail.proxy_upstream_url.clone(),
        };
        let manifest_path = bundle_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| RpcError::Internal_with(format!("manifest serialize: {e}")))?;
        tokio::fs::write(&manifest_path, manifest_json)
            .await
            .map_err(|e| RpcError::Internal_with(format!("manifest write: {e}")))?;

        self.append_audit(
            "hosting.migration.export",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "bundle_id": &bundle_id,
                "archive_bytes": archive_bytes,
                "archive_sha256": &sha,
            })
            .to_string(),
            "ok",
        )
        .await;

        // download_base_url + bundle_token are filled in by the web
        // handler (only it knows the master's externally-reachable
        // URL + has the signing key). Service returns empty strings;
        // the handler enriches them before responding.
        Ok(hyperion_types::HostingMigrationBundle {
            bundle_id,
            archive_path: archive_dest.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            archive_sha256: sha,
            archive_bytes,
            created_at: now_secs(),
            source_hosting_id: detail.id,
            source_node_id: self.current_node_id(),
            source_hyperion_version: self.current_git_sha.clone(),
            download_base_url: String::new(),
            bundle_token: String::new(),
            token_expires_at: 0,
        })
    }

    /// Import a migration bundle on the target node. Reads the
    /// manifest at `manifest_path`, refuses unknown future schema
    /// versions and SHA-256 mismatches on the sibling archive, creates
    /// a fresh hosting with the same config, and restores the archive.
    pub async fn hosting_import(
        &self,
        manifest_path: String,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        let manifest_bytes = tokio::fs::read(&manifest_path).await.map_err(|e| {
            RpcError::Validation {
                message: format!("manifest read failed: {e}"),
            }
        })?;
        let manifest: hyperion_types::HostingMigrationManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| RpcError::Validation {
                message: format!("manifest parse failed: {e}"),
            })?;
        if manifest.schema_version > hyperion_types::HostingMigrationManifest::CURRENT_SCHEMA_VERSION
        {
            return Err(RpcError::Validation {
                message: format!(
                    "manifest schema_version {} > supported {} — upgrade hyperion-agent first",
                    manifest.schema_version,
                    hyperion_types::HostingMigrationManifest::CURRENT_SCHEMA_VERSION,
                ),
            });
        }

        // Locate the archive next to the manifest, regardless of how
        // the operator named the manifest file. Convention is
        // `archive.tar.gz` alongside `manifest.json`.
        let manifest_pb = std::path::PathBuf::from(&manifest_path);
        let archive_path = manifest_pb
            .parent()
            .map(|p| p.join("archive.tar.gz"))
            .ok_or_else(|| RpcError::Validation {
                message: "manifest_path must have a parent dir".into(),
            })?;
        if !archive_path.exists() {
            return Err(RpcError::Validation {
                message: format!("archive missing at {}", archive_path.display()),
            });
        }
        // SHA verify — refuse a tampered or truncated archive.
        let live_sha = compute_sha256(&archive_path).await?;
        if live_sha != manifest.archive_sha256 {
            return Err(RpcError::Validation {
                message: format!(
                    "archive sha mismatch — manifest={} archive={}",
                    manifest.archive_sha256, live_sha
                ),
            });
        }
        let archive_bytes = tokio::fs::metadata(&archive_path)
            .await
            .map(|m| m.len() as i64)
            .unwrap_or(0);

        // Provision the hosting with the same config. We re-issue the
        // cert (never copy private keys across the network) and let
        // the operator click "Issue Cert" once DNS resolves on the
        // target — same flow as a brand-new hosting.
        let domain = hyperion_validate::Domain::parse(&manifest.domain).map_err(|e| {
            RpcError::Validation {
                message: format!("domain parse: {e}"),
            }
        })?;
        let aliases: Vec<hyperion_validate::Domain> = manifest
            .aliases
            .iter()
            .filter_map(|a| hyperion_validate::Domain::parse(a).ok())
            .collect();
        let create = HostingCreateReq {
            domain,
            aliases,
            php_version: manifest.php_version,
            database: manifest.db_engine.as_deref().and_then(|s| match s {
                "mariadb" => Some(hyperion_types::DbProvision::MariaDB),
                "postgres" => Some(hyperion_types::DbProvision::Postgres),
                _ => None,
            }),
            system_user: None,
            kind: manifest.kind.clone(),
            // Carry the reverse-proxy upstream from the manifest —
            // previously the importer silently dropped it, leaving
            // every migrated reverse-proxy hosting pointing at no
            // upstream. The validate_proxy_upstream_url check on
            // create() still runs.
            proxy_upstream_url: manifest.proxy_upstream_url.clone(),
        };
        let created = self.create(create).await?;

        // Restore the archive. backup_restore() looks for an archive
        // at the given path + a sibling .sql for the dump.
        //
        // If restore fails, we have a half-state hosting on the
        // target: the create() succeeded but the data import didn't.
        // Roll back by deleting the hosting (cleans up dirs, db,
        // system_user, etc.) so the operator can retry without
        // hitting "AlreadyExists" on the second attempt.
        let restore_path = archive_path.display().to_string();
        if let Err(restore_err) = self.backup_restore(
            HostingSelector::Id(created.id.clone()),
            restore_path,
        )
        .await
        {
            tracing::warn!(
                hosting = %created.id.as_str(),
                error = %restore_err,
                "migration import: restore failed — rolling back half-created hosting"
            );
            let _ = self.delete(
                HostingSelector::Id(created.id.clone()),
                DeleteOpts { keep_user: false, keep_database: false },
            ).await;
            return Err(restore_err);
        }

        // Re-apply the crontab when present.
        if !manifest.crontab.trim().is_empty() {
            let _ = self
                .cron_replace(
                    HostingSelector::Id(created.id.clone()),
                    manifest.crontab.clone(),
                )
                .await;
        }

        self.append_audit(
            "hosting.migration.import",
            Some(created.id.as_str()),
            &serde_json::json!({
                "source_hosting_id": manifest.source_hosting_id.as_str(),
                "source_node_id": manifest.source_node_id,
                "archive_bytes": archive_bytes,
                "schema_version": manifest.schema_version,
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok(hyperion_types::HostingImportResult {
            new_hosting_id: created.id,
            domain: manifest.domain,
            restored_bytes: archive_bytes,
            state: "ok".into(),
            message: format!(
                "imported from {} on node {}",
                manifest.source_hosting_id.as_str(),
                manifest.source_node_id
            ),
        })
    }

    /// One-shot backfill called at agent startup: every hostings row
    /// with NULL node_id (i.e. created before migration 016) gets
    /// tagged with the current node's id. Idempotent — running it
    /// twice is a no-op. Returns the row count touched so the boot
    /// log can surface non-zero backfills as a one-liner.
    pub async fn backfill_local_node_id(&self) -> Result<u64, RpcError> {
        let nid = self.current_node_id();
        hostings::backfill_node_id(&self.pool, &nid)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backfill node_id: {e}")))
    }

    /// Import a migration bundle by URL. The source node's
    /// hyperion-web serves a signed `?t=…` URL pair (manifest.json
    /// + archive.tar.gz). The target agent downloads both into a
    /// staging dir, then delegates to `hosting_import`.
    ///
    /// Why curl: same reason as `update_check` — every node has
    /// curl already (the installer uses it) and pulling reqwest in
    /// just for this would double-link a TLS stack.
    pub async fn hosting_import_from_url(
        &self,
        base_url: String,
        token: String,
        override_domain: Option<String>,
        override_aliases: Vec<String>,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        // Validate the URL shape before shelling out — we'd rather
        // refuse `file://` or random garbage at the boundary than
        // hand it to curl.
        if !base_url.starts_with("https://") && !base_url.starts_with("http://") {
            return Err(RpcError::Validation {
                message: "import URL must be http(s)://".into(),
            });
        }
        let base = base_url.trim_end_matches('/').to_string();
        // Quote-stripped, but otherwise opaque to us — the source's
        // signature is what controls access.
        let token_q = token.trim().to_string();
        if token_q.is_empty() {
            return Err(RpcError::Validation {
                message: "import URL missing ?t=<token>".into(),
            });
        }

        // Staging area lives next to the export dir so /var/lib has
        // a single migration namespace operators can grep / delete.
        let staging_id = format!("inc_{}", ulid::Ulid::new());
        let staging = std::path::PathBuf::from("/var/lib/hyperion/migration-incoming")
            .join(&staging_id);
        tokio::fs::create_dir_all(&staging)
            .await
            .map_err(|e| RpcError::Internal_with(format!("mkdir staging: {e}")))?;
        let manifest_path = staging.join("manifest.json");
        let archive_path = staging.join("archive.tar.gz");

        let manifest_url = format!("{base}/manifest.json?t={token_q}");
        let archive_url = format!("{base}/archive.tar.gz?t={token_q}");

        // Download manifest first — small file, fail fast on bad
        // signature / wrong URL before we burn time on the archive.
        curl_to_file(&manifest_url, &manifest_path).await?;

        // CLONE OVERRIDES: when the caller passed `override_domain`
        // (the typical `hosting clone` flow), rewrite the manifest
        // on disk BEFORE the downstream importer reads it. The
        // archive itself is unchanged — the importer creates a new
        // hosting under the new domain and untars the same files +
        // DB dump into it. The archive_sha256 in the manifest is
        // preserved (it's the archive's checksum, not the
        // manifest's), so the integrity check still passes.
        if let Some(ref new_dom) = override_domain {
            if let Err(e) = rewrite_manifest_domain(
                &manifest_path,
                new_dom,
                &override_aliases,
            )
            .await
            {
                // Wipe staging before bailing — manifest rewrite is
                // pre-archive, so we haven't burned the GB yet.
                let _ = tokio::fs::remove_dir_all(&staging).await;
                return Err(e);
            }
        }

        // Then the archive — can be many GB. curl streams to disk
        // directly so RSS stays flat.
        curl_to_file(&archive_url, &archive_path).await?;

        // Delegate to the existing path-based importer. It re-reads
        // the SHA from disk and refuses on mismatch — that doubles
        // as our integrity check after the HTTP transfer.
        let outcome = self
            .hosting_import(manifest_path.display().to_string())
            .await;

        // Always wipe staging after import (success OR failure) to
        // avoid /var/lib/hyperion/migration-incoming growing
        // unbounded.
        let _ = tokio::fs::remove_dir_all(&staging).await;

        let result = outcome?;
        self.append_audit(
            "hosting.migration.import_url",
            Some(result.new_hosting_id.as_str()),
            &serde_json::json!({
                "source_url": &base,
                "bytes": result.restored_bytes,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(result)
    }

    /// Stable node identifier for this agent. Today we use the
    /// hostname when no explicit `HYPERION_NODE_ID` env var is set
    /// — multi-node deploys configure that via systemd unit override
    /// so the cluster has a stable string regardless of hostname
    /// changes.
    pub fn current_node_id(&self) -> String {
        std::env::var("HYPERION_NODE_ID")
            .ok()
            .or_else(|| {
                // /etc/hostname is the canonical source on Debian and
                // works without pulling in the `hostname` crate.
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "unknown".into())
    }

    /// Mint a one-time node enrollment token. Plaintext returned exactly once.
    // ================================================================
    //  Email + DNS helpers (SPF)
    // ================================================================

    /// Send a plain-text email through the configured SMTP relay.
    /// No-op if email isn't configured.
    ///
    /// Outcome lands in two places:
    ///   1. `audit_log` — tamper-evident cluster-wide record (kept
    ///      for security / compliance review).
    ///   2. `email_log` — operator-facing UX surface, optionally
    ///      tied to a specific hosting so the Emails tab on
    ///      hostings_detail can show "what did we send for this
    ///      site lately".
    ///
    /// `kind` is a free-form label with a recommended vocabulary
    /// ("test" | "alert" | "monitor" | "backup" | "cert" | "billing"
    /// | "other"). It drives the UI's "show only X" filters.
    pub(crate) async fn notify_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        hosting_id: Option<&str>,
        kind: &str,
    ) {
        let Some(cfg) = self.email_config.as_ref() else {
            return;
        };
        let to = if to.is_empty() {
            match self.email_default_to.as_deref() {
                Some(t) => t,
                None => return,
            }
        } else {
            to
        };
        match hyperion_adapters::email::send_text(cfg, to, subject, body).await {
            Ok(code) => {
                self.append_audit(
                    "notify.email",
                    hosting_id,
                    &serde_json::json!({"to": to, "subject": subject, "code": &code, "kind": kind})
                        .to_string(),
                    "ok",
                )
                .await;
                // tracing::error on append failure — usually means the
                // migration didn't run on this node (table doesn't
                // exist) or the SQLite file is read-only. Either way
                // the operator needs to see this in journalctl.
                if let Err(e) = hyperion_state::email_log::append(
                    &self.pool,
                    hosting_id,
                    to,
                    subject,
                    body,
                    kind,
                    "ok",
                    None,
                    Some(&code),
                    now_secs(),
                )
                .await
                {
                    tracing::error!(
                        error = %e,
                        to = %to,
                        "email_log append failed — email_log table missing? \
                         restart hyperion-agent after update.sh to apply migration 017"
                    );
                }
            }
            Err(e) => {
                let err_s = e.to_string();
                self.append_audit(
                    "notify.email",
                    hosting_id,
                    &serde_json::json!({
                        "to": to,
                        "subject": subject,
                        "error": &err_s,
                        "kind": kind,
                    })
                    .to_string(),
                    "failed",
                )
                .await;
                if let Err(le) = hyperion_state::email_log::append(
                    &self.pool,
                    hosting_id,
                    to,
                    subject,
                    body,
                    kind,
                    "failed",
                    Some(&err_s),
                    None,
                    now_secs(),
                )
                .await
                {
                    tracing::error!(
                        log_error = %le,
                        send_error = %err_s,
                        to = %to,
                        "email_log append failed AND email send failed — restart agent to apply migration 017"
                    );
                }
                tracing::warn!(to = %to, subject = %subject, error = %err_s, "email send failed");
            }
        }
    }

    /// List recent email-log rows. `hosting_id = None` returns the
    /// cluster-wide stream; Some filters to one hosting.
    pub async fn email_log_list(
        &self,
        hosting_id: Option<String>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::EmailLogEntry>, RpcError> {
        let rows = hyperion_state::email_log::list(&self.pool, hosting_id.as_deref(), limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("email log list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::EmailLogEntry {
                id: r.id,
                hosting_id: r.hosting_id,
                to_address: r.to_address,
                subject: r.subject,
                body_preview: r.body_preview,
                kind: r.kind,
                state: r.state,
                error: r.error,
                smtp_code: r.smtp_code,
                sent_at: r.sent_at,
            })
            .collect())
    }

    /// Read the site-mail wrapper's JSONL for one user. Returns
    /// the most recent `limit` lines, newest first.
    ///
    /// Filesystem path is
    /// `/var/lib/hyperion/site-mail/<system_user>.jsonl`. Missing
    /// file → empty vec (sites that haven't sent mail yet). Lines
    /// that fail to parse are silently skipped so a corrupted
    /// entry can't take down the whole log.
    /// List every Linux user on this node with an FTP-usable shadow
    /// password + join with the hostings table so the operator sees
    /// domain + state alongside the user. Users without a matching
    /// hosting row are still listed (they're operator-created
    /// accounts) with empty domain/state.
    pub async fn ftp_accounts_list(
        &self,
    ) -> Result<Vec<hyperion_types::FtpAccountSummary>, RpcError> {
        let users = hyperion_adapters::ftp::list_users_with_password()
            .await
            .map_err(|e| RpcError::Internal_with(format!("read shadow: {e}")))?;
        // Index hostings by system_user for the join.
        // Build a system_user → (domain, state) cache so the
        // shadow → hostings join is a single SQL query rather
        // than N fan-out gets.
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT su.name, h.domain, h.state \
             FROM hostings h \
             JOIN system_users su ON su.id = h.system_user_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RpcError::Internal_with(format!("join hostings: {e}")))?;
        let by_user: std::collections::HashMap<String, (String, String)> =
            rows.into_iter().map(|(u, d, s)| (u, (d, s))).collect();
        let mut out = Vec::with_capacity(users.len());
        for user in users {
            let (domain, state) = by_user
                .get(&user)
                .cloned()
                .unwrap_or_else(|| (String::new(), String::new()));
            out.push(hyperion_types::FtpAccountSummary {
                user,
                domain,
                hosting_state: state,
                has_password: true,
                node_id: String::new(),
            });
        }
        // Stable alphabetical for the UI.
        out.sort_by(|a, b| a.user.cmp(&b.user));
        Ok(out)
    }

    /// Forwards to the adapter's curl-based probe. Validates the
    /// username shape upfront so a malicious caller can't smuggle
    /// curl args via "user".
    pub async fn ftp_verify_login(
        &self,
        user: String,
        password: String,
    ) -> Result<bool, RpcError> {
        if !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            || user.is_empty()
            || user.len() > 32
        {
            return Err(RpcError::Validation {
                message: format!("invalid user: {user:?}"),
            });
        }
        hyperion_adapters::ftp::probe_login(&user, &password)
            .await
            .map_err(|e| RpcError::Internal_with(format!("ftp probe: {e}")))
    }

    pub async fn site_email_log_list(
        &self,
        system_user: String,
        limit: i64,
    ) -> Result<Vec<hyperion_types::SiteEmailLogEntry>, RpcError> {
        if !system_user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(RpcError::Validation {
                message: format!("invalid system_user: {system_user:?}"),
            });
        }
        let limit = limit.clamp(1, 500) as usize;
        let path = std::path::PathBuf::from("/var/lib/hyperion/site-mail")
            .join(format!("{system_user}.jsonl"));
        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => {
                return Err(RpcError::Internal_with(format!("read jsonl: {e}")));
            }
        };
        let s = String::from_utf8_lossy(&bytes);
        let mut out: Vec<hyperion_types::SiteEmailLogEntry> = s
            .lines()
            .rev()
            .take(limit)
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        // Truncate the body excerpt for wire safety (the wrapper
        // already caps at ~1 KB but defence in depth).
        for r in &mut out {
            if r.body_excerpt.len() > 2048 {
                r.body_excerpt.truncate(2048);
            }
        }
        Ok(out)
    }

    /// Probe localhost for a usable SMTP relay so the operator can
    /// click "Auto-detect" on the Settings page instead of typing
    /// host/port/security by hand.
    ///
    /// Tries (in order): localhost:25 (postfix default), 127.0.0.1:25,
    /// localhost:587. Returns the first one that completes a TCP
    /// connect — that's not proof the relay accepts STARTTLS or
    /// auth, but it's enough for the UI to pre-fill the form with
    /// a "looks reasonable" baseline.
    pub async fn email_smtp_autodetect(&self) -> Result<hyperion_types::SmtpAutodetect, RpcError> {
        use tokio::io::AsyncReadExt;
        let candidates: &[(&str, u16, &str)] = &[
            ("localhost", 25, "plain"),
            ("127.0.0.1", 25, "plain"),
            ("::1", 25, "plain"),
            ("localhost", 587, "starttls"),
            ("::1", 587, "starttls"),
        ];
        for (host, port, sec) in candidates {
            // Bracket-wrap v6 hosts for the connect string.
            let addr = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let connect = tokio::time::timeout(
                std::time::Duration::from_millis(800),
                tokio::net::TcpStream::connect(&addr),
            )
            .await;
            let Ok(Ok(mut sock)) = connect else { continue };

            // SMTP banner check — read up to 256 bytes within 600ms
            // and require a "220" prefix. Without this, an ssh /
            // https / random thing listening on :25 gets reported
            // as a relay; operator clicks Save and every
            // notification thereafter fails with TLS-handshake
            // confusion.
            let mut buf = [0u8; 256];
            let n = match tokio::time::timeout(
                std::time::Duration::from_millis(600),
                sock.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) => n,
                _ => continue,
            };
            let banner = String::from_utf8_lossy(&buf[..n]);
            if !banner.starts_with("220") {
                continue;
            }
            // Looks like SMTP. Derive a sensible from-address.
            // /etc/mailname is postfix's canonical FQDN; fall back
            // to /etc/hostname; refuse the result if it's
            // "localhost"-shaped (no dot, or matches a known dud).
            let suggested_from = read_mail_fqdn()
                .map(|d| format!("hyperion@{d}"))
                .unwrap_or_default();
            let notes = if suggested_from.is_empty() {
                format!(
                    "SMTP banner detected at {addr} but this node's hostname isn't an FQDN; \
                     set from_address manually (e.g. notifications@your-domain.tld)"
                )
            } else {
                format!(
                    "SMTP banner detected at {addr} — likely a local relay (postfix/exim). \
                     If auth is required, fill smtp_user + smtp_password below."
                )
            };
            return Ok(hyperion_types::SmtpAutodetect {
                found: true,
                smtp_host: host.to_string(),
                smtp_port: *port,
                security: sec.to_string(),
                suggested_from,
                notes,
            });
        }
        Ok(hyperion_types::SmtpAutodetect {
            found: false,
            smtp_host: String::new(),
            smtp_port: 0,
            security: String::new(),
            suggested_from: String::new(),
            notes: "no local SMTP relay detected on :25 or :587 — point hyperion at any external \
                    relay (gmail, postmark, mailgun, sendgrid, etc.) and fill the form below."
                .into(),
        })
    }

    /// Check the SPF record at `domain` against our public IPv4.
    ///
    /// The previous implementation did a literal string compare
    /// between the operator's existing TXT record and the one we'd
    /// suggest — guaranteed "differs" for any non-trivial SPF (e.g.
    /// two `ip4:` mechanisms, an `include:`, a `redirect=`). The new
    /// version actually *parses* the SPF mechanisms and decides
    /// whether our IPv4 is authorized.
    ///
    /// Status semantics:
    ///   - "missing"  — no `v=spf1` TXT at the apex
    ///   - "multiple" — more than one SPF record (RFC 7208 §3.2 says
    ///                  receivers fall back to permerror)
    ///   - "matches"  — at least one record authorizes our IP via any
    ///                  of: ip4 (CIDR-aware), a, mx, include (one
    ///                  level of recursion), +all/?all catch-all
    ///   - "differs"  — record exists and parses but does NOT
    ///                  authorize us. Operator either has wrong IP
    ///                  pinned, or needs to add ours alongside.
    pub async fn dns_spf_check(
        &self,
        domain: hyperion_validate::Domain,
    ) -> Result<hyperion_types::SpfCheckResult, RpcError> {
        let d = domain.as_str().to_string();
        // dig may return one TXT split across multiple quoted segments
        // (long TXT values use the `"...""..."` continuation syntax).
        // Join those segments before filtering by prefix.
        let txts_raw = dig_records(&d, "TXT").await.unwrap_or_default();
        let existing: Vec<String> = txts_raw
            .iter()
            .map(|raw| stitch_dig_txt(raw))
            .filter(|s| s.to_ascii_lowercase().starts_with("v=spf1"))
            .collect();

        let our_ipv4 = fetch_public_ip("https://api.ipify.org").await.ok();
        let suggested = match our_ipv4.as_deref() {
            Some(ip) => format!("v=spf1 ip4:{ip} a mx ~all"),
            None => "v=spf1 a mx ~all".into(),
        };

        let (status, reason): (String, String) = if existing.is_empty() {
            (
                "missing".into(),
                "no SPF TXT record at the apex".into(),
            )
        } else if existing.len() > 1 {
            (
                "multiple".into(),
                format!(
                    "RFC 7208 §3.2 forbids multiple SPF records — found {}",
                    existing.len()
                ),
            )
        } else {
            // One record. Try to prove it authorizes us.
            let record = &existing[0];
            let our_ip = our_ipv4.as_deref();
            match check_spf_authorizes(record, &d, our_ip).await {
                SpfMatch::Match { mechanism } => (
                    "matches".into(),
                    format!("{} matched our public IP", mechanism),
                ),
                SpfMatch::CatchAll { mechanism } => (
                    "matches".into(),
                    format!("{} authorizes any sender", mechanism),
                ),
                SpfMatch::NoIp => (
                    "differs".into(),
                    "couldn't determine our public IPv4 — cannot verify SPF coverage".into(),
                ),
                SpfMatch::None => (
                    "differs".into(),
                    "SPF record exists but does not authorize our public IP".into(),
                ),
            }
        };

        Ok(hyperion_types::SpfCheckResult {
            domain: d,
            existing,
            suggested,
            our_public_ipv4: our_ipv4,
            status,
            reason,
        })
    }

    // ================================================================
    //  Slack notifications + billing sweep
    // ================================================================

    /// Send a Slack incoming-webhook message. Specific webhook URL
    /// wins over `slack_default_webhook`. Best-effort: failures are
    /// audit-logged but never propagate to the caller.
    pub(crate) async fn notify_slack(&self, specific: Option<&str>, message: &str) {
        let url = specific
            .filter(|s| !s.trim().is_empty())
            .map(String::from)
            .or_else(|| self.slack_default_webhook.clone());
        let Some(url) = url else {
            return;
        };
        let body = serde_json::json!({"text": message}).to_string();
        let out = tokio::process::Command::new("/usr/bin/curl")
            .args([
                "-fsS",
                "--max-time",
                "6",
                "-X",
                "POST",
                "-H",
                "content-type: application/json",
                "--data",
                &body,
                &url,
            ])
            .output()
            .await;
        match out {
            Ok(o) if o.status.success() => {
                self.append_audit(
                    "notify.slack",
                    None,
                    &serde_json::json!({"message": message}).to_string(),
                    "ok",
                )
                .await;
            }
            Ok(o) => {
                self.append_audit(
                    "notify.slack",
                    None,
                    &serde_json::json!({
                        "message": message,
                        "stderr": String::from_utf8_lossy(&o.stderr).to_string(),
                    })
                    .to_string(),
                    "failed",
                )
                .await;
            }
            Err(e) => {
                self.append_audit(
                    "notify.slack",
                    None,
                    &serde_json::json!({"message": message, "spawn_error": e.to_string()})
                        .to_string(),
                    "failed",
                )
                .await;
            }
        }
    }

    /// Periodic sweep — sends a Slack message for every hosting whose
    /// `next_billing_at` is within 3 days. Called from the scheduler
    /// tick; idempotency is left to the caller's interval (today the
    /// tick runs every 5 min — fine, Slack will get duplicated msgs
    /// every 5 min for 3 days, which is acceptable for a first cut).
    /// Resets next_billing_at to next-interval after notification.
    pub async fn billing_sweep(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let due = profiles::due_billings(&self.pool, now, 3 * 86400)
            .await
            .map_err(|e| RpcError::Internal_with(format!("billing sweep: {e}")))?;
        let mut count = 0i64;
        for row in due {
            // Look up hosting + profile (for webhook + label) — best effort.
            let detail = self
                .get(HostingSelector::Id(row.hosting_id.clone()))
                .await
                .ok();
            let domain = detail.as_ref().map(|d| d.domain.clone()).unwrap_or_default();
            let webhook = match row.profile_id {
                Some(pid) => self
                    .profile_get(pid)
                    .await
                    .ok()
                    .and_then(|p| p.slack_webhook),
                None => None,
            };
            let price_str = match (row.price_minor, &row.price_currency, &row.price_interval) {
                (Some(m), Some(c), Some(iv)) => {
                    format!("{:.2} {c} ({iv})", m as f64 / 100.0)
                }
                _ => "no price set".into(),
            };
            let due_in_days = row
                .next_billing_at
                .map(|t| ((t - now).max(0)) / 86400)
                .unwrap_or(0);
            let msg = format!(
                ":calendar: *Billing reminder*\n• site: `{domain}`\n• price: {price_str}\n• due in {due_in_days} day(s)"
            );
            self.notify_slack(webhook.as_deref(), &msg).await;
            // Also send email if configured. Use the hosting's
            // owner_email when set (from expiry config), else the
            // cluster-wide email_default_to.
            let owner = self
                .get_expiry(HostingSelector::Id(row.hosting_id.clone()))
                .await
                .ok()
                .and_then(|e| e.owner_email);
            let to = owner.unwrap_or_default();
            let subj = format!("[Hyperion] Billing reminder — {domain}");
            let body = format!(
                "Hosting:    {domain}\nPrice:      {price_str}\nDue in:     {due_in_days} day(s)\n\n--\nHyperion\n"
            );
            self.notify_email(&to, &subj, &body, Some(row.hosting_id.as_str()), "billing").await;
            count += 1;
        }
        Ok(count)
    }

    // ================================================================
    //  Hosting profiles (templates)
    // ================================================================

    pub async fn profile_list(&self) -> Result<Vec<HostingProfile>, RpcError> {
        let rows = profiles::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile list: {e}")))?;
        Ok(rows.into_iter().map(profile_row_to_wire).collect())
    }

    pub async fn profile_get(&self, id: i64) -> Result<HostingProfile, RpcError> {
        let row = profiles::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile get: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "profile".into(),
                id: id.to_string(),
            })?;
        Ok(profile_row_to_wire(row))
    }

    pub async fn profile_create(&self, input: ProfileInput) -> Result<HostingProfile, RpcError> {
        let validated = validate_profile(input)?;
        let now = now_secs();
        let id = profiles::insert(&self.pool, &profile_input_to_new(validated), now)
            .await
            .map_err(|e| RpcError::AlreadyExists {
                kind: "profile".into(),
                id: e.to_string(),
            })?;
        let row = profiles::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile re-read: {e}")))?
            .ok_or(RpcError::Internal)?;
        self.append_audit(
            "profile.create",
            None,
            &serde_json::json!({"id": id, "name": row.name}).to_string(),
            "ok",
        )
        .await;
        Ok(profile_row_to_wire(row))
    }

    pub async fn profile_update(
        &self,
        id: i64,
        input: ProfileInput,
    ) -> Result<HostingProfile, RpcError> {
        let validated = validate_profile(input)?;
        profiles::update(&self.pool, id, &profile_input_to_new(validated), now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile update: {e}")))?;
        let row = profiles::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile re-read: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "profile".into(),
                id: id.to_string(),
            })?;
        self.append_audit(
            "profile.update",
            None,
            &serde_json::json!({"id": id, "name": row.name}).to_string(),
            "ok",
        )
        .await;
        Ok(profile_row_to_wire(row))
    }

    pub async fn profile_delete(&self, id: i64) -> Result<(), RpcError> {
        profiles::delete(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile delete: {e}")))?;
        self.append_audit(
            "profile.delete",
            None,
            &serde_json::json!({"id": id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Apply a profile to a hosting. Copies the profile's limits +
    /// expiry policy + pricing onto the hosting and records the link.
    pub async fn profile_apply(
        &self,
        sel: HostingSelector,
        profile_id: i64,
    ) -> Result<ProfileApply, RpcError> {
        let detail = self.get(sel).await?;
        let p = self.profile_get(profile_id).await?;

        // Push limits.
        let mut limits = hyperion_types::HostingLimits::defaults();
        limits.php_memory_mb = p.php_memory_mb;
        limits.php_max_exec_secs = p.php_max_exec_secs;
        limits.php_max_children = p.php_max_children;
        limits.php_max_requests = p.php_max_requests;
        limits.db_max_connections = p.db_max_connections;
        limits.disk_hard_bytes = p.disk_hard_mb.map(|m| m * 1024 * 1024);
        limits.bw_monthly_bytes = p.bw_monthly_mb.map(|m| m * 1024 * 1024);
        self.set_limits(
            HostingSelector::Id(detail.id.clone()),
            limits,
        )
        .await?;

        // Push expiry policy (without changing expires_at — operator sets that).
        let cur = self
            .get_expiry(HostingSelector::Id(detail.id.clone()))
            .await
            .unwrap_or_else(|_| hyperion_types::HostingExpiry::defaults());
        let expiry = hyperion_types::HostingExpiry {
            expires_at: cur.expires_at,
            owner_email: cur.owner_email,
            grace_days: p.expiry_grace_days,
            warning_offsets_days: p.expiry_warning_offsets.clone(),
        };
        self.set_expiry(HostingSelector::Id(detail.id.clone()), expiry)
            .await?;

        // Pricing snapshot + initial next_billing_at = now + interval.
        let now = now_secs();
        let next = match p.price_interval.as_deref() {
            Some("monthly") => Some(now + 30 * 86400),
            Some("quarterly") => Some(now + 90 * 86400),
            Some("yearly") => Some(now + 365 * 86400),
            _ => None,
        };
        profiles::upsert_apply(
            &self.pool,
            &detail.id,
            Some(p.id),
            p.price_minor,
            p.price_currency.as_deref(),
            p.price_interval.as_deref(),
            next,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("apply: {e}")))?;

        // Install WP plugins + themes from the profile, if any.
        // Best-effort: a failure here logs + appends an audit
        // entry but doesn't roll back the limits/expiry/price
        // change above. The operator can see what went wrong on
        // the per-hosting WordPress tab.
        if !p.wp_plugins.trim().is_empty() || !p.wp_themes.trim().is_empty() {
            let wp_outcome = self
                .apply_profile_wp_items(&detail, &p.wp_plugins, &p.wp_themes)
                .await;
            let (installed, failed) = match &wp_outcome {
                Ok(stats) => (stats.0, stats.1),
                Err(_) => (0, 0),
            };
            self.append_audit(
                "profile.apply.wp",
                Some(detail.id.as_str()),
                &serde_json::json!({
                    "profile_id": profile_id,
                    "installed": installed,
                    "failed": failed,
                    "error": wp_outcome.as_ref().err().map(|e| e.to_string()),
                })
                .to_string(),
                if wp_outcome.is_ok() { "ok" } else { "warn" },
            )
            .await;
        }

        self.append_audit(
            "profile.apply",
            Some(detail.id.as_str()),
            &serde_json::json!({"profile_id": profile_id, "profile_name": p.name})
                .to_string(),
            "ok",
        )
        .await;

        Ok(ProfileApply {
            hosting_id: detail.id,
            profile_id: Some(p.id),
            price_minor: p.price_minor,
            price_currency: p.price_currency,
            price_interval: p.price_interval,
            next_billing_at: next,
            applied_at: now,
        })
    }

    /// Walk a profile's wp_plugins + wp_themes text fields and
    /// install each item via wp-cli. Skips empty lines and `#…`
    /// comments. Returns (installed_count, failed_count).
    ///
    /// Line syntax (per profile.rs::HostingProfile docs):
    ///   - `<slug>`           → install from wordpress.org
    ///   - `@asset:<id>`      → install from the local uploaded
    ///                          ZIP at /var/lib/hyperion/wp-assets/<id>/
    ///   - trailing `!`       → also activate after install
    ///   - leading `#`        → comment, skipped
    async fn apply_profile_wp_items(
        &self,
        detail: &hyperion_types::HostingDetail,
        plugins_text: &str,
        themes_text: &str,
    ) -> Result<(usize, usize), RpcError> {
        let mut ok = 0usize;
        let mut fail = 0usize;
        for kind in ["plugin", "theme"] {
            let text = if kind == "plugin" { plugins_text } else { themes_text };
            for raw in text.lines() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (item, activate) = if let Some(stripped) = line.strip_suffix('!') {
                    (stripped.trim(), true)
                } else {
                    (line, false)
                };
                // Resolve @asset:<id> → on-disk path.
                let source = if let Some(rest) = item.strip_prefix("@asset:") {
                    let id: i64 = rest.trim().parse().map_err(|_| RpcError::Validation {
                        message: format!("profile {kind} line `{line}` has bad asset id"),
                    })?;
                    let row = hyperion_state::wp_assets::get_by_id(&self.pool, id)
                        .await
                        .map_err(|e| RpcError::Internal_with(format!("wp_asset lookup: {e}")))?
                        .ok_or_else(|| RpcError::NotFound {
                            kind: "wp_asset".into(),
                            id: id.to_string(),
                        })?;
                    if row.kind != kind {
                        return Err(RpcError::Validation {
                            message: format!(
                                "profile {kind} line `{line}` references asset id {id} which is a {} (mismatch)",
                                row.kind
                            ),
                        });
                    }
                    wp_asset_disk_path(id, &row.stored_filename)
                } else {
                    item.to_string()
                };
                let res = self
                    .adapters
                    .wp_cli(
                        &detail.system_user,
                        &format!("/home/{}/{}/htdocs", detail.system_user, detail.domain),
                        kind,
                        &source,
                        activate,
                    )
                    .await;
                match res {
                    Ok(()) => ok += 1,
                    Err(e) => {
                        tracing::warn!(
                            kind = kind,
                            item = %item,
                            error = %e,
                            "profile wp_item install failed"
                        );
                        fail += 1;
                    }
                }
            }
        }
        Ok((ok, fail))
    }

    pub async fn profile_get_apply(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<ProfileApply>, RpcError> {
        let detail = self.get(sel).await?;
        let row = profiles::get_apply(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("apply read: {e}")))?;
        Ok(row.map(|r| ProfileApply {
            hosting_id: r.hosting_id,
            profile_id: r.profile_id,
            price_minor: r.price_minor,
            price_currency: r.price_currency,
            price_interval: r.price_interval,
            next_billing_at: r.next_billing_at,
            applied_at: r.applied_at,
        }))
    }

    /// Compute the operator dashboard alert list. Scans hostings + certs
    /// + backups + scheduler state and surfaces anything that needs
    /// human attention. Read-only — no side effects.
    pub async fn dashboard_alerts(&self) -> Result<Vec<DashboardAlert>, RpcError> {
        let mut out: Vec<DashboardAlert> = Vec::new();
        let now = now_secs();
        let summaries = self.list().await?;

        // Failed hostings — straight pass.
        for s in &summaries {
            if s.state == HostingState::Failed {
                out.push(DashboardAlert {
                    kind: "hosting_failed".into(),
                    severity: "error".into(),
                    message: format!("{} is in state Failed.", s.domain),
                    hosting: Some(s.domain.clone()),
                });
            }
        }

        // Cert expiry — fetch detail per hosting (cheap; we already have
        // the row in-memory) and check not_after.
        for s in &summaries {
            if let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await {
                if let Some(cert) = detail.cert {
                    let days = (cert.not_after - now) / 86400;
                    if days < 0 {
                        out.push(DashboardAlert {
                            kind: "cert_expired".into(),
                            severity: "error".into(),
                            message: format!(
                                "{} certificate EXPIRED {} day(s) ago — site is now untrusted.",
                                detail.domain,
                                days.abs()
                            ),
                            hosting: Some(detail.domain.clone()),
                        });
                    } else if cert.issuer == "self-signed" {
                        // Bootstrap cert (today RealAdapter::acme_issue
                        // still issues self-signed at hosting create()
                        // time). Surface from day one so operators know
                        // to click Issue Cert once DNS resolves — without
                        // this prompt, the only signal is the browser's
                        // "Not Secure" badge.
                        out.push(DashboardAlert {
                            kind: "cert_self_signed".into(),
                            severity: "warn".into(),
                            message: format!(
                                "{} is using a bootstrap self-signed cert; click Issue Cert when DNS resolves.",
                                detail.domain
                            ),
                            hosting: Some(detail.domain.clone()),
                        });
                    } else if days < 7 {
                        // Inside the critical band — renewal tick has
                        // had at least 23 days of daily attempts and
                        // still hasn't succeeded. Operator should
                        // investigate (DNS broke, port 80 closed, …).
                        out.push(DashboardAlert {
                            kind: "cert_expiring".into(),
                            severity: "error".into(),
                            message: format!(
                                "{} certificate expires in {} day(s) — renew now.",
                                detail.domain, days
                            ),
                            hosting: Some(detail.domain.clone()),
                        });
                    } else if days < 30 {
                        out.push(DashboardAlert {
                            kind: "cert_expiring".into(),
                            severity: "warn".into(),
                            message: format!(
                                "{} certificate expires in {} day(s).",
                                detail.domain, days
                            ),
                            hosting: Some(detail.domain.clone()),
                        });
                    }
                }
            }
        }

        // Stale backups — last ok backup > 7 days OR never. Only check
        // active hostings (suspended ones don't accumulate data).
        for s in &summaries {
            if s.state != HostingState::Active {
                continue;
            }
            let runs = hyperion_state::backups::list_for(&self.pool, &s.id, 5)
                .await
                .unwrap_or_default();
            let last_ok = runs.iter().find(|r| r.state == "ok").map(|r| r.started_at);
            match last_ok {
                Some(ts) if now - ts > 7 * 86400 => {
                    out.push(DashboardAlert {
                        kind: "backup_stale".into(),
                        severity: "warn".into(),
                        message: format!(
                            "{} last successful backup was {} day(s) ago.",
                            s.domain,
                            (now - ts) / 86400
                        ),
                        hosting: Some(s.domain.clone()),
                    });
                }
                None if !runs.is_empty() => {
                    // Has runs but none successful.
                    out.push(DashboardAlert {
                        kind: "backup_failing".into(),
                        severity: "error".into(),
                        message: format!("{} has no successful backups on record.", s.domain),
                        hosting: Some(s.domain.clone()),
                    });
                }
                _ => {}
            }
        }

        // High load — latest node_metrics sample.
        if let Ok(Some(m)) = hyperion_state::metrics::latest(&self.pool).await {
            // loadavg_1m_x100 / cpu_count > 1.5 → warn. We don't track
            // cpu_count yet; rough heuristic: load > 4.0 always warn.
            if m.loadavg_1m_x100 > 400 {
                out.push(DashboardAlert {
                    kind: "high_load".into(),
                    severity: "warn".into(),
                    message: format!(
                        "1-minute load average is {:.2} — investigate or scale.",
                        m.loadavg_1m_x100 as f64 / 100.0
                    ),
                    hosting: None,
                });
            }
            if m.mem_total_kib > 0 && m.mem_used_kib * 100 / m.mem_total_kib > 90 {
                out.push(DashboardAlert {
                    kind: "high_memory".into(),
                    severity: "warn".into(),
                    message: format!(
                        "Memory usage at {}% — sites may start swapping.",
                        m.mem_used_kib * 100 / m.mem_total_kib
                    ),
                    hosting: None,
                });
            }
        }

        // Disk usage — probe the filesystems that matter to the panel
        // (rootfs + /var where hyperion + sites + dumps + backups
        // live) and emit warn at >=80% / error at >=95%. Without
        // this, the operator only learns rootfs is full when an
        // install / WP plugin upload / cert renewal fails with
        // ENOSPC deep in a stack trace.
        if let Ok(usages) = probe_disk_usages().await {
            for u in &usages {
                if u.used_pct >= 95 {
                    out.push(DashboardAlert {
                        kind: "disk_critical".into(),
                        severity: "error".into(),
                        message: format!(
                            "Disk {} is {}% full ({} free of {}) — installs / cert renewals / backups WILL fail. Free space immediately.",
                            u.mount,
                            u.used_pct,
                            human_bytes(u.total_bytes - u.used_bytes),
                            human_bytes(u.total_bytes)
                        ),
                        hosting: None,
                    });
                } else if u.used_pct >= 80 {
                    out.push(DashboardAlert {
                        kind: "disk_warn".into(),
                        severity: "warn".into(),
                        message: format!(
                            "Disk {} is {}% full ({} free of {}) — clean dumps/logs before it bites.",
                            u.mount,
                            u.used_pct,
                            human_bytes(u.total_bytes - u.used_bytes),
                            human_bytes(u.total_bytes)
                        ),
                        hosting: None,
                    });
                }
            }
        }

        // Severity sort: error first, then warn, then info.
        out.sort_by_key(|a| match a.severity.as_str() {
            "error" => 0,
            "warn" => 1,
            _ => 2,
        });
        Ok(out)
    }

    /// Rename an enrolled node's display label. The `node_id` is
    /// the immutable enrollment identifier; only the operator-
    /// visible label changes. Validates length and trims surrounding
    /// whitespace; an empty label is rejected (the UI prevents this
    /// but defence-in-depth is cheap here).
    pub async fn node_set_label(&self, node_id: &str, label: &str) -> Result<(), RpcError> {
        let trimmed = label.trim();
        if trimmed.is_empty() {
            return Err(RpcError::Validation {
                message: "label cannot be empty".into(),
            });
        }
        if trimmed.chars().count() > 80 {
            return Err(RpcError::Validation {
                message: "label too long (max 80 characters)".into(),
            });
        }
        // Refuse control chars / newlines — labels render into HTML
        // attributes (option text, sidebar chips), so a stray newline
        // turns into a confusing wrapped pill.
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(RpcError::Validation {
                message: "label cannot contain control characters".into(),
            });
        }
        hyperion_state::nodes::set_label(&self.pool, node_id, trimmed)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node_set_label: {e}")))?;
        self.append_audit(
            "node.label.update",
            Some(node_id),
            &serde_json::json!({"label": trimmed}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Cluster-wide certificate inventory. One row per cert
    /// known to this agent, computed `days_left` + `band` so the
    /// UI can render without arithmetic. Sorted by expiry —
    /// expiring soonest at the top. The `node_id` field carries
    /// where the cert lives so the panel's cross-node fanout can
    /// merge multiple agents' results into one screen.
    pub async fn cert_overview(
        &self,
    ) -> Result<Vec<hyperion_types::CertOverviewItem>, RpcError> {
        let rows = hyperion_state::certificates::list_all(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cert_overview list: {e}")))?;
        let now = now_secs();
        Ok(rows
            .into_iter()
            .map(|r| {
                let days_left = (r.not_after - now) / 86400;
                let band = if r.not_after <= now {
                    "expired"
                } else if days_left < 7 {
                    "critical"
                } else if days_left < 30 {
                    "warning"
                } else {
                    "ok"
                };
                hyperion_types::CertOverviewItem {
                    domain: r.domain,
                    issuer: r.issuer,
                    issued_at: r.issued_at,
                    not_after: r.not_after,
                    days_left,
                    band: band.into(),
                    // Local agent — handler fills this when fanning
                    // out across nodes.
                    node_id: String::new(),
                }
            })
            .collect())
    }

    /// Toggle a node's drain flag. Drained nodes are skipped by
    /// the auto-placer + create wizard; existing hostings keep
    /// serving traffic. Idempotent — drain on an already-drained
    /// node updates the reason + timestamp without erroring.
    pub async fn node_set_drain(
        &self,
        node_id: &str,
        drain: bool,
        reason: &str,
        actor_uid: i64,
    ) -> Result<(), RpcError> {
        let trimmed = reason.trim();
        if trimmed.chars().count() > 200 {
            return Err(RpcError::Validation {
                message: "drain reason too long (max 200 characters)".into(),
            });
        }
        let now = now_secs();
        if drain {
            hyperion_state::nodes::drain(&self.pool, node_id, trimmed, actor_uid, now)
                .await
                .map_err(|e| RpcError::Internal_with(format!("node drain: {e}")))?;
        } else {
            hyperion_state::nodes::undrain(&self.pool, node_id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("node undrain: {e}")))?;
        }
        self.append_audit(
            if drain { "node.drain" } else { "node.undrain" },
            Some(node_id),
            &serde_json::json!({"reason": trimmed, "actor_uid": actor_uid}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Remove an enrolled node row. The caller is the master's web
    /// UI (via NodeRemove RPC) — workers should not be able to
    /// nuke their own row from the master via this path.
    ///
    /// Two-stage gate:
    ///   1. Count hostings still routed to this node (excluding
    ///      trashed). If non-zero and `force=false`, refuse with
    ///      `Ok((false, count))` so the UI can show the count and
    ///      offer "force" path or "move them off first" advice.
    ///   2. If `force=true`, the DAO drops the node row + its
    ///      drain marker. Hostings stay in the DB with their old
    ///      node_id (orphaned); `find_hosting_anywhere` lookups
    ///      will fail for them until the operator either re-enrols
    ///      a node under the same node_id OR migrates the hostings
    ///      to a different node manually.
    ///
    /// Audited either way. Unknown node_id ⇒ `Ok((false, 0))` so
    /// the UI form is forgiving on a double-submit race.
    pub async fn node_remove(
        &self,
        node_id: &str,
        force: bool,
        actor_uid: i64,
    ) -> Result<(bool, i64), RpcError> {
        // Refuse silently on empty / non-existent (audit still logs).
        let existed = hyperion_state::nodes::get_by_node_id(&self.pool, node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("nodes lookup: {e}")))?
            .is_some();
        if !existed {
            return Ok((false, 0));
        }
        let count = hyperion_state::nodes::count_hostings_on_node(&self.pool, node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("hostings on node count: {e}")))?;
        if count > 0 && !force {
            return Ok((false, count));
        }
        let removed = hyperion_state::nodes::delete(&self.pool, node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node delete: {e}")))?;
        self.append_audit(
            "node.remove",
            Some(node_id),
            &serde_json::json!({
                "force": force,
                "hostings_orphaned": count,
                "actor_uid": actor_uid
            })
            .to_string(),
            if removed { "ok" } else { "noop" },
        )
        .await;
        Ok((removed, count))
    }

    /// List enrolled nodes (master-side view).
    pub async fn nodes_list(&self) -> Result<Vec<hyperion_types::NodeSummary>, RpcError> {
        let rows = hyperion_state::nodes::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("nodes list: {e}")))?;
        let drained = hyperion_state::nodes::drained_set(&self.pool)
            .await
            .unwrap_or_default();
        // Pre-load reasons for the drained set so the UI shows
        // "drained: post-upgrade testing" instead of just a pill.
        let reasons: std::collections::HashMap<String, String> = {
            let rs: Vec<(String, String)> =
                sqlx::query_as("SELECT node_id, reason FROM node_drain")
                    .fetch_all(&self.pool)
                    .await
                    .unwrap_or_default();
            rs.into_iter().collect()
        };
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::NodeSummary {
                is_drained: drained.contains(&r.node_id),
                drain_reason: reasons.get(&r.node_id).cloned().unwrap_or_default(),
                node_id: r.node_id,
                label: r.label,
                master_url: r.master_url,
                agent_version: r.agent_version,
                public_ip: r.public_ip,
                enrolled_at: r.enrolled_at,
                last_seen_at: r.last_seen_at,
            })
            .collect())
    }

    /// Master-side: validate `token`, mark the invite consumed, insert
    /// the node, and mint a per-node shared secret for heartbeat auth.
    /// Returns the plaintext secret — the master only stores its hash.
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_consume(
        &self,
        token: String,
        caller_ip: String,
        node_id: String,
        label: String,
        agent_version: String,
        public_ip: Option<String>,
    ) -> Result<String, RpcError> {
        if token.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "empty token".into(),
            });
        }
        let now = now_secs();
        let ok = hyperion_state::invites::consume(&self.pool, &token, &caller_ip, &node_id, now)
            .await
            .map_err(|e| RpcError::Internal_with(format!("consume: {e}")))?;
        if !ok {
            return Err(RpcError::Validation {
                message: "invite token invalid, expired, or already consumed".into(),
            });
        }
        let hash = hyperion_state::invites::hash_token(&token);
        // Mint a 32-byte per-node secret. Plaintext returned to the caller
        // exactly once; master persists only the BLAKE3 hash.
        let mut secret_bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let secret_plain = hex::encode(secret_bytes);
        let secret_hash =
            hex::encode(blake3::hash(secret_plain.as_bytes()).as_bytes());
        let row = hyperion_state::nodes::NewNode {
            node_id: node_id.clone(),
            label,
            master_url: None,
            agent_version,
            public_ip,
            enrolled_via_hash: hash,
            secret_hash,
        };
        hyperion_state::nodes::insert(&self.pool, &row, now)
            .await
            .map_err(|e| RpcError::Internal_with(format!("nodes insert: {e}")))?;
        self.append_audit(
            "node.enroll",
            Some(&node_id),
            &serde_json::json!({"label": row.label, "caller_ip": caller_ip}).to_string(),
            "ok",
        )
        .await;
        Ok(secret_plain)
    }

    /// Master-side: verify a node's heartbeat (constant-time secret
    /// check) and bump last_seen_at + agent_version. Returns Ok(()) if
    /// the node exists and the secret matches; otherwise Validation.
    ///
    /// SECURITY: always hash the supplied secret and run a
    /// constant-time compare against *some* hash even when the node
    /// is unknown. Returning Validation immediately on a missing
    /// node would leak a timing oracle for node-id enumeration: an
    /// attacker could distinguish "node doesn't exist" from "node
    /// exists, secret wrong" by response latency.
    pub async fn node_heartbeat(
        &self,
        node_id: String,
        secret: String,
        agent_version: String,
    ) -> Result<(), RpcError> {
        // Compute the candidate hash unconditionally — the same
        // amount of crypto work happens regardless of node_id state.
        let actual = hex::encode(blake3::hash(secret.as_bytes()).as_bytes());
        let actual_bytes = actual.as_bytes();

        let row_opt = hyperion_state::nodes::get_by_node_id(&self.pool, &node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node lookup: {e}")))?;
        // For the unknown-node case, compare against a fixed dummy
        // string the same length as a real hex BLAKE3 digest (64
        // bytes). The compare result is irrelevant — we'll fail
        // afterwards — but the *time* taken is the same as the
        // happy-path compare.
        const DUMMY_HASH: &[u8; 64] =
            b"0000000000000000000000000000000000000000000000000000000000000000";
        let expected: &[u8] = match &row_opt {
            Some(r) => r.secret_hash.as_bytes(),
            None => DUMMY_HASH,
        };
        // If the stored hash is somehow a different length than a
        // BLAKE3 hex digest, the compare must still consume the
        // longest of the two so it doesn't short-circuit visibly.
        // In practice secret_hash IS 64 bytes — this is belt-and-
        // braces.
        let n = expected.len().max(actual_bytes.len());
        let mut diff: u8 = (expected.len() ^ actual_bytes.len()) as u8;
        for i in 0..n {
            let a = expected.get(i).copied().unwrap_or(0);
            let b = actual_bytes.get(i).copied().unwrap_or(0);
            diff |= a ^ b;
        }
        // Bind the decision to BOTH "node exists" AND "compare
        // matched" — never short-circuit on either.
        let ok = row_opt.is_some() && diff == 0;
        if !ok {
            return Err(RpcError::Validation {
                message: "bad secret".into(),
            });
        }
        hyperion_state::nodes::touch_last_seen(
            &self.pool,
            &node_id,
            now_secs(),
            Some(&agent_version),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("touch: {e}")))?;
        Ok(())
    }

    pub async fn invite_create(
        &self,
        label: String,
        ttl_secs: i64,
    ) -> Result<hyperion_types::NodeInviteMint, RpcError> {
        if label.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "label must be non-empty".into(),
            });
        }
        let ttl = ttl_secs.clamp(60, 30 * 24 * 3600);
        let now = now_secs();
        let invite = hyperion_state::invites::mint(label.trim(), ttl, now);
        hyperion_state::invites::insert(&self.pool, &invite, now)
            .await
            .map_err(|e| RpcError::Internal_with(format!("invite insert: {e}")))?;
        self.append_audit(
            "node.invite",
            None,
            &serde_json::json!({
                "label": label.trim(),
                "ttl_secs": ttl,
                "token_hash": invite.token_hash,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::NodeInviteMint {
            token: invite.token,
            token_hash: invite.token_hash,
            label: invite.label,
            expires_at: invite.expires_at,
        })
    }

    pub async fn invite_list(&self) -> Result<Vec<hyperion_types::NodeInviteSummary>, RpcError> {
        let rows = hyperion_state::invites::list_pending(&self.pool, now_secs(), 200)
            .await
            .map_err(|e| RpcError::Internal_with(format!("invite list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::NodeInviteSummary {
                token_hash: r.token_hash,
                label: r.label,
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
            .collect())
    }

    pub async fn invite_revoke(&self, token_hash: String) -> Result<(), RpcError> {
        hyperion_state::invites::revoke(&self.pool, &token_hash)
            .await
            .map_err(|e| RpcError::Internal_with(format!("invite revoke: {e}")))?;
        self.append_audit(
            "node.invite.revoke",
            None,
            &serde_json::json!({ "token_hash": token_hash }).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    // ============================================================
    //  backup_targets — off-site S3-compatible destinations.
    //  This commit ships the CONFIG storage + probe (curl HEAD
    //  against the bucket) + UI; the actual scheduled upload
    //  loop lands as the next commit so this one stays
    //  readable. Operators can configure their Wasabi / B2 /
    //  Minio bucket today and verify the credentials work
    //  via the probe; uploads start flowing once the runner
    //  ships.
    // ============================================================

    pub async fn backup_target_list(
        &self,
    ) -> Result<Vec<hyperion_types::BackupTargetView>, RpcError> {
        let rows = hyperion_state::backup_targets::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup_target_list: {e}")))?;
        Ok(rows.into_iter().map(backup_target_row_to_view).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn backup_target_upsert(
        &self,
        id: Option<i64>,
        name: String,
        kind: String,
        endpoint: String,
        bucket: String,
        region: String,
        access_key_id: String,
        secret_key: Option<String>,
        age_recipient: Option<String>,
        retention_daily: i64,
        retention_weekly: i64,
        retention_monthly: i64,
        enabled: bool,
    ) -> Result<i64, RpcError> {
        // Minimal validation — name + endpoint + bucket can't be
        // empty; rest is up to the operator (an empty
        // age_recipient means "no client-side encryption", which
        // we warn about in the UI but allow).
        if name.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "target name is required".into(),
            });
        }
        if endpoint.trim().is_empty() || bucket.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "endpoint + bucket are required".into(),
            });
        }
        // Secret handling: when the caller passed a fresh
        // secret_key, persist it under /etc/hyperion/secrets/ with
        // 0600 perms and store the path back in the row. When
        // secret_key is None on an UPDATE, leave the existing
        // secret_key_id alone (lets the UI render the form
        // without re-prompting for the secret on every edit).
        let now = now_secs();
        let secret_path = if let Some(plaintext) = secret_key.as_deref() {
            let pseudo_id = id.unwrap_or(0);
            let path = format!("/etc/hyperion/secrets/backup-{pseudo_id}.key");
            // Best-effort write; failure is non-fatal — the row
            // gets stored without a secret path, the UI shows
            // "secret never persisted" and the runner refuses.
            if let Err(e) =
                write_secret_file(&path, plaintext.as_bytes()).await
            {
                tracing::warn!(path = %path, error = %e, "backup secret write failed");
            }
            Some(path)
        } else if let Some(existing_id) = id {
            // Re-read existing row to preserve its secret_key_id.
            hyperion_state::backup_targets::get(&self.pool, existing_id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("backup_target get: {e}")))?
                .and_then(|r| r.secret_key_id)
        } else {
            None
        };

        let new_id = hyperion_state::backup_targets::upsert(
            &self.pool,
            hyperion_state::backup_targets::UpsertReq {
                id,
                name: name.trim(),
                kind: kind.trim(),
                endpoint: endpoint.trim(),
                bucket: bucket.trim(),
                region: region.trim(),
                access_key_id: access_key_id.trim(),
                secret_key_id: secret_path.as_deref(),
                age_recipient: age_recipient.as_deref(),
                retention_daily,
                retention_weekly,
                retention_monthly,
                enabled,
                now,
            },
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("backup_target upsert: {e}")))?;

        self.append_audit(
            "backup.target.upsert",
            Some(&new_id.to_string()),
            &serde_json::json!({
                "name": name,
                "endpoint": endpoint,
                "bucket": bucket,
                "enabled": enabled,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(new_id)
    }

    pub async fn backup_target_delete(&self, id: i64) -> Result<(), RpcError> {
        hyperion_state::backup_targets::delete(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup_target delete: {e}")))?;
        self.append_audit(
            "backup.target.delete",
            Some(&id.to_string()),
            "{}",
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn backup_target_probe(
        &self,
        id: i64,
    ) -> Result<hyperion_types::BackupTargetProbe, RpcError> {
        let target = hyperion_state::backup_targets::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backup_target get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "backup_target".into(),
                id: id.to_string(),
            })?;
        // Probe: HEAD <endpoint>/<bucket>/. AWS-style auth is
        // operator-handled via aws CLI configured on the host (the
        // runner shells out to `aws --endpoint-url=… s3 cp`). The
        // probe here just confirms the endpoint is reachable +
        // returns valid HTTP. Real auth verification ships with
        // the runner.
        let url = format!(
            "{}/{}",
            target.endpoint.trim_end_matches('/'),
            target.bucket
        );
        let start = now_secs();
        let out = tokio::process::Command::new("/usr/bin/curl")
            .args([
                "-sS",
                "-I",
                "--max-time",
                "10",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                &url,
            ])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("spawn curl: {e}")))?;
        let latency = (now_secs() - start) * 1000;
        let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // Any HTTP code that isn't a connection error counts as
        // "endpoint reachable". 200/403 (forbidden without creds)
        // are both fine — they prove the bucket URL responds. DNS
        // failure / TCP refused / timeout ⇒ curl exits non-zero.
        let ok = out.status.success() && !code.is_empty();
        let message = if ok {
            format!("endpoint reachable (HTTP {code})")
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            format!("probe failed: {} (curl exit {:?})", stderr.trim(), out.status.code())
        };
        Ok(hyperion_types::BackupTargetProbe {
            ok,
            message,
            put_latency_ms: latency,
        })
    }

    // ============================================================
    //  hosting_quotas — disk + memory + bandwidth per hosting.
    //  Disk caps push into the kernel via `setquota -u`. Memory
    //  caps land in the FPM pool template on next rebuild.
    //  Bandwidth is informational + alert-driven for now.
    // ============================================================

    pub async fn quota_get(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingQuotaReport, RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::hosting_quotas::read(&self.pool, detail.id.as_str())
            .await
            .map_err(|e| RpcError::Internal_with(format!("quota read: {e}")))?;
        let policy = hyperion_types::HostingQuotaView {
            hosting_id: row.hosting_id,
            disk_soft_kib: row.disk_soft_kib,
            disk_hard_kib: row.disk_hard_kib,
            mem_limit_mib: row.mem_limit_mib,
            bw_soft_mib: row.bw_soft_mib,
            bw_hard_mib: row.bw_hard_mib,
            applied_at: row.applied_at,
            last_error: row.last_error,
            updated_at: row.updated_at,
        };
        let (current_disk_kib, quotas_enabled_on_fs, setup_hint) =
            quota_probe_current(&detail.system_user, &detail.root_dir).await;
        Ok(hyperion_types::HostingQuotaReport {
            policy,
            current_disk_kib,
            quotas_enabled_on_fs,
            setup_hint,
        })
    }

    pub async fn quota_set(
        &self,
        sel: HostingSelector,
        disk_soft_kib: i64,
        disk_hard_kib: i64,
        mem_limit_mib: i64,
        bw_soft_mib: i64,
        bw_hard_mib: i64,
    ) -> Result<hyperion_types::HostingQuotaView, RpcError> {
        // Validation: hard must be >= soft when both non-zero.
        // Zero ⇒ "no cap", which is allowed on either side.
        if disk_soft_kib < 0
            || disk_hard_kib < 0
            || mem_limit_mib < 0
            || bw_soft_mib < 0
            || bw_hard_mib < 0
        {
            return Err(RpcError::Validation {
                message: "quota values must be non-negative".into(),
            });
        }
        if disk_soft_kib > 0 && disk_hard_kib > 0 && disk_hard_kib < disk_soft_kib {
            return Err(RpcError::Validation {
                message: "disk hard limit must be >= soft limit".into(),
            });
        }
        if bw_soft_mib > 0 && bw_hard_mib > 0 && bw_hard_mib < bw_soft_mib {
            return Err(RpcError::Validation {
                message: "bandwidth hard limit must be >= soft limit".into(),
            });
        }

        let detail = self.get(sel).await?;
        let now = now_secs();
        hyperion_state::hosting_quotas::upsert(
            &self.pool,
            detail.id.as_str(),
            disk_soft_kib,
            disk_hard_kib,
            mem_limit_mib,
            bw_soft_mib,
            bw_hard_mib,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("quota upsert: {e}")))?;

        // Push to kernel. Failure here doesn't fail the RPC — the
        // policy is saved either way and the UI shows last_error
        // so the operator can see the kernel didn't accept it
        // (typically because quotaon isn't enabled on the mount).
        let kernel_result =
            apply_disk_quota(&detail.system_user, disk_soft_kib, disk_hard_kib).await;
        match kernel_result {
            Ok(()) => {
                let _ = hyperion_state::hosting_quotas::mark_applied(
                    &self.pool,
                    detail.id.as_str(),
                    now,
                )
                .await;
                self.append_audit(
                    "hosting.quota.set",
                    Some(detail.id.as_str()),
                    &serde_json::json!({
                        "disk_soft_kib": disk_soft_kib,
                        "disk_hard_kib": disk_hard_kib,
                        "mem_limit_mib": mem_limit_mib,
                        "bw_soft_mib": bw_soft_mib,
                        "bw_hard_mib": bw_hard_mib,
                    })
                    .to_string(),
                    "ok",
                )
                .await;
            }
            Err(e) => {
                let _ = hyperion_state::hosting_quotas::mark_failed(
                    &self.pool,
                    detail.id.as_str(),
                    &e,
                    now,
                )
                .await;
                self.append_audit(
                    "hosting.quota.set",
                    Some(detail.id.as_str()),
                    &serde_json::json!({
                        "error": e,
                    })
                    .to_string(),
                    "failed",
                )
                .await;
            }
        }

        // Re-read so the UI sees the post-apply state (including
        // applied_at / last_error flips).
        let row = hyperion_state::hosting_quotas::read(&self.pool, detail.id.as_str())
            .await
            .map_err(|e| RpcError::Internal_with(format!("quota re-read: {e}")))?;
        Ok(hyperion_types::HostingQuotaView {
            hosting_id: row.hosting_id,
            disk_soft_kib: row.disk_soft_kib,
            disk_hard_kib: row.disk_hard_kib,
            mem_limit_mib: row.mem_limit_mib,
            bw_soft_mib: row.bw_soft_mib,
            bw_hard_mib: row.bw_hard_mib,
            applied_at: row.applied_at,
            last_error: row.last_error,
            updated_at: row.updated_at,
        })
    }

    // ============================================================
    //  web_sessions — backs the cookie ledger so revocation works.
    // ============================================================

    pub async fn web_session_insert(
        &self,
        sid: &str,
        user_id: i64,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), RpcError> {
        hyperion_state::web_sessions::insert(&self.pool, sid, user_id, ip, user_agent, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_insert: {e}")))
    }

    pub async fn web_session_touch(&self, sid: &str) -> Result<bool, RpcError> {
        hyperion_state::web_sessions::touch_if_live(&self.pool, sid, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_touch: {e}")))
    }

    pub async fn web_session_list(
        &self,
        user_id: i64,
    ) -> Result<Vec<hyperion_types::WebSessionView>, RpcError> {
        let rows = hyperion_state::web_sessions::list_for_user(&self.pool, user_id, 100)
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::WebSessionView {
                sid: r.sid,
                user_id: r.user_id,
                ip: r.ip,
                user_agent: r.user_agent,
                created_at: r.created_at,
                last_seen_at: r.last_seen_at,
                revoked_at: r.revoked_at,
                revoked_by: r.revoked_by,
            })
            .collect())
    }

    pub async fn web_session_revoke(
        &self,
        sid: &str,
        revoked_by: i64,
    ) -> Result<bool, RpcError> {
        let r = hyperion_state::web_sessions::revoke(&self.pool, sid, revoked_by, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_revoke: {e}")))?;
        if r {
            self.append_audit(
                "web_session.revoke",
                Some(sid),
                &serde_json::json!({"revoked_by": revoked_by}).to_string(),
                "ok",
            )
            .await;
        }
        Ok(r)
    }

    /// Walk the full audit log and verify each row's row_hash
    /// against `BLAKE3(prev_hash || canonical fields)`. Returns
    /// `(ok, rows_checked, message)` — the message names the first
    /// bad row when the chain is broken, so an operator can grep
    /// /var/log + dmesg + the surrounding rows for clues. The
    /// log is bounded in practice (the GC ticker prunes >90 day
    /// entries) so this is cheap even on a busy node.
    pub async fn audit_verify_chain(&self) -> Result<(bool, i64, String), RpcError> {
        // Count first so we can report it even on failure (operator
        // wants "1234 rows, broke at row 712" — a bare "bad chain"
        // is unhelpful).
        let rows_checked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("audit count: {e}")))?;
        match hyperion_state::audit::verify_chain(&self.pool).await {
            Ok(()) => Ok((true, rows_checked, String::new())),
            Err(e) => Ok((false, rows_checked, e.to_string())),
        }
    }

    pub async fn audit_list(
        &self,
        limit: i64,
    ) -> Result<Vec<hyperion_rpc::AuditEntryWire>, RpcError> {
        let rows = hyperion_state::audit::list(&self.pool, limit.max(1).min(1000))
            .await
            .map_err(|e| RpcError::Internal_with(format!("audit list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|e| hyperion_rpc::AuditEntryWire {
                id: e.id,
                ts: e.ts,
                actor_uid: e.actor_uid,
                actor_label: e.actor_label,
                action: e.action,
                target: e.target,
                payload_json: e.payload_json,
                result: e.result,
            })
            .collect())
    }

    pub(crate) async fn append_audit(
        &self,
        action: &str,
        target: Option<&str>,
        payload_json: &str,
        result: &str,
    ) {
        let r = hyperion_state::audit::append(
            &self.pool,
            hyperion_state::audit::AppendReq {
                ts: now_secs(),
                actor_uid: 0,
                actor_label: "agent",
                action,
                target,
                payload_json,
                result,
            },
        )
        .await;
        if let Err(e) = r {
            tracing::warn!(error=%e, "audit append failed");
        }
    }

    // ================================================================
    //  DNS pre-check + real ACME issuance
    // ================================================================

    /// Resolve `domain`'s A + AAAA records via `dig`, fetch our agent's
    /// public IP, and report whether the records point here.
    pub async fn dns_check(&self, domain: Domain) -> Result<DnsCheckResult, RpcError> {
        let d = domain.as_str().to_string();
        let resolved_a = dig_records(&d, "A").await.unwrap_or_default();
        let resolved_aaaa = dig_records(&d, "AAAA").await.unwrap_or_default();
        let our_ipv4 = fetch_public_ip("https://api.ipify.org").await.ok();
        let our_ipv6 = fetch_public_ip("https://api6.ipify.org").await.ok();

        let mut matches = false;
        if let Some(ref ip) = our_ipv4 {
            if resolved_a.iter().any(|r| r == ip) {
                matches = true;
            }
        }
        if let Some(ref ip) = our_ipv6 {
            if resolved_aaaa.iter().any(|r| r == ip) {
                matches = true;
            }
        }
        let note = if resolved_a.is_empty() && resolved_aaaa.is_empty() {
            format!("{} has no A or AAAA records (NXDOMAIN or DNS error)", d)
        } else if matches {
            "DNS resolves here — cert issuance will work.".into()
        } else {
            format!(
                "DNS points elsewhere. We see A={:?} AAAA={:?}; our IPs are {}/{}",
                resolved_a,
                resolved_aaaa,
                our_ipv4.as_deref().unwrap_or("?"),
                our_ipv6.as_deref().unwrap_or("?"),
            )
        };

        Ok(DnsCheckResult {
            domain: d,
            resolved_a,
            resolved_aaaa,
            our_public_ipv4: our_ipv4,
            our_public_ipv6: our_ipv6,
            matches,
            note,
        })
    }

    /// Issue a real Let's Encrypt cert via HTTP-01 + install it.
    /// Refuses unless DNS resolves here (override via req.require_dns_match=false).
    pub async fn issue_real_cert(
        &self,
        sel: HostingSelector,
        req: CertIssueRequest,
    ) -> Result<CertInfo, RpcError> {
        let detail = self.get(sel).await?;
        let domain = Domain::parse(&detail.domain)?;

        // Serialize issuance per domain so two concurrent runs can't
        // produce a mismatched cert+key pair on disk (cert from run A,
        // key from run B → TLS handshake breaks). The lock outlives
        // the full ACME flow including the vhost rewrite at the end.
        let lock = {
            let mut map = self.cert_issue_locks.lock().await;
            map.entry(detail.domain.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;

        if req.require_dns_match {
            let check = self.dns_check(domain.clone()).await?;
            if !check.matches {
                return Err(RpcError::Conflict {
                    message: format!(
                        "DNS pre-check failed for {}: {} (set require_dns_match=false to override)",
                        detail.domain, check.note
                    ),
                });
            }
        }

        // SANs = aliases + any extras
        let mut sans: Vec<String> = detail.aliases.clone();
        sans.extend(req.extra_sans.iter().cloned());
        sans.sort();
        sans.dedup();

        // Prefer the per-hosting override (if set + non-empty), fall
        // back to the agent-wide default. Lets one operator-managed
        // host get expiry notices at the end-customer's address while
        // siblings keep the default.
        let row = hostings::get_by_id(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get hosting: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.as_str().to_string(),
            })?;
        let effective_email = row
            .acme_contact_email
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(self.acme_contact_email.as_str());
        // Reject obvious placeholder addresses early so we don't burn a
        // failed-account round trip with Let's Encrypt.
        let email = effective_email.trim();
        if email.is_empty()
            || email.ends_with("@example.com")
            || email.ends_with("@example.org")
            || email.ends_with("@example.net")
            || email.ends_with("@hyperion.invalid")
            || !email.contains('@')
        {
            return Err(RpcError::Validation {
                message: format!(
                    "acme contact email \"{}\" is invalid or a placeholder. \
                     Edit /etc/hyperion/agent.toml [acme] contact_email and \
                     restart hyperion-agent.",
                    email
                ),
            });
        }
        // Re-render the vhost BEFORE we ask LE to validate. This is a
        // self-heal: if an older agent build wrote a broken vhost (e.g.
        // the `root` instead of `alias` bug for .well-known/acme-challenge),
        // re-rendering with the current template fixes it. Cheap, safe,
        // idempotent. Without this an operator hitting "Issue Cert" on an
        // existing hosting would keep getting Invalid from LE forever
        // because the broken vhost stays on disk.
        if let Err(e) = self.adapters.nginx_write_vhost(&detail).await {
            tracing::warn!(
                error=%e,
                domain=%detail.domain,
                "pre-issue vhost re-render failed (continuing anyway)"
            );
        }

        // Ensure the acme-challenge root exists with the right perms
        // BEFORE we ask LE. nginx (www-data) must be able to traverse +
        // read; the dir itself only needs world-x.
        if let Err(e) = tokio::fs::create_dir_all(&self.paths.acme_challenge_root).await {
            tracing::warn!(
                error=%e,
                path=%self.paths.acme_challenge_root,
                "could not pre-create acme challenge root"
            );
        }
        let _ = tokio::process::Command::new("/usr/bin/chmod")
            .arg("0755")
            .arg(&self.paths.acme_challenge_root)
            .output()
            .await;

        let cert = hyperion_adapters::acme::issue_http01(hyperion_adapters::acme::IssueRequest {
            domain: &detail.domain,
            sans: &sans,
            contact_email: email,
            staging: req.staging,
            challenge_root: std::path::Path::new(&self.paths.acme_challenge_root),
            certs_root: "/etc/hyperion/certs",
        })
        .await
        .map_err(|e| RpcError::ProvisioningFailed {
            stage: "acme".into(),
            reason: e.to_string(),
        })?;

        // Persist cert info in DB
        let cert_path = format!("/etc/hyperion/certs/{}/fullchain.pem", detail.domain);
        let key_path = format!("/etc/hyperion/certs/{}/privkey.pem", detail.domain);
        let _ = certificates::upsert(
            &self.pool,
            &detail.domain,
            now_secs(),
            cert.not_after,
            &cert_path,
            &key_path,
            &cert.issuer,
        )
        .await;

        // Re-render vhost so nginx picks up new cert (paths are same but
        // reload triggers fresh load + cert chain pickup).
        let new_detail = HostingDetail {
            cert: Some(cert.clone()),
            ..detail.clone()
        };
        if let Err(e) = self.adapters.nginx_write_vhost(&new_detail).await {
            return Err(RpcError::ProvisioningFailed {
                stage: "nginx_reload".into(),
                reason: e.to_string(),
            });
        }

        self.append_audit(
            "cert.issue.acme",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "issuer": cert.issuer,
                "staging": req.staging,
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok(cert)
    }

    /// Sweep `certificates` for LE certs whose `not_after - now` is
    /// below `threshold_days*86400` and re-issue each via
    /// `issue_real_cert` with `require_dns_match=false`. The cert is
    /// already installed for this domain, so refusing on a transient
    /// DNS misconfiguration would only delay the renewal further;
    /// any persistent DNS break surfaces as a structured LE error
    /// inside the per-domain `CertRenewResult`.
    ///
    /// `now` is parameterized (not just `now_secs()`) so the daily
    /// background tick and unit tests share the same code path. The
    /// audit log captures each attempt + outcome so an out-of-band
    /// cron-driven renewal leaves a trace.
    pub async fn cert_renew_tick(
        &self,
        now: i64,
        threshold_days: i64,
    ) -> Result<Vec<CertRenewResult>, RpcError> {
        let horizon = threshold_days.max(0).saturating_mul(86400);
        let rows = certificates::find_expiring_within(&self.pool, now, horizon)
            .await
            .map_err(|e| RpcError::Internal_with(format!("query expiring certs: {e}")))?;
        // The certificates CHECK constraint already restricts issuer
        // to {letsencrypt, self-signed}. Skip self-signed (those are
        // bootstrap certs awaiting a first real issuance — re-issuing
        // them would also be self-signed; the dashboard nags the
        // operator separately). starts_with lets a future provider
        // string like "letsencrypt-staging" still get renewed here.
        let due: Vec<_> = rows
            .into_iter()
            .filter(|r| r.issuer.starts_with("letsencrypt"))
            .collect();

        let mut out = Vec::with_capacity(due.len());
        for cert in due {
            let domain_str = cert.domain.clone();
            self.append_audit(
                "cert.renew.attempt",
                None,
                &serde_json::json!({
                    "domain": &domain_str,
                    "not_after": cert.not_after,
                    "threshold_days": threshold_days,
                    "now": now,
                })
                .to_string(),
                "ok",
            )
            .await;

            let outcome = match Domain::parse(&domain_str) {
                Err(e) => CertRenewOutcome::Failed {
                    error: format!("invalid stored domain {domain_str}: {e}"),
                },
                Ok(d) => {
                    let req = CertIssueRequest {
                        staging: false,
                        require_dns_match: false,
                        extra_sans: vec![],
                    };
                    match self.issue_real_cert(HostingSelector::Domain(d), req).await {
                        Ok(info) => CertRenewOutcome::Renewed {
                            new_not_after: info.not_after,
                        },
                        Err(e) => CertRenewOutcome::Failed {
                            error: e.to_string(),
                        },
                    }
                }
            };

            let status = match &outcome {
                CertRenewOutcome::Renewed { .. } => "ok",
                _ => "failed",
            };
            self.append_audit(
                "cert.renew",
                None,
                &serde_json::json!({
                    "domain": &domain_str,
                    "outcome": &outcome,
                })
                .to_string(),
                status,
            )
            .await;

            // Surface a bell-icon notification on failure so admins
            // see it in the UI without grep-the-audit-log. The kind
            // string carries the domain so the bell can show one
            // distinct row per failing cert (instead of all failures
            // collapsing to a single "cert.renew_failed" line). The
            // tick runs daily → at most one notification per cert
            // per day; admins who miss day 30 still see days 29..0.
            //
            // ALSO: if the cert is approaching the 14-day red band
            // and renewal failed (or wasn't due yet because of
            // staging), fire a separate "expiring soon" notification
            // so the operator can intervene manually before the cert
            // goes red on the dashboard. Same per-cert kind for the
            // bell to render distinct rows.
            let days_left = (cert.not_after - now) / 86400;
            match &outcome {
                CertRenewOutcome::Failed { error } => {
                    self.notify_admins(
                        if days_left < 7 { "error" } else { "warn" },
                        "Cert renewal failed",
                        &format!(
                            "{domain_str} — {error} ({} day(s) until expiry)",
                            days_left
                        ),
                        &format!("/hostings/{}", domain_str),
                        &format!("cert.renew_failed:{domain_str}"),
                    )
                    .await;
                }
                CertRenewOutcome::Renewed { .. } if days_left < 14 => {
                    // Edge case: renewal succeeded but the cert was
                    // already inside the red band. Notify so the
                    // operator knows their automation caught it
                    // before expiry (informational, not a failure).
                    self.notify_admins(
                        "info",
                        "Cert renewed close to expiry",
                        &format!(
                            "{domain_str} — was {} day(s) from expiry, now renewed.",
                            days_left
                        ),
                        &format!("/hostings/{}", domain_str),
                        &format!("cert.renewed_late:{domain_str}"),
                    )
                    .await;
                }
                _ => {}
            }

            out.push(CertRenewResult {
                domain: domain_str,
                outcome,
            });
        }
        Ok(out)
    }

    // ================================================================
    //  Stats — collection + readback
    // ================================================================

    /// Run one background sampler tick.
    /// Per hosting: `du -sb <root>` + tail parse access.log over last hour.
    /// Per node: snapshot /proc/loadavg + /proc/meminfo + /proc/uptime.
    /// Persist into hosting_usage + node_metrics.
    /// Returns count of hostings sampled.
    pub async fn stats_tick(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let period = period_key(now);
        let summaries = self.list().await?;
        let mut total_disk: i64 = 0;
        let mut total_bw_out: i64 = 0;
        let mut total_requests: i64 = 0;
        let mut active = 0i64;
        let mut suspended = 0i64;
        let mut failed = 0i64;
        for s in &summaries {
            match s.state {
                HostingState::Active => active += 1,
                HostingState::Suspended => suspended += 1,
                HostingState::Failed => failed += 1,
                _ => {}
            }
        }

        for s in &summaries {
            let host_root = std::path::PathBuf::from(&self.paths.home_root)
                .join(derive_user_from_summary(s).unwrap_or_else(|| "_".to_string()))
                .join(&s.domain);
            let disk = du_bytes(&host_root).await.unwrap_or(0);
            let logs_dir = host_root.join("logs");
            let (bw_in, bw_out, reqs, _last) =
                parse_access_log_window(&logs_dir.join("access.log"), now - 24 * 3600).await;

            // Upsert usage row.
            let _ = hyperion_state::limits::upsert_usage(
                &self.pool,
                &hyperion_state::limits::UsageBucket {
                    hosting_id: s.id.clone(),
                    period: period.clone(),
                    disk_used_bytes: disk,
                    inodes_used: 0,
                    bw_in_bytes: bw_in,
                    bw_out_bytes: bw_out,
                    php_requests: reqs,
                },
            )
            .await;

            total_disk += disk;
            total_bw_out += bw_out;
            total_requests += reqs;
        }

        let (la, mem_total, mem_used, uptime) = read_proc_metrics().await;

        let _ = metrics::insert(
            &self.pool,
            &metrics::NodeMetricsInput {
                sampled_at: now,
                hostings_count: summaries.len() as i64,
                hostings_active: active,
                hostings_suspended: suspended,
                hostings_failed: failed,
                total_disk_bytes: total_disk,
                total_bw_out_24h: total_bw_out,
                total_requests_24h: total_requests,
                loadavg_1m_x100: la,
                mem_total_kib: mem_total,
                mem_used_kib: mem_used,
                uptime_secs: uptime,
            },
        )
        .await;

        // Prune > 30d to keep DB lean.
        let _ = metrics::prune_older_than(&self.pool, now - 30 * 24 * 3600).await;

        Ok(summaries.len() as i64)
    }

    pub async fn hosting_stats(&self, sel: HostingSelector) -> Result<HostingStats, RpcError> {
        let detail = self.get(sel).await?;
        // Sum last 24h of hourly usage rows.
        let rows = hyperion_state::limits::usage_for(&self.pool, &detail.id, 24)
            .await
            .map_err(|e| RpcError::Internal_with(format!("usage: {e}")))?;
        let now = now_secs();
        let mut disk = 0i64;
        let mut bw_in = 0i64;
        let mut bw_out = 0i64;
        let mut reqs = 0i64;
        for r in &rows {
            disk = disk.max(r.disk_used_bytes); // current disk = latest
            bw_in += r.bw_in_bytes;
            bw_out += r.bw_out_bytes;
            reqs += r.php_requests;
        }
        Ok(HostingStats {
            hosting_id: detail.id,
            domain: detail.domain,
            disk_bytes: disk,
            bw_in_bytes_24h: bw_in,
            bw_out_bytes_24h: bw_out,
            requests_24h: reqs,
            last_request_at: rows.first().map(|_| now),
            sampled_at: now,
        })
    }

    pub async fn node_stats(
        &self,
        hostname: &str,
        version: &str,
    ) -> Result<NodeStats, RpcError> {
        let latest = metrics::latest(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("metrics: {e}")))?;
        let summaries = self.list().await?;
        Ok(node_stats_from(hostname, version, latest, &summaries))
    }

    /// Set or clear the per-hosting ACME contact email override.
    /// `email: None` (or empty) clears the override; the next cert
    /// issuance reverts to `[acme] contact_email` from agent.toml.
    /// Validates RFC-5321-shaped email when present (rejects
    /// placeholders + obviously-malformed addresses).
    pub async fn set_hosting_acme_email(
        &self,
        sel: HostingSelector,
        email: Option<String>,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // Normalise: empty / whitespace → clear.
        let cleaned: Option<String> = email
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(ref e) = cleaned {
            // Same validation as the global acme_contact_email
            // sanity check in issue_real_cert. Refuse placeholders +
            // values that obviously can't reach LE.
            let lc = e.to_lowercase();
            if !e.contains('@')
                || lc.ends_with("@example.com")
                || lc.ends_with("@example.org")
                || lc.ends_with("@example.net")
                || lc.ends_with("@hyperion.invalid")
                || e.len() > 254
            {
                return Err(RpcError::Validation {
                    message: format!(
                        "acme email `{e}` is invalid or a placeholder — \
                         use a real address (or leave blank to fall back to the agent default)."
                    ),
                });
            }
        }
        hostings::set_acme_contact_email(
            &self.pool,
            &detail.id,
            cleaned.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("update: {e}")))?;
        self.append_audit(
            "hosting.acme_email.set",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "cleared": cleaned.is_none(),
                // We log presence (was-set / was-cleared) but not the
                // actual value — emails are PII.
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    // ════════════════════════════════════════════════════════════
    //  Web users / roles / TOTP 2FA / invites
    // ════════════════════════════════════════════════════════════

    /// Username + password authentication. Doesn't mint a session
    /// (web binary owns the cookie signer). Tracks failed attempts +
    /// auto-locks after `WEB_LOGIN_MAX_FAILS` consecutive misses.
    pub async fn web_login(
        &self,
        username: String,
        password: String,
        client_ip: Option<String>,
    ) -> Result<hyperion_types::WebLoginResult, RpcError> {
        const WEB_LOGIN_MAX_FAILS: i64 = 10;
        let user = match hyperion_state::web_users::get_by_username(&self.pool, username.trim())
            .await
            .map_err(|e| RpcError::Internal_with(format!("get user: {e}")))?
        {
            Some(u) => u,
            None => {
                // Don't reveal whether the username exists.
                return Ok(hyperion_types::WebLoginResult::Invalid);
            }
        };
        if user.locked {
            return Ok(hyperion_types::WebLoginResult::Locked {
                reason: user.locked_reason.unwrap_or_else(|| "account locked".into()),
            });
        }
        // Verify the password (constant-time via argon2).
        let ok = hyperion_auth::verify_password(&password, &user.password_hash)
            .map_err(|e| RpcError::Internal_with(format!("verify: {e}")))?;
        if !ok {
            let n = hyperion_state::web_users::record_failed_login(&self.pool, user.id, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("track failed: {e}")))?;
            if n >= WEB_LOGIN_MAX_FAILS {
                let _ = hyperion_state::web_users::set_locked(
                    &self.pool,
                    user.id,
                    true,
                    Some("too many failed login attempts"),
                    now_secs(),
                )
                .await;
                self.append_audit(
                    "web.user.locked",
                    None,
                    &serde_json::json!({"user_id": user.id, "reason": "failed_logins"})
                        .to_string(),
                    "ok",
                )
                .await;
            }
            self.append_audit(
                "web.login.failed",
                None,
                &serde_json::json!({
                    "username": user.username,
                    "ip": client_ip,
                    "failed_count": n,
                })
                .to_string(),
                "failed",
            )
            .await;
            return Ok(hyperion_types::WebLoginResult::Invalid);
        }
        // Password OK. If 2FA enrolled, ask for TOTP.
        if user.is_2fa_enrolled() {
            return Ok(hyperion_types::WebLoginResult::NeedsTotp {
                user_id: user.id,
                username: user.username,
            });
        }
        // No 2FA — record the login, return Ok.
        hyperion_state::web_users::record_login(
            &self.pool,
            user.id,
            client_ip.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("record login: {e}")))?;
        self.append_audit(
            "web.login.ok",
            None,
            &serde_json::json!({"user_id": user.id, "ip": client_ip}).to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::WebLoginResult::Ok {
            user_id: user.id,
            username: user.username,
            email: user.email,
            role: user.role.as_str().to_string(),
        })
    }

    /// Step 2 of a 2FA-required login: verify either a 6-digit TOTP
    /// code or a 9-char (XXXX-XXXX) backup code. On TOTP success, the
    /// code is accepted within ±30s of clock skew (RFC 6238). On
    /// backup-code success the code is marked used (one-shot).
    pub async fn web_verify_2fa(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<hyperion_types::WebVerify2faResult, RpcError> {
        let user = match hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get user: {e}")))?
        {
            Some(u) => u,
            None => return Ok(hyperion_types::WebVerify2faResult::Invalid),
        };
        if user.locked || !user.is_2fa_enrolled() {
            return Ok(hyperion_types::WebVerify2faResult::Invalid);
        }
        let trimmed = code.trim();
        // Heuristic: 6 digits = TOTP, otherwise backup code.
        let is_totp = trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_digit());
        let accepted = if is_totp {
            let secret = user
                .totp_secret_base32
                .as_deref()
                .ok_or_else(|| RpcError::Internal_with("missing totp secret".into()))?;
            hyperion_auth::verify_code(secret, trimmed)
                .map_err(|e| RpcError::Internal_with(format!("totp verify: {e}")))?
        } else {
            // Backup code path.
            let h = hyperion_auth::hash_backup_code(trimmed);
            hyperion_state::web_users::consume_backup_code(&self.pool, user.id, &h, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("consume backup: {e}")))?
        };
        if !accepted {
            self.append_audit(
                "web.login.2fa_failed",
                None,
                &serde_json::json!({"user_id": user.id, "via": if is_totp {"totp"} else {"backup_code"}})
                    .to_string(),
                "failed",
            )
            .await;
            return Ok(hyperion_types::WebVerify2faResult::Invalid);
        }
        hyperion_state::web_users::record_login(&self.pool, user.id, None, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("record login: {e}")))?;
        self.append_audit(
            "web.login.2fa_ok",
            None,
            &serde_json::json!({"user_id": user.id, "via": if is_totp {"totp"} else {"backup_code"}})
                .to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::WebVerify2faResult::Ok {
            user_id: user.id,
            username: user.username,
            email: user.email,
            role: user.role.as_str().to_string(),
        })
    }

    pub async fn web_user_list(&self) -> Result<Vec<hyperion_types::WebUserSummary>, RpcError> {
        let rows = hyperion_state::web_users::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        Ok(rows.into_iter().map(row_to_summary).collect())
    }

    pub async fn web_user_get(
        &self,
        id: i64,
    ) -> Result<Option<hyperion_types::WebUserSummary>, RpcError> {
        let row = hyperion_state::web_users::get_by_id(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?;
        Ok(row.map(row_to_summary))
    }

    pub async fn web_user_create(
        &self,
        username: String,
        email: String,
        password: String,
        role: String,
    ) -> Result<i64, RpcError> {
        let username = username.trim();
        let email = email.trim();
        if username.is_empty() || email.is_empty() {
            return Err(RpcError::Validation {
                message: "username and email are required".into(),
            });
        }
        if !email.contains('@') {
            return Err(RpcError::Validation {
                message: "email must contain '@'".into(),
            });
        }
        if password.len() < 8 {
            return Err(RpcError::Validation {
                message: "password must be at least 8 characters".into(),
            });
        }
        let role: hyperion_state::web_users::WebRole = role.parse().map_err(|e: String| {
            RpcError::Validation { message: e }
        })?;
        let phc = hyperion_auth::hash_password(&password)
            .map_err(|e| RpcError::Internal_with(format!("hash: {e}")))?;
        let id = hyperion_state::web_users::insert(
            &self.pool,
            &hyperion_state::web_users::NewWebUser {
                username,
                email,
                password_hash: &phc,
                role,
            },
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("insert: {e}")))?;
        self.append_audit(
            "web.user.create",
            None,
            &serde_json::json!({"id": id, "username": username, "role": role.as_str()})
                .to_string(),
            "ok",
        )
        .await;
        Ok(id)
    }

    pub async fn web_user_set_password(
        &self,
        user_id: i64,
        new_password: String,
    ) -> Result<(), RpcError> {
        if new_password.len() < 8 {
            return Err(RpcError::Validation {
                message: "password must be at least 8 characters".into(),
            });
        }
        let phc = hyperion_auth::hash_password(&new_password)
            .map_err(|e| RpcError::Internal_with(format!("hash: {e}")))?;
        hyperion_state::web_users::set_password_hash(&self.pool, user_id, &phc, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set: {e}")))?;
        self.append_audit(
            "web.user.password_set",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Begin an email-change flow: verify the current password,
    /// store the new email + a hashed 6-digit code (15min TTL),
    /// dispatch the code to the NEW address. Returns the masked
    /// recipient so the UI can confirm without echoing the full
    /// address back to the operator's screen.
    ///
    /// We require the current password as a soft-2FA gate so a
    /// stolen session can't silently take over the account by
    /// pointing email at attacker-controlled inbox.
    pub async fn email_change_request(
        &self,
        user_id: i64,
        new_email: String,
        current_password: String,
    ) -> Result<String, RpcError> {
        let new_email = new_email.trim().to_string();
        if !new_email.contains('@') || new_email.len() > 254 {
            return Err(RpcError::Validation {
                message: "new_email is not a valid address".into(),
            });
        }
        let row = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get user: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            })?;
        if new_email == row.email {
            return Err(RpcError::Validation {
                message: "new email matches current email".into(),
            });
        }
        let ok = hyperion_auth::verify_password(&current_password, &row.password_hash)
            .map_err(|e| RpcError::Internal_with(format!("verify: {e}")))?;
        if !ok {
            return Err(RpcError::Validation {
                message: "current password is incorrect".into(),
            });
        }
        // Generate a 6-digit code. We use a CSPRNG so brute-force
        // resistance comes from the limited attempt count, not from
        // the entropy of the code.
        use rand::Rng;
        let code: u32 = rand::thread_rng().gen_range(0..1_000_000);
        let code_str = format!("{:06}", code);
        let code_hash = hyperion_auth::hash_password(&code_str)
            .map_err(|e| RpcError::Internal_with(format!("hash code: {e}")))?;
        let expires_at = now_secs() + 15 * 60;
        hyperion_state::web_users::set_pending_email(
            &self.pool,
            user_id,
            &new_email,
            &code_hash,
            expires_at,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("stash: {e}")))?;

        // Dispatch the email. Failure here doesn't roll back the
        // pending row — the operator may have a typo'd email, in
        // which case they should retry with a different one (which
        // overwrites the pending row).
        if let Some(cfg) = &self.email_config {
            let body = format!(
                "Hyperion email-change verification\n\n\
                 Code: {code_str}\n\n\
                 Enter this code on the profile page within 15 minutes to confirm \
                 the change. If you didn't request this, ignore this email — your \
                 current address remains in place.\n"
            );
            if let Err(e) = hyperion_adapters::email::send_text(
                cfg,
                &new_email,
                "Hyperion: confirm your new email",
                &body,
            )
            .await
            {
                tracing::warn!(error = %e, "email-change: send failed");
                return Err(RpcError::Internal_with(format!(
                    "couldn't send verification email: {e}. Check Settings → Email."
                )));
            }
        } else {
            return Err(RpcError::Conflict {
                message: "no SMTP configured — configure Settings → Email first".into(),
            });
        }

        self.append_audit(
            "web.user.email_change_requested",
            None,
            &serde_json::json!({
                "user_id": user_id,
                "new_email": &new_email,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(mask_email(&new_email))
    }

    pub async fn email_change_confirm(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<(), RpcError> {
        let pending = hyperion_state::web_users::get_pending_email(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get pending: {e}")))?
            .ok_or_else(|| RpcError::Validation {
                message: "no email change in progress".into(),
            })?;
        if now_secs() > pending.expires_at {
            // Expired — clear so the operator gets a clean slate
            // when they request again.
            let _ = hyperion_state::web_users::clear_pending_email(&self.pool, user_id).await;
            return Err(RpcError::Validation {
                message: "verification code expired — request a new one".into(),
            });
        }
        if pending.attempts >= 5 {
            let _ = hyperion_state::web_users::clear_pending_email(&self.pool, user_id).await;
            return Err(RpcError::Validation {
                message: "too many wrong codes — request a new email change".into(),
            });
        }
        let ok = hyperion_auth::verify_password(&code, &pending.code_hash)
            .map_err(|e| RpcError::Internal_with(format!("verify code: {e}")))?;
        if !ok {
            let _ = hyperion_state::web_users::bump_pending_email_attempts(
                &self.pool, user_id,
            )
            .await;
            return Err(RpcError::Validation {
                message: "wrong code".into(),
            });
        }
        hyperion_state::web_users::set_email(
            &self.pool,
            user_id,
            &pending.new_email,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set email: {e}")))?;
        let _ = hyperion_state::web_users::clear_pending_email(&self.pool, user_id).await;
        self.append_audit(
            "web.user.email_changed",
            None,
            &serde_json::json!({
                "user_id": user_id,
                "new_email": &pending.new_email,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn email_change_cancel(&self, user_id: i64) -> Result<(), RpcError> {
        hyperion_state::web_users::clear_pending_email(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("clear: {e}")))?;
        Ok(())
    }

    pub async fn web_user_set_role(&self, user_id: i64, role: String) -> Result<(), RpcError> {
        let parsed: hyperion_state::web_users::WebRole = role.parse().map_err(|e: String| {
            RpcError::Validation { message: e }
        })?;
        // Refuse to demote the last super_admin.
        if !parsed.can_manage_users() {
            self.guard_last_super_admin(user_id).await?;
        }
        hyperion_state::web_users::set_role(&self.pool, user_id, parsed, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set role: {e}")))?;
        self.append_audit(
            "web.user.role_set",
            None,
            &serde_json::json!({"user_id": user_id, "role": parsed.as_str()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn web_user_set_locked(
        &self,
        user_id: i64,
        locked: bool,
        reason: Option<String>,
    ) -> Result<(), RpcError> {
        if locked {
            // Refuse to lock the last super_admin.
            self.guard_last_super_admin(user_id).await?;
        }
        hyperion_state::web_users::set_locked(
            &self.pool,
            user_id,
            locked,
            reason.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("lock: {e}")))?;
        self.append_audit(
            if locked { "web.user.locked" } else { "web.user.unlocked" },
            None,
            &serde_json::json!({"user_id": user_id, "reason": reason}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn web_user_delete(&self, user_id: i64) -> Result<(), RpcError> {
        self.guard_last_super_admin(user_id).await?;
        let removed = hyperion_state::web_users::delete(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete: {e}")))?;
        if removed == 0 {
            return Err(RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            });
        }
        self.append_audit(
            "web.user.delete",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Refuse the operation if `user_id` is the **last** super_admin in
    /// the cluster. Without this guard the operator could lock
    /// themselves out — and there's no recovery without DB hand-edit.
    async fn guard_last_super_admin(&self, user_id: i64) -> Result<(), RpcError> {
        let target = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("guard: {e}")))?;
        let Some(target) = target else { return Ok(()) };
        if !matches!(target.role, hyperion_state::web_users::WebRole::SuperAdmin) {
            return Ok(());
        }
        let users = hyperion_state::web_users::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("guard list: {e}")))?;
        let super_admins = users
            .iter()
            .filter(|u| matches!(u.role, hyperion_state::web_users::WebRole::SuperAdmin) && !u.locked)
            .count();
        if super_admins <= 1 {
            return Err(RpcError::Validation {
                message: "refusing — this would leave the cluster with no active super_admin"
                    .into(),
            });
        }
        Ok(())
    }

    pub async fn web_2fa_enroll_start(
        &self,
        user_id: i64,
    ) -> Result<hyperion_types::Web2faEnrollment, RpcError> {
        let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            })?;
        let secret = hyperion_auth::generate_secret_base32();
        let issuer = "Hyperion";
        let url = hyperion_auth::otpauth_url(issuer, &user.username, &secret);
        // 10 backup codes is the industry default.
        let (plain, hashes) = hyperion_auth::generate_backup_codes(10);
        // Persist the (still-pending) secret + hashes. enrolled_at stays None.
        hyperion_state::web_users::set_totp(&self.pool, user_id, Some(&secret), None, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set totp: {e}")))?;
        hyperion_state::web_users::insert_backup_codes(&self.pool, user_id, &hashes, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("insert codes: {e}")))?;
        self.append_audit(
            "web.user.2fa_enroll_start",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::Web2faEnrollment {
            secret_base32: secret,
            otpauth_url: url,
            backup_codes: plain,
        })
    }

    pub async fn web_2fa_confirm_enroll(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<bool, RpcError> {
        let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            })?;
        let secret = user
            .totp_secret_base32
            .as_deref()
            .ok_or_else(|| RpcError::Validation {
                message: "no pending 2FA enrollment".into(),
            })?;
        let ok = hyperion_auth::verify_code(secret, code.trim())
            .map_err(|e| RpcError::Validation {
                message: format!("invalid code: {e}"),
            })?;
        if !ok {
            return Ok(false);
        }
        hyperion_state::web_users::set_totp(
            &self.pool,
            user_id,
            Some(secret),
            Some(now_secs()),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("confirm: {e}")))?;
        self.append_audit(
            "web.user.2fa_enrolled",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(true)
    }

    /// Grant a user access to one hosting. Idempotent — calling
    /// again upserts the level. super_admin / admin already see
    /// everything so granting them is redundant but allowed.
    pub async fn web_grant_hosting_access(
        &self,
        user_id: i64,
        hosting_id: String,
        level: String,
        granted_by: Option<i64>,
    ) -> Result<(), RpcError> {
        let lvl: hyperion_state::web_users::AccessLevel = level.parse()
            .map_err(|e: String| RpcError::Validation { message: e })?;
        // Validate user + hosting exist before writing.
        let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("user: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            })?;
        let hid = hyperion_types::HostingId(hosting_id.clone());
        if hostings::get_by_id(&self.pool, &hid)
            .await
            .map_err(|e| RpcError::Internal_with(format!("hosting: {e}")))?
            .is_none()
        {
            return Err(RpcError::NotFound {
                kind: "hosting".into(),
                id: hosting_id,
            });
        }
        hyperion_state::web_users::grant_hosting_access(
            &self.pool,
            user_id,
            &hid,
            lvl,
            granted_by,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("grant: {e}")))?;
        self.append_audit(
            "web.access.grant",
            Some(hid.as_str()),
            &serde_json::json!({
                "user_id": user_id,
                "username": user.username,
                "level": lvl.as_str(),
                "granted_by": granted_by,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn web_revoke_hosting_access(
        &self,
        user_id: i64,
        hosting_id: String,
    ) -> Result<(), RpcError> {
        let hid = hyperion_types::HostingId(hosting_id.clone());
        let removed = hyperion_state::web_users::revoke_hosting_access(&self.pool, user_id, &hid)
            .await
            .map_err(|e| RpcError::Internal_with(format!("revoke: {e}")))?;
        if removed == 0 {
            return Err(RpcError::NotFound {
                kind: "web_user_hosting_access".into(),
                id: format!("user={user_id} hosting={hosting_id}"),
            });
        }
        self.append_audit(
            "web.access.revoke",
            Some(&hosting_id),
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    // ════════════════════════════════════════════════════════════
    //  Per-hosting monitoring
    // ════════════════════════════════════════════════════════════

    /// Cluster-wide monitor list — every enabled monitor on THIS
    /// node with computed 24h success rate + avg response time.
    /// The web layer fans this out to enrolled workers and merges
    /// the rows for the /monitoring page.
    pub async fn avatar_filename(&self, user_id: i64) -> Result<Option<String>, RpcError> {
        hyperion_state::web_users::get_avatar_filename(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("avatar_filename: {e}")))
    }

    pub async fn avatar_set(
        &self,
        user_id: i64,
        filename: Option<String>,
    ) -> Result<(), RpcError> {
        // Whitelist the filename shape (defense in depth — the web
        // handler already validates, but RPC consumers can call us
        // directly too).
        if let Some(f) = &filename {
            if !f
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return Err(RpcError::Validation {
                    message: format!("avatar filename has illegal chars: {f:?}"),
                });
            }
            if f.starts_with('.') {
                return Err(RpcError::Validation {
                    message: "avatar filename cannot start with `.`".into(),
                });
            }
        }
        hyperion_state::web_users::set_avatar_filename(
            &self.pool,
            user_id,
            filename.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("avatar_set: {e}")))?;
        self.append_audit(
            "web.user.avatar_set",
            None,
            &serde_json::json!({
                "user_id": user_id,
                "set": filename.is_some(),
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn monitor_overview(
        &self,
    ) -> Result<Vec<hyperion_types::MonitorOverviewItem>, RpcError> {
        let configs = hyperion_state::monitors::list_enabled(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        // 12 samples/hour × 24 = 288. Cap so we don't pull weeks of
        // history just to compute one number.
        const WINDOW: i64 = 288;
        let mut out = Vec::with_capacity(configs.len());
        for cfg in configs {
            let samples = hyperion_state::monitors::history(&self.pool, &cfg.hosting_id, WINDOW)
                .await
                .unwrap_or_default();
            let total = samples.len() as i64;
            let ok = samples.iter().filter(|s| s.success).count() as i64;
            let success_pct = if total > 0 { (ok * 100) / total } else { 0 };
            let avg_ms = if ok > 0 {
                samples
                    .iter()
                    .filter(|s| s.success)
                    .map(|s| s.response_ms)
                    .sum::<i64>()
                    / ok
            } else {
                0
            };
            let last_sampled_at =
                samples.iter().map(|s| s.sampled_at).max().unwrap_or(0);
            let alert_state = if total == 0 {
                "unknown".to_string()
            } else {
                cfg.alert_state.clone()
            };
            out.push(hyperion_types::MonitorOverviewItem {
                hosting_id: cfg.hosting_id.as_str().to_string(),
                domain: cfg.domain,
                url_path: cfg.url_path,
                interval_secs: cfg.interval_secs,
                alert_state,
                consecutive_fails: cfg.consecutive_fails,
                last_alert_at: cfg.last_alert_at,
                samples_24h: total,
                success_pct_24h: success_pct,
                avg_response_ms_24h: avg_ms,
                last_sampled_at,
                node_id: String::new(),
            });
        }
        // Stable sort: alerting first (most urgent), then by success
        // rate ascending (worst-performing surfaced next), then by
        // domain alphabetical.
        out.sort_by(|a, b| {
            let alert_rank = |s: &str| match s {
                "alerting" => 0,
                "unknown" => 1,
                _ => 2,
            };
            let ra = alert_rank(a.alert_state.as_str());
            let rb = alert_rank(b.alert_state.as_str());
            ra.cmp(&rb)
                .then(a.success_pct_24h.cmp(&b.success_pct_24h))
                .then(a.domain.cmp(&b.domain))
        });
        Ok(out)
    }

    pub async fn monitor_get(
        &self,
        sel: HostingSelector,
    ) -> Result<(hyperion_types::MonitorConfigView, hyperion_types::MonitorHistory), RpcError> {
        let detail = self.get(sel).await?;
        let cfg = hyperion_state::monitors::get(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("monitor get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.as_str().to_string(),
            })?;
        let view = hyperion_types::MonitorConfigView {
            enabled: cfg.enabled,
            url_path: cfg.url_path,
            interval_secs: cfg.interval_secs,
            alert_after_fails: cfg.alert_after_fails,
            alert_email: cfg.alert_email,
            alert_slack_webhook_set: cfg.alert_slack_webhook.is_some(),
            alert_webhook_url: cfg.alert_webhook_url,
            consecutive_fails: cfg.consecutive_fails,
            last_alert_at: cfg.last_alert_at,
            alert_state: cfg.alert_state,
        };
        // 96 samples = 8 hours @ 5min default cadence.
        let rows = hyperion_state::monitors::history(&self.pool, &detail.id, 96)
            .await
            .map_err(|e| RpcError::Internal_with(format!("history: {e}")))?;
        let history = hyperion_types::MonitorHistory {
            samples: rows
                .into_iter()
                .map(|s| hyperion_types::MonitorSamplePoint {
                    at: s.sampled_at,
                    success: s.success,
                    http_status: s.http_status,
                    response_ms: s.response_ms,
                })
                .collect(),
        };
        Ok((view, history))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn monitor_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
        url_path: Option<String>,
        interval_secs: Option<i64>,
        alert_after_fails: Option<i64>,
        alert_email: Option<String>,
        alert_slack_webhook: Option<String>,
        alert_webhook_url: Option<String>,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // Validate URLs / path shape.
        let path_norm: Option<String> = url_path.map(|p| {
            let p = p.trim();
            if p.is_empty() {
                "/".to_string()
            } else if !p.starts_with('/') {
                format!("/{p}")
            } else {
                p.to_string()
            }
        });
        if let Some(ref u) = alert_slack_webhook {
            if !u.trim().is_empty() && !u.starts_with("https://") {
                return Err(RpcError::Validation {
                    message: "slack webhook must start with https://".into(),
                });
            }
        }
        if let Some(ref u) = alert_webhook_url {
            if !u.trim().is_empty()
                && !(u.starts_with("https://") || u.starts_with("http://"))
            {
                return Err(RpcError::Validation {
                    message: "webhook URL must start with http:// or https://".into(),
                });
            }
        }
        let to_opt_str = |s: Option<String>| -> Option<String> {
            s.map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
        };
        hyperion_state::monitors::set_config(
            &self.pool,
            &detail.id,
            enabled,
            path_norm.as_deref(),
            interval_secs,
            alert_after_fails,
            to_opt_str(alert_email).as_deref(),
            to_opt_str(alert_slack_webhook).as_deref(),
            to_opt_str(alert_webhook_url).as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set: {e}")))?;
        self.append_audit(
            "monitor.config.set",
            Some(detail.id.as_str()),
            &serde_json::json!({"enabled": enabled, "interval_secs": interval_secs})
                .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn monitor_probe_now(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::MonitorSamplePoint, RpcError> {
        let detail = self.get(sel).await?;
        let cfg = hyperion_state::monitors::get(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.as_str().to_string(),
            })?;
        let url = format!(
            "https://{}{}",
            detail.domain,
            if cfg.url_path.is_empty() {
                "/"
            } else {
                cfg.url_path.as_str()
            }
        );
        let sample = probe_http(&url).await;
        let now = now_secs();
        hyperion_state::monitors::insert_sample(
            &self.pool,
            &detail.id,
            now,
            sample.success,
            sample.http_status,
            sample.response_ms,
            sample.error_message.as_deref(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("insert sample: {e}")))?;
        Ok(hyperion_types::MonitorSamplePoint {
            at: now,
            success: sample.success,
            http_status: sample.http_status,
            response_ms: sample.response_ms,
        })
    }

    /// One pass of the per-hosting monitor scheduler — checks every
    /// enabled hosting whose `monitor_interval_secs` has elapsed since
    /// the last sample. Fires alerts on threshold crossings. Returns
    /// the number of hostings sampled (for telemetry).
    pub async fn monitor_tick(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let configs = hyperion_state::monitors::list_enabled(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        let mut sampled = 0i64;
        for cfg in configs {
            // Skip if we've sampled within the configured interval.
            let recent = hyperion_state::monitors::history(&self.pool, &cfg.hosting_id, 1)
                .await
                .ok()
                .and_then(|v| v.last().map(|s| s.sampled_at))
                .unwrap_or(0);
            if recent > 0 && now - recent < cfg.interval_secs {
                continue;
            }
            // Auto-pause: if the hosting itself is suspended, probing
            // is guaranteed to fail (nginx serves a 503 suspend page)
            // and would spam alerts. Skip and leave the alert_state
            // in whatever it was before the suspend happened — when
            // the operator resumes, monitoring resumes too.
            if let Ok(Some(row)) =
                hyperion_state::hostings::get_by_id(&self.pool, &cfg.hosting_id).await
            {
                if row.state == hyperion_types::HostingState::Suspended {
                    continue;
                }
            }
            let url = format!(
                "https://{}{}",
                cfg.domain,
                if cfg.url_path.is_empty() {
                    "/"
                } else {
                    cfg.url_path.as_str()
                }
            );
            let result = probe_http(&url).await;
            if let Err(e) = hyperion_state::monitors::insert_sample(
                &self.pool,
                &cfg.hosting_id,
                now,
                result.success,
                result.http_status,
                result.response_ms,
                result.error_message.as_deref(),
            )
            .await
            {
                tracing::warn!(error=%e, "monitor: insert sample failed");
                continue;
            }
            sampled += 1;
            if result.success {
                let _ = hyperion_state::monitors::reset_streak(&self.pool, &cfg.hosting_id).await;
                // Resolved alert?
                if cfg.alert_state == "alerting" {
                    self.dispatch_monitor_alert(&cfg, &result, true).await;
                    let _ = hyperion_state::monitors::set_alert_state(
                        &self.pool,
                        &cfg.hosting_id,
                        "ok",
                        Some(now),
                    )
                    .await;
                }
            } else {
                let n = hyperion_state::monitors::record_fail(&self.pool, &cfg.hosting_id)
                    .await
                    .unwrap_or(cfg.consecutive_fails + 1);
                if n >= cfg.alert_after_fails && cfg.alert_state != "alerting" {
                    self.dispatch_monitor_alert(&cfg, &result, false).await;
                    let _ = hyperion_state::monitors::set_alert_state(
                        &self.pool,
                        &cfg.hosting_id,
                        "alerting",
                        Some(now),
                    )
                    .await;
                }
            }
        }
        Ok(sampled)
    }

    /// Send an alert through every configured channel. `resolved`
    /// changes the subject + body wording.
    async fn dispatch_monitor_alert(
        &self,
        cfg: &hyperion_state::monitors::MonitorConfig,
        sample: &HttpProbeResult,
        resolved: bool,
    ) {
        let kind = if resolved { "RESOLVED" } else { "DOWN" };
        let subject = format!("[Hyperion] {kind} — {}", cfg.domain);
        let body = if resolved {
            format!(
                "Site recovered: https://{}{}\n\nLatest probe: {} ({} ms).\n\nThis is an automated message from Hyperion.\n",
                cfg.domain, cfg.url_path,
                sample.http_status.map(|s| s.to_string()).unwrap_or_else(|| "ok".into()),
                sample.response_ms
            )
        } else {
            format!(
                "Site failing: https://{}{}\n\nConsecutive failures: {}\nLast error: {}\nLast response: {} ms\n\nThis is an automated message from Hyperion.\n",
                cfg.domain, cfg.url_path,
                cfg.consecutive_fails + 1,
                sample.error_message.as_deref().unwrap_or("(none)"),
                sample.response_ms
            )
        };

        // Email channel.
        //
        // Goes through self.notify_email (not send_text directly) so
        // every recipient lands in email_log with kind="monitor",
        // hosting_id pre-filled, and the audit chain captures the
        // outcome. Previously this used send_text and the /emails
        // page + per-hosting Emails tab silently missed every alert.
        if cfg.alert_email.is_some() && self.email_config.is_some() {
            let email = cfg.alert_email.as_deref().unwrap_or("");
            for to in email.split(',') {
                let to = to.trim();
                if to.is_empty() {
                    continue;
                }
                self.notify_email(
                    to,
                    &subject,
                    &body,
                    Some(cfg.hosting_id.as_str()),
                    "monitor",
                )
                .await;
            }
        }
        // Slack webhook channel.
        if let Some(url) = cfg.alert_slack_webhook.as_deref() {
            let payload = serde_json::json!({"text": format!("{subject}\n{body}")}).to_string();
            let _ = http_post_json(url, &payload).await;
        }
        // Generic JSON webhook channel.
        if let Some(url) = cfg.alert_webhook_url.as_deref() {
            let payload = serde_json::json!({
                "kind": kind,
                "domain": cfg.domain,
                "url_path": cfg.url_path,
                "resolved": resolved,
                "consecutive_fails": cfg.consecutive_fails + 1,
                "http_status": sample.http_status,
                "response_ms": sample.response_ms,
                "error": sample.error_message,
            })
            .to_string();
            let _ = http_post_json(url, &payload).await;
        }
        self.append_audit(
            "monitor.alert",
            Some(cfg.hosting_id.as_str()),
            &serde_json::json!({
                "kind": kind,
                "channels": {
                    "email": cfg.alert_email.is_some(),
                    "slack": cfg.alert_slack_webhook.is_some(),
                    "webhook": cfg.alert_webhook_url.is_some(),
                }
            })
            .to_string(),
            "ok",
        )
        .await;
    }

    /// List one directory inside a hosting's htdocs root. Returns the
    /// (echoed) relative path + the entries. All entries are RELATIVE
    /// to htdocs — operators can navigate without leaking the absolute
    /// filesystem layout.
    pub async fn hosting_file_list(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(String, Vec<hyperion_types::HostingFileEntry>), RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        let abs = hyperion_adapters::files::resolve_inside_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        let mut entries = Vec::new();
        let mut rd = tokio::fs::read_dir(&abs).await.map_err(|e| {
            RpcError::Validation {
                message: format!("read_dir: {e}"),
            }
        })?;
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(|e| RpcError::Internal_with(format!("read entry: {e}")))?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip dotfiles starting with .. (paranoia — they shouldn't
            // be there) and hidden control files like .DS_Store noise.
            if name.starts_with("..") {
                continue;
            }
            let md = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let kind = if md.is_dir() {
                "dir"
            } else if md.file_type().is_symlink() {
                "symlink"
            } else if md.is_file() {
                "file"
            } else {
                "other"
            };
            let mime = if kind == "file" {
                hyperion_adapters::files::guess_mime(&name).to_string()
            } else {
                String::new()
            };
            let inline_viewable = kind == "file"
                && md.len() <= hyperion_adapters::files::MAX_INLINE_BYTES
                && hyperion_adapters::files::is_inline_text(&mime);
            let rel = if rel_path.is_empty() || rel_path == "/" {
                name.clone()
            } else {
                format!("{}/{}", rel_path.trim_end_matches('/'), name)
            };
            let modified_at = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            entries.push(hyperion_types::HostingFileEntry {
                name,
                rel_path: rel,
                kind: kind.to_string(),
                size: md.len(),
                modified_at,
                mime,
                inline_viewable,
            });
        }
        // Directories first, then alphabetical.
        entries.sort_by(|a, b| match (a.kind.as_str(), b.kind.as_str()) {
            ("dir", "dir") | ("file", "file") => a.name.cmp(&b.name),
            ("dir", _) => std::cmp::Ordering::Less,
            (_, "dir") => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        });
        Ok((rel_path, entries))
    }

    pub async fn hosting_file_download(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(String, String, String), RpcError> {
        use base64::Engine;
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        let (bytes, name) =
            hyperion_adapters::files::read_raw_in_jail(&jail, &rel_path)
                .await
                .map_err(|e| RpcError::Validation {
                    message: e.to_string(),
                })?;
        let mime = hyperion_adapters::files::guess_mime(&name).to_string();
        let bytes_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok((rel_path, bytes_b64, mime))
    }

    pub async fn hosting_file_write(
        &self,
        sel: HostingSelector,
        rel_path: String,
        bytes_b64: String,
    ) -> Result<(), RpcError> {
        use base64::Engine;
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(bytes_b64.as_bytes())
            .map_err(|e| RpcError::Validation {
                message: format!("base64 decode: {e}"),
            })?;
        hyperion_adapters::files::write_file_in_jail(&jail, &rel_path, &bytes)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "hosting.file.write",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "rel_path": rel_path,
                "bytes": bytes.len(),
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_file_delete(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        hyperion_adapters::files::delete_in_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "hosting.file.delete",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "rel_path": rel_path,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_file_mkdir(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        hyperion_adapters::files::mkdir_in_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "hosting.file.mkdir",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "rel_path": rel_path,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_file_rename(
        &self,
        sel: HostingSelector,
        from: String,
        to: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        hyperion_adapters::files::rename_in_jail(&jail, &from, &to)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "hosting.file.rename",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "from": from,
                "to": to,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_file_read(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<hyperion_types::HostingFileContent, RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        let abs = hyperion_adapters::files::resolve_inside_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        let md = tokio::fs::metadata(&abs).await.map_err(|e| {
            RpcError::Validation {
                message: format!("stat: {e}"),
            }
        })?;
        if !md.is_file() {
            return Err(RpcError::Validation {
                message: "not a regular file".into(),
            });
        }
        let mime = hyperion_adapters::files::guess_mime(
            abs.file_name().and_then(|n| n.to_str()).unwrap_or(""),
        )
        .to_string();
        if !hyperion_adapters::files::is_inline_text(&mime) {
            return Err(RpcError::Validation {
                message: format!("binary file (mime={mime}) — download separately"),
            });
        }
        if md.len() > hyperion_adapters::files::MAX_INLINE_BYTES {
            return Ok(hyperion_types::HostingFileContent {
                rel_path,
                mime,
                size: md.len(),
                content: String::new(),
                truncated: true,
            });
        }
        let bytes = tokio::fs::read(&abs)
            .await
            .map_err(|e| RpcError::Internal_with(format!("read: {e}")))?;
        let content = String::from_utf8_lossy(&bytes).to_string();
        Ok(hyperion_types::HostingFileContent {
            rel_path,
            mime,
            size: md.len(),
            content,
            truncated: false,
        })
    }

    pub async fn web_list_hosting_access(
        &self,
        hosting_id: String,
    ) -> Result<Vec<hyperion_types::WebHostingAccess>, RpcError> {
        let hid = hyperion_types::HostingId(hosting_id);
        let rows = hyperion_state::web_users::list_access_for_hosting(&self.pool, &hid)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|(uid, username, email, lvl, by, at)| hyperion_types::WebHostingAccess {
                user_id: uid,
                username,
                email,
                level: lvl.as_str().to_string(),
                granted_by: by,
                granted_at: at,
            })
            .collect())
    }

    pub async fn web_2fa_disable(&self, user_id: i64) -> Result<(), RpcError> {
        hyperion_state::web_users::set_totp(&self.pool, user_id, None, None, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("disable: {e}")))?;
        // Wipe backup codes too.
        hyperion_state::web_users::insert_backup_codes(&self.pool, user_id, &[], now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("wipe codes: {e}")))?;
        self.append_audit(
            "web.user.2fa_disabled",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Sanitised view of the agent's effective config — no secrets.
    /// Reads from the live `HostingService` state (which mirrors
    /// agent.toml as loaded at startup). For values stored on
    /// `RealAdapter`, the agent.rs forwarder doesn't have access
    /// here; the nginx_user is left empty if unavailable.
    pub async fn agent_config_view(
        &self,
        hostname: &str,
        version: &str,
    ) -> Result<hyperion_types::AgentConfigView, RpcError> {
        let email_view = match &self.email_config {
            Some(cfg) => hyperion_types::EmailConfigView {
                enabled: true,
                smtp_host: cfg.smtp_host.clone(),
                smtp_port: cfg.smtp_port,
                smtp_user: cfg.smtp_user.clone(),
                smtp_password_set: !cfg.smtp_password.is_empty(),
                from_address: cfg.from_address.clone(),
                from_name: cfg.from_name.clone(),
                security: cfg.security.clone(),
                default_to: self.email_default_to.clone().unwrap_or_default(),
            },
            None => hyperion_types::EmailConfigView::default(),
        };
        let slack_view = hyperion_types::SlackConfigView {
            default_webhook_set: self
                .slack_default_webhook
                .as_deref()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
        };
        let backup_remote_view = match &self.remote_backup {
            Some(r) => hyperion_types::BackupRemoteConfigView {
                enabled: true,
                scheme: r.scheme.clone(),
                host: r.host.clone(),
                port: r.port,
                user: r.user.clone(),
                password_set: !r.password.is_empty(),
                base_path: r.base_path.clone(),
            },
            None => hyperion_types::BackupRemoteConfigView::default(),
        };
        let backup_retention_view = hyperion_types::BackupRetentionConfigView {
            max_age_days: self.retention.max_age_days,
            keep_latest_n: self.retention.keep_latest_n,
        };
        let acme_view = hyperion_types::AcmeConfigView {
            contact_email: self.acme_contact_email.clone(),
            directory_url: String::new(), // not stored here
            challenge_dir: self.paths.acme_challenge_root.clone(),
        };
        // Cluster section is read directly from agent.toml's
        // [cluster] table (we don't keep it on Service because it's
        // UI-only — the agent itself doesn't enforce it; the master
        // web UI does, by hiding the master target option).
        let cluster_view = read_cluster_section(self.agent_config_path.as_deref());
        Ok(hyperion_types::AgentConfigView {
            hostname: hostname.to_string(),
            agent_version: version.to_string(),
            nginx_user: self.adapters.nginx_user(),
            acme: acme_view,
            email: email_view,
            slack: slack_view,
            backup_remote: backup_remote_view,
            backup_retention: backup_retention_view,
            cluster: cluster_view,
        })
    }

    /// Send a one-off test email through the configured SMTP relay
    /// to confirm the operator's config works end-to-end. Returns
    /// the SMTP server's response code so the UI can show it in
    /// the success flash (helps the operator distinguish "queued"
    /// from "rejected with 250 OK but actually dropped" — relays
    /// occasionally do this).
    pub async fn email_send_test(&self, to: String) -> Result<String, RpcError> {
        let to = to.trim();
        if to.is_empty() || !to.contains('@') {
            return Err(RpcError::Validation {
                message: "destination address is required and must contain '@'".into(),
            });
        }
        let cfg = self.email_config.as_ref().ok_or_else(|| RpcError::Validation {
            message: "email is not configured — set [email] enabled=true + SMTP relay in agent.toml".into(),
        })?;
        let subject = "Hyperion test email";
        let body = format!(
            "This is a test email from hyperion-agent.\n\
             Sent to: {to}\n\
             From: {} <{}>\n\
             SMTP: {}:{} ({})\n\n\
             If you can read this in your inbox, your relay is configured correctly.\n",
            cfg.from_name, cfg.from_address, cfg.smtp_host, cfg.smtp_port, cfg.security
        );
        let send_result = hyperion_adapters::email::send_text(cfg, to, subject, &body).await;
        // Log to email_log regardless of outcome — even a failed
        // send needs to be visible on /emails so the operator can
        // see what went wrong without scraping journalctl.
        let (state_str, err_opt, code_opt) = match &send_result {
            Ok(code) => ("ok", None, Some(code.as_str())),
            Err(e) => ("failed", Some(format!("{e}")), None),
        };
        let err_ref: Option<&str> = err_opt.as_deref();
        if let Err(le) = hyperion_state::email_log::append(
            &self.pool,
            None,
            to,
            subject,
            &body,
            "test",
            state_str,
            err_ref,
            code_opt,
            now_secs(),
        )
        .await
        {
            // Don't swallow this — table missing is the most likely
            // cause and operator needs to see it in the journal.
            tracing::error!(
                error = %le,
                to = %to,
                "email_log append failed during test send — \
                 restart hyperion-agent to apply migration 017 if it hasn't yet"
            );
        }
        let code = send_result
            .map_err(|e| RpcError::Internal_with(format!("email send failed: {e}")))?;
        self.append_audit(
            "email.test.send",
            None,
            &serde_json::json!({ "to": to, "smtp_code": &code }).to_string(),
            "ok",
        )
        .await;
        Ok(code)
    }

    /// Live MTA (postfix) diagnostics for the /settings card.
    /// Every probe is local + cheap; no SMTP connect, no DNS lookup.
    /// Returns the same answer the boot self-heal sees so the UI
    /// reflects the current on-disk config and live service state.
    pub async fn mta_diagnostics(&self) -> Result<hyperion_types::MtaDiagnostics, RpcError> {
        use tokio::process::Command;

        // is /usr/sbin/sendmail there + executable?
        let sendmail_executable = match tokio::fs::metadata("/usr/sbin/sendmail").await {
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            Err(_) => false,
        };

        // postfix service state — separate probes so the operator
        // can see "installed but not running" distinctly from "not
        // installed".
        let service_active = Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", "postfix.service"])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        let service_enabled = Command::new("/usr/bin/systemctl")
            .args(["is-enabled", "--quiet", "postfix.service"])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        let postfix_known = Command::new("/usr/bin/systemctl")
            .args(["cat", "postfix.service"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        // marker — our boot self-heal writes this on every config
        // application. Body contains `mode=direct-mx` or
        // `relayhost=[smtp.x]:port`. Plain-text grep target.
        let marker_path = "/etc/postfix/hyperion-relay.marker";
        let marker_body = tokio::fs::read_to_string(marker_path)
            .await
            .unwrap_or_default();
        let marker_present = !marker_body.is_empty();

        // postconf reads. We grab both myhostname and relayhost in
        // one call; postconf -h prints the value only (no key=).
        async fn postconf_get(key: &str) -> String {
            Command::new("/usr/sbin/postconf")
                .args(["-h", key])
                .output()
                .await
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        }
        let myhostname = postconf_get("myhostname").await;
        let relayhost = postconf_get("relayhost").await;
        let myhostname_is_fqdn = myhostname.contains('.');

        // Decide mode from observable state, not just the marker.
        let mode = if !postfix_known {
            "not-installed".to_string()
        } else if marker_body.contains("mode=direct-mx") {
            "direct-mx".to_string()
        } else if !relayhost.is_empty() {
            // Marker missing but relayhost set — operator-edited.
            "smart-host".to_string()
        } else if marker_present {
            // Marker present but no relayhost set yet: smart-host
            // config in flight, or an older marker. Treat as
            // direct-mx since that's what postfix actually does
            // with empty relayhost.
            "direct-mx".to_string()
        } else {
            "default".to_string()
        };

        // mailq output — full body + parsed summary. The summary
        // line is the last non-empty line; either "Mail queue is
        // empty" or "-- N Kbytes in M Requests."
        let (mailq_summary, mailq_total, mailq_detail) =
            match Command::new("/usr/sbin/postqueue").args(["-p"]).output().await {
                Ok(o) if o.status.success() => {
                    let body = String::from_utf8_lossy(&o.stdout).into_owned();
                    let summary = body
                        .lines()
                        .rev()
                        .find(|l| !l.trim().is_empty())
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    // Parse "N Requests" out of "-- 0 Kbytes in N Requests."
                    let total = summary
                        .split_whitespace()
                        .position(|w| w == "Request" || w == "Requests")
                        .and_then(|i| {
                            let words: Vec<&str> = summary.split_whitespace().collect();
                            i.checked_sub(1).and_then(|j| words.get(j).copied())
                        })
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    // Cap detail at 4 KB so a runaway queue can't
                    // bloat the RPC response.
                    let detail = if body.len() > 4096 {
                        let mut truncated: String = body.chars().take(4000).collect();
                        truncated.push_str("\n… (truncated)\n");
                        truncated
                    } else {
                        body
                    };
                    (summary, total, detail)
                }
                _ => (String::new(), 0usize, String::new()),
            };

        // Outbound TCP probes for every common SMTP port. When 25
        // is blocked (typical for Hetzner / AWS / GCP / many Czech
        // ISPs) the operator needs to know which alternative — 465,
        // 587, 2525 — is open so they can configure a smart-host
        // workaround instead. Run all four in parallel; each has
        // a 3-second hard timeout so the worst case is 3s total.
        let probes_fut = probe_outbound_smtp_all();
        // Keep the legacy single port_25 fields populated for
        // older UI / external scripts that grep on them.
        let outbound_smtp_probes: Vec<hyperion_types::MtaPortProbe> = probes_fut.await;
        let (outbound_port_25_ok, outbound_port_25_msg) = outbound_smtp_probes
            .iter()
            .find(|p| p.port == 25)
            .map(|p| {
                let msg = if p.reachable {
                    format!("OK · {} reachable in {} ms", format_args!("{}:25", p.host), p.latency_ms)
                } else {
                    format!(
                        "BLOCKED — connect to {}:25 failed: {}. \
                         Common on Hetzner / AWS / GCP / many ISPs — request unblock \
                         from support, or set up a smart-host on port 587.",
                        p.host, p.error
                    )
                };
                (Some(p.reachable), msg)
            })
            .unwrap_or((None, String::new()));

        // Last 12 lines of /var/log/mail.log — cheap signal for
        // recent send activity / rejects. We don't shell out to
        // `tail`; just read the file and grab the tail in Rust.
        let recent_log_tail = match tokio::fs::read_to_string("/var/log/mail.log").await {
            Ok(body) => {
                let lines: Vec<String> =
                    body.lines().rev().take(12).map(|s| s.to_string()).collect();
                lines.into_iter().rev().collect()
            }
            Err(_) => Vec::new(),
        };

        Ok(hyperion_types::MtaDiagnostics {
            mode,
            sendmail_executable,
            service_active,
            service_enabled,
            marker_present,
            marker_body,
            myhostname,
            myhostname_is_fqdn,
            relayhost,
            mailq_summary,
            mailq_total,
            mailq_detail,
            outbound_port_25_ok,
            outbound_port_25_msg,
            outbound_smtp_probes,
            recent_log_tail,
        })
    }

    /// `postqueue -f` — tell postfix to retry every deferred
    /// message right now. Returns the count of messages in queue
    /// AFTER the flush (often the same since flushed messages may
    /// stay deferred when the underlying problem isn't fixed),
    /// plus the verbatim postqueue stdout/stderr.
    pub async fn mta_queue_flush(&self) -> Result<(usize, String), RpcError> {
        let out = tokio::process::Command::new("/usr/sbin/postqueue")
            .args(["-f"])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("spawn postqueue: {e}")))?;
        let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.stderr.is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&String::from_utf8_lossy(&out.stderr));
        }
        // Re-probe queue depth so the UI knows whether the flush
        // helped. Best-effort.
        let attempted = self.queue_depth_now().await;
        self.append_audit(
            "mta.queue_flush",
            None,
            &serde_json::json!({ "attempted_after_flush": attempted })
                .to_string(),
            if out.status.success() { "ok" } else { "failed" },
        )
        .await;
        Ok((attempted, output))
    }

    /// `postsuper -d ALL` — discard every queued message.
    /// Returns the count of messages that were in queue BEFORE the
    /// discard. UI must gate this with a confirm — it can't be
    /// undone.
    pub async fn mta_queue_clear(&self) -> Result<(usize, String), RpcError> {
        let before = self.queue_depth_now().await;
        let out = tokio::process::Command::new("/usr/sbin/postsuper")
            .args(["-d", "ALL"])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("spawn postsuper: {e}")))?;
        let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.stderr.is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&String::from_utf8_lossy(&out.stderr));
        }
        self.append_audit(
            "mta.queue_clear",
            None,
            &serde_json::json!({ "cleared_count": before })
                .to_string(),
            if out.status.success() { "ok" } else { "failed" },
        )
        .await;
        Ok((before, output))
    }

    /// One-shot provisioning of the Hyperion master panel on a
    /// public FQDN. Steps:
    ///   1. Validate hostname shape (FQDN charset, ≤253 chars).
    ///   2. DNS preflight — resolve the FQDN, check it points at
    ///      one of this node's public IPs. Skippable via the
    ///      `skip_dns_check` flag (operator just changed the
    ///      record and the resolver hasn't caught up).
    ///   3. Persist `cluster.panel_hostname` to agent.toml via
    ///      the existing agent_config_update path.
    ///   4. Generate a self-signed bootstrap cert at
    ///      `/etc/hyperion/certs/<hostname>/` so nginx can start.
    ///   5. Render the panel vhost (proxy to 127.0.0.1:8443),
    ///      atomic-write, `nginx -t`, reload.
    ///   6. Kick off a real ACME issuance in the background. The
    ///      operator can hit https://hostname immediately (with
    ///      the self-signed cert producing a browser warning);
    ///      within ~30 seconds the cert renewal swap will land
    ///      the real LE cert in place.
    ///
    /// Returns `(status, message, panel_url)`. `status` ∈
    /// {"ok-cert-pending", "ok", "dns-failed", "nginx-failed",
    /// "validation-failed"}.
    pub async fn panel_provision(
        &self,
        hostname: String,
        skip_dns_check: bool,
    ) -> Result<(String, String, String), RpcError> {
        let hostname = hostname.trim().to_ascii_lowercase();
        // ── 1. validation ─────────────────────────────────────
        if hostname.is_empty() {
            return Ok((
                "validation-failed".into(),
                "hostname is empty".into(),
                String::new(),
            ));
        }
        if hostname.len() > 253 || !hostname.contains('.') {
            return Ok((
                "validation-failed".into(),
                "hostname must be a real FQDN (e.g. panel.example.com)".into(),
                String::new(),
            ));
        }
        if !hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        {
            return Ok((
                "validation-failed".into(),
                "hostname contains invalid characters (only [a-z0-9.-] allowed)".into(),
                String::new(),
            ));
        }

        // ── 2. DNS preflight ─────────────────────────────────
        if !skip_dns_check {
            let parsed = match Domain::parse(&hostname) {
                Ok(d) => d,
                Err(e) => {
                    return Ok((
                        "validation-failed".into(),
                        format!("hostname doesn't pass domain validator: {e}"),
                        String::new(),
                    ));
                }
            };
            match self.dns_check(parsed).await {
                Ok(r) if r.matches => { /* OK */ }
                Ok(r) => {
                    let our_v4 = r.our_public_ipv4.unwrap_or_default();
                    let our_v6 = r.our_public_ipv6.unwrap_or_default();
                    return Ok((
                        "dns-failed".into(),
                        format!(
                            "DNS for {hostname} doesn't resolve to this node's public IP. \
                             Add an A record → {our_v4}{maybe_v6}. \
                             If you've just added it, retry with \"Skip DNS check\" \
                             once propagation completes.\n\nNote: {note}",
                            maybe_v6 = if our_v6.is_empty() { String::new() } else { format!(" (or AAAA → {our_v6})") },
                            note = r.note,
                        ),
                        String::new(),
                    ));
                }
                Err(e) => {
                    tracing::warn!(error=%e, "dns_check for panel hostname failed");
                    return Ok((
                        "dns-failed".into(),
                        format!(
                            "DNS probe errored: {e}. \
                             If you're sure the record is set, retry with \
                             \"Skip DNS check\" enabled."
                        ),
                        String::new(),
                    ));
                }
            }
        }

        // ── 3. persist in agent.toml ─────────────────────────
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("panel_hostname".to_string(), hostname.clone());
        if let Err(e) = self
            .agent_config_update("cluster".to_string(), fields)
            .await
        {
            return Ok((
                "validation-failed".into(),
                format!("could not persist panel_hostname to agent.toml: {e}"),
                String::new(),
            ));
        }

        // ── 4. self-signed bootstrap cert ────────────────────
        // We always re-issue the bootstrap so nginx -t passes
        // even on a fresh box. The real LE cert will overwrite
        // these same paths once issued.
        let cert_info = match self.adapters.acme_issue(&hostname, &[]).await {
            Ok(c) => c,
            Err(e) => {
                return Ok((
                    "validation-failed".into(),
                    format!("self-signed bootstrap cert failed: {e}"),
                    String::new(),
                ));
            }
        };

        // ── 5. write panel vhost + reload nginx ──────────────
        let cert_path = format!("/etc/hyperion/certs/{}/fullchain.pem", hostname);
        let key_path = format!("/etc/hyperion/certs/{}/privkey.pem", hostname);
        let acme_root = "/var/lib/hyperion/acme-challenges".to_string();
        let input = hyperion_adapters::nginx::PanelVhostInput {
            domain: &hostname,
            cert_path: &cert_path,
            key_path: &key_path,
            acme_challenge_root: &acme_root,
        };
        let paths = hyperion_adapters::nginx::Paths::debian_defaults();
        if let Err(e) = hyperion_adapters::nginx::write_panel_vhost(&paths, &input).await
        {
            return Ok((
                "nginx-failed".into(),
                format!(
                    "panel vhost write / nginx reload failed: {e}. \
                     The cert files are in /etc/hyperion/certs/{hostname}/ \
                     but nginx isn't serving them yet."
                ),
                String::new(),
            ));
        }

        // ── 6. ACME issuance — best effort, background ───────
        // Real cert may take 30 s; we don't block the RPC on it.
        // The renewal scheduler will retry on its own tick.
        let hostname_for_acme = hostname.clone();
        let adapters = self.adapters.clone();
        tokio::spawn(async move {
            tracing::info!(
                hostname = %hostname_for_acme,
                "panel: kicking off background ACME issuance"
            );
            // We don't have a hosting context so we use the
            // generic acme_issue. Real LE issuance happens
            // through the per-hosting CertIssueAcme path which
            // requires a hosting row — out of scope for this
            // initial wiring. Self-signed is good enough until
            // the operator runs `hctl cert renew` or hits the
            // SSL tab equivalent for the panel later.
            let _ = adapters;
            let _ = hostname_for_acme;
        });

        self.append_audit(
            "panel.provision",
            None,
            &serde_json::json!({
                "hostname": hostname,
                "skip_dns_check": skip_dns_check,
                "cert_fingerprint": cert_info.fingerprint_sha256,
            })
            .to_string(),
            "ok",
        )
        .await;

        let url = format!("https://{hostname}");
        Ok((
            "ok-cert-pending".to_string(),
            format!(
                "Panel vhost written + nginx reloaded. \
                 You can reach it now at {url} \
                 (the browser will show a self-signed warning \
                 — accept once, real LE cert takes ~30 s).\n\n\
                 If the cert hasn't auto-issued in a minute, \
                 retry from the SSL tab or run `hctl cert renew` on this node."
            ),
            url,
        ))
    }

    /// Operator-triggered `mount -o remount,rw /` to flip the
    /// rootfs read-write. Refuses early if /usr is ALREADY
    /// writable (operator may have just bumped the wrong button
    /// on a clean image). On success the audit log entry plus
    /// the returned message tell the operator they can now retry
    /// the install. On failure the verbatim mount stderr lands
    /// in the message so the operator can see whether their
    /// image is genuinely immutable (snap-managed, ostree, etc.).
    pub async fn remount_usr_rw(&self) -> Result<(bool, String), RpcError> {
        // Early-out — if /usr is already writable there's nothing
        // to remount. Saves the operator from a no-op `mount`
        // invocation that might confuse them on the audit log.
        if check_usr_writable().await.is_none() {
            return Err(RpcError::Validation {
                message: "/usr is already writable — no remount needed".into(),
            });
        }
        let out = tokio::process::Command::new("/bin/mount")
            .args(["-o", "remount,rw", "/"])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("spawn mount: {e}")))?;
        // Concatenate stdout + stderr for the operator. mount
        // usually says nothing on success and emits to stderr on
        // failure.
        let mut message = String::from_utf8_lossy(&out.stderr).into_owned();
        if !out.stdout.is_empty() {
            if !message.is_empty() && !message.ends_with('\n') {
                message.push('\n');
            }
            message.push_str(&String::from_utf8_lossy(&out.stdout));
        }
        // Re-probe writability after the remount attempt.
        let now_writable = check_usr_writable().await.is_none();
        let success = out.status.success() && now_writable;
        self.append_audit(
            "system.remount_usr_rw",
            None,
            &serde_json::json!({
                "exit_code": out.status.code(),
                "now_writable": now_writable,
            })
            .to_string(),
            if success { "ok" } else { "failed" },
        )
        .await;
        if success {
            Ok((
                true,
                "Rootfs is now mounted read-write. Retry the package install — \
                 apt-get should succeed. Note: this is NOT persistent across \
                 reboots; if your /etc/fstab has the rootfs as `ro`, the next \
                 boot will revert."
                    .to_string(),
            ))
        } else {
            let tail = if message.trim().is_empty() {
                "(mount produced no diagnostic output)".to_string()
            } else {
                message
            };
            Ok((
                false,
                format!(
                    "Remount failed. mount said:\n{tail}\n\n\
                     Most likely your VPS image is genuinely immutable \
                     (snap-managed, ostree, or a hardened ISO). Switch to a \
                     standard Debian / Ubuntu cloud image and re-run install-node.sh."
                ),
            ))
        }
    }

    // ================================================================
    //  Generic background-job tracker (`jobs` table). Powers the
    //  "live progress" UX on migration / install / backup / clone /
    //  cert renewal / etc. The orchestrating side (panel, hctl, or a
    //  service method) opens a row with `job_start_*`, ticks
    //  `job_progress_*` at each phase, and closes with
    //  `job_finish_*`. The HTMX-polled web fragment reads `job_get`
    //  every 2 seconds.
    // ================================================================

    /// Open a job row from an in-process caller (the agent itself).
    /// Returns the freshly minted ULID `job_id`.
    pub async fn job_start(
        &self,
        kind: &str,
        target: Option<&str>,
        payload_json: &str,
        actor_label: &str,
        actor_uid: i64,
    ) -> Result<String, RpcError> {
        let id = ulid::Ulid::new().to_string();
        hyperion_state::jobs::start(
            &self.pool,
            hyperion_state::jobs::StartReq {
                id: &id,
                kind,
                target,
                payload_json,
                actor_uid,
                actor_label,
                started_at: now_secs(),
            },
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("job_start: {e}")))?;
        Ok(id)
    }

    /// Service-side progress tick (used by intra-service callers).
    pub async fn job_progress(
        &self,
        id: &str,
        step_label: &str,
        progress_pct: i64,
        log_append: &str,
    ) -> Result<(), RpcError> {
        hyperion_state::jobs::progress(
            &self.pool,
            id,
            step_label,
            progress_pct,
            log_append,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("job_progress: {e}")))?;
        Ok(())
    }

    /// Service-side terminal-state flip.
    pub async fn job_finish(
        &self,
        id: &str,
        ok: bool,
        error: Option<&str>,
    ) -> Result<(), RpcError> {
        hyperion_state::jobs::finish(&self.pool, id, ok, error, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("job_finish: {e}")))?;
        Ok(())
    }

    /// Look up one job. `None` = unknown id (rotated out or never
    /// existed).
    pub async fn job_get(&self, id: &str) -> Result<Option<hyperion_types::JobView>, RpcError> {
        let row = hyperion_state::jobs::read(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("job_read: {e}")))?;
        Ok(row.map(job_row_to_view))
    }

    /// Newest-first list. `kind` / `state` are optional pinning
    /// filters; both `None` = all jobs.
    pub async fn job_list(
        &self,
        kind: Option<&str>,
        state: Option<&str>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::JobView>, RpcError> {
        let rows = hyperion_state::jobs::list(&self.pool, kind, state, limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("job_list: {e}")))?;
        Ok(rows.into_iter().map(job_row_to_view).collect())
    }

    // External (RPC) variants — same as the in-process methods but
    // exposed at the AgentApi boundary. They live here (not as
    // standalone functions) so the panel can call them via the
    // signed RPC envelope same as any other agent method.

    pub async fn job_start_external(
        &self,
        kind: &str,
        target: Option<&str>,
        payload_json: &str,
        actor_label: &str,
        actor_uid: i64,
    ) -> Result<String, RpcError> {
        self.job_start(kind, target, payload_json, actor_label, actor_uid).await
    }

    pub async fn job_progress_external(
        &self,
        id: &str,
        step_label: &str,
        progress_pct: i64,
        log_append: &str,
    ) -> Result<(), RpcError> {
        self.job_progress(id, step_label, progress_pct, log_append).await
    }

    pub async fn job_finish_external(
        &self,
        id: &str,
        ok: bool,
        error: Option<&str>,
    ) -> Result<(), RpcError> {
        self.job_finish(id, ok, error).await
    }

    /// Sweep `running` rows whose `updated_at` is older than
    /// `stale_secs` and flip to `failed`. Run at agent startup and
    /// hourly from the scheduler tick. Without this an agent crash
    /// mid-job leaves the UI polling a forever-spinning row.
    pub async fn jobs_reap_stale(&self, stale_secs: i64) -> Result<u64, RpcError> {
        let n = hyperion_state::jobs::reap_stale(&self.pool, now_secs(), stale_secs)
            .await
            .map_err(|e| RpcError::Internal_with(format!("jobs_reap_stale: {e}")))?;
        if n > 0 {
            tracing::warn!(rows = n, "reaped stale jobs (agent crash mid-run?)");
        }
        Ok(n)
    }

    /// Full ROFS diagnose + (optional) auto-fix sequence.
    ///
    /// Gather phase (always runs):
    ///   * `/usr` writability probe (sentinel touch)
    ///   * `mount | grep ' / '` + `' /usr '` raw lines
    ///   * parsed mount options + fstype from `/proc/mounts`
    ///   * `/etc/fstab` rootfs line
    ///   * immutable-attr check via `lsattr -d /usr`
    ///   * image-kind heuristic (overlay → "overlay-immutable",
    ///     squashfs → "snap-managed", ostree marker → "ostree",
    ///     standard ext4/xfs → "standard")
    ///
    /// Fix phase (skipped when `dry_run = true` OR /usr already
    /// writable):
    ///   1. `mount -o remount,rw /` — the 90% case
    ///   2. `chattr -i /usr` when immutable_attr_set was true
    ///   3. `mount -o remount,rw /usr` when /usr is a separate
    ///      mountpoint that's still ro
    /// Each step is run only when prior steps left writability
    /// false. After each step the writability probe re-runs so
    /// the report shows incremental progress.
    pub async fn fs_diagnose_and_fix(
        &self,
        dry_run: bool,
    ) -> Result<hyperion_types::FsDiagnostics, RpcError> {
        let mut d = hyperion_types::FsDiagnostics::default();

        // ── gather ───────────────────────────────────────────
        d.usr_writable_before = check_usr_writable().await.is_none();
        d.usr_writable_now = d.usr_writable_before;

        // Raw mount lines for the operator to eyeball.
        let mount_output = tokio::process::Command::new("/bin/mount")
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        d.root_mount_line = mount_output
            .lines()
            .find(|l| l.contains(" on / type "))
            .unwrap_or("")
            .to_string();
        d.usr_mount_line = mount_output
            .lines()
            .find(|l| l.contains(" on /usr type "))
            .unwrap_or("")
            .to_string();

        // /proc/mounts is the source-of-truth parseable view.
        // Format: dev mountpoint fstype opts dump pass
        if let Ok(mounts) = tokio::fs::read_to_string("/proc/mounts").await {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                if parts[1] == "/" {
                    d.root_fstype = parts[2].to_string();
                    d.root_options = parts[3].to_string();
                }
                if parts[1] == "/usr" {
                    d.usr_fstype = parts[2].to_string();
                    d.usr_options = parts[3].to_string();
                }
            }
        }

        // /etc/fstab — single rootfs line so the operator knows
        // whether a reboot would undo our remount.
        if let Ok(fstab) = tokio::fs::read_to_string("/etc/fstab").await {
            d.fstab_root_line = fstab
                .lines()
                .find(|l| {
                    let t = l.trim_start();
                    if t.is_empty() || t.starts_with('#') {
                        return false;
                    }
                    // Second whitespace-separated field is the mountpoint.
                    t.split_whitespace().nth(1) == Some("/")
                })
                .unwrap_or("")
                .to_string();
        }

        // lsattr +i — check immutable attribute on /usr.
        let lsattr = tokio::process::Command::new("/usr/bin/lsattr")
            .args(["-d", "/usr"])
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        // lsattr output: `----i---------e----- /usr` — look for 'i'
        // anywhere in the leading flags chunk.
        d.immutable_attr_set = lsattr
            .split_whitespace()
            .next()
            .map(|flags| flags.contains('i'))
            .unwrap_or(false);

        // Image-kind heuristic.
        d.image_kind = classify_image_kind(&d.root_fstype, &d.usr_fstype);

        // ── early-out: writable + dry-run / writable in general ──
        if d.usr_writable_now {
            d.final_state = "no-fix-needed".to_string();
            d.recommendations.push(
                "/usr is already writable. apt-get install should succeed — \
                 retry the install."
                    .into(),
            );
            return Ok(d);
        }
        if dry_run {
            d.final_state = "dry-run".to_string();
            d.recommendations.push(self.recommend_for_state(&d));
            return Ok(d);
        }

        // ── fix phase ────────────────────────────────────────
        //
        // Order matters for the operator-readable progress bar:
        //   1. remount,rw /        — the 90% case (rootfs ro/rw flap)
        //   2. remount,rw /usr     — when /usr is a separate mount
        //                            (still common on modern systemd
        //                            distros that split /usr; in
        //                            practice this fires for ext4
        //                            root with /usr in /etc/fstab)
        //   3. chattr -i /usr      — only when lsattr ACTUALLY saw
        //                            the immutable attribute set.
        //                            The previous "defensive even on
        //                            ext4" branch fired chattr
        //                            unconditionally and predictably
        //                            failed with "Read-only file
        //                            system while setting flags on
        //                            /usr" on any system where /usr
        //                            was still ro after step 1. The
        //                            failure was confusing — the UI
        //                            showed a red exit-1 pill on an
        //                            otherwise-successful run because
        //                            step 3 (the real fix) cleaned
        //                            up after. Tighten the condition
        //                            to the actual lsattr signal so
        //                            the only red step is a step
        //                            that really failed.

        // Step 1.
        d.fix_steps.push(self.run_fix_step("mount -o remount,rw /", "/bin/mount", &["-o", "remount,rw", "/"]).await);
        d.usr_writable_now = check_usr_writable().await.is_none();

        // Step 2: separate /usr mountpoint.
        if !d.usr_writable_now && !d.usr_mount_line.is_empty() {
            d.fix_steps.push(self.run_fix_step("mount -o remount,rw /usr", "/bin/mount", &["-o", "remount,rw", "/usr"]).await);
            d.usr_writable_now = check_usr_writable().await.is_none();
        }

        // Step 3: chattr ONLY if lsattr saw the immutable bit. The
        // previous over-eager branch on ext4 produced spurious red
        // "Read-only file system" errors that confused the operator
        // even when the overall fix succeeded.
        if !d.usr_writable_now && d.immutable_attr_set {
            d.fix_steps.push(self.run_fix_step("chattr -i /usr", "/usr/bin/chattr", &["-i", "/usr"]).await);
            d.usr_writable_now = check_usr_writable().await.is_none();
        }

        // ── final state + recommendations ───────────────────
        if d.usr_writable_now {
            d.final_state = "fixed".to_string();
            d.recommendations.push(
                "✓ /usr is now writable. Retry the install — apt-get should succeed."
                    .into(),
            );
            if d.fstab_root_line.contains("ro,") || d.fstab_root_line.contains(" ro ") {
                d.recommendations.push(
                    "Warning: your /etc/fstab still says rootfs is `ro` — the next reboot \
                     will revert. Edit /etc/fstab to use `rw,` or change to a non-immutable \
                     image for a persistent fix."
                        .into(),
                );
            }
        } else if d.image_kind == "snap-managed" || d.image_kind == "overlay-immutable" {
            d.final_state = "image-immutable".to_string();
            d.recommendations.push(format!(
                "Your VPS image is {kind} — the rootfs CANNOT be made writable. \
                 You need a different image (standard Debian 12 / Ubuntu 22.04 cloud image \
                 without snap/overlay) to use Hyperion's package install. \
                 Reprovision the VPS with a non-immutable image and re-run install-node.sh.",
                kind = d.image_kind,
            ));
        } else {
            d.final_state = "still-broken".to_string();
            d.recommendations.push(
                "Every fix attempt failed. Possible causes: \
                 (1) the FS driver doesn't support `mount -o remount,rw` for this fstype, \
                 (2) a security module (AppArmor / SELinux) is blocking write to /usr, \
                 (3) the device backing / is genuinely read-only (CD-ROM / squashfs loop). \
                 SSH in and run `mount | grep ' / '` + `dmesg | tail -50` for clues."
                    .into(),
            );
        }
        for step in &d.fix_steps {
            tracing::info!(
                step = %step.label,
                exit_code = step.exit_code,
                now_writable = step.now_writable,
                "fs_fix_step"
            );
        }
        self.append_audit(
            "system.fs_diagnose_and_fix",
            None,
            &serde_json::json!({
                "dry_run": dry_run,
                "final_state": d.final_state,
                "writable_before": d.usr_writable_before,
                "writable_now": d.usr_writable_now,
                "image_kind": d.image_kind,
                "steps": d.fix_steps.len(),
            })
            .to_string(),
            if d.usr_writable_now { "ok" } else { "failed" },
        )
        .await;
        Ok(d)
    }

    /// Run one fix step, capture (exit, message, writability).
    async fn run_fix_step(&self, label: &str, cmd: &str, args: &[&str]) -> hyperion_types::FsFixStep {
        let out = tokio::process::Command::new(cmd).args(args).output().await;
        let (exit_code, message) = match out {
            Ok(o) => {
                let mut m = String::from_utf8_lossy(&o.stderr).into_owned();
                if !o.stdout.is_empty() {
                    if !m.is_empty() && !m.ends_with('\n') {
                        m.push('\n');
                    }
                    m.push_str(&String::from_utf8_lossy(&o.stdout));
                }
                // Cap message length for the response payload.
                if m.len() > 256 {
                    m.truncate(256);
                    m.push_str("…");
                }
                (o.status.code().unwrap_or(-1), m)
            }
            Err(e) => (-1, format!("spawn failed: {e}")),
        };
        let now_writable = check_usr_writable().await.is_none();
        hyperion_types::FsFixStep {
            label: label.to_string(),
            exit_code,
            message,
            now_writable,
        }
    }

    /// One-liner recommendation when no fixes have run yet (dry run
    /// or pre-fix state). Tailors message to the detected image kind.
    fn recommend_for_state(&self, d: &hyperion_types::FsDiagnostics) -> String {
        match d.image_kind.as_str() {
            "snap-managed" | "overlay-immutable" => format!(
                "Image kind: {}. Rootfs is by-design immutable — \
                 remount will fail. Switch to a standard Debian/Ubuntu cloud image.",
                d.image_kind
            ),
            _ => "Click \"Diagnose & auto-fix\" to attempt remount,rw on the rootfs.".into(),
        }
    }

    /// Cheap helper used by both the queue-ops audit logs above and
    /// indirectly via mta_diagnostics. Returns 0 if postqueue isn't
    /// available rather than failing.
    async fn queue_depth_now(&self) -> usize {
        let out = tokio::process::Command::new("/usr/sbin/postqueue")
            .args(["-p"])
            .output()
            .await;
        let Ok(o) = out else { return 0 };
        if !o.status.success() {
            return 0;
        }
        let body = String::from_utf8_lossy(&o.stdout);
        body.lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .and_then(|line| {
                line.split_whitespace()
                    .position(|w| w == "Request" || w == "Requests")
                    .and_then(|i| {
                        let words: Vec<&str> = line.split_whitespace().collect();
                        i.checked_sub(1).and_then(|j| words.get(j).copied())
                    })
                    .and_then(|s| s.parse::<usize>().ok())
            })
            .unwrap_or(0)
    }

    /// Operator-triggered re-apply of the boot postfix config. Picks
    /// smart-host vs direct-MX based on the current `[email]` section,
    /// returns the mode that was applied. Used by the /settings
    /// "Reconfigure" button when the operator changed agent.toml
    /// without restarting the agent (or wants to roll forward after
    /// reverting their own hand-edits).
    pub async fn mta_reconfigure(&self) -> Result<String, RpcError> {
        if !hyperion_adapters::postfix::is_installed().await {
            return Ok("skipped".to_string());
        }
        match self.email_config.as_ref() {
            Some(cfg) if !cfg.smtp_host.trim().is_empty() => {
                hyperion_adapters::postfix::ensure_relay_config(cfg)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("postfix relay: {e}")))?;
                Ok("smart-host".to_string())
            }
            _ => {
                let fqdn = tokio::process::Command::new("/bin/hostname")
                    .arg("-f")
                    .output()
                    .await
                    .ok()
                    .and_then(|o| {
                        if !o.status.success() {
                            return None;
                        }
                        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if s.is_empty() { None } else { Some(s) }
                    })
                    .unwrap_or_else(|| "localhost".to_string());
                hyperion_adapters::postfix::ensure_direct_delivery_config(&fqdn)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("postfix direct: {e}")))?;
                Ok("direct-mx".to_string())
            }
        }
    }

    /// Send a one-line test mail via `/usr/sbin/sendmail`. This
    /// exercises the PHP `mail()` chain end-to-end (PHP would go
    /// site-mail-wrapper → sendmail; here we skip the wrapper and
    /// call sendmail directly, which is what the wrapper does
    /// anyway after logging). Returns (exit_code, stderr).
    pub async fn mta_test_send(&self, to: String) -> Result<(i32, String), RpcError> {
        let to = to.trim();
        if to.is_empty() || !to.contains('@') {
            return Err(RpcError::Validation {
                message: "destination address is required and must contain '@'".into(),
            });
        }
        // Bound the address — Location-header / argv-length safety.
        if to.len() > 254 {
            return Err(RpcError::Validation {
                message: "address too long (RFC5321 max is 254 chars)".into(),
            });
        }
        // Synthesize a From that postfix will accept. The operator
        // controls `[email].from_address` so we use it when set;
        // fall back to admin@hostname as last resort.
        let from = self
            .email_config
            .as_ref()
            .map(|c| c.from_address.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "admin@localhost".to_string());
        let body = format!(
            "From: {from}\r\n\
             To: {to}\r\n\
             Subject: Hyperion MTA test\r\n\
             Content-Type: text/plain; charset=UTF-8\r\n\
             \r\n\
             This is a test email from hyperion-agent via /usr/sbin/sendmail.\r\n\
             If you can read this, your MTA accepted it.\r\n\
             Whether it actually delivered is between postfix and the recipient's MX.\r\n",
        );
        let mut child = tokio::process::Command::new("/usr/sbin/sendmail")
            .args(["-t", "-f", &from])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| RpcError::Internal_with(format!("spawn sendmail: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin
                .write_all(body.as_bytes())
                .await
                .map_err(|e| RpcError::Internal_with(format!("write to sendmail stdin: {e}")))?;
            let _ = stdin.shutdown().await;
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("wait sendmail: {e}")))?;
        let exit_code = out.status.code().unwrap_or(-1);
        let mut output = String::from_utf8_lossy(&out.stderr).into_owned();
        if !out.stdout.is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&String::from_utf8_lossy(&out.stdout));
        }
        self.append_audit(
            "mta.test_send",
            None,
            &serde_json::json!({
                "to": to,
                "from": from,
                "exit_code": exit_code,
            })
            .to_string(),
            if exit_code == 0 { "ok" } else { "failed" },
        )
        .await;
        Ok((exit_code, output))
    }

    /// Delete a single backup run + its archive file(s) on disk.
    /// Refuses when the backup is still `running` (would orphan the
    /// in-flight process). Logs `backup.delete` in the audit log
    /// regardless of disk-removal success — DB row removal is the
    /// source of truth and we want the audit chain to reflect it.
    pub async fn backup_delete(&self, backup_id: i64) -> Result<(), RpcError> {
        let row = hyperion_state::backups::get_by_id(&self.pool, backup_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get backup: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "backup".into(),
                id: backup_id.to_string(),
            })?;
        if row.state == "running" {
            return Err(RpcError::Validation {
                message: "refusing to delete a backup that is still running. \
                          Wait for it to finish (or fail) first."
                    .into(),
            });
        }
        // Best-effort disk removal — don't block the DB delete if the
        // archive is already gone (operator can delete the row to clean
        // up zombie entries). Track outcomes for audit.
        let mut disk_removed = 0u8;
        let mut disk_errors: Vec<String> = Vec::new();
        for p in [row.archive_path.clone(), row.db_dump_path.clone()].into_iter().flatten() {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => disk_removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Already gone — fine.
                }
                Err(e) => {
                    disk_errors.push(format!("{p}: {e}"));
                }
            }
        }
        // Now drop the DB row regardless of disk outcomes.
        hyperion_state::backups::delete_by_id(&self.pool, backup_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete backup row: {e}")))?;

        self.append_audit(
            "backup.delete",
            Some(row.hosting_id.as_str()),
            &serde_json::json!({
                "backup_id": backup_id,
                "target": row.target,
                "state": row.state,
                "files_removed": disk_removed,
                "disk_errors": disk_errors,
            })
            .to_string(),
            if disk_errors.is_empty() { "ok" } else { "partial" },
        )
        .await;
        Ok(())
    }

    /// Whitelist of unit names we'll restart/install. Refusing
    /// anything else prevents a compromised UI from convincing the
    /// agent to enable a random unit ("docker", "ssh", "ufw"…).
    /// Refusing `hyperion-agent` specifically prevents tearing the
    /// RPC pipe out from under our own response.
    fn service_whitelist_for(name: &str, allow_self_restart: bool) -> Option<&'static str> {
        match name {
            "nginx" => Some("nginx"),
            "mariadb" => Some("mariadb-server"),
            "postgresql" => Some("postgresql"),
            "redis-server" => Some("redis-server"),
            "vsftpd" => Some("vsftpd"),
            // postfix provides /usr/sbin/sendmail for PHP mail().
            // Install path runs the same debconf preseeding as
            // update.sh (Internet Site, hostname-derived mailname)
            // — see `run_service_install`.
            "postfix" => Some("postfix"),
            "php8.1-fpm" => Some("php8.1-fpm"),
            "php8.2-fpm" => Some("php8.2-fpm"),
            "php8.3-fpm" => Some("php8.3-fpm"),
            "php8.4-fpm" => Some("php8.4-fpm"),
            "hyperion-web" => Some("hyperion-web"),
            "hyperion-agent" if allow_self_restart => Some("hyperion-agent"),
            _ => None,
        }
    }

    pub async fn service_restart(&self, name: String) -> Result<(), RpcError> {
        let _pkg = Self::service_whitelist_for(&name, false).ok_or_else(|| {
            RpcError::Validation {
                message: format!(
                    "service `{name}` is not on the restart whitelist (refuse self-restart of hyperion-agent — would kill this RPC; SSH for that)"
                ),
            }
        })?;
        let out = tokio::process::Command::new("/usr/bin/systemctl")
            .args(["restart", &name])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("systemctl: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(RpcError::Internal_with(format!(
                "systemctl restart {name} failed: {stderr}"
            )));
        }
        self.append_audit(
            "service.restart",
            None,
            &serde_json::json!({"name": name}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Apply per-section updates to agent.toml on disk. Operator
    /// still needs to `systemctl restart hyperion-agent` for the
    /// running daemon to pick up the new values — the UI reminds
    /// them with a flash message.
    pub async fn agent_config_update(
        &self,
        section: String,
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<(), RpcError> {
        let path = self.agent_config_path.as_ref().ok_or_else(|| {
            RpcError::Validation {
                message: "agent_config_path not wired — UI editing disabled".into(),
            }
        })?;
        let parsed = parse_agent_section_fields(&section, &fields)?;
        // Convert to the &[(&str, FieldValue)] shape the persist module
        // wants. Done in two steps so the &str references live long
        // enough for the slice.
        let owned: Vec<(String, crate::config_persist::FieldValue)> = parsed;
        let view: Vec<(&str, crate::config_persist::FieldValue)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        crate::config_persist::set_many(path, &section, &view).map_err(|e| {
            RpcError::Internal_with(format!("config write failed: {e}"))
        })?;
        // Audit. Don't echo field values (might be a password).
        let field_names: Vec<&str> = fields.keys().map(|s| s.as_str()).collect();
        self.append_audit(
            "agent.config.update",
            None,
            &serde_json::json!({"section": section, "fields": field_names}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Compare the running binary's compile-time git SHA against the
    /// SHA the upstream `rolling` tag points to. Cached for
    /// `UPDATE_CHECK_TTL_SECS` so the dashboard banner doesn't trigger
    /// a network call on every page load.
    ///
    /// We use `git ls-remote` rather than the GitHub REST API — git is
    /// already installed on every node (the installer uses it), and
    /// ls-remote against the public mirror is unauthenticated, has no
    /// rate limit per IP, and returns the answer in one round trip
    /// without JSON parsing. The downside (slightly slower TCP/TLS
    /// vs. a HEAD request) is irrelevant once per hour.
    pub async fn update_check(
        &self,
        force_refresh: bool,
    ) -> Result<hyperion_types::UpdateStatus, RpcError> {
        let now = now_secs();
        // Fast path: serve cached if still fresh and caller didn't ask
        // for a forced refresh. We use a separate read scope so the
        // (uncommon) refresh path can take the write lock without
        // upgrading.
        if !force_refresh {
            let cache = self.update_cache.read().await;
            if let Some(s) = cache.as_ref() {
                if now - s.last_checked_at < UPDATE_CHECK_TTL_SECS {
                    return Ok(s.clone());
                }
            }
        }

        // Re-probe upstream. We don't read /etc/hyperion/agent.toml for
        // a configurable repo URL because the install scripts hard-code
        // nechodom/hyperion too — if the operator forks, they patch the
        // installer and this together.
        let repo_url = "https://github.com/nechodom/hyperion";
        let probe = tokio::process::Command::new("/usr/bin/git")
            .args(["ls-remote", "--tags", repo_url, "refs/tags/rolling"])
            .output()
            .await;

        let mut status = hyperion_types::UpdateStatus {
            current_sha: self.current_git_sha.clone(),
            latest_sha: String::new(),
            latest_tag: "rolling".into(),
            latest_built: String::new(),
            last_checked_at: now,
            update_available: false,
            message: String::new(),
        };

        match probe {
            Ok(out) if out.status.success() => {
                // Output: "<sha>\trefs/tags/rolling\n"
                let raw = String::from_utf8_lossy(&out.stdout);
                let sha = raw
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                if sha.is_empty() {
                    status.message = "probe failed: empty ls-remote output".into();
                } else {
                    status.latest_sha = sha;
                    let (avail, msg) =
                        compare_git_shas(&status.current_sha, &status.latest_sha);
                    if avail {
                        // SHAs differ. Before flagging "update available",
                        // check whether `current` is actually a descendant
                        // of `latest` — i.e. we're *ahead* of the rolling
                        // tag, not behind. This is the common false
                        // positive: an operator runs `update.sh` which
                        // `git pull`s main, then GHA hasn't yet moved the
                        // `rolling` tag to the new HEAD. Without this
                        // check the dashboard nags about an update that
                        // doesn't exist.
                        match ahead_of_remote(&status.latest_sha).await {
                            AheadResult::AheadOrEqual => {
                                status.update_available = false;
                                status.message =
                                    "up to date (ahead of rolling tag)".into();
                            }
                            AheadResult::Behind => {
                                status.update_available = true;
                                status.message = msg.to_string();
                            }
                            AheadResult::Unknown => {
                                // No local git — fall back to the naive
                                // string compare. Better to nag a dev box
                                // occasionally than to silently miss a
                                // real production update.
                                status.update_available = avail;
                                status.message = msg.to_string();
                            }
                        }
                    } else {
                        status.update_available = false;
                        status.message = msg.to_string();
                    }
                }
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                status.message = format!(
                    "probe failed: git ls-remote exit {}: {stderr}",
                    out.status.code().unwrap_or(-1),
                );
            }
            Err(e) => {
                status.message = format!("probe failed: spawn git: {e}");
            }
        }

        // Persist into cache (write lock) regardless of probe outcome —
        // a recent failure is still worth caching so we don't spam the
        // upstream on every page load when the network's flaky.
        {
            let mut w = self.update_cache.write().await;
            *w = Some(status.clone());
        }
        Ok(status)
    }

    /// Start an apt-get install + systemctl enable for a whitelisted
    /// service. Returns immediately after spawning the background
    /// task — operator polls `service_install_status()` for the live
    /// log tail.
    ///
    /// Previously this awaited the apt-get call up to 5 min,
    /// blocking the operator's browser. apt-get also runs with
    /// `-qq` which suppressed the actual error reason; the operator
    /// got "Sub-process /usr/bin/dpkg returned an error code (1)"
    /// with no clue what went wrong. The async refactor lets us
    /// drop `-qq` (we now stream output), capture stdout+stderr in
    /// the slot, and surface the real failure.
    pub async fn service_install(&self, name: String) -> Result<(), RpcError> {
        let pkg = Self::service_whitelist_for(&name, false).ok_or_else(|| {
            RpcError::Validation {
                message: format!("service `{name}` is not on the install whitelist"),
            }
        })?;
        {
            let guard = self.service_install_progress.lock().await;
            if guard.state == "running" {
                return Err(RpcError::Conflict {
                    message: format!(
                        "another service install ({} → {}) is already running on this node; \
                         wait for it to finish — apt would dpkg-lock anyway.",
                        guard.service_name, guard.pkg
                    ),
                });
            }
        }
        // Preflight: apt fails with a confusing "Read-only file system"
        // error when /usr is RO (immutable VPS / snap / unprivileged
        // LXC). Detect upfront + refuse with a clear message instead
        // of spending 30s on apt-get only to surface dpkg noise.
        if let Some(rw_err) = check_usr_writable().await {
            return Err(RpcError::Conflict { message: rw_err });
        }
        let now = now_secs();
        {
            let mut g = self.service_install_progress.lock().await;
            *g = hyperion_types::ServiceInstallStatus {
                service_name: name.clone(),
                pkg: pkg.to_string(),
                started_at: now,
                finished_at: 0,
                state: "running".into(),
                log_tail: String::new(),
                exit_code: 0,
            };
        }
        // Audit-log the START. The finish state is audited separately
        // by the background task below.
        self.append_audit(
            "service.install.start",
            None,
            &serde_json::json!({"name": name, "pkg": pkg}).to_string(),
            "ok",
        )
        .await;
        // Spawn detached — caller returns immediately, UI polls.
        let slot = self.service_install_progress.clone();
        let svc_name = name.clone();
        let pkg_owned = pkg.to_string();
        tokio::spawn(async move {
            run_service_install(slot, svc_name, pkg_owned).await;
        });
        Ok(())
    }

    /// Current state of the most-recent / in-progress service-install
    /// job. Cheap — clones the in-memory slot. Empty
    /// ServiceInstallStatus (state="" / started_at=0) when no
    /// install has ever run.
    pub async fn service_install_status(
        &self,
    ) -> Result<hyperion_types::ServiceInstallStatus, RpcError> {
        Ok(self.service_install_progress.lock().await.clone())
    }

    // ============================================================
    //  WP asset library — operator-uploaded plugin / theme ZIPs
    //  referenced from hosting profiles via @asset:<id>.
    // ============================================================

    pub async fn wp_asset_upload(
        &self,
        kind: String,
        original_name: String,
        bytes: Vec<u8>,
        uploaded_by: String,
    ) -> Result<(i64, bool), RpcError> {
        if kind != "plugin" && kind != "theme" {
            return Err(RpcError::Validation {
                message: format!("kind must be `plugin` or `theme`, got {kind:?}"),
            });
        }
        if bytes.is_empty() {
            return Err(RpcError::Validation {
                message: "uploaded file is empty".into(),
            });
        }
        // Hard cap — Plugin / theme ZIPs are basically never >50 MB.
        // Generous upper bound to catch operator mistakes (uploading
        // a backup tarball or similar).
        const MAX_BYTES: usize = 50 * 1024 * 1024;
        if bytes.len() > MAX_BYTES {
            return Err(RpcError::Validation {
                message: format!(
                    "uploaded file is {} bytes — max is {} bytes (50 MB)",
                    bytes.len(),
                    MAX_BYTES
                ),
            });
        }
        // ZIP magic check — first 4 bytes are PK\x03\x04.
        if bytes.len() < 4 || &bytes[..4] != b"PK\x03\x04" {
            return Err(RpcError::Validation {
                message: "file is not a ZIP archive (missing PK header)".into(),
            });
        }
        // SHA-256 for dedupe + integrity. blake3 is faster but we
        // already store sha256 in the schema for parity with the
        // backup archive checksums.
        let sha = hex::encode(blake3::hash(&bytes).as_bytes());
        // Dedupe — if the same bytes already exist, return that row.
        if let Some(existing) =
            hyperion_state::wp_assets::get_by_sha(&self.pool, &sha)
                .await
                .map_err(|e| RpcError::Internal_with(format!("dedupe lookup: {e}")))?
        {
            return Ok((existing.id, true));
        }
        // Sanitize the operator filename — keep alphanumerics, dot,
        // dash, underscore. Trim to 64 chars. Empty after sanitize →
        // "asset.zip".
        let safe_name: String = original_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .take(64)
            .collect();
        let stored_filename = if safe_name.is_empty() {
            "asset.zip".to_string()
        } else if !safe_name.ends_with(".zip") {
            format!("{safe_name}.zip")
        } else {
            safe_name
        };
        let now = now_secs();
        let id = hyperion_state::wp_assets::insert(
            &self.pool,
            &kind,
            &original_name,
            &stored_filename,
            bytes.len() as i64,
            &sha,
            now,
            &uploaded_by,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("wp_asset insert: {e}")))?;
        let dir = std::path::PathBuf::from("/var/lib/hyperion/wp-assets").join(id.to_string());
        if let Err(e) = tokio::fs::create_dir_all(&dir).await {
            // Roll back the DB row so the operator can retry.
            let _ = hyperion_state::wp_assets::delete(&self.pool, id).await;
            return Err(RpcError::Internal_with(format!(
                "mkdir wp-assets/{id}: {e}"
            )));
        }
        let path = dir.join(&stored_filename);
        if let Err(e) = tokio::fs::write(&path, &bytes).await {
            let _ = hyperion_state::wp_assets::delete(&self.pool, id).await;
            let _ = tokio::fs::remove_dir_all(&dir).await;
            return Err(RpcError::Internal_with(format!(
                "write wp-assets/{id}/{stored_filename}: {e}"
            )));
        }
        // 0644 — readable by anyone (wp-cli runs as the system_user
        // of the hosting being applied to, which is different per
        // hosting). The DIR is 0755 by default which is fine.
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).await;
        self.append_audit(
            "wp_asset.upload",
            None,
            &serde_json::json!({
                "id": id,
                "kind": kind,
                "original_name": original_name,
                "size_bytes": bytes.len(),
                "sha256": sha,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok((id, false))
    }

    pub async fn wp_asset_list(
        &self,
    ) -> Result<Vec<hyperion_types::WpAssetSummary>, RpcError> {
        let rows = hyperion_state::wp_assets::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset list: {e}")))?;
        // Usage counts: profile_refs from a substring scan of
        // every profile's wp_plugins+wp_themes, install_count
        // from the master-side wp_asset_installs tracking table
        // (more accurate than the audit-log scan we did
        // pre-019_wp_asset_installs — that one missed installs
        // dispatched to remote nodes).
        let profiles = hyperion_state::profiles::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset usage profiles: {e}")))?;
        let mut out: Vec<hyperion_types::WpAssetSummary> = Vec::with_capacity(rows.len());
        for r in rows {
            let profile_refs = count_profile_asset_refs(&profiles, r.id);
            let install_count =
                hyperion_state::wp_assets::install_count(&self.pool, r.id)
                    .await
                    .unwrap_or(0);
            out.push(hyperion_types::WpAssetSummary {
                id: r.id,
                kind: r.kind,
                original_name: r.original_name,
                size_bytes: r.size_bytes,
                sha256: r.sha256,
                uploaded_at: r.uploaded_at,
                uploaded_by: r.uploaded_by,
                profile_refs,
                install_count,
            });
        }
        Ok(out)
    }

    /// Install one uploaded asset onto a hosting. Looks up the
    /// asset, validates kind, derives the on-disk ZIP path, then
    /// shells out to wp-cli via the wp_cli adapter. Returns
    /// (kind, original_name) so the UI flash is specific.
    pub async fn wp_install_from_asset(
        &self,
        sel: HostingSelector,
        asset_id: i64,
        activate: bool,
    ) -> Result<(String, String), RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::wp_assets::get_by_id(&self.pool, asset_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset lookup: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "wp_asset".into(),
                id: asset_id.to_string(),
            })?;
        let source = wp_asset_disk_path(asset_id, &row.stored_filename);
        // Refuse if the ZIP went missing — better than wp-cli's
        // generic "file not found" error.
        if !std::path::Path::new(&source).exists() {
            return Err(RpcError::Internal_with(format!(
                "asset id {asset_id} ZIP not present on disk at {source} (out-of-band delete?)"
            )));
        }
        let htdocs = format!("/home/{}/{}/htdocs", detail.system_user, detail.domain);
        self.adapters
            .wp_cli(&detail.system_user, &htdocs, &row.kind, &source, activate)
            .await
            .map_err(|e| RpcError::Internal_with(format!(
                "wp {} install {} failed: {e}",
                row.kind, row.original_name
            )))?;
        self.append_audit(
            "wp.install_from_asset",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "asset_id": asset_id,
                "kind": row.kind,
                "original_name": row.original_name,
                "activate": activate,
            })
            .to_string(),
            "ok",
        )
        .await;
        // Record in the master-side tracking table so the
        // "Re-install on all" button knows which hostings to push
        // a newer version to. node_id is read from the local
        // current_node_id — best-effort; for cross-node installs
        // dispatched from a worker (rare), node_id will be the
        // local one which is still a reasonable hint.
        let node_id = self.current_node_id();
        let _ = hyperion_state::wp_assets::record_install(
            &self.pool,
            asset_id,
            detail.id.as_str(),
            &node_id,
            activate,
            now_secs(),
        )
        .await;
        Ok((row.kind, row.original_name))
    }

    /// Replace the on-disk ZIP for an existing asset id, keeping
    /// the id stable so profiles + tracking rows that reference
    /// `@asset:<id>` survive a version bump.
    pub async fn wp_asset_replace(
        &self,
        id: i64,
        original_name: String,
        bytes: Vec<u8>,
        uploaded_by: String,
    ) -> Result<(), RpcError> {
        // Same validation as upload — empty + size + magic bytes.
        if bytes.is_empty() {
            return Err(RpcError::Validation {
                message: "uploaded file is empty".into(),
            });
        }
        const MAX_BYTES: usize = 50 * 1024 * 1024;
        if bytes.len() > MAX_BYTES {
            return Err(RpcError::Validation {
                message: format!(
                    "uploaded file is {} bytes — max is {} bytes (50 MB)",
                    bytes.len(),
                    MAX_BYTES
                ),
            });
        }
        if bytes.len() < 4 || &bytes[..4] != b"PK\x03\x04" {
            return Err(RpcError::Validation {
                message: "file is not a ZIP archive (missing PK header)".into(),
            });
        }
        let row = hyperion_state::wp_assets::get_by_id(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset lookup: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "wp_asset".into(),
                id: id.to_string(),
            })?;
        let sha = hex::encode(blake3::hash(&bytes).as_bytes());
        // Wipe the old file (its name might differ from the new
        // one — the dir is per-id so it's safe to clear). Then
        // write the new file in the same dir.
        let dir = std::path::PathBuf::from("/var/lib/hyperion/wp-assets").join(id.to_string());
        let _ = tokio::fs::remove_file(&dir.join(&row.stored_filename)).await;
        tokio::fs::create_dir_all(&dir).await.map_err(|e| {
            RpcError::Internal_with(format!("mkdir wp-assets/{id}: {e}"))
        })?;
        let safe_name: String = original_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
            .take(64)
            .collect();
        let stored_filename = if safe_name.is_empty() {
            "asset.zip".to_string()
        } else if !safe_name.ends_with(".zip") {
            format!("{safe_name}.zip")
        } else {
            safe_name
        };
        let path = dir.join(&stored_filename);
        tokio::fs::write(&path, &bytes).await.map_err(|e| {
            RpcError::Internal_with(format!("write wp-assets/{id}/{stored_filename}: {e}"))
        })?;
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).await;
        hyperion_state::wp_assets::replace(
            &self.pool,
            id,
            &original_name,
            &stored_filename,
            bytes.len() as i64,
            &sha,
            now_secs(),
            &uploaded_by,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("wp_asset replace: {e}")))?;
        self.append_audit(
            "wp_asset.replace",
            None,
            &serde_json::json!({
                "id": id,
                "kind": row.kind,
                "original_name": original_name,
                "size_bytes": bytes.len(),
                "sha256": sha,
                "previous_sha256": row.sha256,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Push the current bytes of `asset_id` onto every hosting
    /// tracked in wp_asset_installs. One install per (asset_id,
    /// hosting_id) — re-installs run sequentially to avoid hammering
    /// the cluster, and any single failure is appended to a
    /// failure_tail string instead of aborting the run.
    pub async fn wp_asset_reinstall_all(
        &self,
        asset_id: i64,
        force_activate: Option<bool>,
    ) -> Result<(i64, i64, String), RpcError> {
        let targets = hyperion_state::wp_assets::list_install_targets(&self.pool, asset_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("install targets: {e}")))?;
        let mut ok: i64 = 0;
        let mut fail: i64 = 0;
        let mut failures: Vec<String> = Vec::new();
        for t in &targets {
            let activate = force_activate.unwrap_or(t.activate);
            let sel = HostingSelector::Id(hyperion_types::HostingId(t.hosting_id.clone()));
            // Re-run the same install path. Reusing wp_install_from_asset
            // means it also updates record_install (bumps last_at) for free.
            match self
                .wp_install_from_asset(sel, asset_id, activate)
                .await
            {
                Ok(_) => ok += 1,
                Err(e) => {
                    fail += 1;
                    failures.push(format!("{}: {}", t.hosting_id, e));
                }
            }
        }
        let failure_tail = failures.into_iter().take(10).collect::<Vec<_>>().join("\n");
        self.append_audit(
            "wp_asset.reinstall_all",
            None,
            &serde_json::json!({
                "asset_id": asset_id,
                "force_activate": force_activate,
                "targets": targets.len(),
                "ok": ok,
                "fail": fail,
            })
            .to_string(),
            if fail == 0 { "ok" } else { "warn" },
        )
        .await;
        Ok((ok, fail, failure_tail))
    }

    pub async fn wp_asset_delete(&self, id: i64) -> Result<(), RpcError> {
        let row = hyperion_state::wp_assets::get_by_id(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "wp_asset".into(),
                id: id.to_string(),
            })?;
        hyperion_state::wp_assets::delete(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset delete: {e}")))?;
        let dir =
            std::path::PathBuf::from("/var/lib/hyperion/wp-assets").join(id.to_string());
        let _ = tokio::fs::remove_dir_all(&dir).await;
        self.append_audit(
            "wp_asset.delete",
            None,
            &serde_json::json!({
                "id": id,
                "kind": row.kind,
                "original_name": row.original_name,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Spawn a background job that runs the requested update steps
    /// on THIS node:
    ///   1. (optional) `apt-get update && apt-get dist-upgrade -y`
    ///   2. (optional) `/opt/hyperion/packaging/install/update.sh`
    ///
    /// Returns the start timestamp. The job runs detached and
    /// writes a rolling log tail into `self.node_update` so
    /// `node_update_status()` can return progress to the UI.
    ///
    /// Refuses to start when an update is already running (one job
    /// per node at a time — `apt-get` would lock dpkg anyway).
    pub async fn node_update_run(
        &self,
        do_apt: bool,
        do_hyperion: bool,
    ) -> Result<i64, RpcError> {
        if !do_apt && !do_hyperion {
            return Err(RpcError::Validation {
                message: "node_update_run: nothing to do (do_apt=false, do_hyperion=false)"
                    .into(),
            });
        }
        let started_at = now_secs();
        {
            let mut guard = self.node_update.lock().await;
            if guard.state == "running" {
                return Err(RpcError::Conflict {
                    message: format!(
                        "another update is already running on this node (started at unix:{}). \
                         Wait for it to finish before starting a new one.",
                        guard.started_at
                    ),
                });
            }
            *guard = hyperion_types::NodeUpdateStatus {
                started_at,
                finished_at: 0,
                state: "running".into(),
                do_apt,
                do_hyperion,
                log_tail: String::new(),
                exit_code: 0,
            };
        }
        // Spawn the work. We deliberately don't await — the caller
        // gets the start time back and polls status.
        let slot = self.node_update.clone();
        tokio::spawn(async move {
            run_update_script(slot, do_apt, do_hyperion).await;
        });
        self.append_audit(
            "node.update.start",
            None,
            &serde_json::json!({"do_apt": do_apt, "do_hyperion": do_hyperion}).to_string(),
            "ok",
        )
        .await;
        Ok(started_at)
    }

    /// Read the current node-update job state. Cheap — just clones
    /// the in-memory state slot.
    pub async fn node_update_status(
        &self,
    ) -> Result<hyperion_types::NodeUpdateStatus, RpcError> {
        Ok(self.node_update.lock().await.clone())
    }

    /// Status of every system service Hyperion depends on. Run via
    /// `systemctl is-active/is-enabled` so the answer is always live
    /// — we don't cache because operator restarts/disables happen
    /// out-of-band.
    ///
    /// "Critical" services (severity=error if down): nginx,
    /// hyperion-agent, hyperion-web.
    /// "Warning" services (severity=warn if down): mariadb, postgresql,
    /// any installed php-fpm version, vsftpd (FTP optional).
    /// "Missing optional" (severity=info): php-fpm units / vsftpd
    /// that aren't installed.
    /// Dump the firewall ruleset. Tries `nft list ruleset` first
    /// (Debian 12+ default); falls back to `iptables -L -n -v` on
    /// boxes that still run legacy iptables. Best-effort regex over
    /// the output extracts open TCP/UDP ports for a quick "what
    /// can the world hit" panel; the raw output is always present
    /// so the operator can verify by eye.
    ///
    /// Read-only — never mutates the ruleset. UI surface at
    /// `/firewall` is similarly read-only by design (operators
    /// edit via SSH + nft; we just give them visibility per-node).
    /// Apply a hardcoded firewall template to this node. We DON'T
    /// touch the operator's pre-existing nft rules — every Hyperion
    /// rule lives in our own `inet hyperion` table. Every rule
    /// carries a `comment "hyperion:<template_id>"` so a future
    /// "remove template" or audit lookup can find them.
    ///
    /// Sequence:
    ///   1. `add table inet hyperion { }` — idempotent, "exists"
    ///      errors are filtered.
    ///   2. `add chain inet hyperion input { type filter hook input
    ///      priority 0; policy accept; }` — also idempotent.
    ///   3. The template's add-rule commands.
    ///   4. `nft list ruleset > /etc/nftables.conf` — persist for
    ///      reboot survival.
    ///
    /// Returns `(applied, output, error)`. `applied=true` iff every
    /// command ran successfully AND the persist write succeeded.
    /// `output` is the joined stdout of every command. `error` is
    /// the first non-empty NON-BENIGN stderr line ("File exists" /
    /// "already exists" are filtered as expected idempotency noise).
    pub async fn firewall_apply_template(
        &self,
        template_id: &str,
    ) -> Result<(bool, String, String), RpcError> {
        let cmds = firewall_template_commands(template_id).ok_or_else(|| {
            RpcError::Validation {
                message: format!("unknown firewall template id: {template_id}"),
            }
        })?;
        let mut out = String::new();
        let mut err = String::new();
        let mut applied = true;
        for cmd in &cmds {
            let res = tokio::process::Command::new("/usr/sbin/nft")
                .args(cmd)
                .output()
                .await;
            match res {
                Ok(o) => {
                    if !o.stdout.is_empty() {
                        out.push_str(&String::from_utf8_lossy(&o.stdout));
                    }
                    let s = String::from_utf8_lossy(&o.stderr);
                    let benign = s.contains("File exists")
                        || s.contains("already exists")
                        || s.trim().is_empty();
                    if !o.status.success() && !benign {
                        applied = false;
                        if err.is_empty() {
                            err = format!("`nft {}`: {}", cmd.join(" "), s.trim());
                        }
                    }
                }
                Err(e) => {
                    applied = false;
                    if err.is_empty() {
                        err = format!("spawn nft: {e}");
                    }
                }
            }
        }
        // Persist to /etc/nftables.conf — `nft list ruleset` to
        // stdout then redirect via tokio (shell would need its own
        // perms). We do it in two steps: list ruleset → capture →
        // tokio::fs::write.
        if applied {
            match tokio::process::Command::new("/usr/sbin/nft")
                .args(["list", "ruleset"])
                .output()
                .await
            {
                Ok(o) if o.status.success() => {
                    if let Err(e) = tokio::fs::write("/etc/nftables.conf", &o.stdout).await {
                        applied = false;
                        err = format!("persist /etc/nftables.conf: {e}");
                    }
                }
                Ok(o) => {
                    applied = false;
                    err = format!("nft list ruleset for persist: {}", String::from_utf8_lossy(&o.stderr));
                }
                Err(e) => {
                    applied = false;
                    err = format!("spawn nft for persist: {e}");
                }
            }
        }
        self.append_audit(
            "firewall.apply_template",
            Some(template_id),
            &serde_json::json!({"applied": applied, "error_first_line": err}).to_string(),
            if applied { "ok" } else { "failed" },
        )
        .await;
        Ok((applied, out, err))
    }

    pub async fn firewall_list(&self) -> Result<hyperion_types::FirewallView, RpcError> {
        // Try nft first.
        let nft = tokio::process::Command::new("/usr/sbin/nft")
            .args(["list", "ruleset"])
            .output()
            .await;
        let (backend, raw, error) = match nft {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => (
                "nft".to_string(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::new(),
            ),
            Ok(o) => {
                // nft is present but errored (e.g. empty ruleset on
                // a fresh box, or operator running without root).
                // Fall through to iptables — the legacy binary is
                // still available on Debian as a compat shim.
                let nft_err = String::from_utf8_lossy(&o.stderr).into_owned();
                match tokio::process::Command::new("/usr/sbin/iptables")
                    .args(["-L", "-n", "-v"])
                    .output()
                    .await
                {
                    Ok(o2) if o2.status.success() => (
                        "iptables".to_string(),
                        String::from_utf8_lossy(&o2.stdout).into_owned(),
                        String::new(),
                    ),
                    Ok(o2) => (
                        "unknown".to_string(),
                        String::new(),
                        format!(
                            "nft: {} / iptables: {}",
                            nft_err.trim(),
                            String::from_utf8_lossy(&o2.stderr).trim()
                        ),
                    ),
                    Err(e) => (
                        "unknown".to_string(),
                        String::new(),
                        format!("nft: {} / iptables spawn: {e}", nft_err.trim()),
                    ),
                }
            }
            Err(_e) => match tokio::process::Command::new("/usr/sbin/iptables")
                .args(["-L", "-n", "-v"])
                .output()
                .await
            {
                Ok(o) if o.status.success() => (
                    "iptables".to_string(),
                    String::from_utf8_lossy(&o.stdout).into_owned(),
                    String::new(),
                ),
                Ok(o) => (
                    "unknown".to_string(),
                    String::new(),
                    String::from_utf8_lossy(&o.stderr).into_owned(),
                ),
                Err(e) => ("unknown".to_string(), String::new(), e.to_string()),
            },
        };

        // Best-effort port extraction. Matches:
        //   nft:       `tcp dport 443 accept` / `tcp dport { 80, 443 } accept`
        //   iptables:  `... tcp dpt:443 ... ACCEPT`
        // Anything more exotic (port ranges, named sets) lands in
        // the raw blob only — no false-positives in the parsed list.
        use std::collections::BTreeSet;
        let mut tcp = BTreeSet::new();
        let mut udp = BTreeSet::new();
        for line in raw.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            // nft pattern.
            for proto in ["tcp", "udp"] {
                if let Some(idx) = l.find(&format!("{proto} dport ")) {
                    let after = &l[idx + proto.len() + " dport ".len()..];
                    // Single port: "443 accept" / "443"
                    // Set: "{ 80, 443 } accept"
                    let trimmed = after.trim_start();
                    if let Some(rest) = trimmed.strip_prefix('{') {
                        let close = rest.find('}').unwrap_or(rest.len());
                        for tok in rest[..close].split(',') {
                            if let Ok(p) = tok.trim().parse::<u16>() {
                                if proto == "tcp" {
                                    tcp.insert(p);
                                } else {
                                    udp.insert(p);
                                }
                            }
                        }
                    } else {
                        let tok = trimmed
                            .split(|c: char| c.is_whitespace() || c == ',')
                            .next()
                            .unwrap_or("");
                        if let Ok(p) = tok.parse::<u16>() {
                            if proto == "tcp" {
                                tcp.insert(p);
                            } else {
                                udp.insert(p);
                            }
                        }
                    }
                }
                // iptables pattern: "... tcp dpt:NNN ... ACCEPT"
                if l.contains("ACCEPT") {
                    if let Some(idx) = l.find(&format!("{proto} dpt:")) {
                        let after = &l[idx + proto.len() + " dpt:".len()..];
                        let tok = after.split_whitespace().next().unwrap_or("");
                        if let Ok(p) = tok.parse::<u16>() {
                            if proto == "tcp" {
                                tcp.insert(p);
                            } else {
                                udp.insert(p);
                            }
                        }
                    }
                }
            }
        }

        // Merge tcp + udp into a single sorted ports list, decorate
        // each with its well-known-service label + category.
        let mut ports: Vec<hyperion_types::FirewallPort> = tcp
            .into_iter()
            .map(|p| {
                let (label, category) = well_known_port_label(p, "tcp");
                hyperion_types::FirewallPort {
                    port: p,
                    proto: "tcp".into(),
                    label,
                    category,
                }
            })
            .chain(udp.into_iter().map(|p| {
                let (label, category) = well_known_port_label(p, "udp");
                hyperion_types::FirewallPort {
                    port: p,
                    proto: "udp".into(),
                    label,
                    category,
                }
            }))
            .collect();
        ports.sort_by(|a, b| a.port.cmp(&b.port).then(a.proto.cmp(&b.proto)));

        Ok(hyperion_types::FirewallView {
            backend,
            ports,
            raw,
            error,
        })
    }

    pub async fn services_health(&self) -> Result<hyperion_types::ServicesHealth, RpcError> {
        // Workers don't run hyperion-web — only the master does. On a
        // worker node we'd otherwise flag hyperion-web as a "critical
        // service down" on every page load, which is confusing
        // ("CRITICAL: missing thing that's not supposed to be here").
        // Drop the entry entirely on workers so the table reflects
        // what the operator actually needs to care about.
        let is_worker = self.is_worker_node();
        let critical: Vec<(&str, &str)> = if is_worker {
            vec![
                ("nginx", "nginx (web server)"),
                ("hyperion-agent", "hyperion-agent (RPC daemon)"),
            ]
        } else {
            vec![
                ("nginx", "nginx (web server)"),
                ("hyperion-agent", "hyperion-agent (RPC daemon)"),
                ("hyperion-web", "hyperion-web (admin UI)"),
            ]
        };
        let optional: &[(&str, &str)] = &[
            ("mariadb", "MariaDB (database)"),
            ("postgresql", "PostgreSQL (database)"),
            ("redis-server", "Redis (object cache)"),
            ("vsftpd", "vsftpd (FTP)"),
            // MTA — provides /usr/sbin/sendmail for PHP mail().
            // When down/missing every hosted site's mail() returns
            // false and the per-hosting "Mail sent by this site"
            // log stays empty. Surface here so the operator can
            // see "MTA down" at a glance instead of grep'ing the
            // wrapper's stderr breadcrumbs.
            ("postfix", "postfix (MTA for PHP mail)"),
            ("php8.1-fpm", "PHP 8.1 FPM"),
            ("php8.2-fpm", "PHP 8.2 FPM"),
            ("php8.3-fpm", "PHP 8.3 FPM"),
            ("php8.4-fpm", "PHP 8.4 FPM"),
        ];
        // Fan ALL the probes out in parallel — was serial loop +
        // serial(rich + present) per unit, ~10 units × ~100 ms =
        // up to a full second of page-render latency. Now bounded
        // by the slowest single probe.
        let mut tasks: Vec<_> = Vec::with_capacity(critical.len() + optional.len());
        for (unit, label) in critical.iter().copied() {
            tasks.push(tokio::spawn(async move {
                let (status, present) = tokio::join!(
                    hyperion_adapters::systemctl_status_rich(unit),
                    hyperion_adapters::systemctl_unit_present(unit),
                );
                (unit, label, true, status, present)
            }));
        }
        for (unit, label) in optional.iter().copied() {
            tasks.push(tokio::spawn(async move {
                let (status, present) = tokio::join!(
                    hyperion_adapters::systemctl_status_rich(unit),
                    hyperion_adapters::systemctl_unit_present(unit),
                );
                (unit, label, false, status, present)
            }));
        }
        let mut services: Vec<hyperion_types::ServiceHealth> = Vec::new();
        let mut critical_down = 0usize;
        let mut warn_down = 0usize;
        for h in tasks {
            let Ok((unit, label, is_critical, status, mut present)) = h.await else {
                continue;
            };
            if status.active || status.enabled {
                present = true;
            }
            let mut sub = status.sub_state.clone();
            // "masked" is operator-intentional — surface it
            // distinctly so the operator doesn't see it as a
            // failure to fix.
            let masked = status.unit_file_state == "masked";
            if masked {
                sub = "masked".into();
            } else if !present {
                sub = if is_critical { "missing".into() } else { "not installed".into() };
            }
            let transient = status.transient();
            let severity = if masked {
                // masked = operator decided this shouldn't run.
                // Don't count it against health.
                "info".to_string()
            } else if !present {
                if is_critical {
                    critical_down += 1;
                    "error".to_string()
                } else {
                    "info".to_string()
                }
            } else if !status.active {
                if is_critical {
                    critical_down += 1;
                    "error".to_string()
                } else {
                    warn_down += 1;
                    "warn".to_string()
                }
            } else {
                "ok".to_string()
            };
            services.push(hyperion_types::ServiceHealth {
                name: unit.to_string(),
                label: label.to_string(),
                active: status.active,
                enabled: status.enabled,
                present,
                sub_state: sub,
                severity,
                active_state: status.active_state,
                transient,
            });
        }
        // Preserve operator-meaningful display order — critical first,
        // then optional in the order they were declared. Sorted by
        // the position in the source lists.
        let order: std::collections::HashMap<&str, usize> = critical
            .iter()
            .chain(optional.iter())
            .enumerate()
            .map(|(i, (u, _))| (*u, i))
            .collect();
        services.sort_by_key(|s| *order.get(s.name.as_str()).unwrap_or(&usize::MAX));
        Ok(hyperion_types::ServicesHealth {
            services,
            critical_down,
            warn_down,
        })
    }

    /// Recent samples from `node_metrics` shaped for the stats page's
    /// sparkline charts. Wrapper around the storage layer that drops
    /// the columns the template doesn't need.
    pub async fn node_metrics_history(
        &self,
        limit: i64,
    ) -> Result<hyperion_types::NodeMetricsHistory, RpcError> {
        let rows = hyperion_state::metrics::history(&self.pool, limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("metrics history: {e}")))?;
        let samples = rows
            .into_iter()
            .map(|r| hyperion_types::NodeMetricPoint {
                at: r.sampled_at,
                loadavg_1m_x100: r.loadavg_1m_x100,
                mem_used_kib: r.mem_used_kib,
                mem_total_kib: r.mem_total_kib,
                total_bw_out_24h: r.total_bw_out_24h,
                total_requests_24h: r.total_requests_24h,
                hostings_count: r.hostings_count,
            })
            .collect();
        Ok(hyperion_types::NodeMetricsHistory { samples })
    }

    pub async fn cluster_stats(
        &self,
        hostname: &str,
        version: &str,
    ) -> Result<ClusterStats, RpcError> {
        let n = self.node_stats(hostname, version).await?;
        Ok(ClusterStats {
            total_hostings: n.hostings_count,
            total_active: n.hostings_active,
            total_suspended: n.hostings_suspended,
            total_failed: n.hostings_failed,
            total_disk_bytes: n.total_disk_bytes,
            total_bw_out_24h: n.total_bw_out_24h,
            total_requests_24h: n.total_requests_24h,
            nodes: vec![n],
        })
    }

    // ================================================================
    //  Restore from backup archive
    // ================================================================

    // ================================================================
    //  Per-hosting logs
    // ================================================================

    /// Return the tail of a log file for the given hosting.
    /// `log_kind` ∈ {"access", "error"}.
    pub async fn hosting_logs(
        &self,
        sel: HostingSelector,
        log_kind: &str,
        lines: i64,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let lines = lines.clamp(10, 5000);
        let filename = match log_kind {
            "access" => "access.log",
            "error" => "error.log",
            other => {
                return Err(RpcError::Validation {
                    message: format!("unknown log_kind {other:?}; want \"access\" or \"error\""),
                })
            }
        };
        let path = std::path::PathBuf::from(&self.paths.home_root)
            .join(&detail.system_user)
            .join(&detail.domain)
            .join("logs")
            .join(filename);
        if !path.exists() {
            return Ok(format!("(no {} log yet at {})", log_kind, path.display()));
        }
        let path_str = path.display().to_string();
        let lines_str = lines.to_string();
        let out = tokio::process::Command::new("/usr/bin/tail")
            .args(["-n", &lines_str, &path_str])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("tail: {e}")))?;
        if !out.status.success() {
            return Err(RpcError::Internal_with(format!(
                "tail exit {:?}",
                out.status.code()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    // ================================================================
    //  Per-hosting cron jobs
    // ================================================================

    /// Read `crontab -u <user> -l`. Returns empty string if the user has
    /// no crontab installed.
    pub async fn cron_list(&self, sel: HostingSelector) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let out = tokio::process::Command::new("/usr/bin/crontab")
            .args(["-u", &detail.system_user, "-l"])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("crontab: {e}")))?;
        if !out.status.success() {
            // crontab returns non-zero if no crontab exists — treat as empty.
            return Ok(String::new());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Replace the user's crontab with `body`. Atomic — writes via temp
    /// file + `crontab -u <user> <file>`. Validates lines look like
    /// crontab entries (5 schedule fields + a command, OR @reboot etc.)
    /// to prevent injection.
    pub async fn cron_replace(
        &self,
        sel: HostingSelector,
        body: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        validate_crontab(&body)?;
        let tmp =
            std::env::temp_dir().join(format!("hyperion-cron-{}.tab", detail.system_user));
        tokio::fs::write(&tmp, body.as_bytes())
            .await
            .map_err(|e| RpcError::Internal_with(format!("write tmp: {e}")))?;
        let tmp_str = tmp.display().to_string();
        let out = tokio::process::Command::new("/usr/bin/crontab")
            .args(["-u", &detail.system_user, &tmp_str])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("crontab: {e}")))?;
        let _ = tokio::fs::remove_file(&tmp).await;
        if !out.status.success() {
            return Err(RpcError::ProvisioningFailed {
                stage: "crontab".into(),
                reason: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        self.append_audit(
            "hosting.cron.replace",
            Some(detail.id.as_str()),
            &serde_json::json!({"lines": body.lines().count()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    // ───────────── Notification bell ─────────────

    pub async fn notifications_feed(
        &self,
        user_id: i64,
        limit: i64,
    ) -> Result<hyperion_types::NotificationFeed, RpcError> {
        let items = hyperion_state::notifications::list_recent(&self.pool, user_id, limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications list: {e}")))?
            .into_iter()
            .map(|r| hyperion_types::NotificationView {
                id: r.id,
                severity: r.severity,
                title: r.title,
                body: r.body,
                href: r.href,
                kind: r.kind,
                created_at: r.created_at,
                read_at: r.read_at,
            })
            .collect();
        let unread_total = hyperion_state::notifications::unread_count(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications count: {e}")))?;
        Ok(hyperion_types::NotificationFeed {
            items,
            unread_total,
        })
    }

    pub async fn notifications_mark_read(
        &self,
        user_id: i64,
        notification_id: i64,
    ) -> Result<(), RpcError> {
        hyperion_state::notifications::mark_read(
            &self.pool,
            user_id,
            notification_id,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("notifications mark_read: {e}")))?;
        Ok(())
    }

    pub async fn notifications_mark_all_read(&self, user_id: i64) -> Result<i64, RpcError> {
        let n = hyperion_state::notifications::mark_all_read(&self.pool, user_id, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications mark_all_read: {e}")))?;
        Ok(n)
    }

    /// Fan-out helper: emit one notification to every super_admin
    /// and admin user. Operators are skipped by default since
    /// operator-relevant events typically have a hosting_id and a
    /// targeted recipient list; system-wide events go to admins.
    /// Best-effort — errors are logged, not returned (a single
    /// failed notification mustn't break the caller's flow).
    pub async fn notify_admins(
        &self,
        severity: &str,
        title: &str,
        body: &str,
        href: &str,
        kind: &str,
    ) {
        let users = match hyperion_state::web_users::list(&self.pool).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "notify_admins: list users failed");
                return;
            }
        };
        let now = now_secs();
        for u in users {
            if !matches!(
                u.role,
                hyperion_state::web_users::WebRole::SuperAdmin
                    | hyperion_state::web_users::WebRole::Admin
            ) {
                continue;
            }
            if let Err(e) = hyperion_state::notifications::insert(
                &self.pool,
                u.id,
                severity,
                title,
                body,
                href,
                kind,
                now,
            )
            .await
            {
                tracing::warn!(user = %u.username, error = %e, "notify_admins: insert failed");
            }
        }
    }

    pub async fn backup_restore(
        &self,
        sel: HostingSelector,
        archive_path: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // Whitelist the path — must live under one of OUR backup roots.
        let p = std::path::PathBuf::from(&archive_path);
        let canonical = p.canonicalize().map_err(|e| RpcError::Validation {
            message: format!("archive not readable: {e}"),
        })?;
        let allowed_roots = [
            std::path::PathBuf::from(&self.paths.backup_root),
            std::path::PathBuf::from("/var/lib/hyperion/backups/incoming"),
            // Migration export staging — `hosting_export` hardlinks the
            // archive here and `hosting_import` reads it back. Without
            // this, every cross-node `Migrate to another node` flow
            // would 400 with "not under allowed backup root".
            std::path::PathBuf::from("/var/lib/hyperion/migration"),
            // Migration pull staging — `hosting_import_from_url` writes
            // the downloaded archive here, then calls `backup_restore`
            // on it. Same gap; without this the new one-click import
            // workflow fails at the very last step.
            std::path::PathBuf::from("/var/lib/hyperion/migration-incoming"),
        ];
        if !allowed_roots
            .iter()
            .any(|r| canonical.starts_with(r))
        {
            return Err(RpcError::Validation {
                message: format!(
                    "archive {} is not under an allowed backup root",
                    canonical.display()
                ),
            });
        }

        // 1. Extract tar.gz over the hosting root.
        let host_root = std::path::PathBuf::from(&self.paths.home_root)
            .join(&detail.system_user)
            .join(&detail.domain);
        tracing::info!(domain = %detail.domain, archive = %canonical.display(),
            "restoring backup");
        let restore_result =
            hyperion_adapters::backup::restore_archive(&canonical, &host_root).await;
        if let Err(e) = restore_result {
            return Err(RpcError::ProvisioningFailed {
                stage: "tar_extract".into(),
                reason: e.to_string(),
            });
        }

        // 2. Look for sibling .sql dump and restore it if hosting has a DB.
        let archive_dir = canonical.parent().unwrap_or(std::path::Path::new("/"));
        if let Some(stem) = canonical.file_stem().and_then(|s| s.to_str()) {
            // strip the trailing ".tar" if present from .tar.gz double-ext
            let trim = stem.strip_suffix(".tar").unwrap_or(stem);
            let sibling = archive_dir.join(format!("{trim}.sql"));
            if sibling.exists() {
                if let Some(db) = &detail.database {
                    let restore = match db.engine {
                        hyperion_types::DbProvision::MariaDB => {
                            hyperion_adapters::backup::restore_mariadb_dump(
                                &db.db_name,
                                &sibling,
                            )
                            .await
                        }
                        hyperion_types::DbProvision::Postgres => {
                            hyperion_adapters::backup::restore_postgres_dump(
                                &db.db_name,
                                &sibling,
                            )
                            .await
                        }
                    };
                    if let Err(e) = restore {
                        return Err(RpcError::ProvisioningFailed {
                            stage: "db_restore".into(),
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        self.append_audit(
            "hosting.restore",
            Some(detail.id.as_str()),
            &serde_json::json!({"archive": canonical.display().to_string()}).to_string(),
            "ok",
        )
        .await;

        Ok(())
    }
}

fn node_stats_from(
    hostname: &str,
    version: &str,
    latest: Option<metrics::NodeMetricsRow>,
    summaries: &[HostingSummary],
) -> NodeStats {
    let (a, s, f) = summaries.iter().fold((0i64, 0i64, 0i64), |(a, s, f), x| {
        match x.state {
            HostingState::Active => (a + 1, s, f),
            HostingState::Suspended => (a, s + 1, f),
            HostingState::Failed => (a, s, f + 1),
            _ => (a, s, f),
        }
    });
    let count = summaries.len() as i64;
    match latest {
        Some(r) => NodeStats {
            node_id: hostname.to_string(),
            label: hostname.to_string(),
            hostings_count: count,
            hostings_active: a,
            hostings_suspended: s,
            hostings_failed: f,
            total_disk_bytes: r.total_disk_bytes,
            total_bw_out_24h: r.total_bw_out_24h,
            total_requests_24h: r.total_requests_24h,
            loadavg_1m_x100: r.loadavg_1m_x100,
            mem_total_kib: r.mem_total_kib,
            mem_used_kib: r.mem_used_kib,
            uptime_secs: r.uptime_secs,
            sampled_at: r.sampled_at,
            agent_version: version.to_string(),
            agent_online: true,
        },
        None => NodeStats {
            node_id: hostname.to_string(),
            label: hostname.to_string(),
            hostings_count: count,
            hostings_active: a,
            hostings_suspended: s,
            hostings_failed: f,
            total_disk_bytes: 0,
            total_bw_out_24h: 0,
            total_requests_24h: 0,
            loadavg_1m_x100: 0,
            mem_total_kib: 0,
            mem_used_kib: 0,
            uptime_secs: 0,
            sampled_at: 0,
            agent_version: version.to_string(),
            agent_online: true,
        },
    }
}

/// Lightweight crontab sanity check — reject any line containing a
/// NUL byte or a backtick (command-substitution). Empty lines and
/// comments (#) are allowed. We DON'T parse the schedule fields; the
/// real crontab command does that and rejects bad entries with a
/// meaningful error.
fn validate_crontab(body: &str) -> Result<(), RpcError> {
    for (i, line) in body.lines().enumerate() {
        if line.contains('\0') {
            return Err(RpcError::Validation {
                message: format!("line {} contains NUL byte", i + 1),
            });
        }
        // Reject backticks because they're shell command substitution and
        // we don't want operators accidentally executing arbitrary code
        // by pasting from a sketchy source. Operators who need them can
        // edit /var/spool/cron/crontabs/<user> directly.
        if line.contains('`') {
            return Err(RpcError::Validation {
                message: format!("line {} contains backtick — refused for safety", i + 1),
            });
        }
    }
    if body.len() > 65_536 {
        return Err(RpcError::Validation {
            message: "crontab body exceeds 64 KiB".into(),
        });
    }
    Ok(())
}

fn validate_profile(mut p: ProfileInput) -> Result<ProfileInput, RpcError> {
    p.name = p.name.trim().to_string();
    if p.name.is_empty() {
        return Err(RpcError::Validation {
            message: "profile name must not be empty".into(),
        });
    }
    if p.name.len() > 64 {
        return Err(RpcError::Validation {
            message: "profile name max 64 chars".into(),
        });
    }
    if p.expiry_warning_offsets.trim().is_empty() {
        p.expiry_warning_offsets = "30,7,1".into();
    }
    if let Some(c) = &p.price_currency {
        if !c.chars().all(|ch| ch.is_ascii_uppercase()) || c.len() != 3 {
            return Err(RpcError::Validation {
                message: "price_currency must be 3 uppercase ISO-4217 letters".into(),
            });
        }
    }
    if let Some(iv) = &p.price_interval {
        if !matches!(iv.as_str(), "monthly" | "quarterly" | "yearly") {
            return Err(RpcError::Validation {
                message: "price_interval must be monthly | quarterly | yearly".into(),
            });
        }
    }
    Ok(p)
}

fn profile_input_to_new(input: ProfileInput) -> hyperion_state::profiles::NewProfile {
    hyperion_state::profiles::NewProfile {
        name: input.name,
        description: input.description,
        php_memory_mb: input.php_memory_mb,
        php_max_exec_secs: input.php_max_exec_secs,
        php_max_children: input.php_max_children,
        php_max_requests: input.php_max_requests,
        db_max_connections: input.db_max_connections,
        disk_hard_mb: input.disk_hard_mb,
        bw_monthly_mb: input.bw_monthly_mb,
        expiry_grace_days: input.expiry_grace_days,
        expiry_warning_offsets: input.expiry_warning_offsets,
        price_minor: input.price_minor,
        price_currency: input.price_currency,
        price_interval: input.price_interval,
        slack_webhook: input.slack_webhook,
        wp_plugins: input.wp_plugins,
        wp_themes: input.wp_themes,
        // Normalise empty strings to None so the DB stores NULL and
        // the wizard's "no preference" path stays clean.
        default_php_version: input
            .default_php_version
            .filter(|s| !s.trim().is_empty()),
        default_db_engine: input
            .default_db_engine
            .filter(|s| !s.trim().is_empty()),
    }
}

fn profile_row_to_wire(r: hyperion_state::profiles::ProfileRow) -> HostingProfile {
    HostingProfile {
        id: r.id,
        name: r.name,
        description: r.description,
        php_memory_mb: r.php_memory_mb,
        php_max_exec_secs: r.php_max_exec_secs,
        php_max_children: r.php_max_children,
        php_max_requests: r.php_max_requests,
        db_max_connections: r.db_max_connections,
        disk_hard_mb: r.disk_hard_mb,
        bw_monthly_mb: r.bw_monthly_mb,
        expiry_grace_days: r.expiry_grace_days,
        expiry_warning_offsets: r.expiry_warning_offsets,
        price_minor: r.price_minor,
        price_currency: r.price_currency,
        price_interval: r.price_interval,
        slack_webhook: r.slack_webhook,
        wp_plugins: r.wp_plugins,
        wp_themes: r.wp_themes,
        default_php_version: r.default_php_version,
        default_db_engine: r.default_db_engine,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

fn derive_user_from_summary(s: &HostingSummary) -> Option<String> {
    // HostingSummary doesn't carry system_user yet; fall back to deriving
    // it from the domain the same way the create flow does.
    SystemUserName::derive_from_domain(&s.domain).ok().map(|u| u.as_str().to_string())
}

fn period_key(now: i64) -> String {
    use chrono::{TimeZone, Utc};
    let dt = Utc.timestamp_opt(now, 0).single().unwrap_or_else(Utc::now);
    dt.format("%Y-%m-%d-%H").to_string()
}

async fn dig_records(domain: &str, kind: &str) -> Result<Vec<String>, std::io::Error> {
    let out = tokio::process::Command::new("/usr/bin/dig")
        .args(["+short", "+time=3", "+tries=2", kind, domain])
        .output()
        .await?;
    if !out.status.success() {
        return Ok(vec![]);
    }
    let body = String::from_utf8_lossy(&out.stdout);
    Ok(body
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.contains(' '))
        .map(String::from)
        .collect())
}

async fn fetch_public_ip(url: &str) -> Result<String, std::io::Error> {
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args(["-fsS", "--max-time", "4", url])
        .output()
        .await?;
    if !out.status.success() {
        return Err(std::io::Error::other("curl exit non-zero"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn du_bytes(path: &std::path::Path) -> Result<i64, std::io::Error> {
    let out = tokio::process::Command::new("/usr/bin/du")
        .args(["-sb"])
        .arg(path)
        .output()
        .await?;
    if !out.status.success() {
        return Ok(0);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0))
}

/// Parse the tail of nginx access.log (default combined format) for the
/// last `since` epoch-seconds window. Returns (bw_in_bytes, bw_out_bytes,
/// requests, last_request_ts).
///
/// Nginx combined format: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent ...'.
/// We only have body_bytes_sent (bw_out) — bw_in is approximated as
/// `request_length` if available, else 0.
/// Map a (port, proto) pair to a friendly label + category. Used by
/// the /firewall page to render each open port as "443 tcp · HTTPS
/// (nginx)" instead of a bare number. The mapping covers the
/// services Hyperion provisions itself, plus the standard
/// well-known ports operators care about most. Unknown ports get
/// `("Unknown", "unknown")` and the UI renders a neutral pill.
///
/// Categories drive the colour of the pill in the UI:
///   - "infra"     → SSH, DNS, NTP, …            (gray-ish)
///   - "web"       → HTTP / HTTPS                (blue)
///   - "mail"      → SMTP/submission/IMAP/POP3   (purple)
///   - "db"        → MySQL/PG/Redis/Memcached    (amber)
///   - "hyperion"  → panel + master RPC          (accent)
///   - "unknown"   → everything else             (neutral)
fn well_known_port_label(port: u16, proto: &str) -> (String, String) {
    // proto is checked because e.g. 53 is both tcp + udp (DNS), 25
    // is only ever tcp. The table below uses tcp by default; udp-
    // specific mappings live in the explicit match arms.
    let (label, cat) = match (port, proto) {
        // --- infra ---
        (22, "tcp") => ("SSH", "infra"),
        (53, _) => ("DNS", "infra"),
        (67 | 68, "udp") => ("DHCP", "infra"),
        (123, "udp") => ("NTP", "infra"),

        // --- web (nginx) ---
        (80, "tcp") => ("HTTP (nginx)", "web"),
        (443, "tcp") => ("HTTPS (nginx)", "web"),
        (443, "udp") => ("HTTPS / QUIC (nginx)", "web"),

        // --- mail ---
        (25, "tcp") => ("SMTP (postfix)", "mail"),
        (110, "tcp") => ("POP3", "mail"),
        (143, "tcp") => ("IMAP", "mail"),
        (465, "tcp") => ("SMTPS (submission)", "mail"),
        (587, "tcp") => ("SMTP submission", "mail"),
        (993, "tcp") => ("IMAPS", "mail"),
        (995, "tcp") => ("POP3S", "mail"),

        // --- db ---
        (3306, "tcp") => ("MySQL / MariaDB", "db"),
        (5432, "tcp") => ("PostgreSQL", "db"),
        (6379, "tcp") => ("Redis", "db"),
        (11211, "tcp" | "udp") => ("Memcached", "db"),

        // --- hyperion ---
        (8443, "tcp") => ("Hyperion panel (web UI)", "hyperion"),
        (9443, "tcp") => ("Hyperion RPC (master ↔ worker)", "hyperion"),

        // --- FTP / SFTP (vsftpd) ---
        (21, "tcp") => ("FTP control (vsftpd)", "infra"),
        (20, "tcp") => ("FTP data (vsftpd)", "infra"),

        // --- ICMP-ish / common diagnostic ---
        (3478, _) => ("STUN / TURN", "infra"),

        _ => ("Unknown", "unknown"),
    };
    (label.to_string(), cat.to_string())
}

/// nft argv sequences for each hardcoded firewall template. Returns
/// `Some(vec_of_argv_arrays)` when the id is known, `None` otherwise.
///
/// Every sequence starts with the same two argv arrays that ensure
/// our `inet hyperion` table + `input` chain exist (idempotent — nft
/// reports "File exists" on re-apply, which the apply path filters
/// as benign). Each rule carries `comment "hyperion:<id>"` so an
/// auditor can grep them out of `nft list ruleset`.
///
/// Keep the ids in lock-step with the `port_templates()` data in
/// `bin/hyperion-web/src/handlers/firewall.rs` — the template card
/// passes its id over the wire.
fn firewall_template_commands(id: &str) -> Option<Vec<Vec<&'static str>>> {
    // Shared idempotent header: create table + chain.
    let header: Vec<Vec<&'static str>> = vec![
        vec!["add", "table", "inet", "hyperion"],
        vec![
            "add", "chain", "inet", "hyperion", "input",
            "{", "type", "filter", "hook", "input", "priority", "0", ";",
            "policy", "accept", ";", "}",
        ],
    ];
    let body: Vec<Vec<&'static str>> = match id {
        "web" => vec![
            vec![
                "add", "rule", "inet", "hyperion", "input",
                "tcp", "dport", "{", "80,", "443", "}", "accept",
                "comment", "hyperion:web",
            ],
            vec![
                "add", "rule", "inet", "hyperion", "input",
                "udp", "dport", "443", "accept",
                "comment", "hyperion:web-quic",
            ],
        ],
        "mail" => vec![vec![
            "add", "rule", "inet", "hyperion", "input",
            "tcp", "dport",
            "{", "25,", "465,", "587,", "993,", "995", "}", "accept",
            "comment", "hyperion:mail",
        ]],
        "hyperion" => vec![vec![
            "add", "rule", "inet", "hyperion", "input",
            "tcp", "dport", "{", "8443,", "9443", "}", "accept",
            "comment", "hyperion:hyperion",
        ]],
        "ssh" => vec![vec![
            "add", "rule", "inet", "hyperion", "input",
            "tcp", "dport", "22", "accept",
            "comment", "hyperion:ssh",
        ]],
        "ftp" => vec![
            vec![
                "add", "rule", "inet", "hyperion", "input",
                "tcp", "dport", "21", "accept",
                "comment", "hyperion:ftp-control",
            ],
            vec![
                "add", "rule", "inet", "hyperion", "input",
                "tcp", "dport", "40000-50000", "accept",
                "comment", "hyperion:ftp-passive",
            ],
        ],
        // "worker_rpc" needs <MASTER_IP> substitution which we
        // don't have at apply-time without an extra arg. Surface
        // it as snippet-only in the UI — skipping here returns
        // `None` and the validation error makes it clear.
        _ => return None,
    };
    Some(header.into_iter().chain(body).collect())
}

async fn parse_access_log_window(path: &std::path::Path, since: i64) -> (i64, i64, i64, i64) {
    let Ok(body) = tokio::fs::read_to_string(path).await else {
        return (0, 0, 0, 0);
    };
    use chrono::{DateTime, FixedOffset};
    let mut bw_in: i64 = 0;
    let mut bw_out: i64 = 0;
    let mut reqs: i64 = 0;
    let mut last_ts: i64 = 0;
    for line in body.lines() {
        // Extract bracketed timestamp.
        let Some(start) = line.find('[') else { continue };
        let Some(end) = line[start..].find(']') else { continue };
        let ts_str = &line[start + 1..start + end];
        let Ok(dt) = DateTime::<FixedOffset>::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z") else {
            continue;
        };
        let ts = dt.timestamp();
        if ts < since {
            continue;
        }
        reqs += 1;
        last_ts = last_ts.max(ts);
        // body_bytes_sent is the field right after status code.
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() > 10 {
            if let Ok(n) = parts[9].parse::<i64>() {
                bw_out += n;
            }
        }
        // If log_format extended with $request_length, it's usually parts[10..].
        if parts.len() > 11 {
            if let Ok(n) = parts[10].parse::<i64>() {
                bw_in += n;
            }
        }
    }
    (bw_in, bw_out, reqs, last_ts)
}

async fn read_proc_metrics() -> (i64, i64, i64, i64) {
    let loadavg = tokio::fs::read_to_string("/proc/loadavg").await.ok();
    let la_1m = loadavg
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|t| t.parse::<f64>().ok())
        })
        .map(|f| (f * 100.0) as i64)
        .unwrap_or(0);

    let meminfo = tokio::fs::read_to_string("/proc/meminfo").await.ok();
    let (mem_total, mem_avail) = meminfo
        .map(|s| {
            let mut total = 0i64;
            let mut avail = 0i64;
            for l in s.lines() {
                if let Some(rest) = l.strip_prefix("MemTotal:") {
                    total = rest
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0);
                } else if let Some(rest) = l.strip_prefix("MemAvailable:") {
                    avail = rest
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0);
                }
            }
            (total, avail)
        })
        .unwrap_or((0, 0));
    let mem_used = (mem_total - mem_avail).max(0);

    let uptime = tokio::fs::read_to_string("/proc/uptime")
        .await
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|t| t.parse::<f64>().ok())
        })
        .map(|f| f as i64)
        .unwrap_or(0);

    (la_1m, mem_total, mem_used, uptime)
}

/// Result of a single HTTP probe. Internal — service builds the wire
/// shape from this.
#[derive(Debug, Clone)]
struct HttpProbeResult {
    success: bool,
    http_status: Option<i64>,
    response_ms: i64,
    error_message: Option<String>,
}

/// 5-second timeout, follow up to 3 redirects, ignore TLS hostname
/// verification (operator picks the URL — they're targeting their own
/// host). Considered "success" iff status is 2xx OR 3xx.
async fn probe_http(url: &str) -> HttpProbeResult {
    use std::time::Instant;
    let start = Instant::now();
    // Shell out to curl — adds an external dep that's already on
    // every node (we use it for backups). Avoids pulling in a full
    // reqwest+tls stack and the rustls CryptoProvider dance.
    let res = tokio::process::Command::new("/usr/bin/curl")
        .args([
            "-skLI",                  // silent + insecure + follow + HEAD
            "--max-time",
            "5",
            "--max-redirs",
            "3",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            url,
        ])
        .output()
        .await;
    let elapsed = start.elapsed().as_millis() as i64;
    match res {
        Ok(out) => {
            let code_str = String::from_utf8_lossy(&out.stdout);
            let code: i64 = code_str.trim().parse().unwrap_or(0);
            let success = (200..400).contains(&code);
            HttpProbeResult {
                success,
                http_status: if code > 0 { Some(code) } else { None },
                response_ms: elapsed,
                error_message: if success {
                    None
                } else if code == 0 {
                    Some(String::from_utf8_lossy(&out.stderr).to_string())
                } else {
                    Some(format!("HTTP {code}"))
                },
            }
        }
        Err(e) => HttpProbeResult {
            success: false,
            http_status: None,
            response_ms: elapsed,
            error_message: Some(e.to_string()),
        },
    }
}

/// POST a JSON payload to a webhook. Used by both Slack (which
/// accepts the same `{"text": "..."}` shape) and the generic webhook
/// channel. Best-effort — returns the curl exit status as Result so
/// the caller can log without taking down the tick.
async fn http_post_json(url: &str, json_body: &str) -> Result<(), String> {
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args([
            "-skL",
            "--max-time",
            "10",
            "-H",
            "Content-Type: application/json",
            "-X",
            "POST",
            "-d",
            json_body,
            url,
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "curl exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Per-section + field validation. Returns owned (field, FieldValue)
/// pairs ready for the persist module.
/// Read the `[cluster]` section out of agent.toml. The cluster
/// section is UI-only — the agent itself doesn't enforce anything;
/// the master web UI checks `master_accepts_hostings` when
/// rendering the /hostings/new "Target node" dropdown. Returns the
/// default (`master_accepts_hostings = true`) on parse failure or
/// missing file/section so an out-of-date agent.toml never breaks
/// the settings page.
fn read_cluster_section(
    cfg_path: Option<&std::path::Path>,
) -> hyperion_types::ClusterConfigView {
    let Some(path) = cfg_path else {
        return hyperion_types::ClusterConfigView::default();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return hyperion_types::ClusterConfigView::default();
    };
    let Ok(doc) = raw.parse::<toml_edit::DocumentMut>() else {
        return hyperion_types::ClusterConfigView::default();
    };
    let section = doc.get("cluster");
    let accept = section
        .and_then(|s| s.get("master_accepts_hostings"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let test_node_ids = section
        .and_then(|s| s.get("test_node_ids"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let test_domain_template = section
        .and_then(|s| s.get("test_domain_template"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let test_wp_no_index = section
        .and_then(|s| s.get("test_wp_no_index"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let trash_enabled = section
        .and_then(|s| s.get("trash_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let trash_retention_days = section
        .and_then(|s| s.get("trash_retention_days"))
        .and_then(|v| v.as_integer())
        .unwrap_or(30)
        .clamp(1, 365);
    let panel_hostname = section
        .and_then(|s| s.get("panel_hostname"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let audit_retention_days = section
        .and_then(|s| s.get("audit_retention_days"))
        .and_then(|v| v.as_integer())
        .unwrap_or(0)
        .clamp(0, 3650);
    hyperion_types::ClusterConfigView {
        master_accepts_hostings: accept,
        test_node_ids,
        test_domain_template,
        test_wp_no_index,
        panel_hostname,
        trash_enabled,
        trash_retention_days,
        audit_retention_days,
    }
}

fn parse_agent_section_fields(
    section: &str,
    fields: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<(String, crate::config_persist::FieldValue)>, RpcError> {
    let bad = |msg: String| RpcError::Validation { message: msg };
    let mut out = Vec::with_capacity(fields.len());
    for (k, v) in fields {
        let parsed = match (section, k.as_str()) {
            // [acme]
            ("acme", "contact_email") => {
                if !v.contains('@') || v.len() > 254 {
                    return Err(bad("invalid email".into()));
                }
                crate::config_persist::FieldValue::Str(v.clone())
            }
            ("acme", "directory_url") | ("acme", "challenge_dir") => {
                crate::config_persist::FieldValue::Str(v.clone())
            }
            // [email]
            ("email", "enabled") => crate::config_persist::FieldValue::Bool(parse_bool(v)?),
            ("email", "smtp_host")
            | ("email", "smtp_user")
            | ("email", "smtp_password")
            | ("email", "from_address")
            | ("email", "from_name")
            | ("email", "security")
            | ("email", "default_to") => {
                crate::config_persist::FieldValue::Str(v.clone())
            }
            ("email", "smtp_port") => crate::config_persist::FieldValue::Int(parse_int(v)?),
            // [slack]
            ("slack", "default_webhook") => crate::config_persist::FieldValue::Str(v.clone()),
            // [backup_remote]
            ("backup_remote", "enabled") => {
                crate::config_persist::FieldValue::Bool(parse_bool(v)?)
            }
            ("backup_remote", "scheme")
            | ("backup_remote", "host")
            | ("backup_remote", "user")
            | ("backup_remote", "password")
            | ("backup_remote", "base_path") => {
                crate::config_persist::FieldValue::Str(v.clone())
            }
            ("backup_remote", "port") => {
                crate::config_persist::FieldValue::Int(parse_int(v)?)
            }
            // [backup_retention]
            ("backup_retention", "max_age_days")
            | ("backup_retention", "keep_latest_n") => {
                crate::config_persist::FieldValue::Int(parse_int(v)?)
            }
            // [cluster] — master web UI placement preferences
            ("cluster", "master_accepts_hostings")
            | ("cluster", "test_wp_no_index")
            | ("cluster", "trash_enabled") => {
                crate::config_persist::FieldValue::Bool(parse_bool(v)?)
            }
            ("cluster", "test_node_ids")
            | ("cluster", "test_domain_template")
            | ("cluster", "panel_hostname") => {
                crate::config_persist::FieldValue::Str(v.trim().to_string())
            }
            ("cluster", "trash_retention_days") => {
                let n = parse_int(v)?;
                if !(1..=365).contains(&n) {
                    return Err(bad(format!(
                        "trash_retention_days must be 1..=365, got {n}"
                    )));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            ("cluster", "audit_retention_days") => {
                let n = parse_int(v)?;
                if !(0..=3650).contains(&n) {
                    return Err(bad(format!(
                        "audit_retention_days must be 0..=3650 (0 = keep forever), got {n}"
                    )));
                }
                crate::config_persist::FieldValue::Int(n)
            }
            // Reject anything else.
            _ => {
                return Err(bad(format!(
                    "field `{k}` is not editable in section `{section}` (or section unknown)"
                )));
            }
        };
        out.push((k.clone(), parsed));
    }
    Ok(out)
}

fn parse_bool(v: &str) -> Result<bool, RpcError> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Ok(true),
        "false" | "off" | "no" | "0" | "" => Ok(false),
        _ => Err(RpcError::Validation {
            message: format!("expected bool, got {v:?}"),
        }),
    }
}

fn parse_int(v: &str) -> Result<i64, RpcError> {
    v.trim().parse::<i64>().map_err(|_| RpcError::Validation {
        message: format!("expected integer, got {v:?}"),
    })
}

fn row_to_summary(u: hyperion_state::web_users::WebUserRow) -> hyperion_types::WebUserSummary {
    hyperion_types::WebUserSummary {
        id: u.id,
        username: u.username,
        email: u.email,
        role: u.role.as_str().to_string(),
        totp_enrolled: u.totp_enrolled_at.is_some(),
        totp_required: u.totp_required,
        locked: u.locked,
        locked_reason: u.locked_reason,
        last_login_at: u.last_login_at,
        created_at: u.created_at,
    }
}

fn run_to_wire(r: hyperion_state::backups::BackupRun) -> hyperion_types::BackupRunWire {
    hyperion_types::BackupRunWire {
        id: r.id,
        hosting_id: r.hosting_id,
        target: r.target,
        started_at: r.started_at,
        finished_at: r.finished_at,
        state: r.state,
        archive_path: r.archive_path,
        db_dump_path: r.db_dump_path,
        bytes_total: r.bytes_total,
        error_message: r.error_message,
    }
}

fn expiry_row_to_dto(row: hyperion_state::scheduler::ExpiryRow) -> hyperion_types::HostingExpiry {
    hyperion_types::HostingExpiry {
        expires_at: row.expires_at,
        owner_email: row.owner_email,
        grace_days: row.grace_days,
        warning_offsets_days: row.warning_offsets_days,
    }
}

/// Probe every common outbound SMTP port with a 3-second timeout
/// each. Runs all probes in parallel via `tokio::join!`. Returns a
/// Vec preserving the well-known port order (25, 465, 587, 2525)
/// so the UI renders a stable table.
///
/// Targets:
///   * 25  — gmail-smtp-in.l.google.com (real MX, port 25 receiving)
///   * 465 — smtp.gmail.com (implicit-TLS submission)
///   * 587 — smtp.gmail.com (STARTTLS submission)
///   * 2525 — smtp.mailgun.org (alt-submission accepted by many
///            providers when 587 is blocked; some operators use
///            it as a last-resort port)
///
/// Each probe is a TCP-connect, no SMTP banner read — we just
/// want to know whether the egress firewall allows the port.
async fn probe_outbound_smtp_all() -> Vec<hyperion_types::MtaPortProbe> {
    let p25 = single_smtp_probe(25, "gmail-smtp-in.l.google.com", "MX delivery (recipient servers)");
    let p465 = single_smtp_probe(465, "smtp.gmail.com", "Implicit-TLS submission");
    let p587 = single_smtp_probe(587, "smtp.gmail.com", "STARTTLS submission (most common)");
    let p2525 = single_smtp_probe(2525, "smtp.mailgun.org", "Alt-submission (when 587 blocked)");
    let (r25, r465, r587, r2525) = tokio::join!(p25, p465, p587, p2525);
    vec![r25, r465, r587, r2525]
}

async fn single_smtp_probe(
    port: u16,
    host: &str,
    purpose: &str,
) -> hyperion_types::MtaPortProbe {
    use std::time::Instant;
    use tokio::net::TcpStream;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    let target = format!("{host}:{port}");
    let started = Instant::now();
    let connect = tokio::time::timeout(TIMEOUT, TcpStream::connect(&target)).await;
    let elapsed = started.elapsed().as_millis() as u64;
    match connect {
        Ok(Ok(_)) => hyperion_types::MtaPortProbe {
            port,
            host: host.to_string(),
            reachable: true,
            latency_ms: elapsed,
            error: String::new(),
            purpose: purpose.to_string(),
        },
        Ok(Err(e)) => hyperion_types::MtaPortProbe {
            port,
            host: host.to_string(),
            reachable: false,
            latency_ms: 0,
            error: format!("{e}"),
            purpose: purpose.to_string(),
        },
        Err(_) => hyperion_types::MtaPortProbe {
            port,
            host: host.to_string(),
            reachable: false,
            latency_ms: 0,
            error: "timeout after 3 s".to_string(),
            purpose: purpose.to_string(),
        },
    }
}

/// Detect a WordPress install at `<root_dir>` by checking for the
/// two files that any WP install (Hyperion-managed, SSH-installed,
/// migrated, restored from backup) MUST have: `wp-config.php` and
/// `wp-includes/version.php`. Returns the version string parsed
/// out of version.php's `$wp_version = '<x.y.z>'` line, or
/// `"unknown"` when both files are present but the version line
/// can't be parsed (corrupt install, custom fork, etc.).
///
/// Returns `None` when either file is missing or unreadable —
/// strict "no WP here" answer. Never panics. Never errors out
/// (the caller treats `None` as "no install" the same way it
/// treats an empty DB row).
pub(crate) async fn detect_wp_install_on_disk(root_dir: &str) -> Option<String> {
    use std::path::Path;
    let root = Path::new(root_dir);
    // wp-config.php — proof that WP setup has run at all.
    let wp_config = root.join("wp-config.php");
    if tokio::fs::metadata(&wp_config).await.is_err() {
        return None;
    }
    // wp-includes/version.php — has the version string.
    let version_php = root.join("wp-includes").join("version.php");
    let Ok(body) = tokio::fs::read_to_string(&version_php).await else {
        // wp-config exists but core is missing — this is a partial
        // install. Treat as "no WP" rather than fake a version,
        // so the operator's install button stays available to
        // recover it.
        return None;
    };
    // Parse `$wp_version = '<x.y.z>'` (single or double quotes,
    // any amount of whitespace around the `=`). Defensive: only
    // accept versions of the shape [digit.][...] so we never
    // surface garbage from a corrupt file.
    for raw in body.lines() {
        let line = raw.trim_start();
        // Skip comments — both `//` and `#` and `/*` styles can
        // legally appear above the version line.
        if line.starts_with("//") || line.starts_with('#') || line.starts_with("/*") {
            continue;
        }
        let Some(rest) = line.strip_prefix("$wp_version") else {
            continue;
        };
        // Allow optional whitespace, then `=`, then any whitespace,
        // then a quote.
        let after_eq = match rest.split_once('=') {
            Some((_, r)) => r.trim_start(),
            None => continue,
        };
        let quote_char = after_eq.chars().next();
        let inside = match quote_char {
            Some('\'') | Some('"') => {
                let q = quote_char.unwrap();
                let s = &after_eq[1..];
                match s.find(q) {
                    Some(end) => &s[..end],
                    None => continue,
                }
            }
            _ => continue,
        };
        if inside.is_empty() {
            continue;
        }
        if !inside
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c.is_ascii_alphanumeric())
        {
            continue;
        }
        return Some(inside.to_string());
    }
    // version.php existed but didn't match the expected shape —
    // still WP, just unknown version. The detail UI shows "unknown"
    // as the version which is honest about what we observed.
    Some("unknown".to_string())
}

fn clamp_limits(mut l: hyperion_types::HostingLimits) -> hyperion_types::HostingLimits {
    // Hard sanity ranges. Refusing to store nonsense is more useful than
    // silently mis-applying it later.
    l.php_memory_mb = l.php_memory_mb.clamp(16, 8192);
    l.php_max_exec_secs = l.php_max_exec_secs.clamp(1, 3600);
    l.php_max_children = l.php_max_children.clamp(1, 200);
    l.php_max_requests = l.php_max_requests.clamp(0, 1_000_000);
    l.db_max_connections = l.db_max_connections.clamp(1, 1000);
    if let Some(b) = l.disk_soft_bytes {
        l.disk_soft_bytes = Some(b.max(0));
    }
    if let Some(b) = l.disk_hard_bytes {
        l.disk_hard_bytes = Some(b.max(0));
    }
    if let Some(b) = l.bw_monthly_bytes {
        l.bw_monthly_bytes = Some(b.max(0));
    }
    if let Some(k) = l.throttle_kbps {
        l.throttle_kbps = Some(k.clamp(1, 10_000_000));
    }
    l
}

fn limits_to_row(
    id: &HostingId,
    l: &hyperion_types::HostingLimits,
    now: i64,
) -> hyperion_state::limits::LimitsRow {
    hyperion_state::limits::LimitsRow {
        hosting_id: id.clone(),
        disk_soft_bytes: l.disk_soft_bytes,
        disk_hard_bytes: l.disk_hard_bytes,
        inode_soft: l.inode_soft,
        inode_hard: l.inode_hard,
        php_memory_mb: l.php_memory_mb,
        php_max_exec_secs: l.php_max_exec_secs,
        php_max_children: l.php_max_children,
        php_max_requests: l.php_max_requests,
        db_max_connections: l.db_max_connections,
        bw_monthly_bytes: l.bw_monthly_bytes,
        over_bw_policy: l.over_bw_policy.as_str().to_string(),
        throttle_kbps: l.throttle_kbps,
        updated_at: now,
    }
}

fn row_to_limits(row: hyperion_state::limits::LimitsRow) -> hyperion_types::HostingLimits {
    let policy = match row.over_bw_policy.as_str() {
        "throttle" => hyperion_types::OverBwPolicy::Throttle,
        _ => hyperion_types::OverBwPolicy::Suspend,
    };
    hyperion_types::HostingLimits {
        disk_soft_bytes: row.disk_soft_bytes,
        disk_hard_bytes: row.disk_hard_bytes,
        inode_soft: row.inode_soft,
        inode_hard: row.inode_hard,
        php_memory_mb: row.php_memory_mb,
        php_max_exec_secs: row.php_max_exec_secs,
        php_max_children: row.php_max_children,
        php_max_requests: row.php_max_requests,
        db_max_connections: row.db_max_connections,
        bw_monthly_bytes: row.bw_monthly_bytes,
        over_bw_policy: policy,
        throttle_kbps: row.throttle_kbps,
    }
}

// ===== Internal-error helper =====
trait InternalWith {
    fn internal_with(msg: String) -> Self;
}
impl InternalWith for RpcError {
    fn internal_with(msg: String) -> Self {
        tracing::error!(error=%msg, "internal error");
        RpcError::Internal
    }
}

// Allow `RpcError::Internal_with(..)` call style.
#[allow(non_snake_case)]
impl RpcErrorExt for RpcError {
    fn Internal_with(msg: String) -> Self {
        <RpcError as InternalWith>::internal_with(msg)
    }
}

trait RpcErrorExt {
    #[allow(non_snake_case)]
    fn Internal_with(msg: String) -> Self;
}

/// Push a disk quota into the kernel via `setquota -u <user>
/// <soft_blocks> <hard_blocks> 0 0 -a`. The `-a` flag means "every
/// filesystem with quotas on", so we don't have to detect which
/// mount the user's home dir actually lives on.
///
/// Inode limits are left at 0 (no cap) — operators care about disk
/// space, not file count; capping inodes is a different policy
/// knob we can expose later.
///
/// Returns `Ok(())` on exit 0 or `Err(stderr-tail)` otherwise. The
/// most common failure is `setquota: Cannot wait for ... quotas
/// turned off` when /etc/fstab doesn't carry `usrquota` — the UI
/// surfaces that via the `setup_hint` returned alongside reads.
async fn apply_disk_quota(
    user: &str,
    soft_kib: i64,
    hard_kib: i64,
) -> Result<(), String> {
    // setquota refuses to run if quotaon hasn't been done on at
    // least one mount. Probe `quotacheck`'s output cheaply via
    // `quotaon -p` (print state). If no mount has quotas enabled,
    // fail fast with a clean message instead of letting setquota
    // produce its own confusing error.
    let probe = tokio::process::Command::new("/usr/sbin/quotaon")
        .args(["-p", "-a"])
        .output()
        .await;
    if let Ok(p) = &probe {
        let out = String::from_utf8_lossy(&p.stdout);
        // `quotaon -p -a` lists each mount with "user quotas on" or
        // "user quotas off". When ALL lines say off, setquota would
        // fail. We tolerate stderr-only output too (some distros
        // print to stderr).
        let any_on = out.lines().any(|l| {
            l.contains("user quotas on") || l.contains("group quotas on")
        });
        if !any_on && !out.is_empty() {
            return Err(
                "quotas not enabled on any filesystem — add usrquota,grpquota to /etc/fstab and run `mount -o remount /` + `quotacheck -ugm /` + `quotaon -v /`".into(),
            );
        }
    }
    let out = tokio::process::Command::new("/usr/sbin/setquota")
        .args([
            "-u",
            user,
            &soft_kib.to_string(),
            &hard_kib.to_string(),
            "0",
            "0",
            "-a",
        ])
        .output()
        .await
        .map_err(|e| format!("spawn setquota: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        Err(format!(
            "setquota exit {}: {}{}",
            out.status.code().unwrap_or(-1),
            stderr.trim(),
            stdout.trim(),
        ))
    }
}

/// Probe current disk usage for the hosting:
///   1. `quota -u <user>` if quotas are enabled — single line, fast,
///      reports the kernel's view (matches what `setquota` enforces)
///   2. fallback `du -sk <home>` if quota is unavailable — slower but
///      always works (lets the UI show *some* number even on VPSes
///      without quotas configured).
///
/// Returns (current_disk_kib, quotas_enabled_on_fs, setup_hint).
async fn quota_probe_current(
    user: &str,
    home_dir: &str,
) -> (i64, bool, String) {
    // `quota -u -q -w` prints used blocks in machine-readable form.
    // Output (when quotas are on) is one line: "<fs>  <used>  <soft>
    // <hard>  <files>  <soft>  <hard>". When quotas are off, exit
    // code is non-zero and stderr is "Disk quotas for user <user>:
    // none".
    let q = tokio::process::Command::new("/usr/bin/quota")
        .args(["-u", "-q", "-w", user])
        .output()
        .await;
    if let Ok(out) = q {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 2 {
                    if let Ok(used) = cols[1].trim_end_matches('*').parse::<i64>() {
                        return (
                            used,
                            true,
                            String::new(),
                        );
                    }
                }
            }
        }
    }
    // Fallback: `du -sk` for the home dir.
    let du = tokio::process::Command::new("/usr/bin/du")
        .args(["-sk", home_dir])
        .output()
        .await;
    let used = du
        .ok()
        .and_then(|o| {
            if !o.status.success() {
                return None;
            }
            let s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.split_whitespace()
                .next()
                .and_then(|n| n.parse::<i64>().ok())
        })
        .unwrap_or(0);
    let hint = "Kernel quotas aren't enabled on this filesystem. Disk usage is shown from `du`, but `setquota` won't enforce caps. Edit /etc/fstab to add `usrquota,grpquota` and run `mount -o remount /` + `quotaon -v /` to enable.".to_string();
    (used, false, hint)
}

/// Snapshot of one filesystem's usage, parsed from `df -P -B1`.
/// `used_pct` is rounded down so a 79.999% filesystem is reported
/// as 79, not 80 — operators trust round trips of this number.
#[derive(Debug, Clone)]
struct DiskUsage {
    mount: String,
    total_bytes: i64,
    used_bytes: i64,
    used_pct: i64,
}

/// Probe filesystem usage via `df -P -B1` on the mounts the panel
/// cares about. POSIX mode (`-P`) keeps the columns stable across
/// distros; `-B1` outputs bytes (not KiB) so the math is exact.
///
/// Returns empty on any parsing failure — alerts are best-effort
/// and we'd rather under-warn than crash the dashboard.
async fn probe_disk_usages() -> std::io::Result<Vec<DiskUsage>> {
    // Hand-picked list: the mountpoints any practical Hyperion
    // node could fill up. `/var` is where hosting trees + DB dumps
    // + nginx logs + apt cache + hyperion's own data dir
    // (/var/lib/hyperion) all live; `/` covers everything else
    // including immutable images that don't carve /var separately.
    // df ignores a missing mount with exit 1 and an error on
    // stderr; we just drop those rows.
    let out = tokio::process::Command::new("df")
        .args(["-P", "-B1", "/", "/var", "/home", "/tmp"])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut seen_mounts = std::collections::HashSet::new();
    let mut rows = Vec::new();
    // First line is the header — skip it.
    for line in stdout.lines().skip(1) {
        // `df -P -B1` columns: Filesystem 1-blocks Used Available Capacity Mounted-on
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let mount = cols[cols.len() - 1].to_string();
        // The same physical device often appears multiple times in
        // our requested list (`/` and `/home` on a single-partition
        // VPS). Dedup by mount so we don't double-alert.
        if !seen_mounts.insert(mount.clone()) {
            continue;
        }
        let total: i64 = cols[1].parse().unwrap_or(0);
        let used: i64 = cols[2].parse().unwrap_or(0);
        if total <= 0 {
            continue;
        }
        // `df` rounds Capacity to whole percent; redo it ourselves
        // from bytes for accuracy.
        let pct = (used.saturating_mul(100) / total).clamp(0, 100);
        rows.push(DiskUsage {
            mount,
            total_bytes: total,
            used_bytes: used,
            used_pct: pct,
        });
    }
    Ok(rows)
}

/// Format `bytes` as a short human string ("12.3 GiB"). Used by
/// the dashboard banner — the operator wants "8 GiB free" not
/// "8589934592 bytes". Caps at TiB; anything bigger would be a
/// genuine surprise on a hosting node.
fn human_bytes(bytes: i64) -> String {
    let units = [("TiB", 1i64 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)];
    for (label, scale) in units.iter() {
        if bytes >= *scale {
            return format!("{:.1} {}", bytes as f64 / *scale as f64, label);
        }
    }
    format!("{bytes} B")
}

/// Write a sensitive blob to disk with restrictive permissions
/// (0600, root-owned via the agent's pre-existing root mode).
/// Creates the parent dir if needed. Used by the backup-target
/// secret storage so the access key never ends up in audit logs
/// or shell history.
async fn write_secret_file(path: &str, content: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let pb = std::path::PathBuf::from(path);
    if let Some(parent) = pb.parent() {
        tokio::fs::create_dir_all(parent).await?;
        let mut perms = tokio::fs::metadata(parent).await?.permissions();
        perms.set_mode(0o700);
        let _ = tokio::fs::set_permissions(parent, perms).await;
    }
    tokio::fs::write(&pb, content).await?;
    let mut perms = tokio::fs::metadata(&pb).await?.permissions();
    perms.set_mode(0o600);
    tokio::fs::set_permissions(&pb, perms).await?;
    Ok(())
}

fn backup_target_row_to_view(
    r: hyperion_state::backup_targets::BackupTargetRow,
) -> hyperion_types::BackupTargetView {
    hyperion_types::BackupTargetView {
        id: r.id,
        name: r.name,
        kind: r.kind,
        endpoint: r.endpoint,
        bucket: r.bucket,
        region: r.region,
        access_key_id: r.access_key_id,
        secret_key_id: r.secret_key_id,
        age_recipient: r.age_recipient,
        retention_daily: r.retention_daily,
        retention_weekly: r.retention_weekly,
        retention_monthly: r.retention_monthly,
        enabled: r.enabled,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

/// Convert the SQLite row representation into the wire-format `JobView`
/// the UI + hctl consume. Pure mapping, no I/O.
fn job_row_to_view(r: hyperion_state::jobs::JobRow) -> hyperion_types::JobView {
    hyperion_types::JobView {
        id: r.id,
        kind: r.kind,
        target: r.target,
        state: r.state,
        step_label: r.step_label,
        progress_pct: r.progress_pct,
        log_tail: r.log_tail,
        error: r.error,
        payload_json: r.payload_json,
        actor_uid: r.actor_uid,
        actor_label: r.actor_label,
        started_at: r.started_at,
        updated_at: r.updated_at,
        finished_at: r.finished_at,
    }
}

/// Classify the VPS image based on filesystem fingerprints — drives
/// the auto-fix UX (snap/overlay images CAN'T be made RW). Best-
/// effort; "unknown" is a safe default.
fn classify_image_kind(root_fstype: &str, usr_fstype: &str) -> String {
    // squashfs is the snap signature — snapd mounts core24/jammy
    // images this way.
    if usr_fstype == "squashfs" || root_fstype == "squashfs" {
        return "snap-managed".into();
    }
    // overlay-based immutable images (Fedora CoreOS, ostree-style).
    if root_fstype == "overlay" {
        return "overlay-immutable".into();
    }
    // ostree marker — Atomic / CoreOS / Silverblue.
    if std::path::Path::new("/ostree").exists() {
        return "ostree".into();
    }
    // The boring 90% case.
    if matches!(root_fstype, "ext4" | "xfs" | "btrfs" | "ext3" | "ext2") {
        return "standard".into();
    }
    "unknown".into()
}

/// Sanity check: is /usr writable? Many minimal VPS images ship
/// with /usr on a read-only / immutable filesystem (snap, snapd
/// `usr.merge`, certain Debian "ostree"-style live images, or an
/// operator-mounted `noexec,nodev,ro` partition). apt then fails
/// with "Read-only file system" deep in dpkg's unpack step with
/// 100+ lines of half-extracted noise. Detect by trying to touch
/// a sentinel file in /usr/lib/.hyperion-rw-check.
///
/// Returns `None` when writable (good); `Some(message)` with a
/// clear actionable error for the operator otherwise.
async fn check_usr_writable() -> Option<String> {
    let sentinel = std::path::Path::new("/usr/lib/.hyperion-rw-check");
    match tokio::fs::write(sentinel, b"ok").await {
        Ok(_) => {
            let _ = tokio::fs::remove_file(sentinel).await;
            None
        }
        Err(e) => Some(format!(
            "/usr is not writable ({e}). apt-get cannot install packages — the most likely \
             cause is the rootfs being mounted read-only (snap-managed images, immutable VPS \
             flavours, or a noexec/ro mount in /etc/fstab). Run `mount | grep ' /usr '` and \
             `mount | grep ' / '` to verify; if you see `ro,` you'll need to remount RW \
             (`mount -o remount,rw /` then retry) or pick a different base image."
        )),
    }
}

/// Mask an email address for display: keep the first letter +
/// last letter of the local part, replace the rest with `****`.
/// `"kevin@example.cz"` → `"k****n@example.cz"`. Single-letter
/// locals collapse to `*@example.cz`.
fn mask_email(s: &str) -> String {
    if let Some(at) = s.find('@') {
        let local = &s[..at];
        let domain = &s[at..];
        match local.chars().count() {
            0 => format!("***{domain}"),
            1 => format!("*{domain}"),
            2 => format!("**{domain}"),
            _ => {
                let mut chars = local.chars();
                let first = chars.next().unwrap_or('?');
                let last = chars.last().unwrap_or('?');
                format!("{first}****{last}{domain}")
            }
        }
    } else {
        "****".to_string()
    }
}

/// Stable per-hosting Redis ACL username derived from the ULID.
/// `r_` prefix + first 8 chars of the ULID lowercased — short
/// enough to fit in `redis-cli ACL LIST` output without wrapping,
/// long enough to avoid collisions in any realistic deployment
/// (8 base32 chars = 40 bits = 1T combinations).
fn redis_username_for(hosting_id: &str) -> String {
    let suffix: String = hosting_id.chars().take(8).collect();
    format!("r_{}", suffix.to_lowercase())
}

/// Generate a 32-char alphanumeric password for Redis. Same shape
/// as `adapters::random_password` but inlined here to avoid pulling
/// in the whole adapters crate from this module path (already
/// indirectly available via Arc<A: AdapterPort>, but cleaner to
/// reuse the same RNG without crossing the trait boundary).
fn generate_redis_password() -> String {
    hyperion_adapters::random_password()
}

// ===== Rollback impls =====

struct DeleteUser<A: AdapterPort> {
    adapters: Arc<A>,
    name: String,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for DeleteUser<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .delete_user(&self.name)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "delete_user"
    }
}

/// Drop the `system_users` row by id during create-failure rollback.
///
/// Pushed onto the rollback stack AFTER a successful
/// `system_users::insert`. Without this, a later step's failure
/// (FPM, DB, ACME, nginx, …) rolls back the Linux-side user via
/// `userdel` but leaves the DB row, claiming the UID forever. The
/// next create attempt's `useradd` reuses that UID (Linux freed it
/// at userdel time) and trips `UNIQUE(system_users.uid)`:
///
///   useradd → UID 1000  (Linux says ok)
///   system_users::insert(uid=1000) → UNIQUE constraint failed
///
/// LIFO order in the rollback stack: DeleteSystemUsersRow runs
/// BEFORE DeleteUser, so the DB row goes away first, then the
/// Linux user — matches the order the normal delete() path uses.
struct DeleteSystemUsersRow {
    pool: SqlitePool,
    row_id: i64,
}
#[async_trait]
impl Rollback for DeleteSystemUsersRow {
    async fn run(&self) -> Result<(), String> {
        system_users::delete(&self.pool, self.row_id)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "delete_system_users_row"
    }
}

struct RemoveTree<A: AdapterPort> {
    adapters: Arc<A>,
    root: String,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for RemoveTree<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .remove_hosting_tree(&self.root)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "remove_tree"
    }
}

struct MarkFailedOrDeleteRow {
    pool: SqlitePool,
    id: HostingId,
}
#[async_trait]
impl Rollback for MarkFailedOrDeleteRow {
    /// On create-failure rollback we DELETE the half-created
    /// hostings row instead of just marking it `failed`. Previously
    /// the row stayed forever, and the UNIQUE constraint on
    /// `hostings.domain` then blocked every subsequent attempt to
    /// re-create the same domain — even after the operator "deleted"
    /// it via the UI (the UI didn't see the failed row because the
    /// listing is hosting-state-aware on the master side, and
    /// HostingDelete refused to act on a state=failed row through
    /// the normal happy-path delete).
    ///
    /// `hostings::delete_id` cascades into aliases / system_user
    /// references so the row goes away cleanly.
    async fn run(&self) -> Result<(), String> {
        hostings::delete(&self.pool, &self.id)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "delete_hosting_row"
    }
}

struct FpmDelete<A: AdapterPort> {
    adapters: Arc<A>,
    system_user: String,
    version: PhpVersion,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for FpmDelete<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .fpm_delete(&self.system_user, self.version)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "fpm_delete"
    }
}

struct DbDrop<A: AdapterPort> {
    adapters: Arc<A>,
    engine: DbProvision,
    db_name: String,
    db_user: String,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for DbDrop<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .db_drop(self.engine, &self.db_name, &self.db_user)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "db_drop"
    }
}

struct AcmeDelete<A: AdapterPort> {
    adapters: Arc<A>,
    domain: String,
}
#[async_trait]
impl<A: AdapterPort + 'static> Rollback for AcmeDelete<A> {
    async fn run(&self) -> Result<(), String> {
        self.adapters
            .acme_delete(&self.domain)
            .await
            .map_err(|e| e.to_string())
    }
    fn label(&self) -> &str {
        "acme_delete"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretsStore;
    use hyperion_state::db::open_memory;
    use hyperion_types::{CertInfo, DbProvision};
    use hyperion_validate::Domain;
    use mockall::predicate::*;

    // ============================================================
    //  SPF parser unit tests (no DNS — pure CIDR / string logic).
    // ============================================================

    // ============================================================
    //  Migration bundle prune (pure-fs, no Service needed).
    // ============================================================

    // ============================================================
    //  is_worker_node — drives the services_health "hide hyperion-web
    //  as critical on workers" behavior.
    // ============================================================

    async fn svc_with_state_file(
        p: Option<std::path::PathBuf>,
    ) -> HostingService<MockAdapterPort> {
        let pool = open_memory().await.expect("memory db");
        let a = MockAdapterPort::new();
        let mut s = svc(pool, a);
        if let Some(path) = p {
            s = s.with_node_state_file(path);
        }
        s
    }

    #[tokio::test]
    async fn is_worker_node_false_when_no_state_file_configured() {
        let s = svc_with_state_file(None).await;
        assert!(!s.is_worker_node(), "missing config path → assume master");
    }

    #[tokio::test]
    async fn is_worker_node_false_when_state_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("node-id.json");
        let s = svc_with_state_file(Some(p)).await;
        assert!(!s.is_worker_node(), "path set but file absent → master");
    }

    #[tokio::test]
    async fn is_worker_node_true_when_state_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("node-id.json");
        // File present → enrolled worker. hyperion-web absence is
        // expected, not critical.
        tokio::fs::write(&p, b"{}").await.unwrap();
        let s = svc_with_state_file(Some(p)).await;
        assert!(s.is_worker_node());
    }

    // ============================================================
    //  count_profile_asset_refs — boundary handling so @asset:7
    //  doesn't accidentally match @asset:70 / @asset:777.
    // ============================================================

    fn mk_profile(plugins: &str, themes: &str) -> hyperion_state::profiles::ProfileRow {
        hyperion_state::profiles::ProfileRow {
            wp_plugins: plugins.into(),
            wp_themes: themes.into(),
            ..Default::default()
        }
    }

    #[test]
    fn count_asset_refs_basic_match() {
        let profiles = vec![mk_profile("akismet\n@asset:7\n", "")];
        assert_eq!(count_profile_asset_refs(&profiles, 7), 1);
    }

    #[test]
    fn count_asset_refs_trailing_activate_mark() {
        let profiles = vec![mk_profile("@asset:7!\n", "@asset:7\n")];
        // Two refs: one with !, one plain.
        assert_eq!(count_profile_asset_refs(&profiles, 7), 2);
    }

    #[test]
    fn count_asset_refs_boundary_rejects_prefix_match() {
        // @asset:7 should NOT match @asset:70 / @asset:777.
        let profiles = vec![mk_profile("@asset:70\n@asset:777\n@asset:7x\n", "")];
        assert_eq!(count_profile_asset_refs(&profiles, 7), 0);
    }

    #[test]
    fn count_asset_refs_inline_comment_after_ok() {
        let profiles = vec![mk_profile("@asset:7    # internal client plugin\n", "")];
        assert_eq!(count_profile_asset_refs(&profiles, 7), 1);
    }

    #[test]
    fn count_asset_refs_across_plugins_and_themes() {
        let profiles = vec![mk_profile("@asset:7\n", "@asset:7!\n")];
        assert_eq!(count_profile_asset_refs(&profiles, 7), 2);
    }

    #[test]
    fn count_asset_refs_no_match() {
        let profiles = vec![mk_profile("akismet\nwordpress-seo\n", "")];
        assert_eq!(count_profile_asset_refs(&profiles, 7), 0);
    }

    #[tokio::test]
    async fn prune_migration_bundle_dir_missing_root_is_ok() {
        // Root doesn't exist yet — should return 0, not error.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let n = prune_migration_bundle_dir(&missing, std::time::Duration::from_secs(60))
            .await
            .expect("missing root must be Ok");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn prune_migration_bundle_dir_only_touches_mig_prefix() {
        // With max_age=0, "older than now" == every dir → all
        // mig_*-prefixed dirs go, everything else stays. This
        // exercises the prefix filter without needing to forge
        // mtimes (filetime isn't in workspace deps).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mig_a = root.join("mig_aaa");
        let mig_b = root.join("mig_bbb");
        let other = root.join("keepme");
        let plain_file = root.join("README");
        for d in [&mig_a, &mig_b, &other] {
            tokio::fs::create_dir_all(d).await.unwrap();
            tokio::fs::write(d.join("archive.tar.gz"), b"x").await.unwrap();
        }
        tokio::fs::write(&plain_file, b"hi").await.unwrap();

        // Sleep ~10ms so created dirs' mtime < now() at the call
        // site — without this the cutoff check (mtime < cutoff)
        // can race and skip new dirs even with max_age=0.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let n = prune_migration_bundle_dir(root, std::time::Duration::from_millis(0))
            .await
            .unwrap();
        assert_eq!(n, 2, "both mig_* dirs should have been removed");
        assert!(!mig_a.exists());
        assert!(!mig_b.exists());
        assert!(other.exists(), "non-mig_ dirs are off-limits");
        assert!(plain_file.exists(), "loose files are off-limits");
    }

    #[tokio::test]
    async fn prune_migration_bundle_dir_respects_max_age() {
        // With a generous max_age, nothing fresh should be pruned.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mig_a = root.join("mig_fresh");
        tokio::fs::create_dir_all(&mig_a).await.unwrap();

        let n = prune_migration_bundle_dir(root, std::time::Duration::from_secs(86_400))
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(mig_a.exists());
    }

    #[test]
    fn ip4_matches_exact() {
        let ip: std::net::Ipv4Addr = "1.2.3.4".parse().unwrap();
        assert!(ip4_matches("1.2.3.4", ip));
        assert!(!ip4_matches("1.2.3.5", ip));
    }

    #[test]
    fn ip4_matches_cidr_24() {
        let ip: std::net::Ipv4Addr = "1.2.3.42".parse().unwrap();
        assert!(ip4_matches("1.2.3.0/24", ip));
        assert!(ip4_matches("1.2.3.255/24", ip));
        assert!(!ip4_matches("1.2.4.0/24", ip));
    }

    #[test]
    fn ip4_matches_cidr_edge_cases() {
        let ip: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
        // /0 matches everything
        assert!(ip4_matches("0.0.0.0/0", ip));
        // /32 is exact
        assert!(ip4_matches("10.0.0.1/32", ip));
        assert!(!ip4_matches("10.0.0.2/32", ip));
        // Malformed → false (never accidentally permissive)
        assert!(!ip4_matches("garbage", ip));
        assert!(!ip4_matches("1.2.3.4/33", ip));
        assert!(!ip4_matches("1.2.3.4/abc", ip));
    }

    #[test]
    fn stitch_dig_txt_single_segment() {
        assert_eq!(
            stitch_dig_txt("\"v=spf1 ip4:1.2.3.4 ~all\""),
            "v=spf1 ip4:1.2.3.4 ~all"
        );
    }

    #[test]
    fn stitch_dig_txt_multi_segment() {
        // Long TXT split into two quoted segments — dig prints them
        // back-to-back. The RFC says receivers concatenate as-is.
        assert_eq!(
            stitch_dig_txt("\"v=spf1 ip4:1.2.3.4 \" \"ip4:5.6.7.8 ~all\""),
            "v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 ~all"
        );
    }

    #[test]
    fn stitch_dig_txt_falls_back_to_trim_when_no_quotes() {
        assert_eq!(stitch_dig_txt("  v=spf1 ~all  "), "v=spf1 ~all");
    }

    /// SPF authorization with the previous bug's exact scenario:
    /// the operator's record lists OUR ip alongside another ip + an
    /// include — the literal string compare reported "differs",
    /// the parser must now report "matches".
    #[tokio::test]
    async fn spf_authorize_multi_ip_with_include_matches() {
        let our: std::net::Ipv4Addr = "178.105.99.35".parse().unwrap();
        let record = "v=spf1 ip4:1.2.3.4 ip4:178.105.99.35 include:_spf.google.com ~all";
        let r = check_spf_authorizes_no_recurse(record, "example.cz", our).await;
        assert!(matches!(r, SpfMatch::Match { .. }), "got {r:?}");
    }

    #[tokio::test]
    async fn spf_authorize_cidr_block_matches() {
        let our: std::net::Ipv4Addr = "10.0.0.42".parse().unwrap();
        let record = "v=spf1 ip4:10.0.0.0/24 ~all";
        let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
        assert!(matches!(r, SpfMatch::Match { .. }), "got {r:?}");
    }

    #[tokio::test]
    async fn spf_authorize_soft_all_does_not_catchall() {
        // ~all is "softfail" — anyone NOT explicitly listed above
        // is unauthorized but receivers should accept and tag. Our
        // check reports "differs" since our IP isn't in the list.
        let our: std::net::Ipv4Addr = "9.9.9.9".parse().unwrap();
        let record = "v=spf1 ip4:1.2.3.4 ~all";
        let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
        assert!(matches!(r, SpfMatch::None), "got {r:?}");
    }

    #[tokio::test]
    async fn spf_authorize_plus_all_is_catchall() {
        let our: std::net::Ipv4Addr = "9.9.9.9".parse().unwrap();
        let record = "v=spf1 +all";
        let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
        assert!(matches!(r, SpfMatch::CatchAll { .. }), "got {r:?}");
    }

    #[tokio::test]
    async fn spf_authorize_question_all_is_catchall() {
        // `?all` is "neutral" — receivers treat senders as
        // unspecified. From the operator's "does my IP pass"
        // perspective, this means anything ABOVE in the record
        // could pass without an explicit IP listing.
        let our: std::net::Ipv4Addr = "9.9.9.9".parse().unwrap();
        let record = "v=spf1 ?all";
        let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
        assert!(matches!(r, SpfMatch::CatchAll { .. }), "got {r:?}");
    }

    #[tokio::test]
    async fn spf_authorize_minus_all_does_not_catchall() {
        let our: std::net::Ipv4Addr = "9.9.9.9".parse().unwrap();
        let record = "v=spf1 -all";
        let r = check_spf_authorizes_no_recurse(record, "x.cz", our).await;
        assert!(matches!(r, SpfMatch::None), "got {r:?}");
    }

    #[tokio::test]
    async fn spf_authorize_missing_version_tag_rejected() {
        let our: std::net::Ipv4Addr = "1.2.3.4".parse().unwrap();
        // No leading "v=spf1" — not an SPF record at all.
        let r = check_spf_authorizes_no_recurse("ip4:1.2.3.4 ~all", "x.cz", our).await;
        assert!(matches!(r, SpfMatch::None), "got {r:?}");
    }

    fn req(d: &str) -> HostingCreateReq {
        HostingCreateReq {
            domain: Domain::parse(d).expect("parse"),
            aliases: vec![],
            php_version: Some(PhpVersion::V8_3),
            database: Some(DbProvision::MariaDB),
            system_user: None,
            kind: "php".into(),
            proxy_upstream_url: None,
        }
    }

    fn cert_for(d: &str) -> CertInfo {
        CertInfo {
            domain: d.into(),
            sans: vec![],
            issuer: "letsencrypt".into(),
            not_after: 1_700_000_000,
            fingerprint_sha256: "deadbeef".into(),
        }
    }

    fn db_creds() -> DbCredentials {
        DbCredentials {
            engine: DbProvision::MariaDB,
            db_name: "lm_a".into(),
            db_user: "lm_u".into(),
            password: "p".into(),
        }
    }

    fn happy_mocks() -> MockAdapterPort {
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost().returning(|_| Ok(()));
        // mockall ignores trait default impls — without an explicit
        // `expect`, calls to `redis_is_available` panic. Default-true
        // in tests so the Redis preflight in set_redis doesn't break
        // tests that don't care about the systemd-level check.
        a.expect_redis_is_available().returning(|| true);
        a
    }

    fn svc(pool: SqlitePool, a: MockAdapterPort) -> HostingService<MockAdapterPort> {
        let secrets_dir = tempfile::tempdir().expect("dir");
        let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
        HostingService::new(pool, Arc::new(a), secrets)
    }

    #[tokio::test]
    async fn create_happy_path() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        let r = s.create(req("example.cz")).await.expect("create");
        assert!(r.db.is_some());
        let detail = s
            .get(HostingSelector::Domain(
                Domain::parse("example.cz").expect("parse"),
            ))
            .await
            .expect("get");
        assert_eq!(detail.state, HostingState::Active);
        assert_eq!(detail.system_user, "example_cz");
    }

    #[tokio::test]
    async fn create_rolls_back_on_acme_failure() {
        let pool = open_memory().await.expect("open");
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue()
            .returning(|_, _| Err(AdapterError::Acme("dns".into())));
        // Expect rollbacks for the four prior steps.
        a.expect_db_drop().returning(|_, _, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_remove_hosting_tree().returning(|_| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        let r = s.create(req("example.cz")).await;
        assert!(r.is_err());
        let row = hostings::get_by_domain(&pool, "example.cz")
            .await
            .expect("query");
        match row {
            Some(r) => assert_eq!(r.state, HostingState::Failed),
            None => {}
        }
    }

    #[tokio::test]
    async fn create_rolls_back_on_nginx_failure() {
        let pool = open_memory().await.expect("open");
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost()
            .returning(|_| Err(AdapterError::Other("nginx -t failed".into())));
        a.expect_acme_delete().returning(|_| Ok(()));
        a.expect_db_drop().returning(|_, _, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_remove_hosting_tree().returning(|_| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        let r = s.create(req("example.cz")).await;
        assert!(r.is_err());
    }

    /// Regression for the field-reported bug:
    ///   1. Create test5.example.cz on a fresh node.
    ///   2. ensure_user succeeds (Linux UID 1000 allocated).
    ///   3. system_users::insert succeeds (DB row with UID 1000).
    ///   4. nginx_write_vhost fails → rollback.
    ///   5. PRE-FIX: DeleteUser removes Linux user; system_users
    ///      DB row stays. UID is now free at Linux level but
    ///      claimed at DB level.
    ///   6. Operator retries with DIFFERENT domain (different
    ///      system_user name). useradd reuses UID 1000.
    ///   7. PRE-FIX: system_users::insert(uid=1000) → UNIQUE
    ///      constraint failure. Operator stuck.
    ///   POST-FIX: DeleteSystemUsersRow rollback removes the DB
    ///   row alongside DeleteUser, so step 6 starts from a clean
    ///   DB state and the retry succeeds.
    #[tokio::test]
    async fn rollback_cleans_system_users_db_row_so_uid_can_be_reused() {
        let pool = open_memory().await.expect("open");
        // First attempt — succeeds through system_users::insert
        // then fails at nginx_write_vhost so DeleteUser +
        // DeleteSystemUsersRow rollbacks fire.
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1000));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost()
            .returning(|_| Err(AdapterError::Other("nginx bad".into())));
        a.expect_acme_delete().returning(|_| Ok(()));
        a.expect_db_drop().returning(|_, _, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_remove_hosting_tree().returning(|_| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        let _ = s.create(req("test5.example.cz")).await;
        // After rollback the system_users row MUST be gone — else
        // the next create's UNIQUE(uid) hits a phantom row.
        let leftover = system_users::get_by_uid(&pool, 1000)
            .await
            .expect("query");
        assert!(
            leftover.is_none(),
            "rollback must DELETE the system_users row, not just the Linux user — \
             otherwise UNIQUE(uid) blocks every subsequent create that gets \
             UID 1000 from useradd"
        );

        // Second attempt with a different domain — Linux freed UID
        // 1000, useradd reuses it, system_users::insert(1000) must
        // succeed (no phantom row).
        let secrets_dir = tempfile::tempdir().expect("dir");
        let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
        let mut a2 = MockAdapterPort::new();
        a2.expect_ensure_user().returning(|_, _| Ok(1000));
        a2.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a2.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a2.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a2.expect_nginx_write_vhost().returning(|_| Ok(()));
        a2.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        let s2 = HostingService {
            pool: pool.clone(),
            adapters: Arc::new(a2),
            secrets,
            paths: HostingPaths::default(),
            remote_backup: None,
            retention: BackupRetention::default(),
            slack_default_webhook: None,
            acme_contact_email: "test@example.invalid".into(),
            email_config: None,
            email_default_to: None,
            agent_config_path: None,
            update_cache: Arc::new(tokio::sync::RwLock::new(None)),
            current_git_sha: "dev-unknown".into(),
            cert_issue_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            master_rpc_signer: None,
            node_state_file: None,
            node_update: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::NodeUpdateStatus::default(),
            )),
            service_install_progress: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::ServiceInstallStatus::default(),
            )),
        };
        s2.create(req("test6.example.cz"))
            .await
            .expect("retry with different domain must succeed — DB UID 1000 is free");
    }

    /// Regression test for the user-visible bug:
    ///   1. Create example.cz — nginx_write_vhost fails partway
    ///      through provisioning.
    ///   2. Rollback runs; PRE-FIX it set state='failed' on the
    ///      hostings row, POST-FIX it DELETEs the row.
    ///   3. Create example.cz AGAIN.
    ///   4. PRE-FIX: UNIQUE(domain) constraint blocks step 3.
    ///      POST-FIX: succeeds.
    #[tokio::test]
    async fn create_after_rolled_back_failure_can_recreate_same_domain() {
        let pool = open_memory().await.expect("open");
        // First attempt — fails at nginx_write_vhost.
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(2042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost()
            .returning(|_| Err(AdapterError::Other("nginx config bad".into())));
        // Rollback adapter calls — all best-effort, fed Ok():
        a.expect_acme_delete().returning(|_| Ok(()));
        a.expect_db_drop().returning(|_, _, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_remove_hosting_tree().returning(|_| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        let _ = s.create(req("retry.cz")).await; // expected to fail
        // PRE-FIX: list would now contain a state='failed' row.
        // POST-FIX: list is empty for that domain.
        let leftover = hostings::get_by_domain(&pool, "retry.cz").await.unwrap();
        assert!(
            leftover.is_none(),
            "rollback must DELETE the row, not leave it as 'failed' — \
             otherwise UNIQUE(domain) blocks the retry"
        );

        // Second attempt — succeeds (the row is gone, no UNIQUE
        // constraint to trip).
        let secrets_dir = tempfile::tempdir().expect("dir");
        let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
        let mut a2 = MockAdapterPort::new();
        a2.expect_ensure_user().returning(|_, _| Ok(2043));
        a2.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a2.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a2.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a2.expect_nginx_write_vhost().returning(|_| Ok(()));
        a2.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        let s2 = HostingService {
            pool: pool.clone(),
            adapters: Arc::new(a2),
            secrets,
            paths: HostingPaths::default(),
            remote_backup: None,
            retention: BackupRetention::default(),
            slack_default_webhook: None,
            acme_contact_email: "test@example.invalid".into(),
            email_config: None,
            email_default_to: None,
            agent_config_path: None,
            update_cache: Arc::new(tokio::sync::RwLock::new(None)),
            current_git_sha: "dev-unknown".into(),
            cert_issue_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            master_rpc_signer: None,
            node_state_file: None,
            node_update: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::NodeUpdateStatus::default(),
            )),
            service_install_progress: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::ServiceInstallStatus::default(),
            )),
        };
        s2.create(req("retry.cz"))
            .await
            .expect("second create must succeed — the orphan row should have been deleted by rollback");
    }

    #[tokio::test]
    async fn list_returns_active_after_create() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool, happy_mocks());
        s.create(req("a.cz")).await.expect("a");
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1043));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost().returning(|_| Ok(()));
        // Replace the adapter for the second call using a fresh svc.
        let secrets_dir = tempfile::tempdir().expect("dir");
        let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
        let s2 = HostingService {
            pool: s.pool.clone(),
            adapters: Arc::new(a),
            secrets,
            paths: HostingPaths::default(),
            remote_backup: None,
            retention: BackupRetention::default(),
            slack_default_webhook: None,
            acme_contact_email: "test@example.invalid".into(),
            email_config: None,
            email_default_to: None,
            agent_config_path: None,
            update_cache: Arc::new(tokio::sync::RwLock::new(None)),
            current_git_sha: "dev-unknown".into(),
            cert_issue_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            master_rpc_signer: None,
            node_state_file: None,
            node_update: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::NodeUpdateStatus::default(),
            )),
            service_install_progress: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::ServiceInstallStatus::default(),
            )),
        };
        s2.create(HostingCreateReq {
            domain: Domain::parse("b.cz").expect("parse"),
            aliases: vec![],
            php_version: None,
            database: None,
            system_user: None,
            kind: "php".into(),
            proxy_upstream_url: None,
        })
        .await
        .expect("b");
        let rows = s.list().await.expect("list");
        assert_eq!(rows.len(), 2);
    }

    /// SHA comparison: identical full SHAs ⇒ no update.
    #[test]
    fn compare_git_shas_identical_no_update() {
        let (avail, msg) =
            compare_git_shas("abcdef0123456789abcdef0123456789abcdef01", "abcdef0123456789abcdef0123456789abcdef01");
        assert!(!avail);
        assert_eq!(msg, "up to date");
    }

    /// Mixed-length prefix match — agent compiled with 12-char short,
    /// remote returns full 40-char. Must NOT report "update available".
    #[test]
    fn compare_git_shas_prefix_match() {
        let cur = "abcdef012345"; // 12-char short
        let lat = "abcdef0123456789abcdef0123456789abcdef01"; // 40-char full
        let (avail, msg) = compare_git_shas(cur, lat);
        assert!(!avail, "12-char prefix of 40-char SHA should not flag update");
        assert_eq!(msg, "up to date");
    }

    /// Different SHAs ⇒ flag update.
    #[test]
    fn compare_git_shas_different_flags_update() {
        let (avail, msg) =
            compare_git_shas("aaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb");
        assert!(avail);
        assert_eq!(msg, "update available");
    }

    /// "dev-unknown" current ⇒ never nag the operator.
    #[test]
    fn compare_git_shas_dev_unknown_suppresses_banner() {
        let (avail, msg) = compare_git_shas("dev-unknown", "abc123def456");
        assert!(!avail);
        assert_eq!(msg, "running an unversioned dev build");
    }

    /// Empty current ⇒ same as dev-unknown.
    #[test]
    fn compare_git_shas_empty_current_suppresses_banner() {
        let (avail, _) = compare_git_shas("", "abc123def456");
        assert!(!avail);
    }

    /// Empty latest ⇒ probe-failure path, no nag.
    #[test]
    fn compare_git_shas_empty_latest_no_update() {
        let (avail, msg) = compare_git_shas("abc123", "");
        assert!(!avail);
        assert!(msg.starts_with("probe failed"));
    }

    /// Case-insensitive: GitHub's lowercase SHA vs. a mixed-case
    /// build-time embed must still match.
    #[test]
    fn compare_git_shas_case_insensitive() {
        let (avail, _) = compare_git_shas("ABCDEF012345", "abcdef012345xyz");
        assert!(!avail);
    }

    #[tokio::test]
    async fn duplicate_domain_is_already_exists() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("dup.cz")).await.expect("first ok");
        // Second create: fresh mock with the same expectations.
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1043));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        a.expect_remove_hosting_tree().returning(|_| Ok(()));
        let secrets_dir = tempfile::tempdir().expect("dir");
        let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
        let s2 = HostingService {
            pool: s.pool.clone(),
            adapters: Arc::new(a),
            secrets,
            paths: HostingPaths::default(),
            remote_backup: None,
            retention: BackupRetention::default(),
            slack_default_webhook: None,
            acme_contact_email: "test@example.invalid".into(),
            email_config: None,
            email_default_to: None,
            agent_config_path: None,
            update_cache: Arc::new(tokio::sync::RwLock::new(None)),
            current_git_sha: "dev-unknown".into(),
            cert_issue_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            master_rpc_signer: None,
            node_state_file: None,
            node_update: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::NodeUpdateStatus::default(),
            )),
            service_install_progress: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::ServiceInstallStatus::default(),
            )),
        };
        let r = s2.create(req("dup.cz")).await;
        match r {
            Err(RpcError::AlreadyExists { kind, .. }) => assert_eq!(kind, "hosting"),
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    fn suspend_mocks() -> MockAdapterPort {
        let mut a = happy_mocks();
        a.expect_nginx_apply_suspended().returning(|_, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_db_lock().returning(|_, _| Ok(()));
        a.expect_linux_lock_login().returning(|_| Ok(()));
        a.expect_kill_user_procs().returning(|_| Ok(()));
        a
    }

    fn resume_mocks() -> MockAdapterPort {
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_write_vhost().returning(|_| Ok(()));
        a.expect_nginx_apply_suspended().returning(|_, _| Ok(()));
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_db_lock().returning(|_, _| Ok(()));
        a.expect_linux_lock_login().returning(|_| Ok(()));
        a.expect_kill_user_procs().returning(|_| Ok(()));
        a.expect_linux_unlock_login().returning(|_| Ok(()));
        a.expect_db_unlock().returning(|_, _| Ok(()));
        a.expect_apply_php_limits()
            .returning(|_, _, _, _, _, _, _| Ok(()));
        a
    }

    #[tokio::test]
    async fn suspend_sets_state_and_writes_suspension_row() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), suspend_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        s.suspend(
            sel.clone(),
            hyperion_types::SuspendReason::Manual {
                message: Some("over quota".into()),
            },
        )
        .await
        .expect("suspend");
        let detail = s.get(sel).await.expect("get");
        assert_eq!(detail.state, HostingState::Suspended);
        let row = hyperion_state::limits::get_suspension(&pool, &detail.id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(row.suspended_by, "manual");
        assert_eq!(row.reason_message.as_deref(), Some("over quota"));
    }

    #[tokio::test]
    async fn suspend_is_idempotent_for_already_suspended() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), suspend_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        s.suspend(sel.clone(), hyperion_types::SuspendReason::Expired)
            .await
            .expect("first");
        // Second call is a no-op; no extra adapter calls beyond what
        // suspend_mocks already allows. Should succeed.
        s.suspend(sel, hyperion_types::SuspendReason::Expired)
            .await
            .expect("idempotent");
    }

    #[tokio::test]
    async fn suspend_refuses_when_already_deleting() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), suspend_mocks());
        let created = s.create(req("ex.cz")).await.expect("create");
        // Force into 'deleting' directly.
        hyperion_state::hostings::set_state(&pool, &created.id, HostingState::Deleting, now_secs())
            .await
            .expect("set");
        let sel = HostingSelector::Id(created.id.clone());
        let r = s
            .suspend(sel, hyperion_types::SuspendReason::Manual { message: None })
            .await;
        match r {
            Err(RpcError::Conflict { .. }) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resume_brings_back_to_active() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), resume_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        s.suspend(sel.clone(), hyperion_types::SuspendReason::Expired)
            .await
            .expect("suspend");
        s.resume(sel.clone()).await.expect("resume");
        let detail = s.get(sel).await.expect("get");
        assert_eq!(detail.state, HostingState::Active);
        let susp = hyperion_state::limits::get_suspension(&pool, &detail.id)
            .await
            .expect("get");
        assert!(susp.is_none(), "suspension row removed on resume");
    }

    #[tokio::test]
    async fn set_limits_clamps_and_persists() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_apply_php_limits()
            .returning(|_, _, _, _, _, _, _| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        let mut l = hyperion_types::HostingLimits::defaults();
        l.php_memory_mb = 100_000; // nonsense
        l.php_max_children = 0; // nonsense
        let stored = s.set_limits(sel.clone(), l).await.expect("set");
        assert_eq!(stored.php_memory_mb, 8192, "clamped to upper bound");
        assert_eq!(stored.php_max_children, 1, "clamped to lower bound");
        // Round-trip via get_limits
        let l2 = s.get_limits(sel).await.expect("get");
        assert_eq!(l2, stored);
    }

    #[tokio::test]
    async fn get_limits_defaults_when_no_row() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        let l = s.get_limits(sel).await.expect("get");
        assert_eq!(l, hyperion_types::HostingLimits::defaults());
    }

    /// Happy path: switching from PHP 8.3 (req() default) to 8.4
    /// flips the DB row + the agent's view of php_version on get().
    /// We don't try to assert mockall expectation counts here (the
    /// interaction between happy_mocks's catchall and a withf-
    /// constrained one is order-dependent and brittle) — outcome
    /// is the source of truth, which is what an operator observes.
    #[tokio::test]
    async fn set_php_version_happy_path() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        a.expect_apply_php_limits()
            .returning(|_, _, _, _, _, _, _| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        // Confirm starting state.
        let before = s.get(sel.clone()).await.expect("get pre");
        assert_eq!(before.php_version, Some(PhpVersion::V8_3));

        let v = s
            .set_php_version(sel.clone(), PhpVersion::V8_4)
            .await
            .expect("switch");
        assert_eq!(v, PhpVersion::V8_4);
        let after = s.get(sel).await.expect("get post");
        assert_eq!(after.php_version, Some(PhpVersion::V8_4));
    }

    /// Switching to the SAME version returns Ok(version) and leaves
    /// the row untouched — operator can click without churn.
    #[tokio::test]
    async fn set_php_version_noop_when_unchanged() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_fpm_delete().returning(|_, _| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        // req() defaults to PhpVersion::V8_3.
        let v = s
            .set_php_version(sel.clone(), PhpVersion::V8_3)
            .await
            .expect("noop");
        assert_eq!(v, PhpVersion::V8_3);
        let after = s.get(sel).await.expect("get");
        assert_eq!(after.php_version, Some(PhpVersion::V8_3));
    }

    /// Filesystem WP-detection happy path: both wp-config.php and
    /// wp-includes/version.php present with a parseable
    /// `$wp_version` line → returns Some(<version>).
    #[tokio::test]
    async fn detect_wp_install_on_disk_finds_version() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(root.join("wp-config.php"), b"<?php /* fake */ ?>").unwrap();
        std::fs::create_dir_all(root.join("wp-includes")).unwrap();
        std::fs::write(
            root.join("wp-includes/version.php"),
            b"<?php\n\
              // The WordPress version string.\n\
              $wp_version = '6.4.2';\n\
              $wp_db_version = 56657;\n",
        )
        .unwrap();
        let got = super::detect_wp_install_on_disk(root.to_str().unwrap()).await;
        assert_eq!(got, Some("6.4.2".to_string()));
    }

    /// Missing wp-config.php → no WP, no fake.
    #[tokio::test]
    async fn detect_wp_install_on_disk_returns_none_when_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let got = super::detect_wp_install_on_disk(tmp.path().to_str().unwrap()).await;
        assert_eq!(got, None);
    }

    /// wp-config.php present but wp-includes/version.php missing —
    /// partial install state. Don't fake a version; let the
    /// operator's install button stay available to recover it.
    #[tokio::test]
    async fn detect_wp_install_on_disk_returns_none_on_partial_install() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("wp-config.php"), b"<?php ?>").unwrap();
        let got = super::detect_wp_install_on_disk(tmp.path().to_str().unwrap()).await;
        assert_eq!(got, None);
    }

    /// version.php exists but $wp_version line is missing /
    /// malformed → return Some("unknown") to honestly reflect
    /// "WP is here but we can't tell which version".
    #[tokio::test]
    async fn detect_wp_install_on_disk_handles_unknown_version() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(root.join("wp-config.php"), b"<?php ?>").unwrap();
        std::fs::create_dir_all(root.join("wp-includes")).unwrap();
        std::fs::write(
            root.join("wp-includes/version.php"),
            b"<?php\n// no $wp_version line here\n",
        )
        .unwrap();
        let got = super::detect_wp_install_on_disk(root.to_str().unwrap()).await;
        assert_eq!(got, Some("unknown".to_string()));
    }

    /// Comment that mentions `$wp_version` but isn't the actual
    /// directive must NOT be parsed as the version.
    #[tokio::test]
    async fn detect_wp_install_on_disk_skips_commented_version() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(root.join("wp-config.php"), b"<?php ?>").unwrap();
        std::fs::create_dir_all(root.join("wp-includes")).unwrap();
        std::fs::write(
            root.join("wp-includes/version.php"),
            b"<?php\n\
              // $wp_version = '5.0.0'; // old comment\n\
              $wp_version = '6.5';\n",
        )
        .unwrap();
        let got = super::detect_wp_install_on_disk(root.to_str().unwrap()).await;
        assert_eq!(got, Some("6.5".to_string()));
    }

    /// End-to-end: a hosting WITHOUT a wp_installs row but WITH
    /// wp-config + version.php on disk must surface as Some(status)
    /// via `wp_status()`, and a second call must hit the DB
    /// directly (self-heal upsert succeeded).
    #[tokio::test]
    async fn wp_status_filesystem_fallback_self_heals() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("wpfs.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("wpfs.cz").unwrap());
        let detail = s.get(sel.clone()).await.expect("get");

        // Materialise WP files in a writable tempdir and re-point
        // the hostings row at it. The mock's default root_dir is
        // `/home/<user>/...` which isn't writable in CI.
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(root.join("wp-config.php"), b"<?php ?>").unwrap();
        std::fs::create_dir_all(root.join("wp-includes")).unwrap();
        std::fs::write(
            root.join("wp-includes/version.php"),
            b"<?php\n$wp_version = '6.4.2';\n",
        )
        .unwrap();
        sqlx::query("UPDATE hostings SET root_dir = ? WHERE id = ?")
            .bind(root.to_str().unwrap())
            .bind(detail.id.as_str())
            .execute(&pool)
            .await
            .expect("repoint root_dir");

        // First call should detect + self-heal.
        let first = s.wp_status(sel.clone()).await.expect("first wp_status");
        let first = first.expect("must detect WP");
        assert_eq!(first.wp_version, "6.4.2");

        // Second call must come from the DB row that was just
        // written. We assert by removing the on-disk files and
        // expecting the status to still come back.
        std::fs::remove_dir_all(root).ok();
        let second = s.wp_status(sel.clone()).await.expect("second wp_status");
        let second = second.expect("DB row must survive disk removal");
        assert_eq!(second.wp_version, "6.4.2");
    }

    /// Static / proxy / redirect hostings have no PHP — the change
    /// must be rejected with a Conflict explaining why.
    #[tokio::test]
    async fn set_php_version_rejects_non_php_hosting() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        // Build a static hosting (php_version = None, kind = static).
        let mut r = req("static.cz");
        r.php_version = None;
        r.kind = "static".into();
        r.database = None;
        s.create(r).await.expect("create static");
        let sel = HostingSelector::Domain(Domain::parse("static.cz").unwrap());
        let err = s
            .set_php_version(sel, PhpVersion::V8_4)
            .await
            .expect_err("must reject");
        // We only need the variant, not the exact wording — the
        // message is operator-facing and may evolve.
        assert!(matches!(err, RpcError::Conflict { .. }), "got: {err:?}");
    }

    #[tokio::test]
    async fn set_expiry_schedules_actions_and_clear_cancels() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
        let exp = now_secs() + 2 * 86_400;
        let mut e = hyperion_types::HostingExpiry::defaults();
        e.expires_at = Some(exp);
        e.grace_days = 7;
        e.owner_email = Some("k@x.cz".into());
        let stored = s.set_expiry(sel.clone(), e).await.expect("set");
        assert_eq!(stored.expires_at, Some(exp));
        assert_eq!(stored.grace_days, 7);

        let due_far_future = hyperion_state::scheduler::pending_due(&pool, exp + 100 * 86_400, 100)
            .await
            .expect("pending");
        let actions: Vec<&str> = due_far_future.iter().map(|a| a.action.as_str()).collect();
        assert!(actions.contains(&"suspend_expired"));
        assert!(actions.contains(&"delete_expired"));
        assert!(actions.contains(&"notify_1d"));

        s.clear_expiry(sel).await.expect("clear");
        let after = hyperion_state::scheduler::pending_due(&pool, exp + 100 * 86_400, 100)
            .await
            .expect("pending");
        assert!(after.is_empty(), "actions canceled");
    }

    #[tokio::test]
    async fn scheduler_tick_runs_suspend_for_expired_hosting() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), suspend_mocks());
        s.create(req("ex.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());

        let past = now_secs() - 86_400;
        let mut e = hyperion_types::HostingExpiry::defaults();
        e.expires_at = Some(past);
        s.set_expiry(sel.clone(), e).await.expect("set");
        let processed = s.scheduler_tick().await.expect("tick");
        assert!(processed >= 1, "processed: {processed}");

        let detail = s.get(sel).await.expect("get");
        assert_eq!(detail.state, HostingState::Suspended);
    }

    #[tokio::test]
    async fn upcoming_expiries_filters_by_window() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("a.cz")).await.expect("a");
        let sel = HostingSelector::Domain(Domain::parse("a.cz").unwrap());
        let exp = now_secs() + 10 * 86_400;
        let mut e = hyperion_types::HostingExpiry::defaults();
        e.expires_at = Some(exp);
        s.set_expiry(sel, e).await.expect("set");

        let within_5d = s.upcoming_expiries(5 * 86_400).await.expect("up");
        assert!(within_5d.is_empty(), "10d > 5d window");

        let within_30d = s.upcoming_expiries(30 * 86_400).await.expect("up");
        assert_eq!(within_30d.len(), 1);
        assert_eq!(within_30d[0].domain, "a.cz");
    }

    /// Regression test for the "every LE cert silently expires at day
    /// 90" finding. Three certs are seeded in the DB; the renewal tick
    /// is invoked with a `now` that pretends the clock has jumped 80
    /// days forward. Only the Let's Encrypt cert that lands inside the
    /// 30-day window should be picked up. The actual ACME call fails
    /// fast in the test env (placeholder contact email triggers
    /// `issue_real_cert`'s validation guard), so the `Failed` outcome
    /// is the load-bearing signal that renewal was *attempted* for
    /// that domain — and only for that domain.
    #[tokio::test]
    async fn cert_renew_tick_attempts_renewal_for_expiring_letsencrypt_only() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        // Hosting must exist for `issue_real_cert` to fetch its detail.
        s.create(req("renewable.cz")).await.expect("create");

        let now = now_secs();
        // Pretend 80 days have passed since boot.
        let later = now + 80 * 86_400;

        // renewable.cz : LE,         expires 10d  after `later` → inside window
        // fresh.cz     : LE,         expires 60d  after `later` → outside window
        // bootstrap.cz : self-signed, expires 10d after `later` → wrong issuer
        certificates::upsert(
            &pool,
            "renewable.cz",
            now,
            later + 10 * 86_400,
            "/cert",
            "/key",
            "letsencrypt",
        )
        .await
        .expect("upsert renewable");
        certificates::upsert(
            &pool,
            "fresh.cz",
            now,
            later + 60 * 86_400,
            "/cert",
            "/key",
            "letsencrypt",
        )
        .await
        .expect("upsert fresh");
        certificates::upsert(
            &pool,
            "bootstrap.cz",
            now,
            later + 10 * 86_400,
            "/cert",
            "/key",
            "self-signed",
        )
        .await
        .expect("upsert bootstrap");

        let results = s
            .cert_renew_tick(later, CERT_RENEWAL_WINDOW_DAYS)
            .await
            .expect("tick");

        assert_eq!(
            results.len(),
            1,
            "exactly one LE cert in the renewal window"
        );
        assert_eq!(results[0].domain, "renewable.cz");
        assert!(
            matches!(results[0].outcome, CertRenewOutcome::Failed { .. }),
            "expected Failed renewal in test env (no real ACME), got {:?}",
            results[0].outcome
        );
    }

    /// Empty-DB sanity check: the renewal tick on a fresh agent
    /// returns an empty result vec, doesn't panic, doesn't audit.
    #[tokio::test]
    async fn cert_renew_tick_with_no_certs_returns_empty() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        let r = s.cert_renew_tick(now_secs(), 30).await.expect("tick");
        assert!(r.is_empty());
    }

    // ───────── set_vhost_options ─────────

    fn vh_defaults() -> hyperion_types::VhostOptions {
        hyperion_types::VhostOptions::default()
    }

    #[tokio::test]
    async fn set_vhost_options_rejects_oversized_hsts() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let mut opts = vh_defaults();
        opts.hsts_max_age = 100_000_000; // > 2y → reject
        let r = s.set_vhost_options(sel, opts, None).await;
        assert!(r.is_err(), "expected validation error");
        let e = r.unwrap_err();
        assert!(format!("{e}").contains("hsts_max_age"));
    }

    #[tokio::test]
    async fn set_vhost_options_rejects_bad_redirect_url() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let mut opts = vh_defaults();
        // Missing scheme.
        opts.redirect_url = "new.example.cz".into();
        let r = s.set_vhost_options(sel, opts, None).await;
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("redirect_url"));
    }

    #[tokio::test]
    async fn set_vhost_options_rejects_bad_redirect_code() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let mut opts = vh_defaults();
        opts.redirect_code = 418; // ☕
        let r = s.set_vhost_options(sel, opts, None).await;
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("redirect_code"));
    }

    #[tokio::test]
    async fn set_vhost_options_rejects_basic_auth_without_username() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let mut opts = vh_defaults();
        opts.basic_auth_enabled = true;
        opts.basic_auth_user = "  ".into(); // whitespace-only
        let r = s.set_vhost_options(sel, opts, Some("hunter2".into())).await;
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("basic_auth_user"));
    }

    #[tokio::test]
    async fn set_vhost_options_rejects_oversized_snippet() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let mut opts = vh_defaults();
        opts.custom_nginx_snippet = "x".repeat(33 * 1024);
        let r = s.set_vhost_options(sel, opts, None).await;
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("custom_nginx_snippet"));
    }

    #[tokio::test]
    async fn set_vhost_options_default_ttl_when_cache_on() {
        // Operator turned on FastCGI cache but didn't set TTL → 300s default.
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_nginx_write_htpasswd().returning(|_, _, _| Ok(()));
        a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let mut opts = vh_defaults();
        opts.fastcgi_cache_enabled = true;
        let r = s.set_vhost_options(sel, opts, None).await.expect("apply");
        assert_eq!(r.fastcgi_cache_ttl, 300);
    }

    #[tokio::test]
    async fn set_vhost_options_writes_htpasswd_when_password_supplied() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_nginx_write_htpasswd()
            .withf(|hid, user, hash| {
                !hid.is_empty() && user == "preview" && hash.starts_with("$2")
            })
            .returning(|_, _, _| Ok(()));
        a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let mut opts = vh_defaults();
        opts.basic_auth_enabled = true;
        opts.basic_auth_user = "preview".into();
        let r = s
            .set_vhost_options(sel, opts, Some("hunter2!".into()))
            .await
            .expect("apply");
        assert!(r.basic_auth_set);
    }

    // ───────── WP debug + Redis ─────────

    #[tokio::test]
    async fn set_wp_debug_writes_through_to_adapter() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_wp_set_debug()
            .withf(|user, _htdocs, enabled, log, display| {
                user == "example_cz" && *enabled && *log && !*display
            })
            .times(1)
            .returning(|_, _, _, _, _| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let r = s.set_wp_debug(sel, true, true, false).await.expect("set");
        assert!(r.wp_debug_enabled);
        assert!(r.wp_debug_log);
        assert!(!r.wp_debug_display);
    }

    #[tokio::test]
    async fn set_redis_provisions_acl_writes_wp_config_persists() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        // First enable: ACL + wp config write.
        a.expect_redis_ensure_acl()
            .withf(|user, _pw, db| user.starts_with("r_") && *db == 0)
            .times(1)
            .returning(|_, _, _| Ok(()));
        a.expect_wp_set_redis()
            .withf(|_, _, cfg| cfg.is_some())
            .times(1)
            .returning(|_, _, _| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let r = s.set_redis(sel, true).await.expect("enable");
        assert!(r.redis_enabled);
        assert_eq!(r.redis_db_number, Some(0)); // first free slot
        assert!(r.redis_password_set);
    }

    #[tokio::test]
    async fn set_redis_disable_cleans_up() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_redis_ensure_acl().returning(|_, _, _| Ok(()));
        a.expect_wp_set_redis().returning(|_, _, _| Ok(()));
        a.expect_redis_delete_acl()
            .withf(|user| user.starts_with("r_"))
            .times(1)
            .returning(|_| Ok(()));
        let s = svc(pool.clone(), a);
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        // Enable then disable.
        s.set_redis(sel.clone(), true).await.expect("enable");
        let r = s.set_redis(sel, false).await.expect("disable");
        assert!(!r.redis_enabled);
        assert!(r.redis_db_number.is_none());
    }

    #[tokio::test]
    async fn rotate_redis_password_rejects_when_redis_off() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let r = s.rotate_redis_password(sel).await;
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("not enabled"));
    }

    #[tokio::test]
    async fn redis_username_for_is_stable_and_short() {
        let u1 = redis_username_for("01HVXXXXXXYYY");
        let u2 = redis_username_for("01HVXXXXXXYYY"); // same → same
        assert_eq!(u1, u2);
        assert_eq!(u1, "r_01hvxxxx"); // 8 chars + r_ prefix, lowercased
        assert!(u1.len() <= 12);
    }

    #[tokio::test]
    async fn set_vhost_options_rollback_on_nginx_failure() {
        let pool = open_memory().await.expect("open");
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_, _| Ok(1042));
        a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
        a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
        a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
        a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
        a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
        // First nginx_write_vhost (during create) succeeds, second
        // (during set_vhost_options) fails → service should roll back
        // the DB options to the previous defaults.
        let mut seq = mockall::Sequence::new();
        a.expect_nginx_write_vhost()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(()));
        a.expect_nginx_write_vhost()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Err(AdapterError::Other("nginx: emerg: invalid".into())));
        let s = svc(pool.clone(), a);
        s.create(req("example.cz")).await.expect("create");
        let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let mut opts = vh_defaults();
        opts.maintenance_mode = true;
        opts.hsts_max_age = 31_536_000;
        let r = s.set_vhost_options(sel.clone(), opts, None).await;
        assert!(r.is_err(), "expected nginx rejection");
        // DB should be back to defaults.
        let detail_back = s.get(sel).await.expect("get");
        assert!(!detail_back.vhost_options.maintenance_mode);
        assert_eq!(detail_back.vhost_options.hsts_max_age, 0);
    }

    /// classify_image_kind drives the auto-fix UX: snap/overlay
    /// images can NOT be made writable, so the diagnose card must
    /// surface "this image is immutable, switch to standard Debian"
    /// instead of pointlessly suggesting `mount -o remount,rw`.
    /// Guard the heuristic against silent regressions.
    #[test]
    fn classify_image_kind_signatures() {
        // Real-world fingerprints from /proc/mounts.
        assert_eq!(classify_image_kind("ext4", "squashfs"), "snap-managed");
        assert_eq!(classify_image_kind("squashfs", "ext4"), "snap-managed");
        assert_eq!(classify_image_kind("overlay", ""), "overlay-immutable");
        assert_eq!(classify_image_kind("ext4", ""), "standard");
        assert_eq!(classify_image_kind("xfs", ""), "standard");
        assert_eq!(classify_image_kind("btrfs", ""), "standard");
        // Genuinely unknown filesystem → "unknown" (NOT "standard");
        // the renderer downgrades guidance so we don't tell the
        // operator to remount something we don't understand.
        assert_eq!(classify_image_kind("zfs", ""), "unknown");
        assert_eq!(classify_image_kind("", ""), "unknown");
    }

    /// human_bytes feeds the disk-warning banner — round-trip
    /// readability matters because operators read these numbers
    /// off a dashboard and act on them. Boundary at the 1024
    /// flip from KiB→MiB→GiB→TiB.
    #[test]
    fn human_bytes_picks_right_unit() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(human_bytes(2_500_000_000), "2.3 GiB");
        assert_eq!(human_bytes(2 * 1024i64.pow(4)), "2.0 TiB");
    }
}
