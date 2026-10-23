//! `HostingService` — the orchestrator. Single-node, no transport.

use crate::letters::{render_template, LetterCatalog, LetterLang};
use async_trait::async_trait;
use hyperion_adapters::integrity;
use hyperion_adapters::rollback::{Rollback, RollbackStack};
use hyperion_adapters::AdapterError;
use hyperion_rpc::codec::CareReportMail;
use hyperion_rpc::wire::{
    DbCredentials, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
};
use hyperion_rpc::RpcError;
use hyperion_state::{
    certificates, databases, hostings, metrics, packages, profiles, system_users, wordpress,
};
use hyperion_types::package::{
    CareBackups, CareIntegrity, CareReport, CareUptime, CareUsage, CrsPin, ReportCadence,
};
use hyperion_types::report_sections::{ReportOmit, ReportSection};
use hyperion_types::{
    now_secs, BackupCadence, CertInfo, CertIssueRequest, CertRenewOutcome, CertRenewResult,
    ClusterStats, DashboardAlert, DbProvision, DbSummary, DnsCheckResult, FeatureToggle,
    FtpCheckItem, FtpCheckReport, HostingDetail, HostingId, HostingPackage, HostingProfile,
    HostingState, HostingStats, HostingSummary, LiveFeatureState, NodeStats, PackageFeatures,
    PackageInput, PackagePriorState, PhpVersion, ProfileApply, ProfileInput, SecretId,
    ServicePackage, WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::{Domain, SystemUserName};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;

mod acme_dns;
mod audit;
mod auth;
mod backups;
mod billing;
mod care_packages;
mod care_report;
mod certs;
mod cluster;
mod config;
mod cron;
mod dashboard;
mod database;
mod dkim;
mod files;
mod firewall;
mod fs_health;
mod fs_util;
mod ftp;
mod geoip;
mod git_sync;
mod hosting_profiles;
mod jobs;
mod kv_expiry;
mod letters;
mod limits;
mod login_lock;
mod mail;
mod migration;
mod monitor;
mod net;
mod node_config;
mod nodes;
mod notify;
mod offsite;
mod os_updates;
mod panel;
mod permissions;
mod php_runtimes;
mod protection;
mod provision;
mod quota;
mod rollback;
mod scheduler;
mod site_check;
mod site_config;
mod snapshots;
mod staging;
mod stats;
mod system;
mod trash;
mod users;
mod wp;
mod wp_assets;
mod wp_integrity;
mod wp_mail;
mod wp_updates;

use backups::*;
use billing::*;
#[cfg(test)]
use care_packages::*;
pub use care_report::*;
#[cfg(test)]
use certs::*;
pub(crate) use config::*;
#[cfg(test)]
use cron::*;
use dashboard::*;
use firewall::*;
use fs_health::*;
use fs_util::*;
use git_sync::*;
#[cfg(test)]
use hosting_profiles::*;
pub use letters::*;
use limits::*;
use login_lock::*;
use mail::*;
use migration::*;
#[cfg(test)]
use monitor::*;
pub use net::*;
#[cfg(test)]
use nodes::*;
pub use notify::*;
pub(crate) use offsite::*;
use os_updates::*;
pub use permissions::*;
use protection::*;
pub(crate) use quota::*;
use rollback::*;
#[cfg(test)]
use site_check::*;
#[cfg(test)]
use site_config::*;
pub(crate) use snapshots::*;
pub use stats::*;
pub use system::*;
use trash::*;
pub(crate) use wp::*;
use wp_assets::*;
use wp_integrity::*;
use wp_mail::*;
pub(crate) use wp_updates::*;

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
        aliases: Vec<String>,
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
    ///
    /// Only for lifting a suspension recorded before logins were disabled by
    /// account expiry — see `apply_login_policy`. New locks never use it.
    async fn linux_lock_login(&self, name: &str) -> Result<(), AdapterError>;
    async fn linux_unlock_login(&self, name: &str) -> Result<(), AdapterError>;

    /// A login's account-expiry field as shadow stores it (`""` = never).
    /// `Ok(None)` when the account does not exist.
    async fn linux_login_expiry(&self, login: &str) -> Result<Option<String>, AdapterError>;
    /// Set a login's account-expiry field (`"1"` disables every login; a value
    /// from `linux_login_expiry` puts it back). A missing account is success.
    async fn linux_set_login_expiry(&self, login: &str, expiry: &str) -> Result<(), AdapterError>;

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

    /// Read whether a site accepts public sign-ups, and what role they get.
    async fn wp_registration_get(
        &self,
        system_user: &str,
        htdocs: &str,
    ) -> Result<hyperion_types::WpRegistrationView, AdapterError>;

    /// Open or close public sign-ups.
    async fn wp_registration_set(
        &self,
        system_user: &str,
        htdocs: &str,
        open: bool,
    ) -> Result<(), AdapterError>;

    /// `wp theme list --format=json` — parallel to wp_plugin_list.
    /// Returns the theme table + the core version string.
    async fn wp_theme_list(
        &self,
        system_user: &str,
        htdocs: &str,
    ) -> Result<(Vec<hyperion_types::WpTheme>, String), AdapterError>;

    /// `wp core check-update` — core releases on offer, newest first. An
    /// error means "not checked", which callers must never read as current.
    async fn wp_core_check_update(
        &self,
        system_user: &str,
        htdocs: &str,
    ) -> Result<Vec<hyperion_types::WpCoreUpdate>, AdapterError>;

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
    async fn wp_debug_log_size(&self, htdocs: &str) -> Result<i64, AdapterError>;

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

    // ─── Setup wizard: machine-level changes ─────────────────────────
    // The defaults touch nothing, so test and dev-panel adapters do not have
    // to: installs "start" and never progress, hostname and time zone
    // "apply" without effect. The real adapter overrides every one.

    /// Start `components.sh` as `hyperion-setup-stack.service`.
    async fn setup_stack_start(
        &self,
        _spec: &hyperion_adapters::setup_stack::JobSpec,
    ) -> Result<(), AdapterError> {
        Ok(())
    }
    /// Read the setup install job back from disk + systemd.
    async fn setup_stack_status(&self) -> hyperion_adapters::setup_stack::JobStatus {
        hyperion_adapters::setup_stack::JobStatus {
            spec: None,
            state: hyperion_adapters::setup_stack::JobState::Never,
            progress: Vec::new(),
            log_tail: String::new(),
        }
    }
    /// Is the setup install or a node update holding the package manager?
    async fn package_job_running(&self) -> bool {
        false
    }
    async fn current_hostname(&self) -> String {
        String::new()
    }
    async fn current_timezone(&self) -> String {
        String::new()
    }
    async fn apply_hostname(&self, _fqdn: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn apply_timezone(&self, _tz: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    /// Restart hyperion-agent a few seconds from now, after the current
    /// reply has gone out.
    fn schedule_self_restart(&self) {}

    /// What this node's ModSecurity engine looks like (files only; the
    /// service fills in the site count). Default: no engine.
    async fn modsec_status(&self) -> hyperion_types::crs::ModsecStatus {
        hyperion_types::crs::ModsecStatus::default()
    }

    /// Install the ModSecurity connector and the Core Rule Set.
    async fn modsec_install(&self) -> Result<(), AdapterError> {
        Err(AdapterError::Other(
            "installing ModSecurity is not supported here".into(),
        ))
    }

    /// Load (`need`) or unload the rule set at http level, `nginx -t` +
    /// reload included. Returns whether anything changed.
    async fn modsec_sync_http(&self, _need: bool) -> Result<bool, AdapterError> {
        Ok(false)
    }
}

/// Live state of the panel-vhost ACME issuance.
#[derive(Debug, Clone)]
pub struct PanelProgress {
    /// Hostname the operator picked, e.g. "panel.example.cz".
    pub hostname: String,
    /// "self-signed" — bootstrap cert only, ACME not started yet
    /// "issuing"     — ACME flow running (HTTP-01 challenge)
    /// "issued"      — real cert from Let's Encrypt is now serving
    /// "failed"      — ACME flow errored; `message` carries the reason
    pub stage: String,
    /// Free-form human description of the current step, e.g.
    /// "DNS validated, ordering certificate…" or the error reason.
    pub message: String,
    /// Wall-clock seconds since UNIX epoch when this state was set.
    /// Drives the elapsed-time display in the progress card.
    pub started_at: i64,
    /// Set only when `stage = "issued"` — the cert's not_after, so
    /// the UI can show "real cert · valid until …".
    pub not_after: i64,
}

/// Tunables for the native brute-force scanner, sourced from agent.toml's
/// `[fail2ban]` section. Every default reproduces the historical hardcoded
/// behaviour, so an operator who never touches the section sees no change.
///
/// `PartialEq` so a caller can compare what agent.toml says against
/// `sanitized()` — the settings UI uses that to tell the operator when the
/// numbers in the file are not the numbers the scanner is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail2banConfig {
    /// Master switch. `false` makes `fail2ban_tick` a no-op (manual bans and
    /// boot re-apply still work).
    pub enabled: bool,
    /// Look-back window applied to every log / journal source, in seconds.
    pub window_secs: i64,
    /// Ban duration for a first offence, in seconds.
    pub ban_ttl_secs: i64,
    /// Ban duration for a repeat offender (an IP with a prior ban inside
    /// `repeat_lookback_secs`), in seconds.
    pub repeat_ttl_secs: i64,
    /// How far back to look for a prior ban when deciding "repeat offender".
    pub repeat_lookback_secs: i64,
    /// Failures-within-window thresholds, per source.
    pub http_threshold: u32, // POST /wp-login.php | /xmlrpc.php floods
    pub ssh_threshold: u32,
    pub ftp_threshold: u32,
    pub mail_threshold: u32,
    /// Ban-counted WAF refusals inside the window before a ban (per site).
    /// Higher than the login thresholds: one page of a vulnerability scan is
    /// already a dozen refusals, and a single refusal proves little.
    pub waf_threshold: u32,
}

impl Default for Fail2banConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 600,
            ban_ttl_secs: 3600,
            repeat_ttl_secs: 24 * 3600,
            repeat_lookback_secs: 24 * 3600,
            http_threshold: 12,
            ssh_threshold: 8,
            ftp_threshold: 8,
            mail_threshold: 8,
            waf_threshold: 20,
        }
    }
}

impl Fail2banConfig {
    /// Clamp operator-supplied values to sane floors. A `[fail2ban]` typo
    /// like `ban_ttl_secs = 0` must never become a *permanent* node-wide
    /// ban (ban_add treats ttl ≤ 0 as no-expiry), and a `0` threshold must
    /// not mean "ban on the first observed failure". Called once when the
    /// agent builds its config.
    pub fn sanitized(mut self) -> Self {
        self.window_secs = self.window_secs.max(1);
        // TTLs of 0 / negative would persist as a permanent ban — floor at
        // a minute so a bad value is short-lived, not forever.
        self.ban_ttl_secs = self.ban_ttl_secs.max(60);
        self.repeat_ttl_secs = self.repeat_ttl_secs.max(self.ban_ttl_secs);
        self.repeat_lookback_secs = self.repeat_lookback_secs.max(0);
        // A threshold of 0 would ban any IP with a single failure line
        // (the count map only ever holds counts ≥ 1). Floor at 2.
        self.http_threshold = self.http_threshold.max(2);
        self.ssh_threshold = self.ssh_threshold.max(2);
        self.ftp_threshold = self.ftp_threshold.max(2);
        self.mail_threshold = self.mail_threshold.max(2);
        self.waf_threshold = self.waf_threshold.clamp(3, 1000);
        self
    }
}

pub struct HostingService<A: AdapterPort + 'static> {
    pub pool: SqlitePool,
    pub adapters: Arc<A>,
    pub secrets: Arc<crate::SecretsStore>,
    pub paths: HostingPaths,
    pub remote_backup: Option<RemoteBackupConfig>,
    pub retention: BackupRetention,
    /// Take a content-addressed snapshot before anything changes a site.
    ///
    /// Node-wide, from `[snapshots] enabled`, and ON by default — but it
    /// does nothing at all unless restic is installed, so an install that
    /// has never heard of the feature is unaffected.
    pub snapshots_enabled: bool,
    /// Which engine this node uses. See [`hyperion_types::ProtectionMode`].
    pub protection_mode: hyperion_types::ProtectionMode,
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
    /// Brute-force scanner tunables (agent.toml `[fail2ban]`).
    pub fail2ban: Fail2banConfig,
    /// Node-wide switch for the permission self-repair (agent.toml
    /// `[permissions] enabled`). Default true.
    pub permissions_autoheal: bool,
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
    /// Live state of the panel-vhost ACME issuance — drives the
    /// progress card on /settings/panel#panel-domain. None ⇒ no panel hostname
    /// configured (or agent just started and hasn't checked yet).
    /// Updated by `panel_provision` + its background ACME task.
    pub panel_progress: Arc<tokio::sync::RwLock<Option<PanelProgress>>>,
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
    /// In-memory state of the most-recent / in-progress
    /// service-install job (apt-get install + systemctl enable
    /// for a whitelisted unit like php8.4-fpm). Polled via
    /// `ServiceInstallStatus`. Single slot — apt would dpkg-lock
    /// concurrent jobs anyway.
    pub service_install_progress: Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
    /// Live per-phase sub-step progress a running operation (e.g. a backup)
    /// publishes, keyed by the master job id the caller passed in. Read back
    /// over RPC (`BackupProgress`) by the master, which mirrors it into the job
    /// row so the progress page shows subjobs. Shared across `HostingService`
    /// clones so the concurrent read sees the running op's writes; ephemeral,
    /// cleared when the op finishes.
    pub backup_progress: Arc<tokio::sync::Mutex<HashMap<String, Vec<hyperion_types::JobSubstep>>>>,
}

/// Default renewal window — matches Let's Encrypt's recommended
/// 30-day buffer before `not_after`. Operators override via
/// `[acme] renewal_window_days` in agent.toml.
pub const CERT_RENEWAL_WINDOW_DAYS: i64 = 30;

/// Operator-supplied logo for notification e-mails. One file, one place —
/// a per-node path rather than a DB row because the agent that SENDS the
/// mail is the one that must read it.
pub const EMAIL_LOGO_PATH: &str = "/etc/hyperion/email-logo";

/// What a box is for. Resolved by [`HostingService::deployment_role`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentRole {
    /// One server, no cluster in either direction. The overwhelmingly
    /// common case, and the one the UI used to have no concept of.
    Standalone,
    /// Drives one or more enrolled workers.
    Master,
    /// Enrolled to a master. Decided by the presence of the enrollment
    /// credential, never by config.
    Worker,
}

impl DeploymentRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Master => "master",
            Self::Worker => "worker",
        }
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

fn derive_user_from_summary(s: &HostingSummary) -> Option<String> {
    // HostingSummary doesn't carry system_user yet; fall back to deriving
    // it from the domain the same way the create flow does.
    SystemUserName::derive_from_domain(&s.domain)
        .ok()
        .map(|u| u.as_str().to_string())
}

fn period_key(now: i64) -> String {
    use chrono::{TimeZone, Utc};
    let dt = Utc.timestamp_opt(now, 0).single().unwrap_or_else(Utc::now);
    dt.format("%Y-%m-%d-%H").to_string()
}

/// Run a provisioning rollback stack and surface any *incomplete* cleanup.
/// `rollback_all` already logs each step; this logs the AGGREGATE at error
/// level so a leaked user/dir/db is visible even though the caller then
/// returns the original provisioning error (which would otherwise hide it).
/// One row of a self-check report (FTP, permissions).
fn check_item(id: &str, label: &str, severity: &str, detail: String, fix: &str) -> FtpCheckItem {
    FtpCheckItem {
        id: id.into(),
        label: label.into(),
        severity: severity.into(),
        detail,
        fix: fix.into(),
    }
}

async fn rollback_and_log(stack: &mut RollbackStack) {
    let errs = stack.rollback_all().await;
    if !errs.is_empty() {
        tracing::error!(
            failures = ?errs,
            "rollback incomplete after provisioning failure — manual cleanup may be required"
        );
    }
}

/// A writable HOME/cache base for a site user, beside its htdocs. `root_dir`
/// IS the htdocs; its parent is the site tree, owned by the user.
fn home_dir_for(detail: &HostingDetail) -> String {
    std::path::Path::new(detail.root_dir.trim())
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("/home/{}", detail.system_user))
}

// ===== Internal-error helper =====
trait InternalWith {
    fn internal_with(msg: String) -> Self;
}
impl InternalWith for RpcError {
    fn internal_with(msg: String) -> Self {
        tracing::error!(error=%msg, "internal error");
        // Carry the message on the wire too — the operator-facing
        // 502 page renders it. It used to be log-only, which made
        // every internal failure show as a context-free "internal
        // error" (e.g. the trash CHECK-constraint bug took a day
        // of guessing instead of one glance).
        RpcError::Internal { message: msg }
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

impl<A: AdapterPort + 'static> HostingService<A> {
    pub fn new(pool: SqlitePool, adapters: Arc<A>, secrets: Arc<crate::SecretsStore>) -> Self {
        Self {
            pool,
            adapters,
            secrets,
            paths: HostingPaths::default(),
            // The repair has always run; a service built without an
            // explicit setting keeps it.
            permissions_autoheal: true,
            remote_backup: None,
            retention: BackupRetention::default(),
            snapshots_enabled: true,
            protection_mode: hyperion_types::ProtectionMode::Both,
            slack_default_webhook: None,
            acme_contact_email: "admin@hyperion.invalid".into(),
            email_config: None,
            email_default_to: None,
            fail2ban: Fail2banConfig::default(),
            agent_config_path: None,
            update_cache: Arc::new(tokio::sync::RwLock::new(None)),
            current_git_sha: "dev-unknown".into(),
            cert_issue_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            panel_progress: Arc::new(tokio::sync::RwLock::new(None)),
            master_rpc_signer: None,
            node_state_file: None,
            service_install_progress: Arc::new(tokio::sync::Mutex::new(
                hyperion_types::ServiceInstallStatus::default(),
            )),
            backup_progress: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
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
    /// What this box is FOR, resolved from one fact and one preference.
    ///
    /// `node-id.json` wins because it is a credential, not an opinion: a box
    /// that successfully enrolled IS a worker, whatever a config key claims.
    /// Putting worker-ness in the same key would create a state where the
    /// two can disagree, which is a bug factory. Everything else falls out
    /// of `[cluster] mode`, whose absent/garbage case resolves to Master —
    /// the pre-existing behaviour, so upgrades change nothing until the
    /// startup backfill writes the key explicitly.
    pub fn deployment_role(&self) -> DeploymentRole {
        if self.is_worker_node() {
            return DeploymentRole::Worker;
        }
        match read_cluster_section(self.agent_config_path.as_deref())
            .mode
            .as_str()
        {
            "standalone" => DeploymentRole::Standalone,
            _ => DeploymentRole::Master,
        }
    }

    /// True when this box has no cluster above or below it, so every
    /// node/worker surface in the UI is noise rather than information.
    pub fn is_standalone(&self) -> bool {
        matches!(self.deployment_role(), DeploymentRole::Standalone)
    }

    /// Niceness for the malware sweep — see [`read_scan_niceness`].
    pub fn malware_scan_niceness(&self) -> i32 {
        read_scan_niceness(self.agent_config_path.as_deref())
    }

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

    pub fn with_fail2ban(mut self, cfg: Fail2banConfig) -> Self {
        self.fail2ban = cfg;
        self
    }

    /// Node-wide switch for the permission self-repair. Default ON — the
    /// repair has always run, so upgrading must not silently remove it.
    pub fn with_permissions_autoheal(mut self, enabled: bool) -> Self {
        self.permissions_autoheal = enabled;
        self
    }

    pub fn with_remote_backup(mut self, cfg: Option<RemoteBackupConfig>) -> Self {
        self.remote_backup = cfg;
        self
    }

    /// Node-wide switch for snapshots. Default ON, and a no-op unless
    /// restic is installed — so this is a way to say "not on this node",
    /// not a way to turn the feature on.
    pub fn with_snapshots(mut self, enabled: bool) -> Self {
        self.snapshots_enabled = enabled;
        self
    }

    /// Which engine this node uses. Anything unrecognised is `both` — see
    /// [`hyperion_types::ProtectionMode::parse`] for why that direction.
    pub fn with_protection_mode(mut self, mode: &str) -> Self {
        self.protection_mode = hyperion_types::ProtectionMode::parse(mode);
        self
    }

    pub fn with_retention(mut self, retention: BackupRetention) -> Self {
        self.retention = retention;
        self
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
}

#[cfg(test)]
mod tests;
