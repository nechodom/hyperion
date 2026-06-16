//! The single trait every transport speaks to.

use crate::{
    codec::AuditEntryWire,
    error::RpcError,
    wire::{AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector},
};
use async_trait::async_trait;
use hyperion_types::{
    BackupRunWire, CertInfo, CertIssueRequest, CertRenewResult, ClusterStats, DashboardAlert,
    DnsCheckResult, ExpiringHosting, HostingDetail, HostingExpiry, HostingLimits, HostingProfile,
    HostingStats, HostingSummary, HostingUsageBucket, NodeInviteMint, NodeInviteSummary, NodeStats,
    NodeSummary, ProfileApply, ProfileInput, SuspendReason, WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::Domain;

#[async_trait]
pub trait AgentApi: Send + Sync + 'static {
    async fn agent_info(&self) -> Result<AgentInfo, RpcError>;

    async fn hosting_create(&self, req: HostingCreateReq) -> Result<HostingCreated, RpcError>;
    async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError>;
    async fn hosting_get(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError>;
    async fn hosting_delete(&self, sel: HostingSelector, opts: DeleteOpts) -> Result<(), RpcError>;

    async fn hosting_set_limits(
        &self,
        sel: HostingSelector,
        limits: HostingLimits,
    ) -> Result<HostingLimits, RpcError>;
    async fn hosting_get_limits(&self, sel: HostingSelector) -> Result<HostingLimits, RpcError>;
    async fn hosting_suspend(
        &self,
        sel: HostingSelector,
        reason: SuspendReason,
    ) -> Result<(), RpcError>;
    async fn hosting_resume(&self, sel: HostingSelector) -> Result<(), RpcError>;
    /// Change the PHP version of an existing PHP hosting. Tears
    /// down the old FPM pool, brings up the new one, re-applies
    /// persisted limits, and rewrites the nginx vhost to point at
    /// the new socket. Errors when the hosting is not PHP-kind,
    /// suspended, deleting, or when the new version equals the
    /// current (treated as no-op).
    async fn hosting_set_php_version(
        &self,
        sel: HostingSelector,
        version: hyperion_types::PhpVersion,
    ) -> Result<hyperion_types::PhpVersion, RpcError>;

    /// /trash page: list every trashed hosting on this node with
    /// seconds-remaining until GC.
    async fn trash_list(&self) -> Result<Vec<hyperion_types::TrashEntry>, RpcError>;
    /// Un-trash a hosting back to Active.
    async fn trash_restore(&self, sel: HostingSelector) -> Result<(), RpcError>;
    /// Skip the retention window and hard-delete this hosting now.
    async fn trash_purge(&self, sel: HostingSelector) -> Result<(), RpcError>;
    /// Apply the per-hosting vhost options (basic auth, HSTS, custom
    /// snippet, maintenance mode, FastCGI cache, redirect target).
    /// On the worker side this is validated with `nginx -t` before
    /// the new vhost is committed; on failure the previous vhost is
    /// restored and the rpc returns the verbatim nginx error.
    ///
    /// `basic_auth_password` is the plaintext password the operator
    /// typed; the agent bcrypt-hashes it before writing the htpasswd
    /// file. `None` means "leave the existing hash alone" — sent
    /// when the operator only flipped other toggles. Empty string
    /// also means leave alone (UI sends `""` for an untouched field).
    async fn hosting_set_vhost_options(
        &self,
        sel: HostingSelector,
        options: hyperion_types::VhostOptions,
        basic_auth_password: Option<String>,
    ) -> Result<hyperion_types::VhostOptions, RpcError>;

    /// Toggle WordPress debug flags (WP_DEBUG / WP_DEBUG_LOG /
    /// WP_DEBUG_DISPLAY) for this hosting. Requires WP to be installed.
    async fn hosting_set_wp_debug(
        &self,
        sel: HostingSelector,
        enabled: bool,
        log: bool,
        display: bool,
    ) -> Result<hyperion_types::WpExtras, RpcError>;

    /// Enable or disable per-hosting Redis object cache. On enable,
    /// allocates a Redis DB slot + writes WP_REDIS_* constants. On
    /// disable, removes the constants + deletes the Redis ACL user.
    async fn hosting_set_redis(
        &self,
        sel: HostingSelector,
        enabled: bool,
    ) -> Result<hyperion_types::WpExtras, RpcError>;

    /// Rotate the Redis password for an already-enabled hosting.
    async fn hosting_rotate_redis_password(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpExtras, RpcError>;

    /// Truncate wp-content/debug.log to 0 bytes. Idempotent.
    async fn hosting_rotate_wp_debug_log(
        &self,
        sel: HostingSelector,
    ) -> Result<(), RpcError>;
    async fn hosting_usage(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<HostingUsageBucket>, RpcError>;

    async fn audit_list(&self, limit: i64) -> Result<Vec<AuditEntryWire>, RpcError>;

    /// Walk the audit chain and verify each row_hash. Returns
    /// (ok, rows_checked, message) — message is empty on success,
    /// "row {id} mismatch" or "row {id} prev_hash mismatch" on
    /// failure.
    async fn audit_verify_chain(&self) -> Result<(bool, i64, String), RpcError>;

    async fn backup_target_list(&self) -> Result<Vec<hyperion_types::BackupTargetView>, RpcError>;

    #[allow(clippy::too_many_arguments)]
    async fn backup_target_upsert(
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
    ) -> Result<i64, RpcError>;

    async fn backup_target_delete(&self, id: i64) -> Result<(), RpcError>;

    async fn backup_target_probe(
        &self,
        id: i64,
    ) -> Result<hyperion_types::BackupTargetProbe, RpcError>;

    /// Read current per-hosting quota policy + usage.
    async fn quota_get(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingQuotaReport, RpcError>;

    /// Persist a new policy + push it into the kernel via setquota.
    /// Returns the saved row (with applied_at / last_error reflecting
    /// the kernel call's outcome).
    async fn quota_set(
        &self,
        sel: HostingSelector,
        disk_soft_kib: i64,
        disk_hard_kib: i64,
        mem_limit_mib: i64,
        bw_soft_mib: i64,
        bw_hard_mib: i64,
    ) -> Result<hyperion_types::HostingQuotaView, RpcError>;

    /// Track a freshly-minted Session in the `web_sessions` ledger.
    async fn web_session_insert(
        &self,
        sid: String,
        user_id: i64,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), RpcError>;

    /// Per-request liveness probe — true ⇒ live, false ⇒
    /// revoked / unknown.
    async fn web_session_touch(&self, sid: String) -> Result<bool, RpcError>;

    /// Newest-first list of `user_id`'s sessions.
    async fn web_session_list(
        &self,
        user_id: i64,
    ) -> Result<Vec<hyperion_types::WebSessionView>, RpcError>;

    /// Flip `revoked_at`. Returns true if the row existed and was
    /// still live.
    async fn web_session_revoke(
        &self,
        sid: String,
        revoked_by: i64,
    ) -> Result<bool, RpcError>;

    async fn hosting_set_expiry(
        &self,
        sel: HostingSelector,
        expiry: HostingExpiry,
    ) -> Result<HostingExpiry, RpcError>;
    async fn hosting_get_expiry(&self, sel: HostingSelector) -> Result<HostingExpiry, RpcError>;
    async fn hosting_clear_expiry(&self, sel: HostingSelector) -> Result<(), RpcError>;
    /// Generic per-hosting key/value store (notes, tags, …).
    async fn hosting_kv_set(
        &self,
        hosting_id: String,
        key: String,
        value: String,
    ) -> Result<(), RpcError>;
    async fn hosting_kv_list(
        &self,
        hosting_id: String,
    ) -> Result<Vec<(String, String)>, RpcError>;
    async fn upcoming_expiries(
        &self,
        within_seconds: i64,
    ) -> Result<Vec<ExpiringHosting>, RpcError>;
    /// Manually drive one tick of the scheduler. The agent also runs this
    /// every `[scheduler] tick_interval` seconds in the background.
    async fn scheduler_tick(&self) -> Result<i64, RpcError>;

    async fn backup_now(&self, sel: HostingSelector) -> Result<BackupRunWire, RpcError>;
    async fn backup_list(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<BackupRunWire>, RpcError>;

    async fn invite_create(&self, label: String, ttl_secs: i64)
        -> Result<NodeInviteMint, RpcError>;
    async fn invite_list(&self) -> Result<Vec<NodeInviteSummary>, RpcError>;
    async fn invite_revoke(&self, token_hash: String) -> Result<(), RpcError>;

    async fn cert_issue(&self, domain: Domain) -> Result<CertInfo, RpcError>;
    async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError>;

    /// Resolve `domain`'s A + AAAA records (via `dig`) and report whether
    /// they point at this agent's externally-visible IP.
    async fn dns_check(&self, domain: Domain) -> Result<DnsCheckResult, RpcError>;

    /// Resolve `domain`'s SPF TXT record + suggest one based on this
    /// agent's public IP.
    async fn dns_spf_check(
        &self,
        domain: Domain,
    ) -> Result<hyperion_types::SpfCheckResult, RpcError>;
    /// Issue a real Let's Encrypt cert (HTTP-01) for the hosting at
    /// `sel`. Respects `req.staging` / `req.require_dns_match`.
    async fn cert_issue_acme(
        &self,
        sel: crate::wire::HostingSelector,
        req: CertIssueRequest,
    ) -> Result<CertInfo, RpcError>;

    /// Latest stats snapshot for a hosting (disk, bw, reqs).
    async fn hosting_stats(
        &self,
        sel: crate::wire::HostingSelector,
    ) -> Result<HostingStats, RpcError>;
    /// Latest snapshot for this agent (single-node = this box).
    async fn node_stats(&self) -> Result<NodeStats, RpcError>;
    /// Cluster-wide aggregate. Single-node today = wraps node_stats.
    async fn cluster_stats(&self) -> Result<ClusterStats, RpcError>;

    /// Recent samples from `node_metrics` for sparklines / mini charts.
    /// Returns oldest → newest. `limit` is clamped agent-side.
    async fn node_metrics_history(
        &self,
        limit: i64,
    ) -> Result<hyperion_types::NodeMetricsHistory, RpcError>;

    /// Set / clear the per-hosting ACME contact email override.
    /// Passing `None` or an empty string clears the override; the
    /// next cert issuance reverts to the agent-wide default from
    /// `[acme] contact_email`. Validates email format when present.
    async fn set_hosting_acme_email(
        &self,
        sel: crate::wire::HostingSelector,
        email: Option<String>,
    ) -> Result<(), RpcError>;

    /// Status of system services Hyperion depends on (nginx, mariadb,
    /// postgresql, php-fpm versions, vsftpd, hyperion-agent,
    /// hyperion-web). Computed live via `systemctl is-active/is-enabled`.
    async fn services_health(&self) -> Result<hyperion_types::ServicesHealth, RpcError>;

    /// Dump the firewall ruleset (nft, with iptables fallback). Read-only.
    async fn firewall_list(&self) -> Result<hyperion_types::FirewallView, RpcError>;

    /// Apply a hardcoded firewall template by id. Returns
    /// `(applied, output, error_first_line)`.
    async fn firewall_apply_template(
        &self,
        template_id: String,
    ) -> Result<(bool, String, String), RpcError>;

    /// Restart a whitelisted systemd unit.
    async fn service_restart(&self, name: String) -> Result<(), RpcError>;
    /// apt-install + enable a whitelisted unit. Returns immediately;
    /// poll `service_install_status` for the log tail.
    async fn service_install(&self, name: String) -> Result<(), RpcError>;
    /// State of the most-recent / in-progress service-install job.
    async fn service_install_status(
        &self,
    ) -> Result<hyperion_types::ServiceInstallStatus, RpcError>;
    /// Upload a WP plugin / theme ZIP into the master's asset
    /// library. Returns the row id (newly-inserted or existing if
    /// dedupe matched on SHA-256).
    async fn wp_asset_upload(
        &self,
        kind: String,
        original_name: String,
        bytes: Vec<u8>,
        uploaded_by: String,
    ) -> Result<(i64, bool), RpcError>;
    /// List every uploaded WP asset.
    async fn wp_asset_list(&self) -> Result<Vec<hyperion_types::WpAssetSummary>, RpcError>;
    /// Delete an uploaded asset (DB row + on-disk file).
    async fn wp_asset_delete(&self, id: i64) -> Result<(), RpcError>;
    /// Install an uploaded asset onto a hosting via wp-cli. Returns
    /// (kind, original_name) so the UI flash can be specific.
    async fn wp_install_from_asset(
        &self,
        sel: HostingSelector,
        asset_id: i64,
        activate: bool,
    ) -> Result<(String, String), RpcError>;
    /// Replace an existing asset's on-disk file in place.
    async fn wp_asset_replace(
        &self,
        id: i64,
        original_name: String,
        bytes: Vec<u8>,
        uploaded_by: String,
    ) -> Result<(), RpcError>;
    /// Re-install an asset on every hosting tracked in
    /// wp_asset_installs. Returns (ok_count, fail_count, failure_tail).
    async fn wp_asset_reinstall_all(
        &self,
        asset_id: i64,
        force_activate: Option<bool>,
    ) -> Result<(i64, i64, String), RpcError>;
    /// `wp theme list` for a hosting.
    async fn wp_theme_list(
        &self,
        hosting: HostingSelector,
    ) -> Result<hyperion_types::WpThemeListResponse, RpcError>;
    /// Apply a whitelisted theme action via wp-cli.
    async fn wp_theme_action(
        &self,
        sel: HostingSelector,
        slug: String,
        action: hyperion_types::WpThemeAction,
    ) -> Result<hyperion_types::WpThemeActionResult, RpcError>;
    /// Scan installed plugins + themes against the Wordfence feed.
    async fn wp_vuln_scan(
        &self,
        hosting: HostingSelector,
    ) -> Result<hyperion_types::WpVulnScanResult, RpcError>;
    /// Start a background node-update job. Returns the unix
    /// timestamp the job started at. `NodeUpdateStatus` polls the
    /// log tail + state.
    async fn node_update_run(
        &self,
        do_apt: bool,
        do_hyperion: bool,
    ) -> Result<i64, RpcError>;
    /// Read the state of the most-recent / in-progress update job.
    async fn node_update_status(
        &self,
    ) -> Result<hyperion_types::NodeUpdateStatus, RpcError>;
    /// Update one section of `/etc/hyperion/agent.toml`.
    async fn agent_config_update(
        &self,
        section: String,
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<(), RpcError>;

    /// Compare the running binary's git SHA against the upstream
    /// `rolling` release. Cached agent-side; pass `force_refresh: true`
    /// to bypass the cache.
    async fn update_check(
        &self,
        force_refresh: bool,
    ) -> Result<hyperion_types::UpdateStatus, RpcError>;

    /// Export a hosting as a self-contained migration bundle.
    async fn hosting_export(
        &self,
        hosting: HostingSelector,
    ) -> Result<hyperion_types::HostingMigrationBundle, RpcError>;

    /// Read raw bytes from one of the two files in
    /// `/var/lib/hyperion/migration/<bundle_id>/`: either
    /// `manifest.json` or `archive.tar.gz`. Returned as base64.
    /// Used by the master to pull bundles off a worker source.
    async fn hosting_migration_fetch_bundle_file(
        &self,
        bundle_id: String,
        filename: String,
    ) -> Result<String, RpcError>;

    /// Import a migration bundle on this node.
    async fn hosting_import(
        &self,
        manifest_path: String,
    ) -> Result<hyperion_types::HostingImportResult, RpcError>;

    /// Per-hosting (or cluster-wide) email log.
    async fn email_log_list(
        &self,
        hosting_id: Option<String>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::EmailLogEntry>, RpcError>;

    /// Read the per-user JSONL captured by the site-mail wrapper.
    /// Returns the most recent `limit` lines, newest first.
    async fn site_email_log_list(
        &self,
        system_user: String,
        limit: i64,
    ) -> Result<Vec<hyperion_types::SiteEmailLogEntry>, RpcError>;

    /// List every Linux user on this node with an FTP-usable shadow
    /// password. Joined with the local hosting table so the UI shows
    /// "domain + state + node" alongside the user name.
    async fn ftp_accounts_list(
        &self,
    ) -> Result<Vec<hyperion_types::FtpAccountSummary>, RpcError>;

    /// Probe vsftpd at localhost with the supplied credential.
    async fn ftp_verify_login(
        &self,
        user: String,
        password: String,
    ) -> Result<bool, RpcError>;

    /// Probe localhost for a usable SMTP relay.
    async fn email_smtp_autodetect(&self) -> Result<hyperion_types::SmtpAutodetect, RpcError>;

    /// Read live MTA state for the /settings UI card.
    async fn mta_diagnostics(&self) -> Result<hyperion_types::MtaDiagnostics, RpcError>;

    /// Re-apply postfix smart-host or direct-MX config based on
    /// current [email] settings. Returns the mode that was applied.
    async fn mta_reconfigure(&self) -> Result<String, RpcError>;

    /// Send a test email via `/usr/sbin/sendmail`. Returns
    /// (exit_code, output). 0 = sendmail accepted into queue.
    async fn mta_test_send(&self, to: String) -> Result<(i32, String), RpcError>;

    /// `postqueue -f` — retry every deferred message right now.
    /// Returns (attempted, output) where `attempted` is the count
    /// we parsed out of the post-flush mailq summary (best
    /// effort).
    async fn mta_queue_flush(&self) -> Result<(usize, String), RpcError>;

    /// `postsuper -d ALL` — discard every queued message.
    /// Returns (cleared, output). Destructive operation; the UI
    /// must gate it behind a type-to-confirm modal.
    async fn mta_queue_clear(&self) -> Result<(usize, String), RpcError>;

    /// Provision the master panel on a real FQDN with auto-cert
    /// via nginx reverse-proxy. Returns (status, message, url).
    async fn panel_provision(
        &self,
        hostname: String,
        skip_dns_check: bool,
    ) -> Result<(String, String, String), RpcError>;

    /// Live snapshot of the panel ACME issuance — drives the
    /// progress card on /settings#cluster.
    async fn panel_cert_status(
        &self,
    ) -> Result<Option<hyperion_types::PanelCertProgress>, RpcError>;

    /// Attempt `mount -o remount,rw /` to flip the rootfs to
    /// read-write. Returns (success, message). Refuses (Validation)
    /// when /usr is already writable.
    async fn remount_usr_rw(&self) -> Result<(bool, String), RpcError>;

    /// Full ROFS diagnose + auto-fix sequence. See
    /// `Request::FsDiagnoseAndFix` doc.
    async fn fs_diagnose_and_fix(
        &self,
        dry_run: bool,
    ) -> Result<hyperion_types::FsDiagnostics, RpcError>;

    /// Look up a single background job. Returns `None` if rotated out
    /// of the table.
    async fn job_get(&self, id: String) -> Result<Option<hyperion_types::JobView>, RpcError>;

    /// List background jobs, newest first.
    async fn job_list(
        &self,
        kind: Option<String>,
        state: Option<String>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::JobView>, RpcError>;

    /// Open a new job row, returning a fresh `job_id`.
    async fn job_start(
        &self,
        kind: String,
        target: Option<String>,
        payload_json: String,
        actor_label: String,
        actor_uid: i64,
    ) -> Result<String, RpcError>;

    /// Tick progress on an in-flight job.
    async fn job_progress(
        &self,
        id: String,
        step_label: String,
        progress_pct: i64,
        log_append: String,
    ) -> Result<(), RpcError>;

    /// Flip a job to a terminal state.
    async fn job_finish(
        &self,
        id: String,
        ok: bool,
        error: Option<String>,
    ) -> Result<(), RpcError>;

    /// Import a migration bundle by URL — downloads from the source
    /// node's signed `/api/migration/bundle/<id>` endpoint then runs
    /// the regular import.
    async fn hosting_import_from_url(
        &self,
        base_url: String,
        token: String,
        override_domain: Option<String>,
        override_aliases: Vec<String>,
    ) -> Result<hyperion_types::HostingImportResult, RpcError>;

    /// List installed WordPress plugins for a hosting.
    async fn wp_plugin_list(
        &self,
        hosting: HostingSelector,
    ) -> Result<hyperion_types::WpPluginListResponse, RpcError>;

    /// Apply one whitelisted plugin action via wp-cli.
    async fn wp_plugin_action(
        &self,
        hosting: HostingSelector,
        slug: String,
        action: hyperion_types::WpPluginAction,
    ) -> Result<hyperion_types::WpPluginActionResult, RpcError>;

    /// Delete a single backup run + its archive file from disk.
    /// Refuses to act on a backup that is still `running`.
    async fn backup_delete(&self, backup_id: i64) -> Result<(), RpcError>;

    /// Sanitised view of the agent's effective config — no secrets.
    /// Powers the operator-facing /settings page.
    async fn agent_config_view(&self) -> Result<hyperion_types::AgentConfigView, RpcError>;

    /// Send a one-off test email through the configured SMTP relay.
    /// Returns Ok on a successful relay handshake + DATA accept.
    async fn email_send_test(&self, to: String) -> Result<String, RpcError>;

    // Web users / roles / 2FA — see codec.rs for semantics.
    async fn web_login(
        &self,
        username: String,
        password: String,
        client_ip: Option<String>,
    ) -> Result<hyperion_types::WebLoginResult, RpcError>;
    async fn web_verify_2fa(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<hyperion_types::WebVerify2faResult, RpcError>;
    async fn web_user_list(&self) -> Result<Vec<hyperion_types::WebUserSummary>, RpcError>;
    async fn web_user_get(
        &self,
        id: i64,
    ) -> Result<Option<hyperion_types::WebUserSummary>, RpcError>;
    async fn web_user_create(
        &self,
        username: String,
        email: String,
        password: String,
        role: String,
    ) -> Result<i64, RpcError>;
    async fn web_user_set_password(
        &self,
        user_id: i64,
        new_password: String,
    ) -> Result<(), RpcError>;
    async fn web_user_set_role(&self, user_id: i64, role: String) -> Result<(), RpcError>;
    async fn web_user_set_locked(
        &self,
        user_id: i64,
        locked: bool,
        reason: Option<String>,
    ) -> Result<(), RpcError>;
    async fn web_user_delete(&self, user_id: i64) -> Result<(), RpcError>;
    async fn web_2fa_enroll_start(
        &self,
        user_id: i64,
    ) -> Result<hyperion_types::Web2faEnrollment, RpcError>;
    async fn web_2fa_confirm_enroll(&self, user_id: i64, code: String) -> Result<bool, RpcError>;
    async fn web_2fa_disable(&self, user_id: i64) -> Result<(), RpcError>;

    /// Grant a user access to one hosting. `level` is "read" or "manage".
    /// Idempotent — re-granting upserts the level.
    async fn web_grant_hosting_access(
        &self,
        user_id: i64,
        hosting_id: String,
        level: String,
        granted_by: Option<i64>,
    ) -> Result<(), RpcError>;
    async fn web_revoke_hosting_access(
        &self,
        user_id: i64,
        hosting_id: String,
    ) -> Result<(), RpcError>;
    async fn web_list_hosting_access(
        &self,
        hosting_id: String,
    ) -> Result<Vec<hyperion_types::WebHostingAccess>, RpcError>;

    /// List one directory inside a hosting's htdocs jail.
    async fn hosting_file_list(
        &self,
        sel: crate::wire::HostingSelector,
        rel_path: String,
    ) -> Result<(String, Vec<hyperion_types::HostingFileEntry>), RpcError>;
    /// Read one text file inside a hosting's htdocs jail.
    async fn hosting_file_read(
        &self,
        sel: crate::wire::HostingSelector,
        rel_path: String,
    ) -> Result<hyperion_types::HostingFileContent, RpcError>;
    /// Download any file (≤ 64 MiB) as raw bytes. Returns (rel_path,
    /// base64-encoded bytes, mime). Used for binary files the inline
    /// reader refuses (images, ZIPs, PDFs).
    async fn hosting_file_download(
        &self,
        sel: crate::wire::HostingSelector,
        rel_path: String,
    ) -> Result<(String, String, String), RpcError>;
    /// Write/overwrite a file. bytes_b64 is base64 (no-pad ok).
    async fn hosting_file_write(
        &self,
        sel: crate::wire::HostingSelector,
        rel_path: String,
        bytes_b64: String,
    ) -> Result<(), RpcError>;
    /// Delete one file OR one empty directory.
    async fn hosting_file_delete(
        &self,
        sel: crate::wire::HostingSelector,
        rel_path: String,
    ) -> Result<(), RpcError>;
    /// Create one new empty directory.
    async fn hosting_file_mkdir(
        &self,
        sel: crate::wire::HostingSelector,
        rel_path: String,
    ) -> Result<(), RpcError>;
    /// Rename or move a path inside the jail.
    async fn hosting_file_rename(
        &self,
        sel: crate::wire::HostingSelector,
        from: String,
        to: String,
    ) -> Result<(), RpcError>;

    /// Cluster-wide monitor overview: every hosting on THIS node
    /// with monitor enabled, plus computed 24h success rate +
    /// avg latency. Web fan-outs this to every enrolled worker
    /// and concatenates the rows.
    async fn monitor_overview(
        &self,
    ) -> Result<Vec<hyperion_types::MonitorOverviewItem>, RpcError>;

    /// Read the avatar filename column for one user.
    async fn avatar_filename(&self, user_id: i64) -> Result<Option<String>, RpcError>;
    /// Set / clear the avatar filename column.
    async fn avatar_set(
        &self,
        user_id: i64,
        filename: Option<String>,
    ) -> Result<(), RpcError>;

    /// Verify current_password + store the new_email pending +
    /// send a 6-digit code to it. Returns the masked target.
    async fn email_change_request(
        &self,
        user_id: i64,
        new_email: String,
        current_password: String,
    ) -> Result<String, RpcError>;
    /// Validate the 6-digit code; on success, swap email → pending.
    async fn email_change_confirm(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<(), RpcError>;
    async fn email_change_cancel(&self, user_id: i64) -> Result<(), RpcError>;

    /// Per-hosting monitor: get config + recent samples.
    async fn monitor_get(
        &self,
        sel: crate::wire::HostingSelector,
    ) -> Result<(hyperion_types::MonitorConfigView, hyperion_types::MonitorHistory), RpcError>;
    #[allow(clippy::too_many_arguments)]
    async fn monitor_set(
        &self,
        sel: crate::wire::HostingSelector,
        enabled: bool,
        url_path: Option<String>,
        interval_secs: Option<i64>,
        alert_after_fails: Option<i64>,
        alert_email: Option<String>,
        alert_slack_webhook: Option<String>,
        alert_webhook_url: Option<String>,
    ) -> Result<(), RpcError>;
    async fn monitor_probe_now(
        &self,
        sel: crate::wire::HostingSelector,
    ) -> Result<hyperion_types::MonitorSamplePoint, RpcError>;
    async fn monitor_tick(&self) -> Result<i64, RpcError>;

    /// Install WordPress into a hosting (downloads core, writes wp-config.php
    /// against the hosting's DB credentials, runs `wp core install`, records
    /// the result in `wp_installs`).
    async fn wp_install(
        &self,
        sel: HostingSelector,
        req: WpInstallRequest,
    ) -> Result<WpInstallStatus, RpcError>;
    /// Return the recorded WP install for a hosting, or `None` if no
    /// install has been recorded.
    async fn wp_status(&self, sel: HostingSelector) -> Result<Option<WpInstallStatus>, RpcError>;

    /// Run a single background-sampler tick now (disk + bw counters per
    /// hosting, node metrics row). Returns the count of hostings sampled.
    async fn stats_tick(&self) -> Result<i64, RpcError>;

    /// Tail the last N lines of access / error logs for a hosting.
    async fn hosting_logs(
        &self,
        sel: HostingSelector,
        log_kind: String,
        lines: i64,
    ) -> Result<String, RpcError>;

    /// Read the hosting's crontab (lines belonging to the hosting's system
    /// user). Returns the entire crontab as a string.
    async fn cron_list(&self, sel: HostingSelector) -> Result<String, RpcError>;
    /// Replace the hosting's crontab atomically (writes to a temp file,
    /// `crontab -u <user> <file>`).
    async fn cron_replace(&self, sel: HostingSelector, body: String) -> Result<(), RpcError>;

    /// Master-side node enrollment: consume an invite token, record the
    /// node in the `nodes` table, mint a per-node secret. Returns
    /// `(secret_plaintext, master_rpc_pubkey_b64)` — the latter is
    /// `Some` when the master has a master-RPC signing key
    /// configured, `None` on dev / not-yet-upgraded setups (node
    /// treats `None` as "remote RPC unavailable from this master").
    #[allow(clippy::too_many_arguments)]
    async fn enroll_consume(
        &self,
        token: String,
        caller_ip: String,
        node_id: String,
        label: String,
        agent_version: String,
        public_ip: Option<String>,
    ) -> Result<(String, Option<String>), RpcError>;

    /// Master-side heartbeat: verifies (node_id, secret) and bumps
    /// the node's last_seen_at + agent_version. Returns the master's
    /// remote-RPC pubkey (base64, `None` when remote RPC isn't set
    /// up on this master) so existing enrolled nodes can pick it up
    /// without re-enrolling.
    async fn node_heartbeat(
        &self,
        node_id: String,
        secret: String,
        agent_version: String,
    ) -> Result<Option<String>, RpcError>;

    /// List enrolled nodes (master-side `nodes` table).
    async fn nodes_list(&self) -> Result<Vec<NodeSummary>, RpcError>;

    /// Cluster-wide certificate inventory.
    async fn cert_overview(&self) -> Result<Vec<hyperion_types::CertOverviewItem>, RpcError>;

    /// Rename an enrolled node's display label. `node_id` is the
    /// immutable enrollment identifier; only the label changes.
    /// Returns Ok(()) on success even when the node_id is unknown
    /// (no-op) so the master's "rename" form is forgiving on a
    /// race with deletion.
    async fn node_set_label(&self, node_id: String, label: String) -> Result<(), RpcError>;

    /// Toggle a node's drain flag.
    async fn node_set_drain(
        &self,
        node_id: String,
        drain: bool,
        reason: String,
        actor_uid: i64,
    ) -> Result<(), RpcError>;

    /// Delete an enrolled node row. Returns `(removed, blocking)`:
    /// `removed=true` iff the row was deleted; `blocking>0` ⇒ hostings
    /// still reference it and the request was refused (caller must
    /// pass `force=true` to override + orphan the rows).
    async fn node_remove(
        &self,
        node_id: String,
        force: bool,
        actor_uid: i64,
    ) -> Result<(bool, i64), RpcError>;

    /// Compute operator alerts (cert expiring, failed hostings, stale
    /// backups, high load) at request time.
    async fn dashboard_alerts(&self) -> Result<Vec<DashboardAlert>, RpcError>;

    /// List operator-defined hosting profiles (templates).
    async fn profile_list(&self) -> Result<Vec<HostingProfile>, RpcError>;
    async fn profile_get(&self, id: i64) -> Result<HostingProfile, RpcError>;
    async fn profile_create(&self, input: ProfileInput) -> Result<HostingProfile, RpcError>;
    async fn profile_update(&self, id: i64, input: ProfileInput)
        -> Result<HostingProfile, RpcError>;
    async fn profile_delete(&self, id: i64) -> Result<(), RpcError>;
    /// Apply a profile to a hosting — copies limits + expiry policy +
    /// pricing onto the hosting and links it. `skip_wp_items=true`
    /// leaves the profile's wp_plugins / wp_themes for the caller to
    /// install item-by-item via `profile_wp_item_install` (per-plugin
    /// progress reporting).
    async fn profile_apply(
        &self,
        sel: HostingSelector,
        profile_id: i64,
        skip_wp_items: bool,
    ) -> Result<ProfileApply, RpcError>;
    /// Return the profile-apply row for a hosting, if any.
    async fn profile_get_apply(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<ProfileApply>, RpcError>;
    /// Install ONE profile wp_plugins / wp_themes line on a hosting.
    /// Returns (human label, activated). See codec.rs for the line
    /// syntax.
    async fn profile_wp_item_install(
        &self,
        sel: HostingSelector,
        item_kind: String,
        line: String,
    ) -> Result<(String, bool), RpcError>;

    /// Reset the WordPress admin password (wp user update --user_pass).
    /// Returns the new password (the caller usually shows it to the
    /// operator exactly once).
    async fn wp_reset_password(
        &self,
        sel: HostingSelector,
        wp_user: String,
        new_password: String,
    ) -> Result<(), RpcError>;

    /// Reset the hosting's DB password (ALTER USER on mariadb /
    /// ALTER ROLE on postgres) and rewrite the stored secret.
    /// Returns the new password.
    async fn db_reset_password(
        &self,
        sel: HostingSelector,
        new_password: String,
    ) -> Result<(), RpcError>;

    /// Set / generate the FTP password for the hosting's system user.
    /// Empty `new_password` → server generates one. Returns the
    /// password that was set (caller shows it once).
    async fn ftp_set_password(
        &self,
        sel: HostingSelector,
        new_password: String,
    ) -> Result<String, RpcError>;
    /// Disable FTP (passwd -d <user>).
    async fn ftp_disable(&self, sel: HostingSelector) -> Result<(), RpcError>;
    /// Read current key-only SFTP status for a hosting.
    async fn sftp_status(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::SftpStatus, RpcError>;
    /// Enable/disable key-only chrooted SFTP and replace the keys.
    async fn sftp_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
        public_keys: Vec<String>,
    ) -> Result<hyperion_types::SftpStatus, RpcError>;

    /// Restore a hosting from a previously-taken backup archive. The path
    /// must point at one of OUR archives (under /var/lib/hyperion/backups
    /// or an operator-uploaded copy in /var/lib/hyperion/backups/incoming).
    async fn backup_restore(
        &self,
        sel: HostingSelector,
        archive_path: String,
        mode: hyperion_types::BackupRestoreMode,
    ) -> Result<(), RpcError>;
    /// Stream one slice of a backup archive for download. Returns
    /// (base64 data, total size, filename, eof). `len == 0` ⇒ metadata
    /// only (empty data).
    async fn backup_fetch_chunk(
        &self,
        backup_id: i64,
        offset: u64,
        len: u32,
    ) -> Result<(String, u64, String, bool), RpcError>;
    /// Restore an archive into a new hosting at `new_domain`. Returns
    /// (hosting_id, domain) of the created hosting.
    async fn backup_restore_as_new(
        &self,
        sel: HostingSelector,
        archive_path: String,
        new_domain: String,
    ) -> Result<(String, String), RpcError>;

    // ── Bell-icon notification feed (in-app) ──────────────────────
    /// Recent N notifications + unread total for the given user.
    /// Web caller passes the session's user_id.
    async fn notifications_feed(
        &self,
        user_id: i64,
        limit: i64,
    ) -> Result<hyperion_types::NotificationFeed, RpcError>;
    /// Mark one notification as read for the given user.
    async fn notifications_mark_read(
        &self,
        user_id: i64,
        notification_id: i64,
    ) -> Result<(), RpcError>;
    /// Mark every unread notification for the user as read.
    /// Returns the count of rows marked.
    async fn notifications_mark_all_read(&self, user_id: i64) -> Result<i64, RpcError>;
}
