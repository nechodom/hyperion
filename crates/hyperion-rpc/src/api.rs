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
    async fn hosting_usage(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<HostingUsageBucket>, RpcError>;

    async fn audit_list(&self, limit: i64) -> Result<Vec<AuditEntryWire>, RpcError>;

    async fn hosting_set_expiry(
        &self,
        sel: HostingSelector,
        expiry: HostingExpiry,
    ) -> Result<HostingExpiry, RpcError>;
    async fn hosting_get_expiry(&self, sel: HostingSelector) -> Result<HostingExpiry, RpcError>;
    async fn hosting_clear_expiry(&self, sel: HostingSelector) -> Result<(), RpcError>;
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

    /// Restart a whitelisted systemd unit.
    async fn service_restart(&self, name: String) -> Result<(), RpcError>;
    /// apt-install + enable a whitelisted unit. Returns immediately;
    /// poll `service_install_status` for the log tail.
    async fn service_install(&self, name: String) -> Result<(), RpcError>;
    /// State of the most-recent / in-progress service-install job.
    async fn service_install_status(
        &self,
    ) -> Result<hyperion_types::ServiceInstallStatus, RpcError>;
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

    /// Probe localhost for a usable SMTP relay.
    async fn email_smtp_autodetect(&self) -> Result<hyperion_types::SmtpAutodetect, RpcError>;

    /// Import a migration bundle by URL — downloads from the source
    /// node's signed `/api/migration/bundle/<id>` endpoint then runs
    /// the regular import.
    async fn hosting_import_from_url(
        &self,
        base_url: String,
        token: String,
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
    /// pricing onto the hosting and links it.
    async fn profile_apply(
        &self,
        sel: HostingSelector,
        profile_id: i64,
    ) -> Result<ProfileApply, RpcError>;
    /// Return the profile-apply row for a hosting, if any.
    async fn profile_get_apply(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<ProfileApply>, RpcError>;

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

    /// Restore a hosting from a previously-taken backup archive. The path
    /// must point at one of OUR archives (under /var/lib/hyperion/backups
    /// or an operator-uploaded copy in /var/lib/hyperion/backups/incoming).
    async fn backup_restore(
        &self,
        sel: HostingSelector,
        archive_path: String,
    ) -> Result<(), RpcError>;
}
