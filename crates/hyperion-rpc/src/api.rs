//! The single trait every transport speaks to.

use crate::{
    codec::AuditEntryWire,
    error::RpcError,
    wire::{AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector},
};
use async_trait::async_trait;
use hyperion_types::{
    BackupRunWire, CertInfo, CertIssueRequest, CertRenewResult, ClusterStats, DashboardAlert,
    DnsCheckResult, ExpiringHosting, HostingDetail, HostingExpiry, HostingLimits, HostingStats,
    HostingSummary, HostingUsageBucket, NodeInviteMint, NodeInviteSummary, NodeStats, NodeSummary,
    SuspendReason, WpInstallRequest, WpInstallStatus,
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
    /// node in the `nodes` table, mint a per-node secret. Returns the
    /// secret (plaintext, shown only once — node persists it locally
    /// for heartbeat auth).
    #[allow(clippy::too_many_arguments)]
    async fn enroll_consume(
        &self,
        token: String,
        caller_ip: String,
        node_id: String,
        label: String,
        agent_version: String,
        public_ip: Option<String>,
    ) -> Result<String, RpcError>;

    /// Master-side heartbeat: verifies (node_id, secret) and bumps the
    /// node's last_seen_at + agent_version.
    async fn node_heartbeat(
        &self,
        node_id: String,
        secret: String,
        agent_version: String,
    ) -> Result<(), RpcError>;

    /// List enrolled nodes (master-side `nodes` table).
    async fn nodes_list(&self) -> Result<Vec<NodeSummary>, RpcError>;

    /// Compute operator alerts (cert expiring, failed hostings, stale
    /// backups, high load) at request time.
    async fn dashboard_alerts(&self) -> Result<Vec<DashboardAlert>, RpcError>;

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

    /// Restore a hosting from a previously-taken backup archive. The path
    /// must point at one of OUR archives (under /var/lib/hyperion/backups
    /// or an operator-uploaded copy in /var/lib/hyperion/backups/incoming).
    async fn backup_restore(
        &self,
        sel: HostingSelector,
        archive_path: String,
    ) -> Result<(), RpcError>;
}
