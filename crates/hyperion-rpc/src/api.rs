//! The single trait every transport speaks to.

use crate::{
    codec::AuditEntryWire,
    error::RpcError,
    wire::{AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector},
};
use async_trait::async_trait;
use hyperion_types::{
    BackupRunWire, CertInfo, CertIssueRequest, CertRenewResult, ClusterStats, DnsCheckResult,
    ExpiringHosting, HostingDetail, HostingExpiry, HostingLimits, HostingStats, HostingSummary,
    HostingUsageBucket, NodeInviteMint, NodeInviteSummary, NodeStats, SuspendReason,
    WpInstallRequest, WpInstallStatus,
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

    /// Restore a hosting from a previously-taken backup archive. The path
    /// must point at one of OUR archives (under /var/lib/hyperion/backups
    /// or an operator-uploaded copy in /var/lib/hyperion/backups/incoming).
    async fn backup_restore(
        &self,
        sel: HostingSelector,
        archive_path: String,
    ) -> Result<(), RpcError>;
}
