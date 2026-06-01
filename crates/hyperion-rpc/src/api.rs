//! The single trait every transport speaks to.

use crate::{
    codec::AuditEntryWire,
    error::RpcError,
    wire::{AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector},
};
use async_trait::async_trait;
use hyperion_types::{
    BackupRunWire, CertInfo, CertRenewResult, ExpiringHosting, HostingDetail, HostingExpiry,
    HostingLimits, HostingSummary, HostingUsageBucket, NodeInviteMint, NodeInviteSummary,
    SuspendReason,
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
}
