//! `AgentImpl` — production glue that implements `AgentApi`.

use crate::service::AdapterPort;
use crate::HostingService;
use async_trait::async_trait;
use hyperion_rpc::wire::{
    AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
};
use hyperion_rpc::{AgentApi, AuditEntryWire, RpcError};
use hyperion_types::{
    BackupRunWire, CertInfo, CertIssueRequest, CertRenewResult, ClusterStats, DnsCheckResult,
    ExpiringHosting, HostingDetail, HostingExpiry, HostingLimits, HostingStats, HostingSummary,
    HostingUsageBucket, NodeInviteMint, NodeInviteSummary, NodeStats, NodeSummary, SuspendReason,
    WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::Domain;
use std::sync::Arc;

pub struct AgentImpl<A: AdapterPort + 'static> {
    svc: Arc<HostingService<A>>,
    hostname: String,
    version: String,
}

impl<A: AdapterPort + 'static> AgentImpl<A> {
    pub fn new(svc: Arc<HostingService<A>>) -> Self {
        Self {
            svc,
            hostname: hostname_or_unknown(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

fn hostname_or_unknown() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[async_trait]
impl<A: AdapterPort + 'static> AgentApi for AgentImpl<A> {
    async fn agent_info(&self) -> Result<AgentInfo, RpcError> {
        let count = self.svc.list().await.map(|v| v.len() as i64).unwrap_or(0);
        Ok(AgentInfo {
            hostname: self.hostname.clone(),
            version: self.version.clone(),
            schema_version: 2,
            hostings_count: count,
        })
    }

    async fn hosting_create(&self, req: HostingCreateReq) -> Result<HostingCreated, RpcError> {
        self.svc.create(req).await
    }

    async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError> {
        self.svc.list().await
    }

    async fn hosting_get(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError> {
        self.svc.get(sel).await
    }

    async fn hosting_delete(&self, sel: HostingSelector, opts: DeleteOpts) -> Result<(), RpcError> {
        self.svc.delete(sel, opts).await
    }

    async fn hosting_set_limits(
        &self,
        sel: HostingSelector,
        limits: HostingLimits,
    ) -> Result<HostingLimits, RpcError> {
        self.svc.set_limits(sel, limits).await
    }

    async fn hosting_get_limits(&self, sel: HostingSelector) -> Result<HostingLimits, RpcError> {
        self.svc.get_limits(sel).await
    }

    async fn hosting_suspend(
        &self,
        sel: HostingSelector,
        reason: SuspendReason,
    ) -> Result<(), RpcError> {
        self.svc.suspend(sel, reason).await
    }

    async fn hosting_resume(&self, sel: HostingSelector) -> Result<(), RpcError> {
        self.svc.resume(sel).await
    }

    async fn hosting_usage(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<HostingUsageBucket>, RpcError> {
        self.svc.usage(sel, limit).await
    }

    async fn audit_list(&self, limit: i64) -> Result<Vec<AuditEntryWire>, RpcError> {
        self.svc.audit_list(limit).await
    }

    async fn hosting_set_expiry(
        &self,
        sel: HostingSelector,
        expiry: HostingExpiry,
    ) -> Result<HostingExpiry, RpcError> {
        self.svc.set_expiry(sel, expiry).await
    }

    async fn hosting_get_expiry(&self, sel: HostingSelector) -> Result<HostingExpiry, RpcError> {
        self.svc.get_expiry(sel).await
    }

    async fn hosting_clear_expiry(&self, sel: HostingSelector) -> Result<(), RpcError> {
        self.svc.clear_expiry(sel).await
    }

    async fn upcoming_expiries(
        &self,
        within_seconds: i64,
    ) -> Result<Vec<ExpiringHosting>, RpcError> {
        self.svc.upcoming_expiries(within_seconds).await
    }

    async fn scheduler_tick(&self) -> Result<i64, RpcError> {
        self.svc.scheduler_tick().await
    }

    async fn backup_now(&self, sel: HostingSelector) -> Result<BackupRunWire, RpcError> {
        self.svc.backup_now(sel).await
    }

    async fn backup_list(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<BackupRunWire>, RpcError> {
        self.svc.backup_list(sel, limit).await
    }

    async fn invite_create(
        &self,
        label: String,
        ttl_secs: i64,
    ) -> Result<NodeInviteMint, RpcError> {
        self.svc.invite_create(label, ttl_secs).await
    }

    async fn invite_list(&self) -> Result<Vec<NodeInviteSummary>, RpcError> {
        self.svc.invite_list().await
    }

    async fn invite_revoke(&self, token_hash: String) -> Result<(), RpcError> {
        self.svc.invite_revoke(token_hash).await
    }

    async fn cert_issue(&self, _domain: Domain) -> Result<CertInfo, RpcError> {
        Err(RpcError::Internal)
    }

    async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError> {
        Ok(vec![])
    }

    async fn wp_install(
        &self,
        sel: HostingSelector,
        req: WpInstallRequest,
    ) -> Result<WpInstallStatus, RpcError> {
        self.svc.install_wordpress(sel, req).await
    }

    async fn wp_status(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<WpInstallStatus>, RpcError> {
        self.svc.wp_status(sel).await
    }

    async fn dns_check(&self, domain: Domain) -> Result<DnsCheckResult, RpcError> {
        self.svc.dns_check(domain).await
    }

    async fn cert_issue_acme(
        &self,
        sel: HostingSelector,
        req: CertIssueRequest,
    ) -> Result<CertInfo, RpcError> {
        self.svc.issue_real_cert(sel, req).await
    }

    async fn hosting_stats(&self, sel: HostingSelector) -> Result<HostingStats, RpcError> {
        self.svc.hosting_stats(sel).await
    }

    async fn node_stats(&self) -> Result<NodeStats, RpcError> {
        self.svc.node_stats(&self.hostname, &self.version).await
    }

    async fn cluster_stats(&self) -> Result<ClusterStats, RpcError> {
        self.svc.cluster_stats(&self.hostname, &self.version).await
    }

    async fn stats_tick(&self) -> Result<i64, RpcError> {
        self.svc.stats_tick().await
    }

    async fn backup_restore(
        &self,
        sel: HostingSelector,
        archive_path: String,
    ) -> Result<(), RpcError> {
        self.svc.backup_restore(sel, archive_path).await
    }

    async fn hosting_logs(
        &self,
        sel: HostingSelector,
        log_kind: String,
        lines: i64,
    ) -> Result<String, RpcError> {
        self.svc.hosting_logs(sel, &log_kind, lines).await
    }

    async fn cron_list(&self, sel: HostingSelector) -> Result<String, RpcError> {
        self.svc.cron_list(sel).await
    }

    async fn cron_replace(
        &self,
        sel: HostingSelector,
        body: String,
    ) -> Result<(), RpcError> {
        self.svc.cron_replace(sel, body).await
    }

    async fn enroll_consume(
        &self,
        token: String,
        caller_ip: String,
        node_id: String,
        label: String,
        agent_version: String,
        public_ip: Option<String>,
    ) -> Result<(), RpcError> {
        self.svc
            .enroll_consume(token, caller_ip, node_id, label, agent_version, public_ip)
            .await
    }

    async fn nodes_list(&self) -> Result<Vec<NodeSummary>, RpcError> {
        self.svc.nodes_list().await
    }
}
