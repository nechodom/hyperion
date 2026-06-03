//! `AgentImpl` — production glue that implements `AgentApi`.

use crate::service::AdapterPort;
use crate::HostingService;
use async_trait::async_trait;
use hyperion_rpc::wire::{
    AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
};
use hyperion_rpc::{AgentApi, AuditEntryWire, RpcError};
use hyperion_types::{
    BackupRunWire, CertInfo, CertIssueRequest, CertRenewResult, ClusterStats, DashboardAlert,
    DnsCheckResult, ExpiringHosting, HostingDetail, HostingExpiry, HostingLimits, HostingProfile,
    HostingStats, HostingSummary, HostingUsageBucket, NodeInviteMint, NodeInviteSummary, NodeStats,
    NodeSummary, ProfileApply, ProfileInput, SuspendReason, WpInstallRequest, WpInstallStatus,
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

    async fn dns_spf_check(
        &self,
        domain: Domain,
    ) -> Result<hyperion_types::SpfCheckResult, RpcError> {
        self.svc.dns_spf_check(domain).await
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

    async fn node_metrics_history(
        &self,
        limit: i64,
    ) -> Result<hyperion_types::NodeMetricsHistory, RpcError> {
        self.svc.node_metrics_history(limit).await
    }

    async fn set_hosting_acme_email(
        &self,
        sel: HostingSelector,
        email: Option<String>,
    ) -> Result<(), RpcError> {
        self.svc.set_hosting_acme_email(sel, email).await
    }

    async fn services_health(&self) -> Result<hyperion_types::ServicesHealth, RpcError> {
        self.svc.services_health().await
    }

    async fn backup_delete(&self, backup_id: i64) -> Result<(), RpcError> {
        self.svc.backup_delete(backup_id).await
    }

    async fn agent_config_view(&self) -> Result<hyperion_types::AgentConfigView, RpcError> {
        self.svc.agent_config_view(&self.hostname, &self.version).await
    }

    async fn email_send_test(&self, to: String) -> Result<(), RpcError> {
        self.svc.email_send_test(to).await
    }

    // --- web users ---
    async fn web_login(
        &self,
        username: String,
        password: String,
        client_ip: Option<String>,
    ) -> Result<hyperion_types::WebLoginResult, RpcError> {
        self.svc.web_login(username, password, client_ip).await
    }
    async fn web_verify_2fa(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<hyperion_types::WebVerify2faResult, RpcError> {
        self.svc.web_verify_2fa(user_id, code).await
    }
    async fn web_user_list(&self) -> Result<Vec<hyperion_types::WebUserSummary>, RpcError> {
        self.svc.web_user_list().await
    }
    async fn web_user_get(
        &self,
        id: i64,
    ) -> Result<Option<hyperion_types::WebUserSummary>, RpcError> {
        self.svc.web_user_get(id).await
    }
    async fn web_user_create(
        &self,
        username: String,
        email: String,
        password: String,
        role: String,
    ) -> Result<i64, RpcError> {
        self.svc.web_user_create(username, email, password, role).await
    }
    async fn web_user_set_password(
        &self,
        user_id: i64,
        new_password: String,
    ) -> Result<(), RpcError> {
        self.svc.web_user_set_password(user_id, new_password).await
    }
    async fn web_user_set_role(&self, user_id: i64, role: String) -> Result<(), RpcError> {
        self.svc.web_user_set_role(user_id, role).await
    }
    async fn web_user_set_locked(
        &self,
        user_id: i64,
        locked: bool,
        reason: Option<String>,
    ) -> Result<(), RpcError> {
        self.svc.web_user_set_locked(user_id, locked, reason).await
    }
    async fn web_user_delete(&self, user_id: i64) -> Result<(), RpcError> {
        self.svc.web_user_delete(user_id).await
    }
    async fn web_2fa_enroll_start(
        &self,
        user_id: i64,
    ) -> Result<hyperion_types::Web2faEnrollment, RpcError> {
        self.svc.web_2fa_enroll_start(user_id).await
    }
    async fn web_2fa_confirm_enroll(&self, user_id: i64, code: String) -> Result<bool, RpcError> {
        self.svc.web_2fa_confirm_enroll(user_id, code).await
    }
    async fn web_2fa_disable(&self, user_id: i64) -> Result<(), RpcError> {
        self.svc.web_2fa_disable(user_id).await
    }

    async fn web_grant_hosting_access(
        &self,
        user_id: i64,
        hosting_id: String,
        level: String,
        granted_by: Option<i64>,
    ) -> Result<(), RpcError> {
        self.svc
            .web_grant_hosting_access(user_id, hosting_id, level, granted_by)
            .await
    }
    async fn web_revoke_hosting_access(
        &self,
        user_id: i64,
        hosting_id: String,
    ) -> Result<(), RpcError> {
        self.svc.web_revoke_hosting_access(user_id, hosting_id).await
    }
    async fn web_list_hosting_access(
        &self,
        hosting_id: String,
    ) -> Result<Vec<hyperion_types::WebHostingAccess>, RpcError> {
        self.svc.web_list_hosting_access(hosting_id).await
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
    ) -> Result<String, RpcError> {
        self.svc
            .enroll_consume(token, caller_ip, node_id, label, agent_version, public_ip)
            .await
    }

    async fn node_heartbeat(
        &self,
        node_id: String,
        secret: String,
        agent_version: String,
    ) -> Result<(), RpcError> {
        self.svc
            .node_heartbeat(node_id, secret, agent_version)
            .await
    }

    async fn nodes_list(&self) -> Result<Vec<NodeSummary>, RpcError> {
        self.svc.nodes_list().await
    }

    async fn wp_reset_password(
        &self,
        sel: HostingSelector,
        wp_user: String,
        new_password: String,
    ) -> Result<(), RpcError> {
        self.svc.wp_reset_password(sel, wp_user, new_password).await
    }

    async fn db_reset_password(
        &self,
        sel: HostingSelector,
        new_password: String,
    ) -> Result<(), RpcError> {
        self.svc.db_reset_password(sel, new_password).await
    }

    async fn ftp_set_password(
        &self,
        sel: HostingSelector,
        new_password: String,
    ) -> Result<String, RpcError> {
        self.svc.ftp_set_password(sel, new_password).await
    }

    async fn ftp_disable(&self, sel: HostingSelector) -> Result<(), RpcError> {
        self.svc.ftp_disable(sel).await
    }

    async fn dashboard_alerts(&self) -> Result<Vec<DashboardAlert>, RpcError> {
        self.svc.dashboard_alerts().await
    }

    async fn profile_list(&self) -> Result<Vec<HostingProfile>, RpcError> {
        self.svc.profile_list().await
    }
    async fn profile_get(&self, id: i64) -> Result<HostingProfile, RpcError> {
        self.svc.profile_get(id).await
    }
    async fn profile_create(&self, input: ProfileInput) -> Result<HostingProfile, RpcError> {
        self.svc.profile_create(input).await
    }
    async fn profile_update(
        &self,
        id: i64,
        input: ProfileInput,
    ) -> Result<HostingProfile, RpcError> {
        self.svc.profile_update(id, input).await
    }
    async fn profile_delete(&self, id: i64) -> Result<(), RpcError> {
        self.svc.profile_delete(id).await
    }
    async fn profile_apply(
        &self,
        sel: HostingSelector,
        profile_id: i64,
    ) -> Result<ProfileApply, RpcError> {
        self.svc.profile_apply(sel, profile_id).await
    }
    async fn profile_get_apply(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<ProfileApply>, RpcError> {
        self.svc.profile_get_apply(sel).await
    }
}
