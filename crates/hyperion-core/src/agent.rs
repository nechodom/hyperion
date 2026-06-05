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
    /// Path to the persisted node-id.json. Read on every
    /// `agent_info()` call so `hctl info` reflects enrollment
    /// state without needing the agent to re-spawn.
    node_state_file: std::path::PathBuf,
}

impl<A: AdapterPort + 'static> AgentImpl<A> {
    pub fn new(svc: Arc<HostingService<A>>) -> Self {
        Self::with_state_file(svc, "/etc/hyperion/node-id.json".into())
    }

    pub fn with_state_file(svc: Arc<HostingService<A>>, node_state_file: std::path::PathBuf) -> Self {
        Self {
            svc,
            hostname: hostname_or_unknown(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_state_file,
        }
    }
}

/// Minimal mirror of `bin/hyperion-agent::enroll::PersistedNodeId`
/// just for reading from this side of the crate boundary. Adding a
/// shared crate for this one struct isn't worth the dependency graph
/// — the JSON shape is the contract.
#[derive(serde::Deserialize)]
struct PersistedNodeIdView {
    node_id: String,
    master_url: String,
    #[serde(default)]
    enrolled_at: i64,
}

/// Read node-id.json, return (node_id, master_url, enrolled_at) or
/// triple-`None` when missing/unreadable/malformed. Fall-through is
/// deliberately silent — `hctl info` should still print the agent's
/// hostname + version even on an unenrolled single-node setup.
async fn read_node_state(path: &std::path::Path) -> (Option<String>, Option<String>, Option<i64>) {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(_) => return (None, None, None),
    };
    let parsed: Result<PersistedNodeIdView, _> = serde_json::from_slice(&bytes);
    match parsed {
        Ok(p) => (
            Some(p.node_id),
            Some(p.master_url),
            if p.enrolled_at > 0 { Some(p.enrolled_at) } else { None },
        ),
        Err(_) => (None, None, None),
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
        let (node_id, master_url, enrolled_at) = read_node_state(&self.node_state_file).await;
        Ok(AgentInfo {
            hostname: self.hostname.clone(),
            version: self.version.clone(),
            schema_version: 2,
            hostings_count: count,
            node_id,
            master_url,
            enrolled_at,
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

    async fn trash_list(&self) -> Result<Vec<hyperion_types::TrashEntry>, RpcError> {
        self.svc.list_trash().await
    }
    async fn trash_restore(&self, sel: HostingSelector) -> Result<(), RpcError> {
        self.svc.restore_from_trash(sel).await
    }
    async fn trash_purge(&self, sel: HostingSelector) -> Result<(), RpcError> {
        self.svc.purge_from_trash(sel).await
    }

    async fn hosting_set_vhost_options(
        &self,
        sel: HostingSelector,
        options: hyperion_types::VhostOptions,
        basic_auth_password: Option<String>,
    ) -> Result<hyperion_types::VhostOptions, RpcError> {
        self.svc
            .set_vhost_options(sel, options, basic_auth_password)
            .await
    }

    async fn hosting_set_wp_debug(
        &self,
        sel: HostingSelector,
        enabled: bool,
        log: bool,
        display: bool,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        self.svc.set_wp_debug(sel, enabled, log, display).await
    }

    async fn hosting_set_redis(
        &self,
        sel: HostingSelector,
        enabled: bool,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        self.svc.set_redis(sel, enabled).await
    }

    async fn hosting_rotate_redis_password(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpExtras, RpcError> {
        self.svc.rotate_redis_password(sel).await
    }

    async fn hosting_rotate_wp_debug_log(
        &self,
        sel: HostingSelector,
    ) -> Result<(), RpcError> {
        self.svc.rotate_wp_debug_log(sel).await
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
        // Thin wrapper so the RPC keeps its old signature. The
        // background tick in `hyperion-agent` is the primary driver;
        // this lets `hctl cert renew` work on demand too.
        self.svc
            .cert_renew_tick(
                hyperion_types::now_secs(),
                crate::service::CERT_RENEWAL_WINDOW_DAYS,
            )
            .await
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
    async fn service_restart(&self, name: String) -> Result<(), RpcError> {
        self.svc.service_restart(name).await
    }
    async fn service_install(&self, name: String) -> Result<(), RpcError> {
        self.svc.service_install(name).await
    }
    async fn service_install_status(
        &self,
    ) -> Result<hyperion_types::ServiceInstallStatus, RpcError> {
        self.svc.service_install_status().await
    }
    async fn wp_asset_upload(
        &self,
        kind: String,
        original_name: String,
        bytes: Vec<u8>,
        uploaded_by: String,
    ) -> Result<(i64, bool), RpcError> {
        self.svc
            .wp_asset_upload(kind, original_name, bytes, uploaded_by)
            .await
    }
    async fn wp_asset_list(&self) -> Result<Vec<hyperion_types::WpAssetSummary>, RpcError> {
        self.svc.wp_asset_list().await
    }
    async fn wp_asset_delete(&self, id: i64) -> Result<(), RpcError> {
        self.svc.wp_asset_delete(id).await
    }
    async fn wp_install_from_asset(
        &self,
        sel: hyperion_rpc::HostingSelector,
        asset_id: i64,
        activate: bool,
    ) -> Result<(String, String), RpcError> {
        self.svc.wp_install_from_asset(sel, asset_id, activate).await
    }
    async fn wp_asset_replace(
        &self,
        id: i64,
        original_name: String,
        bytes: Vec<u8>,
        uploaded_by: String,
    ) -> Result<(), RpcError> {
        self.svc
            .wp_asset_replace(id, original_name, bytes, uploaded_by)
            .await
    }
    async fn wp_asset_reinstall_all(
        &self,
        asset_id: i64,
        force_activate: Option<bool>,
    ) -> Result<(i64, i64, String), RpcError> {
        self.svc
            .wp_asset_reinstall_all(asset_id, force_activate)
            .await
    }
    async fn wp_theme_list(
        &self,
        hosting: hyperion_rpc::HostingSelector,
    ) -> Result<hyperion_types::WpThemeListResponse, RpcError> {
        self.svc.wp_theme_list(hosting).await
    }
    async fn wp_theme_action(
        &self,
        sel: hyperion_rpc::HostingSelector,
        slug: String,
        action: hyperion_types::WpThemeAction,
    ) -> Result<hyperion_types::WpThemeActionResult, RpcError> {
        self.svc.wp_theme_action(sel, slug, action).await
    }
    async fn node_update_run(
        &self,
        do_apt: bool,
        do_hyperion: bool,
    ) -> Result<i64, RpcError> {
        self.svc.node_update_run(do_apt, do_hyperion).await
    }
    async fn node_update_status(
        &self,
    ) -> Result<hyperion_types::NodeUpdateStatus, RpcError> {
        self.svc.node_update_status().await
    }
    async fn agent_config_update(
        &self,
        section: String,
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<(), RpcError> {
        self.svc.agent_config_update(section, fields).await
    }

    async fn update_check(
        &self,
        force_refresh: bool,
    ) -> Result<hyperion_types::UpdateStatus, RpcError> {
        self.svc.update_check(force_refresh).await
    }

    async fn hosting_export(
        &self,
        hosting: hyperion_rpc::HostingSelector,
    ) -> Result<hyperion_types::HostingMigrationBundle, RpcError> {
        self.svc.hosting_export(hosting).await
    }

    async fn hosting_migration_fetch_bundle_file(
        &self,
        bundle_id: String,
        filename: String,
    ) -> Result<String, RpcError> {
        self.svc
            .hosting_migration_fetch_bundle_file(bundle_id, filename)
            .await
    }

    async fn hosting_import(
        &self,
        manifest_path: String,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        self.svc.hosting_import(manifest_path).await
    }

    async fn hosting_import_from_url(
        &self,
        base_url: String,
        token: String,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        self.svc.hosting_import_from_url(base_url, token).await
    }

    async fn email_log_list(
        &self,
        hosting_id: Option<String>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::EmailLogEntry>, RpcError> {
        self.svc.email_log_list(hosting_id, limit).await
    }

    async fn email_smtp_autodetect(&self) -> Result<hyperion_types::SmtpAutodetect, RpcError> {
        self.svc.email_smtp_autodetect().await
    }

    async fn wp_plugin_list(
        &self,
        hosting: hyperion_rpc::HostingSelector,
    ) -> Result<hyperion_types::WpPluginListResponse, RpcError> {
        self.svc.wp_plugin_list(hosting).await
    }

    async fn wp_plugin_action(
        &self,
        hosting: hyperion_rpc::HostingSelector,
        slug: String,
        action: hyperion_types::WpPluginAction,
    ) -> Result<hyperion_types::WpPluginActionResult, RpcError> {
        self.svc.wp_plugin_action(hosting, slug, action).await
    }

    async fn backup_delete(&self, backup_id: i64) -> Result<(), RpcError> {
        self.svc.backup_delete(backup_id).await
    }

    async fn agent_config_view(&self) -> Result<hyperion_types::AgentConfigView, RpcError> {
        self.svc.agent_config_view(&self.hostname, &self.version).await
    }

    async fn email_send_test(&self, to: String) -> Result<String, RpcError> {
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

    async fn hosting_file_list(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(String, Vec<hyperion_types::HostingFileEntry>), RpcError> {
        self.svc.hosting_file_list(sel, rel_path).await
    }
    async fn hosting_file_read(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<hyperion_types::HostingFileContent, RpcError> {
        self.svc.hosting_file_read(sel, rel_path).await
    }
    async fn hosting_file_download(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(String, String, String), RpcError> {
        self.svc.hosting_file_download(sel, rel_path).await
    }
    async fn hosting_file_write(
        &self,
        sel: HostingSelector,
        rel_path: String,
        bytes_b64: String,
    ) -> Result<(), RpcError> {
        self.svc.hosting_file_write(sel, rel_path, bytes_b64).await
    }
    async fn hosting_file_delete(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(), RpcError> {
        self.svc.hosting_file_delete(sel, rel_path).await
    }
    async fn hosting_file_mkdir(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(), RpcError> {
        self.svc.hosting_file_mkdir(sel, rel_path).await
    }
    async fn hosting_file_rename(
        &self,
        sel: HostingSelector,
        from: String,
        to: String,
    ) -> Result<(), RpcError> {
        self.svc.hosting_file_rename(sel, from, to).await
    }
    async fn monitor_overview(
        &self,
    ) -> Result<Vec<hyperion_types::MonitorOverviewItem>, RpcError> {
        self.svc.monitor_overview().await
    }
    async fn avatar_filename(&self, user_id: i64) -> Result<Option<String>, RpcError> {
        self.svc.avatar_filename(user_id).await
    }
    async fn avatar_set(
        &self,
        user_id: i64,
        filename: Option<String>,
    ) -> Result<(), RpcError> {
        self.svc.avatar_set(user_id, filename).await
    }

    async fn email_change_request(
        &self,
        user_id: i64,
        new_email: String,
        current_password: String,
    ) -> Result<String, RpcError> {
        self.svc
            .email_change_request(user_id, new_email, current_password)
            .await
    }
    async fn email_change_confirm(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<(), RpcError> {
        self.svc.email_change_confirm(user_id, code).await
    }
    async fn email_change_cancel(&self, user_id: i64) -> Result<(), RpcError> {
        self.svc.email_change_cancel(user_id).await
    }
    async fn monitor_get(
        &self,
        sel: HostingSelector,
    ) -> Result<(hyperion_types::MonitorConfigView, hyperion_types::MonitorHistory), RpcError>
    {
        self.svc.monitor_get(sel).await
    }
    async fn monitor_set(
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
        self.svc
            .monitor_set(
                sel,
                enabled,
                url_path,
                interval_secs,
                alert_after_fails,
                alert_email,
                alert_slack_webhook,
                alert_webhook_url,
            )
            .await
    }
    async fn monitor_probe_now(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::MonitorSamplePoint, RpcError> {
        self.svc.monitor_probe_now(sel).await
    }
    async fn monitor_tick(&self) -> Result<i64, RpcError> {
        self.svc.monitor_tick().await
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

    async fn notifications_feed(
        &self,
        user_id: i64,
        limit: i64,
    ) -> Result<hyperion_types::NotificationFeed, RpcError> {
        self.svc.notifications_feed(user_id, limit).await
    }

    async fn notifications_mark_read(
        &self,
        user_id: i64,
        notification_id: i64,
    ) -> Result<(), RpcError> {
        self.svc
            .notifications_mark_read(user_id, notification_id)
            .await
    }

    async fn notifications_mark_all_read(&self, user_id: i64) -> Result<i64, RpcError> {
        self.svc.notifications_mark_all_read(user_id).await
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
    ) -> Result<(String, Option<String>), RpcError> {
        let secret = self
            .svc
            .enroll_consume(token, caller_ip, node_id, label, agent_version, public_ip)
            .await?;
        Ok((secret, self.svc.master_rpc_pubkey_b64()))
    }

    async fn node_heartbeat(
        &self,
        node_id: String,
        secret: String,
        agent_version: String,
    ) -> Result<Option<String>, RpcError> {
        self.svc
            .node_heartbeat(node_id, secret, agent_version)
            .await?;
        Ok(self.svc.master_rpc_pubkey_b64())
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
