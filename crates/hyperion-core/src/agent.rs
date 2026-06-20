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

    pub fn with_state_file(
        svc: Arc<HostingService<A>>,
        node_state_file: std::path::PathBuf,
    ) -> Self {
        Self {
            svc,
            hostname: hostname_or_unknown(),
            // CARGO_PKG_VERSION is hardcoded "0.1.0" in Cargo.toml
            // and never changes. The hyperion-agent binary has its
            // own build.rs that stamps HYPERION_GIT_SHA — call
            // `.with_version(env!("HYPERION_GIT_SHA"))` from main
            // to surface the actual deployed SHA in AgentInfo.
            version: env!("CARGO_PKG_VERSION").to_string(),
            node_state_file,
        }
    }

    /// Override the version string that AgentInfo reports.
    /// hyperion-agent's main calls this with the build-time git
    /// short SHA so /install + connectivity tests see a useful
    /// version per agent instead of every node showing "v0.1.0".
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
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
            if p.enrolled_at > 0 {
                Some(p.enrolled_at)
            } else {
                None
            },
        ),
        Err(_) => (None, None, None),
    }
}

/// Clear the pinned `master_rpc_pubkey` in node-id.json so the NEXT
/// heartbeat re-adopts whatever key the master currently presents (TOFU
/// re-pin). This is the operator's escape hatch after a *deliberate*
/// master key rotation: the agent otherwise refuses a silently-changed
/// key (anti-MITM). Returns the key that was cleared, if any.
///
/// Parses as a generic JSON object so every other field (node_id,
/// secret, master_url, enrolled_at, …) is preserved untouched. Atomic
/// write (tmp → chmod 0600 → rename) keeps the 0600 perms + avoids a
/// torn read by the heartbeat / inbound-RPC loops that re-read this file.
async fn clear_pinned_pubkey_in_file(path: &std::path::Path) -> Result<Option<String>, String> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| "node-id.json is not a JSON object".to_string())?;
    let cleared = obj
        .get("master_rpc_pubkey")
        .and_then(|x| x.as_str())
        .map(String::from);
    obj.insert("master_rpc_pubkey".to_string(), serde_json::Value::Null);
    let serialized = serde_json::to_vec_pretty(&v).map_err(|e| format!("serialize: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &serialized)
        .await
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
    Ok(cleared)
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

    async fn agent_repin(&self) -> Result<Option<String>, RpcError> {
        let cleared = clear_pinned_pubkey_in_file(&self.node_state_file)
            .await
            .map_err(|message| RpcError::Internal { message })?;
        tracing::warn!(
            had_pin = cleared.is_some(),
            "operator cleared pinned master_rpc_pubkey (repin) — next heartbeat will re-adopt the master's current key"
        );
        Ok(cleared)
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

    async fn hosting_set_php_version(
        &self,
        sel: HostingSelector,
        version: hyperion_types::PhpVersion,
    ) -> Result<hyperion_types::PhpVersion, RpcError> {
        self.svc.set_php_version(sel, version).await
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

    async fn hosting_set_aliases(
        &self,
        sel: HostingSelector,
        aliases: Vec<hyperion_validate::Domain>,
    ) -> Result<hyperion_types::HostingDetail, RpcError> {
        self.svc.hosting_set_aliases(sel, aliases).await
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

    async fn hosting_rotate_wp_debug_log(&self, sel: HostingSelector) -> Result<(), RpcError> {
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

    async fn audit_verify_chain(&self) -> Result<(bool, i64, String), RpcError> {
        self.svc.audit_verify_chain().await
    }

    async fn backup_target_list(&self) -> Result<Vec<hyperion_types::BackupTargetView>, RpcError> {
        self.svc.backup_target_list().await
    }

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
    ) -> Result<i64, RpcError> {
        self.svc
            .backup_target_upsert(
                id,
                name,
                kind,
                endpoint,
                bucket,
                region,
                access_key_id,
                secret_key,
                age_recipient,
                retention_daily,
                retention_weekly,
                retention_monthly,
                enabled,
            )
            .await
    }

    async fn backup_target_delete(&self, id: i64) -> Result<(), RpcError> {
        self.svc.backup_target_delete(id).await
    }

    async fn backup_target_probe(
        &self,
        id: i64,
    ) -> Result<hyperion_types::BackupTargetProbe, RpcError> {
        self.svc.backup_target_probe(id).await
    }

    async fn quota_get(
        &self,
        sel: hyperion_rpc::HostingSelector,
    ) -> Result<hyperion_types::HostingQuotaReport, RpcError> {
        self.svc.quota_get(sel).await
    }

    async fn quota_enable_kernel(
        &self,
        sel: hyperion_rpc::HostingSelector,
    ) -> Result<hyperion_types::QuotaEnableSummary, RpcError> {
        self.svc.quota_enable_kernel(sel).await
    }

    async fn quota_set(
        &self,
        sel: hyperion_rpc::HostingSelector,
        disk_soft_kib: i64,
        disk_hard_kib: i64,
        mem_limit_mib: i64,
        bw_soft_mib: i64,
        bw_hard_mib: i64,
        exceed_action: String,
    ) -> Result<hyperion_types::HostingQuotaView, RpcError> {
        self.svc
            .quota_set(
                sel,
                disk_soft_kib,
                disk_hard_kib,
                mem_limit_mib,
                bw_soft_mib,
                bw_hard_mib,
                &exceed_action,
            )
            .await
    }

    async fn web_session_insert(
        &self,
        sid: String,
        user_id: i64,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), RpcError> {
        self.svc
            .web_session_insert(&sid, user_id, ip.as_deref(), user_agent.as_deref())
            .await
    }

    async fn web_session_touch(&self, sid: String) -> Result<bool, RpcError> {
        self.svc.web_session_touch(&sid).await
    }

    async fn web_session_list(
        &self,
        user_id: i64,
    ) -> Result<Vec<hyperion_types::WebSessionView>, RpcError> {
        self.svc.web_session_list(user_id).await
    }

    async fn web_session_revoke(&self, sid: String, revoked_by: i64) -> Result<bool, RpcError> {
        self.svc.web_session_revoke(&sid, revoked_by).await
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

    async fn hosting_kv_set(
        &self,
        hosting_id: String,
        key: String,
        value: String,
    ) -> Result<(), RpcError> {
        self.svc.hosting_kv_set(hosting_id, key, value).await
    }

    async fn hosting_kv_list(&self, hosting_id: String) -> Result<Vec<(String, String)>, RpcError> {
        self.svc.hosting_kv_list(hosting_id).await
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

    async fn backup_now(
        &self,
        sel: HostingSelector,
        s3_targets: Vec<hyperion_types::S3BackupTarget>,
    ) -> Result<BackupRunWire, RpcError> {
        self.svc.backup_now(sel, s3_targets).await
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
        Err(RpcError::Internal {
            message: "not supported by this agent".into(),
        })
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

    async fn wp_status(&self, sel: HostingSelector) -> Result<Option<WpInstallStatus>, RpcError> {
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

    async fn cert_dns01_begin(
        &self,
        sel: HostingSelector,
        staging: bool,
        provider: String,
    ) -> Result<(bool, String, Vec<String>), RpcError> {
        self.svc.cert_dns01_begin(sel, staging, provider).await
    }

    async fn cert_dns01_finish(&self, sel: HostingSelector) -> Result<CertInfo, RpcError> {
        self.svc.cert_dns01_finish(sel).await
    }

    async fn cert_dns01_begin_domain(
        &self,
        domain: Domain,
        email: Option<String>,
        staging: bool,
        provider: String,
    ) -> Result<(bool, String, Vec<String>), RpcError> {
        self.svc
            .cert_dns01_begin_domain(domain.as_str(), email.as_deref(), staging, provider)
            .await
    }

    async fn cert_dns01_finish_domain(&self, domain: Domain) -> Result<CertInfo, RpcError> {
        self.svc.cert_dns01_finish_domain(domain.as_str()).await
    }

    async fn cert_upload(
        &self,
        sel: HostingSelector,
        cert_pem: String,
        key_pem: String,
        ca_bundle_pem: Option<String>,
    ) -> Result<CertInfo, RpcError> {
        self.svc
            .upload_cert(sel, cert_pem, key_pem, ca_bundle_pem)
            .await
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
    async fn firewall_list(&self) -> Result<hyperion_types::FirewallView, RpcError> {
        self.svc.firewall_list().await
    }
    async fn firewall_apply_template(
        &self,
        template_id: String,
    ) -> Result<(bool, String, String), RpcError> {
        self.svc.firewall_apply_template(&template_id).await
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
        self.svc
            .wp_install_from_asset(sel, asset_id, activate)
            .await
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
    async fn wp_vuln_scan(
        &self,
        hosting: hyperion_rpc::HostingSelector,
    ) -> Result<hyperion_types::WpVulnScanResult, RpcError> {
        self.svc.wp_vuln_scan(hosting).await
    }

    async fn vuln_findings_list(
        &self,
    ) -> Result<Vec<hyperion_types::HostingVulnSummary>, RpcError> {
        self.svc.vuln_findings_list().await
    }

    async fn wp_staging_create(
        &self,
        sel: hyperion_rpc::HostingSelector,
        staging_domain: Option<String>,
    ) -> Result<String, RpcError> {
        self.svc.wp_staging_create(sel, staging_domain).await
    }

    async fn wp_staging_push(
        &self,
        sel: hyperion_rpc::HostingSelector,
        staging_domain: Option<String>,
    ) -> Result<(), RpcError> {
        self.svc.wp_staging_push(sel, staging_domain).await
    }
    async fn node_update_run(&self, do_apt: bool, do_hyperion: bool) -> Result<i64, RpcError> {
        self.svc.node_update_run(do_apt, do_hyperion).await
    }
    async fn node_update_status(&self) -> Result<hyperion_types::NodeUpdateStatus, RpcError> {
        self.svc.node_update_status().await
    }
    async fn agent_config_update(
        &self,
        section: String,
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<(), RpcError> {
        self.svc.agent_config_update(section, fields).await
    }
    async fn email_config_set(
        &self,
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<(), RpcError> {
        self.svc.email_config_set(fields).await
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
        override_domain: Option<String>,
        override_aliases: Vec<String>,
    ) -> Result<hyperion_types::HostingImportResult, RpcError> {
        self.svc
            .hosting_import_from_url(base_url, token, override_domain, override_aliases)
            .await
    }

    async fn email_log_list(
        &self,
        hosting_id: Option<String>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::EmailLogEntry>, RpcError> {
        self.svc.email_log_list(hosting_id, limit).await
    }

    async fn site_email_log_list(
        &self,
        system_user: String,
        limit: i64,
    ) -> Result<Vec<hyperion_types::SiteEmailLogEntry>, RpcError> {
        self.svc.site_email_log_list(system_user, limit).await
    }

    async fn ftp_accounts_list(&self) -> Result<Vec<hyperion_types::FtpAccountSummary>, RpcError> {
        self.svc.ftp_accounts_list().await
    }
    async fn ftp_verify_login(&self, user: String, password: String) -> Result<bool, RpcError> {
        self.svc.ftp_verify_login(user, password).await
    }

    async fn email_smtp_autodetect(&self) -> Result<hyperion_types::SmtpAutodetect, RpcError> {
        self.svc.email_smtp_autodetect().await
    }

    async fn mta_diagnostics(&self) -> Result<hyperion_types::MtaDiagnostics, RpcError> {
        self.svc.mta_diagnostics().await
    }

    async fn mta_reconfigure(&self) -> Result<String, RpcError> {
        self.svc.mta_reconfigure().await
    }

    async fn mta_test_send(&self, to: String) -> Result<(i32, String), RpcError> {
        self.svc.mta_test_send(to).await
    }

    async fn mta_queue_flush(&self) -> Result<(usize, String), RpcError> {
        self.svc.mta_queue_flush().await
    }

    async fn mta_queue_clear(&self) -> Result<(usize, String), RpcError> {
        self.svc.mta_queue_clear().await
    }

    async fn panel_provision(
        &self,
        hostname: String,
        skip_dns_check: bool,
    ) -> Result<(String, String, String), RpcError> {
        self.svc.panel_provision(hostname, skip_dns_check).await
    }

    async fn panel_cert_status(
        &self,
    ) -> Result<Option<hyperion_types::PanelCertProgress>, RpcError> {
        // Map the in-memory Service::PanelProgress (which holds the
        // lock-friendly internal repr) to the wire DTO. They're the
        // same fields — keeping them as separate types lets the
        // wire schema evolve independently of the internal state.
        let svc_state = self.svc.panel_cert_status().await?;
        Ok(svc_state.map(|p| hyperion_types::PanelCertProgress {
            hostname: p.hostname,
            stage: p.stage,
            message: p.message,
            started_at: p.started_at,
            not_after: p.not_after,
        }))
    }

    async fn remount_usr_rw(&self) -> Result<(bool, String), RpcError> {
        self.svc.remount_usr_rw().await
    }

    async fn fs_diagnose_and_fix(
        &self,
        dry_run: bool,
    ) -> Result<hyperion_types::FsDiagnostics, RpcError> {
        self.svc.fs_diagnose_and_fix(dry_run).await
    }

    async fn job_get(&self, id: String) -> Result<Option<hyperion_types::JobView>, RpcError> {
        self.svc.job_get(&id).await
    }

    async fn job_list(
        &self,
        kind: Option<String>,
        state: Option<String>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::JobView>, RpcError> {
        self.svc
            .job_list(kind.as_deref(), state.as_deref(), limit)
            .await
    }

    async fn job_start(
        &self,
        kind: String,
        target: Option<String>,
        payload_json: String,
        actor_label: String,
        actor_uid: i64,
    ) -> Result<String, RpcError> {
        self.svc
            .job_start_external(
                &kind,
                target.as_deref(),
                &payload_json,
                &actor_label,
                actor_uid,
            )
            .await
    }

    async fn job_progress(
        &self,
        id: String,
        step_label: String,
        progress_pct: i64,
        log_append: String,
    ) -> Result<(), RpcError> {
        self.svc
            .job_progress_external(&id, &step_label, progress_pct, &log_append)
            .await
    }

    async fn job_finish(
        &self,
        id: String,
        ok: bool,
        error: Option<String>,
    ) -> Result<(), RpcError> {
        self.svc
            .job_finish_external(&id, ok, error.as_deref())
            .await
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
        self.svc
            .agent_config_view(&self.hostname, &self.version)
            .await
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
        self.svc
            .web_user_create(username, email, password, role)
            .await
    }
    async fn web_user_set_password(
        &self,
        user_id: i64,
        new_password: String,
        current_password: Option<String>,
    ) -> Result<(), RpcError> {
        self.svc
            .web_user_set_password(user_id, new_password, current_password)
            .await
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
        self.svc
            .web_revoke_hosting_access(user_id, hosting_id)
            .await
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
    async fn monitor_overview(&self) -> Result<Vec<hyperion_types::MonitorOverviewItem>, RpcError> {
        self.svc.monitor_overview().await
    }
    async fn avatar_filename(&self, user_id: i64) -> Result<Option<String>, RpcError> {
        self.svc.avatar_filename(user_id).await
    }
    async fn avatar_set(&self, user_id: i64, filename: Option<String>) -> Result<(), RpcError> {
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
    async fn email_change_confirm(&self, user_id: i64, code: String) -> Result<(), RpcError> {
        self.svc.email_change_confirm(user_id, code).await
    }
    async fn email_change_cancel(&self, user_id: i64) -> Result<(), RpcError> {
        self.svc.email_change_cancel(user_id).await
    }
    async fn monitor_get(
        &self,
        sel: HostingSelector,
    ) -> Result<
        (
            hyperion_types::MonitorConfigView,
            hyperion_types::MonitorHistory,
        ),
        RpcError,
    > {
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
        mode: hyperion_types::BackupRestoreMode,
    ) -> Result<(), RpcError> {
        self.svc.backup_restore(sel, archive_path, mode).await
    }

    async fn backup_fetch_chunk(
        &self,
        backup_id: i64,
        offset: u64,
        len: u32,
    ) -> Result<(String, u64, String, bool), RpcError> {
        self.svc.backup_fetch_chunk(backup_id, offset, len).await
    }

    async fn backup_restore_as_new(
        &self,
        sel: HostingSelector,
        archive_path: String,
        new_domain: String,
    ) -> Result<(String, String), RpcError> {
        self.svc
            .backup_restore_as_new(sel, archive_path, new_domain)
            .await
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

    async fn cron_replace(&self, sel: HostingSelector, body: String) -> Result<(), RpcError> {
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
        prior_node_id: Option<String>,
        prior_secret: Option<String>,
    ) -> Result<(String, String, Option<String>), RpcError> {
        let (effective_node_id, secret) = self
            .svc
            .enroll_consume(
                token,
                caller_ip,
                node_id,
                label,
                agent_version,
                public_ip,
                prior_node_id,
                prior_secret,
            )
            .await?;
        Ok((effective_node_id, secret, self.svc.master_rpc_pubkey_b64()))
    }

    async fn node_heartbeat(
        &self,
        node_id: String,
        secret: String,
        agent_version: String,
        tls_spki_pin: Option<String>,
    ) -> Result<Option<String>, RpcError> {
        self.svc
            .node_heartbeat(node_id, secret, agent_version, tls_spki_pin)
            .await?;
        Ok(self.svc.master_rpc_pubkey_b64())
    }

    async fn nodes_list(&self) -> Result<Vec<NodeSummary>, RpcError> {
        self.svc.nodes_list().await
    }

    async fn cert_overview(&self) -> Result<Vec<hyperion_types::CertOverviewItem>, RpcError> {
        self.svc.cert_overview().await
    }

    async fn node_set_label(&self, node_id: String, label: String) -> Result<(), RpcError> {
        self.svc.node_set_label(&node_id, &label).await
    }

    async fn node_set_drain(
        &self,
        node_id: String,
        drain: bool,
        reason: String,
        actor_uid: i64,
    ) -> Result<(), RpcError> {
        self.svc
            .node_set_drain(&node_id, drain, &reason, actor_uid)
            .await
    }

    async fn node_remove(
        &self,
        node_id: String,
        force: bool,
        actor_uid: i64,
    ) -> Result<(bool, i64), RpcError> {
        self.svc.node_remove(&node_id, force, actor_uid).await
    }

    async fn node_reassign_hostings(
        &self,
        from_node_id: String,
        to_node_id: String,
    ) -> Result<i64, RpcError> {
        self.svc
            .node_reassign_hostings(&from_node_id, &to_node_id)
            .await
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

    async fn sftp_status(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::SftpStatus, RpcError> {
        self.svc.sftp_status(sel).await
    }

    async fn sftp_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
        public_keys: Vec<String>,
    ) -> Result<hyperion_types::SftpStatus, RpcError> {
        self.svc.sftp_set(sel, enabled, public_keys).await
    }

    async fn ban_list(
        &self,
        hosting_id: Option<String>,
    ) -> Result<Vec<hyperion_types::IpBanWire>, RpcError> {
        self.svc.ban_list(hosting_id).await
    }

    async fn ban_add(
        &self,
        ip: String,
        hosting_id: Option<String>,
        reason: String,
        ttl_secs: i64,
        source: String,
    ) -> Result<(), RpcError> {
        self.svc
            .ban_add(ip, hosting_id, reason, ttl_secs, source)
            .await
    }

    async fn ban_remove(&self, ip: String) -> Result<(), RpcError> {
        self.svc.ban_remove(ip).await
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
    async fn profile_usage(&self, id: i64) -> Result<Vec<String>, RpcError> {
        self.svc.profile_usage(id).await
    }
    async fn profile_apply(
        &self,
        sel: HostingSelector,
        profile_id: i64,
        skip_wp_items: bool,
        profile: Option<hyperion_types::HostingProfile>,
    ) -> Result<ProfileApply, RpcError> {
        self.svc
            .profile_apply(sel, profile_id, skip_wp_items, profile)
            .await
    }
    async fn profile_get_apply(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<ProfileApply>, RpcError> {
        self.svc.profile_get_apply(sel).await
    }
    async fn profile_wp_item_install(
        &self,
        sel: HostingSelector,
        item_kind: String,
        line: String,
    ) -> Result<(String, bool), RpcError> {
        self.svc
            .profile_wp_item_install(sel, &item_kind, &line)
            .await
    }
}

#[cfg(test)]
mod repin_tests {
    use super::*;

    #[tokio::test]
    async fn repin_clears_pubkey_preserving_other_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node-id.json");
        let original = serde_json::json!({
            "node_id": "node_abc",
            "master_url": "https://m",
            "secret": "s3cr3t",
            "enrolled_at": 1_700_000_000_i64,
            "master_rpc_pubkey": "PINNED_KEY"
        });
        tokio::fs::write(&path, serde_json::to_vec(&original).expect("ser"))
            .await
            .expect("write");

        let cleared = clear_pinned_pubkey_in_file(&path).await.expect("clear");
        assert_eq!(cleared.as_deref(), Some("PINNED_KEY"));

        let after: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.expect("read")).expect("parse");
        assert!(after["master_rpc_pubkey"].is_null(), "pubkey nulled");
        // Every other field survives untouched.
        assert_eq!(after["node_id"], "node_abc");
        assert_eq!(after["secret"], "s3cr3t");
        assert_eq!(after["master_url"], "https://m");
        assert_eq!(after["enrolled_at"], 1_700_000_000_i64);

        // Idempotent: a second clear finds nothing pinned.
        let again = clear_pinned_pubkey_in_file(&path).await.expect("clear2");
        assert_eq!(again, None);
    }
}
