//! Unix-socket RPC server.
//!
//! Listens on a path, dispatches each frame through an `Arc<dyn AgentApi>`.
//! One request/response per connection. The socket is set to mode 0660 on
//! bind; deployment is expected to place it in a group (e.g. `hyperion-admin`)
//! whose members are authorized callers.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use hyperion_rpc::codec::{read_frame, write_frame, Request, Response};
use hyperion_rpc::AgentApi;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Server {
    listener: UnixListener,
    api: Arc<dyn AgentApi>,
    socket_path: PathBuf,
}

impl Server {
    /// Bind a server. Removes any stale socket file at `path`. Sets
    /// permissions to 0660 (root + admin group access).
    pub async fn bind(path: &Path, api: Arc<dyn AgentApi>) -> Result<Self, ServerError> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(path)?;
        let perms = std::fs::Permissions::from_mode(0o660);
        std::fs::set_permissions(path, perms)?;
        Ok(Self {
            listener,
            api,
            socket_path: path.to_owned(),
        })
    }

    /// Run forever, accepting and handling connections concurrently.
    pub async fn run(self) -> Result<(), ServerError> {
        loop {
            let (stream, _addr) = self.listener.accept().await?;
            let api = self.api.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, api).await {
                    error!(error=%e, "conn handler failed");
                }
            });
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

async fn handle_conn(mut stream: UnixStream, api: Arc<dyn AgentApi>) -> std::io::Result<()> {
    let req: Request = read_frame(&mut stream).await?;
    debug!(?req, "received request");
    let resp = dispatch(api, req).await;
    write_frame(&mut stream, &resp).await?;
    Ok(())
}

/// Public dispatcher. The Unix-socket handler uses it; the
/// remote-RPC HTTPS handler on the agent reuses it so behavior is
/// identical whether a request came in over the local socket or
/// over the master→node signed channel.
pub async fn dispatch(api: Arc<dyn AgentApi>, req: Request) -> Response {
    match req {
        Request::AgentInfo => match api.agent_info().await {
            Ok(v) => Response::AgentInfo(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingCreate(r) => match api.hosting_create(r).await {
            Ok(v) => Response::HostingCreate(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingList => match api.hosting_list().await {
            Ok(v) => Response::HostingList(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingGet(s) => match api.hosting_get(s).await {
            Ok(v) => Response::HostingGet(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingDelete { sel, opts } => match api.hosting_delete(sel, opts).await {
            Ok(_) => Response::HostingDelete,
            Err(e) => Response::Error(e),
        },
        Request::HostingSetLimits { sel, limits } => {
            match api.hosting_set_limits(sel, limits).await {
                Ok(l) => Response::HostingSetLimits(l),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingGetLimits(sel) => match api.hosting_get_limits(sel).await {
            Ok(l) => Response::HostingGetLimits(l),
            Err(e) => Response::Error(e),
        },
        Request::HostingSuspend { sel, reason } => match api.hosting_suspend(sel, reason).await {
            Ok(_) => Response::HostingSuspend,
            Err(e) => Response::Error(e),
        },
        Request::HostingResume(sel) => match api.hosting_resume(sel).await {
            Ok(_) => Response::HostingResume,
            Err(e) => Response::Error(e),
        },
        Request::HostingSetPhpVersion { sel, version } => {
            match api.hosting_set_php_version(sel, version).await {
                Ok(v) => Response::HostingSetPhpVersion(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::TrashList => match api.trash_list().await {
            Ok(v) => Response::TrashList(v),
            Err(e) => Response::Error(e),
        },
        Request::TrashRestore(sel) => match api.trash_restore(sel).await {
            Ok(()) => Response::TrashRestore,
            Err(e) => Response::Error(e),
        },
        Request::TrashPurge(sel) => match api.trash_purge(sel).await {
            Ok(()) => Response::TrashPurge,
            Err(e) => Response::Error(e),
        },
        Request::HostingSetVhostOptions {
            sel,
            options,
            basic_auth_password,
        } => match api
            .hosting_set_vhost_options(sel, options, basic_auth_password)
            .await
        {
            Ok(v) => Response::HostingSetVhostOptions(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingSetWpDebug { sel, enabled, log, display } => {
            match api.hosting_set_wp_debug(sel, enabled, log, display).await {
                Ok(v) => Response::HostingSetWpDebug(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingSetRedis { sel, enabled } => {
            match api.hosting_set_redis(sel, enabled).await {
                Ok(v) => Response::HostingSetRedis(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingRotateRedisPassword { sel } => {
            match api.hosting_rotate_redis_password(sel).await {
                Ok(v) => Response::HostingRotateRedisPassword(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingRotateWpDebugLog { sel } => {
            match api.hosting_rotate_wp_debug_log(sel).await {
                Ok(()) => Response::HostingRotateWpDebugLog,
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingUsage { sel, limit } => match api.hosting_usage(sel, limit).await {
            Ok(v) => Response::HostingUsage(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingSetExpiry { sel, expiry } => {
            match api.hosting_set_expiry(sel, expiry).await {
                Ok(v) => Response::HostingSetExpiry(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingGetExpiry(sel) => match api.hosting_get_expiry(sel).await {
            Ok(v) => Response::HostingGetExpiry(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingClearExpiry(sel) => match api.hosting_clear_expiry(sel).await {
            Ok(_) => Response::HostingClearExpiry,
            Err(e) => Response::Error(e),
        },
        Request::HostingKvSet { hosting_id, key, value } => {
            match api.hosting_kv_set(hosting_id, key, value).await {
                Ok(_) => Response::HostingKvSet,
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingKvList { hosting_id } => match api.hosting_kv_list(hosting_id).await {
            Ok(v) => Response::HostingKvList(v),
            Err(e) => Response::Error(e),
        },
        Request::UpcomingExpiries { within_seconds } => {
            match api.upcoming_expiries(within_seconds).await {
                Ok(v) => Response::UpcomingExpiries(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::SchedulerTick => match api.scheduler_tick().await {
            Ok(n) => Response::SchedulerTick {
                actions_processed: n,
            },
            Err(e) => Response::Error(e),
        },
        Request::BackupNow { sel } => match api.backup_now(sel).await {
            Ok(v) => Response::BackupNow(v),
            Err(e) => Response::Error(e),
        },
        Request::BackupList { sel, limit } => match api.backup_list(sel, limit).await {
            Ok(v) => Response::BackupList(v),
            Err(e) => Response::Error(e),
        },
        Request::InviteCreate { label, ttl_secs } => {
            match api.invite_create(label, ttl_secs).await {
                Ok(v) => Response::InviteCreate(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::InviteList => match api.invite_list().await {
            Ok(v) => Response::InviteList(v),
            Err(e) => Response::Error(e),
        },
        Request::InviteRevoke { token_hash } => match api.invite_revoke(token_hash).await {
            Ok(_) => Response::InviteRevoke,
            Err(e) => Response::Error(e),
        },
        Request::AuditList { limit } => match api.audit_list(limit).await {
            Ok(v) => Response::AuditList(v),
            Err(e) => Response::Error(e),
        },
        Request::WebSessionInsert {
            sid,
            user_id,
            ip,
            user_agent,
        } => match api.web_session_insert(sid, user_id, ip, user_agent).await {
            Ok(()) => Response::WebSessionAck,
            Err(e) => Response::Error(e),
        },
        Request::WebSessionTouch { sid } => match api.web_session_touch(sid).await {
            Ok(v) => Response::WebSessionTouch(v),
            Err(e) => Response::Error(e),
        },
        Request::WebSessionList { user_id } => match api.web_session_list(user_id).await {
            Ok(v) => Response::WebSessionList(v),
            Err(e) => Response::Error(e),
        },
        Request::WebSessionRevoke { sid, revoked_by } => {
            match api.web_session_revoke(sid, revoked_by).await {
                Ok(_) => Response::WebSessionAck,
                Err(e) => Response::Error(e),
            }
        }
        Request::BackupTargetList => match api.backup_target_list().await {
            Ok(v) => Response::BackupTargetList(v),
            Err(e) => Response::Error(e),
        },
        Request::BackupTargetUpsert {
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
        } => match api
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
        {
            Ok(id) => Response::BackupTargetUpserted { id },
            Err(e) => Response::Error(e),
        },
        Request::BackupTargetDelete { id } => match api.backup_target_delete(id).await {
            Ok(()) => Response::BackupTargetDeleted,
            Err(e) => Response::Error(e),
        },
        Request::BackupTargetProbe { id } => match api.backup_target_probe(id).await {
            Ok(v) => Response::BackupTargetProbe(v),
            Err(e) => Response::Error(e),
        },
        Request::QuotaGet { hosting } => match api.quota_get(hosting).await {
            Ok(v) => Response::QuotaGet(v),
            Err(e) => Response::Error(e),
        },
        Request::QuotaSet {
            hosting,
            disk_soft_kib,
            disk_hard_kib,
            mem_limit_mib,
            bw_soft_mib,
            bw_hard_mib,
        } => match api
            .quota_set(
                hosting,
                disk_soft_kib,
                disk_hard_kib,
                mem_limit_mib,
                bw_soft_mib,
                bw_hard_mib,
            )
            .await
        {
            Ok(v) => Response::QuotaApplied(v),
            Err(e) => Response::Error(e),
        },
        Request::AuditVerifyChain => match api.audit_verify_chain().await {
            Ok((ok, rows_checked, message)) => Response::AuditVerifyChain {
                ok,
                rows_checked,
                message,
            },
            Err(e) => Response::Error(e),
        },
        Request::CertIssue { domain } => match api.cert_issue(domain).await {
            Ok(v) => Response::CertIssue(v),
            Err(e) => Response::Error(e),
        },
        Request::CertRenewAll => match api.cert_renew_all().await {
            Ok(v) => Response::CertRenewAll(v),
            Err(e) => Response::Error(e),
        },
        Request::WpInstall { sel, req } => match api.wp_install(sel, req).await {
            Ok(v) => Response::WpInstall(v),
            Err(e) => Response::Error(e),
        },
        Request::WpStatus { sel } => match api.wp_status(sel).await {
            Ok(v) => Response::WpStatus(v),
            Err(e) => Response::Error(e),
        },
        Request::DnsCheck { domain } => match api.dns_check(domain).await {
            Ok(v) => Response::DnsCheck(v),
            Err(e) => Response::Error(e),
        },
        Request::DnsSpfCheck { domain } => match api.dns_spf_check(domain).await {
            Ok(v) => Response::DnsSpfCheck(v),
            Err(e) => Response::Error(e),
        },
        Request::CertIssueAcme { sel, req } => match api.cert_issue_acme(sel, req).await {
            Ok(v) => Response::CertIssueAcme(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingStats { sel } => match api.hosting_stats(sel).await {
            Ok(v) => Response::HostingStats(v),
            Err(e) => Response::Error(e),
        },
        Request::NodeStats => match api.node_stats().await {
            Ok(v) => Response::NodeStats(v),
            Err(e) => Response::Error(e),
        },
        Request::ClusterStats => match api.cluster_stats().await {
            Ok(v) => Response::ClusterStats(v),
            Err(e) => Response::Error(e),
        },
        Request::NodeMetricsHistory { limit } => match api.node_metrics_history(limit).await {
            Ok(v) => Response::NodeMetricsHistory(v),
            Err(e) => Response::Error(e),
        },
        Request::SetHostingAcmeEmail { sel, email } => {
            match api.set_hosting_acme_email(sel, email).await {
                Ok(()) => Response::SetHostingAcmeEmail,
                Err(e) => Response::Error(e),
            }
        }
        Request::ServicesHealth => match api.services_health().await {
            Ok(v) => Response::ServicesHealth(v),
            Err(e) => Response::Error(e),
        },
        Request::FirewallList => match api.firewall_list().await {
            Ok(v) => Response::FirewallList(v),
            Err(e) => Response::Error(e),
        },
        Request::FirewallApplyTemplate { template_id } => {
            match api.firewall_apply_template(template_id).await {
                Ok((applied, output, error)) => Response::FirewallTemplateApplied {
                    applied,
                    output,
                    error,
                },
                Err(e) => Response::Error(e),
            }
        }
        Request::ServiceRestart { name } => match api.service_restart(name).await {
            Ok(()) => Response::ServiceRestart,
            Err(e) => Response::Error(e),
        },
        Request::ServiceInstall { name } => match api.service_install(name).await {
            Ok(()) => Response::ServiceInstall,
            Err(e) => Response::Error(e),
        },
        Request::ServiceInstallStatus => match api.service_install_status().await {
            Ok(s) => Response::ServiceInstallStatus(s),
            Err(e) => Response::Error(e),
        },
        Request::WpAssetUpload {
            kind,
            original_name,
            bytes_b64,
            uploaded_by,
        } => {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(bytes_b64.as_bytes()) {
                Ok(bytes) => match api
                    .wp_asset_upload(kind, original_name, bytes, uploaded_by)
                    .await
                {
                    Ok((id, deduped)) => Response::WpAssetUpload { id, deduped },
                    Err(e) => Response::Error(e),
                },
                Err(e) => Response::Error(hyperion_rpc::RpcError::Validation {
                    message: format!("bytes_b64 decode: {e}"),
                }),
            }
        }
        Request::WpAssetList => match api.wp_asset_list().await {
            Ok(v) => Response::WpAssetList(v),
            Err(e) => Response::Error(e),
        },
        Request::WpAssetDelete { id } => match api.wp_asset_delete(id).await {
            Ok(()) => Response::WpAssetDelete,
            Err(e) => Response::Error(e),
        },
        Request::WpInstallFromAsset {
            sel,
            asset_id,
            activate,
        } => match api.wp_install_from_asset(sel, asset_id, activate).await {
            Ok((kind, original_name)) => Response::WpInstallFromAsset {
                kind,
                original_name,
            },
            Err(e) => Response::Error(e),
        },
        Request::WpAssetReplace {
            id,
            original_name,
            bytes_b64,
            uploaded_by,
        } => {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(bytes_b64.as_bytes()) {
                Ok(bytes) => match api
                    .wp_asset_replace(id, original_name, bytes, uploaded_by)
                    .await
                {
                    Ok(()) => Response::WpAssetReplace,
                    Err(e) => Response::Error(e),
                },
                Err(e) => Response::Error(hyperion_rpc::RpcError::Validation {
                    message: format!("bytes_b64 decode: {e}"),
                }),
            }
        }
        Request::WpAssetReinstallAll {
            asset_id,
            force_activate,
        } => match api
            .wp_asset_reinstall_all(asset_id, force_activate)
            .await
        {
            Ok((installed_ok, installed_failed, failure_tail)) => {
                Response::WpAssetReinstallAll {
                    installed_ok,
                    installed_failed,
                    failure_tail,
                }
            }
            Err(e) => Response::Error(e),
        },
        Request::WpThemeList { hosting } => match api.wp_theme_list(hosting).await {
            Ok(t) => Response::WpThemeList(t),
            Err(e) => Response::Error(e),
        },
        Request::WpThemeAction { sel, slug, action } => {
            match api.wp_theme_action(sel, slug, action).await {
                Ok(r) => Response::WpThemeAction(r),
                Err(e) => Response::Error(e),
            }
        }
        Request::WpVulnScan { hosting } => match api.wp_vuln_scan(hosting).await {
            Ok(r) => Response::WpVulnScan(r),
            Err(e) => Response::Error(e),
        },
        Request::NodeUpdateRun { do_apt, do_hyperion } => {
            match api.node_update_run(do_apt, do_hyperion).await {
                Ok(started_at) => Response::NodeUpdateRun { started_at },
                Err(e) => Response::Error(e),
            }
        }
        Request::NodeUpdateStatus => match api.node_update_status().await {
            Ok(s) => Response::NodeUpdateStatus(s),
            Err(e) => Response::Error(e),
        },
        Request::AgentConfigUpdate { section, fields } => {
            match api.agent_config_update(section, fields).await {
                Ok(()) => Response::AgentConfigUpdate,
                Err(e) => Response::Error(e),
            }
        }
        Request::UpdateCheck { force_refresh } => match api.update_check(force_refresh).await {
            Ok(v) => Response::UpdateCheck(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingExport { hosting } => match api.hosting_export(hosting).await {
            Ok(v) => Response::HostingExport(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingMigrationFetchBundleFile { bundle_id, filename } => {
            match api
                .hosting_migration_fetch_bundle_file(bundle_id, filename)
                .await
            {
                Ok(bytes_b64) => Response::HostingMigrationFetchBundleFile { bytes_b64 },
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingImport { manifest_path } => match api.hosting_import(manifest_path).await {
            Ok(v) => Response::HostingImport(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingImportFromUrl {
            base_url,
            token,
            override_domain,
            override_aliases,
        } => {
            match api
                .hosting_import_from_url(base_url, token, override_domain, override_aliases)
                .await
            {
                Ok(v) => Response::HostingImportFromUrl(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::EmailLogList { hosting_id, limit } => {
            match api.email_log_list(hosting_id, limit).await {
                Ok(v) => Response::EmailLogList(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::SiteEmailLogList { system_user, limit } => {
            match api.site_email_log_list(system_user, limit).await {
                Ok(v) => Response::SiteEmailLogList(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::FtpAccountsList => match api.ftp_accounts_list().await {
            Ok(v) => Response::FtpAccountsList(v),
            Err(e) => Response::Error(e),
        },
        Request::FtpVerifyLogin { user, password } => {
            match api.ftp_verify_login(user, password).await {
                Ok(accepted) => Response::FtpVerifyLogin { accepted },
                Err(e) => Response::Error(e),
            }
        }
        Request::EmailSmtpAutodetect => match api.email_smtp_autodetect().await {
            Ok(v) => Response::EmailSmtpAutodetect(v),
            Err(e) => Response::Error(e),
        },
        Request::MtaDiagnostics => match api.mta_diagnostics().await {
            Ok(v) => Response::MtaDiagnostics(v),
            Err(e) => Response::Error(e),
        },
        Request::MtaReconfigure => match api.mta_reconfigure().await {
            Ok(mode) => Response::MtaReconfigure { mode },
            Err(e) => Response::Error(e),
        },
        Request::MtaTestSend { to } => match api.mta_test_send(to).await {
            Ok((exit_code, output)) => Response::MtaTestSend { exit_code, output },
            Err(e) => Response::Error(e),
        },
        Request::MtaQueueFlush => match api.mta_queue_flush().await {
            Ok((attempted, output)) => Response::MtaQueueFlush { attempted, output },
            Err(e) => Response::Error(e),
        },
        Request::MtaQueueClear => match api.mta_queue_clear().await {
            Ok((cleared, output)) => Response::MtaQueueClear { cleared, output },
            Err(e) => Response::Error(e),
        },
        Request::PanelProvision { hostname, skip_dns_check } => {
            match api.panel_provision(hostname, skip_dns_check).await {
                Ok((status, message, panel_url)) => Response::PanelProvision {
                    status,
                    message,
                    panel_url,
                },
                Err(e) => Response::Error(e),
            }
        }
        Request::PanelCertStatus => match api.panel_cert_status().await {
            Ok(v) => Response::PanelCertStatus(v),
            Err(e) => Response::Error(e),
        },
        Request::RemountUsrRw => match api.remount_usr_rw().await {
            Ok((success, message)) => Response::RemountUsrRw { success, message },
            Err(e) => Response::Error(e),
        },
        Request::FsDiagnoseAndFix { dry_run } => match api.fs_diagnose_and_fix(dry_run).await {
            Ok(d) => Response::FsDiagnoseAndFix(d),
            Err(e) => Response::Error(e),
        },
        Request::JobGet { id } => match api.job_get(id).await {
            Ok(v) => Response::JobGet(v),
            Err(e) => Response::Error(e),
        },
        Request::JobList { kind, state, limit } => match api.job_list(kind, state, limit).await {
            Ok(v) => Response::JobList(v),
            Err(e) => Response::Error(e),
        },
        Request::JobStart {
            kind,
            target,
            payload_json,
            actor_label,
            actor_uid,
        } => match api
            .job_start(kind, target, payload_json, actor_label, actor_uid)
            .await
        {
            Ok(job_id) => Response::JobStarted { job_id },
            Err(e) => Response::Error(e),
        },
        Request::JobProgress {
            id,
            step_label,
            progress_pct,
            log_append,
        } => match api
            .job_progress(id, step_label, progress_pct, log_append)
            .await
        {
            Ok(()) => Response::JobAck,
            Err(e) => Response::Error(e),
        },
        Request::JobFinish { id, ok, error } => match api.job_finish(id, ok, error).await {
            Ok(()) => Response::JobAck,
            Err(e) => Response::Error(e),
        },
        Request::WpPluginList { hosting } => match api.wp_plugin_list(hosting).await {
            Ok(v) => Response::WpPluginList(v),
            Err(e) => Response::Error(e),
        },
        Request::WpPluginAction { hosting, slug, action } => {
            match api.wp_plugin_action(hosting, slug, action).await {
                Ok(v) => Response::WpPluginAction(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::BackupDelete { backup_id } => match api.backup_delete(backup_id).await {
            Ok(()) => Response::BackupDelete,
            Err(e) => Response::Error(e),
        },
        Request::AgentConfigView => match api.agent_config_view().await {
            Ok(v) => Response::AgentConfigView(v),
            Err(e) => Response::Error(e),
        },
        Request::EmailSendTest { to } => match api.email_send_test(to).await {
            Ok(code) => Response::EmailSendTest { smtp_code: code },
            Err(e) => Response::Error(e),
        },
        Request::WebLogin { username, password, client_ip } => {
            match api.web_login(username, password, client_ip).await {
                Ok(v) => Response::WebLogin(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::WebVerify2fa { user_id, code } => match api.web_verify_2fa(user_id, code).await {
            Ok(v) => Response::WebVerify2fa(v),
            Err(e) => Response::Error(e),
        },
        Request::WebUserList => match api.web_user_list().await {
            Ok(v) => Response::WebUserList(v),
            Err(e) => Response::Error(e),
        },
        Request::WebUserGet { id } => match api.web_user_get(id).await {
            Ok(v) => Response::WebUserGet(v),
            Err(e) => Response::Error(e),
        },
        Request::WebUserCreate { username, email, password, role } => {
            match api.web_user_create(username, email, password, role).await {
                Ok(id) => Response::WebUserCreate { id },
                Err(e) => Response::Error(e),
            }
        }
        Request::WebUserSetPassword { user_id, new_password } => {
            match api.web_user_set_password(user_id, new_password).await {
                Ok(()) => Response::WebUserSetPassword,
                Err(e) => Response::Error(e),
            }
        }
        Request::WebUserSetRole { user_id, role } => match api.web_user_set_role(user_id, role).await
        {
            Ok(()) => Response::WebUserSetRole,
            Err(e) => Response::Error(e),
        },
        Request::WebUserSetLocked { user_id, locked, reason } => {
            match api.web_user_set_locked(user_id, locked, reason).await {
                Ok(()) => Response::WebUserSetLocked,
                Err(e) => Response::Error(e),
            }
        }
        Request::WebUserDelete { user_id } => match api.web_user_delete(user_id).await {
            Ok(()) => Response::WebUserDelete,
            Err(e) => Response::Error(e),
        },
        Request::Web2faEnrollStart { user_id } => match api.web_2fa_enroll_start(user_id).await {
            Ok(v) => Response::Web2faEnrollStart(v),
            Err(e) => Response::Error(e),
        },
        Request::Web2faConfirmEnroll { user_id, code } => {
            match api.web_2fa_confirm_enroll(user_id, code).await {
                Ok(ok) => Response::Web2faConfirmEnroll { ok },
                Err(e) => Response::Error(e),
            }
        }
        Request::Web2faDisable { user_id } => match api.web_2fa_disable(user_id).await {
            Ok(()) => Response::Web2faDisable,
            Err(e) => Response::Error(e),
        },
        Request::WebGrantHostingAccess { user_id, hosting_id, level, granted_by } => {
            match api
                .web_grant_hosting_access(user_id, hosting_id, level, granted_by)
                .await
            {
                Ok(()) => Response::WebGrantHostingAccess,
                Err(e) => Response::Error(e),
            }
        }
        Request::WebRevokeHostingAccess { user_id, hosting_id } => {
            match api.web_revoke_hosting_access(user_id, hosting_id).await {
                Ok(()) => Response::WebRevokeHostingAccess,
                Err(e) => Response::Error(e),
            }
        }
        Request::WebListHostingAccess { hosting_id } => {
            match api.web_list_hosting_access(hosting_id).await {
                Ok(v) => Response::WebListHostingAccess(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingFileList { sel, rel_path } => {
            match api.hosting_file_list(sel, rel_path).await {
                Ok((rel_path, entries)) => Response::HostingFileList { rel_path, entries },
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingFileRead { sel, rel_path } => {
            match api.hosting_file_read(sel, rel_path).await {
                Ok(v) => Response::HostingFileRead(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingFileDownload { sel, rel_path } => {
            match api.hosting_file_download(sel, rel_path).await {
                Ok((rel_path, bytes_b64, mime)) => Response::HostingFileDownload {
                    rel_path,
                    bytes_b64,
                    mime,
                },
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingFileWrite { sel, rel_path, bytes_b64 } => {
            match api.hosting_file_write(sel, rel_path, bytes_b64).await {
                Ok(()) => Response::HostingFileWrite,
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingFileDelete { sel, rel_path } => {
            match api.hosting_file_delete(sel, rel_path).await {
                Ok(()) => Response::HostingFileDelete,
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingFileMkdir { sel, rel_path } => {
            match api.hosting_file_mkdir(sel, rel_path).await {
                Ok(()) => Response::HostingFileMkdir,
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingFileRename { sel, from, to } => {
            match api.hosting_file_rename(sel, from, to).await {
                Ok(()) => Response::HostingFileRename,
                Err(e) => Response::Error(e),
            }
        }
        Request::MonitorOverview => match api.monitor_overview().await {
            Ok(items) => Response::MonitorOverview(items),
            Err(e) => Response::Error(e),
        },
        Request::AvatarFilename { user_id } => match api.avatar_filename(user_id).await {
            Ok(f) => Response::AvatarFilename(f),
            Err(e) => Response::Error(e),
        },
        Request::AvatarSet { user_id, filename } => {
            match api.avatar_set(user_id, filename).await {
                Ok(()) => Response::AvatarSet,
                Err(e) => Response::Error(e),
            }
        }
        Request::EmailChangeRequest { user_id, new_email, current_password } => {
            match api
                .email_change_request(user_id, new_email, current_password)
                .await
            {
                Ok(masked_to) => Response::EmailChangeRequest { masked_to },
                Err(e) => Response::Error(e),
            }
        }
        Request::EmailChangeConfirm { user_id, code } => {
            match api.email_change_confirm(user_id, code).await {
                Ok(()) => Response::EmailChangeConfirm,
                Err(e) => Response::Error(e),
            }
        }
        Request::EmailChangeCancel { user_id } => {
            match api.email_change_cancel(user_id).await {
                Ok(()) => Response::EmailChangeCancel,
                Err(e) => Response::Error(e),
            }
        }
        Request::MonitorGet { sel } => match api.monitor_get(sel).await {
            Ok((config, history)) => Response::MonitorGet { config, history },
            Err(e) => Response::Error(e),
        },
        Request::MonitorSet {
            sel, enabled, url_path, interval_secs, alert_after_fails,
            alert_email, alert_slack_webhook, alert_webhook_url,
        } => match api
            .monitor_set(
                sel, enabled, url_path, interval_secs, alert_after_fails,
                alert_email, alert_slack_webhook, alert_webhook_url,
            )
            .await
        {
            Ok(()) => Response::MonitorSet,
            Err(e) => Response::Error(e),
        },
        Request::MonitorProbeNow { sel } => match api.monitor_probe_now(sel).await {
            Ok(s) => Response::MonitorProbeNow(s),
            Err(e) => Response::Error(e),
        },
        Request::MonitorTick => match api.monitor_tick().await {
            Ok(n) => Response::MonitorTick { sampled: n },
            Err(e) => Response::Error(e),
        },
        Request::StatsTick => match api.stats_tick().await {
            Ok(n) => Response::StatsTick {
                hostings_sampled: n,
            },
            Err(e) => Response::Error(e),
        },
        Request::BackupRestore { sel, archive_path, mode } => {
            match api.backup_restore(sel, archive_path, mode).await {
                Ok(_) => Response::BackupRestore,
                Err(e) => Response::Error(e),
            }
        }
        Request::BackupFetchChunk { backup_id, offset, len } => {
            match api.backup_fetch_chunk(backup_id, offset, len).await {
                Ok((data_b64, total_size, filename, eof)) => Response::BackupFetchChunk {
                    data_b64,
                    total_size,
                    filename,
                    eof,
                },
                Err(e) => Response::Error(e),
            }
        }
        Request::BackupRestoreAsNew { sel, archive_path, new_domain } => {
            match api.backup_restore_as_new(sel, archive_path, new_domain).await {
                Ok((hosting_id, domain)) => Response::BackupRestoreAsNew { hosting_id, domain },
                Err(e) => Response::Error(e),
            }
        }
        Request::NotificationsFeed { user_id, limit } => {
            match api.notifications_feed(user_id, limit).await {
                Ok(f) => Response::NotificationsFeed(f),
                Err(e) => Response::Error(e),
            }
        }
        Request::NotificationsMarkRead {
            user_id,
            notification_id,
        } => match api
            .notifications_mark_read(user_id, notification_id)
            .await
        {
            Ok(()) => Response::NotificationsMarkRead,
            Err(e) => Response::Error(e),
        },
        Request::NotificationsMarkAllRead { user_id } => {
            match api.notifications_mark_all_read(user_id).await {
                Ok(n) => Response::NotificationsMarkAllRead { marked: n },
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingLogs {
            sel,
            log_kind,
            lines,
        } => match api.hosting_logs(sel, log_kind, lines).await {
            Ok(s) => Response::HostingLogs(s),
            Err(e) => Response::Error(e),
        },
        Request::CronList { sel } => match api.cron_list(sel).await {
            Ok(s) => Response::CronList(s),
            Err(e) => Response::Error(e),
        },
        Request::CronReplace { sel, body } => match api.cron_replace(sel, body).await {
            Ok(_) => Response::CronReplace,
            Err(e) => Response::Error(e),
        },
        Request::EnrollConsume {
            token,
            caller_ip,
            node_id,
            label,
            agent_version,
            public_ip,
        } => match api
            .enroll_consume(token, caller_ip, node_id, label, agent_version, public_ip)
            .await
        {
            Ok((secret, master_rpc_pubkey)) => Response::EnrollConsume {
                secret,
                master_rpc_pubkey,
            },
            Err(e) => Response::Error(e),
        },
        Request::NodeHeartbeat {
            node_id,
            secret,
            agent_version,
        } => match api.node_heartbeat(node_id, secret, agent_version).await {
            Ok(master_rpc_pubkey) => Response::NodeHeartbeat { master_rpc_pubkey },
            Err(e) => Response::Error(e),
        },
        Request::NodesList => match api.nodes_list().await {
            Ok(v) => Response::NodesList(v),
            Err(e) => Response::Error(e),
        },
        Request::CertOverview => match api.cert_overview().await {
            Ok(v) => Response::CertOverview(v),
            Err(e) => Response::Error(e),
        },
        Request::NodeSetLabel { node_id, label } => match api.node_set_label(node_id, label).await {
            Ok(()) => Response::NodeLabelUpdated,
            Err(e) => Response::Error(e),
        },
        Request::NodeSetDrain { node_id, drain, reason } => {
            // actor_uid is captured at the RPC boundary via the
            // master_rpc envelope's signing identity; for local
            // panel calls we pass 0 and the audit row will show
            // "system" — operator identity is captured separately
            // in the web layer's audit append.
            match api.node_set_drain(node_id, drain, reason, 0).await {
                Ok(()) => Response::NodeDrainUpdated,
                Err(e) => Response::Error(e),
            }
        }
        Request::NodeRemove { node_id, force } => {
            match api.node_remove(node_id, force, 0).await {
                Ok((removed, hostings_blocking)) => Response::NodeRemoved {
                    removed,
                    hostings_blocking,
                },
                Err(e) => Response::Error(e),
            }
        }
        Request::WpResetPassword {
            sel,
            wp_user,
            new_password,
        } => match api.wp_reset_password(sel, wp_user, new_password).await {
            Ok(_) => Response::WpResetPassword,
            Err(e) => Response::Error(e),
        },
        Request::DbResetPassword { sel, new_password } => {
            match api.db_reset_password(sel, new_password).await {
                Ok(_) => Response::DbResetPassword,
                Err(e) => Response::Error(e),
            }
        }
        Request::FtpSetPassword { sel, new_password } => {
            match api.ftp_set_password(sel, new_password).await {
                Ok(password) => Response::FtpSetPassword { password },
                Err(e) => Response::Error(e),
            }
        }
        Request::FtpDisable { sel } => match api.ftp_disable(sel).await {
            Ok(_) => Response::FtpDisable,
            Err(e) => Response::Error(e),
        },
        Request::SftpStatus { sel } => match api.sftp_status(sel).await {
            Ok(s) => Response::SftpStatus(s),
            Err(e) => Response::Error(e),
        },
        Request::SftpSet { sel, enabled, public_keys } => {
            match api.sftp_set(sel, enabled, public_keys).await {
                Ok(s) => Response::SftpSet(s),
                Err(e) => Response::Error(e),
            }
        }
        Request::DashboardAlerts => match api.dashboard_alerts().await {
            Ok(v) => Response::DashboardAlerts(v),
            Err(e) => Response::Error(e),
        },
        Request::ProfileList => match api.profile_list().await {
            Ok(v) => Response::ProfileList(v),
            Err(e) => Response::Error(e),
        },
        Request::ProfileGet { id } => match api.profile_get(id).await {
            Ok(v) => Response::ProfileGet(v),
            Err(e) => Response::Error(e),
        },
        Request::ProfileCreate(input) => match api.profile_create(input).await {
            Ok(v) => Response::ProfileCreate(v),
            Err(e) => Response::Error(e),
        },
        Request::ProfileUpdate { id, input } => match api.profile_update(id, input).await {
            Ok(v) => Response::ProfileUpdate(v),
            Err(e) => Response::Error(e),
        },
        Request::ProfileDelete { id } => match api.profile_delete(id).await {
            Ok(_) => Response::ProfileDelete,
            Err(e) => Response::Error(e),
        },
        Request::ProfileApply { sel, profile_id, skip_wp_items } => {
            match api.profile_apply(sel, profile_id, skip_wp_items).await {
                Ok(v) => Response::ProfileApply(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::ProfileGetApply { sel } => match api.profile_get_apply(sel).await {
            Ok(v) => Response::ProfileGetApply(v),
            Err(e) => Response::Error(e),
        },
        Request::ProfileWpItemInstall { sel, item_kind, line } => {
            match api.profile_wp_item_install(sel, item_kind, line).await {
                Ok((label, activated)) => Response::ProfileWpItemInstalled { label, activated },
                Err(e) => Response::Error(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hyperion_rpc::wire::{
        AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
    };
    use hyperion_rpc::{AuditEntryWire, RpcError};
    use hyperion_types::{
        BackupRunWire, CertInfo, CertIssueRequest, CertRenewResult, ClusterStats, DashboardAlert,
        DnsCheckResult, ExpiringHosting, HostingDetail, HostingExpiry, HostingLimits,
        HostingProfile, HostingStats, HostingSummary, HostingUsageBucket, NodeInviteMint,
        NodeInviteSummary, NodeStats, NodeSummary, ProfileApply, ProfileInput, SuspendReason,
        WpInstallRequest, WpInstallStatus,
    };
    use hyperion_validate::Domain;

    struct EchoApi;

    #[async_trait]
    impl AgentApi for EchoApi {
        async fn agent_info(&self) -> Result<AgentInfo, RpcError> {
            Ok(AgentInfo {
                hostname: "test".into(),
                version: "0".into(),
                schema_version: 1,
                hostings_count: 0,
                node_id: None,
                master_url: None,
                enrolled_at: None,
            })
        }
        async fn hosting_create(&self, _: HostingCreateReq) -> Result<HostingCreated, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError> {
            Ok(vec![])
        }
        async fn hosting_get(&self, _: HostingSelector) -> Result<HostingDetail, RpcError> {
            Err(RpcError::NotFound {
                kind: "hosting".into(),
                id: "x".into(),
            })
        }
        async fn hosting_delete(&self, _: HostingSelector, _: DeleteOpts) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_set_limits(
            &self,
            _: HostingSelector,
            l: HostingLimits,
        ) -> Result<HostingLimits, RpcError> {
            Ok(l)
        }
        async fn hosting_get_limits(&self, _: HostingSelector) -> Result<HostingLimits, RpcError> {
            Ok(HostingLimits::defaults())
        }
        async fn hosting_suspend(
            &self,
            _: HostingSelector,
            _: SuspendReason,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_resume(&self, _: HostingSelector) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_set_php_version(
            &self,
            _: HostingSelector,
            v: hyperion_types::PhpVersion,
        ) -> Result<hyperion_types::PhpVersion, RpcError> {
            Ok(v)
        }
        async fn trash_list(&self) -> Result<Vec<hyperion_types::TrashEntry>, RpcError> {
            Ok(vec![])
        }
        async fn trash_restore(&self, _: HostingSelector) -> Result<(), RpcError> {
            Ok(())
        }
        async fn trash_purge(&self, _: HostingSelector) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_set_vhost_options(
            &self,
            _: HostingSelector,
            options: hyperion_types::VhostOptions,
            _: Option<String>,
        ) -> Result<hyperion_types::VhostOptions, RpcError> {
            Ok(options)
        }
        async fn hosting_set_wp_debug(
            &self,
            _: HostingSelector,
            _: bool,
            _: bool,
            _: bool,
        ) -> Result<hyperion_types::WpExtras, RpcError> {
            Ok(hyperion_types::WpExtras::default())
        }
        async fn hosting_set_redis(
            &self,
            _: HostingSelector,
            _: bool,
        ) -> Result<hyperion_types::WpExtras, RpcError> {
            Ok(hyperion_types::WpExtras::default())
        }
        async fn hosting_rotate_redis_password(
            &self,
            _: HostingSelector,
        ) -> Result<hyperion_types::WpExtras, RpcError> {
            Ok(hyperion_types::WpExtras::default())
        }
        async fn hosting_rotate_wp_debug_log(
            &self,
            _: HostingSelector,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_usage(
            &self,
            _: HostingSelector,
            _: i64,
        ) -> Result<Vec<HostingUsageBucket>, RpcError> {
            Ok(vec![])
        }
        async fn audit_verify_chain(&self) -> Result<(bool, i64, String), RpcError> {
            Ok((true, 0, String::new()))
        }
        async fn backup_target_list(
            &self,
        ) -> Result<Vec<hyperion_types::BackupTargetView>, RpcError> {
            Ok(Vec::new())
        }
        async fn backup_target_upsert(
            &self,
            _: Option<i64>,
            _: String,
            _: String,
            _: String,
            _: String,
            _: String,
            _: String,
            _: Option<String>,
            _: Option<String>,
            _: i64,
            _: i64,
            _: i64,
            _: bool,
        ) -> Result<i64, RpcError> {
            Ok(1)
        }
        async fn backup_target_delete(&self, _: i64) -> Result<(), RpcError> {
            Ok(())
        }
        async fn backup_target_probe(
            &self,
            _: i64,
        ) -> Result<hyperion_types::BackupTargetProbe, RpcError> {
            Ok(hyperion_types::BackupTargetProbe::default())
        }
        async fn quota_get(
            &self,
            _: hyperion_rpc::HostingSelector,
        ) -> Result<hyperion_types::HostingQuotaReport, RpcError> {
            Ok(hyperion_types::HostingQuotaReport::default())
        }
        async fn quota_set(
            &self,
            _: hyperion_rpc::HostingSelector,
            _: i64,
            _: i64,
            _: i64,
            _: i64,
            _: i64,
        ) -> Result<hyperion_types::HostingQuotaView, RpcError> {
            Ok(hyperion_types::HostingQuotaView::default())
        }
        async fn web_session_insert(
            &self,
            _: String,
            _: i64,
            _: Option<String>,
            _: Option<String>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn web_session_touch(&self, _: String) -> Result<bool, RpcError> {
            Ok(true)
        }
        async fn web_session_list(
            &self,
            _: i64,
        ) -> Result<Vec<hyperion_types::WebSessionView>, RpcError> {
            Ok(Vec::new())
        }
        async fn web_session_revoke(
            &self,
            _: String,
            _: i64,
        ) -> Result<bool, RpcError> {
            Ok(true)
        }
        async fn audit_list(&self, _: i64) -> Result<Vec<AuditEntryWire>, RpcError> {
            Ok(vec![])
        }
        async fn hosting_set_expiry(
            &self,
            _: HostingSelector,
            e: HostingExpiry,
        ) -> Result<HostingExpiry, RpcError> {
            Ok(e)
        }
        async fn hosting_get_expiry(&self, _: HostingSelector) -> Result<HostingExpiry, RpcError> {
            Ok(HostingExpiry::defaults())
        }
        async fn hosting_kv_set(
            &self,
            _: String,
            _: String,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_kv_list(
            &self,
            _: String,
        ) -> Result<Vec<(String, String)>, RpcError> {
            Ok(vec![])
        }
        async fn hosting_clear_expiry(&self, _: HostingSelector) -> Result<(), RpcError> {
            Ok(())
        }
        async fn upcoming_expiries(&self, _: i64) -> Result<Vec<ExpiringHosting>, RpcError> {
            Ok(vec![])
        }
        async fn scheduler_tick(&self) -> Result<i64, RpcError> {
            Ok(0)
        }
        async fn backup_now(&self, _: HostingSelector) -> Result<BackupRunWire, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn backup_list(
            &self,
            _: HostingSelector,
            _: i64,
        ) -> Result<Vec<BackupRunWire>, RpcError> {
            Ok(vec![])
        }
        async fn invite_create(&self, _: String, _: i64) -> Result<NodeInviteMint, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn invite_list(&self) -> Result<Vec<NodeInviteSummary>, RpcError> {
            Ok(vec![])
        }
        async fn invite_revoke(&self, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn cert_issue(&self, _: Domain) -> Result<CertInfo, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError> {
            Ok(vec![])
        }
        async fn wp_install(
            &self,
            _: HostingSelector,
            _: WpInstallRequest,
        ) -> Result<WpInstallStatus, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn wp_status(
            &self,
            _: HostingSelector,
        ) -> Result<Option<WpInstallStatus>, RpcError> {
            Ok(None)
        }
        async fn dns_check(&self, _: Domain) -> Result<DnsCheckResult, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn dns_spf_check(
            &self,
            _: Domain,
        ) -> Result<hyperion_types::SpfCheckResult, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn cert_issue_acme(
            &self,
            _: HostingSelector,
            _: CertIssueRequest,
        ) -> Result<CertInfo, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn hosting_stats(&self, _: HostingSelector) -> Result<HostingStats, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn node_stats(&self) -> Result<NodeStats, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn cluster_stats(&self) -> Result<ClusterStats, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn node_metrics_history(
            &self,
            _: i64,
        ) -> Result<hyperion_types::NodeMetricsHistory, RpcError> {
            Ok(hyperion_types::NodeMetricsHistory::default())
        }
        async fn set_hosting_acme_email(
            &self,
            _: HostingSelector,
            _: Option<String>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn services_health(&self) -> Result<hyperion_types::ServicesHealth, RpcError> {
            Ok(hyperion_types::ServicesHealth::default())
        }
        async fn firewall_list(&self) -> Result<hyperion_types::FirewallView, RpcError> {
            Ok(hyperion_types::FirewallView::default())
        }
        async fn firewall_apply_template(
            &self,
            _: String,
        ) -> Result<(bool, String, String), RpcError> {
            Ok((true, String::new(), String::new()))
        }
        async fn service_restart(&self, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn node_update_run(&self, _: bool, _: bool) -> Result<i64, RpcError> {
            Ok(0)
        }
        async fn node_update_status(&self) -> Result<hyperion_types::NodeUpdateStatus, RpcError> {
            Ok(hyperion_types::NodeUpdateStatus::default())
        }
        async fn service_install_status(
            &self,
        ) -> Result<hyperion_types::ServiceInstallStatus, RpcError> {
            Ok(hyperion_types::ServiceInstallStatus::default())
        }
        async fn wp_asset_upload(
            &self,
            _: String,
            _: String,
            _: Vec<u8>,
            _: String,
        ) -> Result<(i64, bool), RpcError> {
            Ok((0, false))
        }
        async fn wp_asset_list(
            &self,
        ) -> Result<Vec<hyperion_types::WpAssetSummary>, RpcError> {
            Ok(vec![])
        }
        async fn wp_asset_delete(&self, _: i64) -> Result<(), RpcError> {
            Ok(())
        }
        async fn wp_install_from_asset(
            &self,
            _: HostingSelector,
            _: i64,
            _: bool,
        ) -> Result<(String, String), RpcError> {
            Ok(("plugin".into(), "stub.zip".into()))
        }
        async fn wp_asset_replace(
            &self,
            _: i64,
            _: String,
            _: Vec<u8>,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn wp_asset_reinstall_all(
            &self,
            _: i64,
            _: Option<bool>,
        ) -> Result<(i64, i64, String), RpcError> {
            Ok((0, 0, String::new()))
        }
        async fn wp_theme_list(
            &self,
            _: HostingSelector,
        ) -> Result<hyperion_types::WpThemeListResponse, RpcError> {
            Ok(hyperion_types::WpThemeListResponse::default())
        }
        async fn wp_theme_action(
            &self,
            _: HostingSelector,
            _: String,
            _: hyperion_types::WpThemeAction,
        ) -> Result<hyperion_types::WpThemeActionResult, RpcError> {
            Ok(hyperion_types::WpThemeActionResult {
                state: "ok".into(),
                message: "stub".into(),
                output_tail: String::new(),
            })
        }
        async fn wp_vuln_scan(
            &self,
            _: HostingSelector,
        ) -> Result<hyperion_types::WpVulnScanResult, RpcError> {
            Ok(hyperion_types::WpVulnScanResult::default())
        }
        async fn service_install(&self, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn agent_config_update(
            &self,
            _: String,
            _: std::collections::BTreeMap<String, String>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn update_check(
            &self,
            _: bool,
        ) -> Result<hyperion_types::UpdateStatus, RpcError> {
            Ok(hyperion_types::UpdateStatus::default())
        }
        async fn hosting_export(
            &self,
            _: hyperion_rpc::HostingSelector,
        ) -> Result<hyperion_types::HostingMigrationBundle, RpcError> {
            Ok(hyperion_types::HostingMigrationBundle {
                bundle_id: "mock".into(),
                archive_path: "/tmp/a".into(),
                manifest_path: "/tmp/m.json".into(),
                archive_sha256: "00".into(),
                archive_bytes: 0,
                created_at: 0,
                source_hosting_id: hyperion_types::HostingId("01J".into()),
                source_node_id: "mock".into(),
                source_hyperion_version: "mock".into(),
                download_base_url: String::new(),
                bundle_token: String::new(),
                token_expires_at: 0,
            })
        }
        async fn hosting_migration_fetch_bundle_file(
            &self,
            _: String,
            _: String,
        ) -> Result<String, RpcError> {
            Ok(String::new())
        }
        async fn hosting_import(
            &self,
            _: String,
        ) -> Result<hyperion_types::HostingImportResult, RpcError> {
            Ok(hyperion_types::HostingImportResult {
                new_hosting_id: hyperion_types::HostingId("01J".into()),
                domain: "mock".into(),
                restored_bytes: 0,
                state: "ok".into(),
                message: "mock".into(),
            })
        }
        async fn hosting_import_from_url(
            &self,
            _: String,
            _: String,
            _: Option<String>,
            _: Vec<String>,
        ) -> Result<hyperion_types::HostingImportResult, RpcError> {
            Ok(hyperion_types::HostingImportResult {
                new_hosting_id: hyperion_types::HostingId("01J".into()),
                domain: "mock".into(),
                restored_bytes: 0,
                state: "ok".into(),
                message: "mock".into(),
            })
        }
        async fn email_log_list(
            &self,
            _: Option<String>,
            _: i64,
        ) -> Result<Vec<hyperion_types::EmailLogEntry>, RpcError> {
            Ok(vec![])
        }
        async fn site_email_log_list(
            &self,
            _: String,
            _: i64,
        ) -> Result<Vec<hyperion_types::SiteEmailLogEntry>, RpcError> {
            Ok(vec![])
        }
        async fn ftp_accounts_list(
            &self,
        ) -> Result<Vec<hyperion_types::FtpAccountSummary>, RpcError> {
            Ok(vec![])
        }
        async fn ftp_verify_login(&self, _: String, _: String) -> Result<bool, RpcError> {
            Ok(true)
        }
        async fn email_smtp_autodetect(
            &self,
        ) -> Result<hyperion_types::SmtpAutodetect, RpcError> {
            Ok(hyperion_types::SmtpAutodetect::default())
        }
        async fn mta_diagnostics(&self) -> Result<hyperion_types::MtaDiagnostics, RpcError> {
            Ok(hyperion_types::MtaDiagnostics::default())
        }
        async fn mta_reconfigure(&self) -> Result<String, RpcError> {
            Ok("skipped".to_string())
        }
        async fn mta_test_send(&self, _: String) -> Result<(i32, String), RpcError> {
            Ok((0, String::new()))
        }
        async fn mta_queue_flush(&self) -> Result<(usize, String), RpcError> {
            Ok((0, String::new()))
        }
        async fn mta_queue_clear(&self) -> Result<(usize, String), RpcError> {
            Ok((0, String::new()))
        }
        async fn panel_provision(
            &self,
            _: String,
            _: bool,
        ) -> Result<(String, String, String), RpcError> {
            Ok(("ok-cert-pending".into(), "test".into(), String::new()))
        }
        async fn panel_cert_status(
            &self,
        ) -> Result<Option<hyperion_types::PanelCertProgress>, RpcError> {
            Ok(None)
        }
        async fn remount_usr_rw(&self) -> Result<(bool, String), RpcError> {
            Ok((true, String::new()))
        }
        async fn fs_diagnose_and_fix(
            &self,
            _: bool,
        ) -> Result<hyperion_types::FsDiagnostics, RpcError> {
            Ok(hyperion_types::FsDiagnostics::default())
        }
        async fn job_get(&self, _: String) -> Result<Option<hyperion_types::JobView>, RpcError> {
            Ok(None)
        }
        async fn job_list(
            &self,
            _: Option<String>,
            _: Option<String>,
            _: i64,
        ) -> Result<Vec<hyperion_types::JobView>, RpcError> {
            Ok(Vec::new())
        }
        async fn job_start(
            &self,
            _: String,
            _: Option<String>,
            _: String,
            _: String,
            _: i64,
        ) -> Result<String, RpcError> {
            Ok("mock-job-id".into())
        }
        async fn job_progress(
            &self,
            _: String,
            _: String,
            _: i64,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn job_finish(
            &self,
            _: String,
            _: bool,
            _: Option<String>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn wp_plugin_list(
            &self,
            _: hyperion_rpc::HostingSelector,
        ) -> Result<hyperion_types::WpPluginListResponse, RpcError> {
            Ok(hyperion_types::WpPluginListResponse::default())
        }
        async fn wp_plugin_action(
            &self,
            _: hyperion_rpc::HostingSelector,
            _: String,
            _: hyperion_types::WpPluginAction,
        ) -> Result<hyperion_types::WpPluginActionResult, RpcError> {
            Ok(hyperion_types::WpPluginActionResult {
                state: "ok".into(),
                message: "mock".into(),
                output_tail: String::new(),
            })
        }
        async fn backup_delete(&self, _: i64) -> Result<(), RpcError> {
            Ok(())
        }
        async fn agent_config_view(&self) -> Result<hyperion_types::AgentConfigView, RpcError> {
            Ok(hyperion_types::AgentConfigView::default())
        }
        async fn email_send_test(&self, _: String) -> Result<String, RpcError> {
            Ok("Code(250)".into())
        }
        async fn web_login(
            &self,
            _: String,
            _: String,
            _: Option<String>,
        ) -> Result<hyperion_types::WebLoginResult, RpcError> {
            Ok(hyperion_types::WebLoginResult::Invalid)
        }
        async fn web_verify_2fa(
            &self,
            _: i64,
            _: String,
        ) -> Result<hyperion_types::WebVerify2faResult, RpcError> {
            Ok(hyperion_types::WebVerify2faResult::Invalid)
        }
        async fn web_user_list(&self) -> Result<Vec<hyperion_types::WebUserSummary>, RpcError> {
            Ok(vec![])
        }
        async fn web_user_get(
            &self,
            _: i64,
        ) -> Result<Option<hyperion_types::WebUserSummary>, RpcError> {
            Ok(None)
        }
        async fn web_user_create(
            &self,
            _: String,
            _: String,
            _: String,
            _: String,
        ) -> Result<i64, RpcError> {
            Ok(0)
        }
        async fn web_user_set_password(&self, _: i64, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn web_user_set_role(&self, _: i64, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn web_user_set_locked(
            &self,
            _: i64,
            _: bool,
            _: Option<String>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn web_user_delete(&self, _: i64) -> Result<(), RpcError> {
            Ok(())
        }
        async fn web_2fa_enroll_start(
            &self,
            _: i64,
        ) -> Result<hyperion_types::Web2faEnrollment, RpcError> {
            Ok(hyperion_types::Web2faEnrollment {
                secret_base32: String::new(),
                otpauth_url: String::new(),
                backup_codes: vec![],
            })
        }
        async fn web_2fa_confirm_enroll(&self, _: i64, _: String) -> Result<bool, RpcError> {
            Ok(false)
        }
        async fn web_2fa_disable(&self, _: i64) -> Result<(), RpcError> {
            Ok(())
        }
        async fn web_grant_hosting_access(
            &self,
            _: i64,
            _: String,
            _: String,
            _: Option<i64>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn web_revoke_hosting_access(&self, _: i64, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn web_list_hosting_access(
            &self,
            _: String,
        ) -> Result<Vec<hyperion_types::WebHostingAccess>, RpcError> {
            Ok(vec![])
        }
        async fn hosting_file_list(
            &self,
            _: HostingSelector,
            _: String,
        ) -> Result<(String, Vec<hyperion_types::HostingFileEntry>), RpcError> {
            Ok((String::new(), vec![]))
        }
        async fn hosting_file_read(
            &self,
            _: HostingSelector,
            _: String,
        ) -> Result<hyperion_types::HostingFileContent, RpcError> {
            Ok(hyperion_types::HostingFileContent {
                rel_path: String::new(),
                mime: String::new(),
                size: 0,
                content: String::new(),
                truncated: false,
            })
        }
        async fn hosting_file_download(
            &self,
            _: HostingSelector,
            _: String,
        ) -> Result<(String, String, String), RpcError> {
            Ok((String::new(), String::new(), String::new()))
        }
        async fn hosting_file_write(
            &self,
            _: HostingSelector,
            _: String,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_file_delete(
            &self,
            _: HostingSelector,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_file_mkdir(
            &self,
            _: HostingSelector,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_file_rename(
            &self,
            _: HostingSelector,
            _: String,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn monitor_overview(
            &self,
        ) -> Result<Vec<hyperion_types::MonitorOverviewItem>, RpcError> {
            Ok(vec![])
        }
        async fn avatar_filename(&self, _: i64) -> Result<Option<String>, RpcError> {
            Ok(None)
        }
        async fn avatar_set(&self, _: i64, _: Option<String>) -> Result<(), RpcError> {
            Ok(())
        }
        async fn email_change_request(
            &self,
            _: i64,
            _: String,
            _: String,
        ) -> Result<String, RpcError> {
            Ok(String::new())
        }
        async fn email_change_confirm(&self, _: i64, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn email_change_cancel(&self, _: i64) -> Result<(), RpcError> {
            Ok(())
        }
        async fn monitor_get(
            &self,
            _: HostingSelector,
        ) -> Result<(hyperion_types::MonitorConfigView, hyperion_types::MonitorHistory), RpcError>
        {
            Ok((
                hyperion_types::MonitorConfigView::default(),
                hyperion_types::MonitorHistory::default(),
            ))
        }
        async fn monitor_set(
            &self,
            _: HostingSelector,
            _: bool,
            _: Option<String>,
            _: Option<i64>,
            _: Option<i64>,
            _: Option<String>,
            _: Option<String>,
            _: Option<String>,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn monitor_probe_now(
            &self,
            _: HostingSelector,
        ) -> Result<hyperion_types::MonitorSamplePoint, RpcError> {
            Ok(hyperion_types::MonitorSamplePoint {
                at: 0,
                success: false,
                http_status: None,
                response_ms: 0,
            })
        }
        async fn monitor_tick(&self) -> Result<i64, RpcError> {
            Ok(0)
        }
        async fn stats_tick(&self) -> Result<i64, RpcError> {
            Ok(0)
        }
        async fn backup_restore(
            &self,
            _: HostingSelector,
            _: String,
            _: hyperion_types::BackupRestoreMode,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn backup_fetch_chunk(
            &self,
            _: i64,
            _: u64,
            _: u32,
        ) -> Result<(String, u64, String, bool), RpcError> {
            Ok((String::new(), 0, String::new(), true))
        }
        async fn backup_restore_as_new(
            &self,
            _: HostingSelector,
            _: String,
            _: String,
        ) -> Result<(String, String), RpcError> {
            Ok((String::new(), String::new()))
        }
        async fn notifications_feed(
            &self,
            _: i64,
            _: i64,
        ) -> Result<hyperion_types::NotificationFeed, RpcError> {
            Ok(hyperion_types::NotificationFeed::default())
        }
        async fn notifications_mark_read(&self, _: i64, _: i64) -> Result<(), RpcError> {
            Ok(())
        }
        async fn notifications_mark_all_read(&self, _: i64) -> Result<i64, RpcError> {
            Ok(0)
        }
        async fn hosting_logs(
            &self,
            _: HostingSelector,
            _: String,
            _: i64,
        ) -> Result<String, RpcError> {
            Ok(String::new())
        }
        async fn cron_list(&self, _: HostingSelector) -> Result<String, RpcError> {
            Ok(String::new())
        }
        async fn cron_replace(
            &self,
            _: HostingSelector,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn enroll_consume(
            &self,
            _: String,
            _: String,
            _: String,
            _: String,
            _: String,
            _: Option<String>,
        ) -> Result<(String, Option<String>), RpcError> {
            Ok(("test-secret".into(), None))
        }
        async fn node_heartbeat(
            &self,
            _: String,
            _: String,
            _: String,
        ) -> Result<Option<String>, RpcError> {
            Ok(None)
        }
        async fn node_set_label(&self, _: String, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn node_set_drain(
            &self,
            _: String,
            _: bool,
            _: String,
            _: i64,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn node_remove(
            &self,
            _: String,
            _: bool,
            _: i64,
        ) -> Result<(bool, i64), RpcError> {
            Ok((true, 0))
        }
        async fn cert_overview(
            &self,
        ) -> Result<Vec<hyperion_types::CertOverviewItem>, RpcError> {
            Ok(Vec::new())
        }
        async fn nodes_list(&self) -> Result<Vec<NodeSummary>, RpcError> {
            Ok(vec![])
        }
        async fn wp_reset_password(
            &self,
            _: HostingSelector,
            _: String,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn db_reset_password(
            &self,
            _: HostingSelector,
            _: String,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn ftp_set_password(
            &self,
            _: HostingSelector,
            _: String,
        ) -> Result<String, RpcError> {
            Ok("test-ftp-pw".into())
        }
        async fn ftp_disable(&self, _: HostingSelector) -> Result<(), RpcError> {
            Ok(())
        }
        async fn sftp_status(
            &self,
            _: HostingSelector,
        ) -> Result<hyperion_types::SftpStatus, RpcError> {
            Ok(hyperion_types::SftpStatus::default())
        }
        async fn sftp_set(
            &self,
            _: HostingSelector,
            _: bool,
            _: Vec<String>,
        ) -> Result<hyperion_types::SftpStatus, RpcError> {
            Ok(hyperion_types::SftpStatus::default())
        }
        async fn dashboard_alerts(&self) -> Result<Vec<DashboardAlert>, RpcError> {
            Ok(vec![])
        }
        async fn profile_list(&self) -> Result<Vec<HostingProfile>, RpcError> {
            Ok(vec![])
        }
        async fn profile_get(&self, _: i64) -> Result<HostingProfile, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn profile_create(&self, _: ProfileInput) -> Result<HostingProfile, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn profile_update(
            &self,
            _: i64,
            _: ProfileInput,
        ) -> Result<HostingProfile, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn profile_delete(&self, _: i64) -> Result<(), RpcError> {
            Ok(())
        }
        async fn profile_apply(
            &self,
            _: HostingSelector,
            _: i64,
            _: bool,
        ) -> Result<ProfileApply, RpcError> {
            Err(RpcError::Internal { message: "not supported by this agent".into() })
        }
        async fn profile_get_apply(
            &self,
            _: HostingSelector,
        ) -> Result<Option<ProfileApply>, RpcError> {
            Ok(None)
        }
        async fn profile_wp_item_install(
            &self,
            _: HostingSelector,
            _: String,
            _: String,
        ) -> Result<(String, bool), RpcError> {
            Ok(("test".into(), false))
        }
    }

    async fn spawn(api: Arc<dyn AgentApi>) -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("s.sock");
        let srv = Server::bind(&path, api).await.expect("bind");
        tokio::spawn(srv.run());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        (path, dir)
    }

    #[tokio::test]
    async fn agent_info_round_trip() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let resp = hyperion_rpc_client::call(&path, Request::AgentInfo)
            .await
            .expect("call");
        match resp {
            Response::AgentInfo(info) => assert_eq!(info.hostname, "test"),
            other => panic!("bad resp: {other:?}"),
        }
    }

    #[tokio::test]
    async fn hosting_list_round_trip() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let resp = hyperion_rpc_client::call(&path, Request::HostingList)
            .await
            .expect("call");
        match resp {
            Response::HostingList(v) => assert!(v.is_empty()),
            other => panic!("bad resp: {other:?}"),
        }
    }

    #[tokio::test]
    async fn error_response_round_trip() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let resp = hyperion_rpc_client::call(
            &path,
            Request::HostingGet(HostingSelector::Domain(
                Domain::parse("example.cz").expect("parse"),
            )),
        )
        .await
        .expect("call");
        match resp {
            Response::Error(RpcError::NotFound { kind, id }) => {
                assert_eq!(kind, "hosting");
                assert_eq!(id, "x");
            }
            other => panic!("bad resp: {other:?}"),
        }
    }

    #[tokio::test]
    async fn socket_perms_are_0660() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let m = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o660);
    }

    #[tokio::test]
    async fn many_concurrent_clients() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let mut tasks = vec![];
        for _ in 0..32 {
            let p = path.clone();
            tasks.push(tokio::spawn(async move {
                hyperion_rpc_client::call(&p, Request::AgentInfo)
                    .await
                    .expect("call")
            }));
        }
        for t in tasks {
            let resp = t.await.expect("join");
            matches!(resp, Response::AgentInfo(_));
        }
    }
}
