//! JSON length-prefixed framing.
//!
//! Each frame on the wire is `u32be length || JSON bytes`.
//! `MAX_FRAME` (4 MiB) is enforced both at write and read.

use crate::{
    error::RpcError,
    wire::{AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector},
};
use hyperion_types::{
    BackupRunWire, CertInfo, CertIssueRequest, CertRenewResult, ClusterStats, DashboardAlert,
    DnsCheckResult, ExpiringHosting, HostingDetail, HostingExpiry, HostingLimits, HostingProfile,
    HostingStats, HostingSummary, HostingUsageBucket, NodeInviteMint, NodeInviteSummary, NodeStats,
    NodeSummary, ProfileApply, ProfileInput, SuspendReason, WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::Domain;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    AgentInfo,
    HostingCreate(HostingCreateReq),
    HostingList,
    HostingGet(HostingSelector),
    HostingDelete {
        sel: HostingSelector,
        opts: DeleteOpts,
    },
    HostingSetLimits {
        sel: HostingSelector,
        limits: HostingLimits,
    },
    HostingGetLimits(HostingSelector),
    HostingSuspend {
        sel: HostingSelector,
        reason: SuspendReason,
    },
    HostingResume(HostingSelector),
    HostingUsage {
        sel: HostingSelector,
        limit: i64,
    },
    HostingSetExpiry {
        sel: HostingSelector,
        expiry: HostingExpiry,
    },
    HostingGetExpiry(HostingSelector),
    HostingClearExpiry(HostingSelector),
    UpcomingExpiries {
        within_seconds: i64,
    },
    SchedulerTick,
    BackupNow {
        sel: HostingSelector,
    },
    BackupList {
        sel: HostingSelector,
        limit: i64,
    },
    InviteCreate {
        label: String,
        ttl_secs: i64,
    },
    InviteList,
    InviteRevoke {
        token_hash: String,
    },
    AuditList {
        limit: i64,
    },
    CertIssue {
        domain: Domain,
    },
    CertRenewAll,
    WpInstall {
        sel: HostingSelector,
        req: WpInstallRequest,
    },
    WpStatus {
        sel: HostingSelector,
    },
    DnsCheck {
        domain: Domain,
    },
    DnsSpfCheck {
        domain: Domain,
    },
    CertIssueAcme {
        sel: HostingSelector,
        req: CertIssueRequest,
    },
    HostingStats {
        sel: HostingSelector,
    },
    NodeStats,
    ClusterStats,
    NodeMetricsHistory {
        /// Max samples to return (clamped 1..=2000). Typical: 48 for
        /// ~4 hours @ 5min tick.
        limit: i64,
    },
    /// Set or clear the per-hosting ACME contact email override.
    /// `email: None` means "clear → fall back to agent-wide default".
    SetHostingAcmeEmail {
        sel: HostingSelector,
        email: Option<String>,
    },
    /// Get status of all system services Hyperion depends on
    /// (nginx, mariadb, postgresql, php-fpm versions, vsftpd, etc.)
    /// for the /health page + dashboard widget.
    ServicesHealth,
    /// `systemctl restart <name>` on a whitelisted unit. Restarts
    /// hyperion-agent itself are refused (would terminate this RPC
    /// session); operator must SSH for self-restart.
    ServiceRestart {
        name: String,
    },
    /// `apt-get install -y <pkg>` then `systemctl enable --now <name>`.
    /// `name` must be in the same whitelist as restart. Maps service
    /// name to apt package name (typically identical).
    ServiceInstall {
        name: String,
    },
    /// Update one section of agent.toml. Validated server-side per
    /// section + field. Operator must `systemctl restart hyperion-agent`
    /// to load the new values (UI tells them).
    AgentConfigUpdate {
        /// "acme" | "email" | "slack" | "backup_remote" | "backup_retention"
        section: String,
        /// Field → string-encoded value. Service knows the expected
        /// types per (section, field) and parses accordingly.
        fields: std::collections::BTreeMap<String, String>,
    },
    /// Compare the running binary's git SHA against the upstream
    /// `rolling` release tag's SHA. Cached agent-side for an hour
    /// so the dashboard banner doesn't hammer the GitHub API.
    UpdateCheck {
        /// If true, bypass the cache and re-probe the upstream.
        force_refresh: bool,
    },
    /// Produce a migration bundle (archive + manifest) for `hosting`.
    /// The bundle lives on the source node's disk; the operator
    /// transfers it out-of-band and imports on the target.
    HostingExport { hosting: HostingSelector },
    /// Import a migration bundle by manifest path. Sibling
    /// `archive.tar.gz` is expected next to the manifest.
    HostingImport { manifest_path: String },
    /// Per-hosting (or cluster-wide) email log.
    EmailLogList {
        /// `None` returns the cluster-wide stream; `Some(hosting_id)`
        /// filters to that hosting only.
        hosting_id: Option<String>,
        limit: i64,
    },
    /// Probe localhost for a usable SMTP relay so the UI can
    /// pre-fill the email config form. Cheap — just TCP connect.
    EmailSmtpAutodetect,
    /// Import a migration bundle from a source node's signed URL.
    /// `base_url` is e.g. `https://source-master/api/migration/bundle/<id>`
    /// — the agent appends `/manifest.json?t=<token>` and
    /// `/archive.tar.gz?t=<token>`, downloads both, then runs the
    /// regular import.
    HostingImportFromUrl { base_url: String, token: String },
    /// List installed WordPress plugins for `hosting`.
    WpPluginList { hosting: HostingSelector },
    /// Apply one plugin action via wp-cli. `slug` is the plugin
    /// folder name (ignored for `UpdateAll`).
    WpPluginAction {
        hosting: HostingSelector,
        slug: String,
        action: hyperion_types::WpPluginAction,
    },
    /// Delete a single backup run + its archive file(s) on disk.
    /// Refuses if the backup is still "running". Audits the action.
    BackupDelete {
        backup_id: i64,
    },
    /// View the agent's effective config — agent.toml minus secrets,
    /// plus a few derived bits (detected nginx user, cluster role).
    /// Operator-facing settings page reads from this.
    AgentConfigView,
    /// Send a test email through the configured SMTP relay to verify
    /// deliverability. Returns ok or a clean error string the
    /// operator can act on.
    EmailSendTest {
        to: String,
    },

    // ─── Web users / roles / 2FA ───────────────────────────────
    /// Verify a username + password. Does NOT mint a session — the web
    /// binary keeps its own session signer. Returns enough info for web
    /// to either mint a session or prompt for 2FA / show locked state.
    WebLogin {
        username: String,
        password: String,
        client_ip: Option<String>,
    },
    /// Second step of a 2FA-required login. `user_id` comes from a
    /// prior `WebLogin → NeedsTotp`. `code` is either the 6-digit TOTP
    /// or a backup code (the agent disambiguates by length).
    WebVerify2fa {
        user_id: i64,
        code: String,
    },
    /// List all web users (super_admin only — web enforces).
    WebUserList,
    /// Get one user's sanitised summary by id.
    WebUserGet {
        id: i64,
    },
    /// Create a new user directly (without invite). super_admin only.
    /// Returns the new user id.
    WebUserCreate {
        username: String,
        email: String,
        password: String,
        role: String,
    },
    /// Force-set a user's password (admin reset). super_admin only.
    WebUserSetPassword {
        user_id: i64,
        new_password: String,
    },
    /// Change role. super_admin only.
    WebUserSetRole {
        user_id: i64,
        role: String,
    },
    /// Lock / unlock a user. super_admin only.
    WebUserSetLocked {
        user_id: i64,
        locked: bool,
        reason: Option<String>,
    },
    /// Delete a user. super_admin only. Refuses to delete the last
    /// super_admin to prevent locking out the cluster.
    WebUserDelete {
        user_id: i64,
    },
    /// Start TOTP 2FA enrollment for `user_id` — returns secret + URL +
    /// fresh backup codes. The secret is stored on the user record but
    /// `totp_enrolled_at` stays NULL until `Web2faConfirmEnroll`.
    Web2faEnrollStart {
        user_id: i64,
    },
    /// Confirm enrollment with the first TOTP code. Flips
    /// `totp_enrolled_at` on success.
    Web2faConfirmEnroll {
        user_id: i64,
        code: String,
    },
    /// Disable 2FA on a user (admin override OR self-disable). Clears
    /// the secret + enrollment marker + backup codes.
    Web2faDisable {
        user_id: i64,
    },
    /// Grant a non-admin user access to one hosting at a specific
    /// level (`"read"` for viewer-style, `"manage"` for operator-style).
    /// super_admin / admin ignore this — they see everything.
    WebGrantHostingAccess {
        user_id: i64,
        hosting_id: String,
        level: String,
        granted_by: Option<i64>,
    },
    /// Revoke a previously granted hosting access.
    WebRevokeHostingAccess {
        user_id: i64,
        hosting_id: String,
    },
    /// List all access grants for a given hosting (used to render the
    /// per-hosting access tab).
    WebListHostingAccess {
        hosting_id: String,
    },

    /// List one directory under a hosting's htdocs root. Path is
    /// RELATIVE to htdocs; empty / "/" mean the root itself.
    /// Read-only — file browser MVP.
    HostingFileList {
        sel: HostingSelector,
        rel_path: String,
    },
    /// Read a single text file (≤ 1 MiB) under a hosting's htdocs root.
    /// Binary files are refused — UI offers a download link instead.
    HostingFileRead {
        sel: HostingSelector,
        rel_path: String,
    },

    /// Read the per-hosting monitor config + sample history.
    MonitorGet {
        sel: HostingSelector,
    },
    /// Write the per-hosting monitor config.
    MonitorSet {
        sel: HostingSelector,
        enabled: bool,
        url_path: Option<String>,
        interval_secs: Option<i64>,
        alert_after_fails: Option<i64>,
        alert_email: Option<String>,
        alert_slack_webhook: Option<String>,
        alert_webhook_url: Option<String>,
    },
    /// Operator-driven manual probe (the "Test now" button). Always
    /// records a sample regardless of `monitor_enabled`.
    MonitorProbeNow {
        sel: HostingSelector,
    },
    /// One tick of the background monitor scheduler. Returns the count
    /// of hostings sampled.
    MonitorTick,

    StatsTick,
    BackupRestore {
        sel: HostingSelector,
        archive_path: String,
    },
    HostingLogs {
        sel: HostingSelector,
        log_kind: String,
        lines: i64,
    },
    CronList {
        sel: HostingSelector,
    },
    CronReplace {
        sel: HostingSelector,
        body: String,
    },
    EnrollConsume {
        token: String,
        caller_ip: String,
        node_id: String,
        label: String,
        agent_version: String,
        public_ip: Option<String>,
    },
    NodesList,
    NodeHeartbeat {
        node_id: String,
        secret: String,
        agent_version: String,
    },
    WpResetPassword {
        sel: HostingSelector,
        wp_user: String,
        new_password: String,
    },
    DbResetPassword {
        sel: HostingSelector,
        new_password: String,
    },
    FtpSetPassword {
        sel: HostingSelector,
        new_password: String,
    },
    FtpDisable {
        sel: HostingSelector,
    },
    DashboardAlerts,
    ProfileList,
    ProfileGet { id: i64 },
    ProfileCreate(ProfileInput),
    ProfileUpdate { id: i64, input: ProfileInput },
    ProfileDelete { id: i64 },
    ProfileApply { sel: HostingSelector, profile_id: i64 },
    ProfileGetApply { sel: HostingSelector },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", content = "result", rename_all = "snake_case")]
pub enum Response {
    AgentInfo(AgentInfo),
    HostingCreate(HostingCreated),
    HostingList(Vec<HostingSummary>),
    HostingGet(HostingDetail),
    HostingDelete,
    HostingSetLimits(HostingLimits),
    HostingGetLimits(HostingLimits),
    HostingSuspend,
    HostingResume,
    HostingUsage(Vec<HostingUsageBucket>),
    HostingSetExpiry(HostingExpiry),
    HostingGetExpiry(HostingExpiry),
    HostingClearExpiry,
    UpcomingExpiries(Vec<ExpiringHosting>),
    SchedulerTick { actions_processed: i64 },
    BackupNow(BackupRunWire),
    BackupList(Vec<BackupRunWire>),
    InviteCreate(NodeInviteMint),
    InviteList(Vec<NodeInviteSummary>),
    InviteRevoke,
    AuditList(Vec<AuditEntryWire>),
    CertIssue(CertInfo),
    CertRenewAll(Vec<CertRenewResult>),
    WpInstall(WpInstallStatus),
    WpStatus(Option<WpInstallStatus>),
    DnsCheck(DnsCheckResult),
    DnsSpfCheck(hyperion_types::SpfCheckResult),
    CertIssueAcme(CertInfo),
    HostingStats(HostingStats),
    NodeStats(NodeStats),
    ClusterStats(ClusterStats),
    NodeMetricsHistory(hyperion_types::NodeMetricsHistory),
    SetHostingAcmeEmail,
    ServicesHealth(hyperion_types::ServicesHealth),
    BackupDelete,
    AgentConfigView(hyperion_types::AgentConfigView),
    /// SMTP response code from the relay (e.g. `Code(250)`).
    /// Surfaced in the UI flash so the operator can verify the
    /// relay actually accepted the message.
    EmailSendTest { smtp_code: String },
    ServiceRestart,
    ServiceInstall,
    AgentConfigUpdate,
    UpdateCheck(hyperion_types::UpdateStatus),
    HostingExport(hyperion_types::HostingMigrationBundle),
    HostingImport(hyperion_types::HostingImportResult),
    HostingImportFromUrl(hyperion_types::HostingImportResult),
    EmailLogList(Vec<hyperion_types::EmailLogEntry>),
    EmailSmtpAutodetect(hyperion_types::SmtpAutodetect),
    WpPluginList(hyperion_types::WpPluginListResponse),
    WpPluginAction(hyperion_types::WpPluginActionResult),
    // Web users / roles / 2FA
    WebLogin(hyperion_types::WebLoginResult),
    WebVerify2fa(hyperion_types::WebVerify2faResult),
    WebUserList(Vec<hyperion_types::WebUserSummary>),
    WebUserGet(Option<hyperion_types::WebUserSummary>),
    WebUserCreate { id: i64 },
    WebUserSetPassword,
    WebUserSetRole,
    WebUserSetLocked,
    WebUserDelete,
    Web2faEnrollStart(hyperion_types::Web2faEnrollment),
    Web2faConfirmEnroll { ok: bool },
    Web2faDisable,
    WebGrantHostingAccess,
    WebRevokeHostingAccess,
    WebListHostingAccess(Vec<hyperion_types::WebHostingAccess>),
    HostingFileList {
        rel_path: String,
        entries: Vec<hyperion_types::HostingFileEntry>,
    },
    HostingFileRead(hyperion_types::HostingFileContent),
    MonitorGet {
        config: hyperion_types::MonitorConfigView,
        history: hyperion_types::MonitorHistory,
    },
    MonitorSet,
    MonitorProbeNow(hyperion_types::MonitorSamplePoint),
    MonitorTick { sampled: i64 },
    StatsTick { hostings_sampled: i64 },
    BackupRestore,
    HostingLogs(String),
    CronList(String),
    CronReplace,
    EnrollConsume { secret: String },
    NodesList(Vec<NodeSummary>),
    NodeHeartbeat,
    WpResetPassword,
    DbResetPassword,
    FtpSetPassword { password: String },
    FtpDisable,
    DashboardAlerts(Vec<DashboardAlert>),
    ProfileList(Vec<HostingProfile>),
    ProfileGet(HostingProfile),
    ProfileCreate(HostingProfile),
    ProfileUpdate(HostingProfile),
    ProfileDelete,
    ProfileApply(ProfileApply),
    ProfileGetApply(Option<ProfileApply>),
    Error(RpcError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntryWire {
    pub id: i64,
    pub ts: i64,
    pub actor_uid: i64,
    pub actor_label: String,
    pub action: String,
    pub target: Option<String>,
    pub payload_json: String,
    pub result: String,
}

pub async fn write_frame<W, T>(w: &mut W, value: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("frame {} exceeds MAX_FRAME {}", bytes.len(), MAX_FRAME),
        ));
    }
    let len = bytes.len() as u32;
    w.write_u32(len).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(r: &mut R) -> std::io::Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let len = r.read_u32().await? as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame {len} exceeds MAX_FRAME"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn request_round_trip_through_duplex() {
        let (mut a, mut b) = duplex(8192);
        let req = Request::HostingList;
        write_frame(&mut a, &req).await.expect("write");
        let got: Request = read_frame(&mut b).await.expect("read");
        assert_eq!(req, got);
    }

    #[tokio::test]
    async fn response_round_trip() {
        let (mut a, mut b) = duplex(8192);
        let resp = Response::AgentInfo(AgentInfo {
            hostname: "test".into(),
            version: "0".into(),
            schema_version: 1,
            hostings_count: 0,
            node_id: None,
            master_url: None,
            enrolled_at: None,
        });
        write_frame(&mut a, &resp).await.expect("write");
        let got: Response = read_frame(&mut b).await.expect("read");
        assert_eq!(resp, got);
    }

    #[tokio::test]
    async fn error_response_round_trip() {
        let (mut a, mut b) = duplex(8192);
        let resp = Response::Error(RpcError::NotFound {
            kind: "hosting".into(),
            id: "x".into(),
        });
        write_frame(&mut a, &resp).await.expect("write");
        let got: Response = read_frame(&mut b).await.expect("read");
        assert_eq!(resp, got);
    }

    #[tokio::test]
    async fn refuses_overlarge_frame_on_read() {
        let (mut a, mut b) = duplex(8192);
        a.write_u32((MAX_FRAME + 1) as u32)
            .await
            .expect("write len");
        let result: std::io::Result<Request> = read_frame(&mut b).await;
        assert!(result.is_err());
    }

    #[test]
    fn request_method_tag_in_json() {
        let req = Request::HostingList;
        let s = serde_json::to_string(&req).expect("serialize");
        assert!(s.contains("hosting_list"), "got: {s}");
    }
}
