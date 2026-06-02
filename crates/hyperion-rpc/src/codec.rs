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
    /// Delete a single backup run + its archive file(s) on disk.
    /// Refuses if the backup is still "running". Audits the action.
    BackupDelete {
        backup_id: i64,
    },
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
