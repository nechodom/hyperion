//! Shared serde-friendly types for the hyperion workspace.
//!
//! No I/O, no system calls — just newtype IDs, enums, and DTOs that
//! cross crate boundaries and the RPC wire.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod cert;
pub mod db;
pub mod dns;
pub mod hosting;
pub mod ids;
pub mod jobs;
pub mod limits;
pub mod migration;
pub mod php;
pub mod profile;
pub mod spf;
pub mod stats;
pub mod wp;

pub use cert::{CertInfo, CertOverviewItem, CertRenewOutcome, CertRenewResult, PanelCertProgress};
pub use db::{DbProvision, DbSummary};
pub use dns::{CertIssueRequest, DnsCheckResult};
pub use hosting::{
    HostingDetail, HostingState, HostingSummary, SftpStatus, VhostOptions, WpExtras,
    WpRedisConfig,
};
pub use ids::{AgentId, HostingId, SecretId};
pub use jobs::{
    BackupTargetProbe, BackupTargetView, HostingQuotaReport, HostingQuotaView, JobView,
    QuotaEnableSummary, WebSessionView,
};
pub use limits::{
    BackupRestoreMode, BackupRunWire, ExpiringHosting, HostingExpiry, HostingLimits,
    HostingUsageBucket, IpBanWire, NodeInviteMint, NodeInviteSummary, OverBwPolicy, SuspendReason,
};
pub use migration::{HostingImportResult, HostingMigrationBundle, HostingMigrationManifest};
pub use php::PhpVersion;
pub use profile::{HostingProfile, ProfileApply, ProfileInput, WpAssetSummary};
pub use spf::SpfCheckResult;
pub use stats::{
    AcmeConfigView, AgentConfigView, BackupRemoteConfigView, BackupRetentionConfigView,
    ClusterConfigView, ClusterStats, DashboardAlert, EmailConfigView, EmailLogEntry,
    FirewallPort, FirewallView,
    HostingFileContent,
    HostingFileEntry, HostingStats, MonitorConfigView, MonitorHistory, MonitorOverviewItem,
    MonitorSamplePoint, NodeMetricPoint, NodeMetricsHistory, NodeStats, NodeSummary,
    FsDiagnostics, FsFixStep,
    FtpAccountSummary, MtaDiagnostics, MtaPortProbe, NodeUpdateStatus, NotificationFeed, NotificationView,
    SiteEmailLogEntry, TrashEntry,
    ServiceHealth, ServiceInstallStatus, ServicesHealth, SlackConfigView, SmtpAutodetect,
    UpdateStatus, Web2faEnrollment, WebHostingAccess, WebLoginResult, WebUserSummary,
    WebVerify2faResult,
};
pub use wp::{
    HostingVulnSummary, WpInstallRequest, WpInstallStatus, WpPlugin, WpPluginAction,
    WpPluginActionResult, WpPluginListResponse, WpTheme, WpThemeAction, WpThemeActionResult,
    WpThemeListResponse, WpVulnFinding, WpVulnScanResult,
};

/// Current Unix epoch seconds. Centralized so tests can replace it if needed.
pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}
