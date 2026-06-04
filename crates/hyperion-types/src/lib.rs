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
pub mod limits;
pub mod migration;
pub mod php;
pub mod profile;
pub mod spf;
pub mod stats;
pub mod wp;

pub use cert::{CertInfo, CertRenewOutcome, CertRenewResult};
pub use db::{DbProvision, DbSummary};
pub use dns::{CertIssueRequest, DnsCheckResult};
pub use hosting::{HostingDetail, HostingState, HostingSummary};
pub use ids::{AgentId, HostingId, SecretId};
pub use limits::{
    BackupRunWire, ExpiringHosting, HostingExpiry, HostingLimits, HostingUsageBucket,
    NodeInviteMint, NodeInviteSummary, OverBwPolicy, SuspendReason,
};
pub use migration::{HostingImportResult, HostingMigrationBundle, HostingMigrationManifest};
pub use php::PhpVersion;
pub use profile::{HostingProfile, ProfileApply, ProfileInput, WpAssetSummary};
pub use spf::SpfCheckResult;
pub use stats::{
    AcmeConfigView, AgentConfigView, BackupRemoteConfigView, BackupRetentionConfigView,
    ClusterConfigView, ClusterStats, DashboardAlert, EmailConfigView, EmailLogEntry,
    HostingFileContent,
    HostingFileEntry, HostingStats, MonitorConfigView, MonitorHistory, MonitorSamplePoint,
    NodeMetricPoint, NodeMetricsHistory, NodeStats, NodeSummary, NodeUpdateStatus,
    ServiceHealth, ServiceInstallStatus, ServicesHealth, SlackConfigView, SmtpAutodetect,
    UpdateStatus, Web2faEnrollment, WebHostingAccess, WebLoginResult, WebUserSummary,
    WebVerify2faResult,
};
pub use wp::{
    WpInstallRequest, WpInstallStatus, WpPlugin, WpPluginAction, WpPluginActionResult,
    WpPluginListResponse,
};

/// Current Unix epoch seconds. Centralized so tests can replace it if needed.
pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}
