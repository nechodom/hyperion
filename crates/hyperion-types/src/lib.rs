//! Shared serde-friendly types for the hyperion workspace.
//!
//! No I/O, no system calls — just newtype IDs, enums, and DTOs that
//! cross crate boundaries and the RPC wire.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
// Wire DTOs/tuples are intentionally "complex"/"many-argument"; aliasing each
// adds noise without clarity. Doc-list + test-builder style nits are tolerated.
#![allow(
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::doc_lazy_continuation,
    clippy::field_reassign_with_default
)]
#![forbid(unsafe_code)]

pub mod cert;
pub mod db;
pub mod dkim;
pub mod dns;
pub mod hosting;
pub mod ids;
pub mod import;
pub mod jobs;
pub mod limits;
pub mod migration;
pub mod package;
pub mod php;
pub mod profile;
pub mod spf;
pub mod stats;
pub mod wp;

pub use cert::{CertInfo, CertOverviewItem, CertRenewOutcome, CertRenewResult, PanelCertProgress};
pub use db::{DbProvision, DbSummary};
pub use dkim::DkimStatus;
pub use dns::{CertIssueRequest, DnsCheckResult};
pub use hosting::{
    HostingDetail, HostingState, HostingSummary, SftpStatus, VhostOptions, WpExtras, WpRedisConfig,
};
pub use ids::{AgentId, HostingId, SecretId};
pub use import::{ImportTokenInfo, ImportTokenOp, ImportTokenResult};
pub use jobs::{
    ApiKeyCreated, ApiKeyResolved, ApiKeyView, BackupTargetProbe, BackupTargetView,
    HostingQuotaReport, HostingQuotaView, JobView, QuotaEnableSummary, S3BackupTarget,
    WebSessionView,
};
pub use limits::{
    BackupRestoreMode, BackupRunWire, ExpiringHosting, HostingExpiry, HostingLimits,
    HostingUsageBucket, IpBanWire, NodeInviteMint, NodeInviteSummary, OverBwPolicy, SuspendReason,
};
pub use migration::{HostingImportResult, HostingMigrationBundle, HostingMigrationManifest};
pub use package::{
    BackupCadence, FeatureToggle, HostingPackage, LiveFeatureState, PackageFeatures, PackageInput,
    PackagePriorState, PackageState, ServicePackage,
};
pub use php::PhpVersion;
pub use profile::{HostingProfile, ProfileApply, ProfileInput, WpAssetSummary};
pub use spf::SpfCheckResult;
pub use stats::{decode_mime_header, render_html_shell, CountryTraffic};
pub use stats::{
    AcmeConfigView, AgentConfigView, BackupRemoteConfigView, BackupRetentionConfigView,
    ClusterConfigView, ClusterStats, CustomRoleSummary, DashboardAlert, EffectiveRoleWire,
    EmailConfigView, EmailLogEntry, FirewallPort, FirewallView, FsDiagnostics, FsFixStep,
    FtpAccountSummary, FtpCheckItem, FtpCheckReport, FtpExtraAccount, HostingFileContent,
    HostingFileEntry, HostingStats, MonitorConfigView, MonitorHistory, MonitorOverviewItem,
    MonitorSamplePoint, MtaDiagnostics, MtaPortProbe, NodeMetricPoint, NodeMetricsHistory,
    NodeStats, NodeSummary, NodeUpdateStatus, NotificationFeed, NotificationTemplatesView,
    NotificationView, ServiceHealth, ServiceInstallStatus, ServicesHealth, SiteEmailLogEntry,
    SlackConfigView, SmtpAutodetect, TrashEntry, UpdateStatus, Web2faEnrollment, WebHostingAccess,
    WebLoginResult, WebUserSummary, WebVerify2faResult,
};
pub use stats::{CARE_REPORT_DEFAULT_BODY_TEMPLATE, EXPIRY_WARNING_DEFAULT_BODY_TEMPLATE};
pub use wp::{
    HostingIntegritySummary, HostingVulnSummary, WpFatalReport, WpInstallRequest, WpInstallStatus,
    WpIntegrityFileIssue, WpIntegrityPluginResult, WpIntegrityScanResult, WpMalwareHit, WpPlugin,
    WpPluginAction, WpPluginActionResult, WpPluginListResponse, WpTheme, WpThemeAction,
    WpThemeActionResult, WpThemeListResponse, WpVulnFinding, WpVulnScanResult,
};

/// Current Unix epoch seconds. Centralized so tests can replace it if needed.
pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}
