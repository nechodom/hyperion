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
pub mod php;
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
pub use php::PhpVersion;
pub use stats::{ClusterStats, HostingStats, NodeStats};
pub use wp::{WpInstallRequest, WpInstallStatus};

/// Current Unix epoch seconds. Centralized so tests can replace it if needed.
pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}
