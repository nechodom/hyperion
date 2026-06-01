//! Shared serde-friendly types for the linux-manager workspace.
//!
//! No I/O, no system calls — just newtype IDs, enums, and DTOs that
//! cross crate boundaries and the RPC wire.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

pub mod cert;
pub mod db;
pub mod hosting;
pub mod ids;
pub mod php;

pub use cert::{CertInfo, CertRenewOutcome, CertRenewResult};
pub use db::{DbProvision, DbSummary};
pub use hosting::{HostingDetail, HostingState, HostingSummary};
pub use ids::{AgentId, HostingId, SecretId};
pub use php::PhpVersion;

/// Current Unix epoch seconds. Centralized so tests can replace it if needed.
pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}
