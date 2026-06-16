//! Public wire types for hosting limits + suspension state.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingLimits {
    /// `None` = no enforced limit.
    pub disk_soft_bytes: Option<i64>,
    pub disk_hard_bytes: Option<i64>,
    pub inode_soft: Option<i64>,
    pub inode_hard: Option<i64>,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub bw_monthly_bytes: Option<i64>,
    pub over_bw_policy: OverBwPolicy,
    pub throttle_kbps: Option<i64>,
}

impl HostingLimits {
    pub fn defaults() -> Self {
        Self {
            disk_soft_bytes: None,
            disk_hard_bytes: None,
            inode_soft: None,
            inode_hard: None,
            php_memory_mb: 256,
            php_max_exec_secs: 60,
            php_max_children: 5,
            php_max_requests: 1000,
            db_max_connections: 25,
            bw_monthly_bytes: None,
            over_bw_policy: OverBwPolicy::Suspend,
            throttle_kbps: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OverBwPolicy {
    Suspend,
    Throttle,
}

impl OverBwPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Throttle => "throttle",
        }
    }
}

impl FromStr for OverBwPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "suspend" => Ok(Self::Suspend),
            "throttle" => Ok(Self::Throttle),
            other => Err(format!("unknown policy: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SuspendReason {
    Manual { message: Option<String> },
    Expired,
    OverBandwidth,
}

impl SuspendReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Manual { .. } => "manual",
            Self::Expired => "expired",
            Self::OverBandwidth => "over-bandwidth",
        }
    }
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Manual { message } => message.as_deref(),
            Self::Expired => Some("This site has expired."),
            Self::OverBandwidth => Some("This site exceeded its bandwidth allowance."),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingUsageBucket {
    pub period: String,
    pub disk_used_bytes: i64,
    pub inodes_used: i64,
    pub bw_in_bytes: i64,
    pub bw_out_bytes: i64,
    pub php_requests: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingExpiry {
    /// `None` = no expiry. Otherwise unix-epoch seconds.
    pub expires_at: Option<i64>,
    pub owner_email: Option<String>,
    pub grace_days: i64,
    /// CSV like "30,7,1" — days before expiry to send warnings.
    pub warning_offsets_days: String,
}

impl HostingExpiry {
    pub fn defaults() -> Self {
        Self {
            expires_at: None,
            owner_email: None,
            grace_days: 30,
            warning_offsets_days: "30,7,1".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpiringHosting {
    pub id: crate::HostingId,
    pub domain: String,
    pub expires_at: i64,
    pub owner_email: Option<String>,
    pub grace_days: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupRunWire {
    pub id: i64,
    pub hosting_id: crate::HostingId,
    pub target: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub state: String,
    pub archive_path: Option<String>,
    pub db_dump_path: Option<String>,
    pub bytes_total: i64,
    pub error_message: Option<String>,
}

/// What a `BackupRestore` should put back. Lets the operator restore
/// just the database (e.g. after a bad plugin update mangled options)
/// without clobbering files they've changed since, or just the files
/// without rolling back the DB.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackupRestoreMode {
    /// Full restore — extract the archive over htdocs AND import the
    /// sibling SQL dump. The historical behaviour.
    #[default]
    FilesAndDb,
    /// Import the SQL dump only; leave htdocs untouched.
    DbOnly,
    /// Extract the archive over htdocs only; leave the database alone.
    FilesOnly,
}

impl BackupRestoreMode {
    pub fn restores_files(self) -> bool {
        matches!(self, Self::FilesAndDb | Self::FilesOnly)
    }
    pub fn restores_db(self) -> bool {
        matches!(self, Self::FilesAndDb | Self::DbOnly)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilesAndDb => "files_and_db",
            Self::DbOnly => "db_only",
            Self::FilesOnly => "files_only",
        }
    }
}

/// One IP ban as shown in the UI / returned over the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IpBanWire {
    pub id: i64,
    pub ip: String,
    pub hosting_id: Option<String>,
    pub reason: String,
    /// "auto" | "manual".
    pub source: String,
    pub banned_at: i64,
    /// 0 = permanent.
    pub expires_at: i64,
}

#[cfg(test)]
mod restore_mode_tests {
    use super::BackupRestoreMode;

    #[test]
    fn mode_gates() {
        assert!(BackupRestoreMode::FilesAndDb.restores_files());
        assert!(BackupRestoreMode::FilesAndDb.restores_db());
        assert!(BackupRestoreMode::DbOnly.restores_db());
        assert!(!BackupRestoreMode::DbOnly.restores_files());
        assert!(BackupRestoreMode::FilesOnly.restores_files());
        assert!(!BackupRestoreMode::FilesOnly.restores_db());
    }

    #[test]
    fn default_is_full() {
        assert_eq!(BackupRestoreMode::default(), BackupRestoreMode::FilesAndDb);
    }

    #[test]
    fn round_trips_snake_case() {
        let j = serde_json::to_string(&BackupRestoreMode::DbOnly).unwrap();
        assert_eq!(j, "\"db_only\"");
        let back: BackupRestoreMode = serde_json::from_str(&j).unwrap();
        assert_eq!(back, BackupRestoreMode::DbOnly);
    }
}

/// One pending node enrollment invite — what the operator sees in /install.
/// The plaintext token is NEVER persisted; it's returned only once when
/// the invite is minted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInviteSummary {
    pub token_hash: String,
    pub label: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// What `invite_create` returns: the freshly-minted plaintext token (so
/// the UI can paste it into the install command) + its hash for revoke.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInviteMint {
    pub token: String,
    pub token_hash: String,
    pub label: String,
    pub expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let l = HostingLimits::defaults();
        assert_eq!(l.php_memory_mb, 256);
        assert_eq!(l.over_bw_policy, OverBwPolicy::Suspend);
        assert!(l.disk_hard_bytes.is_none());
    }

    #[test]
    fn limits_round_trip() {
        let l = HostingLimits::defaults();
        let s = serde_json::to_string(&l).expect("ser");
        let back: HostingLimits = serde_json::from_str(&s).expect("de");
        assert_eq!(l, back);
    }

    #[test]
    fn policy_str_round_trip() {
        for p in [OverBwPolicy::Suspend, OverBwPolicy::Throttle] {
            assert_eq!(OverBwPolicy::from_str(p.as_str()).unwrap(), p);
        }
    }

    #[test]
    fn suspend_reason_round_trip() {
        let r = SuspendReason::Manual {
            message: Some("over quota".into()),
        };
        let s = serde_json::to_string(&r).expect("ser");
        let back: SuspendReason = serde_json::from_str(&s).expect("de");
        assert_eq!(r, back);
        let r = SuspendReason::Expired;
        let s = serde_json::to_string(&r).expect("ser");
        let back: SuspendReason = serde_json::from_str(&s).expect("de");
        assert_eq!(r, back);
    }
}
