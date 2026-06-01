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
