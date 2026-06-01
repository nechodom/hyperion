//! Stats DTOs — per-hosting, per-node, and aggregate cluster stats.
//!
//! Numbers come from the agent's background sampler:
//!   - disk:  `du -sb` against the hosting tree
//!   - bw:    counted from nginx access.log (parsed line-by-line)
//!   - reqs:  same source as bw
//!   - last_request_at: max timestamp seen in the access log
//!   - cpu / mem: from /proc/loadavg and /proc/meminfo on each tick
//!
//! Each sample is persisted to `hosting_usage` (already used for
//! bandwidth quotas) and `node_metrics` (this slice's new table). The
//! API just slices the latest rows.

use serde::{Deserialize, Serialize};

use crate::HostingId;

/// Latest snapshot for a single hosting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingStats {
    pub hosting_id: HostingId,
    pub domain: String,
    pub disk_bytes: i64,
    pub bw_in_bytes_24h: i64,
    pub bw_out_bytes_24h: i64,
    pub requests_24h: i64,
    pub last_request_at: Option<i64>,
    pub sampled_at: i64,
}

/// Latest snapshot for an agent node — cluster-wide or single-node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeStats {
    /// Stable agent ID (per `agent_info.hostname` for now).
    pub node_id: String,
    pub label: String,
    pub hostings_count: i64,
    pub hostings_active: i64,
    pub hostings_suspended: i64,
    pub hostings_failed: i64,
    pub total_disk_bytes: i64,
    pub total_bw_out_24h: i64,
    pub total_requests_24h: i64,
    /// 1-minute load average × 100 (so we can store i64).
    pub loadavg_1m_x100: i64,
    pub mem_total_kib: i64,
    pub mem_used_kib: i64,
    pub uptime_secs: i64,
    pub sampled_at: i64,
    pub agent_version: String,
    pub agent_online: bool,
}

/// Operator-facing alert surfaced on the dashboard. Computed from
/// hostings + certs + backups + node_metrics at request time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardAlert {
    /// "cert_expiring" | "hosting_failed" | "backup_stale" | "high_load"
    pub kind: String,
    /// "info" | "warn" | "error"
    pub severity: String,
    pub message: String,
    /// Optional hosting domain for jump-to-detail.
    pub hosting: Option<String>,
}

/// One enrolled node as shown in admin lists (Install + Stats).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSummary {
    pub node_id: String,
    pub label: String,
    pub master_url: Option<String>,
    pub agent_version: String,
    pub public_ip: Option<String>,
    pub enrolled_at: i64,
    pub last_seen_at: i64,
}

/// Cluster-wide aggregate. Today single-node = node_stats[0]; later
/// folds across enrolled nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterStats {
    pub nodes: Vec<NodeStats>,
    pub total_hostings: i64,
    pub total_active: i64,
    pub total_suspended: i64,
    pub total_failed: i64,
    pub total_disk_bytes: i64,
    pub total_bw_out_24h: i64,
    pub total_requests_24h: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosting_stats_round_trips() {
        let s = HostingStats {
            hosting_id: HostingId("01J".into()),
            domain: "example.com".into(),
            disk_bytes: 1024,
            bw_in_bytes_24h: 2048,
            bw_out_bytes_24h: 4096,
            requests_24h: 100,
            last_request_at: Some(1_700_000_000),
            sampled_at: 1_700_000_500,
        };
        let j = serde_json::to_string(&s).expect("ser");
        let back: HostingStats = serde_json::from_str(&j).expect("de");
        assert_eq!(s, back);
    }

    #[test]
    fn cluster_stats_sums_zero_for_empty() {
        let c = ClusterStats {
            nodes: vec![],
            total_hostings: 0,
            total_active: 0,
            total_suspended: 0,
            total_failed: 0,
            total_disk_bytes: 0,
            total_bw_out_24h: 0,
            total_requests_24h: 0,
        };
        let j = serde_json::to_string(&c).expect("ser");
        let back: ClusterStats = serde_json::from_str(&j).expect("de");
        assert_eq!(c, back);
    }
}
