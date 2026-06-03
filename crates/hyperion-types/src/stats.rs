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

/// A single point in a node-metrics time series. Used by the stats
/// page to render sparklines (load, memory %, BW) without requiring
/// a JS chart library — the template converts these into inline SVG.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeMetricPoint {
    pub at: i64,
    pub loadavg_1m_x100: i64,
    pub mem_used_kib: i64,
    pub mem_total_kib: i64,
    pub total_bw_out_24h: i64,
    pub total_requests_24h: i64,
    pub hostings_count: i64,
}

/// Time-series window of node metrics. `samples` are oldest → newest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NodeMetricsHistory {
    pub samples: Vec<NodeMetricPoint>,
}

/// Status of one systemd unit on the node — collected by
/// `services_health()` for the system-health page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceHealth {
    /// Unit name without the `.service` suffix, e.g. `nginx`, `php8.3-fpm`.
    pub name: String,
    /// Display label / one-line description.
    pub label: String,
    /// `systemctl is-active <unit>` was true.
    pub active: bool,
    /// `systemctl is-enabled <unit>` was true (will autostart at boot).
    pub enabled: bool,
    /// `present` if the unit exists at all on this node.
    /// Reading `services_health` from a node where vsftpd isn't
    /// installed yet should surface "missing" rather than "down".
    pub present: bool,
    /// Short status sub-state, e.g. "running", "failed", "dead",
    /// "exited". Empty if not present.
    pub sub_state: String,
    /// Severity ranking for sorting: `error` (down + critical),
    /// `warn` (down but optional), `info` (missing optional unit),
    /// `ok` (active + enabled). UI may colour rows accordingly.
    pub severity: String,
}

/// Bundle of all service-health rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ServicesHealth {
    pub services: Vec<ServiceHealth>,
    /// Convenience: number of services with severity == "error".
    pub critical_down: usize,
    /// Number of services with severity == "warn".
    pub warn_down: usize,
}

/// Operator-facing view of the agent's effective config — minus
/// secrets. The `Request::AgentConfigView` RPC returns this; the
/// `/settings` UI page reads it. We deliberately do NOT echo
/// passwords or invite tokens here — the operator already has the
/// agent.toml file, this is for at-a-glance visibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentConfigView {
    pub hostname: String,
    pub agent_version: String,
    /// Detected nginx user — relevant because FPM pool ownership
    /// depends on it; surfacing here makes the "why 502" debugging
    /// path trivial.
    pub nginx_user: String,
    pub acme: AcmeConfigView,
    pub email: EmailConfigView,
    pub slack: SlackConfigView,
    pub backup_remote: BackupRemoteConfigView,
    pub backup_retention: BackupRetentionConfigView,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AcmeConfigView {
    pub contact_email: String,
    pub directory_url: String,
    pub challenge_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EmailConfigView {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    /// True if a password is configured (we don't return the password).
    pub smtp_password_set: bool,
    pub from_address: String,
    pub from_name: String,
    pub security: String,
    pub default_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SlackConfigView {
    /// True if a default webhook is configured (we never echo the
    /// webhook URL — it's a credential).
    pub default_webhook_set: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BackupRemoteConfigView {
    pub enabled: bool,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// True if a password is configured. We never echo the password.
    pub password_set: bool,
    pub base_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BackupRetentionConfigView {
    pub max_age_days: i64,
    pub keep_latest_n: i64,
}

/// Sanitised wire shape of one row of `web_users`. NEVER includes the
/// password hash or the TOTP secret — those stay on the agent. Booleans
/// `totp_enrolled` and `totp_required` are enough for the UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebUserSummary {
    pub id: i64,
    pub username: String,
    pub email: String,
    /// "super_admin" | "admin" | "operator" | "viewer"
    pub role: String,
    pub totp_enrolled: bool,
    pub totp_required: bool,
    pub locked: bool,
    pub locked_reason: Option<String>,
    pub last_login_at: Option<i64>,
    pub created_at: i64,
}

/// Outcome of a `Request::WebLogin` call. Web binary uses this to decide
/// whether to mint a session immediately, prompt for 2FA, or surface
/// a clean error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WebLoginResult {
    /// Password matches + user has no 2FA. Web can mint a session.
    Ok {
        user_id: i64,
        username: String,
        email: String,
        role: String,
    },
    /// Password matches but user has 2FA enrolled — prompt for TOTP.
    /// Web should stash `user_id` in a short-lived signed cookie and
    /// require a second POST with the TOTP code.
    NeedsTotp {
        user_id: i64,
        username: String,
    },
    /// Password doesn't match (or user doesn't exist). We do NOT
    /// distinguish "no such user" from "wrong password" to avoid
    /// account-enumeration.
    Invalid,
    /// User is locked. `reason` is shown to the user verbatim.
    Locked {
        reason: String,
    },
}

/// Outcome of `Request::WebVerify2fa` — accept the TOTP code.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WebVerify2faResult {
    Ok {
        user_id: i64,
        username: String,
        email: String,
        role: String,
    },
    Invalid,
}

/// Output of `Request::Web2faEnroll` — only returned ONCE; web shows
/// the secret + QR + backup codes to the operator and they must scan
/// + save before confirming.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Web2faEnrollment {
    pub secret_base32: String,
    pub otpauth_url: String,
    pub backup_codes: Vec<String>,
}

/// One grant row on `web_user_hosting_access`. Used by the per-hosting
/// "Access" tab and by the filter that scopes operator/viewer lists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebHostingAccess {
    pub user_id: i64,
    pub username: String,
    pub email: String,
    /// "read" | "manage"
    pub level: String,
    pub granted_by: Option<i64>,
    pub granted_at: i64,
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
