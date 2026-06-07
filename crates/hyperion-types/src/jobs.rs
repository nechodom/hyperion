//! Generic background-job descriptor surfaced to the UI + hctl.
//!
//! The agent's `jobs` table stores the authoritative state; this is
//! the wire-format projection that flows through RPC and renders
//! into the HTMX-polled progress card.

use serde::{Deserialize, Serialize};

/// One job (e.g. "migrating example.cz from node-01 to node-02") at
/// the moment the agent was queried. The UI polls on a 2s cadence
/// while `state == "running"` and stops once it goes terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct JobView {
    pub id: String,
    /// Free-text discriminator — `migration`, `install`, `backup`,
    /// `acme_issue`, `node_update`, `wp_reinstall_all`, `db_reset`,
    /// `hosting_clone`, `rofs_fix`, `cert_renew`. The UI uses this
    /// to pick an icon and humanise the title.
    pub kind: String,
    /// Optional human-friendly subject (usually a domain).
    pub target: Option<String>,
    /// `running` | `done` | `failed` | `cancelled`.
    pub state: String,
    /// Short label for the current step. Operators read this most.
    pub step_label: String,
    /// 0-100. Monotonic by convention; not enforced.
    pub progress_pct: i64,
    /// Bounded ~16 KiB tail of the operation's log. Older bytes are
    /// dropped as the operation produces new output.
    pub log_tail: String,
    /// Set when `state == failed`.
    pub error: Option<String>,
    /// Per-kind opaque context (e.g. migration stores src + dst node
    /// IDs so the UI can render a richer card without a second
    /// lookup).
    pub payload_json: String,
    /// Username / "system" / "agent". `0` for non-human actors.
    pub actor_uid: i64,
    pub actor_label: String,
    pub started_at: i64,
    pub updated_at: i64,
    /// Set once `state` goes terminal.
    pub finished_at: Option<i64>,
}

impl JobView {
    /// True when the operation has finished one way or the other.
    pub fn is_terminal(&self) -> bool {
        matches!(self.state.as_str(), "done" | "failed" | "cancelled")
    }
}

/// One row from `web_sessions`. The signed-cookie Session in
/// `hyperion-auth` is the wire-format the COOKIE carries; this is
/// the projection the agent stores + the panel renders into
/// /settings/sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WebSessionView {
    pub sid: String,
    pub user_id: i64,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<i64>,
}

impl WebSessionView {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Per-hosting quota policy + last-applied state. Powers the
/// "Quota" tab on the hosting detail page and the QuotaSet /
/// QuotaGet RPCs. Zero values mean "no cap".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingQuotaView {
    pub hosting_id: String,
    pub disk_soft_kib: i64,
    pub disk_hard_kib: i64,
    pub mem_limit_mib: i64,
    pub bw_soft_mib: i64,
    pub bw_hard_mib: i64,
    /// Set when the kernel last accepted a setquota call.
    pub applied_at: Option<i64>,
    /// Set when the last setquota call failed (e.g. quotaon not
    /// enabled on the filesystem hosting the user's home dir).
    pub last_error: Option<String>,
    pub updated_at: i64,
}

/// Report of current vs policy. `current_usage_kib` reads from
/// `quota -u <user>` (or `du -sk <home>` as fallback when the
/// kernel-level quota subsystem isn't enabled).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingQuotaReport {
    pub policy: HostingQuotaView,
    pub current_disk_kib: i64,
    /// True when `quotaon` is enabled on the mount carrying the
    /// hosting's home dir. False ⇒ `setquota` would no-op; the UI
    /// shows a setup-guidance banner.
    pub quotas_enabled_on_fs: bool,
    /// Human-readable hint when quotas_enabled_on_fs is false.
    pub setup_hint: String,
}

