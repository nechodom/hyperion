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
