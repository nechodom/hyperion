//! Wire types for URL checks: the master's availability checks of addresses,
//! the replacement for an external uptime tool.
//!
//! The two webhook addresses of a check are credentials. They go IN with
//! [`UrlMonitorInput`] and never come back out: a view says only whether one
//! is set.

use serde::{Deserialize, Serialize};

/// Fewest seconds between two samples of one check.
pub const URL_MIN_INTERVAL_SECS: i64 = 30;
/// Interval a new check starts with.
pub const URL_DEFAULT_INTERVAL_SECS: i64 = 60;
/// Failing samples before a check alerts, when the operator does not say.
pub const URL_DEFAULT_ALERT_AFTER: i64 = 3;

/// What an operator sends to add or change a check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UrlMonitorInput {
    /// `None` adds a check; `Some` changes that one.
    pub id: Option<i64>,
    pub url: String,
    pub interval_secs: i64,
    /// `None`: whatever the probe calls healthy. `Some`: exactly this status.
    pub expected_status: Option<i64>,
    pub alert_after_fails: i64,
    /// Comma-separated addresses; empty means the global ones.
    pub alert_email: Option<String>,
    /// A new Slack webhook. `None` or empty keeps the stored one.
    pub alert_slack_webhook: Option<String>,
    pub clear_slack_webhook: bool,
    /// A new generic webhook. `None` or empty keeps the stored one.
    pub alert_webhook_url: Option<String>,
    pub clear_webhook_url: bool,
    /// The owning node as the web layer worked it out (`local` for the
    /// master) or the operator chose; `None` means no owning node.
    pub node_id: Option<String>,
    /// The operator chose `node_id`; it is not re-derived later.
    pub node_manual: bool,
    /// Who asked, for the audit entry.
    pub actor: String,
}

/// One check as the page lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UrlMonitorView {
    pub id: i64,
    pub url: String,
    pub interval_secs: i64,
    pub expected_status: Option<i64>,
    pub alert_after_fails: i64,
    pub alert_email: String,
    /// A Slack webhook is stored. Its address is never returned.
    pub alert_slack_set: bool,
    /// A generic webhook is stored. Its address is never returned.
    pub alert_webhook_set: bool,
    pub node_id: Option<String>,
    pub node_manual: bool,
    /// `unknown` before the first sample, then `ok` or `alerting`.
    pub alert_state: String,
    pub samples_24h: i64,
    pub success_pct_24h: i64,
    pub avg_ms_24h: i64,
    pub last_sampled_at: i64,
    /// The newest failure in the last 24 hours.
    pub last_error: Option<String>,
    /// Unix seconds the https certificate expires, when one was read.
    pub cert_expires_at: Option<i64>,
}

/// The checks, and whether the module that owns them is on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UrlMonitorList {
    /// The Docker module is on for the cluster. While it is off no check
    /// runs and none is listed.
    pub enabled: bool,
    pub monitors: Vec<UrlMonitorView>,
}

/// A state change not yet acknowledged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UrlMonitorEvent {
    pub id: i64,
    pub url: String,
    /// The stored owning node (`local` for the master).
    pub node_id: Option<String>,
    /// Down, or back up.
    pub down: bool,
    pub error: Option<String>,
}

/// What the web layer learnt when it looked around for an alert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UrlAlertContext {
    /// The check failed and the node it lives on does not answer either.
    pub node_unreachable: bool,
    /// What the Docker stack behind the URL looks like, when its node
    /// answered. A summary of state, never log text.
    pub stack_summary: Option<String>,
    /// The web layer worked out the owning node again (on a recovery);
    /// `node_id` is the result, `None` meaning "no hosting matched". Not
    /// applied to a check whose node the operator chose.
    pub node_rederived: bool,
    pub node_id: Option<String>,
}
