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
    /// Real CPU busy % × 100 (migration 042). `#[serde(default)]` so an older
    /// agent that doesn't send it still deserializes (shows 0).
    #[serde(default)]
    pub cpu_pct_x100: i64,
    #[serde(default)]
    pub swap_total_kib: i64,
    #[serde(default)]
    pub swap_used_kib: i64,
    /// PSI "some avg10" × 100 for cpu / memory / io (0 if kernel lacks PSI).
    #[serde(default)]
    pub psi_cpu_x100: i64,
    #[serde(default)]
    pub psi_mem_x100: i64,
    #[serde(default)]
    pub psi_io_x100: i64,
    /// Network throughput in bytes/sec (delta over the sample window).
    #[serde(default)]
    pub net_rx_bps: i64,
    #[serde(default)]
    pub net_tx_bps: i64,
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
    /// When true, the auto-placer + create wizard skip this node.
    /// Existing hostings on it keep serving traffic — drain is
    /// for "stop new work" maintenance windows, not "evict".
    /// `#[serde(default)]` so workers running the pre-032 schema
    /// still parse this struct fine.
    #[serde(default)]
    pub is_drained: bool,
    /// Optional operator note shown next to the "drained" pill.
    #[serde(default)]
    pub drain_reason: String,
    /// Worker's inbound TLS SPKI pin (curl --pinnedpubkey form) as last
    /// reported on a heartbeat. `None` until first reported (or the agent
    /// predates Block C / has remote_rpc disabled). `#[serde(default)]`
    /// so workers on the older wire format still deserialize.
    #[serde(default)]
    pub tls_spki_pin: Option<String>,
}

/// Cluster-wide aggregate. Today single-node = node_stats[0]; later
/// folds across enrolled nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default)]
    pub cpu_pct_x100: i64,
    #[serde(default)]
    pub swap_used_kib: i64,
    #[serde(default)]
    pub net_rx_bps: i64,
    #[serde(default)]
    pub net_tx_bps: i64,
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
    /// Raw systemd ActiveState ("active" | "activating" | "reloading"
    /// | "deactivating" | "inactive" | "failed" | "unknown"). Drives
    /// the "restarting…" pill in the UI so an operator doesn't see
    /// "down + stop-sigterm" when a service is mid-restart.
    #[serde(default)]
    pub active_state: String,
    /// True when ActiveState is `activating`, `reloading`, or
    /// `deactivating`. Severity is still "ok" for these because
    /// they resolve in seconds, but the UI shows a yellow
    /// "restarting" badge instead of green "running".
    #[serde(default)]
    pub transient: bool,
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

/// Read-only snapshot of the node's firewall state. The agent runs
/// `nft list ruleset` (modern Debian default) and falls back to
/// `iptables -L -n` for older boxes. We expose both the structured
/// "open ports" view (parsed best-effort) and the full raw text so
/// the operator can always eyeball the actual ruleset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FirewallView {
    /// `"nft"` when nftables answered, `"iptables"` when we fell
    /// back, or `"unknown"` when neither command returned a parseable
    /// ruleset (very minimal containers, e.g.).
    pub backend: String,
    /// Structured open-port rows. Each entry is a single accepted
    /// port + protocol pair plus a human-readable "reason" label
    /// derived from the well-known port → service map. Sorted by
    /// port number ascending. Replaces the old `open_tcp` /
    /// `open_udp` u16 lists — the UI needs the label inline and
    /// re-grouping by category in the template was clumsy.
    #[serde(default)]
    pub ports: Vec<FirewallPort>,
    /// Full raw ruleset output. Always present, even when parsing
    /// failed.
    pub raw: String,
    /// Stderr from the firewall command (empty on success). When
    /// non-empty + `raw` empty, the operator gets context for why
    /// the page shows no rules.
    pub error: String,
}

/// One row in the firewall's open-ports table. Built best-effort
/// from the `nft list ruleset` / `iptables -L -n` dump.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FirewallPort {
    pub port: u16,
    /// `"tcp"` or `"udp"`.
    pub proto: String,
    /// Human-readable label, e.g. "HTTPS (nginx)", "Hyperion RPC".
    /// `"Unknown"` when no well-known service maps to this port.
    pub label: String,
    /// One of: `"infra"` (SSH, DNS, …), `"web"` (HTTP/S),
    /// `"mail"` (SMTP, IMAP, POP3, submission), `"db"` (MySQL,
    /// PostgreSQL, Redis), `"hyperion"` (panel + master RPC),
    /// `"unknown"`. Drives the pill colour in the UI.
    pub category: String,
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
    /// Multi-node cluster placement preferences. Optional in the
    /// wire schema so older agents that pre-date the field keep
    /// deserializing.
    #[serde(default)]
    pub cluster: ClusterConfigView,
    /// Operator-editable wording for the Slack + email messages Hyperion
    /// sends (alerts, reminders, test sends). `#[serde(default)]` keeps
    /// older agents parseable; the defaults are pass-through so wording
    /// is unchanged until the operator edits a template.
    #[serde(default)]
    pub notifications: NotificationTemplatesView,
}

/// Editable templates for outbound notification wording. Each is a string
/// with `{placeholder}` tokens substituted at send time. Defaults are
/// pass-through (the raw message/subject/body), so behaviour is identical
/// to no templating until the operator customises one.
///
/// Placeholders:
/// - Slack: `{message}`, `{time}`, `{panel}`
/// - Email subject: `{subject}`, `{time}`
/// - Email body: `{body}`, `{time}`, `{panel}`, `{kind}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationTemplatesView {
    pub slack_template: String,
    pub email_subject_template: String,
    pub email_body_template: String,
}

impl Default for NotificationTemplatesView {
    fn default() -> Self {
        Self {
            slack_template: "{message}".into(),
            email_subject_template: "{subject}".into(),
            email_body_template: "{body}".into(),
        }
    }
}

/// Cluster-placement preferences for the master web UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterConfigView {
    /// When `false`, /hostings/new hides the master from the
    /// "Target node" dropdown and the agent refuses local
    /// hosting_create calls — turning the master into a
    /// control-plane-only node. Existing hostings on the master
    /// stay where they are; this only affects NEW creates.
    pub master_accepts_hostings: bool,

    /// CSV of node ids that are TEST nodes — they host throwaway
    /// staging sites, not production. Creating a hosting on a
    /// test node forces the domain to follow `test_domain_template`
    /// (so test sites can't squat real customer domains by
    /// accident). Conversely, creating on a production node
    /// refuses domains that match the test template.
    #[serde(default)]
    pub test_node_ids: String,

    /// Template for auto-generated test-site domains. `{name}`
    /// is the user-supplied short name and `{node}` is the
    /// target node id. Default empty = test-node feature off.
    /// Example: "test.{name}.{node}.testovaciverze.cz".
    #[serde(default)]
    pub test_domain_template: String,

    /// FQDN where the Hyperion master UI should be served via
    /// nginx + a real TLS cert (e.g. "panel.example.com"). When
    /// set, a one-shot `PanelProvision` RPC writes an nginx vhost
    /// that proxies `https://<hostname>` → the master's local
    /// hyperion-web (HTTPS on 127.0.0.1:8443) and issues a real
    /// Let's Encrypt cert. Empty = self-signed on IP:8443 only
    /// (the default).
    #[serde(default)]
    pub panel_hostname: String,

    /// When true, every WordPress install on a test node gets
    /// `blog_public = 0` (Discourage search engines) so test
    /// content never leaks into Google. Operator can still
    /// flip it manually in the WP admin.
    #[serde(default)]
    pub test_wp_no_index: bool,

    /// When true, hosting `delete` is a SOFT delete: nginx → 503,
    /// FPM stop, DB lock, OS user lock, files preserved. State
    /// flips to "trashed" with a `trashed_at` timestamp. Scheduler
    /// purges trashed sites older than `trash_retention_days`.
    /// Operator can also Restore (un-trash) or Delete permanently
    /// from /trash. Default off = existing hard-delete behaviour.
    #[serde(default)]
    pub trash_enabled: bool,

    /// How many days to keep a trashed hosting before the
    /// scheduler GCs it. Clamped to 1..=365 at the boundary;
    /// default 30. Only matters when `trash_enabled = true`.
    #[serde(default)]
    pub trash_retention_days: i64,

    /// How many days to keep audit-log entries before the
    /// scheduler purges them. Clamped to 0..=3650; `0` = keep
    /// forever (the default — matches pre-retention behaviour).
    ///
    /// The audit log is a tamper-evident hash chain; purging
    /// would break `verify_chain` so we anchor the chain at the
    /// oldest surviving row's prev_hash (single-row table
    /// `audit_chain_anchor`) and resume verification from
    /// there. Verifier transparently honours the anchor.
    #[serde(default)]
    pub audit_retention_days: i64,

    /// When true, admin+ users who log in without 2FA enrolled are
    /// corralled to the enrolment card before they can use the panel.
    /// Defaults to on. Operators can turn it off from /settings (e.g.
    /// during a migration) without rebuilding.
    #[serde(default = "default_true")]
    pub enforce_admin_2fa: bool,

    /// When true, the master passes `curl --pinnedpubkey sha256//<pin>`
    /// on every RPC to a worker that has REPORTED a TLS SPKI pin (Block C
    /// enforce phase) — a presented cert that doesn't match the pin makes
    /// the RPC fail. Defaults to OFF: enforcement is a deliberate flip the
    /// operator makes only AFTER the warn-only phase has confirmed pins
    /// are stable (no spurious mismatch warnings), otherwise a stale pin
    /// would break master→worker RPC. Nodes that have not yet reported a
    /// pin are never enforced (nothing to pin against), so a brand-new
    /// worker is still reachable until its first heartbeat.
    #[serde(default)]
    pub enforce_worker_cert_pinning: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ClusterConfigView {
    fn default() -> Self {
        Self {
            // Permissive default = old behaviour. Operators
            // opt in to "control plane only" via the toggle.
            master_accepts_hostings: true,
            test_node_ids: String::new(),
            test_domain_template: String::new(),
            test_wp_no_index: false,
            panel_hostname: String::new(),
            trash_enabled: false,
            trash_retention_days: 30,
            audit_retention_days: 0, // 0 = keep forever
            enforce_admin_2fa: true,
            // OFF by default — enforcement is an explicit operator flip
            // after the warn-only phase confirms pins are stable.
            enforce_worker_cert_pinning: false,
        }
    }
}

impl ClusterConfigView {
    /// Is this node id flagged as a test node?
    pub fn is_test_node(&self, node_id: &str) -> bool {
        if self.test_node_ids.trim().is_empty() {
            return false;
        }
        self.test_node_ids
            .split(',')
            .map(|s| s.trim())
            .any(|s| !s.is_empty() && s == node_id)
    }

    /// Render the test domain for a given short name + node info.
    /// `{node}` is substituted with the node's HOSTNAME when known
    /// (operator-friendly: `s4` not `node_01kt9d…`); falls back to
    /// `node_id` only when hostname is empty.
    /// `{node_id}` is also supported as an explicit alternative
    /// for operators who want the long ID for namespacing.
    /// Returns empty string when the template isn't configured.
    pub fn render_test_domain(&self, name: &str, node_id: &str, node_hostname: &str) -> String {
        if self.test_domain_template.is_empty() {
            return String::new();
        }
        let node_token = if node_hostname.trim().is_empty() {
            node_id.trim()
        } else {
            node_hostname.trim()
        };
        self.test_domain_template
            .replace("{name}", name.trim())
            .replace("{node}", node_token)
            .replace("{node_id}", node_id.trim())
            .replace("{hostname}", node_hostname.trim())
            .to_ascii_lowercase()
    }

    /// The wildcard BASE domain for a test node — everything below an
    /// auto-subdomain's first label. A single `*.<base>` cert covers
    /// every `<name>.<base>` the node spins up, so it's issued once in
    /// Settings instead of per site. `None` when the template isn't
    /// configured or yields no safe parent (a bare TLD / single label).
    pub fn node_wildcard_base(&self, node_id: &str, node_hostname: &str) -> Option<String> {
        let sample = self.render_test_domain("wildcard", node_id, node_hostname);
        let (_, rest) = sample.split_once('.')?;
        // Refuse `*.tld` — a single-label parent is never a safe wildcard.
        if rest.is_empty() || !rest.contains('.') {
            return None;
        }
        Some(rest.to_string())
    }
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
    NeedsTotp { user_id: i64, username: String },
    /// Password doesn't match (or user doesn't exist). We do NOT
    /// distinguish "no such user" from "wrong password" to avoid
    /// account-enumeration.
    Invalid,
    /// User is locked. `reason` is shown to the user verbatim.
    Locked { reason: String },
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

/// One entry returned by `HostingFileList`. The path is RELATIVE to
/// the hosting's htdocs root — UI breadcrumbs use this directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingFileEntry {
    /// Just the basename (last path component).
    pub name: String,
    /// Path RELATIVE to htdocs (e.g. "wp-content/themes").
    pub rel_path: String,
    /// "file" | "dir" | "symlink" | "other"
    pub kind: String,
    pub size: u64,
    pub modified_at: i64,
    /// MIME guess from extension (text files render inline; binary
    /// shows a download hint).
    pub mime: String,
    /// True iff this file is below the inline-render size cap AND
    /// has a text MIME we recognise. UI uses this to decide whether
    /// to show "View" or "Download" only.
    pub inline_viewable: bool,
}

/// Body of one viewed file. Returned by `HostingFileRead`. Capped
/// at 1 MiB; oversized files return an empty `content` and `truncated: true`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingFileContent {
    pub rel_path: String,
    pub mime: String,
    pub size: u64,
    pub content: String,
    pub truncated: bool,
}

/// Per-hosting monitor config — read back to the operator's settings
/// form on the hosting detail page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MonitorConfigView {
    pub enabled: bool,
    pub url_path: String,
    pub interval_secs: i64,
    pub alert_after_fails: i64,
    pub alert_email: Option<String>,
    pub alert_slack_webhook_set: bool,
    pub alert_webhook_url: Option<String>,
    pub consecutive_fails: i64,
    pub last_alert_at: Option<i64>,
    pub alert_state: String,
}

/// One probe sample for the per-hosting monitor mini-chart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorSamplePoint {
    pub at: i64,
    pub success: bool,
    pub http_status: Option<i64>,
    pub response_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MonitorHistory {
    pub samples: Vec<MonitorSamplePoint>,
}

/// One row out of the per-hosting email log. See
/// `hyperion-state/src/email_log.rs` for the storage layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailLogEntry {
    pub id: i64,
    pub hosting_id: Option<String>,
    pub to_address: String,
    pub subject: String,
    pub body_preview: String,
    pub kind: String,
    pub state: String,
    pub error: Option<String>,
    pub smtp_code: Option<String>,
    pub sent_at: i64,
    /// Node this entry came from, as a display label. The agent leaves it
    /// `None`; the master tags it after a cross-node fan-in so the
    /// cluster-wide /emails page can show a node column. `#[serde(default)]`
    /// keeps older agents' entries parseable.
    #[serde(default)]
    pub node: Option<String>,
}

/// Per-hosting FTP account summary: who can log in, when their
/// password was last touched, and whether vsftpd actually accepts
/// the credential right now. Drives the "FTP accounts" table on
/// the per-hosting FTP tab + the cluster-wide /ftp page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FtpAccountSummary {
    /// Linux user name (== hosting.system_user).
    pub user: String,
    /// Domain of the hosting this user belongs to. Empty if the
    /// user has a shadow password but no matching hosting row
    /// (rare — probably an operator-created account).
    pub domain: String,
    /// True when /etc/shadow has a real bcrypt/sha-512 hash for
    /// this user. False = locked or no-password.
    pub has_password: bool,
    /// Hosting state for context — "active" / "suspended" / etc.
    /// Empty when the user doesn't map to a hosting row.
    pub hosting_state: String,
    /// Node hosting this account.
    pub node_id: String,
}

/// One outbound mail sent BY a hosted PHP site (captured by the
/// site-mail-wrapper). Distinct from the Hyperion-sent emails in
/// EmailLogEntry — those flow through our SMTP config, these flow
/// through the local sendmail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SiteEmailLogEntry {
    pub ts: i64,
    /// system_user — maps to a hosting via the same field on
    /// HostingDetail (`detail.system_user`).
    pub user: String,
    pub from_address: String,
    pub to_address: String,
    pub subject: String,
    /// First ~1 KB of body, captured at send time.
    pub body_excerpt: String,
}

/// Outcome of `EmailSmtpAutodetect`. `found = false` means we
/// couldn't reach any local relay; UI then offers the manual form
/// with a hint about typical relay choices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SmtpAutodetect {
    pub found: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    /// "starttls" | "tls" | "plain"
    pub security: String,
    /// e.g. "hyperion@s4.digitalka.cz" — local hostname-derived
    /// suggestion the operator can keep or override.
    pub suggested_from: String,
    /// One-line operator-facing note explaining what we found.
    pub notes: String,
}

/// One row in `MtaDiagnostics::outbound_smtp_probes` — TCP-connect
/// probe to one well-known SMTP host:port. `latency_ms` is filled
/// when reachable; `error` is filled when not. Mutually exclusive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MtaPortProbe {
    pub port: u16,
    pub host: String,
    pub reachable: bool,
    /// Round-trip latency in ms when reachable.
    #[serde(default)]
    pub latency_ms: u64,
    /// Empty when reachable; verbatim error when not.
    #[serde(default)]
    pub error: String,
    /// Human-friendly note explaining what this port is for so
    /// the operator knows what each row means even on first read.
    /// e.g. "MX delivery", "SMTPS submission",
    /// "STARTTLS submission".
    #[serde(default)]
    pub purpose: String,
}

/// Filesystem (rootfs / `/usr`) read-only diagnostics + the
/// outcomes of any auto-fix attempts. Returned by
/// `Request::FsDiagnoseAndFix`. Lets the operator see at a glance
/// *why* /usr is RO and which fixes were tried.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FsDiagnostics {
    /// True iff `/usr` could be written to (tested by touching a
    /// sentinel file). The whole point of this RPC — operator
    /// wants this true.
    pub usr_writable_now: bool,
    /// Was /usr writable BEFORE the fix attempts? Compared against
    /// `usr_writable_now` so the UI can render "fixed by Hyperion"
    /// vs "already was OK".
    pub usr_writable_before: bool,
    /// Verbatim `mount | grep ' / '` summary line, e.g.
    /// `/dev/vda1 on / type ext4 (rw,relatime)`. Empty when the
    /// probe couldn't find the rootfs.
    pub root_mount_line: String,
    /// Verbatim `mount | grep ' /usr '` summary line — present
    /// only when /usr is a separate mountpoint (rare on standard
    /// Debian, common on snap-managed boxes).
    pub usr_mount_line: String,
    /// Mount options on the rootfs as parsed from `/proc/mounts`
    /// — `rw,relatime` / `ro,nodev` etc.
    pub root_options: String,
    /// Mount options on /usr if it's a separate mountpoint.
    pub usr_options: String,
    /// Filesystem type — `ext4`, `xfs`, `overlay`, `squashfs`,
    /// `tmpfs`. Helps the operator understand immutability.
    pub root_fstype: String,
    pub usr_fstype: String,
    /// Best-effort image classification: "standard" |
    /// "snap-managed" | "ostree" | "overlay-immutable" | "unknown".
    /// Drives the recommendation messaging.
    pub image_kind: String,
    /// `/etc/fstab` entry for the rootfs as a raw line — operator
    /// can scan it for `ro,` and know whether a reboot would
    /// undo any remount.
    pub fstab_root_line: String,
    /// True when `lsattr /usr` reports the immutable attr (`i`).
    /// We attempt `chattr -i` when this is set.
    pub immutable_attr_set: bool,
    /// Steps the RPC actually ran, in order. Empty when `dry_run`
    /// was passed. Each entry is a short label like
    /// `mount -o remount,rw /` paired with its exit code and a
    /// truncated message.
    pub fix_steps: Vec<FsFixStep>,
    /// "fixed" | "no-fix-needed" | "still-broken" |
    /// "image-immutable" | "dry-run". Drives the headline pill on
    /// the UI card.
    pub final_state: String,
    /// Operator-facing next-action list. Always non-empty —
    /// includes a "you're good" message on success.
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FsFixStep {
    /// Human label, e.g. "remount,rw /" / "chattr -i /usr".
    pub label: String,
    /// Process exit code. -1 = spawn error.
    pub exit_code: i32,
    /// Stderr/stdout tail (≤256 chars).
    pub message: String,
    /// True iff the writability re-probe after this step said yes.
    pub now_writable: bool,
}

/// Diagnostics for the local MTA (postfix), returned by
/// `Request::MtaDiagnostics`. Drives the "MTA" card in /settings.
/// Every field is read live — no caching — so the operator sees
/// current state on every page load. Cheap probes only (no SMTP
/// connect, no DNS lookup); page render stays sub-100ms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MtaDiagnostics {
    /// "direct-mx" | "smart-host" | "default" | "not-installed".
    /// "default" means postfix is installed but Hyperion hasn't
    /// applied either mode — UI shows a "Reconfigure" prompt.
    pub mode: String,
    /// True iff `/usr/sbin/sendmail` exists and is executable.
    /// Without this PHP `mail()` returns false on every call.
    pub sendmail_executable: bool,
    /// `systemctl is-active postfix` — true when running.
    pub service_active: bool,
    /// `systemctl is-enabled postfix` — true when set to autostart.
    pub service_enabled: bool,
    /// True when `/etc/postfix/hyperion-relay.marker` exists, i.e.
    /// the boot self-heal already wrote a managed config. False
    /// means the operator is on default-Debian postfix (or never
    /// installed it). The marker body is in `marker_body`.
    pub marker_present: bool,
    /// Raw contents of the marker file (when present) — operator-
    /// friendly grep target. No secrets.
    pub marker_body: String,
    /// `postconf myhostname` — what postfix uses as HELO and
    /// @-domain on local mail. Must match the IP's PTR record for
    /// most receivers to accept the mail.
    pub myhostname: String,
    /// True iff myhostname contains at least one dot (a poor
    /// proxy for "is a real FQDN" but catches the most common
    /// botched case where the box just has a short hostname).
    pub myhostname_is_fqdn: bool,
    /// `postconf relayhost`. Empty string = direct MX. Non-empty
    /// = smart-host (and matches the [email] smtp_host/port).
    pub relayhost: String,
    /// `postqueue -p | tail -1` — "Mail queue is empty" or
    /// "-- N Kbytes in M Requests." Cheap operator hint about
    /// stuck mail.
    pub mailq_summary: String,
    /// Number of messages parsed out of the summary line
    /// ("M Requests" → M). 0 when the queue is empty. The UI uses
    /// this to decide whether to auto-expand the queue/log details.
    #[serde(default)]
    pub mailq_total: usize,
    /// Full `postqueue -p` output, capped at ~4 KB so a runaway
    /// queue doesn't blow out the diagnostics RPC. Empty when the
    /// queue is empty or postqueue isn't available.
    #[serde(default)]
    pub mailq_detail: String,
    /// Tiny outbound connectivity probe — `tcp connect to
    /// gmail-smtp-in.l.google.com:25` with a 3-second timeout.
    /// `None` means "we didn't try / DNS lookup failed";
    /// `Some(true)` = SMTP relay can reach the wider Internet on
    /// port 25 from this node; `Some(false)` = blocked (probably
    /// ISP egress filter — request unblock from support).
    #[serde(default)]
    pub outbound_port_25_ok: Option<bool>,
    /// One-line human-readable explanation of the port-25 probe
    /// (latency, error message, "not probed because ...").
    #[serde(default)]
    pub outbound_port_25_msg: String,
    /// Probes for every common outbound SMTP port. When 25 is
    /// blocked, the operator needs to know which alternative is
    /// open before they can set up a smart-host workaround.
    /// Entries are `(port, target_host, reachable)`:
    ///   * port 25  → MX delivery target (gmail's MX)
    ///   * port 465 → implicit-TLS submission (smtp.gmail.com)
    ///   * port 587 → STARTTLS submission (smtp.gmail.com)
    ///   * port 2525 → alt-submission used by Mailgun/SendGrid
    ///     when the operator is in a network with 587 blocked too
    /// Order is preserved. Empty when probing is disabled.
    #[serde(default)]
    pub outbound_smtp_probes: Vec<MtaPortProbe>,
    /// Best-effort tail of `/var/log/mail.log` (last 12 lines).
    /// Empty when the log doesn't exist (fresh install) or we
    /// can't read it (rare permissions issue).
    pub recent_log_tail: Vec<String>,

    // ── This node's editable `[email]` config, read from its own
    //    agent.toml so the Settings → Mail form can pre-fill per node.
    //    The password is never sent back (only `cfg_password_set`).
    #[serde(default)]
    pub cfg_enabled: bool,
    #[serde(default)]
    pub cfg_smtp_host: String,
    #[serde(default)]
    pub cfg_smtp_port: i64,
    #[serde(default)]
    pub cfg_smtp_user: String,
    #[serde(default)]
    pub cfg_from_address: String,
    #[serde(default)]
    pub cfg_from_name: String,
    #[serde(default)]
    pub cfg_security: String,
    #[serde(default)]
    pub cfg_default_to: String,
    #[serde(default)]
    pub cfg_password_set: bool,
}

/// What we know about whether Hyperion is up-to-date. Returned by
/// `Request::UpdateCheck`; cached agent-side so the GitHub Releases
/// API isn't hit on every page load.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateStatus {
    /// Currently-installed binary git SHA / version string.
    pub current_sha: String,
    /// Latest known remote SHA from the rolling release. Empty if
    /// we've never checked successfully.
    pub latest_sha: String,
    /// Tag name of the upstream release (e.g. "rolling").
    pub latest_tag: String,
    /// When upstream was built (ISO 8601 string from the release body).
    pub latest_built: String,
    /// Last time we successfully reached the remote registry.
    pub last_checked_at: i64,
    /// True if current_sha != latest_sha AND we have both. Falls back
    /// to false on probe failure (don't nag operators about a probe
    /// we couldn't make).
    pub update_available: bool,
    /// Human-readable status — "up to date", "update available",
    /// "never checked", "probe failed: <reason>".
    pub message: String,
}

/// State of the most-recent (or in-progress) service-install job
/// triggered via Request::ServiceInstall. Returned by
/// ServiceInstallStatus so the UI can show live apt-get output
/// instead of just blocking the operator's page for minutes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInstallStatus {
    /// systemd unit name (e.g. "php8.4-fpm"). Empty when no
    /// install has ever run on this node.
    pub service_name: String,
    /// apt package name (typically same as service_name).
    pub pkg: String,
    /// Unix seconds when the job started. 0 → no job has ever run.
    pub started_at: i64,
    /// Unix seconds when the job finished. 0 → still running, or
    /// no job has ever run.
    pub finished_at: i64,
    /// "idle" | "running" | "succeeded" | "failed".
    pub state: String,
    /// Combined stdout+stderr tail of apt-get + systemctl enable,
    /// capped at ~8 kB. Live during the run, frozen after.
    pub log_tail: String,
    /// Final non-zero exit code on failure (0 on success / still
    /// running).
    pub exit_code: i32,
}

/// State of the most-recent (or in-progress) node update job
/// triggered via Request::NodeUpdateRun. Returned by
/// NodeUpdateStatus so the UI can poll progress.
/// One row on the /trash page. Computed by the master web from
/// each agent's `list_trash` response — the seconds_remaining
/// field is server-computed so the UI doesn't have to know about
/// trash_retention_days.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrashEntry {
    pub id: String,
    pub domain: String,
    /// Unix-epoch seconds the hosting went to trash.
    pub trashed_at: i64,
    /// Unix-epoch seconds when the scheduler will purge it.
    pub purge_at: i64,
    /// `purge_at - now()` clamped at 0.
    pub seconds_remaining: i64,
    /// Which node hosts the (still-on-disk) site.
    pub node_id: String,
}

/// One notification surfaced in the bell-icon dropdown.
/// Wire-side mirror of `hyperion_state::notifications::NotificationRow`,
/// dropping the per-user pointer (the wire response is already
/// scoped to the logged-in user).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationView {
    pub id: i64,
    /// "info" | "warn" | "error" — drives the dot colour.
    pub severity: String,
    pub title: String,
    pub body: String,
    /// Internal route to navigate to when clicked.
    pub href: String,
    pub kind: String,
    pub created_at: i64,
    /// None = unread, Some(unix) = read at that time.
    pub read_at: Option<i64>,
}

/// Bell-dropdown payload: a recent slice + an unread total. The
/// total can be larger than `items.len()` if the user has more
/// unread items than the dropdown's hard limit (default 10).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationFeed {
    pub items: Vec<NotificationView>,
    pub unread_total: i64,
}

/// One row on the cluster-wide /monitoring overview page. Mirrors
/// the MonitorConfig + computed success rate / avg latency over
/// the last `MONITOR_OVERVIEW_HISTORY_LIMIT` (~24h) samples.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorOverviewItem {
    pub hosting_id: String,
    pub domain: String,
    pub url_path: String,
    pub interval_secs: i64,
    /// "ok" | "alerting" | "unknown" (no samples yet).
    pub alert_state: String,
    pub consecutive_fails: i64,
    pub last_alert_at: Option<i64>,
    /// Total samples in the window (≤ 288 = 24h × 12 per hour).
    pub samples_24h: i64,
    /// Successful samples / total, as a 0-100 integer percent.
    pub success_pct_24h: i64,
    /// Average response time over the successful samples; 0 if none.
    pub avg_response_ms_24h: i64,
    /// Most recent probe timestamp (0 if none).
    pub last_sampled_at: i64,
    /// Node this hosting lives on — surfaces in the table so an
    /// operator can tell "which worker is the flaky site on".
    /// Empty = master / local.
    pub node_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeUpdateStatus {
    /// Unix seconds when the job started. 0 → no job has ever run.
    pub started_at: i64,
    /// Unix seconds when the job finished. 0 → still running, or
    /// no job has ever run.
    pub finished_at: i64,
    /// "idle" | "running" | "succeeded" | "failed".
    pub state: String,
    /// Whether the apt step was requested for this job.
    pub do_apt: bool,
    /// Whether the hyperion update.sh step was requested.
    pub do_hyperion: bool,
    /// Combined stdout/stderr tail of the running script, capped
    /// to roughly the last 8 kB. Live during the run, frozen
    /// after completion.
    pub log_tail: String,
    /// Exit code of the script (0 = ok). Meaningful only when
    /// state ∈ {"succeeded","failed"}.
    pub exit_code: i32,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            current_sha: env!("CARGO_PKG_VERSION").to_string(),
            latest_sha: String::new(),
            latest_tag: "rolling".into(),
            latest_built: String::new(),
            last_checked_at: 0,
            update_available: false,
            message: "never checked".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_wildcard_base_strips_first_label() {
        let mut c = ClusterConfigView::default();
        c.test_domain_template = "{name}.{node}.testovaciverze.cz".into();
        assert_eq!(
            c.node_wildcard_base("s4", "four").as_deref(),
            Some("four.testovaciverze.cz")
        );
    }

    #[test]
    fn node_wildcard_base_refuses_bare_tld_and_unconfigured() {
        // Single-label parent (`*.cz`) is never a safe wildcard.
        let mut c = ClusterConfigView::default();
        c.test_domain_template = "{name}.cz".into();
        assert_eq!(c.node_wildcard_base("s4", "four"), None);
        // No template configured ⇒ no base.
        let empty = ClusterConfigView::default();
        assert_eq!(empty.node_wildcard_base("s4", "four"), None);
    }

    #[test]
    fn node_wildcard_base_uses_hostname_token() {
        let mut c = ClusterConfigView::default();
        c.test_domain_template = "{name}.{node}.lab.example.com".into();
        // {node} resolves to the hostname (label), lower-cased.
        assert_eq!(
            c.node_wildcard_base("node-xyz", "Lab01").as_deref(),
            Some("lab01.lab.example.com")
        );
    }

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
