//! WordPress install request + status types.
//!
//! `wp-cli` itself lives in `hyperion-adapters::wpcli` — these are the
//! crate-boundary DTOs that travel over the RPC wire and end up in the
//! `wp_installs` state table.

use serde::{Deserialize, Serialize};

use crate::HostingId;

/// Operator-supplied options for `wp core install`.
///
/// All strings are validated at the boundary (`hyperion-validate`) before
/// they ever reach `wp-cli`. Plaintext `admin_password` lives in memory
/// only as long as the request takes to dispatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpInstallRequest {
    /// Canonical site URL (with scheme). E.g. `https://example.com`.
    pub site_url: String,
    /// `wp_options.blogname` — shown in the admin bar.
    pub title: String,
    /// Initial admin username for the WP user table.
    pub admin_user: String,
    pub admin_email: String,
    pub admin_password: String,
    /// Locale code (`cs_CZ`, `en_US`, `sk_SK`, …). Default `en_US`.
    #[serde(default = "default_locale")]
    pub locale: String,
    /// `latest` or a specific version like `6.5.3`.
    #[serde(default = "default_version")]
    pub version: String,
    /// When true, the post-install runs `wp option update blog_public 0`
    /// — flips the WP admin's "Discourage search engines from
    /// indexing this site" toggle on. Set by the web layer for
    /// hostings on test nodes when `cluster.test_wp_no_index` is on.
    #[serde(default)]
    pub no_index: bool,
}

fn default_locale() -> String {
    "en_US".into()
}

fn default_version() -> String {
    "latest".into()
}

/// Current WordPress-install state for a hosting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpInstallStatus {
    pub hosting_id: HostingId,
    pub site_url: String,
    pub wp_version: String,
    pub installed_at: i64,
    pub last_pack_hash: String,
}

/// One row in the WordPress plugin manager UI. Maps 1:1 to a
/// `wp plugin list --format=json` row from wp-cli — fields filtered
/// to what the operator actually needs and re-serialized to a
/// stable Rust-friendly shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpPlugin {
    /// Plugin folder slug — the `wp plugin <action> <slug>` argument.
    pub slug: String,
    /// Human-readable name from the plugin's main PHP file header.
    pub name: String,
    /// Installed version.
    pub version: String,
    /// "active" | "inactive" | "must-use" | "dropin" | "active-network"
    pub status: String,
    /// `true` if wp-cli reports a newer version is available.
    pub update_available: bool,
    /// Latest known upstream version, when `update_available == true`.
    /// Empty otherwise.
    pub latest_version: String,
    /// Whether `auto_update` is enabled at the WordPress level for
    /// this plugin (independent of Hyperion's bulk `auto_update_plugins`
    /// flag on the install).
    pub auto_update: bool,
    /// Set by the master when the keyless defender has PAUSED auto-updates
    /// for this plugin: a minor/patch update kept failing, almost always
    /// because the plugin is commercial and the package download needs a
    /// license key. The plugin is still listed and usable — auto-update just
    /// won't keep retrying (and re-alerting) until the pause lapses or an
    /// operator clicks Resume. Defaults `false`; the agent doesn't know about
    /// the skip-list, so the service layer overlays this in `wp_plugin_list`.
    #[serde(default)]
    pub auto_update_blocked: bool,
    /// One-line reason for the pause (the trimmed wp-cli error), shown next to
    /// the "Auto-update paused" badge. `None` unless `auto_update_blocked`.
    #[serde(default)]
    pub auto_update_block_reason: Option<String>,
}

/// Response payload for `WpPluginList` — the plugin table plus
/// some metadata about the current WordPress install.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpPluginListResponse {
    pub plugins: Vec<WpPlugin>,
    /// WordPress core version on disk.
    pub wp_version: String,
    /// Sum of `update_available == true` rows — surfaced as a badge
    /// in the UI without re-counting client-side.
    pub updates_pending: i64,
    /// `auto_update_plugins` flag from `wp_installs` — the bulk
    /// switch in the Hosting Detail UI.
    pub bulk_auto_update: bool,
    /// Set when the live `wp plugin list` lookup FAILED (wp-cli couldn't
    /// bootstrap WordPress — e.g. a database connection error, a PHP
    /// fatal/notice corrupting the JSON, or a permissions problem). The
    /// web layer puts the reason here instead of silently returning an
    /// empty list, so the panel can show "couldn't list plugins" with the
    /// cause rather than a misleading "no plugins installed". `None` on a
    /// successful lookup (including a genuinely empty install).
    #[serde(default)]
    pub error: Option<String>,
}

/// One outdated installed component (plugin / theme). The "defender" is
/// keyless: it flags components with an available update rather than
/// matching a third-party CVE feed — outdated components are the #1
/// real-world WordPress attack vector, and wp-cli already knows the
/// latest version (it queries WordPress.org).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpVulnFinding {
    pub slug: String,
    pub name: String,
    /// Currently-installed version.
    pub installed_version: String,
    pub title: String,
    /// "high" (major behind) | "medium" (minor) | "low" (patch).
    pub severity: String,
    /// CVE id — empty in keyless mode (kept for wire compatibility).
    pub cve: String,
    /// Version to update TO (the latest available).
    pub patched_version: String,
    /// "plugin" | "theme".
    pub kind: String,
    /// "major" | "minor" | "patch" — how far behind the latest is.
    #[serde(default)]
    pub update_type: String,
    /// True when the latest is a same-major bump, so the defender will
    /// auto-apply it (minor/patch policy). Majors are left to the operator.
    #[serde(default)]
    pub auto_updatable: bool,
}

/// Result of a WordPress update/outdated scan (keyless — via wp-cli's own
/// update status, no external feed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpVulnScanResult {
    pub findings: Vec<WpVulnFinding>,
    /// True when wp-cli couldn't enumerate the install (broken WP, perms) —
    /// the UI shows "couldn't check" rather than a false "all clear".
    #[serde(alias = "feed_unavailable")]
    pub feed_unavailable: bool,
    /// Unused in keyless mode (kept for wire compatibility).
    #[serde(default)]
    pub feed_age_secs: i64,
    /// Plugins + themes actually checked.
    pub checked: i64,
    /// How many components the defender auto-updated on this run (tick only).
    #[serde(default)]
    pub auto_updated: i64,
}

/// One hosting's last stored vuln-scan result, for the cluster-wide
/// vulnerability dashboard. Findings are pre-sorted highest-severity
/// first by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingVulnSummary {
    pub hosting_id: String,
    pub domain: String,
    /// Node the hosting lives on (filled by the web aggregator).
    pub node_id: String,
    /// Unix seconds of the scan. 0 = never scanned.
    pub scanned_at: i64,
    pub findings: Vec<WpVulnFinding>,
}

impl HostingVulnSummary {
    /// Count of findings at the given severity.
    pub fn count_severity(&self, sev: &str) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}

/// Whitelisted plugin actions exposed via the web UI. Anything not
/// in this enum cannot be invoked from a form — the wp-cli surface
/// is large and we'd rather grow it deliberately than expose
/// arbitrary subcommands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WpPluginAction {
    /// `wp plugin install <slug> --activate`. Pulls from wordpress.org
    /// or a public URL if `source` starts with http(s)://.
    Install { source: String },
    /// `wp plugin activate <slug>`.
    Activate,
    /// `wp plugin deactivate <slug>`.
    Deactivate,
    /// `wp plugin update <slug>` (or "all" for every plugin).
    Update,
    /// `wp plugin update --all`.
    UpdateAll,
    /// `wp plugin delete <slug>`. Refused if the plugin is currently
    /// active — the operator must deactivate first (matches wp-cli's
    /// own safety check).
    Delete,
    /// `wp plugin auto-updates enable <slug>` or `disable`.
    SetAutoUpdate { enabled: bool },
    /// Clear the keyless defender's auto-update PAUSE for this plugin, so the
    /// next sweep retries it. NOT a wp-cli action — handled entirely in the
    /// service layer (drops the slug from the per-hosting skip-list). Used by
    /// the "Resume" button after a licensed plugin's key has been added.
    ResumeAutoUpdate,
}

/// Outcome of a `WpPluginAction`. `output_tail` carries the last
/// ~4 KiB of stdout/stderr from wp-cli so the UI can show "what
/// happened" without us trying to fully parse wp-cli's textual
/// output (which changes across versions).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpPluginActionResult {
    /// Best-effort status string. "ok" on success; "failed" when
    /// wp-cli exited non-zero; "noop" when the action was already
    /// in the target state.
    pub state: String,
    pub message: String,
    pub output_tail: String,
}

/// One installed theme — parallel to `WpPlugin` but for `wp theme list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpTheme {
    /// Theme directory slug (the `wp theme <action> <slug>` arg).
    pub slug: String,
    /// Human-readable name from the theme's style.css header.
    pub name: String,
    pub version: String,
    /// "active" | "inactive" | "parent" (when it's the parent of an
    /// active child theme).
    pub status: String,
    pub update_available: bool,
    pub latest_version: String,
}

/// Response for `Request::WpThemeList`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpThemeListResponse {
    pub themes: Vec<WpTheme>,
    /// WordPress core version on disk — same field shape as
    /// WpPluginListResponse so the UI can reuse a header.
    pub wp_version: String,
    pub updates_pending: i64,
    /// Set when the live `wp theme list` lookup FAILED — same semantics as
    /// `WpPluginListResponse::error`. `None` on success.
    #[serde(default)]
    pub error: Option<String>,
}

/// Whitelisted theme actions exposed via the web UI. Mirrors
/// `WpPluginAction` but with theme-specific subset (no
/// auto-update-flag since wp-cli doesn't have a per-theme
/// equivalent — theme auto-updates are managed cluster-wide).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WpThemeAction {
    /// `wp theme install <slug> [--activate]`.
    Install { source: String },
    /// `wp theme activate <slug>` — exactly one theme is active at
    /// any time; activating a new one deactivates the current.
    Activate,
    /// `wp theme update <slug>`.
    Update,
    /// `wp theme update --all`.
    UpdateAll,
    /// `wp theme delete <slug>`. Refuses if the theme is currently
    /// active (matches wp-cli's safety check).
    Delete,
}

/// Outcome of a `WpThemeAction` — same shape as the plugin variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpThemeActionResult {
    pub state: String,
    pub message: String,
    pub output_tail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_defaults_apply_when_optional_fields_absent() {
        let minimal = serde_json::json!({
            "site_url": "https://example.com",
            "title": "x",
            "admin_user": "admin",
            "admin_email": "a@b.cz",
            "admin_password": "secret"
        });
        let r: WpInstallRequest = serde_json::from_value(minimal).expect("parse");
        assert_eq!(r.locale, "en_US");
        assert_eq!(r.version, "latest");
    }

    #[test]
    fn request_round_trips_through_json() {
        let r = WpInstallRequest {
            site_url: "https://example.com".into(),
            title: "Site".into(),
            admin_user: "admin".into(),
            admin_email: "a@b.cz".into(),
            admin_password: "secret".into(),
            locale: "cs_CZ".into(),
            version: "6.5.3".into(),
            no_index: false,
        };
        let s = serde_json::to_string(&r).expect("ser");
        let back: WpInstallRequest = serde_json::from_str(&s).expect("de");
        assert_eq!(r, back);
    }

    #[test]
    fn status_round_trips() {
        let s = WpInstallStatus {
            hosting_id: HostingId("01J".into()),
            site_url: "https://example.com".into(),
            wp_version: "6.5.3".into(),
            installed_at: 1_700_000_000,
            last_pack_hash: "abc".into(),
        };
        let json = serde_json::to_string(&s).expect("ser");
        let back: WpInstallStatus = serde_json::from_str(&json).expect("de");
        assert_eq!(s, back);
    }
}
