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
}

/// One known vulnerability affecting an installed plugin/theme,
/// matched against the Wordfence Intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpVulnFinding {
    pub slug: String,
    pub name: String,
    pub installed_version: String,
    pub title: String,
    /// "critical" | "high" | "medium" | "low" | "unknown".
    pub severity: String,
    /// CVE id, or "" when none is assigned.
    pub cve: String,
    /// First patched version, or "" when unknown.
    pub patched_version: String,
    /// "plugin" | "theme".
    pub kind: String,
}

/// Result of a WordPress vulnerability scan against the Wordfence feed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpVulnScanResult {
    pub findings: Vec<WpVulnFinding>,
    /// True when the feed couldn't be fetched/parsed (offline, etc.) —
    /// the UI shows "couldn't check" rather than a false "all clear".
    pub feed_unavailable: bool,
    /// Age of the cached feed in seconds (for a "checked N ago" note).
    pub feed_age_secs: i64,
    /// Plugins/themes actually checked.
    pub checked: i64,
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
