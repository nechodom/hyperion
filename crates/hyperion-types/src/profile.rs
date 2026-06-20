//! Hosting profile DTOs — operator-defined templates.

use serde::{Deserialize, Serialize};

use crate::HostingId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingProfile {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub disk_hard_mb: Option<i64>,
    pub bw_monthly_mb: Option<i64>,
    pub expiry_grace_days: i64,
    pub expiry_warning_offsets: String,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub slack_webhook: Option<String>,
    /// Newline-separated list of WordPress plugins to install when
    /// this profile is applied to a WP-installed hosting. Each line
    /// is either:
    ///   - a wordpress.org slug ("akismet", "yoast-seo")
    ///   - `@asset:<id>` to install from an uploaded ZIP in the WP
    ///     asset library
    ///
    /// Trailing `!` on a line means "also activate after install".
    /// Lines starting with `#` and empty lines are ignored.
    #[serde(default)]
    pub wp_plugins: String,
    /// Same syntax as `wp_plugins`, but for themes.
    #[serde(default)]
    pub wp_themes: String,
    /// Optional pre-fill for the wizard's PHP-version dropdown.
    /// `None` (or empty string from older agents) = wizard keeps
    /// its global default. `Some("8.4")` = wizard auto-selects
    /// PHP 8.4 when this profile is chosen.
    #[serde(default)]
    pub default_php_version: Option<String>,
    /// Optional pre-fill for the wizard's DB engine dropdown.
    /// One of "mariadb" / "postgres" / "none" or None = no
    /// preference. "none" is meaningful — a profile for static
    /// sites explicitly says "don't provision a DB".
    #[serde(default)]
    pub default_db_engine: Option<String>,
    /// Default action when a hosting created from this profile exceeds its disk
    /// hard cap: "notify" (default) or "suspend". Seeds the hosting's
    /// `hosting_kv` at create; overridable per-hosting from the Quota card.
    #[serde(default)]
    pub quota_exceed_action: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl HostingProfile {
    /// Pretty price like "199.00 Kč/měsíc" or "—" when no price.
    pub fn pretty_price(&self) -> String {
        match (
            &self.price_minor,
            &self.price_currency,
            &self.price_interval,
        ) {
            (Some(m), Some(c), Some(iv)) => {
                let major = *m as f64 / 100.0;
                let iv_word = match iv.as_str() {
                    "monthly" => "/měsíc",
                    "quarterly" => "/kvartál",
                    "yearly" => "/rok",
                    other => other,
                };
                format!("{major:.2} {c}{iv_word}")
            }
            _ => "—".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProfileInput {
    pub name: String,
    pub description: String,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub disk_hard_mb: Option<i64>,
    pub bw_monthly_mb: Option<i64>,
    pub expiry_grace_days: i64,
    pub expiry_warning_offsets: String,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub slack_webhook: Option<String>,
    #[serde(default)]
    pub wp_plugins: String,
    #[serde(default)]
    pub wp_themes: String,
    /// See `HostingProfile::default_php_version`.
    #[serde(default)]
    pub default_php_version: Option<String>,
    /// See `HostingProfile::default_db_engine`.
    #[serde(default)]
    pub default_db_engine: Option<String>,
    /// See `HostingProfile::quota_exceed_action` ("notify" | "suspend").
    #[serde(default)]
    pub quota_exceed_action: String,
}

/// One row in the WordPress asset library — operator-uploaded
/// plugin or theme ZIP that profiles can reference via
/// `@asset:<id>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpAssetSummary {
    pub id: i64,
    /// "plugin" | "theme".
    pub kind: String,
    pub original_name: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub uploaded_at: i64,
    pub uploaded_by: String,
    /// How many profiles' wp_plugins / wp_themes lists reference
    /// this asset via `@asset:<id>`. 0 = orphaned, safe to delete.
    /// `#[serde(default)]` so an older agent (pre-this-field) still
    /// deserializes — the value just defaults to 0 in that case.
    #[serde(default)]
    pub profile_refs: i64,
    /// How many successful one-off installs of this asset have
    /// happened (counted from audit_log entries with action =
    /// "wp.install_from_asset"). Doesn't include profile-driven
    /// installs (those have action "profile.apply.wp" which
    /// doesn't break down per-asset).
    #[serde(default)]
    pub install_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileApply {
    pub hosting_id: HostingId,
    pub profile_id: Option<i64>,
    pub price_minor: Option<i64>,
    pub price_currency: Option<String>,
    pub price_interval: Option<String>,
    pub next_billing_at: Option<i64>,
    pub applied_at: i64,
}

impl ProfileApply {
    pub fn pretty_price(&self) -> String {
        match (
            &self.price_minor,
            &self.price_currency,
            &self.price_interval,
        ) {
            (Some(m), Some(c), Some(iv)) => {
                let major = *m as f64 / 100.0;
                let iv_word = match iv.as_str() {
                    "monthly" => "/měsíc",
                    "quarterly" => "/kvartál",
                    "yearly" => "/rok",
                    other => other,
                };
                format!("{major:.2} {c}{iv_word}")
            }
            _ => "—".into(),
        }
    }
}
