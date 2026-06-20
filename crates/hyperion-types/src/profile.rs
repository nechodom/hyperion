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
    /// Soft (warning) disk cap + memory cap in MiB, applied to the enforced
    /// `hosting_quotas` row at apply alongside `disk_hard_mb`. `None` = no cap.
    #[serde(default)]
    pub disk_soft_mb: Option<i64>,
    #[serde(default)]
    pub mem_limit_mib: Option<i64>,
    /// How many hostings are currently on this profile (rows in
    /// `hosting_profile_apply`). Computed at list/get time — drives the
    /// "in use: N" badge, the "re-apply to N sites" action, and the
    /// delete-confirm warning. `#[serde(default)]` so older agents that don't
    /// send it deserialize with 0.
    #[serde(default)]
    pub in_use_count: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl HostingProfile {
    /// Number of effective plugin lines (ignores blanks + `#` comments) — drives
    /// the "N plugins" badge on the profiles list.
    pub fn plugin_count(&self) -> usize {
        count_items(&self.wp_plugins)
    }

    /// Number of effective theme lines (same rules as `plugin_count`).
    pub fn theme_count(&self) -> usize {
        count_items(&self.wp_themes)
    }

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

/// Count non-blank, non-comment lines in a wp_plugins / wp_themes list (the
/// same lines profile_apply actually installs).
fn count_items(list: &str) -> usize {
    list.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .count()
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
    /// See `HostingProfile::disk_soft_mb` / `mem_limit_mib`.
    #[serde(default)]
    pub disk_soft_mb: Option<i64>,
    #[serde(default)]
    pub mem_limit_mib: Option<i64>,
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
