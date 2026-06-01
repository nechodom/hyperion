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
