//! Hosting DTOs.

use crate::{cert::CertInfo, db::DbSummary, ids::HostingId, php::PhpVersion};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HostingState {
    Provisioning,
    Active,
    Suspended,
    Failed,
    Deleting,
}

impl HostingState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Failed => "failed",
            Self::Deleting => "deleting",
        }
    }
}

impl fmt::Display for HostingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HostingState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "failed" => Ok(Self::Failed),
            "deleting" => Ok(Self::Deleting),
            other => Err(format!("unknown state: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingSummary {
    pub id: HostingId,
    pub domain: String,
    pub state: HostingState,
    pub php_version: Option<PhpVersion>,
    pub created_at: i64,
    /// Stable identifier of the node this hosting lives on. Surfaced
    /// as a chip on the hosting list. `None` for rows that pre-date
    /// migration 016 and haven't been backfilled yet.
    #[serde(default)]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingDetail {
    pub id: HostingId,
    pub domain: String,
    pub aliases: Vec<String>,
    pub state: HostingState,
    pub system_user: String,
    pub php_version: Option<PhpVersion>,
    pub root_dir: String,
    pub database: Option<DbSummary>,
    pub cert: Option<CertInfo>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Per-hosting ACME contact email override. `None` means "use
    /// the agent-wide default from `[acme] contact_email`".
    #[serde(default)]
    pub acme_contact_email: Option<String>,
    /// "php" | "static" | "reverse_proxy". Defaults to "php" for
    /// pre-multi-kind rows.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Upstream URL for kind=reverse_proxy.
    #[serde(default)]
    pub proxy_upstream_url: Option<String>,
    /// Stable identifier of the node this hosting lives on.
    /// `None` for legacy rows (pre-migration 016) that haven't been
    /// backfilled — surfaced as "—" in the UI.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Per-hosting nginx vhost knobs (migration 020). Default
    /// values match the pre-020 behaviour so existing hostings
    /// don't change appearance.
    #[serde(default)]
    pub vhost_options: VhostOptions,
    /// WordPress + Redis app-layer options (migration 021).
    /// Empty/default for non-WP hostings.
    #[serde(default)]
    pub wp_extras: WpExtras,
}

/// Per-hosting nginx vhost configuration the operator flips from
/// the detail page. All fields default to "off" / "" so a hosting
/// that's never touched these renders the same vhost as before.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VhostOptions {
    /// When true, nginx serves the vhost behind HTTP basic auth.
    /// Useful for staging sites / client previews.
    #[serde(default)]
    pub basic_auth_enabled: bool,
    /// Username shown in the browser prompt. Read-only at the wire
    /// level — operator changes via the UI form.
    #[serde(default)]
    pub basic_auth_user: String,
    /// True when a password hash is stored (we never echo the hash
    /// itself over the RPC wire).
    #[serde(default)]
    pub basic_auth_set: bool,

    /// Permanent 301 redirect HTTP → HTTPS in the :80 server
    /// block. The base vhost already does this; this toggle
    /// controls whether it stays on (sane default) or gets
    /// disabled (rare — operator running a Tor / clearnet split).
    #[serde(default)]
    pub force_https: bool,
    /// HSTS max-age in seconds. 0 = HSTS header not emitted.
    /// Common values: 31536000 (1y), 63072000 (2y).
    #[serde(default)]
    pub hsts_max_age: i64,

    /// Free-form nginx snippet appended inside the HTTPS server
    /// block. Validated with `nginx -t` against a sandbox vhost
    /// before save; refused with the verbatim nginx error on
    /// syntax failure.
    #[serde(default)]
    pub custom_nginx_snippet: String,

    /// When true, every request to the HTTPS vhost returns a
    /// generic 503 "we'll be back" page. acme-challenge keeps
    /// working so cert renewals don't break.
    #[serde(default)]
    pub maintenance_mode: bool,

    /// FastCGI page-cache toggle for PHP hostings.
    #[serde(default)]
    pub fastcgi_cache_enabled: bool,
    /// Cache TTL in seconds (5 min default).
    #[serde(default)]
    pub fastcgi_cache_ttl: i64,

    /// Redirect-only kind: when the hosting's kind == "redirect",
    /// every request to the vhost gets a 301/302 to this URL.
    /// No FPM pool, no DB, no htdocs serving.
    #[serde(default)]
    pub redirect_url: String,
    /// 301 (permanent) or 302 (temporary).
    #[serde(default)]
    pub redirect_code: i64,
    /// When true, the request path is appended to the redirect
    /// target (`/foo/bar` → `<target>/foo/bar`). False = flat
    /// `/` for every request.
    #[serde(default)]
    pub redirect_preserve_path: bool,
}

fn default_kind() -> String {
    "php".to_string()
}

/// Redis connection config written into wp-config.php as the
/// `WP_REDIS_*` constants. Generated agent-side from the local
/// Redis listener address + the per-hosting ACL user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WpRedisConfig {
    pub host: String,
    pub port: i64,
    pub database: i64,
    pub username: String,
    pub password: String,
    /// Prefix for all keys this site stores in Redis. Even with a
    /// dedicated DB we use a prefix for grep-ability in `redis-cli`.
    pub key_prefix: String,
}

/// WordPress + Redis app-layer toggles. Applied via wp-cli on the
/// agent side, so only meaningful when there's a WP install in the
/// hosting's htdocs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WpExtras {
    /// Master switch: when true, agent writes WP_DEBUG=true via
    /// `wp config set` and the two related constants below. False
    /// = constants are deleted, not set to false (a false WP_DEBUG
    /// still triggers some plugins' debug code paths).
    #[serde(default)]
    pub wp_debug_enabled: bool,
    /// When debug is on, also enable WP_DEBUG_LOG (writes to
    /// wp-content/debug.log). Recommended; off only for "live debug
    /// to syslog via a custom error handler" setups.
    #[serde(default)]
    pub wp_debug_log: bool,
    /// When debug is on, also enable WP_DEBUG_DISPLAY (prints errors
    /// to the page). DEFAULT OFF — turning this on in production
    /// leaks paths and DB queries to visitors.
    #[serde(default)]
    pub wp_debug_display: bool,
    /// Size of wp-content/debug.log in bytes — sampled by the agent
    /// on the scheduler tick. 0 = file missing.
    #[serde(default)]
    pub wp_debug_log_size_bytes: i64,

    /// Per-hosting Redis object cache toggle. When true, the agent
    /// ensures an ACL user + DB number on the local redis-server and
    /// drops the WP_REDIS_* constants into wp-config.php. The customer
    /// still has to install the "Redis Object Cache" WP plugin and
    /// click "Enable" — we don't side-load plugins.
    #[serde(default)]
    pub redis_enabled: bool,
    /// Assigned Redis DB number (0..15 by default). None = not yet
    /// provisioned. The agent allocates on first enable.
    #[serde(default)]
    pub redis_db_number: Option<i64>,
    /// True when a password is stored in the agent's secrets store.
    /// The plaintext password is NEVER returned over the wire — it's
    /// only written to wp-config.php on the agent side.
    #[serde(default)]
    pub redis_password_set: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbProvision;

    #[test]
    fn state_round_trip() {
        for s in [
            HostingState::Provisioning,
            HostingState::Active,
            HostingState::Suspended,
            HostingState::Failed,
            HostingState::Deleting,
        ] {
            let j = serde_json::to_string(&s).expect("serialize");
            let back: HostingState = serde_json::from_str(&j).expect("deserialize");
            assert_eq!(s, back);
            assert_eq!(HostingState::from_str(s.as_str()).expect("parse"), s);
        }
    }

    #[test]
    fn detail_round_trip() {
        let d = HostingDetail {
            id: HostingId::new_v7(),
            domain: "example.cz".into(),
            aliases: vec!["www.example.cz".into()],
            state: HostingState::Active,
            system_user: "example_cz".into(),
            php_version: Some(PhpVersion::V8_3),
            root_dir: "/home/example_cz/example.cz/htdocs".into(),
            database: Some(DbSummary {
                engine: DbProvision::MariaDB,
                db_name: "lm_a_db".into(),
                db_user: "lm_a_u".into(),
            }),
            cert: None,
            created_at: 1,
            updated_at: 2,
            acme_contact_email: Some("ops@example.cz".into()),
            kind: "php".into(),
            proxy_upstream_url: None,
            node_id: Some("test-node".into()),
            vhost_options: VhostOptions::default(),
            wp_extras: WpExtras::default(),
        };
        let j = serde_json::to_string(&d).expect("serialize");
        let back: HostingDetail = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(d, back);

        // None case also round-trips (serde default).
        let d2 = HostingDetail {
            acme_contact_email: None,
            ..d
        };
        let j2 = serde_json::to_string(&d2).expect("serialize");
        let back2: HostingDetail = serde_json::from_str(&j2).expect("deserialize");
        assert_eq!(d2, back2);
    }

    #[test]
    fn summary_round_trip() {
        let s = HostingSummary {
            id: HostingId::new_v7(),
            domain: "ex.cz".into(),
            state: HostingState::Provisioning,
            php_version: None,
            created_at: 0,
            node_id: Some("n".into()),
        };
        let j = serde_json::to_string(&s).expect("serialize");
        let back: HostingSummary = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(s, back);
    }
}
