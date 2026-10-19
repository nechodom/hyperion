//! Hosting migration between nodes.
//!
//! The migration model is **export-bundle** based: the source node
//! produces a self-contained `.tar.gz` archive plus a JSON manifest
//! capturing everything needed to recreate the hosting on a different
//! node (domain config, PHP version, DB engine, secrets reference,
//! source hosting id, cluster-fold info). The operator transfers the
//! bundle out-of-band (scp, rsync, S3, USB drive — whichever path
//! their security model allows), then runs `hctl hosting import
//! --bundle <file>` on the target node, which provisions an identical
//! hosting and restores the archive.
//!
//! This shape keeps the master agent's blast radius small: the master
//! doesn't need an outbound RPC channel to every node (which would be
//! a new architecture), and operators retain control of where the
//! tenant data flows across the network. A future iteration can add
//! a master-orchestrated push for the "happy path".

use serde::{Deserialize, Serialize};

use crate::HostingId;

/// Bundle produced by `HostingExport`. The `archive_path` and
/// `manifest_path` are both on the source node's local disk under
/// `/var/lib/hyperion/migration/<bundle_id>/`. The UI surfaces them
/// alongside a scp one-liner the operator can paste.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingMigrationBundle {
    pub bundle_id: String,
    /// Tar+gz of the htdocs tree + DB dump. Same format as `backup_now`.
    pub archive_path: String,
    /// JSON manifest next to the archive — see `HostingMigrationManifest`.
    pub manifest_path: String,
    /// SHA-256 of the archive bytes. Operator can verify the transfer
    /// landed clean before invoking the importer.
    pub archive_sha256: String,
    /// Bytes of the archive.
    pub archive_bytes: i64,
    pub created_at: i64,
    /// Original hosting on the source node — included for traceability
    /// (every migration event ties back to the same id even if the
    /// target node assigns a fresh id).
    pub source_hosting_id: HostingId,
    /// Stable node identifier of the source — read from the master's
    /// `nodes` table or, on a single-agent setup, the hostname.
    pub source_node_id: String,
    /// Hyperion git SHA of the source node at export time. The
    /// importer warns the operator when it differs from its own SHA
    /// since the schema may have drifted.
    pub source_hyperion_version: String,
    /// Public download base URL for the bundle on the source node's
    /// hyperion-web. The target node fetches `<base>/manifest.json`
    /// and `<base>/archive.tar.gz` with the `?t=<bundle_token>`
    /// query parameter appended. Empty when the source didn't
    /// derive a public URL (single-node dev setups).
    ///
    /// Set by the handler that calls `hosting_export` — the service
    /// layer doesn't know the master's externally-reachable URL.
    #[serde(default)]
    pub download_base_url: String,
    /// Signed token covering `(bundle_id, expires_at)`. The target
    /// appends it as `?t=<token>` to both download URLs.
    #[serde(default)]
    pub bundle_token: String,
    /// Unix seconds when `bundle_token` stops verifying. Surface to
    /// the operator so they know the deadline.
    #[serde(default)]
    pub token_expires_at: i64,
}

/// Declarative description of what to recreate on the target node.
/// Written as `manifest.json` next to the archive at export time;
/// read by the importer at import time.
///
/// Anything that's *intrinsic* to the hosting belongs here. Anything
/// that's a function of node state (Linux UID, FPM pool path, on-disk
/// vhost path) is recomputed by the importer because the target node
/// is free to choose different numbers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingMigrationManifest {
    pub schema_version: u32,
    pub source_hosting_id: HostingId,
    pub source_node_id: String,
    pub source_hyperion_version: String,
    pub exported_at: i64,
    /// Canonical primary domain.
    pub domain: String,
    /// Additional SAN aliases (www, etc.).
    pub aliases: Vec<String>,
    /// "php" | "static" | "reverse_proxy".
    pub kind: String,
    pub php_version: Option<crate::PhpVersion>,
    /// "mariadb" | "postgres" | None if no DB was provisioned.
    pub db_engine: Option<String>,
    /// Whether this hosting has a real LE cert or self-signed at
    /// export time. The importer re-issues from scratch — it never
    /// transports private keys across the network.
    pub had_real_cert: bool,
    /// Optional WP install metadata. Skipped when the hosting isn't
    /// a WP install.
    pub wp_version: Option<String>,
    /// Cron tab body (best-effort — empty if the source operator
    /// hadn't customised cron).
    pub crontab: String,
    /// Sha256 of the archive next to this manifest. The importer
    /// recomputes and refuses on mismatch (protection against
    /// in-transit corruption / truncated scp).
    pub archive_sha256: String,
    /// Upstream URL for `kind == "reverse_proxy"` hostings.
    /// `None` for other kinds. Previously missing — every
    /// reverse-proxy migration silently lost its upstream.
    #[serde(default)]
    pub proxy_upstream_url: Option<String>,
    /// Sha256 of `archive.sql`, the database dump shipped next to the
    /// archive. `None` = no dump in this bundle. Bundles from before this
    /// field never carried the dump at all, so a site with a database moved
    /// with them arrived with an EMPTY database while the job said "ok";
    /// the importer now refuses a DB site whose bundle has no dump.
    #[serde(default)]
    pub db_dump_sha256: Option<String>,
    /// The domain the bundle was exported under, set when a Copy rewrites
    /// `domain` to the new name. The importer rewrites the WordPress URLs
    /// from this to `domain`.
    #[serde(default)]
    pub renamed_from: Option<String>,
    /// The source site's tree (`<home>/<domain>`, the parent of htdocs) and
    /// its account's home. The importer rewrites crontab lines naming them
    /// to the new site's place. Empty in older bundles: cron then travels
    /// unchanged, as it always did.
    #[serde(default)]
    pub source_tree: String,
    #[serde(default)]
    pub source_home: String,
    /// Everything about the site beyond what `create` takes: limits, quota,
    /// vhost options, schedules, plans. `None` = a bundle from before these
    /// travelled; the importer says so in its report instead of implying it
    /// carried them.
    #[serde(default)]
    pub settings: Option<HostingCarriedSettings>,
}

/// Per-site settings captured at export and re-applied by the importer.
///
/// What travels, and on which operation, is decided field by field (see the
/// importer's `apply_carried_settings`): a Move carries everything below; a
/// Copy is a NEW site, so it takes the technical settings but not what the
/// customer pays for or is promised (billing, care plans, expiry, uptime
/// alerts). Secrets never travel — the target makes its own (see
/// `not_carried`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingCarriedSettings {
    /// PHP-FPM and resource limits (`hosting_limits`).
    #[serde(default)]
    pub limits: Option<crate::HostingLimits>,
    /// Disk/memory/bandwidth caps and the overage action.
    #[serde(default)]
    pub quota: Option<crate::HostingQuotaView>,
    /// nginx-side options: HTTPS/HSTS, redirects, cache, WAF level and
    /// pins, OWASP CRS, noindex, blocked bots/countries, raw snippet, …
    #[serde(default)]
    pub vhost_options: Option<crate::VhostOptions>,
    /// bcrypt hash of the HTTP basic-auth password, so a protected site
    /// stays protected with the password its visitors already have. A hash,
    /// not the password: the bundle already holds every WordPress password
    /// hash in its database dump.
    #[serde(default)]
    pub basic_auth_hash: Option<String>,
    #[serde(default)]
    pub wp_debug: Option<CarriedWpDebug>,
    /// The source had the Redis object cache on. The target provisions its
    /// own ACL user, database number and password.
    #[serde(default)]
    pub redis_enabled: bool,
    /// Allow-listed `hosting_kv` configuration (backup schedule, PHP memory
    /// automation, WordPress update policy, protection switches, …). State
    /// (last-run stamps, log positions, scan results) and secrets never get
    /// in here — see the exporter's allow-list.
    #[serde(default)]
    pub kv: std::collections::BTreeMap<String, String>,
    /// Key-only SFTP was on, and the public keys from the account's
    /// `authorized_keys`. Public keys are not secrets; the person who could
    /// reach the site still can.
    #[serde(default)]
    pub sftp_enabled: bool,
    #[serde(default)]
    pub sftp_keys: Vec<String>,
    /// Extra FTP logins (name part + the directory they are confined to).
    /// Recreated with a fresh random password nobody knows: the operator
    /// resets each one to hand it out. Passwords never travel.
    #[serde(default)]
    pub ftp_logins: Vec<CarriedFtpLogin>,
    /// Renewal date, owner address, grace period. Move only.
    #[serde(default)]
    pub expiry: Option<crate::HostingExpiry>,
    /// Uptime monitor settings. Move only — a copy must not page anyone.
    #[serde(default)]
    pub monitor: Option<CarriedMonitor>,
    /// Profile link and price with its billing clock. Move only — a copy
    /// billed like its original would charge the customer twice.
    #[serde(default)]
    pub billing: Option<CarriedBilling>,
    /// Care plans the site holds (active, including ones waiting for their
    /// start date). Move only.
    #[serde(default)]
    pub care_plans: Vec<CarriedCarePlan>,
    /// Things the source has that deliberately do not travel, one line
    /// each, for the job log ("DKIM: … enable it again …").
    #[serde(default)]
    pub not_carried: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CarriedWpDebug {
    pub enabled: bool,
    pub log: bool,
    pub display: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CarriedFtpLogin {
    /// The operator-chosen part before `.<domain>`.
    pub name: String,
    /// Landing directory relative to the document root.
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CarriedMonitor {
    pub enabled: bool,
    pub url_path: String,
    pub interval_secs: i64,
    pub alert_after_fails: i64,
    #[serde(default)]
    pub alert_email: Option<String>,
    #[serde(default)]
    pub alert_slack_webhook: Option<String>,
    #[serde(default)]
    pub alert_webhook_url: Option<String>,
}

/// The site's `hosting_profile_apply` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CarriedBilling {
    #[serde(default)]
    pub profile_id: Option<i64>,
    #[serde(default)]
    pub price_minor: Option<i64>,
    #[serde(default)]
    pub price_currency: Option<String>,
    #[serde(default)]
    pub price_interval: Option<String>,
    #[serde(default)]
    pub next_billing_at: Option<i64>,
    #[serde(default)]
    pub slack_webhook: Option<String>,
    #[serde(default)]
    pub alert_emails: Option<String>,
    #[serde(default)]
    pub applied_at: i64,
    #[serde(default)]
    pub price_pinned: bool,
}

/// One care-plan activation, with its snapshots. Self-contained by design
/// (the owning node has no plan definitions), so it moves as-is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CarriedCarePlan {
    #[serde(default)]
    pub package_id: Option<i64>,
    pub package_name: String,
    #[serde(default)]
    pub price_minor: Option<i64>,
    #[serde(default)]
    pub price_currency: Option<String>,
    #[serde(default)]
    pub price_interval: Option<String>,
    pub features: crate::package::PackageFeatures,
    #[serde(default)]
    pub next_billing_at: Option<i64>,
    #[serde(default)]
    pub activated_at: i64,
    /// What the forced features were before the plan — a cancel on the
    /// target restores exactly what a cancel on the source would have.
    #[serde(default)]
    pub prior_state_json: Option<String>,
    #[serde(default)]
    pub letters_lang: String,
    #[serde(default)]
    pub check_items: String,
    #[serde(default)]
    pub report_omit: String,
    #[serde(default)]
    pub valid_from: Option<i64>,
    #[serde(default)]
    pub enforcement_started: bool,
}

impl HostingMigrationManifest {
    /// File name of the database dump inside a bundle directory. Named so
    /// `backup_restore` finds it as the sibling of `archive.tar.gz`.
    pub const DB_DUMP_FILE: &'static str = "archive.sql";

    /// Current schema version. Bump on every breaking field change;
    /// the importer refuses bundles with unknown future versions.
    pub const CURRENT_SCHEMA_VERSION: u32 = 1;
}

/// Outcome of `HostingImport`. Successful imports return the new
/// hosting id (which differs from `source_hosting_id` because every
/// node mints fresh ULIDs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingImportResult {
    pub new_hosting_id: HostingId,
    pub domain: String,
    /// `restored_bytes` is the archive size — surfaced so the operator
    /// can compare against the source-side bundle size as a sanity
    /// check.
    pub restored_bytes: i64,
    pub state: String,
    pub message: String,
    /// One line per setting the importer re-applied, could not apply, or
    /// deliberately left behind — the Move/Copy job prints it, so "the site
    /// moved" never silently means "the site moved without its limits".
    #[serde(default)]
    pub carry_report: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrips_json() {
        let m = HostingMigrationManifest {
            schema_version: HostingMigrationManifest::CURRENT_SCHEMA_VERSION,
            source_hosting_id: HostingId("01J".into()),
            source_node_id: "node-a".into(),
            source_hyperion_version: "abc1234".into(),
            exported_at: 1_700_000_000,
            domain: "example.cz".into(),
            aliases: vec!["www.example.cz".into()],
            kind: "php".into(),
            php_version: Some(crate::PhpVersion::V8_3),
            db_engine: Some("mariadb".into()),
            had_real_cert: true,
            wp_version: Some("6.5.3".into()),
            crontab: "* * * * * echo hi\n".into(),
            archive_sha256: "deadbeef".into(),
            proxy_upstream_url: None,
            db_dump_sha256: Some("cafe".into()),
            renamed_from: None,
            source_tree: "/home/example_cz/example.cz".into(),
            source_home: "/home/example_cz".into(),
            settings: Some(HostingCarriedSettings {
                limits: Some(crate::HostingLimits::defaults()),
                redis_enabled: true,
                kv: [("backup_at".to_string(), "03:30".to_string())].into(),
                care_plans: vec![CarriedCarePlan {
                    package_name: "Care".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let json = serde_json::to_string(&m).expect("ser");
        let back: HostingMigrationManifest = serde_json::from_str(&json).expect("de");
        assert_eq!(m, back);
    }

    /// A manifest written before the dump existed still parses: no dump,
    /// no rename.
    #[test]
    fn old_manifest_without_dump_fields_parses() {
        let mut v = serde_json::to_value(HostingMigrationManifest {
            schema_version: 1,
            source_hosting_id: HostingId("01J".into()),
            source_node_id: "n".into(),
            source_hyperion_version: "x".into(),
            exported_at: 0,
            domain: "example.cz".into(),
            aliases: vec![],
            kind: "php".into(),
            php_version: None,
            db_engine: Some("mariadb".into()),
            had_real_cert: false,
            wp_version: None,
            crontab: String::new(),
            archive_sha256: "x".into(),
            proxy_upstream_url: None,
            db_dump_sha256: None,
            renamed_from: None,
            source_tree: String::new(),
            source_home: String::new(),
            settings: None,
        })
        .expect("to value");
        let obj = v.as_object_mut().expect("object");
        for k in [
            "db_dump_sha256",
            "renamed_from",
            "source_tree",
            "source_home",
            "settings",
        ] {
            obj.remove(k);
        }
        let back: HostingMigrationManifest = serde_json::from_value(v).expect("old shape parses");
        assert_eq!(back.db_dump_sha256, None);
        assert_eq!(back.renamed_from, None);
        assert_eq!(
            back.settings, None,
            "an old bundle is told apart from an empty one"
        );
    }

    #[test]
    fn bundle_roundtrips_json() {
        let b = HostingMigrationBundle {
            bundle_id: "mig_abc".into(),
            archive_path: "/var/lib/hyperion/migration/mig_abc/archive.tar.gz".into(),
            manifest_path: "/var/lib/hyperion/migration/mig_abc/manifest.json".into(),
            archive_sha256: "deadbeef".into(),
            archive_bytes: 12_345_678,
            created_at: 1_700_000_000,
            source_hosting_id: HostingId("01J".into()),
            source_node_id: "node-a".into(),
            source_hyperion_version: "abc1234".into(),
            download_base_url: String::new(),
            bundle_token: String::new(),
            token_expires_at: 0,
        };
        let json = serde_json::to_string(&b).expect("ser");
        let back: HostingMigrationBundle = serde_json::from_str(&json).expect("de");
        assert_eq!(b, back);
    }
}
