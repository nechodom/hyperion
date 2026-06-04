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
}

impl HostingMigrationManifest {
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
        };
        let json = serde_json::to_string(&m).expect("ser");
        let back: HostingMigrationManifest = serde_json::from_str(&json).expect("de");
        assert_eq!(m, back);
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
