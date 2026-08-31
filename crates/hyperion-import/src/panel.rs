//! Wire DTOs + adapter/location selection shared by the RPC layer, the core
//! engine, and hctl. Kept here (the leaf crate) so all layers agree on shapes.

use crate::adapter::{Location, SourceAdapter};
use crate::cloudpanel::CloudPanelAdapter;
use crate::ir::IrUnsupported;
use serde::{Deserialize, Serialize};

/// Request for the panel-import RPCs (`hosting_import_panel` + `_plan`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportPanelReq {
    /// `"cloudpanel"` | `"hestiacp"`.
    pub source_kind: String,
    /// `"inplace"` | `"remote"` | `"archive"`.
    pub mode: String,
    /// SSH connection for `remote` mode (source panel on another machine).
    /// Required iff `mode == "remote"`. The private key is ephemeral — the
    /// engine writes it to a 0600 file for the run and deletes it after.
    #[serde(default)]
    pub ssh: Option<SshConn>,
    /// Node-local path to an uploaded export bundle (`bundle.tar`) for
    /// `archive` mode. The engine unpacks it to a temp dir for the run and
    /// removes that temp dir afterwards.
    #[serde(default)]
    pub archive_path: Option<String>,
    /// Per-site overrides chosen in the interactive wizard (keyed by the
    /// SOURCE domain). Empty = import every site as-is (the default). Lets the
    /// operator rename a site, attach a profile, and set a billing date at
    /// import time.
    #[serde(default)]
    pub site_overrides: Vec<SiteImportOverride>,
}

/// One imported site's operator-chosen overrides, applied during the import
/// engine's create step. Matched to a discovered site by `source_domain`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SiteImportOverride {
    /// The domain as the source reported it (the match key).
    pub source_domain: String,
    /// Create the hosting under THIS domain instead of `source_domain`
    /// (WordPress URLs are search-replaced from source→target). `None` = keep.
    #[serde(default)]
    pub target_domain: Option<String>,
    /// Apply this profile (limits + price + billing clock) after create.
    #[serde(default)]
    pub profile_id: Option<i64>,
    /// Override the first-billing timestamp (epoch secs) set by the profile.
    #[serde(default)]
    pub next_billing_at: Option<i64>,
    /// Land the site on THIS PHP version instead of the one derived from what
    /// the source reported. `None` = derive.
    ///
    /// The source's version is frequently one Hyperion does not carry (7.4 and
    /// 8.0 are exactly the versions people migrate away from), so a choice has
    /// to exist somewhere — and the operator is the only one who knows whether
    /// the site's code survives the jump.
    #[serde(default)]
    pub php_version: Option<String>,
}

/// SSH connection to a remote source box. `key` carries the private key
/// material; it is **redacted in Debug** and never persisted.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshConn {
    pub host: String,
    pub user: String,
    pub port: u16,
    /// PEM / OpenSSH private key bytes (ephemeral).
    pub key: String,
}

impl std::fmt::Debug for SshConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConn")
            .field("host", &self.host)
            .field("user", &self.user)
            .field("port", &self.port)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Outcome of an apply run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ImportPanelResult {
    pub created: Vec<ImportedHosting>,
    pub skipped: Vec<SkippedHosting>,
    pub unsupported: Vec<IrUnsupported>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportedHosting {
    pub domain: String,
    pub hosting_id: String,
    pub databases: usize,
    /// Anything the operator has to know about THIS site that the import
    /// decided on its behalf — chiefly a PHP version we do not support being
    /// substituted, which can break the very code being migrated. Silence
    /// here used to mean "fine"; it meant "we threw the version away".
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkippedHosting {
    pub domain: String,
    pub reason: String,
}

/// Pick the source adapter for a kind. `None` for an unknown/unsupported kind.
pub fn adapter_for(source_kind: &str) -> Option<Box<dyn SourceAdapter>> {
    match source_kind {
        "cloudpanel" => Some(Box::new(CloudPanelAdapter)),
        "hestiacp" => Some(Box::new(crate::hestia::HestiaAdapter)),
        _ => None,
    }
}

/// Parse a side-effect-free location mode. Only `inplace` is resolvable here;
/// `remote` needs a key-file written on the node, so the engine builds it.
pub fn location_for(mode: &str) -> Option<Location> {
    match mode {
        "inplace" => Some(Location::InPlace),
        _ => None, // "remote" built by the engine (needs key I/O); "archive" TBD
    }
}
