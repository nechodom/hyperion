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
    /// `"inplace"` | `"remote"` (`"archive"` not yet supported).
    pub mode: String,
    /// SSH connection for `remote` mode (source panel on another machine).
    /// Required iff `mode == "remote"`. The private key is ephemeral — the
    /// engine writes it to a 0600 file for the run and deletes it after.
    #[serde(default)]
    pub ssh: Option<SshConn>,
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
