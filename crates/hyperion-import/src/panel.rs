//! Wire DTOs + adapter/location selection shared by the RPC layer, the core
//! engine, and hctl. Kept here (the leaf crate) so all layers agree on shapes.

use crate::adapter::{Location, SourceAdapter};
use crate::cloudpanel::CloudPanelAdapter;
use crate::ir::IrUnsupported;
use serde::{Deserialize, Serialize};

/// Request for the panel-import RPCs (`hosting_import_panel` + `_plan`).
/// No secret fields — in-place reads local files; remote (P1) passes an
/// on-node key path, never the key bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportPanelReq {
    /// `"cloudpanel"` | `"hestiacp"`.
    pub source_kind: String,
    /// `"inplace"` (P0) | `"remote"` | `"archive"`.
    pub mode: String,
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

/// Parse the location mode. P0 supports in-place only.
pub fn location_for(mode: &str) -> Option<Location> {
    match mode {
        "inplace" => Some(Location::InPlace),
        _ => None, // "remote" / "archive" → P1
    }
}
