//! The `SourceAdapter` trait + the source-location modes every adapter accepts.

use crate::error::ImportError;
use crate::ir::ImportIR;
use std::path::PathBuf;

/// Where an adapter reads the source panel from.
#[derive(Debug, Clone)]
pub enum Location {
    /// The source panel is installed on *this* node — read local files / CLIs.
    /// This is the P0 / headline case (Hyperion agent on the old panel box).
    InPlace,
    /// Pull from a remote source box over SSH (P1).
    Remote(SshTarget),
    /// An uploaded export archive already staged on this node (P1).
    Archive(PathBuf),
}

impl Location {
    /// Short label for error messages / logs (never includes the ssh key).
    pub fn mode(&self) -> &'static str {
        match self {
            Location::InPlace => "in-place",
            Location::Remote(_) => "remote",
            Location::Archive(_) => "archive",
        }
    }
}

/// SSH target for `Location::Remote`. The key is an ephemeral 0600 file written
/// for the job and deleted on completion — never persisted to the DB.
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub user: String,
    pub key_path: PathBuf,
    pub port: u16,
}

/// Result of a cheap [`SourceAdapter::detect`] probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePanelInfo {
    pub kind: SourceKind,
    pub version: String,
    /// Whether the source has these subsystems enabled, so `extract` can skip
    /// the ones that are off (and the report can be honest about what's absent).
    pub has_mail: bool,
    pub has_dns: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    HestiaCp,
    CloudPanel,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::HestiaCp => "hestiacp",
            SourceKind::CloudPanel => "cloudpanel",
        }
    }
}

/// A source control panel Hyperion can import from.
#[async_trait::async_trait]
pub trait SourceAdapter: Send + Sync {
    fn kind(&self) -> SourceKind;

    /// Cheap probe: is this panel present at `location`? `None` = not found.
    async fn detect(&self, location: &Location) -> Option<SourcePanelInfo>;

    /// Walk the source and produce the panel-neutral IR. Performs **no writes**
    /// to the target — DB dumps and file copies happen later, during apply.
    async fn extract(&self, location: &Location) -> Result<ImportIR, ImportError>;
}
