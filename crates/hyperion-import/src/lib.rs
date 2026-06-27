//! Panel import: read a third-party control panel's state and turn it into a
//! panel-neutral intermediate representation (IR), then a dry-run [`ImportPlan`].
//!
//! Layering (see `docs/panel-import-design.md`):
//! ```text
//!   SourceAdapter (HestiaCp / CloudPanel)  →  ImportIR  →  ImportPlanner → ImportPlan
//! ```
//! The **apply/engine** step (which drives `HostingService::create()` +
//! `backup_restore`) deliberately lives in `hyperion-core`, NOT here — so this
//! crate stays a pure, dependency-light extraction+planning layer with no path
//! back to core (avoids a core ↔ import dependency cycle and keeps it trivially
//! unit-testable).
pub mod adapter;
pub mod cloudpanel;
pub mod error;
pub mod hestia;
pub mod ir;
pub mod panel;
pub mod planner;

pub use adapter::{Location, SourceAdapter, SourceKind, SourcePanelInfo, SshTarget};
pub use cloudpanel::CloudPanelAdapter;
pub use error::ImportError;
pub use hestia::HestiaAdapter;
pub use ir::{
    ImportIR, IrCert, IrDatabase, IrDbEngine, IrHosting, IrSiteKind, IrUnsupported, SourceSummary,
};
pub use panel::{
    adapter_for, location_for, ImportPanelReq, ImportPanelResult, ImportedHosting, SkippedHosting,
    SshConn,
};
pub use planner::{Action, ImportPlan, ImportPlanner, PlannedHosting};
