//! Native site scanner building blocks. Everything here runs as root over
//! tenant-controlled trees, so nothing resolves a path by name below the root.

pub mod accept;
pub mod baseline;
pub mod discover;
pub mod manifest;
pub mod pressure;
pub mod quarantine;
pub mod rules;
pub mod runner;
pub mod scan;
pub mod vendor;
pub mod walk;

pub use scan::own_manifest;
pub use walk::{FileMeta, SkipReason, TenantRoot, WalkEvent, WalkOpts, WalkStats};
