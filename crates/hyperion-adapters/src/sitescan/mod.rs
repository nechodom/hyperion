//! Native site scanner building blocks. Everything here runs as root over
//! tenant-controlled trees, so nothing resolves a path by name below the root.

pub mod rules;
pub mod walk;

pub use walk::{FileMeta, SkipReason, TenantRoot, WalkEvent, WalkOpts, WalkStats};
