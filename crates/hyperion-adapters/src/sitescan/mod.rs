//! Native site scanner building blocks. Everything here runs as root over
//! tenant-controlled trees, so nothing resolves a path by name below the root.

pub mod baseline;
pub mod discover;
pub mod manifest;
pub mod pressure;
pub mod rules;
pub mod runner;
pub mod scan;
pub mod walk;

pub use walk::{FileMeta, SkipReason, TenantRoot, WalkEvent, WalkOpts, WalkStats};
