//! Native site scanner building blocks. Everything here runs as root over
//! tenant-controlled trees, so nothing resolves a path by name below the root.

pub mod walk;

pub use walk::{open_file_at, walk, FileMeta, SkipReason, WalkEvent, WalkOpts, WalkStats};
