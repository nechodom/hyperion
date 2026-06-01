//! SQLite-backed state for `lm-agent`.
//!
//! The pool is the single source of truth for hostings, users, DBs, and
//! certificates on the node. All public functions are async.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod audit;
pub mod backups;
pub mod certificates;
pub mod databases;
pub mod db;
pub mod hostings;
pub mod limits;
pub mod scheduler;
pub mod system_users;

pub use db::{open, open_memory, StateError};
