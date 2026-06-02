//! SQLite-backed state for `hyperion-agent`.
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
pub mod invites;
pub mod limits;
pub mod metrics;
pub mod nodejs;
pub mod nodes;
pub mod profiles;
pub mod scheduler;
pub mod system_users;
pub mod wordpress;

pub use db::{open, open_memory, StateError};
