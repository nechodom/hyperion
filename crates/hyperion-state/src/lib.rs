//! SQLite-backed state for `hyperion-agent`.
//!
//! The pool is the single source of truth for hostings, users, DBs, and
//! certificates on the node. All public functions are async.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
// sqlx row tuples / multi-column query helpers are intentionally "complex" and
// "many-argument"; aliasing each adds noise without clarity.
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
#![forbid(unsafe_code)]

pub mod audit;
pub mod backup_targets;
pub mod backups;
pub mod bans;
pub mod capabilities;
pub mod certificates;
pub mod databases;
pub mod db;
pub mod email_log;
pub mod hosting_kv;
pub mod hosting_quotas;
pub mod hostings;
pub mod invites;
pub mod jobs;
pub mod limits;
pub mod metrics;
pub mod monitors;
pub mod nodejs;
pub mod nodes;
pub mod notifications;
pub mod oom_events;
pub mod profiles;
pub mod scheduler;
pub mod system_users;
pub mod web_sessions;
pub mod web_users;
pub mod wordpress;
pub mod wp_assets;

pub use db::{open, open_memory, StateError};
