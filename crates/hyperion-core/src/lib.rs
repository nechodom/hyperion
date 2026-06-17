//! `hyperion-core` — the orchestrator. Implements `AgentApi` by sequencing
//! state writes (via `hyperion-state`) and side effects (via the `AdapterPort`
//! abstraction over `hyperion-adapters`).
//!
//! Tests inject `MockAdapterPort` (via `mockall`) so orchestration logic
//! is verified without touching the system.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod agent;
pub mod config_persist;
pub mod master_rpc;
pub mod real_adapter;
pub mod secrets;
pub mod service;
pub mod wp_updates;

pub use agent::AgentImpl;
pub use real_adapter::RealAdapter;
pub use secrets::{SecretsError, SecretsStore};
pub use service::{AdapterPort, BackupRetention, HostingPaths, HostingService, RemoteBackupConfig};
// Re-export the email config struct so the agent binary can construct
// it without depending on hyperion-adapters directly.
pub use hyperion_adapters::email::EmailConfig;

// Re-export the path-traversability self-heal so the agent's main()
// can call it at startup without adding a hyperion-adapters dep.
pub use hyperion_adapters::fs::ensure_ancestors_traversable;

// Same pattern — agent calls this at startup to ensure /run/php/<ver>/
// exists for every supported PHP version. Without it nginx 502s on
// every fresh boot until something triggers ensure_pool.
pub use hyperion_adapters::phpfpm::ensure_socket_dirs as ensure_phpfpm_socket_dirs;

// Re-export postfix smart-host + direct-delivery helpers so the
// agent's main() can configure the MTA at boot from agent.toml's
// [email] settings (PHP mail() flows through the same authenticated
// relay as Hyperion's own outbound when [email].smtp_host is set,
// or via direct MX with hardened defaults when it isn't).
pub use hyperion_adapters::postfix::{
    ensure_direct_delivery_config as postfix_ensure_direct_delivery_config,
    ensure_relay_config as postfix_ensure_relay_config, is_installed as postfix_is_installed,
    rollback_relay_config as postfix_rollback_relay_config,
};

// Re-export profile types via hyperion_types — they live there.
