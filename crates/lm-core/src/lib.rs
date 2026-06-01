//! `lm-core` — the orchestrator. Implements `AgentApi` by sequencing
//! state writes (via `lm-state`) and side effects (via the `AdapterPort`
//! abstraction over `lm-adapters`).
//!
//! Tests inject `MockAdapterPort` (via `mockall`) so orchestration logic
//! is verified without touching the system.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod agent;
pub mod real_adapter;
pub mod secrets;
pub mod service;

pub use agent::AgentImpl;
pub use real_adapter::RealAdapter;
pub use secrets::{SecretsError, SecretsStore};
pub use service::{AdapterPort, HostingPaths, HostingService};
