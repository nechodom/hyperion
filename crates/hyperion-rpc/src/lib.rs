//! Transport-agnostic RPC layer: typed trait, wire types, JSON frame codec.
//!
//! The same `AgentApi` trait is served by `hyperion-rpc-server` over a local
//! Unix socket today and (in sub-project 1.5) by `hyperion-rpc-tls` over mTLS.
//! Wire format is `u32be length || JSON body`, max body 4 MiB.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod api;
pub mod codec;
pub mod error;
pub mod wire;

pub use api::AgentApi;
pub use codec::{read_frame, write_frame, AuditEntryWire, Request, Response, MAX_FRAME};
pub use error::RpcError;
pub use wire::{
    AgentInfo, DbCredentials, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
};
