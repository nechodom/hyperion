//! Transport-agnostic RPC layer: typed trait, wire types, JSON frame codec.
//!
//! The same `AgentApi` trait is served by `lm-rpc-server` over a local
//! Unix socket today and (in sub-project 1.5) by `lm-rpc-tls` over mTLS.
//! Wire format is `u32be length || JSON body`, max body 4 MiB.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

pub mod api;
pub mod codec;
pub mod error;
pub mod wire;

pub use api::AgentApi;
pub use codec::{read_frame, write_frame, Request, Response, MAX_FRAME};
pub use error::RpcError;
pub use wire::{
    AgentInfo, DbCredentials, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
};
