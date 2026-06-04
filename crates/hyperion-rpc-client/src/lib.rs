//! RPC client — both Unix socket (local agent) and signed HTTPS
//! (remote agent over the master→node channel).
//!
//! One call per connection.
//! [`call`]: local Unix-socket round trip.
//! [`call_remote`]: HTTPS round trip with a master-signed envelope.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod remote;

use hyperion_rpc::codec::{read_frame, write_frame, Request, Response};
use std::path::Path;
use tokio::net::UnixStream;

pub use remote::{call_remote, RemoteCallOpts, RemoteClientError};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Connect to `socket`, send `req`, read one response, close.
pub async fn call(socket: &Path, req: Request) -> Result<Response, ClientError> {
    let mut stream = UnixStream::connect(socket).await?;
    write_frame(&mut stream, &req).await?;
    let resp: Response = read_frame(&mut stream).await?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_missing_socket() {
        let dir = tempfile::tempdir().expect("dir");
        let p = dir.path().join("nope.sock");
        let err = call(&p, Request::AgentInfo).await.unwrap_err();
        match err {
            ClientError::Io(_) => {}
        }
    }
}
