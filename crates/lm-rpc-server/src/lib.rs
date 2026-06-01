//! Unix-socket RPC server.
//!
//! Listens on a path, dispatches each frame through an `Arc<dyn AgentApi>`.
//! One request/response per connection. The socket is set to mode 0660 on
//! bind; deployment is expected to place it in a group (e.g. `lm-admin`)
//! whose members are authorized callers.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

use lm_rpc::codec::{read_frame, write_frame, Request, Response};
use lm_rpc::AgentApi;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Server {
    listener: UnixListener,
    api: Arc<dyn AgentApi>,
    socket_path: PathBuf,
}

impl Server {
    /// Bind a server. Removes any stale socket file at `path`. Sets
    /// permissions to 0660 (root + admin group access).
    pub async fn bind(path: &Path, api: Arc<dyn AgentApi>) -> Result<Self, ServerError> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(path)?;
        let perms = std::fs::Permissions::from_mode(0o660);
        std::fs::set_permissions(path, perms)?;
        Ok(Self {
            listener,
            api,
            socket_path: path.to_owned(),
        })
    }

    /// Run forever, accepting and handling connections concurrently.
    pub async fn run(self) -> Result<(), ServerError> {
        loop {
            let (stream, _addr) = self.listener.accept().await?;
            let api = self.api.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, api).await {
                    error!(error=%e, "conn handler failed");
                }
            });
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

async fn handle_conn(mut stream: UnixStream, api: Arc<dyn AgentApi>) -> std::io::Result<()> {
    let req: Request = read_frame(&mut stream).await?;
    debug!(?req, "received request");
    let resp = dispatch(api, req).await;
    write_frame(&mut stream, &resp).await?;
    Ok(())
}

async fn dispatch(api: Arc<dyn AgentApi>, req: Request) -> Response {
    match req {
        Request::AgentInfo => match api.agent_info().await {
            Ok(v) => Response::AgentInfo(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingCreate(r) => match api.hosting_create(r).await {
            Ok(v) => Response::HostingCreate(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingList => match api.hosting_list().await {
            Ok(v) => Response::HostingList(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingGet(s) => match api.hosting_get(s).await {
            Ok(v) => Response::HostingGet(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingDelete { sel, opts } => match api.hosting_delete(sel, opts).await {
            Ok(_) => Response::HostingDelete,
            Err(e) => Response::Error(e),
        },
        Request::CertIssue { domain } => match api.cert_issue(domain).await {
            Ok(v) => Response::CertIssue(v),
            Err(e) => Response::Error(e),
        },
        Request::CertRenewAll => match api.cert_renew_all().await {
            Ok(v) => Response::CertRenewAll(v),
            Err(e) => Response::Error(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use lm_rpc::wire::{
        AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
    };
    use lm_rpc::RpcError;
    use lm_types::{CertInfo, CertRenewResult, HostingDetail, HostingSummary};
    use lm_validate::Domain;

    struct EchoApi;

    #[async_trait]
    impl AgentApi for EchoApi {
        async fn agent_info(&self) -> Result<AgentInfo, RpcError> {
            Ok(AgentInfo {
                hostname: "test".into(),
                version: "0".into(),
                schema_version: 1,
                hostings_count: 0,
            })
        }
        async fn hosting_create(
            &self,
            _: HostingCreateReq,
        ) -> Result<HostingCreated, RpcError> {
            Err(RpcError::Internal)
        }
        async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError> {
            Ok(vec![])
        }
        async fn hosting_get(&self, _: HostingSelector) -> Result<HostingDetail, RpcError> {
            Err(RpcError::NotFound {
                kind: "hosting".into(),
                id: "x".into(),
            })
        }
        async fn hosting_delete(
            &self,
            _: HostingSelector,
            _: DeleteOpts,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn cert_issue(&self, _: Domain) -> Result<CertInfo, RpcError> {
            Err(RpcError::Internal)
        }
        async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError> {
            Ok(vec![])
        }
    }

    async fn spawn(api: Arc<dyn AgentApi>) -> (PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("s.sock");
        let srv = Server::bind(&path, api).await.expect("bind");
        tokio::spawn(srv.run());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        (path, dir)
    }

    #[tokio::test]
    async fn agent_info_round_trip() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let resp = lm_rpc_client::call(&path, Request::AgentInfo)
            .await
            .expect("call");
        match resp {
            Response::AgentInfo(info) => assert_eq!(info.hostname, "test"),
            other => panic!("bad resp: {other:?}"),
        }
    }

    #[tokio::test]
    async fn hosting_list_round_trip() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let resp = lm_rpc_client::call(&path, Request::HostingList)
            .await
            .expect("call");
        match resp {
            Response::HostingList(v) => assert!(v.is_empty()),
            other => panic!("bad resp: {other:?}"),
        }
    }

    #[tokio::test]
    async fn error_response_round_trip() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let resp = lm_rpc_client::call(
            &path,
            Request::HostingGet(HostingSelector::Domain(
                Domain::parse("example.cz").expect("parse"),
            )),
        )
        .await
        .expect("call");
        match resp {
            Response::Error(RpcError::NotFound { kind, id }) => {
                assert_eq!(kind, "hosting");
                assert_eq!(id, "x");
            }
            other => panic!("bad resp: {other:?}"),
        }
    }

    #[tokio::test]
    async fn socket_perms_are_0660() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let m = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(m, 0o660);
    }

    #[tokio::test]
    async fn many_concurrent_clients() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let mut tasks = vec![];
        for _ in 0..32 {
            let p = path.clone();
            tasks.push(tokio::spawn(async move {
                lm_rpc_client::call(&p, Request::AgentInfo)
                    .await
                    .expect("call")
            }));
        }
        for t in tasks {
            let resp = t.await.expect("join");
            matches!(resp, Response::AgentInfo(_));
        }
    }
}
