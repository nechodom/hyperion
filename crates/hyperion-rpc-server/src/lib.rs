//! Unix-socket RPC server.
//!
//! Listens on a path, dispatches each frame through an `Arc<dyn AgentApi>`.
//! One request/response per connection. The socket is set to mode 0660 on
//! bind; deployment is expected to place it in a group (e.g. `hyperion-admin`)
//! whose members are authorized callers.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use hyperion_rpc::codec::{read_frame, write_frame, Request, Response};
use hyperion_rpc::AgentApi;
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
        Request::HostingSetLimits { sel, limits } => {
            match api.hosting_set_limits(sel, limits).await {
                Ok(l) => Response::HostingSetLimits(l),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingGetLimits(sel) => match api.hosting_get_limits(sel).await {
            Ok(l) => Response::HostingGetLimits(l),
            Err(e) => Response::Error(e),
        },
        Request::HostingSuspend { sel, reason } => match api.hosting_suspend(sel, reason).await {
            Ok(_) => Response::HostingSuspend,
            Err(e) => Response::Error(e),
        },
        Request::HostingResume(sel) => match api.hosting_resume(sel).await {
            Ok(_) => Response::HostingResume,
            Err(e) => Response::Error(e),
        },
        Request::HostingUsage { sel, limit } => match api.hosting_usage(sel, limit).await {
            Ok(v) => Response::HostingUsage(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingSetExpiry { sel, expiry } => {
            match api.hosting_set_expiry(sel, expiry).await {
                Ok(v) => Response::HostingSetExpiry(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::HostingGetExpiry(sel) => match api.hosting_get_expiry(sel).await {
            Ok(v) => Response::HostingGetExpiry(v),
            Err(e) => Response::Error(e),
        },
        Request::HostingClearExpiry(sel) => match api.hosting_clear_expiry(sel).await {
            Ok(_) => Response::HostingClearExpiry,
            Err(e) => Response::Error(e),
        },
        Request::UpcomingExpiries { within_seconds } => {
            match api.upcoming_expiries(within_seconds).await {
                Ok(v) => Response::UpcomingExpiries(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::SchedulerTick => match api.scheduler_tick().await {
            Ok(n) => Response::SchedulerTick {
                actions_processed: n,
            },
            Err(e) => Response::Error(e),
        },
        Request::BackupNow { sel } => match api.backup_now(sel).await {
            Ok(v) => Response::BackupNow(v),
            Err(e) => Response::Error(e),
        },
        Request::BackupList { sel, limit } => match api.backup_list(sel, limit).await {
            Ok(v) => Response::BackupList(v),
            Err(e) => Response::Error(e),
        },
        Request::InviteCreate { label, ttl_secs } => {
            match api.invite_create(label, ttl_secs).await {
                Ok(v) => Response::InviteCreate(v),
                Err(e) => Response::Error(e),
            }
        }
        Request::InviteList => match api.invite_list().await {
            Ok(v) => Response::InviteList(v),
            Err(e) => Response::Error(e),
        },
        Request::InviteRevoke { token_hash } => match api.invite_revoke(token_hash).await {
            Ok(_) => Response::InviteRevoke,
            Err(e) => Response::Error(e),
        },
        Request::AuditList { limit } => match api.audit_list(limit).await {
            Ok(v) => Response::AuditList(v),
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
        Request::WpInstall { sel, req } => match api.wp_install(sel, req).await {
            Ok(v) => Response::WpInstall(v),
            Err(e) => Response::Error(e),
        },
        Request::WpStatus { sel } => match api.wp_status(sel).await {
            Ok(v) => Response::WpStatus(v),
            Err(e) => Response::Error(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hyperion_rpc::wire::{
        AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
    };
    use hyperion_rpc::{AuditEntryWire, RpcError};
    use hyperion_types::{
        BackupRunWire, CertInfo, CertRenewResult, ExpiringHosting, HostingDetail, HostingExpiry,
        HostingLimits, HostingSummary, HostingUsageBucket, NodeInviteMint, NodeInviteSummary,
        SuspendReason, WpInstallRequest, WpInstallStatus,
    };
    use hyperion_validate::Domain;

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
        async fn hosting_create(&self, _: HostingCreateReq) -> Result<HostingCreated, RpcError> {
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
        async fn hosting_delete(&self, _: HostingSelector, _: DeleteOpts) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_set_limits(
            &self,
            _: HostingSelector,
            l: HostingLimits,
        ) -> Result<HostingLimits, RpcError> {
            Ok(l)
        }
        async fn hosting_get_limits(&self, _: HostingSelector) -> Result<HostingLimits, RpcError> {
            Ok(HostingLimits::defaults())
        }
        async fn hosting_suspend(
            &self,
            _: HostingSelector,
            _: SuspendReason,
        ) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_resume(&self, _: HostingSelector) -> Result<(), RpcError> {
            Ok(())
        }
        async fn hosting_usage(
            &self,
            _: HostingSelector,
            _: i64,
        ) -> Result<Vec<HostingUsageBucket>, RpcError> {
            Ok(vec![])
        }
        async fn audit_list(&self, _: i64) -> Result<Vec<AuditEntryWire>, RpcError> {
            Ok(vec![])
        }
        async fn hosting_set_expiry(
            &self,
            _: HostingSelector,
            e: HostingExpiry,
        ) -> Result<HostingExpiry, RpcError> {
            Ok(e)
        }
        async fn hosting_get_expiry(&self, _: HostingSelector) -> Result<HostingExpiry, RpcError> {
            Ok(HostingExpiry::defaults())
        }
        async fn hosting_clear_expiry(&self, _: HostingSelector) -> Result<(), RpcError> {
            Ok(())
        }
        async fn upcoming_expiries(&self, _: i64) -> Result<Vec<ExpiringHosting>, RpcError> {
            Ok(vec![])
        }
        async fn scheduler_tick(&self) -> Result<i64, RpcError> {
            Ok(0)
        }
        async fn backup_now(&self, _: HostingSelector) -> Result<BackupRunWire, RpcError> {
            Err(RpcError::Internal)
        }
        async fn backup_list(
            &self,
            _: HostingSelector,
            _: i64,
        ) -> Result<Vec<BackupRunWire>, RpcError> {
            Ok(vec![])
        }
        async fn invite_create(&self, _: String, _: i64) -> Result<NodeInviteMint, RpcError> {
            Err(RpcError::Internal)
        }
        async fn invite_list(&self) -> Result<Vec<NodeInviteSummary>, RpcError> {
            Ok(vec![])
        }
        async fn invite_revoke(&self, _: String) -> Result<(), RpcError> {
            Ok(())
        }
        async fn cert_issue(&self, _: Domain) -> Result<CertInfo, RpcError> {
            Err(RpcError::Internal)
        }
        async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError> {
            Ok(vec![])
        }
        async fn wp_install(
            &self,
            _: HostingSelector,
            _: WpInstallRequest,
        ) -> Result<WpInstallStatus, RpcError> {
            Err(RpcError::Internal)
        }
        async fn wp_status(
            &self,
            _: HostingSelector,
        ) -> Result<Option<WpInstallStatus>, RpcError> {
            Ok(None)
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
        let resp = hyperion_rpc_client::call(&path, Request::AgentInfo)
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
        let resp = hyperion_rpc_client::call(&path, Request::HostingList)
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
        let resp = hyperion_rpc_client::call(
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
        let m = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o660);
    }

    #[tokio::test]
    async fn many_concurrent_clients() {
        let (path, _d) = spawn(Arc::new(EchoApi)).await;
        let mut tasks = vec![];
        for _ in 0..32 {
            let p = path.clone();
            tasks.push(tokio::spawn(async move {
                hyperion_rpc_client::call(&p, Request::AgentInfo)
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
