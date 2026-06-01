//! `AgentImpl` — production glue that implements `AgentApi`.

use crate::service::AdapterPort;
use crate::HostingService;
use async_trait::async_trait;
use lm_rpc::wire::{
    AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector,
};
use lm_rpc::{AgentApi, RpcError};
use lm_types::{CertInfo, CertRenewResult, HostingDetail, HostingSummary};
use lm_validate::Domain;
use std::sync::Arc;

pub struct AgentImpl<A: AdapterPort + 'static> {
    svc: Arc<HostingService<A>>,
    hostname: String,
    version: String,
}

impl<A: AdapterPort + 'static> AgentImpl<A> {
    pub fn new(svc: Arc<HostingService<A>>) -> Self {
        Self {
            svc,
            hostname: hostname_or_unknown(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

fn hostname_or_unknown() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[async_trait]
impl<A: AdapterPort + 'static> AgentApi for AgentImpl<A> {
    async fn agent_info(&self) -> Result<AgentInfo, RpcError> {
        let count = self
            .svc
            .list()
            .await
            .map(|v| v.len() as i64)
            .unwrap_or(0);
        Ok(AgentInfo {
            hostname: self.hostname.clone(),
            version: self.version.clone(),
            schema_version: 1,
            hostings_count: count,
        })
    }

    async fn hosting_create(
        &self,
        req: HostingCreateReq,
    ) -> Result<HostingCreated, RpcError> {
        self.svc.create(req).await
    }

    async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError> {
        self.svc.list().await
    }

    async fn hosting_get(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError> {
        self.svc.get(sel).await
    }

    async fn hosting_delete(
        &self,
        sel: HostingSelector,
        opts: DeleteOpts,
    ) -> Result<(), RpcError> {
        self.svc.delete(sel, opts).await
    }

    async fn cert_issue(&self, _domain: Domain) -> Result<CertInfo, RpcError> {
        // Foundation: explicit cert issue outside hosting_create is not
        // implemented yet — that's planned for sub-project 9 hardening.
        Err(RpcError::Internal)
    }

    async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError> {
        // Likewise — handled by a systemd timer + adapter loop in a later
        // sub-project. Returns an empty list for now.
        Ok(vec![])
    }
}
