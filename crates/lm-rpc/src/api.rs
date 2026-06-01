//! The single trait every transport speaks to.

use crate::{
    error::RpcError,
    wire::{DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector},
};
use async_trait::async_trait;
use lm_types::{CertInfo, CertRenewResult, HostingDetail, HostingSummary};
use lm_validate::Domain;

use crate::wire::AgentInfo;

#[async_trait]
pub trait AgentApi: Send + Sync + 'static {
    async fn agent_info(&self) -> Result<AgentInfo, RpcError>;

    async fn hosting_create(&self, req: HostingCreateReq) -> Result<HostingCreated, RpcError>;
    async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError>;
    async fn hosting_get(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError>;
    async fn hosting_delete(&self, sel: HostingSelector, opts: DeleteOpts) -> Result<(), RpcError>;

    async fn cert_issue(&self, domain: Domain) -> Result<CertInfo, RpcError>;
    async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError>;
}
