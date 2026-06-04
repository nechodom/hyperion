//! Local-or-remote RPC dispatcher for handlers.
//!
//! Handlers used to do `hyperion_rpc_client::call(&state.agent_socket,
//! request)` and were therefore hard-wired to the master node. With
//! the master→node remote-RPC channel in place, the dispatcher
//! decides per call: when the operator targets a remote node, sign
//! the envelope with the master's Ed25519 key and POST to the
//! node's inbound listener; otherwise fall through to the Unix
//! socket as before.

use crate::state::SharedState;
use hyperion_rpc::codec::{Request, Response};
use hyperion_rpc_client::{call, call_remote, ClientError, RemoteCallOpts, RemoteClientError};

/// Default port the agent's inbound listener binds. Mirrors
/// `RemoteRpcSection::default().bind`. When a per-node endpoint
/// becomes configurable (Batch 11+ work) this constant will be
/// replaced by a lookup against the `nodes` table.
const DEFAULT_AGENT_RPC_PORT: u16 = 9443;

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("local rpc: {0}")]
    Local(#[from] ClientError),
    #[error("remote rpc: {0}")]
    Remote(#[from] RemoteClientError),
    #[error("target node {0} is not enrolled")]
    UnknownNode(String),
    #[error("target node {0} has no public_ip on record — cannot reach")]
    NoEndpoint(String),
    #[error("master remote-RPC signing key not available — start hyperion-agent first")]
    NoSigner,
    #[error("unexpected response from nodes_list")]
    UnexpectedNodesListResponse,
}

/// Sentinel value used in form fields when the operator wants the
/// master itself. Empty string also resolves to local — both are
/// accepted at the form layer.
pub const LOCAL_NODE_SENTINEL: &str = "local";

/// Dispatch `req` to either the local agent (Unix socket) or a
/// remote enrolled agent (signed HTTPS). The chosen path is
/// determined by `target_node_id`:
///
/// - `None` / empty / `"local"` → local socket (master itself).
/// - anything else → look up `target_node_id` in the master's
///   `nodes` table, derive `https://<public_ip>:9443`, sign +
///   POST. Returns `UnknownNode` / `NoEndpoint` when the lookup
///   fails so the handler can surface a clean error to the
///   operator instead of a confusing curl exit code.
pub async fn dispatch_to_node(
    state: &SharedState,
    target_node_id: Option<&str>,
    req: Request,
) -> Result<Response, DispatchError> {
    let target = target_node_id
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != LOCAL_NODE_SENTINEL);
    // Every dispatch leaves a journalctl breadcrumb so operators
    // can debug "I selected stav but it ended up on master" by
    // checking the master's logs:
    //   journalctl -u hyperion-web -g 'dispatch' --since '1 hour ago'
    // Verbosity is intentionally INFO (not debug) — these are rare
    // operator actions, not hot-path requests.
    let req_kind = request_kind_label(&req);
    match target {
        None => {
            tracing::info!(
                target = "master (local socket)",
                request = req_kind,
                "dispatch"
            );
            Ok(call(&state.agent_socket, req).await?)
        }
        Some(node_id) => {
            tracing::info!(
                target = node_id,
                request = req_kind,
                "dispatch (remote signed RPC)"
            );
            dispatch_remote(state, node_id, req).await
        }
    }
}

/// Short string tag for the Request variant — purely for logs/audit
/// (so journalctl shows "HostingCreate" instead of the full
/// pretty-printed enum which is multi-line for nested payloads).
fn request_kind_label(req: &Request) -> &'static str {
    match req {
        Request::AgentInfo => "AgentInfo",
        Request::HostingCreate(_) => "HostingCreate",
        Request::HostingList => "HostingList",
        Request::HostingGet(_) => "HostingGet",
        Request::HostingDelete { .. } => "HostingDelete",
        Request::HostingSuspend { .. } => "HostingSuspend",
        Request::HostingResume(_) => "HostingResume",
        Request::HostingSetLimits { .. } => "HostingSetLimits",
        Request::HostingGetLimits(_) => "HostingGetLimits",
        Request::ServicesHealth => "ServicesHealth",
        Request::ServiceRestart { .. } => "ServiceRestart",
        Request::ServiceInstall { .. } => "ServiceInstall",
        Request::ClusterStats => "ClusterStats",
        Request::NodeMetricsHistory { .. } => "NodeMetricsHistory",
        Request::NodesList => "NodesList",
        Request::WpInstall { .. } => "WpInstall",
        _ => "OtherRpc",
    }
}

async fn dispatch_remote(
    state: &SharedState,
    node_id: &str,
    req: Request,
) -> Result<Response, DispatchError> {
    let signer = state
        .master_rpc_signer
        .as_ref()
        .ok_or(DispatchError::NoSigner)?;
    let endpoint = resolve_node_endpoint(state, node_id).await?;
    let resp =
        call_remote(&endpoint, signer, node_id, req, RemoteCallOpts::default()).await?;
    Ok(resp)
}

/// Look up the target node's public IP from the master's `nodes`
/// table (via the local agent's `NodesList` RPC) and build the
/// `https://<ip>:9443` base URL.
async fn resolve_node_endpoint(
    state: &SharedState,
    node_id: &str,
) -> Result<String, DispatchError> {
    let list_resp = call(&state.agent_socket, Request::NodesList).await?;
    let nodes = match list_resp {
        Response::NodesList(v) => v,
        _ => return Err(DispatchError::UnexpectedNodesListResponse),
    };
    let node = nodes
        .into_iter()
        .find(|n| n.node_id == node_id)
        .ok_or_else(|| DispatchError::UnknownNode(node_id.to_string()))?;
    let ip = node
        .public_ip
        .filter(|s| !s.is_empty())
        .ok_or_else(|| DispatchError::NoEndpoint(node_id.to_string()))?;
    // Wrap v6 addresses in brackets.
    let host_part = if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip
    };
    Ok(format!(
        "https://{host_part}:{}",
        DEFAULT_AGENT_RPC_PORT
    ))
}

impl From<DispatchError> for crate::error::AppError {
    fn from(e: DispatchError) -> Self {
        use crate::error::AppError;
        match e {
            DispatchError::Local(ClientError::Io(io)) => AppError::Rpc(io.to_string()),
            DispatchError::Remote(re) => AppError::Rpc(re.to_string()),
            DispatchError::UnknownNode(n) => AppError::BadRequest(format!(
                "node {n} is not enrolled — pick a different target"
            )),
            DispatchError::NoEndpoint(n) => AppError::BadRequest(format!(
                "node {n} hasn't reported a public IP yet (heartbeat ack pending?)"
            )),
            DispatchError::NoSigner => AppError::Internal(
                "master remote-RPC key not loaded — restart hyperion-web after \
                 hyperion-agent has generated /etc/hyperion/master-rpc.key"
                    .into(),
            ),
            DispatchError::UnexpectedNodesListResponse => {
                AppError::Internal("agent returned an unexpected NodesList shape".into())
            }
        }
    }
}
