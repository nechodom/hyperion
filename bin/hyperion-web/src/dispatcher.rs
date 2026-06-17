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
    /// Specifically when the master couldn't even open a TCP
    /// connection to the worker — curl exit 6/7/28. Distinct from
    /// `Remote` because the recipe to fix it is very different
    /// (agent down / firewall) and the raw curl message would leak
    /// the worker's IP if surfaced verbatim. The `kind` field is
    /// already pre-scrubbed; the `node_id` is the operator-chosen
    /// label so it's safe to display.
    #[error("node {node_id} unreachable: {kind}")]
    NodeUnreachable { node_id: String, kind: String },
    #[error("target node {0} is not enrolled")]
    UnknownNode(String),
    #[error("target node {0} has no public_ip on record — cannot reach")]
    NoEndpoint(String),
    #[error("master remote-RPC signing key not available — start hyperion-agent first")]
    NoSigner,
    #[error("unexpected response from nodes_list")]
    UnexpectedNodesListResponse,
}

/// Translate `RemoteClientError::HttpError { code, stderr }` for
/// well-known curl exit codes into a short, IP-free hint. Returns
/// `Some(kind)` when this *is* a TCP-layer failure (caller should
/// upgrade to `NodeUnreachable`); `None` when it's an
/// application-level error (4xx / 5xx response from the agent).
fn classify_curl_failure(code: Option<i32>) -> Option<&'static str> {
    match code {
        Some(6) => Some("DNS lookup failed for the worker's hostname"),
        Some(7) => Some("TCP connect refused (agent down or firewall blocking 9443)"),
        Some(28) => Some("Timed out waiting for the worker to respond"),
        Some(35) => Some("TLS handshake failed (agent's cert is not valid yet)"),
        Some(56) => Some("Connection reset by the worker mid-handshake"),
        _ => None,
    }
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

/// Per-RPC wall-clock timeout (seconds). The default 30s covers info/list/CRUD,
/// but operations that legitimately run for minutes (backup, restore, export,
/// import, WP install) would otherwise be killed at 30s and *misreported as
/// "node unreachable"* (curl exit 28). Give those a generous ceiling so a slow
/// worker finishes rather than looking dead.
fn timeout_for_request(req: &Request) -> u64 {
    match req {
        // Pull a whole site tree back from disk/S3 — can be very large.
        Request::BackupRestore { .. }
        | Request::BackupRestoreAsNew { .. }
        | Request::HostingImport { .. }
        | Request::HostingImportFromUrl { .. } => 3600,
        // Create the archive / move a bundle / install WordPress.
        Request::BackupNow { .. }
        | Request::BackupFetchChunk { .. }
        | Request::HostingExport { .. }
        | Request::HostingCreate(_)
        | Request::HostingDelete { .. }
        | Request::WpInstall { .. }
        | Request::WpInstallFromAsset { .. } => 600,
        _ => 30,
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
    let opts = RemoteCallOpts {
        timeout_secs: timeout_for_request(&req),
        ..RemoteCallOpts::default()
    };
    match call_remote(&endpoint, signer, node_id, req, opts).await {
        Ok(resp) => Ok(resp),
        Err(RemoteClientError::HttpError { code, stderr }) => {
            // Upgrade TCP-layer failures to NodeUnreachable so the
            // operator gets an actionable themed error page and the
            // worker's IP is never surfaced. For non-connect HTTP
            // errors (4xx/5xx from the agent) we fall through to the
            // generic Remote variant — those carry agent-side error
            // bodies which are safe (don't include the worker's IP).
            if let Some(hint) = classify_curl_failure(code) {
                tracing::warn!(
                    node = node_id,
                    curl_exit = ?code,
                    "worker connect failure (translated to NodeUnreachable)"
                );
                Err(DispatchError::NodeUnreachable {
                    node_id: node_id.to_string(),
                    kind: hint.to_string(),
                })
            } else {
                Err(DispatchError::Remote(RemoteClientError::HttpError {
                    code,
                    stderr,
                }))
            }
        }
        Err(e) => Err(DispatchError::Remote(e)),
    }
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
    Ok(format!("https://{host_part}:{}", DEFAULT_AGENT_RPC_PORT))
}

impl From<DispatchError> for crate::error::AppError {
    fn from(e: DispatchError) -> Self {
        use crate::error::AppError;
        match e {
            DispatchError::Local(ClientError::Io(io)) => AppError::Rpc(io.to_string()),
            DispatchError::Remote(re) => AppError::Rpc(re.to_string()),
            DispatchError::NodeUnreachable { node_id, kind } => AppError::NodeUnreachable {
                node_id,
                hint: kind,
            },
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
