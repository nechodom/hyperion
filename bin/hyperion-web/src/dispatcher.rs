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
use hyperion_core::master_rpc::VerifyOpts;
use hyperion_core::node_rpc::verify_response;
use hyperion_rpc::codec::{Request, Response};
use hyperion_rpc_client::remote::{call_remote_attested, RemoteCallOutcome};
use hyperion_rpc_client::{call, ClientError, RemoteCallOpts, RemoteClientError};

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
    /// The worker answered, but the master could not AUTHENTICATE the
    /// answer: either the Ed25519 response signature didn't verify, or
    /// the node has published a response-signing key and replied
    /// unsigned while enforcement is on. Deliberately NOT folded into
    /// `NodeUnreachable` — "unreachable" reads as downtime and invites a
    /// retry, whereas this is a possible *forged* response (a
    /// substituted password, a faked provisioning success) and has to
    /// read as one. `reason` is a short fixed string from the verifier;
    /// it never carries response content.
    #[error("node {node_id} response failed authentication: {reason}")]
    ResponseAuthFailed { node_id: String, reason: String },
    /// Worker TLS certificate pinning is ENFORCED and the master holds
    /// no pin for this node, so the connection would be made with no
    /// certificate check at all. Same family as `ResponseAuthFailed`
    /// and deliberately not `NodeUnreachable`: nothing is wrong with
    /// the node's reachability, the master simply refuses to open an
    /// unauthenticated channel while the operator has said not to.
    #[error("node {node_id} has no TLS certificate pin on file while pinning is enforced")]
    CertPinMissing { node_id: String },
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
        Some(60) => Some("Worker TLS certificate not trusted"),
        // Block C enforce phase: curl exits 90 when --pinnedpubkey is set
        // and the presented cert's public key doesn't match the pin. This
        // is THE failure mode of enabling enforcement against a worker
        // whose cert has changed — make it actionable instead of a raw
        // "agent rejected" page.
        Some(90) => Some(
            "TLS certificate pin mismatch — the worker's cert no longer matches the SPKI \
             pin it reported. Restart the worker's agent so it re-reports its pin, or turn \
             off Enforce worker TLS certificate pinning in Settings → Cluster.",
        ),
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
/// pretty-printed enum, which is multi-line for nested payloads).
///
/// Derived, not hand-written. This used to be a `match` listing sixteen
/// variants with a `_ => "OtherRpc"` fallback, and the enum has grown a
/// long way past that list — so in practice almost every dispatch logged
/// `OtherRpc` and the logs could not tell you what the panel had asked a
/// node to do. A hand-maintained mirror of an enum silently rots; this
/// cannot.
///
/// `IntoStaticStr` yields the variant NAME only, never its payload, which
/// is what keeps per-node secrets out of the log — the same reason the
/// RPC server logs method names this way instead of `?req`.
fn request_kind_label(req: &Request) -> &'static str {
    <&'static str>::from(req)
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
        | Request::HostingImportFromUrl { .. }
        | Request::HostingImportPanel { .. } => 3600,
        // Creating the archive scales with the SITE, exactly like restoring
        // one — a 12 GB tree is minutes of tar + gzip before the dump even
        // starts. 600s was a coin flip on a large site, and losing it was
        // misreported as "node unreachable".
        Request::BackupNow { .. } => 3600,
        // Move a bundle / install WordPress.
        Request::BackupFetchChunk { .. }
        | Request::HostingExport { .. }
        | Request::HostingCreate(_)
        | Request::HostingDelete { .. }
        | Request::WpInstall { .. }
        | Request::WpInstallFromAsset { .. } => 600,
        // First-time enable apt-installs opendkim + opendkim-tools before it
        // generates the key — well past 30s on a cold apt cache.
        Request::DkimEnable { .. } => 600,
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
    let route = resolve_node_endpoint(state, node_id).await?;
    // Read both enforcement toggles in ONE local RPC, UNCONDITIONALLY.
    // This used to be skipped for a node with neither a reported pin nor
    // a published signing key ("nothing to enforce against, save a round
    // trip") — but "this node has published nothing" is exactly the state
    // an on-path attacker engineers by stripping resp_pubkey from the
    // heartbeat, and skipping the read handed that node a hard-coded
    // enforce=false. BOTH checks below need the real toggle value to
    // refuse a node in that state — an absent TLS pin is engineered the
    // same way, by stripping tls_spki_pin from the heartbeat.
    let enforce = cluster_enforcement(state).await;
    // Block C enforce phase. Refuses BEFORE dialling when there is no pin
    // to enforce with — see check_cert_pinning for why "no pin" cannot be
    // treated as "nothing to enforce".
    let pinned_pubkey =
        check_cert_pinning(node_id, route.reported_pin.as_deref(), enforce.cert_pinning)?;
    let opts = RemoteCallOpts {
        timeout_secs: timeout_for_request(&req),
        pinned_pubkey,
        ..RemoteCallOpts::default()
    };
    match call_remote_attested(&route.endpoint, signer, node_id, req, opts).await {
        Ok(out) => {
            warn_on_pin_mismatch(
                node_id,
                route.reported_pin.as_deref(),
                out.observed_pin.as_deref(),
            );
            // Response authentication lives HERE, on the remote path
            // only. The local Unix-socket branch of `dispatch_to_node`
            // has no signed envelope and therefore no nonce to bind a
            // response to, so the same check there would fail every call
            // the master makes to itself. The gate is the dispatch path
            // taken, never the node id — the master's own `nodes` row
            // stores its hostname, not `LOCAL_NODE_SENTINEL`.
            check_response_auth(
                node_id,
                route.resp_pubkey.as_deref(),
                &out,
                enforce.response_auth,
            )?;
            Ok(out.resp)
        }
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

/// Broadcast one request to many worker nodes **concurrently** and
/// collect the responses. This is the cluster-aggregation workhorse:
/// pages like /hostings, the dashboard, /certs, /bans, /vulns,
/// /monitoring and /trash all need to "ask every node the same
/// question and merge the answers".
///
/// Doing this serially (the old `for n in nodes { dispatch().await }`)
/// meant one slow or wedged worker stalled the *entire* page for up to
/// its full per-RPC timeout, and N slow workers stacked additively.
/// Here the wall-clock is bounded by the **slowest single** node, not
/// the sum. Each task gets a cheap `Arc`-clone of `state`.
///
/// Best-effort by design: a node that errors, times out, or returns an
/// unexpected shape is logged and omitted — the page still renders with
/// whatever nodes answered. The returned pairs are sorted by `node_id`
/// so the merged output is deterministic regardless of which task
/// finishes first. Each pair carries the full `NodeSummary` so callers
/// can tag rows with either `node_id` or the human `label`.
///
/// A node whose response failed AUTHENTICATION is dropped from the
/// aggregate too — but never quietly. Use [`fan_out_reporting`] where
/// the page can say so: "a node's sites are missing because it was
/// down" and "a node's sites are missing because someone forged its
/// answer" must not look identical to the operator.
pub async fn fan_out(
    state: &SharedState,
    nodes: Vec<hyperion_types::NodeSummary>,
    req: Request,
) -> Vec<(hyperion_types::NodeSummary, Response)> {
    fan_out_reporting(state, nodes, req).await.0
}

/// One node's fan-out outcome: the answered pair, or the node plus why
/// it dropped out of the aggregate.
type FanOutResult =
    Result<(hyperion_types::NodeSummary, Response), (hyperion_types::NodeSummary, DispatchError)>;

/// [`fan_out`] that also hands back the nodes that dropped out, so an
/// aggregate page can render a banner instead of silently showing
/// fewer rows. Both vectors are sorted by `node_id`.
///
/// Callers should treat [`DispatchError::ResponseAuthFailed`] in the
/// failure list as a security event, not as node churn: the node
/// answered, and the master threw the answer away because it couldn't
/// prove the node wrote it.
pub async fn fan_out_reporting(
    state: &SharedState,
    nodes: Vec<hyperion_types::NodeSummary>,
    req: Request,
) -> (
    Vec<(hyperion_types::NodeSummary, Response)>,
    Vec<(hyperion_types::NodeSummary, DispatchError)>,
) {
    let mut set: tokio::task::JoinSet<FanOutResult> = tokio::task::JoinSet::new();
    for n in nodes {
        let st = state.clone();
        let r = req.clone();
        set.spawn(async move {
            let nid = n.node_id.clone();
            match dispatch_to_node(&st, Some(nid.as_str()), r).await {
                Ok(resp) => Ok((n, resp)),
                Err(e) => {
                    // A failed-authentication node is not "one more slow
                    // worker". Log it at ERROR with the security wording
                    // so it can't be lost among routine exclusions in
                    // `journalctl -u hyperion-web -g fan_out`.
                    if matches!(
                        e,
                        DispatchError::ResponseAuthFailed { .. }
                            | DispatchError::CertPinMissing { .. }
                    ) {
                        tracing::error!(
                            node = %nid,
                            error = %e,
                            "SECURITY: fan_out excluded a node the master could not \
                             authenticate — this page is rendering an INCOMPLETE \
                             aggregate, not an empty one"
                        );
                    } else {
                        tracing::warn!(node = %nid, error = %e, "fan_out: node excluded");
                    }
                    Err((n, e))
                }
            }
        });
    }
    let mut out: Vec<(hyperion_types::NodeSummary, Response)> = Vec::new();
    let mut failed: Vec<(hyperion_types::NodeSummary, DispatchError)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(pair)) => out.push(pair),
            Ok(Err(pair)) => failed.push(pair),
            // JoinError: the task itself panicked or was cancelled. There
            // is no NodeSummary to report against, same as before.
            Err(_) => {}
        }
    }
    out.sort_by(|a, b| a.0.node_id.cmp(&b.0.node_id));
    failed.sort_by(|a, b| a.0.node_id.cmp(&b.0.node_id));
    (out, failed)
}

/// Where to reach one enrolled node, plus the crypto material the
/// master has on file for it.
struct NodeRoute {
    /// `https://<ip>:9443` base URL.
    endpoint: String,
    /// Last heartbeat-reported TLS SPKI pin, if any.
    reported_pin: Option<String>,
    /// Last published Ed25519 response-signing pubkey, if any.
    /// Two same-shaped `Option<String>`s are exactly the pair a
    /// positional tuple lets a caller swap without the compiler
    /// noticing — pinning against a signing key would fail every
    /// connection — so they travel named.
    resp_pubkey: Option<String>,
}

/// Look up the target node's public IP from the master's `nodes`
/// table (via the local agent's `NodesList` RPC) and build the
/// `https://<ip>:9443` base URL, along with the node's last
/// heartbeat-reported TLS SPKI pin and response-signing pubkey (either
/// may be absent). Both come from the node's AUTHENTICATED heartbeat,
/// which is what makes them usable as the reference to compare this
/// connection against.
async fn resolve_node_endpoint(
    state: &SharedState,
    node_id: &str,
) -> Result<NodeRoute, DispatchError> {
    let list_resp = call(&state.agent_socket, Request::NodesList).await?;
    let nodes = match list_resp {
        Response::NodesList(v) => v,
        _ => return Err(DispatchError::UnexpectedNodesListResponse),
    };
    let node = nodes
        .into_iter()
        .find(|n| n.node_id == node_id)
        .ok_or_else(|| DispatchError::UnknownNode(node_id.to_string()))?;
    let reported_pin = node.tls_spki_pin.clone();
    let resp_pubkey = node.resp_pubkey.clone();
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
    Ok(NodeRoute {
        endpoint: format!("https://{host_part}:{}", DEFAULT_AGENT_RPC_PORT),
        reported_pin,
        resp_pubkey,
    })
}

/// The cluster's two enforcement toggles.
#[derive(Debug, Clone, Copy, Default)]
struct Enforcement {
    /// `[cluster] enforce_worker_cert_pinning` — pin the worker's TLS
    /// cert for real (`curl --pinnedpubkey`).
    cert_pinning: bool,
    /// `[cluster] enforce_response_auth` — refuse an unsigned response
    /// from a node that has published a response-signing key.
    response_auth: bool,
}

/// Read both cluster enforcement toggles (agent.toml `[cluster]`,
/// surfaced via AgentConfigView) in a SINGLE local RPC. They are wanted
/// on the same dispatch, so a function per toggle would double the
/// local round trips on every remote call.
///
/// FAIL-SAFE: any read failure returns all-false (never enforce), so a
/// flaky config read can't accidentally lock the master out of its
/// workers — for either toggle.
async fn cluster_enforcement(state: &SharedState) -> Enforcement {
    match call(&state.agent_socket, Request::AgentConfigView).await {
        Ok(Response::AgentConfigView(c)) => Enforcement {
            cert_pinning: c.cluster.enforce_worker_cert_pinning,
            response_auth: c.cluster.enforce_response_auth,
        },
        _ => Enforcement::default(),
    }
}

/// Decide the `--pinnedpubkey` value for this dispatch, or refuse it.
///
/// The pin the master holds is trust-on-first-use and **write-once**:
/// `nodes.tls_spki_pin` is only ever FILLED (`COALESCE(tls_spki_pin, ?)`
/// in `touch_last_seen`), a heartbeat presenting a DIFFERENT pin is
/// refused and warned about (`tofu_report`), and clearing it is an
/// explicit operator action (`node_reset_crypto`, re-enrollment). So an
/// attacker cannot silently re-aim a pin that has landed.
///
/// What they can still do is stop one from ever landing: the heartbeat
/// travels over `curl -k`, so stripping `tls_spki_pin` from it leaves
/// the column NULL forever. Treating NULL as "nothing to enforce" would
/// hand the attacker the choice of WHICH nodes the toggle protects, and
/// the connection would then be made with `-k` and no pin — precisely
/// the state the toggle exists to end. So under enforcement, no pin on
/// file is a refusal, exactly like no response-signing key on file is in
/// [`check_response_auth`].
///
/// With enforcement OFF this returns `Ok(None)` for every input and
/// nothing is ever refused: the warn-only observation in
/// [`warn_on_pin_mismatch`] is the whole behaviour, unchanged.
fn check_cert_pinning(
    node_id: &str,
    reported_pin: Option<&str>,
    enforce: bool,
) -> Result<Option<String>, DispatchError> {
    if !enforce {
        return Ok(None);
    }
    match reported_pin {
        Some(pin) => Ok(Some(pin.to_string())),
        None => {
            tracing::error!(
                node = node_id,
                "SECURITY: worker TLS certificate pinning is enforced but this node has no \
                 pin on file, so the RPC would run over an unverified connection with nothing \
                 to check the cert against. Refused. Restart the node's agent and wait one \
                 heartbeat for it to report its pin (the 🔒 chip on Nodes), or turn off \
                 Enforce worker TLS certificate pinning in Settings → Cluster."
            );
            Err(DispatchError::CertPinMissing {
                node_id: node_id.to_string(),
            })
        }
    }
}

/// The four-way response-authentication matrix, evaluated on every
/// remote dispatch. `resp_pubkey` is the key the node published over
/// its authenticated heartbeat; `out.resp_sig` is what arrived on
/// *this* connection.
///
/// Capability is decided by PRESENCE of the pubkey, never by
/// `agent_version`: git-describe strings don't order, and the version
/// column lags a node restart by a full heartbeat tick.
///
/// `enforce` is the whole-cluster switch, so NO key on file is just as
/// unverifiable as a stripped signature: once enforcement is on, every
/// arm that cannot actually verify has to refuse. Otherwise an attacker
/// who suppresses `resp_pubkey` from a node's heartbeat (leaving the
/// column NULL) walks straight through the feature that exists to stop
/// exactly that. Settings → Cluster is where the operator confirms every
/// node shows its "🔑 Response auth on file" chip before flipping this;
/// that chip, not `agent_version`, is the readiness signal.
fn check_response_auth(
    node_id: &str,
    resp_pubkey: Option<&str>,
    out: &RemoteCallOutcome,
    enforce: bool,
) -> Result<(), DispatchError> {
    /// Shared `reason` for the two arms where the master simply has no
    /// key to check against. Distinct from a verification failure on
    /// purpose: the operator's fix is "get this node to publish its key"
    /// (upgrade + one heartbeat, or `node reset crypto`), not "hunt for
    /// a forgery".
    const NO_KEY: &str = "no response-signing key on file for this node — nothing to verify \
                          against while response auth is enforced";

    match (out.resp_sig.as_deref(), resp_pubkey) {
        // (1) Old node, nothing on file. The mandatory new-master /
        //     old-node transient of a rolling upgrade: with enforcement
        //     OFF there is no key to verify against, so accept silently.
        //     With it ON this is a node that never published a key —
        //     either genuinely un-upgraded, or one whose key report was
        //     stripped on-path to keep the column NULL. Refuse: an
        //     unverifiable node must not be more trusted than one that
        //     merely dropped its signature.
        (None, None) => {
            if enforce {
                tracing::error!(
                    node = node_id,
                    "SECURITY: worker answered UNSIGNED and has no response-signing key \
                     on file. Response auth is enforced, so the response was discarded. \
                     Upgrade the node (or run `node reset crypto`) and wait one heartbeat \
                     so it publishes its key."
                );
                Err(DispatchError::ResponseAuthFailed {
                    node_id: node_id.to_string(),
                    reason: NO_KEY.to_string(),
                })
            } else {
                Ok(())
            }
        }
        // (2) Both halves present — verify for real, over the RAW bytes
        //     curl received. A WRONG signature is a hard failure
        //     regardless of the enforcement toggle: "unsigned" is a
        //     compatibility state an operator opts out of on their own
        //     schedule, "mis-signed" is an attack and no toggle makes it
        //     benign.
        (Some(sig), Some(pubkey)) => match verify_response(
            sig,
            pubkey,
            node_id,
            &out.req_nonce,
            out.req_ts,
            &out.raw_body,
            chrono::Utc::now().timestamp(),
            VerifyOpts::default(),
        ) {
            Ok(_) => Ok(()),
            Err(reason) => {
                tracing::error!(
                    node = node_id,
                    reason = reason,
                    "SECURITY: worker response failed signature verification — the body \
                     was not produced by the key this node published. Discarding it."
                );
                Err(DispatchError::ResponseAuthFailed {
                    node_id: node_id.to_string(),
                    reason: reason.to_string(),
                })
            }
        },
        // (3) The node signs but the master has no key for it yet: agent
        //     upgraded, first heartbeat not landed. With enforcement OFF
        //     accept — there is nothing to check against — but say so
        //     once, so the operator can tell this apart from a node that
        //     never signs. With it ON, refuse: a signature we cannot
        //     check is not evidence of anything, and an attacker can mint
        //     one trivially by keeping the pubkey column NULL and signing
        //     with a key of their own.
        (Some(_), None) => {
            if enforce {
                tracing::error!(
                    node = node_id,
                    "SECURITY: worker signed its response but has published no \
                     response-signing key, so the signature cannot be checked against \
                     anything. Response auth is enforced, so the response was discarded. \
                     Wait one heartbeat for the node to publish its key."
                );
                Err(DispatchError::ResponseAuthFailed {
                    node_id: node_id.to_string(),
                    reason: NO_KEY.to_string(),
                })
            } else {
                tracing::info!(
                    node = node_id,
                    "worker signed its response but has not published a response-signing \
                     key yet — accepted unverified until its next heartbeat"
                );
                Ok(())
            }
        }
        // (4) THE DOWNGRADE ATTACK: the node is known to sign, and this
        //     answer came back unsigned. Either the worker was rolled
        //     back, or someone on the path stripped the header to dodge
        //     case (2) entirely. Warn-only until the operator flips
        //     enforcement, because one un-upgraded worker would
        //     otherwise take the whole cluster offline.
        (None, Some(_)) => {
            if enforce {
                tracing::error!(
                    node = node_id,
                    "SECURITY: worker publishes a response-signing key but answered \
                     UNSIGNED — possible stripped signature. Response auth is enforced, \
                     so the response was discarded."
                );
                Err(DispatchError::ResponseAuthFailed {
                    node_id: node_id.to_string(),
                    reason: "node publishes a response-signing key but the response \
                             arrived unsigned"
                        .to_string(),
                })
            } else {
                tracing::warn!(
                    node = node_id,
                    "SECURITY (warn-only): worker publishes a response-signing key but \
                     answered UNSIGNED — a downgrade would look exactly like this. \
                     Response auth is NOT enforced yet, so this request was allowed. \
                     Turn on Enforce response authentication in Settings → Cluster once \
                     every node signs."
                );
                Ok(())
            }
        }
    }
}

/// Warn-only TLS pin check (Block C). Compares the SPKI pin the worker
/// reported over its authenticated heartbeat (`reported`) against the
/// pin of the cert it actually presented on this RPC connection
/// (`observed`). A mismatch means the connection's cert differs from
/// what the authenticated worker claims — a possible MITM, or the
/// worker rotated its inbound cert and hasn't heartbeated since. We
/// only LOG (loudly): pinning is not enforced yet, so legitimate RPC is
/// never blocked. Pins are public cert fingerprints — safe to log. No
/// worker IP is logged (only the operator-facing node id).
fn warn_on_pin_mismatch(node_id: &str, reported: Option<&str>, observed: Option<&str>) {
    match (reported, observed) {
        (Some(r), Some(o)) if r != o => {
            tracing::warn!(
                node = node_id,
                reported_pin = r,
                observed_pin = o,
                "SECURITY (warn-only): worker presented a TLS cert whose SPKI pin \
                 does not match the one it reported over heartbeat — possible MITM \
                 or an unreported cert rotation. Pinning is NOT enforced yet, so \
                 this request was allowed."
            );
        }
        (Some(_), Some(_)) => {
            tracing::trace!(node = node_id, "worker TLS pin matches reported");
        }
        // No reported pin yet (pre-heartbeat / older agent) or no observed
        // pin (older curl / parse failure) → nothing to compare.
        _ => {}
    }
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
            // Routed through AppError::Rpc, NEVER AppError::NodeUnreachable:
            // the node answered. Rendering a possible forgery as downtime
            // would send the operator off restarting a healthy agent while
            // an attacker holds the path. The body text carries the real
            // story; `reason` is a fixed verifier string, never content.
            DispatchError::ResponseAuthFailed { node_id, reason } => AppError::Rpc(format!(
                "the response from node {node_id} could not be authenticated ({reason}), \
                 so the master discarded it. This is a signature failure, not a \
                 connectivity problem: check `journalctl -u hyperion-agent` on the node \
                 and whether anything is intercepting master→worker traffic."
            )),
            // Also NOT NodeUnreachable: the node is fine, the master
            // declined to talk to it unverified. The two fixes are named
            // in the order an operator should try them — re-reporting the
            // pin keeps the protection, switching the toggle off drops it.
            DispatchError::CertPinMissing { node_id } => AppError::Rpc(format!(
                "node {node_id} has not reported a TLS certificate pin, and Enforce worker TLS \
                 certificate pinning is on in Settings → Cluster — so the master refused to \
                 dispatch over a connection it cannot check. Restart hyperion-agent on that node \
                 and wait one heartbeat (about 30 s) for the 🔒 chip to appear on Nodes, or turn \
                 the setting off."
            )),
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_core::node_rpc::{sign_response, NodeRpcSigner};

    const NODE: &str = "s4";
    /// Stand-in for a response whose content an attacker would love to
    /// rewrite (the password shown to the operator after a reset).
    const BODY: &[u8] = br#"{"HostingResetPassword":{"password":"real-secret"}}"#;

    fn fresh_signer() -> NodeRpcSigner {
        let tmp = tempfile::tempdir().expect("tempdir");
        NodeRpcSigner::load_or_init(&tmp.path().join("node-rpc.key")).expect("key")
    }

    fn outcome(resp_sig: Option<&str>, req_ts: i64, body: &[u8]) -> RemoteCallOutcome {
        RemoteCallOutcome {
            resp: Response::HostingDelete,
            raw_body: body.to_vec(),
            observed_pin: None,
            resp_sig: resp_sig.map(str::to_string),
            req_ts,
            req_nonce: "nonce-1".to_string(),
        }
    }

    fn is_auth_failure(e: &DispatchError) -> bool {
        matches!(e, DispatchError::ResponseAuthFailed { .. })
    }

    // (1) Old node: no signature, no key on file. The mandatory
    //     new-master/old-node transient of a rolling upgrade — must pass
    //     while enforcement is OFF, or upgrading the master bricks the
    //     panel for every not-yet-upgraded worker.
    #[test]
    fn unsigned_from_unknown_key_node_is_accepted_when_not_enforced() {
        let out = outcome(None, 0, BODY);
        assert!(check_response_auth(NODE, None, &out, false).is_ok());
    }

    // (1) ...but once enforcement is ON, "no key on file" is exactly the
    //     state an attacker engineers by stripping resp_pubkey from the
    //     heartbeat. Accepting it would make the toggle meaningless.
    #[test]
    fn unsigned_from_unknown_key_node_is_refused_when_enforced() {
        let out = outcome(None, 0, BODY);
        let err = check_response_auth(NODE, None, &out, true)
            .expect_err("unverifiable node must be refused under enforcement");
        assert!(is_auth_failure(&err), "wrong variant: {err}");
        assert!(
            err.to_string().contains("no response-signing key on file"),
            "reason must distinguish 'no key' from a signature mismatch: {err}"
        );
    }

    // (2) Both halves present: the real verification path.
    #[test]
    fn valid_signature_is_accepted() {
        let s = fresh_signer();
        let now = chrono::Utc::now().timestamp();
        let sig = sign_response(&s, NODE, "nonce-1", now, now, BODY);
        let out = outcome(Some(&sig), now, BODY);
        assert!(check_response_auth(NODE, Some(s.pubkey_b64()), &out, false).is_ok());
    }

    // (2) A forged body is a HARD failure with enforcement OFF. The
    //     toggle governs "unsigned", never "mis-signed".
    #[test]
    fn forged_body_fails_even_when_enforcement_is_off() {
        let s = fresh_signer();
        let now = chrono::Utc::now().timestamp();
        let sig = sign_response(&s, NODE, "nonce-1", now, now, BODY);
        // On-path attacker swapped the password the operator will see.
        let tampered = br#"{"HostingResetPassword":{"password":"attacker-chosen"}}"#;
        let out = outcome(Some(&sig), now, tampered);
        let err = check_response_auth(NODE, Some(s.pubkey_b64()), &out, false)
            .expect_err("forged body must be refused");
        assert!(is_auth_failure(&err), "wrong variant: {err}");
    }

    // (2) A response captured from one request must not pass as the
    //     answer to another — the nonce is in the preimage.
    #[test]
    fn replayed_response_from_another_request_fails() {
        let s = fresh_signer();
        let now = chrono::Utc::now().timestamp();
        let sig = sign_response(&s, NODE, "nonce-of-some-other-request", now, now, BODY);
        let out = outcome(Some(&sig), now, BODY);
        let err = check_response_auth(NODE, Some(s.pubkey_b64()), &out, false)
            .expect_err("replay must be refused");
        assert!(is_auth_failure(&err), "wrong variant: {err}");
    }

    // (3) Node upgraded, heartbeat not yet landed: accept while
    //     enforcement is off (nothing to verify against), refuse once it
    //     is on — an uncheckable signature proves nothing, and anyone can
    //     produce one with a key of their own.
    #[test]
    fn signature_without_stored_key_is_accepted_only_while_unenforced() {
        let out = outcome(Some("1700000000.whatever"), 1_700_000_000, BODY);
        assert!(check_response_auth(NODE, None, &out, false).is_ok());
        let err = check_response_auth(NODE, None, &out, true)
            .expect_err("uncheckable signature must be refused under enforcement");
        assert!(is_auth_failure(&err), "wrong variant: {err}");
        assert!(
            err.to_string().contains("no response-signing key on file"),
            "reason must distinguish 'no key' from a signature mismatch: {err}"
        );
    }

    // (4) The downgrade: known signer answered unsigned.
    #[test]
    fn missing_signature_from_known_signer_is_warn_only_until_enforced() {
        let s = fresh_signer();
        let out = outcome(None, 1_700_000_000, BODY);
        assert!(check_response_auth(NODE, Some(s.pubkey_b64()), &out, false).is_ok());
        let err = check_response_auth(NODE, Some(s.pubkey_b64()), &out, true)
            .expect_err("enforced downgrade must be refused");
        assert!(is_auth_failure(&err), "wrong variant: {err}");
    }

    const PIN: &str = "/4IrPU/vEdcxQgcB9m3gD/9oaQ9/8WmdvXZIDD+ZVxg=";

    /// Nothing changes until the operator flips the toggle — including
    /// for a node that has never reported a pin. This is the arm that
    /// keeps a mixed cluster working, so it is asserted first.
    #[test]
    fn cert_pinning_is_inert_until_the_operator_enforces_it() {
        assert_eq!(check_cert_pinning(NODE, Some(PIN), false).unwrap(), None);
        assert_eq!(check_cert_pinning(NODE, None, false).unwrap(), None);
    }

    /// Enforcing pins the value on file, verbatim — it is what curl gets
    /// after `sha256//`, so any rewriting here would break every call.
    #[test]
    fn enforced_pinning_pins_exactly_the_pin_on_file() {
        assert_eq!(
            check_cert_pinning(NODE, Some(PIN), true)
                .expect("a node with a pin is dispatched to")
                .as_deref(),
            Some(PIN)
        );
    }

    /// The write-once rule's consequence. Because the master only ever
    /// FILLS `nodes.tls_spki_pin` and refuses a changed one, an attacker
    /// cannot re-aim a pin that landed — the only lever left is keeping
    /// one from ever landing, by stripping `tls_spki_pin` from the
    /// node's (unverified) heartbeats. Enforcement therefore has to read
    /// "no pin on file" as a refusal; reading it as "nothing to check"
    /// would let the attacker choose who the toggle protects.
    #[test]
    fn enforced_pinning_refuses_a_node_whose_pin_never_landed() {
        let err = check_cert_pinning(NODE, None, true)
            .expect_err("a pinless node must not be dispatched to under enforcement");
        assert!(
            matches!(err, DispatchError::CertPinMissing { .. }),
            "wrong variant: {err}"
        );
        assert!(err.to_string().contains("no TLS certificate pin"), "{err}");
    }

    /// ...and the refusal must not read as downtime either: an operator
    /// who restarts a healthy agent looking for a network fault is an
    /// operator who never finds the toggle that caused this.
    #[test]
    fn missing_pin_does_not_render_as_node_unreachable() {
        let app: crate::error::AppError = DispatchError::CertPinMissing {
            node_id: NODE.to_string(),
        }
        .into();
        assert!(
            !matches!(app, crate::error::AppError::NodeUnreachable { .. }),
            "an enforcement refusal must not present as downtime"
        );
        let text = app.to_string();
        assert!(
            text.contains("Settings"),
            "names where to turn it off: {text}"
        );
    }

    /// A forged response must never reach the operator as "node
    /// unreachable" — that reads as downtime and invites a retry.
    #[test]
    fn auth_failure_does_not_render_as_node_unreachable() {
        let err = DispatchError::ResponseAuthFailed {
            node_id: NODE.to_string(),
            reason: "signature verify failed".to_string(),
        };
        let app: crate::error::AppError = err.into();
        assert!(
            !matches!(app, crate::error::AppError::NodeUnreachable { .. }),
            "response auth failure must not present as downtime"
        );
        let text = app.to_string();
        assert!(text.contains("could not be authenticated"), "{text}");
    }
}
