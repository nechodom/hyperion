//! `/install` — the Nodes page: every machine in the cluster (the master
//! included) with its health at a glance, per-node management, and the
//! enrollment tools for adding another one.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::AgentInfo;
use hyperion_types::{NodeInviteMint, NodeInviteSummary, NodeSummary};
use serde::Deserialize;

/// A worker whose last heartbeat is older than this is shown as not
/// checking in. Same window as the hostings list's "node offline" flag, so
/// the two pages can't disagree about the same machine.
const STALE_HEARTBEAT_SECS: i64 = 300;

#[derive(Template)]
#[template(path = "install.html")]
struct InstallTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    master_url: &'a str,
    invites: Vec<NodeInviteSummary>,
    /// The master first, then every enrolled worker. Flags and problems
    /// are resolved server-side (askama can't run closures), and the
    /// verdict line is built from the same `issues`, so the summary at the
    /// top and the rows below can't disagree.
    rows: Vec<NodeRow>,
    worker_count: usize,
    verdict: NodesVerdict,
    just_minted: Option<NodeInviteMint>,
    error: Option<String>,
    csrf_create: String,
    csrf_revoke: String,
    /// CSRF token for the per-row "Test connection" button.
    csrf_test: String,
    /// CSRF for the per-row update form (apt + hyperion).
    csrf_update: String,
    /// Session-wide CSRF token that validates against ANY POST in
    /// the current session. Used by the inline action forms (drain,
    /// rename, toggle-test, clear crypto, remove) so each doesn't need
    /// its own minted path token.
    csrf_token: String,
}

/// One machine on the Nodes page. The master is a row too
/// (`node_id = "local"`, the dispatcher's name for it), so "every machine
/// in the cluster" reads as one list.
#[derive(Debug, Clone)]
pub struct NodeRow {
    pub n: NodeSummary,
    pub is_master: bool,
    /// Heartbeat within `STALE_HEARTBEAT_SECS`. Always true for the master,
    /// which is serving this page.
    pub online: bool,
    pub is_test: bool,
    /// The agent version differs from the master's. An older agent may not
    /// understand newer RPCs, which surfaces as confusing failures.
    pub version_skew: bool,
    /// Plain-language problems, worst first: `(tone, text)`.
    pub issues: Vec<(&'static str, String)>,
}

impl NodeRow {
    /// The node's record by reference, for the template's
    /// `{% let n = r.summary() %}` (askama's `let` would move a field).
    pub fn summary(&self) -> &NodeSummary {
        &self.n
    }

    /// The worst tone among this node's problems, `""` when there are none.
    pub fn tone(&self) -> &'static str {
        self.issues.first().map(|(t, _)| *t).unwrap_or("")
    }
}

/// The one-line answer at the top of the page.
#[derive(Debug, Clone)]
pub struct NodesVerdict {
    pub tone: &'static str,
    pub text: String,
}

/// Build the page's rows: the master from its own `AgentInfo`, then each
/// enrolled worker with its flags and problems.
///
/// `master_ver` is the yardstick for version skew; when it is unknown no
/// node is flagged (no false alarms), and an empty worker version (a
/// pre-version schema) is never "skewed" either.
fn build_rows(
    master: Option<&AgentInfo>,
    nodes: Vec<NodeSummary>,
    test_csv: &str,
    now: i64,
) -> Vec<NodeRow> {
    let test_set: std::collections::HashSet<&str> = test_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let master_ver = master.map(|m| m.version.as_str()).unwrap_or("");
    let mut rows = Vec::with_capacity(nodes.len() + 1);
    rows.push(NodeRow {
        n: NodeSummary {
            node_id: crate::dispatcher::LOCAL_NODE_SENTINEL.to_string(),
            label: master
                .map(|m| m.hostname.clone())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "This server".to_string()),
            master_url: None,
            agent_version: master_ver.to_string(),
            public_ip: master.and_then(|m| m.public_ipv4.clone()),
            enrolled_at: 0,
            last_seen_at: 0,
            is_drained: false,
            drain_reason: String::new(),
            tls_spki_pin: None,
            resp_pubkey: None,
        },
        is_master: true,
        online: true,
        is_test: false,
        version_skew: false,
        issues: Vec::new(),
    });
    for n in nodes {
        let online = n.last_seen_at > 0 && now - n.last_seen_at <= STALE_HEARTBEAT_SECS;
        let version_skew =
            !master_ver.is_empty() && !n.agent_version.is_empty() && n.agent_version != master_ver;
        let mut issues: Vec<(&'static str, String)> = Vec::new();
        if !online {
            issues.push((
                "err",
                if n.last_seen_at > 0 {
                    format!(
                        "no heartbeat since {}",
                        crate::handlers::stats::fmt_ago(&n.last_seen_at)
                    )
                } else {
                    "has never checked in".to_string()
                },
            ));
        }
        if version_skew {
            issues.push((
                "warn",
                format!("agent {} differs from the master's", n.agent_version),
            ));
        }
        if n.tls_spki_pin.is_none() {
            issues.push(("warn", "no TLS pin on file".to_string()));
        }
        if n.resp_pubkey.is_none() {
            issues.push(("warn", "no response-signing key".to_string()));
        }
        issues.sort_by_key(|(t, _)| if *t == "err" { 0 } else { 1 });
        rows.push(NodeRow {
            is_test: test_set.contains(n.node_id.as_str()),
            n,
            is_master: false,
            online,
            version_skew,
            issues,
        });
    }
    rows
}

/// Name what needs a look, worst first, or say plainly that nothing does.
fn build_verdict(rows: &[NodeRow]) -> NodesVerdict {
    let workers = rows.iter().filter(|r| !r.is_master).count();
    // One part per node, its problems joined — the node is named once, and
    // its worst problem sets where it sorts.
    let mut parts: Vec<(&'static str, String)> = rows
        .iter()
        .filter(|r| !r.issues.is_empty())
        .map(|r| {
            let what: Vec<&str> = r.issues.iter().map(|(_, m)| m.as_str()).collect();
            (r.tone(), format!("{}: {}", r.n.label, what.join(", ")))
        })
        .collect();
    if parts.is_empty() {
        return match workers {
            0 => NodesVerdict {
                tone: "",
                text: "Only this server so far — add a node below to spread sites across machines"
                    .to_string(),
            },
            1 => NodesVerdict {
                tone: "ok",
                text: "The worker node is checking in, nothing needs a look".to_string(),
            },
            n => NodesVerdict {
                tone: "ok",
                text: format!("All {n} worker nodes checking in, nothing needs a look"),
            },
        };
    }
    parts.sort_by_key(|(t, _)| if *t == "err" { 0 } else { 1 });
    let tone = parts[0].0;
    let shown: Vec<String> = parts.iter().take(3).map(|(_, s)| s.clone()).collect();
    let mut text = shown.join(" · ");
    if parts.len() > 3 {
        text.push_str(&format!(" · +{} more", parts.len() - 3));
    }
    NodesVerdict { tone, text }
}

/// The master's own `AgentInfo` over the local socket. `None` on any
/// failure; the master row then shows without a version or IP.
async fn fetch_master_info(state: &SharedState) -> Option<AgentInfo> {
    match hyperion_rpc_client::call(&state.agent_socket, Request::AgentInfo).await {
        Ok(RpcResponse::AgentInfo(info)) => Some(info),
        _ => None,
    }
}

/// Render the whole page. `just_minted` carries a fresh invite's plaintext
/// token (shown once); `error` a failed form submission.
async fn render_page(
    state: &SharedState,
    ctx: &AuthCtx,
    headers: &HeaderMap,
    just_minted: Option<NodeInviteMint>,
    error: Option<String>,
) -> Result<String, AppError> {
    let (invites, nodes, test_csv, master) = tokio::join!(
        fetch_invites(state),
        fetch_nodes(state),
        fetch_cluster_test_node_ids(state),
        fetch_master_info(state),
    );
    let rows = build_rows(
        master.as_ref(),
        nodes.unwrap_or_default(),
        &test_csv,
        hyperion_types::now_secs(),
    );
    let verdict = build_verdict(&rows);
    let master_url = derive_master_url(state, headers).await;
    let tpl = InstallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "install",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        master_url: &master_url,
        invites: invites.unwrap_or_default(),
        worker_count: rows.len().saturating_sub(1),
        rows,
        verdict,
        just_minted,
        error,
        csrf_create: csrf_token(state, ctx, "/install/invite"),
        csrf_revoke: csrf_token(state, ctx, "/install/invite/revoke"),
        csrf_test: csrf_token(state, ctx, "/install/test-node"),
        csrf_update: csrf_token(state, ctx, "/install/update-node"),
        csrf_token: super::session_csrf_token(state, ctx),
    };
    Ok(tpl.render()?)
}

pub async fn get_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Minting + revoking invite tokens enrols new boxes into the
    // cluster. Viewers shouldn't even see the page — the plaintext
    // token + master URL on the install one-liner is enough to
    // social-engineer a misconfigured node into a malicious cluster.
    if !ctx.is_super_admin() {
        return Ok(
            Redirect::to("/?flash_error=admin+role+required+for+node+enrollment").into_response(),
        );
    }
    Ok(Html(render_page(&state, &ctx, &headers, None, None).await?).into_response())
}

#[derive(Deserialize)]
pub struct CreateForm {
    label: String,
    #[serde(default = "default_ttl")]
    ttl_hours: i64,
}
fn default_ttl() -> i64 {
    24
}

pub async fn post_invite(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(
            Redirect::to("/?flash_error=admin+role+required+for+node+enrollment").into_response(),
        );
    }
    let label = form.label.trim().to_string();
    if label.is_empty() {
        return Ok(render_with_error(&state, &ctx, &headers, "Label must not be empty").await);
    }
    let ttl_secs = form.ttl_hours.clamp(1, 30 * 24) * 3600;
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::InviteCreate { label, ttl_secs },
    )
    .await?;
    let mint = match resp {
        RpcResponse::InviteCreate(m) => m,
        RpcResponse::Error(e) => {
            return Ok(render_with_error(&state, &ctx, &headers, &e.to_string()).await);
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    // The rendered page carries the plaintext invite token. Make sure
    // browser/proxy caches don't keep it around past the first view.
    let mut response =
        Html(render_page(&state, &ctx, &headers, Some(mint), None).await?).into_response();
    let h = response.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    h.insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    h.insert("vary", axum::http::HeaderValue::from_static("Cookie"));
    Ok(response)
}

#[derive(Deserialize)]
pub struct RevokeForm {
    token_hash: String,
}

pub async fn post_revoke(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RevokeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(
            Redirect::to("/?flash_error=admin+role+required+for+node+enrollment").into_response(),
        );
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::InviteRevoke {
            token_hash: form.token_hash,
        },
    )
    .await?;
    match resp {
        RpcResponse::InviteRevoke => Ok(Redirect::to("/install").into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /install/update-node — super_admin only.
///
/// Starts a background apt + hyperion update on the chosen node
/// via the signed-RPC channel. Returns immediately; operator polls
/// status via /install/update-node-status or sees the log on
/// /install (auto-refresh shows the rolling tail).
#[derive(Deserialize)]
pub struct UpdateNodeForm {
    node_id: String,
    #[serde(default)]
    do_apt: Option<String>,
    #[serde(default)]
    do_hyperion: Option<String>,
    /// Snapshot + auto-restore on a failed health check.
    #[serde(default)]
    safe: Option<String>,
}

pub async fn post_update_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<UpdateNodeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let node_id = form.node_id.trim().to_string();
    if node_id.is_empty() {
        return Err(AppError::BadRequest("missing node_id".into()));
    }
    let do_apt = matches!(form.do_apt.as_deref(), Some("on" | "true" | "1"));
    let do_hyperion = matches!(form.do_hyperion.as_deref(), Some("on" | "true" | "1"));
    let safe = matches!(form.safe.as_deref(), Some("on" | "true" | "1"));
    if !do_apt && !do_hyperion {
        return Ok(Redirect::to(
            "/install?flash_error=nothing+to+update+%28tick+at+least+one+option%29",
        )
        .into_response());
    }
    // Special-case: target "local" runs the update on the master itself.
    let target = if node_id == "local" || node_id.is_empty() {
        None
    } else {
        Some(node_id.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::NodeUpdateRun {
            do_apt,
            do_hyperion,
            safe,
        },
    )
    .await?;
    match resp {
        RpcResponse::NodeUpdateRun { started_at } => Ok(Redirect::to(&format!(
            "/install?flash=update+started+%28unix%3A{}%29#node-{}",
            started_at,
            urlencode(&node_id)
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/install?flash_error={}",
            urlencode(&format!("update failed to start: {e}"))
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Form payload for renaming an enrolled node's display label.
#[derive(Deserialize)]
pub struct RenameNodeForm {
    pub node_id: String,
    pub label: String,
}

/// Form payload for toggling a node's drain (maintenance) flag.
#[derive(Deserialize)]
pub struct DrainNodeForm {
    pub node_id: String,
    /// "on" / "1" / "true" ⇒ drain; anything else ⇒ undrain.
    #[serde(default)]
    pub drain: String,
    #[serde(default)]
    pub reason: String,
}

pub async fn post_drain_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DrainNodeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let node_id = form.node_id.trim().to_string();
    if node_id.is_empty() {
        return Err(AppError::BadRequest("missing node_id".into()));
    }
    let drain = matches!(form.drain.as_str(), "on" | "1" | "true");
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NodeSetDrain {
            node_id: node_id.clone(),
            drain,
            reason: form.reason.trim().to_string(),
        },
    )
    .await?;
    let flash = match resp {
        RpcResponse::NodeDrainUpdated => {
            if drain {
                format!(
                    "Node {} drained — auto-placer will skip it. Existing hostings keep serving.",
                    node_id
                )
            } else {
                format!("Node {} returned to active service.", node_id)
            }
        }
        RpcResponse::Error(e) => format!("Drain toggle failed: {e}"),
        _ => "Drain toggle: unexpected response".into(),
    };
    Ok(Redirect::to(&format!(
        "/install?flash={}#node-{}",
        urlencode(&flash),
        urlencode(&node_id)
    ))
    .into_response())
}

pub async fn post_rename_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RenameNodeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let node_id = form.node_id.trim().to_string();
    let label = form.label.trim().to_string();
    if node_id.is_empty() {
        return Err(AppError::BadRequest("missing node_id".into()));
    }
    if label.is_empty() {
        return Ok(Redirect::to(&format!(
            "/install?flash_error={}#node-{}",
            urlencode("Label cannot be empty."),
            urlencode(&node_id)
        ))
        .into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NodeSetLabel {
            node_id: node_id.clone(),
            label: label.clone(),
        },
    )
    .await?;
    let flash = match resp {
        RpcResponse::NodeLabelUpdated => format!("Node renamed to '{label}'."),
        RpcResponse::Error(e) => format!("Rename failed: {e}"),
        _ => "Rename: unexpected response".into(),
    };
    Ok(Redirect::to(&format!(
        "/install?flash={}#node-{}",
        urlencode(&flash),
        urlencode(&node_id)
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct RemoveNodeForm {
    pub node_id: String,
    /// "on" / "1" / "true" → orphan hostings + delete anyway.
    /// Empty / "off" → refuse if hostings still reference the node.
    #[serde(default)]
    pub force: String,
}

/// POST /install/remove-node — drop an enrolled node from the
/// master's registry. Refuses by default when hostings still
/// reference the node; the operator can re-submit with `force=on`
/// to orphan them.
///
/// The agent on the removed node keeps running unchanged — this
/// only mutates master-side state. To "re-enrol" later, mint a
/// fresh invite token and run the enrol command on the worker.
pub async fn post_remove_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RemoveNodeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let node_id = form.node_id.trim().to_string();
    if node_id.is_empty() {
        return Err(AppError::BadRequest("missing node_id".into()));
    }
    let force = matches!(form.force.as_str(), "on" | "1" | "true");
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NodeRemove {
            node_id: node_id.clone(),
            force,
        },
    )
    .await?;
    // Decompose first into a tuple (success, flash) so the
    // ergonomics work out — match arms move the inner RpcError /
    // bool values, which then can't be re-borrowed below.
    let (success, flash): (bool, String) = match resp {
        RpcResponse::NodeRemoved { removed: true, hostings_blocking } => {
            let msg = if hostings_blocking > 0 {
                format!(
                    "Node {} removed. {} hosting(s) were orphaned — they keep their nginx/FPM running on the now-detached box, but cannot be managed from the master until you re-enrol the node or migrate them.",
                    node_id, hostings_blocking
                )
            } else {
                format!("Node {} removed from the cluster.", node_id)
            };
            (true, msg)
        }
        RpcResponse::NodeRemoved { removed: false, hostings_blocking } if hostings_blocking > 0 => {
            (false, format!(
                "Refused — {} hosting(s) still live on {}. Move them to another node first (Move / copy on each hosting), OR re-submit with the Force option ticked to orphan them and delete the node anyway.",
                hostings_blocking, node_id
            ))
        }
        RpcResponse::NodeRemoved { removed: false, .. } => {
            (false, format!("Node {} not found (already removed?)", node_id))
        }
        RpcResponse::Error(e) => (false, format!("Remove failed: {e}")),
        _ => (false, "Remove: unexpected response".into()),
    };
    let key = if success { "flash" } else { "flash_error" };
    // On success the node id is gone, so don't anchor on it.
    let anchor = if success {
        String::new()
    } else {
        format!("#node-{}", urlencode(&node_id))
    };
    Ok(Redirect::to(&format!("/install?{}={}{}", key, urlencode(&flash), anchor)).into_response())
}

#[derive(Deserialize)]
pub struct ResetNodeCryptoForm {
    pub node_id: String,
}

/// POST /install/reset-node-crypto — forget the pinned crypto anchors
/// (`resp_pubkey` + `tls_spki_pin`) recorded for one node so its next
/// heartbeat re-pins whatever the box now presents.
///
/// This is the escape hatch for the refuse-on-change rule. A legitimate
/// agent reinstall regenerates node-rpc.key and the inbound TLS cert
/// while `node-id.json` survives, so the node keeps its id but presents
/// a new key — which the master refuses forever (loudly, as a possible
/// on-path attack) with no in-product fix. Without this route the only
/// recovery is hand-written SQL against the master's database.
///
/// Gated on `is_super_admin`, exactly like Remove / Drain / Rename: the
/// action deliberately DROPS a security pin, so it must not be reachable
/// by anyone who can't already remove the node outright. Nothing is sent
/// to the node and nothing is re-pinned here — the node's own next
/// report supplies the new values, so a mistaken click lands the
/// operator back where they started rather than pinning a typed value.
pub async fn post_reset_node_crypto(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ResetNodeCryptoForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let node_id = form.node_id.trim().to_string();
    if node_id.is_empty() {
        return Err(AppError::BadRequest("missing node_id".into()));
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NodeResetCrypto {
            node_id: node_id.clone(),
        },
    )
    .await?;
    let (success, flash): (bool, String) = match resp {
        RpcResponse::NodeCryptoReset { cleared: true } => (
            true,
            format!(
                "Pinned crypto cleared for {}. The TLS pin and response-signing key chips stay off until the node's next heartbeat (~30 s), which re-pins whatever it presents then.",
                node_id
            ),
        ),
        RpcResponse::NodeCryptoReset { cleared: false } => (
            false,
            format!("Node {} not found (already removed?)", node_id),
        ),
        RpcResponse::Error(e) => (false, format!("Reset failed: {e}")),
        _ => (false, "Reset: unexpected response".into()),
    };
    let key = if success { "flash" } else { "flash_error" };
    Ok(Redirect::to(&format!(
        "/install?{}={}#node-{}",
        key,
        urlencode(&flash),
        urlencode(&node_id)
    ))
    .into_response())
}

/// GET /install/update-node-status?node_id=… — returns a tiny HTML
/// fragment with state pill + log tail. UI polls this via HTMX.
#[derive(Deserialize)]
pub struct UpdateNodeStatusQuery {
    node_id: String,
}

pub async fn get_update_node_status(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<UpdateNodeStatusQuery>,
) -> Response {
    if !ctx.is_super_admin() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<span class=\"pill err\">admin only</span>",
        )
            .into_response();
    }
    let node_id = q.node_id.trim();
    let target = if node_id == "local" || node_id.is_empty() {
        None
    } else {
        Some(node_id)
    };
    let resp = crate::dispatcher::dispatch_to_node(&state, target, Request::NodeUpdateStatus).await;
    // Whether the every-3s poller on that node's row should keep running.
    // This is one RPC per node row, and the /install page lists every node
    // — an idle cluster was still N requests every three seconds, for ever.
    // An RPC error keeps polling, so a node restarting mid-update recovers.
    let mut still_running = true;
    let body = match resp {
        Ok(RpcResponse::NodeUpdateStatus(s)) => {
            still_running = s.started_at != 0 && s.state == "running";
            render_update_status(&s)
        }
        Ok(RpcResponse::Error(e)) => format!(
            "<div class=\"text-soft small\">status RPC error: {}</div>",
            html_escape(&e.to_string())
        ),
        Ok(_) => "<div class=\"text-soft small\">unexpected response</div>".to_string(),
        Err(e) => format!(
            "<div class=\"text-soft small\">unreachable: {}</div>",
            html_escape(&e.to_string())
        ),
    };
    // 286 tells htmx to swap the body and then retire the poll. "Start
    // update" is a plain form POST that re-renders /install, so the next
    // update gets a fresh poller.
    let status = if still_running {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::from_u16(286).unwrap_or(axum::http::StatusCode::OK)
    };
    (status, [("content-type", "text/html; charset=utf-8")], body).into_response()
}

/// Format a NodeUpdateStatus as a small HTML fragment for the
/// /install per-row poll target.
fn render_update_status(s: &hyperion_types::NodeUpdateStatus) -> String {
    if s.started_at == 0 {
        return "<span class=\"text-soft small\">no update has run on this node</span>".to_string();
    }
    let pill = match s.state.as_str() {
        "running" => "<span class=\"pill warn pulse\">running</span>",
        "succeeded" => "<span class=\"pill ok\">done</span>",
        "failed" => "<span class=\"pill err\">failed</span>",
        "interrupted" => "<span class=\"pill err\">interrupted</span>",
        _ => "<span class=\"pill\">unknown</span>",
    };
    let scope = match (s.do_apt, s.do_hyperion) {
        (true, true) => "apt + hyperion",
        (true, false) => "apt only",
        (false, true) => "hyperion only",
        _ => "nothing",
    };
    let mut out = format!(
        "<div style=\"display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap\">\
            {pill} <span class=\"text-soft small\">{scope}</span>"
    );
    if s.state == "failed" {
        out.push_str(&format!(
            " <span class=\"text-soft small\">exit {}</span>",
            s.exit_code
        ));
    }
    if s.state == "interrupted" {
        // The job's unit is gone and wrote no result — killed by a reboot or
        // by hand. Packages may be half-installed; the next run finishes them
        // before it upgrades anything.
        out.push_str(
            " <span class=\"text-soft small\">stopped before it could finish (reboot?) — \
             run it again: it repairs any half-installed packages first</span>",
        );
    }
    out.push_str("</div>");
    if !s.log_tail.is_empty() {
        out.push_str(&format!(
            "<pre style=\"max-height:14rem;overflow:auto;background:var(--surface-1);padding:0.5rem 0.7rem;border-radius:6px;margin:0.5rem 0 0;font-size:0.78rem;line-height:1.45\">{}</pre>",
            html_escape(&s.log_tail)
        ));
    }
    out
}

/// GET /install/os-updates-panel?node_id=… — a node's operating-system update
/// status as an HTML fragment. Lazy-loaded per card: the answer may involve a
/// couple of seconds of `apt list` on the node when packages changed since its
/// last check, and the page must not wait on every node doing that.
pub async fn get_os_updates(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<UpdateNodeStatusQuery>,
) -> Response {
    os_updates_fragment(&state, &ctx, &q.node_id, Request::OsUpdatesStatus).await
}

/// What a node row shows once its own agent has answered.
#[derive(Debug)]
enum Reach {
    Answered { hostings: i64, ms: u128 },
    Failed(String),
}

/// GET /install/node-facts?node_id=… — the live half of a node row: does
/// the agent answer, how many sites it carries, and whether system updates
/// are waiting. Lazy per row for the same reason as the OS-updates panel:
/// one slow or dead node must not hold up the page.
///
/// Both questions go to the node at once. The update status is the cached
/// one (`OsUpdatesStatus`), never a fresh `apt-get update`.
pub async fn get_node_facts(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<UpdateNodeStatusQuery>,
) -> Response {
    let html = |status: axum::http::StatusCode, body: String| {
        (status, [("content-type", "text/html; charset=utf-8")], body).into_response()
    };
    if !ctx.is_super_admin() {
        return html(
            axum::http::StatusCode::FORBIDDEN,
            "<span class=\"pill err\">admin only</span>".into(),
        );
    }
    let node_id = match q.node_id.trim() {
        "" => "local",
        id => id,
    };
    if !node_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return html(
            axum::http::StatusCode::BAD_REQUEST,
            "<span class=\"pill err\">invalid node id</span>".into(),
        );
    }
    let target = (node_id != "local").then_some(node_id);
    let probe = async {
        let started = std::time::Instant::now();
        let r = crate::dispatcher::dispatch_to_node(&state, target, Request::AgentInfo).await;
        (r, started.elapsed().as_millis())
    };
    let os = crate::dispatcher::dispatch_to_node(&state, target, Request::OsUpdatesStatus);
    let ((info, ms), os) = tokio::join!(probe, os);
    let reach = match info {
        Ok(RpcResponse::AgentInfo(i)) => Reach::Answered {
            hostings: i.hostings_count,
            ms,
        },
        Ok(RpcResponse::Error(e)) => Reach::Failed(format!("agent error: {e}")),
        Ok(_) => Reach::Failed("unexpected response".into()),
        Err(e) => Reach::Failed(e.to_string()),
    };
    // An agent older than the OS-updates RPC answers 400; that row simply
    // has no update facts, the same as one that could not be read.
    let os = match os {
        Ok(RpcResponse::OsUpdates(s)) => Some(s),
        _ => None,
    };
    html(
        axum::http::StatusCode::OK,
        render_node_facts(&reach, os.as_ref()),
    )
}

/// Row facts as HTML. Figures stay grey; only state that needs action takes
/// colour (not answering, updates pending, security, reboot).
fn render_node_facts(reach: &Reach, os: Option<&hyperion_types::OsUpdateStatus>) -> String {
    let (hostings, ms) = match reach {
        Reach::Failed(e) => {
            return format!(
                "<span class=\"pill err\" title=\"{}\">not answering</span>",
                html_escape(e)
            );
        }
        Reach::Answered { hostings, ms } => (*hostings, *ms),
    };
    let mut out = format!(
        "<span class=\"node-fact\">{hostings} site{}</span>\
         <span class=\"node-fact\" title=\"Round trip of a signed call to the agent\">{ms} ms</span>",
        if hostings == 1 { "" } else { "s" }
    );
    if let Some(s) = os {
        if !s.was_checked() {
            out.push_str("<span class=\"node-fact\">updates not checked</span>");
        } else if s.pending.is_empty() {
            out.push_str("<span class=\"node-fact\">up to date</span>");
        } else {
            let n = s.pending.len();
            out.push_str(&format!(
                "<span class=\"pill warn\">{n} update{}</span>",
                if n == 1 { "" } else { "s" }
            ));
            if s.security_count > 0 {
                out.push_str(&format!(
                    "<span class=\"pill err\">{} security</span>",
                    s.security_count
                ));
            }
        }
        if s.reboot_required {
            out.push_str("<span class=\"pill warn\">reboot required</span>");
        }
    }
    out
}

/// POST /install/os-updates-check — refresh the node's package index and
/// re-read what is pending. Read-only on the node: nothing is installed.
///
/// Inline rather than a background job. It is `apt-get update` — seconds, a
/// minute on a slow mirror — and the result is persisted on the node, so a
/// dropped connection loses nothing: the next page load shows it.
pub async fn post_os_updates_check(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<TestNodeForm>,
) -> Response {
    os_updates_fragment(
        &state,
        &ctx,
        &form.node_id,
        Request::OsUpdatesCheck { refresh: true },
    )
    .await
}

async fn os_updates_fragment(
    state: &SharedState,
    ctx: &AuthCtx,
    node_id: &str,
    req: Request,
) -> Response {
    let html = |status: axum::http::StatusCode, body: String| {
        (status, [("content-type", "text/html; charset=utf-8")], body).into_response()
    };
    if !ctx.is_super_admin() {
        return html(
            axum::http::StatusCode::FORBIDDEN,
            "<span class=\"pill err\">admin only</span>".into(),
        );
    }
    let node_id = match node_id.trim() {
        "" => "local",
        id => id,
    };
    if !node_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return html(
            axum::http::StatusCode::BAD_REQUEST,
            "<span class=\"pill err\">invalid node id</span>".into(),
        );
    }
    let target = (node_id != "local").then_some(node_id);
    let body = match crate::dispatcher::dispatch_to_node(state, target, req).await {
        Ok(RpcResponse::OsUpdates(s)) => {
            render_os_updates(node_id, &s, &super::session_csrf_token(state, ctx))
        }
        Ok(RpcResponse::Error(e)) => format!(
            "<span class=\"text-soft small\">Could not read update status: {}</span>",
            html_escape(&e.to_string())
        ),
        Ok(_) => "<span class=\"text-soft small\">unexpected response</span>".to_string(),
        // An agent older than this panel cannot decode the request and answers
        // HTTP 400, which curl reports as exit 22. That is not a connectivity
        // problem, and the Test button on the same card would say so — show
        // the actual reason instead of "unreachable".
        Err(crate::dispatcher::DispatchError::Remote(
            hyperion_rpc_client::RemoteClientError::HttpError {
                code: Some(22),
                stderr,
            },
        )) if stderr.contains("400") => "<span class=\"text-soft small\">This node runs an older \
             Hyperion that does not report operating-system updates yet. Update Hyperion on it \
             to see them.</span>"
            .to_string(),
        Err(e) => format!(
            "<span class=\"text-soft small\">unreachable: {}</span>",
            html_escape(&e.to_string())
        ),
    };
    html(axum::http::StatusCode::OK, body)
}

/// Render a node's OS update status.
///
/// The rule it keeps: a count is only as good as the index it was read from,
/// so "no updates" is never shown without how old that index is, and a node
/// never checked says so instead of looking up to date.
fn render_os_updates(node_id: &str, s: &hyperion_types::OsUpdateStatus, csrf: &str) -> String {
    use crate::handlers::stats::fmt_ago;
    let id = html_escape(node_id);
    let mut pills = String::new();
    if !s.was_checked() {
        pills.push_str("<span class=\"pill\">not checked yet</span>");
    } else if s.pending.is_empty() {
        pills.push_str("<span class=\"pill ok\">no updates pending</span>");
    } else {
        let n = s.pending.len();
        pills.push_str(&format!(
            "<span class=\"pill warn\">{n} update{} pending</span>",
            if n == 1 { "" } else { "s" }
        ));
        if s.security_count > 0 {
            pills.push_str(&format!(
                " <span class=\"pill err\" title=\"From the distribution's security suite\">{} security</span>",
                s.security_count
            ));
        }
    }
    if s.reboot_required {
        let title = if s.reboot_packages.is_empty() {
            "The system marked a reboot as required".to_string()
        } else {
            format!("Requested by: {}", s.reboot_packages.join(", "))
        };
        pills.push_str(&format!(
            " <span class=\"pill warn\" title=\"{}\">reboot required</span>",
            html_escape(&title)
        ));
    }
    let index_age = if s.index_refreshed_at > 0 {
        format!("package index refreshed {}", fmt_ago(&s.index_refreshed_at))
    } else {
        "package index never refreshed by Hyperion".to_string()
    };
    let checked = if s.was_checked() {
        format!(" · checked {}", fmt_ago(&s.checked_at))
    } else {
        String::new()
    };
    let mut out = format!(
        "<div style=\"display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap\">\
            {pills}\
            <span class=\"text-soft small\">{index_age}{checked}</span>\
            <form hx-post=\"/install/os-updates-check\" hx-target=\"#os-upd-{id}\" \
                  hx-swap=\"innerHTML\" hx-disabled-elt=\"find button\" \
                  hx-indicator=\"#os-upd-spin-{id}\" style=\"display:contents\">\
              <input type=\"hidden\" name=\"_csrf\" value=\"{csrf}\">\
              <input type=\"hidden\" name=\"node_id\" value=\"{id}\">\
              <button type=\"submit\" class=\"btn small ghost\" \
                      title=\"Runs apt-get update on the node and re-reads the list. Installs nothing.\">Check now</button>\
            </form>\
            <span id=\"os-upd-spin-{id}\" class=\"htmx-indicator text-soft small\">refreshing the package index…</span>\
         </div>",
        csrf = html_escape(csrf),
    );
    if !s.error.is_empty() {
        out.push_str(&format!(
            "<p class=\"small\" style=\"margin:0.4rem 0 0;color:var(--warn)\">{}</p>",
            html_escape(&s.error)
        ));
    }
    if !s.pending.is_empty() {
        // Security first, then by name — the ones that matter at the top.
        let mut pkgs: Vec<&hyperion_types::OsPendingPackage> = s.pending.iter().collect();
        pkgs.sort_by(|a, b| b.security.cmp(&a.security).then(a.name.cmp(&b.name)));
        out.push_str(&format!(
            "<details style=\"margin-top:0.5rem\"><summary class=\"text-soft small\" style=\"cursor:pointer\">\
             Show {} package{}</summary>\
             <div style=\"max-height:16rem;overflow:auto;margin-top:0.4rem\"><table class=\"table small\">\
             <thead><tr><th>Package</th><th>Installed</th><th>Available</th><th></th></tr></thead><tbody>",
            pkgs.len(),
            if pkgs.len() == 1 { "" } else { "s" }
        ));
        for p in pkgs {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td class=\"muted\">{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&p.name),
                html_escape(&p.installed),
                html_escape(&p.candidate),
                if p.security {
                    "<span class=\"pill err\">security</span>"
                } else {
                    ""
                }
            ));
        }
        out.push_str("</tbody></table></div></details>");
        // The master's update form offers system packages only; a worker's
        // has the System packages / Hyperion choice.
        out.push_str(if node_id == "local" {
            "<p class=\"text-soft small\" style=\"margin:0.4rem 0 0\">\
             To install them, use <strong>Install system updates</strong> below. \
             Services on this server may restart briefly while it runs.</p>"
        } else {
            "<p class=\"text-soft small\" style=\"margin:0.4rem 0 0\">\
             To install them, use <strong>Update</strong> below with <strong>System packages</strong> ticked. \
             Services on the node may restart briefly while it runs.</p>"
        });
    }
    out
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b' ' => "+".to_string(),
            b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b if b.is_ascii_alphanumeric() => (b as char).to_string(),
            b => format!("%{:02X}", b),
        })
        .collect()
}

/// POST /install/test-node — super_admin only.
///
/// Master-side connectivity probe to a remote node. Replaces the
/// "ssh in + curl :9443 + check ss -tlnp" debug ritual: master
/// dispatches an `AgentInfo` over the signed-RPC channel and
/// reports back what happened. Operator gets one of:
///   - ✓ reachable (with agent version + hosting count for sanity)
///   - ✗ no public_ip on record
///   - ✗ remote-RPC signer not loaded
///   - ✗ connection failed (curl message verbatim)
///   - ✗ auth failed (pubkey not yet propagated; wait a heartbeat)
///
/// Returned as HTML fragment so the page can swap it inline via
/// HTMX without reloading.
#[derive(Deserialize)]
pub struct TestNodeForm {
    node_id: String,
}

/// POST /install/toggle-test-node — flip a node's test-vs-prod
/// status by editing the cluster.test_node_ids CSV in agent.toml.
/// Calls AgentConfigUpdate which writes the file atomically (with
/// .bak backup) and keeps comments. The running agent picks up the
/// new value on its next periodic refresh; the wizard's
/// `is_test_node` checks against this CSV via
/// `fetch_cluster_test_node_ids` so the change is visible after a
/// page reload even without an agent restart.
pub async fn post_toggle_test_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<TestNodeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/install?flash_error=Owner+role+required").into_response());
    }
    let node_id = form.node_id.trim();
    if node_id.is_empty() {
        return Ok(Redirect::to("/install?flash_error=missing+node_id").into_response());
    }
    // Reject anything that isn't a sane node ID — the CSV gets
    // written straight into agent.toml so we don't want to allow
    // commas / quotes / shell metachars even if the agent config
    // writer would later catch them.
    if !node_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Ok(Redirect::to(&format!(
            "/install?flash_error={}",
            urlencode("invalid characters in node_id")
        ))
        .into_response());
    }
    // Read current CSV, toggle membership, persist via
    // AgentConfigUpdate. We deliberately re-read on every request
    // (rather than caching) so two operators flipping toggles
    // concurrently don't clobber each other — last write wins on
    // the agent.toml level, which is the documented contract.
    let current_csv = fetch_cluster_test_node_ids(&state).await;
    let mut ids: Vec<String> = current_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let already_test = ids.iter().any(|s| s == node_id);
    if already_test {
        ids.retain(|s| s != node_id);
    } else {
        ids.push(node_id.to_string());
    }
    // Keep deterministic ordering so the CSV in agent.toml doesn't
    // shuffle on every toggle (operator-friendly diffs).
    ids.sort();
    let new_csv = ids.join(",");
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("test_node_ids".to_string(), new_csv.clone());
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AgentConfigUpdate {
            section: "cluster".to_string(),
            fields: fields.into(),
        },
    )
    .await?;
    match resp {
        RpcResponse::AgentConfigUpdate => {
            let action = if already_test { "unmarked" } else { "marked" };
            let msg = format!(
                "{node_id} {action} as test node. Restart hyperion-agent on this master \
                 (Service health → Restart) for the wizard's domain-validation to fully pick up \
                 the change."
            );
            Ok(Redirect::to(&format!(
                "/install?flash={}#node-{}",
                urlencode(&msg),
                urlencode(node_id)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/install?flash_error={}",
            urlencode(&format!("AgentConfigUpdate failed: {e}"))
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_test_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<TestNodeForm>,
) -> Response {
    if !ctx.is_super_admin() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<span class=\"pill err\">admin role required</span>",
        )
            .into_response();
    }
    let node_id = form.node_id.trim();
    if node_id.is_empty() {
        return html_pill_err("missing node_id");
    }
    let started = std::time::Instant::now();
    let result =
        crate::dispatcher::dispatch_to_node(&state, Some(node_id), Request::AgentInfo).await;
    let elapsed_ms = started.elapsed().as_millis();
    match result {
        Ok(RpcResponse::AgentInfo(info)) => html_pill_ok(&format!(
            "reachable · {} · {} hostings · {} ms",
            info.version, info.hostings_count, elapsed_ms
        )),
        Ok(RpcResponse::Error(e)) => html_pill_err(&format!("agent error: {e}")),
        Ok(_) => html_pill_err("unexpected response"),
        Err(e) => html_pill_err(&e.to_string()),
    }
}

fn html_pill_ok(msg: &str) -> Response {
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        format!(
            "<span class=\"pill ok\" title=\"{}\">✓ {}</span>",
            html_escape(msg),
            html_escape(msg)
        ),
    )
        .into_response()
}

fn html_pill_err(msg: &str) -> Response {
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        format!(
            "<span class=\"pill err\" title=\"{}\">✗ {}</span>",
            html_escape(msg),
            html_escape(msg)
        ),
    )
        .into_response()
}

/// Minimal HTML-attribute escape sufficient for the pill above.
/// (askama would be overkill for a single-fragment response.)
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn fetch_invites(state: &SharedState) -> Result<Vec<NodeInviteSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::InviteList).await?;
    match resp {
        RpcResponse::InviteList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_nodes(state: &SharedState) -> Result<Vec<NodeSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await?;
    match resp {
        RpcResponse::NodesList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// derive_master_url lives in handlers::mod — see there for the
// loopback-detection logic and the public-IP fallback rationale.
use super::derive_master_url;

fn csrf_token(state: &SharedState, ctx: &AuthCtx, form_id: &str) -> String {
    let sid = ctx
        .session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default();
    hyperion_auth::csrf::mint(
        state.csrf_key.as_ref(),
        &sid,
        form_id,
        hyperion_types::now_secs(),
    )
}

async fn render_with_error(
    state: &SharedState,
    ctx: &AuthCtx,
    headers: &HeaderMap,
    message: &str,
) -> Response {
    Html(
        render_page(state, ctx, headers, None, Some(message.to_string()))
            .await
            .unwrap_or_else(|_| "<h1>render error</h1>".into()),
    )
    .into_response()
}

/// Read `cluster.test_node_ids` from the agent's view of agent.toml.
/// Returns the raw CSV string ("stav,worker2") or empty on RPC
/// failure / config absence.
async fn fetch_cluster_test_node_ids(state: &SharedState) -> String {
    match hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView).await {
        Ok(RpcResponse::AgentConfigView(c)) => c.cluster.test_node_ids,
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::{OsPendingPackage, OsUpdateStatus};

    fn pkg(name: &str, security: bool) -> OsPendingPackage {
        OsPendingPackage {
            name: name.into(),
            installed: "1.0".into(),
            candidate: "1.1".into(),
            security,
        }
    }

    fn worker(id: &str, last_seen_at: i64, version: &str) -> NodeSummary {
        NodeSummary {
            node_id: id.into(),
            label: format!("{id}.example"),
            master_url: None,
            agent_version: version.into(),
            public_ip: Some("192.0.2.10".into()),
            enrolled_at: 1,
            last_seen_at,
            is_drained: false,
            drain_reason: String::new(),
            tls_spki_pin: Some("pin".into()),
            resp_pubkey: Some("key".into()),
        }
    }

    fn master_info(version: &str) -> AgentInfo {
        AgentInfo {
            hostname: "s4".into(),
            version: version.into(),
            schema_version: 1,
            hostings_count: 3,
            node_id: None,
            master_url: None,
            enrolled_at: None,
            public_ipv4: Some("198.51.100.4".into()),
        }
    }

    #[test]
    fn the_master_is_the_first_row_and_never_has_problems() {
        let now = hyperion_types::now_secs();
        let rows = build_rows(
            Some(&master_info("v1")),
            vec![worker("w1", now, "v1")],
            "",
            now,
        );
        assert_eq!(rows.len(), 2);
        assert!(rows[0].is_master);
        assert_eq!(
            rows[0].n.node_id, "local",
            "dispatcher's name for the master"
        );
        assert_eq!(rows[0].n.label, "s4");
        assert_eq!(rows[0].n.public_ip.as_deref(), Some("198.51.100.4"));
        assert!(rows[0].online && rows[0].issues.is_empty());
        assert!(
            rows[1].online && rows[1].issues.is_empty(),
            "{:?}",
            rows[1].issues
        );

        // No AgentInfo: the master still has a row, just without facts.
        let rows = build_rows(None, vec![], "", now);
        assert_eq!(rows[0].n.label, "This server");
    }

    #[test]
    fn a_stale_heartbeat_is_the_worst_problem_and_leads_the_verdict() {
        let now = hyperion_types::now_secs();
        let mut quiet = worker("w2", now - 3600, "v1");
        quiet.tls_spki_pin = None;
        let rows = build_rows(
            Some(&master_info("v1")),
            vec![worker("w1", now - 10, "v1"), quiet],
            "",
            now,
        );
        assert!(rows[1].online);
        assert!(!rows[2].online);
        assert_eq!(rows[2].tone(), "err");
        assert!(
            rows[2].issues[0].1.starts_with("no heartbeat since"),
            "{:?}",
            rows[2].issues
        );
        assert_eq!(rows[2].issues[1].1, "no TLS pin on file");
        let v = build_verdict(&rows);
        assert_eq!(v.tone, "err");
        assert!(
            v.text.starts_with("w2.example: no heartbeat since"),
            "{}",
            v.text
        );
        assert!(
            v.text.ends_with(", no TLS pin on file"),
            "a node is named once, its problems joined: {}",
            v.text
        );
    }

    #[test]
    fn version_skew_needs_both_versions_known() {
        let now = hyperion_types::now_secs();
        let nodes = vec![
            worker("a", now, "v2"),
            worker("b", now, ""),
            worker("c", now, "v1"),
        ];
        let rows = build_rows(Some(&master_info("v1")), nodes.clone(), "", now);
        assert!(rows[1].version_skew);
        assert_eq!(rows[1].tone(), "warn");
        assert!(!rows[2].version_skew, "empty worker version is not skew");
        assert!(!rows[3].version_skew);
        let rows = build_rows(None, nodes, "", now);
        assert!(
            rows.iter().all(|r| !r.version_skew),
            "unknown master version flags nobody"
        );
    }

    #[test]
    fn test_flag_comes_from_the_csv_and_is_not_a_problem() {
        let now = hyperion_types::now_secs();
        let rows = build_rows(
            Some(&master_info("v1")),
            vec![worker("a", now, "v1"), worker("b", now, "v1")],
            " b , x",
            now,
        );
        assert!(!rows[1].is_test);
        assert!(rows[2].is_test);
        assert!(rows[2].issues.is_empty());
    }

    #[test]
    fn verdict_wording_by_cluster_size() {
        let now = hyperion_types::now_secs();
        let alone = build_rows(Some(&master_info("v1")), vec![], "", now);
        assert_eq!(build_verdict(&alone).tone, "");
        assert!(build_verdict(&alone).text.starts_with("Only this server"));
        let one = build_rows(
            Some(&master_info("v1")),
            vec![worker("a", now, "v1")],
            "",
            now,
        );
        assert_eq!(build_verdict(&one).tone, "ok");
        let many: Vec<NodeSummary> = (0..5).map(|i| worker(&format!("n{i}"), 0, "v1")).collect();
        let rows = build_rows(Some(&master_info("v1")), many, "", now);
        let v = build_verdict(&rows);
        assert!(v.text.ends_with("· +2 more"), "{}", v.text);
    }

    #[test]
    fn row_facts_show_reach_sites_and_updates() {
        let ok = Reach::Answered {
            hostings: 1,
            ms: 42,
        };
        let html = render_node_facts(&ok, None);
        assert!(html.contains("1 site<") && html.contains("42 ms"), "{html}");
        assert!(
            !html.contains("update"),
            "no OS facts from an old agent: {html}"
        );

        let html = render_node_facts(&ok, Some(&OsUpdateStatus::default()));
        assert!(html.contains("updates not checked"), "{html}");

        let checked = OsUpdateStatus {
            checked_at: 1,
            index_refreshed_at: 1,
            ..Default::default()
        };
        assert!(render_node_facts(&ok, Some(&checked)).contains("up to date"));

        let pending = OsUpdateStatus {
            checked_at: 1,
            pending: vec![pkg("openssl", true), pkg("zlib1g", false)],
            security_count: 1,
            reboot_required: true,
            ..Default::default()
        };
        let html = render_node_facts(&ok, Some(&pending));
        assert!(
            html.contains("2 updates") && html.contains("1 security"),
            "{html}"
        );
        assert!(html.contains("reboot required"), "{html}");

        let html = render_node_facts(&Reach::Failed("<curl> 7".into()), Some(&pending));
        assert!(html.contains("not answering"), "{html}");
        assert!(html.contains("&lt;curl&gt;"), "error is escaped: {html}");
        assert!(
            !html.contains("updates"),
            "a dead node shows nothing else: {html}"
        );
    }

    #[test]
    fn a_node_never_checked_is_not_shown_as_up_to_date() {
        let html = render_os_updates("s4", &OsUpdateStatus::default(), "tok");
        assert!(html.contains("not checked yet"), "{html}");
        assert!(!html.contains("no updates pending"), "{html}");
        assert!(html.contains("never refreshed"), "{html}");
    }

    #[test]
    fn pending_updates_render_escaped_with_security_first() {
        let status = OsUpdateStatus {
            checked_at: 1,
            index_refreshed_at: 1,
            pending: vec![
                pkg("zlib1g", false),
                pkg("<script>x", false),
                pkg("openssl", true),
            ],
            security_count: 1,
            reboot_required: true,
            reboot_packages: vec!["kernel 6.1.0-26-amd64 (running 6.1.0-25-amd64)".into()],
            ..Default::default()
        };
        let html = render_os_updates("worker-1.example", &status, "tok\"x");
        assert!(html.contains("3 updates pending"), "{html}");
        assert!(html.contains("1 security"), "{html}");
        assert!(html.contains("reboot required"), "{html}");
        assert!(
            !html.contains("<script>x"),
            "package names are escaped: {html}"
        );
        assert!(html.contains("&lt;script&gt;x"), "{html}");
        assert!(
            !html.contains("tok\"x"),
            "the token is escaped in its attribute"
        );
        let openssl = html.find("<code>openssl</code>").expect("openssl row");
        let zlib = html.find("<code>zlib1g</code>").expect("zlib row");
        assert!(openssl < zlib, "security updates are listed first");
        assert!(
            html.contains("use <strong>Update</strong>"),
            "a node points at its Update pane"
        );

        let master = render_os_updates("local", &status, "tok");
        assert!(
            master.contains("use <strong>Install system updates</strong>"),
            "the master has no Update pane, so it points at its own form: {master}"
        );
    }
}
