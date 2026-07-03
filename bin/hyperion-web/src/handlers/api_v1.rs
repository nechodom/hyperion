//! `/api/v1` — the Bearer-authenticated remote management API.
//!
//! A SEPARATE router branch from the cookie UI: no session `require_auth`
//! and no `check_csrf` (API keys are not cookies, so there's no CSRF and
//! no ambient-authority risk). Authentication is the
//! `Authorization: Bearer hyp_…` header, resolved by the auth extractor
//! into an [`AuthCtx`] carrying the key's owner-clamped caps/scope_all.
//! The SAME `ctx.can(cap)` gates the UI uses apply here verbatim.
//!
//! Read + key-identity:
//!   * `GET /api/v1/me`                    — the key's label + caps + scope_all
//!   * `GET /api/v1/hostings`              — cap HostingView
//!   * `GET /api/v1/hostings/:id`          — cap HostingView
//!   * `GET /api/v1/nodes`                 — cap NodesView
//!   * `GET /api/v1/jobs/:id`              — cluster-scoped (scope_all) key
//! Write / lifecycle (p1b) — per-hosting manage access enforced:
//!   * `POST   /api/v1/hostings/:id/suspend` — cap HostingSuspend, sync
//!   * `POST   /api/v1/hostings/:id/resume`  — cap HostingSuspend, sync
//!   * `DELETE /api/v1/hostings/:id`         — cap HostingDelete → 202 {job_id}
//!
//! JSON shapes are the existing serde types serialized directly — no
//! parallel DTOs. Errors use the envelope `{"error":{"code","message"}}`
//! with the correct status (401 / 403 / 404).
//!
//! See `docs/superpowers/specs/2026-06-30-remote-management-api-design.md`.

use crate::auth::AuthCtx;
use crate::ratelimit::Bucket;
use crate::state::SharedState;
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::{request::Parts, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::{DeleteOpts, HostingSelector};
use hyperion_state::capabilities::Capability;
use serde::Deserialize;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};

/// JSON error envelope `{"error":{"code","message"}}` + an HTTP status.
fn err(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

/// 401 — no/invalid/expired/revoked key.
fn unauthorized() -> Response {
    err(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing or invalid API key",
    )
}

/// 403 — valid key, but it lacks the required capability.
fn forbidden(cap: Capability) -> Response {
    err(
        StatusCode::FORBIDDEN,
        "forbidden",
        &format!("API key lacks capability '{}'", cap.as_str()),
    )
}

/// 404 — known-but-missing resource.
fn not_found(what: &str) -> Response {
    err(StatusCode::NOT_FOUND, "not_found", what)
}

/// 502/500 — agent RPC failure surfaced as JSON (addresses redacted at
/// the RPC layer; messages here are generic).
fn upstream(message: &str) -> Response {
    err(StatusCode::BAD_GATEWAY, "upstream_error", message)
}

/// 409 — the request conflicts with existing state (e.g. create for a
/// domain that already exists). Used by the write endpoints (Slice B).
#[allow(dead_code)]
fn conflict(message: &str) -> Response {
    err(StatusCode::CONFLICT, "conflict", message)
}

/// 429 — per-key rate limit exceeded, with a `Retry-After` hint.
fn rate_limited() -> Response {
    let mut r = err(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "rate limit exceeded for this API key",
    );
    r.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("60"),
    );
    r
}

/// The client's effective source IP for allowlist matching. hyperion-web
/// normally sits behind nginx, so the connection peer is the proxy — the
/// real client arrives in `X-Forwarded-For` (first hop) / `X-Real-IP`.
/// Mirrors the enroll/heartbeat rate-limit bucketing so an allowlist means
/// the same address in both places. Falls back to the connection peer.
fn client_ip(parts: &Parts) -> Option<IpAddr> {
    if let Some(v) = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = v.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    if let Some(v) = parts.headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = v.trim().parse::<IpAddr>() {
            return Some(ip);
        }
    }
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// True iff `ip` falls within the CIDR (or bare IP) `entry`. A bare
/// address is treated as a host route (`/32` · `/128`). A malformed
/// entry matches nothing — a bad allowlist row can't silently widen access.
fn cidr_contains(entry: &str, ip: IpAddr) -> bool {
    let entry = entry.trim();
    if let Ok(net) = entry.parse::<ipnet::IpNet>() {
        return net.contains(&ip);
    }
    if let Ok(single) = entry.parse::<IpAddr>() {
        return single == ip;
    }
    false
}

/// Extractor that REQUIRES a valid Bearer API key. Builds on the shared
/// [`AuthCtx`] extractor; if the request carried no valid API key it
/// rejects with a 401 JSON envelope (vs the UI's redirect-to-login).
pub struct ApiAuth(pub AuthCtx);

#[async_trait::async_trait]
impl FromRequestParts<SharedState> for ApiAuth {
    type Rejection = Response;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let ctx = AuthCtx::from_request_parts(parts, state)
            .await
            .map_err(|_| unauthorized())?;
        let Some(k) = ctx.api_key.as_ref() else {
            return Err(unauthorized());
        };
        // Per-key hardening (both properties of the key, not owner-clamped).
        let peer_ip = client_ip(parts);
        // IP allowlist (empty = allow any). With an allowlist set but no peer
        // info available, fail closed rather than wave the request through.
        if !k.ip_allowlist.is_empty() {
            let allowed =
                peer_ip.is_some_and(|ip| k.ip_allowlist.iter().any(|c| cidr_contains(c, ip)));
            if !allowed {
                return Err(err(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "source IP not allowed for this API key",
                ));
            }
        }
        // Rate limit (0 = unlimited), bucketed by key id.
        if k.rate_limit_per_min > 0 {
            let cap = k.rate_limit_per_min.min(u32::MAX as i64) as u32;
            if !state.ratelimit.check_key(k.id, Bucket::per_minute(cap)) {
                return Err(rate_limited());
            }
        }
        Ok(ApiAuth(ctx))
    }
}

/// Gate a handler on a capability. Returns `None` when the key holds
/// `cap`; otherwise `Some(403 JSON envelope)` for the caller to return.
/// (Returns `Option` rather than `Result` to avoid carrying a large
/// `Response` in an error variant — clippy::result_large_err.)
fn require(ctx: &AuthCtx, cap: Capability) -> Option<Response> {
    if ctx.can(cap) {
        None
    } else {
        Some(forbidden(cap))
    }
}

/// `GET /api/v1/me` — the key's identity. Any valid key.
#[utoipa::path(
    get, path = "/api/v1/me", tag = "identity",
    responses((status = 200, description = "The key's identity: id, label, caps[], scope_all")),
    security(("bearer" = []))
)]
pub async fn get_me(ApiAuth(ctx): ApiAuth) -> Response {
    // Always present here: ApiAuth guarantees an api_key.
    let Some(k) = ctx.api_key.as_ref() else {
        return unauthorized();
    };
    let caps: Vec<&'static str> = Capability::ALL
        .iter()
        .filter(|c| ctx.can(**c))
        .map(|c| c.as_str())
        .collect();
    Json(json!({
        "id": k.id,
        "label": k.label,
        "caps": caps,
        "scope_all": k.scope_all,
    }))
    .into_response()
}

/// Query knobs for `GET /api/v1/hostings` — keyset pagination + filters.
#[derive(Deserialize, Default)]
pub struct HostingsQuery {
    /// Page size, 1..200 (default 50).
    pub limit: Option<usize>,
    /// Opaque keyset cursor = the last item's id from the previous page.
    pub cursor: Option<String>,
    /// Filter by lifecycle state (`active` | `suspended` | `provisioning` | `failed`).
    pub state: Option<String>,
    /// Filter by owning node id.
    pub node: Option<String>,
    /// Case-insensitive domain substring.
    pub q: Option<String>,
}

/// `GET /api/v1/hostings` — paginated, filterable list. Cap HostingView.
///
/// Returns `{ items, next_cursor, total }`. `total` is the filtered count;
/// follow `next_cursor` (when non-null) to page. Ordering is a stable
/// keyset on id (ULIDs sort by creation time).
#[utoipa::path(
    get, path = "/api/v1/hostings", tag = "hostings",
    params(
        ("limit" = Option<usize>, Query, description = "Page size 1..200 (default 50)"),
        ("cursor" = Option<String>, Query, description = "Keyset cursor = previous page's last item id"),
        ("state" = Option<String>, Query, description = "Filter: active | suspended | provisioning | failed"),
        ("node" = Option<String>, Query, description = "Filter by owning node id"),
        ("q" = Option<String>, Query, description = "Case-insensitive domain substring"),
    ),
    responses(
        (status = 200, description = "List envelope { items: [hosting summary], next_cursor: string|null, total: int }"),
        (status = 403, description = "Key lacks the HostingView capability"),
    ),
    security(("bearer" = []))
)]
pub async fn get_hostings(
    State(state): State<SharedState>,
    ApiAuth(ctx): ApiAuth,
    Query(query): Query<HostingsQuery>,
) -> Response {
    if let Some(r) = require(&ctx, Capability::HostingView) {
        return r;
    }
    // Reuse the exact aggregation the /hostings page uses (master +
    // fan-out across enrolled nodes, node_id normalised).
    let mut rows = match crate::handlers::hostings::list_hostings(&state).await {
        Ok(rows) => rows,
        Err(e) => return upstream(&e),
    };
    // Filters.
    if let Some(st) = query
        .state
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        rows.retain(|h| h.state.as_str() == st);
    }
    if let Some(nd) = query
        .node
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        rows.retain(|h| h.node_id.as_deref() == Some(nd));
    }
    if let Some(q) = query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let ql = q.to_ascii_lowercase();
        rows.retain(|h| h.domain.to_ascii_lowercase().contains(&ql));
    }
    // Stable keyset order, then page after the cursor.
    rows.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let total = rows.len();
    if let Some(cur) = query.cursor.as_deref().filter(|s| !s.is_empty()) {
        rows.retain(|h| h.id.as_str() > cur);
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = has_more
        .then(|| rows.last().map(|h| h.id.as_str().to_string()))
        .flatten();
    Json(json!({ "items": rows, "next_cursor": next_cursor, "total": total })).into_response()
    // NOTE(api-p1b): still cluster-wide (every key is scope_all). Tenant
    // read-scoping for per-tenant keys lands with the mint-gate lift.
}

/// `GET /api/v1/hostings/:id` — detail. Cap HostingView.
#[utoipa::path(
    get, path = "/api/v1/hostings/{id}", tag = "hostings",
    params(("id" = String, Path, description = "Hosting id or domain")),
    responses(
        (status = 200, description = "Full hosting detail object"),
        (status = 403, description = "Key lacks the HostingView capability"),
        (status = 404, description = "No such hosting"),
    ),
    security(("bearer" = []))
)]
pub async fn get_hosting(
    State(state): State<SharedState>,
    ApiAuth(ctx): ApiAuth,
    Path(id): Path<String>,
) -> Response {
    if let Some(r) = require(&ctx, Capability::HostingView) {
        return r;
    }
    // Accept either a hosting id or a domain (same disambiguation the UI
    // detail route uses).
    let sel = match crate::handlers::hostings::parse_selector_public(&id) {
        Ok(s) => s,
        Err(_) => return not_found("no such hosting"),
    };
    match crate::handlers::hostings::find_hosting_anywhere(&state, sel).await {
        Ok((detail, _node)) => Json(detail).into_response(),
        Err(crate::error::AppError::NotFound) => not_found("no such hosting"),
        Err(e) => upstream(&e.to_string()),
    }
}

/// `GET /api/v1/nodes` — cluster nodes. Cap NodesView.
#[utoipa::path(
    get, path = "/api/v1/nodes", tag = "nodes",
    responses(
        (status = 200, description = "Array of enrolled cluster nodes"),
        (status = 403, description = "Key lacks the NodesView capability"),
    ),
    security(("bearer" = []))
)]
pub async fn get_nodes(State(state): State<SharedState>, ApiAuth(ctx): ApiAuth) -> Response {
    if let Some(r) = require(&ctx, Capability::NodesView) {
        return r;
    }
    match hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await {
        Ok(RpcResponse::NodesList(v)) => Json(v).into_response(),
        Ok(RpcResponse::Error(e)) => upstream(&e.to_string()),
        Ok(_) => upstream("unexpected agent response"),
        Err(e) => upstream(&e.to_string()),
    }
}

/// `GET /api/v1/jobs/:id` — background job poll. Cluster-scoped keys only.
///
/// Job records describe cluster-wide operations; the cookie UI gates every
/// `/jobs` route on admin. Mirror that: only a `scope_all` key may poll.
/// (Every P1 key is `scope_all`, so this is a no-op today; it becomes
/// "poll your OWN jobs" once per-tenant write endpoints land in p1b.)
#[utoipa::path(
    get, path = "/api/v1/jobs/{id}", tag = "jobs",
    params(("id" = String, Path, description = "Job id (from a 202 Accepted response)")),
    responses(
        (status = 200, description = "Job record: id, kind, state, progress, message, error"),
        (status = 403, description = "Job polling requires a cluster-wide (scope_all) key"),
        (status = 404, description = "No such job"),
    ),
    security(("bearer" = []))
)]
pub async fn get_job(
    State(state): State<SharedState>,
    ApiAuth(ctx): ApiAuth,
    Path(id): Path<String>,
) -> Response {
    if !ctx.scope_all() {
        return err(
            StatusCode::FORBIDDEN,
            "forbidden",
            "job polling requires a cluster-wide (scope_all) API key",
        );
    }
    match hyperion_rpc_client::call(&state.agent_socket, Request::JobGet { id }).await {
        Ok(RpcResponse::JobGet(Some(j))) => Json(j).into_response(),
        Ok(RpcResponse::JobGet(None)) => not_found("no such job"),
        Ok(RpcResponse::Error(e)) => upstream(&e.to_string()),
        Ok(_) => upstream("unexpected agent response"),
        Err(e) => upstream(&e.to_string()),
    }
}

// ─── Write / lifecycle endpoints (p1b) ──────────────────────────────────
//
// These MUTATE, so on top of the Bearer auth they enforce per-hosting
// manage access for the specific write capability, reusing the UI's own
// `require_hosting_access` gate (same rules: capability held, scope_all
// reaches every hosting, a non-scope_all key fails closed until per-key
// grants land). Delete runs as a background job → 202 { job_id }; the
// synchronous suspend/resume return the new state directly. All are
// audited as actor `apikey:<label>` via the job/RPC actor plumbing.
//
// Still TODO(api-p1b): POST /api/v1/hostings (create) — its large request
// body + node placement deserve their own slice — and tenant read-scoping
// so non-scope_all keys can finally be minted (see get_hostings).

/// Resolve `:id` (hosting id OR domain) to its detail + owning node, then
/// enforce manage access for `cap`. Mirrors the UI's
/// `require_manage_for_selector`, but returns the JSON error envelope
/// instead of an HTML 403 / redirect. On success the caller gets the
/// canonical id (for dispatch/audit) and the node the hosting lives on.
async fn resolve_manage(
    state: &SharedState,
    ctx: &AuthCtx,
    id: &str,
    cap: Capability,
) -> Result<(hyperion_types::HostingDetail, Option<String>), Response> {
    let sel = crate::handlers::hostings::parse_selector_public(id)
        .map_err(|_| not_found("no such hosting"))?;
    let (detail, node) = match crate::handlers::hostings::find_hosting_anywhere(state, sel).await {
        Ok(v) => v,
        Err(crate::error::AppError::NotFound) => return Err(not_found("no such hosting")),
        Err(e) => return Err(upstream(&e.to_string())),
    };
    // Reuse the exact per-hosting authz gate the browser UI uses; it only
    // ever fails as a 403, so swap its HTML body for our JSON envelope.
    if crate::handlers::hostings::require_hosting_access(state, ctx, detail.id.as_str(), true, cap)
        .await
        .is_err()
    {
        return Err(forbidden(cap));
    }
    Ok((detail, node))
}

/// `POST /api/v1/hostings/:id/suspend` — cap HostingSuspend. Synchronous.
#[utoipa::path(
    post, path = "/api/v1/hostings/{id}/suspend", tag = "hostings",
    params(("id" = String, Path, description = "Hosting id or domain")),
    responses(
        (status = 200, description = "Suspended — returns { id, state: \"suspended\" }"),
        (status = 403, description = "Key lacks manage access for this hosting"),
        (status = 404, description = "No such hosting"),
    ),
    security(("bearer" = []))
)]
pub async fn post_suspend(
    State(state): State<SharedState>,
    ApiAuth(ctx): ApiAuth,
    Path(id): Path<String>,
) -> Response {
    let (detail, node) = match resolve_manage(&state, &ctx, &id, Capability::HostingSuspend).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let reason = hyperion_types::SuspendReason::Manual {
        message: Some(format!("suspended via API key '{}'", ctx.username)),
    };
    let sel = HostingSelector::Id(detail.id.clone());
    match crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::HostingSuspend { sel, reason },
    )
    .await
    {
        Ok(RpcResponse::HostingSuspend) => {
            Json(json!({ "id": detail.id.as_str(), "state": "suspended" })).into_response()
        }
        Ok(RpcResponse::Error(e)) => upstream(&e.to_string()),
        Ok(_) => upstream("unexpected agent response"),
        Err(e) => upstream(&e.to_string()),
    }
}

/// `POST /api/v1/hostings/:id/resume` — cap HostingSuspend. Synchronous.
#[utoipa::path(
    post, path = "/api/v1/hostings/{id}/resume", tag = "hostings",
    params(("id" = String, Path, description = "Hosting id or domain")),
    responses(
        (status = 200, description = "Resumed — returns { id, state: \"active\" }"),
        (status = 403, description = "Key lacks manage access for this hosting"),
        (status = 404, description = "No such hosting"),
    ),
    security(("bearer" = []))
)]
pub async fn post_resume(
    State(state): State<SharedState>,
    ApiAuth(ctx): ApiAuth,
    Path(id): Path<String>,
) -> Response {
    let (detail, node) = match resolve_manage(&state, &ctx, &id, Capability::HostingSuspend).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sel = HostingSelector::Id(detail.id.clone());
    match crate::dispatcher::dispatch_to_node(&state, node.as_deref(), Request::HostingResume(sel))
        .await
    {
        Ok(RpcResponse::HostingResume) => {
            Json(json!({ "id": detail.id.as_str(), "state": "active" })).into_response()
        }
        Ok(RpcResponse::Error(e)) => upstream(&e.to_string()),
        Ok(_) => upstream("unexpected agent response"),
        Err(e) => upstream(&e.to_string()),
    }
}

/// Query knobs for `DELETE /api/v1/hostings/:id`. Both default false — a
/// bare DELETE removes the site AND its system user AND its database, the
/// same destructive default as the UI's delete form with nothing ticked.
#[derive(Deserialize, Default)]
pub struct DeleteQuery {
    #[serde(default)]
    pub keep_user: bool,
    #[serde(default)]
    pub keep_database: bool,
}

/// `DELETE /api/v1/hostings/:id` — cap HostingDelete → 202 { job_id }.
///
/// Deleting is the slowest mutation (nginx reload, acme cleanup, DROP
/// DATABASE, rm -rf, userdel), so it runs as a background job exactly like
/// the UI. Poll `GET /api/v1/jobs/:id` for completion.
#[utoipa::path(
    delete, path = "/api/v1/hostings/{id}", tag = "hostings",
    params(
        ("id" = String, Path, description = "Hosting id or domain"),
        ("keep_user" = Option<bool>, Query, description = "Keep the system user (default false)"),
        ("keep_database" = Option<bool>, Query, description = "Keep the database (default false)"),
    ),
    responses(
        (status = 202, description = "Accepted — returns { job_id, status }; poll GET /api/v1/jobs/{job_id}"),
        (status = 403, description = "Key lacks manage access for this hosting"),
        (status = 404, description = "No such hosting"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_hosting(
    State(state): State<SharedState>,
    ApiAuth(ctx): ApiAuth,
    Path(id): Path<String>,
    Query(q): Query<DeleteQuery>,
) -> Response {
    let (detail, node) = match resolve_manage(&state, &ctx, &id, Capability::HostingDelete).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let opts = DeleteOpts {
        keep_user: q.keep_user,
        keep_database: q.keep_database,
    };
    let hid = detail.id.as_str().to_string();
    let payload = json!({
        "selector": hid,
        "keep_user": opts.keep_user,
        "keep_database": opts.keep_database,
        "via": "api",
    })
    .to_string();
    let actor_label = format!("apikey:{}", ctx.username);
    let sel = HostingSelector::Id(detail.id.clone());
    let job_state = state.clone();
    let job_node = node.clone();
    let job_hid = hid.clone();
    let job_id = match crate::handlers::jobs::spawn_job(
        state.clone(),
        "hosting_delete",
        Some(&hid),
        &payload,
        &actor_label,
        0, // no session user behind an API key
        move |reporter| async move {
            reporter
                .step(
                    &format!("Deleting {job_hid} — vhost, certificate, database, files…"),
                    20,
                    "",
                )
                .await;
            let resp = crate::dispatcher::dispatch_to_node(
                &job_state,
                job_node.as_deref(),
                Request::HostingDelete { sel, opts },
            )
            .await;
            match resp {
                Ok(RpcResponse::HostingDelete) => {
                    reporter
                        .step("Hosting deleted.", 100, "✓ hosting removed")
                        .await;
                    reporter.finish(true, None).await;
                }
                Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
                Ok(_) => {
                    reporter
                        .finish(false, Some("unexpected agent response".into()))
                        .await
                }
                Err(e) => reporter.finish(false, Some(e.to_string())).await,
            }
        },
    )
    .await
    {
        Ok(id) => id,
        Err(e) => return upstream(&e.to_string()),
    };
    (
        StatusCode::ACCEPTED,
        Json(json!({ "job_id": job_id, "status": "accepted" })),
    )
        .into_response()
}
