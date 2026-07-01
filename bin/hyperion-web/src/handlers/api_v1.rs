//! `/api/v1` — the Bearer-authenticated remote management API.
//!
//! A SEPARATE router branch from the cookie UI: no session `require_auth`
//! and no `check_csrf` (API keys are not cookies, so there's no CSRF and
//! no ambient-authority risk). Authentication is the
//! `Authorization: Bearer hyp_…` header, resolved by the auth extractor
//! into an [`AuthCtx`] carrying the key's owner-clamped caps/scope_all.
//! The SAME `ctx.can(cap)` gates the UI uses apply here verbatim.
//!
//! This slice ships the READ + key-identity endpoints only:
//!   * `GET /api/v1/me`            — the key's label + caps + scope_all
//!   * `GET /api/v1/hostings`      — cap HostingView
//!   * `GET /api/v1/hostings/:id`  — cap HostingView
//!   * `GET /api/v1/nodes`         — cap NodesView
//!   * `GET /api/v1/jobs/:id`      — any valid key (job polling)
//!
//! JSON shapes are the existing serde types serialized directly — no
//! parallel DTOs. Errors use the envelope `{"error":{"code","message"}}`
//! with the correct status (401 / 403 / 404).
//!
//! See `docs/superpowers/specs/2026-06-30-remote-management-api-design.md`.

use crate::auth::AuthCtx;
use crate::state::SharedState;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::{request::Parts, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use serde_json::json;

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
        if ctx.is_api_key() {
            Ok(ApiAuth(ctx))
        } else {
            Err(unauthorized())
        }
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

/// `GET /api/v1/hostings` — list. Cap HostingView.
pub async fn get_hostings(State(state): State<SharedState>, ApiAuth(ctx): ApiAuth) -> Response {
    if let Some(r) = require(&ctx, Capability::HostingView) {
        return r;
    }
    // Reuse the exact aggregation the /hostings page uses (master +
    // fan-out across enrolled nodes, node_id normalised).
    match crate::handlers::hostings::list_hostings(&state).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => upstream(&e),
    }
    // TODO(api-p1b): tenant scoping. For non-scope_all keys this should
    // filter to the owner's `web_user_hosting_access` grants, matching
    // the UI. P1 ships admin-minted keys (scope_all), so the unfiltered
    // list is correct for them; narrow this when per-owner scoping lands.
}

/// `GET /api/v1/hostings/:id` — detail. Cap HostingView.
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

/// `GET /api/v1/jobs/:id` — background job poll. Any valid key.
pub async fn get_job(
    State(state): State<SharedState>,
    ApiAuth(_ctx): ApiAuth,
    Path(id): Path<String>,
) -> Response {
    match hyperion_rpc_client::call(&state.agent_socket, Request::JobGet { id }).await {
        Ok(RpcResponse::JobGet(Some(j))) => Json(j).into_response(),
        Ok(RpcResponse::JobGet(None)) => not_found("no such job"),
        Ok(RpcResponse::Error(e)) => upstream(&e.to_string()),
        Ok(_) => upstream("unexpected agent response"),
        Err(e) => upstream(&e.to_string()),
    }
}

// TODO(api-p1b): write / lifecycle endpoints from the spec's Phase-1
// table — these mutate, so they additionally gate on the write caps and
// (for create/delete) return 202 { job_id } + are audited as
// actor="apikey:<label>". They slot in here as new handlers + routes:
//   * POST   /api/v1/hostings                  HostingCreate   → 202 {job_id}
//   * DELETE /api/v1/hostings/:id              HostingDelete   → 202 {job_id}
//   * POST   /api/v1/hostings/:id/suspend      HostingSuspend
//   * POST   /api/v1/hostings/:id/resume       HostingSuspend
// Reuse the existing hosting_create / hosting_delete / suspend / resume
// RPCs the UI handlers already call (no new async model).
