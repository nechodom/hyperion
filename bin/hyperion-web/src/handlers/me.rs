//! Tiny "who am I" endpoint(s).
//!
//! Used by base.html's nav-hiding JS shim — it reads the role and
//! removes sidebar links the current user can't use, so the user
//! never gets a 403 from clicking a nav item.
//!
//! The session cookie is signed + opaque, so JS can't introspect
//! it client-side. A no-side-effects GET like this is the
//! cheapest substitute. The response is plain text, not JSON, so
//! `.then(r => r.text())` is enough.

use crate::auth::AuthCtx;
use crate::state::SharedState;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use hyperion_state::capabilities::Capability;

/// GET /api/me/role — returns the current session's role, effective
/// capabilities, and scope as JSON. Drives base.html's nav-visibility shim
/// so the sidebar + action buttons reflect EXACTLY what the user can do —
/// including custom roles, which a role-name hierarchy can't represent.
///
/// Shape: `{"role":"operator","caps":[…],"scope_all":false,"mode":"standalone"}`.
/// `mode` is the deployment role of the box (standalone vs master); the shim
/// uses it to drop cluster-only chrome on a one-server install.
///
/// Always 200 — the require_auth middleware would have redirected already if
/// there was no session.
///
/// Cache: `no-store` because role/caps can change (promote/demote, role edit),
/// and we'd rather pay the round-trip than render a stale nav after a change.
pub async fn get_role(State(state): State<SharedState>, ctx: AuthCtx) -> Response {
    let caps: Vec<&'static str> = Capability::ALL
        .iter()
        .filter(|c| ctx.can(**c))
        .map(|c| c.as_str())
        .collect();
    // Read from the cache the 30 s poller maintains, so this stays a
    // zero-RPC endpoint. Presentation only — it says what is worth drawing,
    // never what is permitted.
    let mode = state.deployment_mode.read().await.clone();
    let body = serde_json::json!({
        "role": ctx.role(),
        "caps": caps,
        "scope_all": ctx.scope_all(),
        "mode": mode,
    })
    .to_string();
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}
