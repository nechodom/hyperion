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
use axum::response::Response;
use axum::http::header;
use axum::response::IntoResponse;

/// GET /api/me/role — returns the current session's role as plain text.
///
/// One of: "super_admin", "admin", "operator", "viewer".
/// Always 200 — the require_auth middleware would have redirected
/// already if there was no session.
///
/// Cache: `no-store` because the role can change (user demoted /
/// promoted via /admin/users), and we'd rather pay the round-trip
/// than render a stale nav after a role change.
pub async fn get_role(ctx: AuthCtx) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        ctx.role().to_string(),
    )
        .into_response()
}
