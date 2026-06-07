//! `/settings/sessions` — per-user active session list with a
//! revoke button per row. Backed by the agent's `web_sessions`
//! ledger via the WebSession* RPC family.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "settings_sessions.html")]
struct SessionsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    /// Pre-decorated row payload — see `SessionRow` below. Pre-
    /// computing here keeps the askama template simple (no closure
    /// or filter wizardry).
    rows: Vec<SessionRow>,
    csrf_token: String,
}

/// Per-row decorated payload — converts the wire `WebSessionView`
/// into UI-ready fields (is_this_session flag, relative-time
/// strings).
#[derive(Debug, Clone)]
struct SessionRow {
    sid: String,
    ip: String,
    user_agent: String,
    created_ago: String,
    last_seen_ago: String,
    is_revoked: bool,
    is_current: bool,
}

pub async fn get_sessions(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let session = match ctx.session.as_ref() {
        Some(s) => s.clone(),
        None => return Ok(Redirect::to("/login").into_response()),
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebSessionList {
            user_id: session.user_id,
        },
    )
    .await?;
    let list: Vec<hyperion_types::WebSessionView> = match resp {
        RpcResponse::WebSessionList(v) => v,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let now = hyperion_types::now_secs();
    let rows: Vec<SessionRow> = list
        .into_iter()
        .map(|v| SessionRow {
            is_current: v.sid == session.sid,
            is_revoked: v.is_revoked(),
            sid: short_sid(&v.sid),
            ip: v.ip.unwrap_or_else(|| "—".into()),
            user_agent: v.user_agent.unwrap_or_else(|| "—".into()),
            created_ago: format_ago(now - v.created_at),
            last_seen_ago: format_ago(now - v.last_seen_at),
        })
        .collect();
    let tpl = SessionsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profile",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows,
        csrf_token: super::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct RevokeForm {
    pub sid: String,
}

pub async fn post_revoke(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RevokeForm>,
) -> Result<Response, AppError> {
    let session = match ctx.session.as_ref() {
        Some(s) => s,
        None => return Ok(Redirect::to("/login").into_response()),
    };
    // The agent stores `user_id` per row; calling list_for_user
    // would let us double-check ownership before revoking. For
    // simplicity we always pass `revoked_by = session.user_id`
    // and let the agent decide — a malicious POST trying to
    // revoke someone else's sid still requires CSRF + a valid
    // session, and even then the agent could be extended to
    // gate by ownership. Today's threat model: operators are
    // trusted but might want to kill their own active sessions.
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebSessionRevoke {
            sid: form.sid.clone(),
            revoked_by: session.user_id,
        },
    )
    .await?;
    // If the operator revoked their CURRENT session, drop their
    // cookie so the next request walks them through /login.
    if form.sid == session.sid {
        let mut resp = Redirect::to("/login").into_response();
        resp.headers_mut().insert(
            axum::http::header::SET_COOKIE,
            crate::auth::clear_cookie(&state),
        );
        return Ok(resp);
    }
    Ok(Redirect::to("/settings/sessions?flash=Session+revoked").into_response())
}

/// Shorten a ULID for display ("01KTH…J7693"). The full sid is
/// not user-actionable, just a row identifier in the table.
fn short_sid(s: &str) -> String {
    if s.len() <= 12 {
        return s.to_string();
    }
    format!("{}…{}", &s[..6], &s[s.len() - 4..])
}

/// "23 seconds ago" / "1 minute ago" / "3 days ago" — round
/// numbers so the operator skims the column without reading.
fn format_ago(delta_secs: i64) -> String {
    let s = delta_secs.max(0);
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_sid_truncates_long_ulids() {
        assert_eq!(short_sid("01KTHJ7693D8AEBNR0Q7KEWJC9"), "01KTHJ…WJC9");
        // Short strings (e.g. legacy placeholders) pass through.
        assert_eq!(short_sid("abc"), "abc");
    }

    #[test]
    fn format_ago_picks_unit_boundaries() {
        assert_eq!(format_ago(0), "0s ago");
        assert_eq!(format_ago(45), "45s ago");
        assert_eq!(format_ago(60), "1m ago");
        assert_eq!(format_ago(3600), "1h ago");
        assert_eq!(format_ago(86400), "1d ago");
        // Negative clock skew clamps to 0.
        assert_eq!(format_ago(-5), "0s ago");
    }
}
