//! `/admin/users` — multi-user management for super_admin role.
//!
//! Lists existing web users, lets a super_admin create new ones with
//! a role, change role, lock/unlock, reset password, or delete. The
//! agent's web_user_create / set_role / etc. RPC variants enforce the
//! "last super_admin" guard so admins can't lock themselves out.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{CustomRoleSummary, WebUserSummary};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "users.html")]
struct UsersTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    users: Vec<WebUserSummary>,
    /// Custom roles — listed in the change-role dropdown under a
    /// "Custom" optgroup so an owner can assign one after a user is
    /// created. Best-effort: an RPC failure leaves this empty and the
    /// dropdown shows only built-ins.
    custom_roles: Vec<CustomRoleSummary>,
    #[allow(dead_code)] // accessed by template; will surface via askama macros
    is_super_admin: bool,
    csrf_token: String,
    error: Option<String>,
    flash: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct UsersQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

pub async fn get_users(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<UsersQuery>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let (users, error) =
        match hyperion_rpc_client::call(&state.agent_socket, Request::WebUserList).await {
            Ok(RpcResponse::WebUserList(u)) => (u, None),
            Ok(RpcResponse::Error(e)) => (vec![], Some(e.to_string())),
            Ok(_) => (vec![], Some("unexpected agent response".into())),
            Err(e) => (vec![], Some(format!("rpc: {e}"))),
        };
    // Custom roles for the change-role dropdown. Best-effort — failure
    // just hides the "Custom" optgroup (built-ins still work).
    let custom_roles = match hyperion_rpc_client::call(&state.agent_socket, Request::RoleList).await
    {
        Ok(RpcResponse::RoleList(v)) => v,
        _ => Vec::new(),
    };
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let tpl = UsersTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "users",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        users,
        custom_roles,
        is_super_admin: ctx.is_super_admin(),
        error: error.or(q.error),
        flash: q.flash,
        csrf_token,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct CreateForm {
    username: String,
    email: String,
    password: String,
    role: String,
}

pub async fn post_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebUserCreate {
            username: form.username.trim().to_string(),
            email: form.email.trim().to_string(),
            password: form.password,
            role: form.role,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::WebUserCreate { id: _ } => {
            Ok(Redirect::to("/admin/users?flash=User+created").into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/admin/users?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SetRoleForm {
    user_id: i64,
    role: String,
}

pub async fn post_set_role(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetRoleForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    // A custom-role pick arrives as "custom:<id>"; everything else is a
    // built-in role machine string handled by the existing path.
    if let Some(rest) = form.role.strip_prefix("custom:") {
        let custom_role_id = rest
            .parse::<i64>()
            .map_err(|_| AppError::BadRequest(format!("invalid custom role id: {rest:?}")))?;
        let resp = hyperion_rpc_client::call(
            &state.agent_socket,
            Request::WebUserSetCustomRole {
                user_id: form.user_id,
                custom_role_id,
            },
        )
        .await
        .map_err(AppError::from)?;
        return flash_redirect(resp, "Role updated");
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebUserSetRole {
            user_id: form.user_id,
            role: form.role,
        },
    )
    .await
    .map_err(AppError::from)?;
    flash_redirect(resp, "Role updated")
}

#[derive(Deserialize)]
pub struct LockForm {
    user_id: i64,
    locked: String,
    #[serde(default)]
    reason: String,
}

pub async fn post_lock(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<LockForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let locked = form.locked == "true" || form.locked == "1";
    let reason = if form.reason.trim().is_empty() {
        None
    } else {
        Some(form.reason.trim().to_string())
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebUserSetLocked {
            user_id: form.user_id,
            locked,
            reason,
        },
    )
    .await
    .map_err(AppError::from)?;
    flash_redirect(
        resp,
        if locked {
            "User locked"
        } else {
            "User unlocked"
        },
    )
}

#[derive(Deserialize)]
pub struct DeleteForm {
    user_id: i64,
}

pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebUserDelete {
            user_id: form.user_id,
        },
    )
    .await
    .map_err(AppError::from)?;
    flash_redirect(resp, "User deleted")
}

#[derive(Deserialize)]
pub struct ResetPwForm {
    user_id: i64,
    new_password: String,
}

pub async fn post_reset_password(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ResetPwForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebUserSetPassword {
            user_id: form.user_id,
            new_password: form.new_password,
            // Admin reset: already gated by is_super_admin above, so no
            // current-password re-auth (the admin doesn't know the target's).
            current_password: None,
        },
    )
    .await
    .map_err(AppError::from)?;
    flash_redirect(resp, "Password reset")
}

fn flash_redirect(resp: RpcResponse, success_msg: &str) -> Result<Response, AppError> {
    match resp {
        RpcResponse::WebUserSetRole
        | RpcResponse::WebUserSetLocked
        | RpcResponse::WebUserDelete
        | RpcResponse::WebUserSetPassword => Ok(Redirect::to(&format!(
            "/admin/users?flash={}",
            urlencode(success_msg)
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/admin/users?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
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
