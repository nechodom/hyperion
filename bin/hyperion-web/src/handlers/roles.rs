//! `/roles` — custom-role builder (granular RBAC) for super_admin.
//!
//! Read-only list of the 5 built-in roles (name + scope + capability
//! count, straight from `WebRole::capabilities()/scope_all()`) plus the
//! custom roles (RPC `RoleList`) with Edit / Clone / Delete and a live
//! in-use count. The builder (`role_edit.html`) renders the grouped
//! capability checkboxes from `hyperion_state::capabilities::groups()`;
//! each checkbox's `name` is the capability's machine string, folded
//! back into a `CapSet` on submit.
//!
//! Every handler is gated on `ctx.is_super_admin()` — the route only
//! enforces auth + CSRF, so the gate is what keeps non-owners out.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::{CapSet, Capability};
use hyperion_state::web_users::WebRole;
use hyperion_types::CustomRoleSummary;
use serde::Deserialize;
use std::collections::HashMap;

/// One built-in role row on the list page — read-only summary.
struct BuiltinRoleView {
    label: &'static str,
    machine: &'static str,
    scope_all: bool,
    cap_count: u32,
}

/// One capability checkbox in the builder.
struct CapRow {
    machine: &'static str,
    label: &'static str,
    checked: bool,
}

/// One capability group (e.g. "Hosting") with its rows.
struct CapGroup {
    label: &'static str,
    caps: Vec<CapRow>,
}

#[derive(Template)]
#[template(path = "roles.html")]
struct RolesTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    builtins: Vec<BuiltinRoleView>,
    custom: Vec<CustomRoleSummary>,
    error: Option<String>,
    flash: Option<String>,
}

#[derive(Template)]
#[template(path = "role_edit.html")]
struct RoleEditTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    /// Empty for "new" (unless cloning), else the role's id. `0` means
    /// "create" — the form posts to `/roles`; otherwise it posts to
    /// `/roles/<id>/update`.
    role_id: i64,
    is_edit: bool,
    name: String,
    scope_all: bool,
    groups: Vec<CapGroup>,
    error: Option<String>,
    flash: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct RolesQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct NewQuery {
    /// Clone source role id — pre-fills the builder from this custom role.
    #[serde(default)]
    clone: Option<i64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    flash: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct EditQuery {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    flash: Option<String>,
}

/// GET /roles — built-in roles (read-only) + custom roles (Edit/Clone/Delete).
pub async fn get_roles(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<RolesQuery>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let (custom, error) = match fetch_roles(&state).await {
        Ok(v) => (v, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let builtins = builtin_role_views();
    let tpl = RolesTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "roles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(&state, &ctx),
        builtins,
        custom,
        error: error.or(q.error),
        flash: q.flash,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// GET /roles/new — blank builder, or pre-filled from `?clone=<id>`.
pub async fn get_new(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<NewQuery>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    // Clone source — when present, copy its name + caps + scope into the
    // blank form. Best-effort: a missing/failed lookup just yields a
    // blank form (the operator can still build from scratch).
    let (mut name, mut caps, mut scope_all) = (String::new(), CapSet::empty(), false);
    if let Some(src_id) = q.clone {
        if let Ok(roles) = fetch_roles(&state).await {
            if let Some(src) = roles.into_iter().find(|r| r.id == src_id) {
                name = format!("{} (copy)", src.name);
                caps = CapSet::from_bits(src.capabilities);
                scope_all = src.scope_all;
            }
        }
    }
    let tpl = RoleEditTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "roles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(&state, &ctx),
        role_id: 0,
        is_edit: false,
        name,
        scope_all,
        groups: build_groups(caps),
        error: q.error,
        flash: q.flash,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// GET /roles/:id/edit — builder pre-filled from the role's current caps.
pub async fn get_edit(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(id): Path<i64>,
    Query(q): Query<EditQuery>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let roles = fetch_roles(&state).await.map_err(AppError::Rpc)?;
    let role = match roles.into_iter().find(|r| r.id == id) {
        Some(r) => r,
        None => return Err(AppError::NotFound),
    };
    let caps = CapSet::from_bits(role.capabilities);
    let tpl = RoleEditTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "roles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(&state, &ctx),
        role_id: role.id,
        is_edit: true,
        name: role.name,
        scope_all: role.scope_all,
        groups: build_groups(caps),
        error: q.error,
        flash: q.flash,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// The builder form posts every checked capability as a field named by its
/// machine string, set to "on". `scope` is "all" / anything-else, `name` is
/// the role label. We capture the dynamic capability fields via a flat map.
#[derive(Deserialize)]
pub struct RoleForm {
    name: String,
    #[serde(default)]
    scope: String,
    /// Every other form field (the capability checkboxes, the CSRF token).
    /// A checked box arrives as `<machine> = "on"`; we only look up the
    /// known machine strings, so the CSRF field is harmlessly ignored.
    #[serde(flatten)]
    rest: HashMap<String, String>,
}

impl RoleForm {
    /// Fold the checked capability checkboxes into a `CapSet`.
    fn caps(&self) -> CapSet {
        Capability::ALL
            .into_iter()
            .filter(|c| self.rest.get(c.as_str()).map(String::as_str) == Some("on"))
            .collect()
    }
    fn scope_all(&self) -> bool {
        self.scope == "all"
    }
}

/// POST /roles — create a custom role.
pub async fn post_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RoleForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let name = form.name.trim().to_string();
    let capabilities = form.caps().bits();
    let scope_all = form.scope_all();
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::RoleCreate {
            name: name.clone(),
            capabilities,
            scope_all,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::RoleCreate { id: _ } => Ok(Redirect::to(&format!(
            "/roles?flash={}",
            urlencoding(&format!("Role \"{name}\" created."))
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/roles/new?error={}",
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /roles/:id/update — save edits to an existing custom role.
pub async fn post_update(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(id): Path<i64>,
    Form(form): Form<RoleForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let name = form.name.trim().to_string();
    let capabilities = form.caps().bits();
    let scope_all = form.scope_all();
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::RoleUpdate {
            id,
            name: name.clone(),
            capabilities,
            scope_all,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::RoleUpdate => Ok(Redirect::to(&format!(
            "/roles?flash={}",
            urlencoding(&format!("Role \"{name}\" updated."))
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/roles/{}/edit?error={}",
            id,
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    id: i64,
}

/// POST /roles/:id/delete — delete a custom role. The agent refuses an
/// in-use role; we surface that refusal as a list-page error.
pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::RoleDelete { id: form.id })
        .await
        .map_err(AppError::from)?;
    match resp {
        RpcResponse::RoleDelete => Ok(Redirect::to("/roles?flash=Role+deleted").into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/roles?error={}",
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// ── helpers ────────────────────────────────────────────────────────

/// Fetch all custom roles. Maps RPC / unexpected responses to a string the
/// caller can surface as a page error.
async fn fetch_roles(state: &SharedState) -> Result<Vec<CustomRoleSummary>, String> {
    match hyperion_rpc_client::call(&state.agent_socket, Request::RoleList).await {
        Ok(RpcResponse::RoleList(v)) => Ok(v),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected agent response".into()),
        Err(e) => Err(format!("rpc: {e}")),
    }
}

/// The 5 built-in roles, as read-only summary rows (label + scope + count).
fn builtin_role_views() -> Vec<BuiltinRoleView> {
    [
        (WebRole::SuperAdmin, "Owner"),
        (WebRole::Admin, "Administrator"),
        (WebRole::Operator, "Operator"),
        (WebRole::Customer, "Customer"),
        (WebRole::Viewer, "Read-only"),
    ]
    .into_iter()
    .map(|(r, label)| BuiltinRoleView {
        label,
        machine: r.as_str(),
        scope_all: r.scope_all(),
        cap_count: r.capabilities().count(),
    })
    .collect()
}

/// Build the grouped capability view model, marking each row checked when
/// `caps` contains it.
fn build_groups(caps: CapSet) -> Vec<CapGroup> {
    hyperion_state::capabilities::groups()
        .into_iter()
        .map(|(label, members)| CapGroup {
            label,
            caps: members
                .into_iter()
                .map(|c| CapRow {
                    machine: c.as_str(),
                    label: c.label(),
                    checked: caps.contains(c),
                })
                .collect(),
        })
        .collect()
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
