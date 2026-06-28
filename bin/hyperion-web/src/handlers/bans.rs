//! /bans — cluster-wide active IP bans (fail2ban).
//!
//! Fans `BanList { hosting_id: None }` out across the master + every
//! enrolled node so the operator sees every active nftables ban on the
//! fleet in one table, with an Unban action that dispatches back to the
//! owning node.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use serde::Deserialize;

/// One ban row with the node it lives on (for the table + the Unban form).
pub struct BanRow {
    pub node_id: String,
    pub node_label: String,
    pub ip: String,
    pub reason: String,
    pub source: String,
    pub banned_at: i64,
    pub expires_at: i64,
}

#[derive(Template)]
#[template(path = "bans.html")]
struct BansTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    rows: Vec<BanRow>,
    auto: usize,
    manual: usize,
    flash: Option<String>,
    flash_error: Option<String>,
    csrf_token: String,
}

#[derive(Deserialize, Default)]
pub struct BansQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_error: Option<String>,
}

pub async fn get_bans(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<BansQuery>,
) -> Result<Response, AppError> {
    // Cluster-wide bans: require all-hostings scope (tenant roles with
    // SecurityManage act only on their own hostings, not the cluster view).
    if !(ctx.can(Capability::SecurityManage) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let mut rows: Vec<BanRow> = Vec::new();
    let push = |rows: &mut Vec<BanRow>,
                node_id: &str,
                node_label: &str,
                bans: Vec<hyperion_types::IpBanWire>| {
        for b in bans {
            rows.push(BanRow {
                node_id: node_id.to_string(),
                node_label: node_label.to_string(),
                ip: b.ip,
                reason: b.reason,
                source: b.source,
                banned_at: b.banned_at,
                expires_at: b.expires_at,
            });
        }
    };
    // Master (LOCAL sentinel handled by the dispatcher / direct call).
    if let Ok(RpcResponse::BanList(bans)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::BanList { hosting_id: None }).await
    {
        push(&mut rows, "local", "master", bans);
    }
    // Workers.
    if let Ok(RpcResponse::NodesList(nodes)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        for (n, resp) in
            crate::dispatcher::fan_out(&state, nodes, Request::BanList { hosting_id: None }).await
        {
            if let RpcResponse::BanList(bans) = resp {
                push(&mut rows, n.node_id.as_str(), &n.label, bans);
            }
        }
    }
    rows.sort_by(|a, b| b.banned_at.cmp(&a.banned_at));
    let auto = rows.iter().filter(|r| r.source == "auto").count();
    let manual = rows.iter().filter(|r| r.source == "manual").count();

    let tpl = BansTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "bans",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows,
        auto,
        manual,
        flash: q.flash.filter(|s| !s.is_empty()),
        flash_error: q.flash_error.filter(|s| !s.is_empty()),
        csrf_token: super::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct ClusterUnbanForm {
    pub ip: String,
    /// Node the ban lives on ("local" = master).
    #[serde(default)]
    pub node_id: String,
}

/// POST /bans/unban — lift a ban on its owning node, then back to /bans.
pub async fn post_unban(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::Form(form): axum::Form<ClusterUnbanForm>,
) -> Result<Response, AppError> {
    // Cluster-wide bans: require all-hostings scope (tenant roles with
    // SecurityManage act only on their own hostings, not the cluster view).
    if !(ctx.can(Capability::SecurityManage) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let target = if form.node_id.is_empty() || form.node_id == "local" {
        None
    } else {
        Some(form.node_id.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::BanRemove {
            ip: form.ip.trim().to_string(),
        },
    )
    .await?;
    match resp {
        RpcResponse::BanRemove => Ok(Redirect::to("/bans?flash=ban+lifted").into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/bans?flash_error={}",
            url::form_urlencoded::byte_serialize(e.to_string().as_bytes()).collect::<String>()
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
