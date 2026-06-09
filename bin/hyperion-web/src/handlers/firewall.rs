//! `/firewall` — cluster-wide firewall ruleset overview.
//!
//! Fans out `FirewallList` RPC to the master + every enrolled
//! worker. Per node we show:
//!
//!   - which backend answered (nft / iptables / unknown)
//!   - the parsed "open ports" pill row (best-effort)
//!   - the full raw ruleset inside a collapsed `<details>`
//!
//! Read-only by design. The operator inspects via this page,
//! mutates via SSH + nft / firewalld / ufw — we don't ship a
//! rule editor because the risk of bricking remote access by
//! accidentally locking yourself out is too high to justify a
//! GUI button for. The "View" gives 80% of the value of a
//! full editor (catching unexpected open ports, drift between
//! nodes) at 0% of the risk.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};

#[derive(Template)]
#[template(path = "firewall.html")]
struct FirewallTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    /// One entry per node — master first, then workers in node_id
    /// order so the page is deterministic.
    nodes: Vec<NodeFirewall>,
}

pub struct NodeFirewall {
    pub node_id: String,
    pub label: String,
    pub view: hyperion_types::FirewallView,
    /// True when the RPC failed entirely — render a "node
    /// unreachable" notice instead of an empty card.
    pub unreachable: bool,
}

pub async fn get_firewall(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Only admins should see the ruleset — it reveals service
    // topology that an operator role doesn't need.
    if !ctx.is_admin_or_higher() {
        return Ok(
            Redirect::to("/?flash_error=admin+role+required+to+view+firewall")
                .into_response(),
        );
    }
    let mut nodes: Vec<NodeFirewall> = Vec::new();
    // Master.
    let master = match hyperion_rpc_client::call(&state.agent_socket, Request::FirewallList).await {
        Ok(RpcResponse::FirewallList(v)) => NodeFirewall {
            node_id: "master".to_string(),
            label: "master".to_string(),
            view: v,
            unreachable: false,
        },
        _ => NodeFirewall {
            node_id: "master".to_string(),
            label: "master".to_string(),
            view: hyperion_types::FirewallView::default(),
            unreachable: true,
        },
    };
    nodes.push(master);
    // Workers — fan out via dispatcher.
    if let Ok(RpcResponse::NodesList(workers)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        for w in workers {
            let v = match crate::dispatcher::dispatch_to_node(
                &state,
                Some(w.node_id.as_str()),
                Request::FirewallList,
            )
            .await
            {
                Ok(RpcResponse::FirewallList(v)) => Some(v),
                _ => None,
            };
            let unreachable = v.is_none();
            nodes.push(NodeFirewall {
                node_id: w.node_id.clone(),
                label: w.label.clone(),
                view: v.unwrap_or_default(),
                unreachable,
            });
        }
    }
    let tpl = FirewallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "firewall",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        nodes,
    };
    Ok(Html(tpl.render()?).into_response())
}
