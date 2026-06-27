//! /import — migrate existing hosting from another control panel (HestiaCP /
//! CloudPanel) into Hyperion. Runs agent-side on the chosen node: a dry-run
//! plan first, then an explicit apply. Mail + DNS are out of scope (reported,
//! never imported). Admin+ only.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use serde::Deserialize;

/// A selectable node for the "run on" dropdown.
pub struct NodeOpt {
    pub id: String,
    pub label: String,
}

/// One row of the dry-run plan table.
pub struct PlanRow {
    pub action: String,
    pub domain: String,
    pub php: String,
    pub db: usize,
    pub reason: String,
}

/// Generic two-column row (created / skipped / notes lists).
pub struct KvRow {
    pub a: String,
    pub b: String,
}

#[derive(Template)]
#[template(path = "import_panel.html")]
struct ImportTpl {
    username: String,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    nodes: Vec<NodeOpt>,
    // Echo of the current selection (drives the form + the apply step).
    source_kind: String,
    mode: String,
    node_id: String,
    // "form" | "plan" | "result"
    stage: &'static str,
    source_label: String,
    source_version: String,
    plan_rows: Vec<PlanRow>,
    notes: Vec<KvRow>,
    created: Vec<KvRow>,
    skipped: Vec<KvRow>,
    result_msg: String,
    error: Option<String>,
}

impl ImportTpl {
    fn base(state: &SharedState, ctx: &AuthCtx, nodes: Vec<NodeOpt>) -> Self {
        ImportTpl {
            username: ctx.username.clone(),
            user_initial: super::user_initial(&ctx.username),
            active: "import",
            css_version: super::css_version(),
            htmx_version: super::htmx_version(),
            csrf_token: super::session_csrf_token(state, ctx),
            nodes,
            source_kind: "cloudpanel".into(),
            mode: "inplace".into(),
            node_id: "local".into(),
            stage: "form",
            source_label: String::new(),
            source_version: String::new(),
            plan_rows: Vec::new(),
            notes: Vec::new(),
            created: Vec::new(),
            skipped: Vec::new(),
            result_msg: String::new(),
            error: None,
        }
    }
}

async fn node_options(state: &SharedState) -> Vec<NodeOpt> {
    let mut v = vec![NodeOpt {
        id: "local".into(),
        label: "master (this node)".into(),
    }];
    if let Ok(RpcResponse::NodesList(nodes)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        for n in nodes {
            v.push(NodeOpt {
                id: n.node_id.as_str().to_string(),
                label: n.label,
            });
        }
    }
    v
}

fn target(node_id: &str) -> Option<&str> {
    if node_id.is_empty() || node_id == "local" {
        None
    } else {
        Some(node_id)
    }
}

pub async fn get_import(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let tpl = ImportTpl::base(&state, &ctx, node_options(&state).await);
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct ImportForm {
    pub source_kind: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub node_id: String,
}
fn default_mode() -> String {
    "inplace".into()
}

/// POST /import/plan — dry-run the import on the chosen node.
pub async fn post_plan(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::Form(form): axum::Form<ImportForm>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let req = hyperion_import::ImportPanelReq {
        source_kind: form.source_kind.clone(),
        mode: form.mode.clone(),
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target(&form.node_id),
        Request::HostingImportPanelPlan { req },
    )
    .await?;

    let mut tpl = ImportTpl::base(&state, &ctx, node_options(&state).await);
    tpl.source_kind = form.source_kind.clone();
    tpl.mode = form.mode.clone();
    tpl.node_id = form.node_id.clone();
    match resp {
        RpcResponse::HostingImportPanelPlan(plan) => {
            tpl.stage = "plan";
            tpl.source_label = plan.source.kind.clone();
            tpl.source_version = plan.source.version.clone();
            tpl.plan_rows = plan
                .items
                .iter()
                .map(|i| PlanRow {
                    action: action_str(&i.action).into(),
                    domain: i.domain.clone(),
                    php: i.php_version.clone().unwrap_or_else(|| "—".into()),
                    db: i.db_count,
                    reason: i.reason.clone(),
                })
                .collect();
            tpl.notes = plan
                .unsupported
                .iter()
                .map(|u| KvRow {
                    a: u.category.clone(),
                    b: u.detail.clone(),
                })
                .collect();
        }
        RpcResponse::Error(e) => tpl.error = Some(e.to_string()),
        _ => tpl.error = Some("unexpected response from node".into()),
    }
    Ok(Html(tpl.render()?).into_response())
}

/// POST /import/apply — actually run the import on the chosen node.
pub async fn post_apply(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::Form(form): axum::Form<ImportForm>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let req = hyperion_import::ImportPanelReq {
        source_kind: form.source_kind.clone(),
        mode: form.mode.clone(),
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target(&form.node_id),
        Request::HostingImportPanel { req },
    )
    .await?;

    let mut tpl = ImportTpl::base(&state, &ctx, node_options(&state).await);
    tpl.source_kind = form.source_kind.clone();
    tpl.mode = form.mode.clone();
    tpl.node_id = form.node_id.clone();
    match resp {
        RpcResponse::HostingImportPanel(res) => {
            tpl.stage = "result";
            tpl.result_msg = res.message.clone();
            tpl.created = res
                .created
                .iter()
                .map(|c| KvRow {
                    a: c.domain.clone(),
                    b: format!("{} · {} database(s)", c.hosting_id, c.databases),
                })
                .collect();
            tpl.skipped = res
                .skipped
                .iter()
                .map(|s| KvRow {
                    a: s.domain.clone(),
                    b: s.reason.clone(),
                })
                .collect();
            tpl.notes = res
                .unsupported
                .iter()
                .map(|u| KvRow {
                    a: u.category.clone(),
                    b: u.detail.clone(),
                })
                .collect();
        }
        RpcResponse::Error(e) => tpl.error = Some(e.to_string()),
        _ => tpl.error = Some("unexpected response from node".into()),
    }
    Ok(Html(tpl.render()?).into_response())
}

fn action_str(a: &hyperion_import::Action) -> &'static str {
    match a {
        hyperion_import::Action::Create => "create",
        hyperion_import::Action::Skip => "skip",
        hyperion_import::Action::Conflict => "conflict",
        hyperion_import::Action::Unsupported => "unsupported",
    }
}
