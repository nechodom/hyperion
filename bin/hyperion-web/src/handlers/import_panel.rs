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
    ssh_host: String,
    ssh_user: String,
    ssh_port: String,
    ssh_key: String,
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
            ssh_host: String::new(),
            ssh_user: "root".into(),
            ssh_port: "22".into(),
            ssh_key: String::new(),
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
    #[serde(default)]
    pub ssh_host: String,
    #[serde(default)]
    pub ssh_user: String,
    #[serde(default)]
    pub ssh_port: String,
    #[serde(default)]
    pub ssh_key: String,
}
fn default_mode() -> String {
    "inplace".into()
}

/// Build the SSH connection for remote mode from the form (None otherwise).
fn build_ssh(form: &ImportForm) -> Option<hyperion_import::SshConn> {
    if form.mode != "remote" || form.ssh_host.trim().is_empty() || form.ssh_key.trim().is_empty() {
        return None;
    }
    Some(hyperion_import::SshConn {
        host: form.ssh_host.trim().to_string(),
        user: if form.ssh_user.trim().is_empty() {
            "root".into()
        } else {
            form.ssh_user.trim().to_string()
        },
        port: form.ssh_port.trim().parse().unwrap_or(22),
        key: form.ssh_key.clone(),
    })
}

/// Copy the SSH form fields into the template so the apply step can resubmit.
fn echo_ssh(tpl: &mut ImportTpl, form: &ImportForm) {
    tpl.ssh_host = form.ssh_host.clone();
    tpl.ssh_user = if form.ssh_user.trim().is_empty() {
        "root".into()
    } else {
        form.ssh_user.clone()
    };
    tpl.ssh_port = if form.ssh_port.trim().is_empty() {
        "22".into()
    } else {
        form.ssh_port.clone()
    };
    tpl.ssh_key = form.ssh_key.clone();
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
        ssh: build_ssh(&form),
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
    echo_ssh(&mut tpl, &form);
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
        ssh: build_ssh(&form),
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
    echo_ssh(&mut tpl, &form);
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
