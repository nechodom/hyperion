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
use hyperion_state::capabilities::Capability;
use serde::Deserialize;
use std::str::FromStr;

/// A selectable node for the "run on" dropdown.
pub struct NodeOpt {
    pub id: String,
    pub label: String,
}

/// One row of the dry-run plan table.
pub struct PlanRow {
    pub action: String,
    pub domain: String,
    /// What the SOURCE reports this site runs on, verbatim — including
    /// versions Hyperion does not carry, which is most of why the choice
    /// below exists.
    pub php: String,
    /// The supported version this site will land on unless the operator picks
    /// another. Preselected in the form.
    pub php_target: String,
    /// True when `php_target` is not what the source runs, so the row can say
    /// so instead of the operator finding out from a broken site.
    pub php_substituted: bool,
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
    /// The PHP versions this build supports, for the per-site picker.
    php_options: Vec<String>,
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
            php_options: hyperion_types::PhpVersion::all()
                .iter()
                .map(|v| v.as_str().to_string())
                .collect(),
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
    if !ctx.can(Capability::PanelImport) {
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
    /// archive mode: node-local path to an uploaded bundle (set by the upload
    /// handler, echoed through the plan → apply steps).
    #[serde(default)]
    pub archive_path: String,
}
fn default_mode() -> String {
    "inplace".into()
}

/// None unless the form carries a non-empty archive path.
fn opt_archive(form: &ImportForm) -> Option<String> {
    let p = form.archive_path.trim();
    if p.is_empty() {
        None
    } else {
        Some(p.to_string())
    }
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
    if !ctx.can(Capability::PanelImport) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let req = hyperion_import::ImportPanelReq {
        source_kind: form.source_kind.clone(),
        mode: form.mode.clone(),
        ssh: build_ssh(&form),
        archive_path: opt_archive(&form),
        // The non-interactive panel-import path imports every site as-is; the
        // per-site rename/profile/billing overrides only come from the wizard.
        site_overrides: Vec::new(),
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
                .map(|i| {
                    // Where this site will land unless the operator picks
                    // otherwise, worked out by the SAME function the import
                    // will use — a preview that guesses differently from the
                    // thing it previews is worse than no preview.
                    let (target, substituted) = i
                        .php_version
                        .as_deref()
                        .and_then(hyperion_types::PhpVersion::nearest_supported)
                        .map(|(v, sub)| (v.as_str().to_string(), sub))
                        // Nothing reported: the import gives a php site the
                        // lowest supported version rather than none at all.
                        .unwrap_or_else(|| ("8.1".to_string(), true));
                    PlanRow {
                        action: action_str(&i.action).into(),
                        domain: i.domain.clone(),
                        php: i.php_version.clone().unwrap_or_else(|| "—".into()),
                        php_target: target,
                        php_substituted: substituted,
                        db: i.db_count,
                        reason: i.reason.clone(),
                    }
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

/// Per-site PHP choices out of the plan form.
///
/// Each row submits `php__<source domain>=<version>`. The domain is the plan's
/// match key, so it is echoed back rather than re-derived — and it is used ONLY
/// to look up an override, never to build a path or a command.
fn php_overrides_from(body: &[u8]) -> Vec<hyperion_import::SiteImportOverride> {
    url::form_urlencoded::parse(body)
        .filter_map(|(k, v)| {
            let domain = k.strip_prefix("php__")?.trim();
            let version = v.trim();
            if domain.is_empty() || version.is_empty() {
                return None;
            }
            // Only versions this build actually carries. The field is a
            // <select>, but a form post is not a promise.
            hyperion_types::PhpVersion::from_str(version).ok()?;
            Some(hyperion_import::SiteImportOverride {
                source_domain: domain.to_string(),
                target_domain: None,
                profile_id: None,
                next_billing_at: None,
                php_version: Some(version.to_string()),
            })
        })
        .collect()
}

/// POST /import/apply — run the import as a background job on the chosen node.
///
/// The import can take minutes (large docroots, DB dumps, remote ssh/rsync), so
/// it must NOT be tied to the browser request: we open a job, detach the work
/// onto a tokio task via `spawn_job`, and redirect to the live progress page.
/// Losing the browser connection no longer aborts the import.
pub async fn post_apply(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    // RAW body, not `Form<ImportForm>`: the plan table submits one
    // `php__<domain>` field per site, and a fixed struct silently drops every
    // key it does not name. The fixed fields are still deserialized from the
    // same bytes, so there is one body and one parse of the truth.
    axum::extract::RawForm(body): axum::extract::RawForm,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    // The same bytes, parsed once for the fixed fields. `RawForm` hands over
    // the urlencoded body; `Form` would have deserialized exactly this.
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let field = |name: &str| -> String {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let mode = field("mode");
    let form = ImportForm {
        source_kind: field("source_kind"),
        mode: if mode.is_empty() {
            default_mode()
        } else {
            mode
        },
        node_id: field("node_id"),
        ssh_host: field("ssh_host"),
        ssh_user: field("ssh_user"),
        ssh_port: field("ssh_port"),
        ssh_key: field("ssh_key"),
        archive_path: field("archive_path"),
    };
    let site_overrides = php_overrides_from(&body);
    let req = hyperion_import::ImportPanelReq {
        source_kind: form.source_kind.clone(),
        mode: form.mode.clone(),
        ssh: build_ssh(&form),
        archive_path: opt_archive(&form),
        // Per-site PHP choices from the plan table. Rename/profile/billing
        // overrides still only come from the self-service wizard.
        site_overrides,
    };
    // Owned bits captured by the detached task (no secrets in the job payload —
    // the ssh key lives only in `req`, in memory, never persisted to the row).
    let node = target(&form.node_id).map(String::from);
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let label = format!("{} ({})", form.source_kind, form.mode);
    let job_state = state.clone();

    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "panel_import",
        Some(&label),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_panel_import_job(reporter, job_state, node, req).await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker: dispatch the import RPC and fold the per-site outcome into
/// the job log. The import RPC is one coarse step (the node does all sites then
/// replies); progress is start → done, with the full created/skipped/unsupported
/// breakdown captured in the job's log tail.
pub(crate) async fn run_panel_import_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    node: Option<String>,
    req: hyperion_import::ImportPanelReq,
) {
    let source = req.source_kind.clone();
    // SECURITY (sec-findings #6): the ingested bundle (plaintext DB dumps +
    // wp-config secrets) must be deleted once the import finishes — success OR
    // failure. Capture the path now (it's moved into the RPC below) and only
    // ever delete our own `<migration>/bundle-*.tar` files, never an arbitrary
    // operator-supplied archive_path.
    let cleanup_bundle: Option<String> =
        req.archive_path.as_deref().map(str::to_string).filter(|p| {
            std::path::Path::new(p)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("bundle-") && n.ends_with(".tar"))
                && p.starts_with("/var/lib/hyperion/migration/")
        });
    let where_ = if req.mode == "remote" {
        format!(
            "{} over SSH",
            req.ssh
                .as_ref()
                .map(|s| s.host.as_str())
                .unwrap_or("remote")
        )
    } else {
        "this node (in-place)".to_string()
    };
    reporter
        .step(&format!("Importing {source} from {where_}…"), 10, "")
        .await;

    match crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::HostingImportPanel { req },
    )
    .await
    {
        Ok(RpcResponse::HostingImportPanel(res)) => {
            let mut log = String::new();
            for c in &res.created {
                log.push_str(&format!(
                    "✓ created {} ({} database(s))\n",
                    c.domain, c.databases
                ));
            }
            for s in &res.skipped {
                log.push_str(&format!("· skipped {} — {}\n", s.domain, s.reason));
            }
            for u in &res.unsupported {
                log.push_str(&format!("(not imported — {}: {})\n", u.category, u.detail));
            }
            reporter.step(&res.message, 100, &log).await;
            reporter.finish(true, None).await;
        }
        Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
        Ok(_) => {
            reporter
                .finish(false, Some("unexpected response from node".into()))
                .await
        }
        Err(e) => reporter.finish(false, Some(e.to_string())).await,
    }

    // Always shred the ingested bundle once the job is done (any outcome).
    if let Some(p) = cleanup_bundle {
        if let Err(e) = tokio::fs::remove_file(&p).await {
            tracing::warn!(path = %p, error = %e, "could not delete ingested import bundle");
        }
    }
}

fn action_str(a: &hyperion_import::Action) -> &'static str {
    match a {
        hyperion_import::Action::Create => "create",
        hyperion_import::Action::Skip => "skip",
        hyperion_import::Action::Conflict => "conflict",
        hyperion_import::Action::Unsupported => "unsupported",
    }
}

#[cfg(test)]
mod php_override_tests {
    use super::php_overrides_from;

    /// The plan table submits one `php__<domain>` per site; the choice has to
    /// survive the trip, because a fixed Form struct silently drops every key
    /// it does not name and the operator's pick would vanish without a word.
    #[test]
    fn a_per_site_choice_reaches_the_import() {
        let body = b"source_kind=cloudpanel&php__a.cz=8.2&php__b.cz=8.4&mode=inplace";
        let mut got = php_overrides_from(body);
        got.sort_by(|x, y| x.source_domain.cmp(&y.source_domain));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].source_domain, "a.cz");
        assert_eq!(got[0].php_version.as_deref(), Some("8.2"));
        assert_eq!(got[1].source_domain, "b.cz");
        assert_eq!(got[1].php_version.as_deref(), Some("8.4"));
        // Nothing else is invented for these sites.
        assert!(got[0].target_domain.is_none() && got[0].profile_id.is_none());
    }

    /// A <select> is not a promise: the body is whatever was posted, and a
    /// version this build does not carry must not reach the importer.
    #[test]
    fn an_unsupported_version_is_dropped() {
        for bad in ["7.4", "8.0", "9.9", "", "latest", "8.3;rm -rf /"] {
            let body = format!("php__a.cz={bad}");
            assert!(
                php_overrides_from(body.as_bytes()).is_empty(),
                "accepted {bad:?}"
            );
        }
    }

    /// Fields that are not a per-site PHP choice are none of this function's
    /// business.
    #[test]
    fn other_fields_are_ignored() {
        let body = b"source_kind=cloudpanel&ssh_key=secret&mode=inplace&php_=8.2&php=8.2";
        assert!(php_overrides_from(body).is_empty());
    }
}
