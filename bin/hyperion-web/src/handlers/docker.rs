//! `/docker` — what the Docker module sees on every node that runs it.
//!
//! The master keeps the list of nodes that turned the module on
//! (`DockerNodeList`); this page asks exactly those nodes for their last
//! reading (`DockerOverview`) and draws stacks per node, problems first. A node
//! that does not answer is a row that says so, never a gap: a short list on a
//! monitoring page reads as "nothing is wrong".
//!
//! Everything here is a read except the module's own switches (install and
//! remove, administrators only, as background jobs) and "forget" on a stack
//! that disappeared, which clears Hyperion's record and touches no container.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::docker::{
    DockerContainer, DockerLogRequest, DockerNodeEntry, DockerNodeList, DockerNodeStatus,
    DockerProject, ImageUpdateState, DEFAULT_LOG_LINES, MAX_LOG_LINES,
};
use hyperion_types::NodeSummary;
use serde::Deserialize;

use crate::dispatcher::{DispatchError, LOCAL_NODE_SENTINEL};

/// What the URL calls the group of containers that belong to no compose
/// project. Parentheses cannot be in a compose project name.
const OTHER_TOKEN: &str = "(other)";
/// What the page calls it.
const OTHER_LABEL: &str = "other containers";
/// A container log past this, with no `max-size`, is how Docker fills a disk.
const LOG_WARN_BYTES: u64 = 1024 * 1024 * 1024;
/// How many of a node's largest logs are listed.
const BIGGEST_LOGS: usize = 5;
/// Longest project name taken from a URL.
const NAME_MAX_CHARS: usize = 128;

/// What one node said when asked for its Docker overview.
#[derive(Debug, Clone)]
pub(crate) enum NodeDockerState {
    /// It answered.
    Ok(DockerNodeStatus),
    /// It runs an agent that does not know the Docker module.
    OldAgent,
    /// It did not answer, or answered with something unusable.
    Unreachable,
}

/// One node of the module with what it said.
#[derive(Debug, Clone)]
pub(crate) struct NodeDockerRow {
    /// `local` for the master, else the enrolled node id.
    pub node_id: String,
    pub label: String,
    pub status: NodeDockerState,
}

/// Only for readers who may see every tenant's containers.
fn allowed(ctx: &AuthCtx) -> bool {
    ctx.can(Capability::DockerView) && ctx.scope_all()
}

/// Logs hold what the containers print, so they have a capability of their
/// own; the rows still span every tenant, hence `scope_all`.
fn logs_allowed(ctx: &AuthCtx) -> bool {
    ctx.can(Capability::DockerLogs) && ctx.scope_all()
}

/// The master's own bookkeeping: whether the module is on and which nodes run
/// it. Ids are normalized so the master is always `local`.
async fn registry(state: &SharedState) -> Result<DockerNodeList, String> {
    match crate::dispatcher::dispatch_to_node(state, None, Request::DockerNodeList).await {
        Ok(RpcResponse::DockerNodeList(mut l)) => {
            for n in &mut l.nodes {
                n.node_id = canonical_node(state, &n.node_id).await;
            }
            l.nodes.sort_by(|a, b| {
                (a.node_id != LOCAL_NODE_SENTINEL, &a.node_id)
                    .cmp(&(b.node_id != LOCAL_NODE_SENTINEL, &b.node_id))
            });
            l.nodes.dedup_by(|a, b| a.node_id == b.node_id);
            Ok(l)
        }
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected agent response".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// `local` for the master (however it was spelled), else the node id as
/// given. Whether that id is a real node is the dispatcher's question.
async fn canonical_node(state: &SharedState, raw: &str) -> String {
    match crate::dispatcher::remote_target(state, Some(raw)).await {
        None => LOCAL_NODE_SENTINEL.to_string(),
        Some(id) => id.to_string(),
    }
}

/// The registered node a URL names, as the dispatcher will address it. A
/// node that is not registered is not a valid target for anything here.
async fn registered_target(
    state: &SharedState,
    list: &DockerNodeList,
    raw: &str,
) -> Option<String> {
    let want = canonical_node(state, raw).await;
    list.nodes
        .iter()
        .any(|n: &DockerNodeEntry| n.node_id == want)
        .then_some(want)
}

/// A node as the dispatcher wants it: `None` is the master.
fn dispatch_target(canonical: &str) -> Option<&str> {
    (canonical != LOCAL_NODE_SENTINEL).then_some(canonical)
}

fn classify_answer(resp: RpcResponse) -> NodeDockerState {
    match resp {
        RpcResponse::DockerOverview(st) => NodeDockerState::Ok(st),
        RpcResponse::Error(e) => {
            tracing::warn!(error = %e, "docker overview refused by a registered node");
            NodeDockerState::Unreachable
        }
        _ => NodeDockerState::Unreachable,
    }
}

/// `None` for an answer the master threw away because it could not prove who
/// wrote it: that node's rows are reported by `node_auth_warning`, not drawn.
pub(crate) fn classify_failure(e: &DispatchError) -> Option<NodeDockerState> {
    match e {
        DispatchError::ResponseAuthFailed { .. } => None,
        e if crate::cluster_sync::is_old_agent(e) => Some(NodeDockerState::OldAgent),
        _ => Some(NodeDockerState::Unreachable),
    }
}

/// Ask every node in `list` for its overview. Master first, then the rest by
/// label. A registered node the master no longer lists as enrolled is a row
/// that cannot be reached (and can still be removed).
async fn collect_for(
    state: &SharedState,
    list: &DockerNodeList,
) -> (Vec<NodeDockerRow>, Vec<(NodeSummary, DispatchError)>) {
    let mut rows: Vec<NodeDockerRow> = Vec::new();
    let enrolled = crate::handlers::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default();

    if list.nodes.iter().any(|n| n.node_id == LOCAL_NODE_SENTINEL) {
        let status =
            match crate::dispatcher::dispatch_to_node(state, None, Request::DockerOverview).await {
                Ok(resp) => classify_answer(resp),
                Err(e) => classify_failure(&e).unwrap_or(NodeDockerState::Unreachable),
            };
        rows.push(NodeDockerRow {
            node_id: LOCAL_NODE_SENTINEL.to_string(),
            label: "master".to_string(),
            status,
        });
    }

    let mut ask: Vec<NodeSummary> = Vec::new();
    for e in list
        .nodes
        .iter()
        .filter(|n| n.node_id != LOCAL_NODE_SENTINEL)
    {
        match enrolled.iter().find(|n| n.node_id == e.node_id) {
            Some(n) => ask.push(n.clone()),
            None => rows.push(NodeDockerRow {
                node_id: e.node_id.clone(),
                label: e.node_id.clone(),
                status: NodeDockerState::Unreachable,
            }),
        }
    }
    let (answered, failed) =
        crate::dispatcher::fan_out_reporting(state, ask, Request::DockerOverview).await;
    for (n, resp) in answered {
        rows.push(NodeDockerRow {
            node_id: n.node_id.clone(),
            label: node_label(&n),
            status: classify_answer(resp),
        });
    }
    for (n, e) in &failed {
        if let Some(status) = classify_failure(e) {
            rows.push(NodeDockerRow {
                node_id: n.node_id.clone(),
                label: node_label(n),
                status,
            });
        }
    }
    rows.sort_by(|a, b| {
        (a.node_id != LOCAL_NODE_SENTINEL, &a.label)
            .cmp(&(b.node_id != LOCAL_NODE_SENTINEL, &b.label))
    });
    (rows, failed)
}

fn node_label(n: &NodeSummary) -> String {
    if n.label.is_empty() {
        n.node_id.clone()
    } else {
        n.label.clone()
    }
}

/// The module's status on every node that runs it: master and enrolled
/// workers, concatenated, plus the workers whose answer was discarded. Shared
/// with the sidebar's Docker dot so it counts what this page lists.
pub(crate) async fn collect_status(
    state: &SharedState,
) -> (Vec<NodeDockerRow>, Vec<(NodeSummary, DispatchError)>) {
    match registry(state).await {
        Ok(list) => collect_for(state, &list).await,
        Err(_) => (Vec::new(), Vec::new()),
    }
}

/// What the sidebar needs: is the module on for the cluster, and how many
/// things need a person. Counted by [`problem_count`] so the dot agrees with
/// the page it links to.
pub(crate) async fn nav_summary(state: &SharedState) -> (bool, i64) {
    let Ok(list) = registry(state).await else {
        return (false, 0);
    };
    if !list.cluster_installed {
        return (false, 0);
    }
    // One more local call than reusing `list`, in exchange for the dot and
    // the page going through the same function.
    let (rows, _) = collect_status(state).await;
    (true, problem_count(&rows))
}

/// Stacks that are not fine, nodes whose Docker is not answering, and nodes
/// that did not answer at all. A node that only needs updating is a to-do,
/// not a problem with Docker.
pub(crate) fn problem_count(rows: &[NodeDockerRow]) -> i64 {
    rows.iter()
        .map(|r| match &r.status {
            NodeDockerState::Ok(st) if !st.daemon_ok => 1,
            NodeDockerState::Ok(st) => {
                st.projects.iter().filter(|p| p.verdict != "ok").count() as i64
            }
            NodeDockerState::Unreachable => 1,
            NodeDockerState::OldAgent => 0,
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

struct StackView {
    /// Shown name; "other containers" for the group without a project.
    name: String,
    href: String,
    tone: &'static str,
    state_label: &'static str,
    /// Service names, or container names for the catch-all group.
    services: String,
    containers: usize,
    summary: String,
    /// "No containers since 3h ago" for a gone stack.
    gone: String,
    forget_action: Option<String>,
    /// Hostings that reverse-proxy to a port this stack publishes.
    hostings: Vec<HostingLink>,
    /// Image updates worth a badge on the list: an update at the registry,
    /// or a pulled image the container was not recreated on. "Cannot verify"
    /// is not one; its reason is on the stack page.
    updates: Vec<UpdatePill>,
}

/// A small badge about an image.
struct UpdatePill {
    tone: &'static str,
    label: String,
}

/// The longest reason text shown. It comes from a node.
const REASON_MAX_CHARS: usize = 300;

fn update_pill(u: &ImageUpdateState) -> UpdatePill {
    let (tone, label) = match u {
        ImageUpdateState::UpToDate => ("muted", "up to date"),
        ImageUpdateState::UpdateAvailable => ("info", "update available"),
        ImageUpdateState::NotRecreated => ("warn", "pulled, not recreated"),
        ImageUpdateState::CannotVerify { .. } => ("muted", "cannot verify"),
    };
    UpdatePill {
        tone,
        label: label.to_string(),
    }
}

/// Badges for a stack on the list: how many of its containers run an image
/// that has an update, and how many were not recreated after a pull.
fn stack_updates(p: &DockerProject) -> Vec<UpdatePill> {
    let count = |want: &ImageUpdateState| {
        p.containers
            .iter()
            .filter(|c| c.update.as_ref() == Some(want))
            .count()
    };
    let mut out = Vec::new();
    let n = count(&ImageUpdateState::UpdateAvailable);
    if n > 0 {
        out.push(UpdatePill {
            tone: "info",
            label: if n == 1 {
                "update available".to_string()
            } else {
                format!("{n} updates available")
            },
        });
    }
    let n = count(&ImageUpdateState::NotRecreated);
    if n > 0 {
        out.push(UpdatePill {
            tone: "warn",
            label: if n == 1 {
                "pulled, not recreated".to_string()
            } else {
                format!("{n} pulled, not recreated")
            },
        });
    }
    out
}

/// A hosting named on a Docker page, linking to its detail page.
struct HostingLink {
    domain: String,
    href: String,
}

fn hosting_links(p: &DockerProject) -> Vec<HostingLink> {
    p.hostings
        .iter()
        .map(|d| HostingLink {
            domain: d.clone(),
            href: format!("/hostings/{}", enc(d)),
        })
        .collect()
}

struct LogView {
    stack: String,
    container: String,
    size: String,
    warn: bool,
}

struct DiskView {
    images: String,
    volumes: String,
    build_cache: String,
    read: String,
}

struct NodeView {
    label: String,
    /// `ok`, `old` or `down`.
    kind: &'static str,
    /// The daemon did not answer on the node's latest attempt.
    daemon_error: Option<String>,
    stale_stacks: bool,
    read: String,
    stacks: Vec<StackView>,
    logs: Vec<LogView>,
    log_warnings: usize,
    disk: Option<DiskView>,
    /// Some stack here has an image badge, so the page says what it means.
    has_updates: bool,
    remove_action: String,
    remove_body: String,
}

struct OfferView {
    label: String,
    install_action: String,
}

struct Verdict {
    tone: &'static str,
    line: String,
    counts: String,
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b if b.is_ascii_alphanumeric() => (b as char).to_string(),
            b => format!("%{b:02X}"),
        })
        .collect()
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn project_token(name: &str) -> String {
    if name.is_empty() {
        enc(OTHER_TOKEN)
    } else {
        enc(name)
    }
}

fn project_name(p: &DockerProject) -> String {
    if p.name.is_empty() {
        OTHER_LABEL.to_string()
    } else {
        p.name.clone()
    }
}

fn is_problem(p: &DockerProject) -> bool {
    p.verdict != "ok"
}

fn stack_view(node_id: &str, p: &DockerProject) -> StackView {
    let (tone, state_label) = match p.verdict.as_str() {
        "ok" => ("ok", "running"),
        "gone" => ("warn", "gone"),
        _ => ("err", "problem"),
    };
    let mut names: Vec<&str> = p
        .containers
        .iter()
        .filter(|c| !c.oneoff)
        .map(|c| {
            if p.name.is_empty() || c.service.is_empty() {
                c.name.as_str()
            } else {
                c.service.as_str()
            }
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    let gone = match p.gone_since {
        Some(t) if p.verdict == "gone" => {
            format!(
                "No containers left, gone {}",
                crate::handlers::stats::fmt_ago(&t)
            )
        }
        _ if p.verdict == "gone" => "No containers left".to_string(),
        _ => String::new(),
    };
    StackView {
        name: project_name(p),
        href: format!("/docker/{}/{}", enc(node_id), project_token(&p.name)),
        tone,
        state_label,
        services: names.join(", "),
        containers: p.containers.len(),
        summary: p.summary.clone(),
        gone,
        forget_action: (p.verdict == "gone" && !p.name.is_empty())
            .then(|| format!("/docker/{}/{}/forget", enc(node_id), enc(&p.name))),
        hostings: hosting_links(p),
        updates: stack_updates(p),
    }
}

fn log_warns(c: &DockerContainer) -> bool {
    c.log_size_bytes > LOG_WARN_BYTES && c.log_max_size.is_none()
}

fn biggest_logs(st: &DockerNodeStatus) -> Vec<LogView> {
    let mut all: Vec<(&DockerProject, &DockerContainer)> = st
        .projects
        .iter()
        .flat_map(|p| p.containers.iter().map(move |c| (p, c)))
        .filter(|(_, c)| c.log_size_bytes > 0)
        .collect();
    all.sort_by(|a, b| b.1.log_size_bytes.cmp(&a.1.log_size_bytes));
    all.into_iter()
        .take(BIGGEST_LOGS)
        .map(|(p, c)| LogView {
            stack: project_name(p),
            container: c.name.clone(),
            size: crate::handlers::stats::fmt_bytes(
                &(c.log_size_bytes.min(i64::MAX as u64) as i64),
            ),
            warn: log_warns(c),
        })
        .collect()
}

fn disk_view(st: &DockerNodeStatus) -> Option<DiskView> {
    let d = st.disk.as_ref()?;
    let b = |v: u64| crate::handlers::stats::fmt_bytes(&(v.min(i64::MAX as u64) as i64));
    Some(DiskView {
        images: b(d.images_bytes),
        volumes: b(d.volumes_bytes),
        build_cache: b(d.build_cache_bytes),
        read: crate::handlers::stats::fmt_ago(&d.read_at),
    })
}

fn remove_body(label: &str) -> String {
    format!(
        "Deletes what Hyperion kept about Docker on {label}: remembered stacks, open alerts, \
         the cached disk figures, image-update answers and restart-loop history. URL checks are \
         kept and the module stays on for the cluster. Docker itself, its containers, images and \
         volumes are left alone."
    )
}

fn node_view(row: &NodeDockerRow) -> NodeView {
    let id = enc(&row.node_id);
    let mut v = NodeView {
        label: row.label.clone(),
        kind: "ok",
        daemon_error: None,
        stale_stacks: false,
        read: String::new(),
        stacks: Vec::new(),
        logs: Vec::new(),
        log_warnings: 0,
        disk: None,
        has_updates: false,
        remove_action: format!("/docker/nodes/{id}/remove"),
        remove_body: remove_body(&row.label),
    };
    match &row.status {
        NodeDockerState::OldAgent => v.kind = "old",
        NodeDockerState::Unreachable => v.kind = "down",
        NodeDockerState::Ok(st) => {
            if !st.daemon_ok {
                v.daemon_error = Some(
                    st.daemon_error
                        .clone()
                        .unwrap_or_else(|| "the Docker daemon did not answer".to_string()),
                );
                v.stale_stacks = !st.projects.is_empty();
            }
            v.read = crate::handlers::stats::fmt_ago(&st.read_at);
            let mut projects: Vec<&DockerProject> = st.projects.iter().collect();
            // Problems first, then by name; the catch-all group last.
            projects.sort_by(|a, b| {
                (!is_problem(a), a.name.is_empty(), &a.name).cmp(&(
                    !is_problem(b),
                    b.name.is_empty(),
                    &b.name,
                ))
            });
            v.stacks = projects
                .into_iter()
                .map(|p| stack_view(&row.node_id, p))
                .collect();
            v.logs = biggest_logs(st);
            v.log_warnings = st
                .projects
                .iter()
                .flat_map(|p| &p.containers)
                .filter(|c| log_warns(c))
                .count();
            v.disk = disk_view(st);
            v.has_updates = v.stacks.iter().any(|s| !s.updates.is_empty());
        }
    }
    v
}

fn verdict(rows: &[NodeDockerRow]) -> Verdict {
    if rows.is_empty() {
        return Verdict {
            tone: "muted",
            line: "No node runs the Docker module yet".into(),
            counts: String::new(),
        };
    }
    let mut stacks = 0usize;
    let mut quiet = 0usize;
    for r in rows {
        match &r.status {
            NodeDockerState::Ok(st) => stacks += st.projects.len(),
            NodeDockerState::OldAgent | NodeDockerState::Unreachable => quiet += 1,
        }
    }
    let problems = problem_count(rows);
    let on = plural(rows.len(), "node", "nodes");
    let unreachable = rows
        .iter()
        .filter(|r| matches!(r.status, NodeDockerState::Unreachable))
        .count();
    let counts = if quiet > 0 {
        format!(
            "{} on {on}, {} not read",
            plural(stacks, "stack", "stacks"),
            quiet
        )
    } else {
        format!("{} on {on}", plural(stacks, "stack", "stacks"))
    };
    let (tone, line) = if problems == 0 && quiet == 0 {
        ("ok", "Everything is running".to_string())
    } else if problems == 0 {
        (
            "warn",
            "Nothing is wrong on the nodes that answered".to_string(),
        )
    } else if unreachable > 0 && problems == unreachable as i64 {
        (
            "warn",
            plural(unreachable, "node did not answer", "nodes did not answer"),
        )
    } else {
        (
            "err",
            format!(
                "{} to look at",
                plural(problems as usize, "problem", "problems")
            ),
        )
    };
    Verdict { tone, line, counts }
}

// ---------------------------------------------------------------------------
// GET /docker
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct DockerQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_error: Option<String>,
}

#[derive(Template)]
#[template(path = "docker.html")]
struct DockerTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    is_admin: bool,
    verdict: Verdict,
    nodes: Vec<NodeView>,
    /// Nodes the module is not turned on for, with the button to do it.
    offers: Vec<OfferView>,
    /// Set when a node's answer failed authentication.
    node_auth_warning: Option<String>,
    /// Nodes that did not answer, by name.
    silent: Vec<String>,
    flash: Option<String>,
    flash_error: Option<String>,
}

pub async fn get_docker(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<DockerQuery>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(Redirect::to("/").into_response());
    }
    let list = match registry(&state).await {
        Ok(l) => l,
        Err(e) => return Err(AppError::Rpc(e)),
    };
    if !list.cluster_installed {
        return Ok(if ctx.is_admin_or_higher() {
            Redirect::to("/settings/panel#docker-module")
        } else {
            Redirect::to("/")
        }
        .into_response());
    }

    let (rows, failed) = collect_for(&state, &list).await;
    let node_auth_warning = crate::handlers::node_auth_warning(&failed);

    let silent: Vec<String> = rows
        .iter()
        .filter(|r| matches!(r.status, NodeDockerState::Unreachable))
        .map(|r| r.label.clone())
        .collect();

    // Nodes with something to look at first; the order of the rest is kept.
    let mut flagged: Vec<(bool, NodeView)> = rows
        .iter()
        .map(|r| (problem_count(std::slice::from_ref(r)) == 0, node_view(r)))
        .collect();
    flagged.sort_by_key(|(quiet, _)| *quiet);
    let nodes: Vec<NodeView> = flagged.into_iter().map(|(_, v)| v).collect();

    // Offers: the master and every enrolled node that does not run it yet.
    let mut offers: Vec<OfferView> = Vec::new();
    if ctx.is_admin_or_higher() {
        let enrolled = crate::handlers::hostings::fetch_remote_nodes(&state)
            .await
            .unwrap_or_default();
        let has = |id: &str| list.nodes.iter().any(|n| n.node_id == id);
        if !has(LOCAL_NODE_SENTINEL) {
            offers.push(OfferView {
                label: "master".into(),
                install_action: format!("/docker/nodes/{LOCAL_NODE_SENTINEL}/install"),
            });
        }
        for n in enrolled.iter().filter(|n| !has(&n.node_id)) {
            offers.push(OfferView {
                label: node_label(n),
                install_action: format!("/docker/nodes/{}/install", enc(&n.node_id)),
            });
        }
    }

    let tpl = DockerTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "docker",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        is_admin: ctx.is_admin_or_higher(),
        verdict: verdict(&rows),
        nodes,
        offers,
        node_auth_warning,
        silent,
        flash: q.flash,
        flash_error: q.flash_error,
    };
    Ok(Html(tpl.render()?).into_response())
}

// ---------------------------------------------------------------------------
// GET /docker/:node/:project
// ---------------------------------------------------------------------------

struct ContainerView {
    name: String,
    service: String,
    image: String,
    tone: &'static str,
    state: String,
    exit: String,
    restarts: i64,
    started: String,
    ports: String,
    cpu: String,
    memory: String,
    log: String,
    log_warn: bool,
    /// What the daily image check says about this container's image.
    update: Option<UpdatePill>,
    /// Why it could not be checked, for "cannot verify" only.
    update_reason: String,
    /// "3 hours ago", when there is an answer.
    update_checked: String,
    /// Why the latest check failed, when the answer shown is an older one.
    update_error: String,
}

#[derive(Template)]
#[template(path = "docker_stack.html")]
struct StackTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    node_label: String,
    name: String,
    tone: &'static str,
    state_label: &'static str,
    summary: String,
    gone: String,
    forget_action: Option<String>,
    can_forget: bool,
    containers: Vec<ContainerView>,
    /// Some container logs past 1 GiB with no `max-size`.
    log_warning: bool,
    /// Some container has an image answer, so the page says how it is made.
    update_note: bool,
    disk: Option<DiskView>,
    read: String,
    stats_note: String,
    daemon_error: Option<String>,
    /// The log viewer, for readers who hold `DockerLogs`.
    logs: Option<LogsPanel>,
    /// Reverse proxies: the hostings already pointing here and what could be
    /// added. `None` for a stack with no containers.
    proxy: Option<ProxyView>,
}

/// One port a reverse proxy could forward to.
struct ProxyOfferView {
    /// `http://127.0.0.1:18080`, what the hosting would forward to.
    url: String,
    /// "web, container port 80".
    what: String,
    /// Open on every address; the warning explains the consequence.
    public_bind: bool,
    /// The compose line that keeps it behind the proxy.
    compose_hint: String,
    /// The wizard, prefilled.
    href: String,
}

struct ConflictView {
    host: u16,
    container: u16,
}

struct ProxyView {
    hostings: Vec<HostingLink>,
    offers: Vec<ProxyOfferView>,
    /// Host ports 80 and 443, which nginx owns.
    conflicts: Vec<ConflictView>,
    /// Ports bound to one address `127.0.0.1` does not reach.
    elsewhere: Vec<String>,
    /// The reader may open the wizard.
    can_create: bool,
}

/// What a stack's published ports allow. Offers are one per host port: the
/// same port on `0.0.0.0` and `::` is one app, and public if any bind is.
fn proxy_view(node_id: &str, p: &DockerProject, can_create: bool) -> Option<ProxyView> {
    use hyperion_core::service::{proxy_offer, ProxyOffer};
    if p.containers.is_empty() {
        return None;
    }
    let mut offers: std::collections::BTreeMap<u16, ProxyOfferView> = Default::default();
    let mut conflicts: Vec<ConflictView> = Vec::new();
    let mut elsewhere: Vec<String> = Vec::new();
    for c in &p.containers {
        for port in &c.ports {
            match proxy_offer(port) {
                ProxyOffer::Offer { url, public_bind } => {
                    let what = if c.service.is_empty() {
                        format!("{}, container port {}", c.name, port.container_port)
                    } else {
                        format!("{}, container port {}", c.service, port.container_port)
                    };
                    let e = offers.entry(port.host_port).or_insert_with(|| ProxyOfferView {
                        href: format!(
                            "/hostings/new?site_type=reverse_proxy&proxy_upstream_url={}&target_node={}",
                            enc(&url),
                            enc(node_id)
                        ),
                        compose_hint: format!(
                            "127.0.0.1:{}:{}",
                            port.host_port, port.container_port
                        ),
                        url,
                        what,
                        public_bind: false,
                    });
                    e.public_bind |= public_bind;
                }
                ProxyOffer::Conflict => conflicts.push(ConflictView {
                    host: port.host_port,
                    container: port.container_port,
                }),
                ProxyOffer::OtherAddress => {
                    elsewhere.push(format!("{}:{}", port.host_ip, port.host_port))
                }
                ProxyOffer::NotTcp => {}
            }
        }
    }
    conflicts.sort_by_key(|c| (c.host, c.container));
    conflicts.dedup_by_key(|c| (c.host, c.container));
    elsewhere.sort();
    elsewhere.dedup();
    Some(ProxyView {
        hostings: hosting_links(p),
        offers: offers.into_values().collect(),
        conflicts,
        elsewhere,
        can_create,
    })
}

fn container_tone(c: &DockerContainer) -> &'static str {
    let unhealthy = c.health.as_deref() == Some("unhealthy");
    match c.state.as_str() {
        _ if c.oom_killed || unhealthy => "err",
        "restarting" | "dead" => "err",
        "running" => "ok",
        "exited" if c.finished_job() => "muted",
        "exited" => "err",
        "created" if c.failed_to_start() => "err",
        _ => "muted",
    }
}

fn container_view(c: &DockerContainer) -> ContainerView {
    let mut state = c.state.clone();
    if let Some(h) = &c.health {
        state.push_str(&format!(" ({h})"));
    }
    let exit = if c.state == "exited" || c.oom_killed {
        let mut s = format!("exit {}", c.exit_code);
        if c.oom_killed {
            s.push_str(", out of memory");
        }
        s
    } else {
        String::new()
    };
    let mut ports: Vec<String> = c
        .ports
        .iter()
        .filter(|p| p.host_port != 0)
        .map(|p| {
            let ip = if p.host_ip.is_empty() {
                "0.0.0.0"
            } else {
                p.host_ip.as_str()
            };
            format!("{ip}:{}→{}/{}", p.host_port, p.container_port, p.proto)
        })
        .collect();
    ports.sort();
    ports.dedup();
    let b = |v: u64| crate::handlers::stats::fmt_bytes(&(v.min(i64::MAX as u64) as i64));
    ContainerView {
        name: c.name.clone(),
        service: c.service.clone(),
        image: c.image.clone(),
        tone: container_tone(c),
        state,
        exit,
        restarts: c.restart_count,
        started: if c.started_at > 0 {
            crate::handlers::stats::fmt_ago(&c.started_at)
        } else {
            String::new()
        },
        ports: ports.join(", "),
        cpu: c
            .cpu_pct_x100
            .map(|v| format!("{}.{:02}%", v / 100, (v % 100).abs()))
            .unwrap_or_default(),
        memory: c.mem_bytes.map(b).unwrap_or_default(),
        log: if c.log_size_bytes > 0 {
            b(c.log_size_bytes)
        } else {
            String::new()
        },
        log_warn: log_warns(c),
        update: c.update.as_ref().map(update_pill),
        update_reason: match &c.update {
            Some(ImageUpdateState::CannotVerify { reason }) => reason
                .chars()
                .filter(|ch| !ch.is_control())
                .take(REASON_MAX_CHARS)
                .collect(),
            _ => String::new(),
        },
        update_error: c
            .update_error
            .chars()
            .filter(|ch| !ch.is_control())
            .take(REASON_MAX_CHARS)
            .collect(),
        update_checked: if c.update.is_some() && c.update_checked_at > 0 {
            crate::handlers::stats::fmt_ago(&c.update_checked_at)
        } else {
            String::new()
        },
    }
}

/// The URL's project segment as the module's project name. `None` for
/// anything that cannot be a name: the page answers 404 without echoing it.
fn project_from_url(raw: &str) -> Option<String> {
    if raw == OTHER_TOKEN {
        return Some(String::new());
    }
    let ok = !raw.is_empty()
        && raw.chars().count() <= NAME_MAX_CHARS
        && !raw.chars().any(|c| c.is_control());
    ok.then(|| raw.to_string())
}

pub async fn get_docker_stack(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path((node, project)): Path<(String, String)>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(Redirect::to("/").into_response());
    }
    let list = registry(&state).await.map_err(AppError::Rpc)?;
    if !list.cluster_installed {
        return Ok(Redirect::to("/").into_response());
    }
    let canonical = registered_target(&state, &list, &node)
        .await
        .ok_or(AppError::NotFound)?;
    let name = project_from_url(&project).ok_or(AppError::NotFound)?;
    let label = if canonical == LOCAL_NODE_SENTINEL {
        "master".to_string()
    } else {
        crate::handlers::hostings::fetch_remote_nodes(&state)
            .await
            .unwrap_or_default()
            .iter()
            .find(|n| n.node_id == canonical)
            .map(node_label)
            .unwrap_or_else(|| canonical.clone())
    };
    let st = match crate::dispatcher::dispatch_to_node(
        &state,
        dispatch_target(&canonical),
        Request::DockerOverview,
    )
    .await
    {
        Ok(RpcResponse::DockerOverview(st)) => st,
        Ok(RpcResponse::Error(e)) => return Err(AppError::Rpc(e.to_string())),
        Ok(_) => return Err(AppError::Internal("unexpected agent response".into())),
        Err(e) => return Err(AppError::Rpc(e.to_string())),
    };
    let p = st
        .projects
        .iter()
        .find(|p| p.name == name)
        .ok_or(AppError::NotFound)?;
    let sv = stack_view(&canonical, p);
    let mut containers: Vec<ContainerView> = p.containers.iter().map(container_view).collect();
    containers.sort_by(|a, b| (a.tone == "ok", &a.name).cmp(&(b.tone == "ok", &b.name)));
    let proxy = proxy_view(&canonical, p, ctx.can(Capability::HostingCreate));
    let tpl = StackTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "docker",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        node_label: label,
        name: sv.name,
        tone: sv.tone,
        state_label: sv.state_label,
        summary: sv.summary,
        gone: sv.gone,
        forget_action: sv.forget_action,
        can_forget: ctx.is_admin_or_higher(),
        log_warning: containers.iter().any(|c| c.log_warn),
        update_note: containers.iter().any(|c| c.update.is_some()),
        containers,
        disk: disk_view(&st),
        read: crate::handlers::stats::fmt_ago(&st.read_at),
        stats_note: if st.stats_at > 0 {
            format!(
                "CPU and memory read {}",
                crate::handlers::stats::fmt_ago(&st.stats_at)
            )
        } else {
            String::new()
        },
        daemon_error: (!st.daemon_ok).then(|| {
            st.daemon_error
                .clone()
                .unwrap_or_else(|| "the Docker daemon did not answer".to_string())
        }),
        logs: (logs_allowed(&ctx) && !p.containers.is_empty()).then(|| {
            LogsPanel::closed(
                &canonical,
                &name,
                p.containers.iter().map(|c| c.name.clone()).collect(),
            )
        }),
        proxy,
    };
    Ok(Html(tpl.render()?).into_response())
}

// ---------------------------------------------------------------------------
// GET /docker/hosting-chip?selector=
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct ChipQuery {
    #[serde(default)]
    pub selector: String,
}

#[derive(Template)]
#[template(path = "_docker_chip.html")]
struct ChipTpl {
    name: String,
    href: String,
    tone: &'static str,
    state_label: &'static str,
    summary: String,
}

/// The stack behind one reverse-proxy hosting, as a line for the hosting's
/// page. Lazy, and silent: whatever goes wrong or does not match, the answer
/// is an empty body, never an error in the middle of someone else's page. It
/// names the one matching stack and carries no container or log detail.
pub async fn get_hosting_chip(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<ChipQuery>,
) -> Response {
    let nothing = || Html(String::new()).into_response();
    if !allowed(&ctx) || q.selector.is_empty() || q.selector.chars().count() > NAME_MAX_CHARS {
        return nothing();
    }
    match hosting_chip(&state, &q.selector).await {
        Some(tpl) => tpl
            .render()
            .map(|h| Html(h).into_response())
            .unwrap_or_else(|_| nothing()),
        None => nothing(),
    }
}

async fn hosting_chip(state: &SharedState, selector: &str) -> Option<ChipTpl> {
    let sel = crate::handlers::hostings::parse_selector_public(selector).ok()?;
    let list = registry(state).await.ok()?;
    if !list.cluster_installed {
        return None;
    }
    let (detail, node) = crate::handlers::hostings::find_hosting_anywhere(state, sel)
        .await
        .ok()?;
    if detail.kind != "reverse_proxy" {
        return None;
    }
    let canonical =
        registered_target(state, &list, node.as_deref().unwrap_or(LOCAL_NODE_SENTINEL)).await?;
    let st = match crate::dispatcher::dispatch_to_node(
        state,
        dispatch_target(&canonical),
        Request::DockerOverview,
    )
    .await
    {
        Ok(RpcResponse::DockerOverview(st)) => st,
        _ => return None,
    };
    let p = st.projects.iter().find(|p| {
        p.hostings
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&detail.domain))
    })?;
    let sv = stack_view(&canonical, p);
    let (tone, state_label) = if st.daemon_ok {
        (sv.tone, sv.state_label)
    } else {
        ("warn", "Docker not answering")
    };
    Some(ChipTpl {
        name: sv.name,
        href: sv.href,
        tone,
        state_label,
        summary: sv.summary,
    })
}

// ---------------------------------------------------------------------------
// GET /docker/:node/:project/logs
// ---------------------------------------------------------------------------

/// How the viewer polls while "Follow" is on.
const LOG_POLL_NOTE: &str = "Following stopped. Press Refresh to read the log again.";
/// What the "Lines" menu offers.
const LINE_CHOICES: [u32; 6] = [50, 100, 200, 500, 1000, 2000];
/// Longest filter the form sends; the node enforces its own limit too.
const FILTER_MAX_CHARS: usize = 200;

struct LogRow {
    time: String,
    service: String,
    text: String,
}

/// Everything `_docker_logs.html` draws. Askama escapes every field.
struct LogsPanel {
    /// Where the form (and the follow poll) asks.
    action: String,
    containers: Vec<String>,
    /// The container chosen; empty for all of them.
    container: String,
    lines: u32,
    filter: String,
    follow: bool,
    /// The log has been read, as opposed to the form on its own.
    opened: bool,
    rows: Vec<LogRow>,
    show_service: bool,
    note: String,
    error: Option<String>,
    /// Said in place of more rows when following has ended.
    stopped: Option<String>,
    /// Proof that this session already opened this log, so changing the
    /// filter or the line count does not write another audit entry.
    opened_proof: Option<String>,
    /// The next follow request; `None` means nothing polls.
    poll_url: Option<String>,
    /// Only rows and the next poll element: the answer to a follow poll.
    append: bool,
}

struct Choice {
    value: String,
    selected: bool,
}

impl LogsPanel {
    /// "All containers" is the empty value; the named one is selected.
    fn container_choices(&self) -> Vec<Choice> {
        self.containers
            .iter()
            .map(|c| Choice {
                value: c.clone(),
                selected: *c == self.container,
            })
            .collect()
    }

    fn line_options(&self) -> Vec<Choice> {
        LINE_CHOICES
            .iter()
            .map(|n| Choice {
                value: n.to_string(),
                selected: *n == self.lines,
            })
            .collect()
    }

    fn closed(node: &str, project: &str, containers: Vec<String>) -> Self {
        Self {
            action: logs_action(node, project),
            containers,
            container: String::new(),
            lines: DEFAULT_LOG_LINES,
            filter: String::new(),
            follow: false,
            opened: false,
            rows: Vec::new(),
            show_service: true,
            note: String::new(),
            error: None,
            stopped: None,
            opened_proof: None,
            poll_url: None,
            append: false,
        }
    }
}

fn logs_action(node: &str, project: &str) -> String {
    format!("/docker/{}/{}/logs", enc(node), project_token(project))
}

#[derive(Deserialize, Default)]
pub struct LogsQuery {
    #[serde(default)]
    pub container: Option<String>,
    #[serde(default)]
    pub lines: Option<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub follow: Option<String>,
    /// Where the last answer ended, with `proof` that this page was given it.
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
    /// Present on the requests the follow element makes.
    #[serde(default)]
    pub poll: Option<String>,
    /// Proof that this session already opened this log.
    #[serde(default)]
    pub opened: Option<String>,
}

#[derive(Template)]
#[template(path = "_docker_logs.html")]
struct LogsTpl {
    logs: LogsPanel,
}

/// What a cursor or an "already opened" token is bound to, besides the
/// session: the node, the stack and the container, so one cannot be used to
/// read somewhere else without a record.
fn log_proof_scope(kind: &str, node: &str, project: &str, container: &str, extra: &str) -> String {
    format!("docker-log:{kind}|{node}|{project}|{container}|{extra}")
}

fn session_id(ctx: &AuthCtx) -> String {
    ctx.session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default()
}

fn mint_log_proof(state: &SharedState, ctx: &AuthCtx, scope: &str) -> String {
    hyperion_auth::csrf::mint(
        state.csrf_key.as_ref(),
        &session_id(ctx),
        scope,
        hyperion_types::now_secs(),
    )
}

fn log_proof_ok(state: &SharedState, ctx: &AuthCtx, scope: &str, token: Option<&str>) -> bool {
    token.is_some_and(|t| {
        hyperion_auth::csrf::verify(
            state.csrf_key.as_ref(),
            &session_id(ctx),
            scope,
            t,
            hyperion_types::now_secs(),
        )
    })
}

fn short_ts(ts: &str) -> String {
    ts.chars().take(19).collect::<String>().replace('T', " ")
}

fn truthy(v: &Option<String>) -> bool {
    v.as_deref()
        .is_some_and(|v| !v.is_empty() && v != "0" && v != "off" && v != "false")
}

/// GET /docker/:node/:project/logs — the log viewer's rows, for htmx. Reading
/// a log needs `DockerLogs` on top of seeing every tenant. The container the
/// form names is only ever a name the node looks up in its own inspect
/// result.
///
/// A person opening a log is audited once. A follow poll carries the cursor
/// the previous answer handed out, signed for this session, this log and that
/// cursor, so a poll cannot be forged to read an old part of the log without
/// the open that comes first; one whose proof does not check out ends the
/// following instead of reading anything.
pub async fn get_docker_logs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path((node, project)): Path<(String, String)>,
    Query(q): Query<LogsQuery>,
) -> Result<Response, AppError> {
    if !logs_allowed(&ctx) {
        return Err(AppError::Forbidden);
    }
    let list = registry(&state).await.map_err(AppError::Rpc)?;
    if !list.cluster_installed {
        return Err(AppError::NotFound);
    }
    let canonical = registered_target(&state, &list, &node)
        .await
        .ok_or(AppError::NotFound)?;
    let name = project_from_url(&project).ok_or(AppError::NotFound)?;

    let container = q
        .container
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_string);
    if container
        .as_deref()
        .is_some_and(|c| c.chars().count() > NAME_MAX_CHARS || c.chars().any(|c| c.is_control()))
    {
        return Err(AppError::NotFound);
    }
    let container_key = container.clone().unwrap_or_default();
    let lines = q
        .lines
        .as_deref()
        .and_then(|l| l.trim().parse::<u32>().ok())
        .filter(|n| (1..=MAX_LOG_LINES).contains(n))
        .unwrap_or(DEFAULT_LOG_LINES);
    let filter: String = q
        .filter
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(FILTER_MAX_CHARS)
        .collect();
    let follow = truthy(&q.follow);
    let is_poll = q.poll.is_some();

    let cursor_scope =
        |cursor: &str| log_proof_scope("cursor", &canonical, &name, &container_key, cursor);
    let open_scope = log_proof_scope("open", &canonical, &name, &container_key, "");
    let cursor = q
        .cursor
        .as_deref()
        .filter(|c| !c.is_empty())
        .filter(|c| log_proof_ok(&state, &ctx, &cursor_scope(c), q.proof.as_deref()))
        .map(str::to_string);

    let mut panel = LogsPanel::closed(&canonical, &name, Vec::new());
    panel.container = container_key.clone();
    panel.lines = lines;
    panel.filter = filter.clone();
    panel.follow = follow;
    panel.opened = true;
    panel.append = is_poll;

    if is_poll && cursor.is_none() {
        // Nothing to read from: the page's cursor is not one this session
        // was given.
        panel.stopped = Some(LOG_POLL_NOTE.to_string());
        return render_logs(panel);
    }

    let already_opened = log_proof_ok(&state, &ctx, &open_scope, q.opened.as_deref());
    let audit_actor = (cursor.is_none() && !already_opened).then(|| ctx.username.clone());

    // The containers for the menu come from the node's own list.
    let answer = crate::dispatcher::dispatch_to_node(
        &state,
        dispatch_target(&canonical),
        Request::DockerLogs(DockerLogRequest {
            project: name.clone(),
            container: container.clone(),
            lines,
            since_cursor: cursor.clone(),
            filter: (!filter.is_empty()).then(|| filter.clone()),
            audit_actor,
        }),
    )
    .await;
    if !is_poll {
        panel.containers = stack_container_names(&state, &canonical, &name).await;
    }
    match answer {
        Ok(RpcResponse::DockerLogs(chunk)) => {
            panel.show_service = container.is_none();
            panel.rows = chunk
                .lines
                .into_iter()
                .map(|l| LogRow {
                    time: short_ts(&l.ts),
                    service: l.service,
                    text: l.text,
                })
                .collect();
            let mut notes: Vec<String> = Vec::new();
            if chunk.truncated {
                notes.push(
                    "The log is longer than one page can hold, so older lines are left out."
                        .to_string(),
                );
            }
            if chunk.unreadable > 0 {
                notes.push(format!(
                    "{} could not be read.",
                    plural(chunk.unreadable as usize, "container", "containers")
                ));
            }
            panel.note = notes.join(" ");
            panel.opened_proof = Some(mint_log_proof(&state, &ctx, &open_scope));
            if follow {
                // A log with nothing in it yet has no cursor; "0" reads from
                // the start, which is nothing, so the first line is news.
                let next = chunk.cursor.as_deref().unwrap_or("0");
                let proof = mint_log_proof(&state, &ctx, &cursor_scope(next));
                panel.poll_url = Some(poll_url(
                    &panel.action,
                    container.as_deref(),
                    lines,
                    &filter,
                    next,
                    &proof,
                ));
            }
        }
        Ok(RpcResponse::Error(e)) => {
            panel.error = Some(e.to_string());
            if is_poll {
                panel.stopped = Some(LOG_POLL_NOTE.to_string());
            }
        }
        Ok(_) => {
            panel.error = Some("The node sent something unexpected.".to_string());
        }
        Err(e) => {
            panel.error = Some(format!("The node did not answer: {e}"));
            if is_poll {
                panel.stopped = Some(LOG_POLL_NOTE.to_string());
            }
        }
    }
    render_logs(panel)
}

/// The URL the follow element asks, carrying everything the next answer
/// needs. The values are percent-encoded; Askama escapes the whole for HTML.
fn poll_url(
    action: &str,
    container: Option<&str>,
    lines: u32,
    filter: &str,
    cursor: &str,
    proof: &str,
) -> String {
    let mut u = format!("{action}?lines={lines}&follow=on&poll=1");
    if let Some(c) = container {
        u.push_str(&format!("&container={}", enc(c)));
    }
    if !filter.is_empty() {
        u.push_str(&format!("&filter={}", enc(filter)));
    }
    u.push_str(&format!("&cursor={}&proof={}", enc(cursor), enc(proof)));
    u
}

/// The container names of a stack, for the menu, from the node's overview.
/// A node that cannot say just leaves the menu with "All containers".
async fn stack_container_names(state: &SharedState, canonical: &str, project: &str) -> Vec<String> {
    match crate::dispatcher::dispatch_to_node(
        state,
        dispatch_target(canonical),
        Request::DockerOverview,
    )
    .await
    {
        Ok(RpcResponse::DockerOverview(st)) => st
            .projects
            .iter()
            .find(|p| p.name == project)
            .map(|p| p.containers.iter().map(|c| c.name.clone()).collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn render_logs(panel: LogsPanel) -> Result<Response, AppError> {
    let tpl = LogsTpl { logs: panel };
    let mut resp = Html(tpl.render()?).into_response();
    // Log text is not something to keep in a cache or a history entry.
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

fn admin_only(ctx: &AuthCtx) -> Result<(), AppError> {
    if ctx.is_admin_or_higher() && allowed(ctx) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn settings_card(query: &str) -> String {
    crate::handlers::settings::chrome::card_url("docker-module", query)
}

/// POST /docker/install-cluster — bookkeeping only; nodes are turned on one
/// by one afterwards.
pub async fn post_install_cluster(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    admin_only(&ctx)?;
    let dest = match crate::dispatcher::dispatch_to_node(
        &state,
        None,
        Request::DockerClusterInstall,
    )
    .await
    {
        Ok(RpcResponse::DockerModule(_)) => "/docker".to_string(),
        Ok(RpcResponse::Error(e)) => settings_card(&format!("flash_error={}", enc(&e.to_string()))),
        Ok(_) => return Err(AppError::Internal("unexpected agent response".into())),
        Err(e) => settings_card(&format!("flash_error={}", enc(&e.to_string()))),
    };
    // The sidebar must show the entry now, not when the minute is up.
    state.caches.nav_dots.invalidate();
    Ok(Redirect::to(&dest).into_response())
}

/// POST /docker/remove-cluster — turns the module off everywhere. Every
/// registered node is asked first; one that does not answer is reported and
/// stays registered, and the module stays on until it is gone.
pub async fn post_remove_cluster(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    admin_only(&ctx)?;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "docker_cluster_remove",
        None,
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            let list = match registry(&job_state).await {
                Ok(l) => l,
                Err(e) => {
                    reporter.finish(false, Some(e)).await;
                    return;
                }
            };
            let total = list.nodes.len().max(1) as i64;
            let mut failed: Vec<String> = Vec::new();
            let mut log = String::new();
            for (i, n) in list.nodes.iter().enumerate() {
                let label = node_display(&job_state, &n.node_id).await;
                reporter
                    .step(
                        &format!("Removing the module from {label}…"),
                        (i as i64) * 90 / total,
                        "",
                    )
                    .await;
                match remove_on_node(&job_state, &n.node_id).await {
                    Ok(()) => log.push_str(&format!("{label}: removed.\n")),
                    Err(why) => {
                        log.push_str(&format!("{label}: {why}\n"));
                        failed.push(label);
                    }
                }
            }
            if !failed.is_empty() {
                reporter.step("Some nodes did not answer.", 95, &log).await;
                reporter
                    .finish(
                        false,
                        Some(format!(
                            "The module stays on because {} did not answer. It is still listed, so \
                             you can remove it there when the node is back.",
                            failed.join(", ")
                        )),
                    )
                    .await;
                job_state.caches.nav_dots.invalidate();
                return;
            }
            reporter
                .step("Turning the module off for the cluster…", 95, &log)
                .await;
            match crate::dispatcher::dispatch_to_node(
                &job_state,
                None,
                Request::DockerClusterRemove,
            )
            .await
            {
                Ok(RpcResponse::DockerModule(_)) => {
                    job_state.caches.nav_dots.invalidate();
                    reporter.step("Removed.", 100, "").await;
                    reporter.finish(true, None).await;
                }
                Ok(RpcResponse::Error(e)) => reporter.finish(false, Some(e.to_string())).await,
                Ok(_) => {
                    reporter
                        .finish(false, Some("unexpected agent response".into()))
                        .await
                }
                Err(e) => reporter.finish(false, Some(e.to_string())).await,
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

/// "master", or the node's label.
async fn node_display(state: &SharedState, canonical: &str) -> String {
    if canonical == LOCAL_NODE_SENTINEL {
        return "master".to_string();
    }
    crate::handlers::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default()
        .iter()
        .find(|n| n.node_id == canonical)
        .map(node_label)
        .unwrap_or_else(|| canonical.to_string())
}

/// Turn the module off on one node, then forget it on the master. A node the
/// master no longer has is forgotten without asking it. Anything else that
/// goes wrong leaves it registered and says why.
async fn remove_on_node(state: &SharedState, canonical: &str) -> Result<(), String> {
    match crate::dispatcher::dispatch_to_node(
        state,
        dispatch_target(canonical),
        Request::DockerNodeRemove,
    )
    .await
    {
        Ok(RpcResponse::DockerModule(_)) => {}
        Ok(RpcResponse::Error(e)) => return Err(e.to_string()),
        Ok(_) => return Err("unexpected agent response".into()),
        // Enrolled once, gone now: there is nothing left to switch off.
        Err(DispatchError::UnknownNode(_)) => {}
        Err(e) if crate::cluster_sync::is_old_agent(&e) => {
            return Err("runs an older agent that does not know the Docker module".into())
        }
        Err(e) => return Err(format!("did not answer ({e})")),
    }
    register(state, canonical, false).await
}

async fn register(state: &SharedState, canonical: &str, installed: bool) -> Result<(), String> {
    match crate::dispatcher::dispatch_to_node(
        state,
        None,
        Request::DockerNodeRegister {
            node_id: canonical.to_string(),
            installed,
        },
    )
    .await
    {
        Ok(RpcResponse::DockerNodeRegistered) => Ok(()),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected agent response".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// The node a write names, which must be this panel's master or one of its
/// enrolled workers. Anything else is a 404 before any job exists.
async fn writable_target(state: &SharedState, raw: &str) -> Result<String, AppError> {
    let canonical = canonical_node(state, raw).await;
    if canonical == LOCAL_NODE_SENTINEL {
        return Ok(canonical);
    }
    let enrolled = crate::handlers::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default();
    if enrolled.iter().any(|n| n.node_id == canonical) {
        return Ok(canonical);
    }
    Err(AppError::NotFound)
}

/// POST /docker/nodes/:node/install — checks Docker on the node, turns the
/// module on there and records it on the master. Background job.
pub async fn post_node_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(node): Path<String>,
) -> Result<Response, AppError> {
    admin_only(&ctx)?;
    // With the module off for the cluster a node must not be turned on by a
    // direct POST: nothing lists it, and the nav would stay hidden.
    if !registry(&state)
        .await
        .map_err(AppError::Rpc)?
        .cluster_installed
    {
        return Err(AppError::BadRequest(
            "The Docker module is not turned on. Turn it on in Settings first.".into(),
        ));
    }
    let canonical = writable_target(&state, &node).await?;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let target = canonical.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "docker_node_install",
        Some(&canonical),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            let label = node_display(&job_state, &target).await;
            reporter
                .step(&format!("Checking that Docker answers on {label}…"), 10, "")
                .await;
            let version = match crate::dispatcher::dispatch_to_node(
                &job_state,
                dispatch_target(&target),
                Request::DockerNodeInstall,
            )
            .await
            {
                Ok(RpcResponse::DockerModule(st)) => st.docker_version.unwrap_or_default(),
                Ok(RpcResponse::Error(e)) => {
                    reporter.finish(false, Some(e.to_string())).await;
                    return;
                }
                Ok(_) => {
                    reporter
                        .finish(false, Some("unexpected agent response".into()))
                        .await;
                    return;
                }
                Err(e) if crate::cluster_sync::is_old_agent(&e) => {
                    reporter
                        .finish(
                            false,
                            Some(format!(
                                "{label} runs an older agent that does not know the Docker \
                                 module. Update the node first."
                            )),
                        )
                        .await;
                    return;
                }
                Err(e) => {
                    reporter.finish(false, Some(e.to_string())).await;
                    return;
                }
            };
            reporter
                .step(
                    "Recording the node…",
                    80,
                    &format!("Docker {version} answered on {label}.\n"),
                )
                .await;
            match register(&job_state, &target, true).await {
                Ok(()) => {
                    job_state.caches.nav_dots.invalidate();
                    reporter.step("Done.", 100, "").await;
                    reporter.finish(true, None).await;
                }
                Err(e) => {
                    // The node is on but the master does not know: the
                    // operator can run the job again, which is idempotent.
                    reporter
                        .finish(
                            false,
                            Some(format!(
                                "Docker answered on {label}, but the master could not record it \
                                 ({e}). Run the install again."
                            )),
                        )
                        .await;
                }
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

/// POST /docker/nodes/:node/remove — turns the module off on the node and
/// forgets it on the master. Background job; docker is never touched.
pub async fn post_node_remove(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(node): Path<String>,
) -> Result<Response, AppError> {
    admin_only(&ctx)?;
    // A node that was enrolled and is gone is still removable from the list,
    // so only the registry is consulted here, not the enrolled nodes.
    let list = registry(&state).await.map_err(AppError::Rpc)?;
    let canonical = registered_target(&state, &list, &node)
        .await
        .ok_or(AppError::NotFound)?;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let target = canonical.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "docker_node_remove",
        Some(&canonical),
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            let label = node_display(&job_state, &target).await;
            reporter
                .step(&format!("Removing the module from {label}…"), 20, "")
                .await;
            match remove_on_node(&job_state, &target).await {
                Ok(()) => {
                    job_state.caches.nav_dots.invalidate();
                    reporter.step("Removed.", 100, "").await;
                    reporter.finish(true, None).await;
                }
                Err(why) => {
                    reporter
                        .finish(
                            false,
                            Some(format!(
                                "{label}: {why}. It stays in the list so you can remove it \
                                 later."
                            )),
                        )
                        .await
                }
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

/// POST /docker/:node/:project/forget — Hyperion's record of a stack that is
/// gone, and its alert. No container is touched.
pub async fn post_forget(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path((node, project)): Path<(String, String)>,
) -> Result<Response, AppError> {
    admin_only(&ctx)?;
    let list = registry(&state).await.map_err(AppError::Rpc)?;
    let canonical = registered_target(&state, &list, &node)
        .await
        .ok_or(AppError::NotFound)?;
    let name = project_from_url(&project).ok_or(AppError::NotFound)?;
    if name.is_empty() {
        return Ok(Redirect::to(&format!(
            "/docker?flash_error={}",
            enc("Containers without a stack cannot be forgotten.")
        ))
        .into_response());
    }
    let dest = match crate::dispatcher::dispatch_to_node(
        &state,
        dispatch_target(&canonical),
        Request::DockerForgetProject {
            project: name.clone(),
        },
    )
    .await
    {
        Ok(RpcResponse::DockerProjectForgotten) => {
            state.caches.nav_dots.invalidate();
            format!("/docker?flash={}", enc(&format!("Forgot {name}.")))
        }
        Ok(RpcResponse::Error(e)) => format!("/docker?flash_error={}", enc(&e.to_string())),
        Ok(_) => return Err(AppError::Internal("unexpected agent response".into())),
        Err(e) => format!("/docker?flash_error={}", enc(&e.to_string())),
    };
    Ok(Redirect::to(&dest).into_response())
}

// ---------------------------------------------------------------------------
// Settings card
// ---------------------------------------------------------------------------

/// What the Settings card shows: is the module on, and for how many nodes.
pub(crate) struct ModuleCard {
    pub installed: bool,
    pub nodes: usize,
    pub error: Option<String>,
}

pub(crate) async fn module_card(state: &SharedState) -> ModuleCard {
    match registry(state).await {
        Ok(l) => ModuleCard {
            installed: l.cluster_installed,
            nodes: l.nodes.len(),
            error: None,
        },
        Err(e) => ModuleCard {
            installed: false,
            nodes: 0,
            error: Some(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_rpc_client::remote::RemoteClientError;

    #[test]
    fn a_finished_job_is_muted_and_a_failed_start_is_red() {
        let exited = |policy: &str, code: i64| DockerContainer {
            state: "exited".into(),
            restart_policy: policy.into(),
            exit_code: code,
            ..Default::default()
        };
        for policy in ["", "no", "on-failure"] {
            assert_eq!(container_tone(&exited(policy, 0)), "muted", "{policy}");
            assert_eq!(container_tone(&exited(policy, 1)), "err", "{policy}");
        }
        assert_eq!(container_tone(&exited("always", 0)), "err");
        let created = |code: i64| DockerContainer {
            state: "created".into(),
            exit_code: code,
            ..Default::default()
        };
        assert_eq!(container_tone(&created(0)), "muted", "still starting");
        assert_eq!(container_tone(&created(128)), "err", "the start failed");
    }

    fn row(label: &str, status: NodeDockerState) -> NodeDockerRow {
        NodeDockerRow {
            node_id: label.into(),
            label: label.into(),
            status,
        }
    }

    fn proj(name: &str, verdict: &str) -> DockerProject {
        DockerProject {
            name: name.into(),
            verdict: verdict.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_node_with_an_older_agent_is_told_to_update_not_called_down() {
        let old = DispatchError::Remote(RemoteClientError::HttpError {
            code: Some(22),
            stderr: "400".into(),
        });
        assert!(matches!(
            classify_failure(&old),
            Some(NodeDockerState::OldAgent)
        ));
        let down = DispatchError::NoEndpoint("n".into());
        assert!(matches!(
            classify_failure(&down),
            Some(NodeDockerState::Unreachable)
        ));
        // An answer the master could not authenticate is not drawn as a node:
        // `node_auth_warning` reports it.
        let forged = DispatchError::ResponseAuthFailed {
            node_id: "n".into(),
            reason: "bad signature".into(),
        };
        assert!(classify_failure(&forged).is_none());
        // And a pin the master does not have is a node that cannot be read.
        assert!(matches!(
            classify_failure(&DispatchError::CertPinMissing {
                node_id: "n".into()
            }),
            Some(NodeDockerState::Unreachable)
        ));
    }

    #[test]
    fn old_agent_row_says_update_first() {
        let v = node_view(&row("web-2", NodeDockerState::OldAgent));
        assert_eq!(v.kind, "old");
        let tpl = DockerTpl {
            username: "kevin",
            user_initial: 'k',
            active: "docker",
            css_version: "t",
            htmx_version: "t",
            csrf_token: "tok".into(),
            is_admin: true,
            verdict: verdict(&[row("web-2", NodeDockerState::OldAgent)]),
            nodes: vec![v],
            offers: vec![],
            node_auth_warning: None,
            silent: vec![],
            flash: None,
            flash_error: None,
        };
        let html = tpl.render().expect("render");
        assert!(html.contains("Update the node first"), "{html}");
        assert!(!html.contains("did not answer"), "{html}");
    }

    #[test]
    fn problems_count_nodes_and_stacks_once() {
        let ok = |projects: Vec<DockerProject>| {
            NodeDockerState::Ok(DockerNodeStatus {
                daemon_ok: true,
                projects,
                ..Default::default()
            })
        };
        assert_eq!(problem_count(&[]), 0);
        assert_eq!(
            problem_count(&[
                row(
                    "a",
                    ok(vec![
                        proj("x", "ok"),
                        proj("y", "problem"),
                        proj("z", "gone")
                    ])
                ),
                row("b", NodeDockerState::Unreachable),
                row("c", NodeDockerState::OldAgent),
                // The daemon is the problem; its stale stacks are not counted on top.
                row(
                    "d",
                    NodeDockerState::Ok(DockerNodeStatus {
                        daemon_ok: false,
                        projects: vec![proj("q", "problem")],
                        ..Default::default()
                    })
                ),
            ]),
            // a: problem and gone; b: silent; c: needs updating, no problem; d: daemon
            4
        );
    }

    #[test]
    fn urls_name_projects_without_letting_markup_through() {
        assert_eq!(project_from_url("(other)"), Some(String::new()));
        assert_eq!(project_from_url("shop"), Some("shop".into()));
        assert_eq!(project_from_url(""), None);
        assert_eq!(project_from_url("a\nb"), None);
        assert_eq!(project_from_url(&"x".repeat(NAME_MAX_CHARS + 1)), None);
        assert_eq!(project_token(""), "%28other%29");
        assert_eq!(project_token("a<b>"), "a%3Cb%3E");
    }

    #[test]
    fn a_follow_poll_shows_why_it_stopped_and_what_was_left_out() {
        let mut p = LogsPanel::closed("local", "shop", Vec::new());
        p.append = true;
        p.opened = true;
        p.error = Some("Docker is not responding <b>now</b>".into());
        p.note = "1 container could not be read.".into();
        p.stopped = Some(LOG_POLL_NOTE.into());
        let html = LogsTpl { logs: p }.render().expect("render");
        assert!(
            html.contains("Docker is not responding &lt;b&gt;now&lt;/b&gt;"),
            "{html}"
        );
        assert!(html.contains("1 container could not be read."), "{html}");
        assert!(html.contains("Following stopped"), "{html}");
        assert!(!html.contains("id=\"docker-logs\""), "rows only: {html}");
    }

    #[test]
    fn a_big_log_without_max_size_warns() {
        let mut c = DockerContainer {
            log_size_bytes: LOG_WARN_BYTES + 1,
            ..Default::default()
        };
        assert!(log_warns(&c));
        c.log_max_size = Some("10m".into());
        assert!(!log_warns(&c), "rotation is configured");
        c.log_max_size = None;
        c.log_size_bytes = LOG_WARN_BYTES;
        assert!(!log_warns(&c), "exactly 1 GiB is not over it");
    }

    fn container_with(update: Option<ImageUpdateState>) -> DockerContainer {
        DockerContainer {
            name: "shop-web-1".into(),
            image: "nginx:alpine".into(),
            update,
            update_checked_at: 1_000_000,
            ..Default::default()
        }
    }

    #[test]
    fn the_list_badges_updates_and_stays_quiet_about_the_rest() {
        let mut p = proj("shop", "ok");
        p.containers = vec![
            container_with(Some(ImageUpdateState::UpdateAvailable)),
            container_with(Some(ImageUpdateState::UpdateAvailable)),
            container_with(Some(ImageUpdateState::NotRecreated)),
            container_with(Some(ImageUpdateState::UpToDate)),
            container_with(Some(ImageUpdateState::CannotVerify {
                reason: "pinned".into(),
            })),
            container_with(None),
        ];
        let labels: Vec<String> = stack_updates(&p).into_iter().map(|u| u.label).collect();
        assert_eq!(labels, ["2 updates available", "pulled, not recreated"][..]);
        p.containers.truncate(1);
        let labels: Vec<String> = stack_updates(&p).into_iter().map(|u| u.label).collect();
        assert_eq!(labels, ["update available"]);
        p.containers = vec![container_with(Some(ImageUpdateState::CannotVerify {
            reason: "built on this node".into(),
        }))];
        assert!(
            stack_updates(&p).is_empty(),
            "no badge noise on the list for cannot verify"
        );
    }

    #[test]
    fn the_stack_page_gives_the_reason_for_cannot_verify() {
        let v = container_view(&container_with(Some(ImageUpdateState::CannotVerify {
            reason: "pinned to a digest, so the tag cannot move\u{7}".into(),
        })));
        assert_eq!(v.update.expect("pill").label, "cannot verify");
        assert_eq!(
            v.update_reason,
            "pinned to a digest, so the tag cannot move"
        );
        assert!(!v.update_checked.is_empty());
        let v = container_view(&container_with(Some(ImageUpdateState::UpdateAvailable)));
        assert_eq!(v.update.expect("pill").label, "update available");
        assert!(v.update_reason.is_empty());
        let v = container_view(&container_with(None));
        assert!(v.update.is_none() && v.update_checked.is_empty());
    }

    #[test]
    fn an_older_answer_shows_why_the_latest_check_failed() {
        let mut c = container_with(Some(ImageUpdateState::UpToDate));
        c.update_error = "unauthorized: the registry wants a login\u{7}".into();
        let v = container_view(&c);
        assert_eq!(v.update_error, "unauthorized: the registry wants a login");
        assert!(container_view(&container_with(None))
            .update_error
            .is_empty());
    }

    #[test]
    fn a_node_row_says_what_the_badges_mean_only_when_there_are_some() {
        let mut p = proj("shop", "ok");
        p.containers = vec![container_with(Some(ImageUpdateState::UpdateAvailable))];
        let st = |p: DockerProject| {
            NodeDockerState::Ok(DockerNodeStatus {
                daemon_ok: true,
                projects: vec![p],
                ..Default::default()
            })
        };
        assert!(node_view(&row("web-1", st(p))).has_updates);
        assert!(!node_view(&row("web-1", st(proj("quiet", "ok")))).has_updates);
    }
}
