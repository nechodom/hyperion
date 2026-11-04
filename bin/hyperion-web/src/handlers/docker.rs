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
    DockerContainer, DockerNodeEntry, DockerNodeList, DockerNodeStatus, DockerProject,
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
        "Deletes what Hyperion kept about Docker on {label}: remembered stacks, open alerts and \
         the cached disk figures. Docker itself, its containers, images and volumes are left alone."
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
    disk: Option<DiskView>,
    read: String,
    stats_note: String,
    daemon_error: Option<String>,
}

fn container_tone(c: &DockerContainer) -> &'static str {
    let unhealthy = c.health.as_deref() == Some("unhealthy");
    match c.state.as_str() {
        _ if c.oom_killed || unhealthy => "err",
        "restarting" | "dead" => "err",
        "running" => "ok",
        "exited" if c.exit_code == 0 && c.restart_policy == "no" => "muted",
        "exited" => "err",
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
    };
    Ok(Html(tpl.render()?).into_response())
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
}
