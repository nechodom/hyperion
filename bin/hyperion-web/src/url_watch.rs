//! The web side of the URL checks.
//!
//! The agent samples the addresses and parks what changed. This side does
//! what only the master's web layer can: ask the node an address lives on
//! whether it answers and what its Docker stack says, and re-derive which
//! node that is. It then hands the facts back (`UrlMonitorAlert`), and the
//! agent sends and acknowledges.
//!
//! Nothing here can lose an alert: an event is acknowledged only by that
//! last call, so a lookup that fails, times out or a panel that restarts
//! just means the next pass returns the event again.

use crate::dispatcher::LOCAL_NODE_SENTINEL;
use crate::docker_watch::{classify, Probe};
use crate::error::AppError;
use crate::state::SharedState;
use hyperion_rpc::codec::{Request, Response};
use hyperion_rpc::wire::HostingSelector;
use hyperion_types::docker::DockerProject;
use hyperion_types::url_monitor::{UrlAlertContext, UrlMonitorEvent};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

/// The agent samples for at most this long (its own budget is 90 s).
const TICK_TIMEOUT_SECS: u64 = 150;
/// Looking at a node (its Docker, or which hosting an address belongs to)
/// may not hold an alert up longer than this.
const LOOKUP_TIMEOUT_SECS: u64 = 10;
/// Sending one alert: the bell, mail and two webhooks, each with its own
/// limit in the agent.
const ALERT_TIMEOUT_SECS: u64 = 90;
/// Alerts handled in one pass. The rest stay parked for the next, 15 s later:
/// a whole node dying with many checks on it is a few passes, not a burst.
const EVENTS_PER_PASS: usize = 20;
/// Longest stack line passed on to the agent (which shortens it again).
const SUMMARY_MAX_CHARS: usize = 300;

/// The agent's socket; a refusal or a failure is logged and ends the pass.
async fn local(state: &SharedState, req: Request, secs: u64) -> Option<Response> {
    match tokio::time::timeout(
        Duration::from_secs(secs),
        hyperion_rpc_client::call(&state.agent_socket, req),
    )
    .await
    {
        Ok(Ok(Response::Error(e))) => {
            tracing::warn!(error = %e, "url checks: the agent refused");
            None
        }
        Ok(Ok(r)) => Some(r),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "url checks: the agent did not answer");
            None
        }
        Err(_) => {
            tracing::warn!("url checks: the agent took too long");
            None
        }
    }
}

/// One pass: sample what is due, then deal with every alert still waiting.
pub async fn pass(state: &SharedState) {
    let Some(Response::UrlMonitorTick(events)) =
        local(state, Request::UrlMonitorTick, TICK_TIMEOUT_SECS).await
    else {
        return;
    };
    handle_events(state, events).await;
}

/// What a node said when asked what runs on it.
#[derive(Debug, Clone)]
enum Lookup {
    /// It answered with its stacks.
    Stacks {
        projects: Vec<DockerProject>,
        daemon_ok: bool,
    },
    /// The transport failed or it did not answer in time.
    Silent,
    /// It answered with something that says nothing about the address.
    Unknown,
}

/// Ask `node` (`local` is the master) for its Docker overview.
async fn look(state: &SharedState, node: &str) -> Lookup {
    let target = (node != LOCAL_NODE_SENTINEL).then_some(node);
    let asked = tokio::time::timeout(
        Duration::from_secs(LOOKUP_TIMEOUT_SECS),
        crate::dispatcher::dispatch_to_node(state, target, Request::DockerOverview),
    )
    .await;
    let Ok(answer) = asked else {
        return Lookup::Silent;
    };
    match (&answer, classify(&answer)) {
        (Ok(Response::DockerOverview(st)), _) => Lookup::Stacks {
            projects: st.projects.clone(),
            daemon_ok: st.daemon_ok,
        },
        (_, Probe::Silent) => Lookup::Silent,
        _ => Lookup::Unknown,
    }
}

/// The host of an address, lower case, without port or brackets.
pub(crate) fn hostname_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
}

/// What the stack behind `host` looks like, in one short line, or `None`
/// when no stack lists that host. It is a statement of state: the stack's
/// verdict and, for a problem, the summary the node computed (service, exit
/// code and cause). Never a log line.
pub(crate) fn stack_summary(
    projects: &[DockerProject],
    daemon_ok: bool,
    host: &str,
) -> Option<String> {
    let p = projects.iter().find(|p| {
        p.hostings
            .iter()
            .any(|h| h.trim_end_matches('.').eq_ignore_ascii_case(host))
    })?;
    let name = if p.name.is_empty() {
        "other containers"
    } else {
        p.name.as_str()
    };
    let line = if !daemon_ok {
        format!("{name}: Docker is not responding on that node")
    } else {
        match p.verdict.as_str() {
            "problem" if !p.summary.trim().is_empty() => format!("{name}: {}", p.summary.trim()),
            "problem" => format!("{name}: has a problem"),
            "gone" => format!("{name}: no containers left"),
            _ => format!("{name}: running normally"),
        }
    };
    Some(line.chars().take(SUMMARY_MAX_CHARS).collect())
}

/// What the owning-node lookup concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Derived {
    /// `Some(node)` (`local` for the master) hosts the address; `None`: no
    /// hosting has that host name.
    Node(Option<String>),
    /// The lookup could not tell (a node did not answer): keep what is
    /// stored. A dead node cannot claim its domain, so silence is not "no
    /// match".
    Unknown,
}

/// Which node hosts the address' host name, asked live.
pub(crate) async fn derive_node(state: &SharedState, url: &str) -> Derived {
    let Some(host) = hostname_of(url) else {
        return Derived::Node(None);
    };
    // An IP address or a one-label name is no hosting's domain.
    let Ok(domain) = hyperion_validate::Domain::parse(&host) else {
        return Derived::Node(None);
    };
    let asked = tokio::time::timeout(
        Duration::from_secs(LOOKUP_TIMEOUT_SECS),
        crate::handlers::hostings::find_hosting_anywhere(state, HostingSelector::Domain(domain)),
    )
    .await;
    match asked {
        Ok(Ok((_, None))) => Derived::Node(Some(LOCAL_NODE_SENTINEL.to_string())),
        Ok(Ok((_, Some(node)))) => Derived::Node(Some(node)),
        Ok(Err(AppError::NotFound)) => Derived::Node(None),
        Ok(Err(_)) | Err(_) => Derived::Unknown,
    }
}

/// The part of the context a failing check needs from its node.
fn down_context(
    host: &str,
    node: Option<&str>,
    found: &HashMap<String, Lookup>,
) -> UrlAlertContext {
    let mut ctx = UrlAlertContext::default();
    let Some(node) = node else { return ctx };
    match found.get(node) {
        Some(Lookup::Stacks {
            projects,
            daemon_ok,
        }) => {
            ctx.stack_summary = stack_summary(projects, *daemon_ok, host);
        }
        // The master is the checker: that it does not answer itself is no
        // news about a node.
        Some(Lookup::Silent) => ctx.node_unreachable = node != LOCAL_NODE_SENTINEL,
        Some(Lookup::Unknown) | None => {}
    }
    ctx
}

async fn handle_events(state: &SharedState, mut events: Vec<UrlMonitorEvent>) {
    events.truncate(EVENTS_PER_PASS);

    // Each node once, however many checks live on it.
    let nodes: BTreeSet<String> = events
        .iter()
        .filter(|e| e.down)
        .filter_map(|e| e.node_id.clone())
        .collect();
    let mut asking = tokio::task::JoinSet::new();
    for node in nodes {
        let state = state.clone();
        asking.spawn(async move {
            let found = look(&state, &node).await;
            (node, found)
        });
    }
    let mut found: HashMap<String, Lookup> = HashMap::new();
    while let Some(Ok((node, l))) = asking.join_next().await {
        found.insert(node, l);
    }
    let found = std::sync::Arc::new(found);

    let mut sending = tokio::task::JoinSet::new();
    for e in events {
        let state = state.clone();
        let found = found.clone();
        sending.spawn(async move {
            let host = hostname_of(&e.url).unwrap_or_default();
            let ctx = if e.down {
                down_context(&host, e.node_id.as_deref(), &found)
            } else {
                // Back up: everything answers, so this is the moment to
                // find out whether the address still lives where it did.
                match derive_node(&state, &e.url).await {
                    Derived::Node(n) => UrlAlertContext {
                        node_rederived: true,
                        node_id: n,
                        ..Default::default()
                    },
                    Derived::Unknown => UrlAlertContext::default(),
                }
            };
            let id = e.id;
            local(
                &state,
                Request::UrlMonitorAlert { id, context: ctx },
                ALERT_TIMEOUT_SECS,
            )
            .await;
        });
    }
    while sending.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(name: &str, verdict: &str, summary: &str, hosts: &[&str]) -> DockerProject {
        DockerProject {
            name: name.into(),
            verdict: verdict.into(),
            summary: summary.into(),
            hostings: hosts.iter().map(|h| h.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn the_host_is_lower_case_without_port_or_dot() {
        assert_eq!(
            hostname_of("https://Shop.Example.CZ:8443/a?b=c").as_deref(),
            Some("shop.example.cz")
        );
        assert_eq!(
            hostname_of("http://example.cz./").as_deref(),
            Some("example.cz")
        );
        assert_eq!(hostname_of("not a url"), None);
    }

    #[test]
    fn the_stack_is_found_by_host_and_worded_as_state() {
        let projects = vec![
            project("blog", "ok", "", &["blog.example.cz"]),
            project(
                "shop",
                "problem",
                "web exited 137, OOM-killed",
                &["Shop.example.cz"],
            ),
            project("old", "gone", "", &["old.example.cz"]),
            project("wobbly", "problem", "", &["wobbly.example.cz"]),
        ];
        let line = |h| stack_summary(&projects, true, h);
        assert_eq!(
            line("shop.example.cz").as_deref(),
            Some("shop: web exited 137, OOM-killed")
        );
        assert_eq!(
            line("blog.example.cz").as_deref(),
            Some("blog: running normally")
        );
        assert_eq!(
            line("old.example.cz").as_deref(),
            Some("old: no containers left")
        );
        assert_eq!(
            line("wobbly.example.cz").as_deref(),
            Some("wobbly: has a problem")
        );
        assert_eq!(line("else.example.cz"), None, "no stack lists that host");
        assert_eq!(
            stack_summary(&projects, false, "blog.example.cz").as_deref(),
            Some("blog: Docker is not responding on that node")
        );
    }

    #[test]
    fn a_node_that_does_not_answer_is_named_unless_it_is_the_master() {
        let mut found = HashMap::new();
        found.insert("node_a".to_string(), Lookup::Silent);
        found.insert(LOCAL_NODE_SENTINEL.to_string(), Lookup::Silent);
        found.insert("node_b".to_string(), Lookup::Unknown);
        found.insert(
            "node_c".to_string(),
            Lookup::Stacks {
                projects: vec![project("shop", "ok", "", &["shop.example.cz"])],
                daemon_ok: true,
            },
        );
        let ctx = |n: Option<&str>| down_context("shop.example.cz", n, &found);
        assert!(ctx(Some("node_a")).node_unreachable);
        assert!(
            !ctx(Some(LOCAL_NODE_SENTINEL)).node_unreachable,
            "the master checking itself says nothing about a node"
        );
        assert!(
            !ctx(Some("node_b")).node_unreachable,
            "an answer is an answer"
        );
        assert!(!ctx(None).node_unreachable, "no owning node, no accusation");
        assert_eq!(
            ctx(Some("node_c")).stack_summary.as_deref(),
            Some("shop: running normally")
        );
        assert_eq!(ctx(Some("node_missing")), UrlAlertContext::default());
    }
}
