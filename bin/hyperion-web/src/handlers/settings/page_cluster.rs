//! `GET /settings/cluster` — where new sites go, which nodes are for testing,
//! how far the master↔node channel is locked down, and whether every node
//! has the master's settings. `POST /settings/cluster/sync` runs a settings
//! sync pass now.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::cluster_sync::{NodeSync, SyncState};
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::Request;
use hyperion_state::capabilities::Capability;
use hyperion_types::{AgentConfigView, NodeSummary};
use std::collections::HashMap;

#[derive(Template)]
#[template(path = "settings_cluster.html")]
struct ClusterTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    config: AgentConfigView,
    config_error: Option<String>,
    test_nodes: Vec<TestNode>,
    readiness: Readiness,
    /// The hardening card's pill: (tone, words).
    hardening: (&'static str, &'static str),
    sync_rows: Vec<SyncRow>,
    /// The sync card's pill: (tone, words).
    sync_summary: (&'static str, String),
}

pub async fn get_cluster(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, nodes) = chrome::chrome(&state, &ctx, "cluster", &q).await;
    let (config_res, sync) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        state.cluster_sync.all(),
    );
    let (config, config_error) = super::config_or_default(config_res);
    let test_nodes = test_nodes(&config.cluster.test_node_ids, &config.hostname, &nodes);
    let readiness = readiness(&nodes);
    let hardening = hardening_state(
        config.cluster.enforce_worker_cert_pinning,
        config.cluster.enforce_response_auth,
    );
    let sync_rows = sync_rows(&nodes, &sync);
    let sync_summary = sync_summary(&sync_rows);
    let tpl = ClusterTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        config,
        config_error,
        test_nodes,
        readiness,
        hardening,
        sync_rows,
        sync_summary,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// POST /settings/cluster/sync — run a settings sync pass now rather than at
/// the next five-minute tick. The pass itself waits a few seconds (a save
/// restarts the master's agent, which the payload needs), so the flash says
/// to reload instead of pretending the answer is already in.
pub async fn post_cluster_sync(State(state): State<SharedState>, ctx: AuthCtx) -> Response {
    if !ctx.can(Capability::SettingsManage) {
        return Redirect::to("/").into_response();
    }
    state.cluster_sync.kick();
    chrome::back_with_flash(
        "settings-sync",
        "Checking every node now — reload in about ten seconds to see where each one stands.",
    )
}

fn node_label(n: &NodeSummary) -> String {
    if n.label.trim().is_empty() {
        n.node_id.clone()
    } else {
        n.label.clone()
    }
}

/// One node marked as test in `[cluster] test_node_ids`.
#[derive(Debug, PartialEq, Eq)]
pub struct TestNode {
    pub label: String,
    pub node_id: String,
    pub is_master: bool,
    /// False ⇒ the id names no enrolled node (removed, or typed by hand).
    pub known: bool,
}

/// The marked test nodes, named. The master is marked as `local` by the Nodes
/// page and may be listed by its hostname in a hand-edited file; both read as
/// this server, once. An id that names no enrolled node is kept, raw, so a
/// stale entry is visible rather than silently ignored.
pub fn test_nodes(csv: &str, master_hostname: &str, nodes: &[NodeSummary]) -> Vec<TestNode> {
    let master_host = master_hostname.trim();
    let mut out: Vec<TestNode> = Vec::new();
    for id in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let is_master = id == crate::dispatcher::LOCAL_NODE_SENTINEL
            || (!master_host.is_empty() && id == master_host);
        let t = if is_master {
            TestNode {
                label: if master_host.is_empty() {
                    "This server".to_string()
                } else {
                    master_host.to_string()
                },
                node_id: crate::dispatcher::LOCAL_NODE_SENTINEL.to_string(),
                is_master: true,
                known: true,
            }
        } else {
            match nodes.iter().find(|n| n.node_id == id) {
                Some(n) => TestNode {
                    label: node_label(n),
                    node_id: n.node_id.clone(),
                    is_master: false,
                    known: true,
                },
                None => TestNode {
                    label: id.to_string(),
                    node_id: id.to_string(),
                    is_master: false,
                    known: false,
                },
            }
        };
        if !out.iter().any(|o| o.node_id == t.node_id) {
            out.push(t);
        }
    }
    out
}

/// Which workers the two enforced hardening steps would cut off: a node with
/// no TLS pin (step 1) or no response-signing key (step 2) on file is refused
/// while that step is on. A blank value counts as absent — the dispatcher
/// treats it as unverifiable.
pub struct Readiness {
    pub total: usize,
    pub unpinned: Vec<String>,
    pub unsigned: Vec<String>,
}

impl Readiness {
    pub fn pinned(&self) -> usize {
        self.total - self.unpinned.len()
    }

    pub fn signing(&self) -> usize {
        self.total - self.unsigned.len()
    }

    /// "2 of 3 nodes have a TLS pin on file".
    pub fn pin_line(&self) -> String {
        count_line(self.pinned(), self.total, "a TLS pin on file")
    }

    /// "3 of 3 nodes have a response-signing key on file".
    pub fn key_line(&self) -> String {
        count_line(self.signing(), self.total, "a response-signing key on file")
    }
}

fn count_line(have: usize, total: usize, what: &str) -> String {
    format!(
        "{have} of {total} node{} {} {what}",
        if total == 1 { "" } else { "s" },
        if have == 1 || total == 1 {
            "has"
        } else {
            "have"
        },
    )
}

pub fn readiness(nodes: &[NodeSummary]) -> Readiness {
    let blank = |v: &Option<String>| v.as_deref().unwrap_or("").trim().is_empty();
    Readiness {
        total: nodes.len(),
        unpinned: nodes
            .iter()
            .filter(|n| blank(&n.tls_spki_pin))
            .map(node_label)
            .collect(),
        unsigned: nodes
            .iter()
            .filter(|n| blank(&n.resp_pubkey))
            .map(node_label)
            .collect(),
    }
}

/// The hardening card's pill from the two switches. Step 2 without step 1 is
/// the one combination that is wrong in itself.
pub fn hardening_state(pinning: bool, response_auth: bool) -> (&'static str, &'static str) {
    match (pinning, response_auth) {
        (true, true) => ("ok", "both steps on"),
        (true, false) => ("muted", "step 1 on"),
        (false, true) => ("warn", "out of order"),
        (false, false) => ("muted", "off"),
    }
}

/// One worker in the settings sync table.
#[derive(Debug)]
pub struct SyncRow {
    pub label: String,
    pub node_id: String,
    pub tone: &'static str,
    pub verdict: &'static str,
    pub detail: String,
    /// "3m ago"; empty when the node was never checked.
    pub checked: String,
    /// The same moment as a UTC date and time, for the tooltip.
    pub checked_utc: String,
}

/// A row per enrolled worker, in node-list order, with what the last sync
/// pass that reached it said. A node the loop has not reached yet (the web
/// service just started, or the node was just enrolled) says so instead of
/// reading as a failure.
pub fn sync_rows(nodes: &[NodeSummary], sync: &HashMap<String, NodeSync>) -> Vec<SyncRow> {
    nodes
        .iter()
        .map(|n| {
            let (tone, verdict, detail, at) = match sync.get(&n.node_id) {
                Some(s) => {
                    let (tone, verdict) = match s.state {
                        SyncState::InSync | SyncState::Applied => ("ok", "in sync"),
                        SyncState::OldAgent => ("warn", "old agent"),
                        SyncState::Failed => ("err", "failed"),
                    };
                    (tone, verdict, s.detail.clone(), s.at)
                }
                None => (
                    "muted",
                    "not checked yet",
                    "the first pass runs within a minute of start".to_string(),
                    0,
                ),
            };
            SyncRow {
                label: node_label(n),
                node_id: n.node_id.clone(),
                tone,
                verdict,
                detail,
                checked: if at > 0 {
                    crate::handlers::stats::fmt_ago(&at)
                } else {
                    String::new()
                },
                checked_utc: if at > 0 {
                    chrono::DateTime::from_timestamp(at, 0)
                        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                        .unwrap_or_default()
                } else {
                    String::new()
                },
            }
        })
        .collect()
}

/// The sync card's pill: how many workers do not have the master's settings.
pub fn sync_summary(rows: &[SyncRow]) -> (&'static str, String) {
    if rows.is_empty() {
        return ("muted", "no workers".to_string());
    }
    let behind = rows
        .iter()
        .filter(|r| r.tone == "warn" || r.tone == "err")
        .count();
    if behind > 0 {
        return ("warn", format!("{behind} of {} behind", rows.len()));
    }
    if rows.iter().any(|r| r.tone == "muted") {
        return ("muted", "not checked yet".to_string());
    }
    ("ok", "all in sync".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, label: &str) -> NodeSummary {
        NodeSummary {
            node_id: id.into(),
            label: label.into(),
            master_url: None,
            agent_version: String::new(),
            public_ip: None,
            enrolled_at: 0,
            last_seen_at: 0,
            is_drained: false,
            drain_reason: String::new(),
            tls_spki_pin: None,
            resp_pubkey: None,
            rpc_port: None,
            external_ip: None,
        }
    }

    fn synced(state: SyncState, detail: &str) -> NodeSync {
        NodeSync {
            state,
            at: 1_700_000_000,
            detail: detail.into(),
        }
    }

    #[test]
    fn no_test_nodes_from_an_empty_or_blank_csv() {
        assert!(test_nodes("", "s4", &[]).is_empty());
        assert!(test_nodes(" , ,", "s4", &[node("a", "a")]).is_empty());
    }

    #[test]
    fn test_ids_are_named_from_the_node_list() {
        let nodes = [node("node_01", "lab-01"), node("node_02", "")];
        let got = test_nodes(" node_01 ,node_02", "s4", &nodes);
        let names: Vec<(&str, &str, bool)> = got
            .iter()
            .map(|t| (t.label.as_str(), t.node_id.as_str(), t.known))
            .collect();
        assert_eq!(
            names,
            vec![("lab-01", "node_01", true), ("node_02", "node_02", true)]
        );
    }

    #[test]
    fn the_master_is_named_once_by_local_or_by_hostname() {
        let got = test_nodes("local,s4", "s4", &[]);
        assert_eq!(
            got,
            vec![TestNode {
                label: "s4".into(),
                node_id: "local".into(),
                is_master: true,
                known: true,
            }]
        );
        // No hostname known: still this server, not a raw "local".
        assert_eq!(test_nodes("local", "", &[])[0].label, "This server");
    }

    #[test]
    fn an_unknown_test_id_is_kept_raw() {
        let got = test_nodes("gone_node", "s4", &[node("node_01", "lab-01")]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].label, "gone_node");
        assert!(!got[0].known);
        assert!(!got[0].is_master);
    }

    #[test]
    fn readiness_counts_blank_values_as_absent() {
        let mut a = node("a", "alpha");
        a.tls_spki_pin = Some("pin".into());
        a.resp_pubkey = Some("key".into());
        let mut b = node("b", "beta");
        b.tls_spki_pin = Some("  ".into());
        b.resp_pubkey = Some("key".into());
        let c = node("c", "");
        let r = readiness(&[a, b, c]);
        assert_eq!(r.total, 3);
        assert_eq!(r.unpinned, vec!["beta".to_string(), "c".to_string()]);
        assert_eq!(r.unsigned, vec!["c".to_string()]);
        assert_eq!(r.pin_line(), "1 of 3 nodes has a TLS pin on file");
        assert_eq!(
            r.key_line(),
            "2 of 3 nodes have a response-signing key on file"
        );
    }

    #[test]
    fn readiness_line_for_a_single_node() {
        let mut a = node("a", "alpha");
        a.resp_pubkey = Some("key".into());
        let r = readiness(&[a]);
        assert_eq!(
            r.key_line(),
            "1 of 1 node has a response-signing key on file"
        );
        assert_eq!(r.pin_line(), "0 of 1 node has a TLS pin on file");
        assert_eq!(readiness(&[]).total, 0);
    }

    #[test]
    fn only_step_two_without_step_one_is_flagged() {
        assert_eq!(hardening_state(true, true), ("ok", "both steps on"));
        assert_eq!(hardening_state(false, true).0, "warn");
        assert_eq!(hardening_state(true, false).0, "muted");
        assert_eq!(hardening_state(false, false), ("muted", "off"));
    }

    #[test]
    fn sync_rows_follow_the_node_list_and_say_what_each_pass_found() {
        let nodes = [
            node("a", "alpha"),
            node("b", "beta"),
            node("c", "gamma"),
            node("d", "delta"),
        ];
        let mut sync = HashMap::new();
        sync.insert(
            "a".to_string(),
            synced(SyncState::Applied, "took the master's settings"),
        );
        sync.insert(
            "b".to_string(),
            synced(SyncState::OldAgent, "runs an older agent"),
        );
        sync.insert(
            "c".to_string(),
            synced(SyncState::Failed, "did not answer within 15s"),
        );
        // A node that left the cluster still in the map is not listed.
        sync.insert("gone".to_string(), synced(SyncState::InSync, ""));
        let rows = sync_rows(&nodes, &sync);
        let got: Vec<(&str, &str, &str)> = rows
            .iter()
            .map(|r| (r.label.as_str(), r.tone, r.verdict))
            .collect();
        assert_eq!(
            got,
            vec![
                ("alpha", "ok", "in sync"),
                ("beta", "warn", "old agent"),
                ("gamma", "err", "failed"),
                ("delta", "muted", "not checked yet"),
            ]
        );
        assert_eq!(rows[2].detail, "did not answer within 15s");
        assert_eq!(rows[0].checked_utc, "2023-11-14 22:13 UTC");
        assert!(!rows[0].checked.is_empty());
        assert!(rows[3].checked.is_empty() && rows[3].checked_utc.is_empty());
        assert_eq!(sync_summary(&rows), ("warn", "2 of 4 behind".to_string()));
    }

    #[test]
    fn sync_summary_states() {
        assert_eq!(sync_summary(&[]).1, "no workers");
        let nodes = [node("a", "alpha"), node("b", "beta")];
        let mut sync = HashMap::new();
        sync.insert("a".to_string(), synced(SyncState::InSync, ""));
        assert_eq!(
            sync_summary(&sync_rows(&nodes, &sync)),
            ("muted", "not checked yet".to_string())
        );
        sync.insert("b".to_string(), synced(SyncState::Applied, ""));
        assert_eq!(
            sync_summary(&sync_rows(&nodes, &sync)),
            ("ok", "all in sync".to_string())
        );
    }
}
