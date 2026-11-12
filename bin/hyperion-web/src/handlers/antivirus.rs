//! `GET /antivirus` — what ClamAV found, where, and when it last looked.
//!
//! Each node runs its own pass over its own sites, so the page fans
//! `AntivirusOverview` out across the master and every enrolled node and
//! merges the answers: one row per node (is ClamAV there, when did it last
//! run, why is it waiting, when is it next due), every detection with its
//! site, and the sites no pass has covered. `POST /antivirus/run` asks one
//! node for a pass now. The schedule itself is Settings → Antivirus.

use crate::auth::AuthCtx;
use crate::error::AppError;
#[allow(unused_imports)] // askama resolves {{ x|tenant_text }} through this
use crate::filters;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::antivirus::{pass_end, AntivirusOverview, AntivirusSettings};
use serde::Deserialize;

/// Detections listed on the page. Each site's own card has all of its own.
const DETECTION_ROWS: usize = 300;

/// One node's answer.
pub struct NodeData {
    pub node_id: String,
    pub label: String,
    /// `None`: reachable, but too old to know the request.
    pub overview: Option<AntivirusOverview>,
}

/// One row of the nodes table.
pub struct NodeRow {
    pub node_id: String,
    pub label: String,
    /// `ready`, `not installed`, `signatures downloading`, `update the node`.
    pub clamav: &'static str,
    pub clamav_tone: &'static str,
    /// What the last pass was: "3h ago · complete", or "never".
    pub last: String,
    pub last_tone: &'static str,
    /// Sites, files and detections of that pass; empty when none ran.
    pub last_detail: String,
    /// What it is doing or waiting for now.
    pub now: String,
    pub now_tone: &'static str,
    pub free: String,
    /// A pass can be asked for: ClamAV is there and none runs.
    pub can_run: bool,
    pub sites: usize,
    pub covered: usize,
}

/// One detection.
pub struct HitRow {
    pub hosting_id: String,
    pub domain: String,
    pub node_label: String,
    pub path: String,
    pub signature: String,
    pub found: String,
}

/// One site no pass vouches for, or one whose pass left something out.
pub struct GapRow {
    pub hosting_id: String,
    pub domain: String,
    pub node_label: String,
    pub covered: String,
    pub why: String,
}

/// One site, in the full list.
pub struct SiteRow {
    pub hosting_id: String,
    pub domain: String,
    pub node_label: String,
    pub covered: String,
    pub hits: u32,
    pub file_findings: u32,
    pub file_review: u32,
}

pub struct Page {
    pub verdict: String,
    pub verdict_tone: &'static str,
    /// The schedule the master's node reads, in words.
    pub schedule: String,
    pub schedule_on: bool,
    pub nodes: Vec<NodeRow>,
    pub show_node: bool,
    pub hits: Vec<HitRow>,
    pub hits_total: u64,
    /// The list is shorter than the count: a site sends its first fifty, and
    /// the page keeps the first few hundred.
    pub hits_cut: bool,
    pub sites_hit: usize,
    pub gaps: Vec<GapRow>,
    pub sites: Vec<SiteRow>,
    pub sites_total: usize,
    pub sites_covered: usize,
    pub any_clamav: bool,
    pub old_nodes: Vec<String>,
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `in 13 h`, `in 2 d`, `in 20 min`: how far ahead `ts` is.
fn fmt_in(ts: i64, now: i64) -> String {
    let d = (ts - now).max(0);
    if d < 90 {
        "within minutes".into()
    } else if d < 3600 {
        format!("in {} min", d / 60)
    } else if d < 48 * 3600 {
        format!("in {} h", (d + 1800) / 3600)
    } else {
        format!("in {} d", (d + 43_200) / 86_400)
    }
}

fn end_words(end: &str) -> (&'static str, &'static str) {
    match end {
        pass_end::COMPLETE => ("complete", "ok"),
        pass_end::PARTIAL => ("some files not read", "warn"),
        pass_end::OUT_OF_MEMORY => ("stopped: out of memory", "err"),
        pass_end::TIMED_OUT => ("stopped after six hours", "warn"),
        pass_end::FAILED => ("could not run", "err"),
        pass_end::INTERRUPTED => ("interrupted by a restart", "warn"),
        _ => ("ended", "muted"),
    }
}

fn node_row(n: &NodeData, now: i64) -> NodeRow {
    let Some(o) = &n.overview else {
        return NodeRow {
            node_id: n.node_id.clone(),
            label: n.label.clone(),
            clamav: "update the node",
            clamav_tone: "muted",
            last: "—".into(),
            last_tone: "muted",
            last_detail: String::new(),
            now: "This node runs an older version and can't report its passes.".into(),
            now_tone: "muted",
            free: "—".into(),
            can_run: false,
            sites: 0,
            covered: 0,
        };
    };
    let (clamav, clamav_tone) = match (o.installed, o.db_present) {
        (false, _) => ("not installed", "muted"),
        (true, false) => ("signatures downloading", "warn"),
        (true, true) => ("ready", "ok"),
    };
    let (last, last_tone, last_detail) = if o.last_finished > 0 {
        let (words, tone) = end_words(&o.last_end);
        (
            format!("{} · {words}", super::stats::fmt_ago(&o.last_started)),
            tone,
            format!(
                "{} · {} · {}",
                plural(u64::from(o.last_sites), "site", "sites"),
                plural(o.last_files, "file", "files"),
                plural(u64::from(o.last_hits), "detection", "detections"),
            ),
        )
    } else {
        ("never".to_string(), "muted", String::new())
    };
    let s = &o.settings;
    let (now_text, now_tone) = if !o.installed {
        (
            "Nothing to run. Add ClamAV on the Services page.".to_string(),
            "muted",
        )
    } else if o.running_since > 0 {
        (
            format!(
                "A pass is running, started {}.",
                super::stats::fmt_ago(&o.running_since)
            ),
            "ok",
        )
    } else if o.run_requested {
        (
            "A pass was asked for and starts within minutes.".to_string(),
            "ok",
        )
    } else if let Some(why) = &o.held {
        (
            format!("{why} ({}).", super::stats::fmt_ago(&o.held_at)),
            "warn",
        )
    } else if o.backoff_until > now {
        (
            format!(
                "Resting after running out of memory; next scheduled pass {}.",
                fmt_in(o.next_due_at.max(o.backoff_until), now)
            ),
            "warn",
        )
    } else if !s.enabled {
        (
            "Scheduled pass is off; it runs only when asked.".to_string(),
            "warn",
        )
    } else if o.next_due_at > 0 && o.next_due_at <= now {
        ("Due now; starts within ten minutes.".to_string(), "ok")
    } else if o.next_due_at > 0 {
        (
            format!("Next pass {}.", fmt_in(o.next_due_at, now)),
            "muted",
        )
    } else {
        ("No pass scheduled.".to_string(), "muted")
    };
    NodeRow {
        node_id: n.node_id.clone(),
        label: n.label.clone(),
        clamav,
        clamav_tone,
        last,
        last_tone,
        last_detail,
        now: now_text,
        now_tone,
        free: format!("{:.1} GiB", o.mem_available as f64 / f64::from(1u32 << 30)),
        can_run: o.installed && o.db_present && o.running_since == 0 && !o.run_requested,
        sites: o.sites.len(),
        covered: o.sites.iter().filter(|s| s.covered_at > 0).count(),
    }
}

/// Merge every node's answer into the page.
pub fn build(nodes: &[NodeData], now: i64) -> Page {
    let mut hits = Vec::new();
    let mut hits_total = 0u64;
    let mut sites_hit = 0usize;
    let mut gaps = Vec::new();
    let mut sites = Vec::new();
    let mut old_nodes = Vec::new();
    let mut any_clamav = false;
    for n in nodes {
        let Some(o) = &n.overview else {
            old_nodes.push(n.label.clone());
            continue;
        };
        any_clamav |= o.installed;
        for s in &o.sites {
            let covered = if s.covered_at > 0 {
                super::stats::fmt_ago(&s.covered_at)
            } else {
                "never".to_string()
            };
            hits_total += u64::from(s.hits_total);
            if s.hits_total > 0 {
                sites_hit += 1;
            }
            for h in &s.hits {
                hits.push(HitRow {
                    hosting_id: s.hosting_id.clone(),
                    domain: s.domain.clone(),
                    node_label: n.label.clone(),
                    path: h.path.clone(),
                    signature: h.signature.clone(),
                    found: covered.clone(),
                });
            }
            // A site on a node without ClamAV isn't a gap in a pass: the
            // node's row already says there is nothing to run.
            if o.installed && (s.covered_at == 0 || s.note.is_some()) {
                gaps.push(GapRow {
                    hosting_id: s.hosting_id.clone(),
                    domain: s.domain.clone(),
                    node_label: n.label.clone(),
                    covered: covered.clone(),
                    why: s.note.clone().unwrap_or_else(|| {
                        "No pass has run since this site was first scanned.".to_string()
                    }),
                });
            }
            sites.push(SiteRow {
                hosting_id: s.hosting_id.clone(),
                domain: s.domain.clone(),
                node_label: n.label.clone(),
                covered,
                hits: s.hits_total,
                file_findings: s.file_findings,
                file_review: s.file_review,
            });
        }
    }
    hits.truncate(DETECTION_ROWS);
    sites.sort_by(|a, b| b.hits.cmp(&a.hits).then(a.domain.cmp(&b.domain)));
    gaps.sort_by(|a, b| a.domain.cmp(&b.domain));
    let sites_total = sites.len();
    let sites_covered = sites.iter().filter(|s| s.covered != "never").count();

    let (verdict, verdict_tone) = if hits_total > 0 {
        (
            format!(
                "ClamAV detected {} on {}.",
                plural(hits_total, "file", "files"),
                plural(sites_hit as u64, "site", "sites")
            ),
            "err",
        )
    } else if !any_clamav {
        (
            "ClamAV isn't installed on any node, so no file has been checked against its signatures.".to_string(),
            "warn",
        )
    } else if sites_covered < sites_total {
        (
            format!(
                "No detections, but only {sites_covered} of {} have been covered by a pass.",
                plural(sites_total as u64, "site", "sites")
            ),
            "warn",
        )
    } else {
        (
            format!(
                "No detections on {}.",
                plural(sites_total as u64, "site", "sites")
            ),
            "ok",
        )
    };
    // The master's own reading; every node holds the same once synced.
    let settings: AntivirusSettings = nodes
        .iter()
        .find(|n| n.node_id == "local")
        .or(nodes.first())
        .and_then(|n| n.overview.as_ref())
        .map(|o| o.settings)
        .unwrap_or_default();
    Page {
        verdict,
        verdict_tone,
        schedule: format!(
            "{}, {} (each node's local time), with at least {} of memory free",
            settings.every_text(),
            settings.window_text(),
            settings.min_free_text()
        ),
        schedule_on: settings.enabled,
        show_node: nodes.len() > 1,
        nodes: nodes.iter().map(|n| node_row(n, now)).collect(),
        hits_cut: hits_total > hits.len() as u64,
        hits,
        hits_total,
        sites_hit,
        gaps,
        sites,
        sites_total,
        sites_covered,
        any_clamav,
        old_nodes,
    }
}

#[derive(Template)]
#[template(path = "antivirus.html")]
struct AntivirusTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    p: Page,
    flash: Option<String>,
    flash_error: Option<String>,
    csrf_token: String,
    node_auth_warning: Option<String>,
    unreachable: Vec<String>,
}

#[derive(Deserialize, Default)]
pub struct AntivirusQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_error: Option<String>,
}

pub async fn get_antivirus(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<AntivirusQuery>,
) -> Result<Response, AppError> {
    // Cluster-wide view: every site's detections, so all-hostings scope.
    if !(ctx.can(Capability::SecurityManage) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let mut nodes: Vec<NodeData> = Vec::new();
    let mut unreachable: Vec<String> = Vec::new();
    match hyperion_rpc_client::call(&state.agent_socket, Request::AntivirusOverview).await {
        Ok(RpcResponse::AntivirusOverview(o)) => nodes.push(NodeData {
            node_id: "local".into(),
            label: "master".into(),
            overview: Some(o),
        }),
        other => {
            tracing::warn!(answer = ?other.err().map(|e| e.to_string()), "antivirus: the master's own agent did not answer");
            unreachable.push("master".into());
        }
    }
    let mut node_auth_warning = None;
    if let Ok(list) = crate::dispatcher::cached_nodes(&state).await {
        let (answered, failed) =
            crate::dispatcher::fan_out_reporting(&state, list, Request::AntivirusOverview).await;
        for (n, resp) in answered {
            nodes.push(NodeData {
                node_id: n.node_id,
                label: n.label,
                overview: match resp {
                    RpcResponse::AntivirusOverview(o) => Some(o),
                    _ => None,
                },
            });
        }
        node_auth_warning = super::node_auth_warning(&failed);
        for (n, e) in failed {
            match e {
                crate::dispatcher::DispatchError::ResponseAuthFailed { .. } => {}
                // An older node drops the connection on a request it cannot
                // decode. It is there, it just can't say.
                crate::dispatcher::DispatchError::Remote(_) => nodes.push(NodeData {
                    node_id: n.node_id,
                    label: n.label,
                    overview: None,
                }),
                _ => unreachable.push(n.label),
            }
        }
    }
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    let tpl = AntivirusTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "antivirus",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        p: build(&nodes, chrono::Utc::now().timestamp()),
        flash: q.flash.filter(|s| !s.is_empty()),
        flash_error: q.flash_error.filter(|s| !s.is_empty()),
        csrf_token: super::session_csrf_token(&state, &ctx),
        node_auth_warning,
        unreachable,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct RunForm {
    #[serde(default)]
    pub node_id: String,
}

fn back(kind: &str, msg: &str) -> Response {
    Redirect::to(&format!(
        "/antivirus?{kind}={}",
        url::form_urlencoded::byte_serialize(msg.as_bytes()).collect::<String>()
    ))
    .into_response()
}

/// `POST /antivirus/run` — ask one node for a ClamAV pass now.
pub async fn post_run(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::Form(form): axum::Form<RunForm>,
) -> Result<Response, AppError> {
    if !(ctx.can(Capability::SecurityManage) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let target = if form.node_id.is_empty() || form.node_id == "local" {
        None
    } else {
        Some(form.node_id.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(&state, target, Request::AntivirusRunNow).await;
    Ok(match resp {
        Ok(RpcResponse::AntivirusRunNow { queued: true }) => back(
            "flash",
            "Pass requested. It starts within a minute if the node has the memory; this page shows why if it doesn't.",
        ),
        Ok(RpcResponse::AntivirusRunNow { queued: false }) => {
            back("flash", "A pass is already running on that node.")
        }
        Ok(RpcResponse::Error(e)) => back("flash_error", &e.to_string()),
        Ok(_) => back("flash_error", "unexpected response"),
        Err(e) => back(
            "flash_error",
            &format!("The node did not take the request ({e}). An older node has to be updated first."),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::antivirus::AntivirusSite;
    use hyperion_types::WpMalwareHit;

    const NOW: i64 = 1_800_000_000;

    fn site(id: &str, domain: &str, covered_at: i64) -> AntivirusSite {
        AntivirusSite {
            hosting_id: id.into(),
            domain: domain.into(),
            covered_at,
            ..Default::default()
        }
    }

    fn ready(sites: Vec<AntivirusSite>) -> AntivirusOverview {
        AntivirusOverview {
            installed: true,
            db_present: true,
            mem_available: 5 << 30,
            last_started: NOW - 7200,
            last_finished: NOW - 3600,
            last_end: pass_end::COMPLETE.into(),
            last_sites: sites.len() as u32,
            last_files: 1234,
            next_due_at: NOW + 13 * 3600,
            sites,
            ..Default::default()
        }
    }

    fn node(id: &str, o: Option<AntivirusOverview>) -> NodeData {
        NodeData {
            node_id: id.into(),
            label: if id == "local" {
                "master".into()
            } else {
                id.into()
            },
            overview: o,
        }
    }

    fn render(p: Page) -> String {
        AntivirusTpl {
            username: "kevin",
            user_initial: 'K',
            active: "antivirus",
            css_version: "x",
            htmx_version: "x",
            p,
            flash: None,
            flash_error: None,
            csrf_token: "tok".into(),
            node_auth_warning: None,
            unreachable: vec![],
        }
        .render()
        .expect("render")
    }

    #[test]
    fn detections_lead_and_name_their_site_file_and_signature() {
        let mut bad = site("h1", "shop.example", NOW - 3600);
        bad.hits = vec![WpMalwareHit {
            path: "/home/shop/htdocs/wp-content/uploads/x.php".into(),
            signature: "Php.Trojan.Webshell-1".into(),
        }];
        bad.hits_total = 1;
        let p = build(
            &[
                node(
                    "local",
                    Some(ready(vec![bad, site("h2", "blog.example", NOW - 3600)])),
                ),
                node("web-1", Some(ready(vec![site("h3", "new.example", 0)]))),
            ],
            NOW,
        );
        assert_eq!(p.verdict_tone, "err");
        assert_eq!(p.verdict, "ClamAV detected 1 file on 1 site.");
        assert_eq!((p.sites_total, p.sites_covered), (3, 2));
        assert_eq!(p.sites[0].domain, "shop.example", "worst first");
        assert_eq!(p.gaps.len(), 1);
        assert_eq!(p.gaps[0].domain, "new.example");
        let html = render(p);
        assert!(html.contains("Php.Trojan.Webshell-1"));
        assert!(html.contains("/home/shop/htdocs/wp-content/uploads/x.php"));
        assert!(html.contains(r#"href="/hostings/h1""#));
        assert!(html.contains("No pass has run since this site was first scanned."));
        assert!(html.contains("Next pass in 13 h."));
        assert!(html.contains("1 site · 1234 files · 0 detections"));
        // One Run-now form per node, naming it.
        assert!(html.contains(r#"name="node_id" value="local""#));
        assert!(html.contains(r#"name="node_id" value="web-1""#));
        assert!(html.contains(r#"href="/settings/antivirus#antivirus-schedule""#));
    }

    #[test]
    fn a_held_pass_says_why_and_a_missing_clamav_is_not_a_gap() {
        let mut held = ready(vec![site("h1", "a.example", 0)]);
        held.last_finished = 0;
        held.held =
            Some("ClamAV skipped its pass: the node has less than 2 GiB of memory free".into());
        held.held_at = NOW - 600;
        let none = AntivirusOverview {
            sites: vec![site("h2", "b.example", 0)],
            ..Default::default()
        };
        let p = build(&[node("local", Some(held)), node("web-1", Some(none))], NOW);
        assert_eq!(p.verdict_tone, "warn");
        assert!(p.verdict.contains("only 0 of 2 sites"), "{}", p.verdict);
        assert_eq!(
            p.gaps.len(),
            1,
            "the node without ClamAV has no pass to miss"
        );
        assert!(p.nodes[0].now.contains("less than 2 GiB"));
        assert_eq!(p.nodes[0].last, "never");
        assert!(p.nodes[0].can_run);
        assert_eq!(p.nodes[1].clamav, "not installed");
        assert!(!p.nodes[1].can_run);
        let html = render(p);
        assert_eq!(html.matches(r#"action="/antivirus/run""#).count(), 1);
    }

    #[test]
    fn an_old_node_is_named_and_nothing_installed_is_said_plainly() {
        let p = build(
            &[
                node("local", Some(AntivirusOverview::default())),
                node("web-1", None),
            ],
            NOW,
        );
        assert_eq!(p.old_nodes, vec!["web-1".to_string()]);
        assert!(p.verdict.contains("isn't installed on any node"));
        assert_eq!(p.nodes[1].clamav, "update the node");
        let html = render(p);
        assert!(html.contains("web-1 runs an older version"));
    }

    #[test]
    fn a_running_pass_cannot_be_started_twice_and_off_is_said() {
        let mut running = ready(vec![site("h1", "a.example", NOW - 86_400)]);
        running.running_since = NOW - 120;
        let mut off = ready(vec![site("h2", "b.example", NOW - 86_400)]);
        off.settings.enabled = false;
        off.next_due_at = 0;
        let p = build(
            &[node("local", Some(running)), node("web-1", Some(off))],
            NOW,
        );
        assert!(!p.nodes[0].can_run);
        assert!(p.nodes[0].now.starts_with("A pass is running"));
        assert!(p.nodes[1].can_run);
        assert!(p.nodes[1].now.contains("off"));
        assert_eq!(p.verdict_tone, "ok");
        assert_eq!(p.verdict, "No detections on 2 sites.");
    }

    #[test]
    fn times_ahead_read_in_the_unit_that_fits() {
        assert_eq!(fmt_in(NOW + 30, NOW), "within minutes");
        assert_eq!(fmt_in(NOW + 1200, NOW), "in 20 min");
        assert_eq!(fmt_in(NOW + 13 * 3600, NOW), "in 13 h");
        assert_eq!(fmt_in(NOW + 6 * 86_400, NOW), "in 6 d");
        assert_eq!(fmt_in(NOW - 5, NOW), "within minutes");
    }
}
