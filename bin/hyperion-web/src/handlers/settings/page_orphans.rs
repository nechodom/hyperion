//! `GET /settings/backups/orphans` — backups left on the FTP/SFTP target by
//! sites that no longer exist.
//!
//! Every other off-site action starts from a live hosting, because the hosting
//! is what says which folder and which domain. A site deleted without its
//! off-site copies left them at `<base_path>/<system_user>/<domain>-<digits>.*`
//! with nothing in the panel pointing at them.
//!
//! An orphan is a file whose domain no hosting anywhere in the cluster uses,
//! trashed ones included. Nodes can share one target and sites move between
//! nodes, so one node's rows do not settle it: every node is asked, and if any
//! does not answer nothing is called an orphan. These files can be the last
//! copy of a site, so nothing goes unless the operator ticks it, and the delete
//! asks every node again rather than trust a list that may be hours old.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{OffsiteFolderListing, OffsiteOrphanCensus};
use std::collections::{BTreeMap, HashSet};

/// How many files one delete may name. Bounds how many RPCs one POST starts.
const MAX_SELECTED: usize = 5000;

/// 2000-01-01. Older than any backup a run could have written.
const EARLIEST_PLAUSIBLE_STAMP: i64 = 946_684_800;

/// One node's answer to the census, or why there is none.
pub struct NodeAnswer {
    /// `None` is the master, reached over the local socket.
    pub node: Option<String>,
    pub label: String,
    pub census: Result<OffsiteOrphanCensus, String>,
}

/// One target, and a node to reach it through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CensusTarget {
    pub key: String,
    pub node: Option<String>,
}

/// What every node said, put together.
#[derive(Debug, Default)]
pub struct Census {
    pub domains: HashSet<String>,
    pub targets: Vec<CensusTarget>,
}

/// One file that may be offered for deletion.
#[derive(Debug, Clone)]
pub struct OrphanFile {
    pub name: String,
    pub bytes: i64,
    pub stamp: i64,
    /// `<folder>/<name>`: what ticking it sends.
    pub value: String,
    pub is_dump: bool,
}

/// One deleted site's files in one folder.
#[derive(Debug, Clone)]
pub struct OrphanDomain {
    pub domain: String,
    pub files: Vec<OrphanFile>,
}

/// A file whose name is not one a backup run writes. Shown, never offered.
#[derive(Debug, Clone)]
pub struct UnknownFile {
    pub name: String,
    pub bytes: i64,
}

/// One per-system-user folder, with what is worth showing about it.
#[derive(Debug, Clone)]
pub struct OrphanFolder {
    pub name: String,
    pub domains: Vec<OrphanDomain>,
    pub unknown: Vec<UnknownFile>,
    pub error: Option<String>,
}

/// One target's findings.
#[derive(Debug, Clone)]
pub struct OrphanTarget {
    pub key: String,
    pub folders: Vec<OrphanFolder>,
    /// Backups of sites that exist: counted, not listed.
    pub in_use: usize,
    /// The target could not be listed at all.
    pub problem: Option<String>,
}

/// The last search, kept for the page to show.
#[derive(Debug, Clone, Default)]
pub struct OrphanReport {
    pub at: i64,
    /// Non-empty: nothing may be called an orphan, because these did not
    /// answer. `targets` is empty then.
    pub refused: Vec<String>,
    pub targets: Vec<OrphanTarget>,
}

impl OrphanFile {
    pub fn size(&self) -> String {
        crate::handlers::stats::fmt_bytes(&self.bytes)
    }

    /// When the backup was taken, from the stamp in its name: an FTP listing
    /// gives dates to the minute at best, and not always the year. A stamp too
    /// small to be a unix time was not written by a backup run, so no date is
    /// better than 1970.
    pub fn date(&self) -> String {
        if self.stamp < EARLIEST_PLAUSIBLE_STAMP {
            return "unknown".to_string();
        }
        crate::handlers::jobs::fmt_local(self.stamp, "%Y-%m-%d %H:%M")
    }
}

impl OrphanDomain {
    pub fn size(&self) -> String {
        crate::handlers::stats::fmt_bytes(&self.files.iter().map(|f| f.bytes).sum())
    }
}

impl UnknownFile {
    pub fn size(&self) -> String {
        crate::handlers::stats::fmt_bytes(&self.bytes)
    }
}

impl OrphanFolder {
    pub fn file_count(&self) -> usize {
        self.domains.iter().map(|d| d.files.len()).sum()
    }

    pub fn size(&self) -> String {
        crate::handlers::stats::fmt_bytes(
            &self
                .domains
                .iter()
                .flat_map(|d| &d.files)
                .map(|f| f.bytes)
                .sum(),
        )
    }
}

impl OrphanTarget {
    pub fn file_count(&self) -> usize {
        self.folders.iter().map(OrphanFolder::file_count).sum()
    }

    pub fn size(&self) -> String {
        crate::handlers::stats::fmt_bytes(
            &self
                .folders
                .iter()
                .flat_map(|f| &f.domains)
                .flat_map(|d| &d.files)
                .map(|f| f.bytes)
                .sum(),
        )
    }
}

impl OrphanReport {
    pub fn when(&self) -> String {
        crate::handlers::stats::fmt_ago(&self.at)
    }
}

/// Put the nodes' answers together, or say which did not answer.
pub fn merge_census(answers: Vec<NodeAnswer>) -> Result<Census, Vec<String>> {
    let mut census = Census::default();
    let mut refused = Vec::new();
    for a in answers {
        match a.census {
            Ok(c) => {
                census
                    .domains
                    .extend(c.domains.iter().map(|d| d.to_ascii_lowercase()));
                if let Some(key) = c.target {
                    if !census.targets.iter().any(|t| t.key == key) {
                        census.targets.push(CensusTarget { key, node: a.node });
                    }
                }
            }
            Err(e) => refused.push(format!("{}: {e}", a.label)),
        }
    }
    if refused.is_empty() {
        Ok(census)
    } else {
        Err(refused)
    }
}

/// Sort a target's listing into what may be offered and what may not. Also
/// returns how many files belong to sites that exist.
pub fn classify_folders(
    listing: Vec<OffsiteFolderListing>,
    domains: &HashSet<String>,
) -> (Vec<OrphanFolder>, usize) {
    let mut in_use = 0;
    let mut out = Vec::new();
    for folder in listing {
        let mut by_domain: BTreeMap<String, Vec<OrphanFile>> = BTreeMap::new();
        let mut unknown = Vec::new();
        for f in folder.files {
            let Some(parsed) = hyperion_validate::parse_offsite_backup_name(&f.name) else {
                unknown.push(UnknownFile {
                    name: f.name,
                    bytes: f.bytes,
                });
                continue;
            };
            if domains.contains(parsed.domain.as_str()) {
                in_use += 1;
                continue;
            }
            by_domain
                .entry(parsed.domain.as_str().to_string())
                .or_default()
                .push(OrphanFile {
                    value: format!("{}/{}", folder.name, f.name),
                    name: f.name,
                    bytes: f.bytes,
                    stamp: parsed.stamp,
                    is_dump: parsed.is_dump,
                });
        }
        if by_domain.is_empty() && unknown.is_empty() && folder.error.is_none() {
            continue;
        }
        unknown.sort_by(|a, b| a.name.cmp(&b.name));
        let domains_here = by_domain
            .into_iter()
            .map(|(domain, mut files)| {
                files.sort_by(|a, b| b.stamp.cmp(&a.stamp).then_with(|| a.name.cmp(&b.name)));
                OrphanDomain { domain, files }
            })
            .collect();
        out.push(OrphanFolder {
            name: folder.name,
            domains: domains_here,
            unknown,
            error: folder.error,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    (out, in_use)
}

/// The ticked `<folder>/<name>`s from the form's one comma-joined field: the
/// checkboxes are UI-only, because axum's `Form` cannot gather repeated keys
/// into a `Vec`. Malformed pieces are dropped, not reported, since the field is
/// machine-written. Plain names hold neither a comma nor a slash, so the split
/// cannot cut one in two.
pub fn parse_selection(raw: &str) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    raw.split(',')
        .filter_map(|piece| {
            let (folder, file) = piece.trim().split_once('/')?;
            (!folder.is_empty() && !file.is_empty() && !file.contains('/'))
                .then(|| (folder.to_string(), file.to_string()))
        })
        .filter(|pair| seen.insert(pair.clone()))
        .take(MAX_SELECTED)
        .collect()
}

/// Which of the ticked files are orphans by the census just taken. The second
/// half is the ones that are not, as `<folder>/<name>`.
pub fn still_orphaned(
    selection: Vec<(String, String)>,
    domains: &HashSet<String>,
) -> (Vec<(String, String)>, Vec<String>) {
    let mut keep = Vec::new();
    let mut refused = Vec::new();
    for (folder, file) in selection {
        let orphaned = hyperion_adapters::backup::is_plain_backup_name(&folder)
            && hyperion_validate::parse_offsite_backup_name(&file)
                .is_some_and(|p| !domains.contains(p.domain.as_str()));
        if orphaned {
            keep.push((folder, file));
        } else {
            refused.push(format!("{folder}/{file}"));
        }
    }
    (keep, refused)
}

/// Take a deleted file off the report, and whatever that leaves empty.
pub fn forget_deleted(report: &mut OrphanReport, key: &str, folder: &str, file: &str) {
    let Some(target) = report.targets.iter_mut().find(|t| t.key == key) else {
        return;
    };
    let Some(f) = target.folders.iter_mut().find(|f| f.name == folder) else {
        return;
    };
    for d in &mut f.domains {
        d.files.retain(|x| x.name != file);
    }
    f.domains.retain(|d| !d.files.is_empty());
    target
        .folders
        .retain(|f| !f.domains.is_empty() || !f.unknown.is_empty() || f.error.is_some());
}

/// A census answer out of an RPC reply.
fn census_of(reply: Result<RpcResponse, String>) -> Result<OffsiteOrphanCensus, String> {
    match reply? {
        RpcResponse::BackupOrphanCensus(c) => Ok(c),
        RpcResponse::Error(e) => Err(e.to_string()),
        _ => Err("unexpected agent response".to_string()),
    }
}

/// Ask the master and every enrolled node. A node left out of the fan-out's
/// answers, for whatever reason, is an answer of "no": silence must not count
/// as having no sites.
async fn ask_every_node(state: &SharedState) -> Vec<NodeAnswer> {
    let req = Request::BackupOrphanCensus {};
    let mut answers = vec![NodeAnswer {
        node: None,
        label: "master (this server)".to_string(),
        census: census_of(
            crate::dispatcher::dispatch_to_node(state, None, req.clone())
                .await
                .map_err(|e| e.to_string()),
        ),
    }];
    let nodes = match crate::dispatcher::cached_nodes(state).await {
        Ok(nodes) => nodes,
        Err(e) => {
            answers.push(NodeAnswer {
                node: None,
                label: "enrolled nodes".to_string(),
                census: Err(format!("the list could not be read: {e}")),
            });
            return answers;
        }
    };
    let (answered, failed) = crate::dispatcher::fan_out_reporting(state, nodes.clone(), req).await;
    for n in nodes {
        let reply = if let Some((_, r)) = answered.iter().find(|(a, _)| a.node_id == n.node_id) {
            Ok(r.clone())
        } else if let Some((_, e)) = failed.iter().find(|(f, _)| f.node_id == n.node_id) {
            Err(e.to_string())
        } else {
            Err("no answer".to_string())
        };
        answers.push(NodeAnswer {
            label: if n.label.trim().is_empty() {
                n.node_id.clone()
            } else {
                n.label.clone()
            },
            node: Some(n.node_id),
            census: census_of(reply),
        });
    }
    answers
}

/// The search, as far as it can go. Stores the report for the page; returns
/// whether every target could be listed, and the job's log.
async fn run_search(
    state: &SharedState,
    reporter: &crate::handlers::jobs::JobReporter,
) -> Result<String, String> {
    reporter
        .step("Asking every node which sites it has…", 5, "")
        .await;
    let census = match merge_census(ask_every_node(state).await) {
        Ok(c) => c,
        Err(refused) => {
            let why = refusal_words(&refused);
            store_report(
                state,
                OrphanReport {
                    at: hyperion_types::now_secs(),
                    refused,
                    targets: Vec::new(),
                },
            );
            return Err(why);
        }
    };
    let total = census.targets.len();
    let mut targets = Vec::with_capacity(total);
    let mut log = format!(
        "{} domain(s) in use across the cluster.\n",
        census.domains.len()
    );
    let mut failed = Vec::new();
    for (i, t) in census.targets.iter().enumerate() {
        let pct = (10 + 85 * i / total.max(1)) as i64;
        reporter.step(&format!("Listing {}…", t.key), pct, "").await;
        let listed = match crate::dispatcher::dispatch_to_node(
            state,
            t.node.as_deref(),
            Request::BackupOrphanList {},
        )
        .await
        {
            Ok(RpcResponse::BackupOrphanList(v)) => Ok(v),
            Ok(RpcResponse::Error(e)) => Err(e.to_string()),
            Ok(_) => Err("unexpected agent response".to_string()),
            Err(e) => Err(e.to_string()),
        };
        let target = match listed {
            Ok(listing) => {
                let (folders, in_use) = classify_folders(listing, &census.domains);
                OrphanTarget {
                    key: t.key.clone(),
                    folders,
                    in_use,
                    problem: None,
                }
            }
            Err(e) => {
                failed.push(format!("{}: {e}", t.key));
                OrphanTarget {
                    key: t.key.clone(),
                    folders: Vec::new(),
                    in_use: 0,
                    problem: Some(e),
                }
            }
        };
        log.push_str(&format!(
            "{}: {} leftover file(s), {} of sites that exist.\n",
            target.key,
            target.file_count(),
            target.in_use
        ));
        targets.push(target);
    }
    store_report(
        state,
        OrphanReport {
            at: hyperion_types::now_secs(),
            refused: Vec::new(),
            targets,
        },
    );
    if failed.is_empty() {
        Ok(log)
    } else {
        Err(format!("could not list {}", failed.join("; ")))
    }
}

fn refusal_words(refused: &[String]) -> String {
    format!(
        "Nothing is called leftover, because a node that did not answer could be hosting any \
         of these sites: {}",
        refused.join("; ")
    )
}

fn store_report(state: &SharedState, report: OrphanReport) {
    *state
        .caches
        .orphan_report
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(report);
}

/// May this user search for and delete these files? `BackupRun` is not enough:
/// every Customer holds it, and this reaches every tenant's backups, of sites
/// nobody holds a grant on any more because they are gone. Same rule as the
/// estate-wide backfill.
fn may_manage(ctx: &AuthCtx) -> bool {
    ctx.can(Capability::BackupTargets) && ctx.scope_all()
}

const PAGE: &str = "/settings/backups/orphans";

const NOT_ALLOWED: &str =
    "Leftover backups need the \u{201c}Manage off-site backup targets\u{201d} \
                           permission and access to every site.";

#[derive(Template)]
#[template(path = "settings_orphans.html")]
struct OrphansTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    report: Option<OrphanReport>,
}

/// GET /settings/backups/orphans — the last search and its findings.
pub async fn get_orphans(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !may_manage(&ctx) {
        return Ok(Redirect::to("/").into_response());
    }
    let (mut chrome, _nodes) = chrome::chrome(&state, &ctx, "backups", &q).await;
    chrome.title = "Leftover backups";
    chrome.lead = "Backups on the FTP/SFTP target from sites that no longer exist.";
    // Nothing on this page is agent.toml, so the frame's "only an Owner can
    // change these" does not apply to whoever got this far.
    chrome.can_edit = true;
    let report = state
        .caches
        .orphan_report
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let tpl = OrphansTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        report,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// POST /settings/backups/orphans/scan — one round trip per folder on every
/// target, so a job. Deletes nothing.
pub async fn post_scan(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !may_manage(&ctx) {
        return Ok(chrome::back_with_error("offsite-orphans", NOT_ALLOWED));
    }
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "offsite-orphan-scan",
        None,
        "{}",
        &ctx.username,
        actor_uid,
        move |reporter| async move {
            let hb = reporter.heartbeat("Still listing the off-site target…");
            let outcome = run_search(&job_state, &reporter).await;
            hb.abort();
            match outcome {
                Ok(log) => {
                    reporter.step("Finished.", 100, &log).await;
                    reporter.finish(true, None).await;
                }
                Err(why) => reporter.finish(false, Some(why)).await,
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

#[derive(serde::Deserialize)]
pub struct OrphanDeleteForm {
    target: String,
    #[serde(default)]
    files: String,
}

/// POST /settings/backups/orphans/delete — delete the ticked files, after
/// asking every node again. One file at a time: each gets its own audit row and
/// its own verdict, and the job can say how far it got.
pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<OrphanDeleteForm>,
) -> Result<Response, AppError> {
    if !may_manage(&ctx) {
        return Ok(chrome::back_with_error("offsite-orphans", NOT_ALLOWED));
    }
    let selection = parse_selection(&form.files);
    if selection.is_empty() {
        return Ok(Redirect::to(&format!(
            "{PAGE}?flash_error=Tick+at+least+one+file+to+delete."
        ))
        .into_response());
    }
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let key = form.target.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "offsite-orphan-delete",
        Some(form.target.as_str()),
        &serde_json::json!({ "files": selection.len() }).to_string(),
        &ctx.username,
        actor_uid,
        move |reporter| async move {
            let hb = reporter.heartbeat("Still deleting…");
            let (ok, err) = run_delete(
                &job_state,
                &reporter,
                &key,
                selection,
                actor_uid,
                &actor_label,
            )
            .await;
            hb.abort();
            reporter.finish(ok, err).await;
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

/// The delete job's work. Whatever the census refuses is not touched.
async fn run_delete(
    state: &SharedState,
    reporter: &crate::handlers::jobs::JobReporter,
    key: &str,
    selection: Vec<(String, String)>,
    actor_uid: i64,
    actor_label: &str,
) -> (bool, Option<String>) {
    reporter
        .step("Asking every node again which sites it has…", 5, "")
        .await;
    let census = match merge_census(ask_every_node(state).await) {
        Ok(c) => c,
        Err(refused) => {
            return (
                false,
                Some(format!("Nothing was deleted. {}", refusal_words(&refused))),
            )
        }
    };
    let Some(target) = census.targets.iter().find(|t| t.key == key) else {
        return (
            false,
            Some(format!(
                "Nothing was deleted: no node pushes to {key} any more."
            )),
        );
    };
    let (keep, refused) = still_orphaned(selection, &census.domains);
    if !refused.is_empty() {
        reporter
            .step(
                "Checked the selection.",
                10,
                &format!(
                    "Left alone, because a site uses the domain now or the name is not a \
                     backup's: {}\n",
                    refused.join(", ")
                ),
            )
            .await;
    }
    let total = keep.len();
    let mut failed = 0;
    let mut deleted = 0;
    for (i, (folder, file)) in keep.into_iter().enumerate() {
        let reply = crate::dispatcher::dispatch_to_node(
            state,
            target.node.as_deref(),
            Request::BackupOrphanDelete {
                target: key.to_string(),
                folder: folder.clone(),
                file: file.clone(),
                actor_uid,
                actor_label: actor_label.to_string(),
            },
        )
        .await;
        let line = match reply {
            Ok(RpcResponse::BackupOrphanDelete(_)) => {
                deleted += 1;
                let mut guard = state
                    .caches
                    .orphan_report
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if let Some(report) = guard.as_mut() {
                    forget_deleted(report, key, &folder, &file);
                }
                format!("deleted {folder}/{file}\n")
            }
            Ok(RpcResponse::Error(e)) => {
                failed += 1;
                format!("NOT deleted {folder}/{file}: {e}\n")
            }
            Ok(_) => {
                failed += 1;
                format!("NOT deleted {folder}/{file}: unexpected agent response\n")
            }
            Err(e) => {
                failed += 1;
                format!("NOT deleted {folder}/{file}: {e}\n")
            }
        };
        let pct = (10 + 88 * (i + 1) / total.max(1)) as i64;
        reporter
            .step(&format!("{} of {total} file(s) done…", i + 1), pct, &line)
            .await;
    }
    reporter
        .step(
            "Finished.",
            100,
            &format!(
                "{deleted} deleted, {failed} failed, {} left alone.\n",
                refused.len()
            ),
        )
        .await;
    if failed > 0 {
        (
            false,
            Some(format!("{failed} of {total} file(s) could not be deleted")),
        )
    } else if !refused.is_empty() {
        (
            false,
            Some(format!(
                "{} selected file(s) are no longer leftovers and were left alone",
                refused.len()
            )),
        )
    } else {
        (true, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::OffsiteFile;

    fn answer(
        node: Option<&str>,
        label: &str,
        domains: &[&str],
        target: Option<&str>,
    ) -> NodeAnswer {
        NodeAnswer {
            node: node.map(str::to_string),
            label: label.to_string(),
            census: Ok(OffsiteOrphanCensus {
                domains: domains.iter().map(|d| d.to_string()).collect(),
                target: target.map(str::to_string),
            }),
        }
    }

    fn domains(names: &[&str]) -> HashSet<String> {
        names.iter().map(|d| d.to_string()).collect()
    }

    fn folder(name: &str, files: &[&str]) -> OffsiteFolderListing {
        OffsiteFolderListing {
            name: name.to_string(),
            files: files
                .iter()
                .map(|n| OffsiteFile {
                    name: n.to_string(),
                    bytes: 10,
                })
                .collect(),
            error: None,
        }
    }

    /// Guessing here deletes a live site's only off-site copy: the silent
    /// node may be the one hosting it.
    #[test]
    fn one_silent_node_refuses_the_whole_census_and_is_named() {
        let got = merge_census(vec![
            answer(None, "master", &["a.cz"], Some("ftp://t")),
            NodeAnswer {
                node: Some("web-2".into()),
                label: "web-2.example.net".into(),
                census: Err("timed out".into()),
            },
            answer(Some("web-3"), "web-3", &["b.cz"], Some("ftp://t")),
        ]);
        let refused = got.expect_err("refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].contains("web-2.example.net"), "{refused:?}");
        assert!(refused[0].contains("timed out"), "{refused:?}");
    }

    #[test]
    fn the_census_is_every_nodes_domains_and_each_target_once() {
        let c = merge_census(vec![
            answer(None, "master", &["a.cz"], None),
            answer(Some("web-2"), "web-2", &["B.cz"], Some("ftp://shared")),
            answer(Some("web-3"), "web-3", &["c.cz"], Some("ftp://shared")),
            answer(Some("web-4"), "web-4", &[], Some("sftp://own")),
        ])
        .expect("census");
        assert_eq!(c.domains, domains(&["a.cz", "b.cz", "c.cz"]));
        assert_eq!(
            c.targets,
            [
                CensusTarget {
                    key: "ftp://shared".into(),
                    node: Some("web-2".into())
                },
                CensusTarget {
                    key: "sftp://own".into(),
                    node: Some("web-4".into())
                },
            ],
            "a shared target is listed once, through the first node that has it"
        );
    }

    #[test]
    fn a_file_goes_by_its_whole_domain_never_a_prefix_of_it() {
        // a.cz is alive, a.cz-shop.cz is gone.
        let (folders, in_use) = classify_folders(
            vec![folder(
                "web1",
                &["a.cz-shop.cz-100.tar.gz", "a.cz-100.tar.gz"],
            )],
            &domains(&["a.cz"]),
        );
        assert_eq!(in_use, 1);
        assert_eq!(folders[0].domains.len(), 1);
        assert_eq!(folders[0].domains[0].domain, "a.cz-shop.cz");
        assert_eq!(
            folders[0].domains[0].files[0].name,
            "a.cz-shop.cz-100.tar.gz"
        );
        assert_eq!(
            folders[0].domains[0].files[0].value,
            "web1/a.cz-shop.cz-100.tar.gz"
        );

        // The other way round.
        let (folders, in_use) = classify_folders(
            vec![folder(
                "web1",
                &["a.cz-shop.cz-100.tar.gz", "a.cz-100.tar.gz"],
            )],
            &domains(&["a.cz-shop.cz"]),
        );
        assert_eq!(in_use, 1);
        assert_eq!(folders[0].domains[0].domain, "a.cz");
    }

    #[test]
    fn unrecognised_files_are_shown_as_unknown_and_never_offered() {
        let (folders, in_use) = classify_folders(
            vec![folder(
                "web1",
                &[
                    "notes.txt",
                    "a.cz-100.manifest.json",
                    "A.cz-100.tar.gz",
                    "a.cz-100-200.tar.gz",
                    "gone.cz-100.sql",
                ],
            )],
            &domains(&[]),
        );
        assert_eq!(in_use, 0);
        let f = &folders[0];
        let offered: Vec<&str> = f
            .domains
            .iter()
            .flat_map(|d| d.files.iter().map(|x| x.name.as_str()))
            .collect();
        assert_eq!(offered, ["gone.cz-100.sql"]);
        assert!(f.domains[0].files[0].is_dump);
        assert_eq!(f.unknown.len(), 4);
    }

    #[test]
    fn folders_with_nothing_to_say_are_left_out_and_newest_files_come_first() {
        let mut broken = folder("web3", &[]);
        broken.error = Some("curl (55)".into());
        let (folders, in_use) = classify_folders(
            vec![
                folder("web9", &["live.cz-100.tar.gz"]),
                broken,
                folder("web1", &["z.cz-100.tar.gz", "b.cz-100.sql", "b.cz-300.sql"]),
                folder("web2", &[]),
            ],
            &domains(&["live.cz"]),
        );
        assert_eq!(in_use, 1);
        let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["web1", "web3"], "an unlisted folder is not empty");
        assert_eq!(folders[1].error.as_deref(), Some("curl (55)"));
        let web1 = &folders[0];
        assert_eq!(web1.domains[0].domain, "b.cz");
        assert_eq!(web1.domains[0].files[0].stamp, 300);
        assert_eq!(web1.domains[1].domain, "z.cz");
    }

    #[test]
    fn a_selection_is_read_deduped_and_capped() {
        assert_eq!(
            parse_selection(
                " web1/a.cz-1.sql,web1/a.cz-1.sql,, web2/b.cz-2.tgz ,nofolder,a/b/c,/x"
            ),
            [
                ("web1".to_string(), "a.cz-1.sql".to_string()),
                ("web2".to_string(), "b.cz-2.tgz".to_string()),
            ]
        );
        assert!(parse_selection("").is_empty());
        let many: Vec<String> = (0..MAX_SELECTED + 50)
            .map(|i| format!("web1/a.cz-{i}.sql"))
            .collect();
        assert_eq!(parse_selection(&many.join(",")).len(), MAX_SELECTED);
    }

    /// The page can be hours old: a site created since, a tampered POST or a
    /// file name that was never offered all stop here.
    #[test]
    fn only_what_is_orphaned_right_now_survives_a_selection() {
        let (keep, refused) = still_orphaned(
            vec![
                ("web1".into(), "gone.cz-1.sql".into()),
                ("web1".into(), "back.cz-1.sql".into()),
                ("web1".into(), "notes.txt".into()),
                ("..".into(), "gone.cz-1.sql".into()),
                ("%2e%2e".into(), "gone.cz-1.sql".into()),
            ],
            &domains(&["back.cz"]),
        );
        assert_eq!(keep, [("web1".to_string(), "gone.cz-1.sql".to_string())]);
        assert_eq!(
            refused,
            [
                "web1/back.cz-1.sql",
                "web1/notes.txt",
                "../gone.cz-1.sql",
                "%2e%2e/gone.cz-1.sql",
            ]
        );
    }

    #[test]
    fn a_deleted_file_leaves_the_report_and_takes_empty_groups_with_it() {
        let (folders, _) = classify_folders(
            vec![
                folder("web1", &["a.cz-1.sql", "a.cz-2.sql", "b.cz-1.sql"]),
                folder("web2", &["a.cz-1.sql"]),
            ],
            &domains(&[]),
        );
        let mut report = OrphanReport {
            at: 1,
            refused: Vec::new(),
            targets: vec![OrphanTarget {
                key: "ftp://t".into(),
                folders,
                in_use: 0,
                problem: None,
            }],
        };
        forget_deleted(&mut report, "ftp://other", "web2", "a.cz-1.sql");
        assert_eq!(report.targets[0].folders.len(), 2, "another target's file");
        forget_deleted(&mut report, "ftp://t", "web2", "a.cz-1.sql");
        assert_eq!(report.targets[0].folders.len(), 1);
        forget_deleted(&mut report, "ftp://t", "web1", "a.cz-1.sql");
        assert_eq!(report.targets[0].folders[0].domains[0].files.len(), 1);
        forget_deleted(&mut report, "ftp://t", "web1", "a.cz-2.sql");
        assert_eq!(report.targets[0].folders[0].domains.len(), 1);
    }

    fn render(report: Option<OrphanReport>) -> String {
        OrphansTpl {
            username: "kevin",
            user_initial: 'k',
            active: "settings",
            css_version: "t",
            htmx_version: "t",
            chrome: Chrome {
                section: "backups",
                title: "Leftover backups",
                lead: "",
                can_edit: true,
                has_nodes: true,
                flash: None,
                flash_error: None,
            },
            csrf_token: "tok".into(),
            report,
        }
        .render()
        .expect("render")
    }

    /// The checkbox is the only way into a delete, so what has none cannot go.
    #[test]
    fn only_orphans_get_a_checkbox_and_the_delete_asks_to_be_typed() {
        let (folders, in_use) = classify_folders(
            vec![folder(
                "web1",
                &["gone.cz-1762000000.tar.gz", "notes.txt", "live.cz-1.sql"],
            )],
            &domains(&["live.cz"]),
        );
        let page = render(Some(OrphanReport {
            at: 1,
            refused: Vec::new(),
            targets: vec![OrphanTarget {
                key: "ftp://bk@h:21/backups".into(),
                folders,
                in_use,
                problem: None,
            }],
        }));
        assert!(
            page.contains("value=\"web1/gone.cz-1762000000.tar.gz\""),
            "{page}"
        );
        assert_eq!(page.matches("class=\"orphan-file\"").count(), 1, "{page}");
        assert!(page.contains("notes.txt"), "shown: {page}");
        assert!(!page.contains("value=\"web1/notes.txt\""), "{page}");
        assert!(!page.contains("live.cz-1.sql"), "a live site's: {page}");
        assert!(page.contains("data-confirm-require=\"delete\""), "{page}");
        assert!(page.contains("value=\"ftp://bk@h:21/backups\""), "{page}");
    }

    #[test]
    fn a_refusal_lists_the_nodes_and_offers_nothing() {
        let page = render(Some(OrphanReport {
            at: 1,
            refused: vec!["web-2: timed out".into()],
            targets: Vec::new(),
        }));
        assert!(page.contains("id=\"orphan-refused\""), "{page}");
        assert!(page.contains("web-2: timed out"), "{page}");
        assert!(!page.contains("Delete ticked files"), "{page}");
        assert!(!page.contains("id=\"orphan-no-target\""), "{page}");
    }

    #[test]
    fn a_stamp_too_small_for_a_unix_time_has_no_date() {
        let file = |stamp| OrphanFile {
            name: String::new(),
            bytes: 0,
            stamp,
            value: String::new(),
            is_dump: false,
        };
        assert_eq!(file(100).date(), "unknown");
        assert!(file(1_762_000_000).date().starts_with("2025-"));
    }
}
