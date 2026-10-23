//! Service health → "PHP versions": every PHP branch a node runs, whether its
//! build carries a published hole, which sites sit on it, and the uninstall
//! for a branch nothing needs any more.
//!
//! The node reports raw facts (`PhpRuntimes`); the verdict is worked out HERE
//! against this binary's advisory table (`hyperion_types::php_security`), so
//! a worker on an older agent is still judged by what the master knows.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::handlers::mail_health::{node_target, NodeQuery};
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::php_security::{
    parse_branch, parse_package_version, verdict, PhpPatchState, PhpRuntime,
};
use serde::Deserialize;

/// Sites listed by name on a row before "and N more".
const SITES_SHOWN: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdvisoryRef {
    pub cve: &'static str,
    pub title: &'static str,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SiteRef {
    pub domain: String,
    pub trashed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhpRow {
    pub branch: String,
    /// "8.1.34", or the raw package version when it does not parse.
    pub build: String,
    /// Pill class: `ok` / `warn` / `err` / `muted`.
    pub tone: &'static str,
    pub status: String,
    pub note: String,
    pub advisories: Vec<AdvisoryRef>,
    pub sites: Vec<SiteRef>,
    pub more_sites: usize,
    pub site_count: usize,
    pub pma: bool,
    /// The branch can never be fixed — the uninstall is the way out, so it
    /// is the primary (red) action rather than a quiet one.
    pub unfixable: bool,
    /// Why the Uninstall button is not offered. `None` = offered. The node
    /// re-checks every rule (and phpMyAdmin's) before purging anything.
    pub blocked: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PhpView {
    pub rows: Vec<PhpRow>,
    /// `ok` / `warn` / `err` / `muted`.
    pub tone: &'static str,
    pub verdict: String,
}

fn row_for(r: &PhpRuntime, others_with_fpm: bool) -> PhpRow {
    let installed = r.fpm || !r.package_version.is_empty();
    let v = parse_branch(&r.branch).map(|b| verdict(b, &r.package_version));
    let build = parse_package_version(&r.package_version)
        .map(|((a, b, c), _)| format!("{a}.{b}.{c}"))
        .unwrap_or_else(|| r.package_version.clone());
    let fix = v
        .as_ref()
        .and_then(|v| v.update_to.clone())
        .unwrap_or_default();
    let b = &r.branch;
    let state = v.as_ref().map(|v| v.state);
    let (tone, status, note) = match state {
        _ if !installed => (
            "err",
            "Not installed".to_string(),
            format!(
                "Sites set to PHP {b} cannot run: the branch is not on this node. \
                 Install it from the list above, or switch the sites to another PHP."
            ),
        ),
        Some(PhpPatchState::Unfixable) => (
            "err",
            "No fix — end of life".to_string(),
            format!(
                "Known remote-code-execution holes that will never be closed on {b}: the \
                 branch is past end of life. Move every site to PHP 8.3 or 8.4 on its PHP \
                 tab, then uninstall {b} here."
            ),
        ),
        Some(PhpPatchState::Outdated) => (
            "err",
            format!("Update to {fix}"),
            format!(
                "This build has known remote-code-execution holes, fixed in {fix}. Run the \
                 operating-system update for this node (Nodes → Update) to install it."
            ),
        ),
        Some(PhpPatchState::DistroBuild) => (
            "warn",
            "Debian build — check".to_string(),
            format!(
                "Debian's own build. Debian backports security fixes without raising the \
                 version number, so this may already carry the fix that upstream shipped \
                 in {fix} — check the Debian security tracker for php{b}."
            ),
        ),
        Some(PhpPatchState::Unknown) | None => (
            "muted",
            "Version unknown".to_string(),
            "The installed build's version could not be read, so it cannot be checked \
             against known holes."
                .to_string(),
        ),
        Some(PhpPatchState::Patched) => (
            "ok",
            "Patched".to_string(),
            "No known hole in this build.".to_string(),
        ),
    };
    let advisories = v
        .as_ref()
        .map(|v| {
            v.advisories
                .iter()
                .map(|a| AdvisoryRef {
                    cve: a.cve,
                    title: a.title,
                    url: a.url(),
                })
                .collect()
        })
        .unwrap_or_default();
    let blocked = if !installed {
        Some("Not installed.".to_string())
    } else if !r.sites.is_empty() {
        Some(format!(
            "Move {} first — removing {b} would take {} down.",
            if r.sites.len() == 1 {
                "its site".to_string()
            } else {
                format!("its {} sites", r.sites.len())
            },
            if r.sites.len() == 1 { "it" } else { "them" },
        ))
    } else if r.fpm && !others_with_fpm {
        Some("The only PHP on this node — install another first.".to_string())
    } else {
        None
    };
    PhpRow {
        branch: r.branch.clone(),
        build,
        tone,
        status,
        note,
        advisories,
        sites: r
            .sites
            .iter()
            .take(SITES_SHOWN)
            .map(|s| SiteRef {
                domain: s.domain.clone(),
                trashed: s.trashed,
            })
            .collect(),
        more_sites: r.sites.len().saturating_sub(SITES_SHOWN),
        site_count: r.sites.len(),
        pma: r.pma,
        unfixable: state == Some(PhpPatchState::Unfixable),
        blocked,
    }
}

pub(crate) fn build_view(runtimes: &[PhpRuntime]) -> PhpView {
    let rows: Vec<PhpRow> = runtimes
        .iter()
        .map(|r| {
            let others = runtimes.iter().any(|o| o.branch != r.branch && o.fpm);
            row_for(r, others)
        })
        .collect();
    if rows.is_empty() {
        return PhpView {
            rows,
            tone: "muted",
            verdict: "No PHP installed on this node.".into(),
        };
    }
    let bad: Vec<String> = rows
        .iter()
        .filter(|r| r.tone == "err")
        .map(|r| {
            if r.site_count > 0 {
                format!(
                    "PHP {}: {} — {} site{}",
                    r.branch,
                    r.status.to_lowercase(),
                    r.site_count,
                    if r.site_count == 1 { "" } else { "s" }
                )
            } else {
                format!("PHP {}: {}", r.branch, r.status.to_lowercase())
            }
        })
        .collect();
    let (tone, verdict) = if !bad.is_empty() {
        ("err", bad.join(" · "))
    } else if rows.iter().any(|r| r.tone == "warn" || r.tone == "muted") {
        (
            "warn",
            "No PHP build here is known to be exposed, but not every one could be checked."
                .to_string(),
        )
    } else {
        (
            "ok",
            format!(
                "All {} PHP version{} patched against known holes.",
                rows.len(),
                if rows.len() == 1 { "" } else { "s" }
            ),
        )
    };
    PhpView {
        rows,
        tone,
        verdict,
    }
}

#[derive(Template)]
#[template(path = "_php_versions.html")]
struct PhpVersionsTpl {
    view: PhpView,
    error: Option<String>,
    is_super_admin: bool,
    csrf_token: String,
    /// `node` for the forms: empty = master.
    node: String,
}

/// `GET /services/php?node=<id>` — the PHP versions group's body. Lazy: it
/// asks the node for its packages and sites.
pub async fn get_php_versions(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<NodeQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ServicesView) {
        return Ok(Html(
            "<div class=\"item\"><span class=\"text-soft small\">admin only</span></div>"
                .to_string(),
        )
        .into_response());
    }
    let target = node_target(&q.node);
    let (view, error) =
        match crate::dispatcher::dispatch_to_node(&state, target.as_deref(), Request::PhpRuntimes)
            .await
        {
            Ok(RpcResponse::PhpRuntimes(v)) => (build_view(&v), None),
            Ok(RpcResponse::Error(e)) => (
                PhpView::default(),
                Some(format!(
                    "The node could not list its PHP versions: {e}. An agent older than this \
                     panel does not know how — update the node."
                )),
            ),
            Ok(_) => (
                PhpView::default(),
                Some("Unexpected answer from the node.".to_string()),
            ),
            Err(e) => (
                PhpView::default(),
                Some(format!("Could not reach the node: {e}")),
            ),
        };
    let tpl = PhpVersionsTpl {
        view,
        error,
        is_super_admin: ctx.is_super_admin(),
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        node: target.unwrap_or_default(),
    };
    Ok(([("cache-control", "no-store")], Html(tpl.render()?)).into_response())
}

#[derive(Deserialize)]
pub struct PhpUninstallForm {
    pub branch: String,
    #[serde(default)]
    pub node: String,
}

/// `POST /services/php-uninstall` — super_admin only. Starts the purge on
/// the node and lands on the install-progress panel that follows it.
pub async fn post_php_uninstall(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PhpUninstallForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let target = node_target(&form.node);
    let prefix = match target.as_deref() {
        Some(id) => format!("node={}&", crate::handlers::jobs::urlencode(id)),
        None => String::new(),
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::PhpUninstall {
            branch: form.branch.clone(),
        },
    )
    .await?;
    let dest = match resp {
        RpcResponse::PhpUninstall => format!(
            "/services?{prefix}flash={}#install-progress",
            crate::handlers::jobs::urlencode(&format!(
                "Uninstall of PHP {} started — see live progress below",
                form.branch
            )),
        ),
        RpcResponse::Error(e) => format!(
            "/services?{prefix}flash_error={}#php-versions",
            crate::handlers::jobs::urlencode(&e.to_string()),
        ),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::php_security::PhpRuntimeSite;

    fn rt(branch: &str, version: &str, fpm: bool, sites: &[&str]) -> PhpRuntime {
        PhpRuntime {
            branch: branch.into(),
            package_version: version.into(),
            fpm,
            sites: sites
                .iter()
                .map(|d| PhpRuntimeSite {
                    id: d.to_string(),
                    domain: d.to_string(),
                    trashed: false,
                })
                .collect(),
            pma: false,
        }
    }

    #[test]
    fn an_end_of_life_branch_with_sites_is_red_and_cannot_be_removed_yet() {
        let v = build_view(&[
            rt("8.1", "8.1.34-1+0~x", true, &["a.cz", "b.cz"]),
            rt("8.4", "8.4.27-1+0~x", true, &[]),
        ]);
        assert_eq!(v.tone, "err");
        assert_eq!(v.verdict, "PHP 8.1: no fix — end of life — 2 sites");
        let r = &v.rows[0];
        assert!(r.unfixable);
        assert_eq!(r.build, "8.1.34");
        assert_eq!(r.advisories.len(), 2);
        assert!(r.advisories[0].url.ends_with("GHSA-6wmf-4rv5-p3rp"));
        assert!(r.blocked.as_deref().unwrap().contains("its 2 sites"));
        assert_eq!(v.rows[1].tone, "ok");
        assert_eq!(
            v.rows[1].blocked, None,
            "a patched branch nobody uses may go too"
        );
    }

    #[test]
    fn an_unused_end_of_life_branch_offers_the_uninstall() {
        let v = build_view(&[
            rt("8.1", "8.1.34-1+0~x", true, &[]),
            rt("8.3", "8.3.36-1+0~x", true, &["a.cz"]),
        ]);
        assert_eq!(v.rows[0].blocked, None);
        assert!(v.rows[1].blocked.is_some());
    }

    #[test]
    fn the_only_php_is_never_offered() {
        let v = build_view(&[rt("8.1", "8.1.34-1+0~x", true, &[])]);
        assert!(v.rows[0].blocked.as_deref().unwrap().contains("only PHP"));
    }

    #[test]
    fn an_outdated_build_says_what_to_update_to() {
        let v = build_view(&[rt("8.3", "8.3.20-1+0~x", true, &[])]);
        assert_eq!(v.rows[0].status, "Update to 8.3.36");
        assert_eq!(v.tone, "err");
    }

    #[test]
    fn a_branch_with_sites_but_no_package_is_flagged() {
        let v = build_view(&[
            rt("8.2", "", false, &["x.cz"]),
            rt("8.4", "8.4.27-1+0~x", true, &[]),
        ]);
        assert_eq!(v.rows[0].status, "Not installed");
        assert_eq!(v.rows[0].tone, "err");
    }

    #[test]
    fn all_patched_is_green_and_a_debian_build_is_amber() {
        let v = build_view(&[rt("8.4", "8.4.27-1+0~x", true, &[])]);
        assert_eq!(v.tone, "ok");
        let v = build_view(&[rt("8.4", "8.4.11-1+deb13u2", true, &[])]);
        assert_eq!(v.rows[0].tone, "warn");
        assert_eq!(v.tone, "warn");
    }
}
