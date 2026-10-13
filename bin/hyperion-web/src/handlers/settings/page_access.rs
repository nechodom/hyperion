//! `GET /settings/access` — who may sign in to the panel, and how long what
//! they did stays on record.
//!
//! Two settings live here, both in `[cluster]` and both read only by the
//! master: the 2FA rule for Administrators and Owners, and the audit log's
//! retention window. Users, roles and API keys have pages of their own; the
//! middle card only points at them, so somebody who used to find API keys on
//! the old one-page Settings learns where they went.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::Request;
use hyperion_state::capabilities::Capability;
use hyperion_types::AgentConfigView;

#[derive(Template)]
#[template(path = "settings_access.html")]
struct PageTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    config: AgentConfigView,
    config_error: Option<String>,
}

pub async fn get_access(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, _nodes) = chrome::chrome(&state, &ctx, "access", &q).await;
    let (config, config_error) = super::config_or_default(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView).await,
    );
    let tpl = PageTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        config,
        config_error,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(config: AgentConfigView) -> String {
        PageTpl {
            username: "kevin",
            user_initial: 'K',
            active: "settings",
            css_version: "x",
            htmx_version: "x",
            chrome: Chrome {
                section: "access",
                title: "Access",
                lead: "",
                can_edit: true,
                has_nodes: false,
                flash: None,
                flash_error: None,
            },
            csrf_token: "tok".into(),
            config,
            config_error: None,
        }
        .render()
        .expect("render")
    }

    /// `[cluster]` is written from cards on four pages, and a box named in
    /// `_checkboxes` but absent from the POST is saved as false. The 2FA form
    /// must declare its own box and nothing else; the retention form none.
    #[test]
    fn each_cluster_form_declares_only_its_own_checkboxes() {
        let html = page(AgentConfigView::default());
        let declared: Vec<&str> = html
            .match_indices(r#"name="_checkboxes" value=""#)
            .map(|(at, m)| {
                let rest = &html[at + m.len()..];
                &rest[..rest.find('"').unwrap_or(0)]
            })
            .collect();
        assert_eq!(declared, vec!["enforce_admin_2fa"]);
        assert_eq!(html.matches(r#"name="section" value="cluster""#).count(), 2);
    }

    #[test]
    fn state_reads_from_the_config() {
        let mut c = AgentConfigView::default();
        c.cluster.enforce_admin_2fa = false;
        c.cluster.audit_retention_days = 90;
        let html = page(c);
        assert!(html.contains(r#"<span class="pill warn">optional</span>"#));
        assert!(html.contains(r#"<span class="pill ok">90 days</span>"#));
        let html = page(AgentConfigView::default());
        assert!(html.contains(r#"<span class="pill ok">required</span>"#));
        assert!(html.contains("kept forever"));
    }
}
