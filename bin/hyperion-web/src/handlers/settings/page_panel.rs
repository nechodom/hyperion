//! `GET /settings/panel` — where the panel is reached, and self-updates.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{AgentConfigView, UpdateStatus};

#[derive(Template)]
#[template(path = "settings_panel.html")]
struct PanelTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    config: AgentConfigView,
    config_error: Option<String>,
    /// No usable Let's Encrypt contact (empty or a placeholder), so the
    /// panel's certificate request would be refused.
    acme_missing: bool,
    update: UpdateStatus,
    current_short: String,
    latest_short: String,
}

pub async fn get_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, _nodes) = chrome::chrome(&state, &ctx, "panel", &q).await;
    let (config_res, update_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        // A release check can reach the network; a slow one shows as
        // "unknown" rather than holding the page.
        tokio::time::timeout(
            std::time::Duration::from_secs(4),
            hyperion_rpc_client::call(
                &state.agent_socket,
                Request::UpdateCheck {
                    force_refresh: false
                },
            ),
        ),
    );
    let (config, config_error) = super::config_or_default(config_res);
    let update = match update_res {
        Ok(Ok(RpcResponse::UpdateCheck(u))) => u,
        _ => UpdateStatus::default(),
    };
    let tpl = PanelTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        current_short: super::short_sha(&update.current_sha),
        latest_short: super::short_sha(&update.latest_sha),
        acme_missing: config_error.is_none()
            && super::overview::acme_contact_missing(&config.acme.contact_email),
        config,
        config_error,
        update,
    };
    Ok(Html(tpl.render()?).into_response())
}
