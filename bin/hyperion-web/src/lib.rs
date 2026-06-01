//! hyperion-web library — the axum-based admin UI, factored so the binary
//! can drive it and tests can call `build_router` directly.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod admin_user;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod state;

use crate::state::SharedState;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;

pub fn build_router(state: SharedState) -> Router {
    let protected = Router::new()
        .route("/", get(handlers::dashboard::get_dashboard))
        .route("/hostings", get(handlers::hostings::get_list))
        .route("/hostings/new", get(handlers::hostings::get_new))
        .route("/hostings", post(handlers::hostings::post_create))
        .route("/hostings/delete", post(handlers::hostings::post_delete))
        .route("/hostings/suspend", post(handlers::hostings::post_suspend))
        .route("/hostings/resume", post(handlers::hostings::post_resume))
        .route(
            "/hostings/set-limits",
            post(handlers::hostings::post_set_limits),
        )
        .route("/audit", get(handlers::audit::get_audit))
        .route("/install", get(handlers::install::get_install))
        .route("/install/invite", post(handlers::install::post_invite))
        .route(
            "/install/invite/revoke",
            post(handlers::install::post_revoke),
        )
        .route("/hostings/:selector", get(handlers::hostings::get_detail))
        .route("/logout", post(handlers::login::post_logout))
        .layer(from_fn_with_state(state.clone(), auth::check_csrf))
        .layer(from_fn_with_state(state.clone(), auth::require_auth));

    Router::new()
        .merge(protected)
        .route("/login", get(handlers::login::get_login))
        .route("/login", post(handlers::login::post_login))
        .route("/static/app.css", get(handlers::statics::app_css))
        .route("/static/htmx.min.js", get(handlers::statics::htmx_js))
        .with_state(state)
}
