//! hyperion-web library — the axum-based admin UI, factored so the binary
//! can drive it and tests can call `build_router` directly.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod admin_user;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod ratelimit;
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
        .route(
            "/hostings/acme-email",
            post(handlers::hostings::post_set_acme_email),
        )
        .route(
            "/hostings/wp/install",
            post(handlers::hostings::post_wp_install),
        )
        .route(
            "/hostings/wp/plugin-action",
            post(handlers::hostings::post_wp_plugin_action),
        )
        .route(
            "/hostings/migration/export",
            post(handlers::hostings::post_migration_export),
        )
        .route("/hostings/import", get(handlers::migration::get_import))
        .route(
            "/hostings/migration/import-from-url",
            post(handlers::migration::post_import_from_url),
        )
        .route(
            "/hostings/backup-now",
            post(handlers::hostings::post_backup_now),
        )
        .route(
            "/hostings/expiry/set",
            post(handlers::hostings::post_set_expiry),
        )
        .route(
            "/hostings/expiry/clear",
            post(handlers::hostings::post_clear_expiry),
        )
        .route(
            "/hostings/dns-check",
            post(handlers::hostings::post_dns_check),
        )
        .route(
            "/hostings/cert/issue",
            post(handlers::hostings::post_cert_issue),
        )
        .route(
            "/hostings/restore",
            post(handlers::hostings::post_restore),
        )
        .route(
            "/hostings/logs",
            post(handlers::hostings::post_logs),
        )
        .route(
            "/hostings/cron",
            post(handlers::hostings::post_cron_save),
        )
        .route(
            "/hostings/wp/reset-password",
            post(handlers::hostings::post_wp_reset),
        )
        .route(
            "/hostings/db/reset-password",
            post(handlers::hostings::post_db_reset),
        )
        .route(
            "/hostings/ftp/set",
            post(handlers::hostings::post_ftp_set),
        )
        .route(
            "/hostings/ftp/disable",
            post(handlers::hostings::post_ftp_disable),
        )
        .route(
            "/hostings/restore-upload",
            post(handlers::hostings::post_restore_upload)
                .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024 * 1024)),
        )
        .route("/hostings/bulk", post(handlers::hostings::post_bulk))
        .route("/stats", get(handlers::stats::get_stats))
        .route(
            "/services",
            get(handlers::services_health::get_services_health),
        )
        .route(
            "/services/restart",
            post(handlers::services_health::post_service_restart),
        )
        .route(
            "/services/install",
            post(handlers::services_health::post_service_install),
        )
        .route("/settings", get(handlers::settings::get_settings))
        .route(
            "/settings/email-test",
            post(handlers::settings::post_email_test),
        )
        .route(
            "/api/email-autodetect",
            post(handlers::settings::post_email_autodetect),
        )
        .route(
            "/settings/config",
            post(handlers::settings::post_config),
        )
        .route("/admin/users", get(handlers::users::get_users))
        .route("/admin/users", post(handlers::users::post_create))
        .route("/admin/users/role", post(handlers::users::post_set_role))
        .route("/admin/users/lock", post(handlers::users::post_lock))
        .route("/admin/users/delete", post(handlers::users::post_delete))
        .route(
            "/admin/users/password",
            post(handlers::users::post_reset_password),
        )
        .route(
            "/hostings/access/grant",
            post(handlers::hostings::post_access_grant),
        )
        .route(
            "/hostings/access/revoke",
            post(handlers::hostings::post_access_revoke),
        )
        .route(
            "/hostings/:selector/files",
            get(handlers::files::get_files),
        )
        .route(
            "/hostings/monitor/set",
            post(handlers::hostings::post_monitor_set),
        )
        .route(
            "/hostings/monitor/probe",
            post(handlers::hostings::post_monitor_probe),
        )
        .route("/api/search", get(handlers::search::get_search))
        .route("/profile", get(handlers::profile::get_profile))
        .route("/profile/2fa/start", post(handlers::profile::post_2fa_start))
        .route("/profile/2fa/confirm", post(handlers::profile::post_2fa_confirm))
        .route("/profile/2fa/disable", post(handlers::profile::post_2fa_disable))
        .route(
            "/profile/password",
            post(handlers::profile::post_change_password),
        )
        .route(
            "/hostings/dns-check-domain",
            post(handlers::hostings::post_dns_check_domain),
        )
        .route(
            "/hostings/backups/delete",
            post(handlers::hostings::post_backup_delete),
        )
        .route("/profiles", get(handlers::profiles::get_profiles))
        .route("/profiles/create", post(handlers::profiles::post_create))
        .route(
            "/profiles/:id/edit",
            get(handlers::profiles::get_edit),
        )
        .route(
            "/profiles/:id/update",
            post(handlers::profiles::post_update),
        )
        .route("/profiles/delete", post(handlers::profiles::post_delete))
        .route("/profiles/apply", post(handlers::profiles::post_apply))
        .route("/audit", get(handlers::audit::get_audit))
        .route("/emails", get(handlers::emails::get_emails))
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
        .route("/login/2fa", get(handlers::login::get_login_2fa))
        .route("/login/2fa", post(handlers::login::post_login_2fa))
        .route("/static/app.css", get(handlers::statics::app_css))
        .route("/static/htmx.min.js", get(handlers::statics::htmx_js))
        // Node enrollment — no session auth (the token IS the credential).
        .route("/api/enroll", post(handlers::enroll::post_enroll))
        .route("/api/heartbeat", post(handlers::enroll::post_heartbeat))
        // Probes — no auth (LB / monitoring scrapes).
        .route("/healthz", get(handlers::health::get_healthz))
        .route("/readyz", get(handlers::health::get_readyz))
        // Migration bundle downloads — public-by-design, signature-gated.
        // Target nodes pull the bundle without a session cookie.
        .route(
            "/api/migration/bundle/:bundle_id/:filename",
            get(handlers::migration::get_bundle_file),
        )
        .with_state(state)
}
