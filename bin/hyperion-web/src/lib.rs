//! hyperion-web library — the axum-based admin UI, factored so the binary
//! can drive it and tests can call `build_router` directly.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod admin_user;
pub mod auth;
pub mod config;
pub mod dispatcher;
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
            "/hostings/vhost-options",
            post(handlers::hostings::post_vhost_options),
        )
        .route(
            "/hostings/wp/debug",
            post(handlers::hostings::post_wp_debug),
        )
        .route(
            "/hostings/wp/debug-log/rotate",
            post(handlers::hostings::post_wp_debug_log_rotate),
        )
        .route(
            "/hostings/wp/redis",
            post(handlers::hostings::post_wp_redis),
        )
        .route(
            "/hostings/wp/redis/rotate",
            post(handlers::hostings::post_wp_redis_rotate),
        )
        .route(
            "/hostings/set-limits",
            post(handlers::hostings::post_set_limits),
        )
        .route(
            "/hostings/set-php-version",
            post(handlers::hostings::post_set_php_version),
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
        .route(
            "/hostings/migration/move",
            post(handlers::hostings::post_migration_move),
        )
        .route(
            "/hostings/clone",
            post(handlers::hostings::post_hosting_clone),
        )
        .route(
            "/hostings/quota/set",
            post(handlers::hostings::post_quota_set),
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
        .route("/monitoring", get(handlers::monitoring::get_monitoring))
        .route("/trash", get(handlers::trash::get_trash))
        .route("/trash/restore", post(handlers::trash::post_trash_restore))
        .route("/trash/purge", post(handlers::trash::post_trash_purge))
        .route("/api/trash-count", get(handlers::trash::get_trash_count))
        .route("/api/check-domain", get(handlers::hostings::get_check_domain))
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
        .route(
            "/services/remount-usr-rw",
            post(handlers::services_health::post_remount_usr_rw),
        )
        .route(
            "/services/fs-diagnose",
            post(handlers::services_health::post_fs_diagnose),
        )
        .route(
            "/services/install-status",
            get(handlers::services_health::get_service_install_status),
        )
        .route("/settings", get(handlers::settings::get_settings))
        .route(
            "/settings/email-test",
            post(handlers::settings::post_email_test),
        )
        .route(
            "/settings/mta-reconfigure",
            post(handlers::settings::post_mta_reconfigure),
        )
        .route(
            "/settings/mta-test",
            post(handlers::settings::post_mta_test),
        )
        .route(
            "/settings/mta-queue-flush",
            post(handlers::settings::post_mta_queue_flush),
        )
        .route(
            "/settings/mta-queue-clear",
            post(handlers::settings::post_mta_queue_clear),
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
            "/hostings/:selector/files/upload",
            post(handlers::files::post_upload)
                // 100 MB cap matches the file manager's MAX_WRITE_BYTES
                // at the adapter (64 MB) plus headroom for the multipart
                // envelope. Default 2 MB would 400 every real upload.
                .layer(axum::extract::DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        .route(
            "/hostings/:selector/files/download",
            get(handlers::files::get_download),
        )
        .route("/hostings/files/delete", post(handlers::files::post_delete))
        .route("/hostings/files/mkdir", post(handlers::files::post_mkdir))
        .route("/hostings/files/rename", post(handlers::files::post_rename))
        .route(
            "/hostings/files/edit-save",
            post(handlers::files::post_edit_save)
                // Edited content can be > 2 MB (operator edits a big
                // wp-config.php or .htaccess); same body cap as the
                // upload route would be overkill, 5 MB is plenty.
                .layer(axum::extract::DefaultBodyLimit::max(5 * 1024 * 1024)),
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
            "/profile/email/request",
            post(handlers::profile::post_email_change_request),
        )
        .route(
            "/profile/email/confirm",
            post(handlers::profile::post_email_change_confirm),
        )
        .route(
            "/profile/email/cancel",
            post(handlers::profile::post_email_change_cancel),
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
            "/profiles/wp-assets",
            get(handlers::profiles::get_wp_assets),
        )
        .route(
            "/profiles/wp-assets/upload",
            post(handlers::profiles::post_wp_asset_upload)
                // 100 MB cap — plugin / theme ZIPs are often 20-50 MB.
                // Default 2 MB silently 400'd legitimate uploads.
                .layer(axum::extract::DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        .route(
            "/profiles/wp-assets/delete",
            post(handlers::profiles::post_wp_asset_delete),
        )
        .route(
            "/profiles/wp-assets/replace",
            post(handlers::profiles::post_wp_asset_replace)
                .layer(axum::extract::DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        .route(
            "/profiles/wp-assets/reinstall-all",
            post(handlers::profiles::post_wp_asset_reinstall_all),
        )
        .route(
            "/hostings/wp/install-from-asset",
            post(handlers::profiles::post_wp_install_from_asset),
        )
        .route(
            "/hostings/wp/theme-action",
            post(handlers::hostings::post_wp_theme_action),
        )
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
        .route("/certs", get(handlers::certs::get_certs))
        .route("/audit", get(handlers::audit::get_audit))
        .route("/settings/backups", get(handlers::backups::get_backups))
        .route(
            "/settings/backups/upsert",
            post(handlers::backups::post_upsert),
        )
        .route(
            "/settings/backups/:id/delete",
            post(handlers::backups::post_delete),
        )
        .route(
            "/settings/backups/:id/probe",
            post(handlers::backups::post_probe),
        )
        .route("/audit/verify", post(handlers::audit::post_verify_chain))
        .route("/settings/sessions", get(handlers::sessions::get_sessions))
        .route(
            "/settings/sessions/revoke",
            post(handlers::sessions::post_revoke),
        )
        .route("/jobs", get(handlers::jobs::get_jobs))
        .route("/jobs/:id", get(handlers::jobs::get_job_detail))
        .route(
            "/jobs/:id/progress",
            get(handlers::jobs::get_job_progress),
        )
        .route(
            "/jobs/:id/retry",
            post(handlers::jobs::post_job_retry),
        )
        .route(
            "/api/jobs-running-count",
            get(handlers::jobs::get_running_count),
        )
        .route("/emails", get(handlers::emails::get_emails))
        .route("/install", get(handlers::install::get_install))
        .route("/install/invite", post(handlers::install::post_invite))
        .route(
            "/install/invite/revoke",
            post(handlers::install::post_revoke),
        )
        .route(
            "/install/test-node",
            post(handlers::install::post_test_node),
        )
        .route(
            "/install/toggle-test-node",
            post(handlers::install::post_toggle_test_node),
        )
        .route(
            "/install/update-node",
            post(handlers::install::post_update_node),
        )
        .route(
            "/install/rename-node",
            post(handlers::install::post_rename_node),
        )
        .route(
            "/install/drain-node",
            post(handlers::install::post_drain_node),
        )
        .route(
            "/install/update-node-status",
            get(handlers::install::get_update_node_status),
        )
        .route("/hostings/:selector", get(handlers::hostings::get_detail))
        .route("/logout", post(handlers::login::post_logout))
        // Tiny role echo for the nav-hiding shim in base.html.
        // Returns "super_admin" | "admin" | "operator" | "viewer".
        .route("/api/me/role", get(handlers::me::get_role))
        // Avatar serve + upload. Upload uses a 2 MB body cap —
        // double the 1 MB asset cap to leave room for multipart
        // envelope overhead.
        .route("/avatar/me", get(handlers::avatar::get_my_avatar))
        .route("/avatar/:user_id", get(handlers::avatar::get_user_avatar))
        .route(
            "/profile/avatar/upload",
            post(handlers::avatar::post_avatar_upload)
                .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route(
            "/profile/avatar/clear",
            post(handlers::avatar::post_avatar_clear),
        )
        // Bell-icon notification feed. mark-read + mark-all-read are
        // CSRF-exempt at the middleware (see check_csrf comment).
        .route(
            "/notifications",
            get(handlers::notifications::get_archive),
        )
        .route(
            "/api/notifications/feed",
            get(handlers::notifications::get_feed),
        )
        .route(
            "/api/notifications/mark-read",
            post(handlers::notifications::post_mark_read),
        )
        .route(
            "/api/notifications/mark-all-read",
            post(handlers::notifications::post_mark_all_read),
        )
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
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

/// Defence-in-depth headers applied to every response:
///   * **Content-Security-Policy** — blocks injection of external
///     `<script src=…>` and forces same-origin for fetch/img/form
///     submits. Currently allows `'unsafe-inline'` for script and
///     style because the legacy templates rely on ~11 inline
///     `onclick`/`onchange` handlers and many `style="…"` attributes.
///     Tightening to nonce-only would require refactoring those to
///     delegated listeners + classes — tracked as future work.
///     Even without nonce, blocking remote `<script>` defangs
///     stored-XSS that injects a `<script src=evil.example.com>`
///     tag (the most common payload).
///   * **X-Frame-Options DENY** — paranoia in addition to
///     `frame-ancestors 'none'` for ancient browsers.
///   * **X-Content-Type-Options nosniff** — stops MIME sniffing
///     turning a benign `.txt` upload into a script.
///   * **Referrer-Policy strict-origin** — leaks only the panel
///     hostname (not URL path) when the operator clicks an external
///     link from a hosting-detail page.
///   * **Permissions-Policy** — locks down browser sensors the
///     panel never needs (camera, mic, geolocation, …) so a
///     compromised iframe can't request them.
///   * **HSTS** — once we've served HTTPS, refuse plain HTTP for
///     2 years. `includeSubDomains` because every hosting under
///     the same parent zone should also be HTTPS-only.
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    // CSP. Order matters only for readability; semicolons are the
    // separator. NB: `frame-ancestors 'none'` is what actually
    // prevents click-jacking — XFO is the belt-and-braces.
    h.insert(
        "content-security-policy",
        axum::http::HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self' data:; \
             connect-src 'self'; \
             form-action 'self'; \
             base-uri 'self'; \
             object-src 'none'; \
             frame-ancestors 'none'; \
             frame-src 'none'",
        ),
    );
    h.insert(
        "x-frame-options",
        axum::http::HeaderValue::from_static("DENY"),
    );
    h.insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        "referrer-policy",
        axum::http::HeaderValue::from_static("strict-origin"),
    );
    h.insert(
        "permissions-policy",
        axum::http::HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()",
        ),
    );
    h.insert(
        "strict-transport-security",
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    resp
}
