pub mod audit;
pub mod dashboard;
pub mod enroll;
pub mod health;
pub mod hostings;
pub mod install;
pub mod login;
pub mod files;
pub mod migration;
pub mod profile;
pub mod profiles;
pub mod search;
pub mod services_health;
pub mod settings;
pub mod statics;
pub mod stats;
pub mod users;

/// Uppercase first ASCII letter of `username`, or `?` if empty / non-ASCII.
/// Used as the avatar glyph in the sidebar.
pub fn user_initial(username: &str) -> char {
    username
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('?')
}

/// Short content hash of the bundled CSS. Goes into `?v=…` on the
/// `<link>` tag so a redeploy invalidates the browser cache cleanly.
pub fn css_version() -> &'static str {
    statics::css_version()
}

/// Same for the htmx bundle.
pub fn htmx_version() -> &'static str {
    statics::htmx_version()
}

/// Session-wide CSRF token. ONE token valid for any POST in the same
/// session — way nicer for templates than minting a separate scoped
/// token for every form. Verified by the middleware via the wildcard
/// `SESSION_WIDE_FORM_ID` path.
///
/// Templates inject this as `<input type="hidden" name="_csrf" value="{{ csrf_token }}">`
/// in every form. Returns empty string on unauthenticated requests
/// (which never reach the CSRF guard anyway — they're redirected to
/// /login before the POST middleware runs).
pub fn session_csrf_token(
    state: &crate::state::SharedState,
    ctx: &crate::auth::AuthCtx,
) -> String {
    let sid = ctx
        .session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default();
    hyperion_auth::csrf::mint(
        state.csrf_key.as_ref(),
        &sid,
        hyperion_auth::csrf::SESSION_WIDE_FORM_ID,
        hyperion_types::now_secs(),
    )
}
