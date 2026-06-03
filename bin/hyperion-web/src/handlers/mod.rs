pub mod audit;
pub mod dashboard;
pub mod enroll;
pub mod health;
pub mod hostings;
pub mod install;
pub mod login;
pub mod files;
pub mod profile;
pub mod profiles;
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
