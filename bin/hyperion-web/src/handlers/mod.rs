pub mod audit;
pub mod dashboard;
pub mod hostings;
pub mod install;
pub mod login;
pub mod statics;

/// Uppercase first ASCII letter of `username`, or `?` if empty / non-ASCII.
/// Used as the avatar glyph in the sidebar.
pub fn user_initial(username: &str) -> char {
    username
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('?')
}
