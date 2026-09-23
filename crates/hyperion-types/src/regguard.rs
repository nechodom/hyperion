//! Registration spam guard — per-hosting view for the WordPress card.

use serde::{Deserialize, Serialize};

/// State of the registration spam guard for one hosting, read from the owning
/// node. `enabled` is the operator's intent (stored in `hosting_kv`);
/// `installed` is what is actually on disk in `wp-content/mu-plugins/`. They
/// differ only briefly (a just-toggled site whose node hasn't written yet) or
/// when the site is not WordPress.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegGuardView {
    /// The operator turned the guard on for this hosting.
    #[serde(default)]
    pub enabled: bool,
    /// The must-use plugin is present and current on disk.
    #[serde(default)]
    pub installed: bool,
    /// The site is WordPress (has `wp-content`); the guard is a no-op otherwise
    /// and the card says so instead of offering a dead toggle.
    #[serde(default)]
    pub is_wordpress: bool,
}
