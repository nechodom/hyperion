//! Contact form guard — per-hosting view for the WordPress tab.

use serde::{Deserialize, Serialize};

/// One refused form submission, as the site's module logged it.
///
/// Written by the tenant's PHP: every field is text somebody else chose. The
/// node keeps only lines whose time and rule have the shape the module
/// writes, and clips the rest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormGuardHit {
    /// `YYYY-MM-DDTHH:MM:SS`, UTC.
    #[serde(default)]
    pub at: String,
    /// `empty`, `short`, `duplicate`, `rate` or `link_in_name`.
    #[serde(default)]
    pub rule: String,
    /// The form's name in Elementor.
    #[serde(default)]
    pub form: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub ip: String,
}

/// State of the contact form guard for one hosting, read from the owning node.
/// `enabled` is the operator's intent (`hosting_kv`); `installed` is what is
/// on disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormGuardView {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub installed: bool,
    #[serde(default)]
    pub is_wordpress: bool,
    /// The site has Elementor Pro, the only form builder the guard hooks into.
    /// Without it the module loads and does nothing.
    #[serde(default)]
    pub has_elementor_pro: bool,
    /// Refusals in the last seven days. `None` when the log could not be
    /// read — which is not the same as none.
    #[serde(default)]
    pub refused_7d: Option<u32>,
    /// The most recent refusals, newest first.
    #[serde(default)]
    pub recent: Vec<FormGuardHit>,
}
