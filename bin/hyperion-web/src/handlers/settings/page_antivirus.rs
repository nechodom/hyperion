//! `GET /settings/antivirus` — when each node's ClamAV pass runs.
//!
//! The schedule is the master's `[antivirus]` section, read straight from
//! `/etc/hyperion/agent.toml`; the settings sync copies it to every node, and
//! each node reads it when its tick asks whether a pass is due, so a save
//! needs no restart. What the passes found is on `/antivirus`.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_state::capabilities::Capability;
use hyperion_types::antivirus::AntivirusSettings;

/// The master's agent.toml — the file the settings sync copies `[antivirus]`
/// from.
const AGENT_TOML: &str = "/etc/hyperion/agent.toml";

/// `[antivirus]` as agent.toml holds it, defaults filled in for absent keys.
/// `None` when the file is not valid TOML.
pub(crate) fn parse_antivirus_section(raw: &str) -> Option<AntivirusSettings> {
    let doc: toml::Value = raw.parse().ok()?;
    let table = doc.get("antivirus");
    Some(AntivirusSettings::from_lookup(
        |k| table?.get(k)?.as_bool(),
        |k| table?.get(k)?.as_integer(),
    ))
}

#[derive(Template)]
#[template(path = "settings_antivirus.html")]
struct PageTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    /// `None` when agent.toml could not be read or parsed; `error` says which.
    settings: Option<AntivirusSettings>,
    error: String,
    hours: std::ops::Range<u32>,
}

pub async fn get_antivirus(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, _nodes) = chrome::chrome(&state, &ctx, "antivirus", &q).await;
    let (settings, error) = match tokio::fs::read_to_string(AGENT_TOML).await {
        Ok(raw) => match parse_antivirus_section(&raw) {
            Some(s) => (Some(s), String::new()),
            None => (None, "it is not valid TOML".to_string()),
        },
        Err(e) => (None, format!("it could not be read: {e}")),
    };
    let tpl = PageTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        settings,
        error,
        hours: 0..24,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(settings: Option<AntivirusSettings>, can_edit: bool) -> String {
        PageTpl {
            username: "kevin",
            user_initial: 'K',
            active: "settings",
            css_version: "x",
            htmx_version: "x",
            chrome: Chrome {
                section: "antivirus",
                title: "Antivirus",
                lead: "",
                can_edit,
                has_nodes: true,
                flash: None,
                flash_error: None,
            },
            csrf_token: "tok".into(),
            settings,
            error: "it could not be read: nope".into(),
            hours: 0..24,
        }
        .render()
        .expect("render")
    }

    #[test]
    fn an_absent_section_is_the_defaults_and_a_broken_file_is_none() {
        assert_eq!(
            parse_antivirus_section("[agent]\nx = 1\n"),
            Some(AntivirusSettings::default())
        );
        let s = parse_antivirus_section(
            "[antivirus]\nenabled = false\nevery_days = 1\nwindow_start_hour = 22\nwindow_end_hour = 4\nmin_free_memory_mb = 4096\n",
        )
        .expect("valid");
        assert!(!s.enabled);
        assert_eq!(
            (
                s.every_days,
                s.window_start_hour,
                s.window_end_hour,
                s.min_free_memory_mb
            ),
            (1, 22, 4, 4096)
        );
        assert_eq!(parse_antivirus_section("[antivirus"), None);
    }

    #[test]
    fn the_form_posts_every_field_of_the_section() {
        let html = page(
            Some(AntivirusSettings {
                window_start_hour: 22,
                ..Default::default()
            }),
            true,
        );
        for name in [
            "enabled",
            "every_days",
            "window_start_hour",
            "window_end_hour",
            "min_free_memory_mb",
        ] {
            assert!(html.contains(&format!("name=\"{name}\"")), "{name} missing");
        }
        assert!(html.contains(r#"name="section" value="antivirus""#));
        assert!(html.contains(r#"name="_checkboxes" value="enabled""#));
        assert!(html.contains(r#"name="_return_tab" value="antivirus-schedule""#));
        assert!(html.contains(r#"<option value="22" selected>22:00</option>"#));
        assert!(html.contains(r#"<option value="6" selected>06:00</option>"#));
        assert!(html.contains("All nodes"));
        assert!(html.contains(r#"href="/antivirus""#));
    }

    #[test]
    fn an_unreadable_file_shows_why_and_no_form() {
        let html = page(None, true);
        assert!(html.contains(r#"id="antivirus-schedule""#));
        assert!(html.contains("it could not be read: nope"));
        assert!(!html.contains(r#"value="antivirus""#));
    }

    #[test]
    fn the_form_locks_for_non_owners() {
        let html = page(Some(AntivirusSettings::default()), false);
        assert!(html.contains(r#"<fieldset class="group" disabled>"#));
    }
}
