//! `GET /settings/logs` — how long each kind of log is kept.
//!
//! The windows are the master's `[log_retention]` section, read straight from
//! `/etc/hyperion/agent.toml`; the settings sync copies it to every node, and
//! each node's hourly retention pass reads it, so a save needs no restart.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_state::capabilities::Capability;
use hyperion_types::log_retention::{LogClass, LogRetention, CLASSES};

/// The master's agent.toml — the file the settings sync copies
/// `[log_retention]` from.
const AGENT_TOML: &str = "/etc/hyperion/agent.toml";

/// `[log_retention]` as agent.toml holds it (the old `[cluster]
/// audit_retention_days` as the audit fallback, as the agent reads it).
/// `None` when the file is not valid TOML.
pub(crate) fn parse_log_retention_section(raw: &str) -> Option<LogRetention> {
    let doc: toml::Value = raw.parse().ok()?;
    let table = doc.get("log_retention");
    let legacy = doc
        .get("cluster")
        .and_then(|c| c.get("audit_retention_days"))
        .and_then(|v| v.as_integer());
    Some(LogRetention::from_lookup(
        |k| table?.get(k)?.as_integer(),
        legacy,
    ))
}

/// One row of the card.
pub(crate) struct Row {
    pub class: &'static LogClass,
    pub days: u32,
}

#[derive(Template)]
#[template(path = "settings_logs.html")]
struct PageTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    /// `None` when agent.toml could not be read or parsed; `error` says which.
    rows: Option<Vec<Row>>,
    error: String,
    min_days: u32,
    max_days: u32,
}

fn rows(r: &LogRetention) -> Vec<Row> {
    CLASSES
        .iter()
        .map(|class| Row {
            class,
            days: r
                .get(class.key)
                .unwrap_or(hyperion_types::log_retention::DEFAULT_DAYS),
        })
        .collect()
}

pub async fn get_logs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, _nodes) = chrome::chrome(&state, &ctx, "logs", &q).await;
    let (rows, error) = match tokio::fs::read_to_string(AGENT_TOML).await {
        Ok(raw) => match parse_log_retention_section(&raw) {
            Some(r) => (Some(self::rows(&r)), String::new()),
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
        rows,
        error,
        min_days: *hyperion_types::log_retention::DAYS_RANGE.start(),
        max_days: *hyperion_types::log_retention::DAYS_RANGE.end(),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(r: Option<LogRetention>, can_edit: bool) -> String {
        PageTpl {
            username: "kevin",
            user_initial: 'K',
            active: "settings",
            css_version: "x",
            htmx_version: "x",
            chrome: Chrome {
                section: "logs",
                title: "Log retention",
                lead: "",
                can_edit,
                has_nodes: true,
                flash: None,
                flash_error: None,
            },
            csrf_token: "tok".into(),
            rows: r.as_ref().map(rows),
            error: "it could not be read: nope".into(),
            min_days: 1,
            max_days: 3650,
        }
        .render()
        .expect("render")
    }

    #[test]
    fn an_absent_section_is_thirty_days_and_the_old_audit_key_counts_only_when_chosen() {
        let r = parse_log_retention_section("[agent]\nx = 1\n").expect("valid");
        assert_eq!(r, LogRetention::default());
        let r = parse_log_retention_section("[cluster]\naudit_retention_days = 0\n").unwrap();
        assert_eq!(r.audit_days, 30, "the old 'forever' default moves to 30");
        let r = parse_log_retention_section("[cluster]\naudit_retention_days = 365\n").unwrap();
        assert_eq!(r.audit_days, 365);
        let r = parse_log_retention_section(
            "[cluster]\naudit_retention_days = 365\n[log_retention]\naudit_days = 14\nweb_days = 7\n",
        )
        .unwrap();
        assert_eq!((r.audit_days, r.web_days, r.email_days), (14, 7, 30));
        assert_eq!(parse_log_retention_section("[log_retention"), None);
    }

    #[test]
    fn the_form_posts_every_class_and_says_why() {
        let html = page(
            Some(LogRetention {
                web_days: 14,
                ..Default::default()
            }),
            true,
        );
        for c in CLASSES {
            assert!(
                html.contains(&format!("name=\"{}\"", c.key)),
                "{} missing",
                c.key
            );
        }
        assert!(html.contains(r#"name="section" value="log_retention""#));
        assert!(html.contains(r#"name="_return_tab" value="log-retention""#));
        assert!(html.contains(
            r#"id="lr_web_days" name="web_days" type="number" min="1" max="3650" value="14""#
        ));
        assert!(html.contains("GDPR"));
        // The care report's floor is said out loud.
        assert!(html.contains("can stay longer than set here"));
        assert!(html.contains("All nodes"));
    }

    #[test]
    fn an_unreadable_file_shows_why_and_no_form() {
        let html = page(None, true);
        assert!(html.contains(r#"id="log-retention""#));
        assert!(html.contains("it could not be read: nope"));
        assert!(!html.contains(r#"value="log_retention""#));
    }

    #[test]
    fn the_form_locks_for_non_owners() {
        let html = page(Some(LogRetention::default()), false);
        assert!(html.contains(r#"<fieldset class="group" disabled>"#));
    }
}
