//! `GET /settings/alerts` — who hears about problems, where, in which
//! language and in what words: the Slack channel, the administrator
//! addresses of every node, the alert language and the wording around
//! every alert.
//!
//! The recipients are per node (`[email] default_to` lives in each node's
//! own agent.toml), so their card is a lazy fragment
//! ([`get_alert_recipients`]) that asks every node at once; the rest of the
//! page reads the master only.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::handlers::hostings::csrf_token_for;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::Request;
use hyperion_state::capabilities::Capability;
use hyperion_types::{AgentConfigView, EmailConfigView};

#[derive(Template)]
#[template(path = "settings_alerts.html")]
struct PageTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    /// `/settings/slack-test` checks a token minted for its own path.
    csrf_slack_test: String,
    config: AgentConfigView,
    config_error: Option<String>,
    /// `[letters] operator_lang`: `en` / `cs`.
    operator_lang: String,
    /// agent.toml could not be read, so `operator_lang` is the default
    /// (`en`), not what is set — the Language form is switched off rather
    /// than offering to save a guess.
    lang_error: Option<String>,
}

pub async fn get_alerts(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, _nodes) = chrome::chrome(&state, &ctx, "alerts", &q).await;
    let (config_res, toml_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        tokio::fs::read_to_string("/etc/hyperion/agent.toml"),
    );
    let (config, config_error) = super::config_or_default(config_res);
    let (letters, lang_error) = match toml_res {
        Ok(raw) => (hyperion_core::service::letter_catalog_from_toml(&raw), None),
        Err(e) => (Default::default(), Some(e.to_string())),
    };
    let tpl = PageTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        csrf_slack_test: csrf_token_for(&state, &ctx, "/settings/slack-test"),
        config,
        config_error,
        operator_lang: letters.operator_lang.as_str().to_string(),
        lang_error,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// One node's line in the Recipients card.
pub struct RecipientRow {
    /// `target_node` for its form: `local` or the worker's id.
    pub node: String,
    pub label: String,
    /// `None` = the node did not answer, and this is why. Such a row gets
    /// no form: an empty field saved over the real list would erase it.
    pub error: Option<String>,
    pub default_to: String,
    /// Addresses the mailer will actually use (the ones with an `@`).
    pub count: usize,
    /// With the relay off the node sends no e-mail at all, so its list is
    /// kept but unused.
    pub relay_on: bool,
    /// Unique per row, for `<label for>`.
    pub field_id: String,
}

impl RecipientRow {
    pub fn known(&self) -> bool {
        self.error.is_none()
    }

    /// The node's Mail page, where its relay is turned on.
    pub fn mail_href(&self) -> String {
        if self.node == crate::dispatcher::LOCAL_NODE_SENTINEL {
            "/settings/mail#smtp-relay".to_string()
        } else {
            format!(
                "/settings/mail?node={}#smtp-relay",
                url::form_urlencoded::byte_serialize(self.node.as_bytes()).collect::<String>()
            )
        }
    }
}

/// The rows, master first, in the order of `targets` — `(target_node,
/// label)` pairs — with each node's answer beside it.
pub fn recipient_rows(
    targets: &[(String, String)],
    answers: Vec<Result<EmailConfigView, String>>,
) -> Vec<RecipientRow> {
    targets
        .iter()
        .zip(answers)
        .enumerate()
        .map(|(i, ((node, label), answer))| {
            let (error, email) = match answer {
                Ok(e) => (None, e),
                Err(e) => (Some(e), EmailConfigView::default()),
            };
            RecipientRow {
                node: node.clone(),
                label: label.clone(),
                count: super::overview::address_count(&email.default_to),
                relay_on: email.enabled,
                default_to: email.default_to,
                error,
                field_id: format!("default_to_{i}"),
            }
        })
        .collect()
}

/// A `default_to` list rewritten with one separator: the field takes
/// commas, semicolons, spaces and new lines (a column pasted out of a
/// spreadsheet), and the file should read as the list it is. Nothing is
/// dropped — a token without an `@` comes back on the page as typed, where
/// the address count beside it shows it is not counted.
pub fn normalize_address_list(raw: &str) -> String {
    raw.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|a| !a.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Template)]
#[template(path = "_settings_alert_recipients.html")]
struct RecipientsTpl {
    rows: Vec<RecipientRow>,
    has_nodes: bool,
    /// Only an Owner writes agent.toml. The page wraps this card in the
    /// read-only fieldset too; rendering no form here covers the fragment
    /// fetched on its own.
    can_edit: bool,
    csrf_token: String,
}

/// `GET /settings/alerts/recipients` — every node's administrator
/// addresses, asked of all nodes at once (4 s each). A node that does not
/// answer reads as unknown, never as "no addresses".
pub async fn get_alert_recipients(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Err(AppError::Forbidden);
    }
    let nodes = chrome::enrolled_nodes(&state).await;
    let mut targets: Vec<(String, String)> = vec![(
        crate::dispatcher::LOCAL_NODE_SENTINEL.to_string(),
        if nodes.is_empty() {
            "This server".to_string()
        } else {
            "This server (master)".to_string()
        },
    )];
    targets.extend(
        nodes
            .iter()
            .map(|n| (n.node_id.clone(), super::page_mail::node_label(n))),
    );

    let mut set = tokio::task::JoinSet::new();
    for (i, (node, _)) in targets.iter().enumerate() {
        let state = state.clone();
        let target = (i > 0).then(|| node.clone());
        set.spawn(async move {
            let answer = super::node_email(&state, target.as_deref()).await;
            (i, answer)
        });
    }
    let mut answers: Vec<Result<EmailConfigView, String>> =
        vec![Err("no answer".to_string()); targets.len()];
    while let Some(joined) = set.join_next().await {
        if let Ok((i, answer)) = joined {
            answers[i] = answer;
        }
    }
    let tpl = RecipientsTpl {
        rows: recipient_rows(&targets, answers),
        has_nodes: !nodes.is_empty(),
        can_edit: ctx.is_super_admin(),
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_keep_the_order_and_never_read_silence_as_no_addresses() {
        let targets = vec![
            ("local".to_string(), "This server (master)".to_string()),
            ("node_a".to_string(), "web-2".to_string()),
            ("node_b".to_string(), "web-3".to_string()),
        ];
        let rows = recipient_rows(
            &targets,
            vec![
                Ok(EmailConfigView {
                    enabled: true,
                    default_to: "ops@x.cz, cto@x.cz".into(),
                    ..Default::default()
                }),
                Err("no answer within 4 s".into()),
                Ok(EmailConfigView {
                    default_to: "ops@x.cz; typo".into(),
                    ..Default::default()
                }),
            ],
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].node, "local");
        assert!(rows[0].known() && rows[0].relay_on);
        assert_eq!(rows[0].count, 2);
        assert!(!rows[1].known());
        assert_eq!(rows[1].default_to, "");
        assert_eq!(rows[2].count, 1);
        assert!(!rows[2].relay_on);
        let ids: std::collections::BTreeSet<&str> =
            rows.iter().map(|r| r.field_id.as_str()).collect();
        assert_eq!(ids.len(), 3, "label targets must be unique");
        assert_eq!(rows[0].mail_href(), "/settings/mail#smtp-relay");
        assert_eq!(rows[1].mail_href(), "/settings/mail?node=node_a#smtp-relay");
    }

    fn render_page(connected: bool, lang: &str) -> String {
        let mut config = AgentConfigView::default();
        config.slack.default_webhook_set = connected;
        PageTpl {
            username: "kevin",
            user_initial: 'K',
            active: "settings",
            css_version: "1",
            htmx_version: "1",
            chrome: Chrome {
                section: "alerts",
                title: "Alerts",
                lead: "",
                can_edit: true,
                has_nodes: false,
                flash: None,
                flash_error: None,
            },
            csrf_token: "session-tok".into(),
            csrf_slack_test: "slack-tok".into(),
            config,
            config_error: None,
            operator_lang: lang.into(),
            lang_error: None,
        }
        .render()
        .expect("render")
    }

    #[test]
    fn slack_shows_test_and_disconnect_when_connected_and_a_url_field_when_not() {
        let html = render_page(true, "cs");
        let forms: Vec<&str> = html.split("<form").skip(1).collect();
        let test = forms
            .iter()
            .find(|f| f.contains("/settings/slack-test"))
            .expect("test form");
        assert!(test.contains("value=\"slack-tok\""), "path-scoped token");
        let disconnect = forms
            .iter()
            .find(|f| f.contains("name=\"_disconnect\""))
            .expect("disconnect form");
        assert!(disconnect.contains("data-confirm-title"));
        assert!(!html.contains("name=\"default_webhook\" type=\"url\""));
        assert!(html.contains("<option value=\"cs\" selected>"));

        let html = render_page(false, "en");
        assert!(html.contains("id=\"default_webhook\""));
        assert!(!html.contains("/settings/slack-test"));
        assert!(html.contains("<option value=\"en\" selected>"));
        for id in [
            "slack",
            "alert-recipients",
            "alert-language",
            "alert-templates",
        ] {
            assert!(html.contains(&format!("id=\"{id}\"")), "{id}");
        }
    }

    #[test]
    fn the_fragment_has_a_form_per_answering_node_and_none_for_non_owners() {
        let targets = vec![
            ("local".to_string(), "This server (master)".to_string()),
            ("node_a".to_string(), "web-2".to_string()),
        ];
        let answers = || {
            vec![
                Ok(EmailConfigView {
                    enabled: true,
                    default_to: "ops@x.cz".into(),
                    ..Default::default()
                }),
                Err("no answer within 4 s".to_string()),
            ]
        };
        let render = |can_edit| {
            RecipientsTpl {
                rows: recipient_rows(&targets, answers()),
                has_nodes: true,
                can_edit,
                csrf_token: "tok".into(),
            }
            .render()
            .expect("render")
        };
        let owner = render(true);
        // The silent node gets no form: saving an empty field would erase it.
        assert_eq!(owner.matches("action=\"/settings/config\"").count(), 1);
        assert!(owner.contains("name=\"_return_tab\" value=\"alert-recipients\""));
        assert!(owner.contains("name=\"target_node\" value=\"local\""));
        assert!(owner.contains("did not answer"));
        let viewer = render(false);
        assert_eq!(viewer.matches("<form").count(), 0);
        assert!(viewer.contains("ops@x.cz"));
    }

    #[test]
    fn address_lists_are_stored_with_one_separator_and_nothing_dropped() {
        assert_eq!(normalize_address_list(""), "");
        assert_eq!(
            normalize_address_list("a@x.cz;b@y.cz\r\nc@z.cz ,, d@w.cz"),
            "a@x.cz, b@y.cz, c@z.cz, d@w.cz"
        );
        assert_eq!(normalize_address_list(" typo, a@x.cz "), "typo, a@x.cz");
        // Counted the way the mailer counts, before and after.
        let raw = "a@x.cz\nb@y.cz";
        assert_eq!(
            super::super::overview::address_count(raw),
            super::super::overview::address_count(&normalize_address_list(raw))
        );
    }
}
