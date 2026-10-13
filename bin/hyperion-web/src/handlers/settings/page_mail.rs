//! `GET /settings/mail` — how one node sends e-mail: its relay, a test
//! send through it, and a line on its local postfix.
//!
//! Every node has its own `[email]`. With workers enrolled a picker at the
//! top chooses which (`?node=<id>`; empty or `local` = the master) and every
//! card follows it. The page reads that node's `[email]` through
//! `AgentConfigView` — not `MtaDiagnostics`, which runs DNS lookups and port
//! probes and held the old page for seconds; the postfix line is a lazy
//! fragment ([`get_mail_health`]) and the full diagnosis lives on Service
//! health.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::handlers::mail_health;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_state::capabilities::Capability;
use hyperion_types::{EmailConfigView, NodeSummary};

/// One entry of the node picker.
pub struct NodeOption {
    /// `local` for the master, else the worker's id.
    pub id: String,
    pub label: String,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "settings_mail.html")]
struct PageTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    /// The node the page shows and saves to (`target_node`): `local` or a
    /// worker's id.
    node: String,
    /// That node in a sentence: "this server", "the master", a label.
    node_label: String,
    /// The local relay probe only looks at the master's own localhost.
    is_master: bool,
    picker: Vec<NodeOption>,
    email: EmailConfigView,
    /// Why the node's `[email]` could not be read. The form is then not
    /// rendered at all: one filled with defaults would overwrite the real
    /// values on the first Save.
    email_error: Option<String>,
    /// Pre-fill for the test: the node's first administrator address.
    test_to: String,
    /// The node's Mail delivery group on Service health.
    services_href: String,
}

/// The picker: the master first, then the workers as the Nodes page lists
/// them. `selected` is the node the page shows (`None` = the master).
pub fn picker(nodes: &[NodeSummary], selected: Option<&str>) -> Vec<NodeOption> {
    let mut out = vec![NodeOption {
        id: crate::dispatcher::LOCAL_NODE_SENTINEL.to_string(),
        label: "This server (master)".to_string(),
        selected: selected.is_none(),
    }];
    out.extend(nodes.iter().map(|n| NodeOption {
        id: n.node_id.clone(),
        label: node_label(n),
        selected: selected == Some(n.node_id.as_str()),
    }));
    out
}

/// A worker as the picker and the copy name it: its label (or id), with
/// its address when known.
pub fn node_label(n: &NodeSummary) -> String {
    let name = if n.label.trim().is_empty() {
        n.node_id.as_str()
    } else {
        n.label.as_str()
    };
    match n.public_ip.as_deref().map(str::trim) {
        Some(ip) if !ip.is_empty() => format!("{name} — {ip}"),
        _ => name.to_string(),
    }
}

pub async fn get_mail(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, nodes) = chrome::chrome(&state, &ctx, "mail", &q).await;
    let target = mail_health::node_target(&q.node);
    let node_label = match target.as_deref() {
        None if chrome.has_nodes => "the master".to_string(),
        None => "this server".to_string(),
        Some(id) => nodes
            .iter()
            .find(|n| n.node_id == id)
            .map(|n| {
                if n.label.trim().is_empty() {
                    n.node_id.clone()
                } else {
                    n.label.clone()
                }
            })
            .unwrap_or_else(|| id.to_string()),
    };
    let (email, email_error) = match super::node_email(&state, target.as_deref()).await {
        Ok(e) => (e, None),
        Err(e) => (EmailConfigView::default(), Some(e)),
    };
    let tpl = PageTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        node: target
            .clone()
            .unwrap_or_else(|| crate::dispatcher::LOCAL_NODE_SENTINEL.to_string()),
        node_label,
        is_master: target.is_none(),
        picker: picker(&nodes, target.as_deref()),
        test_to: mail_health::first_address(&email.default_to),
        services_href: mail_health::services_url(target.as_deref(), ""),
        email,
        email_error,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Template)]
#[template(path = "_settings_mail_health.html")]
struct HealthTpl {
    tone: &'static str,
    line: String,
    error: Option<String>,
}

/// `GET /settings/mail/health?node=<id>` — the Local mail server card's
/// one line, loaded when the card scrolls into view: the diagnosis behind
/// it probes DNS and outbound ports and takes seconds.
pub async fn get_mail_health(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<mail_health::NodeQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Err(AppError::Forbidden);
    }
    let target = mail_health::node_target(&q.node);
    let tpl = match mail_health::fetch(&state, target.as_deref()).await {
        Ok(d) => {
            let (tone, line) = mail_health::verdict(&d);
            HealthTpl {
                tone,
                line,
                error: None,
            }
        }
        Err(e) => HealthTpl {
            tone: "",
            line: String::new(),
            error: Some(e),
        },
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn node(id: &str, label: &str, ip: Option<&str>) -> NodeSummary {
        NodeSummary {
            node_id: id.into(),
            label: label.into(),
            master_url: None,
            agent_version: String::new(),
            public_ip: ip.map(str::to_string),
            enrolled_at: 0,
            last_seen_at: 0,
            is_drained: false,
            drain_reason: String::new(),
            tls_spki_pin: None,
            resp_pubkey: None,
            rpc_port: None,
            external_ip: None,
        }
    }

    fn render(is_master: bool, email: EmailConfigView, email_error: Option<String>) -> String {
        let nodes = vec![node("node_a", "web-2", None)];
        let selected = (!is_master).then_some("node_a");
        PageTpl {
            username: "kevin",
            user_initial: 'K',
            active: "settings",
            css_version: "1",
            htmx_version: "1",
            chrome: Chrome {
                section: "mail",
                title: "Mail",
                lead: "",
                can_edit: true,
                has_nodes: true,
                flash: None,
                flash_error: None,
            },
            csrf_token: "tok".into(),
            node: selected.unwrap_or("local").into(),
            node_label: if is_master {
                "the master".into()
            } else {
                "web-2".into()
            },
            is_master,
            picker: picker(&nodes, selected),
            test_to: crate::handlers::mail_health::first_address(&email.default_to),
            services_href: "/services#mail-delivery".into(),
            email,
            email_error,
        }
        .render()
        .expect("render")
    }

    #[test]
    fn the_page_never_offers_a_form_it_could_not_fill() {
        // A node that did not answer: no relay form (defaults would be saved
        // over its real values), no test, no local-relay probe.
        let html = render(
            false,
            EmailConfigView::default(),
            Some("no answer within 4 s".into()),
        );
        assert!(!html.contains("action=\"/settings/config\""));
        assert!(!html.contains("action=\"/settings/email-test\""));
        assert!(!html.contains("email-autodetect"));
        assert!(html.contains("no answer within 4 s"));
        // Every card is still there for links and save redirects to land on.
        for id in ["smtp-relay", "mail-test", "mail-health"] {
            assert!(html.contains(&format!("id=\"{id}\"")), "{id}");
        }

        // The master with its relay off: the form and the probe, no test.
        let off = EmailConfigView {
            smtp_host: "relay.example.cz".into(),
            default_to: "ops@x.cz, cto@x.cz".into(),
            ..Default::default()
        };
        let html = render(true, off.clone(), None);
        assert!(html.contains("action=\"/settings/config\""));
        assert!(html.contains("id=\"email-autodetect\""));
        assert!(html.contains("value=\"relay.example.cz\""));
        assert!(!html.contains("action=\"/settings/email-test\""));
        assert!(html.contains("name=\"target_node\" value=\"local\""));
        // The recipients belong to Alerts; this form must not post them.
        assert!(!html.contains("name=\"default_to\""));

        // A worker with its relay on: the test, aimed at that worker, and
        // no probe of the master's localhost.
        let on = EmailConfigView {
            enabled: true,
            ..off
        };
        let html = render(false, on, None);
        let test = html
            .split("<form")
            .find(|f| f.contains("/settings/email-test"))
            .expect("test form");
        assert!(test.contains("name=\"target_node\" value=\"node_a\""));
        assert!(test.contains("value=\"ops@x.cz\""));
        assert!(!html.contains("email-autodetect"));
    }

    #[test]
    fn the_picker_lists_the_master_first_and_marks_the_shown_node() {
        let nodes = vec![
            node("node_a", "web-2", Some("203.0.113.7")),
            node("node_b", "", None),
        ];
        let p = picker(&nodes, None);
        let ids: Vec<&str> = p.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["local", "node_a", "node_b"]);
        assert!(p[0].selected && !p[1].selected);
        assert_eq!(p[1].label, "web-2 — 203.0.113.7");
        // A node without a label is still nameable.
        assert_eq!(p[2].label, "node_b");

        let p = picker(&nodes, Some("node_b"));
        assert_eq!(
            p.iter()
                .filter(|o| o.selected)
                .map(|o| o.id.as_str())
                .collect::<Vec<_>>(),
            ["node_b"]
        );
    }
}
