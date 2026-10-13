//! `/install/node-settings` — one node's own settings, edited from the master.
//!
//! Settings is the master's page: most of what it saves lives in the master's
//! agent.toml, and a few sections are copied to every node. But several
//! settings are ACTED ON by each node from its own file — its brute-force
//! scanner, its off-site FTP push, its automatic updates, its Let's Encrypt
//! account, how long it keeps its own backups — and before this page the only
//! way to change them on a worker was SSH.
//!
//! Reading uses `AgentConfigView` (sanitised, read fresh off disk for the
//! backup sections) plus `NodeConfigRead` (the whole file, masked by the node
//! itself). Saving sends `NodeConfigSet`, which writes the section and has the
//! node restart its own agent — hyperion-web can only restart the master's.

use crate::auth::AuthCtx;
use crate::dispatcher::DispatchError;
use crate::error::AppError;
use crate::handlers::settings::{
    parse_fail2ban_section, synthesize_unchecked_checkboxes, Fail2banView,
};
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::AgentConfigView;
use serde::Deserialize;
use std::collections::BTreeMap;

/// The agent.toml sections this page may write, with the card each one
/// returns to. Anything else is refused: `[cluster]` and `[notifications]`
/// are the master's to hold, and `[email]` has its own page (Settings → Mail,
/// which also reconfigures postfix).
const SECTIONS: &[(&str, &str, &str)] = &[
    ("update", "updates", "Automatic updates"),
    ("fail2ban", "bruteforce", "Brute-force thresholds"),
    ("backup_remote", "offsite-ftp", "FTP / SFTP target"),
    ("acme", "acme", "Let's Encrypt contact"),
    ("protection", "protection-mode", "What is kept"),
    ("backup", "local-copies", "Local copies"),
    ("backup_retention", "backup-retention", "Archive retention"),
    ("snapshots", "snapshot-retention", "Snapshot retention"),
];

fn section_meta(section: &str) -> Option<(&'static str, &'static str)> {
    SECTIONS
        .iter()
        .find(|(s, _, _)| *s == section)
        .map(|(_, anchor, label)| (*anchor, *label))
}

/// `""` / `"local"` is the master itself.
fn is_local(node_id: &str) -> bool {
    let t = node_id.trim();
    t.is_empty() || t == crate::dispatcher::LOCAL_NODE_SENTINEL
}

/// Node ids are written into URLs and passed to the dispatcher. Same rule as
/// the Nodes page's own forms.
fn valid_node_id(node_id: &str) -> bool {
    !node_id.is_empty()
        && node_id.len() <= 128
        && node_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b' ' => "+".to_string(),
            b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            b if b.is_ascii_alphanumeric() => (b as char).to_string(),
            b => format!("%{:02X}", b),
        })
        .collect()
}

/// The values on this page that `AgentConfigView` doesn't carry, read out of
/// the node's own (masked) agent.toml.
#[derive(Debug, Default, PartialEq)]
struct RawExtras {
    acme_contact: Option<String>,
}

fn parse_raw_extras(raw: &str) -> RawExtras {
    let doc: Option<toml::Value> = raw.parse().ok();
    RawExtras {
        acme_contact: doc
            .as_ref()
            .and_then(|d| d.get("acme"))
            .and_then(|a| a.get("contact_email"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
    }
}

#[derive(Template)]
#[template(path = "node_settings.html")]
struct NodeSettingsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    /// `"local"` for the master, else the enrolled node id.
    node_id: String,
    label: String,
    is_master: bool,
    /// Whether any worker is enrolled — the "Settings saves this to every
    /// node" notes only make sense then.
    has_workers: bool,
    /// `None` = the node could not be asked; the page says why and shows no
    /// forms (a form pre-filled with defaults would overwrite real values).
    config: Option<AgentConfigView>,
    config_error: String,
    /// The node's agent.toml, masked node-side. `None` when the node's agent
    /// predates `NodeConfigRead`.
    raw_toml: Option<String>,
    raw_error: String,
    fail2ban: Option<Fail2banView>,
    acme_contact: String,
    /// A worker whose synced sections the master's settings sync manages:
    /// every card is shown read-only, because the next sync pass would undo
    /// an edit made here. False for the master and for an agent too old to
    /// take the sync (its own file is still the only way to set it).
    managed: bool,
    /// What the last sync pass said about this node; empty before the first.
    sync_verdict: String,
    sync_detail: String,
    sync_ok: bool,
}

#[derive(Deserialize)]
pub struct NodeQuery {
    #[serde(default)]
    node_id: String,
}

/// GET /install/node-settings?node_id=<id>
pub async fn get_node_settings(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<NodeQuery>,
) -> Result<Response, AppError> {
    // Same gate as the Nodes page this hangs off.
    if !ctx.is_super_admin() || !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/?flash_error=owner+role+required").into_response());
    }
    let node_id = if is_local(&q.node_id) {
        crate::dispatcher::LOCAL_NODE_SENTINEL.to_string()
    } else {
        q.node_id.trim().to_string()
    };
    if !valid_node_id(&node_id) {
        return Ok(Redirect::to("/install?flash_error=invalid+node+id").into_response());
    }
    let is_master = is_local(&node_id);
    let nodes: Vec<hyperion_types::NodeSummary> = match crate::dispatcher::cached_nodes(&state)
        .await
        .map(RpcResponse::NodesList)
    {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(),
    };
    let summary = nodes.iter().find(|n| n.node_id == node_id);
    if !is_master && summary.is_none() {
        return Ok(Redirect::to(&format!(
            "/install?flash_error={}",
            urlencode(&format!("node {node_id} is not enrolled"))
        ))
        .into_response());
    }
    let target = (!is_master).then_some(node_id.as_str());
    let (view_res, raw_res) = tokio::join!(
        crate::dispatcher::dispatch_to_node(&state, target, Request::AgentConfigView),
        crate::dispatcher::dispatch_to_node(&state, target, Request::NodeConfigRead),
    );
    let (config, config_error) = match view_res {
        Ok(RpcResponse::AgentConfigView(c)) => (Some(c), String::new()),
        Ok(RpcResponse::Error(e)) => (None, e.to_string()),
        Ok(_) => (
            None,
            "the node answered with something unexpected".to_string(),
        ),
        Err(e) => (None, e.to_string()),
    };
    let (raw_toml, raw_error) = match raw_res {
        Ok(RpcResponse::NodeConfigRead(s)) => (Some(s), String::new()),
        Ok(RpcResponse::Error(e)) => (None, e.to_string()),
        // An agent from before NodeConfigRead can't decode it and answers 400.
        Err(DispatchError::Remote(_)) => (
            None,
            "this node runs an older agent that cannot send its configuration — update it \
             from the Nodes page"
                .to_string(),
        ),
        Ok(_) => (
            None,
            "the node answered with something unexpected".to_string(),
        ),
        Err(e) => (None, e.to_string()),
    };
    let fail2ban = raw_toml.as_deref().and_then(parse_fail2ban_section);
    let extras = raw_toml
        .as_deref()
        .map(parse_raw_extras)
        .unwrap_or_default();
    let acme_contact = extras
        .acme_contact
        .or_else(|| config.as_ref().map(|c| c.acme.contact_email.clone()))
        .unwrap_or_default();
    let label = match summary {
        Some(n) if !n.label.trim().is_empty() => n.label.clone(),
        Some(n) => n.node_id.clone(),
        None => config
            .as_ref()
            .map(|c| c.hostname.clone())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "this server".to_string()),
    };
    let sync = if is_master {
        None
    } else {
        state.cluster_sync.status_for(&node_id).await
    };
    let tpl = NodeSettingsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "install",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(&state, &ctx),
        node_id,
        label,
        is_master,
        has_workers: !nodes.is_empty(),
        config,
        config_error,
        raw_toml,
        raw_error,
        fail2ban,
        acme_contact,
        managed: !is_master && sync.as_ref().map_or(true, |s| s.managed()),
        sync_verdict: sync
            .as_ref()
            .map(|s| s.verdict().to_string())
            .unwrap_or_default(),
        sync_detail: sync.as_ref().map(|s| s.detail.clone()).unwrap_or_default(),
        sync_ok: sync.as_ref().is_some_and(|s| s.is_ok()),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct NodeSettingsForm {
    #[serde(default)]
    node_id: String,
    section: String,
    #[serde(flatten)]
    fields: BTreeMap<String, String>,
}

/// Turn a submitted form into the fields to write: routing and UI keys out,
/// unticked declared checkboxes in as `false`, and a blank password dropped
/// so "leave blank to keep" keeps it.
fn fields_to_write(
    section: &str,
    mut fields: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    for k in ["_csrf", "node_id", "section"] {
        fields.remove(k);
    }
    let declared = fields.remove("_checkboxes").unwrap_or_default();
    if section == "backup_remote" && fields.get("password").is_some_and(|v| v.trim().is_empty()) {
        fields.remove("password");
    }
    synthesize_unchecked_checkboxes(&mut fields, &declared);
    fields
}

/// POST /install/node-settings — write one section on one node.
pub async fn post_node_settings(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeSettingsForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/install?flash_error=owner+role+required").into_response());
    }
    let node_id = if is_local(&form.node_id) {
        crate::dispatcher::LOCAL_NODE_SENTINEL.to_string()
    } else {
        form.node_id.trim().to_string()
    };
    if !valid_node_id(&node_id) {
        return Ok(Redirect::to("/install?flash_error=invalid+node+id").into_response());
    }
    let page = format!("/install/node-settings?node_id={}", urlencode(&node_id));
    let Some((anchor, label)) = section_meta(&form.section) else {
        return Ok(Redirect::to(&format!(
            "{page}&flash_error={}",
            urlencode("that section cannot be edited per node")
        ))
        .into_response());
    };
    // The master's settings sync owns these sections on a worker that can
    // take it; a value written here would be replaced on the next pass.
    if !is_local(&node_id)
        && state
            .cluster_sync
            .status_for(&node_id)
            .await
            .map_or(true, |s| s.managed())
    {
        return Ok(Redirect::to(&format!(
            "{page}&flash_error={}#{anchor}",
            urlencode(&format!(
                "{label} is set for every node on Settings, and this node follows the master — \
                 change it there"
            ))
        ))
        .into_response());
    }
    let section = form.section.clone();
    let fields = fields_to_write(&section, form.fields);
    let target = (!is_local(&node_id)).then_some(node_id.as_str());
    if target.is_none() {
        // The master's file IS the cluster's value.
        state.cluster_sync.kick();
    }
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::NodeConfigSet {
            section: section.clone(),
            fields: fields.clone().into(),
        },
    )
    .await;
    let dest = match resp {
        Ok(RpcResponse::NodeConfigSet) => format!(
            "{page}&flash={}#{anchor}",
            urlencode(&format!(
                "{label} saved on this node — its agent is restarting (~5s)"
            ))
        ),
        Ok(RpcResponse::Error(e)) => {
            format!("{page}&flash_error={}#{anchor}", urlencode(&e.to_string()))
        }
        // An agent from before NodeConfigSet can't decode it (400). It does
        // know AgentConfigUpdate, which writes the same file with the same
        // validation — it just can't be told to restart, so say the value
        // waits for the next restart instead of claiming it is live.
        Err(DispatchError::Remote(_)) if target.is_some() => {
            match crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::AgentConfigUpdate {
                    section,
                    fields: fields.into(),
                },
            )
            .await
            {
                Ok(RpcResponse::AgentConfigUpdate) => format!(
                    "{page}&flash={}#{anchor}",
                    urlencode(&format!(
                        "{label} written to this node's agent.toml. It runs an older agent that \
                         cannot restart itself on request, so the value takes effect when that \
                         agent next restarts — updating the node does that"
                    ))
                ),
                Ok(RpcResponse::Error(e)) => {
                    format!("{page}&flash_error={}#{anchor}", urlencode(&e.to_string()))
                }
                Ok(_) => format!(
                    "{page}&flash_error={}#{anchor}",
                    urlencode("the node answered with something unexpected")
                ),
                Err(e) => format!("{page}&flash_error={}#{anchor}", urlencode(&e.to_string())),
            }
        }
        Ok(_) => format!(
            "{page}&flash_error={}#{anchor}",
            urlencode("the node answered with something unexpected")
        ),
        Err(e) => format!("{page}&flash_error={}#{anchor}", urlencode(&e.to_string())),
    };
    Ok(Redirect::to(&dest).into_response())
}

/// POST /install/node-settings/probe — connection check of the node's SAVED
/// off-site FTP target, run ON that node (it is the one that pushes). HTMX
/// fragment, same shape as Settings' probe.
pub async fn post_node_backup_probe(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(q): Form<NodeQuery>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(
            Html("<span class=\"pill err\">owner role required</span>".to_string()).into_response(),
        );
    }
    if !is_local(&q.node_id) && !valid_node_id(q.node_id.trim()) {
        return Ok(
            Html("<span class=\"pill err\">invalid node id</span>".to_string()).into_response(),
        );
    }
    let esc = |s: &str| askama_escape::escape(s, askama_escape::Html).to_string();
    let target = (!is_local(&q.node_id)).then_some(q.node_id.trim());
    let html =
        match crate::dispatcher::dispatch_to_node(&state, target, Request::BackupRemoteProbe {})
            .await
        {
            Ok(RpcResponse::BackupRemoteProbe(p)) => {
                let cls = if p.ok { "pill ok" } else { "pill err" };
                let latency = if p.ok && p.put_latency_ms > 0 {
                    format!(" · {}ms", p.put_latency_ms)
                } else {
                    String::new()
                };
                format!(
                    "<span class=\"{cls}\">{}{}</span>",
                    esc(&p.message),
                    latency
                )
            }
            Ok(RpcResponse::Error(e)) => format!(
                "<span class=\"pill err\">check failed: {}</span>",
                esc(&e.to_string())
            ),
            Ok(_) => "<span class=\"pill err\">unexpected response</span>".into(),
            Err(e) => format!(
                "<span class=\"pill err\">check failed: {}</span>",
                esc(&e.to_string())
            ),
        };
    Ok(Html(html).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_node_acted_sections_are_writable() {
        for s in [
            "update",
            "fail2ban",
            "backup_remote",
            "acme",
            "protection",
            "backup",
            "backup_retention",
            "snapshots",
        ] {
            assert!(section_meta(s).is_some(), "{s} should be editable per node");
        }
        for s in [
            "cluster",
            "notifications",
            "letters",
            "email",
            "slack",
            "remote_rpc",
            "agent",
            "",
        ] {
            assert!(
                section_meta(s).is_none(),
                "{s} must not be editable per node"
            );
        }
    }

    #[test]
    fn fields_strip_routing_keys_and_keep_blank_password() {
        let mut f = BTreeMap::new();
        f.insert("_csrf".into(), "t".into());
        f.insert("node_id".into(), "n1".into());
        f.insert("section".into(), "backup_remote".into());
        f.insert("_checkboxes".into(), "enabled".into());
        f.insert("host".into(), "ftp.example.com".into());
        f.insert("password".into(), "  ".into());
        let out = fields_to_write("backup_remote", f);
        assert_eq!(out.get("enabled").map(String::as_str), Some("false"));
        assert_eq!(out.get("host").map(String::as_str), Some("ftp.example.com"));
        assert!(
            !out.contains_key("password"),
            "blank password must keep the stored one"
        );
        for k in ["_csrf", "node_id", "section", "_checkboxes"] {
            assert!(!out.contains_key(k), "{k} leaked into agent.toml fields");
        }
    }

    #[test]
    fn node_id_rules() {
        assert!(is_local(""));
        assert!(is_local("local"));
        assert!(!is_local("web-2"));
        assert!(valid_node_id("web-2.example_1"));
        assert!(!valid_node_id("a/b"));
        assert!(!valid_node_id("a\"b"));
        assert!(!valid_node_id(""));
    }

    #[test]
    fn acme_contact_read_from_raw_toml() {
        let raw =
            "[acme]\ncontact_email = \"ops@example.com\"\n[email]\nsmtp_password = \"«set»\"\n";
        assert_eq!(
            parse_raw_extras(raw).acme_contact.as_deref(),
            Some("ops@example.com")
        );
        assert_eq!(parse_raw_extras("not = [toml").acme_contact, None);
    }
}
