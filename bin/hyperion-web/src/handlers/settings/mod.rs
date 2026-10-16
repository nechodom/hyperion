//! `/settings` — the Settings pages and every action they post to.
//!
//! An overview (`overview.rs`) plus one page per section, each in its own
//! file and loading only what it shows; `chrome.rs` holds the frame they
//! share — the section list, the card → page table every redirect goes
//! through, and the read-only rule for anybody but an Owner. This file keeps
//! the POST handlers (they predate the split, and several pages share them)
//! and the helpers more than one page needs.

pub mod chrome;
mod overview;
mod page_access;
mod page_alerts;
mod page_backups;
mod page_bans;
mod page_cluster;
mod page_https;
mod page_letters;
mod page_mail;
mod page_panel;

pub use overview::get_overview;
pub use page_access::get_access;
pub use page_alerts::{get_alert_recipients, get_alerts};
pub use page_backups::get_backups;
pub use page_bans::get_bans;
pub use page_cluster::{get_cluster, post_cluster_sync};
pub use page_https::{get_https, get_preview_dns};
pub use page_letters::{get_letters, post_adopt_legacy};
pub use page_mail::{get_mail, get_mail_health};
pub use page_panel::get_panel;

use crate::auth::AuthCtx;
use crate::error::AppError;
#[allow(unused_imports)] // askama resolves {{ x|datetime }} through this
use crate::filters;
use crate::ratelimit::Bucket;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{AgentConfigView, SmtpAutodetect};
use serde::Deserialize;
use std::net::SocketAddr;

/// One node's `[email]` as its agent.toml has it, for the Mail page and
/// Alerts → Recipients — whose forms are saved straight back, so a blank
/// read must never look like a blank setting.
///
/// The master's own agent answers `AgentConfigView` from the file. A worker
/// is asked for its masked agent.toml (`NodeConfigRead`) instead: an agent
/// from before this release builds `AgentConfigView.email` from its boot copy,
/// which is EMPTY whenever its relay is off — the form would show blanks and
/// a Save would write them over the stored host and sender. A worker too old
/// to answer `NodeConfigRead` is reported as such and gets no form.
pub(crate) async fn node_email(
    state: &SharedState,
    target: Option<&str>,
) -> Result<hyperion_types::EmailConfigView, String> {
    let wait = std::time::Duration::from_secs(4);
    let Some(node) = target else {
        return match tokio::time::timeout(
            wait,
            hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        )
        .await
        {
            Ok(Ok(RpcResponse::AgentConfigView(c))) => Ok(c.email),
            Ok(Ok(RpcResponse::Error(e))) => Err(e.to_string()),
            Ok(Ok(_)) => Err("unexpected answer from the agent".into()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("no answer within 4 s".into()),
        };
    };
    match tokio::time::timeout(
        wait,
        crate::dispatcher::dispatch_to_node(state, Some(node), Request::NodeConfigRead),
    )
    .await
    {
        Ok(Ok(RpcResponse::NodeConfigRead(raw))) => email_view_from_masked_toml(&raw),
        Ok(Ok(RpcResponse::Error(e))) => Err(e.to_string()),
        Ok(Ok(_)) => Err("unexpected answer from the node".into()),
        // An agent from before NodeConfigRead cannot decode the request.
        Ok(Err(e)) if crate::cluster_sync::is_old_agent(&e) => Err(
            "it runs an older agent that cannot show its mail settings here — update it from Nodes"
                .into(),
        ),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("no answer within 4 s".into()),
    }
}

/// `[email]` out of a node's masked agent.toml (`config_persist::mask_secrets`
/// turns the password into `«set»` / `«empty»`). Defaults are the agent's own
/// for absent keys.
pub(crate) fn email_view_from_masked_toml(
    raw: &str,
) -> Result<hyperion_types::EmailConfigView, String> {
    let doc: toml::Value = raw
        .parse()
        .map_err(|e| format!("its agent.toml does not parse: {e}"))?;
    let e = doc.get("email");
    let text = |k: &str| {
        e.and_then(|t| t.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let password = text("smtp_password");
    let security = text("security");
    Ok(hyperion_types::EmailConfigView {
        enabled: e
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        smtp_host: text("smtp_host"),
        smtp_port: e
            .and_then(|t| t.get("smtp_port"))
            .and_then(|v| v.as_integer())
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .unwrap_or(587),
        smtp_user: text("smtp_user"),
        smtp_password_set: !password.is_empty() && password != "«empty»",
        from_address: text("from_address"),
        from_name: text("from_name"),
        security: if security.trim().is_empty() {
            "starttls".into()
        } else {
            security
        },
        default_to: text("default_to"),
    })
}

/// The master's `AgentConfigView`, or the defaults plus why it could not be
/// read. A page built from defaults must say so: every value on it would
/// otherwise look like a setting somebody chose.
pub(crate) fn config_or_default<E: std::fmt::Display>(
    res: Result<RpcResponse, E>,
) -> (AgentConfigView, Option<String>) {
    match res {
        Ok(RpcResponse::AgentConfigView(c)) => (c, None),
        Ok(RpcResponse::Error(e)) => (AgentConfigView::default(), Some(e.to_string())),
        Ok(_) => (
            AgentConfigView::default(),
            Some("unexpected agent response".into()),
        ),
        Err(e) => (AgentConfigView::default(), Some(format!("rpc: {e}"))),
    }
}

fn short_sha(s: &str) -> String {
    s.chars().take(12).collect()
}

/// POST /settings/email-logo — replace or clear the notification logo.
///
/// Validation is by MAGIC BYTES on the agent side, not by filename or the
/// browser-supplied content type: both come from whoever is uploading, and
/// this file is embedded into mail that leaves the building.
pub async fn post_email_logo(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    mut multipart: axum::extract::Multipart,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(chrome::back_with_error(
            "email-branding",
            "Only an Owner can change the logo.",
        ));
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut clear = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name().unwrap_or("") {
            // _csrf is verified by the check_csrf middleware before this
            // handler runs, same as every other POST.
            "_csrf" => {}
            "clear" => {
                clear = !field.text().await.unwrap_or_default().is_empty();
            }
            "logo" => {
                bytes = field.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
            }
            _ => {}
        }
    }
    let payload = if clear { Vec::new() } else { bytes };
    if payload.is_empty() && !clear {
        return Ok(chrome::back_with_error(
            "email-branding",
            "No image was selected.",
        ));
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EmailLogoSet {
            png_or_jpeg: payload,
        },
    )
    .await?;
    match resp {
        RpcResponse::EmailLogoSet => Ok(chrome::back_with_flash(
            "email-branding",
            if clear {
                "Logo removed — emails are headed by the panel hostname again."
            } else {
                "Logo saved."
            },
        )),
        RpcResponse::Error(e) => Ok(chrome::back_with_error("email-branding", &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /settings/backup-remote/probe — connection check for the configured
/// FTP/FTPS/SFTP off-site target: connect, log in, list the directory. Returns
/// an HTMX fragment shown next to the button.
pub async fn post_backup_remote_probe(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            Html("<span class=\"pill err\">admin role required</span>".to_string()).into_response(),
        );
    }
    let esc = |s: &str| askama_escape::escape(s, askama_escape::Html).to_string();
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::BackupRemoteProbe {}).await?;
    let html = match resp {
        RpcResponse::BackupRemoteProbe(p) => {
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
        RpcResponse::Error(e) => {
            format!(
                "<span class=\"pill err\">check failed: {}</span>",
                esc(&e.to_string())
            )
        }
        _ => "<span class=\"pill err\">unexpected response</span>".into(),
    };
    Ok(Html(html).into_response())
}

/// GET /settings/email-logo.img — the stored logo, for the settings preview.
pub async fn get_email_logo_img(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let uri = match hyperion_rpc_client::call(&state.agent_socket, Request::EmailLogoGet).await {
        Ok(RpcResponse::EmailLogoGet(Some(u))) => u,
        _ => return Err(AppError::NotFound),
    };
    // Re-serve the data URI as real bytes for the <img>. `no-store`: the URL
    // never changes when a new logo is uploaded, and this is one admin-only
    // preview, so a cached copy would only ever show the previous logo.
    let (meta, b64) = match uri.split_once(";base64,") {
        Some(v) => v,
        None => return Err(AppError::NotFound),
    };
    let mime = meta
        .strip_prefix("data:")
        .unwrap_or("image/png")
        .to_string();
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| AppError::NotFound)?;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, mime),
            (axum::http::header::CACHE_CONTROL, "no-store".to_string()),
        ],
        bytes,
    )
        .into_response())
}

/// GET /settings/email-preview — the rendered HTML of a sample notification.
///
/// Rendered by the SAME function that composes real mail, so the preview
/// cannot drift from what recipients get — a preview that is merely
/// "representative" is worth very little the day it stops matching.
pub async fn get_email_preview(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let logo = match hyperion_rpc_client::call(&state.agent_socket, Request::EmailLogoGet).await {
        Ok(RpcResponse::EmailLogoGet(v)) => v,
        _ => None,
    };
    let brand = state.panel_hostname.read().await.clone();
    let brand = if brand.trim().is_empty() {
        "Hyperion".to_string()
    } else {
        brand
    };
    let sample = "Certificate for example.cz expires in 7 days.\n\n         It renews automatically 30 days before expiry, so no action is normally \
         needed — this notice means the last attempt did not succeed.\n\n         Open the site's SSL tab to see what Let's Encrypt reported.";
    let html = hyperion_types::render_html_shell(
        &brand,
        sample,
        logo.as_deref(),
        &format!("Sent by Hyperion · https://{brand}"),
    );
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response())
}

/// The account id on file, if any. Asks the AGENT rather than reading the
/// file here — on a worker the panel and the credentials are not on the
/// same box, and reading locally would answer for the wrong machine.
async fn hyperion_adapters_geoip_creds(state: &SharedState) -> Option<String> {
    match hyperion_rpc_client::call(&state.agent_socket, Request::GeoipCredsAccount).await {
        Ok(RpcResponse::GeoipCredsAccount(Some(id))) => Some(id),
        _ => None,
    }
}

/// POST /settings/geoip-creds — store the MaxMind credentials, then prove
/// they work by downloading with them.
pub async fn post_geoip_creds(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Form(form): axum::extract::Form<GeoipCredsForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(chrome::back_with_error(
            "geoip",
            "Only an Owner can change the GeoIP credentials.",
        ));
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::GeoipSetCreds {
            account_id: form.account_id,
            license_key: form.license_key.into(),
        },
    )
    .await;
    Ok(match resp {
        Ok(RpcResponse::GeoipSetCreds(n)) => chrome::back_with_flash(
            "geoip",
            &format!("Credentials saved and the GeoIP database installed — {n} ranges."),
        ),
        Ok(RpcResponse::Error(e)) => chrome::back_with_error("geoip", &e.to_string()),
        Ok(_) => chrome::back_with_error("geoip", "Unexpected answer from the agent."),
        Err(e) => chrome::back_with_error("geoip", &format!("The agent did not answer: {e}")),
    })
}

#[derive(serde::Deserialize)]
pub struct GeoipCredsForm {
    pub account_id: String,
    pub license_key: String,
}

/// POST /settings/geoip-refresh — download or refresh the country database.
///
/// Synchronous: it is one download and a parse, and the operator pressed a
/// button expecting an answer. Errors come back on the page rather than in
/// a log, because the usual one — a rejected licence key — is something
/// only they can fix.
pub async fn post_geoip_refresh(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(chrome::back_with_error(
            "geoip",
            "Only an Owner can refresh the GeoIP database.",
        ));
    }
    Ok(
        match hyperion_rpc_client::call(&state.agent_socket, Request::GeoipRefresh).await {
            Ok(RpcResponse::GeoipRefresh(n)) => {
                chrome::back_with_flash("geoip", &format!("GeoIP database installed — {n} ranges."))
            }
            Ok(RpcResponse::Error(e)) => chrome::back_with_error("geoip", &e.to_string()),
            Ok(_) => chrome::back_with_error("geoip", "Unexpected answer from the agent."),
            Err(e) => chrome::back_with_error("geoip", &format!("The agent did not answer: {e}")),
        },
    )
}

/// Render a unix timestamp as a short YYYY-MM-DD (UTC), or "—" for None.
fn fmt_date(ts: Option<i64>) -> String {
    match ts {
        Some(t) => chrono::DateTime::from_timestamp(t, 0)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "—".to_string()),
        None => "—".to_string(),
    }
}

/// The `[fail2ban]` section as it currently reads on disk, for the
/// Brute-force scanner card (`/settings/bans`) and the overview.
///
/// Not part of `AgentConfigView`: the section is read straight out of
/// `/etc/hyperion/agent.toml`, so the form shows the file rather than a
/// value re-derived somewhere else.
pub struct Fail2banView {
    /// The values in the file, defaults filled in for absent keys.
    pub cfg: hyperion_core::Fail2banConfig,
    /// False ⇒ agent.toml has no `[fail2ban]` table at all, so these are
    /// the built-in defaults rather than anything an operator chose. Said
    /// out loud in the card so the form can't imply a decision nobody made.
    pub in_toml: bool,
    /// True ⇒ at least one value on disk is outside the floors
    /// `Fail2banConfig::sanitized` applies at agent start, so the running
    /// scanner is NOT using the numbers shown. Only reachable by hand-editing
    /// the file — the form's own validation refuses to write such a value.
    pub clamped: bool,
}

/// Parse the `[fail2ban]` table out of agent.toml for the Brute-force scanner card.
///
/// An absent table is not an error: the agent runs the built-in defaults
/// then, which is exactly what's rendered — flagged with `in_toml = false`.
/// `None` means the file didn't parse at all, and the card says that instead
/// of showing numbers it can't stand behind.
pub(crate) fn parse_fail2ban_section(raw: &str) -> Option<Fail2banView> {
    let doc: toml::Value = raw.parse().ok()?;
    let table = doc.get("fail2ban");
    let d = hyperion_core::Fail2banConfig::default();
    let flag = |key: &str, fallback: bool| {
        table
            .and_then(|t| t.get(key))
            .and_then(|v| v.as_bool())
            .unwrap_or(fallback)
    };
    let num = |key: &str, fallback: i64| {
        table
            .and_then(|t| t.get(key))
            .and_then(|v| v.as_integer())
            .unwrap_or(fallback)
    };
    // Thresholds are u32 in the config; a hand-edited negative or absurd
    // value saturates rather than wrapping into a huge threshold that would
    // silently disable a scanner.
    let count =
        |key: &str, fallback: u32| num(key, fallback as i64).clamp(0, u32::MAX as i64) as u32;
    let cfg = hyperion_core::Fail2banConfig {
        enabled: flag("enabled", d.enabled),
        window_secs: num("window_secs", d.window_secs),
        ban_ttl_secs: num("ban_ttl_secs", d.ban_ttl_secs),
        repeat_ttl_secs: num("repeat_ttl_secs", d.repeat_ttl_secs),
        repeat_lookback_secs: num("repeat_lookback_secs", d.repeat_lookback_secs),
        http_threshold: count("http_threshold", d.http_threshold),
        ssh_threshold: count("ssh_threshold", d.ssh_threshold),
        ftp_threshold: count("ftp_threshold", d.ftp_threshold),
        mail_threshold: count("mail_threshold", d.mail_threshold),
        waf_threshold: count("waf_threshold", d.waf_threshold),
    };
    Some(Fail2banView {
        in_toml: table.is_some(),
        clamped: cfg.clone().sanitized() != cfg,
        cfg,
    })
}

#[derive(Deserialize)]
pub struct EmailTestForm {
    to: String,
    /// Which node should send the test email. Empty / "local" /
    /// "" → master. Anything else is a node_id from /install.
    /// Lets the operator verify that each worker's local SMTP
    /// config (or no-config-falls-back-to-master-relay) works.
    #[serde(default)]
    target_node: String,
}

/// POST /settings/slack-test — post a test message to the saved webhook.
///
/// Same gate and rate limit as the e-mail test: this makes the box emit an
/// outbound request to an operator-supplied URL, so an authenticated viewer
/// must not be able to drive it, and a stolen admin cookie must not be able
/// to drive it in a loop.
pub async fn post_slack_test(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to(
            "/settings/alerts?flash_error=admin+role+required+to+send+a+test+message#slack",
        )
        .into_response());
    }
    let ip = email_test_ip(&headers, peer);
    if !state
        .ratelimit
        .check("slack-test", ip, Bucket::per_minute(3))
    {
        return Ok(Redirect::to(
            "/settings/alerts?flash_error=test+message+rate+limit+exceeded+%E2%80%94+wait+a+minute#slack",
        )
        .into_response());
    }
    let resp = crate::dispatcher::dispatch_to_node(&state, None, Request::SlackSendTest).await?;
    Ok(match resp {
        RpcResponse::SlackSendTest => Redirect::to(
            "/settings/alerts?flash=Test+message+posted+%E2%80%94+check+the+Slack+channel#slack",
        )
        .into_response(),
        RpcResponse::Error(e) => {
            let msg = super::hostings::urlencoding(&e.to_string());
            Redirect::to(&format!("/settings/alerts?flash_error={msg}#slack")).into_response()
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    })
}

/// POST /settings/email-test — fires a one-off SMTP send + redirects
/// back to Settings → Mail (`/settings/mail#mail-test`) with a flash message.
pub async fn post_email_test(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<EmailTestForm>,
) -> Result<Response, AppError> {
    // Every redirect below returns to Settings → Mail AND keeps the node the
    // operator was looking at (`&mail_node=…`), so it is computed before
    // any gate. ""/"local" (the master) adds no suffix.
    let (_, node_q) = mail_node_target(&form.target_node);
    // Without this gate any authenticated viewer can use Hyperion's
    // SMTP relay as a free spam vector — the relay's daily quota
    // would also get blown out, breaking real cluster notifications.
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to(&format!(
            "/settings/mail?flash_error=admin+role+required+to+send+test+emails{node_q}#mail-test"
        ))
        .into_response());
    }
    // Per-IP rate limit so a compromised admin cookie / leaked
    // session can't be used as an open relay or address enumerator.
    // 3/min is comfortable for an operator clicking Test a few times
    // and absurdly low for automated abuse.
    let ip = email_test_ip(&headers, peer);
    if !state
        .ratelimit
        .check("email-test", ip, Bucket::per_minute(3))
    {
        return Ok(Redirect::to(&format!(
            "/settings/mail?flash_error=test+email+rate+limit+exceeded+%E2%80%94+wait+a+minute{node_q}#mail-test"
        ))
        .into_response());
    }
    let to = form.to.trim().to_string();
    // Bound the address at the RFC5321 max so a 50 KB pathological
    // 'to' field can't blow out the Location header on the redirect.
    if to.len() > 254 {
        return Ok(Redirect::to(&format!(
            "/settings/mail?flash_error=address+too+long+%28max+254+chars%29{node_q}#mail-test"
        ))
        .into_response());
    }
    // Multi-node: when an operator picks a target_node, the test
    // dispatches via the signed RPC channel so the chosen worker
    // does the actual SMTP send. This verifies that worker's
    // outbound SMTP path independently from the master's.
    let target_owned = form.target_node.trim().to_string();
    let target =
        if target_owned.is_empty() || target_owned == crate::dispatcher::LOCAL_NODE_SENTINEL {
            None
        } else {
            Some(target_owned.as_str())
        };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::EmailSendTest { to: to.clone() },
    )
    .await?;
    match resp {
        RpcResponse::EmailSendTest { smtp_code } => {
            // Surface the SMTP server's response code in the flash —
            // "250 OK" means the relay accepted the message into its
            // queue (whether it'll be delivered is between the relay
            // and the recipient's MX). Operator can tell "queued"
            // from "rejected by relay before our test even left".
            let node_label = if target_owned.is_empty() || target_owned == "local" {
                "master".to_string()
            } else {
                target_owned.clone()
            };
            let msg = format!("Test email sent from {node_label} to {to} · SMTP relay said {smtp_code} · the Email log has the delivery record");
            Ok(Redirect::to(&format!(
                "/settings/mail?flash={}{node_q}#mail-test",
                urlencode(&msg)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => {
            // Point at the Email log (/emails) so the operator can see the
            // failed row in context (it's already logged there).
            let msg = format!("{e} — the Email log has the failed attempt");
            Ok(Redirect::to(&format!(
                "/settings/mail?flash_error={}{node_q}#mail-test",
                urlencode(&msg)
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ConfigEditForm {
    /// "acme" | "email" | "slack" | "backup_remote" | "backup_retention"
    pub section: String,
    /// Field name -> string-encoded value. Service does the typing.
    /// Empty string clears (or sets the field to "" depending on
    /// type — int parsing rejects empty).
    #[serde(flatten)]
    pub fields: std::collections::BTreeMap<String, String>,
}

/// Browsers don't submit unchecked checkboxes at all. The config
/// handler treats a missing field as "leave alone", so without this
/// helper, unchecking a checkbox would silently do nothing.
///
/// **Per-FORM declaration**, not per-section. Each `<form>` carries
/// a hidden `_checkboxes` field with the comma-separated names of
/// the checkboxes IT owns. Synthesize-false only those.
///
/// Why per-form and not per-section: the `cluster` section has
/// multiple sub-forms (Master placement, Test nodes, Trash,
/// Audit retention, …). A section-wide list would synthesize
/// `trash_enabled=false` whenever the operator saved the Audit
/// Retention form — silently turning trash off on every save.
/// Kevin reported exactly that: "trash se vypne po restartu agenta"
/// — the restart was a red herring; the unintended `false` got
/// persisted by the previous form save.
///
/// Forms without checkboxes omit `_checkboxes` entirely (or leave
/// it empty); the helper is a no-op then.
pub(crate) fn synthesize_unchecked_checkboxes(
    fields: &mut std::collections::BTreeMap<String, String>,
    declared: &str,
) {
    for name in declared.split(',') {
        let n = name.trim();
        if n.is_empty() {
            continue;
        }
        if !fields.contains_key(n) {
            fields.insert(n.to_string(), "false".to_string());
        }
    }
}

/// POST /settings/config — Owner only. Updates one section of agent.toml in
/// place, preserving comments, then restarts hyperion-agent a few seconds
/// after the redirect so the new value takes effect. The redirect lands on
/// the card the form came from (`_return_tab`, else the section's own card),
/// with the outcome shown inside that card.
pub async fn post_config(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ConfigEditForm>,
) -> Result<Response, AppError> {
    // `_return_tab` names the CARD to come back to. Several cards write the
    // same section ([cluster] from five pages, [notifications] from two,
    // [email] from Mail and Alerts), so the section alone cannot say which.
    let return_tab_override = form
        .fields
        .get("_return_tab")
        .and_then(|v| sanitize_return_tab(v));
    let card = return_tab_override.unwrap_or_else(|| section_to_tab(&form.section));
    if !ctx.is_super_admin() {
        // The pages render these forms disabled for anybody but an Owner;
        // this is the backstop for a form posted anyway.
        return Ok(chrome::back_with_error(
            card,
            "Only an Owner can change settings.",
        ));
    }
    // Strip the `section` field from the bag — it's not a TOML field
    // itself, it's the routing key. axum's `#[serde(flatten)]` collects
    // every form field including `section`, so filter it out.
    let mut fields = form.fields;
    fields.remove("section");
    fields.remove("_csrf");
    // `_return_tab` is a UI hint, not a config key.
    fields.remove("_return_tab");
    // `_checkboxes` declares which boolean checkboxes THIS specific
    // form is responsible for. Synth-false defaults apply only to
    // these — see comment on synthesize_unchecked_checkboxes for the
    // bug this prevents (saving one cluster sub-form silently
    // resetting another sub-form's checkboxes to false).
    let declared_checkboxes = fields.remove("_checkboxes").unwrap_or_default();
    // "Leave blank to keep" for sensitive fields — empty string would
    // overwrite a real password / webhook URL with "".
    let drop_if_empty: &[&str] = match form.section.as_str() {
        "email" => &["smtp_password"],
        "slack" => &["default_webhook"],
        "backup_remote" => &["password"],
        "performance" => &["psi_api_key"],
        _ => &[],
    };
    for k in drop_if_empty {
        if fields.get(*k).map(|v| v.trim().is_empty()).unwrap_or(false) {
            fields.remove(*k);
        }
    }
    // Disconnect Slack posts an empty webhook WITH `_disconnect` — the one
    // case where empty means "remove it", not "leave blank to keep". Without
    // the marker the empty value was dropped just above, so Disconnect saved
    // nothing and still reported "Slack saved".
    if fields.remove("_disconnect").is_some() && form.section == "slack" {
        fields.insert("default_webhook".into(), String::new());
    }
    // A letter sentence submitted EXACTLY as the pack writes it is not an
    // override, and storing it would fork that sentence: every later
    // improvement to the built-in wording would stop reaching this install,
    // with nothing in the UI to say so.
    //
    // This is not hypothetical. "Fill the fields with the built-in wording"
    // exists so an operator can EDIT a sentence instead of retyping something
    // they can see but not select — and it puts all 125 built-ins into the
    // form. Pressing it and saving, which is the obvious thing to do, would
    // otherwise fork the entire catalogue in one click. Retyping a sentence
    // character-for-character does the same, more slowly.
    if form.section == "letters" {
        let cat = current_letter_catalogue().await;
        for (id, value) in fields.iter_mut() {
            if id == "lang" || value.is_empty() {
                continue;
            }
            if hyperion_core::letters::lookup(id).is_some() {
                *value = letter_value_to_store(id, value, cat.lang);
            }
        }
    }
    // Unchecked checkboxes don't show up in the form at all — but our
    // service knows the field is required. Synthesise the missing
    // booleans as "false" so unchecking persists. ONLY for checkboxes
    // this form actually declared via `_checkboxes`; cross-form
    // synthesis is the bug Kevin hit.
    synthesize_unchecked_checkboxes(&mut fields, &declared_checkboxes);

    // `target_node` (present only on the per-node mail forms) selects which
    // node this save targets. Pull it out before the fields are persisted.
    let target_node_raw = fields.remove("target_node").unwrap_or_default();

    // The email section is PER-NODE: dispatch EmailConfigSet to the chosen node
    // (master = local socket). It writes that node's agent.toml, applies
    // postfix live, and self-restarts the node's agent. Every other section
    // is written on the master (local write + web-driven restart, below);
    // the synced ones then reach every node through `crate::cluster_sync`.
    if form.section == "email" {
        // Alerts → Recipients takes commas, semicolons and new lines; the
        // file keeps one separator.
        if let Some(v) = fields.get_mut("default_to") {
            *v = page_alerts::normalize_address_list(v);
        }
        let (node_target, node_q) = mail_node_target(&target_node_raw);
        // The Mail page edits one node and keeps it in its URL; Alerts lists
        // every node's recipients at once, so it needs no node to come back to.
        let node_q = if chrome::card_section(card) == Some("mail") {
            node_q
        } else {
            String::new()
        };
        let resp = crate::dispatcher::dispatch_to_node(
            &state,
            node_target.as_deref(),
            Request::EmailConfigSet {
                fields: fields.into(),
            },
        )
        .await
        .map_err(AppError::from)?;
        // Name the card and the node the way the pages do — a worker by its
        // label, not its `node_…` id; one server needs no name at all.
        let what = return_tab_override
            .and_then(card_label)
            .unwrap_or("Outgoing relay");
        let nodes = chrome::enrolled_nodes(&state).await;
        let msg = match node_target.as_deref() {
            None if nodes.is_empty() => {
                format!("{what} saved — the agent restarts in about 5 s.")
            }
            None => format!("{what} saved on the master — its agent restarts in about 5 s."),
            Some(id) => {
                let name = nodes
                    .iter()
                    .find(|n| n.node_id == id)
                    .map(|n| n.label.trim())
                    .filter(|l| !l.is_empty())
                    .unwrap_or(id);
                format!("{what} saved on {name} — its agent restarts in about 5 s.")
            }
        };
        let dest = match resp {
            RpcResponse::EmailConfigSet => {
                chrome::card_url(card, &format!("flash={}{node_q}", urlencode(&msg)))
            }
            RpcResponse::Error(e) => chrome::card_url(
                card,
                &format!("flash_error={}{node_q}", urlencode(&e.to_string())),
            ),
            _ => return Err(AppError::Internal("unexpected response".into())),
        };
        return Ok(Redirect::to(&dest).into_response());
    }

    // Nodes the settings sync cannot update (an agent from before it) still
    // get the settings their sites are run by pushed at save time. See
    // `fields_for_workers` and `push_to_unsynced_nodes`.
    let propagated_fields = fields_for_workers(&form.section, &fields);
    // Does this save carry anything the settings sync distributes? Decided
    // per KEY: [cluster] is mostly master-only, and only its trash keys go
    // out, so a 2FA save must not promise the other nodes anything.
    let synced = fields
        .keys()
        .any(|k| hyperion_core::cluster_sync::is_synced_key(&form.section, k));
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AgentConfigUpdate {
            section: form.section.clone(),
            fields: fields.into(),
        },
    )
    .await
    .map_err(AppError::from)?;
    // The flash names the CARD that was saved when the form said which
    // one it was, so a 2FA save does not read "Cluster settings saved".
    let label = return_tab_override
        .and_then(card_label)
        .unwrap_or_else(|| section_label(&form.section));
    let dest = match resp {
        RpcResponse::AgentConfigUpdate => {
            // The settings sync carries every synced section to the other
            // nodes — including the ones down right now, on a later pass.
            if synced {
                state.cluster_sync.kick();
            }
            restart_agent_soon();
            let pushed = match propagated_fields {
                Some((sect, f)) => push_to_unsynced_nodes(&state, &sect, f).await,
                None => Ok(0),
            };
            let is_master = state.deployment_mode.read().await.as_str() == "master";
            let has_nodes = !chrome::enrolled_nodes(&state).await.is_empty();
            // After saving the off-site FTP target, carry a flag so the page
            // re-runs the connection check once the agent is back.
            let probe = if form.section == "backup_remote" {
                "&probe_backup_remote=1"
            } else {
                ""
            };
            match pushed {
                Ok(_) => {
                    let mut msg = format!("{label} saved — the agent restarts in about 5 s");
                    if synced && is_master && has_nodes {
                        msg.push_str("; the other nodes get it within a minute");
                    }
                    msg.push('.');
                    chrome::card_url(card, &format!("flash={}{probe}", urlencode(&msg)))
                }
                Err(failed) => chrome::card_url(
                    card,
                    &format!(
                        "flash_error={}{probe}",
                        urlencode(&format!(
                            "{label} saved on this master, but {} did not take it: {}. \
                             Sites on {} keep the previous setting until it is updated — \
                             the Nodes page shows which nodes have the master's settings.",
                            if failed.len() == 1 {
                                "one node"
                            } else {
                                "some nodes"
                            },
                            failed.join("; "),
                            if failed.len() == 1 { "it" } else { "them" },
                        ))
                    ),
                ),
            }
        }
        RpcResponse::Error(e) => {
            chrome::card_url(card, &format!("flash_error={}", urlencode(&e.to_string())))
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}

/// Restart the master's agent a few seconds from now, after a save to its
/// agent.toml.
///
/// Delayed so the redirect response gets back to the browser BEFORE the
/// agent goes down; 3 s is plenty for the in-flight response to land, and
/// systemd brings the agent back within ~2 s, so the operator's next click
/// sees the fresh config.
///
/// Why not the service_restart RPC? It refuses to restart hyperion-agent
/// through the agent itself (it would kill its own RPC pipe). Doing it from
/// hyperion-web's process side dodges that — we are not the agent.
fn restart_agent_soon() {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let out = tokio::process::Command::new("/usr/bin/systemctl")
            .args(["restart", "hyperion-agent"])
            .output()
            .await;
        match out {
            Ok(o) if o.status.success() => {
                tracing::info!("auto-restart hyperion-agent after config save: ok");
            }
            Ok(o) => {
                tracing::error!(
                    stderr = %String::from_utf8_lossy(&o.stderr),
                    exit_code = ?o.status.code(),
                    "auto-restart hyperion-agent failed — operator must restart manually"
                );
            }
            Err(e) => {
                tracing::error!(error=%e, "auto-restart hyperion-agent: spawn failed");
            }
        }
    });
}

/// Push a just-saved section straight to the nodes the settings sync cannot
/// update.
///
/// Since `crate::cluster_sync` the master's settings reach every node on
/// their own — a node that is down for a save gets it on a later pass, and
/// the Nodes and Cluster pages say which nodes are behind. An agent from
/// before the sync cannot take them that way (the sync reports it as an
/// old agent), and its sites would keep running on whatever that node last
/// had. For those nodes — and for nodes the sync has not reported on yet —
/// the save is still pushed directly, the way every save used to be.
///
/// `Ok(n)` = the section is now on n such nodes. `Err(labels)` lists, per
/// node, what went wrong, in words the operator can act on.
async fn push_to_unsynced_nodes(
    state: &SharedState,
    section: &str,
    fields: std::collections::BTreeMap<String, String>,
) -> Result<usize, Vec<String>> {
    let nodes: Vec<hyperion_types::NodeSummary> = match crate::dispatcher::cached_nodes(state)
        .await
        .map(hyperion_rpc::codec::Response::NodesList)
    {
        Ok(RpcResponse::NodesList(v)) => v,
        // The node list itself is unreadable. Saying "pushed to 0 nodes"
        // here would claim a single-node install; say what happened.
        _ => {
            return Err(vec![
                "the enrolled-node list could not be read, so no other node was updated"
                    .to_string(),
            ])
        }
    };
    // The trash keys joined the sync later than the rest: a node from the
    // first synced release ignores the `[cluster]` part of the payload, and
    // would otherwise never get them. They go to every node.
    let everyone = section == "cluster";
    let mut targets = Vec::new();
    for n in nodes {
        let managed = state
            .cluster_sync
            .status_for(&n.node_id)
            .await
            .is_some_and(|s| s.managed());
        if everyone || !managed {
            targets.push(n);
        }
    }
    if targets.is_empty() {
        return Ok(0);
    }
    let mut set = tokio::task::JoinSet::new();
    for n in targets {
        let st = state.clone();
        let f = fields.clone();
        let sect = section.to_string();
        let node_id = n.node_id.clone();
        let label = if n.label.trim().is_empty() {
            n.node_id.clone()
        } else {
            n.label.clone()
        };
        set.spawn(async move {
            let resp = crate::dispatcher::dispatch_to_node(
                &st,
                Some(node_id.as_str()),
                Request::AgentConfigUpdate {
                    section: sect.to_string(),
                    fields: f.clone().into(),
                },
            )
            .await;
            match resp {
                Ok(RpcResponse::AgentConfigUpdate) => Ok(()),
                // An agent from before "keep the newest local copies" refuses
                // the whole [backup] save over that one key — and with it the
                // on/off switch it does understand. Resend without the key
                // when leaving it out changes nothing on that node.
                Ok(RpcResponse::Error(e))
                    if backup_keep_unknown_to_old_node(&sect, &e.to_string()) =>
                {
                    match backup_fields_for_old_node(&f) {
                        Some(f_old) => {
                            match crate::dispatcher::dispatch_to_node(
                                &st,
                                Some(node_id.as_str()),
                                Request::AgentConfigUpdate {
                                    section: sect.to_string(),
                                    fields: f_old.into(),
                                },
                            )
                            .await
                            {
                                Ok(RpcResponse::AgentConfigUpdate) => Ok(()),
                                Ok(RpcResponse::Error(e)) => {
                                    Err(format!("{label} refused it ({e})"))
                                }
                                Ok(_) => Err(format!("{label} answered with something unexpected")),
                                Err(e) => Err(format!("{label} could not be updated ({e})")),
                            }
                        }
                        None => Err(format!(
                            "{label} runs an older agent that cannot keep the newest local \
                             copies, so it kept its previous setting — upgrade it, or set the \
                             count to 0 to change dropping there"
                        )),
                    }
                }
                // An agent from before the language keys were writable
                // refuses the whole [letters] save over them — and with it
                // `lang` and the sentences it does understand. Resend without.
                Ok(RpcResponse::Error(e))
                    if sect == "letters"
                        && LETTERS_KEYS_OLD_NODES_REFUSE
                            .iter()
                            .any(|k| e.to_string().contains(k))
                        && f.keys()
                            .any(|k| LETTERS_KEYS_OLD_NODES_REFUSE.contains(&k.as_str())) =>
                {
                    let mut f_old = f.clone();
                    f_old.retain(|k, _| !LETTERS_KEYS_OLD_NODES_REFUSE.contains(&k.as_str()));
                    if f_old.is_empty() {
                        return Err(format!(
                            "{label} runs an older agent that cannot take the alert or billing \
                             language — update it"
                        ));
                    }
                    match crate::dispatcher::dispatch_to_node(
                        &st,
                        Some(node_id.as_str()),
                        Request::AgentConfigUpdate {
                            section: sect.to_string(),
                            fields: f_old.into(),
                        },
                    )
                    .await
                    {
                        Ok(RpcResponse::AgentConfigUpdate) => Ok(()),
                        Ok(RpcResponse::Error(e)) => Err(format!("{label} refused it ({e})")),
                        Ok(_) => Err(format!("{label} answered with something unexpected")),
                        Err(e) => Err(format!("{label} could not be updated ({e})")),
                    }
                }
                // An older agent that doesn't know these keys refuses the
                // write; the operator needs to hear THAT, not "unreachable".
                Ok(RpcResponse::Error(e)) => Err(format!("{label} refused it ({e})")),
                Ok(_) => Err(format!("{label} answered with something unexpected")),
                Err(e) => Err(format!("{label} could not be updated ({e})")),
            }
        });
    }
    let mut ok = 0usize;
    let mut failed: Vec<String> = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(())) => ok += 1,
            Ok(Err(why)) => failed.push(why),
            Err(e) => failed.push(format!("a node update task failed ({e})")),
        }
    }
    if failed.is_empty() {
        Ok(ok)
    } else {
        // Sorted so the same failure reads the same way twice running.
        failed.sort();
        Err(failed)
    }
}

/// `[letters]` keys an agent from before this release refuses as "not
/// editable" — and with them the whole save.
const LETTERS_KEYS_OLD_NODES_REFUSE: &[&str] = &["operator_lang", "billing_lang"];

/// `[cluster]` keys read by the node that OWNS a hosting. `delete()` reads
/// its own node's `trash_enabled` and the trash GC its own retention, so a
/// value saved on the master alone left every worker delete permanent; and
/// each node's nginx builds its sites' preview aliases from its own
/// `test_domain_template`, so previews never worked on a worker. The same
/// keys `hyperion_core::cluster_sync::is_synced_key` carries.
const CLUSTER_KEYS_FOR_WORKERS: &[&str] = &[
    "trash_enabled",
    "trash_retention_days",
    "test_domain_template",
];

/// The `(section, fields)` a save must also send every enrolled node, or
/// `None` when the section is master-only.
///
/// `[notifications]` holds the two CUSTOMER letters, and those are read on
/// the node that OWNS each hosting — not here. The backup engine choice and
/// both retention rules are the same kind of setting: they are ACTED ON by the
/// node that owns each site (the scheduled backup sweep, the pre-change
/// snapshot, the retention sweeps), so a value saved only on the master
/// governed only the master's sites. `[backup] drop_local_after_offsite` is
/// acted on by the owning node's backup run, and `[performance]` by its care
/// report and CWV measurement.
///
/// `[cluster]` is mostly master-only (sign-in, placement, hardening, previews
/// — seven cards write it), so only [`CLUSTER_KEYS_FOR_WORKERS`] go out, and
/// only when the save carries one.
fn fields_for_workers(
    section: &str,
    fields: &std::collections::BTreeMap<String, String>,
) -> Option<(String, std::collections::BTreeMap<String, String>)> {
    match section {
        "notifications" | "letters" | "protection" | "snapshots" | "backup_retention"
        | "backup" | "performance" => Some((section.to_string(), fields.clone())),
        "cluster" => {
            let picked: std::collections::BTreeMap<String, String> = fields
                .iter()
                .filter(|(k, _)| CLUSTER_KEYS_FOR_WORKERS.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            (!picked.is_empty()).then(|| (section.to_string(), picked))
        }
        _ => None,
    }
}

/// Did a node refuse a `[backup]` save only because it predates
/// `keep_local_latest`? (Its config parser rejects unknown keys by name.)
fn backup_keep_unknown_to_old_node(section: &str, error: &str) -> bool {
    section == "backup" && error.contains("keep_local_latest")
}

/// The `[backup]` fields to send a node that predates `keep_local_latest`, or
/// `None` when leaving the key out would change what that node does. An old
/// node behaves as "keep 0", so the key can go when it says 0 (or nothing), or
/// when dropping is being switched off. A keep count above 0 with dropping on
/// must NOT be stripped: the old node would then drop the very copies the
/// operator asked to keep.
fn backup_fields_for_old_node(
    fields: &std::collections::BTreeMap<String, String>,
) -> Option<std::collections::BTreeMap<String, String>> {
    let keep = fields
        .get("keep_local_latest")
        .map(|v| v.trim())
        .unwrap_or("");
    let drop_on = fields.get("drop_local_after_offsite").is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "true" | "on" | "1" | "yes"
        )
    });
    if !(keep.is_empty() || keep == "0" || !drop_on) {
        return None;
    }
    let mut f = fields.clone();
    f.remove("keep_local_latest");
    Some(f)
}

/// Operator-facing name for a config section.
///
/// The redirect used to say "Section [backup_remote] saved", which is the name
/// of a TOML table — it tells somebody who already knows the file what
/// happened, and tells everybody else nothing. The message is the only
/// confirmation a save has, so it should name the thing that was saved.
fn section_label(section: &str) -> &'static str {
    match section {
        "backup_remote" => "FTP / SFTP target",
        "backup_retention" => "Archive retention",
        "backup" => "Local copies",
        "protection" => "What is kept",
        "snapshots" => "Snapshot retention",
        "performance" => "Core Web Vitals",
        "cluster" => "Cluster settings",
        "notifications" => "Alert wording",
        "letters" => "Sentences",
        "fail2ban" => "Brute-force scanner",
        "update" => "Updates",
        "acme" => "Let's Encrypt contact",
        "slack" => "Slack",
        _ => "Settings",
    }
}

/// Operator-facing name for the CARD a `_return_tab` anchor points at, for
/// the save flash. Only the cards of a section written by several forms are
/// listed: seven forms write `[cluster]` and two write `[notifications]`, so
/// [`section_label`] alone would call every one of them by its section's
/// name ("Cluster settings saved" after turning on 2FA). Anything else —
/// a tab id, a retired id — returns None and the section label is used.
fn card_label(anchor: &str) -> Option<&'static str> {
    match anchor {
        "sign-in" => Some("Two-factor sign-in"),
        "hardening" => Some("Channel hardening"),
        "placement" => Some("Placement"),
        "test-nodes" => Some("Test nodes"),
        "preview-address" => Some("Preview address"),
        "trash" => Some("Trash"),
        "audit-retention" => Some("Audit log retention"),
        "alert-templates" => Some("Alert wording"),
        "alert-language" => Some("Alert language"),
        "alert-recipients" => Some("Recipients"),
        "customer-letters" => Some("Letters"),
        "letter-language" => Some("Letter languages"),
        "letter-wording" => Some("Sentences"),
        _ => None,
    }
}

/// How many backups one click copies.
///
/// A ceiling rather than "all of them": this is real bandwidth over somebody
/// else's FTP account, and an unbounded sweep on a large estate runs for hours
/// with no way to stop it. The job log says when it stopped short, because a
/// truncated sweep reporting "finished" leaves the rest uncopied silently.
const BACKFILL_BATCH: i64 = 200;

/// Query for [`post_offsite_backfill`]. `drop=1` turns the copy into a
/// copy-then-delete-local sweep; anything else keeps the historical
/// copy-only behaviour. A string, not a bool, because `serde_urlencoded`
/// only parses `true`/`false` for bools and the button sends `1`.
#[derive(serde::Deserialize, Default)]
pub struct OffsiteBackfillParams {
    #[serde(default)]
    drop: Option<String>,
}

/// POST /settings/backups/backfill — send local backups that never left, and
/// (with `?drop=1`) delete each local copy once it is independently confirmed
/// off-site.
pub async fn post_offsite_backfill(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(params): axum::extract::Query<OffsiteBackfillParams>,
) -> Result<Response, AppError> {
    // BackupRun is NOT enough. Every Customer role holds it, and this action
    // is not scoped to a hosting: it walks every successful backup on the
    // node, for every tenant, uploads them over the operator's own off-site
    // account and writes state onto rows the caller has no grant on. One
    // tenant could burn the operator's remote quota and stamp "failed" on
    // everybody else's backups.
    //
    // `BackupTargets` is what the sibling page already uses for "may decide
    // where backups go", and neither Operator nor Customer holds it.
    // `scope_all` on top, because an estate-wide action needs estate-wide
    // scope by definition.
    if !ctx.can(Capability::BackupTargets) || !ctx.scope_all() {
        return Ok(chrome::back_with_error(
            "offsite-backfill",
            "Copying existing backups off-site needs the \u{201c}Manage off-site backup targets\u{201d} \
             permission and access to every site.",
        ));
    }
    let drop_local = matches!(params.drop.as_deref(), Some("1") | Some("true"));
    // The S3 targets live in the master's table; resolving them here (reading
    // each 0600 secret) lets the node push to them too, so the sweep is not
    // silently FTP-only. Same read the per-hosting backup uses.
    let s3_targets = crate::handlers::hostings::resolve_s3_targets(&state).await;
    // Real transfers, sized by the estate — a job, never a request.
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "offsite-backfill",
        None,
        "{}",
        &actor_label,
        actor_uid,
        move |reporter| async move {
            reporter
                .step(
                    if drop_local {
                        "Copying backups off-site, then dropping the local copy once verified…"
                    } else {
                        "Looking for backups with no off-site copy…"
                    },
                    5,
                    "",
                )
                .await;
            // One blocking RPC per node that uploads and, with drop on,
            // re-checks every site's local copies: heartbeat the job row so a
            // long sweep is not reaped as stale (and its real result thrown
            // away) mid-flight. The percentage is the nodes finished so far,
            // shared so a heartbeat never moves the bar backwards.
            let pct = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(5));
            let hb = {
                let reporter = reporter.clone();
                let pct = pct.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                        reporter
                            .step(
                                "Still working — copying off-site and re-checking local copies…",
                                pct.load(std::sync::atomic::Ordering::Relaxed),
                                "",
                            )
                            .await;
                    }
                })
            };
            // Each node keeps its OWN sites' backup rows and archives, so the
            // sweep runs on every node — the master and each enrolled worker,
            // concurrently — and each node's result goes into the log as it
            // lands. The per-site off-site card sends worker sites' owners
            // here too, so a master-only sweep left exactly them behind.
            let mut targets: Vec<(Option<String>, String)> =
                vec![(None, "master (this server)".to_string())];
            // Not knowing the workers is not "there are none": that becomes a
            // turn of its own, and fails the job so it does not read as
            // estate-wide.
            let mut node_list_problem: Option<String> = None;
            match crate::dispatcher::cached_nodes(&job_state).await {
                Ok(nodes) => targets.extend(nodes.into_iter().map(|n| {
                    let label = if n.label.trim().is_empty() {
                        n.node_id.clone()
                    } else {
                        n.label.clone()
                    };
                    (Some(n.node_id), label)
                })),
                Err(e) => {
                    node_list_problem = Some(format!(
                        "the enrolled-node list could not be read ({e}), so no worker was swept"
                    ))
                }
            }
            let mut set = tokio::task::JoinSet::new();
            for (i, (node, label)) in targets.iter().cloned().enumerate() {
                let st = job_state.clone();
                let s3 = s3_targets.clone();
                set.spawn(async move {
                    let outcome = match crate::dispatcher::dispatch_to_node(
                        &st,
                        node.as_deref(),
                        Request::BackupOffsiteBackfill {
                            limit: BACKFILL_BATCH,
                            drop_local,
                            s3_targets: s3,
                        },
                    )
                    .await
                    {
                        Ok(RpcResponse::BackupOffsiteBackfill(r)) => Ok(r),
                        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
                        Ok(_) => Err("unexpected agent response".to_string()),
                        Err(e) => Err(e.to_string()),
                    };
                    (i, label, outcome)
                });
            }
            let total = targets.len();
            let mut turns: Vec<(usize, BackfillTurn)> = Vec::with_capacity(total);
            while let Some(joined) = set.join_next().await {
                let Ok((i, label, outcome)) = joined else {
                    continue;
                };
                let block = backfill_node_block(&label, &outcome, drop_local);
                let done = turns.len() + 1;
                let now_pct = (5 + 90 * done / total.max(1)) as i64;
                pct.store(now_pct, std::sync::atomic::Ordering::Relaxed);
                reporter
                    .step(
                        &format!("{done} of {total} node(s) finished…"),
                        now_pct,
                        &block,
                    )
                    .await;
                turns.push((i, (label, outcome)));
            }
            hb.abort();
            // A panicked task left no turn behind: never let that read as done.
            if turns.len() < total {
                let answered: Vec<usize> = turns.iter().map(|(i, _)| *i).collect();
                for (i, (_, label)) in targets.iter().enumerate() {
                    if !answered.contains(&i) {
                        turns.push((i, (label.clone(), Err("the sweep crashed".to_string()))));
                    }
                }
            }
            turns.sort_by_key(|(i, _)| *i);
            let mut turns: Vec<BackfillTurn> = turns.into_iter().map(|(_, t)| t).collect();
            let mut last_block = String::new();
            if let Some(problem) = node_list_problem {
                let outcome = Err(problem);
                last_block = backfill_node_block("enrolled nodes", &outcome, drop_local);
                turns.push(("enrolled nodes".to_string(), outcome));
            }
            let (ok, err) = backfill_job_verdict(&turns, drop_local);
            reporter.step("Finished.", 100, &last_block).await;
            reporter.finish(ok, err).await;
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// One node's turn in the off-site backfill job: its label, and its result
/// or why it did not run.
type BackfillTurn = (
    String,
    Result<hyperion_types::OffsiteBackfillResult, String>,
);

/// The job-log block for one node's turn.
fn backfill_node_block(
    label: &str,
    outcome: &Result<hyperion_types::OffsiteBackfillResult, String>,
    drop_local: bool,
) -> String {
    let mut log = format!("\n── {label} ──\n");
    let r = match outcome {
        Ok(r) => r,
        Err(e) => {
            log.push_str(&format!(
                "NOT RUN:    {e}\n            The backups on this node were not looked at — \
                 run the copy again once it answers.\n"
            ));
            return log;
        }
    };
    log.push_str(&format!(
        "considered: {}\npushed:     {}\nfailed:     {}\n",
        r.considered, r.pushed, r.failed
    ));
    if drop_local {
        log.push_str(&format!(
            "dropped:    {} local cop{} removed after an independent off-site \
             re-verify\nkept local: {} cop{} kept — could NOT be confirmed \
             off-site (missing, wrong size, or unreachable to re-check)\n",
            r.dropped,
            if r.dropped == 1 { "y" } else { "ies" },
            r.kept_local,
            if r.kept_local == 1 { "y" } else { "ies" },
        ));
        if r.already_offsite > 0 {
            log.push_str(&format!(
                "            ({} of those were already off-site: re-checked \
                 there and dropped without being uploaded again)\n",
                r.already_offsite
            ));
        }
    }
    // Separated from `failed` because no retry fixes it: the archive was
    // pruned off local disk before anything copied it anywhere. Those backups
    // are simply gone, and saying so is the point.
    if r.missing_locally > 0 {
        log.push_str(&format!(
            "GONE:       {} backup(s) had no local archive left to send — \
             they were pruned before ever being copied off-site\n",
            r.missing_locally
        ));
    }
    if r.considered >= BACKFILL_BATCH {
        log.push_str("There are more waiting than one run copies — run it again to continue.\n");
    }
    if !r.note.is_empty() {
        log.push_str(&format!("{}\n", r.note));
    }
    log
}

/// `(ok, error)` for the whole job. Green only when EVERY node ran and none
/// failed a push. A node that did not run is named first — "the estate is
/// off-site now" must not be read over a node nobody looked at. A copy kept
/// with "delete local" asked for is not a failure of the sweep, but it is not
/// done either, so it is not shown green over copies still on disk.
fn backfill_job_verdict(turns: &[BackfillTurn], drop_local: bool) -> (bool, Option<String>) {
    let not_run: Vec<&str> = turns
        .iter()
        .filter(|(_, o)| o.is_err())
        .map(|(l, _)| l.as_str())
        .collect();
    if !not_run.is_empty() {
        return (
            false,
            Some(format!(
                "not run on {} — those backups were not looked at",
                not_run.join(", ")
            )),
        );
    }
    let ok_turns = || {
        turns
            .iter()
            .filter_map(|(l, o)| o.as_ref().ok().map(|r| (l, r)))
    };
    let failed: i64 = ok_turns().map(|(_, r)| r.failed).sum();
    let kept: Vec<String> = ok_turns()
        .filter(|(_, r)| drop_local && r.kept_local > 0)
        .map(|(l, r)| {
            format!(
                "{} local cop{} on {l}",
                r.kept_local,
                if r.kept_local == 1 { "y" } else { "ies" }
            )
        })
        .collect();
    if !kept.is_empty() {
        return (
            false,
            Some(format!(
                "{} kept — not confirmed off-site; each site's Backups tab says why",
                kept.join(", ")
            )),
        );
    }
    let notes: Vec<String> = ok_turns()
        .filter(|(_, r)| !r.note.is_empty())
        .map(|(l, r)| format!("{l}: {}", r.note))
        .collect();
    if !notes.is_empty() {
        return (false, Some(notes.join(" · ")));
    }
    (failed == 0, None)
}

/// The card a save of `[section]` returns to when the form did not name one
/// (`_return_tab`). Every value is a card in [`chrome::CARDS`].
fn section_to_tab(section: &str) -> &'static str {
    match section {
        "email" => "smtp-relay",
        "acme" => "acme",
        "update" => "updates",
        "slack" => "slack",
        // [notifications] is written by Alert wording and by the customer
        // letters; [letters] by the letter editor, the language cards and
        // the sentence list. Each form sends `_return_tab`; these are only
        // the fallbacks.
        "notifications" => "alert-templates",
        "letters" => "letter-wording",
        "performance" => "performance",
        "protection" => "protection-mode",
        "backup_remote" => "offsite-ftp",
        "backup" => "local-copies",
        "backup_retention" => "backup-retention",
        "snapshots" => "snapshot-retention",
        "fail2ban" => "bruteforce-scanner",
        // [cluster] is written from five pages and every form says which
        // card it is; the fallback is a card every install has.
        "cluster" => "panel-domain",
        _ => "panel-domain",
    }
}

/// Sanitise an operator-supplied `_return_tab` hint: only a card id from
/// [`chrome::CARDS`] is honoured, so a malicious or mistyped value cannot
/// poison the redirect URL.
fn sanitize_return_tab(v: &str) -> Option<&'static str> {
    let v = v.trim();
    chrome::CARDS
        .iter()
        .find(|(card, _)| *card == v)
        .map(|(card, _)| *card)
}

#[derive(Deserialize)]
pub struct PanelProvisionForm {
    /// FQDN the operator wants the panel reachable at, e.g.
    /// `panel.example.com`. Server-side validation (in the RPC
    /// `panel_provision` impl) trims, lowercases, rejects bare
    /// IPs, refuses anything with a path / port / scheme.
    pub hostname: String,
    /// Skip the DNS A/AAAA preflight. Use when the operator KNOWS
    /// the record has propagated but our resolver hasn't caught
    /// up yet (TTL > 0 cache, recently-changed authoritative).
    #[serde(default)]
    pub skip_dns_check: Option<String>,
    pub _csrf: String,
}

/// GET /settings/panel-cert-status — tiny HTML fragment for the
/// HTMX poll loop on /settings/panel#panel-domain. The progress card polls
/// every 2 s while stage is "issuing" / "self-signed", and stops
/// polling once it lands on "issued" / "failed". Output: a
/// single <div> whose contents the page swaps in place.
pub async fn get_panel_cert_status(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Panel-cert issuance progress is admin chrome (polled from /settings).
    if !ctx.can(Capability::SettingsManage) {
        return Err(AppError::Forbidden);
    }
    let snap = match hyperion_rpc_client::call(&state.agent_socket, Request::PanelCertStatus).await
    {
        Ok(RpcResponse::PanelCertStatus(v)) => v,
        _ => None,
    };
    let body = match snap {
        // Nothing in flight since the agent started: say what the config
        // does tell us rather than a bare "nothing in progress".
        None => {
            let host = match hyperion_rpc_client::call(
                &state.agent_socket,
                Request::AgentConfigView,
            )
            .await
            {
                Ok(RpcResponse::AgentConfigView(c)) => Some(c.cluster.panel_hostname),
                _ => None,
            };
            let text = match host.as_deref().map(str::trim) {
                Some("") => "No domain is set, so the panel serves its own self-signed \
                             certificate."
                    .to_string(),
                Some(h) => format!(
                    "No certificate request for {} is running now. Its certificate renews \
                     on its own; saving the domain again requests a new one.",
                    html_escape(h)
                ),
                None => "No certificate request is running now.".to_string(),
            };
            format!("<div class=\"text-soft small\" style=\"padding:0.4rem 0\">{text}</div>")
        }
        Some(p) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let elapsed = (now - p.started_at).max(0);
            // Stage-driven visual: pill colour + progress bar +
            // whether HTMX keeps polling.
            let (pill_class, pill_text, bar_pct, bar_color, keep_polling) = match p.stage.as_str() {
                "self-signed" => ("warn", "self-signed", 10, "var(--warn)", true),
                "issuing" => (
                    "warn",
                    "issuing…",
                    50 + ((elapsed % 30) * 50 / 30).min(40),
                    "var(--info)",
                    true,
                ),
                "issued" => ("ok", "trusted certificate", 100, "var(--success)", false),
                "failed" => ("err", "failed", 100, "var(--danger)", false),
                _ => ("", p.stage.as_str(), 0, "var(--surface-2)", false),
            };
            let trigger_attrs = if keep_polling {
                "hx-get=\"/settings/panel-cert-status\" hx-trigger=\"every 2s\" hx-swap=\"innerHTML\" hx-target=\"this\""
            } else {
                ""
            };
            let elapsed_str = if elapsed < 60 {
                format!("{}s", elapsed)
            } else {
                format!("{}m {}s", elapsed / 60, elapsed % 60)
            };
            format!(
                "<div {trigger}><div style=\"display:flex;align-items:center;gap:0.6rem;flex-wrap:wrap;margin-bottom:0.5rem\">\
                   <span class=\"pill {pill}\">{txt}</span>\
                   <span class=\"text-soft small\">{host}</span>\
                   <span class=\"text-soft small\">· elapsed {elapsed}</span>\
                 </div>\
                 <div style=\"height:6px;border-radius:3px;background:var(--surface-2);overflow:hidden;margin-bottom:0.5rem\">\
                   <div style=\"width:{pct}%;height:100%;background:{color};transition:width 0.4s ease\"></div>\
                 </div>\
                 <div class=\"text-soft small\" style=\"line-height:1.5\">{msg}</div></div>",
                trigger = trigger_attrs,
                pill = pill_class,
                txt = pill_text,
                host = html_escape(&p.hostname),
                elapsed = elapsed_str,
                pct = bar_pct,
                color = bar_color,
                msg = html_escape(&p.message),
            )
        }
    };
    Ok(([("content-type", "text/html; charset=utf-8")], body).into_response())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// POST /settings/panel-provision — super_admin only. Binds the
/// Hyperion control panel to a public hostname:
///
///   1. Validates hostname + DNS resolves to this box (unless
///      `skip_dns_check` is on).
///   2. Persists `cluster.panel_hostname` to agent.toml.
///   3. Writes the panel's nginx vhost
///      (`/etc/nginx/sites-enabled/hyperion-panel.conf`) with a
///      self-signed cert so nginx will start even before ACME.
///   4. Reloads nginx.
///   5. Triggers a background ACME issuance via Let's Encrypt.
///      Status `ok-cert-pending` means steps 1–4 succeeded and the
///      cert will land within ~30s; flip the page or check
///      /services for the new vhost.
///
/// Redirects back to /settings/panel#panel-domain with a flash message
/// containing the agent's reply (status + panel URL).
pub async fn post_panel_provision(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PanelProvisionForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(
            Redirect::to("/settings/panel?flash_error=owner+role+required#panel-domain")
                .into_response(),
        );
    }
    let hostname = form.hostname.trim().to_lowercase();
    if hostname.is_empty() {
        return Ok(Redirect::to(
            "/settings/panel?flash_error=Panel+hostname+is+required#panel-domain",
        )
        .into_response());
    }
    let skip_dns_check = matches!(
        form.skip_dns_check.as_deref(),
        Some("on" | "true" | "1" | "yes")
    );
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::PanelProvision {
            hostname: hostname.clone(),
            skip_dns_check,
        },
    )
    .await
    .map_err(AppError::from)?;
    let dest = match resp {
        RpcResponse::PanelProvision {
            status,
            message,
            panel_url,
        } => {
            // Build a friendly one-liner flash. Truncate the agent's
            // multi-line `message` to its first non-empty line so the
            // URL query stays readable — full message lands in the
            // agent's structured logs anyway.
            let first_line = message
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .to_string();
            let key = match status.as_str() {
                "ok" | "ok-cert-pending" => "flash",
                _ => "flash_error",
            };
            let url_hint = if panel_url.is_empty() {
                String::new()
            } else {
                format!(" — {}", panel_url)
            };
            let summary = format!("{status}: {first_line}{url_hint}");
            format!("/settings/panel?{key}={}#panel-domain", urlencode(&summary))
        }
        RpcResponse::Error(e) => format!(
            "/settings/panel?flash_error={}#panel-domain",
            urlencode(&e.to_string())
        ),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}

/// POST /api/email-autodetect
///
/// Probes the local box for a usable SMTP relay so the operator can
/// click "Auto-detect" on the Settings page instead of guessing
/// host/port/security. Behind require_auth (the protected router)
/// — viewers can run it too since it's read-only.
pub async fn post_email_autodetect(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Viewers shouldn't be able to fingerprint local SMTP via this
    // endpoint — the probe is operator-config only.
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Json(SmtpAutodetect {
            found: false,
            smtp_host: String::new(),
            smtp_port: 0,
            security: String::new(),
            suggested_from: String::new(),
            notes: "admin role required to probe SMTP".into(),
        })
        .into_response());
    }
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::EmailSmtpAutodetect).await?;
    let a = match resp {
        RpcResponse::EmailSmtpAutodetect(a) => a,
        RpcResponse::Error(e) => {
            return Ok(Json(SmtpAutodetect {
                found: false,
                smtp_host: String::new(),
                smtp_port: 0,
                security: String::new(),
                suggested_from: String::new(),
                notes: format!("agent error: {e}"),
            })
            .into_response());
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Json(a).into_response())
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

/// Resolve the effective source IP for the email-test rate limit
/// bucket. Same precedence as the /api/enroll handler: forwarded-for
/// → real-ip → peer socket.
pub(crate) fn email_test_ip(headers: &HeaderMap, peer: SocketAddr) -> std::net::IpAddr {
    // Only a request that came through the panel's own nginx (loopback peer)
    // may name its client, and only through X-Real-IP, which that nginx SETS
    // to `$remote_addr`. X-Forwarded-For was read first before: its first
    // entry is whatever the client sent, so every request could pick a fresh
    // bucket and the per-address limit on test sends never held.
    if peer.ip().is_loopback() {
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

/// Resolve a Mail-tab `target_node` value into a dispatch target + the
/// redirect query suffix that keeps the operator on that node's Mail view.
/// "" / "local" → master (local socket, no suffix).
fn mail_node_target(raw: &str) -> (Option<String>, String) {
    let t = raw.trim();
    if t.is_empty() || t == "local" {
        (None, String::new())
    } else {
        (Some(t.to_string()), format!("&node={}", urlencode(t)))
    }
}

// The postfix actions (queue retry / discard, reconfigure, sendmail test)
// moved to `handlers::mail_health`, beside the Mail delivery diagnostics on
// Service health.

// ── Node-level preview wildcard certs ─────────────────────────────────
//
// Every site gets a `<name>.<base>` preview address (and a test node
// auto-creates such subdomains); rather than a per-site ACME cert each
// time, the operator issues ONE `*.<base>` wildcard per node and every
// one of them reuses it. DNS-01 shows the TXT
// records on an interstitial for the operator to publish — the server
// holds no DNS credentials. The cert lives on the chosen node
// (shared-nothing), so the flow is dispatched there.

#[derive(Template)]
#[template(path = "node_wildcard_dns01.html")]
struct NodeWildcardDns01Tpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    node_id: String,
    base: String,
    records: Vec<(String, String)>,
    records_field: String,
    csrf_finish: String,
    /// Set when a validation was refused because the records aren't on the
    /// authoritative nameservers yet.
    error: Option<String>,
}

/// Resolve a node's preview-wildcard base domain (+ display label).
/// `None` when no safe base can be derived from the template.
///
/// Deliberately NOT gated on test-node marking. Preview vhosts were never
/// a test-node feature — the agent renders them for every site once the
/// template and the wildcard cert exist — but this gate made the ONLY
/// path to issuing that cert require the marking. On a single-server
/// install (no workers enrolled) the node list was empty, so the whole
/// preview feature was unreachable; and marking a production server as
/// "test" to get at it would make the create wizard refuse production
/// domains there. The master is addressed by the `local` sentinel, which
/// the dispatcher already normalises.
async fn resolve_node_wildcard_base(
    state: &SharedState,
    node_id: &str,
) -> Option<(String, String)> {
    let config = match crate::dispatcher::cached_agent_config(state)
        .await
        .map(|c| hyperion_rpc::codec::Response::AgentConfigView((*c).clone()))
    {
        Ok(RpcResponse::AgentConfigView(c)) => c,
        _ => return None,
    };
    let is_local = node_id.trim().is_empty()
        || node_id == crate::dispatcher::LOCAL_NODE_SENTINEL
        || node_id == config.hostname;
    let label = if is_local {
        config.hostname.clone()
    } else {
        match crate::dispatcher::cached_nodes(state)
            .await
            .map(hyperion_rpc::codec::Response::NodesList)
        {
            Ok(RpcResponse::NodesList(ns)) => ns
                .into_iter()
                .find(|n| n.node_id == node_id)
                .map(|n| n.label)
                // An unknown node id must not fall back to "some string
                // that derives a base anyway" — refuse instead.
                .unwrap_or_default(),
            _ => String::new(),
        }
    };
    if !is_local && label.is_empty() {
        return None;
    }
    // The master's id in a template is its hostname — what its agent and
    // the HTTPS page's row both use — never the `local` sentinel the form
    // posts, or a `{node_id}` template would issue for a different base
    // than the row shows.
    let template_id = if is_local {
        config.hostname.as_str()
    } else {
        node_id
    };
    config
        .cluster
        .node_wildcard_base(template_id, &label)
        .map(|base| (label, base))
}

#[derive(Deserialize)]
pub struct NodeWildcardBeginForm {
    pub node_id: String,
    #[serde(default)]
    pub staging: Option<String>,
}

/// POST /settings/node-wildcard/begin — issue (or renew) a node's preview
/// `*.<base>` wildcard via the domain-only DNS-01 flow on that node.
pub async fn post_node_wildcard_begin(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeWildcardBeginForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(chrome::back_with_error(
            "preview-wildcard",
            "Only an Owner can issue preview certificates.",
        ));
    }
    let (label, base) = match resolve_node_wildcard_base(&state, &form.node_id).await {
        Some(v) => v,
        None => {
            return Ok(chrome::back_with_error(
                "preview-wildcard",
                "This node has no preview base yet — set the preview address first.",
            ));
        }
    };
    let domain = match hyperion_validate::Domain::parse(&base) {
        Ok(d) => d,
        Err(e) => {
            return Ok(chrome::back_with_error(
                "preview-wildcard",
                &format!("The preview address gives {base}, which is not a valid domain: {e}"),
            ));
        }
    };
    let staging = form.staging.as_deref() == Some("on");
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        Some(&form.node_id),
        Request::CertDns01BeginDomain {
            domain,
            email: None,
            staging,
        },
    )
    .await?;
    match resp {
        RpcResponse::CertDns01BeginDomain {
            completed: true, ..
        } => Ok(chrome::back_with_flash(
            "preview-wildcard",
            &format!("Preview certificate *.{base} issued on {label}."),
        )),
        RpcResponse::CertDns01BeginDomain {
            completed: false,
            records,
        } => {
            let tpl = NodeWildcardDns01Tpl {
                username: &ctx.username,
                user_initial: super::user_initial(&ctx.username),
                active: "settings",
                css_version: super::css_version(),
                htmx_version: super::htmx_version(),
                node_id: form.node_id.clone(),
                base,
                records_field: super::dns01_records_field(&records),
                records,
                csrf_finish: super::session_csrf_token(&state, &ctx),
                error: None,
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => Ok(chrome::back_with_error("preview-wildcard", &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct NodeWildcardFinishForm {
    pub node_id: String,
    pub base: String,
    /// The records the page showed (see `dns01_records_field`).
    #[serde(default)]
    pub records: String,
}

/// POST /settings/node-wildcard/finish — validate the published TXT,
/// install the wildcard on the node, then re-point its auto-subdomains.
pub async fn post_node_wildcard_finish(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeWildcardFinishForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(chrome::back_with_error(
            "preview-wildcard",
            "Only an Owner can issue preview certificates.",
        ));
    }
    let domain = match hyperion_validate::Domain::parse(form.base.trim()) {
        Ok(d) => d,
        Err(e) => {
            return Ok(chrome::back_with_error(
                "preview-wildcard",
                &format!("{} is not a valid domain: {e}", form.base.trim()),
            ));
        }
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        Some(&form.node_id),
        Request::CertDns01FinishDomain { domain },
    )
    .await?;
    let records = super::parse_dns01_records_field(&form.records);
    match resp {
        // Nothing was sent to Let's Encrypt: same order, same values —
        // stay on the records page rather than start a new order.
        RpcResponse::Error(e)
            if super::is_dns01_not_ready(&e.to_string()) && !records.is_empty() =>
        {
            let tpl = NodeWildcardDns01Tpl {
                username: &ctx.username,
                user_initial: super::user_initial(&ctx.username),
                active: "settings",
                css_version: super::css_version(),
                htmx_version: super::htmx_version(),
                node_id: form.node_id.clone(),
                base: form.base.trim().to_string(),
                records_field: super::dns01_records_field(&records),
                records,
                csrf_finish: super::session_csrf_token(&state, &ctx),
                error: Some(e.to_string()),
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::CertDns01FinishDomain(_) => Ok(chrome::back_with_flash(
            "preview-wildcard",
            &format!("Preview certificate *.{} issued.", form.base.trim()),
        )),
        RpcResponse::Error(e) => Ok(chrome::back_with_error("preview-wildcard", &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// What to store for catalogue string `id` when the operator submits `value`:
/// LF line endings, and EMPTY when it is the pack's own wording for `lang`.
///
/// A sentence submitted EXACTLY as the pack writes it is not an override, and
/// storing it would fork that sentence: every later improvement to the
/// built-in wording would stop reaching this install, with nothing in the UI
/// to say so. "Fill empty fields with the built-in wording" and "Start from
/// the built-in" put the pack's text into the form so an operator can EDIT a
/// sentence instead of retyping it; pressing one and saving, which is the
/// obvious thing to do, would otherwise fork every sentence in one click.
///
/// CLEARED, not dropped: typing the pack's own wording means "I want what the
/// pack says", the same act as emptying the field, so it must also remove an
/// override that is already there.
///
/// NORMALISED FIRST. A <textarea> submits CRLF per the HTML spec and the pack
/// holds LF, so without it the comparison was always false for every
/// multi-line sentence. Storing LF is right regardless: a CRLF that survived
/// would reach a plain-text mail body.
pub(super) fn letter_value_to_store(
    id: &str,
    value: &str,
    lang: hyperion_core::letters::LetterLang,
) -> String {
    let value = if value.contains('\r') {
        value.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        value.to_string()
    };
    match hyperion_core::letters::lookup(id) {
        Some(s) if value == s.built_in(lang) => String::new(),
        _ => value,
    }
}

/// The letter language + overrides exactly as the mailer reads them.
///
/// Read from the same file rather than passed around, because the export and
/// the import are separate requests and a stale copy would let an operator
/// export one thing and import against another.
async fn current_letter_catalogue() -> hyperion_core::letters::LetterCatalog {
    tokio::fs::read_to_string("/etc/hyperion/agent.toml")
        .await
        .ok()
        .as_deref()
        .map(hyperion_core::service::letter_catalog_from_toml)
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// Bulk export / import of the letter wording
//
// The per-string editor is fine for changing one sentence and miserable for
// going through all of them: the built-in text is the field's PLACEHOLDER, not
// its value, so an operator who wants to reword something has to retype it from
// scratch — they cannot select it, cannot copy it, and cannot see two sentences
// side by side to keep the tone consistent.
//
// So: one file out, one file in. The format is the same `[letters]` TOML the
// overrides are already STORED in, which means the export doubles as a backup
// and can be pasted straight into agent.toml by anyone who prefers that.
// ─────────────────────────────────────────────────────────────────────────────

/// Collect every string leaf of a TOML table as a DOTTED id.
///
/// 111 of the 125 ids contain a dot, and in TOML a bare `care.subject = "x"` is
/// a nested table rather than a key of that name. An operator hand-editing the
/// file will write it both ways — the download quotes them, a snippet typed
/// from memory usually does not — and a paste that is silently discarded is the
/// worst outcome available: the flash says it worked and the next letter goes
/// out with the old wording. So both spellings are accepted and mean the same
/// thing, which is what the operator meant either way.
fn flatten_toml_strings(t: &dyn toml_edit::TableLike, prefix: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in t.iter() {
        let id = if prefix.is_empty() {
            k.to_string()
        } else {
            format!("{prefix}.{k}")
        };
        if let Some(text) = v.as_str() {
            out.push((id, text.to_string()));
        } else if let Some(sub) = v.as_table_like() {
            out.extend(flatten_toml_strings(sub, &id));
        }
    }
    out
}

/// Render an id as a TOML key.
///
/// Most ids contain a dot (`care.subject`), and a bare dotted key in TOML means
/// a NESTED TABLE, not a key of that name — `care.subject = "x"` parses as
/// `care = { subject = "x" }`, so the import would find no such string and
/// silently keep the old wording. The agent's own writer quotes these because
/// `toml_edit` does it automatically; this export builds the text by hand and
/// has to do it itself.
fn toml_key(id: &str) -> String {
    if !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        id.to_string()
    } else {
        format!("\"{}\"", id.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Escape a string as a TOML basic string, or emit a multi-line literal.
///
/// Letter bodies contain newlines and `{placeholders}`; both have to survive a
/// round trip unchanged, because a mangled placeholder reaches a customer.
fn toml_value(s: &str) -> String {
    if s.contains('\n') {
        // Multi-line basic string. `"""` inside the text would end it early,
        // and a trailing quote would glue onto the terminator — neither
        // appears in the pack today, but the export must not depend on that.
        let body = s.replace('\\', "\\\\").replace("\"\"\"", "\\\"\\\"\\\"");
        let body = if body.ends_with('"') {
            format!("{}\\\"", &body[..body.len() - 1])
        } else {
            body
        };
        format!("\"\"\"\n{body}\"\"\"")
    } else {
        let esc = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\t', "\\t")
            .replace('\r', "\\r");
        format!("\"{esc}\"")
    }
}

/// `GET /settings/letters.toml` — every sentence, with its current text.
///
/// The value written for each id is what the letter says TODAY: the operator's
/// override where one exists, otherwise the built-in wording for the chosen
/// language. That is the whole point — the file is something to edit, not a
/// list of blanks to fill in.
pub async fn get_letters_export(
    // Not read: the catalogue comes from agent.toml directly, so the export and
    // the import cannot disagree about what is stored. Kept so the handler
    // keeps the shape every other one here has.
    State(_state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // The same gate every other write to agent.toml uses. `post_config` is
    // super_admin, and this reads and replaces the very same section — a
    // lower bar here would be a way around it.
    if !ctx.is_super_admin() {
        return Ok((axum::http::StatusCode::FORBIDDEN, "super admin only\n").into_response());
    }
    let cat = current_letter_catalogue().await;
    let lang = match cat.lang {
        hyperion_core::letters::LetterLang::Cs => "cs",
        _ => "en",
    };

    let mut out = String::new();
    out.push_str(&format!(
        "# Hyperion letter wording — every sentence Hyperion writes that leaves\n\
         # the building: the customer's care report and expiry warning, the\n\
         # operator alerts, the Slack messages and the disk-quota letters.\n\
         #\n\
         # Language pack in use: {lang}\n\
         #\n\
         # Edit the values, then paste the whole file back into Settings →\n\
         # Customer letters → Sentences → \"Replace the wording from a file\".\n\
         # A value left EXACTLY as the built-in wording is not stored as an\n\
         # override, so future improvements to that sentence still reach you;\n\
         # change one character and it becomes yours and stops tracking.\n\
         #\n\
         # Words in {{braces}} are values the server fills in. Keep them spelled\n\
         # exactly as they are — a brace you mistype is left in the letter\n\
         # verbatim rather than dropped, so a customer would see it.\n\
         \n[letters]\nlang = \"{lang}\"\n"
    ));

    for g in hyperion_core::letters::groups() {
        out.push_str(&format!("\n# ── {g} ──\n"));
        for s in hyperion_core::letters::STRINGS
            .iter()
            .filter(|s| s.group == g)
        {
            // An empty override is not an override: `LetterCatalog::get`
            // falls back to the pack for one, and so must this. Reading the map
            // directly exported a BLANK for every string once the per-string
            // form had been saved with its fields empty — which is what saving
            // it without touching anything does.
            let own = cat.overrides.get(s.id).filter(|v| !v.trim().is_empty());
            let effective = own
                .cloned()
                .unwrap_or_else(|| s.built_in(cat.lang).to_string());
            let overridden = own.is_some();
            out.push_str(&format!(
                "\n# {}{}\n{} = {}\n",
                s.note,
                if overridden { "  [your wording]" } else { "" },
                toml_key(s.id),
                toml_value(&effective)
            ));
        }
    }

    Ok((
        axum::http::StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"hyperion-letters.toml\"",
            ),
        ],
        out,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct LettersImportForm {
    #[serde(default)]
    pub _csrf: String,
    pub toml: String,
}

/// `POST /settings/letters/import` — replace the wording from a pasted file.
///
/// Everything the file does not mention is left alone; an id it mentions with
/// the built-in wording has its override REMOVED rather than stored, so the
/// operator's file stays a diff against the pack instead of forking it.
pub async fn post_letters_import(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<LettersImportForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to(
            "/settings/letters?flash_error=super+admin+required#letter-wording",
        )
        .into_response());
    }
    let doc: toml_edit::DocumentMut = match form.toml.parse() {
        Ok(d) => d,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/settings/letters?flash_error={}#letter-wording",
                urlencode(&format!("that is not valid TOML: {e}"))
            ))
            .into_response())
        }
    };
    // Accept the file with or without its `[letters]` header, because an
    // operator who edits only a handful of lines will paste only those.
    let root = doc
        .get("letters")
        .and_then(|t| t.as_table_like())
        .map(|t| flatten_toml_strings(t, ""))
        .unwrap_or_else(|| flatten_toml_strings(doc.as_table(), ""));
    let table = root;

    let cat = current_letter_catalogue().await;

    // Which pack the operator was editing AGAINST decides what counts as
    // "unchanged", and the file says so. Reading the stored language instead
    // would compare Czech text to English built-ins the moment someone
    // translates by exporting, switching `lang`, and pasting back — every one
    // of the 125 sentences would differ, so every one would be stored as an
    // override, and the whole catalogue would silently stop tracking the pack.
    // Whatever the rest of the product accepts. `LetterLang::parse` trims,
    // lowercases and takes cs/cz/cesky/česky — so demanding the exact bytes
    // "en" or "cs" here would drop a `lang = "CS"` line silently, and dropping
    // it also flips the fork guard below to compare against one pack instead of
    // two. `LetterLang::parse` is the right accepter for the ALIASES an operator
    // may reasonably type ("CS", "cz", "česky") — but it answers English for
    // anything it does not know, which is the correct fallback for a config file
    // already on disk and the WRONG answer for a file being imported: `lang =
    // "sk"` is a plausible mistake, and coercing it would switch every letter to
    // English without saying so. So the value is checked against the aliases
    // first and named back when it is none of them.
    let mut lang: Option<String> = None;
    let mut bad_lang: Option<String> = None;
    for (id, value) in &table {
        if id != "lang" || value.trim().is_empty() {
            continue;
        }
        let v = value.trim().to_lowercase();
        let known = matches!(
            v.as_str(),
            "en" | "eng" | "english" | "cs" | "cz" | "cesky" | "česky"
        );
        if !known {
            bad_lang = Some(value.trim().to_string());
            continue;
        }
        lang = Some(match hyperion_core::letters::LetterLang::parse(value) {
            hyperion_core::letters::LetterLang::Cs => "cs".to_string(),
            _ => "en".to_string(),
        });
    }
    if let Some(bad) = bad_lang {
        return Ok(Redirect::to(&format!(
            "/settings/letters?flash_error={}#letter-wording",
            urlencode(&format!(
                "lang = \"{bad}\" is not a language this version has — the packs are \
                 English (en) and Czech (cs). Nothing was changed."
            ))
        ))
        .into_response());
    }
    // "Unchanged" is judged against BOTH packs, not one.
    //
    // Against the stored pack only: export in English, set lang = "cs", paste —
    // every Czech sentence differs from its English built-in, so all 125 become
    // overrides and the catalogue silently stops tracking the pack for ever.
    //
    // Against the file's pack only: the same operator who switches lang but has
    // not translated anything yet pastes 125 ENGLISH values against the Czech
    // pack — same fork, and worse, the overrides then win, so the language
    // switch they just asked for does nothing.
    //
    // Either pack's own wording means "I did not change this sentence", which
    // is the question actually being asked.
    let file_lang = lang
        .as_deref()
        .map(hyperion_core::letters::LetterLang::parse);
    let packs: Vec<hyperion_core::letters::LetterLang> = match file_lang {
        Some(l) if l != cat.lang => vec![l, cat.lang],
        _ => vec![cat.lang],
    };

    let mut fields: std::collections::BTreeMap<String, String> = Default::default();
    let mut unknown: Vec<String> = Vec::new();
    let mut kept = 0usize;

    for (id, value) in table {
        if id == "lang" {
            continue;
        }
        let Some(s) = hyperion_core::letters::STRINGS.iter().find(|s| s.id == id) else {
            // An id this build does not have. Named rather than dropped: it is
            // usually a typo or a file from a newer version, and silently
            // ignoring it would leave the operator believing they had changed
            // something they had not.
            unknown.push(id);
            continue;
        };
        // Identical to the pack? Then it is NOT an override. Storing it would
        // fork that sentence: every later improvement to the built-in wording
        // would stop reaching this install, invisibly.
        // Same normalisation as the save path: a file edited on Windows, or
        // pasted through a textarea, carries CRLF that the pack does not.
        let value = if value.contains('\r') {
            value.replace("\r\n", "\n").replace('\r', "\n")
        } else {
            value
        };
        if packs.iter().any(|&l| value == s.built_in(l)) {
            fields.insert(id, String::new());
        } else {
            fields.insert(id, value);
            kept += 1;
        }
    }

    if let Some(l) = lang {
        fields.insert("lang".into(), l);
    }
    if fields.is_empty() {
        // Name what was NOT recognised rather than calling the file empty. An
        // operator whose ids are all mistyped — a stale file, a hand-edited
        // key — would otherwise be told their work contained nothing, which is
        // the "absent vs lost" confusion this project refuses everywhere else.
        let msg = if unknown.is_empty() {
            "that file contained no letter strings".to_string()
        } else {
            format!(
                "none of the {} id(s) in that file are known to this version, so \
                 nothing was changed: {}",
                unknown.len(),
                unknown
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        return Ok(Redirect::to(&format!(
            "/settings/letters?flash_error={}#letter-wording",
            urlencode(&msg)
        ))
        .into_response());
    }

    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AgentConfigUpdate {
            section: "letters".into(),
            fields: fields.clone().into(),
        },
    )
    .await
    .map_err(AppError::from)?;
    if let RpcResponse::Error(e) = resp {
        return Ok(Redirect::to(&format!(
            "/settings/letters?flash_error={}#letter-wording",
            urlencode(&e.to_string())
        ))
        .into_response());
    }
    // Letters render on the node that OWNS each hosting, so the master's
    // write is not the job finished: the settings sync carries it to every
    // node (kicked now rather than on its next pass), and nodes it cannot
    // update get it pushed directly. A push failure is said in the flash —
    // the operator would otherwise believe their customers get the new
    // wording when some nodes still send the old one.
    state.cluster_sync.kick();
    let propagation = push_to_unsynced_nodes(&state, "letters", fields.clone()).await;

    let mut msg = format!("{kept} sentence(s) now use your wording");
    if let Err(problems) = &propagation {
        msg.push_str(&format!(
            "; but {} node(s) did NOT get it and are still sending the old \
             wording: {}",
            problems.len(),
            problems.join("; ")
        ));
    }
    if !unknown.is_empty() {
        msg.push_str(&format!(
            "; {} id(s) were not recognised and were ignored: {}",
            unknown.len(),
            unknown
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(Redirect::to(&format!(
        "/settings/letters?flash={}#letter-wording",
        urlencode(&msg)
    ))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::{flatten_toml_strings, synthesize_unchecked_checkboxes, toml_key, toml_value};

    /// Each node's backups live on that node, so the sweep runs once per
    /// node and the job log says which node did what — a node that could
    /// not be reached must read as "not done", never as "nothing to copy".
    #[test]
    fn offsite_backfill_reports_every_node_and_fails_on_an_unreached_one() {
        use super::{backfill_job_verdict, backfill_node_block};
        let clean = hyperion_types::OffsiteBackfillResult {
            considered: 3,
            pushed: 3,
            ..Default::default()
        };
        let turns = vec![
            ("master".to_string(), Ok(clean.clone())),
            (
                "s5".to_string(),
                Err("node s5 unreachable: TCP connect refused".to_string()),
            ),
        ];
        let block = backfill_node_block(&turns[0].0, &turns[0].1, false);
        assert!(block.contains("master"), "{block}");
        assert!(block.contains("pushed:     3"), "{block}");
        let block = backfill_node_block(&turns[1].0, &turns[1].1, false);
        assert!(block.contains("s5"), "{block}");
        assert!(block.contains("NOT RUN"), "{block}");
        let (ok, err) = backfill_job_verdict(&turns, false);
        assert!(!ok);
        assert!(err.as_deref().unwrap_or("").contains("s5"), "{err:?}");

        // Every node answered, nothing failed → green.
        let all_ok = vec![
            ("master".to_string(), Ok(clean.clone())),
            ("s5".to_string(), Ok(clean.clone())),
        ];
        assert_eq!(backfill_job_verdict(&all_ok, false), (true, None));

        // A copy kept with "delete local" asked for is not done either, and
        // the message names the node holding it.
        let kept = hyperion_types::OffsiteBackfillResult {
            kept_local: 2,
            ..clean.clone()
        };
        let turns = vec![
            ("master".to_string(), Ok(clean)),
            ("s5".to_string(), Ok(kept)),
        ];
        let (ok, err) = backfill_job_verdict(&turns, true);
        assert!(!ok);
        assert!(err.as_deref().unwrap_or("").contains("s5"), "{err:?}");
    }

    /// `delete()` runs on the node that OWNS the hosting and reads that
    /// node's own `[cluster] trash_enabled`, so trash saved on the master
    /// alone left every worker delete permanent.
    #[test]
    fn trash_settings_reach_the_workers_but_no_other_cluster_key_does() {
        use super::fields_for_workers;
        let m = |pairs: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let got = fields_for_workers(
            "cluster",
            &m(&[("trash_enabled", "true"), ("trash_retention_days", "14")]),
        )
        .expect("trash card propagates");
        assert_eq!(got.0, "cluster");
        assert_eq!(
            got.1,
            m(&[("trash_enabled", "true"), ("trash_retention_days", "14")])
        );
        // The other [cluster] cards are master-only (sign-in, placement,
        // hardening…): pushing them would rewrite worker config.
        assert!(fields_for_workers("cluster", &m(&[("require_2fa", "true")])).is_none());
        // A mixed bag sends the trash keys ONLY.
        let got = fields_for_workers(
            "cluster",
            &m(&[("trash_enabled", "false"), ("require_2fa", "true")]),
        )
        .expect("trash key present");
        assert_eq!(got.1, m(&[("trash_enabled", "false")]));
        // The sections that already propagated still do, whole.
        let f = m(&[("drop_local_after_offsite", "true")]);
        assert_eq!(fields_for_workers("backup", &f), Some(("backup".into(), f)));
        assert!(fields_for_workers("acme", &m(&[("contact_email", "a@b.cz")])).is_none());
        // The preview template too: each node's nginx reads its own copy.
        let got = fields_for_workers(
            "cluster",
            &m(&[("test_domain_template", "{name}.p.example.com")]),
        )
        .expect("preview template propagates");
        assert_eq!(
            got.1,
            m(&[("test_domain_template", "{name}.p.example.com")])
        );
        // Every key pushed is one the sync carries too, and vice versa for
        // [cluster] — the two paths must agree.
        for k in super::CLUSTER_KEYS_FOR_WORKERS {
            assert!(
                hyperion_core::cluster_sync::is_synced_key("cluster", k),
                "{k}"
            );
        }
    }

    /// A node from before `keep_local_latest` gets the [backup] save without
    /// it only when that cannot change what the node does.
    #[test]
    fn backup_fields_for_old_node_strips_only_when_harmless() {
        use super::{backup_fields_for_old_node, backup_keep_unknown_to_old_node};
        let m = |pairs: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert!(backup_keep_unknown_to_old_node(
            "backup",
            "validation: field `keep_local_latest` is not editable in section `backup`"
        ));
        assert!(!backup_keep_unknown_to_old_node("backup", "something else"));
        assert!(!backup_keep_unknown_to_old_node(
            "snapshots",
            "keep_local_latest"
        ));

        // keep 0 = what the old node does anyway → strip.
        let f = backup_fields_for_old_node(&m(&[
            ("drop_local_after_offsite", "true"),
            ("keep_local_latest", "0"),
        ]))
        .expect("harmless");
        assert_eq!(f, m(&[("drop_local_after_offsite", "true")]));
        // Switching dropping OFF must reach it whatever the count says.
        assert!(backup_fields_for_old_node(&m(&[
            ("drop_local_after_offsite", "false"),
            ("keep_local_latest", "3"),
        ]))
        .is_some());
        // Dropping on with a keep count: stripping would drop the kept copies.
        assert!(backup_fields_for_old_node(&m(&[
            ("drop_local_after_offsite", "TRUE"),
            ("keep_local_latest", "3"),
        ]))
        .is_none());
    }
    use std::collections::BTreeMap;

    /// The fork guard must survive a `<textarea>`.
    ///
    /// A textarea submits CRLF per the HTML spec and the pack holds LF, so the
    /// guard's `value == built_in` was ALWAYS false for the 46 multi-line
    /// sentences — it never fired for any of them. "Fill the fields with the
    /// built-in wording" followed by Save, the obvious next click, therefore
    /// forked all 46 in one press: exactly the failure the guard exists to
    /// prevent, shipped in the same release as the button that triggers it.
    #[test]
    fn a_textareas_crlf_does_not_defeat_the_fork_guard() {
        // The normalisation the save and import paths apply before comparing.
        let normalise = |v: &str| {
            if v.contains('\r') {
                v.replace("\r\n", "\n").replace('\r', "\n")
            } else {
                v.to_string()
            }
        };
        let lang = hyperion_core::letters::LetterLang::En;
        let mut multiline = 0;
        for s in hyperion_core::letters::STRINGS.iter() {
            let built_in = s.built_in(lang);
            if !built_in.contains('\n') {
                continue;
            }
            multiline += 1;
            // What the browser actually posts back for an untouched field.
            let posted = built_in.replace('\n', "\r\n");
            assert_ne!(
                posted, built_in,
                "the fixture is wrong if these are already equal"
            );
            assert_eq!(
                normalise(&posted),
                built_in,
                "{} would be stored as an override after a round trip through the form",
                s.id
            );
        }
        assert!(
            multiline >= 20,
            "expected the pack to hold many multi-line bodies, found {multiline}"
        );
    }

    /// `LetterLang::parse` answers English for anything it does not know, which
    /// is the right fallback for a config file already on disk and the WRONG
    /// answer for a file being imported.
    ///
    /// `lang = "sk"` is a plausible mistake. Coercing it would switch every
    /// customer letter to English and say nothing — so the accepter here is the
    /// alias LIST, and the parse is only used to fold a known alias onto its
    /// pack.
    #[test]
    fn an_unknown_language_is_named_not_coerced_to_english() {
        // What the import accepts, in the same shape.
        let accepts = |v: &str| {
            let v = v.trim().to_lowercase();
            matches!(
                v.as_str(),
                "en" | "eng" | "english" | "cs" | "cz" | "cesky" | "česky"
            )
        };
        for good in ["en", "EN", " cs ", "cz", "Česky", "english"] {
            assert!(accepts(good), "{good:?} is a language an operator may type");
        }
        for bad in ["sk", "de", "pl", "c", "czech-ish", "42"] {
            assert!(
                !accepts(bad),
                "{bad:?} must be named back, not silently become English"
            );
            // And the thing that made this necessary: parse() maps them all to
            // English, so it cannot be the accepter.
            assert_eq!(
                hyperion_core::letters::LetterLang::parse(bad),
                hyperion_core::letters::LetterLang::En,
                "parse() coerces {bad:?} — which is exactly why it is not the gate"
            );
        }
    }

    /// Every sentence in the pack must survive a trip out to TOML and back.
    ///
    /// The bodies carry newlines, quotes and `{placeholders}`, and a mangled
    /// placeholder reaches a CUSTOMER — so this walks the real catalogue rather
    /// than a handful of samples.
    #[test]
    fn every_string_survives_the_export_round_trip() {
        for lang in [
            hyperion_core::letters::LetterLang::En,
            hyperion_core::letters::LetterLang::Cs,
        ] {
            let mut doc = String::from("[letters]\n");
            for s in hyperion_core::letters::STRINGS.iter() {
                doc.push_str(&format!(
                    "{} = {}\n",
                    toml_key(s.id),
                    toml_value(s.built_in(lang))
                ));
            }
            let parsed: toml_edit::DocumentMut = doc
                .parse()
                .unwrap_or_else(|e| panic!("export is not valid TOML for {lang:?}: {e}\n{doc}"));
            let table = parsed
                .get("letters")
                .and_then(|t| t.as_table_like())
                .expect("[letters] table");
            for s in hyperion_core::letters::STRINGS.iter() {
                let got = table
                    .get(s.id)
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("{} missing after round trip", s.id));
                assert_eq!(
                    got,
                    s.built_in(lang),
                    "{} changed on the way through TOML ({lang:?})",
                    s.id
                );
            }
        }
    }

    /// A value that is byte-identical to the pack must NOT become an override.
    ///
    /// Storing it would fork that sentence silently: every later improvement to
    /// the built-in wording would stop reaching the install, and nothing in the
    /// UI would say so. The import writes an empty string for those, which is
    /// how this codebase spells "remove the override".
    #[test]
    fn unchanged_wording_is_not_stored_as_an_override() {
        let s = hyperion_core::letters::STRINGS
            .first()
            .expect("the catalogue is not empty");
        let lang = hyperion_core::letters::LetterLang::En;
        let built_in = s.built_in(lang);

        // What post_letters_import decides, in the same shape.
        let decide = |value: &str| -> String {
            if value == built_in {
                String::new()
            } else {
                value.to_string()
            }
        };
        assert_eq!(
            decide(built_in),
            "",
            "identical wording must clear, not store"
        );
        assert_eq!(
            decide(&format!("{built_in} ")),
            format!("{built_in} "),
            "one changed character makes it the operator's"
        );
    }

    /// Switching language in the file must not fork the whole catalogue.
    ///
    /// The operator's route to a translation is: export, change `lang`, replace
    /// the values, paste back. If "unchanged" is judged against the language
    /// STORED rather than the one the file declares, every Czech sentence
    /// differs from its English built-in — so all 125 become overrides at once
    /// and the install silently stops tracking the pack for ever.
    #[test]
    fn a_language_switch_is_judged_against_the_file_not_the_stored_pack() {
        use hyperion_core::letters::LetterLang;
        let s = hyperion_core::letters::STRINGS
            .iter()
            .find(|s| s.built_in(LetterLang::En) != s.built_in(LetterLang::Cs))
            .expect("some string differs between the packs");

        // The rule post_letters_import applies: unchanged against EITHER pack.
        let packs = [LetterLang::Cs, LetterLang::En];
        let is_override = |value: &str| !packs.iter().any(|&l| value == s.built_in(l));

        // Stored English, file says Czech, values are the Czech built-ins:
        // a translation. Nothing is the operator's own.
        assert!(
            !is_override(s.built_in(LetterLang::Cs)),
            "the Czech pack's own wording must not be stored as the operator's"
        );
        // Same switch, but the values are still English because they have not
        // been translated yet. Also nothing of the operator's — and crucially
        // no override, so the language switch they asked for actually takes.
        assert!(
            !is_override(s.built_in(LetterLang::En)),
            "storing these would make the language switch a no-op"
        );
        // A genuine edit is still theirs.
        assert!(is_override(&format!("{} x", s.built_in(LetterLang::Cs))));
    }

    /// Pressing "fill the fields with the built-in wording" and then Save must
    /// not fork all 125 sentences.
    ///
    /// The button exists so an operator can EDIT a sentence rather than retype
    /// something they can see but not select — so it puts every built-in into
    /// the form. Saving that, which is the obvious next click, would store all
    /// of them as overrides and the install would silently stop tracking the
    /// pack for ever. The save path clears anything identical to the pack, so
    /// the button is safe and so is retyping a sentence by hand.
    #[test]
    fn saving_the_built_in_wording_clears_rather_than_forks() {
        use hyperion_core::letters::LetterLang;
        let lang = LetterLang::En;
        // The rule post_config applies to a `letters` submission.
        let decide = |id: &str, value: &str| -> Option<String> {
            if id == "lang" || value.is_empty() {
                return Some(value.to_string());
            }
            match hyperion_core::letters::lookup(id) {
                Some(s) if value == s.built_in(lang) => Some(String::new()),
                _ => Some(value.to_string()),
            }
        };
        for s in hyperion_core::letters::STRINGS.iter() {
            assert_eq!(
                decide(s.id, s.built_in(lang)).as_deref(),
                Some(""),
                "{} would have been stored as the operator's own wording",
                s.id
            );
        }
        // A real edit still lands.
        let s = hyperion_core::letters::STRINGS.first().expect("non-empty");
        let edited = format!("{} (edited)", s.built_in(lang));
        assert_eq!(decide(s.id, &edited).as_deref(), Some(edited.as_str()));
    }

    /// An empty override is not an override, and the export must say so.
    ///
    /// `LetterCatalog::get` already falls back to the pack for one. Reading the
    /// map directly exported a BLANK for every sentence once the per-string
    /// form had been saved with its fields empty — which is what saving it
    /// without touching anything does.
    #[test]
    fn an_empty_override_exports_as_the_pack_wording() {
        use hyperion_core::letters::{LetterCatalog, LetterLang};
        let s = hyperion_core::letters::STRINGS.first().expect("non-empty");
        let mut cat = LetterCatalog::new(LetterLang::En);
        cat.overrides.insert(s.id.to_string(), String::new());

        // The rule get_letters_export applies.
        let own = cat.overrides.get(s.id).filter(|v| !v.trim().is_empty());
        assert!(
            own.is_none(),
            "a blank must not read as the operator's wording"
        );
        let effective = own
            .cloned()
            .unwrap_or_else(|| s.built_in(cat.lang).to_string());
        assert_eq!(effective, s.built_in(LetterLang::En));
    }

    /// Both spellings of a dotted id must mean the same thing.
    ///
    /// The download quotes them, because in TOML a bare `care.subject = "x"` is
    /// a nested TABLE, not a key of that name. A snippet typed from memory
    /// usually does not — and a paste that is silently discarded is the worst
    /// outcome available: the flash says it worked and the next letter goes out
    /// with the old wording.
    #[test]
    fn a_dotted_id_is_accepted_quoted_or_not() {
        let quoted: toml_edit::DocumentMut = "[letters]\n\"care.subject\" = \"hi\"\n"
            .parse()
            .expect("valid");
        let bare: toml_edit::DocumentMut =
            "[letters]\ncare.subject = \"hi\"\n".parse().expect("valid");

        let read = |d: &toml_edit::DocumentMut| {
            flatten_toml_strings(d.get("letters").unwrap().as_table_like().unwrap(), "")
        };
        assert_eq!(read(&quoted), vec![("care.subject".into(), "hi".into())]);
        assert_eq!(
            read(&bare),
            vec![("care.subject".into(), "hi".into())],
            "an unquoted dotted key must not be silently dropped"
        );

        // Three segments, which the catalogue has (care.unmeasured.note).
        let deep: toml_edit::DocumentMut = "[letters]\ncare.unmeasured.note = \"x\"\n"
            .parse()
            .expect("valid");
        assert_eq!(
            read(&deep),
            vec![("care.unmeasured.note".into(), "x".into())]
        );
    }

    /// A multi-line body must not be able to end its own TOML string early.
    #[test]
    fn a_body_containing_triple_quotes_still_round_trips() {
        let nasty = "line one\nshe said \"\"\"hello\"\"\" and left\nline three\n";
        let doc = format!("[letters]\nx = {}\n", toml_value(nasty));
        let parsed: toml_edit::DocumentMut = doc.parse().expect("valid TOML");
        assert_eq!(
            parsed["letters"]["x"].as_str().expect("string"),
            nasty,
            "escaping lost the text"
        );
    }

    /// An older node that cannot report its `[letters]` must read as UNKNOWN,
    /// never as agreement.
    ///
    #[test]
    fn a_workers_email_is_read_from_its_file_not_its_boot_copy() {
        let raw = "[email]\nenabled = false\nsmtp_host = \"smtp.example.com\"\n\
                   smtp_password = \"«set»\"\nfrom_address = \"n@example.cz\"\n\
                   default_to = \"ops@example.cz\"\n";
        let v = super::email_view_from_masked_toml(raw).unwrap();
        assert!(!v.enabled);
        assert_eq!(
            v.smtp_host, "smtp.example.com",
            "relay off must not read blank"
        );
        assert!(v.smtp_password_set);
        assert_eq!(v.smtp_port, 587);
        assert_eq!(v.default_to, "ops@example.cz");
        let none =
            super::email_view_from_masked_toml("[email]\nsmtp_password = \"«empty»\"\n").unwrap();
        assert!(!none.smtp_password_set);
        assert!(super::email_view_from_masked_toml("not = [toml").is_err());
    }

    #[test]
    fn test_send_limit_keys_on_the_real_client() {
        use axum::http::HeaderMap;
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        h.insert("x-real-ip", "198.51.100.7".parse().unwrap());
        let direct: std::net::SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let proxied: std::net::SocketAddr = "127.0.0.1:5000".parse().unwrap();
        // Straight to :8443 — no header is believed.
        assert_eq!(super::email_test_ip(&h, direct), direct.ip());
        // Through our nginx — X-Real-IP (set by nginx), never X-Forwarded-For.
        assert_eq!(
            super::email_test_ip(&h, proxied).to_string(),
            "198.51.100.7"
        );
    }

    #[test]
    fn declared_unchecked_synthesizes_false() {
        // Browser sends NO master_accepts_hostings when the box is
        // unchecked. The form declared it via `_checkboxes`, so the
        // synthesiser inserts false so the unchecking persists.
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        synthesize_unchecked_checkboxes(&mut fields, "master_accepts_hostings");
        assert_eq!(fields.get("master_accepts_hostings"), Some(&"false".into()));
    }

    #[test]
    fn checked_value_is_preserved() {
        // When the box IS checked, browser sends "true" (or "on" — we
        // pass through whatever the form sent). Don't clobber it.
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        fields.insert("master_accepts_hostings".into(), "true".into());
        synthesize_unchecked_checkboxes(&mut fields, "master_accepts_hostings");
        assert_eq!(fields.get("master_accepts_hostings"), Some(&"true".into()));
    }

    #[test]
    fn comma_list_handles_multiple() {
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        fields.insert("test_wp_no_index".into(), "true".into());
        synthesize_unchecked_checkboxes(&mut fields, "trash_enabled, test_wp_no_index");
        // trash_enabled was missing → synthesised false
        assert_eq!(fields.get("trash_enabled"), Some(&"false".into()));
        // test_wp_no_index was present → preserved
        assert_eq!(fields.get("test_wp_no_index"), Some(&"true".into()));
    }

    #[test]
    fn empty_declaration_does_nothing() {
        // The regression test for Kevin's bug — saving the Audit
        // Retention form (no checkboxes in it) MUST NOT touch
        // `trash_enabled` or any other unrelated boolean.
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        fields.insert("audit_retention_days".into(), "90".into());
        synthesize_unchecked_checkboxes(&mut fields, "");
        assert!(!fields.contains_key("trash_enabled"));
        assert!(!fields.contains_key("master_accepts_hostings"));
    }

    #[test]
    fn declared_field_already_present_unchanged() {
        // Cross-form bug guard: even if a form (hypothetically)
        // declares `trash_enabled` but the operator never had access
        // to a trash_enabled control on this form, the field comes in
        // missing and we'd insert false. That's by design ONLY when
        // the form OWNS the checkbox — `_checkboxes` is the contract.
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        fields.insert("trash_enabled".into(), "true".into());
        synthesize_unchecked_checkboxes(&mut fields, "trash_enabled");
        assert_eq!(fields.get("trash_enabled"), Some(&"true".into()));
    }

    #[test]
    fn mask_replaces_password_lines() {
        let input = r#"
[email]
smtp_host = "smtp.postmark.com"
smtp_password = "actual-secret-here"
from_address = "ops@example.cz"
"#;
        let out = hyperion_core::config_persist::mask_secrets(input);
        assert!(out.contains("smtp_password = \"«set»\""));
        assert!(!out.contains("actual-secret-here"));
        // Non-suspect lines pass through unchanged.
        assert!(out.contains("smtp_host = \"smtp.postmark.com\""));
        assert!(out.contains("from_address = \"ops@example.cz\""));
    }

    #[test]
    fn mask_distinguishes_empty_vs_set() {
        let input = "secret = \"\"\npassword = \"x\"\n";
        let out = hyperion_core::config_persist::mask_secrets(input);
        assert!(out.contains("secret = \"«empty»\""));
        assert!(out.contains("password = \"«set»\""));
    }

    #[test]
    fn mask_handles_indented_keys() {
        // toml allows indented keys (common in editor-formatted files).
        let input = "    invite_token = \"super-secret\"\n";
        let out = hyperion_core::config_persist::mask_secrets(input);
        assert!(out.contains("invite_token = \"«set»\""));
        assert!(!out.contains("super-secret"));
    }

    #[test]
    fn mask_leaves_non_secret_keys_alone() {
        let input = "url = \"https://example.cz\"\n";
        let out = hyperion_core::config_persist::mask_secrets(input);
        assert!(out.contains("url = \"https://example.cz\""));
    }

    #[test]
    fn mask_does_not_match_partial_key_names() {
        // "passwordless" is NOT in the suspect list — leave it.
        let input = "passwordless = true\nmy_password = \"x\"\n";
        let out = hyperion_core::config_persist::mask_secrets(input);
        assert!(out.contains("passwordless = true"));
        // A `_password` / `_key` / `_token` suffix IS masked: matching only
        // exact names printed `[performance] psi_api_key` in the clear.
        assert!(out.contains("my_password = \"«set»\""));
    }

    #[test]
    fn mask_handles_webhook_url() {
        let input = "default_webhook = \"https://hooks.slack.com/services/T/B/abc\"\n";
        let out = hyperion_core::config_persist::mask_secrets(input);
        assert!(out.contains("default_webhook = \"«set»\""));
        assert!(!out.contains("hooks.slack.com"));
    }

    #[test]
    fn mask_leaves_comments_alone() {
        let input = "# password = \"never-stored-but-comment\"\nactual = \"value\"\n";
        let out = hyperion_core::config_persist::mask_secrets(input);
        // Comment lines don't match because the key-detection
        // looks for "<key> =" before the equals sign and "# password"
        // doesn't match "password" exactly.
        assert!(out.contains("# password = \"never-stored-but-comment\""));
    }

    // ============================================================
    //  [fail2ban] section → Brute-force scanner card
    // ============================================================

    /// No section at all is the common case on an install that never
    /// touched it: the agent runs the defaults, so the form shows the
    /// defaults — but flagged, so nothing implies an operator chose them.
    #[test]
    fn absent_section_shows_the_defaults_the_agent_actually_runs() {
        let v = super::parse_fail2ban_section("[agent]\nsocket_path = \"/run/x.sock\"\n")
            .expect("valid toml");
        assert!(!v.in_toml);
        assert!(!v.clamped);
        assert_eq!(v.cfg, hyperion_core::Fail2banConfig::default());
    }

    /// A partially-filled section keeps the operator's values and fills the
    /// rest from the same defaults the agent would.
    #[test]
    fn partial_section_merges_with_the_agent_defaults() {
        let v = super::parse_fail2ban_section(
            "[fail2ban]\nenabled = false\nhttp_threshold = 4\nban_ttl_secs = 7200\n",
        )
        .expect("valid toml");
        let d = hyperion_core::Fail2banConfig::default();
        assert!(v.in_toml);
        assert!(!v.cfg.enabled);
        assert_eq!(v.cfg.http_threshold, 4);
        assert_eq!(v.cfg.ban_ttl_secs, 7200);
        assert_eq!(v.cfg.ssh_threshold, d.ssh_threshold);
        assert_eq!(v.cfg.window_secs, d.window_secs);
        assert!(!v.clamped);
    }

    /// A hand-edited value the agent overrides at start-up must be reported,
    /// not quietly rendered as if the scanner were using it.
    #[test]
    fn a_value_the_agent_clamps_is_flagged() {
        let v =
            super::parse_fail2ban_section("[fail2ban]\nban_ttl_secs = 0\n").expect("valid toml");
        assert!(v.in_toml);
        assert_eq!(v.cfg.ban_ttl_secs, 0, "the file is shown as it reads");
        assert!(v.clamped, "…and the card has to say the agent uses 60 s");
    }

    /// Unparseable agent.toml yields nothing, so the card says the values
    /// are unknown rather than showing built-in defaults as if they were
    /// this node's settings.
    #[test]
    fn unparseable_toml_yields_no_view() {
        assert!(super::parse_fail2ban_section("[fail2ban\nenabled = ").is_none());
    }

    // ============================================================
    //  Save redirects: section_to_tab / sanitize_return_tab / card_label
    // ============================================================

    use super::{card_label, chrome, sanitize_return_tab, section_label, section_to_tab};

    /// Every `[section]` a /settings/config form can post, plus two that no
    /// form posts, which must still land somewhere visible.
    const SECTIONS: &[&str] = &[
        "email",
        "acme",
        "update",
        "slack",
        "notifications",
        "letters",
        "performance",
        "protection",
        "backup_remote",
        "backup",
        "backup_retention",
        "snapshots",
        "fail2ban",
        "cluster",
        "",
        "no-such-section",
    ];

    #[test]
    fn every_section_redirects_to_a_card() {
        for s in SECTIONS {
            let t = section_to_tab(s);
            assert!(
                chrome::card_section(t).is_some(),
                "section [{s}] redirects to #{t}, which is not a card"
            );
        }
        // [cluster] is written from five pages; its fallback must be a card
        // a standalone install has (the Cluster page is hidden there).
        assert_ne!(
            chrome::card_section(section_to_tab("cluster")),
            Some("cluster")
        );
    }

    #[test]
    fn sanitize_return_tab_accepts_exactly_the_cards() {
        for (card, _) in chrome::CARDS {
            assert_eq!(sanitize_return_tab(card), Some(*card), "{card}");
        }
        assert_eq!(sanitize_return_tab("  trash \n"), Some("trash"));
    }

    #[test]
    fn sanitize_return_tab_rejects_junk() {
        for junk in [
            "",
            " ",
            "evil",
            "GENERAL",
            "general",
            "tab-general",
            "trash#x",
            "trash&flash=pwned",
            "\"><script>alert(1)</script>",
            "https://evil.example/",
            "../../login",
            "sign in",
            "cluster\r\nLocation: https://evil.example",
        ] {
            assert_eq!(sanitize_return_tab(junk), None, "{junk:?} must be dropped");
        }
    }

    /// Each card that shares its section with other cards names ITSELF in the
    /// save flash; everything else falls back to the section's label.
    #[test]
    fn card_label_names_shared_section_cards() {
        for anchor in [
            "sign-in",
            "hardening",
            "placement",
            "test-nodes",
            "preview-address",
            "trash",
            "audit-retention",
            "alert-templates",
            "alert-language",
            "alert-recipients",
            "customer-letters",
            "letter-language",
            "letter-wording",
        ] {
            assert!(card_label(anchor).is_some(), "{anchor} has no label");
            assert!(
                sanitize_return_tab(anchor).is_some(),
                "{anchor} has a label but the handler would drop it"
            );
        }
        // The flash wiring post_config uses: card first, section as fallback.
        let flash = |rt: Option<&'static str>, section: &str| {
            rt.and_then(card_label)
                .unwrap_or_else(|| section_label(section))
        };
        assert_eq!(flash(Some("sign-in"), "cluster"), "Two-factor sign-in");
        assert_eq!(flash(Some("acme"), "acme"), "Let's Encrypt contact");
        assert_eq!(flash(None, "acme"), "Let's Encrypt contact");
    }
}
