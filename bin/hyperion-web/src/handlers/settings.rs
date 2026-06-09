//! `/settings` — agent-wide configuration view + email test trigger.
//!
//! READ-ONLY for now; agent.toml editing is the next iteration. The
//! page reads `AgentConfigView` from the RPC (sanitised — no secrets)
//! and renders it with clear "set / not set" indicators.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::ratelimit::Bucket;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::response::Json;
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{AgentConfigView, EmailLogEntry, SmtpAutodetect, UpdateStatus};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    config: AgentConfigView,
    update_status: UpdateStatus,
    update_current_short: String,
    update_latest_short: String,
    /// Last 5 emails the agent sent (any kind, any state). Rendered
    /// inline under the Send test button so the operator sees their
    /// test send immediately without navigating to /emails.
    recent_emails: Vec<EmailLogEntry>,
    /// Enrolled remote nodes — drives the "From: <node>" dropdown
    /// in the Send-test-email form. Empty on single-node setups.
    nodes: Vec<hyperion_types::NodeSummary>,
    /// Read-only snapshot of agent.toml with secrets masked, for
    /// the "Raw TOML" tab. Failing to read shows "(could not
    /// read /etc/hyperion/agent.toml: …)".
    raw_toml: String,
    /// Live MTA (postfix) state — mode (smart-host / direct-mx /
    /// not-installed / default), myhostname, relayhost, mailq depth,
    /// recent mail.log. Drives the new "MTA" card under the SMTP
    /// relay form. Defaults to MtaDiagnostics::default() on RPC
    /// failure (card renders "unknown" and offers a Reconfigure
    /// button — operator at least sees the slot exists).
    mta: hyperion_types::MtaDiagnostics,
    error: Option<String>,
    flash: Option<String>,
    flash_error: Option<String>,
    csrf_token: String,
}

fn short_sha(s: &str) -> String {
    s.chars().take(12).collect()
}

#[derive(Deserialize, Default)]
pub struct SettingsQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    flash_error: Option<String>,
}

pub async fn get_settings(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<SettingsQuery>,
) -> Result<Response, AppError> {
    let (config_res, update_res, emails_res, mta_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::UpdateCheck { force_refresh: false },
        ),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::EmailLogList { hosting_id: None, limit: 5 },
        ),
        hyperion_rpc_client::call(&state.agent_socket, Request::MtaDiagnostics),
    );
    let (config, error) = match config_res {
        Ok(RpcResponse::AgentConfigView(c)) => (c, None),
        Ok(RpcResponse::Error(e)) => (AgentConfigView::default(), Some(e.to_string())),
        Ok(_) => (
            AgentConfigView::default(),
            Some("unexpected agent response".into()),
        ),
        Err(e) => (AgentConfigView::default(), Some(format!("rpc: {e}"))),
    };
    let update_status: UpdateStatus = match update_res {
        Ok(RpcResponse::UpdateCheck(u)) => u,
        _ => UpdateStatus::default(),
    };
    let recent_emails: Vec<EmailLogEntry> = match emails_res {
        Ok(RpcResponse::EmailLogList(rows)) => rows,
        _ => vec![],
    };
    let mta: hyperion_types::MtaDiagnostics = match mta_res {
        Ok(RpcResponse::MtaDiagnostics(d)) => d,
        _ => hyperion_types::MtaDiagnostics::default(),
    };
    // Enrolled nodes — for the "send test from <node>" dropdown.
    // Best-effort: NodesList failure → empty Vec → dropdown shows
    // only the master option.
    let nodes: Vec<hyperion_types::NodeSummary> =
        match hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await {
            Ok(RpcResponse::NodesList(v)) => v,
            _ => Vec::new(),
        };
    // Read agent.toml for the Raw TOML tab. Mask anything that
    // looks like a password / token line — token values are
    // single-line strings so a regex on `password = "..."` /
    // `token = "..."` / `webhook = "https://hooks..."` suffices.
    let raw_toml = match tokio::fs::read_to_string("/etc/hyperion/agent.toml").await {
        Ok(s) => mask_secrets_in_toml(&s),
        Err(e) => format!("(could not read /etc/hyperion/agent.toml: {e})"),
    };
    let update_current_short = short_sha(&update_status.current_sha);
    let update_latest_short = short_sha(&update_status.latest_sha);
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let tpl = SettingsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "settings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        config,
        update_status,
        update_current_short,
        update_latest_short,
        recent_emails,
        nodes,
        raw_toml,
        mta,
        error,
        flash: q.flash,
        flash_error: q.flash_error,
        csrf_token,
    };
    Ok(Html(tpl.render()?).into_response())
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

/// POST /settings/email-test — fires a one-off SMTP send + redirects
/// back to /settings with a flash message.
pub async fn post_email_test(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<EmailTestForm>,
) -> Result<Response, AppError> {
    // Without this gate any authenticated viewer can use Hyperion's
    // SMTP relay as a free spam vector — the relay's daily quota
    // would also get blown out, breaking real cluster notifications.
    if !ctx.is_admin_or_higher() {
        return Ok(
            Redirect::to("/settings?flash_error=admin+role+required+to+send+test+emails")
                .into_response(),
        );
    }
    // Per-IP rate limit so a compromised admin cookie / leaked
    // session can't be used as an open relay or address enumerator.
    // 3/min is comfortable for an operator clicking Test a few times
    // and absurdly low for automated abuse.
    let ip = email_test_ip(&headers, peer);
    if !state.ratelimit.check("email-test", ip, Bucket::per_minute(3)) {
        return Ok(Redirect::to(
            "/settings?flash_error=test+email+rate+limit+exceeded+%E2%80%94+wait+a+minute",
        )
        .into_response());
    }
    let to = form.to.trim().to_string();
    // Bound the address at the RFC5321 max so a 50 KB pathological
    // 'to' field can't blow out the Location header on the redirect.
    if to.len() > 254 {
        return Ok(
            Redirect::to("/settings?flash_error=address+too+long+%28max+254+chars%29")
                .into_response(),
        );
    }
    // Multi-node: when an operator picks a target_node, the test
    // dispatches via the signed RPC channel so the chosen worker
    // does the actual SMTP send. This verifies that worker's
    // outbound SMTP path independently from the master's.
    let target_owned = form.target_node.trim().to_string();
    let target = if target_owned.is_empty()
        || target_owned == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
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
            let msg = format!("Test email sent from {node_label} to {to} · SMTP relay said {smtp_code} · check /emails for the delivery record");
            Ok(
                Redirect::to(&format!("/settings?flash={}", urlencode(&msg)))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => {
            // Include a pointer to /emails so the operator can see the
            // failed-row in context (it's already logged there).
            let msg = format!("{e} — see /emails for the failed row");
            Ok(Redirect::to(&format!(
                "/settings?flash_error={}",
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
/// For each section that has known boolean checkboxes, we insert
/// the explicit "false" when the field is missing. Listed by
/// section so a future section can opt in without grep-archaeology.
fn synthesize_unchecked_checkboxes(
    section: &str,
    fields: &mut std::collections::BTreeMap<String, String>,
) {
    let known: &[&str] = match section {
        "email" => &["enabled"],
        "backup_remote" => &["enabled"],
        "cluster" => &["master_accepts_hostings", "test_wp_no_index", "trash_enabled"],
        _ => return,
    };
    for k in known {
        if !fields.contains_key(*k) {
            fields.insert((*k).to_string(), "false".to_string());
        }
    }
}

/// POST /settings/config — super_admin only. Updates one section of
/// agent.toml in place, preserving comments. Operator must restart the
/// agent to apply.
pub async fn post_config(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ConfigEditForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    // Strip the `section` field from the bag — it's not a TOML field
    // itself, it's the routing key. axum's `#[serde(flatten)]` collects
    // every form field including `section`, so filter it out.
    let mut fields = form.fields;
    fields.remove("section");
    fields.remove("_csrf");
    // "Leave blank to keep" for sensitive fields — empty string would
    // overwrite a real password / webhook URL with "".
    let drop_if_empty: &[&str] = match form.section.as_str() {
        "email" => &["smtp_password"],
        "slack" => &["default_webhook"],
        "backup_remote" => &["password"],
        _ => &[],
    };
    for k in drop_if_empty {
        if fields.get(*k).map(|v| v.trim().is_empty()).unwrap_or(false) {
            fields.remove(*k);
        }
    }
    // Unchecked checkboxes don't show up in the form at all — but our
    // service knows the field is required. Synthesise the missing
    // booleans as "false" so unchecking persists.
    synthesize_unchecked_checkboxes(&form.section, &mut fields);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AgentConfigUpdate {
            section: form.section.clone(),
            fields,
        },
    )
    .await
    .map_err(AppError::from)?;
    let dest = match resp {
        RpcResponse::AgentConfigUpdate => {
            // Spawn a delayed restart so the redirect response gets back
            // to the browser BEFORE the agent goes down. 3s buffer is
            // plenty for the in-flight HTTP response to land. The agent
            // itself restarts via systemd within ~2s after the kill,
            // so the operator's next click sees the fresh config.
            //
            // Why not use the existing service_restart RPC? It refuses
            // to restart hyperion-agent through the agent itself (would
            // kill its own RPC pipe). Doing it from hyperion-web's
            // process side dodges that — we're not the agent.
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
            format!(
                "/settings?flash=Section+%5B{}%5D+saved+%E2%80%94+hyperion-agent+restarting+%28~5s%29",
                urlencode(&form.section)
            )
        }
        RpcResponse::Error(e) => format!("/settings?flash_error={}", urlencode(&e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
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
/// Redirects back to /settings#tab-cluster with a flash message
/// containing the agent's reply (status + panel URL).
pub async fn post_panel_provision(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PanelProvisionForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let hostname = form.hostname.trim().to_lowercase();
    if hostname.is_empty() {
        return Ok(Redirect::to(
            "/settings?flash_error=Panel+hostname+is+required#tab-cluster",
        )
        .into_response());
    }
    let skip_dns_check = matches!(
        form.skip_dns_check.as_deref(),
        Some("on" | "true" | "1" | "yes")
    );
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::PanelProvision { hostname: hostname.clone(), skip_dns_check },
    )
    .await
    .map_err(AppError::from)?;
    let dest = match resp {
        RpcResponse::PanelProvision { status, message, panel_url } => {
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
            format!("/settings?{key}={}#tab-cluster", urlencode(&summary))
        }
        RpcResponse::Error(e) => format!(
            "/settings?flash_error={}#tab-cluster",
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
    if !ctx.is_admin_or_higher() {
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
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::EmailSmtpAutodetect,
    )
    .await?;
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

/// Mask password / token / webhook values in raw TOML before
/// rendering it to the Raw TOML tab on /settings. We never want
/// to leak credentials into HTML the operator might screenshot.
///
/// Strategy: replace the contents of any double-quoted value on a
/// line whose key matches the suspect list with `"«set»"` (or
/// `"«empty»"` if it was already blank). Operates line-by-line so
/// it's robust against multi-line values that we don't have
/// (everything in agent.toml is single-line strings).
fn mask_secrets_in_toml(s: &str) -> String {
    const SUSPECT_KEYS: &[&str] = &[
        "password",
        "smtp_password",
        "invite_token",
        "secret",
        "webhook",
        "default_webhook",
        "auth_token",
        "api_key",
        "key",
    ];
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let trimmed = line.trim_start();
        // Find `<key> = "..."` lines that match a suspect.
        if let Some(eq) = trimmed.find('=') {
            let key = trimmed[..eq].trim();
            if SUSPECT_KEYS.iter().any(|k| key == *k) {
                let value_part = trimmed[eq + 1..].trim();
                if value_part.starts_with('"') {
                    let indent_len = line.len() - trimmed.len();
                    let mask = if value_part == "\"\"" { "«empty»" } else { "«set»" };
                    out.push_str(&line[..indent_len]);
                    out.push_str(key);
                    out.push_str(" = \"");
                    out.push_str(mask);
                    out.push('"');
                    out.push('\n');
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
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
fn email_test_ip(headers: &HeaderMap, peer: SocketAddr) -> std::net::IpAddr {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            if let Ok(ip) = first.trim().parse() {
                return ip;
            }
        }
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = v.trim().parse() {
            return ip;
        }
    }
    peer.ip()
}

#[derive(Deserialize)]
pub struct MtaTestForm {
    pub to: String,
}

/// POST /settings/mta-queue-flush — `postqueue -f` to retry all
/// deferred mail now. Admin-only; no rate limit (it's cheap and
/// idempotent — re-clicking is fine).
pub async fn post_mta_queue_flush(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            Redirect::to("/settings?flash_error=admin+role+required#mail").into_response(),
        );
    }
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::MtaQueueFlush).await?;
    match resp {
        RpcResponse::MtaQueueFlush { attempted, output } => {
            let msg = if attempted == 0 {
                "Queue flush requested · queue is now empty".to_string()
            } else {
                let tail: String = output.lines().take(2).collect::<Vec<_>>().join(" · ");
                let tail = if tail.is_empty() { "(no output)".into() } else { tail };
                format!(
                    "Queue flush requested · {attempted} message(s) still deferred — \
                     check the log tail for the reason · {tail}"
                )
            };
            Ok(
                Redirect::to(&format!("/settings?flash={}#mail", urlencode(&msg)))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}#mail",
            urlencode(&format!("queue flush failed: {e}"))
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /settings/mta-queue-clear — `postsuper -d ALL`. Destructive;
/// gated by the type-to-confirm modal in the template.
pub async fn post_mta_queue_clear(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            Redirect::to("/settings?flash_error=admin+role+required#mail").into_response(),
        );
    }
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::MtaQueueClear).await?;
    match resp {
        RpcResponse::MtaQueueClear { cleared, output: _ } => {
            let msg = if cleared == 0 {
                "Queue clear requested · nothing was in queue".to_string()
            } else {
                format!("Queue clear · {cleared} message(s) discarded")
            };
            Ok(
                Redirect::to(&format!("/settings?flash={}#mail", urlencode(&msg)))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}#mail",
            urlencode(&format!("queue clear failed: {e}"))
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /settings/mta-reconfigure — re-apply postfix smart-host /
/// direct-MX config based on the current `[email]` section. Used
/// when the operator changed agent.toml without restarting the
/// agent, or wants to roll forward after reverting a hand-edit.
pub async fn post_mta_reconfigure(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            Redirect::to("/settings?flash_error=admin+role+required+to+reconfigure+MTA#mail")
                .into_response(),
        );
    }
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::MtaReconfigure).await?;
    match resp {
        RpcResponse::MtaReconfigure { mode } => {
            let msg = match mode.as_str() {
                "skipped" => "postfix not installed — install it from /services first".to_string(),
                m => format!("postfix reconfigured: now in {m} mode"),
            };
            Ok(
                Redirect::to(&format!("/settings?flash={}#mail", urlencode(&msg)))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}#mail",
            urlencode(&format!("MTA reconfigure failed: {e}"))
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /settings/mta-test — send a test mail via /usr/sbin/sendmail
/// (exercises the PHP `mail()` chain end-to-end). Distinct from the
/// existing /settings/email-test which uses the lettre SMTP client
/// — this one validates the WHOLE pipe including postfix's
/// outgoing leg.
pub async fn post_mta_test(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<MtaTestForm>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(
            Redirect::to("/settings?flash_error=admin+role+required+to+send+test+emails#mail")
                .into_response(),
        );
    }
    // Same per-IP rate limit as the SMTP-relay test. Prevents a
    // compromised cookie from turning the local MTA into an
    // address-enumerator or spam vector.
    let ip = email_test_ip(&headers, peer);
    if !state.ratelimit.check("mta-test", ip, Bucket::per_minute(3)) {
        return Ok(Redirect::to(
            "/settings?flash_error=test+email+rate+limit+exceeded+%E2%80%94+wait+a+minute#mail",
        )
        .into_response());
    }
    let to = form.to.trim().to_string();
    if to.len() > 254 {
        return Ok(
            Redirect::to("/settings?flash_error=address+too+long+%28max+254+chars%29#mail")
                .into_response(),
        );
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::MtaTestSend { to: to.clone() },
    )
    .await?;
    match resp {
        RpcResponse::MtaTestSend { exit_code, output } => {
            if exit_code == 0 {
                let msg = format!(
                    "Sendmail queued the message to {to} (exit 0). \
                     Check the recipient's inbox/spam + `tail /var/log/mail.log` \
                     on this node for delivery progress."
                );
                Ok(
                    Redirect::to(&format!("/settings?flash={}#mail", urlencode(&msg)))
                        .into_response(),
                )
            } else {
                let trimmed = output.trim();
                let tail = if trimmed.is_empty() {
                    "(no output from sendmail)".to_string()
                } else {
                    trimmed.chars().take(180).collect()
                };
                let msg = format!("sendmail exit {exit_code}: {tail}");
                Ok(Redirect::to(&format!(
                    "/settings?flash_error={}#mail",
                    urlencode(&msg)
                ))
                .into_response())
            }
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}#mail",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::{mask_secrets_in_toml, synthesize_unchecked_checkboxes};
    use std::collections::BTreeMap;

    #[test]
    fn unchecked_cluster_checkbox_synthesizes_false() {
        // Browser sends NO master_accepts_hostings when the box is
        // unchecked. Synthesizer must insert false so the unchecking
        // persists.
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        synthesize_unchecked_checkboxes("cluster", &mut fields);
        assert_eq!(fields.get("master_accepts_hostings"), Some(&"false".into()));
    }

    #[test]
    fn checked_cluster_checkbox_preserved() {
        // When the box IS checked, browser sends "true" (or "on" — we
        // pass through whatever the form sent). Don't clobber it.
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        fields.insert("master_accepts_hostings".into(), "true".into());
        synthesize_unchecked_checkboxes("cluster", &mut fields);
        assert_eq!(fields.get("master_accepts_hostings"), Some(&"true".into()));
    }

    #[test]
    fn unchecked_email_enabled_synthesizes_false() {
        // Regression: existing behaviour for [email].enabled stays.
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        synthesize_unchecked_checkboxes("email", &mut fields);
        assert_eq!(fields.get("enabled"), Some(&"false".into()));
    }

    #[test]
    fn unknown_section_does_nothing() {
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        synthesize_unchecked_checkboxes("acme", &mut fields);
        assert!(fields.is_empty());
    }

    #[test]
    fn mask_replaces_password_lines() {
        let input = r#"
[email]
smtp_host = "smtp.postmark.com"
smtp_password = "actual-secret-here"
from_address = "ops@example.cz"
"#;
        let out = mask_secrets_in_toml(input);
        assert!(out.contains("smtp_password = \"«set»\""));
        assert!(!out.contains("actual-secret-here"));
        // Non-suspect lines pass through unchanged.
        assert!(out.contains("smtp_host = \"smtp.postmark.com\""));
        assert!(out.contains("from_address = \"ops@example.cz\""));
    }

    #[test]
    fn mask_distinguishes_empty_vs_set() {
        let input = "secret = \"\"\npassword = \"x\"\n";
        let out = mask_secrets_in_toml(input);
        assert!(out.contains("secret = \"«empty»\""));
        assert!(out.contains("password = \"«set»\""));
    }

    #[test]
    fn mask_handles_indented_keys() {
        // toml allows indented keys (common in editor-formatted files).
        let input = "    invite_token = \"super-secret\"\n";
        let out = mask_secrets_in_toml(input);
        assert!(out.contains("invite_token = \"«set»\""));
        assert!(!out.contains("super-secret"));
    }

    #[test]
    fn mask_leaves_non_secret_keys_alone() {
        let input = "url = \"https://example.cz\"\n";
        let out = mask_secrets_in_toml(input);
        assert!(out.contains("url = \"https://example.cz\""));
    }

    #[test]
    fn mask_does_not_match_partial_key_names() {
        // "passwordless" is NOT in the suspect list — leave it.
        let input = "passwordless = true\nmy_password = \"x\"\n";
        let out = mask_secrets_in_toml(input);
        assert!(out.contains("passwordless = true"));
        // my_password isn't in the explicit list either — leave it.
        // (operators using non-standard key names get protection
        // by the on-disk file mode, not by this best-effort scrub.)
        assert!(out.contains("my_password = \"x\""));
    }

    #[test]
    fn mask_handles_webhook_url() {
        let input = "default_webhook = \"https://hooks.slack.com/services/T/B/abc\"\n";
        let out = mask_secrets_in_toml(input);
        assert!(out.contains("default_webhook = \"«set»\""));
        assert!(!out.contains("hooks.slack.com"));
    }

    #[test]
    fn mask_leaves_comments_alone() {
        let input = "# password = \"never-stored-but-comment\"\nactual = \"value\"\n";
        let out = mask_secrets_in_toml(input);
        // Comment lines don't match because the key-detection
        // looks for "<key> =" before the equals sign and "# password"
        // doesn't match "password" exactly.
        assert!(out.contains("# password = \"never-stored-but-comment\""));
    }
}
