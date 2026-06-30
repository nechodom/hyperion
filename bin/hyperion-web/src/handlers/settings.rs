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
use axum::response::Json;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
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
    /// Test nodes that can carry a node-wide `*.<base>` wildcard cert,
    /// each with its computed base domain. Drives the per-node wildcard
    /// issuance rows in the "Test nodes & staging sites" card.
    wildcard_nodes: Vec<NodeWildcardRow>,
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
    /// Which node the Mail tab is currently editing ("" / "local" = master).
    /// The `mta` diagnostics + the form pre-fill are for THIS node.
    mail_node: String,
    /// Master node's Cloudflare DNS-01 token state — drives the "Cloudflare
    /// certs (DNS-01)" card so the operator can save/test the token without SSH.
    cloudflare: hyperion_types::CloudflareTokenInfo,
    error: Option<String>,
    flash: Option<String>,
    flash_error: Option<String>,
    csrf_token: String,
    /// Capability groups for the "create API key" multiselect (reuses the
    /// roles capability groups). Empty when the user can't manage keys.
    api_key_cap_groups: Vec<ApiKeyCapGroup>,
    /// Existing API keys (prefix · label · caps summary · last used · expires).
    api_keys: Vec<ApiKeyRowView>,
    /// True ⇒ render the "API keys" card (user holds ApiKeysManage).
    can_manage_api_keys: bool,
    /// A freshly-minted raw key to reveal exactly once (via ?api_key_new=).
    new_api_key: Option<String>,
}

fn short_sha(s: &str) -> String {
    s.chars().take(12).collect()
}

/// One capability checkbox in the API-key create form.
pub struct ApiKeyCapRow {
    pub machine: &'static str,
    pub label: &'static str,
}

/// One capability group (e.g. "Hosting") for the API-key form.
pub struct ApiKeyCapGroup {
    pub label: &'static str,
    pub caps: Vec<ApiKeyCapRow>,
}

/// A pre-decorated API-key row for the Settings list.
pub struct ApiKeyRowView {
    pub id: i64,
    pub key_prefix: String,
    pub label: String,
    pub caps_summary: String,
    pub last_used: String,
    pub expires: String,
    pub is_revoked: bool,
}

/// Build the capability-group checkboxes for the create form, reusing the
/// canonical roles capability groups.
fn api_key_cap_groups() -> Vec<ApiKeyCapGroup> {
    hyperion_state::capabilities::groups()
        .into_iter()
        .map(|(label, members)| ApiKeyCapGroup {
            label,
            caps: members
                .into_iter()
                .map(|c| ApiKeyCapRow {
                    machine: c.as_str(),
                    label: c.label(),
                })
                .collect(),
        })
        .collect()
}

/// Short human summary of a CapSet for the list ("3 caps" / "all caps").
fn caps_summary(caps: u64) -> String {
    let set = hyperion_state::capabilities::CapSet::from_bits(caps);
    let n = set.count();
    let all = hyperion_state::capabilities::CapSet::all().count();
    if n == 0 {
        "no caps".to_string()
    } else if n == all {
        "all caps".to_string()
    } else {
        format!("{n} cap{}", if n == 1 { "" } else { "s" })
    }
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

/// One test node's wildcard-cert row in the Settings card.
pub struct NodeWildcardRow {
    pub node_id: String,
    pub label: String,
    /// Base domain a `*.<base>` cert would cover (e.g. `four.example.cz`).
    pub base: String,
    /// The wildcard subject shown to the operator (`*.<base>`).
    pub wildcard: String,
}

#[derive(Deserialize, Default)]
pub struct SettingsQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    flash_error: Option<String>,
    /// Node whose [email] config the Mail tab should show/edit.
    /// "" / "local" = master. Drives the per-node MtaDiagnostics fetch.
    #[serde(default)]
    mail_node: String,
    /// A freshly-minted raw API key to reveal exactly once. Passed back
    /// from the create handler's redirect so the key never lives in the
    /// session or the DB — it's shown, then gone on the next reload.
    #[serde(default)]
    api_key_new: Option<String>,
}

pub async fn get_settings(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<SettingsQuery>,
) -> Result<Response, AppError> {
    // Cluster/agent configuration, node topology, and the recent outbound-email
    // log across ALL hostings. Every POST under /settings is admin-gated, but
    // the GET page was reachable by any logged-in user (the nav only hides the
    // link). Tenant-scoped roles must not read it.
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (config_res, update_res, emails_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::UpdateCheck {
                force_refresh: false
            },
        ),
        hyperion_rpc_client::call(
            &state.agent_socket,
            Request::EmailLogList {
                hosting_id: None,
                limit: 5
            },
        ),
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
    // The Mail tab edits ONE node's [email] config at a time. Fetch that
    // node's MTA diagnostics + config over the signed channel (master = local
    // socket). The form pre-fills from `mta.cfg_*`.
    let mail_node = q.mail_node.trim().to_string();
    let mail_target = if mail_node.is_empty() || mail_node == "local" {
        None
    } else {
        Some(mail_node.as_str())
    };
    let mta: hyperion_types::MtaDiagnostics =
        match crate::dispatcher::dispatch_to_node(&state, mail_target, Request::MtaDiagnostics)
            .await
        {
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
    // Master's Cloudflare DNS-01 token state (live-verified if present) for the
    // "Cloudflare certs" card. Best-effort: a failed RPC just shows "unknown".
    let cloudflare: hyperion_types::CloudflareTokenInfo = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::CloudflareTokenStatus,
    )
    .await
    {
        Ok(RpcResponse::CloudflareToken(i)) => i,
        _ => hyperion_types::CloudflareTokenInfo::default(),
    };
    let update_current_short = short_sha(&update_status.current_sha);
    let update_latest_short = short_sha(&update_status.latest_sha);
    // Per-test-node wildcard rows: a `*.<base>` cert issued once covers
    // every auto-subdomain the node spins up. Only test nodes with a
    // derivable base domain qualify.
    let wildcard_nodes: Vec<NodeWildcardRow> = nodes
        .iter()
        .filter(|n| config.cluster.is_test_node(&n.node_id))
        .filter_map(|n| {
            config
                .cluster
                .node_wildcard_base(&n.node_id, &n.label)
                .map(|base| NodeWildcardRow {
                    node_id: n.node_id.clone(),
                    label: n.label.clone(),
                    wildcard: format!("*.{base}"),
                    base,
                })
        })
        .collect();
    // API keys card (gated by ApiKeysManage). Fetch the list best-effort;
    // a failed RPC just shows an empty list. The capability multiselect
    // reuses the canonical roles groups.
    let can_manage_api_keys = ctx.can(Capability::ApiKeysManage);
    let api_keys: Vec<ApiKeyRowView> = if can_manage_api_keys {
        match hyperion_rpc_client::call(&state.agent_socket, Request::ApiKeyList).await {
            Ok(RpcResponse::ApiKeyList(rows)) => rows
                .into_iter()
                .map(|r| ApiKeyRowView {
                    id: r.id,
                    is_revoked: r.is_revoked(),
                    key_prefix: r.key_prefix,
                    caps_summary: caps_summary(r.caps),
                    last_used: fmt_date(r.last_used_at),
                    expires: fmt_date(r.expires_at),
                    label: r.label,
                })
                .collect(),
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };
    let api_key_cap_groups = if can_manage_api_keys {
        api_key_cap_groups()
    } else {
        Vec::new()
    };
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
        wildcard_nodes,
        raw_toml,
        mta,
        mail_node,
        cloudflare,
        error,
        flash: q.flash,
        flash_error: q.flash_error,
        csrf_token,
        api_key_cap_groups,
        api_keys,
        can_manage_api_keys,
        new_api_key: q.api_key_new,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// `POST /settings/api-keys` — mint a new API key. Gated by
/// ApiKeysManage. Caps are folded from the checked capability checkboxes
/// (named by machine string) and clamped server-side to the owner's
/// effective caps. The raw key is revealed once via the redirect.
pub async fn post_api_key_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ApiKeyCreateForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ApiKeysManage) {
        return Ok(
            Redirect::to("/?flash_error=API+key+management+requires+permission").into_response(),
        );
    }
    let Some(session) = ctx.session.as_ref() else {
        // API-key management is a UI-only action (the create form lives
        // in Settings); reject Bearer-driven self-minting here.
        return Ok(Redirect::to("/login").into_response());
    };
    let label = form.label.trim();
    if label.is_empty() {
        return Ok(
            Redirect::to("/settings?flash_error=API+key+label+is+required#api").into_response(),
        );
    }
    // Fold checked capability checkboxes into a CapSet bitmask.
    let mut caps = hyperion_state::capabilities::CapSet::empty();
    for (k, v) in &form.extra {
        if v == "on" {
            if let Some(c) = hyperion_state::capabilities::Capability::from_machine_str(k) {
                caps.insert(c);
            }
        }
    }
    // Optional expiry (YYYY-MM-DD → end-of-day UTC unix). Empty = never.
    let expires_at = match form.expires.trim() {
        "" => None,
        s => match chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            Ok(d) => d.and_hms_opt(23, 59, 59).map(|dt| dt.and_utc().timestamp()),
            Err(_) => {
                return Ok(Redirect::to(
                    "/settings?flash_error=Invalid+expiry+date+(use+YYYY-MM-DD)#api",
                )
                .into_response())
            }
        },
    };
    let scope_all = ctx.scope_all();
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ApiKeyCreate {
            label: label.to_string(),
            owner_user_id: session.user_id,
            caps: caps.bits(),
            scope_all,
            expires_at,
        },
    )
    .await?;
    let created = match resp {
        RpcResponse::ApiKeyCreated(c) => c,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    // Reveal the raw key once via the redirect query param. It's never
    // stored anywhere recoverable.
    let enc: String = url::form_urlencoded::byte_serialize(created.raw_key.as_bytes()).collect();
    Ok(Redirect::to(&format!("/settings?api_key_new={enc}#api")).into_response())
}

/// `POST /settings/api-keys/revoke` — revoke a key by id. Gated by
/// ApiKeysManage.
pub async fn post_api_key_revoke(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ApiKeyRevokeForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ApiKeysManage) {
        return Ok(
            Redirect::to("/?flash_error=API+key+management+requires+permission").into_response(),
        );
    }
    let revoked_by = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ApiKeyRevoke {
            id: form.id,
            revoked_by,
        },
    )
    .await?;
    Ok(Redirect::to("/settings?flash=API+key+revoked#api").into_response())
}

#[derive(Deserialize)]
pub struct ApiKeyCreateForm {
    #[serde(default)]
    pub _csrf: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub expires: String,
    /// The capability checkboxes (named by machine string) + any other
    /// fields. Each checked box arrives as `<machine>=on`.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct ApiKeyRevokeForm {
    #[serde(default)]
    pub _csrf: String,
    pub id: i64,
}

#[derive(Deserialize)]
pub struct CloudflareTokenForm {
    #[serde(default)]
    pub _csrf: String,
    pub token: String,
}

/// `POST /settings/cloudflare/token` — validate the Cloudflare DNS-01 API token
/// against the live API and, only if accepted, persist it on the master (0600).
/// Enables one-click real-cert issuance via DNS-01 behind the CloudFlare proxy.
pub async fn post_cloudflare_token(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CloudflareTokenForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::CloudflareTokenSet {
            token: form.token.into(),
        },
    )
    .await
    .map_err(AppError::from)?;
    let dest = match resp {
        RpcResponse::CloudflareToken(i) => {
            format!("/settings?flash={}#cluster", urlencode(&i.message))
        }
        RpcResponse::Error(e) => {
            format!(
                "/settings?flash_error={}#cluster",
                urlencode(&e.to_string())
            )
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
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
    if !ctx.can(Capability::SettingsManage) {
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
    if !state
        .ratelimit
        .check("email-test", ip, Bucket::per_minute(3))
    {
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
            let msg = format!("Test email sent from {node_label} to {to} · SMTP relay said {smtp_code} · check /emails for the delivery record");
            Ok(Redirect::to(&format!("/settings?flash={}", urlencode(&msg))).into_response())
        }
        RpcResponse::Error(e) => {
            // Include a pointer to /emails so the operator can see the
            // failed-row in context (it's already logged there).
            let msg = format!("{e} — see /emails for the failed row");
            Ok(Redirect::to(&format!("/settings?flash_error={}", urlencode(&msg))).into_response())
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
fn synthesize_unchecked_checkboxes(
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
    // `_return_tab` is a UI hint — pull it out BEFORE field validation
    // so it doesn't get written to agent.toml as if it were a real
    // config key.
    let return_tab_override = fields
        .remove("_return_tab")
        .and_then(|v| sanitize_return_tab(&v));
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
        _ => &[],
    };
    for k in drop_if_empty {
        if fields.get(*k).map(|v| v.trim().is_empty()).unwrap_or(false) {
            fields.remove(*k);
        }
    }
    // Unchecked checkboxes don't show up in the form at all — but our
    // service knows the field is required. Synthesise the missing
    // booleans as "false" so unchecking persists. ONLY for checkboxes
    // this form actually declared via `_checkboxes`; cross-form
    // synthesis is the bug Kevin hit.
    synthesize_unchecked_checkboxes(&mut fields, &declared_checkboxes);

    // `target_node` (present only on the Mail form) selects which node this
    // save targets. Pull it out before the fields are persisted to agent.toml.
    let target_node_raw = fields.remove("target_node").unwrap_or_default();

    // The email section is PER-NODE: dispatch EmailConfigSet to the chosen node
    // (master = local socket). It writes that node's agent.toml, applies
    // postfix live, and self-restarts the node's agent. Every other section
    // stays master-only (local write + web-driven restart, below).
    if form.section == "email" {
        let node_target: Option<&str> =
            if target_node_raw.trim().is_empty() || target_node_raw == "local" {
                None
            } else {
                Some(target_node_raw.trim())
            };
        let node_q = match node_target {
            Some(n) => format!("&mail_node={}", urlencode(n)),
            None => String::new(),
        };
        let resp = crate::dispatcher::dispatch_to_node(
            &state,
            node_target,
            Request::EmailConfigSet {
                fields: fields.into(),
            },
        )
        .await
        .map_err(AppError::from)?;
        let dest = match resp {
            RpcResponse::EmailConfigSet => format!(
                "/settings?flash=Mail+settings+saved+%26+applied+%E2%80%94+agent+restarting+%28~5s%29{node_q}#mail"
            ),
            RpcResponse::Error(e) => {
                format!("/settings?flash_error={}{node_q}#mail", urlencode(&e.to_string()))
            }
            _ => return Err(AppError::Internal("unexpected response".into())),
        };
        return Ok(Redirect::to(&dest).into_response());
    }

    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AgentConfigUpdate {
            section: form.section.clone(),
            fields: fields.into(),
        },
    )
    .await
    .map_err(AppError::from)?;
    // Map TOML section → URL hash so the redirect lands the operator
    // back on the SAME tab they just saved. Without this the redirect
    // bounces them to /settings (no fragment) which always opens the
    // first tab — annoying when you're iterating on cluster settings
    // and keep getting yanked back to Mail. Forms can override the
    // mapping with a hidden `_return_tab` field (sanitised), which
    // is how the Retention tab — which writes cluster.* fields but
    // visually lives elsewhere — keeps the operator in place.
    let tab = return_tab_override.unwrap_or_else(|| section_to_tab(&form.section));
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
                "/settings?flash=Section+%5B{}%5D+saved+%E2%80%94+hyperion-agent+restarting+%28~5s%29#{}",
                urlencode(&form.section),
                tab
            )
        }
        RpcResponse::Error(e) => format!(
            "/settings?flash_error={}#{}",
            urlencode(&e.to_string()),
            tab
        ),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    Ok(Redirect::to(&dest).into_response())
}

/// Map the agent.toml section name to the /settings tab id. The two
/// vocabularies don't line up 1:1 — the UI groups related sections
/// onto one tab (e.g. backup_remote + backup_retention both live
/// under #backups). Unknown sections fall back to "mail" because
/// it's the leftmost tab; better than dumping the operator on a
/// random screen.
///
/// Forms can override this entirely via a hidden `_return_tab` field
/// — that's how the Retention tab (which writes `cluster.*` fields
/// but lives on its own tab) keeps the operator in place after save.
fn section_to_tab(section: &str) -> &'static str {
    match section {
        "email" => "mail",
        "acme" => "tls",
        "slack" => "notifications",
        "backup_remote" | "backup_retention" => "backups",
        "cluster" => "cluster",
        _ => "mail",
    }
}

/// Sanitise an operator-supplied `_return_tab` hint. Only known tab
/// ids are honoured so a malicious / typo'd value can't poison the
/// redirect URL.
fn sanitize_return_tab(v: &str) -> Option<&'static str> {
    match v.trim() {
        "mail" => Some("mail"),
        "tls" => Some("tls"),
        "notifications" => Some("notifications"),
        "backups" => Some("backups"),
        "cluster" => Some("cluster"),
        "testnodes" => Some("testnodes"),
        "retention" => Some("retention"),
        "raw" => Some("raw"),
        _ => None,
    }
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
/// Redirects back to /settings#cluster with a flash message
/// containing the agent's reply (status + panel URL).
/// GET /settings/panel-cert-status — tiny HTML fragment for the
/// HTMX poll loop on /settings#cluster. The progress card polls
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
        None => String::from(
            "<div class=\"text-soft small\" style=\"padding:0.4rem 0\">No panel cert issuance in progress.</div>"
        ),
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
                "issuing"     => ("warn", "issuing…",    50 + ((elapsed % 30) * 50 / 30).min(40), "var(--accent)", true),
                "issued"      => ("ok",   "real LE cert", 100, "var(--success)", false),
                "failed"      => ("err",  "failed",       100, "var(--danger)", false),
                _             => ("",     p.stage.as_str(),0, "var(--surface-2)", false),
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
        return Ok(
            Redirect::to("/settings?flash_error=Panel+hostname+is+required#cluster")
                .into_response(),
        );
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
            format!("/settings?{key}={}#cluster", urlencode(&summary))
        }
        RpcResponse::Error(e) => format!(
            "/settings?flash_error={}#cluster",
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
            if SUSPECT_KEYS.contains(&key) {
                let value_part = trimmed[eq + 1..].trim();
                if value_part.starts_with('"') {
                    let indent_len = line.len() - trimmed.len();
                    let mask = if value_part == "\"\"" {
                        "«empty»"
                    } else {
                        "«set»"
                    };
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
    /// Which node to act on. "" / "local" = master. The MTA card shows
    /// the selected node's diagnostics, so its buttons target it too.
    #[serde(default)]
    pub target_node: String,
}

/// Body for the button-only MTA actions (queue flush/clear, reconfigure).
/// Carries just the Mail-tab node selector so the action runs on the same
/// node whose diagnostics are on screen.
#[derive(Deserialize, Default)]
pub struct NodeActionForm {
    #[serde(default)]
    pub target_node: String,
}

/// Resolve a Mail-tab `target_node` value into a dispatch target + the
/// redirect query suffix that keeps the operator on that node's Mail view.
/// "" / "local" → master (local socket, no suffix).
fn mail_node_target(raw: &str) -> (Option<String>, String) {
    let t = raw.trim();
    if t.is_empty() || t == "local" {
        (None, String::new())
    } else {
        (Some(t.to_string()), format!("&mail_node={}", urlencode(t)))
    }
}

/// POST /settings/mta-queue-flush — `postqueue -f` to retry all
/// deferred mail now. Admin-only; no rate limit (it's cheap and
/// idempotent — re-clicking is fine).
pub async fn post_mta_queue_flush(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeActionForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/settings?flash_error=admin+role+required#mail").into_response());
    }
    let (target, node_q) = mail_node_target(&form.target_node);
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target.as_deref(), Request::MtaQueueFlush)
            .await
            .map_err(AppError::from)?;
    match resp {
        RpcResponse::MtaQueueFlush { attempted, output } => {
            let msg = if attempted == 0 {
                "Queue flush requested · queue is now empty".to_string()
            } else {
                let tail: String = output.lines().take(2).collect::<Vec<_>>().join(" · ");
                let tail = if tail.is_empty() {
                    "(no output)".into()
                } else {
                    tail
                };
                format!(
                    "Queue flush requested · {attempted} message(s) still deferred — \
                     check the log tail for the reason · {tail}"
                )
            };
            Ok(
                Redirect::to(&format!("/settings?flash={}{node_q}#mail", urlencode(&msg)))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}{node_q}#mail",
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
    Form(form): Form<NodeActionForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/settings?flash_error=admin+role+required#mail").into_response());
    }
    let (target, node_q) = mail_node_target(&form.target_node);
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target.as_deref(), Request::MtaQueueClear)
            .await
            .map_err(AppError::from)?;
    match resp {
        RpcResponse::MtaQueueClear { cleared, output: _ } => {
            let msg = if cleared == 0 {
                "Queue clear requested · nothing was in queue".to_string()
            } else {
                format!("Queue clear · {cleared} message(s) discarded")
            };
            Ok(
                Redirect::to(&format!("/settings?flash={}{node_q}#mail", urlencode(&msg)))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}{node_q}#mail",
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
    Form(form): Form<NodeActionForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to(
            "/settings?flash_error=admin+role+required+to+reconfigure+MTA#mail",
        )
        .into_response());
    }
    let (target, node_q) = mail_node_target(&form.target_node);
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target.as_deref(), Request::MtaReconfigure)
            .await
            .map_err(AppError::from)?;
    match resp {
        RpcResponse::MtaReconfigure { mode } => {
            let msg = match mode.as_str() {
                "skipped" => "postfix not installed — install it from /services first".to_string(),
                m => format!("postfix reconfigured: now in {m} mode"),
            };
            Ok(
                Redirect::to(&format!("/settings?flash={}{node_q}#mail", urlencode(&msg)))
                    .into_response(),
            )
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}{node_q}#mail",
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
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to(
            "/settings?flash_error=admin+role+required+to+send+test+emails#mail",
        )
        .into_response());
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
    let (target, node_q) = mail_node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::MtaTestSend { to: to.clone() },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::MtaTestSend { exit_code, output } => {
            if exit_code == 0 {
                let msg = format!(
                    "Sendmail queued the message to {to} (exit 0). \
                     Check the recipient's inbox/spam + `tail /var/log/mail.log` \
                     on this node for delivery progress."
                );
                Ok(
                    Redirect::to(&format!("/settings?flash={}{node_q}#mail", urlencode(&msg)))
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
                    "/settings?flash_error={}{node_q}#mail",
                    urlencode(&msg)
                ))
                .into_response())
            }
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}{node_q}#mail",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// ── Node-level wildcard certs for test nodes ──────────────────────────
//
// A test node auto-creates `<name>.<base>` subdomains; rather than a
// per-site ACME cert each time, the operator issues ONE `*.<base>`
// wildcard here and every auto-subdomain reuses it. Manual DNS-01 shows
// the TXT records on an interstitial; Cloudflare publishes + finishes in
// one shot. The cert lives on the chosen node (shared-nothing), so the
// flow is dispatched there.

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
    record_name: String,
    values: Vec<String>,
    csrf_finish: String,
}

/// Resolve a test node's wildcard base domain (+ display label). `None`
/// when the node isn't a test node or no safe base can be derived.
async fn resolve_node_wildcard_base(
    state: &SharedState,
    node_id: &str,
) -> Option<(String, String)> {
    let config =
        match hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView).await {
            Ok(RpcResponse::AgentConfigView(c)) => c,
            _ => return None,
        };
    if !config.cluster.is_test_node(node_id) {
        return None;
    }
    let label = match hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await {
        Ok(RpcResponse::NodesList(ns)) => ns
            .into_iter()
            .find(|n| n.node_id == node_id)
            .map(|n| n.label)
            .unwrap_or_else(|| node_id.to_string()),
        _ => node_id.to_string(),
    };
    config
        .cluster
        .node_wildcard_base(node_id, &label)
        .map(|base| (label, base))
}

#[derive(Deserialize)]
pub struct NodeWildcardBeginForm {
    pub node_id: String,
    pub provider: String,
    #[serde(default)]
    pub staging: Option<String>,
}

/// POST /settings/node-wildcard/begin — issue (or renew) a test node's
/// `*.<base>` wildcard via the domain-only DNS-01 flow on that node.
pub async fn post_node_wildcard_begin(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeWildcardBeginForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let (_, base) = match resolve_node_wildcard_base(&state, &form.node_id).await {
        Some(v) => v,
        None => {
            return Ok(Redirect::to(
                "/settings?flash_error=node+is+not+a+test+node+or+has+no+wildcard+base#testnodes",
            )
            .into_response());
        }
    };
    let domain = match hyperion_validate::Domain::parse(&base) {
        Ok(d) => d,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/settings?flash_error={}#cluster",
                urlencode(&format!("invalid wildcard base {base}: {e}"))
            ))
            .into_response());
        }
    };
    let provider = if form.provider == "cloudflare" {
        "cloudflare"
    } else {
        "manual"
    };
    let staging = form.staging.as_deref() == Some("on");
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        Some(&form.node_id),
        Request::CertDns01BeginDomain {
            domain,
            email: None,
            staging,
            provider: provider.to_string(),
        },
    )
    .await?;
    match resp {
        RpcResponse::CertDns01BeginDomain {
            completed: true, ..
        } => Ok(Redirect::to(&format!(
            "/settings?flash={}#testnodes",
            urlencode(&format!("wildcard *.{base} issued on {}", form.node_id))
        ))
        .into_response()),
        RpcResponse::CertDns01BeginDomain {
            completed: false,
            record_name,
            values,
        } => {
            let tpl = NodeWildcardDns01Tpl {
                username: &ctx.username,
                user_initial: super::user_initial(&ctx.username),
                active: "settings",
                css_version: super::css_version(),
                htmx_version: super::htmx_version(),
                node_id: form.node_id.clone(),
                base,
                record_name,
                values,
                csrf_finish: super::session_csrf_token(&state, &ctx),
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}#cluster",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct NodeWildcardFinishForm {
    pub node_id: String,
    pub base: String,
}

/// POST /settings/node-wildcard/finish — validate the published TXT,
/// install the wildcard on the node, then re-point its auto-subdomains.
pub async fn post_node_wildcard_finish(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeWildcardFinishForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let domain = match hyperion_validate::Domain::parse(form.base.trim()) {
        Ok(d) => d,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/settings?flash_error={}#cluster",
                urlencode(&format!("invalid wildcard base: {e}"))
            ))
            .into_response());
        }
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        Some(&form.node_id),
        Request::CertDns01FinishDomain { domain },
    )
    .await?;
    match resp {
        RpcResponse::CertDns01FinishDomain(_) => Ok(Redirect::to(&format!(
            "/settings?flash={}#testnodes",
            urlencode(&format!(
                "wildcard *.{} issued + applied to test sites",
                form.base
            ))
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/settings?flash_error={}#cluster",
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
