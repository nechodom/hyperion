//! `/admin/api-keys` — Bearer keys for the `/api/v1` remote API.
//!
//! Lived on Settings → Access & API until Settings was split into pages; a
//! key is an account-like credential, so it sits under Administration next
//! to Users and Roles. Gated by `ApiKeysManage`. The create form reuses the
//! roles capability groups and clamps to the caller's own capabilities.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "api_keys.html")]
struct ApiKeysTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    flash: Option<String>,
    flash_error: Option<String>,
    /// Capability groups for the create form (the roles groups).
    cap_groups: Vec<ApiKeyCapGroup>,
    keys: Vec<ApiKeyRowView>,
    /// A freshly minted raw key to reveal exactly once.
    new_key: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct ApiKeysQuery {
    #[serde(default)]
    flash: Option<String>,
    #[serde(default)]
    flash_error: Option<String>,
}

/// `GET /admin/api-keys` — the create form and the list of keys.
pub async fn get_api_keys(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: HeaderMap,
    Query(q): Query<ApiKeysQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ApiKeysManage) {
        return Ok(Redirect::to("/").into_response());
    }
    // A freshly-minted key is handed over in a one-time HttpOnly cookie (set
    // by post_api_key_create) instead of the URL; read + clear it here so it
    // is shown exactly once.
    let new_key = cookie_value(&headers, "hyp_new_api_key");
    let keys: Vec<ApiKeyRowView> =
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
                    restrictions: restrictions_summary(&r.ip_allowlist, r.rate_limit_per_min),
                    label: r.label,
                })
                .collect(),
            _ => Vec::new(),
        };
    let tpl = ApiKeysTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "api-keys",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(&state, &ctx),
        flash: q.flash,
        flash_error: q.flash_error,
        cap_groups: api_key_cap_groups(),
        keys,
        new_key: new_key.clone(),
    };
    let mut resp = Html(tpl.render()?).into_response();
    // One-shot: clear the reveal cookie so a refresh doesn't show the key again.
    if new_key.is_some() {
        if let Ok(v) = axum::http::HeaderValue::from_str(
            "hyp_new_api_key=; Max-Age=0; Path=/admin/api-keys; HttpOnly; SameSite=Strict",
        ) {
            resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
        }
    }
    Ok(resp)
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
    /// Human summary of the key's hardening ("2 IPs · 60/min", or "—").
    pub restrictions: String,
}

/// Compact one-line summary of a key's IP allowlist + rate limit for the
/// Settings list. "—" when the key has neither restriction.
fn restrictions_summary(ip_allowlist: &[String], rate_limit_per_min: i64) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !ip_allowlist.is_empty() {
        let n = ip_allowlist.len();
        parts.push(format!("{n} IP{}", if n == 1 { "" } else { "s" }));
    }
    if rate_limit_per_min > 0 {
        parts.push(format!("{rate_limit_per_min}/min"));
    }
    if parts.is_empty() {
        "—".to_string()
    } else {
        parts.join(" · ")
    }
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

/// Read one cookie value from the request's `Cookie` header (none if absent).
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim().to_string())
}

/// `POST /admin/api-keys` — mint a new API key. Gated by
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
        // on this page); reject Bearer-driven self-minting here.
        return Ok(Redirect::to("/login").into_response());
    };
    let label = form.label.trim();
    if label.is_empty() {
        return Ok(
            Redirect::to("/admin/api-keys?flash_error=API+key+label+is+required").into_response(),
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
                    "/admin/api-keys?flash_error=Invalid+expiry+date+(use+YYYY-MM-DD)",
                )
                .into_response())
            }
        },
    };
    let scope_all = ctx.scope_all();
    // A tenant-scoped account can't own an API key yet — the /api/v1 read
    // endpoints aren't tenant-filtered (that lands in p1b). The RPC refuses
    // this too (authoritative backstop), but catch it here so the operator
    // gets a clear flash on this page instead of a bare 502.
    if !scope_all {
        return Ok(Redirect::to(
            "/admin/api-keys?flash_error=API+keys+require+an+account+with+cluster-wide+scope.+Per-tenant+keys+arrive+in+a+later+release.",
        )
        .into_response());
    }
    // Optional hardening. CIDRs are split on comma/whitespace/newline; each must
    // parse as an IP network (a bare IP works too — ipnet accepts /32 · /128).
    let mut ip_allowlist: Vec<String> = Vec::new();
    for tok in form.ip_allowlist.split([',', '\n', '\r', ' ', '\t']) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if tok.parse::<ipnet::IpNet>().is_err() && tok.parse::<std::net::IpAddr>().is_err() {
            return Ok(Redirect::to(
                "/admin/api-keys?flash_error=Invalid+IP/CIDR+in+the+allowlist+(use+e.g.+203.0.113.0/24).",
            )
            .into_response());
        }
        ip_allowlist.push(tok.to_string());
    }
    let rate_limit_per_min: i64 = match form.rate_limit.trim() {
        "" => 0,
        s => match s.parse::<i64>() {
            Ok(n) if n >= 0 => n,
            _ => {
                return Ok(Redirect::to(
                    "/admin/api-keys?flash_error=Rate+limit+must+be+a+non-negative+number+(0+%3D+unlimited).",
                )
                .into_response())
            }
        },
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ApiKeyCreate {
            label: label.to_string(),
            owner_user_id: session.user_id,
            caps: caps.bits(),
            scope_all,
            expires_at,
            ip_allowlist,
            rate_limit_per_min,
        },
    )
    .await?;
    let created = match resp {
        RpcResponse::ApiKeyCreated(c) => c,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    // Reveal the raw key exactly once via a short-lived HttpOnly cookie rather
    // than the URL: a key in a redirect query string lands in browser history
    // and the reverse-proxy access log. The page reads it once and clears it. (`hyp_<base62>` is cookie-safe — no encoding needed.)
    let mut cookie = format!(
        "hyp_new_api_key={}; Max-Age=120; Path=/admin/api-keys; HttpOnly; SameSite=Strict",
        created.raw_key
    );
    // The panel vhost also answers on :80; without `Secure` a plain-http
    // visit within the two minutes would carry the raw key in cleartext.
    if state.secure_cookies() {
        cookie.push_str("; Secure");
    }
    let mut resp = Redirect::to("/admin/api-keys#new-key").into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
    }
    Ok(resp)
}

/// `POST /admin/api-keys/revoke` — revoke a key by id. Gated by
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
    Ok(Redirect::to("/admin/api-keys?flash=API+key+revoked").into_response())
}

#[derive(Deserialize)]
pub struct ApiKeyCreateForm {
    #[serde(default)]
    pub _csrf: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub expires: String,
    /// Optional comma/newline-separated CIDRs the key may connect from
    /// (e.g. "203.0.113.0/24, 198.51.100.7"). Empty = any peer IP.
    #[serde(default)]
    pub ip_allowlist: String,
    /// Optional requests/min ceiling; empty or "0" = unlimited.
    #[serde(default)]
    pub rate_limit: String,
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
