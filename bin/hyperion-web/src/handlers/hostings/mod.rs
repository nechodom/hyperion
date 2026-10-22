//! `/hostings/*` — the list, the create wizard, and every page, card and
//! action of one hosting. Each tab or card lives in its own file; this one
//! holds the shared helpers (selector parsing, CSRF tokens, kv lookups).

use crate::auth::AuthCtx;
use crate::error::AppError;
#[allow(unused_imports)] // askama resolves {{ x|date }} through this
use crate::filters;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::{DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector};
use hyperion_state::capabilities::Capability;
use hyperion_types::{
    CertIssueRequest, DbProvision, DnsCheckResult, HostingDetail, HostingProfile, HostingStats,
    HostingSummary, PhpVersion, ProfileApply, SpfCheckResult, WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::{Domain, SystemUserName};
use serde::Deserialize;
use std::str::FromStr;

mod access;
mod backups;
mod billing;
mod bulk;
mod certs;
mod create;
mod cron;
mod database;
mod detail;
mod dns;
mod ftp;
mod git_sync;
mod integrity;
mod jobs;
mod letters;
mod lifecycle;
mod list;
mod logs;
mod lookup;
mod mail;
mod monitor;
mod offsite;
mod performance;
mod permissions;
mod php;
mod placement;
mod protection;
mod quota;
mod signups;
mod site_check;
mod snapshots;
mod staging;
mod traffic;
mod transfer;
mod vhost;
mod waf;
mod wp;
mod wp_mail;
mod wp_updates;

pub use access::*;
pub use backups::*;
pub use billing::*;
pub use bulk::*;
pub use certs::*;
pub use create::*;
pub use cron::*;
pub use database::*;
pub use detail::*;
pub use dns::*;
pub use ftp::*;
pub use git_sync::*;
pub use integrity::*;
pub use jobs::*;
pub use letters::*;
pub use lifecycle::*;
pub use list::*;
pub use logs::*;
pub use lookup::*;
pub use mail::*;
pub use monitor::*;
pub use offsite::*;
pub use performance::*;
pub use permissions::*;
pub use php::*;
pub use placement::*;
pub use protection::*;
pub use quota::*;
pub use signups::*;
pub use site_check::*;
pub use snapshots::*;
pub use staging::*;
pub use traffic::*;
pub use transfer::*;
pub use vhost::*;
pub use waf::*;
pub use wp::*;
pub use wp_mail::*;
pub use wp_updates::*;

/// Browsers (and reverse proxies in front) can cache /hostings/new
/// by default. After an enrollment the dropdown should refresh on
/// the next visit, NOT show the previous stale rendering. The
/// form also carries a one-time CSRF token, so a cached page
/// would be useless on submit anyway.
fn no_store(mut response: Response) -> Response {
    let h = response.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    h.insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    h.insert("vary", axum::http::HeaderValue::from_static("Cookie"));
    response
}

/// Look up enrolled nodes via NodesList. The master itself isn't a
/// row in the `nodes` table (it's the orchestrator, not an enrollee),
/// so whatever this returns IS the set of remote targets the
/// operator can pick from.
pub(crate) async fn fetch_remote_nodes(
    state: &SharedState,
) -> Result<Vec<hyperion_types::NodeSummary>, AppError> {
    let resp = crate::dispatcher::cached_nodes(state)
        .await
        .map(hyperion_rpc::codec::Response::NodesList)?;
    match resp {
        RpcResponse::NodesList(v) => Ok(v),
        _ => Err(AppError::Internal("unexpected NodesList response".into())),
    }
}

/// Base64-encode (STANDARD) — small local helper to avoid threading the
/// engine import through every call site.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Resolve a per-form `target_node` field to the Option<&str>
/// shape that dispatch_to_node accepts. Empty / "local" / "" →
/// master itself; anything else is a remote node_id.
fn node_target(raw: &str) -> Option<&str> {
    let s = raw.trim();
    if s.is_empty() || s == crate::dispatcher::LOCAL_NODE_SENTINEL {
        None
    } else {
        Some(s)
    }
}

/// A config-save outcome as either an HTMX toast or a classic redirect.
///
/// Progressive enhancement: the forms POST with `hx-post`, so on a normal
/// browser HTMX sends `HX-Request: true` and we answer with a 204 + an
/// `HX-Trigger` that fires a client-side toast — the page never reloads,
/// the card keeps its place. Without JS (or a non-HTMX POST) the SAME
/// handler falls back to the redirect it always did, so nothing breaks.
///
/// `ok`/`err` messages are plain text; the client JSON-decodes the
/// trigger, so they are escaped here.
fn save_result(
    headers: &axum::http::HeaderMap,
    is_ok: bool,
    message: &str,
    redirect_to: String,
) -> Response {
    let is_htmx = headers
        .get("HX-Request")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !is_htmx {
        return Redirect::to(&redirect_to).into_response();
    }
    // HX-Trigger payload: {"toast":{"level":"ok|error","text":"…"}}.
    let level = if is_ok { "ok" } else { "error" };
    let json = format!(
        "{{\"toast\":{{\"level\":\"{level}\",\"text\":{}}}}}",
        json_string(message)
    );
    (
        axum::http::StatusCode::NO_CONTENT,
        [("HX-Trigger", json)],
        (),
    )
        .into_response()
}

/// Minimal JSON string encoder for the toast text — quotes + the control
/// characters a header value must not carry raw.
///
/// Pure ASCII out: the text travels in the `HX-Trigger` HEADER, and a
/// browser reads header bytes as Latin-1, so a raw UTF-8 "—" arrived as
/// "â\u{80}\u{94}". Everything past ASCII is a `\uXXXX` escape (a surrogate
/// pair above the BMP), which the client's JSON.parse turns back.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Re-export of parse_selector for sibling handler modules.
pub fn parse_selector_public(s: &str) -> Result<HostingSelector, AppError> {
    parse_selector(s)
}

/// Generate a 24-char WordPress admin password from a charset that
/// avoids visually-ambiguous characters (no `0/O`, `1/l/I`) so the
/// operator can read it off the credentials card without
/// second-guessing. We use the OS's CSPRNG via `rand::thread_rng()`
/// which is the same source used elsewhere in the codebase for
/// generating DB passwords.
/// A URL-safe single-use token for the FTP password hand-off. Same CSPRNG
/// as every other secret here; length is well past guessing range for a
/// value that lives for five minutes and is consumed on first read.
fn one_shot_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn now_secs_web() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_selector(s: &str) -> Result<HostingSelector, AppError> {
    if s.contains('.') {
        Ok(HostingSelector::Domain(Domain::parse(s)?))
    } else {
        Ok(HostingSelector::Id(hyperion_types::HostingId(
            s.to_string(),
        )))
    }
}

pub(crate) fn csrf_token_for(state: &SharedState, ctx: &AuthCtx, form_id: &str) -> String {
    let sid = ctx
        .session
        .as_ref()
        .map(|s| s.sid.clone())
        .unwrap_or_default();
    hyperion_auth::csrf::mint(
        state.csrf_key.as_ref(),
        &sid,
        form_id,
        hyperion_types::now_secs(),
    )
}

/// Fetch the full cluster config block — used by post_create to
/// evaluate test-node placement rules. Returns the default
/// (permissive) view on any RPC failure so a misconfigured agent
/// doesn't deadlock the create form.
pub(crate) async fn fetch_cluster_config(state: &SharedState) -> hyperion_types::ClusterConfigView {
    match crate::dispatcher::cached_agent_config(state)
        .await
        .map(|c| hyperion_rpc::codec::Response::AgentConfigView((*c).clone()))
    {
        Ok(RpcResponse::AgentConfigView(c)) => c.cluster,
        _ => hyperion_types::ClusterConfigView::default(),
    }
}

/// Stash a failure message server-side and return a single-use token for
/// the redirect.
///
/// A wp-cli failure is routinely longer than a URL can carry, and the
/// message puts the REASON at the end — so routing it through the query
/// string truncated away exactly the part the operator needed, leaving them
/// with a command line and no explanation. Query strings are also written
/// verbatim to nginx's access log, and a failure can quote a path or a
/// database error.
pub(crate) async fn stash_error(state: &SharedState, msg: &str) -> String {
    let token = one_shot_token();
    let now = now_secs_web();
    let mut g = state.error_handoff.lock().await;
    // Drop stale entries before inserting, so an abandoned hand-off cannot
    // sit in memory indefinitely.
    g.retain(|_, (_, at)| now - *at < 300);
    g.insert(token.clone(), (msg.to_string(), now));
    token
}

/// Read a single panel-side metadata value from the master's hosting_kv
/// (keyed by ULID), returning `None` for missing or blank values.
async fn read_master_kv(state: &SharedState, hosting_id: &str, key: &str) -> Option<String> {
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingKvList {
            hosting_id: hosting_id.to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .filter(|s| !s.trim().is_empty()),
        _ => None,
    }
}

fn upper_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// One key of a hosting_kv listing.
pub(crate) fn kv_get<'a>(kv: &'a [(String, String)], key: &str) -> Option<&'a str> {
    kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests;
