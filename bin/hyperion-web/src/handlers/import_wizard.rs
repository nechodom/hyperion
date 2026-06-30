//! Self-service import wizard: server→server bundle push, no browser upload.
//!
//! Flow: an admin mints a one-time token (`/import/wizard`), gets a `curl … |
//! sudo bash` one-liner, runs it on the SOURCE box. That bootstrap downloads the
//! exporter from THIS node, exports the panel, and streams the bundle straight
//! to `/import/ingest/<token>` — which writes it to the master's migration dir
//! and kicks off the normal archive import as a background job. The browser only
//! watches progress; closing it changes nothing.
//!
//! `agent` / `agent-bin` / `ingest` are PUBLIC routes (the source box has no
//! Hyperion session) — the token IS the bearer credential: high-entropy,
//! single-use (atomic consume on ingest), short-lived, scoped, stored hashed.
//! See docs/superpowers/specs/2026-06-28-self-service-import-wizard-design.md.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{ImportTokenInfo, ImportTokenOp, ImportTokenResult};
use serde::Deserialize;
use std::path::PathBuf;

// 4h: must exceed the source's poll budget (≈3h40m, see get_agent_script) plus
// run/scan startup, so a deliberating operator can't outlive the token mid-wait
// (which would read as a false "cancelled" and 403 a late ingest).
const TOKEN_TTL_SECS: i64 = 4 * 60 * 60;
const MIGRATION_DIR: &str = "/var/lib/hyperion/migration";
const MIN_FREE_BYTES: i64 = 2 * 1024 * 1024 * 1024; // 2 GiB floor before accepting

/// One in-flight transfer row for the wizard table.
pub struct TransferRow {
    pub id: i64,
    pub source_kind: String,
    pub status: String,
    pub received: String,
    pub job_id: Option<String>,
    pub created_by: String,
    /// Interactive stage derived from manifest/selection presence:
    /// "awaiting_report" | "awaiting_selection" | "selected" | "active".
    pub stage: String,
    /// How many sites the source reported (for the "Choose sites (N)" link).
    pub site_count: usize,
}

/// Shown once after minting: the single interactive command to paste on the
/// source box.
pub struct MintedView {
    pub one_liner: String,
    pub kind: String,
}

#[derive(Template)]
#[template(path = "import_wizard.html")]
struct ImportWizardTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    minted: Option<MintedView>,
    flash: Option<String>,
    flash_error: Option<String>,
}

#[derive(Deserialize)]
pub struct MintForm {
    pub source_kind: String,
    #[serde(default)]
    pub _csrf: String,
}

// ---- RPC helpers (token ops live in the agent's DB) ---------------------------

async fn token_rpc(state: &SharedState, op: ImportTokenOp) -> Result<ImportTokenResult, AppError> {
    match hyperion_rpc_client::call(&state.agent_socket, Request::ImportToken(op)).await {
        Ok(RpcResponse::ImportToken(r)) => Ok(r),
        Ok(RpcResponse::Error(e)) => Err(AppError::Internal(e.to_string())),
        Ok(_) => Err(AppError::Internal("unexpected RPC response".into())),
        Err(e) => Err(AppError::from(e)),
    }
}

async fn resolve(
    state: &SharedState,
    token: &str,
    consume: bool,
) -> Result<Option<ImportTokenInfo>, AppError> {
    match token_rpc(
        state,
        ImportTokenOp::Resolve {
            token: token.to_string(),
            consume,
        },
    )
    .await?
    {
        ImportTokenResult::Resolved(o) => Ok(o),
        _ => Ok(None),
    }
}

async fn update(
    state: &SharedState,
    id: i64,
    status: Option<&str>,
    job_id: Option<&str>,
    received_bytes: Option<i64>,
) {
    let _ = token_rpc(
        state,
        ImportTokenOp::Update {
            id,
            status: status.map(String::from),
            job_id: job_id.map(String::from),
            received_bytes,
        },
    )
    .await;
}

async fn list_transfers(state: &SharedState) -> Vec<TransferRow> {
    match token_rpc(state, ImportTokenOp::List).await {
        Ok(ImportTokenResult::Listed(v)) => v
            .into_iter()
            .map(|i| {
                let site_count = serde_json::from_str::<Vec<serde_json::Value>>(&i.manifest_json)
                    .map(|a| a.len())
                    .unwrap_or(0);
                let has_manifest = !i.manifest_json.trim().is_empty();
                let has_selection = !i.selection_json.trim().is_empty();
                // Stage drives the wizard row: the source is in one of these
                // phases while status is still "pending" (pre-ingest).
                let stage = if i.job_id.is_some() || i.status != "pending" {
                    "active"
                } else if has_selection {
                    "selected"
                } else if has_manifest {
                    "awaiting_selection"
                } else {
                    "awaiting_report"
                }
                .to_string();
                TransferRow {
                    id: i.id,
                    source_kind: i.source_kind,
                    status: i.status,
                    received: human_bytes(i.received_bytes),
                    job_id: i.job_id,
                    created_by: i.created_by,
                    stage,
                    site_count,
                }
            })
            .collect(),
        _ => Vec::new(),
    }
}

// ---- wizard pages (protected) -------------------------------------------------

#[derive(Deserialize, Default)]
pub struct WizardQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_error: Option<String>,
}

pub async fn get_wizard(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<WizardQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    render(&state, &ctx, None, q.flash, q.flash_error).await
}

pub async fn post_mint(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: HeaderMap,
    Form(form): Form<MintForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let kind = if form.source_kind == "hestiacp" {
        "hestiacp"
    } else {
        "cloudpanel"
    };
    let res = token_rpc(
        &state,
        ImportTokenOp::Mint {
            target_node: "local".into(), // v1: bundle lands on the master node
            source_kind: kind.into(),
            created_by: ctx.username.clone(),
            ttl_secs: TOKEN_TTL_SECS,
        },
    )
    .await?;
    let token = match res {
        ImportTokenResult::Minted { token, .. } => token,
        _ => return Err(AppError::Internal("mint returned unexpected result".into())),
    };
    let base = base_url(&state, &headers).await;
    let one_liner = format!("curl -fsSL \"{base}/import/agent/{token}\" | sudo bash");
    render(
        &state,
        &ctx,
        Some(MintedView {
            one_liner,
            kind: kind.into(),
        }),
        None,
        None,
    )
    .await
}

/// htmx poll target — just the transfers table fragment.
pub async fn get_transfers(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(Html(String::new()).into_response());
    }
    let rows = list_transfers(&state).await;
    let csrf = super::session_csrf_token(&state, &ctx);
    Ok(Html(transfers_html(&rows, &csrf)).into_response())
}

/// One site in the reported manifest, for the selection checklist.
struct SiteRow {
    domain: String,
    owner: String,
    php: String,
    dbs: usize,
}

/// A profile choice for the per-site dropdown on the import checklist.
struct ProfileOpt {
    id: i64,
    name: String,
    price: String,
}

#[derive(Template)]
#[template(path = "import_select.html")]
struct ImportSelectTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    token_id: i64,
    source_kind: String,
    sites: Vec<SiteRow>,
    profiles: Vec<ProfileOpt>,
}

/// `GET /import/select/:id` — the checklist of reported sites for one transfer.
/// Rendered as its own (non-polled) page so ticking boxes is never clobbered.
pub async fn get_select(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    // Find the token row + its reported manifest.
    let infos = match token_rpc(&state, ImportTokenOp::List).await? {
        ImportTokenResult::Listed(v) => v,
        _ => Vec::new(),
    };
    let Some(info) = infos.into_iter().find(|i| i.id == id) else {
        return Ok(
            Redirect::to("/import?flash_error=transfer+not+found+or+expired").into_response(),
        );
    };
    #[derive(serde::Deserialize)]
    struct ManifestSite {
        domain: String,
        #[serde(default)]
        owner: String,
        #[serde(default)]
        php: String,
        #[serde(default)]
        dbs: Vec<String>,
    }
    let sites: Vec<SiteRow> = serde_json::from_str::<Vec<ManifestSite>>(&info.manifest_json)
        .unwrap_or_default()
        .into_iter()
        .map(|s| SiteRow {
            domain: s.domain,
            owner: s.owner,
            php: s.php,
            dbs: s.dbs.len(),
        })
        .collect();
    if sites.is_empty() {
        return Ok(Redirect::to("/import?flash_error=no+sites+reported+yet").into_response());
    }
    // Profiles for the per-site dropdown (best-effort; empty = no profile column).
    let profiles: Vec<ProfileOpt> =
        match hyperion_rpc_client::call(&state.agent_socket, Request::ProfileList).await {
            Ok(RpcResponse::ProfileList(v)) => v
                .into_iter()
                .map(|p| ProfileOpt {
                    id: p.id,
                    name: p.name.clone(),
                    price: p.pretty_price(),
                })
                .collect(),
            _ => Vec::new(),
        };
    let tpl = ImportSelectTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "import",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(&state, &ctx),
        token_id: id,
        source_kind: info.source_kind,
        sites,
        profiles,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct SelectForm {
    #[serde(default)]
    pub _csrf: String,
    pub id: i64,
    /// JSON array the page's JS builds from the ticked rows — one object per
    /// chosen site: `{source, target, profile_id, billing_at}` (target/profile/
    /// billing optional). A JSON blob (not repeated form keys) sidesteps
    /// serde_urlencoded's no-Vec limitation and carries the whole per-site config.
    #[serde(default)]
    pub config: String,
}

/// `POST /import/select` — record the operator's pick; the waiting source script
/// picks it up on its next poll and exports just those sites.
pub async fn post_select(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SelectForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    // Only accept domains the source actually reported for THIS token. This (a)
    // keeps domains verbatim (no char-mangling → underscores/IDN survive), and
    // (b) guarantees the pick will match on export, so a selection can never
    // wedge the transfer at "selected" or silently drop a site.
    let manifest: std::collections::HashSet<String> =
        match token_rpc(&state, ImportTokenOp::List).await? {
            ImportTokenResult::Listed(v) => v
                .into_iter()
                .find(|i| i.id == form.id)
                .map(|i| manifest_domain_set(&i.manifest_json))
                .unwrap_or_default(),
            _ => Default::default(),
        };
    // The page posts a JSON array of per-site config. Keep only rows whose
    // source the manifest actually reported (verbatim domains — no mangling),
    // and turn each into a SiteImportOverride the import engine applies.
    #[derive(serde::Deserialize)]
    struct RowIn {
        source: String,
        #[serde(default)]
        target: String,
        #[serde(default)]
        profile_id: Option<i64>,
        #[serde(default)]
        billing_at: Option<i64>,
    }
    let rows: Vec<RowIn> = serde_json::from_str(&form.config).unwrap_or_default();
    let mut overrides: Vec<hyperion_import::SiteImportOverride> = Vec::new();
    let mut bad_targets: Vec<String> = Vec::new();
    for r in rows.into_iter().filter(|r| manifest.contains(&r.source)) {
        let t = r.target.trim().to_lowercase();
        // Only a rename when a non-empty, *different* (case-insensitive) target is
        // given. Validate it up-front so a typo'd domain is surfaced here rather
        // than silently dropped during apply (Domain::parse is the final gate).
        let target_domain = if t.is_empty() || t == r.source.to_lowercase() {
            None
        } else if wire_safe_domain(&t) {
            Some(t)
        } else {
            bad_targets.push(r.target.trim().to_string());
            continue;
        };
        overrides.push(hyperion_import::SiteImportOverride {
            source_domain: r.source.clone(),
            target_domain,
            profile_id: r.profile_id.filter(|&p| p > 0),
            next_billing_at: r.billing_at.filter(|&b| b > 0),
        });
    }
    if !bad_targets.is_empty() {
        let msg = format!(
            "invalid \"import as\" domain(s): {}",
            bad_targets.join(", ")
        );
        return Ok(Redirect::to(&format!(
            "/import/select/{}?flash_error={}",
            form.id,
            urlencode(&msg)
        ))
        .into_response());
    }
    if overrides.is_empty() {
        return Ok(Redirect::to(&format!(
            "/import/select/{}?flash_error=pick+at+least+one+site",
            form.id
        ))
        .into_response());
    }
    let n = overrides.len();
    let selection_json = serde_json::to_string(&overrides).unwrap_or_else(|_| "[]".into());
    token_rpc(
        &state,
        ImportTokenOp::SetSelection {
            id: form.id,
            selection_json,
        },
    )
    .await?;
    let msg = format!("Selected {n} site(s) — the source is now exporting them.");
    Ok(Redirect::to(&format!("/import?flash={}", urlencode(&msg))).into_response())
}

#[derive(Deserialize)]
pub struct CancelForm {
    #[serde(default)]
    pub _csrf: String,
    pub id: i64,
}

/// `POST /import/cancel` — revoke a transfer; its waiting source script sees
/// `cancelled` on the next poll and stops.
pub async fn post_cancel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CancelForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    token_rpc(&state, ImportTokenOp::Cancel { id: form.id }).await?;
    Ok(Redirect::to("/import?flash=Transfer+cancelled").into_response())
}

/// Percent-encode for flash query params.
fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn render(
    state: &SharedState,
    ctx: &AuthCtx,
    minted: Option<MintedView>,
    flash: Option<String>,
    flash_error: Option<String>,
) -> Result<Response, AppError> {
    let tpl = ImportWizardTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "import",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(state, ctx),
        minted,
        flash: flash.filter(|s| !s.is_empty()),
        flash_error: flash_error.filter(|s| !s.is_empty()),
    };
    Ok(Html(tpl.render()?).into_response())
}

// ---- public token-gated endpoints (no session) --------------------------------

/// `GET /import/agent/:token` — the bootstrap the operator pipes to `sudo bash`
/// on the source box. Auditable (curl it without `| bash` first). Interactive:
/// it reports the discovered sites to Hyperion, then WAITS — polling for the
/// operator's pick in the panel — and finally exports only the selected sites.
pub async fn get_agent_script(
    State(state): State<SharedState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(info) = resolve(&state, &token, false).await? else {
        return Ok((StatusCode::NOT_FOUND, "invalid or expired import token\n").into_response());
    };
    let base = base_url(&state, &headers).await;
    let kind = info.source_kind;
    // $T/$B/$K/$TMP/$SEL use no braces, so they pass through format! untouched.
    // Values are SINGLE-quoted: token is hex, kind is a fixed enum, base is
    // charset-stripped in base_url — none can contain a single quote, so this
    // cannot be broken out of (defense-in-depth atop base_url sanitization).
    let script = format!(
        r#"#!/bin/bash
# Hyperion self-service import — runs on the SOURCE panel box (as root).
# It reports your sites to Hyperion, waits for you to pick them in the panel,
# then exports only those and streams them back. Nothing touches your machine.
set -eu
T='{token}'
B='{base}'
K='{kind}'
echo "[hyperion] downloading exporter from $B …" >&2
TMP="$(mktemp)"; LIST="$(mktemp)"
curl -fsSL "$B/import/agent-bin/$T" -o "$TMP"
chmod +x "$TMP"
echo "[hyperion] scanning $K and reporting the sites to Hyperion …" >&2
"$TMP" --kind "$K" --list --json > "$LIST"
curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @"$LIST" "$B/import/manifest/$T" >/dev/null
echo "[hyperion] reported. Open Hyperion -> Import, tick the sites you want, click Import. Waiting…" >&2
SEL=""
for _ in $(seq 1 2640); do
  R="$(curl -fsS "$B/import/selection/$T" || true)"
  case "$R" in
    pending|"") sleep 5 ;;
    cancelled) echo "[hyperion] cancelled (or token expired) in the panel." >&2; rm -f "$TMP" "$LIST"; exit 0 ;;
    *) SEL="$R"; break ;;
  esac
done
if [ -z "$SEL" ]; then echo "[hyperion] timed out waiting for a selection." >&2; rm -f "$TMP" "$LIST"; exit 1; fi
echo "[hyperion] exporting the selected sites and streaming to Hyperion …" >&2
set -o pipefail
# The panel always sends an explicit comma-separated list of the chosen SOURCE
# domains (never a wildcard), so the source exports exactly those.
"$TMP" --kind "$K" --only "$SEL" --out - | curl -fsS --max-time 86400 -X POST -T - "$B/import/ingest/$T"
rm -f "$TMP" "$LIST"
echo "[hyperion] done — watch progress in Hyperion -> Import." >&2
"#
    );
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        script,
    )
        .into_response())
}

/// `POST /import/manifest/:token` (public, token-gated, NOT consumed) — the
/// source reports its discovered sites (the `--list --json` output). Stored
/// against the token so the wizard can render the pick-list.
pub async fn post_manifest(
    State(state): State<SharedState>,
    Path(token): Path<String>,
    body: String,
) -> Result<Response, AppError> {
    if resolve(&state, &token, false).await?.is_none() {
        return Ok((StatusCode::NOT_FOUND, "invalid or expired import token\n").into_response());
    }
    // Cap the manifest size (defensive) and require it to parse as a JSON ARRAY
    // (the site list) — not just any JSON, else a `{}` would advance the row to a
    // dead-end "Choose sites (0)" stage.
    if body.len() > 512 * 1024 || serde_json::from_str::<Vec<serde_json::Value>>(&body).is_err() {
        return Ok((StatusCode::BAD_REQUEST, "bad manifest\n").into_response());
    }
    token_rpc(
        &state,
        ImportTokenOp::SetManifest {
            token,
            manifest_json: body,
        },
    )
    .await?;
    Ok((StatusCode::OK, "ok\n").into_response())
}

/// `GET /import/selection/:token` (public, token-gated, NOT consumed) — the
/// source polls this and blocks until the operator picks. Plain-text reply:
/// `pending` (keep waiting), `a.com,b.com` (export those source domains), or
/// `cancelled`.
pub async fn get_selection(
    State(state): State<SharedState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let Some(info) = resolve(&state, &token, false).await? else {
        // Unknown / expired / cancelled → tell the source to stop.
        return Ok((StatusCode::OK, "cancelled\n").into_response());
    };
    let reply = selection_reply(&info.selection_json);
    Ok((StatusCode::OK, format!("{reply}\n")).into_response())
}

/// Map the stored selection JSON to the source script's plain-text protocol.
/// Domains are kept VERBATIM (post_select already constrained them to the
/// reported manifest) — only wire-unsafe entries are dropped, so underscores /
/// IDN survive instead of being silently mangled.
fn selection_reply(selection_json: &str) -> String {
    if selection_json.trim().is_empty() {
        return "pending".into();
    }
    let Ok(v) = serde_json::from_str::<Vec<hyperion_import::SiteImportOverride>>(selection_json)
    else {
        return "pending".into();
    };
    // The source exports by SOURCE domain (the bundle is keyed that way); any
    // operator rename is applied on the import side, not here.
    let domains: Vec<String> = v
        .into_iter()
        .map(|o| o.source_domain)
        .filter(|d| wire_safe_domain(d))
        .collect();
    if domains.is_empty() {
        "pending".into()
    } else {
        domains.join(",")
    }
}

/// Parse the reported-manifest JSON into the set of domains, for validating an
/// operator's pick against what the source actually reported.
fn manifest_domain_set(manifest_json: &str) -> std::collections::HashSet<String> {
    #[derive(serde::Deserialize)]
    struct D {
        domain: String,
    }
    serde_json::from_str::<Vec<D>>(manifest_json)
        .map(|v| v.into_iter().map(|d| d.domain).collect())
        .unwrap_or_default()
}

/// A domain is safe to carry in the plain-text poll reply AND a double-quoted
/// shell arg (`--only "$SEL"`, runtime-expanded so not re-parsed): non-empty,
/// no comma (the list delimiter), no whitespace/control, no quote/shell-meta.
/// Real panel domains (incl. underscores and punycode IDN) pass — this rejects,
/// never rewrites, so a legitimate domain is never silently mangled.
fn wire_safe_domain(s: &str) -> bool {
    !s.is_empty()
        && !s.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(
                    c,
                    ',' | '"' | '\'' | '`' | '\\' | '$' | ';' | '&' | '|' | '<' | '>' | '(' | ')'
                )
        })
}

/// `GET /import/agent-bin/:token` — serve the portable `hyperion-export` binary
/// (static musl, runs on any Linux) so the source box can produce the bundle.
pub async fn get_agent_bin(
    State(state): State<SharedState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    if resolve(&state, &token, false).await?.is_none() {
        return Ok((StatusCode::NOT_FOUND, "invalid or expired import token\n").into_response());
    }
    let Some(bin) = exporter_bin_path() else {
        return Ok((
            StatusCode::NOT_FOUND,
            "hyperion-export binary not found on this node — run update.sh to install it\n",
        )
            .into_response());
    };
    let file = tokio::fs::File::open(&bin)
        .await
        .map_err(|e| AppError::Internal(format!("open agent binary: {e}")))?;
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        body,
    )
        .into_response())
}

/// `POST /import/ingest/:token` — receive the streamed bundle (token consumed
/// atomically) → write to disk → spawn the archive import job.
pub async fn post_ingest(
    State(state): State<SharedState>,
    Path(token): Path<String>,
    body: axum::body::Body,
) -> Result<Response, AppError> {
    // Atomic single-use claim. None = already used / expired / unknown.
    let Some(info) = resolve(&state, &token, true).await? else {
        return Ok((
            StatusCode::FORBIDDEN,
            "invalid or already-used import token\n",
        )
            .into_response());
    };

    let _ = tokio::fs::create_dir_all(MIGRATION_DIR).await;
    if let Some(avail) = avail_bytes(MIGRATION_DIR).await {
        if avail < MIN_FREE_BYTES {
            update(&state, info.id, Some("failed"), None, None).await;
            return Ok((
                StatusCode::INSUFFICIENT_STORAGE,
                "not enough free disk on the target node\n",
            )
                .into_response());
        }
    }

    let path = format!("{MIGRATION_DIR}/bundle-{}.tar", info.id);
    let mut file = match tokio::fs::File::create(&path).await {
        Ok(f) => f,
        Err(e) => {
            update(&state, info.id, Some("failed"), None, None).await;
            return Err(AppError::Internal(format!("create bundle file: {e}")));
        }
    };

    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;
    let mut body = body;
    let mut total: i64 = 0;
    let mut last_report: i64 = 0;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if let Err(e) = file.write_all(&data).await {
                        let _ = tokio::fs::remove_file(&path).await;
                        update(&state, info.id, Some("failed"), None, None).await;
                        return Ok((
                            StatusCode::INSUFFICIENT_STORAGE,
                            format!("write failed (disk full?): {e}\n"),
                        )
                            .into_response());
                    }
                    total += data.len() as i64;
                    if total - last_report > 16 * 1024 * 1024 {
                        last_report = total;
                        update(&state, info.id, None, None, Some(total)).await;
                    }
                }
            }
            Some(Err(e)) => {
                let _ = tokio::fs::remove_file(&path).await;
                update(&state, info.id, Some("failed"), None, None).await;
                return Ok(
                    (StatusCode::BAD_REQUEST, format!("upload error: {e}\n")).into_response()
                );
            }
            None => break,
        }
    }
    let _ = file.flush().await;
    update(&state, info.id, None, None, Some(total)).await;

    // The operator's per-site overrides (domain rename / profile / billing) were
    // stored on the token as the selection; hand them to the import engine.
    let site_overrides: Vec<hyperion_import::SiteImportOverride> =
        serde_json::from_str(&info.selection_json).unwrap_or_default();

    // Kick off the archive import as a background job (reuses Location::Archive).
    let req = hyperion_import::ImportPanelReq {
        source_kind: info.source_kind.clone(),
        mode: "archive".into(),
        ssh: None,
        archive_path: Some(path),
        site_overrides,
    };
    let node = if info.target_node.is_empty() || info.target_node == "local" {
        None
    } else {
        Some(info.target_node.clone())
    };
    let label = format!("{} (self-service bundle)", info.source_kind);
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "panel_import",
        Some(&label),
        "{}",
        &info.created_by,
        0,
        move |reporter| async move {
            crate::handlers::import_panel::run_panel_import_job(reporter, job_state, node, req)
                .await;
        },
    )
    .await?;
    update(
        &state,
        info.id,
        Some("importing"),
        Some(&job_id),
        Some(total),
    )
    .await;

    Ok((
        StatusCode::OK,
        format!("received {total} bytes; import job {job_id} started\n"),
    )
        .into_response())
}

// ---- helpers ------------------------------------------------------------------

/// Build the panel base URL that gets baked into the root-run bootstrap script.
/// SECURITY: prefer the operator-configured `panel_hostname` (trusted) over the
/// request `Host` header (attacker-controlled), and strip whatever we use to a
/// strict host[:port] charset so no shell metacharacter can ever reach the
/// generated script. Combined with single-quoting in the script, this closes the
/// Host-header → RCE-on-source vector.
async fn base_url(state: &SharedState, headers: &HeaderMap) -> String {
    let scheme = if state.cfg.web.tls_enabled {
        "https"
    } else {
        "http"
    };
    let configured = state.panel_hostname.read().await.clone();
    let raw = if !configured.trim().is_empty() {
        configured.trim().to_string()
    } else {
        headers
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "localhost".into())
    };
    // host[:port] / [ipv6] only — drops quotes, $, ;, spaces, backticks, etc.
    let host: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        .collect();
    let host = if host.is_empty() {
        "localhost".to_string()
    } else {
        host
    };
    format!("{scheme}://{host}")
}

/// Resolve the portable `hyperion-export` binary this node serves to source
/// boxes — a static musl build that runs on any Linux regardless of glibc.
/// env override → standard install paths → sibling of the web binary.
fn exporter_bin_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HYPERION_EXPORT_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let mut cands = vec![
        PathBuf::from("/usr/local/bin/hyperion-export"),
        PathBuf::from("/usr/sbin/hyperion-export"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            cands.push(dir.join("hyperion-export"));
        }
    }
    cands.into_iter().find(|p| p.is_file())
}

async fn avail_bytes(dir: &str) -> Option<i64> {
    let out = tokio::process::Command::new("df")
        .arg("-B1")
        .arg("--output=avail")
        .arg(dir)
        .output()
        .await
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .nth(1)
        .and_then(|l| l.trim().parse::<i64>().ok())
}

fn human_bytes(n: i64) -> String {
    let n = n as f64;
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", n as i64, U[i])
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn esc(s: &str) -> String {
    askama_escape::escape(s, askama_escape::Html).to_string()
}

fn transfers_html(rows: &[TransferRow], csrf: &str) -> String {
    if rows.is_empty() {
        return "<p class=\"text-soft\">No transfers in flight. Generate a command above and run it on your source server.</p>".to_string();
    }
    let mut h = String::from(
        "<table class=\"table\"><thead><tr><th>Source</th><th>By</th><th>Stage</th><th>Received</th><th></th></tr></thead><tbody>",
    );
    for r in rows {
        // Stage label + the primary action cell.
        let (stage, action) = match r.stage.as_str() {
            "awaiting_report" => (
                "scanning source…".to_string(),
                "<span class=\"text-soft\">waiting for the source to report…</span>".to_string(),
            ),
            "awaiting_selection" if r.site_count > 0 => (
                format!("{} site(s) found", r.site_count),
                format!(
                    "<a class=\"btn small primary\" href=\"/import/select/{}\">Choose sites →</a>",
                    r.id
                ),
            ),
            "awaiting_selection" => (
                "reported 0 sites".to_string(),
                "<span class=\"text-soft\">nothing to import on the source</span>".to_string(),
            ),
            "selected" => (
                "selected".to_string(),
                "<span class=\"text-soft\">waiting for the source to export…</span>".to_string(),
            ),
            _ => (
                esc(&r.status),
                match &r.job_id {
                    Some(j) => format!("<a href=\"/jobs/{}\">progress →</a>", esc(j)),
                    None => "<span class=\"text-soft\">receiving…</span>".to_string(),
                },
            ),
        };
        // Cancel stays available until the import job has actually started.
        let cancel = if r.job_id.is_none() && r.stage != "active" {
            format!(
                "<form method=\"post\" action=\"/import/cancel\" style=\"display:inline;margin-left:.4rem\">\
                 <input type=\"hidden\" name=\"_csrf\" value=\"{}\">\
                 <input type=\"hidden\" name=\"id\" value=\"{}\">\
                 <button class=\"btn small ghost\" type=\"submit\">Cancel</button></form>",
                esc(csrf),
                r.id,
            )
        } else {
            String::new()
        };
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
            esc(&r.source_kind),
            esc(&r.created_by),
            stage,
            esc(&r.received),
            action,
            cancel,
        ));
    }
    h.push_str("</tbody></table>");
    h
}

#[cfg(test)]
mod tests {
    use super::{manifest_domain_set, selection_reply, wire_safe_domain};

    #[test]
    fn wire_safe_domain_accepts_real_domains_rejects_meta() {
        // Real domains — including underscore + punycode IDN — are KEPT verbatim.
        assert!(wire_safe_domain("a.com"));
        assert!(wire_safe_domain("b-c.example.org"));
        assert!(wire_safe_domain("my_app.example.com"));
        assert!(wire_safe_domain("xn--mnchen-3ya.de"));
        // Wire/shell-unsafe entries rejected (never rewritten).
        assert!(!wire_safe_domain(""));
        assert!(!wire_safe_domain("a.com;rm"));
        assert!(!wire_safe_domain("a b.com"));
        assert!(!wire_safe_domain("a\".com"));
        assert!(!wire_safe_domain("a,b")); // comma is the list delimiter
    }

    #[test]
    fn selection_reply_maps_the_poll_protocol() {
        // Not chosen yet / unparseable → keep waiting.
        assert_eq!(selection_reply(""), "pending");
        assert_eq!(selection_reply("   "), "pending");
        assert_eq!(selection_reply("not json"), "pending");
        assert_eq!(selection_reply("[]"), "pending");
        // The selection is now a per-site override list; the poll reply is the
        // comma-joined SOURCE domains (verbatim, incl. underscore).
        assert_eq!(
            selection_reply(r#"[{"source_domain":"a.com"},{"source_domain":"b.com"}]"#),
            "a.com,b.com"
        );
        assert_eq!(
            selection_reply(r#"[{"source_domain":"my_app.example.com"}]"#),
            "my_app.example.com"
        );
        // A rename target / profile never leaks into the source poll — the
        // source always exports by its OWN (source) domain.
        assert_eq!(
            selection_reply(r#"[{"source_domain":"a.com","target_domain":"b.cz","profile_id":2}]"#),
            "a.com"
        );
        // Wire-unsafe entries dropped; all-unsafe → pending.
        assert_eq!(
            selection_reply(r#"[{"source_domain":"a.com"},{"source_domain":"bad;rm"}]"#),
            "a.com"
        );
        assert_eq!(
            selection_reply(r#"[{"source_domain":"bad;rm"}]"#),
            "pending"
        );
    }

    #[test]
    fn manifest_domain_set_extracts_domains() {
        let set = manifest_domain_set(
            r#"[{"domain":"a.com","owner":"u","php":"8.2","dbs":[]},{"domain":"b.com"}]"#,
        );
        assert!(set.contains("a.com") && set.contains("b.com") && set.len() == 2);
        assert!(manifest_domain_set("garbage").is_empty());
    }
}
