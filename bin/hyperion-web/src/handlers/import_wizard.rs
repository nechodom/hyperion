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
const MIGRATION_DIR_DEFAULT: &str = "/var/lib/hyperion/migration";

/// The panel's own nginx vhost, as the agent writes it.
const PANEL_VHOST: &str = "/etc/nginx/sites-enabled/hyperion-panel.conf";

/// Where received bundles land.
///
/// Overridable via `HYPERION_MIGRATION_DIR` for two reasons: the tests must not
/// write to a real system path, and an operator whose `/var` is too small for a
/// 40 GB bundle needs somewhere to put it that is not a recompile away.
fn migration_dir() -> String {
    std::env::var("HYPERION_MIGRATION_DIR").unwrap_or_else(|_| MIGRATION_DIR_DEFAULT.to_string())
}
const MIN_FREE_BYTES: i64 = 2 * 1024 * 1024 * 1024; // 2 GiB floor before accepting

/// One in-flight transfer row for the wizard table.
pub struct TransferRow {
    pub id: i64,
    pub source_kind: String,
    pub status: String,
    pub received: String,
    /// Raw byte count behind `received` — the formatted string is for display
    /// only and must never be parsed back to compute a percentage.
    pub received_bytes: i64,
    pub job_id: Option<String>,
    pub created_by: String,
    /// Interactive stage derived from manifest/selection presence:
    /// "awaiting_report" | "awaiting_selection" | "selected" | "packing" |
    /// "active".
    pub stage: String,
    /// How many sites the source reported (for the "Choose sites (N)" link).
    pub site_count: usize,
    /// Total the source declared, 0 = unknown. A percentage without this is a
    /// number with no denominator, so the renderer must not print one.
    pub expected_bytes: i64,
    /// Measured bytes/second, 0 = not enough evidence to state one. Zero renders
    /// as nothing at all — never as "0 B/s", which would read as a stall.
    pub rate_bytes_per_sec: i64,
    /// What the source last said while PACKING. Empty until it reports.
    pub packing_note: String,
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
    /// Set when the panel's own nginx vhost predates the upload rules, so a
    /// bundle over 2 GiB would still be refused mid-stream. Rendered as a
    /// warning card rather than left for the operator to discover as
    /// `curl: (55) Send failure: Broken pipe` on somebody else's server.
    stale_vhost: Option<String>,
}

/// Does the live panel vhost carry the `/import/` upload rules?
///
/// Read from disk rather than assumed, because the fix ships in a template and
/// an operator can be running a vhost rendered by an older version: the agent
/// re-asserts it at boot, but only when `[cluster] panel_hostname` is set AND
/// the certificate exists. Silence there is exactly the case where the operator
/// upgrades, re-runs the one-liner, and hits the identical 413 — with a panel
/// whose UI now promises resumable background uploads.
async fn stale_panel_vhost() -> Option<String> {
    let text = match tokio::fs::read_to_string(PANEL_VHOST).await {
        Ok(t) => t,
        // No managed vhost at all. Either this panel is reached directly on
        // :8443 (in which case nginx is not in the path and there is nothing to
        // warn about) or it is behind something we did not write. Say nothing
        // rather than cry wolf.
        Err(_) => return None,
    };
    diagnose_panel_vhost(&text)
}

/// Split out from the file read so it can be tested against real rendered
/// vhosts rather than only against a live filesystem.
///
/// It looks for the two shapes that actually hurt, and it must be updated
/// whenever `nginx-panel.conf.j2` changes what it emits. The first version of
/// this check went stale exactly that way: it treated the presence of
/// `location /import/` as the sign of a GOOD vhost, and when that location was
/// renamed the test inverted — a correctly updated box was told it was stale,
/// while a box carrying the broken location was told it was fine. The
/// `vhost_diagnosis_matches_what_the_template_actually_renders` test pins it to
/// the real renderer so it cannot drift again.
fn diagnose_panel_vhost(text: &str) -> Option<String> {
    // The regression from v0.56.0. nginx 301s the unslashed URI for a
    // proxy_pass prefix location ending in `/`, so `location /import/` sends
    // `/import` — the import page itself — to `/import/`, which axum does not
    // route. The operator sees a 404 on a page that worked yesterday, and
    // nothing in the panel explains it.
    if text.contains("location /import/") {
        return Some(format!(
            "The nginx vhost at {PANEL_VHOST} carries a `location /import/` \
             block. nginx answers `/import` with a 301 to `/import/` for a \
             location written that way, and that path is not routed — so the \
             Import page itself returns 404. Run update.sh on this box (or \
             restart the Hyperion agent) to re-render the vhost."
        ));
    }
    // The upload rules are missing entirely: an older vhost, from before
    // resumable uploads existed.
    if !text.contains("/import/upload") || !text.contains("proxy_request_buffering off") {
        return Some(format!(
            "The nginx vhost at {PANEL_VHOST} predates this version and still \
             caps every upload at 2 GiB. An import larger than that will fail \
             mid-transfer with a broken pipe on the source server. Run \
             update.sh on this box (or restart the Hyperion agent) to \
             re-render it."
        ));
    }
    None
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
                // What the source reports while it packs — the phase that used
                // to be dead air, and is usually the longest part of a run.
                let packing_note = summarise_source_progress(&i.source_progress_json);
                let stage = if i.job_id.is_some() || i.status != "pending" {
                    "active"
                } else if has_selection && !packing_note.is_empty() && i.received_bytes == 0 {
                    "packing"
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
                    received_bytes: i.received_bytes,
                    job_id: i.job_id,
                    created_by: i.created_by,
                    stage,
                    site_count,
                    expected_bytes: i.expected_bytes,
                    rate_bytes_per_sec: i.rate_bytes_per_sec,
                    packing_note,
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
            // The self-service wizard does not offer a PHP choice; the import
            // derives one from what the source reports.
            php_version: None,
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
        stale_vhost: stale_panel_vhost().await,
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
    // The runner lives in `assets/import-runner.sh`, not in a format! string.
    //
    // It grew from a one-line pipeline into a few hundred lines with an offset
    // loop, a back-off ladder, flock and setsid handling — and a `format!` raw
    // string requires every `{` and `}` in that to be doubled. A slip in the
    // doubling compiles cleanly and ships a syntactically invalid script whose
    // first reader is an operator running it as root on a customer's production
    // server. As a real file it is checked by `bash -n` in CI, and the three
    // values it needs arrive as a small generated prelude instead.
    //
    // Those values are single-quoted: the token is hex, the kind is a fixed
    // enum, and `base` is charset-stripped in `base_url`, so none can contain
    // the `'` that would end the quoting.
    const RUNNER: &str = include_str!("../../assets/import-runner.sh");
    let script = format!(
        "#!/bin/bash\n\
         # Hyperion self-service import — generated for one token, valid once.\n\
         T='{token}'\n\
         B='{base}'\n\
         K='{kind}'\n\
         {RUNNER}"
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

// ─────────────────────────────────────────────────────────────────────────────
// Resumable chunked upload
//
// The original path was one `curl -T -` streaming a whole panel's worth of
// docroots and database dumps through a single HTTP request, and its token was
// consumed by the request STARTING. So any interruption — a dropped SSH
// session, a proxy's body limit, a network blip four hours in — lost the
// transfer permanently: the bundle had to be re-packed AND the token was spent.
//
// These five routes replace that with an offset protocol whose one invariant is
// that THE SERVER IS AUTHORITATIVE ABOUT THE OFFSET. The client never decides
// where its bytes go; it asks, appends where told, and is corrected with a 409
// whenever it disagrees. That single rule is what makes a resume safe across a
// reconnect, a panel restart, or a partial write.
//
// Replies are `key value` lines, matching the existing `/import/selection`
// protocol, so the bash runner parses them with `sed` rather than needing a
// JSON tool on a stranger's server.
// ─────────────────────────────────────────────────────────────────────────────

/// Largest chunk the panel will accept. nginx no longer caps `/import/`, so this
/// IS the ceiling — and being the ceiling in the application means an oversized
/// body gets a sentence back instead of a closed socket.
const MAX_CHUNK_BYTES: u64 = 128 * 1024 * 1024;

/// Chunk size the panel asks the source to use.
const PREFERRED_CHUNK_BYTES: u64 = 64 * 1024 * 1024;

/// Pull the token out of `Authorization: Bearer …`.
///
/// The token is NOT in the path for these routes, unlike the bootstrap fetch.
/// The upload loop makes one request per chunk — hundreds for a large bundle —
/// and a URL lands in the panel's nginx access log every time. That log is
/// world-readable on many installs and is routinely shipped to aggregation, so
/// putting a live credential in it hundreds of times is the same mistake as
/// putting one on argv, which this project already refuses to do.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let t = raw.strip_prefix("Bearer ")?.trim();
    // The token is hex; refuse anything else rather than passing operator-shaped
    // junk into a hash lookup.
    if t.is_empty() || t.len() > 128 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(t.to_string())
}

fn text(code: StatusCode, body: String) -> Response {
    (
        code,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// Parse a `key value` body into a small map. Bounded by the route's 8 KiB body
/// limit, so no size guard is needed here.
fn kv(body: &str) -> std::collections::HashMap<&str, &str> {
    body.lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect()
}

fn part_path(id: i64) -> String {
    format!("{}/bundle-{id}.tar.part", migration_dir())
}

fn final_path(id: i64) -> String {
    format!("{}/bundle-{id}.tar", migration_dir())
}

async fn part_len(id: i64) -> u64 {
    tokio::fs::metadata(part_path(id))
        .await
        .map(|m| m.len())
        .unwrap_or(0)
}

/// Make sure the migration directory exists and is 0700.
///
/// The bundle holds plaintext database dumps and wp-config secrets; a site's
/// PHP-FPM uid must not be able to traverse in.
async fn ensure_migration_dir() {
    use std::os::unix::fs::PermissionsExt;
    let _ = tokio::fs::create_dir_all(migration_dir()).await;
    let _ =
        tokio::fs::set_permissions(migration_dir(), std::fs::Permissions::from_mode(0o700)).await;
}

/// `POST /import/upload/begin` — admit an attempt and say where to continue.
///
/// Idempotent by design: calling it again after a dropped connection is exactly
/// how a resume starts, and the reply carries the offset the panel already
/// holds. That is why it uses `ClaimUpload` rather than the single-use
/// `Resolve { consume: true }`, which refuses the second call for ever.
pub async fn post_upload_begin(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    let f = kv(&body);
    let expected: u64 = f.get("bytes").and_then(|v| v.parse().ok()).unwrap_or(0);
    let sha = f.get("sha256").copied().unwrap_or("");
    // Optional: the measured UNCOMPRESSED size of the selected docroots. Absent
    // (an older runner, or a source where `du` could not read every docroot)
    // means the inflate figure is unknown, and an unknown figure must not be
    // the reason a transfer is refused — the check below is simply skipped.
    let inflate: u64 = f
        .get("inflate")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    // A bundle with no declared digest is refused outright. There is no fallback
    // to `tar tf`: a tar truncated at a 512-byte boundary and zero-padded — what
    // a crash or a short write leaves — reads as a clean end-of-archive, so
    // `tar tf` exits 0 having silently dropped every member past the cut, and
    // the import then creates those sites EMPTY and reports success.
    if expected == 0 || sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(text(
            StatusCode::BAD_REQUEST,
            "begin needs `bytes <n>` and `sha256 <64 hex>`\n".into(),
        ));
    }

    // What this token was carrying BEFORE this call, read while it is still
    // readable. `claim_upload` writes the incoming digest and then re-SELECTs,
    // so the row it returns always echoes back the sha just sent — which made
    // the stale-partial check below compare a value with itself and never fire.
    // A resume after a re-pack would then be told to continue at the previous
    // bundle's offset, splicing the tail of one archive onto the head of
    // another; only the commit digest would notice, after the whole remainder
    // had been uploaded.
    let previous_sha = resolve(&state, &token, false)
        .await?
        .map(|i| i.bundle_sha256)
        .unwrap_or_default();

    let claimed = match token_rpc(
        &state,
        ImportTokenOp::ClaimUpload {
            token: token.clone(),
            expected_bytes: expected as i64,
            bundle_sha256: sha.to_string(),
        },
    )
    .await?
    {
        ImportTokenResult::Resolved(Some(i)) => i,
        _ => {
            return Ok(text(
                StatusCode::FORBIDDEN,
                "this import token is expired, cancelled, or its bundle already \
                 arrived and is being imported\n"
                    .into(),
            ))
        }
    };

    // A different bundle than the one this token was carrying. Re-packing is a
    // normal event — the run directory was cleaned, the box rebooted before
    // staging finished, a site was fixed and the export re-run — so the partial
    // is discarded and the transfer restarts, rather than the token being
    // bricked with a mismatch error the operator cannot act on.
    ensure_migration_dir().await;
    let mut offset = part_len(claimed.id).await;
    if offset > 0 && !previous_sha.is_empty() && previous_sha != sha {
        let _ = tokio::fs::remove_file(part_path(claimed.id)).await;
        offset = 0;
    }
    // Never claim to hold more than was declared: a stale .part longer than the
    // new bundle would make the client skip past the end.
    if offset > expected {
        let _ = tokio::fs::remove_file(part_path(claimed.id)).await;
        offset = 0;
    }

    // A real preflight, against the size actually being sent. The old blind
    // 2 GiB floor accepted a 40 GB bundle onto a disk with 3 GB free and
    // discovered the problem hours later, mid-write.
    //
    // And RECEIVING the bundle was never the whole cost. The bundle is unpacked
    // into a staging tree of its own size beside it, and each site's compressed
    // `docroot.tar.gz` is then inflated into the real hosting tree — so a 13 GB
    // bundle of 30 sites needs ~57 GB, not 14. Checking only the first of those
    // three is what let a multi-hour upload the operator watched succeed die
    // mid-import, with some sites created and populated and some created empty.
    if let Some(avail) = avail_bytes(&migration_dir()).await {
        // 2 copies: the arriving `.tar`, plus the staging tree it is unpacked
        // into. `inflate` is 0 when the source could not measure it, and then
        // this is exactly the old bundle-plus-headroom check.
        // Charge only what is still to ARRIVE. A resume already has `offset`
        // bytes on this disk — `df` has stopped counting them as free — so
        // demanding the whole bundle again refused a transfer that was 90 %
        // done for space it was already using, and refused it permanently:
        // every retry made the same demand.
        let need = hyperion_import::bundle::import_needed_bytes(expected, inflate, 2)
            .saturating_sub(offset);
        if (avail as u64) < need {
            // Deliberately NOT marked failed. Freeing disk and re-running the
            // one-liner is the obvious fix, and a token burnt here would force
            // the operator back through mint + scan + selection for a problem
            // they just solved.
            let human = hyperion_import::progress::human_bytes;
            return Ok(text(
                StatusCode::INSUFFICIENT_STORAGE,
                format!(
                    "not enough free disk on the target node: {} free, {} needed \
                     (the {} bundle, counted twice because it is unpacked into a \
                     staging tree beside itself{}, plus 1 GB of headroom)\n",
                    human(avail as u64),
                    human(need),
                    human(expected),
                    if inflate > 0 {
                        format!(", plus {} of site files once unpacked", human(inflate))
                    } else {
                        String::new()
                    },
                ),
            ));
        }
    }

    Ok(text(
        StatusCode::OK,
        format!("offset {offset}\nchunk {PREFERRED_CHUNK_BYTES}\nstate receiving\n"),
    ))
}

/// `PUT /import/upload/chunk` — append one chunk at the offset the server holds.
pub async fn put_upload_chunk(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Result<Response, AppError> {
    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    // Refuse an oversized chunk from the DECLARED length, before reading a byte.
    // Discovering the overflow mid-stream is precisely the failure that produced
    // `curl (55)` and a SIGPIPE'd tar with no usable error.
    if let Some(len) = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len > MAX_CHUNK_BYTES {
            return Ok(text(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("chunk of {len} bytes exceeds the {MAX_CHUNK_BYTES} byte limit\n"),
            ));
        }
    }
    let Some(info) = resolve(&state, &token, false).await? else {
        // `get_fetchable` admits pending/receiving only, so a cancelled or
        // completed transfer lands here. 410 is the runner's stop signal.
        return Ok(text(StatusCode::GONE, "state cancelled\n".into()));
    };
    if info.status == "importing" {
        // The precondition stated here rather than left to the query filter:
        // once commit has handed the bundle to a job, no further byte may be
        // appended to it, whatever a stale runner believes.
        return Ok(text(
            StatusCode::GONE,
            "state importing\nthis bundle already arrived and is being imported\n".into(),
        ));
    }
    let want: u64 = headers
        .get("x-hyperion-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(u64::MAX);

    ensure_migration_dir().await;
    let path = part_path(info.id);
    let have = part_len(info.id).await;
    if want != have {
        // The sole resume negotiation. No write happens; the client seeks.
        return Ok(text(
            StatusCode::CONFLICT,
            format!("offset {have}\nstate receiving\n"),
        ));
    }

    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;
    let mut file = {
        let mut o = tokio::fs::OpenOptions::new();
        // 0600 from creation, never the default 0644 — it is world-readable
        // while it streams otherwise, and this file is every selected site's
        // database in plaintext.
        o.create(true).append(true).mode(0o600);
        match o.open(&path).await {
            Ok(f) => f,
            Err(e) => return Err(AppError::Internal(format!("open bundle part: {e}"))),
        }
    };

    // Any failure mid-chunk rolls the file back to the last acknowledged offset,
    // so a partial chunk is never counted and the client can retry exactly that
    // chunk. Without this a torn write would leave the file at an offset the
    // client does not know about, and the resume would splice bytes into the
    // middle of a member.
    let rollback = |e: String| async move {
        if let Ok(f) = tokio::fs::OpenOptions::new().write(true).open(&path).await {
            let _ = f.set_len(have).await;
        }
        e
    };

    let mut body = body;
    let mut written: u64 = 0;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                // Content-Length was checked before the body was read, but a
                // chunked request declares none — so the running total is
                // capped here too.
                if written + data.len() as u64 > MAX_CHUNK_BYTES {
                    let msg = rollback("chunk exceeded the size limit mid-stream".into()).await;
                    return Ok(text(StatusCode::PAYLOAD_TOO_LARGE, format!("{msg}\n")));
                }
                if let Err(e) = file.write_all(&data).await {
                    let msg = rollback(format!("write failed (disk full?): {e}")).await;
                    return Ok(text(
                        StatusCode::INSUFFICIENT_STORAGE,
                        format!("{msg}\noffset {have}\n"),
                    ));
                }
                written += data.len() as u64;
            }
            Some(Err(e)) => {
                let msg = rollback(format!("upload error: {e}")).await;
                return Ok(text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{msg}\noffset {have}\n"),
                ));
            }
            None => break,
        }
    }
    if let Err(e) = file.flush().await {
        let msg = rollback(format!("flush failed: {e}")).await;
        return Ok(text(
            StatusCode::INSUFFICIENT_STORAGE,
            format!("{msg}\noffset {have}\n"),
        ));
    }
    drop(file);

    let now_off = have + written;
    let _ = token_rpc(
        &state,
        ImportTokenOp::RecordUpload {
            id: info.id,
            received_bytes: now_off as i64,
        },
    )
    .await;
    Ok(text(
        StatusCode::OK,
        format!("offset {now_off}\nstate receiving\n"),
    ))
}

/// `POST /import/upload/commit` — verify and hand the bundle to the import job.
pub async fn post_upload_commit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    let Some(info) = resolve(&state, &token, false).await? else {
        return Ok(text(StatusCode::GONE, "state cancelled\n".into()));
    };
    // Already committed. Retrying a commit whose 200 was lost is normal, and
    // answering "cancelled" for it would be both wrong and alarming; answering
    // with the existing job is right, and re-importing the same bundle would be
    // the actual harm.
    if info.status == "importing" {
        if let Some(job) = info.job_id.as_deref() {
            return Ok(text(
                StatusCode::OK,
                format!(
                    "state importing\njob {job}\nreceived {}\n",
                    info.received_bytes
                ),
            ));
        }
    }
    let f = kv(&body);
    let declared: u64 = f.get("bytes").and_then(|v| v.parse().ok()).unwrap_or(0);
    let sha = f.get("sha256").copied().unwrap_or("").to_lowercase();

    let part = part_path(info.id);
    let have = part_len(info.id).await;
    if have != declared || declared == 0 {
        return Ok(text(
            StatusCode::CONFLICT,
            format!(
                "the panel holds {have} bytes but the source declared {declared}\n\
                 offset {have}\nstate receiving\n"
            ),
        ));
    }

    // The real integrity check. `tar tf` is not one — see post_upload_begin.
    let actual = match hyperion_import::bundle::seal(std::path::Path::new(&part)).await {
        Ok((_, digest)) => digest,
        Err(e) => return Err(AppError::Internal(format!("hash bundle: {e}"))),
    };
    if actual != sha {
        // Exactly one full re-upload is granted: a corrupt resume must not be
        // able to loop for ever, and must never reach the import job.
        let _ = tokio::fs::remove_file(&part).await;
        update(&state, info.id, None, None, Some(0)).await;
        return Ok(text(
            StatusCode::CONFLICT,
            format!(
                "the bundle arrived corrupted — the source promised sha256 {sha} but \
                 {} arrived. The partial has been discarded; the upload will restart \
                 from zero.\noffset 0\nstate receiving\n",
                &actual[..16]
            ),
        ));
    }

    let final_p = final_path(info.id);
    if let Err(e) = tokio::fs::rename(&part, &final_p).await {
        return Err(AppError::Internal(format!("finalise bundle: {e}")));
    }

    // `tar tf` stays as a SECONDARY check: the digest proves the bytes are the
    // ones the source sealed, but not that the source sealed a valid archive.
    let tar_ok = tokio::process::Command::new("tar")
        .arg("tf")
        .arg(&final_p)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if !tar_ok {
        let head = tokio::fs::read(&final_p).await.unwrap_or_default();
        let preview: String = String::from_utf8_lossy(&head[..head.len().min(160)])
            .chars()
            .map(|c| if c.is_control() { '·' } else { c })
            .collect();
        let _ = tokio::fs::remove_file(&final_p).await;
        update(&state, info.id, Some("failed"), None, Some(have as i64)).await;
        return Ok(text(
            StatusCode::BAD_REQUEST,
            format!(
                "the {have} bytes arrived intact (the digest matched) but they are not a \
                 tar archive — the exporter produced something else. First bytes: \
                 {preview:?}\n"
            ),
        ));
    }

    let site_overrides: Vec<hyperion_import::SiteImportOverride> =
        serde_json::from_str(&info.selection_json).unwrap_or_default();
    let req = hyperion_import::ImportPanelReq {
        source_kind: info.source_kind.clone(),
        mode: "archive".into(),
        ssh: None,
        archive_path: Some(final_p),
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
        Some(have as i64),
    )
    .await;

    Ok(text(
        StatusCode::OK,
        format!("state importing\njob {job_id}\nreceived {have}\n"),
    ))
}

/// `GET /import/upload/status` — what the panel believes, for the source to
/// compare against.
pub async fn get_upload_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    let Some(info) = resolve(&state, &token, false).await? else {
        return Ok(text(StatusCode::OK, "state cancelled\n".into()));
    };
    Ok(text(
        StatusCode::OK,
        format!(
            "state {}\noffset {}\nexpected {}\njob {}\n",
            info.status,
            part_len(info.id).await,
            info.expected_bytes,
            info.job_id.as_deref().unwrap_or("-"),
        ),
    ))
}

/// `POST /import/progress` — what the source is doing while it PACKS.
///
/// Before this the panel showed dead air for the longest phase of a run, so an
/// operator watching the Transfers table could not tell a working export from a
/// dead one.
pub async fn post_source_progress(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    // Stored verbatim and rendered as text, never evaluated. The 8 KiB route
    // limit bounds it.
    let _ = token_rpc(
        &state,
        ImportTokenOp::SetSourceProgress {
            token,
            progress_json: body,
        },
    )
    .await?;
    Ok(text(StatusCode::OK, "ok\n".into()))
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
    selection_for(&state, &token).await
}

/// `GET /import/selection` — the same reply, with the token in a header.
///
/// The runner polls this up to 2640 times while it waits for the operator to
/// pick sites. With the token in the path that was 2640 lines of the panel's
/// nginx access log carrying a live credential — the same reason the chunk loop
/// never put it there. The path form stays for a source that started before
/// this shipped.
pub async fn get_selection_bearer(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    selection_for(&state, &token).await
}

async fn selection_for(state: &SharedState, token: &str) -> Result<Response, AppError> {
    let Some(info) = resolve(state, token, false).await? else {
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
#[derive(serde::Deserialize, Default)]
pub struct AgentBinQuery {
    /// What the SOURCE box reported from `uname -m`.
    #[serde(default)]
    pub arch: Option<String>,
}

pub async fn get_agent_bin(
    State(state): State<SharedState>,
    Path(token): Path<String>,
    axum::extract::Query(q): axum::extract::Query<AgentBinQuery>,
) -> Result<Response, AppError> {
    if resolve(&state, &token, false).await?.is_none() {
        return Ok((StatusCode::NOT_FOUND, "invalid or expired import token\n").into_response());
    }
    let Some(bin) = exporter_bin_path_for(q.arch.as_deref()) else {
        return Ok((
            StatusCode::NOT_FOUND,
            "no hyperion-export binary for that architecture on this node.\n\
             Run update.sh here to install the per-architecture exporters.\n",
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
/// LEGACY single-shot ingest, kept for a transfer already in flight when the
/// panel was upgraded — its source is running the old bootstrap and knows
/// nothing about chunks. New transfers never reach it.
///
/// It has no digest, so its only structural check is `tar tf`, which exits 0 on
/// a zero-padded truncation. The CONSEQUENCE of that is closed elsewhere:
/// `panel_import` now refuses a bundle whose manifest does not account for a
/// missing docroot, instead of creating the site empty and reporting success.
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

    let _ = tokio::fs::create_dir_all(migration_dir()).await;
    // SECURITY (sec-findings #6): the bundle holds plaintext DB dumps +
    // wp-config secrets. Lock the dir to 0700 so other local users (e.g. a site
    // PHP-FPM uid) can't traverse in and read bundle-*.tar.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(migration_dir(), std::fs::Permissions::from_mode(0o700))
            .await;
    }
    if let Some(avail) = avail_bytes(&migration_dir()).await {
        if avail < MIN_FREE_BYTES {
            update(&state, info.id, Some("failed"), None, None).await;
            return Ok((
                StatusCode::INSUFFICIENT_STORAGE,
                "not enough free disk on the target node\n",
            )
                .into_response());
        }
    }

    let path = format!("{}/bundle-{}.tar", migration_dir(), info.id);
    // SECURITY (sec-findings #6): create the bundle 0600 at creation (before any
    // bytes), not the default 0644 — otherwise it's world-readable while it
    // streams and forever after.
    let mut file = {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        match opts.open(&path).await {
            Ok(f) => f,
            Err(e) => {
                update(&state, info.id, Some("failed"), None, None).await;
                return Err(AppError::Internal(format!("create bundle file: {e}")));
            }
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
    drop(file);
    update(&state, info.id, None, None, Some(total)).await;

    // Validate it's actually a tar BEFORE spawning the import job — a truncated or
    // contaminated upload otherwise dies deep inside the job with an opaque
    // "tar: This does not look like a tar archive". Surface what we really got
    // (a stray log line / error text here points straight at the cause).
    let tar_ok = tokio::process::Command::new("tar")
        .arg("tf")
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if !tar_ok {
        let head = tokio::fs::read(&path).await.unwrap_or_default();
        let preview: String = String::from_utf8_lossy(&head[..head.len().min(160)])
            .chars()
            .map(|c| if c.is_control() { '·' } else { c })
            .collect();
        let _ = tokio::fs::remove_file(&path).await;
        update(&state, info.id, Some("failed"), None, Some(total)).await;
        return Ok((
            StatusCode::BAD_REQUEST,
            format!(
                "received {total} bytes, but it is NOT a valid tar bundle — the exporter's \
                 output was truncated or contaminated before upload. First bytes: {preview:?}\n"
            ),
        )
            .into_response());
    }

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
/// Pick the exporter built for the SOURCE box's CPU.
///
/// The source of an import is somebody else's server, and an ARM VPS is
/// ordinary now — serving the panel's own x86_64 binary to one meant the
/// bootstrap died on the kernel's bare "Exec format error". `arch` is what
/// the source reported from `uname -m`; an unknown or absent value falls back
/// to the unsuffixed binary, which is what older installs have.
fn exporter_bin_path_for(arch: Option<&str>) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HYPERION_EXPORT_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let mut cands: Vec<PathBuf> = Vec::new();
    // Normalise the handful of spellings uname reports.
    let suffix = match arch.map(|a| a.trim()) {
        Some("aarch64") | Some("arm64") => Some("aarch64"),
        Some("x86_64") | Some("amd64") => Some("x86_64"),
        _ => None,
    };
    if let Some(sfx) = suffix {
        cands.push(PathBuf::from(format!(
            "/usr/local/bin/hyperion-export-{sfx}"
        )));
        cands.push(PathBuf::from(format!("/usr/sbin/hyperion-export-{sfx}")));
    }
    cands.extend([
        PathBuf::from("/usr/local/bin/hyperion-export"),
        PathBuf::from("/usr/sbin/hyperion-export"),
    ]);
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

/// One line for the Progress column.
///
/// Every figure here is measured. A percentage needs `expected_bytes` and is
/// omitted without it; a rate and an ETA need two samples far enough apart,
/// which the state layer already decided by returning 0 — so 0 renders as
/// nothing at all, never as "0 B/s", which would read as a stall.
fn progress_cell(r: &TransferRow) -> String {
    if r.expected_bytes <= 0 {
        // Total unknown: say how much has landed and stop there.
        return esc(&r.received);
    }
    let pct = (r.received_bytes.min(r.expected_bytes) * 100) / r.expected_bytes;
    let rate = if r.rate_bytes_per_sec > 0 {
        let left = (r.expected_bytes - r.received_bytes).max(0);
        let eta = left / r.rate_bytes_per_sec;
        format!(
            " · {}/s · ~{} left",
            human_bytes(r.rate_bytes_per_sec),
            hyperion_import::progress::human_secs(eta)
        )
    } else {
        String::new()
    };
    format!(
        "<div style=\"min-width:11rem\"><div class=\"progress-bar\" style=\"margin-bottom:.25rem\">\
         <div class=\"progress-bar-fill\" style=\"width:{pct}%\"></div></div>\
         <span class=\"text-soft small\">{} of {} ({pct}%){}</span></div>",
        esc(&r.received),
        esc(&human_bytes(r.expected_bytes)),
        esc(&rate),
    )
}

/// Reduce the source's packing report to one sentence for the table.
///
/// The body is whatever the source POSTed, so it is parsed defensively and
/// rendered as escaped text — never trusted, never evaluated.
fn summarise_source_progress(json: &str) -> String {
    if json.trim().is_empty() {
        return String::new();
    }
    let f: std::collections::HashMap<&str, &str> = json
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let done = f.get("sites_done").copied().unwrap_or("?");
    let total = f.get("sites_total").copied().unwrap_or("?");
    // A skip is the one thing in this report the operator must not miss: it
    // means a site is going to arrive incomplete, and until now it reached them
    // nowhere at all — not during the export, not in the import result.
    let skipped = match f.get("skipped").and_then(|v| v.parse::<i64>().ok()) {
        Some(n) if n > 0 => format!(" · {n} item(s) could not be exported"),
        _ => String::new(),
    };
    match f.get("input_done").and_then(|v| v.parse::<i64>().ok()) {
        Some(b) => format!(
            "packing site {done} of {total} — {} so far{skipped}",
            human_bytes(b)
        ),
        None => format!("packing site {done} of {total}{skipped}"),
    }
}

fn transfers_html(rows: &[TransferRow], csrf: &str) -> String {
    if rows.is_empty() {
        return "<p class=\"text-soft\">No transfers in flight. Generate a command above and run it on your source server.</p>".to_string();
    }
    let mut h = String::from(
        "<div class=\"table-wrap\"><table class=\"table\"><thead><tr><th>Source</th><th>By</th><th>Stage</th><th>Progress</th><th></th></tr></thead><tbody>",
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
            "packing" => (
                "packing on the source".to_string(),
                format!("<span class=\"text-soft\">{}</span>", esc(&r.packing_note)),
            ),
            "selected" => (
                "selected".to_string(),
                "<span class=\"text-soft\">waiting for the source to export…</span>".to_string(),
            ),
            _ if r.status == "failed" => (
                "<span class=\"pill err\">failed</span>".to_string(),
                "<span class=\"text-soft\">this transfer did not finish — start a new \
                 one from the command above</span>"
                    .to_string(),
            ),
            _ => (
                esc(&r.status),
                match &r.job_id {
                    Some(j) => format!("<a href=\"/jobs/{}\">progress →</a>", esc(j)),
                    None => "<span class=\"text-soft\">receiving…</span>".to_string(),
                },
            ),
        };
        // Cancel stays available until the import job has actually started —
        // including WHILE a bundle is being received. It used to disappear the
        // moment the stage went "active", which is exactly when a transfer the
        // operator no longer wants is costing the most disk and bandwidth.
        let cancel = if r.job_id.is_none() {
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
            progress_cell(r),
            action,
            cancel,
        ));
    }
    h.push_str("</tbody></table></div>");
    h
}

#[cfg(test)]
mod tests {
    /// The diagnosis must be pinned to what the template ACTUALLY renders, not
    /// to a string someone remembered.
    ///
    /// The first version of this check treated `location /import/` as the sign
    /// of a healthy vhost. #137 renamed that location — because it was 301-ing
    /// `/import` into a 404 — and the check silently inverted: a correctly
    /// updated box was told it was stale, and a box carrying the broken
    /// location was told it was fine. Rendering the real template here means
    /// the next rename fails this test instead of the operator's diagnosis.
    #[test]
    fn vhost_diagnosis_matches_what_the_template_actually_renders() {
        let current =
            hyperion_adapters::nginx::render_panel(&hyperion_adapters::nginx::PanelVhostInput {
                domain: "panel.example.cz",
                cert_path: "/c/fullchain.pem",
                key_path: "/c/privkey.pem",
                acme_challenge_root: "/var/lib/hyperion/acme-challenges",
            })
            .expect("render_panel");

        assert_eq!(
            super::diagnose_panel_vhost(&current),
            None,
            "the vhost this version renders must not be reported as stale"
        );
    }

    /// The shape that took the Import page down, and the one that caps uploads.
    #[test]
    fn a_broken_or_ancient_vhost_is_named_precisely() {
        // v0.56.0's vhost: it HAS the upload rules, so a naive "are the rules
        // present" check calls it healthy — while `/import` 404s.
        let broken = "location /import/ {\n  proxy_request_buffering off;\n  proxy_pass x;\n}";
        let msg = super::diagnose_panel_vhost(broken).expect("must warn");
        assert!(
            msg.contains("404"),
            "name the symptom the operator is seeing: {msg}"
        );
        assert!(msg.contains("update.sh"), "name the remedy: {msg}");

        // Pre-resumable-upload vhost: no upload rules at all.
        let ancient = "location / {\n  proxy_pass x;\n}";
        let msg = super::diagnose_panel_vhost(ancient).expect("must warn");
        assert!(
            msg.contains("2 GiB"),
            "name the limit that will bite: {msg}"
        );
    }

    use super::{kv, manifest_domain_set, selection_reply, wire_safe_domain};

    /// `inflate` is what turns the begin-time check from "can I receive this"
    /// into "can I import this". It is optional on the wire (an older runner
    /// sends none, and a source that could not measure every docroot omits it),
    /// and anything unparseable has to read as "no figure" — 0 — so the check
    /// degrades to the old bundle-plus-headroom one instead of refusing a
    /// transfer on a guess.
    #[test]
    fn begin_reads_an_optional_inflate_figure() {
        let parse = |body: &str| {
            kv(body)
                .get("inflate")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        };
        assert_eq!(
            parse("bytes 100\nsha256 abc\ninflate 33285996544\n"),
            33_285_996_544
        );
        // Absent, empty, and junk all mean the same thing: no figure.
        assert_eq!(parse("bytes 100\nsha256 abc\n"), 0);
        assert_eq!(parse("bytes 100\ninflate \n"), 0);
        assert_eq!(parse("bytes 100\ninflate unknown\n"), 0);
        assert_eq!(parse("bytes 100\ninflate -1\n"), 0);
    }

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
