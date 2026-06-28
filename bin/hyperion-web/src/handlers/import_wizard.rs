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
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{ImportTokenInfo, ImportTokenOp, ImportTokenResult};
use serde::Deserialize;
use std::path::PathBuf;

const TOKEN_TTL_SECS: i64 = 2 * 60 * 60; // 2h
const MIGRATION_DIR: &str = "/var/lib/hyperion/migration";
const MIN_FREE_BYTES: i64 = 2 * 1024 * 1024 * 1024; // 2 GiB floor before accepting

/// One in-flight transfer row for the wizard table.
pub struct TransferRow {
    pub source_kind: String,
    pub status: String,
    pub received: String,
    pub job_id: Option<String>,
    pub created_by: String,
}

/// Shown once after minting: the command to paste on the source box.
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
    transfers: Vec<TransferRow>,
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
            .map(|i| TransferRow {
                source_kind: i.source_kind,
                status: i.status,
                received: human_bytes(i.received_bytes),
                job_id: i.job_id,
                created_by: i.created_by,
            })
            .collect(),
        _ => Vec::new(),
    }
}

// ---- wizard pages (protected) -------------------------------------------------

pub async fn get_wizard(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    render(&state, &ctx, None).await
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
    let base = base_url(&state, &headers);
    let one_liner = format!("curl -fsSL {base}/import/agent/{token} | sudo bash");
    render(
        &state,
        &ctx,
        Some(MintedView {
            one_liner,
            kind: kind.into(),
        }),
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
    Ok(Html(transfers_html(&rows)).into_response())
}

async fn render(
    state: &SharedState,
    ctx: &AuthCtx,
    minted: Option<MintedView>,
) -> Result<Response, AppError> {
    let transfers = list_transfers(state).await;
    let tpl = ImportWizardTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "import",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(state, ctx),
        minted,
        transfers,
    };
    Ok(Html(tpl.render()?).into_response())
}

// ---- public token-gated endpoints (no session) --------------------------------

/// `GET /import/agent/:token` — the bootstrap script the operator pipes to
/// `sudo bash` on the source box. Auditable (curl it without `| bash` first).
pub async fn get_agent_script(
    State(state): State<SharedState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(info) = resolve(&state, &token, false).await? else {
        return Ok((StatusCode::NOT_FOUND, "invalid or expired import token\n").into_response());
    };
    let base = base_url(&state, &headers);
    let kind = info.source_kind;
    // $T/$B/$K/$TMP use no braces, so they pass through format! untouched.
    let script = format!(
        r#"#!/bin/sh
# Hyperion self-service import — runs on the SOURCE panel box (as root).
set -eu
T="{token}"
B="{base}"
K="{kind}"
echo "[hyperion] downloading exporter from $B …" >&2
TMP="$(mktemp)"
curl -fsSL "$B/import/agent-bin/$T" -o "$TMP"
chmod +x "$TMP"
echo "[hyperion] exporting $K and streaming the bundle to Hyperion (nothing is downloaded to your machine) …" >&2
"$TMP" export-bundle --kind "$K" --out - | curl -fsS --max-time 86400 -X POST -T - "$B/import/ingest/$T"
rm -f "$TMP"
echo "[hyperion] upload done — watch progress in Hyperion → Import." >&2
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

/// `GET /import/agent-bin/:token` — serve THIS node's hyperion-agent binary so
/// the source can run `export-bundle` (matching arch assumed; see spec).
pub async fn get_agent_bin(
    State(state): State<SharedState>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    if resolve(&state, &token, false).await?.is_none() {
        return Ok((StatusCode::NOT_FOUND, "invalid or expired import token\n").into_response());
    }
    let Some(bin) = agent_bin_path() else {
        return Ok((
            StatusCode::NOT_FOUND,
            "hyperion-agent binary not found on this node\n",
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

    // Kick off the archive import as a background job (reuses Location::Archive).
    let req = hyperion_import::ImportPanelReq {
        source_kind: info.source_kind.clone(),
        mode: "archive".into(),
        ssh: None,
        archive_path: Some(path),
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

fn base_url(state: &SharedState, headers: &HeaderMap) -> String {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("localhost");
    let scheme = if state.cfg.web.tls_enabled {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{host}")
}

/// Resolve THIS node's hyperion-agent binary: env override → sibling of the web
/// binary (installed together) → the standard install path.
fn agent_bin_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HYPERION_AGENT_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let pb = dir.join("hyperion-agent");
            if pb.is_file() {
                return Some(pb);
            }
        }
    }
    let std_path = PathBuf::from("/usr/local/bin/hyperion-agent");
    std_path.is_file().then_some(std_path)
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

fn transfers_html(rows: &[TransferRow]) -> String {
    if rows.is_empty() {
        return "<p class=\"text-soft\">No transfers in flight. Mint a command above and run it on your source server.</p>".to_string();
    }
    let mut h = String::from(
        "<table class=\"table\"><thead><tr><th>Source</th><th>By</th><th>Status</th><th>Received</th><th></th></tr></thead><tbody>",
    );
    for r in rows {
        let link = match &r.job_id {
            Some(j) => format!("<a href=\"/jobs/{}\">progress →</a>", esc(j)),
            None => "<span class=\"text-soft\">waiting for source…</span>".to_string(),
        };
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td><span class=\"pill\">{}</span></td><td>{}</td><td>{}</td></tr>",
            esc(&r.source_kind),
            esc(&r.created_by),
            esc(&r.status),
            esc(&r.received),
            link,
        ));
    }
    h.push_str("</tbody></table>");
    h
}
