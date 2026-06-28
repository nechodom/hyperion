//! Migration bundle download + import-from-URL.
//!
//! Three endpoints living here:
//!
//! - `GET /api/migration/bundle/:bundle_id/:filename` — PUBLIC (no
//!   cookie auth). Streams `manifest.json` or `archive.tar.gz` to
//!   any caller who presents a valid `?t=<token>` signed for this
//!   bundle. The token is minted by `post_migration_export` and
//!   expires 1h after creation. Source-side endpoint — runs on the
//!   node that holds the bundle on disk.
//!
//! - `POST /hostings/migration/import-from-url` — AUTHENTICATED.
//!   Operator pastes the source's signed URL + token, this handler
//!   delegates to `HostingService::hosting_import_from_url` which
//!   downloads + verifies + provisions. Target-side endpoint.
//!
//! - `GET /hostings/import` — AUTHENTICATED. Renders the form for
//!   the import-from-URL flow.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use serde::Deserialize;
use tokio_util::io::ReaderStream;

/// One-hour lifetime for download tokens. Long enough that an
/// operator who clicks "Export" and then walks away can still come
/// back to copy the URL; short enough that an accidentally-shared
/// URL has a tight blast radius.
pub const BUNDLE_DOWNLOAD_TTL_SECS: i64 = 60 * 60;

/// Whitelisted filenames inside a bundle dir. Anything else 404s —
/// stops `..` and friends from escaping the bundle directory even
/// though we already do path-join validation below.
const ALLOWED_FILES: &[&str] = &["manifest.json", "archive.tar.gz"];

#[derive(Deserialize)]
pub struct DownloadQuery {
    pub t: String,
}

/// GET /api/migration/bundle/:bundle_id/:filename?t=<token>
///
/// Public. The signature is the access control.
pub async fn get_bundle_file(
    State(state): State<SharedState>,
    Path((bundle_id, filename)): Path<(String, String)>,
    Query(q): Query<DownloadQuery>,
) -> Result<Response, AppError> {
    // Validate bundle_id shape — only `mig_<26-char ULID>` is legal.
    if !bundle_id.starts_with("mig_") || bundle_id.len() != 4 + 26 {
        return Ok((StatusCode::NOT_FOUND, "not found").into_response());
    }
    if !bundle_id[4..].chars().all(|c| c.is_ascii_alphanumeric()) {
        return Ok((StatusCode::NOT_FOUND, "not found").into_response());
    }
    if !ALLOWED_FILES.contains(&filename.as_str()) {
        return Ok((StatusCode::NOT_FOUND, "not found").into_response());
    }

    // Verify signature.
    let exp = match hyperion_auth::bundle_sig::verify(state.csrf_key.as_ref(), &bundle_id, &q.t) {
        Ok(e) => e,
        Err(reason) => {
            tracing::warn!(bundle_id, reason, "migration download: bad token");
            return Ok((StatusCode::FORBIDDEN, "invalid token").into_response());
        }
    };
    if hyperion_types::now_secs() > exp {
        return Ok((StatusCode::FORBIDDEN, "token expired").into_response());
    }

    // Path is bundle_dir/<filename>. We use Path::join which protects
    // against absolute-path injection (already gated by ALLOWED_FILES
    // whitelist; this is the defense-in-depth layer).
    let bundle_dir = std::path::PathBuf::from("/var/lib/hyperion/migration").join(&bundle_id);
    let file_path = bundle_dir.join(&filename);
    if !file_path.starts_with(&bundle_dir) {
        return Ok((StatusCode::NOT_FOUND, "not found").into_response());
    }

    let file = match tokio::fs::File::open(&file_path).await {
        Ok(f) => f,
        Err(_) => return Ok((StatusCode::NOT_FOUND, "bundle missing on disk").into_response()),
    };
    let meta = file
        .metadata()
        .await
        .map_err(|e| AppError::Internal(format!("stat: {e}")))?;
    let len = meta.len();

    // Stream the body — for multi-GB archives we MUST NOT collect into
    // memory. ReaderStream wraps the AsyncRead in a Stream<Bytes>.
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let ct = if filename == "manifest.json" {
        "application/json"
    } else {
        "application/gzip"
    };
    use axum::http::HeaderValue;
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    // `ct` and the cache-control value are static + always-valid → from_static
    // is infallible. The length + filename headers can't realistically fail
    // either, but fall back to a static value rather than unwrap.
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
    h.insert(
        header::CONTENT_LENGTH,
        len.to_string()
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(resp)
}

#[derive(Template)]
#[template(path = "migration_import.html")]
struct MigrationImportTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    error: Option<String>,
    flash: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct ImportQuery {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub flash: Option<String>,
}

pub async fn get_import(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<ImportQuery>,
) -> Result<Response, AppError> {
    let tpl = MigrationImportTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(&state, &ctx),
        error: q.error.clone(),
        flash: q.flash.clone(),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct ImportFromUrlForm {
    pub base_url: String,
    pub token: String,
}

pub async fn post_import_from_url(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ImportFromUrlForm>,
) -> Result<Response, AppError> {
    // Admin-or-higher: creating a hosting is admin-level, importing
    // is the same operation under the hood.
    if !ctx.can(Capability::HostingMigrateClone) {
        return Ok(Redirect::to("/hostings/import?error=admin+role+required").into_response());
    }
    let base = form.base_url.trim().to_string();
    let token = form.token.trim().to_string();
    if base.is_empty() || token.is_empty() {
        return Ok(
            Redirect::to("/hostings/import?error=both+URL+and+token+are+required").into_response(),
        );
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingImportFromUrl {
            base_url: base,
            token,
            override_domain: None,
            override_aliases: Vec::new(),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingImportFromUrl(r) => {
            // Redirect straight to the imported hosting's detail page.
            let url = format!(
                "/hostings/{}?flash=Imported+{}+bytes",
                urlencode(&r.domain),
                r.restored_bytes
            );
            Ok(Redirect::to(&url).into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/import?error={}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
