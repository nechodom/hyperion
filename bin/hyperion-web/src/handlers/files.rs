//! `/hostings/<sel>/files` — file browser scoped to the hosting's
//! htdocs root. Path traversal + symlinks already refused at the
//! adapter layer; this handler plumbs URL → RPC → template, plus
//! the write endpoints (upload / delete / mkdir / rename / download).

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::handlers::hostings::{parse_selector_public, require_hosting_access};
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use base64::Engine;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{HostingFileContent, HostingFileEntry};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "hosting_files.html")]
struct FilesTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    selector: String,
    domain: String,
    rel_path: String,
    breadcrumbs: Vec<(String, String)>,
    entries: Vec<HostingFileEntry>,
    /// Set when ?file=<rel_path> — renders inline viewer.
    viewer: Option<HostingFileContent>,
    error: Option<String>,
    /// Whether the current user can write (mkdir/upload/delete/rename).
    /// Viewers see only the read-only UI.
    can_write: bool,
    /// One CSRF token used by every form on the files page.
    csrf_token: String,
    /// Optional flash from ?flash=...; rendered as a green banner.
    flash: Option<String>,
    /// When true, the viewer renders an editable textarea + Save
    /// button instead of a read-only `<pre>`. Triggered by
    /// `?file=...&edit=1`.
    edit_mode: bool,
}

#[derive(Deserialize, Default)]
pub struct FilesQuery {
    #[serde(default)]
    pub path: String,
    /// When set, renders the file viewer instead of the listing.
    /// `file` is a full rel_path (e.g. "wp-content/themes/style.css").
    #[serde(default)]
    pub file: Option<String>,
    /// Set after a successful POST → green banner in the UI.
    #[serde(default)]
    pub flash: Option<String>,
    /// "1" → render the viewer in edit mode (textarea + Save button).
    #[serde(default)]
    pub edit: Option<String>,
}

pub async fn get_files(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<FilesQuery>,
) -> Result<Response, AppError> {
    let sel = parse_selector_public(&selector)?;
    // Cross-node aware lookup — file operations MUST run on the
    // node that owns the hosting (files live in /home/<user>/...
    // on that node's disk, not master's). find_hosting_anywhere
    // checks master first, then fans out to every worker.
    let (detail, owner_node) =
        crate::handlers::hostings::find_hosting_anywhere(&state, sel.clone()).await?;
    let target = owner_node.as_deref();
    // RBAC: same guard as detail page — read level is fine.
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }

    // Decide whether we're browsing a directory or viewing a file.
    let (viewer, rel_path, entries, error) = if let Some(file_path) = q.file.clone() {
        let resp = crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::HostingFileRead {
                sel: sel.clone(),
                rel_path: file_path.clone(),
            },
        )
        .await?;
        match resp {
            RpcResponse::HostingFileRead(c) => {
                // Re-list the parent dir so the listing still shows.
                let parent = parent_dir(&file_path);
                let list = list_dir(&state, target, sel.clone(), parent.clone()).await;
                (Some(c), parent, list.entries, list.error)
            }
            RpcResponse::Error(e) => {
                let list = list_dir(&state, target, sel.clone(), q.path.clone()).await;
                (None, q.path.clone(), list.entries, Some(e.to_string()))
            }
            _ => return Err(AppError::Internal("unexpected response".into())),
        }
    } else {
        let list = list_dir(&state, target, sel.clone(), q.path.clone()).await;
        (None, q.path.clone(), list.entries, list.error)
    };

    let breadcrumbs = build_breadcrumbs(&rel_path);

    let can_write = !ctx.is_read_only();
    let edit_mode = q.edit.as_deref() == Some("1") && viewer.is_some() && can_write;
    let tpl = FilesTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        selector,
        domain: detail.domain,
        rel_path,
        breadcrumbs,
        entries,
        viewer,
        error,
        can_write,
        csrf_token: super::session_csrf_token(&state, &ctx),
        flash: q.flash.clone(),
        edit_mode,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct EditSaveForm {
    pub selector: String,
    pub rel_path: String,
    pub content: String,
}

pub async fn post_edit_save(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<EditSaveForm>,
) -> Result<Response, AppError> {
    if let Some(r) = require_write(&ctx) {
        return Ok(r);
    }
    let sel = parse_selector_public(&form.selector)?;
    let owner_node = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let bytes_b64 = base64::engine::general_purpose::STANDARD.encode(form.content.as_bytes());
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileWrite {
            sel,
            rel_path: form.rel_path.clone(),
            bytes_b64,
        },
    )
    .await?;
    let parent = parent_dir(&form.rel_path);
    match resp {
        RpcResponse::HostingFileWrite => {
            // Stay on the editor after save so the operator can keep
            // iterating; flash banner confirms the write landed.
            Ok(Redirect::to(&format!(
                "/hostings/{}/files?path={}&file={}&edit=1&flash=Saved",
                crate::handlers::hostings::urlencoding(&form.selector),
                crate::handlers::hostings::urlencoding(&parent),
                crate::handlers::hostings::urlencoding(&form.rel_path)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/{}/files?path={}&file={}&edit=1&flash={}",
            crate::handlers::hostings::urlencoding(&form.selector),
            crate::handlers::hostings::urlencoding(&parent),
            crate::handlers::hostings::urlencoding(&form.rel_path),
            crate::handlers::hostings::urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// ─────────── Write handlers ───────────

/// Guard: refuse non-writers up front so we don't even round-trip
/// to the agent. The agent enforces too, but bouncing early is
/// cheaper + gives a nicer error.
fn require_write(ctx: &AuthCtx) -> Option<Response> {
    if ctx.is_read_only() {
        return Some((StatusCode::FORBIDDEN, "viewer role cannot modify files").into_response());
    }
    None
}

/// Resolve a file-manager selector's owner node AND enforce that the caller has
/// **manage** access to that specific hosting.
///
/// SECURITY: the write handlers (edit-save / delete / mkdir / rename / upload)
/// previously only checked `require_write` (= "not the viewer role"), so any
/// tenant-scoped operator or customer could write/delete/upload into ANY
/// hosting's tree just by passing a different selector — e.g. overwrite a
/// victim's `wp-config.php` or drop a PHP webshell into another tenant's site
/// (→ RCE). The READ handlers already gate with `require_hosting_access`; this
/// brings the writes to parity (manage level). On any failure it returns the
/// Response to send (Forbidden / NotFound), mirroring `require_hosting_access`.
async fn authorize_file_write(
    state: &SharedState,
    ctx: &AuthCtx,
    sel: &hyperion_rpc::wire::HostingSelector,
) -> Result<Option<String>, Response> {
    let (detail, owner_node) = crate::handlers::hostings::find_hosting_anywhere(state, sel.clone())
        .await
        .map_err(|e| e.into_response())?;
    require_hosting_access(state, ctx, detail.id.as_str(), true).await?;
    Ok(owner_node)
}

fn redirect_back(selector: &str, rel_path: &str, flash: &str) -> Response {
    let q = format!(
        "?path={}&flash={}",
        crate::handlers::hostings::urlencoding(rel_path),
        crate::handlers::hostings::urlencoding(flash)
    );
    Redirect::to(&format!(
        "/hostings/{}/files{}",
        crate::handlers::hostings::urlencoding(selector),
        q
    ))
    .into_response()
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub selector: String,
    pub rel_path: String,
    #[serde(default)]
    pub dir: String, // optional return path for the redirect
}

pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    if let Some(r) = require_write(&ctx) {
        return Ok(r);
    }
    let sel = parse_selector_public(&form.selector)?;
    let owner_node = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileDelete {
            sel,
            rel_path: form.rel_path.clone(),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingFileDelete => Ok(redirect_back(&form.selector, &form.dir, "Deleted")),
        RpcResponse::Error(e) => Ok(redirect_back(&form.selector, &form.dir, &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct MkdirForm {
    pub selector: String,
    /// Parent dir we're sitting in.
    #[serde(default)]
    pub dir: String,
    /// New directory name (single component — no slashes).
    pub name: String,
}

pub async fn post_mkdir(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<MkdirForm>,
) -> Result<Response, AppError> {
    if let Some(r) = require_write(&ctx) {
        return Ok(r);
    }
    if form.name.contains('/') || form.name.contains('\\') || form.name.contains('\0') {
        return Ok(redirect_back(&form.selector, &form.dir, "Invalid name"));
    }
    let sel = parse_selector_public(&form.selector)?;
    let owner_node = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let rel_path = if form.dir.is_empty() {
        form.name.clone()
    } else {
        format!("{}/{}", form.dir.trim_end_matches('/'), form.name)
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileMkdir {
            sel,
            rel_path: rel_path.clone(),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingFileMkdir => Ok(redirect_back(&form.selector, &form.dir, "Created")),
        RpcResponse::Error(e) => Ok(redirect_back(&form.selector, &form.dir, &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct RenameForm {
    pub selector: String,
    #[serde(default)]
    pub dir: String,
    pub from: String,
    /// New name (single component).
    pub to_name: String,
}

pub async fn post_rename(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RenameForm>,
) -> Result<Response, AppError> {
    if let Some(r) = require_write(&ctx) {
        return Ok(r);
    }
    if form.to_name.contains('/') || form.to_name.contains('\\') || form.to_name.contains('\0') {
        return Ok(redirect_back(&form.selector, &form.dir, "Invalid new name"));
    }
    // Build `to` path as siblings of `from`.
    let parent = parent_dir(&form.from);
    let to = if parent.is_empty() {
        form.to_name.clone()
    } else {
        format!("{}/{}", parent, form.to_name)
    };
    let sel = parse_selector_public(&form.selector)?;
    let owner_node = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileRename {
            sel,
            from: form.from.clone(),
            to,
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingFileRename => Ok(redirect_back(&form.selector, &form.dir, "Renamed")),
        RpcResponse::Error(e) => Ok(redirect_back(&form.selector, &form.dir, &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Upload via multipart — `field "file"` is the uploaded file,
/// `field "dir"` is the destination directory inside htdocs. CSRF
/// rides in the `?_csrf=` query string per the multipart pattern
/// established by the WP asset upload flow.
pub async fn post_upload(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    mut mp: Multipart,
) -> Result<Response, AppError> {
    if let Some(r) = require_write(&ctx) {
        return Ok(r);
    }
    let sel = parse_selector_public(&selector)?;
    // Authorize (manage access to THIS hosting) before reading the up-to-100 MB
    // multipart body, so an unauthorized cross-tenant upload is rejected early.
    let owner_node = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let mut dir = String::new();
    let mut filename: Option<String> = None;
    let mut bytes: Vec<u8> = Vec::new();
    // Multipart errors here are almost always "body too large" (the
    // route caps the body at 100 MB via DefaultBodyLimit). That is an
    // operator/client mistake, not a server fault — surface it as a
    // friendly redirect-back, NOT AppError::Internal (which renders the
    // scary "Something went wrong on our side" 500 page). Mirrors the
    // empty-upload handling below and the avatar/restore upload paths.
    let too_large = |dir: &str, e: &dyn std::fmt::Display| {
        redirect_back(
            &selector,
            dir,
            &format!("Upload failed — file too large (max 100 MB) or malformed: {e}"),
        )
    };
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return Ok(too_large(&dir, &e)),
        };
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "dir" => {
                dir = match field.text().await {
                    Ok(t) => t,
                    Err(e) => return Ok(too_large(&dir, &e)),
                };
            }
            "file" => {
                let fname = field.file_name().unwrap_or("upload.bin").to_string();
                // Strip any path components — never trust client filenames.
                let clean = std::path::Path::new(&fname)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("upload.bin")
                    .to_string();
                filename = Some(clean);
                bytes = match field.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => return Ok(too_large(&dir, &e)),
                };
            }
            _ => {} // ignore unknown fields
        }
    }
    let Some(fname) = filename else {
        return Ok(redirect_back(&selector, &dir, "No file"));
    };
    if bytes.is_empty() {
        return Ok(redirect_back(&selector, &dir, "Empty upload"));
    }
    let rel_path = if dir.is_empty() {
        fname.clone()
    } else {
        format!("{}/{}", dir.trim_end_matches('/'), fname)
    };
    let bytes_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileWrite {
            sel,
            rel_path,
            bytes_b64,
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingFileWrite => Ok(redirect_back(&selector, &dir, "Uploaded")),
        RpcResponse::Error(e) => Ok(redirect_back(&selector, &dir, &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    pub path: String,
}

pub async fn get_download(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DownloadQuery>,
) -> Result<Response, AppError> {
    let sel = parse_selector_public(&selector)?;
    // Cross-node aware — the file lives on the owner node's disk.
    let (detail, owner_node) =
        crate::handlers::hostings::find_hosting_anywhere(&state, sel.clone()).await?;
    let target = owner_node.as_deref();
    // Read access is enough for download — same as the inline reader.
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingFileDownload {
            sel,
            rel_path: q.path.clone(),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingFileDownload {
            rel_path,
            bytes_b64,
            mime,
        } => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(bytes_b64.as_bytes())
                .map_err(|e| AppError::Internal(format!("b64: {e}")))?;
            // Browser-safe download filename (strip path).
            let fname = std::path::Path::new(&rel_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("download.bin");
            Ok((
                [
                    (header::CONTENT_TYPE, mime),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", fname.replace('"', "")),
                    ),
                ],
                bytes,
            )
                .into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

struct DirListing {
    entries: Vec<HostingFileEntry>,
    error: Option<String>,
}

async fn list_dir(
    state: &SharedState,
    target: Option<&str>,
    sel: hyperion_rpc::wire::HostingSelector,
    rel_path: String,
) -> DirListing {
    match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::HostingFileList { sel, rel_path },
    )
    .await
    {
        Ok(RpcResponse::HostingFileList { entries, .. }) => DirListing {
            entries,
            error: None,
        },
        Ok(RpcResponse::Error(e)) => DirListing {
            entries: vec![],
            error: Some(e.to_string()),
        },
        Ok(_) => DirListing {
            entries: vec![],
            error: Some("unexpected response".into()),
        },
        Err(e) => DirListing {
            entries: vec![],
            error: Some(format!("rpc: {e}")),
        },
    }
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

/// Public helper used by the template to render "Up one level" link.
/// Askama can't call private functions, so this is the export.
pub fn parent_path_for_template(path: &str) -> String {
    parent_dir(path)
}

/// `fmt_bytes` from the stats handler is `&i64 -> String`, but file
/// sizes are `u64`. Convert here so the template doesn't need a cast
/// (askama can't parse `as i64`).
pub fn fmt_size_u64(n: &u64) -> String {
    crate::handlers::stats::fmt_bytes(&(*n as i64))
}

/// Build clickable breadcrumb segments. Each tuple is (display, link path).
fn build_breadcrumbs(rel_path: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    out.push(("htdocs".to_string(), String::new()));
    if rel_path.is_empty() {
        return out;
    }
    let mut accum = String::new();
    for seg in rel_path.split('/').filter(|s| !s.is_empty()) {
        if !accum.is_empty() {
            accum.push('/');
        }
        accum.push_str(seg);
        out.push((seg.to_string(), accum.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_dir_handles_typical_cases() {
        assert_eq!(parent_dir(""), "");
        assert_eq!(parent_dir("file.txt"), "");
        assert_eq!(parent_dir("dir/file.txt"), "dir");
        assert_eq!(parent_dir("a/b/c.txt"), "a/b");
    }

    #[test]
    fn breadcrumbs_split_correctly() {
        assert_eq!(
            build_breadcrumbs(""),
            vec![("htdocs".to_string(), "".to_string())]
        );
        assert_eq!(
            build_breadcrumbs("wp-content/themes"),
            vec![
                ("htdocs".to_string(), "".to_string()),
                ("wp-content".to_string(), "wp-content".to_string()),
                ("themes".to_string(), "wp-content/themes".to_string()),
            ]
        );
    }
}
