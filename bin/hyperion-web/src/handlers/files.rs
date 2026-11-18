//! `/hostings/<sel>/files` — the file manager, scoped to the hosting's
//! htdocs root. Path traversal and symlinks are refused at the adapter; this
//! module owns what the browser sees: URLs, the banner, which controls a role
//! gets, and the line endings a `<textarea>` would otherwise rewrite.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::filters;
use crate::handlers::hostings::{parse_selector_public, require_hosting_access};
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use base64::Engine;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::RpcError;
use hyperion_state::capabilities::Capability;
use hyperion_types::{HostingFileContent, HostingFileEntry};
use serde::Deserialize;

/// Per-file cap, as the adapter enforces it. Said once so the hint, the
/// refusal and the limit cannot drift apart again.
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_FILE_LABEL: &str = "64 MiB";
/// Whole-request cap for an upload: several files, each under the per-file
/// cap. Fields are read and written one at a time, so this bounds the
/// request, not the memory held.
pub const UPLOAD_BODY_LIMIT: usize = 512 * 1024 * 1024;

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
    /// The folder being listed, or the folder of the file being viewed.
    rel_path: String,
    /// `Some` everywhere but the root: where "up" goes.
    parent_path: Option<String>,
    breadcrumbs: Vec<(String, String)>,
    entries: Vec<HostingFileEntry>,
    hidden_count: usize,
    /// Set when `?file=` — the page is then the viewer, not the listing.
    viewer: Option<HostingFileContent>,
    /// Base name of the viewed file.
    viewer_name: String,
    /// `1\n2\n3…` for the viewer's gutter.
    gutter: String,
    line_count: usize,
    error: Option<String>,
    ok: Option<String>,
    /// Whether this user may write here: the same check the write handlers
    /// make, so a button never leads to a 403.
    can_write: bool,
    /// One CSRF token used by every form on the page.
    csrf_token: String,
    /// The viewer is an editor (`?file=…&edit=1`, and the file is editable).
    edit_mode: bool,
    max_file_label: &'static str,
}

#[derive(Deserialize, Default)]
pub struct FilesQuery {
    #[serde(default)]
    pub path: String,
    /// A file's full rel_path: render the viewer instead of the listing.
    #[serde(default)]
    pub file: Option<String>,
    /// "1" → the viewer is an editor.
    #[serde(default)]
    pub edit: Option<String>,
    /// Outcome of the POST that redirected here.
    #[serde(default)]
    pub ok: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// The outcome banner a redirect carries.
enum Flash<'a> {
    Ok(&'a str),
    Err(&'a str),
}

impl Flash<'_> {
    fn query(&self) -> String {
        match self {
            Flash::Ok(m) => format!("ok={}", enc(m)),
            Flash::Err(m) => format!("error={}", enc(m)),
        }
    }
}

/// One component of a query string. Names here are whatever a tenant put on
/// disk — `a&b #1.txt`, `50%.csv` — so every path in a URL goes through this.
fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// An agent refusal as a sentence for the banner: the validation text itself,
/// without the transport's "validation failed:" label in front of it.
fn say(e: &RpcError) -> String {
    let text = match e {
        RpcError::Validation { message } => message.clone(),
        other => other.to_string(),
    };
    // The adapter's catch-all error prints as "other: …"; the label is ours,
    // not something to show an operator.
    text.strip_prefix("other: ").unwrap_or(&text).to_string()
}

/// A single path component an operator typed: a name, not a path.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
}

fn join(dir: &str, name: &str) -> String {
    let dir = dir.trim_matches('/');
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Put back the line endings the file had.
///
/// A browser submits a `<textarea>` with CRLF line breaks whatever was in it,
/// so saving the form's text verbatim turned every LF file — which is every
/// file on a Linux host — into a CRLF one. Normalise to LF first, then to
/// CRLF only when that is what the file used.
pub fn restore_eol(text: &str, crlf: bool) -> String {
    let lf = text.replace("\r\n", "\n");
    if crlf {
        lf.replace('\n', "\r\n")
    } else {
        lf
    }
}

/// `Content-Disposition` for a download. A header value is ASCII, and site
/// files are not (`příloha.pdf`): the plain `filename` gets a safe stand-in
/// and `filename*` carries the real name, percent-encoded (RFC 6266).
pub fn content_disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut star = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            star.push(b as char);
        } else {
            star.push_str(&format!("%{b:02X}"));
        }
    }
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{star}")
}

fn gutter_for(content: &str) -> (String, usize) {
    let n = content.lines().count().max(1);
    let mut g = String::with_capacity(n * 4);
    for i in 1..=n {
        if i > 1 {
            g.push('\n');
        }
        g.push_str(&i.to_string());
    }
    (g, n)
}

/// May this user change files of this hosting? Mirrors `authorize_file_write`.
async fn may_write(state: &SharedState, ctx: &AuthCtx, hosting_id: &str) -> bool {
    !ctx.is_read_only()
        && require_hosting_access(state, ctx, hosting_id, true, Capability::HostingFiles)
            .await
            .is_ok()
}

/// Everything `render` needs beyond the request itself.
struct Page {
    selector: String,
    domain: String,
    rel_path: String,
    entries: Vec<HostingFileEntry>,
    viewer: Option<HostingFileContent>,
    error: Option<String>,
    ok: Option<String>,
    can_write: bool,
    want_edit: bool,
}

fn render(state: &SharedState, ctx: &AuthCtx, p: Page) -> Result<Response, AppError> {
    let edit_mode =
        p.want_edit && p.can_write && p.viewer.as_ref().is_some_and(|v| !v.lossy && !v.truncated);
    let (gutter, line_count) = p
        .viewer
        .as_ref()
        .map(|v| gutter_for(&v.content))
        .unwrap_or_default();
    let viewer_name = p
        .viewer
        .as_ref()
        .map(|v| base_name(&v.rel_path).to_string())
        .unwrap_or_default();
    let tpl = FilesTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        selector: p.selector,
        domain: p.domain,
        parent_path: (!p.rel_path.is_empty()).then(|| parent_dir(&p.rel_path)),
        breadcrumbs: build_breadcrumbs(&p.rel_path),
        hidden_count: p.entries.iter().filter(|e| e.name.starts_with('.')).count(),
        rel_path: p.rel_path,
        entries: p.entries,
        viewer: p.viewer,
        viewer_name,
        gutter,
        line_count,
        error: p.error,
        ok: p.ok,
        can_write: p.can_write,
        csrf_token: super::session_csrf_token(state, ctx),
        edit_mode,
        max_file_label: MAX_FILE_LABEL,
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_files(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<FilesQuery>,
) -> Result<Response, AppError> {
    let sel = parse_selector_public(&selector)?;
    // Cross-node aware lookup — file operations MUST run on the node that
    // owns the hosting (the files are on that node's disk, not master's).
    let (detail, owner_node) =
        crate::handlers::hostings::find_hosting_anywhere(&state, sel.clone()).await?;
    let target = owner_node.as_deref();
    // READ-only browsing: gate on view, not the write cap, so a read-only
    // role can still inspect files. Writes go through authorize_file_write.
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    {
        return Ok(r);
    }
    let can_write = may_write(&state, &ctx, detail.id.as_str()).await;
    let rel = q.path.trim_matches('/').to_string();
    let mut page = Page {
        selector,
        domain: detail.domain,
        rel_path: rel.clone(),
        entries: vec![],
        viewer: None,
        error: q.error.clone().filter(|m| !m.is_empty()),
        ok: q.ok.clone().filter(|m| !m.is_empty()),
        can_write,
        want_edit: q.edit.as_deref() == Some("1"),
    };

    if let Some(file_path) = q.file.as_deref().map(|f| f.trim_matches('/')) {
        let resp = crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::HostingFileRead {
                sel: sel.clone(),
                rel_path: file_path.to_string(),
            },
        )
        .await?;
        match resp {
            // The viewer is the whole page; no listing to fetch.
            RpcResponse::HostingFileRead(c) => {
                page.rel_path = parent_dir(file_path);
                page.viewer = Some(c);
                return render(&state, &ctx, page);
            }
            // Could not open it: say why, above the folder it lives in.
            RpcResponse::Error(e) => {
                page.rel_path = parent_dir(file_path);
                page.error = Some(format!("{}: {}", base_name(file_path), say(&e)));
            }
            _ => return Err(AppError::Internal("unexpected response".into())),
        }
    }

    let list = list_dir(&state, target, sel, page.rel_path.clone()).await;
    page.entries = list.entries;
    if page.error.is_none() {
        page.error = list.error;
    }
    render(&state, &ctx, page)
}

#[derive(Deserialize)]
pub struct EditSaveForm {
    pub selector: String,
    pub rel_path: String,
    pub content: String,
    /// `HostingFileContent::version` from when the editor was opened.
    #[serde(default)]
    pub version: String,
    /// "1" when the file used CRLF line endings.
    #[serde(default)]
    pub crlf: String,
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
    let (owner_node, domain) = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let crlf = form.crlf == "1";
    let text = restore_eol(&form.content, crlf);
    let refusal = if text.len() > MAX_FILE_BYTES {
        Some(format!(
            "Too large to save (the limit is {MAX_FILE_LABEL})."
        ))
    } else {
        let resp = crate::dispatcher::dispatch_to_node(
            &state,
            owner_node.as_deref(),
            Request::HostingFileWrite {
                sel: sel.clone(),
                rel_path: form.rel_path.clone(),
                bytes_b64: base64::engine::general_purpose::STANDARD.encode(text.as_bytes()),
                expect_version: Some(form.version.clone()).filter(|v| !v.is_empty()),
                create_only: false,
            },
        )
        .await?;
        match resp {
            RpcResponse::HostingFileWrite => None,
            RpcResponse::Error(e) => Some(say(&e)),
            _ => return Err(AppError::Internal("unexpected response".into())),
        }
    };
    let Some(why) = refusal else {
        // Stay in the editor so the operator can keep iterating.
        return Ok(Redirect::to(&format!(
            "/hostings/{}/files?file={}&edit=1&{}",
            enc(&form.selector),
            enc(&form.rel_path),
            Flash::Ok("Saved").query()
        ))
        .into_response());
    };

    // Not saved. A redirect would throw away what was typed, so the editor is
    // rendered right here with the text still in it.
    let mut version = form.version.clone();
    let mut error = format!("Not saved: {why}.");
    if why.contains("changed on disk") {
        // Hand the editor the file's CURRENT version: the operator has now
        // been told, so pressing Save again is a decision to overwrite.
        version = match crate::dispatcher::dispatch_to_node(
            &state,
            owner_node.as_deref(),
            Request::HostingFileRead {
                sel,
                rel_path: form.rel_path.clone(),
            },
        )
        .await
        {
            Ok(RpcResponse::HostingFileRead(c)) => c.version,
            _ => String::new(),
        };
        error = "Not saved: this file changed on disk after you opened it. \
                 Your text is still below. Saving again will overwrite the other change; \
                 open the file in a new tab first to see what it was."
            .into();
    }
    let size = text.len() as u64;
    render(
        &state,
        &ctx,
        Page {
            selector: form.selector,
            domain,
            rel_path: parent_dir(&form.rel_path),
            entries: vec![],
            viewer: Some(HostingFileContent {
                mime: String::new(),
                size,
                content: text.replace("\r\n", "\n"),
                truncated: false,
                version,
                lossy: false,
                crlf,
                rel_path: form.rel_path,
            }),
            error: Some(error),
            ok: None,
            can_write: true,
            want_edit: true,
        },
    )
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
/// **manage** access to that specific hosting. Returns the owner node and the
/// hosting's domain.
///
/// SECURITY: the write handlers (edit-save / delete / mkdir / rename / upload /
/// new-file) previously only checked `require_write` (= "not the viewer role"),
/// so any tenant-scoped operator or customer could write/delete/upload into ANY
/// hosting's tree just by passing a different selector — e.g. overwrite a
/// victim's `wp-config.php` or drop a PHP webshell into another tenant's site
/// (→ RCE). The READ handlers already gate with `require_hosting_access`; this
/// brings the writes to parity (manage level). On any failure it returns the
/// Response to send (Forbidden / NotFound), mirroring `require_hosting_access`.
async fn authorize_file_write(
    state: &SharedState,
    ctx: &AuthCtx,
    sel: &hyperion_rpc::wire::HostingSelector,
) -> Result<(Option<String>, String), Response> {
    let (detail, owner_node) = crate::handlers::hostings::find_hosting_anywhere(state, sel.clone())
        .await
        .map_err(|e| e.into_response())?;
    require_hosting_access(
        state,
        ctx,
        detail.id.as_str(),
        true,
        Capability::HostingFiles,
    )
    .await?;
    Ok((owner_node, detail.domain))
}

fn redirect_back(selector: &str, dir: &str, flash: Flash<'_>) -> Response {
    Redirect::to(&format!(
        "/hostings/{}/files?path={}&{}",
        enc(selector),
        enc(dir.trim_matches('/')),
        flash.query()
    ))
    .into_response()
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub selector: String,
    pub rel_path: String,
    /// Folder to return to.
    #[serde(default)]
    pub dir: String,
    /// "1" → a folder goes with everything in it. The form sends it only for
    /// folders, behind a dialog that makes the operator type the name.
    #[serde(default)]
    pub recursive: String,
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
    let (owner_node, _) = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileDelete {
            sel,
            rel_path: form.rel_path.clone(),
            recursive: form.recursive == "1",
        },
    )
    .await?;
    let name = base_name(&form.rel_path);
    match resp {
        RpcResponse::HostingFileDelete => Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Ok(&format!("Deleted {name}")),
        )),
        RpcResponse::Error(e) => Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Err(&format!("Could not delete {name}: {}", say(&e))),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct NameForm {
    pub selector: String,
    /// The folder we're sitting in.
    #[serde(default)]
    pub dir: String,
    /// New name (single component — no slashes).
    pub name: String,
}

const BAD_NAME: &str = "That name will not work: a name cannot be empty, “.” or “..”, \
                        or contain a slash.";

pub async fn post_mkdir(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NameForm>,
) -> Result<Response, AppError> {
    if let Some(r) = require_write(&ctx) {
        return Ok(r);
    }
    let name = form.name.trim();
    if !valid_name(name) {
        return Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Err(BAD_NAME),
        ));
    }
    let sel = parse_selector_public(&form.selector)?;
    let (owner_node, _) = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileMkdir {
            sel,
            rel_path: join(&form.dir, name),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingFileMkdir => Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Ok(&format!("Created folder {name}")),
        )),
        RpcResponse::Error(e) => Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Err(&format!("Could not create {name}: {}", say(&e))),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Create an empty file and open it in the editor.
pub async fn post_new_file(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NameForm>,
) -> Result<Response, AppError> {
    if let Some(r) = require_write(&ctx) {
        return Ok(r);
    }
    let name = form.name.trim();
    if !valid_name(name) {
        return Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Err(BAD_NAME),
        ));
    }
    let sel = parse_selector_public(&form.selector)?;
    let (owner_node, _) = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    // `create_only` is the real guard, but a node on an older release ignores
    // the field and would overwrite. Look first, so "New file" can never
    // empty an existing one whatever the node runs.
    let listing = list_dir(
        &state,
        owner_node.as_deref(),
        sel.clone(),
        form.dir.trim_matches('/').to_string(),
    )
    .await;
    if let Some(e) = listing.error {
        return Ok(redirect_back(&form.selector, &form.dir, Flash::Err(&e)));
    }
    if listing.entries.iter().any(|e| e.name == name) {
        return Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Err(&format!("{name} already exists here.")),
        ));
    }
    let rel_path = join(&form.dir, name);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileWrite {
            sel,
            rel_path: rel_path.clone(),
            bytes_b64: String::new(),
            expect_version: None,
            create_only: true,
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingFileWrite => Ok(Redirect::to(&format!(
            "/hostings/{}/files?file={}&edit=1",
            enc(&form.selector),
            enc(&rel_path)
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Err(&format!("Could not create {name}: {}", say(&e))),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct RenameForm {
    pub selector: String,
    #[serde(default)]
    pub dir: String,
    pub from: String,
    /// New name (single component). `name` is what the shared name dialog
    /// posts; `to_name` is the field's older spelling.
    #[serde(alias = "to_name")]
    pub name: String,
}

pub async fn post_rename(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RenameForm>,
) -> Result<Response, AppError> {
    if let Some(r) = require_write(&ctx) {
        return Ok(r);
    }
    let to_name = form.name.trim();
    if !valid_name(to_name) {
        return Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Err(BAD_NAME),
        ));
    }
    let old = base_name(&form.from).to_string();
    if to_name == old {
        return Ok(redirect_back(&form.selector, &form.dir, Flash::Ok("")));
    }
    // The new name is a sibling of the old one.
    let to = join(&parent_dir(&form.from), to_name);
    let sel = parse_selector_public(&form.selector)?;
    let (owner_node, _) = match authorize_file_write(&state, &ctx, &sel).await {
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
        RpcResponse::HostingFileRename => Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Ok(&format!("Renamed {old} to {to_name}")),
        )),
        RpcResponse::Error(e) => Ok(redirect_back(
            &form.selector,
            &form.dir,
            Flash::Err(&format!("Could not rename {old}: {}", say(&e))),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Upload via multipart — every `file` field is one uploaded file, `dir` is
/// the destination folder (sent first, so it is known before the files).
/// CSRF rides in the `?_csrf=` query string per the multipart pattern.
///
/// Files are written as they arrive, one at a time, and the outcome is one
/// banner: how many landed, and which did not and why.
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
    // Authorize (manage access to THIS hosting) before reading the body, so
    // an unauthorized cross-tenant upload is rejected early.
    let (owner_node, _) = match authorize_file_write(&state, &ctx, &sel).await {
        Ok(n) => n,
        Err(resp) => return Ok(resp),
    };
    let mut dir = String::new();
    let mut done = 0usize;
    let mut failed: Vec<String> = Vec::new();
    // A multipart error is almost always the body cap. That is the
    // operator's file being too big, not a server fault: say so on the page
    // instead of the "something went wrong on our side" 500.
    let cut_short = |done: usize| {
        format!(
            "The upload was cut short{}: the request was too large or malformed. \
             The limit is {MAX_FILE_LABEL} per file.",
            if done > 0 {
                format!(" after {done} file(s)")
            } else {
                String::new()
            }
        )
    };
    loop {
        let field = match mp.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => return Ok(redirect_back(&selector, &dir, Flash::Err(&cut_short(done)))),
        };
        match field.name().unwrap_or("") {
            "dir" => {
                dir = match field.text().await {
                    Ok(t) => t,
                    Err(_) => {
                        return Ok(redirect_back(&selector, &dir, Flash::Err(&cut_short(done))))
                    }
                };
            }
            "file" => {
                // Never trust a client's file name: keep the last component.
                // An empty one is the browser's "no file chosen".
                let raw = field.file_name().unwrap_or("").replace('\\', "/");
                let name = base_name(&raw).to_string();
                let bytes = match field.bytes().await {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(redirect_back(&selector, &dir, Flash::Err(&cut_short(done))))
                    }
                };
                if name.is_empty() {
                    continue;
                }
                if !valid_name(&name) {
                    failed.push(format!("{name}: not a usable file name"));
                    continue;
                }
                if bytes.len() > MAX_FILE_BYTES {
                    failed.push(format!("{name}: larger than {MAX_FILE_LABEL}"));
                    continue;
                }
                let resp = crate::dispatcher::dispatch_to_node(
                    &state,
                    owner_node.as_deref(),
                    Request::HostingFileWrite {
                        sel: sel.clone(),
                        rel_path: join(&dir, &name),
                        bytes_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
                        expect_version: None,
                        create_only: false,
                    },
                )
                .await?;
                match resp {
                    RpcResponse::HostingFileWrite => done += 1,
                    RpcResponse::Error(e) => failed.push(format!("{name}: {}", say(&e))),
                    _ => return Err(AppError::Internal("unexpected response".into())),
                }
            }
            _ => {} // ignore unknown fields
        }
    }
    let uploaded = match done {
        1 => "Uploaded 1 file".to_string(),
        n => format!("Uploaded {n} files"),
    };
    if !failed.is_empty() {
        let lead = if done > 0 {
            format!("{uploaded}, but not: ")
        } else {
            "Not uploaded: ".to_string()
        };
        return Ok(redirect_back(
            &selector,
            &dir,
            Flash::Err(&format!("{lead}{}", failed.join("; "))),
        ));
    }
    if done == 0 {
        return Ok(redirect_back(
            &selector,
            &dir,
            Flash::Err("No file was chosen."),
        ));
    }
    Ok(redirect_back(&selector, &dir, Flash::Ok(&uploaded)))
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
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        // READ-only browsing/download: gate on view, not the write cap, so a
        // read-only role (Viewer) can still inspect files. The WRITE handlers go
        // through authorize_file_write → HostingFiles.
        Capability::HostingView,
    )
    .await
    {
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
                    (header::CONTENT_DISPOSITION, content_disposition(fname)),
                ],
                bytes,
            )
                .into_response())
        }
        RpcResponse::Error(e) => Err(AppError::from(e)),
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
            error: Some(say(&e)),
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
    match path.trim_matches('/').rfind('/') {
        Some(i) => path.trim_matches('/')[..i].to_string(),
        None => String::new(),
    }
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
        assert_eq!(parent_dir("/a/b/"), "a");
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

    /// A browser sends CRLF for every line break in a textarea. An LF file
    /// must come back LF, a CRLF file CRLF, and neither may grow `\r\r\n`.
    #[test]
    fn a_save_keeps_the_files_line_endings() {
        let from_browser = "<?php\r\necho 1;\r\n";
        assert_eq!(restore_eol(from_browser, false), "<?php\necho 1;\n");
        assert_eq!(restore_eol(from_browser, true), "<?php\r\necho 1;\r\n");
        // A script that posts LF gets the same result.
        assert_eq!(restore_eol("a\nb\n", true), "a\r\nb\r\n");
        assert_eq!(restore_eol("a\nb\n", false), "a\nb\n");
        // A leading blank line is content.
        assert_eq!(restore_eol("\r\nfirst", false), "\nfirst");
    }

    #[test]
    fn download_names_survive_as_a_header() {
        let v = content_disposition("příloha (1).pdf");
        assert!(
            v.contains("filename*=UTF-8''p%C5%99%C3%ADloha%20%281%29.pdf"),
            "{v}"
        );
        assert!(v.contains("filename=\"p__loha (1).pdf\""), "{v}");
        // The point of the exercise: axum can put it on a response.
        axum::http::HeaderValue::from_str(&v).expect("a valid header value");
        // Nothing a name holds may close the quoted string or add a header.
        let hostile = content_disposition("a\"; x=\"b\r\nSet-Cookie: c.txt");
        assert!(!hostile.contains('\r') && !hostile.contains('\n'));
        assert_eq!(hostile.matches('"').count(), 2, "{hostile}");
        axum::http::HeaderValue::from_str(&hostile).expect("still valid");
    }

    #[test]
    fn paths_in_urls_are_encoded_not_html_escaped() {
        let e = enc("a&b #1+50%?.txt");
        for c in ['&', '#', '+', '%', '?', ' '] {
            // `%` and `+` appear only as the encoding's own syntax.
            if c != '%' && c != '+' {
                assert!(!e.contains(c), "{c:?} left bare in {e}");
            }
        }
        let back: String = url::form_urlencoded::parse(format!("p={e}").as_bytes())
            .next()
            .expect("pair")
            .1
            .into_owned();
        assert_eq!(back, "a&b #1+50%?.txt");
        assert_eq!(
            filters::urlq("wp-content/a b").expect("filter"),
            "wp-content%2Fa+b"
        );
    }

    #[test]
    fn names_are_single_components() {
        for ok in ["a.txt", ".htaccess", "příloha.pdf", "a b", "..hidden"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a\\b", "a\nb", "a\0b"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert_eq!(join("", "a"), "a");
        assert_eq!(join("/x/y/", "a"), "x/y/a");
    }

    #[test]
    fn the_gutter_numbers_every_line() {
        assert_eq!(gutter_for(""), ("1".to_string(), 1));
        assert_eq!(gutter_for("a\nb\n"), ("1\n2".to_string(), 2));
        assert_eq!(gutter_for("a\nb\nc"), ("1\n2\n3".to_string(), 3));
    }

    #[test]
    fn refusals_read_as_sentences() {
        let e = RpcError::Validation {
            message: "other: path already exists".into(),
        };
        assert_eq!(say(&e), "path already exists");
    }

    #[test]
    fn flashes_carry_their_kind() {
        assert_eq!(Flash::Ok("Saved").query(), "ok=Saved");
        assert_eq!(Flash::Err("no & no").query(), "error=no+%26+no");
    }
}
