//! Import through a WordPress plugin: for a site on a host that offers no shell
//! and no panel we can read, which is most shared hosting.
//!
//! The operator generates a code here and pastes it into the plugin in the
//! site's wp-admin. The plugin then pushes the site: its PHP runs in short slices
//! driven by the browser tab, and each slice is sent here straight away, so the
//! source needs neither a long execution limit nor spare disk.
//!
//! The upload routes are PUBLIC, the same as the one-command wizard's: the source
//! has no session and the token is the credential. They live under
//! `/import/upload/` because the panel's nginx vhost already lifts its body limit
//! there, so no vhost change is needed.
//!
//! Unlike the wizard's single bundle, a plugin upload is two streams whose final
//! size and digest nobody knows up front: PHP cannot carry a hash context between
//! requests on every version we meet. Each chunk carries its own SHA-256 instead,
//! the server stays authoritative about each stream's offset, and the finished
//! streams are checked and turned into an ordinary bundle by the import job.

use super::import_wizard::{
    avail_bytes, bearer, ensure_migration_dir, final_path, migration_dir, resolve, text, token_rpc,
    update, wire_safe_domain, MAX_CHUNK_BYTES, PLUGIN_KIND as SOURCE_KIND,
};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_import::wordpress::{self, WpSource, WpTarget, DB_STREAM, FILES_STREAM};
use hyperion_import::SiteImportOverride;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{ImportTokenOp, ImportTokenResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Same life as the one-command wizard's token. Every chunk extends it.
const TOKEN_TTL_SECS: i64 = 4 * 60 * 60;
/// What the plugin is told to send per chunk. It sends less when its own memory
/// limit is lower, and slices are bounded by time as well.
const PREFERRED_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
/// A chunk is refused below this much free disk. `begin` checks against the size
/// the source declared, which is the source's word and can be wrong or a lie.
const CHUNK_FREE_FLOOR: u64 = hyperion_import::bundle::IMPORT_HEADROOM_BYTES;
/// Where a chunk waits until it is whole and its digest checks out.
const CHUNK_PART: &str = "chunk.part";
/// Prefix of the pasted code, so the plugin can say "this is not a code" and a
/// future format can be told apart.
const CODE_PREFIX: &str = "HYP1.";

const PLUGIN_PHP: &str = include_str!("../../assets/hyperion-migrate.php");

/// Everything the plugin needs, in one paste. Shown once, like the wizard's
/// command, and worth as much: it lets its holder upload a site to this panel.
#[derive(Serialize)]
struct PluginCode<'a> {
    /// Panel base URL.
    u: &'a str,
    /// The bearer token.
    t: &'a str,
}

fn plugin_code(base: &str, token: &str) -> String {
    use base64::Engine;
    let json = serde_json::to_vec(&PluginCode { u: base, t: token }).unwrap_or_default();
    format!(
        "{CODE_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    )
}

/// The plugin's `Version:` header, so the page cannot disagree with the zip.
fn plugin_version() -> &'static str {
    PLUGIN_PHP
        .lines()
        .find_map(|l| l.trim_start_matches([' ', '*']).strip_prefix("Version:"))
        .map(str::trim)
        .unwrap_or("")
}

pub struct MintedCode {
    pub code: String,
    pub target_domain: String,
}

struct ProfileOpt {
    id: i64,
    name: String,
    price: String,
}

#[derive(Template)]
#[template(path = "import_wordpress.html")]
struct ImportWordpressTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    minted: Option<MintedCode>,
    flash: Option<String>,
    flash_error: Option<String>,
    profiles: Vec<ProfileOpt>,
    plugin_version: &'static str,
    /// The plugin refuses a panel on plain HTTP, so say so before anyone installs it.
    insecure_panel: bool,
}

async fn render(
    state: &SharedState,
    ctx: &AuthCtx,
    minted: Option<MintedCode>,
    flash: Option<String>,
    flash_error: Option<String>,
) -> Result<Response, AppError> {
    let profiles = match hyperion_rpc_client::call(&state.agent_socket, Request::ProfileList).await
    {
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
    let tpl = ImportWordpressTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "import",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: super::session_csrf_token(state, ctx),
        minted,
        flash: flash.filter(|s| !s.is_empty()),
        flash_error: flash_error.filter(|s| !s.is_empty()),
        profiles,
        plugin_version: plugin_version(),
        insecure_panel: !state.cfg.web.tls_enabled,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize, Default)]
pub struct PageQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_error: Option<String>,
}

fn refused() -> Response {
    Redirect::to("/?flash_error=admin+role+required").into_response()
}

/// `GET /import/wordpress`
pub async fn get_page(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(refused());
    }
    render(&state, &ctx, None, q.flash, q.flash_error).await
}

/// `GET /import/wordpress/hyperion-migrate.zip`. Built per request: it is one
/// small file, and this way it can never disagree with the panel serving it.
pub async fn get_plugin_zip(ctx: AuthCtx) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(refused());
    }
    let zip = plugin_zip().map_err(|e| AppError::Internal(format!("build plugin zip: {e}")))?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"hyperion-migrate.zip\"",
            ),
        ],
        zip,
    )
        .into_response())
}

fn plugin_zip() -> Result<Vec<u8>, zip::result::ZipError> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("hyperion-migrate/hyperion-migrate.php", opts)?;
    w.write_all(PLUGIN_PHP.as_bytes())?;
    Ok(w.finish()?.into_inner())
}

#[derive(Deserialize)]
pub struct MintForm {
    #[serde(default)]
    pub _csrf: String,
    #[serde(default)]
    pub target_domain: String,
    #[serde(default)]
    pub profile_id: String,
}

/// `POST /import/wordpress/mint`
pub async fn post_mint(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: HeaderMap,
    Form(form): Form<MintForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::PanelImport) {
        return Ok(refused());
    }
    let target = form.target_domain.trim().to_ascii_lowercase();
    if !target.is_empty()
        && (!wire_safe_domain(&target) || hyperion_validate::Domain::parse(&target).is_err())
    {
        let msg = format!("\"{}\" is not a valid domain", form.target_domain.trim());
        return render(&state, &ctx, None, None, Some(msg)).await;
    }
    if is_panel_name(&state, &target).await {
        let msg = format!("\"{target}\" is this panel's own address");
        return render(&state, &ctx, None, None, Some(msg)).await;
    }
    let (token, id) = match token_rpc(
        &state,
        ImportTokenOp::Mint {
            target_node: "local".into(), // Bundles land on the master, as in the wizard.
            source_kind: SOURCE_KIND.into(),
            created_by: ctx.username.clone(),
            ttl_secs: TOKEN_TTL_SECS,
        },
    )
    .await?
    {
        ImportTokenResult::Minted { token, id, .. } => (token, id),
        _ => return Err(AppError::Internal("mint returned unexpected result".into())),
    };
    // The source domain is not known until the plugin reports it, so this row's
    // key is filled in by `begin`.
    let choice = SiteImportOverride {
        source_domain: String::new(),
        target_domain: (!target.is_empty()).then(|| target.clone()),
        profile_id: form.profile_id.trim().parse().ok().filter(|&p: &i64| p > 0),
        ..Default::default()
    };
    token_rpc(
        &state,
        ImportTokenOp::SetSelection {
            id,
            selection_json: serde_json::to_string(&[choice]).unwrap_or_else(|_| "[]".into()),
        },
    )
    .await?;
    let base = super::import_wizard::base_url(&state, &headers).await;
    render(
        &state,
        &ctx,
        Some(MintedCode {
            code: plugin_code(&base, &token),
            target_domain: target,
        }),
        None,
        None,
    )
    .await
}

// ---- machine endpoints (public, token-gated) --------------------------------

fn run_dir(id: i64) -> PathBuf {
    // `bundle-*` is what the migration dir's stale-artefact sweep already removes,
    // so an abandoned transfer does not leave a database dump here for ever.
    PathBuf::from(format!("{}/bundle-wp-{id}", migration_dir()))
}

/// Transfers with a request in progress. A retry can arrive while the request it
/// gave up on is still running, and two of them appending to one stream, or one
/// committing twice, would corrupt the site or import it twice. One web process
/// serves these routes, so this needs no more than a set.
static BUSY_RUNS: std::sync::Mutex<std::collections::BTreeSet<i64>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

struct RunLock(i64);

impl RunLock {
    fn take(id: i64) -> Option<Self> {
        let free = BUSY_RUNS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id);
        // Not `then_some`: it builds its argument either way, and dropping that one
        // would hand back the lock its holder still needs.
        free.then(|| Self(id))
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        BUSY_RUNS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// The plugin waits and retries on this one.
fn run_is_busy() -> Response {
    text(
        StatusCode::LOCKED,
        "another request for this transfer is still running\n".into(),
    )
}

/// Is `name` this panel's own address? A hosting by that name would put a second
/// nginx server block on the panel's hostname, and a source chooses its own name.
async fn is_panel_name(state: &SharedState, name: &str) -> bool {
    same_site_name(&state.panel_hostname.read().await, name)
}

fn same_site_name(panel: &str, name: &str) -> bool {
    let panel = panel.trim().to_ascii_lowercase();
    let bare = |h: &str| h.strip_prefix("www.").unwrap_or(h).to_string();
    !panel.is_empty() && bare(&panel) == bare(name)
}

/// Delete whatever a transfer has staged. Called when a transfer is cancelled.
pub(super) async fn discard_run(id: i64) {
    let _ = tokio::fs::remove_dir_all(run_dir(id)).await;
}

async fn stream_len(id: i64, name: &str) -> u64 {
    tokio::fs::metadata(run_dir(id).join(name))
        .await
        .map(|m| m.len())
        .unwrap_or(0)
}

#[derive(Deserialize, Serialize, Default)]
struct BeginBody {
    /// Random per run of the plugin. A new value means the source started over,
    /// so whatever is staged here belongs to a run that no longer exists.
    run: String,
    home_url: String,
    #[serde(default)]
    wp_version: String,
    #[serde(default)]
    php_version: String,
    #[serde(default)]
    files_bytes: u64,
    #[serde(default)]
    db_estimate: u64,
    #[serde(default)]
    warnings: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct RunMeta {
    begin: BeginBody,
    target_domain: String,
    aliases: Vec<String>,
    url_rewrites: Vec<(String, String)>,
}

fn run_meta_path(id: i64) -> PathBuf {
    run_dir(id).join("run.json")
}

async fn read_run_meta(id: i64) -> Option<RunMeta> {
    let raw = tokio::fs::read(run_meta_path(id)).await.ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Stage directory and metadata: 0700 and 0600 from creation, because the streams
/// are the site's database and wp-config.
async fn prepare_run(id: i64, meta: &RunMeta) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::AsyncWriteExt;
    ensure_migration_dir().await;
    let dir = run_dir(id);
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await?;
    let mut o = tokio::fs::OpenOptions::new();
    o.create(true).truncate(true).write(true).mode(0o600);
    let mut f = o.open(run_meta_path(id)).await?;
    f.write_all(&serde_json::to_vec(meta).unwrap_or_default())
        .await?;
    f.flush().await
}

/// `POST /import/upload/wp/begin`: admit a run and say where each stream stands.
///
/// Idempotent, because calling it again is how a reloaded tab resumes.
pub async fn post_begin(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    let Some(info) = resolve(&state, &token, false).await? else {
        return Ok(text(
            StatusCode::GONE,
            "this code has expired or was cancelled. Generate a new one in Hyperion.\n".into(),
        ));
    };
    if info.source_kind != SOURCE_KIND {
        return Ok(text(
            StatusCode::FORBIDDEN,
            "this code is not a WordPress plugin code\n".into(),
        ));
    }
    let Some(_lock) = RunLock::take(info.id) else {
        return Ok(run_is_busy());
    };
    if info.status == "importing" {
        return Ok(text(
            StatusCode::OK,
            format!(
                "state importing\njob {}\n",
                info.job_id.as_deref().unwrap_or("-")
            ),
        ));
    }
    let begin: BeginBody = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(e) => {
            return Ok(text(
                StatusCode::BAD_REQUEST,
                format!("bad begin body: {e}\n"),
            ))
        }
    };
    if begin.run.is_empty()
        || begin.run.len() > 64
        || !begin.run.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Ok(text(StatusCode::BAD_REQUEST, "bad run id\n".into()));
    }

    let mut choice = serde_json::from_str::<Vec<SiteImportOverride>>(&info.selection_json)
        .unwrap_or_default()
        .into_iter()
        .next()
        .unwrap_or_default();
    let target = match wordpress::resolve_target(&begin.home_url, choice.target_domain.as_deref()) {
        Ok(t) => t,
        Err(e) => return Ok(text(StatusCode::BAD_REQUEST, format!("{e}\n"))),
    };
    if !wire_safe_domain(&target.domain)
        || hyperion_validate::Domain::parse(&target.domain).is_err()
    {
        return Ok(text(
            StatusCode::BAD_REQUEST,
            format!(
                "\"{}\" cannot be a hosting's domain here. Generate a new code in Hyperion and \
                 fill in \"Import as\".\n",
                target.domain
            ),
        ));
    }
    if is_panel_name(&state, &target.domain).await {
        return Ok(text(
            StatusCode::BAD_REQUEST,
            format!(
                "{} is this panel's own address. Generate a new code in Hyperion and fill in \
                 \"Import as\".\n",
                target.domain
            ),
        ));
    }
    // Hours of upload that the import then skips as a conflict would be a poor way
    // to find this out.
    if hosting_exists(&state, &target.domain).await {
        return Ok(text(
            StatusCode::CONFLICT,
            format!(
                "{} already exists in Hyperion. Delete it there, or generate a new code and \
                 fill in \"Import as\".\n",
                target.domain
            ),
        ));
    }

    let previous = read_run_meta(info.id).await;
    let same_run = previous.as_ref().is_some_and(|m| m.begin.run == begin.run);
    if !same_run {
        discard_run(info.id).await;
    }
    let (offset_db, offset_files) = (
        stream_len(info.id, DB_STREAM).await,
        stream_len(info.id, FILES_STREAM).await,
    );

    // Worst case, and on a site of photos close to the real one: the arriving
    // streams, the staging copy and the unpacked site, each about the source's
    // size. Only what has not arrived yet is charged.
    let total = begin.files_bytes.saturating_add(begin.db_estimate);
    if let Some(avail) = avail_bytes(&migration_dir()).await {
        let need = hyperion_import::bundle::import_needed_bytes(total, begin.files_bytes, 2)
            .saturating_sub(offset_db + offset_files);
        if (avail as u64) < need {
            let human = hyperion_import::progress::human_bytes;
            return Ok(text(
                StatusCode::INSUFFICIENT_STORAGE,
                format!(
                    "not enough free disk in Hyperion: {} free, {} needed for a {} site\n",
                    human(avail as u64),
                    human(need),
                    human(total),
                ),
            ));
        }
    }

    let claimed = token_rpc(
        &state,
        ImportTokenOp::ClaimUpload {
            token,
            // No total to compare against: the streams are compressed and their
            // final size is unknown, and a percentage against the raw size would
            // stop well short of 100 on every site.
            expected_bytes: 0,
            bundle_sha256: String::new(),
        },
    )
    .await?;
    if !matches!(claimed, ImportTokenResult::Resolved(Some(_))) {
        return Ok(text(
            StatusCode::GONE,
            "this code has expired or was cancelled. Generate a new one in Hyperion.\n".into(),
        ));
    }

    let WpTarget {
        domain,
        aliases,
        url_rewrites,
    } = target;
    // `target_domain` stays: a resuming tab calls this again, and without it the site
    // would quietly go back to its own name. `job_overrides` takes it out.
    choice.source_domain = domain.clone();
    choice.wp_url_rewrites = url_rewrites.clone();
    token_rpc(
        &state,
        ImportTokenOp::SetSelection {
            id: info.id,
            selection_json: serde_json::to_string(&[&choice]).unwrap_or_else(|_| "[]".into()),
        },
    )
    .await?;
    let meta = RunMeta {
        begin,
        target_domain: domain.clone(),
        aliases,
        url_rewrites,
    };
    prepare_run(info.id, &meta)
        .await
        .map_err(|e| AppError::Internal(format!("prepare import run: {e}")))?;

    Ok(text(
        StatusCode::OK,
        format!(
            "state receiving\ndomain {domain}\noffset_db {offset_db}\noffset_files {offset_files}\n\
             chunk {PREFERRED_CHUNK_BYTES}\n"
        ),
    ))
}

/// The stored choices as the import job wants them. The bundle's manifest already
/// names the target, so a rename here would be applied to the wrong name.
fn job_overrides(selection_json: &str) -> Vec<SiteImportOverride> {
    let mut overrides: Vec<SiteImportOverride> =
        serde_json::from_str(selection_json).unwrap_or_default();
    for o in &mut overrides {
        o.target_domain = None;
    }
    overrides
}

async fn hosting_exists(state: &SharedState, domain: &str) -> bool {
    match hyperion_rpc_client::call(&state.agent_socket, Request::HostingList).await {
        Ok(RpcResponse::HostingList(v)) => v.iter().any(|h| h.domain.as_str() == domain),
        // The import's own conflict check is still the backstop.
        _ => false,
    }
}

/// Add a verified chunk to its stream, or leave the stream at `have`.
async fn append_chunk(part: &Path, stream: &Path, have: u64) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut from = tokio::fs::File::open(part).await?;
    let mut o = tokio::fs::OpenOptions::new();
    o.create(true).append(true).mode(0o600);
    let mut to = o.open(stream).await?;
    let copied = match tokio::io::copy(&mut from, &mut to).await {
        Ok(_) => to.flush().await,
        Err(e) => Err(e),
    };
    if copied.is_err() {
        let _ = to.set_len(have).await;
    }
    let _ = tokio::fs::remove_file(part).await;
    copied
}

/// `PUT /import/upload/wp/chunk`: append one chunk to one stream.
pub async fn put_chunk(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Result<Response, AppError> {
    use http_body_util::BodyExt;
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    let Some(info) = resolve(&state, &token, false).await? else {
        return Ok(text(StatusCode::GONE, "state cancelled\n".into()));
    };
    if info.status != "receiving" {
        return Ok(text(StatusCode::GONE, format!("state {}\n", info.status)));
    }
    if info.source_kind != SOURCE_KIND {
        return Ok(text(
            StatusCode::FORBIDDEN,
            "this code is not a WordPress plugin code\n".into(),
        ));
    }
    let header_str = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let name = match header_str("x-hyperion-stream") {
        Some("db") => DB_STREAM,
        Some("files") => FILES_STREAM,
        _ => {
            return Ok(text(
                StatusCode::BAD_REQUEST,
                "x-hyperion-stream must be db or files\n".into(),
            ))
        }
    };
    let Some(want_sha) = header_str("x-hyperion-sha256").map(str::to_ascii_lowercase) else {
        return Ok(text(
            StatusCode::BAD_REQUEST,
            "x-hyperion-sha256 is required\n".into(),
        ));
    };
    let Some(lock) = RunLock::take(info.id) else {
        return Ok(run_is_busy());
    };
    if !tokio::fs::try_exists(run_meta_path(info.id))
        .await
        .unwrap_or(false)
    {
        return Ok(text(StatusCode::CONFLICT, "call begin first\n".into()));
    }
    let want: u64 = header_str("x-hyperion-offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(u64::MAX);
    let have = stream_len(info.id, name).await;
    if want != have {
        return Ok(text(StatusCode::CONFLICT, format!("offset {have}\n")));
    }
    if let Some(avail) = avail_bytes(&migration_dir()).await {
        if (avail as u64) < CHUNK_FREE_FLOOR {
            return Ok(text(
                StatusCode::INSUFFICIENT_STORAGE,
                format!(
                    "not enough free disk in Hyperion: {} free. Free some up and try again.\n",
                    hyperion_import::progress::human_bytes(avail as u64),
                ),
            ));
        }
    }

    // Into a side file first, never straight onto the stream. nginx does not buffer
    // this route and hyper drops a handler whose client went away, so a request
    // killed mid-body runs no rollback here. Those bytes on the stream would be an
    // offset the plugin cannot resume from, since it only holds whole slices.
    let part = run_dir(info.id).join(CHUNK_PART);
    let mut o = tokio::fs::OpenOptions::new();
    o.create(true).truncate(true).write(true).mode(0o600);
    let mut file = o
        .open(&part)
        .await
        .map_err(|e| AppError::Internal(format!("open import chunk: {e}")))?;

    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                return Ok(text(
                    StatusCode::BAD_REQUEST,
                    format!("upload error: {e}\noffset {have}\n"),
                ));
            }
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        written += data.len() as u64;
        if written > MAX_CHUNK_BYTES {
            return Ok(text(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("chunk exceeds the {MAX_CHUNK_BYTES} byte limit\n"),
            ));
        }
        hasher.update(&data);
        if let Err(e) = file.write_all(&data).await {
            return Ok(text(
                StatusCode::INSUFFICIENT_STORAGE,
                format!("write failed (disk full?): {e}\noffset {have}\n"),
            ));
        }
    }
    if let Err(e) = file.flush().await {
        return Ok(text(
            StatusCode::INSUFFICIENT_STORAGE,
            format!("write failed (disk full?): {e}\noffset {have}\n"),
        ));
    }
    drop(file);
    if hex::encode(hasher.finalize()) != want_sha {
        return Ok(text(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("chunk arrived corrupted\noffset {have}\n"),
        ));
    }

    // A task of its own, so that a client leaving now cannot stop this halfway. It
    // keeps the lock for as long as it runs.
    let stream = run_dir(info.id).join(name);
    let appended = tokio::spawn(async move {
        let _lock = lock;
        append_chunk(&part, &stream, have).await
    })
    .await
    .map_err(|e| AppError::Internal(format!("append import chunk: {e}")))?;
    if let Err(e) = appended {
        return Ok(text(
            StatusCode::INSUFFICIENT_STORAGE,
            format!("write failed (disk full?): {e}\noffset {have}\n"),
        ));
    }

    let now_off = have + written;
    let other = if name == DB_STREAM {
        FILES_STREAM
    } else {
        DB_STREAM
    };
    let _ = token_rpc(
        &state,
        ImportTokenOp::RecordUpload {
            id: info.id,
            received_bytes: (now_off + stream_len(info.id, other).await) as i64,
        },
    )
    .await;
    Ok(text(StatusCode::OK, format!("offset {now_off}\n")))
}

#[derive(Deserialize)]
struct CommitBody {
    db_bytes: u64,
    files_bytes: u64,
    files_members: u64,
    /// The full list. The one sent to `begin` predates everything noticed while
    /// the database and the files were being read.
    #[serde(default)]
    warnings: Vec<String>,
}

/// `POST /import/upload/wp/commit`: hand the finished streams to the import job.
///
/// Replies at once. Checking the streams means reading all of them, and the
/// source's request must not have to outlive that.
pub async fn post_commit(
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
    if info.source_kind != SOURCE_KIND {
        return Ok(text(
            StatusCode::FORBIDDEN,
            "this code is not a WordPress plugin code\n".into(),
        ));
    }
    let Some(_lock) = RunLock::take(info.id) else {
        return Ok(run_is_busy());
    };
    // Again, now that nobody else can be committing: a commit that held the lock
    // until a moment ago has changed the answer.
    let Some(info) = resolve(&state, &token, false).await? else {
        return Ok(text(StatusCode::GONE, "state cancelled\n".into()));
    };
    if info.status == "importing" {
        // A retried commit whose reply was lost. Importing twice would be the harm.
        return Ok(text(
            StatusCode::OK,
            format!(
                "state importing\njob {}\n",
                info.job_id.as_deref().unwrap_or("-")
            ),
        ));
    }
    let commit: CommitBody = match serde_json::from_str(&body) {
        Ok(c) => c,
        Err(e) => {
            return Ok(text(
                StatusCode::BAD_REQUEST,
                format!("bad commit body: {e}\n"),
            ))
        }
    };
    let (have_db, have_files) = (
        stream_len(info.id, DB_STREAM).await,
        stream_len(info.id, FILES_STREAM).await,
    );
    if have_db != commit.db_bytes || have_files != commit.files_bytes || have_files == 0 {
        return Ok(text(
            StatusCode::CONFLICT,
            format!("offset_db {have_db}\noffset_files {have_files}\n"),
        ));
    }
    let Some(mut meta) = read_run_meta(info.id).await else {
        return Ok(text(StatusCode::CONFLICT, "call begin first\n".into()));
    };
    if !commit.warnings.is_empty() {
        meta.begin.warnings = commit.warnings;
    }

    let site_overrides = job_overrides(&info.selection_json);
    let label = format!("WordPress plugin: {}", meta.target_domain);
    let id = info.id;
    let out = final_path(id);
    let req = hyperion_import::ImportPanelReq {
        source_kind: SOURCE_KIND.into(),
        mode: "archive".into(),
        ssh: None,
        archive_path: Some(out.clone()),
        site_overrides,
    };
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "panel_import",
        Some(&label),
        "{}",
        &info.created_by,
        0,
        move |reporter| async move {
            let beat = reporter.heartbeat("Checking what the plugin sent…");
            let dir = run_dir(id);
            let source = WpSource {
                home_url: meta.begin.home_url,
                wp_version: meta.begin.wp_version,
                php_version: meta.begin.php_version,
                files_bytes: meta.begin.files_bytes,
                warnings: meta.begin.warnings,
            };
            let target = WpTarget {
                domain: meta.target_domain,
                aliases: meta.aliases,
                url_rewrites: meta.url_rewrites,
            };
            let members = commit.files_members;
            let target_out = PathBuf::from(&out);
            let staged = dir.clone();
            let max_dump = avail_bytes(&migration_dir())
                .await
                .map(|a| (a as u64).saturating_sub(CHUNK_FREE_FLOOR));
            let assembled = tokio::task::spawn_blocking(move || {
                wordpress::assemble_bundle(
                    &staged,
                    &target_out,
                    &source,
                    &target,
                    members,
                    max_dump,
                )
            })
            .await
            .unwrap_or_else(|e| Err(format!("assemble task: {e}")));
            beat.abort();
            // On both paths: this is the site's database, and it is either in the
            // bundle now or of no further use.
            discard_run(id).await;
            if let Err(e) = assembled {
                let _ = tokio::fs::remove_file(&out).await;
                update(&job_state, id, Some("failed"), None, None).await;
                reporter.finish(false, Some(e)).await;
                return;
            }
            crate::handlers::import_panel::run_panel_import_job(reporter, job_state, None, req)
                .await;
        },
    )
    .await?;
    update(
        &state,
        id,
        Some("importing"),
        Some(&job_id),
        Some((have_db + have_files) as i64),
    )
    .await;
    Ok(text(
        StatusCode::OK,
        format!("state importing\njob {job_id}\n"),
    ))
}

/// `POST /import/upload/wp/abort`: the plugin's Cancel. The code stays good for
/// another try, but the site's database does not sit here waiting for one.
pub async fn post_abort(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let Some(token) = bearer(&headers) else {
        return Ok(text(StatusCode::UNAUTHORIZED, "no bearer token\n".into()));
    };
    let Some(info) = resolve(&state, &token, false).await? else {
        return Ok(text(StatusCode::GONE, "state cancelled\n".into()));
    };
    if info.source_kind != SOURCE_KIND {
        return Ok(text(
            StatusCode::FORBIDDEN,
            "this code is not a WordPress plugin code\n".into(),
        ));
    }
    let Some(_lock) = RunLock::take(info.id) else {
        return Ok(run_is_busy());
    };
    // Past commit, the streams belong to the import job.
    if info.status == "receiving" {
        discard_run(info.id).await;
        update(&state, info.id, None, None, Some(0)).await;
    }
    Ok(text(StatusCode::OK, format!("state {}\n", info.status)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_job_gets_no_rename_on_top_of_the_manifest() {
        let got = job_overrides(
            r#"[{"source_domain":"new.cz","target_domain":"new.cz","profile_id":2}]"#,
        );
        assert_eq!(got[0].source_domain, "new.cz");
        assert_eq!(got[0].target_domain, None);
        assert_eq!(got[0].profile_id, Some(2));
    }

    #[test]
    fn the_page_states_the_version_the_zip_holds() {
        assert!(
            plugin_version().starts_with(|c: char| c.is_ascii_digit()),
            "got {:?}",
            plugin_version()
        );
    }

    #[test]
    fn the_panel_own_name_is_recognised_with_or_without_www() {
        assert!(same_site_name("panel.example.cz", "panel.example.cz"));
        assert!(same_site_name(" Panel.Example.cz ", "www.panel.example.cz"));
        assert!(!same_site_name("panel.example.cz", "example.cz"));
        // No panel hostname set, and no "Import as" typed.
        assert!(!same_site_name("", ""));
    }

    #[test]
    fn a_run_is_locked_until_its_holder_lets_go() {
        let first = RunLock::take(-1).expect("free");
        assert!(RunLock::take(-1).is_none());
        drop(first);
        assert!(RunLock::take(-1).is_some());
    }

    #[test]
    fn the_plugin_zip_holds_the_plugin_where_wordpress_looks_for_it() {
        let zip = plugin_zip().expect("zip");
        let mut a = zip::ZipArchive::new(std::io::Cursor::new(zip)).expect("read zip");
        let mut f = a
            .by_name("hyperion-migrate/hyperion-migrate.php")
            .expect("entry");
        let mut body = String::new();
        std::io::Read::read_to_string(&mut f, &mut body).expect("read");
        assert!(body.contains("Plugin Name:"), "WordPress reads this header");
    }

    /// The plugin is PHP nothing here compiles, so a typo would otherwise ship and
    /// surface as a white screen in a stranger's wp-admin. Skipped where no PHP is
    /// installed.
    #[test]
    fn the_plugin_is_valid_php() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/hyperion-migrate.php");
        let Ok(out) = std::process::Command::new("php")
            .args(["-l", path])
            .output()
        else {
            return;
        };
        assert!(
            out.status.success(),
            "php -l: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn the_code_decodes_to_what_the_plugin_expects() {
        use base64::Engine;
        let code = plugin_code("https://panel.example.cz", "abc123");
        let raw = code.strip_prefix(CODE_PREFIX).expect("prefix");
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .expect("base64");
        let v: serde_json::Value = serde_json::from_slice(&json).expect("json");
        assert_eq!(v["u"], "https://panel.example.cz");
        assert_eq!(v["t"], "abc123");
    }
}
