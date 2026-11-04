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
    update, wire_safe_domain, MAX_CHUNK_BYTES,
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
use std::path::PathBuf;

const SOURCE_KIND: &str = "wordpress";
/// Same life as the one-command wizard's token. Every chunk extends it.
const TOKEN_TTL_SECS: i64 = 4 * 60 * 60;
/// What the plugin is told to send per chunk. It sends less when its own memory
/// limit is lower, and slices are bounded by time as well.
const PREFERRED_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
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
    flash_error: Option<String>,
    profiles: Vec<ProfileOpt>,
}

async fn render(
    state: &SharedState,
    ctx: &AuthCtx,
    minted: Option<MintedCode>,
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
        flash_error: flash_error.filter(|s| !s.is_empty()),
        profiles,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize, Default)]
pub struct PageQuery {
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
    render(&state, &ctx, None, q.flash_error).await
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
        return render(&state, &ctx, None, Some(msg)).await;
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
    )
    .await
}

// ---- machine endpoints (public, token-gated) --------------------------------

fn run_dir(id: i64) -> PathBuf {
    // `bundle-*` is what the migration dir's stale-artefact sweep already removes,
    // so an abandoned transfer does not leave a database dump here for ever.
    PathBuf::from(format!("{}/bundle-wp-{id}", migration_dir()))
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
    choice.source_domain = domain.clone();
    choice.target_domain = None; // The manifest already names the target.
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

async fn hosting_exists(state: &SharedState, domain: &str) -> bool {
    match hyperion_rpc_client::call(&state.agent_socket, Request::HostingList).await {
        Ok(RpcResponse::HostingList(v)) => v.iter().any(|h| h.domain.as_str() == domain),
        // The import's own conflict check is still the backstop.
        _ => false,
    }
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

    let path = run_dir(info.id).join(name);
    let mut o = tokio::fs::OpenOptions::new();
    o.create(true).append(true).mode(0o600);
    let mut file = o
        .open(&path)
        .await
        .map_err(|e| AppError::Internal(format!("open import stream: {e}")))?;
    let rollback = || async {
        if let Ok(f) = tokio::fs::OpenOptions::new().write(true).open(&path).await {
            let _ = f.set_len(have).await;
        }
    };

    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                rollback().await;
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
            rollback().await;
            return Ok(text(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("chunk exceeds the {MAX_CHUNK_BYTES} byte limit\n"),
            ));
        }
        hasher.update(&data);
        if let Err(e) = file.write_all(&data).await {
            rollback().await;
            return Ok(text(
                StatusCode::INSUFFICIENT_STORAGE,
                format!("write failed (disk full?): {e}\noffset {have}\n"),
            ));
        }
    }
    if let Err(e) = file.flush().await {
        rollback().await;
        return Ok(text(
            StatusCode::INSUFFICIENT_STORAGE,
            format!("write failed (disk full?): {e}\noffset {have}\n"),
        ));
    }
    drop(file);
    if hex::encode(hasher.finalize()) != want_sha {
        rollback().await;
        return Ok(text(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("chunk arrived corrupted\noffset {have}\n"),
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
    let Some(meta) = read_run_meta(info.id).await else {
        return Ok(text(StatusCode::CONFLICT, "call begin first\n".into()));
    };

    let site_overrides: Vec<SiteImportOverride> =
        serde_json::from_str(&info.selection_json).unwrap_or_default();
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
            let assembled = tokio::task::spawn_blocking(move || {
                wordpress::assemble_bundle(&staged, &target_out, &source, &target, members)
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

#[cfg(test)]
mod tests {
    use super::*;

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
