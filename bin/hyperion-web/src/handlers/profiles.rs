//! `/profiles` — operator-defined hosting templates (limits + expiry
//! policy + pricing + optional Slack webhook).

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_types::{HostingProfile, ProfileInput, WpAssetSummary};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "profiles.html")]
struct ProfilesTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    profiles: Vec<HostingProfile>,
    csrf_create: String,
    csrf_delete: String,
    csrf_clone: String,
    flash: Option<String>,
    error: Option<String>,
    /// Pre-split asset library — feeds the "Add from library"
    /// picker on the New profile form. Empty list ⇒ picker hides
    /// itself; operator falls back to typing `@asset:N` by hand.
    plugin_assets: Vec<WpAssetSummary>,
    theme_assets: Vec<WpAssetSummary>,
}

#[derive(Template)]
#[template(path = "profile_edit.html")]
struct ProfileEditTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    profile: HostingProfile,
    /// Pre-computed "price in major units" string so the form has a
    /// clean default like "199.00" instead of "19900".
    price_major: String,
    csrf_update: String,
    error: Option<String>,
    /// Uploaded plugin assets — drives the "Add from library" picker
    /// next to the wp_plugins textarea so operators don't have to
    /// look up `@asset:N` IDs in a separate tab.
    plugin_assets: Vec<WpAssetSummary>,
    /// Uploaded theme assets — same purpose, separate list.
    theme_assets: Vec<WpAssetSummary>,
}

#[derive(Deserialize, Default)]
pub struct ProfilesQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn get_profiles(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<ProfilesQuery>,
) -> Result<Response, AppError> {
    let profiles = fetch_profiles(&state).await.unwrap_or_default();
    // Asset library — best-effort. An empty list hides the picker.
    let assets: Vec<WpAssetSummary> = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WpAssetList,
    )
    .await
    {
        Ok(RpcResponse::WpAssetList(v)) => v,
        _ => Vec::new(),
    };
    let (plugin_assets, theme_assets): (Vec<_>, Vec<_>) =
        assets.into_iter().partition(|a| a.kind == "plugin");
    let tpl = ProfilesTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profiles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        profiles,
        csrf_create: csrf_token(&state, &ctx, "/profiles/create"),
        csrf_delete: csrf_token(&state, &ctx, "/profiles/delete"),
        csrf_clone: csrf_token(&state, &ctx, "/profiles/clone"),
        flash: q.flash,
        error: q.error,
        plugin_assets,
        theme_assets,
    };
    Ok(Html(tpl.render()?).into_response())
}

async fn fetch_profiles(state: &SharedState) -> Result<Vec<HostingProfile>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::ProfileList).await?;
    match resp {
        RpcResponse::ProfileList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct CreateForm {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_256")]
    pub php_memory_mb: i64,
    #[serde(default = "default_60")]
    pub php_max_exec_secs: i64,
    #[serde(default = "default_10")]
    pub php_max_children: i64,
    #[serde(default = "default_1000")]
    pub php_max_requests: i64,
    #[serde(default = "default_50")]
    pub db_max_connections: i64,
    #[serde(default)]
    pub disk_hard_mb: String,
    #[serde(default)]
    pub bw_monthly_mb: String,
    #[serde(default = "default_30")]
    pub expiry_grace_days: i64,
    #[serde(default = "default_offsets")]
    pub expiry_warning_offsets: String,
    /// Price in major units (e.g. 199.00) — converted to minor for storage.
    #[serde(default)]
    pub price_major: String,
    #[serde(default)]
    pub price_currency: String,
    #[serde(default)]
    pub price_interval: String,
    #[serde(default)]
    pub slack_webhook: String,
    /// Newline-separated list of WordPress plugins this profile
    /// installs when applied. Each line is a wordpress.org slug
    /// (e.g. `akismet`) or `@asset:<id>` to install from an
    /// uploaded ZIP. Trailing `!` = also activate after install.
    /// Lines starting with `#` are comments.
    #[serde(default)]
    pub wp_plugins: String,
    /// Same syntax as `wp_plugins`, for themes.
    #[serde(default)]
    pub wp_themes: String,
    /// Optional wizard pre-fill — when set the new-hosting wizard's
    /// PHP-version dropdown auto-selects this value. Empty / "" =
    /// no preference (wizard keeps its global default).
    #[serde(default)]
    pub default_php_version: String,
    /// Optional wizard pre-fill — "mariadb" / "postgres" / "none"
    /// / "" (empty = no preference).
    #[serde(default)]
    pub default_db_engine: String,
}

fn default_256() -> i64 {
    256
}
fn default_60() -> i64 {
    60
}
fn default_10() -> i64 {
    10
}
fn default_1000() -> i64 {
    1000
}
fn default_50() -> i64 {
    50
}
fn default_30() -> i64 {
    30
}
fn default_offsets() -> String {
    "30,7,1".into()
}

pub async fn post_create(
    State(state): State<SharedState>,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    let price_minor = parse_price_major(&form.price_major)?;
    let currency = form.price_currency.trim().to_string();
    let interval = form.price_interval.trim().to_string();
    let input = ProfileInput {
        name: form.name,
        description: form.description,
        php_memory_mb: form.php_memory_mb,
        php_max_exec_secs: form.php_max_exec_secs,
        php_max_children: form.php_max_children,
        php_max_requests: form.php_max_requests,
        db_max_connections: form.db_max_connections,
        disk_hard_mb: parse_opt_i64(&form.disk_hard_mb),
        bw_monthly_mb: parse_opt_i64(&form.bw_monthly_mb),
        expiry_grace_days: form.expiry_grace_days,
        expiry_warning_offsets: form.expiry_warning_offsets,
        price_minor,
        price_currency: if currency.is_empty() {
            None
        } else {
            Some(currency)
        },
        price_interval: if interval.is_empty() {
            None
        } else {
            Some(interval)
        },
        slack_webhook: if form.slack_webhook.trim().is_empty() {
            None
        } else {
            Some(form.slack_webhook.trim().to_string())
        },
        wp_plugins: form.wp_plugins.clone(),
        wp_themes: form.wp_themes.clone(),
        default_php_version: if form.default_php_version.trim().is_empty() {
            None
        } else {
            Some(form.default_php_version.trim().to_string())
        },
        default_db_engine: if form.default_db_engine.trim().is_empty() {
            None
        } else {
            Some(form.default_db_engine.trim().to_string())
        },
    };
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileCreate(input)).await?;
    match resp {
        RpcResponse::ProfileCreate(p) => Ok(Redirect::to(&format!(
            "/profiles?flash={}",
            urlencoding(&format!("Profile \"{}\" created.", p.name))
        ))
        .into_response()),
        RpcResponse::Error(e) => {
            Ok(Redirect::to(&format!("/profiles?error={}", urlencoding(&e.to_string())))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub id: i64,
}

#[derive(Deserialize)]
pub struct CloneForm {
    pub id: i64,
}

/// POST /profiles/clone — duplicate an existing profile into a new
/// row with name "Original (copy)". The user can then edit the
/// fresh row freely without having to retype the 20+ knobs that
/// make a profile (PHP limits, DB caps, plugin/theme lists, etc.).
///
/// Lands on the new profile's edit page so operators tweak first
/// and save again, rather than having a "copy" linger if they
/// abandon mid-edit (we already saved the duplicate — that's
/// intentional; the alternative of a temp-row that we'd have to
/// GC is fragile).
pub async fn post_clone(
    State(state): State<SharedState>,
    Form(form): Form<CloneForm>,
) -> Result<Response, AppError> {
    // Fetch the source profile.
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ProfileGet { id: form.id },
    )
    .await?;
    let src = match resp {
        RpcResponse::ProfileGet(p) => p,
        RpcResponse::Error(hyperion_rpc::RpcError::NotFound { .. }) => {
            return Ok(Redirect::to("/profiles?error=Profile+not+found").into_response());
        }
        RpcResponse::Error(e) => {
            return Ok(Redirect::to(&format!("/profiles?error={}", urlencoding(&e.to_string()))).into_response());
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    // Build the input from the source. ProfileInput is the "create"
    // shape — we copy every field 1:1 except the name (suffix "
    // (copy)" so list-row uniqueness isn't violated; agent enforces
    // unique name and would refuse a literal duplicate).
    let input = ProfileInput {
        name: format!("{} (copy)", src.name),
        description: src.description.clone(),
        php_memory_mb: src.php_memory_mb,
        php_max_exec_secs: src.php_max_exec_secs,
        php_max_children: src.php_max_children,
        php_max_requests: src.php_max_requests,
        db_max_connections: src.db_max_connections,
        disk_hard_mb: src.disk_hard_mb,
        bw_monthly_mb: src.bw_monthly_mb,
        expiry_grace_days: src.expiry_grace_days,
        expiry_warning_offsets: src.expiry_warning_offsets.clone(),
        price_minor: src.price_minor,
        price_currency: src.price_currency.clone(),
        price_interval: src.price_interval.clone(),
        slack_webhook: src.slack_webhook.clone(),
        wp_plugins: src.wp_plugins.clone(),
        wp_themes: src.wp_themes.clone(),
        default_php_version: src.default_php_version.clone(),
        default_db_engine: src.default_db_engine.clone(),
    };
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileCreate(input)).await?;
    match resp {
        RpcResponse::ProfileCreate(p) => Ok(Redirect::to(&format!(
            "/profiles/{}/edit?flash={}",
            p.id,
            urlencoding(&format!("Cloned from \"{}\" — edit the copy and save.", src.name))
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profiles?error={}",
            urlencoding(&format!("clone failed: {}", e))
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn get_edit(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Query(q): Query<EditQuery>,
) -> Result<Response, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::ProfileGet { id }).await?;
    let profile = match resp {
        RpcResponse::ProfileGet(p) => p,
        RpcResponse::Error(hyperion_rpc::RpcError::NotFound { .. }) => {
            return Err(AppError::NotFound)
        }
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let price_major = match profile.price_minor {
        Some(m) => format!("{:.2}", m as f64 / 100.0),
        None => String::new(),
    };
    // Asset library — feeds the "Add from library" picker. Failure
    // here shouldn't 500 the edit page; an empty Vec just hides
    // the picker entirely and the operator falls back to typing
    // `@asset:N` by hand.
    let assets: Vec<WpAssetSummary> = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WpAssetList,
    )
    .await
    {
        Ok(RpcResponse::WpAssetList(v)) => v,
        _ => Vec::new(),
    };
    let (plugin_assets, theme_assets): (Vec<_>, Vec<_>) =
        assets.into_iter().partition(|a| a.kind == "plugin");
    let tpl = ProfileEditTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profiles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        profile,
        price_major,
        csrf_update: csrf_token(&state, &ctx, &format!("/profiles/{}/update", id)),
        error: q.error,
        plugin_assets,
        theme_assets,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize, Default)]
pub struct EditQuery {
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn post_update(
    State(state): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    let price_minor = parse_price_major(&form.price_major)?;
    let currency = form.price_currency.trim().to_string();
    let interval = form.price_interval.trim().to_string();
    let input = ProfileInput {
        name: form.name,
        description: form.description,
        php_memory_mb: form.php_memory_mb,
        php_max_exec_secs: form.php_max_exec_secs,
        php_max_children: form.php_max_children,
        php_max_requests: form.php_max_requests,
        db_max_connections: form.db_max_connections,
        disk_hard_mb: parse_opt_i64(&form.disk_hard_mb),
        bw_monthly_mb: parse_opt_i64(&form.bw_monthly_mb),
        expiry_grace_days: form.expiry_grace_days,
        expiry_warning_offsets: form.expiry_warning_offsets,
        price_minor,
        price_currency: if currency.is_empty() {
            None
        } else {
            Some(currency)
        },
        price_interval: if interval.is_empty() {
            None
        } else {
            Some(interval)
        },
        slack_webhook: if form.slack_webhook.trim().is_empty() {
            None
        } else {
            Some(form.slack_webhook.trim().to_string())
        },
        wp_plugins: form.wp_plugins.clone(),
        wp_themes: form.wp_themes.clone(),
        default_php_version: if form.default_php_version.trim().is_empty() {
            None
        } else {
            Some(form.default_php_version.trim().to_string())
        },
        default_db_engine: if form.default_db_engine.trim().is_empty() {
            None
        } else {
            Some(form.default_db_engine.trim().to_string())
        },
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ProfileUpdate { id, input },
    )
    .await?;
    match resp {
        RpcResponse::ProfileUpdate(p) => Ok(Redirect::to(&format!(
            "/profiles?flash={}",
            urlencoding(&format!("Profile \"{}\" updated.", p.name))
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profiles/{}/edit?error={}",
            id,
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_delete(
    State(state): State<SharedState>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileDelete { id: form.id })
            .await?;
    match resp {
        RpcResponse::ProfileDelete => Ok(Redirect::to("/profiles?flash=Profile+deleted").into_response()),
        RpcResponse::Error(e) => {
            Ok(Redirect::to(&format!("/profiles?error={}", urlencoding(&e.to_string())))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ApplyForm {
    pub selector: String,
    pub profile_id: i64,
}

pub async fn post_apply(
    State(state): State<SharedState>,
    Form(form): Form<ApplyForm>,
) -> Result<Response, AppError> {
    let sel = super::hostings::parse_selector_public(&form.selector)?;
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ProfileApply {
            sel,
            profile_id: form.profile_id,
        },
    )
    .await?;
    match resp {
        RpcResponse::ProfileApply(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?profile=applied", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?profile_error={}", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

fn parse_opt_i64(s: &str) -> Option<i64> {
    s.trim().parse().ok().filter(|n: &i64| *n > 0)
}

/// Parse "199.00" / "199,00" / "199" → 19900 (minor units).
fn parse_price_major(s: &str) -> Result<Option<i64>, AppError> {
    let s = s.trim().replace(',', ".");
    if s.is_empty() {
        return Ok(None);
    }
    let n: f64 = s
        .parse()
        .map_err(|_| AppError::BadRequest(format!("price not numeric: {s}")))?;
    if n < 0.0 {
        return Err(AppError::BadRequest("price must be ≥ 0".into()));
    }
    Ok(Some((n * 100.0).round() as i64))
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn csrf_token(state: &SharedState, ctx: &AuthCtx, form_id: &str) -> String {
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

// ============================================================
//  WordPress asset library — /profiles/wp-assets
// ============================================================

#[derive(Template)]
#[template(path = "wp_assets.html")]
struct WpAssetsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    assets: Vec<WpAssetSummary>,
    csrf_upload: String,
    csrf_delete: String,
    flash: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct WpAssetsQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// GET /profiles/wp-assets — admin-only library of uploaded plugin/theme ZIPs.
pub async fn get_wp_assets(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<WpAssetsQuery>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let assets = match hyperion_rpc_client::call(&state.agent_socket, Request::WpAssetList).await? {
        RpcResponse::WpAssetList(v) => v,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let tpl = WpAssetsTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profiles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        assets,
        csrf_upload: super::session_csrf_token(&state, &ctx),
        csrf_delete: super::session_csrf_token(&state, &ctx),
        flash: q.flash,
        error: q.error,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// POST /profiles/wp-assets/upload — multipart form with the ZIP.
///
/// Uses axum's built-in Multipart extractor. Single file per
/// upload; we read it fully into memory (capped at 50 MB on the
/// service side) and forward to the agent via WpAssetUpload RPC.
pub async fn post_wp_asset_upload(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    mut multipart: axum::extract::Multipart,
) -> Result<Response, AppError> {
    // Diagnostic breadcrumb — if you see "CSRF check failed" in
    // journalctl but NOT this line, the middleware rejected the
    // request before it reached here (token missing / mismatched).
    tracing::info!(
        operator = %ctx.username,
        "post_wp_asset_upload entered"
    );
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let mut kind: Option<String> = None;
    let mut original_name: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;
    // ~60 MB hard cap on a single field read — the service then
    // applies its 50 MB cap. Anything larger means the operator
    // grabbed the wrong file by accident.
    const MAX_FIELD_BYTES: usize = 60 * 1024 * 1024;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "kind" => {
                let v = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("kind: {e}")))?;
                if v != "plugin" && v != "theme" {
                    return Err(AppError::BadRequest(format!(
                        "kind must be plugin or theme, got {v:?}"
                    )));
                }
                kind = Some(v);
            }
            "file" => {
                let filename = field
                    .file_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| "asset.zip".to_string());
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("file: {e}")))?;
                if data.len() > MAX_FIELD_BYTES {
                    return Err(AppError::BadRequest(format!(
                        "file too large ({} bytes); max {}",
                        data.len(),
                        MAX_FIELD_BYTES
                    )));
                }
                original_name = Some(filename);
                bytes = Some(data.to_vec());
            }
            _ => {
                // Unknown field — silently skip. Lets us add fields
                // later without rejecting old clients.
            }
        }
    }
    let kind = kind.ok_or_else(|| AppError::BadRequest("missing `kind` field".into()))?;
    let original_name =
        original_name.ok_or_else(|| AppError::BadRequest("missing `file` field".into()))?;
    let bytes = bytes.ok_or_else(|| AppError::BadRequest("missing `file` bytes".into()))?;
    use base64::Engine;
    let bytes_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WpAssetUpload {
            kind,
            original_name: original_name.clone(),
            bytes_b64,
            uploaded_by: ctx.username.clone(),
        },
    )
    .await?;
    match resp {
        RpcResponse::WpAssetUpload { id, deduped } => {
            let msg = if deduped {
                format!(
                    "Asset \"{original_name}\" already in library as id {id} — no duplicate stored."
                )
            } else {
                format!("Uploaded \"{original_name}\" → id {id}.")
            };
            Ok(Redirect::to(&format!(
                "/profiles/wp-assets?flash={}",
                urlencoding(&msg)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profiles/wp-assets?error={}",
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpAssetDeleteForm {
    pub id: i64,
}

#[derive(Deserialize)]
pub struct WpInstallFromAssetForm {
    pub selector: String,
    pub asset_id: i64,
    #[serde(default)]
    pub activate: Option<String>,
    /// Carried through the JS shim on the detail page so we
    /// dispatch to the node that owns the hosting (not always
    /// the master).
    #[serde(default)]
    pub target_node: String,
}

/// POST /hostings/wp/install-from-asset — operator clicks the
/// dropdown on a hosting's WordPress tab and picks one of the
/// uploaded plugin/theme ZIPs.
pub async fn post_wp_install_from_asset(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpInstallFromAssetForm>,
) -> Result<Response, AppError> {
    let sel = super::hostings::parse_selector_public(&form.selector)?;
    let sel_url = urlencoding(&form.selector);
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?wp_error={}#wordpress",
            sel_url,
            urlencoding("admin role required to install WP assets")
        ))
        .into_response());
    }
    let activate = matches!(form.activate.as_deref(), Some("on" | "true" | "1"));
    let target = if form.target_node.is_empty()
        || form.target_node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(form.target_node.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::WpInstallFromAsset {
            sel,
            asset_id: form.asset_id,
            activate,
        },
    )
    .await?;
    match resp {
        RpcResponse::WpInstallFromAsset {
            kind,
            original_name,
        } => {
            let activated = if activate { " and activated" } else { "" };
            let msg = format!(
                "Installed {kind} \"{original_name}\" from library{activated}."
            );
            Ok(Redirect::to(&format!(
                "/hostings/{}?wp_flash={}#wordpress",
                sel_url,
                urlencoding(&msg)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/{}?wp_error={}#wordpress",
            sel_url,
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /profiles/wp-assets/replace — multipart upload that
/// overwrites an existing asset's on-disk ZIP. Field `id` carries
/// the target asset, `file` is the new ZIP. Admin-only.
pub async fn post_wp_asset_replace(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    mut multipart: axum::extract::Multipart,
) -> Result<Response, AppError> {
    tracing::info!(operator = %ctx.username, "post_wp_asset_replace entered");
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let mut id: Option<i64> = None;
    let mut original_name: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;
    const MAX_FIELD_BYTES: usize = 60 * 1024 * 1024;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "id" => {
                let v = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("id: {e}")))?;
                id = v.trim().parse::<i64>().ok();
            }
            "file" => {
                let filename = field
                    .file_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| "asset.zip".to_string());
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("file: {e}")))?;
                if data.len() > MAX_FIELD_BYTES {
                    return Err(AppError::BadRequest(format!(
                        "file too large ({} bytes); max {}",
                        data.len(),
                        MAX_FIELD_BYTES
                    )));
                }
                original_name = Some(filename);
                bytes = Some(data.to_vec());
            }
            _ => {}
        }
    }
    let id = id.ok_or_else(|| AppError::BadRequest("missing `id` field".into()))?;
    let original_name =
        original_name.ok_or_else(|| AppError::BadRequest("missing `file` field".into()))?;
    let bytes = bytes.ok_or_else(|| AppError::BadRequest("missing `file` bytes".into()))?;
    use base64::Engine;
    let bytes_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WpAssetReplace {
            id,
            original_name: original_name.clone(),
            bytes_b64,
            uploaded_by: ctx.username.clone(),
        },
    )
    .await?;
    match resp {
        RpcResponse::WpAssetReplace => Ok(Redirect::to(&format!(
            "/profiles/wp-assets?flash={}",
            urlencoding(&format!(
                "Asset id {id} replaced with \"{original_name}\". Click \"Re-install on all\" to push the new version."
            ))
        ))
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profiles/wp-assets?error={}",
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpAssetReinstallForm {
    pub id: i64,
    /// "" = keep original per-row activate flag; "force_on" =
    /// activate everywhere; "force_off" = deactivate everywhere.
    #[serde(default)]
    pub activate_mode: String,
}

/// POST /profiles/wp-assets/reinstall-all — pushes the asset's
/// current bytes onto every hosting tracked in wp_asset_installs.
pub async fn post_wp_asset_reinstall_all(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpAssetReinstallForm>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let force_activate = match form.activate_mode.as_str() {
        "force_on" => Some(true),
        "force_off" => Some(false),
        _ => None,
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WpAssetReinstallAll {
            asset_id: form.id,
            force_activate,
        },
    )
    .await?;
    match resp {
        RpcResponse::WpAssetReinstallAll {
            installed_ok,
            installed_failed,
            failure_tail,
        } => {
            let msg = if installed_failed == 0 {
                format!("Re-installed on {installed_ok} hosting(s).")
            } else {
                format!(
                    "Re-installed on {installed_ok} hosting(s); {installed_failed} failed. First failures: {}",
                    failure_tail.lines().take(3).collect::<Vec<_>>().join(" | ")
                )
            };
            let key = if installed_failed == 0 { "flash" } else { "error" };
            Ok(Redirect::to(&format!(
                "/profiles/wp-assets?{}={}",
                key,
                urlencoding(&msg)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profiles/wp-assets?error={}",
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_wp_asset_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpAssetDeleteForm>,
) -> Result<Response, AppError> {
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WpAssetDelete { id: form.id },
    )
    .await?;
    match resp {
        RpcResponse::WpAssetDelete => Ok(Redirect::to(
            "/profiles/wp-assets?flash=Asset+deleted",
        )
        .into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profiles/wp-assets?error={}",
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
