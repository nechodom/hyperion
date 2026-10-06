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
use hyperion_state::capabilities::Capability;
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
    rows: Vec<ProfileRow>,
    /// Sites on any profile, cluster-wide — the header note.
    total_sites: i64,
    csrf_clone: String,
    flash: Option<String>,
    error: Option<String>,
}

/// `/profiles/new` — the create form on a page of its own. It used to sit
/// under the list, so the list page was mostly an empty form.
#[derive(Template)]
#[template(path = "profile_new.html")]
struct ProfileNewTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    /// Defaults on a fresh form; what was typed when a create is refused.
    profile: HostingProfile,
    price_major: String,
    csrf_create: String,
    error: Option<String>,
    /// Pre-split asset library — feeds the "Add from library" picker.
    /// Empty list ⇒ picker hides itself; operator falls back to typing
    /// `@asset:N` by hand.
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
    /// Sites on this profile the viewer may see, A→Z by domain.
    sites: Vec<SiteLink>,
    /// Sites counted on the profile but not in `sites` (a node that did not
    /// answer the list, or outside the viewer's access).
    unlisted: i64,
    csrf_update: String,
    /// CSRF for the "re-apply to all sites on this profile" action.
    csrf_reapply: String,
    csrf_clone: String,
    csrf_delete: String,
    /// Just saved: remind that sites on the profile still run the old values.
    saved: bool,
    error: Option<String>,
    flash: Option<String>,
    /// Uploaded plugin assets — drives the "Add from library" picker
    /// next to the wp_plugins textarea so operators don't have to
    /// look up `@asset:N` IDs in a separate tab.
    plugin_assets: Vec<WpAssetSummary>,
    /// Uploaded theme assets — same purpose, separate list.
    theme_assets: Vec<WpAssetSummary>,
}

/// One site on a profile, for the edit page's list.
pub(crate) struct SiteLink {
    pub id: String,
    pub domain: String,
}

/// A profile as one table row: the plan read out in words, so tiers can be
/// told apart without opening each one.
pub(crate) struct ProfileRow {
    pub p: HostingProfile,
    /// "256 MB · 60 s"
    pub php: String,
    /// "10 workers · 50 DB connections"
    pub php_sub: String,
    /// "2 GB" | "Unlimited"
    pub disk: String,
    /// "warns at 1.5 GB" | ""
    pub disk_sub: String,
    /// "Daily" | "Every 3 days" | "Off"
    pub backups: String,
    /// "kept 30 days · latest 5" | ""
    pub backups_sub: String,
    /// "PHP 8.3 · MariaDB · 3 plugins · 1 theme" | ""
    pub new_sites: String,
}

impl ProfileRow {
    pub(crate) fn new(p: HostingProfile) -> Self {
        let php = format!("{} MB · {} s", p.php_memory_mb, p.php_max_exec_secs);
        let php_sub = format!(
            "{} worker{} · {} DB connection{}",
            p.php_max_children,
            plural(p.php_max_children),
            p.db_max_connections,
            plural(p.db_max_connections)
        );
        let disk = match p.disk_hard_mb {
            Some(mb) => fmt_mb(mb),
            None => "Unlimited".into(),
        };
        let disk_sub = match p.disk_soft_mb {
            Some(mb) => format!("warns at {}", fmt_mb(mb)),
            None => String::new(),
        };
        let backups = cadence_label(&p.backup_cadence, p.backup_interval_days);
        let mut keep = Vec::new();
        if backups != "Off" {
            if p.backup_keep_days > 0 {
                keep.push(format!(
                    "kept {} day{}",
                    p.backup_keep_days,
                    plural(p.backup_keep_days)
                ));
            }
            if p.backup_keep_last > 0 {
                keep.push(format!("latest {} always", p.backup_keep_last));
            }
        }
        let mut new_sites = Vec::new();
        if let Some(v) = p.default_php_version.as_deref().filter(|v| !v.is_empty()) {
            new_sites.push(format!("PHP {v}"));
        }
        if let Some(e) = p.default_db_engine.as_deref().filter(|e| !e.is_empty()) {
            new_sites.push(
                match e {
                    "mariadb" => "MariaDB",
                    "postgres" => "PostgreSQL",
                    "none" => "no database",
                    other => other,
                }
                .to_string(),
            );
        }
        let (np, nt) = (p.plugin_count(), p.theme_count());
        if np > 0 {
            new_sites.push(format!("{np} plugin{}", plural(np as i64)));
        }
        if nt > 0 {
            new_sites.push(format!("{nt} theme{}", plural(nt as i64)));
        }
        Self {
            php,
            php_sub,
            disk,
            disk_sub,
            backups,
            backups_sub: keep.join(" · "),
            new_sites: new_sites.join(" · "),
            p,
        }
    }
}

fn plural(n: i64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Megabytes as the form takes them, shown in GB from 1024 up.
fn fmt_mb(mb: i64) -> String {
    if mb >= 1024 {
        let gb = mb as f64 / 1024.0;
        if mb % 1024 == 0 {
            format!("{} GB", mb / 1024)
        } else {
            format!("{gb:.1} GB")
        }
    } else {
        format!("{mb} MB")
    }
}

/// The backup cadence as the list shows it. Anything unrecognised is what
/// the backup scheduler treats it as: off.
fn cadence_label(cadence: &str, interval_days: i64) -> String {
    match cadence {
        "daily" => "Daily".into(),
        "weekly" => "Weekly".into(),
        "monthly" => "Monthly".into(),
        "custom" if interval_days == 1 => "Daily".into(),
        "custom" if interval_days > 1 => format!("Every {interval_days} days"),
        _ => "Off".into(),
    }
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
    if !ctx.can(Capability::ProfilesManage) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let mut profiles = fetch_profiles(&state).await.unwrap_or_default();
    // The in_use_count from ProfileList is master-local; add the per-node counts
    // from every worker so the badge is cluster-wide.
    let remote = remote_usage_counts(&state).await;
    for p in &mut profiles {
        if let Some(extra) = remote.get(&p.id) {
            p.in_use_count += extra;
        }
    }
    let total_sites = profiles.iter().map(|p| p.in_use_count).sum();
    let tpl = ProfilesTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profiles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows: profiles.into_iter().map(ProfileRow::new).collect(),
        total_sites,
        csrf_clone: csrf_token(&state, &ctx, "/profiles/clone"),
        flash: q.flash,
        error: q.error,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// GET /profiles/new — the create form.
pub async fn get_new(State(state): State<SharedState>, ctx: AuthCtx) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    render_new(&state, &ctx, blank_profile(), String::new(), None).await
}

async fn render_new(
    state: &SharedState,
    ctx: &AuthCtx,
    profile: HostingProfile,
    price_major: String,
    error: Option<String>,
) -> Result<Response, AppError> {
    let (plugin_assets, theme_assets) = fetch_assets(state).await;
    let tpl = ProfileNewTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profiles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        profile,
        price_major,
        csrf_create: csrf_token(state, ctx, "/profiles/create"),
        error,
        plugin_assets,
        theme_assets,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Asset library split into plugins and themes — best-effort. An empty
/// list hides the picker; the operator can still type `@asset:N`.
async fn fetch_assets(state: &SharedState) -> (Vec<WpAssetSummary>, Vec<WpAssetSummary>) {
    let assets: Vec<WpAssetSummary> =
        match hyperion_rpc_client::call(&state.agent_socket, Request::WpAssetList).await {
            Ok(RpcResponse::WpAssetList(v)) => v,
            _ => Vec::new(),
        };
    assets.into_iter().partition(|a| a.kind == "plugin")
}

/// A new profile's starting values — the same defaults `CreateForm` falls
/// back to when a field is missing.
fn blank_profile() -> HostingProfile {
    profile_from_input(
        0,
        &ProfileInput {
            php_memory_mb: default_256(),
            php_max_exec_secs: default_60(),
            php_max_children: default_10(),
            php_max_requests: default_1000(),
            db_max_connections: default_50(),
            expiry_grace_days: default_30(),
            expiry_warning_offsets: default_offsets(),
            quota_exceed_action: "notify".into(),
            backup_cadence: "off".into(),
            ..ProfileInput::default()
        },
    )
}

/// What a form submission would make, as a profile — re-renders a refused
/// form with what was typed instead of a blank one.
fn profile_from_input(id: i64, i: &ProfileInput) -> HostingProfile {
    HostingProfile {
        id,
        name: i.name.clone(),
        description: i.description.clone(),
        php_memory_mb: i.php_memory_mb,
        php_max_exec_secs: i.php_max_exec_secs,
        php_max_children: i.php_max_children,
        php_max_requests: i.php_max_requests,
        db_max_connections: i.db_max_connections,
        disk_hard_mb: i.disk_hard_mb,
        bw_monthly_mb: i.bw_monthly_mb,
        expiry_grace_days: i.expiry_grace_days,
        expiry_warning_offsets: i.expiry_warning_offsets.clone(),
        price_minor: i.price_minor,
        price_currency: i.price_currency.clone(),
        price_interval: i.price_interval.clone(),
        slack_webhook: i.slack_webhook.clone(),
        alert_emails: i.alert_emails.clone(),
        wp_plugins: i.wp_plugins.clone(),
        wp_themes: i.wp_themes.clone(),
        default_php_version: i.default_php_version.clone(),
        default_db_engine: i.default_db_engine.clone(),
        quota_exceed_action: i.quota_exceed_action.clone(),
        disk_soft_mb: i.disk_soft_mb,
        mem_limit_mib: i.mem_limit_mib,
        backup_cadence: i.backup_cadence.clone(),
        backup_interval_days: i.backup_interval_days,
        backup_keep_days: i.backup_keep_days,
        backup_keep_last: i.backup_keep_last,
        in_use_count: 0,
        created_at: 0,
        updated_at: 0,
    }
}

async fn fetch_profiles(state: &SharedState) -> Result<Vec<HostingProfile>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::ProfileList).await?;
    match resp {
        RpcResponse::ProfileList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize, Clone)]
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
    pub disk_soft_mb: String,
    #[serde(default)]
    pub mem_limit_mib: String,
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
    /// Operator addresses that also receive alerts for sites on this
    /// profile, on top of the cluster-wide list. Comma- or newline-separated.
    #[serde(default)]
    pub alert_emails: String,
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
    /// Default disk-overage action for sites created from this profile:
    /// "notify" (default) or "suspend".
    #[serde(default)]
    pub quota_exceed_action: String,
    /// Recurring-backup cadence: "off" (default) | "daily" | "weekly" | "monthly" | "custom".
    #[serde(default)]
    pub backup_cadence: String,
    /// Custom period in days (used when cadence is "custom") + retention
    /// overrides (blank/0 = node-wide default). Parsed from the form.
    #[serde(default)]
    pub backup_interval_days: String,
    #[serde(default)]
    pub backup_keep_days: String,
    #[serde(default)]
    pub backup_keep_last: String,
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

/// The form as a profile input. Errors are worded for the form banner.
fn input_from_form(form: CreateForm) -> Result<ProfileInput, String> {
    let price_minor = parse_price_major(&form.price_major).map_err(|e| match e {
        AppError::BadRequest(m) => m,
        other => other.to_string(),
    })?;
    let opt = |s: &str| {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };
    Ok(ProfileInput {
        description: form.description,
        php_memory_mb: form.php_memory_mb,
        php_max_exec_secs: form.php_max_exec_secs,
        php_max_children: form.php_max_children,
        php_max_requests: form.php_max_requests,
        db_max_connections: form.db_max_connections,
        disk_hard_mb: parse_opt_i64(&form.disk_hard_mb),
        // Dead stores — see the form template note; a plan must not carry
        // a number nothing keeps.
        bw_monthly_mb: None,
        mem_limit_mib: None,
        expiry_grace_days: form.expiry_grace_days,
        expiry_warning_offsets: form.expiry_warning_offsets,
        price_minor,
        // The field only LOOKS uppercase (CSS); the agent refuses "czk".
        price_currency: opt(&form.price_currency).map(|c| c.to_ascii_uppercase()),
        price_interval: opt(&form.price_interval),
        alert_emails: form.alert_emails.trim().to_string(),
        slack_webhook: opt(&form.slack_webhook),
        wp_plugins: form.wp_plugins,
        wp_themes: form.wp_themes,
        default_php_version: opt(&form.default_php_version),
        default_db_engine: opt(&form.default_db_engine),
        quota_exceed_action: form.quota_exceed_action,
        disk_soft_mb: parse_opt_i64(&form.disk_soft_mb),
        backup_cadence: form.backup_cadence,
        backup_interval_days: parse_opt_i64(&form.backup_interval_days).unwrap_or(0),
        backup_keep_days: parse_opt_i64(&form.backup_keep_days).unwrap_or(0),
        backup_keep_last: parse_opt_i64(&form.backup_keep_last).unwrap_or(0),
        name: form.name,
    })
}

/// The best-effort typed-back profile for a form the parser refused (bad
/// price): every other field as entered, the price left out.
fn input_lossy(form: &CreateForm) -> ProfileInput {
    let mut f = form.clone();
    f.price_major = String::new();
    input_from_form(f).unwrap_or_default()
}

pub async fn post_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    // Profiles are an admin construct (PHP limits, pricing, plugin/theme
    // bundles). The route only enforces auth+CSRF, so without this gate
    // any authenticated viewer could create/edit/delete them — matching
    // the asset handlers below which all gate on ProfilesManage.
    if !ctx.can(Capability::ProfilesManage) {
        return Err(AppError::Forbidden);
    }
    let price_typed = form.price_major.clone();
    let input = match input_from_form(form.clone()) {
        Ok(i) => i,
        Err(msg) => {
            let typed = profile_from_input(0, &input_lossy(&form));
            return render_new(&state, &ctx, typed, price_typed, Some(msg)).await;
        }
    };
    let typed = profile_from_input(0, &input);
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileCreate(input)).await?;
    match resp {
        RpcResponse::ProfileCreate(p) => Ok(Redirect::to(&format!(
            "/profiles?flash={}",
            urlencoding(&format!("Profile \"{}\" created.", p.name))
        ))
        .into_response()),
        // Refused (duplicate name, bad value): the form comes back as typed.
        RpcResponse::Error(e) => {
            render_new(&state, &ctx, typed, price_typed, Some(e.to_string())).await
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
    ctx: AuthCtx,
    Form(form): Form<CloneForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Err(AppError::Forbidden);
    }
    // Fetch the source profile.
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileGet { id: form.id }).await?;
    let src = match resp {
        RpcResponse::ProfileGet(p) => p,
        RpcResponse::Error(hyperion_rpc::RpcError::NotFound { .. }) => {
            return Ok(Redirect::to("/profiles?error=Profile+not+found").into_response());
        }
        RpcResponse::Error(e) => {
            return Ok(
                Redirect::to(&format!("/profiles?error={}", urlencoding(&e.to_string())))
                    .into_response(),
            );
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
        alert_emails: src.alert_emails.clone(),
        wp_plugins: src.wp_plugins.clone(),
        wp_themes: src.wp_themes.clone(),
        default_php_version: src.default_php_version.clone(),
        default_db_engine: src.default_db_engine.clone(),
        quota_exceed_action: src.quota_exceed_action.clone(),
        disk_soft_mb: src.disk_soft_mb,
        mem_limit_mib: src.mem_limit_mib,
        backup_cadence: src.backup_cadence.clone(),
        backup_interval_days: src.backup_interval_days,
        backup_keep_days: src.backup_keep_days,
        backup_keep_last: src.backup_keep_last,
    };
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileCreate(input)).await?;
    match resp {
        RpcResponse::ProfileCreate(p) => Ok(Redirect::to(&format!(
            "/profiles/{}/edit?flash={}",
            p.id,
            urlencoding(&format!(
                "Cloned from \"{}\" — edit the copy and save.",
                src.name
            ))
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
    // SECURITY (sec-findings #2): the edit page renders per-profile pricing and
    // the Slack incoming-webhook secret. Gate it like the sibling profile
    // handlers — without ProfilesManage any authenticated user could IDOR-read
    // every profile's secret by walking /profiles/N/edit.
    if !ctx.can(Capability::ProfilesManage) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
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
    render_edit(
        &state,
        &ctx,
        profile,
        price_major,
        q.saved,
        q.error,
        q.flash,
    )
    .await
}

async fn render_edit(
    state: &SharedState,
    ctx: &AuthCtx,
    mut profile: HostingProfile,
    price_major: String,
    saved: bool,
    error: Option<String>,
    flash: Option<String>,
) -> Result<Response, AppError> {
    let id = profile.id;
    let (count, sites) = profile_sites(state, ctx, id).await;
    // ProfileGet's in_use_count is master-local; the union of every node's
    // apply rows is the cluster-wide figure the re-apply button acts on.
    if let Some(n) = count {
        profile.in_use_count = n;
    }
    let unlisted = (profile.in_use_count - sites.len() as i64).max(0);
    let (plugin_assets, theme_assets) = fetch_assets(state).await;
    let tpl = ProfileEditTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "profiles",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        profile,
        price_major,
        unlisted,
        sites,
        csrf_update: csrf_token(state, ctx, &format!("/profiles/{}/update", id)),
        csrf_reapply: csrf_token(state, ctx, "/profiles/reapply"),
        csrf_clone: csrf_token(state, ctx, "/profiles/clone"),
        csrf_delete: csrf_token(state, ctx, "/profiles/delete"),
        saved,
        error,
        flash,
        plugin_assets,
        theme_assets,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Sites on a profile, cluster-wide: the count (None when the master's own
/// list could not be read) and the ones the viewer may see, by domain.
async fn profile_sites(
    state: &SharedState,
    ctx: &AuthCtx,
    profile_id: i64,
) -> (Option<i64>, Vec<SiteLink>) {
    let mut ids: Vec<String> = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ProfileUsage { id: profile_id },
    )
    .await
    {
        Ok(RpcResponse::ProfileUsage(v)) => v,
        _ => return (None, Vec::new()),
    };
    ids.extend(remote_usage_ids(state, profile_id).await);
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return (Some(0), Vec::new());
    }
    let count = ids.len() as i64;
    let rows = super::hostings::list_hostings(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|h| {
            ids.binary_search_by(|i| i.as_str().cmp(h.id.as_str()))
                .is_ok()
        })
        .collect();
    let mut sites: Vec<SiteLink> = super::hostings::filter_by_access(state, ctx, rows)
        .await
        .into_iter()
        .map(|h| SiteLink {
            id: h.id.as_str().to_string(),
            domain: h.domain,
        })
        .collect();
    sites.sort_by(|a, b| a.domain.cmp(&b.domain));
    (Some(count), sites)
}

#[derive(Deserialize, Default)]
pub struct EditQuery {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub flash: Option<String>,
    /// Set by the save redirect.
    #[serde(default)]
    pub saved: bool,
}

pub async fn post_update(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Err(AppError::Forbidden);
    }
    let price_typed = form.price_major.clone();
    let input = match input_from_form(form.clone()) {
        Ok(i) => i,
        Err(msg) => {
            let typed = profile_from_input(id, &input_lossy(&form));
            return render_edit(&state, &ctx, typed, price_typed, false, Some(msg), None).await;
        }
    };
    let typed = profile_from_input(id, &input);
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::ProfileUpdate { id, input })
        .await?;
    match resp {
        // Back to the profile, not the list: the sites still on the old
        // values and the button that updates them are on this page.
        RpcResponse::ProfileUpdate(_) => {
            Ok(Redirect::to(&format!("/profiles/{id}/edit?saved=true")).into_response())
        }
        RpcResponse::Error(hyperion_rpc::RpcError::NotFound { .. }) => Err(AppError::NotFound),
        RpcResponse::Error(e) => {
            render_edit(
                &state,
                &ctx,
                typed,
                price_typed,
                false,
                Some(e.to_string()),
                None,
            )
            .await
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Err(AppError::Forbidden);
    }
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::ProfileDelete { id: form.id })
            .await?;
    match resp {
        RpcResponse::ProfileDelete => {
            Ok(Redirect::to("/profiles?flash=Profile+deleted").into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profiles?error={}",
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ApplyForm {
    pub selector: String,
    pub profile_id: i64,
}

/// POST /profiles/apply — apply a profile to an EXISTING hosting.
///
/// Runs as a background job (kind "profile_apply") so plugin- and
/// theme-heavy profiles get the same per-item progress card the
/// post-create flow has. Redirects back to the hosting detail with
/// `?wpjob=<id>` — the detail page renders the polling progress
/// card whenever that param is present.
///
/// Also fixes a multi-node bug: the previous version called the
/// LOCAL agent socket only, so applying a profile to a worker-
/// resident hosting failed with "no such hosting".
pub async fn post_apply(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ApplyForm>,
) -> Result<Response, AppError> {
    // Applying a profile mutates a specific hosting (PHP limits, expiry,
    // pricing, and installs plugins/themes). Gate it exactly like every
    // other per-hosting mutation: manage-level access to THAT hosting.
    // Previously this had no authz at all — any authenticated user could
    // apply any profile to any hosting cluster-wide.
    let sel = match super::hostings::require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::ProfilesManage,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // Resolve the owning node — the job's RPCs must land there.
    let (detail, owner_node) = match super::hostings::find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?profile_error={}",
                sel_url,
                urlencoding(&e.to_string())
            ))
            .into_response());
        }
    };
    let actor_label = ctx.username.clone();
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let payload = serde_json::json!({
        "hosting_id": detail.id.as_str(),
        "domain": detail.domain,
        "profile_id": form.profile_id,
    });
    let job_state = state.clone();
    let job_target = owner_node.clone();
    let job_hosting_id = detail.id.clone();
    let job_profile_id = form.profile_id;
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "profile_apply",
        Some(&detail.domain),
        &payload.to_string(),
        &actor_label,
        actor_uid,
        move |reporter| async move {
            match super::hostings::run_profile_apply_phase(
                &reporter,
                &job_state,
                job_target.as_deref(),
                &job_hosting_id,
                job_profile_id,
                5,
                90,
                None,
            )
            .await
            {
                Ok(()) => {
                    reporter.step("Done", 100, "Profile fully applied.\n").await;
                    reporter.finish(true, None).await;
                }
                Err(msg) => {
                    reporter.finish(false, Some(msg)).await;
                }
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/hostings/{}?wpjob={}#wordpress", sel_url, job_id)).into_response())
}

#[derive(Deserialize)]
pub struct ReapplyAllForm {
    pub profile_id: i64,
}

/// POST /profiles/reapply — re-push a profile to EVERY hosting on it.
///
/// "Profile as a living plan": after editing a profile, propagate the new
/// limits / quota / expiry / pricing (+ WP items) to all N sites in one job.
/// Reuses the exact per-hosting apply path as the single /profiles/apply
/// (resolves each hosting's owning node, applies the profile inline), so it
/// stays multi-node-correct. Admin+ only — it mutates many hostings at once,
/// potentially across tenants. Redirects to the job page so the operator
/// watches the per-site progress.
pub async fn post_reapply_all(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ReapplyAllForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Err(AppError::Forbidden);
    }
    let profile_id = form.profile_id;
    let edit_url = format!("/profiles/{profile_id}/edit");
    // Hosting ids currently on this profile (master-only table).
    let mut ids: Vec<String> = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ProfileUsage { id: profile_id },
    )
    .await?
    {
        RpcResponse::ProfileUsage(v) => v,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    // Add worker-resident hostings so a re-apply covers the whole cluster, not
    // just master-local sites (their apply rows live on the owning node).
    ids.extend(remote_usage_ids(&state, profile_id).await);
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Ok(Redirect::to(&format!(
            "{edit_url}?flash={}",
            urlencoding("No hostings are on this profile yet — nothing to re-apply.")
        ))
        .into_response());
    }
    let actor_label = ctx.username.clone();
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let payload = serde_json::json!({"profile_id": profile_id, "count": ids.len()});
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "profile_reapply_all",
        None,
        &payload.to_string(),
        &actor_label,
        actor_uid,
        move |reporter| async move {
            let total = ids.len() as i64;
            let mut ok = 0i64;
            let mut failed: Vec<String> = Vec::new();
            // Resolve the profile ONCE for the whole batch (master-only table)
            // and pass it inline to every site — avoids an identical ProfileGet
            // round-trip per hosting inside the loop.
            let profile = match hyperion_rpc_client::call(
                &job_state.agent_socket,
                Request::ProfileGet { id: profile_id },
            )
            .await
            {
                Ok(RpcResponse::ProfileGet(p)) => p,
                _ => {
                    reporter
                        .finish(
                            false,
                            Some(
                                "Couldn't read the profile from the master — nothing re-applied."
                                    .into(),
                            ),
                        )
                        .await;
                    return;
                }
            };
            for (i, raw) in ids.iter().enumerate() {
                let sel =
                    hyperion_rpc::wire::HostingSelector::Id(hyperion_types::HostingId(raw.clone()));
                // Per-site slice of the [5, 95] progress band.
                let base = 5 + (i as i64) * 90 / total;
                let span = (90 / total).max(1);
                let (detail, owner_node) =
                    match super::hostings::find_hosting_anywhere(&job_state, sel).await {
                        Ok(v) => v,
                        Err(e) => {
                            failed.push(format!("{raw}: {e}"));
                            reporter
                                .step(
                                    &format!("Skipped {raw}"),
                                    base + span,
                                    &format!("could not locate hosting {raw}: {e}\n"),
                                )
                                .await;
                            continue;
                        }
                    };
                reporter
                    .step(
                        &format!("Re-applying to {} ({}/{})", detail.domain, i + 1, total),
                        base,
                        &format!("→ {}\n", detail.domain),
                    )
                    .await;
                match super::hostings::run_profile_apply_phase(
                    &reporter,
                    &job_state,
                    owner_node.as_deref(),
                    &detail.id,
                    profile_id,
                    base,
                    span,
                    Some(profile.clone()),
                )
                .await
                {
                    Ok(()) => ok += 1,
                    Err(msg) => failed.push(format!("{}: {msg}", detail.domain)),
                }
            }
            if failed.is_empty() {
                reporter
                    .step("Done", 100, &format!("Re-applied to all {ok} site(s).\n"))
                    .await;
                reporter.finish(true, None).await;
            } else {
                reporter
                    .finish(
                        false,
                        Some(format!(
                            "Re-applied to {ok}/{total}; {} failed:\n{}",
                            failed.len(),
                            failed.join("\n")
                        )),
                    )
                    .await;
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

/// Sum, across all worker nodes, the per-profile live-hosting counts. The
/// master-local counts already live on each HostingProfile (from ProfileList);
/// this adds the workers so the "in use: N" badge is cluster-wide. Best-effort:
/// a down node simply contributes nothing (fan_out excludes it).
async fn remote_usage_counts(state: &SharedState) -> std::collections::HashMap<i64, i64> {
    let mut map: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    let workers = super::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default();
    if workers.is_empty() {
        return map;
    }
    for (_n, resp) in crate::dispatcher::fan_out(state, workers, Request::ProfileUsageCounts).await
    {
        if let RpcResponse::ProfileUsageCounts(counts) = resp {
            for (pid, n) in counts {
                *map.entry(pid).or_insert(0) += n;
            }
        }
    }
    map
}

/// Union, across all worker nodes, the hosting ids on a profile — the caller
/// already holds the master-local ids. Drives cluster-wide re-apply + the
/// edit-page count. Best-effort (a down node contributes nothing).
async fn remote_usage_ids(state: &SharedState, profile_id: i64) -> Vec<String> {
    let mut out = Vec::new();
    let workers = super::hostings::fetch_remote_nodes(state)
        .await
        .unwrap_or_default();
    if workers.is_empty() {
        return out;
    }
    for (_n, resp) in
        crate::dispatcher::fan_out(state, workers, Request::ProfileUsage { id: profile_id }).await
    {
        if let RpcResponse::ProfileUsage(ids) = resp {
            out.extend(ids);
        }
    }
    out
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
    if !ctx.can(Capability::ProfilesManage) {
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
    if !ctx.can(Capability::ProfilesManage) {
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
            Ok(
                Redirect::to(&format!("/profiles/wp-assets?flash={}", urlencoding(&msg)))
                    .into_response(),
            )
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
    if !ctx.can(Capability::ProfilesManage) {
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
            let msg = format!("Installed {kind} \"{original_name}\" from library{activated}.");
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
    if !ctx.can(Capability::ProfilesManage) {
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
    if !ctx.can(Capability::ProfilesManage) {
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
            let key = if installed_failed == 0 {
                "flash"
            } else {
                "error"
            };
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
    if !ctx.can(Capability::ProfilesManage) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::WpAssetDelete { id: form.id })
            .await?;
    match resp {
        RpcResponse::WpAssetDelete => {
            Ok(Redirect::to("/profiles/wp-assets?flash=Asset+deleted").into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profiles/wp-assets?error={}",
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> CreateForm {
        serde_json::from_value(serde_json::json!({"name": "Pro", "php_memory_mb": 512}))
            .expect("form")
    }

    #[test]
    fn row_reads_the_plan_out() {
        let mut p = blank_profile();
        p.disk_hard_mb = Some(2048);
        p.disk_soft_mb = Some(1536);
        p.backup_cadence = "custom".into();
        p.backup_interval_days = 3;
        p.backup_keep_days = 30;
        p.default_php_version = Some("8.3".into());
        p.default_db_engine = Some("mariadb".into());
        p.wp_plugins = "akismet!\n# note\n\nwordpress-seo".into();
        let r = ProfileRow::new(p);
        assert_eq!(r.php, "256 MB · 60 s");
        assert_eq!(r.php_sub, "10 workers · 50 DB connections");
        assert_eq!(r.disk, "2 GB");
        assert_eq!(r.disk_sub, "warns at 1.5 GB");
        assert_eq!(r.backups, "Every 3 days");
        assert_eq!(r.backups_sub, "kept 30 days");
        assert_eq!(r.new_sites, "PHP 8.3 · MariaDB · 2 plugins");
    }

    #[test]
    fn row_for_an_unlimited_profile_without_backups() {
        let mut p = blank_profile();
        // Retention without a cadence keeps nothing — the list must not
        // claim it does.
        p.backup_keep_days = 30;
        let r = ProfileRow::new(p);
        assert_eq!(r.disk, "Unlimited");
        assert_eq!(r.disk_sub, "");
        assert_eq!(r.backups, "Off");
        assert_eq!(r.backups_sub, "");
        assert_eq!(r.new_sites, "");
    }

    #[test]
    fn cadence_labels() {
        assert_eq!(cadence_label("daily", 0), "Daily");
        assert_eq!(cadence_label("custom", 1), "Daily");
        assert_eq!(cadence_label("custom", 0), "Off");
        assert_eq!(cadence_label("", 0), "Off");
        assert_eq!(cadence_label("hourly", 0), "Off");
    }

    #[test]
    fn mb_formatting() {
        assert_eq!(fmt_mb(512), "512 MB");
        assert_eq!(fmt_mb(1024), "1 GB");
        assert_eq!(fmt_mb(10_240), "10 GB");
        assert_eq!(fmt_mb(1500), "1.5 GB");
    }

    #[test]
    fn blank_profile_matches_the_form_defaults() {
        // A field the browser did not send falls back to the same value a
        // fresh form shows.
        let typed = profile_from_input(0, &input_from_form(form()).expect("input"));
        let blank = blank_profile();
        assert_eq!(typed.php_max_exec_secs, blank.php_max_exec_secs);
        assert_eq!(typed.php_max_children, blank.php_max_children);
        assert_eq!(typed.php_max_requests, blank.php_max_requests);
        assert_eq!(typed.db_max_connections, blank.db_max_connections);
        assert_eq!(typed.expiry_grace_days, blank.expiry_grace_days);
        assert_eq!(typed.expiry_warning_offsets, blank.expiry_warning_offsets);
        assert_eq!(typed.php_memory_mb, 512);
    }

    #[test]
    fn a_bad_price_keeps_the_rest_of_the_form() {
        let mut f = form();
        f.price_major = "lots".into();
        f.price_currency = " czk ".into();
        f.description = "the big one".into();
        let err = input_from_form(f.clone()).expect_err("non-numeric price");
        assert!(err.contains("lots"), "{err}");
        let typed = input_lossy(&f);
        assert_eq!(typed.name, "Pro");
        assert_eq!(typed.description, "the big one");
        assert_eq!(typed.price_minor, None);
        assert_eq!(typed.price_currency.as_deref(), Some("CZK"));
    }

    #[test]
    fn blank_optionals_are_none() {
        let mut f = form();
        f.slack_webhook = "  ".into();
        f.default_php_version = String::new();
        f.disk_hard_mb = "0".into();
        let i = input_from_form(f).expect("input");
        assert_eq!(i.slack_webhook, None);
        assert_eq!(i.default_php_version, None);
        assert_eq!(i.disk_hard_mb, None);
        assert_eq!(i.price_minor, None);
    }
}
