use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::{DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector};
use hyperion_types::{
    CertIssueRequest, DbProvision, DnsCheckResult, HostingDetail, HostingProfile, HostingStats,
    HostingSummary, PhpVersion, ProfileApply, SpfCheckResult, WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::{Domain, SystemUserName};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Template)]
#[template(path = "hostings_list.html")]
struct ListTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    /// Each entry is `(hosting, is_on_test_node, is_on_unreachable_node)`.
    /// Pre-tagged on the server so the askama template doesn't need
    /// to do a closure-based set-lookup inside the loop (askama can't
    /// parse Rust closures). `unreachable` ⇒ that node's heartbeat
    /// is more than UNREACHABLE_HEARTBEAT_SECS stale, which usually
    /// means the worker agent is down (the actual hosting may still
    /// be serving traffic on the worker, but we can't operate on it
    /// from the master while the agent is offline).
    rows: Vec<(HostingSummary, bool, bool)>,
    total_count: usize,
    q: String,
    state_filter: String,
    /// Currently active sort column ("" / "domain" / "created" /
    /// "state" / "node"). Template uses this to render the up/down
    /// arrow on the active column header.
    sort_key: String,
    /// "asc" | "desc" — passed through the URL so the operator can
    /// flip the direction by re-clicking the same column.
    sort_dir: String,
    csrf_token: String,
    csrf_bulk: String,
    error: Option<String>,
    flash: Option<String>,
    /// WP asset library — drives the "Bulk install asset" dropdown.
    /// Empty list = the dropdown hides itself.
    wp_assets: Vec<hyperion_types::WpAssetSummary>,
}

#[derive(Template)]
#[template(path = "hostings_new.html")]
struct NewTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    csrf_token: String,
    error: Option<&'a str>,
    domain_in: &'a str,
    aliases_in: &'a str,
    /// "" = none/static, otherwise "8.1".."8.4"
    php_in: String,
    /// "" = none, otherwise "mariadb"/"postgres"
    db_in: String,
    /// "" = default php, otherwise echoes back kind selector
    #[allow(dead_code)]
    kind_in: String,
    /// Echoed-back upstream URL when create failed and kind=reverse_proxy
    proxy_upstream_url_in: String,
    /// Enrolled remote nodes (master excluded). When empty, the
    /// template hides the "Target node" dropdown and the hosting is
    /// provisioned on the master itself.
    nodes: Vec<hyperion_types::NodeSummary>,
    /// Pre-selected target node when re-rendering after a validation
    /// error. Empty / "local" → master.
    target_node_in: String,
    /// Echoes the [cluster] master_accepts_hostings setting from
    /// agent.toml. When false the template hides the master from
    /// the Target-node dropdown — operator turned the master into
    /// a control-plane-only node via Settings → Cluster.
    master_accepts_hostings: bool,
    /// CSV of node ids flagged as test-only. JS uses this to know
    /// when to swap "Primary domain" for the "Test-site short name"
    /// field + render a preview from the template.
    test_node_ids: String,
    /// Template for auto-generated test-site domains (e.g.
    /// "test.{name}.{node}.testovaciverze.cz"). Empty = feature off.
    test_domain_template: String,
    /// All defined hosting profiles, so the wizard's step 1 can
    /// render a picker. Selecting one stamps the profile_id field
    /// in the form; post_create dispatches profile_apply after the
    /// hosting goes Active.
    profiles: Vec<hyperion_types::HostingProfile>,
}

/// Per-field append to `CreateForm` for the optional WP install
/// checkbox + its admin fields. Standalone struct so older code that
/// only uses the basic fields keeps compiling — Form picks both
/// because axum Form derives Deserialize on the whole body.

#[derive(Template)]
#[template(path = "hostings_detail.html")]
struct DetailTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    detail: HostingDetail,
    limits: hyperion_types::HostingLimits,
    wp_status: Option<WpInstallStatus>,
    expiry: hyperion_types::HostingExpiry,
    backups: Vec<hyperion_types::BackupRunWire>,
    stats: Option<HostingStats>,
    csrf_delete: String,
    csrf_suspend: String,
    csrf_resume: String,
    csrf_limits: String,
    csrf_wp_install: String,
    csrf_backup_now: String,
    csrf_expiry_set: String,
    csrf_expiry_clear: String,
    csrf_dns_check: String,
    csrf_cert_issue: String,
    csrf_restore: String,
    csrf_restore_as_new: String,
    csrf_logs: String,
    csrf_cron: String,
    cron_body: String,
    csrf_wp_reset: String,
    csrf_db_reset: String,
    csrf_profile_apply: String,
    profile_apply: Option<ProfileApply>,
    applied_profile_name: Option<String>,
    profiles: Vec<HostingProfile>,
    csrf_ftp_set: String,
    csrf_ftp_disable: String,
    ftp_new_password: Option<String>,
    error: Option<&'a str>,
    wp_error: Option<String>,
    wp_flash: Option<String>,
    backup_error: Option<String>,
    backup_flash: Option<String>,
    expiry_error: Option<String>,
    expiry_flash: Option<String>,
    cert_error: Option<String>,
    cert_flash: Option<String>,
    restore_error: Option<String>,
    restore_flash: Option<String>,
    cron_error: Option<String>,
    cron_flash: Option<String>,
    db_error: Option<String>,
    db_flash: Option<String>,
    profile_error: Option<String>,
    profile_flash: Option<String>,
    ftp_error: Option<String>,
    ftp_flash: Option<String>,
    just_created: Option<HostingCreated>,
    /// When the post-create flow spawned a background WP install /
    /// profile-apply job, this carries the job id so the detail
    /// page can render an inline progress card that HTMX-polls
    /// `/jobs/<id>/progress`. None on the standard GET detail path.
    wp_install_job_id: Option<String>,
    /// Drives the per-user Access tab — super_admin only.
    is_super_admin: bool,
    /// Existing access grants for this hosting (populated for super_admin).
    access_grants: Vec<hyperion_types::WebHostingAccess>,
    /// Users available to grant to (operator/viewer roles; super_admin
    /// and admin are excluded since they already see everything).
    users_for_access: Vec<hyperion_types::WebUserSummary>,
    /// Per-hosting monitor config + sample history (for the Monitor tab).
    monitor_config: hyperion_types::MonitorConfigView,
    monitor_history: hyperion_types::MonitorHistory,
    /// WordPress plugin list — populated only when wp_status is Some.
    /// Empty otherwise; the template's WP tab shows an "install WP first"
    /// state instead of an empty table.
    wp_plugins: hyperion_types::WpPluginListResponse,
    /// Per-hosting email log — last 50 emails the agent sent on
    /// behalf of this hosting (alerts, cert reminders, monitor
    /// down/up, billing). Drives the new Emails tab.
    email_log: Vec<hyperion_types::EmailLogEntry>,
    /// Last 50 outbound mails sent BY the hosted PHP site itself,
    /// captured by /usr/local/lib/hyperion/site-mail-wrapper into
    /// the per-user JSONL. Distinct from `email_log` above which
    /// is Hyperion-system mail.
    site_emails: Vec<hyperion_types::SiteEmailLogEntry>,
    /// Every FTP-usable Linux account on the same node as this
    /// hosting. The FTP tab shows the count + a sortable list so
    /// the operator can see "I created 3 accounts" instead of
    /// trusting the silence after a successful POST.
    ftp_accounts: Vec<hyperion_types::FtpAccountSummary>,
    /// Result of `ftp_verify_login` for THIS hosting's system user,
    /// done right after we know there's a password set. Lets the
    /// UI show a green "vsftpd accepts this credential" pill.
    /// None = no password set / didn't probe.
    ftp_login_ok: Option<bool>,
    /// Session-wide CSRF token used by the newer forms that don't have
    /// dedicated csrf_* fields plumbed (access, acme-email, monitor,
    /// backup delete). Middleware accepts both.
    csrf_token: String,
    /// Which node owns this hosting — "" (master) or the enrolled
    /// `node_id`. Per-hosting action forms render this as a hidden
    /// input so post_suspend / post_delete / post_set_limits / etc.
    /// dispatch the RPC to the correct agent. Empty string is the
    /// safe default for backwards compatibility with single-node
    /// setups.
    target_node: String,
    /// Enrolled remote nodes — drives the one-click "Migrate to…"
    /// dropdown on the Migration tab. Empty on single-node setups
    /// (the dropdown hides itself in that case).
    all_nodes: Vec<hyperion_types::NodeSummary>,
    /// Uploaded plugin/theme ZIPs from the master's library —
    /// drives the "Install from library" dropdown on the WP tab.
    /// Library lives on the MASTER (the master web is what
    /// operators upload to), so we always fetch via the local
    /// agent socket regardless of where this hosting lives.
    wp_assets: Vec<hyperion_types::WpAssetSummary>,
    /// Installed WP themes for the new Themes tab. Same shape as
    /// wp_plugins above, mirrored across the wp_theme adapter.
    /// Empty when wp_status is None (no WP install).
    wp_themes: hyperion_types::WpThemeListResponse,
    /// CSRF token for the vhost options form (basic auth, HSTS,
    /// FastCGI cache, custom snippet, maintenance mode, redirect).
    csrf_vhost_options: String,
    /// Per-hosting quota report (policy + current usage + kernel
    /// enabled flag). Drives the Quota tab. Best-effort: a
    /// `QuotaGet` RPC failure on a worker node yields a default
    /// report so the tab still renders without taking the whole
    /// page down.
    quota: hyperion_types::HostingQuotaReport,
    csrf_quota_set: String,
    /// Set by the post handler on success — banner in the UI.
    vhost_saved: bool,
    /// Set when set_vhost_options returned an error — banner in UI.
    vhost_error: Option<String>,
    /// WP debug toggle form CSRF.
    /// Up to 48 hourly buckets of (disk, bw_in, bw_out, php_requests)
    /// for the Stats card sparklines. Newest last, may be shorter
    /// than 48 if the agent is freshly installed.
    usage_buckets: Vec<hyperion_types::HostingUsageBucket>,
    csrf_wp_debug: String,
    /// WP debug.log rotate button CSRF.
    csrf_wp_debug_rotate: String,
    /// WP Redis enable/disable form CSRF.
    csrf_wp_redis: String,
    /// WP Redis password rotate button CSRF.
    csrf_wp_redis_rotate: String,
    /// Set after a successful WP debug/Redis POST — banner in UI.
    wp_extras_flash: bool,
    /// Set when set_wp_debug / set_redis returned an error — banner.
    wp_extras_error: Option<String>,
    /// All PHP versions Hyperion knows about — drives the "Change
    /// PHP version" dropdown on the PHP row. We pass the full set
    /// (8.1 → 8.4) and let the agent reject a version whose FPM
    /// service isn't installed; that error path is fine because
    /// the operator can install it from /services first. Owned
    /// `String` (not `&str`) so the askama template can compare
    /// directly against `v.as_str()` without a deref dance.
    php_options: Vec<String>,
    /// Composite health snapshot + onboarding checklist. `None` on the
    /// post-create in-place render (the auto-reload lands on the full
    /// detail GET which computes it).
    health: Option<HostingHealth>,
    /// Free-text operator note for this hosting (panel-side metadata).
    notes: String,
    /// Operator tags (already split + cleaned) for filtering/labelling.
    tags: Vec<String>,
    csrf_notes: String,
    /// Effective staging hostname for this hosting — the saved per-hosting
    /// override (master hosting_kv) or the default `staging.<domain>`.
    /// Drives the staging card's input prefill, confirm text + "Open" link.
    staging_domain: String,
    /// Operator php.ini overrides (applied via .user.ini).
    php_ini: PhpIniSettings,
    csrf_php_ini: String,
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub bulk_flash: Option<String>,
    /// Sort column. Empty / unknown ⇒ `domain` (alphabetical), the
    /// default the list shipped with. Accepted: `domain`, `created`,
    /// `updated`, `state`, `node`, `disk`.
    #[serde(default)]
    pub sort: String,
    /// `asc` | `desc`. Empty ⇒ `asc` for textual columns,
    /// `desc` for time/numeric (newest/largest first).
    #[serde(default)]
    pub dir: String,
}

pub async fn get_list(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<ListQuery>,
) -> Result<Response, AppError> {
    let rows = list_hostings(&state).await.map_err(AppError::Rpc)?;
    let total_count = rows.len();
    // Role-based filter: operators + viewers only see hostings they
    // have an explicit access grant for. super_admin + admin see all.
    let rows = filter_by_access(&state, &ctx, rows).await;
    let needle = q.q.trim().to_lowercase();
    let state_filter = q.state.trim().to_lowercase();
    let mut rows: Vec<HostingSummary> = rows
        .into_iter()
        .filter(|r| needle.is_empty() || r.domain.to_lowercase().contains(&needle))
        .filter(|r| state_filter.is_empty() || r.state.as_str() == state_filter)
        .collect();
    // ── Server-side sort ──
    //
    // Operators with 50+ hostings want to find "the one I created
    // today" in a deterministic order. The list defaults to
    // alphabetical-by-domain (preserves the long-standing UX);
    // explicit ?sort= overrides — created (newest first by
    // default), state, node, with ?dir= flipping the comparator.
    let sort_key = q.sort.trim().to_lowercase();
    let dir_desc = match q.dir.trim().to_lowercase().as_str() {
        "desc" => Some(true),
        "asc" => Some(false),
        _ => None,
    };
    // Default direction per column — alphabetical = asc; time =
    // newest-first; state = active first (asc by string works
    // because Active < Failed < Provisioning < Suspended < Trashed).
    let desc = dir_desc.unwrap_or(matches!(sort_key.as_str(), "created" | "updated"));
    match sort_key.as_str() {
        "created" => rows.sort_by_key(|r| r.created_at),
        "state" => rows.sort_by(|a, b| a.state.as_str().cmp(b.state.as_str())),
        "node" => rows.sort_by(|a, b| {
            a.node_id
                .as_deref()
                .unwrap_or("")
                .cmp(b.node_id.as_deref().unwrap_or(""))
        }),
        // Default + "domain" both fall here.
        _ => rows.sort_by(|a, b| a.domain.to_lowercase().cmp(&b.domain.to_lowercase())),
    }
    if desc {
        rows.reverse();
    }
    // Pre-tag each row with `is_on_test_node` + `is_on_unreachable_node`
    // so the template can render the TEST chip + offline pill without
    // doing closure-based set lookups (askama can't parse Rust closures).
    let test_set: std::collections::HashSet<String> = fetch_cluster_config(&state)
        .await
        .test_node_ids
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    // Compute "unreachable" set: any node whose last_seen_at heartbeat
    // is more than UNREACHABLE_HEARTBEAT_SECS old. The agent posts
    // heartbeats every ~30s; 5 min of silence is a clear "the worker
    // is gone" signal. Best-effort — if NodesList errors we just
    // tag nothing (graceful degradation).
    const UNREACHABLE_HEARTBEAT_SECS: i64 = 300;
    let now_secs: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let unreachable_set: std::collections::HashSet<String> = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::NodesList,
    )
    .await
    {
        Ok(RpcResponse::NodesList(ns)) => ns
            .into_iter()
            .filter(|n| n.last_seen_at > 0 && (now_secs - n.last_seen_at) > UNREACHABLE_HEARTBEAT_SECS)
            .map(|n| n.node_id)
            .collect(),
        _ => std::collections::HashSet::new(),
    };
    let rows: Vec<(HostingSummary, bool, bool)> = rows
        .into_iter()
        .map(|r| {
            let is_test = r
                .node_id
                .as_ref()
                .map(|n| test_set.contains(n))
                .unwrap_or(false);
            let is_unreachable = r
                .node_id
                .as_ref()
                .map(|n| unreachable_set.contains(n))
                .unwrap_or(false);
            (r, is_test, is_unreachable)
        })
        .collect();
    let csrf_token = csrf_token_for(&state, &ctx, "/hostings/delete");
    let csrf_bulk = csrf_token_for(&state, &ctx, "/hostings/bulk");
    let tpl = ListTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        rows,
        total_count,
        q: q.q,
        state_filter,
        sort_key: if sort_key.is_empty() { "domain".to_string() } else { sort_key },
        sort_dir: if desc { "desc".into() } else { "asc".into() },
        csrf_token,
        csrf_bulk,
        error: None,
        flash: q.bulk_flash,
        wp_assets: fetch_wp_assets(&state).await.unwrap_or_default(),
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_new(State(state): State<SharedState>, ctx: AuthCtx) -> Result<Response, AppError> {
    // Creating a new hosting is a cluster-scoped action. Tenant-
    // scoped roles (operator / customer / viewer) get bounced —
    // the post_create handler enforces this server-side anyway,
    // bouncing on GET avoids rendering the entire form just to
    // refuse the submit.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    // Wildcard CSRF token so it also covers the DNS-preflight HTMX
    // button (form_id /hostings/dns-check-domain) in addition to the
    // main /hostings POST.
    let csrf_token = super::session_csrf_token(&state, &ctx);
    // Fetch enrolled remote nodes so the "Target node" dropdown can
    // offer them. Failure here just leaves the dropdown empty — the
    // form still works for the default-master case.
    let nodes = match fetch_remote_nodes(&state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error=%e,
                "fetch_remote_nodes failed — Target node dropdown will be empty"
            );
            Vec::new()
        }
    };
    // Check the [cluster] section from agent.toml — master might be
    // set to control-plane-only, in which case we hide the master
    // option from the Target-node dropdown.
    let cluster_cfg = fetch_cluster_config(&state).await;
    let master_accepts_hostings = cluster_cfg.master_accepts_hostings;
    let tpl = NewTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token,
        error: None,
        domain_in: "",
        aliases_in: "",
        php_in: "8.3".to_string(),
        db_in: "mariadb".to_string(),
        kind_in: "php".to_string(),
        proxy_upstream_url_in: String::new(),
        nodes,
        target_node_in: String::new(),
        master_accepts_hostings,
        test_node_ids: cluster_cfg.test_node_ids,
        test_domain_template: cluster_cfg.test_domain_template,
        profiles: fetch_all_profiles(&state).await.unwrap_or_default(),
    };
    // Browsers (and reverse proxies in front) can cache /hostings/new
    // by default. After an enrollment the dropdown should refresh on
    // the next visit, NOT show the previous stale rendering. The
    // form also carries a one-time CSRF token, so a cached page
    // would be useless on submit anyway.
    let mut response = Html(tpl.render()?).into_response();
    let h = response.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    h.insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    h.insert("vary", axum::http::HeaderValue::from_static("Cookie"));
    Ok(response)
}

/// Look up enrolled nodes via NodesList. The master itself isn't a
/// row in the `nodes` table (it's the orchestrator, not an enrollee),
/// so whatever this returns IS the set of remote targets the
/// operator can pick from.
pub(crate) async fn fetch_remote_nodes(
    state: &SharedState,
) -> Result<Vec<hyperion_types::NodeSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await?;
    match resp {
        RpcResponse::NodesList(v) => Ok(v),
        _ => Err(AppError::Internal("unexpected NodesList response".into())),
    }
}

#[derive(Deserialize)]
pub struct CreateForm {
    domain: String,
    #[serde(default)]
    aliases: String,
    #[serde(default)]
    php: String,
    #[serde(default)]
    db: String,
    #[serde(default)]
    system_user: String,
    /// "php" | "static" | "reverse_proxy" — defaults to "php".
    #[serde(default)]
    pub kind: String,
    /// Upstream URL when kind=reverse_proxy.
    #[serde(default)]
    pub proxy_upstream_url: String,
    /// Target node for provisioning. "" / "local" → master itself;
    /// anything else is a node_id from /install / NodesList.
    #[serde(default)]
    pub target_node: String,
    /// Short site name for test-node hostings. When the target is
    /// a test node + this is non-empty, the server renders the
    /// final domain from `cluster.test_domain_template` and
    /// IGNORES `domain` above. Pure UX field — production creates
    /// leave it empty.
    #[serde(default)]
    pub test_site_name: String,
    /// "on" if the user checked the "install WordPress" checkbox.
    #[serde(default)]
    pub install_wp: String,
    /// WP admin login (the username typed into wp-login.php).
    /// Defaults to "admin" when blank. Operators should pick
    /// something non-obvious — "admin" is the first username every
    /// drive-by brute-forcer tries.
    #[serde(default)]
    pub wp_admin_user: String,
    /// WP admin email (also gets the install confirmation email).
    #[serde(default)]
    pub wp_admin_email: String,
    /// WP admin password — what the operator types.
    #[serde(default)]
    pub wp_admin_password: String,
    /// `wp_options.blogname` — default to the domain if blank.
    #[serde(default)]
    pub wp_title: String,
    /// Locale; defaults to en_US if blank.
    #[serde(default)]
    pub wp_locale: String,
    /// Hosting-profile id selected in the wizard's first step.
    /// `0` (or absent) = no profile — operator wants raw defaults.
    /// When non-zero, post_create dispatches profile_apply right
    /// after the hosting goes Active so limits / wp plugins /
    /// themes get stamped in.
    #[serde(default)]
    pub profile_id: i64,
    /// "on" if the operator ticked "issue a Let's Encrypt cert
    /// right after provisioning". Runs as the first step of the
    /// post-create background job (before WP install, so WP's
    /// site_url is served with a trusted cert from the start).
    /// Requires DNS to already point at the target node — the
    /// wizard's DNS preflight tells the operator whether that's
    /// the case.
    #[serde(default)]
    pub issue_cert: String,
}

pub async fn post_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CreateForm>,
) -> Result<Response, AppError> {
    // Creating a new hosting is a cluster-scoped action — operators
    // with per-hosting grants can't conjure new sites into existence.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let csrf_token = super::session_csrf_token(&state, &ctx);

    // ─── Test-node short-name expansion ─────────────────────────
    // When the target is a test node + the operator filled the
    // "Site name" field, we synthesize the final domain from the
    // cluster template instead of using the free-form domain field.
    // Production targets fall through unchanged.
    let cluster_cfg = fetch_cluster_config(&state).await;
    let mut effective_domain = form.domain.trim().to_string();
    let target_is_test = !form.target_node.is_empty()
        && form.target_node != crate::dispatcher::LOCAL_NODE_SENTINEL
        && cluster_cfg.is_test_node(&form.target_node);
    if target_is_test && !form.test_site_name.trim().is_empty() {
        if cluster_cfg.test_domain_template.is_empty() {
            return Ok(render_new_error(
                &ctx,
                &csrf_token,
                &form,
                "Target is a test node but Settings → Test nodes has no domain template. Set one first.",
            ));
        }
        // Validate the short-name: lowercase alphanum + dash, no
        // leading / trailing dash, ≤ 32 chars. Keeps the derived
        // domain DNS-valid even with weird operator typos.
        let name = form.test_site_name.trim().to_ascii_lowercase();
        if name.is_empty() || name.len() > 32
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            || name.starts_with('-') || name.ends_with('-')
        {
            return Ok(render_new_error(
                &ctx,
                &csrf_token,
                &form,
                "Site name must be 1–32 chars of a–z 0–9 -, no leading/trailing dash.",
            ));
        }
        // Resolve the target node's hostname (label) so `{node}`
        // expands to "s4" not "node_01kt9d6hrsbaw1pyzjdmwnmrhp" —
        // operator-friendly URL. Falls back to the long node_id
        // when NodesList lookup fails (rare).
        let node_hostname = fetch_remote_nodes(&state)
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|n| n.node_id == form.target_node)
            .map(|n| n.label)
            .unwrap_or_default();
        effective_domain = cluster_cfg.render_test_domain(&name, &form.target_node, &node_hostname);
    } else if target_is_test && form.test_site_name.trim().is_empty() {
        // Operator picked a test node but didn't fill the short-name
        // field → enforce that the typed domain matches the template
        // shape (e.g. ends in `.testovaciverze.cz`). Sniff the suffix
        // properly via `extract_test_suffix` — the previous
        // `rsplit_once('.')` was a bug: for template
        // `{name}.{node}.testovaciverze.cz` it returned `.cz` and
        // blocked EVERY .cz domain in the cluster.
        if !cluster_cfg.test_domain_template.is_empty() {
            let suffix = extract_test_suffix(&cluster_cfg.test_domain_template);
            if !suffix.is_empty()
                && !effective_domain
                    .to_ascii_lowercase()
                    .ends_with(&suffix.to_ascii_lowercase())
            {
                return Ok(render_new_error(
                    &ctx,
                    &csrf_token,
                    &form,
                    &format!(
                        "Test-node hostings must end with `{suffix}` (per Settings → Test nodes). \
                         Either pick a production node, fill the short Site name field, or \
                         change the typed domain."
                    ),
                ));
            }
        }
    } else if !target_is_test && !cluster_cfg.test_domain_template.is_empty() {
        // Production target: refuse domains that match the test
        // template — operator probably mis-routed.
        let suffix = extract_test_suffix(&cluster_cfg.test_domain_template);
        if !suffix.is_empty()
            && effective_domain
                .to_ascii_lowercase()
                .ends_with(&suffix.to_ascii_lowercase())
        {
            return Ok(render_new_error(
                &ctx,
                &csrf_token,
                &form,
                &format!(
                    "Domain ends with `{suffix}` which is reserved for test nodes. \
                     Either pick a test node or use a different domain."
                ),
            ));
        }
    }

    // Parse inputs; render the form with an error if anything is malformed.
    let domain = match Domain::parse(&effective_domain) {
        Ok(d) => d,
        Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e.to_string())),
    };
    let aliases = match parse_aliases(&form.aliases) {
        Ok(v) => v,
        Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e)),
    };
    let php_version = if form.php.is_empty() || form.php == "none" {
        None
    } else {
        match PhpVersion::from_str(&form.php) {
            Ok(v) => Some(v),
            Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e)),
        }
    };
    let database = if form.db.is_empty() || form.db == "none" {
        None
    } else {
        match DbProvision::from_str(&form.db) {
            Ok(v) => Some(v),
            Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e)),
        }
    };
    let system_user = if form.system_user.trim().is_empty() {
        None
    } else {
        match SystemUserName::parse(form.system_user.trim()) {
            Ok(v) => Some(v),
            Err(e) => return Ok(render_new_error(&ctx, &csrf_token, &form, &e.to_string())),
        }
    };
    let kind = if form.kind == "reverse_proxy" {
        "reverse_proxy".to_string()
    } else if form.kind == "static" {
        "static".to_string()
    } else {
        "php".to_string()
    };
    let proxy_upstream_url = if kind == "reverse_proxy" {
        let u = form.proxy_upstream_url.trim().to_string();
        if u.is_empty() {
            return Ok(render_new_error(
                &ctx,
                &csrf_token,
                &form,
                "Reverse proxy requires an upstream URL.",
            ));
        }
        Some(u)
    } else {
        None
    };
    let req = HostingCreateReq {
        domain,
        aliases,
        php_version,
        database,
        system_user,
        kind,
        proxy_upstream_url,
    };
    // Cache target_node — every downstream RPC in this handler
    // (HostingCreate, optional WpInstall, HostingGet, fetch_limits)
    // must hit the SAME node, otherwise the WP install would land on
    // the master while the hosting itself lives on stav.
    //
    // "auto" is the auto-placement sentinel — pick the best-fit
    // worker by available capacity + load. Falls back to master if
    // no online workers are available + master_accepts_hostings is on.
    let mut target_node = form.target_node.clone();
    if target_node == "auto" {
        match pick_auto_placement_target(&state).await {
            Some(picked) => {
                tracing::info!(picked = %picked, "auto-placement chose node");
                target_node = picked;
            }
            None => {
                // Fall back to master if it accepts hostings;
                // otherwise surface a clean error.
                if fetch_master_accepts_hostings(&state).await {
                    target_node = crate::dispatcher::LOCAL_NODE_SENTINEL.to_string();
                    tracing::info!("auto-placement: no workers, falling back to master");
                } else {
                    return Ok(render_new_error(
                        &ctx,
                        &csrf_token,
                        &form,
                        "Auto-placement found no online workers and master is \
                         in control-plane-only mode. Enrol a worker or enable \
                         master hosting in Settings → Cluster.",
                    ));
                }
            }
        }
    }
    let target = if target_node.is_empty()
        || target_node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(target_node.as_str())
    };
    // Server-side enforcement of the cluster.master_accepts_hostings
    // toggle. UI hides the master option already (defense in depth)
    // but a hand-crafted POST with target_node=local would otherwise
    // bypass it.
    if target.is_none() && !fetch_master_accepts_hostings(&state).await {
        return Ok(render_new_error(
            &ctx,
            &csrf_token,
            &form,
            "Master is in control-plane-only mode (Settings → Cluster). Pick a worker node from the dropdown.",
        ));
    }
    // Loud breadcrumb so the operator can verify in journalctl which
    // node a create attempt was actually dispatched to. The dispatcher
    // also logs, but having both lets us tell apart "form submitted
    // local because dropdown wasn't rendered" (no log here with the
    // real intent) from "dispatcher overrode the choice" (logs differ).
    tracing::info!(
        operator = %ctx.username,
        domain = %req.domain.as_str(),
        target_node_form_value = %target_node,
        target_after_normalize = ?target,
        "post_create dispatch decision"
    );
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingCreate(req.clone()),
    )
    .await?;
    match resp {
        RpcResponse::HostingCreate(mut created) => {
            // ──────────────────────────────────────────────────────
            //  Profile-driven WP install detection.
            //
            //  When the operator picks a profile that includes WP
            //  plugins or themes, profile_apply would try to install
            //  them on a hosting that has no WordPress yet → every
            //  plugin install would fail silently and the operator
            //  would never see those plugins.
            //
            //  Fix: fetch the selected profile, check whether its
            //  wp_plugins/wp_themes lists contain anything meaningful,
            //  and if so:
            //    1. Force WP install on (server-side enforcement —
            //       even if the wizard's checkbox somehow wasn't set
            //       to "on", e.g. operator hand-crafted a POST).
            //    2. Defer profile_apply to AFTER the install so
            //       plugins land on a real WP install.
            //  Also synthesize sensible WP credentials when the
            //  profile mandates WP but the operator didn't fill in
            //  the WP form fields (admin_email defaults to
            //  `admin@<domain>`, password is auto-generated and
            //  shown on the success page).
            // ──────────────────────────────────────────────────────
            let selected_profile: Option<HostingProfile> = if form.profile_id > 0 {
                fetch_all_profiles(&state).await.ok()
                    .and_then(|profs| {
                        profs.into_iter().find(|p| p.id == form.profile_id)
                    })
            } else {
                None
            };
            let profile_forces_wp = selected_profile
                .as_ref()
                .is_some_and(|p| {
                    profile_has_meaningful_wp_content(&p.wp_plugins)
                        || profile_has_meaningful_wp_content(&p.wp_themes)
                });
            // ─── WordPress install + profile apply ───────────
            //
            // The previous synchronous path was responsible for the
            // bug Kevin hit: the WP install step was guarded by 4
            // conditions (db.is_some, kind == php, valid email,
            // password ≥ 6), and EVERY failure mode landed in a
            // `tracing::warn!` — operator saw a clean hosting detail
            // page and no clue WP wasn't installed.
            //
            // Replacement: when WP is requested AND can run (db +
            // php kind), we auto-fill missing credentials, dispatch
            // the work to a background JOB, and surface a live
            // progress card on the just-created hosting detail
            // page. The credentials show immediately so the
            // operator can copy them while the install runs.
            //
            // Bug-incompatible paths that still want the silent
            // "skip" behaviour (no DB, non-PHP kind) get a clean
            // wp_error flash instead of disappearing.
            let wp_form_checked = form.install_wp.eq_ignore_ascii_case("on")
                || form.install_wp == "true"
                || form.install_wp == "1";
            let wp_was_requested = wp_form_checked || profile_forces_wp;
            let issue_cert_checked = form.issue_cert.eq_ignore_ascii_case("on")
                || form.issue_cert == "true"
                || form.issue_cert == "1";
            let mut wp_install_job_id: Option<String> = None;
            let mut wp_install_error: Option<String> = None;
            // Resolve the WP install request (with auto-filled
            // credentials) when WP can actually run. The infeasible
            // combinations surface as a clear flash instead of the
            // old silent skip.
            let mut wp_req_opt: Option<hyperion_types::WpInstallRequest> = None;
            if wp_was_requested && req.kind != "php" {
                wp_install_error = Some(format!(
                    "WordPress install was requested but the hosting kind is `{}` — WP needs a PHP hosting. Recreate with the PHP runtime selected.",
                    req.kind
                ));
            } else if wp_was_requested && created.db.is_none() {
                wp_install_error = Some(
                    "WordPress install was requested but no database was provisioned. WP needs MariaDB — recreate with a database selected.".into(),
                );
            } else if wp_was_requested {
                // Auto-fill missing/short credentials regardless of
                // whether the profile forced WP. The operator picked
                // "install WP" — honor that intent and fill the
                // blanks rather than silently dropping the install.
                let admin_user_raw = form.wp_admin_user.trim();
                let admin_user = if admin_user_raw.is_empty() {
                    "admin".to_string()
                } else {
                    admin_user_raw.to_string()
                };
                let admin_email_input = form.wp_admin_email.trim().to_string();
                let admin_email = if admin_email_input.is_empty() {
                    format!("admin@{}", req.domain.as_str())
                } else {
                    admin_email_input
                };
                let admin_password_input = form.wp_admin_password.clone();
                let admin_password = if admin_password_input.len() < 6 {
                    generate_wp_admin_password()
                } else {
                    admin_password_input
                };
                if !is_valid_wp_username(&admin_user) {
                    wp_install_error = Some(format!(
                        "Admin username `{}` is not a valid WordPress username (letters, numbers, _, -, @, . only). Hosting was created — Re-run WP install from the WordPress tab once you've picked a valid name.",
                        admin_user
                    ));
                } else {
                    let title = if form.wp_title.trim().is_empty() {
                        req.domain.as_str().to_string()
                    } else {
                        form.wp_title.trim().to_string()
                    };
                    let locale = if form.wp_locale.trim().is_empty() {
                        "en_US".to_string()
                    } else {
                        form.wp_locale.trim().to_string()
                    };
                    let site_url = format!("https://{}", req.domain.as_str());
                    let no_index = target_is_test && cluster_cfg.test_wp_no_index;
                    wp_req_opt = Some(hyperion_types::WpInstallRequest {
                        site_url: site_url.clone(),
                        title,
                        admin_user: admin_user.clone(),
                        admin_email: admin_email.clone(),
                        admin_password: admin_password.clone(),
                        locale,
                        version: "latest".to_string(),
                        no_index,
                    });
                    // Show the credentials immediately on the detail
                    // page, even though the install runs in the
                    // background — the operator must save the
                    // password NOW (it's not stored in plaintext).
                    created.wp = Some(hyperion_rpc::wire::WpCreatedInfo {
                        admin_user,
                        admin_email,
                        admin_password,
                        admin_login_url: format!("{}/wp-login.php", site_url),
                    });
                }
            }
            // Spawn the post-create pipeline whenever there's
            // background work to do: LE cert and/or WP install
            // (each optional, profile rides along with WP).
            if wp_req_opt.is_some() || issue_cert_checked {
                let job_state = state.clone();
                let job_target_owned = target.map(|s| s.to_string());
                let job_hosting_id = created.id.clone();
                let job_profile_id = if wp_req_opt.is_some() {
                    form.profile_id
                } else {
                    // Without WP, the profile (if any) is applied by
                    // the synchronous branch below — don't double-
                    // apply it inside the job.
                    0
                };
                let job_payload = serde_json::json!({
                    "hosting_id": created.id.as_str(),
                    "domain": req.domain.as_str(),
                    "issue_cert": issue_cert_checked,
                    "install_wp": wp_req_opt.is_some(),
                    "profile_id": job_profile_id,
                });
                let actor_label = ctx.username.clone();
                let actor_uid = ctx
                    .session
                    .as_ref()
                    .map(|s| s.user_id)
                    .unwrap_or(0);
                let job_wp_req = wp_req_opt;
                let job_domain = req.domain.as_str().to_string();
                let spawn_res = crate::handlers::jobs::spawn_job(
                    state.clone(),
                    "post_create_setup",
                    Some(req.domain.as_str()),
                    &job_payload.to_string(),
                    &actor_label,
                    actor_uid,
                    move |reporter| async move {
                        run_post_create_job(
                            reporter,
                            job_state,
                            job_target_owned,
                            job_hosting_id,
                            job_domain,
                            issue_cert_checked,
                            job_wp_req,
                            job_profile_id,
                        )
                        .await;
                    },
                )
                .await;
                match spawn_res {
                    Ok(id) => wp_install_job_id = Some(id),
                    Err(e) => {
                        wp_install_error = Some(format!(
                            "Could not start the post-create setup job: {e}. Issue the cert from the SSL tab / run WP install from the WordPress tab manually."
                        ));
                    }
                }
            }
            if wp_install_job_id.is_some() {
                // Background job owns the profile apply — skip the
                // synchronous fallback below.
            } else if form.profile_id > 0 {
                // No WP install requested, but a profile WAS chosen
                // — apply it now (likely just PHP limits / expiry,
                // since WP-content profiles trigger the path above).
                // Synchronous because there's no wp-cli I/O to wait
                // on, just a quick limits + expiry update.
                let apply = crate::dispatcher::dispatch_to_node(
                    &state,
                    target,
                    Request::ProfileApply {
                        sel: HostingSelector::Id(created.id.clone()),
                        profile_id: form.profile_id,
                        skip_wp_items: false,
                    },
                )
                .await;
                match apply {
                    Ok(RpcResponse::ProfileApply(_)) => {}
                    Ok(RpcResponse::Error(e)) => {
                        wp_install_error = Some(format!(
                            "Profile applied with errors: {e}. Hosting is alive — re-run from the Profile tab."
                        ));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        wp_install_error = Some(format!(
                            "Profile apply RPC failed: {e}. Re-run from the Profile tab."
                        ));
                    }
                }
            }

            // Re-fetch detail for nice display. Must go to the SAME
            // node we just provisioned on — otherwise the master
            // would return "no such hosting" because the row lives
            // on the remote node's state DB.
            let detail_resp = crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::HostingGet(HostingSelector::Id(created.id.clone())),
            )
            .await?;
            let detail = match detail_resp {
                RpcResponse::HostingGet(d) => d,
                _ => return Err(AppError::Internal("expected HostingGet".into())),
            };
            let limits = fetch_limits(&state, target, HostingSelector::Id(created.id.clone()))
                .await
                .unwrap_or_else(|_| hyperion_types::HostingLimits::defaults());
            let staging_domain_default = format!("staging.{}", detail.domain);
            let tpl = DetailTpl {
                username: &ctx.username,
                user_initial: super::user_initial(&ctx.username),
                active: "hostings",
                css_version: super::css_version(),
                htmx_version: super::htmx_version(),
                detail,
                limits,
                wp_status: None,
                expiry: hyperion_types::HostingExpiry::defaults(),
                backups: vec![],
                stats: None,
                csrf_delete: csrf_token_for(&state, &ctx, "/hostings/delete"),
                csrf_suspend: csrf_token_for(&state, &ctx, "/hostings/suspend"),
                csrf_resume: csrf_token_for(&state, &ctx, "/hostings/resume"),
                csrf_limits: csrf_token_for(&state, &ctx, "/hostings/set-limits"),
                csrf_wp_install: csrf_token_for(&state, &ctx, "/hostings/wp/install"),
                csrf_backup_now: csrf_token_for(&state, &ctx, "/hostings/backup-now"),
                csrf_expiry_set: csrf_token_for(&state, &ctx, "/hostings/expiry/set"),
                csrf_expiry_clear: csrf_token_for(&state, &ctx, "/hostings/expiry/clear"),
                csrf_dns_check: csrf_token_for(&state, &ctx, "/hostings/dns-check"),
                csrf_cert_issue: csrf_token_for(&state, &ctx, "/hostings/cert/issue"),
                csrf_restore: csrf_token_for(&state, &ctx, "/hostings/restore"),
                csrf_restore_as_new: csrf_token_for(&state, &ctx, "/hostings/restore-as-new"),
                csrf_logs: csrf_token_for(&state, &ctx, "/hostings/logs"),
                csrf_cron: csrf_token_for(&state, &ctx, "/hostings/cron"),
                cron_body: String::new(),
                csrf_wp_reset: csrf_token_for(&state, &ctx, "/hostings/wp/reset-password"),
                csrf_db_reset: csrf_token_for(&state, &ctx, "/hostings/db/reset-password"),
                csrf_profile_apply: csrf_token_for(&state, &ctx, "/profiles/apply"),
                profile_apply: None,
                applied_profile_name: None,
                profiles: vec![],
                csrf_ftp_set: csrf_token_for(&state, &ctx, "/hostings/ftp/set"),
                csrf_ftp_disable: csrf_token_for(&state, &ctx, "/hostings/ftp/disable"),
                ftp_new_password: None,
                error: None,
                wp_error: wp_install_error,
                wp_flash: wp_install_job_id
                    .as_ref()
                    .map(|_| "Post-create setup kicked off in the background — live status above.".to_string()),
                backup_error: None,
                backup_flash: None,
                expiry_error: None,
                expiry_flash: None,
                cert_error: None,
                cert_flash: None,
                restore_error: None,
                restore_flash: None,
                cron_error: None,
                cron_flash: None,
                db_error: None,
                db_flash: None,
                profile_error: None,
                profile_flash: None,
                ftp_error: None,
                ftp_flash: None,
                just_created: Some(created),
                wp_install_job_id,
                is_super_admin: ctx.is_super_admin(),
                access_grants: vec![],
                users_for_access: vec![],
                monitor_config: hyperion_types::MonitorConfigView::default(),
                monitor_history: hyperion_types::MonitorHistory::default(),
                wp_plugins: hyperion_types::WpPluginListResponse::default(),
                email_log: vec![],
                site_emails: vec![],
                ftp_accounts: vec![],
                ftp_login_ok: None,
                csrf_token: super::session_csrf_token(&state, &ctx),
                target_node: target.unwrap_or("").to_string(),
                all_nodes: fetch_remote_nodes(&state).await.unwrap_or_default(),
                wp_assets: fetch_wp_assets(&state).await.unwrap_or_default(),
                wp_themes: hyperion_types::WpThemeListResponse::default(),
                csrf_vhost_options: csrf_token_for(&state, &ctx, "/hostings/vhost-options"),
                quota: hyperion_types::HostingQuotaReport::default(),
                csrf_quota_set: csrf_token_for(&state, &ctx, "/hostings/quota/set"),
                vhost_saved: false,
                vhost_error: None,
                usage_buckets: vec![],
                csrf_wp_debug: csrf_token_for(&state, &ctx, "/hostings/wp/debug"),
                csrf_wp_debug_rotate: csrf_token_for(
                    &state,
                    &ctx,
                    "/hostings/wp/debug-log/rotate",
                ),
                csrf_wp_redis: csrf_token_for(&state, &ctx, "/hostings/wp/redis"),
                csrf_wp_redis_rotate: csrf_token_for(&state, &ctx, "/hostings/wp/redis/rotate"),
                wp_extras_flash: false,
                wp_extras_error: None,
                php_options: PHP_VERSION_OPTIONS.iter().map(|s| s.to_string()).collect(),
                health: None,
                notes: String::new(),
                tags: vec![],
                csrf_notes: csrf_token_for(&state, &ctx, "/hostings/notes"),
                staging_domain: staging_domain_default,
                php_ini: PhpIniSettings::default(),
                csrf_php_ini: csrf_token_for(&state, &ctx, "/hostings/php-ini"),
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => Ok(render_new_error(
            &ctx,
            &csrf_token,
            &form,
            &format!("agent: {e}"),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Every PHP version the panel knows how to provision. Drives the
/// PHP-version dropdown on the hosting detail page. Lives here
/// (not in hyperion-types::PhpVersion::all()) so the UI list can
/// be reordered / filtered without touching the type definition.
const PHP_VERSION_OPTIONS: &[&str] = &["8.1", "8.2", "8.3", "8.4"];

/// One row in the per-hosting Health card. `severity` drives the dot
/// colour: good=green, warn=amber, bad=red, info=grey.
pub struct HealthCheck {
    pub severity: &'static str,
    pub ok: bool,
    pub label: String,
    pub detail: String,
}

/// Composite "is this hosting healthy?" snapshot, computed purely from
/// data the detail page already fetches (no extra RPC). The non-green
/// rows double as an onboarding checklist for a freshly-created site.
pub struct HostingHealth {
    pub score: i64,
    pub grade: &'static str,
    pub checks: Vec<HealthCheck>,
    /// Count of checks that aren't green — drives the "N things to fix".
    pub todo: i64,
}

fn health_grade(score: i64) -> &'static str {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_hosting_health(
    detail: &HostingDetail,
    backups: &[hyperion_types::BackupRunWire],
    monitor_enabled: bool,
    wp_installed: bool,
    wp_updates_pending: i64,
    quota: &hyperion_types::HostingQuotaReport,
    now: i64,
) -> HostingHealth {
    let mut checks: Vec<HealthCheck> = Vec::new();
    let mut score: i64 = 100;

    // 1. State
    let active = detail.state == hyperion_types::HostingState::Active;
    checks.push(HealthCheck {
        severity: if active { "good" } else { "bad" },
        ok: active,
        label: "Hosting active".into(),
        detail: if active {
            "Serving normally.".into()
        } else {
            format!("State is {}.", detail.state.as_str())
        },
    });
    if !active {
        score -= 40;
    }

    // 2. Trusted TLS
    let trusted = detail
        .cert
        .as_ref()
        .map(|c| c.issuer != "self-signed")
        .unwrap_or(false);
    checks.push(HealthCheck {
        severity: if trusted { "good" } else { "warn" },
        ok: trusted,
        label: "Trusted HTTPS certificate".into(),
        detail: if trusted {
            "A trusted cert is active.".into()
        } else {
            "Self-signed / none — issue a Let's Encrypt cert from the SSL tab.".into()
        },
    });
    if !trusted {
        score -= 20;
    }

    // 3. Recent backup
    let last_ok = backups
        .iter()
        .filter(|b| b.state == "done")
        .filter_map(|b| b.finished_at)
        .max();
    let backup_ok = last_ok.map(|t| now - t < 7 * 86400).unwrap_or(false);
    checks.push(HealthCheck {
        severity: if backup_ok { "good" } else { "warn" },
        ok: backup_ok,
        label: "Recent backup".into(),
        detail: match last_ok {
            Some(t) if backup_ok => format!("Last backup {}.", crate::handlers::stats::fmt_ago(&t)),
            Some(t) => format!(
                "Last backup {} — older than 7 days.",
                crate::handlers::stats::fmt_ago(&t)
            ),
            None => "No successful backup yet — run one from the Backups tab.".into(),
        },
    });
    if !backup_ok {
        score -= 15;
    }

    // 4. Uptime monitoring
    checks.push(HealthCheck {
        severity: if monitor_enabled { "good" } else { "info" },
        ok: monitor_enabled,
        label: "Uptime monitoring".into(),
        detail: if monitor_enabled {
            "Enabled.".into()
        } else {
            "Off — turn it on in the Monitor tab.".into()
        },
    });
    if !monitor_enabled {
        score -= 5;
    }

    // 5. WordPress up to date (only when WP is installed)
    if wp_installed {
        let current = wp_updates_pending == 0;
        checks.push(HealthCheck {
            severity: if current { "good" } else { "warn" },
            ok: current,
            label: "WordPress up to date".into(),
            detail: if current {
                "All plugins current.".into()
            } else {
                format!("{wp_updates_pending} plugin update(s) pending.")
            },
        });
        if !current {
            score -= 10;
        }
    }

    // 6. Disk headroom (only when quotas are actually enforced)
    if quota.quotas_enabled_on_fs && quota.policy.disk_hard_kib > 0 {
        let pct =
            ((quota.current_disk_kib as f64 / quota.policy.disk_hard_kib as f64) * 100.0) as i64;
        let (sev, ok, penalty) = if pct >= 90 {
            ("bad", false, 15)
        } else if pct >= 75 {
            ("warn", false, 5)
        } else {
            ("good", true, 0)
        };
        checks.push(HealthCheck {
            severity: sev,
            ok,
            label: "Disk headroom".into(),
            detail: format!("{pct}% of the disk quota used."),
        });
        score -= penalty;
    }

    let score = score.clamp(0, 100);
    let todo = checks.iter().filter(|c| !c.ok).count() as i64;
    HostingHealth {
        score,
        grade: health_grade(score),
        checks,
        todo,
    }
}

/// Operator-tunable php.ini settings, applied via a per-hosting
/// `.user.ini` in htdocs (PHP_INI_PERDIR — no FPM pool change, so a bad
/// value can never stop the pool from starting). Empty string = leave
/// the pool/global default. Values are validated before they're written.
#[derive(Default)]
pub struct PhpIniSettings {
    pub memory_limit: String,
    pub upload_max_filesize: String,
    pub post_max_size: String,
    pub max_execution_time: String,
    pub max_input_vars: String,
    pub display_errors: String,
}

impl PhpIniSettings {
    /// Build from a hosting's KV map (keys prefixed `php.`).
    fn from_kv(pairs: &[(String, String)]) -> Self {
        let get = |k: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        PhpIniSettings {
            memory_limit: get("php.memory_limit"),
            upload_max_filesize: get("php.upload_max_filesize"),
            post_max_size: get("php.post_max_size"),
            max_execution_time: get("php.max_execution_time"),
            max_input_vars: get("php.max_input_vars"),
            display_errors: get("php.display_errors"),
        }
    }

    /// True when at least one override is set (drives "managed by
    /// Hyperion" note in the UI).
    pub fn any(&self) -> bool {
        !(self.memory_limit.is_empty()
            && self.upload_max_filesize.is_empty()
            && self.post_max_size.is_empty()
            && self.max_execution_time.is_empty()
            && self.max_input_vars.is_empty()
            && self.display_errors.is_empty())
    }
}

pub async fn get_detail(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DetailQuery>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    // Multi-node detail lookup: try master first, then fan out across
    // enrolled workers. Returns the detail PLUS the node id where it
    // was found so every subsequent per-hosting RPC on this page
    // (limits, stats, backups, …) goes to the SAME node. Without
    // this, the detail page would show 404 for any hosting that
    // lives on a worker.
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    let target = owner_node.as_deref();
    // RBAC guard: operator + viewer must have an access grant.
    // super_admin + admin pass through. Unauthenticated redirects to
    // /login earlier (require_auth middleware), so unwrap to /hostings
    // for the no-access case.
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    let sel_id = HostingSelector::Id(detail.id.clone());

    // === Parallel RPC fan-out ===
    // The hosting detail page used to do ~12 serial RPCs (limits,
    // wp_status, plugins, themes, expiry, backups, stats, cron,
    // profile_apply, profiles, spf, monitor, email_log). On a
    // multi-node setup with 100ms+ per RPC that added up to >1s
    // of page-render latency. tokio::join! buckets them so the
    // whole page is bounded by the SLOWEST single RPC.
    //
    // wp_plugins + wp_themes still depend on wp_status (only
    // probe wp-cli if WP is installed). We get wp_status in the
    // first wave + conditionally fire plugins/themes in a tiny
    // second wave.
    let usage_fut = async {
        match crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::HostingUsage { sel: sel_id.clone(), limit: 48 },
        )
        .await
        {
            Ok(RpcResponse::HostingUsage(rows)) => rows,
            _ => vec![],
        }
    };
    let (
        limits_res,
        wp_status_res,
        expiry_res,
        backups_res,
        stats_res,
        cron_res,
        profile_apply_res,
        profiles_res,
        usage_buckets,
    ) = tokio::join!(
        fetch_limits(&state, target, sel_id.clone()),
        fetch_wp_status(&state, target, sel_id.clone()),
        fetch_expiry(&state, target, sel_id.clone()),
        fetch_backup_list(&state, target, sel_id.clone(), 10),
        fetch_stats(&state, target, sel_id.clone()),
        fetch_cron(&state, target, sel_id.clone()),
        fetch_profile_apply(&state, target, sel_id.clone()),
        fetch_all_profiles(&state),
        usage_fut,
    );
    let limits = limits_res.unwrap_or_else(|_| hyperion_types::HostingLimits::defaults());
    let wp_status = wp_status_res.unwrap_or(None);
    let expiry = expiry_res.unwrap_or_else(|_| hyperion_types::HostingExpiry::defaults());
    let backups = backups_res.unwrap_or_default();
    let stats = stats_res.ok();
    let cron_body = cron_res.unwrap_or_default();
    let profile_apply = profile_apply_res.unwrap_or(None);
    let profiles = profiles_res.unwrap_or_default();

    // Wave 2 — independent of wp_status, and WP plugins/themes
    // only when WP is installed. Wave 1 already finished so we
    // know wp_status now.
    let wp_plugins_fut = async {
        if wp_status.is_some() {
            match crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::WpPluginList { hosting: sel_id.clone() },
            )
            .await
            {
                Ok(RpcResponse::WpPluginList(r)) => r,
                _ => hyperion_types::WpPluginListResponse::default(),
            }
        } else {
            hyperion_types::WpPluginListResponse::default()
        }
    };
    let wp_themes_fut = async {
        if wp_status.is_some() {
            match crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::WpThemeList { hosting: sel_id.clone() },
            )
            .await
            {
                Ok(RpcResponse::WpThemeList(r)) => r,
                _ => hyperion_types::WpThemeListResponse::default(),
            }
        } else {
            hyperion_types::WpThemeListResponse::default()
        }
    };
    let monitor_fut = async {
        // Monitor config/history live on the OWNING node (post_monitor_set
        // writes there) — read from the same node, not the master local
        // socket, or a worker-hosted site's Monitor tab always shows
        // "disabled / no history" even after the operator enabled it.
        match crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::MonitorGet { sel: sel_id.clone() },
        )
        .await
        {
            Ok(RpcResponse::MonitorGet { config, history }) => (config, history),
            _ => (
                hyperion_types::MonitorConfigView::default(),
                hyperion_types::MonitorHistory::default(),
            ),
        }
    };
    // NOTE: the passive DNS preflight banner and the SPF card are
    // NOT part of this join anymore. Both shell out to dig/curl on
    // the agent (up to ~8s worst case on broken DNS), which used to
    // gate the whole page render. They now load lazily over HTMX
    // via /hostings/:sel/dns-panel and /hostings/:sel/spf-panel.
    let email_log_fut = async {
        // Per-hosting Hyperion mail log lives on the owning node too.
        match crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::EmailLogList {
                hosting_id: Some(detail.id.as_str().to_string()),
                limit: 50,
            },
        )
        .await
        {
            Ok(RpcResponse::EmailLogList(r)) => r,
            _ => vec![],
        }
    };
    // Site-outbound mail — captured by the wrapper on the agent
    // where the hosting lives, so dispatch this one through
    // dispatch_to_node instead of the local socket. We hand a
    // clone of `state` into the future to keep the other join!
    // members' borrows happy.
    let site_emails_fut = {
        let su = detail.system_user.clone();
        let state2 = state.clone();
        async move {
            match crate::dispatcher::dispatch_to_node(
                &state2,
                target,
                Request::SiteEmailLogList {
                    system_user: su,
                    limit: 50,
                },
            )
            .await
            {
                Ok(RpcResponse::SiteEmailLogList(r)) => r,
                _ => vec![],
            }
        }
    };
    // FTP accounts on the same node — surfaces "you've created N
    // accounts" on the FTP tab. Cheap (shadow read + one SQL join).
    let ftp_accounts_fut = {
        let state2 = state.clone();
        async move {
            match crate::dispatcher::dispatch_to_node(
                &state2,
                target,
                Request::FtpAccountsList,
            )
            .await
            {
                Ok(RpcResponse::FtpAccountsList(mut rows)) => {
                    for r in &mut rows {
                        r.node_id = target.unwrap_or("").to_string();
                    }
                    rows
                }
                _ => vec![],
            }
        }
    };
    // Quota fan-out joins the same RPC bucket so the Quota tab
    // doesn't add a sequential round-trip to the page load.
    let quota_fut = {
        let state2 = state.clone();
        let sel = sel_id.clone();
        async move {
            match crate::dispatcher::dispatch_to_node(
                &state2,
                target,
                Request::QuotaGet { hosting: sel },
            )
            .await
            {
                Ok(RpcResponse::QuotaGet(r)) => r,
                _ => hyperion_types::HostingQuotaReport::default(),
            }
        }
    };
    let (
        wp_plugins,
        wp_themes,
        monitor_pair,
        email_log,
        site_emails,
        ftp_accounts,
        quota,
    ) = tokio::join!(
        wp_plugins_fut,
        wp_themes_fut,
        monitor_fut,
        email_log_fut,
        site_emails_fut,
        ftp_accounts_fut,
        quota_fut,
    );
    // If THIS hosting's user has a password, probe vsftpd to
    // verify it actually accepts the credential. We don't know
    // the password (it's only ever shown once), so we can only
    // check "user is in shadow". Login probe is left to the
    // operator via a dedicated button in the UI.
    let ftp_login_ok: Option<bool> = ftp_accounts
        .iter()
        .find(|a| a.user == detail.system_user)
        .map(|a| a.has_password);
    let (monitor_config, monitor_history) = monitor_pair;

    let applied_profile_name = profile_apply
        .as_ref()
        .and_then(|a| a.profile_id)
        .and_then(|pid| profiles.iter().find(|p| p.id == pid).map(|p| p.name.clone()));
    // Access tab data — fetched only for super_admin since they're the
    // only ones who see the tab. Empty vec for everyone else is cheap
    // and keeps the template happy.
    let (access_grants_for_detail, users_for_access_for_detail) = if ctx.is_super_admin() {
        let grants = match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::WebListHostingAccess {
                hosting_id: detail.id.as_str().to_string(),
            },
        )
        .await
        {
            Ok(RpcResponse::WebListHostingAccess(g)) => g,
            _ => vec![],
        };
        let users = match hyperion_rpc_client::call(&state.agent_socket, Request::WebUserList)
            .await
        {
            Ok(RpcResponse::WebUserList(u)) => u
                .into_iter()
                // Only operators + viewers can be granted per-web access;
                // super_admin and admin already see everything.
                .filter(|u| u.role == "operator" || u.role == "viewer")
                .collect(),
            _ => vec![],
        };
        (grants, users)
    } else {
        (vec![], vec![])
    };
    // Composite health snapshot — computed from data already fetched
    // above (no extra RPC). Borrows `detail` before it's moved into the
    // template below.
    let hosting_health = compute_hosting_health(
        &detail,
        &backups,
        monitor_config.enabled,
        wp_status.is_some(),
        wp_plugins.updates_pending,
        &quota,
        hyperion_types::now_secs(),
    );
    // Operator notes + tags (panel-side metadata on the master's
    // hosting_kv, keyed by ULID — same regardless of which node hosts
    // the site).
    let kv_pairs = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingKvList {
            hosting_id: detail.id.as_str().to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v,
        _ => vec![],
    };
    let notes = kv_pairs
        .iter()
        .find(|(k, _)| k == "notes")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let tags: Vec<String> = kv_pairs
        .iter()
        .find(|(k, _)| k == "tags")
        .map(|(_, v)| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    // Effective staging hostname: saved per-hosting override or default.
    let staging_domain = kv_pairs
        .iter()
        .find(|(k, _)| k == "staging_domain")
        .map(|(_, v)| v.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("staging.{}", detail.domain));
    let tpl = DetailTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        detail,
        limits,
        wp_status,
        expiry,
        backups,
        stats,
        csrf_delete: csrf_token_for(&state, &ctx, "/hostings/delete"),
        csrf_suspend: csrf_token_for(&state, &ctx, "/hostings/suspend"),
        csrf_resume: csrf_token_for(&state, &ctx, "/hostings/resume"),
        csrf_limits: csrf_token_for(&state, &ctx, "/hostings/set-limits"),
        csrf_wp_install: csrf_token_for(&state, &ctx, "/hostings/wp/install"),
        csrf_backup_now: csrf_token_for(&state, &ctx, "/hostings/backup-now"),
        csrf_expiry_set: csrf_token_for(&state, &ctx, "/hostings/expiry/set"),
        csrf_expiry_clear: csrf_token_for(&state, &ctx, "/hostings/expiry/clear"),
        csrf_dns_check: csrf_token_for(&state, &ctx, "/hostings/dns-check"),
        csrf_cert_issue: csrf_token_for(&state, &ctx, "/hostings/cert/issue"),
        csrf_restore: csrf_token_for(&state, &ctx, "/hostings/restore"),
        csrf_restore_as_new: csrf_token_for(&state, &ctx, "/hostings/restore-as-new"),
        csrf_logs: csrf_token_for(&state, &ctx, "/hostings/logs"),
        csrf_cron: csrf_token_for(&state, &ctx, "/hostings/cron"),
        cron_body,
        csrf_wp_reset: csrf_token_for(&state, &ctx, "/hostings/wp/reset-password"),
        csrf_db_reset: csrf_token_for(&state, &ctx, "/hostings/db/reset-password"),
        csrf_profile_apply: csrf_token_for(&state, &ctx, "/profiles/apply"),
        profile_apply,
        applied_profile_name,
        profiles,
        csrf_ftp_set: csrf_token_for(&state, &ctx, "/hostings/ftp/set"),
        csrf_ftp_disable: csrf_token_for(&state, &ctx, "/hostings/ftp/disable"),
        ftp_new_password: q.ftp_pw,
        error: None,
        wp_error: q.wp_error,
        wp_flash: q.wp.map(|s| {
            if s == "reset" {
                "WordPress admin password reset.".to_string()
            } else {
                "WordPress install succeeded.".into()
            }
        }),
        backup_error: q.backup_error,
        backup_flash: q.backup.map(|_| "Backup started — see list below.".into()),
        expiry_error: q.expiry_error,
        expiry_flash: q.expiry.map(|s| {
            if s == "cleared" {
                "Expiry cleared.".to_string()
            } else {
                "Expiry updated.".to_string()
            }
        }),
        cert_error: q.cert_error,
        cert_flash: q.cert.map(|s| {
            if s == "staging" {
                "Staging certificate issued — issuer 'letsencrypt-staging'.".into()
            } else {
                "Production HTTPS certificate issued.".into()
            }
        }),
        restore_error: q.restore_error,
        restore_flash: q.restore.map(|_| "Backup restored.".into()),
        cron_error: q.cron_error,
        cron_flash: q.cron.map(|_| "Crontab saved.".into()),
        db_error: q.db_error,
        db_flash: q.db.map(|_| "Database password reset.".into()),
        profile_error: q.profile_error,
        profile_flash: q.profile.map(|_| "Profile applied.".into()),
        ftp_error: q.ftp_error,
        ftp_flash: q.ftp.map(|s| {
            if s == "disabled" {
                "FTP disabled — password cleared.".into()
            } else {
                "FTP password set.".into()
            }
        }),
        just_created: None,
        wp_install_job_id: q.wpjob.filter(|s| !s.trim().is_empty()),
        is_super_admin: ctx.is_super_admin(),
        access_grants: access_grants_for_detail,
        users_for_access: users_for_access_for_detail,
        monitor_config,
        monitor_history,
        wp_plugins,
        email_log,
        site_emails,
        ftp_accounts,
        ftp_login_ok,
        csrf_token: super::session_csrf_token(&state, &ctx),
        target_node: owner_node.clone().unwrap_or_default(),
        all_nodes: fetch_remote_nodes(&state).await.unwrap_or_default(),
        wp_assets: fetch_wp_assets(&state).await.unwrap_or_default(),
        wp_themes,
        csrf_vhost_options: csrf_token_for(&state, &ctx, "/hostings/vhost-options"),
        quota,
        csrf_quota_set: csrf_token_for(&state, &ctx, "/hostings/quota/set"),
        vhost_saved: q.vhost_saved.as_deref() == Some("1"),
        vhost_error: q.vhost_error,
        usage_buckets,
        csrf_wp_debug: csrf_token_for(&state, &ctx, "/hostings/wp/debug"),
        csrf_wp_debug_rotate: csrf_token_for(&state, &ctx, "/hostings/wp/debug-log/rotate"),
        csrf_wp_redis: csrf_token_for(&state, &ctx, "/hostings/wp/redis"),
        csrf_wp_redis_rotate: csrf_token_for(&state, &ctx, "/hostings/wp/redis/rotate"),
        wp_extras_flash: q.wp_extras_saved.as_deref() == Some("1"),
        wp_extras_error: q.wp_extras_error,
        php_options: PHP_VERSION_OPTIONS.iter().map(|s| s.to_string()).collect(),
        health: Some(hosting_health),
        notes,
        tags,
        csrf_notes: csrf_token_for(&state, &ctx, "/hostings/notes"),
        staging_domain,
        php_ini: PhpIniSettings::from_kv(&kv_pairs),
        csrf_php_ini: csrf_token_for(&state, &ctx, "/hostings/php-ini"),
    };
    Ok(Html(tpl.render()?).into_response())
}

async fn fetch_profile_apply(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<Option<ProfileApply>, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::ProfileGetApply { sel }).await?;
    match resp {
        RpcResponse::ProfileGetApply(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_all_profiles(state: &SharedState) -> Result<Vec<HostingProfile>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::ProfileList).await?;
    match resp {
        RpcResponse::ProfileList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_cron(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<String, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::CronList { sel }).await?;
    match resp {
        RpcResponse::CronList(s) => Ok(s),
        RpcResponse::Error(_) => Ok(String::new()),
        _ => Ok(String::new()),
    }
}

async fn fetch_stats(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<HostingStats, AppError> {
    let resp = crate::dispatcher::dispatch_to_node(state, target, Request::HostingStats { sel })
        .await?;
    match resp {
        RpcResponse::HostingStats(s) => Ok(s),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize, Default)]
pub struct DetailQuery {
    /// Set to "installed" via the redirect after a successful WP install.
    #[serde(default)]
    pub wp: Option<String>,
    /// Job id of a running WP-install / profile-apply job — when
    /// present the detail page renders the live polling progress
    /// card. Set by the /profiles/apply redirect (and usable by
    /// any future flow that wants the same card).
    #[serde(default)]
    pub wpjob: Option<String>,
    /// Surface WP install failures back into the detail page.
    #[serde(default)]
    pub wp_error: Option<String>,
    #[serde(default)]
    pub backup: Option<String>,
    #[serde(default)]
    pub backup_error: Option<String>,
    #[serde(default)]
    pub expiry: Option<String>,
    #[serde(default)]
    pub expiry_error: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub cert_error: Option<String>,
    #[serde(default)]
    pub restore: Option<String>,
    #[serde(default)]
    pub restore_error: Option<String>,
    #[serde(default)]
    pub cron: Option<String>,
    #[serde(default)]
    pub cron_error: Option<String>,
    #[serde(default)]
    pub db: Option<String>,
    #[serde(default)]
    pub db_error: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub profile_error: Option<String>,
    #[serde(default)]
    pub ftp: Option<String>,
    #[serde(default)]
    pub ftp_error: Option<String>,
    /// Newly-set FTP password — shown ONCE then dropped. Carried in
    /// the query string after a successful POST so the redirect lands
    /// the operator on the page WITH the password visible.
    #[serde(default)]
    pub ftp_pw: Option<String>,
    /// "1" after a successful vhost-options POST → green banner.
    #[serde(default)]
    pub vhost_saved: Option<String>,
    /// nginx -t error / validation error from the vhost-options POST,
    /// surfaced back through the redirect.
    #[serde(default)]
    pub vhost_error: Option<String>,
    /// "1" after WP debug / Redis form was applied successfully.
    #[serde(default)]
    pub wp_extras_saved: Option<String>,
    /// Error from WP debug / Redis form, surfaced via redirect.
    #[serde(default)]
    pub wp_extras_error: Option<String>,
}

async fn fetch_expiry(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<hyperion_types::HostingExpiry, AppError> {
    let resp = crate::dispatcher::dispatch_to_node(state, target, Request::HostingGetExpiry(sel))
        .await?;
    match resp {
        RpcResponse::HostingGetExpiry(e) => Ok(e),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_backup_list(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
    limit: i64,
) -> Result<Vec<hyperion_types::BackupRunWire>, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::BackupList { sel, limit })
            .await?;
    match resp {
        RpcResponse::BackupList(rows) => Ok(rows),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_wp_status(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<Option<WpInstallStatus>, AppError> {
    let resp =
        crate::dispatcher::dispatch_to_node(state, target, Request::WpStatus { sel }).await?;
    match resp {
        RpcResponse::WpStatus(s) => Ok(s),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpInstallForm {
    pub selector: String,
    pub site_url: String,
    pub title: String,
    pub admin_user: String,
    pub admin_email: String,
    pub admin_password: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Deserialize)]
pub struct BackupNowForm {
    pub selector: String,
    #[serde(default)]
    pub target_node: String,
}

pub async fn post_backup_now(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupNowForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::BackupNow { sel },
    )
    .await?;
    let sel_url = urlencoding(&form.selector);
    match resp {
        RpcResponse::BackupNow(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?backup=started", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?backup_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SetExpiryForm {
    pub selector: String,
    /// `YYYY-MM-DD` from <input type="date">, or empty to clear.
    pub expires_on: String,
    #[serde(default)]
    pub owner_email: String,
    #[serde(default)]
    pub grace_days: Option<i64>,
    #[serde(default)]
    pub warning_offsets: Option<String>,
}

pub async fn post_set_expiry(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetExpiryForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let expires_at = match parse_yyyymmdd_to_epoch(form.expires_on.trim()) {
        Ok(t) => t,
        Err(msg) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?expiry_error={}",
                sel_url,
                urlencoding(&msg)
            ))
            .into_response());
        }
    };
    let expiry = hyperion_types::HostingExpiry {
        expires_at,
        owner_email: if form.owner_email.trim().is_empty() {
            None
        } else {
            Some(form.owner_email.trim().to_string())
        },
        grace_days: form.grace_days.unwrap_or(30).max(0),
        warning_offsets_days: form
            .warning_offsets
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("30,7,1")
            .to_string(),
    };
    // Expiry lives on the owner node (the detail page reads it from
    // there); dispatch the write to the same node, mirroring
    // post_clear_expiry. Master-local-only made Set fail on every
    // worker-hosted site while Clear worked.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::HostingSetExpiry { sel, expiry },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetExpiry(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?expiry=set", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?expiry_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ClearExpiryForm {
    pub selector: String,
}

pub async fn post_clear_expiry(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ClearExpiryForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // Find owner node first — when the operator clicks Clear Expiry
    // on a worker-hosted row, dispatch to the worker, not the
    // master that doesn't know about that hosting.
    let target_owned: Option<String> =
        find_hosting_anywhere(&state, sel.clone())
            .await
            .ok()
            .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::HostingClearExpiry(sel),
    )
    .await?;
    match resp {
        RpcResponse::HostingClearExpiry => {
            Ok(Redirect::to(&format!("/hostings/{}?expiry=cleared", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?expiry_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Parse YYYY-MM-DD into a Unix epoch (UTC midnight). Empty input → None.
fn parse_yyyymmdd_to_epoch(s: &str) -> Result<Option<i64>, String> {
    if s.is_empty() {
        return Ok(None);
    }
    let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| format!("Date must be YYYY-MM-DD, got: {s}"))?;
    let dt = d
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| "Invalid date".to_string())?
        .and_utc();
    Ok(Some(dt.timestamp()))
}

pub async fn post_wp_install(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpInstallForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let locale = if form.locale.trim().is_empty() {
        "en_US".to_string()
    } else {
        form.locale.trim().to_string()
    };
    let version = if form.version.trim().is_empty() {
        "latest".to_string()
    } else {
        form.version.trim().to_string()
    };
    let req = WpInstallRequest {
        site_url: form.site_url.trim().to_string(),
        title: form.title.trim().to_string(),
        admin_user: form.admin_user.trim().to_string(),
        admin_email: form.admin_email.trim().to_string(),
        admin_password: form.admin_password,
        locale,
        version,
        // Stand-alone WP install (existing hosting, not part of
        // create flow) — leave no_index off; operator can flip
        // it later in WP admin.
        no_index: false,
    };
    // Find owner node so WpInstall lands on the right agent
    // (post-migration the master may not own the row anymore).
    let target_owned: Option<String> =
        find_hosting_anywhere(&state, sel.clone())
            .await
            .ok()
            .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::WpInstall { sel, req },
    )
    .await?;
    let sel_url = urlencoding(&form.selector);
    match resp {
        RpcResponse::WpInstall(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?wp=installed", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?wp_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn fetch_limits(
    state: &SharedState,
    target: Option<&str>,
    sel: HostingSelector,
) -> Result<hyperion_types::HostingLimits, AppError> {
    let resp = crate::dispatcher::dispatch_to_node(state, target, Request::HostingGetLimits(sel))
        .await?;
    match resp {
        RpcResponse::HostingGetLimits(l) => Ok(l),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    selector: String,
    #[serde(default)]
    keep_user: Option<String>,
    #[serde(default)]
    keep_db: Option<String>,
    /// Which node owns this hosting. Filled by the listing template
    /// from the aggregated HostingSummary.node_id field. Empty /
    /// "local" → master itself. Missing field defaults to master
    /// for backwards compatibility with the pre-multi-node form.
    #[serde(default)]
    target_node: String,
}

pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let opts = DeleteOpts {
        keep_user: form.keep_user.as_deref() == Some("on"),
        keep_database: form.keep_db.as_deref() == Some("on"),
    };
    // Deleting is the slowest mutation we have — nginx reload, acme
    // cleanup, DROP DATABASE, rm -rf of the whole tree, userdel. On
    // a big site that's tens of seconds, which used to leave the
    // operator staring at a hung POST (and the browser console full
    // of aborted-fetch noise). Run it as a background job and land
    // on the job page with a live progress bar instead.
    //
    // Dispatch goes to the node that actually owns the hosting.
    // Without this, deletes always hit the master and silently do
    // nothing for hostings provisioned on a worker (the very bug
    // that left orphan rows blocking the UNIQUE(domain) constraint
    // on retry).
    let target_owned: Option<String> = node_target(&form.target_node).map(String::from);
    let payload = serde_json::json!({
        "selector": form.selector,
        "keep_user": opts.keep_user,
        "keep_database": opts.keep_database,
        "target_node": form.target_node,
    });
    let actor_label = ctx.username.clone();
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let job_state = state.clone();
    let job_selector = form.selector.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "hosting_delete",
        Some(&form.selector),
        &payload.to_string(),
        &actor_label,
        actor_uid,
        move |reporter| async move {
            reporter
                .step(
                    &format!("Deleting {job_selector} — vhost, certificate, database, files…"),
                    20,
                    "",
                )
                .await;
            let resp = crate::dispatcher::dispatch_to_node(
                &job_state,
                target_owned.as_deref(),
                Request::HostingDelete { sel, opts },
            )
            .await;
            match resp {
                Ok(RpcResponse::HostingDelete) => {
                    reporter
                        .step("Hosting deleted.", 100, "✓ hosting removed")
                        .await;
                    reporter.finish(true, None).await;
                }
                Ok(RpcResponse::Error(e)) => {
                    reporter.finish(false, Some(e.to_string())).await;
                }
                Ok(_) => {
                    reporter
                        .finish(false, Some("unexpected agent response".into()))
                        .await;
                }
                Err(e) => {
                    reporter.finish(false, Some(e.to_string())).await;
                }
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{job_id}")).into_response())
}

#[derive(Deserialize)]
pub struct NotesForm {
    pub selector: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: String,
}

/// Normalise a comma-separated tag string into trimmed, lowercased,
/// deduped, charset-limited tokens (≤12 tags, ≤24 chars each).
fn normalize_tags(raw: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for t in raw.split(',') {
        let cleaned: String = t
            .trim()
            .to_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
            .take(24)
            .collect();
        let cleaned = cleaned.trim().to_string();
        if cleaned.is_empty() {
            continue;
        }
        if seen.insert(cleaned.clone()) {
            out.push(cleaned);
        }
        if out.len() >= 12 {
            break;
        }
    }
    out
}

/// POST /hostings/notes — save the operator note + tags. Panel-side
/// metadata stored in the master's hosting_kv (keyed by ULID), so it
/// is the same regardless of which node hosts the site.
pub async fn post_set_notes(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NotesForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // Resolve the ULID (the selector may be a domain) for the KV key.
    let hosting_id = match find_hosting_anywhere(&state, sel).await {
        Ok((d, _)) => d.id.as_str().to_string(),
        Err(_) => {
            return Ok(Redirect::to(&format!("/hostings/{sel_url}")).into_response());
        }
    };
    let notes: String = form.notes.replace('\r', "").chars().take(2000).collect();
    let tags = normalize_tags(&form.tags).join(",");
    // Master-side metadata → local socket.
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingKvSet {
            hosting_id: hosting_id.clone(),
            key: "notes".into(),
            value: notes,
        },
    )
    .await;
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingKvSet {
            hosting_id,
            key: "tags".into(),
            value: tags,
        },
    )
    .await;
    Ok(Redirect::to(&format!("/hostings/{sel_url}?flash_saved=notes#overview")).into_response())
}

#[derive(Deserialize)]
pub struct PhpIniForm {
    pub selector: String,
    #[serde(default)]
    pub memory_limit: String,
    #[serde(default)]
    pub upload_max_filesize: String,
    #[serde(default)]
    pub post_max_size: String,
    #[serde(default)]
    pub max_execution_time: String,
    #[serde(default)]
    pub max_input_vars: String,
    #[serde(default)]
    pub display_errors: String,
}

/// `256M`, `1G`, `512` or empty. Bounded so a pasted novel can't get in.
fn valid_php_size(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let (digits, suffix) = if s.as_bytes().last().map(u8::is_ascii_alphabetic).unwrap_or(false) {
        (&s[..s.len() - 1], &s[s.len() - 1..])
    } else {
        (s, "")
    };
    !digits.is_empty()
        && digits.len() <= 6
        && digits.bytes().all(|b| b.is_ascii_digit())
        && matches!(suffix, "" | "K" | "M" | "G" | "k" | "m" | "g")
}

fn valid_php_int(s: &str, lo: i64, hi: i64) -> bool {
    s.is_empty() || s.parse::<i64>().map(|n| (lo..=hi).contains(&n)).unwrap_or(false)
}

/// POST /hostings/php-ini — write operator php.ini overrides as a
/// per-hosting `.user.ini` in htdocs (PHP_INI_PERDIR; FPM re-reads it
/// within user_ini.cache_ttl, default 5 min — no restart, and a bad
/// value can never stop the pool starting). Values are validated and
/// also kept in the master KV for re-display.
pub async fn post_set_php_ini(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PhpIniForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let dr = |k: &str| -> String {
        match k {
            "On" | "Off" | "" => k.to_string(),
            _ => String::new(),
        }
    };
    let display = dr(form.display_errors.trim());
    // Validate; on any bad value bounce back with a flash.
    if !valid_php_size(form.memory_limit.trim())
        || !valid_php_size(form.upload_max_filesize.trim())
        || !valid_php_size(form.post_max_size.trim())
        || !valid_php_int(form.max_execution_time.trim(), 0, 3600)
        || !valid_php_int(form.max_input_vars.trim(), 100, 200_000)
        || (!form.display_errors.trim().is_empty() && display.is_empty())
    {
        return Ok(Redirect::to(&format!(
            "/hostings/{sel_url}?flash_error=Invalid+PHP+value+%E2%80%94+sizes+like+256M%2F1G%2C+numbers+in+range%2C+display_errors+On%2FOff#settings"
        ))
        .into_response());
    }
    // Resolve owner — the .user.ini lives on the node hosting the site.
    let (detail, owner_node) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(e) => return Err(AppError::from(e)),
    };
    let hosting_id = detail.id.as_str().to_string();

    // Build the .user.ini (only set lines).
    let mut body = String::from("; Managed by Hyperion — edit via the panel (Settings → PHP).\n");
    let mut line = |k: &str, v: &str| {
        let v = v.trim();
        if !v.is_empty() {
            body.push_str(&format!("{k} = {v}\n"));
        }
    };
    line("memory_limit", &form.memory_limit);
    line("upload_max_filesize", &form.upload_max_filesize);
    line("post_max_size", &form.post_max_size);
    line("max_execution_time", &form.max_execution_time);
    line("max_input_vars", &form.max_input_vars);
    if !display.is_empty() {
        body.push_str(&format!("display_errors = {display}\n"));
    }
    let bytes_b64 = base64_encode(body.as_bytes());
    // Write the file on the owning node (jailed write chowns to the
    // hosting user, so PHP can read it).
    let _ = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingFileWrite {
            sel: HostingSelector::Id(detail.id.clone()),
            rel_path: ".user.ini".into(),
            bytes_b64,
        },
    )
    .await;
    // Persist values for re-display (master KV, keyed by ULID).
    for (k, v) in [
        ("php.memory_limit", form.memory_limit.trim()),
        ("php.upload_max_filesize", form.upload_max_filesize.trim()),
        ("php.post_max_size", form.post_max_size.trim()),
        ("php.max_execution_time", form.max_execution_time.trim()),
        ("php.max_input_vars", form.max_input_vars.trim()),
        ("php.display_errors", display.as_str()),
    ] {
        let _ = hyperion_rpc_client::call(
            &state.agent_socket,
            Request::HostingKvSet {
                hosting_id: hosting_id.clone(),
                key: k.to_string(),
                value: v.to_string(),
            },
        )
        .await;
    }
    Ok(Redirect::to(&format!("/hostings/{sel_url}?flash_saved=php#settings")).into_response())
}

/// Base64-encode (STANDARD) — small local helper to avoid threading the
/// engine import through every call site.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Resolve a per-form `target_node` field to the Option<&str>
/// shape that dispatch_to_node accepts. Empty / "local" / "" →
/// master itself; anything else is a remote node_id.
fn node_target(raw: &str) -> Option<&str> {
    let s = raw.trim();
    if s.is_empty() || s == crate::dispatcher::LOCAL_NODE_SENTINEL {
        None
    } else {
        Some(s)
    }
}

#[derive(Deserialize)]
pub struct SuspendForm {
    selector: String,
    #[serde(default)]
    reason: String,
    /// Node where the hosting lives — populated by the detail
    /// page's target_node injector. Empty / "local" → master.
    #[serde(default)]
    target_node: String,
}

pub async fn post_suspend(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SuspendForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let reason = hyperion_types::SuspendReason::Manual {
        message: if form.reason.trim().is_empty() {
            None
        } else {
            Some(form.reason.trim().to_string())
        },
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSuspend { sel, reason },
    )
    .await?;
    match resp {
        RpcResponse::HostingSuspend => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct ResumeForm {
    selector: String,
    #[serde(default)]
    target_node: String,
}

pub async fn post_resume(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ResumeForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingResume(sel),
    )
    .await?;
    match resp {
        RpcResponse::HostingResume => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct VhostOptionsForm {
    selector: String,
    #[serde(default)]
    target_node: String,
    // Use stringly "on" semantics — HTML checkboxes don't send
    // false values, so #[serde(default)] + presence check.
    #[serde(default)]
    basic_auth_enabled: Option<String>,
    #[serde(default)]
    basic_auth_user: String,
    /// Operator-typed new password. Empty string = leave hash alone.
    #[serde(default)]
    basic_auth_password: String,
    #[serde(default)]
    force_https: Option<String>,
    #[serde(default)]
    hsts_max_age: i64,
    #[serde(default)]
    custom_nginx_snippet: String,
    #[serde(default)]
    maintenance_mode: Option<String>,
    #[serde(default)]
    fastcgi_cache_enabled: Option<String>,
    #[serde(default)]
    fastcgi_cache_ttl: i64,
    #[serde(default)]
    redirect_url: String,
    #[serde(default)]
    redirect_code: i64,
    #[serde(default)]
    redirect_preserve_path: Option<String>,
    #[serde(default)]
    waf_enabled: Option<String>,
    #[serde(default)]
    wp_admin_allowlist: String,
}

fn checkbox_on(v: &Option<String>) -> bool {
    v.as_deref()
        .map(|s| matches!(s, "on" | "true" | "1" | "yes"))
        .unwrap_or(false)
}

pub async fn post_vhost_options(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<VhostOptionsForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let options = hyperion_types::VhostOptions {
        basic_auth_enabled: checkbox_on(&form.basic_auth_enabled),
        basic_auth_user: form.basic_auth_user.trim().to_string(),
        basic_auth_set: false, // service decides — based on pw + existing
        force_https: checkbox_on(&form.force_https),
        hsts_max_age: form.hsts_max_age,
        custom_nginx_snippet: form.custom_nginx_snippet,
        maintenance_mode: checkbox_on(&form.maintenance_mode),
        fastcgi_cache_enabled: checkbox_on(&form.fastcgi_cache_enabled),
        fastcgi_cache_ttl: form.fastcgi_cache_ttl,
        redirect_url: form.redirect_url.trim().to_string(),
        redirect_code: form.redirect_code,
        redirect_preserve_path: checkbox_on(&form.redirect_preserve_path),
        waf_enabled: checkbox_on(&form.waf_enabled),
        wp_admin_allowlist: form.wp_admin_allowlist.trim().to_string(),
    };
    let pw_opt = if form.basic_auth_password.is_empty() {
        None
    } else {
        Some(form.basic_auth_password)
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetVhostOptions {
            sel,
            options,
            basic_auth_password: pw_opt,
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetVhostOptions(_) => Ok(Redirect::to(&format!(
            "/hostings/{}?vhost_saved=1",
            urlencoding(&form.selector)
        ))
        .into_response()),
        RpcResponse::Error(e) => {
            // Bounce back to the detail page with the error in the query
            // string so the operator sees the verbatim nginx -t output
            // (or validation error) in a banner instead of a bare 500.
            Ok(Redirect::to(&format!(
                "/hostings/{}?vhost_error={}",
                urlencoding(&form.selector),
                urlencoding(&e.to_string())
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// ──────────── WP debug + Redis handlers ────────────

#[derive(Deserialize)]
pub struct WpDebugForm {
    selector: String,
    #[serde(default)]
    target_node: String,
    #[serde(default)]
    enabled: Option<String>,
    #[serde(default)]
    log: Option<String>,
    #[serde(default)]
    display: Option<String>,
}

fn redirect_after_wp_extras(form_selector: &str, error: Option<String>) -> Response {
    match error {
        Some(e) => {
            // Two parallel channels so the error is visible no matter
            // where the operator is on the page:
            //   - `flash_error` triggers the top-of-page red toast via
            //     base.html's onload shim. Visible regardless of which
            //     tab is currently active or how far the page is
            //     scrolled — perfect for the post-redirect case where
            //     the form lived inside a deeply-nested card.
            //   - `wp_extras_error` populates the in-card banner so
            //     the message is still there after the toast fades
            //     (7s). Until we wire this banner into every
            //     WP-extras card, it lives inside Debug + Redis only.
            Redirect::to(&format!(
                "/hostings/{}?wp_extras_error={}&flash_error={}#wordpress",
                urlencoding(form_selector),
                urlencoding(&e),
                urlencoding(&e),
            ))
            .into_response()
        }
        None => Redirect::to(&format!(
            "/hostings/{}?wp_extras_saved=1&flash=Settings+saved#wordpress",
            urlencoding(form_selector)
        ))
        .into_response(),
    }
}

pub async fn post_wp_debug(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpDebugForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetWpDebug {
            sel,
            enabled: checkbox_on(&form.enabled),
            log: checkbox_on(&form.log),
            display: checkbox_on(&form.display),
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetWpDebug(_) => Ok(redirect_after_wp_extras(&form.selector, None)),
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpRotateForm {
    selector: String,
    #[serde(default)]
    target_node: String,
}

pub async fn post_wp_debug_log_rotate(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpRotateForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingRotateWpDebugLog { sel },
    )
    .await?;
    match resp {
        RpcResponse::HostingRotateWpDebugLog => {
            Ok(redirect_after_wp_extras(&form.selector, None))
        }
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpRedisForm {
    selector: String,
    #[serde(default)]
    target_node: String,
    /// "on" = enable; anything else = disable.
    #[serde(default)]
    enabled: String,
}

pub async fn post_wp_redis(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpRedisForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetRedis {
            sel,
            enabled: form.enabled == "on",
        },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetRedis(_) => Ok(redirect_after_wp_extras(&form.selector, None)),
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_wp_redis_rotate(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpRotateForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingRotateRedisPassword { sel },
    )
    .await?;
    match resp {
        RpcResponse::HostingRotateRedisPassword(_) => {
            Ok(redirect_after_wp_extras(&form.selector, None))
        }
        RpcResponse::Error(e) => Ok(redirect_after_wp_extras(
            &form.selector,
            Some(e.to_string()),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SetLimitsForm {
    selector: String,
    php_memory_mb: i64,
    php_max_exec_secs: i64,
    php_max_children: i64,
    php_max_requests: i64,
    db_max_connections: i64,
    #[serde(default)]
    disk_hard_mb: String,
    #[serde(default)]
    bw_monthly_mb: String,
    #[serde(default)]
    target_node: String,
}

#[derive(Deserialize)]
pub struct BackupDeleteForm {
    selector: String,
    backup_id: i64,
}

/// POST /hostings/backups/delete — remove a single backup run + its
/// archive file. Refuses if the backup is still running.
pub async fn post_backup_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupDeleteForm>,
) -> Result<Response, AppError> {
    // form.selector controls the redirect target AND the owner node —
    // backup_id is the OWNER node's per-node autoincrement id, so this
    // MUST dispatch to the owner. Sending it to the master could delete
    // an unrelated master backup that happens to share the numeric id
    // (both start at 1), or NotFound → a 502. We still gate via the
    // selector because non-admins can only see the backup list for
    // hostings they have access to; a viewer probing arbitrary
    // backup_ids without a matching access grant gets 403 here.
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel)
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::BackupDelete {
            backup_id: form.backup_id,
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupDelete => {
            Ok(Redirect::to(&format!("/hostings/{sel_url}#backups")).into_response())
        }
        // The agent deliberately refuses to delete a still-running
        // backup — surface that as a flash, not a full 502 page.
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/{}?backup_error={}#backups",
            sel_url,
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SetAcmeEmailForm {
    selector: String,
    #[serde(default)]
    acme_email: String,
}

/// POST /hostings/acme-email — set or clear the per-hosting ACME
/// contact email override. An empty `acme_email` field clears the
/// override, falling back to `[acme] contact_email` from agent.toml.
pub async fn post_set_acme_email(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetAcmeEmailForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let trimmed = form.acme_email.trim();
    let email = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    };
    let sel_url = urlencoding(&form.selector);
    // The acme_contact_email override lives on the hosting's row on its
    // owning node — dispatch there, not the master local socket (which
    // would NotFound for a worker-hosted site). Agent errors (e.g.
    // malformed email) become a flash, not a 502 page.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::SetHostingAcmeEmail { sel, email },
    )
    .await?;
    match resp {
        RpcResponse::SetHostingAcmeEmail => {
            Ok(Redirect::to(&format!("/hostings/{sel_url}")).into_response())
        }
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/hostings/{}?cert_error={}#ssl",
            sel_url,
            urlencoding(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct SetPhpVersionForm {
    pub selector: String,
    /// One of "8.1", "8.2", "8.3", "8.4". Anything else returns 400.
    pub php_version: String,
    /// Optional target-node hint; honours the dispatcher's
    /// local/remote routing the same way every other POST does.
    #[serde(default)]
    pub target_node: String,
}

/// POST /hostings/set-php-version — flip an existing hosting's PHP
/// runtime version. The agent does the FPM teardown + bring-up +
/// vhost rewrite atomically; on success we redirect back to the
/// hosting detail with a success flash on the PHP card.
pub async fn post_set_php_version(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetPhpVersionForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let version: hyperion_types::PhpVersion = form
        .php_version
        .trim()
        .parse()
        .map_err(|e: String| AppError::BadRequest(format!("php_version: {e}")))?;
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetPhpVersion { sel, version },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetPhpVersion(v) => Ok(Redirect::to(&format!(
            "/hostings/{}?flash=PHP+version+switched+to+{}",
            urlencoding(&form.selector),
            v
        ))
        .into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_set_limits(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SetLimitsForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let mut l = hyperion_types::HostingLimits::defaults();
    l.php_memory_mb = form.php_memory_mb;
    l.php_max_exec_secs = form.php_max_exec_secs;
    l.php_max_children = form.php_max_children;
    l.php_max_requests = form.php_max_requests;
    l.db_max_connections = form.db_max_connections;
    if let Ok(mb) = form.disk_hard_mb.trim().parse::<i64>() {
        if mb > 0 {
            l.disk_hard_bytes = Some(mb * 1024 * 1024);
        }
    }
    if let Ok(mb) = form.bw_monthly_mb.trim().parse::<i64>() {
        if mb > 0 {
            l.bw_monthly_bytes = Some(mb * 1024 * 1024);
        }
    }
    let target = node_target(&form.target_node);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::HostingSetLimits { sel, limits: l },
    )
    .await?;
    match resp {
        RpcResponse::HostingSetLimits(_) => {
            Ok(Redirect::to(&format!("/hostings/{}", urlencoding(&form.selector))).into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct AccessGrantForm {
    pub hosting_id: String,
    pub user_id: i64,
    #[serde(default)]
    pub level: String,
}

#[derive(Deserialize)]
pub struct AccessRevokeForm {
    pub hosting_id: String,
    pub user_id: i64,
}

/// POST /hostings/access/grant — super_admin only. Grants a non-admin
/// user `read` or `manage` access to one hosting.
pub async fn post_access_grant(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<AccessGrantForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let level = if form.level == "read" { "read" } else { "manage" };
    let granted_by = ctx.session.as_ref().map(|s| s.user_id);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebGrantHostingAccess {
            user_id: form.user_id,
            hosting_id: form.hosting_id.clone(),
            level: level.to_string(),
            granted_by,
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::WebGrantHostingAccess => {
            Ok(Redirect::to(&format!("/hostings/{}#access", urlencoding(&form.hosting_id)))
                .into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /hostings/access/revoke — super_admin only.
pub async fn post_access_revoke(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<AccessRevokeForm>,
) -> Result<Response, AppError> {
    if !ctx.is_super_admin() {
        return Ok(Redirect::to("/").into_response());
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebRevokeHostingAccess {
            user_id: form.user_id,
            hosting_id: form.hosting_id.clone(),
        },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::WebRevokeHostingAccess => {
            Ok(Redirect::to(&format!("/hostings/{}#access", urlencoding(&form.hosting_id)))
                .into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct MonitorSetForm {
    pub selector: String,
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub url_path: String,
    #[serde(default)]
    pub interval_secs: String,
    #[serde(default)]
    pub alert_after_fails: String,
    #[serde(default)]
    pub alert_email: String,
    #[serde(default)]
    pub alert_slack_webhook: String,
    #[serde(default)]
    pub alert_webhook_url: String,
}

pub async fn post_monitor_set(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<MonitorSetForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
    // Cross-node aware: the form selector is now a ULID (after the
    // duplicate-domain fix), so the master agent may not own the
    // row at all. `find_hosting_anywhere` checks master first, then
    // fans out to every enrolled worker. The returned `owner_node`
    // is what we dispatch the MonitorSet RPC to so the config
    // lands on the agent that actually serves the hosting.
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    let target = owner_node.as_deref();
    // Guard with manage-level access. super_admin / admin bypass.
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), true).await {
        return Ok(r);
    }
    let enabled = form.enabled == "on" || form.enabled == "true" || form.enabled == "1";
    let path = if form.url_path.trim().is_empty() {
        None
    } else {
        Some(form.url_path.trim().to_string())
    };
    let interval = form
        .interval_secs
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0);
    let after = form
        .alert_after_fails
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0);
    let email = if form.alert_email.trim().is_empty() {
        None
    } else {
        Some(form.alert_email.trim().to_string())
    };
    let slack = if form.alert_slack_webhook.trim().is_empty() {
        None
    } else {
        Some(form.alert_slack_webhook.trim().to_string())
    };
    let webhook = if form.alert_webhook_url.trim().is_empty() {
        None
    } else {
        Some(form.alert_webhook_url.trim().to_string())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::MonitorSet {
            sel: sel.clone(),
            enabled,
            url_path: path,
            interval_secs: interval,
            alert_after_fails: after,
            alert_email: email,
            alert_slack_webhook: slack,
            alert_webhook_url: webhook,
        },
    )
    .await?;
    match resp {
        RpcResponse::MonitorSet => {
            Ok(Redirect::to(&format!("/hostings/{}#monitor", urlencoding(&form.selector)))
                .into_response())
        }
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct MonitorProbeForm {
    pub selector: String,
}

pub async fn post_monitor_probe(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<MonitorProbeForm>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&form.selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    let target = owner_node.as_deref();
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), true).await {
        return Ok(r);
    }
    let _ = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::MonitorProbeNow { sel },
    )
    .await?;
    Ok(Redirect::to(&format!("/hostings/{}#monitor", urlencoding(&form.selector)))
        .into_response())
}

/// Drop hosting summaries the caller doesn't have access to.
/// super_admin + admin pass through everything; operator + viewer get
/// filtered down to the set of hostings their `web_user_hosting_access`
/// rows mention. Unauthenticated callers see nothing.
///
/// Failures (RPC error, missing user_id) are conservative: we filter
/// to empty rather than risk over-disclosure.
pub(crate) async fn filter_by_access(
    state: &SharedState,
    ctx: &AuthCtx,
    rows: Vec<HostingSummary>,
) -> Vec<HostingSummary> {
    if ctx.is_admin_or_higher() {
        return rows;
    }
    let Some(sess) = ctx.session.as_ref() else {
        return Vec::new();
    };
    // Fetch the access set once and filter in memory.
    let mut allowed: std::collections::HashSet<String> = std::collections::HashSet::new();
    // We don't have a dedicated "list my hostings" RPC; iterate over
    // the visible rows and ask the agent per-id. For the typical
    // operator-with-a-few-hostings case this is cheap; for a 1000-
    // hosting cluster it's wasteful but acceptable for v1.
    for r in &rows {
        let access_resp = hyperion_rpc_client::call(
            &state.agent_socket,
            Request::WebListHostingAccess {
                hosting_id: r.id.as_str().to_string(),
            },
        )
        .await;
        if let Ok(RpcResponse::WebListHostingAccess(grants)) = access_resp {
            if grants.iter().any(|g| g.user_id == sess.user_id) {
                allowed.insert(r.id.as_str().to_string());
            }
        }
    }
    rows.into_iter()
        .filter(|r| allowed.contains(r.id.as_str()))
        .collect()
}

/// Block detail / write access for callers without the required level.
/// "read" → viewer-style (any access entry suffices). "manage" →
/// operator-style (level=manage). super_admin + admin always allowed.
///
/// Returns a `403 Forbidden` response on rejection. POST handlers must
/// propagate this with `Ok(r)` — a redirect would silently steer the
/// caller back to /hostings and obscure the access failure.
pub async fn require_hosting_access(
    state: &SharedState,
    ctx: &AuthCtx,
    hosting_id: &str,
    require_manage: bool,
) -> Result<(), Response> {
    if ctx.is_admin_or_higher() {
        return Ok(());
    }
    let forbidden = || {
        (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<h1>403 Forbidden</h1>".to_string(),
        )
            .into_response()
    };
    let Some(sess) = ctx.session.as_ref() else {
        return Err(forbidden());
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebListHostingAccess {
            hosting_id: hosting_id.to_string(),
        },
    )
    .await;
    let grants = match resp {
        Ok(RpcResponse::WebListHostingAccess(g)) => g,
        _ => return Err(forbidden()),
    };
    let mine = grants.into_iter().find(|g| g.user_id == sess.user_id);
    match mine {
        None => Err(forbidden()),
        Some(g) if require_manage && g.level != "manage" => Err(forbidden()),
        Some(_) => Ok(()),
    }
}

/// Convenience wrapper for mutating POST handlers: parse the selector,
/// resolve the hosting id (looking it up by domain if needed), and
/// require manage-level access. Returns the resolved `HostingSelector`
/// on success so the caller can pass it straight to its RPC request.
///
/// Failure conditions all collapse to a 403 response — the caller
/// propagates it via `Ok(r)`. Surfacing the precise reason (no such
/// hosting vs. no access) would help account-enumeration; viewers
/// shouldn't be able to probe which ids exist.
pub async fn require_manage_for_selector(
    state: &SharedState,
    ctx: &AuthCtx,
    sel_str: &str,
) -> Result<HostingSelector, Response> {
    let forbidden = || {
        (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<h1>403 Forbidden</h1>".to_string(),
        )
            .into_response()
    };
    let sel = parse_selector(sel_str).map_err(|_| forbidden())?;
    if ctx.is_admin_or_higher() {
        return Ok(sel);
    }
    let hosting_id = match &sel {
        HostingSelector::Id(id) => id.as_str().to_string(),
        _ => {
            let resp = hyperion_rpc_client::call(
                &state.agent_socket,
                Request::HostingGet(sel.clone()),
            )
            .await;
            match resp {
                Ok(RpcResponse::HostingGet(d)) => d.id.as_str().to_string(),
                _ => return Err(forbidden()),
            }
        }
    };
    require_hosting_access(state, ctx, &hosting_id, true).await?;
    Ok(sel)
}

pub(crate) fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Extract the literal suffix from a test-domain template.
///
/// Given a template like `{name}.{node}.testovaciverze.cz`,
/// returns `.testovaciverze.cz` — the part *after* the last
/// placeholder. That's the bit a domain on a test node has to
/// end with for the suffix-match check to work.
///
/// The previous implementation used `rsplit_once('.')` which
/// just split on the LAST dot, returning `.cz` for any
/// multi-label template. That blocked every single `.cz` domain
/// in the cluster from being created on production nodes — the
/// suffix check thought EVERY .cz was a "test-node leak".
///
/// Templates with no placeholders fall back to treating the
/// entire string as the literal suffix (with a leading dot if
/// not present). Empty template ⇒ empty suffix ⇒ no check fires.
fn extract_test_suffix(template: &str) -> String {
    let t = template.trim();
    if t.is_empty() {
        return String::new();
    }
    // A real test-domain TEMPLATE always contains at least one
    // `{...}` placeholder — that's the whole point (substitution
    // slots for `name` / `node`). If the operator set the field to
    // a bare suffix like `.cz` with no braces, we treat that as
    // "no usable template" and skip the suffix check entirely —
    // refusing to extract `.cz` as a fake "this is reserved"
    // suffix that would falsely block every .cz domain in the
    // cluster from being created on production nodes.
    if !t.contains('{') || !t.contains('}') {
        return String::new();
    }
    // Find the LAST closing brace from a `{xxx}` placeholder; whatever
    // comes after it is the literal suffix. For `{name}.{node}.foo.bar`
    // that's `.foo.bar`; for `{name}.foo.bar` it's `.foo.bar` too.
    let after_last_placeholder = match t.rfind('}') {
        Some(idx) => &t[idx + 1..],
        None => return String::new(),
    };
    // Trim a leading `.` so we can always add exactly one back.
    let inner = after_last_placeholder.trim_start_matches('.');
    if inner.is_empty() {
        String::new()
    } else {
        format!(".{inner}")
    }
}

#[cfg(test)]
mod test_suffix_tests {
    use super::extract_test_suffix;

    #[test]
    fn typical_multi_placeholder() {
        // The case that bit Kevin — `.cz` would falsely block every
        // production .cz domain. Now correctly yields the full suffix.
        assert_eq!(
            extract_test_suffix("{name}.{node}.testovaciverze.cz"),
            ".testovaciverze.cz"
        );
    }

    #[test]
    fn single_placeholder() {
        assert_eq!(
            extract_test_suffix("{name}.staging.example.com"),
            ".staging.example.com"
        );
    }

    #[test]
    fn no_placeholder_is_treated_as_no_template() {
        // A "template" with no placeholders can't substitute anything,
        // so it's not a real template — return empty so the suffix
        // check is skipped. Earlier behaviour returned the whole
        // string as a literal suffix; that turned a stray
        // `test_domain_template = ".cz"` setting into a hard block on
        // every .cz domain in the cluster.
        assert_eq!(extract_test_suffix("staging.example.com"), "");
        assert_eq!(extract_test_suffix(".cz"), "");
        assert_eq!(extract_test_suffix("cz"), "");
    }

    #[test]
    fn empty() {
        assert_eq!(extract_test_suffix(""), "");
        assert_eq!(extract_test_suffix("   "), "");
    }

    #[test]
    fn trailing_brace_only() {
        // Degenerate but shouldn't panic.
        assert_eq!(extract_test_suffix("{name}"), "");
    }
}

fn parse_aliases(input: &str) -> Result<Vec<Domain>, String> {
    let mut out = Vec::new();
    for piece in input.split(|c: char| c == ',' || c.is_whitespace()) {
        let p = piece.trim();
        if p.is_empty() {
            continue;
        }
        match Domain::parse(p) {
            Ok(d) => out.push(d),
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(out)
}

/// Re-export of parse_selector for sibling handler modules.
pub fn parse_selector_public(s: &str) -> Result<HostingSelector, AppError> {
    parse_selector(s)
}

/// Conservative validator for the WordPress admin username the
/// operator types in the New Hosting form. WP itself accepts a
/// fairly wide range (including spaces, periods, `@`), but we
/// bound it to the safe subset to avoid:
///   - shell quoting bugs if it gets passed to wp-cli unescaped,
///   - URL-encoding surprises in wp-login.php links,
///   - operator typos that yield a username they then can't type
///     reliably (zero-width space, RTL marks, etc.).
///
/// Rules: 1..=60 chars, ASCII alphanumeric + `._@-`. No leading
/// dash (looks like a CLI flag), no leading dot (hidden), no
/// embedded whitespace.
/// Does a profile's `wp_plugins` / `wp_themes` list contain at
/// least one meaningful entry? Lines starting with `#` or `;` and
/// blank lines are ignored (same parser semantics the agent uses).
/// Returns `true` iff stripping comments+blanks leaves at least one
/// non-empty token. Used by the wizard / post_create to decide
/// whether the profile mandates a WP install.
fn profile_has_meaningful_wp_content(list: &str) -> bool {
    for raw in list.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        return true;
    }
    false
}

/// Generate a 24-char WordPress admin password from a charset that
/// avoids visually-ambiguous characters (no `0/O`, `1/l/I`) so the
/// operator can read it off the credentials card without
/// second-guessing. We use the OS's CSPRNG via `rand::thread_rng()`
/// which is the same source used elsewhere in the codebase for
/// generating DB passwords.
fn generate_wp_admin_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ\
                              abcdefghijkmnpqrstuvwxyz\
                              23456789\
                              !@#$%^&*-_=+";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| {
            let i = rng.gen_range(0..CHARSET.len());
            CHARSET[i] as char
        })
        .collect()
}

#[cfg(test)]
mod profile_helper_tests {
    use super::{generate_wp_admin_password, profile_has_meaningful_wp_content};

    #[test]
    fn meaningful_wp_content_finds_plugins() {
        assert!(profile_has_meaningful_wp_content("akismet"));
        assert!(profile_has_meaningful_wp_content("yoast-seo!"));
        assert!(profile_has_meaningful_wp_content("@asset:42"));
        assert!(profile_has_meaningful_wp_content("  contact-form-7\n  classic-editor"));
    }

    #[test]
    fn meaningful_wp_content_ignores_comments_and_blanks() {
        assert!(!profile_has_meaningful_wp_content(""));
        assert!(!profile_has_meaningful_wp_content("   "));
        assert!(!profile_has_meaningful_wp_content("# header line"));
        assert!(!profile_has_meaningful_wp_content("; another comment"));
        assert!(!profile_has_meaningful_wp_content(
            "# akismet\n\
             ; yoast-seo\n\
             \n"
        ));
    }

    #[test]
    fn meaningful_wp_content_mixed_still_truthy() {
        assert!(profile_has_meaningful_wp_content(
            "# Base set\nakismet\n# More:\nyoast-seo!\n"
        ));
    }

    #[test]
    fn generated_password_is_exactly_24_chars() {
        for _ in 0..50 {
            let p = generate_wp_admin_password();
            assert_eq!(p.len(), 24, "password not 24 chars: {p:?}");
            assert!(!p.chars().any(|c| c == '0' || c == 'O' || c == '1'
                || c == 'l' || c == 'I'),
                "password contains visually-ambiguous char: {p:?}");
        }
    }
}

fn is_valid_wp_username(s: &str) -> bool {
    if s.is_empty() || s.len() > 60 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'-' || bytes[0] == b'.' {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '@' || c == '-'
    })
}

#[cfg(test)]
mod wp_username_tests {
    use super::is_valid_wp_username;

    #[test]
    fn accepts_typical_usernames() {
        assert!(is_valid_wp_username("admin"));
        assert!(is_valid_wp_username("kevin"));
        assert!(is_valid_wp_username("kevin.nechodom"));
        assert!(is_valid_wp_username("kevin_99"));
        assert!(is_valid_wp_username("k@example.cz"));
        assert!(is_valid_wp_username("a"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_valid_wp_username(""));
    }

    #[test]
    fn rejects_too_long() {
        assert!(!is_valid_wp_username(&"a".repeat(61)));
        assert!(is_valid_wp_username(&"a".repeat(60)));
    }

    #[test]
    fn rejects_leading_dash_or_dot() {
        assert!(!is_valid_wp_username("-admin"));
        assert!(!is_valid_wp_username(".hidden"));
    }

    #[test]
    fn rejects_whitespace_and_shell_metacharacters() {
        assert!(!is_valid_wp_username("admin user"));
        assert!(!is_valid_wp_username("admin\nuser"));
        assert!(!is_valid_wp_username("admin;rm"));
        assert!(!is_valid_wp_username("$(whoami)"));
        assert!(!is_valid_wp_username("admin`whoami`"));
        assert!(!is_valid_wp_username("admin/test"));
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(!is_valid_wp_username("admín"));
        assert!(!is_valid_wp_username("админ"));
    }
}

fn parse_selector(s: &str) -> Result<HostingSelector, AppError> {
    if s.contains('.') {
        Ok(HostingSelector::Domain(Domain::parse(s)?))
    } else {
        Ok(HostingSelector::Id(hyperion_types::HostingId(
            s.to_string(),
        )))
    }
}

fn csrf_token_for(state: &SharedState, ctx: &AuthCtx, form_id: &str) -> String {
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

fn render_new_error<'a>(
    ctx: &'a AuthCtx,
    csrf_token: &'a str,
    form: &'a CreateForm,
    error: &'a str,
) -> Response {
    let tpl = NewTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "hostings",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf_token: csrf_token.to_string(),
        error: Some(error),
        domain_in: &form.domain,
        aliases_in: &form.aliases,
        php_in: form.php.clone(),
        db_in: form.db.clone(),
        kind_in: form.kind.clone(),
        proxy_upstream_url_in: form.proxy_upstream_url.clone(),
        // Re-rendering on validation error doesn't need a fresh
        // NodesList — we'd repeat the agent RPC for no UX gain.
        // The dropdown silently empties, which is acceptable since
        // the operator is fixing a field, not switching nodes.
        nodes: Vec::new(),
        target_node_in: form.target_node.clone(),
        // Same reasoning — preserve the operator-set value on
        // re-render. Defaulting to true keeps backward-compat.
        master_accepts_hostings: true,
        // Re-render skips the agent call; if the operator picked a
        // test node, the JS will still hide/show the right fields
        // because it reads from the `data-test-nodes` attribute on
        // the dropdown (rendered straight from `test_node_ids`).
        // Empty here means: don't fight with the operator's typed
        // value — they're fixing a validation error, not switching
        // node types.
        test_node_ids: String::new(),
        test_domain_template: String::new(),
        // Re-render skips re-fetching the profile list — empty is
        // fine because the operator's already past step 1 (the form
        // still carries profile_id from the original submit).
        profiles: Vec::new(),
    };
    Html(
        tpl.render()
            .unwrap_or_else(|_| "<h1>render error</h1>".into()),
    )
    .into_response()
}

/// Best-effort fetch of the WP asset library from the master.
/// Used by the hosting detail page to render the "Install from
/// library" dropdown on the WP tab. Failure → empty list (the
/// dropdown hides itself in the template).
async fn fetch_wp_assets(
    state: &SharedState,
) -> Result<Vec<hyperion_types::WpAssetSummary>, AppError> {
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::WpAssetList).await?;
    match resp {
        RpcResponse::WpAssetList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Check the master's [cluster] section: should the master itself
/// accept new hostings, or is it a control-plane-only node? Used
/// by /hostings/new to gate the master option in the Target-node
/// dropdown. Defaults to true (permissive) on any RPC failure or
/// missing config field — least-surprise.
async fn fetch_master_accepts_hostings(state: &SharedState) -> bool {
    match hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView).await {
        Ok(RpcResponse::AgentConfigView(c)) => c.cluster.master_accepts_hostings,
        _ => true,
    }
}

/// Fetch the full cluster config block — used by post_create to
/// evaluate test-node placement rules. Returns the default
/// (permissive) view on any RPC failure so a misconfigured agent
/// doesn't deadlock the create form.
pub(crate) async fn fetch_cluster_config(
    state: &SharedState,
) -> hyperion_types::ClusterConfigView {
    match hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView).await {
        Ok(RpcResponse::AgentConfigView(c)) => c.cluster,
        _ => hyperion_types::ClusterConfigView::default(),
    }
}

/// Pull the two bundle files (manifest.json + archive.tar.gz) off
/// a worker source via signed RPC and write them under the master's
/// own /var/lib/hyperion/migration/<bundle_id>/. After this the
/// master's existing /api/migration/bundle/<id>/<filename> route
/// serves the right bytes to the target node — the target doesn't
/// need to know the bundle started life on a worker.
///
/// Returns the local bundle directory on the master on success.
async fn pull_bundle_from_worker(
    state: &SharedState,
    source_node: &str,
    bundle_id: &str,
) -> Result<std::path::PathBuf, String> {
    use base64::Engine;
    let local_dir = std::path::PathBuf::from("/var/lib/hyperion/migration").join(bundle_id);
    tokio::fs::create_dir_all(&local_dir)
        .await
        .map_err(|e| format!("create local bundle dir: {e}"))?;
    for filename in ["manifest.json", "archive.tar.gz"] {
        let resp = crate::dispatcher::dispatch_to_node(
            state,
            Some(source_node),
            Request::HostingMigrationFetchBundleFile {
                bundle_id: bundle_id.to_string(),
                filename: filename.to_string(),
            },
        )
        .await
        .map_err(|e| format!("rpc {filename}: {e}"))?;
        let bytes_b64 = match resp {
            RpcResponse::HostingMigrationFetchBundleFile { bytes_b64 } => bytes_b64,
            RpcResponse::Error(e) => return Err(format!("source rejected {filename}: {e}")),
            _ => return Err(format!("unexpected response for {filename}")),
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(bytes_b64.as_bytes())
            .map_err(|e| format!("b64 {filename}: {e}"))?;
        tokio::fs::write(local_dir.join(filename), &bytes)
            .await
            .map_err(|e| format!("write {filename}: {e}"))?;
    }
    Ok(local_dir)
}

/// Auto-placement: pick the best-fit node for a new hosting when
/// the operator chose the "auto" sentinel in the create form.
///
/// Strategy (lower is better):
///   - Disqualify offline workers entirely.
///   - Score = 0.45·hostings + 0.35·loadavg + 0.20·mem_pct
///     normalised across the candidate set so a single node never
///     dominates by virtue of having the largest absolute numbers.
///   - Tiebreak by lexicographically smaller node_id (stable).
///   - Master is INCLUDED as a candidate iff
///     `cluster.master_accepts_hostings = true`.
///
/// Returns the chosen target string ready for the existing
/// dispatcher contract:
///   - `Some("worker-id")` to dispatch to a worker
///   - `Some(LOCAL_NODE_SENTINEL)` to dispatch locally
///   - `None` when no candidate qualifies (caller falls back to
///     master / error).
async fn pick_auto_placement_target(state: &SharedState) -> Option<String> {
    use hyperion_types::NodeStats;

    let nodes = fetch_remote_nodes(state).await.unwrap_or_default();
    let master_accepts = fetch_master_accepts_hostings(state).await;

    // Collect candidate NodeStats. Each entry is (target_string, NodeStats).
    let mut candidates: Vec<(String, NodeStats)> = Vec::with_capacity(nodes.len() + 1);

    if master_accepts {
        if let Ok(RpcResponse::ClusterStats(c)) =
            hyperion_rpc_client::call(&state.agent_socket, Request::ClusterStats).await
        {
            if let Some(mut n) = c.nodes.into_iter().next() {
                if n.label.is_empty() {
                    n.label = "master".into();
                }
                if n.agent_online {
                    candidates.push((crate::dispatcher::LOCAL_NODE_SENTINEL.to_string(), n));
                }
            }
        }
    }

    for ns in nodes {
        match crate::dispatcher::dispatch_to_node(state, Some(&ns.node_id), Request::ClusterStats)
            .await
        {
            Ok(RpcResponse::ClusterStats(c)) => {
                if let Some(stat) = c.nodes.into_iter().next() {
                    if stat.agent_online {
                        candidates.push((ns.node_id.clone(), stat));
                    }
                }
            }
            _ => {
                tracing::warn!(node = %ns.node_id, "auto-placement: stats unavailable; skipping");
            }
        }
    }

    if candidates.is_empty() {
        return None;
    }

    // Normalise each axis to [0, 1]. Lower = better. A zero-range
    // axis collapses to 0 contribution (every candidate is equal on
    // that axis).
    let max_host = candidates.iter().map(|(_, s)| s.hostings_count).max().unwrap_or(0);
    let max_load = candidates.iter().map(|(_, s)| s.loadavg_1m_x100).max().unwrap_or(0);
    let max_mem_pct: f64 = candidates
        .iter()
        .map(|(_, s)| mem_pct(s))
        .fold(0.0_f64, f64::max);

    let mut scored: Vec<(String, f64)> = candidates
        .iter()
        .map(|(id, s)| {
            let h = if max_host > 0 {
                s.hostings_count as f64 / max_host as f64
            } else {
                0.0
            };
            let l = if max_load > 0 {
                s.loadavg_1m_x100 as f64 / max_load as f64
            } else {
                0.0
            };
            let m_pct = mem_pct(s);
            let m = if max_mem_pct > 0.0 { m_pct / max_mem_pct } else { 0.0 };
            let score = 0.45 * h + 0.35 * l + 0.20 * m;
            (id.clone(), score)
        })
        .collect();
    // Stable tiebreak: lexicographically smaller node_id wins.
    scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));
    scored.into_iter().next().map(|(id, _)| id)
}

fn mem_pct(s: &hyperion_types::NodeStats) -> f64 {
    if s.mem_total_kib <= 0 {
        return 0.0;
    }
    (s.mem_used_kib as f64 / s.mem_total_kib as f64).clamp(0.0, 1.0)
}

/// Locate which node a hosting lives on, so per-hosting actions
/// (suspend, resume, set-limits, backup, cert, …) dispatched from
/// the detail page land on the right agent.
///
/// Strategy: try the master's local socket first (the common case).
/// On NotFound, fan out across enrolled nodes. The first one that
/// returns the hosting wins; its `node_id` is returned so the
/// handler can pass it to `dispatch_to_node`.
///
/// Returns `(HostingDetail, node_id_or_None)`. `None` means master.
pub async fn find_hosting_anywhere(
    state: &SharedState,
    sel: HostingSelector,
) -> Result<(hyperion_types::HostingDetail, Option<String>), AppError> {
    // 1. Master local.
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingGet(sel.clone()),
    )
    .await
    {
        Ok(RpcResponse::HostingGet(d)) => return Ok((d, None)),
        Ok(RpcResponse::Error(e)) if !is_not_found_error(&e) => {
            return Err(AppError::Rpc(e.to_string()));
        }
        Ok(_) => {}
        Err(e) => return Err(AppError::from(e)),
    }
    // 2. Fan out to enrolled nodes.
    let nodes_resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await;
    let nodes: Vec<hyperion_types::NodeSummary> = match nodes_resp {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(),
    };
    for n in nodes {
        let r = crate::dispatcher::dispatch_to_node(
            state,
            Some(&n.node_id),
            Request::HostingGet(sel.clone()),
        )
        .await;
        match r {
            Ok(RpcResponse::HostingGet(d)) => return Ok((d, Some(n.node_id))),
            Ok(RpcResponse::Error(_)) => continue, // not on this node
            _ => continue,
        }
    }
    Err(AppError::NotFound)
}

fn is_not_found_error(e: &hyperion_rpc::error::RpcError) -> bool {
    matches!(e, hyperion_rpc::error::RpcError::NotFound { .. })
}

/// Aggregate hostings from the master + every enrolled remote node.
/// Each row gets its `node_id` field REWRITTEN to the master's
/// identifier for that node ("local" sentinel for master, the
/// enrolled `node_id` for each worker) so the templates can show
/// + the action forms can dispatch correctly without translating
/// hostname↔enrolled-id (which differs because workers' hostings
/// rows tag node_id with their hostname, while the master's view
/// of "which node is this" uses the enrolled id).
///
/// Failure to reach a remote node is logged and that node's
/// hostings are simply omitted — the local list still renders.
/// GET /api/check-domain?domain=X — JSON preflight for the create
/// wizard. Returns `{"exists": false}` when the domain is free, or
/// `{"exists": true, "node": "<id>", "domain": "<canonical>"}` when
/// it's already claimed somewhere in the cluster.
///
/// Uses the same fan-out as the /hostings page (`list_hostings`)
/// rather than its own dispatch loop so the answer is consistent
/// with what the operator sees on the list. Cheap-ish (one
/// HostingList per node) but capped by the same dispatcher
/// timeouts, so even a partially-down cluster returns within ~3s.
pub async fn get_check_domain(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<CheckDomainQuery>,
) -> axum::response::Response {
    // Same role gate as the wizard — viewers / customers can't see
    // /hostings/new so they shouldn't be able to probe domain
    // availability either.
    if !ctx.is_admin_or_higher() {
        return axum::Json(serde_json::json!({"exists": false, "checked": false})).into_response();
    }
    let needle = q.domain.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return axum::Json(serde_json::json!({"exists": false, "checked": false})).into_response();
    }
    // Domain format guard — refuse obvious garbage early so a
    // pathological 50 KB field doesn't trigger a fan-out.
    if needle.len() > 253
        || !needle
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return axum::Json(serde_json::json!({
            "exists": false,
            "checked": false,
            "reason": "invalid characters"
        }))
        .into_response();
    }
    let rows = match list_hostings(&state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error=%e, "check-domain: list_hostings failed");
            return axum::Json(serde_json::json!({"exists": false, "checked": false})).into_response();
        }
    };
    let hit = rows
        .iter()
        .find(|r| r.domain.eq_ignore_ascii_case(&needle));
    match hit {
        Some(r) => axum::Json(serde_json::json!({
            "exists": true,
            "checked": true,
            "domain": r.domain,
            "node": r.node_id.clone().unwrap_or_default(),
            "state": r.state.as_str(),
        }))
        .into_response(),
        None => axum::Json(serde_json::json!({
            "exists": false,
            "checked": true,
        }))
        .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CheckDomainQuery {
    pub domain: String,
}

async fn list_hostings(state: &SharedState) -> Result<Vec<HostingSummary>, String> {
    // 1. Master's own hostings (always included).
    let local_resp = hyperion_rpc_client::call(&state.agent_socket, Request::HostingList)
        .await
        .map_err(|e| e.to_string())?;
    let mut local: Vec<HostingSummary> = match local_resp {
        RpcResponse::HostingList(v) => v,
        RpcResponse::Error(e) => return Err(e.to_string()),
        _ => return Err("unexpected response".into()),
    };
    for r in &mut local {
        r.node_id = Some(crate::dispatcher::LOCAL_NODE_SENTINEL.to_string());
    }

    // 2. Enrolled remote nodes — best-effort fan-out.
    let nodes_resp = hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await;
    let nodes: Vec<hyperion_types::NodeSummary> = match nodes_resp {
        Ok(RpcResponse::NodesList(v)) => v,
        _ => Vec::new(), // failed lookup — fall back to master-only
    };
    let mut all = local;
    for n in nodes {
        match crate::dispatcher::dispatch_to_node(
            state,
            Some(&n.node_id),
            Request::HostingList,
        )
        .await
        {
            Ok(RpcResponse::HostingList(mut remote)) => {
                for r in &mut remote {
                    r.node_id = Some(n.node_id.clone());
                }
                all.extend(remote);
            }
            Ok(RpcResponse::Error(e)) => {
                tracing::warn!(node=%n.node_id, error=%e, "remote hosting list refused");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(node=%n.node_id, error=%e, "remote hosting list unreachable");
            }
        }
    }
    Ok(all)
}

// ==================================================================
//  DNS check + real ACME issue + restore
// ==================================================================

#[derive(Deserialize)]
pub struct DnsCheckForm {
    pub selector: String,
}

/// HTMX-style endpoint: returns just the result fragment (not a full page)
/// so the operator can poll without losing the rest of the screen.
/// HTMX endpoint for the **create form**: DNS preflight against a
/// raw domain string (no existing hosting yet). Returns the same
/// HTML fragment as `post_dns_check` so the visual feedback is
/// identical to the post-create flow.
#[derive(Deserialize)]
pub struct DnsCheckDomainForm {
    domain: String,
}

pub async fn post_dns_check_domain(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DnsCheckDomainForm>,
) -> Result<Response, AppError> {
    // Used by the new-hosting form. Match post_create's gating —
    // operators can't be on this page anyway.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    let trimmed = form.domain.trim();
    let parsed = match Domain::parse(trimmed) {
        Ok(d) => d,
        Err(e) => {
            return Ok(Html(format!(
                "<div class=\"flash error\"><div class=\"flash-body\">Invalid domain: {}</div></div>",
                askama_escape::escape(&e.to_string(), askama_escape::Html)
            ))
            .into_response());
        }
    };
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::DnsCheck { domain: parsed },
    )
    .await?;
    let html = match resp {
        RpcResponse::DnsCheck(r) => render_dns_fragment(&r),
        RpcResponse::Error(e) => format!(
            "<div class=\"flash error\"><div class=\"flash-body\">DNS check failed: {}</div></div>",
            askama_escape::escape(&e.to_string(), askama_escape::Html)
        ),
        _ => "<div class=\"flash error\"><div class=\"flash-body\">Unexpected response.</div></div>"
            .into(),
    };
    Ok(Html(html).into_response())
}

pub async fn post_dns_check(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DnsCheckForm>,
) -> Result<Response, AppError> {
    // DNS check is non-mutating but ties to a specific hosting; gate
    // at manage so a viewer can't probe via this endpoint.
    let detail_sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    // Find the hosting across the cluster — the operator may be
    // looking at a worker-hosted row whose master row doesn't
    // exist. DnsCheck itself runs from the MASTER (dig from our
    // network egress) regardless of where the hosting lives, so
    // we only need find_anywhere for the domain lookup.
    let (detail, _) = find_hosting_anywhere(&state, detail_sel).await?;
    let domain = Domain::parse(&detail.domain)?;
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::DnsCheck { domain }).await?;
    let html = match resp {
        RpcResponse::DnsCheck(r) => render_dns_fragment(&r),
        RpcResponse::Error(e) => {
            format!(
                "<div class=\"flash error\"><div class=\"flash-body\">DNS check failed: {}</div></div>",
                askama_escape::escape(&e.to_string(), askama_escape::Html)
            )
        }
        _ => "<div class=\"flash error\"><div class=\"flash-body\">Unexpected response.</div></div>"
            .into(),
    };
    Ok(Html(html).into_response())
}

fn render_dns_fragment(r: &DnsCheckResult) -> String {
    let esc = |s: &str| askama_escape::escape(s, askama_escape::Html).to_string();
    let badge = if r.matches {
        "<span class=\"pill ok\">matches ✓</span>"
    } else {
        "<span class=\"pill err\">no match ✗</span>"
    };
    let a_list = if r.resolved_a.is_empty() {
        "<span class=\"text-soft\">none</span>".to_string()
    } else {
        r.resolved_a
            .iter()
            .map(|ip| format!("<code>{}</code>", esc(ip)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let aaaa_list = if r.resolved_aaaa.is_empty() {
        "<span class=\"text-soft\">none</span>".to_string()
    } else {
        r.resolved_aaaa
            .iter()
            .map(|ip| format!("<code>{}</code>", esc(ip)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let our_v4 = r.our_public_ipv4.as_deref().unwrap_or("?");
    let our_v6 = r.our_public_ipv6.as_deref().unwrap_or("?");
    format!(
        r#"<div class="kv" style="margin-top:0.5rem">
            <dt>Status</dt><dd>{badge}</dd>
            <dt>A records</dt><dd>{a_list}</dd>
            <dt>AAAA records</dt><dd>{aaaa_list}</dd>
            <dt>Our IPv4</dt><dd><code>{ipv4}</code></dd>
            <dt>Our IPv6</dt><dd><code>{ipv6}</code></dd>
        </div>
        <p class="muted" style="font-size:0.85rem;margin-top:0.7rem;margin-bottom:0">{note}</p>"#,
        badge = badge,
        a_list = a_list,
        aaaa_list = aaaa_list,
        ipv4 = esc(our_v4),
        ipv6 = esc(our_v6),
        note = esc(&r.note),
    )
}

/// Lazily-loaded DNS preflight banner on the hosting detail page.
/// The page shell renders immediately; this fragment swaps in once
/// dig/curl on the owning node come back (sub-second on healthy DNS,
/// multiple seconds when resolvers time out — exactly the case that
/// used to freeze the whole page render).
#[derive(Template)]
#[template(path = "_hosting_dns_banner.html")]
struct DnsBannerTpl {
    dns: hyperion_types::DnsCheckResult,
}

pub async fn get_dns_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    // On any failure return an empty fragment — the placeholder just
    // disappears. A missing advisory banner beats a broken page corner.
    let Ok(domain) = Domain::parse(&detail.domain) else {
        return Ok(Html(String::new()).into_response());
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::DnsCheck { domain },
    )
    .await;
    let html = match resp {
        Ok(RpcResponse::DnsCheck(r)) => DnsBannerTpl { dns: r }.render()?,
        _ => String::new(),
    };
    Ok(Html(html).into_response())
}

/// Lazily-loaded SPF card (Email DNS) — same reasoning as the DNS
/// banner above. Dispatched to the OWNING node: the site's outbound
/// mail egresses from the node where its PHP runs, so the suggested
/// `ip4:` mechanism must quote that node's public IP, not the
/// master's.
#[derive(Template)]
#[template(path = "_hosting_spf_card.html")]
struct SpfCardTpl {
    sp: SpfCheckResult,
    domain: String,
}

pub async fn get_spf_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    let Ok(domain) = Domain::parse(&detail.domain) else {
        return Ok(Html(String::new()).into_response());
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::DnsSpfCheck { domain },
    )
    .await;
    let html = match resp {
        Ok(RpcResponse::DnsSpfCheck(r)) => SpfCardTpl {
            sp: r,
            domain: detail.domain.clone(),
        }
        .render()?,
        _ => String::new(),
    };
    Ok(Html(html).into_response())
}

/// Lazily-loaded WordPress vulnerability panel (Wordfence feed match).
/// Dispatched to the OWNING node — the feed cache + wp-cli both live
/// where the site's files are.
#[derive(Template)]
#[template(path = "_hosting_vuln_panel.html")]
struct VulnPanelTpl {
    scan: hyperion_types::WpVulnScanResult,
    selector: String,
    auto_update_enabled: bool,
    csrf_token: String,
}

pub async fn get_vuln_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    // Auto-update toggle state lives in the OWNING node's hosting_kv
    // ("wp_auto_update"); default ON when absent.
    let auto_update_enabled = match crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::HostingKvList { hosting_id: detail.id.as_str().to_string() },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v
            .into_iter()
            .find(|(k, _)| k == "wp_auto_update")
            .map(|(_, val)| val.trim() != "off")
            .unwrap_or(true),
        _ => true,
    };
    let csrf_token = super::session_csrf_token(&state, &ctx);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::WpVulnScan { hosting: sel },
    )
    .await;
    let html = match resp {
        Ok(RpcResponse::WpVulnScan(scan)) => VulnPanelTpl {
            scan,
            selector: selector.clone(),
            auto_update_enabled,
            csrf_token,
        }
        .render()?,
        // On any failure render the "couldn't check" state rather than
        // a blank corner — the operator should know the scan didn't run.
        _ => VulnPanelTpl {
            scan: hyperion_types::WpVulnScanResult {
                feed_unavailable: true,
                ..Default::default()
            },
            selector: selector.clone(),
            auto_update_enabled,
            csrf_token,
        }
        .render()?,
    };
    Ok(Html(html).into_response())
}

#[derive(Deserialize)]
pub struct WpAutoUpdateForm {
    pub selector: String,
    /// "on" enables the defender's daily minor/patch auto-update; anything
    /// else disables it.
    pub enabled: String,
}

/// Toggle the keyless defender's daily minor/patch auto-update for a
/// hosting. Stored in the OWNING node's hosting_kv ("wp_auto_update",
/// keyed by the hosting ULID) where the daily tick reads it.
pub async fn post_wp_auto_update(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpAutoUpdateForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let (detail, target) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(_) => {
            return Ok(Redirect::to(&format!("/hostings/{}#wordpress", sel_url)).into_response());
        }
    };
    let value = if form.enabled == "on" { "on" } else { "off" };
    let _ = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::HostingKvSet {
            hosting_id: detail.id.as_str().to_string(),
            key: "wp_auto_update".into(),
            value: value.into(),
        },
    )
    .await;
    Ok(Redirect::to(&format!("/hostings/{}?flash_saved=auto-update#wordpress", sel_url)).into_response())
}

/// Lazily-loaded SFTP panel (FTP tab). Dispatched to the OWNING node —
/// the system user, home dir and authorized_keys all live there.
#[derive(Template)]
#[template(path = "_hosting_sftp_panel.html")]
struct SftpPanelTpl {
    sftp: hyperion_types::SftpStatus,
    selector: String,
    csrf_sftp: String,
    /// "" on success; an error string when the status probe failed.
    error: String,
}

pub async fn get_sftp_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    let csrf_sftp = csrf_token_for(&state, &ctx, "/hostings/sftp");
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::SftpStatus { sel },
    )
    .await;
    let tpl = match resp {
        Ok(RpcResponse::SftpStatus(sftp)) => SftpPanelTpl {
            sftp,
            selector: detail.id.as_str().to_string(),
            csrf_sftp,
            error: String::new(),
        },
        Ok(RpcResponse::Error(e)) => SftpPanelTpl {
            sftp: hyperion_types::SftpStatus {
                system_user: detail.system_user.clone(),
                host_hint: detail.domain.clone(),
                ..Default::default()
            },
            selector: detail.id.as_str().to_string(),
            csrf_sftp,
            error: e.to_string(),
        },
        _ => SftpPanelTpl {
            sftp: hyperion_types::SftpStatus {
                system_user: detail.system_user.clone(),
                host_hint: detail.domain.clone(),
                ..Default::default()
            },
            selector: detail.id.as_str().to_string(),
            csrf_sftp,
            error: "could not reach the owning node".into(),
        },
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct SftpForm {
    pub selector: String,
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(default)]
    pub public_keys: String,
}

pub async fn post_sftp(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SftpForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let enabled = checkbox_on(&form.enabled);
    // Split the textarea into one key per non-blank line. The node
    // re-validates each key before writing authorized_keys.
    let keys: Vec<String> = form
        .public_keys
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::SftpSet { sel, enabled, public_keys: keys },
    )
    .await?;
    match resp {
        RpcResponse::SftpSet(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?sftp=ok#ftp", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?sftp_error={}#ftp", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Lazily-loaded "Banned IPs" panel (Settings tab). Dispatched to the
/// OWNING node — bans are enforced node-wide by nftables there.
#[derive(Template)]
#[template(path = "_hosting_bans_panel.html")]
struct BansPanelTpl {
    bans: Vec<hyperion_types::IpBanWire>,
    selector: String,
    csrf_ban: String,
    error: String,
}

pub async fn get_bans_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    let csrf_ban = csrf_token_for(&state, &ctx, "/hostings/ban");
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::BanList { hosting_id: Some(detail.id.as_str().to_string()) },
    )
    .await;
    let (bans, error) = match resp {
        Ok(RpcResponse::BanList(b)) => (b, String::new()),
        Ok(RpcResponse::Error(e)) => (vec![], e.to_string()),
        _ => (vec![], "could not reach the owning node".into()),
    };
    let tpl = BansPanelTpl {
        bans,
        selector: detail.id.as_str().to_string(),
        csrf_ban,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct BanForm {
    pub selector: String,
    /// "add" | "remove".
    pub op: String,
    pub ip: String,
    #[serde(default)]
    pub reason: String,
}

pub async fn post_ban(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BanForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let hosting_id = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((d, _)) => Some(d.id.as_str().to_string()),
        Err(_) => None,
    };
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel)
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let req = if form.op == "remove" {
        Request::BanRemove { ip: form.ip.trim().to_string() }
    } else {
        let reason = if form.reason.trim().is_empty() {
            "manual ban".to_string()
        } else {
            form.reason.trim().chars().take(200).collect()
        };
        Request::BanAdd {
            ip: form.ip.trim().to_string(),
            hosting_id,
            reason,
            ttl_secs: 0, // manual bans are permanent until lifted
            source: "manual".into(),
        }
    };
    let resp = crate::dispatcher::dispatch_to_node(&state, target_owned.as_deref(), req).await?;
    match resp {
        RpcResponse::BanAdd | RpcResponse::BanRemove => {
            Ok(Redirect::to(&format!("/hostings/{}?ban=ok#settings", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?ban_error={}#settings", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct CertIssueForm {
    pub selector: String,
    #[serde(default)]
    pub staging: Option<String>,
    #[serde(default)]
    pub require_dns_match: Option<String>,
}

pub async fn post_cert_issue(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CertIssueForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let req = CertIssueRequest {
        staging: form.staging.as_deref() == Some("on"),
        require_dns_match: form.require_dns_match.as_deref() != Some("off"),
        extra_sans: vec![],
    };
    let staging = req.staging;
    // Cert lives on the node that owns the hosting (nginx vhost +
    // /etc/letsencrypt/live both go there). Find the right node
    // before dispatching ACME.
    let target_owned: Option<String> =
        find_hosting_anywhere(&state, sel.clone())
            .await
            .ok()
            .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::CertIssueAcme { sel, req },
    )
    .await?;
    match resp {
        RpcResponse::CertIssueAcme(_) => {
            let kind = if staging { "staging" } else { "prod" };
            Ok(Redirect::to(&format!("/hostings/{}?cert={}", sel_url, kind)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cert_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct Dns01BeginForm {
    pub selector: String,
    #[serde(default)]
    pub staging: Option<String>,
    /// "manual" (default) | "cloudflare".
    #[serde(default)]
    pub provider: String,
}

/// Interstitial page that shows the TXT records to publish for a manual
/// DNS-01 wildcard issuance, with a "I've published them, continue" form.
#[derive(Template)]
#[template(path = "cert_dns01.html")]
struct Dns01Tpl {
    username: String,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    domain: String,
    selector: String,
    record_name: String,
    values: Vec<String>,
    csrf_finish: String,
}

pub async fn post_cert_dns01_begin(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<Dns01BeginForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
    let staging = form.staging.as_deref() == Some("on");
    let provider = if form.provider == "cloudflare" {
        "cloudflare".to_string()
    } else {
        "manual".to_string()
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::CertDns01Begin { sel, staging, provider },
    )
    .await?;
    match resp {
        RpcResponse::CertDns01Begin { completed: true, .. } => {
            Ok(Redirect::to(&format!("/hostings/{}?cert=wildcard", sel_url)).into_response())
        }
        RpcResponse::CertDns01Begin { completed: false, record_name, values } => {
            let tpl = Dns01Tpl {
                username: ctx.username.clone(),
                user_initial: super::user_initial(&ctx.username),
                active: "hostings",
                css_version: super::css_version(),
                htmx_version: super::htmx_version(),
                domain: detail.domain.clone(),
                selector: detail.id.as_str().to_string(),
                record_name,
                values,
                csrf_finish: csrf_token_for(&state, &ctx, "/hostings/cert/dns01/finish"),
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cert_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct Dns01FinishForm {
    pub selector: String,
}

pub async fn post_cert_dns01_finish(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<Dns01FinishForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::CertDns01Finish { sel },
    )
    .await?;
    match resp {
        RpcResponse::CertDns01Finish(_) => {
            Ok(Redirect::to(&format!("/hostings/{}?cert=wildcard", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cert_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct RestoreForm {
    pub selector: String,
    pub archive_path: String,
    /// "files_and_db" (default) | "db_only" | "files_only".
    #[serde(default)]
    pub mode: String,
}

/// Map the restore-form's string into the typed enum. Unknown / empty
/// ⇒ full files+DB restore (the safe historical default).
fn parse_restore_mode(s: &str) -> hyperion_types::BackupRestoreMode {
    match s {
        "db_only" => hyperion_types::BackupRestoreMode::DbOnly,
        "files_only" => hyperion_types::BackupRestoreMode::FilesOnly,
        _ => hyperion_types::BackupRestoreMode::FilesAndDb,
    }
}

#[derive(Deserialize)]
pub struct LogsForm {
    pub selector: String,
    pub kind: String,
    #[serde(default = "default_log_lines")]
    pub lines: i64,
}
fn default_log_lines() -> i64 {
    200
}

pub async fn post_logs(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<LogsForm>,
) -> Result<Response, AppError> {
    // Logs can carry sensitive request data and stack traces — gate
    // them at manage level just like the other per-hosting writes.
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    // Per-site nginx/php logs live on the OWNING node's disk — dispatch
    // there, not the master local socket (which NotFounds for a
    // worker-hosted site). This is an HTMX target (#logs-output), so on
    // error render an inline fragment, NOT AppError::Rpc — a 5xx makes
    // htmx drop the swap and the button look dead.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::HostingLogs {
            sel,
            log_kind: form.kind.clone(),
            lines: form.lines,
        },
    )
    .await?;
    let body = match resp {
        RpcResponse::HostingLogs(s) => s,
        RpcResponse::Error(e) => {
            let msg = e.to_string();
            let esc = askama_escape::escape(&msg, askama_escape::Html);
            return Ok(Html(format!(
                r#"<div class="flash error" style="margin:0"><div class="flash-body">Could not read logs: {esc}</div></div>"#
            ))
            .into_response());
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let kind = askama_escape::escape(&form.kind, askama_escape::Html).to_string();
    let lines_label = form.lines;
    let pre = if body.trim().is_empty() {
        format!(
            r#"<div class="muted" style="padding:0.5rem 0">No {kind} log entries.</div>"#,
            kind = kind
        )
    } else {
        let esc = askama_escape::escape(&body, askama_escape::Html).to_string();
        format!(
            r#"<div class="muted" style="font-size:0.8rem;margin-bottom:0.4rem">Last {lines} lines · {kind}.log</div>
<pre style="max-height:36rem;overflow:auto;font-size:11.5px;line-height:1.5">{esc}</pre>"#,
            lines = lines_label,
            kind = kind,
            esc = esc
        )
    };
    Ok(Html(pre).into_response())
}

#[derive(Deserialize)]
pub struct CronForm {
    pub selector: String,
    pub body: String,
}

pub async fn post_cron_save(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CronForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // The crontab lives on the owning node (the editor reads it from
    // there) — write to the same node, not the master local socket.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::CronReplace {
            sel,
            body: form.body,
        },
    )
    .await?;
    match resp {
        RpcResponse::CronReplace => {
            Ok(Redirect::to(&format!("/hostings/{}?cron=saved", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?cron_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct WpResetForm {
    pub selector: String,
    pub wp_user: String,
    pub new_password: String,
}

/// Multipart upload of a tar.gz backup archive. Saved to
/// /var/lib/hyperion/backups/incoming/<sanitized-filename> then handed
/// off to the existing BackupRestore RPC.
pub async fn post_restore_upload(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    mut multipart: axum::extract::Multipart,
) -> Result<Response, AppError> {
    let mut selector: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        match field.name() {
            Some("selector") => {
                selector = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("selector: {e}")))?,
                );
            }
            Some("archive") => {
                filename = field.file_name().map(|s| {
                    s.chars()
                        .filter(|c| c.is_ascii_alphanumeric() || ['.', '-', '_'].contains(c))
                        .collect()
                });
                bytes = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("read archive: {e}")))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }
    let selector = selector.ok_or_else(|| AppError::BadRequest("missing selector".into()))?;
    // Authorize BEFORE touching the filesystem — a viewer must not be
    // able to dump arbitrary tarballs into /var/lib/hyperion/backups
    // even if they can't ultimately trigger the restore.
    let sel = match require_manage_for_selector(&state, &ctx, &selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let bytes = bytes.ok_or_else(|| AppError::BadRequest("missing archive file".into()))?;
    let filename = filename
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("upload-{}.tar.gz", hyperion_types::now_secs()));
    if !filename.ends_with(".tar.gz") {
        return Err(AppError::BadRequest(
            "archive must be a .tar.gz file".into(),
        ));
    }

    let incoming_dir = std::path::PathBuf::from("/var/lib/hyperion/backups/incoming");
    tokio::fs::create_dir_all(&incoming_dir)
        .await
        .map_err(|e| AppError::Internal(format!("mkdir incoming: {e}")))?;
    let dest = incoming_dir.join(&filename);
    tokio::fs::write(&dest, &bytes)
        .await
        .map_err(|e| AppError::Internal(format!("write upload: {e}")))?;

    let sel_url = urlencoding(&selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupRestore {
            sel,
            archive_path: dest.display().to_string(),
            mode: hyperion_types::BackupRestoreMode::FilesAndDb,
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupRestore => {
            Ok(Redirect::to(&format!("/hostings/{}?restore=ok", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?restore_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct BulkForm {
    pub action: String,
    /// Comma-separated list of selectors (domains). Browsers POST checkboxes
    /// one per name, so we use serde to gather them into a Vec. Axum's Form
    /// extractor surfaces repeated fields as comma-separated when the form
    /// type expects a String — use the manual deserializer instead.
    #[serde(default)]
    pub selected: Vec<String>,
    /// Asset id for the `install_asset` bulk action. Empty string
    /// (the wizard's "no asset picked" state) and missing field
    /// both map to 0 — install_asset then gets refused with a clean
    /// flash message rather than blowing up with a 422 deserialise
    /// error from serde trying to parse "" as i64.
    ///
    /// We accept the field as a String so the empty case is valid;
    /// `asset_id_parsed()` does the i64 conversion safely.
    #[serde(default)]
    pub asset_id: String,
    /// Whether to also activate the asset after install. Plain
    /// HTML checkbox → "on" when ticked, missing when not.
    #[serde(default)]
    pub activate: Option<String>,
}

impl BulkForm {
    /// Parse `asset_id` lazily. Empty / missing / non-numeric ⇒ 0
    /// (which the install_asset branch already rejects with a
    /// human flash, so falling through is safe).
    fn asset_id_parsed(&self) -> i64 {
        self.asset_id.trim().parse().unwrap_or(0)
    }
}

pub async fn post_bulk(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BulkForm>,
) -> Result<Response, AppError> {
    // Bulk ops span arbitrary hostings (admin can pick anything in the
    // list). Operators with per-hosting grants don't get to run bulk
    // delete across the cluster — that's an admin-level lever.
    if !ctx.is_admin_or_higher() {
        return Err(AppError::Forbidden);
    }
    if form.selected.is_empty() {
        return Ok(Redirect::to("/hostings?q=&state=").into_response());
    }
    // Pre-flight validation for install_asset — surface a single
    // clean error rather than echoing it per-selected hosting.
    if form.action == "install_asset" && form.asset_id_parsed() <= 0 {
        return Ok(Redirect::to(
            "/hostings?bulk_flash=Pick+an+asset+from+the+library+before+running+the+bulk+install",
        )
        .into_response());
    }
    let activate = matches!(form.activate.as_deref(), Some("on" | "true" | "1"));
    let mut ok = 0;
    let mut errs: Vec<String> = vec![];
    for sel_str in &form.selected {
        let sel = match parse_selector(sel_str) {
            Ok(s) => s,
            Err(e) => {
                errs.push(format!("{sel_str}: {e}"));
                continue;
            }
        };
        // For multi-node correctness: every per-hosting action —
        // including backup — has to land on the node that actually owns
        // the hosting (backups are stored per node, and BackupNow on the
        // master NotFounds for a worker-hosted row). Look it up first
        // (best-effort — single-node setups treat all hostings as local).
        let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
            .await
            .ok()
            .and_then(|(_d, n)| n);
        let target = target_owned.as_deref();
        let req = match form.action.as_str() {
            "suspend" => Request::HostingSuspend {
                sel,
                reason: hyperion_types::SuspendReason::Manual {
                    message: Some("bulk suspend".into()),
                },
            },
            "resume" => Request::HostingResume(sel),
            "backup" => Request::BackupNow { sel },
            "delete" => Request::HostingDelete {
                sel,
                opts: hyperion_rpc::wire::DeleteOpts {
                    keep_user: false,
                    keep_database: false,
                },
            },
            "install_asset" => Request::WpInstallFromAsset {
                sel,
                asset_id: form.asset_id_parsed(),
                activate,
            },
            other => {
                return Err(AppError::BadRequest(format!(
                    "unknown bulk action: {other}"
                )));
            }
        };
        let result = crate::dispatcher::dispatch_to_node(&state, target, req).await;
        match result {
            Ok(RpcResponse::Error(e)) => errs.push(format!("{sel_str}: {e}")),
            Ok(_) => ok += 1,
            Err(e) => errs.push(format!("{sel_str}: {e}")),
        }
    }
    let flash = if errs.is_empty() {
        format!("{} {} {}", ok, form.action, if ok == 1 { "ok" } else { "ok" })
    } else {
        format!(
            "{} succeeded, {} failed: {}",
            ok,
            errs.len(),
            errs.into_iter().take(3).collect::<Vec<_>>().join("; ")
        )
    };
    let q = urlencoding(&flash);
    Ok(Redirect::to(&format!("/hostings?bulk_flash={}", q)).into_response())
}

/// POST /hostings/:sel/wp/plugins/action
///
/// Single endpoint that dispatches every plugin operation by reading
/// the `action` form field. Keeps the WP plugin tab from sprouting
/// six separate routes (one per verb), and lets the audit log carry
/// the same `wp.plugin.action` event for all of them — the operator
/// only needs to grep for one prefix.
///
/// Form fields:
///   - selector: hosting selector (domain or id)
///   - slug: plugin slug; empty for "update_all"
///   - action: "install" | "activate" | "deactivate" | "update"
///             | "update_all" | "delete" | "auto_update_enable"
///             | "auto_update_disable"
///   - source: only required when action="install" — wp.org slug or URL
#[derive(Deserialize)]
pub struct WpPluginActionForm {
    pub selector: String,
    #[serde(default)]
    pub slug: String,
    pub action: String,
    #[serde(default)]
    pub source: String,
}

#[derive(Deserialize)]
pub struct WpThemeActionForm {
    pub selector: String,
    #[serde(default)]
    pub slug: String,
    pub action: String,
    #[serde(default)]
    pub source: String,
    /// Carries the hosting's node id (injected by the detail
    /// page's JS shim) so the dispatch lands on the right agent.
    #[serde(default)]
    pub target_node: String,
}

/// POST /hostings/wp/theme-action — single endpoint for every
/// whitelisted theme verb. Mirrors post_wp_plugin_action but
/// follows the hosting via target_node.
pub async fn post_wp_theme_action(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpThemeActionForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let action = match form.action.as_str() {
        "install" => {
            let source = form.source.trim().to_string();
            if source.is_empty() {
                return Err(AppError::BadRequest(
                    "theme install requires a source (slug or https URL)".into(),
                ));
            }
            hyperion_types::WpThemeAction::Install { source }
        }
        "activate" => hyperion_types::WpThemeAction::Activate,
        "update" => hyperion_types::WpThemeAction::Update,
        "update_all" => hyperion_types::WpThemeAction::UpdateAll,
        "delete" => hyperion_types::WpThemeAction::Delete,
        other => {
            return Err(AppError::BadRequest(format!(
                "unknown wp theme action: {}",
                askama_escape::escape(other, askama_escape::Html)
            )));
        }
    };
    let slug = match &action {
        hyperion_types::WpThemeAction::UpdateAll => String::new(),
        hyperion_types::WpThemeAction::Install { source } => source.clone(),
        _ => {
            let s = form.slug.trim().to_string();
            if s.is_empty() {
                return Err(AppError::BadRequest("missing theme slug".into()));
            }
            s
        }
    };
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
        Request::WpThemeAction { sel, slug, action },
    )
    .await?;
    match resp {
        RpcResponse::WpThemeAction(r) => {
            let msg = format!("Theme {}: {}", r.state, r.message);
            Ok(Redirect::to(&format!(
                "/hostings/{}?{}={}#wordpress",
                sel_url,
                if r.state == "failed" { "wp_error" } else { "wp_flash" },
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

/// POST /hostings/migration/export
///
/// Trigger a migration-bundle export on the source node. Returns a
/// redirect to the detail page with the bundle paths flashed —
/// operator copies the scp one-liner from there. The bundle stays on
/// disk until the operator deletes it (no auto-prune for now).
#[derive(Deserialize)]
pub struct MigrationExportForm {
    pub selector: String,
}

/// Template for the one-shot "export result" page rendered inline as
/// the POST response (NOT a redirect — the URL would otherwise carry
/// the signed token through browser history and the Referer header).
#[derive(Template)]
#[template(path = "migration_export_result.html")]
struct MigrationExportResultTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    selector: &'a str,
    bundle: hyperion_types::HostingMigrationBundle,
    /// Session-wide CSRF token. Currently unread by the template
    /// itself (no forms on the result page), but populated so a
    /// future "delete bundle now" or "regenerate token" button can
    /// drop in without re-plumbing the handler.
    #[allow(dead_code)]
    csrf_token: String,
}

/// One-click migration: export the hosting from its current node,
/// hand the signed download URL to the target node, wait for the
/// import to finish. After success, the OLD hosting is suspended
/// (NOT deleted — operator should verify the new one before
/// pulling the trigger).
///
/// Current limitation: only works when the SOURCE is the master.
/// Worker-to-worker / worker-to-master needs the master to proxy
/// the bundle bytes (each worker holds its own /var/lib/hyperion/
/// migration/<id>/ — only master serves the /api/migration/bundle/
/// route). That's a follow-up.
#[derive(Deserialize)]
pub struct MigrationMoveForm {
    pub selector: String,
    pub target_node: String,
    /// Hidden — populated by the JS-injected hidden input. Identifies
    /// which node the hosting currently LIVES on (source).
    #[serde(default)]
    pub source_node: String,
}

/// Form input for "Clone this hosting to a new domain (and
/// optionally a different node)". Renders into the cross-node
/// migration tracker so the operator gets a live progress bar.
#[derive(serde::Deserialize)]
pub struct HostingCloneForm {
    /// Source hosting selector (domain or id, same shape as
    /// migrate uses).
    pub selector: String,
    /// New domain for the clone — e.g. `staging.example.cz`.
    pub new_domain: String,
    /// Optional target node. Empty / `LOCAL_NODE_SENTINEL` ⇒ clone
    /// on the master itself (single-node deploy or staging clone
    /// next to the original).
    #[serde(default)]
    pub target_node: String,
    /// Hidden — populated by the page so the source-node dispatch
    /// matches the original migration form.
    #[serde(default)]
    pub source_node: String,
}

pub async fn post_hosting_clone(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<HostingCloneForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);

    // ── Sanity gates ──
    let new_domain = form.new_domain.trim().to_string();
    if new_domain.is_empty() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error=Pick+a+target+domain+for+the+clone#clone",
            sel_url
        ))
        .into_response());
    }
    if new_domain == form.selector.trim() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#clone",
            sel_url,
            urlencoding("Clone domain must differ from the source domain.")
        ))
        .into_response());
    }

    let source_local = form.source_node.is_empty()
        || form.source_node == crate::dispatcher::LOCAL_NODE_SENTINEL;
    let source_node_str = if source_local {
        crate::dispatcher::LOCAL_NODE_SENTINEL.to_string()
    } else {
        form.source_node.clone()
    };
    // Default target_node = source when empty so single-node deploys
    // can clone in place.
    let target_node_str = if form.target_node.trim().is_empty() {
        source_node_str.clone()
    } else {
        form.target_node.trim().to_string()
    };

    // Reuse the migration job pattern — same kind="hosting_clone"
    // bucket so /jobs shows them under their own filter row.
    let master_url = super::derive_master_url(&state, &headers).await;
    let bundle_ttl = crate::handlers::migration::BUNDLE_DOWNLOAD_TTL_SECS;
    let payload = serde_json::json!({
        "selector": form.selector,
        "new_domain": new_domain,
        "source_node": form.source_node,
        "target_node": target_node_str,
    });
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let clone_state = state.clone();
    let clone_sel = sel.clone();
    let clone_form_sel = form.selector.clone();
    let clone_source = form.source_node.clone();
    let clone_target = target_node_str.clone();
    let clone_new_domain = new_domain.clone();

    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "hosting_clone",
        Some(&new_domain),
        &payload.to_string(),
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_clone_job(
                reporter,
                clone_state,
                clone_sel,
                clone_form_sel,
                source_local,
                clone_source,
                clone_target,
                clone_new_domain,
                master_url,
                bundle_ttl,
            )
            .await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker for hosting clone. Same shape as
/// `run_migration_job` but:
///   * does NOT suspend the source (clones are an additive op —
///     the original keeps serving traffic)
///   * passes `override_domain` so the importer creates the new
///     hosting under `new_domain` instead of the manifest's
///     captured domain
///   * surfaces the new domain in the final step label so the
///     operator can click it from the job page.
#[allow(clippy::too_many_arguments)]
async fn run_clone_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    sel: hyperion_rpc::HostingSelector,
    selector_text: String,
    source_local: bool,
    source_node: String,
    target_node: String,
    new_domain: String,
    master_url: String,
    bundle_ttl: i64,
) {
    let source_dispatch = if source_local {
        None
    } else {
        Some(source_node.as_str())
    };

    // ---- 0. Version preflight (see run_migration_job for the
    //         rationale; same cryptic curl bug bit clones too). ----
    reporter
        .step("Pre-flight: version check on source + target", 2, "")
        .await;
    let master_v = probe_agent_version(&state, None).await;
    let src_v = probe_agent_version(&state, source_dispatch).await;
    let tgt_v = probe_agent_version(&state, Some(target_node.as_str())).await;
    if src_v != master_v || tgt_v != master_v {
        reporter
            .finish(
                false,
                Some(format!(
                    "agent version mismatch — master {master_v}, source {src_v}, target {tgt_v}. \
                     Update the lagging node via /install#node-{target_node} before re-running clone."
                )),
            )
            .await;
        return;
    }
    reporter
        .step(
            "Pre-flight: versions match",
            4,
            &format!("master={master_v} source={src_v} target={tgt_v}\n"),
        )
        .await;

    reporter
        .step(
            &format!(
                "Exporting source bundle on {}",
                if source_local { "master" } else { source_node.as_str() }
            ),
            5,
            &format!("source selector: {}\n", selector_text),
        )
        .await;
    let export = match crate::dispatcher::dispatch_to_node(
        &state,
        source_dispatch,
        Request::HostingExport { hosting: sel.clone() },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            reporter
                .finish(false, Some(format!("dispatch HostingExport: {e}")))
                .await;
            return;
        }
    };
    let bundle = match export {
        RpcResponse::HostingExport(b) => b,
        RpcResponse::Error(e) => {
            reporter.finish(false, Some(format!("Export failed: {e}"))).await;
            return;
        }
        _ => {
            reporter
                .finish(false, Some("expected HostingExport response".into()))
                .await;
            return;
        }
    };
    reporter
        .step(
            "Bundle ready on source",
            30,
            &format!(
                "bundle_id={} archive_bytes={}\n",
                bundle.bundle_id, bundle.archive_bytes
            ),
        )
        .await;

    if !source_local {
        reporter
            .step("Proxying bundle from worker to master", 45, "")
            .await;
        if let Err(e) =
            pull_bundle_from_worker(&state, &source_node, &bundle.bundle_id).await
        {
            reporter
                .finish(false, Some(format!("Bundle proxy failed: {e}")))
                .await;
            return;
        }
        reporter.step("Bundle landed on master", 55, "proxy ok\n").await;
    } else {
        reporter
            .step("Bundle already on master (source was local)", 55, "")
            .await;
    }

    let exp = hyperion_types::now_secs() + bundle_ttl;
    let token =
        hyperion_auth::bundle_sig::mint(state.csrf_key.as_ref(), &bundle.bundle_id, exp);
    let base_url = format!("{master_url}/api/migration/bundle/{}", bundle.bundle_id);

    reporter
        .step(
            &format!(
                "Importing as {} on {}",
                new_domain, target_node
            ),
            65,
            &format!("override_domain={new_domain}\n"),
        )
        .await;
    let import = match crate::dispatcher::dispatch_to_node(
        &state,
        Some(target_node.as_str()),
        Request::HostingImportFromUrl {
            base_url: base_url.clone(),
            token: token.clone(),
            override_domain: Some(new_domain.clone()),
            override_aliases: Vec::new(),
        },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            reporter
                .finish(false, Some(format!("dispatch HostingImportFromUrl: {e}")))
                .await;
            return;
        }
    };
    let new_id = match import {
        RpcResponse::HostingImportFromUrl(r) => r.new_hosting_id,
        RpcResponse::Error(e) => {
            reporter
                .finish(false, Some(format!("Target import failed: {e}")))
                .await;
            return;
        }
        _ => {
            reporter
                .finish(false, Some("expected HostingImportFromUrl response".into()))
                .await;
            return;
        }
    };

    tracing::info!(
        source = %selector_text,
        target_node = %target_node,
        new_domain = %new_domain,
        new_hosting_id = new_id.as_str(),
        "hosting clone completed"
    );

    reporter
        .step(
            &format!(
                "Done — clone live at {} (id {}) on {}",
                new_domain,
                new_id.as_str(),
                target_node
            ),
            100,
            "clone ok\n",
        )
        .await;
    reporter.finish(true, None).await;
}

#[derive(serde::Deserialize)]
pub struct QuotaSetForm {
    pub selector: String,
    #[serde(default)]
    pub disk_soft_mib: i64,
    #[serde(default)]
    pub disk_hard_mib: i64,
    #[serde(default)]
    pub mem_limit_mib: i64,
    #[serde(default)]
    pub bw_soft_mib: i64,
    #[serde(default)]
    pub bw_hard_mib: i64,
}

pub async fn post_quota_set(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<QuotaSetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // UI accepts MiB for both disk fields (cleaner than asking
    // operators to type kibibytes). Convert to KiB at the boundary
    // — setquota wants 1024-byte blocks.
    let disk_soft_kib = form.disk_soft_mib.saturating_mul(1024);
    let disk_hard_kib = form.disk_hard_mib.saturating_mul(1024);
    // setquota runs against the filesystem on the node that holds
    // /home/<user> — dispatch to the owner, not the master local socket
    // (the Quota tab already READS from the owner).
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::QuotaSet {
            hosting: sel,
            disk_soft_kib,
            disk_hard_kib,
            mem_limit_mib: form.mem_limit_mib,
            bw_soft_mib: form.bw_soft_mib,
            bw_hard_mib: form.bw_hard_mib,
        },
    )
    .await?;
    let flash = match resp {
        RpcResponse::QuotaApplied(v) => {
            if let Some(err) = v.last_error.as_deref() {
                format!("Quota saved (kernel: {err})")
            } else {
                "Quota saved + applied to the kernel.".to_string()
            }
        }
        RpcResponse::Error(e) => format!("Quota set failed: {e}"),
        _ => "Quota set: unexpected response".into(),
    };
    Ok(Redirect::to(&format!(
        "/hostings/{}?flash={}#quota",
        sel_url,
        urlencoding(&flash)
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct QuotaEnableForm {
    pub selector: String,
}

/// POST /hostings/quota/enable-kernel — turn on Linux kernel disk quotas on
/// the OWNING node's filesystem (edits /etc/fstab + remount + quotacheck +
/// quotaon). Admin-only: this is a node-wide filesystem change, not a
/// per-hosting tweak, so per-hosting "manage" isn't enough.
pub async fn post_quota_enable_kernel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<QuotaEnableForm>,
) -> Result<Response, AppError> {
    let sel_url = urlencoding(&form.selector);
    if !ctx.is_admin_or_higher() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error=admin+role+required+to+enable+kernel+quotas#quota",
            sel_url
        ))
        .into_response());
    }
    let sel = parse_selector(&form.selector)?;
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::QuotaEnableKernel { hosting: sel },
    )
    .await?;
    let flash = match resp {
        RpcResponse::QuotaEnableKernel(s) => s.message,
        RpcResponse::Error(e) => format!("Couldn't enable kernel quotas: {e}"),
        _ => "Enable kernel quotas: unexpected response".into(),
    };
    Ok(Redirect::to(&format!("/hostings/{}?flash={}#quota", sel_url, urlencoding(&flash))).into_response())
}

pub async fn post_migration_move(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<MigrationMoveForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);

    // 0. Sanity gates.
    let target = form.target_node.trim();
    if target.is_empty() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error=Pick+a+target+node+for+migration#migration",
            sel_url
        ))
        .into_response());
    }
    let source_local = form.source_node.is_empty()
        || form.source_node == crate::dispatcher::LOCAL_NODE_SENTINEL;
    let source_node_str = if source_local {
        crate::dispatcher::LOCAL_NODE_SENTINEL.to_string()
    } else {
        form.source_node.clone()
    };
    let target_owned = target.to_string();
    if target_owned == source_node_str {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#migration",
            sel_url,
            urlencoding("Target node must be different from the source.")
        ))
        .into_response());
    }

    // Migration is 30-300 seconds depending on hosting size, with
    // mysqldump + tar + scp + reimport phases. Doing this inline
    // freezes the browser tab with no signal. Hand it to the generic
    // job-tracker: open a `migration` row, tokio::spawn the work,
    // redirect the operator to /jobs/<id> where they watch the live
    // progress bar tick through each phase.
    let master_url = super::derive_master_url(&state, &headers).await;
    let bundle_ttl = crate::handlers::migration::BUNDLE_DOWNLOAD_TTL_SECS;
    let payload = serde_json::json!({
        "selector": form.selector,
        "source_node": form.source_node,
        "target_node": target_owned,
    });
    let migration_state = state.clone();
    let migration_sel = sel.clone();
    let migration_form_sel = form.selector.clone();
    let migration_source_node = form.source_node.clone();
    let migration_target = target_owned.clone();
    let actor_label = ctx.username.clone();
    let actor_uid = ctx
        .session
        .as_ref()
        .map(|s| s.user_id)
        .unwrap_or(0);

    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "migration",
        Some(&form.selector),
        &payload.to_string(),
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_migration_job(
                reporter,
                migration_state,
                migration_sel,
                migration_form_sel,
                source_local,
                migration_source_node,
                migration_target,
                master_url,
                bundle_ttl,
            )
            .await;
        },
    )
    .await?;

    // 200 OK with redirect to the live progress page.
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Run the migration in the background, ticking progress at each
/// phase boundary so the operator's progress bar advances in
/// readable jumps (Export 25% → Bundle 45% → Import 80% → Suspend
/// 95% → Done 100%). Always calls `.finish()` exactly once — even
/// on early bailout — so the row never gets stuck in `running`.
/// Background runner for the post-create setup pipeline. Lives
/// behind `spawn_job("post_create_setup", …)` so the handler can
/// return the hosting detail page (with credentials) within
/// milliseconds while the slow work runs here. Every phase is
/// optional and the progress bands shift accordingly:
///
///   5–30%  — Let's Encrypt cert (when the wizard checkbox was on)
///   35–70% — WordPress core install (when requested + feasible)
///   70–95% — Profile apply, plugin-by-plugin (when a profile rode
///            along with the WP install)
///   100%   — Done
///
/// A failed cert does NOT abort the WP install — the site works
/// on the bootstrap cert; the job still finishes `failed` with the
/// cert error in the message so the operator knows to fix DNS and
/// re-issue from the SSL tab.
#[allow(clippy::too_many_arguments)]
async fn run_post_create_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    target_node: Option<String>,
    hosting_id: hyperion_types::HostingId,
    domain: String,
    issue_cert: bool,
    wp_req: Option<hyperion_types::WpInstallRequest>,
    profile_id: i64,
) {
    let target = target_node.as_deref();
    let mut deferred_failures: Vec<String> = Vec::new();

    // ── Phase 1: Let's Encrypt cert ──────────────────────────
    if issue_cert {
        reporter
            .step(
                &format!("Issuing Let's Encrypt certificate for {domain}"),
                5,
                "ACME HTTP-01 — ordering cert, serving the challenge, waiting for validation…\n",
            )
            .await;
        let resp = crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::CertIssueAcme {
                sel: HostingSelector::Id(hosting_id.clone()),
                req: hyperion_types::CertIssueRequest {
                    staging: false,
                    // DNS readiness was already shown in the wizard's
                    // preflight; let the agent's own check gate the
                    // issuance so we fail fast (with a clear message)
                    // instead of burning a Let's Encrypt attempt.
                    require_dns_match: true,
                    extra_sans: vec![],
                },
            },
        )
        .await;
        match resp {
            Ok(RpcResponse::CertIssueAcme(info)) => {
                reporter
                    .step(
                        "Certificate issued",
                        30,
                        &format!(
                            "✓ Let's Encrypt cert active (issuer: {}) — https://{domain} now serves a trusted cert.\n",
                            info.issuer
                        ),
                    )
                    .await;
            }
            Ok(RpcResponse::Error(e)) => {
                deferred_failures.push(format!(
                    "Certificate issuance failed: {e}. The site stays on the self-signed bootstrap cert — fix DNS if needed and re-issue from the SSL tab."
                ));
                reporter
                    .step(
                        "Certificate issuance failed — continuing",
                        30,
                        &format!("✗ cert: {e}\n"),
                    )
                    .await;
            }
            Ok(other) => {
                deferred_failures.push(format!(
                    "Certificate issuance returned an unexpected RPC variant ({other:?}). Re-issue from the SSL tab."
                ));
                reporter
                    .step("Certificate issuance failed — continuing", 30, "✗ cert: unexpected response\n")
                    .await;
            }
            Err(e) => {
                deferred_failures.push(format!(
                    "Certificate issuance RPC failed: {e}. Re-issue from the SSL tab."
                ));
                reporter
                    .step(
                        "Certificate issuance failed — continuing",
                        30,
                        &format!("✗ cert: {e}\n"),
                    )
                    .await;
            }
        }
    }

    // ── Phase 2: WordPress core ──────────────────────────────
    if let Some(wp_req) = wp_req {
        reporter
            .step(
                "Installing WordPress core",
                35,
                "Running wp-cli core install (download + DB seed + admin user)…\n",
            )
            .await;
        let install_resp = crate::dispatcher::dispatch_to_node(
            &state,
            target,
            Request::WpInstall {
                sel: HostingSelector::Id(hosting_id.clone()),
                req: wp_req,
            },
        )
        .await;
        match install_resp {
            Ok(RpcResponse::WpInstall(_)) => {
                reporter
                    .step(
                        "WordPress installed",
                        65,
                        "✓ wp-cli reported success — wp-config.php, wp-content/, admin user all in place.\n",
                    )
                    .await;
            }
            Ok(RpcResponse::Error(e)) => {
                deferred_failures.push(format!(
                    "WordPress install failed: {e}. The hosting itself is alive — re-run from the WordPress tab."
                ));
                reporter.finish(false, Some(deferred_failures.join("\n"))).await;
                return;
            }
            Ok(other) => {
                deferred_failures.push(format!(
                    "WordPress install returned an unexpected RPC variant ({other:?}). Re-run from the WordPress tab."
                ));
                reporter.finish(false, Some(deferred_failures.join("\n"))).await;
                return;
            }
            Err(e) => {
                deferred_failures.push(format!(
                    "WordPress install RPC failed (couldn't reach the agent): {e}. Re-run from the WordPress tab."
                ));
                reporter.finish(false, Some(deferred_failures.join("\n"))).await;
                return;
            }
        }

        // ── Phase 3: profile (plugins/themes ride with WP) ───
        if profile_id > 0 {
            if let Err(msg) = run_profile_apply_phase(
                &reporter,
                &state,
                target,
                &hosting_id,
                profile_id,
                70,
                25,
            )
            .await
            {
                deferred_failures.push(msg);
                reporter.finish(false, Some(deferred_failures.join("\n"))).await;
                return;
            }
        }
    }

    if !deferred_failures.is_empty() {
        reporter
            .finish(false, Some(deferred_failures.join("\n")))
            .await;
        return;
    }
    reporter
        .step(
            "Done",
            100,
            "Post-create setup finished — refresh the hosting detail page to see the result.\n",
        )
        .await;
    reporter.finish(true, None).await;
}

/// The profile-apply phase shared by the post-create WP-install job
/// and the standalone "apply profile to existing hosting" job:
///
///   1. `ProfileApply { skip_wp_items: true }` on the owning node —
///      limits, expiry policy, pricing snapshot.
///   2. `ProfileGet` on the master to enumerate the profile's
///      plugin + theme lines.
///   3. One `ProfileWpItemInstall` per line, with a progress step +
///      a ✓/✗ log line each. Per-item failures don't abort the
///      remaining items; they're collected and reported together.
///
/// Progress is mapped onto `pct_base..pct_base+pct_span`. Returns
/// `Err(finish_message)` when the run should fail the job; the
/// caller calls `reporter.finish(false, …)`.
pub(crate) async fn run_profile_apply_phase(
    reporter: &crate::handlers::jobs::JobReporter,
    state: &SharedState,
    target: Option<&str>,
    hosting_id: &hyperion_types::HostingId,
    profile_id: i64,
    pct_base: i64,
    pct_span: i64,
) -> Result<(), String> {
    reporter
        .step(
            "Applying profile limits + expiry + pricing",
            pct_base,
            "profile_apply — PHP limits, expiry policy, price snapshot…\n",
        )
        .await;
    let apply = crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::ProfileApply {
            sel: HostingSelector::Id(hosting_id.clone()),
            profile_id,
            skip_wp_items: true,
        },
    )
    .await;
    match apply {
        Ok(RpcResponse::ProfileApply(_)) => {}
        Ok(RpcResponse::Error(e)) => {
            return Err(format!(
                "Profile apply failed: {e}. Re-run from the Profile tab on /hostings/{}.",
                hosting_id.as_str()
            ));
        }
        Ok(_) => {}
        Err(e) => {
            return Err(format!(
                "Profile apply RPC failed (couldn't reach the agent): {e}. Re-run from the Profile tab."
            ));
        }
    }

    // Profiles live in the MASTER's DB — read the line lists from
    // the local socket regardless of where the hosting lives.
    let profile = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ProfileGet { id: profile_id },
    )
    .await
    {
        Ok(RpcResponse::ProfileGet(p)) => p,
        _ => {
            return Err(
                "Limits applied, but reading the profile back failed — plugins/themes were NOT installed. Re-run from the Profile tab.".to_string(),
            );
        }
    };
    let items = profile_wp_lines(&profile.wp_plugins, &profile.wp_themes);
    let total = items.len();
    if total == 0 {
        reporter
            .step(
                "Profile applied",
                pct_base + pct_span,
                "Profile has no plugins or themes — limits + expiry + pricing only.\n",
            )
            .await;
        return Ok(());
    }

    let mut failed: Vec<String> = Vec::new();
    for (idx, (kind, line)) in items.iter().enumerate() {
        let pct = pct_base + ((idx as i64) * pct_span / (total as i64));
        reporter
            .step(
                &format!("Installing {kind} {}/{}: {line}", idx + 1, total),
                pct,
                "",
            )
            .await;
        let resp = crate::dispatcher::dispatch_to_node(
            state,
            target,
            Request::ProfileWpItemInstall {
                sel: HostingSelector::Id(hosting_id.clone()),
                item_kind: kind.to_string(),
                line: line.clone(),
            },
        )
        .await;
        match resp {
            Ok(RpcResponse::ProfileWpItemInstalled { label, activated }) => {
                reporter
                    .step(
                        &format!("Installed {kind} {}/{}: {label}", idx + 1, total),
                        pct,
                        &format!(
                            "✓ {kind} {label}{}\n",
                            if activated { " (activated)" } else { "" }
                        ),
                    )
                    .await;
            }
            Ok(RpcResponse::Error(e)) => {
                failed.push(format!("{kind} `{line}`: {e}"));
                reporter
                    .step(
                        &format!("Failed {kind} {}/{}: {line}", idx + 1, total),
                        pct,
                        &format!("✗ {kind} {line}: {e}\n"),
                    )
                    .await;
            }
            other => {
                failed.push(format!("{kind} `{line}`: unexpected response"));
                reporter
                    .step(
                        &format!("Failed {kind} {}/{}: {line}", idx + 1, total),
                        pct,
                        &format!("✗ {kind} {line}: unexpected RPC response {other:?}\n"),
                    )
                    .await;
            }
        }
    }
    if !failed.is_empty() {
        return Err(format!(
            "{} of {} profile item(s) installed, {} failed:\n{}\nRe-run the failed ones from the WordPress tab or the asset library.",
            total - failed.len(),
            total,
            failed.len(),
            failed.join("\n")
        ));
    }
    reporter
        .step(
            "Profile applied",
            pct_base + pct_span,
            &format!("All {total} plugin/theme item(s) installed.\n"),
        )
        .await;
    Ok(())
}

/// Enumerate a profile's wp_plugins + wp_themes text fields into
/// `(kind, line)` pairs, skipping blanks and `#` comment lines.
/// The line content (slug / @asset:N / trailing `!`) is passed
/// verbatim to the agent — parsing semantics live in ONE place
/// (Service::install_profile_wp_line); this is just a splitter so
/// the job runner knows how many items to report progress for.
fn profile_wp_lines(plugins_text: &str, themes_text: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for (kind, text) in [("plugin", plugins_text), ("theme", themes_text)] {
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            out.push((kind, line.to_string()));
        }
    }
    out
}

async fn probe_agent_version(state: &SharedState, node: Option<&str>) -> String {
    match crate::dispatcher::dispatch_to_node(state, node, Request::AgentInfo).await {
        Ok(RpcResponse::AgentInfo(i)) => i.version,
        _ => String::from("unknown"),
    }
}

async fn run_migration_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    sel: hyperion_rpc::HostingSelector,
    selector_text: String,
    source_local: bool,
    source_node: String,
    target_node: String,
    master_url: String,
    bundle_ttl: i64,
) {
    let source_dispatch = if source_local {
        None
    } else {
        Some(source_node.as_str())
    };

    // ---- 0. Version preflight ----
    //
    // The cross-node migration / clone pipeline calls
    // `curl_to_file` on the TARGET node — if its agent binary
    // is from before bb09ebc, every import dies with a cryptic
    // `curl: option --max-time: expected a proper numerical
    // parameter` ~2 s into the run. The error tail looks
    // identical to the one the master-side fix already cured,
    // so the operator wastes time re-reading their own commit
    // history before realising the worker just wasn't updated.
    //
    // Stop that loop here: probe AgentInfo on source AND
    // target, compare against the master's own version. Any
    // mismatch ⇒ fail-fast with a clean message pointing
    // directly at `/install#node-<id>` where the per-node
    // Update button lives. The operator clicks once and
    // re-runs the migration.
    reporter
        .step("Pre-flight: version check on source + target", 2, "")
        .await;
    let master_v = probe_agent_version(&state, None).await;
    let src_v = probe_agent_version(&state, source_dispatch).await;
    let tgt_v = probe_agent_version(&state, Some(target_node.as_str())).await;
    if src_v != master_v || tgt_v != master_v {
        reporter
            .finish(
                false,
                Some(format!(
                    "agent version mismatch — master {master_v}, source {src_v}, target {tgt_v}. \
                     The cross-node migration curl bug was fixed in commit bb09ebc; \
                     update the lagging node(s) via /install#node-{target_node} \
                     (and the source if it isn't the master) before re-running migration."
                )),
            )
            .await;
        return;
    }
    reporter
        .step(
            "Pre-flight: versions match",
            4,
            &format!("master={master_v} source={src_v} target={tgt_v}\n"),
        )
        .await;

    // ---- 1. Export bundle on source ----
    reporter
        .step(
            &format!("Exporting bundle on {}", if source_local { "master" } else { source_node.as_str() }),
            5,
            "scheduling HostingExport RPC\n",
        )
        .await;
    let export = match crate::dispatcher::dispatch_to_node(
        &state,
        source_dispatch,
        Request::HostingExport { hosting: sel.clone() },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            reporter.finish(false, Some(format!("dispatch HostingExport: {e}"))).await;
            return;
        }
    };
    let bundle = match export {
        RpcResponse::HostingExport(b) => b,
        RpcResponse::Error(e) => {
            reporter.finish(false, Some(format!("Export failed: {e}"))).await;
            return;
        }
        _ => {
            reporter.finish(false, Some("expected HostingExport response".into())).await;
            return;
        }
    };
    reporter
        .step(
            "Bundle ready on source",
            30,
            &format!(
                "bundle_id={} archive_bytes={}\n",
                bundle.bundle_id, bundle.archive_bytes
            ),
        )
        .await;

    // ---- 1b. Pull bundle to master if source was a worker ----
    if !source_local {
        reporter
            .step("Proxying bundle from worker to master", 45, "")
            .await;
        if let Err(e) = pull_bundle_from_worker(&state, &source_node, &bundle.bundle_id).await {
            reporter.finish(false, Some(format!("Bundle proxy failed: {e}"))).await;
            return;
        }
        reporter.step("Bundle landed on master", 55, "proxy ok\n").await;
    } else {
        reporter
            .step("Bundle already on master (source was local)", 55, "")
            .await;
    }

    // ---- 2. Mint signed download URL ----
    let exp = hyperion_types::now_secs() + bundle_ttl;
    let token = hyperion_auth::bundle_sig::mint(state.csrf_key.as_ref(), &bundle.bundle_id, exp);
    let base_url = format!("{master_url}/api/migration/bundle/{}", bundle.bundle_id);

    // ---- 3. Import on target ----
    reporter
        .step(
            &format!("Importing on target {}", target_node),
            65,
            &format!("HostingImportFromUrl base_url={}\n", base_url),
        )
        .await;
    let import = match crate::dispatcher::dispatch_to_node(
        &state,
        Some(target_node.as_str()),
        Request::HostingImportFromUrl {
            base_url: base_url.clone(),
            token: token.clone(),
            override_domain: None,
            override_aliases: Vec::new(),
        },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            reporter.finish(false, Some(format!("dispatch HostingImportFromUrl: {e}"))).await;
            return;
        }
    };
    let new_id = match import {
        RpcResponse::HostingImportFromUrl(r) => r.new_hosting_id,
        RpcResponse::Error(e) => {
            reporter.finish(false, Some(format!("Target import failed: {e}"))).await;
            return;
        }
        _ => {
            reporter
                .finish(false, Some("expected HostingImportFromUrl response".into()))
                .await;
            return;
        }
    };
    reporter
        .step(
            "Imported on target",
            85,
            &format!("new_hosting_id={}\n", new_id.as_str()),
        )
        .await;

    // ---- 4. Suspend source (best-effort) ----
    reporter
        .step("Suspending source copy (best-effort)", 95, "")
        .await;
    let _ = crate::dispatcher::dispatch_to_node(
        &state,
        source_dispatch,
        Request::HostingSuspend {
            sel: sel.clone(),
            reason: hyperion_types::SuspendReason::Manual {
                message: Some(format!(
                    "Migrated to node {target_node} as {} — verify and delete here when ready.",
                    new_id.as_str()
                )),
            },
        },
    )
    .await;

    tracing::info!(
        selector = %selector_text,
        target_node = %target_node,
        new_hosting_id = new_id.as_str(),
        "migration job completed"
    );

    reporter
        .step(
            &format!(
                "Done — new hosting id {} on {}",
                new_id.as_str(),
                target_node
            ),
            100,
            "all phases ok\n",
        )
        .await;
    reporter.finish(true, None).await;
}


pub async fn post_migration_export(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<MigrationExportForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingExport { hosting: sel },
    )
    .await?;
    match resp {
        RpcResponse::HostingExport(mut b) => {
            // Mint the signed download URL — agent has no idea what
            // master URL the operator's browser used to reach us, so
            // the web layer is the only thing that can derive it.
            let master_url = super::derive_master_url(&state, &headers).await;
            let exp = hyperion_types::now_secs()
                + crate::handlers::migration::BUNDLE_DOWNLOAD_TTL_SECS;
            let token = hyperion_auth::bundle_sig::mint(
                state.csrf_key.as_ref(),
                &b.bundle_id,
                exp,
            );
            b.download_base_url = format!(
                "{master_url}/api/migration/bundle/{}",
                b.bundle_id
            );
            b.bundle_token = token;
            b.token_expires_at = exp;

            let tpl = MigrationExportResultTpl {
                username: &ctx.username,
                user_initial: super::user_initial(&ctx.username),
                active: "hostings",
                css_version: super::css_version(),
                htmx_version: super::htmx_version(),
                selector: &form.selector,
                bundle: b,
                csrf_token: super::session_csrf_token(&state, &ctx),
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&format!("Migration export failed: {}", e));
            Ok(Redirect::to(&format!("/hostings/{}?flash_error={}#migration", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// derive_master_url is the shared helper in handlers::mod — see
// there for the loopback-detection + public-IP fallback rationale.
// Hostings caller imports via the super:: path below.

pub async fn post_wp_plugin_action(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpPluginActionForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // Map the form's `action` string into the typed enum. Anything not
    // on the whitelist gets a 400 — the UI shouldn't be able to send it.
    let action = match form.action.as_str() {
        "install" => {
            let source = form.source.trim().to_string();
            if source.is_empty() {
                return Err(AppError::BadRequest(
                    "plugin install requires a source (slug or https URL)".into(),
                ));
            }
            hyperion_types::WpPluginAction::Install { source }
        }
        "activate" => hyperion_types::WpPluginAction::Activate,
        "deactivate" => hyperion_types::WpPluginAction::Deactivate,
        "update" => hyperion_types::WpPluginAction::Update,
        "update_all" => hyperion_types::WpPluginAction::UpdateAll,
        "delete" => hyperion_types::WpPluginAction::Delete,
        "auto_update_enable" => hyperion_types::WpPluginAction::SetAutoUpdate { enabled: true },
        "auto_update_disable" => hyperion_types::WpPluginAction::SetAutoUpdate { enabled: false },
        other => {
            return Err(AppError::BadRequest(format!(
                "unknown wp plugin action: {}",
                askama_escape::escape(other, askama_escape::Html)
            )));
        }
    };
    // slug is meaningless for `update_all` and `install` (the latter
    // gets the slug from `source`). For everything else it MUST validate.
    let slug = match &action {
        hyperion_types::WpPluginAction::UpdateAll => String::new(),
        hyperion_types::WpPluginAction::Install { source } => source.clone(),
        _ => {
            let s = form.slug.trim().to_string();
            if s.is_empty() {
                return Err(AppError::BadRequest("missing plugin slug".into()));
            }
            s
        }
    };
    // WordPress lives on the owning node — dispatch there (the plugin
    // LIST is already read from the owner). Master-local made every
    // plugin install/activate/update fail on worker-hosted sites, while
    // the sibling theme action worked.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::WpPluginAction { hosting: sel, slug, action },
    )
    .await?;
    match resp {
        RpcResponse::WpPluginAction(r) => {
            // Encode the state + a short message into the redirect so the
            // detail page can pop a toast on next render.
            let flash = format!(
                "Plugin {}: {}",
                r.state,
                r.message.chars().take(140).collect::<String>(),
            );
            let q = urlencoding(&flash);
            let key = if r.state == "ok" || r.state == "noop" {
                "flash"
            } else {
                "flash_error"
            };
            Ok(Redirect::to(&format!("/hostings/{}?{}={}#wp", sel_url, key, q)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&format!("Plugin action failed: {}", e));
            Ok(
                Redirect::to(&format!("/hostings/{}?flash_error={}#wp", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_wp_reset(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<WpResetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // WordPress lives on the owning node — dispatch there, not the
    // master local socket (NotFound for a worker-hosted site).
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::WpResetPassword {
            sel,
            wp_user: form.wp_user.trim().to_string(),
            new_password: form.new_password,
        },
    )
    .await?;
    match resp {
        RpcResponse::WpResetPassword => {
            Ok(Redirect::to(&format!("/hostings/{}?wp=reset", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?wp_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DbResetForm {
    pub selector: String,
    pub new_password: String,
}

pub async fn post_db_reset(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DbResetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // The database lives on the owning node — dispatch there.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::DbResetPassword {
            sel,
            new_password: form.new_password,
        },
    )
    .await?;
    match resp {
        RpcResponse::DbResetPassword => {
            Ok(Redirect::to(&format!("/hostings/{}?db=reset", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?db_error={}", sel_url, msg)).into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct FtpSetForm {
    pub selector: String,
    /// Empty → server generates one.
    #[serde(default)]
    pub new_password: String,
}

pub async fn post_ftp_set(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpSetForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // FTP account lives on the owning node — find it (mirrors
    // post_ftp_disable just below).
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::FtpSetPassword {
            sel,
            new_password: form.new_password,
        },
    )
    .await?;
    match resp {
        RpcResponse::FtpSetPassword { password } => {
            Ok(Redirect::to(&format!(
                "/hostings/{}?ftp=set&ftp_pw={}#settings",
                sel_url,
                urlencoding(&password)
            ))
            .into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?ftp_error={}#settings", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct FtpDisableForm {
    pub selector: String,
}

pub async fn post_ftp_disable(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpDisableForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // FTP account lives on the node owning the hosting — find it.
    let target_owned: Option<String> =
        find_hosting_anywhere(&state, sel.clone())
            .await
            .ok()
            .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::FtpDisable { sel },
    )
    .await?;
    match resp {
        RpcResponse::FtpDisable => {
            Ok(Redirect::to(&format!("/hostings/{}?ftp=disabled#settings", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?ftp_error={}#settings", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_restore(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RestoreForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // The backup archive + the hosting tree live on the owning node —
    // dispatch there (archive_path is the worker's local path).
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::BackupRestore {
            sel,
            archive_path: form.archive_path.trim().to_string(),
            mode: parse_restore_mode(&form.mode),
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupRestore => {
            Ok(Redirect::to(&format!("/hostings/{}?restore=ok", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?restore_error={}", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Stream a backup archive to the operator's browser as a download.
/// Pulls the file off the owning node in bounded chunks (so an archive
/// larger than MAX_FRAME still works) and pipes them straight to the
/// HTTP body via a tokio duplex pipe — never buffering the whole file
/// in the master's memory.
pub async fn get_backup_download(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path((selector, backup_id)): Path<(String, i64)>,
) -> Result<Response, AppError> {
    use base64::Engine;
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    if let Err(r) = require_hosting_access(&state, &ctx, detail.id.as_str(), false).await {
        return Ok(r);
    }
    // Metadata probe (len=0): total size + filename, and it validates
    // the backup belongs to a hosting + the path is under a backup root.
    let meta = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::BackupFetchChunk { backup_id, offset: 0, len: 0 },
    )
    .await?;
    let (total_size, filename) = match meta {
        RpcResponse::BackupFetchChunk { total_size, filename, .. } => (total_size, filename),
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };

    const CHUNK: u32 = 8 * 1024 * 1024;
    let (mut writer, reader) = tokio::io::duplex(CHUNK as usize);
    let task_state = state.clone();
    let task_owner = owner_node.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut offset: u64 = 0;
        loop {
            let resp = crate::dispatcher::dispatch_to_node(
                &task_state,
                task_owner.as_deref(),
                Request::BackupFetchChunk { backup_id, offset, len: CHUNK },
            )
            .await;
            let (data_b64, eof) = match resp {
                Ok(RpcResponse::BackupFetchChunk { data_b64, eof, .. }) => (data_b64, eof),
                // Error/abort → drop the writer; the client sees a
                // truncated download rather than a hung connection.
                _ => break,
            };
            let bytes = match base64::engine::general_purpose::STANDARD.decode(data_b64.as_bytes())
            {
                Ok(b) => b,
                Err(_) => break,
            };
            if !bytes.is_empty() && writer.write_all(&bytes).await.is_err() {
                break; // client disconnected
            }
            offset += bytes.len() as u64;
            if eof || bytes.is_empty() {
                break;
            }
        }
        // writer dropped here → reader observes EOF
    });

    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = axum::body::Body::from_stream(stream);
    let safe_name = filename.replace(['"', '\\', '\n', '\r'], "");
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/gzip".to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{safe_name}\""),
            ),
            (axum::http::header::CONTENT_LENGTH, total_size.to_string()),
        ],
        body,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct RestoreAsNewForm {
    pub selector: String,
    pub archive_path: String,
    pub new_domain: String,
}

/// Restore a backup archive into a brand-new hosting at a new domain.
/// Dispatched to the source's owning node (the new hosting is created
/// there). Long-running, but bounded — runs synchronously and redirects
/// to the new hosting on success.
pub async fn post_restore_as_new(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RestoreAsNewForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let new_domain = form.new_domain.trim().to_string();
    if new_domain.is_empty() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?restore_error={}#backups",
            sel_url,
            urlencoding("Enter a new domain for the restored copy.")
        ))
        .into_response());
    }
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target_owned.as_deref(),
        Request::BackupRestoreAsNew {
            sel,
            archive_path: form.archive_path.trim().to_string(),
            new_domain,
        },
    )
    .await?;
    match resp {
        RpcResponse::BackupRestoreAsNew { domain, .. } => Ok(Redirect::to(&format!(
            "/hostings/{}?created=1",
            urlencoding(&domain)
        ))
        .into_response()),
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?restore_error={}#backups", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct StagingForm {
    pub selector: String,
    /// Optional custom staging hostname typed on the create form.
    /// Empty/absent ⇒ fall back to the saved override or `staging.<domain>`.
    #[serde(default)]
    pub staging_domain: Option<String>,
}

/// Read a single panel-side metadata value from the master's hosting_kv
/// (keyed by ULID), returning `None` for missing or blank values.
async fn read_master_kv(state: &SharedState, hosting_id: &str, key: &str) -> Option<String> {
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingKvList { hosting_id: hosting_id.to_string() },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .filter(|s| !s.trim().is_empty()),
        _ => None,
    }
}

/// Create a staging.<domain> copy of a WordPress site.
pub async fn post_wp_staging_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<StagingForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // Effective staging hostname: the freshly-typed value wins; else the
    // saved per-hosting override; else None (the node uses staging.<domain>).
    let staging_override: Option<String> =
        match form.staging_domain.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => Some(s.to_ascii_lowercase()),
            None => read_master_kv(&state, &form.selector, "staging_domain").await,
        };
    let target: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::WpStagingCreate { sel, staging_domain: staging_override },
    )
    .await?;
    match resp {
        RpcResponse::WpStagingCreate { staging_domain } => {
            // Persist the hostname actually used so push + "Open staging"
            // stay consistent (panel-side metadata, master's hosting_kv).
            let _ = hyperion_rpc_client::call(
                &state.agent_socket,
                Request::HostingKvSet {
                    hosting_id: form.selector.clone(),
                    key: "staging_domain".into(),
                    value: staging_domain.clone(),
                },
            )
            .await;
            Ok(Redirect::to(&format!("/hostings/{}?created=1", urlencoding(&staging_domain)))
                .into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?staging_error={}#wordpress", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Push the staging copy back over production.
pub async fn post_wp_staging_push(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<StagingForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(&state, &ctx, &form.selector).await {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // Push must target the same staging hostname create used.
    let staging_override = read_master_kv(&state, &form.selector, "staging_domain").await;
    let target: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::WpStagingPush { sel, staging_domain: staging_override },
    )
    .await?;
    match resp {
        RpcResponse::WpStagingPush => {
            Ok(Redirect::to(&format!("/hostings/{}?staging=pushed#wordpress", sel_url))
                .into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(Redirect::to(&format!("/hostings/{}?staging_error={}#wordpress", sel_url, msg))
                .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
