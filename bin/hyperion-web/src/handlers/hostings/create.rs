//! The create wizard, the test-site form and the post-create background job.

use super::*;

#[derive(Template)]
#[template(path = "hostings_new.html")]
pub(super) struct NewTpl<'a> {
    pub(super) username: &'a str,
    pub(super) user_initial: char,
    pub(super) active: &'static str,
    pub(super) css_version: &'static str,
    pub(super) htmx_version: &'static str,
    pub(super) csrf_token: String,
    pub(super) error: Option<&'a str>,
    pub(super) domain_in: &'a str,
    pub(super) aliases_in: &'a str,
    /// "" = none/static, otherwise "8.1".."8.4"
    pub(super) php_in: String,
    /// "" = none, otherwise "mariadb"/"postgres"
    pub(super) db_in: String,
    /// "" = default php, otherwise echoes back kind selector
    #[allow(dead_code)]
    pub(super) kind_in: String,
    /// Type-first choice echoed back after a validation error so the
    /// selected "What do you want to create?" card stays highlighted.
    /// One of "" | "wordpress" | "php" | "static" | "reverse_proxy"
    /// | "redirect".
    pub(super) site_type_in: String,
    /// Echoed-back upstream URL when create failed and kind=reverse_proxy
    pub(super) proxy_upstream_url_in: String,
    /// Enrolled remote nodes (master excluded). When empty, the
    /// template hides the "Target node" dropdown and the hosting is
    /// provisioned on the master itself.
    pub(super) nodes: Vec<hyperion_types::NodeSummary>,
    /// Pre-selected target node when re-rendering after a validation
    /// error. Empty / "local" → master.
    pub(super) target_node_in: String,
    /// Echoes the [cluster] master_accepts_hostings setting from
    /// agent.toml. When false the template hides the master from
    /// the Target-node dropdown — operator turned the master into
    /// a control-plane-only node via Settings → Cluster →
    /// Placement.
    pub(super) master_accepts_hostings: bool,
    /// CSV of node ids flagged as test-only. JS uses this to know
    /// when to swap "Primary domain" for the "Test-site short name"
    /// field + render a preview from the template.
    pub(super) test_node_ids: String,
    /// Template for auto-generated test-site domains (e.g.
    /// "test.{name}.{node}.testovaciverze.cz"). Empty = feature off.
    pub(super) test_domain_template: String,
    /// All defined hosting profiles, so the wizard's step 1 can
    /// render a picker. Selecting one stamps the profile_id field
    /// in the form; post_create dispatches profile_apply after the
    /// hosting goes Active.
    pub(super) profiles: Vec<hyperion_types::HostingProfile>,
    /// A test site can be made (template + a test server) — shows the
    /// "Test website" card that leads to the one-screen form.
    pub(super) test_available: bool,
    /// The master's hostname, the `{node}` its test addresses use.
    pub(super) master_hostname: String,
}

/// `/hostings/new?test=1` — the one-screen test-site form. The operator
/// picks what to run and types a subdomain; the address comes from the
/// preview template, the server from the test-node list, and everything
/// else from the same defaults the wizard uses.
#[derive(Template)]
#[template(path = "hostings_new_test.html")]
pub(super) struct NewTestTpl<'a> {
    pub(super) username: &'a str,
    pub(super) user_initial: char,
    pub(super) active: &'static str,
    pub(super) css_version: &'static str,
    pub(super) htmx_version: &'static str,
    pub(super) csrf_token: String,
    pub(super) error: Option<&'a str>,
    pub(super) setup: TestSetup,
    /// What the operator typed/picked, echoed after a refused post.
    pub(super) input: TestFormIn,
    /// The id of the server card that starts selected: the posted one if it
    /// is still a test server, else the first.
    pub(super) selected_node: String,
    /// The user may install from the plugin library (profiles permission).
    pub(super) library_allowed: bool,
    /// Library plugins + themes to offer; empty when the library is empty
    /// or the user may not install from it.
    pub(super) library_plugins: Vec<hyperion_types::WpAssetSummary>,
    pub(super) library_themes: Vec<hyperion_types::WpAssetSummary>,
    /// Owner role: may mark a server as a test server on the Nodes page.
    pub(super) is_super_admin: bool,
}

/// The test form's fields as the operator left them.
#[derive(Default)]
pub(super) struct TestFormIn {
    pub(super) name: String,
    /// "" | "wordpress" | "static" | "php" | "reverse_proxy"
    pub(super) site_type: String,
    pub(super) target_node: String,
    pub(super) proxy_upstream_url: String,
    /// "Show in search engines?" — hidden unless they chose otherwise.
    pub(super) search_hidden: bool,
    /// WordPress fields (never the password).
    pub(super) wp: TestWpIn,
}

impl TestFormIn {
    pub(super) fn from_form(form: &CreateForm) -> Self {
        Self {
            name: form.test_site_name.trim().to_ascii_lowercase(),
            site_type: form.site_type.trim().to_string(),
            target_node: form.target_node.trim().to_string(),
            proxy_upstream_url: form.proxy_upstream_url.trim().to_string(),
            search_hidden: form.search_visibility.trim() != "visible",
            wp: TestWpIn::from_form(form),
        }
    }

    /// The site type card that starts selected.
    pub(super) fn is_type(&self, t: &str) -> bool {
        self.site_type == t || (self.site_type.is_empty() && t == "wordpress")
    }
}

/// Render `/hostings/new?test=1`, fresh or after a refused post.
pub(super) async fn render_test_form(
    state: &SharedState,
    ctx: &AuthCtx,
    csrf_token: String,
    error: Option<&str>,
    input: TestFormIn,
) -> Result<String, askama::Error> {
    let (setup, (library_plugins, library_themes)) =
        tokio::join!(fetch_test_setup(state), test_form_library(state, ctx));
    let selected_node = setup
        .targets
        .iter()
        .find(|t| t.node_id == input.target_node)
        .or_else(|| setup.targets.first())
        .map(|t| t.node_id.clone())
        .unwrap_or_default();
    NewTestTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "hostings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        csrf_token,
        error,
        setup,
        input,
        selected_node,
        library_allowed: ctx.can(Capability::ProfilesManage),
        library_plugins,
        library_themes,
        is_super_admin: ctx.is_super_admin(),
    }
    .render()
}

#[derive(Default)]
pub(super) struct TestWpIn {
    pub(super) admin_email: String,
    pub(super) title: String,
    pub(super) admin_user: String,
    pub(super) locale: String,
    /// Picked plugin ids, `,`-wrapped (",3,7,") so the template can ask
    /// `contains(",3,")` without a closure.
    pub(super) plugin_ids: String,
    pub(super) theme_id: i64,
}

impl TestWpIn {
    pub(super) fn from_form(form: &CreateForm) -> Self {
        let ids: Vec<String> = parse_asset_ids(&form.wp_plugin_assets)
            .unwrap_or_default()
            .iter()
            .map(i64::to_string)
            .collect();
        Self {
            admin_email: form.wp_admin_email.trim().to_string(),
            title: form.wp_title.trim().to_string(),
            admin_user: form.wp_admin_user.trim().to_string(),
            locale: form.wp_locale.trim().to_string(),
            plugin_ids: format!(",{},", ids.join(",")),
            theme_id: form.wp_theme_asset,
        }
    }

    pub(super) fn picked(&self, id: &i64) -> bool {
        self.plugin_ids.contains(&format!(",{id},"))
    }
}

/// The library split by kind for the test form, or nothing when this user
/// can't install from it.
pub(super) async fn test_form_library(
    state: &SharedState,
    ctx: &AuthCtx,
) -> (
    Vec<hyperion_types::WpAssetSummary>,
    Vec<hyperion_types::WpAssetSummary>,
) {
    if !ctx.can(Capability::ProfilesManage) {
        return (Vec::new(), Vec::new());
    }
    fetch_wp_assets(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .partition(|a| a.kind == "plugin")
}

/// The signed-in user's email, to prefill the WordPress admin address — the
/// welcome mail to `admin@<test subdomain>` would go nowhere.
pub(super) async fn session_user_email(state: &SharedState, ctx: &AuthCtx) -> String {
    let Some(uid) = ctx.session.as_ref().map(|s| s.user_id) else {
        return String::new();
    };
    match hyperion_rpc_client::call(&state.agent_socket, Request::WebUserGet { id: uid }).await {
        Ok(RpcResponse::WebUserGet(Some(u))) => u.email,
        _ => String::new(),
    }
}

#[derive(Deserialize, Default)]
pub struct NewQuery {
    /// `1` opens the one-screen test-site form instead of the wizard.
    #[serde(default)]
    pub(super) test: String,
}

pub async fn get_new(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<NewQuery>,
) -> Result<Response, AppError> {
    // Creating a new hosting is a cluster-scoped action. Tenant-
    // scoped roles (operator / customer / viewer) get bounced —
    // the post_create handler enforces this server-side anyway,
    // bouncing on GET avoids rendering the entire form just to
    // refuse the submit.
    if !ctx.can(Capability::HostingCreate) {
        return Err(AppError::Forbidden);
    }
    // Wildcard CSRF token so it also covers the DNS-preflight HTMX
    // button (form_id /hostings/dns-check-domain) in addition to the
    // main /hostings POST.
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    if q.test == "1" {
        let input = TestFormIn {
            search_hidden: true,
            wp: TestWpIn {
                admin_email: session_user_email(&state, &ctx).await,
                ..Default::default()
            },
            ..Default::default()
        };
        let html = render_test_form(&state, &ctx, csrf_token, None, input).await?;
        return Ok(no_store(Html(html).into_response()));
    }
    let test_setup = fetch_test_setup(&state).await;
    // Fetch enrolled remote nodes so the "Target node" dropdown can
    // offer them. Failure here just leaves the dropdown empty — the
    // form still works for the default-master case.
    let nodes = match fetch_remote_nodes(&state).await {
        // Drained nodes are left out: draining promises that no new site
        // is placed there, by the placer or by this form.
        Ok(v) => v.into_iter().filter(|n| !n.is_drained).collect(),
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
    let (master_hostname, cluster_cfg) = fetch_master_and_cluster(&state).await;
    let master_accepts_hostings = cluster_cfg.master_accepts_hostings;
    let tpl = NewTpl {
        test_available: test_setup.available(),
        master_hostname: master_hostname.clone(),
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "hostings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        csrf_token,
        error: None,
        domain_in: "",
        aliases_in: "",
        php_in: "8.3".to_string(),
        db_in: "mariadb".to_string(),
        kind_in: "php".to_string(),
        site_type_in: String::new(),
        proxy_upstream_url_in: String::new(),
        nodes,
        target_node_in: String::new(),
        master_accepts_hostings,
        // The master's option posts `local`; list it under that id too when
        // it is a test server, so the short-name field follows it.
        test_node_ids: if is_master_test(&cluster_cfg, &master_hostname) {
            format!("{},local", cluster_cfg.test_node_ids)
        } else {
            cluster_cfg.test_node_ids.clone()
        },
        test_domain_template: cluster_cfg.test_domain_template.clone(),
        profiles: fetch_all_profiles(&state).await.unwrap_or_default(),
    };
    Ok(no_store(Html(tpl.render()?).into_response()))
}

#[derive(Deserialize)]
pub struct CreateForm {
    pub(super) domain: String,
    #[serde(default)]
    pub(super) aliases: String,
    #[serde(default)]
    pub(super) php: String,
    #[serde(default)]
    pub(super) db: String,
    #[serde(default)]
    pub(super) system_user: String,
    /// "php" | "static" | "reverse_proxy" | "redirect" — defaults to "php".
    /// "redirect" is provisioned as a static hosting whose vhost is then set
    /// to a 301/302 redirect (no distinct backend kind exists).
    #[serde(default)]
    pub kind: String,
    /// Upstream URL when kind=reverse_proxy.
    #[serde(default)]
    pub proxy_upstream_url: String,
    /// Target URL when kind=redirect.
    #[serde(default)]
    pub redirect_url: String,
    /// 301 (permanent) or 302 (temporary); used when kind=redirect.
    #[serde(default)]
    pub redirect_code: i64,
    /// "on" to append the original request path to the redirect target.
    #[serde(default)]
    pub redirect_preserve_path: String,
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
    /// "1" when the post came from the one-screen test-site form
    /// (`/hostings/new?test=1`). The name is then required, and a refused
    /// post re-renders that form instead of the full wizard.
    #[serde(default)]
    pub test_mode: String,
    /// Library plugins to install (and activate) right after WordPress, as
    /// comma-joined `wp_assets` ids — one field, because axum's `Form` can't
    /// collect repeated keys.
    #[serde(default)]
    pub wp_plugin_assets: String,
    /// One library theme to install and activate after WordPress; 0 = keep
    /// the WordPress default.
    #[serde(default)]
    pub wp_theme_asset: i64,
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
    /// "on" when the operator ticked "Discourage search engines".
    #[serde(default)]
    pub wp_no_index: Option<String>,
    /// "hidden" | "visible" — the test form's explicit "show in search
    /// engines?" answer, for every site type. Wins over `wp_no_index` and the
    /// test-node policy, because the operator chose. Empty = the legacy
    /// behaviour (the wizard and the API don't send it).
    #[serde(default)]
    pub search_visibility: String,
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
    /// Type-first UI selection: one of "wordpress" | "php" | "static"
    /// | "reverse_proxy" | "redirect". When non-empty it is the
    /// AUTHORITATIVE source for the backend `kind` and whether
    /// WordPress installs — the redesigned create form drives one
    /// radio-backed choice card into this single field so the no-JS
    /// path submits a coherent intent without having to set `kind`
    /// and `install_wp` separately. When empty (the JSON API has its
    /// own struct, and the e2e form tests POST a flat field set), we
    /// fall back to the legacy `kind` + `install_wp` fields so those
    /// paths are untouched.
    #[serde(default)]
    pub site_type: String,
}

pub async fn post_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(mut form): Form<CreateForm>,
) -> Result<Response, AppError> {
    // Creating a new hosting is a cluster-scoped action — operators
    // with per-hosting grants can't conjure new sites into existence.
    if !ctx.can(Capability::HostingCreate) {
        return Err(AppError::Forbidden);
    }
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let plan = match plan_create(&state, &ctx, &mut form).await {
        Ok(plan) => plan,
        Err(msg) => return Ok(render_new_error(&state, &ctx, &csrf_token, &form, &msg).await),
    };
    // Loud breadcrumb so the operator can verify in journalctl which
    // node a create attempt was actually dispatched to. The dispatcher
    // also logs, but having both lets us tell apart "form submitted
    // local because dropdown wasn't rendered" (no log here with the
    // real intent) from "dispatcher overrode the choice" (logs differ).
    tracing::info!(
        operator = %ctx.username,
        domain = %plan.req.domain.as_str(),
        target_node_form_value = %plan.target_node,
        target_after_normalize = ?plan.target(),
        "post_create dispatch decision"
    );
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        plan.target(),
        Request::HostingCreate(plan.req.clone()),
    )
    .await?;
    match resp {
        RpcResponse::HostingCreate(created) => {
            finish_create(&state, &ctx, &form, plan, created).await
        }
        RpcResponse::Error(e) => {
            Ok(render_new_error(&state, &ctx, &csrf_token, &form, &format!("agent: {e}")).await)
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Everything `post_create` decided before anything exists: the request
/// the node gets, where it goes, and what to do once it is there.
pub(super) struct CreatePlan {
    pub(super) req: HostingCreateReq,
    /// The form's node choice after "auto" placement, as logged.
    pub(super) target_node: String,
    /// `None` = the master itself.
    target: Option<String>,
    /// The type-first card, lowercased ("" when the form predates it).
    site_type: String,
    is_redirect: bool,
    vhost_noindex: bool,
    wp_no_index: bool,
    library_picks: Vec<LibraryPick>,
}

impl CreatePlan {
    fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }
}

/// Validate the create form and decide the request. `Err` is the message
/// the re-rendered form shows; nothing has been created yet when it comes
/// back. The checks run in the order the operator would fix them.
async fn plan_create(
    state: &SharedState,
    ctx: &AuthCtx,
    form: &mut CreateForm,
) -> Result<CreatePlan, String> {
    let (master_hostname, cluster_cfg) = fetch_master_and_cluster(state).await;
    let target_is_test = is_test_target(&cluster_cfg, &master_hostname, &form.target_node);
    if form.test_mode == "1" {
        if !target_is_test {
            return Err("That server no longer takes test sites. Pick another one, or mark it as a test server on the Nodes page.".into());
        }
        if form.test_site_name.trim().is_empty() {
            return Err("Type the subdomain name for the test site.".into());
        }
        // The test form asks for nothing but the name. A PHP app gets the
        // runtime and database the wizard pre-selects; WordPress is
        // backfilled below; static and proxy need neither.
        if form.site_type == "php" {
            if form.php.is_empty() {
                form.php = "8.3".into();
            }
            if form.db.is_empty() {
                form.db = "mariadb".into();
            }
        }
    }
    let effective_domain =
        resolve_create_domain(state, form, &cluster_cfg, &master_hostname, target_is_test).await?;

    // ─── Type-first intent resolution ───────────────────────────
    // The redesigned create form drives a single radio-backed choice
    // card into `site_type`. When present it is AUTHORITATIVE for the
    // backend kind and whether WordPress installs, so the no-JS path
    // submits a coherent intent in one field instead of juggling
    // `kind` + `install_wp`. Empty → fall back to the legacy `kind`
    // field (the JSON API has its own struct and the flat-field e2e
    // form tests never send site_type, so both are unaffected).
    //   wordpress      → php + a database + WordPress install
    //   php            → php, no forced WP (DB optional via Advanced)
    //   static         → static files only
    //   reverse_proxy  → proxy to an upstream URL
    //   redirect       → 301/302 to a target URL (provisioned static)
    let site_type = form.site_type.trim().to_ascii_lowercase();
    let wp_from_type = site_type == "wordpress";
    let effective_kind: String = match site_type.as_str() {
        "wordpress" | "php" => "php".to_string(),
        "static" => "static".to_string(),
        "reverse_proxy" => "reverse_proxy".to_string(),
        "redirect" => "redirect".to_string(),
        // Empty or unrecognised → legacy `kind` field (unchanged).
        _ => form.kind.clone(),
    };

    let domain = Domain::parse(&effective_domain)
        .map_err(|e| e.to_string())?
        .without_www();
    let aliases = parse_aliases(&form.aliases)?;
    // WordPress needs a PHP runtime AND a database. When the operator
    // chose the WordPress card but left the runtime at its blank/none
    // default — the common path, and the old footgun where the agent
    // then refused the install — backfill a supported PHP version and
    // MariaDB here. An explicit Advanced-options value still wins.
    // For WordPress with no explicit PHP version, fall back to the
    // same "8.3" default get_new() renders; parse it through the real
    // validator (never expected to fail, but handled rather than
    // unwrapped so a future rename surfaces cleanly).
    let php_version = match choice_or_default(&form.php, wp_from_type, "8.3") {
        "" => None,
        v => Some(PhpVersion::from_str(v)?),
    };
    let database = match choice_or_default(&form.db, wp_from_type, "mariadb") {
        "" => None,
        v => Some(DbProvision::from_str(v)?),
    };
    let system_user = match form.system_user.trim() {
        "" => None,
        v => Some(SystemUserName::parse(v).map_err(|e| e.to_string())?),
    };
    // A "redirect" hosting has no distinct backend kind — it is provisioned
    // as a plain static site whose vhost we then switch to a 301/302 (applied
    // right after HostingCreate succeeds, in `finish_create`).
    let is_redirect = effective_kind == "redirect";
    // Search-engine visibility. `vhost_noindex` sends X-Robots-Tag from
    // nginx (any site type); `wp_no_index` also sets WordPress's own
    // blog_public = 0. An explicit answer decides both. Without one, the
    // wizard's "Discourage search engines" box does, and WordPress on a test
    // node follows the cluster's test-node policy as before.
    let (vhost_noindex, wp_no_index) = match form.search_visibility.trim() {
        "hidden" => (true, true),
        "visible" => (false, false),
        _ => {
            let ticked = form.wp_no_index.as_deref() == Some("on");
            (
                ticked,
                ticked || (target_is_test && cluster_cfg.test_wp_no_index),
            )
        }
    };
    let kind = if effective_kind == "reverse_proxy" {
        "reverse_proxy"
    } else if effective_kind == "static" || is_redirect {
        "static"
    } else {
        "php"
    };
    let proxy_upstream_url = if kind == "reverse_proxy" {
        let u = form.proxy_upstream_url.trim();
        if u.is_empty() {
            return Err("Reverse proxy requires an upstream URL.".into());
        }
        Some(u.to_string())
    } else {
        None
    };
    if is_redirect {
        let u = form.redirect_url.trim();
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return Err("Redirect requires a target URL starting with http:// or https://.".into());
        }
    }
    let req = HostingCreateReq {
        domain,
        aliases,
        php_version,
        database,
        system_user,
        kind: kind.to_string(),
        proxy_upstream_url,
    };
    let (target_node, target) = resolve_create_target(state, &form.target_node).await?;
    // Library plugins/themes picked on the form. Checked before anything is
    // created, so a bad pick refuses the form instead of leaving a site that
    // silently lacks what was asked for.
    let library_picks = resolve_library_picks(state, ctx, form, &site_type).await?;
    refuse_duplicate_domain(state, &req.domain).await?;
    Ok(CreatePlan {
        req,
        target_node,
        target,
        site_type,
        is_redirect,
        vhost_noindex,
        wp_no_index,
        library_picks,
    })
}

/// The form's runtime/database value, with "" and "none" meaning "not
/// chosen" — which the WordPress card fills with `wp_default`.
fn choice_or_default<'a>(raw: &'a str, wp_from_type: bool, wp_default: &'a str) -> &'a str {
    match raw {
        "" | "none" if wp_from_type => wp_default,
        "" | "none" => "",
        v => v,
    }
}

/// ─── Test-node short-name expansion ─────────────────────────
/// When the target is a test node + the operator filled the "Site name"
/// field, the final domain is synthesized from the cluster template instead
/// of the free-form domain field. Production targets keep the typed domain,
/// but neither side may borrow the other's names.
async fn resolve_create_domain(
    state: &SharedState,
    form: &CreateForm,
    cluster_cfg: &hyperion_types::ClusterConfigView,
    master_hostname: &str,
    target_is_test: bool,
) -> Result<String, String> {
    let typed = form.domain.trim().to_string();
    let short_name = form.test_site_name.trim();
    let template = &cluster_cfg.test_domain_template;
    if target_is_test && !short_name.is_empty() {
        if template.is_empty() {
            return Err("Target is a test node but no preview address template is set (Settings → HTTPS & previews → Preview address). Set one first.".into());
        }
        // Validate the short-name: lowercase alphanum + dash, no
        // leading / trailing dash, ≤ 32 chars. Keeps the derived
        // domain DNS-valid even with weird operator typos.
        let name = short_name.to_ascii_lowercase();
        if name.len() > 32
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            || name.starts_with('-')
            || name.ends_with('-')
        {
            return Err(
                "Site name must be 1–32 chars of a–z 0–9 -, no leading/trailing dash.".into(),
            );
        }
        // Resolve the target node's hostname (label) so `{node}`
        // expands to "s4" not "node_01kt9d6hrsbaw1pyzjdmwnmrhp" —
        // operator-friendly URL. The master renders with its own
        // hostname. Falls back to the long node_id when NodesList
        // lookup fails (rare).
        let (node_id, node_hostname) =
            test_render_identity(state, master_hostname, &form.target_node).await;
        return Ok(cluster_cfg.render_test_domain(&name, &node_id, &node_hostname));
    }
    if template.is_empty() {
        return Ok(typed);
    }
    // Sniff the suffix properly via `extract_test_suffix` — the previous
    // `rsplit_once('.')` was a bug: for template
    // `{name}.{node}.testovaciverze.cz` it returned `.cz` and blocked EVERY
    // .cz domain in the cluster.
    let suffix = extract_test_suffix(template);
    if suffix.is_empty() {
        return Ok(typed);
    }
    let in_test_space = typed
        .to_ascii_lowercase()
        .ends_with(&suffix.to_ascii_lowercase());
    if target_is_test && !in_test_space {
        // Operator picked a test node but didn't fill the short-name
        // field → the typed domain must match the template shape.
        return Err(format!(
            "Test-node hostings must end with `{suffix}` (per Settings → HTTPS & \
             previews → Preview address). Either pick a production node, fill the \
             short Site name field, or change the typed domain."
        ));
    }
    if !target_is_test && in_test_space {
        // Production target: refuse domains that match the test
        // template — operator probably mis-routed.
        return Err(format!(
            "Domain ends with `{suffix}` which is reserved for test nodes. \
             Either pick a test node or use a different domain."
        ));
    }
    Ok(typed)
}

/// Where the hosting goes: the form value after "auto" placement, and the
/// dispatch target (`None` = the master). Every downstream RPC for this
/// create (HostingCreate, the WP install, HostingGet, fetch_limits) must hit
/// the SAME node, otherwise the WP install would land on the master while
/// the hosting itself lives on a worker.
async fn resolve_create_target(
    state: &SharedState,
    form_value: &str,
) -> Result<(String, Option<String>), String> {
    let mut target_node = form_value.to_string();
    // "auto" is the auto-placement sentinel — pick the best-fit worker by
    // available capacity + load. Falls back to master if no online workers
    // are available + master_accepts_hostings is on.
    if target_node == "auto" {
        match pick_auto_placement_target(state).await {
            Some(picked) => {
                tracing::info!(picked = %picked, "auto-placement chose node");
                target_node = picked;
            }
            None if fetch_master_accepts_hostings(state).await => {
                target_node = crate::dispatcher::LOCAL_NODE_SENTINEL.to_string();
                tracing::info!("auto-placement: no workers, falling back to master");
            }
            None => {
                return Err("Auto-placement found no online workers and master is \
                     in control-plane-only mode. Enrol a worker or enable \
                     master hosting in Settings → Cluster → Placement."
                    .into());
            }
        }
    }
    let target = if target_node.is_empty() || target_node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(target_node.clone())
    };
    // Server-side enforcement of the cluster.master_accepts_hostings
    // toggle. UI hides the master option already (defense in depth)
    // but a hand-crafted POST with target_node=local would otherwise
    // bypass it.
    if target.is_none() && !fetch_master_accepts_hostings(state).await {
        return Err("Master is in control-plane-only mode (Settings → Cluster → Placement). Pick a worker node from the dropdown.".into());
    }
    Ok((target_node, target))
}

/// Server-side cluster-wide duplicate-domain guard. The wizard runs a
/// live /hostings/check-domain preflight, but that's advisory only — a
/// hand-crafted POST, a stale form, or two operators racing the same
/// domain would otherwise create duplicate vhosts on two nodes (nginx
/// server_name collision → whichever box DNS points at answers, the
/// other silently shadows, and certs/limits diverge). Mirrors
/// get_check_domain's primary-domain match. Fails OPEN on a list error: a
/// transient master-agent hiccup shouldn't block legitimate creates, and
/// the agent still rejects a same-node duplicate.
async fn refuse_duplicate_domain(state: &SharedState, domain: &Domain) -> Result<(), String> {
    match list_hostings(state).await {
        Ok(rows) => match rows
            .iter()
            .find(|r| r.domain.eq_ignore_ascii_case(domain.as_str()))
        {
            Some(dup) => {
                let where_ = match dup.node_id.as_deref() {
                    Some(crate::dispatcher::LOCAL_NODE_SENTINEL) | None => {
                        "the master node".to_string()
                    }
                    Some(n) => format!("node {n}"),
                };
                Err(format!(
                    "A hosting for {} already exists on {}. Pick a different domain.",
                    dup.domain, where_
                ))
            }
            None => Ok(()),
        },
        Err(e) => {
            tracing::warn!(error=%e, domain=%domain.as_str(),
                "post_create: cluster duplicate-domain check skipped (list failed) — proceeding");
            Ok(())
        }
    }
}

/// The hosting exists: switch on what the form asked for that creation
/// itself does not do, start the background setup, and render the new
/// hosting's detail page in place.
async fn finish_create(
    state: &SharedState,
    ctx: &AuthCtx,
    form: &CreateForm,
    plan: CreatePlan,
    mut created: HostingCreated,
) -> Result<Response, AppError> {
    let target = plan.target();
    if plan.is_redirect || plan.vhost_noindex {
        apply_initial_vhost_options(state, target, &created.id, form, &plan).await;
    }
    // ──────────────────────────────────────────────────────
    //  Profile-driven WP install detection.
    //
    //  When the operator picks a profile that includes WP
    //  plugins or themes, profile_apply would try to install
    //  them on a hosting that has no WordPress yet → every
    //  plugin install would fail silently and the operator
    //  would never see those plugins. So such a profile forces
    //  the WP install on (even from a hand-crafted POST) and the
    //  profile apply moves into the job, AFTER the install.
    // ──────────────────────────────────────────────────────
    let selected_profile: Option<HostingProfile> = if form.profile_id > 0 {
        fetch_all_profiles(state)
            .await
            .ok()
            .and_then(|profs| profs.into_iter().find(|p| p.id == form.profile_id))
    } else {
        None
    };
    let profile_forces_wp = selected_profile.as_ref().is_some_and(|p| {
        profile_has_meaningful_wp_content(&p.wp_plugins)
            || profile_has_meaningful_wp_content(&p.wp_themes)
    });
    // `site_type == "wordpress"` is the type-first "WordPress website" card:
    // it implies php + a database (backfilled in plan_create), so the
    // feasibility checks pass by construction. It is an independent signal
    // from the legacy install_wp checkbox so the no-JS card path installs
    // WordPress without that box.
    let wp_was_requested =
        form_flag_on(&form.install_wp) || profile_forces_wp || plan.site_type == "wordpress";
    let issue_cert_checked = form_flag_on(&form.issue_cert);
    let mut wp_install_error: Option<String> = None;
    // The previous synchronous path guarded the WP install by 4 conditions
    // and let EVERY failure land in a `tracing::warn!` — the operator saw a
    // clean hosting page and no clue WP wasn't installed. Now an infeasible
    // request is a visible flash, and a feasible one becomes a background
    // job with a live progress card.
    let mut wp_req: Option<hyperion_types::WpInstallRequest> = None;
    if wp_was_requested {
        match plan_wp_install(form, &plan.req, created.db.is_some(), plan.wp_no_index) {
            Ok((req, info)) => {
                wp_req = Some(req);
                // Show the credentials immediately on the detail page, even
                // though the install runs in the background — the operator
                // must save the password NOW (it's not stored in plaintext).
                created.wp = Some(info);
            }
            Err(msg) => wp_install_error = Some(msg),
        }
    }
    let job_installs_wp = wp_req.is_some();
    let mut wp_install_job_id: Option<String> = None;
    if job_installs_wp || issue_cert_checked {
        match spawn_post_create_job(
            state,
            ctx,
            &plan,
            &created.id,
            form.profile_id,
            issue_cert_checked,
            wp_req,
        )
        .await
        {
            Ok(id) => wp_install_job_id = Some(id),
            Err(e) => {
                wp_install_error = Some(format!(
                    "Could not start the post-create setup job: {e}. Issue the cert from the SSL tab / run WP install from the WordPress tab manually."
                ));
            }
        }
    }
    // The job applies the profile only when it installs WordPress
    // (plugins/themes need WP first). A cert-only job leaves the
    // profile to the synchronous branch — skipping it there too
    // meant the profile was never applied at all.
    let job_applies_profile = wp_install_job_id.is_some() && job_installs_wp;
    if !job_applies_profile && form.profile_id > 0 {
        if let Err(msg) = apply_profile_now(state, target, &created.id, form.profile_id).await {
            wp_install_error = Some(msg);
        }
    }

    // Announce the new site on Slack — AFTER the profile step, so the
    // message carries the price and the billing date rather than
    // "not set". When the background job owns the profile apply, the
    // job announces once it is done; announcing here would race it
    // and lose (the price snapshot isn't written yet).
    if !job_applies_profile {
        announce_hosting_created(state, target, &created.id).await;
    }

    // Re-fetch detail for nice display. Must go to the SAME
    // node we just provisioned on — otherwise the master
    // would return "no such hosting" because the row lives
    // on the remote node's state DB.
    let detail = match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::HostingGet(HostingSelector::Id(created.id.clone())),
    )
    .await?
    {
        RpcResponse::HostingGet(d) => d,
        _ => return Err(AppError::Internal("expected HostingGet".into())),
    };
    let limits = fetch_limits(state, target, HostingSelector::Id(created.id.clone()))
        .await
        .unwrap_or_else(|_| hyperion_types::HostingLimits::defaults());
    let preview_domain = compute_preview_domain(state, target, &detail.domain).await;
    let modsec = fetch_modsec_status(state, target).await;
    let wp_assets = fetch_wp_assets(state).await.unwrap_or_default();
    let base = DetailTpl::base(
        state,
        ctx,
        detail,
        limits,
        target.unwrap_or("").to_string(),
        preview_domain,
        modsec,
        wp_assets,
    );
    let tpl = DetailTpl {
        wp_error: wp_install_error,
        wp_flash: wp_install_job_id.as_ref().map(|_| {
            "Post-create setup kicked off in the background — live status above.".to_string()
        }),
        just_created: Some(created),
        wp_install_job_id,
        // The plugin list has not been fetched, so claim installed to keep
        // the prompt off a page that cannot know either way.
        redis_plugin_installed: true,
        ..base
    };
    Ok(Html(tpl.render()?).into_response())
}

/// A checkbox-ish form value: "on" from a browser, "true"/"1" from scripts.
fn form_flag_on(v: &str) -> bool {
    v.eq_ignore_ascii_case("on") || v == "true" || v == "1"
}

/// A "redirect" hosting was provisioned as a static site; switch its vhost
/// to the requested 301/302 now that it exists. Applied synchronously so the
/// operator lands on a working redirect, not a bare placeholder. A failure
/// here is non-fatal (the hosting still exists), so it is only logged.
///
/// "Hide from search engines" rides the same write. It starts from what the
/// node stored — its column defaults (cache TTL, redirect code) are not
/// `VhostOptions::default()`.
async fn apply_initial_vhost_options(
    state: &SharedState,
    target: Option<&str>,
    id: &hyperion_types::HostingId,
    form: &CreateForm,
    plan: &CreatePlan,
) {
    let mut options = match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::HostingGet(HostingSelector::Id(id.clone())),
    )
    .await
    {
        Ok(RpcResponse::HostingGet(d)) => d.vhost_options,
        _ => hyperion_types::VhostOptions::default(),
    };
    if plan.is_redirect {
        options.redirect_url = form.redirect_url.trim().to_string();
        options.redirect_code = if form.redirect_code == 302 { 302 } else { 301 };
        options.redirect_preserve_path = form.redirect_preserve_path.eq_ignore_ascii_case("on");
    }
    options.noindex = plan.vhost_noindex;
    match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::HostingSetVhostOptions {
            sel: HostingSelector::Id(id.clone()),
            options,
            basic_auth_password: None,
        },
    )
    .await
    {
        Ok(RpcResponse::HostingSetVhostOptions(_)) => {}
        Ok(RpcResponse::Error(e)) => {
            tracing::warn!(error = %e, "applying vhost options after create failed");
        }
        other => {
            tracing::warn!(
                ?other,
                "unexpected response applying vhost options after create"
            );
        }
    }
}

/// The WordPress install a create asked for, with missing credentials
/// filled in, or why it cannot run on this hosting. The operator picked
/// "install WP" — honor that intent and fill the blanks rather than
/// silently dropping the install.
pub(super) fn plan_wp_install(
    form: &CreateForm,
    req: &HostingCreateReq,
    has_db: bool,
    no_index: bool,
) -> Result<(WpInstallRequest, hyperion_rpc::wire::WpCreatedInfo), String> {
    if req.kind != "php" {
        return Err(format!(
            "WordPress install was requested but the hosting kind is `{}` — WP needs a PHP hosting. Recreate with the PHP runtime selected.",
            req.kind
        ));
    }
    if !has_db {
        return Err("WordPress install was requested but no database was provisioned. WP needs MariaDB — recreate with a database selected.".into());
    }
    let domain = req.domain.as_str();
    let admin_user = match form.wp_admin_user.trim() {
        "" => "admin".to_string(),
        v => v.to_string(),
    };
    if !is_valid_wp_username(&admin_user) {
        return Err(format!(
            "Admin username `{}` is not a valid WordPress username (letters, numbers, _, -, @, . only). Hosting was created — Re-run WP install from the WordPress tab once you've picked a valid name.",
            admin_user
        ));
    }
    let admin_email = match form.wp_admin_email.trim() {
        "" => format!("admin@{domain}"),
        v => v.to_string(),
    };
    let admin_password = if form.wp_admin_password.len() < 6 {
        generate_wp_admin_password()
    } else {
        form.wp_admin_password.clone()
    };
    let title = match form.wp_title.trim() {
        "" => domain.to_string(),
        v => v.to_string(),
    };
    let locale = match form.wp_locale.trim() {
        "" => "en_US".to_string(),
        v => v.to_string(),
    };
    let site_url = format!("https://{domain}");
    let info = hyperion_rpc::wire::WpCreatedInfo {
        admin_user: admin_user.clone(),
        admin_email: admin_email.clone(),
        admin_password: admin_password.clone(),
        admin_login_url: format!("{site_url}/wp-login.php"),
    };
    let req = WpInstallRequest {
        site_url,
        title,
        admin_user,
        admin_email,
        admin_password,
        locale,
        version: "latest".to_string(),
        // Either the operator asked for it on this site, or the
        // node-wide test-node policy does. Test nodes keep
        // forcing it: a throwaway staging copy must never be
        // indexable just because nobody remembered to tick a box.
        no_index,
    };
    Ok((req, info))
}

/// Start the post-create pipeline: LE cert and/or WP install (each
/// optional; the profile and library picks ride along with WP). Returns the
/// job id for the live progress card.
async fn spawn_post_create_job(
    state: &SharedState,
    ctx: &AuthCtx,
    plan: &CreatePlan,
    hosting_id: &hyperion_types::HostingId,
    profile_id: i64,
    issue_cert: bool,
    wp_req: Option<WpInstallRequest>,
) -> Result<String, AppError> {
    let installs_wp = wp_req.is_some();
    // Library picks only make sense once WordPress is in.
    let library = if installs_wp {
        plan.library_picks.clone()
    } else {
        Vec::new()
    };
    // Without WP, the profile (if any) is applied synchronously by
    // finish_create — don't double-apply it inside the job.
    let job_profile_id = if installs_wp { profile_id } else { 0 };
    let domain = plan.req.domain.as_str().to_string();
    let payload = serde_json::json!({
        "hosting_id": hosting_id.as_str(),
        "domain": domain,
        "issue_cert": issue_cert,
        "install_wp": installs_wp,
        "profile_id": job_profile_id,
        "library_assets": library.iter().map(|p| p.id).collect::<Vec<_>>(),
    });
    let job_state = state.clone();
    let target = plan.target.clone();
    let hosting_id = hosting_id.clone();
    crate::handlers::jobs::spawn_job(
        state.clone(),
        "post_create_setup",
        Some(plan.req.domain.as_str()),
        &payload.to_string(),
        &ctx.username,
        ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0),
        move |reporter| async move {
            run_post_create_job(
                reporter,
                job_state.clone(),
                target.clone(),
                hosting_id.clone(),
                domain,
                issue_cert,
                wp_req,
                job_profile_id,
                library,
            )
            .await;
            // This job applied the profile, so it announces — after the
            // price snapshot exists. Even a failed job announces: the
            // hosting exists either way.
            if installs_wp {
                announce_hosting_created(&job_state, target.as_deref(), &hosting_id).await;
            }
        },
    )
    .await
}

/// No WP install requested, but a profile WAS chosen — apply it now (likely
/// just PHP limits / expiry, since WP-content profiles go through the job).
/// Synchronous because there's no wp-cli I/O to wait on. The profile is
/// resolved on the master (master-only table) so the apply works even when
/// `target` is a worker. `Err` is the flash for the detail page.
async fn apply_profile_now(
    state: &SharedState,
    target: Option<&str>,
    id: &hyperion_types::HostingId,
    profile_id: i64,
) -> Result<(), String> {
    let resolved_profile = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::ProfileGet { id: profile_id },
    )
    .await
    {
        Ok(RpcResponse::ProfileGet(p)) => Some(p),
        _ => None,
    };
    let apply = crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::ProfileApply {
            sel: HostingSelector::Id(id.clone()),
            profile_id,
            skip_wp_items: false,
            profile: resolved_profile,
        },
    )
    .await;
    match apply {
        Ok(RpcResponse::Error(e)) => Err(format!(
            "Profile applied with errors: {e}. Hosting is alive — re-run from the Profile tab."
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "Profile apply RPC failed: {e}. Re-run from the Profile tab."
        )),
    }
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
pub(super) fn extract_test_suffix(template: &str) -> String {
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
pub(super) fn profile_has_meaningful_wp_content(list: &str) -> bool {
    for raw in list.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        return true;
    }
    false
}

pub(super) fn generate_wp_admin_password() -> String {
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

pub(super) fn is_valid_wp_username(s: &str) -> bool {
    if s.is_empty() || s.len() > 60 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'-' || bytes[0] == b'.' {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '@' || c == '-')
}

pub(super) async fn render_new_error(
    state: &SharedState,
    ctx: &AuthCtx,
    csrf_token: &str,
    form: &CreateForm,
    error: &str,
) -> Response {
    if form.test_mode == "1" {
        let html = render_test_form(
            state,
            ctx,
            csrf_token.to_string(),
            Some(error),
            TestFormIn::from_form(form),
        )
        .await
        .unwrap_or_else(|_| "<h1>render error</h1>".into());
        return Html(html).into_response();
    }
    let tpl = NewTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "hostings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        csrf_token: csrf_token.to_string(),
        error: Some(error),
        domain_in: &form.domain,
        aliases_in: &form.aliases,
        php_in: form.php.clone(),
        db_in: form.db.clone(),
        kind_in: form.kind.clone(),
        site_type_in: form.site_type.clone(),
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
        test_available: false,
        master_hostname: String::new(),
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
pub(super) async fn fetch_wp_assets(
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
pub(super) async fn fetch_master_accepts_hostings(state: &SharedState) -> bool {
    match crate::dispatcher::cached_agent_config(state)
        .await
        .map(|c| hyperion_rpc::codec::Response::AgentConfigView((*c).clone()))
    {
        Ok(RpcResponse::AgentConfigView(c)) => c.cluster.master_accepts_hostings,
        _ => true,
    }
}

/// Placeholder the test-site form's JS swaps for the typed name. Rendered
/// through the real template server-side, so the preview the operator sees
/// is the same string post_create will build — never JS template math.
pub(super) const TEST_NAME_TOKEN: &str = "__name__";

/// One server a test site can land on.
pub(crate) struct TestTarget {
    /// What the form posts as `target_node`: `local` for the master.
    pub node_id: String,
    pub label: String,
    /// Full address with `__name__` where the subdomain goes.
    pub pattern: String,
}

impl TestTarget {
    /// The address before the subdomain (usually empty).
    pub fn prefix(&self) -> &str {
        self.pattern
            .split_once(TEST_NAME_TOKEN)
            .map_or("", |(p, _)| p)
    }

    /// The address after the subdomain, e.g. `.s4.example.com`.
    pub fn suffix(&self) -> &str {
        self.pattern
            .split_once(TEST_NAME_TOKEN)
            .map_or(self.pattern.as_str(), |(_, s)| s)
    }
}

/// A server that takes sites but not test sites — listed on the test form
/// so "why can't I pick X?" has an answer on the page.
pub(crate) struct OtherServer {
    pub node_id: String,
    pub label: String,
}

/// Everything the test-site flow needs to know about the cluster.
pub(crate) struct TestSetup {
    pub template: String,
    pub targets: Vec<TestTarget>,
    pub others: Vec<OtherServer>,
}

impl TestSetup {
    /// A test site can be created at all: a template to build the address
    /// from, and at least one test server to put it on.
    pub fn available(&self) -> bool {
        !self.template.is_empty() && !self.targets.is_empty()
    }
}

/// Is `target_node` (as the create form posts it) a test server? The master
/// is posted as `local` but may sit in `test_node_ids` either as `local` (the
/// Nodes page writes that) or by its hostname — the id its own rows carry.
pub(super) fn is_test_target(
    cluster: &hyperion_types::ClusterConfigView,
    master_hostname: &str,
    target_node: &str,
) -> bool {
    let target = target_node.trim();
    if target.is_empty() || target == crate::dispatcher::LOCAL_NODE_SENTINEL {
        return is_master_test(cluster, master_hostname);
    }
    target != "auto" && cluster.is_test_node(target)
}

pub(crate) fn is_master_test(
    cluster: &hyperion_types::ClusterConfigView,
    master_hostname: &str,
) -> bool {
    cluster.is_test_node(crate::dispatcher::LOCAL_NODE_SENTINEL)
        || (!master_hostname.trim().is_empty() && cluster.is_test_node(master_hostname.trim()))
}

/// `(node_id, hostname)` to render the test template with for `target_node`.
/// The master renders with its hostname for both — that is the identity the
/// agent itself resolves the wildcard base with, so the address we build and
/// the wildcard that covers it come from the same string.
pub(super) async fn test_render_identity(
    state: &SharedState,
    master_hostname: &str,
    target_node: &str,
) -> (String, String) {
    let target = target_node.trim();
    if target.is_empty() || target == crate::dispatcher::LOCAL_NODE_SENTINEL {
        return (master_hostname.to_string(), master_hostname.to_string());
    }
    let label = fetch_remote_nodes(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|n| n.node_id == target)
        .map(|n| n.label)
        .unwrap_or_default();
    (target.to_string(), label)
}

/// The master's hostname plus the cluster section, from one cached read.
pub(super) async fn fetch_master_and_cluster(
    state: &SharedState,
) -> (String, hyperion_types::ClusterConfigView) {
    match crate::dispatcher::cached_agent_config(state).await {
        Ok(c) => (c.hostname.clone(), c.cluster.clone()),
        Err(_) => (String::new(), hyperion_types::ClusterConfigView::default()),
    }
}

/// Which servers take test sites, and what address each would give. The
/// master counts when it is marked as a test server and accepts sites;
/// drained workers are left out, same as for any new site.
pub(crate) async fn fetch_test_setup(state: &SharedState) -> TestSetup {
    let (master_hostname, cluster) = fetch_master_and_cluster(state).await;
    let template = cluster.test_domain_template.trim().to_string();
    let mut targets = Vec::new();
    let mut others = Vec::new();
    if template.is_empty() {
        return TestSetup {
            template,
            targets,
            others,
        };
    }
    if cluster.master_accepts_hostings {
        let label = if master_hostname.is_empty() {
            "This server".to_string()
        } else {
            master_hostname.clone()
        };
        let node_id = crate::dispatcher::LOCAL_NODE_SENTINEL.to_string();
        if is_master_test(&cluster, &master_hostname) {
            targets.push(TestTarget {
                node_id,
                label,
                pattern: cluster.render_test_domain(
                    TEST_NAME_TOKEN,
                    &master_hostname,
                    &master_hostname,
                ),
            });
        } else {
            others.push(OtherServer { node_id, label });
        }
    }
    for n in fetch_remote_nodes(state).await.unwrap_or_default() {
        if n.is_drained {
            continue;
        }
        if !cluster.is_test_node(&n.node_id) {
            others.push(OtherServer {
                node_id: n.node_id,
                label: n.label,
            });
            continue;
        }
        targets.push(TestTarget {
            pattern: cluster.render_test_domain(TEST_NAME_TOKEN, &n.node_id, &n.label),
            node_id: n.node_id,
            label: n.label,
        });
    }
    TestSetup {
        template,
        targets,
        others,
    }
}

/// Internal preview hostname for a hosting on its owner node, mirroring
/// the agent's vhost rule so the link we show always matches a server
/// block that actually exists. `None` ⇒ no preview link (no wildcard,
/// or the domain is already under it).
///
/// The wildcard base is resolved from the cluster `test_domain_template`
/// (master-local config) using the owner node's id + hostname label.
///
/// Cross-node accuracy: we don't have a dedicated "does node X carry a
/// wildcard for base B" RPC, so we reuse the existing per-node
/// `CertOverview` (dispatched to the OWNER node) and confirm a cert
/// whose `domain == base` exists there. By construction that base
/// hostname (a node's auto-subdomain parent) only ever receives the
/// `*.<base>` wildcard cert issued in Settings → HTTPS & previews →
/// Preview certificates, so a cert at that exact domain on
/// that node IS the wildcard. This is strictly more accurate than
/// assuming "test node ⇒ has wildcard" and needs no new RPC, schema,
/// or wire change.
/// Preview affordance for ONE hosting — shown on EVERY site's detail
/// page, not just those with a live wildcard.
///
/// The point of the struct (vs. the old bare `Option<String>`) is that a
/// missing preview is now explained in place instead of silently absent:
/// an operator who wanted a preview URL "for all sites" was seeing
/// nothing on a production site and reasonably concluded the feature was
/// test-only. It never was — every site gets a preview once the node has
/// a `*.<base>` wildcard. The card now says exactly which of the two
/// setup steps is missing.
#[derive(Default)]
pub(crate) struct PreviewInfo {
    /// The live preview hostname, when the wildcard exists. Empty ⇒ not
    /// available yet; `reason`/`base` explain why.
    pub url: String,
    /// The base a wildcard would need (`hosting.nechodom.cz`), when a
    /// template is configured. Empty ⇒ no template set.
    pub base: String,
    /// "" (available) | "no-template" (previews not set up on this node)
    /// | "no-wildcard" (template set, cert not issued) | "under-base"
    /// (this domain is already under the wildcard, so it needs no second
    /// address).
    pub reason: String,
}

impl PreviewInfo {
    pub fn available(&self) -> bool {
        !self.url.is_empty()
    }
}

pub(crate) async fn compute_preview_domain(
    state: &SharedState,
    owner_node: Option<&str>,
    primary_domain: &str,
) -> PreviewInfo {
    // Full config view, not just .cluster: the MASTER's hostname lives
    // here, and it is the `{node}` token for master-hosted sites. The
    // previous code looked the master up in the REMOTE node list — where
    // it never appears — so `{node}` rendered empty, the base derived to
    // nothing, and every master-hosted site reported "previews not set
    // up" while the Settings page, using the same template plus the
    // hostname it DID have, had issued a perfectly valid wildcard. Same
    // template, two different answers, one missing hostname.
    let (master_hostname, cluster) = match crate::dispatcher::cached_agent_config(state)
        .await
        .map(|c| hyperion_rpc::codec::Response::AgentConfigView((*c).clone()))
    {
        Ok(RpcResponse::AgentConfigView(c)) => (c.hostname.clone(), c.cluster),
        _ => (String::new(), hyperion_types::ClusterConfigView::default()),
    };
    // Owner node id + its hostname label (so `{node}` → "s4", not the
    // long node_id). Empty node_id ⇒ master / local.
    let node_id = owner_node.unwrap_or("").to_string();
    let node_hostname = if node_id.is_empty() {
        master_hostname
    } else {
        fetch_remote_nodes(state)
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|n| n.node_id == node_id)
            .map(|n| n.label)
            .unwrap_or_default()
    };
    // No template configured on this node ⇒ previews aren't set up at all.
    let Some(base) = cluster.node_wildcard_base(&node_id, &node_hostname) else {
        return PreviewInfo {
            reason: "no-template".into(),
            ..Default::default()
        };
    };
    // Sibling domains on the owner node, so the dedup rule here matches
    // the vhost the agent wrote (same rule, same input → same name).
    let siblings: Vec<String> =
        match crate::dispatcher::dispatch_to_node(state, owner_node, Request::HostingList).await {
            Ok(RpcResponse::HostingList(v)) => v
                .into_iter()
                .map(|h| h.domain)
                .filter(|d| !d.eq_ignore_ascii_case(primary_domain))
                .collect(),
            _ => Vec::new(),
        };
    // server_name derivation + the "already under base?" skip live in the
    // shared helper, so the URL here can't diverge from the agent's vhost.
    // `None` here means the domain is ALREADY under the wildcard — it is
    // reachable on the wildcard directly, no second address needed.
    let Some(server_name) = hyperion_types::ClusterConfigView::preview_subdomain_dedup(
        primary_domain,
        &base,
        &siblings,
    ) else {
        return PreviewInfo {
            base,
            reason: "under-base".into(),
            ..Default::default()
        };
    };
    // Confirm the wildcard cert actually exists on the owner node.
    let resp = crate::dispatcher::dispatch_to_node(state, owner_node, Request::CertOverview).await;
    let has_wildcard = matches!(
        resp,
        Ok(RpcResponse::CertOverview(ref items))
            if items.iter().any(|c| c.domain.eq_ignore_ascii_case(&base))
    );
    if has_wildcard {
        PreviewInfo {
            url: server_name,
            base,
            reason: String::new(),
        }
    } else {
        // Template set, but the *.<base> wildcard has not been issued —
        // the one remaining step, the same for every site on the node.
        PreviewInfo {
            base,
            reason: "no-wildcard".into(),
            ..Default::default()
        }
    }
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
    if !ctx.can(Capability::HostingCreate) {
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
            return axum::Json(serde_json::json!({"exists": false, "checked": false}))
                .into_response();
        }
    };
    let hit = rows.iter().find(|r| r.domain.eq_ignore_ascii_case(&needle));
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

/// Run the migration in the background, ticking progress at each
/// phase boundary so the operator's progress bar advances in
/// readable jumps (Export 25% → Bundle 45% → Import 80% → Suspend
/// 95% → Done 100%). Always calls `.finish()` exactly once — even
/// on early bailout — so the row never gets stuck in `running`.
/// A plugin or theme from the WP asset library, to install after WordPress.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LibraryPick {
    pub id: i64,
    /// "plugin" | "theme"
    pub kind: String,
    pub name: String,
}

/// Parse `wp_plugin_assets` ("3,7, 12") into ids. Garbage is an error, not a
/// silent skip — a site missing a plugin someone ticked is worse than a
/// refused form. Duplicates collapse; the order the operator saw is kept.
pub(super) fn parse_asset_ids(csv: &str) -> Result<Vec<i64>, String> {
    let mut ids: Vec<i64> = Vec::new();
    for part in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let id: i64 = part
            .parse()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| format!("`{part}` is not a library item id."))?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    if ids.len() > MAX_LIBRARY_PICKS {
        return Err(format!(
            "Pick at most {MAX_LIBRARY_PICKS} library plugins at once."
        ));
    }
    Ok(ids)
}

pub(super) const MAX_LIBRARY_PICKS: usize = 30;

/// Match the picked ids against the library: each must exist and be of the
/// kind its field asked for (plugins in the plugin list, a theme in the theme
/// field). Plugins first, then the theme, so the theme activates last.
pub(super) fn match_library_picks(
    plugin_ids: &[i64],
    theme_id: i64,
    library: &[hyperion_types::WpAssetSummary],
) -> Result<Vec<LibraryPick>, String> {
    let find = |id: i64, kind: &str| -> Result<LibraryPick, String> {
        let a = library
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("Library item {id} no longer exists — reload the form."))?;
        if a.kind != kind {
            return Err(format!(
                "\"{}\" in the library is a {}, not a {kind}.",
                a.original_name, a.kind
            ));
        }
        Ok(LibraryPick {
            id,
            kind: a.kind.clone(),
            name: a.original_name.clone(),
        })
    };
    let mut out = Vec::with_capacity(plugin_ids.len() + 1);
    for &id in plugin_ids {
        out.push(find(id, "plugin")?);
    }
    if theme_id > 0 {
        out.push(find(theme_id, "theme")?);
    }
    Ok(out)
}

/// Resolve the form's library picks, or say why they can't be honoured.
/// Installing from the library needs the same right as the WordPress tab's
/// "Install from library" (profiles) and a WordPress site. Any server will
/// do: a worker gets the master's copy of each ZIP right before the install
/// (see `crate::wp_library`).
pub(super) async fn resolve_library_picks(
    state: &SharedState,
    ctx: &AuthCtx,
    form: &CreateForm,
    site_type: &str,
) -> Result<Vec<LibraryPick>, String> {
    let plugin_ids = parse_asset_ids(&form.wp_plugin_assets)?;
    if plugin_ids.is_empty() && form.wp_theme_asset <= 0 {
        return Ok(Vec::new());
    }
    if !ctx.can(Capability::ProfilesManage) {
        return Err("Installing from the plugin library needs the profiles permission.".into());
    }
    if site_type != "wordpress" {
        return Err("Library plugins and themes need a WordPress site.".into());
    }
    let library = fetch_wp_assets(state)
        .await
        .map_err(|e| format!("Couldn't read the plugin library: {e}"))?;
    match_library_picks(&plugin_ids, form.wp_theme_asset, &library)
}

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
/// Post the one-time "new hosting" Slack message. Idempotent on the node
/// side (hosting_kv marker), so a retried create cannot announce twice.
/// Best-effort: a Slack outage must not fail a provision that succeeded.
pub(super) async fn announce_hosting_created(
    state: &SharedState,
    target: Option<&str>,
    id: &hyperion_types::HostingId,
) {
    if let Err(e) = crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::HostingAnnounceCreated {
            sel: HostingSelector::Id(id.clone()),
        },
    )
    .await
    {
        tracing::warn!(error = %e, "new-hosting Slack announcement failed");
    }
}

pub(super) async fn run_post_create_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    target_node: Option<String>,
    hosting_id: hyperion_types::HostingId,
    domain: String,
    issue_cert: bool,
    wp_req: Option<hyperion_types::WpInstallRequest>,
    profile_id: i64,
    library: Vec<LibraryPick>,
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
                    .step(
                        "Certificate issuance failed — continuing",
                        30,
                        "✗ cert: unexpected response\n",
                    )
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
                reporter
                    .finish(false, Some(deferred_failures.join("\n")))
                    .await;
                return;
            }
            Ok(other) => {
                deferred_failures.push(format!(
                    "WordPress install returned an unexpected RPC variant ({other:?}). Re-run from the WordPress tab."
                ));
                reporter
                    .finish(false, Some(deferred_failures.join("\n")))
                    .await;
                return;
            }
            Err(e) => {
                deferred_failures.push(format!(
                    "WordPress install RPC failed (couldn't reach the agent): {e}. Re-run from the WordPress tab."
                ));
                reporter
                    .finish(false, Some(deferred_failures.join("\n")))
                    .await;
                return;
            }
        }

        // ── Phase 3: profile (plugins/themes ride with WP) ───
        // Shares the 70–95% band with the library phase when both run.
        let profile_span = if library.is_empty() { 25 } else { 12 };
        if profile_id > 0 {
            if let Err(msg) = run_profile_apply_phase(
                &reporter,
                &state,
                target,
                &hosting_id,
                profile_id,
                70,
                profile_span,
                None,
            )
            .await
            {
                deferred_failures.push(msg);
                reporter
                    .finish(false, Some(deferred_failures.join("\n")))
                    .await;
                return;
            }
        }

        // ── Phase 4: plugins/themes picked from the library ──
        // A failed item doesn't stop the rest; they're reported together.
        let (base, span) = if profile_id > 0 { (82, 13) } else { (70, 25) };
        let total = library.len() as i64;
        for (idx, pick) in library.iter().enumerate() {
            reporter
                .step(
                    &format!(
                        "Installing {} {}/{} from the library: {}",
                        pick.kind,
                        idx + 1,
                        total,
                        pick.name
                    ),
                    base + (idx as i64) * span / total.max(1),
                    "",
                )
                .await;
            let resp = crate::dispatcher::dispatch_to_node(
                &state,
                target,
                Request::WpInstallFromAsset {
                    sel: HostingSelector::Id(hosting_id.clone()),
                    asset_id: pick.id,
                    activate: true,
                },
            )
            .await;
            let line = match resp {
                Ok(RpcResponse::WpInstallFromAsset { .. }) => {
                    format!("✓ {} installed and activated\n", pick.name)
                }
                Ok(RpcResponse::Error(e)) => {
                    deferred_failures.push(format!(
                        "Library {} \"{}\" failed: {e}. Install it from the WordPress tab.",
                        pick.kind, pick.name
                    ));
                    format!("✗ {}: {e}\n", pick.name)
                }
                Ok(other) => {
                    deferred_failures.push(format!(
                        "Library {} \"{}\" returned an unexpected response ({other:?}).",
                        pick.kind, pick.name
                    ));
                    format!("✗ {}: unexpected response\n", pick.name)
                }
                Err(e) => {
                    deferred_failures.push(format!(
                        "Library {} \"{}\" couldn't reach the agent: {e}. Install it from the WordPress tab.",
                        pick.kind, pick.name
                    ));
                    format!("✗ {}: {e}\n", pick.name)
                }
            };
            reporter
                .step(
                    &format!("Library {} {}/{}", pick.kind, idx + 1, total),
                    base + ((idx as i64) + 1) * span / total.max(1),
                    &line,
                )
                .await;
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
    // The resolved profile, when the caller already has it (re-apply-to-all
    // fetches it ONCE for the whole batch instead of once per site). `None` ⇒
    // fetch it here, as the single-apply path does.
    prefetched: Option<hyperion_types::HostingProfile>,
) -> Result<(), String> {
    reporter
        .step(
            "Applying profile limits + expiry + pricing",
            pct_base,
            "profile_apply — PHP limits, expiry policy, price snapshot…\n",
        )
        .await;
    // Resolve the profile on the master (hosting_profiles is master-only) and
    // pass it inline, so the apply works even when the hosting lives on a
    // worker (which has no profiles in its own DB). Reused below for WP items.
    let profile = match prefetched {
        Some(p) => p,
        None => match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::ProfileGet { id: profile_id },
        )
        .await
        {
            Ok(RpcResponse::ProfileGet(p)) => p,
            _ => {
                return Err(
                    "Couldn't read the profile from the master — re-run from the Profile tab."
                        .to_string(),
                )
            }
        },
    };
    let apply = crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::ProfileApply {
            sel: HostingSelector::Id(hosting_id.clone()),
            profile_id,
            skip_wp_items: true,
            profile: Some(profile.clone()),
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

    // `profile` was already fetched from the master above (and passed inline to
    // the apply); reuse it for the plugin/theme line list.
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
pub(super) fn profile_wp_lines(
    plugins_text: &str,
    themes_text: &str,
) -> Vec<(&'static str, String)> {
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

#[cfg(test)]
mod test_target_tests {
    use super::{is_master_test, is_test_target, TEST_NAME_TOKEN};
    use hyperion_types::ClusterConfigView;

    fn cfg(ids: &str) -> ClusterConfigView {
        ClusterConfigView {
            test_node_ids: ids.into(),
            test_domain_template: "{name}.{node}.example.com".into(),
            ..Default::default()
        }
    }

    #[test]
    fn master_is_test_when_listed_as_local_or_by_hostname() {
        assert!(is_master_test(&cfg("local"), "s4"));
        assert!(is_master_test(&cfg("node_a,s4"), "s4"));
        assert!(!is_master_test(&cfg("node_a"), "s4"));
        // An unknown hostname must not match an empty CSV entry.
        assert!(!is_master_test(&cfg("node_a"), ""));
    }

    #[test]
    fn local_and_empty_targets_mean_the_master() {
        let c = cfg("local");
        assert!(is_test_target(&c, "s4", "local"));
        assert!(is_test_target(&c, "s4", ""));
        assert!(!is_test_target(&c, "s4", "node_a"));
        // Auto-placement is never a test target, whatever the CSV says.
        assert!(!is_test_target(&cfg("auto,local"), "s4", "auto"));
    }

    #[test]
    fn worker_targets_follow_the_csv() {
        let c = cfg("node_a");
        assert!(is_test_target(&c, "s4", "node_a"));
        assert!(!is_test_target(&c, "s4", "node_b"));
        assert!(!is_test_target(&c, "s4", "local"));
    }

    #[test]
    fn preview_pattern_is_the_real_template_with_a_slot() {
        // The test form's JS swaps the token for the typed name; the
        // token must survive the template's lowercasing untouched.
        let p = cfg("local").render_test_domain(TEST_NAME_TOKEN, "s4", "s4");
        assert_eq!(p, "__name__.s4.example.com");
        assert_eq!(
            p.replace(TEST_NAME_TOKEN, "blog"),
            cfg("local").render_test_domain("blog", "s4", "s4")
        );
    }
}

#[cfg(test)]
mod library_pick_tests {
    use super::{match_library_picks, parse_asset_ids, LibraryPick, MAX_LIBRARY_PICKS};
    use hyperion_types::WpAssetSummary;

    fn asset(id: i64, kind: &str, name: &str) -> WpAssetSummary {
        WpAssetSummary {
            id,
            kind: kind.into(),
            original_name: name.into(),
            size_bytes: 0,
            sha256: String::new(),
            uploaded_at: 0,
            uploaded_by: String::new(),
            profile_refs: 0,
            install_count: 0,
        }
    }

    #[test]
    fn ids_parse_dedupe_and_keep_order() {
        assert_eq!(parse_asset_ids("").unwrap(), Vec::<i64>::new());
        assert_eq!(parse_asset_ids(" 7, 3,,7 ,12").unwrap(), vec![7, 3, 12]);
    }

    #[test]
    fn garbage_ids_refuse_instead_of_skipping() {
        assert!(parse_asset_ids("3,abc").is_err());
        assert!(parse_asset_ids("0").is_err());
        assert!(parse_asset_ids("-4").is_err());
        let many: Vec<String> = (1..=(MAX_LIBRARY_PICKS as i64 + 1))
            .map(|i| i.to_string())
            .collect();
        assert!(parse_asset_ids(&many.join(",")).is_err());
    }

    #[test]
    fn picks_match_the_library_plugins_first_theme_last() {
        let lib = vec![
            asset(1, "plugin", "seo.zip"),
            asset(2, "theme", "astra.zip"),
            asset(3, "plugin", "forms.zip"),
        ];
        let picks = match_library_picks(&[3, 1], 2, &lib).unwrap();
        let names: Vec<&str> = picks.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["forms.zip", "seo.zip", "astra.zip"]);
        assert_eq!(
            picks[2],
            LibraryPick {
                id: 2,
                kind: "theme".into(),
                name: "astra.zip".into()
            }
        );
    }

    #[test]
    fn wrong_kind_or_missing_item_refuses() {
        let lib = vec![
            asset(1, "plugin", "seo.zip"),
            asset(2, "theme", "astra.zip"),
        ];
        // A theme ticked as a plugin, a plugin chosen as the theme.
        assert!(match_library_picks(&[2], 0, &lib).is_err());
        assert!(match_library_picks(&[], 1, &lib).is_err());
        // Deleted from the library since the form was rendered.
        assert!(match_library_picks(&[9], 0, &lib).is_err());
        assert!(match_library_picks(&[], 0, &lib).unwrap().is_empty());
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

#[cfg(test)]
mod profile_helper_tests {
    use super::{generate_wp_admin_password, profile_has_meaningful_wp_content};

    #[test]
    fn meaningful_wp_content_finds_plugins() {
        assert!(profile_has_meaningful_wp_content("akismet"));
        assert!(profile_has_meaningful_wp_content("yoast-seo!"));
        assert!(profile_has_meaningful_wp_content("@asset:42"));
        assert!(profile_has_meaningful_wp_content(
            "  contact-form-7\n  classic-editor"
        ));
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
            assert!(
                !p.chars()
                    .any(|c| c == '0' || c == 'O' || c == '1' || c == 'l' || c == 'I'),
                "password contains visually-ambiguous char: {p:?}"
            );
        }
    }
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
