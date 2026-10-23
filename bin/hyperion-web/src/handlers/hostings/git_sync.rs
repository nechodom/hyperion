//! Git deploy card and the GitHub webhook.

use super::*;

// ─────────────────────────── Git deploy ───────────────────────────

/// GitHub links for the configured repository, built once for the card.
pub(super) struct GitSyncRepoLinks {
    pub(super) slug: String,
    pub(super) web_url: String,
    pub(super) tree_url: String,
    pub(super) deploy_keys_url: String,
    pub(super) webhooks_url: String,
}

/// One line of the card's deploy history.
pub(super) struct GitSyncHistoryRow {
    pub(super) ok: bool,
    pub(super) commit: String,
    pub(super) message: String,
    pub(super) trigger: &'static str,
    pub(super) actor: String,
    pub(super) ago: String,
    pub(super) at_full: String,
}

#[derive(Template)]
#[template(path = "_hosting_gitsync_card.html")]
pub(super) struct GitSyncCardTpl {
    pub(super) selector: String,
    pub(super) view: hyperion_types::gitsync::GitSyncView,
    /// What the settings form shows: the saved config, or — after a refused
    /// save — what the operator typed, so nothing they entered is lost.
    pub(super) form: hyperion_types::gitsync::GitSyncConfig,
    pub(super) repo: Option<GitSyncRepoLinks>,
    pub(super) rows: Vec<GitSyncHistoryRow>,
    pub(super) can_manage: bool,
    pub(super) gs_csrf_config: String,
    pub(super) gs_csrf_genkey: String,
    pub(super) gs_csrf_sync: String,
    pub(super) gs_csrf_check: String,
    pub(super) gs_csrf_disconnect: String,
    pub(super) webhook_url: String,
    pub(super) last_ago: String,
    pub(super) notice: Option<String>,
    pub(super) error: Option<String>,
    pub(super) check: Option<hyperion_types::gitsync::GitSyncCheck>,
    /// Open the settings fold (a refused save re-renders with it open).
    pub(super) editing: bool,
}

/// What a card render carries beyond the node's view.
#[derive(Default)]
pub(super) struct GitSyncCardExtras {
    pub(super) notice: Option<String>,
    pub(super) error: Option<String>,
    pub(super) check: Option<hyperion_types::gitsync::GitSyncCheck>,
    /// The operator's refused input, to put back in the form.
    pub(super) form: Option<hyperion_types::gitsync::GitSyncConfig>,
}

/// The panel's own public origin as GitHub must POST to it. Reconstructed
/// from the request: the operator reached the panel at this address.
pub(super) fn gitsync_webhook_url(headers: &axum::http::HeaderMap, path: &str) -> String {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| {
            !h.is_empty()
                && h.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
                })
        })
        .unwrap_or("your-panel");
    format!("https://{host}{path}")
}

pub(super) fn gitsync_trigger_label(t: &str) -> &'static str {
    match t {
        "webhook" => "push",
        "manual" => "manual",
        _ => "deploy",
    }
}

pub(super) fn gitsync_card(
    state: &SharedState,
    ctx: &AuthCtx,
    headers: &axum::http::HeaderMap,
    selector: &str,
    view: hyperion_types::gitsync::GitSyncView,
    can_manage: bool,
    extras: GitSyncCardExtras,
) -> Response {
    let webhook_url = gitsync_webhook_url(headers, &view.webhook_path);
    let csrf = |path: &str| csrf_token_for(state, ctx, path);
    let tpl = gitsync_card_tpl(selector, view, can_manage, extras, webhook_url, csrf);
    Html(tpl.render().unwrap_or_default()).into_response()
}

/// The card's template, everything derived — split from [`gitsync_card`] so
/// the render tests need no session or router.
pub(super) fn gitsync_card_tpl(
    selector: &str,
    view: hyperion_types::gitsync::GitSyncView,
    can_manage: bool,
    extras: GitSyncCardExtras,
    webhook_url: String,
    csrf: impl Fn(&str) -> String,
) -> GitSyncCardTpl {
    let repo = hyperion_types::gitsync::parse_repo(&view.config.repo).map(|r| GitSyncRepoLinks {
        slug: r.slug(),
        web_url: r.https_url(),
        tree_url: r.tree_url(view.config.effective_branch()),
        deploy_keys_url: r.deploy_keys_url(),
        webhooks_url: r.webhooks_url(),
    });
    let history = if view.history.is_empty() && view.last.at > 0 {
        vec![view.last.clone()]
    } else {
        view.history.clone()
    };
    let rows = history
        .iter()
        .map(|h| GitSyncHistoryRow {
            ok: h.status == "ok",
            commit: h.commit.clone(),
            message: h.message.clone(),
            trigger: gitsync_trigger_label(&h.trigger),
            actor: h.actor.clone(),
            ago: crate::handlers::stats::fmt_ago(&h.at),
            at_full: chrono::DateTime::from_timestamp(h.at, 0)
                .filter(|_| h.at > 0)
                .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_default(),
        })
        .collect();
    let last_ago = if view.last.at > 0 {
        crate::handlers::stats::fmt_ago(&view.last.at)
    } else {
        String::new()
    };
    let editing = extras.form.is_some();
    GitSyncCardTpl {
        selector: selector.to_string(),
        form: extras.form.unwrap_or_else(|| view.config.clone()),
        webhook_url,
        gs_csrf_config: csrf("/hostings/gitsync/config"),
        gs_csrf_genkey: csrf("/hostings/gitsync/genkey"),
        gs_csrf_sync: csrf("/hostings/gitsync/sync"),
        gs_csrf_check: csrf("/hostings/gitsync/check"),
        gs_csrf_disconnect: csrf("/hostings/gitsync/disconnect"),
        repo,
        rows,
        last_ago,
        can_manage,
        view,
        notice: extras.notice,
        error: extras.error,
        check: extras.check,
        editing,
    }
}

/// Read the card's view from the OWNING node. `Err` is the sentence the card
/// shows instead.
pub(super) async fn gitsync_load(
    state: &SharedState,
    owner: Option<&str>,
    sel: HostingSelector,
) -> Result<hyperion_types::gitsync::GitSyncView, String> {
    match crate::dispatcher::dispatch_to_node(state, owner, Request::GitSyncView { sel }).await {
        Ok(RpcResponse::GitSyncView(v)) => Ok(v),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected response from the node".into()),
        Err(e) => Err(format!(
            "Could not read the deploy settings from the node ({e})."
        )),
    }
}

/// The text an RPC refusal shows on the card: a validation message as is,
/// anything else with what was being attempted.
pub(super) fn gitsync_rpc_error(doing: &str, e: &hyperion_rpc::RpcError) -> String {
    match e {
        hyperion_rpc::RpcError::Validation { message }
        | hyperion_rpc::RpcError::Conflict { message } => message.clone(),
        other => format!("{doing}: {other}"),
    }
}

/// Re-render the card after an action, reading the view fresh from the node.
pub(super) async fn gitsync_after(
    state: &SharedState,
    ctx: &AuthCtx,
    headers: &axum::http::HeaderMap,
    selector: &str,
    owner: Option<&str>,
    sel: HostingSelector,
    mut extras: GitSyncCardExtras,
) -> Response {
    match gitsync_load(state, owner, sel).await {
        Ok(view) => gitsync_card(state, ctx, headers, selector, view, true, extras),
        Err(e) => {
            extras.error = Some(extras.error.map_or(e.clone(), |x| format!("{x} {e}")));
            gitsync_card(
                state,
                ctx,
                headers,
                selector,
                Default::default(),
                true,
                extras,
            )
        }
    }
}

/// GET /hostings/:selector/gitsync-panel — the deploy card (config + status),
/// read from the OWNING node. Lazy-loaded, and polled while a deploy runs.
pub async fn get_gitsync_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let can_manage =
        require_manage_for_selector(&state, &ctx, &selector, Capability::HostingEditConfig)
            .await
            .is_ok();
    let fail = |msg: String| {
        gitsync_card(
            &state,
            &ctx,
            &headers,
            &selector,
            Default::default(),
            false,
            GitSyncCardExtras {
                error: Some(msg),
                ..Default::default()
            },
        )
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => return Ok(fail(e.to_string())),
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => return Ok(fail(e.to_string())),
    };
    if require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    .is_err()
    {
        return Ok(fail("You do not have access to this hosting.".into()));
    }
    match gitsync_load(&state, owner.as_deref(), sel).await {
        Ok(mut view) => {
            // The webhook secret lets anyone holding it trigger deploys. A
            // viewer can see the card, not take the secret off it.
            if !can_manage {
                view.webhook_secret.clear();
            }
            Ok(gitsync_card(
                &state,
                &ctx,
                &headers,
                &selector,
                view,
                can_manage,
                Default::default(),
            ))
        }
        Err(e) => Ok(fail(e)),
    }
}

#[derive(serde::Deserialize)]
pub struct GitSyncConfigForm {
    pub selector: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub subdir: String,
    #[serde(default)]
    pub auth: String,
    #[serde(default)]
    pub webhook_enabled: Option<String>,
    #[serde(default)]
    pub pat: String,
}

#[derive(serde::Deserialize)]
pub struct GitSyncForm {
    pub selector: String,
}

/// POST /hostings/gitsync/config — connect, or save changed settings.
/// Re-renders the card in place; a refusal keeps what was typed.
pub async fn post_gitsync_config(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<GitSyncConfigForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let auth = match form.auth.as_str() {
        "deploykey" | "pat" => form.auth.clone(),
        _ => "public".to_string(),
    };
    let config = hyperion_types::gitsync::GitSyncConfig {
        repo: form.repo.trim().to_string(),
        branch: form.branch.trim().to_string(),
        subdir: form.subdir.trim().to_string(),
        auth: auth.clone(),
        webhook_enabled: form.webhook_enabled.is_some(),
    };
    // Only touch the token when the operator typed one in the token mode; a
    // blank field keeps whatever is stored.
    let pat = if auth == "pat" && !form.pat.trim().is_empty() {
        Some(form.pat.clone())
    } else {
        None
    };
    let was_connected = match gitsync_load(&state, owner.as_deref(), sel.clone()).await {
        Ok(v) => v.config.is_configured(),
        Err(_) => false,
    };
    let extras = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::GitSyncConfigSet {
            sel: sel.clone(),
            config: config.clone(),
            pat,
        },
    )
    .await
    {
        Ok(RpcResponse::GitSyncAck) => GitSyncCardExtras {
            notice: Some(if was_connected {
                "Saved. The next deploy uses these settings.".into()
            } else if auth == "deploykey" {
                "Connected. Add the deploy key below to the repository on GitHub, then Test access."
                    .into()
            } else {
                "Connected. Test access, then Deploy now.".into()
            }),
            ..Default::default()
        },
        Ok(RpcResponse::Error(e)) => GitSyncCardExtras {
            error: Some(gitsync_rpc_error("Could not save", &e)),
            form: Some(config),
            ..Default::default()
        },
        Ok(_) => GitSyncCardExtras {
            error: Some("unexpected response from the node".into()),
            form: Some(config),
            ..Default::default()
        },
        Err(e) => GitSyncCardExtras {
            error: Some(format!("Could not save on the node ({e}).")),
            form: Some(config),
            ..Default::default()
        },
    };
    Ok(gitsync_after(
        &state,
        &ctx,
        &headers,
        &form.selector,
        owner.as_deref(),
        sel,
        extras,
    )
    .await)
}

/// POST /hostings/gitsync/genkey — generate (or replace) the deploy key.
pub async fn post_gitsync_genkey(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<GitSyncForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let extras = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::GitSyncGenerateKey { sel: sel.clone() },
    )
    .await
    {
        Ok(RpcResponse::GitSyncPubkey(_)) => GitSyncCardExtras {
            notice: Some(
                "New deploy key made. Add it to the repository on GitHub — the old one no longer works."
                    .into(),
            ),
            ..Default::default()
        },
        Ok(RpcResponse::Error(e)) => GitSyncCardExtras {
            error: Some(gitsync_rpc_error("Could not make a key", &e)),
            ..Default::default()
        },
        Ok(_) => GitSyncCardExtras {
            error: Some("unexpected response from the node".into()),
            ..Default::default()
        },
        Err(e) => GitSyncCardExtras {
            error: Some(format!("Could not make a key on the node ({e}).")),
            ..Default::default()
        },
    };
    Ok(gitsync_after(
        &state,
        &ctx,
        &headers,
        &form.selector,
        owner.as_deref(),
        sel,
        extras,
    )
    .await)
}

/// POST /hostings/gitsync/check — can the node read the branch? Changes
/// nothing; the answer renders in the Access row.
pub async fn post_gitsync_check(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<GitSyncForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let extras = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::GitSyncCheck { sel: sel.clone() },
    )
    .await
    {
        Ok(RpcResponse::GitSyncCheck(c)) => GitSyncCardExtras {
            check: Some(c),
            ..Default::default()
        },
        Ok(RpcResponse::Error(e)) => GitSyncCardExtras {
            error: Some(gitsync_rpc_error("Could not test access", &e)),
            ..Default::default()
        },
        Ok(_) => GitSyncCardExtras {
            error: Some("unexpected response from the node".into()),
            ..Default::default()
        },
        Err(e) => GitSyncCardExtras {
            error: Some(format!("Could not test access from the node ({e}).")),
            ..Default::default()
        },
    };
    Ok(gitsync_after(
        &state,
        &ctx,
        &headers,
        &form.selector,
        owner.as_deref(),
        sel,
        extras,
    )
    .await)
}

/// POST /hostings/gitsync/disconnect — stop deploying from GitHub. The
/// site's files stay as last deployed.
pub async fn post_gitsync_disconnect(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<GitSyncForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let extras = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::GitSyncDisconnect { sel: sel.clone() },
    )
    .await
    {
        Ok(RpcResponse::GitSyncAck) => GitSyncCardExtras {
            notice: Some(
                "Disconnected. The site keeps its files; remove the deploy key and webhook on GitHub too."
                    .into(),
            ),
            ..Default::default()
        },
        Ok(RpcResponse::Error(e)) => GitSyncCardExtras {
            error: Some(gitsync_rpc_error("Could not disconnect", &e)),
            ..Default::default()
        },
        Ok(_) => GitSyncCardExtras {
            error: Some("unexpected response from the node".into()),
            ..Default::default()
        },
        Err(e) => GitSyncCardExtras {
            error: Some(format!("Could not disconnect on the node ({e}).")),
            ..Default::default()
        },
    };
    Ok(gitsync_after(
        &state,
        &ctx,
        &headers,
        &form.selector,
        owner.as_deref(),
        sel,
        extras,
    )
    .await)
}

/// POST /hostings/gitsync/sync — deploy now, as a job.
pub async fn post_gitsync_now(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<GitSyncForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let (_, owner) = find_hosting_anywhere(&state, sel.clone()).await?;
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor = ctx.username.clone();
    let job_state = state.clone();
    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "gitsync_deploy",
        Some(&form.selector),
        "{}",
        &ctx.username,
        actor_uid,
        move |reporter| async move {
            reporter
                .step(
                    "Fetching the branch from GitHub and updating the webroot…",
                    20,
                    "",
                )
                .await;
            match crate::dispatcher::dispatch_to_node(
                &job_state,
                owner.as_deref(),
                Request::GitSyncNow {
                    sel,
                    trigger: "manual".into(),
                    actor,
                },
            )
            .await
            {
                Ok(RpcResponse::GitSyncLast(l)) => {
                    reporter
                        .step(&format!("Deployed {} — {}", l.commit, l.message), 100, "")
                        .await;
                    reporter.finish(true, None).await;
                }
                Ok(RpcResponse::Error(e)) => {
                    reporter
                        .finish(false, Some(gitsync_rpc_error("Deploy failed", &e)))
                        .await
                }
                Ok(_) => {
                    reporter
                        .finish(false, Some("unexpected agent response".into()))
                        .await
                }
                Err(e) => reporter.finish(false, Some(e.to_string())).await,
            }
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// POST /webhooks/git/:id — GitHub push webhook (PUBLIC: no session, no CSRF).
///
/// Authenticated by the per-hosting HMAC secret only. Verifies the signature,
/// checks the push is on the configured branch, then deploys in the background
/// so GitHub gets a fast answer.
pub async fn post_git_webhook(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    use axum::http::StatusCode;
    let sel = match parse_selector(&id) {
        Ok(s) => s,
        Err(_) => return (StatusCode::NOT_FOUND, "no such hosting").into_response(),
    };
    let Ok((_, owner)) = find_hosting_anywhere(&state, sel.clone()).await else {
        return (StatusCode::NOT_FOUND, "no such hosting").into_response();
    };
    let view = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::GitSyncView { sel: sel.clone() },
    )
    .await
    {
        Ok(RpcResponse::GitSyncView(v)) => v,
        _ => return (StatusCode::NOT_FOUND, "no such hosting").into_response(),
    };
    if !view.config.webhook_enabled || view.webhook_secret.is_empty() {
        return (StatusCode::NOT_FOUND, "auto-deploy is off").into_response();
    }
    let sig = headers
        .get("x-hub-signature-256")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !hyperion_types::gitsync::verify_webhook(&view.webhook_secret, &body, sig) {
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }
    let event = headers
        .get("x-github-event")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if event == "ping" {
        return (StatusCode::OK, "pong").into_response();
    }
    if event != "push" {
        return (StatusCode::OK, "ignored").into_response();
    }
    let want = format!("refs/heads/{}", view.config.effective_branch());
    let got = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("ref").and_then(|r| r.as_str()).map(String::from))
        .unwrap_or_default();
    if got != want {
        return (StatusCode::OK, "not the deploy branch").into_response();
    }
    // Fire and forget: the deploy is slow (a git clone); GitHub wants a fast
    // answer. The outcome is recorded on the node and shown in the card.
    let st = state.clone();
    tokio::spawn(async move {
        let _ = crate::dispatcher::dispatch_to_node(
            &st,
            owner.as_deref(),
            Request::GitSyncNow {
                sel,
                trigger: "webhook".into(),
                actor: String::new(),
            },
        )
        .await;
    });
    (StatusCode::ACCEPTED, "deploying").into_response()
}

#[cfg(test)]
mod gitsync_card_tests {
    use super::*;
    use hyperion_types::gitsync::{GitSyncCheck, GitSyncConfig, GitSyncLast, GitSyncView};

    fn connected(auth: &str) -> GitSyncView {
        GitSyncView {
            config: GitSyncConfig {
                repo: "https://github.com/acme/site".into(),
                branch: "main".into(),
                subdir: "public".into(),
                auth: auth.into(),
                webhook_enabled: true,
            },
            deploy_pubkey: "ssh-ed25519 AAAAPUBLIC hyperion@ex.cz".into(),
            webhook_secret: "s3cr3t-hook".into(),
            webhook_path: "/webhooks/git/h1".into(),
            git_available: true,
            ..Default::default()
        }
    }

    fn render(view: GitSyncView, can_manage: bool, extras: GitSyncCardExtras) -> String {
        gitsync_card_tpl(
            "h1",
            view,
            can_manage,
            extras,
            "https://panel.example/webhooks/git/h1".into(),
            |p| format!("tok:{p}"),
        )
        .render()
        .expect("gitsync card renders")
    }

    #[test]
    fn not_connected_offers_the_connect_form_and_nothing_else() {
        let html = render(GitSyncView::default(), true, Default::default());
        assert!(html.contains("not connected"));
        assert!(html.contains("Connect repository"));
        assert!(html.contains(r#"hx-post="/hostings/gitsync/config""#));
        assert!(
            !html.contains("/hostings/gitsync/sync"),
            "no deploy before a repo"
        );
        assert!(!html.contains("Disconnect"));
    }

    #[test]
    fn a_deployed_site_links_the_live_commit_and_lists_history() {
        let mut v = connected("public");
        let ok = GitSyncLast {
            at: 1_800_000_000,
            commit: "abc1234".into(),
            status: "ok".into(),
            message: "Ship the new header".into(),
            trigger: "webhook".into(),
            ..Default::default()
        };
        let failed = GitSyncLast {
            at: 1_799_999_000,
            status: "error".into(),
            message: "The repository has no branch named \"main\".".into(),
            trigger: "manual".into(),
            actor: "kevin".into(),
            ..Default::default()
        };
        v.last = ok.clone();
        v.history = vec![ok, failed];
        let html = render(v, true, Default::default());
        assert!(html.contains(r#"href="https://github.com/acme/site/commit/abc1234""#));
        assert!(html.contains("Ship the new header"));
        assert!(html.contains("Recent deploys (2)"));
        assert!(html.contains("· push"), "a webhook deploy reads as a push");
        assert!(html.contains("manual by kevin"));
        assert!(html.contains("folder <code>public/</code>"));
        // Not the first deploy any more: no "replace all files" dialog.
        assert!(
            !html.contains("Replace this site&#x27;s files?")
                && !html.contains("Replace this site's files?")
        );
    }

    #[test]
    fn the_first_deploy_asks_before_replacing_the_webroot() {
        let html = render(connected("public"), true, Default::default());
        assert!(html.contains("data-confirm-title=\"Replace this site"));
        assert!(html.contains("Not deployed yet"));
    }

    #[test]
    fn deploy_key_mode_shows_the_key_and_where_it_goes() {
        let html = render(connected("deploykey"), true, Default::default());
        assert!(html.contains("ssh-ed25519 AAAAPUBLIC hyperion@ex.cz"));
        assert!(html.contains("https://github.com/acme/site/settings/keys/new"));
        assert!(html.contains("Replace this key"));
    }

    #[test]
    fn webhook_secret_and_actions_are_for_managers_only() {
        let html = render(connected("deploykey"), false, Default::default());
        assert!(!html.contains("s3cr3t-hook"));
        assert!(!html.contains("/hostings/gitsync/sync"));
        assert!(!html.contains("/hostings/gitsync/check"));
        assert!(!html.contains("/hostings/gitsync/disconnect"));
        let html = render(connected("public"), true, Default::default());
        assert!(html.contains("s3cr3t-hook"));
        assert!(html.contains("https://panel.example/webhooks/git/h1"));
        assert!(html.contains("https://github.com/acme/site/settings/hooks/new"));
    }

    #[test]
    fn an_access_check_result_lands_in_the_access_row() {
        let ok = render(
            connected("public"),
            true,
            GitSyncCardExtras {
                check: Some(GitSyncCheck {
                    ok: true,
                    commit: "def5678".into(),
                    message: "This node can read acme/site and its branch main.".into(),
                    detail: String::new(),
                }),
                ..Default::default()
            },
        );
        assert!(ok.contains("chk-note tone-ok"));
        assert!(ok.contains("/commit/def5678"));
        let refused = render(
            connected("pat"),
            true,
            GitSyncCardExtras {
                check: Some(GitSyncCheck {
                    ok: false,
                    message: "GitHub refused the access token.".into(),
                    detail: "remote: Invalid username or token.".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert!(refused.contains("chk-note tone-err"));
        assert!(refused.contains("What git said"));
    }

    #[test]
    fn a_refused_save_keeps_what_was_typed_and_opens_the_settings() {
        let typed = GitSyncConfig {
            repo: "https://gitlab.com/acme/site".into(),
            branch: "prod".into(),
            auth: "pat".into(),
            ..Default::default()
        };
        let html = render(
            connected("public"),
            true,
            GitSyncCardExtras {
                error: Some("That is not a GitHub repository.".into()),
                form: Some(typed),
                ..Default::default()
            },
        );
        assert!(html.contains(r#"value="https://gitlab.com/acme/site""#));
        assert!(html.contains(r#"value="prod""#));
        assert!(html.contains(r#"<details class="chk-fold" open>"#));
        assert!(html.contains("That is not a GitHub repository."));
    }

    #[test]
    fn a_running_deploy_polls_only_while_visible() {
        let mut v = connected("public");
        v.running = true;
        let html = render(v, true, Default::default());
        assert!(html.contains("data-poll-visible"));
        assert!(html.contains(r#"hx-trigger="poll-tick""#));
        let idle = render(connected("public"), true, Default::default());
        assert!(!idle.contains("data-poll-visible"));
    }

    #[test]
    fn the_webhook_url_never_echoes_a_hostile_host_header() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::HOST,
            "evil.example\"><script>"
                .parse()
                .unwrap_or(axum::http::HeaderValue::from_static("x")),
        );
        assert_eq!(
            gitsync_webhook_url(&h, "/webhooks/git/h1"),
            "https://your-panel/webhooks/git/h1"
        );
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::HOST,
            "panel.example:8443".parse().unwrap(),
        );
        assert_eq!(
            gitsync_webhook_url(&h, "/webhooks/git/h1"),
            "https://panel.example:8443/webhooks/git/h1"
        );
    }
}
