//! FTP and SFTP cards: passwords, extra accounts, FTPS, repair.

use super::*;

#[derive(Template)]
#[template(path = "_hosting_ftp_card.html")]
pub(super) struct FtpCardTpl {
    pub(super) report: hyperion_types::FtpCheckReport,
    pub(super) selector: String,
    pub(super) csrf_repair: String,
    pub(super) csrf_repair_node: String,
    pub(super) csrf_ftps: String,
    pub(super) target_node: String,
    pub(super) error: Option<String>,
}

/// GET /hostings/:selector/ftp-panel — diagnose this site's FTP.
///
/// Runs on the OWNING node: the vsftpd config, the shadow entry and the web
/// root are all node-local, so checking them on the master would report every
/// remote hosting as broken.
pub async fn get_ftp_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let card = |report, target_node: String, error: Option<String>| {
        Html(
            FtpCardTpl {
                report,
                selector: selector.clone(),
                csrf_repair: csrf_token_for(&state, &ctx, "/hostings/ftp/repair"),
                csrf_repair_node: csrf_token_for(&state, &ctx, "/hostings/ftp/repair-node"),
                csrf_ftps: csrf_token_for(&state, &ctx, "/hostings/ftp/ftps"),
                target_node,
                error,
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return Ok(card(
                Default::default(),
                String::new(),
                Some(format!("could not read the selector: {e}")),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => return Ok(card(Default::default(), String::new(), Some(e.to_string()))),
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
        return Ok(card(
            Default::default(),
            String::new(),
            Some("You do not have access to this hosting.".into()),
        ));
    }
    let node_label = owner.clone().unwrap_or_else(|| "this server".to_string());
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::FtpSelfCheck { sel },
    )
    .await
    {
        Ok(RpcResponse::FtpSelfCheck(mut r)) => {
            // The agent cannot name itself reliably; the web layer already
            // knows which node it dispatched to.
            r.node_id = node_label.clone();
            Ok(card(r, node_label, None))
        }
        Ok(RpcResponse::Error(e)) => Ok(card(Default::default(), node_label, Some(e.to_string()))),
        Ok(_) => Ok(card(
            Default::default(),
            node_label,
            Some("unexpected response from the node".into()),
        )),
        Err(e) => Ok(card(Default::default(), node_label, Some(e.to_string()))),
    }
}

#[derive(serde::Deserialize)]
pub struct FtpAccountForm {
    pub selector: String,
    #[serde(default)]
    pub login: String,
    #[serde(default)]
    pub subdir: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub id: i64,
}

/// POST /hostings/ftp/account — add an extra FTP login.
///
/// Gated on `HostingFiles`, matching the existing FTP password action: this
/// hands out file access, and anyone who can already set the site's FTP
/// password can hand out exactly the same access.
pub async fn post_ftp_account_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpAccountForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingFiles)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::FtpAccountCreate {
            sel,
            login: form.login.trim().to_string(),
            subdir: form.subdir.trim().to_string(),
            label: form.label.trim().to_string(),
            actor: ctx.username.clone(),
        },
    )
    .await?;
    ftp_password_redirect(&state, resp, &sel_url).await
}

/// POST /hostings/ftp/account/reset — new password for one extra login.
pub async fn post_ftp_account_reset(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpAccountForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingFiles)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::FtpAccountReset { sel, id: form.id },
    )
    .await?;
    ftp_password_redirect(&state, resp, &sel_url).await
}

/// POST /hostings/ftp/account/delete — remove an extra login.
pub async fn post_ftp_account_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpAccountForm>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingFiles)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let sel_url = urlencoding(&form.selector);
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::FtpAccountDelete { sel, id: form.id },
    )
    .await?;
    Ok(match resp {
        RpcResponse::FtpAccountDelete(m) => Redirect::to(&format!(
            "/hostings/{sel_url}?flash={}#ftp",
            urlencoding(&m)
        ))
        .into_response(),
        RpcResponse::Error(e) => {
            let token = stash_error(&state, &e.to_string()).await;
            Redirect::to(&format!("/hostings/{sel_url}?wp_error_ref={token}#ftp")).into_response()
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    })
}

/// Shared tail for the two actions that mint a password.
///
/// The password goes through the same one-shot hand-off the site's own FTP
/// password uses — never the query string, which nginx writes to its access
/// log verbatim.
/// The login a name of "deploy" would produce on this hosting.
///
/// Rendered in the form so the operator sees the real result — including the
/// shortened form Hyperion falls back to when the domain will not fit. Falls
/// back to the plain shape only if composition fails, which for a hosting
/// that exists it cannot.
pub(super) fn ftp_login_example(domain: &str) -> String {
    hyperion_validate::compose_extra_login("deploy", domain)
        .unwrap_or_else(|_| format!("deploy.{domain}"))
}

pub(super) async fn ftp_password_redirect(
    state: &SharedState,
    resp: RpcResponse,
    sel_url: &str,
) -> Result<Response, AppError> {
    Ok(match resp {
        RpcResponse::FtpAccountCreate(login, pw) | RpcResponse::FtpAccountReset(login, pw) => {
            let token = one_shot_token();
            {
                let now = now_secs_web();
                let mut g = state.ftp_password_handoff.lock().await;
                g.retain(|_, (_, at)| now - *at < 300);
                // Login and password together. The panel used to render a
                // fresh password beside the SITE's username, which is not the
                // account it belongs to — an operator copied both and got
                // "530 Login incorrect".
                g.insert(token.clone(), (format!("{login}\n{pw}"), now));
            }
            Redirect::to(&format!(
                "/hostings/{sel_url}?ftp=set&ftp_pw_token={token}#ftp"
            ))
            .into_response()
        }
        RpcResponse::Error(e) => {
            let token = stash_error(state, &e.to_string()).await;
            Redirect::to(&format!("/hostings/{sel_url}?wp_error_ref={token}#ftp")).into_response()
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    })
}

#[derive(serde::Deserialize)]
pub struct FtpRepairForm {
    pub selector: String,
}

/// POST /hostings/ftp/repair — per-site repair. No daemon is touched.
pub async fn post_ftp_repair(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpRepairForm>,
) -> Result<Response, AppError> {
    ftp_repair_action(state, ctx, form, false).await
}

#[derive(serde::Deserialize)]
pub struct FtpsForm {
    pub selector: String,
    #[serde(default)]
    pub enabled: Option<String>,
}

/// POST /hostings/ftp/ftps — turn FTPS on/off for the whole node.
///
/// Admin only, and always with `require_tls`: FTPS that is merely *offered*
/// protects nobody, because a client that skips it still sends the password
/// in the clear and the server accepts it.
pub async fn post_ftp_ftps(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpsForm>,
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
    if !ctx.is_admin_or_higher() {
        return Ok((
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<h1>403 Forbidden</h1><p>FTPS is a node-wide setting — it restarts a \
             service every site on this node shares. Admin only.</p>"
                .to_string(),
        )
            .into_response());
    }
    let enabled = checkbox_on(&form.enabled);
    let sel_url = urlencoding(&form.selector);
    let node: Option<String> = find_hosting_anywhere(&state, sel)
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        node.as_deref(),
        Request::FtpSetFtps {
            enabled,
            require_tls: enabled,
        },
    )
    .await?;
    Ok(match resp {
        RpcResponse::FtpSetFtps(m) => Redirect::to(&format!(
            "/hostings/{sel_url}?flash={}#ftp",
            urlencoding(&m)
        ))
        .into_response(),
        RpcResponse::Error(e) => Redirect::to(&format!(
            "/hostings/{sel_url}?flash_error={}#ftp",
            urlencoding(&e.to_string())
        ))
        .into_response(),
        _ => return Err(AppError::Internal("unexpected response".into())),
    })
}

/// POST /hostings/ftp/repair-node — node-wide vsftpd config repair. Admin
/// only: it restarts a daemon every hosting on the node shares.
pub async fn post_ftp_repair_node(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<FtpRepairForm>,
) -> Result<Response, AppError> {
    ftp_repair_action(state, ctx, form, true).await
}

pub(super) async fn ftp_repair_action(
    state: SharedState,
    ctx: AuthCtx,
    form: FtpRepairForm,
    node_wide: bool,
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
    // Rewriting the node's vsftpd.conf and restarting the daemon affects
    // every hosting on the box, so per-hosting manage rights are not enough.
    if node_wide && !ctx.is_admin_or_higher() {
        return Ok((
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<h1>403 Forbidden</h1><p>Repairing the node's vsftpd configuration              restarts a service every site on this node shares — admin only.</p>"
                .to_string(),
        )
            .into_response());
    }
    let sel_url = urlencoding(&form.selector);
    let node: Option<String> = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let req = if node_wide {
        Request::FtpRepairNodeConfig
    } else {
        Request::FtpRepairSite { sel }
    };
    let resp = crate::dispatcher::dispatch_to_node(&state, node.as_deref(), req).await?;
    Ok(match resp {
        RpcResponse::FtpRepairSite(m) | RpcResponse::FtpRepairNodeConfig(m) => Redirect::to(
            &format!("/hostings/{sel_url}?flash={}#ftp", urlencoding(&m)),
        )
        .into_response(),
        RpcResponse::Error(e) => Redirect::to(&format!(
            "/hostings/{sel_url}?flash_error={}#ftp",
            urlencoding(&e.to_string())
        ))
        .into_response(),
        _ => return Err(AppError::Internal("unexpected response".into())),
    })
}

/// Lazily-loaded SFTP panel (FTP tab). Dispatched to the OWNING node —
/// the system user, home dir and authorized_keys all live there.
#[derive(Template)]
#[template(path = "_hosting_sftp_panel.html")]
pub(super) struct SftpPanelTpl {
    pub(super) sftp: hyperion_types::SftpStatus,
    pub(super) selector: String,
    pub(super) csrf_sftp: String,
    /// "" on success; an error string when the status probe failed.
    pub(super) error: String,
}

pub async fn get_sftp_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel.clone()).await?;
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
        Request::SftpSet {
            sel,
            enabled,
            public_keys: keys,
        },
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
            // The password is shown once, on the next page render — but it
            // must not travel in the URL to get there. A query string is
            // written to nginx's access log verbatim, kept in browser
            // history, and sent as the Referer of anything the page loads.
            // Hand over a single-use token instead and keep the credential
            // server-side.
            let token = one_shot_token();
            {
                let now = now_secs_web();
                let mut g = state.ftp_password_handoff.lock().await;
                // Drop anything stale before inserting, so an abandoned
                // hand-off cannot sit in memory indefinitely.
                g.retain(|_, (_, at)| now - *at < 300);
                g.insert(token.clone(), (password, now));
            }
            Ok(Redirect::to(&format!(
                "/hostings/{sel_url}?ftp=set&ftp_pw_token={token}#ftp"
            ))
            .into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?ftp_error={}#ftp", sel_url, msg))
                    .into_response(),
            )
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
    let sel_url = urlencoding(&form.selector);
    // FTP account lives on the node owning the hosting — find it.
    let target_owned: Option<String> = find_hosting_anywhere(&state, sel.clone())
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
            Ok(Redirect::to(&format!("/hostings/{}?ftp=disabled#ftp", sel_url)).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&e.to_string());
            Ok(
                Redirect::to(&format!("/hostings/{}?ftp_error={}#ftp", sel_url, msg))
                    .into_response(),
            )
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}
