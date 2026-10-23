//! Per-hosting access grants and the access checks every handler goes through.

use super::*;

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
    let level = if form.level == "read" {
        "read"
    } else {
        "manage"
    };
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
        RpcResponse::WebGrantHostingAccess => Ok(Redirect::to(&format!(
            "/hostings/{}#access",
            urlencoding(&form.hosting_id)
        ))
        .into_response()),
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
        RpcResponse::WebRevokeHostingAccess => Ok(Redirect::to(&format!(
            "/hostings/{}#access",
            urlencoding(&form.hosting_id)
        ))
        .into_response()),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
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
    if ctx.is_admin_or_higher() || ctx.scope_all() {
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
    cap: Capability,
) -> Result<(), Response> {
    let forbidden = || {
        (
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<h1>403 Forbidden</h1>".to_string(),
        )
            .into_response()
    };
    // Admins (built-in admin/super) are the only unconditional escape hatch.
    if ctx.is_admin_or_higher() {
        return Ok(());
    }
    // SECURITY (sec-findings #1): an "all hostings" scope (a custom role with
    // scope=all) must NOT imply the action capability. A scope_all role still
    // has to hold `cap` for THIS action — otherwise a read-only-but-all-scope
    // role could write files / delete / reset DBs across the whole cluster.
    if !ctx.can(cap) {
        return Err(forbidden());
    }
    // With the capability held, an all-scope role reaches every hosting without
    // a per-hosting grant.
    if ctx.scope_all() {
        return Ok(());
    }
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
    cap: Capability,
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
    // Admins (built-in admin/super) are the only unconditional escape hatch.
    if ctx.is_admin_or_higher() {
        return Ok(sel);
    }
    // SECURITY (sec-findings #1): scope_all must NOT bypass the per-action
    // capability — a scope_all custom role still has to hold `cap`.
    if !ctx.can(cap) {
        return Err(forbidden());
    }
    if ctx.scope_all() {
        return Ok(sel);
    }
    let hosting_id = match &sel {
        HostingSelector::Id(id) => id.as_str().to_string(),
        // Resolve on whichever node OWNS the site. This asked only the
        // master's socket, so a tenant addressing a worker-hosted site by
        // domain — the FTP table and every /hostings/<domain> page do —
        // got NotFound here and a 403 on every action.
        _ => match find_hosting_anywhere(state, sel.clone()).await {
            Ok((d, _)) => d.id.as_str().to_string(),
            Err(_) => return Err(forbidden()),
        },
    };
    require_hosting_access(state, ctx, &hosting_id, true, cap).await?;
    Ok(sel)
}
