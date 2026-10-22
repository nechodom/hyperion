//! WordPress sign-up spam guard.

use super::*;

#[derive(Template)]
#[template(path = "_hosting_signup_card.html")]
pub(super) struct SignupCardTpl {
    pub(super) selector: String,
    pub(super) domain: String,
    pub(super) reg: hyperion_types::WpRegistrationView,
    /// The node could not be asked. NOT the same as "closed": a card that
    /// says closed over a site still taking sign-ups is worse than one that
    /// admits it does not know.
    pub(super) unknown: bool,
    pub(super) can_manage: bool,
    pub(super) csrf_token: String,
    pub(super) error: Option<String>,
}

/// GET /hostings/:selector/signup-panel
pub async fn get_signup_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    render_signups(&state, &ctx, selector, None).await
}

pub(super) async fn render_signups(
    state: &SharedState,
    ctx: &AuthCtx,
    selector: String,
    error: Option<String>,
) -> Result<Response, AppError> {
    let can_manage =
        require_manage_for_selector(state, ctx, &selector, Capability::HostingEditConfig)
            .await
            .is_ok();
    let card = |reg: hyperion_types::WpRegistrationView, unknown: bool, domain: String, error| {
        Html(
            SignupCardTpl {
                selector: selector.clone(),
                domain,
                reg,
                unknown,
                can_manage,
                csrf_token: csrf_token_for(state, ctx, "/hostings/signups"),
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
                true,
                String::new(),
                Some(e.to_string()),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(card(
                Default::default(),
                true,
                String::new(),
                Some(e.to_string()),
            ))
        }
    };
    if require_hosting_access(
        state,
        ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    .is_err()
    {
        return Ok(card(
            Default::default(),
            true,
            detail.domain.clone(),
            Some("You do not have access to this hosting.".into()),
        ));
    }
    match crate::dispatcher::dispatch_to_node(
        state,
        owner.as_deref(),
        Request::WpRegistrationGet { sel },
    )
    .await
    {
        // `error` is the one from a WRITE that just failed, carried through so
        // the re-rendered card shows what went wrong. Dropping it would put a
        // clean card over a refused change — the operator walks away believing
        // sign-ups are closed.
        Ok(RpcResponse::WpRegistration(r)) => Ok(card(r, false, detail.domain, error)),
        Ok(RpcResponse::Error(e)) => Ok(card(
            Default::default(),
            true,
            detail.domain,
            Some(e.to_string()),
        )),
        Ok(_) => Ok(card(
            Default::default(),
            true,
            detail.domain,
            error.or_else(|| Some("unexpected response from the owning node".into())),
        )),
        Err(e) => Ok(card(
            Default::default(),
            true,
            detail.domain,
            Some(e.to_string()),
        )),
    }
}

#[derive(serde::Deserialize)]
pub struct SignupForm {
    pub selector: String,
    pub open: String,
}

/// POST /hostings/signups — open or close public registration.
pub async fn post_signups(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SignupForm>,
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
    let owner = find_hosting_anywhere(&state, sel.clone())
        .await
        .ok()
        .and_then(|(_d, n)| n);
    let open = form.open.trim() == "1";
    let error = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::WpRegistrationSet { sel, open },
    )
    .await
    {
        Ok(RpcResponse::WpRegistration(_)) => None,
        Ok(RpcResponse::Error(e)) => Some(e.to_string()),
        Ok(_) => Some("unexpected response from the owning node".into()),
        Err(e) => Some(e.to_string()),
    };
    // Re-read from the node either way, so a refused write shows the site as
    // it actually is rather than as the click implied.
    render_signups(&state, &ctx, form.selector, error).await
}

// ───────────────────── Registration spam guard ─────────────────────

#[derive(Template)]
#[template(path = "_hosting_regguard_card.html")]
pub(super) struct RegGuardCardTpl {
    pub(super) selector: String,
    pub(super) view: hyperion_types::regguard::RegGuardView,
    pub(super) can_manage: bool,
    pub(super) csrf_toggle: String,
    pub(super) error: Option<String>,
}

#[derive(Deserialize)]
pub struct RegGuardToggleForm {
    pub(super) selector: String,
    /// Present + "on" when the operator ticks the box; absent when unticked.
    #[serde(default)]
    pub(super) enabled: Option<String>,
}

pub(super) fn regguard_card(
    state: &SharedState,
    ctx: &AuthCtx,
    selector: String,
    view: hyperion_types::regguard::RegGuardView,
    can_manage: bool,
    error: Option<String>,
) -> Response {
    Html(
        RegGuardCardTpl {
            selector,
            view,
            can_manage,
            csrf_toggle: csrf_token_for(state, ctx, "/hostings/regguard"),
            error,
        }
        .render()
        .unwrap_or_default(),
    )
    .into_response()
}

/// GET /hostings/:selector/regguard-panel — the spam-guard card, read from the
/// owning node. Lazy-loaded, like the deploy panel.
pub async fn get_regguard_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let can_manage =
        require_manage_for_selector(&state, &ctx, &selector, Capability::HostingEditConfig)
            .await
            .is_ok();
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return Ok(regguard_card(
                &state,
                &ctx,
                selector,
                Default::default(),
                can_manage,
                Some(e.to_string()),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(regguard_card(
                &state,
                &ctx,
                selector,
                Default::default(),
                can_manage,
                Some(e.to_string()),
            ))
        }
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
        return Ok(regguard_card(
            &state,
            &ctx,
            selector,
            Default::default(),
            can_manage,
            Some("You do not have access to this hosting.".into()),
        ));
    }
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::RegGuardView { sel },
    )
    .await
    {
        Ok(RpcResponse::RegGuardView(v)) => {
            Ok(regguard_card(&state, &ctx, selector, v, can_manage, None))
        }
        Ok(RpcResponse::Error(e)) => Ok(regguard_card(
            &state,
            &ctx,
            selector,
            Default::default(),
            can_manage,
            Some(e.to_string()),
        )),
        _ => Ok(regguard_card(
            &state,
            &ctx,
            selector,
            Default::default(),
            can_manage,
            Some("unexpected response from the node".into()),
        )),
    }
}

/// POST /hostings/regguard — turn the guard on/off; returns the re-rendered
/// card for an HTMX swap.
pub async fn post_regguard(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<RegGuardToggleForm>,
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
    let enabled = matches!(form.enabled.as_deref(), Some("on" | "true" | "1"));
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::RegGuardSet { sel, enabled },
    )
    .await
    {
        Ok(RpcResponse::RegGuardSet(v)) => {
            Ok(regguard_card(&state, &ctx, form.selector, v, true, None))
        }
        Ok(RpcResponse::Error(e)) => Ok(regguard_card(
            &state,
            &ctx,
            form.selector,
            Default::default(),
            true,
            Some(e.to_string()),
        )),
        _ => Ok(regguard_card(
            &state,
            &ctx,
            form.selector,
            Default::default(),
            true,
            Some("unexpected response from the node".into()),
        )),
    }
}
