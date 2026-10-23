//! Sent-mail log, SPF and DKIM cards.

use super::*;

/// Rows per page of the "Sent by Hyperion about this site" table.
pub(super) const SENT_MAIL_PAGE: usize = 10;
/// The node's `email_log::list` clamps its limit to 500; paging past that
/// would silently return the same last page again.
pub(super) const SENT_MAIL_MAX: usize = 500;

/// The next page of rows for the "Sent by Hyperion about this site" table:
/// `<tr>`s that replace the "Load more" row they were requested from.
#[derive(Template)]
#[template(path = "_hosting_sent_mail_rows.html")]
pub(super) struct SentMailRowsTpl {
    pub(super) hosting_id: String,
    pub(super) email_log: Vec<hyperion_types::EmailLogEntry>,
    pub(super) email_log_more: bool,
    /// Rows on screen once this page is in — the next request's `shown`.
    pub(super) email_log_shown: usize,
    /// Why the page could not be read; empty when it was.
    pub(super) sent_mail_error: String,
}

#[derive(serde::Deserialize)]
pub struct SentMailQuery {
    pub shown: Option<usize>,
}

/// `GET /hostings/:selector/sent-mail?shown=N` — rows N.. N+10 of the site's
/// Hyperion mail log, read from the OWNING node.
///
/// The RPC has a limit but no offset, so this asks for the first N+11 and
/// drops the N already on screen — no wire change, and old nodes answer it.
/// Failures render as a row with the reason: HTMX does not swap a non-2xx,
/// which would leave the button looking dead.
pub async fn get_sent_mail_rows(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
    axum::extract::Query(q): axum::extract::Query<SentMailQuery>,
) -> Result<Response, AppError> {
    let shown = q.shown.unwrap_or(0).min(SENT_MAIL_MAX);
    let render = |hosting_id: String,
                  rows: Vec<hyperion_types::EmailLogEntry>,
                  more: bool,
                  error: Option<String>| {
        let email_log_shown = shown + rows.len();
        Html(
            SentMailRowsTpl {
                hosting_id,
                email_log: rows,
                email_log_more: more,
                email_log_shown,
                sent_mail_error: error.unwrap_or_default(),
            }
            .render()
            .unwrap_or_default(),
        )
        .into_response()
    };
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return Ok(render(
                String::new(),
                vec![],
                false,
                Some(format!("could not read the selector: {e}")),
            ))
        }
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(render(
                String::new(),
                vec![],
                false,
                Some(format!("could not look up this site: {e}")),
            ))
        }
    };
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
    let id = detail.id.as_str().to_string();
    let limit = (shown + SENT_MAIL_PAGE + 1).min(SENT_MAIL_MAX);
    match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::EmailLogList {
            hosting_id: Some(id.clone()),
            limit: limit as i64,
        },
    )
    .await
    {
        Ok(RpcResponse::EmailLogList(rows)) => {
            let (page, more) = sent_mail_page(rows, shown);
            Ok(render(id, page, more, None))
        }
        Ok(RpcResponse::Error(e)) => Ok(render(id, vec![], false, Some(e.to_string()))),
        Ok(_) => Ok(render(
            id,
            vec![],
            false,
            Some("unexpected response from the node".into()),
        )),
        Err(e) => Ok(render(id, vec![], false, Some(e.to_string()))),
    }
}

/// Cut one page out of the first `shown + PAGE + 1` rows, newest first.
/// `more` is true only when a row past the page came back AND the next page
/// would still be inside the node's 500-row cap.
pub(super) fn sent_mail_page<T>(rows: Vec<T>, shown: usize) -> (Vec<T>, bool) {
    let total = rows.len();
    let page: Vec<T> = rows.into_iter().skip(shown).take(SENT_MAIL_PAGE).collect();
    let more = total > shown + SENT_MAIL_PAGE && shown + SENT_MAIL_PAGE < SENT_MAIL_MAX;
    (page, more)
}

pub async fn get_spf_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return Ok(spf_card_error(
                &selector,
                &selector,
                &format!("could not read the site selector: {e}"),
            ))
        }
    };
    let (detail, owner_node) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(spf_card_error(
                &selector,
                &selector,
                &format!("could not look up this site: {e}"),
            ))
        }
    };
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
    // An unparseable domain used to render an empty string, which made
    // the whole card vanish — the same silent-disappearance bug the
    // dispatch arms below were already fixed for. Report it instead.
    let resp = match Domain::parse(&detail.domain) {
        Ok(domain) => {
            crate::dispatcher::dispatch_to_node(
                &state,
                owner_node.as_deref(),
                Request::DnsSpfCheck { domain },
            )
            .await
        }
        Err(e) => Ok(RpcResponse::DnsSpfCheck(unknown_spf(
            &detail.domain,
            &format!("{} is not a parseable domain: {e}", detail.domain),
        ))),
    };
    // NEVER render nothing. This arm used to collapse every failure —
    // node unreachable, RPC error — into an empty string, so the card
    // silently vanished from the page and the operator had no idea a
    // check even existed, let alone that it failed. An unknown-status
    // card with the reason is strictly more honest.
    let sp = match resp {
        Ok(RpcResponse::DnsSpfCheck(r)) => r,
        Ok(RpcResponse::Error(e)) => unknown_spf(&detail.domain, &e.to_string()),
        Ok(_) => unknown_spf(&detail.domain, "unexpected response from the owning node"),
        Err(e) => unknown_spf(&detail.domain, &e.to_string()),
    };
    let html = SpfCardTpl {
        sp,
        domain: detail.domain.clone(),
        selector,
        checked_at: chrono::Local::now().format("%H:%M:%S").to_string(),
    }
    .render()?;
    Ok(Html(html).into_response())
}

/// An `unknown`-status SPF result carrying the failure reason — for when
/// the check could not run at all (node unreachable, RPC refused).
pub(super) fn unknown_spf(domain: &str, why: &str) -> SpfCheckResult {
    SpfCheckResult {
        domain: domain.to_string(),
        existing: vec![],
        suggested: String::new(),
        our_public_ipv4: None,
        status: "unknown".into(),
        reason: format!("could not check: {why}"),
    }
}

/// DKIM card — lazily swapped into the detail page and re-rendered by the
/// enable/verify/disable actions. All dispatched to the OWNING node (the
/// OpenDKIM key + signing tables live where the site's mail is injected).
#[derive(Template)]
#[template(path = "_hosting_dkim_card.html")]
pub(super) struct DkimCardTpl {
    pub(super) st: hyperion_types::DkimStatus,
    /// The URL selector these forms post back with.
    pub(super) selector: String,
    pub(super) csrf_token: String,
    /// Set only when an action failed — surfaced above the card body.
    pub(super) error: Option<String>,
}

pub async fn get_dkim_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = match parse_selector(&selector) {
        Ok(s) => s,
        Err(e) => {
            return render_dkim_error_card(
                &selector,
                crate::handlers::session_csrf_token(&state, &ctx),
                format!("could not read the site selector: {e}"),
            )
        }
    };
    let (detail, owner_node) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(e) => {
            return render_dkim_error_card(
                &selector,
                crate::handlers::session_csrf_token(&state, &ctx),
                format!("could not look up this site: {e}"),
            )
        }
    };
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
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner_node.as_deref(),
        Request::DkimStatus { sel },
    )
    .await;
    let csrf = crate::handlers::session_csrf_token(&state, &ctx);
    match resp {
        Ok(RpcResponse::DkimStatus(st)) => Ok(Html(
            DkimCardTpl {
                st,
                selector,
                csrf_token: csrf,
                error: None,
            }
            .render()?,
        )
        .into_response()),
        // A failed status probe just collapses the skeleton (like the SPF card).
        _ => Ok(Html(String::new()).into_response()),
    }
}

/// Render a DKIM card carrying just an error banner (default status) — used
/// when the owner lookup or the RPC transport itself fails, so the HTMX swap
/// shows a message instead of collapsing to a 500.
pub(super) fn render_dkim_error_card(
    selector: &str,
    csrf: String,
    err: String,
) -> Result<Response, AppError> {
    Ok(Html(
        DkimCardTpl {
            st: hyperion_types::DkimStatus::default(),
            selector: selector.to_string(),
            csrf_token: csrf,
            error: Some(err),
        }
        .render()?,
    )
    .into_response())
}

/// Shared body of the three DKIM actions: authorize (manage), dispatch to the
/// owning node, then re-render the card for the HTMX swap. On an RPC error we
/// still re-fetch the status so the card reflects reality plus the message.
pub(super) async fn dkim_action(
    state: SharedState,
    ctx: AuthCtx,
    selector: String,
    req: impl FnOnce(HostingSelector) -> Request,
    // `Option<String>` rather than the whole RpcResponse: the caller only ever
    // reads the Error variant's message, and returning the enum made every one
    // of these an oversized Err (clippy::result_large_err) for a value that was
    // immediately discarded. `Some(msg)` = the node reported an error;
    // `None` = an unexpected variant.
    take: impl FnOnce(RpcResponse) -> Result<hyperion_types::DkimStatus, Option<String>>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &selector, Capability::HostingEditConfig)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let csrf = crate::handlers::session_csrf_token(&state, &ctx);
    // Resolve the owning node EXPLICITLY — a DKIM write must land where the
    // key + mail live. `.ok()`-to-None (as the read panels do) would silently
    // retarget a lookup failure to the master, generating a key on the wrong
    // node. Surface the error in the card instead.
    let owner: Option<String> = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((_d, n)) => n,
        Err(e) => return render_dkim_error_card(&selector, csrf, e.to_string()),
    };
    let resp = match crate::dispatcher::dispatch_to_node(&state, owner.as_deref(), req(sel.clone()))
        .await
    {
        Ok(r) => r,
        // Transport failure (node unreachable / timeout) — a graceful card, not a 500.
        Err(e) => return render_dkim_error_card(&selector, csrf, e.to_string()),
    };
    let (st, error) = match take(resp) {
        Ok(st) => (st, None),
        Err(Some(msg)) => {
            // Re-read current status so the card body stays accurate.
            let st = match crate::dispatcher::dispatch_to_node(
                &state,
                owner.as_deref(),
                Request::DkimStatus { sel },
            )
            .await
            {
                Ok(RpcResponse::DkimStatus(s)) => s,
                _ => hyperion_types::DkimStatus::default(),
            };
            (st, Some(msg))
        }
        Err(None) => return Err(AppError::Internal("unexpected DKIM response".into())),
    };
    Ok(Html(
        DkimCardTpl {
            st,
            selector,
            csrf_token: csrf,
            error,
        }
        .render()?,
    )
    .into_response())
}

pub async fn post_dkim_enable(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DkimActionForm>,
) -> Result<Response, AppError> {
    dkim_action(
        state,
        ctx,
        form.selector,
        |sel| Request::DkimEnable { sel },
        |r| match r {
            RpcResponse::DkimEnable(s) => Ok(s),
            RpcResponse::Error(e) => Err(Some(e.to_string())),
            _ => Err(None),
        },
    )
    .await
}

pub async fn post_dkim_disable(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DkimActionForm>,
) -> Result<Response, AppError> {
    dkim_action(
        state,
        ctx,
        form.selector,
        |sel| Request::DkimDisable { sel },
        |r| match r {
            RpcResponse::DkimDisable(s) => Ok(s),
            RpcResponse::Error(e) => Err(Some(e.to_string())),
            _ => Err(None),
        },
    )
    .await
}

pub async fn post_dkim_verify(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DkimActionForm>,
) -> Result<Response, AppError> {
    dkim_action(
        state,
        ctx,
        form.selector,
        |sel| Request::DkimVerify { sel },
        |r| match r {
            RpcResponse::DkimVerify(s) => Ok(s),
            RpcResponse::Error(e) => Err(Some(e.to_string())),
            _ => Err(None),
        },
    )
    .await
}

/// Form for the DKIM enable/disable/verify buttons — just the hosting
/// selector (the `_csrf` field is consumed by the CSRF middleware).
#[derive(Deserialize)]
pub struct DkimActionForm {
    pub selector: String,
}

#[cfg(test)]
mod sent_mail_page_tests {
    use super::{sent_mail_page, SENT_MAIL_MAX, SENT_MAIL_PAGE};

    #[test]
    fn first_page_with_more() {
        let (page, more) = sent_mail_page((0..11).collect::<Vec<_>>(), 0);
        assert_eq!(page, (0..10).collect::<Vec<_>>());
        assert!(more);
    }

    #[test]
    fn exact_page_has_no_more() {
        let (page, more) = sent_mail_page((0..20).collect::<Vec<_>>(), 10);
        assert_eq!(page, (10..20).collect::<Vec<_>>());
        assert!(!more);
    }

    #[test]
    fn short_tail() {
        let (page, more) = sent_mail_page((0..13).collect::<Vec<_>>(), 10);
        assert_eq!(page, vec![10, 11, 12]);
        assert!(!more);
    }

    #[test]
    fn stops_at_node_cap() {
        // The node never returns more than 500 rows, so the page ending at
        // 500 must not offer a button that would fetch the same rows again.
        let shown = SENT_MAIL_MAX - SENT_MAIL_PAGE;
        let (page, more) = sent_mail_page((0..SENT_MAIL_MAX + 1).collect::<Vec<_>>(), shown);
        assert_eq!(page.len(), SENT_MAIL_PAGE);
        assert!(!more);
    }
}
