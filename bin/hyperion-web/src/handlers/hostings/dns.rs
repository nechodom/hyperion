//! DNS preflight banner and DNS checks.

use super::*;

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
    pub(super) domain: String,
}

pub async fn post_dns_check_domain(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DnsCheckDomainForm>,
) -> Result<Response, AppError> {
    // Used by the new-hosting form. Match post_create's gating —
    // operators can't be on this page anyway.
    if !ctx.can(Capability::HostingCreate) {
        return Err(AppError::Forbidden);
    }
    let trimmed = form.domain.trim();
    let parsed = match Domain::parse(trimmed) {
        Ok(d) => d.without_www(),
        Err(e) => {
            return Ok(Html(format!(
                "<div class=\"flash error\"><div class=\"flash-body\">Invalid domain: {}</div></div>",
                askama_escape::escape(&e.to_string(), askama_escape::Html)
            ))
            .into_response());
        }
    };
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::DnsCheck { domain: parsed })
        .await?;
    let html = match resp {
        RpcResponse::DnsCheck(r) => render_dns_fragment(&r),
        RpcResponse::Error(e) => format!(
            "<div class=\"flash error\"><div class=\"flash-body\">DNS check failed: {}</div></div>",
            askama_escape::escape(&e.to_string(), askama_escape::Html)
        ),
        _ => {
            "<div class=\"flash error\"><div class=\"flash-body\">Unexpected response.</div></div>"
                .into()
        }
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
    let detail_sel =
        match require_manage_for_selector(&state, &ctx, &form.selector, Capability::HostingView)
            .await
        {
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
    let resp = hyperion_rpc_client::call(&state.agent_socket, Request::DnsCheck { domain }).await?;
    let html = match resp {
        RpcResponse::DnsCheck(r) => render_dns_fragment(&r),
        RpcResponse::Error(e) => {
            format!(
                "<div class=\"flash error\"><div class=\"flash-body\">DNS check failed: {}</div></div>",
                askama_escape::escape(&e.to_string(), askama_escape::Html)
            )
        }
        _ => {
            "<div class=\"flash error\"><div class=\"flash-body\">Unexpected response.</div></div>"
                .into()
        }
    };
    Ok(Html(html).into_response())
}

pub(super) fn render_dns_fragment(r: &DnsCheckResult) -> String {
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
pub(super) struct DnsBannerTpl {
    pub(super) dns: hyperion_types::DnsCheckResult,
}

pub async fn get_dns_panel(
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
pub(super) struct SpfCardTpl {
    pub(super) sp: SpfCheckResult,
    pub(super) domain: String,
    /// The URL selector this fragment was requested with — the
    /// "Check again" button re-requests the same panel.
    pub(super) selector: String,
    /// Wall-clock time this check ran, `HH:MM:SS`. An unchanged SPF
    /// record re-renders a byte-identical card, so without this stamp a
    /// re-check is invisible and the button reads as broken.
    pub(super) checked_at: String,
}

/// Render the SPF card in its `unknown` state carrying `why`.
///
/// Exists so this endpoint can report a failure INSIDE the card. The card is
/// lazily swapped into a placeholder that is itself a spinner, and HTMX does
/// not swap on a non-2xx — so any error status left that spinner on screen
/// forever. "A spinner that never resolves" is the least informative failure
/// a UI can have: it looks like a hung request, gives no reason, and reads as
/// a broken button rather than a broken lookup.
pub(super) fn spf_card_error(selector: &str, domain: &str, why: &str) -> Response {
    match (SpfCardTpl {
        sp: unknown_spf(domain, why),
        domain: domain.to_string(),
        selector: selector.to_string(),
        checked_at: chrono::Local::now().format("%H:%M:%S").to_string(),
    })
    .render()
    {
        Ok(html) => Html(html).into_response(),
        // The template itself failed — plain text still beats a spinner.
        Err(e) => Html(format!(
            "<div class=\"card hover\"><h2>Email DNS (SPF)</h2>\
             <p class=\"muted\">Could not render the SPF card: {e}</p></div>"
        ))
        .into_response(),
    }
}
