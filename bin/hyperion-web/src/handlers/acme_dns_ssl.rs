//! The "Automatic renewal" block of a wildcard certificate: on a hosting's
//! SSL tab, and per node under Settings → HTTPS → Preview certificates.
//!
//! Setting it up mints the domain's delegation label, checks the
//! customer's `_acme-challenge` CNAME into the delegated zone, and offers a
//! one-click issuance once the CNAME is verified. Labels and the responder
//! live on the master's own agent; the certificate on the node that owns it.
//! A customer sees only whether automatic renewal is on.

use crate::acme_dns_renew::DueCert;
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_adapters::dns_probe::{self, CnameProblem};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::HostingSelector;
use hyperion_state::capabilities::Capability;
use hyperion_types::{AcmeDnsLabel, HostingId};
use hyperion_validate::Domain;
use std::time::Duration;

/// The CNAME check asks every authoritative server of the domain.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the preview issuance waits for the node's certificate list.
const CERT_TIMEOUT: Duration = Duration::from_secs(10);

/// May this user see the CNAME and act on it? Tenant roles hold
/// `CertManage` for their own hostings, hence the all-hostings scope.
pub fn allowed(ctx: &AuthCtx) -> bool {
    ctx.can(Capability::CertManage) && ctx.scope_all()
}

/// Whose wildcard a block is about.
#[derive(Clone, Debug)]
pub enum Subject {
    Hosting {
        id: String,
        domain: String,
        /// Owning node; `None` = the master.
        node: Option<String>,
    },
    Preview {
        /// The route segment: `local` or a worker's id.
        node: String,
        base: String,
        /// Owning node; `None` = the master.
        owner: Option<String>,
    },
}

impl Subject {
    fn base(&self) -> &str {
        match self {
            Subject::Hosting { domain, .. } => domain,
            Subject::Preview { base, .. } => base,
        }
    }

    fn owner(&self) -> Option<&str> {
        match self {
            Subject::Hosting { node, .. } => node.as_deref(),
            Subject::Preview { owner, .. } => owner.as_deref(),
        }
    }

    fn hosting_id(&self) -> Option<&str> {
        match self {
            Subject::Hosting { id, .. } => Some(id),
            Subject::Preview { .. } => None,
        }
    }

    /// Prefix of the setup and check routes.
    fn route(&self) -> String {
        match self {
            Subject::Hosting { id, .. } => format!("/hostings/{id}/cert/acme-dns"),
            Subject::Preview { node, .. } => format!("/settings/https/preview/{node}/acme-dns"),
        }
    }

    fn auto_url(&self) -> String {
        match self {
            Subject::Hosting { id, .. } => format!("/hostings/{id}/cert/dns01/auto"),
            Subject::Preview { .. } => format!("{}/auto", self.route()),
        }
    }

    /// The block's element id, which htmx swaps.
    fn dom_id(&self) -> String {
        match self {
            Subject::Hosting { .. } => "acme-ssl".to_string(),
            Subject::Preview { node, .. } => {
                let safe: String = node
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                    .collect();
                format!("acme-ssl-{safe}")
            }
        }
    }
}

/// What the block template draws.
#[derive(Default)]
pub struct AcmeSslBlock {
    /// The administrator's block; false = the customer's one state line.
    pub admin: bool,
    pub dom_id: String,
    /// A heading over the block (the node, on the HTTPS page).
    pub heading: String,
    pub base: String,
    pub setup_url: String,
    pub check_url: String,
    pub auto_url: String,
    pub csrf: String,
    /// The delegated zone, once one is saved.
    pub zone: Option<String>,
    /// The responder answers for the zone.
    pub enabled: bool,
    pub label: Option<AcmeDnsLabel>,
    /// The zone or the labels could not be read from the agent.
    pub unreadable: Option<String>,
}

impl AcmeSslBlock {
    /// The last CNAME check passed.
    pub fn verified(&self) -> bool {
        self.label.as_ref().is_some_and(label_verified)
    }

    /// The master renews this wildcard by itself.
    pub fn auto_on(&self) -> bool {
        self.verified() && self.enabled && self.zone.is_some()
    }

    /// One click issues now: the CNAME is verified and the zone answers.
    pub fn can_issue(&self) -> bool {
        self.auto_on()
    }

    pub fn challenge(&self) -> String {
        format!("_acme-challenge.{}", self.base)
    }

    /// `<label>.<zone>`, or empty until both exist.
    pub fn target(&self) -> String {
        match (&self.label, &self.zone) {
            (Some(l), Some(z)) => l.target(z),
            _ => String::new(),
        }
    }

    pub fn tone(&self) -> &'static str {
        if self.unreadable.is_some() || self.zone.is_none() {
            return "muted";
        }
        match &self.label {
            None => "muted",
            Some(l) if l.last_check_error.is_some() => "warn",
            Some(l) if l.verified_at.is_some() => "ok",
            Some(_) => "muted",
        }
    }

    pub fn verdict(&self) -> &'static str {
        if self.unreadable.is_some() {
            return "unknown";
        }
        if self.zone.is_none() {
            return "no delegated zone";
        }
        match &self.label {
            None => "not set up",
            Some(l) if l.last_check_error.is_some() => "CNAME not verified",
            Some(l) if l.verified_at.is_some() => "CNAME verified",
            Some(_) => "not checked yet",
        }
    }

    /// The line under the pill: the checker's own words, or why not.
    pub fn note(&self) -> String {
        if let Some(e) = &self.unreadable {
            return format!("The setting could not be read ({e}).");
        }
        match &self.label {
            Some(l) => match (&l.last_check_error, l.verified_at) {
                (Some(e), _) => e.clone(),
                (None, Some(t)) => format!("checked {}", fmt_date(t)),
                (None, None) => String::new(),
            },
            None => String::new(),
        }
    }
}

fn label_verified(l: &AcmeDnsLabel) -> bool {
    l.verified_at.is_some() && l.last_check_error.is_none()
}

fn fmt_date(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// The block's template on its own, for the htmx swaps.
#[derive(Template)]
#[template(path = "_acme_dns_ssl_block.html")]
struct BlockTpl<'a> {
    acme_ssl: &'a AcmeSslBlock,
}

/// The delegated zone and its on/off switch, from the master's agent.
async fn zone(state: &SharedState) -> Result<(Option<String>, bool), String> {
    match crate::dispatcher::dispatch_to_node(state, None, Request::AcmeDnsConfigGet).await {
        Ok(RpcResponse::AcmeDnsConfig(c)) => {
            Ok((c.zone.filter(|z| !z.trim().is_empty()), c.enabled))
        }
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected answer".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Every delegation label, from the master's agent.
async fn labels(state: &SharedState) -> Result<Vec<AcmeDnsLabel>, String> {
    match crate::dispatcher::dispatch_to_node(state, None, Request::AcmeDnsLabels).await {
        Ok(RpcResponse::AcmeDnsLabels(l)) => Ok(l),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected answer".into()),
        Err(e) => Err(e.to_string()),
    }
}

fn find_label(labels: &[AcmeDnsLabel], base: &str) -> Option<AcmeDnsLabel> {
    labels
        .iter()
        .find(|l| l.base.eq_ignore_ascii_case(base))
        .cloned()
}

/// The block for `subject`, with no label filled in yet.
fn shell(state: &SharedState, ctx: &AuthCtx, subject: &Subject) -> AcmeSslBlock {
    let route = subject.route();
    AcmeSslBlock {
        admin: allowed(ctx),
        dom_id: subject.dom_id(),
        base: subject.base().to_string(),
        setup_url: format!("{route}/setup"),
        check_url: format!("{route}/check"),
        auto_url: subject.auto_url(),
        csrf: crate::handlers::session_csrf_token(state, ctx),
        ..Default::default()
    }
}

/// The block as it stands, read from the master's agent.
pub async fn load(state: &SharedState, ctx: &AuthCtx, subject: &Subject) -> AcmeSslBlock {
    let mut block = shell(state, ctx, subject);
    match zone(state).await {
        Ok((z, enabled)) => {
            block.zone = z;
            block.enabled = enabled;
        }
        Err(e) => block.unreadable = Some(e),
    }
    match labels(state).await {
        Ok(l) => block.label = find_label(&l, subject.base()),
        Err(e) => block.unreadable = block.unreadable.or(Some(e)),
    }
    block
}

/// The block on a hosting's SSL tab. `node` = the owning node as the
/// lookup returned it.
pub async fn load_for_hosting(
    state: &SharedState,
    ctx: &AuthCtx,
    detail: &hyperion_types::HostingDetail,
    node: Option<&str>,
) -> AcmeSslBlock {
    let subject = Subject::Hosting {
        id: detail.id.as_str().to_string(),
        domain: detail.domain.clone(),
        node: owner_of(state, node.map(str::to_string)).await,
    };
    load(state, ctx, &subject).await
}

/// The blocks for every preview row of the HTTPS page, from one read of
/// the zone and the labels. `rows` = (route node, heading, base).
pub async fn load_previews(
    state: &SharedState,
    ctx: &AuthCtx,
    rows: &[(String, String, String)],
) -> Vec<AcmeSslBlock> {
    if !allowed(ctx) || rows.is_empty() {
        return Vec::new();
    }
    let zone = zone(state).await;
    let labels = labels(state).await;
    let mut out = Vec::with_capacity(rows.len());
    for (node, heading, base) in rows {
        let subject = Subject::Preview {
            node: node.clone(),
            base: base.clone(),
            owner: None,
        };
        let mut block = shell(state, ctx, &subject);
        block.heading = heading.clone();
        match &zone {
            Ok((z, enabled)) => {
                block.zone = z.clone();
                block.enabled = *enabled;
            }
            Err(e) => block.unreadable = Some(e.clone()),
        }
        match &labels {
            Ok(l) => block.label = find_label(l, base),
            Err(e) => block.unreadable = block.unreadable.take().or(Some(e.clone())),
        }
        out.push(block);
    }
    out
}

/// Check the CNAME and record the verdict on the label. When the verdict
/// flips, tell the node that owns the certificate at once, so its expiry
/// alerts follow without waiting for the daily renewal pass.
async fn probe(state: &SharedState, subject: &Subject, label: &AcmeDnsLabel, zone: &str) {
    let Ok(base) = Domain::parse(&label.base) else {
        return;
    };
    let was = label_verified(label);
    let outcome = match tokio::time::timeout(
        PROBE_TIMEOUT,
        dns_probe::check_cname(&label.challenge_name(), &label.target(zone)),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(CnameProblem::Other("the lookup timed out".into())),
    };
    let ok = outcome.is_ok();
    let mark = Request::AcmeDnsLabelMark {
        base: base.clone(),
        ok,
        error: outcome.err().map(|p| p.to_string()),
    };
    match crate::dispatcher::dispatch_to_node(state, None, mark).await {
        Ok(RpcResponse::AcmeDnsLabelMark) => {}
        other => tracing::warn!(base = %label.base, ?other, "acme-dns: label mark failed"),
    }
    if ok != was {
        let req = Request::CertSetDelegated {
            domain: base,
            delegated: ok,
        };
        match crate::dispatcher::dispatch_to_node(state, subject.owner(), req).await {
            Ok(RpcResponse::CertSetDelegated) => {}
            other => tracing::warn!(
                base = %label.base,
                node = ?subject.owner(),
                ?other,
                "acme-dns: delegated flag not updated"
            ),
        }
    }
}

/// Probe the subject's label (when there is one and a zone to point at)
/// and render the block afresh.
async fn probe_and_render(
    state: &SharedState,
    ctx: &AuthCtx,
    subject: &Subject,
) -> Result<Response, AppError> {
    let before = load(state, ctx, subject).await;
    if let (Some(label), Some(z)) = (&before.label, &before.zone) {
        probe(state, subject, label, z).await;
    }
    let block = load(state, ctx, subject).await;
    Ok(Html(BlockTpl { acme_ssl: &block }.render()?).into_response())
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "admin role required").into_response()
}

/// `None` for the master: absent, the `local` sentinel, or its hostname.
async fn owner_of(state: &SharedState, node: Option<String>) -> Option<String> {
    let node = node
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty() && n != crate::dispatcher::LOCAL_NODE_SENTINEL)?;
    if crate::dispatcher::is_master_hostname(state, &node).await {
        None
    } else {
        Some(node)
    }
}

/// The hosting behind a route selector, and its certificate's days left.
async fn hosting_subject(state: &SharedState, selector: &str) -> Result<(Subject, i64), AppError> {
    let sel = crate::handlers::hostings::parse_selector_public(selector)?;
    let (detail, node) = crate::handlers::hostings::find_hosting_anywhere(state, sel).await?;
    let days_left = detail
        .cert
        .as_ref()
        .map(|c| (c.not_after - hyperion_types::now_secs()).div_euclid(86_400))
        .unwrap_or(0);
    let subject = Subject::Hosting {
        id: detail.id.as_str().to_string(),
        domain: detail.domain.clone(),
        node: owner_of(state, node).await,
    };
    Ok((subject, days_left))
}

/// The preview base of the route's node.
async fn preview_subject(state: &SharedState, node: &str) -> Result<Subject, AppError> {
    let (_label, base) = crate::handlers::settings::resolve_node_wildcard_base(state, node)
        .await
        .ok_or(AppError::NotFound)?;
    Ok(Subject::Preview {
        node: node.to_string(),
        base,
        owner: owner_of(state, Some(node.to_string())).await,
    })
}

/// Mint (or find) the subject's label, then check it.
async fn setup(
    state: &SharedState,
    ctx: &AuthCtx,
    subject: &Subject,
) -> Result<Response, AppError> {
    let base = Domain::parse(subject.base()).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let req = Request::AcmeDnsLabelEnsure {
        base,
        hosting_id: subject.hosting_id().map(str::to_string),
    };
    match crate::dispatcher::dispatch_to_node(state, None, req).await? {
        RpcResponse::AcmeDnsLabel(_) => {}
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    }
    probe_and_render(state, ctx, subject).await
}

/// POST /hostings/:selector/cert/acme-dns/setup — htmx: the block.
pub async fn post_hosting_setup(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(forbidden());
    }
    let (subject, _) = hosting_subject(&state, &selector).await?;
    setup(&state, &ctx, &subject).await
}

/// POST /hostings/:selector/cert/acme-dns/check — htmx: the block.
pub async fn post_hosting_check(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(forbidden());
    }
    let (subject, _) = hosting_subject(&state, &selector).await?;
    probe_and_render(&state, &ctx, &subject).await
}

/// POST /hostings/:selector/cert/dns01/auto — issue the wildcard over the
/// delegated zone as a background job.
pub async fn post_hosting_auto(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(forbidden());
    }
    let (subject, days_left) = hosting_subject(&state, &selector).await?;
    let back = |msg: &str| {
        Redirect::to(&format!(
            "/hostings/{}?cert_error={}#ssl",
            urlencode(&selector),
            urlencode(msg)
        ))
        .into_response()
    };
    match start_issue(&state, &ctx, &subject, days_left).await? {
        Ok(job) => Ok(Redirect::to(&format!("/jobs/{job}")).into_response()),
        Err(msg) => Ok(back(&msg)),
    }
}

/// POST /settings/https/preview/:node/acme-dns/setup — htmx: the block.
pub async fn post_preview_setup(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(node): Path<String>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(forbidden());
    }
    let subject = preview_subject(&state, &node).await?;
    setup(&state, &ctx, &subject).await
}

/// POST /settings/https/preview/:node/acme-dns/check — htmx: the block.
pub async fn post_preview_check(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(node): Path<String>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(forbidden());
    }
    let subject = preview_subject(&state, &node).await?;
    probe_and_render(&state, &ctx, &subject).await
}

/// POST /settings/https/preview/:node/acme-dns/auto — issue the node's
/// preview wildcard over the delegated zone as a background job.
pub async fn post_preview_auto(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(node): Path<String>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(forbidden());
    }
    let subject = preview_subject(&state, &node).await?;
    let days_left = preview_days_left(&state, &subject).await;
    match start_issue(&state, &ctx, &subject, days_left).await? {
        Ok(job) => Ok(Redirect::to(&format!("/jobs/{job}")).into_response()),
        Err(msg) => Ok(super::settings::chrome::back_with_error(
            "preview-wildcard",
            &msg,
        )),
    }
}

/// Days left on the node's `*.<base>` certificate; 0 when unknown.
async fn preview_days_left(state: &SharedState, subject: &Subject) -> i64 {
    let res = tokio::time::timeout(
        CERT_TIMEOUT,
        crate::dispatcher::dispatch_to_node(state, subject.owner(), Request::CertOverview),
    )
    .await;
    match res {
        Ok(Ok(RpcResponse::CertOverview(items))) => items
            .iter()
            .find(|c| c.domain.eq_ignore_ascii_case(subject.base()))
            .map_or(0, |c| c.days_left),
        _ => 0,
    }
}

/// Spawn the issuance job. The inner `Err` is a refusal for the operator
/// (no label yet); the renewal itself re-checks everything and reports
/// its failure as the job's.
async fn start_issue(
    state: &SharedState,
    ctx: &AuthCtx,
    subject: &Subject,
    days_left: i64,
) -> Result<Result<String, String>, AppError> {
    let label = match labels(state).await {
        Ok(l) => find_label(&l, subject.base()),
        Err(e) => return Ok(Err(format!("the delegation labels could not be read: {e}"))),
    };
    let Some(label) = label else {
        return Ok(Err(format!(
            "automatic renewal is not set up for {}",
            subject.base()
        )));
    };
    let due = DueCert {
        node_id: subject.owner().map(str::to_string),
        domain: subject.base().to_string(),
        hosting_id: subject.hosting_id().map(str::to_string),
        label,
        days_left,
    };
    let (kind, target) = match subject {
        Subject::Hosting { id, .. } => ("acme_issue", id.clone()),
        Subject::Preview { base, .. } => ("cert_renew", base.clone()),
    };
    let payload = serde_json::json!({
        "domain": due.domain,
        "node_id": due.node_id,
        "via": "acme-dns",
    })
    .to_string();
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let job_state = state.clone();
    let job = crate::handlers::jobs::spawn_job(
        state.clone(),
        kind,
        Some(&target),
        &payload,
        &ctx.username,
        actor_uid,
        move |reporter| async move {
            reporter
                .step(
                    &format!("Issuing *.{} over the delegated acme zone…", due.domain),
                    10,
                    "",
                )
                .await;
            match crate::acme_dns_renew::renew_one(&job_state, &due).await {
                Ok(()) => {
                    reporter.step("Wildcard certificate issued.", 100, "").await;
                    reporter.finish(true, None).await;
                }
                Err(e) => reporter.finish(false, Some(e)).await,
            }
        },
    )
    .await?;
    Ok(Ok(job))
}

/// A hosting is gone for good: drop its delegation labels on the master.
/// Never fails the caller; a leftover label only lists a dead domain.
pub async fn forget_hosting(state: &SharedState, hosting_id: &str) {
    let req = Request::AcmeDnsLabelsDeleteForHosting {
        hosting_id: hosting_id.to_string(),
    };
    match crate::dispatcher::dispatch_to_node(state, None, req).await {
        Ok(RpcResponse::AcmeDnsLabelsDeleteForHosting) => {}
        other => tracing::warn!(hosting_id, ?other, "acme-dns: labels not deleted"),
    }
}

/// After a delete that may only have moved the hosting to the trash:
/// forget its labels when the owning node no longer knows it.
pub async fn forget_hosting_if_gone(state: &SharedState, node: Option<&str>, hosting_id: &str) {
    let sel = HostingSelector::Id(HostingId::from(hosting_id.to_string()));
    // Still there (trashed) or no answer: a trashed site keeps its labels.
    if let Ok(RpcResponse::Error(hyperion_rpc::error::RpcError::NotFound { .. })) =
        crate::dispatcher::dispatch_to_node(state, node, Request::HostingGet(sel)).await
    {
        forget_hosting(state, hosting_id).await
    }
}

/// The hosting id behind `sel` on `node`, for the cleanup after a delete.
pub async fn hosting_id_of(
    state: &SharedState,
    node: Option<&str>,
    sel: &HostingSelector,
) -> Option<String> {
    if let HostingSelector::Id(id) = sel {
        return Some(id.as_str().to_string());
    }
    match crate::dispatcher::dispatch_to_node(state, node, Request::HostingGet(sel.clone())).await {
        Ok(RpcResponse::HostingGet(d)) => Some(d.id.as_str().to_string()),
        _ => None,
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(verified_at: Option<i64>, error: Option<&str>) -> AcmeDnsLabel {
        AcmeDnsLabel {
            base: "example.com".into(),
            label: "abcd1234abcd1234".into(),
            hosting_id: Some("h1".into()),
            created_at: 0,
            verified_at,
            last_check_error: error.map(str::to_string),
        }
    }

    fn block(zone: Option<&str>, enabled: bool, l: Option<AcmeDnsLabel>) -> AcmeSslBlock {
        AcmeSslBlock {
            base: "example.com".into(),
            zone: zone.map(str::to_string),
            enabled,
            label: l,
            ..Default::default()
        }
    }

    #[test]
    fn automatic_renewal_needs_a_verified_label_and_an_enabled_zone() {
        let ok = || Some(label(Some(10), None));
        assert!(block(Some("acme.p.example"), true, ok()).auto_on());
        assert!(!block(Some("acme.p.example"), false, ok()).auto_on());
        assert!(!block(None, true, ok()).auto_on());
        assert!(!block(Some("acme.p.example"), true, Some(label(None, None))).auto_on());
        assert!(!block(
            Some("acme.p.example"),
            true,
            Some(label(Some(10), Some("the CNAME record does not exist yet")))
        )
        .auto_on());
        assert!(!block(Some("acme.p.example"), true, None).auto_on());
    }

    #[test]
    fn the_target_needs_both_label_and_zone() {
        let b = block(Some("acme.p.example"), true, Some(label(None, None)));
        assert_eq!(b.challenge(), "_acme-challenge.example.com");
        assert_eq!(b.target(), "abcd1234abcd1234.acme.p.example");
        assert_eq!(block(None, true, Some(label(None, None))).target(), "");
        assert_eq!(block(Some("acme.p.example"), true, None).target(), "");
    }

    #[test]
    fn the_verdict_reads_the_error_before_the_stamp() {
        let b = block(
            Some("z.example"),
            true,
            Some(label(Some(10), Some("the CNAME record does not exist yet"))),
        );
        assert_eq!(b.verdict(), "CNAME not verified");
        assert_eq!(b.note(), "the CNAME record does not exist yet");
        assert_eq!(
            block(Some("z.example"), true, Some(label(Some(10), None))).verdict(),
            "CNAME verified"
        );
        assert_eq!(block(None, true, None).verdict(), "no delegated zone");
        assert_eq!(block(Some("z.example"), true, None).verdict(), "not set up");
    }

    #[test]
    fn preview_ids_are_safe_element_ids() {
        let s = Subject::Preview {
            node: "lab 01.x".into(),
            base: "lab.example.com".into(),
            owner: None,
        };
        assert_eq!(s.dom_id(), "acme-ssl-lab-01-x");
        assert_eq!(s.route(), "/settings/https/preview/lab 01.x/acme-dns");
        assert_eq!(
            s.auto_url(),
            "/settings/https/preview/lab 01.x/acme-dns/auto"
        );
    }
}
