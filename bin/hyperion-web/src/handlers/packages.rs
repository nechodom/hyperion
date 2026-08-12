//! `/packages` — care packages ("balíček péče"), the paid entitlement
//! layer, plus the per-hosting card that renders one.
//!
//! Two audiences, one data source:
//!
//!   * the OPERATOR defines packages here and activates them on a site.
//!     Gated exactly like `/profiles` (`Capability::ProfilesManage`) —
//!     a package is the same kind of object: an admin-authored plan
//!     nobody self-serves.
//!   * the CUSTOMER sees, on their own hosting, what they are paying
//!     for and whether it is actually switched on. That view is the
//!     reason the feature exists — it is what justifies the invoice —
//!     so the card never shows a promise without saying whether the
//!     site is currently keeping it.
//!
//! Definitions live in the MASTER's database; activation rows and every
//! feature they force live on the OWNING node. So this module reads
//! definitions over the local socket and everything hosting-scoped
//! through the dispatcher, passing the resolved definition inline on
//! activate (same escape hatch as `profile_apply`).
//!
//! Define no package and none of this renders: the panel is unchanged
//! for an operator who does not sell care.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{CareReportMail, Request, Response as RpcResponse};
use hyperion_rpc::wire::HostingSelector;
use hyperion_state::capabilities::Capability;
use hyperion_types::package::ReportCadence;
use hyperion_types::{
    BackupCadence, FeatureToggle, HostingPackage, LiveFeatureState, PackageFeatures, PackageInput,
    ServicePackage,
};
use serde::Deserialize;

// ============================================================
//  /packages — the operator's definition page
// ============================================================

#[derive(Template)]
#[template(path = "packages.html")]
struct PackagesTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    packages: Vec<PackageView>,
    csrf_token: String,
    flash: Option<String>,
    error: Option<String>,
}

/// A definition plus the one thing the form needs that the wire type
/// doesn't carry: the price in MAJOR units, so the edit field shows
/// "490.00" rather than "49000".
struct PackageView {
    pkg: ServicePackage,
    price_major: String,
}

#[derive(Deserialize, Default)]
pub struct PackagesQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// GET /packages — define what you sell.
pub async fn get_packages(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PackagesQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    // Best-effort: an agent that can't answer yields an empty list, which
    // renders as the "no packages yet" explainer rather than a 500 on a
    // page whose whole job is to let you create the first one.
    let packages = fetch_packages(&state)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|pkg| PackageView {
            price_major: price_major(pkg.price_minor),
            pkg,
        })
        .collect();
    let tpl = PackagesTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "packages",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        packages,
        csrf_token: super::session_csrf_token(&state, &ctx),
        flash: q.flash,
        error: q.error,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// Definitions from the master. `service_packages` is master-only — a
/// worker has no copy — so this always goes over the local socket.
async fn fetch_packages(state: &SharedState) -> Result<Vec<ServicePackage>, AppError> {
    match hyperion_rpc_client::call(&state.agent_socket, Request::PackageList).await? {
        RpcResponse::PackageList(v) => Ok(v),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// Create + edit form. One struct for both, like `profiles::CreateForm`,
/// so the two field lists cannot drift apart.
#[derive(Deserialize)]
pub struct PackageForm {
    pub name: String,
    /// Blank ⇒ the service derives it from the name.
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub description: String,
    /// Unchecked checkboxes are simply absent from the POST body, which
    /// is exactly what `Option` models — and why this is not a `bool`.
    #[serde(default)]
    pub enabled: Option<String>,
    /// Price in major units (e.g. 490.00) — converted to minor here.
    #[serde(default)]
    pub price_major: String,
    #[serde(default)]
    pub price_currency: String,
    #[serde(default)]
    pub price_interval: String,
    // The tri-state bundle. Parsed through `from_stored`, so a value the
    // browser somehow mangled degrades to "leave" (no opinion) instead of
    // forcing something nobody bought.
    #[serde(default)]
    pub feat_wp_auto_update: String,
    #[serde(default)]
    pub feat_integrity_scan: String,
    #[serde(default)]
    pub feat_monitoring: String,
    #[serde(default)]
    pub feat_hardening: String,
    #[serde(default)]
    pub feat_backup_cadence: String,
    /// The care-report cadence. `Option`, not `String`, and the
    /// distinction is load-bearing: `None` means the FORM did not carry
    /// the field at all. `packages.html` posts it today, but an older
    /// cached form — or any other client — must leave the stored cadence
    /// alone: parsing an absent field as "leave" would silently switch off
    /// a report the customer pays for the next time somebody fixes a typo
    /// in the package name.
    #[serde(default)]
    pub feat_report_cadence: Option<String>,
}

impl PackageForm {
    /// `current` is the cadence already stored on the definition, for an
    /// edit; `None` on create (where "not in the form" really does mean
    /// "no opinion").
    fn into_input(self, current: Option<ReportCadence>) -> Result<PackageInput, AppError> {
        let price_minor = parse_price_major(&self.price_major)?;
        let currency = self.price_currency.trim().to_string();
        let interval = self.price_interval.trim().to_string();
        let report_cadence = match self.feat_report_cadence.as_deref() {
            Some(v) => ReportCadence::from_stored(v),
            None => current.unwrap_or_default(),
        };
        Ok(PackageInput {
            name: self.name.trim().to_string(),
            slug: self.slug.trim().to_string(),
            description: self.description.trim().to_string(),
            enabled: self.enabled.is_some(),
            price_minor,
            price_currency: (!currency.is_empty()).then_some(currency),
            price_interval: (!interval.is_empty()).then_some(interval),
            features: PackageFeatures {
                wp_auto_update: FeatureToggle::from_stored(&self.feat_wp_auto_update),
                integrity_scan: FeatureToggle::from_stored(&self.feat_integrity_scan),
                monitoring: FeatureToggle::from_stored(&self.feat_monitoring),
                hardening: FeatureToggle::from_stored(&self.feat_hardening),
                backup_cadence: BackupCadence::from_stored(&self.feat_backup_cadence),
                report_cadence,
            },
        })
    }
}

pub async fn post_create(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PackageForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Err(AppError::Forbidden);
    }
    let input = form.into_input(None)?;
    match hyperion_rpc_client::call(&state.agent_socket, Request::PackageCreate(input)).await? {
        RpcResponse::PackageCreate(p) => Ok(redirect_flash(&format!(
            "Package \"{}\" created. Activate it on a hosting from that site's detail page.",
            p.name
        ))),
        RpcResponse::Error(e) => Ok(redirect_error(&e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_update(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(id): Path<i64>,
    Form(form): Form<PackageForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Err(AppError::Forbidden);
    }
    // Read the definition first, purely to carry over any feature an
    // incoming form might not post back — see
    // `PackageForm::feat_report_cadence` for why absent must not mean
    // "leave".
    let current =
        match hyperion_rpc_client::call(&state.agent_socket, Request::PackageGet { id }).await? {
            RpcResponse::PackageGet(p) => Some(p.features.report_cadence),
            RpcResponse::Error(e) => return Ok(redirect_error(&e.to_string())),
            _ => return Err(AppError::Internal("unexpected response".into())),
        };
    let input = form.into_input(current)?;
    match hyperion_rpc_client::call(&state.agent_socket, Request::PackageUpdate { id, input })
        .await?
    {
        // Edits reach every ACTIVE activation on the next enforcement pass
        // — that liveness is the point of a package, and the operator
        // should not be surprised by it.
        RpcResponse::PackageUpdate(p) => Ok(redirect_flash(&format!(
            "Package \"{}\" updated. Sites already holding it pick the change up on the next enforcement pass.",
            p.name
        ))),
        RpcResponse::Error(e) => Ok(redirect_error(&e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub id: i64,
}

/// POST /packages/delete — remove a definition.
///
/// Deliberately NOT a cascade: activations survive with `package_id`
/// NULLed, keeping the price the customer agreed to and the prior state
/// a clean cancellation needs. What they lose is enforcement, which is
/// why the confirm dialog quotes `active_count` and why retiring a
/// package you still sell is the `enabled` checkbox instead.
pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DeleteForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::ProfilesManage) {
        return Err(AppError::Forbidden);
    }
    match hyperion_rpc_client::call(&state.agent_socket, Request::PackageDelete { id: form.id })
        .await?
    {
        RpcResponse::PackageDelete => Ok(redirect_flash(
            "Package deleted. Sites that held it keep their record and price, but it is no longer enforced.",
        )),
        RpcResponse::Error(e) => Ok(redirect_error(&e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// ============================================================
//  The hosting-detail card
// ============================================================

#[derive(Template)]
#[template(path = "_hosting_packages_card.html")]
struct PackagesCardTpl {
    /// What the card's forms post back with.
    selector: String,
    csrf_token: String,
    /// Packages this hosting holds right now, oldest activation first.
    held: Vec<HeldPackage>,
    /// Definitions an admin could still activate here (enabled, and not
    /// already held — the state layer refuses a second active row for
    /// the same package, so offering one would only produce an error).
    offerable: Vec<Offerable>,
    /// Server-side answer to "may THIS session activate or cancel on
    /// THIS hosting?" — computed with the same call the two POST
    /// handlers gate on, so the buttons can never offer what the action
    /// would refuse. The template also carries `data-require-caps`, but
    /// that is only for the customer's benefit, not the boundary.
    can_manage: bool,
    /// True when at least one held package sells a periodic care report —
    /// the only thing that makes the preview / send-now controls
    /// meaningful, so they are absent otherwise.
    sells_report: bool,
    /// Where a care report would be sent — the hosting's owner e-mail.
    /// Empty when none is set, which is the case worth shouting about: a
    /// package that SELLS a periodic report and has nowhere to send it is
    /// a promise the customer paid for and will never receive, and nothing
    /// used to say so.
    report_to: String,
    /// The rendered mail, shown in place after the operator asks for a
    /// preview. `None` on every other render; a preview is never sticky,
    /// because a stale one would show a period that has since moved.
    preview: Option<ReportPreview>,
    /// Set after an action so the swapped-in card carries its own result.
    flash: Option<String>,
    error: Option<String>,
}

/// The care report as the preview block renders it — the operator reading
/// exactly what their customer will receive, before it goes.
struct ReportPreview {
    subject: String,
    /// Plain text, rendered inside a `<pre>`. Not summarised, not
    /// reformatted: a preview that differs from the mail is worse than no
    /// preview at all.
    body: String,
    /// Empty when the site has no owner e-mail — the template says so
    /// loudly, because that is the state in which the scheduled send has
    /// nowhere to go.
    to: String,
    /// "weekly" | "monthly" | "quarterly" — or "leave" / "off" when
    /// nothing schedules this report and it would only ever go out by
    /// hand.
    cadence: String,
    /// "1. 6. 2026 – 30. 6. 2026", the period the body covers.
    period: String,
    /// Not one section could be measured. The scheduled send skips such a
    /// report; the operator should see why rather than wonder where their
    /// customer's mail went.
    entirely_unmeasured: bool,
}

impl ReportPreview {
    /// Straight from the wire, with one thing added: the period as a date
    /// range. Subject and body are passed through untouched — see the
    /// struct's doc.
    fn from_mail(m: CareReportMail) -> Self {
        // The period is half-open, so the last day INSIDE it is `end - 1`.
        // Same arithmetic as the renderer, so the range above the preview
        // agrees with the one in the subject line the operator is reading.
        let last_day = (m.period_end - 1).max(m.period_start);
        Self {
            period: format!(
                "{} – {}",
                preview_date(m.period_start),
                preview_date(last_day)
            ),
            subject: m.subject,
            body: m.body,
            to: m.to,
            cadence: m.cadence,
            entirely_unmeasured: m.entirely_unmeasured,
        }
    }
}

/// "1. 6. 2026" — the shape `care_report_render` puts in the mail, so the
/// period shown above the preview reads like the one inside it.
fn preview_date(ts: i64) -> String {
    use chrono::Datelike;
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    match chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0) {
        Some(dt) => {
            let m = MONTHS
                .get((dt.month() as usize).saturating_sub(1))
                .copied()
                .unwrap_or("???");
            format!("{} {} {}", dt.day(), m, dt.year())
        }
        None => "unknown date".to_string(),
    }
}

/// One activation as the card renders it: the money (snapshotted at
/// activation) joined to the promise (the definition) joined to what the
/// site is actually doing (read off the owning node).
struct HeldPackage {
    activation_id: i64,
    name: String,
    description: String,
    price: String,
    next_billing_at: Option<i64>,
    /// One line per feature the package forces. Empty for a package that
    /// forces nothing — which is worth showing plainly rather than
    /// padding out with invented bullets.
    included: Vec<IncludedFeature>,
    /// The definition was deleted: the record and its price survive, but
    /// there is no bundle left to enforce. Says so instead of rendering
    /// an empty feature list that looks like a package selling nothing.
    orphaned: bool,
}

/// One capability a package promises, and whether the site is keeping it.
struct IncludedFeature {
    label: String,
    /// Customer-facing "what this actually does" — no jargon, because
    /// the person reading it is the person paying for it.
    detail: &'static str,
    /// "active" | "inactive" | "unknown". Precomputed so the template
    /// stays layout rather than becoming a rules engine, and so
    /// "couldn't read the node" can never render as a green tick.
    status: &'static str,
    /// What the site is doing instead, when it isn't what was bought.
    live_label: String,
}

struct Offerable {
    id: i64,
    name: String,
    price: String,
}

/// Whether this site's customer actually receives a care report, how often,
/// and when the last one went out.
///
/// Site-level on purpose: the cadence is the FOLD of every package the site
/// holds (the send tick folds it the same way, so a weekly package next to
/// a quarterly one delivers weekly), while each held package's line only
/// says what THAT package sells. Passed into `build_held` for the same
/// reason `LiveFeatureState` is — the definition states the promise, this
/// states what the site is really doing about it.
enum ReportDelivery {
    /// The owning node couldn't be read. Renders as "couldn't check" and
    /// never as a report that did (or didn't) arrive — the same rule the
    /// other five features follow.
    Unknown,
    /// Nothing this site holds schedules a report, so there is no marker to
    /// read: a package that pins reports `off` is keeping that promise by
    /// construction.
    NotScheduled,
    /// The customer is entitled to a report on `cadence`, and `last_sent`
    /// is the end of the last period actually mailed (`None` = they have
    /// had none yet).
    Scheduled {
        cadence: ReportCadence,
        last_sent: Option<i64>,
    },
}

/// GET /hostings/:selector/packages-panel — lazily swapped into the
/// detail page.
///
/// Lazy like the SPF / DKIM / integrity cards, and for the same reason:
/// it reads the owning node (activations + the live state of five
/// features) and must not hold the whole detail render behind that.
pub async fn get_packages_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    render_card(&state, &ctx, selector, None, None, None).await
}

#[derive(Deserialize)]
pub struct ActivateForm {
    pub selector: String,
    pub package_id: i64,
}

/// POST /hostings/packages/activate — an admin puts a package on a site.
///
/// The definition is resolved on the MASTER and passed inline, because
/// `service_packages` lives only there: a worker asked for package 3 by
/// id would find nothing. Same split as `profile_apply`.
pub async fn post_activate(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ActivateForm>,
) -> Result<Response, AppError> {
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
    let def = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::PackageGet {
            id: form.package_id,
        },
    )
    .await?
    {
        RpcResponse::PackageGet(p) => Some(p),
        RpcResponse::Error(e) => {
            return render_card(&state, &ctx, form.selector, None, Some(e.to_string()), None).await;
        }
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let name = def.as_ref().map(|p| p.name.clone()).unwrap_or_default();
    let owner = owner_node(&state, &form.selector).await;
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::PackageActivate {
            sel,
            package_id: form.package_id,
            package: def,
        },
    )
    .await;
    let (flash, error) = match resp {
        // Deliberately doesn't claim every feature landed: the card
        // re-renders from the node's LIVE state right below this message,
        // and a setter that failed shows there as "not on".
        Ok(RpcResponse::PackageActivate(_)) => (
            Some(format!("\"{name}\" is now active on this site.")),
            None,
        ),
        Ok(RpcResponse::Error(e)) => (None, Some(e.to_string())),
        Ok(_) => (None, Some("unexpected response".into())),
        Err(e) => (None, Some(e.to_string())),
    };
    render_card(&state, &ctx, form.selector, flash, error, None).await
}

#[derive(Deserialize)]
pub struct CancelForm {
    pub selector: String,
    pub activation_id: i64,
}

/// POST /hostings/packages/cancel — stop an entitlement.
///
/// The node restores what this package switched on, except where another
/// package the site still holds forces the same feature. Nothing here
/// needs to know that rule; it just has to reach the owning node.
pub async fn post_cancel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CancelForm>,
) -> Result<Response, AppError> {
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
    let owner = owner_node(&state, &form.selector).await;
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::PackageCancel {
            sel,
            activation_id: form.activation_id,
        },
    )
    .await;
    let (flash, error) = match resp {
        Ok(RpcResponse::PackageCancel(a)) => (
            Some(format!(
                "\"{}\" cancelled. Anything it had switched on — and that nothing else pays for — has been put back the way it was.",
                if a.package_name.is_empty() { "Package".into() } else { a.package_name }
            )),
            None,
        ),
        Ok(RpcResponse::Error(e)) => (None, Some(e.to_string())),
        Ok(_) => (None, Some("unexpected response".into())),
        Err(e) => (None, Some(e.to_string())),
    };
    render_card(&state, &ctx, form.selector, flash, error, None).await
}

#[derive(Deserialize)]
pub struct ReportForm {
    pub selector: String,
}

/// POST /hostings/packages/report-preview — render the report and send
/// NOTHING.
///
/// The important half of the pair: the operator reads the exact text their
/// customer will receive before any of it goes out. The node builds it with
/// the same period, recipient and renderer the scheduled send uses, so this
/// is a rehearsal rather than an approximation.
///
/// Gated exactly like activate / cancel. Not a formality: the report quotes
/// the site's traffic, the attacks against it and its integrity-scan
/// verdict, so "it only reads" is not a reason to widen who may ask for it.
pub async fn post_report_preview(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ReportForm>,
) -> Result<Response, AppError> {
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
    // Hosting-scoped, so it must reach the OWNING node: every metric behind
    // the report is per-node, and the master would truthfully answer "not
    // measured" for all six sections of a worker's site.
    let owner = owner_node(&state, &form.selector).await;
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::CareReportPreview { sel },
    )
    .await;
    let (preview, error) = match resp {
        Ok(RpcResponse::CareReportPreview(m)) => (Some(ReportPreview::from_mail(m)), None),
        Ok(RpcResponse::Error(e)) => (None, Some(e.to_string())),
        Ok(_) => (None, Some("unexpected response".into())),
        Err(e) => (None, Some(e.to_string())),
    };
    // No flash on success: the preview block below IS the result, and a
    // "preview rendered" banner over it would only compete with it.
    render_card(&state, &ctx, form.selector, None, error, preview).await
}

/// POST /hostings/packages/report-send — send it now, for real.
///
/// A real send, with the marker to match: the period it covers is recorded
/// as reported, so the scheduled report neither repeats it an hour later
/// nor loses the days before it. The node refuses outright when the site
/// has no owner e-mail or the node has no relay — both come back as an
/// error on the card rather than as a silent success.
pub async fn post_report_send(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ReportForm>,
) -> Result<Response, AppError> {
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
    let owner = owner_node(&state, &form.selector).await;
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::CareReportSend { sel },
    )
    .await;
    let (flash, error) = match resp {
        Ok(RpcResponse::CareReportSend(m)) => (
            Some(format!(
                "Care report sent to {}. The period it covers is now recorded as reported, \
                 so the scheduled one won't repeat it.",
                m.to
            )),
            None,
        ),
        Ok(RpcResponse::Error(e)) => (None, Some(e.to_string())),
        Ok(_) => (None, Some("unexpected response".into())),
        Err(e) => (None, Some(e.to_string())),
    };
    // Deliberately no preview of what was just sent: the marker has moved,
    // so re-rendering the mail would show a period that no longer exists.
    render_card(&state, &ctx, form.selector, flash, error, None).await
}

/// Build and render the card, or collapse to nothing.
///
/// Empty response (the HTMX swap removes the skeleton) in two cases:
///   * no package was ever defined AND this site holds none — the
///     operator does not sell care, so the feature stays invisible;
///   * this site holds none and the viewer can't activate any — an
///     empty "you have no packages" card on a customer's site is an
///     upsell nobody asked this panel to run.
async fn render_card(
    state: &SharedState,
    ctx: &AuthCtx,
    selector: String,
    flash: Option<String>,
    error: Option<String>,
    preview: Option<ReportPreview>,
) -> Result<Response, AppError> {
    let sel = super::hostings::parse_selector_public(&selector)?;
    let (detail, owner) = super::hostings::find_hosting_anywhere(state, sel.clone()).await?;
    // Reading the card is ordinary hosting-detail access — the customer
    // whose invoice this justifies holds exactly that and nothing more.
    if let Err(r) = super::hostings::require_hosting_access(
        state,
        ctx,
        detail.id.as_str(),
        false,
        Capability::HostingView,
    )
    .await
    {
        return Ok(r);
    }
    // The same evaluation the activate / cancel handlers run, so a
    // rendered button always corresponds to an action that will be
    // allowed. Server-side: hiding a button is not a permission check.
    let can_manage = super::hostings::require_manage_for_selector(
        state,
        ctx,
        &selector,
        Capability::ProfilesManage,
    )
    .await
    .is_ok();

    let activations = match crate::dispatcher::dispatch_to_node(
        state,
        owner.as_deref(),
        Request::PackageActivations {
            sel: sel.clone(),
            history: false,
        },
    )
    .await
    {
        Ok(RpcResponse::PackageActivations(v)) => v,
        // A node that can't answer must not render as "you hold nothing"
        // — that reads as a cancelled entitlement. Collapse instead.
        _ => return Ok(Html(String::new()).into_response()),
    };
    let definitions = fetch_packages(state).await.unwrap_or_default();
    if definitions.is_empty() && activations.is_empty() {
        return Ok(Html(String::new()).into_response());
    }
    if activations.is_empty() && !can_manage {
        return Ok(Html(String::new()).into_response());
    }

    let live = live_feature_state(state, owner.as_deref(), &detail).await;
    // The reporting cadence this site adds up to, folded with the package
    // layer's own rule — the customer keeps the most they paid for, so a
    // weekly package next to a quarterly one delivers weekly and a package
    // pinning reports off cannot silence one that sells them.
    //
    // Folded off the CURRENT definitions rather than the activation's
    // snapshot: the snapshot lives on the owning node and never crosses the
    // wire. The two differ only between an edit and the next enforcement
    // pass, and everywhere else on this card an edited package already
    // shows what it is about to do.
    let cadence = activations
        .iter()
        .filter_map(|a| {
            a.package_id
                .and_then(|pid| definitions.iter().find(|d| d.id == pid))
        })
        .fold(ReportCadence::Leave, |acc, d| {
            acc.combine(d.features.report_cadence)
        });
    // Does anything this site holds actually sell a report? Only then is
    // the delivery marker worth an extra round trip — and only then do the
    // preview / send controls belong on the card at all.
    let sells_report = schedules_report(cadence);
    let delivery = if sells_report {
        report_delivery(state, owner.as_deref(), &detail, cadence).await
    } else {
        ReportDelivery::NotScheduled
    };
    let held: Vec<HeldPackage> = activations
        .iter()
        .map(|a| {
            let def = a
                .package_id
                .and_then(|pid| definitions.iter().find(|d| d.id == pid));
            build_held(a, def, live.as_ref(), &delivery)
        })
        .collect();
    // Don't offer what the site already holds: the partial unique index
    // rejects a second active row for the same package, so the only
    // thing that picker entry could produce is an error message.
    let offerable: Vec<Offerable> = definitions
        .iter()
        .filter(|d| d.enabled)
        .filter(|d| !activations.iter().any(|a| a.package_id == Some(d.id)))
        .map(|d| Offerable {
            id: d.id,
            name: d.name.clone(),
            price: d.pretty_price(),
        })
        .collect();

    let report_to = crate::dispatcher::dispatch_to_node(
        state,
        owner.as_deref(),
        Request::HostingGetExpiry(sel.clone()),
    )
    .await
    .ok()
    .and_then(|r| match r {
        RpcResponse::HostingGetExpiry(e) => e.owner_email,
        _ => None,
    })
    .map(|s| s.trim().to_string())
    .unwrap_or_default();

    let tpl = PackagesCardTpl {
        report_to,
        selector,
        csrf_token: super::session_csrf_token(state, ctx),
        held,
        offerable,
        can_manage,
        sells_report,
        preview,
        flash,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
}

fn build_held(
    a: &HostingPackage,
    def: Option<&ServicePackage>,
    live: Option<&LiveFeatureState>,
    delivery: &ReportDelivery,
) -> HeldPackage {
    HeldPackage {
        activation_id: a.id,
        // The activation carries the name; the definition carries the
        // sales copy. Falling back to the activation's copy keeps a
        // deleted definition's row readable.
        name: if a.package_name.is_empty() {
            def.map(|d| d.name.clone())
                .unwrap_or_else(|| "Care package".into())
        } else {
            a.package_name.clone()
        },
        description: def.map(|d| d.description.clone()).unwrap_or_default(),
        // The PRICE SNAPSHOT, never the definition's current price: what
        // the customer agreed to is what the card must show.
        price: a.pretty_price(),
        next_billing_at: a.next_billing_at,
        included: def
            .map(|d| {
                let mut lines = included_features(&d.features, live);
                // The report is the sixth feature the bundle sells, and the
                // only one whose "is it actually happening?" is a send
                // marker rather than a live setting — hence its own builder
                // and its own site-level input.
                lines.extend(report_feature(d.features.report_cadence, delivery));
                lines
            })
            .unwrap_or_default(),
        orphaned: def.is_none(),
    }
}

/// Turn a bundle into customer-facing lines, one per feature the package
/// actually FORCES. `Leave` produces no line at all — a package that
/// says nothing about monitoring must not appear to sell it.
fn included_features(f: &PackageFeatures, live: Option<&LiveFeatureState>) -> Vec<IncludedFeature> {
    let mut out = Vec::new();
    out.extend(bool_feature(
        f.wp_auto_update,
        live.map(|l| l.wp_auto_update),
        "Automatic WordPress updates",
        "WordPress updates left manual",
        "Minor and security releases are applied for you, so a published \
         vulnerability isn't left open for weeks.",
    ));
    out.extend(bool_feature(
        f.integrity_scan,
        live.map(|l| l.integrity_scan),
        "File integrity and malware scanning",
        "File integrity scanning switched off",
        "Every core and plugin file is compared against what WordPress.org \
         published, and the site's files are scanned for known malware.",
    ));
    out.extend(bool_feature(
        f.monitoring,
        live.map(|l| l.monitoring),
        "Uptime monitoring",
        "Uptime monitoring switched off",
        "The site is fetched on a schedule and an alert goes out when it \
         stops answering — you hear it from us, not from a customer.",
    ));
    out.extend(bool_feature(
        f.hardening,
        live.map(|l| l.hardening),
        "Web-application firewall and hardening",
        "Firewall and hardening switched off",
        "Common attack patterns are blocked at the web server, before they \
         ever reach WordPress.",
    ));
    if let Some(want) = f.backup_cadence.kv_value() {
        let (status, live_label) = match live.map(|l| l.backup_cadence) {
            None => ("unknown", String::new()),
            Some(c) if c.as_str() == want => ("active", String::new()),
            Some(c) => ("inactive", format!("currently {}", c.as_str())),
        };
        out.push(IncludedFeature {
            label: if want == "off" {
                "Automatic backups switched off".into()
            } else {
                format!("Automatic backups — {want}")
            },
            detail: "A full copy of the files and the database is taken on \
                     that cadence and kept, so a bad update or a broken \
                     plugin is an hour's problem rather than a lost site.",
            status,
            live_label,
        });
    }
    out
}

/// One boolean feature's line, or `None` when the package leaves it
/// alone. `live == None` means the node couldn't be read, and renders as
/// "couldn't check" — never as a tick, because a false all-clear on a
/// paid feature is the one failure mode that costs the operator a
/// customer.
fn bool_feature(
    toggle: FeatureToggle,
    live: Option<bool>,
    on_label: &str,
    off_label: &str,
    detail: &'static str,
) -> Option<IncludedFeature> {
    let want = toggle.forces()?;
    let (status, live_label) = match live {
        None => ("unknown", String::new()),
        Some(v) if v == want => ("active", String::new()),
        Some(true) => ("inactive", "currently on".to_string()),
        Some(false) => ("inactive", "currently off".to_string()),
    };
    Some(IncludedFeature {
        label: if want { on_label } else { off_label }.to_string(),
        detail,
        status,
        live_label,
    })
}

/// The care report's line: the cadence this package sells, and whether the
/// customer is really getting it.
///
/// Same three states as `bool_feature`, and the same rule behind them — a
/// node we couldn't read renders "couldn't check", never a report that went
/// out. `Leave` produces no line at all: a package with no opinion about
/// reports must not appear to sell one.
fn report_feature(cadence: ReportCadence, delivery: &ReportDelivery) -> Option<IncludedFeature> {
    let label = report_cadence_label(cadence)?;
    let (status, live_label) = match delivery {
        ReportDelivery::Unknown => ("unknown", String::new()),
        // Reachable only for `Off`, whose promise is the ABSENCE of a mail
        // and is therefore kept by there being nothing scheduled. Anything
        // else here would mean we were asked about a cadence nobody sells,
        // and "couldn't check" is the honest answer to that.
        ReportDelivery::NotScheduled => {
            if cadence == ReportCadence::Off {
                ("active", String::new())
            } else {
                ("unknown", String::new())
            }
        }
        ReportDelivery::Scheduled {
            cadence: got,
            last_sent,
        } => {
            // The fold takes the most frequent cadence the site holds, so
            // another package can only ever make the report arrive MORE
            // often than this one promises — never less. That is a promise
            // kept, not drift, so it stays "on" and simply names what the
            // customer actually receives.
            let mut note = if *got == cadence {
                String::new()
            } else {
                format!(
                    "arrives {} — another package on this site pays for that; ",
                    report_cadence_label(*got).unwrap_or("—")
                )
            };
            note.push_str(&match last_sent {
                Some(ts) => format!("last sent {}", crate::handlers::stats::fmt_ago(ts)),
                // Not an error: a fresh activation's first period simply
                // hasn't elapsed yet.
                None => "none sent yet".to_string(),
            });
            ("active", note)
        }
    };
    Some(IncludedFeature {
        label: format!("Care report — {label}"),
        detail: "A plain-language e-mail to the site's owner covering the \
                 period: attacks blocked, updates applied, traffic, uptime, \
                 backups taken and what the integrity scan found. It is what \
                 makes work nobody notices visible.",
        status,
        live_label,
    })
}

/// Czech label for a report cadence, or `None` when the package has no
/// opinion at all (`Leave`) — callers that must print something render
/// that as "—".
///
/// Czech because the report itself is: the customer's mail, its subject and
/// its period all speak Czech, so naming the cadence in English here would
/// describe a thing that doesn't exist under that name.
fn report_cadence_label(c: ReportCadence) -> Option<&'static str> {
    match c {
        ReportCadence::Leave => None,
        ReportCadence::Off => Some("off"),
        ReportCadence::Weekly => Some("weekly"),
        ReportCadence::Monthly => Some("monthly"),
        ReportCadence::Quarterly => Some("quarterly"),
    }
}

/// Does this cadence actually put a report in the customer's inbox?
///
/// `Off` and `Leave` do not — the first pins reports off, the second has no
/// opinion — which is exactly the split the send tick makes with its own
/// (service-private) `report_cadence_secs`. Anything that hides the
/// preview / send controls has to agree with what the tick would do.
fn schedules_report(c: ReportCadence) -> bool {
    matches!(
        c,
        ReportCadence::Weekly | ReportCadence::Monthly | ReportCadence::Quarterly
    )
}

/// What the five package features are set to on this site RIGHT NOW.
///
/// Mirrors `Service::package_live_state` through the same four sources:
/// two `hosting_kv` keys on the owning node, the monitor row, and the
/// vhost options already on the detail we hold. `None` when the kv read
/// failed — the card then claims nothing rather than guessing, which is
/// also why `LiveFeatureState` has no `Default`.
async fn live_feature_state(
    state: &SharedState,
    owner: Option<&str>,
    detail: &hyperion_types::HostingDetail,
) -> Option<LiveFeatureState> {
    let kv: Vec<(String, String)> = match crate::dispatcher::dispatch_to_node(
        state,
        owner,
        Request::HostingKvList {
            hosting_id: detail.id.as_str().to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v,
        _ => return None,
    };
    let value = |key: &str| -> Option<String> {
        kv.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
    };
    // Both toggles default ON when the key is absent, matching the
    // service-side getters — "never configured" is not "switched off".
    let wp_auto_update = value("wp_auto_update").map(|v| v != "off").unwrap_or(true);
    let integrity_scan = value("integrity_scan_enabled")
        .map(|v| v != "off")
        .unwrap_or(true);
    // A site state, never `Leave`: an unset or unrecognised cadence means
    // no scheduled backup, which is `Off`.
    let backup_cadence = match value("backup_cadence").as_deref() {
        Some("daily") => BackupCadence::Daily,
        Some("weekly") => BackupCadence::Weekly,
        Some("monthly") => BackupCadence::Monthly,
        _ => BackupCadence::Off,
    };
    // A hosting with no monitor row is not being monitored, and a missing
    // row is exactly what MonitorGet answers with NotFound — so anything
    // other than a config that says enabled reads as off.
    let monitor = crate::dispatcher::dispatch_to_node(
        state,
        owner,
        Request::MonitorGet {
            sel: HostingSelector::Id(detail.id.clone()),
        },
    )
    .await;
    let monitoring =
        matches!(monitor, Ok(RpcResponse::MonitorGet { ref config, .. }) if config.enabled);
    Some(LiveFeatureState {
        wp_auto_update,
        integrity_scan,
        monitoring,
        hardening: detail.vhost_options.waf_enabled,
        backup_cadence,
    })
}

/// `hosting_kv` key the service writes after a care report actually goes
/// out — the end of the last period the customer was told about.
///
/// Spelled out here rather than imported because it is private to
/// `hyperion-core`: the service owns every write, this only reads it, and a
/// read that finds nothing means "no report has been sent yet", never
/// "reports are off".
const CARE_REPORT_KV_PERIOD_END: &str = "care_report_period_end";

/// The delivery half of the report — the one thing the panel cannot work
/// out for itself: when a report was last really sent.
///
/// `cadence` is folded by the caller from the packages the site holds; this
/// only adds the marker, which is why an unreadable node collapses the
/// whole thing to `Unknown` instead of answering "never sent" and painting
/// a paid feature as silently broken.
async fn report_delivery(
    state: &SharedState,
    owner: Option<&str>,
    detail: &hyperion_types::HostingDetail,
    cadence: ReportCadence,
) -> ReportDelivery {
    let kv: Vec<(String, String)> = match crate::dispatcher::dispatch_to_node(
        state,
        owner,
        Request::HostingKvList {
            hosting_id: detail.id.as_str().to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v,
        _ => return ReportDelivery::Unknown,
    };
    let last_sent = kv
        .iter()
        .find(|(k, _)| k == CARE_REPORT_KV_PERIOD_END)
        .and_then(|(_, v)| v.trim().parse::<i64>().ok());
    ReportDelivery::Scheduled { cadence, last_sent }
}

/// The node id the hosting lives on (`None` = master), for dispatch.
/// Failure collapses to `None`: the local agent then answers, and it
/// answers "no such hosting" rather than silently writing to the wrong
/// site.
async fn owner_node(state: &SharedState, selector: &str) -> Option<String> {
    let sel = super::hostings::parse_selector_public(selector).ok()?;
    super::hostings::find_hosting_anywhere(state, sel)
        .await
        .ok()
        .and_then(|(_, node)| node)
}

// ============================================================
//  Small shared helpers
// ============================================================

/// "49000" → "490.00" for the edit form; empty for an unpriced package.
fn price_major(minor: Option<i64>) -> String {
    match minor {
        Some(m) => format!("{:.2}", m as f64 / 100.0),
        None => String::new(),
    }
}

/// Parse "490.00" / "490,00" / "490" → 49000 (minor units).
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

fn redirect_flash(msg: &str) -> Response {
    Redirect::to(&format!("/packages?flash={}", urlencoding(msg))).into_response()
}

fn redirect_error(msg: &str) -> Response {
    Redirect::to(&format!("/packages?error={}", urlencoding(msg))).into_response()
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(monitoring: bool, cadence: BackupCadence) -> LiveFeatureState {
        LiveFeatureState {
            wp_auto_update: true,
            integrity_scan: false,
            monitoring,
            hardening: false,
            backup_cadence: cadence,
        }
    }

    #[test]
    fn only_forced_features_get_a_line() {
        let f = PackageFeatures {
            monitoring: FeatureToggle::On,
            backup_cadence: BackupCadence::Daily,
            ..Default::default()
        };
        let lines = included_features(&f, Some(&live(true, BackupCadence::Daily)));
        assert_eq!(lines.len(), 2, "leave ⇒ no line at all");
        assert!(lines.iter().all(|l| l.status == "active"));
        // The customer is told the cadence they bought, not just "backups".
        assert!(lines[1].label.contains("daily"), "{}", lines[1].label);
    }

    #[test]
    fn a_paid_feature_that_is_off_reads_as_not_active() {
        let f = PackageFeatures {
            monitoring: FeatureToggle::On,
            backup_cadence: BackupCadence::Daily,
            ..Default::default()
        };
        let lines = included_features(&f, Some(&live(false, BackupCadence::Weekly)));
        assert_eq!(lines[0].status, "inactive");
        assert_eq!(lines[0].live_label, "currently off");
        assert_eq!(lines[1].status, "inactive");
        assert_eq!(lines[1].live_label, "currently weekly");
    }

    #[test]
    fn unreadable_node_never_renders_a_tick() {
        let f = PackageFeatures {
            monitoring: FeatureToggle::On,
            backup_cadence: BackupCadence::Daily,
            ..Default::default()
        };
        let lines = included_features(&f, None);
        assert!(
            lines.iter().all(|l| l.status == "unknown"),
            "a node we couldn't read must not paint a paid feature green"
        );
    }

    /// `Off` is a promise too ("this package keeps X off"), and it is
    /// kept when the site has X off — the inverse of the On case.
    #[test]
    fn a_feature_pinned_off_is_active_when_the_site_has_it_off() {
        let f = PackageFeatures {
            integrity_scan: FeatureToggle::Off,
            ..Default::default()
        };
        let lines = included_features(&f, Some(&live(true, BackupCadence::Off)));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].status, "active");
        assert!(lines[0].label.contains("off"), "{}", lines[0].label);
    }

    #[test]
    fn price_round_trips_through_the_form() {
        assert_eq!(parse_price_major("490.00").expect("parse"), Some(49_000));
        assert_eq!(parse_price_major("490,00").expect("parse"), Some(49_000));
        assert_eq!(parse_price_major("  ").expect("parse"), None);
        assert!(parse_price_major("-1").is_err());
        assert!(parse_price_major("free").is_err());
        assert_eq!(price_major(Some(49_000)), "490.00");
        assert_eq!(price_major(None), "");
    }

    #[test]
    fn an_orphaned_activation_still_shows_its_price() {
        let a = HostingPackage {
            id: 7,
            hosting_id: hyperion_types::HostingId("h1".into()),
            package_id: None,
            package_name: String::new(),
            price_minor: Some(49_000),
            price_currency: Some("Kč".into()),
            price_interval: Some("monthly".into()),
            next_billing_at: None,
            state: hyperion_types::PackageState::Active,
            activated_at: 0,
            cancelled_at: None,
            prior_state_json: None,
        };
        let held = build_held(&a, None, None, &ReportDelivery::Unknown);
        assert!(held.orphaned);
        assert_eq!(held.price, "490.00 Kč/month");
        assert!(held.included.is_empty());
        assert_eq!(held.name, "Care package", "never renders as a blank row");
    }
}
