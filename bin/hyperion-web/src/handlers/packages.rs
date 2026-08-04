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
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_rpc::wire::HostingSelector;
use hyperion_state::capabilities::Capability;
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
}

impl PackageForm {
    fn into_input(self) -> Result<PackageInput, AppError> {
        let price_minor = parse_price_major(&self.price_major)?;
        let currency = self.price_currency.trim().to_string();
        let interval = self.price_interval.trim().to_string();
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
    let input = form.into_input()?;
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
    let input = form.into_input()?;
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
    /// Set after an action so the swapped-in card carries its own result.
    flash: Option<String>,
    error: Option<String>,
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
    render_card(&state, &ctx, selector, None, None).await
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
            return render_card(&state, &ctx, form.selector, None, Some(e.to_string())).await;
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
    render_card(&state, &ctx, form.selector, flash, error).await
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
    render_card(&state, &ctx, form.selector, flash, error).await
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
            sel,
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
    let held: Vec<HeldPackage> = activations
        .iter()
        .map(|a| {
            let def = a
                .package_id
                .and_then(|pid| definitions.iter().find(|d| d.id == pid));
            build_held(a, def, live.as_ref())
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

    let tpl = PackagesCardTpl {
        selector,
        csrf_token: super::session_csrf_token(state, ctx),
        held,
        offerable,
        can_manage,
        flash,
        error,
    };
    Ok(Html(tpl.render()?).into_response())
}

fn build_held(
    a: &HostingPackage,
    def: Option<&ServicePackage>,
    live: Option<&LiveFeatureState>,
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
            .map(|d| included_features(&d.features, live))
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
        let held = build_held(&a, None, None);
        assert!(held.orphaned);
        assert_eq!(held.price, "490.00 Kč/měsíc");
        assert!(held.included.is_empty());
        assert_eq!(held.name, "Care package", "never renders as a blank row");
    }
}
