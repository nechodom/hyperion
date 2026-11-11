//! The "Automatic wildcard renewal" card on Settings → HTTPS: the delegated
//! acme-dns zone, the DNS records that delegate it with the state of each,
//! and the delegated wildcards that renew through it. Everything talks to
//! the master's own agent — the responder runs there.

use super::chrome;
use crate::auth::AuthCtx;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hyperion_adapters::dns_delegation::{DelegationReport, DelegationSetup, Link};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{AcmeDnsConfig, AcmeDnsLabel};
use serde::Deserialize;
use std::time::Duration;

/// How long the delegation check may take as a whole. Every link has its
/// own, shorter limit; this only bounds a probe that hangs outright.
const CHECK_TIMEOUT: Duration = Duration::from_secs(20);

/// May this user see and change the delegated zone? Tenant roles hold
/// `CertManage` for their own hostings, hence the all-hostings scope; the
/// zone is a global setting on Settings -> HTTPS, hence `SettingsManage`.
pub fn allowed(ctx: &AuthCtx) -> bool {
    ctx.can(Capability::CertManage) && ctx.scope_all() && ctx.can(Capability::SettingsManage)
}

/// One DNS record the operator adds in the parent zone.
pub struct AcmeRecord {
    pub kind: &'static str,
    pub name: String,
    pub value: String,
}

impl AcmeRecord {
    /// The record as one zone-file line, for the copy button.
    pub fn line(&self) -> String {
        format!("{} {} {}", self.name, self.kind, self.value)
    }
}

/// One delegated wildcard, as the card lists it.
pub struct LabelRow {
    pub base: String,
    /// Where the wildcard is managed: the site's SSL tab, or the preview
    /// certificates on this page.
    pub href: String,
    pub tone: &'static str,
    pub verdict: &'static str,
    /// The CNAME checker's last complaint, or the verified date.
    pub note: String,
}

/// The pill beside the card's title.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub tone: &'static str,
    pub word: &'static str,
}

impl Verdict {
    const fn new(tone: &'static str, word: &'static str) -> Self {
        Self { tone, word }
    }
}

/// One line of the status list: a link of the delegation and how it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRow {
    /// `ok` / `warn` / `err`, or empty for "nothing known".
    pub tone: &'static str,
    pub name: &'static str,
    /// The DNS record this row is about, as a line to copy.
    pub record: Option<String>,
    pub detail: String,
    /// Still being looked up.
    pub checking: bool,
}

/// The status list under the zone: the records to add, each with its own
/// state, the responder, and what public resolvers see. Rendered with the
/// page (lookups pending) and again by the check, which fills them in.
#[derive(Debug, Clone, Default)]
pub struct StatusBlock {
    pub rows: Vec<StatusRow>,
    /// What to do next, and how urgent it is.
    pub headline: String,
    pub headline_tone: &'static str,
    /// The DNS lookups are still to run: the block fetches itself.
    pub pending: bool,
    /// The card's pill.
    pub verdict: Option<Verdict>,
    /// Send the pill along as an out-of-band swap: the check's answer
    /// replaces the one beside the card's title.
    pub oob: bool,
}

/// What the template draws.
#[derive(Default)]
pub struct AcmeCard {
    /// False: the card is an empty shell for a user who may not touch it.
    pub allowed: bool,
    pub zone: String,
    pub ns_host: String,
    pub public_ipv4: String,
    pub public_ipv6: String,
    /// The responder is switched on (the saved state, not the checkbox).
    pub enabled: bool,
    /// A zone has been saved.
    pub configured: bool,
    /// The zone as saved, for the summary; the form may hold other text.
    pub saved_zone: String,
    pub saved_ns_host: String,
    pub saved_addresses: Vec<String>,
    /// A refused save or switch, shown in the card.
    pub error: Option<String>,
    /// The form's own save was refused: unfold it, with what was typed.
    pub form_open: bool,
    /// The config could not be read from the agent.
    pub unreadable: Option<String>,
    pub verdict: Option<Verdict>,
    pub labels: Vec<LabelRow>,
    /// The labels could not be read; the list must not read as empty.
    pub labels_error: Option<String>,
}

impl AcmeCard {
    /// Changing the zone strands every CNAME that points into it, so the
    /// form asks for a second, explicit yes once any exist (or may exist).
    pub fn zone_in_use(&self) -> bool {
        !self.labels.is_empty() || self.labels_error.is_some()
    }

    /// Who would be stranded by a zone change, for the confirmation.
    pub fn zone_users(&self) -> String {
        match (self.labels_error.is_some(), self.labels.len()) {
            (true, _) => "wildcards may point their CNAME into it".to_string(),
            (false, 1) => "1 wildcard points its CNAME into it".to_string(),
            (false, n) => format!("{n} wildcards point their CNAME into it"),
        }
    }

    pub fn wildcards(&self) -> String {
        match self.labels.len() {
            1 => "1 wildcard".to_string(),
            n => format!("{n} wildcards"),
        }
    }
}

/// `acme.<panel hostname>`; empty while the panel has no hostname.
pub fn suggested_zone(panel_host: &str) -> String {
    let h = panel_host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        String::new()
    } else {
        format!("acme.{h}")
    }
}

/// `ns-acme.<panel parent>`: the NS host lives in the panel's parent zone
/// (outside the delegated zone). A two-label panel host is its own parent.
pub fn suggested_ns_host(panel_host: &str) -> String {
    let h = panel_host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return String::new();
    }
    let parent = match h.split_once('.') {
        Some((_, rest)) if rest.contains('.') => rest,
        _ => h.as_str(),
    };
    format!("ns-acme.{parent}")
}

/// The records that delegate `zone` to this server: NS at the zone, address
/// A/AAAA for the NS host. Empty until both names are known.
pub fn records(zone: &str, ns_host: &str, v4: &str, v6: &str) -> Vec<AcmeRecord> {
    let (zone, ns_host) = (zone.trim(), ns_host.trim());
    if zone.is_empty() || ns_host.is_empty() {
        return Vec::new();
    }
    let mut out = vec![AcmeRecord {
        kind: "NS",
        name: zone.to_string(),
        value: format!("{ns_host}."),
    }];
    if !v4.trim().is_empty() {
        out.push(AcmeRecord {
            kind: "A",
            name: ns_host.to_string(),
            value: v4.trim().to_string(),
        });
    }
    if !v6.trim().is_empty() {
        out.push(AcmeRecord {
            kind: "AAAA",
            name: ns_host.to_string(),
            value: v6.trim().to_string(),
        });
    }
    out
}

pub fn label_row(l: &AcmeDnsLabel) -> LabelRow {
    let href = match l.hosting_id {
        Some(_) => format!("/hostings/{}#ssl", l.base),
        None => "#preview-wildcard".to_string(),
    };
    let (tone, verdict, note) = match (&l.last_check_error, l.verified_at) {
        (Some(e), _) => ("warn", "CNAME not verified", e.clone()),
        (None, Some(t)) => ("ok", "verified", super::fmt_date(Some(t))),
        (None, None) => ("muted", "not checked yet", String::new()),
    };
    LabelRow {
        base: l.base.clone(),
        href,
        tone,
        verdict,
        note,
    }
}

/// The delegated-wildcard rows from the agent's answer, or why there are none.
pub fn labels_from(res: Result<RpcResponse, String>) -> (Vec<LabelRow>, Option<String>) {
    match res {
        Ok(RpcResponse::AcmeDnsLabels(l)) => (l.iter().map(label_row).collect(), None),
        Ok(RpcResponse::Error(e)) => (Vec::new(), Some(e.to_string())),
        Ok(_) => (Vec::new(), Some("unexpected answer".into())),
        Err(e) => (Vec::new(), Some(e)),
    }
}

/// Tone and sentence of one looked-up link. A record that is not there yet
/// is something to do, not a fault; one that leads elsewhere is.
fn link_row(name: &'static str, record: Option<String>, link: &Link) -> StatusRow {
    let tone = match link {
        Link::Ok(_) => "ok",
        Link::Missing(_) => "warn",
        Link::Wrong(_) => "err",
        Link::Unknown(_) => "",
    };
    StatusRow {
        tone,
        name,
        // A record that is in place is no longer something to copy.
        record: record.filter(|_| !link.is_ok()),
        detail: link.detail().to_string(),
        checking: false,
    }
}

fn record_line(config: &AcmeDnsConfig, kind: &str) -> Option<String> {
    records(
        config.zone.as_deref().unwrap_or(""),
        &config.ns_host,
        config.public_ipv4.as_deref().unwrap_or(""),
        config.public_ipv6.as_deref().unwrap_or(""),
    )
    .iter()
    .find(|r| r.kind == kind)
    .map(AcmeRecord::line)
}

/// The responder's own row, from what the agent says about its sockets.
/// `None`: it is on and bound, so only a lookup can say more.
fn responder_from_agent(config: &AcmeDnsConfig) -> Option<StatusRow> {
    let row = |tone, detail: String| StatusRow {
        tone,
        name: "Responder",
        record: None,
        detail,
        checking: false,
    };
    if !config.enabled {
        return Some(row("", "switched off; port 53 is closed".into()));
    }
    if config.listening.is_empty() {
        return Some(row(
            "err",
            match &config.last_error {
                Some(e) => format!("not listening: {e}"),
                None => {
                    "not listening yet; it starts within a few seconds of being switched on".into()
                }
            },
        ));
    }
    None
}

/// The card's pill and the one sentence under it, from the saved config
/// and (once looked up) the state of every link. The first thing that is
/// in the way decides, in the order an operator would fix them.
pub fn verdict(config: &AcmeDnsConfig, report: Option<&DelegationReport>) -> (Verdict, String) {
    if config.zone.as_deref().unwrap_or("").is_empty() {
        return (
            Verdict::new("muted", "not set up"),
            "No zone is delegated to this server yet.".into(),
        );
    }
    if !config.enabled {
        return (
            Verdict::new("muted", "off"),
            "The responder is off, so no wildcard renews through this zone.".into(),
        );
    }
    if config.listening.is_empty() {
        return (
            Verdict::new("err", "responder down"),
            "The responder is switched on but holds no port 53.".into(),
        );
    }
    let Some(r) = report else {
        return (
            Verdict::new("muted", "checking"),
            "Looking up the delegation…".into(),
        );
    };
    if r.public.is_ok() {
        return (
            Verdict::new("ok", "working"),
            "Public resolvers reach this server for the zone. A wildcard whose CNAME is \
             verified renews by itself."
                .into(),
        );
    }
    let ns_host = &config.ns_host;
    let records = [
        ("NS", Some(&r.ns)),
        ("A", r.a.as_ref()),
        ("AAAA", r.aaaa.as_ref()),
    ];
    for (kind, link) in records {
        match link {
            Some(Link::Missing(_)) => {
                let what = if kind == "NS" {
                    "Add the NS record at the DNS provider of the parent zone.".to_string()
                } else {
                    format!("Add the {kind} record for {ns_host} at its DNS provider.")
                };
                return (Verdict::new("warn", "waiting for DNS"), what);
            }
            Some(Link::Wrong(e)) => {
                return (
                    Verdict::new("err", "points elsewhere"),
                    format!("The {kind} record leads somewhere else: {e}."),
                )
            }
            _ => {}
        }
    }
    if r.a.is_none() && r.aaaa.is_none() {
        return (
            Verdict::new("warn", "no address"),
            format!(
                "Set the public address of this server, so {ns_host} can get an address record."
            ),
        );
    }
    match &r.responder {
        Link::Missing(e) | Link::Wrong(e) => {
            return (
                Verdict::new("err", "responder not answering"),
                format!("The responder does not answer for the zone: {e}."),
            )
        }
        _ => {}
    }
    match &r.public {
        Link::Wrong(e) if e.contains("another panel") => (
            Verdict::new("err", "points elsewhere"),
            "Public resolvers reach another panel for this zone.".into(),
        ),
        Link::Wrong(e) => (
            Verdict::new("err", "not reachable"),
            format!(
                "The records are in place, but {e}. Check that the hosting provider's \
                 firewall lets UDP and TCP port 53 through to this server."
            ),
        ),
        Link::Missing(_) if r.ns.is_ok() => (
            Verdict::new("warn", "waiting for DNS"),
            "The records are in place. Public resolvers still hold the old answer; that \
             clears by itself, usually within an hour."
                .into(),
        ),
        other => (
            Verdict::new("muted", "could not be checked"),
            format!("The delegation could not be looked up: {}.", other.detail()),
        ),
    }
}

/// The status list. `report` is `None` while the lookups are still to run.
pub fn status_block(config: &AcmeDnsConfig, report: Option<&DelegationReport>) -> StatusBlock {
    let pending = |name, record| StatusRow {
        tone: "",
        name,
        record,
        detail: "looking it up…".to_string(),
        checking: true,
    };
    let looked_up = |name: &'static str, record: Option<String>, link: Option<&Link>| match link {
        Some(l) => link_row(name, record, l),
        None => pending(name, record),
    };
    // A saved address the probe could not parse was never looked up.
    let unparsed = Link::Unknown("the saved address is not a valid one".into());
    let mut rows = Vec::new();
    rows.push(looked_up(
        "NS record",
        record_line(config, "NS"),
        report.map(|r| &r.ns),
    ));
    if config.public_ipv4.is_some() {
        rows.push(looked_up(
            "A record",
            record_line(config, "A"),
            report.map(|r| r.a.as_ref().unwrap_or(&unparsed)),
        ));
    }
    if config.public_ipv6.is_some() {
        rows.push(looked_up(
            "AAAA record",
            record_line(config, "AAAA"),
            report.map(|r| r.aaaa.as_ref().unwrap_or(&unparsed)),
        ));
    }
    if config.public_ipv4.is_none() && config.public_ipv6.is_none() {
        rows.push(StatusRow {
            tone: "warn",
            name: "Address record",
            record: None,
            detail: "no public address is set, so there is no address record to add".into(),
            checking: false,
        });
    }
    rows.push(match responder_from_agent(config) {
        Some(row) => row,
        None => {
            let mut row = looked_up("Responder", None, report.map(|r| &r.responder));
            // Bound somewhere, but not everywhere it should be.
            if let (false, Some(e)) = (row.checking, &config.last_error) {
                row.detail = format!("{}; {e}", row.detail);
                if row.tone == "ok" {
                    row.tone = "warn";
                }
            }
            row
        }
    });
    rows.push(looked_up("Public DNS", None, report.map(|r| &r.public)));
    let (verdict, headline) = verdict(config, report);
    StatusBlock {
        rows,
        headline,
        headline_tone: match verdict.tone {
            "muted" => "",
            t => t,
        },
        pending: report.is_none(),
        verdict: Some(verdict),
        oob: false,
    }
}

/// The saved config, or why it could not be read.
async fn saved_config(state: &SharedState) -> Result<AcmeDnsConfig, String> {
    match crate::dispatcher::dispatch_to_node(state, None, Request::AcmeDnsConfigGet).await {
        Ok(RpcResponse::AcmeDnsConfig(c)) => Ok(c),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected answer".into()),
        Err(e) => Err(e.to_string()),
    }
}

async fn saved_labels(state: &SharedState) -> Result<Vec<AcmeDnsLabel>, String> {
    match crate::dispatcher::dispatch_to_node(state, None, Request::AcmeDnsLabels).await {
        Ok(RpcResponse::AcmeDnsLabels(l)) => Ok(l),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected answer".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Fill the card from the agent. `form` overrides the saved values when a
/// refused save re-renders the card with what the operator typed. The
/// status list comes back beside it, its lookups still to run.
pub async fn load(
    state: &SharedState,
    ctx: &AuthCtx,
    panel_host: &str,
    form: Option<&AcmeForm>,
    error: Option<String>,
) -> (AcmeCard, StatusBlock) {
    if !allowed(ctx) {
        return (AcmeCard::default(), StatusBlock::default());
    }
    let mut card = AcmeCard {
        allowed: true,
        error,
        ..Default::default()
    };
    let saved = match saved_config(state).await {
        Ok(c) => c,
        Err(e) => {
            card.unreadable = Some(e);
            return (card, StatusBlock::default());
        }
    };
    card.configured = saved.zone.as_deref().is_some_and(|z| !z.is_empty());
    card.enabled = saved.enabled;
    card.saved_zone = saved.zone.clone().unwrap_or_default();
    card.saved_ns_host = saved.ns_host.clone();
    card.saved_addresses = [&saved.public_ipv4, &saved.public_ipv6]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    let (labels, labels_error) =
        labels_from(saved_labels(state).await.map(RpcResponse::AcmeDnsLabels));
    card.labels = labels;
    card.labels_error = labels_error;
    // A power switch posts no fields: the form keeps the saved values then.
    let form = form.filter(|f| f.power.is_none());
    card.form_open = card.error.is_some() && form.is_some();
    let pick = |typed: Option<&str>, saved: &str, suggestion: String| -> String {
        match typed {
            Some(t) => t.trim().to_string(),
            None if !saved.is_empty() => saved.to_string(),
            None => suggestion,
        }
    };
    let saved_v4 = saved.public_ipv4.clone().unwrap_or_default();
    // Suggestions are for a first setup only: a saved zone without an
    // address was saved that way on purpose.
    let v4_suggestion = if !card.configured && form.is_none() {
        match tokio::time::timeout(Duration::from_secs(5), crate::handlers::cached_public_ip())
            .await
        {
            Ok(Some(ip)) if ip.parse::<std::net::Ipv4Addr>().is_ok() => ip,
            _ => String::new(),
        }
    } else {
        String::new()
    };
    card.zone = pick(
        form.map(|f| f.zone.as_str()),
        &card.saved_zone,
        suggested_zone(panel_host),
    );
    card.ns_host = pick(
        form.map(|f| f.ns_host.as_str()),
        &saved.ns_host,
        suggested_ns_host(panel_host),
    );
    card.public_ipv4 = pick(
        form.map(|f| f.public_ipv4.as_str()),
        &saved_v4,
        v4_suggestion,
    );
    card.public_ipv6 = pick(
        form.map(|f| f.public_ipv6.as_str()),
        saved.public_ipv6.as_deref().unwrap_or(""),
        String::new(),
    );
    let status = if card.configured {
        status_block(&saved, None)
    } else {
        StatusBlock::default()
    };
    card.verdict = Some(verdict(&saved, None).0);
    (card, status)
}

#[derive(Deserialize, Default)]
pub struct AcmeForm {
    #[serde(default)]
    pub zone: String,
    #[serde(default)]
    pub ns_host: String,
    #[serde(default)]
    pub public_ipv4: String,
    #[serde(default)]
    pub public_ipv6: String,
    #[serde(default)]
    pub enabled: Option<String>,
    /// `on` / `off`: switch the responder and leave everything else as
    /// saved. The other fields are not posted then.
    #[serde(default)]
    pub power: Option<String>,
    /// The second yes for changing a zone that wildcards point into.
    #[serde(default)]
    pub confirm_zone: Option<String>,
}

fn blank(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn same_zone(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().trim_end_matches('.').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// Why this save must not go through as it is: it would move (or drop) a
/// zone that delegated wildcards point their CNAME into, without the
/// operator having said so. `labels` is `None` when they could not be read,
/// which is not "there are none".
pub fn zone_change_refusal(
    saved_zone: &str,
    new_zone: &str,
    labels: Option<usize>,
    confirmed: bool,
) -> Option<String> {
    if saved_zone.trim().is_empty() || same_zone(saved_zone, new_zone) || confirmed {
        return None;
    }
    let who = match labels {
        Some(0) => return None,
        Some(1) => "1 wildcard points its".to_string(),
        Some(n) => format!("{n} wildcards point their"),
        None => "The delegated wildcards could not be read; any that exist point their".to_string(),
    };
    Some(format!(
        "{who} _acme-challenge CNAME into {saved_zone}. Changing the zone stops their renewal \
         until every CNAME is updated at its DNS provider. Tick the confirmation under the \
         zone to change it anyway."
    ))
}

/// After a confirmed zone change every CNAME target is a new name, so no
/// label may keep reading "verified".
async fn unverify_labels(state: &SharedState, labels: &[AcmeDnsLabel], old_zone: &str) {
    for l in labels {
        let Ok(base) = hyperion_validate::Domain::parse(&l.base) else {
            continue;
        };
        let req = Request::AcmeDnsLabelMark {
            base,
            ok: false,
            error: Some(format!(
                "the delegated zone changed from {old_zone}: update the CNAME, then check it"
            )),
        };
        if let Err(e) = crate::dispatcher::dispatch_to_node(state, None, req).await {
            tracing::warn!(base = %l.base, error = %e, "acme-dns: could not unverify the label");
        }
    }
}

/// POST /settings/https/acme-dns — save the delegated zone, or switch the
/// responder (`power`). A refusal (port 53 held, firewall failure, bad
/// name, a zone in use) re-renders the page with the message inside the
/// card and what was typed; success redirects back.
pub async fn post_acme_dns(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<AcmeForm>,
) -> Result<Response, crate::error::AppError> {
    if !allowed(&ctx) {
        return Ok((StatusCode::FORBIDDEN, "admin role required").into_response());
    }
    let refuse = |refusal: String| async {
        let html = super::page_https::render_page(
            &state,
            &ctx,
            Some(&form),
            Some(refusal),
            &Default::default(),
        )
        .await?;
        Ok::<_, crate::error::AppError>(axum::response::Html(html).into_response())
    };
    let saved = saved_config(&state).await;
    let (req, moved) = match form.power.as_deref() {
        Some(power) => {
            let saved = match &saved {
                Ok(c) => c,
                Err(e) => return refuse(format!("the saved zone could not be read: {e}")).await,
            };
            let req = Request::AcmeDnsConfigSet {
                zone: saved.zone.clone(),
                ns_host: saved.ns_host.clone(),
                public_ipv4: saved.public_ipv4.clone(),
                public_ipv6: saved.public_ipv6.clone(),
                enabled: power == "on",
            };
            (req, None)
        }
        None => {
            let saved_zone = saved
                .as_ref()
                .ok()
                .and_then(|c| c.zone.clone())
                .unwrap_or_default();
            let mut moved = None;
            if !saved_zone.is_empty() && !same_zone(&saved_zone, &form.zone) {
                let labels = saved_labels(&state).await;
                if let Some(refusal) = zone_change_refusal(
                    &saved_zone,
                    &form.zone,
                    labels.as_ref().ok().map(Vec::len),
                    form.confirm_zone.is_some(),
                ) {
                    return refuse(refusal).await;
                }
                moved = Some((labels.unwrap_or_default(), saved_zone));
            }
            let req = Request::AcmeDnsConfigSet {
                zone: blank(&form.zone),
                ns_host: form.ns_host.trim().to_string(),
                public_ipv4: blank(&form.public_ipv4),
                public_ipv6: blank(&form.public_ipv6),
                enabled: form.enabled.is_some(),
            };
            (req, moved)
        }
    };
    let enabled = matches!(&req, Request::AcmeDnsConfigSet { enabled: true, .. });
    let answer = crate::dispatcher::dispatch_to_node(&state, None, req).await;
    // The zone is stored even when the responder then refuses to start.
    if let Some((labels, old_zone)) = &moved {
        let now = saved_config(&state).await.ok().and_then(|c| c.zone);
        if !same_zone(now.as_deref().unwrap_or(""), old_zone) {
            unverify_labels(&state, labels, old_zone).await;
        }
    }
    let refusal = match answer {
        Ok(RpcResponse::AcmeDnsConfig(_)) => {
            let msg = match (form.power.is_some(), enabled) {
                (true, true) => "The responder is on.",
                (true, false) => "The responder is off and port 53 is closed.",
                (false, true) => "Delegated zone saved and the responder is on.",
                (false, false) => "Delegated zone saved; the responder is off.",
            };
            return Ok(chrome::back_with_flash("acme-dns", msg));
        }
        Ok(RpcResponse::Error(e)) => e.to_string(),
        Ok(_) => "unexpected answer from the agent".to_string(),
        Err(e) => e.to_string(),
    };
    refuse(refusal).await
}

/// The status list as its own fragment: what the check answers with.
#[derive(Template)]
#[template(path = "_acme_dns_status.html")]
struct StatusTpl {
    acme_status: StatusBlock,
}

fn status_html(status: StatusCode, mut block: StatusBlock) -> Response {
    block.oob = true;
    let body = StatusTpl { acme_status: block }
        .render()
        .unwrap_or_else(|e| {
            format!(
                "<p class=\"chk-note tone-err\">{}</p>",
                super::html_escape(&e.to_string())
            )
        });
    (status, [("content-type", "text/html; charset=utf-8")], body).into_response()
}

/// A status list that is one sentence: the check could not even start.
fn status_note(tone: &'static str, word: &'static str, note: String) -> StatusBlock {
    StatusBlock {
        rows: Vec::new(),
        headline: note,
        headline_tone: tone,
        pending: false,
        verdict: Some(Verdict::new(
            if tone.is_empty() { "muted" } else { tone },
            word,
        )),
        oob: false,
    }
}

/// GET /settings/https/acme-dns/check — htmx partial: the status list with
/// every link of the saved delegation looked up. Changes nothing.
pub async fn get_acme_dns_check(State(state): State<SharedState>, ctx: AuthCtx) -> Response {
    if !allowed(&ctx) {
        return status_html(
            StatusCode::FORBIDDEN,
            status_note(
                "err",
                "not allowed",
                "Only an administrator can check the delegation.".into(),
            ),
        );
    }
    let config = match saved_config(&state).await {
        Ok(c) => c,
        Err(e) => {
            return status_html(
                StatusCode::OK,
                status_note(
                    "",
                    "could not be checked",
                    format!("The saved zone could not be read ({e})."),
                ),
            )
        }
    };
    let Some(zone) = config.zone.clone().filter(|z| !z.is_empty()) else {
        return status_html(
            StatusCode::OK,
            status_note("", "not set up", "Save a zone first.".into()),
        );
    };
    let setup = DelegationSetup {
        zone,
        ns_host: config.ns_host.clone(),
        ipv4: config.public_ipv4.as_deref().and_then(|s| s.parse().ok()),
        ipv6: config.public_ipv6.as_deref().and_then(|s| s.parse().ok()),
        check_token: config.check_token.clone(),
    };
    match tokio::time::timeout(CHECK_TIMEOUT, state.dns_probe.delegation(&setup)).await {
        Ok(report) => status_html(StatusCode::OK, status_block(&config, Some(&report))),
        Err(_) => status_html(
            StatusCode::OK,
            status_note(
                "",
                "could not be checked",
                "The lookups timed out. Try again in a moment.".into(),
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_follow_the_panel_hostname() {
        assert_eq!(
            suggested_zone("Panel.Example.com."),
            "acme.panel.example.com"
        );
        assert_eq!(suggested_zone(""), "");
        assert_eq!(
            suggested_ns_host("panel.example.com"),
            "ns-acme.example.com"
        );
        assert_eq!(suggested_ns_host("example.com"), "ns-acme.example.com");
        assert_eq!(suggested_ns_host(""), "");
    }

    #[test]
    fn records_need_both_names_and_skip_unknown_addresses() {
        assert!(records("", "ns.example.com", "1.2.3.4", "").is_empty());
        let r = records("acme.example.com", "ns-acme.example.com", "1.2.3.4", "");
        let lines: Vec<String> = r.iter().map(AcmeRecord::line).collect();
        assert_eq!(
            lines,
            vec![
                "acme.example.com NS ns-acme.example.com.",
                "ns-acme.example.com A 1.2.3.4"
            ]
        );
        let r = records("z.example.com", "ns.example.com", "1.2.3.4", "2001:db8::1");
        assert_eq!(r.last().map(|r| r.kind), Some("AAAA"));
    }

    fn config(enabled: bool, listening: &[&str]) -> AcmeDnsConfig {
        AcmeDnsConfig {
            zone: Some("acme.panel.example.com".into()),
            ns_host: "ns-acme.example.com".into(),
            public_ipv4: Some("203.0.113.9".into()),
            public_ipv6: None,
            enabled,
            check_token: "tok".into(),
            listening: listening.iter().map(|s| s.to_string()).collect(),
            last_error: None,
        }
    }

    fn on() -> AcmeDnsConfig {
        config(true, &["203.0.113.9:53"])
    }

    fn ok(s: &str) -> Link {
        Link::Ok(s.into())
    }

    fn missing(s: &str) -> Link {
        Link::Missing(s.into())
    }

    /// Everything in place.
    fn report() -> DelegationReport {
        DelegationReport {
            responder: ok("answers on 203.0.113.9:53"),
            ns: ok("delegated"),
            a: Some(ok("points at 203.0.113.9")),
            aaaa: None,
            public: ok("public resolvers get this panel's answer"),
        }
    }

    #[test]
    fn the_pill_never_reads_on_from_the_saved_flag_alone() {
        // Saved and switched on says nothing about DNS: until the lookups
        // ran the pill is neutral, and only they can turn it green.
        let (v, _) = verdict(&on(), None);
        assert_eq!((v.tone, v.word), ("muted", "checking"));
        let (v, _) = verdict(&on(), Some(&report()));
        assert_eq!((v.tone, v.word), ("ok", "working"));
        let mut unset = on();
        unset.zone = None;
        assert_eq!(verdict(&unset, None).0.word, "not set up");
        assert_eq!(verdict(&config(false, &[]), Some(&report())).0.word, "off");
        assert_eq!(verdict(&config(true, &[]), None).0.word, "responder down");
    }

    #[test]
    fn the_headline_names_the_one_record_that_is_missing() {
        // The responder answers and the address record is there: only the
        // NS record is to add, and the card must say exactly that.
        let mut r = report();
        r.ns = missing("example.com has no NS record for acme.panel.example.com");
        r.public = missing("public resolvers do not see the delegation");
        let (v, line) = verdict(&on(), Some(&r));
        assert_eq!((v.tone, v.word), ("warn", "waiting for DNS"));
        assert!(line.contains("Add the NS record"), "{line}");
        let mut r = report();
        r.a = Some(missing("ns-acme.example.com has no A record"));
        r.public = missing("x");
        let (_, line) = verdict(&on(), Some(&r));
        assert!(
            line.contains("Add the A record for ns-acme.example.com"),
            "{line}"
        );
    }

    #[test]
    fn records_in_place_but_unseen_is_a_cache_not_a_fault() {
        let mut r = report();
        r.public = missing("public resolvers do not see the delegation");
        let (v, line) = verdict(&on(), Some(&r));
        assert_eq!((v.tone, v.word), ("warn", "waiting for DNS"));
        assert!(line.contains("still hold the old answer"), "{line}");
        // A resolver that follows the delegation and gets nothing back is
        // a closed port, which waiting does not fix.
        r.public = Link::Wrong("public resolvers follow the delegation but get no answer".into());
        let (v, line) = verdict(&on(), Some(&r));
        assert_eq!((v.tone, v.word), ("err", "not reachable"));
        assert!(line.contains("port 53"), "{line}");
    }

    #[test]
    fn a_record_that_leads_elsewhere_is_a_fault() {
        let mut r = report();
        r.ns = Link::Wrong("example.com delegates the zone to ns1.elsewhere.net".into());
        r.public = missing("x");
        let (v, line) = verdict(&on(), Some(&r));
        assert_eq!((v.tone, v.word), ("err", "points elsewhere"));
        assert!(line.contains("ns1.elsewhere.net"), "{line}");
        let mut r = report();
        r.public = Link::Wrong("public resolvers reach another panel for this zone".into());
        assert_eq!(verdict(&on(), Some(&r)).0.word, "points elsewhere");
    }

    #[test]
    fn the_status_list_carries_each_record_with_its_own_state() {
        let pending = status_block(&on(), None);
        assert!(pending.pending);
        let names: Vec<&str> = pending.rows.iter().map(|r| r.name).collect();
        assert_eq!(names, ["NS record", "A record", "Responder", "Public DNS"]);
        assert!(pending.rows.iter().all(|r| r.checking));
        assert_eq!(
            pending.rows[0].record.as_deref(),
            Some("acme.panel.example.com NS ns-acme.example.com.")
        );
        let mut r = report();
        r.ns = missing("example.com has no NS record for acme.panel.example.com");
        r.public = missing("public resolvers do not see the delegation");
        let done = status_block(&on(), Some(&r));
        assert!(!done.pending);
        let tones: Vec<&str> = done.rows.iter().map(|r| r.tone).collect();
        assert_eq!(tones, ["warn", "ok", "ok", "warn"]);
        // Only what is still to add is offered for copying.
        assert!(done.rows[0].record.is_some(), "the missing NS record");
        assert!(done.rows[1].record.is_none(), "the A record is in place");
        assert_eq!(done.headline_tone, "warn");
    }

    #[test]
    fn the_responder_row_comes_from_the_agent_when_it_is_not_up() {
        // Off: nothing to look up, and nothing to wait for.
        let off = status_block(&config(false, &[]), None);
        let responder = off
            .rows
            .iter()
            .find(|r| r.name == "Responder")
            .expect("row");
        assert!(!responder.checking && responder.detail.contains("switched off"));
        let mut down = config(true, &[]);
        down.last_error = Some("bind 203.0.113.9:53: Address already in use".into());
        let block = status_block(&down, Some(&report()));
        let responder = block
            .rows
            .iter()
            .find(|r| r.name == "Responder")
            .expect("row");
        assert_eq!(responder.tone, "err");
        assert!(responder.detail.contains("Address already in use"));
        // Bound, but one address failed: answering is not the whole truth.
        let mut partial = on();
        partial.last_error = Some("bind [2001:db8::9]:53: Cannot assign".into());
        let block = status_block(&partial, Some(&report()));
        let responder = block
            .rows
            .iter()
            .find(|r| r.name == "Responder")
            .expect("row");
        assert_eq!(responder.tone, "warn");
        assert!(
            responder.detail.contains("Cannot assign"),
            "{}",
            responder.detail
        );
    }

    #[test]
    fn a_zone_with_no_address_says_so_instead_of_listing_a_record() {
        let mut c = on();
        c.public_ipv4 = None;
        let block = status_block(&c, None);
        let row = block
            .rows
            .iter()
            .find(|r| r.name == "Address record")
            .expect("row");
        assert_eq!(row.tone, "warn");
        assert!(row.record.is_none() && !row.checking);
    }

    #[test]
    fn a_zone_wildcards_point_into_is_not_changed_without_a_second_yes() {
        let z = "acme.panel.example.com";
        // Same zone, however it is typed: an ordinary save.
        assert!(zone_change_refusal(z, " ACME.panel.example.com. ", Some(3), false).is_none());
        // Nothing points into it, or there was no zone before: free to change.
        assert!(zone_change_refusal(z, "other.example.com", Some(0), false).is_none());
        assert!(zone_change_refusal("", "other.example.com", Some(3), false).is_none());
        let refusal = zone_change_refusal(z, "other.example.com", Some(2), false).expect("refused");
        assert!(
            refusal.contains("2 wildcards") && refusal.contains(z),
            "{refusal}"
        );
        // Blanking the zone is a change too.
        assert!(zone_change_refusal(z, "", Some(1), false).is_some());
        // Labels that could not be read are not "no labels".
        assert!(zone_change_refusal(z, "other.example.com", None, false).is_some());
        assert!(zone_change_refusal(z, "other.example.com", Some(2), true).is_none());
    }

    #[test]
    fn a_failed_labels_read_is_an_error_not_an_empty_list() {
        let (rows, err) = labels_from(Err("agent down".into()));
        assert!(rows.is_empty());
        assert_eq!(err.as_deref(), Some("agent down"));
        let (rows, err) = labels_from(Ok(RpcResponse::AcmeDnsLabels(vec![])));
        assert!(rows.is_empty() && err.is_none());
    }

    #[test]
    fn label_rows_read_error_before_verified() {
        let l = |v: Option<i64>, e: Option<&str>| AcmeDnsLabel {
            base: "example.com".into(),
            label: "x".into(),
            hosting_id: None,
            created_at: 0,
            verified_at: v,
            last_check_error: e.map(str::to_string),
        };
        assert_eq!(label_row(&l(Some(1), Some("no CNAME"))).tone, "warn");
        assert_eq!(label_row(&l(Some(86_400), None)).verdict, "verified");
        assert_eq!(label_row(&l(None, None)).verdict, "not checked yet");
    }

    #[test]
    fn a_label_links_to_where_its_wildcard_is_managed() {
        let mut l = AcmeDnsLabel {
            base: "example.com".into(),
            label: "x".into(),
            hosting_id: Some("h1".into()),
            created_at: 0,
            verified_at: None,
            last_check_error: None,
        };
        assert_eq!(label_row(&l).href, "/hostings/example.com#ssl");
        // No hosting: a node's preview base.
        l.hosting_id = None;
        assert_eq!(label_row(&l).href, "#preview-wildcard");
    }
}
