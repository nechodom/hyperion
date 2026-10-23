//! The "Automatic wildcard renewal" card on Settings → HTTPS: the delegated
//! acme-dns zone, the DNS records that delegate it, and the delegated
//! wildcards that renew through it. Everything talks to the master's own
//! agent — the responder runs there.

use super::chrome;
use crate::auth::AuthCtx;
use crate::state::SharedState;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{AcmeDnsConfig, AcmeDnsLabel};
use serde::Deserialize;
use std::time::Duration;

/// How long the delegation check may take: a TXT walk over public recursors.
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
    pub tone: &'static str,
    pub verdict: &'static str,
    /// The CNAME checker's last complaint, or the verified date.
    pub note: String,
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
    pub enabled: bool,
    /// A zone has been saved (the Check button has something to check).
    pub configured: bool,
    pub listening: Vec<String>,
    pub last_error: Option<String>,
    /// A refused save, shown in the card.
    pub error: Option<String>,
    /// The config could not be read from the agent.
    pub unreadable: Option<String>,
    pub records: Vec<AcmeRecord>,
    pub labels: Vec<LabelRow>,
    /// The labels could not be read; the list must not read as empty.
    pub labels_error: Option<String>,
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

/// The records that delegate `zone` to this server: NS at the zone, glue
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
    match (&l.last_check_error, l.verified_at) {
        (Some(e), _) => LabelRow {
            base: l.base.clone(),
            tone: "warn",
            verdict: "CNAME not verified",
            note: e.clone(),
        },
        (None, Some(t)) => LabelRow {
            base: l.base.clone(),
            tone: "ok",
            verdict: "verified",
            note: super::fmt_date(Some(t)),
        },
        (None, None) => LabelRow {
            base: l.base.clone(),
            tone: "muted",
            verdict: "not checked yet",
            note: String::new(),
        },
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

/// Fill the card from the agent. `form` overrides the saved values when a
/// refused save re-renders the card with what the operator typed.
pub async fn load(
    state: &SharedState,
    ctx: &AuthCtx,
    panel_host: &str,
    form: Option<&AcmeForm>,
    error: Option<String>,
) -> AcmeCard {
    if !allowed(ctx) {
        return AcmeCard::default();
    }
    let mut card = AcmeCard {
        allowed: true,
        error,
        ..Default::default()
    };
    let saved =
        match crate::dispatcher::dispatch_to_node(state, None, Request::AcmeDnsConfigGet).await {
            Ok(RpcResponse::AcmeDnsConfig(c)) => c,
            Ok(RpcResponse::Error(e)) => {
                card.unreadable = Some(e.to_string());
                return card;
            }
            Ok(_) => {
                card.unreadable = Some("unexpected answer".into());
                return card;
            }
            Err(e) => {
                card.unreadable = Some(e.to_string());
                return card;
            }
        };
    card.configured = saved.zone.is_some();
    card.listening = saved.listening.clone();
    card.last_error = saved.last_error.clone();
    let (labels, labels_error) = labels_from(
        crate::dispatcher::dispatch_to_node(state, None, Request::AcmeDnsLabels)
            .await
            .map_err(|e| e.to_string()),
    );
    card.labels = labels;
    card.labels_error = labels_error;
    let pick = |typed: Option<&str>, saved: &str, suggestion: String| -> String {
        match typed {
            Some(t) => t.trim().to_string(),
            None if !saved.is_empty() => saved.to_string(),
            None => suggestion,
        }
    };
    let saved_v4 = saved.public_ipv4.clone().unwrap_or_default();
    let v4_suggestion = if saved_v4.is_empty() && form.is_none() {
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
        saved.zone.as_deref().unwrap_or(""),
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
    card.enabled = form.map_or(saved.enabled, |f| f.enabled.is_some());
    card.records = records(
        &card.zone,
        &card.ns_host,
        &card.public_ipv4,
        &card.public_ipv6,
    );
    card
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
}

fn blank(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// POST /settings/https/acme-dns — save the delegated zone. A refusal (port
/// 53 held, firewall failure, bad name) re-renders the page with the
/// message inside the card and what was typed; success redirects back.
pub async fn post_acme_dns(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<AcmeForm>,
) -> Result<Response, crate::error::AppError> {
    if !allowed(&ctx) {
        return Ok((StatusCode::FORBIDDEN, "admin role required").into_response());
    }
    let enabled = form.enabled.is_some();
    let req = Request::AcmeDnsConfigSet {
        zone: blank(&form.zone),
        ns_host: form.ns_host.trim().to_string(),
        public_ipv4: blank(&form.public_ipv4),
        public_ipv6: blank(&form.public_ipv6),
        enabled,
    };
    let refusal = match crate::dispatcher::dispatch_to_node(&state, None, req).await {
        Ok(RpcResponse::AcmeDnsConfig(_)) => {
            let msg = if enabled {
                "Delegated zone saved and the responder is on."
            } else {
                "Delegated zone saved; the responder is off."
            };
            return Ok(chrome::back_with_flash("acme-dns", msg));
        }
        Ok(RpcResponse::Error(e)) => e.to_string(),
        Ok(_) => "unexpected answer from the agent".to_string(),
        Err(e) => e.to_string(),
    };
    let html = super::page_https::render_page(
        &state,
        &ctx,
        Some(&form),
        Some(refusal),
        &Default::default(),
    )
    .await?;
    Ok(axum::response::Html(html).into_response())
}

/// The check pill: state word and the line under it.
fn check_cell(tone: &str, verdict: &str, note: &str) -> String {
    let esc = super::html_escape;
    let sub = if note.is_empty() {
        String::new()
    } else {
        format!("<span class=\"cell-sub\">{}</span>", esc(note))
    };
    format!("<span class=\"pill {tone}\">{}</span>{sub}", esc(verdict))
}

/// The verdict for a failed delegation check, from the probe's own words.
pub fn classify_check_error(e: &str) -> (&'static str, &'static str) {
    if e.contains("another panel") {
        ("warn", "points elsewhere")
    } else if e.contains("not delegated") {
        ("err", "delegation missing")
    } else {
        ("muted", "could not be checked")
    }
}

/// POST /settings/https/acme-dns/check — htmx partial: is the saved zone
/// delegated to this panel, seen from public resolvers?
pub async fn post_acme_dns_check(State(state): State<SharedState>, ctx: AuthCtx) -> Response {
    let html = |status: StatusCode, body: String| {
        (status, [("content-type", "text/html; charset=utf-8")], body).into_response()
    };
    if !allowed(&ctx) {
        return html(StatusCode::FORBIDDEN, check_cell("err", "not allowed", ""));
    }
    let config: AcmeDnsConfig =
        match crate::dispatcher::dispatch_to_node(&state, None, Request::AcmeDnsConfigGet).await {
            Ok(RpcResponse::AcmeDnsConfig(c)) => c,
            Ok(RpcResponse::Error(e)) => {
                return html(
                    StatusCode::OK,
                    check_cell("muted", "could not be checked", &e.to_string()),
                )
            }
            _ => {
                return html(
                    StatusCode::OK,
                    check_cell("muted", "could not be checked", "the agent did not answer"),
                )
            }
        };
    let Some(zone) = config.zone.as_deref().filter(|z| !z.is_empty()) else {
        return html(
            StatusCode::OK,
            check_cell("muted", "not set up", "save a zone first"),
        );
    };
    let body = match tokio::time::timeout(
        CHECK_TIMEOUT,
        state.dns_probe.zone_delegated(zone, &config.check_token),
    )
    .await
    {
        Ok(Ok(())) => check_cell("ok", "working", "the zone answers from this panel"),
        Ok(Err(e)) => {
            let (tone, verdict) = classify_check_error(&e);
            check_cell(tone, verdict, &e)
        }
        Err(_) => check_cell("muted", "could not be checked", "the lookup timed out"),
    };
    html(StatusCode::OK, body)
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

    #[test]
    fn check_errors_are_told_apart() {
        assert_eq!(
            classify_check_error(
                "_hyperion-check.z has no TXT record: the zone is not delegated to this panel"
            )
            .1,
            "delegation missing"
        );
        assert_eq!(
            classify_check_error(
                "answers with a different token: the zone is delegated to another panel"
            )
            .1,
            "points elsewhere"
        );
        assert_eq!(classify_check_error("timeout").1, "could not be checked");
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
}
