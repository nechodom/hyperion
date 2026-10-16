//! `GET /settings/https` — the Let's Encrypt contact, the preview address
//! template, and each node's preview wildcard certificate.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{
    AgentConfigView, CertOverviewItem, ClusterConfigView, DnsCheckResult, NodeSummary,
};
use serde::Deserialize;
use std::time::Duration;

/// How long one node gets to list its certificates. A node that takes
/// longer reads "unknown" rather than holding the page.
const CERT_TIMEOUT: Duration = Duration::from_secs(4);

/// How long one node gets for its DNS check: two `dig`s, the authoritative
/// walk and the public-IP lookup. The check loads lazily, so it holds up
/// nothing but its own cell.
const DNS_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Template)]
#[template(path = "settings_https.html")]
struct HttpsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    config: AgentConfigView,
    config_error: Option<String>,
    /// The contact is a placeholder Let's Encrypt is never sent (the
    /// agent's built-in `admin@example.com`, `…@hyperion.invalid`).
    acme_placeholder: bool,
    /// This server's preview base — what its `*.<base>` wildcard covers —
    /// when the template yields one.
    preview_base: Option<String>,
    /// Where a site `mysite.com` on this server is previewed.
    preview_example: String,
    wildcard_rows: Vec<WildcardRow>,
    /// The card's state, worst row first. `None` when there are no rows.
    wildcard_summary: Option<(&'static str, &'static str)>,
    /// A base two or more nodes share. One wildcard DNS record points at
    /// one server, so all but one of them cannot serve their previews.
    shared_base: Option<String>,
}

/// One node's preview wildcard certificate, as the table shows it.
pub struct WildcardRow {
    pub node_id: String,
    pub label: String,
    /// The master, addressed by the `local` sentinel.
    pub is_master: bool,
    /// What a `*.<base>` certificate covers, e.g. `lab-01.example.com`.
    pub base: String,
    pub cert: CertState,
}

/// What the node said about its `*.<base>` certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertState {
    /// No answer in time, or not a certificate list. Never reported as
    /// "missing": a check that could not run is not a finding.
    Unknown,
    /// The node answered and holds no certificate for the base.
    Missing,
    /// The node holds one. `band` is CertOverview's: "ok", "warning"
    /// (< 30 d), "critical" (< 7 d) or "expired".
    Present {
        band: String,
        days_left: i64,
        expires: String,
    },
}

impl WildcardRow {
    pub fn wildcard(&self) -> String {
        format!("*.{}", self.base)
    }

    /// Is there a certificate to renew (rather than one to issue)?
    pub fn issued(&self) -> bool {
        matches!(self.cert, CertState::Present { .. })
    }

    /// Pill tone.
    pub fn tone(&self) -> &'static str {
        match &self.cert {
            CertState::Unknown => "muted",
            CertState::Missing => "warn",
            CertState::Present {
                band, days_left, ..
            } => {
                if *days_left < 0 || band == "expired" || band == "critical" {
                    "err"
                } else if band == "warning" {
                    "warn"
                } else {
                    "ok"
                }
            }
        }
    }

    /// Pill words.
    pub fn verdict(&self) -> String {
        match &self.cert {
            CertState::Unknown => "unknown".into(),
            CertState::Missing => "not issued".into(),
            CertState::Present {
                band, days_left, ..
            } => {
                if *days_left < 0 || band == "expired" {
                    "expired".into()
                } else if band == "critical" {
                    format!("expires in {days_left} d")
                } else if band == "warning" {
                    "renew soon".into()
                } else {
                    "valid".into()
                }
            }
        }
    }

    /// The line under the pill.
    pub fn note(&self) -> String {
        match &self.cert {
            CertState::Unknown => "the node did not answer".into(),
            CertState::Missing => String::new(),
            CertState::Present {
                band,
                days_left,
                expires,
            } => {
                if *days_left < 0 || band == "expired" {
                    format!("expired {expires} — issue it again")
                } else if band == "critical" {
                    format!("{expires} — renew now")
                } else {
                    format!("expires {expires} · {days_left} d")
                }
            }
        }
    }
}

pub async fn get_https(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, nodes) = chrome::chrome(&state, &ctx, "https", &q).await;
    let (config, config_error) = super::config_or_default(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView).await,
    );
    let preview_base = master_base(&config);
    let preview_example = preview_base
        .as_deref()
        .and_then(|b| ClusterConfigView::preview_subdomain("mysite.com", b))
        .unwrap_or_default();
    let mut wildcard_rows = wildcard_rows(&config.cluster, &config.hostname, &nodes);
    fill_cert_states(&state, &mut wildcard_rows).await;
    let tpl = HttpsTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        wildcard_summary: summary(&wildcard_rows),
        shared_base: shared_base(&wildcard_rows),
        wildcard_rows,
        preview_base,
        preview_example,
        acme_placeholder: config_error.is_none()
            && !config.acme.contact_email.trim().is_empty()
            && super::overview::acme_contact_missing(&config.acme.contact_email),
        config,
        config_error,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// The master's preview base. Its node id is its hostname here, the same
/// derivation `resolve_node_wildcard_base` uses when the Issue button posts.
fn master_base(config: &AgentConfigView) -> Option<String> {
    config
        .cluster
        .node_wildcard_base(&config.hostname, &config.hostname)
}

/// A row per node with a derivable base: the master first (by the `local`
/// sentinel, so a single server can issue its wildcard too), then every
/// worker. Previews are not a test-node feature, so no node is filtered out
/// for not being one.
pub fn wildcard_rows(
    cluster: &ClusterConfigView,
    master_hostname: &str,
    nodes: &[NodeSummary],
) -> Vec<WildcardRow> {
    let mut rows = Vec::with_capacity(nodes.len() + 1);
    if let Some(base) = cluster.node_wildcard_base(master_hostname, master_hostname) {
        rows.push(WildcardRow {
            node_id: crate::dispatcher::LOCAL_NODE_SENTINEL.to_string(),
            label: if master_hostname.trim().is_empty() {
                "This server".to_string()
            } else {
                master_hostname.to_string()
            },
            is_master: true,
            base,
            cert: CertState::Unknown,
        });
    }
    rows.extend(nodes.iter().filter_map(|n| {
        cluster
            .node_wildcard_base(&n.node_id, &n.label)
            .map(|base| WildcardRow {
                node_id: n.node_id.clone(),
                label: if n.label.trim().is_empty() {
                    n.node_id.clone()
                } else {
                    n.label.clone()
                },
                is_master: false,
                base,
                cert: CertState::Unknown,
            })
    }));
    rows
}

/// Ask every node for its certificates at once, each with its own
/// [`CERT_TIMEOUT`]: the page waits for the slowest node, not for the sum.
async fn fill_cert_states(state: &SharedState, rows: &mut [WildcardRow]) {
    let mut set = tokio::task::JoinSet::new();
    for (i, row) in rows.iter().enumerate() {
        let st = state.clone();
        let target = (!row.is_master).then(|| row.node_id.clone());
        set.spawn(async move {
            let res = tokio::time::timeout(
                CERT_TIMEOUT,
                crate::dispatcher::dispatch_to_node(&st, target.as_deref(), Request::CertOverview),
            )
            .await;
            let items = match res {
                Ok(Ok(RpcResponse::CertOverview(items))) => Some(items),
                _ => None,
            };
            (i, items)
        });
    }
    while let Some(joined) = set.join_next().await {
        if let Ok((i, items)) = joined {
            if let Some(row) = rows.get_mut(i) {
                row.cert = cert_state(&row.base, items.as_deref());
            }
        }
    }
}

/// The base's certificate in a node's list. A `*.<base>` certificate is
/// listed under its base domain, matched case-insensitively. `None` (no
/// answer) is Unknown, never Missing.
pub fn cert_state(base: &str, items: Option<&[CertOverviewItem]>) -> CertState {
    let Some(items) = items else {
        return CertState::Unknown;
    };
    match items.iter().find(|c| c.domain.eq_ignore_ascii_case(base)) {
        Some(c) => CertState::Present {
            band: if c.days_left < 0 {
                "expired".to_string()
            } else {
                c.band.clone()
            },
            days_left: c.days_left,
            expires: super::fmt_date(Some(c.not_after)),
        },
        None => CertState::Missing,
    }
}

/// The card's state in a pill: the worst row decides.
pub fn summary(rows: &[WildcardRow]) -> Option<(&'static str, &'static str)> {
    if rows.is_empty() {
        return None;
    }
    let any = |tone: &str| rows.iter().any(|r| r.tone() == tone);
    Some(if any("err") {
        ("err", "renew now")
    } else if rows.iter().any(|r| r.cert == CertState::Missing) {
        ("warn", "not issued yet")
    } else if any("warn") {
        ("warn", "renew soon")
    } else if any("muted") {
        ("muted", "unknown")
    } else {
        ("ok", "valid")
    })
}

/// The first base more than one node derives (a template without `{node}`
/// on a cluster), or `None`.
pub fn shared_base(rows: &[WildcardRow]) -> Option<String> {
    let mut seen = std::collections::BTreeSet::new();
    rows.iter()
        .find(|r| !seen.insert(r.base.to_ascii_lowercase()))
        .map(|r| r.base.clone())
}

/// Does a name under a node's preview base reach that node? A valid
/// `*.<base>` certificate says nothing about it: without the wildcard DNS
/// record every preview address is NXDOMAIN while the card reads "valid".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewDns {
    /// The check did not run (old agent, timeout, no base). Never reported
    /// as missing.
    Unknown(String),
    /// No A or AAAA record. `ip` is the node's own public IPv4, the value
    /// the record should hold, when the node knows it.
    Missing { ip: Option<String> },
    /// Every address is a Cloudflare edge. The universal certificate does
    /// not cover two-level subdomains, so the proxy breaks HTTPS here.
    Proxied,
    /// Resolves, but not to this node.
    Elsewhere { seen: Vec<String>, ours: String },
    /// Resolves to this node.
    Here { ip: String },
    /// Resolves; the node could not learn its own public IP to compare.
    Resolves { seen: Vec<String> },
}

impl PreviewDns {
    pub fn tone(&self) -> &'static str {
        match self {
            PreviewDns::Unknown(_) | PreviewDns::Resolves { .. } => "muted",
            PreviewDns::Missing { .. } => "err",
            PreviewDns::Proxied | PreviewDns::Elsewhere { .. } => "warn",
            PreviewDns::Here { .. } => "ok",
        }
    }

    pub fn verdict(&self) -> &'static str {
        match self {
            PreviewDns::Unknown(_) => "unknown",
            PreviewDns::Missing { .. } => "no record",
            PreviewDns::Proxied => "proxied",
            PreviewDns::Elsewhere { .. } => "points elsewhere",
            PreviewDns::Here { .. } => "points here",
            PreviewDns::Resolves { .. } => "resolves",
        }
    }
}

/// The verdict for one probe name. The node's own `DnsCheck` already
/// compares the records with its public IPs; this only orders the cases.
pub fn preview_dns(r: &DnsCheckResult) -> PreviewDns {
    let seen: Vec<String> = r
        .resolved_a
        .iter()
        .chain(&r.resolved_aaaa)
        .cloned()
        .collect();
    if seen.is_empty() {
        return PreviewDns::Missing {
            ip: r.our_public_ipv4.clone(),
        };
    }
    // `matches` is true for a proxied name too; proxied is the finding.
    if r.proxied {
        return PreviewDns::Proxied;
    }
    let ours: Vec<&String> = r.our_public_ipv4.iter().chain(&r.our_public_ipv6).collect();
    if r.matches {
        let ip = seen
            .iter()
            .find(|s| ours.contains(s))
            .unwrap_or(&seen[0])
            .clone();
        return PreviewDns::Here { ip };
    }
    match ours.first() {
        Some(o) => PreviewDns::Elsewhere {
            seen,
            ours: (*o).clone(),
        },
        None => PreviewDns::Resolves { seen },
    }
}

/// The DNS cell: a pill and the line under it.
pub fn render_preview_dns(base: &str, dns: &PreviewDns) -> String {
    let esc = super::html_escape;
    let note = match dns {
        PreviewDns::Unknown(why) => format!(
            "<span class=\"cell-sub\" title=\"{}\">could not be checked</span>",
            esc(why)
        ),
        PreviewDns::Missing { ip } => format!(
            "<span class=\"cell-sub\">previews do not resolve — add <code>*.{}</code> A {}</span>",
            esc(base),
            ip.as_deref()
                .map(|ip| format!("<code>{}</code>", esc(ip)))
                .unwrap_or_else(|| "pointing at this node".into())
        ),
        PreviewDns::Proxied => {
            "<span class=\"cell-sub\">Cloudflare proxy on — set the record to DNS only</span>"
                .to_string()
        }
        PreviewDns::Elsewhere { seen, ours } => format!(
            "<span class=\"cell-sub\">{} — this node is <code>{}</code></span>",
            esc(&seen.join(", ")),
            esc(ours)
        ),
        PreviewDns::Here { ip } => format!("<span class=\"cell-sub\">{}</span>", esc(ip)),
        PreviewDns::Resolves { seen } => format!(
            "<span class=\"cell-sub\">{} · this node's IP unknown</span>",
            esc(&seen.join(", "))
        ),
    };
    format!(
        "<span class=\"pill {}\">{}</span>{note}",
        dns.tone(),
        dns.verdict()
    )
}

/// A made-up name under the base. Fresh each time, so no resolver can
/// answer from a cached NXDOMAIN of an earlier check.
fn probe_name(base: &str) -> String {
    format!("hyperion-check-{:08x}.{base}", rand::random::<u32>())
}

#[derive(Deserialize)]
pub struct PreviewDnsQuery {
    #[serde(default)]
    pub node_id: String,
}

/// GET /settings/https/preview-dns?node_id=… — the DNS cell of one row.
/// The node itself resolves a made-up name under its base and compares
/// the answer with its own public IP (`DnsCheck`). Lazy per row: the
/// public-IP lookup alone can take seconds.
pub async fn get_preview_dns(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PreviewDnsQuery>,
) -> Response {
    let html = |status: axum::http::StatusCode, body: String| {
        (status, [("content-type", "text/html; charset=utf-8")], body).into_response()
    };
    if !ctx.can(Capability::SettingsManage) {
        return html(
            axum::http::StatusCode::FORBIDDEN,
            "<span class=\"pill err\">not allowed</span>".into(),
        );
    }
    let node_id = q.node_id.trim();
    if node_id.is_empty()
        || !node_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return html(
            axum::http::StatusCode::BAD_REQUEST,
            "<span class=\"pill err\">invalid node id</span>".into(),
        );
    }
    // The base comes from the config, never from the query string.
    let Some((_, base)) = super::resolve_node_wildcard_base(&state, node_id).await else {
        return html(
            axum::http::StatusCode::OK,
            render_preview_dns("", &PreviewDns::Unknown("no preview base".into())),
        );
    };
    let dns = match hyperion_validate::Domain::parse(&probe_name(&base)) {
        Err(e) => PreviewDns::Unknown(e.to_string()),
        Ok(domain) => match tokio::time::timeout(
            DNS_TIMEOUT,
            crate::dispatcher::dispatch_to_node(
                &state,
                Some(node_id),
                Request::DnsCheck { domain },
            ),
        )
        .await
        {
            Ok(Ok(RpcResponse::DnsCheck(r))) => preview_dns(&r),
            Ok(Ok(RpcResponse::Error(e))) => PreviewDns::Unknown(e.to_string()),
            Ok(Ok(_)) => PreviewDns::Unknown("unexpected response".into()),
            Ok(Err(e)) => PreviewDns::Unknown(e.to_string()),
            Err(_) => PreviewDns::Unknown("the node did not answer in time".into()),
        },
    };
    html(axum::http::StatusCode::OK, render_preview_dns(&base, &dns))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, label: &str) -> NodeSummary {
        NodeSummary {
            node_id: id.into(),
            label: label.into(),
            master_url: None,
            agent_version: String::new(),
            public_ip: None,
            enrolled_at: 0,
            last_seen_at: 0,
            is_drained: false,
            drain_reason: String::new(),
            tls_spki_pin: None,
            resp_pubkey: None,
            rpc_port: None,
            external_ip: None,
        }
    }

    fn cluster(template: &str) -> ClusterConfigView {
        ClusterConfigView {
            test_domain_template: template.into(),
            ..Default::default()
        }
    }

    fn cert(domain: &str, days_left: i64, band: &str) -> CertOverviewItem {
        CertOverviewItem {
            domain: domain.into(),
            issuer: String::new(),
            issued_at: 0,
            not_after: 1_800_000_000,
            days_left,
            band: band.into(),
            node_id: String::new(),
        }
    }

    fn row(cert: CertState) -> WildcardRow {
        WildcardRow {
            node_id: "n".into(),
            label: "n".into(),
            is_master: false,
            base: "n.example.com".into(),
            cert,
        }
    }

    #[test]
    fn no_template_means_no_rows() {
        let rows = wildcard_rows(
            &cluster(""),
            "s4.example.com",
            &[node("w1", "w1.example.com")],
        );
        assert!(rows.is_empty());
    }

    #[test]
    fn master_comes_first_by_the_local_sentinel_then_workers() {
        let rows = wildcard_rows(
            &cluster("{name}.{node}.preview.example.com"),
            "s4",
            &[node("node_01", "lab-01"), node("node_02", "")],
        );
        let got: Vec<(&str, &str, &str, bool)> = rows
            .iter()
            .map(|r| {
                (
                    r.node_id.as_str(),
                    r.label.as_str(),
                    r.base.as_str(),
                    r.is_master,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("local", "s4", "s4.preview.example.com", true),
                ("node_01", "lab-01", "lab-01.preview.example.com", false),
                // No label: the id names the row and fills `{node}`.
                ("node_02", "node_02", "node_02.preview.example.com", false),
            ]
        );
        assert!(rows.iter().all(|r| r.cert == CertState::Unknown));
        assert_eq!(rows[1].wildcard(), "*.lab-01.preview.example.com");
    }

    #[test]
    fn a_template_without_a_parent_domain_gives_no_row() {
        // `{name}.com` leaves `*.com`, never a safe wildcard.
        assert!(wildcard_rows(&cluster("{name}.com"), "s4", &[]).is_empty());
    }

    #[test]
    fn an_unanswered_node_is_unknown_not_missing() {
        assert_eq!(cert_state("a.example.com", None), CertState::Unknown);
        assert_eq!(cert_state("a.example.com", Some(&[])), CertState::Missing);
        let unknown = row(CertState::Unknown);
        assert_eq!(
            (unknown.tone(), unknown.verdict().as_str()),
            ("muted", "unknown")
        );
    }

    #[test]
    fn the_certificate_is_matched_by_base_case_insensitively() {
        let items = [
            cert("other.example.com", 80, "ok"),
            cert("A.Example.com", 80, "ok"),
        ];
        match cert_state("a.example.com", Some(&items)) {
            CertState::Present {
                band, days_left, ..
            } => {
                assert_eq!(band, "ok");
                assert_eq!(days_left, 80);
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn negative_days_read_as_expired_whatever_the_band() {
        let items = [cert("a.example.com", -2, "critical")];
        let r = WildcardRow {
            cert: cert_state("a.example.com", Some(&items)),
            ..row(CertState::Unknown)
        };
        assert_eq!((r.tone(), r.verdict().as_str()), ("err", "expired"));
        assert!(r.issued());
    }

    #[test]
    fn bands_map_to_pills() {
        let p = |band: &str, days: i64| {
            row(CertState::Present {
                band: band.into(),
                days_left: days,
                expires: "2027-01-01".into(),
            })
        };
        assert_eq!(
            (p("ok", 70).tone(), p("ok", 70).verdict()),
            ("ok", "valid".into())
        );
        assert_eq!(p("warning", 20).tone(), "warn");
        assert_eq!(p("critical", 3).verdict(), "expires in 3 d");
        assert_eq!(p("critical", 3).tone(), "err");
        assert_eq!(row(CertState::Missing).tone(), "warn");
        assert!(!row(CertState::Missing).issued());
    }

    #[test]
    fn the_summary_takes_the_worst_row() {
        let ok = || {
            row(CertState::Present {
                band: "ok".into(),
                days_left: 70,
                expires: String::new(),
            })
        };
        assert_eq!(summary(&[]), None);
        assert_eq!(summary(&[ok(), ok()]), Some(("ok", "valid")));
        assert_eq!(
            summary(&[ok(), row(CertState::Unknown)]),
            Some(("muted", "unknown"))
        );
        assert_eq!(
            summary(&[row(CertState::Unknown), row(CertState::Missing)]),
            Some(("warn", "not issued yet"))
        );
        let expired = row(CertState::Present {
            band: "expired".into(),
            days_left: -1,
            expires: String::new(),
        });
        assert_eq!(
            summary(&[row(CertState::Missing), expired]),
            Some(("err", "renew now"))
        );
    }

    #[test]
    fn a_template_without_node_makes_nodes_share_a_base() {
        let nodes = [node("node_01", "lab-01")];
        let shared = wildcard_rows(&cluster("{name}.preview.example.com"), "s4", &nodes);
        assert_eq!(shared_base(&shared).as_deref(), Some("preview.example.com"));
        let own = wildcard_rows(&cluster("{name}.{node}.preview.example.com"), "s4", &nodes);
        assert_eq!(shared_base(&own), None);
    }

    fn dns(a: &[&str], ours: Option<&str>, matches: bool, proxied: bool) -> DnsCheckResult {
        DnsCheckResult {
            domain: "hyperion-check-0.n.example.com".into(),
            resolved_a: a.iter().map(|s| s.to_string()).collect(),
            resolved_aaaa: vec![],
            our_public_ipv4: ours.map(str::to_string),
            our_public_ipv6: None,
            matches,
            note: String::new(),
            proxied,
            origin_cert_self_signed: false,
        }
    }

    #[test]
    fn no_record_under_the_base_is_missing_with_the_ip_to_add() {
        // The reported case: `*.hos-1` never published, certificate valid.
        let d = preview_dns(&dns(&[], Some("37.27.109.116"), false, false));
        assert_eq!(
            d,
            PreviewDns::Missing {
                ip: Some("37.27.109.116".into())
            }
        );
        assert_eq!((d.tone(), d.verdict()), ("err", "no record"));
        let html = render_preview_dns("hos-1.digitalka.cz", &d);
        assert!(html.contains("<code>*.hos-1.digitalka.cz</code> A <code>37.27.109.116</code>"));
        let unknown_ip = render_preview_dns("a.example.com", &PreviewDns::Missing { ip: None });
        assert!(unknown_ip.contains("pointing at this node"));
    }

    #[test]
    fn a_record_at_this_node_points_here() {
        let d = preview_dns(&dns(&["178.105.99.35"], Some("178.105.99.35"), true, false));
        assert_eq!(
            d,
            PreviewDns::Here {
                ip: "178.105.99.35".into()
            }
        );
        assert_eq!(d.tone(), "ok");
    }

    #[test]
    fn proxied_wins_over_matches() {
        // DnsCheck reports a proxied name as matching; for a two-level
        // wildcard the proxy is the problem.
        let d = preview_dns(&dns(&["104.16.1.1"], Some("1.2.3.4"), true, true));
        assert_eq!(d, PreviewDns::Proxied);
        assert_eq!(d.tone(), "warn");
    }

    #[test]
    fn another_address_points_elsewhere_or_is_unverified_without_our_ip() {
        let d = preview_dns(&dns(&["5.6.7.8"], Some("1.2.3.4"), false, false));
        assert_eq!(
            d,
            PreviewDns::Elsewhere {
                seen: vec!["5.6.7.8".into()],
                ours: "1.2.3.4".into()
            }
        );
        assert_eq!(d.verdict(), "points elsewhere");
        let d = preview_dns(&dns(&["5.6.7.8"], None, false, false));
        assert_eq!(
            d,
            PreviewDns::Resolves {
                seen: vec!["5.6.7.8".into()]
            }
        );
        assert_eq!(d.tone(), "muted");
    }

    #[test]
    fn the_dns_cell_escapes_what_it_shows() {
        let html = render_preview_dns("x.example.com", &PreviewDns::Unknown("<b>\"".into()));
        assert!(html.contains("title=\"&lt;b&gt;&quot;\""));
        assert!(html.starts_with("<span class=\"pill muted\">unknown</span>"));
    }

    #[test]
    fn the_probe_name_is_a_valid_fresh_name_under_the_base() {
        let a = probe_name("hos-1.digitalka.cz");
        assert!(a.starts_with("hyperion-check-") && a.ends_with(".hos-1.digitalka.cz"));
        assert!(hyperion_validate::Domain::parse(&a).is_ok());
        assert_ne!(a, probe_name("hos-1.digitalka.cz"));
    }
}
