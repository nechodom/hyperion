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
use hyperion_types::{AgentConfigView, CertOverviewItem, ClusterConfigView, NodeSummary};
use std::time::Duration;

/// How long one node gets to list its certificates. A node that takes
/// longer reads "unknown" rather than holding the page.
const CERT_TIMEOUT: Duration = Duration::from_secs(4);

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
}
