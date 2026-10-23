//! Unattended renewal of wildcard certificates whose `_acme-challenge` is
//! CNAME-delegated to the panel's acme zone.
//!
//! Once a day the master finds every Let's Encrypt wildcard inside the
//! renewal window whose base has a delegation label, and renews it in
//! one pass: confirm the customer's CNAME still points at us, start the
//! order on the node that owns the cert, serve the TXT values from the
//! master's responder, wait until the public resolvers see them, then
//! finish fail-closed. The values are withdrawn whatever happens.
//!
//! Only the master runs this: it holds the responder and the labels, and
//! it is the only node that can sign RPCs to the workers.

use crate::dispatcher::{DispatchError, LOCAL_NODE_SENTINEL};
use crate::state::SharedState;
use async_trait::async_trait;
use hyperion_adapters::dns_probe::{self, CnameProblem};
use hyperion_rpc::codec::{Request, Response};
use hyperion_rpc::wire::HostingSelector;
use hyperion_rpc_client::RemoteClientError;
use hyperion_types::{AcmeDnsLabel, CertOverviewItem, HostingId};
use hyperion_validate::Domain;
use std::time::Duration;

/// Let the agent and the node list settle after a restart first.
const FIRST_RUN_DELAY: Duration = Duration::from_secs(10 * 60);
const INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Public resolvers may cache the empty answer from before the values
/// were set; a minute covers the responder's 60 s TTL.
const TXT_ATTEMPTS: usize = 6;
const TXT_RETRY: Duration = Duration::from_secs(10);

/// A delegated wildcard the master should renew now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueCert {
    /// Owning node; `None` = the master itself.
    pub node_id: Option<String>,
    pub domain: String,
    /// `None` = a preview base, issued through the bare-domain RPCs.
    pub hosting_id: Option<String>,
    pub label: AcmeDnsLabel,
    /// Days left on the wildcard now; `None` = there is none yet (a first
    /// issuance), so a failure has no expiry to alert about.
    pub days_left: Option<i64>,
}

/// LE-issued (issuer starts with "letsencrypt", staging included),
/// `renewal_type != "manual"`, wildcard, `days_left <= window_days`, and a
/// label exists for the domain. A blank or `local` node means the master.
pub fn select_due(
    items: &[(Option<String>, CertOverviewItem)],
    labels: &[AcmeDnsLabel],
    window_days: i64,
) -> Vec<DueCert> {
    let mut due: Vec<DueCert> = Vec::new();
    for (node, item) in items {
        let node_id = local_or(node.as_deref());
        if !item.issuer.starts_with("letsencrypt")
            || item.renewal_type == "manual"
            || !item.wildcard
            || item.days_left > window_days
        {
            continue;
        }
        let Some(label) = labels
            .iter()
            .find(|l| l.base.eq_ignore_ascii_case(&item.domain))
        else {
            continue;
        };
        if due
            .iter()
            .any(|d| d.node_id == node_id && d.domain == item.domain)
        {
            continue;
        }
        due.push(DueCert {
            node_id,
            domain: item.domain.clone(),
            hosting_id: item.hosting_id.clone(),
            label: label.clone(),
            days_left: Some(item.days_left),
        });
    }
    due
}

/// `None` for the master (absent, blank, the `local` sentinel).
fn local_or(node: Option<&str>) -> Option<String> {
    node.map(str::trim)
        .filter(|s| !s.is_empty() && *s != LOCAL_NODE_SENTINEL)
        .map(str::to_string)
}

/// One daily pass: every due delegated wildcard, then the delegated flag on
/// each cert brought in line with its label. Returns `(domain, outcome)`
/// per renewal attempted. Does nothing off the master or with the zone
/// disabled.
pub async fn run_once(state: &SharedState) -> Vec<(String, Result<(), String>)> {
    if state.deployment_mode.read().await.as_str() != "master" {
        return Vec::new();
    }
    run_once_with(&Live(state)).await
}

/// Renew one delegated wildcard now: read the acme-dns config (refused when
/// disabled), prove the zone delegation, then CNAME check, begin, publish,
/// wait for public visibility, strict finish, withdraw, report. Ignores
/// the renewal window, so it also serves a first issuance. Refused off the
/// master, and while another renewal of the same label is running. Once
/// the pre-flight passed, the outcome is reported to the master agent
/// (audit, and an alert on failure) as well as returned.
pub async fn renew_one(state: &SharedState, due: &DueCert) -> Result<(), String> {
    if state.deployment_mode.read().await.as_str() != "master" {
        return Err("automatic wildcard renewal runs on the master only".into());
    }
    renew_one_with(&Live(state), due, None).await
}

/// Labels with a renewal in progress. `AcmeDnsValuesSet` replaces a
/// label's values and `AcmeDnsValuesClear` drops them, so two orders on one
/// label would withdraw each other's values while the CA validates.
#[derive(Default)]
struct InFlight(std::sync::Mutex<std::collections::HashSet<String>>);

/// Holds one label in [`InFlight`] until dropped.
struct Claim<'a> {
    set: &'a InFlight,
    key: String,
}

impl InFlight {
    fn claim(&self, key: &str) -> Option<Claim<'_>> {
        let mut set = self.0.lock().unwrap_or_else(|p| p.into_inner());
        set.insert(key.to_string()).then(|| Claim {
            set: self,
            key: key.to_string(),
        })
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        let mut set = self.set.0.lock().unwrap_or_else(|p| p.into_inner());
        set.remove(&self.key);
    }
}

static IN_FLIGHT: std::sync::LazyLock<InFlight> = std::sync::LazyLock::new(InFlight::default);

/// First run 10 minutes after start, then daily.
pub fn spawn(state: SharedState) {
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval_at(tokio::time::Instant::now() + FIRST_RUN_DELAY, INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            for (domain, outcome) in run_once(&state).await {
                match outcome {
                    Ok(()) => tracing::info!(domain, "acme-dns: wildcard renewed"),
                    Err(error) => tracing::warn!(domain, error, "acme-dns: renewal failed"),
                }
            }
        }
    });
}

/// Everything the renewal touches outside this module, so the tests run
/// without sockets or DNS.
#[async_trait]
trait Backend: Send + Sync {
    async fn dispatch(&self, node: Option<&str>, req: Request) -> Result<Response, DispatchError>;
    /// Ids of the enrolled workers.
    async fn remote_nodes(&self) -> Result<Vec<String>, String>;
    async fn is_master_hostname(&self, node_id: &str) -> bool;
    async fn zone_delegated(&self, zone: &str, check_token: &str) -> Result<(), String>;
    async fn cname(&self, name: &str, target: &str) -> Result<(), CnameProblem>;
    async fn txt_visible(&self, name: &str, values: &[String]) -> Result<(), String>;
    async fn pause(&self, d: Duration);
    fn in_flight(&self) -> &InFlight;
}

struct Live<'a>(&'a SharedState);

#[async_trait]
impl Backend for Live<'_> {
    async fn dispatch(&self, node: Option<&str>, req: Request) -> Result<Response, DispatchError> {
        crate::dispatcher::dispatch_to_node(self.0, node, req).await
    }
    async fn remote_nodes(&self) -> Result<Vec<String>, String> {
        crate::dispatcher::cached_nodes(self.0)
            .await
            .map(|nodes| nodes.into_iter().map(|n| n.node_id).collect())
            .map_err(|e| e.to_string())
    }
    async fn is_master_hostname(&self, node_id: &str) -> bool {
        crate::dispatcher::is_master_hostname(self.0, node_id).await
    }
    async fn zone_delegated(&self, zone: &str, check_token: &str) -> Result<(), String> {
        dns_probe::check_zone_delegated(zone, check_token).await
    }
    async fn cname(&self, name: &str, target: &str) -> Result<(), CnameProblem> {
        dns_probe::check_cname(name, target).await
    }
    async fn txt_visible(&self, name: &str, values: &[String]) -> Result<(), String> {
        dns_probe::txt_visible_via_public(name, values).await
    }
    async fn pause(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
    fn in_flight(&self) -> &InFlight {
        &IN_FLIGHT
    }
}

/// Send a master-local side-effect request; `Err` carries why it did not
/// take, already logged.
async fn confirm<B: Backend>(b: &B, req: Request, ok: fn(&Response) -> bool) -> Result<(), String> {
    let what = <&'static str>::from(&req);
    let outcome = match b.dispatch(None, req).await {
        Ok(r) if ok(&r) => return Ok(()),
        Ok(Response::Error(e)) => e.to_string(),
        Ok(other) => format!("unexpected answer {other:?}"),
        Err(e) => e.to_string(),
    };
    tracing::warn!(
        request = what,
        error = outcome,
        "acme-dns: master agent did not apply"
    );
    Err(outcome)
}

/// Every cert in the cluster, tagged with its owning node (`None` = the
/// master; a node entry that is really the master's hostname is not asked
/// twice). A node that does not answer contributes nothing.
async fn gather<B: Backend>(b: &B) -> Vec<(Option<String>, CertOverviewItem)> {
    let mut all = Vec::new();
    match b.dispatch(None, Request::CertOverview).await {
        Ok(Response::CertOverview(items)) => all.extend(items.into_iter().map(|i| (None, i))),
        Ok(other) => tracing::warn!(?other, "acme-dns: local cert overview refused"),
        Err(e) => tracing::warn!(error = %e, "acme-dns: local cert overview failed"),
    }
    let nodes = b.remote_nodes().await.unwrap_or_else(|e| {
        tracing::warn!(error = e, "acme-dns: node list failed");
        Vec::new()
    });
    for id in nodes {
        // The master's own hostname is the local agent, already asked.
        if b.is_master_hostname(&id).await {
            continue;
        }
        match b.dispatch(Some(&id), Request::CertOverview).await {
            Ok(Response::CertOverview(items)) => {
                all.extend(items.into_iter().map(|i| (Some(id.clone()), i)))
            }
            Ok(other) => tracing::warn!(node = id, ?other, "acme-dns: cert overview refused"),
            Err(e) => tracing::warn!(node = id, error = %e, "acme-dns: cert overview failed"),
        }
    }
    all
}

/// The configured zone and its check token; `None` while acme-dns is
/// disabled.
async fn enabled_zone<B: Backend>(b: &B) -> Result<Option<(String, String)>, String> {
    let config = match b.dispatch(None, Request::AcmeDnsConfigGet).await {
        Ok(Response::AcmeDnsConfig(c)) => c,
        Ok(Response::Error(e)) => return Err(format!("reading the acme-dns config: {e}")),
        Ok(other) => {
            return Err(format!(
                "reading the acme-dns config: unexpected answer {other:?}"
            ))
        }
        Err(e) => return Err(format!("reading the acme-dns config: {e}")),
    };
    match config.zone {
        Some(z) if config.enabled && !z.is_empty() => Ok(Some((z, config.check_token))),
        _ => Ok(None),
    }
}

async fn run_once_with<B: Backend>(b: &B) -> Vec<(String, Result<(), String>)> {
    let (zone, check_token) = match enabled_zone(b).await {
        Ok(Some(z)) => z,
        Ok(None) => return Vec::new(),
        Err(e) => {
            tracing::warn!(error = e, "acme-dns: renewal skipped");
            return Vec::new();
        }
    };
    if let Err(detail) = b.zone_delegated(&zone, &check_token).await {
        let _ = confirm(b, Request::AcmeDnsZoneBroken { detail }, |r| {
            matches!(r, Response::AcmeDnsZoneBroken)
        })
        .await;
        return Vec::new();
    }
    let items = gather(b).await;
    let labels = sweep_orphans(b, labels(b).await).await;
    let due = select_due(
        &items,
        &labels,
        hyperion_core::service::CERT_RENEWAL_WINDOW_DAYS,
    );
    let mut results = Vec::with_capacity(due.len());
    for d in &due {
        results.push((d.domain.clone(), renew_one_with(b, d, Some(&zone)).await));
    }
    // The CNAME checks above moved some labels' verified stamps.
    sync_delegated(b, &items, &labels_after(b, due.is_empty(), labels).await).await;
    results
}

async fn labels<B: Backend>(b: &B) -> Vec<AcmeDnsLabel> {
    match b.dispatch(None, Request::AcmeDnsLabels).await {
        Ok(Response::AcmeDnsLabels(l)) => l,
        other => {
            tracing::warn!(?other, "acme-dns: labels not readable");
            Vec::new()
        }
    }
}

/// Drop the labels of hostings no node has any more (a trash purge by the
/// node's own retention sweep never passes through the panel). A label is
/// only dropped when EVERY node answered and none knows the hosting; a
/// node that did not answer keeps it. Returns the labels left.
async fn sweep_orphans<B: Backend>(b: &B, labels: Vec<AcmeDnsLabel>) -> Vec<AcmeDnsLabel> {
    if labels.iter().all(|l| l.hosting_id.is_none()) {
        return labels;
    }
    let mut nodes: Vec<Option<String>> = vec![None];
    match b.remote_nodes().await {
        Ok(ids) => {
            for id in ids {
                if !b.is_master_hostname(&id).await {
                    nodes.push(Some(id));
                }
            }
        }
        Err(e) => {
            tracing::debug!(
                error = e,
                "acme-dns: orphan sweep skipped, node list failed"
            );
            return labels;
        }
    }
    let mut kept = Vec::with_capacity(labels.len());
    for label in labels {
        let Some(hosting_id) = label.hosting_id.clone() else {
            kept.push(label);
            continue;
        };
        if !hosting_gone_everywhere(b, &nodes, &hosting_id).await {
            kept.push(label);
            continue;
        }
        let Ok(base) = Domain::parse(&label.base) else {
            kept.push(label);
            continue;
        };
        match confirm(b, Request::AcmeDnsLabelDelete { base }, |r| {
            matches!(r, Response::AcmeDnsLabelDelete)
        })
        .await
        {
            Ok(()) => tracing::info!(
                base = label.base,
                hosting_id,
                "acme-dns: label of a deleted hosting dropped"
            ),
            Err(_) => kept.push(label),
        }
    }
    kept
}

/// Every node said "no such hosting". Any other answer, or none, is a no.
async fn hosting_gone_everywhere<B: Backend>(
    b: &B,
    nodes: &[Option<String>],
    hosting_id: &str,
) -> bool {
    for node in nodes {
        let sel = HostingSelector::Id(HostingId::from(hosting_id.to_string()));
        match b.dispatch(node.as_deref(), Request::HostingGet(sel)).await {
            Ok(Response::Error(hyperion_rpc::RpcError::NotFound { .. })) => {}
            other => {
                if !matches!(other, Ok(Response::HostingGet(_))) {
                    tracing::debug!(
                        ?node,
                        hosting_id,
                        ?other,
                        "acme-dns: label kept, node gave no definite answer"
                    );
                }
                return false;
            }
        }
    }
    true
}

/// The labels again, unless nothing was checked since they were read.
async fn labels_after<B: Backend>(
    b: &B,
    unchanged: bool,
    before: Vec<AcmeDnsLabel>,
) -> Vec<AcmeDnsLabel> {
    if unchanged {
        before
    } else {
        labels(b).await
    }
}

/// Point each wildcard's `delegated` flag at its label's last verdict, on
/// the node that owns the cert, so node-side expiry alerts know whether
/// the master is renewing it. Only changed flags are sent.
async fn sync_delegated<B: Backend>(
    b: &B,
    items: &[(Option<String>, CertOverviewItem)],
    labels: &[AcmeDnsLabel],
) {
    for label in labels {
        let delegated = label.verified_at.is_some() && label.last_check_error.is_none();
        for (node, item) in items {
            if !item.wildcard
                || !item.domain.eq_ignore_ascii_case(&label.base)
                || item.delegated == delegated
            {
                continue;
            }
            let Ok(domain) = Domain::parse(&item.domain) else {
                continue;
            };
            let node = local_or(node.as_deref());
            match b
                .dispatch(
                    node.as_deref(),
                    Request::CertSetDelegated { domain, delegated },
                )
                .await
            {
                Ok(Response::CertSetDelegated) => {}
                other => tracing::warn!(
                    ?node,
                    domain = item.domain,
                    ?other,
                    "acme-dns: delegated flag not updated"
                ),
            }
        }
    }
}

/// One cert, end to end. `verified_zone` = the zone this run already
/// proved delegated; `None` reads the config and probes it first.
async fn renew_one_with<B: Backend>(
    b: &B,
    due: &DueCert,
    verified_zone: Option<&str>,
) -> Result<(), String> {
    let Some(_claim) = b.in_flight().claim(&due.label.label) else {
        return Err(format!("a renewal for {} is already running", due.domain));
    };
    let zone = match verified_zone {
        Some(z) => z.to_string(),
        None => preflight(b).await?,
    };
    let (outcome, not_withdrawn) = attempt(b, &zone, due).await;
    let (ok, mut detail, days_left) = match &outcome {
        Ok(Some(days)) => (
            true,
            "renewed over the delegated acme zone".to_string(),
            Some(*days),
        ),
        Ok(None) => (
            true,
            "the CA issued without a new challenge".to_string(),
            due.days_left,
        ),
        Err(e) => (false, e.clone(), due.days_left),
    };
    if let Some(why) = not_withdrawn {
        detail.push_str(&format!(" (TXT values not withdrawn: {why})"));
    }
    // No expiry known (a first issuance that failed): the agent would alert
    // "0 days left" on a certificate that does not exist. The caller's job
    // carries the failure instead.
    if let Some(days_left) = days_left {
        let report = Request::AcmeDnsRenewReport {
            domain: due.domain.clone(),
            node_id: due.node_id.clone().unwrap_or_default(),
            ok,
            detail,
            days_left,
        };
        let _ = confirm(b, report, |r| matches!(r, Response::AcmeDnsRenewReport)).await;
    }
    outcome.map(|_| ())
}

/// No order unless acme-dns is enabled and its zone provably delegated to
/// this panel. Returns the zone.
async fn preflight<B: Backend>(b: &B) -> Result<String, String> {
    let (zone, check_token) = enabled_zone(b)
        .await?
        .ok_or("the delegated acme zone is not enabled")?;
    b.zone_delegated(&zone, &check_token)
        .await
        .map_err(|e| format!("the delegated acme zone does not resolve to this panel: {e}"))?;
    Ok(zone)
}

/// The renewal itself. `Ok(Some(days))` = new cert, `days` until it
/// expires; `Ok(None)` = the CA issued at once (authorizations still
/// valid), so nothing was published. The second half is why the TXT
/// values could not be withdrawn, if they could not.
async fn attempt<B: Backend>(
    b: &B,
    zone: &str,
    due: &DueCert,
) -> (Result<Option<i64>, String>, Option<String>) {
    match order(b, zone, due).await {
        Order::Done(outcome) => (outcome, None),
        Order::Published(outcome) => {
            // Withdraw the values on every path once they may have been served.
            let clear = Request::AcmeDnsValuesClear {
                label: due.label.label.clone(),
            };
            let cleared = confirm(b, clear, |r| matches!(r, Response::AcmeDnsValuesClear)).await;
            (outcome.map(Some), cleared.err())
        }
    }
}

enum Order {
    /// Ended before any value was handed to the responder.
    Done(Result<Option<i64>, String>),
    /// Values were (or may have been) published; they must be withdrawn.
    Published(Result<i64, String>),
}

async fn order<B: Backend>(b: &B, zone: &str, due: &DueCert) -> Order {
    match begin(b, zone, due).await {
        Ok(Begun::Issued) => Order::Done(Ok(None)),
        Ok(Begun::Publish {
            challenge,
            values,
            finish,
        }) => Order::Published(
            publish_and_finish(
                b,
                due.node_id.as_deref(),
                &due.label.label,
                &challenge,
                values,
                *finish,
            )
            .await,
        ),
        Err(e) => Order::Done(Err(e)),
    }
}

enum Begun {
    Issued,
    Publish {
        challenge: String,
        values: Vec<String>,
        finish: Box<Request>,
    },
}

/// CNAME check, then start the order on the owning node and vet the TXT
/// records it asks for.
async fn begin<B: Backend>(b: &B, zone: &str, due: &DueCert) -> Result<Begun, String> {
    let challenge = due.label.challenge_name();
    let base = Domain::parse(&due.label.base).map_err(|e| e.to_string())?;
    let cname = b.cname(&challenge, &due.label.target(zone)).await;
    let mark = Request::AcmeDnsLabelMark {
        base,
        ok: cname.is_ok(),
        error: cname.as_ref().err().map(CnameProblem::to_string),
    };
    let _ = confirm(b, mark, |r| matches!(r, Response::AcmeDnsLabelMark)).await;
    if let Err(problem) = cname {
        return Err(format!("{challenge}: {problem}"));
    }

    let node = due.node_id.as_deref();
    let domain = || Domain::parse(&due.domain).map_err(|e| e.to_string());
    let begin = match &due.hosting_id {
        Some(h) => Request::CertDns01Begin {
            sel: HostingSelector::Id(HostingId::from(h.clone())),
            staging: false,
        },
        None => Request::CertDns01BeginDomain {
            domain: domain()?,
            email: None,
            staging: false,
        },
    };
    let records = match b.dispatch(node, begin).await {
        Ok(
            Response::CertDns01Begin {
                completed: true, ..
            }
            | Response::CertDns01BeginDomain {
                completed: true, ..
            },
        ) => return Ok(Begun::Issued),
        Ok(
            Response::CertDns01Begin { records, .. }
            | Response::CertDns01BeginDomain { records, .. },
        ) => records,
        Ok(Response::Error(e)) => return Err(format!("starting the order: {e}")),
        Ok(other) => return Err(format!("starting the order: unexpected answer {other:?}")),
        Err(e) => return Err(format!("starting the order: {e}")),
    };
    if records.is_empty() {
        return Err("starting the order: the CA asked for no TXT record".into());
    }
    if let Some((name, _)) = records.iter().find(|(n, _)| !same_name(n, &challenge)) {
        return Err(format!(
            "the order wants a TXT record at {name}, outside the delegated {challenge}"
        ));
    }
    let values: Vec<String> = records.into_iter().map(|(_, v)| v).collect();
    let finish = match &due.hosting_id {
        Some(h) => Request::CertDns01FinishStrict {
            sel: HostingSelector::Id(HostingId::from(h.clone())),
        },
        None => Request::CertDns01FinishDomainStrict { domain: domain()? },
    };
    Ok(Begun::Publish {
        challenge,
        values,
        finish: Box::new(finish),
    })
}

async fn publish_and_finish<B: Backend>(
    b: &B,
    node: Option<&str>,
    label: &str,
    challenge: &str,
    values: Vec<String>,
    finish: Request,
) -> Result<i64, String> {
    let set = Request::AcmeDnsValuesSet {
        label: label.to_string(),
        values: values.clone(),
    };
    match b.dispatch(None, set).await {
        Ok(Response::AcmeDnsValuesSet) => {}
        Ok(Response::Error(e)) => return Err(format!("publishing the TXT values: {e}")),
        Ok(other) => {
            return Err(format!(
                "publishing the TXT values: unexpected answer {other:?}"
            ))
        }
        Err(e) => return Err(format!("publishing the TXT values: {e}")),
    }
    let mut visible = Err(String::new());
    for n in 0..TXT_ATTEMPTS {
        if n > 0 {
            b.pause(TXT_RETRY).await;
        }
        visible = b.txt_visible(challenge, &values).await;
        if visible.is_ok() {
            break;
        }
    }
    // Finishing now would only spend one of Let's Encrypt's failed
    // validations on a record it cannot see either.
    visible.map_err(|e| format!("the TXT values are not publicly visible: {e}"))?;
    match b.dispatch(node, finish).await {
        Ok(Response::CertDns01Finish(info) | Response::CertDns01FinishDomain(info)) => {
            Ok((info.not_after - chrono::Utc::now().timestamp()) / 86400)
        }
        Ok(Response::Error(e)) => Err(format!("finishing the order: {e}")),
        Ok(other) => Err(format!("finishing the order: unexpected answer {other:?}")),
        Err(e) if refused_as_unknown(&e) => Err(format!(
            "node {} needs an update for automatic wildcard renewal",
            node.unwrap_or("master")
        )),
        Err(e) => Err(format!("finishing the order: {e}")),
    }
}

/// A worker that cannot decode the request (an agent from before the
/// strict finish) answers HTTP 400; signature and replay refusals are 401.
/// Never retried with the lenient finish, which would ignore a failed
/// pre-flight.
fn refused_as_unknown(e: &DispatchError) -> bool {
    matches!(
        e,
        DispatchError::Remote(RemoteClientError::HttpError { code: Some(22), stderr })
            if stderr.starts_with("HTTP 400")
    )
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_rpc::RpcError;
    use hyperion_rpc_client::RemoteClientError;
    use hyperion_types::{AcmeDnsConfig, CertInfo};
    use std::sync::Mutex;

    const ZONE: &str = "acme.panel.example";

    fn label(base: &str) -> AcmeDnsLabel {
        AcmeDnsLabel {
            base: base.into(),
            label: "abcd1234abcd1234".into(),
            hosting_id: None,
            created_at: 0,
            verified_at: Some(1),
            last_check_error: None,
        }
    }

    fn item(
        domain: &str,
        issuer: &str,
        renewal: &str,
        wildcard: bool,
        days: i64,
    ) -> CertOverviewItem {
        CertOverviewItem {
            domain: domain.into(),
            issuer: issuer.into(),
            days_left: days,
            wildcard,
            renewal_type: renewal.into(),
            delegated: true,
            ..Default::default()
        }
    }

    fn due_item(domain: &str) -> CertOverviewItem {
        CertOverviewItem {
            hosting_id: Some("h1".into()),
            ..item(domain, "letsencrypt", "auto", true, 12)
        }
    }

    type Answer = fn() -> Result<Response, DispatchError>;

    /// Records every dispatch and answers from a script; probes are canned.
    struct Fake {
        log: Mutex<Vec<(Option<String>, Request)>>,
        pauses: Mutex<usize>,
        txt_calls: Mutex<usize>,
        nodes: Vec<String>,
        master: &'static str,
        /// CertOverview per target (`None` = the local agent).
        overview: Vec<(Option<&'static str>, CertOverviewItem)>,
        labels: Vec<AcmeDnsLabel>,
        enabled: bool,
        zone: Result<(), String>,
        cname: Result<(), CnameProblem>,
        txt: Result<(), String>,
        records: Vec<(String, String)>,
        finish: Option<Answer>,
        clear_fails: bool,
        /// HostingGet answers per target; a target not listed says NotFound.
        hostings: Vec<(Option<&'static str>, Answer)>,
        in_flight: InFlight,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                log: Mutex::new(Vec::new()),
                pauses: Mutex::new(0),
                txt_calls: Mutex::new(0),
                nodes: Vec::new(),
                master: "s4",
                overview: vec![(None, due_item("example.com"))],
                labels: vec![label("example.com")],
                enabled: true,
                zone: Ok(()),
                cname: Ok(()),
                txt: Ok(()),
                records: vec![
                    ("_acme-challenge.example.com".into(), "v1".into()),
                    ("_acme-challenge.example.com".into(), "v2".into()),
                ],
                finish: None,
                clear_fails: false,
                hostings: Vec::new(),
                in_flight: InFlight::default(),
            }
        }

        fn kinds(&self) -> Vec<&'static str> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .map(|(_, r)| <&'static str>::from(r))
                .collect()
        }

        fn sent(&self) -> Vec<(Option<String>, Request)> {
            self.log.lock().unwrap().clone()
        }

        fn reports(&self) -> Vec<(bool, String, String)> {
            self.sent()
                .into_iter()
                .filter_map(|(_, r)| match r {
                    Request::AcmeDnsRenewReport {
                        ok,
                        detail,
                        node_id,
                        ..
                    } => Some((ok, detail, node_id)),
                    _ => None,
                })
                .collect()
        }
    }

    #[async_trait]
    impl Backend for Fake {
        async fn dispatch(
            &self,
            node: Option<&str>,
            req: Request,
        ) -> Result<Response, DispatchError> {
            self.log
                .lock()
                .unwrap()
                .push((node.map(str::to_string), req.clone()));
            Ok(match req {
                Request::AcmeDnsConfigGet => Response::AcmeDnsConfig(AcmeDnsConfig {
                    zone: Some(ZONE.into()),
                    ns_host: "ns.panel.example".into(),
                    public_ipv4: None,
                    public_ipv6: None,
                    enabled: self.enabled,
                    check_token: "tok".into(),
                    listening: Vec::new(),
                    last_error: None,
                }),
                Request::AcmeDnsLabels => Response::AcmeDnsLabels(self.labels.clone()),
                Request::CertOverview => Response::CertOverview(
                    self.overview
                        .iter()
                        .filter(|(n, _)| *n == node)
                        .map(|(_, i)| i.clone())
                        .collect(),
                ),
                Request::CertDns01Begin { .. } => Response::CertDns01Begin {
                    completed: false,
                    records: self.records.clone(),
                },
                Request::CertDns01BeginDomain { .. } => Response::CertDns01BeginDomain {
                    completed: false,
                    records: self.records.clone(),
                },
                Request::CertDns01FinishStrict { .. } => match self.finish {
                    Some(f) => return f(),
                    None => Response::CertDns01Finish(cert_info()),
                },
                Request::CertDns01FinishDomainStrict { .. } => match self.finish {
                    Some(f) => return f(),
                    None => Response::CertDns01FinishDomain(cert_info()),
                },
                Request::AcmeDnsLabelMark { .. } => Response::AcmeDnsLabelMark,
                Request::AcmeDnsValuesSet { .. } => Response::AcmeDnsValuesSet,
                Request::AcmeDnsValuesClear { .. } if self.clear_fails => {
                    Response::Error(RpcError::Internal {
                        message: "database is locked".into(),
                    })
                }
                Request::AcmeDnsValuesClear { .. } => Response::AcmeDnsValuesClear,
                Request::AcmeDnsRenewReport { .. } => Response::AcmeDnsRenewReport,
                Request::AcmeDnsZoneBroken { .. } => Response::AcmeDnsZoneBroken,
                Request::CertSetDelegated { .. } => Response::CertSetDelegated,
                Request::AcmeDnsLabelDelete { .. } => Response::AcmeDnsLabelDelete,
                Request::HostingGet(_) => match self.hostings.iter().find(|(n, _)| *n == node) {
                    Some((_, f)) => return f(),
                    None => Response::Error(RpcError::NotFound {
                        kind: "hosting".into(),
                        id: "h-gone".into(),
                    }),
                },
                other => panic!("unexpected dispatch {}", <&'static str>::from(&other)),
            })
        }
        async fn remote_nodes(&self) -> Result<Vec<String>, String> {
            Ok(self.nodes.clone())
        }
        async fn is_master_hostname(&self, node_id: &str) -> bool {
            node_id == self.master
        }
        async fn zone_delegated(&self, _zone: &str, _token: &str) -> Result<(), String> {
            self.zone.clone()
        }
        async fn cname(&self, _name: &str, _target: &str) -> Result<(), CnameProblem> {
            self.cname.clone()
        }
        async fn txt_visible(&self, _name: &str, _values: &[String]) -> Result<(), String> {
            *self.txt_calls.lock().unwrap() += 1;
            self.txt.clone()
        }
        async fn pause(&self, _d: Duration) {
            *self.pauses.lock().unwrap() += 1;
        }
        fn in_flight(&self) -> &InFlight {
            &self.in_flight
        }
    }

    fn cert_info() -> CertInfo {
        CertInfo {
            domain: "example.com".into(),
            sans: vec!["*.example.com".into(), "example.com".into()],
            issuer: "letsencrypt".into(),
            not_after: chrono::Utc::now().timestamp() + 90 * 86400,
            fingerprint_sha256: "ff".into(),
        }
    }

    #[test]
    fn select_due_picks_only_le_wildcards_with_labels_inside_window() {
        let items: Vec<(Option<String>, CertOverviewItem)> = vec![
            (None, item("manual.com", "letsencrypt", "manual", true, 5)),
            (None, item("selfsigned.com", "self-signed", "auto", true, 5)),
            (None, item("plain.com", "letsencrypt", "auto", false, 5)),
            (None, item("later.com", "letsencrypt", "auto", true, 31)),
            (None, item("nolabel.com", "letsencrypt", "auto", true, 5)),
            (
                Some("node_1".into()),
                CertOverviewItem {
                    hosting_id: Some("h9".into()),
                    ..item("good.com", "letsencrypt-staging", "auto", true, 30)
                },
            ),
        ];
        let labels: Vec<AcmeDnsLabel> = [
            "manual.com",
            "selfsigned.com",
            "plain.com",
            "later.com",
            "good.com",
        ]
        .into_iter()
        .map(label)
        .collect();
        let due = select_due(&items, &labels, 30);
        assert_eq!(
            due,
            vec![DueCert {
                node_id: Some("node_1".into()),
                domain: "good.com".into(),
                hosting_id: Some("h9".into()),
                label: label("good.com"),
                days_left: Some(30),
            }]
        );
    }

    #[tokio::test]
    async fn select_due_normalises_master_hostname_to_local() {
        let mut fake = Fake::new();
        fake.nodes = vec!["s4".into(), "node_1".into()];
        fake.overview = vec![
            (None, due_item("a.com")),
            (Some("node_1"), due_item("b.com")),
        ];
        fake.labels = vec![label("a.com"), label("b.com")];
        let items = gather(&fake).await;
        let due = select_due(&items, &fake.labels, 30);
        let got: Vec<(Option<String>, String)> =
            due.into_iter().map(|d| (d.node_id, d.domain)).collect();
        assert_eq!(
            got,
            vec![
                (None, "a.com".into()),
                (Some("node_1".into()), "b.com".into())
            ]
        );
        // The master's hostname is never dispatched to as if it were a worker.
        assert!(fake.sent().iter().all(|(n, _)| n.as_deref() != Some("s4")));
        // Blank and the `local` sentinel mean the master too.
        let items = vec![
            (Some(String::new()), due_item("a.com")),
            (Some("local".into()), due_item("b.com")),
        ];
        assert!(select_due(&items, &fake.labels, 30)
            .iter()
            .all(|d| d.node_id.is_none()));
    }

    #[tokio::test]
    async fn removed_cname_creates_no_order() {
        let mut fake = Fake::new();
        fake.cname = Err(CnameProblem::Missing);
        let out = run_once_with(&fake).await;
        assert_eq!(out.len(), 1);
        assert!(out[0].1.is_err());
        let kinds = fake.kinds();
        assert!(!kinds.contains(&"CertDns01Begin"));
        assert!(!kinds.contains(&"CertDns01BeginDomain"));
        assert!(fake.sent().iter().any(|(_, r)| matches!(
            r,
            Request::AcmeDnsLabelMark { ok: false, error: Some(e), .. }
                if e.contains("does not exist")
        )));
        let reports = fake.reports();
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].0);
        assert!(reports[0].1.contains("does not exist"), "{}", reports[0].1);
    }

    #[tokio::test]
    async fn values_are_cleared_when_finish_fails() {
        let mut fake = Fake::new();
        fake.finish = Some(|| {
            Ok(Response::Error(RpcError::Internal {
                message: "order invalid".into(),
            }))
        });
        let out = run_once_with(&fake).await;
        assert!(out[0]
            .1
            .as_ref()
            .is_err_and(|e| e.contains("order invalid")));
        assert!(fake.sent().iter().any(|(_, r)| matches!(
            r,
            Request::AcmeDnsValuesClear { label } if label == "abcd1234abcd1234"
        )));
        assert!(!fake.reports()[0].0);
    }

    #[tokio::test]
    async fn old_node_refusing_strict_finish_is_a_failure_not_a_fallback() {
        let mut fake = Fake::new();
        fake.nodes = vec!["node_1".into()];
        fake.overview = vec![(Some("node_1"), due_item("example.com"))];
        fake.finish = Some(|| {
            Err(DispatchError::Remote(RemoteClientError::HttpError {
                code: Some(22),
                stderr: "HTTP 400: bad request body".into(),
            }))
        });
        let out = run_once_with(&fake).await;
        let err = out[0].1.clone().unwrap_err();
        assert_eq!(
            err,
            "node node_1 needs an update for automatic wildcard renewal"
        );
        let kinds = fake.kinds();
        assert!(!kinds.contains(&"CertDns01Finish"));
        assert!(kinds.contains(&"AcmeDnsValuesClear"));
        let reports = fake.reports();
        assert!(reports[0].1.contains("needs an update"));
        assert_eq!(reports[0].2, "node_1");
    }

    #[tokio::test]
    async fn happy_path_dispatch_order() {
        let fake = Fake::new();
        let out = run_once_with(&fake).await;
        assert_eq!(out, vec![("example.com".to_string(), Ok(()))]);
        assert_eq!(
            fake.kinds(),
            vec![
                "AcmeDnsConfigGet",
                "CertOverview",
                "AcmeDnsLabels",
                "AcmeDnsLabelMark",
                "CertDns01Begin",
                "AcmeDnsValuesSet",
                "CertDns01FinishStrict",
                "AcmeDnsValuesClear",
                "AcmeDnsRenewReport",
                // Re-read for the delegated-flag sync.
                "AcmeDnsLabels",
            ]
        );
        let sent = fake.sent();
        assert!(sent.iter().any(|(_, r)| matches!(
            r,
            Request::AcmeDnsValuesSet { label, values }
                if label == "abcd1234abcd1234" && values == &["v1".to_string(), "v2".to_string()]
        )));
        assert!(fake.reports()[0].0);
        // Public visibility was confirmed before finishing, without waiting.
        assert_eq!(*fake.txt_calls.lock().unwrap(), 1);
        assert_eq!(*fake.pauses.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn broken_zone_alerts_once_and_stops() {
        let mut fake = Fake::new();
        fake.zone = Err("_hyperion-check.acme.panel.example: NXDOMAIN".into());
        let out = run_once_with(&fake).await;
        assert!(out.is_empty());
        assert_eq!(fake.kinds(), vec!["AcmeDnsConfigGet", "AcmeDnsZoneBroken"]);
    }

    #[tokio::test]
    async fn disabled_zone_does_nothing() {
        let mut fake = Fake::new();
        fake.enabled = false;
        assert!(run_once_with(&fake).await.is_empty());
        assert_eq!(fake.kinds(), vec!["AcmeDnsConfigGet"]);
    }

    #[tokio::test]
    async fn record_outside_the_delegated_name_is_refused() {
        let mut fake = Fake::new();
        fake.records = vec![("_acme-challenge.other.com".into(), "v1".into())];
        let out = run_once_with(&fake).await;
        assert!(out[0]
            .1
            .as_ref()
            .is_err_and(|e| e.contains("_acme-challenge.other.com")));
        assert!(!fake.kinds().contains(&"AcmeDnsValuesSet"));
        assert!(!fake.kinds().contains(&"CertDns01FinishStrict"));
    }

    #[tokio::test]
    async fn invisible_txt_is_retried_then_fails_without_finishing() {
        let mut fake = Fake::new();
        fake.txt = Err("_acme-challenge.example.com: missing v1".into());
        let out = run_once_with(&fake).await;
        assert!(out[0].1.as_ref().is_err_and(|e| e.contains("missing v1")));
        assert_eq!(*fake.txt_calls.lock().unwrap(), 6);
        assert_eq!(*fake.pauses.lock().unwrap(), 5);
        let kinds = fake.kinds();
        assert!(!kinds.contains(&"CertDns01FinishStrict"));
        assert!(kinds.contains(&"AcmeDnsValuesClear"));
    }

    #[tokio::test]
    async fn preview_base_uses_the_domain_rpcs() {
        let mut fake = Fake::new();
        fake.overview = vec![(None, item("example.com", "letsencrypt", "auto", true, 3))];
        let out = run_once_with(&fake).await;
        assert_eq!(out, vec![("example.com".to_string(), Ok(()))]);
        let kinds = fake.kinds();
        assert!(kinds.contains(&"CertDns01BeginDomain"));
        assert!(kinds.contains(&"CertDns01FinishDomainStrict"));
        assert!(!kinds.contains(&"CertDns01Begin"));
    }

    #[tokio::test]
    async fn delegated_flag_follows_the_label() {
        let mut fake = Fake::new();
        fake.nodes = vec!["node_1".into()];
        let mut stale = item("example.com", "letsencrypt", "auto", true, 80);
        stale.delegated = false;
        let mut gone = item("gone.com", "letsencrypt", "auto", true, 80);
        gone.delegated = true;
        fake.overview = vec![(Some("node_1"), stale), (None, gone)];
        let mut broken = label("gone.com");
        broken.verified_at = None;
        broken.last_check_error = Some("the CNAME record does not exist yet".into());
        fake.labels = vec![label("example.com"), broken];
        let out = run_once_with(&fake).await;
        assert!(out.is_empty(), "nothing inside the window");
        let set: Vec<(Option<String>, String, bool)> = fake
            .sent()
            .into_iter()
            .filter_map(|(n, r)| match r {
                Request::CertSetDelegated { domain, delegated } => {
                    Some((n, domain.to_string(), delegated))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            set,
            vec![
                (Some("node_1".into()), "example.com".into(), true),
                (None, "gone.com".into(), false),
            ]
        );
    }

    fn due() -> DueCert {
        DueCert {
            node_id: None,
            domain: "example.com".into(),
            hosting_id: Some("h1".into()),
            label: label("example.com"),
            days_left: Some(60),
        }
    }

    #[tokio::test]
    async fn a_failed_first_issuance_sends_no_report() {
        let mut fake = Fake::new();
        fake.cname = Err(CnameProblem::Missing);
        let first = DueCert {
            days_left: None,
            ..due()
        };
        assert!(renew_one_with(&fake, &first, None).await.is_err());
        assert!(fake.reports().is_empty(), "a 0-days alert for no cert");
        // With an expiry known, the same failure is reported.
        assert!(renew_one_with(&fake, &due(), None).await.is_err());
        assert_eq!(fake.reports().len(), 1);
    }

    fn orphan() -> AcmeDnsLabel {
        AcmeDnsLabel {
            base: "gone.example".into(),
            label: "zzzz1234zzzz1234".into(),
            hosting_id: Some("h-gone".into()),
            ..label("gone.example")
        }
    }

    fn label_deletes(fake: &Fake) -> Vec<String> {
        fake.sent()
            .into_iter()
            .filter_map(|(_, r)| match r {
                Request::AcmeDnsLabelDelete { base } => Some(base.as_str().to_string()),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn orphan_label_is_dropped_when_every_node_says_gone() {
        let mut fake = Fake::new();
        fake.nodes = vec!["s4".into(), "node_1".into()];
        fake.labels = vec![label("example.com"), orphan()];
        run_once_with(&fake).await;
        assert_eq!(label_deletes(&fake), vec!["gone.example".to_string()]);
        let asked: Vec<Option<String>> = fake
            .sent()
            .into_iter()
            .filter(|(_, r)| matches!(r, Request::HostingGet(_)))
            .map(|(n, _)| n)
            .collect();
        assert_eq!(asked, vec![None, Some("node_1".into())]);
    }

    #[tokio::test]
    async fn orphan_label_is_kept_when_a_node_is_unreachable() {
        let mut fake = Fake::new();
        fake.nodes = vec!["node_1".into()];
        fake.labels = vec![orphan()];
        fake.hostings = vec![(Some("node_1"), || {
            Err(DispatchError::Remote(RemoteClientError::HttpError {
                code: Some(7),
                stderr: "connection refused".into(),
            }))
        })];
        run_once_with(&fake).await;
        assert!(label_deletes(&fake).is_empty());
    }

    #[tokio::test]
    async fn a_label_whose_hosting_lives_on_is_kept() {
        let mut fake = Fake::new();
        fake.nodes = vec!["node_1".into()];
        fake.labels = vec![orphan()];
        fake.hostings = vec![(Some("node_1"), || {
            Ok(Response::Error(RpcError::Internal {
                message: "database is locked".into(),
            }))
        })];
        run_once_with(&fake).await;
        assert!(label_deletes(&fake).is_empty());
    }

    #[tokio::test]
    async fn renew_one_probes_the_zone_before_ordering() {
        let mut fake = Fake::new();
        fake.zone = Err("_hyperion-check.acme.panel.example: NXDOMAIN".into());
        let err = renew_one_with(&fake, &due(), None).await.unwrap_err();
        assert!(err.contains("NXDOMAIN"), "{err}");
        let kinds = fake.kinds();
        assert!(!kinds.contains(&"CertDns01Begin"));
        assert!(!kinds.contains(&"AcmeDnsValuesSet"));
    }

    #[tokio::test]
    async fn renew_one_refuses_while_acme_dns_is_disabled() {
        let mut fake = Fake::new();
        fake.enabled = false;
        let err = renew_one_with(&fake, &due(), None).await.unwrap_err();
        assert!(err.contains("not enabled"), "{err}");
        assert_eq!(fake.kinds(), vec!["AcmeDnsConfigGet"]);
    }

    #[tokio::test]
    async fn renew_one_outside_the_window_orders_after_the_preflight() {
        let fake = Fake::new();
        assert_eq!(renew_one_with(&fake, &due(), None).await, Ok(()));
        let kinds = fake.kinds();
        assert_eq!(kinds[0], "AcmeDnsConfigGet");
        assert!(kinds.contains(&"CertDns01FinishStrict"));
    }

    #[tokio::test]
    async fn a_second_renewal_of_the_same_label_fails_fast() {
        let fake = Fake::new();
        let held = fake.in_flight.claim("abcd1234abcd1234");
        assert!(held.is_some());
        let err = renew_one_with(&fake, &due(), None).await.unwrap_err();
        assert_eq!(err, "a renewal for example.com is already running");
        assert!(fake.kinds().is_empty());
        drop(held);
        // Released on drop: the next one runs.
        assert_eq!(renew_one_with(&fake, &due(), None).await, Ok(()));
        assert!(fake.in_flight.claim("abcd1234abcd1234").is_some());
    }

    #[tokio::test]
    async fn a_failed_renewal_releases_the_label() {
        let mut fake = Fake::new();
        fake.cname = Err(CnameProblem::Missing);
        assert!(renew_one_with(&fake, &due(), None).await.is_err());
        assert!(fake.in_flight.claim("abcd1234abcd1234").is_some());
    }

    #[tokio::test]
    async fn values_left_behind_are_named_in_the_report() {
        let mut fake = Fake::new();
        fake.clear_fails = true;
        let out = run_once_with(&fake).await;
        assert_eq!(out, vec![("example.com".to_string(), Ok(()))]);
        let reports = fake.reports();
        assert!(reports[0].0);
        assert!(
            reports[0]
                .1
                .contains("(TXT values not withdrawn: internal error: database is locked)"),
            "{}",
            reports[0].1
        );
    }
}
