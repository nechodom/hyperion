//! A node's local mail server (postfix): the "Mail delivery" group on
//! Service health (`/services?node=<id>#mail-delivery`) and the actions
//! that go with it.
//!
//! These lived on the one-page Settings, where every visit to the Mail tab
//! ran the whole diagnosis — reverse DNS, SPF, four outbound port probes —
//! before the page could render. Settings → Mail now only configures the
//! relay and shows a one-line verdict ([`verdict`]), loaded lazily; the
//! findings and the fixes are here, next to the postfix service row they
//! are about, and load only when the group scrolls into view.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::ratelimit::Bucket;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::MtaDiagnostics;
use serde::Deserialize;
use std::net::SocketAddr;

/// How long the diagnosis may take. It runs DNS lookups and port probes on
/// the node (3 s each, in parallel) and, for a worker, crosses the network
/// twice; it is lazy, so a slow answer only keeps "Checking…" up longer.
const DIAG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// `""` / `"local"` → the master (`None`), anything else a worker's id.
pub(crate) fn node_target(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t == crate::dispatcher::LOCAL_NODE_SENTINEL {
        None
    } else {
        Some(t.to_string())
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// `/services?node=<id>&<query>#mail-delivery` — the master gets no `node=`.
pub(crate) fn services_url(target: Option<&str>, query: &str) -> String {
    let mut q: Vec<String> = Vec::new();
    if let Some(id) = target {
        q.push(format!("node={}", urlencode(id)));
    }
    if !query.is_empty() {
        q.push(query.to_string());
    }
    if q.is_empty() {
        "/services#mail-delivery".to_string()
    } else {
        format!("/services?{}#mail-delivery", q.join("&"))
    }
}

fn back_with_flash(target: Option<&str>, msg: &str) -> Response {
    Redirect::to(&services_url(target, &format!("flash={}", urlencode(msg)))).into_response()
}

fn back_with_error(target: Option<&str>, msg: &str) -> Response {
    Redirect::to(&services_url(
        target,
        &format!("flash_error={}", urlencode(msg)),
    ))
    .into_response()
}

/// The first address of a `default_to` list, split the way the mailer
/// splits it. A test field is `type="email"`, which takes ONE address: the
/// whole list pre-filled into it failed the browser's validation, so the
/// test could not be sent until the field was edited by hand.
pub(crate) fn first_address(list: &str) -> String {
    list.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .find(|a| a.contains('@'))
        .unwrap_or("")
        .to_string()
}

/// Ask `target` for its postfix diagnosis.
pub(crate) async fn fetch(
    state: &SharedState,
    target: Option<&str>,
) -> Result<MtaDiagnostics, String> {
    match tokio::time::timeout(
        DIAG_TIMEOUT,
        crate::dispatcher::dispatch_to_node(state, target, Request::MtaDiagnostics),
    )
    .await
    {
        Ok(Ok(RpcResponse::MtaDiagnostics(d))) => Ok(d),
        Ok(Ok(RpcResponse::Error(e))) => Err(e.to_string()),
        Ok(Ok(_)) => Err("unexpected answer from the agent".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("no answer within {} s", DIAG_TIMEOUT.as_secs())),
    }
}

/// What the template reads: the agent's diagnosis reduced to one tone and
/// one line per check. Tones are `ok` / `warn` / `err`, or empty for
/// "could not tell" — a probe that did not run is never a finding.
pub(crate) struct MailDiag {
    pub d: MtaDiagnostics,
}

impl MailDiag {
    pub fn installed(&self) -> bool {
        self.d.mode != "not-installed"
    }

    fn mode_phrase(&self) -> String {
        match self.d.mode.as_str() {
            "smart-host" if !self.d.relayhost.is_empty() => {
                format!("Relays through {}", self.d.relayhost)
            }
            "smart-host" => "Relays through a smart host".into(),
            "direct-mx" => "Delivers directly to each recipient's server".into(),
            "not-installed" => "Not installed".into(),
            _ => "Default configuration, not managed by Hyperion".into(),
        }
    }

    pub fn postfix_tone(&self) -> &'static str {
        if !self.installed() || !self.d.service_active || !self.d.sendmail_executable {
            "err"
        } else if self.d.mode == "default" || !self.d.service_enabled {
            "warn"
        } else {
            "ok"
        }
    }

    pub fn postfix_summary(&self) -> String {
        if !self.installed() {
            return "Not installed — sites' mail() cannot send from this node".into();
        }
        let mut parts = vec![self.mode_phrase()];
        parts.push(if self.d.service_active {
            "running".into()
        } else {
            "stopped".into()
        });
        if !self.d.service_enabled {
            parts.push("won't start at boot".into());
        }
        if !self.d.sendmail_executable {
            parts.push("sendmail missing".into());
        }
        parts.join(" · ")
    }

    pub fn helo_tone(&self) -> &'static str {
        if self.d.myhostname.is_empty() {
            ""
        } else if self.d.myhostname_is_fqdn {
            "ok"
        } else {
            "warn"
        }
    }

    pub fn helo_summary(&self) -> String {
        if self.d.myhostname.is_empty() {
            "Unknown — postconf did not answer".into()
        } else if self.d.myhostname_is_fqdn {
            self.d.myhostname.clone()
        } else {
            format!("{} — not a fully qualified name", self.d.myhostname)
        }
    }

    pub fn ptr_tone(&self) -> &'static str {
        match self.d.ptr_status.as_str() {
            "ok" => "ok",
            "mismatch" | "missing" | "hostname-not-fqdn" => "warn",
            _ => "",
        }
    }

    pub fn ptr_summary(&self) -> String {
        let ip = &self.d.public_ipv4;
        let ptr = &self.d.ptr_name;
        match self.d.ptr_status.as_str() {
            "ok" => format!("{ip} → {ptr}, matches the HELO name"),
            "hostname-not-fqdn" if !ptr.is_empty() => {
                format!("{ip} → {ptr}; cannot compare, the hostname is not a FQDN")
            }
            "hostname-not-fqdn" => format!("{ip} has no PTR, and the hostname is not a FQDN"),
            "mismatch" => format!("{ip} → {ptr}, does not match {}", self.d.myhostname),
            "missing" => format!("{ip} has no PTR record"),
            _ => "Unknown — the lookup could not run".into(),
        }
    }

    pub fn sender_tone(&self) -> &'static str {
        match self.d.sender_auth_status.as_str() {
            "authorized" => "ok",
            "foreign-reject" => "err",
            "no-spf" | "not-authorized" | "no-domain" => "warn",
            _ => "",
        }
    }

    pub fn sender_summary(&self) -> String {
        let dom = &self.d.sender_domain;
        match self.d.sender_auth_status.as_str() {
            "authorized" => format!("{dom} — SPF authorizes this server"),
            "foreign-reject" => format!("{dom} — receivers silently discard this mail"),
            "no-spf" => format!("{dom} has no SPF record"),
            "not-authorized" => format!("{dom} — SPF does not include this server"),
            "no-domain" => "The sender address has no domain".into(),
            _ => "Unknown — the check could not run".into(),
        }
    }

    pub fn port25_blocked(&self) -> bool {
        matches!(self.d.outbound_port_25_ok, Some(false))
    }

    /// Ports other than 25 that answered — where a smart host could go.
    pub fn open_alternatives(&self) -> Vec<u16> {
        self.d
            .outbound_smtp_probes
            .iter()
            .filter(|p| p.reachable && p.port != 25)
            .map(|p| p.port)
            .collect()
    }

    pub fn ports_tone(&self) -> &'static str {
        if self.d.outbound_smtp_probes.is_empty() {
            ""
        } else if self.port25_blocked() && self.d.mode != "smart-host" {
            // Direct delivery talks to port 25 and nothing else.
            "err"
        } else if self.d.outbound_smtp_probes.iter().all(|p| !p.reachable) {
            "err"
        } else {
            "ok"
        }
    }

    pub fn ports_summary(&self) -> String {
        if self.d.outbound_smtp_probes.is_empty() {
            return "Not probed".into();
        }
        let list = self
            .d
            .outbound_smtp_probes
            .iter()
            .map(|p| {
                format!(
                    "{} {}",
                    p.port,
                    if p.reachable { "open" } else { "blocked" }
                )
            })
            .collect::<Vec<_>>()
            .join(" · ");
        if self.port25_blocked() && self.d.mode == "smart-host" {
            format!("{list} — 25 is not needed while the smart host takes the mail")
        } else {
            list
        }
    }

    pub fn queue_tone(&self) -> &'static str {
        if self.d.mailq_summary.is_empty() {
            ""
        } else if self.d.mailq_total > 0 {
            "warn"
        } else {
            "ok"
        }
    }

    pub fn queue_summary(&self) -> String {
        if self.d.mailq_summary.is_empty() {
            "Unknown — postqueue is not available".into()
        } else if self.d.mailq_total == 1 {
            "1 message deferred".into()
        } else if self.d.mailq_total > 1 {
            format!("{} messages deferred", self.d.mailq_total)
        } else {
            "Empty".into()
        }
    }
}

/// The one-line verdict Settings → Mail shows: how postfix sends, whether
/// it runs, what is stuck. `(tone, line)`.
pub(crate) fn verdict(d: &MtaDiagnostics) -> (&'static str, String) {
    let v = MailDiag { d: d.clone() };
    if !v.installed() {
        return (
            "err",
            "Postfix is not installed — sites' mail() cannot send.".into(),
        );
    }
    let mode = match d.mode.as_str() {
        "smart-host" => "Postfix relays through the smart host",
        "direct-mx" => "Postfix delivers directly",
        _ => "Postfix runs its default configuration",
    };
    let run = if d.service_active {
        "running"
    } else {
        "stopped"
    };
    let queue = if d.mailq_summary.is_empty() {
        "queue unknown".to_string()
    } else if d.mailq_total == 0 {
        "queue empty".to_string()
    } else {
        format!("{} deferred", d.mailq_total)
    };
    let tone = if !d.service_active || !d.sendmail_executable {
        "err"
    } else if d.mailq_total > 0 || d.mode == "default" {
        "warn"
    } else {
        "ok"
    };
    (tone, format!("{mode} · {run} · {queue}."))
}

#[derive(Deserialize, Default)]
pub struct NodeQuery {
    #[serde(default)]
    pub node: String,
}

#[derive(Template)]
#[template(path = "_mail_diagnostics.html")]
struct DiagTpl {
    /// `target_node` for the forms, `node=` for Re-check: empty = master.
    node: String,
    /// The node's name in the copy.
    node_label: String,
    /// The group heading's node, as the Service health header names it.
    group_label: String,
    v: MailDiag,
    error: Option<String>,
    csrf_token: String,
    test_to: String,
}

/// `GET /services/mail-diagnostics?node=<id>` — the Mail delivery group's
/// body on Service health. Lazy: it runs the slow probes.
pub async fn get_mail_diagnostics(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<NodeQuery>,
) -> Result<Response, AppError> {
    let target = node_target(&q.node);
    // The diagnosis carries the mail log (recipient addresses) and drives
    // postfix: same gate as the card had on Settings.
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Html(
            "<div class=\"group\"><div class=\"ghead\">Mail delivery</div><div class=\"item\">\
             <p class=\"text-soft small\" style=\"margin:0\">Mail diagnostics need the \
             “Edit global settings” permission.</p></div></div>"
                .to_string(),
        )
        .into_response());
    }
    let node = match &target {
        None => None,
        Some(id) => crate::dispatcher::cached_nodes(&state)
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|n| &n.node_id == id),
    };
    let (node_label, group_label) = labels(target.as_deref(), node.as_ref());
    let (d, error) = match fetch(&state, target.as_deref()).await {
        Ok(d) => (d, None),
        Err(e) => (MtaDiagnostics::default(), Some(e)),
    };
    let tpl = DiagTpl {
        node: target.clone().unwrap_or_default(),
        node_label,
        group_label,
        test_to: first_address(&d.cfg_default_to),
        v: MailDiag { d },
        error,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

/// `(in a sentence, in the group heading)` for the node shown — the heading
/// the way the Service health header names it, so the swap changes nothing.
fn labels(target: Option<&str>, node: Option<&hyperion_types::NodeSummary>) -> (String, String) {
    match (target, node) {
        (None, _) => ("this server".into(), "master (this node)".into()),
        (Some(id), None) => (id.to_string(), id.to_string()),
        (Some(id), Some(n)) => {
            let name = if n.label.trim().is_empty() {
                id.to_string()
            } else {
                n.label.clone()
            };
            let heading = match n.public_ip.as_deref() {
                Some(ip) if !ip.is_empty() => format!("{name} ({ip})"),
                _ => name.clone(),
            };
            (name, heading)
        }
    }
}

/// Body for the button-only actions: just the node they act on.
#[derive(Deserialize, Default)]
pub struct NodeActionForm {
    #[serde(default)]
    pub target_node: String,
}

#[derive(Deserialize)]
pub struct MtaTestForm {
    pub to: String,
    #[serde(default)]
    pub target_node: String,
}

/// POST /services/mail/queue-flush — `postqueue -f`: retry every deferred
/// message now. Cheap and idempotent, so no rate limit.
pub async fn post_mta_queue_flush(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeActionForm>,
) -> Result<Response, AppError> {
    let target = node_target(&form.target_node);
    if !ctx.can(Capability::SettingsManage) {
        return Ok(back_with_error(target.as_deref(), "admin role required"));
    }
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target.as_deref(), Request::MtaQueueFlush)
            .await
            .map_err(AppError::from)?;
    match resp {
        RpcResponse::MtaQueueFlush { attempted, output } => {
            let msg = if attempted == 0 {
                "Queue retried — it is empty now.".to_string()
            } else {
                let tail: String = output.lines().take(2).collect::<Vec<_>>().join(" · ");
                let tail = if tail.is_empty() {
                    "(no output)".into()
                } else {
                    tail
                };
                format!(
                    "Queue retried — {attempted} message(s) still deferred; \
                     the mail log says why. {tail}"
                )
            };
            Ok(back_with_flash(target.as_deref(), &msg))
        }
        RpcResponse::Error(e) => Ok(back_with_error(
            target.as_deref(),
            &format!("Queue retry failed: {e}"),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /services/mail/queue-clear — `postsuper -d ALL`. Destructive; the
/// confirm dialog is on the form.
pub async fn post_mta_queue_clear(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeActionForm>,
) -> Result<Response, AppError> {
    let target = node_target(&form.target_node);
    if !ctx.can(Capability::SettingsManage) {
        return Ok(back_with_error(target.as_deref(), "admin role required"));
    }
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target.as_deref(), Request::MtaQueueClear)
            .await
            .map_err(AppError::from)?;
    match resp {
        RpcResponse::MtaQueueClear { cleared, output: _ } => {
            let msg = if cleared == 0 {
                "The queue was already empty.".to_string()
            } else {
                format!("{cleared} queued message(s) discarded.")
            };
            Ok(back_with_flash(target.as_deref(), &msg))
        }
        RpcResponse::Error(e) => Ok(back_with_error(
            target.as_deref(),
            &format!("Discarding the queue failed: {e}"),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /services/mail/reconfigure — re-apply the smart-host / direct-MX
/// config from the node's current `[email]` without restarting its agent:
/// after a hand edit of agent.toml, or to roll forward after reverting one.
pub async fn post_mta_reconfigure(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<NodeActionForm>,
) -> Result<Response, AppError> {
    let target = node_target(&form.target_node);
    if !ctx.can(Capability::SettingsManage) {
        return Ok(back_with_error(
            target.as_deref(),
            "admin role required to reconfigure postfix",
        ));
    }
    let resp =
        crate::dispatcher::dispatch_to_node(&state, target.as_deref(), Request::MtaReconfigure)
            .await
            .map_err(AppError::from)?;
    match resp {
        RpcResponse::MtaReconfigure { mode } => {
            let msg = match mode.as_str() {
                "skipped" => "Postfix is not installed — install it first.".to_string(),
                m => format!("Postfix reconfigured — now in {m} mode."),
            };
            Ok(back_with_flash(target.as_deref(), &msg))
        }
        RpcResponse::Error(e) => Ok(back_with_error(
            target.as_deref(),
            &format!("Reconfiguring postfix failed: {e}"),
        )),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /services/mail/test — a message through `/usr/sbin/sendmail`, the
/// path sites' PHP `mail()` takes (wrapper → postfix → relay or MX). The
/// relay test on Settings → Mail talks SMTP to the relay instead and never
/// touches postfix.
pub async fn post_mta_test(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<MtaTestForm>,
) -> Result<Response, AppError> {
    let target = node_target(&form.target_node);
    if !ctx.can(Capability::SettingsManage) {
        return Ok(back_with_error(
            target.as_deref(),
            "admin role required to send test e-mail",
        ));
    }
    // Same per-IP limit as the relay test: a stolen cookie must not turn the
    // node's postfix into an address prober or a spam source.
    let ip = crate::handlers::settings::email_test_ip(&headers, peer);
    if !state.ratelimit.check("mta-test", ip, Bucket::per_minute(3)) {
        return Ok(back_with_error(
            target.as_deref(),
            "Test e-mail rate limit exceeded — wait a minute.",
        ));
    }
    let to = form.to.trim().to_string();
    if to.len() > 254 {
        return Ok(back_with_error(
            target.as_deref(),
            "Address too long (max 254 characters).",
        ));
    }
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target.as_deref(),
        Request::MtaTestSend { to: to.clone() },
    )
    .await
    .map_err(AppError::from)?;
    match resp {
        RpcResponse::MtaTestSend { exit_code, output } => {
            if exit_code == 0 {
                Ok(back_with_flash(
                    target.as_deref(),
                    &format!(
                        "Postfix queued the message to {to}. Delivery shows in the mail \
                         log within seconds; check the inbox and the spam folder."
                    ),
                ))
            } else {
                let trimmed = output.trim();
                let tail = if trimmed.is_empty() {
                    "(no output from sendmail)".to_string()
                } else {
                    trimmed.chars().take(180).collect()
                };
                Ok(back_with_error(
                    target.as_deref(),
                    &format!("sendmail exit {exit_code}: {tail}"),
                ))
            }
        }
        RpcResponse::Error(e) => Ok(back_with_error(target.as_deref(), &e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::MtaPortProbe;

    fn probe(port: u16, reachable: bool) -> MtaPortProbe {
        MtaPortProbe {
            port,
            reachable,
            ..Default::default()
        }
    }

    fn healthy() -> MtaDiagnostics {
        MtaDiagnostics {
            mode: "direct-mx".into(),
            sendmail_executable: true,
            service_active: true,
            service_enabled: true,
            myhostname: "mail.example.cz".into(),
            myhostname_is_fqdn: true,
            mailq_summary: "Mail queue is empty".into(),
            outbound_port_25_ok: Some(true),
            outbound_smtp_probes: vec![probe(25, true), probe(587, true)],
            ..Default::default()
        }
    }

    #[test]
    fn redirects_return_to_the_mail_group_and_keep_the_node() {
        assert_eq!(services_url(None, ""), "/services#mail-delivery");
        assert_eq!(
            services_url(None, "flash=ok"),
            "/services?flash=ok#mail-delivery"
        );
        assert_eq!(
            services_url(Some("node_01 x"), "flash=ok"),
            "/services?node=node_01+x&flash=ok#mail-delivery"
        );
        assert_eq!(node_target(""), None);
        assert_eq!(node_target(" local "), None);
        assert_eq!(node_target("node_1").as_deref(), Some("node_1"));
    }

    #[test]
    fn first_address_takes_one_from_a_list() {
        assert_eq!(first_address(""), "");
        assert_eq!(first_address("ops@x.cz, cto@x.cz"), "ops@x.cz");
        assert_eq!(first_address("not-one; b@y.cz\nc@z.cz"), "b@y.cz");
    }

    #[test]
    fn a_healthy_node_reads_ok_everywhere_it_was_checked() {
        let v = MailDiag { d: healthy() };
        assert_eq!(v.postfix_tone(), "ok");
        assert_eq!(v.helo_tone(), "ok");
        assert_eq!(v.queue_tone(), "ok");
        assert_eq!(v.ports_tone(), "ok");
        // Not checked is not a finding.
        assert_eq!(v.ptr_tone(), "");
        assert_eq!(v.sender_tone(), "");
        assert_eq!(verdict(&v.d).0, "ok");
        assert_eq!(
            verdict(&v.d).1,
            "Postfix delivers directly · running · queue empty."
        );
    }

    #[test]
    fn port_25_matters_only_without_a_smart_host() {
        let mut d = healthy();
        d.outbound_port_25_ok = Some(false);
        d.outbound_smtp_probes = vec![probe(25, false), probe(587, true)];
        assert_eq!(MailDiag { d: d.clone() }.ports_tone(), "err");
        assert_eq!(MailDiag { d: d.clone() }.open_alternatives(), vec![587]);
        d.mode = "smart-host".into();
        d.relayhost = "[smtp.example.cz]:587".into();
        let v = MailDiag { d };
        assert_eq!(v.ports_tone(), "ok");
        assert!(v.ports_summary().contains("not needed"));
        assert!(v
            .postfix_summary()
            .starts_with("Relays through [smtp.example.cz]:587"));
    }

    #[test]
    fn stuck_mail_and_a_stopped_postfix_are_findings() {
        let mut d = healthy();
        d.mailq_total = 3;
        d.mailq_summary = "-- 4 Kbytes in 3 Requests.".into();
        assert_eq!(
            MailDiag { d: d.clone() }.queue_summary(),
            "3 messages deferred"
        );
        assert_eq!(verdict(&d).0, "warn");
        d.service_active = false;
        assert_eq!(MailDiag { d: d.clone() }.postfix_tone(), "err");
        assert_eq!(
            verdict(&d),
            (
                "err",
                "Postfix delivers directly · stopped · 3 deferred.".into()
            )
        );
        d.mode = "not-installed".into();
        assert_eq!(verdict(&d).0, "err");
        assert!(MailDiag { d }
            .postfix_summary()
            .starts_with("Not installed"));
    }

    fn render(d: MtaDiagnostics, error: Option<String>) -> String {
        DiagTpl {
            node: "node_a".into(),
            node_label: "web-2".into(),
            group_label: "web-2 (203.0.113.7)".into(),
            test_to: first_address(&d.cfg_default_to),
            v: MailDiag { d },
            error,
            csrf_token: "tok".into(),
        }
        .render()
        .expect("render")
    }

    #[test]
    fn the_group_body_offers_the_fixes_that_apply_and_no_others() {
        // Healthy: no queue actions, but the test and reconfigure are there.
        let html = render(healthy(), None);
        assert!(!html.contains("/services/mail/queue-clear"));
        assert!(html.contains("action=\"/services/mail/test\""));
        assert!(html.contains("action=\"/services/mail/reconfigure\""));
        assert!(html.contains("name=\"target_node\" value=\"node_a\""));

        // Stuck mail behind a blocked port 25: the queue actions, the
        // discard confirmed on its FORM, and the port advice.
        let mut d = healthy();
        d.mailq_total = 2;
        d.mailq_summary = "-- 2 Kbytes in 2 Requests.".into();
        d.outbound_port_25_ok = Some(false);
        d.outbound_smtp_probes = vec![probe(25, false), probe(587, true)];
        d.cfg_default_to = "ops@x.cz, cto@x.cz".into();
        let html = render(d, None);
        let form = html
            .split("<form")
            .find(|f| f.contains("/services/mail/queue-clear"))
            .expect("discard form");
        assert!(form.contains("data-confirm-variant=\"danger\""));
        assert!(html.contains("Port 25 is blocked"));
        assert!(html.contains("Port 587 is open"));
        assert!(
            html.contains("value=\"ops@x.cz\""),
            "one address in a type=email field"
        );

        // Not installed: nothing to act on but a re-check.
        let mut d = healthy();
        d.mode = "not-installed".into();
        let html = render(d, None);
        assert!(!html.contains("<form"));
        assert!(html.contains("Re-check"));
        // The fragment is the whole group, and Re-check swaps it again.
        assert!(html.trim_start().starts_with("<div class=\"group\">"));
        assert!(html.contains("Mail delivery · web-2 (203.0.113.7)"));
        assert!(html.contains("hx-get=\"/services/mail-diagnostics?node=node_a\""));
        assert!(html.contains("hx-target=\"#mail-delivery-body\""));

        // Unreachable: says so, offers nothing.
        let html = render(
            MtaDiagnostics::default(),
            Some("no answer within 15 s".into()),
        );
        assert!(html.contains("no answer within 15 s"));
        assert!(!html.contains("<form"));
    }

    #[test]
    fn a_foreign_sender_domain_is_the_worst_sender_finding() {
        let mut d = healthy();
        d.sender_domain = "hyperion.com".into();
        d.sender_auth_status = "foreign-reject".into();
        assert_eq!(MailDiag { d: d.clone() }.sender_tone(), "err");
        d.sender_auth_status = "no-spf".into();
        assert_eq!(MailDiag { d: d.clone() }.sender_tone(), "warn");
        d.ptr_status = "missing".into();
        d.public_ipv4 = "203.0.113.5".into();
        let v = MailDiag { d };
        assert_eq!(v.ptr_tone(), "warn");
        assert_eq!(v.ptr_summary(), "203.0.113.5 has no PTR record");
    }
}
