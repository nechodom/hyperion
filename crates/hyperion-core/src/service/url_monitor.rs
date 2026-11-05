//! URL checks, run from the master: the replacement for an external uptime
//! tool.
//!
//! A check is an address, an interval and an optional expected status. The
//! master probes it with the same `probe_http` the per-hosting monitor uses
//! and decides with the same `monitor_transition`, so a flapping site is
//! judged identically in both places. What differs is the vantage point (a
//! whole node dying is seen from outside) and the owner of the address,
//! which need not be a hosting at all.
//!
//! A decision is not an alert. The tick PARKS what changed (`pending_alert`)
//! and returns it; the web layer, which can ask nodes things, adds what it
//! learnt (is the node behind the address answering, what does its Docker
//! stack say) and calls [`HostingService::url_monitor_alert`], which sends
//! and acknowledges. An alert nobody acknowledged is returned again by the
//! next tick, so a restart between the two loses nothing.
//!
//! Everything is master only, and only while the Docker module is on for the
//! cluster: with it off nothing is probed, listed or sent.

use super::monitor::{monitor_transition, probe_http, HttpProbeResult, MonitorTransition};
use super::notify::{docker_outbound_text, http_post_json, truncate_chars};
use super::*;
use hyperion_state::url_monitors as store;
use hyperion_types::url_monitor::{
    UrlAlertContext, UrlMonitorEvent, UrlMonitorInput, UrlMonitorList, UrlMonitorView,
    URL_MIN_INTERVAL_SECS,
};
use std::time::Duration;

/// Probes in flight at once.
const CONCURRENCY: usize = 20;
/// Most a tick spends sampling. Every probe has its own `--max-time`, so
/// this only matters with more hung addresses than `CONCURRENCY` fits in it;
/// whatever is not done is due again on the next tick.
const TICK_BUDGET: Duration = Duration::from_secs(90);
/// Samples are kept this long.
const KEEP_SAMPLES_SECS: i64 = 7 * 86_400;
/// The window the page's figures cover.
const FIGURES_SECS: i64 = 86_400;
/// An https certificate is read at most this often per check.
const CERT_EVERY_SECS: i64 = 3_600;
/// Seconds one certificate read may take. Shorter than a probe, and run
/// beside it, so it never lengthens a check.
const CERT_MAX_TIME_SECS: &str = "10";
/// Days left at which a certificate warns, once each.
pub(super) const CERT_ALERT_DAYS: [i64; 2] = [14, 3];

const MAX_CHECKS: i64 = 500;
const URL_MAX_CHARS: usize = 2_048;
const HOOK_MAX_CHARS: usize = 2_048;
const NODE_MAX_CHARS: usize = 128;
const EMAIL_MAX_ADDRESSES: usize = 10;
/// Longest error or stack line carried into an alert.
const LINE_MAX_CHARS: usize = 300;
const ALERT_HREF: &str = "/monitoring";

/// Who the audit entry names: the person who asked, else the agent.
fn audit_actor(actor: &str) -> &str {
    let a = actor.trim();
    if a.is_empty() || a.chars().count() > 64 || a.chars().any(|c| c.is_control()) {
        "agent"
    } else {
        a
    }
}

fn db_err(what: &str, e: hyperion_state::StateError) -> RpcError {
    RpcError::Internal_with(format!("{what}: {e}"))
}

fn invalid(message: impl Into<String>) -> RpcError {
    RpcError::Validation {
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Judge a probe against the status the operator expects.
///
/// `probe_http` calls 2xx/3xx healthy and everything else down. A check may
/// expect a status that is "down" to the probe (a login wall that answers
/// 401 on purpose), or insist on one that it would call healthy. The probe
/// followed redirects, so the status is the final one.
///
/// A match passes unless the page itself is broken: the probe's body checks
/// (an empty 200, a WordPress fatal) and a transfer that was cut short stay
/// failures, since the status line alone says nothing about those.
pub(super) fn url_check_outcome(result: HttpProbeResult, expected: Option<i64>) -> HttpProbeResult {
    let (Some(want), Some(got)) = (expected, result.http_status) else {
        return result;
    };
    // The probe's own wording when the status alone decided it.
    let status_only = result.error_message.as_deref() == Some(format!("HTTP {got}").as_str());
    if got == want {
        if result.success || status_only {
            return HttpProbeResult {
                success: true,
                error_message: None,
                hard_failure: false,
                ..result
            };
        }
        return result;
    }
    HttpProbeResult {
        success: false,
        error_message: Some(format!("HTTP {got}, expected {want}")),
        hard_failure: got >= 500,
        ..result
    }
}

/// The expiry, in unix seconds, of the first certificate in the output of
/// `curl -w '%{certs}'`: the site's own, the chain follows it.
///
/// Builds print the date as `Jan 11 14:17:51 2027 GMT` (a one-digit day is
/// space padded) or as `2027-01-11 14:17:51 GMT`; both are read, as UTC. No
/// date, or one in neither shape, is `None`: an unreadable answer must never
/// become an invented expiry.
pub(super) fn parse_cert_expiry(curl_certs: &str) -> Option<i64> {
    let line = curl_certs
        .lines()
        .find_map(|l| l.trim().strip_prefix("Expire date:"))?;
    let words: Vec<&str> = line.split_whitespace().collect();
    // A trailing zone name is cosmetic: curl prints GMT, some builds UTC.
    let words = match words.last() {
        Some(z) if z.eq_ignore_ascii_case("gmt") || z.eq_ignore_ascii_case("utc") => {
            &words[..words.len() - 1]
        }
        _ => &words[..],
    };
    let text = words.join(" ");
    ["%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"]
        .iter()
        .find_map(|f| chrono::NaiveDateTime::parse_from_str(&text, f).ok())
        .map(|d| d.and_utc().timestamp())
}

/// Which certificate warning, if any, is owed now. `last_day` is the
/// threshold last warned about. Each threshold warns once per certificate:
/// the most urgent one reached is returned, and only when it is more urgent
/// than what was already said. A certificate that was renewed (far from
/// expiry again) is for the caller to reset.
pub(super) fn cert_alert_due(expires_at: i64, now: i64, last_day: Option<i64>) -> Option<i64> {
    let left = expires_at - now;
    let reached = CERT_ALERT_DAYS
        .iter()
        .copied()
        .filter(|d| left <= d * 86_400)
        .min()?;
    last_day
        .map_or(true, |last| last > reached)
        .then_some(reached)
}

/// Is it time to read this check's certificate again?
pub(super) fn cert_check_due(checked_at: i64, now: i64) -> bool {
    now - checked_at >= CERT_EVERY_SECS
}

/// Collapse a text to one line of at most [`LINE_MAX_CHARS`] characters, with
/// control characters (escapes, newlines) turned into spaces. Probe errors
/// come from curl and stack summaries from another machine; neither may add
/// lines or escape sequences to an alert.
fn one_line(s: &str) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    truncate_chars(
        &flat.split_whitespace().collect::<Vec<_>>().join(" "),
        LINE_MAX_CHARS,
    )
}

fn has_forbidden_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn validate_url(raw: &str) -> Result<(), RpcError> {
    if raw.is_empty() || raw.chars().count() > URL_MAX_CHARS {
        return Err(invalid(format!(
            "the address must be between 1 and {URL_MAX_CHARS} characters"
        )));
    }
    if has_forbidden_chars(raw) {
        return Err(invalid(
            "the address must not contain spaces or line breaks",
        ));
    }
    // The parser forgives `https:///host` and `https:\\host`; a typo that
    // forgiving would store an address nobody wrote.
    let after_scheme = raw.split_once("://").map(|(_, rest)| rest);
    if after_scheme.map_or(true, |rest| rest.starts_with(['/', '\\'])) {
        return Err(invalid(
            "not a web address; write it as https://example.com/",
        ));
    }
    let parsed = url::Url::parse(raw)
        .map_err(|_| invalid("not a web address; write it as https://example.com/"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid(
            "only http:// and https:// addresses can be checked",
        ));
    }
    if parsed.host_str().map_or(true, str::is_empty) {
        return Err(invalid("the address has no host name"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid(
            "the address must not carry a user name or password; they would be \
             stored and sent in clear text",
        ));
    }
    Ok(())
}

/// A webhook address: http or https, nothing else.
fn validate_hook(what: &str, raw: &str) -> Result<(), RpcError> {
    let ok = raw.chars().count() <= HOOK_MAX_CHARS
        && !has_forbidden_chars(raw)
        && url::Url::parse(raw)
            .map(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "{what} must be an http:// or https:// address"
        )))
    }
}

fn validate_emails(raw: &str) -> Result<(), RpcError> {
    let list: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .collect();
    if list.len() > EMAIL_MAX_ADDRESSES {
        return Err(invalid(format!(
            "at most {EMAIL_MAX_ADDRESSES} alert addresses"
        )));
    }
    for a in list {
        let at = a.find('@');
        let ok = a.len() <= 254
            && !has_forbidden_chars(a)
            && at.is_some_and(|i| i > 0 && i + 1 < a.len() && !a[i + 1..].contains('@'));
        if !ok {
            return Err(invalid(format!("'{a}' is not an e-mail address")));
        }
    }
    Ok(())
}

fn clean(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// A secret field: set when a value came in, cleared on request, else kept.
fn secret<'a>(value: &'a Option<String>, clear: bool) -> store::SecretField<'a> {
    match (
        clear,
        value.as_deref().map(str::trim).filter(|v| !v.is_empty()),
    ) {
        (true, _) => store::SecretField::Clear,
        (false, Some(v)) => store::SecretField::Set(v),
        (false, None) => store::SecretField::Keep,
    }
}

/// Where a check points, as far as the audit trail needs: scheme, host and
/// port. The path and query are left out, since either may carry a token.
fn url_for_audit(raw: &str) -> String {
    url::Url::parse(raw)
        .map(|u| {
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{}://{}{port}", u.scheme(), u.host_str().unwrap_or(""))
        })
        .unwrap_or_default()
}

fn host_of(raw: &str) -> String {
    url::Url::parse(raw)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| truncate_chars(raw, 60))
}

/// What a failed probe says, for the alert and the page.
fn failure_text(r: &HttpProbeResult) -> String {
    one_line(
        &r.error_message
            .clone()
            .or_else(|| r.http_status.map(|c| format!("HTTP {c}")))
            .unwrap_or_else(|| "no response".to_string()),
    )
}

/// `curl -w '%{certs}'` against an https address, reduced to the expiry.
/// Reads the TLS handshake and a HEAD answer, nothing more. `None` when curl
/// is absent, the host did not answer, or this curl build prints no
/// certificate information.
async fn read_cert_expiry(url: &str) -> Option<i64> {
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args([
            "-sk",
            "-I",
            "-o",
            "/dev/null",
            "--connect-timeout",
            "5",
            "--max-time",
            CERT_MAX_TIME_SECS,
            "-w",
            "%{certs}",
            url,
        ])
        .output()
        .await
        .ok()?;
    parse_cert_expiry(&String::from_utf8_lossy(&out.stdout))
}

/// One probe and, for an https address whose certificate is due, the read of
/// it beside it.
async fn sample_one(row: store::Row, now: i64) -> (i64, HttpProbeResult, Option<Option<i64>>) {
    let want_cert = row.url.starts_with("https://") && cert_check_due(row.cert_checked_at, now);
    let probe = async { url_check_outcome(probe_http(&row.url).await, row.expected_status) };
    let cert = async {
        if want_cert {
            Some(read_cert_expiry(&row.url).await)
        } else {
            None
        }
    };
    let (result, cert) = tokio::join!(probe, cert);
    (row.id, result, cert)
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

impl<A: AdapterPort + 'static> HostingService<A> {
    fn url_master_only(&self) -> Result<(), RpcError> {
        if self.is_worker_node() {
            return Err(invalid("URL checks run on the master"));
        }
        Ok(())
    }

    /// Checks exist only while the module is on for the cluster.
    async fn url_module_on(&self) -> bool {
        hyperion_state::docker::get_module(&self.pool)
            .await
            .map(|m| m.cluster_installed)
            .unwrap_or(false)
    }

    pub async fn url_monitor_list(&self) -> Result<UrlMonitorList, RpcError> {
        self.url_master_only()?;
        if !self.url_module_on().await {
            return Ok(UrlMonitorList::default());
        }
        let now = now_secs();
        let rows = store::list(&self.pool)
            .await
            .map_err(|e| db_err("url_monitor_list", e))?;
        let mut monitors = Vec::with_capacity(rows.len());
        for r in rows {
            let st = store::stats_since(&self.pool, r.id, now - FIGURES_SECS)
                .await
                .map_err(|e| db_err("url_monitor_list", e))?;
            monitors.push(UrlMonitorView {
                id: r.id,
                url: r.url,
                interval_secs: r.interval_secs,
                expected_status: r.expected_status,
                alert_after_fails: r.alert_after_fails,
                alert_email: r.alert_email.unwrap_or_default(),
                alert_slack_set: r.alert_slack_webhook.is_some(),
                alert_webhook_set: r.alert_webhook_url.is_some(),
                node_id: r.node_id,
                node_manual: r.node_manual,
                alert_state: if r.last_sampled_at == 0 {
                    "unknown".to_string()
                } else {
                    r.alert_state
                },
                samples_24h: st.samples,
                success_pct_24h: if st.samples > 0 {
                    st.ok * 100 / st.samples
                } else {
                    0
                },
                avg_ms_24h: st.avg_ms,
                last_sampled_at: st.last_sampled_at,
                last_error: st.last_error,
                cert_expires_at: r.cert_expires_at,
            });
        }
        Ok(UrlMonitorList {
            enabled: true,
            monitors,
        })
    }

    pub async fn url_monitor_set(&self, input: UrlMonitorInput) -> Result<i64, RpcError> {
        self.url_master_only()?;
        if !self.url_module_on().await {
            return Err(invalid(
                "URL checks belong to the Docker module. Turn the Docker module on first.",
            ));
        }
        let url = input.url.trim();
        validate_url(url)?;
        if input.interval_secs < URL_MIN_INTERVAL_SECS || input.interval_secs > 86_400 {
            return Err(invalid(format!(
                "the interval must be between {URL_MIN_INTERVAL_SECS} seconds and a day"
            )));
        }
        if let Some(s) = input.expected_status {
            if !(100..=599).contains(&s) {
                return Err(invalid("the expected status must be between 100 and 599"));
            }
        }
        if !(1..=20).contains(&input.alert_after_fails) {
            return Err(invalid(
                "alert after must be between 1 and 20 failed checks",
            ));
        }
        let email = clean(&input.alert_email);
        if let Some(e) = &email {
            validate_emails(e)?;
        }
        if let Some(h) = clean(&input.alert_slack_webhook) {
            validate_hook("the Slack webhook", &h)?;
        }
        if let Some(h) = clean(&input.alert_webhook_url) {
            validate_hook("the webhook", &h)?;
        }
        let node = clean(&input.node_id);
        if let Some(n) = &node {
            if n.chars().count() > NODE_MAX_CHARS || n.chars().any(|c| c.is_control()) {
                return Err(invalid("not a node id"));
            }
        }
        let fields = store::Fields {
            url,
            interval_secs: input.interval_secs,
            expected_status: input.expected_status,
            alert_after_fails: input.alert_after_fails,
            alert_email: email.as_deref(),
            slack: secret(&input.alert_slack_webhook, input.clear_slack_webhook),
            webhook: secret(&input.alert_webhook_url, input.clear_webhook_url),
            node_id: node.as_deref(),
            node_manual: input.node_manual,
        };
        let created = input.id.is_none();
        let id = match input.id {
            Some(id) => {
                if !store::update(&self.pool, id, &fields)
                    .await
                    .map_err(|e| db_err("url_monitor_set", e))?
                {
                    return Err(RpcError::NotFound {
                        kind: "url check".into(),
                        id: id.to_string(),
                    });
                }
                id
            }
            None => {
                if store::count(&self.pool)
                    .await
                    .map_err(|e| db_err("url_monitor_set", e))?
                    >= MAX_CHECKS
                {
                    return Err(invalid(format!("at most {MAX_CHECKS} URL checks")));
                }
                store::insert(&self.pool, &fields, now_secs())
                    .await
                    .map_err(|e| db_err("url_monitor_set", e))?
            }
        };
        // Where it points and how it is checked; never a webhook, and never
        // the query part of the address, which may be a token.
        self.append_audit_as(
            0,
            audit_actor(&input.actor),
            "url_monitor.set",
            None,
            &serde_json::json!({
                "id": id,
                "created": created,
                "url": url_for_audit(url),
                "interval_secs": input.interval_secs,
                "expected_status": input.expected_status,
                "node": node,
                "node_manual": input.node_manual,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(id)
    }

    pub async fn url_monitor_delete(&self, id: i64, actor: &str) -> Result<(), RpcError> {
        self.url_master_only()?;
        let gone = store::delete(&self.pool, id)
            .await
            .map_err(|e| db_err("url_monitor_delete", e))?;
        if gone {
            self.append_audit_as(
                0,
                audit_actor(actor),
                "url_monitor.delete",
                None,
                &serde_json::json!({ "id": id }).to_string(),
                "ok",
            )
            .await;
        }
        Ok(())
    }

    /// Sample every check that is due, decide, and return the alerts still
    /// waiting to be acknowledged.
    pub async fn url_monitor_tick(&self) -> Result<Vec<UrlMonitorEvent>, RpcError> {
        self.url_tick_at(now_secs()).await
    }

    pub(super) async fn url_tick_at(&self, now: i64) -> Result<Vec<UrlMonitorEvent>, RpcError> {
        self.url_master_only()?;
        if !self.url_module_on().await {
            return Ok(Vec::new());
        }
        let rows = store::list(&self.pool)
            .await
            .map_err(|e| db_err("url_monitor_tick", e))?;
        let mut due: Vec<store::Row> = rows
            .into_iter()
            .filter(|r| now - r.last_sampled_at >= r.interval_secs)
            .collect();
        // The longest-waiting first, so a pile of hung addresses cannot
        // starve the rest.
        due.sort_by_key(|r| (r.last_sampled_at, r.id));

        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
        let mut set = tokio::task::JoinSet::new();
        for row in due {
            let permits = permits.clone();
            set.spawn(async move {
                let _slot = permits.acquire_owned().await;
                sample_one(row, now).await
            });
        }
        let deadline = tokio::time::Instant::now() + TICK_BUDGET;
        while let Ok(Some(done)) = tokio::time::timeout_at(deadline, set.join_next()).await {
            let Ok((id, result, cert)) = done else {
                continue;
            };
            let at = now_secs();
            if let Err(e) = self.url_apply_sample(id, &result, at).await {
                tracing::warn!(id, error = %e, "url check: could not record a sample");
            }
            if let Some(expires) = cert {
                if let Err(e) = store::set_cert_read(&self.pool, id, at, expires).await {
                    tracing::warn!(id, error = %e, "url check: could not record a certificate");
                }
            }
        }
        // Anything still running past the budget is abandoned; its curl ends
        // on its own --max-time and the check is due again next tick.
        set.abort_all();

        if let Err(e) = store::prune_samples(&self.pool, now - KEEP_SAMPLES_SECS).await {
            tracing::warn!(error = %e, "url check: could not prune samples");
        }
        self.url_cert_alerts(now).await?;
        let pending = store::pending(&self.pool)
            .await
            .map_err(|e| db_err("url_monitor_tick", e))?;
        Ok(pending
            .into_iter()
            .map(|r| UrlMonitorEvent {
                id: r.id,
                url: r.url,
                node_id: r.node_id,
                down: r.pending_alert.as_deref() == Some("down"),
                error: r.pending_error,
            })
            .collect())
    }

    /// Record one probe of check `id` and decide what it changes. Uses the
    /// per-hosting monitor's window and `monitor_transition`, so the two
    /// agree on what a flapping site is. The decision is parked, not sent.
    pub(super) async fn url_apply_sample(
        &self,
        id: i64,
        result: &HttpProbeResult,
        now: i64,
    ) -> Result<Option<MonitorTransition>, RpcError> {
        let Some(row) = store::get(&self.pool, id)
            .await
            .map_err(|e| db_err("url_apply_sample", e))?
        else {
            // Deleted while it was being probed.
            return Ok(None);
        };
        let err = |e| db_err("url_apply_sample", e);
        store::insert_sample(
            &self.pool,
            id,
            &store::Sample {
                sampled_at: now,
                success: result.success,
                http_status: result.http_status,
                response_ms: result.response_ms,
                error_message: result.error_message.as_deref().map(one_line),
            },
        )
        .await
        .map_err(err)?;
        store::set_sampled(&self.pool, id, now).await.map_err(err)?;
        let window = (row.alert_after_fails * 2).max(4);
        let recent = store::recent(&self.pool, id, window).await.map_err(err)?;
        let transition = monitor_transition(
            row.alert_state == "alerting",
            row.last_alert_at,
            &recent,
            row.alert_after_fails,
            result.hard_failure,
        );
        match transition {
            Some(MonitorTransition::Down) => {
                store::record_transition(&self.pool, id, true, Some(&failure_text(result)), now)
                    .await
                    .map_err(err)?
            }
            Some(MonitorTransition::Up) => {
                store::record_transition(&self.pool, id, false, None, now)
                    .await
                    .map_err(err)?
            }
            None => {}
        }
        Ok(transition)
    }

    /// Warn about certificates close to expiring, once per threshold, and
    /// forget the warnings of one that was renewed.
    pub(super) async fn url_cert_alerts(&self, now: i64) -> Result<(), RpcError> {
        let rows = store::list(&self.pool)
            .await
            .map_err(|e| db_err("url_cert_alerts", e))?;
        for row in rows {
            let Some(expires) = row.cert_expires_at else {
                continue;
            };
            let Some(day) = cert_alert_due(expires, now, row.cert_alert_day) else {
                // Renewed: the next certificate warns afresh.
                if row.cert_alert_day.is_some() && expires - now > CERT_ALERT_DAYS[0] * 86_400 {
                    store::set_cert_alert_day(&self.pool, row.id, None)
                        .await
                        .map_err(|e| db_err("url_cert_alerts", e))?;
                }
                continue;
            };
            // Recorded first: a warning that fails to send is not repeated
            // every tick for the life of the certificate.
            store::set_cert_alert_day(&self.pool, row.id, Some(day))
                .await
                .map_err(|e| db_err("url_cert_alerts", e))?;
            self.url_cert_alert(&row, expires, now).await;
        }
        Ok(())
    }

    async fn url_cert_alert(&self, row: &store::Row, expires: i64, now: i64) {
        let cat = self.operator_catalog();
        let date = chrono::DateTime::<chrono::Utc>::from_timestamp(expires, 0)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        let days_left = (expires - now).div_euclid(86_400);
        let expired = expires <= now;
        let (severity, id) = if expired {
            ("error", "ops.url_cert_expired")
        } else {
            ("warn", "ops.url_cert")
        };
        let left = format!("{days_left} {}", cat.plural("unit_day", days_left));
        let args = [
            ("url", row.url.as_str()),
            ("left", left.as_str()),
            ("date", date.as_str()),
        ];
        let title = cat.render(&format!("{id}.title"), &args);
        let body = cat.render(&format!("{id}.body"), &args);
        let kind = format!("url.cert:{}", row.id);
        self.notify_admins(severity, &title, &body, ALERT_HREF, &kind)
            .await;
        let payload = serde_json::json!({
            "kind": "CERT",
            "url": row.url,
            "expires_at": expires,
            "days_left": days_left,
            "expired": expired,
        });
        let subject = format!("{title}: {}", host_of(&row.url));
        self.url_outbound(row, &subject, &body, &kind, payload)
            .await;
    }

    /// Send the alert check `id` owes and acknowledge it. Asking again for
    /// one already acknowledged does nothing.
    pub async fn url_monitor_alert(
        &self,
        id: i64,
        context: UrlAlertContext,
    ) -> Result<(), RpcError> {
        self.url_master_only()?;
        if !self.url_module_on().await {
            return Ok(());
        }
        let Some(row) = store::get(&self.pool, id)
            .await
            .map_err(|e| db_err("url_monitor_alert", e))?
        else {
            return Ok(());
        };
        let Some(pending) = row.pending_alert.clone() else {
            return Ok(());
        };
        let down = pending == "down";

        // The web layer worked the owner out again on a recovery. A node
        // the operator chose stays.
        if context.node_rederived && !row.node_manual {
            let node = clean(&context.node_id);
            if node.as_deref().map_or(true, |n| {
                n.chars().count() <= NODE_MAX_CHARS && !n.chars().any(|c| c.is_control())
            }) {
                store::set_node(&self.pool, id, node.as_deref())
                    .await
                    .map_err(|e| db_err("url_monitor_alert", e))?;
            }
        }

        let cat = self.operator_catalog();
        let error = row
            .pending_error
            .as_deref()
            .map(one_line)
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| "no response".to_string());
        let (severity, title, body) = if down {
            let mut extra = String::new();
            if context.node_unreachable {
                extra.push('\n');
                extra.push_str(&cat.render("ops.url_down.node_note", &[]));
            }
            if let Some(summary) = context.stack_summary.as_deref().map(one_line) {
                if !summary.is_empty() {
                    extra.push('\n');
                    extra.push_str(
                        &cat.render("ops.url_down.stack_note", &[("summary", summary.as_str())]),
                    );
                }
            }
            let args = [
                ("url", row.url.as_str()),
                ("error", error.as_str()),
                ("extra", extra.as_str()),
            ];
            (
                "error",
                cat.render("ops.url_down.title", &args),
                cat.render("ops.url_down.body", &args),
            )
        } else {
            let args = [("url", row.url.as_str())];
            (
                "info",
                cat.render("ops.url_up.title", &args),
                cat.render("ops.url_up.body", &args),
            )
        };

        let kind = format!("url.monitor:{id}");
        self.notify_admins(severity, &title, &body, ALERT_HREF, &kind)
            .await;
        let status = store::last_status(&self.pool, id).await.unwrap_or(None);
        let payload = serde_json::json!({
            "kind": if down { "DOWN" } else { "RESOLVED" },
            "url": row.url,
            "resolved": !down,
            "error": down.then_some(&error),
            "http_status": status,
            "node_unreachable": context.node_unreachable,
            "stack": context.stack_summary.as_deref().map(one_line).filter(|s| !s.is_empty()),
        });
        let subject = format!("{title}: {}", host_of(&row.url));
        let channels = self
            .url_outbound(&row, &subject, &body, &kind, payload)
            .await;

        // Only the alert that was sent is cleared: a change decided while
        // this one was going out stays parked.
        store::ack_pending(&self.pool, id, &pending)
            .await
            .map_err(|e| db_err("url_monitor_alert", e))?;
        self.append_audit(
            "url_monitor.alert",
            None,
            &serde_json::json!({ "id": id, "down": down, "channels": channels }).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Send past the bell. A channel the check has of its own is used; a
    /// missing mail list or Slack webhook falls back to the master's global
    /// one, and the generic webhook exists only on the check. Returns which
    /// channels were attempted, for the audit record.
    ///
    /// Each message is the same text the bell shows plus a link to the page;
    /// webhook addresses go only to `http_post_json`. Nothing here fails the
    /// caller.
    async fn url_outbound(
        &self,
        row: &store::Row,
        subject: &str,
        body: &str,
        kind: &str,
        payload: serde_json::Value,
    ) -> serde_json::Value {
        let panel = self.notify_panel_url();
        let full = if panel.is_empty() {
            body.to_string()
        } else {
            format!("{body}\n{panel}{ALERT_HREF}")
        };

        let own_mail: Vec<&str> = row
            .alert_email
            .as_deref()
            .map(|l| {
                l.split(',')
                    .map(str::trim)
                    .filter(|a| !a.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let mail = if own_mail.is_empty() {
            self.outbound_global_email(subject, &full).await;
            "global"
        } else {
            for to in &own_mail {
                self.notify_email(to, subject, &full, None, "url_monitor")
                    .await;
            }
            "own"
        };

        let slack = match row.alert_slack_webhook.as_deref() {
            Some(url) => {
                let text = docker_outbound_text(subject, &full);
                let outcome =
                    http_post_json(url, &serde_json::json!({ "text": text }).to_string()).await;
                if let Err(e) = &outcome {
                    // The reason, never the address: it is a credential.
                    tracing::warn!(kind, error = %e, "url check: Slack post failed");
                }
                self.append_audit(
                    "notify.url.slack",
                    None,
                    &serde_json::json!({ "kind": kind }).to_string(),
                    if outcome.is_ok() { "ok" } else { "failed" },
                )
                .await;
                "own"
            }
            None => {
                self.outbound_global_slack(subject, &full, kind, "notify.docker.slack")
                    .await;
                "global"
            }
        };

        let webhook = match row.alert_webhook_url.as_deref() {
            Some(url) => {
                if let Err(e) = http_post_json(url, &payload.to_string()).await {
                    tracing::warn!(kind, error = %e, "url check: webhook post failed");
                }
                true
            }
            None => false,
        };
        serde_json::json!({ "email": mail, "slack": slack, "webhook": webhook })
    }
}
