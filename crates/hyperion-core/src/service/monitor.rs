//! The per-hosting HTTP uptime monitor and its alerts.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    pub async fn monitor_overview(
        &self,
    ) -> Result<Vec<hyperion_types::MonitorOverviewItem>, RpcError> {
        let configs = hyperion_state::monitors::list_enabled(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        // 12 samples/hour × 24 = 288. Cap so we don't pull weeks of
        // history just to compute one number.
        const WINDOW: i64 = 288;
        let mut out = Vec::with_capacity(configs.len());
        for cfg in configs {
            let samples = hyperion_state::monitors::history(&self.pool, &cfg.hosting_id, WINDOW)
                .await
                .unwrap_or_default();
            let total = samples.len() as i64;
            let ok = samples.iter().filter(|s| s.success).count() as i64;
            let success_pct = if total > 0 { (ok * 100) / total } else { 0 };
            let avg_ms = if ok > 0 {
                samples
                    .iter()
                    .filter(|s| s.success)
                    .map(|s| s.response_ms)
                    .sum::<i64>()
                    / ok
            } else {
                0
            };
            let last_sampled_at = samples.iter().map(|s| s.sampled_at).max().unwrap_or(0);
            let alert_state = if total == 0 {
                "unknown".to_string()
            } else {
                cfg.alert_state.clone()
            };
            out.push(hyperion_types::MonitorOverviewItem {
                hosting_id: cfg.hosting_id.as_str().to_string(),
                domain: cfg.domain,
                url_path: cfg.url_path,
                interval_secs: cfg.interval_secs,
                alert_state,
                consecutive_fails: cfg.consecutive_fails,
                last_alert_at: cfg.last_alert_at,
                samples_24h: total,
                success_pct_24h: success_pct,
                avg_response_ms_24h: avg_ms,
                last_sampled_at,
                node_id: String::new(),
            });
        }
        // Stable sort: alerting first (most urgent), then by success
        // rate ascending (worst-performing surfaced next), then by
        // domain alphabetical.
        out.sort_by(|a, b| {
            let alert_rank = |s: &str| match s {
                "alerting" => 0,
                "unknown" => 1,
                _ => 2,
            };
            let ra = alert_rank(a.alert_state.as_str());
            let rb = alert_rank(b.alert_state.as_str());
            ra.cmp(&rb)
                .then(a.success_pct_24h.cmp(&b.success_pct_24h))
                .then(a.domain.cmp(&b.domain))
        });
        Ok(out)
    }

    pub async fn monitor_get(
        &self,
        sel: HostingSelector,
    ) -> Result<
        (
            hyperion_types::MonitorConfigView,
            hyperion_types::MonitorHistory,
        ),
        RpcError,
    > {
        let detail = self.get(sel).await?;
        let cfg = hyperion_state::monitors::get(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("monitor get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.as_str().to_string(),
            })?;
        let view = hyperion_types::MonitorConfigView {
            enabled: cfg.enabled,
            url_path: cfg.url_path,
            interval_secs: cfg.interval_secs,
            alert_after_fails: cfg.alert_after_fails,
            alert_email: cfg.alert_email,
            alert_slack_webhook_set: cfg.alert_slack_webhook.is_some(),
            alert_webhook_url: cfg.alert_webhook_url,
            consecutive_fails: cfg.consecutive_fails,
            last_alert_at: cfg.last_alert_at,
            alert_state: cfg.alert_state,
        };
        // 96 samples = 8 hours @ 5min default cadence.
        let rows = hyperion_state::monitors::history(&self.pool, &detail.id, 96)
            .await
            .map_err(|e| RpcError::Internal_with(format!("history: {e}")))?;
        let history = hyperion_types::MonitorHistory {
            samples: rows
                .into_iter()
                .map(|s| hyperion_types::MonitorSamplePoint {
                    at: s.sampled_at,
                    success: s.success,
                    http_status: s.http_status,
                    response_ms: s.response_ms,
                })
                .collect(),
        };
        Ok((view, history))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn monitor_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
        url_path: Option<String>,
        interval_secs: Option<i64>,
        alert_after_fails: Option<i64>,
        alert_email: Option<String>,
        alert_slack_webhook: Option<String>,
        // Explicitly remove the stored Slack webhook. Separate from an empty
        // `alert_slack_webhook` because the secret is never shown to the
        // operator, so a blank field means "I was not shown it", not
        // "delete it".
        clear_slack_webhook: bool,
        alert_webhook_url: Option<String>,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // Validate URLs / path shape.
        let path_norm: Option<String> = url_path.map(|p| {
            let p = p.trim();
            if p.is_empty() {
                "/".to_string()
            } else if !p.starts_with('/') {
                format!("/{p}")
            } else {
                p.to_string()
            }
        });
        if let Some(ref u) = alert_slack_webhook {
            if !u.trim().is_empty() && !u.starts_with("https://") {
                return Err(RpcError::Validation {
                    message: "slack webhook must start with https://".into(),
                });
            }
        }
        if let Some(ref u) = alert_webhook_url {
            if !u.trim().is_empty() && !(u.starts_with("https://") || u.starts_with("http://")) {
                return Err(RpcError::Validation {
                    message: "webhook URL must start with http:// or https://".into(),
                });
            }
        }
        let to_opt_str = |s: Option<String>| -> Option<String> {
            s.map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
        };
        let slack_clean = to_opt_str(alert_slack_webhook);
        hyperion_state::monitors::set_config(
            &self.pool,
            &detail.id,
            enabled,
            path_norm.as_deref(),
            interval_secs,
            alert_after_fails,
            to_opt_str(alert_email).as_deref(),
            match (clear_slack_webhook, slack_clean.as_deref()) {
                (true, _) => hyperion_state::monitors::SecretField::Clear,
                (false, Some(v)) => hyperion_state::monitors::SecretField::Set(v),
                (false, None) => hyperion_state::monitors::SecretField::Keep,
            },
            to_opt_str(alert_webhook_url).as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set: {e}")))?;
        self.append_audit(
            "monitor.config.set",
            Some(detail.id.as_str()),
            &serde_json::json!({"enabled": enabled, "interval_secs": interval_secs}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn monitor_probe_now(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::MonitorSamplePoint, RpcError> {
        let detail = self.get(sel).await?;
        let cfg = hyperion_state::monitors::get(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.as_str().to_string(),
            })?;
        let sample = probe_site(&detail.domain, &cfg.url_path).await;
        let now = now_secs();
        hyperion_state::monitors::insert_sample(
            &self.pool,
            &detail.id,
            now,
            sample.success,
            sample.http_status,
            sample.response_ms,
            sample.error_message.as_deref(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("insert sample: {e}")))?;
        Ok(hyperion_types::MonitorSamplePoint {
            at: now,
            success: sample.success,
            http_status: sample.http_status,
            response_ms: sample.response_ms,
        })
    }

    /// One pass of the per-hosting monitor scheduler — checks every
    /// enabled hosting whose `monitor_interval_secs` has elapsed since
    /// the last sample. Fires alerts on threshold crossings. Returns
    /// the number of hostings sampled (for telemetry).
    pub async fn monitor_tick(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let configs = hyperion_state::monitors::list_enabled(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        let mut sampled = 0i64;
        for cfg in configs {
            // Skip if we've sampled within the configured interval.
            let recent = hyperion_state::monitors::history(&self.pool, &cfg.hosting_id, 1)
                .await
                .ok()
                .and_then(|v| v.last().map(|s| s.sampled_at))
                .unwrap_or(0);
            if recent > 0 && now - recent < cfg.interval_secs {
                continue;
            }
            // Auto-pause: if the hosting itself is suspended, probing
            // is guaranteed to fail (nginx serves a 503 suspend page)
            // and would spam alerts. Skip and leave the alert_state
            // in whatever it was before the suspend happened — when
            // the operator resumes, monitoring resumes too.
            if let Ok(Some(row)) =
                hyperion_state::hostings::get_by_id(&self.pool, &cfg.hosting_id).await
            {
                if row.state == hyperion_types::HostingState::Suspended {
                    continue;
                }
            }
            let result = probe_site(&cfg.domain, &cfg.url_path).await;
            if let Err(e) = hyperion_state::monitors::insert_sample(
                &self.pool,
                &cfg.hosting_id,
                now,
                result.success,
                result.http_status,
                result.response_ms,
                result.error_message.as_deref(),
            )
            .await
            {
                tracing::warn!(error=%e, "monitor: insert sample failed");
                continue;
            }
            sampled += 1;
            // Decide from the RECENT WINDOW, not from a bare consecutive
            // counter: a site that fails every other sample used to reset the
            // streak on each success and never alerted at all.
            let window = (cfg.alert_after_fails * 2).max(4);
            let recent: Vec<(i64, bool)> =
                hyperion_state::monitors::history(&self.pool, &cfg.hosting_id, window)
                    .await
                    .map(|v| v.iter().map(|s| (s.sampled_at, s.success)).collect())
                    .unwrap_or_else(|_| vec![(now, result.success)]);
            if result.success {
                let _ = hyperion_state::monitors::reset_streak(&self.pool, &cfg.hosting_id).await;
            } else {
                let _ = hyperion_state::monitors::record_fail(&self.pool, &cfg.hosting_id).await;
            }
            let alerting = cfg.alert_state == "alerting";
            match monitor_transition(
                alerting,
                cfg.last_alert_at,
                &recent,
                cfg.alert_after_fails,
                result.hard_failure,
            ) {
                Some(MonitorTransition::Up) => {
                    self.dispatch_monitor_alert(&cfg, &result, true).await;
                    let _ = hyperion_state::monitors::set_alert_state(
                        &self.pool,
                        &cfg.hosting_id,
                        "ok",
                        Some(now),
                    )
                    .await;
                }
                Some(MonitorTransition::Down) => {
                    self.dispatch_monitor_alert(&cfg, &result, false).await;
                    let _ = hyperion_state::monitors::set_alert_state(
                        &self.pool,
                        &cfg.hosting_id,
                        "alerting",
                        Some(now),
                    )
                    .await;
                }
                None => {}
            }
        }
        Ok(sampled)
    }

    /// Send an alert through every configured channel. `resolved`
    /// changes the subject + body wording.
    pub(super) async fn dispatch_monitor_alert(
        &self,
        cfg: &hyperion_state::monitors::MonitorConfig,
        sample: &HttpProbeResult,
        resolved: bool,
    ) {
        let kind = if resolved { "RESOLVED" } else { "DOWN" };
        // The bell, always: email/Slack/webhook below are per-monitor opt-ins,
        // so a monitor with none of them set used to change state in silence.
        // Down is an error (the site does not serve); recovery is info.
        let href = format!("/hostings/{}", cfg.domain);
        if resolved {
            self.notify_admins_say(
                "info",
                "ops.site_up",
                &[("domain", cfg.domain.as_str())],
                &href,
                &format!("monitor.up:{}", cfg.domain),
            )
            .await;
        } else {
            let error = sample
                .error_message
                .clone()
                .or_else(|| sample.http_status.map(|c| format!("HTTP {c}")))
                .unwrap_or_else(|| "no response".into());
            self.notify_admins_say(
                "error",
                "ops.site_down",
                &[("domain", cfg.domain.as_str()), ("error", error.as_str())],
                &href,
                &format!("monitor.down:{}", cfg.domain),
            )
            .await;
        }
        let subject = format!("[Hyperion] {kind} — {}", cfg.domain);
        let body = if resolved {
            format!(
                "Site recovered: https://{}{}\n\nLatest probe: {} ({} ms).\n\nThis is an automated message from Hyperion.\n",
                cfg.domain, cfg.url_path,
                sample.http_status.map(|s| s.to_string()).unwrap_or_else(|| "ok".into()),
                sample.response_ms
            )
        } else {
            format!(
                "Site failing: https://{}{}\n\nConsecutive failures: {}\nLast error: {}\nLast response: {} ms\n\nThis is an automated message from Hyperion.\n",
                cfg.domain, cfg.url_path,
                cfg.consecutive_fails + 1,
                sample.error_message.as_deref().unwrap_or("(none)"),
                sample.response_ms
            )
        };

        // Email channel.
        //
        // Goes through self.notify_email (not send_text directly) so
        // every recipient lands in email_log with kind="monitor",
        // hosting_id pre-filled, and the audit chain captures the
        // outcome. Previously this used send_text and the /emails
        // page + per-hosting Emails tab silently missed every alert.
        if cfg.alert_email.is_some() && self.email_config.is_some() {
            let email = cfg.alert_email.as_deref().unwrap_or("");
            for to in email.split(',') {
                let to = to.trim();
                if to.is_empty() {
                    continue;
                }
                self.notify_email(
                    to,
                    &subject,
                    &body,
                    Some(cfg.hosting_id.as_str()),
                    "monitor",
                )
                .await;
            }
        }
        // Slack webhook channel.
        if let Some(url) = cfg.alert_slack_webhook.as_deref() {
            let payload = serde_json::json!({"text": format!("{subject}\n{body}")}).to_string();
            let _ = http_post_json(url, &payload).await;
        }
        // Generic JSON webhook channel.
        if let Some(url) = cfg.alert_webhook_url.as_deref() {
            let payload = serde_json::json!({
                "kind": kind,
                "domain": cfg.domain,
                "url_path": cfg.url_path,
                "resolved": resolved,
                "consecutive_fails": cfg.consecutive_fails + 1,
                "http_status": sample.http_status,
                "response_ms": sample.response_ms,
                "error": sample.error_message,
            })
            .to_string();
            let _ = http_post_json(url, &payload).await;
        }
        self.append_audit(
            "monitor.alert",
            Some(cfg.hosting_id.as_str()),
            &serde_json::json!({
                "kind": kind,
                "channels": {
                    "email": cfg.alert_email.is_some(),
                    "slack": cfg.alert_slack_webhook.is_some(),
                    "webhook": cfg.alert_webhook_url.is_some(),
                }
            })
            .to_string(),
            "ok",
        )
        .await;
    }
}

/// Result of a single HTTP probe. Internal — service builds the wire
/// shape from this.
#[derive(Debug, Clone)]
pub(super) struct HttpProbeResult {
    pub(super) success: bool,
    pub(super) http_status: Option<i64>,
    pub(super) response_ms: i64,
    pub(super) error_message: Option<String>,
    /// The site answered and what it said is unambiguously broken (a 5xx, or
    /// a 2xx whose body is a WordPress/PHP fatal-error page). Such a failure
    /// is not a network blip, so it alerts after fewer consecutive samples.
    pub(super) hard_failure: bool,
}

/// Should the monitor raise an alert? `recent` is the newest-last success
/// flags of the latest samples, the current one included. Alert on
/// `threshold` failures IN A ROW (`2` at most when the site answered with an
/// error page: it is down, not flaky), or on `threshold` failures within the
/// last `2 * threshold` samples — a site flapping every other request is
/// broken even though no streak ever builds.
pub(super) fn monitor_should_alert(recent: &[bool], threshold: i64, hard: bool) -> bool {
    let threshold = threshold.max(1) as usize;
    let streak_needed = if hard { threshold.min(2) } else { threshold };
    let streak = recent.iter().rev().take_while(|ok| !**ok).count();
    let window = recent.len().saturating_sub(threshold * 2);
    let fails_in_window = recent[window..].iter().filter(|ok| !**ok).count();
    streak >= streak_needed || fails_in_window >= threshold
}

/// An open alert resolves only after a few clean samples in a row (two, or
/// the threshold if smaller), so a flapping site does not resolve and re-fire
/// on every lucky request.
pub(super) fn monitor_recovered(recent: &[bool], threshold: i64) -> bool {
    let need = (threshold.max(1) as usize).min(2);
    recent.len() >= need && recent.iter().rev().take(need).all(|ok| *ok)
}

/// A change of a monitor's alert state, announced to the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MonitorTransition {
    Down,
    Up,
}

/// What the newest sample does to a monitor's alert state. `recent` is
/// `(sampled_at, success)` newest-last, the current sample included;
/// `last_change_at` is when the state last flipped (`monitor_last_alert_at`).
///
/// While the site is up, only samples taken AFTER the last flip count: the
/// failures an incident was made of stay inside the 2×threshold window for a
/// few samples after it resolved, and counting them again re-fired "down" on
/// the very next clean probe — then "up", then "down" on the next blip, for
/// every site. And "down" is only ever announced on a failing probe.
pub(super) fn monitor_transition(
    alerting: bool,
    last_change_at: Option<i64>,
    recent: &[(i64, bool)],
    threshold: i64,
    hard: bool,
) -> Option<MonitorTransition> {
    if alerting {
        let flags: Vec<bool> = recent.iter().map(|(_, ok)| *ok).collect();
        return monitor_recovered(&flags, threshold).then_some(MonitorTransition::Up);
    }
    if !matches!(recent.last(), Some((_, false))) {
        return None;
    }
    let since = last_change_at.unwrap_or(i64::MIN);
    let flags: Vec<bool> = recent
        .iter()
        .filter(|(at, _)| *at > since)
        .map(|(_, ok)| *ok)
        .collect();
    monitor_should_alert(&flags, threshold, hard).then_some(MonitorTransition::Down)
}

/// Probe the configured path and, when that is the homepage, a second page
/// that renders through a different template. The homepage is often cached or
/// near-static while the rest of a WordPress site is broken (a plugin fatal on
/// archive/search templates, a theme error off the front page). The second
/// probe only counts when it is unambiguously broken (5xx / error page): a 404
/// there is just a non-WordPress site and must not alert.
pub(super) async fn probe_site(domain: &str, url_path: &str) -> HttpProbeResult {
    let path = if url_path.is_empty() { "/" } else { url_path };
    let primary = probe_http(&format!("https://{domain}{path}")).await;
    if !primary.success || path != "/" {
        return primary;
    }
    let second_path = "/?s=hyperion-probe";
    let second = probe_http(&format!("https://{domain}{second_path}")).await;
    if second.hard_failure {
        return HttpProbeResult {
            error_message: second
                .error_message
                .map(|m| format!("{m} (on {second_path})")),
            ..second
        };
    }
    primary
}

/// Marker for the status line appended after the body in the probe's curl
/// output, so one process yields both.
pub(super) const PROBE_STATUS_MARK: &str = "\n__HYPERION_PROBE_STATUS__";
/// Only the head of the body is inspected; fatal-error pages are tiny.
pub(super) const PROBE_BODY_CAP: usize = 64 * 1024;

/// Text that only ever appears on a broken page. Matched case-insensitively
/// against the head of a 2xx body. Deliberately specific — "fatal error" alone
/// would flag a blog post ABOUT fatal errors.
pub(super) const PROBE_BODY_MARKERS: &[(&str, &str)] = &[
    (
        "critical error on this website",
        "WordPress critical error page",
    ),
    (
        "error establishing a database connection",
        "database connection error",
    ),
    ("<b>fatal error</b>:", "PHP fatal error in page"),
    ("<b>parse error</b>:", "PHP parse error in page"),
    ("fatal error: uncaught", "PHP fatal error in page"),
    ("allowed memory size of", "PHP out of memory in page"),
];

/// Decide whether a response that arrived is a broken site. `None` = healthy.
/// A status in 200..400 is NOT enough: WordPress/PHP error pages are routinely
/// served as 200 (display_errors, caching layers, error-catching plugins), and
/// a white screen is a 200 with nothing in it.
pub(super) fn classify_probe(code: i64, body: &str) -> Option<(String, bool)> {
    if code >= 500 {
        return Some((format!("HTTP {code}"), true));
    }
    if !(200..400).contains(&code) {
        return Some((format!("HTTP {code}"), false));
    }
    if code == 200 {
        if body.trim().is_empty() {
            return Some(("HTTP 200 with an empty body (white screen)".into(), true));
        }
        let lower = body.to_lowercase();
        for (needle, what) in PROBE_BODY_MARKERS {
            if lower.contains(needle) {
                return Some((format!("HTTP 200 but {what}"), true));
            }
        }
    }
    None
}

/// curl did not deliver a page to judge: no status at all, or it gave up
/// (timeout, reset, TLS) before a single body byte. The status line alone is
/// no verdict — an empty 200 there would read as a white screen, a HARD
/// failure, when the site was only slow. Part of a page that did arrive is
/// still judged.
pub(super) fn probe_gave_up(code: i64, curl_ok: bool, head: &str) -> bool {
    code == 0 || (!curl_ok && head.trim().is_empty())
}

/// Seconds one probe request may take, end to end. The probe is an UNCACHED
/// render (see [`probe_http`]), so this is a budget for PHP building the page
/// on a box that may be mid-backup — the 5 s that suited the old cached HEAD
/// timed out healthy sites and reported them down.
pub(super) const PROBE_MAX_TIME_SECS: &str = "15";
/// Seconds to establish the connection; a box that does not answer at all
/// still fails fast.
pub(super) const PROBE_CONNECT_TIMEOUT_SECS: &str = "5";

/// Follow up to 3 redirects, ignore TLS hostname
/// verification (operator picks the URL — they're targeting their own
/// host). A full GET (not HEAD: HEAD is cached separately from GET and some
/// plugins/themes only break while rendering), with a unique query string so
/// the FastCGI cache cannot answer for a PHP that is already dead. Success
/// means a 2xx/3xx AND a body that is not a known error page.
pub(super) async fn probe_http(url: &str) -> HttpProbeResult {
    use std::time::Instant;
    let start = Instant::now();
    let sep = if url.contains('?') { '&' } else { '?' };
    let probe_url = format!("{url}{sep}hyperion_probe={}", now_secs());
    // Shell out to curl — adds an external dep that's already on
    // every node (we use it for backups). Avoids pulling in a full
    // reqwest+tls stack and the rustls CryptoProvider dance.
    let res = tokio::process::Command::new("/usr/bin/curl")
        .args([
            // silent but keep curl's error line (the alert's "last error") +
            // insecure + follow redirects
            "-sSkL",
            "--connect-timeout",
            PROBE_CONNECT_TIMEOUT_SECS,
            "--max-time",
            PROBE_MAX_TIME_SECS,
            "--max-redirs",
            "3",
            "-H",
            "Cache-Control: no-cache",
            "-w",
            &format!("{PROBE_STATUS_MARK}%{{http_code}}"),
            &probe_url,
        ])
        .output()
        .await;
    let elapsed = start.elapsed().as_millis() as i64;
    match res {
        Ok(out) => {
            let raw = String::from_utf8_lossy(&out.stdout);
            let (body, code_str) = raw
                .rsplit_once(PROBE_STATUS_MARK)
                .unwrap_or((raw.as_ref(), "0"));
            let code: i64 = code_str.trim().parse().unwrap_or(0);
            let head: String = body.chars().take(PROBE_BODY_CAP).collect();
            if probe_gave_up(code, out.status.success(), &head) {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return HttpProbeResult {
                    success: false,
                    http_status: (code > 0).then_some(code),
                    response_ms: elapsed,
                    error_message: Some(if err.is_empty() {
                        "no response".into()
                    } else {
                        err
                    }),
                    hard_failure: false,
                };
            }
            let verdict = classify_probe(code, &head);
            HttpProbeResult {
                success: verdict.is_none(),
                http_status: Some(code),
                response_ms: elapsed,
                hard_failure: verdict.as_ref().is_some_and(|v| v.1),
                error_message: verdict.map(|v| v.0),
            }
        }
        Err(e) => HttpProbeResult {
            success: false,
            http_status: None,
            response_ms: elapsed,
            error_message: Some(e.to_string()),
            hard_failure: false,
        },
    }
}
