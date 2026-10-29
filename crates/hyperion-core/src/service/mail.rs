//! The node MTA: SPF checks, diagnostics, queue, reconfigure, email logs.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// List recent email-log rows. `hosting_id = None` returns the
    /// cluster-wide stream; Some filters to one hosting.
    pub async fn email_log_list(
        &self,
        hosting_id: Option<String>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::EmailLogEntry>, RpcError> {
        let rows = hyperion_state::email_log::list(&self.pool, hosting_id.as_deref(), limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("email log list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::EmailLogEntry {
                id: r.id,
                hosting_id: r.hosting_id,
                to_address: r.to_address,
                subject: r.subject,
                body_preview: r.body_preview,
                kind: r.kind,
                state: r.state,
                error: r.error,
                smtp_code: r.smtp_code,
                sent_at: r.sent_at,
                // Master tags this after a cross-node fan-in.
                node: None,
            })
            .collect())
    }

    pub async fn site_email_log_list(
        &self,
        system_user: String,
        limit: i64,
    ) -> Result<Vec<hyperion_types::SiteEmailLogEntry>, RpcError> {
        if !system_user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(RpcError::Validation {
                message: format!("invalid system_user: {system_user:?}"),
            });
        }
        let limit = limit.clamp(1, 500) as usize;
        let path = std::path::PathBuf::from("/var/lib/hyperion/site-mail")
            .join(format!("{system_user}.jsonl"));
        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => {
                return Err(RpcError::Internal_with(format!("read jsonl: {e}")));
            }
        };
        let s = String::from_utf8_lossy(&bytes);
        let mut out: Vec<hyperion_types::SiteEmailLogEntry> = s
            .lines()
            .rev()
            .take(limit)
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        for r in &mut out {
            // Subjects AND the From/To display names arrive RFC 2047 encoded
            // whenever they contain a non-ASCII character, which for a Czech
            // site is most of them — the From showed as
            // `=?UTF-8?Q?Centrum_SRD=C3=8D=C4=8CKO...?= <addr>` until this
            // decoded it. `decode_mime_header` only touches the encoded word
            // and leaves the `<address>` part intact; an undecodable header
            // comes back unchanged.
            r.subject = hyperion_types::decode_mime_header(&r.subject);
            r.from_address = hyperion_types::decode_mime_header(&r.from_address);
            r.to_address = hyperion_types::decode_mime_header(&r.to_address);
            // Truncate the body excerpt for wire safety (the wrapper
            // already caps at ~1 KB but defence in depth).
            if r.body_excerpt.len() > 2048 {
                r.body_excerpt.truncate(2048);
            }
        }
        Ok(out)
    }

    /// Probe localhost for a usable SMTP relay so the operator can
    /// click "Auto-detect" on the Settings page instead of typing
    /// host/port/security by hand.
    ///
    /// Tries (in order): localhost:25 (postfix default), 127.0.0.1:25,
    /// localhost:587. Returns the first one that completes a TCP
    /// connect — that's not proof the relay accepts STARTTLS or
    /// auth, but it's enough for the UI to pre-fill the form with
    /// a "looks reasonable" baseline.
    pub async fn email_smtp_autodetect(&self) -> Result<hyperion_types::SmtpAutodetect, RpcError> {
        use tokio::io::AsyncReadExt;
        let candidates: &[(&str, u16, &str)] = &[
            ("localhost", 25, "plain"),
            ("127.0.0.1", 25, "plain"),
            ("::1", 25, "plain"),
            ("localhost", 587, "starttls"),
            ("::1", 587, "starttls"),
        ];
        for (host, port, sec) in candidates {
            // Bracket-wrap v6 hosts for the connect string.
            let addr = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let connect = tokio::time::timeout(
                std::time::Duration::from_millis(800),
                tokio::net::TcpStream::connect(&addr),
            )
            .await;
            let Ok(Ok(mut sock)) = connect else { continue };

            // SMTP banner check — read up to 256 bytes within 600ms
            // and require a "220" prefix. Without this, an ssh /
            // https / random thing listening on :25 gets reported
            // as a relay; operator clicks Save and every
            // notification thereafter fails with TLS-handshake
            // confusion.
            let mut buf = [0u8; 256];
            let n = match tokio::time::timeout(
                std::time::Duration::from_millis(600),
                sock.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) => n,
                _ => continue,
            };
            let banner = String::from_utf8_lossy(&buf[..n]);
            if !banner.starts_with("220") {
                continue;
            }
            // Looks like SMTP. Derive a sensible from-address.
            // /etc/mailname is postfix's canonical FQDN; fall back
            // to /etc/hostname; refuse the result if it's
            // "localhost"-shaped (no dot, or matches a known dud).
            let suggested_from = read_mail_fqdn()
                .map(|d| format!("hyperion@{d}"))
                .unwrap_or_default();
            let notes = if suggested_from.is_empty() {
                format!(
                    "SMTP banner detected at {addr} but this node's hostname isn't an FQDN; \
                     set from_address manually (e.g. notifications@your-domain.tld)"
                )
            } else {
                format!(
                    "SMTP banner detected at {addr} — likely a local relay (postfix/exim). \
                     If auth is required, fill smtp_user + smtp_password below."
                )
            };
            return Ok(hyperion_types::SmtpAutodetect {
                found: true,
                smtp_host: host.to_string(),
                smtp_port: *port,
                security: sec.to_string(),
                suggested_from,
                notes,
            });
        }
        Ok(hyperion_types::SmtpAutodetect {
            found: false,
            smtp_host: String::new(),
            smtp_port: 0,
            security: String::new(),
            suggested_from: String::new(),
            notes: "no local SMTP relay detected on :25 or :587 — point hyperion at any external \
                    relay (gmail, postmark, mailgun, sendgrid, etc.) and fill the form below."
                .into(),
        })
    }

    /// Check the SPF record at `domain` against our public IPv4.
    ///
    /// The previous implementation did a literal string compare
    /// between the operator's existing TXT record and the one we'd
    /// suggest — guaranteed "differs" for any non-trivial SPF (e.g.
    /// two `ip4:` mechanisms, an `include:`, a `redirect=`). The new
    /// version actually *parses* the SPF mechanisms and decides
    /// whether our IPv4 is authorized.
    ///
    /// Status semantics:
    ///   - "missing"  — no `v=spf1` TXT at the apex
    ///   - "multiple" — more than one SPF record (RFC 7208 §3.2 says
    ///                  receivers fall back to permerror)
    ///   - "matches"  — at least one record authorizes our IP via any
    ///                  of: ip4 (CIDR-aware), a, mx, include (one
    ///                  level of recursion), +all/?all catch-all
    ///   - "differs"  — record exists and parses but does NOT
    ///                  authorize us. Operator either has wrong IP
    ///                  pinned, or needs to add ours alongside.
    pub async fn dns_spf_check(
        &self,
        domain: hyperion_validate::Domain,
    ) -> Result<hyperion_types::SpfCheckResult, RpcError> {
        let d = domain.as_str().to_string();
        // TXT lookup + public-IP probe are independent — join them
        // so the worst case is one slow probe, not the sum.
        let (txts_raw, our_ipv4) = tokio::join!(
            dig_records(&d, "TXT"),
            fetch_public_ip_v4("https://api4.ipify.org"),
        );
        // A failed LOOKUP is not an absent RECORD. `unwrap_or_default()`
        // here used to collapse "dig is not installed on this node" and
        // "DNS is unreachable" into an empty list, which rendered as
        // "missing — no SPF TXT record at the apex" — and an operator who
        // HAD published the record hours ago re-checked their DNS over
        // and over while the truth was on this box. Same rule as
        // everywhere else in this codebase: a probe that could not run
        // must never masquerade as a finding.
        let txts_raw = match txts_raw {
            Ok(v) => v,
            Err(e) => {
                let our_public_ipv4 = our_ipv4.ok();
                return Ok(hyperion_types::SpfCheckResult {
                    domain: d,
                    status: "unknown".into(),
                    reason: format!("could not check: {e}"),
                    existing: vec![],
                    suggested: match our_public_ipv4.as_deref() {
                        Some(ip) => format!("v=spf1 ip4:{ip} a mx ~all"),
                        None => "v=spf1 a mx ~all".into(),
                    },
                    our_public_ipv4,
                });
            }
        };
        // dig may return one TXT split across multiple quoted segments
        // (long TXT values use the `"...""..."` continuation syntax).
        // Join those segments before filtering by prefix.
        let existing: Vec<String> = txts_raw
            .iter()
            .map(|raw| stitch_dig_txt(raw))
            .filter(|s| s.to_ascii_lowercase().starts_with("v=spf1"))
            .collect();

        let our_ipv4 = our_ipv4.ok();
        let suggested = match our_ipv4.as_deref() {
            Some(ip) => format!("v=spf1 ip4:{ip} a mx ~all"),
            None => "v=spf1 a mx ~all".into(),
        };

        let (status, reason): (String, String) = if existing.is_empty() {
            ("missing".into(), "no SPF TXT record at the apex".into())
        } else if existing.len() > 1 {
            (
                "multiple".into(),
                format!(
                    "RFC 7208 §3.2 forbids multiple SPF records — found {}",
                    existing.len()
                ),
            )
        } else {
            // One record. Try to prove it authorizes us.
            let record = &existing[0];
            let our_ip = our_ipv4.as_deref();
            match check_spf_authorizes(record, &d, our_ip).await {
                SpfMatch::Match { mechanism } => (
                    "matches".into(),
                    format!("{} matched our public IP", mechanism),
                ),
                SpfMatch::CatchAll { mechanism } => (
                    "matches".into(),
                    format!("{} authorizes any sender", mechanism),
                ),
                // NOT a finding. We could not work out this node's public
                // address — the outbound probe was blocked, or the service
                // was down — so we never got as far as comparing anything.
                // Reported as `differs` it read as "your SPF record is
                // wrong", which is a claim about the operator's DNS made
                // from a measurement that never happened.
                SpfMatch::NoIp => (
                    "unknown".into(),
                    "could not check: this node's public IPv4 could not be determined, so the \
                     record could not be compared against anything"
                        .into(),
                ),
                SpfMatch::None => (
                    "differs".into(),
                    "SPF record exists but does not authorize our public IP".into(),
                ),
            }
        };

        Ok(hyperion_types::SpfCheckResult {
            domain: d,
            existing,
            suggested,
            our_public_ipv4: our_ipv4,
            status,
            reason,
        })
    }

    /// Send a one-off test email through the configured SMTP relay
    /// to confirm the operator's config works end-to-end. Returns
    /// the SMTP server's response code so the UI can show it in
    /// the success flash (helps the operator distinguish "queued"
    /// from "rejected with 250 OK but actually dropped" — relays
    /// occasionally do this).
    pub async fn email_send_test(&self, to: String) -> Result<String, RpcError> {
        let to = to.trim();
        if to.is_empty() || !to.contains('@') {
            return Err(RpcError::Validation {
                message: "destination address is required and must contain '@'".into(),
            });
        }
        let cfg = self
            .email_config
            .as_ref()
            .ok_or_else(|| RpcError::Validation {
                message:
                    "email is not configured — set [email] enabled=true + SMTP relay in agent.toml"
                        .into(),
            })?;
        let subject = "Hyperion test email";
        let body = format!(
            "This is a test email from hyperion-agent.\n\
             Sent to: {to}\n\
             From: {} <{}>\n\
             SMTP: {}:{} ({})\n\n\
             If you can read this in your inbox, your relay is configured correctly.\n",
            cfg.from_name, cfg.from_address, cfg.smtp_host, cfg.smtp_port, cfg.security
        );
        let send_result = hyperion_adapters::email::send_text(cfg, to, subject, &body).await;
        // Log to email_log regardless of outcome — even a failed
        // send needs to be visible on /emails so the operator can
        // see what went wrong without scraping journalctl.
        let (state_str, err_opt, code_opt) = match &send_result {
            Ok(code) => ("ok", None, Some(code.as_str())),
            Err(e) => ("failed", Some(format!("{e}")), None),
        };
        let err_ref: Option<&str> = err_opt.as_deref();
        if let Err(le) = hyperion_state::email_log::append(
            &self.pool,
            None,
            to,
            subject,
            &body,
            "test",
            state_str,
            err_ref,
            code_opt,
            now_secs(),
        )
        .await
        {
            // Don't swallow this — table missing is the most likely
            // cause and operator needs to see it in the journal.
            tracing::error!(
                error = %le,
                to = %to,
                "email_log append failed during test send — \
                 restart hyperion-agent to apply migration 017 if it hasn't yet"
            );
        }
        let code =
            send_result.map_err(|e| RpcError::Internal_with(format!("email send failed: {e}")))?;
        self.append_audit(
            "email.test.send",
            None,
            &serde_json::json!({ "to": to, "smtp_code": &code }).to_string(),
            "ok",
        )
        .await;
        Ok(code)
    }

    /// Live MTA (postfix) diagnostics for the /settings card.
    /// Every probe is local + cheap; no SMTP connect, no DNS lookup.
    /// Returns the same answer the boot self-heal sees so the UI
    /// reflects the current on-disk config and live service state.
    pub async fn mta_diagnostics(&self) -> Result<hyperion_types::MtaDiagnostics, RpcError> {
        use tokio::process::Command;

        // is /usr/sbin/sendmail there + executable?
        let sendmail_executable = match tokio::fs::metadata("/usr/sbin/sendmail").await {
            Ok(m) => {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            Err(_) => false,
        };

        // postfix service state — separate probes so the operator
        // can see "installed but not running" distinctly from "not
        // installed".
        let service_active = Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", "postfix.service"])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        let service_enabled = Command::new("/usr/bin/systemctl")
            .args(["is-enabled", "--quiet", "postfix.service"])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        let postfix_known = Command::new("/usr/bin/systemctl")
            .args(["cat", "postfix.service"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        // marker — our boot self-heal writes this on every config
        // application. Body contains `mode=direct-mx` or
        // `relayhost=[smtp.x]:port`. Plain-text grep target.
        let marker_path = "/etc/postfix/hyperion-relay.marker";
        let marker_body = tokio::fs::read_to_string(marker_path)
            .await
            .unwrap_or_default();
        let marker_present = !marker_body.is_empty();

        // postconf reads. We grab both myhostname and relayhost in
        // one call; postconf -h prints the value only (no key=).
        async fn postconf_get(key: &str) -> String {
            Command::new("/usr/sbin/postconf")
                .args(["-h", key])
                .output()
                .await
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        }
        let myhostname = postconf_get("myhostname").await;
        let relayhost = postconf_get("relayhost").await;
        let myhostname_is_fqdn = myhostname.contains('.');
        // Reverse DNS for the address this node sends from. Two network
        // round trips, so it is STARTED here and awaited beside the port
        // probes below rather than in front of them — this runs on every
        // Settings page load, and serialising it would put ~7 s in front
        // of the operator. A failure degrades to "unknown", never to a
        // claim about the record.
        let ptr_fut = mta_ptr_check(&myhostname);
        // This node's editable [email] config, read fresh from its agent.toml
        // so the Settings → Mail form pre-fills the right values per node.
        let email_view = self
            .agent_config_path
            .as_ref()
            .map(|p| load_email_section(p))
            .unwrap_or_default();

        // The sender-identity check shares the page-load budget, so it
        // runs beside the probes too.
        let sender_fut = mta_sender_auth_check(&email_view.from_address);

        // Decide mode from observable state, not just the marker.
        let mode = if !postfix_known {
            "not-installed".to_string()
        } else if marker_body.contains("mode=direct-mx") {
            "direct-mx".to_string()
        } else if !relayhost.is_empty() {
            // Marker missing but relayhost set — operator-edited.
            "smart-host".to_string()
        } else if marker_present {
            // Marker present but no relayhost set yet: smart-host
            // config in flight, or an older marker. Treat as
            // direct-mx since that's what postfix actually does
            // with empty relayhost.
            "direct-mx".to_string()
        } else {
            "default".to_string()
        };

        // mailq output — full body + parsed summary. The summary
        // line is the last non-empty line; either "Mail queue is
        // empty" or "-- N Kbytes in M Requests."
        let (mailq_summary, mailq_total, mailq_detail) = match Command::new("/usr/sbin/postqueue")
            .args(["-p"])
            .output()
            .await
        {
            Ok(o) if o.status.success() => {
                let body = String::from_utf8_lossy(&o.stdout).into_owned();
                let summary = body
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                // Parse "N Requests" out of "-- 0 Kbytes in N Requests."
                let total = summary
                    .split_whitespace()
                    .position(|w| w == "Request" || w == "Requests")
                    .and_then(|i| {
                        let words: Vec<&str> = summary.split_whitespace().collect();
                        i.checked_sub(1).and_then(|j| words.get(j).copied())
                    })
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);
                // Cap detail at 4 KB so a runaway queue can't
                // bloat the RPC response.
                let detail = if body.len() > 4096 {
                    let mut truncated: String = body.chars().take(4000).collect();
                    truncated.push_str("\n… (truncated)\n");
                    truncated
                } else {
                    body
                };
                (summary, total, detail)
            }
            _ => (String::new(), 0usize, String::new()),
        };

        // Outbound TCP probes for every common SMTP port. When 25
        // is blocked (typical for Hetzner / AWS / GCP / many Czech
        // ISPs) the operator needs to know which alternative — 465,
        // 587, 2525 — is open so they can configure a smart-host
        // workaround instead. Run all four in parallel; each has
        // a 3-second hard timeout so the worst case is 3s total.
        let probes_fut = probe_outbound_smtp_all();
        // Keep the legacy single port_25 fields populated for
        // older UI / external scripts that grep on them.
        let (
            outbound_smtp_probes,
            (public_ipv4, ptr_name, ptr_status),
            (sender_domain, sender_auth_status, sender_auth_detail, sender_spf_suggested),
        ) = tokio::join!(probes_fut, ptr_fut, sender_fut);
        let (outbound_port_25_ok, outbound_port_25_msg) = outbound_smtp_probes
            .iter()
            .find(|p| p.port == 25)
            .map(|p| {
                let msg = if p.reachable {
                    format!(
                        "OK · {} reachable in {} ms",
                        format_args!("{}:25", p.host),
                        p.latency_ms
                    )
                } else {
                    format!(
                        "BLOCKED — connect to {}:25 failed: {}. \
                         Common on Hetzner / AWS / GCP / many ISPs — request unblock \
                         from support, or set up a smart-host on port 587.",
                        p.host, p.error
                    )
                };
                (Some(p.reachable), msg)
            })
            .unwrap_or((None, String::new()));

        // Last 12 lines of /var/log/mail.log — cheap signal for
        // recent send activity / rejects. We don't shell out to
        // `tail`; just read the file and grab the tail in Rust.
        let recent_log_tail = match tokio::fs::read_to_string("/var/log/mail.log").await {
            Ok(body) => {
                let lines: Vec<String> =
                    body.lines().rev().take(12).map(|s| s.to_string()).collect();
                lines.into_iter().rev().collect()
            }
            Err(_) => Vec::new(),
        };

        Ok(hyperion_types::MtaDiagnostics {
            mode,
            sendmail_executable,
            service_active,
            service_enabled,
            marker_present,
            marker_body,
            myhostname,
            myhostname_is_fqdn,
            public_ipv4,
            ptr_name,
            ptr_status,
            relayhost,
            mailq_summary,
            mailq_total,
            mailq_detail,
            outbound_port_25_ok,
            outbound_port_25_msg,
            outbound_smtp_probes,
            recent_log_tail,
            cfg_password_set: !email_view.smtp_password.is_empty(),
            sender_domain,
            sender_auth_status,
            sender_auth_detail,
            sender_spf_suggested,
            cfg_enabled: email_view.enabled,
            cfg_smtp_host: email_view.smtp_host,
            cfg_smtp_port: email_view.smtp_port,
            cfg_smtp_user: email_view.smtp_user,
            cfg_from_address: email_view.from_address,
            cfg_from_name: email_view.from_name,
            cfg_security: email_view.security,
            cfg_default_to: email_view.default_to,
        })
    }

    /// `postqueue -f` — tell postfix to retry every deferred
    /// message right now. Returns the count of messages in queue
    /// AFTER the flush (often the same since flushed messages may
    /// stay deferred when the underlying problem isn't fixed),
    /// plus the verbatim postqueue stdout/stderr.
    pub async fn mta_queue_flush(&self) -> Result<(usize, String), RpcError> {
        let out = tokio::process::Command::new("/usr/sbin/postqueue")
            .args(["-f"])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("spawn postqueue: {e}")))?;
        let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.stderr.is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&String::from_utf8_lossy(&out.stderr));
        }
        // Re-probe queue depth so the UI knows whether the flush
        // helped. Best-effort.
        let attempted = self.queue_depth_now().await;
        self.append_audit(
            "mta.queue_flush",
            None,
            &serde_json::json!({ "attempted_after_flush": attempted }).to_string(),
            if out.status.success() { "ok" } else { "failed" },
        )
        .await;
        Ok((attempted, output))
    }

    /// `postsuper -d ALL` — discard every queued message.
    /// Returns the count of messages that were in queue BEFORE the
    /// discard. UI must gate this with a confirm — it can't be
    /// undone.
    pub async fn mta_queue_clear(&self) -> Result<(usize, String), RpcError> {
        let before = self.queue_depth_now().await;
        let out = tokio::process::Command::new("/usr/sbin/postsuper")
            .args(["-d", "ALL"])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("spawn postsuper: {e}")))?;
        let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.stderr.is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&String::from_utf8_lossy(&out.stderr));
        }
        self.append_audit(
            "mta.queue_clear",
            None,
            &serde_json::json!({ "cleared_count": before }).to_string(),
            if out.status.success() { "ok" } else { "failed" },
        )
        .await;
        Ok((before, output))
    }

    /// Cheap helper used by both the queue-ops audit logs above and
    /// indirectly via mta_diagnostics. Returns 0 if postqueue isn't
    /// available rather than failing.
    pub(super) async fn queue_depth_now(&self) -> usize {
        let out = tokio::process::Command::new("/usr/sbin/postqueue")
            .args(["-p"])
            .output()
            .await;
        let Ok(o) = out else { return 0 };
        if !o.status.success() {
            return 0;
        }
        let body = String::from_utf8_lossy(&o.stdout);
        body.lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .and_then(|line| {
                line.split_whitespace()
                    .position(|w| w == "Request" || w == "Requests")
                    .and_then(|i| {
                        let words: Vec<&str> = line.split_whitespace().collect();
                        i.checked_sub(1).and_then(|j| words.get(j).copied())
                    })
                    .and_then(|s| s.parse::<usize>().ok())
            })
            .unwrap_or(0)
    }

    /// Operator-triggered re-apply of the boot postfix config. Picks
    /// smart-host vs direct-MX based on the current `[email]` section,
    /// returns the mode that was applied. Used by the /settings
    /// "Reconfigure" button when the operator changed agent.toml
    /// without restarting the agent (or wants to roll forward after
    /// reverting their own hand-edits).
    pub async fn mta_reconfigure(&self) -> Result<String, RpcError> {
        if !hyperion_adapters::postfix::is_installed().await {
            return Ok("skipped".to_string());
        }
        // Read the [email] section fresh from agent.toml so a config the
        // operator JUST saved (via AgentConfigUpdate) is applied here without
        // needing an agent restart — this is the per-node apply path. Falls
        // back to the in-memory snapshot only when no config path is wired.
        let disk = self
            .agent_config_path
            .as_ref()
            .map(|p| load_email_section(p));
        // Applies in either mode; read before `disk` is consumed below.
        let size_limit_mb = disk.as_ref().map_or(0, |e| e.message_size_limit_mb);
        // Read before `disk` is consumed by the match below. These two
        // apply to direct-MX delivery and are independent of whether a
        // relay is configured at all.
        let toml_email = DirectMxTuning {
            inet_protocols: disk
                .as_ref()
                .map(|e| e.inet_protocols.clone())
                .unwrap_or_default(),
            bind_address: disk
                .as_ref()
                .map(|e| e.bind_address.clone())
                .unwrap_or_default(),
        };
        let relay_cfg: Option<hyperion_adapters::email::EmailConfig> = match disk {
            Some(e) if e.enabled && !e.smtp_host.trim().is_empty() => {
                Some(hyperion_adapters::email::EmailConfig {
                    smtp_host: e.smtp_host,
                    smtp_port: e.smtp_port.clamp(1, 65535) as u16,
                    smtp_user: e.smtp_user,
                    smtp_password: e.smtp_password,
                    from_address: e.from_address,
                    from_name: e.from_name,
                    security: e.security,
                })
            }
            Some(_) => None, // present but disabled / no host → direct MX
            None => self
                .email_config
                .as_ref()
                .filter(|c| !c.smtp_host.trim().is_empty())
                .cloned(),
        };
        // This node's own FQDN — postfix's `myhostname` in direct-MX mode, and
        // the yardstick for spotting a self-referential "relay" below.
        let fqdn = tokio::process::Command::new("/bin/hostname")
            .arg("-f")
            .output()
            .await
            .ok()
            .and_then(|o| {
                if !o.status.success() {
                    return None;
                }
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            })
            .unwrap_or_else(|| "localhost".to_string());

        // A relay host that points back at THIS node (localhost / a loopback IP /
        // our own hostname) can't be a postfix smart-host: postfix would try to
        // relay through itself and defer every message with
        // "mail for localhost loops back to myself". Treat such a "relay" as no
        // external relay and deliver DIRECTLY (MX) instead. (The "detect local
        // relay" button pre-fills localhost:25 — the intent there is "send via
        // the local postfix", which IS direct delivery, not relay-to-self.)
        let use_smart_host = relay_cfg
            .as_ref()
            .map(|c| !hyperion_adapters::postfix::host_is_local(&c.smtp_host, &fqdn))
            .unwrap_or(false);

        hyperion_adapters::postfix::ensure_message_size_limit(size_limit_mb)
            .await
            .map_err(|e| RpcError::Internal_with(format!("postfix message size: {e}")))?;
        match relay_cfg.as_ref() {
            Some(cfg) if use_smart_host => {
                hyperion_adapters::postfix::ensure_relay_config(cfg)
                    .await
                    .map_err(|e| RpcError::Internal_with(format!("postfix relay: {e}")))?;
                Ok("smart-host".to_string())
            }
            _ => {
                hyperion_adapters::postfix::ensure_direct_delivery_config(
                    &fqdn,
                    &hyperion_adapters::postfix::DirectDeliveryOpts {
                        // Empty ⇒ the adapter's own defaults (ipv4, no
                        // bind address), so a node whose agent.toml
                        // predates these keys gets the safe policy
                        // without the operator touching anything.
                        inet_protocols: Some(toml_email.inet_protocols.clone())
                            .filter(|s| !s.trim().is_empty()),
                        bind_address: Some(toml_email.bind_address.clone())
                            .filter(|s| !s.trim().is_empty()),
                    },
                )
                .await
                .map_err(|e| RpcError::Internal_with(format!("postfix direct: {e}")))?;
                // Re-assert the envelope map: a reconfigure rewrites main.cf,
                // and this is the one place guaranteed to run on every node
                // after any mail change.
                if let Err(e) = self.sync_sender_canonical().await {
                    tracing::warn!(error = %e, "mta: envelope-sender map not rebuilt");
                }
                Ok("direct-mx".to_string())
            }
        }
    }

    /// Send a one-line test mail via `/usr/sbin/sendmail`. This
    /// exercises the PHP `mail()` chain end-to-end (PHP would go
    /// site-mail-wrapper → sendmail; here we skip the wrapper and
    /// call sendmail directly, which is what the wrapper does
    /// anyway after logging). Returns (exit_code, stderr).
    pub async fn mta_test_send(&self, to: String) -> Result<(i32, String), RpcError> {
        let to = to.trim();
        if to.is_empty() || !to.contains('@') {
            return Err(RpcError::Validation {
                message: "destination address is required and must contain '@'".into(),
            });
        }
        // `to` goes into a header of a message handed to `sendmail -t`, which
        // takes its recipients FROM the headers. A CR/LF would let the field
        // add `Bcc:` lines, a subject and a body of the sender's choosing; a
        // comma or semicolon, more recipients. Exactly one plain address.
        if !is_single_plain_address(to) {
            return Err(RpcError::Validation {
                message: "enter exactly one e-mail address".into(),
            });
        }
        // Bound the address — Location-header / argv-length safety.
        if to.len() > 254 {
            return Err(RpcError::Validation {
                message: "address too long (RFC5321 max is 254 chars)".into(),
            });
        }
        // Synthesize a From that postfix will accept. The operator
        // controls `[email].from_address` so we use it when set;
        // fall back to admin@hostname as last resort.
        let from = self
            .email_config
            .as_ref()
            .map(|c| c.from_address.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "admin@localhost".to_string());
        let body = format!(
            "From: {from}\r\n\
             To: {to}\r\n\
             Subject: Hyperion MTA test\r\n\
             Content-Type: text/plain; charset=UTF-8\r\n\
             \r\n\
             This is a test email from hyperion-agent via /usr/sbin/sendmail.\r\n\
             If you can read this, your MTA accepted it.\r\n\
             Whether it actually delivered is between postfix and the recipient's MX.\r\n",
        );
        // Go through the SITE-MAIL WRAPPER when it is installed, exactly as a
        // hosted PHP site does, rather than straight to /usr/sbin/sendmail.
        //
        // This test called sendmail directly for six releases while every real
        // site's mail was rejected for want of a `-t` the wrapper never got —
        // so the one diagnostic an operator reaches for was structurally
        // incapable of reproducing the only failure that mattered, and it
        // reported success throughout. A test that exercises a different path
        // than production is not a test of production.
        //
        // `-t -i` are still passed: PHP would supply them via `sendmail_path`,
        // and this is standing in for PHP.
        let (bin, args): (&str, Vec<&str>) = if tokio::fs::metadata(SITE_MAIL_WRAPPER).await.is_ok()
        {
            (
                SITE_MAIL_WRAPPER,
                vec!["-u", "hyperion", "-t", "-i", "-f", &from],
            )
        } else {
            ("/usr/sbin/sendmail", vec!["-t", "-f", &from])
        };
        let mut child = tokio::process::Command::new(bin)
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| RpcError::Internal_with(format!("spawn sendmail: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin
                .write_all(body.as_bytes())
                .await
                .map_err(|e| RpcError::Internal_with(format!("write to sendmail stdin: {e}")))?;
            let _ = stdin.shutdown().await;
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("wait sendmail: {e}")))?;
        let exit_code = out.status.code().unwrap_or(-1);
        let mut output = String::from_utf8_lossy(&out.stderr).into_owned();
        if !out.stdout.is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&String::from_utf8_lossy(&out.stdout));
        }
        self.append_audit(
            "mta.test_send",
            None,
            &serde_json::json!({
                "to": to,
                "from": from,
                "exit_code": exit_code,
            })
            .to_string(),
            if exit_code == 0 { "ok" } else { "failed" },
        )
        .await;
        Ok((exit_code, output))
    }
}

/// Outcome of `check_spf_authorizes` — how (or whether) the SPF
/// record authorizes our public IP.
#[derive(Debug, Clone)]
pub(super) enum SpfMatch {
    /// A specific mechanism matched our IP (e.g. "ip4:1.2.3.4").
    Match { mechanism: String },
    /// The record ends in `+all` or `?all` — pass anything.
    CatchAll { mechanism: String },
    /// No public IPv4 was discoverable for the agent, so we can't
    /// decide. Surfaces as "differs" upstream with a clarifying
    /// reason.
    NoIp,
    /// The record exists but doesn't authorize us.
    None,
}

/// Decide whether an SPF record authorizes `our_ip`. Implements the
/// `ip4` / `ip6` / `a` / `mx` / `include` / `redirect` / `+all` /
/// `?all` mechanisms — enough to cover the common cases an operator
/// sets up by hand. Doesn't fully implement RFC 7208 (no `exists:`,
/// no recursion past one `include:`), but the failure mode is
/// always conservative: we say "differs" when in doubt, never
/// "matches" wrongly.
pub(super) async fn check_spf_authorizes(
    record: &str,
    domain: &str,
    our_ip: Option<&str>,
) -> SpfMatch {
    let our_ip_parsed = match our_ip.and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()) {
        Some(ip) => ip,
        None => return SpfMatch::NoIp,
    };

    // Tokenize — SPF mechanisms are whitespace-separated. Drop the
    // leading version tag.
    let mut tokens: Vec<&str> = record.split_whitespace().collect();
    if tokens.first().map(|s| s.to_ascii_lowercase()) != Some("v=spf1".into()) {
        return SpfMatch::None;
    }
    tokens.remove(0);

    // First pass — scan for `redirect=`. If present, replace the
    // whole evaluation with the redirect target's SPF (one level
    // only — recursion would need a depth counter and we'd rather
    // refuse complexity than infinite-loop).
    for tok in &tokens {
        if let Some(target) = tok.strip_prefix("redirect=") {
            return check_spf_redirect(target, our_ip_parsed).await;
        }
    }

    for tok in &tokens {
        // Strip the qualifier prefix; we treat +/?/~/- the same for
        // pass detection — only `-` (Fail) would actively REJECT us,
        // but we don't model that since the operator's question is
        // "does my IP pass" not "would a strict receiver bounce".
        let tok_l = tok.to_ascii_lowercase();
        let (qualifier, mech) = match tok_l.chars().next() {
            Some(q @ ('+' | '-' | '~' | '?')) => (q, &tok_l[1..]),
            _ => ('+', tok_l.as_str()),
        };

        // Catch-all — `+all` or `?all` count as match-everything.
        // `~all` (softfail) and `-all` (fail) do not — those mean
        // "anyone NOT explicitly listed above is unauthorized".
        if mech == "all" {
            if qualifier == '+' || qualifier == '?' {
                return SpfMatch::CatchAll {
                    mechanism: tok.to_string(),
                };
            }
            continue;
        }

        // ip4:<addr> or ip4:<addr>/<prefix>
        if let Some(rest) = mech.strip_prefix("ip4:") {
            if ip4_matches(rest, our_ip_parsed) {
                return SpfMatch::Match {
                    mechanism: format!("ip4:{}", rest),
                };
            }
            continue;
        }

        // a / a:<domain> / a/<prefix> — resolve A records and check.
        if mech == "a" || mech.starts_with("a:") || mech.starts_with("a/") {
            let lookup_domain = if let Some(rest) = mech.strip_prefix("a:") {
                rest.split('/').next().unwrap_or(domain)
            } else {
                domain
            };
            for ip_str in dig_records(lookup_domain, "A").await.unwrap_or_default() {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    if ip == our_ip_parsed {
                        return SpfMatch::Match {
                            mechanism: format!("a ({lookup_domain})"),
                        };
                    }
                }
            }
            continue;
        }

        // mx / mx:<domain> — resolve MX targets, then their A
        // records.
        if mech == "mx" || mech.starts_with("mx:") || mech.starts_with("mx/") {
            let lookup_domain = if let Some(rest) = mech.strip_prefix("mx:") {
                rest.split('/').next().unwrap_or(domain)
            } else {
                domain
            };
            let mx_targets = dig_records(lookup_domain, "MX").await.unwrap_or_default();
            for line in mx_targets {
                // dig MX output: "10 mail.example.com." — strip
                // priority + trailing dot.
                let target = line
                    .split_whitespace()
                    .last()
                    .map(|s| s.trim_end_matches('.'))
                    .unwrap_or("");
                if target.is_empty() {
                    continue;
                }
                for ip_str in dig_records(target, "A").await.unwrap_or_default() {
                    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                        if ip == our_ip_parsed {
                            return SpfMatch::Match {
                                mechanism: format!("mx ({target})"),
                            };
                        }
                    }
                }
            }
            continue;
        }

        // include:<domain> — fetch the included domain's SPF and
        // evaluate it for our IP (one level of recursion only).
        if let Some(target) = mech.strip_prefix("include:") {
            if let SpfMatch::Match { mechanism } = check_spf_include(target, our_ip_parsed).await {
                return SpfMatch::Match {
                    mechanism: format!("include:{target} → {mechanism}"),
                };
            }
            if let SpfMatch::CatchAll { mechanism } = check_spf_include(target, our_ip_parsed).await
            {
                return SpfMatch::CatchAll {
                    mechanism: format!("include:{target} → {mechanism}"),
                };
            }
            continue;
        }
        // ip6:, ptr:, exists: — not implemented; skip silently.
    }
    SpfMatch::None
}

/// Resolve `target`'s SPF and evaluate it for `our_ip`. One level
/// only — `include` of an `include` is treated as no-match to avoid
/// pathological chains (Office365 / Google Workspace alone have
/// 3-4 levels deep, which is exactly what burns SPF's 10-DNS-lookup
/// budget at receive time — we surface it as "not matched" so the
/// operator notices and adds their IP directly).
pub(super) fn check_spf_include<'a>(
    target: &'a str,
    our_ip: std::net::Ipv4Addr,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = SpfMatch> + Send + 'a>> {
    Box::pin(async move {
        let txts = dig_records(target, "TXT").await.unwrap_or_default();
        for raw in txts {
            let stitched = stitch_dig_txt(&raw);
            if stitched.to_ascii_lowercase().starts_with("v=spf1") {
                // Pass false_to_string() so the redirect path doesn't
                // recursively await on Future<Future> — we resolve
                // one level synchronously below.
                return check_spf_authorizes_no_recurse(&stitched, target, our_ip).await;
            }
        }
        SpfMatch::None
    })
}

/// Same as `check_spf_redirect`, but cap recursion explicitly at the
/// caller (we only call into this from the top-level evaluator).
pub(super) async fn check_spf_redirect(target: &str, our_ip: std::net::Ipv4Addr) -> SpfMatch {
    let txts = dig_records(target, "TXT").await.unwrap_or_default();
    for raw in txts {
        let stitched = stitch_dig_txt(&raw);
        if stitched.to_ascii_lowercase().starts_with("v=spf1") {
            return check_spf_authorizes_no_recurse(&stitched, target, our_ip).await;
        }
    }
    SpfMatch::None
}

/// Single-pass SPF eval that does NOT chase further `include:` /
/// `redirect=` references. Used by include/redirect handlers to
/// bound the recursion.
pub(super) async fn check_spf_authorizes_no_recurse(
    record: &str,
    domain: &str,
    our_ip: std::net::Ipv4Addr,
) -> SpfMatch {
    let mut tokens: Vec<&str> = record.split_whitespace().collect();
    if tokens.first().map(|s| s.to_ascii_lowercase()) != Some("v=spf1".into()) {
        return SpfMatch::None;
    }
    tokens.remove(0);
    for tok in &tokens {
        let tok_l = tok.to_ascii_lowercase();
        let (qualifier, mech) = match tok_l.chars().next() {
            Some(q @ ('+' | '-' | '~' | '?')) => (q, &tok_l[1..]),
            _ => ('+', tok_l.as_str()),
        };
        if mech == "all" {
            if qualifier == '+' || qualifier == '?' {
                return SpfMatch::CatchAll {
                    mechanism: tok.to_string(),
                };
            }
            continue;
        }
        if let Some(rest) = mech.strip_prefix("ip4:") {
            if ip4_matches(rest, our_ip) {
                return SpfMatch::Match {
                    mechanism: format!("ip4:{rest}"),
                };
            }
            continue;
        }
        if mech == "a" || mech.starts_with("a:") {
            let lookup = mech.strip_prefix("a:").unwrap_or(domain);
            for ip_str in dig_records(lookup, "A").await.unwrap_or_default() {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    if ip == our_ip {
                        return SpfMatch::Match {
                            mechanism: format!("a ({lookup})"),
                        };
                    }
                }
            }
            continue;
        }
        // include: inside an include is not resolved.
    }
    SpfMatch::None
}

/// Check whether `spec` (an `ip4:` value — either bare IPv4 or
/// `IPv4/prefix`) covers `ip`. Returns false on malformed input.
pub(super) fn ip4_matches(spec: &str, ip: std::net::Ipv4Addr) -> bool {
    if let Some((addr, prefix_s)) = spec.split_once('/') {
        let Ok(net_ip) = addr.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        let Ok(prefix) = prefix_s.parse::<u8>() else {
            return false;
        };
        if prefix > 32 {
            return false;
        }
        if prefix == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - prefix);
        let net_u = u32::from(net_ip) & mask;
        let ip_u = u32::from(ip) & mask;
        net_u == ip_u
    } else {
        spec.parse::<std::net::Ipv4Addr>()
            .map(|a| a == ip)
            .unwrap_or(false)
    }
}

/// `dig +short TXT` returns each TXT record on one line, with each
/// 255-char-or-less string segment in its own quoted block:
///
///   "v=spf1 ip4:1.2.3.4 " "ip4:5.6.7.8 ~all"
///
/// Stitch those segments back into a single string. Drops the
/// quotes, joins consecutive segments with no separator (per RFC
/// 7208 §3.3 — TXT continuation strings are concatenated as-is).
pub(super) fn stitch_dig_txt(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_quote = false;
    for c in raw.chars() {
        if c == '"' {
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            out.push(c);
        }
    }
    // If the raw line had no quotes at all (older dig versions),
    // just trim it.
    if out.is_empty() {
        return raw.trim().to_string();
    }
    out
}

/// Resolve a sensible mail-FQDN for the suggested From address.
/// /etc/mailname is postfix's canonical source; fall back to
/// /etc/hostname. Returns None for non-FQDN inputs (no dot, or
/// the well-known duds "localhost" / "localhost.localdomain") so
/// the autodetect doesn't suggest a from-address that every
/// external relay will reject with "550 sender domain not FQDN".
pub(super) fn read_mail_fqdn() -> Option<String> {
    for path in &["/etc/mailname", "/etc/hostname"] {
        let v = std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(s) = v {
            if !s.contains('.') {
                continue;
            }
            if s == "localhost.localdomain" {
                continue;
            }
            return Some(s);
        }
    }
    None
}

/// What the DNS of the `from_address` domain says about mail sent from
/// this node. Returns `(domain, status, detail, suggested_spf)` for
/// `MtaDiagnostics`.
///
/// Exists because of a failure mode the server cannot observe at all: a
/// `from_address` on a domain whose SPF excludes this server and whose
/// DMARC says reject means receivers ACCEPT the message (250) and then
/// discard it. No bounce, nothing in the queue, nothing in the spam
/// folder. The queue log looks like success, and the operator debugs
/// postfix — the actual verdict was published in someone else's DNS the
/// whole time. `hyperion@hyperion.com`, an innocent-looking placeholder,
/// is exactly this: that real domain publishes `v=spf1 -all` + `p=reject`.
pub(super) async fn mta_sender_auth_check(from_address: &str) -> (String, String, String, String) {
    let unknown = |domain: &str, why: &str| {
        (
            domain.to_string(),
            "unknown".to_string(),
            format!("Could not check: {why}. Not the same as OK — verify by hand."),
            String::new(),
        )
    };
    let domain = from_address
        .rsplit_once('@')
        .map(|(_, d)| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default();
    if domain.is_empty() || !domain.contains('.') {
        return (
            domain,
            "no-domain".to_string(),
            "from_address has no usable domain — receivers cannot even evaluate it.".to_string(),
            String::new(),
        );
    }

    // Our address and the domain's TXT in parallel; DMARC only matters on
    // the not-authorized path, so it is fetched there.
    let (our_ip, txts) = tokio::join!(
        fetch_public_ip_v4("https://api4.ipify.org"),
        dig_records(&domain, "TXT"),
    );
    let Ok(txts) = txts else {
        return unknown(&domain, "the TXT lookup failed");
    };
    let Ok(our_ip) = our_ip else {
        return unknown(&domain, "this node's public IPv4 could not be determined");
    };

    // TXT answers come back quoted and possibly chunked; normalize the
    // same way dns_spf_check does before matching the version tag.
    let spf = txts
        .iter()
        .map(|t| t.trim().trim_matches('"').replace("\" \"", ""))
        .find(|t| t.to_ascii_lowercase().starts_with("v=spf1"));
    let Some(spf) = spf else {
        return (
            domain.clone(),
            "no-spf".to_string(),
            format!(
                "{domain} publishes no SPF record, so receivers score mail from it \
                 as unauthenticated — spam folder territory."
            ),
            format!("v=spf1 ip4:{our_ip} ~all"),
        );
    };

    match check_spf_authorizes(&spf, &domain, Some(&our_ip)).await {
        SpfMatch::Match { mechanism } => (
            domain.clone(),
            "authorized".to_string(),
            format!("SPF of {domain} authorizes this server ({mechanism})."),
            String::new(),
        ),
        SpfMatch::CatchAll { mechanism } => (
            domain.clone(),
            "authorized".to_string(),
            format!("SPF of {domain} passes everything ({mechanism}) — permissive, but it passes."),
            String::new(),
        ),
        SpfMatch::NoIp => unknown(&domain, "this node's public IPv4 could not be parsed"),
        SpfMatch::None => {
            // Not authorized. Whether that means "spam folder" or
            // "silently destroyed" is decided by the domain's DMARC.
            let dmarc = dig_records(&format!("_dmarc.{domain}"), "TXT")
                .await
                .unwrap_or_default()
                .iter()
                .map(|t| t.trim().trim_matches('"').replace("\" \"", ""))
                .find(|t| t.to_ascii_lowercase().starts_with("v=dmarc1"))
                .unwrap_or_default();
            let policy = dmarc_policy_of(&dmarc);
            if policy == "reject" || policy == "quarantine" {
                (
                    domain.clone(),
                    "foreign-reject".to_string(),
                    format!(
                        "SPF of {domain} does NOT authorize this server, and its DMARC says \
                         p={policy} — receivers accept the message and then destroy it. \
                         No bounce, no spam folder, no trace here. Nothing sent as this \
                         address will ever arrive; use a domain you control."
                    ),
                    String::new(),
                )
            } else {
                (
                    domain.clone(),
                    "not-authorized".to_string(),
                    format!(
                        "SPF of {domain} exists but does not include this server — \
                         mail fails SPF and tends to land in spam. Add ip4:{our_ip} \
                         to that record, or send from a domain that lists this node."
                    ),
                    String::new(),
                )
            }
        }
    }
}

/// The `p=` policy of a DMARC record, lowercased; empty when absent.
///
/// Only `p=` — `sp=` governs subdomains of the record's own domain, and
/// the caller looks the record up at the exact from-domain, so applying
/// `sp=` here would judge mail by a policy that does not bind it.
pub(super) fn dmarc_policy_of(record: &str) -> String {
    record
        .split(';')
        .filter_map(|kv| kv.trim().strip_prefix("p="))
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Reverse-DNS check for the address this node sends mail from.
///
/// Returns `(public_ipv4, ptr_name, status)` where status is `ok` /
/// `mismatch` / `missing` / `unknown`.
///
/// The comparison is against postfix's `myhostname`, because that is the
/// name it announces in HELO, and the rule receivers apply is that the
/// two agree. Matching is case-insensitive and ignores a trailing dot,
/// which `dig -x` includes and `postconf` does not — comparing them raw
/// would report a mismatch on a perfectly good record.
///
/// `unknown` covers both "could not learn our address" and "the lookup
/// itself failed", and is kept strictly separate from `missing`. Telling
/// an operator a PTR is absent when we simply could not ask would send
/// them to re-create a record that already exists.
pub(super) async fn mta_ptr_check(myhostname: &str) -> (String, String, String) {
    let Ok(ip) = fetch_public_ip_v4("https://api4.ipify.org").await else {
        return (String::new(), String::new(), "unknown".to_string());
    };
    // A bare hostname cannot match any PTR, and reporting that as a PTR
    // mismatch sends the operator to the WRONG side of the comparison:
    // the guidance said "set the PTR to `hosting`" — a bare word — while
    // the PTR was a perfectly good FQDN and the hostname was the thing
    // needing the fix. Report it as its own state so the card can point
    // at `hostnamectl`, not at the DNS console.
    if !myhostname.contains('.') {
        let out = tokio::process::Command::new("/usr/bin/dig")
            .args(["+short", "+time=3", "+tries=1", "-x", &ip])
            .output()
            .await;
        let ptr = out
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or("")
                    .trim_end_matches('.')
                    .to_string()
            })
            .unwrap_or_default();
        return (ip, ptr, "hostname-not-fqdn".to_string());
    }
    let out = tokio::process::Command::new("/usr/bin/dig")
        .args(["+short", "+time=3", "+tries=1", "-x", &ip])
        .output()
        .await;
    let Ok(out) = out else {
        return (ip, String::new(), "unknown".to_string());
    };
    if !out.status.success() {
        return (ip, String::new(), "unknown".to_string());
    }
    let ptr = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string();
    if ptr.is_empty() {
        return (ip, String::new(), "missing".to_string());
    }
    let norm = |s: &str| s.trim().trim_end_matches('.').to_ascii_lowercase();
    let status = if norm(&ptr) == norm(myhostname) {
        "ok"
    } else {
        "mismatch"
    };
    (ip, ptr, status.to_string())
}

/// Probe every common outbound SMTP port with a 3-second timeout
/// each. Runs all probes in parallel via `tokio::join!`. Returns a
/// Vec preserving the well-known port order (25, 465, 587, 2525)
/// so the UI renders a stable table.
///
/// Targets:
///   * 25  — gmail-smtp-in.l.google.com (real MX, port 25 receiving)
///   * 465 — smtp.gmail.com (implicit-TLS submission)
///   * 587 — smtp.gmail.com (STARTTLS submission)
///   * 2525 — smtp.mailgun.org (alt-submission accepted by many
///            providers when 587 is blocked; some operators use
///            it as a last-resort port)
///
/// Each probe is a TCP-connect, no SMTP banner read — we just
/// want to know whether the egress firewall allows the port.
pub(super) async fn probe_outbound_smtp_all() -> Vec<hyperion_types::MtaPortProbe> {
    let p25 = single_smtp_probe(
        25,
        "gmail-smtp-in.l.google.com",
        "MX delivery (recipient servers)",
    );
    let p465 = single_smtp_probe(465, "smtp.gmail.com", "Implicit-TLS submission");
    let p587 = single_smtp_probe(587, "smtp.gmail.com", "STARTTLS submission (most common)");
    let p2525 = single_smtp_probe(
        2525,
        "smtp.mailgun.org",
        "Alt-submission (when 587 blocked)",
    );
    let (r25, r465, r587, r2525) = tokio::join!(p25, p465, p587, p2525);
    vec![r25, r465, r587, r2525]
}

pub(super) async fn single_smtp_probe(
    port: u16,
    host: &str,
    purpose: &str,
) -> hyperion_types::MtaPortProbe {
    use std::time::Instant;
    use tokio::net::TcpStream;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    let target = format!("{host}:{port}");
    let started = Instant::now();
    let connect = tokio::time::timeout(TIMEOUT, TcpStream::connect(&target)).await;
    let elapsed = started.elapsed().as_millis() as u64;
    match connect {
        Ok(Ok(_)) => hyperion_types::MtaPortProbe {
            port,
            host: host.to_string(),
            reachable: true,
            latency_ms: elapsed,
            error: String::new(),
            purpose: purpose.to_string(),
        },
        Ok(Err(e)) => hyperion_types::MtaPortProbe {
            port,
            host: host.to_string(),
            reachable: false,
            latency_ms: 0,
            error: format!("{e}"),
            purpose: purpose.to_string(),
        },
        Err(_) => hyperion_types::MtaPortProbe {
            port,
            host: host.to_string(),
            reachable: false,
            latency_ms: 0,
            error: "timeout after 3 s".to_string(),
            purpose: purpose.to_string(),
        },
    }
}

/// Enable Linux kernel disk quotas on the filesystem carrying `home_path`.
/// Steps assume root (the agent runs as root); a non-root run surfaces as
/// a clear message, not a panic. ext-family filesystems get the full
/// remount + quotacheck + quotaon; XFS quotas only come up at mount time,
/// so there we update fstab and ask for a reboot.
/// Minimal view of agent.toml's `[email]` section, read fresh from disk.
#[derive(Default)]
/// The two `[email]` keys that shape DIRECT-MX delivery rather than the
/// relay. Split out so `mta_reconfigure` can read them off the on-disk
/// section before that section is consumed building the relay config.
pub(super) struct DirectMxTuning {
    pub(super) inet_protocols: String,
    pub(super) bind_address: String,
}

#[derive(Default)]
pub(super) struct EmailTomlView {
    pub(super) enabled: bool,
    pub(super) smtp_host: String,
    pub(super) smtp_port: i64,
    pub(super) smtp_user: String,
    pub(super) smtp_password: String,
    pub(super) from_address: String,
    pub(super) from_name: String,
    pub(super) security: String,
    pub(super) default_to: String,
    pub(super) inet_protocols: String,
    pub(super) bind_address: String,
    /// `message_size_limit_mb`; 0 when absent = postfix's own value.
    pub(super) message_size_limit_mb: u32,
}

/// Read the `[email]` section straight from agent.toml so callers see the
/// CURRENT on-disk config — not the value loaded into the process at startup.
/// Lets `mta_reconfigure` apply a just-saved config without an agent restart,
/// and lets `mta_diagnostics` pre-fill the Settings → Mail form per node.
pub(super) fn load_email_section(path: &std::path::Path) -> EmailTomlView {
    read_email_section(path).unwrap_or_default()
}

/// [`load_email_section`], with an unreadable file kept apart from an empty
/// section: `None` means "the file said nothing", which a caller showing the
/// values to an operator must not render as "nothing is set".
pub(super) fn read_email_section(path: &std::path::Path) -> Option<EmailTomlView> {
    let doc = crate::config_persist::load(path).ok()?;
    let t = doc.as_table().get("email");
    let s = |k: &str| {
        t.and_then(|x| x.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    Some(EmailTomlView {
        enabled: t
            .and_then(|x| x.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        smtp_host: s("smtp_host"),
        smtp_port: t
            .and_then(|x| x.get("smtp_port"))
            .and_then(|v| v.as_integer())
            .unwrap_or(0),
        smtp_user: s("smtp_user"),
        smtp_password: s("smtp_password"),
        from_address: s("from_address"),
        from_name: s("from_name"),
        security: s("security"),
        default_to: s("default_to"),
        inet_protocols: s("inet_protocols"),
        bind_address: s("bind_address"),
        message_size_limit_mb: t
            .and_then(|x| x.get("message_size_limit_mb"))
            .and_then(|v| v.as_integer())
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0),
    })
}

/// `[email]` as the Settings pages show it, read from agent.toml.
///
/// Not from the copy the agent loaded at boot, for the reason
/// `read_backup_remote_section` gives: a save restarts the agent a few
/// seconds AFTER the page it redirects to has rendered, so a view built from
/// memory showed the old relay right under "Saved". And the boot copy only
/// exists while the relay is ON — with it off, every field read back empty,
/// so ticking "enabled" again and pressing Save wrote those blanks over the
/// host, the user and the sender still in the file.
pub(super) fn email_view_from_toml(e: EmailTomlView) -> hyperion_types::EmailConfigView {
    hyperion_types::EmailConfigView {
        enabled: e.enabled,
        smtp_host: e.smtp_host,
        // What the agent uses when the key is absent (`EmailSection`'s default).
        smtp_port: u16::try_from(e.smtp_port)
            .ok()
            .filter(|p| *p != 0)
            .unwrap_or(587),
        smtp_user: e.smtp_user,
        smtp_password_set: !e.smtp_password.is_empty(),
        from_address: e.from_address,
        from_name: e.from_name,
        security: if e.security.trim().is_empty() {
            "starttls".into()
        } else {
            e.security
        },
        default_to: e.default_to,
        message_size_limit_mb: e.message_size_limit_mb,
    }
}

/// `[slack] default_webhook` is set in agent.toml — same reasoning as
/// [`email_view_from_toml`]: Connect and Disconnect must show at once.
/// `None` when the file cannot be read.
pub(super) fn slack_webhook_set_in_toml(path: &std::path::Path) -> Option<bool> {
    let doc = crate::config_persist::load(path).ok()?;
    Some(
        doc.as_table()
            .get("slack")
            .and_then(|t| t.get("default_webhook"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty()),
    )
}

/// Mask an email address for display: keep the first letter +
/// last letter of the local part, replace the rest with `****`.
/// `"kevin@example.cz"` → `"k****n@example.cz"`. Single-letter
/// locals collapse to `*@example.cz`.
pub(super) fn mask_email(s: &str) -> String {
    if let Some(at) = s.find('@') {
        let local = &s[..at];
        let domain = &s[at..];
        match local.chars().count() {
            0 => format!("***{domain}"),
            1 => format!("*{domain}"),
            2 => format!("**{domain}"),
            _ => {
                let mut chars = local.chars();
                let first = chars.next().unwrap_or('?');
                let last = chars.last().unwrap_or('?');
                format!("{first}****{last}{domain}")
            }
        }
    } else {
        "****".to_string()
    }
}
