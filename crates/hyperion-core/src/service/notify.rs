//! Notifications: Slack, email, the notification centre feed and the outbox.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Name shown in the e-mail header when no logo is configured. The
    /// panel hostname is the closest thing to a brand the operator has
    /// already told us; "Hyperion" is a fallback, not a signature.
    pub(super) fn notify_brand_name(&self) -> String {
        let host = read_cluster_section(self.agent_config_path.as_deref()).panel_hostname;
        let host = host.trim();
        if host.is_empty() {
            "Hyperion".to_string()
        } else {
            host.to_string()
        }
    }

    pub(super) fn notify_email_footer(&self) -> String {
        let panel = self.notify_panel_url();
        if panel.is_empty() {
            "Sent by Hyperion.".to_string()
        } else {
            format!("Sent by Hyperion · {panel}")
        }
    }

    /// The operator's logo, as a data URI, or `None`.
    ///
    /// Embedded rather than linked: mail clients block remote images by
    /// default, so a linked logo shows as a broken box for most recipients —
    /// which is worse than no logo at all. Read fresh each send so replacing
    /// the file takes effect without a restart; it is a few KB off local
    /// disk, next to an SMTP round trip.
    pub async fn notify_logo_data_uri_pub(&self) -> Option<String> {
        self.notify_logo_data_uri().await
    }

    /// Store (or clear) the logo. Validated by MAGIC BYTES, not by the
    /// filename or a content-type header — both are supplied by whoever is
    /// uploading, and this file is embedded into mail that leaves the
    /// building.
    pub async fn email_logo_set(&self, bytes: Vec<u8>) -> Result<(), RpcError> {
        let path = std::path::Path::new(EMAIL_LOGO_PATH);
        if bytes.is_empty() {
            let _ = tokio::fs::remove_file(path).await;
            self.append_audit("email.logo.clear", None, "{}", "ok")
                .await;
            return Ok(());
        }
        if bytes.len() > 512 * 1024 {
            return Err(RpcError::Validation {
                message: "logo must be 512 KB or smaller — it is embedded into every message"
                    .into(),
            });
        }
        let ok = matches!(bytes.as_slice(), [0x89, b'P', b'N', b'G', ..])
            || matches!(bytes.as_slice(), [0xFF, 0xD8, 0xFF, ..])
            || bytes.starts_with(b"GIF8");
        if !ok {
            return Err(RpcError::Validation {
                message: "logo must be a PNG, JPEG or GIF image".into(),
            });
        }
        tokio::fs::write(path, &bytes)
            .await
            .map_err(|e| RpcError::Internal_with(format!("write logo: {e}")))?;
        self.append_audit(
            "email.logo.set",
            None,
            &serde_json::json!({"bytes": bytes.len()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// The logo file as raw bytes + its MIME, validated by magic bytes. `None`
    /// when absent, empty, oversized, or an unrecognised format. This is the
    /// form the actual mail uses — attached inline via Content-ID — because
    /// mail clients block `data:` image URIs.
    pub(super) async fn notify_logo_bytes(&self) -> Option<(Vec<u8>, &'static str)> {
        let path = std::path::Path::new(EMAIL_LOGO_PATH);
        let bytes = tokio::fs::read(path).await.ok()?;
        // Cap it. A large image is slow for every recipient and some servers
        // refuse oversized messages outright.
        if bytes.is_empty() || bytes.len() > 512 * 1024 {
            return None;
        }
        let mime = match bytes.as_slice() {
            [0x89, b'P', b'N', b'G', ..] => "image/png",
            [0xFF, 0xD8, 0xFF, ..] => "image/jpeg",
            b if b.starts_with(b"GIF8") => "image/gif",
            b if b.starts_with(b"<svg") || b.starts_with(b"<?xml") => "image/svg+xml",
            _ => return None,
        };
        Some((bytes, mime))
    }

    /// The logo as a `data:` URI — for the settings-page preview only, which
    /// renders in a browser where data URIs work. Real mail uses
    /// [`Self::notify_logo_bytes`] + a Content-ID part instead.
    pub(super) async fn notify_logo_data_uri(&self) -> Option<String> {
        let (bytes, mime) = self.notify_logo_bytes().await?;
        use base64::Engine;
        Some(format!(
            "data:{mime};base64,{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        ))
    }

    /// Mint a one-time node enrollment token. Plaintext returned exactly once.
    // ================================================================
    //  Email + DNS helpers (SPF)
    // ================================================================

    /// Send a plain-text email through the configured SMTP relay.
    /// No-op if email isn't configured.
    ///
    /// Outcome lands in two places:
    ///   1. `audit_log` — tamper-evident cluster-wide record (kept
    ///      for security / compliance review).
    ///   2. `email_log` — operator-facing UX surface, optionally
    ///      tied to a specific hosting so the Emails tab on
    ///      hostings_detail can show "what did we send for this
    ///      site lately".
    ///
    /// `kind` is a free-form label with a recommended vocabulary
    /// ("test" | "alert" | "monitor" | "backup" | "cert" | "billing"
    /// | "other"). It drives the UI's "show only X" filters.
    ///
    /// Returns `true` ONLY when the relay accepted the message. No relay
    /// configured, no recipient to fall back to, and an outright rejection
    /// are all `false`. Callers that go on to record "the customer has been
    /// told" — a period marked as reported, an audit row reading "ok", a
    /// success message on a card — MUST branch on it: a letter the relay
    /// refused was never received, and saying otherwise is the one failure
    /// nobody downstream can detect.
    /// Operator alert addresses this hosting's profile adds.
    ///
    /// The apply-row SNAPSHOT is read first, exactly as the billing sweep
    /// reads the snapshotted Slack webhook: it survives the profile being
    /// deleted, which sets `profile_id` NULL. The live profile is only a
    /// fallback for rows applied before migration 063 — those have no
    /// snapshot, and reading the profile is better than alerting nobody.
    ///
    /// Empty on any failure. An alert must still reach the cluster-wide
    /// addresses when this lookup cannot answer.
    pub(super) async fn profile_alert_emails(&self, hosting_id: &str) -> Vec<String> {
        let id = HostingId(hosting_id.to_string());
        let Ok(Some(row)) = profiles::get_apply(&self.pool, &id).await else {
            return Vec::new();
        };
        if let Some(list) = row.alert_emails.as_deref().filter(|s| !s.trim().is_empty()) {
            return parse_recipient_list(list);
        }
        let Some(pid) = row.profile_id else {
            return Vec::new();
        };
        match profiles::get(&self.pool, pid).await {
            Ok(Some(p)) => parse_recipient_list(&p.alert_emails),
            _ => Vec::new(),
        }
    }

    pub(crate) async fn notify_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        hosting_id: Option<&str>,
        kind: &str,
    ) -> bool {
        let Some(cfg) = self.email_config.as_ref() else {
            return false;
        };
        // A named recipient (a hosting owner, a customer) gets the letter and
        // nobody else. Everything NOT addressed to someone in particular is an
        // operator alert, and those go to every administrator address on
        // record — one entry was never enough for a team, and an alert nobody
        // happened to be reading is an alert that did not happen.
        // An operator alert (empty `to`) also reaches whatever this site's
        // profile names — see `resolve_recipients`.
        let from_profile = match hosting_id {
            Some(id) if to.is_empty() => self.profile_alert_emails(id).await,
            _ => Vec::new(),
        };
        let recipients = resolve_recipients(
            to,
            self.email_default_to.as_deref().unwrap_or(""),
            &from_profile,
        );
        if recipients.is_empty() {
            return false;
        }
        // Apply the operator's editable email wording (defaults "{subject}"
        // / "{body}" are pass-through). Rendered text is what we send AND
        // log, so the email log shows exactly what the recipient received.
        //
        // EXCEPT for the two CUSTOMER letters. Those are complete letters
        // with their own editable templates and their own signature; the
        // generic wrapper is written for short operator alerts (it typically
        // prefixes a tag and appends a panel link the customer cannot open).
        // Wrapping one inside the other produces a mangled subject and a
        // dead link in a letter that goes to a paying customer.
        let tmpls = read_notifications_section(self.agent_config_path.as_deref());
        let is_customer_letter = kind == CARE_REPORT_EMAIL_KIND || kind == EXPIRY_EMAIL_KIND;
        let time = fmt_notif_time(now_secs());
        let panel = self.notify_panel_url();
        let subject_rendered = if is_customer_letter {
            subject.to_string()
        } else {
            render_template(
                &tmpls.email_subject_template,
                &[("subject", subject), ("time", &time)],
            )
        };
        let body_rendered = if is_customer_letter {
            body.to_string()
        } else {
            render_template(
                &tmpls.email_body_template,
                &[
                    ("body", body),
                    ("time", &time),
                    ("panel", &panel),
                    ("kind", kind),
                ],
            )
        };
        let subject = subject_rendered.as_str();
        let body = body_rendered.as_str();
        // Send both shapes. The plain text is exactly what was composed, so
        // nothing is lost for a client that refuses HTML — and a
        // text/html-ONLY message reads as spam to several filters.
        //
        // The logo rides as an inline Content-ID part, NOT a `data:` URI:
        // Gmail and friends strip data-URI images, so the shell references
        // `cid:hyperion-logo` and the bytes are attached below.
        let logo = self.notify_logo_bytes().await;
        let logo_src = logo
            .as_ref()
            .map(|_| format!("cid:{}", hyperion_adapters::email::LOGO_CID));
        let html = hyperion_adapters::email::render_html_shell(
            &self.notify_brand_name(),
            body,
            logo_src.as_deref(),
            &self.notify_email_footer(),
        );
        let logo_part = logo.as_ref().map(|(b, m)| (b.as_slice(), *m));
        let mut any_ok = false;
        for to in &recipients {
            let to = to.as_str();
            any_ok |= match hyperion_adapters::email::send_html(
                cfg, to, subject, body, &html, logo_part,
            )
            .await
            {
                Ok(code) => {
                    self.append_audit(
                    "notify.email",
                    hosting_id,
                    &serde_json::json!({"to": to, "subject": subject, "code": &code, "kind": kind})
                        .to_string(),
                    "ok",
                )
                .await;
                    // tracing::error on append failure — usually means the
                    // migration didn't run on this node (table doesn't
                    // exist) or the SQLite file is read-only. Either way
                    // the operator needs to see this in journalctl.
                    if let Err(e) = hyperion_state::email_log::append(
                        &self.pool,
                        hosting_id,
                        to,
                        subject,
                        body,
                        kind,
                        "ok",
                        None,
                        Some(&code),
                        now_secs(),
                    )
                    .await
                    {
                        tracing::error!(
                            error = %e,
                            to = %to,
                            "email_log append failed — email_log table missing? \
                             restart hyperion-agent after update.sh to apply migration 017"
                        );
                    }
                    true
                }
                Err(e) => {
                    let err_s = e.to_string();
                    self.append_audit(
                        "notify.email",
                        hosting_id,
                        &serde_json::json!({
                            "to": to,
                            "subject": subject,
                            "error": &err_s,
                            "kind": kind,
                        })
                        .to_string(),
                        "failed",
                    )
                    .await;
                    if let Err(le) = hyperion_state::email_log::append(
                        &self.pool,
                        hosting_id,
                        to,
                        subject,
                        body,
                        kind,
                        "failed",
                        Some(&err_s),
                        None,
                        now_secs(),
                    )
                    .await
                    {
                        tracing::error!(
                            log_error = %le,
                            send_error = %err_s,
                            to = %to,
                            "email_log append failed AND email send failed — restart agent to apply migration 017"
                        );
                    }
                    tracing::warn!(to = %to, subject = %subject, error = %err_s, "email send failed");
                    false
                }
            };
        }
        any_ok
    }

    // ================================================================
    //  Slack notifications + billing sweep
    // ================================================================

    /// Send a Slack incoming-webhook message. Specific webhook URL
    /// wins over `slack_default_webhook`. Best-effort: failures are
    /// audit-logged but never propagate to the caller.
    /// Panel URL for `{panel}` in notification templates —
    /// `https://<panel_hostname>` from `[cluster]`, or empty when unset.
    pub(super) fn notify_panel_url(&self) -> String {
        let host = read_cluster_section(self.agent_config_path.as_deref()).panel_hostname;
        let host = host.trim();
        if host.is_empty() {
            String::new()
        } else {
            format!("https://{host}")
        }
    }

    /// Post a test message to the default Slack webhook and REPORT what
    /// happened.
    ///
    /// Deliberately not a thin wrapper over `notify_slack`: that path is
    /// fire-and-forget by design (a failed alert must never take down the
    /// operation that raised it), so it swallows every error into the audit
    /// log. A test button that swallows errors tells the operator nothing —
    /// the entire question being asked is "did this work?".
    ///
    /// Goes through the same `http_post_json` SSRF guard as the real
    /// notification path, so a webhook pointed at 169.254.169.254 is
    /// refused here exactly as it would be in production.
    pub async fn slack_send_test(&self) -> Result<(), RpcError> {
        let Some(url) = self.slack_default_webhook.clone() else {
            return Err(RpcError::Validation {
                message: "No Slack webhook is configured — save one first.".into(),
            });
        };
        let tmpls = read_notifications_section(self.agent_config_path.as_deref());
        let time = fmt_notif_time(now_secs());
        let panel = self.notify_panel_url();
        let message = render_template(
            &tmpls.slack_template,
            &[
                (
                    "message",
                    "Hyperion test message — your Slack webhook is working.",
                ),
                ("time", &time),
                ("panel", &panel),
            ],
        );
        let body = serde_json::json!({ "text": message }).to_string();
        let outcome = http_post_json(&url, &body).await;
        // Audited either way: a test send is still a message leaving the
        // box, and the failure text is what the operator will quote.
        self.append_audit(
            "notify.slack.test",
            None,
            &serde_json::json!({
                "error": outcome.as_ref().err().map(|e| e.to_string()),
            })
            .to_string(),
            if outcome.is_ok() { "ok" } else { "failed" },
        )
        .await;
        outcome.map_err(|e| RpcError::Validation {
            message: format!("Slack refused the test message: {e}"),
        })
    }

    /// Announce a newly provisioned hosting on Slack, once.
    ///
    /// Deliberately NOT fired from `create()`: the price and the billing clock
    /// are set by applying a PROFILE, which happens after the hosting exists.
    /// Announcing at create time would tell the operator "no price set" for
    /// every site, which is the one thing the message is for. So the create
    /// paths call this after the profile step, and a hosting_kv marker makes a
    /// second call a no-op — an operator who re-runs a profile, or an API
    /// client that retries, must not re-announce the site.
    ///
    /// The webhook is the profile's own when it has one, else the cluster
    /// default — same precedence as the billing reminder, so a plan with its
    /// own channel keeps everything about that plan together.
    pub async fn notify_hosting_created(&self, sel: HostingSelector) -> Result<bool, RpcError> {
        let detail = self.get(sel).await?;
        const KV_ANNOUNCED: &str = "created_announced";
        if matches!(
            hyperion_state::hosting_kv::get(&self.pool, detail.id.as_str(), KV_ANNOUNCED).await,
            Ok(Some(_))
        ) {
            return Ok(false);
        }

        let applied = hyperion_state::profiles::get_apply(&self.pool, &detail.id)
            .await
            .ok()
            .flatten();
        // Price, care plan and total, from the same helper the care-plan
        // message uses — the two must never disagree about one site.
        let (price_line, plan_line, total_line) = self.price_picture(&detail.id).await;
        let cat = self.letter_catalog();
        let next_line = Self::next_invoice_line(
            &cat,
            cat.get("slack.what_hosting"),
            applied.as_ref().and_then(|a| a.next_billing_at),
            now_secs(),
        );
        let node = detail
            .node_id
            .as_deref()
            .filter(|n| !n.is_empty())
            .map(|n| n.to_string())
            .unwrap_or_else(|| cat.get("slack.node_unknown").to_string());
        let msg = cat.render(
            "slack.new_hosting",
            &[
                ("domain", &detail.domain),
                ("price", &price_line),
                ("plan", &plan_line),
                ("total", &total_line),
                ("next", &next_line),
                ("node", &node),
            ],
        );

        // The webhook snapshotted at apply time first — it survives the
        // profile being deleted or re-pointed, which is the whole reason the
        // billing sweep reads it that way too. Live lookup only as a fallback.
        let webhook = match applied.as_ref().and_then(|a| a.slack_webhook.clone()) {
            Some(w) => Some(w),
            None => match applied.as_ref().and_then(|a| a.profile_id) {
                Some(pid) => self
                    .profile_get(pid)
                    .await
                    .ok()
                    .and_then(|p| p.slack_webhook),
                None => None,
            },
        };
        self.notify_slack(webhook.as_deref(), &msg).await;

        // Marked only after the send is attempted. notify_slack is
        // best-effort, so a failed post still marks — re-announcing on the
        // next retry would be worse than one lost message.
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            detail.id.as_str(),
            KV_ANNOUNCED,
            &now_secs().to_string(),
            now_secs(),
        )
        .await;
        self.append_audit(
            "hosting.created.announced",
            Some(detail.id.as_str()),
            &serde_json::json!({ "domain": detail.domain }).to_string(),
            "ok",
        )
        .await;
        Ok(true)
    }

    pub(crate) async fn notify_slack(&self, specific: Option<&str>, message: &str) {
        let url = specific
            .filter(|s| !s.trim().is_empty())
            .map(String::from)
            .or_else(|| self.slack_default_webhook.clone());
        let Some(url) = url else {
            return;
        };
        // Apply the operator's editable Slack wording (default "{message}"
        // is pass-through, so output is unchanged unless customised).
        let tmpls = read_notifications_section(self.agent_config_path.as_deref());
        let time = fmt_notif_time(now_secs());
        let panel = self.notify_panel_url();
        let rendered = render_template(
            &tmpls.slack_template,
            &[("message", message), ("time", &time), ("panel", &panel)],
        );
        let message = rendered.as_str();
        let body = serde_json::json!({"text": message}).to_string();
        // SECURITY (sec-findings #3): the Slack webhook is operator/tenant
        // supplied (profile webhooks come in via ProfilesManage, not just
        // super-admin) and this runs as root inside the trust boundary. Route it
        // through the SAME SSRF guard the monitor alert path uses — refuse
        // loopback/private/link-local (incl. 169.254.169.254 cloud metadata),
        // pin curl to the resolved IP, forbid redirects, and restrict the
        // protocol so gopher://… Redis injection can't reach internal services.
        match http_post_json(&url, &body).await {
            Ok(()) => {
                self.append_audit(
                    "notify.slack",
                    None,
                    &serde_json::json!({"message": message}).to_string(),
                    "ok",
                )
                .await;
            }
            Err(e) => {
                self.append_audit(
                    "notify.slack",
                    None,
                    &serde_json::json!({
                        "message": message,
                        "error": e,
                    })
                    .to_string(),
                    "failed",
                )
                .await;
            }
        }
    }

    // ───────────── Notification bell ─────────────

    pub async fn notifications_feed(
        &self,
        user_id: i64,
        limit: i64,
    ) -> Result<hyperion_types::NotificationFeed, RpcError> {
        let items = hyperion_state::notifications::list_recent(&self.pool, user_id, limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications list: {e}")))?
            .into_iter()
            .map(notification_view)
            .collect();
        let unread_total = hyperion_state::notifications::unread_count(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications count: {e}")))?;
        Ok(hyperion_types::NotificationFeed {
            items,
            unread_total,
        })
    }

    pub async fn notifications_mark_read(
        &self,
        user_id: i64,
        notification_id: i64,
    ) -> Result<(), RpcError> {
        hyperion_state::notifications::mark_read(&self.pool, user_id, notification_id, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications mark_read: {e}")))?;
        Ok(())
    }

    pub async fn notifications_mark_all_read(&self, user_id: i64) -> Result<i64, RpcError> {
        let n = hyperion_state::notifications::mark_all_read(&self.pool, user_id, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications mark_all_read: {e}")))?;
        Ok(n)
    }

    pub async fn notifications_search(
        &self,
        user_id: i64,
        filter: hyperion_types::NotificationSearchFilter,
    ) -> Result<hyperion_types::NotificationSearchResult, RpcError> {
        let err = |e| RpcError::Internal_with(format!("notifications search: {e}"));
        let limit = if filter.limit <= 0 {
            NOTIFICATION_PAGE
        } else {
            filter.limit.min(500)
        };
        // Topics are folded from the raw kinds here: the kinds carry site ids,
        // so the topic filter becomes an exact-kind list for the query.
        let kind_counts = hyperion_state::notifications::kind_counts(&self.pool, user_id)
            .await
            .map_err(err)?;
        let f = notification_filter(filter, &kind_counts);
        // One extra row says whether an "Older" link is needed.
        let mut rows = hyperion_state::notifications::search(&self.pool, user_id, &f, limit + 1)
            .await
            .map_err(err)?;
        let more = rows.len() as i64 > limit;
        rows.truncate(limit as usize);
        let c = hyperion_state::notifications::search_counts(&self.pool, user_id, &f)
            .await
            .map_err(err)?;
        let topics = hyperion_types::NOTIFICATION_TOPICS
            .iter()
            .filter_map(|(key, label)| {
                let (total, unread) = kind_counts
                    .iter()
                    .filter(|(k, _, _)| hyperion_types::notification_topic(k).0 == *key)
                    .fold((0, 0), |(t, u), (_, n, r)| (t + n, u + r));
                (total > 0).then(|| hyperion_types::NotificationTopicCount {
                    topic: key.to_string(),
                    label: label.to_string(),
                    total,
                    unread,
                })
            })
            .collect();
        let unread_total = hyperion_state::notifications::unread_count(&self.pool, user_id)
            .await
            .map_err(err)?;
        Ok(hyperion_types::NotificationSearchResult {
            items: rows.into_iter().map(notification_view).collect(),
            counts: hyperion_types::NotificationCounts {
                all: c.all,
                unread: c.unread,
                error: c.error,
                warn: c.warn,
                info: c.info,
                unread_error: c.unread_error,
            },
            topics,
            unread_total,
            more,
        })
    }

    pub async fn notifications_get(
        &self,
        user_id: i64,
        id: i64,
    ) -> Result<Option<hyperion_types::NotificationView>, RpcError> {
        Ok(hyperion_state::notifications::get(&self.pool, user_id, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications get: {e}")))?
            .map(notification_view))
    }

    pub async fn notifications_mark_matching(
        &self,
        user_id: i64,
        filter: hyperion_types::NotificationSearchFilter,
    ) -> Result<i64, RpcError> {
        let err = |e| RpcError::Internal_with(format!("notifications mark_matching: {e}"));
        let kind_counts = hyperion_state::notifications::kind_counts(&self.pool, user_id)
            .await
            .map_err(err)?;
        hyperion_state::notifications::mark_read_matching(
            &self.pool,
            user_id,
            &notification_filter(filter, &kind_counts),
            now_secs(),
        )
        .await
        .map_err(err)
    }

    /// Worker side of the collection: what this node parked for the master.
    pub async fn notifications_outbox(
        &self,
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<hyperion_types::NotificationOutboxItem>, RpcError> {
        Ok(
            hyperion_state::notifications::outbox_after(&self.pool, after_id, limit)
                .await
                .map_err(|e| RpcError::Internal_with(format!("notifications outbox: {e}")))?
                .into_iter()
                .map(|r| hyperion_types::NotificationOutboxItem {
                    id: r.id,
                    severity: r.severity,
                    title: r.title,
                    body: r.body,
                    href: r.href,
                    kind: r.kind,
                    created_at: r.created_at,
                })
                .collect(),
        )
    }

    pub async fn notifications_node_cursor(&self, node_id: &str) -> Result<i64, RpcError> {
        hyperion_state::notifications::node_cursor(&self.pool, node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications cursor: {e}")))
    }

    /// Master side of the collection: give a worker's alerts to every admin
    /// here, as `notify_admins` would have had they been raised on this box.
    ///
    /// The node's answer is signed, but it is still text a worker wrote, and
    /// it ends up as a link in the master's panel: the link is kept only when
    /// it is an internal path, and the severity is pinned to the known three.
    pub async fn notifications_ingest(
        &self,
        node_id: &str,
        items: Vec<hyperion_types::NotificationOutboxItem>,
    ) -> Result<i64, RpcError> {
        if node_id.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "node_id is required".into(),
            });
        }
        let admins: Vec<i64> = hyperion_state::web_users::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("notifications ingest: {e}")))?
            .into_iter()
            .filter(|u| {
                matches!(
                    u.role,
                    hyperion_state::web_users::WebRole::SuperAdmin
                        | hyperion_state::web_users::WebRole::Admin
                )
            })
            .map(|u| u.id)
            .collect();
        let mut written = 0;
        for it in items {
            let row = hyperion_state::notifications::OutboxRow {
                id: it.id,
                severity: match it.severity.as_str() {
                    s @ ("error" | "warn") => s.to_string(),
                    _ => "info".to_string(),
                },
                title: truncate_chars(&it.title, 200),
                body: truncate_chars(&it.body, 1000),
                href: if is_internal_href(&it.href) {
                    it.href
                } else {
                    "/".to_string()
                },
                kind: truncate_chars(&it.kind, 200),
                created_at: it.created_at,
            };
            let replaces = hyperion_types::notification_replaces(&row.kind);
            for &uid in &admins {
                let put = if replaces {
                    hyperion_state::notifications::replace(
                        &self.pool,
                        uid,
                        node_id,
                        Some(row.id),
                        &row,
                    )
                    .await
                } else {
                    hyperion_state::notifications::insert_from_node(&self.pool, uid, node_id, &row)
                        .await
                };
                match put {
                    Ok(true) => written += 1,
                    Ok(false) => {}
                    Err(e) => {
                        return Err(RpcError::Internal_with(format!(
                            "notifications ingest: {e}"
                        )))
                    }
                }
            }
        }
        Ok(written)
    }

    /// An operator alert, in the OPERATOR's language (`[letters] operator_lang`,
    /// default English) — NOT the customer `lang`. A Czech-customer operator
    /// gets their bell in English while their customers still get Czech letters.
    ///
    /// WHICH alert fires and how severe it is stays decided here. An
    /// operator owning the wording cannot promote a warning to an error or
    /// silence one by emptying it: a blank override falls back to the pack,
    /// exactly as it does for the customer letters.
    pub(super) async fn notify_admins_say(
        &self,
        severity: &str,
        id: &str,
        args: &[(&str, &str)],
        href: &str,
        kind: &str,
    ) {
        let cat = self.operator_catalog();
        let title = cat.render(&format!("{id}.title"), args);
        let body = cat.render(&format!("{id}.body"), args);
        self.notify_admins(severity, &title, &body, href, kind)
            .await;
    }

    /// What each severity MEANS, so the notification centre can be read at a
    /// glance instead of parsed.
    ///
    /// * `error` (red) — something is broken RIGHT NOW: the site does not
    ///   serve, the certificate is expired, malware is on disk, the
    ///   filesystem is failing. An operator should stop what they are doing.
    /// * `warn` (orange) — something will break, or a promise is unmet: a
    ///   certificate expiring next week, backups that have never succeeded, a
    ///   care report with nowhere to go. Needs doing; nothing is down.
    /// * `info` — a thing happened that was worth recording.
    ///
    /// The line is deliberately "is it broken now", not "how much do I care".
    /// Everything an operator cares about looks urgent to whoever wrote it,
    /// which is how a panel ends up all red — and a panel that is all red
    /// tells you nothing, so the one genuinely-down site does not stand out.
    /// Fan-out helper: emit one notification to every super_admin
    /// and admin user. Operators are skipped by default since
    /// operator-relevant events typically have a hosting_id and a
    /// targeted recipient list; system-wide events go to admins.
    /// Best-effort — errors are logged, not returned (a single
    /// failed notification mustn't break the caller's flow).
    pub async fn notify_admins(
        &self,
        severity: &str,
        title: &str,
        body: &str,
        href: &str,
        kind: &str,
    ) {
        let now = now_secs();
        // A worker has no web users: the panel and its accounts live on the
        // master. Fanning out here reached nobody, so every alert a worker's
        // own ticks raised was dropped. Park it; the master collects it.
        if self.is_worker_node() {
            if let Err(e) = hyperion_state::notifications::outbox_insert(
                &self.pool, severity, title, body, href, kind, now,
            )
            .await
            {
                tracing::warn!(error = %e, kind, "notify_admins: outbox insert failed");
            }
            return;
        }
        // A worker's repeats are folded when the master collects them.
        let replaces = hyperion_types::notification_replaces(kind);
        let card = hyperion_state::notifications::OutboxRow {
            id: 0,
            severity: severity.to_string(),
            title: title.to_string(),
            body: body.to_string(),
            href: href.to_string(),
            kind: kind.to_string(),
            created_at: now,
        };
        let users = match hyperion_state::web_users::list(&self.pool).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "notify_admins: list users failed");
                return;
            }
        };
        for u in users {
            if !matches!(
                u.role,
                hyperion_state::web_users::WebRole::SuperAdmin
                    | hyperion_state::web_users::WebRole::Admin
            ) {
                continue;
            }
            let put = if replaces {
                hyperion_state::notifications::replace(&self.pool, u.id, "", None, &card)
                    .await
                    .map(|_| ())
            } else {
                hyperion_state::notifications::insert(
                    &self.pool, u.id, severity, title, body, href, kind, now,
                )
                .await
                .map(|_| ())
            };
            if let Err(e) = put {
                tracing::warn!(user = %u.username, error = %e, "notify_admins: insert failed");
            }
        }
    }
}

/// How long the bell's archive (and a worker's outbox) keeps a row.
pub(super) const NOTIFICATION_RETENTION_SECS: i64 = 90 * 86_400;
/// Archive page size when the caller does not ask for one.
pub(super) const NOTIFICATION_PAGE: i64 = 100;

pub(super) fn notification_view(
    r: hyperion_state::notifications::NotificationRow,
) -> hyperion_types::NotificationView {
    hyperion_types::NotificationView {
        id: r.id,
        severity: r.severity,
        title: r.title,
        body: r.body,
        href: r.href,
        kind: r.kind,
        created_at: r.created_at,
        read_at: r.read_at,
        node_id: r.node_id,
    }
}

/// The storage filter for a wire filter. A topic becomes the exact list of
/// this user's kinds in it (`kind_counts` = every kind they have), because
/// kinds carry site ids and cannot be matched by prefix alone.
pub(super) fn notification_filter(
    f: hyperion_types::NotificationSearchFilter,
    kind_counts: &[(String, i64, i64)],
) -> hyperion_state::notifications::SearchFilter {
    let topic = f.topic.trim();
    hyperion_state::notifications::SearchFilter {
        kinds: (!topic.is_empty()).then(|| {
            kind_counts
                .iter()
                .filter(|(k, _, _)| hyperion_types::notification_topic(k).0 == topic)
                .map(|(k, _, _)| k.clone())
                .collect()
        }),
        q: f.q,
        severity: f.severity,
        unread_only: f.unread_only,
        before: f.before,
    }
}

/// A notification link must stay inside the panel: a path, not a scheme or
/// a protocol-relative `//host` (which a browser reads as another site).
pub fn is_internal_href(href: &str) -> bool {
    href.starts_with('/') && !href.starts_with("//") && !href.contains('\\')
}

pub(super) fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        format!("{}…", s.chars().take(max).collect::<String>())
    } else {
        s.to_string()
    }
}

/// POST a JSON payload to a webhook. Used by both Slack (which
/// accepts the same `{"text": "..."}` shape) and the generic webhook
/// channel. Best-effort — returns the curl exit status as Result so
/// the caller can log without taking down the tick.
pub(super) async fn http_post_json(url: &str, json_body: &str) -> Result<(), String> {
    // SSRF guard: the webhook URL is operator/tenant-supplied (monitor alert
    // webhooks are set via require_hosting_access(write), i.e. by tenant-scoped
    // operators), and these target EXTERNAL services (Slack, etc.). Resolve the
    // host and refuse loopback/private/link-local destinations (e.g. the cloud
    // metadata endpoint 169.254.169.254), then pin curl to the validated IP via
    // `--resolve` so it can't re-resolve to something internal (DNS rebinding).
    // We also drop `-L` (no redirect-following) + cap redirects + restrict the
    // protocol, closing the redirect-to-internal pivot.
    let resolve = ssrf_guard_resolve(url).await?;
    let mut args: Vec<String> = vec![
        "-sSk".into(),
        "--max-redirs".into(),
        "0".into(),
        "--proto".into(),
        "=https,http".into(),
        "--max-time".into(),
        "10".into(),
    ];
    for r in &resolve {
        args.push("--resolve".into());
        args.push(r.clone());
    }
    args.extend([
        "-H".into(),
        "Content-Type: application/json".into(),
        "-X".into(),
        "POST".into(),
        "-d".into(),
        json_body.to_string(),
        url.to_string(),
    ]);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args(&arg_refs)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "curl exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Per-section + field validation. Returns owned (field, FieldValue)
/// pairs ready for the persist module.
/// Read the `[cluster]` section out of agent.toml. The cluster
/// section is UI-only — the agent itself doesn't enforce anything;
/// the master web UI checks `master_accepts_hostings` when
/// rendering the /hostings/new "Target node" dropdown. Returns the
/// default (`master_accepts_hostings = true`) on parse failure or
/// missing file/section so an out-of-date agent.toml never breaks
/// the settings page.

/// Format a unix timestamp for embedding in a notification template.
pub(super) fn fmt_notif_time(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default()
}

/// Read the operator-editable `[notifications]` message templates from
/// agent.toml. Missing file / section / keys fall back to the
/// pass-through defaults, so wording is unchanged until customised.
pub(super) fn read_notifications_section(
    cfg_path: Option<&std::path::Path>,
) -> hyperion_types::NotificationTemplatesView {
    let def = hyperion_types::NotificationTemplatesView::default();
    let Some(path) = cfg_path else {
        return def;
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return def;
    };
    let Ok(doc) = raw.parse::<toml_edit::DocumentMut>() else {
        return def;
    };
    let section = doc.get("notifications");
    let get = |key: &str, fallback: &str| -> String {
        section
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(fallback)
            .to_string()
    };
    // Fingerprint of `[letters]`: the language, then every override id and its
    // text, in sorted order. Read from the SAME parsed document so it describes
    // the file this node will actually render from.
    //
    // A digest rather than the section itself: the parity badge only needs to
    // know whether two nodes agree, and shipping ~125 sentences per node to
    // answer that would be a payload for a yes/no.
    let letters_fingerprint = {
        let cat = letter_catalog_from_toml(&raw);
        let mut h = blake3::Hasher::new();
        h.update(match cat.lang {
            crate::letters::LetterLang::Cs => b"cs",
            _ => b"en",
        });
        for (id, text) in &cat.overrides {
            h.update(b"\x00");
            h.update(id.as_bytes());
            h.update(b"\x01");
            h.update(text.as_bytes());
        }
        h.finalize().to_hex().to_string()
    };
    hyperion_types::NotificationTemplatesView {
        letters_fingerprint,
        slack_template: get("slack_template", &def.slack_template),
        email_subject_template: get("email_subject_template", &def.email_subject_template),
        email_body_template: get("email_body_template", &def.email_body_template),
        // The customer letters default to "" — which the renderers read as
        // "use the built-in letter", so a missing key, an empty key and an
        // unreadable agent.toml all land on today's wording.
        care_report_body_template: get("care_report_body_template", &def.care_report_body_template),
        care_report_subject_template: get(
            "care_report_subject_template",
            &def.care_report_subject_template,
        ),
        expiry_warning_body_template: get(
            "expiry_warning_body_template",
            &def.expiry_warning_body_template,
        ),
        expiry_warning_subject_template: get(
            "expiry_warning_subject_template",
            &def.expiry_warning_subject_template,
        ),
    }
}

/// Split the administrator notification address setting into addresses.
///
/// One field, any number of people. Operators write such a list every way
/// there is — commas, semicolons, newlines out of a pasted column — so all of
/// them are accepted rather than making the operator guess which separator
/// this particular field wanted.
///
/// Anything without an `@` is dropped instead of being sent to: the field is
/// free text, and a stray word between two commas would otherwise fail every
/// send that shares its batch. Duplicates are dropped too, so the same person
/// listed twice is not mailed twice.
/// Who one message actually goes to.
///
/// Two different jobs, and conflating them is how a customer ends up on an
/// operator's alert list:
///
/// * A NAMED recipient — a hosting owner, a customer — gets the letter and
///   nobody else. It may still be a LIST: an owner-e-mail field holding
///   "a@x.cz, b@x.cz" used to go out as one malformed address and bounce.
///   Anything the parser cannot make sense of is passed through unchanged
///   rather than dropped, because an SMTP server rejecting an address the
///   operator typed beats hyperion quietly sending to nobody.
/// * An OPERATOR alert — no named recipient — goes to every administrator
///   address on record: the cluster-wide list PLUS whatever the site's
///   profile adds. Additive, never a replacement: adding one address to a
///   profile must not silently stop the operator receiving alerts they were
///   already getting.
///
/// Case-insensitively deduplicated, so an address on both lists is mailed
/// once.
pub(super) fn resolve_recipients(to: &str, cluster: &str, from_profile: &[String]) -> Vec<String> {
    if !to.trim().is_empty() {
        let list = parse_recipient_list(to);
        return if list.is_empty() {
            vec![to.to_string()]
        } else {
            list
        };
    }
    let mut list = parse_recipient_list(cluster);
    for addr in from_profile {
        if !list.iter().any(|e| e.eq_ignore_ascii_case(addr)) {
            list.push(addr.clone());
        }
    }
    list
}

pub(super) fn parse_recipient_list(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split([',', ';', '\n', '\r', ' ', '\t']) {
        let a = part.trim().trim_matches(['<', '>']).trim();
        // Cheapest possible check that it is an address at all: something
        // before an @ and something after it. Full validation belongs to the
        // SMTP server, which will reject what it does not like.
        if a.is_empty() || !a.contains('@') || a.starts_with('@') || a.ends_with('@') {
            continue;
        }
        if !out.iter().any(|e| e.eq_ignore_ascii_case(a)) {
            out.push(a.to_string());
        }
    }
    out
}

#[cfg(test)]
mod recipient_list_tests {
    use super::{parse_recipient_list, resolve_recipients};

    /// The rule the profile alert list exists to follow: it ADDS to the
    /// cluster-wide addresses. Replacing them would mean adding one address
    /// to a profile silently stops the operator getting alerts they were
    /// already receiving.
    #[test]
    fn a_profile_list_adds_to_the_cluster_list() {
        let got = resolve_recipients("", "ops@us.cz", &["it@klient.cz".to_string()]);
        assert_eq!(got, vec!["ops@us.cz", "it@klient.cz"]);
    }

    #[test]
    fn an_address_on_both_lists_is_mailed_once() {
        let got = resolve_recipients("", "ops@us.cz, shared@x.cz", &["OPS@US.CZ".to_string()]);
        assert_eq!(got, vec!["ops@us.cz", "shared@x.cz"]);
    }

    /// A named recipient is the customer. The profile's operator addresses
    /// must never be added to a letter addressed to them.
    #[test]
    fn a_named_recipient_never_gains_the_operator_addresses() {
        let got = resolve_recipients("zakaznik@x.cz", "ops@us.cz", &["it@klient.cz".to_string()]);
        assert_eq!(got, vec!["zakaznik@x.cz"]);
    }

    /// An owner-e-mail field holding two addresses went out as one
    /// malformed recipient and bounced.
    #[test]
    fn a_named_recipient_may_itself_be_a_list() {
        let got = resolve_recipients("a@x.cz, b@x.cz", "ops@us.cz", &[]);
        assert_eq!(got, vec!["a@x.cz", "b@x.cz"]);
    }

    /// Something the parser cannot read is passed on for the SMTP server to
    /// reject, rather than silently becoming "send to nobody".
    #[test]
    fn an_unparseable_named_recipient_is_passed_through() {
        assert_eq!(
            resolve_recipients("not-an-address", "ops@us.cz", &[]),
            vec!["not-an-address"]
        );
    }

    /// No named recipient, no cluster list and no profile list = nothing to
    /// send to, which the caller turns into "did not send".
    #[test]
    fn nothing_configured_yields_no_recipients() {
        assert!(resolve_recipients("", "", &[]).is_empty());
    }

    /// A profile list alone is enough — an install that never set a
    /// cluster-wide address still alerts the people a profile names.
    #[test]
    fn a_profile_list_alone_is_enough() {
        let got = resolve_recipients("", "", &["it@klient.cz".to_string()]);
        assert_eq!(got, vec!["it@klient.cz"]);
    }

    #[test]
    fn one_address_still_works() {
        assert_eq!(parse_recipient_list("ops@example.cz"), ["ops@example.cz"]);
        assert_eq!(
            parse_recipient_list("  ops@example.cz  "),
            ["ops@example.cz"]
        );
    }

    /// Every separator an operator might reach for, including a column
    /// pasted out of a spreadsheet.
    #[test]
    fn a_list_is_split_however_it_was_written() {
        let want = ["a@x.cz", "b@x.cz", "c@x.cz"];
        for raw in [
            "a@x.cz,b@x.cz,c@x.cz",
            "a@x.cz, b@x.cz, c@x.cz",
            "a@x.cz; b@x.cz; c@x.cz",
            "a@x.cz\nb@x.cz\nc@x.cz",
            "a@x.cz b@x.cz c@x.cz",
            "<a@x.cz>, <b@x.cz>, <c@x.cz>",
        ] {
            assert_eq!(parse_recipient_list(raw), want, "{raw:?}");
        }
    }

    /// A stray word must not become a recipient — one unsendable address
    /// would otherwise fail alongside the real ones.
    #[test]
    fn non_addresses_are_dropped_not_sent_to() {
        assert_eq!(
            parse_recipient_list("ops@example.cz, and, also, admin@example.cz"),
            ["ops@example.cz", "admin@example.cz"]
        );
        for raw in ["", "   ", ",,,", "nobody", "@x.cz", "a@"] {
            assert!(parse_recipient_list(raw).is_empty(), "{raw:?}");
        }
    }

    #[test]
    fn the_same_person_is_not_mailed_twice() {
        assert_eq!(
            parse_recipient_list("ops@example.cz, OPS@Example.cz, ops@example.cz"),
            ["ops@example.cz"]
        );
    }
}
