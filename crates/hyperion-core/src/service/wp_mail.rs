//! Keeping WordPress mail on the node's MTA: override, autofix, self-check.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Rebuild postfix's envelope-sender map from every hosting on THIS
    /// node that has DKIM switched on.
    ///
    /// SPF is evaluated against the ENVELOPE sender's domain, and PHP
    /// `mail()` produces an envelope of `<php-fpm user>@<node fqdn>`. So
    /// until this ran, the per-site SPF record the panel tells the
    /// operator to publish was never consulted by any receiver — they
    /// were checking this node's own hostname, which usually has no SPF
    /// record at all. The suggestion was decorative and the card went
    /// green anyway.
    ///
    /// **Keyed on DKIM being enabled**, deliberately. Enabling DKIM means
    /// the operator has published a record in that domain's DNS, so they
    /// demonstrably control its mail identity and the SPF advice on the
    /// same page is theirs to act on. It also means the envelope is never
    /// moved to a domain nobody has set up: a site with DKIM off keeps
    /// the old behaviour exactly.
    ///
    /// Rebuilt wholesale rather than patched, so the file cannot drift
    /// from the hostings that actually exist. The `From:` HEADER is left
    /// alone — see `ensure_sender_canonical`; rewriting it would break
    /// every DKIM signature this node produces.
    pub(super) async fn sync_sender_canonical(&self) -> Result<(), RpcError> {
        let fqdn = my_fqdn().await;
        let mut entries: Vec<(String, String)> = Vec::new();
        for s in self.list().await? {
            if !self.dkim_kv_get(s.id.as_str()).await.enabled {
                continue;
            }
            // The STORED system user, never the domain-derived guess: an
            // imported or renamed site defeats the guess, and a wrong
            // left-hand side here silently fails to match, leaving that
            // site's envelope on the node hostname while the panel says
            // its SPF is fine.
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            if detail.system_user.trim().is_empty() {
                continue;
            }
            entries.push((detail.system_user.clone(), detail.domain.clone()));
        }
        hyperion_adapters::postfix::ensure_sender_canonical(&fqdn, &entries)
            .await
            .map_err(|e| RpcError::Internal_with(format!("postfix sender canonical: {e}")))
    }

    /// Is the WordPress mail self-repair allowed to act on this hosting?
    ///
    /// **Default ON** (absent ⇒ enabled), same contract as the permission
    /// repair: a read error also answers "on", because silently stopping a
    /// repair is worse than repeating one.
    pub async fn wp_mail_autofix_enabled(&self, hosting_id: &str) -> bool {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, WP_MAIL_AUTOFIX_KV_KEY).await
        {
            Ok(Some(v)) => v.trim() != "off",
            _ => true,
        }
    }

    /// Turn the per-site WordPress mail self-repair on or off.
    pub async fn wp_mail_autofix_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
    ) -> Result<bool, RpcError> {
        let detail = self.get(sel).await?;
        hyperion_state::hosting_kv::set(
            &self.pool,
            detail.id.as_str(),
            WP_MAIL_AUTOFIX_KV_KEY,
            if enabled { "on" } else { "off" },
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("wp mail autofix set: {e}")))?;
        // Turning it OFF leaves whatever is on disk exactly as it is. The
        // switch means "stop deciding for me", not "undo what you did" —
        // removing a working mu-plugin because somebody wanted manual
        // control would break the site's mail at the moment they asked for
        // less interference.
        self.append_audit(
            "hosting.wp_mail.autofix.set",
            Some(detail.id.as_str()),
            &serde_json::json!({ "enabled": enabled }).to_string(),
            "ok",
        )
        .await;
        Ok(enabled)
    }

    /// The address this site should send as.
    ///
    /// An operator override wins; otherwise `wordpress@<domain>`. Not the
    /// admin's own mailbox: SPF checks the ENVELOPE, and a real person's
    /// address at another provider is precisely the sender that fails it.
    pub(super) async fn wp_mail_from_address(&self, hosting_id: &str, domain: &str) -> String {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, WP_MAIL_FROM_KV_KEY).await {
            Ok(Some(v)) if !v.trim().is_empty() => v.trim().to_string(),
            _ => hyperion_adapters::wpmail::default_from(domain),
        }
    }

    /// Has hyperion taken WordPress's mail back off an SMTP plugin?
    ///
    /// Off unless it was turned on, and it is only ever turned on after mail
    /// has actually been failing — a working SMTP plugin is the site owner's
    /// choice and none of our business.
    pub(super) async fn wp_mail_force_local(&self, hosting_id: &str) -> Option<i64> {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, WP_MAIL_FORCE_LOCAL_KV_KEY)
            .await
        {
            Ok(Some(v)) => v.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    /// May Hyperion change this site's mail at all? Absent or unreadable ⇒
    /// yes, like the other switches: the pin is what keeps an unconfigured
    /// site's mail from vanishing, so a read error must not drop it.
    pub async fn wp_mail_override_enabled(&self, hosting_id: &str) -> bool {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, WP_MAIL_OVERRIDE_KV_KEY).await
        {
            Ok(Some(v)) => v.trim() != "off",
            _ => true,
        }
    }

    /// What the mail module may do on this site, and since when Hyperion
    /// has been sending instead of an SMTP plugin (only while it may).
    pub(super) async fn wp_mail_policy(
        &self,
        hosting_id: &str,
    ) -> (hyperion_adapters::wpmail::MailPolicy, Option<i64>) {
        use hyperion_adapters::wpmail::MailPolicy;
        if !self.wp_mail_override_enabled(hosting_id).await {
            return (MailPolicy::HandsOff, None);
        }
        match self.wp_mail_force_local(hosting_id).await {
            Some(at) => (MailPolicy::PinFromAndForceLocal, Some(at)),
            None => (MailPolicy::PinFrom, None),
        }
    }

    /// Change what Hyperion may do to one site's mail, and write the module
    /// to match straight away — whatever the auto-configure switch says,
    /// because this is an operator asking for it now.
    ///
    /// * `on` — rewrite a From address on another domain (the default).
    /// * `off` — leave mail alone: for a site sending through its own SMTP
    ///   server. Also hands mail back if Hyperion had taken it over.
    /// * `hand_back` — stop sending instead of the SMTP plugin (its
    ///   credentials were fixed), keep the sender rewrite.
    pub async fn wp_mail_override_set(
        &self,
        sel: HostingSelector,
        mode: String,
    ) -> Result<hyperion_types::FtpCheckReport, RpcError> {
        let detail = self.get(sel.clone()).await?;
        let id = detail.id.as_str();
        let mode = mode.trim().to_ascii_lowercase();
        let set = |v: &'static str| {
            hyperion_state::hosting_kv::set(&self.pool, id, WP_MAIL_OVERRIDE_KV_KEY, v, now_secs())
        };
        match mode.as_str() {
            "on" => set("on").await,
            "off" => set("off").await,
            "hand_back" => Ok(()),
            other => {
                return Err(RpcError::Internal_with(format!(
                    "unknown mail override mode {other:?} (on, off, hand_back)"
                )))
            }
        }
        .map_err(|e| RpcError::Internal_with(format!("wp mail override set: {e}")))?;
        if mode != "on" {
            hyperion_state::hosting_kv::delete(&self.pool, id, WP_MAIL_FORCE_LOCAL_KV_KEY)
                .await
                .map_err(|e| RpcError::Internal_with(format!("wp mail hand back: {e}")))?;
        }
        let now = now_secs();
        hyperion_state::hosting_kv::set(
            &self.pool,
            id,
            WP_MAIL_OVERRIDE_CHANGED_KV_KEY,
            &now.to_string(),
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("wp mail override set: {e}")))?;
        self.append_audit(
            "hosting.wp_mail.override.set",
            Some(id),
            &serde_json::json!({ "domain": detail.domain, "mode": mode }).to_string(),
            "ok",
        )
        .await;
        self.wp_mail_apply(&detail).await?;
        self.wp_mail_self_check(sel).await
    }

    /// Everything we can say about one site's outgoing mail.
    ///
    /// Reads only — the repair is [`Self::wp_mail_repair`]. Reported through
    /// `FtpCheckReport` because that is already this codebase's shape for
    /// "a list of findings, each with a severity and maybe a fix"; the WP
    /// permission check reuses it for the same reason.
    pub async fn wp_mail_self_check(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::FtpCheckReport, RpcError> {
        use hyperion_adapters::wpmail;
        let detail = self.get(sel).await?;
        let mut items: Vec<hyperion_types::FtpCheckItem> = Vec::new();
        let mut push = |id: &str, label: &str, severity: &str, detail: String, fix: &str| {
            items.push(hyperion_types::FtpCheckItem {
                id: id.into(),
                label: label.into(),
                severity: severity.into(),
                detail,
                fix: fix.into(),
            });
        };
        let root = detail.root_dir.trim().to_string();
        let from = self
            .wp_mail_from_address(detail.id.as_str(), &detail.domain)
            .await;
        let (policy, forced_at) = self.wp_mail_policy(detail.id.as_str()).await;
        let log = wpmail::failure_log_path(&root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let expected = wpmail::render_mu_plugin(&detail.domain, &from, &log, policy);
        let state = wpmail::mu_plugin_state(&root, &expected).await;

        if matches!(state, wpmail::MuState::NotWordPress) {
            // Not a finding. A static site has no `wp_mail()` to fix, and
            // reporting "missing" about it would be a complaint that the
            // site is not WordPress.
            // Say what was LOOKED FOR, not what was concluded: a WordPress
            // site whose tree is missing (a failed import, a stub node) must
            // not be told it "is not WordPress" by a card that never opened
            // wp-config.php — it checked for one directory.
            push(
                "wp_mail_plugin",
                "No WordPress tree here",
                "info",
                format!(
                    "There is no wp-content directory under {}, so there is no WordPress \
                     mail to configure. A static or proxied site is expected to look like \
                     this; a WordPress site that does has a missing document tree.",
                    if root.is_empty() {
                        "the document root"
                    } else {
                        root.as_str()
                    }
                ),
                "",
            );
            return Ok(hyperion_types::FtpCheckReport {
                items,
                node_id: self.current_node_id(),
                ..Default::default()
            });
        }

        match state {
            wpmail::MuState::Current if !policy.pins_from() => push(
                "wp_mail_plugin",
                "Hyperion does not rewrite this site's mail",
                "info",
                format!(
                    "Rewriting is switched off for this site, so the From address and SMTP \
                     settings WordPress uses go out unchanged — the setting for a site that sends \
                     through its own SMTP server. Failed sends are still recorded. Mail From an \
                     address outside {} relies on that server being allowed to send for it.",
                    detail.domain
                ),
                "",
            ),
            wpmail::MuState::Current => push(
                "wp_mail_plugin",
                "Sender is pinned to this domain",
                "ok",
                format!(
                    "Hyperion rewrites any From address outside {} to {from}, which is what this \
                     domain's SPF record covers; a sender already on the domain is left as it is. \
                     A site that sends through its own SMTP server can have the rewrite switched \
                     off below.",
                    detail.domain
                ),
                "",
            ),
            wpmail::MuState::Missing if !policy.pins_from() => push(
                "wp_mail_plugin",
                "Failed sends are not being recorded",
                "warn",
                "Rewriting is switched off for this site, but the plugin that records failed \
                 sends is not installed, so a broken SMTP setup would go unnoticed."
                    .into(),
                "site_repair",
            ),
            wpmail::MuState::Missing => push(
                "wp_mail_plugin",
                "Sender is not pinned",
                "warn",
                format!(
                    "The mu-plugin that keeps the From address on {} is not installed, so \
                     WordPress and its plugins can send as any address they like. Mail from \
                     another domain fails SPF at the receiving end and is dropped without a \
                     bounce.",
                    detail.domain
                ),
                "site_repair",
            ),
            wpmail::MuState::Stale => push(
                "wp_mail_plugin",
                "Sender pin is out of date",
                "warn",
                format!(
                    "The installed mu-plugin does not match what this site needs now \
                     (expected sender {from}). Rewriting it is the fix."
                ),
                "site_repair",
            ),
            wpmail::MuState::NotWordPress => {}
        }

        // Failures the plugin recorded. This is the only direct evidence
        // that mail is actually broken — `wp_mail()` returns false and
        // almost every caller in WordPress ignores it.
        let log = wpmail::read_failure_log(&root, 20).await;
        let lines: Vec<String> = log.lines().to_vec();
        let day = now_secs() - 86_400;
        let week = now_secs() - 7 * 86_400;
        let recent = wpmail::failures_since(&lines, day);
        let weekly = wpmail::failures_since(&lines, week);
        // PHP's own mail() refused the newest one: the server's path, which
        // neither the plugin nor a takeover changes.
        let local = weekly > 0
            && lines
                .last()
                .is_some_and(|l| wpmail::is_local_transport_failure(l));
        let since_takeover = forced_at.map_or(0, |at| wpmail::failures_since(&lines, at));

        // Which plugin, if any, has taken `wp_mail()` over. Listed rather
        // than judged: one with working credentials is the owner's choice.
        let active: Vec<String> =
            match hyperion_adapters::wpcli::plugin_list(detail.system_user.trim(), &root).await {
                Ok((plugins, _)) => plugins
                    .into_iter()
                    .filter(|p| p.status.starts_with("active"))
                    .map(|p| p.slug)
                    .collect(),
                // wp-cli failing is its own problem and is reported by the other
                // WordPress cards; here it only means we cannot name the plugin.
                Err(_) => Vec::new(),
            };
        let smtp = wpmail::smtp_plugins_in(&active);
        // The one thing the repair can do about failures themselves: take
        // mail off a failing SMTP plugin. Offering the button for anything
        // else is a button that re-renders the same card — which is how
        // "Configure" came to look broken on a site whose mail() was failing.
        let takeover_pending =
            weekly > 0 && !local && forced_at.is_none() && policy.pins_from() && !smtp.is_empty();
        if matches!(log, wpmail::FailureLog::Unreadable) {
            // "We could not read the record" is not "nothing has failed".
            // Rendering the second for the first is how a site whose log we
            // never opened showed a green card.
            push(
                "wp_mail_failures",
                "Send failures could not be read",
                "warn",
                "The file this site's failed sends are recorded in could not be read — it may \
                 have been replaced with a link, which we do not follow. Nothing here says mail \
                 is working; it says we cannot tell."
                    .into(),
                "site_repair",
            );
        } else if weekly == 0 {
            push(
                "wp_mail_failures",
                "No send failures recorded",
                "ok",
                if lines.is_empty() {
                    "Nothing has failed since the record started.".into()
                } else {
                    format!(
                        "Nothing in the last 7 days. Last recorded failure: {}",
                        lines.last().cloned().unwrap_or_default()
                    )
                },
                "",
            );
        } else {
            let counts = format!(
                "{weekly} failed send(s) in the last 7 days ({recent} in the last 24 h). \
                 Most recent: {}",
                lines.last().cloned().unwrap_or_default()
            );
            let (label, detail_text) = if local {
                (
                    "PHP mail() on this server is failing",
                    format!(
                        "\"Could not instantiate mail function\" means PHP handed the message to \
                         this server's sendmail and got a failure back — the server's mail path \
                         (Hyperion's wrapper, sendmail, postfix), not the site or an SMTP plugin, \
                         so rewriting the mail plugin cannot fix it{}; what the server itself \
                         says is below. {counts}",
                        if forced_at.is_some() {
                            ", and Hyperion sending in the plugin's place goes through that same path"
                        } else {
                            ""
                        }
                    ),
                )
            } else if since_takeover > 0 {
                (
                    "WordPress could not send",
                    format!(
                        "{since_takeover} of these since Hyperion took sending over from the SMTP \
                         plugin, so the plugin's credentials are not the cause — this server's own \
                         mail path is; what the server itself says is below. {counts}"
                    ),
                )
            } else {
                ("WordPress could not send", counts)
            };
            push(
                "wp_mail_failures",
                label,
                if recent > 0 { "error" } else { "warn" },
                detail_text,
                if takeover_pending { "site_repair" } else { "" },
            );
        }

        // When sends fail on the server's side, say what the server says:
        // the failure log only ever holds PHPMailer's one-line summary.
        if local || since_takeover > 0 {
            let probe = wp_mail_transport_probe(&detail).await;
            let said = probe
                .stderr
                .last()
                .map(|l| format!(" Last thing the mail chain said for this site: {l}"))
                .unwrap_or_default();
            if !probe.problems.is_empty() {
                push(
                    "wp_mail_transport",
                    "This server's mail path is broken",
                    "error",
                    format!("{}.{said}", probe.problems.join("; ")),
                    if probe.fixable() { "site_repair" } else { "" },
                );
            } else if !said.is_empty() {
                push(
                    "wp_mail_transport",
                    "Sendmail refused this site's mail",
                    "warn",
                    format!(
                        "The wrapper and sendmail are installed and postfix is running.{said} \
                         Postfix's own log (`journalctl -u postfix@-`) has the rest."
                    ),
                    "",
                );
            } else {
                push(
                    "wp_mail_transport",
                    "This server's mail path is in place",
                    "info",
                    "The wrapper and sendmail are installed, postdrop can queue, and postfix is \
                     running, and nothing from the mail chain is in this site's PHP-FPM log. If \
                     the failures above are older than a fix, they age out; if new ones appear, \
                     send a test from Settings → Mail and read `journalctl -u postfix@-`."
                        .into(),
                    "",
                );
            }
        }

        if !smtp.is_empty() {
            push(
                "wp_mail_smtp_plugin",
                "An SMTP plugin is handling mail",
                if weekly > 0 { "warn" } else { "info" },
                format!(
                    "{} is active and sends the site's mail itself. {}{}",
                    smtp.join(", "),
                    if weekly > 0 {
                        "Since sends are failing, its credentials are the first thing to check."
                    } else {
                        "It is working, so Hyperion does not send in its place."
                    },
                    if policy.pins_from() {
                        format!(
                            " Hyperion still rewrites a From address outside {} to {from}; if \
                             the SMTP server needs its own sender address, switch the rewrite off.",
                            detail.domain
                        )
                    } else {
                        String::new()
                    }
                ),
                if takeover_pending { "site_repair" } else { "" },
            );
        }
        if let Some(at) = forced_at {
            push(
                "wp_mail_force_local",
                "Hyperion is sending this site's mail",
                "info",
                format!(
                    "Since {}, Hyperion has been overriding the SMTP plugin and sending through \
                     this server's own mail path, because sends were failing. Fix the plugin's \
                     credentials, then hand sending back to it below.",
                    iso_date(&LetterCatalog::default(), at)
                ),
                "",
            );
        }

        Ok(hyperion_types::FtpCheckReport {
            items,
            node_id: self.current_node_id(),
            ..Default::default()
        })
    }

    /// Fix what [`Self::wp_mail_self_check`] found, then re-check.
    ///
    /// Two steps, in order of how invasive they are:
    ///
    /// 1. Write the mu-plugin. Always safe — it pins the From address and
    ///    starts recording failures, and changes nothing else.
    /// 2. Only when mail is ACTUALLY failing and an SMTP plugin is in the
    ///    way: take `wp_mail()` back. This one overrides a choice the site
    ///    owner made, so it needs evidence rather than a hunch, and it is
    ///    announced (`notify_admins`) rather than done quietly.
    pub async fn wp_mail_repair(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::FtpCheckReport, RpcError> {
        let detail = self.get(sel.clone()).await?;
        self.wp_mail_apply(&detail).await?;
        self.wp_mail_transport_heal(&detail).await;
        self.wp_mail_self_check(sel).await
    }

    /// Put back the two pieces of the server's mail path a repair can put
    /// back without guessing: postfix stopped, and postdrop without the
    /// setgid bit that lets a site user queue mail. Anything else the
    /// self-check names for a person to fix.
    ///
    /// Only from the operator's click, never the five-minute tick: starting
    /// a stopped MTA is a node-wide act, and somebody may have stopped it.
    async fn wp_mail_transport_heal(&self, detail: &HostingDetail) {
        let probe = wp_mail_transport_probe(detail).await;
        let mut done: Vec<&str> = Vec::new();
        if probe.postdrop_perms {
            match hyperion_adapters::cmd::run(POSTFIX_BIN, &["set-permissions"]).await {
                Ok(_) => done.push("postfix set-permissions"),
                Err(e) => tracing::warn!(error = %e, "wp mail: postfix set-permissions failed"),
            }
        }
        if probe.postfix_down {
            match hyperion_adapters::cmd::run("systemctl", &["start", "postfix"]).await {
                Ok(_) => done.push("systemctl start postfix"),
                Err(e) => tracing::warn!(error = %e, "wp mail: postfix did not start"),
            }
        }
        if !done.is_empty() {
            self.append_audit(
                "hosting.wp_mail.transport_heal",
                Some(detail.id.as_str()),
                &serde_json::json!({ "domain": detail.domain, "ran": done }).to_string(),
                "ok",
            )
            .await;
        }
    }

    /// The repair itself, against a detail we already hold. Returns whether
    /// anything was written.
    pub(super) async fn wp_mail_apply(&self, detail: &HostingDetail) -> Result<bool, RpcError> {
        use hyperion_adapters::wpmail;
        let root = detail.root_dir.trim().to_string();
        let user = detail.system_user.trim().to_string();
        if root.is_empty() || user.is_empty() {
            return Ok(false);
        }
        let id = detail.id.as_str();
        let from = self.wp_mail_from_address(id, &detail.domain).await;
        let log = wpmail::failure_log_path(&root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let (mut policy, forced_at) = self.wp_mail_policy(id).await;

        // Has mail been failing, and is something in the way?
        // `log` above is the log's PATH, which goes into the plugin; this is
        // its CONTENT.
        let failures = wpmail::read_failure_log(&root, 20).await;
        // Only since the operator last touched the switch: failures from
        // before a hand-back are the ones they just fixed.
        let changed_at =
            hyperion_state::hosting_kv::get(&self.pool, id, WP_MAIL_OVERRIDE_CHANGED_KV_KEY)
                .await
                .ok()
                .flatten()
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(0);
        let since = (now_secs() - 7 * 86_400).max(changed_at);
        // Unreadable is not "failing": taking mail off a working SMTP plugin
        // because we could not open a log file would be acting on nothing.
        let failing = wpmail::failures_since(failures.lines(), since) > 0
            // PHP's own mail() failing is not the SMTP plugin's doing, and the
            // takeover sends through that same mail(): overriding the owner's
            // choice — and alerting about it — would change nothing.
            && !failures
                .lines()
                .last()
                .is_some_and(|l| wpmail::is_local_transport_failure(l));
        // Never while rewriting is switched off: that site chose its SMTP
        // server, and its failures are for the card to report.
        if failing && forced_at.is_none() && policy.pins_from() {
            let active: Vec<String> =
                match hyperion_adapters::wpcli::plugin_list(&user, &root).await {
                    Ok((p, _)) => p
                        .into_iter()
                        .filter(|p| p.status.starts_with("active"))
                        .map(|p| p.slug)
                        .collect(),
                    Err(_) => Vec::new(),
                };
            let smtp = wpmail::smtp_plugins_in(&active);
            if !smtp.is_empty() {
                let now = now_secs();
                let _ = hyperion_state::hosting_kv::set(
                    &self.pool,
                    id,
                    WP_MAIL_FORCE_LOCAL_KV_KEY,
                    &now.to_string(),
                    now,
                )
                .await;
                policy = wpmail::MailPolicy::PinFromAndForceLocal;
                // Announced, not quiet: this overrides a decision somebody
                // made deliberately, and an operator who does not know it
                // happened cannot explain it to their customer.
                self.notify_admins_say(
                    "warn",
                    "ops.mail_override",
                    &[("domain", &detail.domain), ("plugins", &smtp.join(", "))],
                    &format!("/hostings/{}", detail.domain),
                    "wp_mail_override",
                )
                .await;
            }
        }

        let contents = wpmail::render_mu_plugin(&detail.domain, &from, &log, policy);
        match wpmail::mu_plugin_state(&root, &contents).await {
            wpmail::MuState::Current | wpmail::MuState::NotWordPress => Ok(false),
            _ => {
                wpmail::install_mu_plugin(&root, &user, &contents)
                    .await
                    .map_err(RpcError::from)?;
                Ok(true)
            }
        }
    }

    /// Keep every WordPress site's mail configured, and only speak up when
    /// the repair did not help.
    ///
    /// The user-visible contract is "set it up automatically; if it errors,
    /// try to fix it; notify only after that fails". So: writing the
    /// mu-plugin is silent, taking mail off a broken SMTP plugin is a
    /// warning, and mail STILL failing afterwards is an error — that is the
    /// point at which hyperion has run out of things to try and a person
    /// has to look.
    pub async fn wp_mail_tick(&self) -> Result<i64, RpcError> {
        let mut acted = 0i64;
        for s in self.list().await? {
            if s.state != HostingState::Active {
                continue;
            }
            if !self.wp_mail_autofix_enabled(s.id.as_str()).await {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            if detail.root_dir.trim().is_empty() || detail.system_user.trim().is_empty() {
                continue;
            }
            let before = self.wp_mail_force_local(detail.id.as_str()).await;
            match self.wp_mail_apply(&detail).await {
                Ok(true) => {
                    acted += 1;
                    tracing::info!(domain = %detail.domain, "wp mail: configuration written");
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(domain = %detail.domain, error = %e, "wp mail: repair failed");
                    self.append_audit(
                        "hosting.wp_mail.autofix",
                        Some(detail.id.as_str()),
                        &serde_json::json!({"error": e.to_string()}).to_string(),
                        "failed",
                    )
                    .await;
                    continue;
                }
            }
            // The one thing worth waking somebody for: we already took mail
            // over, and it is STILL failing. Measured from the moment of the
            // override so the failures that CAUSED it cannot re-trigger this
            // for ever.
            if let Some(at) = before {
                let lines = hyperion_adapters::wpmail::recent_failures(&detail.root_dir, 20).await;
                // A SLIDING day, floored by the override plus an hour's
                // grace. An absolute cutoff was wrong in both directions: a
                // single failure the day after the override re-alerted for
                // ever, and a site that started failing months later was
                // compared against a cutoff so old that every line counted.
                // The floor keeps the failures that CAUSED the override from
                // being read as evidence against it.
                let since = (now_secs() - 86_400).max(at + 3_600);
                if hyperion_adapters::wpmail::failures_since(&lines, since) > 0 {
                    self.notify_admins_say(
                        "error",
                        "ops.mail_failing",
                        &[("domain", &detail.domain)],
                        &format!("/hostings/{}", detail.domain),
                        "wp_mail_failing",
                    )
                    .await;
                }
            }
        }
        Ok(acted)
    }
}

/// Per-site switch for the WordPress mail self-repair. Absent ⇒ ON.
pub(super) const WP_MAIL_AUTOFIX_KV_KEY: &str = "wp_mail_autofix_enabled";
/// Unix seconds when hyperion took `wp_mail()` off an SMTP plugin, or absent.
/// A timestamp rather than a flag because "is it still failing SINCE we
/// intervened" is the question the tick has to answer.
pub(super) const WP_MAIL_FORCE_LOCAL_KV_KEY: &str = "wp_mail_force_local_at";
/// Operator override for the sender address; absent ⇒ `wordpress@<domain>`.
pub(super) const WP_MAIL_FROM_KV_KEY: &str = "wp_mail_from";
/// Per-site switch for Hyperion rewriting the site's mail at all (sender
/// pin, SMTP takeover). Absent ⇒ ON; `off` is for a site on its own SMTP
/// server whose provider wants the account's own From address.
pub(super) const WP_MAIL_OVERRIDE_KV_KEY: &str = "wp_mail_override";
/// Unix seconds of the operator's last change to that switch. Failures
/// recorded before it are not evidence for a takeover: they are what the
/// operator just dealt with, and counting them took mail straight back off
/// the SMTP plugin on the next tick after it was handed back.
pub(super) const WP_MAIL_OVERRIDE_CHANGED_KV_KEY: &str = "wp_mail_override_changed_at";

/// The shim every PHP-FPM pool has as its `sendmail_path`. The mail test
/// runs through it when present so the diagnostic and production share a
/// code path.
pub(super) const SITE_MAIL_WRAPPER: &str = "/usr/local/lib/hyperion/site-mail-wrapper";

const SENDMAIL_BIN: &str = "/usr/sbin/sendmail";
const POSTDROP_BIN: &str = "/usr/sbin/postdrop";
const POSTFIX_BIN: &str = "/usr/sbin/postfix";
/// Where Debian's PHP-FPM writes `php<ver>-fpm.log`.
const FPM_LOG_DIR: &str = "/var/log";

/// Where the server's half of one site's mail stands: what PHP's `mail()`
/// runs when the site sends.
pub(super) struct MailTransportProbe {
    /// What is wrong, in the operator's words. Empty ⇒ in place.
    pub(super) problems: Vec<String>,
    /// postfix is installed and not running — the repair starts it.
    pub(super) postfix_down: bool,
    /// postdrop lost its setgid bit — the repair runs `postfix set-permissions`.
    pub(super) postdrop_perms: bool,
    /// The mail chain's own words from this pool's FPM log, newest last.
    pub(super) stderr: Vec<String>,
}

impl MailTransportProbe {
    /// Is there something here the repair button can actually do?
    pub(super) fn fixable(&self) -> bool {
        self.postfix_down || self.postdrop_perms
    }
}

/// Look at the server's mail path the way the site's PHP uses it, without
/// sending anything.
pub(super) async fn wp_mail_transport_probe(detail: &HostingDetail) -> MailTransportProbe {
    use std::os::unix::fs::PermissionsExt;
    let mut probe = MailTransportProbe {
        problems: Vec::new(),
        postfix_down: false,
        postdrop_perms: false,
        stderr: Vec::new(),
    };
    let mode = |p: &'static str| async move {
        tokio::fs::metadata(p)
            .await
            .ok()
            .map(|m| m.permissions().mode())
    };
    match mode(SITE_MAIL_WRAPPER).await {
        None => probe.problems.push(format!(
            "{SITE_MAIL_WRAPPER}, which every site's PHP runs as its sendmail, is missing — \
             update.sh reinstalls it"
        )),
        Some(m) if m & 0o111 == 0 => probe.problems.push(format!(
            "{SITE_MAIL_WRAPPER} is not executable, so PHP cannot run it — update.sh \
             reinstalls it"
        )),
        Some(_) => {}
    }
    if mode(SENDMAIL_BIN).await.is_none() {
        probe.problems.push(format!(
            "postfix is not installed ({SENDMAIL_BIN} is missing)"
        ));
    } else {
        if mode(POSTDROP_BIN).await.is_some_and(|m| m & 0o2000 == 0) {
            probe.postdrop_perms = true;
            probe.problems.push(format!(
                "{POSTDROP_BIN} has lost its setgid bit, so a site user cannot put mail in the \
                 queue"
            ));
        }
        if let Ok(out) = tokio::process::Command::new(POSTFIX_BIN)
            .arg("status")
            .output()
            .await
        {
            if !out.status.success() {
                probe.postfix_down = true;
                let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
                probe.problems.push(if said.is_empty() {
                    "postfix is not running".to_string()
                } else {
                    format!("postfix is not running ({said})")
                });
            }
        }
    }
    if let Some(ver) = detail.php_version {
        let path = std::path::Path::new(FPM_LOG_DIR).join(format!("{}.log", ver.service_name()));
        let pool = detail.system_user.trim().to_string();
        if let Ok(Some(text)) = tokio::task::spawn_blocking(move || {
            hyperion_adapters::wpmail::log_tail(&path, 512 * 1024)
        })
        .await
        {
            probe.stderr = hyperion_adapters::wpmail::sendmail_stderr_for_pool(&text, &pool, 3);
        }
    }
    probe
}
