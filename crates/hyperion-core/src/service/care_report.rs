//! The periodic care report the customer receives: building, rendering,
//! sending.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ================================================================
    //  The care report — the only half of a package the CUSTOMER sees
    // ================================================================
    //
    // Everything above is invisible when it works: a well-run site is a
    // site nobody notices, and an invoice for something nobody noticed is
    // the one that gets cancelled. The report is what turns a month of
    // quiet into something the person paying can read.
    //
    // One rule outranks looking good: it must never imply something was
    // measured when it was not. `hyperion_state::reports` produces that
    // distinction FROM THE ROWS (`None` = nobody was watching, `Some(0)` =
    // we watched and nothing happened), and everything below is only
    // allowed to print it — never to guess it. A flattering "100 %
    // dostupnost" for a site nobody ever monitored is a written claim to a
    // paying customer, and worse than sending nothing at all.
    //
    // Node locality: every source (bans, usage buckets, monitor samples,
    // backup runs, the audit log, the stored scan) is per-node, so all of
    // this runs on the node that OWNS the hosting. Run on the master for a
    // worker-hosted site, every query truthfully answers "not measured" —
    // which is why the tick is registered on every node and why the web
    // layer dispatches preview / send to the owner.

    /// Assemble one hosting's care report for the half-open period
    /// `[from, to)` out of THIS node's tables.
    ///
    /// Starts from `CareReport::empty` — every section unmeasured — and
    /// only ever fills a section in, so a query that fails costs the
    /// customer information instead of inventing a reassuring number.
    pub async fn care_report_build(
        &self,
        sel: HostingSelector,
        from: i64,
        to: i64,
    ) -> Result<CareReport, RpcError> {
        use hyperion_state::reports;
        let detail = self.get(sel).await?;
        let id = detail.id.as_str();
        let wrap = |what: &str, e: hyperion_state::db::StateError| {
            RpcError::Internal_with(format!("care report ({what}): {e}"))
        };
        let mut report = CareReport::empty(detail.id.clone(), detail.domain.clone(), from, to);
        report.service_work = self.care_service_work(id, from, to).await;

        // The one metric whose unmeasured state the database CANNOT see:
        // with `[fail2ban] enabled = false` — or with this site opted out of
        // the HTTP scan — the scanner never looked, so zero bans means nobody
        // was watching rather than nobody attacking. Only this caller knows
        // which, so only this caller may map it — hence the count stays
        // `None` instead of becoming a proud zero.
        //
        // An opted-out site loses the handful of bans an operator may have
        // attributed to it by hand, since those share the same column. That
        // is the safe direction: the section claims ongoing protection, and
        // there was none.
        //
        // Protection running NOW is only half the question: it says nothing
        // about the 29 days before an operator switched it on. The scanner's
        // own coverage stamp answers the other half, and bounds the claim to
        // the days it can evidence.
        if let Some(since) = self.bruteforce_coverage_since(id).await {
            // The COUNT and the sentence describing it must come from one
            // window. Counting the whole period while saying "watching
            // since the 25th, so this figure covers only that part" put a
            // 21-day total inside a 5-day claim — and in the flattering
            // direction. Bans survive an opt-out (rows are never deleted)
            // and can be attributed by hand at any time, so the two windows
            // really do diverge.
            if let Some(effective) = attacks_window(since, from, to) {
                report.attacks_blocked = Some(
                    reports::attacks_blocked(&self.pool, id, effective, to)
                        .await
                        .map_err(|e| wrap("attacks", e))?,
                );
                report.attacks_covered_since = (since > from).then_some(since);
            }
        }
        report.updates_applied = reports::updates_applied(&self.pool, id, from, to)
            .await
            .map_err(|e| wrap("updates", e))?;
        report.usage = reports::usage(&self.pool, id, from, to)
            .await
            .map_err(|e| wrap("usage", e))?;
        // `reports::uptime` always answers, because zero samples IS its
        // unmeasured state. The DTO says the same thing with `None`, so
        // collapse it here — that keeps ONE rule for the renderer ("absent
        // ⇒ say we did not measure") instead of two ways to say it, and it
        // is what lets `is_entirely_unmeasured` be true for a site nothing
        // ever watched.
        let uptime = reports::uptime(&self.pool, id, from, to)
            .await
            .map_err(|e| wrap("uptime", e))?;
        report.uptime = (uptime.samples > 0).then_some(uptime);
        report.backups = reports::backups(&self.pool, id, from, to)
            .await
            .map_err(|e| wrap("backups", e))?;
        report.integrity = reports::integrity(&self.pool, id, from, to)
            .await
            .map_err(|e| wrap("integrity", e))?;
        // Page performance: render + speed from the site check, Core Web
        // Vitals from whatever source is configured. Both live in hosting_kv
        // on this node, so this is a local read like the sections above.
        report.performance = self.care_performance(id).await;
        Ok(report)
    }

    /// Render the current period's report WITHOUT sending anything — what
    /// the operator's "Preview" button shows.
    ///
    /// It exists so the operator can read the exact text their customer
    /// will receive before it goes out. That means it must use the same
    /// period, the same recipient and the same renderer the tick does; a
    /// preview that differs from the mail is worse than no preview.
    pub async fn care_report_preview(
        &self,
        sel: HostingSelector,
    ) -> Result<CareReportMail, RpcError> {
        let (detail, mail, letter) = self.care_report_mail(sel, None).await?;
        // Audited even though it sends nothing: the preview renders the
        // customer's owner e-mail, their traffic figures, the attacks-blocked
        // count and the integrity verdict. "It only reads" is not a reason to
        // leave a cross-tenant read off the trail — /audit should be able to
        // answer who looked at whose report.
        //
        // `letter` says WHICH body was rendered, and it is the only durable
        // answer: the template is read from the agent.toml of the node that
        // owns the hosting (see `care_report_template`), so two sites can be
        // previewed on the same panel, minutes apart, and get different
        // letters. Without this the trail records that a preview happened but
        // not which of the two the operator was shown.
        self.append_audit(
            "package.report.preview",
            Some(detail.id.as_str()),
            &serde_json::json!({ "domain": detail.domain, "letter": letter }).to_string(),
            "ok",
        )
        .await;
        Ok(mail)
    }

    /// Send the current period's report now, on the operator's say-so.
    ///
    /// A real send: once the relay has taken the message it records the
    /// period as reported, so the scheduled one does not repeat it an hour
    /// later and the NEXT period starts here. A relay that refuses is an
    /// error to the operator and leaves the period open — the card must
    /// never read "sent to …" for a letter nobody received.
    ///
    /// Refuses (rather than falling back to the cluster's default
    /// address) when the site has no care report e-mail — the report belongs to
    /// the customer, and quietly mailing it to the operator instead would
    /// leave the customer with nothing while everything looked fine.
    pub async fn care_report_send(&self, sel: HostingSelector) -> Result<CareReportMail, RpcError> {
        let (detail, mail, letter) = self.care_report_mail(sel, None).await?;
        if mail.to.is_empty() {
            return Err(RpcError::Validation {
                message: "this site has no care report e-mail — set one on the care plan \
                          first, otherwise the report has nowhere to go"
                    .into(),
            });
        }
        if self.email_config.is_none() {
            return Err(RpcError::Validation {
                message: "no SMTP relay is configured on the node that owns this site, \
                          so nothing can be sent"
                    .into(),
            });
        }
        if !self
            .notify_email(
                &mail.to,
                &mail.subject,
                &mail.body,
                Some(detail.id.as_str()),
                CARE_REPORT_EMAIL_KIND,
            )
            .await
        {
            // No marker and no "ok" audit row: the period stays open, so the
            // tick can still deliver it once the relay is fixed. The error
            // names where the relay's OWN words are — `notify_email` already
            // wrote them to email_log, which is the site's Emails tab.
            return Err(RpcError::Internal_with(format!(
                "the SMTP relay refused this report, so nothing was sent — \
                 open the Emails tab on {} for the relay's own message. \
                 The period stays open and can be reported once it works.",
                detail.domain
            )));
        }
        self.care_report_mark_reported(&detail.id, mail.period_end)
            .await;
        self.append_audit(
            "package.report.send",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "to": mail.to,
                "period_start": mail.period_start,
                "period_end": mail.period_end,
                "manual": true,
                // Which body the customer just received — see the preview's
                // audit row for why the answer is per-node and therefore
                // worth recording next to the send itself.
                "letter": letter,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(mail)
    }

    /// Render a report for the operator's own `[from, to)` WITHOUT sending
    /// anything — the preview half of a one-off, custom-range report.
    pub async fn care_report_preview_range(
        &self,
        sel: HostingSelector,
        from: i64,
        to: i64,
    ) -> Result<CareReportMail, RpcError> {
        let (detail, mail, letter) = self.care_report_mail(sel, Some((from, to))).await?;
        self.append_audit(
            "package.report.preview",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "letter": letter,
                "custom_range": true,
                "period_start": mail.period_start,
                "period_end": mail.period_end,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(mail)
    }

    /// Send a report for the operator's own `[from, to)` now — a one-off,
    /// OUTSIDE the schedule.
    ///
    /// Same refusals as [`Self::care_report_send`] (no recipient, no
    /// relay, relay said no), with one deliberate difference: the period
    /// marker is never touched. The schedule's periods stay contiguous no
    /// matter what range the operator picked — a custom report for last
    /// year must not swallow the month the next scheduled letter is about,
    /// and one for last week must not make the schedule repeat it.
    pub async fn care_report_send_range(
        &self,
        sel: HostingSelector,
        from: i64,
        to: i64,
    ) -> Result<CareReportMail, RpcError> {
        let (detail, mail, letter) = self.care_report_mail(sel, Some((from, to))).await?;
        if mail.to.is_empty() {
            return Err(RpcError::Validation {
                message: "this site has no care report e-mail — set one on the care plan \
                          first, otherwise the report has nowhere to go"
                    .into(),
            });
        }
        if self.email_config.is_none() {
            return Err(RpcError::Validation {
                message: "no SMTP relay is configured on the node that owns this site, \
                          so nothing can be sent"
                    .into(),
            });
        }
        if !self
            .notify_email(
                &mail.to,
                &mail.subject,
                &mail.body,
                Some(detail.id.as_str()),
                CARE_REPORT_EMAIL_KIND,
            )
            .await
        {
            return Err(RpcError::Internal_with(format!(
                "the SMTP relay refused this report, so nothing was sent — \
                 open the Emails tab on {} for the relay's own message.",
                detail.domain
            )));
        }
        // No `care_report_mark_reported`: see the doc above.
        self.append_audit(
            "package.report.send",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "to": mail.to,
                "period_start": mail.period_start,
                "period_end": mail.period_end,
                "manual": true,
                "custom_range": true,
                "letter": letter,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(mail)
    }

    /// The operator's care-report body template from `[notifications]` in
    /// agent.toml. Empty string (the default, and also what an unreadable
    /// or template-less agent.toml yields) means "use the built-in letter".
    ///
    /// THIS NODE's agent.toml, and that is the whole subtlety: the report is
    /// rendered wherever the hosting lives, because that is the only node
    /// holding its metrics. Settings → Customer letters writes the file it can
    /// reach — the master's — so until the same text reaches a worker, that
    /// worker's customers keep receiving the built-in letter. hyperion-web
    /// pushes the section to every enrolled node on save and shows, per node,
    /// which letter is actually on disk there; every render here records
    /// which one it used (`letter_origin`), so the answer survives in the
    /// trail rather than living only in a page nobody reloaded.
    pub(super) fn care_report_template(&self) -> String {
        read_notifications_section(self.agent_config_path.as_deref()).care_report_body_template
    }

    /// The letter LANGUAGE plus every per-string override, from `[letters]`
    /// in agent.toml.
    ///
    /// Same per-node caveat as the two body templates above: the letter is
    /// rendered on the node that owns the hosting, so a worker keeps writing
    /// in the old language until the section reaches it.
    /// `hosting_kv` key holding a site's own letter language.
    pub const LETTER_LANG_KV_KEY: &'static str = "letters.lang";

    /// Build the current period's mail for one hosting — the shared body
    /// of preview and send, so the two can never render different text.
    ///
    /// `range` is the operator's own `[from, to)` for a one-off report;
    /// `None` is the open period the schedule would report next. Everything
    /// else — recipient, sections left out, letter — is the same either way,
    /// so a custom-range letter reads exactly like a scheduled one.
    ///
    /// Returns the letter's origin alongside it (`letter_origin`), read from
    /// the SAME string that was rendered: re-reading agent.toml at the audit
    /// site could name a letter the mail wasn't built from.
    pub(super) async fn care_report_mail(
        &self,
        sel: HostingSelector,
        range: Option<(i64, i64)>,
    ) -> Result<(HostingDetail, CareReportMail, &'static str), RpcError> {
        let detail = self.get(sel).await?;
        let now = now_secs();
        let (cadence, started_at, omit) = self.care_report_entitlement(&detail.id).await;
        let (from, to) = match range {
            Some(r) => care_report_custom_range(r, now)?,
            None => {
                self.care_report_period(&detail.id, cadence, started_at, now)
                    .await
            }
        };
        let report = self
            .care_report_build(HostingSelector::Id(detail.id.clone()), from, to)
            .await?;
        // Preview and send share this path, so the operator's edited letter
        // is what BOTH show — a preview that differs from the mail is worse
        // than no preview.
        let template = self.care_report_template();
        let subject_template = read_notifications_section(self.agent_config_path.as_deref())
            .care_report_subject_template;
        let cat = self.letter_catalog_for(&detail.id).await;
        let letter = letter_origin_with(&template, &cat, CARE_FRAME_IDS);
        let (subject, body) = care_report_render_full_omitting(
            &cat,
            &report,
            &detail.domain,
            &template,
            &subject_template,
            omit,
        );
        let mail = CareReportMail {
            subject,
            body,
            period_start: from,
            period_end: to,
            to: self.care_report_recipient(&detail).await,
            cadence: cadence.as_str().to_string(),
            entirely_unmeasured: report.is_entirely_unmeasured_for(omit),
        };
        Ok((detail, mail, letter))
    }

    /// Periodic sweep — one care report per entitled hosting per cadence.
    ///
    /// Walks THIS node's active activations (they are co-located with
    /// their hosting, which is also where every metric lives), folds each
    /// hosting's packages into one cadence, and mails the customer once a
    /// full period has elapsed since the last report.
    ///
    /// Three things it deliberately does NOT do:
    ///   * it never reports on "now minus one cadence". The period start
    ///     is the end of the last report actually sent, so a tick the node
    ///     slept through widens the next report instead of dropping the
    ///     days in between;
    ///   * it never consumes a period it could not deliver. Missing
    ///     recipient, missing relay, nothing measurable, a relay that
    ///     refused the message — each leaves the marker untouched, so the
    ///     history is still there when the operator fixes it;
    ///   * it never fails quietly. Every skip is a WARN naming the domain,
    ///     because not sending a report the customer is paying for is the
    ///     failure this feature exists to prevent, and it is invisible by
    ///     nature.
    ///
    /// Returns how many reports went out.
    pub async fn care_report_tick(&self) -> Result<i64, RpcError> {
        let rows = packages::list_all_in_force(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("care report tick: {e}")))?;
        if rows.is_empty() {
            // Same ignore-the-feature-entirely path as the drift tick: no
            // activations, no queries against any hosting.
            return Ok(0);
        }
        // Fold each hosting's activations into ONE cadence up front, with
        // the same rule the drift tick uses: the customer keeps the most
        // they paid for, so a monthly package alongside a quarterly one
        // sends monthly, and a package that pins reports `off` cannot
        // silence one that sells them.
        let mut order: Vec<HostingId> = Vec::new();
        let mut wanted: HashMap<String, (ReportCadence, i64, Vec<ReportOmit>)> = HashMap::new();
        for row in rows {
            let c = row.features.report_cadence;
            // Only an activation that actually SELLS a report may set the
            // entitlement's start date; `i64::MAX` is the "none yet" seed
            // and is unreachable once one does (see `care_report_period`,
            // which only reads it for a sellable cadence). The operator's
            // `valid_from` wins over the click: backdated, the first report
            // reaches back to the day the customer started paying.
            let sells = report_cadence_secs(c).is_some();
            let starts = sells.then(|| row.valid_from.unwrap_or(row.activated_at));
            // Same rule for the sections: only a plan that sells a report has a
            // say in what it holds.
            let omit = sells.then(|| ReportOmit::parse(&row.report_omit));
            match wanted.get_mut(row.hosting_id.as_str()) {
                Some((cadence, since, omits)) => {
                    *cadence = cadence.combine(c);
                    if let Some(t) = starts {
                        *since = (*since).min(t);
                    }
                    omits.extend(omit);
                }
                None => {
                    order.push(row.hosting_id.clone());
                    wanted.insert(
                        row.hosting_id.as_str().to_string(),
                        (c, starts.unwrap_or(i64::MAX), omit.into_iter().collect()),
                    );
                }
            }
        }

        let now = now_secs();
        // Read the operator's letter template ONCE per tick, not once per
        // hosting: it's a file read, and every report in this sweep must in
        // any case be worded the same way.
        //
        // "The same way" is per NODE, not per cluster — this file is this
        // node's (see `care_report_template`). The origin therefore goes on
        // every "care report sent" line: a worker that never received the
        // operator's letter says so in its own journal, which is where you
        // look when a customer forwards you wording you don't recognise.
        let body_template = self.care_report_template();
        let subject_template = read_notifications_section(self.agent_config_path.as_deref())
            .care_report_subject_template;
        let mut sent = 0i64;
        for hosting_id in order {
            let Some((cadence, started_at, omits)) = wanted.get(hosting_id.as_str()) else {
                continue;
            };
            let (cadence, started_at) = (*cadence, *started_at);
            // What this site's plans, folded, leave out of the letter.
            let omit = ReportOmit::fold_sites(omits.iter().copied());
            let Some(cadence_secs) = report_cadence_secs(cadence) else {
                continue; // leave / off — this site buys no report
            };
            let detail = match self.get(HostingSelector::Id(hosting_id.clone())).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(hosting_id = %hosting_id.as_str(), error = %e, "care report: hosting read failed");
                    continue;
                }
            };
            if detail.state != HostingState::Active {
                continue;
            }
            let (from, to) = self
                .care_report_period(&hosting_id, cadence, Some(started_at), now)
                .await;
            if to - from < cadence_secs {
                continue; // the period isn't full yet — the common case
            }

            // Both guards leave the marker alone on purpose: the period
            // stays open, so once the operator fixes the cause the customer
            // gets the whole history rather than starting from that moment.
            // Yes, this warns on every tick until it is fixed. That is the
            // point — a report nobody receives has no other symptom.
            if self.email_config.is_none() {
                tracing::warn!(
                    domain = %detail.domain,
                    hosting_id = %detail.id.as_str(),
                    "care report: due, but this node has no SMTP relay configured — \
                     nothing sent; the period stays open"
                );
                continue;
            }
            let to_addr = self.care_report_recipient(&detail).await;
            if to_addr.is_empty() {
                // NOT falling through to `notify_email`'s empty-recipient
                // default: that would mail the customer's report to the
                // operator and look like a success.
                tracing::warn!(
                    domain = %detail.domain,
                    hosting_id = %detail.id.as_str(),
                    "care report: due, but the site has no care report e-mail — nothing sent. \
                     Set one on the care plan; the period stays open until then"
                );
                // Leave a marker so this is visible in the PANEL, not only in
                // journalctl. A warning nobody reads is the same as no warning,
                // and this one means a customer is paying for something they
                // will never receive. One row per affected site, read back by
                // dashboard_alerts in a single query.
                let _ = hyperion_state::hosting_kv::set(
                    &self.pool,
                    detail.id.as_str(),
                    CARE_REPORT_BLOCKED_KEY,
                    &detail.domain,
                    now_secs(),
                )
                .await;
                continue;
            }

            let report = match self
                .care_report_build(HostingSelector::Id(detail.id.clone()), from, to)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(domain = %detail.domain, error = %e, "care report: build failed; the period stays open");
                    continue;
                }
            };
            if report.is_entirely_unmeasured_for(omit) {
                // Six "not measured" lines is a true statement and a
                // terrible invoice attachment, and it almost always means
                // the report was assembled somewhere the data isn't.
                tracing::warn!(
                    domain = %detail.domain,
                    hosting_id = %detail.id.as_str(),
                    "care report: due, but not one metric could be measured — nothing sent. \
                     Is this the node that owns the site, and is any package feature actually on? \
                     The period stays open"
                );
                continue;
            }
            // The catalogue is the SITE's (its language), so whether the
            // operator's wording applies is decided per site too.
            let cat = self.letter_catalog_for(&detail.id).await;
            let letter = letter_origin_with(&body_template, &cat, CARE_FRAME_IDS);
            let (subject, body) = care_report_render_full_omitting(
                &cat,
                &report,
                &detail.domain,
                &body_template,
                &subject_template,
                omit,
            );
            // Fourth guard, on exactly the terms of the three above. The
            // marker is BOTH "already reported" and the next period's start,
            // so consuming it on a message the relay refused does not delay
            // the report — it deletes those days: the customer never gets
            // this month and the next report begins after it.
            if !self
                .notify_email(
                    &to_addr,
                    &subject,
                    &body,
                    Some(detail.id.as_str()),
                    CARE_REPORT_EMAIL_KIND,
                )
                .await
            {
                tracing::warn!(
                    domain = %detail.domain,
                    hosting_id = %detail.id.as_str(),
                    to = %to_addr,
                    "care report: due, but the relay refused it — nothing sent. \
                     The relay's own message is in the site's Emails tab; \
                     the period stays open"
                );
                continue;
            }
            self.care_report_mark_reported(&detail.id, to).await;
            tracing::info!(
                domain = %detail.domain,
                cadence = %cadence,
                period_days = (to - from) / 86_400,
                letter = letter,
                "care report sent"
            );
            sent += 1;
        }
        Ok(sent)
    }

    /// What this hosting's ACTIVE packages add up to for reporting, and
    /// when that entitlement began.
    ///
    /// The cadence uses the package layer's own fold, so it agrees with
    /// the drift tick by construction. `started_at` is the earliest
    /// activation that actually sells a report, and it is the first
    /// period's start for a site that has never had one: the first report
    /// runs from the day the customer started paying, not from an invented
    /// "one cadence ago".
    pub(super) async fn care_report_entitlement(
        &self,
        hosting_id: &HostingId,
    ) -> (ReportCadence, Option<i64>, ReportOmit) {
        // In force only: a plan waiting for its start date entitles the site
        // to nothing yet, and its start date must not pull the first period
        // into the future.
        let rows = match packages::list_in_force_for_hosting(&self.pool, hosting_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(hosting_id = %hosting_id.as_str(), error = %e, "care report: read held failed");
                return (ReportCadence::Leave, None, ReportOmit::NONE);
            }
        };
        let mut cadence = ReportCadence::Leave;
        let mut started: Option<i64> = None;
        // Only a plan that SELLS a report has a say in what the report holds.
        let mut omits: Vec<ReportOmit> = Vec::new();
        for row in rows {
            let c = row.features.report_cadence;
            cadence = cadence.combine(c);
            if report_cadence_secs(c).is_some() {
                // The operator's start date when there is one — a customer who
                // started paying on the 1st and was entered on the 5th is
                // reported on from the 1st.
                let from = row.valid_from.unwrap_or(row.activated_at);
                started = Some(started.map_or(from, |s: i64| s.min(from)));
                omits.push(ReportOmit::parse(&row.report_omit));
            }
        }
        (cadence, started, ReportOmit::fold_sites(omits))
    }

    /// The half-open period the next report covers, `[from, now)`.
    ///
    /// `from`, in priority order:
    ///   1. the end of the last period actually REPORTED. Periods are
    ///      therefore contiguous: nothing is ever counted twice, and
    ///      nothing between two reports is lost because a tick was missed.
    ///   2. the moment the site started paying for reports.
    ///   3. one cadence back. Reachable ONLY from the operator's preview /
    ///      send-now on a site holding no package at all — the tick
    ///      iterates activations, so case 2 always applies there. This is
    ///      the "now minus 30 days" that must never drive a scheduled
    ///      report, and it does not.
    pub(super) async fn care_report_period(
        &self,
        hosting_id: &HostingId,
        cadence: ReportCadence,
        started_at: Option<i64>,
        now: i64,
    ) -> (i64, i64) {
        let marker = hyperion_state::hosting_kv::get(
            &self.pool,
            hosting_id.as_str(),
            CARE_REPORT_KV_PERIOD_END,
        )
        .await
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<i64>().ok());
        let from = marker.or(started_at).unwrap_or_else(|| {
            now - report_cadence_secs(cadence).unwrap_or(CARE_REPORT_FALLBACK_SECS)
        });
        // A marker ahead of `now` (clock stepped backwards, or a restored
        // database) would otherwise produce a reversed window that reads as
        // a period in which nothing at all happened.
        (from.min(now), now)
    }

    /// Record that everything up to `period_end` has been reported. This
    /// is what a restart reads, so the same period can't be mailed twice,
    /// and it is where the next period begins.
    ///
    /// Written only once the relay has ACCEPTED the message. It used to be
    /// written after every attempt, arguing that a rejection should cost
    /// that one report rather than re-send it every hour until the relay
    /// recovers. That reasoning was wrong, and it contradicted the guards
    /// in the tick (no relay / no recipient / nothing measurable), which
    /// all leave the period open on purpose: this key is ALSO where the
    /// next period starts, so consuming it on a failed send does not
    /// re-send less — it drops the days entirely. A retry costs at worst a
    /// duplicate letter; a consumed period is a month the customer paid
    /// for and can now never be told about.
    pub(super) async fn care_report_mark_reported(&self, hosting_id: &HostingId, period_end: i64) {
        if let Err(e) = hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id.as_str(),
            CARE_REPORT_KV_PERIOD_END,
            &period_end.to_string(),
            now_secs(),
        )
        .await
        {
            // Losing this marker means the next tick re-reports the same
            // period — duplicate mail, never a gap.
            tracing::warn!(
                hosting_id = %hosting_id.as_str(),
                error = %e,
                "care report: sent, but the period marker could not be stored — \
                 the next tick may repeat this report"
            );
        }
    }

    /// Where this site's care report goes: the addresses saved on the care
    /// plan (`care_report_recipients`), comma-joined. Deliberately NOT the
    /// expiry `owner_email` — the report and the expiry warnings are
    /// different mail for different readers — and deliberately no
    /// cluster-wide fallback, see `care_report_send`. Empty when none is set.
    pub(super) async fn care_report_recipient(&self, detail: &HostingDetail) -> String {
        let raw = hyperion_state::hosting_kv::get(
            &self.pool,
            detail.id.as_str(),
            CARE_REPORT_RECIPIENTS_KV_KEY,
        )
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        parse_recipient_list(&raw).join(", ")
    }
}

/// `hosting_kv` key written when a care report came due and could not be
/// sent for want of a recipient. Read back by the dashboard so the failure
/// is visible where operators look, not only in the journal.
pub(super) const CARE_REPORT_BLOCKED_KEY: &str = "care_report_blocked";

// ─── the care report ────────────────────────────────────────────────

/// `hosting_kv` key holding the END of the last period a care report was
/// actually sent for.
///
/// Written only after a mail goes out, which makes it two things at once:
/// the "already sent" marker a restart reads (so nobody gets the same
/// report twice), and the start of the NEXT period (so a tick the node
/// slept through widens the next report instead of silently dropping the
/// days in between).
pub(super) const CARE_REPORT_KV_PERIOD_END: &str = "care_report_period_end";

/// `email_log` / audit label for care reports, so the Emails tab can show
/// what a site's customer was actually sent.
pub(super) const CARE_REPORT_EMAIL_KIND: &str = "care_report";
/// Kind tag for the expiry warning. A sibling of the care report: both are
/// complete CUSTOMER letters, which is what exempts them from the generic
/// operator-alert wrapper in `notify_email`.
pub(super) const EXPIRY_EMAIL_KIND: &str = "expiry";

/// Period length used when a hosting has no entitlement and no history at
/// all — i.e. an operator previewing the report on a site that holds no
/// package. Never reached by the scheduled tick; see `care_report_period`.
pub(super) const CARE_REPORT_FALLBACK_SECS: i64 = 30 * 86_400;

/// Seconds in one report cadence, or `None` when the cadence sends
/// nothing (`Leave` = no package has an opinion, `Off` = pinned off).
///
/// Fixed-length periods rather than calendar months on purpose: the
/// `hosting_kv` marker records where each period actually ENDED, so
/// periods stay contiguous whatever the step is. All a 30-day "month"
/// costs is that the mail slides a few days across a year.
pub(super) fn report_cadence_secs(c: ReportCadence) -> Option<i64> {
    match c {
        ReportCadence::Leave | ReportCadence::Off => None,
        ReportCadence::Weekly => Some(7 * 86_400),
        ReportCadence::Monthly => Some(30 * 86_400),
        ReportCadence::Quarterly => Some(91 * 86_400),
    }
}

/// Subject + plain-text body of one care report, in CZECH.
///
/// PURE — no database, no SMTP, no clock. Everything it says comes out of
/// the `CareReport` it was handed, which is what makes the wording
/// testable and what keeps the honesty rule enforceable: a section is
/// `None` because `hyperion_state::reports` could not measure it, and the
/// only thing this function is allowed to do about that is SAY SO. It
/// must never turn an absent measurement into a zero, a percentage or a
/// clean bill of health.
///
/// `domain` is passed separately rather than read off the report so the
/// renderer can be exercised without building a hosting; at every call
/// site it is `report.domain`.
pub fn care_report_render(
    cat: &LetterCatalog,
    report: &CareReport,
    domain: &str,
) -> (String, String) {
    // "" = the built-in letter for `cat`'s language, which is exactly what
    // this function is.
    care_report_render_with(cat, report, domain, "")
}

/// Validate an operator-picked report range and clamp its end to `now`.
///
/// Half-open `[from, to)` in UNIX seconds, like every other report period.
/// The end is clamped rather than refused so "to: today" works at any hour —
/// a report cannot describe time that has not happened. What is left must
/// still be a real window: a reversed or empty range would render as a
/// period in which nothing at all happened, which reads as a clean bill of
/// health rather than as a typo.
pub(crate) fn care_report_custom_range(
    (from, to): (i64, i64),
    now: i64,
) -> Result<(i64, i64), RpcError> {
    let to = to.min(now);
    if from < 0 || from >= to {
        return Err(RpcError::Validation {
            message: "the report range must start before it ends, and before now".into(),
        });
    }
    Ok((from, to))
}

/// The sample a Settings preview shows for each `{placeholder}`, as
/// `(name, value)` pairs ready to hand to the page.
///
/// Produced by the SAME `care_section_*` functions the customer's letter
/// goes through, because the preview's whole job is to show the operator
/// what their wording will do to real sections. Hand-copying the strings
/// into the page's JavaScript is what this replaces: they had already
/// drifted, and an operator tuning a sentence was reading text no
/// customer would ever receive.
///
/// Availability is deliberately left UNMEASURED. It is the case the
/// operator most needs to see inside their own wording — a letter that
/// reads well with a percentage in it can read absurdly with "not
/// monitored" in the same slot, and finding that out from a customer is
/// too late.
pub fn care_report_preview_fields(cat: &LetterCatalog) -> Vec<(&'static str, String)> {
    // 1–30 Jun 2026, half-open. Fixed, so the preview never depends on
    // the clock and two operators comparing screens see the same letter.
    let from = 1_780_272_000; // 2026-06-01 00:00 UTC
    let to = from + 30 * 86_400;
    let report = CareReport {
        attacks_blocked: Some(12),
        attacks_covered_since: None,
        updates_applied: Some(3),
        usage: Some(CareUsage {
            bw_in_bytes: Some(2_000_000),
            bw_out_bytes: 34_500_000,
            requests: 12_345,
            disk_peak_bytes: 1_200_000_000,
            days_counted: 30,
            days_in_period: 30,
        }),
        // See the doc comment: unmeasured on purpose.
        uptime: None,
        backups: Some(CareBackups {
            taken: 30,
            failed: 1,
            last_success_at: Some(to - 3600),
        }),
        integrity: Some(CareIntegrity {
            scanned_at: to - 3600,
            checksums_ran: true,
            malware_scan_ran: true,
            ..Default::default()
        }),
        performance: Some(hyperion_types::CarePerformance {
            checked_at: to - 3600,
            pages_checked: 8,
            pages_ok: 8,
            findings_error: 0,
            findings_warn: 1,
            median_ttfb_ms: 210,
            slowest_ttfb_ms: 480,
            html_bytes: 240_000,
            cwv: Some(hyperion_types::CwvResult {
                measured_at: to - 3600,
                source: "psi".into(),
                strategy: "mobile".into(),
                field: Some(hyperion_types::CwvMetrics {
                    lcp_ms: Some(2400),
                    cls_x1000: Some(60),
                    inp_ms: Some(180),
                    ..Default::default()
                }),
                perf_score: Some(88),
                ..Default::default()
            }),
        }),
        ..CareReport::empty(HostingId("preview".into()), "example.com".into(), from, to)
    };
    let (_, _, fields) = care_report_parts(cat, &report, "example.com");
    fields
}

/// Subject, section strings and the full placeholder set for one report.
/// Split out so [`care_report_preview_fields`] cannot diverge from what
/// [`care_report_render_with`] actually sends.
pub(super) fn care_report_parts(
    cat: &LetterCatalog,
    report: &CareReport,
    domain: &str,
) -> (String, [String; 8], Vec<(&'static str, String)>) {
    care_report_parts_omitting(cat, report, domain, ReportOmit::NONE)
}

/// [`care_report_parts`] for a plan that leaves some sections out.
///
/// A section the plan leaves out renders as the EMPTY string, and its bare
/// values (`{attacks_count}`, `{uptime_pct}`, …) as the same dash an
/// unmeasured one gets: the customer did not buy it, so the letter has no
/// figure to quote, and a custom sentence wrapped around one must not
/// reintroduce what the plan left out.
pub(super) fn care_report_parts_omitting(
    cat: &LetterCatalog,
    report: &CareReport,
    domain: &str,
    omit: ReportOmit,
) -> (String, [String; 8], Vec<(&'static str, String)>) {
    let days = care_days_spanned(report.period_start, report.period_end);
    // The period is half-open, so the last day INSIDE it is `end - 1`.
    let last_day = (report.period_end - 1).max(report.period_start);
    let from_str = report_date(cat, report.period_start);
    let to_str = report_date(cat, last_day);
    // Day count carries its own unit word so a template can never render
    // "1 days", and so `{days}` alone reproduces the default's "(30 days)".
    let days_str = format!("{days} {}", cat.plural("unit_day", days));
    let days_count = days.to_string();
    let start_iso = iso_date(cat, report.period_start);
    let end_iso = iso_date(cat, last_day);
    let mut parts = [
        care_section_attacks(cat, report.attacks_blocked, report.attacks_covered_since),
        care_section_updates(cat, report.updates_applied),
        care_section_usage(cat, report.usage.as_ref()),
        care_section_uptime(cat, report.uptime.as_ref()),
        care_section_backups(cat, report.backups.as_ref()),
        care_section_integrity(cat, report.integrity.as_ref()),
        care_section_performance(cat, report.performance.as_ref()),
        care_section_service(cat, report.service_work.as_ref()),
    ];
    let mut fields = vec![
        ("domain", domain.to_string()),
        ("period_start", from_str),
        // Inclusive last day of the period, same as the default letter.
        ("period_end", to_str),
        ("days", days_str),
        // Rendered sections, unmeasured wording included. See above.
        ("attacks", parts[0].clone()),
        ("updates", parts[1].clone()),
        ("traffic", parts[2].clone()),
        ("uptime", parts[3].clone()),
        ("backups", parts[4].clone()),
        ("integrity", parts[5].clone()),
        // Render + speed + Core Web Vitals.
        ("performance", parts[6].clone()),
        // What a PERSON did. Not a measurement, and the section says so in
        // every branch — see `care_section_service`.
        ("service", parts[7].clone()),
        // ── Bare values ────────────────────────────────────────────────
        //
        // The six placeholders above each expand to a whole SECTION —
        // heading, figure and the paragraph explaining it. These carry the
        // MEASUREMENT and nothing else, so an operator writing their own
        // sentence around one is not fighting a paragraph they did not
        // write.
        //
        // An em dash, never a zero, when something was not measured. The
        // whole report is built on not claiming a figure it does not have —
        // "0 attacks blocked" on a site nobody was watching is exactly the
        // lie the sections go to such lengths to avoid, and a bare-value
        // placeholder must not reintroduce it.
        ("days_count", days_count),
        ("period_start_iso", start_iso),
        ("period_end_iso", end_iso),
        ("attacks_count", opt_num(cat, report.attacks_blocked)),
        ("updates_count", opt_num(cat, report.updates_applied)),
        (
            "traffic_requests",
            report
                .usage
                .as_ref()
                .map(|u| cat.group_int(u.requests))
                .unwrap_or_else(|| UNMEASURED.to_string()),
        ),
        (
            // The SAME units the `{traffic}` section quotes. A bare value
            // in MiB beside a section in MB is two different numbers for
            // one measurement in one letter.
            "traffic_sent",
            report
                .usage
                .as_ref()
                .map(|u| customer_bytes(cat, u.bw_out_bytes))
                .unwrap_or_else(|| UNMEASURED.to_string()),
        ),
        (
            "traffic_received",
            report
                .usage
                .as_ref()
                .and_then(|u| u.bw_in_bytes)
                .map(|n| customer_bytes(cat, n))
                .unwrap_or_else(|| UNMEASURED.to_string()),
        ),
        (
            "disk_peak",
            report
                .usage
                .as_ref()
                .map(|u| customer_bytes(cat, u.disk_peak_bytes))
                .unwrap_or_else(|| UNMEASURED.to_string()),
        ),
        (
            "uptime_pct",
            match report.uptime.as_ref() {
                // Zero samples IS "not monitored" — dividing by it would
                // print a confident 100 %.
                Some(u) if u.samples > 0 => cat.decimal(&format!(
                    "{:.2}",
                    (u.successes as f64 / u.samples as f64) * 100.0
                )),
                _ => UNMEASURED.to_string(),
            },
        ),
        (
            "backups_count",
            report
                .backups
                .as_ref()
                .map(|b| cat.group_int(b.taken))
                .unwrap_or_else(|| UNMEASURED.to_string()),
        ),
        (
            "backups_failed",
            report
                .backups
                .as_ref()
                .map(|b| cat.group_int(b.failed))
                .unwrap_or_else(|| UNMEASURED.to_string()),
        ),
        (
            "backup_last_iso",
            report
                .backups
                .as_ref()
                .and_then(|b| b.last_success_at)
                .map(|ts| iso_date(cat, ts))
                .unwrap_or_else(|| UNMEASURED.to_string()),
        ),
    ];
    // The plan's choice, applied last so it covers every placeholder in one
    // place instead of being threaded through each of the twenty tuples above.
    if !omit.is_empty() {
        for (i, sec) in ReportSection::ALL.into_iter().enumerate() {
            if omit.contains(sec) {
                parts[i].clear();
            }
        }
        for (name, value) in fields.iter_mut() {
            if let Some(sec) = ReportSection::parse(name) {
                if omit.contains(sec) {
                    value.clear();
                }
            } else if let Some(sec) = bare_value_section(name) {
                if omit.contains(sec) {
                    *value = UNMEASURED.to_string();
                }
            }
        }
    }
    // The catalogue subject takes every placeholder the body does — the same
    // set the old `[notifications] care_report_subject_template` was given —
    // so wording moved from that template into `care.subject` (Settings →
    // Customer letters → "Move into the editor") renders exactly as before.
    // Rendered after the plan's choice, like the body.
    let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let subject = cat.render("care.subject", &pairs);
    (subject, parts, fields)
}

/// Which section a bare-value placeholder belongs to, so a plan that leaves the
/// section out takes its figures with it.
pub(super) fn bare_value_section(name: &str) -> Option<ReportSection> {
    match name {
        "attacks_count" => Some(ReportSection::Attacks),
        "updates_count" => Some(ReportSection::Updates),
        "traffic_requests" | "traffic_sent" | "traffic_received" | "disk_peak" => {
            Some(ReportSection::Traffic)
        }
        "uptime_pct" => Some(ReportSection::Uptime),
        "backups_count" | "backups_failed" | "backup_last_iso" => Some(ReportSection::Backups),
        _ => None,
    }
}

/// Collapse the blank lines a left-out section leaves behind.
///
/// The built-in letter separates sections with one blank line, so an empty
/// `{attacks}` between two of them would print two. Only ever applied to a
/// letter that actually left something out, and line-based so a template saved
/// with CRLF endings keeps them. At most one blank line in a row survives.
pub(super) fn collapse_blank_runs(body: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut prev_blank = false;
    for line in body.split('\n') {
        let blank = line.trim().is_empty();
        if blank && prev_blank {
            continue;
        }
        prev_blank = blank;
        out.push(line);
    }
    out.join("\n")
}

pub fn care_report_render_with(
    cat: &LetterCatalog,
    report: &CareReport,
    domain: &str,
    body_template: &str,
) -> (String, String) {
    care_report_render_with_omitting(cat, report, domain, body_template, ReportOmit::NONE)
}

/// [`care_report_render_with`] for a plan that leaves sections out of the
/// letter. Left-out sections are never mentioned — not as a section, not as a
/// bare value, and not in the "we could not measure …" disclosure, because the
/// customer did not buy them and "not measured" would imply they should have
/// been.
pub fn care_report_render_with_omitting(
    cat: &LetterCatalog,
    report: &CareReport,
    domain: &str,
    body_template: &str,
    omit: ReportOmit,
) -> (String, String) {
    let (subject, _, fields) = care_report_parts_omitting(cat, report, domain, omit);
    // Empty means "the built-in letter", and the built-in letter is now a
    // catalogue string like every other word in it — so a Czech install
    // that has customised nothing still sends a Czech report. The custom
    // and default paths are one path, which is why the disclosure note
    // below cannot be reached by only one of them.
    let template = if body_template.trim().is_empty() {
        cat.get("care.body").to_string()
    } else {
        body_template.to_string()
    };
    let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut body = render_template(&template, &pairs);
    if !omit.is_empty() {
        body = collapse_blank_runs(&body);
    }
    body.push_str(&care_omitted_unmeasured_note(cat, report, &template, omit));
    (subject, body)
}

/// [`care_report_render_with`], with the subject line editable too.
///
/// This letter goes to a paying customer, and until now only its body could be
/// changed — so an operator who translated it sent Czech prose under an English
/// subject, with no field anywhere to fix it. The subject takes the same
/// placeholders as the body; empty keeps the catalogue's, which is the built-in
/// subject in the letter's own language.
pub fn care_report_render_full(
    cat: &LetterCatalog,
    report: &CareReport,
    domain: &str,
    body_template: &str,
    subject_template: &str,
) -> (String, String) {
    care_report_render_full_omitting(
        cat,
        report,
        domain,
        body_template,
        subject_template,
        ReportOmit::NONE,
    )
}

/// [`care_report_render_full`] for a plan that leaves sections out. This is the
/// path the scheduled send, the preview and send-now all share, so what the
/// operator reads is what the customer receives.
pub fn care_report_render_full_omitting(
    cat: &LetterCatalog,
    report: &CareReport,
    domain: &str,
    body_template: &str,
    subject_template: &str,
    omit: ReportOmit,
) -> (String, String) {
    let (built_in_subject, body) =
        care_report_render_with_omitting(cat, report, domain, body_template, omit);
    if subject_template.trim().is_empty() {
        return (built_in_subject, body);
    }
    let (_, _, fields) = care_report_parts_omitting(cat, report, domain, omit);
    let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    (render_template(subject_template, &pairs), body)
}

/// The one thing a custom letter must not be allowed to do: quietly drop
/// a section that would have said "we did not measure this".
///
/// Omitting a MEASURED section is an editorial choice and stays the
/// operator's — a shorter letter is still a true one. Omitting an
/// UNMEASURED one is different in kind: the disclosure disappears, and the
/// letter's own preamble ("where something was not being measured, we say
/// so") is still there promising otherwise, because the operator started
/// from the built-in letter and deleted the section that read badly.
/// Availability is the one they delete, and it is the one that matters.
///
/// So the disclosure is re-attached at the end — in the letter's own
/// language, which is the point of the catalogue: a Czech report used to
/// get this paragraph bolted on in English no matter how thoroughly it had
/// been translated.
pub(super) fn care_omitted_unmeasured_note(
    cat: &LetterCatalog,
    report: &CareReport,
    body_template: &str,
    omit: ReportOmit,
) -> String {
    let unmeasured: Vec<&str> = [
        (
            "attacks",
            report.attacks_blocked.is_none(),
            "care.unmeasured.attacks",
        ),
        (
            "updates",
            report.updates_applied.is_none(),
            "care.unmeasured.updates",
        ),
        ("traffic", report.usage.is_none(), "care.unmeasured.traffic"),
        ("uptime", report.uptime.is_none(), "care.unmeasured.uptime"),
        (
            "backups",
            report.backups.is_none(),
            "care.unmeasured.backups",
        ),
        (
            "integrity",
            report.integrity.is_none(),
            "care.unmeasured.integrity",
        ),
        // Unreadable, not merely un-ticked: an empty checklist is a fact the
        // letter states out loud, so only a record we could not read at all
        // belongs in the "we cannot say" list.
        (
            "service",
            report.service_work.is_none(),
            "care.unmeasured.service",
        ),
    ]
    .into_iter()
    .filter(|(placeholder, is_unmeasured, _)| {
        // A section the PLAN leaves out is not "unmeasured": nobody promised
        // it, so the letter has nothing to disclose about it.
        let plan_sends = ReportSection::parse(placeholder).map_or(true, |sec| omit.sends(sec));
        *is_unmeasured && plan_sends && !body_template.contains(&format!("{{{placeholder}}}"))
    })
    .map(|(_, _, id)| cat.get(id))
    .collect();
    if unmeasured.is_empty() {
        return String::new();
    }
    let n = unmeasured.len() as i64;
    cat.render(
        "care.unmeasured.note",
        &[
            ("list", &unmeasured.join(cat.get("list_sep"))),
            ("pronoun", cat.plural("care.unmeasured.pronoun", n)),
        ],
    )
}

/// What a bare-value placeholder prints when the thing was never measured.
///
/// Not "0", and not an English phrase. A zero would be a claim the report has
/// no evidence for — the whole letter is built on refusing that — and a phrase
/// would put one language's word into a letter written in another. A dash is a
/// fact in any language: the operator sees it in the preview and writes their
/// own sentence around it.
pub(super) const UNMEASURED: &str = "—";

/// `hosting_kv` key holding the monthly service checklist JSON.
pub const CARE_CHECKS_KV_KEY: &str = "care_service_checks";
/// Care report recipients (comma-separated), set on the care plan card.
pub const CARE_REPORT_RECIPIENTS_KV_KEY: &str = "care_report_recipients";

/// A count, or [`UNMEASURED`] when there is none.
pub(super) fn opt_num(cat: &LetterCatalog, v: Option<i64>) -> String {
    v.map(|n| cat.group_int(n))
        .unwrap_or_else(|| UNMEASURED.to_string())
}

/// `YYYY-MM-DD`. Month names are a language; digits are not, so a letter in
/// any language gets a date it can use without translating anything.
pub(super) fn iso_date(cat: &LetterCatalog, ts: i64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| cat.get("date_unknown").to_string())
}

/// Blocked attacks. `None` is the case the database cannot produce on its
/// own — the caller sets it when the ban scanner was switched off — and it
/// is exactly why zero must not be printed there.
///
/// Which of the four wordings is used is decided HERE, from the data. The
/// operator owns every word of all four and none of that decision, so a
/// translated letter can say "nesledováno" but can never say "0".
pub(super) fn care_section_attacks(
    cat: &LetterCatalog,
    blocked: Option<i64>,
    covered_since: Option<i64>,
) -> String {
    // Protection started mid-period: the count is real but it is not a
    // period total, and "0" is emphatically not "a quiet month". Both
    // wordings below would otherwise assert coverage we cannot evidence.
    if let (Some(n), Some(since)) = (blocked, covered_since) {
        return cat.render(
            "care.attacks.since",
            &[
                ("count", &cat.group_int(n)),
                ("since", &report_date(cat, since)),
            ],
        );
    }
    match blocked {
        None => cat.get("care.attacks.none").to_string(),
        Some(0) => cat.get("care.attacks.zero").to_string(),
        Some(n) => cat.render("care.attacks.some", &[("count", &cat.group_int(n))]),
    }
}

/// Applied updates. Two things the copy has to say out loud: the number
/// covers plugins and themes ONLY (WordPress core has no durable record
/// to count), and an audit log that does not span the period yields
/// "not determined" rather than a partial total dressed up as a whole one.
pub(super) fn care_section_updates(cat: &LetterCatalog, applied: Option<i64>) -> String {
    match applied {
        None => cat.get("care.updates.none").to_string(),
        Some(0) => cat.get("care.updates.zero").to_string(),
        Some(n) => cat.render(
            "care.updates.some",
            &[
                ("count", &cat.group_int(n)),
                ("unit", cat.plural("unit_update", n)),
            ],
        ),
    }
}

/// Traffic and footprint. Carries its own coverage caveat: a month with a
/// four-day sampling gap says so instead of presenting 26 days of traffic
/// as a month.
pub(super) fn care_section_usage(cat: &LetterCatalog, usage: Option<&CareUsage>) -> String {
    let Some(u) = usage else {
        return cat.get("care.traffic.none").to_string();
    };
    let mut out = cat.render(
        "care.traffic.head",
        &[
            ("requests", &cat.group_int(u.requests)),
            ("unit", cat.plural("unit_request", u.requests)),
            ("sent", &customer_bytes(cat, u.bw_out_bytes)),
        ],
    );
    // Inbound bytes need a log format the stock nginx config doesn't have,
    // so a zero there is ambiguous — and `reports::usage` hands us `None`
    // rather than letting us print "0 B received" for a live site.
    match u.bw_in_bytes {
        Some(n) => out.push_str(&cat.render(
            "care.traffic.received",
            &[("received", &customer_bytes(cat, n))],
        )),
        None => out.push_str(cat.get("care.traffic.received_unknown")),
    }
    out.push_str(&cat.render(
        "care.traffic.disk_peak",
        &[("disk", &customer_bytes(cat, u.disk_peak_bytes))],
    ));
    // "was higher" would state a fact about days we just said we did not
    // measure — the site may have served nothing on them. The partial
    // wording keeps that a possibility.
    let id = if u.is_complete() {
        "care.traffic.complete"
    } else {
        "care.traffic.partial"
    };
    out.push_str(&cat.render(
        id,
        &[
            ("counted", &cat.group_int(u.days_counted)),
            ("total", &cat.group_int(u.days_in_period)),
            ("unit", cat.plural("unit_day", u.days_in_period)),
        ],
    ));
    out
}

/// Uptime. THE section this whole design exists for: with no samples
/// there is no percentage to print, and "100 %" for a site nobody
/// monitored is the exact lie the report must never tell.
pub(super) fn care_section_uptime(cat: &LetterCatalog, uptime: Option<&CareUptime>) -> String {
    let Some(u) = uptime else {
        return cat.get("care.uptime.none").to_string();
    };
    // `samples > 0` is guaranteed by the assembler (zero samples arrive as
    // `None` above), so this can only ever be `Some`.
    let Some(ratio) = u.success_ratio_x100() else {
        return cat.get("care.uptime.none").to_string();
    };
    let failures = u.failures();
    let pct = pct_x100_str(cat, ratio);
    let samples = cat.group_int(u.samples);
    let mut out = if failures == 0 {
        cat.render(
            "care.uptime.perfect",
            &[
                ("pct", &pct),
                ("samples", &samples),
                ("unit", cat.plural("unit_check", u.samples)),
            ],
        )
    } else {
        cat.render(
            "care.uptime.failures",
            &[
                ("pct", &pct),
                ("samples", &samples),
                ("unit", cat.plural("unit_check", u.samples)),
                ("failures", &cat.group_int(failures)),
                ("failures_unit", cat.plural("unit_check", failures)),
            ],
        )
    };
    // A percentage computed from a subset of the period is a percentage OF
    // that subset, and the days with no checks at all are exactly the days
    // most likely to have been an outage — the agent being down is why no
    // check was recorded. Saying so is the difference between a measured
    // score and a flattering one.
    if !u.is_complete() {
        out.push_str(&cat.render(
            "care.uptime.partial",
            &[
                ("counted", &cat.group_int(u.days_counted)),
                ("total", &cat.group_int(u.days_in_period)),
                ("total_unit", cat.plural("unit_day", u.days_in_period)),
                ("counted_unit", cat.plural("unit_day", u.days_counted)),
            ],
        ));
    }
    out
}

/// Backups. Three genuinely different states, and the middle one is the
/// alarming one: a site that DOES take backups and took none this period
/// must not read the same as a site that never had any.
pub(super) fn care_section_backups(cat: &LetterCatalog, backups: Option<&CareBackups>) -> String {
    let Some(b) = backups else {
        return cat.get("care.backups.none").to_string();
    };
    let mut out = if b.taken == 0 {
        cat.get("care.backups.zero").to_string()
    } else {
        let mut s = cat.render(
            "care.backups.some",
            &[
                ("count", &cat.group_int(b.taken)),
                ("unit", cat.plural("unit_copy", b.taken)),
            ],
        );
        // Only ever a time INSIDE the period: the report must not reach
        // backwards for a comforting older date.
        if let Some(ts) = b.last_success_at {
            s.push_str(&cat.render("care.backups.last", &[("when", &report_datetime(cat, ts))]));
        }
        s
    };
    if b.failed > 0 {
        out.push_str(&cat.render(
            "care.backups.failed",
            &[("count", &cat.group_int(b.failed))],
        ));
    }
    out
}

/// File integrity + malware. "Clean" requires BOTH halves to have run —
/// zero malware hits from a scanner that was never installed means "not
/// looked for", and the copy has to say which.
pub(super) fn care_section_integrity(
    cat: &LetterCatalog,
    integrity: Option<&CareIntegrity>,
) -> String {
    let Some(i) = integrity else {
        return cat.get("care.integrity.none").to_string();
    };
    let when = report_date(cat, i.scanned_at);
    let findings = i.total_findings();
    let mut out = if i.is_clean() {
        cat.render("care.integrity.clean", &[("when", &when)])
    } else if findings == 0 {
        cat.render("care.integrity.partial", &[("when", &when)])
    } else {
        let mut what: Vec<String> = Vec::new();
        if i.core_issues > 0 {
            what.push(cat.render(
                "care.integrity.what_core",
                &[("count", &cat.group_int(i.core_issues))],
            ));
        }
        if i.plugin_issues > 0 {
            what.push(cat.render(
                "care.integrity.what_plugin",
                &[("count", &cat.group_int(i.plugin_issues))],
            ));
        }
        if i.malware_hits > 0 {
            what.push(cat.render(
                "care.integrity.what_malware",
                &[("count", &cat.group_int(i.malware_hits))],
            ));
        }
        cat.render(
            "care.integrity.findings",
            &[
                ("count", &cat.group_int(findings)),
                ("unit", cat.plural("unit_finding", findings)),
                ("when", &when),
                ("what", &what.join(cat.get("list_sep"))),
            ],
        )
    };
    // Which half did NOT run is information the customer is owed, in every
    // one of the three branches above.
    if !i.checksums_ran {
        out.push_str(cat.get("care.integrity.no_checksums"));
    }
    if !i.malware_scan_ran {
        out.push_str(cat.get("care.integrity.no_malware_scan"));
    }
    out
}

/// The monthly service check. The one section that reports what a PERSON
/// did rather than what was measured, and every wording it can use says so.
///
/// Three states that must stay distinct: the record could not be read, the
/// record is empty, and the record says what happened. Collapsing the first
/// two would turn "we do not know" into "we did not do it", and collapsing
/// the last two would turn "we did not do it" into silence.
/// The performance section: render + server speed (from the site check) and
/// Core Web Vitals (from the configured source). `None` when nothing was
/// measured, which the caller passes straight through from `care_performance`.
pub(super) fn care_section_performance(
    cat: &LetterCatalog,
    perf: Option<&hyperion_types::CarePerformance>,
) -> String {
    let Some(p) = perf else {
        return cat.get("care.performance.none").to_string();
    };
    let mut out = cat.get("care.performance.header").to_string();
    if p.has_site_check() {
        // "OK — everything rendered" only when there is genuinely nothing to
        // report: no errors, no warnings, and every page fetched answered. A
        // 404 behind a menu item or a missing image is a `warn`, and claiming
        // "every one loaded, with its links and images resolving" over the top
        // of one is the flattering half-truth the whole report exists to avoid.
        let all_clean =
            p.findings_error == 0 && p.findings_warn == 0 && p.pages_ok == p.pages_checked;
        if all_clean {
            out.push_str(&cat.render(
                "care.performance.render_ok",
                &[("pages", &cat.group_int(p.pages_checked))],
            ));
        } else {
            // Count everything not clean — a warn is still a problem worth the
            // customer's eye, just not a page-down one. `findings_error +
            // findings_warn` ALREADY counts each broken page once (site_check
            // pushes exactly one `page` finding per non-OK page — a home/sitemap
            // page that errors or is missing), alongside the broken link/image
            // findings. Adding `(pages_checked - pages_ok)` on top counted every
            // broken page twice and could print more "problems" than pages
            // fetched — the flattering-in-reverse inflation this report avoids.
            let problems = p.findings_error + p.findings_warn;
            out.push_str(&cat.render(
                "care.performance.render_issues",
                &[
                    ("errors", &cat.group_int(problems)),
                    ("pages", &cat.group_int(p.pages_checked)),
                ],
            ));
        }
        // The server-speed line needs a page that actually answered to time.
        // With none, `median_ttfb_ms` is a filtered-to-nothing 0, and "0 ms
        // typical" is a fabricated measured-zero — so the line is omitted.
        if p.pages_ok > 0 {
            out.push_str(&cat.render(
                "care.performance.speed",
                &[
                    ("median", &cat.group_int(p.median_ttfb_ms)),
                    ("slowest", &cat.group_int(p.slowest_ttfb_ms)),
                ],
            ));
        }
    }
    // Core Web Vitals: field if we have real-visitor data, else lab, else —
    // when a source is on but produced nothing — a plain "no data yet".
    // Field if we have real-visitor data, else lab, else — a source is on but
    // produced nothing yet — a plain "no data".
    match p.cwv.as_ref() {
        Some(cwv) if cwv.best_is_field() => {
            if let Some(m) = cwv.field.as_ref() {
                out.push_str(&cat.render(
                    "care.performance.cwv_field",
                    &[
                        ("lcp", &cwv_ms(cat, m.lcp_ms)),
                        ("cls", &cwv_cls(m)),
                        ("inp", &cwv_ms(cat, m.inp_ms)),
                    ],
                ));
            }
        }
        Some(cwv) if cwv.has_data() => {
            if let Some(m) = cwv.lab.as_ref() {
                out.push_str(
                    &cat.render(
                        "care.performance.cwv_lab",
                        &[
                            ("lcp", &cwv_ms(cat, m.lcp_ms)),
                            ("cls", &cwv_cls(m)),
                            (
                                "score",
                                &cwv.perf_score
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| UNMEASURED.into()),
                            ),
                        ],
                    ),
                );
            }
        }
        Some(_) => out.push_str(cat.get("care.performance.cwv_pending")),
        None => {}
    }
    out
}

/// A CWV millisecond value for a letter: `"2400 ms"`, or the em dash when it
/// was not reported.
pub(super) fn cwv_ms(_cat: &LetterCatalog, ms: Option<i64>) -> String {
    match ms {
        Some(v) => format!("{v} ms"),
        None => UNMEASURED.to_string(),
    }
}

/// CLS as its decimal, or the em dash.
pub(super) fn cwv_cls(m: &hyperion_types::CwvMetrics) -> String {
    m.cls_display().unwrap_or_else(|| UNMEASURED.to_string())
}

pub(super) fn care_section_service(
    cat: &LetterCatalog,
    work: Option<&hyperion_types::package::CareServiceWork>,
) -> String {
    let Some(w) = work else {
        return cat.get("care.service.unknown").to_string();
    };
    if w.is_empty() {
        return cat.get("care.service.none").to_string();
    }
    // One item per line, each preceded by the separator. The item names
    // contain commas ("forms, including that the message arrives"), so a
    // comma-joined list read as one run-on sentence with the boundaries
    // between items lost.
    let name = |ids: &[String]| -> String {
        let sep = cat.get("care.service.item_sep");
        ids.iter()
            .map(|id| format!("{sep}{}", service_item_name(cat, id, &w.labels)))
            .collect::<String>()
    };
    let done = name(&w.done);
    if w.missing.is_empty() {
        return cat.render("care.service.all", &[("done", &done)]);
    }
    cat.render(
        "care.service.partial",
        &[("done", &done), ("missing", &name(&w.missing))],
    )
}

/// What to CALL one checklist item in a customer's letter.
///
/// A built-in id is named by the letter pack, so a Czech report says it in
/// Czech. An item the operator added exists only as the label they typed —
/// there is no translation of "GDPR review" for the pack to find — so the
/// label travels with the report. Falling back to the bare id is the last
/// resort and is still better than the alternative this function exists to
/// prevent: `cat.get` on an unknown key returns the KEY, which would print
/// `care.service.item.gdpr` into a letter a customer reads.
pub(super) fn service_item_name(
    cat: &LetterCatalog,
    id: &str,
    labels: &std::collections::BTreeMap<String, String>,
) -> String {
    if hyperion_types::care_check::ServiceCheckItem::parse(id).is_some() {
        return cat.get(&format!("care.service.item.{id}")).to_string();
    }
    labels
        .get(id)
        .filter(|l| !l.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| id.to_string())
}

/// Calendar days the half-open window `[from, to)` touches.
///
/// Mirrors `hyperion_state::reports::days_spanned` so the header says the
/// same "30 days" the traffic section's coverage line does — and keeps
/// saying it for a report whose traffic section is unmeasured.
pub(super) fn care_days_spanned(from: i64, to: i64) -> i64 {
    if to <= from {
        return 0;
    }
    (to - 1).div_euclid(86_400) - from.div_euclid(86_400) + 1
}

/// Bytes for a CUSTOMER: SI steps (kB / MB / GB), because that is what
/// their connection and their invoice talk about. `human_bytes` (GiB)
/// stays as it is for the operator dashboard — two audiences, two
/// conventions, and neither should learn the other's.
pub(super) fn customer_bytes(cat: &LetterCatalog, n: i64) -> String {
    const STEPS: [(&str, i64); 3] = [("GB", 1_000_000_000), ("MB", 1_000_000), ("kB", 1_000)];
    for (label, scale) in STEPS {
        if n.abs() >= scale {
            let v = n as f64 / scale as f64;
            return cat.decimal(&format!("{v:.1} {label}"));
        }
    }
    format!("{} B", cat.group_int(n))
}

/// "30 Jun 2026" — or "30. čvn 2026". Spelled month, because a purely
/// numeric date reads as a different day depending on the reader's country,
/// and both the month names and the order they appear in come from the
/// catalogue.
pub(super) fn report_date(cat: &LetterCatalog, ts: i64) -> String {
    use chrono::Datelike;
    match chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0) {
        Some(dt) => {
            let months = cat.months();
            let m = months
                .get((dt.month() as usize).saturating_sub(1))
                .cloned()
                .unwrap_or_else(|| "???".to_string());
            cat.render(
                "date_fmt",
                &[
                    ("day", &dt.day().to_string()),
                    ("month", &m),
                    ("year", &dt.year().to_string()),
                ],
            )
        }
        // Unrepresentable timestamps can't reach a real report; saying so
        // beats printing a wrong date with total confidence.
        None => cat.get("date_unknown").to_string(),
    }
}

/// "30 Jun 2026 03:14 UTC" — the zone is spelled out because the customer
/// may not be in UTC and an unlabelled clock time would be a small lie.
pub(super) fn report_datetime(cat: &LetterCatalog, ts: i64) -> String {
    use chrono::Timelike;
    match chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0) {
        Some(dt) => cat.render(
            "date_time_fmt",
            &[
                ("date", &report_date(cat, ts)),
                ("time", &format!("{:02}:{:02}", dt.hour(), dt.minute())),
            ],
        ),
        None => cat.get("time_unknown").to_string(),
    }
}

/// Hundredths of a percent → "99.93 %", or "99,93 %".
pub(super) fn pct_x100_str(cat: &LetterCatalog, x: i64) -> String {
    cat.decimal(&format!("{}.{:02} %", x / 100, (x % 100).abs()))
}
