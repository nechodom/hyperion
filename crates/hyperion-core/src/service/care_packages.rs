//! Care packages ("balíček péče"): the catalogue, activations, and the drift
//! tick that keeps paid features on.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ================================================================
    //  Care packages ("balíček péče") — the paid entitlement layer
    // ================================================================
    //
    // Every feature a package sells already worked; each just lived
    // somewhere different (two `hosting_kv` keys, the monitor row, the
    // vhost options). What was missing was a record that the customer PAID
    // for them, and something that keeps them switched on — hence
    // activate (snapshot + apply), cancel (restore), and a tick that
    // re-asserts.
    //
    // Two rules hold throughout:
    //   * every write goes through the SAME setter the panel uses. Those
    //     setters rewrite vhosts and seed schedules; a raw column/kv write
    //     would record the promise without keeping it.
    //   * `Leave` is not `Off`. A package only ever touches a feature it
    //     explicitly forces, which is what lets two packages coexist on
    //     one hosting.
    //
    // Define no packages and none of this runs.

    pub async fn package_list(&self) -> Result<Vec<ServicePackage>, RpcError> {
        let rows = packages::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package list: {e}")))?;
        // One GROUP BY for every count, then attach by id (no N+1).
        let counts: HashMap<i64, i64> = packages::counts_active(&self.pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        Ok(rows
            .into_iter()
            .map(|r| {
                let mut w = package_row_to_wire(r);
                w.active_count = counts.get(&w.id).copied().unwrap_or(0);
                w
            })
            .collect())
    }

    pub async fn package_get(&self, id: i64) -> Result<ServicePackage, RpcError> {
        let row = packages::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package get: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "package".into(),
                id: id.to_string(),
            })?;
        let mut w = package_row_to_wire(row);
        w.active_count = packages::count_active(&self.pool, id).await.unwrap_or(0);
        Ok(w)
    }

    pub async fn package_create(&self, input: PackageInput) -> Result<ServicePackage, RpcError> {
        let validated = validate_package(input)?;
        let id = packages::insert(&self.pool, &package_input_to_new(validated), now_secs())
            .await
            // Both `name` and `slug` are UNIQUE, so the overwhelmingly
            // likely cause is a duplicate of one of them.
            .map_err(|e| RpcError::AlreadyExists {
                kind: "package".into(),
                id: e.to_string(),
            })?;
        let out = self.package_get(id).await?;
        self.append_audit(
            "package.create",
            None,
            &serde_json::json!({"id": id, "name": out.name, "slug": out.slug}).to_string(),
            "ok",
        )
        .await;
        Ok(out)
    }

    /// Overwrite a definition. Edits reach every ACTIVE activation on the
    /// next drift tick — that liveness is the whole point of a package —
    /// but never rewrite an activation's price snapshot.
    pub async fn package_update(
        &self,
        id: i64,
        input: PackageInput,
    ) -> Result<ServicePackage, RpcError> {
        // 404 before writing, so editing a deleted package doesn't report ok.
        self.package_get(id).await?;
        let validated = validate_package(input)?;
        let new = package_input_to_new(validated);
        let lang = new.letters_lang.clone();
        packages::update(&self.pool, id, &new, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("package update: {e}")))?;
        // Push the LANGUAGE onto the sites already on this package.
        //
        // Deliberately unlike the price and the bundle, which stay snapshotted:
        // those are what the customer agreed to. A language is a presentation
        // default the operator changes when they find the setting, expecting it
        // to apply to the forty sites already sold — and the panel says exactly
        // that in three places ("Sites already holding this package pick the
        // change up on the next enforcement pass"). Without this the field was
        // write-once at activation and all three statements were false.
        //
        // THIS NODE ONLY. `hosting_packages` is co-located with its hosting,
        // so on a master these two lines reach the master's own sites and
        // nothing else. The caller fans [`Self::package_relist`] out to every
        // node — and has to tell the operator about any node that did not
        // answer, because those sites keep the old settings with nothing on
        // screen to say so.
        let moved = packages::set_letters_lang(&self.pool, id, &lang)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package language: {e}")))?;
        // And the CHECKLIST, for the same reason: it is what the operator
        // promises to look at from here on, not a term the customer bought.
        // Months already ticked keep their own frozen list, so this changes
        // what is checked next month without rescoring the record.
        let relisted = packages::set_check_items(&self.pool, id, &new.check_items)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package checklist: {e}")))?;
        // And which care-report sections the letter carries — the same kind of
        // presentation promise, so it follows the plan onto the sites already
        // sold. A report already sent is history; the next one uses this.
        let resectioned = packages::set_report_omit(&self.pool, id, &new.report_omit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package report sections: {e}")))?;
        let out = self.package_get(id).await?;
        self.append_audit(
            "package.update",
            None,
            &serde_json::json!({
                "id": id, "name": out.name, "slug": out.slug,
                "letters_lang": lang, "activations_relanguaged": moved,
                "activations_relisted": relisted,
                "report_omit": new.report_omit,
                "activations_resectioned": resectioned,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(out)
    }

    /// Does an ACTIVE care package on this site sell it backups?
    ///
    /// Read from the activation SNAPSHOT, not from the definition: this runs
    /// on the node that owns the hosting, where `service_packages` is empty.
    /// The same trap the letter language and the checklist both fell into.
    ///
    /// An unreadable activation list answers TRUE — "keep taking backups" is
    /// the only safe direction for a question about whether a customer is
    /// owed them.
    pub(super) async fn backups_are_sold_to(&self, id: &HostingId) -> bool {
        // IN FORCE only: a plan that starts next month is not yet owed backups.
        match packages::list_in_force_for_hosting(&self.pool, id).await {
            Ok(rows) => rows
                .iter()
                .any(|r| !r.features.backup_cadence.is_leave_or_off()),
            Err(e) => {
                tracing::warn!(
                    hosting = %id.as_str(), error = %e,
                    "scheduled backups: could not read care packages — keeping backups on"
                );
                true
            }
        }
    }

    /// Apply a definition's live fields to the activations THIS node owns.
    ///
    /// The other half of [`Self::package_update`]. That one runs on the
    /// master, whose `hosting_packages` holds only the sites the master owns;
    /// every other site's activation row lives in its own node's database and
    /// is unreachable from there. The panel calls this on every node after an
    /// edit.
    ///
    /// Takes the VALUES, not the id: `service_packages` is master-only, so a
    /// worker asked to look the definition up would find nothing and quietly
    /// do nothing — the exact failure this exists to fix.
    pub async fn package_relist(
        &self,
        package_id: i64,
        letters_lang: &str,
        check_items: &str,
        report_omit: &str,
    ) -> Result<(u64, u64), RpcError> {
        // Re-normalised, not trusted: this arrives over RPC from a master that
        // may be a different build, and a malformed value stored on a worker
        // would be read back by `ReportOmit::parse` on every report.
        let report_omit = hyperion_types::report_sections::ReportOmit::parse(report_omit);
        // A value that leaves out everything is refused rather than stored —
        // the same rule `validate_package` applies on the master. A worker
        // that stored it would send a letter with no body.
        if report_omit.leaves_out_everything() {
            return Err(RpcError::Validation {
                message: "a care plan must send at least one report section".into(),
            });
        }
        let report_omit = report_omit.to_stored();
        let resectioned = packages::set_report_omit(&self.pool, package_id, &report_omit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package relist sections: {e}")))?;
        let relanguaged = packages::set_letters_lang(&self.pool, package_id, letters_lang)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package relist language: {e}")))?;
        let relisted = packages::set_check_items(&self.pool, package_id, check_items)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package relist checklist: {e}")))?;
        if relanguaged > 0 || relisted > 0 || resectioned > 0 {
            self.append_audit(
                "package.relist",
                None,
                &serde_json::json!({
                    "package_id": package_id,
                    "letters_lang": letters_lang,
                    "report_omit": report_omit,
                    "activations_relanguaged": relanguaged,
                    "activations_relisted": relisted,
                    "activations_resectioned": resectioned,
                })
                .to_string(),
                "ok",
            )
            .await;
        }
        Ok((relanguaged, relisted))
    }

    /// Re-price the activations THIS node owns to a definition's price.
    ///
    /// Never automatic: the price is snapshotted at activation because it is
    /// what the customer agreed to. The panel calls this on every node only
    /// when the operator ticks "apply the new price to sites already on this
    /// package" while saving it. Takes the VALUES for the same reason as
    /// [`Self::package_relist`]: a worker has no `service_packages` row to
    /// look them up in.
    ///
    /// Re-validated here, not trusted: the request may come from a master of
    /// another build, and a bad interval stored on a worker would silently
    /// stop that site's reminders. Returns how many ACTIVE activations moved.
    pub async fn package_reprice(
        &self,
        package_id: i64,
        price_minor: Option<i64>,
        price_currency: Option<String>,
        price_interval: Option<String>,
    ) -> Result<u64, RpcError> {
        if price_minor.is_some_and(|m| m < 0) {
            return Err(RpcError::Validation {
                message: "price must not be negative".into(),
            });
        }
        let currency = price_currency
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        let interval = price_interval
            .map(|i| i.trim().to_lowercase())
            .filter(|i| !i.is_empty());
        let interval_secs = match interval.as_deref() {
            None => None,
            Some(iv) => Some(
                billing_interval_secs(iv).ok_or_else(|| RpcError::Validation {
                    message: "price interval must be monthly | quarterly | yearly".into(),
                })?,
            ),
        };
        let repriced = packages::set_price(
            &self.pool,
            package_id,
            price_minor,
            currency.as_deref(),
            interval.as_deref(),
            interval_secs,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("package reprice: {e}")))?;
        if repriced > 0 {
            self.append_audit(
                "package.reprice",
                None,
                &serde_json::json!({
                    "package_id": package_id,
                    "price_minor": price_minor,
                    "price_currency": currency,
                    "price_interval": interval,
                    "activations_repriced": repriced,
                })
                .to_string(),
                "ok",
            )
            .await;
        }
        Ok(repriced)
    }

    /// Delete a definition. Existing activations SURVIVE with `package_id`
    /// NULLed (the FK is ON DELETE SET NULL): the price the customer agreed
    /// to and the prior state a clean cancel needs are not ours to erase.
    /// What they lose is the bundle, so the drift tick stops enforcing them
    /// — which is why the audit entry records how many sites that hit.
    /// Retiring a package the operator still sells is `enabled = false`.
    pub async fn package_delete(&self, id: i64) -> Result<(), RpcError> {
        let orphaned = packages::count_active(&self.pool, id).await.unwrap_or(0);
        packages::delete(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package delete: {e}")))?;
        if orphaned > 0 {
            tracing::warn!(
                package_id = id,
                activations = orphaned,
                "package definition deleted while still active on hostings — \
                 their activations survive but are no longer enforced"
            );
        }
        self.append_audit(
            "package.delete",
            None,
            &serde_json::json!({"id": id, "orphaned_activations": orphaned}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// The packages a hosting holds. `history = true` includes cancelled
    /// rows (what the customer bought and when it stopped).
    /// Which monthly service checks an operator ticked inside `[from, to)`.
    ///
    /// The checklist is filed per calendar month and a report period is not,
    /// so a period is mapped onto every month it TOUCHES: a quarterly report
    /// asks about three months, a weekly one about the one or two its days
    /// fall in. An item counts as done if it was ticked in any of them —
    /// the customer is being told the work happened, and a fortnightly
    /// report that straddles a month boundary must not report the same
    /// month's work as missing in the half that fell the wrong side.
    ///
    /// `None` when the value could not be read at all. That is a different
    /// statement from "nothing was ticked", and the letter words it as one:
    /// an unreadable record must never read as a confirmed omission, and an
    /// omission must never read as work done.
    /// The monthly checklist this site is on, from the packages it HOLDS.
    ///
    /// Read from the activation snapshots, never from `service_packages`: the
    /// definitions table only exists on the master, and every caller of this
    /// runs on the node that owns the hosting. Resolving through `package_id`
    /// would give the operator's real list on a single-node install and the
    /// built-in four on every worker — the same trap the letter language fell
    /// into.
    ///
    /// A site holding two packages is asked for the union. An unreadable
    /// activation list yields the built-in four rather than an empty one,
    /// because "0 of 0" renders as a finished month.
    pub(crate) async fn care_check_items(
        &self,
        hosting_id: &HostingId,
    ) -> Vec<hyperion_types::care_check::CheckItemDef> {
        // In force only: a plan waiting for its start date asks for no checks.
        let rows = packages::list_in_force_for_hosting(&self.pool, hosting_id)
            .await
            .unwrap_or_default();
        let snapshots: Vec<&str> = rows.iter().map(|r| r.check_items.as_str()).collect();
        hyperion_types::care_check::resolve_check_items(&snapshots)
    }

    pub(super) async fn care_service_work(
        &self,
        hosting_id: &str,
        from: i64,
        to: i64,
    ) -> Option<hyperion_types::package::CareServiceWork> {
        use hyperion_types::care_check::{period_key, CareServiceChecks};
        let raw = hyperion_state::hosting_kv::get(&self.pool, hosting_id, CARE_CHECKS_KV_KEY)
            .await
            .ok()?
            .unwrap_or_default();
        let checks = CareServiceChecks::parse(&raw);
        // Every month the half-open window touches, walked a day at a time
        // from the first day to the last one INSIDE it. A period shorter
        // than a month yields one or two keys; a quarter yields three or
        // four. Cheap either way, and it cannot miss a month the way
        // stepping by 30 days can.
        let last = (to - 1).max(from);
        let mut months: Vec<String> = Vec::new();
        let mut t = from;
        loop {
            let k = period_key(t);
            if !months.contains(&k) {
                months.push(k);
            }
            if t >= last {
                break;
            }
            t = (t + 86_400).min(last);
        }
        // What the customer was owed across this window is the UNION of what
        // each month it touches was scored against — a frozen list for a month
        // already ticked, the site's current plan for one still open. A
        // quarterly report whose plan gained an item in month two has to name
        // that item, and must not retro-charge months one and three with it
        // beyond what their own record says.
        let live = self
            .care_check_items(&HostingId(hosting_id.to_string()))
            .await;
        let mut items: Vec<hyperion_types::care_check::CheckItemDef> = Vec::new();
        for m in &months {
            for def in checks.items_now(m, &live) {
                if !items.iter().any(|k| k.id == def.id) {
                    items.push(def);
                }
            }
        }
        let mut work = hyperion_types::package::CareServiceWork::default();
        for item in items {
            let done = months
                .iter()
                .any(|m| checks.month(m).is_some_and(|mm| mm.contains_key(&item.id)));
            if done {
                work.done.push(item.id.clone());
            } else {
                work.missing.push(item.id.clone());
            }
            // Only what the letter pack cannot name. Carrying a label for a
            // built-in id would let an operator's edit of the package silently
            // override the translated wording in a customer's letter.
            if hyperion_types::care_check::ServiceCheckItem::parse(&item.id).is_none() {
                work.labels.insert(item.id, item.label);
            }
        }
        Some(work)
    }

    /// Care standing for every site on THIS node: what it pays for, and how
    /// much of `period`'s monthly service checklist has been ticked.
    ///
    /// The two halves have to be read together and can only be read here —
    /// `hosting_packages` rows are co-located with their hosting, and the
    /// checklist is in this node's `hosting_kv`. The panel fans this out one
    /// call per node; the alternative was two round-trips per site, on the
    /// dashboard, on every page load.
    ///
    /// A site whose checklist cannot be read is reported with NOTHING ticked
    /// rather than skipped. Skipping it would quietly shrink the list of
    /// sites the operator owes a look at, which is the one direction this
    /// answer must not fail in.
    pub async fn care_overview(
        &self,
        period: String,
    ) -> Result<Vec<hyperion_types::care_check::CareOverviewRow>, RpcError> {
        use hyperion_types::care_check::{CareOverviewRow, CareServiceChecks};
        let rows = packages::list_all_in_force(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("care overview: {e}")))?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let prev = hyperion_types::care_check::previous_period(&period);
        // Group the activations by hosting first: a site holding two packages
        // is ONE row with two names, not two rows the operator has to tick
        // twice.
        let mut order: Vec<HostingId> = Vec::new();
        let mut names: HashMap<String, Vec<String>> = HashMap::new();
        // The checklist snapshots, grouped the same way. Taken from the rows
        // already in hand rather than re-queried per site: this runs on the
        // dashboard, on every load, for every site on the node.
        let mut lists: HashMap<String, Vec<String>> = HashMap::new();
        // Billing facts, folded per site the same way: earliest start, soonest
        // reminder, and every priced plan's snapshot.
        let mut since: HashMap<String, i64> = HashMap::new();
        let mut next_bill: HashMap<String, i64> = HashMap::new();
        let mut charges: HashMap<String, Vec<hyperion_types::care_check::CareCharge>> =
            HashMap::new();
        for r in rows {
            let key = r.hosting_id.as_str().to_string();
            if !names.contains_key(&key) {
                order.push(r.hosting_id.clone());
            }
            let start = r.valid_from.unwrap_or(r.activated_at);
            since
                .entry(key.clone())
                .and_modify(|t| *t = (*t).min(start))
                .or_insert(start);
            if let Some(nb) = r.next_billing_at {
                next_bill
                    .entry(key.clone())
                    .and_modify(|t| *t = (*t).min(nb))
                    .or_insert(nb);
            }
            if let (Some(m), Some(c), Some(iv)) = (
                r.price_minor,
                r.price_currency.as_ref(),
                r.price_interval.as_ref(),
            ) {
                charges.entry(key.clone()).or_default().push(
                    hyperion_types::care_check::CareCharge {
                        price_minor: m,
                        currency: c.clone(),
                        interval: iv.clone(),
                    },
                );
            }
            let entry = names.entry(key.clone()).or_default();
            // The activation SNAPSHOTS the name, so a deleted definition
            // still says what the customer bought.
            if !r.package_name.trim().is_empty() && !entry.contains(&r.package_name) {
                entry.push(r.package_name.clone());
            }
            lists.entry(key).or_default().push(r.check_items.clone());
        }
        let mut out = Vec::with_capacity(order.len());
        for id in order {
            let domain = match hyperion_state::hostings::get_by_id(&self.pool, &id).await {
                Ok(Some(h)) => h.domain,
                // The activation outlived its hosting, or the row is
                // unreadable. Naming it by id beats dropping it: an
                // activation with no site is itself worth seeing.
                _ => id.as_str().to_string(),
            };
            let raw = hyperion_state::hosting_kv::get(&self.pool, id.as_str(), CARE_CHECKS_KV_KEY)
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
            let checks = CareServiceChecks::parse(&raw);
            // The site's own list, not the built-in four: two sites on two
            // plans are asked different questions and the dashboard has to
            // say so, including in the denominator.
            let raw_lists = lists.remove(id.as_str()).unwrap_or_default();
            let live = hyperion_types::care_check::resolve_check_items(
                &raw_lists.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            let total = checks.items_now(&period, &live).len();
            let outstanding: Vec<String> = checks
                .outstanding_now(&period, &live)
                .into_iter()
                .map(|i| i.label)
                .collect();
            // A month nobody touched at all is far more likely to predate the
            // plan than to have been skipped, so only a month that was
            // STARTED and left unfinished is reported as outstanding.
            let prev_outstanding = match prev.as_deref() {
                Some(p) if checks.month(p).is_some() => checks.outstanding_defs(p).len(),
                _ => 0,
            };
            out.push(CareOverviewRow {
                hosting_id: id.as_str().to_string(),
                domain,
                packages: names.remove(id.as_str()).unwrap_or_default(),
                checks_done: total.saturating_sub(outstanding.len()),
                checks_total: total,
                outstanding,
                prev_outstanding,
                since: since.remove(id.as_str()),
                next_billing_at: next_bill.remove(id.as_str()),
                charges: charges.remove(id.as_str()).unwrap_or_default(),
            });
        }
        // Sites needing attention first, then alphabetically — the card is
        // read top-down as a work list.
        out.sort_by(|a, b| {
            b.outstanding
                .len()
                .cmp(&a.outstanding.len())
                .then_with(|| a.domain.cmp(&b.domain))
        });
        Ok(out)
    }

    pub async fn package_activations(
        &self,
        sel: HostingSelector,
        history: bool,
    ) -> Result<Vec<HostingPackage>, RpcError> {
        let detail = self.get(sel).await?;
        let rows = if history {
            packages::history_for_hosting(&self.pool, &detail.id).await
        } else {
            packages::list_for_hosting(&self.pool, &detail.id).await
        }
        .map_err(|e| RpcError::Internal_with(format!("package activations: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let name = r.package_name.clone();
            out.push(activation_row_to_wire(r, name));
        }
        Ok(out)
    }

    /// Activate a package on a hosting: snapshot what every forced feature
    /// was set to, push the bundle through the real setters, and record the
    /// price the customer agreed to plus the reminder clock.
    ///
    /// Idempotent. Re-activating a package the hosting already holds does
    /// not open a second row — it re-asserts the bundle and returns the
    /// existing activation, keeping the ORIGINAL prior state. Re-capturing
    /// it would record the state this very activation forced, and a later
    /// cancel would then "restore" the package's own values as if they had
    /// been the customer's.
    pub async fn package_activate(
        &self,
        sel: HostingSelector,
        package_id: i64,
        package: Option<ServicePackage>,
        valid_from: Option<i64>,
    ) -> Result<HostingPackage, RpcError> {
        let detail = self.get(sel).await?;
        let now = now_secs();
        // The operator's start date, checked before anything is written. `None`
        // means "starts now", which is stored as NULL so a row nobody dated
        // stays byte-identical to what this function wrote before.
        let valid_from = validate_valid_from(valid_from, now)?;
        // A start date in the future makes this a plan the site does not have
        // YET: it is recorded, shown and billed from its date, but nothing is
        // captured or forced until then (see `package_start_due`).
        let starts_now = valid_from.map_or(true, |t| t <= now);
        // The master passes the resolved definition inline (`service_packages`
        // lives in ITS database); a node that is itself the master falls back
        // to a local lookup. Same split as profile_apply, for the same reason.
        let def = match package {
            Some(p) => p,
            None => self.package_get(package_id).await?,
        };
        // A retired package must not be sellable. `enabled = false` is THE
        // documented retire path (it deliberately leaves existing activations
        // running), so enforcing it only in the picker's filter would leave a
        // hand-crafted POST — or a stale picker rendered before the operator
        // withdrew it — able to sell a package that is no longer on offer,
        // snapshotting its price and forcing its bundle.
        if !def.enabled {
            return Err(RpcError::Conflict {
                message: format!(
                    "package \"{}\" is retired and can no longer be activated",
                    def.name
                ),
            });
        }
        let features = def.features;

        let held = packages::list_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package activate: read held: {e}")))?;
        if let Some(existing) = held.iter().find(|a| a.package_id == Some(package_id)) {
            // A plan still waiting for its start date is re-asserted by NOBODY:
            // forcing its features now would be activating it early. Moving the
            // date is `package_set_valid_from`'s job, not this call's.
            if existing.is_pending() {
                return Ok(activation_row_to_wire(existing.clone(), def.name));
            }
            let live = self.package_live_state(&detail).await;
            let changed = self.package_push_features(&detail, &features, &live).await;
            self.append_audit(
                "package.activate",
                Some(detail.id.as_str()),
                &serde_json::json!({
                    "package_id": package_id,
                    "package_name": def.name,
                    "activation_id": existing.id,
                    "reasserted": true,
                    "changed": changed,
                })
                .to_string(),
                "ok",
            )
            .await;
            return Ok(activation_row_to_wire(existing.clone(), def.name));
        }

        // Read the site BEFORE writing to it. This is the only moment the
        // pre-package state still exists, and it is exactly what a cancel
        // puts back.
        //
        // Only when the plan starts now. A plan dated for the future captures
        // nothing: the state read today would be restored over whatever was
        // changed in the weeks between, so the capture happens when the plan
        // actually starts (`package_start_due`).
        let live = self.package_live_state(&detail).await;
        let prior_state_json = if starts_now {
            let prior = PackagePriorState::capture(&features, &live);
            match serde_json::to_string(&prior) {
                Ok(j) => Some(j),
                Err(e) => {
                    // Losing the snapshot would make a later cancel silently
                    // leave paid features switched on forever — refuse instead.
                    return Err(RpcError::Internal_with(format!(
                        "package activate: serialise prior state: {e}"
                    )));
                }
            }
        } else {
            None
        };
        // The reminder clock counts from the START of the term, not from the
        // click: a plan backdated to the 1st renews on the next whole interval
        // after today, and one that starts next month renews an interval after
        // that.
        let next_billing_at = def
            .price_interval
            .as_deref()
            .and_then(|iv| advance_billing_date(valid_from.unwrap_or(now), iv, now));
        let activation_id = packages::activate(
            &self.pool,
            &packages::NewActivation {
                hosting_id: detail.id.clone(),
                package_id,
                // Snapshotted with the rest: the letter is rendered on the
                // node that owns this hosting, where `service_packages` is
                // empty, so reading the definition there would silently fall
                // back to the cluster language on every worker.
                letters_lang: def.letters_lang.clone(),
                // Snapshotted for the same reason: the monthly checklist is
                // rendered and ticked on the owning node too.
                check_items: def.check_items.clone(),
                // Snapshotted for the same reason: the letter is rendered on the
                // owning node, which cannot look the plan's choice up.
                report_omit: def.report_omit.clone(),
                valid_from,
                enforcement_started: starts_now,
                // Snapshot the name, price AND bundle: a later re-price,
                // re-scope or delete of the definition must not rewrite what
                // this customer agreed to. The bundle snapshot is also what
                // makes the activation self-contained — definitions live only
                // on the master, but this row is enforced on the node that
                // owns the hosting, which has no `service_packages` to read.
                package_name: def.name.clone(),
                price_minor: def.price_minor,
                price_currency: def.price_currency.clone(),
                price_interval: def.price_interval.clone(),
                features: def.features,
                next_billing_at,
                prior_state_json,
            },
            now,
        )
        .await
        .map_err(|e| RpcError::Conflict {
            message: format!("package activate: {e}"),
        })?;

        // Record first, apply second. If a setter fails half-way the row is
        // still there with the correct prior state and the drift tick
        // finishes the job; the other order can leave features switched on
        // with nothing saying who paid for them.
        let changed = if starts_now {
            self.package_push_features(&detail, &features, &live).await
        } else {
            Vec::new()
        };
        self.append_audit(
            "package.activate",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "package_id": package_id,
                "package_name": def.name,
                "activation_id": activation_id,
                "price_minor": def.price_minor,
                "next_billing_at": next_billing_at,
                "valid_from": valid_from,
                "pending": !starts_now,
                "changed": changed,
            })
            .to_string(),
            "ok",
        )
        .await;

        let row = packages::get_activation(&self.pool, activation_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package activate: re-read: {e}")))?
            .ok_or(RpcError::Internal {
                message: "activation vanished after write (concurrent delete?)".into(),
            })?;
        // Tell Slack the price changed. Only from HERE, the path that opens a
        // NEW row — the early return above re-asserts a package the hosting
        // already holds, and announcing that would report a price rise that
        // did not happen, every time the drift tick re-applied the bundle.
        //
        // The message carries the whole picture, not just the package: an
        // operator reading "care plan added" wants to know what the customer
        // now pays in total, which is the number that goes on the invoice.
        let (price_line, plan_line, total_line) = self.price_picture(&detail.id).await;
        let cat = self.letter_catalog();
        // Both clocks, each named: the plan's own (what this message is
        // about) and the hosting's, which runs on its own cycle. One unnamed
        // date read as the next invoice for everything on the site.
        let applied = hyperion_state::profiles::get_apply(&self.pool, &detail.id)
            .await
            .ok()
            .flatten();
        let mut next_line = Self::next_invoice_line(&cat, &def.name, row.next_billing_at, now);
        if let Some(t) = applied.as_ref().and_then(|a| a.next_billing_at) {
            next_line.push('\n');
            next_line.push_str(&Self::next_invoice_line(
                &cat,
                cat.get("slack.what_hosting"),
                Some(t),
                now,
            ));
        }
        // Same channel the hosting's own billing messages go to: the profile's
        // webhook snapshotted at apply time, else the cluster default.
        let webhook = applied.and_then(|a| a.slack_webhook);
        let msg = cat.render(
            "slack.care_activated",
            &[
                ("domain", &detail.domain),
                ("price", &price_line),
                ("plan", &plan_line),
                ("total", &total_line),
                ("next", &next_line),
            ],
        );
        self.notify_slack(webhook.as_deref(), &msg).await;

        Ok(activation_row_to_wire(row, def.name))
    }

    /// Start every activation whose `valid_from` has arrived.
    ///
    /// Runs at the head of the enforcement tick, so a plan dated for the 1st
    /// is live within one pass of the 1st. Returns how many were started.
    pub(crate) async fn package_start_due(&self) -> i64 {
        let due = match packages::list_due_to_start(&self.pool, now_secs()).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "care package: reading plans due to start failed");
                return 0;
            }
        };
        let mut started = 0;
        for row in due {
            if self.package_start_one(&row).await {
                started += 1;
            }
        }
        started
    }

    /// Begin ONE waiting activation: capture the prior state NOW, flip the row
    /// to started, then force the bundle through the real setters.
    ///
    /// Order matters and matches `package_activate`: the prior state is read
    /// before anything is written, and the row is recorded before the setters
    /// run, so a setter that fails half-way leaves a row the drift tick finishes
    /// rather than features switched on that nothing accounts for. The state
    /// layer's compare-and-set means two passes racing here cannot both capture.
    ///
    /// A site that is not Active (suspended, trashed) is skipped and retried on
    /// the next pass: re-rendering the vhost of a suspended site is not this
    /// tick's job, and starting must not capture the state of a site that is
    /// about to change.
    pub(super) async fn package_start_one(
        &self,
        row: &hyperion_state::packages::HostingPackageRow,
    ) -> bool {
        let detail = match self.get(HostingSelector::Id(row.hosting_id.clone())).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(hosting_id = %row.hosting_id.as_str(), error = %e, "care package start: hosting read failed");
                return false;
            }
        };
        if detail.state != HostingState::Active {
            return false;
        }
        let live = self.package_live_state(&detail).await;
        let prior = PackagePriorState::capture(&row.features, &live);
        let prior_json = match serde_json::to_string(&prior) {
            Ok(j) => j,
            Err(e) => {
                // Same rule as activation: no snapshot, no start — a cancel
                // could not restore, and would leave the features on forever.
                tracing::warn!(error = %e, "care package start: serialise prior state failed");
                return false;
            }
        };
        match packages::mark_started(&self.pool, row.id, Some(&prior_json)).await {
            Ok(true) => {}
            // Another pass (or a cancel) got there first.
            Ok(false) => return false,
            Err(e) => {
                tracing::warn!(error = %e, "care package start: could not record the start");
                return false;
            }
        }
        let changed = self
            .package_push_features(&detail, &row.features, &live)
            .await;
        self.append_audit(
            "package.start",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "activation_id": row.id,
                "package_name": row.package_name,
                "valid_from": row.valid_from,
                "changed": changed,
            })
            .to_string(),
            "ok",
        )
        .await;
        true
    }

    /// Change when an activation's term begins.
    ///
    /// Earlier is always fine — it moves where the first care report and the
    /// billing clock count from (a report already sent is history and keeps its
    /// period; the next one still starts where the last ended). Later is fine
    /// for a plan that has not started. What is refused is moving a plan that is
    /// ALREADY IN FORCE into the future: that would mean un-forcing features and
    /// restoring a prior state long since overtaken, which is what cancelling
    /// and re-activating are for.
    pub async fn package_set_valid_from(
        &self,
        sel: HostingSelector,
        activation_id: i64,
        valid_from: i64,
    ) -> Result<HostingPackage, RpcError> {
        let detail = self.get(sel).await?;
        let row = packages::get_activation(&self.pool, activation_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package valid_from: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "package activation".into(),
                id: activation_id.to_string(),
            })?;
        // The selector and the activation must agree, as in cancel.
        if row.hosting_id != detail.id {
            return Err(RpcError::NotFound {
                kind: "package activation".into(),
                id: activation_id.to_string(),
            });
        }
        if !row.state.is_active() {
            return Err(RpcError::Conflict {
                message: "this package was cancelled — its dates are history".into(),
            });
        }
        let now = now_secs();
        let Some(valid_from) = validate_valid_from(Some(valid_from), now)? else {
            // `validate_valid_from(Some(_))` never yields None.
            return Err(RpcError::Internal {
                message: "package valid_from: no date after validation".into(),
            });
        };
        if row.enforcement_started && valid_from > now {
            return Err(RpcError::Conflict {
                message: "this package is already in force, so its start date cannot be moved \
                          into the future — cancel it and activate it again with the later date"
                    .into(),
            });
        }
        // The reminder clock follows the term. A plan with no price interval has
        // no clock to move.
        let next_billing_at = match row.price_interval.as_deref() {
            Some(iv) if row.next_billing_at.is_some() || !row.enforcement_started => {
                advance_billing_date(valid_from, iv, now)
            }
            _ => row.next_billing_at,
        };
        let moved =
            packages::set_valid_from(&self.pool, activation_id, valid_from, next_billing_at)
                .await
                .map_err(|e| RpcError::Internal_with(format!("package valid_from: {e}")))?;
        if !moved {
            return Err(RpcError::Conflict {
                message: "this package was cancelled while the date was being changed".into(),
            });
        }
        self.append_audit(
            "package.valid_from",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "activation_id": activation_id,
                "package_name": row.package_name,
                "from": row.valid_from,
                "to": valid_from,
                "next_billing_at": next_billing_at,
            })
            .to_string(),
            "ok",
        )
        .await;
        // Moving a waiting plan to today or earlier starts it NOW — the
        // operator who just fixed the date expects the plan to be live, not
        // "within one enforcement pass".
        if !row.enforcement_started && valid_from <= now {
            if let Ok(Some(fresh)) = packages::get_activation(&self.pool, activation_id).await {
                self.package_start_one(&fresh).await;
            }
        }
        let row = packages::get_activation(&self.pool, activation_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package valid_from: re-read: {e}")))?
            .ok_or(RpcError::Internal {
                message: "activation vanished after write (concurrent delete?)".into(),
            })?;
        let name = row.package_name.clone();
        Ok(activation_row_to_wire(row, name))
    }

    /// End an activation and put back what it changed.
    ///
    /// Only the features THIS package forced are restored, and only where
    /// no OTHER still-active package forces the same one — otherwise
    /// cancelling the cheaper package would switch off something the
    /// customer still pays for through another. The row is kept, marked
    /// cancelled, as history.
    pub async fn package_cancel(
        &self,
        sel: HostingSelector,
        activation_id: i64,
    ) -> Result<HostingPackage, RpcError> {
        let detail = self.get(sel).await?;
        let row = packages::get_activation(&self.pool, activation_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package cancel: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "package activation".into(),
                id: activation_id.to_string(),
            })?;
        // The selector and the activation must agree — an id from another
        // site is a 404 here, never a cancellation of someone else's package.
        if row.hosting_id != detail.id {
            return Err(RpcError::NotFound {
                kind: "package activation".into(),
                id: activation_id.to_string(),
            });
        }
        let name = row.package_name.clone();
        if !row.state.is_active() {
            // Already history: the restore ran once, at the right moment.
            // Doing it again would undo whatever changed since.
            return Ok(activation_row_to_wire(row, name));
        }

        // Mark it cancelled FIRST: that both settles the double-cancel race
        // (the state layer returns false for the loser) and takes this row
        // out of the "what else is still active" fold below.
        let won = packages::cancel(&self.pool, activation_id, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("package cancel: {e}")))?;
        if !won {
            let row = packages::get_activation(&self.pool, activation_id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("package cancel: re-read: {e}")))?
                .ok_or(RpcError::NotFound {
                    kind: "package activation".into(),
                    id: activation_id.to_string(),
                })?;
            return Ok(activation_row_to_wire(row, name));
        }

        let still_forced = self.package_desired_state(&detail.id).await;
        let prior = row
            .prior_state_json
            .as_deref()
            .and_then(|j| serde_json::from_str::<PackagePriorState>(j).ok())
            .unwrap_or_default();
        // Turn the snapshot into a restore intent, then blank out every
        // feature another live package still speaks about.
        let mut restore = PackageFeatures {
            wp_auto_update: toggle_of(prior.wp_auto_update),
            integrity_scan: toggle_of(prior.integrity_scan),
            monitoring: toggle_of(prior.monitoring),
            // An exact prior level (rows from migration 084 on) is put back
            // below, after the push; an older row restores through the
            // on/off it recorded, as it always did.
            hardening: if prior.waf_level.is_some() {
                FeatureToggle::Leave
            } else {
                toggle_of(prior.hardening)
            },
            firewall_strict: false,
            crs: prior
                .crs
                .as_deref()
                .map(CrsPin::from_stored)
                .unwrap_or_default(),
            bruteforce: toggle_of(prior.bruteforce),
            backup_cadence: prior.backup_cadence.unwrap_or_default(),
            // The custom period + retention ride with the cadence above: a
            // non-`Leave` prior cadence re-opens the backup block in
            // `package_push_features`, which writes these back; a `Leave`
            // prior (the package never forced backups, or the fold below
            // blanks it) closes it and leaves them untouched. `None` from an
            // older row reads as 0, the same "no opinion" the site stores.
            backup_interval_days: prior.backup_interval_days.unwrap_or(0),
            backup_keep_days: prior.backup_keep_days.unwrap_or(0),
            backup_keep_last: prior.backup_keep_last.unwrap_or(0),
            // `Leave` is the ONLY correct value here, and not because there
            // is nothing captured to restore: the report cadence is never
            // written to the site at all. It is derived live from the
            // hosting's still-active activations every time a report is due
            // (see `care_report_entitlement`), so this row leaving the
            // active set IS the restore — and the fold below is what keeps
            // a sibling package's cadence intact.
            report_cadence: ReportCadence::Leave,
        };
        if still_forced.wp_auto_update.forces().is_some() {
            restore.wp_auto_update = FeatureToggle::Leave;
        }
        if still_forced.integrity_scan.forces().is_some() {
            restore.integrity_scan = FeatureToggle::Leave;
        }
        if still_forced.monitoring.forces().is_some() {
            restore.monitoring = FeatureToggle::Leave;
        }
        let firewall_still_forced = still_forced.hardening.forces().is_some();
        if firewall_still_forced {
            restore.hardening = FeatureToggle::Leave;
        }
        if !still_forced.crs.is_leave() {
            restore.crs = CrsPin::Leave;
        }
        if still_forced.bruteforce.forces().is_some() {
            restore.bruteforce = FeatureToggle::Leave;
        }
        if !still_forced.backup_cadence.is_leave() {
            restore.backup_cadence = BackupCadence::Leave;
        }

        let live = self.package_live_state(&detail).await;
        let mut changed = self.package_push_features(&detail, &restore, &live).await;
        // The exact WAF level from before the package: a Standard site that a
        // Strict plan raised goes back to Standard, not "still on".
        if !firewall_still_forced {
            if let Some(level) = prior
                .waf_level
                .as_deref()
                .and_then(hyperion_types::waf::WafLevel::parse)
            {
                if level != live.waf_level {
                    let r = self.package_set_waf_level(&detail, level).await;
                    push_change(
                        &mut changed,
                        &detail,
                        "firewall",
                        live.waf_level.as_str(),
                        level.as_str(),
                        r,
                    );
                }
            }
        }
        self.append_audit(
            "package.cancel",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "activation_id": activation_id,
                "package_id": row.package_id,
                "package_name": name,
                "restored": changed,
            })
            .to_string(),
            "ok",
        )
        .await;

        let row = packages::get_activation(&self.pool, activation_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package cancel: re-read: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "package activation".into(),
                id: activation_id.to_string(),
            })?;
        Ok(activation_row_to_wire(row, name))
    }

    /// Re-assert every active package's forced features. THE reason this
    /// feature exists: without it a package is a label. Someone switches
    /// backups off on a site whose customer pays for backups, and by the
    /// next tick they are back on and the correction is in the audit log.
    ///
    /// Cheap by construction — one read of the live state per hosting and a
    /// write only where something actually moved — so it can run on the
    /// same cadence as its sibling ticks.
    ///
    /// Scope: the activations on THIS node (`hosting_packages` rows are
    /// co-located with their hosting) whose definition is also readable
    /// here. An activation whose `package_id` is NULL (definition deleted)
    /// has no bundle left to enforce and is skipped; so is a hosting that
    /// isn't Active, because re-rendering a suspended site's vhost is not
    /// this tick's job. Returns the number of feature corrections made.
    pub async fn package_enforce_tick(&self) -> Result<i64, RpcError> {
        // Activations whose start date has arrived are started first (prior
        // state captured NOW, features forced), so the fold below sees them.
        self.package_start_due().await;
        let rows = packages::list_all_in_force(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("package enforce: {e}")))?;
        if rows.is_empty() {
            // The ignore-the-feature-entirely path: no activations, no work,
            // no queries against any hosting.
            return Ok(0);
        }
        // Fold each hosting's bundles into ONE desired state before touching
        // it, so two packages that both speak about backups don't fight each
        // other every tick (On beats Off; the more frequent cadence wins).
        let mut order: Vec<HostingId> = Vec::new();
        let mut wanted: HashMap<String, PackageFeatures> = HashMap::new();
        // Which plans sell protection to each site, and since when — for the
        // protection check below (its alert names the plan; a plan that only
        // just started gets the scanner's first pass before anyone is told).
        let mut sellers: HashMap<String, (Vec<String>, i64)> = HashMap::new();
        for row in rows {
            if row.features.bruteforce == FeatureToggle::On
                || matches!(row.features.crs, CrsPin::Detect | CrsPin::Block)
            {
                let e = sellers
                    .entry(row.hosting_id.as_str().to_string())
                    .or_insert_with(|| (Vec::new(), i64::MAX));
                if !e.0.contains(&row.package_name) {
                    e.0.push(row.package_name.clone());
                }
                e.1 = e.1.min(row.valid_from.unwrap_or(row.activated_at));
            }
            // The bundle comes from the ACTIVATION's own snapshot, never from
            // the definition: definitions are master-only, so resolving one
            // here would make this tick a silent no-op on every worker node.
            // It also means a definition edited (or deleted) after the sale
            // cannot change, or quietly stop, what an existing customer is
            // getting — same contract as their frozen price.
            let features = row.features;
            let key = row.hosting_id.as_str().to_string();
            match wanted.get_mut(&key) {
                Some(acc) => *acc = acc.combine(features),
                None => {
                    order.push(row.hosting_id.clone());
                    wanted.insert(key, features);
                }
            }
        }

        let mut corrected = 0i64;
        // Asked at most once per tick, and only if some site needs it.
        let mut engine: Option<bool> = None;
        for hosting_id in order {
            let Some(want) = wanted.get(hosting_id.as_str()) else {
                continue;
            };
            if want.is_noop() {
                continue;
            }
            let detail = match self.get(HostingSelector::Id(hosting_id.clone())).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(hosting_id = %hosting_id.as_str(), error = %e, "package enforce: hosting read failed");
                    continue;
                }
            };
            if detail.state != HostingState::Active {
                continue;
            }
            let live = self.package_live_state(&detail).await;
            let changed = self.package_push_features(&detail, want, &live).await;
            if let Some((names, since)) = sellers.get(hosting_id.as_str()) {
                self.package_protection_check(&detail, want, names, *since, &mut engine)
                    .await;
            }
            if changed.is_empty() {
                continue; // nothing drifted — the common case
            }
            corrected += changed.len() as i64;
            let summary = changed
                .iter()
                .map(|c| format!("{}: {} → {}", c.feature, c.from, c.to))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::info!(
                domain = %detail.domain,
                hosting_id = %detail.id.as_str(),
                corrections = %summary,
                "care package: re-asserted a paid feature that had been switched off"
            );
            self.append_audit(
                "package.enforce",
                Some(detail.id.as_str()),
                &serde_json::json!({"changed": changed}).to_string(),
                "ok",
            )
            .await;
        }
        Ok(corrected)
    }

    /// Install the ModSecurity engine when a care plan in force here sells
    /// the Core Rule Set and the node has none. The card promises the rule
    /// set "will be switched back on automatically"; without an engine the
    /// drift tick can never keep that promise, so it waited forever for
    /// someone to find the install button.
    ///
    /// Scheduled path only (the hourly tick calls this right before
    /// [`Self::package_enforce_tick`]): apt takes minutes, which no RPC
    /// caller of the enforce tick budgets for. At most one attempt per
    /// [`PACKAGE_MODSEC_AUTO_RETRY_SECS`]. Returns whether it installed.
    pub async fn package_crs_engine_ensure(&self) -> bool {
        let wanted = match packages::list_all_in_force(&self.pool).await {
            Ok(rows) => rows
                .iter()
                .any(|r| matches!(r.features.crs, CrsPin::Detect | CrsPin::Block)),
            Err(e) => {
                tracing::warn!(error = %e, "package: read activations for ModSecurity failed");
                return false;
            }
        };
        if !wanted || self.adapters.modsec_status().await.available() {
            return false;
        }
        let now = now_secs();
        let last = hyperion_state::node_kv::get(&self.pool, PACKAGE_MODSEC_AUTO_KV)
            .await
            .ok()
            .flatten()
            .and_then(|v| v.trim().parse::<i64>().ok());
        if last.is_some_and(|t| now.saturating_sub(t) < PACKAGE_MODSEC_AUTO_RETRY_SECS) {
            return false;
        }
        let _ =
            hyperion_state::node_kv::set(&self.pool, PACKAGE_MODSEC_AUTO_KV, &now.to_string(), now)
                .await;
        tracing::info!("care package sells the Core Rule Set: installing ModSecurity on this node");
        match self.modsec_install().await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(error = %e, "care package: automatic ModSecurity install failed — retrying later");
                false
            }
        }
    }

    /// Is the protection a plan sells actually running on this site? A
    /// package can force the per-site switches, but two things it cannot
    /// force live on the NODE: the brute-force scanner (`[fail2ban] enabled`,
    /// and the scanner having really looked at the site lately) and the
    /// ModSecurity engine the Core Rule Set needs. When either is missing the
    /// operator is told — once per change of reason, not on every tick — and
    /// told nothing more once it is fixed.
    pub(super) async fn package_protection_check(
        &self,
        detail: &HostingDetail,
        want: &PackageFeatures,
        plans: &[String],
        since: i64,
        engine: &mut Option<bool>,
    ) {
        let id = detail.id.as_str();
        let now = now_secs();
        let cat = self.operator_catalog();
        let mut reasons: Vec<String> = Vec::new();
        if want.bruteforce == FeatureToggle::On {
            if !self.fail2ban.enabled {
                reasons.push(cat.render("ops.protection_reason.fail2ban_off", &[]));
            } else if !self.http_bruteforce_scan_enabled(id).await {
                reasons.push(cat.render("ops.protection_reason.scan_off", &[]));
            } else {
                let last =
                    hyperion_state::hosting_kv::get(&self.pool, id, FAIL2BAN_HTTP_SINCE_KV_KEY)
                        .await
                        .ok()
                        .flatten()
                        .as_deref()
                        .and_then(parse_coverage_stamp)
                        .map(|(_, last)| last);
                if bruteforce_evidence_missing(last, since, now) {
                    reasons.push(cat.render("ops.protection_reason.no_scan", &[]));
                }
            }
        }
        if matches!(want.crs, CrsPin::Detect | CrsPin::Block) {
            let available = match *engine {
                Some(a) => a,
                None => {
                    let a = self.adapters.modsec_status().await.available();
                    *engine = Some(a);
                    a
                }
            };
            if !available {
                reasons.push(cat.render("ops.protection_reason.no_modsec", &[]));
            }
        }
        let reason = reasons.join(" ");
        let warned = hyperion_state::hosting_kv::get(&self.pool, id, PACKAGE_PROTECTION_WARNED_KV)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if reason == warned {
            return;
        }
        if !reason.is_empty() {
            self.notify_admins_say(
                "warn",
                "ops.package_protection",
                &[
                    ("domain", &detail.domain),
                    ("plan", &plans.join(", ")),
                    ("reason", &reason),
                ],
                &format!("/hostings/{}#protection", detail.domain),
                &format!("protection.package:{}", detail.domain),
            )
            .await;
        }
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            id,
            PACKAGE_PROTECTION_WARNED_KV,
            &reason,
            now,
        )
        .await;
    }

    /// What every active package on this hosting adds up to. `Leave` on a
    /// feature means no package held here speaks about it, so nothing may
    /// touch it.
    pub(super) async fn package_desired_state(&self, hosting_id: &HostingId) -> PackageFeatures {
        // In force only. This is also what `package_cancel` reads to decide
        // which features a sibling still pays for — a sibling that has not
        // started yet is not paying for anything.
        let rows = match packages::list_in_force_for_hosting(&self.pool, hosting_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(hosting_id = %hosting_id.as_str(), error = %e, "package: read held failed");
                return PackageFeatures::default();
            }
        };
        let mut out = PackageFeatures::default();
        for row in rows {
            // Snapshot, not definition — see package_enforce_tick. This is
            // also the guard that stops a cancel from switching off a feature
            // a sibling package still pays for, so silently reading `Leave`
            // here (which a worker-node definition lookup would always do)
            // would clobber a live entitlement.
            out = out.combine(row.features);
        }
        out
    }

    /// The live value of every package-controlled feature on one hosting,
    /// read straight off this node. Both halves of the entitlement need it:
    /// activation snapshots it into `prior_state_json`, and every push
    /// compares against it so it only writes where something moved.
    pub(super) async fn package_live_state(&self, detail: &HostingDetail) -> LiveFeatureState {
        let id = detail.id.as_str();
        // The custom period + the two retention overrides, read straight off
        // the kv the profile/care-package apply seeds and the scheduler/prune
        // sweep reads. Absent or unparseable is 0 ("no opinion"), never a
        // guess — a wrong prior would be faithfully restored on cancel.
        let kv_num = |key: &'static str| {
            let pool = self.pool.clone();
            let id = id.to_string();
            async move {
                hyperion_state::hosting_kv::get(&pool, &id, key)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|v| v.trim().parse::<i64>().ok())
                    .unwrap_or(0)
            }
        };
        LiveFeatureState {
            wp_auto_update: self.wp_auto_update_enabled(id).await,
            integrity_scan: self.integrity_scan_enabled(id).await,
            monitoring: hyperion_state::monitors::get(&self.pool, &detail.id)
                .await
                .ok()
                .flatten()
                .map(|c| c.enabled)
                .unwrap_or(false),
            hardening: detail.vhost_options.effective_waf_level()
                != hyperion_types::waf::WafLevel::Off,
            waf_level: detail.vhost_options.effective_waf_level(),
            crs: detail.vhost_options.crs_settings().mode,
            bruteforce: self.http_bruteforce_scan_enabled(id).await,
            // A site state, never `Leave`: "no cadence configured" is `Off`.
            backup_cadence: match hyperion_state::hosting_kv::get(&self.pool, id, BACKUP_KV_CADENCE)
                .await
            {
                Ok(Some(v)) => BackupCadence::from_stored(canonical_backup_cadence(&v)),
                _ => BackupCadence::Off,
            },
            backup_interval_days: kv_num(BACKUP_KV_INTERVAL_DAYS).await,
            backup_keep_days: kv_num(BACKUP_KV_KEEP_DAYS).await,
            backup_keep_last: kv_num(BACKUP_KV_KEEP_LAST).await,
        }
    }

    /// Drive the five package features to `want`, writing ONLY where the
    /// live value differs. Returns one entry per feature actually changed.
    ///
    /// Every branch goes through the setter the panel uses: the kv writes
    /// are the ones the defender and the backup driver read, `monitor_set`
    /// re-validates the config, and `set_vhost_options` re-renders the
    /// vhost and `nginx -t`s it. A failed setter is logged and left out of
    /// the result — the next tick retries it rather than the audit claiming
    /// a change that never landed.
    pub(super) async fn package_push_features(
        &self,
        detail: &HostingDetail,
        want: &PackageFeatures,
        live: &LiveFeatureState,
    ) -> Vec<FeatureChange> {
        let mut changed: Vec<FeatureChange> = Vec::new();
        let id = detail.id.as_str();

        if let Some(on) = want.wp_auto_update.forces() {
            if on != live.wp_auto_update {
                let r = self
                    .hosting_kv_set(
                        id.to_string(),
                        "wp_auto_update".into(),
                        feature_kv_value(on).into(),
                    )
                    .await;
                push_change(
                    &mut changed,
                    detail,
                    "wp_auto_update",
                    feature_kv_value(live.wp_auto_update),
                    feature_kv_value(on),
                    r,
                );
            }
        }
        if let Some(on) = want.integrity_scan.forces() {
            if on != live.integrity_scan {
                let r = self
                    .hosting_kv_set(
                        id.to_string(),
                        INTEGRITY_ENABLED_KV_KEY.into(),
                        feature_kv_value(on).into(),
                    )
                    .await;
                push_change(
                    &mut changed,
                    detail,
                    "integrity_scan",
                    feature_kv_value(live.integrity_scan),
                    feature_kv_value(on),
                    r,
                );
            }
        }
        if let Some(on) = want.monitoring.forces() {
            if on != live.monitoring {
                let r = self.package_set_monitoring(detail, on).await;
                push_change(
                    &mut changed,
                    detail,
                    "monitoring",
                    feature_kv_value(live.monitoring),
                    feature_kv_value(on),
                    r,
                );
            }
        }
        // The firewall: Off, at least Standard (a stricter level the operator
        // chose stays), or held at Strict.
        if let Some(target) = package_waf_target(want.firewall_level(), live.waf_level) {
            if target != live.waf_level {
                let r = self.package_set_waf_level(detail, target).await;
                push_change(
                    &mut changed,
                    detail,
                    "firewall",
                    live.waf_level.as_str(),
                    target.as_str(),
                    r,
                );
            }
        }
        // The Core Rule Set tier of the same firewall. Switching it ON needs
        // the ModSecurity engine on this node (the vhost path refuses
        // otherwise), so without one the push waits — the protection check
        // tells the operator, the scheduled tick installs the engine itself
        // (`package_crs_engine_ensure`) — and lands on the first pass after.
        if let Some(mode) = want.crs.forces() {
            let needs_engine = mode != hyperion_types::crs::CrsMode::Off
                && live.crs == hyperion_types::crs::CrsMode::Off;
            let engine_ok = !needs_engine || self.adapters.modsec_status().await.available();
            if mode != live.crs && engine_ok {
                let r = self.package_set_crs(detail, mode).await;
                push_change(
                    &mut changed,
                    detail,
                    "core_rule_set",
                    live.crs.as_str(),
                    mode.as_str(),
                    r,
                );
            }
        }
        if let Some(on) = want.bruteforce.forces() {
            if on != live.bruteforce {
                let r = self
                    .hosting_kv_set(
                        id.to_string(),
                        FAIL2BAN_HTTP_KV_KEY.into(),
                        feature_kv_value(on).into(),
                    )
                    .await;
                push_change(
                    &mut changed,
                    detail,
                    "bruteforce",
                    feature_kv_value(live.bruteforce),
                    feature_kv_value(on),
                    r,
                );
            }
        }
        // Backups: the cadence, and — only when the package speaks about
        // backups at all (`kv_value()` is `Some` iff the cadence is not
        // `Leave`) — the custom period and the two retention overrides that
        // ride with it. A package that leaves backups alone writes none of
        // these, so it never disturbs another package's schedule or history.
        // Each value is asserted independently so the audit names exactly what
        // drifted, and so a `custom` cadence and its interval both land.
        if let Some(cadence) = want.backup_cadence.kv_value() {
            if cadence != live.backup_cadence.as_str() {
                let r = self
                    .hosting_kv_set(id.to_string(), BACKUP_KV_CADENCE.into(), cadence.into())
                    .await;
                push_change(
                    &mut changed,
                    detail,
                    "backup_cadence",
                    live.backup_cadence.as_str(),
                    cadence,
                    r,
                );
            }
            for (key, feature, want_n, live_n) in [
                (
                    BACKUP_KV_INTERVAL_DAYS,
                    "backup_interval_days",
                    want.backup_interval_days,
                    live.backup_interval_days,
                ),
                (
                    BACKUP_KV_KEEP_DAYS,
                    "backup_keep_days",
                    want.backup_keep_days,
                    live.backup_keep_days,
                ),
                (
                    BACKUP_KV_KEEP_LAST,
                    "backup_keep_last",
                    want.backup_keep_last,
                    live.backup_keep_last,
                ),
            ] {
                if want_n != live_n {
                    let r = self
                        .hosting_kv_set(id.to_string(), key.into(), want_n.to_string())
                        .await;
                    push_change(
                        &mut changed,
                        detail,
                        feature,
                        &live_n.to_string(),
                        &want_n.to_string(),
                        r,
                    );
                }
            }
        }
        changed
    }

    /// Flip uptime monitoring without disturbing anything else on the
    /// monitor row. `monitor_set` overwrites the whole config, so the
    /// current path / interval / alert targets are read back and passed
    /// through — an entitlement must not quietly reset a site's alert
    /// email to nobody.
    pub(super) async fn package_set_monitoring(
        &self,
        detail: &HostingDetail,
        enabled: bool,
    ) -> Result<(), RpcError> {
        let cur = hyperion_state::monitors::get(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("monitor read: {e}")))?;
        let (url_path, interval, after_fails, email, slack, webhook) = match cur {
            Some(c) => (
                Some(c.url_path),
                Some(c.interval_secs),
                Some(c.alert_after_fails),
                c.alert_email,
                c.alert_slack_webhook,
                c.alert_webhook_url,
            ),
            None => (None, None, None, None, None, None),
        };
        self.monitor_set(
            HostingSelector::Id(detail.id.clone()),
            enabled,
            url_path,
            interval,
            after_fails,
            email,
            slack,
            // This path only flips `enabled`; it re-reads and re-sends every
            // other field, so it never removes anything.
            false,
            webhook,
        )
        .await
    }

    /// Put the WAF on exactly `level` through the vhost-options path (vhost
    /// re-render + `nginx -t`). Off goes through `waf_turn_off`, so rules
    /// pinned on go too — the same "no WAF" the old switch meant.
    pub(super) async fn package_set_waf_level(
        &self,
        detail: &HostingDetail,
        level: hyperion_types::waf::WafLevel,
    ) -> Result<(), RpcError> {
        // Re-read: one push may write the firewall AND the rule set, and
        // starting the second from the caller's snapshot would undo the first.
        let mut options = self
            .get(HostingSelector::Id(detail.id.clone()))
            .await?
            .vhost_options;
        if level == hyperion_types::waf::WafLevel::Off {
            options.waf_turn_off();
        } else {
            options.set_waf_level(level);
        }
        self.set_vhost_options(HostingSelector::Id(detail.id.clone()), options, None)
            .await?;
        Ok(())
    }

    /// Set the Core Rule Set mode, leaving paranoia, threshold, the WordPress
    /// exclusions and the operator's own exclusions as they are — those are
    /// tuning for one site, not something a plan can know.
    pub(super) async fn package_set_crs(
        &self,
        detail: &HostingDetail,
        mode: hyperion_types::crs::CrsMode,
    ) -> Result<(), RpcError> {
        // Re-read, for the same reason as `package_set_waf_level`.
        let mut options = self
            .get(HostingSelector::Id(detail.id.clone()))
            .await?
            .vhost_options;
        options.crs_mode = mode.as_str().to_string();
        self.set_vhost_options(HostingSelector::Id(detail.id.clone()), options, None)
            .await?;
        Ok(())
    }
}

// ─── care packages ──────────────────────────────────────────────────

/// One feature the entitlement layer actually wrote. The audit payload
/// and the drift log line are both built from these.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(super) struct FeatureChange {
    pub(super) feature: &'static str,
    pub(super) from: String,
    pub(super) to: String,
}

/// Record a feature write that landed, or log one that didn't. A failed
/// setter must NOT appear in the result: the audit entry would claim a
/// change that never happened, and the drift tick is already the retry.
pub(super) fn push_change(
    out: &mut Vec<FeatureChange>,
    detail: &HostingDetail,
    feature: &'static str,
    from: &str,
    to: &str,
    result: Result<(), RpcError>,
) {
    match result {
        Ok(()) => out.push(FeatureChange {
            feature,
            from: from.to_string(),
            to: to.to_string(),
        }),
        Err(e) => tracing::warn!(
            domain = %detail.domain,
            hosting_id = %detail.id.as_str(),
            feature,
            error = %e,
            "care package: could not apply a paid feature — retrying on the next tick"
        ),
    }
}

/// The two values the kv-backed toggles store. `wp_auto_update` reads
/// anything that is not "off" as on, so "on" is the only enabled spelling
/// we ever write.
pub(super) fn feature_kv_value(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

/// The WAF level a package's firewall intent drives the site to, given the
/// level it is on now — `None` when the package leaves the firewall alone.
/// "At least Standard" keeps a Strict the operator set by hand: the promise
/// is "protected", and Strict is that too.
pub(super) fn package_waf_target(
    want: Option<hyperion_types::waf::WafLevel>,
    live: hyperion_types::waf::WafLevel,
) -> Option<hyperion_types::waf::WafLevel> {
    use hyperion_types::waf::WafLevel;
    Some(match want? {
        WafLevel::Standard if live == WafLevel::Strict => WafLevel::Strict,
        other => other,
    })
}

/// A captured prior value as a restore intent. `None` — the package never
/// forced this feature — stays `Leave`, so cancelling leaves it alone.
pub(super) fn toggle_of(prior: Option<bool>) -> FeatureToggle {
    match prior {
        Some(true) => FeatureToggle::On,
        Some(false) => FeatureToggle::Off,
        None => FeatureToggle::Leave,
    }
}

/// URL/API handle for a package: "Péče Plus" → "pece-plus".
///
/// Folds the Czech/Slovak diacritics an operator actually types (the panel
/// is Czech), lower-cases, and collapses everything else into single
/// dashes. Anything unfoldable is dropped, so a name with no ASCII left
/// yields "" — the caller turns that into "set a slug yourself" rather
/// than inventing a handle nobody can guess.
pub(super) fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in slug_fold(input).chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// Package-definition validation. Same shape as `validate_profile`:
/// normalise in place, and reject anything that would otherwise fail late
/// or silently.
pub(super) fn validate_package(mut p: PackageInput) -> Result<PackageInput, RpcError> {
    p.name = p.name.trim().to_string();
    if p.name.is_empty() {
        return Err(RpcError::Validation {
            message: "package name must not be empty".into(),
        });
    }
    if p.name.chars().count() > 64 {
        return Err(RpcError::Validation {
            message: "package name max 64 chars".into(),
        });
    }
    p.description = p.description.trim().to_string();
    // The web layer normally derives + de-duplicates the slug, but hctl and
    // `/api/v1` can post an empty one — and two empty slugs collide on a
    // UNIQUE index, which reads as nothing an operator can act on.
    p.slug = slugify(if p.slug.trim().is_empty() {
        &p.name
    } else {
        &p.slug
    });
    if p.slug.is_empty() {
        return Err(RpcError::Validation {
            message:
                "could not derive a slug from the package name — set one explicitly (a-z, 0-9, -)"
                    .into(),
        });
    }
    if p.slug.chars().count() > 64 {
        return Err(RpcError::Validation {
            message: "package slug max 64 chars".into(),
        });
    }
    // Pricing is display text plus the reminder cadence — but a negative
    // amount, or an interval the sweep cannot step, is a silent
    // never-reminds bug rather than a cosmetic one.
    if p.price_minor.is_some_and(|m| m < 0) {
        return Err(RpcError::Validation {
            message: "price must not be negative".into(),
        });
    }
    p.price_currency = p
        .price_currency
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty());
    p.price_interval = p
        .price_interval
        .map(|i| i.trim().to_lowercase())
        .filter(|i| !i.is_empty());
    if let Some(iv) = p.price_interval.as_deref() {
        if billing_interval_secs(iv).is_none() {
            return Err(RpcError::Validation {
                message: "price interval must be monthly | quarterly | yearly".into(),
            });
        }
    }
    // A language the letter pack does not know resolves to English silently,
    // so an unknown one is rejected here rather than stored. The web form
    // already gates this; `hctl` and `/api/v1` post the same struct.
    p.letters_lang = p.letters_lang.trim().to_lowercase();
    if !matches!(p.letters_lang.as_str(), "" | "en" | "cs") {
        return Err(RpcError::Validation {
            message: "letters language must be en | cs, or empty for no opinion".into(),
        });
    }
    p.check_items = validate_check_items(&p.check_items)?;
    p.report_omit = validate_report_omit(&p.report_omit)?;
    // Custom backup period + retention overrides, same bounds as a profile
    // (migration 070): the scheduler only honours a 1..=365 interval, and
    // the retention clamps stop a pasted number from becoming an absurd
    // cutoff. 0 stays 0 — "no opinion", the preset schedule / node rule.
    p.features.backup_interval_days = p.features.backup_interval_days.clamp(0, 365);
    p.features.backup_keep_days = p.features.backup_keep_days.clamp(0, 36_500);
    p.features.backup_keep_last = p.features.backup_keep_last.clamp(0, 1_000);
    Ok(p)
}

/// Earliest start date accepted: 2015-01-01 UTC. Far enough back for any
/// customer who ever paid, near enough that a pasted epoch-in-milliseconds or a
/// year typed as `0024` is refused instead of becoming a first report that
/// "covers" a century.
pub(super) const VALID_FROM_MIN: i64 = 1_420_070_400;
/// Furthest a start date may lie ahead: a plan signed now for next year's term.
pub(super) const VALID_FROM_MAX_AHEAD_SECS: i64 = 366 * 86_400;

/// Check the operator's start date. `None` passes through (starts now).
pub(super) fn validate_valid_from(
    valid_from: Option<i64>,
    now: i64,
) -> Result<Option<i64>, RpcError> {
    let Some(t) = valid_from else {
        return Ok(None);
    };
    if t < VALID_FROM_MIN {
        return Err(RpcError::Validation {
            message: "the start date cannot be before 1 January 2015".into(),
        });
    }
    if t > now + VALID_FROM_MAX_AHEAD_SECS {
        return Err(RpcError::Validation {
            message: "the start date cannot be more than a year ahead".into(),
        });
    }
    Ok(Some(t))
}

/// Normalise the sections a plan leaves out of the customer letter into the
/// exact comma list that gets stored: known ids only, in letter order.
///
/// A plan that leaves out EVERY section would send a letter with no body, which
/// is never what anybody meant — the way to send no report is the cadence, and
/// saying so here beats the customer receiving a salutation and a signature.
pub(super) fn validate_report_omit(raw: &str) -> Result<String, RpcError> {
    let omit = hyperion_types::report_sections::ReportOmit::parse(raw);
    if omit.leaves_out_everything() {
        return Err(RpcError::Validation {
            message: "a care plan must send at least one report section — to send no report, \
                      set the report cadence to off"
                .into(),
        });
    }
    Ok(omit.to_stored())
}

/// How many items one plan may promise, and how long each may be.
///
/// A ceiling exists because this string is SNAPSHOTTED onto every activation
/// and frozen into up to 24 months of every site's record: a pasted document
/// in this field is not a cosmetic problem, it is multiplied by the estate.
pub(super) const MAX_CHECK_ITEMS: usize = 30;
pub(super) const MAX_CHECK_LABEL: usize = 120;
pub(super) const MAX_CHECK_DETAIL: usize = 300;

/// Normalise one checklist item id.
///
/// NOT `slugify`: that maps `_` to `-`, and `post_update` is a built-in id
/// with marks filed under it on every site that has ever ticked it. Running
/// the package slug rule over these would rename it to `post-update` the
/// first time anybody edited a plan, orphaning that history everywhere at
/// once. Underscores are therefore kept; everything else follows the same
/// fold-and-hyphenate rule so the web layer's derived ids pass through
/// unchanged.
pub(super) fn check_item_id(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in slug_fold(raw).chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// Lowercase and fold the diacritics `slugify` folds, without touching
/// anything else. Shared so the two rules cannot drift apart on which
/// letters they know.
pub(super) fn slug_fold(input: &str) -> String {
    const FOLD: &[(char, char)] = &[
        ('á', 'a'),
        ('ä', 'a'),
        ('č', 'c'),
        ('ď', 'd'),
        ('é', 'e'),
        ('ě', 'e'),
        ('í', 'i'),
        ('ĺ', 'l'),
        ('ľ', 'l'),
        ('ň', 'n'),
        ('ó', 'o'),
        ('ô', 'o'),
        ('ö', 'o'),
        ('ŕ', 'r'),
        ('ř', 'r'),
        ('š', 's'),
        ('ť', 't'),
        ('ú', 'u'),
        ('ů', 'u'),
        ('ü', 'u'),
        ('ý', 'y'),
        ('ž', 'z'),
    ];
    input
        .to_lowercase()
        .chars()
        .map(|ch| {
            FOLD.iter()
                .find(|(from, _)| *from == ch)
                .map(|(_, to)| *to)
                .unwrap_or(ch)
        })
        .collect()
}

/// Normalise a plan's checklist into the exact JSON that gets stored.
///
/// Returns the EMPTY string for a list that is absent, unreadable or exactly
/// the built-in four. That collapse is deliberate: "" is what every package
/// held before this existed and is what the resolver reads as "the built-in
/// four", so a plan nobody edited keeps saying it in one way rather than two.
pub(super) fn validate_check_items(raw: &str) -> Result<String, RpcError> {
    use hyperion_types::care_check::{
        builtin_check_items, check_items_to_json, parse_check_items_raw, CheckItemDef,
    };
    let parsed = parse_check_items_raw(raw);
    if parsed.is_empty() {
        // Covers both "the caller sent nothing" and "the caller sent
        // something we could not read". Neither may shrink what the plan
        // promises, and both mean the built-in four.
        return Ok(String::new());
    }
    if parsed.len() > MAX_CHECK_ITEMS {
        return Err(RpcError::Validation {
            message: format!("a care plan may list at most {MAX_CHECK_ITEMS} monthly checks"),
        });
    }
    let mut out: Vec<CheckItemDef> = Vec::with_capacity(parsed.len());
    for item in parsed {
        let id = check_item_id(&item.id);
        if id.is_empty() {
            return Err(RpcError::Validation {
                message: format!("checklist item \"{}\" has no usable id", item.label.trim()),
            });
        }
        // Ids key the marks. Two items sharing one would make a single tick
        // satisfy both, which is the one failure this list must not have.
        if out.iter().any(|k: &CheckItemDef| k.id == id) {
            return Err(RpcError::Validation {
                message: format!("two checklist items share the id \"{id}\""),
            });
        }
        let label = item.label.trim();
        if label.chars().count() > MAX_CHECK_LABEL {
            return Err(RpcError::Validation {
                message: format!("checklist item name max {MAX_CHECK_LABEL} chars"),
            });
        }
        let detail = item.detail.trim();
        if detail.chars().count() > MAX_CHECK_DETAIL {
            return Err(RpcError::Validation {
                message: format!("checklist item note max {MAX_CHECK_DETAIL} chars"),
            });
        }
        out.push(CheckItemDef {
            id,
            label: label.to_string(),
            detail: detail.to_string(),
        });
    }
    if out == builtin_check_items() {
        return Ok(String::new());
    }
    Ok(check_items_to_json(&out))
}

pub(super) fn package_input_to_new(input: PackageInput) -> hyperion_state::packages::NewPackage {
    hyperion_state::packages::NewPackage {
        name: input.name,
        slug: input.slug,
        description: input.description,
        enabled: input.enabled,
        price_minor: input.price_minor,
        price_currency: input.price_currency,
        price_interval: input.price_interval,
        features: input.features,
        letters_lang: input.letters_lang,
        check_items: input.check_items,
        report_omit: input.report_omit,
    }
}

pub(super) fn package_row_to_wire(r: hyperion_state::packages::PackageRow) -> ServicePackage {
    // Both read `r` — take them before the struct literal moves out of it.
    let features = r.features();
    let enabled = r.is_enabled();
    ServicePackage {
        id: r.id,
        name: r.name,
        slug: r.slug,
        description: r.description,
        enabled,
        price_minor: r.price_minor,
        price_currency: r.price_currency,
        price_interval: r.price_interval,
        letters_lang: r.letters_lang,
        check_items: r.check_items,
        report_omit: r.report_omit,
        features,
        // Filled in by package_list / package_get; 0 from the bare conversion.
        active_count: 0,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

/// `package_name` is looked up by the caller and is empty once the
/// definition is gone — the activation itself outlives it.
pub(super) fn activation_row_to_wire(
    r: hyperion_state::packages::HostingPackageRow,
    package_name: String,
) -> HostingPackage {
    HostingPackage {
        id: r.id,
        hosting_id: r.hosting_id,
        package_id: r.package_id,
        package_name,
        letters_lang: r.letters_lang,
        check_items: r.check_items,
        report_omit: r.report_omit,
        valid_from: r.valid_from,
        enforcement_started: r.enforcement_started,
        price_minor: r.price_minor,
        price_currency: r.price_currency,
        price_interval: r.price_interval,
        next_billing_at: r.next_billing_at,
        state: r.state,
        activated_at: r.activated_at,
        cancelled_at: r.cancelled_at,
        prior_state_json: r.prior_state_json,
    }
}

/// The last "protection is not running" reason a care plan's protection check
/// told the operator about for a site (`hosting_kv`). Empty = nothing
/// outstanding. Lets the check alert once per change instead of every tick.
pub(super) const PACKAGE_PROTECTION_WARNED_KV: &str = "package_protection_warned";

/// When this node last tried, on its own, to install the ModSecurity engine a
/// care plan's Core Rule Set needs (`node_kv`, unix seconds). Written BEFORE
/// the attempt, so an install that dies half-way is not retried every tick.
pub(super) const PACKAGE_MODSEC_AUTO_KV: &str = "package_modsec_auto_install_at";

/// How long a failed automatic install waits before the next one. apt on a
/// broken mirror or a read-only /usr fails the same way every time; the
/// operator's alert already says ModSecurity is missing.
pub(super) const PACKAGE_MODSEC_AUTO_RETRY_SECS: i64 = 6 * 3600;
