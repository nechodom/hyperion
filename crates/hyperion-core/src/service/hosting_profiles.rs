//! Hosting profiles: the templates and applying them to sites.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ================================================================
    //  Hosting profiles (templates)
    // ================================================================

    pub async fn profile_list(&self) -> Result<Vec<HostingProfile>, RpcError> {
        let rows = profiles::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile list: {e}")))?;
        // One GROUP BY query for all counts, then attach by id (avoids N+1).
        let counts: std::collections::HashMap<i64, i64> = profiles::counts_by_profile(&self.pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        Ok(rows
            .into_iter()
            .map(|r| {
                let mut w = profile_row_to_wire(r);
                w.in_use_count = counts.get(&w.id).copied().unwrap_or(0);
                w
            })
            .collect())
    }

    pub async fn profile_get(&self, id: i64) -> Result<HostingProfile, RpcError> {
        let row = profiles::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile get: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "profile".into(),
                id: id.to_string(),
            })?;
        let mut w = profile_row_to_wire(row);
        w.in_use_count = profiles::count_in_use(&self.pool, id).await.unwrap_or(0);
        Ok(w)
    }

    /// The live hosting ids on this profile ON THIS NODE — the web unions these
    /// across nodes for cluster-wide "re-apply to all".
    pub async fn profile_usage(&self, id: i64) -> Result<Vec<String>, RpcError> {
        profiles::hosting_ids_for_profile(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile usage: {e}")))
    }

    /// (profile_id, live-hosting count) for every profile with apply rows on
    /// THIS node — the web sums these across nodes for the "in use: N" badge.
    pub async fn profile_usage_counts(&self) -> Result<Vec<(i64, i64)>, RpcError> {
        profiles::counts_by_profile(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile usage counts: {e}")))
    }

    pub async fn profile_create(&self, input: ProfileInput) -> Result<HostingProfile, RpcError> {
        let validated = validate_profile(input)?;
        let now = now_secs();
        let id = profiles::insert(&self.pool, &profile_input_to_new(validated), now)
            .await
            .map_err(|e| RpcError::AlreadyExists {
                kind: "profile".into(),
                id: e.to_string(),
            })?;
        let row = profiles::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile re-read: {e}")))?
            .ok_or(RpcError::Internal {
                message: "row vanished after write (concurrent delete?)".into(),
            })?;
        self.append_audit(
            "profile.create",
            None,
            &serde_json::json!({"id": id, "name": row.name}).to_string(),
            "ok",
        )
        .await;
        Ok(profile_row_to_wire(row))
    }

    pub async fn profile_update(
        &self,
        id: i64,
        input: ProfileInput,
    ) -> Result<HostingProfile, RpcError> {
        let validated = validate_profile(input)?;
        profiles::update(&self.pool, id, &profile_input_to_new(validated), now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile update: {e}")))?;
        let row = profiles::get(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile re-read: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "profile".into(),
                id: id.to_string(),
            })?;
        self.append_audit(
            "profile.update",
            None,
            &serde_json::json!({"id": id, "name": row.name}).to_string(),
            "ok",
        )
        .await;
        Ok(profile_row_to_wire(row))
    }

    pub async fn profile_delete(&self, id: i64) -> Result<(), RpcError> {
        profiles::delete(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("profile delete: {e}")))?;
        self.append_audit(
            "profile.delete",
            None,
            &serde_json::json!({"id": id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Apply a profile to a hosting. Copies the profile's limits +
    /// expiry policy + pricing onto the hosting and records the link.
    pub async fn profile_apply(
        &self,
        sel: HostingSelector,
        profile_id: i64,
        skip_wp_items: bool,
        profile: Option<hyperion_types::HostingProfile>,
    ) -> Result<ProfileApply, RpcError> {
        let detail = self.get(sel).await?;
        // The master passes the resolved profile inline (the table is
        // master-only). Fall back to a local lookup only when none was supplied
        // (i.e. this node IS the master, or an old caller) — on a worker that
        // would 404, which is the multi-node bug this closes.
        let p = match profile {
            Some(p) => p,
            None => self.profile_get(profile_id).await?,
        };

        // Push the FPM-pool / DB limits via the limits path. Disk / memory /
        // bandwidth caps do NOT go here: `limits.disk_hard_bytes` is inert (it's
        // never pushed to setquota and the enforce loop never reads it). They go
        // through quota_set below — the ENFORCED hosting_quotas path.
        let mut limits = hyperion_types::HostingLimits::defaults();
        limits.php_memory_mb = p.php_memory_mb;
        limits.php_max_exec_secs = p.php_max_exec_secs;
        limits.php_max_children = p.php_max_children;
        limits.php_max_requests = p.php_max_requests;
        limits.db_max_connections = p.db_max_connections;
        self.set_limits(HostingSelector::Id(detail.id.clone()), limits)
            .await?;

        // Disk + memory + bandwidth caps + the overage policy → the enforced
        // hosting_quotas row (setquota / quota_enforce_tick read it). quota_set
        // also seeds quota_exceed_action and pushes the cap to the kernel, so a
        // profile-created site's disk cap actually enforces and its over-quota
        // notify/suspend action can fire. Only when the profile sets a cap;
        // otherwise just seed the overage policy for a later per-hosting cap.
        if p.disk_hard_mb.is_some() || p.disk_soft_mb.is_some() || p.mem_limit_mib.is_some() {
            // A kernel-push failure is recorded in hosting_quotas.last_error (not
            // an Err); quota_set only Errs on a Validation reject, which a
            // validated profile shouldn't hit — but if it does, log it instead of
            // silently reporting a clean apply.
            if let Err(e) = self
                .quota_set(
                    HostingSelector::Id(detail.id.clone()),
                    p.disk_soft_mb.unwrap_or(0) * 1024,
                    p.disk_hard_mb.unwrap_or(0) * 1024,
                    p.mem_limit_mib.unwrap_or(0),
                    0,                            // bw soft (unused)
                    p.bw_monthly_mb.unwrap_or(0), // monthly allowance → bw hard
                    &p.quota_exceed_action,
                )
                .await
            {
                tracing::warn!(
                    hosting_id = %detail.id.as_str(),
                    error = %e,
                    "profile apply: quota_set rejected the profile's caps; disk/mem quota not set"
                );
            }
        } else {
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                detail.id.as_str(),
                QUOTA_KV_ACTION,
                QuotaExceedAction::parse(&p.quota_exceed_action).as_str(),
                now_secs(),
            )
            .await;
        }

        // Seed the recurring-backup cadence from the profile ("off" by default =
        // nothing scheduled). The per-node scheduled-backup driver reads this
        // per-hosting value; operators can override it on the Backups card.
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            detail.id.as_str(),
            BACKUP_KV_CADENCE,
            canonical_backup_cadence(&p.backup_cadence),
            now_secs(),
        )
        .await;
        // Custom period (used when cadence == "custom") + retention overrides.
        // Written every apply, 0 included, so dropping them on the profile and
        // re-applying reverts a site to the presets / the node-wide rule.
        for (k, v) in [
            (BACKUP_KV_INTERVAL_DAYS, p.backup_interval_days),
            (BACKUP_KV_KEEP_DAYS, p.backup_keep_days),
            (BACKUP_KV_KEEP_LAST, p.backup_keep_last),
        ] {
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                detail.id.as_str(),
                k,
                &v.to_string(),
                now_secs(),
            )
            .await;
        }

        // Push expiry policy (without changing expires_at — operator sets that).
        let cur = self
            .get_expiry(HostingSelector::Id(detail.id.clone()))
            .await
            .unwrap_or_else(|_| hyperion_types::HostingExpiry::defaults());
        let expiry = hyperion_types::HostingExpiry {
            expires_at: cur.expires_at,
            owner_email: cur.owner_email,
            // Carried through: applying a profile changes the expiry POLICY,
            // not when the customer joined.
            customer_since: cur.customer_since,
            grace_days: p.expiry_grace_days,
            warning_offsets_days: p.expiry_warning_offsets.clone(),
        };
        self.set_expiry(HostingSelector::Id(detail.id.clone()), expiry)
            .await?;

        // Pricing snapshot + billing clock (see `next_billing_on_price_change`).
        // A price the operator set on this hosting and pinned stays: the
        // profile's price is only copied over an unpinned one.
        let now = now_secs();
        let existing = profiles::get_apply(&self.pool, &detail.id)
            .await
            .ok()
            .flatten();
        let price_kept = existing.as_ref().is_some_and(|e| e.price_pinned);
        let (price_minor, price_currency, price_interval) = match existing.as_ref() {
            Some(e) if price_kept => (
                e.price_minor,
                e.price_currency.clone(),
                e.price_interval.clone(),
            ),
            _ => (
                p.price_minor,
                p.price_currency.clone(),
                p.price_interval.clone(),
            ),
        };
        let next = next_billing_on_price_change(existing.as_ref(), price_interval.as_deref(), now);
        profiles::upsert_apply(
            &self.pool,
            &detail.id,
            Some(p.id),
            price_minor,
            price_currency.as_deref(),
            price_interval.as_deref(),
            next,
            p.slack_webhook.as_deref(),
            // Snapshotted for the same reason the price and the Slack
            // webhook are: deleting the profile sets `profile_id` NULL, and
            // a live lookup would silently stop alerting the people this
            // site's alerts were going to.
            Some(p.alert_emails.as_str()),
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("apply: {e}")))?;

        // Install WP plugins + themes from the profile, if any.
        // Best-effort: a failure here logs + appends an audit
        // entry but doesn't roll back the limits/expiry/price
        // change above. The operator can see what went wrong on
        // the per-hosting WordPress tab.
        //
        // `skip_wp_items` — the caller (the web layer's WP-install
        // job) installs items one-by-one via ProfileWpItemInstall so
        // it can show per-plugin progress; running them here too
        // would double-install.
        if !skip_wp_items && (!p.wp_plugins.trim().is_empty() || !p.wp_themes.trim().is_empty()) {
            let wp_outcome = self
                .apply_profile_wp_items(&detail, &p.wp_plugins, &p.wp_themes)
                .await;
            let (installed, failed) = match &wp_outcome {
                Ok(stats) => (stats.0, stats.1),
                Err(_) => (0, 0),
            };
            self.append_audit(
                "profile.apply.wp",
                Some(detail.id.as_str()),
                &serde_json::json!({
                    "profile_id": profile_id,
                    "installed": installed,
                    "failed": failed,
                    "error": wp_outcome.as_ref().err().map(|e| e.to_string()),
                })
                .to_string(),
                if wp_outcome.is_ok() { "ok" } else { "warn" },
            )
            .await;
        }

        self.append_audit(
            "profile.apply",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "profile_id": profile_id,
                "profile_name": p.name,
                "price_kept": price_kept,
            })
            .to_string(),
            "ok",
        )
        .await;

        Ok(ProfileApply {
            hosting_id: detail.id,
            profile_id: Some(p.id),
            price_minor,
            price_currency,
            price_interval,
            next_billing_at: next,
            applied_at: now,
            price_pinned: price_kept,
        })
    }

    /// Walk a profile's wp_plugins + wp_themes text fields and
    /// install each item via wp-cli. Skips empty lines and `#…`
    /// comments. Returns (installed_count, failed_count).
    ///
    /// Line syntax (per profile.rs::HostingProfile docs):
    ///   - `<slug>`           → install from wordpress.org
    ///   - `@asset:<id>`      → install from the local uploaded
    ///                          ZIP at /var/lib/hyperion/wp-assets/<id>/
    ///   - trailing `!`       → also activate after install
    ///   - leading `#`        → comment, skipped
    pub(super) async fn apply_profile_wp_items(
        &self,
        detail: &hyperion_types::HostingDetail,
        plugins_text: &str,
        themes_text: &str,
    ) -> Result<(usize, usize), RpcError> {
        let mut ok = 0usize;
        let mut fail = 0usize;
        for kind in ["plugin", "theme"] {
            let text = if kind == "plugin" {
                plugins_text
            } else {
                themes_text
            };
            for raw in text.lines() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                match self.install_profile_wp_line(detail, kind, line).await {
                    Ok(_) => ok += 1,
                    Err(e) => {
                        tracing::warn!(
                            kind = kind,
                            line = %line,
                            error = %e,
                            "profile wp_item install failed"
                        );
                        fail += 1;
                    }
                }
            }
        }
        Ok((ok, fail))
    }

    /// Install ONE profile wp_plugins / wp_themes line. Shared by
    /// the bulk `apply_profile_wp_items` walk above and the
    /// `ProfileWpItemInstall` RPC (which the web layer's WP-install
    /// job calls once per item to get per-plugin progress).
    ///
    /// Returns `(human_label, activated)` — the asset's
    /// original_name for `@asset:` lines, the slug otherwise.
    pub(super) async fn install_profile_wp_line(
        &self,
        detail: &hyperion_types::HostingDetail,
        kind: &str,
        line: &str,
    ) -> Result<(String, bool), RpcError> {
        let line = line.trim();
        // Strip an inline `# comment` so picker-generated lines like
        // `@asset:7    # client plugin` parse cleanly.
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return Err(RpcError::Validation {
                message: "empty profile line".into(),
            });
        }
        let (item, activate) = if let Some(stripped) = line.strip_suffix('!') {
            (stripped.trim(), true)
        } else {
            (line, false)
        };
        // Resolve @asset:<id> → on-disk path + friendly label.
        let (source, label) = if let Some(rest) = item.strip_prefix("@asset:") {
            let id: i64 = rest.trim().parse().map_err(|_| RpcError::Validation {
                message: format!("profile {kind} line `{line}` has bad asset id"),
            })?;
            let row = hyperion_state::wp_assets::get_by_id(&self.pool, id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("wp_asset lookup: {e}")))?
                .ok_or_else(|| RpcError::NotFound {
                    kind: "wp_asset".into(),
                    id: id.to_string(),
                })?;
            if row.kind != kind {
                return Err(RpcError::Validation {
                    message: format!(
                        "profile {kind} line `{line}` references asset id {id} which is a {} (mismatch)",
                        row.kind
                    ),
                });
            }
            (
                wp_asset_disk_path(id, &row.stored_filename),
                row.original_name,
            )
        } else {
            (item.to_string(), item.to_string())
        };
        self.adapters
            .wp_cli(
                &detail.system_user,
                // root_dir, not a hand-built path: identical only while
                // home_root is the default "/home", and silently wrong the
                // moment an operator changes it.
                &detail.root_dir,
                kind,
                &source,
                activate,
            )
            .await
            .map_err(|e| {
                RpcError::Internal_with(format!("wp {kind} install {label} failed: {e}"))
            })?;
        Ok((label, activate))
    }

    /// Public entry point for the `ProfileWpItemInstall` RPC.
    pub async fn profile_wp_item_install(
        &self,
        sel: HostingSelector,
        item_kind: &str,
        line: &str,
    ) -> Result<(String, bool), RpcError> {
        if item_kind != "plugin" && item_kind != "theme" {
            return Err(RpcError::Validation {
                message: format!("item_kind must be plugin|theme, got {item_kind:?}"),
            });
        }
        let detail = self.get(sel).await?;
        let out = self.install_profile_wp_line(&detail, item_kind, line).await;
        let (state_str, err_str) = match &out {
            Ok(_) => ("ok", None),
            Err(e) => ("failed", Some(e.to_string())),
        };
        self.append_audit(
            "profile.wp_item.install",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "kind": item_kind,
                "line": line,
                "error": err_str,
            })
            .to_string(),
            state_str,
        )
        .await;
        out
    }

    pub async fn profile_get_apply(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<ProfileApply>, RpcError> {
        let detail = self.get(sel).await?;
        let row = profiles::get_apply(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("apply read: {e}")))?;
        Ok(row.map(|r| ProfileApply {
            hosting_id: r.hosting_id,
            profile_id: r.profile_id,
            price_minor: r.price_minor,
            price_currency: r.price_currency,
            price_interval: r.price_interval,
            next_billing_at: r.next_billing_at,
            applied_at: r.applied_at,
            price_pinned: r.price_pinned,
        }))
    }
}

pub(super) fn validate_profile(mut p: ProfileInput) -> Result<ProfileInput, RpcError> {
    p.name = p.name.trim().to_string();
    if p.name.is_empty() {
        return Err(RpcError::Validation {
            message: "profile name must not be empty".into(),
        });
    }
    if p.name.len() > 64 {
        return Err(RpcError::Validation {
            message: "profile name max 64 chars".into(),
        });
    }
    if p.expiry_warning_offsets.trim().is_empty() {
        p.expiry_warning_offsets = "30,7,1".into();
    }
    // SECURITY (sec-findings #3): the Slack webhook is later fired by the root
    // agent from inside the trust boundary. Pin the scheme to https:// at the
    // boundary (the SSRF guard in notify_slack blocks internal IPs at send
    // time; this rejects http://internal and gopher:// up front), matching how
    // set_monitor_config validates alert_slack_webhook.
    p.slack_webhook = p
        .slack_webhook
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(ref u) = p.slack_webhook {
        if !u.starts_with("https://") {
            return Err(RpcError::Validation {
                message: "slack webhook must start with https://".into(),
            });
        }
    }
    if let Some(c) = &p.price_currency {
        if !c.chars().all(|ch| ch.is_ascii_uppercase()) || c.len() != 3 {
            return Err(RpcError::Validation {
                message: "price_currency must be 3 uppercase ISO-4217 letters".into(),
            });
        }
    }
    if let Some(iv) = &p.price_interval {
        if !matches!(iv.as_str(), "monthly" | "quarterly" | "yearly") {
            return Err(RpcError::Validation {
                message: "price_interval must be monthly | quarterly | yearly".into(),
            });
        }
    }
    // Numeric limits flow verbatim onto the live FPM pool / quota at apply, so
    // reject nonsensical values here (create AND update both call this). PHP
    // memory + the worker/request/connection counts must be at least 1; the
    // exec timeout + grace must be non-negative.
    for (val, what, min) in [
        (p.php_memory_mb, "PHP memory_limit (MiB)", 1),
        (p.php_max_children, "PHP max children", 1),
        (p.php_max_requests, "PHP max requests", 1),
        (p.db_max_connections, "DB max connections", 1),
        (p.php_max_exec_secs, "PHP max exec seconds", 0),
        (p.expiry_grace_days, "expiry grace days", 0),
    ] {
        if val < min {
            return Err(RpcError::Validation {
                message: format!("{what} must be >= {min}"),
            });
        }
    }
    // Caps are optional; when set they must be non-negative and the disk soft
    // cap must not exceed the hard cap (quota_set rejects soft > hard).
    for (val, what) in [
        (p.disk_hard_mb, "disk hard cap (MiB)"),
        (p.disk_soft_mb, "disk soft cap (MiB)"),
        (p.mem_limit_mib, "memory cap (MiB)"),
        (p.bw_monthly_mb, "monthly bandwidth (MiB)"),
    ] {
        if let Some(v) = val {
            if v < 0 {
                return Err(RpcError::Validation {
                    message: format!("{what} must be >= 0"),
                });
            }
        }
    }
    if let (Some(soft), Some(hard)) = (p.disk_soft_mb, p.disk_hard_mb) {
        if soft > 0 && hard > 0 && soft > hard {
            return Err(RpcError::Validation {
                message: "disk soft cap must be <= disk hard cap".into(),
            });
        }
    }
    // Reject a malformed expiry-warning-offsets CSV at save time instead of
    // silently dropping bad tokens (or falling back) later when the scheduler
    // parses it. Every comma-separated token must be a non-negative integer.
    if p.expiry_warning_offsets.split(',').any(|tok| {
        let t = tok.trim();
        t.is_empty() || t.parse::<i64>().map(|n| n < 0).unwrap_or(true)
    }) {
        return Err(RpcError::Validation {
            message: "expiry warning offsets must be comma-separated non-negative day counts (e.g. 30,7,1)".into(),
        });
    }
    // Constrain the small closed enums so a typo'd value fails loudly here
    // rather than silently coercing (quota action) or no-op'ing (db engine) at
    // apply. Empty = "no preference" and is allowed.
    if let Some(eng) = p.default_db_engine.as_deref() {
        if !matches!(eng, "" | "mariadb" | "postgres" | "none") {
            return Err(RpcError::Validation {
                message: "default DB engine must be mariadb | postgres | none".into(),
            });
        }
    }
    if !p.quota_exceed_action.trim().is_empty()
        && !matches!(p.quota_exceed_action.as_str(), "notify" | "suspend")
    {
        return Err(RpcError::Validation {
            message: "quota overage action must be notify | suspend".into(),
        });
    }
    if !p.backup_cadence.trim().is_empty()
        && !matches!(
            p.backup_cadence.as_str(),
            "off" | "daily" | "weekly" | "monthly"
        )
    {
        return Err(RpcError::Validation {
            message: "backup cadence must be off | daily | weekly | monthly".into(),
        });
    }
    Ok(p)
}

pub(super) fn profile_input_to_new(input: ProfileInput) -> hyperion_state::profiles::NewProfile {
    hyperion_state::profiles::NewProfile {
        name: input.name,
        description: input.description,
        php_memory_mb: input.php_memory_mb,
        php_max_exec_secs: input.php_max_exec_secs,
        php_max_children: input.php_max_children,
        php_max_requests: input.php_max_requests,
        db_max_connections: input.db_max_connections,
        disk_hard_mb: input.disk_hard_mb,
        bw_monthly_mb: input.bw_monthly_mb,
        expiry_grace_days: input.expiry_grace_days,
        expiry_warning_offsets: input.expiry_warning_offsets,
        price_minor: input.price_minor,
        price_currency: input.price_currency,
        price_interval: input.price_interval,
        slack_webhook: input.slack_webhook,
        alert_emails: input.alert_emails,
        wp_plugins: input.wp_plugins,
        wp_themes: input.wp_themes,
        // Normalise empty strings to None so the DB stores NULL and
        // the wizard's "no preference" path stays clean.
        default_php_version: input.default_php_version.filter(|s| !s.trim().is_empty()),
        default_db_engine: input.default_db_engine.filter(|s| !s.trim().is_empty()),
        // Canonicalise to "notify" | "suspend" so a stray value never poisons
        // the seed.
        quota_exceed_action: QuotaExceedAction::parse(&input.quota_exceed_action)
            .as_str()
            .to_string(),
        disk_soft_mb: input.disk_soft_mb.filter(|m| *m > 0),
        mem_limit_mib: input.mem_limit_mib.filter(|m| *m > 0),
        backup_cadence: canonical_backup_cadence(&input.backup_cadence).to_string(),
        backup_interval_days: input.backup_interval_days.clamp(0, 365),
        backup_keep_days: input.backup_keep_days.clamp(0, 36_500),
        backup_keep_last: input.backup_keep_last.clamp(0, 1_000),
    }
}

pub(super) fn profile_row_to_wire(r: hyperion_state::profiles::ProfileRow) -> HostingProfile {
    HostingProfile {
        id: r.id,
        name: r.name,
        description: r.description,
        php_memory_mb: r.php_memory_mb,
        php_max_exec_secs: r.php_max_exec_secs,
        php_max_children: r.php_max_children,
        php_max_requests: r.php_max_requests,
        db_max_connections: r.db_max_connections,
        disk_hard_mb: r.disk_hard_mb,
        bw_monthly_mb: r.bw_monthly_mb,
        expiry_grace_days: r.expiry_grace_days,
        expiry_warning_offsets: r.expiry_warning_offsets,
        price_minor: r.price_minor,
        price_currency: r.price_currency,
        price_interval: r.price_interval,
        slack_webhook: r.slack_webhook,
        alert_emails: r.alert_emails,
        wp_plugins: r.wp_plugins,
        wp_themes: r.wp_themes,
        default_php_version: r.default_php_version,
        default_db_engine: r.default_db_engine,
        quota_exceed_action: r.quota_exceed_action,
        disk_soft_mb: r.disk_soft_mb,
        mem_limit_mib: r.mem_limit_mib,
        backup_cadence: r.backup_cadence,
        backup_interval_days: r.backup_interval_days,
        backup_keep_days: r.backup_keep_days,
        backup_keep_last: r.backup_keep_last,
        // Filled in by profile_list / profile_get; 0 from the bare conversion.
        in_use_count: 0,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}
