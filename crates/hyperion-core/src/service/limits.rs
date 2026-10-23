//! Per-hosting resource limits, PHP version, and the PHP memory/worker
//! automation.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Apply / replace the per-hosting limits. Persists the row, then asks the
    /// adapter to apply the PHP-FPM side effects. Returns the canonical row
    /// (so callers see exactly what was stored after defaults / clamping).
    pub async fn set_limits(
        &self,
        sel: HostingSelector,
        limits: hyperion_types::HostingLimits,
    ) -> Result<hyperion_types::HostingLimits, RpcError> {
        let detail = self.get(sel).await?;
        let before = hyperion_state::limits::get(&self.pool, &detail.id)
            .await
            .ok()
            .flatten()
            .map(|r| r.php_memory_mb);
        let limits = self.store_and_apply_limits(&detail, limits).await?;
        // A memory value typed by hand (or applied by a profile) is the new
        // floor for the automatic memory_limit. Saving the card UNCHANGED —
        // it shows the value the automation raised to — must not adopt that
        // raised value as the operator's own, or it would never come down.
        if before != Some(limits.php_memory_mb) {
            self.php_mem_auto_rebase(detail.id.as_str(), limits.php_memory_mb)
                .await;
        }
        Ok(limits)
    }

    /// Persist the limits row and rewrite the pool, without touching the
    /// automatic-memory floor. Shared by the operator path above and by
    /// [`Self::php_mem_auto_tick`].
    pub(super) async fn store_and_apply_limits(
        &self,
        detail: &HostingDetail,
        limits: hyperion_types::HostingLimits,
    ) -> Result<hyperion_types::HostingLimits, RpcError> {
        let limits = clamp_limits(limits);
        let row = limits_to_row(&detail.id, &limits, now_secs());
        hyperion_state::limits::upsert(&self.pool, &row)
            .await
            .map_err(|e| RpcError::Internal_with(format!("limits upsert: {e}")))?;
        if let Err(e) = self
            .adapters
            .apply_php_limits(
                &detail.system_user,
                &detail.domain,
                detail.php_version,
                limits.php_memory_mb,
                limits.php_max_exec_secs,
                limits.php_max_children,
                limits.php_max_requests,
            )
            .await
        {
            return Err(e.into());
        }
        Ok(limits)
    }

    /// Make `base_mb` the floor of an existing automatic-memory state.
    pub(super) async fn php_mem_auto_rebase(&self, hosting_id: &str, base_mb: i64) {
        use hyperion_types::phpmem;
        let Some(mut st) =
            hyperion_state::hosting_kv::get(&self.pool, hosting_id, phpmem::KV_STATE)
                .await
                .ok()
                .flatten()
                .and_then(|v| phpmem::State::parse(&v))
        else {
            return;
        };
        let now = now_secs();
        st.base_mb = base_mb;
        st.last_change_at = now;
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id,
            phpmem::KV_STATE,
            &st.to_json(),
            now,
        )
        .await;
    }

    /// Automatic PHP `memory_limit` (see `hyperion_types::phpmem`).
    ///
    /// For every live site with the automation on, read what nginx appended
    /// to its `error.log`, and when PHP ran out of memory at the limit in
    /// force, raise the pool's limit one step — bounded by the site's ceiling
    /// and by the node's RAM. A fortnight without running out takes it one
    /// step back towards the operator's own value. Turning the automation off
    /// puts the operator's value back.
    ///
    /// Returns how many pools it rewrote.
    pub async fn php_mem_auto_tick(&self) -> Result<i64, RpcError> {
        use hyperion_types::phpmem::{self, Step};
        let mem_total_mb = read_mem_total_mb().await;
        let mut acted = 0i64;
        for s in self.list().await? {
            let id = s.id.as_str().to_string();
            let kv = |k: &'static str| {
                let id = id.clone();
                async move {
                    hyperion_state::hosting_kv::get(&self.pool, &id, k)
                        .await
                        .ok()
                        .flatten()
                }
            };
            let enabled = kv(phpmem::KV_ENABLED).await.as_deref() == Some("on");
            let stored = kv(phpmem::KV_STATE)
                .await
                .and_then(|v| phpmem::State::parse(&v));
            if !enabled && stored.is_none() {
                continue;
            }
            // Suspended or trashed: the pool is not serving, nothing to learn
            // from its log and nothing worth rewriting.
            if s.state != HostingState::Active {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            if detail.php_version.is_none() || detail.system_user.trim().is_empty() {
                continue;
            }
            let limits = hyperion_state::limits::get(&self.pool, &detail.id)
                .await
                .ok()
                .flatten()
                .map(row_to_limits)
                .unwrap_or_else(hyperion_types::HostingLimits::defaults);
            let current = limits.php_memory_mb;
            let now = now_secs();

            if !enabled {
                // Turned off: hand back the operator's value, then forget.
                let base = stored.map(|st| st.base_mb).unwrap_or(current);
                if base > 0 && base != current {
                    let mut l = limits.clone();
                    l.php_memory_mb = base;
                    if let Err(e) = self.store_and_apply_limits(&detail, l).await {
                        tracing::warn!(domain = %detail.domain, error = %e, "php mem auto: restoring the operator's limit failed; will retry");
                        continue;
                    }
                    acted += 1;
                    self.append_audit(
                        "php.mem_auto.restore",
                        Some(&id),
                        &serde_json::json!({"from_mb": current, "to_mb": base}).to_string(),
                        "ok",
                    )
                    .await;
                }
                let _ = hyperion_state::hosting_kv::delete(&self.pool, &id, phpmem::KV_STATE).await;
                continue;
            }

            let mut st = stored.unwrap_or_else(|| phpmem::State {
                base_mb: current,
                ..Default::default()
            });
            let before = st.clone();
            let path = std::path::PathBuf::from(&self.paths.home_root)
                .join(&detail.system_user)
                .join(&detail.domain)
                .join("logs")
                .join("error.log");
            let (ino, off) = (st.log_ino, st.log_offset);
            let read = tokio::task::spawn_blocking(move || {
                hyperion_adapters::fs::read_appended(&path, ino, off, phpmem::MAX_SCAN_BYTES)
            })
            .await;
            match read {
                Ok(Ok(a)) => {
                    if phpmem::count_ooms(&a.text, current) > 0 {
                        st.last_oom_at = now;
                    }
                    st.log_ino = a.ino;
                    st.log_offset = a.offset;
                }
                // No log yet, or one root must not read (a symlink): nothing
                // seen. The lowering below still runs on time alone.
                Ok(Err(e)) => {
                    tracing::debug!(domain = %detail.domain, error = %e, "php mem auto: error.log not read")
                }
                Err(e) => tracing::warn!(error = %e, "php mem auto: log reader panicked"),
            }

            let ceiling = kv(phpmem::KV_MAX_MB)
                .await
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(phpmem::DEFAULT_MAX_MB)
                .clamp(16, 8192);
            let ram_cap = mem_total_mb.and_then(|t| phpmem::ram_cap_mb(t, limits.php_max_children));
            let href = format!("/hostings/{}#limits", detail.domain);
            match phpmem::decide(now, current, ceiling, ram_cap, &st) {
                Step::Nothing => {}
                Step::Raise { to } | Step::Lower { to } if to == current => {}
                step @ (Step::Raise { to } | Step::Lower { to }) => {
                    let raise = matches!(step, Step::Raise { .. });
                    let mut l = limits.clone();
                    l.php_memory_mb = to;
                    match self.store_and_apply_limits(&detail, l).await {
                        Ok(_) => {
                            st.last_change_at = now;
                            acted += 1;
                            let (from_s, to_s) = (current.to_string(), to.to_string());
                            self.append_audit(
                                if raise {
                                    "php.mem_auto.raise"
                                } else {
                                    "php.mem_auto.lower"
                                },
                                Some(&id),
                                &serde_json::json!({"from_mb": current, "to_mb": to, "ceiling_mb": ceiling}).to_string(),
                                "ok",
                            )
                            .await;
                            if raise {
                                let ceiling_s = ceiling.to_string();
                                self.notify_admins_say(
                                    "info",
                                    "ops.php_mem_raised",
                                    &[
                                        ("domain", detail.domain.as_str()),
                                        ("from", from_s.as_str()),
                                        ("to", to_s.as_str()),
                                        ("ceiling", ceiling_s.as_str()),
                                    ],
                                    &href,
                                    "php_mem_auto",
                                )
                                .await;
                            }
                        }
                        Err(e) => {
                            // State untouched (bar the log position), so the
                            // next tick tries the same step again.
                            tracing::warn!(domain = %detail.domain, to_mb = to, error = %e, "php mem auto: pool rewrite failed; will retry");
                        }
                    }
                }
                Step::Capped { at, by_ram } => {
                    st.capped_alert_at = now;
                    let at_s = at.to_string();
                    // Still running out at the most it may get. Not an
                    // outage of the whole site — the pages that need less
                    // still serve — so a warning: a plugin to look at, or a
                    // ceiling to raise on purpose.
                    self.notify_admins_say(
                        "warn",
                        if by_ram {
                            "ops.php_mem_capped_ram"
                        } else {
                            "ops.php_mem_capped"
                        },
                        &[("domain", detail.domain.as_str()), ("limit", at_s.as_str())],
                        &href,
                        "php_mem_auto",
                    )
                    .await;
                }
            }
            if st != before {
                let _ = hyperion_state::hosting_kv::set(
                    &self.pool,
                    &id,
                    phpmem::KV_STATE,
                    &st.to_json(),
                    now,
                )
                .await;
            }
        }
        Ok(acted)
    }

    /// Notice pools that ran out of PHP workers.
    ///
    /// Reads what each PHP version's FPM log (`<log_dir>/php<ver>-fpm.log`)
    /// gained since the last tick — `cursors` carries the position between
    /// ticks and starts every log at its end, so history is not news —
    /// counts `server reached pm.max_children` per pool, records it in the
    /// owning hosting's `hosting_kv` for the limits card, and warns the
    /// admins at most every [`phpworkers::ALERT_EVERY_SECS`] per site.
    ///
    /// Returns how many sites hit their limit this tick.
    pub async fn php_workers_tick(
        &self,
        log_dir: &std::path::Path,
        cursors: &mut std::collections::HashMap<PhpVersion, (u64, u64)>,
    ) -> Result<i64, RpcError> {
        use hyperion_types::phpworkers;
        let mut hits: std::collections::BTreeMap<String, i64> = Default::default();
        for ver in PhpVersion::all() {
            let path = log_dir.join(format!("{}.log", ver.service_name()));
            if !path.exists() {
                continue;
            }
            let (ino, off) = cursors.get(ver).copied().unwrap_or((0, 0));
            let read = tokio::task::spawn_blocking(move || {
                hyperion_adapters::fs::read_appended(&path, ino, off, phpworkers::MAX_SCAN_BYTES)
            })
            .await;
            match read {
                Ok(Ok(a)) => {
                    for (pool, n) in phpworkers::count_by_pool(&a.text) {
                        *hits.entry(pool).or_insert(0) += n;
                    }
                    cursors.insert(*ver, (a.ino, a.offset));
                }
                Ok(Err(e)) => {
                    tracing::debug!(version = %ver.as_str(), error = %e, "php workers: FPM log not read")
                }
                Err(e) => tracing::warn!(error = %e, "php workers: log reader panicked"),
            }
        }
        if hits.is_empty() {
            return Ok(0);
        }
        let now = now_secs();
        let mut sites = 0i64;
        for s in self.list().await? {
            if s.state != HostingState::Active || s.php_version.is_none() {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            let Some(&n) = hits.get(detail.system_user.as_str()) else {
                continue;
            };
            sites += 1;
            let id = detail.id.as_str().to_string();
            let mut st = hyperion_state::hosting_kv::get(&self.pool, &id, phpworkers::KV_STATE)
                .await
                .ok()
                .flatten()
                .and_then(|v| phpworkers::State::parse(&v))
                .unwrap_or_default();
            st.record(now, n);
            if st.should_alert(now) {
                st.alerted_at = now;
                let children = hyperion_state::limits::get(&self.pool, &detail.id)
                    .await
                    .ok()
                    .flatten()
                    .map(|r| r.php_max_children)
                    .unwrap_or_else(|| hyperion_types::HostingLimits::defaults().php_max_children)
                    .to_string();
                let today = st.hits_today(now).to_string();
                // warn, not error: the site still serves, queued — see the
                // severity rule on `notify_admins`. One card per site: the
                // next alert rewrites it with the new count.
                let kind = format!("php_workers:{}", detail.domain);
                self.notify_admins_say(
                    "warn",
                    "ops.php_workers_full",
                    &[
                        ("domain", detail.domain.as_str()),
                        ("children", children.as_str()),
                        ("today", today.as_str()),
                    ],
                    &format!("/hostings/{}#limits", detail.domain),
                    &kind,
                )
                .await;
            }
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                &id,
                phpworkers::KV_STATE,
                &st.to_json(),
                now,
            )
            .await;
        }
        Ok(sites)
    }

    pub async fn get_limits(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingLimits, RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::limits::get(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("limits get: {e}")))?;
        Ok(row
            .map(row_to_limits)
            .unwrap_or_else(hyperion_types::HostingLimits::defaults))
    }

    /// Switch a hosting's PHP version. Orchestrates:
    /// 1. Validation — hosting must be PHP (not static / proxy /
    ///    redirect), target version must differ from current, hosting
    ///    must not be suspended/deleting (use suspend/resume for that).
    /// 2. Tear down the OLD FPM pool (`fpm_delete`) so the old socket
    ///    file gets removed and the previous php<ver>-fpm pool config
    ///    file is dropped.
    /// 3. Persist the new `php_version` on the hostings row.
    /// 4. Ensure the NEW FPM pool exists (`fpm_ensure`) — this
    ///    creates the pool config under /etc/php/<new>/fpm/pool.d
    ///    and reloads php<new>-fpm.
    /// 5. Re-apply the persisted per-hosting PHP limits to the new
    ///    pool (memory, max_children, max_exec, max_requests), so a
    ///    plan limit set on PHP 8.3 carries over to PHP 8.4.
    /// 6. Re-render the nginx vhost so the `fastcgi_pass` socket
    ///    points at the new path (`/run/php/<new>/<user>.sock`).
    ///    `nginx -t` runs inside `nginx_write_vhost` and rolls back
    ///    on failure.
    /// 7. Audit log line so the operator can trace the change.
    ///
    /// On nginx -t failure the new pool is left in place but the
    /// vhost still points at the OLD socket — site keeps serving via
    /// the old FPM, the operator sees the vhost write error in the
    /// flash. This is the safe direction: NEW pool is up, old pool
    /// is gone, but vhost is unchanged → site keeps working off
    /// whichever socket the OS still considers valid. Operator then
    /// fixes the underlying config issue and retries.
    pub async fn set_php_version(
        &self,
        sel: HostingSelector,
        new_version: PhpVersion,
    ) -> Result<PhpVersion, RpcError> {
        let detail = self.get(sel).await?;

        // A hosting with no PHP runtime is CONVERTED rather than refused.
        //
        // This used to answer "delete and recreate as a PHP hosting",
        // which is the worst possible advice for the case that actually
        // produces it: an imported WordPress site whose source panel did
        // not report a PHP version, so the importer classified it static.
        // The files and the database are already in place, and the
        // operator was being told to destroy them. Everything the
        // conversion needs — pool creation, limits, vhost re-render —
        // already happens below; only this guard stood in the way.
        //
        // Static ONLY. A reverse-proxy hosting serves an upstream and has
        // no document root to run PHP from, and a redirect has no content
        // at all; giving either an FPM pool would produce a site that
        // silently does not work.
        let converting = detail.php_version.is_none();
        // Refuse by what the kind LACKS (a document root), not by
        // matching one blessed kind. The first version allowed only
        // `static` — and an imported WordPress site whose source panel
        // reported no PHP version arrives as kind="php" with NO version,
        // which that guard rejected with the absurd sentence "hosting
        // kind `php` cannot run PHP".
        if converting && matches!(detail.kind.as_str(), "reverse_proxy" | "redirect") {
            return Err(RpcError::Conflict {
                message: format!(
                    "hosting kind `{}` cannot run PHP — it has no document root to run it \
                     from. Only a static or PHP hosting can be given a PHP version.",
                    detail.kind
                ),
            });
        }
        let current = detail.php_version;
        if current == Some(new_version) {
            // No-op early-return so the operator can click the same
            // version twice without churn. Return Ok with the
            // current value so the UI flash can still confirm.
            return Ok(new_version);
        }
        if matches!(detail.state, HostingState::Suspended) {
            return Err(RpcError::Conflict {
                message: "hosting is suspended — resume first, then change PHP version".into(),
            });
        }
        if matches!(detail.state, HostingState::Deleting | HostingState::Trashed) {
            return Err(RpcError::Conflict {
                message: "hosting is being deleted or in trash".into(),
            });
        }

        // 1. Tear down old FPM pool. Best-effort: a missing pool file
        //    or already-stopped service is fine — we're about to
        //    replace it with the new version anyway. The new pool
        //    create below is what actually has to succeed.
        if let Some(current) = current {
            if let Err(e) = self.adapters.fpm_delete(&detail.system_user, current).await {
                tracing::warn!(
                    domain = %detail.domain,
                    from_version = %current,
                    error = %e,
                    "set_php_version: fpm_delete of old version failed (continuing)"
                );
            }
        }

        // 1b. Converting: flip the kind FIRST, so the vhost re-render in
        //     step 5 reads a hosting that is already PHP. Doing it after
        //     would render the static template against a hosting that has
        //     a pool — a site that 404s every .php it is asked for.
        if converting && detail.kind != "php" {
            hyperion_state::hostings::set_kind(&self.pool, &detail.id, "php", None, now_secs())
                .await
                .map_err(|e| {
                    RpcError::Internal_with(format!("set_php_version: kind -> php: {e}"))
                })?;
        }

        // 2. Persist the new version. If subsequent steps fail, the
        //    hostings row reflects intent — the boot-time FPM self-heal
        //    + vhost rewrite will re-converge on next agent restart.
        hyperion_state::hostings::set_php_version(
            &self.pool,
            &detail.id,
            Some(new_version),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set_php_version persist: {e}")))?;

        // 3. Ensure the new pool. If this fails we leave the row at
        //    the new version (intent) but rollback the FPM-pool-only
        //    side: there's nothing to rollback because step 1 already
        //    deleted the old pool. Operator retries; agent self-heal
        //    will re-converge.
        if let Err(e) = self
            .adapters
            .fpm_ensure(&detail.system_user, &detail.domain, new_version)
            .await
        {
            return Err(RpcError::Internal_with(format!(
                "fpm_ensure for PHP {new_version} failed: {e} \
                 (the hostings row was updated; retry to converge)"
            )));
        }

        // 4. Re-apply persisted PHP limits to the new pool so a plan
        //    limit set on PHP 8.3 (memory, children, etc.) survives
        //    the switch to 8.4. Best-effort — operator can re-apply
        //    via the Limits card if needed.
        if let Ok(Some(row)) = hyperion_state::limits::get(&self.pool, &detail.id).await {
            let l = row_to_limits(row);
            if let Err(e) = self
                .adapters
                .apply_php_limits(
                    &detail.system_user,
                    &detail.domain,
                    Some(new_version),
                    l.php_memory_mb,
                    l.php_max_exec_secs,
                    l.php_max_children,
                    l.php_max_requests,
                )
                .await
            {
                tracing::warn!(
                    domain = %detail.domain,
                    error = %e,
                    "set_php_version: re-apply limits to new pool failed (best-effort)"
                );
            }
        }

        // 5. Re-render vhost so fastcgi_pass points at the new socket.
        //    Pull the FRESH detail (with new php_version) for rendering.
        let new_detail = self.get(HostingSelector::Id(detail.id.clone())).await?;
        if let Err(e) = self.write_vhost_for_state(&new_detail).await {
            return Err(RpcError::Internal_with(format!(
                "nginx_write_vhost after PHP version change failed: {e} \
                 (FPM pool for PHP {new_version} is up; site still serves via the old socket \
                 until the vhost is rewritten — retry once the underlying config error is fixed)"
            )));
        }

        // 6. Audit log so we can reconstruct who/when/from→to.
        self.append_audit(
            "hosting.set_php_version",
            Some(detail.id.as_str()),
            &serde_json::json!({
                // `null` for a conversion — there was no previous version,
                // and "static" is the kind, not a PHP version.
                "from": current.map(|v| v.as_str()),
                "to": new_version.as_str(),
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(new_version)
    }
}

pub(super) fn clamp_limits(mut l: hyperion_types::HostingLimits) -> hyperion_types::HostingLimits {
    // Hard sanity ranges. Refusing to store nonsense is more useful than
    // silently mis-applying it later.
    l.php_memory_mb = l.php_memory_mb.clamp(16, 8192);
    l.php_max_exec_secs = l.php_max_exec_secs.clamp(1, 3600);
    l.php_max_children = l.php_max_children.clamp(1, 200);
    l.php_max_requests = l.php_max_requests.clamp(0, 1_000_000);
    l.db_max_connections = l.db_max_connections.clamp(1, 1000);
    if let Some(b) = l.disk_soft_bytes {
        l.disk_soft_bytes = Some(b.max(0));
    }
    if let Some(b) = l.disk_hard_bytes {
        l.disk_hard_bytes = Some(b.max(0));
    }
    if let Some(b) = l.bw_monthly_bytes {
        l.bw_monthly_bytes = Some(b.max(0));
    }
    if let Some(k) = l.throttle_kbps {
        l.throttle_kbps = Some(k.clamp(1, 10_000_000));
    }
    l
}

pub(super) fn limits_to_row(
    id: &HostingId,
    l: &hyperion_types::HostingLimits,
    now: i64,
) -> hyperion_state::limits::LimitsRow {
    hyperion_state::limits::LimitsRow {
        hosting_id: id.clone(),
        disk_soft_bytes: l.disk_soft_bytes,
        disk_hard_bytes: l.disk_hard_bytes,
        inode_soft: l.inode_soft,
        inode_hard: l.inode_hard,
        php_memory_mb: l.php_memory_mb,
        php_max_exec_secs: l.php_max_exec_secs,
        php_max_children: l.php_max_children,
        php_max_requests: l.php_max_requests,
        db_max_connections: l.db_max_connections,
        bw_monthly_bytes: l.bw_monthly_bytes,
        over_bw_policy: l.over_bw_policy.as_str().to_string(),
        throttle_kbps: l.throttle_kbps,
        updated_at: now,
    }
}

pub(super) fn row_to_limits(
    row: hyperion_state::limits::LimitsRow,
) -> hyperion_types::HostingLimits {
    let policy = match row.over_bw_policy.as_str() {
        "throttle" => hyperion_types::OverBwPolicy::Throttle,
        _ => hyperion_types::OverBwPolicy::Suspend,
    };
    hyperion_types::HostingLimits {
        disk_soft_bytes: row.disk_soft_bytes,
        disk_hard_bytes: row.disk_hard_bytes,
        inode_soft: row.inode_soft,
        inode_hard: row.inode_hard,
        php_memory_mb: row.php_memory_mb,
        php_max_exec_secs: row.php_max_exec_secs,
        php_max_children: row.php_max_children,
        php_max_requests: row.php_max_requests,
        db_max_connections: row.db_max_connections,
        bw_monthly_bytes: row.bw_monthly_bytes,
        over_bw_policy: policy,
        throttle_kbps: row.throttle_kbps,
    }
}
