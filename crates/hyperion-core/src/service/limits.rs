//! Per-hosting resource limits, PHP version, and the PHP memory/worker
//! automation.

use super::*;

/// Where [`HostingService::php_workers_tick`] has read to, between ticks.
/// Kept in memory: a restart starts every log at its end, so history is not
/// news, and an ongoing incident shows up again with its next warning.
#[derive(Debug, Default)]
pub struct PhpWorkersCursors {
    fpm: std::collections::HashMap<PhpVersion, (u64, u64)>,
    /// Access-log position per (pool, hosting id), only while it is being
    /// watched. Per hosting because sites can share a system user, and so a
    /// pool, but never a log.
    access: std::collections::HashMap<(String, String), (u64, u64)>,
    /// Pools whose access log is being read, and until when.
    watching: std::collections::HashMap<String, i64>,
}

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
            .flatten();
        let before_children = before.as_ref().map(|r| r.php_max_children);
        let before = before.map(|r| r.php_memory_mb);
        let limits = self.store_and_apply_limits(&detail, limits).await?;
        // Same rule for the automatic max_children.
        if before_children != Some(limits.php_max_children) {
            self.php_workers_auto_rebase(detail.id.as_str(), limits.php_max_children)
                .await;
        }
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

    /// Make `base` the floor of an existing automatic-max_children state.
    async fn php_workers_auto_rebase(&self, hosting_id: &str, base: i64) {
        use hyperion_types::phpworkers;
        let Some(mut st) =
            hyperion_state::hosting_kv::get(&self.pool, hosting_id, phpworkers::KV_AUTO_STATE)
                .await
                .ok()
                .flatten()
                .and_then(|v| phpworkers::AutoState::parse(&v))
        else {
            return;
        };
        let now = now_secs();
        st.base = base;
        st.last_change_at = now;
        st.pending_hits = 0;
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id,
            phpworkers::KV_AUTO_STATE,
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

    /// What the automatic max_children has to know about this node: its
    /// memory, its CPU pressure, the size of each pool's workers, and what
    /// every site's raised workers could use together.
    async fn php_workers_node_snapshot(
        &self,
    ) -> Result<
        (
            hyperion_types::phpworkers::NodeFacts,
            std::collections::HashMap<String, hyperion_types::phpworkers::PoolMemory>,
        ),
        RpcError,
    > {
        use hyperion_types::phpworkers;
        let pools = hyperion_adapters::phpfpm::pool_memory().await;
        let mut extra_committed_mb = 0i64;
        for s in self.list().await? {
            if s.state != HostingState::Active {
                continue;
            }
            let Some(st) = hyperion_state::hosting_kv::get(
                &self.pool,
                s.id.as_str(),
                phpworkers::KV_AUTO_STATE,
            )
            .await
            .ok()
            .flatten()
            .and_then(|v| phpworkers::AutoState::parse(&v)) else {
                continue;
            };
            let Ok(Some(row)) = hyperion_state::limits::get(&self.pool, &s.id).await else {
                continue;
            };
            let extra = row.php_max_children - st.base;
            if st.base <= 0 || extra <= 0 {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            let size = phpworkers::worker_size_mb(
                pools.get(detail.system_user.as_str()).copied(),
                row.php_memory_mb,
            );
            extra_committed_mb += extra * size;
        }
        Ok((
            phpworkers::NodeFacts {
                mem_total_mb: read_mem_total_mb().await,
                mem_available_mb: read_mem_available_mb().await,
                extra_committed_mb,
                cpu_pressure_pct: read_psi_some_avg60("cpu").await / 100,
            },
            pools,
        ))
    }

    /// This site's share of the whole node's CPU over the last minute,
    /// percent. 0 before the tracker has two reads to compare.
    async fn php_site_cpu_pct(&self, detail: &HostingDetail) -> i64 {
        let Some(live) = self.cpu_tracker.live(now_secs()) else {
            return 0;
        };
        match hyperion_state::system_users::get_by_name(&self.pool, &detail.system_user).await {
            Ok(Some(u)) => live.uid_pct_x100(u.uid) / 100,
            _ => 0,
        }
    }

    /// Whether the automation can still do something for this site, and if
    /// not, why.
    async fn php_workers_room(
        &self,
        detail: &HostingDetail,
        limits: &hyperion_types::HostingLimits,
    ) -> Result<hyperion_types::phpworkers::RaiseRoom, RpcError> {
        use hyperion_types::phpworkers;
        let id = detail.id.as_str();
        let kv = |k: &'static str| async move {
            hyperion_state::hosting_kv::get(&self.pool, id, k)
                .await
                .ok()
                .flatten()
        };
        if !phpworkers::auto_enabled(kv(phpworkers::KV_AUTO).await.as_deref()) {
            return Ok(phpworkers::RaiseRoom {
                cap: limits.php_max_children,
                blocked: Some(phpworkers::RaiseBlock::Off),
            });
        }
        let base = kv(phpworkers::KV_AUTO_STATE)
            .await
            .and_then(|v| phpworkers::AutoState::parse(&v))
            .map(|st| st.base)
            .filter(|&b| b > 0)
            .unwrap_or(limits.php_max_children);
        let ceiling = phpworkers::auto_ceiling(
            kv(phpworkers::KV_AUTO_MAX)
                .await
                .and_then(|v| v.trim().parse().ok()),
            base,
        );
        let (node, pools) = self.php_workers_node_snapshot().await?;
        let size = phpworkers::worker_size_mb(
            pools.get(detail.system_user.as_str()).copied(),
            limits.php_memory_mb,
        );
        Ok(phpworkers::raise_room(
            limits.php_max_children,
            ceiling,
            limits.php_memory_mb,
            size,
            self.php_site_cpu_pct(detail).await,
            &node,
        ))
    }

    /// Feed this tick's signs of trouble to the automatic max_children, when
    /// it is on: `hits` written under the limit now in force (a line from
    /// before the last raise is no reason for another), and whether visitors
    /// were affected. FPM warns once per episode, so a long one shows one
    /// line however bad it is; visitors affected is reason enough on its own.
    async fn php_workers_auto_note(
        &self,
        detail: &HostingDetail,
        by_limit: Option<&std::collections::BTreeMap<i64, i64>>,
        visitors_affected: bool,
        now: i64,
    ) {
        use hyperion_types::phpworkers;
        let id = detail.id.as_str();
        let kv = |k: &'static str| async move {
            hyperion_state::hosting_kv::get(&self.pool, id, k)
                .await
                .ok()
                .flatten()
        };
        if !phpworkers::auto_enabled(kv(phpworkers::KV_AUTO).await.as_deref()) {
            return;
        }
        let current = hyperion_state::limits::get(&self.pool, &detail.id)
            .await
            .ok()
            .flatten()
            .map(|r| r.php_max_children)
            .unwrap_or_else(|| hyperion_types::HostingLimits::defaults().php_max_children);
        let fresh = by_limit.map_or(0, |b| phpworkers::hits_at_or_above(b, current));
        if fresh <= 0 && !visitors_affected {
            return;
        }
        let mut st = kv(phpworkers::KV_AUTO_STATE)
            .await
            .and_then(|v| phpworkers::AutoState::parse(&v))
            .unwrap_or_else(|| phpworkers::AutoState {
                base: current,
                ..Default::default()
            });
        st.pending_hits += fresh;
        if visitors_affected {
            st.pending_hits = st.pending_hits.max(phpworkers::RAISE_AFTER_HITS);
        }
        st.last_full_at = now;
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            id,
            phpworkers::KV_AUTO_STATE,
            &st.to_json(),
            now,
        )
        .await;
    }

    /// Automatic `max_children` (see `hyperion_types::phpworkers`).
    ///
    /// For every live site that has run out of workers with it on: after
    /// [`phpworkers::RAISE_AFTER_HITS`] times at the limit in force, or once
    /// visitors were affected, raise `max_children` one step, bounded by
    /// [`phpworkers::raise_room`]. A raised site taking CPU from the others
    /// gives a step back ([`phpworkers::over_share`]), and so does a
    /// fortnight without running out, towards the operator's own value. Turning it off puts
    /// that value back. The signs of trouble are fed in by
    /// [`Self::php_workers_tick`]. Raises go in the audit log and on the
    /// limits card, not in the notification centre: nobody has to do anything
    /// about one.
    ///
    /// Returns how many pools it rewrote.
    pub async fn php_workers_auto_tick(&self) -> Result<i64, RpcError> {
        use hyperion_types::phpworkers::{self, AutoStep};
        let mut acted = 0i64;
        let mut snapshot = None;
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
            // No state: the site has never run out, so nothing to raise and
            // nothing to give back. This is every quiet site on every tick.
            let Some(stored) = kv(phpworkers::KV_AUTO_STATE)
                .await
                .and_then(|v| phpworkers::AutoState::parse(&v))
            else {
                continue;
            };
            let enabled = phpworkers::auto_enabled(kv(phpworkers::KV_AUTO).await.as_deref());
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
            let current = limits.php_max_children;
            let now = now_secs();

            if !enabled {
                // Turned off: hand back the operator's value, then forget.
                let base = stored.base;
                if base > 0 && base != current {
                    let mut l = limits.clone();
                    l.php_max_children = base;
                    if let Err(e) = self.store_and_apply_limits(&detail, l).await {
                        tracing::warn!(domain = %detail.domain, error = %e, "php workers auto: restoring the operator's max_children failed; will retry");
                        continue;
                    }
                    acted += 1;
                    self.append_audit(
                        "php.workers_auto.restore",
                        Some(&id),
                        &serde_json::json!({"from": current, "to": base}).to_string(),
                        "ok",
                    )
                    .await;
                }
                let _ =
                    hyperion_state::hosting_kv::delete(&self.pool, &id, phpworkers::KV_AUTO_STATE)
                        .await;
                continue;
            }

            let mut st = stored;
            let before = st.clone();
            let ceiling = phpworkers::auto_ceiling(
                kv(phpworkers::KV_AUTO_MAX)
                    .await
                    .and_then(|v| v.trim().parse().ok()),
                st.base,
            );
            // Measuring means walking /proc: only for a site that wants to
            // rise or is above its own value, once per tick however many.
            let wants_to_rise = st.pending_hits >= phpworkers::RAISE_AFTER_HITS;
            let (cap, gives_back) = if wants_to_rise || current > st.base {
                if snapshot.is_none() {
                    snapshot = Some(self.php_workers_node_snapshot().await?);
                }
                let Some((node, pools)) = snapshot.as_ref() else {
                    continue;
                };
                let size = phpworkers::worker_size_mb(
                    pools.get(detail.system_user.as_str()).copied(),
                    limits.php_memory_mb,
                );
                let site_cpu = self.php_site_cpu_pct(&detail).await;
                (
                    Some(
                        phpworkers::raise_room(
                            current,
                            ceiling,
                            limits.php_memory_mb,
                            size,
                            site_cpu,
                            node,
                        )
                        .cap,
                    ),
                    phpworkers::over_share(now, current, site_cpu, node.cpu_pressure_pct, &st),
                )
            } else {
                (None, None)
            };
            let step = match gives_back {
                Some(to) => AutoStep::Lower { to },
                None => phpworkers::decide_auto(now, current, ceiling, cap, &st),
            };
            match step {
                AutoStep::Nothing => {}
                AutoStep::Raise { to } | AutoStep::Lower { to } if to == current => {}
                step @ (AutoStep::Raise { to } | AutoStep::Lower { to }) => {
                    let raise = matches!(step, AutoStep::Raise { .. });
                    let mut l = limits.clone();
                    l.php_max_children = to;
                    match self.store_and_apply_limits(&detail, l).await {
                        Ok(_) => {
                            st.last_change_at = now;
                            st.pending_hits = 0;
                            acted += 1;
                            // A raise changes what the next site may have.
                            snapshot = None;
                            self.append_audit(
                                if raise {
                                    "php.workers_auto.raise"
                                } else {
                                    "php.workers_auto.lower"
                                },
                                Some(&id),
                                &serde_json::json!({"from": current, "to": to, "ceiling": ceiling})
                                    .to_string(),
                                "ok",
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::warn!(domain = %detail.domain, to, error = %e, "php workers auto: pool rewrite failed; will retry");
                        }
                    }
                }
            }
            if st != before {
                let _ = hyperion_state::hosting_kv::set(
                    &self.pool,
                    &id,
                    phpworkers::KV_AUTO_STATE,
                    &st.to_json(),
                    now,
                )
                .await;
            }
        }
        Ok(acted)
    }

    /// The scripts that showed up most in this site's PHP-FPM slow-request
    /// log lately (root-owned, outside the site's tree). Empty when there is
    /// none or it cannot be read.
    async fn php_slow_scripts(
        &self,
        detail: &HostingDetail,
    ) -> Vec<hyperion_types::phpworkers::SlowScript> {
        use hyperion_types::phpworkers;
        if detail.system_user.trim().is_empty() {
            return Vec::new();
        }
        let path = hyperion_adapters::phpfpm::slowlog_path(&detail.system_user);
        match hyperion_adapters::fs::tail_lines(&path, 20 * phpworkers::SLOWLOG_ENTRIES).await {
            Ok(text) => phpworkers::slow_scripts(&text, &detail.root_dir, 3),
            Err(_) => Vec::new(),
        }
    }

    /// Notice pools that ran out of PHP workers, and whether anybody felt it.
    ///
    /// Reads what each PHP version's FPM log (`<log_dir>/php<ver>-fpm.log`)
    /// gained since the last tick — `cursors` carries the position between
    /// ticks and starts every log at its end, so history is not news — and
    /// counts `server reached pm.max_children` per pool. That goes in the
    /// owning hosting's `hosting_kv` for the limits card, and starts a watch
    /// on the site's access log: what visitors got while the pool stays full.
    ///
    /// Only that reaches a person, per [`phpworkers::State::should_alert`]:
    /// a full pool nobody noticed is not news, and neither is one the
    /// automation is still dealing with.
    ///
    /// Returns how many sites are being watched.
    pub async fn php_workers_tick(
        &self,
        log_dir: &std::path::Path,
        cursors: &mut PhpWorkersCursors,
    ) -> Result<i64, RpcError> {
        use hyperion_types::phpworkers;
        let mut hits: std::collections::BTreeMap<String, std::collections::BTreeMap<i64, i64>> =
            Default::default();
        for ver in PhpVersion::all() {
            let path = log_dir.join(format!("{}.log", ver.service_name()));
            if !path.exists() {
                continue;
            }
            let (ino, off) = cursors.fpm.get(ver).copied().unwrap_or((0, 0));
            let read = tokio::task::spawn_blocking(move || {
                hyperion_adapters::fs::read_appended(&path, ino, off, phpworkers::MAX_SCAN_BYTES)
            })
            .await;
            match read {
                Ok(Ok(a)) => {
                    for (pool, by_limit) in phpworkers::count_by_pool_and_limit(&a.text) {
                        let e = hits.entry(pool).or_default();
                        for (limit, n) in by_limit {
                            *e.entry(limit).or_insert(0) += n;
                        }
                    }
                    cursors.fpm.insert(*ver, (a.ino, a.offset));
                }
                Ok(Err(e)) => {
                    tracing::debug!(version = %ver.as_str(), error = %e, "php workers: FPM log not read")
                }
                Err(e) => tracing::warn!(error = %e, "php workers: log reader panicked"),
            }
        }
        let now = now_secs();
        for pool in hits.keys() {
            cursors
                .watching
                .insert(pool.clone(), now + phpworkers::WATCH_SECS);
        }
        // A watch that ran out, or whose site is gone: forget it and where
        // its log was, so the next one starts at the end of the log.
        let expired: Vec<String> = cursors
            .watching
            .iter()
            .filter(|&(_, &until)| until <= now)
            .map(|(pool, _)| pool.clone())
            .collect();
        for pool in expired {
            cursors.watching.remove(&pool);
            cursors.access.retain(|(p, _), _| *p != pool);
        }
        if cursors.watching.is_empty() {
            return Ok(0);
        }
        let mut sites = 0i64;
        for s in self.list().await? {
            if s.state != HostingState::Active || s.php_version.is_none() {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            let pool = detail.system_user.clone();
            if !cursors.watching.contains_key(pool.as_str()) {
                continue;
            }
            sites += 1;
            let by_limit = hits.get(pool.as_str());
            let path = std::path::PathBuf::from(&self.paths.home_root)
                .join(&detail.system_user)
                .join(&detail.domain)
                .join("logs")
                .join("access.log");
            let access_key = (pool.clone(), detail.id.as_str().to_string());
            let (ino, off) = cursors.access.get(&access_key).copied().unwrap_or((0, 0));
            let read = tokio::task::spawn_blocking(move || {
                hyperion_adapters::fs::read_appended(&path, ino, off, phpworkers::MAX_SCAN_BYTES)
            })
            .await;
            let (errors, waits) = match read {
                Ok(Ok(a)) => {
                    cursors.access.insert(access_key, (a.ino, a.offset));
                    phpworkers::count_impact(&a.text)
                }
                // No log yet, or one root must not read (a symlink).
                Ok(Err(e)) => {
                    tracing::debug!(domain = %detail.domain, error = %e, "php workers: access.log not read");
                    (0, 0)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "php workers: log reader panicked");
                    (0, 0)
                }
            };
            let affected = errors + waits > 0;
            if affected {
                cursors
                    .watching
                    .insert(pool.clone(), now + phpworkers::WATCH_SECS);
            }
            if by_limit.is_none() && !affected {
                continue;
            }
            let id = detail.id.as_str().to_string();
            let mut st = hyperion_state::hosting_kv::get(&self.pool, &id, phpworkers::KV_STATE)
                .await
                .ok()
                .flatten()
                .and_then(|v| phpworkers::State::parse(&v))
                .unwrap_or_default();
            if let Some(by_limit) = by_limit {
                st.record(now, by_limit.values().sum());
            }
            st.record_impact(now, errors, waits);
            let incident = st.is_incident(now);
            self.php_workers_auto_note(&detail, by_limit, incident, now)
                .await;
            if incident {
                self.php_workers_maybe_alert(&detail, &mut st, now).await;
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
        // Whatever is still being watched but matched no live site this time
        // (suspended, deleted) runs out on its own above.
        Ok(sites)
    }

    /// Tell the admins about an incident the automation can do nothing more
    /// for. One card per site, rewritten at most once a day.
    async fn php_workers_maybe_alert(
        &self,
        detail: &HostingDetail,
        st: &mut hyperion_types::phpworkers::State,
        now: i64,
    ) {
        use hyperion_types::phpworkers::{self, RaiseBlock};
        // Everything below walks /proc and every site: only when the answer
        // could be yes.
        if !st.should_alert(now, false) {
            return;
        }
        let limits = hyperion_state::limits::get(&self.pool, &detail.id)
            .await
            .ok()
            .flatten()
            .map(row_to_limits)
            .unwrap_or_else(hyperion_types::HostingLimits::defaults);
        let room = match self.php_workers_room(detail, &limits).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e, "php workers: could not work out the room to raise");
                return;
            }
        };
        if !st.should_alert(now, room.blocked.is_none()) {
            return;
        }
        st.alerted_at = now;
        let (errors, waits) = st.impact_recent(now);
        let (children, errors, waits, today) = (
            limits.php_max_children.to_string(),
            errors.to_string(),
            waits.to_string(),
            st.hits_24h(now).to_string(),
        );
        let args = [
            ("domain", detail.domain.as_str()),
            ("children", children.as_str()),
            ("errors", errors.as_str()),
            ("waits", waits.as_str()),
            ("today", today.as_str()),
        ];
        let cat = self.operator_catalog();
        let title = cat.render("ops.php_workers_full.title", &args);
        let mut body = cat.render("ops.php_workers_full.body", &args);
        let why = match room.blocked {
            Some(RaiseBlock::Off) | None => "ops.php_workers_full.why_off",
            Some(RaiseBlock::Ceiling) => "ops.php_workers_full.why_ceiling",
            Some(RaiseBlock::SiteRam | RaiseBlock::NodeRam) => "ops.php_workers_full.why_ram",
            Some(RaiseBlock::SiteShare) => "ops.php_workers_full.why_share",
            Some(RaiseBlock::NodeCpu) => "ops.php_workers_full.why_cpu",
        };
        body.push(' ');
        body.push_str(&cat.render(why, &args));
        // What held the workers, so the alert says where to look instead of
        // only that there is somewhere to look.
        let slow = self.php_slow_scripts(detail).await;
        if !slow.is_empty() {
            let line = phpworkers::slow_scripts_line(&slow);
            body.push(' ');
            body.push_str(&cat.render("ops.php_workers_full.slow", &[("scripts", line.as_str())]));
        }
        if !detail.vhost_options.fastcgi_cache_enabled {
            body.push(' ');
            body.push_str(&cat.render("ops.php_workers_full.cache", &args));
        }
        // warn, not error: the site still serves, queued — see the severity
        // rule on `notify_admins`. One card per site: the next alert rewrites
        // it with the new count.
        let kind = format!("php_workers:{}", detail.domain);
        self.notify_admins(
            "warn",
            &title,
            &body,
            &format!("/hostings/{}#limits", detail.domain),
            &kind,
        )
        .await;
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
    ///    must not be deleting or in trash. A suspended hosting stays
    ///    offline: the new version is tried, then only the row changes.
    /// 2. Ensure the NEW FPM pool exists (`fpm_ensure`) — this
    ///    creates the pool config under /etc/php/<new>/fpm/pool.d
    ///    and reloads php<new>-fpm.
    /// 3. Re-apply the persisted per-hosting PHP limits to the new
    ///    pool (memory, max_children, max_exec, max_requests), so a
    ///    plan limit set on PHP 8.3 carries over to PHP 8.4.
    /// 4. Persist the new `php_version` on the hostings row.
    /// 5. Re-render the nginx vhost so the `fastcgi_pass` socket
    ///    points at the new path (`/run/php/<new>/<user>.sock`).
    ///    `nginx -t` runs inside `nginx_write_vhost` and rolls back
    ///    on failure.
    /// 6. Release the OLD FPM pool: it goes unless a site sharing this
    ///    system user still runs on it.
    /// 7. Audit log line so the operator can trace the change.
    ///
    /// The old pool goes LAST so that no failure can leave a site without
    /// one: this used to delete it first, and a new pool that would not
    /// start left the site on 502s with the row already naming the new
    /// version — where retrying that version was a no-op. Now every failure
    /// up to step 5 leaves the site serving on its old pool, with the row
    /// saying so. Both pools can run side by side: they belong to different
    /// FPM masters and listen on different sockets.
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
        if matches!(detail.state, HostingState::Deleting | HostingState::Trashed) {
            return Err(RpcError::Conflict {
                message: "hosting is being deleted or in trash".into(),
            });
        }
        // A suspended site has no pool and stays offline: only the row changes,
        // and resume builds the pool from it. This used to demand a resume
        // first, which put a site suspended over an unsafe PHP back online
        // just to take it off that PHP.
        let suspended = detail.state == HostingState::Suspended;

        // 1. Ensure the new pool. Nothing has changed yet, so a failure here
        //    only has to be reported. A pool file may stay behind when FPM
        //    would not reload; retrying overwrites it. Not removed here, as
        //    `fpm_delete` reloads too — for a version that failed to install
        //    that would run the whole apt install a second time.
        if let Err(e) = self
            .adapters
            .fpm_ensure(&detail.system_user, &detail.domain, new_version)
            .await
        {
            return Err(RpcError::Internal_with(format!(
                "fpm_ensure for PHP {new_version} failed: {e} \
                 (the site was left as it was)"
            )));
        }

        // 2. Re-apply persisted PHP limits to the new pool so a plan
        //    limit set on PHP 8.3 (memory, children, etc.) survives
        //    the switch to 8.4. Best-effort — operator can re-apply
        //    via the Limits card if needed.
        //
        //    A suspended site only needed the proof that the version starts,
        //    as resume ignores a pool that fails. It must not keep a running
        //    pool, though a live sibling on that version keeps theirs; resume
        //    applies the limits to the one it builds.
        if suspended {
            self.release_fpm_pool(&detail.system_user, new_version)
                .await;
        } else if let Ok(Some(row)) = hyperion_state::limits::get(&self.pool, &detail.id).await {
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

        // 3. Point the row and the vhost at the new pool. A failure in here
        //    is undone below, since nginx keeps the old vhost when `nginx -t`
        //    refuses the new one.
        if let Err(e) = self
            .switch_row_and_vhost(&detail, converting, new_version)
            .await
        {
            self.undo_php_switch(&detail, converting).await;
            if !suspended {
                self.release_fpm_pool(&detail.system_user, new_version)
                    .await;
            }
            return Err(e);
        }

        // 4. This site no longer points at the old pool. Best-effort: it
        //    already runs on the new version, so a leftover pool is litter,
        //    not a failed switch.
        if let Some(current) = current.filter(|_| !suspended) {
            self.release_fpm_pool(&detail.system_user, current).await;
        }

        // 5. Audit log so we can reconstruct who/when/from→to.
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

    /// Step 3 of [`Self::set_php_version`]. The kind flips FIRST when
    /// converting, so the re-render reads a hosting that is already PHP.
    /// Doing it after would render the static template against a hosting
    /// that has a pool — a site that 404s every .php it is asked for.
    async fn switch_row_and_vhost(
        &self,
        detail: &HostingDetail,
        converting: bool,
        new_version: PhpVersion,
    ) -> Result<(), RpcError> {
        if converting && detail.kind != "php" {
            hyperion_state::hostings::set_kind(&self.pool, &detail.id, "php", None, now_secs())
                .await
                .map_err(|e| {
                    RpcError::Internal_with(format!("set_php_version: kind -> php: {e}"))
                })?;
        }
        hyperion_state::hostings::set_php_version(
            &self.pool,
            &detail.id,
            Some(new_version),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set_php_version persist: {e}")))?;

        // Pull the FRESH detail (with new php_version) for rendering.
        let new_detail = self.get(HostingSelector::Id(detail.id.clone())).await?;
        self.write_vhost_for_state(&new_detail).await.map_err(|e| {
            RpcError::Internal_with(format!(
                "nginx_write_vhost after PHP version change failed: {e} \
                 (the site stays on its previous PHP; retry once the underlying \
                 config error is fixed)"
            ))
        })
    }

    /// Put the row back to `detail` after a switch that did not complete. A
    /// write failing here is logged only: the caller is already returning
    /// the error that brought us here.
    async fn undo_php_switch(&self, detail: &HostingDetail, converting: bool) {
        if converting && detail.kind != "php" {
            // `None` is right for every kind that can be converted: only a
            // reverse proxy has an upstream, and it is refused up front.
            if let Err(e) = hyperion_state::hostings::set_kind(
                &self.pool,
                &detail.id,
                &detail.kind,
                None,
                now_secs(),
            )
            .await
            {
                tracing::error!(domain = %detail.domain, error = %e, "set_php_version: could not restore the kind");
            }
        }
        if let Err(e) = hyperion_state::hostings::set_php_version(
            &self.pool,
            &detail.id,
            detail.php_version,
            now_secs(),
        )
        .await
        {
            tracing::error!(domain = %detail.domain, error = %e, "set_php_version: could not restore the version");
        }
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
