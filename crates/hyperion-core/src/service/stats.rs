//! Metrics collection and readback: hostings, nodes, network history.

use super::cpu_usage::{parse_proc_stat_cpu, read_proc_snapshot};
use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ================================================================
    //  Stats — collection + readback
    // ================================================================

    /// Run one background sampler tick.
    /// Per hosting: `du -sb <root>` + tail parse access.log over last hour.
    /// Per node: snapshot /proc/loadavg + /proc/meminfo + /proc/uptime.
    /// Persist into hosting_usage + node_metrics.
    /// Returns count of hostings sampled.
    pub async fn stats_tick(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let period = period_key(now);
        // Start of the UTC hour this tick falls in — the lower bound of the
        // window whose result `period` names.
        let hour_start = now - now.rem_euclid(3600);
        let prev_period = period_key(hour_start - 3600);
        let summaries = self.list().await?;
        let mut total_disk: i64 = 0;
        let total_bw_out: i64 = 0;
        let total_requests: i64 = 0;
        let mut active = 0i64;
        let mut suspended = 0i64;
        let mut failed = 0i64;
        for s in &summaries {
            match s.state {
                HostingState::Active => active += 1,
                HostingState::Suspended => suspended += 1,
                HostingState::Failed => failed += 1,
                _ => {}
            }
        }

        // What the 10 s sampler measured since the last tick. Hyperion runs one
        // php-fpm pool per user, so a site's footprint is its user's processes.
        let cpu = self.cpu_tracker.take_interval();
        let rss_by_uid = self.cpu_tracker.rss_by_uid();
        let users = hyperion_state::hostings::system_users_by_hosting(&self.pool)
            .await
            .unwrap_or_default();

        for s in &summaries {
            let site_user = users.get(s.id.as_str());
            let user = site_user
                .map(|(name, _)| name.clone())
                .or_else(|| derive_user_from_summary(s));
            let host_root = std::path::PathBuf::from(&self.paths.home_root)
                .join(user.clone().unwrap_or_else(|| "_".to_string()))
                .join(&s.domain);
            // A site whose tree is not where it should be would make `du` and
            // the log parse both answer zero, and the row that gets written is
            // indistinguishable from a real measurement: the customer's letter
            // reads "0 requests, 0 B sent, peak disk 0 B … these figures cover
            // the whole period" for a live site with gigabytes of files.
            //
            // Writing no row at all is the honest alternative — the day drops
            // out of `days_counted`, so the letter says the period was only
            // partly measured instead of inventing a zero.
            if !tokio::fs::try_exists(&host_root).await.unwrap_or(false) {
                tracing::warn!(
                    hosting = %s.id.as_str(), domain = %s.domain, path = %host_root.display(),
                    "stats: hosting root not found — skipping this sample rather than \
                     recording zeros; check the site's system user",
                );
                continue;
            }
            let disk = du_bytes(&host_root).await.unwrap_or(0);
            let inodes = du_inodes(&host_root).await;
            let logs_dir = host_root.join("logs");
            let access_log = logs_dir.join("access.log");
            // The bucket is keyed by UTC HOUR, so it must hold that hour's
            // traffic and nothing else — see `parse_access_log_window`.
            //
            // BOUNDED at the top even though this hour is still running:
            // `hour_start` is computed once at the start of the tick, but
            // the per-site loop does `du` and a 200 ms /proc pass first, so
            // a busy node can reach this line in the NEXT hour. Unbounded,
            // that traffic would be filed into the hour named by `period`
            // and counted again by its own bucket later.
            let (bw_in, bw_out, reqs, _last) =
                parse_access_log_window(&access_log, hour_start, Some(hour_start + 3600)).await;
            // The current hour is still running, so this row is rewritten on
            // every tick and is only complete once the hour ends. Backfill
            // the hour we just left so it stops being short by up to one
            // tick interval — a 5-minute sampler otherwise loses the last
            // few minutes of every hour, a systematic ~4 % undercount in the
            // customer's traffic figure.
            let (p_in, p_out, p_reqs, _) =
                parse_access_log_window(&access_log, hour_start - 3600, Some(hour_start)).await;
            // What arrived since the last tick, for the five-minute history:
            // the growth of this hour's bucket and of the one just left, read
            // before either is rewritten below. Floored, because a rotated log
            // parses lower than what is stored.
            let (s_in, s_out, s_reqs) =
                hyperion_state::limits::usage_traffic_at(&self.pool, &s.id, &period)
                    .await
                    .unwrap_or((bw_in, bw_out, reqs));
            let (sp_in, sp_out, sp_reqs) =
                hyperion_state::limits::usage_traffic_at(&self.pool, &s.id, &prev_period)
                    .await
                    .unwrap_or((p_in, p_out, p_reqs));
            let tick_in = (bw_in - s_in).max(0) + (p_in - sp_in).max(0);
            let tick_out = (bw_out - s_out).max(0) + (p_out - sp_out).max(0);
            let tick_reqs = (reqs - s_reqs).max(0) + (p_reqs - sp_reqs).max(0);
            if p_reqs > 0 {
                // `> 0` guards logrotate: once access.log has been rotated
                // away the parse legitimately returns zero, and writing that
                // would erase a real hour we had already measured. A quiet
                // hour needs no row — absent and zero sum identically.
                let _ = hyperion_state::limits::upsert_usage_traffic(
                    &self.pool,
                    &s.id,
                    &prev_period,
                    p_in,
                    p_out,
                    p_reqs,
                )
                .await;
            }

            // Per-hosting RSS + CPU from this user's processes.
            let uid = site_user.map(|(_, uid)| *uid);
            let mem_rss = uid.and_then(|u| rss_by_uid.get(&u).copied()).unwrap_or(0);
            let cpu_pct = uid.map(|u| cpu.uid_pct_x100(u)).unwrap_or(0);
            let (cpu_busy, cpu_peak) = uid
                .and_then(|u| cpu.by_uid.get(&u).copied())
                .unwrap_or((0, 0));

            let _ = hyperion_state::usage_samples::insert(
                &self.pool,
                &hyperion_state::usage_samples::UsageSample {
                    hosting_id: s.id.clone(),
                    at: now,
                    cpu_busy_jiffies: cpu_busy,
                    // No user, nothing measured: an unknown, not an idle site.
                    cpu_total_jiffies: if uid.is_some() { cpu.total } else { 0 },
                    cpu_peak_x100: cpu_peak,
                    mem_rss_bytes: mem_rss,
                    bw_in_bytes: tick_in,
                    bw_out_bytes: tick_out,
                    requests: tick_reqs,
                },
            )
            .await;

            // Upsert usage row.
            let _ = hyperion_state::limits::upsert_usage(
                &self.pool,
                &hyperion_state::limits::UsageBucket {
                    hosting_id: s.id.clone(),
                    period: period.clone(),
                    disk_used_bytes: disk,
                    inodes_used: inodes,
                    bw_in_bytes: bw_in,
                    bw_out_bytes: bw_out,
                    php_requests: reqs,
                    mem_rss_bytes: mem_rss,
                    cpu_pct_x100: cpu_pct,
                },
            )
            .await;

            total_disk += disk;
        }

        // Node-level traffic totals come from the LAST 24 HOURLY BUCKETS,
        // not from the per-site figures parsed above. Those figures are
        // the CURRENT hour's window — summing them into a field named
        // *_24h stored every five minutes made the dashboard sparkline a
        // sawtooth: hour-to-date climbing from zero, resetting on every
        // hour boundary. A cumulative counter plotted as a series. (Before
        // the hour-bucket fix the same sums were a rolling 24 h, which was
        // smooth but ~24x inflated — this is the second half of that fix.)
        let (total_bw_out, total_requests) =
            match hyperion_state::limits::usage_rollup_all(&self.pool, 24).await {
                // Only sites still on the node's list. A trashed site stops
                // being sampled, so its last 24 buckets FREEZE — and a rollup
                // that takes "the last 24, however old" added that frozen day
                // of traffic to the node's totals on every tick until purge.
                Ok(rows) => rows
                    .iter()
                    .filter(|row| summaries.iter().any(|s| s.id == row.hosting_id))
                    .fold((0i64, 0i64), |(b, r), row| {
                        (b + row.bw_out_bytes, r + row.php_requests)
                    }),
                // Rollup failing must not sink the whole sample — fall
                // back to the hour-to-date sums, which are at least real
                // traffic, and let the next tick correct the shape.
                Err(_) => (total_bw_out, total_requests),
            };

        // Node disk = REAL filesystem usage + capacity of the home root's
        // volume (df Used/Size), not the sum of tenant `du` above — the latter
        // ignores the OS, /var/lib databases, logs, backups and the panel DB,
        // so a node at 95% real disk could look nearly empty. We keep BOTH:
        // this node-volume figure (disk-pressure) AND `total_disk` (the real
        // per-site footprint) so the dashboard can show them separately. Fall
        // back to the du sum / unknown capacity only if df fails.
        let (node_disk_used, node_disk_total) =
            match fs_used_total_bytes(std::path::Path::new(&self.paths.home_root)).await {
                Some((used, total)) => (used as i64, total as i64),
                None => (total_disk, 0),
            };

        let pm = read_proc_metrics().await;
        // Keep a little over the longest range /stats offers.
        let _ = hyperion_state::usage_samples::prune_older_than(&self.pool, now - 49 * 3600).await;

        let _ = metrics::insert(
            &self.pool,
            &metrics::NodeMetricsInput {
                sampled_at: now,
                hostings_count: summaries.len() as i64,
                hostings_active: active,
                hostings_suspended: suspended,
                hostings_failed: failed,
                total_disk_bytes: node_disk_used,
                total_bw_out_24h: total_bw_out,
                total_requests_24h: total_requests,
                loadavg_1m_x100: pm.loadavg_1m_x100,
                mem_total_kib: pm.mem_total_kib,
                mem_used_kib: pm.mem_used_kib,
                uptime_secs: pm.uptime_secs,
                // The average over the tick where the sampler ran, so the
                // history is not a row of 200 ms snapshots.
                cpu_pct_x100: if cpu.total > 0 {
                    cpu.node_pct_x100()
                } else {
                    pm.cpu_pct_x100
                },
                swap_total_kib: pm.swap_total_kib,
                swap_used_kib: pm.swap_used_kib,
                psi_cpu_x100: pm.psi_cpu_x100,
                psi_mem_x100: pm.psi_mem_x100,
                psi_io_x100: pm.psi_io_x100,
                net_rx_bps: pm.net_rx_bps,
                net_tx_bps: pm.net_tx_bps,
                hostings_disk_bytes: total_disk,
                node_disk_total_bytes: node_disk_total,
            },
        )
        .await;

        // Prune > 30d to keep DB lean.
        let _ = metrics::prune_older_than(&self.pool, now - 30 * 24 * 3600).await;

        // Scrape any new kernel OOM-kills into oom_events (same cadence).
        let _ = self.scan_oom_events().await;

        Ok(summaries.len() as i64)
    }

    /// Append kernel OOM-kill events newer than the last one we recorded into
    /// `oom_events`, scraped from the journal. No-ops if journalctl is missing
    /// or the kernel log is unreadable. Returns how many were recorded.
    pub async fn scan_oom_events(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let since = hyperion_state::oom_events::latest_at(&self.pool)
            .await
            .ok()
            .flatten()
            .unwrap_or(now - 24 * 3600);
        let out = tokio::process::Command::new("/usr/bin/journalctl")
            .args([
                "-k",
                "-o",
                "short-unix",
                "--no-pager",
                "--since",
                &format!("@{}", since + 1),
                "--grep",
                "Killed process",
            ])
            .output()
            .await;
        let out = match out {
            Ok(o) if o.status.success() => o,
            _ => return Ok(0),
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut n = 0i64;
        for line in text.lines() {
            // short-unix line: "<unix.micros> <host> <ident>: <message>"
            let Some(at) = line
                .split_whitespace()
                .next()
                .and_then(|t| t.split('.').next())
                .and_then(|t| t.parse::<i64>().ok())
            else {
                continue;
            };
            if at <= since || !line.contains("Killed process") {
                continue;
            }
            let (pid, comm) = parse_oom_kill(line);
            let detail: String = line
                .split_once("kernel: ")
                .map(|x| x.1)
                .unwrap_or(line)
                .chars()
                .take(300)
                .collect();
            let _ = hyperion_state::oom_events::insert(&self.pool, at, &comm, pid, &detail).await;
            n += 1;
        }
        // Keep ~90 days of OOM history.
        let _ =
            hyperion_state::oom_events::prune_older_than(&self.pool, now - 90 * 24 * 3600).await;
        Ok(n)
    }

    /// Stats for ONE hosting (the hosting detail page).
    ///
    /// The aggregation below is mirrored in SQL by
    /// [`Self::hosting_stats_all`] / `limits::usage_rollup_all`, which
    /// serves the whole-node breakdown in a single query. The two must
    /// stay semantically identical — a site's numbers may not change
    /// depending on which page you look at. Change one, change both.
    pub async fn hosting_stats(&self, sel: HostingSelector) -> Result<HostingStats, RpcError> {
        let detail = self.get(sel).await?;
        // Sum last 24h of hourly usage rows.
        let rows = hyperion_state::limits::usage_for(&self.pool, &detail.id, 24)
            .await
            .map_err(|e| RpcError::Internal_with(format!("usage: {e}")))?;
        let now = now_secs();
        let mut disk = 0i64;
        let mut bw_in = 0i64;
        let mut bw_out = 0i64;
        let mut reqs = 0i64;
        for r in &rows {
            disk = disk.max(r.disk_used_bytes); // current disk = latest
            bw_in += r.bw_in_bytes;
            bw_out += r.bw_out_bytes;
            reqs += r.php_requests;
        }
        // Memory + CPU are instantaneous, so take the most recent row (rows
        // are period-DESC), not a 24h sum.
        let (mut mem_rss, mut cpu_pct) = rows
            .first()
            .map(|r| (r.mem_rss_bytes, r.cpu_pct_x100))
            .unwrap_or((0, 0));
        let live = self.cpu_tracker.live(now);
        let uid = hyperion_state::system_users::get_by_name(&self.pool, &detail.system_user)
            .await
            .ok()
            .flatten()
            .map(|u| u.uid);
        let (cpu_live, cpu_cores) = match (&live, uid) {
            (Some(l), Some(uid)) => {
                cpu_pct = l.uid_pct_x100(uid);
                mem_rss = l.rss_bytes(uid);
                (true, l.cores)
            }
            _ => (false, 0),
        };
        let day = hyperion_state::usage_samples::rollup_since(
            &self.pool,
            now - 24 * 3600,
            Some(&detail.id),
        )
        .await
        .unwrap_or_default();
        let day = day.first();
        Ok(HostingStats {
            hosting_id: detail.id,
            domain: detail.domain,
            disk_bytes: disk,
            bw_in_bytes_24h: bw_in,
            bw_out_bytes_24h: bw_out,
            requests_24h: reqs,
            last_request_at: rows.first().map(|_| now),
            sampled_at: day.map_or(0, |d| d.last_at),
            mem_rss_bytes: mem_rss,
            cpu_pct_x100: cpu_pct,
            cpu_live,
            cpu_avg_24h_x100: day.and_then(|d| d.cpu_avg_x100()),
            cpu_peak_24h_x100: day
                .filter(|d| d.cpu_avg_x100().is_some())
                .map(|d| d.cpu_peak_x100),
            cpu_cores,
        })
    }

    /// Stats for EVERY active hosting on this node, in one DB query.
    ///
    /// Backs the /stats per-site breakdown. Doing this with
    /// [`Self::hosting_stats`] would be one RPC round-trip *and* one
    /// query per site; here it is a single window-function rollup —
    /// see `limits::usage_rollup_all`, whose aggregation deliberately
    /// mirrors `hosting_stats`' Rust-side fold so the detail page and
    /// the breakdown table can never disagree about the same site.
    pub async fn hosting_stats_all(&self) -> Result<Vec<HostingStats>, RpcError> {
        let summaries = self.list().await?;
        let rollups = hyperion_state::limits::usage_rollup_all(&self.pool, 24)
            .await
            .map_err(|e| RpcError::Internal_with(format!("usage: {e}")))?;
        let by_id: HashMap<&str, &hyperion_state::limits::UsageRollup> =
            rollups.iter().map(|r| (r.hosting_id.as_str(), r)).collect();
        let now = now_secs();
        let live = self.cpu_tracker.live(now);
        let users = hyperion_state::hostings::system_users_by_hosting(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("usage: {e}")))?;
        let day = hyperion_state::usage_samples::rollup_since(&self.pool, now - 24 * 3600, None)
            .await
            .map_err(|e| RpcError::Internal_with(format!("usage: {e}")))?;
        let day_by_id: HashMap<&str, &hyperion_state::usage_samples::UsageSampleRollup> =
            day.iter().map(|r| (r.hosting_id.as_str(), r)).collect();
        // Drive the list from the HOSTINGS, not from the usage rows: a
        // site created since the last sampler tick has no usage rows
        // yet, and it must still show up (all zeros) instead of
        // silently vanishing from the breakdown.
        Ok(summaries
            .into_iter()
            .filter(|s| matches!(s.state, HostingState::Active))
            .map(|s| {
                let r = by_id.get(s.id.as_str()).copied();
                let d = day_by_id.get(s.id.as_str()).copied();
                let uid = users.get(s.id.as_str()).map(|(_, uid)| *uid);
                let live_uid = live.as_ref().zip(uid);
                HostingStats {
                    domain: s.domain,
                    disk_bytes: r.map(|r| r.disk_used_bytes).unwrap_or(0),
                    bw_in_bytes_24h: r.map(|r| r.bw_in_bytes).unwrap_or(0),
                    bw_out_bytes_24h: r.map(|r| r.bw_out_bytes).unwrap_or(0),
                    requests_24h: r.map(|r| r.php_requests).unwrap_or(0),
                    // Same rule as hosting_stats: "we have at least one
                    // sample" ⇒ stamp now; never sampled ⇒ None.
                    last_request_at: r.filter(|r| r.periods > 0).map(|_| now),
                    sampled_at: d.map_or(0, |d| d.last_at),
                    mem_rss_bytes: match live_uid {
                        Some((l, uid)) => l.rss_bytes(uid),
                        None => r.map(|r| r.mem_rss_bytes).unwrap_or(0),
                    },
                    cpu_pct_x100: match live_uid {
                        Some((l, uid)) => l.uid_pct_x100(uid),
                        None => r.map(|r| r.cpu_pct_x100).unwrap_or(0),
                    },
                    cpu_live: live_uid.is_some(),
                    cpu_avg_24h_x100: d.and_then(|d| d.cpu_avg_x100()),
                    cpu_peak_24h_x100: d
                        .filter(|d| d.cpu_avg_x100().is_some())
                        .map(|d| d.cpu_peak_x100),
                    cpu_cores: live.as_ref().map_or(0, |l| l.cores),
                    hosting_id: s.id,
                }
            })
            .collect())
    }

    /// Usage of every active hosting over the last `window_secs`, one DB round
    /// per source. `0` is the live view: CPU and memory from the running
    /// sampler, traffic from the latest five-minute sample.
    pub async fn hosting_usage_range(
        &self,
        window_secs: i64,
    ) -> Result<Vec<hyperion_types::HostingUsageRange>, RpcError> {
        // The newest tick, however late `du` made it. Longer than one interval
        // or a late tick reads as no traffic at all.
        const LIVE_TRAFFIC_SECS: i64 = 400;
        let err = |e: hyperion_state::StateError| RpcError::Internal_with(format!("usage: {e}"));
        let now = now_secs();
        let is_live = window_secs <= 0;
        let since = now
            - if is_live {
                LIVE_TRAFFIC_SECS
            } else {
                window_secs.min(49 * 3600)
            };
        let summaries = self.list().await?;
        let disks = hyperion_state::limits::usage_rollup_all(&self.pool, 24)
            .await
            .map_err(err)?;
        let disk_by_id: HashMap<&str, &hyperion_state::limits::UsageRollup> =
            disks.iter().map(|r| (r.hosting_id.as_str(), r)).collect();
        let samples = hyperion_state::usage_samples::rollup_since(&self.pool, since, None)
            .await
            .map_err(err)?;
        let sample_by_id: HashMap<&str, &hyperion_state::usage_samples::UsageSampleRollup> =
            samples.iter().map(|r| (r.hosting_id.as_str(), r)).collect();
        let users = hyperion_state::hostings::system_users_by_hosting(&self.pool)
            .await
            .map_err(err)?;
        let live = self.cpu_tracker.live(now);
        let active: Vec<_> = summaries
            .into_iter()
            .filter(|s| matches!(s.state, HostingState::Active))
            .collect();
        let mut sites_per_uid: HashMap<i64, i64> = HashMap::new();
        for s in &active {
            if let Some((_, uid)) = users.get(s.id.as_str()) {
                *sites_per_uid.entry(*uid).or_default() += 1;
            }
        }
        Ok(active
            .into_iter()
            .map(|s| {
                let d = disk_by_id.get(s.id.as_str()).copied();
                let r = sample_by_id.get(s.id.as_str()).copied();
                let uid = users.get(s.id.as_str()).map(|(_, uid)| *uid);
                let live_uid = live.as_ref().zip(uid);
                let (cpu_pct_x100, cpu_peak_x100, mem_avg_bytes, mem_peak_bytes) = if is_live {
                    let rss = live_uid.map_or(0, |(l, uid)| l.rss_bytes(uid));
                    (live_uid.map(|(l, uid)| l.uid_pct_x100(uid)), None, rss, rss)
                } else {
                    let avg = r.and_then(|r| r.cpu_avg_x100());
                    (
                        avg,
                        r.filter(|_| avg.is_some()).map(|r| r.cpu_peak_x100),
                        r.map_or(0, |r| r.mem_avg_bytes),
                        r.map_or(0, |r| r.mem_peak_bytes),
                    )
                };
                hyperion_types::HostingUsageRange {
                    domain: s.domain,
                    disk_bytes: d.map_or(0, |d| d.disk_used_bytes),
                    cpu_pct_x100,
                    cpu_peak_x100,
                    cpu_cores: live.as_ref().map_or(0, |l| l.cores),
                    mem_avg_bytes,
                    mem_peak_bytes,
                    bw_in_bytes: r.map_or(0, |r| r.bw_in_bytes),
                    bw_out_bytes: r.map_or(0, |r| r.bw_out_bytes),
                    requests: r.map_or(0, |r| r.requests),
                    first_at: r.map_or(0, |r| r.first_at),
                    last_at: r.map_or(0, |r| r.last_at),
                    has_samples: d.is_some_and(|d| d.periods > 0) || r.is_some(),
                    shared_user_sites: uid
                        .and_then(|u| sites_per_uid.get(&u).copied())
                        .unwrap_or(1),
                    hosting_id: s.id,
                }
            })
            .collect())
    }

    /// One tick of the 10 s CPU sampler. Blocking `/proc` walk, off the runtime.
    pub async fn cpu_sample_tick(&self) {
        let snap = tokio::task::spawn_blocking(read_proc_snapshot)
            .await
            .ok()
            .flatten();
        if let Some(snap) = snap {
            self.cpu_tracker.observe(now_secs(), snap);
        }
    }

    pub async fn node_stats(&self, hostname: &str, version: &str) -> Result<NodeStats, RpcError> {
        let latest = metrics::latest(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("metrics: {e}")))?;
        let summaries = self.list().await?;
        // Local backup archives that are still on disk. Summed here rather
        // than sampled, so the figure never lags a delete or a fresh run.
        //
        // CRITICAL: only rows whose `archive_path` is still set count as "on
        // disk". A backup that was copied off-site and then dropped locally
        // keeps state='ok' but has its archive_path cleared — counting it here
        // reported bytes that are no longer on the node ("I deleted everything
        // and it still says 81 GiB"). The off-site copy is credited separately
        // in the per-hosting breakdown below.
        // Aggregated in SQL (GROUP BY hosting_id), so the figures are exact no
        // matter how many rows a busy node holds — an in-memory fold over a
        // capped `list_all` silently undercounts past the cap.
        let (backup_bytes, backup_count, backup_storage) =
            match hyperion_state::backups::storage_by_hosting(&self.pool).await {
                Ok(rows) => {
                    // Domain for each hosting id, from the summaries we already
                    // fetched — an id with no summary (deleted hosting whose
                    // rows linger) falls back to the id so it is still visible.
                    let domain_of: std::collections::HashMap<&str, &str> = summaries
                        .iter()
                        .map(|s| (s.id.as_str(), s.domain.as_str()))
                        .collect();
                    // The on-disk TOTAL is the sum of the per-hosting local
                    // footprints — same rows, so the KPI and the table can
                    // never disagree.
                    let total_bytes: i64 = rows.iter().map(|r| r.1).sum();
                    let total_count: i64 = rows.iter().map(|r| r.2).sum();
                    let mut storage: Vec<hyperion_types::BackupStorageRow> = rows
                        .into_iter()
                        .map(|(hid, lb, lc, ob, oc)| hyperion_types::BackupStorageRow {
                            domain: domain_of
                                .get(hid.as_str())
                                .map(|d| d.to_string())
                                .unwrap_or_else(|| hid.clone()),
                            hosting_id: hyperion_types::HostingId(hid),
                            local_bytes: lb,
                            local_count: lc,
                            offsite_bytes: ob,
                            offsite_count: oc,
                            untracked_bytes: 0,
                            untracked_count: 0,
                        })
                        .collect();
                    // The rows only know what was RECORDED. What the backup
                    // directory really holds can be far more: archives of
                    // hostings since deleted or moved away, a run that died
                    // before it was recorded. Reporting only the records said
                    // "0 B on server" over 24 GiB of real files.
                    let untracked = self.untracked_backup_files(&summaries).await;
                    let untracked_total: i64 = untracked.iter().map(|u| u.bytes).sum();
                    merge_untracked(&mut storage, untracked, &summaries);
                    // Biggest local footprint first — that is the row an
                    // operator hunting for disk is looking for.
                    storage.sort_by(|a, b| {
                        (b.local_bytes + b.untracked_bytes)
                            .cmp(&(a.local_bytes + a.untracked_bytes))
                            .then(b.offsite_bytes.cmp(&a.offsite_bytes))
                    });
                    (total_bytes + untracked_total, total_count, storage)
                }
                Err(e) => {
                    tracing::debug!(error=%e, "could not total backup sizes");
                    (0, 0, Vec::new())
                }
            };
        let mut ns = node_stats_from(
            hostname,
            version,
            latest,
            &summaries,
            backup_bytes,
            backup_count,
        );
        ns.backup_storage = backup_storage;
        // RAM / load / uptime are INSTANTANEOUS readings. The background sampler
        // only writes them every 5 min, so the gauge could be minutes stale and
        // never match a live `htop`/`free`. Read them LIVE here (this runs on
        // the node itself) so the headline number is current. The 24h aggregates
        // (disk, bandwidth, requests) legitimately stay from the latest sample.
        let pm = read_proc_metrics().await;
        if pm.mem_total_kib > 0 {
            ns.loadavg_1m_x100 = pm.loadavg_1m_x100;
            ns.mem_total_kib = pm.mem_total_kib;
            ns.mem_used_kib = pm.mem_used_kib;
            ns.uptime_secs = pm.uptime_secs;
            ns.cpu_pct_x100 = pm.cpu_pct_x100;
            ns.swap_total_kib = pm.swap_total_kib;
            ns.swap_used_kib = pm.swap_used_kib;
            ns.psi_cpu_x100 = pm.psi_cpu_x100;
            ns.psi_mem_x100 = pm.psi_mem_x100;
            ns.psi_io_x100 = pm.psi_io_x100;
            ns.net_rx_bps = pm.net_rx_bps;
            ns.net_tx_bps = pm.net_tx_bps;
            ns.sampled_at = now_secs(); // = "just now", so the freshness label is honest
        }
        // The sampler's last minute beats a 200 ms snapshot, and reads the same
        // window as the per-site figures, so the two can be compared.
        if let Some(live) = self.cpu_tracker.live(now_secs()) {
            let site_uids: std::collections::HashSet<i64> =
                hyperion_state::hostings::system_users_by_hosting(&self.pool)
                    .await
                    .unwrap_or_default()
                    .into_values()
                    .map(|(_, uid)| uid)
                    .collect();
            ns.cpu_pct_x100 = live.node_pct_x100();
            ns.cpu_cores = live.cores;
            ns.cpu_breakdown = Some(live.breakdown(&site_uids));
        }
        // OOM-kill counters (filled regardless of the /proc read).
        ns.oom_kills_24h =
            hyperion_state::oom_events::count_since(&self.pool, now_secs() - 24 * 3600)
                .await
                .unwrap_or(0);
        ns.last_oom_at = hyperion_state::oom_events::latest_at(&self.pool)
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
        Ok(ns)
    }

    /// One tick of the dedicated high-resolution sampler. `prev` holds the last
    /// per-interface counters + the MONOTONIC instant they were read, so the
    /// rate is bytes-since-last over real elapsed time. Cheap — /proc reads, no
    /// `du` — so it can run every few seconds, unlike `stats_tick`. Keeps ~1h.
    ///
    /// Two traps this avoids deliberately:
    ///   * `dt` comes from a MONOTONIC `Instant`, never the wall clock — a
    ///     backward clock step (chrony/timesyncd at boot, VM suspend/resume)
    ///     would otherwise shrink `dt` and report a spike many times the real
    ///     rate.
    ///   * the delta is summed PER INTERFACE over only the interfaces present
    ///     in BOTH reads: an interface that appears (bringing a nonzero
    ///     lifetime counter) or disappears between ticks contributes nothing,
    ///     and one interface's counter reset is skipped for that interface
    ///     alone instead of discarding the whole sample.
    pub async fn net_sample_tick(&self, prev: &mut NetSamplerState) -> Result<(), RpcError> {
        let mono = std::time::Instant::now();
        let now = now_secs();
        let Some(cur) = read_net_by_iface().await else {
            return Ok(());
        };
        let cur_map: std::collections::HashMap<String, (u64, u64)> =
            cur.into_iter().map(|(n, r, t)| (n, (r, t))).collect();
        if let Some((prev_map, pinstant)) = prev.as_ref() {
            let dt = mono.saturating_duration_since(*pinstant).as_secs();
            let (rx_bps, tx_bps) = net_rate_from_delta(prev_map, &cur_map, dt);
            let pm = read_proc_metrics().await;
            // The same last-minute figure the page prints above the graph.
            let cpu_pct_x100 = self
                .cpu_tracker
                .live(now)
                .map_or(pm.cpu_pct_x100, |live| live.node_pct_x100());
            let sample = hyperion_state::net_samples::NetSample {
                at: now,
                rx_bps,
                tx_bps,
                cpu_pct_x100,
                loadavg_1m_x100: pm.loadavg_1m_x100,
                mem_used_kib: pm.mem_used_kib,
                mem_total_kib: pm.mem_total_kib,
            };
            if let Err(e) = hyperion_state::net_samples::insert(&self.pool, &sample).await {
                tracing::debug!(error=%e, "net sample insert failed");
            }
            // Short rolling window — the graph only shows the last hour.
            let _ = hyperion_state::net_samples::prune_older_than(&self.pool, now - 3600).await;
        }
        *prev = Some((cur_map, mono));
        Ok(())
    }

    /// High-resolution history (oldest → newest) for the realtime stats
    /// sparklines. Empty until the sampler has taken two ticks.
    pub async fn net_history(&self, limit: i64) -> Result<hyperion_types::NetHistory, RpcError> {
        let samples = hyperion_state::net_samples::recent(&self.pool, limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("net_history: {e}")))?
            .into_iter()
            .map(|s| hyperion_types::NetSamplePoint {
                at: s.at,
                rx_bps: s.rx_bps,
                tx_bps: s.tx_bps,
                cpu_pct_x100: s.cpu_pct_x100,
                loadavg_1m_x100: s.loadavg_1m_x100,
                mem_used_kib: s.mem_used_kib,
                mem_total_kib: s.mem_total_kib,
            })
            .collect();
        Ok(hyperion_types::NetHistory { samples })
    }

    /// Recent samples from `node_metrics` shaped for the stats page's
    /// sparkline charts. Wrapper around the storage layer that drops
    /// the columns the template doesn't need.
    pub async fn node_metrics_history(
        &self,
        limit: i64,
    ) -> Result<hyperion_types::NodeMetricsHistory, RpcError> {
        let rows = hyperion_state::metrics::history(&self.pool, limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("metrics history: {e}")))?;
        let samples = rows
            .into_iter()
            .map(|r| hyperion_types::NodeMetricPoint {
                at: r.sampled_at,
                loadavg_1m_x100: r.loadavg_1m_x100,
                mem_used_kib: r.mem_used_kib,
                mem_total_kib: r.mem_total_kib,
                total_bw_out_24h: r.total_bw_out_24h,
                total_requests_24h: r.total_requests_24h,
                hostings_count: r.hostings_count,
                cpu_pct_x100: r.cpu_pct_x100,
                swap_used_kib: r.swap_used_kib,
                net_rx_bps: r.net_rx_bps,
                net_tx_bps: r.net_tx_bps,
            })
            .collect();
        Ok(hyperion_types::NodeMetricsHistory { samples })
    }

    pub async fn cluster_stats(
        &self,
        hostname: &str,
        version: &str,
    ) -> Result<ClusterStats, RpcError> {
        let n = self.node_stats(hostname, version).await?;
        Ok(ClusterStats {
            total_hostings: n.hostings_count,
            total_active: n.hostings_active,
            total_suspended: n.hostings_suspended,
            total_failed: n.hostings_failed,
            total_disk_bytes: n.total_disk_bytes,
            total_hostings_disk_bytes: n.hostings_disk_bytes,
            total_node_disk_total_bytes: n.node_disk_total_bytes,
            total_bw_out_24h: n.total_bw_out_24h,
            total_requests_24h: n.total_requests_24h,
            nodes: vec![n],
        })
    }
}

/// Backup files of one domain that are on disk but named by no backup record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UntrackedBackups {
    pub(super) domain: String,
    pub(super) bytes: i64,
    /// `.tar.gz` archives among them.
    pub(super) archives: i64,
}

/// One file in the backup directory that no backup record names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UntrackedFile {
    /// The domain from its name, or `<user>/` when the name is not one of
    /// ours (such a file is reported, never offered for deletion).
    pub(super) key: String,
    /// True when the name parsed as a backup file of `key`.
    pub(super) ours: bool,
    pub(super) path: std::path::PathBuf,
    pub(super) bytes: i64,
    pub(super) is_archive: bool,
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Per domain, every file in the backup directory that no backup row
    /// accounts for. See [`Self::untracked_backup_file_list`].
    async fn untracked_backup_files(&self, summaries: &[HostingSummary]) -> Vec<UntrackedBackups> {
        let mut by_domain: std::collections::BTreeMap<String, (i64, i64)> =
            std::collections::BTreeMap::new();
        for f in self.untracked_backup_file_list(summaries).await {
            let e = by_domain.entry(f.key).or_insert((0, 0));
            e.0 += f.bytes;
            e.1 += f.is_archive as i64;
        }
        by_domain
            .into_iter()
            .map(|(domain, (bytes, archives))| UntrackedBackups {
                domain,
                bytes,
                archives,
            })
            .collect()
    }

    /// Walk `<backup_root>/<user>/` and list every file that no backup row
    /// accounts for. A failed read of the table or the directory yields
    /// nothing rather than a guess: claiming files are untracked when the
    /// claim list is unknown would be its own lie — and the delete action
    /// acts on this list.
    async fn untracked_backup_file_list(&self, summaries: &[HostingSummary]) -> Vec<UntrackedFile> {
        let (paths, running) = match hyperion_state::backups::claimed_local_files(&self.pool).await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "could not list recorded backup files");
                return Vec::new();
            }
        };
        let mut claimed: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        for p in paths {
            let p = std::path::PathBuf::from(p);
            // The manifest is written beside the archive and no column names it.
            if let Some(m) = super::offsite::manifest_path_for(&p) {
                claimed.insert(m);
            }
            claimed.insert(p);
        }
        let domain_of: std::collections::HashMap<&str, &str> = summaries
            .iter()
            .map(|s| (s.id.as_str(), s.domain.as_str()))
            .collect();
        let running: Vec<(String, i64)> = running
            .into_iter()
            .filter_map(|(hid, at)| domain_of.get(hid.as_str()).map(|d| (d.to_string(), at)))
            .collect();
        let root = std::path::PathBuf::from(&self.paths.backup_root);
        tokio::task::spawn_blocking(move || scan_untracked_backups(&root, &claimed, &running))
            .await
            .unwrap_or_default()
    }

    /// Delete the untracked backup files of one domain — the ones "Backups by
    /// site" reports as untracked. The list is taken afresh here, never from
    /// the page: a file a backup record has claimed since, or one a run in
    /// progress is writing, is not on it. Only files whose name is one of ours
    /// for exactly `domain` go; anything else in the directory is left alone.
    /// Returns `(files removed, bytes freed)`.
    pub async fn backup_untracked_delete(&self, domain: &str) -> Result<(u64, i64), RpcError> {
        let domain = domain.trim();
        if domain.is_empty() {
            return Err(RpcError::Validation {
                message: "no domain given".into(),
            });
        }
        let summaries = self.list().await?;
        let files: Vec<UntrackedFile> = self
            .untracked_backup_file_list(&summaries)
            .await
            .into_iter()
            .filter(|f| f.ours && f.key == domain)
            .collect();
        let mut removed = 0u64;
        let mut freed = 0i64;
        let mut errors: Vec<String> = Vec::new();
        for f in &files {
            // A push or restore reading it right now keeps it.
            if super::offsite::archive_in_use(&f.path) {
                continue;
            }
            match tokio::fs::remove_file(&f.path).await {
                Ok(()) => {
                    removed += 1;
                    freed += f.bytes;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => errors.push(format!("{}: {e}", f.path.display())),
            }
        }
        self.append_audit(
            "backup.untracked.delete",
            None,
            &serde_json::json!({
                "domain": domain,
                "files_removed": removed,
                "bytes_freed": freed,
                "errors": errors,
            })
            .to_string(),
            if errors.is_empty() { "ok" } else { "partial" },
        )
        .await;
        if removed == 0 && !errors.is_empty() {
            return Err(RpcError::Internal_with(errors.join("; ")));
        }
        Ok((removed, freed))
    }
}

/// The blocking half of [`HostingService::untracked_backup_file_list`]: one
/// level of per-user directories under `root`, regular files only (a symlink
/// is never followed or counted). `running` holds `(domain, started_at)` of
/// runs in progress — their files exist before any row names them, so a file
/// of that domain stamped at or after the start (less a minute of clock slack
/// between the row and the file name) is skipped.
pub(super) fn scan_untracked_backups(
    root: &std::path::Path,
    claimed: &std::collections::HashSet<std::path::PathBuf>,
    running: &[(String, i64)],
) -> Vec<UntrackedFile> {
    let mut out = Vec::new();
    let Ok(users) = std::fs::read_dir(root) else {
        return out;
    };
    for user in users.flatten() {
        let Ok(ft) = user.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(user.path()) else {
            continue;
        };
        for f in files.flatten() {
            let path = f.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_file() || claimed.contains(&path) {
                continue;
            }
            let name = f.file_name().to_string_lossy().into_owned();
            let parsed = parse_backup_file_name(&name);
            if let Some((domain, ts, _)) = parsed {
                if running
                    .iter()
                    .any(|(d, at)| d == domain && ts >= at.saturating_sub(60))
                {
                    continue;
                }
            }
            // A file that is not one of ours by name still sits in the
            // backup directory and still takes the space: count it under
            // its directory (the system user) rather than drop it.
            let (key, ours, is_archive) = match parsed {
                Some((domain, _, ext)) => (domain.to_string(), true, ext == "tar.gz"),
                None => (
                    format!("{}/", user.file_name().to_string_lossy()),
                    false,
                    false,
                ),
            };
            out.push(UntrackedFile {
                key,
                ours,
                path,
                bytes: meta.len() as i64,
                is_archive,
            });
        }
    }
    out
}

/// `<domain>-<unix secs>.<tar.gz|sql|manifest.json>`, the names `BackupFiles`
/// gives a run's files, into `(domain, stamp, extension)`.
pub(super) fn parse_backup_file_name(name: &str) -> Option<(&str, i64, &'static str)> {
    let (stem, ext) = ["tar.gz", "sql", "manifest.json"]
        .into_iter()
        .find_map(|ext| Some((name.strip_suffix(ext)?.strip_suffix('.')?, ext)))?;
    let (domain, ts) = stem.rsplit_once('-')?;
    if domain.is_empty() || ts.is_empty() || !ts.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((domain, ts.parse().ok()?, ext))
}

/// Fold the untracked files into the per-site rows: onto the site's own row
/// when it has one, else a new row — linked to the hosting when one on this
/// node has the domain, unlinked (empty id) when none does.
pub(super) fn merge_untracked(
    storage: &mut Vec<hyperion_types::BackupStorageRow>,
    untracked: Vec<UntrackedBackups>,
    summaries: &[HostingSummary],
) {
    for u in untracked {
        if let Some(row) = storage.iter_mut().find(|r| r.domain == u.domain) {
            row.untracked_bytes += u.bytes;
            row.untracked_count += u.archives;
            continue;
        }
        let hosting_id = summaries
            .iter()
            .find(|s| s.domain == u.domain)
            .map(|s| s.id.clone())
            .unwrap_or_else(|| hyperion_types::HostingId(String::new()));
        storage.push(hyperion_types::BackupStorageRow {
            hosting_id,
            domain: u.domain,
            local_bytes: 0,
            local_count: 0,
            offsite_bytes: 0,
            offsite_count: 0,
            untracked_bytes: u.bytes,
            untracked_count: u.archives,
        });
    }
}

pub(super) fn node_stats_from(
    hostname: &str,
    version: &str,
    latest: Option<metrics::NodeMetricsRow>,
    summaries: &[HostingSummary],
    backup_bytes: i64,
    backup_count: i64,
) -> NodeStats {
    let (a, s, f) = summaries
        .iter()
        .fold((0i64, 0i64, 0i64), |(a, s, f), x| match x.state {
            HostingState::Active => (a + 1, s, f),
            HostingState::Suspended => (a, s + 1, f),
            HostingState::Failed => (a, s, f + 1),
            _ => (a, s, f),
        });
    let count = summaries.len() as i64;
    match latest {
        Some(r) => NodeStats {
            backup_bytes,
            backup_count,
            node_id: hostname.to_string(),
            label: hostname.to_string(),
            hostings_count: count,
            hostings_active: a,
            hostings_suspended: s,
            hostings_failed: f,
            total_disk_bytes: r.total_disk_bytes,
            hostings_disk_bytes: r.hostings_disk_bytes,
            node_disk_total_bytes: r.node_disk_total_bytes,
            total_bw_out_24h: r.total_bw_out_24h,
            total_requests_24h: r.total_requests_24h,
            loadavg_1m_x100: r.loadavg_1m_x100,
            mem_total_kib: r.mem_total_kib,
            mem_used_kib: r.mem_used_kib,
            uptime_secs: r.uptime_secs,
            sampled_at: r.sampled_at,
            agent_version: version.to_string(),
            agent_online: true,
            cpu_pct_x100: r.cpu_pct_x100,
            cpu_cores: 0,
            cpu_breakdown: None,
            swap_total_kib: r.swap_total_kib,
            swap_used_kib: r.swap_used_kib,
            psi_cpu_x100: r.psi_cpu_x100,
            psi_mem_x100: r.psi_mem_x100,
            psi_io_x100: r.psi_io_x100,
            net_rx_bps: r.net_rx_bps,
            net_tx_bps: r.net_tx_bps,
            oom_kills_24h: 0, // filled by node_stats() (needs DB access)
            last_oom_at: 0,
            backup_storage: Vec::new(),
        },
        None => NodeStats {
            backup_bytes,
            backup_count,
            node_id: hostname.to_string(),
            label: hostname.to_string(),
            hostings_count: count,
            hostings_active: a,
            hostings_suspended: s,
            hostings_failed: f,
            total_disk_bytes: 0,
            hostings_disk_bytes: 0,
            node_disk_total_bytes: 0,
            total_bw_out_24h: 0,
            total_requests_24h: 0,
            loadavg_1m_x100: 0,
            mem_total_kib: 0,
            mem_used_kib: 0,
            uptime_secs: 0,
            sampled_at: 0,
            agent_version: version.to_string(),
            agent_online: true,
            cpu_pct_x100: 0,
            cpu_cores: 0,
            cpu_breakdown: None,
            swap_total_kib: 0,
            swap_used_kib: 0,
            psi_cpu_x100: 0,
            psi_mem_x100: 0,
            psi_io_x100: 0,
            net_rx_bps: 0,
            net_tx_bps: 0,
            oom_kills_24h: 0,
            last_oom_at: 0,
            backup_storage: Vec::new(),
        },
    }
}

/// Instantaneous node metrics read straight from /proc. CPU% and network rate
/// require a delta, so this samples twice ~200 ms apart — cheap enough for the
/// 5-min sampler and a page load.
#[derive(Debug, Clone, Default)]
pub(super) struct ProcMetrics {
    pub(super) loadavg_1m_x100: i64,
    pub(super) mem_total_kib: i64,
    pub(super) mem_used_kib: i64,
    pub(super) uptime_secs: i64,
    pub(super) cpu_pct_x100: i64,
    pub(super) swap_total_kib: i64,
    pub(super) swap_used_kib: i64,
    pub(super) psi_cpu_x100: i64,
    pub(super) psi_mem_x100: i64,
    pub(super) psi_io_x100: i64,
    pub(super) net_rx_bps: i64,
    pub(super) net_tx_bps: i64,
}

/// `(busy_jiffies, total_jiffies)` from the aggregate `cpu` line of /proc/stat.
/// busy = total - idle - iowait.
pub(super) async fn read_cpu_jiffies() -> Option<(u64, u64)> {
    let s = tokio::fs::read_to_string("/proc/stat").await.ok()?;
    let (busy, total, _) = parse_proc_stat_cpu(&s)?;
    Some((busy.max(0) as u64, total.max(0) as u64))
}

/// Rolling state the network sampler carries between ticks: the last
/// per-interface `(rx_bytes, tx_bytes)` counters and the monotonic instant they
/// were read. `None` before the first tick. Owned by the agent's sampler task,
/// passed to [`HostingService::net_sample_tick`].
pub type NetSamplerState = Option<(
    std::collections::HashMap<String, (u64, u64)>,
    std::time::Instant,
)>;

/// bytes/sec (rx, tx) between two per-interface counter snapshots over `dt`
/// seconds. Summed over only the interfaces present in BOTH maps, and a
/// per-interface counter that went backwards is skipped for that interface —
/// so a new/removed interface, or a single interface's reset, cannot dump a
/// lifetime counter into one window. `dt` is floored at 1s (divide-by-zero
/// guard); the caller sources it from a MONOTONIC clock so it is never
/// negative.
pub(super) fn net_rate_from_delta(
    prev: &std::collections::HashMap<String, (u64, u64)>,
    cur: &std::collections::HashMap<String, (u64, u64)>,
    dt_secs: u64,
) -> (i64, i64) {
    let dt = dt_secs.max(1);
    let mut rx = 0u64;
    let mut tx = 0u64;
    for (name, (cr, ct)) in cur {
        if let Some((pr, pt)) = prev.get(name) {
            if cr >= pr {
                rx += cr - pr;
            }
            if ct >= pt {
                tx += ct - pt;
            }
        }
    }
    ((rx / dt) as i64, (tx / dt) as i64)
}

/// Per-interface `(name, rx_bytes, tx_bytes)` for every non-loopback interface
/// in /proc/net/dev. Kept per-name (not pre-summed) so a rate sampler can diff
/// each interface independently: an interface that appears or disappears
/// between two reads then contributes nothing, instead of dumping its whole
/// lifetime counter into one window.
pub(super) async fn read_net_by_iface() -> Option<Vec<(String, u64, u64)>> {
    let s = tokio::fs::read_to_string("/proc/net/dev").await.ok()?;
    let mut out = Vec::new();
    for line in s.lines() {
        let Some((iface, rest)) = line.split_once(':') else {
            continue;
        };
        let iface = iface.trim();
        if iface == "lo" || iface.is_empty() {
            continue;
        }
        let cols: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        // /proc/net/dev: rx_bytes is col 0, tx_bytes is col 8.
        if let (Some(r), Some(t)) = (cols.first(), cols.get(8)) {
            out.push((iface.to_string(), *r, *t));
        }
    }
    Some(out)
}

/// `(rx_bytes, tx_bytes)` summed over every non-loopback interface in
/// /proc/net/dev.
pub(super) async fn read_net_bytes() -> Option<(u64, u64)> {
    let per = read_net_by_iface().await?;
    let mut rx = 0u64;
    let mut tx = 0u64;
    for (_, r, t) in per {
        rx += r;
        tx += t;
    }
    Some((rx, tx))
}

/// `some avg10` (×100) from /proc/pressure/<resource>. 0 when PSI is
/// unavailable (kernel without CONFIG_PSI). Line: `some avg10=0.00 avg60=...`.
pub(super) async fn read_psi_some_avg10(resource: &str) -> i64 {
    read_psi_some(resource, "avg10=").await
}

/// [`read_psi_some_avg10`] over the last minute, for a decision that a burst
/// of a few seconds should not swing.
pub(super) async fn read_psi_some_avg60(resource: &str) -> i64 {
    read_psi_some(resource, "avg60=").await
}

async fn read_psi_some(resource: &str, field: &str) -> i64 {
    let path = format!("/proc/pressure/{resource}");
    let Ok(s) = tokio::fs::read_to_string(&path).await else {
        return 0;
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("some ") {
            for tok in rest.split_whitespace() {
                if let Some(v) = tok.strip_prefix(field) {
                    return v.parse::<f64>().map(|f| (f * 100.0) as i64).unwrap_or(0);
                }
            }
        }
    }
    0
}

/// `MemTotal` from /proc/meminfo, in MiB. `None` off Linux or on a parse
/// failure — callers then skip the RAM bound rather than guess one.
pub(super) async fn read_mem_total_mb() -> Option<i64> {
    let s = tokio::fs::read_to_string("/proc/meminfo").await.ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kib| kib.parse::<i64>().ok())
        .map(|kib| kib / 1024)
        .filter(|&mb| mb > 0)
}

/// `MemAvailable` from /proc/meminfo, in MiB. `None` as for
/// [`read_mem_total_mb`].
pub(super) async fn read_mem_available_mb() -> Option<i64> {
    let s = tokio::fs::read_to_string("/proc/meminfo").await.ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kib| kib.parse::<i64>().ok())
        .map(|kib| kib / 1024)
}

pub(super) async fn read_proc_metrics() -> ProcMetrics {
    let loadavg = tokio::fs::read_to_string("/proc/loadavg").await.ok();
    let la_1m = loadavg
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|t| t.parse::<f64>().ok())
        })
        .map(|f| (f * 100.0) as i64)
        .unwrap_or(0);

    let meminfo = tokio::fs::read_to_string("/proc/meminfo").await.ok();
    let (mem_total, mem_avail, swap_total, swap_free) = meminfo
        .map(|s| {
            let field = |line: &str, key: &str| -> Option<i64> {
                line.strip_prefix(key)?
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse().ok())
            };
            let (mut t, mut a, mut st, mut sf) = (0i64, 0i64, 0i64, 0i64);
            for l in s.lines() {
                if let Some(v) = field(l, "MemTotal:") {
                    t = v;
                } else if let Some(v) = field(l, "MemAvailable:") {
                    a = v;
                } else if let Some(v) = field(l, "SwapTotal:") {
                    st = v;
                } else if let Some(v) = field(l, "SwapFree:") {
                    sf = v;
                }
            }
            (t, a, st, sf)
        })
        .unwrap_or((0, 0, 0, 0));
    let mem_used = (mem_total - mem_avail).max(0);
    let swap_used = (swap_total - swap_free).max(0);

    let uptime = tokio::fs::read_to_string("/proc/uptime")
        .await
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|t| t.parse::<f64>().ok())
        })
        .map(|f| f as i64)
        .unwrap_or(0);

    // CPU% + network rate need a delta: snapshot, wait, snapshot.
    let cpu0 = read_cpu_jiffies().await;
    let net0 = read_net_bytes().await;
    const DT_MS: u64 = 200;
    tokio::time::sleep(std::time::Duration::from_millis(DT_MS)).await;
    let cpu1 = read_cpu_jiffies().await;
    let net1 = read_net_bytes().await;

    let cpu_pct_x100 = match (cpu0, cpu1) {
        (Some((b0, t0)), Some((b1, t1))) if t1 > t0 => {
            (((b1 - b0) as f64 / (t1 - t0) as f64) * 10000.0) as i64
        }
        _ => 0,
    };
    let dt_secs = DT_MS as f64 / 1000.0;
    let rate = |a: u64, b: u64| -> i64 {
        if b >= a {
            ((b - a) as f64 / dt_secs) as i64
        } else {
            0 // counter wrapped/reset
        }
    };
    let (net_rx_bps, net_tx_bps) = match (net0, net1) {
        (Some((r0, t0)), Some((r1, t1))) => (rate(r0, r1), rate(t0, t1)),
        _ => (0, 0),
    };

    ProcMetrics {
        loadavg_1m_x100: la_1m,
        mem_total_kib: mem_total,
        mem_used_kib: mem_used,
        uptime_secs: uptime,
        cpu_pct_x100,
        swap_total_kib: swap_total,
        swap_used_kib: swap_used,
        psi_cpu_x100: read_psi_some_avg10("cpu").await,
        psi_mem_x100: read_psi_some_avg10("memory").await,
        psi_io_x100: read_psi_some_avg10("io").await,
        net_rx_bps,
        net_tx_bps,
    }
}

/// (pid, comm) from a kernel OOM line containing "Killed process 1234 (comm)".
pub(super) fn parse_oom_kill(msg: &str) -> (i64, String) {
    let Some(idx) = msg.find("Killed process ") else {
        return (0, String::new());
    };
    let rest = &msg[idx + "Killed process ".len()..];
    let pid = rest
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    let comm = rest
        .split_once('(')
        .and_then(|(_, t)| t.split_once(')').map(|(c, _)| c.to_string()))
        .unwrap_or_default();
    (pid, comm)
}

/// Snapshot of one filesystem's usage, parsed from `df -P -B1`.
/// `used_pct` is rounded down so a 79.999% filesystem is reported
/// as 79, not 80 — operators trust round trips of this number.
#[derive(Debug, Clone)]
pub(super) struct DiskUsage {
    pub(super) mount: String,
    pub(super) total_bytes: i64,
    pub(super) used_bytes: i64,
    pub(super) used_pct: i64,
}

/// Probe filesystem usage via `df -P -B1` on the mounts the panel
/// cares about. POSIX mode (`-P`) keeps the columns stable across
/// distros; `-B1` outputs bytes (not KiB) so the math is exact.
///
/// Returns empty on any parsing failure — alerts are best-effort
/// and we'd rather under-warn than crash the dashboard.
pub(super) async fn probe_disk_usages() -> std::io::Result<Vec<DiskUsage>> {
    // Hand-picked list: the mountpoints any practical Hyperion
    // node could fill up. `/var` is where hosting trees + DB dumps
    // + nginx logs + apt cache + hyperion's own data dir
    // (/var/lib/hyperion) all live; `/` covers everything else
    // including immutable images that don't carve /var separately.
    // df ignores a missing mount with exit 1 and an error on
    // stderr; we just drop those rows.
    let out = tokio::process::Command::new("df")
        .args(["-P", "-B1", "/", "/var", "/home", "/tmp"])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut seen_mounts = std::collections::HashSet::new();
    let mut rows = Vec::new();
    // First line is the header — skip it.
    for line in stdout.lines().skip(1) {
        // `df -P -B1` columns: Filesystem 1-blocks Used Available Capacity Mounted-on
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let mount = cols[cols.len() - 1].to_string();
        // The same physical device often appears multiple times in
        // our requested list (`/` and `/home` on a single-partition
        // VPS). Dedup by mount so we don't double-alert.
        if !seen_mounts.insert(mount.clone()) {
            continue;
        }
        let total: i64 = cols[1].parse().unwrap_or(0);
        let used: i64 = cols[2].parse().unwrap_or(0);
        if total <= 0 {
            continue;
        }
        // `df` rounds Capacity to whole percent; redo it ourselves
        // from bytes for accuracy.
        let pct = (used.saturating_mul(100) / total).clamp(0, 100);
        rows.push(DiskUsage {
            mount,
            total_bytes: total,
            used_bytes: used,
            used_pct: pct,
        });
    }
    Ok(rows)
}

/// Format `bytes` as a short human string ("12.3 GiB"). Used by
/// the dashboard banner — the operator wants "8 GiB free" not
/// "8589934592 bytes". Caps at TiB; anything bigger would be a
/// genuine surprise on a hosting node.
pub(super) fn human_bytes(bytes: i64) -> String {
    let units = [
        ("TiB", 1i64 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (label, scale) in units.iter() {
        if bytes >= *scale {
            return format!("{:.1} {}", bytes as f64 / *scale as f64, label);
        }
    }
    format!("{bytes} B")
}
