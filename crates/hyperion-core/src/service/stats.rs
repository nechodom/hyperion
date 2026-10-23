//! Metrics collection and readback: hostings, nodes, network history.

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

        // One /proc pass-pair (200 ms apart) to attribute live memory + CPU to
        // each hosting's system_user — Hyperion runs one php-fpm pool per user,
        // so a site's footprint is its user's processes. This is the only
        // per-tick /proc walk; the per-hosting loop just looks up by uid.
        let proc1 = scan_proc_usage_by_uid().await;
        let cpu_total1 = read_cpu_jiffies().await.map(|(_, t)| t).unwrap_or(0) as i64;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let proc2 = scan_proc_usage_by_uid().await;
        let cpu_total2 = read_cpu_jiffies().await.map(|(_, t)| t).unwrap_or(0) as i64;
        let cpu_total_delta = (cpu_total2 - cpu_total1).max(1);

        for s in &summaries {
            let user = derive_user_from_summary(s);
            let host_root = std::path::PathBuf::from(&self.paths.home_root)
                .join(user.clone().unwrap_or_else(|| "_".to_string()))
                .join(&s.domain);
            // `derive_user_from_summary` GUESSES the system user from the
            // domain, and an imported or renamed site defeats the guess. The
            // path then points at nothing, `du` and the log parse both answer
            // zero, and the row that gets written is indistinguishable from a
            // real measurement: the customer's letter reads "0 requests, 0 B
            // sent, peak disk 0 B … these figures cover the whole period" for
            // a live site with gigabytes of files.
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

            // Per-hosting RSS + CPU% from this user's processes.
            let (mem_rss, cpu_pct) = match &user {
                Some(uname) => {
                    match hyperion_state::system_users::get_by_name(&self.pool, uname).await {
                        Ok(Some(su)) => {
                            let rss = proc2.get(&su.uid).map(|(r, _)| *r).unwrap_or(0);
                            let c0 = proc1.get(&su.uid).map(|(_, c)| *c).unwrap_or(0);
                            let c1 = proc2.get(&su.uid).map(|(_, c)| *c).unwrap_or(0);
                            (rss, (c1 - c0).max(0) * 10000 / cpu_total_delta)
                        }
                        _ => (0, 0),
                    }
                }
                None => (0, 0),
            };

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
                cpu_pct_x100: pm.cpu_pct_x100,
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
        let (mem_rss, cpu_pct) = rows
            .first()
            .map(|r| (r.mem_rss_bytes, r.cpu_pct_x100))
            .unwrap_or((0, 0));
        Ok(HostingStats {
            hosting_id: detail.id,
            domain: detail.domain,
            disk_bytes: disk,
            bw_in_bytes_24h: bw_in,
            bw_out_bytes_24h: bw_out,
            requests_24h: reqs,
            last_request_at: rows.first().map(|_| now),
            sampled_at: now,
            mem_rss_bytes: mem_rss,
            cpu_pct_x100: cpu_pct,
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
        // Drive the list from the HOSTINGS, not from the usage rows: a
        // site created since the last sampler tick has no usage rows
        // yet, and it must still show up (all zeros) instead of
        // silently vanishing from the breakdown.
        Ok(summaries
            .into_iter()
            .filter(|s| matches!(s.state, HostingState::Active))
            .map(|s| {
                let r = by_id.get(s.id.as_str()).copied();
                HostingStats {
                    hosting_id: s.id,
                    domain: s.domain,
                    disk_bytes: r.map(|r| r.disk_used_bytes).unwrap_or(0),
                    bw_in_bytes_24h: r.map(|r| r.bw_in_bytes).unwrap_or(0),
                    bw_out_bytes_24h: r.map(|r| r.bw_out_bytes).unwrap_or(0),
                    requests_24h: r.map(|r| r.php_requests).unwrap_or(0),
                    // Same rule as hosting_stats: "we have at least one
                    // sample" ⇒ stamp now; never sampled ⇒ None.
                    last_request_at: r.filter(|r| r.periods > 0).map(|_| now),
                    sampled_at: now,
                    mem_rss_bytes: r.map(|r| r.mem_rss_bytes).unwrap_or(0),
                    cpu_pct_x100: r.map(|r| r.cpu_pct_x100).unwrap_or(0),
                }
            })
            .collect())
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
                        })
                        .collect();
                    // Biggest local footprint first — that is the row an
                    // operator hunting for disk is looking for.
                    storage.sort_by(|a, b| {
                        b.local_bytes
                            .cmp(&a.local_bytes)
                            .then(b.offsite_bytes.cmp(&a.offsite_bytes))
                    });
                    (total_bytes, total_count, storage)
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

    /// One tick of the dedicated high-resolution network sampler. `prev` holds
    /// the last per-interface counters + the MONOTONIC instant they were read,
    /// so the rate is bytes-since-last over real elapsed time. Cheap — one
    /// /proc/net/dev read, no `du` — so it can run every few seconds, unlike
    /// `stats_tick`. Keeps ~1h.
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
            if let Err(e) =
                hyperion_state::net_samples::insert(&self.pool, now, rx_bps, tx_bps).await
            {
                tracing::debug!(error=%e, "net sample insert failed");
            }
            // Short rolling window — the graph only shows the last hour.
            let _ = hyperion_state::net_samples::prune_older_than(&self.pool, now - 3600).await;
        }
        *prev = Some((cur_map, mono));
        Ok(())
    }

    /// High-resolution network history (oldest → newest) for the realtime
    /// stats sparkline. Empty until the sampler has taken two ticks.
    pub async fn net_history(&self, limit: i64) -> Result<hyperion_types::NetHistory, RpcError> {
        let samples = hyperion_state::net_samples::recent(&self.pool, limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("net_history: {e}")))?
            .into_iter()
            .map(|s| hyperion_types::NetSamplePoint {
                at: s.at,
                rx_bps: s.rx_bps,
                tx_bps: s.tx_bps,
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
    let line = s.lines().next()?; // "cpu  u n s idle iowait irq softirq steal ..."
    let mut it = line.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let vals: Vec<u64> = it.filter_map(|v| v.parse::<u64>().ok()).collect();
    if vals.len() < 5 {
        return None;
    }
    let total: u64 = vals.iter().sum();
    let idle = vals[3] + vals.get(4).copied().unwrap_or(0); // idle + iowait
    Some((total.saturating_sub(idle), total))
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
    let path = format!("/proc/pressure/{resource}");
    let Ok(s) = tokio::fs::read_to_string(&path).await else {
        return 0;
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("some ") {
            for tok in rest.split_whitespace() {
                if let Some(v) = tok.strip_prefix("avg10=") {
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

/// utime+stime jiffies from a `/proc/<pid>/stat` line. `comm` (field 2) can
/// contain spaces and parens, so we anchor on the LAST ')' and count fields
/// after it: utime is the 12th, stime the 13th token there.
pub(super) fn parse_stat_cpu_jiffies(s: &str) -> i64 {
    let after = match s.rfind(')') {
        Some(i) => &s[i + 1..],
        None => return 0,
    };
    let toks: Vec<&str> = after.split_whitespace().collect();
    let utime = toks
        .get(11)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let stime = toks
        .get(12)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    utime + stime
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

/// One pass over /proc: per-UID (summed RSS bytes, summed CPU jiffies) across
/// that user's processes. Used to attribute memory + CPU to each hosting via
/// its system_user — Hyperion runs one php-fpm pool per user, so a hosting's
/// footprint is its user's processes. RSS overcounts shared pages (PHP binary
/// / opcache shared across workers); it's the standard pragmatic figure.
pub(super) async fn scan_proc_usage_by_uid() -> std::collections::HashMap<i64, (i64, i64)> {
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt;
    const PAGE: i64 = 4096; // Debian x86_64 page size
    let mut map: HashMap<i64, (i64, i64)> = HashMap::new();
    let Ok(mut rd) = tokio::fs::read_dir("/proc").await else {
        return map;
    };
    while let Ok(Some(ent)) = rd.next_entry().await {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue; // not a pid dir
        }
        let dir = ent.path();
        let Ok(meta) = tokio::fs::metadata(&dir).await else {
            continue; // process exited between readdir and stat
        };
        let uid = meta.uid() as i64;
        let rss = tokio::fs::read_to_string(dir.join("statm"))
            .await
            .ok()
            .and_then(|s| {
                s.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<i64>().ok())
            })
            .unwrap_or(0)
            * PAGE;
        let cpu = tokio::fs::read_to_string(dir.join("stat"))
            .await
            .map(|s| parse_stat_cpu_jiffies(&s))
            .unwrap_or(0);
        let e = map.entry(uid).or_insert((0, 0));
        e.0 += rss;
        e.1 += cpu;
    }
    map
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
