//! WordPress update detection, auto-updates and the Hyperion plugin.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Whether this node applies Hyperion updates by itself, from
    /// `[update] auto`. Default OFF.
    ///
    /// Off by default because unattended updates of the thing that runs
    /// everyone's sites is a decision an operator makes deliberately, not one
    /// they discover. When it IS on, the update always runs in safe mode:
    /// automatic and irreversible is a combination worth avoiding, and the
    /// operator is asleep precisely when this fires.
    pub fn auto_update_enabled(&self) -> bool {
        self.agent_config_path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|raw| raw.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|doc| {
                doc.get("update")
                    .and_then(|s| s.get("auto"))
                    .and_then(|v| v.as_bool())
            })
            .unwrap_or(false)
    }

    /// Check for a new release and, when auto-update is on, apply it in safe
    /// mode. Returns true when an update was STARTED.
    pub async fn auto_update_tick(&self) -> bool {
        if !self.auto_update_enabled() {
            return false;
        }
        let status = match self.update_check(false).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error=%e, "auto-update: version probe failed");
                return false;
            }
        };
        if !status.update_available {
            return false;
        }
        tracing::info!(
            current = %status.current_sha,
            latest = %status.latest_sha,
            "auto-update: applying a new release in safe mode"
        );
        // do_apt = false: an unattended dist-upgrade is a much bigger blast
        // radius than a Hyperion update and is not what this toggle promises.
        match self.node_update_run(false, true, true).await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(error=%e, "auto-update: could not start");
                false
            }
        }
    }

    /// Keep every WordPress site's Hyperion plugin in shape, and tell its
    /// status page what we see.
    ///
    /// Per active WordPress hosting: move pre-merge top-level files into the
    /// plugin's module directory, keep the loader current, reland the spam
    /// guard when the operator has it on but the file on disk is older than
    /// this agent's, and write `status.php` — the page in wp-admin reads its
    /// age as "is Hyperion still looking after this site?".
    ///
    /// The status is rewritten when what it says changes, and otherwise once
    /// an hour, so a node with hundreds of sites is not rewriting hundreds of
    /// files every five minutes. Returns how many sites had a plugin file
    /// written (status refreshes do not count).
    pub async fn wp_plugin_tick(&self) -> Result<i64, RpcError> {
        use hyperion_adapters::{regguard, wpmail, wpplugin};
        // hosting id → (status without its timestamp, when last written).
        static WRITTEN: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (String, i64)>>> =
            std::sync::OnceLock::new();
        let written = WRITTEN.get_or_init(Default::default);
        let now = now_secs();
        let mut acted = 0i64;
        for s in self.list().await? {
            if s.state != HostingState::Active {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            let root = detail.root_dir.trim().to_string();
            let user = detail.system_user.trim().to_string();
            if root.is_empty()
                || user.is_empty()
                || !std::path::Path::new(&root).join("wp-content").is_dir()
            {
                continue;
            }
            let id = detail.id.as_str();
            // "Report only" means Hyperion adds nothing to the site on its
            // own. A site switched to it that carries no Hyperion file yet
            // stays that way; one that already has the plugin keeps it
            // current, since a stale copy is worse than either.
            let has_any = std::path::Path::new(&root)
                .join("wp-content/mu-plugins")
                .join(wpplugin::LOADER_FILE)
                .exists()
                || std::path::Path::new(&root)
                    .join("wp-content/mu-plugins")
                    .join(wpplugin::MODULE_DIR)
                    .exists()
                || wpplugin::Module::ALL.iter().any(|m| {
                    std::path::Path::new(&root)
                        .join("wp-content/mu-plugins")
                        .join(m.legacy_file())
                        .exists()
                });
            if !has_any && !self.wp_mail_autofix_enabled(id).await {
                continue;
            }
            let mut wrote = false;
            match wpplugin::adopt_legacy(&root, &user).await {
                Ok(n) => wrote |= n > 0,
                Err(e) => {
                    tracing::warn!(domain = %detail.domain, error = %e, "wp plugin: legacy files not moved")
                }
            }
            match wpplugin::ensure_loader(&root, &user).await {
                Ok(w) => wrote |= w,
                Err(e) => {
                    tracing::warn!(domain = %detail.domain, error = %e, "wp plugin: loader not written");
                    continue;
                }
            }
            // The spam guard used to reland only when somebody toggled it,
            // so a corrected guard never reached the sites that had it on.
            let guard_on = matches!(
                hyperion_state::hosting_kv::get(&self.pool, id, "regguard_enabled").await,
                Ok(Some(v)) if v == "1"
            );
            if guard_on && !regguard::is_installed(&root).await {
                match regguard::install(&root, &user).await {
                    Ok(w) => wrote |= w,
                    Err(e) => {
                        tracing::warn!(domain = %detail.domain, error = %e, "wp plugin: spam guard not written")
                    }
                }
            }
            if wrote {
                acted += 1;
            }

            // What the status page shows.
            let mail = if wpplugin::module_contents(&root, wpplugin::Module::Mail)
                .await
                .is_some()
            {
                let (policy, _) = self.wp_mail_policy(id).await;
                // Unreadable says nothing, rather than "no failures".
                let failures_7d = match wpmail::read_failure_log(&root, 200).await {
                    wpmail::FailureLog::Read(lines) => {
                        Some(wpmail::failures_since(&lines, now - 7 * 86_400))
                    }
                    wpmail::FailureLog::Absent => Some(0),
                    wpmail::FailureLog::Unreadable => None,
                };
                Some(wpplugin::MailStatus {
                    from: self.wp_mail_from_address(id, &detail.domain).await,
                    failures_7d,
                    forced_local: policy.forces_local(),
                    pin_from: policy.pins_from(),
                })
            } else {
                None
            };
            let runs = hyperion_state::backups::list_for(&self.pool, &detail.id, 50)
                .await
                .unwrap_or_default();
            let backup = wpplugin::BackupStatus {
                last_ok_at: runs
                    .iter()
                    .find(|r| r.state == "ok")
                    .map(|r| r.finished_at.unwrap_or(r.started_at)),
                last_failed_at: runs
                    .iter()
                    .find(|r| r.state == "failed")
                    .map(|r| r.finished_at.unwrap_or(r.started_at)),
            };
            let mut status = wpplugin::SiteStatus {
                checked_at: 0,
                agent: self.current_git_sha.chars().take(12).collect(),
                node: self.current_node_id(),
                domain: detail.domain.clone(),
                mail,
                backup,
            };
            let key = serde_json::to_string(&status).unwrap_or_default();
            let due = match written.lock() {
                Ok(m) => match m.get(id) {
                    Some((k, at)) => *k != key || now - at >= 3_600,
                    None => true,
                },
                Err(_) => true,
            };
            if !due {
                continue;
            }
            status.checked_at = now;
            match wpplugin::write_status(&root, &user, &status).await {
                Ok(_) => {
                    if let Ok(mut m) = written.lock() {
                        m.insert(id.to_string(), (key, now));
                    }
                }
                Err(e) => {
                    tracing::warn!(domain = %detail.domain, error = %e, "wp plugin: status not written")
                }
            }
        }
        Ok(acted)
    }

    /// Scan a hosting's installed plugins, themes and core for available
    /// updates (keyless — wp-cli's own update status, which asks
    /// WordPress.org) and save the result for the cluster page.
    ///
    /// A scan that cannot read the install carries `feed_unavailable` and the
    /// reason rather than a misleading "all clear", and the saved record keeps
    /// the last good findings with the failure stamped beside them.
    ///
    /// Saving every scan — not only the nightly sweep's — keeps the cluster
    /// page from listing an update somebody already applied by hand from the
    /// site's WordPress tab until tomorrow night.
    pub async fn wp_vuln_scan(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpVulnScanResult, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to scan".into(),
            });
        }
        let mut findings = Vec::new();
        let mut checked = 0i64;
        let mut enumerated = false;
        let mut core_version = String::new();
        let mut errors: Vec<String> = Vec::new();
        // Plugins.
        match self
            .adapters
            .wp_plugin_list(&detail.system_user, &detail.root_dir)
            .await
        {
            Ok((plugins, v)) => {
                enumerated = true;
                core_version = v;
                for p in plugins {
                    checked += 1;
                    if p.update_available && !p.latest_version.is_empty() {
                        findings.push(crate::wp_updates::outdated_finding(
                            &p.slug,
                            &p.name,
                            "plugin",
                            &p.version,
                            &p.latest_version,
                        ));
                    }
                }
            }
            Err(e) => errors.push(format!("plugins: {e}")),
        }
        // Themes.
        match self
            .adapters
            .wp_theme_list(&detail.system_user, &detail.root_dir)
            .await
        {
            Ok((themes, v)) => {
                enumerated = true;
                if core_version.trim().is_empty() {
                    core_version = v;
                }
                for t in themes {
                    checked += 1;
                    if t.update_available && !t.latest_version.is_empty() {
                        findings.push(crate::wp_updates::outdated_finding(
                            &t.slug,
                            &t.name,
                            "theme",
                            &t.version,
                            &t.latest_version,
                        ));
                    }
                }
            }
            Err(e) => errors.push(format!("themes: {e}")),
        }
        // Core. Only asked of an install that answered at all — a site whose
        // plugin list cannot load will not answer this either. An error is
        // "core not checked", which the page must never show as current.
        let (core_checked, core_updates) = if enumerated {
            match self
                .adapters
                .wp_core_check_update(&detail.system_user, &detail.root_dir)
                .await
            {
                Ok(v) => (true, v),
                Err(_) => (false, Vec::new()),
            }
        } else {
            (false, Vec::new())
        };
        findings.sort_by_key(|f| crate::wp_updates::severity_rank(&f.severity));
        let skips = self.wp_update_skips(detail.id.as_str()).await;
        crate::wp_updates::overlay_skips(&mut findings, &skips);
        let error = if enumerated {
            String::new()
        } else {
            errors.join("; ").chars().take(300).collect()
        };
        let result = hyperion_types::WpVulnScanResult {
            findings,
            feed_unavailable: !enumerated,
            feed_age_secs: 0,
            checked,
            auto_updated: 0,
            core_version: core_version.trim().to_string(),
            core_checked,
            core_updates,
            error,
        };
        self.append_audit(
            "wp.vuln.scan",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "checked": result.checked,
                "findings": result.findings.len(),
                "enumerated": enumerated,
            })
            .to_string(),
            if result.feed_unavailable {
                "failed"
            } else {
                "ok"
            },
        )
        .await;
        self.record_vuln_scan(detail.id.as_str(), &result).await;
        Ok(result)
    }

    /// The last saved scan for a hosting, if any.
    pub(super) async fn stored_vuln_scan(&self, hosting_id: &str) -> Option<StoredVulnScan> {
        hyperion_state::hosting_kv::get(&self.pool, hosting_id, "vuln_scan")
            .await
            .ok()
            .flatten()
            .and_then(|j| serde_json::from_str::<StoredVulnScan>(&j).ok())
    }

    /// Persist a saved scan as-is. Best-effort: a write that fails leaves the
    /// previous record, which the page shows with its own (older) time.
    pub(super) async fn write_vuln_scan(&self, hosting_id: &str, stored: &StoredVulnScan) {
        if let Ok(json) = serde_json::to_string(stored) {
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                hosting_id,
                "vuln_scan",
                &json,
                now_secs(),
            )
            .await;
        }
    }

    /// Save one scan's result. A good scan replaces the record (keeping the
    /// last sweep's auto-update count, which a scan from the site's tab does
    /// not know); a failed one keeps the last good findings and stamps the
    /// failure beside them.
    pub(super) async fn record_vuln_scan(
        &self,
        hosting_id: &str,
        result: &hyperion_types::WpVulnScanResult,
    ) {
        let now = now_secs();
        let prior = self.stored_vuln_scan(hosting_id).await;
        let stored = if result.feed_unavailable {
            let mut st = prior.unwrap_or_default();
            st.failed_at = now;
            st.error = result.error.clone();
            st
        } else {
            let mut result = result.clone();
            result.auto_updated = prior.map_or(0, |p| p.result.auto_updated);
            StoredVulnScan {
                scanned_at: now,
                result,
                failed_at: 0,
                error: String::new(),
            }
        };
        self.write_vuln_scan(hosting_id, &stored).await;
    }

    /// Whether the keyless defender may auto-apply minor/patch updates for
    /// a hosting. Per-hosting toggle in `hosting_kv` (`wp_auto_update`);
    /// **default ON** (absent ⇒ enabled). "off" disables it.
    pub(super) async fn wp_auto_update_enabled(&self, hosting_id: &str) -> bool {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, "wp_auto_update").await {
            Ok(Some(v)) => v.trim() != "off",
            _ => true,
        }
    }

    /// The per-hosting auto-update pause map (commercial plugins whose update
    /// kept failing — see wp_updates::AutoUpdateSkip). Absent/garbage ⇒ empty.
    pub(super) async fn wp_update_skips(&self, hosting_id: &str) -> crate::wp_updates::SkipMap {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, "wp_update_skips").await {
            Ok(Some(s)) => crate::wp_updates::parse_skip_map(&s),
            _ => crate::wp_updates::SkipMap::new(),
        }
    }

    /// Persist the pause map. Best-effort: a write failure just means the next
    /// sweep re-learns the failure (degrades safe).
    pub(super) async fn set_wp_update_skips(
        &self,
        hosting_id: &str,
        map: &crate::wp_updates::SkipMap,
    ) {
        let json = serde_json::to_string(map).unwrap_or_else(|_| "{}".to_string());
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id,
            "wp_update_skips",
            &json,
            now_secs(),
        )
        .await;
    }

    /// Daily defender sweep over every active WordPress hosting: scan for
    /// outdated plugins/themes, AUTO-APPLY safe minor/patch (same-major)
    /// updates when the per-hosting toggle is on (default), store the
    /// result for the dashboard, and notify admins about each
    /// **newly-appeared** major update (manual action) + any auto-update
    /// failure. Returns the number of new majors seen this run.
    pub async fn wp_vuln_scan_tick(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let summaries = self.list().await?;
        let mut new_majors = 0i64;
        for s in &summaries {
            if s.state == HostingState::Active && self.hosting_runs_wordpress(s).await {
                new_majors += self.vuln_sweep_one(s, now).await;
            }
        }
        Ok(new_majors)
    }

    /// [`wp_vuln_scan_tick`](Self::wp_vuln_scan_tick) once a night, in the
    /// node's local [`WP_DEFENDER_WINDOW_START_MIN`] window. `None` = not
    /// due, `Some(new majors)` = swept.
    ///
    /// The last run is stamped in `node_kv` BEFORE the sweep, so neither a
    /// restart (every deploy restarts the agent) nor a sweep that dies half
    /// way runs it again the same night. Each run can take a full backup of
    /// every site with a pending update; it used to fire a few minutes after
    /// every agent start, which on a busy deploy day meant several of them,
    /// with the updates going in mid-afternoon.
    pub async fn wp_defender_tick(&self) -> Result<Option<i64>, RpcError> {
        self.wp_defender_tick_at(&chrono::Local, now_secs()).await
    }

    pub(super) async fn wp_defender_tick_at<Tz: chrono::TimeZone>(
        &self,
        tz: &Tz,
        now: i64,
    ) -> Result<Option<i64>, RpcError> {
        // A read that failed is not "never ran": sweeping on it could repeat
        // the night's backups, so it waits for the next tick instead.
        let last_run = match hyperion_state::node_kv::get(&self.pool, WP_DEFENDER_LAST_RUN_KV).await
        {
            Ok(v) => v.and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0),
            Err(e) => {
                tracing::warn!(error = %e, "wp defender: last run unreadable — skipping");
                return Ok(None);
            }
        };
        if !wp_defender_due(tz, last_run, now) {
            return Ok(None);
        }
        hyperion_state::node_kv::set(&self.pool, WP_DEFENDER_LAST_RUN_KV, &now.to_string(), now)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp defender: stamp last run: {e}")))?;
        self.wp_vuln_scan_tick().await.map(Some)
    }

    /// Only WordPress hostings — skip static / proxy sites.
    ///
    /// The `wordpress` row is written when HYPERION installs WordPress, so
    /// trusting it alone made the sweep blind to every site that arrived any
    /// other way: a CloudPanel/HestiaCP import, a restore, a site the
    /// customer uploaded themselves. Those have WordPress on disk and no row,
    /// so they were never scanned, never auto-updated, and never appeared on
    /// the WordPress-updates page — silently, and precisely for the sites
    /// most likely to be running something old.
    ///
    /// So ask the disk when the table has nothing. wp_status detects a real
    /// install and writes the row as it goes, which means this costs a
    /// filesystem probe once per imported site rather than on every tick.
    pub(super) async fn hosting_runs_wordpress(&self, s: &HostingSummary) -> bool {
        if wordpress::get_install(&self.pool, &s.id)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return true;
        }
        self.wp_status(HostingSelector::Id(s.id.clone()))
            .await
            .ok()
            .flatten()
            .is_some()
    }

    /// One site of the defender sweep. Returns the number of NEW major
    /// updates it reported.
    pub(super) async fn vuln_sweep_one(&self, s: &HostingSummary, now: i64) -> i64 {
        // Major-update keys from the prior stored scan (diff so a standing
        // major doesn't re-alert daily). Read BEFORE scanning: the scan saves
        // itself, so read after it every major would already look known and
        // none would ever alert.
        let prior: std::collections::HashSet<String> = self
            .stored_vuln_scan(s.id.as_str())
            .await
            .map(|st| {
                st.result
                    .findings
                    .iter()
                    .filter(|f| f.update_type == "major")
                    .map(|f| format!("{}:{}", f.slug, f.patched_version))
                    .collect()
            })
            .unwrap_or_default();
        // Couldn't enumerate: the scan has already stamped the failure beside
        // the last good findings.
        let mut scan = match self.wp_vuln_scan(HostingSelector::Id(s.id.clone())).await {
            Ok(r) if !r.feed_unavailable => r,
            _ => return 0,
        };
        let mut rescan_error: Option<String> = None;
        let mut auto_updated = 0i64;
        if self.wp_auto_update_enabled(s.id.as_str()).await {
            let batch = self.auto_update_batch(s, &scan).await;
            auto_updated = batch.updated;
            // Re-scan so the stored result reflects what's LEFT (typically
            // only major updates needing manual review). A re-scan that
            // cannot read the site keeps the pre-update findings — an empty
            // list here would read as "up to date".
            if auto_updated > 0 {
                self.purge_page_cache_after(s.id.as_str(), "wp.auto_update")
                    .await;
                match self.wp_vuln_scan(HostingSelector::Id(s.id.clone())).await {
                    Ok(r) if !r.feed_unavailable => scan = r,
                    Ok(r) => rescan_error = Some(r.error),
                    Err(e) => rescan_error = Some(e.to_string()),
                }
            }
            // Release the pre-update backup only when the whole batch went
            // in cleanly: it stays 24 hours from now, when the updates are
            // done, then goes. Anything else keeps it held — it is the last
            // copy from before whatever went wrong — until the next
            // pre-update backup of the site replaces it.
            if let Some(run_id) = batch.pre_update_run {
                let clean = !batch.failed && rescan_error.is_none();
                let delete_at = now_secs() + hyperion_state::backups::PRE_UPDATE_KEEP_SECS;
                if clean {
                    if let Err(e) =
                        hyperion_state::backups::release_pre_update(&self.pool, run_id, delete_at)
                            .await
                    {
                        tracing::warn!(error = %e, "pre-update backup: release failed");
                    }
                }
                self.append_audit(
                    "hosting.backup.pre_update",
                    Some(s.id.as_str()),
                    &serde_json::json!({
                        "run_id": run_id,
                        "updated": auto_updated,
                        "held": !clean,
                        "delete_at": if clean { delete_at } else { 0 },
                    })
                    .to_string(),
                    "ok",
                )
                .await;
            }
        }
        scan.auto_updated = auto_updated;
        let new_majors = self.notify_new_majors(s, &scan, &prior).await;

        let (failed_at, error) = match rescan_error {
            Some(e) => (now_secs(), e),
            None => (0, String::new()),
        };
        self.write_vuln_scan(
            s.id.as_str(),
            &StoredVulnScan {
                scanned_at: now,
                result: scan,
                failed_at,
                error,
            },
        )
        .await;
        new_majors
    }

    /// Auto-apply minor/patch (same-major) plugin, theme and core updates,
    /// behind ONE full backup (files + database) taken before the batch —
    /// what a care plan promises ("backed up before every update"), and the
    /// same kind of copy every other backup is, restorable from the same
    /// screen. Not one per plugin: the question afterwards is "what did
    /// tonight's updates change".
    ///
    /// No backup, no updates: an update that breaks the site with nothing to
    /// go back to is exactly what the promise rules out. The site waits for
    /// the next sweep and the operator hears why.
    pub(super) async fn auto_update_batch(
        &self,
        s: &HostingSummary,
        scan: &hyperion_types::WpVulnScanResult,
    ) -> AutoUpdateBatch {
        let now = now_secs();
        let mut batch = AutoUpdateBatch::default();
        let mut skips = self.wp_update_skips(s.id.as_str()).await;
        // Skip plugins we've already PAUSED (commercial / license-gated
        // updates that keep failing) — no pointless retry, no re-alert.
        let targets: Vec<(String, String)> = scan
            .findings
            .iter()
            .filter(|f| f.auto_updatable)
            .filter(|f| !crate::wp_updates::is_paused(&skips, &f.slug, now))
            .map(|f| (f.kind.clone(), f.slug.clone()))
            .collect();
        // The minor core release this batch would apply, decided up front so
        // the backup covers core as well.
        let core_release = scan.core_updates.iter().find(|u| u.is_minor()).cloned();
        if targets.is_empty() && core_release.is_none() {
            return batch;
        }
        match self.pre_update_backup(&s.id).await {
            Ok(id) => batch.pre_update_run = Some(id),
            Err(e) => {
                tracing::warn!(domain = %s.domain, error = %e,
                    "wp auto-update: pre-update backup failed — updates skipped");
                self.notify_admins_say(
                    "warn",
                    "ops.preupdate_backup_failed",
                    &[("domain", &s.domain), ("error", &e)],
                    &format!("/hostings/{}#backups", s.domain),
                    &format!("wp.update.backup_failed:{}", s.domain),
                )
                .await;
                return batch;
            }
        }
        let mut skips_dirty = false;
        for (kind, slug) in targets {
            match self.apply_wp_item_update(s, &kind, &slug).await {
                Ok(()) => {
                    batch.updated += 1;
                    // Recovered (e.g. license added) — lift any pause.
                    if skips.remove(&slug).is_some() {
                        skips_dirty = true;
                    }
                }
                Err(err_msg) => {
                    batch.failed = true;
                    tracing::warn!(domain = %s.domain, %kind, %slug, "wp auto-update failed: {err_msg}");
                    // Themes can't be commercial-licensed the same way;
                    // only pause plugins (themes just log + retry).
                    if kind != "theme" {
                        let newly_paused =
                            crate::wp_updates::record_failure(&mut skips, &slug, now, &err_msg);
                        skips_dirty = true;
                        if newly_paused {
                            self.notify_admins_say(
                                "warn",
                                "ops.update_paused",
                                &[("domain", &s.domain), ("slug", &slug)],
                                &format!("/hostings/{}#wordpress", s.domain),
                                &format!("wp.update.paused:{}:{slug}", s.domain),
                            )
                            .await;
                        }
                    }
                }
            }
        }
        if skips_dirty {
            self.set_wp_update_skips(s.id.as_str(), &skips).await;
        }
        if let Some(rel) = core_release {
            match self.apply_core_minor_update(s, &rel).await {
                Some(true) => batch.updated += 1,
                Some(false) => batch.failed = true,
                None => {}
            }
        }
        batch
    }

    /// `wp plugin|theme update <slug>`; `Err` is what to record about it.
    pub(super) async fn apply_wp_item_update(
        &self,
        s: &HostingSummary,
        kind: &str,
        slug: &str,
    ) -> Result<(), String> {
        let sel = HostingSelector::Id(s.id.clone());
        let state = if kind == "theme" {
            self.wp_theme_action(sel, slug.to_string(), hyperion_types::WpThemeAction::Update)
                .await
                .map(|r| r.state)
        } else {
            self.wp_plugin_action(
                sel,
                slug.to_string(),
                hyperion_types::WpPluginAction::Update,
            )
            .await
            .map(|r| r.state)
        };
        match state {
            Ok(st) if st != "failed" => Ok(()),
            Ok(_) => Err(format!("wp update {kind} {slug} reported failed")),
            Err(e) => Err(e.to_string()),
        }
    }

    /// WordPress core, the third of "keep it updated" that carries the
    /// security releases every published exploit is written against.
    /// `--minor` is the ceiling: a 6.5.3 → 6.5.5 hop is what WordPress
    /// itself installs unattended, while a major is where themes break and
    /// stays a decision a person makes while they are around to look at it.
    /// The batch's backup already covers this.
    ///
    /// `Some(true)` applied, `Some(false)` failed, `None` not attempted (the
    /// hosting could not be read).
    pub(super) async fn apply_core_minor_update(
        &self,
        s: &HostingSummary,
        rel: &hyperion_types::WpCoreUpdate,
    ) -> Option<bool> {
        let detail = self.get(HostingSelector::Id(s.id.clone())).await.ok()?;
        let user = detail.system_user.trim().to_string();
        let root = detail.root_dir.trim().to_string();
        if user.is_empty() || root.is_empty() {
            return None;
        }
        match hyperion_adapters::wpcli::core_update_minor(&user, &root).await {
            Ok(out) => {
                tracing::info!(
                    domain = %detail.domain,
                    version = %rel.version,
                    "wp core: minor update applied"
                );
                let tail: String = {
                    let rev: String = out.chars().rev().take(400).collect();
                    rev.chars().rev().collect()
                };
                self.append_audit(
                    "wp.core.auto_update",
                    Some(detail.id.as_str()),
                    &serde_json::json!({ "version": rel.version, "output_tail": tail }).to_string(),
                    "ok",
                )
                .await;
                Some(true)
            }
            Err(e) => {
                // Worth telling somebody: unlike a commercial plugin needing a
                // licence, a core update that will not apply leaves a
                // known-vulnerable core serving the site.
                tracing::warn!(domain = %detail.domain, error = %e,
                    "wp core: minor update failed");
                self.notify_admins_say(
                    "warn",
                    "ops.core_failed",
                    &[
                        ("domain", &detail.domain),
                        ("version", &rel.version),
                        ("error", &e.to_string()),
                    ],
                    &format!("/hostings/{}#wordpress", detail.domain),
                    &format!("wp.core.failed:{}", detail.domain),
                )
                .await;
                Some(false)
            }
        }
    }

    /// Update WordPress core to `version` because a person asked to — the
    /// release a major the sweep leaves alone, or a minor applied now rather
    /// than tonight.
    ///
    /// Only a release wp-cli offers this site RIGHT NOW is accepted: the
    /// form's version is a request, not an instruction, so a stale page or a
    /// hand-made POST cannot walk a site onto a release it was not offered,
    /// or back onto an older one.
    ///
    /// Same promise as the sweep: one pre-update backup first, no backup no
    /// update, released 24 hours after a clean update and held after a
    /// failed one.
    pub async fn wp_core_update(
        &self,
        sel: HostingSelector,
        version: String,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to update WordPress".into(),
            });
        }
        let (user, root) = (
            detail.system_user.trim().to_string(),
            detail.root_dir.trim().to_string(),
        );
        if user.is_empty() || root.is_empty() {
            return Err(RpcError::Validation {
                message: "this hosting has no system user or document root".into(),
            });
        }
        let version = version.trim().to_string();
        if !hyperion_adapters::wpcli::is_core_release(&version) {
            return Err(RpcError::Validation {
                message: format!("not a WordPress release number: {version:?}"),
            });
        }
        let offered = self
            .adapters
            .wp_core_check_update(&user, &root)
            .await
            .map_err(|e| RpcError::Validation {
                message: format!(
                    "could not ask WordPress which releases this site is offered, so \
                     nothing was updated: {e}"
                ),
            })?;
        if !offered.iter().any(|u| u.version == version) {
            let list: Vec<&str> = offered.iter().map(|u| u.version.as_str()).collect();
            return Err(RpcError::Validation {
                message: if list.is_empty() {
                    format!(
                        "WordPress {version} is not offered to this site — it is already \
                         up to date. Nothing was changed."
                    )
                } else {
                    format!(
                        "WordPress {version} is not offered to this site (offered: {}). \
                         Nothing was changed.",
                        list.join(", ")
                    )
                },
            });
        }
        let from = detect_wp_install_on_disk(&root).await.unwrap_or_default();

        let run_id =
            self.pre_update_backup(&detail.id)
                .await
                .map_err(|e| RpcError::Validation {
                    message: format!(
                        "the backup before the update failed, so WordPress was NOT updated: {e}"
                    ),
                })?;

        match hyperion_adapters::wpcli::core_update_to(&user, &root, &version).await {
            Ok(out) => {
                let delete_at = now_secs() + hyperion_state::backups::PRE_UPDATE_KEEP_SECS;
                if let Err(e) =
                    hyperion_state::backups::release_pre_update(&self.pool, run_id, delete_at).await
                {
                    tracing::warn!(error = %e, "pre-update backup: release failed");
                }
                let tail: String = {
                    let rev: String = out.chars().rev().take(400).collect();
                    rev.chars().rev().collect()
                };
                self.append_audit(
                    "wp.core.update",
                    Some(detail.id.as_str()),
                    &serde_json::json!({
                        "from": from,
                        "version": version,
                        "run_id": run_id,
                        "output_tail": tail,
                    })
                    .to_string(),
                    "ok",
                )
                .await;
                self.purge_page_cache_after(detail.id.as_str(), "wp.core.update")
                    .await;
                // The hostings list reads the recorded version.
                let _ = self.refresh_wp_version(&detail.id, &root, "").await;
                // Saves itself: the cluster page and the Updates row stop
                // listing the release that just went in.
                let _ = self
                    .wp_vuln_scan(HostingSelector::Id(detail.id.clone()))
                    .await;
                Ok(format!(
                    "WordPress updated{} to {version}. The backup taken before it is kept \
                     for 24 hours.",
                    if from.is_empty() {
                        String::new()
                    } else {
                        format!(" from {from}")
                    }
                ))
            }
            Err(e) => {
                // The backup stays held — it is the copy from before whatever
                // the half-applied update left behind.
                self.append_audit(
                    "wp.core.update",
                    Some(detail.id.as_str()),
                    &serde_json::json!({
                        "from": from,
                        "version": version,
                        "run_id": run_id,
                        "error": e.to_string(),
                    })
                    .to_string(),
                    "failed",
                )
                .await;
                Err(RpcError::Validation {
                    message: format!(
                        "WordPress {version} did not install: {e}\n\nThe backup taken just \
                         before it is kept (Backups tab, \"before update\") until the next \
                         update replaces it."
                    ),
                })
            }
        }
    }

    /// Notify about each major update that was not in the previous scan.
    pub(super) async fn notify_new_majors(
        &self,
        s: &HostingSummary,
        scan: &hyperion_types::WpVulnScanResult,
        prior: &std::collections::HashSet<String>,
    ) -> i64 {
        let mut n = 0;
        for f in scan.findings.iter().filter(|f| f.update_type == "major") {
            let key = format!("{}:{}", f.slug, f.patched_version);
            if prior.contains(&key) {
                continue;
            }
            n += 1;
            self.notify_admins_say(
                "warn",
                "ops.major_update",
                &[
                    ("domain", &s.domain),
                    ("kind", &f.kind),
                    ("name", &f.name),
                    ("from", &f.installed_version),
                    ("to", &f.patched_version),
                ],
                &format!("/hostings/{}#wordpress", s.domain),
                &format!("wp.update.major:{}:{}", s.domain, key),
            )
            .await;
        }
        n
    }

    /// Every WordPress hosting on this node with its last saved update scan,
    /// for the cluster WordPress-updates page.
    ///
    /// Up-to-date sites stay in: dropping them made "up to date" and "never
    /// scanned" look identical — both simply absent. Installs the sweep has
    /// not reached yet are listed too, with `scanned_at` 0, for the same
    /// reason.
    ///
    /// The auto-update switch and the pause map are read NOW, not taken from
    /// the saved scan, so a flipped switch or a Resume shows at once.
    pub async fn vuln_findings_list(
        &self,
    ) -> Result<Vec<hyperion_types::HostingVulnSummary>, RpcError> {
        let pairs = hyperion_state::hosting_kv::list_by_key(&self.pool, "vuln_scan")
            .await
            .map_err(|e| RpcError::Internal_with(format!("vuln list: {e}")))?;
        let kv_map = |key: &'static str| async move {
            hyperion_state::hosting_kv::list_by_key(&self.pool, key)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect::<std::collections::HashMap<String, String>>()
        };
        let switches = kv_map("wp_auto_update").await;
        let skips = kv_map("wp_update_skips").await;
        let installs = wordpress::list_install_ids(&self.pool)
            .await
            .unwrap_or_default();
        let summaries = self.list().await.unwrap_or_default();

        let mut stored: Vec<(String, StoredVulnScan)> = Vec::new();
        for (hid, json) in pairs {
            if let Ok(st) = serde_json::from_str::<StoredVulnScan>(&json) {
                stored.push((hid, st));
            }
        }
        // Installs with no saved scan yet. Active ones only: the sweep skips
        // a suspended site, so "not checked yet" would never clear for it.
        for hid in installs {
            if stored.iter().any(|(h, _)| *h == hid) {
                continue;
            }
            let active = summaries
                .iter()
                .any(|s| s.id.as_str() == hid && s.state == HostingState::Active);
            if active {
                stored.push((hid, StoredVulnScan::default()));
            }
        }

        let mut out = Vec::new();
        for (hid, st) in stored {
            // A hosting that does not resolve is TRASHED or gone — `list()`
            // is `WHERE state != 'trashed'` — and its stored scan outlives it
            // in `hosting_kv` so that un-trashing restores the history.
            //
            // It must not become a row: a nameless line with a node, a count
            // and a timestamp but no site is nothing an operator can click or
            // act on, and a trashed site is deliberately not running anyway.
            let Some(domain) = summaries
                .iter()
                .find(|s| s.id.as_str() == hid)
                .map(|s| s.domain.clone())
            else {
                continue;
            };
            let auto_update = switches.get(&hid).map_or(true, |v| v.trim() != "off");
            let skip_map = skips
                .get(&hid)
                .map(|j| crate::wp_updates::parse_skip_map(j))
                .unwrap_or_default();
            let mut findings = st.result.findings;
            crate::wp_updates::overlay_skips(&mut findings, &skip_map);
            out.push(hyperion_types::HostingVulnSummary {
                hosting_id: hid,
                domain,
                node_id: String::new(),
                scanned_at: st.scanned_at,
                findings,
                auto_update: Some(auto_update),
                auto_updated: st.result.auto_updated,
                checked: st.result.checked,
                core_version: st.result.core_version,
                core_checked: st.result.core_checked,
                core_updates: st.result.core_updates,
                failed_at: st.failed_at,
                error: st.error,
            });
        }
        // Most major updates first; the page re-sorts by what each needs.
        out.sort_by(|a, b| {
            b.count_severity("high")
                .cmp(&a.count_severity("high"))
                .then(b.findings.len().cmp(&a.findings.len()))
        });
        Ok(out)
    }
}

/// What we persist per hosting under the `vuln_scan` KV key: the last
/// scan result plus when it ran (the KV layer's own updated_at isn't
/// read back by `list_by_key`, so the timestamp rides inside the value).
///
/// `failed_at`/`error` stamp the latest attempt that could not read the site;
/// the findings beside them are then from the last good scan (or empty, with
/// `scanned_at` 0, when there never was one).
#[derive(serde::Serialize, serde::Deserialize, Default)]
pub(super) struct StoredVulnScan {
    pub(super) scanned_at: i64,
    pub(super) result: hyperion_types::WpVulnScanResult,
    #[serde(default)]
    pub(super) failed_at: i64,
    #[serde(default)]
    pub(super) error: String,
}

/// Whether a PRE-UPDATE backup is to be deleted now. A site keeps ONE: any
/// run older than its newest successful pre-update backup goes, held or not
/// (`superseded`). The newest one stays while held — its batch did not go in
/// cleanly, or is still going — and once released goes at its `delete_at`,
/// 24 hours after the updates. A failed run (nothing in it to roll back to)
/// stays listed for 24 hours. Always false for an ordinary backup, which the
/// archive rule decides about.
pub(crate) fn pre_update_due_for_prune(
    r: &hyperion_state::backups::BackupRun,
    superseded: bool,
    now: i64,
) -> bool {
    if !r.is_pre_update() || r.state == "running" {
        return false;
    }
    if superseded {
        return true;
    }
    r.pre_update_delete_at().is_some_and(|t| t <= now)
}

/// What one auto-update batch did.
#[derive(Default)]
pub(super) struct AutoUpdateBatch {
    /// Plugins, themes and core updates that went in.
    updated: i64,
    /// Any of them failed.
    failed: bool,
    /// The backup taken before the batch, held until it went in cleanly.
    pre_update_run: Option<i64>,
}

/// `node_kv` key: unix seconds the nightly defender sweep last started.
pub(super) const WP_DEFENDER_LAST_RUN_KV: &str = "wp_defender_last_run_at";

/// The defender sweep's window opens at this many minutes past local
/// midnight (02:00 server time) and stays open for
/// [`WP_DEFENDER_WINDOW_SECS`]. At night because the sweep applies updates
/// and backs up every site it touches; four hours so a node that boots or
/// deploys inside the window still gets its night.
pub(super) const WP_DEFENDER_WINDOW_START_MIN: u32 = 2 * 60;
pub(super) const WP_DEFENDER_WINDOW_SECS: i64 = 4 * 3600;

/// Whether the defender sweep should start at `now`: inside tonight's
/// window, and not already started since it opened. A node that is down
/// for the whole window skips that night rather than updating during the
/// day.
pub(super) fn wp_defender_due<Tz: chrono::TimeZone>(tz: &Tz, last_run: i64, now: i64) -> bool {
    let Some(opens) = local_slot(tz, now, 0, WP_DEFENDER_WINDOW_START_MIN) else {
        return false;
    };
    now >= opens && now < opens + WP_DEFENDER_WINDOW_SECS && last_run < opens
}
