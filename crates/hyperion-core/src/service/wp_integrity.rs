//! WordPress file integrity and malware scanning.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ==================================================================
    //  File integrity + malware — the "has anything been TAMPERED WITH?"
    //  half of the defender, sibling to the outdated-component scan
    //  above. Same shapes, same KV storage idiom, and the same honesty
    //  rule: a signal that could not run is reported as "couldn't check",
    //  never as "clean".
    // ==================================================================

    /// Does this hosting actually carry a WordPress install?
    ///
    /// The `wp_installs` row is the cheap answer, but it only exists for
    /// installs Hyperion performed itself — a site imported from
    /// CloudPanel/HestiaCP or restored from a foreign backup has
    /// WordPress on disk and no row. The on-disk fallback is what makes
    /// the care package cover those sites too.
    pub(super) async fn hosting_has_wordpress(&self, detail: &HostingDetail) -> bool {
        if wordpress::get_install(&self.pool, &detail.id)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return true;
        }
        detect_wp_install_on_disk(&detail.root_dir).await.is_some()
    }

    /// The last stored integrity scan for a hosting. `None` when never
    /// scanned — or when the stored JSON no longer parses, which we treat
    /// as "never scanned" so a future shape change can't wedge the
    /// feature on a live node.
    pub(super) async fn stored_integrity_scan(
        &self,
        hosting_id: &str,
    ) -> Option<StoredIntegrityScan> {
        let json = hyperion_state::hosting_kv::get(&self.pool, hosting_id, INTEGRITY_KV_KEY)
            .await
            .ok()
            .flatten()?;
        serde_json::from_str(&json).ok()
    }

    /// Whether the daily integrity sweep may look at this hosting.
    /// Per-hosting toggle in `hosting_kv` (`integrity_scan_enabled`);
    /// **default ON** (absent ⇒ enabled). "off" opts the site out.
    pub(super) async fn integrity_scan_enabled(&self, hosting_id: &str) -> bool {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, INTEGRITY_ENABLED_KV_KEY)
            .await
        {
            Ok(Some(v)) => v.trim() != "off",
            _ => true,
        }
    }

    /// Persist the latest integrity scan. Best-effort: a write failure
    /// costs a dashboard row and an extra ClamAV pass tomorrow, never the
    /// scan itself.
    pub(super) async fn set_stored_integrity_scan(
        &self,
        hosting_id: &str,
        stored: &StoredIntegrityScan,
    ) {
        let Ok(json) = serde_json::to_string(stored) else {
            return;
        };
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id,
            INTEGRITY_KV_KEY,
            &json,
            now_secs(),
        )
        .await;
    }

    /// Verify a hosting's WordPress against the checksums WordPress.org
    /// publishes for the exact installed versions, then — when a scanner
    /// exists on the node — sweep its docroot with ClamAV. Mirrors
    /// `wp_vuln_scan`: best-effort, and a probe that couldn't run comes
    /// back as "couldn't check" rather than a silent pass.
    ///
    /// The result is stored under the `integrity_scan` KV key so the
    /// dashboard, the daily ClamAV cadence and the next sweep's
    /// new-findings diff all read the same record.
    pub async fn wp_integrity_scan(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpIntegrityScanResult, RpcError> {
        let detail = self.get(sel).await?;
        if detail.state != HostingState::Active {
            return Err(RpcError::Conflict {
                message: "hosting must be active to scan".into(),
            });
        }
        let now = now_secs();
        // Static sites and reverse proxies have no core to compare
        // against. Say so, rather than running wp-cli against a docroot
        // with no WordPress in it and rendering its failure as a finding.
        // Not stored: a non-WP hosting has no place on the integrity
        // dashboard.
        if !self.hosting_has_wordpress(&detail).await {
            return Ok(hyperion_types::WpIntegrityScanResult {
                error: Some(INTEGRITY_ERR_NOT_WORDPRESS.to_string()),
                scanned_at: now,
                ..Default::default()
            });
        }

        // Probe failures are collected, not returned: one dead signal must
        // not hide what the other two found.
        let mut errors: Vec<String> = Vec::new();
        // Read once: the ClamAV cadence needs the previous pass's age, and
        // the store decision below needs to know whether this hosting has
        // ever produced a record at all.
        let prior = self.stored_integrity_scan(detail.id.as_str()).await;

        // 1. Core, against the hashes published for the installed version.
        let core = match integrity::verify_core(&detail.system_user, &detail.root_dir).await {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("core verification failed: {e}"));
                integrity::CoreChecksums::default()
            }
        };

        // 2. Plugins. wp-cli's batch summary wording is too version-fragile
        //    to parse counts out of, so the denominator comes from the
        //    plugin list we can already enumerate.
        let plugins = match integrity::verify_plugins(&detail.system_user, &detail.root_dir).await {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("plugin verification failed: {e}"));
                integrity::PluginChecksums::default()
            }
        };
        let (plugins_total, plugins_listed) = match self
            .adapters
            .wp_plugin_list(&detail.system_user, &detail.root_dir)
            .await
        {
            Ok((list, _v)) => (list.len() as i64, true),
            Err(e) => {
                errors.push(format!("plugin list failed: {e}"));
                (0, false)
            }
        };

        // 3. ClamAV over the docroot — the only signal that looks inside
        //    `wp-content/uploads`, which core verification skips by design.
        let (clamav_available, malware, clamav_at) = integrity_malware_pass(
            &detail,
            now,
            self.malware_scan_niceness(),
            prior.as_ref(),
            &mut errors,
        )
        .await;

        let mut result = assemble_integrity_result(
            core,
            plugins,
            malware,
            clamav_available,
            plugins_total,
            plugins_listed,
        );
        result.scanned_at = now;
        result.error = (!errors.is_empty()).then(|| errors.join("; "));

        // Store when at least one signal actually ran — or when this
        // hosting has no record at all, so a site nobody has EVER been
        // able to check still reaches the dashboard saying exactly that.
        // What we refuse to do is let a failed run overwrite yesterday's
        // real findings with an empty list.
        if result.wp_cli_ok || clamav_available || prior.is_none() {
            self.set_stored_integrity_scan(
                detail.id.as_str(),
                &StoredIntegrityScan {
                    scanned_at: now,
                    clamav_at,
                    result: result.clone(),
                },
            )
            .await;
        }

        self.append_audit(
            "wp.integrity.scan",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "core_issues": result.core_issue_count(),
                "plugin_issues": result.plugin_issue_count(),
                "malware": result.malware.len(),
                "wp_cli_ok": result.wp_cli_ok,
                "clamav": result.clamav_available,
            })
            .to_string(),
            if result.wp_cli_ok { "ok" } else { "failed" },
        )
        .await;
        Ok(result)
    }

    /// Daily integrity sweep over every active WordPress hosting on this
    /// node: verify core + plugin checksums, run ClamAV where it exists,
    /// store each result for the dashboard, and notify admins about
    /// **newly-appeared** findings — a standing one must not re-alert
    /// every night or the operator learns to ignore the panel.
    /// Returns the number of hostings that gained a new finding.
    ///
    /// Sequential on purpose (see `integrity_malware_pass`): one docroot
    /// walk at a time is the difference between a security feature and an
    /// IO outage.
    pub async fn wp_integrity_scan_tick(&self) -> Result<i64, RpcError> {
        let summaries = self.list().await?;
        let mut newly_flagged = 0i64;
        for s in &summaries {
            if s.state != HostingState::Active {
                continue;
            }
            // Per-site opt-out (default on). This is the switch the
            // `integrity_scan` package feature forces, so a customer who
            // pays for scanning keeps getting scanned even after someone
            // turns it off on the site.
            if !self.integrity_scan_enabled(s.id.as_str()).await {
                continue;
            }
            // Read the prior record BEFORE scanning — `wp_integrity_scan`
            // overwrites it, and the alert diff needs yesterday's keys.
            let prior_keys = self
                .stored_integrity_scan(s.id.as_str())
                .await
                .map(|p| integrity_finding_keys(&p.result))
                .unwrap_or_default();
            let scan = match self
                .wp_integrity_scan(HostingSelector::Id(s.id.clone()))
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(domain = %s.domain, error = %e, "integrity scan failed");
                    continue;
                }
            };
            // Static / proxy sites: nothing to verify, nothing to alert on.
            if scan.error.as_deref() == Some(INTEGRITY_ERR_NOT_WORDPRESS) {
                continue;
            }
            let new_keys = integrity_finding_keys(&scan)
                .difference(&prior_keys)
                .count();
            if new_keys == 0 {
                continue;
            }
            newly_flagged += 1;
            // A modified core file, a tampered plugin or a signature hit is
            // a suspected compromise. A merely *missing* core file is
            // usually a botched update — still worth saying, not worth
            // waking someone up for.
            let compromised = !scan.malware.is_empty()
                || !scan.core_modified.is_empty()
                || !scan.core_unexpected.is_empty()
                || !scan.plugins_failed.is_empty();
            self.notify_admins_say(
                if compromised { "error" } else { "warn" },
                "ops.integrity",
                &[
                    ("domain", &s.domain),
                    ("core", &scan.core_issue_count().to_string()),
                    ("plugins", &scan.plugin_issue_count().to_string()),
                    ("malware", &scan.malware.len().to_string()),
                    ("new", &new_keys.to_string()),
                ],
                &format!("/hostings/{}#wordpress", s.domain),
                &format!("wp.integrity:{}", s.domain),
            )
            .await;
        }
        Ok(newly_flagged)
    }

    /// Read every hosting's last stored integrity scan (this node only)
    /// for the cluster-wide dashboard. Mirrors `vuln_findings_list`, but
    /// deliberately returns CLEAN and COULDN'T-CHECK rows too: "we have
    /// not been able to look at this site" is exactly what the operator
    /// selling the care package needs to see, and a page that only ever
    /// lists problems can't distinguish it from "all good".
    pub async fn integrity_findings_list(
        &self,
    ) -> Result<Vec<hyperion_types::HostingIntegritySummary>, RpcError> {
        let pairs = hyperion_state::hosting_kv::list_by_key(&self.pool, INTEGRITY_KV_KEY)
            .await
            .map_err(|e| RpcError::Internal_with(format!("integrity list: {e}")))?;
        let summaries = self.list().await.unwrap_or_default();
        let mut out = Vec::new();
        for (hid, json) in pairs {
            let Ok(st) = serde_json::from_str::<StoredIntegrityScan>(&json) else {
                continue;
            };
            // Same as `vuln_findings_list`: a hosting that does not resolve is
            // trashed or gone, and a nameless row is not information.
            let Some(domain) = summaries
                .iter()
                .find(|s| s.id.as_str() == hid)
                .map(|s| s.domain.clone())
            else {
                continue;
            };
            out.push(hyperion_types::HostingIntegritySummary {
                hosting_id: hid,
                domain,
                node_id: String::new(),
                scanned_at: st.scanned_at,
                result: st.result,
            });
        }
        // Worst first: most findings, then anything not provably clean
        // (couldn't-check outranks clean), then alphabetical for stability.
        out.sort_by(|a, b| {
            b.result
                .total_findings()
                .cmp(&a.result.total_findings())
                .then(a.result.is_clean().cmp(&b.result.is_clean()))
                .then(a.domain.cmp(&b.domain))
        });
        Ok(out)
    }
}

/// `hosting_kv` key holding the last integrity scan, sibling to
/// `vuln_scan`.
pub(super) const INTEGRITY_KV_KEY: &str = "integrity_scan";

/// `hosting_kv` key gating the daily integrity sweep for ONE hosting —
/// the per-site switch a care package sells (and enforces).
///
/// **Default ON** (absent ⇒ enabled), exactly like `wp_auto_update`: an
/// installation that never touches packages must keep scanning every site
/// it scans today. Only an explicit "off" opts a site out.
pub(super) const INTEGRITY_ENABLED_KV_KEY: &str = "integrity_scan_enabled";

/// Marker put in `WpIntegrityScanResult::error` for a hosting that has no
/// WordPress at all. A sentinel rather than free text because the sweep
/// branches on it — a static site is *skipped*, not *reported*.
pub(super) const INTEGRITY_ERR_NOT_WORDPRESS: &str = "hosting has no WordPress installation";

/// Minimum gap between two ClamAV passes over the same docroot. Twenty
/// hours rather than a flat day so ordinary jitter in the daily sweep
/// can't push a site's scan past the cutoff and silently halve its
/// cadence to every other night.
pub(super) const CLAMAV_MIN_INTERVAL_SECS: i64 = 20 * 3600;

/// Node-wide gate: at most one `clamscan` at a time on this machine.
/// It reads an entire docroot, so two concurrent passes turn a shared
/// host's IO into a queue for every site on it. Callers `try_lock` and
/// carry their previous verdict forward rather than waiting — see
/// `integrity_malware_pass`.
pub(super) static CLAMAV_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What we persist per hosting under the `integrity_scan` KV key: the
/// last result, when it ran, and — separately — when the ClamAV half of
/// it last actually walked the disk. Both timestamps ride inside the
/// value because the KV layer's own `updated_at` isn't read back by
/// `list_by_key`, and because checksum verification runs far more often
/// than the malware pass.
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct StoredIntegrityScan {
    pub(super) scanned_at: i64,
    /// Unix seconds of the last real ClamAV pass; 0 = never ran. Drives
    /// the daily cadence, so a carried-forward hit list keeps its
    /// original age instead of looking freshly confirmed.
    #[serde(default)]
    pub(super) clamav_at: i64,
    pub(super) result: hyperion_types::WpIntegrityScanResult,
}

/// The ClamAV half of an integrity scan, with the two guards that keep a
/// signature sweep from hurting the node it protects:
///
///   * **one `clamscan` per node at a time.** It reads an entire docroot,
///     so two at once turn a shared host's IO into a queue for every site
///     on it. A scan that finds the gate busy carries the previous
///     verdict forward instead of waiting — a panel "Scan now" must not
///     block behind a night-long sweep.
///   * **one pass per site per day.** Checksum verification is cheap and
///     stays fresh on every call; re-walking a 20 GB docroot because
///     someone reloaded a page is not.
///
/// Returns `(available, hits, produced_at)`, where `produced_at` is when
/// those hits were actually observed (0 = never).
pub(super) async fn integrity_malware_pass(
    detail: &HostingDetail,
    now: i64,
    scan_niceness: i32,
    prior: Option<&StoredIntegrityScan>,
    errors: &mut Vec<String>,
) -> (bool, Vec<hyperion_types::WpMalwareHit>, i64) {
    // No scanner installed. A normal state on a shared host — never an
    // error, and explicitly NOT a clean bill of health (the caller renders
    // `clamav_available = false` as "not scanned").
    if !integrity::clamav_available() {
        return (false, Vec::new(), 0);
    }
    let carry = || match prior {
        Some(p) => (
            p.result.clamav_available,
            p.result.malware.clone(),
            p.clamav_at,
        ),
        None => (false, Vec::new(), 0),
    };
    if let Some(p) = prior {
        if p.clamav_at > 0 && now.saturating_sub(p.clamav_at) < CLAMAV_MIN_INTERVAL_SECS {
            return carry();
        }
    }
    let Ok(_gate) = CLAMAV_GATE.try_lock() else {
        errors.push("malware scan skipped: another scan is already running on this node".into());
        return carry();
    };
    match integrity::scan_malware_niced(&detail.root_dir, scan_niceness).await {
        Ok(scan) => (
            scan.available,
            scan.hits,
            if scan.available { now } else { 0 },
        ),
        // clamscan exited ≥ 2: part of the tree could not be read, so this
        // pass proves nothing. "Couldn't check" — we never build a pass on
        // top of a partial walk.
        Err(e) => {
            errors.push(format!("malware scan failed: {e}"));
            (false, Vec::new(), 0)
        }
    }
}

/// Fold the three probe outcomes into the wire result.
///
/// Pure on purpose: this is where "we could not check" becomes what the
/// panel renders, and getting it wrong means telling a paying customer
/// their site is clean when nothing ever looked at it. `scanned_at` and
/// `error` are the caller's to fill.
pub(super) fn assemble_integrity_result(
    core: integrity::CoreChecksums,
    plugins: integrity::PluginChecksums,
    malware: Vec<hyperion_types::WpMalwareHit>,
    clamav_available: bool,
    plugins_total: i64,
    plugins_listed: bool,
) -> hyperion_types::WpIntegrityScanResult {
    let core_checked = core.checked;
    let core_ok = core.is_clean();
    // A site with no plugins at all gives wp-cli nothing to verify, so its
    // silence is not a failure — but only when we KNOW the list is empty.
    // A failed enumeration also reports zero, and that must never be
    // laundered into "verified".
    let plugins_ok = plugins.checked || (plugins_listed && plugins_total == 0);
    let plugins_unknown = plugins.unknown;
    // Denominator: everything installed, minus what WordPress.org
    // publishes no hashes for (every premium plugin).
    let plugins_checked = (plugins_total - plugins_unknown.len() as i64).max(0);
    hyperion_types::WpIntegrityScanResult {
        core_ok,
        core_modified: core.modified,
        core_unexpected: core.unexpected,
        core_missing: core.missing,
        plugins_failed: plugins.failed,
        plugins_unknown,
        malware,
        clamav_available,
        wp_cli_ok: core_checked && plugins_ok,
        plugins_checked,
        plugins_total,
        error: None,
        scanned_at: 0,
    }
}

/// Stable identity for every finding in a scan, so the sweep can alert on
/// what is NEW instead of re-sending the same list nightly. The prefixes
/// keep the three core buckets apart: the same path moving from "missing"
/// to "modified" is a different event, not the same one.
pub(super) fn integrity_finding_keys(
    r: &hyperion_types::WpIntegrityScanResult,
) -> std::collections::HashSet<String> {
    let mut keys = std::collections::HashSet::new();
    for p in &r.core_modified {
        keys.insert(format!("core:mod:{p}"));
    }
    for p in &r.core_unexpected {
        keys.insert(format!("core:new:{p}"));
    }
    for p in &r.core_missing {
        keys.insert(format!("core:gone:{p}"));
    }
    for plugin in &r.plugins_failed {
        for i in &plugin.issues {
            keys.insert(format!("plugin:{}:{}", plugin.slug, i.path));
        }
    }
    for hit in &r.malware {
        keys.insert(format!("malware:{}:{}", hit.path, hit.signature));
    }
    keys
}

/// How much the malware sweep should yield to everything else, from
/// `[integrity] scan_niceness` (0-19, 0 = don't nice at all).
///
/// Defaults to a RECOMMENDATION rather than 0, because the setting exists to
/// stop an unattended sweep making live sites slow, and a default of "no
/// limit" means every box has that problem until someone notices and goes
/// looking for the switch. On a single-core VPS clamscan saturating its only
/// core is the difference between a site that responds and one that does not,
/// so the fewer cores a box has, the harder the scan should yield.
pub(super) fn recommended_scan_niceness() -> i32 {
    match std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
    {
        1 => 19, // one core: the scan must always lose to a web request
        2..=3 => 15,
        4..=7 => 10,
        _ => 5, // plenty of cores: stay polite, but finish in good time
    }
}

pub(super) fn read_scan_niceness(cfg_path: Option<&std::path::Path>) -> i32 {
    let from_cfg = cfg_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| raw.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|doc| {
            doc.get("integrity")
                .and_then(|s| s.get("scan_niceness"))
                .and_then(|v| v.as_integer())
        });
    match from_cfg {
        Some(n) => (n as i32).clamp(0, 19),
        None => recommended_scan_niceness(),
    }
}
