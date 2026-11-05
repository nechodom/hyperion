//! WordPress file integrity and malware scanning.

use super::*;
use hyperion_adapters::sitescan::scan::{ScanMode, SiteScanOutcome};

impl<A: AdapterPort + 'static> HostingService<A> {
    // ==================================================================
    //  File integrity + malware — the "has anything been TAMPERED WITH?"
    //  half of the defender, sibling to the outdated-component scan
    //  above. Same shapes, same KV storage idiom, and the same honesty
    //  rule: a signal that could not run is reported as "couldn't check",
    //  never as "clean". The schedule and the worker are in `scan_queue`.
    // ==================================================================

    /// The last stored integrity scan for a hosting. `None` when never
    /// scanned — or when the stored JSON no longer parses, which we treat
    /// as "never scanned" so a future shape change can't wedge the
    /// feature on a live node.
    pub(super) async fn stored_integrity_scan(
        &self,
        hosting_id: &str,
    ) -> Option<StoredIntegrityScan> {
        self.integrity_record(hosting_id).await.ok().flatten()
    }

    /// The same, for a caller to whom a read that FAILED is not "never scanned":
    /// the scheduler would start a scan on the strength of a database error.
    pub(super) async fn integrity_record(
        &self,
        hosting_id: &str,
    ) -> Result<Option<StoredIntegrityScan>, hyperion_state::StateError> {
        let json =
            hyperion_state::hosting_kv::get(&self.pool, hosting_id, INTEGRITY_KV_KEY).await?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    /// Whether the scheduled site scan may look at this hosting.
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

    /// "Scan now": wait for the node's one scan slot, scan this site, return the
    /// result. Compares with the checksums WordPress.org publishes for the exact
    /// installed versions by parsing and hashing, never by running wp-cli or any
    /// tenant PHP, then sweeps the docroot with ClamAV when a scanner exists. A
    /// probe that couldn't run comes back as "couldn't check" rather than a
    /// silent pass.
    ///
    /// The result is stored under the `integrity_scan` KV key so the dashboard,
    /// the ClamAV cadence and the next sweep's new-findings diff all read the
    /// same record.
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
        // Not stored: a reverse proxy has no place on the integrity dashboard.
        if detail.kind == "reverse_proxy" {
            return Ok(hyperion_types::WpIntegrityScanResult {
                error: Some(SITE_SCAN_NO_FILES.to_string()),
                scanned_at: now_secs(),
                // A node fact, true or not for this site: left at false the
                // card would send the operator to install ClamAV again.
                clamav_installed: integrity::clamav_available(),
                ..Default::default()
            });
        }
        let _gate = self.site_scan_gate.lock().await;
        // After the wait, which can be as long as another site's scan.
        let now = now_secs();
        let prior = self.stored_integrity_scan(detail.id.as_str()).await;
        match self
            .site_scan_locked(&detail, ScanMode::Delta, prior.as_ref(), now)
            .await
        {
            SiteScanRun::Finished(result) => Ok(result),
            SiteScanRun::Busy => Ok(scan_busy_result(prior)),
        }
    }

    /// What the last scan left for this hosting, without starting one.
    ///
    /// The WordPress tab loads this when it opens. It reads one KV row; no
    /// worker, no clamscan, no tenant PHP. A hosting never scanned comes back
    /// with `scanned_at == 0`, which `is_clean()` already refuses to call clean.
    pub async fn wp_integrity_stored(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpIntegrityScanResult, RpcError> {
        let detail = self.get(sel).await?;
        if let Some(stored) = self.stored_integrity_scan(detail.id.as_str()).await {
            let mut result = stored.result;
            // The record's own clock wins over a result that predates the
            // field; the scanner flag is a node fact, read fresh.
            result.scanned_at = stored.scanned_at;
            result.clamav_installed = integrity::clamav_available();
            result.scan_queued = false;
            return Ok(result);
        }
        Ok(hyperion_types::WpIntegrityScanResult {
            clamav_installed: integrity::clamav_available(),
            ..Default::default()
        })
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
            // No release to compare with, which this page's "couldn't check"
            // would misread. Its findings are on the site's own card.
            if st.result.coverage.no_upstream {
                continue;
            }
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

/// `hosting_kv` key gating the scheduled site scan for ONE hosting —
/// the per-site switch a care package sells (and enforces).
///
/// **Default ON** (absent ⇒ enabled), exactly like `wp_auto_update`: an
/// installation that never touches packages must keep scanning every site
/// it scans today. Only an explicit "off" opts a site out.
pub(super) const INTEGRITY_ENABLED_KV_KEY: &str = "integrity_scan_enabled";

/// Minimum gap between two ClamAV passes over the same docroot. Twenty
/// hours rather than a flat day so ordinary jitter in the daily sweep
/// can't push a site's scan past the cutoff and silently halve its
/// cadence to every other night.
pub(super) const CLAMAV_MIN_INTERVAL_SECS: i64 = 20 * 3600;

/// Minimum gap before retrying a ClamAV pass that failed.
pub(super) const CLAMAV_FAILED_RETRY_SECS: i64 = 3600;

/// Is a ClamAV pass over this docroot held off right now — a good one is
/// recent enough, or the last attempt failed recently?
pub(super) fn clamav_pass_held_off(prior: Option<&StoredIntegrityScan>, now: i64) -> bool {
    prior.is_some_and(|p| {
        (p.clamav_at > 0 && now.saturating_sub(p.clamav_at) < CLAMAV_MIN_INTERVAL_SECS)
            || (p.clamav_failed_at > 0
                && now.saturating_sub(p.clamav_failed_at) < CLAMAV_FAILED_RETRY_SECS)
    })
}

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
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(super) struct StoredIntegrityScan {
    pub(super) scanned_at: i64,
    /// Unix seconds of the last real ClamAV pass; 0 = never ran. Drives
    /// the daily cadence, so a carried-forward hit list keeps its
    /// original age instead of looking freshly confirmed.
    #[serde(default)]
    pub(super) clamav_at: i64,
    /// Unix seconds of the last ClamAV pass that FAILED (clamscan exit ≥ 2,
    /// e.g. no signature database yet); 0 = none since the last good one.
    /// Holds the next attempt off for [`CLAMAV_FAILED_RETRY_SECS`]: the card
    /// scans lazily on view, and a failure that repeats otherwise re-walked
    /// the whole docroot on every page load.
    #[serde(default)]
    pub(super) clamav_failed_at: i64,
    /// Unix seconds of the last run that read every file: a first scan, or a
    /// full re-hash that wasn't stopped. 0 = none.
    #[serde(default)]
    pub(super) full_at: i64,
    /// Unix seconds of the last run that gave no answer; 0 = the last one did.
    /// Holds the next attempt off, or a site the worker can't get through would
    /// take the node's one slot on every tick.
    #[serde(default)]
    pub(super) failed_at: i64,
    /// The last run stopped early, under load or at its read budget. It's due
    /// again sooner than a run that finished.
    #[serde(default)]
    pub(super) stopped: bool,
    pub(super) result: hyperion_types::WpIntegrityScanResult,
}

/// The previous pass's verdict, carried forward when this one does not run.
fn carried_malware_verdict(
    prior: Option<&StoredIntegrityScan>,
) -> (bool, Vec<hyperion_types::WpMalwareHit>, i64, i64) {
    match prior {
        Some(p) => (
            p.result.clamav_available,
            p.result.malware.clone(),
            p.clamav_at,
            p.clamav_failed_at,
        ),
        None => (false, Vec::new(), 0, 0),
    }
}

/// The reasons a ClamAV pass does not start at all. `Some(tuple)` = the
/// pass is over with that verdict; `None` = go ahead and scan. Node facts
/// come in as arguments so this stays testable.
pub(super) fn malware_pass_precheck(
    installed: bool,
    db_present: bool,
    now: i64,
    prior: Option<&StoredIntegrityScan>,
    errors: &mut Vec<String>,
) -> Option<(bool, Vec<hyperion_types::WpMalwareHit>, i64, i64)> {
    // No scanner installed. A normal state on a shared host — never an
    // error, and explicitly NOT a clean bill of health (the caller renders
    // `clamav_available = false` as "not scanned").
    if !installed {
        return Some((false, Vec::new(), 0, 0));
    }
    // Installed but still downloading signatures right after the package
    // went in: clamscan would exit 2 on every run. Wait, without the
    // failure back-off or a failed stamp.
    if !db_present {
        errors.push("malware scan waiting: ClamAV signatures are still downloading".into());
        return Some(carried_malware_verdict(prior));
    }
    if clamav_pass_held_off(prior, now) {
        if let Some(p) = prior.filter(|p| p.clamav_failed_at > 0) {
            errors.push(format!(
                "malware scan failed at its last attempt; next try after {} UTC",
                chrono::DateTime::from_timestamp(p.clamav_failed_at + CLAMAV_FAILED_RETRY_SECS, 0)
                    .map(|t| t.format("%H:%M").to_string())
                    .unwrap_or_default()
            ));
        }
        return Some(carried_malware_verdict(prior));
    }
    None
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
) -> (bool, Vec<hyperion_types::WpMalwareHit>, i64, i64) {
    if let Some(done) = malware_pass_precheck(
        integrity::clamav_available(),
        integrity::clamav_db_present(),
        now,
        prior,
        errors,
    ) {
        return done;
    }
    let Ok(_gate) = CLAMAV_GATE.try_lock() else {
        errors.push("malware scan skipped: another scan is already running on this node".into());
        return carried_malware_verdict(prior);
    };
    match integrity::scan_malware_niced(&detail.root_dir, scan_niceness).await {
        Ok(scan) => malware_scan_outcome(scan, now, errors),
        // clamscan exited ≥ 2 without a single detection: part of the tree
        // could not be read, so this pass proves nothing. "Couldn't check"
        // — we never build a pass on top of a partial walk.
        Err(e) => {
            errors.push(format!("malware scan failed: {e}"));
            (false, Vec::new(), 0, now)
        }
    }
}

/// Fold one finished ClamAV run into the pass tuple. A partial run that
/// still found something counts as having run: the hits are real, and a
/// retry back-off would only delay telling anyone. The report says it was
/// partial, so the missing hits are not read as absent.
pub(super) fn malware_scan_outcome(
    scan: integrity::MalwareScan,
    now: i64,
    errors: &mut Vec<String>,
) -> (bool, Vec<hyperion_types::WpMalwareHit>, i64, i64) {
    if scan.partial && scan.available {
        errors.push(
            "malware scan was partial: some files could not be read, so more may be hiding".into(),
        );
    }
    (
        scan.available,
        scan.hits,
        if scan.available { now } else { 0 },
        0,
    )
}

/// Fold the native scan and the ClamAV pass into the wire result, keeping the
/// fields the reports and the dashboard have always read.
///
/// Pure on purpose: this is where "we could not check" becomes what the panel
/// renders, and getting it wrong means telling a paying customer their site is
/// clean when nothing ever looked at it. `scanned_at` and `error` are the
/// caller's to fill.
pub(super) fn assemble_integrity_result(
    outcome: SiteScanOutcome,
    malware: Vec<hyperion_types::WpMalwareHit>,
    clamav_available: bool,
    report_only: bool,
) -> hyperion_types::WpIntegrityScanResult {
    let up = outcome.upstream;
    hyperion_types::WpIntegrityScanResult {
        // A missing file alone leaves core "ok": usually a botched update, and
        // listed in its own bucket.
        core_ok: up.ran && up.core_modified.is_empty() && up.core_unexpected.is_empty(),
        wp_cli_ok: up.ran,
        core_modified: up.core_modified,
        core_unexpected: up.core_unexpected,
        core_missing: up.core_missing,
        plugins_failed: up.plugins_failed,
        plugins_unknown: up.plugins_unknown,
        themes_failed: up.themes_failed,
        plugins_checked: outcome.coverage.plugins_verified,
        plugins_total: outcome.coverage.plugins_total,
        malware,
        clamav_available,
        native_scan_ran: true,
        report_only,
        findings: outcome.findings,
        review: outcome.review,
        coverage: outcome.coverage,
        ..Default::default()
    }
}

/// Stable identity for every finding in a scan, so the sweep can alert on
/// what is NEW instead of re-sending the same list nightly. The prefixes
/// keep the three core buckets apart: the same path moving from "missing"
/// to "modified" is a different event, not the same one.
///
/// Today's signals only: core, plugins and ClamAV. What the new layers find
/// (rule hits, changes to review, themes) stays out through the silent pilot.
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

/// Whether the new layers' findings count for more than the panel, from
/// `[integrity] new_layers_live`. Off until the owner has seen pilot results.
pub(super) fn read_new_layers_live(cfg_path: Option<&std::path::Path>) -> bool {
    cfg_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| raw.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|doc| {
            doc.get("integrity")
                .and_then(|s| s.get("new_layers_live"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(false)
}
