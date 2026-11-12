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

    /// Scan now and wait for the answer: the node's one scan slot, this site.
    /// ClamAV is not part of it; the node's weekly pass is. `hctl`'s; the panel sends
    /// [`wp_integrity_scan_request`](Self::wp_integrity_scan_request) instead.
    /// Compares with the checksums WordPress.org publishes for the exact installed
    /// versions by parsing and hashing, never by running wp-cli or any tenant PHP.
    /// A probe that couldn't run comes back as "couldn't check" rather than a
    /// silent pass.
    ///
    /// The result is stored under the `integrity_scan` KV key so the dashboard
    /// and the next sweep's new-findings diff read the same record.
    pub async fn wp_integrity_scan(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpIntegrityScanResult, RpcError> {
        let detail = self.get(sel).await?;
        if let Some(refused) = scan_refusal(&detail)? {
            return Ok(refused);
        }
        let gate = self.site_scan.node.lock().await;
        // After the wait, which can be as long as another site's scan.
        let now = now_secs();
        // A read that failed is not "never scanned".
        let prior = self
            .integrity_record(detail.id.as_str())
            .await
            .map_err(|e| RpcError::Internal_with(format!("integrity record: {e}")))?;
        let run = self
            .site_scan_locked(&detail, ScanMode::Delta, prior.as_ref(), now)
            .await;
        drop(gate);
        let (result, native_ran) = match run {
            SiteScanRun::Finished { result, native_ran } => (result, native_ran),
            SiteScanRun::Busy => return Ok(scan_busy_result(prior)),
            SiteScanRun::NotStored => return Ok(scan_not_stored_result(prior)),
        };
        Ok(if native_ran {
            result
        } else {
            scan_did_not_run(result)
        })
    }

    /// "Scan now": note that a scan is wanted, wake the tick, and answer with what
    /// is stored. The scan can be an hour away behind another site's, so nothing
    /// waits for it; the card polls while `scan_queued` is set. Asking twice is
    /// still one scan.
    pub async fn wp_integrity_scan_request(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::WpIntegrityScanResult, RpcError> {
        let detail = self.get(sel.clone()).await?;
        if let Some(refused) = scan_refusal(&detail)? {
            return Ok(refused);
        }
        let now = now_secs();
        hyperion_state::hosting_kv::set(
            &self.pool,
            detail.id.as_str(),
            SCAN_REQUESTED_KV_KEY,
            &now.to_string(),
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("scan request: {e}")))?;
        self.site_scan.wake.notify_one();
        self.wp_integrity_stored(sel).await
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
        // A reload of the page keeps polling for as long as the request stands
        // and nothing newer than it has been stored.
        let flag = self.scan_request_flag(detail.id.as_str()).await;
        if let Some(stored) = self.stored_integrity_scan(detail.id.as_str()).await {
            let queued = flag.as_deref().is_some_and(|f| {
                f.trim()
                    .parse::<i64>()
                    .map_or(true, |at| stored.scanned_at <= at)
            });
            let mut result = stored.result;
            // The record's own clock wins over a result that predates the
            // field; the scanner flag is a node fact, read fresh.
            result.scanned_at = stored.scanned_at;
            result.clamav_at = stored.clamav_at;
            result.clamav_installed = integrity::clamav_available();
            result.scan_queued = queued;
            return Ok(result);
        }
        Ok(hyperion_types::WpIntegrityScanResult {
            clamav_installed: integrity::clamav_available(),
            scan_queued: flag.is_some(),
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
            // The file lists are the site card's. With every site on the node in
            // one reply they'd be most of a frame, and this page counts them.
            let mut result = st.result;
            result.findings = Vec::new();
            result.review = Vec::new();
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
                result,
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

/// `hosting_kv` key: unix seconds someone last asked for a scan of this hosting.
/// Gone once a scan that started after that has been stored.
pub(super) const SCAN_REQUESTED_KV_KEY: &str = "scan_requested";

/// What we persist per hosting under the `integrity_scan` KV key: the
/// last result, when it ran, and — separately — when the node's ClamAV pass
/// last covered the site. Both timestamps ride inside the value because the KV
/// layer's own `updated_at` isn't read back by `list_by_key`, and because the
/// scan runs far more often than the weekly malware pass.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub(super) struct StoredIntegrityScan {
    pub(super) scanned_at: i64,
    /// Unix seconds of the last ClamAV pass that covered this site; 0 = never.
    /// A carried-forward hit list keeps its original age instead of looking
    /// freshly confirmed.
    #[serde(default)]
    pub(super) clamav_at: i64,
    /// Written by releases that had a per-site ClamAV pass; nothing sets or reads
    /// it now. Kept so an old record still parses.
    #[serde(default)]
    pub(super) clamav_failed_at: i64,
    /// Why the last ClamAV pass said nothing, or what it did not cover. Generic
    /// text only: clamscan's own words name tenant files.
    #[serde(default)]
    pub(super) clamav_error: Option<String>,
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
        accepted_by_writer: outcome.accepted_by_writer,
        coverage: outcome.coverage,
        ..Default::default()
    }
}

/// Stable identity for every finding in a scan, so the sweep can alert on
/// what is NEW instead of re-sending the same list nightly. The prefixes
/// keep the buckets apart: the same path moving from "missing" to "modified"
/// is a different event, not the same one.
///
/// Every signal, whether or not it alerts yet: a record from the silent pilot
/// holds the same keys a live one would, which is what lets the first live
/// scan treat what already stood as known. A failed comparison is one key
/// however many buckets list it (`core:`, `plugin:`, `theme:` carry it), so
/// `find:` is for what a rule objected to.
pub(super) fn integrity_finding_keys(
    r: &hyperion_types::WpIntegrityScanResult,
) -> std::collections::HashSet<String> {
    let mut keys = legacy_finding_keys(r);
    for t in &r.themes_failed {
        for i in &t.issues {
            keys.insert(format!("theme:{}:{}", t.slug, i.path));
        }
    }
    keys.extend(r.listed_findings().map(find_key));
    keys.extend(r.review.iter().map(review_key));
    keys
}

fn find_key(f: &hyperion_types::SiteFileFinding) -> String {
    format!("find:{}:{}", f.rel, f.rule_id.as_deref().unwrap_or("-"))
}

fn review_key(f: &hyperion_types::SiteFileFinding) -> String {
    format!("review:{}", f.rel)
}

/// Today's signals: core, plugins and ClamAV. They alert whether or not the new
/// layers are live.
pub(super) fn legacy_finding_keys(
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

/// What a scan has to say that the last one didn't.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct IntegrityAlertPlan {
    /// New failed comparisons, rule hits and failed themes.
    pub(super) findings: usize,
    /// New changes to review: one batched message per site per sweep.
    pub(super) review: usize,
    /// The findings include something that isn't just a missing core file.
    pub(super) error: bool,
}

impl IntegrityAlertPlan {
    pub(super) fn is_empty(&self) -> bool {
        self.findings == 0 && self.review == 0
    }
}

/// Which new keys a scan alerts, against the record it replaces (ClamAV's are
/// its own sweep's to tell and never count here).
///
/// Through the silent pilot only today's signals count; the rest are stored
/// and stay quiet. Live, rule hits, changes to review and failed themes count
/// too, and on a first scan only the high-severity ones: a site with no
/// baseline would otherwise report its whole tree. A pilot record's keys are
/// known, so turning the switch on alerts what appears after it.
///
/// The first-scan filter reads the severity of rule findings and review items
/// only. A failed theme comparison has none and counts as High, like a failed
/// core or plugin comparison: it alerts on a first scan too.
///
/// A difference from a vendor's package that is held for review (the pilot's, or
/// a version whose packages disagree, even with `vendor_refs_live` on) never
/// alerts: nothing has shown the reference is right.
pub(super) fn plan_integrity_alert(
    prior: Option<&hyperion_types::WpIntegrityScanResult>,
    scan: &hyperion_types::WpIntegrityScanResult,
) -> IntegrityAlertPlan {
    let known = prior.map(integrity_finding_keys).unwrap_or_default();
    let mut new: std::collections::HashSet<String> = integrity_finding_keys(scan)
        .into_iter()
        .filter(|k| !k.starts_with("malware:") && !known.contains(k))
        .collect();
    let held: std::collections::HashSet<String> = scan
        .review
        .iter()
        .filter(|f| f.held_vendor_note().is_some())
        .map(review_key)
        .collect();
    new.retain(|k| !held.contains(k));
    if !scan.is_live() {
        let legacy = legacy_finding_keys(scan);
        new.retain(|k| legacy.contains(k));
    } else if prior.map_or(true, |p| !p.native_scan_ran) {
        let high: std::collections::HashSet<String> = scan
            .listed_findings()
            .filter(|f| f.severity == "high")
            .map(find_key)
            .chain(
                scan.review
                    .iter()
                    .filter(|f| f.severity == "high")
                    .map(review_key),
            )
            .collect();
        new.retain(|k| !(k.starts_with("find:") || k.starts_with("review:")) || high.contains(k));
    }
    let review = new.iter().filter(|k| k.starts_with("review:")).count();
    let findings = new.len() - review;
    // A missing core file is usually a botched update; anything else a finding
    // names is a suspected compromise.
    let error = new
        .iter()
        .any(|k| !k.starts_with("core:gone:") && !k.starts_with("review:"));
    IntegrityAlertPlan {
        findings,
        review,
        error,
    }
}

/// A hosting that is never scanned, and why, or `Err` for one that can't be right
/// now. A reverse proxy has no files of its own.
pub(super) fn scan_refusal(
    detail: &HostingDetail,
) -> Result<Option<hyperion_types::WpIntegrityScanResult>, RpcError> {
    if detail.state != HostingState::Active {
        return Err(RpcError::Conflict {
            message: "hosting must be active to scan".into(),
        });
    }
    if !kind_has_files(&detail.kind) {
        // Not stored: it has no place on the integrity dashboard.
        return Ok(Some(hyperion_types::WpIntegrityScanResult {
            error: Some(SITE_SCAN_NO_FILES.to_string()),
            scanned_at: now_secs(),
            // A node fact, true or not for this site: left at false the
            // card would send the operator to install ClamAV again.
            clamav_installed: integrity::clamav_available(),
            ..Default::default()
        }));
    }
    Ok(None)
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

/// `[antivirus]`: when the node's ClamAV pass runs. A file that can't be read,
/// or says nothing, is the defaults.
pub(super) fn read_antivirus_settings(
    cfg_path: Option<&std::path::Path>,
) -> hyperion_types::antivirus::AntivirusSettings {
    let doc = cfg_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| raw.parse::<toml_edit::DocumentMut>().ok());
    let get = |key: &str| doc.as_ref()?.get("antivirus")?.get(key).cloned();
    hyperion_types::antivirus::AntivirusSettings::from_lookup(
        |k| get(k)?.as_bool(),
        |k| get(k)?.as_integer(),
    )
}

/// Whether a difference from a vendor's package counts as a finding, from
/// `[integrity] vendor_refs_live`. Off until real licences have shown these
/// references can be believed: it's a change to review until then.
pub(super) fn read_vendor_refs_live(cfg_path: Option<&std::path::Path>) -> bool {
    cfg_path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|raw| raw.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|doc| {
            doc.get("integrity")
                .and_then(|s| s.get("vendor_refs_live"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(false)
}
