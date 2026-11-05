//! When the native site scan runs, one site at a time, and what becomes of its
//! answer.
//!
//! The per-node lock is FIFO and the tick holds it per site, so "Scan now"
//! waiting on it runs after the current site and before the rest of the sweep:
//! that is all the queue there is. The worker parses hostile files as root, so
//! its reply is untrusted input here, clamped before anything stores it.

use super::*;
use chrono::{Datelike, Timelike};
use hyperion_adapters::sitescan::discover::Discovery;
use hyperion_adapters::sitescan::manifest::ComponentKind;
use hyperion_adapters::sitescan::runner::{WorkerJob, WorkerReply};
use hyperion_adapters::sitescan::scan::{ScanInput, ScanMode, SiteScanOutcome};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(super) use hyperion_adapters::sitescan::runner::SCAN_DIR;

/// Where quarantined files are held, per hosting.
pub(super) const QUARANTINE_DIR: &str = "/var/lib/hyperion/quarantine";

const HOUR_SECS: i64 = 3600;
const DAY_SECS: i64 = 24 * HOUR_SECS;
/// A delta scan (stat walk, read what changed) this often.
const DELTA_INTERVAL_SECS: i64 = 6 * HOUR_SECS;
/// A scan that stopped early, or failed, comes back this soon and no sooner.
const RETRY_SECS: i64 = HOUR_SECS;
/// Not quite a week, so a re-hash that started late in the window doesn't push
/// the next one past its night.
const FULL_REHASH_MIN_AGE_SECS: i64 = 6 * DAY_SECS;
/// The full re-hash runs in these local hours.
const FULL_REHASH_HOURS: std::ops::Range<u32> = 2..6;

/// A stamp this far ahead of `now` means the clock moved back. Anything less is a
/// "Scan now" that finished during a sweep, whose clock lags by up to a minute.
const CLOCK_MOVED_SECS: i64 = 5 * 60;

/// `node_kv` key: unix seconds the manifest cache was last swept.
const EVICT_LAST_RUN_KV: &str = "site_scan_evict_last_run_at";

/// wordpress.org requests one site's scan may make.
const MAX_HTTP_FETCHES: u32 = 200;
/// Theme ZIPs one site's scan may download. Each is up to 256 MiB.
const MAX_THEME_ZIPS: u32 = 20;
/// Core looks up the site's locale, then en_US.
const CORE_HTTP_COST: u32 = 2;
/// Failures in a row that mean wordpress.org is out of reach. The node's lock is
/// held meanwhile, and each attempt can take a minute to give up.
const NETWORK_GIVE_UP: u32 = 3;

// What a reply may hold. An honest worker stays under these by its own limits.
const MAX_ITEMS: usize = 1000;
/// `LIST_CAP` plugins, as many themes, and core.
const MAX_COMPONENTS: usize = 10_001;
/// The worker's 20, and what the agent adds in front of them.
const MAX_REASONS: usize = 24;
const MAX_AUTO_ACCEPTED: usize = 200;
const MAX_DOMAINS: usize = 10;
const MAX_PATH_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 1024;
const MAX_REASON_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 256;
const MAX_ID_BYTES: usize = 128;

/// What the card says when the scan didn't run. Generic on purpose: the worker's
/// own message can carry tenant text.
const SITE_SCAN_FAILED: &str = "the site scan could not finish; this is the last result it stored";
const SITE_SCAN_BUSY: &str = "another site scan is still running on this node; try again shortly";
pub(super) const SITE_SCAN_NO_FILES: &str = "a reverse proxy has no files of its own to scan";

// One of these is alive per site, so the size of the variants costs nothing.
/// How one site's turn with the lock ended.
#[allow(clippy::large_enum_variant)]
pub(super) enum SiteScanRun {
    Finished(hyperion_types::WpIntegrityScanResult),
    /// A worker that survived an agent restart holds the unit. Nothing happened.
    Busy,
}

#[allow(clippy::large_enum_variant)]
enum NativeScan {
    Ran(SiteScanOutcome),
    Failed,
    Busy,
}

/// What looking up a site's components left for the scan.
pub(super) struct ManifestPass {
    /// Slugs wordpress.org knows, or None when that couldn't be established for
    /// every component, and then no slug gets a premium-update pass.
    pub(super) known_slugs: Option<BTreeSet<String>>,
    pub(super) reasons: Vec<String>,
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Scan the sites that are due on this node, oldest-scanned first, and tell
    /// admins about what is new: a standing finding must not re-alert or the
    /// operator learns to ignore the panel. Returns the number of hostings that
    /// gained a new finding.
    ///
    /// Everything that decides "due" lives in each site's stored record, so an
    /// agent restart (every deploy is one) starts nothing by itself.
    pub async fn site_scan_tick(&self) -> Result<i64, RpcError> {
        self.site_scan_tick_at(&chrono::Local, now_secs()).await
    }

    pub(super) async fn site_scan_tick_at<Tz: chrono::TimeZone>(
        &self,
        tz: &Tz,
        now: i64,
    ) -> Result<i64, RpcError> {
        self.site_scan_evict_daily(now).await;
        let started = std::time::Instant::now();
        let mut queue = Vec::new();
        for s in self.list().await? {
            if s.state != HostingState::Active || s.kind.as_deref() == Some("reverse_proxy") {
                continue;
            }
            // Per-site opt-out (default on). This is the switch the
            // `integrity_scan` package feature forces, so a customer who pays
            // for scanning keeps getting scanned even after someone turns it
            // off on the site.
            if !self.integrity_scan_enabled(s.id.as_str()).await {
                continue;
            }
            // A read that failed is not "never scanned".
            let prior = match self.integrity_record(s.id.as_str()).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(domain = %s.domain, error = %e, "site scan: record unreadable");
                    continue;
                }
            };
            if site_scan_due(prior.as_ref(), now, tz, s.id.as_str()).is_some() {
                queue.push((prior.map_or(0, |p| p.scanned_at), s));
            }
        }
        queue.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.id.as_str().cmp(b.1.id.as_str()))
        });

        let mut newly_flagged = 0i64;
        for (_, s) in queue {
            let gate = self.site_scan_gate.lock().await;
            // A sweep can outlast the window it started in. To the minute is all
            // a schedule needs.
            let now = now + i64::try_from(started.elapsed().as_secs() / 60 * 60).unwrap_or(0);
            // Asked again under the lock: "Scan now" may have got here first.
            let Ok(prior) = self.integrity_record(s.id.as_str()).await else {
                continue;
            };
            let Some(mode) = site_scan_due(prior.as_ref(), now, tz, s.id.as_str()) else {
                continue;
            };
            let detail = match self.get(HostingSelector::Id(s.id.clone())).await {
                Ok(d) if d.state == HostingState::Active => d,
                _ => continue,
            };
            let prior_keys = prior
                .as_ref()
                .map(|p| integrity_finding_keys(&p.result))
                .unwrap_or_default();
            let scan = match self
                .site_scan_locked(&detail, mode, prior.as_ref(), now)
                .await
            {
                SiteScanRun::Finished(r) => r,
                SiteScanRun::Busy => {
                    tracing::debug!("site scan: another worker is running; next tick");
                    return Ok(newly_flagged);
                }
            };
            drop(gate);

            // Upstream's and ClamAV's keys only: the new layers stay silent
            // through the pilot.
            let new_keys = integrity_finding_keys(&scan)
                .difference(&prior_keys)
                .count();
            if new_keys == 0 {
                continue;
            }
            newly_flagged += 1;
            // A modified core file, a tampered plugin or a signature hit is a
            // suspected compromise. A merely *missing* core file is usually a
            // botched update: still worth saying, not worth waking someone up
            // for.
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

    /// Scan one site and store the result. The caller holds the node's lock.
    pub(super) async fn site_scan_locked(
        &self,
        detail: &HostingDetail,
        mode: ScanMode,
        prior: Option<&StoredIntegrityScan>,
        now: i64,
    ) -> SiteScanRun {
        let native = self.native_site_scan(detail, mode, now).await;
        if matches!(native, NativeScan::Busy) {
            return SiteScanRun::Busy;
        }
        // Collected, not returned: one dead signal must not hide what the other
        // found.
        let mut errors: Vec<String> = Vec::new();
        let (clamav_available, malware, clamav_at, clamav_failed_at) = integrity_malware_pass(
            detail,
            now,
            self.malware_scan_niceness(),
            prior,
            &mut errors,
        )
        .await;
        let clamav_installed = integrity::clamav_available();

        let (stored, returned) = if let NativeScan::Ran(mut outcome) = native {
            let stopped = outcome.stopped;
            let auto_accepted = std::mem::take(&mut outcome.auto_accepted);
            let mut result = assemble_integrity_result(
                outcome,
                malware,
                clamav_available,
                !self.site_scan_new_layers_live(),
            );
            if let Some(p) = prior.filter(|_| stopped) {
                carry_standing_findings(&mut result, &p.result);
            }
            result.scanned_at = now;
            result.clamav_installed = clamav_installed;
            result.error = (!errors.is_empty()).then(|| errors.join("; "));
            let first_scan = prior.map_or(true, |p| !p.result.native_scan_ran);
            let read_everything = !stopped && (mode == ScanMode::FullRehash || first_scan);
            let stored = StoredIntegrityScan {
                scanned_at: now,
                clamav_at,
                clamav_failed_at,
                full_at: if read_everything {
                    now
                } else {
                    prior.map_or(0, |p| p.full_at)
                },
                failed_at: 0,
                stopped,
                result: result.clone(),
            };
            if !auto_accepted.is_empty() {
                self.append_audit(
                    "wp.integrity.auto_accept",
                    Some(detail.id.as_str()),
                    &serde_json::json!({ "files": auto_accepted }).to_string(),
                    "ok",
                )
                .await;
            }
            (stored, result)
        } else {
            // What the last run found is still the best anyone knows, and an
            // empty list here would read as "those went away". The record's
            // clock stays where it was: this run proved nothing.
            errors.insert(0, SITE_SCAN_FAILED.to_string());
            let mut result = prior.map_or_else(Default::default, |p| p.result.clone());
            result.malware = malware;
            result.clamav_available = clamav_available;
            result.clamav_installed = clamav_installed;
            result.error = Some(errors.join("; "));
            let scanned_at = prior.map_or(now, |p| p.scanned_at);
            if prior.is_none() {
                result.scanned_at = now;
            }
            let stored = StoredIntegrityScan {
                scanned_at,
                clamav_at,
                clamav_failed_at,
                full_at: prior.map_or(0, |p| p.full_at),
                failed_at: now,
                stopped: prior.is_some_and(|p| p.stopped),
                result: result.clone(),
            };
            (stored, scan_did_not_run(result))
        };
        self.set_stored_integrity_scan(detail.id.as_str(), &stored)
            .await;
        self.append_audit(
            "wp.integrity.scan",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "core_issues": returned.core_issue_count(),
                "plugin_issues": returned.plugin_issue_count(),
                "malware": returned.malware.len(),
                "findings": returned.findings.len(),
                "review": returned.review.len(),
                "upstream": returned.wp_cli_ok,
                "native": returned.native_scan_ran,
                "clamav": returned.clamav_available,
            })
            .to_string(),
            if returned.native_scan_ran {
                "ok"
            } else {
                "failed"
            },
        )
        .await;
        SiteScanRun::Finished(returned)
    }

    /// Discover in the worker, fetch here (the worker has no network), scan in
    /// the worker.
    async fn native_site_scan(
        &self,
        detail: &HostingDetail,
        mode: ScanMode,
        now: i64,
    ) -> NativeScan {
        let root = PathBuf::from(&detail.root_dir);
        let job = WorkerJob::Discover { root: root.clone() };
        let mut discovery = match self.adapters.site_scan_worker(job).await {
            WorkerReply::Discovery(d) => d,
            other => return self.scan_not_answered(detail, other),
        };
        discovery.components.truncate(MAX_COMPONENTS);

        let scan_dir = Path::new(&self.paths.scan_dir);
        let manifests_dir = scan_dir.join("manifests");
        let pass = self
            .site_scan_fetch_manifests(&discovery, &manifests_dir)
            .await;
        let job = WorkerJob::Scan(ScanInput {
            root,
            discovery,
            manifests_dir,
            baseline_path: scan_dir.join("baselines").join(detail.id.as_str()),
            mode,
            now,
            wporg_known_slugs: pass.known_slugs,
            accept_since: None,
        });
        let mut outcome = match self.adapters.site_scan_worker(job).await {
            WorkerReply::Scan(o) => o,
            other => return self.scan_not_answered(detail, other),
        };
        // In front, so the cap below can't lose them to the worker's own.
        let mut reasons = pass.reasons;
        reasons.append(&mut outcome.coverage.partial_reasons);
        outcome.coverage.partial_reasons = reasons;
        clamp_scan_outcome(&mut outcome);
        NativeScan::Ran(outcome)
    }

    /// The reply wasn't the answer asked for. Why goes to the log only, escaped:
    /// it can carry names a tenant chose.
    fn scan_not_answered(&self, detail: &HostingDetail, reply: WorkerReply) -> NativeScan {
        match reply {
            WorkerReply::Busy => NativeScan::Busy,
            WorkerReply::Failed(why) => {
                tracing::warn!(domain = %detail.domain, why = ?why, "site scan failed");
                NativeScan::Failed
            }
            _ => {
                tracing::warn!(domain = %detail.domain, "site scan: the worker answered another job");
                NativeScan::Failed
            }
        }
    }

    /// Have the cache hold whatever wordpress.org has for this site's
    /// components, within a budget: discovery is the tenant's to fill, and a
    /// thousand made-up plugin folders must not become a thousand downloads.
    /// What is cached costs nothing, and what isn't reached this time is reached
    /// by a later scan, since each answer stays cached.
    pub(super) async fn site_scan_fetch_manifests(
        &self,
        discovery: &Discovery,
        cache_dir: &Path,
    ) -> ManifestPass {
        let mut http = MAX_HTTP_FETCHES;
        let mut zips = MAX_THEME_ZIPS;
        let mut failures = 0u32;
        let mut known = Some(BTreeSet::new());
        let (mut core_unreached, mut unreached, mut over_budget) = (false, 0usize, 0usize);

        // Core first: its answer is the one no tenant's folders may use up.
        let mut components: Vec<_> = discovery.components.iter().collect();
        components.sort_by_key(|c| c.key.kind != ComponentKind::Core);
        for c in components {
            let is_core = c.key.kind == ComponentKind::Core;
            let is_theme = c.key.kind == ComponentKind::Theme;
            let mut answer = self
                .adapters
                .site_scan_cached_manifest(&c.key, cache_dir)
                .await;
            if answer.is_none() {
                let cost = if is_core { CORE_HTTP_COST } else { 1 };
                if failures >= NETWORK_GIVE_UP {
                    core_unreached |= is_core;
                    unreached += usize::from(!is_core);
                } else if http < cost || (is_theme && zips == 0) {
                    over_budget += 1;
                } else {
                    http -= cost;
                    zips -= u32::from(is_theme);
                    match self
                        .adapters
                        .site_scan_fetch_manifest(&c.key, cache_dir)
                        .await
                    {
                        Ok(a) => {
                            failures = 0;
                            answer = Some(a);
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "site scan: manifest fetch failed");
                            failures += 1;
                            core_unreached |= is_core;
                            unreached += usize::from(!is_core);
                        }
                    }
                }
            }
            if is_core {
                continue;
            }
            match answer {
                // A manifest from wordpress.org names the slug as known.
                Some(Some(_)) => {
                    if let Some(set) = known.as_mut() {
                        set.insert(c.key.slug.clone());
                    }
                }
                // Nobody asked or nobody answered: it may be on wordpress.org.
                None => known = None,
                Some(None) => {
                    // Only these can get the premium-update pass.
                    if known.is_none() || c.is_child_theme || c.key.version.is_empty() {
                        continue;
                    }
                    let mut slug_known = self
                        .adapters
                        .site_scan_cached_slug(c.key.kind, &c.key.slug, cache_dir)
                        .await;
                    if slug_known.is_none() && http > 0 && failures < NETWORK_GIVE_UP {
                        http -= 1;
                        match self
                            .adapters
                            .site_scan_slug_known(c.key.kind, &c.key.slug, cache_dir)
                            .await
                        {
                            Ok(k) => {
                                failures = 0;
                                slug_known = Some(k);
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "site scan: slug lookup failed");
                                failures += 1;
                            }
                        }
                    }
                    match slug_known {
                        Some(true) => {
                            if let Some(set) = known.as_mut() {
                                set.insert(c.key.slug.clone());
                            }
                        }
                        Some(false) => {}
                        None => known = None,
                    }
                }
            }
        }

        // Counts, not names: a slug is a folder name the tenant chose.
        let mut reasons = Vec::new();
        if core_unreached {
            reasons.push(
                "wordpress.org couldn't be reached, so WordPress core couldn't be checked"
                    .to_string(),
            );
        }
        if unreached > 0 {
            reasons.push(format!(
                "wordpress.org couldn't be reached, so {unreached} plugins or themes couldn't be checked"
            ));
        }
        if over_budget > 0 {
            reasons.push(format!(
                "{over_budget} plugins or themes couldn't be checked: more than one scan looks up; the next scan continues"
            ));
        }
        ManifestPass {
            known_slugs: known,
            reasons,
        }
    }

    /// Sweep the manifest cache once a day, stamped in `node_kv` so a restart
    /// doesn't repeat it. Under the lock: never beneath a running worker.
    async fn site_scan_evict_daily(&self, now: i64) {
        let last = match hyperion_state::node_kv::get(&self.pool, EVICT_LAST_RUN_KV).await {
            Ok(v) => v.and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0),
            Err(e) => {
                tracing::warn!(error = %e, "site scan: eviction stamp unreadable");
                return;
            }
        };
        if last > 0 && last <= now && now - last < DAY_SECS {
            return;
        }
        if let Err(e) =
            hyperion_state::node_kv::set(&self.pool, EVICT_LAST_RUN_KV, &now.to_string(), now).await
        {
            tracing::warn!(error = %e, "site scan: eviction stamp not written");
            return;
        }
        let _gate = self.site_scan_gate.lock().await;
        let dir = Path::new(&self.paths.scan_dir).join("manifests");
        self.adapters.site_scan_evict_manifests(&dir).await;
    }
}

/// The night of the week a site's full re-hash belongs to, 0 = Monday. FNV-1a by
/// hand: std's hasher may change between builds, which would move every site's
/// night on a deploy and could skip one for a week.
pub(super) fn site_scan_weekday(id: &str) -> u32 {
    let hash = id.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    u32::try_from(hash % 7).unwrap_or(0)
}

/// The clock moved back since `at` was stamped. Waiting for it to catch up could
/// switch a site's scans off for as long as it moved.
fn stamped_ahead(at: i64, now: i64) -> bool {
    at > now + CLOCK_MOVED_SECS
}

/// `at` is a real moment less than [`RETRY_SECS`] ago.
fn within_retry(at: i64, now: i64) -> bool {
    at > 0 && !stamped_ahead(at, now) && now - at < RETRY_SECS
}

/// Which scan a site is due, if any. No record, or a record from before the
/// native scan (no baseline behind it), is a first scan: at once, at any hour,
/// since the worker's caps make that safe.
pub(super) fn site_scan_due<Tz: chrono::TimeZone>(
    prior: Option<&StoredIntegrityScan>,
    now: i64,
    tz: &Tz,
    id: &str,
) -> Option<ScanMode> {
    let Some(p) = prior else {
        return Some(ScanMode::Delta);
    };
    if within_retry(p.failed_at, now) {
        return None;
    }
    if !p.result.native_scan_ran {
        return Some(ScanMode::Delta);
    }
    if p.stopped && within_retry(p.scanned_at, now) {
        return None;
    }
    if full_rehash_due(p, now, tz, id) {
        return Some(ScanMode::FullRehash);
    }
    let wait = if p.stopped {
        RETRY_SECS
    } else {
        DELTA_INTERVAL_SECS
    };
    (stamped_ahead(p.scanned_at, now) || now - p.scanned_at >= wait).then_some(ScanMode::Delta)
}

fn full_rehash_due<Tz: chrono::TimeZone>(
    p: &StoredIntegrityScan,
    now: i64,
    tz: &Tz,
    id: &str,
) -> bool {
    let Some(local) = tz.timestamp_opt(now, 0).single() else {
        return false;
    };
    FULL_REHASH_HOURS.contains(&local.hour())
        && local.weekday().num_days_from_monday() == site_scan_weekday(id)
        && (stamped_ahead(p.full_at, now) || now - p.full_at >= FULL_REHASH_MIN_AGE_SECS)
}

/// The stored result as the caller of a scan that didn't run should read it:
/// the findings are the last run's, and nothing was verified just now.
pub(super) fn scan_did_not_run(
    mut result: hyperion_types::WpIntegrityScanResult,
) -> hyperion_types::WpIntegrityScanResult {
    result.wp_cli_ok = false;
    result.core_ok = false;
    result.native_scan_ran = false;
    result
}

/// The answer to "Scan now" while another worker holds the unit.
pub(super) fn scan_busy_result(
    prior: Option<StoredIntegrityScan>,
) -> hyperion_types::WpIntegrityScanResult {
    let mut result = scan_did_not_run(prior.map(|p| p.result).unwrap_or_default());
    result.error = Some(SITE_SCAN_BUSY.to_string());
    result.clamav_installed = integrity::clamav_available();
    result
}

/// A scan that stopped early says nothing about the files it didn't reach, so
/// what the last run listed stays until a complete run clears it. Dropping it
/// would also read as "new" to the alert diff when the next run finds it again.
fn carry_standing_findings(
    result: &mut hyperion_types::WpIntegrityScanResult,
    prior: &hyperion_types::WpIntegrityScanResult,
) {
    for (into, from) in [
        (&mut result.core_modified, &prior.core_modified),
        (&mut result.core_unexpected, &prior.core_unexpected),
        (&mut result.core_missing, &prior.core_missing),
    ] {
        union_into(into, from);
        into.truncate(MAX_ITEMS);
    }
    for (into, from) in [
        (&mut result.plugins_failed, &prior.plugins_failed),
        (&mut result.themes_failed, &prior.themes_failed),
    ] {
        for old in from {
            match into.iter_mut().find(|p| p.slug == old.slug) {
                Some(p) => union_into(&mut p.issues, &old.issues),
                None => into.push(old.clone()),
            }
        }
        clamp_failed(into);
    }
    for (into, from) in [
        (&mut result.findings, &prior.findings),
        (&mut result.review, &prior.review),
    ] {
        union_into(into, from);
        into.truncate(MAX_ITEMS);
    }
}

fn union_into<T: Clone + PartialEq>(into: &mut Vec<T>, from: &[T]) {
    for item in from {
        if !into.contains(item) {
            into.push(item.clone());
        }
    }
}

/// Cut a string to at most `max` bytes, on a character boundary.
fn clip(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

fn clip_opt(s: &mut Option<String>, max: usize) {
    if let Some(s) = s {
        clip(s, max);
    }
}

fn clip_list(list: &mut Vec<String>, count: usize, bytes: usize) {
    list.truncate(count);
    for s in list {
        clip(s, bytes);
    }
}

fn clamp_finding(f: &mut hyperion_types::SiteFileFinding) {
    clip(&mut f.rel, MAX_PATH_BYTES);
    if f.severity != "high" && f.severity != "medium" {
        f.severity = "medium".to_string();
    }
    clip_opt(&mut f.rule_id, MAX_ID_BYTES);
    clip_list(&mut f.domains, MAX_DOMAINS, MAX_NAME_BYTES);
    clip(&mut f.snippet, MAX_TEXT_BYTES);
    clip(&mut f.sha256, MAX_ID_BYTES);
    clip_opt(&mut f.component, MAX_NAME_BYTES);
    clip_opt(&mut f.source_label, MAX_ID_BYTES);
}

/// At most [`MAX_ITEMS`] issues across all of a list's components.
fn clamp_failed(list: &mut Vec<hyperion_types::WpIntegrityPluginResult>) {
    list.truncate(MAX_ITEMS);
    let mut left = MAX_ITEMS;
    for p in list.iter_mut() {
        clip(&mut p.slug, MAX_NAME_BYTES);
        p.issues.truncate(left);
        left -= p.issues.len();
        for i in &mut p.issues {
            clip(&mut i.path, MAX_PATH_BYTES);
            clip(&mut i.message, MAX_TEXT_BYTES);
        }
    }
    list.retain(|p| !p.issues.is_empty());
}

/// Bound what a reply can make the node store and show. The worker read hostile
/// files as root, so nothing about the reply is taken on trust, its size least of
/// all.
pub(super) fn clamp_scan_outcome(o: &mut SiteScanOutcome) {
    let issues = |l: &[hyperion_types::WpIntegrityPluginResult]| -> usize {
        l.iter().map(|p| p.issues.len()).sum()
    };
    let up = &mut o.upstream;
    let over = o.findings.len() > MAX_ITEMS
        || o.review.len() > MAX_ITEMS
        || up.core_modified.len() > MAX_ITEMS
        || up.core_unexpected.len() > MAX_ITEMS
        || up.core_missing.len() > MAX_ITEMS
        || issues(&up.plugins_failed) > MAX_ITEMS
        || issues(&up.themes_failed) > MAX_ITEMS;

    clip_list(&mut up.core_modified, MAX_ITEMS, MAX_PATH_BYTES);
    clip_list(&mut up.core_unexpected, MAX_ITEMS, MAX_PATH_BYTES);
    clip_list(&mut up.core_missing, MAX_ITEMS, MAX_PATH_BYTES);
    clamp_failed(&mut up.plugins_failed);
    clamp_failed(&mut up.themes_failed);
    clip_list(&mut up.plugins_unknown, MAX_COMPONENTS, MAX_NAME_BYTES);
    clip_list(&mut up.themes_unknown, MAX_COMPONENTS, MAX_NAME_BYTES);
    for list in [&mut o.findings, &mut o.review] {
        list.truncate(MAX_ITEMS);
        list.iter_mut().for_each(clamp_finding);
    }
    clip_list(&mut o.auto_accepted, MAX_AUTO_ACCEPTED, MAX_PATH_BYTES);

    let c = &mut o.coverage;
    for n in [
        &mut c.plugins_verified,
        &mut c.plugins_total,
        &mut c.themes_verified,
        &mut c.themes_total,
        &mut c.files_watched,
        &mut c.watching_since,
        &mut c.files_partly_inspected,
        &mut c.symlinks_skipped,
    ] {
        *n = (*n).max(0);
    }
    if over {
        c.partial_reasons.insert(
            0,
            "the scan's reply was over its limits and was cut".to_string(),
        );
    }
    clip_list(&mut c.partial_reasons, MAX_REASONS, MAX_REASON_BYTES);
}

/// What a purged site leaves here: its baseline and its quarantine. Neither may
/// exist. An id that could name anything but one entry of these root-owned
/// directories is refused, since one of them is removed recursively.
pub(super) async fn remove_site_scan_state(paths: &HostingPaths, hosting_id: &str) {
    if hosting_id.is_empty() || hosting_id.starts_with('.') || hosting_id.contains('/') {
        tracing::error!(hosting_id, "purge: not removing scan state for this id");
        return;
    }
    let baseline = Path::new(&paths.scan_dir)
        .join("baselines")
        .join(hosting_id);
    match tokio::fs::remove_file(&baseline).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::error!(error = %e, hosting_id, "purge: baseline not removed"),
    }
    let quarantine = Path::new(&paths.quarantine_dir).join(hosting_id);
    match tokio::fs::remove_dir_all(&quarantine).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::error!(error = %e, hosting_id, "purge: quarantine not removed"),
    }
}
