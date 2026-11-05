//! When the native site scan runs, one site at a time, and what becomes of its
//! answer.
//!
//! The tick takes the node's lock per site and asks between sites whether anyone
//! has requested a scan, so "Scan now" runs after the current site and before the
//! rest of the sweep: that is all the queue there is. ClamAV is its own sweep
//! beside it. The worker parses hostile files as root, so its reply is untrusted
//! input here, clamped before anything stores it.

use super::*;
use chrono::{Datelike, Timelike};
use hyperion_adapters::sitescan::accept::{self, WriterPaths};
use hyperion_adapters::sitescan::discover::Discovery;
use hyperion_adapters::sitescan::manifest::{ComponentKey, ComponentKind};
use hyperion_adapters::sitescan::runner::{WorkerJob, WorkerReply};
use hyperion_adapters::sitescan::scan::{
    ScanInput, ScanMode, SiteScanOutcome, WriterAccepted, WriterKind,
};
use hyperion_adapters::sitescan::vendor::{self, VendorError};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
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

/// `hosting_kv` key: unix seconds a request for this hosting was last honoured.
const SCAN_REQUEST_HONOURED_KV_KEY: &str = "scan_request_honoured_at";
/// A site's requests are honoured this far apart at most. Anyone with `WpManage`
/// can ask, a customer included, and the node has one worker.
const SCAN_REQUEST_MIN_GAP_SECS: i64 = 10 * 60;

/// `node_kv` key: unix seconds the manifest cache and the quarantine were last swept.
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

/// Vendor packages one hosting's pass may download.
const MAX_VENDOR_PER_SITE: usize = 3;
/// And all of this node together, by the clock: nothing refills it early.
const MAX_VENDOR_PER_HOUR: u32 = 10;
/// `node_kv` key: when this hour's vendor downloads began, and how many so far.
const VENDOR_BUDGET_KV: &str = "site_scan_vendor_budget";
/// `hosting_kv` key: what the last scan left for the vendor sweep.
const VENDOR_SITE_KV_KEY: &str = "scan_vendor_site";
/// A hosting's transients are looked at this often, unless a scan changed something.
const VENDOR_PASS_EVERY_SECS: i64 = 6 * HOUR_SECS;
/// Candidates kept per hosting. Folder names are the tenant's to multiply.
const MAX_VENDOR_CANDIDATES: usize = 500;
/// Packages named on the card for one scan.
const MAX_VENDOR_PACKAGES_SHOWN: usize = 50;

pub(super) const VENDOR_NO_CONFIG: &str = "wp-config.php couldn't be read here, so premium plugins and themes weren't compared with their vendors' packages";
pub(super) const VENDOR_NOT_OWN_DB: &str = "wp-config.php doesn't name a database of this site's own, so premium plugins and themes weren't compared with their vendors' packages";
pub(super) const VENDOR_NO_LOGIN: &str = "this site's own database login isn't available, so premium plugins and themes weren't compared with their vendors' packages";
pub(super) const VENDOR_DB_UNREADABLE: &str = "the site's database couldn't be read with its own login, so premium plugins and themes weren't compared with their vendors' packages";
pub(super) const VENDOR_NO_UPDATE_DATA: &str = "the site's database holds no update data (a multisite or an external object cache keeps it elsewhere, or WordPress hasn't checked yet), so premium plugins and themes weren't compared with their vendors' packages";

// What a reply may hold. An honest worker stays under these by its own limits.
const MAX_ITEMS: usize = 1000;
/// `LIST_CAP` plugins, as many themes, and core.
const MAX_COMPONENTS: usize = 10_001;
/// The worker's 20, and what the agent adds in front of them.
const MAX_REASONS: usize = 24;
const MAX_AUTO_ACCEPTED: usize = 200;
/// The trust list's own cap.
const MAX_TRUST_GONE: usize = 5000;
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
const SITE_SCAN_NOT_STORED: &str = "the scan's result could not be stored; try again shortly";
const SITE_SCAN_CUT_SHORT: &str = "the scan did not finish; part of the site was not looked at";

/// False for a hosting with no files of its own to scan. A redirect from the
/// wizard is a `static` row with a docroot, so it counts as having files.
pub(super) fn kind_has_files(kind: &str) -> bool {
    kind != "reverse_proxy"
}

// One of these is alive per site, so the size of the variants costs nothing.
/// How one site's turn with the lock ended.
#[allow(clippy::large_enum_variant)]
pub(super) enum SiteScanRun {
    Finished {
        result: hyperion_types::WpIntegrityScanResult,
        /// The worker answered. Otherwise `result` is the last run's.
        native_ran: bool,
    },
    /// A worker that survived an agent restart holds the unit. Nothing happened.
    Busy,
    /// The record couldn't be read to store into, so nothing was written over it.
    NotStored,
}

/// How one site's turn in the tick ended.
enum SiteScanTurn {
    NewFindings,
    NothingNew,
    /// Nothing ran: not due after all, gone, or nothing could be stored.
    NotRun,
    Busy,
}

/// The half of a stored record that belongs to ClamAV. A scan's store takes it as
/// it stands then, not as it stood when the scan began: a pass may have finished
/// meanwhile.
struct ClamavVerdict {
    available: bool,
    malware: Vec<hyperion_types::WpMalwareHit>,
    at: i64,
    failed_at: i64,
    error: Option<String>,
}

impl ClamavVerdict {
    fn of(record: Option<&StoredIntegrityScan>) -> Self {
        match record {
            Some(r) => Self {
                available: r.result.clamav_available,
                malware: r.result.malware.clone(),
                at: r.clamav_at,
                failed_at: r.clamav_failed_at,
                error: r.clamav_error.clone(),
            },
            None => Self {
                available: false,
                malware: Vec::new(),
                at: 0,
                failed_at: 0,
                error: None,
            },
        }
    }
}

/// `result.error` from the two halves that can each have failed.
fn record_error(native_failed: bool, clamav: Option<&str>) -> Option<String> {
    let native = native_failed.then_some(SITE_SCAN_FAILED);
    let parts: Vec<&str> = native.into_iter().chain(clamav).collect();
    (!parts.is_empty()).then(|| parts.join("; "))
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

/// What the last scan left for the vendor sweep, and what the sweep left for the
/// next scan's coverage. Kept apart from the scan record: the sweep runs outside the
/// node's lock.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct VendorSite {
    /// What wordpress.org doesn't know on this site, by the running version.
    #[serde(default)]
    pub(super) candidates: Vec<ComponentKey>,
    /// Slugs with a difference from their vendor manifest.
    #[serde(default)]
    pub(super) differing: BTreeSet<String>,
    /// Unix seconds of the last finished pass. 0 is "go ahead".
    #[serde(default)]
    pub(super) pass_at: i64,
    #[serde(default)]
    pub(super) unknown_hosts: Vec<String>,
    #[serde(default)]
    pub(super) note: Option<String>,
}

/// Why a hosting's pass stopped where it did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum VendorStop {
    #[default]
    Done,
    /// This hosting's share of one pass. It goes on next tick.
    SiteCap,
    /// This hour's downloads are spent.
    OutOfBudget,
    /// A vendor was too slow, so nothing more is tried this tick.
    TimedOut,
}

/// What one hosting's pass came to.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct VendorPass {
    pub(super) unknown_hosts: Vec<String>,
    pub(super) note: Option<String>,
    pub(super) stop: VendorStop,
    /// Keys whose manifest appeared or came into dispute: sites on them rescan.
    pub(super) changed: Vec<ComponentKey>,
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Scan the sites someone asked for, then the ones due on this node,
    /// oldest-scanned first, asking again between sites, and tell admins about
    /// what is new: a standing finding must not re-alert or the operator learns to
    /// ignore the panel. Returns the number of hostings that gained a new finding.
    ///
    /// Everything that decides "due" lives in each site's stored record, so an
    /// agent restart (every deploy is one) starts nothing by itself.
    pub async fn site_scan_tick(&self) -> Result<i64, RpcError> {
        self.site_scan_tick_at(&chrono::Local, now_secs()).await
    }

    /// Returns when someone has asked for a scan since the last call returned.
    pub async fn site_scan_wait_for_request(&self) {
        self.site_scan.wake.notified().await;
    }

    pub(super) async fn site_scan_tick_at<Tz: chrono::TimeZone>(
        &self,
        tz: &Tz,
        now: i64,
    ) -> Result<i64, RpcError> {
        self.site_scan_evict_daily(now).await;
        let started = std::time::Instant::now();
        let mut queue = self.site_scan_due_queue(tz, now).await?;
        // What this tick has answered, so a request that can't be cleared (a
        // database error) can't keep it here.
        let mut answered = HashSet::new();
        let mut newly_flagged = 0i64;
        // A request goes ahead of the schedule, but never twice running: whoever
        // is asking, every other site on the node still gets its turn.
        let mut schedule_owed = false;
        loop {
            // A sweep can outlast the window it started in. To the minute is all
            // a schedule needs.
            let now = now + i64::try_from(started.elapsed().as_secs() / 60 * 60).unwrap_or(0);
            let request = if schedule_owed && !queue.is_empty() {
                None
            } else {
                self.next_scan_request(&mut answered, now).await
            };
            let (id, requested) = match request {
                Some(id) => (id, true),
                None => match queue.pop_front() {
                    Some(id) => (id, false),
                    None => return Ok(newly_flagged),
                },
            };
            match self.site_scan_turn(&id, requested, tz, now).await {
                SiteScanTurn::NewFindings => {
                    newly_flagged += 1;
                    schedule_owed = requested;
                }
                SiteScanTurn::NothingNew => schedule_owed = requested,
                SiteScanTurn::NotRun => {}
                SiteScanTurn::Busy => {
                    tracing::debug!("site scan: another worker is running; next tick");
                    return Ok(newly_flagged);
                }
            }
        }
    }

    /// Who the schedule says is due, oldest-scanned first.
    async fn site_scan_due_queue<Tz: chrono::TimeZone>(
        &self,
        tz: &Tz,
        now: i64,
    ) -> Result<VecDeque<HostingId>, RpcError> {
        let mut due = Vec::new();
        for s in self.list().await? {
            if s.state != HostingState::Active || !kind_has_files(s.kind.as_deref().unwrap_or("")) {
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
                due.push((prior.map_or(0, |p| p.scanned_at), s.id));
            }
        }
        due.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.as_str().cmp(b.1.as_str())));
        Ok(due.into_iter().map(|(_, id)| id).collect())
    }

    /// The longest-waiting request this tick hasn't answered yet, among sites not
    /// honoured in the last ten minutes. The rest stay queued for a later tick.
    async fn next_scan_request(
        &self,
        answered: &mut HashSet<(String, String)>,
        now: i64,
    ) -> Option<HostingId> {
        let read = |key: &'static str| hyperion_state::hosting_kv::list_by_key(&self.pool, key);
        let (requests, honoured) = match (
            read(SCAN_REQUESTED_KV_KEY).await,
            read(SCAN_REQUEST_HONOURED_KV_KEY).await,
        ) {
            (Ok(r), Ok(h)) => (r, h),
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!(error = %e, "site scan: requests unreadable");
                return None;
            }
        };
        let too_soon = |id: &str| {
            honoured
                .iter()
                .find(|(h, _)| h == id)
                .and_then(|(_, at)| at.trim().parse::<i64>().ok())
                .is_some_and(|at| !stamped_ahead(at, now) && now - at < SCAN_REQUEST_MIN_GAP_SECS)
        };
        let next = requests
            .into_iter()
            .filter(|r| !answered.contains(r) && !too_soon(&r.0))
            .min_by_key(|(_, at)| at.trim().parse::<i64>().unwrap_or(0))?;
        let id = HostingId(next.0.clone());
        answered.insert(next);
        Some(id)
    }

    fn accepted_path(&self, hosting_id: &str) -> PathBuf {
        Path::new(&self.paths.scan_dir)
            .join("accepted")
            .join(hosting_id)
    }

    /// What a writer of ours left for this site, if anything is pending.
    async fn scan_accepted(
        &self,
        hosting_id: &str,
        now: i64,
    ) -> Option<(WriterAccepted, accept::Stamp)> {
        let path = self.accepted_path(hosting_id);
        let loaded = tokio::task::spawn_blocking(move || accept::load_accepted(&path, now))
            .await
            .ok()?;
        match loaded {
            accept::Loaded::Found(accepted, stamp) => Some((accepted, stamp)),
            accept::Loaded::Nothing => None,
        }
    }

    /// What Hyperion's per-site mail module should be on this site: rendered
    /// from the same inputs the install tick uses, so the scan can compare the
    /// file with it instead of taking it on trust.
    ///
    /// Only for a site the install tick looks after: one that is active and has the
    /// auto-configure switch on. Otherwise its file is whatever an older release
    /// wrote and nothing will bring it up to date, so a comparison would raise a
    /// finding that means nothing; the rules still run on it.
    pub(super) async fn scan_own_expected(
        &self,
        detail: &HostingDetail,
    ) -> BTreeMap<String, [u8; 32]> {
        use hyperion_adapters::{wpmail, wpplugin};
        let id = detail.id.as_str();
        if detail.state != HostingState::Active || !self.wp_mail_autofix_enabled(id).await {
            return BTreeMap::new();
        }
        let from = self.wp_mail_from_address(id, &detail.domain).await;
        let (policy, _) = self.wp_mail_policy(id).await;
        let log = wpmail::failure_log_path(detail.root_dir.trim())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let body = wpmail::render_mu_plugin(&detail.domain, &from, &log, policy);
        BTreeMap::from([(
            wpplugin::module_rel(wpplugin::Module::Mail),
            wpplugin::expected_digest(&body),
        )])
    }

    /// A writer of ours has finished changing the site's files. Call it LAST, after
    /// whatever else the action does: the hashing is detached, in the worker's own
    /// unit so it doesn't wait behind a scan, and this returns at once. The handle
    /// is for tests.
    ///
    /// `paths` is what the writer wrote, and only a writer that replaces the whole
    /// tree may say `All`. `None`, a list with no code in it that fits, a failed
    /// hash or a site that isn't scanned record no list: the scan then reviews the
    /// changes like any others. The scan is queued either way, except for a site
    /// that isn't scanned, which is left alone.
    pub(super) async fn scan_writer_done(
        &self,
        detail: &HostingDetail,
        kind: WriterKind,
        paths: Option<WriterPaths>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let id = detail.id.as_str();
        if !kind_has_files(&detail.kind) || !self.integrity_scan_enabled(id).await {
            return None;
        }
        // Code types only, and a list too big to send is no list.
        let paths = match paths {
            Some(WriterPaths::List(names)) => accept::code_names(names).map(WriterPaths::List),
            other => other,
        };
        let Some(paths) = paths else {
            tracing::debug!(domain = %detail.domain, "site scan: no list for this writer");
            self.request_rescan(id).await;
            return None;
        };
        let job = WorkerJob::WriterHash {
            root: PathBuf::from(&detail.root_dir),
            kind,
            paths,
            out: self.accepted_path(id),
        };
        let (adapters, pool, shared) = (
            self.adapters.clone(),
            self.pool.clone(),
            self.site_scan.clone(),
        );
        let (id, domain) = (id.to_string(), detail.domain.clone());
        Some(tokio::spawn(async move {
            match adapters.site_scan_worker(job).await {
                WorkerReply::Hashed { listed, partial } => {
                    tracing::debug!(%domain, listed, partial, "site scan: writer's files hashed");
                }
                other => tracing::warn!(
                    %domain, why = ?other,
                    "site scan: the writer's files were not hashed; its changes get reviewed"
                ),
            }
            super::scan_actions::request_rescan_in(&pool, &shared, &id).await;
        }))
    }

    /// The value of this hosting's request, if one stands.
    pub(super) async fn scan_request_flag(&self, hosting_id: &str) -> Option<String> {
        hyperion_state::hosting_kv::get(&self.pool, hosting_id, SCAN_REQUESTED_KV_KEY)
            .await
            .ok()
            .flatten()
    }

    #[cfg(test)]
    pub(super) async fn vendor_site_for_test(&self, hosting_id: &str) -> VendorSite {
        self.vendor_site(hosting_id).await.unwrap_or_default()
    }

    #[cfg(test)]
    pub(super) async fn clear_scan_request_for_test(&self, hosting_id: &str) {
        self.clear_scan_request(hosting_id).await;
    }

    async fn clear_scan_request(&self, hosting_id: &str) {
        if let Err(e) =
            hyperion_state::hosting_kv::delete(&self.pool, hosting_id, SCAN_REQUESTED_KV_KEY).await
        {
            tracing::warn!(error = %e, "site scan: request not cleared");
        }
    }

    /// One site's turn: its scan under the node's lock, the alert after it.
    async fn site_scan_turn<Tz: chrono::TimeZone>(
        &self,
        id: &HostingId,
        requested: bool,
        tz: &Tz,
        now: i64,
    ) -> SiteScanTurn {
        let gate = self.site_scan.node.lock().await;
        // Read before the run: a request made during it is about what's on disk
        // by then, which the run may already have passed.
        let request = self.scan_request_flag(id.as_str()).await;
        // Asked again under the lock: "Scan now" may have got here first.
        let Ok(prior) = self.integrity_record(id.as_str()).await else {
            return SiteScanTurn::NotRun;
        };
        let mode = if requested {
            Some(ScanMode::Delta)
        } else {
            site_scan_due(prior.as_ref(), now, tz, id.as_str())
        };
        let Some(mode) = mode else {
            return SiteScanTurn::NotRun;
        };
        let detail = match self.get(HostingSelector::Id(id.clone())).await {
            Ok(d) if d.state == HostingState::Active && kind_has_files(&d.kind) => d,
            // Nothing will scan it, so nothing should wait for that.
            _ => {
                self.clear_scan_request(id.as_str()).await;
                return SiteScanTurn::NotRun;
            }
        };
        let scan = match self
            .site_scan_locked(&detail, mode, prior.as_ref(), now)
            .await
        {
            SiteScanRun::Finished { result, .. } => result,
            SiteScanRun::Busy => return SiteScanTurn::Busy,
            // No alert either: with nothing stored, the next run would send it
            // again. The request stands.
            SiteScanRun::NotStored => return SiteScanTurn::NotRun,
        };
        if requested {
            if let Err(e) = hyperion_state::hosting_kv::set(
                &self.pool,
                id.as_str(),
                SCAN_REQUEST_HONOURED_KV_KEY,
                &now.to_string(),
                now,
            )
            .await
            {
                tracing::warn!(error = %e, "site scan: request stamp not written");
            }
        }
        if request.is_some() && self.scan_request_flag(id.as_str()).await == request {
            self.clear_scan_request(id.as_str()).await;
        }
        drop(gate);

        // ClamAV's hits are its own sweep's to tell. The new layers speak only
        // once they are live; until then their keys are stored and stay quiet.
        let plan = plan_integrity_alert(prior.as_ref().map(|p| &p.result), &scan);
        if plan.is_empty() {
            return SiteScanTurn::NothingNew;
        }
        if plan.findings > 0 {
            self.notify_integrity_findings(&detail.domain, &scan, plan.findings, plan.error)
                .await;
        }
        if plan.review > 0 {
            self.notify_integrity_review(&detail.domain, &scan, plan.review)
                .await;
        }
        SiteScanTurn::NewFindings
    }

    /// `error`: the new findings include something worse than a missing core file.
    async fn notify_integrity_findings(
        &self,
        domain: &str,
        scan: &hyperion_types::WpIntegrityScanResult,
        new_keys: usize,
        error: bool,
    ) {
        // A modified core file, a tampered plugin or a signature hit is a
        // suspected compromise. A merely *missing* core file is usually a
        // botched update: still worth saying, not worth waking someone up
        // for.
        let compromised = error
            || !scan.malware.is_empty()
            || !scan.core_modified.is_empty()
            || !scan.core_unexpected.is_empty()
            || !scan.plugins_failed.is_empty();
        // The new layers are counted only once they count for anything.
        let (themes, rules) = if scan.is_live() {
            (scan.theme_issue_count(), scan.listed_findings().count())
        } else {
            (0, 0)
        };
        self.notify_admins_say(
            if compromised { "error" } else { "warn" },
            "ops.integrity",
            &[
                ("domain", domain),
                ("core", &scan.core_issue_count().to_string()),
                ("plugins", &(scan.plugin_issue_count() + themes).to_string()),
                ("malware", &scan.malware.len().to_string()),
                ("rules", &rules.to_string()),
                ("new", &new_keys.to_string()),
            ],
            &format!("/hostings/{domain}#wordpress"),
            &format!("wp.integrity:{domain}"),
        )
        .await;
    }

    /// Changes to review, batched: one warning for the site, however many.
    async fn notify_integrity_review(
        &self,
        domain: &str,
        scan: &hyperion_types::WpIntegrityScanResult,
        new_keys: usize,
    ) {
        self.notify_admins_say(
            "warn",
            "ops.integrity_review",
            &[
                ("domain", domain),
                (
                    "review",
                    &scan
                        .review
                        .iter()
                        .filter(|f| f.held_vendor_note().is_none())
                        .count()
                        .to_string(),
                ),
                ("new", &new_keys.to_string()),
            ],
            &format!("/hostings/{domain}#wordpress"),
            &format!("wp.integrity.review:{domain}"),
        )
        .await;
    }

    /// ClamAV over the sites this node scans, one at a time, longest-waiting
    /// first, so a site whose pass keeps failing doesn't keep the sweep to itself.
    /// Sites with no release to compare with aren't part of it, and neither is a
    /// site nothing is known about yet. Returns the number of hostings with a new
    /// hit.
    pub async fn site_scan_clamav_tick(&self) -> Result<i64, RpcError> {
        self.site_scan_clamav_tick_at(now_secs()).await
    }

    pub(super) async fn site_scan_clamav_tick_at(&self, now: i64) -> Result<i64, RpcError> {
        let started = std::time::Instant::now();
        let mut sites = Vec::new();
        for s in self.list().await? {
            if s.state != HostingState::Active
                || !kind_has_files(s.kind.as_deref().unwrap_or(""))
                || !self.integrity_scan_enabled(s.id.as_str()).await
            {
                continue;
            }
            let Some(rec) = self.stored_integrity_scan(s.id.as_str()).await else {
                continue;
            };
            let known = rec.result.native_scan_ran || rec.failed_at > 0;
            if known && !rec.result.coverage.no_upstream {
                sites.push((rec.clamav_at.max(rec.clamav_failed_at), s.id));
            }
        }
        sites.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.as_str().cmp(b.1.as_str())));

        let mut newly_flagged = 0i64;
        for (_, id) in sites {
            let Ok(detail) = self.get(HostingSelector::Id(id)).await else {
                continue;
            };
            // Passes take hours, so the clock has to keep up with them.
            let now = now + i64::try_from(started.elapsed().as_secs()).unwrap_or(0);
            let Ok(prior) = self.integrity_record(detail.id.as_str()).await else {
                continue;
            };
            // ClamAV's keys only. A pass can take hours, and a scan storing its
            // own finding meanwhile has already said so.
            let before = prior
                .map(|p| malware_finding_keys(&p.result))
                .unwrap_or_default();
            let Some((after, _)) = self.site_scan_clamav_pass(&detail, now).await else {
                continue;
            };
            let new_keys = malware_finding_keys(&after).difference(&before).count();
            if new_keys > 0 {
                newly_flagged += 1;
                self.notify_integrity_findings(&detail.domain, &after, new_keys, false)
                    .await;
            }
        }
        Ok(newly_flagged)
    }

    /// One ClamAV pass and its half of the record. Says whether it actually ran
    /// now. A pass held off rewrites nothing, so asking every ten minutes is cheap.
    ///
    /// `None` when the record couldn't be read, and then nothing is written: a
    /// failed read isn't an empty record, and the scan's half would be lost.
    pub(super) async fn site_scan_clamav_pass(
        &self,
        detail: &HostingDetail,
        now: i64,
    ) -> Option<(hyperion_types::WpIntegrityScanResult, bool)> {
        let prior = match self.integrity_record(detail.id.as_str()).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e, "clamav: record unreadable");
                return None;
            }
        };
        let mut errors: Vec<String> = Vec::new();
        let (available, malware, at, failed_at) = self
            .integrity_malware_pass(detail, now, prior.as_ref(), &mut errors)
            .await;
        let ran_now = available && at == now;
        let error = (!errors.is_empty()).then(|| errors.join("; "));

        let _record = self.site_scan.record.lock().await;
        let mut rec = match self.integrity_record(detail.id.as_str()).await {
            Ok(r) => r.unwrap_or_default(),
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e, "clamav: record unreadable");
                return None;
            }
        };
        let changed = rec.result.clamav_available != available
            || rec.result.malware != malware
            || rec.clamav_at != at
            || rec.clamav_failed_at != failed_at
            || rec.clamav_error != error;
        rec.result.clamav_available = available;
        rec.result.malware = malware;
        rec.clamav_at = at;
        rec.clamav_failed_at = failed_at;
        rec.clamav_error = error;
        rec.result.error = record_error(rec.failed_at > 0, rec.clamav_error.as_deref());
        rec.result.clamav_installed = integrity::clamav_available();
        if changed {
            self.set_stored_integrity_scan(detail.id.as_str(), &rec)
                .await;
        }
        Some((rec.result, ran_now))
    }

    /// Scan one site and store the result. The caller holds the node's lock.
    pub(super) async fn site_scan_locked(
        &self,
        detail: &HostingDetail,
        mode: ScanMode,
        prior: Option<&StoredIntegrityScan>,
        now: i64,
    ) -> SiteScanRun {
        // Read before the scan starts: a writer that finishes meanwhile leaves a
        // newer list, which this scan hasn't seen and which stays.
        let accepted = self.scan_accepted(detail.id.as_str(), now).await;
        let outcome = match self
            .native_site_scan(detail, mode, now, accepted.as_ref().map(|(a, _)| a.clone()))
            .await
        {
            NativeScan::Busy => return SiteScanRun::Busy,
            NativeScan::Failed => None,
            NativeScan::Ran(outcome) => Some(outcome),
        };
        // Spent only by a scan that looked at everything: a stopped one never saw
        // part of what the writer left.
        let complete = outcome.as_ref().is_some_and(|o| !o.stopped && !o.capped);
        let native_ran = outcome.is_some();
        let report_only = !self.site_scan_new_layers_live();
        let auto_accepted = outcome
            .as_ref()
            .map(|o| o.auto_accepted.clone())
            .unwrap_or_default();
        // What this run itself said, before the last run's standing items join it.
        let (reported, trust_gone) = outcome.as_ref().map_or_else(Default::default, |o| {
            let reported: Vec<(String, String)> = o
                .findings
                .iter()
                .chain(&o.review)
                .map(|f| (f.rel.clone(), f.sha256.clone()))
                .collect();
            (reported, o.trust_gone.clone())
        });

        // Before anything can go wrong below: the worker has accepted these.
        if !auto_accepted.is_empty() {
            self.append_audit(
                "wp.integrity.auto_accept",
                Some(detail.id.as_str()),
                &serde_json::json!({ "files": auto_accepted }).to_string(),
                "ok",
            )
            .await;
        }

        let record_lock = self.site_scan.record.lock().await;
        let current = match self.integrity_record(detail.id.as_str()).await {
            Ok(c) => c,
            // A failed read isn't an empty record: ClamAV's list would be lost.
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e, "site scan: record unreadable");
                return SiteScanRun::NotStored;
            }
        };
        let clamav = ClamavVerdict::of(current.as_ref());
        let stored = match outcome {
            Some(outcome) => stored_from_outcome(outcome, prior, clamav, mode, now, report_only),
            None => stored_after_failure(prior, clamav, now),
        };
        self.set_stored_integrity_scan(detail.id.as_str(), &stored)
            .await;
        self.prune_scan_trust(detail.id.as_str(), &reported, &trust_gone)
            .await;
        drop(record_lock);
        if let (Some((_, stamp)), true) = (accepted, complete) {
            accept::spend_accepted(&self.accepted_path(detail.id.as_str()), &stamp);
        }

        let r = &stored.result;
        self.append_audit(
            "wp.integrity.scan",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "core_issues": r.core_issue_count(),
                "plugin_issues": r.plugin_issue_count(),
                "findings": r.findings.len(),
                "review": r.review.len(),
                "upstream": r.wp_cli_ok,
                "native": native_ran,
            })
            .to_string(),
            if native_ran { "ok" } else { "failed" },
        )
        .await;
        SiteScanRun::Finished {
            result: stored.result,
            native_ran,
        }
    }

    /// Discover in the worker, fetch here (the worker has no network), scan in
    /// the worker.
    async fn native_site_scan(
        &self,
        detail: &HostingDetail,
        mode: ScanMode,
        now: i64,
        accepted: Option<WriterAccepted>,
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
        let candidates = pass
            .known_slugs
            .as_ref()
            .map(|known| vendor::vendor_candidates(&discovery, known));
        let job = WorkerJob::Scan(ScanInput {
            root,
            discovery,
            manifests_dir,
            baseline_path: scan_dir.join("baselines").join(detail.id.as_str()),
            mode,
            now,
            wporg_known_slugs: pass.known_slugs,
            accepted,
            own_expected: self.scan_own_expected(detail).await,
            own_files_since: self.site_scan.started_at,
            trusted: self.scan_trust_map(detail.id.as_str()).await,
        });
        let mut outcome = match self.adapters.site_scan_worker(job).await {
            WorkerReply::Scan(o) => o,
            other => return self.scan_not_answered(detail, other),
        };
        // In front, so the cap below can't lose them to the worker's own.
        let mut reasons = pass.reasons;
        reasons.append(&mut outcome.coverage.partial_reasons);
        outcome.coverage.partial_reasons = reasons;
        hold_vendor_differences(&mut outcome, self.site_scan_vendor_refs_live());
        let site = self
            .vendor_site_after_scan(detail, candidates, &outcome, now)
            .await;
        // The worker has no say in these: it never saw any of this.
        outcome.coverage.unknown_vendor_hosts = site.unknown_hosts.clone();
        outcome.coverage.vendor_note = site.note.clone();
        outcome.coverage.vendor_packages =
            vendor_packages_behind(&outcome, &site, &self.vendor_cache_dir()).await;
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

    fn vendor_cache_dir(&self) -> PathBuf {
        Path::new(&self.paths.scan_dir).join("manifests")
    }

    /// What this scan means for the vendor sweep. A candidate list or a difference
    /// that's new goes ahead of the sweep's six hours. Without a word on what
    /// wordpress.org knows, the last list stands.
    async fn vendor_site_after_scan(
        &self,
        detail: &HostingDetail,
        candidates: Option<Vec<ComponentKey>>,
        outcome: &SiteScanOutcome,
        now: i64,
    ) -> VendorSite {
        let id = detail.id.as_str();
        let _record = self.site_scan.record.lock().await;
        let mut site = self.vendor_site(id).await.unwrap_or_default();
        let before = site.clone();
        if let Some(mut c) = candidates {
            c.truncate(MAX_VENDOR_CANDIDATES);
            site.candidates = c;
        }
        site.differing = vendor_differing_slugs(outcome);
        if site.candidates != before.candidates || !site.differing.is_subset(&before.differing) {
            site.pass_at = 0;
        }
        if site != before {
            self.put_vendor_site(id, &site, now).await;
        }
        site
    }

    async fn vendor_site(&self, hosting_id: &str) -> Option<VendorSite> {
        let raw = hyperion_state::hosting_kv::get(&self.pool, hosting_id, VENDOR_SITE_KV_KEY)
            .await
            .ok()
            .flatten()?;
        serde_json::from_str(&raw).ok()
    }

    async fn put_vendor_site(&self, hosting_id: &str, site: &VendorSite, now: i64) {
        let Ok(raw) = serde_json::to_string(site) else {
            return;
        };
        if let Err(e) =
            hyperion_state::hosting_kv::set(&self.pool, hosting_id, VENDOR_SITE_KV_KEY, &raw, now)
                .await
        {
            tracing::warn!(error = %e, "site scan: vendor state not stored");
        }
    }

    /// Premium plugins' reference copies, beside the site scan rather than in it: a
    /// vendor can take minutes per package, and a "Scan now" must not wait behind
    /// one. Works from what each hosting's last scan left, one at a time. A manifest
    /// that appears asks for a scan of every site on that version.
    pub async fn site_scan_vendor_tick(&self) -> Result<(), RpcError> {
        self.site_scan_vendor_tick_at(now_secs()).await
    }

    pub(super) async fn site_scan_vendor_tick_at(&self, now: i64) -> Result<(), RpcError> {
        let rows = hyperion_state::hosting_kv::list_by_key(&self.pool, VENDOR_SITE_KV_KEY)
            .await
            .map_err(|e| RpcError::Internal_with(format!("vendor sites: {e}")))?;
        let cache_dir = self.vendor_cache_dir();
        for (id, raw) in rows {
            let Ok(site) = serde_json::from_str::<VendorSite>(&raw) else {
                continue;
            };
            let recent = site.pass_at > 0
                && !stamped_ahead(site.pass_at, now)
                && now - site.pass_at < VENDOR_PASS_EVERY_SECS;
            if site.candidates.is_empty() || recent {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(HostingId(id.clone()))).await else {
                continue;
            };
            if detail.state != HostingState::Active
                || !kind_has_files(&detail.kind)
                || !self.integrity_scan_enabled(&id).await
            {
                continue;
            }
            let pass = self
                .site_scan_vendor_pass(&detail, &site, &cache_dir, now)
                .await;
            self.vendor_pass_done(&id, &site, &pass, now).await;
            for key in &pass.changed {
                self.rescan_sites_on(key).await;
            }
            // Not again until the clock says, or the slow vendor has had a rest.
            if matches!(pass.stop, VendorStop::OutOfBudget | VendorStop::TimedOut) {
                break;
            }
        }
        Ok(())
    }

    /// Store what a pass said, over whatever a scan stored meanwhile. Cut short by a
    /// budget, it's still due, and so is one that a scan has since given more to do.
    async fn vendor_pass_done(
        &self,
        hosting_id: &str,
        asked: &VendorSite,
        pass: &VendorPass,
        now: i64,
    ) {
        let _record = self.site_scan.record.lock().await;
        let mut site = self.vendor_site(hosting_id).await.unwrap_or_default();
        site.unknown_hosts.clone_from(&pass.unknown_hosts);
        site.note.clone_from(&pass.note);
        let same_work = site.candidates == asked.candidates && site.differing == asked.differing;
        if same_work && matches!(pass.stop, VendorStop::Done | VendorStop::TimedOut) {
            site.pass_at = now;
        }
        self.put_vendor_site(hosting_id, &site, now).await;
    }

    /// Ask for a scan of every hosting running this slug and version.
    pub(super) async fn rescan_sites_on(&self, key: &ComponentKey) {
        let Ok(rows) =
            hyperion_state::hosting_kv::list_by_key(&self.pool, VENDOR_SITE_KV_KEY).await
        else {
            return;
        };
        for (id, raw) in rows {
            let on_it = serde_json::from_str::<VendorSite>(&raw)
                .is_ok_and(|site| site.candidates.contains(key));
            if on_it {
                self.request_rescan(&id).await;
            }
        }
    }

    /// One hosting's try at a reference for what wordpress.org doesn't know, from
    /// the package links WordPress holds. What this can't do leaves those components
    /// on the baseline, and says why on this site's card alone.
    ///
    /// `wp-config.php` can name anyone's database, so the name counts only if it's
    /// one this hosting owns, and even then it's read with that hosting's login.
    pub(super) async fn site_scan_vendor_pass(
        &self,
        detail: &HostingDetail,
        site: &VendorSite,
        cache_dir: &Path,
        now: i64,
    ) -> VendorPass {
        let refused = |why: &str| VendorPass {
            note: Some(why.to_string()),
            ..Default::default()
        };
        let logins = match databases::mariadb_logins_for_hosting(&self.pool, &detail.id).await {
            Ok(own) if !own.is_empty() => own,
            Ok(_) => return refused(VENDOR_NOT_OWN_DB),
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e, "site scan: databases unreadable");
                return refused(VENDOR_DB_UNREADABLE);
            }
        };
        let Some((db, prefix)) = self
            .adapters
            .site_scan_wp_config_db(Path::new(&detail.root_dir))
            .await
        else {
            return refused(VENDOR_NO_CONFIG);
        };
        let Some((_, user, secret_id)) = logins.iter().find(|(name, _, _)| *name == db) else {
            return refused(VENDOR_NOT_OWN_DB);
        };
        let secret: Option<serde_json::Value> = self.secrets.get(secret_id).await.ok();
        let Some(password) = secret
            .as_ref()
            .and_then(|s| s.get("password"))
            .and_then(|p| p.as_str())
        else {
            return refused(VENDOR_NO_LOGIN);
        };

        let mut refs = Vec::new();
        let mut any_row = false;
        for (option, kind) in [
            (
                hyperion_adapters::mariadb::UPDATE_PLUGINS_OPTION,
                ComponentKind::Plugin,
            ),
            (
                hyperion_adapters::mariadb::UPDATE_THEMES_OPTION,
                ComponentKind::Theme,
            ),
        ] {
            match self
                .adapters
                .site_scan_read_option(&db, &prefix, option, user, password)
                .await
            {
                Ok(Some(value)) => {
                    any_row = true;
                    refs.extend(vendor::parse_update_transient(&value, kind));
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!(domain = %detail.domain, error = %e, "site scan: option unreadable");
                    return refused(VENDOR_DB_UNREADABLE);
                }
            }
        }
        if !any_row {
            return refused(VENDOR_NO_UPDATE_DATA);
        }

        let (candidates, differing) = (site.candidates.clone(), site.differing.clone());
        let (dir, hosting) = (cache_dir.to_path_buf(), detail.id.as_str().to_string());
        let plan = tokio::task::spawn_blocking(move || {
            let at = std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(u64::try_from(now).unwrap_or(0));
            vendor::plan_downloads(refs, &candidates, &differing, &hosting, &dir, at)
        })
        .await
        .unwrap_or_default();

        let mut pass = VendorPass::default();
        let mut hosts: BTreeSet<String> = plan.unknown_hosts.into_iter().collect();
        for (done, package) in plan.fetch.iter().enumerate() {
            if done >= MAX_VENDOR_PER_SITE {
                pass.stop = VendorStop::SiteCap;
                break;
            }
            if !self.take_vendor_download(now).await {
                tracing::debug!("site scan: this hour's vendor downloads are spent");
                pass.stop = VendorStop::OutOfBudget;
                break;
            }
            let key = ComponentKey {
                kind: package.kind,
                slug: package.slug.clone(),
                version: package.version.clone(),
                locale: None,
            };
            match self
                .adapters
                .site_scan_vendor_fetch(package, detail.id.as_str(), cache_dir)
                .await
            {
                Ok(vendor::VendorFetched::New | vendor::VendorFetched::Disputed) => {
                    pass.changed.push(key);
                }
                Ok(vendor::VendorFetched::Confirmed) => {}
                // A vendor's redirect to somewhere nobody listed.
                Err(VendorError::UnknownHost(host)) => {
                    hosts.insert(host);
                }
                Err(VendorError::TimedOut) => {
                    pass.stop = VendorStop::TimedOut;
                    break;
                }
                Err(e) => {
                    tracing::debug!(domain = %detail.domain, error = %e, "site scan: vendor package failed");
                }
            }
        }
        for host in &hosts {
            tracing::info!(domain = %detail.domain, %host, "site scan: package URL on a host not on the vendor list");
        }
        pass.unknown_hosts = hosts.into_iter().take(vendor::MAX_UNKNOWN_HOSTS).collect();
        pass
    }

    /// One download from this hour's ten, stamped in `node_kv` so neither a wake nor
    /// a restart hands out more. If that can't be read or written, none.
    async fn take_vendor_download(&self, now: i64) -> bool {
        let stored = match hyperion_state::node_kv::get(&self.pool, VENDOR_BUDGET_KV).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "site scan: vendor budget unreadable");
                return false;
            }
        };
        let (mut start, mut spent) = stored
            .as_deref()
            .and_then(|v| v.split_once(' '))
            .and_then(|(s, n)| Some((s.parse::<i64>().ok()?, n.parse::<u32>().ok()?)))
            .unwrap_or((now, 0));
        if stamped_ahead(start, now) || now - start >= HOUR_SECS {
            (start, spent) = (now, 0);
        }
        if spent >= MAX_VENDOR_PER_HOUR {
            return false;
        }
        let next = format!("{start} {}", spent + 1);
        if let Err(e) = hyperion_state::node_kv::set(&self.pool, VENDOR_BUDGET_KV, &next, now).await
        {
            tracing::warn!(error = %e, "site scan: vendor budget not stored");
            return false;
        }
        true
    }

    /// Sweep the manifest cache, under the lock so never beneath a running worker,
    /// and the quarantine, once a day. Stamped in `node_kv` so a restart doesn't
    /// repeat it.
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
        self.site_scan_purge_quarantine(now).await;
        let accepted = Path::new(&self.paths.scan_dir).join("accepted");
        let _ = tokio::task::spawn_blocking(move || accept::purge_expired(&accepted, now)).await;
        let _gate = self.site_scan.node.lock().await;
        let dir = Path::new(&self.paths.scan_dir).join("manifests");
        self.adapters.site_scan_evict_manifests(&dir).await;
    }

    /// Held files go 90 days after they came in. Root's own tree, nothing of a
    /// tenant's, so this doesn't wait for anything.
    async fn site_scan_purge_quarantine(&self, now: i64) {
        let base = PathBuf::from(&self.paths.quarantine_dir);
        let removed = tokio::task::spawn_blocking(move || {
            hyperion_adapters::sitescan::quarantine::purge_quarantine(&base, now)
        })
        .await
        .unwrap_or(0);
        if removed > 0 {
            tracing::info!(removed, "site scan: purged old quarantined files");
        }
    }
}

/// Where a difference from a vendor's package isn't yet to be believed, it's a change
/// to review with no alert behind it: through the pilot, and for a version whose
/// packages disagree. A rule hit is the rule's own and stays a finding either way.
pub(super) fn hold_vendor_differences(o: &mut SiteScanOutcome, live: bool) {
    let held = |label: Option<&str>| match label {
        Some(hyperion_types::PACKAGES_DISAGREE_LABEL) => true,
        Some(hyperion_types::VENDOR_PACKAGE_LABEL) => !live,
        _ => false,
    };
    o.upstream
        .plugins_failed
        .retain(|p| !held(p.source.as_deref()));
    o.upstream
        .themes_failed
        .retain(|p| !held(p.source.as_deref()));
    let (mut moved, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut o.findings)
        .into_iter()
        .partition(|f| f.is_comparison() && f.rule_id.is_none() && held(f.source_label.as_deref()));
    o.findings = kept;
    for f in &mut moved {
        f.severity = "medium".to_string();
    }
    o.review.append(&mut moved);
}

/// Slugs this scan found different from their vendor's package. Not those already
/// disputed: there's nothing more a comparison could settle.
fn vendor_differing_slugs(o: &SiteScanOutcome) -> BTreeSet<String> {
    o.findings
        .iter()
        .chain(&o.review)
        .filter(|f| {
            f.is_comparison()
                && f.source_label.as_deref() == Some(hyperion_types::VENDOR_PACKAGE_LABEL)
        })
        .filter_map(|f| f.component.clone())
        .collect()
}

/// Where the manifests behind this scan's vendor differences came from.
async fn vendor_packages_behind(
    o: &SiteScanOutcome,
    site: &VendorSite,
    cache_dir: &Path,
) -> Vec<hyperion_types::VendorPackageInfo> {
    let slugs: BTreeSet<&str> = o
        .findings
        .iter()
        .chain(&o.review)
        .filter(|f| {
            f.is_comparison()
                && matches!(
                    f.source_label.as_deref(),
                    Some(hyperion_types::VENDOR_PACKAGE_LABEL)
                        | Some(hyperion_types::PACKAGES_DISAGREE_LABEL)
                )
        })
        .filter_map(|f| f.component.as_deref())
        .collect();
    let keys: Vec<ComponentKey> = site
        .candidates
        .iter()
        .filter(|k| slugs.contains(k.slug.as_str()))
        .take(MAX_VENDOR_PACKAGES_SHOWN)
        .cloned()
        .collect();
    if keys.is_empty() {
        return Vec::new();
    }
    let dir = cache_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        keys.iter()
            .filter_map(|k| vendor::package_info(&dir, k))
            .collect()
    })
    .await
    .unwrap_or_default()
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

/// The record a finished run leaves.
fn stored_from_outcome(
    mut outcome: SiteScanOutcome,
    prior: Option<&StoredIntegrityScan>,
    clamav: ClamavVerdict,
    mode: ScanMode,
    now: i64,
    report_only: bool,
) -> StoredIntegrityScan {
    let stopped = outcome.stopped;
    let capped = outcome.capped;
    let themes_unknown = std::mem::take(&mut outcome.upstream.themes_unknown);
    let mut result =
        assemble_integrity_result(outcome, clamav.malware, clamav.available, report_only);
    if let Some(p) = prior {
        carry_standing_findings(&mut result, &p.result, stopped || capped, &themes_unknown);
    }
    result.scanned_at = now;
    result.clamav_installed = integrity::clamav_available();
    result.error = record_error(false, clamav.error.as_deref());
    let first_scan = prior.map_or(true, |p| !p.result.native_scan_ran);
    let read_everything = !stopped && (mode == ScanMode::FullRehash || first_scan);
    StoredIntegrityScan {
        scanned_at: now,
        clamav_at: clamav.at,
        clamav_failed_at: clamav.failed_at,
        clamav_error: clamav.error,
        full_at: if read_everything {
            now
        } else {
            prior.map_or(0, |p| p.full_at)
        },
        failed_at: 0,
        stopped,
        result,
    }
}

/// The record a run that gave no answer leaves. What the last run found is still
/// the best anyone knows, and an empty list here would read as "those went away".
/// The record's clock stays where it was: this run proved nothing.
fn stored_after_failure(
    prior: Option<&StoredIntegrityScan>,
    clamav: ClamavVerdict,
    now: i64,
) -> StoredIntegrityScan {
    let mut result = prior.map_or_else(Default::default, |p| p.result.clone());
    result.malware = clamav.malware;
    result.clamav_available = clamav.available;
    result.clamav_installed = integrity::clamav_available();
    result.error = record_error(true, clamav.error.as_deref());
    if prior.is_none() {
        result.scanned_at = now;
    }
    StoredIntegrityScan {
        scanned_at: prior.map_or(now, |p| p.scanned_at),
        clamav_at: clamav.at,
        clamav_failed_at: clamav.failed_at,
        clamav_error: clamav.error,
        full_at: prior.map_or(0, |p| p.full_at),
        failed_at: now,
        stopped: prior.is_some_and(|p| p.stopped),
        result,
    }
}

/// [`integrity_finding_keys`] with ClamAV's alone.
fn malware_finding_keys(
    r: &hyperion_types::WpIntegrityScanResult,
) -> std::collections::HashSet<String> {
    let mut keys = legacy_finding_keys(r);
    keys.retain(|k| k.starts_with("malware:"));
    keys
}

/// The stored result as the caller of a scan that didn't run should read it: the
/// findings are the last run's, nothing was verified just now, and a ClamAV
/// verdict carried from an earlier pass isn't this scan's.
pub(super) fn scan_did_not_run(
    mut result: hyperion_types::WpIntegrityScanResult,
    clamav_ran_now: bool,
) -> hyperion_types::WpIntegrityScanResult {
    result.wp_cli_ok = false;
    result.core_ok = false;
    result.native_scan_ran = false;
    result.clamav_available = clamav_ran_now;
    result
}

/// The answer to a blocking scan that has nothing new to say.
fn scan_unanswered(
    prior: Option<StoredIntegrityScan>,
    why: &str,
) -> hyperion_types::WpIntegrityScanResult {
    let mut result = scan_did_not_run(prior.map(|p| p.result).unwrap_or_default(), false);
    result.error = Some(why.to_string());
    result.clamav_installed = integrity::clamav_available();
    result
}

/// Another worker holds the unit.
pub(super) fn scan_busy_result(
    prior: Option<StoredIntegrityScan>,
) -> hyperion_types::WpIntegrityScanResult {
    scan_unanswered(prior, SITE_SCAN_BUSY)
}

/// The scan ran and there was nowhere safe to put its result.
pub(super) fn scan_not_stored_result(
    prior: Option<StoredIntegrityScan>,
) -> hyperion_types::WpIntegrityScanResult {
    scan_unanswered(prior, SITE_SCAN_NOT_STORED)
}

/// A run says nothing about what it couldn't speak for, so what the last run
/// listed there stays until a run that could clears it. Dropping it would read as
/// "new" to the alert diff when the next run finds it again, at `error`, with
/// wordpress.org back from an outage.
///
/// `everything` is a run cut short: anything could be past where it stopped.
/// Otherwise that's core when it wasn't compared, and each plugin or theme with no
/// manifest this time, however that came about. A site that has no WordPress any
/// more has nothing upstream left to carry.
fn carry_standing_findings(
    result: &mut hyperion_types::WpIntegrityScanResult,
    prior: &hyperion_types::WpIntegrityScanResult,
    everything: bool,
    themes_unknown: &[String],
) {
    use hyperion_types::FindingKind as Kind;
    let upstream_applies = !result.coverage.no_upstream;
    let carry_core = upstream_applies && (everything || !result.wp_cli_ok);
    if carry_core {
        for (into, from) in [
            (&mut result.core_modified, &prior.core_modified),
            (&mut result.core_unexpected, &prior.core_unexpected),
            (&mut result.core_missing, &prior.core_missing),
        ] {
            union_into(into, from);
            into.truncate(MAX_ITEMS);
        }
    }
    let unverified: HashSet<String> = result
        .plugins_unknown
        .iter()
        .chain(themes_unknown)
        .cloned()
        .collect();
    let carried_component = |slug: &str| everything || unverified.contains(slug);
    // wordpress.org out of reach is why its findings are carried. A vendor manifest
    // that isn't there this time was forgotten, or nothing runs it any more, and what
    // it said goes with it.
    let is_vendor = |label: Option<&str>| {
        matches!(
            label,
            Some(hyperion_types::VENDOR_PACKAGE_LABEL)
                | Some(hyperion_types::PACKAGES_DISAGREE_LABEL)
        )
    };
    if upstream_applies {
        for (into, from) in [
            (&mut result.plugins_failed, &prior.plugins_failed),
            (&mut result.themes_failed, &prior.themes_failed),
        ] {
            for old in from.iter().filter(|p| {
                carried_component(&p.slug) && (everything || !is_vendor(p.source.as_deref()))
            }) {
                match into.iter_mut().find(|p| p.slug == old.slug) {
                    Some(p) => union_into(&mut p.issues, &old.issues),
                    None => into.push(old.clone()),
                }
            }
            clamp_failed(into);
        }
    }
    let carried_findings: Vec<_> = prior
        .findings
        .iter()
        .filter(|f| match f.kind {
            Kind::CoreModified | Kind::CoreUnexpected | Kind::CoreMissing => carry_core,
            Kind::UpstreamModified | Kind::UpstreamAdded | Kind::UpstreamMissing => {
                upstream_applies
                    && carried_component(f.component.as_deref().unwrap_or(""))
                    && (everything || !is_vendor(f.source_label.as_deref()))
            }
            _ => everything,
        })
        .cloned()
        .collect();
    union_into(&mut result.findings, &carried_findings);
    result.findings.truncate(MAX_ITEMS);
    if everything {
        union_into(&mut result.review, &prior.review);
        result.review.truncate(MAX_ITEMS);
    }
    // Worked out again: what was carried counts.
    result.core_ok =
        result.wp_cli_ok && result.core_modified.is_empty() && result.core_unexpected.is_empty();
}

fn union_into<T: Clone + PartialEq>(into: &mut Vec<T>, from: &[T]) {
    for item in from {
        if !into.contains(item) {
            into.push(item.clone());
        }
    }
}

/// Cut a string to at most `max` bytes, on a character boundary.
pub(super) fn clip(s: &mut String, max: usize) {
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
        clip(&mut p.version, MAX_ID_BYTES);
        clip_opt(&mut p.source, MAX_ID_BYTES);
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
    for (list, cap) in [
        (&mut o.findings, MAX_ITEMS),
        (&mut o.review, MAX_ITEMS),
        (&mut o.accepted_by_writer, MAX_AUTO_ACCEPTED),
    ] {
        list.truncate(cap);
        list.iter_mut().for_each(clamp_finding);
    }
    clip_list(&mut o.auto_accepted, MAX_AUTO_ACCEPTED, MAX_PATH_BYTES);
    clip_list(&mut o.trust_gone, MAX_TRUST_GONE, MAX_PATH_BYTES);

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
        &mut c.plugins_vendor_verified,
        &mut c.themes_vendor_verified,
    ] {
        *n = (*n).max(0);
    }
    if over {
        c.partial_reasons.insert(
            0,
            "the scan's reply was over its limits and was cut".to_string(),
        );
    }
    // A run cut short is never clean, whatever the worker said about it.
    if (o.stopped || o.capped) && c.partial_reasons.is_empty() {
        c.partial_reasons.push(SITE_SCAN_CUT_SHORT.to_string());
    }
    clip_list(&mut c.partial_reasons, MAX_REASONS, MAX_REASON_BYTES);
    clip_list(
        &mut c.unknown_vendor_hosts,
        vendor::MAX_UNKNOWN_HOSTS,
        MAX_NAME_BYTES,
    );
    clip_opt(&mut c.vendor_note, MAX_REASON_BYTES);
}

/// What a purged site leaves here: its baseline, its writer's list and its quarantine. Neither may
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
    let accepted = Path::new(&paths.scan_dir).join("accepted").join(hosting_id);
    match tokio::fs::remove_file(&accepted).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::error!(error = %e, hosting_id, "purge: accepted list not removed"),
    }
    let quarantine = Path::new(&paths.quarantine_dir).join(hosting_id);
    match tokio::fs::remove_dir_all(&quarantine).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::error!(error = %e, hosting_id, "purge: quarantine not removed"),
    }
}
