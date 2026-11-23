//! The content monitor: what a site says, judged against what it said before.
//!
//! The file scanner can't see a hidden link written into a post or a script tag
//! stored in a widget, because no file changes. This reads the site's stored
//! content (as the hosting's own database login, `SELECT` only) and a handful of
//! its pages (from this node's own copy), reduces both to items, and speaks up
//! only about items the site's baseline doesn't know.
//!
//! Nothing here writes to a tenant's database or runs a tenant's code.

use super::backups::local_slot;
use super::scan_queue::kind_has_files;
use super::*;
use hyperion_adapters::contentscan::{self, db as cdb};
use hyperion_adapters::sitecheck;
use hyperion_types::content::{
    ContentItem, ContentKind, ContentLayer, ContentScanResult, MAX_PLACES,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// `hosting_kv`: the last result, as the card shows it.
pub(super) const CONTENT_KV_KEY: &str = "content_scan";
/// `hosting_kv`: what the site is known to hold, and where the last read stopped.
pub(super) const CONTENT_BASELINE_KV_KEY: &str = "content_baseline";
/// `hosting_kv`: unix seconds someone asked for a scan of this site.
pub(super) const CONTENT_REQUESTED_KV_KEY: &str = "content_scan_requested";
/// `node_kv`: the night (its window's opening, unix seconds) whose sweep is done.
/// With each site's own `scanned_at` it is why a restart starts nothing.
pub(super) const CONTENT_SWEEP_KV: &str = "content_sweep_done_for";

/// The daily sweep runs in these local hours, like the scanner's full re-hash.
const WINDOW_HOURS: std::ops::Range<u32> = 2..6;
const WINDOW_OPENS_MIN: u32 = 2 * 60;
/// Keys the baseline holds for one site.
pub(super) const MAX_KEYS: usize = 2_000;
/// A key unseen this long leaves the baseline, so a host that returns is news.
const KEY_EXPIRY_SECS: i64 = 30 * 86_400;
/// This many new link hosts in one sweep is worth one look.
pub(super) const LINK_BURST: usize = 10;
/// The pages to fetch are chosen again this often.
const PAGES_REFRESH_SECS: i64 = 7 * 86_400;
/// A site's "Scan now" is honoured this far apart at most.
const REQUEST_MIN_GAP_SECS: i64 = 10 * 60;
/// Items listed per bucket. The rest are counted.
const MAX_LISTED: usize = 100;

const NOT_OWN_DB: &str = "wp-config.php names a database this hosting doesn't own";
const NO_LOGIN: &str = "no stored login for the site's database";
const DB_UNREADABLE: &str = "the site's database couldn't be read";
const DB_CAPPED: &str =
    "more stored content than one night reads; the rest follows on the next nights";

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct BaseKey {
    #[serde(default)]
    pub(super) first_seen: i64,
    #[serde(default)]
    pub(super) last_seen: i64,
    /// A person said so, rather than it being there when watching began.
    #[serde(default)]
    pub(super) trusted: bool,
}

/// What a site is known to hold. Root's, in the node's own database: the tenant
/// can't reach it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Baseline {
    /// When watching began; 0 before the first scan.
    #[serde(default)]
    pub(super) since: i64,
    #[serde(default)]
    pub(super) keys: BTreeMap<String, BaseKey>,
    #[serde(default)]
    pub(super) cursor: cdb::Cursor,
    /// The pages fetched beside the homepage, and when they were chosen.
    #[serde(default)]
    pub(super) pages: Vec<String>,
    #[serde(default)]
    pub(super) pages_at: i64,
}

pub(super) fn base_key(kind: ContentKind, key: &str) -> String {
    format!("{}|{key}", kind.as_str())
}

impl Baseline {
    /// Every host the site is known for, whatever it is known for.
    fn hosts(&self) -> BTreeSet<&str> {
        self.keys
            .keys()
            .filter_map(|k| k.split_once('|'))
            .filter(|(kind, _)| *kind != ContentKind::InlineScript.as_str())
            .map(|(_, host)| host)
            .collect()
    }

    fn count(&self, kind: ContentKind) -> u32 {
        let prefix = format!("{}|", kind.as_str());
        u32::try_from(self.keys.keys().filter(|k| k.starts_with(&prefix)).count())
            .unwrap_or(u32::MAX)
    }
}

/// One thing seen in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Sighting {
    pub(super) kind: ContentKind,
    pub(super) key: String,
    pub(super) snippet: String,
    pub(super) place: String,
    pub(super) from_db: bool,
}

/// Everything one sweep of one site read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Observed {
    pub(super) db: ContentLayer,
    pub(super) pages: ContentLayer,
    pub(super) pages_fetched: u32,
    pub(super) crawler_note: Option<String>,
    pub(super) seen: Vec<Sighting>,
    /// Where the next database read starts, when this one ran.
    pub(super) cursor: Option<cdb::Cursor>,
}

fn collect(seen: &[Sighting]) -> BTreeMap<(ContentKind, String), ContentItem> {
    let mut items: BTreeMap<(ContentKind, String), ContentItem> = BTreeMap::new();
    for s in seen {
        let item = items
            .entry((s.kind, s.key.clone()))
            .or_insert_with(|| ContentItem {
                kind: s.kind,
                key: s.key.clone(),
                count: 0,
                places: Vec::new(),
                snippet: s.snippet.clone(),
                first_seen: 0,
                at_first_scan: false,
                notified: false,
                in_db: false,
                on_page: false,
            });
        item.count = item.count.saturating_add(1);
        if item.places.len() < MAX_PLACES && !item.places.contains(&s.place) {
            item.places.push(s.place.clone());
        }
        item.in_db |= s.from_db;
        item.on_page |= !s.from_db;
    }
    items
}

/// Could this item still be there, unread? An item absent from a layer that
/// didn't read everything isn't gone.
fn may_still_stand(item: &ContentItem, obs: &Observed) -> bool {
    if item.kind == ContentKind::LinkBurst {
        return true;
    }
    let crawler_blind = item.kind == ContentKind::Cloaked && obs.crawler_note.is_some();
    (item.in_db && !obs.db.is_complete())
        || (item.on_page && !obs.pages.is_complete())
        || crawler_blind
}

/// Judge one sweep against the baseline, and bring the baseline up to date.
///
/// Known keys are quiet. Visible outbound links join the baseline as they
/// appear, since a site is expected to link out. Everything else that is new
/// stands in the result until it is gone or trusted. On the first scan nothing
/// that matters is blessed: findings are findings, and the script and frame
/// hosts already there are listed once, for a person to look at.
pub(super) fn judge(
    baseline: &mut Baseline,
    obs: &Observed,
    prior: Option<&ContentScanResult>,
    now: i64,
) -> ContentScanResult {
    let first = baseline.since == 0;
    if first {
        baseline.since = now;
    }
    if let Some(cursor) = obs.cursor {
        baseline.cursor = cursor;
    }
    let items = collect(&obs.seen);
    let prior_item = |kind: ContentKind, key: &str| prior.and_then(|p| p.item(kind, key));
    let mut standing: Vec<ContentItem> = Vec::new();
    let mut new_links: Vec<String> = Vec::new();
    for ((kind, key), mut item) in items.clone() {
        let bk = base_key(kind, &key);
        if let Some(known) = baseline.keys.get_mut(&bk) {
            known.last_seen = now;
            continue;
        }
        if kind == ContentKind::LinkHost {
            baseline.keys.insert(
                bk,
                BaseKey {
                    first_seen: now,
                    last_seen: now,
                    trusted: false,
                },
            );
            new_links.push(key);
            continue;
        }
        match prior_item(kind, &key) {
            Some(before) => {
                item.first_seen = before.first_seen;
                item.at_first_scan = before.at_first_scan;
                item.notified = before.notified;
            }
            None => {
                item.first_seen = now;
                item.at_first_scan = first && !kind.is_finding();
            }
        }
        standing.push(item);
    }
    // What stood before and wasn't seen now: gone, unless it couldn't be looked for.
    if let Some(p) = prior {
        for before in p.findings.iter().chain(&p.review) {
            let seen_now = items.contains_key(&(before.kind, before.key.clone()));
            let known = baseline
                .keys
                .contains_key(&base_key(before.kind, &before.key));
            if !seen_now && !known && may_still_stand(before, obs) {
                standing.push(before.clone());
            }
        }
    }
    if !first && new_links.len() >= LINK_BURST {
        standing.push(ContentItem {
            kind: ContentKind::LinkBurst,
            key: now.to_string(),
            count: u32::try_from(new_links.len()).unwrap_or(u32::MAX),
            places: new_links.iter().take(MAX_PLACES).cloned().collect(),
            snippet: String::new(),
            first_seen: now,
            at_first_scan: false,
            notified: false,
            in_db: false,
            on_page: true,
        });
    }
    let everything_read = !matches!(obs.db, ContentLayer::Partial(_) | ContentLayer::Failed(_))
        && !matches!(obs.pages, ContentLayer::Partial(_) | ContentLayer::Failed(_));
    if everything_read {
        baseline
            .keys
            .retain(|_, k| now - k.last_seen < KEY_EXPIRY_SECS);
    }
    trim_baseline(baseline);

    standing.sort_by(|a, b| (a.kind, &a.key).cmp(&(b.kind, &b.key)));
    let (mut findings, mut review): (Vec<_>, Vec<_>) =
        standing.into_iter().partition(|i| i.kind.is_finding());
    let more = findings.len().saturating_sub(MAX_LISTED) + review.len().saturating_sub(MAX_LISTED);
    findings.truncate(MAX_LISTED);
    review.truncate(MAX_LISTED);
    ContentScanResult {
        scanned_at: now,
        watching_since: baseline.since,
        rule_pack: contentscan::rules::RULE_PACK,
        report_only: false,
        db: obs.db.clone(),
        pages: obs.pages.clone(),
        pages_fetched: obs.pages_fetched,
        crawler_note: obs.crawler_note.clone(),
        findings,
        review,
        link_hosts: baseline.count(ContentKind::LinkHost),
        known_hosts: baseline.count(ContentKind::ScriptHost)
            + baseline.count(ContentKind::FrameHost),
        more: u32::try_from(more).unwrap_or(u32::MAX),
    }
}

/// Keep the baseline within its size: the link hosts longest unseen go first,
/// and what a person trusted goes last.
fn trim_baseline(baseline: &mut Baseline) {
    let over = baseline.keys.len().saturating_sub(MAX_KEYS);
    if over == 0 {
        return;
    }
    let link = format!("{}|", ContentKind::LinkHost.as_str());
    let mut order: Vec<(bool, bool, i64, String)> = baseline
        .keys
        .iter()
        .map(|(k, v)| (v.trusted, !k.starts_with(&link), v.last_seen, k.clone()))
        .collect();
    order.sort();
    for (_, _, _, key) in order.into_iter().take(over) {
        baseline.keys.remove(&key);
    }
}

/// Who hears about what, and what that leaves marked as told.
///
/// Off (the pilot), nobody hears, and findings stay untold so they are said once
/// when alerts go live. Changes to review are never said late: they were on the
/// card the whole time.
pub(super) fn settle_notifications(result: &mut ContentScanResult, live: bool) -> (usize, usize) {
    result.report_only = !live;
    let mut new_findings = 0;
    let mut new_review = 0;
    if live {
        for f in result.findings.iter_mut().filter(|f| !f.notified) {
            f.notified = true;
            new_findings += 1;
        }
    }
    for r in result.review.iter_mut().filter(|r| !r.notified) {
        r.notified = true;
        if live && !r.at_first_scan {
            new_review += 1;
        }
    }
    (new_findings, new_review)
}

/// Host-shaped keys among these sightings.
fn hosts_of(seen: &[Sighting]) -> BTreeSet<String> {
    seen.iter()
        .filter(|s| s.kind != ContentKind::InlineScript)
        .map(|s| s.key.clone())
        .collect()
}

fn page_sightings(body: &str, url: &str, site_hosts: &[String]) -> Vec<Sighting> {
    contentscan::extract(body, site_hosts, true)
        .into_iter()
        .map(|s| Sighting {
            kind: s.kind,
            key: s.key,
            snippet: s.snippet,
            place: url.to_string(),
            from_db: false,
        })
        .collect()
}

/// Is the daily sweep's window open at `now`, and when did it open?
fn window_open<Tz: chrono::TimeZone>(tz: &Tz, now: i64) -> Option<i64> {
    use chrono::Timelike;
    let local = tz.timestamp_opt(now, 0).earliest()?;
    if !WINDOW_HOURS.contains(&local.hour()) {
        return None;
    }
    local_slot(tz, now, 0, WINDOW_OPENS_MIN)
}

impl<A: AdapterPort + 'static> HostingService<A> {
    async fn content_kv<T: serde::de::DeserializeOwned>(
        &self,
        hosting_id: &str,
        key: &str,
    ) -> Option<T> {
        let raw = hyperion_state::hosting_kv::get(&self.pool, hosting_id, key)
            .await
            .ok()??;
        serde_json::from_str(&raw).ok()
    }

    async fn put_content_kv<T: serde::Serialize>(&self, hosting_id: &str, key: &str, value: &T) {
        let Ok(raw) = serde_json::to_string(value) else {
            return;
        };
        if let Err(e) =
            hyperion_state::hosting_kv::set(&self.pool, hosting_id, key, &raw, now_secs()).await
        {
            tracing::warn!(error = %e, key, "content scan: state not stored");
        }
    }

    pub(super) async fn content_baseline(&self, hosting_id: &str) -> Baseline {
        self.content_kv(hosting_id, CONTENT_BASELINE_KV_KEY)
            .await
            .unwrap_or_default()
    }

    /// What the last content scan left for this hosting, without starting one.
    pub async fn content_scan_stored(
        &self,
        sel: HostingSelector,
    ) -> Result<Option<ContentScanResult>, RpcError> {
        let detail = self.get(sel).await?;
        Ok(self.content_kv(detail.id.as_str(), CONTENT_KV_KEY).await)
    }

    /// Someone pressed "Scan now". Best-effort: it is the file scan they asked for
    /// by name, and this rides along.
    pub(super) async fn content_scan_request(&self, hosting_id: &str, now: i64) {
        if let Err(e) = hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id,
            CONTENT_REQUESTED_KV_KEY,
            &now.to_string(),
            now,
        )
        .await
        {
            tracing::warn!(error = %e, "content scan: request not stored");
            return;
        }
        self.site_scan.content_wake.notify_one();
    }

    /// Returns when someone has asked for a content scan.
    pub async fn content_scan_wait_for_request(&self) {
        self.site_scan.content_wake.notified().await;
    }

    /// The site's stored content, when it is a WordPress site whose database this
    /// hosting owns. `wp-config.php` is the tenant's file and can name anyone's
    /// database, so its claim counts only against what the hosting owns, and
    /// even then the read is done with that hosting's own login.
    async fn content_read_db(
        &self,
        detail: &HostingDetail,
        site_hosts: &[String],
        cursor: cdb::Cursor,
        obs: &mut Observed,
    ) {
        let Some((db, prefix)) = self
            .adapters
            .site_scan_wp_config_db(Path::new(&detail.root_dir))
            .await
        else {
            obs.db = ContentLayer::NotApplicable;
            return;
        };
        let logins = match databases::mariadb_logins_for_hosting(&self.pool, &detail.id).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(domain = %detail.domain, error = %e, "content scan: databases unreadable");
                obs.db = ContentLayer::Failed(DB_UNREADABLE.into());
                return;
            }
        };
        let Some((_, user, secret_id)) = logins.iter().find(|(name, _, _)| *name == db) else {
            obs.db = ContentLayer::Failed(NOT_OWN_DB.into());
            return;
        };
        let secret: Option<serde_json::Value> = self.secrets.get(secret_id).await.ok();
        let Some(password) = secret
            .as_ref()
            .and_then(|s| s.get("password"))
            .and_then(|p| p.as_str())
        else {
            obs.db = ContentLayer::Failed(NO_LOGIN.into());
            return;
        };
        let read = match self
            .adapters
            .content_db_read(&db, &prefix, user, password, cursor, site_hosts.to_vec())
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(domain = %detail.domain, error = %e, "content scan: database unreadable");
                obs.db = ContentLayer::Failed(DB_UNREADABLE.into());
                return;
            }
        };
        obs.seen.extend(read.placed.into_iter().map(|p| Sighting {
            kind: p.seen.kind,
            key: p.seen.key,
            snippet: p.seen.snippet,
            place: p.place,
            from_db: true,
        }));
        match read.end {
            cdb::ReadEnd::Complete => {
                obs.db = ContentLayer::Complete;
                obs.cursor = Some(cdb::Cursor::default());
            }
            cdb::ReadEnd::Capped(at) => {
                obs.db = ContentLayer::Partial(DB_CAPPED.into());
                obs.cursor = Some(at);
            }
            // The cursor stays: the stretch that broke is tried again.
            cdb::ReadEnd::Broken(why) if read.rows > 0 => obs.db = ContentLayer::Partial(why),
            cdb::ReadEnd::Broken(why) => obs.db = ContentLayer::Failed(why),
        }
    }

    /// Up to four pages beside the homepage, from the site's own sitemap. For an
    /// index, the first child that lists any. A sitemap is the site's text: every
    /// address goes through the same-site test before it is fetched.
    async fn content_pick_pages(&self, domain: &str, base: &str) -> Vec<String> {
        let same_site = |raw: &str| sitecheck::resolve_url(raw, base, domain);
        let pick = |locs: Vec<String>| -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for u in locs {
                if u.trim_end_matches('/') != base.trim_end_matches('/') && !out.contains(&u) {
                    out.push(u);
                }
                if out.len() == contentscan::MAX_EXTRA_PAGES {
                    break;
                }
            }
            out
        };
        for candidate in ["wp-sitemap.xml", "sitemap.xml", "sitemap_index.xml"] {
            let url = format!("{base}{candidate}");
            let Ok(f) = self.adapters.content_page(&url, domain, false).await else {
                continue;
            };
            if !f.is_ok() || f.body.trim().is_empty() {
                continue;
            }
            let locs: Vec<String> = sitecheck::sitemap_locs(&f.body)
                .iter()
                .filter_map(|u| same_site(u))
                .collect();
            if locs.is_empty() {
                continue;
            }
            if !sitecheck::is_sitemap_index(&f.body) {
                return pick(locs);
            }
            for child in locs.into_iter().take(2) {
                let Ok(cf) = self.adapters.content_page(&child, domain, false).await else {
                    continue;
                };
                let child_locs: Vec<String> = sitecheck::sitemap_locs(&cf.body)
                    .iter()
                    .filter_map(|u| same_site(u))
                    .collect();
                if cf.is_ok() && !child_locs.is_empty() {
                    return pick(child_locs);
                }
            }
            return Vec::new();
        }
        Vec::new()
    }

    /// The homepage and a few more, as a visitor gets them, then the homepage
    /// once more as a crawler gets it.
    async fn content_read_pages(
        &self,
        detail: &HostingDetail,
        site_hosts: &[String],
        baseline: &mut Baseline,
        obs: &mut Observed,
        now: i64,
    ) {
        let domain = detail.domain.trim();
        if domain.is_empty() || detail.kind.trim() == "redirect" {
            obs.pages = ContentLayer::NotApplicable;
            return;
        }
        let base = format!("https://{domain}/");
        let home = match self.adapters.content_page(&base, domain, false).await {
            Ok(f) if f.is_ok() => f,
            Ok(f) => {
                obs.pages = ContentLayer::Failed(format!(
                    "the homepage didn't answer with a page (status {})",
                    f.status
                ));
                return;
            }
            Err(e) => {
                tracing::debug!(domain, error = %e, "content scan: homepage unreadable");
                obs.pages = ContentLayer::Failed("the homepage couldn't be fetched".into());
                return;
            }
        };
        obs.pages_fetched = 1;
        obs.seen
            .extend(page_sightings(&home.body, &base, site_hosts));

        let stale = baseline.pages_at == 0
            || baseline.pages_at > now
            || now - baseline.pages_at >= PAGES_REFRESH_SECS;
        if stale {
            baseline.pages = self.content_pick_pages(domain, &base).await;
            baseline.pages_at = now;
        }
        let mut unanswered = 0u32;
        for url in baseline.pages.iter().take(contentscan::MAX_EXTRA_PAGES) {
            // Chosen days ago, by the site: still held to the same-site test.
            let Some(url) = sitecheck::resolve_url(url, &base, domain) else {
                continue;
            };
            match self.adapters.content_page(&url, domain, false).await {
                Ok(f) if f.is_ok() => {
                    obs.pages_fetched += 1;
                    obs.seen.extend(page_sightings(&f.body, &url, site_hosts));
                }
                _ => unanswered += 1,
            }
        }
        obs.pages = if unanswered == 0 {
            ContentLayer::Complete
        } else {
            // Next sweep picks again: a page that is gone shouldn't be asked for
            // all week.
            baseline.pages_at = 0;
            ContentLayer::Partial(format!("{unanswered} page(s) didn't answer"))
        };

        // What only a crawler is shown. Known = this sweep's ordinary views, the
        // stored content, and everything the site is already known for, so two
        // fetches differing by a rotating advert isn't cloaking.
        let mut known = hosts_of(&obs.seen);
        known.extend(baseline.hosts().into_iter().map(str::to_string));
        match self.adapters.content_page(&base, domain, true).await {
            Ok(f) if f.is_ok() => {
                for s in page_sightings(&f.body, &base, site_hosts) {
                    if s.kind == ContentKind::InlineScript {
                        obs.seen.push(s);
                    } else if !known.contains(&s.key) {
                        obs.seen.push(Sighting {
                            kind: ContentKind::Cloaked,
                            ..s
                        });
                    }
                }
            }
            // Sent somewhere else, where a visitor was shown the page.
            Ok(f) if f.is_redirect() => {
                match contentscan::url_host(&f.location).filter(|h| {
                    !site_hosts.iter().any(|s| {
                        let s = contentscan::normal_host(s);
                        *h == s || h.ends_with(&format!(".{s}"))
                    })
                }) {
                    Some(host) if !known.contains(&host) => obs.seen.push(Sighting {
                        kind: ContentKind::Cloaked,
                        key: host,
                        snippet: format!(
                            "redirect to {}",
                            f.location.chars().take(100).collect::<String>()
                        ),
                        place: base.clone(),
                        from_db: false,
                    }),
                    Some(_) => {}
                    None => {
                        obs.crawler_note =
                            Some("the page as served to a crawler redirects in a loop".into());
                    }
                }
            }
            // Refused or failed is "couldn't look", never a finding: security
            // plugins turn away a crawler that isn't one.
            Ok(f) => {
                obs.crawler_note = Some(format!(
                    "the page as served to a crawler couldn't be compared (status {})",
                    f.status
                ));
            }
            Err(_) => {
                obs.crawler_note =
                    Some("the page as served to a crawler couldn't be fetched".into());
            }
        }
    }

    /// Scan one site's content now. `Some(true)` when someone was told of
    /// something new; `None` when the site isn't one this looks at.
    pub(super) async fn content_scan_site(&self, id: &HostingId, now: i64) -> Option<bool> {
        let detail = self.get(HostingSelector::Id(id.clone())).await.ok()?;
        if detail.state != HostingState::Active
            || !kind_has_files(&detail.kind)
            || !self.integrity_scan_enabled(id.as_str()).await
        {
            return None;
        }
        let mut site_hosts = vec![detail.domain.clone()];
        site_hosts.extend(detail.aliases.iter().cloned());
        site_hosts.retain(|h| !h.trim().is_empty());

        // Reading is slow and holds nothing. The cursor and page list are this
        // tick's alone to move.
        let before = self.content_baseline(id.as_str()).await;
        let mut pages_state = before.clone();
        let mut obs = Observed::default();
        self.content_read_db(&detail, &site_hosts, before.cursor, &mut obs)
            .await;
        self.content_read_pages(&detail, &site_hosts, &mut pages_state, &mut obs, now)
            .await;

        let _held = self.site_scan.content.lock().await;
        // Read again under the lock: a Trust may have landed while pages loaded.
        let mut baseline = self.content_baseline(id.as_str()).await;
        baseline.pages = pages_state.pages;
        baseline.pages_at = pages_state.pages_at;
        let prior: Option<ContentScanResult> = self.content_kv(id.as_str(), CONTENT_KV_KEY).await;
        let mut result = judge(&mut baseline, &obs, prior.as_ref(), now);
        let live = self.content_live();
        let (new_findings, new_review) = settle_notifications(&mut result, live);
        self.put_content_kv(id.as_str(), CONTENT_BASELINE_KV_KEY, &baseline)
            .await;
        self.put_content_kv(id.as_str(), CONTENT_KV_KEY, &result)
            .await;
        drop(_held);

        if !live {
            // The pilot's numbers, one line per site, for comparing nodes.
            tracing::info!(
                domain = %detail.domain,
                findings = result.findings.len(),
                review = result.review.len(),
                partial = result.is_partial(),
                "content scan (report-only)"
            );
        }
        let href = format!("/hostings/{}#wordpress", detail.domain);
        if new_findings > 0 {
            self.notify_admins_say(
                "error",
                "ops.content",
                &[
                    ("domain", &detail.domain),
                    ("findings", &result.findings.len().to_string()),
                    ("new", &new_findings.to_string()),
                ],
                &href,
                &format!("content:{}", detail.domain),
            )
            .await;
        }
        if new_review > 0 {
            self.notify_admins_say(
                "warn",
                "ops.content_review",
                &[
                    ("domain", &detail.domain),
                    ("review", &result.review.len().to_string()),
                    ("new", &new_review.to_string()),
                ],
                &href,
                &format!("content.review:{}", detail.domain),
            )
            .await;
        }
        Some(new_findings + new_review > 0)
    }

    /// The content monitor's tick. Returns how many sites gained something
    /// someone was told about.
    pub async fn content_scan_tick(&self) -> Result<i64, RpcError> {
        self.content_scan_tick_at(&chrono::Local, now_secs()).await
    }

    pub(super) async fn content_scan_tick_at<Tz: chrono::TimeZone>(
        &self,
        tz: &Tz,
        now: i64,
    ) -> Result<i64, RpcError> {
        let mut flagged = 0i64;
        // Requests first, whatever the hour.
        let requests = hyperion_state::hosting_kv::list_by_key(&self.pool, CONTENT_REQUESTED_KV_KEY)
            .await
            .unwrap_or_default();
        for (id, _) in requests {
            let last: Option<ContentScanResult> = self.content_kv(&id, CONTENT_KV_KEY).await;
            let too_soon = last.is_some_and(|r| {
                r.scanned_at <= now && now - r.scanned_at < REQUEST_MIN_GAP_SECS
            });
            if too_soon {
                continue;
            }
            let _ = hyperion_state::hosting_kv::delete(&self.pool, &id, CONTENT_REQUESTED_KV_KEY)
                .await;
            if self.content_scan_site(&HostingId(id), now).await == Some(true) {
                flagged += 1;
            }
        }

        let opened = window_open(tz, now);
        let sweep_done = match hyperion_state::node_kv::get(&self.pool, CONTENT_SWEEP_KV).await {
            Ok(v) => v.and_then(|s| s.trim().parse::<i64>().ok()),
            Err(e) => {
                tracing::warn!(error = %e, "content scan: sweep stamp unreadable");
                return Ok(flagged);
            }
        };
        let nightly_owed = opened.is_some_and(|o| sweep_done != Some(o));

        // Oldest first. A site never scanned is due at any hour; the rest once a
        // night, when their last scan is older than tonight's opening.
        let mut due: Vec<(i64, HostingId)> = Vec::new();
        for s in self.list().await? {
            if s.state != HostingState::Active || !kind_has_files(s.kind.as_deref().unwrap_or("")) {
                continue;
            }
            if !self.integrity_scan_enabled(s.id.as_str()).await {
                continue;
            }
            let last: Option<ContentScanResult> =
                self.content_kv(s.id.as_str(), CONTENT_KV_KEY).await;
            match (last, opened) {
                (None, _) => due.push((0, s.id)),
                (Some(r), Some(o)) if nightly_owed && (r.scanned_at < o || r.scanned_at > now) => {
                    due.push((r.scanned_at.min(now), s.id));
                }
                _ => {}
            }
        }
        due.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.as_str().cmp(b.1.as_str())));

        let started = std::time::Instant::now();
        let cores = hyperion_adapters::sitescan::pressure::host_cores();
        let mut finished = true;
        for (last, id) in due {
            let now = now + i64::try_from(started.elapsed().as_secs()).unwrap_or(0);
            // The night's work stops with the night. A first scan doesn't wait.
            if last != 0 && window_open(tz, now).is_none() {
                finished = false;
                break;
            }
            if hyperion_adapters::sitescan::pressure::sample_pressure(cores) {
                tracing::debug!("content scan: the node is busy; next tick");
                finished = false;
                break;
            }
            if self.content_scan_site(&id, now).await == Some(true) {
                flagged += 1;
            }
        }
        if let (true, true, Some(o)) = (finished, nightly_owed, opened) {
            if let Err(e) =
                hyperion_state::node_kv::set(&self.pool, CONTENT_SWEEP_KV, &o.to_string(), now)
                    .await
            {
                tracing::warn!(error = %e, "content scan: sweep stamp not stored");
            }
        }
        Ok(flagged)
    }

    async fn content_trust_where(
        &self,
        sel: HostingSelector,
        actor: &str,
        action: &str,
        pick: impl Fn(&ContentItem) -> bool,
        none: &str,
    ) -> Result<ContentScanResult, RpcError> {
        let detail = self.get(sel).await?;
        let id = detail.id.as_str();
        let now = now_secs();
        let outcome = {
            let _held = self.site_scan.content.lock().await;
            let stored: Option<ContentScanResult> = self.content_kv(id, CONTENT_KV_KEY).await;
            match stored {
                None => Err("this site's content hasn't been scanned yet".to_string()),
                Some(mut result) => {
                    let (trusted, kept_findings): (Vec<_>, Vec<_>) =
                        result.findings.drain(..).partition(|i| pick(i));
                    let (trusted_review, kept_review): (Vec<_>, Vec<_>) =
                        result.review.drain(..).partition(|i| pick(i));
                    result.findings = kept_findings;
                    result.review = kept_review;
                    let trusted: Vec<ContentItem> =
                        trusted.into_iter().chain(trusted_review).collect();
                    if trusted.is_empty() {
                        Err(none.to_string())
                    } else {
                        let mut baseline = self.content_baseline(id).await;
                        for item in &trusted {
                            if item.kind == ContentKind::LinkBurst {
                                continue;
                            }
                            baseline.keys.insert(
                                base_key(item.kind, &item.key),
                                BaseKey {
                                    first_seen: item.first_seen,
                                    last_seen: now,
                                    trusted: true,
                                },
                            );
                        }
                        self.put_content_kv(id, CONTENT_BASELINE_KV_KEY, &baseline)
                            .await;
                        self.put_content_kv(id, CONTENT_KV_KEY, &result).await;
                        Ok((result, trusted))
                    }
                }
            }
        };
        let label = if actor.is_empty() { "agent" } else { actor };
        match outcome {
            Ok((result, trusted)) => {
                let items: Vec<_> = trusted
                    .iter()
                    .map(|i| serde_json::json!({ "kind": i.kind.as_str(), "key": i.key }))
                    .collect();
                self.append_audit_as(
                    0,
                    label,
                    action,
                    Some(id),
                    &serde_json::json!({ "total": items.len(), "items": items }).to_string(),
                    "ok",
                )
                .await;
                Ok(result)
            }
            Err(why) => {
                self.append_audit_as(
                    0,
                    label,
                    action,
                    Some(id),
                    &serde_json::json!({ "reason": why }).to_string(),
                    "refused",
                )
                .await;
                Err(RpcError::Conflict { message: why })
            }
        }
    }

    /// Vouch for one item the content scan reported: it joins the baseline and
    /// is quiet from now on. `kind` and `key` must name an item of the stored
    /// result, so a stale card or a made-up key trusts nothing.
    pub async fn content_trust(
        &self,
        sel: HostingSelector,
        kind: String,
        key: String,
        actor: String,
    ) -> Result<ContentScanResult, RpcError> {
        let Some(kind) = ContentKind::parse(&kind) else {
            return Err(RpcError::Conflict {
                message: "no such kind of item".into(),
            });
        };
        self.content_trust_where(
            sel,
            &actor,
            "content.trust",
            |i| i.kind == kind && i.key == key,
            "that item is no longer on this site's result; reload the card",
        )
        .await
    }

    /// Vouch for every change to review at once. Findings are never part of
    /// this: each is trusted by itself or not at all.
    pub async fn content_trust_all_review(
        &self,
        sel: HostingSelector,
        actor: String,
    ) -> Result<ContentScanResult, RpcError> {
        self.content_trust_where(
            sel,
            &actor,
            "content.trust_all",
            |i| !i.kind.is_finding(),
            "nothing here can be trusted all at once",
        )
        .await
    }
}
