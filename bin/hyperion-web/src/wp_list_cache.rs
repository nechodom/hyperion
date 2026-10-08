//! In-process cache of each hosting's WordPress plugin + theme lists.
//!
//! The hosting detail page needs both lists on every render (the WordPress
//! tab's tables, the update badge in the section nav, the health verdict on
//! Overview), and each one is a `wp plugin list` / `wp theme list` on the
//! owning node — a full WordPress bootstrap, routinely seconds on a real site.
//! They were the slowest thing on the page by far, and the page is rendered
//! again after every save and by the 15-second backups refresh.
//!
//! Stale-while-revalidate, so the page stays current without waiting:
//!
//! * younger than [`FRESH`] — served as is;
//! * older, up to [`MAX_STALE`] — served immediately AND refreshed in the
//!   background, so the next render has the new answer;
//! * older than that, or missing — fetched inline, as before.
//!
//! Anything the panel itself does that can change what WordPress reports
//! (plugin/theme actions, restores, profile applies…) clears the whole cache
//! via [`invalidates`], so the render that follows such an action always asks
//! wp-cli again. What the cache can miss is a change made OUTSIDE the panel
//! (WordPress's own auto-updates, a plugin installed over SFTP): that shows
//! up one render late, never more than [`MAX_STALE`] late.
//!
//! Only clean answers are cached. A failed wp-cli run (`error: Some`) is
//! exactly what the operator is trying to fix, so it is asked again every
//! time.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyperion_types::{WpPluginListResponse, WpThemeListResponse};

/// Served without a background refresh.
pub const FRESH: Duration = Duration::from_secs(60);
/// Served while a background refresh runs; past this the render waits.
pub const MAX_STALE: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Default)]
pub struct WpLists {
    pub plugins: WpPluginListResponse,
    pub themes: WpThemeListResponse,
}

impl WpLists {
    fn is_clean(&self) -> bool {
        self.plugins.error.is_none() && self.themes.error.is_none()
    }
}

#[derive(Debug)]
pub enum Lookup {
    Fresh(Arc<WpLists>),
    /// Usable now, but due a refresh.
    Stale(Arc<WpLists>),
    Miss,
}

struct Entry {
    lists: Arc<WpLists>,
    fetched: Instant,
    refreshing: bool,
}

#[derive(Default)]
pub struct WpListCache {
    entries: Mutex<HashMap<String, Entry>>,
    /// Bumped by every invalidation. A fetch remembers the generation it
    /// started in and is dropped on store if it changed — otherwise a
    /// refresh already in flight when the operator updated a plugin would
    /// write the pre-update list back over the invalidation.
    generation: AtomicU64,
}

impl WpListCache {
    pub fn lookup(&self, hosting_id: &str) -> Lookup {
        self.lookup_at(hosting_id, Instant::now())
    }

    fn lookup_at(&self, hosting_id: &str, now: Instant) -> Lookup {
        let map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        match map.get(hosting_id) {
            None => Lookup::Miss,
            Some(e) => {
                let age = now.saturating_duration_since(e.fetched);
                if age < FRESH {
                    Lookup::Fresh(e.lists.clone())
                } else if age < MAX_STALE {
                    Lookup::Stale(e.lists.clone())
                } else {
                    Lookup::Miss
                }
            }
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Claim the background refresh for this hosting. `false` when one is
    /// already running — a busy page must not stack up wp-cli runs.
    pub fn begin_refresh(&self, hosting_id: &str) -> bool {
        let mut map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        match map.get_mut(hosting_id) {
            Some(e) if !e.refreshing => {
                e.refreshing = true;
                true
            }
            _ => false,
        }
    }

    /// Record a fetch that started in generation `gen`. Dropped when the
    /// cache was invalidated meanwhile, or when wp-cli reported an error
    /// (which also releases the refresh claim, so the next render retries).
    pub fn store(&self, hosting_id: &str, lists: WpLists, gen: u64) {
        self.store_at(hosting_id, lists, gen, Instant::now())
    }

    fn store_at(&self, hosting_id: &str, lists: WpLists, gen: u64, now: Instant) {
        let mut map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if gen != self.generation.load(Ordering::SeqCst) {
            return;
        }
        if !lists.is_clean() {
            if let Some(e) = map.get_mut(hosting_id) {
                e.refreshing = false;
            }
            return;
        }
        map.insert(
            hosting_id.to_string(),
            Entry {
                lists: Arc::new(lists),
                fetched: now,
                refreshing: false,
            },
        );
    }

    pub fn invalidate_all(&self) {
        let mut map = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        self.generation.fetch_add(1, Ordering::SeqCst);
        map.clear();
    }
}

/// POSTs that are known NOT to change what `wp plugin list` / `wp theme
/// list` report. Everything else invalidates the cache — the safe direction:
/// an unlisted action costs one slow render, a wrongly listed one shows a
/// stale plugin table. Must-use plugins count (they are in `wp plugin list`),
/// which is why the mu-plugin writers (registration guard, wp-mail fix) are
/// NOT here, and anything under `/hostings/wp/` never is.
const KEEPS_WP_LISTS: &[&str] = &[
    "/hostings/notes",
    "/hostings/vhost-options",
    "/hostings/aliases",
    "/hostings/proxy-upstream",
    "/hostings/set-limits",
    "/hostings/set-php-version",
    "/hostings/acme-email",
    "/hostings/php-ini",
    "/hostings/quota/",
    "/hostings/backup-now",
    "/hostings/backup-cadence",
    "/hostings/backup-target",
    "/hostings/backups/",
    "/hostings/expiry/",
    "/hostings/dns-check",
    "/hostings/cert/",
    "/hostings/logs",
    "/hostings/cron",
    "/hostings/ftp/",
    "/hostings/sftp",
    "/hostings/dkim/",
    "/hostings/bruteforce-scan",
    "/hostings/letter-language",
    "/hostings/perm-autoheal",
    "/hostings/integrity/scan",
    "/hostings/ban",
    "/hostings/waf-",
    "/hostings/access/",
    "/hostings/monitor/",
    "/hostings/performance/measure",
    "/hostings/site-check",
    "/hostings/snapshots/now",
    "/hostings/snapshots/diff",
    "/hostings/snapshots/delete",
    "/hostings/packages/report",
    "/hostings/packages/valid-from",
    "/hostings/packages/service-check",
    "/hostings/gitsync/config",
    "/hostings/gitsync/genkey",
    "/hostings/suspend",
    "/hostings/resume",
];

/// Does a request with this method + path have to drop the cache?
pub fn invalidates(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    !KEEPS_WP_LISTS.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    fn lists(n: usize) -> WpLists {
        let mut l = WpLists::default();
        l.plugins.updates_pending = n as _;
        l
    }

    #[test]
    fn fresh_then_stale_then_miss() {
        let c = WpListCache::default();
        let t0 = Instant::now();
        assert!(matches!(c.lookup_at("h", t0), Lookup::Miss));
        c.store_at("h", lists(1), c.generation(), t0);
        assert!(matches!(
            c.lookup_at("h", t0 + Duration::from_secs(5)),
            Lookup::Fresh(_)
        ));
        assert!(matches!(c.lookup_at("h", t0 + FRESH), Lookup::Stale(_)));
        assert!(matches!(c.lookup_at("h", t0 + MAX_STALE), Lookup::Miss));
    }

    #[test]
    fn invalidation_drops_entries_and_inflight_fetches() {
        let c = WpListCache::default();
        let gen = c.generation();
        c.store("h", lists(1), gen);
        // A refresh starts, then the operator updates a plugin.
        let inflight = c.generation();
        c.invalidate_all();
        assert!(matches!(c.lookup("h"), Lookup::Miss));
        // The refresh lands with the pre-update answer: must not be kept.
        c.store("h", lists(1), inflight);
        assert!(matches!(c.lookup("h"), Lookup::Miss));
        // A fetch started after the invalidation is.
        c.store("h", lists(0), c.generation());
        assert!(matches!(c.lookup("h"), Lookup::Fresh(_)));
    }

    #[test]
    fn errors_are_never_cached_and_release_the_refresh_claim() {
        let c = WpListCache::default();
        let t0 = Instant::now();
        c.store_at("h", lists(1), c.generation(), t0);
        assert!(c.begin_refresh("h"));
        assert!(!c.begin_refresh("h"), "second claim while one runs");
        let mut bad = lists(0);
        bad.plugins.error = Some("PHP Fatal error".into());
        c.store_at("h", bad, c.generation(), t0);
        // Old clean answer kept, claim released for a retry.
        match c.lookup_at("h", t0) {
            Lookup::Fresh(l) => assert_eq!(l.plugins.updates_pending, 1),
            other => panic!("expected the old entry, got {other:?}"),
        }
        assert!(c.begin_refresh("h"));
        assert!(!c.begin_refresh("missing"));
    }

    #[test]
    fn which_requests_invalidate() {
        assert!(!invalidates(&Method::GET, "/hostings/wp/plugin-action"));
        assert!(invalidates(&Method::POST, "/hostings/wp/plugin-action"));
        assert!(invalidates(&Method::POST, "/hostings/wp/theme-action"));
        assert!(invalidates(&Method::POST, "/hostings/restore"));
        assert!(invalidates(&Method::POST, "/hostings/regguard"));
        assert!(invalidates(&Method::POST, "/profiles/3/apply"));
        assert!(!invalidates(&Method::POST, "/hostings/notes"));
        assert!(!invalidates(&Method::POST, "/hostings/vhost-options"));
        assert!(!invalidates(&Method::POST, "/hostings/ftp/account/reset"));
        assert!(!invalidates(&Method::POST, "/hostings/backups/delete-bulk"));
    }
}
