//! "The pool ran out of PHP workers" — read from PHP-FPM's own log.
//!
//! When every `pm.max_children` worker of a pool is busy, FPM queues the
//! next request and logs
//!
//! ```text
//! [06-Oct-2026 10:49:14] WARNING: [pool example_cz] server reached pm.max_children setting (5), consider raising it
//! ```
//!
//! to `/var/log/php<ver>-fpm.log`. The site is not erroring: it is slow, and
//! once the queue outgrows nginx's FastCGI timeout it 502s or 504s. Nothing
//! in the site's own logs says why, and the automatic memory_limit cannot
//! help — memory is not what ran out. So this is detected and reported on
//! its own, with the two ways out: more workers, or (usually) finding what
//! keeps them busy in the slow-request log.
//!
//! Pure: parsing and the per-hosting state. The node does the I/O. The
//! state lives in the OWNING node's `hosting_kv`, like the pool.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// JSON-encoded [`State`].
pub const KV_STATE: &str = "php.workers_full";
/// How often one site is reported again while it keeps hitting the limit.
pub const ALERT_EVERY_SECS: i64 = 6 * 3600;
/// Most of the FPM log read per tick.
pub const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

const DAY_SECS: i64 = 86_400;

/// What the node remembers per hosting.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// Last time the pool was seen at its limit.
    #[serde(default)]
    pub last_at: i64,
    /// UTC day number (`unix / 86400`) that `today` counts.
    #[serde(default)]
    pub day: i64,
    /// Times the limit was hit on `day`.
    #[serde(default)]
    pub today: i64,
    /// Last alert sent.
    #[serde(default)]
    pub alerted_at: i64,
}

impl State {
    pub fn parse(s: &str) -> Option<State> {
        serde_json::from_str(s).ok()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Record `hits` seen at `now`.
    pub fn record(&mut self, now: i64, hits: i64) {
        if hits <= 0 {
            return;
        }
        let day = now.div_euclid(DAY_SECS);
        if day != self.day {
            self.day = day;
            self.today = 0;
        }
        self.today += hits;
        self.last_at = now;
    }

    /// Times the limit was hit today (UTC), as of `now`.
    pub fn hits_today(&self, now: i64) -> i64 {
        if self.day == now.div_euclid(DAY_SECS) {
            self.today
        } else {
            0
        }
    }

    /// Whether a hit just recorded at `now` is worth an alert.
    pub fn should_alert(&self, now: i64) -> bool {
        self.last_at == now && now - self.alerted_at >= ALERT_EVERY_SECS
    }
}

/// `server reached pm.max_children` warnings in `text`, per pool name.
/// The pool name is the site's system user.
pub fn count_by_pool(text: &str) -> BTreeMap<String, i64> {
    const POOL: &str = "[pool ";
    const NEEDLE: &str = "server reached pm.max_children setting";
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some(at) = line.find(POOL) else { continue };
        let rest = &line[at + POOL.len()..];
        let Some(end) = rest.find(']') else { continue };
        if !rest[end..].contains(NEEDLE) {
            continue;
        }
        let pool = rest[..end].trim();
        if pool.is_empty() {
            continue;
        }
        *out.entry(pool.to_string()).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_the_real_fpm_warning_per_pool() {
        let log = "\
[06-Oct-2026 06:56:45] WARNING: [pool dluhopisar_cz] server reached pm.max_children setting (5), consider raising it
[06-Oct-2026 06:57:50] WARNING: [pool dluhopisar_cz] server reached pm.max_children setting (5), consider raising it
[06-Oct-2026 10:49:14] WARNING: [pool masarykovazs_eu] server reached pm.max_children setting (5), consider raising it
[06-Oct-2026 10:50:00] NOTICE: [pool dluhopisar_cz] child 1234 started
[06-Oct-2026 10:50:01] WARNING: [pool other_cz] seems busy (you may need to increase pm.start_servers, or pm.min/max_spare_servers)
";
        let c = count_by_pool(log);
        assert_eq!(c.get("dluhopisar_cz"), Some(&2));
        assert_eq!(c.get("masarykovazs_eu"), Some(&1));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn counts_reset_each_day_and_alerts_are_spaced() {
        let day0 = 20_000 * DAY_SECS;
        let mut st = State::default();
        st.record(day0 + 100, 3);
        assert_eq!(st.hits_today(day0 + 100), 3);
        assert!(st.should_alert(day0 + 100));
        st.alerted_at = day0 + 100;

        st.record(day0 + 200, 1);
        assert_eq!(st.hits_today(day0 + 200), 4);
        assert!(!st.should_alert(day0 + 200), "inside the alert spacing");
        assert!(
            !st.should_alert(day0 + 200 + ALERT_EVERY_SECS),
            "no new hit, no alert"
        );

        st.record(day0 + DAY_SECS + 5, 2);
        assert_eq!(
            st.hits_today(day0 + DAY_SECS + 5),
            2,
            "a new day starts from zero"
        );
        assert!(st.should_alert(day0 + DAY_SECS + 5));
        assert_eq!(st.hits_today(day0 + 3 * DAY_SECS), 0);
    }
}
