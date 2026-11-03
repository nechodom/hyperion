//! WordPress cron from the command line instead of from visitors.
//!
//! WP-Cron normally fires by a site requesting its own `wp-cron.php` during
//! somebody's page view: one more PHP worker taken, at the moment the site
//! has visitors. On a pool of five that is a real share of the capacity. So
//! the node runs `wp cron event run --due-now` itself, as the site's user, and
//! a small module of the Hyperion plugin stops WordPress spawning its own.
//!
//! Order matters. The module lands only after the command line has worked on
//! that site, and goes away after [`MAX_FAILS`] failures in a row, so a site
//! whose plugins do not run under wp-cli goes back to how it was rather than
//! losing cron. Pure: the state. The node does the I/O.

use serde::{Deserialize, Serialize};

/// `"off"` keeps a site on WordPress's own cron. Anything else means on.
pub const KV_ENABLED: &str = "wp.system_cron";
/// JSON-encoded [`State`].
pub const KV_STATE: &str = "wp.system_cron_state";
/// How often the node runs a site's due events.
pub const RUN_EVERY_SECS: i64 = 5 * 60;
/// Sites running their cron at once. Each boots all of WordPress.
pub const CONCURRENCY: usize = 3;
/// Longest one run may take. Long enough for a backup plugin's slice of work,
/// short enough that a hung HTTP call in an event cannot hold a slot for good.
pub const RUN_TIMEOUT_SECS: u64 = 10 * 60;
/// Failures in a row before the site goes back to WordPress's own cron.
pub const MAX_FAILS: i64 = 3;
/// How long until a site that went back is tried again.
pub const RETRY_AFTER_SECS: i64 = 24 * 3600;

/// Whether the system cron is on for a site, from the stored [`KV_ENABLED`].
pub fn enabled(stored: Option<&str>) -> bool {
    stored != Some("off")
}

/// What the node remembers per hosting.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// Last run that worked.
    #[serde(default)]
    pub last_ok_at: i64,
    /// Failures in a row.
    #[serde(default)]
    pub fails: i64,
    /// No run before this; set when the site went back to its own cron.
    #[serde(default)]
    pub retry_after: i64,
}

impl State {
    pub fn parse(s: &str) -> Option<State> {
        serde_json::from_str(s).ok()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Whether a run is due at `now`, given the last one.
    pub fn due(&self, now: i64, last_run_at: i64) -> bool {
        now >= self.retry_after && now - last_run_at >= RUN_EVERY_SECS
    }

    pub fn record_ok(&mut self, now: i64) {
        self.last_ok_at = now;
        self.fails = 0;
        self.retry_after = 0;
    }

    /// Record a failure. True when this one sends the site back to its own
    /// cron.
    pub fn record_failure(&mut self, now: i64) -> bool {
        self.fails += 1;
        if self.fails < MAX_FAILS {
            return false;
        }
        self.fails = 0;
        self.retry_after = now + RETRY_AFTER_SECS;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_unless_turned_off() {
        assert!(enabled(None));
        assert!(enabled(Some("on")));
        assert!(!enabled(Some("off")));
    }

    #[test]
    fn repeated_failure_goes_back_and_a_success_resets() {
        let mut st = State::default();
        assert!(!st.record_failure(100));
        assert!(!st.record_failure(200));
        st.record_ok(300);
        assert_eq!((st.fails, st.last_ok_at), (0, 300));

        assert!(!st.record_failure(400));
        assert!(!st.record_failure(500));
        assert!(st.record_failure(600));
        assert!(!st.due(600 + RUN_EVERY_SECS, 0), "waits for the retry");
        assert!(st.due(600 + RETRY_AFTER_SECS, 0));
        st.record_ok(600 + RETRY_AFTER_SECS);
        assert_eq!(st.retry_after, 0);
    }

    #[test]
    fn due_every_few_minutes() {
        let st = State::default();
        assert!(st.due(1000, 0));
        assert!(!st.due(1000, 1000 - RUN_EVERY_SECS + 1));
        assert!(st.due(1000, 1000 - RUN_EVERY_SECS));
    }
}
