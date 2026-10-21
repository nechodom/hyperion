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
//! Optionally the node also raises `pm.max_children` itself (see
//! [`decide_auto`]): opt-in per site, bounded by the operator's ceiling and
//! by the node's RAM, and stepped back down after a quiet fortnight. More
//! workers only help when the box has room for them; when one slow script
//! holds them all, more workers just queue on it too — hence opt-in.
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
/// How far back the count goes.
pub const WINDOW_SECS: i64 = 24 * HOUR_SECS;
/// Slow requests (newest) an alert summarises.
pub const SLOWLOG_ENTRIES: usize = 200;

const HOUR_SECS: i64 = 3600;

/// What the node remembers per hosting.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// Last time the pool was seen at its limit.
    #[serde(default)]
    pub last_at: i64,
    /// `(hour, hits)` for the hours of the last [`WINDOW_SECS`], `hour` being
    /// `unix / 3600`, oldest first. A rolling window rather than "today":
    /// a UTC day reset at midnight, so the alert after a bad evening said
    /// "1× today".
    #[serde(default)]
    pub hours: Vec<(i64, i64)>,
    /// Last alert sent.
    #[serde(default)]
    pub alerted_at: i64,
    /// Before the rolling window: the UTC day `today` counted. Read once,
    /// to carry the count over; never written.
    #[serde(default, skip_serializing)]
    day: i64,
    #[serde(default, skip_serializing)]
    today: i64,
}

impl State {
    pub fn parse(s: &str) -> Option<State> {
        let mut st: State = serde_json::from_str(s).ok()?;
        if st.hours.is_empty() && st.today > 0 && st.day == st.last_at.div_euclid(86_400) {
            st.hours.push((st.last_at.div_euclid(HOUR_SECS), st.today));
        }
        st.day = 0;
        st.today = 0;
        Some(st)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Record `hits` seen at `now`.
    pub fn record(&mut self, now: i64, hits: i64) {
        if hits <= 0 {
            return;
        }
        let hour = now.div_euclid(HOUR_SECS);
        match self.hours.last_mut() {
            Some((h, n)) if *h == hour => *n += hits,
            _ => self.hours.push((hour, hits)),
        }
        let oldest = hour - WINDOW_SECS / HOUR_SECS + 1;
        self.hours.retain(|&(h, _)| h >= oldest);
        self.last_at = now;
    }

    /// Times the limit was hit in the last 24 hours, as of `now`.
    pub fn hits_24h(&self, now: i64) -> i64 {
        let oldest = now.div_euclid(HOUR_SECS) - WINDOW_SECS / HOUR_SECS + 1;
        self.hours
            .iter()
            .filter(|&&(h, _)| h >= oldest)
            .map(|&(_, n)| n)
            .sum()
    }

    /// Whether a hit just recorded at `now` is worth an alert.
    pub fn should_alert(&self, now: i64) -> bool {
        self.last_at == now && now - self.alerted_at >= ALERT_EVERY_SECS
    }
}

/// One script in the slow-request log, with how often it was there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowScript {
    /// Path under the site's document root (or the full path when it is
    /// not under it).
    pub script: String,
    pub count: i64,
    /// The function the request was waiting in most often (the top frame
    /// of FPM's backtrace), e.g. `curl_exec`.
    pub waiting_in: Option<String>,
}

/// The scripts that held workers longest, most frequent first, from the
/// newest [`SLOWLOG_ENTRIES`] entries of FPM's slow-request log:
///
/// ```text
/// [21-Oct-2026 10:49:14]  [pool alice_cz] pid 4242
/// script_filename = /home/alice/alice.cz/htdocs/wp-cron.php
/// [0x00007f2a] curl_exec() /home/alice/alice.cz/htdocs/wp-includes/Requests/src/Transport/Curl.php:205
/// ```
///
/// `root` (the site's htdocs) is cut off the front of each script.
pub fn slow_scripts(text: &str, root: &str, limit: usize) -> Vec<SlowScript> {
    // (script, top frame) per entry, in log order.
    let mut entries: Vec<(String, Option<String>)> = Vec::new();
    let mut in_entry = false;
    for line in text.lines() {
        let line = line.trim_end();
        if line.contains("[pool ") && line.contains("] pid ") {
            in_entry = true;
            entries.push((String::new(), None));
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some(cur) = entries.last_mut() else {
            continue;
        };
        if let Some(path) = line.strip_prefix("script_filename = ") {
            cur.0 = path.trim().to_string();
        } else if line.starts_with("[0x") && cur.1.is_none() {
            cur.1 = line
                .split_once("] ")
                .and_then(|(_, rest)| rest.split_once('('))
                .map(|(f, _)| f.trim().to_string())
                .filter(|f| !f.is_empty());
        }
    }
    let root = root.trim_end_matches('/');
    let start = entries.len().saturating_sub(SLOWLOG_ENTRIES);
    let mut by_script: BTreeMap<String, (i64, BTreeMap<String, i64>)> = BTreeMap::new();
    for (script, frame) in entries.drain(start..) {
        if script.is_empty() {
            continue;
        }
        let rel = match script.strip_prefix(root) {
            Some(r) if !root.is_empty() && r.starts_with('/') => r.trim_start_matches('/'),
            _ => script.as_str(),
        };
        let e = by_script.entry(rel.to_string()).or_default();
        e.0 += 1;
        if let Some(f) = frame {
            *e.1.entry(f).or_insert(0) += 1;
        }
    }
    let mut out: Vec<SlowScript> = by_script
        .into_iter()
        .map(|(script, (count, frames))| SlowScript {
            script,
            count,
            waiting_in: frames
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
                .map(|(f, _)| f),
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.script.cmp(&b.script)));
    out.truncate(limit);
    out
}

/// `wp-cron.php 14× (curl_exec), index.php 3×` — the alert's list.
pub fn slow_scripts_line(scripts: &[SlowScript]) -> String {
    scripts
        .iter()
        .map(|s| match &s.waiting_in {
            Some(f) => format!("{} {}× ({f})", s.script, s.count),
            None => format!("{} {}×", s.script, s.count),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `server reached pm.max_children` warnings in `text`, per pool name.
/// The pool name is the site's system user.
pub fn count_by_pool(text: &str) -> BTreeMap<String, i64> {
    count_by_pool_and_limit(text)
        .into_iter()
        .map(|(pool, by_limit)| (pool, by_limit.values().sum()))
        .collect()
}

/// [`count_by_pool`], split by the `max_children` each warning names
/// (`setting (5)`); 0 when it names none. The automation must not count a
/// warning written under a lower limit than the one now in force — a line
/// from before its own raise.
pub fn count_by_pool_and_limit(text: &str) -> BTreeMap<String, BTreeMap<i64, i64>> {
    const POOL: &str = "[pool ";
    const NEEDLE: &str = "server reached pm.max_children setting";
    let mut out: BTreeMap<String, BTreeMap<i64, i64>> = BTreeMap::new();
    for line in text.lines() {
        let Some(at) = line.find(POOL) else { continue };
        let rest = &line[at + POOL.len()..];
        let Some(end) = rest.find(']') else { continue };
        let Some(n) = rest[end..].find(NEEDLE) else {
            continue;
        };
        let pool = rest[..end].trim();
        if pool.is_empty() {
            continue;
        }
        let after = rest[end + n + NEEDLE.len()..].trim_start();
        let limit = after
            .strip_prefix('(')
            .and_then(|a| a.split_once(')'))
            .and_then(|(v, _)| v.trim().parse::<i64>().ok())
            .unwrap_or(0);
        *out.entry(pool.to_string())
            .or_default()
            .entry(limit)
            .or_insert(0) += 1;
    }
    out
}

/// Hits in `by_limit` written under a limit of at least `current`. A warning
/// that names no limit counts: it cannot be told apart from a fresh one.
pub fn hits_at_or_above(by_limit: &BTreeMap<i64, i64>, current: i64) -> i64 {
    by_limit
        .iter()
        .filter(|&(&limit, _)| limit == 0 || limit >= current)
        .map(|(_, &n)| n)
        .sum()
}

/// `"on"` turns the automatic `max_children` on for a hosting.
pub const KV_AUTO: &str = "php.workers_auto";
/// The most workers the automation may give a hosting.
pub const KV_AUTO_MAX: &str = "php.workers_auto_max";
/// JSON-encoded [`AutoState`].
pub const KV_AUTO_STATE: &str = "php.workers_auto_state";
/// Ceiling when the operator has not set one.
pub const DEFAULT_AUTO_MAX: i64 = 20;
/// Highest ceiling the card accepts (the limits card's own max).
pub const AUTO_MAX_LIMIT: i64 = 200;
/// Workers one raise or one lowering adds or takes away.
pub const AUTO_STEP: i64 = 4;
/// Times the pool must run out (since the last change) before a raise: one
/// burst of traffic is not a reason to keep more workers around.
pub const RAISE_AFTER_HITS: i64 = 3;
/// Minimum gap between two changes, so the next step is decided on what the
/// NEW limit does.
pub const AUTO_COOLDOWN_SECS: i64 = 30 * 60;
/// Quiet period (no hit, no change) before one step back down.
pub const AUTO_LOWER_AFTER_SECS: i64 = 14 * 86_400;

/// What the node remembers per hosting for the automatic `max_children`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoState {
    /// The operator's own `max_children` — the floor a lowering returns to.
    /// Reset whenever someone sets it by hand.
    pub base: i64,
    /// Hits at the limit in force since the last change.
    #[serde(default)]
    pub pending_hits: i64,
    /// Last hit at the limit in force.
    #[serde(default)]
    pub last_full_at: i64,
    /// Last time the limit changed (by this automation or by hand).
    #[serde(default)]
    pub last_change_at: i64,
}

impl AutoState {
    pub fn parse(s: &str) -> Option<AutoState> {
        serde_json::from_str(s).ok()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// What the automatic `max_children` should do for one hosting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoStep {
    Nothing,
    Raise { to: i64 },
    Lower { to: i64 },
}

/// Decide one hosting's step. `ram_cap` is the most workers the node can
/// afford at the site's memory_limit (`None` when its RAM could not be read).
pub fn decide_auto(
    now: i64,
    current: i64,
    ceiling: i64,
    ram_cap: Option<i64>,
    st: &AutoState,
) -> AutoStep {
    let base = st.base;
    // The operator lowered the ceiling under a value this automation set.
    // Never below their own base: that one is theirs.
    let lower_bound = ceiling.max(base);
    if current > lower_bound {
        return AutoStep::Lower { to: lower_bound };
    }
    if st.pending_hits >= RAISE_AFTER_HITS {
        let cap = ceiling.min(ram_cap.unwrap_or(i64::MAX));
        if current >= cap || now - st.last_change_at < AUTO_COOLDOWN_SECS {
            return AutoStep::Nothing;
        }
        return AutoStep::Raise {
            to: (current + AUTO_STEP).min(cap),
        };
    }
    let quiet_since = st.last_full_at.max(st.last_change_at);
    if current > base && now - quiet_since >= AUTO_LOWER_AFTER_SECS {
        return AutoStep::Lower {
            to: (current - AUTO_STEP).max(base),
        };
    }
    AutoStep::Nothing
}

/// Workers the node can afford: three quarters of its RAM, each worker
/// allowed the site's whole memory_limit. The same bound the automatic
/// memory_limit keeps from its side (`phpmem::ram_cap_mb`).
pub fn ram_cap_children(mem_total_mb: i64, memory_mb: i64) -> Option<i64> {
    if mem_total_mb <= 0 {
        return None;
    }
    Some((mem_total_mb * 3 / 4 / memory_mb.max(1)).max(1))
}

/// The operator's own `max_children` once a limits-card save lands. Mirrors
/// `set_limits`: a value different from the stored one becomes the new
/// floor; resubmitting the stored (possibly raised) value keeps the floor
/// already in `st`.
pub fn floor_after_save(typed: i64, stored: Option<i64>, st: Option<&AutoState>) -> i64 {
    match (stored, st) {
        (Some(stored), Some(s)) if typed == stored && s.base > 0 => s.base,
        _ => typed,
    }
}

/// A ceiling at or under the floor leaves the automation nothing to raise to.
pub fn ceiling_leaves_no_room(ceiling: i64, floor: i64) -> bool {
    ceiling <= floor
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
    fn counts_roll_over_24_hours_and_alerts_are_spaced() {
        let t0 = 20_000 * 86_400 + 22 * HOUR_SECS; // 22:00 UTC
        let mut st = State::default();
        st.record(t0 + 100, 3);
        assert_eq!(st.hits_24h(t0 + 100), 3);
        assert!(st.should_alert(t0 + 100));
        st.alerted_at = t0 + 100;

        st.record(t0 + 200, 1);
        assert_eq!(st.hits_24h(t0 + 200), 4);
        assert!(!st.should_alert(t0 + 200), "inside the alert spacing");
        assert!(
            !st.should_alert(t0 + 200 + ALERT_EVERY_SECS),
            "no new hit, no alert"
        );

        // Past UTC midnight the evening still counts.
        let t1 = t0 + 7 * HOUR_SECS;
        st.record(t1, 2);
        assert_eq!(st.hits_24h(t1), 6, "midnight does not reset the count");
        assert!(st.should_alert(t1));

        // A day later only the newer hour is left, and old hours are dropped.
        assert_eq!(st.hits_24h(t0 + 24 * HOUR_SECS + 100), 2);
        st.record(t1 + 30 * HOUR_SECS, 1);
        assert_eq!(st.hours.len(), 1);
        assert_eq!(st.hits_24h(t1 + 30 * HOUR_SECS), 1);
    }

    #[test]
    fn old_daily_state_carries_its_count_over() {
        let at = 20_000 * 86_400 + 5 * HOUR_SECS;
        let old = format!(r#"{{"last_at":{at},"day":20000,"today":22,"alerted_at":{at}}}"#);
        let st = State::parse(&old).unwrap();
        assert_eq!(st.hits_24h(at + 60), 22);
        assert!(!st.to_json().contains("today"));
        let stale = format!(r#"{{"last_at":{at},"day":19990,"today":22}}"#);
        assert_eq!(State::parse(&stale).unwrap().hits_24h(at), 0);
    }

    #[test]
    fn slow_scripts_ranks_what_holds_the_workers() {
        let log = "
[21-Oct-2026 10:49:14]  [pool alice_cz] pid 4242
script_filename = /home/alice/alice.cz/htdocs/wp-cron.php
[0x00007f2a00001] curl_exec() /home/alice/alice.cz/htdocs/wp-includes/Requests/src/Transport/Curl.php:205
[0x00007f2a00002] request() /home/alice/alice.cz/htdocs/wp-includes/Requests/src/Requests.php:469

[21-Oct-2026 10:50:14]  [pool alice_cz] pid 4243
script_filename = /home/alice/alice.cz/htdocs/index.php
[0x00007f2a00003] mysqli_query() /home/alice/alice.cz/htdocs/wp-includes/class-wpdb.php:2351

[21-Oct-2026 10:51:14]  [pool alice_cz] pid 4244
script_filename = /home/alice/alice.cz/htdocs/wp-cron.php
[0x00007f2a00004] curl_exec() /x.php:1

[21-Oct-2026 10:52:14]  [pool alice_cz] pid 4245
script_filename = /opt/elsewhere/run.php
";
        let s = slow_scripts(log, "/home/alice/alice.cz/htdocs/", 2);
        assert_eq!(
            s,
            [
                SlowScript {
                    script: "wp-cron.php".into(),
                    count: 2,
                    waiting_in: Some("curl_exec".into()),
                },
                SlowScript {
                    script: "/opt/elsewhere/run.php".into(),
                    count: 1,
                    waiting_in: None,
                },
            ]
        );
        assert_eq!(
            slow_scripts_line(&s),
            "wp-cron.php 2× (curl_exec), /opt/elsewhere/run.php 1×"
        );
        assert!(slow_scripts("", "/x", 3).is_empty());
    }

    #[test]
    fn hits_are_split_by_the_limit_they_were_written_under() {
        let log = "\
[06-Oct-2026 06:56:45] WARNING: [pool a_cz] server reached pm.max_children setting (10), consider raising it
[06-Oct-2026 06:57:45] WARNING: [pool a_cz] server reached pm.max_children setting (14), consider raising it
[06-Oct-2026 06:58:45] WARNING: [pool a_cz] server reached pm.max_children setting, consider raising it
";
        let by = count_by_pool_and_limit(log);
        let a = &by["a_cz"];
        assert_eq!(count_by_pool(log)["a_cz"], 3);
        assert_eq!(
            hits_at_or_above(a, 14),
            2,
            "the (10) line is from before the raise"
        );
        assert_eq!(hits_at_or_above(a, 10), 3);
    }

    #[test]
    fn auto_raises_after_repeated_hits_within_bounds() {
        let st = |pending: i64, change: i64| AutoState {
            base: 10,
            pending_hits: pending,
            last_full_at: 1_000_000,
            last_change_at: change,
        };
        let now = 1_000_000;
        assert_eq!(decide_auto(now, 10, 20, None, &st(2, 0)), AutoStep::Nothing);
        assert_eq!(
            decide_auto(now, 10, 20, None, &st(3, 0)),
            AutoStep::Raise { to: 14 }
        );
        // Ceiling and RAM both cap the step.
        assert_eq!(
            decide_auto(now, 18, 20, None, &st(3, 0)),
            AutoStep::Raise { to: 20 }
        );
        assert_eq!(
            decide_auto(now, 10, 20, Some(12), &st(3, 0)),
            AutoStep::Raise { to: 12 }
        );
        assert_eq!(decide_auto(now, 20, 20, None, &st(9, 0)), AutoStep::Nothing);
        assert_eq!(
            decide_auto(now, 12, 20, Some(12), &st(9, 0)),
            AutoStep::Nothing
        );
        // Cooldown.
        assert_eq!(
            decide_auto(now, 14, 20, None, &st(5, now - 60)),
            AutoStep::Nothing
        );
    }

    #[test]
    fn auto_steps_back_after_a_quiet_fortnight_never_below_base() {
        let now = 100 * 86_400;
        let quiet = AutoState {
            base: 10,
            pending_hits: 0,
            last_full_at: now - AUTO_LOWER_AFTER_SECS,
            last_change_at: now - AUTO_LOWER_AFTER_SECS - 5,
        };
        assert_eq!(
            decide_auto(now, 16, 20, None, &quiet),
            AutoStep::Lower { to: 12 }
        );
        assert_eq!(
            decide_auto(now, 12, 20, None, &quiet),
            AutoStep::Lower { to: 10 }
        );
        assert_eq!(decide_auto(now, 10, 20, None, &quiet), AutoStep::Nothing);
        let recent = AutoState {
            last_full_at: now - 3600,
            ..quiet.clone()
        };
        assert_eq!(decide_auto(now, 16, 20, None, &recent), AutoStep::Nothing);
        // Ceiling lowered under a raised value: straight down to it.
        assert_eq!(
            decide_auto(now, 18, 12, None, &recent),
            AutoStep::Lower { to: 12 }
        );
        // ...but never under the operator's own value.
        assert_eq!(
            decide_auto(now, 18, 8, None, &recent),
            AutoStep::Lower { to: 10 }
        );
    }

    #[test]
    fn ram_cap_and_floor_helpers() {
        assert_eq!(ram_cap_children(4096, 256), Some(12));
        assert_eq!(ram_cap_children(0, 256), None);
        assert_eq!(ram_cap_children(512, 1024), Some(1));
        let st = AutoState {
            base: 10,
            ..Default::default()
        };
        assert_eq!(floor_after_save(14, Some(14), Some(&st)), 10);
        assert_eq!(floor_after_save(12, Some(14), Some(&st)), 12);
        assert_eq!(floor_after_save(14, None, None), 14);
        assert!(ceiling_leaves_no_room(10, 10));
    }
}
