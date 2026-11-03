//! "The pool ran out of PHP workers" — read from PHP-FPM's own log.
//!
//! When every `pm.max_children` worker of a pool is busy, FPM queues the
//! next request and logs
//!
//! ```text
//! [06-Oct-2026 10:49:14] WARNING: [pool example_cz] server reached pm.max_children setting (5), consider raising it
//! ```
//!
//! to `/var/log/php<ver>-fpm.log`. That line is a CAUSE, not a symptom: FPM
//! writes it when a once-a-second check finds no idle worker, so it says
//! nothing about how long that lasted or whether anybody waited. A site that
//! logs it five times a day may never have made a visitor notice, so a hit
//! alone is recorded for the limits card and alerts nobody.
//!
//! What a visitor felt is in the site's access log: [`count_impact`] counts
//! 502/504 answers and front-end pages that took over [`WAIT_SECS`], while
//! the pool has recently been full. The memory automation cannot help here —
//! memory is not what ran out.
//!
//! The node also raises `pm.max_children` itself (see [`decide_auto`]): on
//! unless turned off per site, bounded by the site's ceiling, by what the
//! node can spare and by the site's share of it (see [`raise_room`]), handed
//! back when it takes CPU from the others ([`over_share`]), and stepped back
//! down after a quiet fortnight. An alert therefore means one thing: visitors were
//! affected and the automation can do nothing more, see [`State::should_alert`].
//!
//! Pure: parsing and the per-hosting state. The node does the I/O. The
//! state lives in the OWNING node's `hosting_kv`, like the pool.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// JSON-encoded [`State`].
pub const KV_STATE: &str = "php.workers_full";
/// How often one site is reported again while visitors keep being affected.
pub const ALERT_EVERY_SECS: i64 = 24 * 3600;
/// A front-end request that took this long while the pool was full counts as
/// a visitor who waited.
pub const WAIT_SECS: f64 = 10.0;
/// 502/504 answers in [`IMPACT_WINDOW_HOURS`] that make it an incident.
pub const IMPACT_ERRORS: i64 = 3;
/// Waits in [`IMPACT_WINDOW_HOURS`] that make it an incident.
pub const IMPACT_WAITS: i64 = 10;
/// Clock hours (this one and the one before) an incident is judged over.
pub const IMPACT_WINDOW_HOURS: i64 = 2;
/// How long after the last sign of trouble the access log is still read. FPM
/// writes its warning once per episode, so a long one shows a single line:
/// each affected visitor seen extends this.
pub const WATCH_SECS: i64 = 15 * 60;
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
    /// `(hour, errors, waits)`: what visitors got while the pool was full,
    /// kept like `hours`.
    #[serde(default)]
    pub impact: Vec<(i64, i64, i64)>,
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

    /// Record what visitors got, seen at `now`.
    pub fn record_impact(&mut self, now: i64, errors: i64, waits: i64) {
        if errors <= 0 && waits <= 0 {
            return;
        }
        let hour = now.div_euclid(HOUR_SECS);
        match self.impact.last_mut() {
            Some((h, e, w)) if *h == hour => {
                *e += errors.max(0);
                *w += waits.max(0);
            }
            _ => self.impact.push((hour, errors.max(0), waits.max(0))),
        }
        let oldest = hour - WINDOW_SECS / HOUR_SECS + 1;
        self.impact.retain(|&(h, _, _)| h >= oldest);
    }

    /// `(errors, waits)` over the last `hours` clock hours, as of `now`.
    fn impact_within(&self, now: i64, hours: i64) -> (i64, i64) {
        let oldest = now.div_euclid(HOUR_SECS) - hours + 1;
        self.impact
            .iter()
            .filter(|&&(h, _, _)| h >= oldest)
            .fold((0, 0), |(e, w), &(_, de, dw)| (e + de, w + dw))
    }

    /// `(errors, waits)` over the last 24 hours, as of `now`.
    pub fn impact_24h(&self, now: i64) -> (i64, i64) {
        self.impact_within(now, WINDOW_SECS / HOUR_SECS)
    }

    /// `(errors, waits)` the current incident is judged on.
    pub fn impact_recent(&self, now: i64) -> (i64, i64) {
        self.impact_within(now, IMPACT_WINDOW_HOURS)
    }

    /// Enough visitors were affected lately to call it an incident. A single
    /// slow page or a single 504 is not one: those happen on a healthy site.
    pub fn is_incident(&self, now: i64) -> bool {
        let (errors, waits) = self.impact_recent(now);
        errors >= IMPACT_ERRORS || waits >= IMPACT_WAITS
    }

    /// Whether to put this in front of a person: visitors were affected,
    /// the automation has nothing left to try, and they were not told today.
    pub fn should_alert(&self, now: i64, automation_can_help: bool) -> bool {
        !automation_can_help && self.is_incident(now) && now - self.alerted_at >= ALERT_EVERY_SECS
    }
}

/// `(errors, waits)` in lines of a site's access log, in the node's
/// `hyperion_timed` format (`combined` + `$request_time` last):
///
/// ```text
/// 1.2.3.4 - - [06/Oct/2026:10:49:14 +0200] "GET / HTTP/2.0" 200 512 "-" "UA" 12.345
/// ```
///
/// An error is a 502 or 504 anywhere but `wp-cron.php`, which no visitor
/// waits for. A wait is a GET or HEAD outside wp-admin, the login page and
/// cron that took [`WAIT_SECS`]: an import in wp-admin taking a minute is
/// that import, not a queue. A line in another format has no request time
/// and cannot count as a wait. The file sits in a tree the tenant can write,
/// so a forged line can only ever trigger that tenant's own alert and raise.
pub fn count_impact(text: &str) -> (i64, i64) {
    let (mut errors, mut waits) = (0, 0);
    for line in text.lines() {
        // The request is the first quoted field; nginx escapes quotes inside.
        let Some((_, rest)) = line.split_once('"') else {
            continue;
        };
        let Some((request, after)) = rest.split_once('"') else {
            continue;
        };
        let mut req = request.split_whitespace();
        let method = req.next().unwrap_or("");
        let path = req.next().unwrap_or("");
        let status = after.split_whitespace().next().unwrap_or("");
        let is_cron = path.starts_with("/wp-cron.php");
        if matches!(status, "502" | "504") {
            if !is_cron {
                errors += 1;
            }
            continue;
        }
        let waited = line
            .rsplit(char::is_whitespace)
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .is_some_and(|t| t >= WAIT_SECS);
        let front_end = matches!(method, "GET" | "HEAD")
            && !is_cron
            && !path.starts_with("/wp-admin")
            && !path.starts_with("/wp-login.php");
        if waited && front_end {
            waits += 1;
        }
    }
    (errors, waits)
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

/// `"off"` turns the automatic `max_children` off for a hosting. Anything
/// else, absence included, means on: see [`auto_enabled`].
pub const KV_AUTO: &str = "php.workers_auto";
/// The most workers the automation may give a hosting.
pub const KV_AUTO_MAX: &str = "php.workers_auto_max";
/// JSON-encoded [`AutoState`].
pub const KV_AUTO_STATE: &str = "php.workers_auto_state";
/// Ceiling when the operator has not set one, unless the site's own value
/// is already near it: see [`auto_ceiling`].
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
/// Share of the node's RAM all sites' extra workers may be promised together:
/// `total / this`. A worst case rather than a measurement of today, because
/// every site's raise stays in force until a quiet fortnight passes.
pub const NODE_EXTRA_RAM_DIVISOR: i64 = 4;
/// RAM that must stay free after a raise: `total / this`.
pub const NODE_FREE_RAM_DIVISOR: i64 = 5;
/// The most of the node's RAM one site's workers may be raised into:
/// `total / this`. What keeps one busy site from taking the room the others
/// need, however much of it happens to be free today.
pub const SITE_RAM_SHARE_DIVISOR: i64 = 3;
/// CPU share of the whole node (percent) at which a site gets no more
/// workers. And, when the node is short of CPU ([`CPU_BUSY_PCT`]), the share
/// at which a raised site gives workers back: see [`over_share`].
pub const SITE_CPU_SHARE_PCT: i64 = 50;
/// Worker size assumed for a pool with no worker running to measure.
pub const FALLBACK_WORKER_MB: i64 = 128;
/// CPU pressure (`some avg60`, percent) above which a raise waits: more
/// workers on a box short of CPU only make every request slower.
pub const CPU_BUSY_PCT: i64 = 70;

/// Whether the automatic `max_children` is on, from the stored [`KV_AUTO`].
/// On unless somebody turned it off: "solves itself, within limits" is the
/// point, and the limits do not depend on the operator ticking anything.
pub fn auto_enabled(stored: Option<&str>) -> bool {
    stored != Some("off")
}

/// The site's ceiling: the stored one, else [`DEFAULT_AUTO_MAX`] or two steps
/// over the site's own value when that is already near it, so a site given 20
/// workers by hand still has room without anybody configuring anything.
pub fn auto_ceiling(stored: Option<i64>, floor: i64) -> i64 {
    stored
        .unwrap_or_else(|| DEFAULT_AUTO_MAX.max(floor + 2 * AUTO_STEP))
        .clamp(1, AUTO_MAX_LIMIT)
}

/// Why a site cannot get another worker right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaiseBlock {
    /// The automation is off for this site.
    Off,
    /// The site's own ceiling.
    Ceiling,
    /// All workers at the site's memory_limit would not fit the node.
    SiteRam,
    /// The site already has its share of the node (RAM or CPU).
    SiteShare,
    /// The node's budget for extra workers is spent, or too little is free.
    NodeRam,
    /// The node is short of CPU.
    NodeCpu,
}

/// What the node looks like to a raise. `None` memory figures mean they could
/// not be read (off Linux): those bounds are skipped rather than guessed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeFacts {
    pub mem_total_mb: Option<i64>,
    pub mem_available_mb: Option<i64>,
    /// What every site's workers above its own value could use together.
    pub extra_committed_mb: i64,
    /// `some avg60` CPU pressure, percent.
    pub cpu_pressure_pct: i64,
}

/// How far a site may go now, and what stops it going further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaiseRoom {
    pub cap: i64,
    /// Set when `cap` leaves the site no room to rise.
    pub blocked: Option<RaiseBlock>,
}

/// The most workers one site may have right now. `worker_mb` is what one of
/// its workers uses ([`worker_size_mb`]), `site_cpu_pct` its share of the
/// whole node's CPU over the last minute.
///
/// Per-site RAM alone cannot protect the box: fifty sites each within three
/// quarters of it are far beyond it together, and one site within it can
/// still leave the others nothing. So a raise also has to fit the site's
/// share of the node, the node's budget for extra workers, and leave a share
/// of RAM free today.
pub fn raise_room(
    current: i64,
    ceiling: i64,
    memory_mb: i64,
    worker_mb: i64,
    site_cpu_pct: i64,
    node: &NodeFacts,
) -> RaiseRoom {
    let worker_mb = worker_mb.max(1);
    let site_ram = node
        .mem_total_mb
        .and_then(|t| ram_cap_children(t, memory_mb))
        .unwrap_or(i64::MAX);
    let site_share = node
        .mem_total_mb
        .map_or(i64::MAX, |t| t / SITE_RAM_SHARE_DIVISOR / worker_mb);
    let budget = node.mem_total_mb.map_or(i64::MAX, |t| {
        (t / NODE_EXTRA_RAM_DIVISOR - node.extra_committed_mb) / worker_mb
    });
    let free = match (node.mem_total_mb, node.mem_available_mb) {
        (Some(t), Some(a)) => (a - t / NODE_FREE_RAM_DIVISOR) / worker_mb,
        _ => i64::MAX,
    };
    let node_cap = current.saturating_add(budget.min(free).max(0));
    let cap = ceiling.min(site_ram).min(site_share).min(node_cap);
    if current < cap {
        let cpu = if site_cpu_pct >= SITE_CPU_SHARE_PCT {
            Some(RaiseBlock::SiteShare)
        } else if node.cpu_pressure_pct >= CPU_BUSY_PCT {
            Some(RaiseBlock::NodeCpu)
        } else {
            None
        };
        if cpu.is_some() {
            return RaiseRoom {
                cap: current,
                blocked: cpu,
            };
        }
    }
    let blocked = if current < cap {
        None
    } else if cap == ceiling {
        Some(RaiseBlock::Ceiling)
    } else if cap == site_ram {
        Some(RaiseBlock::SiteRam)
    } else if cap == site_share {
        Some(RaiseBlock::SiteShare)
    } else {
        Some(RaiseBlock::NodeRam)
    };
    RaiseRoom { cap, blocked }
}

/// A site the automation raised is taking the node from the others: the node
/// is short of CPU and this site has its share of it. It gives one step back
/// (the cooldown letting the effect show before another), never below the
/// operator's own value. A site at that value is never touched: only what
/// the automation gave, it can take away.
pub fn over_share(
    now: i64,
    current: i64,
    site_cpu_pct: i64,
    node_cpu_pressure_pct: i64,
    st: &AutoState,
) -> Option<i64> {
    (st.base > 0
        && current > st.base
        && site_cpu_pct >= SITE_CPU_SHARE_PCT
        && node_cpu_pressure_pct >= CPU_BUSY_PCT
        && now - st.last_change_at >= AUTO_COOLDOWN_SECS)
        .then(|| (current - AUTO_STEP).max(st.base))
}

/// One pool's workers, measured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolMemory {
    pub workers: i64,
    /// The largest worker's proportional set size. PSS because RSS counts
    /// OPcache's shared memory once per worker, and the largest because a
    /// raise has to fit the heavy pages, not the average one.
    pub largest_mb: i64,
}

/// What to assume one worker of a pool uses: measured when any is running,
/// never more than the pool's memory_limit allows, else a modest guess.
pub fn worker_size_mb(measured: Option<PoolMemory>, memory_mb: i64) -> i64 {
    match measured {
        Some(m) if m.workers > 0 && m.largest_mb > 0 => m.largest_mb,
        _ => FALLBACK_WORKER_MB.min(memory_mb.max(1)),
    }
}

/// The pool name of a process, from its `/proc/<pid>/cmdline`
/// (`php-fpm: pool example_cz`, padded with NULs or spaces).
pub fn pool_of_cmdline(cmdline: &str) -> Option<&str> {
    cmdline
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .strip_prefix("php-fpm: pool ")
        .map(|p| p.trim_matches(|c: char| c == '\0' || c.is_whitespace()))
        .filter(|p| !p.is_empty())
}

/// `Pss:` in MiB from `/proc/<pid>/smaps_rollup`.
pub fn pss_mb(smaps_rollup: &str) -> Option<i64> {
    smaps_rollup
        .lines()
        .find_map(|l| l.strip_prefix("Pss:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kib| kib.parse::<i64>().ok())
        .map(|kib| kib / 1024)
}

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
/// afford ([`raise_room`]; `None` when that could not be worked out).
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
    fn counts_roll_over_24_hours() {
        let t0 = 20_000 * 86_400 + 22 * HOUR_SECS; // 22:00 UTC
        let mut st = State::default();
        st.record(t0 + 100, 3);
        st.record(t0 + 200, 1);
        assert_eq!(st.hits_24h(t0 + 200), 4);

        // Past UTC midnight the evening still counts.
        let t1 = t0 + 7 * HOUR_SECS;
        st.record(t1, 2);
        assert_eq!(st.hits_24h(t1), 6, "midnight does not reset the count");

        // A day later only the newer hour is left, and old hours are dropped.
        assert_eq!(st.hits_24h(t0 + 24 * HOUR_SECS + 100), 2);
        st.record(t1 + 30 * HOUR_SECS, 1);
        assert_eq!(st.hours.len(), 1);
        assert_eq!(st.hits_24h(t1 + 30 * HOUR_SECS), 1);
    }

    #[test]
    fn a_full_pool_alone_never_alerts() {
        let t = 20_000 * 86_400;
        let mut st = State::default();
        st.record(t, 500);
        assert!(!st.is_incident(t));
        assert!(!st.should_alert(t, false), "nobody was affected");
    }

    #[test]
    fn an_incident_alerts_only_when_the_automation_is_out_of_options() {
        let t = 20_000 * 86_400 + 30 * 60;
        let mut st = State::default();
        st.record_impact(t, IMPACT_ERRORS - 1, IMPACT_WAITS - 1);
        assert!(!st.is_incident(t), "a slow page or two is not an incident");
        st.record_impact(t, 1, 0);
        assert!(st.is_incident(t));
        assert!(!st.should_alert(t, true), "it can still raise the pool");
        assert!(st.should_alert(t, false));

        st.alerted_at = t;
        st.record_impact(t + 3600, 5, 5);
        assert!(!st.should_alert(t + 3600, false), "already told today");
        assert_eq!(st.impact_24h(t + 3600), (8, 14));
        st.record_impact(t + ALERT_EVERY_SECS, 5, 5);
        assert!(st.should_alert(t + ALERT_EVERY_SECS, false));

        // An old incident does not alert on a quiet day.
        assert!(!st.should_alert(t + 3 * ALERT_EVERY_SECS, false));
        st.record_impact(t + 3 * ALERT_EVERY_SECS, 1, 0);
        assert_eq!(st.impact.len(), 1, "old hours are dropped");
        assert!(!st.is_incident(t + 3 * ALERT_EVERY_SECS));
    }

    #[test]
    fn an_incident_spanning_an_hour_boundary_still_adds_up() {
        let t = 20_000 * 86_400 + 59 * 60;
        let mut st = State::default();
        st.record_impact(t, 2, 0);
        st.record_impact(t + 120, 1, 0);
        assert!(st.is_incident(t + 120));
    }

    #[test]
    fn state_without_impact_still_parses() {
        let st = State::parse(r#"{"last_at":5,"hours":[[1,2]],"alerted_at":3}"#).unwrap();
        assert!(st.impact.is_empty());
    }

    #[test]
    fn impact_counts_what_a_visitor_felt() {
        let line = |req: &str, status: u32, time: &str| {
            format!(
                "1.2.3.4 - - [06/Oct/2026:10:49:14 +0200] \"{req} HTTP/2.0\" {status} 512 \"-\" \"Mozilla/5.0 (X; \\x22q\\x22)\" {time}\n"
            )
        };
        let mut log = String::new();
        log += &line("GET /", 200, "0.120"); // fine
        log += &line("GET /shop", 200, "12.5"); // wait
        log += &line("HEAD /", 200, "10.000"); // wait
        log += &line("GET /", 499, "30.1"); // gave up waiting
        log += &line("GET /", 502, "0.001"); // error
        log += &line("POST /checkout", 504, "60.0"); // error, not also a wait
        log += &line("GET /wp-admin/admin.php?page=x", 502, "1.0"); // editors count
        log += &line("POST /checkout", 200, "15.0"); // a slow POST is not a queue
        log += &line("GET /wp-admin/import.php", 200, "90.0");
        log += &line("GET /wp-login.php", 200, "11.0");
        log += &line("GET /wp-cron.php?doing_wp_cron", 200, "120.0");
        log += &line("POST /wp-cron.php", 504, "120.0");
        // Plain `combined` has no request time, and junk is skipped.
        log += "1.2.3.4 - - [x] \"GET / HTTP/1.1\" 200 5 \"-\" \"UA 99\"\n";
        log += "garbage\n\"unterminated\n";
        assert_eq!(count_impact(&log), (3, 3));
    }

    #[test]
    fn auto_is_on_unless_turned_off() {
        assert!(auto_enabled(None));
        assert!(auto_enabled(Some("on")));
        assert!(!auto_enabled(Some("off")));
    }

    #[test]
    fn the_default_ceiling_leaves_room_above_a_hand_set_value() {
        assert_eq!(auto_ceiling(None, 5), DEFAULT_AUTO_MAX);
        assert_eq!(auto_ceiling(None, 30), 38);
        assert_eq!(auto_ceiling(None, 199), AUTO_MAX_LIMIT);
        assert_eq!(auto_ceiling(Some(9), 30), 9, "a stored ceiling is theirs");
    }

    fn node(total: i64, available: i64, extra: i64) -> NodeFacts {
        NodeFacts {
            mem_total_mb: Some(total),
            mem_available_mb: Some(available),
            extra_committed_mb: extra,
            cpu_pressure_pct: 0,
        }
    }

    #[test]
    fn raise_room_is_bounded_by_every_limit() {
        // 16 GB, 10 GB free, nothing extra yet, 100 MB workers: ceiling rules.
        let r = raise_room(5, 20, 256, 100, 0, &node(16_000, 10_000, 0));
        assert_eq!((r.cap, r.blocked), (20, None));
        // Ceiling reached.
        let r = raise_room(20, 20, 256, 100, 0, &node(16_000, 10_000, 0));
        assert_eq!(r.blocked, Some(RaiseBlock::Ceiling));
        // One site at a huge memory_limit: its own workers could fill the box.
        let r = raise_room(5, 20, 2048, 100, 0, &node(16_000, 10_000, 0));
        assert_eq!((r.cap, r.blocked), (5, Some(RaiseBlock::SiteRam)));
        // The node's budget (a quarter of RAM) is nearly spent by other sites.
        let r = raise_room(5, 20, 256, 100, 0, &node(16_000, 10_000, 3_800));
        assert_eq!((r.cap, r.blocked), (7, None), "room for two more");
        // ...and spent.
        let r = raise_room(5, 20, 256, 100, 0, &node(16_000, 10_000, 4_000));
        assert_eq!((r.cap, r.blocked), (5, Some(RaiseBlock::NodeRam)));
        // Over budget does not lower anything by itself.
        let r = raise_room(5, 20, 256, 100, 0, &node(16_000, 10_000, 9_000));
        assert_eq!((r.cap, r.blocked), (5, Some(RaiseBlock::NodeRam)));
        // Too little free right now, whatever the budget says.
        let r = raise_room(5, 20, 256, 100, 0, &node(16_000, 3_250, 0));
        assert_eq!((r.cap, r.blocked), (5, Some(RaiseBlock::NodeRam)));
        let r = raise_room(5, 20, 256, 100, 0, &node(16_000, 3_500, 0));
        assert_eq!((r.cap, r.blocked), (8, None));
        // A site with heavy workers has its share of RAM, whatever is free.
        let r = raise_room(5, 20, 256, 1000, 0, &node(16_000, 15_000, 0));
        assert_eq!((r.cap, r.blocked), (5, Some(RaiseBlock::SiteShare)));
        // A site already on half the node's CPU gets no more workers.
        let r = raise_room(
            5,
            20,
            256,
            100,
            SITE_CPU_SHARE_PCT,
            &node(16_000, 10_000, 0),
        );
        assert_eq!((r.cap, r.blocked), (5, Some(RaiseBlock::SiteShare)));
        // CPU short: wait, with room or not.
        let mut busy = node(16_000, 10_000, 0);
        busy.cpu_pressure_pct = CPU_BUSY_PCT;
        let r = raise_room(5, 20, 256, 100, 0, &busy);
        assert_eq!((r.cap, r.blocked), (5, Some(RaiseBlock::NodeCpu)));
        // Memory unreadable: only the ceiling is left.
        let r = raise_room(5, 20, 256, 100, 0, &NodeFacts::default());
        assert_eq!((r.cap, r.blocked), (20, None));
    }

    #[test]
    fn a_raised_site_gives_back_only_when_it_is_taking_from_the_others() {
        let now = 1_000_000;
        let st = AutoState {
            base: 5,
            last_change_at: now - AUTO_COOLDOWN_SECS,
            ..Default::default()
        };
        let (share, busy) = (SITE_CPU_SHARE_PCT, CPU_BUSY_PCT);
        assert_eq!(over_share(now, 13, share, busy, &st), Some(9));
        assert_eq!(over_share(now, 7, share, busy, &st), Some(5), "never below");
        // Busy node, but others are the cause.
        assert_eq!(over_share(now, 13, share - 1, busy, &st), None);
        // Big share of an idle node harms nobody.
        assert_eq!(over_share(now, 13, share, busy - 1, &st), None);
        // At the operator's own value: not ours to take.
        assert_eq!(over_share(now, 5, share, busy, &st), None);
        // Let the last change show first.
        let recent = AutoState {
            last_change_at: now - 60,
            ..st.clone()
        };
        assert_eq!(over_share(now, 13, share, busy, &recent), None);
    }

    #[test]
    fn worker_size_prefers_the_measured_one() {
        let m = |workers, largest_mb| {
            Some(PoolMemory {
                workers,
                largest_mb,
            })
        };
        assert_eq!(worker_size_mb(m(3, 90), 256), 90);
        assert_eq!(worker_size_mb(m(0, 0), 256), FALLBACK_WORKER_MB);
        assert_eq!(worker_size_mb(None, 64), 64, "memory_limit caps the guess");
    }

    #[test]
    fn reads_pool_names_and_pss_from_proc() {
        assert_eq!(
            pool_of_cmdline("php-fpm: pool example_cz\0\0\0"),
            Some("example_cz")
        );
        assert_eq!(
            pool_of_cmdline("php-fpm: pool example_cz       "),
            Some("example_cz")
        );
        assert_eq!(
            pool_of_cmdline("php-fpm: master process (/etc/x.conf)"),
            None
        );
        assert_eq!(pool_of_cmdline("nginx: worker process"), None);
        assert_eq!(
            pss_mb("55d0-7ffc ---p 0 00:00 0 [rollup]\nRss:   204800 kB\nPss:   102400 kB\n"),
            Some(100)
        );
        assert_eq!(pss_mb("Rss: 1 kB\n"), None);
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
