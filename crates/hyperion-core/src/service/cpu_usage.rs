//! Per-site CPU accounting from `/proc`.
//!
//! A site's CPU is the CPU of its system user's processes, so the honest
//! figure is "jiffies charged to that uid over a span of time". Two readings
//! 200 ms apart every five minutes cannot give that: PHP is idle during almost
//! any 200 ms, so a site serving 40,000 requests a day read 0.0% and the rare
//! tick that caught a request read a spike.
//!
//! So this samples every [`TICK_SECS`] and keeps the running totals here, in
//! memory. The page reads a rolling one-minute average, and the five-minute
//! stats tick drains what accumulated into `hosting_usage_samples`.
//!
//! Attribution is per PID across ticks, because a uid's plain sum goes DOWN
//! whenever a process exits (a recycled FPM worker takes its whole lifetime
//! with it). See [`account`].

use hyperion_types::CpuBreakdown;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

/// How often [`read_proc_snapshot`] runs. One pass is a few milliseconds on a
/// box with hundreds of processes.
pub const TICK_SECS: u64 = 10;
/// The "now" the page shows: long enough that a site between two requests is
/// not 0%, short enough to still be now.
const WINDOW_SECS: i64 = 60;
/// A reading older than this means the sampler stopped; say so, don't show it.
const STALE_SECS: i64 = 45;
/// Debian x86_64 page size, for the `rss` field of `/proc/<pid>/stat`.
const PAGE: i64 = 4096;

/// Who a process belongs to when its uid is not a site's. Matched on the
/// kernel's `comm`, which a tenant can set freely, so this is only ever read
/// for uids that are NOT sites (see [`LiveCpu::breakdown`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpuClass {
    Database,
    Web,
    Panel,
    Other,
}

fn class_of(comm: &str) -> CpuClass {
    match comm {
        "mysqld" | "mariadbd" | "redis-server" => CpuClass::Database,
        "nginx" => CpuClass::Web,
        _ if comm.starts_with("php-fpm") => CpuClass::Web,
        _ if comm.starts_with("hyperion") || comm == "hctl" => CpuClass::Panel,
        _ => CpuClass::Other,
    }
}

/// One process, as of one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSample {
    pub ppid: i64,
    pub uid: i64,
    pub class: CpuClass,
    /// Tells a reused PID from the same process.
    pub start_ticks: i64,
    /// utime + stime.
    pub self_jiffies: i64,
    /// cutime + cstime: children this process has reaped.
    pub child_jiffies: i64,
    pub rss_bytes: i64,
}

/// One whole read of `/proc`.
#[derive(Debug, Clone, Default)]
pub struct ProcSnapshot {
    pub busy_jiffies: i64,
    pub total_jiffies: i64,
    pub cores: i64,
    pub procs: HashMap<i64, ProcSample>,
}

/// Parse one `/proc/<pid>/stat`. `comm` can hold spaces and parens, so the
/// fields are counted from the LAST `)`.
pub fn parse_proc_stat(uid: i64, s: &str) -> Option<ProcSample> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?;
    let toks: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
    let num = |i: usize| toks.get(i).and_then(|v| v.parse::<i64>().ok());
    Some(ProcSample {
        ppid: num(1)?,
        uid,
        class: class_of(comm),
        start_ticks: num(19)?,
        self_jiffies: num(11)? + num(12)?,
        child_jiffies: num(13)? + num(14)?,
        rss_bytes: num(21)?.max(0) * PAGE,
    })
}

/// `(busy, total, cores)` from `/proc/stat`. Only the first eight fields count:
/// guest and guest_nice are already inside user and nice, and adding them again
/// inflates the total on a box that hosts VMs.
pub fn parse_proc_stat_cpu(s: &str) -> Option<(i64, i64, i64)> {
    let first = s.lines().next()?;
    let mut it = first.split_whitespace();
    if it.next()? != "cpu" {
        return None;
    }
    let vals: Vec<i64> = it.take(8).filter_map(|v| v.parse().ok()).collect();
    if vals.len() < 5 {
        return None;
    }
    let total: i64 = vals.iter().sum();
    let cores = s
        .lines()
        .filter(|l| {
            l.strip_prefix("cpu")
                .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        })
        .count() as i64;
    Some((total - vals[3] - vals[4], total, cores))
}

/// Read `/proc` once. Blocking; `None` where there is no `/proc`.
pub fn read_proc_snapshot() -> Option<ProcSnapshot> {
    use std::os::unix::fs::MetadataExt;
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let (busy_jiffies, total_jiffies, cores) = parse_proc_stat_cpu(&stat)?;
    let mut procs = HashMap::new();
    for ent in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i64>().ok()) else {
            continue; // not a pid dir
        };
        let dir = ent.path();
        // The directory itself is owned by the EUID even for a non-dumpable
        // process such as an FPM worker, unlike the files inside it.
        let Ok(meta) = std::fs::metadata(&dir) else {
            continue; // exited between readdir and stat
        };
        if let Some(p) = std::fs::read_to_string(dir.join("stat"))
            .ok()
            .and_then(|s| parse_proc_stat(meta.uid() as i64, &s))
        {
            procs.insert(pid, p);
        }
    }
    Some(ProcSnapshot {
        busy_jiffies,
        total_jiffies,
        cores,
        procs,
    })
}

/// Jiffies burned between two reads, per `(uid, class)`.
///
/// A process seen at both reads is charged the difference. A new one is charged
/// everything it has, since all of it happened in between. Child time matters
/// because a command a worker ran and waited for (ImageMagick, wp-cli) can start
/// and finish between two reads and leaves no other trace.
///
/// Child time also double-counts: when a process is reaped its whole lifetime
/// lands in the parent's cutime, including what the previous reads already
/// charged it. So the last-seen total of each process that disappeared is taken
/// back off its parent. That also keeps the FPM master, which reaps every
/// worker, from being billed for all the PHP on the box.
pub fn account(
    prev: &HashMap<i64, ProcSample>,
    cur: &HashMap<i64, ProcSample>,
) -> HashMap<(i64, CpuClass), i64> {
    let mut out: HashMap<(i64, CpuClass), i64> = HashMap::new();
    for (pid, c) in cur {
        let (s0, c0) = match prev.get(pid) {
            Some(p) if p.start_ticks == c.start_ticks => (p.self_jiffies, p.child_jiffies),
            _ => (0, 0),
        };
        *out.entry((c.uid, c.class)).or_default() +=
            (c.self_jiffies - s0).max(0) + (c.child_jiffies - c0).max(0);
    }
    for (pid, p) in prev {
        let gone = cur
            .get(pid)
            .map_or(true, |c| c.start_ticks != p.start_ticks);
        if !gone {
            continue;
        }
        if let Some(parent) = cur.get(&p.ppid) {
            *out.entry((parent.uid, parent.class)).or_default() -= p.self_jiffies + p.child_jiffies;
        }
    }
    out.retain(|_, v| {
        *v = (*v).max(0);
        *v > 0
    });
    out
}

/// `part / whole` as a percentage × 100, within 0..=100%.
fn pct_x100(part: i64, whole: i64) -> i64 {
    if whole > 0 {
        (part.saturating_mul(10_000) / whole).clamp(0, 10_000)
    } else {
        0
    }
}

struct TickDelta {
    from_at: i64,
    busy: i64,
    total: i64,
    by: HashMap<(i64, CpuClass), i64>,
}

/// What accumulated since the last [`CpuTracker::take_interval`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuInterval {
    pub busy: i64,
    pub total: i64,
    /// uid → (jiffies charged, highest one-minute average × 100).
    pub by_uid: HashMap<i64, (i64, i64)>,
}

impl CpuInterval {
    pub fn node_pct_x100(&self) -> i64 {
        pct_x100(self.busy, self.total)
    }
    pub fn uid_pct_x100(&self, uid: i64) -> i64 {
        pct_x100(self.by_uid.get(&uid).map_or(0, |(j, _)| *j), self.total)
    }
}

#[derive(Default)]
struct Inner {
    prev: Option<(i64, ProcSnapshot)>,
    ring: VecDeque<TickDelta>,
    interval: CpuInterval,
    rss_by_uid: HashMap<i64, i64>,
}

/// The sampler's state. Shared by the sampler task and the RPC handlers.
#[derive(Default)]
pub struct CpuTracker {
    inner: Mutex<Inner>,
}

/// The rolling "now" view.
#[derive(Debug, Clone)]
pub struct LiveCpu {
    pub window_secs: i64,
    pub cores: i64,
    pub busy: i64,
    pub total: i64,
    by: HashMap<(i64, CpuClass), i64>,
    rss_by_uid: HashMap<i64, i64>,
}

impl LiveCpu {
    pub fn node_pct_x100(&self) -> i64 {
        pct_x100(self.busy, self.total)
    }

    pub fn uid_pct_x100(&self, uid: i64) -> i64 {
        let used = self
            .by
            .iter()
            .filter(|((u, _), _)| *u == uid)
            .map(|(_, v)| *v)
            .sum();
        pct_x100(used, self.total)
    }

    pub fn rss_bytes(&self, uid: i64) -> i64 {
        self.rss_by_uid.get(&uid).copied().unwrap_or(0)
    }

    /// Split the node's busy time. A process of a site's uid counts for that
    /// site whatever it is called, so a tenant naming a process `mysqld` moves
    /// nothing. "Other" is the remainder, so the parts always add up to the
    /// node's busy figure; kernel time and whatever exited unseen land there.
    pub fn breakdown(&self, site_uids: &HashSet<i64>) -> CpuBreakdown {
        let (mut sites, mut database, mut web, mut panel) = (0i64, 0i64, 0i64, 0i64);
        for ((uid, class), v) in &self.by {
            if site_uids.contains(uid) {
                sites += v;
                continue;
            }
            match class {
                CpuClass::Database => database += v,
                CpuClass::Web => web += v,
                CpuClass::Panel => panel += v,
                CpuClass::Other => {}
            }
        }
        let busy = pct_x100(self.busy, self.total);
        let sites_x100 = pct_x100(sites, self.total);
        let database_x100 = pct_x100(database, self.total);
        let web_x100 = pct_x100(web, self.total);
        let panel_x100 = pct_x100(panel, self.total);
        CpuBreakdown {
            window_secs: self.window_secs,
            sites_x100,
            database_x100,
            web_x100,
            panel_x100,
            other_x100: (busy - sites_x100 - database_x100 - web_x100 - panel_x100).max(0),
        }
    }
}

impl CpuTracker {
    /// A panic elsewhere must not stop the figures: every value in here is
    /// valid on its own, so a poisoned lock is still a usable one.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Feed one read. The first one is only a baseline: a process's lifetime
    /// total says nothing about the last ten seconds.
    pub fn observe(&self, at: i64, snap: ProcSnapshot) {
        let mut g = self.lock();
        let inner = &mut *g;
        inner.rss_by_uid.clear();
        for p in snap.procs.values() {
            *inner.rss_by_uid.entry(p.uid).or_default() += p.rss_bytes;
        }
        if let Some((prev_at, prev)) = inner.prev.as_ref() {
            let total = snap.total_jiffies - prev.total_jiffies;
            // No time passed, or the counters went backwards: nothing to learn.
            if total > 0 {
                let by = account(&prev.procs, &snap.procs);
                inner.interval.total += total;
                inner.interval.busy += (snap.busy_jiffies - prev.busy_jiffies).max(0);
                for ((uid, _), v) in &by {
                    inner.interval.by_uid.entry(*uid).or_default().0 += v;
                }
                inner.ring.push_back(TickDelta {
                    from_at: *prev_at,
                    busy: snap.busy_jiffies - prev.busy_jiffies,
                    total,
                    by,
                });
                while inner
                    .ring
                    .front()
                    .is_some_and(|t| t.from_at < at - WINDOW_SECS)
                {
                    inner.ring.pop_front();
                }
                let ring_total: i64 = inner.ring.iter().map(|t| t.total).sum();
                let mut per_uid: HashMap<i64, i64> = HashMap::new();
                for ((uid, _), v) in inner.ring.iter().flat_map(|t| t.by.iter()) {
                    *per_uid.entry(*uid).or_default() += v;
                }
                for (uid, used) in per_uid {
                    let e = inner.interval.by_uid.entry(uid).or_default();
                    e.1 = e.1.max(pct_x100(used, ring_total));
                }
            }
        }
        inner.prev = Some((at, snap));
    }

    /// The last minute. `None` until two reads exist, or once the sampler has
    /// stopped: an old number shown as "now" is the bug this module replaced.
    pub fn live(&self, now: i64) -> Option<LiveCpu> {
        let g = self.lock();
        let (last_at, snap) = g.prev.as_ref()?;
        if now - last_at > STALE_SECS {
            return None;
        }
        let first = g.ring.front()?;
        let mut by: HashMap<(i64, CpuClass), i64> = HashMap::new();
        for t in &g.ring {
            for (k, v) in &t.by {
                *by.entry(*k).or_default() += v;
            }
        }
        Some(LiveCpu {
            window_secs: last_at - first.from_at,
            cores: snap.cores,
            busy: g.ring.iter().map(|t| t.busy).sum(),
            total: g.ring.iter().map(|t| t.total).sum(),
            by,
            rss_by_uid: g.rss_by_uid.clone(),
        })
    }

    /// Everything since the previous call. Called by the five-minute stats tick.
    pub fn take_interval(&self) -> CpuInterval {
        let mut g = self.lock();
        std::mem::take(&mut g.interval)
    }

    /// Latest RSS per uid.
    pub fn rss_by_uid(&self) -> HashMap<i64, i64> {
        self.lock().rss_by_uid.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(ppid: i64, uid: i64, class: CpuClass, s: i64, c: i64) -> ProcSample {
        ProcSample {
            ppid,
            uid,
            class,
            start_ticks: 1,
            self_jiffies: s,
            child_jiffies: c,
            rss_bytes: 4096,
        }
    }

    fn map(items: &[(i64, ProcSample)]) -> HashMap<i64, ProcSample> {
        items.iter().cloned().collect()
    }

    const SITE: i64 = 1001;
    const O: CpuClass = CpuClass::Other;
    const W: CpuClass = CpuClass::Web;

    #[test]
    fn parses_a_stat_line_with_a_hostile_comm() {
        // Field numbers from proc(5): utime 14, stime 15, cutime 16, cstime 17,
        // starttime 22, rss 24. A tenant controls comm, so it may contain ") ".
        let line = "42 (php) 9 x) S 7 42 42 0 -1 4194304 1 0 0 0 11 22 33 44 20 0 1 0 555 1000 3 18446744073709551615";
        let p = parse_proc_stat(SITE, line).expect("parse");
        assert_eq!(p.ppid, 7);
        assert_eq!(p.self_jiffies, 33);
        assert_eq!(p.child_jiffies, 77);
        assert_eq!(p.start_ticks, 555);
        assert_eq!(p.rss_bytes, 3 * PAGE);
        assert_eq!(p.class, CpuClass::Other, "that comm is not a known daemon");
    }

    #[test]
    fn classifies_daemons_by_comm() {
        assert_eq!(class_of("mariadbd"), CpuClass::Database);
        assert_eq!(class_of("nginx"), CpuClass::Web);
        assert_eq!(class_of("php-fpm8.3"), CpuClass::Web);
        assert_eq!(class_of("hyperion-agent"), CpuClass::Panel);
        assert_eq!(class_of("kworker/0:1"), CpuClass::Other);
    }

    #[test]
    fn proc_stat_total_leaves_guest_time_out() {
        let s = "cpu  100 0 50 800 50 0 0 0 999 999\ncpu0 50 0 25 400 25 0 0 0 0 0\ncpu1 50 0 25 400 25 0 0 0 0 0\nintr 1\n";
        assert_eq!(parse_proc_stat_cpu(s), Some((150, 1000, 2)));
    }

    #[test]
    fn a_process_exiting_does_not_erase_the_others() {
        // A plain per-uid sum falls by 1000 here and clamps the whole site to 0.
        let prev = map(&[
            (10, proc(1, SITE, O, 1000, 0)),
            (11, proc(1, SITE, O, 50, 0)),
        ]);
        let cur = map(&[(11, proc(1, SITE, O, 80, 0))]);
        assert_eq!(account(&prev, &cur).get(&(SITE, O)), Some(&30));
    }

    #[test]
    fn a_process_started_since_the_last_read_counts_in_full() {
        let prev = map(&[]);
        let cur = map(&[(10, proc(1, SITE, O, 25, 0))]);
        assert_eq!(account(&prev, &cur).get(&(SITE, O)), Some(&25));
    }

    #[test]
    fn a_reused_pid_is_a_new_process() {
        let prev = map(&[(10, proc(1, SITE, O, 1000, 0))]);
        let mut fresh = proc(1, SITE, O, 5, 0);
        fresh.start_ticks = 2;
        let cur = map(&[(10, fresh)]);
        assert_eq!(account(&prev, &cur).get(&(SITE, O)), Some(&5));
    }

    #[test]
    fn a_short_child_seen_only_through_its_parent_still_counts() {
        // ImageMagick ran and was reaped between the reads.
        let prev = map(&[(10, proc(1, SITE, O, 100, 0))]);
        let cur = map(&[(10, proc(1, SITE, O, 101, 40))]);
        assert_eq!(account(&prev, &cur).get(&(SITE, O)), Some(&41));
    }

    #[test]
    fn a_reaped_child_is_not_charged_twice() {
        // Child had 60 at the last read, finished at 70 and landed in the
        // parent's cutime. Only the 10 since then is new.
        let prev = map(&[
            (10, proc(1, SITE, O, 100, 0)),
            (20, proc(10, SITE, O, 60, 0)),
        ]);
        let cur = map(&[(10, proc(1, SITE, O, 100, 70))]);
        assert_eq!(account(&prev, &cur).get(&(SITE, O)), Some(&10));
    }

    #[test]
    fn the_fpm_master_is_not_billed_for_a_recycled_worker() {
        let prev = map(&[
            (1, proc(0, 0, W, 5, 0)),
            (20, proc(1, SITE, W, 5000, 0)),
            (21, proc(1, SITE, W, 10, 0)),
        ]);
        let cur = map(&[(1, proc(0, 0, W, 5, 5001)), (21, proc(1, SITE, W, 12, 0))]);
        let got = account(&prev, &cur);
        assert_eq!(got.get(&(SITE, W)), Some(&2));
        assert_eq!(got.get(&(0, W)), Some(&1), "only the unseen tail");
    }

    fn snap(busy: i64, total: i64, procs: &[(i64, ProcSample)]) -> ProcSnapshot {
        ProcSnapshot {
            busy_jiffies: busy,
            total_jiffies: total,
            cores: 4,
            procs: map(procs),
        }
    }

    #[test]
    fn first_read_is_a_baseline_and_lifetime_totals_are_ignored() {
        let t = CpuTracker::default();
        t.observe(100, snap(5000, 90_000, &[(10, proc(1, SITE, O, 9000, 0))]));
        assert!(t.live(100).is_none(), "one read cannot give a rate");
        t.observe(110, snap(5100, 94_000, &[(10, proc(1, SITE, O, 9040, 0))]));
        let live = t.live(110).expect("live");
        assert_eq!(live.uid_pct_x100(SITE), 100); // 40 of 4000 jiffies = 1%
        assert_eq!(live.node_pct_x100(), 250); // 100 of 4000
        assert_eq!(live.window_secs, 10);
        assert_eq!(live.cores, 4);
    }

    #[test]
    fn live_goes_blank_when_the_sampler_stops() {
        let t = CpuTracker::default();
        t.observe(100, snap(0, 0, &[]));
        t.observe(110, snap(1, 100, &[]));
        assert!(t.live(110 + STALE_SECS).is_some());
        assert!(t.live(111 + STALE_SECS).is_none());
    }

    #[test]
    fn live_window_rolls_off_old_ticks() {
        let t = CpuTracker::default();
        t.observe(0, snap(0, 0, &[(10, proc(1, SITE, O, 0, 0))]));
        // A burst in the first ten seconds, then nothing.
        t.observe(10, snap(400, 4000, &[(10, proc(1, SITE, O, 400, 0))]));
        assert_eq!(t.live(10).expect("live").uid_pct_x100(SITE), 1000);
        for i in 2..=8 {
            t.observe(
                i * 10,
                snap(400, 4000 * i, &[(10, proc(1, SITE, O, 400, 0))]),
            );
        }
        assert_eq!(
            t.live(80).expect("live").uid_pct_x100(SITE),
            0,
            "a burst over a minute ago is not now"
        );
    }

    #[test]
    fn interval_drains_with_the_highest_one_minute_average() {
        let t = CpuTracker::default();
        t.observe(0, snap(0, 0, &[(10, proc(1, SITE, O, 0, 0))]));
        t.observe(10, snap(400, 4000, &[(10, proc(1, SITE, O, 400, 0))]));
        t.observe(20, snap(400, 8000, &[(10, proc(1, SITE, O, 400, 0))]));
        let i = t.take_interval();
        assert_eq!(i.total, 8000);
        assert_eq!(i.busy, 400);
        assert_eq!(i.by_uid.get(&SITE), Some(&(400, 1000)));
        assert_eq!(i.uid_pct_x100(SITE), 500);
        assert_eq!(i.node_pct_x100(), 500);
        assert_eq!(t.take_interval(), CpuInterval::default(), "drained");
    }

    #[test]
    fn breakdown_adds_up_and_ignores_a_tenant_named_mysqld() {
        let t = CpuTracker::default();
        let db = CpuClass::Database;
        t.observe(
            0,
            snap(
                0,
                0,
                &[
                    (10, proc(1, SITE, db, 0, 0)), // tenant process called mysqld
                    (11, proc(1, 106, db, 0, 0)),  // the real one
                    (12, proc(1, 33, W, 0, 0)),
                ],
            ),
        );
        t.observe(
            10,
            snap(
                1000,
                4000,
                &[
                    (10, proc(1, SITE, db, 400, 0)),
                    (11, proc(1, 106, db, 200, 0)),
                    (12, proc(1, 33, W, 100, 0)),
                ],
            ),
        );
        let live = t.live(10).expect("live");
        let b = live.breakdown(&HashSet::from([SITE]));
        assert_eq!(b.sites_x100, 1000);
        assert_eq!(b.database_x100, 500);
        assert_eq!(b.web_x100, 250);
        assert_eq!(b.panel_x100, 0);
        assert_eq!(b.other_x100, 750, "the rest of the 25% busy");
        assert_eq!(live.rss_bytes(SITE), 4096);
    }

    /// The real thing: everything above feeds on hand-written lines, this is
    /// what catches `/proc` not looking the way the parser thinks it does.
    #[cfg(target_os = "linux")]
    #[test]
    fn reads_this_process_out_of_the_real_proc() {
        use std::os::unix::fs::MetadataExt;
        let me = std::process::id() as i64;
        let uid = std::fs::metadata("/proc/self").expect("self").uid() as i64;
        let first = read_proc_snapshot().expect("snapshot");
        assert!(first.cores > 0);
        assert!(first.total_jiffies > first.busy_jiffies);
        assert_eq!(first.procs.get(&me).map(|p| p.uid), Some(uid));

        let t = CpuTracker::default();
        t.observe(0, first);
        // Burn about half a second, far more than one jiffy.
        let start = std::time::Instant::now();
        let mut x = 0u64;
        while start.elapsed() < std::time::Duration::from_millis(500) {
            x = std::hint::black_box(x.wrapping_add(1));
        }
        t.observe(1, read_proc_snapshot().expect("snapshot"));
        let live = t.live(1).expect("live");
        assert!(live.uid_pct_x100(uid) > 0, "our own CPU must show up");
        assert!(live.rss_bytes(uid) > 0);
        assert!(live.node_pct_x100() > 0);
    }
}
