//! Period-scoped aggregations behind the CARE REPORT — the periodic
//! e-mail that tells a paying customer, in plain language, what their
//! care package actually did for their site over one billing period.
//!
//! Nothing here formats or sends anything. It answers six questions
//! about `[from_ts, to_ts)` for ONE hosting, and it answers them the way
//! the report must be allowed to speak:
//!
//! > **A number this module returns was measured. A metric it cannot
//! > measure comes back as `None` — never as zero.**
//!
//! That distinction is the whole point of the module. The report is a
//! written claim to someone who pays for it, so "100 % uptime" for a
//! site nobody ever monitored, or "clean" for a scan that never ran, is
//! worse than sending nothing at all. Every function below therefore
//! separates *"we watched, and nothing happened"* from *"nobody was
//! watching"*, and it does so from the ROWS — a renderer that has to
//! infer it has already lost.
//!
//! Everything is read from THIS node's tables, so the assembler must run
//! where the hosting lives: bans, usage samples, monitor samples, backup
//! runs and the stored integrity scan are all per-node. Run on the wrong
//! node, every query truthfully reports "not measured".

use crate::db::StateError;
use hyperion_types::package::{CareBackups, CareIntegrity, CareUptime, CareUsage};
use serde::Deserialize;
use sqlx::SqlitePool;

/// `hosting_kv` key the owning node stores its last integrity scan under.
/// Must match `hyperion_core::service::INTEGRITY_KV_KEY`; a mismatch reads
/// as "never scanned", which is the safe direction.
const INTEGRITY_KV_KEY: &str = "integrity_scan";

/// Audit actions that record a WordPress component update. Both are
/// written by `HostingService::wp_plugin_action` / `wp_theme_action`,
/// which the defender's auto-updater goes through — so the audit log is
/// the durable record of work the transient scan result is not.
const UPDATE_ACTIONS: [&str; 2] = ["wp.plugin.action", "wp.theme.action"];

// =====================================================================
//  Attacks blocked
// =====================================================================

/// Ban events attributed to THIS site inside the period.
///
/// Node-wide bans (`ip_bans.hosting_id IS NULL` — an operator's manual
/// block, or a scanner hit that could not be pinned to one vhost) are
/// excluded, and SQL equality does that for us: `hosting_id = ?` never
/// matches NULL. Counting them would credit every site on the node with
/// the same block and inflate what each customer is told they got.
///
/// Counts BAN EVENTS, not rows-still-active: a ban placed and expired
/// inside the period is work that happened, and `active` says nothing
/// about the period. Re-banning the same IP flips the old row inactive
/// and inserts a new one, so a repeat offender counts once per ban.
///
/// Returns a plain count, never `None`: the database cannot see whether
/// the ban scanner was RUNNING at all. A caller that knows `[fail2ban]
/// enabled = false` for the period must map this to
/// `CareReport::attacks_blocked = None` itself — with the scanner off,
/// zero bans means nobody was watching, not that nobody attacked.
pub async fn attacks_blocked(
    pool: &SqlitePool,
    hosting_id: &str,
    from_ts: i64,
    to_ts: i64,
) -> Result<i64, StateError> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ip_bans
          WHERE hosting_id = ? AND banned_at >= ? AND banned_at < ?",
    )
    .bind(hosting_id)
    .bind(from_ts)
    .bind(to_ts)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

// =====================================================================
//  Traffic, requests, disk
// =====================================================================

/// Traffic + footprint from the hourly `hosting_usage` sampler.
///
/// `None` when the sampler produced NO bucket for this site in the
/// period. A site that was never sampled has no traffic figure, which is
/// not the same as no traffic — and "0 requests" on a live site is
/// exactly the kind of claim this module exists to prevent.
///
/// The aggregation mirrors [`crate::limits::usage_rollup_all`] so the
/// report and the /stats breakdown cannot disagree about one site: disk
/// is the MAX over the window (a level, not a flow — summing it would
/// report 24× the real footprint), traffic and requests are sums.
///
/// **Bucket rounding.** `hosting_usage.period` is a UTC hour key
/// (`YYYY-MM-DD-HH`), so the window is snapped to whole hours: the hour
/// containing `from_ts` is included, the hour containing `to_ts` is not.
/// Report periods start on a UTC day boundary, where this is exact; for
/// anything else it rounds toward reporting LESS traffic, which is the
/// direction that cannot overstate.
pub async fn usage(
    pool: &SqlitePool,
    hosting_id: &str,
    from_ts: i64,
    to_ts: i64,
) -> Result<Option<CareUsage>, StateError> {
    let (from_key, to_key) = (period_key(from_ts), period_key(to_ts));
    // `substr(period, 1, 10)` is the 'YYYY-MM-DD' date prefix — counting
    // DISTINCT dates is what turns a sampling gap into a visible
    // "covers 26 of 31 days" instead of a month-shaped lie.
    let row: Option<(i64, Option<i64>, Option<i64>, Option<i64>, i64)> = sqlx::query_as(
        "SELECT COUNT(*)                        AS buckets,
                SUM(bw_in_bytes)                AS bw_in,
                SUM(bw_out_bytes)               AS bw_out,
                SUM(php_requests)               AS requests,
                COUNT(DISTINCT substr(period, 1, 10)) AS days
           FROM hosting_usage
          WHERE hosting_id = ? AND period >= ? AND period < ?",
    )
    .bind(hosting_id)
    .bind(&from_key)
    .bind(&to_key)
    .fetch_optional(pool)
    .await?;
    // A bare aggregate always returns one row; `buckets == 0` is the
    // "never sampled" case, and the SUMs are NULL there.
    let Some((buckets, bw_in, bw_out, requests, days_counted)) = row else {
        return Ok(None);
    };
    if buckets == 0 {
        return Ok(None);
    }
    let bw_out_bytes = bw_out.unwrap_or(0);
    let requests = requests.unwrap_or(0);
    let bw_in_total = bw_in.unwrap_or(0);
    // Inbound bytes need the node's nginx log format to carry request
    // size, and the stock format does not — so a zero here is ambiguous.
    // Requests with zero inbound bytes is physically impossible, so that
    // combination is a logging gap and must read "not measured"; zero
    // bytes with zero requests really is nothing happening.
    let bw_in_bytes = if bw_in_total > 0 {
        Some(bw_in_total)
    } else if requests > 0 {
        None
    } else {
        Some(0)
    };
    let disk_peak_bytes = max_disk(pool, hosting_id, &from_key, &to_key).await?;
    Ok(Some(CareUsage {
        bw_in_bytes,
        bw_out_bytes,
        requests,
        disk_peak_bytes,
        days_counted,
        days_in_period: days_spanned(from_ts, to_ts),
    }))
}

/// Peak disk footprint over the window. Split out of the traffic
/// aggregate purely so the MAX-vs-SUM distinction stays impossible to
/// miss when someone edits one of them.
async fn max_disk(
    pool: &SqlitePool,
    hosting_id: &str,
    from_key: &str,
    to_key: &str,
) -> Result<i64, StateError> {
    let (peak,): (Option<i64>,) = sqlx::query_as(
        "SELECT MAX(disk_used_bytes) FROM hosting_usage
          WHERE hosting_id = ? AND period >= ? AND period < ?",
    )
    .bind(hosting_id)
    .bind(from_key)
    .bind(to_key)
    .fetch_one(pool)
    .await?;
    Ok(peak.unwrap_or(0))
}

// =====================================================================
//  Uptime
// =====================================================================

/// Uptime checks in the period: how many ran, and how many succeeded.
///
/// BOTH counts come back, and no percentage does. That is deliberate:
/// `samples == 0` is a site nobody monitored, and the only place a ratio
/// may be computed is [`CareUptime::success_ratio_x100`], which returns
/// `None` there instead of dividing 0/0 into a flattering "100 %". A
/// renderer that sees zero samples must print "nekontrolováno".
///
/// Never `None`: unlike backups there is no separate "was this feature
/// ever on" signal to recover, so zero samples IS the unmeasured state
/// and the type already carries it.
pub async fn uptime(
    pool: &SqlitePool,
    hosting_id: &str,
    from_ts: i64,
    to_ts: i64,
) -> Result<CareUptime, StateError> {
    let (samples, successes): (i64, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), SUM(success) FROM monitor_samples
          WHERE hosting_id = ? AND sampled_at >= ? AND sampled_at < ?",
    )
    .bind(hosting_id)
    .bind(from_ts)
    .bind(to_ts)
    .fetch_one(pool)
    .await?;
    Ok(CareUptime {
        samples,
        // `success` is CHECKed to 0/1, so SUM is the success count. NULL
        // only when there were no rows at all.
        successes: successes.unwrap_or(0),
    })
}

// =====================================================================
//  Backups
// =====================================================================

/// Backups in the period.
///
/// `None` when the site has no backup history AT ALL — not one run, ever.
/// Backups were evidently never running, and "0 backups" would read to
/// the customer as a failure rather than as a feature they never bought.
/// `Some` with `taken == 0` is the genuinely alarming case and must reach
/// the report intact: this site DOES take backups, and none happened in
/// this period.
///
/// A run is attributed to the period it STARTED in, so an overnight run
/// crossing a period boundary is counted once, by exactly one report.
/// `last_success_at` is a finish time and never reaches outside the
/// period for a comforting older date. Runs still in flight count as
/// neither taken nor failed — they have not happened yet.
pub async fn backups(
    pool: &SqlitePool,
    hosting_id: &str,
    from_ts: i64,
    to_ts: i64,
) -> Result<Option<CareBackups>, StateError> {
    // Deliberately unbounded in time: this asks "does this site do
    // backups at all", which is what separates "none this month" from
    // "never configured".
    let (ever,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM backup_runs WHERE hosting_id = ?")
        .bind(hosting_id)
        .fetch_one(pool)
        .await?;
    if ever == 0 {
        return Ok(None);
    }
    let (taken, failed, last_success_at): (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT COALESCE(SUM(state = 'ok'), 0),
                COALESCE(SUM(state = 'failed'), 0),
                MAX(CASE WHEN state = 'ok' THEN finished_at END)
           FROM backup_runs
          WHERE hosting_id = ? AND started_at >= ? AND started_at < ?",
    )
    .bind(hosting_id)
    .bind(from_ts)
    .bind(to_ts)
    .fetch_one(pool)
    .await?;
    Ok(Some(CareBackups {
        taken,
        failed,
        last_success_at,
    }))
}

// =====================================================================
//  Updates applied
// =====================================================================

/// Plugin/theme updates APPLIED in the period, or `None` when the audit
/// log cannot account for the whole period.
///
/// The durable source is the audit log, not the defender's scan result:
/// `WpVulnScanResult::auto_updated` is recomputed and overwritten on
/// every tick, so by the time a monthly report is assembled it holds
/// whatever the last sweep did — not the month. Every applied update
/// does, however, go through `wp_plugin_action` / `wp_theme_action`,
/// each of which appends an audit row keyed on the hosting id. Those
/// rows are append-only and hash-chained, which makes them exactly the
/// per-period record the report needs.
///
/// Two honesty limits, both of which the Czech copy must state rather
/// than paper over:
///
///   * **Coverage.** The audit log has a retention sweep. If its oldest
///     surviving row postdates `from_ts` — purged, or a node younger
///     than the period — part of the period is unaccounted for and this
///     returns `None`. An incomplete count printed as a total understates
///     the work done and invites "I paid for this?".
///   * **Scope.** Plugins and themes only; WordPress CORE updates have no
///     audit action today, so they are not in the number.
///
/// Only `result = 'ok'` counts. wp-cli reports `noop` when the component
/// was already current — an update that changed nothing is not an update
/// applied. `update_all` contributes 1: the row carries no per-component
/// count, so it is a floor, never an overstatement.
pub async fn updates_applied(
    pool: &SqlitePool,
    hosting_id: &str,
    from_ts: i64,
    to_ts: i64,
) -> Result<Option<i64>, StateError> {
    if !audit_covers(pool, from_ts).await? {
        return Ok(None);
    }
    // Filter down to this hosting's successful wp actions in-window, then
    // decide on the parsed payload. A LIKE over the JSON would silently
    // mis-count the day someone reformats the payload; `serde_json` on a
    // per-site, per-period slice costs nothing and cannot drift.
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT payload_json FROM audit_log
          WHERE target = ? AND ts >= ? AND ts < ?
            AND action IN (?, ?)
            AND result = 'ok'",
    )
    .bind(hosting_id)
    .bind(from_ts)
    .bind(to_ts)
    .bind(UPDATE_ACTIONS[0])
    .bind(UPDATE_ACTIONS[1])
    .fetch_all(pool)
    .await?;
    let n = rows
        .iter()
        .filter(|(json,)| {
            serde_json::from_str::<AuditWpPayload>(json)
                .map(|p| p.action == "update" || p.action == "update_all")
                .unwrap_or(false)
        })
        .count() as i64;
    Ok(Some(n))
}

/// The `action` discriminator inside a `wp.*.action` audit payload —
/// "install" | "activate" | "update" | "update_all" | "delete" | …
/// Everything else in the payload is irrelevant here, so an added field
/// upstream cannot break this parse.
#[derive(Deserialize)]
struct AuditWpPayload {
    #[serde(default)]
    action: String,
}

/// Whether the audit log can account for everything from `from_ts`
/// onwards.
///
/// True only when a row at or before `from_ts` survives: retention
/// deletes by `ts < cutoff`, so an older row still being present proves
/// the cutoff never reached into the period. An empty log proves nothing
/// and reads as no coverage.
async fn audit_covers(pool: &SqlitePool, from_ts: i64) -> Result<bool, StateError> {
    let (oldest,): (Option<i64>,) = sqlx::query_as("SELECT MIN(ts) FROM audit_log")
        .fetch_one(pool)
        .await?;
    Ok(matches!(oldest, Some(t) if t <= from_ts))
}

// =====================================================================
//  File integrity / malware
// =====================================================================

/// Outcome of the file-integrity + malware scan, or `None` when no scan
/// ran INSIDE the period.
///
/// The owning node keeps only the LAST scan (one `hosting_kv` row, not a
/// history), so the period test is on its timestamp: a scan from before
/// the period says nothing about the period, and reporting it would date
/// a clean bill of health to a month it never covered. A stored value
/// that no longer parses is also `None` — a shape change must cost the
/// customer information, never invent a verdict.
///
/// `checksums_ran` / `malware_scan_ran` carry the same honesty INSIDE a
/// scan that did happen: zero malware hits with `malware_scan_ran ==
/// false` means "not looked for" (no scanner on the node — a normal
/// state), never "none found". [`CareIntegrity::is_clean`] is the only
/// sanctioned way to a green verdict and requires both.
pub async fn integrity(
    pool: &SqlitePool,
    hosting_id: &str,
    from_ts: i64,
    to_ts: i64,
) -> Result<Option<CareIntegrity>, StateError> {
    let Some(json) = crate::hosting_kv::get(pool, hosting_id, INTEGRITY_KV_KEY).await? else {
        return Ok(None);
    };
    let Ok(stored) = serde_json::from_str::<StoredIntegrityScan>(&json) else {
        return Ok(None);
    };
    let scanned_at = if stored.scanned_at > 0 {
        stored.scanned_at
    } else {
        stored.result.scanned_at
    };
    if scanned_at < from_ts || scanned_at >= to_ts {
        return Ok(None);
    }
    let r = &stored.result;
    Ok(Some(CareIntegrity {
        scanned_at,
        checksums_ran: r.wp_cli_ok,
        malware_scan_ran: r.clamav_available,
        core_issues: r.core_issue_count() as i64,
        plugin_issues: r.plugin_issue_count() as i64,
        malware_hits: r.malware.len() as i64,
    }))
}

/// Read-side mirror of the record the owning node writes under
/// `integrity_scan` (`hyperion_core::service::StoredIntegrityScan`). Only
/// the two fields the report needs are named; `#[serde(default)]`
/// everywhere means an older or newer writer still parses.
#[derive(Deserialize)]
struct StoredIntegrityScan {
    #[serde(default)]
    scanned_at: i64,
    #[serde(default)]
    result: hyperion_types::WpIntegrityScanResult,
}

// =====================================================================
//  Window helpers
// =====================================================================

/// UTC hour key `YYYY-MM-DD-HH`, byte-identical to the one
/// `hyperion_core::service::period_key` writes into `hosting_usage`.
/// The column is TEXT, so the comparison is lexicographic — which is
/// also chronological for this format, and only for this format.
fn period_key(ts: i64) -> String {
    use chrono::{TimeZone, Utc};
    // A timestamp chrono cannot represent is far outside any real
    // reporting window; the epoch key makes such a window empty rather
    // than accidentally matching every bucket.
    match Utc.timestamp_opt(ts, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d-%H").to_string(),
        None => "1970-01-01-00".to_string(),
    }
}

/// How many UTC days the half-open window `[from_ts, to_ts)` touches —
/// the denominator behind "covers N of M days".
///
/// Counts calendar days, not 86 400-second slices, so it matches
/// `days_counted` (which counts distinct date prefixes present in
/// `hosting_usage`). A calendar month renders as 30 or 31, never 30.4.
fn days_spanned(from_ts: i64, to_ts: i64) -> i64 {
    if to_ts <= from_ts {
        return 0;
    }
    // `to_ts` is exclusive, so the last instant inside the window is
    // `to_ts - 1`; using `to_ts` itself would count a spurious extra day
    // for a window ending exactly at midnight.
    day_index(to_ts - 1) - day_index(from_ts) + 1
}

/// Days since the epoch, floored — negative timestamps included, which
/// integer division alone gets wrong (it truncates toward zero).
fn day_index(ts: i64) -> i64 {
    ts.div_euclid(86_400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;
    use hyperion_types::HostingId;

    /// Two hostings: half of what these queries promise is that one
    /// site's numbers never leak into another's report.
    async fn fresh() -> (SqlitePool, HostingId, HostingId) {
        let pool = open_memory().await.expect("open mem");
        let a = seed(&pool, "u_a", 3001, "a.cz").await;
        let b = seed(&pool, "u_b", 3002, "b.cz").await;
        (pool, a, b)
    }

    async fn seed(pool: &SqlitePool, user: &str, uid: i64, domain: &str) -> HostingId {
        let suid = crate::system_users::insert(pool, user, uid, &format!("/home/{user}"), "/x", 1)
            .await
            .expect("user");
        let id = HostingId::new_v7();
        crate::hostings::insert(pool, &id, domain, suid, None, "/r", 1, None)
            .await
            .expect("hosting");
        id
    }

    // A one-day window with room on both sides, so "outside" can be
    // tested in both directions.
    const FROM: i64 = 1_000_000;
    const TO: i64 = 1_086_400;

    // ------------------------------------------------------- attacks

    async fn ban(pool: &SqlitePool, ip: &str, hosting: Option<&str>, at: i64) {
        crate::bans::add_or_refresh(pool, ip, hosting, "brute force", "auto", at, at + 3600)
            .await
            .expect("ban");
    }

    #[tokio::test]
    async fn attacks_count_only_this_site_inside_the_window() {
        let (pool, a, b) = fresh().await;
        // Inside, on both edges: `from` is included, `to` is not.
        ban(&pool, "1.1.1.1", Some(a.as_str()), FROM).await;
        ban(&pool, "1.1.1.2", Some(a.as_str()), TO - 1).await;
        // Outside, on both sides.
        ban(&pool, "1.1.1.3", Some(a.as_str()), FROM - 1).await;
        ban(&pool, "1.1.1.4", Some(a.as_str()), TO).await;
        // Another site's ban.
        ban(&pool, "1.1.1.5", Some(b.as_str()), FROM + 10).await;
        // A NODE-WIDE ban: enforced for everyone, attributable to nobody.
        // Counting it would tell every customer on the box that their
        // site was defended when it was the operator blocking a scanner.
        ban(&pool, "1.1.1.6", None, FROM + 20).await;

        assert_eq!(
            attacks_blocked(&pool, a.as_str(), FROM, TO)
                .await
                .expect("count"),
            2
        );
        assert_eq!(
            attacks_blocked(&pool, b.as_str(), FROM, TO)
                .await
                .expect("count"),
            1
        );
    }

    #[tokio::test]
    async fn attacks_on_a_site_with_no_bans_is_a_measured_zero() {
        let (pool, a, _b) = fresh().await;
        // Zero here is a real measurement ("we watched, nothing came").
        // The unmeasured case — scanner switched off — is not visible in
        // the DB and is the caller's to supply.
        assert_eq!(
            attacks_blocked(&pool, a.as_str(), FROM, TO)
                .await
                .expect("count"),
            0
        );
    }

    // --------------------------------------------------------- usage

    async fn put_usage(
        pool: &SqlitePool,
        id: &HostingId,
        period: &str,
        disk: i64,
        bw_in: i64,
        bw_out: i64,
        reqs: i64,
    ) {
        crate::limits::upsert_usage(
            pool,
            &crate::limits::UsageBucket {
                hosting_id: id.clone(),
                period: period.into(),
                disk_used_bytes: disk,
                inodes_used: 0,
                bw_in_bytes: bw_in,
                bw_out_bytes: bw_out,
                php_requests: reqs,
                mem_rss_bytes: 0,
                cpu_pct_x100: 0,
            },
        )
        .await
        .expect("upsert usage");
    }

    /// A whole UTC day, for windows that line up with `hosting_usage`'s
    /// hour keys the way a real report period does.
    const DAY_FROM: i64 = 1_780_704_000; // 2026-06-06 00:00 UTC
    const DAY_TO: i64 = DAY_FROM + 86_400; // 2026-06-07 00:00 UTC

    #[tokio::test]
    async fn usage_sums_traffic_peaks_disk_and_respects_bucket_edges() {
        let (pool, a, b) = fresh().await;
        // Inside the day. Disk peaks in the MIDDLE bucket, so a naive
        // "latest" would report 100 instead of the 900 peak.
        put_usage(&pool, &a, "2026-06-06-00", 100, 1, 10, 5).await;
        put_usage(&pool, &a, "2026-06-06-12", 900, 2, 20, 6).await;
        put_usage(&pool, &a, "2026-06-06-23", 300, 4, 40, 7).await;
        // The hour before and the hour after — both outside.
        put_usage(&pool, &a, "2026-06-05-23", 999_999, 500, 500, 500).await;
        put_usage(&pool, &a, "2026-06-07-00", 999_999, 500, 500, 500).await;
        // Another site, same hours.
        put_usage(&pool, &b, "2026-06-06-00", 7, 70, 700, 7000).await;

        let u = usage(&pool, a.as_str(), DAY_FROM, DAY_TO)
            .await
            .expect("usage")
            .expect("sampled");
        assert_eq!(u.bw_out_bytes, 10 + 20 + 40);
        assert_eq!(u.requests, 5 + 6 + 7);
        assert_eq!(u.bw_in_bytes, Some(1 + 2 + 4));
        assert_eq!(u.disk_peak_bytes, 900, "disk is a level: MAX, never SUM");
        assert_eq!(u.days_counted, 1);
        assert_eq!(u.days_in_period, 1);
        assert!(u.is_complete());

        let ub = usage(&pool, b.as_str(), DAY_FROM, DAY_TO)
            .await
            .expect("usage")
            .expect("sampled");
        assert_eq!(ub.requests, 7000, "sites must not pool their traffic");
    }

    #[tokio::test]
    async fn usage_of_a_never_sampled_site_is_not_measured() {
        let (pool, a, _b) = fresh().await;
        // The exact failure the Option exists for: this must NOT come
        // back as a tidy "0 requests, 0 B" for a site that may well have
        // been serving traffic the whole month unsampled.
        assert_eq!(
            usage(&pool, a.as_str(), DAY_FROM, DAY_TO).await.expect("q"),
            None
        );
        // A bucket that exists but sits outside the window is equally
        // "not measured" for THIS period.
        put_usage(&pool, &a, "2026-06-05-23", 1, 1, 1, 1).await;
        assert_eq!(
            usage(&pool, a.as_str(), DAY_FROM, DAY_TO).await.expect("q"),
            None
        );
    }

    #[tokio::test]
    async fn usage_reports_partial_day_coverage() {
        let (pool, a, _b) = fresh().await;
        // A month-shaped window with a four-day sampling gap in it.
        let from = 1_780_272_000; // 2026-06-01 00:00 UTC
        let to = 1_782_864_000; // 2026-07-01 00:00 UTC
        for day in [1u32, 2, 3, 4, 5, 10, 20] {
            put_usage(&pool, &a, &format!("2026-06-{day:02}-05"), 10, 0, 1, 1).await;
        }
        let u = usage(&pool, a.as_str(), from, to)
            .await
            .expect("usage")
            .expect("sampled");
        assert_eq!(u.days_counted, 7);
        assert_eq!(u.days_in_period, 30, "June, not 30.0-something");
        assert!(
            !u.is_complete(),
            "7 sampled days must never be presented as a month"
        );
    }

    #[tokio::test]
    async fn requests_without_inbound_bytes_read_as_not_measured() {
        let (pool, a, b) = fresh().await;
        // The stock nginx log format carries no request size, so bw_in
        // lands as 0 while requests are counted. Printing "0 B přijato"
        // for a site that served 300 requests is a false statement.
        put_usage(&pool, &a, "2026-06-06-01", 10, 0, 5_000, 300).await;
        let u = usage(&pool, a.as_str(), DAY_FROM, DAY_TO)
            .await
            .expect("usage")
            .expect("sampled");
        assert_eq!(u.bw_in_bytes, None);
        assert_eq!(u.requests, 300, "the rest of the bucket is still real");

        // Genuinely nothing happened: zero bytes AND zero requests is a
        // measurement, not a gap.
        put_usage(&pool, &b, "2026-06-06-01", 10, 0, 0, 0).await;
        let ub = usage(&pool, b.as_str(), DAY_FROM, DAY_TO)
            .await
            .expect("usage")
            .expect("sampled");
        assert_eq!(ub.bw_in_bytes, Some(0));
    }

    // -------------------------------------------------------- uptime

    #[tokio::test]
    async fn uptime_counts_samples_and_successes_in_window() {
        let (pool, a, b) = fresh().await;
        for (ts, ok) in [
            (FROM, true), // included: the window is half-open at the start
            (FROM + 10, true),
            (FROM + 20, false),
            (TO - 1, true),    // included
            (FROM - 1, false), // excluded
            (TO, false),       // excluded
        ] {
            crate::monitors::insert_sample(&pool, &a, ts, ok, Some(200), 12, None)
                .await
                .expect("sample");
        }
        crate::monitors::insert_sample(&pool, &b, FROM + 5, false, None, 0, Some("boom"))
            .await
            .expect("sample b");

        let up = uptime(&pool, a.as_str(), FROM, TO).await.expect("uptime");
        assert_eq!(up.samples, 4, "both edges resolved correctly");
        assert_eq!(up.successes, 3);
        assert_eq!(up.failures(), 1);
        assert_eq!(up.success_ratio_x100(), Some(7500));

        // The other site's single failed check stays its own.
        let upb = uptime(&pool, b.as_str(), FROM, TO).await.expect("uptime");
        assert_eq!((upb.samples, upb.successes), (1, 0));
    }

    #[tokio::test]
    async fn uptime_without_samples_yields_no_percentage() {
        let (pool, a, _b) = fresh().await;
        // Monitoring never enabled. The counts are zero and — the whole
        // point — no percentage can be derived from them, so the report
        // cannot print a fabricated 100 %.
        let up = uptime(&pool, a.as_str(), FROM, TO).await.expect("uptime");
        assert_eq!((up.samples, up.successes), (0, 0));
        assert_eq!(up.success_ratio_x100(), None);

        // Samples that exist only OUTSIDE the period must not rescue it.
        crate::monitors::insert_sample(&pool, &a, FROM - 1, true, Some(200), 5, None)
            .await
            .expect("sample");
        let up = uptime(&pool, a.as_str(), FROM, TO).await.expect("uptime");
        assert_eq!(up.samples, 0);
        assert_eq!(up.success_ratio_x100(), None);
    }

    // ------------------------------------------------------- backups

    #[tokio::test]
    async fn backups_count_by_start_time_and_report_last_success() {
        let (pool, a, b) = fresh().await;
        // Two good runs and one failure inside; one good run before.
        let r1 = crate::backups::start(&pool, &a, "local", FROM)
            .await
            .expect("r1");
        crate::backups::mark_ok(&pool, r1, "/b/1.tar.gz", None, 10, FROM + 60)
            .await
            .expect("ok1");
        let r2 = crate::backups::start(&pool, &a, "local", TO - 1)
            .await
            .expect("r2");
        // Finishes AFTER the window closes — attribution is by start, so
        // this run belongs to this period and to no other.
        crate::backups::mark_ok(&pool, r2, "/b/2.tar.gz", None, 20, TO + 500)
            .await
            .expect("ok2");
        let r3 = crate::backups::start(&pool, &a, "local", FROM + 5)
            .await
            .expect("r3");
        crate::backups::mark_failed(&pool, r3, "disk full", FROM + 30)
            .await
            .expect("fail");
        // Outside the window entirely.
        let r0 = crate::backups::start(&pool, &a, "local", FROM - 100)
            .await
            .expect("r0");
        crate::backups::mark_ok(&pool, r0, "/b/0.tar.gz", None, 5, FROM - 50)
            .await
            .expect("ok0");
        // Still running: neither taken nor failed.
        crate::backups::start(&pool, &a, "local", FROM + 7)
            .await
            .expect("running");

        let bk = backups(&pool, a.as_str(), FROM, TO)
            .await
            .expect("backups")
            .expect("has history");
        assert_eq!(bk.taken, 2);
        assert_eq!(bk.failed, 1);
        assert_eq!(bk.last_success_at, Some(TO + 500));

        // The other site has no runs at all.
        assert_eq!(backups(&pool, b.as_str(), FROM, TO).await.expect("q"), None);
    }

    #[tokio::test]
    async fn backups_distinguish_never_configured_from_none_this_period() {
        let (pool, a, _b) = fresh().await;
        // No history at all ⇒ not measured. "0 záloh" would read as a
        // failure rather than as a feature never bought.
        assert_eq!(backups(&pool, a.as_str(), FROM, TO).await.expect("q"), None);

        // One run, but before the period: the site DOES take backups and
        // took none this month. That is a real, alarming measurement and
        // must survive as Some(0) — never collapse back into None.
        let r = crate::backups::start(&pool, &a, "local", FROM - 100)
            .await
            .expect("start");
        crate::backups::mark_ok(&pool, r, "/b/old.tar.gz", None, 1, FROM - 90)
            .await
            .expect("ok");
        let bk = backups(&pool, a.as_str(), FROM, TO)
            .await
            .expect("backups")
            .expect("history exists");
        assert_eq!(bk.taken, 0);
        assert_eq!(bk.failed, 0);
        assert_eq!(
            bk.last_success_at, None,
            "the report must not reach outside the period for a comforting date"
        );
    }

    // ------------------------------------------------------- updates

    async fn wp_audit(
        pool: &SqlitePool,
        ts: i64,
        target: &str,
        action: &str,
        wp_action: &str,
        result: &str,
    ) {
        crate::audit::append(
            pool,
            crate::audit::AppendReq {
                ts,
                actor_uid: 0,
                actor_label: "agent",
                action,
                target: Some(target),
                payload_json: &format!(
                    r#"{{"action":"{wp_action}","slug":"akismet","state":"{result}"}}"#
                ),
                result,
            },
        )
        .await
        .expect("audit");
    }

    /// Anchors the log before the window so `audit_covers` is satisfied
    /// — the coverage rule itself is exercised separately below.
    async fn anchor_audit(pool: &SqlitePool, ts: i64) {
        crate::audit::append(
            pool,
            crate::audit::AppendReq {
                ts,
                actor_uid: 0,
                actor_label: "agent",
                action: "agent.start",
                target: None,
                payload_json: "{}",
                result: "ok",
            },
        )
        .await
        .expect("anchor");
    }

    #[tokio::test]
    async fn updates_counted_from_the_audit_log() {
        let (pool, a, b) = fresh().await;
        anchor_audit(&pool, FROM - 10).await;
        // Applied, inside, both component kinds.
        wp_audit(&pool, FROM, a.as_str(), "wp.plugin.action", "update", "ok").await;
        wp_audit(&pool, TO - 1, a.as_str(), "wp.theme.action", "update", "ok").await;
        // An "update all" run — one row, no per-component count, so it
        // contributes a floor of 1.
        wp_audit(
            &pool,
            FROM + 1,
            a.as_str(),
            "wp.plugin.action",
            "update_all",
            "ok",
        )
        .await;
        // Not updates applied: a noop (already current), a failure, an
        // install, and another site's update.
        wp_audit(
            &pool,
            FROM + 2,
            a.as_str(),
            "wp.plugin.action",
            "update",
            "noop",
        )
        .await;
        wp_audit(
            &pool,
            FROM + 3,
            a.as_str(),
            "wp.plugin.action",
            "update",
            "failed",
        )
        .await;
        wp_audit(
            &pool,
            FROM + 4,
            a.as_str(),
            "wp.plugin.action",
            "install",
            "ok",
        )
        .await;
        wp_audit(
            &pool,
            FROM + 5,
            b.as_str(),
            "wp.plugin.action",
            "update",
            "ok",
        )
        .await;
        // Outside the window on both sides.
        wp_audit(
            &pool,
            FROM - 1,
            a.as_str(),
            "wp.plugin.action",
            "update",
            "ok",
        )
        .await;
        wp_audit(&pool, TO, a.as_str(), "wp.plugin.action", "update", "ok").await;

        assert_eq!(
            updates_applied(&pool, a.as_str(), FROM, TO)
                .await
                .expect("q"),
            Some(3)
        );
        assert_eq!(
            updates_applied(&pool, b.as_str(), FROM, TO)
                .await
                .expect("q"),
            Some(1)
        );
    }

    #[tokio::test]
    async fn updates_are_not_measured_when_the_log_misses_part_of_the_period() {
        let (pool, a, _b) = fresh().await;
        // Empty log: nothing to account with. NOT zero — a site whose
        // node was rebuilt mid-period may well have had ten updates.
        assert_eq!(
            updates_applied(&pool, a.as_str(), FROM, TO)
                .await
                .expect("q"),
            None
        );

        // Log starts INSIDE the period (retention purged the head, or the
        // node is younger than the period). Even with a visible update,
        // the count would be a partial total dressed up as a whole one.
        wp_audit(
            &pool,
            FROM + 100,
            a.as_str(),
            "wp.plugin.action",
            "update",
            "ok",
        )
        .await;
        assert_eq!(
            updates_applied(&pool, a.as_str(), FROM, TO)
                .await
                .expect("q"),
            None
        );

        // A row exactly ON the period start is enough: retention deletes
        // `ts < cutoff`, so its survival proves nothing inside the period
        // was purged.
        crate::audit::purge_older_than(&pool, 0, 0)
            .await
            .expect("noop purge");
        anchor_audit(&pool, FROM).await;
        assert_eq!(
            updates_applied(&pool, a.as_str(), FROM, TO)
                .await
                .expect("q"),
            Some(1)
        );
    }

    #[tokio::test]
    async fn a_covered_period_with_no_updates_is_a_measured_zero() {
        let (pool, a, _b) = fresh().await;
        anchor_audit(&pool, FROM - 10).await;
        // "We looked, and nothing needed applying" — genuinely different
        // from "we cannot tell", and the customer deserves to see which.
        assert_eq!(
            updates_applied(&pool, a.as_str(), FROM, TO)
                .await
                .expect("q"),
            Some(0)
        );
    }

    // ----------------------------------------------------- integrity

    async fn put_scan(pool: &SqlitePool, hosting: &str, json: &str) {
        crate::hosting_kv::set(pool, hosting, INTEGRITY_KV_KEY, json, 1)
            .await
            .expect("kv");
    }

    #[tokio::test]
    async fn integrity_is_reported_only_for_a_scan_inside_the_period() {
        let (pool, a, _b) = fresh().await;
        // Never scanned.
        assert_eq!(
            integrity(&pool, a.as_str(), FROM, TO).await.expect("q"),
            None
        );

        // Scanned, but before the period began. A clean bill of health
        // from last month says nothing about this month.
        put_scan(
            &pool,
            a.as_str(),
            &format!(
                r#"{{"scanned_at":{},"result":{{"wp_cli_ok":true,"clamav_available":true}}}}"#,
                FROM - 1
            ),
        )
        .await;
        assert_eq!(
            integrity(&pool, a.as_str(), FROM, TO).await.expect("q"),
            None
        );

        // Inside.
        put_scan(
            &pool,
            a.as_str(),
            &format!(
                r#"{{"scanned_at":{},"result":{{"wp_cli_ok":true,"clamav_available":true,
                     "core_modified":["wp-includes/x.php"],"malware":[]}}}}"#,
                FROM + 50
            ),
        )
        .await;
        let i = integrity(&pool, a.as_str(), FROM, TO)
            .await
            .expect("q")
            .expect("scanned");
        assert_eq!(i.scanned_at, FROM + 50);
        assert!(i.checksums_ran && i.malware_scan_ran);
        assert_eq!(i.core_issues, 1);
        assert_eq!(i.total_findings(), 1);
        assert!(!i.is_clean());
    }

    #[tokio::test]
    async fn integrity_without_a_malware_pass_is_never_clean() {
        let (pool, a, _b) = fresh().await;
        // No ClamAV on the node — a normal state on a shared host. Zero
        // hits here means "not looked for", so the report must say
        // "nekontrolováno", never "čisto".
        put_scan(
            &pool,
            a.as_str(),
            &format!(
                r#"{{"scanned_at":{},"result":{{"wp_cli_ok":true,"clamav_available":false}}}}"#,
                FROM + 1
            ),
        )
        .await;
        let i = integrity(&pool, a.as_str(), FROM, TO)
            .await
            .expect("q")
            .expect("scanned");
        assert!(!i.malware_scan_ran);
        assert_eq!(i.malware_hits, 0);
        assert!(!i.is_clean(), "an absent scanner never means clean");
    }

    #[tokio::test]
    async fn unparseable_stored_scan_reads_as_not_measured() {
        let (pool, a, _b) = fresh().await;
        // A shape change must cost the customer information, never
        // invent a verdict.
        put_scan(&pool, a.as_str(), "{oops").await;
        assert_eq!(
            integrity(&pool, a.as_str(), FROM, TO).await.expect("q"),
            None
        );
    }

    // ------------------------------------------------------- helpers

    #[tokio::test]
    async fn every_metric_of_an_untouched_site_reads_as_unmeasured() {
        // The load-bearing default. A brand-new site with a package on it
        // must produce a report full of "nekontrolováno", not a report
        // full of flattering zeros.
        let (pool, a, _b) = fresh().await;
        assert_eq!(usage(&pool, a.as_str(), FROM, TO).await.expect("q"), None);
        assert_eq!(backups(&pool, a.as_str(), FROM, TO).await.expect("q"), None);
        assert_eq!(
            integrity(&pool, a.as_str(), FROM, TO).await.expect("q"),
            None
        );
        assert_eq!(
            updates_applied(&pool, a.as_str(), FROM, TO)
                .await
                .expect("q"),
            None
        );
        assert_eq!(
            uptime(&pool, a.as_str(), FROM, TO)
                .await
                .expect("q")
                .success_ratio_x100(),
            None
        );
    }

    #[test]
    fn day_span_counts_calendar_days() {
        // Whole June: 30, not 30-point-something.
        assert_eq!(days_spanned(1_780_272_000, 1_782_864_000), 30);
        // A window ending exactly at midnight must not claim the next day.
        assert_eq!(days_spanned(DAY_FROM, DAY_TO), 1);
        assert_eq!(days_spanned(DAY_FROM, DAY_TO + 1), 2);
        // Degenerate windows have no days rather than a negative count.
        assert_eq!(days_spanned(DAY_TO, DAY_FROM), 0);
        assert_eq!(days_spanned(DAY_FROM, DAY_FROM), 0);
    }

    #[test]
    fn period_key_matches_the_sampler_format() {
        // Byte-identical to what `hosting_usage.period` holds, or every
        // traffic figure silently reads as "not measured".
        assert_eq!(period_key(1_780_704_000), "2026-06-06-00");
        assert_eq!(period_key(1_780_704_000 + 3_600), "2026-06-06-01");
    }
}
