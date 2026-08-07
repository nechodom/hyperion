//! `hosting_limits`, `hosting_suspension`, `hosting_usage` tables.

use crate::db::StateError;
use hyperion_types::HostingId;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsRow {
    pub hosting_id: HostingId,
    pub disk_soft_bytes: Option<i64>,
    pub disk_hard_bytes: Option<i64>,
    pub inode_soft: Option<i64>,
    pub inode_hard: Option<i64>,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub bw_monthly_bytes: Option<i64>,
    pub over_bw_policy: String,
    pub throttle_kbps: Option<i64>,
    pub updated_at: i64,
}

impl LimitsRow {
    /// Default limits used when no row exists yet for a hosting.
    pub fn defaults_for(hosting_id: &HostingId, now: i64) -> Self {
        Self {
            hosting_id: hosting_id.clone(),
            disk_soft_bytes: None,
            disk_hard_bytes: None,
            inode_soft: None,
            inode_hard: None,
            php_memory_mb: 256,
            php_max_exec_secs: 60,
            php_max_children: 5,
            php_max_requests: 1000,
            db_max_connections: 25,
            bw_monthly_bytes: None,
            over_bw_policy: "suspend".into(),
            throttle_kbps: None,
            updated_at: now,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert(pool: &SqlitePool, row: &LimitsRow) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_limits (
            hosting_id,
            disk_soft_bytes, disk_hard_bytes, inode_soft, inode_hard,
            php_memory_mb, php_max_exec_secs, php_max_children, php_max_requests,
            db_max_connections,
            bw_monthly_bytes, over_bw_policy, throttle_kbps,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hosting_id) DO UPDATE SET
            disk_soft_bytes    = excluded.disk_soft_bytes,
            disk_hard_bytes    = excluded.disk_hard_bytes,
            inode_soft         = excluded.inode_soft,
            inode_hard         = excluded.inode_hard,
            php_memory_mb      = excluded.php_memory_mb,
            php_max_exec_secs  = excluded.php_max_exec_secs,
            php_max_children   = excluded.php_max_children,
            php_max_requests   = excluded.php_max_requests,
            db_max_connections = excluded.db_max_connections,
            bw_monthly_bytes   = excluded.bw_monthly_bytes,
            over_bw_policy     = excluded.over_bw_policy,
            throttle_kbps      = excluded.throttle_kbps,
            updated_at         = excluded.updated_at"#,
    )
    .bind(row.hosting_id.as_str())
    .bind(row.disk_soft_bytes)
    .bind(row.disk_hard_bytes)
    .bind(row.inode_soft)
    .bind(row.inode_hard)
    .bind(row.php_memory_mb)
    .bind(row.php_max_exec_secs)
    .bind(row.php_max_children)
    .bind(row.php_max_requests)
    .bind(row.db_max_connections)
    .bind(row.bw_monthly_bytes)
    .bind(&row.over_bw_policy)
    .bind(row.throttle_kbps)
    .bind(row.updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get(pool: &SqlitePool, id: &HostingId) -> Result<Option<LimitsRow>, StateError> {
    type Tup = (
        String,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        i64,
        i64,
        i64,
        i64,
        i64,
        Option<i64>,
        String,
        Option<i64>,
        i64,
    );
    let row: Option<Tup> = sqlx::query_as(
        "SELECT hosting_id,
                disk_soft_bytes, disk_hard_bytes, inode_soft, inode_hard,
                php_memory_mb, php_max_exec_secs, php_max_children, php_max_requests,
                db_max_connections,
                bw_monthly_bytes, over_bw_policy, throttle_kbps,
                updated_at
         FROM hosting_limits WHERE hosting_id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            hosting_id,
            ds,
            dh,
            ino_s,
            ino_h,
            mem,
            exec,
            ch,
            req,
            db_conn,
            bw,
            policy,
            kbps,
            updated_at,
        )| LimitsRow {
            hosting_id: HostingId(hosting_id),
            disk_soft_bytes: ds,
            disk_hard_bytes: dh,
            inode_soft: ino_s,
            inode_hard: ino_h,
            php_memory_mb: mem,
            php_max_exec_secs: exec,
            php_max_children: ch,
            php_max_requests: req,
            db_max_connections: db_conn,
            bw_monthly_bytes: bw,
            over_bw_policy: policy,
            throttle_kbps: kbps,
            updated_at,
        },
    ))
}

pub async fn delete(pool: &SqlitePool, id: &HostingId) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_limits WHERE hosting_id = ?")
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- Suspension ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspensionRow {
    pub hosting_id: HostingId,
    pub suspended_at: i64,
    pub suspended_by: String,
    pub reason_message: Option<String>,
    pub custom_page_html: Option<String>,
}

pub async fn insert_suspension(pool: &SqlitePool, row: &SuspensionRow) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_suspension
           (hosting_id, suspended_at, suspended_by, reason_message, custom_page_html)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(hosting_id) DO UPDATE SET
             suspended_at = excluded.suspended_at,
             suspended_by = excluded.suspended_by,
             reason_message = excluded.reason_message,
             custom_page_html = excluded.custom_page_html"#,
    )
    .bind(row.hosting_id.as_str())
    .bind(row.suspended_at)
    .bind(&row.suspended_by)
    .bind(&row.reason_message)
    .bind(&row.custom_page_html)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_suspension(
    pool: &SqlitePool,
    id: &HostingId,
) -> Result<Option<SuspensionRow>, StateError> {
    let row: Option<(String, i64, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT hosting_id, suspended_at, suspended_by, reason_message, custom_page_html
         FROM hosting_suspension WHERE hosting_id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(hosting_id, ts, by, msg, html)| SuspensionRow {
        hosting_id: HostingId(hosting_id),
        suspended_at: ts,
        suspended_by: by,
        reason_message: msg,
        custom_page_html: html,
    }))
}

pub async fn delete_suspension(pool: &SqlitePool, id: &HostingId) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_suspension WHERE hosting_id = ?")
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- Usage ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageBucket {
    pub hosting_id: HostingId,
    pub period: String,
    pub disk_used_bytes: i64,
    pub inodes_used: i64,
    pub bw_in_bytes: i64,
    pub bw_out_bytes: i64,
    pub php_requests: i64,
    /// Migration 043: latest RSS of the hosting's processes (bytes) + CPU %.
    pub mem_rss_bytes: i64,
    pub cpu_pct_x100: i64,
}

pub async fn upsert_usage(pool: &SqlitePool, bucket: &UsageBucket) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_usage
           (hosting_id, period, disk_used_bytes, inodes_used, bw_in_bytes, bw_out_bytes,
            php_requests, mem_rss_bytes, cpu_pct_x100)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(hosting_id, period) DO UPDATE SET
             disk_used_bytes = excluded.disk_used_bytes,
             inodes_used     = excluded.inodes_used,
             -- Traffic within one hour only ever grows, so a LOWER reading
             -- is not a correction — it is the log having been rotated or
             -- truncated underneath us mid-hour. Taking the max keeps what
             -- was already measured instead of erasing it. Disk, inodes,
             -- memory and CPU are LEVELS and must still track downwards.
             bw_in_bytes     = MAX(bw_in_bytes,  excluded.bw_in_bytes),
             bw_out_bytes    = MAX(bw_out_bytes, excluded.bw_out_bytes),
             php_requests    = MAX(php_requests, excluded.php_requests),
             mem_rss_bytes   = excluded.mem_rss_bytes,
             cpu_pct_x100    = excluded.cpu_pct_x100"#,
    )
    .bind(bucket.hosting_id.as_str())
    .bind(&bucket.period)
    .bind(bucket.disk_used_bytes)
    .bind(bucket.inodes_used)
    .bind(bucket.bw_in_bytes)
    .bind(bucket.bw_out_bytes)
    .bind(bucket.php_requests)
    .bind(bucket.mem_rss_bytes)
    .bind(bucket.cpu_pct_x100)
    .execute(pool)
    .await?;
    Ok(())
}

/// Write ONLY the three traffic columns of one bucket, leaving disk,
/// inodes, memory and CPU as they were.
///
/// Used to backfill the hour the sampler has just left. Those other
/// columns are point-in-time readings that belonged to that hour when it
/// was live; overwriting them now with the CURRENT disk or RSS would
/// rewrite history, and `MAX(disk_used_bytes)` over a period — the care
/// report's "peak disk use" — would report today's figure as the peak.
///
/// When no row exists yet the insert supplies zeros for those columns.
/// That is correct rather than merely convenient: a zero cannot raise a
/// MAX, and the hour genuinely did carry traffic, so it belongs in the
/// DISTINCT-date coverage count.
///
/// Like [`upsert_usage`], an existing value is never LOWERED — see the
/// comment there. Both writers can land on the same closed hour, and the
/// one holding a rotated-away log must not win.
pub async fn upsert_usage_traffic(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    period: &str,
    bw_in_bytes: i64,
    bw_out_bytes: i64,
    php_requests: i64,
) -> Result<(), StateError> {
    // NOTE: six positional binds, left to right — hosting_id, period, then
    // the three traffic values in the VALUES list. The UPDATE clause reads
    // from `excluded`, so it adds no binds of its own.
    sqlx::query(
        r#"INSERT INTO hosting_usage
           (hosting_id, period, disk_used_bytes, inodes_used, bw_in_bytes, bw_out_bytes,
            php_requests, mem_rss_bytes, cpu_pct_x100)
           VALUES (?, ?, 0, 0, ?, ?, ?, 0, 0)
           ON CONFLICT(hosting_id, period) DO UPDATE SET
             bw_in_bytes  = MAX(bw_in_bytes,  excluded.bw_in_bytes),
             bw_out_bytes = MAX(bw_out_bytes, excluded.bw_out_bytes),
             php_requests = MAX(php_requests, excluded.php_requests)"#,
    )
    .bind(hosting_id.as_str())
    .bind(period)
    .bind(bw_in_bytes)
    .bind(bw_out_bytes)
    .bind(php_requests)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::type_complexity)] // positional row tuple; mirrors the table
pub async fn usage_for(
    pool: &SqlitePool,
    id: &HostingId,
    limit: i64,
) -> Result<Vec<UsageBucket>, StateError> {
    let rows: Vec<(String, String, i64, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT hosting_id, period, disk_used_bytes, inodes_used,
                bw_in_bytes, bw_out_bytes, php_requests, mem_rss_bytes, cpu_pct_x100
         FROM hosting_usage WHERE hosting_id = ? ORDER BY period DESC LIMIT ?",
    )
    .bind(id.as_str())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(hosting_id, period, disk, inodes, bw_in, bw_out, php, mem_rss, cpu)| UsageBucket {
                hosting_id: HostingId(hosting_id),
                period,
                disk_used_bytes: disk,
                inodes_used: inodes,
                bw_in_bytes: bw_in,
                bw_out_bytes: bw_out,
                php_requests: php,
                mem_rss_bytes: mem_rss,
                cpu_pct_x100: cpu,
            },
        )
        .collect())
}

/// One hosting's usage rolled up over its most recent `limit` periods.
/// Produced by [`usage_rollup_all`] — the bulk sibling of [`usage_for`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRollup {
    pub hosting_id: HostingId,
    /// MAX over the window: disk is a level, not a flow — summing it
    /// would report 24× the real footprint.
    pub disk_used_bytes: i64,
    pub bw_in_bytes: i64,
    pub bw_out_bytes: i64,
    pub php_requests: i64,
    /// From the SINGLE most recent period only — RSS and CPU% are
    /// instantaneous gauges, so a sum is meaningless.
    pub mem_rss_bytes: i64,
    pub cpu_pct_x100: i64,
    /// How many periods actually fed the aggregate (1..=limit). Lets
    /// callers distinguish "sampled, and it was zero" from "never
    /// sampled" without a second query.
    pub periods: i64,
}

/// Roll up `hosting_usage` for EVERY hosting in one round-trip.
///
/// Exists because the /stats per-site breakdown needs N hostings at
/// once and [`usage_for`] is per-hosting — N sites would be N queries
/// per node. The aggregation must stay byte-for-byte identical to what
/// `HostingService::hosting_stats` computes in Rust from `usage_for`,
/// or the hosting detail page and the breakdown table would disagree
/// about the same site.
///
/// The window function ranks each hosting's periods independently, so
/// `rn <= limit` is a per-hosting "latest N" — a plain `LIMIT` would
/// cut across hostings and starve the ones sorted last.
pub async fn usage_rollup_all(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<UsageRollup>, StateError> {
    // NOTE: exactly ONE positional bind (`limit`, in the WHERE). Adding
    // a filter here means adding its .bind() in the same left-to-right
    // order — a misaligned bind silently yields empty/wrong rows.
    let rows: Vec<(String, i64, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "WITH ranked AS (
             SELECT hosting_id, disk_used_bytes, bw_in_bytes, bw_out_bytes,
                    php_requests, mem_rss_bytes, cpu_pct_x100,
                    ROW_NUMBER() OVER (
                        PARTITION BY hosting_id ORDER BY period DESC
                    ) AS rn
             FROM hosting_usage
         )
         SELECT hosting_id,
                MAX(disk_used_bytes)                                   AS disk_used_bytes,
                SUM(bw_in_bytes)                                       AS bw_in_bytes,
                SUM(bw_out_bytes)                                      AS bw_out_bytes,
                SUM(php_requests)                                      AS php_requests,
                COALESCE(MAX(CASE WHEN rn = 1 THEN mem_rss_bytes END), 0) AS mem_rss_bytes,
                COALESCE(MAX(CASE WHEN rn = 1 THEN cpu_pct_x100  END), 0) AS cpu_pct_x100,
                COUNT(*)                                               AS periods
         FROM ranked
         WHERE rn <= ?
         GROUP BY hosting_id",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(hosting_id, disk, bw_in, bw_out, php, mem_rss, cpu, periods)| UsageRollup {
                hosting_id: HostingId(hosting_id),
                disk_used_bytes: disk,
                bw_in_bytes: bw_in,
                bw_out_bytes: bw_out,
                php_requests: php,
                mem_rss_bytes: mem_rss,
                cpu_pct_x100: cpu,
                periods,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;
    use crate::{hostings, system_users};

    async fn fixture(pool: &SqlitePool) -> HostingId {
        let suid = system_users::insert(pool, "u", 1042, "/home/u", "/x", 1)
            .await
            .expect("user");
        let id = HostingId::new_v7();
        hostings::insert(pool, &id, "example.cz", suid, None, "/r", 1, None)
            .await
            .expect("hosting");
        id
    }

    /// Second/third hosting for the bulk-rollup tests — needs its own
    /// system user because `system_users` is unique on name + uid.
    async fn fixture_named(pool: &SqlitePool, user: &str, uid: i64, domain: &str) -> HostingId {
        let suid = system_users::insert(pool, user, uid, &format!("/home/{user}"), "/x", 1)
            .await
            .expect("user");
        let id = HostingId::new_v7();
        hostings::insert(pool, &id, domain, suid, None, "/r", 1, None)
            .await
            .expect("hosting");
        id
    }

    /// `period` is 'YYYY-MM-DD-HH'; callers pass the hour so the
    /// lexicographic DESC ordering is also chronological.
    async fn put_usage(
        pool: &SqlitePool,
        id: &HostingId,
        hour: u32,
        disk: i64,
        bw_in: i64,
        bw_out: i64,
        reqs: i64,
        mem: i64,
        cpu: i64,
    ) {
        upsert_usage(
            pool,
            &UsageBucket {
                hosting_id: id.clone(),
                period: format!("2026-06-01-{hour:02}"),
                disk_used_bytes: disk,
                inodes_used: 0,
                bw_in_bytes: bw_in,
                bw_out_bytes: bw_out,
                php_requests: reqs,
                mem_rss_bytes: mem,
                cpu_pct_x100: cpu,
            },
        )
        .await
        .expect("upsert usage");
    }

    fn find<'a>(rollups: &'a [UsageRollup], id: &HostingId) -> Option<&'a UsageRollup> {
        rollups.iter().find(|r| &r.hosting_id == id)
    }

    #[tokio::test]
    async fn limits_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let mut row = LimitsRow::defaults_for(&id, 100);
        row.php_memory_mb = 512;
        row.disk_hard_bytes = Some(5_368_709_120);
        upsert(&pool, &row).await.expect("upsert");
        let got = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.php_memory_mb, 512);
        assert_eq!(got.disk_hard_bytes, Some(5_368_709_120));
    }

    #[tokio::test]
    async fn limits_upsert_updates_on_conflict() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let mut row = LimitsRow::defaults_for(&id, 100);
        row.php_memory_mb = 128;
        upsert(&pool, &row).await.expect("upsert");
        row.php_memory_mb = 1024;
        row.updated_at = 200;
        upsert(&pool, &row).await.expect("upsert again");
        let got = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.php_memory_mb, 1024);
        assert_eq!(got.updated_at, 200);
    }

    #[tokio::test]
    async fn limits_cascade_delete_with_hosting() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &LimitsRow::defaults_for(&id, 1))
            .await
            .expect("upsert");
        hostings::delete(&pool, &id).await.expect("delete");
        let got = get(&pool, &id).await.expect("get");
        assert!(got.is_none(), "limits cascade-deleted");
    }

    #[tokio::test]
    async fn over_bw_policy_check_constraint() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let mut row = LimitsRow::defaults_for(&id, 1);
        row.over_bw_policy = "bogus".into();
        let r = upsert(&pool, &row).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn suspension_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let row = SuspensionRow {
            hosting_id: id.clone(),
            suspended_at: 500,
            suspended_by: "manual".into(),
            reason_message: Some("over quota".into()),
            custom_page_html: None,
        };
        insert_suspension(&pool, &row).await.expect("insert");
        let got = get_suspension(&pool, &id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got, row);
        delete_suspension(&pool, &id).await.expect("delete");
        assert!(get_suspension(&pool, &id).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn hostings_state_check_allows_suspended() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        sqlx::query("UPDATE hostings SET state='suspended' WHERE id = ?")
            .bind(id.as_str())
            .execute(&pool)
            .await
            .expect("update");
        let row = hostings::get_by_id(&pool, &id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(row.state.as_str(), "suspended");
    }

    #[tokio::test]
    async fn usage_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let bucket = UsageBucket {
            hosting_id: id.clone(),
            period: "2026-06-01-00".into(),
            disk_used_bytes: 1024,
            inodes_used: 12,
            bw_in_bytes: 2048,
            bw_out_bytes: 4096,
            php_requests: 17,
            mem_rss_bytes: 33_554_432,
            cpu_pct_x100: 1250,
        };
        upsert_usage(&pool, &bucket).await.expect("upsert");
        let got = usage_for(&pool, &id, 10).await.expect("get");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], bucket);
    }

    #[tokio::test]
    async fn usage_rollup_all_aggregates_each_hosting_independently() {
        let pool = open_memory().await.expect("open");
        let a = fixture(&pool).await;
        let b = fixture_named(&pool, "v", 1043, "other.cz").await;

        // Hosting A: disk peaks in the MIDDLE period, so a naive
        // "latest disk" would report 100 instead of the 900 peak.
        put_usage(&pool, &a, 10, 100, 1, 10, 100, 111, 11).await;
        put_usage(&pool, &a, 11, 900, 2, 20, 200, 222, 22).await;
        put_usage(&pool, &a, 12, 300, 4, 40, 400, 333, 33).await;
        // Hosting B: different magnitudes, so cross-contamination shows.
        put_usage(&pool, &b, 10, 7, 5, 50, 5, 777, 77).await;
        put_usage(&pool, &b, 11, 9, 6, 60, 6, 888, 88).await;

        let got = usage_rollup_all(&pool, 24).await.expect("rollup");
        assert_eq!(got.len(), 2, "one row per hosting that has usage");

        let ra = find(&got, &a).expect("hosting a present");
        assert_eq!(ra.disk_used_bytes, 900, "disk is MAX over the window");
        assert_eq!(ra.bw_in_bytes, 1 + 2 + 4);
        assert_eq!(ra.bw_out_bytes, 10 + 20 + 40);
        assert_eq!(ra.php_requests, 100 + 200 + 400);
        // Instantaneous gauges come from period 12 only, never summed.
        assert_eq!(ra.mem_rss_bytes, 333);
        assert_eq!(ra.cpu_pct_x100, 33);
        assert_eq!(ra.periods, 3);

        let rb = find(&got, &b).expect("hosting b present");
        assert_eq!(rb.disk_used_bytes, 9);
        assert_eq!(rb.bw_in_bytes, 5 + 6);
        assert_eq!(rb.bw_out_bytes, 50 + 60);
        assert_eq!(rb.php_requests, 5 + 6);
        assert_eq!(rb.mem_rss_bytes, 888);
        assert_eq!(rb.cpu_pct_x100, 88);
        assert_eq!(rb.periods, 2);
    }

    #[tokio::test]
    async fn usage_rollup_all_limit_is_per_hosting_not_global() {
        let pool = open_memory().await.expect("open");
        let a = fixture(&pool).await;
        let b = fixture_named(&pool, "v", 1043, "other.cz").await;

        // 3 periods each, window = 2 → the oldest of each must drop.
        // A's oldest carries an absurd disk + bw so leakage is loud.
        put_usage(&pool, &a, 10, 999_999, 1_000, 1_000, 1_000, 1, 1).await;
        put_usage(&pool, &a, 11, 10, 1, 2, 3, 2, 2).await;
        put_usage(&pool, &a, 12, 20, 1, 2, 3, 42, 43).await;
        put_usage(&pool, &b, 10, 888_888, 1_000, 1_000, 1_000, 1, 1).await;
        put_usage(&pool, &b, 11, 30, 7, 8, 9, 3, 3).await;
        put_usage(&pool, &b, 12, 40, 7, 8, 9, 55, 56).await;

        let got = usage_rollup_all(&pool, 2).await.expect("rollup");
        let ra = find(&got, &a).expect("hosting a present");
        assert_eq!(ra.periods, 2, "a global LIMIT would starve one hosting");
        assert_eq!(ra.disk_used_bytes, 20);
        assert_eq!(ra.bw_in_bytes, 2);
        assert_eq!(ra.bw_out_bytes, 4);
        assert_eq!(ra.php_requests, 6);
        assert_eq!(ra.mem_rss_bytes, 42);
        assert_eq!(ra.cpu_pct_x100, 43);

        let rb = find(&got, &b).expect("hosting b present");
        assert_eq!(rb.periods, 2);
        assert_eq!(rb.disk_used_bytes, 40);
        assert_eq!(rb.bw_in_bytes, 14);
        assert_eq!(rb.bw_out_bytes, 16);
        assert_eq!(rb.php_requests, 18);
        assert_eq!(rb.mem_rss_bytes, 55);
        assert_eq!(rb.cpu_pct_x100, 56);
    }

    #[tokio::test]
    async fn usage_rollup_all_omits_never_sampled_hostings() {
        let pool = open_memory().await.expect("open");
        let a = fixture(&pool).await;
        let b = fixture_named(&pool, "v", 1043, "other.cz").await;
        put_usage(&pool, &a, 10, 5, 1, 2, 3, 4, 5).await;

        let got = usage_rollup_all(&pool, 24).await.expect("rollup");
        // A brand-new site has no usage rows at all. The query simply
        // omits it (GROUP BY over an empty set); the caller is the one
        // that back-fills zeros from its hosting list, so a fresh site
        // never silently vanishes from the breakdown.
        assert_eq!(got.len(), 1);
        assert!(find(&got, &b).is_none(), "no rows ⇒ no group");
        assert_eq!(find(&got, &a).expect("a").periods, 1);
    }

    #[tokio::test]
    async fn usage_rollup_all_on_empty_table_is_empty() {
        let pool = open_memory().await.expect("open");
        let _ = fixture(&pool).await;
        let got = usage_rollup_all(&pool, 24).await.expect("rollup");
        assert!(got.is_empty());
    }

    /// Guards the invariant the two call sites depend on: the bulk
    /// rollup and `HostingService::hosting_stats`' Rust-side fold over
    /// `usage_for` must produce identical numbers for the same rows.
    #[tokio::test]
    async fn usage_rollup_all_matches_usage_for_fold() {
        let pool = open_memory().await.expect("open");
        let a = fixture(&pool).await;
        for h in 0..30u32 {
            put_usage(
                &pool,
                &a,
                h,
                (h as i64 * 37) % 500,
                h as i64,
                h as i64 * 2,
                h as i64 * 3,
                h as i64 * 1000,
                h as i64 * 7,
            )
            .await;
        }

        let rows = usage_for(&pool, &a, 24).await.expect("usage_for");
        let (mut disk, mut bw_in, mut bw_out, mut reqs) = (0i64, 0i64, 0i64, 0i64);
        for r in &rows {
            disk = disk.max(r.disk_used_bytes);
            bw_in += r.bw_in_bytes;
            bw_out += r.bw_out_bytes;
            reqs += r.php_requests;
        }
        let (mem, cpu) = rows
            .first()
            .map(|r| (r.mem_rss_bytes, r.cpu_pct_x100))
            .unwrap_or((0, 0));

        let got = usage_rollup_all(&pool, 24).await.expect("rollup");
        let ra = find(&got, &a).expect("a");
        assert_eq!(ra.disk_used_bytes, disk);
        assert_eq!(ra.bw_in_bytes, bw_in);
        assert_eq!(ra.bw_out_bytes, bw_out);
        assert_eq!(ra.php_requests, reqs);
        assert_eq!(ra.mem_rss_bytes, mem);
        assert_eq!(ra.cpu_pct_x100, cpu);
        assert_eq!(ra.periods, rows.len() as i64);
    }
}
