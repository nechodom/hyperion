//! Five-minute per-site usage history (`hosting_usage_samples`).
//!
//! Written once per site by the stats tick, read as a rollup over whatever
//! window the /stats range picker asks for. Node-local: each agent writes and
//! reads its own rows.

use crate::db::StateError;
use hyperion_types::HostingId;
use sqlx::SqlitePool;

/// What one site did during one stats tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageSample {
    pub hosting_id: HostingId,
    pub at: i64,
    pub cpu_busy_jiffies: i64,
    pub cpu_total_jiffies: i64,
    pub cpu_peak_x100: i64,
    pub mem_rss_bytes: i64,
    pub bw_in_bytes: i64,
    pub bw_out_bytes: i64,
    pub requests: i64,
}

/// One site's samples rolled up over a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageSampleRollup {
    pub hosting_id: HostingId,
    pub cpu_busy_jiffies: i64,
    pub cpu_total_jiffies: i64,
    pub cpu_peak_x100: i64,
    pub mem_avg_bytes: i64,
    pub mem_peak_bytes: i64,
    pub bw_in_bytes: i64,
    pub bw_out_bytes: i64,
    pub requests: i64,
    /// Oldest and newest sample in the window, so a caller can tell a quiet
    /// window from one the history does not reach back to yet.
    pub first_at: i64,
    pub last_at: i64,
}

impl UsageSampleRollup {
    /// Average share of the node's CPU, × 100. `None` when no tick in the
    /// window measured CPU at all, which is not the same as an idle site.
    pub fn cpu_avg_x100(&self) -> Option<i64> {
        (self.cpu_total_jiffies > 0).then(|| {
            (self.cpu_busy_jiffies.saturating_mul(10_000) / self.cpu_total_jiffies).clamp(0, 10_000)
        })
    }
}

/// Record one sample. A second write for the same site and second replaces.
pub async fn insert(pool: &SqlitePool, s: &UsageSample) -> Result<(), StateError> {
    sqlx::query(
        "INSERT OR REPLACE INTO hosting_usage_samples
           (hosting_id, at, cpu_busy_jiffies, cpu_total_jiffies, cpu_peak_x100,
            mem_rss_bytes, bw_in_bytes, bw_out_bytes, requests)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(s.hosting_id.as_str())
    .bind(s.at)
    .bind(s.cpu_busy_jiffies)
    .bind(s.cpu_total_jiffies)
    .bind(s.cpu_peak_x100)
    .bind(s.mem_rss_bytes)
    .bind(s.bw_in_bytes)
    .bind(s.bw_out_bytes)
    .bind(s.requests)
    .execute(pool)
    .await?;
    Ok(())
}

/// Roll up every sample at or after `since`, one row per site. `only` narrows
/// it to one site for the hosting detail page.
#[allow(clippy::type_complexity)] // positional row tuple; mirrors the SELECT
pub async fn rollup_since(
    pool: &SqlitePool,
    since: i64,
    only: Option<&HostingId>,
) -> Result<Vec<UsageSampleRollup>, StateError> {
    // NOTE: THREE positional binds, left to right: since, then `only` twice.
    let only = only.map(|id| id.as_str().to_string());
    let rows: Vec<(String, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT hosting_id,
                SUM(cpu_busy_jiffies), SUM(cpu_total_jiffies), MAX(cpu_peak_x100),
                CAST(AVG(mem_rss_bytes) AS INTEGER), MAX(mem_rss_bytes),
                SUM(bw_in_bytes), SUM(bw_out_bytes), SUM(requests),
                MIN(at), MAX(at)
         FROM hosting_usage_samples
         WHERE at >= ? AND (? IS NULL OR hosting_id = ?)
         GROUP BY hosting_id",
    )
    .bind(since)
    .bind(only.clone())
    .bind(only)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, busy, total, peak, mem_avg, mem_peak, bw_in, bw_out, requests, first, last)| {
                UsageSampleRollup {
                    hosting_id: HostingId(id),
                    cpu_busy_jiffies: busy,
                    cpu_total_jiffies: total,
                    cpu_peak_x100: peak,
                    mem_avg_bytes: mem_avg,
                    mem_peak_bytes: mem_peak,
                    bw_in_bytes: bw_in,
                    bw_out_bytes: bw_out,
                    requests,
                    first_at: first,
                    last_at: last,
                }
            },
        )
        .collect())
}

/// Delete samples older than `cutoff`.
pub async fn prune_older_than(pool: &SqlitePool, cutoff: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_usage_samples WHERE at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    fn sample(id: &str, at: i64, busy: i64, total: i64, peak: i64, mem: i64) -> UsageSample {
        UsageSample {
            hosting_id: HostingId(id.into()),
            at,
            cpu_busy_jiffies: busy,
            cpu_total_jiffies: total,
            cpu_peak_x100: peak,
            mem_rss_bytes: mem,
            bw_in_bytes: 10,
            bw_out_bytes: 20,
            requests: 3,
        }
    }

    #[tokio::test]
    async fn rollup_covers_only_the_window_and_weights_cpu_by_time() {
        let pool = open_memory().await.expect("open");
        for s in [
            sample("a", 100, 900, 1_000, 9_500, 400), // outside the window
            sample("a", 200, 10, 1_000, 300, 100),
            sample("a", 300, 30, 3_000, 200, 300),
            sample("b", 300, 0, 1_000, 0, 50),
        ] {
            insert(&pool, &s).await.expect("insert");
        }
        let rows = rollup_since(&pool, 150, None).await.expect("rollup");
        let a = rows.iter().find(|r| r.hosting_id.0 == "a").expect("a");
        // 40 of 4000 = 1%, not the 1% + 1% / 2 a naive mean of the two ticks
        // happens to give here: a longer tick must weigh more.
        assert_eq!(a.cpu_avg_x100(), Some(100));
        assert_eq!(a.cpu_peak_x100, 300, "the spike outside the window is gone");
        assert_eq!((a.mem_avg_bytes, a.mem_peak_bytes), (200, 300));
        assert_eq!((a.bw_in_bytes, a.bw_out_bytes, a.requests), (20, 40, 6));
        assert_eq!((a.first_at, a.last_at), (200, 300));

        let b = rows.iter().find(|r| r.hosting_id.0 == "b").expect("b");
        assert_eq!(b.cpu_avg_x100(), Some(0), "measured and idle is a real 0");
    }

    #[tokio::test]
    async fn rollup_tells_unmeasured_cpu_from_idle() {
        let pool = open_memory().await.expect("open");
        insert(&pool, &sample("a", 100, 0, 0, 0, 1))
            .await
            .expect("insert");
        let rows = rollup_since(&pool, 0, None).await.expect("rollup");
        assert_eq!(rows[0].cpu_avg_x100(), None);
    }

    #[tokio::test]
    async fn rollup_can_be_narrowed_to_one_site() {
        let pool = open_memory().await.expect("open");
        insert(&pool, &sample("a", 100, 1, 2, 3, 4))
            .await
            .expect("insert");
        insert(&pool, &sample("b", 100, 1, 2, 3, 4))
            .await
            .expect("insert");
        let id = HostingId("b".into());
        let rows = rollup_since(&pool, 0, Some(&id)).await.expect("rollup");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].hosting_id, id);
    }

    #[tokio::test]
    async fn prune_drops_only_older_rows() {
        let pool = open_memory().await.expect("open");
        insert(&pool, &sample("a", 100, 1, 2, 3, 4))
            .await
            .expect("insert");
        insert(&pool, &sample("a", 200, 1, 2, 3, 4))
            .await
            .expect("insert");
        prune_older_than(&pool, 150).await.expect("prune");
        let rows = rollup_since(&pool, 0, None).await.expect("rollup");
        assert_eq!(rows[0].first_at, 200);
    }
}
