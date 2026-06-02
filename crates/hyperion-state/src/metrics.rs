//! `node_metrics` table — rolling per-tick node-wide samples.

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeMetricsRow {
    pub id: i64,
    pub sampled_at: i64,
    pub hostings_count: i64,
    pub hostings_active: i64,
    pub hostings_suspended: i64,
    pub hostings_failed: i64,
    pub total_disk_bytes: i64,
    pub total_bw_out_24h: i64,
    pub total_requests_24h: i64,
    pub loadavg_1m_x100: i64,
    pub mem_total_kib: i64,
    pub mem_used_kib: i64,
    pub uptime_secs: i64,
}

#[derive(Debug, Clone, Default)]
pub struct NodeMetricsInput {
    pub sampled_at: i64,
    pub hostings_count: i64,
    pub hostings_active: i64,
    pub hostings_suspended: i64,
    pub hostings_failed: i64,
    pub total_disk_bytes: i64,
    pub total_bw_out_24h: i64,
    pub total_requests_24h: i64,
    pub loadavg_1m_x100: i64,
    pub mem_total_kib: i64,
    pub mem_used_kib: i64,
    pub uptime_secs: i64,
}

pub async fn insert(pool: &SqlitePool, m: &NodeMetricsInput) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO node_metrics
           (sampled_at, hostings_count, hostings_active, hostings_suspended,
            hostings_failed, total_disk_bytes, total_bw_out_24h,
            total_requests_24h, loadavg_1m_x100, mem_total_kib, mem_used_kib,
            uptime_secs)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id"#,
    )
    .bind(m.sampled_at)
    .bind(m.hostings_count)
    .bind(m.hostings_active)
    .bind(m.hostings_suspended)
    .bind(m.hostings_failed)
    .bind(m.total_disk_bytes)
    .bind(m.total_bw_out_24h)
    .bind(m.total_requests_24h)
    .bind(m.loadavg_1m_x100)
    .bind(m.mem_total_kib)
    .bind(m.mem_used_kib)
    .bind(m.uptime_secs)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn latest(pool: &SqlitePool) -> Result<Option<NodeMetricsRow>, StateError> {
    let row: Option<(
        i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64,
    )> = sqlx::query_as(
        "SELECT id, sampled_at, hostings_count, hostings_active, hostings_suspended,
                hostings_failed, total_disk_bytes, total_bw_out_24h,
                total_requests_24h, loadavg_1m_x100, mem_total_kib, mem_used_kib,
                uptime_secs
         FROM node_metrics ORDER BY sampled_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            id,
            sampled_at,
            hostings_count,
            hostings_active,
            hostings_suspended,
            hostings_failed,
            total_disk_bytes,
            total_bw_out_24h,
            total_requests_24h,
            loadavg_1m_x100,
            mem_total_kib,
            mem_used_kib,
            uptime_secs,
        )| NodeMetricsRow {
            id,
            sampled_at,
            hostings_count,
            hostings_active,
            hostings_suspended,
            hostings_failed,
            total_disk_bytes,
            total_bw_out_24h,
            total_requests_24h,
            loadavg_1m_x100,
            mem_total_kib,
            mem_used_kib,
            uptime_secs,
        },
    ))
}

/// Last N node_metrics samples ordered oldest → newest (so charts read
/// left-to-right). Caller picks `limit`; typical: 48 for a "last 4h
/// @ 5min tick" sparkline, 288 for a 24h window.
pub async fn history(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<NodeMetricsRow>, StateError> {
    let limit = limit.clamp(1, 2000);
    let rows: Vec<(
        i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64,
    )> = sqlx::query_as(
        "SELECT id, sampled_at, hostings_count, hostings_active, hostings_suspended,
                hostings_failed, total_disk_bytes, total_bw_out_24h,
                total_requests_24h, loadavg_1m_x100, mem_total_kib, mem_used_kib,
                uptime_secs
         FROM node_metrics
         ORDER BY sampled_at DESC
         LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    // We selected DESC for the LIMIT, now flip so callers iterate
    // left-to-right (oldest first) — the natural reading order for a
    // line chart.
    let mut out: Vec<NodeMetricsRow> = rows
        .into_iter()
        .map(|t| NodeMetricsRow {
            id: t.0,
            sampled_at: t.1,
            hostings_count: t.2,
            hostings_active: t.3,
            hostings_suspended: t.4,
            hostings_failed: t.5,
            total_disk_bytes: t.6,
            total_bw_out_24h: t.7,
            total_requests_24h: t.8,
            loadavg_1m_x100: t.9,
            mem_total_kib: t.10,
            mem_used_kib: t.11,
            uptime_secs: t.12,
        })
        .collect();
    out.reverse();
    Ok(out)
}

/// Prune samples older than `cutoff_at`. Returns number of rows deleted.
pub async fn prune_older_than(pool: &SqlitePool, cutoff_at: i64) -> Result<u64, StateError> {
    let r = sqlx::query("DELETE FROM node_metrics WHERE sampled_at < ?")
        .bind(cutoff_at)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn insert_then_latest() {
        let pool = open_memory().await.expect("open");
        let m = NodeMetricsInput {
            sampled_at: 100,
            hostings_count: 5,
            loadavg_1m_x100: 35,
            mem_total_kib: 1_000_000,
            mem_used_kib: 250_000,
            ..Default::default()
        };
        insert(&pool, &m).await.expect("insert");
        let l = latest(&pool).await.expect("latest").expect("present");
        assert_eq!(l.hostings_count, 5);
        assert_eq!(l.loadavg_1m_x100, 35);
    }

    #[tokio::test]
    async fn latest_picks_most_recent() {
        let pool = open_memory().await.expect("open");
        insert(
            &pool,
            &NodeMetricsInput {
                sampled_at: 100,
                hostings_count: 1,
                ..Default::default()
            },
        )
        .await
        .expect("insert 1");
        insert(
            &pool,
            &NodeMetricsInput {
                sampled_at: 200,
                hostings_count: 2,
                ..Default::default()
            },
        )
        .await
        .expect("insert 2");
        let l = latest(&pool).await.expect("latest").expect("present");
        assert_eq!(l.hostings_count, 2);
    }

    #[tokio::test]
    async fn history_returns_ascending() {
        let pool = open_memory().await.expect("open");
        // Insert in reverse time order to confirm the function sorts.
        for ts in [300, 100, 200] {
            insert(&pool, &NodeMetricsInput {
                sampled_at: ts,
                hostings_count: ts,
                ..Default::default()
            })
            .await
            .expect("insert");
        }
        let h = history(&pool, 10).await.expect("history");
        // Should be oldest → newest: 100, 200, 300.
        let ts: Vec<i64> = h.iter().map(|r| r.sampled_at).collect();
        assert_eq!(ts, vec![100, 200, 300]);
    }

    #[tokio::test]
    async fn history_respects_limit() {
        let pool = open_memory().await.expect("open");
        for ts in 1..=20 {
            insert(&pool, &NodeMetricsInput {
                sampled_at: ts,
                ..Default::default()
            })
            .await
            .expect("insert");
        }
        // limit=5 → last 5 samples, oldest first within that window.
        let h = history(&pool, 5).await.expect("history");
        let ts: Vec<i64> = h.iter().map(|r| r.sampled_at).collect();
        assert_eq!(ts, vec![16, 17, 18, 19, 20]);
    }

    #[tokio::test]
    async fn prune_keeps_recent() {
        let pool = open_memory().await.expect("open");
        for ts in [50, 100, 200, 300] {
            insert(
                &pool,
                &NodeMetricsInput {
                    sampled_at: ts,
                    ..Default::default()
                },
            )
            .await
            .expect("insert");
        }
        let n = prune_older_than(&pool, 150).await.expect("prune");
        assert_eq!(n, 2); // dropped 50 + 100
    }
}
