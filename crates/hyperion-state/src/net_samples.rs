//! High-resolution node ring (`net_samples`): network throughput, plus CPU,
//! load and memory since migration 090.
//!
//! Fed by a dedicated lightweight sampler every few seconds (a /proc/net/dev
//! delta, no `du`), kept to a short rolling window, so the stats page can draw
//! genuinely realtime sparklines without touching the heavy 5-minute stats
//! sampler. Node-local: each agent writes and reads its own rows.

use crate::db::StateError;
use sqlx::SqlitePool;

/// One sample at `at` (unix secs): throughput in bytes/sec and the node's
/// gauges. `mem_total_kib` is 0 on rows written before the gauges existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetSample {
    pub at: i64,
    pub rx_bps: i64,
    pub tx_bps: i64,
    pub cpu_pct_x100: i64,
    pub loadavg_1m_x100: i64,
    pub mem_used_kib: i64,
    pub mem_total_kib: i64,
}

/// Record one sample.
pub async fn insert(pool: &SqlitePool, s: &NetSample) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO net_samples (at, rx_bps, tx_bps, cpu_pct_x100, loadavg_1m_x100, \
         mem_used_kib, mem_total_kib) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(s.at)
    .bind(s.rx_bps)
    .bind(s.tx_bps)
    .bind(s.cpu_pct_x100)
    .bind(s.loadavg_1m_x100)
    .bind(s.mem_used_kib)
    .bind(s.mem_total_kib)
    .execute(pool)
    .await?;
    Ok(())
}

/// The most recent `limit` samples, returned OLDEST → NEWEST so a caller can
/// feed them straight into a left-to-right sparkline.
pub async fn recent(pool: &SqlitePool, limit: i64) -> Result<Vec<NetSample>, StateError> {
    let limit = limit.clamp(1, 5000);
    // Newest-first with LIMIT, then reversed to oldest-first.
    let mut rows: Vec<(i64, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT at, rx_bps, tx_bps, cpu_pct_x100, loadavg_1m_x100, mem_used_kib, mem_total_kib \
         FROM net_samples ORDER BY at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.reverse();
    Ok(rows
        .into_iter()
        .map(
            |(at, rx_bps, tx_bps, cpu_pct_x100, loadavg_1m_x100, mem_used_kib, mem_total_kib)| {
                NetSample {
                    at,
                    rx_bps,
                    tx_bps,
                    cpu_pct_x100,
                    loadavg_1m_x100,
                    mem_used_kib,
                    mem_total_kib,
                }
            },
        )
        .collect())
}

/// Drop samples older than `cutoff_at`. Returns rows deleted.
pub async fn prune_older_than(pool: &SqlitePool, cutoff_at: i64) -> Result<u64, StateError> {
    let r = sqlx::query("DELETE FROM net_samples WHERE at < ?")
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
    async fn insert_recent_oldest_first_and_prune() {
        let pool = open_memory().await.expect("open");
        for (at, rx, tx) in [(100, 10, 1), (200, 20, 2), (300, 30, 3)] {
            let s = NetSample {
                at,
                rx_bps: rx,
                tx_bps: tx,
                ..Default::default()
            };
            insert(&pool, &s).await.expect("insert");
        }
        let s = recent(&pool, 10).await.expect("recent");
        // Oldest → newest.
        assert_eq!(
            s.iter().map(|x| x.at).collect::<Vec<_>>(),
            vec![100, 200, 300]
        );
        assert_eq!(s.last().unwrap().rx_bps, 30);

        // LIMIT keeps the NEWEST, still oldest-first.
        let s = recent(&pool, 2).await.expect("recent2");
        assert_eq!(s.iter().map(|x| x.at).collect::<Vec<_>>(), vec![200, 300]);

        let n = prune_older_than(&pool, 250).await.expect("prune");
        assert_eq!(n, 2, "100 and 200 dropped");
        let s = recent(&pool, 10).await.expect("recent3");
        assert_eq!(s.iter().map(|x| x.at).collect::<Vec<_>>(), vec![300]);
    }

    #[tokio::test]
    async fn gauges_round_trip_in_their_own_columns() {
        let pool = open_memory().await.expect("open");
        let sample = NetSample {
            at: 100,
            rx_bps: 1,
            tx_bps: 2,
            cpu_pct_x100: 3,
            loadavg_1m_x100: 4,
            mem_used_kib: 5,
            mem_total_kib: 6,
        };
        insert(&pool, &sample).await.expect("insert");
        assert_eq!(recent(&pool, 1).await.expect("recent"), vec![sample]);
    }
}
