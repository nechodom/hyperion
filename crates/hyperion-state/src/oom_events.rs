//! `oom_events` table — kernel OOM-kill records scraped from the journal.

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OomEventRow {
    pub id: i64,
    pub at: i64,
    pub comm: String,
    pub pid: i64,
    pub detail: String,
}

/// Append one OOM event.
pub async fn insert(
    pool: &SqlitePool,
    at: i64,
    comm: &str,
    pid: i64,
    detail: &str,
) -> Result<(), StateError> {
    sqlx::query("INSERT INTO oom_events (at, comm, pid, detail) VALUES (?, ?, ?, ?)")
        .bind(at)
        .bind(comm)
        .bind(pid)
        .bind(detail)
        .execute(pool)
        .await?;
    Ok(())
}

/// Unix-seconds of the most recent recorded event, or `None` if the table is
/// empty. Used as the journal-scan cursor (only fetch entries newer than this).
pub async fn latest_at(pool: &SqlitePool) -> Result<Option<i64>, StateError> {
    // MAX over an empty table returns one row holding NULL, so decode the
    // column as Option<i64> (None = empty table).
    let row: (Option<i64>,) = sqlx::query_as("SELECT MAX(at) FROM oom_events")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Count events at/after `since` (e.g. now-24h for the "OOM kills · 24h" badge).
pub async fn count_since(pool: &SqlitePool, since: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oom_events WHERE at >= ?")
        .bind(since)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Most recent `limit` events, newest first.
pub async fn recent(pool: &SqlitePool, limit: i64) -> Result<Vec<OomEventRow>, StateError> {
    let limit = limit.clamp(1, 500);
    let rows: Vec<OomEventRow> =
        sqlx::query_as("SELECT id, at, comm, pid, detail FROM oom_events ORDER BY at DESC LIMIT ?")
            .bind(limit)
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Prune events older than `cutoff_at`. Returns rows deleted.
pub async fn prune_older_than(pool: &SqlitePool, cutoff_at: i64) -> Result<u64, StateError> {
    let r = sqlx::query("DELETE FROM oom_events WHERE at < ?")
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
    async fn insert_count_latest_recent() {
        let pool = open_memory().await.expect("open");
        assert_eq!(latest_at(&pool).await.unwrap(), None);
        insert(&pool, 1000, "php-fpm8.3", 42, "Killed process 42")
            .await
            .unwrap();
        insert(&pool, 2000, "mysqld", 7, "Killed process 7")
            .await
            .unwrap();
        assert_eq!(latest_at(&pool).await.unwrap(), Some(2000));
        assert_eq!(count_since(&pool, 1500).await.unwrap(), 1);
        assert_eq!(count_since(&pool, 0).await.unwrap(), 2);
        let r = recent(&pool, 10).await.unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].at, 2000); // newest first
        assert_eq!(r[0].comm, "mysqld");
    }
}
