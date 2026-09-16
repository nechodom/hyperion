//! Node-level key/value store (`node_kv` table).
//!
//! `hosting_kv`'s counterpart for facts about this machine rather than about
//! one site on it. The value is opaque; the feature that owns a key owns its
//! encoding.

use crate::db::StateError;
use sqlx::SqlitePool;

/// Upsert one key.
pub async fn set(pool: &SqlitePool, key: &str, value: &str, now: i64) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO node_kv (key, value, updated_at) VALUES (?, ?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Read one key. `Ok(None)` means the key was never written — which is not the
/// same as a read that failed, and callers must not treat them alike.
pub async fn get(pool: &SqlitePool, key: &str) -> Result<Option<String>, StateError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM node_kv WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
}

/// Remove one key. Removing a key that is not there is not an error.
pub async fn delete(pool: &SqlitePool, key: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM node_kv WHERE key = ?")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_value_round_trips_and_absent_is_not_an_error() {
        let pool = crate::db::open_memory().await.expect("open");
        assert_eq!(get(&pool, "k").await.expect("read"), None);
        set(&pool, "k", "one", 1).await.expect("set");
        assert_eq!(get(&pool, "k").await.expect("read").as_deref(), Some("one"));
        set(&pool, "k", "two", 2).await.expect("upsert");
        assert_eq!(get(&pool, "k").await.expect("read").as_deref(), Some("two"));
        delete(&pool, "k").await.expect("delete");
        delete(&pool, "k").await.expect("deleting again is fine");
        assert_eq!(get(&pool, "k").await.expect("read"), None);
    }
}
