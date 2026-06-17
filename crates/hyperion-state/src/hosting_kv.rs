//! Generic per-hosting key/value store (`hosting_kv` table).
//!
//! Backs per-hosting feature config that doesn't deserve its own column
//! on the large `hostings` table: notes, tags, PHP overrides, WAF flags,
//! wp-admin allowlist, etc. The value is an opaque string — the feature
//! owns its encoding (plain text / CSV / JSON).

use crate::db::StateError;
use sqlx::SqlitePool;

/// Upsert one key for a hosting.
pub async fn set(
    pool: &SqlitePool,
    hosting_id: &str,
    key: &str,
    value: &str,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO hosting_kv (hosting_id, key, value, updated_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT(hosting_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(hosting_id)
    .bind(key)
    .bind(value)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Read one key. `None` when unset.
pub async fn get(
    pool: &SqlitePool,
    hosting_id: &str,
    key: &str,
) -> Result<Option<String>, StateError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM hosting_kv WHERE hosting_id = ? AND key = ?")
            .bind(hosting_id)
            .bind(key)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(v,)| v))
}

/// All (key, value) pairs for a hosting, ordered by key.
pub async fn list(
    pool: &SqlitePool,
    hosting_id: &str,
) -> Result<Vec<(String, String)>, StateError> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM hosting_kv WHERE hosting_id = ? ORDER BY key")
            .bind(hosting_id)
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Every (hosting_id, value) pair stored under one key across ALL
/// hostings. Used by cluster-wide views (e.g. the vuln dashboard reads
/// each hosting's stored scan result without N per-hosting lookups).
pub async fn list_by_key(
    pool: &SqlitePool,
    key: &str,
) -> Result<Vec<(String, String)>, StateError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT hosting_id, value FROM hosting_kv WHERE key = ? ORDER BY hosting_id",
    )
    .bind(key)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete one key (idempotent).
pub async fn delete(pool: &SqlitePool, hosting_id: &str, key: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_kv WHERE hosting_id = ? AND key = ?")
        .bind(hosting_id)
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

/// Drop every key for a hosting — call from the hard-delete path so a
/// reused hosting id doesn't inherit stale config.
pub async fn delete_all(pool: &SqlitePool, hosting_id: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_kv WHERE hosting_id = ?")
        .bind(hosting_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn set_get_list_delete_roundtrip() {
        let pool = open_memory().await.expect("open");
        set(&pool, "h1", "notes", "hello", 1).await.expect("set");
        set(&pool, "h1", "tags", "a,b", 1).await.expect("set");
        assert_eq!(
            get(&pool, "h1", "notes").await.unwrap().as_deref(),
            Some("hello")
        );
        // upsert overwrites
        set(&pool, "h1", "notes", "world", 2).await.expect("set2");
        assert_eq!(
            get(&pool, "h1", "notes").await.unwrap().as_deref(),
            Some("world")
        );
        let all = list(&pool, "h1").await.unwrap();
        assert_eq!(all.len(), 2);
        delete(&pool, "h1", "tags").await.expect("del");
        assert_eq!(list(&pool, "h1").await.unwrap().len(), 1);
        delete_all(&pool, "h1").await.expect("del_all");
        assert!(list(&pool, "h1").await.unwrap().is_empty());
        assert!(get(&pool, "h1", "nope").await.unwrap().is_none());
    }
}
