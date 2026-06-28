//! Self-service import tokens: one-time, scoped, expiring bearer tokens that let
//! a source panel box (no Hyperion login) fetch the bootstrap script and push an
//! export bundle to a target node. Only the token **hash** is stored; the
//! plaintext is shown once in the wizard. See the design spec
//! (docs/superpowers/specs/2026-06-28-self-service-import-wizard-design.md).

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ImportTokenRow {
    pub id: i64,
    pub token_hash: String,
    pub target_node: String,
    pub source_kind: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub status: String,
    pub received_bytes: i64,
    pub job_id: Option<String>,
}

const COLS: &str = "id, token_hash, target_node, source_kind, created_by, created_at, \
                    expires_at, used_at, status, received_bytes, job_id";

/// Mint a token row. `token_hash` is the blake3 hex of the plaintext (minted by
/// the caller). Returns the new row id.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &SqlitePool,
    token_hash: &str,
    target_node: &str,
    source_kind: &str,
    created_by: &str,
    created_at: i64,
    expires_at: i64,
) -> Result<i64, StateError> {
    let id = sqlx::query(
        "INSERT INTO import_tokens \
         (token_hash, target_node, source_kind, created_by, created_at, expires_at, status) \
         VALUES (?, ?, ?, ?, ?, ?, 'pending')",
    )
    .bind(token_hash)
    .bind(target_node)
    .bind(source_kind)
    .bind(created_by)
    .bind(created_at)
    .bind(expires_at)
    .execute(pool)
    .await?
    .last_insert_rowid();
    Ok(id)
}

/// Look up a token by hash if it is still usable for the bootstrap fetch:
/// pending/receiving status AND not expired. Does NOT consume it (the `agent`
/// script GET can be retried; only `ingest` consumes).
pub async fn get_fetchable(
    pool: &SqlitePool,
    token_hash: &str,
    now: i64,
) -> Result<Option<ImportTokenRow>, StateError> {
    let row = sqlx::query_as::<_, ImportTokenRow>(&format!(
        "SELECT {COLS} FROM import_tokens \
         WHERE token_hash = ? AND expires_at > ? \
           AND status IN ('pending', 'receiving')",
    ))
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Atomically consume a token for ingest: flips an unused, unexpired, pending
/// token to `receiving` and stamps `used_at`. Returns the row on success, `None`
/// if it was already used / expired / cancelled (single-use guarantee — the
/// UPDATE's WHERE is the lock).
pub async fn consume_for_ingest(
    pool: &SqlitePool,
    token_hash: &str,
    now: i64,
) -> Result<Option<ImportTokenRow>, StateError> {
    let affected = sqlx::query(
        "UPDATE import_tokens SET status = 'receiving', used_at = ? \
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? AND status = 'pending'",
    )
    .bind(now)
    .bind(token_hash)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, ImportTokenRow>(&format!(
        "SELECT {COLS} FROM import_tokens WHERE token_hash = ?",
    ))
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Update progress / lifecycle. `status` ∈ receiving|importing|done|failed.
pub async fn set_status(pool: &SqlitePool, id: i64, status: &str) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET status = ? WHERE id = ?")
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record the spawned import job id against the token (so the wizard can link to
/// `/jobs/<id>`).
pub async fn set_job(pool: &SqlitePool, id: i64, job_id: &str) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET job_id = ?, status = 'importing' WHERE id = ?")
        .bind(job_id)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Bump the running byte counter as the bundle streams in (for the progress UI).
pub async fn set_received_bytes(pool: &SqlitePool, id: i64, bytes: i64) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET received_bytes = ? WHERE id = ?")
        .bind(bytes)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Revoke a token (wizard "cancel"). Idempotent.
pub async fn cancel(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET status = 'cancelled' WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Active tokens (pending/receiving/importing, unexpired) — for the wizard's
/// "in-flight transfers" list.
pub async fn list_active(
    pool: &SqlitePool,
    now: i64,
) -> Result<Vec<ImportTokenRow>, StateError> {
    let rows = sqlx::query_as::<_, ImportTokenRow>(&format!(
        "SELECT {COLS} FROM import_tokens \
         WHERE status IN ('pending', 'receiving', 'importing') AND expires_at > ? \
         ORDER BY created_at DESC",
    ))
    .bind(now)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Best-effort GC of expired/finished rows older than `cutoff`.
pub async fn cleanup(pool: &SqlitePool, cutoff: i64) -> Result<u64, StateError> {
    let n = sqlx::query(
        "DELETE FROM import_tokens \
         WHERE expires_at < ? OR status IN ('done', 'failed', 'cancelled')",
    )
    .bind(cutoff)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem() -> SqlitePool {
        let pool = crate::open(std::path::Path::new(":memory:")).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let pool = mem().await;
        create(&pool, "h1", "local", "cloudpanel", "admin", 100, 1_000)
            .await
            .unwrap();
        // first consume wins
        let r = consume_for_ingest(&pool, "h1", 200).await.unwrap();
        assert!(r.is_some());
        // second consume is refused (already used)
        let r2 = consume_for_ingest(&pool, "h1", 200).await.unwrap();
        assert!(r2.is_none());
    }

    #[tokio::test]
    async fn expired_token_not_fetchable_or_consumable() {
        let pool = mem().await;
        create(&pool, "h2", "local", "cloudpanel", "admin", 100, 1_000)
            .await
            .unwrap();
        // now (2000) is past expires_at (1000)
        assert!(get_fetchable(&pool, "h2", 2_000).await.unwrap().is_none());
        assert!(consume_for_ingest(&pool, "h2", 2_000)
            .await
            .unwrap()
            .is_none());
    }
}
