//! `backup_runs` table.

use crate::db::StateError;
use hyperion_types::HostingId;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRun {
    pub id: i64,
    pub hosting_id: HostingId,
    pub target: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub state: String,
    pub archive_path: Option<String>,
    pub db_dump_path: Option<String>,
    pub bytes_total: i64,
    pub error_message: Option<String>,
    /// SHA-256 of the archive, hex.
    ///
    /// Migration 031 created this column and nothing ever wrote it, so until
    /// now the entire integrity assurance for a backup was that the file was
    /// not zero bytes. Empty means a run from before it was recorded — NOT a
    /// run that failed its check, and the panel has to keep those apart.
    pub sha256_hex: String,
    /// Where the off-site copy went, as a human-readable location — an
    /// `ftp://host/dir/file` or an `s3://bucket/key`. Empty = no off-site copy
    /// is known to exist.
    pub remote_blob_key: String,
    /// What we know about that copy: empty (never pushed), `pending`,
    /// `ok`, `failed`, or `verified` — the last meaning the bytes were read
    /// back and their size matched. `ok` and `verified` are deliberately
    /// different words: one is "the upload returned success", the other is
    /// "we looked".
    pub remote_state: String,
    /// Why the off-site copy is not there, when it is not. Empty on success.
    pub remote_error: String,
}

/// The row as SQLite hands it back, mapped BY NAME.
///
/// Hand-written tuple destructuring is what this replaced, and it is the exact
/// shape of the bug this codebase has hit before: adding a column meant
/// editing a tuple type and a destructuring pattern in three places, and
/// getting one of them out of order does not fail — it silently puts the
/// archive path in the dump column.
#[derive(sqlx::FromRow)]
struct BackupRunRow {
    id: i64,
    hosting_id: String,
    target: String,
    started_at: i64,
    finished_at: Option<i64>,
    state: String,
    #[sqlx(default)]
    sha256_hex: Option<String>,
    #[sqlx(default)]
    remote_blob_key: Option<String>,
    #[sqlx(default)]
    remote_state: Option<String>,
    #[sqlx(default)]
    remote_error: Option<String>,
    archive_path: Option<String>,
    db_dump_path: Option<String>,
    bytes_total: i64,
    error_message: Option<String>,
}

impl From<BackupRunRow> for BackupRun {
    fn from(r: BackupRunRow) -> Self {
        BackupRun {
            id: r.id,
            hosting_id: HostingId(r.hosting_id),
            target: r.target,
            started_at: r.started_at,
            finished_at: r.finished_at,
            state: r.state,
            sha256_hex: r.sha256_hex.unwrap_or_default(),
            remote_blob_key: r.remote_blob_key.unwrap_or_default(),
            remote_state: r.remote_state.unwrap_or_default(),
            remote_error: r.remote_error.unwrap_or_default(),
            archive_path: r.archive_path,
            db_dump_path: r.db_dump_path,
            bytes_total: r.bytes_total,
            error_message: r.error_message,
        }
    }
}

const SELECT_COLS: &str = "id, hosting_id, target, started_at, finished_at, state, \
     sha256_hex, remote_blob_key, remote_state, remote_error, archive_path, \
     db_dump_path, bytes_total, error_message";

pub async fn start(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    target: &str,
    now: i64,
) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO backup_runs (hosting_id, target, started_at, state)
           VALUES (?, ?, ?, 'running') RETURNING id"#,
    )
    .bind(hosting_id.as_str())
    .bind(target)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn mark_ok(
    pool: &SqlitePool,
    id: i64,
    archive_path: &str,
    db_dump_path: Option<&str>,
    bytes_total: i64,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"UPDATE backup_runs
           SET state='ok', finished_at=?, archive_path=?, db_dump_path=?,
               bytes_total=?, error_message=NULL
           WHERE id = ?"#,
    )
    .bind(now)
    .bind(archive_path)
    .bind(db_dump_path)
    .bind(bytes_total)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_failed(
    pool: &SqlitePool,
    id: i64,
    error: &str,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"UPDATE backup_runs
           SET state='failed', finished_at=?, error_message=?
           WHERE id = ?"#,
    )
    .bind(now)
    .bind(error)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_for(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    limit: i64,
) -> Result<Vec<BackupRun>, StateError> {
    let rows = sqlx::query_as::<_, BackupRunRow>(&format!(
        "SELECT {SELECT_COLS} FROM backup_runs WHERE hosting_id = ? \
         ORDER BY started_at DESC LIMIT ?"
    ))
    .bind(hosting_id.as_str())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<Option<BackupRun>, StateError> {
    let row = sqlx::query_as::<_, BackupRunRow>(&format!(
        "SELECT {SELECT_COLS} FROM backup_runs WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Record the archive's digest, computed once when it is written.
///
/// Separate from `mark_ok` because hashing a multi-gigabyte archive is not
/// free and the caller decides when to pay for it — but a run without a digest
/// is a run nothing can ever verify, so the caller that skips it is choosing
/// that.
pub async fn set_sha256(pool: &SqlitePool, id: i64, hex: &str) -> Result<(), StateError> {
    sqlx::query("UPDATE backup_runs SET sha256_hex = ? WHERE id = ?")
        .bind(hex)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record what happened to the off-site copy.
///
/// The columns this writes have existed since migration 031 and were dead, so
/// nothing in the panel could answer "is this backup anywhere but here?" — and
/// a backfill had nothing to diff against.
pub async fn set_remote(
    pool: &SqlitePool,
    id: i64,
    blob_key: &str,
    state: &str,
    error: &str,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE backup_runs SET remote_blob_key = ?, remote_state = ?, remote_error = ? \
         WHERE id = ?",
    )
    .bind(blob_key)
    .bind(state)
    .bind(error)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Successful local backups with no off-site copy, oldest first.
///
/// What a backfill works from. `state='ok'` because pushing the archive of a
/// failed run would copy a file that may be truncated; oldest first because
/// the oldest is the one closest to being pruned off local disk.
pub async fn list_needing_offsite(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<BackupRun>, StateError> {
    let rows = sqlx::query_as::<_, BackupRunRow>(&format!(
        "SELECT {SELECT_COLS} FROM backup_runs \
          WHERE state = 'ok' \
            AND archive_path IS NOT NULL \
            AND (remote_state IS NULL OR remote_state NOT IN ('ok', 'verified')) \
          ORDER BY started_at ASC \
          LIMIT ?"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn delete_by_id(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM backup_runs WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_all(pool: &SqlitePool, limit: i64) -> Result<Vec<BackupRun>, StateError> {
    let rows = sqlx::query_as::<_, BackupRunRow>(&format!(
        "SELECT {SELECT_COLS} FROM backup_runs ORDER BY started_at DESC LIMIT ?"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
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

    /// `get_by_id` is intentionally hosting-agnostic — every caller must bind
    /// the row to the hosting it authorized. This test pins the fact rather
    /// than the intent, because the callers that forgot it let a tenant with
    /// one site download, delete and restore every other site's backups: ids
    /// are a dense node-wide sequence, and "the path is under a backup root"
    /// is true of every tenant's archives at once.
    ///
    /// If this ever starts filtering, the callers can be simplified — until
    /// then, treat an id alone as unauthenticated input.
    #[tokio::test]
    async fn get_by_id_does_not_filter_by_hosting() {
        let pool = open_memory().await.expect("open");
        let a = fixture(&pool).await;

        let suid_b = system_users::insert(&pool, "v", 1043, "/home/v", "/y", 1)
            .await
            .expect("user b");
        let b = HostingId::new_v7();
        hostings::insert(&pool, &b, "other.cz", suid_b, None, "/r2", 1, None)
            .await
            .expect("hosting b");

        let run_b = start(&pool, &b, "local", 100).await.expect("start b");
        mark_ok(&pool, run_b, "/var/backups/other.tar.gz", None, 10, 200)
            .await
            .expect("ok");

        // Fetched with no hosting context at all — this is exactly what a
        // caller holding only an id gets.
        let row = get_by_id(&pool, run_b).await.expect("get").expect("row");
        assert_eq!(
            row.hosting_id, b,
            "the row belongs to hosting b, and nothing in this call said so"
        );
        assert_ne!(
            row.hosting_id, a,
            "a caller authorized for hosting a would be handed b's archive path \
             unless it checks hosting_id itself"
        );
    }

    #[tokio::test]
    async fn start_mark_ok_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let run = start(&pool, &id, "local", 100).await.expect("start");
        mark_ok(
            &pool,
            run,
            "/var/backups/ex.tar.gz",
            Some("/var/backups/ex.sql"),
            1024,
            200,
        )
        .await
        .expect("ok");
        let rows = list_for(&pool, &id, 10).await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "ok");
        assert_eq!(rows[0].bytes_total, 1024);
        assert_eq!(
            rows[0].archive_path.as_deref(),
            Some("/var/backups/ex.tar.gz")
        );
    }

    #[tokio::test]
    async fn mark_failed_path() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let run = start(&pool, &id, "local", 100).await.expect("start");
        mark_failed(&pool, run, "boom", 200).await.expect("fail");
        let rows = list_for(&pool, &id, 10).await.expect("list");
        assert_eq!(rows[0].state, "failed");
        assert_eq!(rows[0].error_message.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn cascade_with_hosting_delete() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let _ = start(&pool, &id, "local", 100).await.expect("start");
        hostings::delete(&pool, &id).await.expect("delete");
        let rows = list_for(&pool, &id, 10).await.expect("list");
        assert!(rows.is_empty());
    }
}
