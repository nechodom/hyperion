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
}

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
    let rows: Vec<(
        i64,
        String,
        String,
        i64,
        Option<i64>,
        String,
        Option<String>,
        Option<String>,
        i64,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, hosting_id, target, started_at, finished_at, state,
                archive_path, db_dump_path, bytes_total, error_message
         FROM backup_runs WHERE hosting_id = ?
         ORDER BY started_at DESC LIMIT ?",
    )
    .bind(hosting_id.as_str())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                hosting_id,
                target,
                started_at,
                finished_at,
                state,
                archive_path,
                db_dump_path,
                bytes_total,
                error_message,
            )| BackupRun {
                id,
                hosting_id: HostingId(hosting_id),
                target,
                started_at,
                finished_at,
                state,
                archive_path,
                db_dump_path,
                bytes_total,
                error_message,
            },
        )
        .collect())
}

/// Delete a backup_run row by id.
/// Single backup run by id. Used by `backup_delete` to find the
/// archive path on disk before deleting it.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<Option<BackupRun>, StateError> {
    let row: Option<(
        i64,
        String,
        String,
        i64,
        Option<i64>,
        String,
        Option<String>,
        Option<String>,
        i64,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, hosting_id, target, started_at, finished_at, state, archive_path,
                db_dump_path, bytes_total, error_message
         FROM backup_runs WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            id,
            hosting_id,
            target,
            started_at,
            finished_at,
            state,
            archive_path,
            db_dump_path,
            bytes_total,
            error_message,
        )| BackupRun {
            id,
            hosting_id: HostingId(hosting_id),
            target,
            started_at,
            finished_at,
            state,
            archive_path,
            db_dump_path,
            bytes_total,
            error_message,
        },
    ))
}

pub async fn delete_by_id(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM backup_runs WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_all(pool: &SqlitePool, limit: i64) -> Result<Vec<BackupRun>, StateError> {
    let rows: Vec<(
        i64,
        String,
        String,
        i64,
        Option<i64>,
        String,
        Option<String>,
        Option<String>,
        i64,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, hosting_id, target, started_at, finished_at, state,
                archive_path, db_dump_path, bytes_total, error_message
         FROM backup_runs ORDER BY started_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                hosting_id,
                target,
                started_at,
                finished_at,
                state,
                archive_path,
                db_dump_path,
                bytes_total,
                error_message,
            )| BackupRun {
                id,
                hosting_id: HostingId(hosting_id),
                target,
                started_at,
                finished_at,
                state,
                archive_path,
                db_dump_path,
                bytes_total,
                error_message,
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
