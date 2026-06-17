//! `system_users` table — one row per Linux user managed by hyperion-agent.

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemUserRow {
    pub id: i64,
    pub name: String,
    pub uid: i64,
    pub home_dir: String,
    pub shell: String,
    pub created_at: i64,
}

pub async fn insert(
    pool: &SqlitePool,
    name: &str,
    uid: i64,
    home_dir: &str,
    shell: &str,
    now: i64,
) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO system_users (name, uid, home_dir, shell, created_at)
           VALUES (?, ?, ?, ?, ?) RETURNING id"#,
    )
    .bind(name)
    .bind(uid)
    .bind(home_dir)
    .bind(shell)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_by_name(
    pool: &SqlitePool,
    name: &str,
) -> Result<Option<SystemUserRow>, StateError> {
    let row = sqlx::query_as::<_, (i64, String, i64, String, String, i64)>(
        "SELECT id, name, uid, home_dir, shell, created_at FROM system_users WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(id, name, uid, home_dir, shell, created_at)| SystemUserRow {
            id,
            name,
            uid,
            home_dir,
            shell,
            created_at,
        },
    ))
}

/// Look up a system_users row by UID. Used to detect stale rows left
/// from earlier failed deletes (UID gets re-assigned by Linux but the
/// orphan row in our DB collides on the UNIQUE(uid) constraint).
pub async fn get_by_uid(pool: &SqlitePool, uid: i64) -> Result<Option<SystemUserRow>, StateError> {
    let row = sqlx::query_as::<_, (i64, String, i64, String, String, i64)>(
        "SELECT id, name, uid, home_dir, shell, created_at FROM system_users WHERE uid = ?",
    )
    .bind(uid)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(id, name, uid, home_dir, shell, created_at)| SystemUserRow {
            id,
            name,
            uid,
            home_dir,
            shell,
            created_at,
        },
    ))
}

/// True iff at least one hosting still references this `system_users` row.
pub async fn has_hostings(pool: &SqlitePool, id: i64) -> Result<bool, StateError> {
    let row: (i64,) = sqlx::query_as("SELECT count(*) FROM hostings WHERE system_user_id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(row.0 > 0)
}

pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM system_users WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn insert_and_get_by_name_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = insert(
            &pool,
            "alice",
            1042,
            "/home/alice",
            "/usr/sbin/nologin",
            100,
        )
        .await
        .expect("insert");
        let got = get_by_name(&pool, "alice")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.id, id);
        assert_eq!(got.uid, 1042);
        assert_eq!(got.home_dir, "/home/alice");
    }

    #[tokio::test]
    async fn name_uniqueness() {
        let pool = open_memory().await.expect("open");
        insert(&pool, "alice", 1042, "/home/alice", "/x", 1)
            .await
            .expect("first ok");
        let err = insert(&pool, "alice", 1043, "/home/alice", "/x", 2).await;
        assert!(err.is_err(), "duplicate name must fail");
    }

    #[tokio::test]
    async fn uid_uniqueness() {
        let pool = open_memory().await.expect("open");
        insert(&pool, "alice", 1042, "/home/alice", "/x", 1)
            .await
            .expect("first ok");
        let err = insert(&pool, "bob", 1042, "/home/bob", "/x", 2).await;
        assert!(err.is_err(), "duplicate uid must fail");
    }

    #[tokio::test]
    async fn delete_removes_row() {
        let pool = open_memory().await.expect("open");
        let id = insert(&pool, "alice", 1042, "/home/alice", "/x", 1)
            .await
            .expect("insert");
        delete(&pool, id).await.expect("delete");
        let got = get_by_name(&pool, "alice").await.expect("get");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn get_by_uid_finds_orphan() {
        let pool = open_memory().await.expect("open");
        insert(&pool, "ghost", 1042, "/home/ghost", "/x", 1)
            .await
            .expect("insert");
        let r = get_by_uid(&pool, 1042).await.expect("get");
        assert_eq!(r.expect("present").name, "ghost");
        assert!(get_by_uid(&pool, 1099).await.expect("get").is_none());
    }
}
