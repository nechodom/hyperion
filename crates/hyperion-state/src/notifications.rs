//! In-app notification feed for the bell-icon widget in the
//! header. Per-user persistence — the same event (e.g. a cert
//! renewal failure) is fanned out to every user who should see
//! it (super_admin/admin universally, operators per-hosting access).
//!
//! Storage layer only — fan-out routing + role-aware filtering
//! live in `hyperion-core::service::notify_*` so this crate stays
//! free of role logic.

use crate::db::StateError;
use sqlx::SqlitePool;

/// One row from the `notifications` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationRow {
    pub id: i64,
    pub user_id: i64,
    pub severity: String,
    pub title: String,
    pub body: String,
    pub href: String,
    pub kind: String,
    pub created_at: i64,
    pub read_at: Option<i64>,
}

/// Insert one notification for one user. Returns the new row id.
/// Caller is expected to fan-out by calling this for each recipient.
#[allow(clippy::too_many_arguments)]
pub async fn insert(
    pool: &SqlitePool,
    user_id: i64,
    severity: &str,
    title: &str,
    body: &str,
    href: &str,
    kind: &str,
    now: i64,
) -> Result<i64, StateError> {
    let r = sqlx::query(
        "INSERT INTO notifications \
         (user_id, severity, title, body, href, kind, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(severity)
    .bind(title)
    .bind(body)
    .bind(href)
    .bind(kind)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(r.last_insert_rowid())
}

/// Most-recent N notifications for one user (read + unread). Used
/// by the bell dropdown which shows ~10 at a time with a "view all"
/// link to the full notifications page.
pub async fn list_recent(
    pool: &SqlitePool,
    user_id: i64,
    limit: i64,
) -> Result<Vec<NotificationRow>, StateError> {
    let limit = limit.clamp(1, 100);
    let rows: Vec<(i64, i64, String, String, String, String, String, i64, Option<i64>)> =
        sqlx::query_as(
            "SELECT id, user_id, severity, title, body, href, kind, created_at, read_at \
             FROM notifications WHERE user_id = ? \
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, user_id, severity, title, body, href, kind, created_at, read_at)| {
                NotificationRow {
                    id,
                    user_id,
                    severity,
                    title,
                    body,
                    href,
                    kind,
                    created_at,
                    read_at,
                }
            },
        )
        .collect())
}

/// Count of unread notifications for one user. Drives the red
/// badge on the bell icon.
pub async fn unread_count(pool: &SqlitePool, user_id: i64) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Mark one notification as read for a given user. The user_id is
/// checked at the query level so a malicious user can't mark
/// someone else's notification.
pub async fn mark_read(
    pool: &SqlitePool,
    user_id: i64,
    notification_id: i64,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE notifications SET read_at = ? \
         WHERE id = ? AND user_id = ? AND read_at IS NULL",
    )
    .bind(now)
    .bind(notification_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark every unread notification for this user as read. Used by
/// the "mark all read" button in the dropdown.
pub async fn mark_all_read(
    pool: &SqlitePool,
    user_id: i64,
    now: i64,
) -> Result<i64, StateError> {
    let r = sqlx::query(
        "UPDATE notifications SET read_at = ? \
         WHERE user_id = ? AND read_at IS NULL",
    )
    .bind(now)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() as i64)
}

/// Garbage-collect notifications older than `older_than_secs` ago.
/// Called from the scheduler tick so the table doesn't grow
/// unbounded on long-running boxes.
pub async fn gc_older_than(
    pool: &SqlitePool,
    older_than_secs: i64,
    now: i64,
) -> Result<i64, StateError> {
    let cutoff = now - older_than_secs;
    let r = sqlx::query("DELETE FROM notifications WHERE created_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    async fn fresh() -> SqlitePool {
        let pool = open_memory().await.expect("memory db");
        // Seed one web_users row to satisfy the notifications FK.
        sqlx::query(
            "INSERT INTO web_users (id, username, email, role, password_hash, \
             created_at, updated_at) \
             VALUES (1, 'kevin', 'k@x.cz', 'super_admin', '$argon2id$x', 0, 0)",
        )
        .execute(&pool)
        .await
        .expect("seed user");
        pool
    }

    #[tokio::test]
    async fn insert_then_list_returns_in_reverse_chrono_order() {
        let pool = fresh().await;
        insert(&pool, 1, "info", "first", "", "/", "test", 1).await.unwrap();
        insert(&pool, 1, "info", "second", "", "/", "test", 2).await.unwrap();
        insert(&pool, 1, "info", "third", "", "/", "test", 3).await.unwrap();
        let rows = list_recent(&pool, 1, 10).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].title, "third");
        assert_eq!(rows[1].title, "second");
        assert_eq!(rows[2].title, "first");
    }

    #[tokio::test]
    async fn unread_count_decrements_when_marked_read() {
        let pool = fresh().await;
        let a = insert(&pool, 1, "info", "a", "", "/", "test", 1).await.unwrap();
        insert(&pool, 1, "info", "b", "", "/", "test", 2).await.unwrap();
        insert(&pool, 1, "info", "c", "", "/", "test", 3).await.unwrap();
        assert_eq!(unread_count(&pool, 1).await.unwrap(), 3);
        mark_read(&pool, 1, a, 10).await.unwrap();
        assert_eq!(unread_count(&pool, 1).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn mark_read_refuses_other_users_rows() {
        let pool = fresh().await;
        sqlx::query(
            "INSERT INTO web_users (id, username, email, role, password_hash, \
             created_at, updated_at) \
             VALUES (2, 'mallory', 'm@x.cz', 'operator', '$argon2id$x', 0, 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let n = insert(&pool, 1, "info", "secret", "", "/", "test", 1).await.unwrap();
        // mallory (user 2) tries to mark kevin's (user 1) notification
        mark_read(&pool, 2, n, 10).await.unwrap();
        // still unread for kevin
        let rows = list_recent(&pool, 1, 10).await.unwrap();
        assert!(rows[0].read_at.is_none());
    }

    #[tokio::test]
    async fn mark_all_read_returns_count() {
        let pool = fresh().await;
        for i in 0..5 {
            insert(&pool, 1, "info", &format!("n{i}"), "", "/", "test", i)
                .await
                .unwrap();
        }
        // Mark one already read so mark_all_read should affect 4.
        let first = list_recent(&pool, 1, 10).await.unwrap().last().unwrap().id;
        mark_read(&pool, 1, first, 10).await.unwrap();
        assert_eq!(mark_all_read(&pool, 1, 20).await.unwrap(), 4);
        assert_eq!(unread_count(&pool, 1).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn gc_drops_older_rows() {
        let pool = fresh().await;
        insert(&pool, 1, "info", "ancient", "", "/", "test", 100).await.unwrap();
        insert(&pool, 1, "info", "recent", "", "/", "test", 1000).await.unwrap();
        // now=2000, ttl=500 → cutoff=1500 → "ancient" (100) deleted, "recent" (1000) deleted too
        // Use ttl 1500 → cutoff = 500 → only "ancient" deleted
        let n = gc_older_than(&pool, 1500, 2000).await.unwrap();
        assert_eq!(n, 1);
        let rows = list_recent(&pool, 1, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "recent");
    }
}
