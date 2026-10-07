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
    /// Node that raised it; empty = this box (the master).
    pub node_id: String,
}

type RowTuple = (
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
    i64,
    Option<i64>,
    String,
);

const COLS: &str = "id, user_id, severity, title, body, href, kind, created_at, read_at, node_id";

fn from_tuple(t: RowTuple) -> NotificationRow {
    let (id, user_id, severity, title, body, href, kind, created_at, read_at, node_id) = t;
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
        node_id,
    }
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

/// Insert one notification a worker raised, collected from its outbox.
/// `(user_id, node_id, origin_id)` is unique, so collecting the same outbox
/// row twice is a no-op. Returns whether a row was written.
pub async fn insert_from_node(
    pool: &SqlitePool,
    user_id: i64,
    node_id: &str,
    item: &OutboxRow,
) -> Result<bool, StateError> {
    let r = sqlx::query(
        "INSERT OR IGNORE INTO notifications \
         (user_id, severity, title, body, href, kind, created_at, node_id, origin_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&item.severity)
    .bind(&item.title)
    .bind(&item.body)
    .bind(&item.href)
    .bind(&item.kind)
    .bind(item.created_at)
    .bind(node_id)
    .bind(item.id)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Highest outbox id already collected from `node_id`, for any user. The
/// collector resumes after it, so a panel restart neither re-reads the
/// whole outbox nor skips anything.
pub async fn node_cursor(pool: &SqlitePool, node_id: &str) -> Result<i64, StateError> {
    let row: (Option<i64>,) = sqlx::query_as(
        "SELECT MAX(origin_id) FROM notifications WHERE node_id = ? AND origin_id IS NOT NULL",
    )
    .bind(node_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0.unwrap_or(0))
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
    let sql = format!(
        "SELECT {COLS} FROM notifications WHERE user_id = ? \
         ORDER BY created_at DESC, id DESC LIMIT ?"
    );
    let rows: Vec<RowTuple> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(from_tuple).collect())
}

/// One notification by id, scoped to its owner. `None` for someone else's.
pub async fn get(
    pool: &SqlitePool,
    user_id: i64,
    id: i64,
) -> Result<Option<NotificationRow>, StateError> {
    let sql = format!("SELECT {COLS} FROM notifications WHERE id = ? AND user_id = ?");
    let row: Option<RowTuple> = sqlx::query_as(&sql)
        .bind(id)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(from_tuple))
}

/// What the archive page asks for. Empty strings mean "any".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchFilter {
    /// Substring of the title, body or kind.
    pub q: String,
    /// `error` | `warn` | `info` (= anything else). Not part of the counts'
    /// scope, so the segments always show what each severity would give.
    pub severity: String,
    /// Only rows not read yet. Also outside the counts' scope.
    pub unread_only: bool,
    /// Only these exact kinds; `None` = any. An empty list matches nothing
    /// (a topic with no rows yet).
    pub kinds: Option<Vec<String>>,
    /// Keyset cursor: rows strictly older than `(created_at, id)`.
    pub before: Option<(i64, i64)>,
}

/// Totals for the segments, over the search box + kinds only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchCounts {
    pub all: i64,
    pub unread: i64,
    pub error: i64,
    pub warn: i64,
    pub info: i64,
    /// Unread rows that are `error` — the verdict's headline number.
    pub unread_error: i64,
}

fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

enum Arg {
    Int(i64),
    Text(String),
}

/// `WHERE …` for `f`. `scope_only` leaves out severity, unread and the
/// cursor — the part the counts are taken over.
fn where_clause(user_id: i64, f: &SearchFilter, scope_only: bool) -> (String, Vec<Arg>) {
    let mut wh = vec!["user_id = ?".to_string()];
    let mut args = vec![Arg::Int(user_id)];
    let q = f.q.trim();
    if !q.is_empty() {
        let pat = format!("%{}%", like_escape(q));
        wh.push(
            "(title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\' OR kind LIKE ? ESCAPE '\\' \
             OR node_id LIKE ? ESCAPE '\\')"
                .into(),
        );
        for _ in 0..4 {
            args.push(Arg::Text(pat.clone()));
        }
    }
    if let Some(kinds) = &f.kinds {
        if kinds.is_empty() {
            wh.push("0".into());
        } else {
            wh.push(format!("kind IN ({})", vec!["?"; kinds.len()].join(", ")));
            args.extend(kinds.iter().cloned().map(Arg::Text));
        }
    }
    if !scope_only {
        match f.severity.as_str() {
            "error" | "warn" => {
                wh.push("severity = ?".into());
                args.push(Arg::Text(f.severity.clone()));
            }
            "info" => wh.push("severity NOT IN ('error', 'warn')".into()),
            _ => {}
        }
        if f.unread_only {
            wh.push("read_at IS NULL".into());
        }
        if let Some((ts, id)) = f.before {
            wh.push("(created_at < ? OR (created_at = ? AND id < ?))".into());
            args.push(Arg::Int(ts));
            args.push(Arg::Int(ts));
            args.push(Arg::Int(id));
        }
    }
    (format!(" WHERE {}", wh.join(" AND ")), args)
}

/// One page of the archive, newest first.
pub async fn search(
    pool: &SqlitePool,
    user_id: i64,
    f: &SearchFilter,
    limit: i64,
) -> Result<Vec<NotificationRow>, StateError> {
    let (wh, args) = where_clause(user_id, f, false);
    let sql =
        format!("SELECT {COLS} FROM notifications{wh} ORDER BY created_at DESC, id DESC LIMIT ?");
    let mut query = sqlx::query_as::<_, RowTuple>(&sql);
    for a in args {
        query = match a {
            Arg::Int(v) => query.bind(v),
            Arg::Text(v) => query.bind(v),
        };
    }
    let rows = query.bind(limit.clamp(1, 500)).fetch_all(pool).await?;
    Ok(rows.into_iter().map(from_tuple).collect())
}

/// Segment totals over `f`'s scope (search box + kinds).
pub async fn search_counts(
    pool: &SqlitePool,
    user_id: i64,
    f: &SearchFilter,
) -> Result<SearchCounts, StateError> {
    let (wh, args) = where_clause(user_id, f, true);
    let sql = format!(
        "SELECT COUNT(*), \
           COALESCE(SUM(read_at IS NULL), 0), \
           COALESCE(SUM(severity = 'error'), 0), \
           COALESCE(SUM(severity = 'warn'), 0), \
           COALESCE(SUM(severity NOT IN ('error', 'warn')), 0), \
           COALESCE(SUM(severity = 'error' AND read_at IS NULL), 0) \
         FROM notifications{wh}"
    );
    let mut query = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(&sql);
    for a in args {
        query = match a {
            Arg::Int(v) => query.bind(v),
            Arg::Text(v) => query.bind(v),
        };
    }
    let (all, unread, error, warn, info, unread_error) = query.fetch_one(pool).await?;
    Ok(SearchCounts {
        all,
        unread,
        error,
        warn,
        info,
        unread_error,
    })
}

/// Every kind this user has rows in, with `(total, unread)`. Over the whole
/// archive; the caller folds kinds into topics.
pub async fn kind_counts(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<(String, i64, i64)>, StateError> {
    Ok(sqlx::query_as(
        "SELECT kind, COUNT(*), COALESCE(SUM(read_at IS NULL), 0) \
         FROM notifications WHERE user_id = ? GROUP BY kind ORDER BY kind",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?)
}

/// Count of unread notifications for one user. Drives the red
/// badge on the bell icon.
pub async fn unread_count(pool: &SqlitePool, user_id: i64) -> Result<i64, StateError> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL")
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
pub async fn mark_all_read(pool: &SqlitePool, user_id: i64, now: i64) -> Result<i64, StateError> {
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

/// Mark the unread rows matching `f` as read — the archive's "mark these
/// read" when it is filtered. The cursor is ignored: it means every match,
/// not just the page on screen.
pub async fn mark_read_matching(
    pool: &SqlitePool,
    user_id: i64,
    f: &SearchFilter,
    now: i64,
) -> Result<i64, StateError> {
    let f = SearchFilter {
        before: None,
        unread_only: true,
        ..f.clone()
    };
    let (wh, args) = where_clause(user_id, &f, false);
    let sql = format!("UPDATE notifications SET read_at = ?{wh}");
    let mut query = sqlx::query(&sql).bind(now);
    for a in args {
        query = match a {
            Arg::Int(v) => query.bind(v),
            Arg::Text(v) => query.bind(v),
        };
    }
    Ok(query.execute(pool).await?.rows_affected() as i64)
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
    let o = sqlx::query("DELETE FROM notification_outbox WHERE created_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    Ok((r.rows_affected() + o.rows_affected()) as i64)
}

/// One alert a worker raised, waiting for the master to collect it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub id: i64,
    pub severity: String,
    pub title: String,
    pub body: String,
    pub href: String,
    pub kind: String,
    pub created_at: i64,
}

/// Park an alert on a worker (which has no web users to give it to).
pub async fn outbox_insert(
    pool: &SqlitePool,
    severity: &str,
    title: &str,
    body: &str,
    href: &str,
    kind: &str,
    now: i64,
) -> Result<i64, StateError> {
    let r = sqlx::query(
        "INSERT INTO notification_outbox (severity, title, body, href, kind, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
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

/// Outbox rows after `after_id`, oldest first.
pub async fn outbox_after(
    pool: &SqlitePool,
    after_id: i64,
    limit: i64,
) -> Result<Vec<OutboxRow>, StateError> {
    let rows: Vec<(i64, String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, severity, title, body, href, kind, created_at FROM notification_outbox \
         WHERE id > ? ORDER BY id LIMIT ?",
    )
    .bind(after_id)
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, severity, title, body, href, kind, created_at)| OutboxRow {
                id,
                severity,
                title,
                body,
                href,
                kind,
                created_at,
            },
        )
        .collect())
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
        insert(&pool, 1, "info", "first", "", "/", "test", 1)
            .await
            .unwrap();
        insert(&pool, 1, "info", "second", "", "/", "test", 2)
            .await
            .unwrap();
        insert(&pool, 1, "info", "third", "", "/", "test", 3)
            .await
            .unwrap();
        let rows = list_recent(&pool, 1, 10).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].title, "third");
        assert_eq!(rows[1].title, "second");
        assert_eq!(rows[2].title, "first");
    }

    #[tokio::test]
    async fn unread_count_decrements_when_marked_read() {
        let pool = fresh().await;
        let a = insert(&pool, 1, "info", "a", "", "/", "test", 1)
            .await
            .unwrap();
        insert(&pool, 1, "info", "b", "", "/", "test", 2)
            .await
            .unwrap();
        insert(&pool, 1, "info", "c", "", "/", "test", 3)
            .await
            .unwrap();
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
        let n = insert(&pool, 1, "info", "secret", "", "/", "test", 1)
            .await
            .unwrap();
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
        insert(&pool, 1, "info", "ancient", "", "/", "test", 100)
            .await
            .unwrap();
        insert(&pool, 1, "info", "recent", "", "/", "test", 1000)
            .await
            .unwrap();
        // now=2000, ttl=500 → cutoff=1500 → "ancient" (100) deleted, "recent" (1000) deleted too
        // Use ttl 1500 → cutoff = 500 → only "ancient" deleted
        let n = gc_older_than(&pool, 1500, 2000).await.unwrap();
        assert_eq!(n, 1);
        let rows = list_recent(&pool, 1, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "recent");
    }

    async fn seed_mix(pool: &SqlitePool) {
        // (severity, title, kind, created_at)
        for (sev, title, kind, ts) in [
            ("error", "Cert failed a.cz", "cert.renew_failed:a.cz", 10),
            ("warn", "Cert failing b.cz", "cert.renew_failed:b.cz", 20),
            ("info", "Memory raised", "php_mem_auto", 30),
            ("error", "Pages broken", "site_check_broken", 40),
            ("warn", "Snake_case thing", "cert_x", 50),
        ] {
            insert(pool, 1, sev, title, "", "/", kind, ts)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn search_filters_by_kinds_severity_and_unread() {
        let pool = fresh().await;
        seed_mix(&pool).await;
        let kinds = SearchFilter {
            kinds: Some(vec![
                "cert.renew_failed:a.cz".into(),
                "cert.renew_failed:b.cz".into(),
            ]),
            ..Default::default()
        };
        assert_eq!(search(&pool, 1, &kinds, 50).await.unwrap().len(), 2);
        let none = SearchFilter {
            kinds: Some(vec![]),
            ..Default::default()
        };
        assert!(search(&pool, 1, &none, 50).await.unwrap().is_empty());
        assert_eq!(search_counts(&pool, 1, &none).await.unwrap().all, 0);

        let info = SearchFilter {
            severity: "info".into(),
            ..Default::default()
        };
        let rows = search(&pool, 1, &info, 50).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "Memory raised");

        let first = search(&pool, 1, &SearchFilter::default(), 50)
            .await
            .unwrap();
        mark_read(&pool, 1, first[0].id, 99).await.unwrap();
        let unread = SearchFilter {
            unread_only: true,
            ..Default::default()
        };
        assert_eq!(search(&pool, 1, &unread, 50).await.unwrap().len(), 4);

        let c = search_counts(&pool, 1, &info).await.unwrap();
        assert_eq!(
            (c.all, c.unread, c.error, c.warn, c.info, c.unread_error),
            (5, 4, 2, 2, 1, 2),
            "counts ignore the severity/unread filter"
        );
    }

    #[tokio::test]
    async fn search_cursor_pages_without_gaps_or_repeats() {
        let pool = fresh().await;
        // Three rows share a timestamp: the cursor has to break the tie on id.
        for (i, ts) in [5, 5, 5, 4, 3].into_iter().enumerate() {
            insert(&pool, 1, "info", &format!("n{i}"), "", "/", "k", ts)
                .await
                .unwrap();
        }
        let mut seen = Vec::new();
        let mut f = SearchFilter::default();
        loop {
            let page = search(&pool, 1, &f, 2).await.unwrap();
            if page.is_empty() {
                break;
            }
            let last = page.last().unwrap();
            f.before = Some((last.created_at, last.id));
            seen.extend(page.into_iter().map(|r| r.title));
        }
        assert_eq!(seen, ["n2", "n1", "n0", "n3", "n4"]);
    }

    #[tokio::test]
    async fn search_q_matches_title_and_is_user_scoped() {
        let pool = fresh().await;
        seed_mix(&pool).await;
        let f = SearchFilter {
            q: "broken".into(),
            ..Default::default()
        };
        assert_eq!(search(&pool, 1, &f, 50).await.unwrap().len(), 1);
        assert!(search(&pool, 2, &f, 50).await.unwrap().is_empty());
        // A literal % is not a wildcard.
        let pct = SearchFilter {
            q: "%".into(),
            ..Default::default()
        };
        assert!(search(&pool, 1, &pct, 50).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn mark_read_matching_touches_only_the_filtered_rows() {
        let pool = fresh().await;
        seed_mix(&pool).await;
        let f = SearchFilter {
            kinds: Some(vec![
                "cert.renew_failed:a.cz".into(),
                "cert.renew_failed:b.cz".into(),
            ]),
            // A cursor must not narrow "mark these read" to one page.
            before: Some((15, i64::MAX)),
            ..Default::default()
        };
        assert_eq!(mark_read_matching(&pool, 1, &f, 99).await.unwrap(), 2);
        assert_eq!(unread_count(&pool, 1).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn kind_counts_cover_the_whole_archive() {
        let pool = fresh().await;
        seed_mix(&pool).await;
        let kinds = kind_counts(&pool, 1).await.unwrap();
        assert_eq!(kinds.len(), 5);
        assert!(kinds.contains(&("php_mem_auto".to_string(), 1, 1)));
    }

    #[tokio::test]
    async fn node_rows_are_collected_once_and_cursor_follows() {
        let pool = fresh().await;
        assert_eq!(node_cursor(&pool, "w1").await.unwrap(), 0);
        let a = outbox_insert(&pool, "error", "RO fs", "", "/", "system.rofs", 7)
            .await
            .unwrap();
        let b = outbox_insert(&pool, "warn", "Cert", "", "/", "cert", 8)
            .await
            .unwrap();
        let items = outbox_after(&pool, 0, 10).await.unwrap();
        assert_eq!(items.iter().map(|r| r.id).collect::<Vec<_>>(), [a, b]);
        assert_eq!(outbox_after(&pool, a, 10).await.unwrap().len(), 1);
        for it in &items {
            assert!(insert_from_node(&pool, 1, "w1", it).await.unwrap());
            // Second collection of the same row: ignored.
            assert!(!insert_from_node(&pool, 1, "w1", it).await.unwrap());
        }
        assert_eq!(node_cursor(&pool, "w1").await.unwrap(), b);
        assert_eq!(node_cursor(&pool, "w2").await.unwrap(), 0);
        let rows = list_recent(&pool, 1, 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].node_id, "w1");
        assert_eq!(rows[0].created_at, 8, "keeps the time the node raised it");
    }

    #[tokio::test]
    async fn gc_also_prunes_the_outbox() {
        let pool = fresh().await;
        outbox_insert(&pool, "info", "old", "", "/", "k", 100)
            .await
            .unwrap();
        outbox_insert(&pool, "info", "new", "", "/", "k", 1900)
            .await
            .unwrap();
        assert_eq!(gc_older_than(&pool, 1500, 2000).await.unwrap(), 1);
        assert_eq!(outbox_after(&pool, 0, 10).await.unwrap().len(), 1);
    }
}
