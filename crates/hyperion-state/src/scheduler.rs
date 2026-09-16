//! `scheduled_actions` table + per-hosting expiry helpers on `hostings`.

use crate::db::StateError;
use hyperion_types::HostingId;
use sqlx::SqlitePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledKind {
    Notify30d,
    Notify7d,
    Notify1d,
    SuspendExpired,
    DeleteExpired,
}

impl ScheduledKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Notify30d => "notify_30d",
            Self::Notify7d => "notify_7d",
            Self::Notify1d => "notify_1d",
            Self::SuspendExpired => "suspend_expired",
            Self::DeleteExpired => "delete_expired",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "notify_30d" => Some(Self::Notify30d),
            "notify_7d" => Some(Self::Notify7d),
            "notify_1d" => Some(Self::Notify1d),
            "suspend_expired" => Some(Self::SuspendExpired),
            "delete_expired" => Some(Self::DeleteExpired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRow {
    pub id: i64,
    pub hosting_id: HostingId,
    pub action: ScheduledKind,
    pub due_at: i64,
    pub state: String,
    pub attempts: i64,
    pub last_attempt_at: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
}

pub async fn upsert(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    action: ScheduledKind,
    due_at: i64,
    now: i64,
) -> Result<(), StateError> {
    // INSERT OR IGNORE: a row with the same (hosting, action, due) is
    // already queued; nothing to do.
    sqlx::query(
        r#"INSERT INTO scheduled_actions
           (hosting_id, action, due_at, state, attempts, created_at)
           VALUES (?, ?, ?, 'pending', 0, ?)
           ON CONFLICT(hosting_id, action, due_at) DO NOTHING"#,
    )
    .bind(hosting_id.as_str())
    .bind(action.as_str())
    .bind(due_at)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Cancel a hosting's pending actions that fell due at or before `now`, and
/// say which they were.
///
/// For a restore from the trash: an operator bringing a site back has made a
/// decision about it, and an expiry warning dated weeks ago, a suspension or a
/// deletion replayed on top of that decision would undo it. Actions still in
/// the future are left alone.
pub async fn cancel_overdue_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    now: i64,
) -> Result<Vec<ScheduledKind>, StateError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "UPDATE scheduled_actions SET state = 'canceled' \
         WHERE hosting_id = ? AND state = 'pending' AND due_at <= ? \
         RETURNING action",
    )
    .bind(hosting_id.as_str())
    .bind(now)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(a,)| ScheduledKind::parse(&a))
        .collect())
}

pub async fn cancel_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE scheduled_actions SET state='canceled' \
         WHERE hosting_id = ? AND state = 'pending'",
    )
    .bind(hosting_id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Pending actions whose time has come — for hostings that are not in the
/// trash.
///
/// A trashed hosting's actions stay `pending` rather than being run. Run, they
/// mailed the customer "your hosting expires in 7 days" about a site already
/// thrown away, and the suspend and delete arms failed against a trashed site
/// three times each.
///
/// Held is not the end of it: whatever fell due while the site sat in the trash
/// must not fire the moment it comes out. A replayed `DeleteExpired` put a
/// just-restored site straight back in the trash — or, with the trash switched
/// off in the meantime, hard-deleted it. `restore_from_trash` therefore cancels
/// those with [`cancel_overdue_for_hosting`]; what is still in the future stays
/// armed.
pub async fn pending_due(
    pool: &SqlitePool,
    now: i64,
    limit: i64,
) -> Result<Vec<ScheduledRow>, StateError> {
    let rows: Vec<(
        i64,
        String,
        String,
        i64,
        String,
        i64,
        Option<i64>,
        Option<String>,
        i64,
    )> = sqlx::query_as(
        "SELECT id, hosting_id, action, due_at, state, attempts, last_attempt_at,
                last_error, created_at
         FROM scheduled_actions
         WHERE state = 'pending' AND due_at <= ?
           AND hosting_id NOT IN (SELECT id FROM hostings WHERE state = 'trashed')
         ORDER BY due_at LIMIT ?",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, hid, action, due, state, attempts, lat, lerr, created) in rows {
        let kind = ScheduledKind::parse(&action)
            .ok_or_else(|| StateError::InvalidState(action.clone()))?;
        out.push(ScheduledRow {
            id,
            hosting_id: HostingId(hid),
            action: kind,
            due_at: due,
            state,
            attempts,
            last_attempt_at: lat,
            last_error: lerr,
            created_at: created,
        });
    }
    Ok(out)
}

pub async fn mark_running(pool: &SqlitePool, id: i64, now: i64) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE scheduled_actions
         SET state='running', last_attempt_at=?, attempts=attempts+1
         WHERE id = ? AND state = 'pending'",
    )
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_done(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("UPDATE scheduled_actions SET state='done', last_error=NULL WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn mark_failed_or_retry(
    pool: &SqlitePool,
    id: i64,
    error: &str,
    max_attempts: i64,
) -> Result<(), StateError> {
    // If we've already attempted enough times, terminal-fail; else go back to
    // pending so the next tick retries.
    sqlx::query(
        "UPDATE scheduled_actions
         SET state = CASE WHEN attempts >= ? THEN 'failed' ELSE 'pending' END,
             last_error = ?
         WHERE id = ?",
    )
    .bind(max_attempts)
    .bind(error)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

// ------- Per-hosting expiry helpers -------

#[allow(clippy::too_many_arguments)]
pub async fn set_expiry(
    pool: &SqlitePool,
    id: &HostingId,
    expires_at: Option<i64>,
    owner_email: Option<&str>,
    grace_days: i64,
    warning_offsets_csv: &str,
    customer_since: Option<i64>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE hostings
         SET expires_at = ?, owner_email = ?, grace_days = ?,
             warning_offsets_days = ?, customer_since = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind(expires_at)
    .bind(owner_email)
    .bind(grace_days)
    .bind(warning_offsets_csv)
    .bind(customer_since)
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryRow {
    pub id: HostingId,
    pub domain: String,
    pub expires_at: Option<i64>,
    pub owner_email: Option<String>,
    pub grace_days: i64,
    pub warning_offsets_days: String,
    /// The past date the operator typed, before it was rolled forward to the
    /// next occurrence of its day and month. Records since when the hosting
    /// has been with us; `None` when a future date was typed.
    pub customer_since: Option<i64>,
}

pub async fn get_expiry(
    pool: &SqlitePool,
    id: &HostingId,
) -> Result<Option<ExpiryRow>, StateError> {
    let row: Option<(
        String,
        String,
        Option<i64>,
        Option<String>,
        i64,
        String,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT id, domain, expires_at, owner_email, grace_days, warning_offsets_days,
                customer_since
         FROM hostings WHERE id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(
        row.map(|(id, domain, exp, email, grace, offs, since)| ExpiryRow {
            id: HostingId(id),
            domain,
            expires_at: exp,
            owner_email: email,
            grace_days: grace,
            warning_offsets_days: offs,
            customer_since: since,
        }),
    )
}

/// All hostings with a non-NULL expiry, sorted ascending.
pub async fn list_with_expiry(pool: &SqlitePool) -> Result<Vec<ExpiryRow>, StateError> {
    let rows: Vec<(
        String,
        String,
        Option<i64>,
        Option<String>,
        i64,
        String,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT id, domain, expires_at, owner_email, grace_days, warning_offsets_days,
                customer_since
         FROM hostings WHERE expires_at IS NOT NULL ORDER BY expires_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, domain, exp, email, grace, offs, since)| ExpiryRow {
            id: HostingId(id),
            domain,
            expires_at: exp,
            owner_email: email,
            grace_days: grace,
            warning_offsets_days: offs,
            customer_since: since,
        })
        .collect())
}

/// Parse the `"30,7,1"` style CSV into a sorted (descending) Vec<i64>.
pub fn parse_offsets(csv: &str) -> Vec<i64> {
    let mut v: Vec<i64> = csv
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .filter(|&n| n > 0)
        .collect();
    v.sort_unstable_by(|a, b| b.cmp(a));
    v.dedup();
    v
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
    async fn set_expiry_writes_columns() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        set_expiry(
            &pool,
            &id,
            Some(1_900_000_000),
            Some("k@x.cz"),
            14,
            "30,7",
            Some(1_700_000_000),
            100,
        )
        .await
        .expect("set");
        let row = get_expiry(&pool, &id).await.expect("get").expect("present");
        assert_eq!(row.expires_at, Some(1_900_000_000));
        assert_eq!(row.owner_email.as_deref(), Some("k@x.cz"));
        // The date the operator originally typed survives the write — it is
        // the only record of since when the hosting has been with us.
        assert_eq!(row.customer_since, Some(1_700_000_000));
        assert_eq!(row.grace_days, 14);
        assert_eq!(row.warning_offsets_days, "30,7");
    }

    #[tokio::test]
    async fn upsert_pending_action_is_idempotent() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &id, ScheduledKind::Notify7d, 200, 100)
            .await
            .expect("first");
        upsert(&pool, &id, ScheduledKind::Notify7d, 200, 100)
            .await
            .expect("second");
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM scheduled_actions")
            .fetch_one(&pool)
            .await
            .expect("query");
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn pending_due_returns_only_due_pending() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &id, ScheduledKind::Notify30d, 50, 1)
            .await
            .expect("a");
        upsert(&pool, &id, ScheduledKind::Notify7d, 200, 1)
            .await
            .expect("b");
        upsert(&pool, &id, ScheduledKind::Notify1d, 1000, 1)
            .await
            .expect("c");
        let rows = pending_due(&pool, 300, 10).await.expect("query");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.action == ScheduledKind::Notify30d));
        assert!(rows.iter().any(|r| r.action == ScheduledKind::Notify7d));
    }

    #[tokio::test]
    async fn pending_due_holds_a_trashed_hostings_actions() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &id, ScheduledKind::Notify7d, 50, 1)
            .await
            .expect("queue");
        hostings::mark_trashed(&pool, &id, 60).await.expect("trash");
        assert!(
            pending_due(&pool, 300, 10).await.expect("query").is_empty(),
            "nothing may run for a site in the trash"
        );
        hostings::unmark_trashed(&pool, &id, 70)
            .await
            .expect("restore");
        assert_eq!(
            pending_due(&pool, 300, 10).await.expect("query").len(),
            1,
            "the held action is still there once the site is restored"
        );
    }

    #[tokio::test]
    async fn cancel_overdue_leaves_future_actions_armed() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &id, ScheduledKind::Notify7d, 50, 1)
            .await
            .expect("past notice");
        upsert(&pool, &id, ScheduledKind::DeleteExpired, 100, 1)
            .await
            .expect("past delete");
        upsert(&pool, &id, ScheduledKind::SuspendExpired, 900, 1)
            .await
            .expect("future suspend");
        let mut dropped = cancel_overdue_for_hosting(&pool, &id, 300)
            .await
            .expect("cancel");
        dropped.sort_by_key(|k| k.as_str());
        assert_eq!(
            dropped,
            vec![ScheduledKind::DeleteExpired, ScheduledKind::Notify7d]
        );
        let due_later = pending_due(&pool, 1000, 10).await.expect("query");
        assert_eq!(due_later.len(), 1, "{due_later:?}");
        assert_eq!(due_later[0].action, ScheduledKind::SuspendExpired);
        // Reconciliation re-upserts the same (hosting, action, due) rows on
        // every tick. The cancelled ones must stay cancelled.
        upsert(&pool, &id, ScheduledKind::DeleteExpired, 100, 2)
            .await
            .expect("reconcile");
        assert_eq!(pending_due(&pool, 1000, 10).await.expect("query").len(), 1);
    }

    #[tokio::test]
    async fn mark_running_then_done() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &id, ScheduledKind::SuspendExpired, 100, 1)
            .await
            .expect("upsert");
        let pending = pending_due(&pool, 200, 10).await.expect("query");
        let row = pending.first().expect("present");
        mark_running(&pool, row.id, 150).await.expect("running");
        mark_done(&pool, row.id).await.expect("done");
        let after = pending_due(&pool, 200, 10).await.expect("query");
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn mark_failed_or_retry_returns_to_pending_until_max_attempts() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &id, ScheduledKind::SuspendExpired, 100, 1)
            .await
            .expect("upsert");
        let row = pending_due(&pool, 200, 10).await.expect("q")[0].clone();
        // attempt 1
        mark_running(&pool, row.id, 150).await.expect("r");
        mark_failed_or_retry(&pool, row.id, "boom", 3)
            .await
            .expect("fail1");
        let again = pending_due(&pool, 200, 10).await.expect("q");
        assert_eq!(again.len(), 1);
        // attempt 2
        mark_running(&pool, again[0].id, 151).await.expect("r");
        mark_failed_or_retry(&pool, again[0].id, "boom", 3)
            .await
            .expect("fail2");
        let again = pending_due(&pool, 200, 10).await.expect("q");
        assert_eq!(again.len(), 1);
        // attempt 3 — now reaches max, goes terminal
        mark_running(&pool, again[0].id, 152).await.expect("r");
        mark_failed_or_retry(&pool, again[0].id, "boom", 3)
            .await
            .expect("fail3");
        let again = pending_due(&pool, 200, 10).await.expect("q");
        assert!(again.is_empty(), "now in failed state");
    }

    #[tokio::test]
    async fn cancel_for_hosting_blanks_pending() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &id, ScheduledKind::Notify7d, 100, 1)
            .await
            .expect("a");
        upsert(&pool, &id, ScheduledKind::Notify1d, 200, 1)
            .await
            .expect("b");
        cancel_for_hosting(&pool, &id).await.expect("cancel");
        let due = pending_due(&pool, 1000, 10).await.expect("q");
        assert!(due.is_empty());
    }

    #[test]
    fn parse_offsets_sorts_desc_and_dedups() {
        assert_eq!(parse_offsets("30,7,1"), vec![30, 7, 1]);
        assert_eq!(parse_offsets("1,7,30,7"), vec![30, 7, 1]);
        assert_eq!(parse_offsets("  30 ,bad, -1, 7"), vec![30, 7]);
        assert!(parse_offsets("").is_empty());
    }
}
