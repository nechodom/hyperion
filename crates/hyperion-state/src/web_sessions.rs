//! `web_sessions` — DB-backed session ledger that complements the
//! signed-cookie Session token. The cookie carries `sid` (a ULID);
//! this table answers "is that sid still live, and who owns it?"

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub sid: String,
    pub user_id: i64,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<i64>,
}

/// Insert a new live session row.
pub async fn insert(
    pool: &SqlitePool,
    sid: &str,
    user_id: i64,
    ip: Option<&str>,
    user_agent: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO web_sessions
            (sid, user_id, ip, user_agent, created_at, last_seen_at, revoked_at, revoked_by)
           VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)"#,
    )
    .bind(sid)
    .bind(user_id)
    .bind(ip)
    .bind(user_agent)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns true ⇒ "this sid is acceptable, don't lock the user out".
/// Concretely:
///   * row present + revoked_at IS NULL ⇒ true (alive); side-effect
///     updates `last_seen_at` for the /settings/sessions UI
///   * row present + revoked_at IS NOT NULL ⇒ false (operator killed it)
///   * row absent ⇒ true (legacy cookie minted before this table
///     existed; signature alone is the gate). Once the planned
///     "revoke all legacy" sweep runs, an absent row can be
///     reinterpreted as dead.
///
/// The semantics here matter for security: the cookie's Ed25519
/// signature already prevents forgery, so accepting unknown sids
/// is safe. Returning `false` for unknown sids would log out
/// every operator immediately after the schema migration.
pub async fn touch_if_live(pool: &SqlitePool, sid: &str, now: i64) -> Result<bool, StateError> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT revoked_at FROM web_sessions WHERE sid = ?")
            .bind(sid)
            .fetch_optional(pool)
            .await?;
    match row {
        Some((None,)) => {
            // Live — touch last_seen_at; best-effort.
            let _ = sqlx::query("UPDATE web_sessions SET last_seen_at = ? WHERE sid = ?")
                .bind(now)
                .bind(sid)
                .execute(pool)
                .await;
            Ok(true)
        }
        Some((Some(_),)) => Ok(false), // explicit revocation wins
        None => Ok(true),              // legacy / pre-migration cookie — accept
    }
}

/// Newest-first list of sessions belonging to `user_id`. Used by
/// the /settings/sessions page.
pub async fn list_for_user(
    pool: &SqlitePool,
    user_id: i64,
    limit: i64,
) -> Result<Vec<SessionRow>, StateError> {
    let limit = limit.clamp(1, 200);
    let rows: Vec<(
        String,
        i64,
        Option<String>,
        Option<String>,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
    )> = sqlx::query_as(
        r#"SELECT sid, user_id, ip, user_agent, created_at, last_seen_at, revoked_at, revoked_by
             FROM web_sessions
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?"#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(sid, user_id, ip, ua, created_at, last_seen_at, revoked_at, revoked_by)| SessionRow {
                sid,
                user_id,
                ip,
                user_agent: ua,
                created_at,
                last_seen_at,
                revoked_at,
                revoked_by,
            },
        )
        .collect())
}

/// Flip `revoked_at` for one session. No-op if already revoked.
/// Returns true if the row was found and owned by `user_id` (or
/// `user_id` is privileged). Caller is expected to do the
/// privilege check.
pub async fn revoke(
    pool: &SqlitePool,
    sid: &str,
    revoked_by: i64,
    now: i64,
) -> Result<bool, StateError> {
    let n = sqlx::query(
        "UPDATE web_sessions SET revoked_at = ?, revoked_by = ? WHERE sid = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(revoked_by)
    .bind(sid)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Revoke every live session for `user_id`. Operator-callable
/// kill-switch when an account is compromised.
pub async fn revoke_all_for_user(
    pool: &SqlitePool,
    user_id: i64,
    revoked_by: i64,
    now: i64,
) -> Result<u64, StateError> {
    let n = sqlx::query(
        r#"UPDATE web_sessions
              SET revoked_at = ?, revoked_by = ?
            WHERE user_id = ?
              AND revoked_at IS NULL"#,
    )
    .bind(now)
    .bind(revoked_by)
    .bind(user_id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Drop rows older than `keep_secs`. Run from the daily scheduler
/// to keep the table bounded. Even with aggressive sign-in churn
/// this stays in the low thousands of rows; the GC is cheap.
pub async fn gc_older_than(pool: &SqlitePool, cutoff: i64) -> Result<u64, StateError> {
    let n = sqlx::query("DELETE FROM web_sessions WHERE created_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    async fn fresh() -> SqlitePool {
        let p = open_memory().await.expect("open mem");
        // The schema requires a referenced web_users row; seed one.
        sqlx::query(
            r#"INSERT INTO web_users
                (id, username, email, password_hash, role, totp_required,
                 locked, failed_logins, created_at, updated_at)
               VALUES (1, 'kevin', 'k@example.com', 'x', 'admin', 0,
                       0, 0, 0, 0)"#,
        )
        .execute(&p)
        .await
        .expect("seed user");
        p
    }

    #[tokio::test]
    async fn insert_touch_revoke_lifecycle() {
        let p = fresh().await;
        insert(&p, "sid-a", 1, Some("1.2.3.4"), Some("curl/8"), 1000)
            .await
            .expect("insert");
        assert!(touch_if_live(&p, "sid-a", 1500).await.expect("touch"));
        let rows = list_for_user(&p, 1, 10).await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(rows[0].last_seen_at, 1500);
        assert!(rows[0].revoked_at.is_none());

        // Revoke; touch should now report dead.
        assert!(revoke(&p, "sid-a", 1, 2000).await.expect("revoke"));
        assert!(!touch_if_live(&p, "sid-a", 2100).await.expect("touch-2"));

        // Second revoke is a no-op (idempotent).
        assert!(!revoke(&p, "sid-a", 1, 2200).await.expect("revoke-2"));
    }

    /// A missing sid (legacy cookie minted before this table
    /// existed) is accepted — the cookie's Ed25519 signature is
    /// the gate, so an unknown sid is not a credential we need to
    /// reject. An EXPLICIT revoked_at row is the only way to kill
    /// a session.
    #[tokio::test]
    async fn unknown_sid_is_accepted_as_legacy() {
        let p = fresh().await;
        assert!(touch_if_live(&p, "no-such-sid", 100).await.expect("touch"));
    }

    /// Mass revoke for compromise-recovery: every live row goes
    /// dead, dead rows stay dead.
    #[tokio::test]
    async fn revoke_all_kills_only_live_rows() {
        let p = fresh().await;
        insert(&p, "live-1", 1, None, None, 100).await.expect("i1");
        insert(&p, "live-2", 1, None, None, 200).await.expect("i2");
        insert(&p, "dead-1", 1, None, None, 50).await.expect("i3");
        revoke(&p, "dead-1", 1, 60).await.expect("pre-revoke");

        let n = revoke_all_for_user(&p, 1, 1, 1000).await.expect("ra");
        assert_eq!(n, 2, "only the two live rows should flip");
        assert!(!touch_if_live(&p, "live-1", 1100).await.expect("t1"));
        assert!(!touch_if_live(&p, "live-2", 1100).await.expect("t2"));
        assert!(!touch_if_live(&p, "dead-1", 1100).await.expect("t3"));
    }
}
