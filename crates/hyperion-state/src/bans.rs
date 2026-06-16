//! Per-node IP ban list (`ip_bans` table) — the persistent mirror of
//! the `inet hyperion` nftables `banned` set. Rows survive reboots so
//! the agent can re-apply unexpired bans to nftables on start.

use crate::db::StateError;
use sqlx::SqlitePool;

/// One ban row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpBan {
    pub id: i64,
    pub ip: String,
    pub hosting_id: Option<String>,
    pub reason: String,
    pub source: String,
    pub banned_at: i64,
    /// 0 = permanent.
    pub expires_at: i64,
}

type RawBan = (i64, String, Option<String>, String, String, i64, i64);

fn to_ban(r: RawBan) -> IpBan {
    IpBan {
        id: r.0,
        ip: r.1,
        hosting_id: r.2,
        reason: r.3,
        source: r.4,
        banned_at: r.5,
        expires_at: r.6,
    }
}

const COLS: &str = "id, ip, hosting_id, reason, source, banned_at, expires_at";

/// Add a ban, refreshing any existing active ban for the same IP (the
/// partial unique index permits only one active row per IP). Returns the
/// new row id.
pub async fn add_or_refresh(
    pool: &SqlitePool,
    ip: &str,
    hosting_id: Option<&str>,
    reason: &str,
    source: &str,
    banned_at: i64,
    expires_at: i64,
) -> Result<i64, StateError> {
    sqlx::query("UPDATE ip_bans SET active = 0 WHERE ip = ? AND active = 1")
        .bind(ip)
        .execute(pool)
        .await?;
    let r = sqlx::query(
        "INSERT INTO ip_bans (ip, hosting_id, reason, source, banned_at, expires_at, active) \
         VALUES (?, ?, ?, ?, ?, ?, 1)",
    )
    .bind(ip)
    .bind(hosting_id)
    .bind(reason)
    .bind(source)
    .bind(banned_at)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(r.last_insert_rowid())
}

/// Deactivate the active ban for an IP. Returns true if one was removed.
pub async fn deactivate(pool: &SqlitePool, ip: &str) -> Result<bool, StateError> {
    let r = sqlx::query("UPDATE ip_bans SET active = 0 WHERE ip = ? AND active = 1")
        .bind(ip)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Sweep expired bans (active, expires_at > 0, lapsed) → mark inactive
/// and return their IPs so the caller can drop them from nftables too.
pub async fn reap_expired(pool: &SqlitePool, now: i64) -> Result<Vec<String>, StateError> {
    let ips: Vec<(String,)> = sqlx::query_as(
        "SELECT ip FROM ip_bans WHERE active = 1 AND expires_at > 0 AND expires_at <= ?",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;
    if !ips.is_empty() {
        sqlx::query(
            "UPDATE ip_bans SET active = 0 WHERE active = 1 AND expires_at > 0 AND expires_at <= ?",
        )
        .bind(now)
        .execute(pool)
        .await?;
    }
    Ok(ips.into_iter().map(|(ip,)| ip).collect())
}

/// True when the IP currently has an active, unexpired ban.
pub async fn is_active(pool: &SqlitePool, ip: &str, now: i64) -> Result<bool, StateError> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM ip_bans WHERE ip = ? AND active = 1 AND (expires_at = 0 OR expires_at > ?) LIMIT 1",
    )
    .bind(ip)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// All active, unexpired bans (most recent first). Used for re-applying
/// to nftables on boot and for the cluster view.
pub async fn list_active(pool: &SqlitePool, now: i64) -> Result<Vec<IpBan>, StateError> {
    let rows: Vec<RawBan> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM ip_bans WHERE active = 1 AND (expires_at = 0 OR expires_at > ?) \
         ORDER BY banned_at DESC"
    ))
    .bind(now)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(to_ban).collect())
}

/// Active, unexpired bans attributed to one hosting, plus node-wide
/// manual bans (hosting_id NULL) so the operator sees everything that
/// affects their site.
pub async fn list_for_hosting(
    pool: &SqlitePool,
    hosting_id: &str,
    now: i64,
) -> Result<Vec<IpBan>, StateError> {
    let rows: Vec<RawBan> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM ip_bans \
         WHERE active = 1 AND (expires_at = 0 OR expires_at > ?) \
           AND (hosting_id = ? OR hosting_id IS NULL) \
         ORDER BY banned_at DESC"
    ))
    .bind(now)
    .bind(hosting_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(to_ban).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn ban_lifecycle() {
        let pool = open_memory().await.expect("open");
        add_or_refresh(&pool, "1.2.3.4", Some("h1"), "brute force", "auto", 100, 3700)
            .await
            .expect("add");
        assert!(is_active(&pool, "1.2.3.4", 200).await.unwrap());
        assert_eq!(list_active(&pool, 200).await.unwrap().len(), 1);

        // Refresh keeps a single active row.
        add_or_refresh(&pool, "1.2.3.4", Some("h1"), "brute force", "auto", 300, 4000)
            .await
            .expect("refresh");
        assert_eq!(list_active(&pool, 350).await.unwrap().len(), 1);

        // Expiry sweep.
        let reaped = reap_expired(&pool, 5000).await.unwrap();
        assert_eq!(reaped, vec!["1.2.3.4".to_string()]);
        assert!(!is_active(&pool, "1.2.3.4", 5001).await.unwrap());

        // Manual permanent ban + per-hosting view.
        add_or_refresh(&pool, "9.9.9.9", None, "manual", "manual", 600, 0)
            .await
            .expect("manual");
        assert!(is_active(&pool, "9.9.9.9", 99_999).await.unwrap());
        let for_h = list_for_hosting(&pool, "h1", 700).await.unwrap();
        assert_eq!(for_h.len(), 1); // the node-wide manual ban shows up
        assert!(deactivate(&pool, "9.9.9.9").await.unwrap());
        assert!(!deactivate(&pool, "9.9.9.9").await.unwrap());
    }
}
