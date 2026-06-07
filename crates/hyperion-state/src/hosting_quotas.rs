//! Per-hosting quota policy storage.
//!
//! The agent owns the enforcement layer (calling `setquota`); this
//! crate just persists the desired values + the last-applied
//! timestamp + error. UI reads/writes via the QuotaSet/QuotaGet RPCs.

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuotaRow {
    pub hosting_id: String,
    pub disk_soft_kib: i64,
    pub disk_hard_kib: i64,
    pub mem_limit_mib: i64,
    pub bw_soft_mib: i64,
    pub bw_hard_mib: i64,
    pub applied_at: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

/// Read the current quota row for `hosting_id`. Returns `Default`
/// (zero everywhere) when no row exists — caller treats "all
/// zeroes" as "no quotas configured".
pub async fn read(pool: &SqlitePool, hosting_id: &str) -> Result<QuotaRow, StateError> {
    let row: Option<(
        String,
        i64,
        i64,
        i64,
        i64,
        i64,
        Option<i64>,
        Option<String>,
        i64,
    )> = sqlx::query_as(
        r#"SELECT hosting_id, disk_soft_kib, disk_hard_kib, mem_limit_mib,
                  bw_soft_mib, bw_hard_mib, applied_at, last_error, updated_at
             FROM hosting_quotas WHERE hosting_id = ?"#,
    )
    .bind(hosting_id)
    .fetch_optional(pool)
    .await?;
    Ok(row
        .map(|(h, ds, dh, mem, bws, bwh, app, err, upd)| QuotaRow {
            hosting_id: h,
            disk_soft_kib: ds,
            disk_hard_kib: dh,
            mem_limit_mib: mem,
            bw_soft_mib: bws,
            bw_hard_mib: bwh,
            applied_at: app,
            last_error: err,
            updated_at: upd,
        })
        .unwrap_or(QuotaRow {
            hosting_id: hosting_id.to_string(),
            ..Default::default()
        }))
}

/// Upsert the policy fields. `applied_at` + `last_error` are NOT
/// touched here — those are managed by `mark_applied` /
/// `mark_failed` after the kernel call.
#[allow(clippy::too_many_arguments)]
pub async fn upsert(
    pool: &SqlitePool,
    hosting_id: &str,
    disk_soft_kib: i64,
    disk_hard_kib: i64,
    mem_limit_mib: i64,
    bw_soft_mib: i64,
    bw_hard_mib: i64,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_quotas
             (hosting_id, disk_soft_kib, disk_hard_kib, mem_limit_mib,
              bw_soft_mib, bw_hard_mib, applied_at, last_error, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)
           ON CONFLICT(hosting_id) DO UPDATE SET
              disk_soft_kib = excluded.disk_soft_kib,
              disk_hard_kib = excluded.disk_hard_kib,
              mem_limit_mib = excluded.mem_limit_mib,
              bw_soft_mib   = excluded.bw_soft_mib,
              bw_hard_mib   = excluded.bw_hard_mib,
              updated_at    = excluded.updated_at"#,
    )
    .bind(hosting_id)
    .bind(disk_soft_kib)
    .bind(disk_hard_kib)
    .bind(mem_limit_mib)
    .bind(bw_soft_mib)
    .bind(bw_hard_mib)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_applied(
    pool: &SqlitePool,
    hosting_id: &str,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE hosting_quotas SET applied_at = ?, last_error = NULL WHERE hosting_id = ?",
    )
    .bind(now)
    .bind(hosting_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_failed(
    pool: &SqlitePool,
    hosting_id: &str,
    err: &str,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query("UPDATE hosting_quotas SET last_error = ?, updated_at = ? WHERE hosting_id = ?")
        .bind(err)
        .bind(now)
        .bind(hosting_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete(pool: &SqlitePool, hosting_id: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_quotas WHERE hosting_id = ?")
        .bind(hosting_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    async fn fresh() -> SqlitePool {
        let p = open_memory().await.expect("open mem");
        // FK on hostings requires both a system_user (FK target) and
        // the hosting row itself. Insert minimal rows to satisfy
        // the chain; the quota row has no other deps.
        sqlx::query(
            r#"INSERT INTO system_users (id, name, uid, home_dir, shell, created_at)
               VALUES (1, 'site_h1', 1001, '/home/site_h1', '/usr/sbin/nologin', 0)"#,
        )
        .execute(&p)
        .await
        .expect("seed system_user");
        sqlx::query(
            r#"INSERT INTO hostings (id, domain, system_user_id, root_dir, state, created_at, updated_at)
               VALUES ('h1', 'example.cz', 1, '/home/site_h1/example.cz', 'active', 0, 0)"#,
        )
        .execute(&p)
        .await
        .expect("seed host");
        p
    }

    #[tokio::test]
    async fn upsert_then_read_round_trips() {
        let p = fresh().await;
        upsert(&p, "h1", 100_000, 200_000, 256, 5_000, 10_000, 1000)
            .await
            .expect("upsert");
        let r = read(&p, "h1").await.expect("read");
        assert_eq!(r.disk_soft_kib, 100_000);
        assert_eq!(r.disk_hard_kib, 200_000);
        assert_eq!(r.mem_limit_mib, 256);
        assert_eq!(r.bw_soft_mib, 5_000);
        assert_eq!(r.bw_hard_mib, 10_000);
        assert!(r.applied_at.is_none());

        // mark_applied flips applied_at + clears last_error.
        mark_applied(&p, "h1", 2000).await.expect("ma");
        let r = read(&p, "h1").await.expect("read");
        assert_eq!(r.applied_at, Some(2000));
        assert!(r.last_error.is_none());

        // mark_failed records the error without clearing the policy.
        mark_failed(&p, "h1", "quotaon disabled", 3000).await.expect("mf");
        let r = read(&p, "h1").await.expect("read");
        assert_eq!(r.last_error.as_deref(), Some("quotaon disabled"));
        // applied_at stays — last successful application is still
        // meaningful even after a later failure.
        assert_eq!(r.applied_at, Some(2000));
    }

    /// Reading a never-configured hosting returns Default + the id —
    /// caller treats this as "no quotas, show empty form".
    #[tokio::test]
    async fn read_missing_returns_default_with_id() {
        let p = fresh().await;
        let r = read(&p, "h1").await.expect("read");
        assert_eq!(r.hosting_id, "h1");
        assert_eq!(r.disk_soft_kib, 0);
        assert_eq!(r.disk_hard_kib, 0);
        assert!(r.applied_at.is_none());
    }
}
