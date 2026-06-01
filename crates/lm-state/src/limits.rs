//! `hosting_limits`, `hosting_suspension`, `hosting_usage` tables.

use crate::db::StateError;
use lm_types::HostingId;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsRow {
    pub hosting_id: HostingId,
    pub disk_soft_bytes: Option<i64>,
    pub disk_hard_bytes: Option<i64>,
    pub inode_soft: Option<i64>,
    pub inode_hard: Option<i64>,
    pub php_memory_mb: i64,
    pub php_max_exec_secs: i64,
    pub php_max_children: i64,
    pub php_max_requests: i64,
    pub db_max_connections: i64,
    pub bw_monthly_bytes: Option<i64>,
    pub over_bw_policy: String,
    pub throttle_kbps: Option<i64>,
    pub updated_at: i64,
}

impl LimitsRow {
    /// Default limits used when no row exists yet for a hosting.
    pub fn defaults_for(hosting_id: &HostingId, now: i64) -> Self {
        Self {
            hosting_id: hosting_id.clone(),
            disk_soft_bytes: None,
            disk_hard_bytes: None,
            inode_soft: None,
            inode_hard: None,
            php_memory_mb: 256,
            php_max_exec_secs: 60,
            php_max_children: 5,
            php_max_requests: 1000,
            db_max_connections: 25,
            bw_monthly_bytes: None,
            over_bw_policy: "suspend".into(),
            throttle_kbps: None,
            updated_at: now,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert(pool: &SqlitePool, row: &LimitsRow) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_limits (
            hosting_id,
            disk_soft_bytes, disk_hard_bytes, inode_soft, inode_hard,
            php_memory_mb, php_max_exec_secs, php_max_children, php_max_requests,
            db_max_connections,
            bw_monthly_bytes, over_bw_policy, throttle_kbps,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hosting_id) DO UPDATE SET
            disk_soft_bytes    = excluded.disk_soft_bytes,
            disk_hard_bytes    = excluded.disk_hard_bytes,
            inode_soft         = excluded.inode_soft,
            inode_hard         = excluded.inode_hard,
            php_memory_mb      = excluded.php_memory_mb,
            php_max_exec_secs  = excluded.php_max_exec_secs,
            php_max_children   = excluded.php_max_children,
            php_max_requests   = excluded.php_max_requests,
            db_max_connections = excluded.db_max_connections,
            bw_monthly_bytes   = excluded.bw_monthly_bytes,
            over_bw_policy     = excluded.over_bw_policy,
            throttle_kbps      = excluded.throttle_kbps,
            updated_at         = excluded.updated_at"#,
    )
    .bind(row.hosting_id.as_str())
    .bind(row.disk_soft_bytes)
    .bind(row.disk_hard_bytes)
    .bind(row.inode_soft)
    .bind(row.inode_hard)
    .bind(row.php_memory_mb)
    .bind(row.php_max_exec_secs)
    .bind(row.php_max_children)
    .bind(row.php_max_requests)
    .bind(row.db_max_connections)
    .bind(row.bw_monthly_bytes)
    .bind(&row.over_bw_policy)
    .bind(row.throttle_kbps)
    .bind(row.updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get(pool: &SqlitePool, id: &HostingId) -> Result<Option<LimitsRow>, StateError> {
    type Tup = (
        String,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        i64,
        i64,
        i64,
        i64,
        i64,
        Option<i64>,
        String,
        Option<i64>,
        i64,
    );
    let row: Option<Tup> = sqlx::query_as(
        "SELECT hosting_id,
                disk_soft_bytes, disk_hard_bytes, inode_soft, inode_hard,
                php_memory_mb, php_max_exec_secs, php_max_children, php_max_requests,
                db_max_connections,
                bw_monthly_bytes, over_bw_policy, throttle_kbps,
                updated_at
         FROM hosting_limits WHERE hosting_id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            hosting_id,
            ds,
            dh,
            ino_s,
            ino_h,
            mem,
            exec,
            ch,
            req,
            db_conn,
            bw,
            policy,
            kbps,
            updated_at,
        )| LimitsRow {
            hosting_id: HostingId(hosting_id),
            disk_soft_bytes: ds,
            disk_hard_bytes: dh,
            inode_soft: ino_s,
            inode_hard: ino_h,
            php_memory_mb: mem,
            php_max_exec_secs: exec,
            php_max_children: ch,
            php_max_requests: req,
            db_max_connections: db_conn,
            bw_monthly_bytes: bw,
            over_bw_policy: policy,
            throttle_kbps: kbps,
            updated_at,
        },
    ))
}

pub async fn delete(pool: &SqlitePool, id: &HostingId) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_limits WHERE hosting_id = ?")
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- Suspension ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspensionRow {
    pub hosting_id: HostingId,
    pub suspended_at: i64,
    pub suspended_by: String,
    pub reason_message: Option<String>,
    pub custom_page_html: Option<String>,
}

pub async fn insert_suspension(pool: &SqlitePool, row: &SuspensionRow) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_suspension
           (hosting_id, suspended_at, suspended_by, reason_message, custom_page_html)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(hosting_id) DO UPDATE SET
             suspended_at = excluded.suspended_at,
             suspended_by = excluded.suspended_by,
             reason_message = excluded.reason_message,
             custom_page_html = excluded.custom_page_html"#,
    )
    .bind(row.hosting_id.as_str())
    .bind(row.suspended_at)
    .bind(&row.suspended_by)
    .bind(&row.reason_message)
    .bind(&row.custom_page_html)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_suspension(
    pool: &SqlitePool,
    id: &HostingId,
) -> Result<Option<SuspensionRow>, StateError> {
    let row: Option<(String, i64, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT hosting_id, suspended_at, suspended_by, reason_message, custom_page_html
         FROM hosting_suspension WHERE hosting_id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(hosting_id, ts, by, msg, html)| SuspensionRow {
        hosting_id: HostingId(hosting_id),
        suspended_at: ts,
        suspended_by: by,
        reason_message: msg,
        custom_page_html: html,
    }))
}

pub async fn delete_suspension(pool: &SqlitePool, id: &HostingId) -> Result<(), StateError> {
    sqlx::query("DELETE FROM hosting_suspension WHERE hosting_id = ?")
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

// ---------- Usage ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageBucket {
    pub hosting_id: HostingId,
    pub period: String,
    pub disk_used_bytes: i64,
    pub inodes_used: i64,
    pub bw_in_bytes: i64,
    pub bw_out_bytes: i64,
    pub php_requests: i64,
}

pub async fn upsert_usage(pool: &SqlitePool, bucket: &UsageBucket) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO hosting_usage
           (hosting_id, period, disk_used_bytes, inodes_used, bw_in_bytes, bw_out_bytes, php_requests)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(hosting_id, period) DO UPDATE SET
             disk_used_bytes = excluded.disk_used_bytes,
             inodes_used     = excluded.inodes_used,
             bw_in_bytes     = excluded.bw_in_bytes,
             bw_out_bytes    = excluded.bw_out_bytes,
             php_requests    = excluded.php_requests"#,
    )
    .bind(bucket.hosting_id.as_str())
    .bind(&bucket.period)
    .bind(bucket.disk_used_bytes)
    .bind(bucket.inodes_used)
    .bind(bucket.bw_in_bytes)
    .bind(bucket.bw_out_bytes)
    .bind(bucket.php_requests)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn usage_for(
    pool: &SqlitePool,
    id: &HostingId,
    limit: i64,
) -> Result<Vec<UsageBucket>, StateError> {
    let rows: Vec<(String, String, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT hosting_id, period, disk_used_bytes, inodes_used,
                bw_in_bytes, bw_out_bytes, php_requests
         FROM hosting_usage WHERE hosting_id = ? ORDER BY period DESC LIMIT ?",
    )
    .bind(id.as_str())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(hosting_id, period, disk, inodes, bw_in, bw_out, php)| UsageBucket {
                hosting_id: HostingId(hosting_id),
                period,
                disk_used_bytes: disk,
                inodes_used: inodes,
                bw_in_bytes: bw_in,
                bw_out_bytes: bw_out,
                php_requests: php,
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
        hostings::insert(pool, &id, "example.cz", suid, None, "/r", 1)
            .await
            .expect("hosting");
        id
    }

    #[tokio::test]
    async fn limits_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let mut row = LimitsRow::defaults_for(&id, 100);
        row.php_memory_mb = 512;
        row.disk_hard_bytes = Some(5_368_709_120);
        upsert(&pool, &row).await.expect("upsert");
        let got = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.php_memory_mb, 512);
        assert_eq!(got.disk_hard_bytes, Some(5_368_709_120));
    }

    #[tokio::test]
    async fn limits_upsert_updates_on_conflict() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let mut row = LimitsRow::defaults_for(&id, 100);
        row.php_memory_mb = 128;
        upsert(&pool, &row).await.expect("upsert");
        row.php_memory_mb = 1024;
        row.updated_at = 200;
        upsert(&pool, &row).await.expect("upsert again");
        let got = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.php_memory_mb, 1024);
        assert_eq!(got.updated_at, 200);
    }

    #[tokio::test]
    async fn limits_cascade_delete_with_hosting() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        upsert(&pool, &LimitsRow::defaults_for(&id, 1))
            .await
            .expect("upsert");
        hostings::delete(&pool, &id).await.expect("delete");
        let got = get(&pool, &id).await.expect("get");
        assert!(got.is_none(), "limits cascade-deleted");
    }

    #[tokio::test]
    async fn over_bw_policy_check_constraint() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let mut row = LimitsRow::defaults_for(&id, 1);
        row.over_bw_policy = "bogus".into();
        let r = upsert(&pool, &row).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn suspension_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let row = SuspensionRow {
            hosting_id: id.clone(),
            suspended_at: 500,
            suspended_by: "manual".into(),
            reason_message: Some("over quota".into()),
            custom_page_html: None,
        };
        insert_suspension(&pool, &row).await.expect("insert");
        let got = get_suspension(&pool, &id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got, row);
        delete_suspension(&pool, &id).await.expect("delete");
        assert!(get_suspension(&pool, &id).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn hostings_state_check_allows_suspended() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        sqlx::query("UPDATE hostings SET state='suspended' WHERE id = ?")
            .bind(id.as_str())
            .execute(&pool)
            .await
            .expect("update");
        let row = hostings::get_by_id(&pool, &id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(row.state.as_str(), "suspended");
    }

    #[tokio::test]
    async fn usage_round_trip() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        let bucket = UsageBucket {
            hosting_id: id.clone(),
            period: "2026-06-01-00".into(),
            disk_used_bytes: 1024,
            inodes_used: 12,
            bw_in_bytes: 2048,
            bw_out_bytes: 4096,
            php_requests: 17,
        };
        upsert_usage(&pool, &bucket).await.expect("upsert");
        let got = usage_for(&pool, &id, 10).await.expect("get");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], bucket);
    }
}
