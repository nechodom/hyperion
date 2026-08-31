//! Extra FTP logins for a hosting — see migration 061 for why they share the
//! site's uid rather than getting one of their own.

use crate::StateError;
use hyperion_types::HostingId;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpAccountRow {
    pub id: i64,
    pub hosting_id: HostingId,
    pub login: String,
    pub local_root: String,
    pub label: String,
    pub created_at: i64,
    pub created_by: String,
}

const COLS: &str = "id, hosting_id, login, local_root, label, created_at, created_by";

type Raw = (i64, String, String, String, String, i64, String);

fn row(r: Raw) -> FtpAccountRow {
    FtpAccountRow {
        id: r.0,
        hosting_id: HostingId::from(r.1),
        login: r.2,
        local_root: r.3,
        label: r.4,
        created_at: r.5,
        created_by: r.6,
    }
}

pub async fn insert(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    login: &str,
    local_root: &str,
    label: &str,
    created_by: &str,
    now: i64,
) -> Result<i64, StateError> {
    let r = sqlx::query(
        "INSERT INTO ftp_accounts (hosting_id, login, local_root, label, created_at, created_by) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(hosting_id.as_str())
    .bind(login)
    .bind(local_root)
    .bind(label)
    .bind(now)
    .bind(created_by)
    .execute(pool)
    .await?;
    Ok(r.last_insert_rowid())
}

pub async fn list_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<Vec<FtpAccountRow>, StateError> {
    let rows: Vec<Raw> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM ftp_accounts WHERE hosting_id = ? ORDER BY login"
    ))
    .bind(hosting_id.as_str())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(row).collect())
}

/// Fetch by id AND hosting. Never by id alone: the web layer authorizes a
/// hosting and forwards an id, so a lookup that ignores the hosting is an
/// IDOR waiting to happen — the same shape as the backup ids.
pub async fn get_owned(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    id: i64,
) -> Result<Option<FtpAccountRow>, StateError> {
    let r: Option<Raw> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM ftp_accounts WHERE id = ? AND hosting_id = ?"
    ))
    .bind(id)
    .bind(hosting_id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(r.map(row))
}

pub async fn delete_owned(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    id: i64,
) -> Result<bool, StateError> {
    let r = sqlx::query("DELETE FROM ftp_accounts WHERE id = ? AND hosting_id = ?")
        .bind(id)
        .bind(hosting_id.as_str())
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Every extra login on this node, for the teardown that runs when a hosting
/// is deleted.
pub async fn logins_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<Vec<String>, StateError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT login FROM ftp_accounts WHERE hosting_id = ?")
            .bind(hosting_id.as_str())
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;
    use crate::{hostings, system_users};

    async fn fixture(pool: &SqlitePool, domain: &str, uid: i64) -> HostingId {
        let suid = system_users::insert(pool, &format!("u{uid}"), uid, "/home/u", "/x", 1)
            .await
            .expect("user");
        let id = HostingId::new_v7();
        hostings::insert(pool, &id, domain, suid, None, "/r", 1, None)
            .await
            .expect("hosting");
        id
    }

    /// A lookup by bare id would let a caller authorized for one hosting act
    /// on another's account — the exact shape the backup ids had.
    #[tokio::test]
    async fn accounts_are_only_reachable_through_their_own_hosting() {
        let pool = open_memory().await.expect("open");
        let a = fixture(&pool, "a.cz", 1001).await;
        let b = fixture(&pool, "b.cz", 1002).await;

        let id_b = insert(
            &pool,
            &b,
            "b_deploy",
            "/home/u1002/b.cz/htdocs",
            "",
            "op",
            1,
        )
        .await
        .expect("insert");

        assert!(
            get_owned(&pool, &a, id_b).await.expect("get").is_none(),
            "hosting a could read hosting b's FTP account"
        );
        assert!(
            !delete_owned(&pool, &a, id_b).await.expect("del"),
            "hosting a could delete hosting b's FTP account"
        );
        assert!(get_owned(&pool, &b, id_b).await.expect("get").is_some());
    }

    /// passwd is a node-wide namespace, so two hostings cannot both claim a
    /// login — the second create must fail here rather than at useradd.
    #[tokio::test]
    async fn a_login_is_unique_across_the_node() {
        let pool = open_memory().await.expect("open");
        let a = fixture(&pool, "a.cz", 1001).await;
        let b = fixture(&pool, "b.cz", 1002).await;
        insert(&pool, &a, "shared", "/x", "", "op", 1)
            .await
            .expect("first");
        assert!(
            insert(&pool, &b, "shared", "/y", "", "op", 1)
                .await
                .is_err(),
            "a duplicate login was accepted"
        );
    }

    #[tokio::test]
    async fn deleting_the_hosting_takes_its_accounts() {
        let pool = open_memory().await.expect("open");
        let a = fixture(&pool, "a.cz", 1001).await;
        insert(&pool, &a, "a_deploy", "/x", "", "op", 1)
            .await
            .expect("insert");
        assert_eq!(logins_for_hosting(&pool, &a).await.expect("list").len(), 1);
        sqlx::query("DELETE FROM hostings WHERE id = ?")
            .bind(a.as_str())
            .execute(&pool)
            .await
            .expect("delete hosting");
        assert!(
            logins_for_hosting(&pool, &a)
                .await
                .expect("list")
                .is_empty(),
            "the CASCADE did not fire — orphan rows would resurrect logins"
        );
    }
}
