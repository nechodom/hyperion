//! `databases` table — one row per managed DB attached to a hosting.

use crate::db::StateError;
use lm_types::{DbProvision, HostingId, SecretId};
use sqlx::SqlitePool;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseRow {
    pub id: i64,
    pub hosting_id: HostingId,
    pub engine: DbProvision,
    pub db_name: String,
    pub db_user: String,
    pub secret_id: SecretId,
    pub created_at: i64,
}

pub async fn insert(
    pool: &SqlitePool,
    hosting_id: &HostingId,
    engine: DbProvision,
    db_name: &str,
    db_user: &str,
    secret_id: &SecretId,
    now: i64,
) -> Result<i64, StateError> {
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO databases (hosting_id, engine, db_name, db_user, secret_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?) RETURNING id"#,
    )
    .bind(hosting_id.as_str())
    .bind(engine.as_str())
    .bind(db_name)
    .bind(db_user)
    .bind(secret_id.as_str())
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_for_hosting(
    pool: &SqlitePool,
    hosting_id: &HostingId,
) -> Result<Option<DatabaseRow>, StateError> {
    let row: Option<(i64, String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, hosting_id, engine, db_name, db_user, secret_id, created_at
         FROM databases WHERE hosting_id = ? LIMIT 1",
    )
    .bind(hosting_id.as_str())
    .fetch_optional(pool)
    .await?;
    let Some((id, hosting_id, engine, db_name, db_user, secret_id, created_at)) = row else {
        return Ok(None);
    };
    Ok(Some(DatabaseRow {
        id,
        hosting_id: HostingId(hosting_id),
        engine: DbProvision::from_str(&engine).map_err(StateError::InvalidState)?,
        db_name,
        db_user,
        secret_id: SecretId(secret_id),
        created_at,
    }))
}

pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM databases WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::open_memory, hostings, system_users};

    async fn fixture_hosting(pool: &SqlitePool) -> HostingId {
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
    async fn insert_and_get() {
        let pool = open_memory().await.expect("open");
        let hid = fixture_hosting(&pool).await;
        let sec = SecretId::new();
        insert(
            &pool,
            &hid,
            DbProvision::MariaDB,
            "lm_d",
            "lm_u",
            &sec,
            1,
        )
        .await
        .expect("insert");
        let got = get_for_hosting(&pool, &hid)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.engine, DbProvision::MariaDB);
        assert_eq!(got.db_name, "lm_d");
        assert_eq!(got.secret_id, sec);
    }

    #[tokio::test]
    async fn unique_engine_dbname() {
        let pool = open_memory().await.expect("open");
        let hid = fixture_hosting(&pool).await;
        insert(
            &pool,
            &hid,
            DbProvision::MariaDB,
            "lm_d",
            "lm_u",
            &SecretId::new(),
            1,
        )
        .await
        .expect("first ok");
        // Same (engine, db_name) but different secret should still fail.
        let r = insert(
            &pool,
            &hid,
            DbProvision::MariaDB,
            "lm_d",
            "lm_u2",
            &SecretId::new(),
            2,
        )
        .await;
        assert!(r.is_err(), "duplicate engine+db_name must fail");
    }

    #[tokio::test]
    async fn unique_secret_id() {
        let pool = open_memory().await.expect("open");
        let hid = fixture_hosting(&pool).await;
        let sec = SecretId::new();
        insert(
            &pool,
            &hid,
            DbProvision::MariaDB,
            "a",
            "u",
            &sec,
            1,
        )
        .await
        .expect("ok");
        let r = insert(
            &pool,
            &hid,
            DbProvision::Postgres,
            "b",
            "u",
            &sec,
            2,
        )
        .await;
        assert!(r.is_err(), "duplicate secret_id must fail");
    }
}
