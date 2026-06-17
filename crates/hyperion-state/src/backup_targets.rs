//! Off-site backup destinations — generic S3-compatible storage
//! (Wasabi, B2, Minio, AWS) with operator-supplied credentials
//! and age recipient public key for client-side encryption.
//!
//! The secret_access_key plaintext NEVER lives in this table; the
//! agent stores it under /etc/hyperion/secrets/backup-<id>.key
//! (mode 0600, root) and the row carries only the on-disk path
//! (here represented as `secret_key_id` which the secrets adapter
//! turns into a real path).

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BackupTargetRow {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_key_id: Option<String>,
    pub age_recipient: Option<String>,
    pub retention_daily: i64,
    pub retention_weekly: i64,
    pub retention_monthly: i64,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct UpsertReq<'a> {
    pub id: Option<i64>,
    pub name: &'a str,
    pub kind: &'a str,
    pub endpoint: &'a str,
    pub bucket: &'a str,
    pub region: &'a str,
    pub access_key_id: &'a str,
    pub secret_key_id: Option<&'a str>,
    pub age_recipient: Option<&'a str>,
    pub retention_daily: i64,
    pub retention_weekly: i64,
    pub retention_monthly: i64,
    pub enabled: bool,
    pub now: i64,
}

pub async fn upsert(pool: &SqlitePool, req: UpsertReq<'_>) -> Result<i64, StateError> {
    if let Some(id) = req.id {
        sqlx::query(
            r#"UPDATE backup_targets SET
                  name=?, kind=?, endpoint=?, bucket=?, region=?,
                  access_key_id=?, secret_key_id=?, age_recipient=?,
                  retention_daily=?, retention_weekly=?, retention_monthly=?,
                  enabled=?, updated_at=?
                WHERE id=?"#,
        )
        .bind(req.name)
        .bind(req.kind)
        .bind(req.endpoint)
        .bind(req.bucket)
        .bind(req.region)
        .bind(req.access_key_id)
        .bind(req.secret_key_id)
        .bind(req.age_recipient)
        .bind(req.retention_daily)
        .bind(req.retention_weekly)
        .bind(req.retention_monthly)
        .bind(if req.enabled { 1i64 } else { 0 })
        .bind(req.now)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(id)
    } else {
        let r: (i64,) = sqlx::query_as(
            r#"INSERT INTO backup_targets
                  (name, kind, endpoint, bucket, region,
                   access_key_id, secret_key_id, age_recipient,
                   retention_daily, retention_weekly, retention_monthly,
                   enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id"#,
        )
        .bind(req.name)
        .bind(req.kind)
        .bind(req.endpoint)
        .bind(req.bucket)
        .bind(req.region)
        .bind(req.access_key_id)
        .bind(req.secret_key_id)
        .bind(req.age_recipient)
        .bind(req.retention_daily)
        .bind(req.retention_weekly)
        .bind(req.retention_monthly)
        .bind(if req.enabled { 1i64 } else { 0 })
        .bind(req.now)
        .bind(req.now)
        .fetch_one(pool)
        .await?;
        Ok(r.0)
    }
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<BackupTargetRow>, StateError> {
    let rows: Vec<(
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    )> = sqlx::query_as(
        r#"SELECT id, name, kind, endpoint, bucket, region,
                  access_key_id, secret_key_id, age_recipient,
                  retention_daily, retention_weekly, retention_monthly,
                  enabled, created_at, updated_at
             FROM backup_targets
            ORDER BY name ASC"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, name, kind, endpoint, bucket, region, aki, ski, age, rd, rw, rm, en, ca, ua)| {
                BackupTargetRow {
                    id,
                    name,
                    kind,
                    endpoint,
                    bucket,
                    region,
                    access_key_id: aki,
                    secret_key_id: ski,
                    age_recipient: age,
                    retention_daily: rd,
                    retention_weekly: rw,
                    retention_monthly: rm,
                    enabled: en != 0,
                    created_at: ca,
                    updated_at: ua,
                }
            },
        )
        .collect())
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Option<BackupTargetRow>, StateError> {
    Ok(list(pool).await?.into_iter().find(|r| r.id == id))
}

pub async fn delete(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM backup_targets WHERE id = ?")
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
    async fn upsert_then_list_roundtrip() {
        let p = open_memory().await.expect("open mem");
        let id = upsert(
            &p,
            UpsertReq {
                id: None,
                name: "wasabi-eu",
                kind: "s3",
                endpoint: "https://s3.eu-central-1.wasabisys.com",
                bucket: "hyperion-prod",
                region: "eu-central-1",
                access_key_id: "AKIA-redacted",
                secret_key_id: Some("/etc/hyperion/secrets/backup-wasabi.key"),
                age_recipient: Some("age1xy...stub"),
                retention_daily: 7,
                retention_weekly: 4,
                retention_monthly: 12,
                enabled: true,
                now: 1000,
            },
        )
        .await
        .expect("upsert");

        let rows = list(&p).await.expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert_eq!(rows[0].bucket, "hyperion-prod");
        assert!(rows[0].enabled);

        // Update flips enabled + bumps updated_at.
        upsert(
            &p,
            UpsertReq {
                id: Some(id),
                name: "wasabi-eu",
                kind: "s3",
                endpoint: "https://s3.eu-central-1.wasabisys.com",
                bucket: "hyperion-prod",
                region: "eu-central-1",
                access_key_id: "AKIA-redacted",
                secret_key_id: Some("/etc/hyperion/secrets/backup-wasabi.key"),
                age_recipient: Some("age1xy...stub"),
                retention_daily: 7,
                retention_weekly: 4,
                retention_monthly: 12,
                enabled: false,
                now: 2000,
            },
        )
        .await
        .expect("update");
        let g = get(&p, id).await.expect("get").expect("present");
        assert!(!g.enabled);
        assert_eq!(g.updated_at, 2000);

        delete(&p, id).await.expect("delete");
        assert!(list(&p).await.expect("list").is_empty());
    }
}
