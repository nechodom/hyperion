//! `certificates` table.

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRow {
    pub id: i64,
    pub domain: String,
    pub issued_at: i64,
    pub not_after: i64,
    pub cert_path: String,
    pub key_path: String,
    pub issuer: String,
}

pub async fn upsert(
    pool: &SqlitePool,
    domain: &str,
    issued_at: i64,
    not_after: i64,
    cert_path: &str,
    key_path: &str,
    issuer: &str,
) -> Result<i64, StateError> {
    // SQLite ON CONFLICT does an upsert
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO certificates (domain, issued_at, not_after, cert_path, key_path, issuer)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(domain) DO UPDATE SET
             issued_at = excluded.issued_at,
             not_after = excluded.not_after,
             cert_path = excluded.cert_path,
             key_path = excluded.key_path,
             issuer = excluded.issuer
           RETURNING id"#,
    )
    .bind(domain)
    .bind(issued_at)
    .bind(not_after)
    .bind(cert_path)
    .bind(key_path)
    .bind(issuer)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get(pool: &SqlitePool, domain: &str) -> Result<Option<CertRow>, StateError> {
    let row: Option<(i64, String, i64, i64, String, String, String)> = sqlx::query_as(
        "SELECT id, domain, issued_at, not_after, cert_path, key_path, issuer
         FROM certificates WHERE domain = ?",
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(id, domain, issued_at, not_after, cert_path, key_path, issuer)| CertRow {
            id,
            domain,
            issued_at,
            not_after,
            cert_path,
            key_path,
            issuer,
        },
    ))
}

pub async fn delete(pool: &SqlitePool, domain: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM certificates WHERE domain = ?")
        .bind(domain)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn find_expiring_within(
    pool: &SqlitePool,
    now: i64,
    horizon_secs: i64,
) -> Result<Vec<CertRow>, StateError> {
    let cutoff = now + horizon_secs;
    let rows: Vec<(i64, String, i64, i64, String, String, String)> = sqlx::query_as(
        "SELECT id, domain, issued_at, not_after, cert_path, key_path, issuer
         FROM certificates WHERE not_after <= ? ORDER BY not_after",
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, domain, issued_at, not_after, cert_path, key_path, issuer)| CertRow {
                id,
                domain,
                issued_at,
                not_after,
                cert_path,
                key_path,
                issuer,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn upsert_inserts_then_updates() {
        let pool = open_memory().await.expect("open");
        let id1 = upsert(
            &pool,
            "example.cz",
            100,
            1000,
            "/c/a.pem",
            "/c/a.key",
            "letsencrypt",
        )
        .await
        .expect("upsert");
        let id2 = upsert(
            &pool,
            "example.cz",
            200,
            2000,
            "/c/a.pem",
            "/c/a.key",
            "letsencrypt",
        )
        .await
        .expect("upsert");
        assert_eq!(id1, id2, "upsert reuses id");
        let got = get(&pool, "example.cz")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.issued_at, 200);
        assert_eq!(got.not_after, 2000);
    }

    #[tokio::test]
    async fn find_expiring_within_horizon() {
        let pool = open_memory().await.expect("open");
        upsert(&pool, "a.cz", 1, 100, "/x", "/y", "letsencrypt")
            .await
            .expect("ok");
        upsert(&pool, "b.cz", 1, 1000, "/x", "/y", "letsencrypt")
            .await
            .expect("ok");
        upsert(&pool, "c.cz", 1, 10_000, "/x", "/y", "letsencrypt")
            .await
            .expect("ok");
        let exp = find_expiring_within(&pool, 0, 500).await.expect("find");
        let domains: Vec<&str> = exp.iter().map(|r| r.domain.as_str()).collect();
        assert_eq!(domains, vec!["a.cz"]);
        let exp = find_expiring_within(&pool, 0, 5000).await.expect("find");
        let domains: Vec<&str> = exp.iter().map(|r| r.domain.as_str()).collect();
        assert_eq!(domains, vec!["a.cz", "b.cz"]);
    }

    #[tokio::test]
    async fn issuer_check_constraint() {
        let pool = open_memory().await.expect("open");
        let r = upsert(&pool, "x.cz", 1, 1, "/a", "/b", "bogus").await;
        assert!(r.is_err());
    }
}
