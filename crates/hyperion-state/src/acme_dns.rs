//! acme-dns tables: the delegated zone config, one label per base domain,
//! and the live TXT values the master's responder serves. Present in every
//! agent's DB, used only on the master.

use crate::db::StateError;
use hyperion_types::{AcmeDnsConfig, AcmeDnsLabel};
use sqlx::SqlitePool;
use std::collections::HashMap;

/// `None` until the operator first saves the config. Runtime fields
/// (`listening`, `last_error`) come back empty; the agent fills them.
pub async fn config_get(pool: &SqlitePool) -> Result<Option<AcmeDnsConfig>, StateError> {
    let row: Option<(
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        i64,
        String,
    )> = sqlx::query_as(
        "SELECT zone, ns_host, public_ipv4, public_ipv6, enabled, check_token
             FROM acme_dns_config WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(zone, ns_host, public_ipv4, public_ipv6, enabled, check_token)| AcmeDnsConfig {
            zone,
            ns_host,
            public_ipv4,
            public_ipv6,
            enabled: enabled != 0,
            check_token,
            listening: Vec::new(),
            last_error: None,
        },
    ))
}

pub async fn config_put(pool: &SqlitePool, cfg: &AcmeDnsConfig) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO acme_dns_config
             (id, zone, ns_host, public_ipv4, public_ipv6, enabled, check_token)
           VALUES (1, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             zone = excluded.zone,
             ns_host = excluded.ns_host,
             public_ipv4 = excluded.public_ipv4,
             public_ipv6 = excluded.public_ipv6,
             enabled = excluded.enabled,
             check_token = excluded.check_token"#,
    )
    .bind(&cfg.zone)
    .bind(&cfg.ns_host)
    .bind(&cfg.public_ipv4)
    .bind(&cfg.public_ipv6)
    .bind(cfg.enabled as i64)
    .bind(&cfg.check_token)
    .execute(pool)
    .await?;
    Ok(())
}

type LabelTuple = (
    String,
    String,
    Option<String>,
    i64,
    Option<i64>,
    Option<String>,
);

fn label_from(t: LabelTuple) -> AcmeDnsLabel {
    AcmeDnsLabel {
        base: t.0,
        label: t.1,
        hosting_id: t.2,
        created_at: t.3,
        verified_at: t.4,
        last_check_error: t.5,
    }
}

const LABEL_COLS: &str = "base, label, hosting_id, created_at, verified_at, last_check_error";

fn random_label() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

pub async fn label_get(pool: &SqlitePool, base: &str) -> Result<Option<AcmeDnsLabel>, StateError> {
    let row: Option<LabelTuple> = sqlx::query_as(&format!(
        "SELECT {LABEL_COLS} FROM acme_dns_labels WHERE base = ?"
    ))
    .bind(base)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(label_from))
}

/// The label for `base`, minting one on first use. An existing row keeps
/// its label, `created_at` and verification; a different `Some(hosting_id)`
/// re-points it (Move/Copy gives the base a new hosting id, and the old id
/// is purged later, which must not take the customer's CNAME target with
/// it). `None` never strips an owner.
pub async fn label_ensure(
    pool: &SqlitePool,
    base: &str,
    hosting_id: Option<&str>,
    now: i64,
) -> Result<AcmeDnsLabel, StateError> {
    if let Some(mut existing) = label_get(pool, base).await? {
        if let Some(h) = hosting_id.filter(|h| existing.hosting_id.as_deref() != Some(*h)) {
            sqlx::query("UPDATE acme_dns_labels SET hosting_id = ? WHERE base = ?")
                .bind(h)
                .bind(base)
                .execute(pool)
                .await?;
            existing.hosting_id = Some(h.to_string());
        }
        return Ok(existing);
    }
    // A UNIQUE collision on a random 16-char label is vanishingly unlikely;
    // a base race resolves via OR IGNORE + the re-read below.
    sqlx::query(
        "INSERT OR IGNORE INTO acme_dns_labels (base, label, hosting_id, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(base)
    .bind(random_label())
    .bind(hosting_id)
    .bind(now)
    .execute(pool)
    .await?;
    label_get(pool, base)
        .await?
        .ok_or_else(|| StateError::InvalidState(format!("acme-dns label for {base}")))
}

pub async fn labels_all(pool: &SqlitePool) -> Result<Vec<AcmeDnsLabel>, StateError> {
    let rows: Vec<LabelTuple> = sqlx::query_as(&format!(
        "SELECT {LABEL_COLS} FROM acme_dns_labels ORDER BY base"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(label_from).collect())
}

/// Record a delegation check: ok stamps `verified_at` and clears the error;
/// a failure stores the error and clears `verified_at`.
pub async fn label_mark(
    pool: &SqlitePool,
    base: &str,
    ok: bool,
    error: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    if ok {
        sqlx::query(
            "UPDATE acme_dns_labels SET verified_at = ?, last_check_error = NULL WHERE base = ?",
        )
        .bind(now)
        .bind(base)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE acme_dns_labels SET verified_at = NULL, last_check_error = ? WHERE base = ?",
        )
        .bind(error)
        .bind(base)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn label_delete(pool: &SqlitePool, base: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM acme_dns_labels WHERE base = ?")
        .bind(base)
        .execute(pool)
        .await?;
    Ok(())
}

/// Drop every label owned by a hosting (preview labels, `hosting_id` NULL,
/// are never touched). Returns how many went.
pub async fn labels_delete_for_hosting(
    pool: &SqlitePool,
    hosting_id: &str,
) -> Result<u64, StateError> {
    let r = sqlx::query("DELETE FROM acme_dns_labels WHERE hosting_id = ?")
        .bind(hosting_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

/// Replace the TXT values served for `label` (apex + wildcard need two).
pub async fn values_set(
    pool: &SqlitePool,
    label: &str,
    values: &[String],
    expires_at: i64,
) -> Result<(), StateError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM acme_dns_values WHERE label = ?")
        .bind(label)
        .execute(&mut *tx)
        .await?;
    for v in values {
        sqlx::query("INSERT INTO acme_dns_values (label, value, expires_at) VALUES (?, ?, ?)")
            .bind(label)
            .bind(v)
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn values_clear(pool: &SqlitePool, label: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM acme_dns_values WHERE label = ?")
        .bind(label)
        .execute(pool)
        .await?;
    Ok(())
}

/// Unexpired values per label, each list in insertion order.
pub async fn values_live(
    pool: &SqlitePool,
    now: i64,
) -> Result<HashMap<String, Vec<String>>, StateError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT label, value FROM acme_dns_values WHERE expires_at > ? ORDER BY rowid",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for (label, value) in rows {
        out.entry(label).or_default().push(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn label_ensure_is_idempotent_and_random() {
        let pool = open_memory().await.expect("open");
        let a1 = label_ensure(&pool, "example.com", Some("h1"), 10)
            .await
            .expect("a1");
        let a2 = label_ensure(&pool, "example.com", Some("h1"), 99)
            .await
            .expect("a2");
        let b = label_ensure(&pool, "other.com", None, 10).await.expect("b");
        assert_eq!(a1, a2);
        assert_eq!(a1.created_at, 10, "second call must not re-stamp");
        assert_eq!(a1.hosting_id.as_deref(), Some("h1"));
        assert_ne!(a1.label, b.label);
        for l in [&a1.label, &b.label] {
            assert_eq!(l.len(), 16);
            assert!(l
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        }
        assert_eq!(labels_all(&pool).await.expect("all").len(), 2);
    }

    #[tokio::test]
    async fn label_ensure_repoints_a_moved_base_to_its_new_hosting() {
        let pool = open_memory().await.expect("open");
        let first = label_ensure(&pool, "example.com", Some("h1"), 10)
            .await
            .expect("h1");
        label_mark(&pool, "example.com", true, None, 20)
            .await
            .expect("mark");
        // Move/Copy: the same base now belongs to a new hosting id.
        let moved = label_ensure(&pool, "example.com", Some("h2"), 99)
            .await
            .expect("h2");
        assert_eq!(moved.hosting_id.as_deref(), Some("h2"));
        assert_eq!(moved.label, first.label, "the customer's CNAME must hold");
        assert_eq!(moved.created_at, 10);
        assert_eq!(moved.verified_at, Some(20));
        // Purging the source hosting no longer takes the label with it.
        assert_eq!(
            labels_delete_for_hosting(&pool, "h1").await.expect("del"),
            0
        );
        let left = label_get(&pool, "example.com")
            .await
            .expect("get")
            .expect("survives");
        assert_eq!(left.hosting_id.as_deref(), Some("h2"));
        // A preview-style ensure (no hosting) never strips an owner.
        let again = label_ensure(&pool, "example.com", None, 100)
            .await
            .expect("none");
        assert_eq!(again.hosting_id.as_deref(), Some("h2"));
    }

    #[tokio::test]
    async fn expired_values_are_not_served() {
        let pool = open_memory().await.expect("open");
        values_set(&pool, "lab", &["v".into()], 99)
            .await
            .expect("set");
        assert!(values_live(&pool, 100).await.expect("live").is_empty());
        assert_eq!(
            values_live(&pool, 98).await.expect("live").get("lab"),
            Some(&vec!["v".to_string()])
        );
    }

    #[tokio::test]
    async fn values_set_replaces_and_holds_two_values() {
        let pool = open_memory().await.expect("open");
        values_set(&pool, "lab", &["a".into(), "b".into()], 1000)
            .await
            .expect("set");
        values_set(&pool, "lab", &["c".into(), "d".into()], 1000)
            .await
            .expect("replace");
        values_set(&pool, "other", &["x".into()], 1000)
            .await
            .expect("other");
        let live = values_live(&pool, 0).await.expect("live");
        assert_eq!(live["lab"], vec!["c".to_string(), "d".to_string()]);
        assert_eq!(live["other"], vec!["x".to_string()]);
        values_clear(&pool, "lab").await.expect("clear");
        assert!(!values_live(&pool, 0)
            .await
            .expect("live")
            .contains_key("lab"));
    }

    #[tokio::test]
    async fn labels_delete_for_hosting_leaves_preview_labels() {
        let pool = open_memory().await.expect("open");
        label_ensure(&pool, "a.com", Some("h1"), 1)
            .await
            .expect("a");
        label_ensure(&pool, "b.com", Some("h1"), 1)
            .await
            .expect("b");
        label_ensure(&pool, "c.com", Some("h2"), 1)
            .await
            .expect("c");
        label_ensure(&pool, "preview.com", None, 1)
            .await
            .expect("p");
        assert_eq!(
            labels_delete_for_hosting(&pool, "h1").await.expect("del"),
            2
        );
        let left: Vec<String> = labels_all(&pool)
            .await
            .expect("all")
            .into_iter()
            .map(|l| l.base)
            .collect();
        assert_eq!(left, vec!["c.com", "preview.com"]);
        label_delete(&pool, "c.com").await.expect("delete");
        assert!(label_get(&pool, "c.com").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn config_round_trips() {
        let pool = open_memory().await.expect("open");
        assert!(config_get(&pool).await.expect("get").is_none());
        let cfg = AcmeDnsConfig {
            zone: Some("acme.panel.example".into()),
            ns_host: "ns-acme.panel.example".into(),
            public_ipv4: Some("192.0.2.1".into()),
            public_ipv6: Some("2001:db8::1".into()),
            enabled: true,
            check_token: "t".repeat(32),
            listening: Vec::new(),
            last_error: None,
        };
        config_put(&pool, &cfg).await.expect("put");
        assert_eq!(config_get(&pool).await.expect("get"), Some(cfg.clone()));
        // Runtime fields are not stored.
        let mut with_runtime = cfg.clone();
        with_runtime.listening = vec!["0.0.0.0:53".into()];
        with_runtime.last_error = Some("boom".into());
        with_runtime.enabled = false;
        with_runtime.zone = None;
        with_runtime.public_ipv6 = None;
        config_put(&pool, &with_runtime).await.expect("put2");
        let got = config_get(&pool).await.expect("get").expect("some");
        assert!(got.listening.is_empty() && got.last_error.is_none());
        assert!(!got.enabled && got.zone.is_none() && got.public_ipv6.is_none());
        assert_eq!(got.public_ipv4.as_deref(), Some("192.0.2.1"));
    }

    #[tokio::test]
    async fn label_mark_records_error_then_clears_it() {
        let pool = open_memory().await.expect("open");
        label_ensure(&pool, "a.com", None, 1).await.expect("a");
        label_mark(&pool, "a.com", false, Some("no CNAME"), 50)
            .await
            .expect("fail");
        let l = label_get(&pool, "a.com").await.expect("get").expect("some");
        assert_eq!(l.last_check_error.as_deref(), Some("no CNAME"));
        assert_eq!(l.verified_at, None);
        label_mark(&pool, "a.com", true, None, 60)
            .await
            .expect("ok");
        let l = label_get(&pool, "a.com").await.expect("get").expect("some");
        assert_eq!(l.last_check_error, None);
        assert_eq!(l.verified_at, Some(60));
    }
}
