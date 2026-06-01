//! `node_invites` table — one-time enrollment tokens.
//!
//! Plaintext tokens are NEVER persisted. The caller mints a random token,
//! stores `BLAKE3(token)` in the DB, and shows the plaintext to the
//! operator exactly once.

use crate::db::StateError;
use sqlx::SqlitePool;

const TOKEN_BYTES: usize = 24; // 192 bits → 39-char base32

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRow {
    pub token_hash: String,
    pub label: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub consumed_at: Option<i64>,
    pub consumed_by_ip: Option<String>,
    pub consumed_by_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewInvite {
    /// Plaintext token. Shown to the operator once, never persisted.
    pub token: String,
    pub token_hash: String,
    pub label: String,
    pub expires_at: i64,
}

/// Mint a fresh token + return the plaintext + hash. Hash is what gets
/// stored on disk.
pub fn mint(label: &str, ttl_secs: i64, now: i64) -> NewInvite {
    use rand::RngCore;
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = format_token(&bytes);
    let token_hash = hex::encode(blake3::hash(token.as_bytes()).as_bytes());
    NewInvite {
        token,
        token_hash,
        label: label.to_string(),
        expires_at: now + ttl_secs,
    }
}

fn format_token(bytes: &[u8]) -> String {
    // Crockford-style base16 (each byte = 2 chars). Avoids ambiguous
    // chars (no 0/O/1/I/L). 24 bytes → 48 chars; we tack a '-' every
    // 2 bytes so it's easy to read aloud.
    const ALPHA: &[u8] = b"ABCDEFGHJKMNPQRS";
    let mut out = String::with_capacity(60);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push('-');
        }
        let hi = (b >> 4) as usize;
        let lo = (b & 0x0f) as usize;
        out.push(ALPHA[hi] as char);
        out.push(ALPHA[lo] as char);
    }
    out
}

pub fn hash_token(token: &str) -> String {
    hex::encode(blake3::hash(token.as_bytes()).as_bytes())
}

pub async fn insert(pool: &SqlitePool, n: &NewInvite, now: i64) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO node_invites (token_hash, label, expires_at, created_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(&n.token_hash)
    .bind(&n.label)
    .bind(n.expires_at)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_pending(
    pool: &SqlitePool,
    now: i64,
    limit: i64,
) -> Result<Vec<InviteRow>, StateError> {
    let rows: Vec<(
        String,
        String,
        i64,
        i64,
        Option<i64>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT token_hash, label, expires_at, created_at, consumed_at,
                    consumed_by_ip, consumed_by_id
             FROM node_invites
             WHERE consumed_at IS NULL AND expires_at > ?
             ORDER BY created_at DESC LIMIT ?",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                token_hash,
                label,
                expires_at,
                created_at,
                consumed_at,
                consumed_by_ip,
                consumed_by_id,
            )| {
                InviteRow {
                    token_hash,
                    label,
                    expires_at,
                    created_at,
                    consumed_at,
                    consumed_by_ip,
                    consumed_by_id,
                }
            },
        )
        .collect())
}

pub async fn consume(
    pool: &SqlitePool,
    token: &str,
    caller_ip: &str,
    new_agent_id: &str,
    now: i64,
) -> Result<bool, StateError> {
    let hash = hash_token(token);
    let res = sqlx::query(
        "UPDATE node_invites
         SET consumed_at = ?, consumed_by_ip = ?, consumed_by_id = ?
         WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?",
    )
    .bind(now)
    .bind(caller_ip)
    .bind(new_agent_id)
    .bind(&hash)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn revoke(pool: &SqlitePool, token_hash: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM node_invites WHERE token_hash = ? AND consumed_at IS NULL")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[test]
    fn mint_produces_unique_tokens() {
        let mut set = std::collections::HashSet::new();
        for _ in 0..1000 {
            let n = mint("node", 3600, 100);
            assert!(set.insert(n.token));
        }
    }

    #[test]
    fn token_format_is_groups_of_2_separated_by_dash() {
        let n = mint("node", 3600, 100);
        assert!(n.token.contains('-'));
        for ch in n.token.chars() {
            assert!(ch.is_ascii_alphanumeric() || ch == '-');
            // No ambiguous chars
            assert!(!matches!(ch, 'O' | 'I' | 'L' | '0' | '1'));
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let a = hash_token("ABCD-EFGH");
        let b = hash_token("ABCD-EFGH");
        let c = hash_token("ABCD-EFGI");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[tokio::test]
    async fn insert_and_list_pending() {
        let pool = open_memory().await.expect("open");
        let n = mint("node-1", 3600, 100);
        insert(&pool, &n, 100).await.expect("insert");
        let pending = list_pending(&pool, 200, 10).await.expect("list");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].label, "node-1");
    }

    #[tokio::test]
    async fn expired_invites_not_listed() {
        let pool = open_memory().await.expect("open");
        let n = mint("node-1", 3600, 100);
        insert(&pool, &n, 100).await.expect("insert");
        // now = 100 + 3600 + 1 is past expiry
        let pending = list_pending(&pool, 100 + 3601, 10).await.expect("list");
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn consume_marks_used_and_refuses_second_consume() {
        let pool = open_memory().await.expect("open");
        let n = mint("node-1", 3600, 100);
        let token = n.token.clone();
        insert(&pool, &n, 100).await.expect("insert");
        let ok1 = consume(&pool, &token, "1.2.3.4", "agent-A", 150)
            .await
            .expect("first");
        assert!(ok1);
        // Second consume must fail.
        let ok2 = consume(&pool, &token, "5.6.7.8", "agent-B", 160)
            .await
            .expect("second");
        assert!(!ok2);
        // And list_pending no longer shows it.
        let pending = list_pending(&pool, 200, 10).await.expect("list");
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn consume_refuses_wrong_token() {
        let pool = open_memory().await.expect("open");
        let n = mint("node-1", 3600, 100);
        insert(&pool, &n, 100).await.expect("insert");
        let ok = consume(&pool, "WRONG-TOKEN", "1.2.3.4", "agent-A", 150)
            .await
            .expect("consume");
        assert!(!ok);
    }

    #[tokio::test]
    async fn consume_refuses_expired() {
        let pool = open_memory().await.expect("open");
        let n = mint("node-1", 3600, 100);
        let token = n.token.clone();
        insert(&pool, &n, 100).await.expect("insert");
        let ok = consume(&pool, &token, "1.2.3.4", "agent-A", 100 + 3601)
            .await
            .expect("consume");
        assert!(!ok);
    }

    #[tokio::test]
    async fn revoke_removes_pending() {
        let pool = open_memory().await.expect("open");
        let n = mint("node-1", 3600, 100);
        let hash = n.token_hash.clone();
        insert(&pool, &n, 100).await.expect("insert");
        revoke(&pool, &hash).await.expect("revoke");
        let pending = list_pending(&pool, 200, 10).await.expect("list");
        assert!(pending.is_empty());
    }
}
