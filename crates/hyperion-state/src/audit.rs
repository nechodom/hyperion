//! Tamper-evident audit log.
//!
//! Each row's `row_hash = BLAKE3(prev_hash || canonical_fields)`.
//! `prev_hash` for row 1 is the all-zero hash. `verify_chain` rejects any
//! mutation of historical rows.

use crate::db::StateError;
use sqlx::SqlitePool;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: i64,
    pub actor_uid: i64,
    pub actor_label: String,
    pub action: String,
    pub target: Option<String>,
    pub payload_json: String,
    pub result: String,
    pub prev_hash: String,
    pub row_hash: String,
}

#[derive(Debug, Clone)]
pub struct AppendReq<'a> {
    pub ts: i64,
    pub actor_uid: i64,
    pub actor_label: &'a str,
    pub action: &'a str,
    pub target: Option<&'a str>,
    pub payload_json: &'a str,
    pub result: &'a str,
}

/// Append one entry. Reads the previous row_hash inside the same connection,
/// computes the new row_hash, and inserts. Acquires a transaction for atomicity.
pub async fn append(pool: &SqlitePool, req: AppendReq<'_>) -> Result<i64, StateError> {
    let mut tx = pool.begin().await?;
    let prev: Option<(String,)> =
        sqlx::query_as("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let prev_hash = prev
        .map(|(h,)| h)
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    let row_hash = compute_row_hash(
        &prev_hash,
        req.ts,
        req.actor_uid,
        req.actor_label,
        req.action,
        req.target,
        req.payload_json,
        req.result,
    );
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO audit_log
           (ts, actor_uid, actor_label, action, target, payload_json, result, prev_hash, row_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING id"#,
    )
    .bind(req.ts)
    .bind(req.actor_uid)
    .bind(req.actor_label)
    .bind(req.action)
    .bind(req.target)
    .bind(req.payload_json)
    .bind(req.result)
    .bind(&prev_hash)
    .bind(&row_hash)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.0)
}

/// Verify the entire chain. Returns AuditChain on first mismatch.
/// Anchor — present iff a retention sweep has previously truncated
/// the head of the chain. When present, verify_chain starts with
/// `expected_prev = anchor_hash` instead of GENESIS_HASH; this is
/// the hash that the now-oldest row's `prev_hash` points to.
///
/// Single-row pattern (CHECK id=1). `None` = chain has never been
/// truncated, verify starts at GENESIS_HASH as before.
pub async fn get_anchor(pool: &SqlitePool) -> Result<Option<AuditAnchor>, StateError> {
    let row: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT anchor_hash, last_purged_id, last_purge_ts FROM audit_chain_anchor WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(h, lid, lts)| AuditAnchor {
        anchor_hash: h,
        last_purged_id: lid,
        last_purge_ts: lts,
    }))
}

#[derive(Debug, Clone)]
pub struct AuditAnchor {
    pub anchor_hash: String,
    pub last_purged_id: i64,
    pub last_purge_ts: i64,
}

/// Delete audit rows older than `cutoff_ts` and update the anchor so
/// `verify_chain` keeps working on the truncated chain.
///
/// Returns `(deleted_count, new_anchor)`. `new_anchor` is `None` when
/// every row was deleted (next append starts a brand-new chain from
/// GENESIS_HASH) or when there was nothing to delete.
///
/// Atomicity: anchor update + delete run in one transaction so a
/// crash mid-sweep can't leave the chain unverifiable.
pub async fn purge_older_than(
    pool: &SqlitePool,
    cutoff_ts: i64,
    now_ts: i64,
) -> Result<(i64, Option<String>), StateError> {
    let mut tx = pool.begin().await?;
    // The oldest surviving row's `prev_hash` is what verify_chain
    // needs to seed its expected_prev with. Capture BEFORE deleting
    // so we don't have to re-query.
    let survivor: Option<(String,)> =
        sqlx::query_as("SELECT prev_hash FROM audit_log WHERE ts >= ? ORDER BY id ASC LIMIT 1")
            .bind(cutoff_ts)
            .fetch_optional(&mut *tx)
            .await?;
    // Highest id we're about to delete — purely informational, for
    // the anchor row + operator forensics.
    let last_purged: Option<i64> = sqlx::query_as("SELECT MAX(id) FROM audit_log WHERE ts < ?")
        .bind(cutoff_ts)
        .fetch_optional(&mut *tx)
        .await?
        .and_then(|(v,): (Option<i64>,)| v);
    let deleted = sqlx::query("DELETE FROM audit_log WHERE ts < ?")
        .bind(cutoff_ts)
        .execute(&mut *tx)
        .await?
        .rows_affected() as i64;
    if deleted == 0 {
        tx.commit().await?;
        return Ok((0, None));
    }
    if let Some((anchor_hash,)) = survivor {
        sqlx::query(
            "INSERT INTO audit_chain_anchor (id, anchor_hash, last_purged_id, last_purge_ts)
             VALUES (1, ?, ?, ?)
             ON CONFLICT (id) DO UPDATE SET
                 anchor_hash = excluded.anchor_hash,
                 last_purged_id = excluded.last_purged_id,
                 last_purge_ts = excluded.last_purge_ts",
        )
        .bind(&anchor_hash)
        .bind(last_purged.unwrap_or(0))
        .bind(now_ts)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((deleted, Some(anchor_hash)))
    } else {
        // Every row deleted (very aggressive retention or empty
        // post-cutoff window). Clear the anchor so the next append
        // starts a fresh chain from GENESIS_HASH.
        sqlx::query("DELETE FROM audit_chain_anchor WHERE id = 1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok((deleted, None))
    }
}

pub async fn verify_chain(pool: &SqlitePool) -> Result<(), StateError> {
    let rows: Vec<(
        i64,
        i64,
        i64,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT id, ts, actor_uid, actor_label, action, target, payload_json, result, prev_hash, row_hash
         FROM audit_log ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    // If a retention sweep has truncated the head of the chain,
    // start with the anchor's recorded hash instead of GENESIS.
    let mut expected_prev = match get_anchor(pool).await? {
        Some(a) => a.anchor_hash,
        None => GENESIS_HASH.to_string(),
    };
    for (
        id,
        ts,
        actor_uid,
        actor_label,
        action,
        target,
        payload_json,
        result,
        prev_hash,
        row_hash,
    ) in rows
    {
        if prev_hash != expected_prev {
            return Err(StateError::AuditChain {
                row: id,
                expected: expected_prev,
                got: prev_hash,
            });
        }
        let recomputed = compute_row_hash(
            &prev_hash,
            ts,
            actor_uid,
            &actor_label,
            &action,
            target.as_deref(),
            &payload_json,
            &result,
        );
        if recomputed != row_hash {
            return Err(StateError::AuditChain {
                row: id,
                expected: recomputed,
                got: row_hash,
            });
        }
        expected_prev = row_hash;
    }
    Ok(())
}

pub async fn list(pool: &SqlitePool, limit: i64) -> Result<Vec<AuditEntry>, StateError> {
    let rows: Vec<(
        i64,
        i64,
        i64,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
    )> = sqlx::query_as(
        "SELECT id, ts, actor_uid, actor_label, action, target, payload_json, result, prev_hash, row_hash
         FROM audit_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                ts,
                actor_uid,
                actor_label,
                action,
                target,
                payload_json,
                result,
                prev_hash,
                row_hash,
            )| AuditEntry {
                id,
                ts,
                actor_uid,
                actor_label,
                action,
                target,
                payload_json,
                result,
                prev_hash,
                row_hash,
            },
        )
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn compute_row_hash(
    prev_hash: &str,
    ts: i64,
    actor_uid: i64,
    actor_label: &str,
    action: &str,
    target: Option<&str>,
    payload_json: &str,
    result: &str,
) -> String {
    let mut h = blake3::Hasher::new();
    h.update(prev_hash.as_bytes());
    h.update(b"|");
    h.update(ts.to_be_bytes().as_ref());
    h.update(b"|");
    h.update(actor_uid.to_be_bytes().as_ref());
    h.update(b"|");
    h.update(actor_label.as_bytes());
    h.update(b"|");
    h.update(action.as_bytes());
    h.update(b"|");
    h.update(target.unwrap_or("").as_bytes());
    h.update(b"|");
    h.update(payload_json.as_bytes());
    h.update(b"|");
    h.update(result.as_bytes());
    hex::encode(h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    fn req<'a>(action: &'a str) -> AppendReq<'a> {
        AppendReq {
            ts: 100,
            actor_uid: 0,
            actor_label: "cli:root",
            action,
            target: None,
            payload_json: "{}",
            result: "ok",
        }
    }

    #[tokio::test]
    async fn append_chains_correctly() {
        let pool = open_memory().await.expect("open");
        append(&pool, req("a.create")).await.expect("a");
        append(&pool, req("b.create")).await.expect("b");
        append(&pool, req("c.create")).await.expect("c");
        verify_chain(&pool).await.expect("chain valid");
    }

    #[tokio::test]
    async fn first_entry_uses_genesis() {
        let pool = open_memory().await.expect("open");
        append(&pool, req("first")).await.expect("ok");
        let row: (String,) = sqlx::query_as("SELECT prev_hash FROM audit_log ORDER BY id LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("query");
        assert_eq!(row.0, GENESIS_HASH);
    }

    #[tokio::test]
    async fn verify_detects_payload_tampering() {
        let pool = open_memory().await.expect("open");
        append(&pool, req("a.create")).await.expect("a");
        append(&pool, req("b.create")).await.expect("b");
        // Tamper with row 1's payload, leaving the hash alone.
        sqlx::query("UPDATE audit_log SET payload_json = '{\"evil\":true}' WHERE id = 1")
            .execute(&pool)
            .await
            .expect("tamper");
        let err = verify_chain(&pool).await.unwrap_err();
        match err {
            StateError::AuditChain { row, .. } => assert_eq!(row, 1),
            other => panic!("wrong err: {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_detects_prev_hash_tampering() {
        let pool = open_memory().await.expect("open");
        append(&pool, req("a.create")).await.expect("a");
        append(&pool, req("b.create")).await.expect("b");
        sqlx::query("UPDATE audit_log SET prev_hash = ? WHERE id = 2")
            .bind(GENESIS_HASH)
            .execute(&pool)
            .await
            .expect("tamper");
        let err = verify_chain(&pool).await.unwrap_err();
        match err {
            StateError::AuditChain { row, .. } => assert_eq!(row, 2),
            other => panic!("wrong err: {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_returns_descending() {
        let pool = open_memory().await.expect("open");
        append(&pool, req("a")).await.expect("a");
        append(&pool, req("b")).await.expect("b");
        append(&pool, req("c")).await.expect("c");
        let rows = list(&pool, 10).await.expect("list");
        let actions: Vec<&str> = rows.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(actions, vec!["c", "b", "a"]);
    }

    #[tokio::test]
    async fn empty_chain_is_valid() {
        let pool = open_memory().await.expect("open");
        verify_chain(&pool).await.expect("empty is valid");
    }
}
