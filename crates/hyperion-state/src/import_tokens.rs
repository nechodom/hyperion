//! Self-service import tokens: one-time, scoped, expiring bearer tokens that let
//! a source panel box (no Hyperion login) fetch the bootstrap script and push an
//! export bundle to a target node. Only the token **hash** is stored; the
//! plaintext is shown once in the wizard. See the design spec
//! (docs/superpowers/specs/2026-06-28-self-service-import-wizard-design.md).

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ImportTokenRow {
    pub id: i64,
    pub token_hash: String,
    pub target_node: String,
    pub source_kind: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub status: String,
    pub received_bytes: i64,
    pub job_id: Option<String>,
    /// JSON site list the source reported (interactive import). `None` until the
    /// `--list --json` report arrives.
    pub manifest_json: Option<String>,
    /// JSON of the operator's pick (`["*"]` = all, or a list of domains). `None`
    /// until they choose in the panel.
    pub selection_json: Option<String>,
    /// Total bundle size the source declared at `begin`. 0 = not declared (a
    /// token from before resumable uploads, or a source that could not measure),
    /// which the UI must render as "total unknown" — never as 0%.
    pub expected_bytes: i64,
    /// Hex sha256 the source promised for the finished bundle.
    pub bundle_sha256: Option<String>,
    /// When `received_bytes` was last written.
    pub received_at: i64,
    /// The older of the two samples a rate is measured across. A single counter
    /// cannot yield a rate; these two columns are the second observation.
    pub rate_ref_bytes: i64,
    pub rate_ref_at: i64,
    /// What the source last reported about its packing phase (verbatim JSON).
    pub source_progress_json: Option<String>,
    pub source_progress_at: i64,
}

const COLS: &str = "id, token_hash, target_node, source_kind, created_by, created_at, \
                    expires_at, used_at, status, received_bytes, job_id, \
                    manifest_json, selection_json, expected_bytes, bundle_sha256, \
                    received_at, rate_ref_bytes, rate_ref_at, source_progress_json, \
                    source_progress_at";

/// Hard ceiling on a token's life, however many times an upload extends it. A
/// transfer that genuinely needs longer than two days is not a transfer that
/// should be resumed under the same credential.
pub const MAX_TOKEN_LIFETIME_SECS: i64 = 48 * 60 * 60;

/// How far ahead each upload heartbeat pushes the expiry.
pub const EXPIRY_SLIDE_SECS: i64 = 2 * 60 * 60;

/// A rate is only reported once there is enough evidence for one. Below either
/// threshold the UI prints an em dash, not a number: a figure extrapolated from
/// two samples 300 ms apart is noise wearing the costume of a measurement.
pub const RATE_MIN_WINDOW_SECS: i64 = 20;
pub const RATE_MIN_BYTES: i64 = 32 * 1024 * 1024;

/// Mint a token row. `token_hash` is the blake3 hex of the plaintext (minted by
/// the caller). Returns the new row id.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &SqlitePool,
    token_hash: &str,
    target_node: &str,
    source_kind: &str,
    created_by: &str,
    created_at: i64,
    expires_at: i64,
) -> Result<i64, StateError> {
    let id = sqlx::query(
        "INSERT INTO import_tokens \
         (token_hash, target_node, source_kind, created_by, created_at, expires_at, status) \
         VALUES (?, ?, ?, ?, ?, ?, 'pending')",
    )
    .bind(token_hash)
    .bind(target_node)
    .bind(source_kind)
    .bind(created_by)
    .bind(created_at)
    .bind(expires_at)
    .execute(pool)
    .await?
    .last_insert_rowid();
    Ok(id)
}

/// Look up a token by hash if it is still live: pending/receiving/importing AND
/// not expired. Does NOT consume it (the `agent` script GET can be retried; only
/// the legacy `ingest` consumes).
///
/// `importing` is admitted so the source can be told plainly that its bundle
/// already arrived — a commit whose reply was lost otherwise came back as
/// "cancelled". The handlers that must NOT act on a committed transfer check
/// `status` themselves; a query filter is the wrong place for a precondition
/// only some callers have.
pub async fn get_fetchable(
    pool: &SqlitePool,
    token_hash: &str,
    now: i64,
) -> Result<Option<ImportTokenRow>, StateError> {
    let row = sqlx::query_as::<_, ImportTokenRow>(&format!(
        "SELECT {COLS} FROM import_tokens \
         WHERE token_hash = ? AND expires_at > ? \
           AND status IN ('pending', 'receiving', 'importing')",
    ))
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Atomically consume a token for ingest: flips an unused, unexpired, pending
/// token to `receiving` and stamps `used_at`. Returns the row on success, `None`
/// if it was already used / expired / cancelled (single-use guarantee — the
/// UPDATE's WHERE is the lock).
pub async fn consume_for_ingest(
    pool: &SqlitePool,
    token_hash: &str,
    now: i64,
) -> Result<Option<ImportTokenRow>, StateError> {
    let affected = sqlx::query(
        "UPDATE import_tokens SET status = 'receiving', used_at = ? \
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? AND status = 'pending'",
    )
    .bind(now)
    .bind(token_hash)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, ImportTokenRow>(&format!(
        "SELECT {COLS} FROM import_tokens WHERE token_hash = ?",
    ))
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Admit an upload attempt, idempotently.
///
/// This is deliberately NOT `consume_for_ingest`. That one flips `pending →
/// receiving` exactly once and stamps `used_at`, so the SECOND request for a
/// token — which is precisely what a resumed upload is — is refused forever.
/// Here the WHERE admits `receiving` as well, so `begin` can be called again
/// after a dropped connection and answer with the offset to continue from.
/// `used_at` is stamped once via COALESCE, keeping its "first claimed" meaning.
///
/// It stays a lock in the one way that matters: `status = 'importing'` (commit
/// happened, the job is running) and `'done'`/`'failed'`/`'cancelled'` are all
/// excluded, so a bundle can never be re-sent over a completed import.
pub async fn claim_upload(
    pool: &SqlitePool,
    token_hash: &str,
    expected_bytes: i64,
    bundle_sha256: &str,
    now: i64,
) -> Result<Option<ImportTokenRow>, StateError> {
    let affected = sqlx::query(
        "UPDATE import_tokens \
         SET status = 'receiving', used_at = COALESCE(used_at, ?), \
             expected_bytes = ?, bundle_sha256 = ?, received_at = ? \
         WHERE token_hash = ? AND expires_at > ? AND status IN ('pending', 'receiving')",
    )
    .bind(now)
    .bind(expected_bytes)
    .bind(bundle_sha256)
    .bind(now)
    .bind(token_hash)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, ImportTokenRow>(&format!(
        "SELECT {COLS} FROM import_tokens WHERE token_hash = ?",
    ))
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record upload progress and slide the rate reference.
///
/// The reference pair only moves once the current sample is at least
/// `RATE_MIN_WINDOW_SECS` old, so the window a rate is measured over is always
/// wide enough to mean something. Without that the reference would chase the
/// newest sample and every rate would be computed across whatever tiny interval
/// separated the last two chunks.
pub async fn record_upload(
    pool: &SqlitePool,
    id: i64,
    received_bytes: i64,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE import_tokens \
         SET rate_ref_bytes = CASE WHEN ? - rate_ref_at >= ? THEN received_bytes \
                                   ELSE rate_ref_bytes END, \
             rate_ref_at    = CASE WHEN ? - rate_ref_at >= ? THEN received_at \
                                   ELSE rate_ref_at END, \
             received_bytes = ?, received_at = ? \
         WHERE id = ?",
    )
    .bind(now)
    .bind(RATE_MIN_WINDOW_SECS)
    .bind(now)
    .bind(RATE_MIN_WINDOW_SECS)
    .bind(received_bytes)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    touch_expiry(pool, id, now).await
}

/// Push the expiry out while a transfer is actually moving, capped absolutely.
///
/// A 30 GB pack-and-upload can easily outlive the 4 h mint TTL, and today that
/// turns a working transfer into a 403 halfway through. Extending on evidence of
/// progress is safe; extending forever is not, so the new expiry is the smaller
/// of `now + 2 h` and `created_at + 48 h`.
pub async fn touch_expiry(pool: &SqlitePool, id: i64, now: i64) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE import_tokens \
         SET expires_at = MIN(created_at + ?, ?) \
         WHERE id = ? AND expires_at < MIN(created_at + ?, ?)",
    )
    .bind(MAX_TOKEN_LIFETIME_SECS)
    .bind(now + EXPIRY_SLIDE_SECS)
    .bind(id)
    .bind(MAX_TOKEN_LIFETIME_SECS)
    .bind(now + EXPIRY_SLIDE_SECS)
    .execute(pool)
    .await?;
    Ok(())
}

/// Store what the source says about its packing phase, verbatim.
pub async fn set_source_progress(
    pool: &SqlitePool,
    token_hash: &str,
    progress_json: &str,
    now: i64,
) -> Result<bool, StateError> {
    let n = sqlx::query(
        "UPDATE import_tokens SET source_progress_json = ?, source_progress_at = ? \
         WHERE token_hash = ? AND expires_at > ? \
           AND status IN ('pending', 'receiving')",
    )
    .bind(progress_json)
    .bind(now)
    .bind(token_hash)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Bytes per second across the stored sample pair, or `None` when the evidence
/// is too thin to justify a figure.
///
/// The caller must render `None` as an em dash. Every branch that returns `None`
/// is a case where a number would be a guess: no second sample, a window shorter
/// than 20 s, fewer than 32 MiB moved, or a clock that stepped backwards (ntp
/// correcting mid-transfer, which would otherwise produce a wild rate).
pub fn rate_bytes_per_sec(row: &ImportTokenRow) -> Option<i64> {
    if row.rate_ref_at <= 0 || row.received_at <= 0 {
        return None;
    }
    let dt = row.received_at - row.rate_ref_at;
    let db = row.received_bytes - row.rate_ref_bytes;
    if dt < RATE_MIN_WINDOW_SECS || db < RATE_MIN_BYTES {
        return None;
    }
    Some(db / dt)
}

/// Update progress / lifecycle. `status` ∈ receiving|importing|done|failed.
pub async fn set_status(pool: &SqlitePool, id: i64, status: &str) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET status = ? WHERE id = ?")
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record the spawned import job id against the token (so the wizard can link to
/// `/jobs/<id>`).
pub async fn set_job(pool: &SqlitePool, id: i64, job_id: &str) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET job_id = ?, status = 'importing' WHERE id = ?")
        .bind(job_id)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Bump the running byte counter as the bundle streams in (for the progress UI).
pub async fn set_received_bytes(pool: &SqlitePool, id: i64, bytes: i64) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET received_bytes = ? WHERE id = ?")
        .bind(bytes)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record the site list the source reported (interactive import), while the
/// token is still pending + unexpired. Returns `true` if a row was updated.
pub async fn set_manifest(
    pool: &SqlitePool,
    token_hash: &str,
    manifest_json: &str,
    now: i64,
) -> Result<bool, StateError> {
    // `selection_json IS NULL` freezes the manifest once the operator has picked,
    // so a late/replayed report can't swap the list out from under their choice.
    let n = sqlx::query(
        "UPDATE import_tokens SET manifest_json = ? \
         WHERE token_hash = ? AND status = 'pending' AND expires_at > ? \
           AND selection_json IS NULL",
    )
    .bind(manifest_json)
    .bind(token_hash)
    .bind(now)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Record the operator's site selection (JSON; `["*"]` = all). Does NOT touch
/// `status`, so the single-use ingest guard stays intact.
pub async fn set_selection(
    pool: &SqlitePool,
    id: i64,
    selection_json: &str,
) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET selection_json = ? WHERE id = ?")
        .bind(selection_json)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Revoke a token (wizard "cancel"). Idempotent.
pub async fn cancel(pool: &SqlitePool, id: i64) -> Result<(), StateError> {
    sqlx::query("UPDATE import_tokens SET status = 'cancelled' WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Active tokens (pending/receiving/importing, unexpired) — for the wizard's
/// "in-flight transfers" list.
pub async fn list_active(pool: &SqlitePool, now: i64) -> Result<Vec<ImportTokenRow>, StateError> {
    let rows = sqlx::query_as::<_, ImportTokenRow>(&format!(
        "SELECT {COLS} FROM import_tokens \
         WHERE status IN ('pending', 'receiving', 'importing') AND expires_at > ? \
         ORDER BY created_at DESC",
    ))
    .bind(now)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Best-effort GC of expired/finished rows older than `cutoff`.
pub async fn cleanup(pool: &SqlitePool, cutoff: i64) -> Result<u64, StateError> {
    let n = sqlx::query(
        "DELETE FROM import_tokens \
         WHERE expires_at < ? OR status IN ('done', 'failed', 'cancelled')",
    )
    .bind(cutoff)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem() -> SqlitePool {
        let pool = crate::open(std::path::Path::new(":memory:")).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn consume_is_single_use() {
        let pool = mem().await;
        create(&pool, "h1", "local", "cloudpanel", "admin", 100, 1_000)
            .await
            .unwrap();
        // first consume wins
        let r = consume_for_ingest(&pool, "h1", 200).await.unwrap();
        assert!(r.is_some());
        // second consume is refused (already used)
        let r2 = consume_for_ingest(&pool, "h1", 200).await.unwrap();
        assert!(r2.is_none());
    }

    /// The whole point of `claim_upload`: a resumed upload calls `begin` again,
    /// and that second call must succeed. `consume_for_ingest` cannot do this —
    /// it is asserted alongside so the difference stays visible.
    #[tokio::test]
    async fn claim_upload_is_idempotent_where_consume_is_not() {
        let pool = mem().await;
        create(&pool, "r1", "local", "cloudpanel", "admin", 100, 100_000)
            .await
            .unwrap();
        let first = claim_upload(&pool, "r1", 5_000, "abc", 200).await.unwrap();
        assert!(first.is_some(), "first claim must be admitted");
        assert_eq!(first.as_ref().unwrap().status, "receiving");
        assert_eq!(first.as_ref().unwrap().used_at, Some(200));

        // The resume. Same token, now in `receiving`.
        let second = claim_upload(&pool, "r1", 5_000, "abc", 300).await.unwrap();
        assert!(second.is_some(), "a resumed upload must be re-admitted");
        // used_at keeps its "first claimed" meaning.
        assert_eq!(second.unwrap().used_at, Some(200));

        // The old single-use claim would have refused that second attempt.
        assert!(
            consume_for_ingest(&pool, "r1", 300)
                .await
                .unwrap()
                .is_none(),
            "consume_for_ingest must stay single-use for the legacy path"
        );
    }

    /// Once commit has spawned the import job the bundle must never be
    /// re-sent — otherwise a stale runner could overwrite a bundle mid-import.
    #[tokio::test]
    async fn claim_upload_is_refused_once_importing() {
        let pool = mem().await;
        let id = create(&pool, "r2", "local", "cloudpanel", "admin", 100, 100_000)
            .await
            .unwrap();
        claim_upload(&pool, "r2", 10, "d", 200).await.unwrap();
        set_job(&pool, id, "job-1").await.unwrap();
        assert!(claim_upload(&pool, "r2", 10, "d", 300)
            .await
            .unwrap()
            .is_none());
        // ...and a cancelled token likewise.
        create(&pool, "r3", "local", "cloudpanel", "admin", 100, 100_000)
            .await
            .unwrap();
        let id3 = get_fetchable(&pool, "r3", 200).await.unwrap().unwrap().id;
        cancel(&pool, id3).await.unwrap();
        assert!(claim_upload(&pool, "r3", 10, "d", 300)
            .await
            .unwrap()
            .is_none());
    }

    /// A long transfer must not be killed by its own mint TTL, and must not get
    /// an unbounded lease either.
    #[tokio::test]
    async fn expiry_slides_while_moving_but_never_past_the_hard_cap() {
        let pool = mem().await;
        let created = 1_000;
        let id = create(
            &pool,
            "r4",
            "local",
            "cloudpanel",
            "admin",
            created,
            created + 600,
        )
        .await
        .unwrap();
        touch_expiry(&pool, id, created + 500).await.unwrap();
        let row = get_fetchable(&pool, "r4", created + 500)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.expires_at,
            created + 500 + EXPIRY_SLIDE_SECS,
            "a moving upload should get another two hours"
        );

        // Far in the future the cap binds instead of the slide.
        touch_expiry(&pool, id, created + MAX_TOKEN_LIFETIME_SECS)
            .await
            .unwrap();
        let row = sqlx::query_as::<_, ImportTokenRow>(&format!(
            "SELECT {COLS} FROM import_tokens WHERE id = ?"
        ))
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row.expires_at,
            created + MAX_TOKEN_LIFETIME_SECS,
            "expiry must never exceed created_at + 48h"
        );
    }

    /// Every `None` branch here is a case where printing a number would be
    /// inventing one.
    #[tokio::test]
    async fn a_rate_is_only_reported_with_enough_evidence() {
        let pool = mem().await;
        let id = create(&pool, "r5", "local", "cloudpanel", "admin", 0, 100_000)
            .await
            .unwrap();
        claim_upload(&pool, "r5", 1_000_000_000, "x", 100)
            .await
            .unwrap();

        let row_at = |pool: SqlitePool, id: i64| async move {
            sqlx::query_as::<_, ImportTokenRow>(&format!(
                "SELECT {COLS} FROM import_tokens WHERE id = ?"
            ))
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        };

        // One sample: no window at all.
        record_upload(&pool, id, RATE_MIN_BYTES * 4, 105)
            .await
            .unwrap();
        assert_eq!(rate_bytes_per_sec(&row_at(pool.clone(), id).await), None);

        // Second sample, but only 5 s later — below the window floor.
        record_upload(&pool, id, RATE_MIN_BYTES * 8, 110)
            .await
            .unwrap();
        assert_eq!(
            rate_bytes_per_sec(&row_at(pool.clone(), id).await),
            None,
            "a 5s window must not produce a figure"
        );

        // A wide enough window that moved enough bytes: now a rate is honest.
        record_upload(&pool, id, RATE_MIN_BYTES * 8, 200)
            .await
            .unwrap();
        record_upload(&pool, id, RATE_MIN_BYTES * 24, 260)
            .await
            .unwrap();
        let r = rate_bytes_per_sec(&row_at(pool.clone(), id).await);
        assert!(r.is_some(), "a 60s window moving 512 MiB is measurable");
        assert!(r.unwrap() > 0);
    }

    /// A backwards clock step must not render as a wild rate.
    #[test]
    fn a_backwards_clock_yields_no_rate() {
        let row = ImportTokenRow {
            id: 1,
            token_hash: "h".into(),
            target_node: "local".into(),
            source_kind: "cloudpanel".into(),
            created_by: "admin".into(),
            created_at: 0,
            expires_at: 0,
            used_at: None,
            status: "receiving".into(),
            received_bytes: RATE_MIN_BYTES * 4,
            job_id: None,
            manifest_json: None,
            selection_json: None,
            expected_bytes: 0,
            bundle_sha256: None,
            // received_at BEFORE the reference: the clock stepped back.
            received_at: 100,
            rate_ref_bytes: 0,
            rate_ref_at: 500,
            source_progress_json: None,
            source_progress_at: 0,
        };
        assert_eq!(rate_bytes_per_sec(&row), None);
    }

    #[tokio::test]
    async fn expired_token_not_fetchable_or_consumable() {
        let pool = mem().await;
        create(&pool, "h2", "local", "cloudpanel", "admin", 100, 1_000)
            .await
            .unwrap();
        // now (2000) is past expires_at (1000)
        assert!(get_fetchable(&pool, "h2", 2_000).await.unwrap().is_none());
        assert!(consume_for_ingest(&pool, "h2", 2_000)
            .await
            .unwrap()
            .is_none());
    }
}
