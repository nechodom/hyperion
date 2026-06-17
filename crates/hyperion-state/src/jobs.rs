//! Generic long-running job tracker.
//!
//! Every multi-second operation (migration, install, backup,
//! ACME issue, node update, …) creates a row here. The web UI
//! polls `read(id)` every 2 seconds and renders the live
//! progress card; `hctl` reads the same row for CLI status.
//!
//! Service layer drives this via the `Service::job_*` family
//! (in hyperion-core) which wraps these primitives with a
//! drop-guard so an aborted task can't leave a job stuck in
//! `running` forever.

use crate::db::StateError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRow {
    pub id: String,
    pub kind: String,
    pub target: Option<String>,
    pub state: String,
    pub step_label: String,
    pub progress_pct: i64,
    pub log_tail: String,
    pub error: Option<String>,
    pub payload_json: String,
    pub actor_uid: i64,
    pub actor_label: String,
    pub started_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StartReq<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub target: Option<&'a str>,
    pub payload_json: &'a str,
    pub actor_uid: i64,
    pub actor_label: &'a str,
    pub started_at: i64,
}

/// Insert a row in `running` state with progress=0. Service layer
/// generates the ULID `id` ahead of time so the caller can use it
/// immediately even before this query commits (race-free vs. the
/// HTMX-polled status endpoint).
pub async fn start(pool: &SqlitePool, req: StartReq<'_>) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO jobs
            (id, kind, target, state, step_label, progress_pct,
             log_tail, error, payload_json,
             actor_uid, actor_label,
             started_at, updated_at, finished_at)
           VALUES (?, ?, ?, 'running', '', 0,
                   '', NULL, ?,
                   ?, ?,
                   ?, ?, NULL)"#,
    )
    .bind(req.id)
    .bind(req.kind)
    .bind(req.target)
    .bind(req.payload_json)
    .bind(req.actor_uid)
    .bind(req.actor_label)
    .bind(req.started_at)
    .bind(req.started_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update the step label, progress (0-100) and append to the bounded
/// log_tail. We cap `log_tail` at ~16 KiB by truncating from the
/// front — keeps the tail relevant, avoids unbounded growth.
pub async fn progress(
    pool: &SqlitePool,
    id: &str,
    step_label: &str,
    pct: i64,
    log_append: &str,
    now: i64,
) -> Result<(), StateError> {
    const TAIL_CAP: usize = 16 * 1024;
    // Read current tail to know whether to truncate after appending.
    // One round-trip is OK here — progress is called at coarse step
    // boundaries, not per byte.
    let (cur_tail,): (String,) = sqlx::query_as("SELECT log_tail FROM jobs WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    let mut new_tail = if log_append.is_empty() {
        cur_tail
    } else {
        let mut s = cur_tail;
        s.push_str(log_append);
        if !log_append.ends_with('\n') {
            s.push('\n');
        }
        s
    };
    if new_tail.len() > TAIL_CAP {
        // Drop from the front. char_indices to keep UTF-8 valid;
        // truncating raw bytes mid-codepoint would panic on render.
        let cut = new_tail
            .char_indices()
            .find(|(i, _)| *i >= new_tail.len() - TAIL_CAP)
            .map(|(i, _)| i)
            .unwrap_or(0);
        new_tail = new_tail.split_at(cut).1.to_string();
    }
    let pct_clamped = pct.clamp(0, 100);
    sqlx::query(
        r#"UPDATE jobs
              SET step_label = ?,
                  progress_pct = ?,
                  log_tail = ?,
                  updated_at = ?
            WHERE id = ?
              AND state = 'running'"#,
    )
    .bind(step_label)
    .bind(pct_clamped)
    .bind(&new_tail)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Flip to a terminal state. No-op if the row is already terminal —
/// belt-and-braces against a service double-finish.
pub async fn finish(
    pool: &SqlitePool,
    id: &str,
    ok: bool,
    error: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    let state = if ok { "done" } else { "failed" };
    let pct = if ok { 100 } else { 0 };
    sqlx::query(
        r#"UPDATE jobs
              SET state = ?,
                  progress_pct = CASE WHEN ? = 1 THEN 100 ELSE progress_pct END,
                  error = ?,
                  finished_at = ?,
                  updated_at = ?
            WHERE id = ?
              AND state = 'running'"#,
    )
    .bind(state)
    .bind(if ok { 1i64 } else { 0 })
    .bind(error)
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    let _ = pct; // silence the unused — `CASE` does the work.
    Ok(())
}

pub async fn read(pool: &SqlitePool, id: &str) -> Result<Option<JobRow>, StateError> {
    let row: Option<(
        String,
        String,
        Option<String>,
        String,
        String,
        i64,
        String,
        Option<String>,
        String,
        i64,
        String,
        i64,
        i64,
        Option<i64>,
    )> = sqlx::query_as(
        r#"SELECT id, kind, target, state, step_label, progress_pct,
                  log_tail, error, payload_json,
                  actor_uid, actor_label,
                  started_at, updated_at, finished_at
             FROM jobs WHERE id = ?"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(
            id,
            kind,
            target,
            state,
            step_label,
            progress_pct,
            log_tail,
            error,
            payload_json,
            actor_uid,
            actor_label,
            started_at,
            updated_at,
            finished_at,
        )| JobRow {
            id,
            kind,
            target,
            state,
            step_label,
            progress_pct,
            log_tail,
            error,
            payload_json,
            actor_uid,
            actor_label,
            started_at,
            updated_at,
            finished_at,
        },
    ))
}

/// List jobs, newest first. `kind=None` returns all kinds.
pub async fn list(
    pool: &SqlitePool,
    kind: Option<&str>,
    state: Option<&str>,
    limit: i64,
) -> Result<Vec<JobRow>, StateError> {
    let limit = limit.clamp(1, 1000);
    let rows: Vec<(
        String,
        String,
        Option<String>,
        String,
        String,
        i64,
        String,
        Option<String>,
        String,
        i64,
        String,
        i64,
        i64,
        Option<i64>,
    )> = match (kind, state) {
        (Some(k), Some(s)) => {
            sqlx::query_as(
                r#"SELECT id, kind, target, state, step_label, progress_pct,
                      log_tail, error, payload_json,
                      actor_uid, actor_label,
                      started_at, updated_at, finished_at
                 FROM jobs
                WHERE kind = ? AND state = ?
                ORDER BY started_at DESC
                LIMIT ?"#,
            )
            .bind(k)
            .bind(s)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        (Some(k), None) => {
            sqlx::query_as(
                r#"SELECT id, kind, target, state, step_label, progress_pct,
                      log_tail, error, payload_json,
                      actor_uid, actor_label,
                      started_at, updated_at, finished_at
                 FROM jobs
                WHERE kind = ?
                ORDER BY started_at DESC
                LIMIT ?"#,
            )
            .bind(k)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        (None, Some(s)) => {
            sqlx::query_as(
                r#"SELECT id, kind, target, state, step_label, progress_pct,
                      log_tail, error, payload_json,
                      actor_uid, actor_label,
                      started_at, updated_at, finished_at
                 FROM jobs
                WHERE state = ?
                ORDER BY started_at DESC
                LIMIT ?"#,
            )
            .bind(s)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        (None, None) => {
            sqlx::query_as(
                r#"SELECT id, kind, target, state, step_label, progress_pct,
                      log_tail, error, payload_json,
                      actor_uid, actor_label,
                      started_at, updated_at, finished_at
                 FROM jobs
                ORDER BY started_at DESC
                LIMIT ?"#,
            )
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                kind,
                target,
                state,
                step_label,
                progress_pct,
                log_tail,
                error,
                payload_json,
                actor_uid,
                actor_label,
                started_at,
                updated_at,
                finished_at,
            )| JobRow {
                id,
                kind,
                target,
                state,
                step_label,
                progress_pct,
                log_tail,
                error,
                payload_json,
                actor_uid,
                actor_label,
                started_at,
                updated_at,
                finished_at,
            },
        )
        .collect())
}

/// On agent startup, sweep `running` rows whose updated_at is older
/// than `stale_secs` and flip them to `failed`. Otherwise a process
/// crash mid-job leaves the UI polling forever. `stale_secs` should
/// be > the longest plausible step (rsync of a fat hosting can take
/// minutes); 1 hour is a safe default.
pub async fn reap_stale(pool: &SqlitePool, now: i64, stale_secs: i64) -> Result<u64, StateError> {
    let cutoff = now - stale_secs;
    let res = sqlx::query(
        r#"UPDATE jobs
              SET state = 'failed',
                  error = 'agent restarted while this job was running',
                  finished_at = ?,
                  updated_at = ?
            WHERE state = 'running'
              AND updated_at < ?"#,
    )
    .bind(now)
    .bind(now)
    .bind(cutoff)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    async fn fresh_pool() -> SqlitePool {
        // open_memory() already runs migrations against the in-memory
        // DB, so it ships with the `jobs` table and indices we need.
        open_memory().await.expect("open mem")
    }

    #[tokio::test]
    async fn round_trip_lifecycle() {
        let pool = fresh_pool().await;
        start(
            &pool,
            StartReq {
                id: "job-a",
                kind: "migration",
                target: Some("example.cz"),
                payload_json: "{\"src\":\"node1\",\"dst\":\"node2\"}",
                actor_uid: 7,
                actor_label: "kevin",
                started_at: 1000,
            },
        )
        .await
        .expect("start");

        progress(&pool, "job-a", "Exporting bundle", 25, "tar...\n", 1100)
            .await
            .expect("progress");
        let r = read(&pool, "job-a").await.expect("read").expect("present");
        assert_eq!(r.state, "running");
        assert_eq!(r.progress_pct, 25);
        assert_eq!(r.step_label, "Exporting bundle");
        assert!(r.log_tail.contains("tar..."));

        finish(&pool, "job-a", true, None, 1200)
            .await
            .expect("finish");
        let r = read(&pool, "job-a").await.expect("read").expect("present");
        assert_eq!(r.state, "done");
        assert_eq!(r.progress_pct, 100);
        assert!(r.finished_at.is_some());
        // Idempotency: a second finish must NOT flip a done job to
        // failed (e.g. double-tap from a paranoid handler).
        finish(&pool, "job-a", false, Some("oops"), 1300)
            .await
            .expect("finish-2");
        let r = read(&pool, "job-a").await.expect("read").expect("present");
        assert_eq!(r.state, "done", "terminal state must be sticky");
        assert!(r.error.is_none(), "error must not be set on done job");
    }

    /// Log tail must not grow without bound; the 16 KiB cap protects
    /// SQLite + the templates from a runaway logger.
    #[tokio::test]
    async fn log_tail_is_bounded() {
        let pool = fresh_pool().await;
        start(
            &pool,
            StartReq {
                id: "job-b",
                kind: "install",
                target: None,
                payload_json: "{}",
                actor_uid: 0,
                actor_label: "system",
                started_at: 0,
            },
        )
        .await
        .expect("start");
        // 100 KiB of noise — well above the 16 KiB cap.
        let chunk = "x".repeat(8 * 1024);
        for i in 0..12 {
            progress(&pool, "job-b", "noise", i * 8, &chunk, 100 + i)
                .await
                .expect("progress");
        }
        let r = read(&pool, "job-b").await.expect("read").expect("present");
        assert!(
            r.log_tail.len() <= 16 * 1024 + 32,
            "log_tail should be ~bounded, got {} bytes",
            r.log_tail.len()
        );
    }

    /// reap_stale flips orphan `running` rows. Operators should not
    /// see a forever-spinning job after an agent restart.
    #[tokio::test]
    async fn reap_stale_marks_orphans_failed() {
        let pool = fresh_pool().await;
        start(
            &pool,
            StartReq {
                id: "job-c",
                kind: "backup",
                target: Some("example.cz"),
                payload_json: "{}",
                actor_uid: 0,
                actor_label: "system",
                started_at: 0,
            },
        )
        .await
        .expect("start");
        // updated_at was set to started_at = 0; now is 3700 (>1h
        // window). Reaper should flip it.
        let n = reap_stale(&pool, 3700, 3600).await.expect("reap");
        assert_eq!(n, 1);
        let r = read(&pool, "job-c").await.expect("read").expect("present");
        assert_eq!(r.state, "failed");
        assert!(r.error.as_deref().unwrap_or("").contains("agent restarted"));

        // A second reap is a no-op (the job is already terminal).
        let n = reap_stale(&pool, 7400, 3600).await.expect("reap-2");
        assert_eq!(n, 0);
    }
}
