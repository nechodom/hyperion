//! Per-hosting email log — append-only record of every transactional
//! email the agent sends (test, cert-expiry, backup-failure,
//! monitor-down, billing, etc.).
//!
//! Kept narrower than `audit_log` deliberately: the audit table is a
//! tamper-evident chain that covers every state-changing operation,
//! whereas this table is operator-facing UX — "show me the emails for
//! example.cz from the last 30 days" should be one SQL query, not a
//! grep across heterogeneous payloads.

use crate::db::StateError;
use sqlx::SqlitePool;

/// Cap on persisted body preview. Real bodies (often hundreds of
/// chars with HTML escaping etc.) are summarized to this length so
/// the table stays compact and we never accidentally persist a
/// password / reset token that might appear in a future body.
pub const BODY_PREVIEW_MAX: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailLogRow {
    pub id: i64,
    /// `None` for cluster-wide notifications (billing summaries,
    /// master-level alerts that don't relate to a specific hosting).
    pub hosting_id: Option<String>,
    pub to_address: String,
    pub subject: String,
    pub body_preview: String,
    /// "test" | "alert" | "monitor" | "backup" | "cert" | "billing"
    /// | "other" — free-form but with a recommended vocabulary.
    pub kind: String,
    /// "ok" | "failed".
    pub state: String,
    pub error: Option<String>,
    /// SMTP server's numeric response code (e.g. "Code(250)"). None
    /// when the send didn't even reach the server (DNS, TLS, etc.).
    pub smtp_code: Option<String>,
    pub sent_at: i64,
}

/// Append one row. The caller controls `state` + `error`; we just
/// persist what we're told.
#[allow(clippy::too_many_arguments)]
pub async fn append(
    pool: &SqlitePool,
    hosting_id: Option<&str>,
    to_address: &str,
    subject: &str,
    body_preview: &str,
    kind: &str,
    state: &str,
    error: Option<&str>,
    smtp_code: Option<&str>,
    now: i64,
) -> Result<i64, StateError> {
    // Truncate at a char boundary so multi-byte UTF-8 (Czech chars in
    // a subject line) doesn't panic.
    let preview = truncate_chars(body_preview, BODY_PREVIEW_MAX);
    let r = sqlx::query(
        r#"INSERT INTO email_log
           (hosting_id, to_address, subject, body_preview, kind, state, error, smtp_code, sent_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(hosting_id)
    .bind(to_address)
    .bind(subject)
    .bind(&preview)
    .bind(kind)
    .bind(state)
    .bind(error)
    .bind(smtp_code)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(r.last_insert_rowid())
}

/// Recent emails, newest first. `hosting_id = None` returns the
/// last `limit` across all hostings + cluster-wide events.
/// `hosting_id = Some(id)` filters to just that hosting (no
/// cluster-wide ones — those have hosting_id NULL).
pub async fn list(
    pool: &SqlitePool,
    hosting_id: Option<&str>,
    limit: i64,
) -> Result<Vec<EmailLogRow>, StateError> {
    let limit = limit.clamp(1, 500);
    let rows: Vec<(
        i64,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        i64,
    )> = match hosting_id {
        Some(id) => {
            sqlx::query_as(
                "SELECT id, hosting_id, to_address, subject, body_preview, kind, state,
                    error, smtp_code, sent_at
               FROM email_log
              WHERE hosting_id = ?
              ORDER BY sent_at DESC, id DESC
              LIMIT ?",
            )
            .bind(id)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as(
                "SELECT id, hosting_id, to_address, subject, body_preview, kind, state,
                    error, smtp_code, sent_at
               FROM email_log
              ORDER BY sent_at DESC, id DESC
              LIMIT ?",
            )
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows
        .into_iter()
        .map(
            |(id, hid, to, subj, prev, kind, state, err, code, sent)| EmailLogRow {
                id,
                hosting_id: hid,
                to_address: to,
                subject: subj,
                body_preview: prev,
                kind,
                state,
                error: err,
                smtp_code: code,
                sent_at: sent,
            },
        )
        .collect())
}

/// Truncate `s` to at most `max` Rust chars (NOT bytes), preserving
/// UTF-8 validity. Adds an ellipsis only when actually truncated.
fn truncate_chars(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    #[tokio::test]
    async fn append_and_list_round_trip() {
        let pool = open_memory().await.expect("open");
        // Seed a hosting so the FK constraint passes.
        let suid = crate::system_users::insert(&pool, "u1", 1042, "/home/u1", "/bin/bash", 1)
            .await
            .expect("user");
        let hid = hyperion_types::HostingId::new_v7();
        crate::hostings::insert(&pool, &hid, "ex.cz", suid, None, "/x", 1, None)
            .await
            .expect("hosting");

        let _ = append(
            &pool,
            Some(hid.as_str()),
            "ops@ex.cz",
            "DOWN: ex.cz",
            "Site returned 502 after 3 retries.",
            "monitor",
            "ok",
            None,
            Some("Code(250)"),
            100,
        )
        .await
        .expect("append");
        let _ = append(
            &pool,
            None,
            "billing@cluster.local",
            "Billing summary",
            "Total invoiced: $42",
            "billing",
            "ok",
            None,
            Some("Code(250)"),
            200,
        )
        .await
        .expect("append");

        let per_hosting = list(&pool, Some(hid.as_str()), 10).await.expect("list");
        assert_eq!(per_hosting.len(), 1);
        assert_eq!(per_hosting[0].subject, "DOWN: ex.cz");

        let all = list(&pool, None, 10).await.expect("list all");
        assert_eq!(all.len(), 2);
        // Newest first.
        assert_eq!(all[0].subject, "Billing summary");
        assert_eq!(all[1].subject, "DOWN: ex.cz");
    }

    #[tokio::test]
    async fn append_truncates_long_body_preview() {
        let pool = open_memory().await.expect("open");
        let big = "ě".repeat(500);
        append(
            &pool, None, "to@x", "subj", &big, "test", "ok", None, None, 0,
        )
        .await
        .expect("append");
        let rows = list(&pool, None, 1).await.expect("list");
        assert_eq!(rows[0].body_preview.chars().count(), BODY_PREVIEW_MAX + 1); // + ellipsis
        assert!(rows[0].body_preview.ends_with('…'));
    }

    #[tokio::test]
    async fn list_respects_limit_clamp() {
        let pool = open_memory().await.expect("open");
        for i in 0..5 {
            append(
                &pool,
                None,
                "to@x",
                &format!("subj {i}"),
                "",
                "test",
                "ok",
                None,
                None,
                i,
            )
            .await
            .expect("append");
        }
        // Asking for 1000 is clamped to 500; we have 5 — got 5.
        let rows = list(&pool, None, 1000).await.expect("list");
        assert_eq!(rows.len(), 5);
        // Asking for 0 is clamped to 1.
        let rows = list(&pool, None, 0).await.expect("list zero");
        assert_eq!(rows.len(), 1);
    }
}
