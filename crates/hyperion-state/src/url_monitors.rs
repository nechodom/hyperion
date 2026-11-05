//! URL checks (`url_monitors`, `url_monitor_samples`): the master's own
//! availability checks of addresses it does not host, or hosts elsewhere.
//!
//! Nothing here probes anything; it only remembers what the checks decided.

use crate::db::StateError;
pub use crate::monitors::SecretField;
use sqlx::SqlitePool;

/// One stored check. The two webhook columns are credentials: callers must
/// not hand them to a browser.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Row {
    pub id: i64,
    pub url: String,
    pub interval_secs: i64,
    pub expected_status: Option<i64>,
    pub alert_after_fails: i64,
    pub alert_email: Option<String>,
    pub alert_slack_webhook: Option<String>,
    pub alert_webhook_url: Option<String>,
    pub node_id: Option<String>,
    pub node_manual: bool,
    pub alert_state: String,
    pub last_alert_at: Option<i64>,
    pub pending_alert: Option<String>,
    pub pending_error: Option<String>,
    pub last_sampled_at: i64,
    pub cert_expires_at: Option<i64>,
    pub cert_checked_at: i64,
    pub cert_alert_day: Option<i64>,
    pub created_at: i64,
}

const COLUMNS: &str = "id, url, interval_secs, expected_status, alert_after_fails, alert_email, \
     alert_slack_webhook, alert_webhook_url, node_id, node_manual, alert_state, last_alert_at, \
     pending_alert, pending_error, last_sampled_at, cert_expires_at, cert_checked_at, \
     cert_alert_day, created_at";

/// What an operator may set. The alert channels and the node are not part of
/// the sampling state, so saving never touches `alert_state` or the pending
/// alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields<'a> {
    pub url: &'a str,
    pub interval_secs: i64,
    pub expected_status: Option<i64>,
    pub alert_after_fails: i64,
    pub alert_email: Option<&'a str>,
    pub slack: SecretField<'a>,
    pub webhook: SecretField<'a>,
    pub node_id: Option<&'a str>,
    pub node_manual: bool,
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<Row>, StateError> {
    Ok(
        sqlx::query_as::<_, Row>(&format!("SELECT {COLUMNS} FROM url_monitors ORDER BY id"))
            .fetch_all(pool)
            .await?,
    )
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Option<Row>, StateError> {
    Ok(
        sqlx::query_as::<_, Row>(&format!("SELECT {COLUMNS} FROM url_monitors WHERE id = ?"))
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn count(pool: &SqlitePool) -> Result<i64, StateError> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM url_monitors")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn insert(pool: &SqlitePool, f: &Fields<'_>, now: i64) -> Result<i64, StateError> {
    let res = sqlx::query(
        "INSERT INTO url_monitors (url, interval_secs, expected_status, alert_after_fails, \
         alert_email, alert_slack_webhook, alert_webhook_url, node_id, node_manual, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(f.url)
    .bind(f.interval_secs)
    .bind(f.expected_status)
    .bind(f.alert_after_fails)
    .bind(f.alert_email)
    .bind(secret_for_insert(&f.slack))
    .bind(secret_for_insert(&f.webhook))
    .bind(f.node_id)
    .bind(f.node_manual)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(res.last_insert_rowid())
}

fn secret_for_insert<'a>(s: &SecretField<'a>) -> Option<&'a str> {
    match s {
        SecretField::Set(v) => Some(v),
        SecretField::Keep | SecretField::Clear => None,
    }
}

/// Rewrite the operator-set fields of one check. Returns false when it does
/// not exist. A secret that is `Keep` is left out of the statement.
///
/// A check pointed at another ADDRESS is a new check as far as what was
/// learnt goes: in the same transaction its certificate expiry, the warning
/// already given for it, the hour's certificate read, its samples, its alert
/// state and any parked alert are dropped, so nothing about the old address
/// is judged against the new one. Changing anything else keeps all of it.
pub async fn update(pool: &SqlitePool, id: i64, f: &Fields<'_>) -> Result<bool, StateError> {
    let mut tx = pool.begin().await?;
    let old: Option<(String,)> = sqlx::query_as("SELECT url FROM url_monitors WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some((old_url,)) = old else {
        return Ok(false);
    };
    let mut sets = vec![
        "url = ?",
        "interval_secs = ?",
        "expected_status = ?",
        "alert_after_fails = ?",
        "alert_email = ?",
        "node_id = ?",
        "node_manual = ?",
    ];
    let moved = old_url != f.url;
    if moved {
        sets.extend([
            "cert_expires_at = NULL",
            "cert_alert_day = NULL",
            "cert_checked_at = 0",
            "alert_state = 'ok'",
            "last_alert_at = NULL",
            "pending_alert = NULL",
            "pending_error = NULL",
            "last_sampled_at = 0",
        ]);
    }
    if f.slack != SecretField::Keep {
        sets.push("alert_slack_webhook = ?");
    }
    if f.webhook != SecretField::Keep {
        sets.push("alert_webhook_url = ?");
    }
    let sql = format!("UPDATE url_monitors SET {} WHERE id = ?", sets.join(", "));
    let mut q = sqlx::query(&sql)
        .bind(f.url)
        .bind(f.interval_secs)
        .bind(f.expected_status)
        .bind(f.alert_after_fails)
        .bind(f.alert_email)
        .bind(f.node_id)
        .bind(f.node_manual);
    for s in [&f.slack, &f.webhook] {
        match s {
            SecretField::Keep => {}
            SecretField::Clear => q = q.bind(None::<&str>),
            SecretField::Set(v) => q = q.bind(Some(*v)),
        }
    }
    let changed = q.bind(id).execute(&mut *tx).await?.rows_affected() > 0;
    if moved {
        sqlx::query("DELETE FROM url_monitor_samples WHERE monitor_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(changed)
}

/// Delete a check and its samples. False when it did not exist.
pub async fn delete(pool: &SqlitePool, id: i64) -> Result<bool, StateError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM url_monitor_samples WHERE monitor_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let gone = sqlx::query("DELETE FROM url_monitors WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    tx.commit().await?;
    Ok(gone)
}

/// Every check and every sample (module removal).
pub async fn clear_all(pool: &SqlitePool) -> Result<(), StateError> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM url_monitor_samples")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM url_monitors")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// One probe result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub sampled_at: i64,
    pub success: bool,
    pub http_status: Option<i64>,
    pub response_ms: i64,
    pub error_message: Option<String>,
}

/// Record a probe of `url` and stamp the check as sampled, but only while
/// the check still points at `url`. A probe started against an address the
/// operator has since replaced says nothing about the new one: it is dropped
/// and this returns false. Check and write are one statement pair in one
/// transaction, so the address cannot change between them.
pub async fn insert_sample_for_url(
    pool: &SqlitePool,
    id: i64,
    url: &str,
    s: &Sample,
) -> Result<bool, StateError> {
    let mut tx = pool.begin().await?;
    let stamped =
        sqlx::query("UPDATE url_monitors SET last_sampled_at = ? WHERE id = ? AND url = ?")
            .bind(s.sampled_at)
            .bind(id)
            .bind(url)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            > 0;
    if !stamped {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO url_monitor_samples \
         (monitor_id, sampled_at, success, http_status, response_ms, error_message) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(s.sampled_at)
    .bind(s.success)
    .bind(s.http_status)
    .bind(s.response_ms)
    .bind(s.error_message.as_deref())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn insert_sample(pool: &SqlitePool, id: i64, s: &Sample) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO url_monitor_samples \
         (monitor_id, sampled_at, success, http_status, response_ms, error_message) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(s.sampled_at)
    .bind(s.success)
    .bind(s.http_status)
    .bind(s.response_ms)
    .bind(s.error_message.as_deref())
    .execute(pool)
    .await?;
    Ok(())
}

/// The newest `limit` samples as `(sampled_at, success)`, oldest first: the
/// window `monitor_transition` decides from.
pub async fn recent(
    pool: &SqlitePool,
    id: i64,
    limit: i64,
) -> Result<Vec<(i64, bool)>, StateError> {
    let mut rows: Vec<(i64, bool)> = sqlx::query_as(
        "SELECT sampled_at, success FROM url_monitor_samples WHERE monitor_id = ? \
         ORDER BY sampled_at DESC, rowid DESC LIMIT ?",
    )
    .bind(id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.reverse();
    Ok(rows)
}

/// Stamp that a check was sampled at `at`.
pub async fn set_sampled(pool: &SqlitePool, id: i64, at: i64) -> Result<(), StateError> {
    sqlx::query("UPDATE url_monitors SET last_sampled_at = ? WHERE id = ?")
        .bind(at)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record a decided transition. `to` is `alerting` or `ok`; the alert it
/// owes the operator is parked in `pending_alert` (`down` / `up`) until it is
/// acknowledged. A recovery that arrives while the matching `down` was never
/// announced cancels it instead: nobody was told, so nobody needs telling.
pub async fn record_transition(
    pool: &SqlitePool,
    id: i64,
    down: bool,
    error: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    record_transition_for(pool, id, None, down, error, now).await
}

/// [`record_transition`] that applies only while the check still points at
/// `url` (when given): a decision made about an address that was replaced
/// meanwhile is dropped.
pub async fn record_transition_for(
    pool: &SqlitePool,
    id: i64,
    url: Option<&str>,
    down: bool,
    error: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    let mut tx = pool.begin().await?;
    let pending: Option<(Option<String>, String)> =
        sqlx::query_as("SELECT pending_alert, url FROM url_monitors WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((pending, current)) = pending else {
        return Ok(());
    };
    if url.is_some_and(|u| u != current) {
        return Ok(());
    }
    let (state, new_pending, new_error) = if down {
        ("alerting", Some("down"), error)
    } else if pending.as_deref() == Some("down") {
        ("ok", None, None)
    } else {
        ("ok", Some("up"), None)
    };
    sqlx::query(
        "UPDATE url_monitors SET alert_state = ?, last_alert_at = ?, pending_alert = ?, \
         pending_error = ? WHERE id = ?",
    )
    .bind(state)
    .bind(now)
    .bind(new_pending)
    .bind(new_error)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Checks with an alert waiting for acknowledgement, oldest decision first.
pub async fn pending(pool: &SqlitePool) -> Result<Vec<Row>, StateError> {
    Ok(sqlx::query_as::<_, Row>(&format!(
        "SELECT {COLUMNS} FROM url_monitors WHERE pending_alert IS NOT NULL \
         ORDER BY last_alert_at, id"
    ))
    .fetch_all(pool)
    .await?)
}

/// Clear the parked alert, but only when it is still the one that was sent
/// (`kind`): a transition decided meanwhile stays parked. True when cleared.
pub async fn ack_pending(pool: &SqlitePool, id: i64, kind: &str) -> Result<bool, StateError> {
    Ok(sqlx::query(
        "UPDATE url_monitors SET pending_alert = NULL, pending_error = NULL \
         WHERE id = ? AND pending_alert = ?",
    )
    .bind(id)
    .bind(kind)
    .execute(pool)
    .await?
    .rows_affected()
        > 0)
}

/// Re-point a check at another node (or none).
pub async fn set_node(pool: &SqlitePool, id: i64, node: Option<&str>) -> Result<(), StateError> {
    sqlx::query("UPDATE url_monitors SET node_id = ? WHERE id = ?")
        .bind(node)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A certificate read of `url`: when it was read, and the expiry if one could
/// be read. An unreadable answer keeps the expiry already on record. Applies
/// only while the check still points at `url`; returns whether it did.
pub async fn set_cert_read(
    pool: &SqlitePool,
    id: i64,
    url: &str,
    checked_at: i64,
    expires_at: Option<i64>,
) -> Result<bool, StateError> {
    Ok(sqlx::query(
        "UPDATE url_monitors SET cert_checked_at = ?, cert_expires_at = COALESCE(?, cert_expires_at) \
         WHERE id = ? AND url = ?",
    )
    .bind(checked_at)
    .bind(expires_at)
    .bind(id)
    .bind(url)
    .execute(pool)
    .await?
    .rows_affected()
        > 0)
}

/// The cert threshold last warned about (`None` clears it: a renewed
/// certificate warns again).
pub async fn set_cert_alert_day(
    pool: &SqlitePool,
    id: i64,
    day: Option<i64>,
) -> Result<(), StateError> {
    sqlx::query("UPDATE url_monitors SET cert_alert_day = ? WHERE id = ?")
        .bind(day)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// What the last 24 hours of one check look like.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub samples: i64,
    pub ok: i64,
    /// Mean response of the successful samples.
    pub avg_ms: i64,
    pub last_sampled_at: i64,
    /// The newest failing sample's error in the window.
    pub last_error: Option<String>,
}

pub async fn stats_since(pool: &SqlitePool, id: i64, since: i64) -> Result<Stats, StateError> {
    let (samples, ok, avg, last): (i64, Option<i64>, Option<f64>, Option<i64>) = sqlx::query_as(
        "SELECT COUNT(*), SUM(success), AVG(CASE WHEN success = 1 THEN response_ms END), \
         MAX(sampled_at) FROM url_monitor_samples WHERE monitor_id = ? AND sampled_at >= ?",
    )
    .bind(id)
    .bind(since)
    .fetch_one(pool)
    .await?;
    let last_error: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT error_message, http_status FROM url_monitor_samples \
         WHERE monitor_id = ? AND sampled_at >= ? AND success = 0 \
         ORDER BY sampled_at DESC, rowid DESC LIMIT 1",
    )
    .bind(id)
    .bind(since)
    .fetch_optional(pool)
    .await?;
    Ok(Stats {
        samples,
        ok: ok.unwrap_or(0),
        avg_ms: avg.map_or(0, |a| a.round() as i64),
        last_sampled_at: last.unwrap_or(0),
        last_error: last_error.map(|(e, st)| {
            e.filter(|e| !e.is_empty())
                .or_else(|| st.map(|c| format!("HTTP {c}")))
                .unwrap_or_else(|| "no response".to_string())
        }),
    })
}

/// The HTTP status of the newest sample, if it had one.
pub async fn last_status(pool: &SqlitePool, id: i64) -> Result<Option<i64>, StateError> {
    let row: Option<(Option<i64>,)> = sqlx::query_as(
        "SELECT http_status FROM url_monitor_samples WHERE monitor_id = ? \
         ORDER BY sampled_at DESC, rowid DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.0))
}

/// Drop samples older than `before`. Returns how many went.
pub async fn prune_samples(pool: &SqlitePool, before: i64) -> Result<u64, StateError> {
    Ok(
        sqlx::query("DELETE FROM url_monitor_samples WHERE sampled_at < ?")
            .bind(before)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

/// Samples on record for one check.
pub async fn sample_count(pool: &SqlitePool, id: i64) -> Result<i64, StateError> {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM url_monitor_samples WHERE monitor_id = ?")
            .bind(id)
            .fetch_one(pool)
            .await?;
    Ok(n)
}
