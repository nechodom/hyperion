//! Per-hosting monitoring config + samples.

use crate::db::StateError;
use hyperion_types::HostingId;
use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorConfig {
    pub hosting_id: HostingId,
    pub domain: String,
    pub enabled: bool,
    pub url_path: String,
    pub interval_secs: i64,
    pub alert_after_fails: i64,
    pub alert_email: Option<String>,
    pub alert_slack_webhook: Option<String>,
    pub alert_webhook_url: Option<String>,
    pub consecutive_fails: i64,
    pub last_alert_at: Option<i64>,
    pub alert_state: String,
}

/// All hostings where `monitor_enabled = 1`. Joins the monitor columns
/// from `hostings` for the agent's monitor_tick to walk.
pub async fn list_enabled(pool: &SqlitePool) -> Result<Vec<MonitorConfig>, StateError> {
    let rows: Vec<(
        String, String, i64, Option<String>, Option<i64>, Option<i64>,
        Option<String>, Option<String>, Option<String>, i64, Option<i64>, String,
    )> = sqlx::query_as(
        "SELECT id, domain, monitor_enabled, monitor_url_path, monitor_interval_secs,
                monitor_alert_after_fails, monitor_alert_email,
                monitor_alert_slack_webhook, monitor_alert_webhook_url,
                monitor_consecutive_fails, monitor_last_alert_at, monitor_alert_state
         FROM hostings
         WHERE monitor_enabled = 1 AND state = 'active'",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(
            id, domain, enabled, url_path, interval_secs, alert_after,
            ae, asw, awu, fails, last_at, state,
        )| MonitorConfig {
            hosting_id: HostingId(id),
            domain,
            enabled: enabled != 0,
            url_path: url_path.unwrap_or_else(|| "/".into()),
            interval_secs: interval_secs.unwrap_or(300).clamp(60, 3600),
            alert_after_fails: alert_after.unwrap_or(3).max(1),
            alert_email: ae,
            alert_slack_webhook: asw,
            alert_webhook_url: awu,
            consecutive_fails: fails,
            last_alert_at: last_at,
            alert_state: state,
        })
        .collect())
}

/// Look up the monitor config for one hosting (used by the detail
/// page form to prefill). Returns None when the hosting doesn't exist.
pub async fn get(pool: &SqlitePool, id: &HostingId) -> Result<Option<MonitorConfig>, StateError> {
    let row: Option<(
        String, String, i64, Option<String>, Option<i64>, Option<i64>,
        Option<String>, Option<String>, Option<String>, i64, Option<i64>, String,
    )> = sqlx::query_as(
        "SELECT id, domain, monitor_enabled, monitor_url_path, monitor_interval_secs,
                monitor_alert_after_fails, monitor_alert_email,
                monitor_alert_slack_webhook, monitor_alert_webhook_url,
                monitor_consecutive_fails, monitor_last_alert_at, monitor_alert_state
         FROM hostings WHERE id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(
        rid, domain, enabled, url_path, interval_secs, alert_after,
        ae, asw, awu, fails, last_at, state,
    )| MonitorConfig {
        hosting_id: HostingId(rid),
        domain,
        enabled: enabled != 0,
        url_path: url_path.unwrap_or_else(|| "/".into()),
        interval_secs: interval_secs.unwrap_or(300).clamp(60, 3600),
        alert_after_fails: alert_after.unwrap_or(3).max(1),
        alert_email: ae,
        alert_slack_webhook: asw,
        alert_webhook_url: awu,
        consecutive_fails: fails,
        last_alert_at: last_at,
        alert_state: state,
    }))
}

/// Persist the operator-set fields. None values clear the column.
#[allow(clippy::too_many_arguments)]
pub async fn set_config(
    pool: &SqlitePool,
    id: &HostingId,
    enabled: bool,
    url_path: Option<&str>,
    interval_secs: Option<i64>,
    alert_after_fails: Option<i64>,
    alert_email: Option<&str>,
    alert_slack_webhook: Option<&str>,
    alert_webhook_url: Option<&str>,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        "UPDATE hostings
         SET monitor_enabled = ?,
             monitor_url_path = ?,
             monitor_interval_secs = ?,
             monitor_alert_after_fails = ?,
             monitor_alert_email = ?,
             monitor_alert_slack_webhook = ?,
             monitor_alert_webhook_url = ?,
             updated_at = ?
         WHERE id = ?",
    )
    .bind(if enabled { 1 } else { 0 })
    .bind(url_path)
    .bind(interval_secs)
    .bind(alert_after_fails)
    .bind(alert_email)
    .bind(alert_slack_webhook)
    .bind(alert_webhook_url)
    .bind(now)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Bump the consecutive-failure counter. Returns the new value.
pub async fn record_fail(
    pool: &SqlitePool,
    id: &HostingId,
) -> Result<i64, StateError> {
    sqlx::query(
        "UPDATE hostings SET monitor_consecutive_fails = monitor_consecutive_fails + 1 WHERE id = ?",
    )
    .bind(id.as_str())
    .execute(pool)
    .await?;
    let (n,): (i64,) = sqlx::query_as(
        "SELECT monitor_consecutive_fails FROM hostings WHERE id = ?",
    )
    .bind(id.as_str())
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Reset consecutive fails on success.
pub async fn reset_streak(pool: &SqlitePool, id: &HostingId) -> Result<(), StateError> {
    sqlx::query("UPDATE hostings SET monitor_consecutive_fails = 0 WHERE id = ?")
        .bind(id.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_alert_state(
    pool: &SqlitePool,
    id: &HostingId,
    state: &str,
    last_alert_at: Option<i64>,
) -> Result<(), StateError> {
    if let Some(t) = last_alert_at {
        sqlx::query(
            "UPDATE hostings SET monitor_alert_state = ?, monitor_last_alert_at = ? WHERE id = ?",
        )
        .bind(state)
        .bind(t)
        .bind(id.as_str())
        .execute(pool)
        .await?;
    } else {
        sqlx::query("UPDATE hostings SET monitor_alert_state = ? WHERE id = ?")
            .bind(state)
            .bind(id.as_str())
            .execute(pool)
            .await?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorSample {
    pub id: i64,
    pub hosting_id: HostingId,
    pub sampled_at: i64,
    pub success: bool,
    pub http_status: Option<i64>,
    pub response_ms: i64,
    pub error_message: Option<String>,
}

pub async fn insert_sample(
    pool: &SqlitePool,
    id: &HostingId,
    sampled_at: i64,
    success: bool,
    http_status: Option<i64>,
    response_ms: i64,
    error_message: Option<&str>,
) -> Result<(), StateError> {
    sqlx::query(
        "INSERT INTO monitor_samples
         (hosting_id, sampled_at, success, http_status, response_ms, error_message)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.as_str())
    .bind(sampled_at)
    .bind(if success { 1 } else { 0 })
    .bind(http_status)
    .bind(response_ms)
    .bind(error_message)
    .execute(pool)
    .await?;
    Ok(())
}

/// Last N samples for a hosting, oldest first (charting order).
pub async fn history(
    pool: &SqlitePool,
    id: &HostingId,
    limit: i64,
) -> Result<Vec<MonitorSample>, StateError> {
    let limit = limit.clamp(1, 2000);
    let rows: Vec<(
        i64, String, i64, i64, Option<i64>, i64, Option<String>,
    )> = sqlx::query_as(
        "SELECT id, hosting_id, sampled_at, success, http_status, response_ms, error_message
         FROM monitor_samples
         WHERE hosting_id = ?
         ORDER BY sampled_at DESC
         LIMIT ?",
    )
    .bind(id.as_str())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut out: Vec<MonitorSample> = rows
        .into_iter()
        .map(|(id, hid, at, s, hs, ms, e)| MonitorSample {
            id,
            hosting_id: HostingId(hid),
            sampled_at: at,
            success: s != 0,
            http_status: hs,
            response_ms: ms,
            error_message: e,
        })
        .collect();
    out.reverse();
    Ok(out)
}

pub async fn prune_older_than(pool: &SqlitePool, cutoff_at: i64) -> Result<u64, StateError> {
    let r = sqlx::query("DELETE FROM monitor_samples WHERE sampled_at < ?")
        .bind(cutoff_at)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    async fn fresh_hosting(pool: &SqlitePool, name: &str) -> HostingId {
        // Use the byte sum so a single-letter username doesn't collide
        // with another single-letter username via the same UID.
        let uid: i64 = 2000 + name.bytes().map(|b| b as i64).sum::<i64>();
        let suid = crate::system_users::insert(
            pool,
            name,
            uid,
            &format!("/h/{name}"),
            "/x",
            1,
        )
        .await
        .expect("user");
        let id = HostingId::new_v7();
        crate::hostings::insert(pool, &id, &format!("{name}.cz"), suid, None, "/x", 1, None)
            .await
            .expect("hosting");
        // Move to active so list_enabled finds it.
        crate::hostings::set_state(pool, &id, hyperion_types::HostingState::Active, 2)
            .await
            .expect("active");
        id
    }

    #[tokio::test]
    async fn default_monitor_is_disabled() {
        let pool = open_memory().await.expect("open");
        let id = fresh_hosting(&pool, "example").await;
        let cfg = get(&pool, &id).await.expect("get").expect("present");
        assert!(!cfg.enabled);
        assert_eq!(cfg.url_path, "/");
        assert_eq!(cfg.interval_secs, 300);
        assert_eq!(cfg.alert_after_fails, 3);
        assert_eq!(cfg.alert_state, "ok");
    }

    #[tokio::test]
    async fn set_config_round_trips() {
        let pool = open_memory().await.expect("open");
        let id = fresh_hosting(&pool, "x").await;
        set_config(
            &pool,
            &id,
            true,
            Some("/health"),
            Some(120),
            Some(5),
            Some("ops@example.cz"),
            Some("https://hooks.slack.com/services/A/B/C"),
            None,
            10,
        )
        .await
        .expect("set");
        let cfg = get(&pool, &id).await.expect("get").expect("present");
        assert!(cfg.enabled);
        assert_eq!(cfg.url_path, "/health");
        assert_eq!(cfg.interval_secs, 120);
        assert_eq!(cfg.alert_after_fails, 5);
        assert_eq!(cfg.alert_email.as_deref(), Some("ops@example.cz"));
        assert_eq!(
            cfg.alert_slack_webhook.as_deref(),
            Some("https://hooks.slack.com/services/A/B/C")
        );
        assert!(cfg.alert_webhook_url.is_none());
    }

    #[tokio::test]
    async fn list_enabled_only_returns_active_with_flag() {
        let pool = open_memory().await.expect("open");
        let a = fresh_hosting(&pool, "a").await;
        let b = fresh_hosting(&pool, "b").await;
        set_config(&pool, &a, true, None, None, None, None, None, None, 1)
            .await
            .expect("a");
        // b stays disabled.
        let _ = b;
        let enabled = list_enabled(&pool).await.expect("list");
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].hosting_id, a);
    }

    #[tokio::test]
    async fn streak_record_and_reset() {
        let pool = open_memory().await.expect("open");
        let id = fresh_hosting(&pool, "x").await;
        let n1 = record_fail(&pool, &id).await.expect("fail 1");
        assert_eq!(n1, 1);
        let n2 = record_fail(&pool, &id).await.expect("fail 2");
        assert_eq!(n2, 2);
        reset_streak(&pool, &id).await.expect("reset");
        let cfg = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(cfg.consecutive_fails, 0);
    }

    #[tokio::test]
    async fn samples_history_ascending() {
        let pool = open_memory().await.expect("open");
        let id = fresh_hosting(&pool, "x").await;
        for ts in [300, 100, 200] {
            insert_sample(&pool, &id, ts, true, Some(200), 10, None)
                .await
                .expect("insert");
        }
        let hist = history(&pool, &id, 10).await.expect("hist");
        let ts: Vec<i64> = hist.iter().map(|s| s.sampled_at).collect();
        assert_eq!(ts, vec![100, 200, 300]);
    }

    #[tokio::test]
    async fn alert_state_set_round_trips() {
        let pool = open_memory().await.expect("open");
        let id = fresh_hosting(&pool, "x").await;
        set_alert_state(&pool, &id, "alerting", Some(500))
            .await
            .expect("alerting");
        let cfg = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(cfg.alert_state, "alerting");
        assert_eq!(cfg.last_alert_at, Some(500));
        set_alert_state(&pool, &id, "ok", None).await.expect("ok");
        let cfg = get(&pool, &id).await.expect("get").expect("present");
        assert_eq!(cfg.alert_state, "ok");
    }
}
