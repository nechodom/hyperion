//! WAF hit records (migration 077). NODE-LOCAL: each node records the
//! refusals of the hostings it serves, read from its own root-owned hit
//! logs.
//!
//! Three shapes for three questions:
//! - `waf_hits_hourly` — "how much, by rule" for the panel's totals;
//! - `waf_recent` — "what exactly" for the last refusals list;
//! - `waf_ip_minute` — "who, how often lately" for the auto-ban threshold.
//!   Only ban-counted rules land here, so a tag that must never ban
//!   (`xmlrpc`, `geo`, `bot`…) cannot reach the threshold at all.

use crate::db::StateError;
use hyperion_types::waf::{WafHit, WafRuleCount};
use sqlx::SqlitePool;

/// Refusals kept per hosting in `waf_recent`.
pub const RECENT_CAP: i64 = 200;
/// Hourly rows older than this are pruned.
pub const HOURLY_KEEP_SECS: i64 = 30 * 86_400;
/// Per-IP minute rows older than this are pruned. Longer than any sane
/// `[fail2ban] window_secs`.
pub const IP_MINUTE_KEEP_SECS: i64 = 86_400;
/// Stored length of the attacker-controlled fields.
pub const FIELD_MAX: usize = 200;

fn truncate(s: &str) -> String {
    if s.len() <= FIELD_MAX {
        return s.to_string();
    }
    let mut end = FIELD_MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Record a batch of hits for one hosting, in one transaction.
pub async fn record(
    pool: &SqlitePool,
    hosting_id: &str,
    hits: &[WafHit],
) -> Result<(), StateError> {
    if hits.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for h in hits {
        let hour = h.ts - h.ts.rem_euclid(3600);
        sqlx::query(
            "INSERT INTO waf_hits_hourly (hosting_id, hour, rule, hits) VALUES (?, ?, ?, 1) \
             ON CONFLICT(hosting_id, hour, rule) DO UPDATE SET hits = hits + 1",
        )
        .bind(hosting_id)
        .bind(hour)
        .bind(&h.rule)
        .execute(&mut *tx)
        .await?;
        if hyperion_types::waf::counts_for_ban(&h.rule) {
            let minute = h.ts - h.ts.rem_euclid(60);
            sqlx::query(
                "INSERT INTO waf_ip_minute (hosting_id, ip, minute, hits) VALUES (?, ?, ?, 1) \
                 ON CONFLICT(hosting_id, ip, minute) DO UPDATE SET hits = hits + 1",
            )
            .bind(hosting_id)
            .bind(&h.ip)
            .bind(minute)
            .execute(&mut *tx)
            .await?;
        }
    }
    // Only the newest RECENT_CAP can survive the cap, so skip inserting the
    // rest of a flood rather than writing and deleting it.
    let skip = hits.len().saturating_sub(RECENT_CAP as usize);
    for h in &hits[skip..] {
        sqlx::query(
            "INSERT INTO waf_recent (hosting_id, ts, ip, rule, method, uri, ua) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(hosting_id)
        .bind(h.ts)
        .bind(truncate(&h.ip))
        .bind(truncate(&h.rule))
        .bind(truncate(&h.method))
        .bind(truncate(&h.uri))
        .bind(truncate(&h.ua))
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "DELETE FROM waf_recent WHERE hosting_id = ? AND id NOT IN \
         (SELECT id FROM waf_recent WHERE hosting_id = ? ORDER BY id DESC LIMIT ?)",
    )
    .bind(hosting_id)
    .bind(hosting_id)
    .bind(RECENT_CAP)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Hits per rule since `since` (hour-granular: the hour containing `since`
/// counts whole), most-hit first.
pub async fn totals(
    pool: &SqlitePool,
    hosting_id: &str,
    since: i64,
) -> Result<Vec<WafRuleCount>, StateError> {
    let hour = since - since.rem_euclid(3600);
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT rule, SUM(hits) AS n FROM waf_hits_hourly \
         WHERE hosting_id = ? AND hour >= ? GROUP BY rule ORDER BY n DESC, rule",
    )
    .bind(hosting_id)
    .bind(hour)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(rule, hits)| WafRuleCount { rule, hits })
        .collect())
}

/// The newest `limit` refusals, newest first.
pub async fn recent(
    pool: &SqlitePool,
    hosting_id: &str,
    limit: i64,
) -> Result<Vec<WafHit>, StateError> {
    let rows: Vec<(i64, String, String, String, String, String)> = sqlx::query_as(
        "SELECT ts, ip, rule, method, uri, ua FROM waf_recent \
         WHERE hosting_id = ? ORDER BY id DESC LIMIT ?",
    )
    .bind(hosting_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(ts, ip, rule, method, uri, ua)| WafHit {
            ts,
            ip,
            rule,
            method,
            uri,
            ua,
        })
        .collect())
}

/// Callers with at least `threshold` ban-counted hits since `since`.
pub async fn ip_offenders(
    pool: &SqlitePool,
    hosting_id: &str,
    since: i64,
    threshold: u32,
) -> Result<Vec<String>, StateError> {
    let minute = since - since.rem_euclid(60);
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT ip FROM waf_ip_minute WHERE hosting_id = ? AND minute >= ? \
         GROUP BY ip HAVING SUM(hits) >= ? ORDER BY ip",
    )
    .bind(hosting_id)
    .bind(minute)
    .bind(threshold as i64)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(ip,)| ip).collect())
}

/// Forget the per-IP counts of one caller on one hosting, once it has been
/// banned — otherwise the same hits would re-trigger a ban the moment the
/// first one expires.
pub async fn clear_ip(pool: &SqlitePool, hosting_id: &str, ip: &str) -> Result<(), StateError> {
    sqlx::query("DELETE FROM waf_ip_minute WHERE hosting_id = ? AND ip = ?")
        .bind(hosting_id)
        .bind(ip)
        .execute(pool)
        .await?;
    Ok(())
}

/// Drop rows past their retention.
pub async fn prune(pool: &SqlitePool, now: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM waf_hits_hourly WHERE hour < ?")
        .bind(now - HOURLY_KEEP_SECS)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM waf_ip_minute WHERE minute < ?")
        .bind(now - IP_MINUTE_KEEP_SECS)
        .execute(pool)
        .await?;
    Ok(())
}

/// Everything recorded for one hosting (hosting delete).
pub async fn delete_hosting(pool: &SqlitePool, hosting_id: &str) -> Result<(), StateError> {
    for table in ["waf_hits_hourly", "waf_recent", "waf_ip_minute"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE hosting_id = ?"))
            .bind(hosting_id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    fn hit(ts: i64, ip: &str, rule: &str) -> WafHit {
        WafHit {
            ts,
            ip: ip.into(),
            rule: rule.into(),
            method: "GET".into(),
            uri: "/x".into(),
            ua: "ua".into(),
        }
    }

    #[tokio::test]
    async fn records_read_back_by_rule_and_newest_first() {
        let pool = open_memory().await.expect("open");
        let t = 1_800_000_000;
        record(
            &pool,
            "h1",
            &[
                hit(t, "1.1.1.1", "probe_args"),
                hit(t + 1, "1.1.1.1", "probe_args"),
                hit(t + 2, "2.2.2.2", "xmlrpc"),
            ],
        )
        .await
        .expect("record");
        let tot = totals(&pool, "h1", t - 10).await.expect("totals");
        assert_eq!(
            tot,
            vec![
                WafRuleCount {
                    rule: "probe_args".into(),
                    hits: 2
                },
                WafRuleCount {
                    rule: "xmlrpc".into(),
                    hits: 1
                },
            ]
        );
        let rec = recent(&pool, "h1", 10).await.expect("recent");
        assert_eq!(rec.len(), 3);
        assert_eq!(rec[0].rule, "xmlrpc", "newest first");
        assert!(totals(&pool, "h2", 0).await.expect("other").is_empty());
    }

    #[tokio::test]
    async fn recent_is_capped_and_fields_truncated() {
        let pool = open_memory().await.expect("open");
        let long = "a".repeat(5000);
        let mut hits: Vec<WafHit> = (0..(RECENT_CAP + 50))
            .map(|i| hit(1_800_000_000 + i, "1.1.1.1", "probe_args"))
            .collect();
        hits.last_mut().expect("last").uri = long;
        record(&pool, "h1", &hits).await.expect("record");
        record(&pool, "h1", &[hit(1_800_001_000, "1.1.1.1", "dotfiles")])
            .await
            .expect("record");
        let rec = recent(&pool, "h1", 1000).await.expect("recent");
        assert_eq!(rec.len() as i64, RECENT_CAP);
        assert_eq!(rec[1].uri.len(), FIELD_MAX);
        // Totals still count the whole flood, not just what was kept.
        let tot = totals(&pool, "h1", 0).await.expect("totals");
        assert_eq!(tot[0].hits, RECENT_CAP + 50);
    }

    #[tokio::test]
    async fn offenders_count_only_ban_rules_inside_the_window() {
        let pool = open_memory().await.expect("open");
        let t = 1_800_000_000;
        let mut hits = Vec::new();
        for i in 0..5 {
            hits.push(hit(t + i, "1.1.1.1", "probe_args"));
            hits.push(hit(t + i, "2.2.2.2", "xmlrpc"));
            hits.push(hit(t + i, "3.3.3.3", "geo"));
            hits.push(hit(t - 7200 + i, "4.4.4.4", "probe_args"));
        }
        record(&pool, "h1", &hits).await.expect("record");
        let off = ip_offenders(&pool, "h1", t - 600, 5).await.expect("off");
        assert_eq!(off, vec!["1.1.1.1".to_string()]);
        clear_ip(&pool, "h1", "1.1.1.1").await.expect("clear");
        assert!(ip_offenders(&pool, "h1", t - 600, 5)
            .await
            .expect("off")
            .is_empty());
    }

    #[tokio::test]
    async fn prune_and_delete_hosting() {
        let pool = open_memory().await.expect("open");
        let t = 1_800_000_000;
        record(&pool, "h1", &[hit(t, "1.1.1.1", "probe_args")])
            .await
            .expect("r");
        prune(&pool, t + HOURLY_KEEP_SECS + 7200)
            .await
            .expect("prune");
        assert!(totals(&pool, "h1", 0).await.expect("t").is_empty());
        assert!(ip_offenders(&pool, "h1", 0, 1).await.expect("o").is_empty());
        assert_eq!(recent(&pool, "h1", 10).await.expect("r").len(), 1);
        delete_hosting(&pool, "h1").await.expect("del");
        assert!(recent(&pool, "h1", 10).await.expect("r").is_empty());
    }

    #[tokio::test]
    async fn waf_level_round_trips_through_the_hostings_row() {
        let pool = open_memory().await.expect("open");
        let suid = crate::system_users::insert(&pool, "u1", 1042, "/home/u1", "/bin/bash", 1)
            .await
            .expect("user");
        let hid = hyperion_types::HostingId::new_v7();
        crate::hostings::insert(&pool, &hid, "ex.cz", suid, None, "/x", 1, None)
            .await
            .expect("hosting");
        let mut opts = hyperion_types::VhostOptions::default();
        opts.set_waf_level(hyperion_types::waf::WafLevel::Strict);
        opts.waf_overrides = r#"{"xmlrpc":false,"bogus":true}"#.into();
        opts.canonical_host = "non-www".into();
        crate::hostings::set_vhost_options(&pool, &hid, &opts, None, 2)
            .await
            .expect("set");
        let back = crate::hostings::get_by_id(&pool, &hid)
            .await
            .expect("get")
            .expect("row")
            .vhost_options;
        assert_eq!(back.waf_level, "strict");
        assert!(back.waf_enabled);
        assert_eq!(
            back.waf_overrides, r#"{"xmlrpc":false}"#,
            "junk dropped on write"
        );
        assert_eq!(
            back.canonical_host, "non-www",
            "neighbouring bind unshifted"
        );

        // A legacy writer: empty level, bool on ⇒ stored as standard.
        let legacy = hyperion_types::VhostOptions {
            waf_enabled: true,
            ..Default::default()
        };
        crate::hostings::set_vhost_options(&pool, &hid, &legacy, Some("hash"), 3)
            .await
            .expect("set");
        let back = crate::hostings::get_by_id(&pool, &hid)
            .await
            .expect("get")
            .expect("row")
            .vhost_options;
        assert_eq!(back.waf_level, "standard");
        assert!(back.waf_enabled);
    }
}
