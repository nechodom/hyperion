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
use hyperion_types::waf::{
    WafBatch, WafHit, WafHourCount, WafIpActivity, WafRuleCount, WafRuleSample,
};
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

/// Record one aggregated batch for one hosting, in one transaction: an
/// upsert per (hour, rule) and per (address, minute), plus the newest
/// refusals verbatim. A flood of a million refusals is a few hundred rows.
pub async fn record(
    pool: &SqlitePool,
    hosting_id: &str,
    batch: &WafBatch,
) -> Result<(), StateError> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for ((hour, rule), hits) in &batch.hourly {
        sqlx::query(
            "INSERT INTO waf_hits_hourly (hosting_id, hour, rule, hits) VALUES (?, ?, ?, ?) \
             ON CONFLICT(hosting_id, hour, rule) DO UPDATE SET hits = hits + excluded.hits",
        )
        .bind(hosting_id)
        .bind(hour)
        .bind(truncate(rule))
        .bind(hits)
        .execute(&mut *tx)
        .await?;
    }
    for ((ip, minute), hits) in &batch.ip_minute {
        sqlx::query(
            "INSERT INTO waf_ip_minute (hosting_id, ip, minute, hits) VALUES (?, ?, ?, ?) \
             ON CONFLICT(hosting_id, ip, minute) DO UPDATE SET hits = hits + excluded.hits",
        )
        .bind(hosting_id)
        .bind(ip)
        .bind(minute)
        .bind(hits)
        .execute(&mut *tx)
        .await?;
    }
    for h in &batch.recent {
        sqlx::query(
            "INSERT INTO waf_recent (hosting_id, ts, ip, rule, method, uri, ua, browser) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(hosting_id)
        .bind(h.ts)
        .bind(truncate(&h.ip))
        .bind(truncate(&h.rule))
        .bind(truncate(&h.method))
        .bind(truncate(&h.uri))
        .bind(truncate(&h.ua))
        .bind(h.browser)
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
    #[allow(clippy::type_complexity)]
    let rows: Vec<(i64, String, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT ts, ip, rule, method, uri, ua, browser FROM waf_recent \
         WHERE hosting_id = ? ORDER BY id DESC LIMIT ?",
    )
    .bind(hosting_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(ts, ip, rule, method, uri, ua, browser)| WafHit {
            ts,
            ip,
            rule,
            method,
            uri,
            ua,
            browser,
            ..Default::default()
        })
        .collect())
}

/// Hits per (hosting, rule) since `since`, every hosting on the node at
/// once (hour-granular like [`totals`]).
pub async fn totals_by_site(
    pool: &SqlitePool,
    since: i64,
) -> Result<Vec<(String, WafRuleCount)>, StateError> {
    let hour = since - since.rem_euclid(3600);
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT hosting_id, rule, SUM(hits) AS n FROM waf_hits_hourly \
         WHERE hour >= ? GROUP BY hosting_id, rule ORDER BY hosting_id, n DESC, rule",
    )
    .bind(hour)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(h, rule, hits)| (h, WafRuleCount { rule, hits }))
        .collect())
}

/// Hits per UTC hour and rule since `since`, every hosting together,
/// oldest first.
pub async fn hourly_all(pool: &SqlitePool, since: i64) -> Result<Vec<WafHourCount>, StateError> {
    let hour = since - since.rem_euclid(3600);
    let rows: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT hour, rule, SUM(hits) FROM waf_hits_hourly \
         WHERE hour >= ? GROUP BY hour, rule ORDER BY hour, rule",
    )
    .bind(hour)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(hour, rule, hits)| WafHourCount { hour, rule, hits })
        .collect())
}

/// Per (hosting, rule), what the kept recent refusals look like: how many,
/// how many from a real browser, from how many addresses, and the newest
/// one's request line.
pub async fn rule_samples(pool: &SqlitePool) -> Result<Vec<WafRuleSample>, StateError> {
    // `MAX(id)` makes SQLite take the bare columns (ts, method, uri) from
    // the row holding that maximum — the newest refusal of the group.
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, String, i64, i64, i64, i64, i64, String, String)> = sqlx::query_as(
        "SELECT hosting_id, rule, COUNT(*), SUM(browser), COUNT(DISTINCT ip), MAX(id), \
                ts, method, uri \
         FROM waf_recent GROUP BY hosting_id, rule",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(hosting_id, rule, hits, browser, ips, _, last_ts, method, uri)| WafRuleSample {
                hosting_id,
                rule,
                hits,
                browser,
                ips,
                last_ts,
                method,
                uri,
            },
        )
        .collect())
}

/// The `limit` addresses with the most kept recent refusals, busiest first.
pub async fn top_ips(pool: &SqlitePool, limit: i64) -> Result<Vec<WafIpActivity>, StateError> {
    // GROUP_CONCAT(DISTINCT …) joins with ','; neither a hosting id (a
    // UUID) nor a rule tag (cleaned to [a-z0-9_]) can contain one.
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, i64, i64, String, String, i64)> = sqlx::query_as(
        "SELECT ip, COUNT(*) AS n, SUM(browser), GROUP_CONCAT(DISTINCT hosting_id), \
                GROUP_CONCAT(DISTINCT rule), MAX(ts) \
         FROM waf_recent GROUP BY ip ORDER BY n DESC, ip LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let split = |s: String| -> Vec<String> {
        let mut v: Vec<String> = s
            .split(',')
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        v.sort();
        v
    };
    Ok(rows
        .into_iter()
        .map(|(ip, hits, browser, sites, rules, last_ts)| WafIpActivity {
            ip,
            hits,
            browser,
            sites: split(sites),
            rules: split(rules),
            last_ts,
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

/// Drop rows past their retention. `ban_window_secs` is the auto-ban
/// window: per-address counts older than twice it can never matter again,
/// and keeping them only grows the table a flood fills.
pub async fn prune(pool: &SqlitePool, now: i64, ban_window_secs: i64) -> Result<(), StateError> {
    sqlx::query("DELETE FROM waf_hits_hourly WHERE hour < ?")
        .bind(now - HOURLY_KEEP_SECS)
        .execute(pool)
        .await?;
    let ip_keep = ban_window_secs
        .saturating_mul(2)
        .clamp(600, IP_MINUTE_KEEP_SECS);
    sqlx::query("DELETE FROM waf_ip_minute WHERE minute < ?")
        .bind(now - ip_keep)
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
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn records_read_back_by_rule_and_newest_first() {
        let pool = open_memory().await.expect("open");
        let t = 1_800_000_000;
        record(
            &pool,
            "h1",
            &WafBatch::from_hits([
                hit(t, "1.1.1.1", "probe_args"),
                hit(t + 1, "1.1.1.1", "probe_args"),
                hit(t + 2, "2.2.2.2", "xmlrpc"),
            ]),
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
        // A second batch adds to the same rows rather than replacing them.
        record(
            &pool,
            "h1",
            &WafBatch::from_hits([hit(t + 3, "1.1.1.1", "probe_args")]),
        )
        .await
        .expect("record");
        let tot = totals(&pool, "h1", t - 10).await.expect("totals");
        assert_eq!(
            tot[0],
            WafRuleCount {
                rule: "probe_args".into(),
                hits: 3
            }
        );
        assert_eq!(
            ip_offenders(&pool, "h1", t - 10, 3).await.expect("off"),
            vec!["1.1.1.1".to_string()]
        );
        let rec = recent(&pool, "h1", 10).await.expect("recent");
        assert_eq!(rec.len(), 4);
        assert_eq!(rec[0].ts, t + 3, "newest first");
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
        record(&pool, "h1", &WafBatch::from_hits(hits))
            .await
            .expect("record");
        record(
            &pool,
            "h1",
            &WafBatch::from_hits([hit(1_800_001_000, "1.1.1.1", "dotfiles")]),
        )
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
        record(&pool, "h1", &WafBatch::from_hits(hits))
            .await
            .expect("record");
        let off = ip_offenders(&pool, "h1", t - 600, 5).await.expect("off");
        assert_eq!(off, vec!["1.1.1.1".to_string()]);
        clear_ip(&pool, "h1", "1.1.1.1").await.expect("clear");
        assert!(ip_offenders(&pool, "h1", t - 600, 5)
            .await
            .expect("off")
            .is_empty());
    }

    #[tokio::test]
    async fn overview_queries_read_back_across_sites() {
        let pool = open_memory().await.expect("open");
        let t = 1_800_000_000; // on an hour boundary
        let b = |ts, ip: &str, rule: &str, uri: &str, browser| WafHit {
            uri: uri.into(),
            browser,
            ..hit(ts, ip, rule)
        };
        record(
            &pool,
            "h1",
            &WafBatch::from_hits([
                b(t, "1.1.1.1", "probe_args", "/old", false),
                b(t + 10, "2.2.2.2", "probe_args", "/new", true),
                b(t + 3600, "2.2.2.2", "xmlrpc", "/xmlrpc.php", true),
            ]),
        )
        .await
        .expect("h1");
        record(
            &pool,
            "h2",
            &WafBatch::from_hits([b(t + 20, "1.1.1.1", "dotfiles", "/.env", false)]),
        )
        .await
        .expect("h2");

        let by_site = totals_by_site(&pool, t).await.expect("by site");
        assert_eq!(by_site.len(), 3);
        assert_eq!(by_site[0].0, "h1");
        assert_eq!(by_site[0].1.rule, "probe_args");
        assert_eq!(by_site[0].1.hits, 2);

        let hourly = hourly_all(&pool, t).await.expect("hourly");
        assert_eq!(
            hourly
                .iter()
                .map(|h| (h.hour - t, h.rule.as_str(), h.hits))
                .collect::<Vec<_>>(),
            vec![
                (0, "dotfiles", 1),
                (0, "probe_args", 2),
                (3600, "xmlrpc", 1)
            ]
        );
        assert!(hourly_all(&pool, t + 7200).await.expect("later").is_empty());

        let samples = rule_samples(&pool).await.expect("samples");
        let probe = samples
            .iter()
            .find(|s| s.hosting_id == "h1" && s.rule == "probe_args")
            .expect("probe sample");
        assert_eq!((probe.hits, probe.browser, probe.ips), (2, 1, 2));
        assert_eq!(probe.uri, "/new", "the newest refusal's request");
        assert_eq!(probe.last_ts, t + 10);

        let ips = top_ips(&pool, 10).await.expect("ips");
        assert_eq!(ips[0].ip, "1.1.1.1", "ties break by address");
        assert_eq!(ips[0].sites, vec!["h1".to_string(), "h2".to_string()]);
        assert_eq!(
            ips[0].rules,
            vec!["dotfiles".to_string(), "probe_args".to_string()]
        );
        assert_eq!(ips[1].ip, "2.2.2.2");
        assert_eq!((ips[1].hits, ips[1].browser), (2, 2));
        assert_eq!(top_ips(&pool, 1).await.expect("cap").len(), 1);
    }

    #[tokio::test]
    async fn prune_and_delete_hosting() {
        let pool = open_memory().await.expect("open");
        let t = 1_800_000_000;
        record(
            &pool,
            "h1",
            &WafBatch::from_hits([hit(t, "1.1.1.1", "probe_args")]),
        )
        .await
        .expect("r");
        prune(&pool, t + HOURLY_KEEP_SECS + 7200, 600)
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
