//! Tests for `service::log_retention` and the audit purge it now drives.

use super::*;

fn cfg_dir(toml: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(&cfg, toml).expect("write agent.toml");
    (dir, cfg)
}

#[test]
fn read_log_retention_defaults_to_thirty_days_and_reads_the_section() {
    assert_eq!(
        super::super::log_retention::read_log_retention(None),
        hyperion_types::log_retention::LogRetention::default()
    );
    let (_d, cfg) = cfg_dir(
        "[cluster]\naudit_retention_days = 0\n[log_retention]\nweb_days = 7\nsystem_days = 90\n",
    );
    let r = super::super::log_retention::read_log_retention(Some(&cfg));
    assert_eq!(
        (r.web_days, r.system_days, r.audit_days, r.bans_days),
        (7, 90, 30, 30)
    );
}

#[test]
fn log_retention_fields_parse_in_range_only() {
    let ok = |k: &str, v: &str| {
        let mut f = std::collections::BTreeMap::new();
        f.insert(k.to_string(), v.to_string());
        super::parse_agent_section_fields("log_retention", &f).is_ok()
    };
    for c in hyperion_types::log_retention::CLASSES {
        assert!(ok(c.key, "30"), "{}", c.key);
        assert!(ok(c.key, "1"), "{}", c.key);
        assert!(ok(c.key, "3650"), "{}", c.key);
        assert!(!ok(c.key, "0"), "{}: no 'forever'", c.key);
        assert!(!ok(c.key, "3651"), "{}", c.key);
        assert!(!ok(c.key, "x"), "{}", c.key);
    }
    assert!(
        !ok("audit_retention_days", "30"),
        "not a key of this section"
    );
}

#[test]
fn log_retention_is_synced_to_every_node() {
    assert!(crate::cluster_sync::SYNCED_SECTIONS.contains(&"log_retention"));
    for c in hyperion_types::log_retention::CLASSES {
        assert!(crate::cluster_sync::is_synced_key("log_retention", c.key));
    }
    assert!(!crate::cluster_sync::is_synced_key(
        "log_retention",
        "something_else"
    ));
}

#[tokio::test]
async fn the_audit_log_moves_from_forever_to_thirty_days_unless_a_window_was_chosen() {
    let pool = open_memory().await.expect("open");
    let now = now_secs();
    for ts in [now - 40 * 86_400, now - 10 * 86_400] {
        hyperion_state::audit::append(
            &pool,
            hyperion_state::audit::AppendReq {
                ts,
                actor_uid: 0,
                actor_label: "t",
                action: "test.row",
                target: None,
                payload_json: "{}",
                result: "ok",
            },
        )
        .await
        .expect("append");
    }
    // A window someone chose under the old key is kept.
    let (_d, cfg) = cfg_dir("[cluster]\naudit_retention_days = 60\n");
    let s = svc(pool.clone(), MockAdapterPort::new()).with_agent_config_path(cfg);
    s.audit_retention_tick().await.expect("tick");
    assert_eq!(hyperion_state::audit::count(&pool).await.unwrap(), 2);
    // The old default 0 ("forever") is now 30 days.
    let (_d, cfg) = cfg_dir("[cluster]\naudit_retention_days = 0\n");
    let s = svc(pool.clone(), MockAdapterPort::new()).with_agent_config_path(cfg);
    s.audit_retention_tick().await.expect("tick");
    assert_eq!(hyperion_state::audit::count(&pool).await.unwrap(), 1);
    // And what is left still verifies.
    hyperion_state::audit::verify_chain(&pool)
        .await
        .expect("chain");
}

#[tokio::test]
async fn the_tick_rotates_site_logs_and_prunes_every_table() {
    let pool = open_memory().await.expect("open");
    let home = tempfile::tempdir().expect("home");
    let (_d, cfg) = cfg_dir("[log_retention]\nweb_days = 5\nfirewall_days = 10\n");
    let mut mocks = happy_mocks();
    mocks
        .expect_apply_log_retention()
        .withf(|r| r.web_days == 5 && r.firewall_days == 10 && r.system_days == 30)
        .times(1)
        .returning(|_| ());
    let s = svc(pool.clone(), mocks)
        .with_agent_config_path(cfg)
        .with_paths(HostingPaths {
            home_root: home.path().display().to_string(),
            ..HostingPaths::default()
        });
    s.create(req("logs.cz")).await.expect("create");
    let h = s
        .get(HostingSelector::Domain(
            Domain::parse("logs.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let logs = home
        .path()
        .join(&h.system_user)
        .join(&h.domain)
        .join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("access.log"), "203.0.113.7 - - [x] \"GET /\"\n").unwrap();
    std::fs::write(logs.join("error.log.5.gz"), "x").unwrap();

    let now = now_secs();
    let old = now - 40 * 86_400;
    let recent = now - 86_400;
    // WAF samples.
    let hit = |ts| hyperion_types::waf::WafHit {
        ts,
        ip: "203.0.113.7".into(),
        rule: "scanner_ua".into(),
        method: "GET".into(),
        uri: "/x".into(),
        ua: "ua".into(),
        ..Default::default()
    };
    hyperion_state::waf::record(
        &pool,
        h.id.as_str(),
        &hyperion_types::waf::WafBatch::from_hits(vec![hit(old), hit(recent)]),
    )
    .await
    .expect("waf");
    // Ban history: one ended long ago, one in force.
    hyperion_state::bans::add_or_refresh(&pool, "198.51.100.1", None, "t", "auto", old, old + 60)
        .await
        .unwrap();
    hyperion_state::bans::reap_expired(&pool, now)
        .await
        .unwrap();
    hyperion_state::bans::add_or_refresh(&pool, "198.51.100.2", None, "t", "manual", old, 0)
        .await
        .unwrap();
    // Email log.
    for at in [old, recent] {
        hyperion_state::email_log::append(
            &pool, None, "a@b.cz", "s", "b", "test", "ok", None, None, at,
        )
        .await
        .unwrap();
    }
    // A panel session last seen long ago.
    hyperion_state::web_sessions::insert(&pool, "sid-old", 1, Some("192.0.2.1"), Some("ua"), old)
        .await
        .ok();

    let out = s.log_retention_tick().await;
    assert_eq!(out.site_logs_rotated, 1);
    assert_eq!(out.site_logs_removed, 1, "copy 5 is past a 5-day window");
    assert!(logs.join("access.log.1").exists());
    assert_eq!(std::fs::metadata(logs.join("access.log")).unwrap().len(), 0);
    assert_eq!(out.waf_samples, 1);
    assert_eq!(out.bans, 1);
    assert!(hyperion_state::bans::is_active(&pool, "198.51.100.2", now)
        .await
        .unwrap());
    assert_eq!(out.emails, 1);
    assert_eq!(
        hyperion_state::email_log::list(&pool, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    // The sessions table may refuse a row for a user that does not exist;
    // when it took it, its address is gone now.
    let rows = hyperion_state::web_sessions::list_for_user(&pool, 1, 10)
        .await
        .unwrap();
    assert!(rows.iter().all(|r| r.ip.is_none()));
}

/// The care report counts a period's updates from the audit log and its
/// attacks from the ban history, and calls the section "not measured" if
/// retention cut into the period. Retention waits for the report.
#[tokio::test]
async fn retention_never_cuts_into_a_care_report_period_not_reported_yet() {
    let pool = open_memory().await.expect("open");
    // Monthly report, period open for 40 days (the relay refuses).
    let (s, detail) = site_owing_a_care_report(&pool).await;
    let (_d, cfg) = cfg_dir("");
    let s = s.with_agent_config_path(cfg);
    let now = now_secs();
    let floor = s
        .care_report_open_floor(now)
        .await
        .expect("a period is open");
    assert!(floor <= now - 40 * 86_400 + 5 && floor >= now - 40 * 86_400 - 5);

    // An update 35 days ago: past the 30-day window, inside the period.
    for ts in [now - 45 * 86_400, now - 35 * 86_400] {
        hyperion_state::audit::append(
            &pool,
            hyperion_state::audit::AppendReq {
                ts,
                actor_uid: 0,
                actor_label: "t",
                action: "wp.plugin.action",
                target: Some(detail.id.as_str()),
                payload_json: r#"{"action":"update"}"#,
                result: "ok",
            },
        )
        .await
        .expect("append");
    }
    // A ban that began and ended inside the period, 35 days ago.
    hyperion_state::bans::add_or_refresh(
        &pool,
        "198.51.100.9",
        Some(detail.id.as_str()),
        "t",
        "auto",
        now - 35 * 86_400,
        now - 35 * 86_400 + 60,
    )
    .await
    .unwrap();
    hyperion_state::bans::reap_expired(&pool, now)
        .await
        .unwrap();

    s.audit_retention_tick().await.expect("tick");
    let left = hyperion_state::audit::list(&pool, 1000)
        .await
        .expect("list");
    let ts: Vec<i64> = left.iter().map(|r| r.ts).collect();
    assert!(
        ts.contains(&(now - 35 * 86_400)),
        "inside the open period: kept"
    );
    assert!(!ts.contains(&(now - 45 * 86_400)), "before it: purged");

    let mut mocks = MockAdapterPort::new();
    mocks.expect_apply_log_retention().returning(|_| ());
    let s2 = svc(pool.clone(), mocks).with_agent_config_path(_d.path().join("agent.toml"));
    assert_eq!(s2.log_retention_tick().await.bans, 0);
    assert!(
        hyperion_state::reports::attacks_blocked(&pool, detail.id.as_str(), floor, now)
            .await
            .unwrap()
            >= 1
    );
}
