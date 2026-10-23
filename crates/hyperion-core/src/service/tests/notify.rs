//! Tests for `service::notify`.

use super::*;

#[tokio::test]
async fn worker_parks_admin_alerts_in_the_outbox() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("node-id.json");
    tokio::fs::write(&p, b"{}").await.unwrap();
    let s = svc_with_state_file(Some(p)).await;
    s.notify_admins("error", "RO fs", "body", "/services", "system.rofs")
        .await;
    let out = s.notifications_outbox(0, 10).await.unwrap();
    assert_eq!(
        out.len(),
        1,
        "a worker has no admins — the alert must be parked"
    );
    assert_eq!(out[0].title, "RO fs");
}

#[tokio::test]
async fn master_ingests_node_alerts_once_and_sanitises_them() {
    use hyperion_state::web_users::WebRole;
    let s = svc_with_state_file(None).await;
    let admin = seed_web_user(&s, "boss", WebRole::Admin).await;
    let op = seed_web_user(&s, "op", WebRole::Operator).await;
    let item = |id: i64, href: &str, sev: &str| hyperion_types::NotificationOutboxItem {
        id,
        severity: sev.into(),
        title: "t".into(),
        body: "b".into(),
        href: href.into(),
        kind: "system.rofs".into(),
        created_at: 5,
    };
    let items = vec![
        item(1, "/hostings/a.cz", "error"),
        item(2, "//evil.example/x", "bogus"),
        item(3, "https://evil.example", "warn"),
    ];
    assert_eq!(
        s.notifications_ingest("w1", items.clone()).await.unwrap(),
        3
    );
    // Collected again (lost reply, panel restart): nothing new.
    assert_eq!(s.notifications_ingest("w1", items).await.unwrap(), 0);
    assert_eq!(s.notifications_node_cursor("w1").await.unwrap(), 3);

    let feed = s.notifications_feed(admin, 10).await.unwrap();
    assert_eq!(feed.unread_total, 3);
    let by_id = |oid: &str| feed.items.iter().find(|n| n.href == oid).cloned();
    assert!(by_id("/hostings/a.cz").is_some());
    assert_eq!(
        feed.items.iter().filter(|n| n.href == "/").count(),
        2,
        "off-panel links are replaced, never shown"
    );
    assert!(feed.items.iter().all(|n| n.node_id == "w1"));
    assert!(feed
        .items
        .iter()
        .all(|n| ["error", "warn", "info"].contains(&n.severity.as_str())));
    assert_eq!(s.notifications_feed(op, 10).await.unwrap().items.len(), 0);
}

/// A site that keeps running out of PHP workers is ONE card per admin,
/// rewritten with the latest count — raised here or collected from a
/// worker — not a new card every few hours.
#[tokio::test]
async fn repeated_php_worker_alerts_rewrite_one_card_per_site() {
    use hyperion_state::web_users::WebRole;
    let s = svc_with_state_file(None).await;
    let me = seed_web_user(&s, "boss", WebRole::Admin).await;
    s.notify_admins("warn", "full", "1x", "/", "php_workers:a.cz")
        .await;
    s.notify_admins("warn", "full", "6x", "/", "php_workers:a.cz")
        .await;
    s.notify_admins("warn", "full", "2x", "/", "php_workers:b.cz")
        .await;
    let item = |id: i64, body: &str| hyperion_types::NotificationOutboxItem {
        id,
        severity: "warn".into(),
        title: "full".into(),
        body: body.into(),
        href: "/".into(),
        kind: "php_workers:c.cz".into(),
        created_at: 5,
    };
    s.notifications_ingest("w1", vec![item(1, "1x"), item(2, "22x")])
        .await
        .unwrap();
    let feed = s.notifications_feed(me, 10).await.unwrap();
    let bodies: Vec<_> = feed.items.iter().map(|n| n.body.as_str()).collect();
    assert_eq!(feed.items.len(), 3, "{bodies:?}");
    assert!(bodies.contains(&"6x") && bodies.contains(&"2x") && bodies.contains(&"22x"));
    assert_eq!(s.notifications_node_cursor("w1").await.unwrap(), 2);
}

#[tokio::test]
async fn search_and_mark_by_topic_fold_per_site_kinds() {
    use hyperion_state::web_users::WebRole;
    let s = svc_with_state_file(None).await;
    let me = seed_web_user(&s, "boss", WebRole::Admin).await;
    s.notify_admins("error", "a", "", "/", "cert.renew_failed:a.cz")
        .await;
    s.notify_admins("warn", "b", "", "/", "cert.renewed_late:b.cz")
        .await;
    s.notify_admins("error", "c", "", "/", "monitor.down:c.cz")
        .await;
    s.notify_admins("info", "d", "", "/", "something.new").await;
    let f = |topic: &str| hyperion_types::NotificationSearchFilter {
        topic: topic.into(),
        ..Default::default()
    };
    let r = s.notifications_search(me, f("certs")).await.unwrap();
    assert_eq!(r.items.len(), 2);
    assert_eq!(r.counts.all, 2);
    let topics: Vec<_> = r
        .topics
        .iter()
        .map(|t| (t.topic.as_str(), t.total))
        .collect();
    assert_eq!(topics, [("uptime", 1), ("certs", 2), ("other", 1)]);
    assert!(s
        .notifications_search(me, f("trash"))
        .await
        .unwrap()
        .items
        .is_empty());

    // "Mark these read" under a topic must not touch the other topics.
    assert_eq!(
        s.notifications_mark_matching(me, f("certs")).await.unwrap(),
        2
    );
    assert_eq!(s.notifications_feed(me, 10).await.unwrap().unread_total, 2);
}

#[tokio::test]
async fn is_internal_href_refuses_other_sites() {
    assert!(is_internal_href("/hostings/a.cz#ssl"));
    for bad in [
        "//evil.cz",
        "https://evil.cz",
        "/\\evil.cz",
        "javascript:alert(1)",
        "",
    ] {
        assert!(!is_internal_href(bad), "{bad}");
    }
}

#[test]
fn customer_letter_templates_default_to_empty_meaning_builtin() {
    let tmp = tempfile::tempdir().expect("dir");
    // No file at all, and a file with no [notifications] section: both
    // leave the letters empty, i.e. the built-in wording.
    assert!(read_notifications_section(None)
        .care_report_body_template
        .is_empty());
    let bare = tmp.path().join("bare.toml");
    std::fs::write(&bare, b"[cluster]\npanel_hostname = \"p\"\n").expect("write");
    let v = read_notifications_section(Some(bare.as_path()));
    assert!(v.care_report_body_template.is_empty());
    assert!(v.expiry_warning_body_template.is_empty());
    // The three wrapper templates keep their pass-through defaults.
    assert_eq!(v.slack_template, "{message}");
    // A customised letter reads back verbatim; the OTHER letter is
    // still empty (no accidental cross-fill).
    let set = tmp.path().join("set.toml");
    std::fs::write(
        &set,
        b"[notifications]\ncare_report_body_template = \"Hi {domain}\\n{uptime}\"\n",
    )
    .expect("write");
    let v = read_notifications_section(Some(set.as_path()));
    assert_eq!(v.care_report_body_template, "Hi {domain}\n{uptime}");
    assert!(v.expiry_warning_body_template.is_empty());
}
