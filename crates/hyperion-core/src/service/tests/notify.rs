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

// ---------------------------------------------------------------------------
// The webhook POST: options on stdin, never on a command line.
// ---------------------------------------------------------------------------

/// The directive each line of a curl config starts with.
fn config_directives(config: &str) -> Vec<String> {
    config
        .lines()
        .map(|l| l.split([' ', '=']).next().unwrap_or("").to_string())
        .collect()
}

/// A body, an address and a pin with quotes, newlines and a directive of
/// their own in them stay values: nothing becomes a further option.
#[test]
fn a_webhook_post_cannot_smuggle_options_through_its_values() {
    let evil = "x\"\noutput = \"/etc/cron.d/pwned\"\nurl = \"http://evil\"";
    let config = post_json_config(
        &format!("https://example.test/{evil}"),
        &[format!("example.test:443:1.2.3.4{evil}")],
        &format!("{{\"text\":\"{evil}\"}}"),
    );
    let known = [
        "silent",
        "show-error",
        "insecure",
        "max-redirs",
        "proto",
        "max-time",
        "resolve",
        "header",
        "request",
        "data-raw",
        "url",
    ];
    for d in config_directives(&config) {
        assert!(
            known.contains(&d.as_str()),
            "unexpected option {d:?}:\n{config}"
        );
    }
}

/// Every command line on this machine, as any local user reads them.
fn command_lines() -> String {
    let out = std::process::Command::new("ps")
        .args(["-axo", "args="])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A webhook address (Slack's is its whole credential) and the payload are
/// not on curl's command line while it runs.
#[tokio::test]
async fn a_webhook_post_keeps_address_and_payload_off_the_command_line() {
    if !std::path::Path::new("/usr/bin/curl").exists() {
        return;
    }
    let site = spawn_test_site().await;
    site.set(SiteMode::Slow(4));
    let tag = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let url = format!("https://{}/services/HOOK-{tag}", site.host());
    let body = format!("{{\"text\":\"PAYLOAD-{tag}\"}}");
    let post = tokio::spawn(async move { post_json_pinned(&url, &[], &body).await });
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let seen = command_lines();
    assert!(
        !seen.contains(&format!("HOOK-{tag}")),
        "the address is on a command line"
    );
    assert!(
        !seen.contains(&format!("PAYLOAD-{tag}")),
        "the payload is on a command line"
    );
    assert!(
        seen.contains("curl --config -"),
        "the post was not running when the command lines were read"
    );
    post.await.expect("post").expect("delivered");
}

/// What curl really sends: a one-shot plain-HTTP receiver returns the
/// request it got.
async fn receive_one_request() -> (u16, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.expect("accept");
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = tcp.read(&mut chunk).await.expect("read");
            got.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&got).into_owned();
            if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                let want: usize = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if rest.len() >= want {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        let _ = tcp
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        String::from_utf8_lossy(&got).into_owned()
    });
    (port, task)
}

/// The body arrives byte for byte, whatever it holds, as a POST of JSON.
#[tokio::test]
async fn a_webhook_post_delivers_the_body_whole() {
    if !std::path::Path::new("/usr/bin/curl").exists() {
        return;
    }
    for body in [
        r#"{"text":"*Title*\nline \"quoted\" \\ back, ünïcode ✓"}"#.to_string(),
        "@/etc/hostname".to_string(),
    ] {
        let (port, got) = receive_one_request().await;
        post_json_pinned(&format!("http://127.0.0.1:{port}/hook"), &[], &body)
            .await
            .expect("delivered");
        let request = got.await.expect("request");
        assert!(request.starts_with("POST /hook "), "{request}");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "{request}"
        );
        assert!(
            request.ends_with(&body),
            "the body arrived whole: {request}"
        );
    }
}

/// A transport failure is still an error, and a refused address is
/// still refused before curl runs.
#[tokio::test]
async fn a_webhook_post_reports_a_failure_and_still_refuses_internal_addresses() {
    if !std::path::Path::new("/usr/bin/curl").exists() {
        return;
    }
    // Nothing listens on port 1.
    let err = post_json_pinned("http://127.0.0.1:1/hook", &[], "{}")
        .await
        .expect_err("refused connection");
    assert!(err.starts_with("curl exit "), "{err}");
    let err = http_post_json("http://169.254.169.254/latest", "{}")
        .await
        .expect_err("metadata address");
    assert!(
        !err.starts_with("curl exit "),
        "the guard answers first: {err}"
    );
}
