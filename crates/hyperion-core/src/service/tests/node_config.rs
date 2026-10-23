//! Tests for `service::node_config`.

use super::*;

/// REPRODUCTION of an operator report: "I edited the report template but
/// the hosting's preview did not change."
///
/// The existing test above writes agent.toml by hand. An operator does not
/// — they save the Settings form, which goes through `agent_config_update`
/// with exactly what a browser posts: a multi-line textarea, CRLF line
/// endings and all. This walks that path end to end, then previews.
#[tokio::test]
async fn a_template_saved_through_the_settings_form_reaches_the_preview() {
    let tmp = tempfile::tempdir().expect("tmp");
    let toml = tmp.path().join("agent.toml");
    // A realistic agent.toml that already has other sections in it.
    std::fs::write(&toml, b"[notifications]\nslack_template = \"{message}\"\n")
        .expect("write agent.toml");

    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks()).with_agent_config_path(toml.clone());
    s.create(req("pece.cz")).await.expect("create");
    let detail = s
        .get(HostingSelector::Domain(
            Domain::parse("pece.cz").expect("parse"),
        ))
        .await
        .expect("get");

    // Exactly what a <textarea> posts.
    let template = "Dobry den,\r\n\r\nreport pro {domain}.\r\n{uptime}\r\n";
    let mut fields = std::collections::BTreeMap::new();
    fields.insert(
        "care_report_body_template".to_string(),
        template.to_string(),
    );
    s.agent_config_update("notifications".to_string(), fields)
        .await
        .expect("save through the settings path");

    let written = std::fs::read_to_string(&toml).expect("read back");
    let mail = s
        .care_report_preview(HostingSelector::Id(detail.id.clone()))
        .await
        .expect("preview");
    assert!(
            mail.body.contains("report pro pece.cz."),
            "the saved template must reach the preview.\n--- agent.toml ---\n{written}\n--- body ---\n{}",
            mail.body
        );
}

/// The Settings pages read `[email]` and `[slack]` through
/// `agent_config_view`, which must report the FILE: with the relay off the
/// boot copy is empty (so the form came back blank and a save wrote the
/// blanks over the stored host), and right after a save the agent has not
/// restarted yet (so the page under "Saved" showed the old values).
#[tokio::test]
async fn config_view_reports_email_and_slack_as_written_in_agent_toml() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("agent.toml");
    std::fs::write(
            &path,
            "[email]\nenabled = false\nsmtp_host = \"relay.example.cz\"\nsmtp_user = \"u\"\n\
             smtp_password = \"s3cret\"\nfrom_address = \"noreply@example.cz\"\n\
             default_to = \"ops@example.cz\"\n\n[slack]\ndefault_webhook = \"https://hooks.slack.com/x\"\n",
        )
        .expect("seed");
    let pool = open_memory().await.expect("open");
    let mut mocks = happy_mocks();
    mocks
        .expect_nginx_user()
        .returning(|| "www-data".to_string());
    // No boot copy at all: the relay is off, so the agent has none.
    let s = svc(pool, mocks)
        .with_email(None, None)
        .with_agent_config_path(path.clone());

    let v = s.agent_config_view("h", "v").await.expect("view");
    assert!(!v.email.enabled);
    assert_eq!(v.email.smtp_host, "relay.example.cz");
    assert_eq!(v.email.smtp_user, "u");
    assert!(v.email.smtp_password_set);
    assert_eq!(v.email.from_address, "noreply@example.cz");
    assert_eq!(v.email.default_to, "ops@example.cz");
    // Absent keys read as what the agent would use.
    assert_eq!(v.email.smtp_port, 587);
    assert_eq!(v.email.security, "starttls");
    assert!(v.slack.default_webhook_set);

    // Disconnect writes an empty webhook; the view says so at once.
    let mut f = std::collections::BTreeMap::new();
    f.insert("default_webhook".to_string(), String::new());
    s.agent_config_update("slack".to_string(), f)
        .await
        .expect("disconnect");
    let v = s.agent_config_view("h", "v").await.expect("view");
    assert!(!v.slack.default_webhook_set);
}

/// The Settings form's round trip: a save lands in agent.toml under
/// `[fail2ban]`, and the allow-list refuses both unknown keys and any
/// value `Fail2banConfig::sanitized` would silently override at boot.
#[tokio::test]
async fn fail2ban_section_round_trips_and_refuses_values_the_agent_would_clamp() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("agent.toml");
    // No [fail2ban] table yet — the common case, and `ensure_table` has
    // to create it rather than error.
    std::fs::write(&path, "[agent]\nsocket_path = \"/run/hyperion.sock\"\n").expect("seed");
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks()).with_agent_config_path(path.clone());

    let save = |pairs: Vec<(&'static str, &'static str)>| {
        let fields: std::collections::BTreeMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        s.agent_config_update("fail2ban".to_string(), fields)
    };

    save(vec![
        ("enabled", "true"),
        ("window_secs", "900"),
        ("ban_ttl_secs", "7200"),
        ("http_threshold", "6"),
    ])
    .await
    .expect("save");

    let doc: toml_edit::DocumentMut = std::fs::read_to_string(&path)
        .expect("read back")
        .parse()
        .expect("parse");
    assert_eq!(doc["fail2ban"]["enabled"].as_bool(), Some(true));
    assert_eq!(doc["fail2ban"]["window_secs"].as_integer(), Some(900));
    assert_eq!(doc["fail2ban"]["ban_ttl_secs"].as_integer(), Some(7200));
    assert_eq!(doc["fail2ban"]["http_threshold"].as_integer(), Some(6));
    // Untouched sections survive the rewrite.
    assert!(doc.get("agent").is_some());

    // `ban_ttl_secs = 0` is the dangerous one: `ban_add` reads ttl ≤ 0 as
    // no-expiry, so it would sit in the file looking like a PERMANENT
    // node-wide ban while the running agent used 60 s.
    assert!(save(vec![("ban_ttl_secs", "0")]).await.is_err());
    // A threshold of 1 bans on the first mistyped password.
    assert!(save(vec![("http_threshold", "1")]).await.is_err());
    assert!(save(vec![("window_secs", "0")]).await.is_err());
    assert!(save(vec![("ssh_threshold", "not a number")]).await.is_err());
    // The allow-list still rejects anything it doesn't know.
    assert!(save(vec![("nft_table", "hyperion")]).await.is_err());

    // A rejected save writes nothing — the good values are still there.
    let after: toml_edit::DocumentMut = std::fs::read_to_string(&path)
        .expect("read back")
        .parse()
        .expect("parse");
    assert_eq!(after["fail2ban"]["ban_ttl_secs"].as_integer(), Some(7200));
    assert_eq!(after["fail2ban"]["http_threshold"].as_integer(), Some(6));
    assert!(after["fail2ban"].get("nft_table").is_none());
}
