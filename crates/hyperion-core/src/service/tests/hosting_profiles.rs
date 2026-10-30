//! Tests for `service::hosting_profiles`.

use super::*;

#[test]
fn validate_profile_rejects_bad_numbers() {
    use super::validate_profile;
    let base = || hyperion_types::ProfileInput {
        name: "Plan".into(),
        php_memory_mb: 256,
        php_max_exec_secs: 30,
        php_max_children: 10,
        php_max_requests: 500,
        db_max_connections: 50,
        ..Default::default()
    };
    // A clean profile passes.
    assert!(validate_profile(base()).is_ok());
    // Zero/negative worker + memory counts are rejected.
    assert!(validate_profile(hyperion_types::ProfileInput {
        php_max_children: 0,
        ..base()
    })
    .is_err());
    assert!(validate_profile(hyperion_types::ProfileInput {
        php_memory_mb: -1,
        ..base()
    })
    .is_err());
    assert!(validate_profile(hyperion_types::ProfileInput {
        db_max_connections: 0,
        ..base()
    })
    .is_err());
    // Negative caps rejected; soft > hard rejected.
    assert!(validate_profile(hyperion_types::ProfileInput {
        disk_hard_mb: Some(-5),
        ..base()
    })
    .is_err());
    assert!(validate_profile(hyperion_types::ProfileInput {
        disk_soft_mb: Some(2048),
        disk_hard_mb: Some(1024),
        ..base()
    })
    .is_err());
    // soft <= hard passes.
    assert!(validate_profile(hyperion_types::ProfileInput {
        disk_soft_mb: Some(1024),
        disk_hard_mb: Some(2048),
        ..base()
    })
    .is_ok());
    // Malformed expiry-warning-offsets rejected; a clean CSV passes.
    assert!(validate_profile(hyperion_types::ProfileInput {
        expiry_warning_offsets: "30,foo,1".into(),
        ..base()
    })
    .is_err());
    assert!(validate_profile(hyperion_types::ProfileInput {
        expiry_warning_offsets: "30,7,1".into(),
        ..base()
    })
    .is_ok());
    // Closed enums: bad db engine + bad quota action rejected.
    assert!(validate_profile(hyperion_types::ProfileInput {
        default_db_engine: Some("mysql".into()),
        ..base()
    })
    .is_err());
    assert!(validate_profile(hyperion_types::ProfileInput {
        quota_exceed_action: "suspendd".into(),
        ..base()
    })
    .is_err());
    assert!(validate_profile(hyperion_types::ProfileInput {
        default_db_engine: Some("postgres".into()),
        quota_exceed_action: "suspend".into(),
        ..base()
    })
    .is_ok());
}

/// A profile's alert e-mails are added to the monitor's, never replace them.
#[test]
fn merge_alert_emails_appends_and_dedupes() {
    use super::merge_alert_emails;
    let add = vec!["it@klient.cz".to_string(), "OPS@us.cz".to_string()];
    assert_eq!(
        merge_alert_emails("ops@us.cz", &add).as_deref(),
        Some("ops@us.cz,it@klient.cz")
    );
    assert_eq!(
        merge_alert_emails("", &add).as_deref(),
        Some("it@klient.cz,OPS@us.cz")
    );
    assert_eq!(merge_alert_emails(" ", &[]), None);
}

/// A price typed on the hosting outlives a profile re-apply only when the
/// operator pinned it; unpinned, the profile's price comes back.
#[tokio::test]
async fn a_pinned_hosting_price_survives_a_profile_re_apply() {
    let pool = open_memory().await.expect("open");
    // profile_apply pushes the profile's limits onto the site.
    let mut a = happy_mocks();
    a.expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("cena.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("cena.cz").unwrap());
    let profile = s
        .profile_create(hyperion_types::ProfileInput {
            name: "Basic".into(),
            php_memory_mb: 256,
            php_max_exec_secs: 30,
            php_max_children: 10,
            php_max_requests: 500,
            db_max_connections: 50,
            price_minor: Some(19_900),
            price_currency: Some("CZK".into()),
            price_interval: Some("monthly".into()),
            ..Default::default()
        })
        .await
        .expect("profile");
    s.profile_apply(sel.clone(), profile.id, true, None)
        .await
        .expect("apply");

    let set = s
        .hosting_price_set(
            sel.clone(),
            Some(240_000),
            Some(" czk ".into()),
            Some("yearly".into()),
            true,
        )
        .await
        .expect("price set");
    assert_eq!(set.pretty_price(), "2400.00 CZK/year");
    assert!(set.price_pinned);
    assert_eq!(set.profile_id, Some(profile.id), "still on the profile");
    let yearly_clock = set.next_billing_at.expect("clock");

    let again = s
        .profile_apply(sel.clone(), profile.id, true, None)
        .await
        .expect("re-apply");
    assert_eq!(
        again.pretty_price(),
        "2400.00 CZK/year",
        "pinned price kept"
    );
    assert!(again.price_pinned);
    assert_eq!(again.next_billing_at, Some(yearly_clock), "clock not moved");

    s.hosting_price_set(
        sel.clone(),
        Some(240_000),
        Some("CZK".into()),
        Some("yearly".into()),
        false,
    )
    .await
    .expect("unpin");
    let back = s
        .profile_apply(sel.clone(), profile.id, true, None)
        .await
        .expect("re-apply unpinned");
    assert_eq!(
        back.pretty_price(),
        "199.00 CZK/month",
        "profile price back"
    );
    assert!(!back.price_pinned);
}

/// Applying a profile puts its alert channels on the site's uptime monitor:
/// the Slack webhook and the alert e-mails. E-mails are ADDED to the ones
/// already there (re-applying never duplicates them, never drops one), and
/// nothing else on the monitor moves.
#[tokio::test]
async fn profile_apply_carries_slack_and_alert_emails_onto_the_monitor() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("kanaly.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("kanaly.cz").unwrap());
    s.monitor_set(
        sel.clone(),
        true,
        Some("/health".into()),
        Some(120),
        Some(3),
        Some("ops@us.cz".into()),
        None,
        false,
        None,
    )
    .await
    .expect("monitor set");
    let profile = s
        .profile_create(hyperion_types::ProfileInput {
            name: "Kanaly".into(),
            php_memory_mb: 256,
            php_max_exec_secs: 30,
            php_max_children: 10,
            php_max_requests: 500,
            db_max_connections: 50,
            slack_webhook: Some("https://hooks.slack.com/services/T/B/x".into()),
            alert_emails: "it@klient.cz, OPS@us.cz".into(),
            ..Default::default()
        })
        .await
        .expect("profile");

    for _ in 0..2 {
        s.profile_apply(sel.clone(), profile.id, true, None)
            .await
            .expect("apply");
    }

    let (cfg, _) = s.monitor_get(sel.clone()).await.expect("monitor get");
    assert_eq!(
        cfg.alert_email.as_deref(),
        Some("ops@us.cz,it@klient.cz"),
        "merged, deduped, kept the existing one"
    );
    assert!(cfg.alert_slack_webhook_set, "webhook copied");
    assert!(cfg.enabled, "on/off untouched");
    assert_eq!(cfg.url_path, "/health");
    assert_eq!(cfg.interval_secs, 120);
    assert_eq!(cfg.alert_after_fails, 3);

    // A profile with no channels leaves the monitor's channels alone.
    let bare = s
        .profile_create(hyperion_types::ProfileInput {
            name: "Bare".into(),
            php_memory_mb: 256,
            php_max_exec_secs: 30,
            php_max_children: 10,
            php_max_requests: 500,
            db_max_connections: 50,
            ..Default::default()
        })
        .await
        .expect("bare profile");
    s.profile_apply(sel.clone(), bare.id, true, None)
        .await
        .expect("apply bare");
    let (cfg, _) = s.monitor_get(sel).await.expect("monitor get");
    assert_eq!(cfg.alert_email.as_deref(), Some("ops@us.cz,it@klient.cz"));
    assert!(cfg.alert_slack_webhook_set, "webhook kept");
}
