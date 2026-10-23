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
