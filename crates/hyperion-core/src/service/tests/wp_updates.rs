//! Tests for `service::wp_updates`.

use super::*;

/// A WordPress site the sweep has not reached yet used to be absent —
/// indistinguishable from a site that is not WordPress at all.
#[tokio::test]
async fn the_updates_list_shows_wordpress_sites_the_sweep_has_not_reached() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let site = hosting_for_packages(&s, "kos.cz").await;
    wordpress::record_install(&pool, &site.id, "https://kos.cz", "6.6.2", "h", 1)
        .await
        .expect("wp row");

    let list = s.vuln_findings_list().await.expect("list");
    assert_eq!(
        list.len(),
        1,
        "an install with no scan is still a row: {list:?}"
    );
    assert_eq!(list[0].domain, "kos.cz");
    assert_eq!(list[0].scanned_at, 0, "never scanned");
    assert_eq!(list[0].auto_update, Some(true), "an absent switch means on");
}

/// A sweep that cannot read the site must not wipe what was known, and
/// must not pass for a fresh result either.
#[tokio::test]
async fn a_scan_that_cannot_read_the_site_keeps_the_last_findings_and_says_why() {
    let pool = open_memory().await.expect("open");
    let mut a = package_mocks();
    let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let c = calls.clone();
    a.expect_wp_plugin_list().returning(move |_, _| {
        if c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Ok((
                vec![wp_plugin("woocommerce", "8.7.0", "9.0.1")],
                "6.5.3".into(),
            ))
        } else {
            Err(AdapterError::Other(
                "Error establishing a database connection".into(),
            ))
        }
    });
    let t = Arc::new(std::sync::atomic::AtomicU32::new(0));
    a.expect_wp_theme_list().returning(move |_, _| {
        if t.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Ok((vec![], "6.5.3".into()))
        } else {
            Err(AdapterError::Other("theme list failed".into()))
        }
    });
    a.expect_wp_core_check_update().returning(|_, _| {
        Ok(vec![hyperion_types::WpCoreUpdate {
            version: "6.6.2".into(),
            update_type: "major".into(),
        }])
    });
    let s = svc(pool.clone(), a);
    let site = hosting_for_packages(&s, "kos.cz").await;

    let good = s
        .wp_vuln_scan(HostingSelector::Id(site.id.clone()))
        .await
        .expect("scan");
    assert!(!good.feed_unavailable);
    assert!(good.core_checked, "core was asked");
    assert_eq!(good.core_version, "6.5.3");
    assert_eq!(good.core_updates.len(), 1);

    let bad = s
        .wp_vuln_scan(HostingSelector::Id(site.id.clone()))
        .await
        .expect("scan");
    assert!(bad.feed_unavailable);
    assert!(bad.error.contains("database connection"), "{}", bad.error);

    let list = s.vuln_findings_list().await.expect("list");
    assert_eq!(list.len(), 1);
    let row = &list[0];
    assert_eq!(
        row.findings.len(),
        1,
        "the last good findings stay: {row:?}"
    );
    assert!(row.scanned_at > 0, "the good scan's time stays");
    assert!(row.failed_at >= row.scanned_at, "the failure is newer");
    assert!(row.error.contains("database connection"), "{}", row.error);
    assert_eq!(row.core_updates.len(), 1, "core from the good scan stays");
}

/// Whether an update applies itself depends on the site's switch and on
/// the pause map — both read when the list is built, so Resume or a
/// flipped switch shows at once rather than after the next sweep.
#[tokio::test]
async fn the_updates_list_carries_the_auto_update_switch_and_paused_plugins() {
    let pool = open_memory().await.expect("open");
    let s = svc(
        pool.clone(),
        wp_scan_mocks(vec![wp_plugin("acf-pro", "6.2.0", "6.3.1")], vec![]),
    );
    let site = hosting_for_packages(&s, "kos.cz").await;
    s.wp_vuln_scan(HostingSelector::Id(site.id.clone()))
        .await
        .expect("scan");

    let now = now_secs();
    let mut skips = crate::wp_updates::SkipMap::new();
    skips.insert(
        "acf-pro".into(),
        crate::wp_updates::AutoUpdateSkip {
            fail_count: 2,
            first_failed_at: now - 86_400,
            last_failed_at: now - 60,
            paused_until: now + 1_000,
            last_error: "Download failed. Unauthorized".into(),
        },
    );
    for (key, value) in [
        ("wp_auto_update", "off".to_string()),
        (
            "wp_update_skips",
            serde_json::to_string(&skips).expect("skips"),
        ),
    ] {
        hyperion_state::hosting_kv::set(&pool, site.id.as_str(), key, &value, now)
            .await
            .expect("kv");
    }

    let list = s.vuln_findings_list().await.expect("list");
    let row = &list[0];
    assert_eq!(row.auto_update, Some(false));
    let f = &row.findings[0];
    assert!(f.auto_updatable, "same-major");
    assert_eq!(f.auto_update_failures, 2);
    assert!(f.auto_update_paused_until > now, "paused");
    assert!(f.auto_update_error.contains("Unauthorized"));
}

/// The scan now saves itself, so the sweep must read yesterday's majors
/// BEFORE scanning — read after, every major looks already known and no
/// alert ever goes out.
#[tokio::test]
async fn the_sweep_alerts_a_new_major_once_even_though_the_scan_saves_itself() {
    let pool = open_memory().await.expect("open");
    let s = svc(
        pool.clone(),
        wp_scan_mocks(vec![wp_plugin("woocommerce", "8.7.0", "9.0.1")], vec![]),
    );
    let site = hosting_for_packages(&s, "kos.cz").await;
    wordpress::record_install(&pool, &site.id, "https://kos.cz", "6.5.3", "h", 1)
        .await
        .expect("wp row");

    assert_eq!(
        s.wp_vuln_scan_tick().await.expect("tick"),
        1,
        "first sight of a major alerts"
    );
    assert_eq!(
        s.wp_vuln_scan_tick().await.expect("tick"),
        0,
        "a standing major does not alert again"
    );
    let list = s.vuln_findings_list().await.expect("list");
    assert_eq!(list[0].findings.len(), 1);
    assert_eq!(list[0].failed_at, 0, "the sweep worked");
}
