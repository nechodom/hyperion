//! Tests for `service::wp_integrity`.

use super::*;

#[tokio::test]
async fn integrity_scan_storage_round_trips() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), MockAdapterPort::new());
    let mut result = assemble_integrity_result(
        integrity::CoreChecksums {
            checked: true,
            modified: vec!["wp-includes/version.php".into()],
            ..Default::default()
        },
        plugins_verified(),
        vec![hyperion_types::WpMalwareHit {
            path: "/home/x/htdocs/wp-content/uploads/a.php".into(),
            signature: "Php.Trojan.Webshell-1".into(),
        }],
        true,
        3,
        true,
    );
    result.scanned_at = 1_700_000_000;
    let stored = StoredIntegrityScan {
        scanned_at: 1_700_000_000,
        clamav_at: 1_699_990_000,
        clamav_failed_at: 0,
        result: result.clone(),
    };
    s.set_stored_integrity_scan("H1", &stored).await;

    let back = s.stored_integrity_scan("H1").await.expect("stored");
    assert_eq!(back.scanned_at, 1_700_000_000);
    // The ClamAV timestamp is the daily-cadence clock — losing it
    // would re-walk every docroot on every scan.
    assert_eq!(back.clamav_at, 1_699_990_000);
    assert_eq!(back.result, result);
    assert_eq!(back.result.core_modified, vec!["wp-includes/version.php"]);
    assert_eq!(back.result.malware.len(), 1);

    // Absent key and unparseable value both read as "never scanned"
    // rather than exploding a live sweep.
    assert!(s.stored_integrity_scan("H2").await.is_none());
    let _ = hyperion_state::hosting_kv::set(&pool, "H3", INTEGRITY_KV_KEY, "{oops", 1).await;
    assert!(s.stored_integrity_scan("H3").await.is_none());
}

#[tokio::test]
async fn integrity_scan_on_non_wordpress_hosting_is_could_not_check() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("static-site.cz")).await.expect("create");
    let detail = s
        .get(HostingSelector::Domain(
            Domain::parse("static-site.cz").expect("parse"),
        ))
        .await
        .expect("get");

    let r = s
        .wp_integrity_scan(HostingSelector::Id(detail.id.clone()))
        .await
        .expect("scan returns a result, not an error");
    assert_eq!(r.error.as_deref(), Some(INTEGRITY_ERR_NOT_WORDPRESS));
    assert!(!r.wp_cli_ok, "nothing was verified");
    assert!(!r.core_ok);
    assert!(
        !r.is_clean(),
        "a site we never looked at must never read as clean"
    );
    assert_eq!(r.total_findings(), 0);
    // Nothing to show on the integrity dashboard for a static site —
    // and nothing stored means the sweep can tell it apart from a
    // WordPress site whose scan failed.
    assert!(
        hyperion_state::hosting_kv::get(&pool, detail.id.as_str(), INTEGRITY_KV_KEY)
            .await
            .expect("kv get")
            .is_none()
    );
    assert!(
        s.integrity_findings_list().await.expect("list").is_empty(),
        "non-WordPress hostings never reach the dashboard"
    );
}

#[test]
fn integrity_result_without_wp_cli_is_not_clean() {
    // wp-cli missing / WordPress unbootable: every probe came back
    // unchecked. Zero findings here means "we found nothing out"
    // — not "there is nothing wrong".
    let r = assemble_integrity_result(
        integrity::CoreChecksums::default(),
        integrity::PluginChecksums::default(),
        Vec::new(),
        false,
        0,
        false,
    );
    assert!(!r.wp_cli_ok);
    assert!(!r.core_ok);
    assert!(!r.is_clean(), "unchecked is never clean");
    assert_eq!(r.total_findings(), 0);
    assert_eq!(r.plugins_checked, 0);

    // Same, but ClamAV DID run and found nothing. Still not clean:
    // one working signal doesn't vouch for the other.
    let r = assemble_integrity_result(
        integrity::CoreChecksums::default(),
        integrity::PluginChecksums::default(),
        Vec::new(),
        true,
        0,
        false,
    );
    assert!(!r.is_clean(), "clamav alone can't clear a site");
}

#[test]
fn integrity_clean_requires_every_signal_to_have_run() {
    // Both signals ran, both empty — the only shape that is clean.
    let r = assemble_integrity_result(
        core_verified(),
        plugins_verified(),
        Vec::new(),
        true,
        4,
        true,
    );
    assert!(r.wp_cli_ok && r.core_ok && r.is_clean());
    assert_eq!(r.plugins_checked, 4);
    assert_eq!(r.plugins_total, 4);

    // No scanner installed on the node → "not scanned", not "clean".
    let r = assemble_integrity_result(
        core_verified(),
        plugins_verified(),
        Vec::new(),
        false,
        4,
        true,
    );
    assert!(r.wp_cli_ok, "checksums still verified");
    assert!(!r.is_clean(), "a missing scanner is not a pass");
}

#[test]
fn integrity_empty_plugin_list_does_not_poison_wp_cli_ok() {
    // A site with zero plugins gives wp-cli nothing to verify; its
    // silence is not a failure...
    let r = assemble_integrity_result(
        core_verified(),
        integrity::PluginChecksums::default(),
        Vec::new(),
        true,
        0,
        true,
    );
    assert!(r.wp_cli_ok, "nothing to verify is not a failed check");

    // ...but a FAILED enumeration reports zero plugins too, and that
    // must not be laundered into "verified".
    let r = assemble_integrity_result(
        core_verified(),
        integrity::PluginChecksums::default(),
        Vec::new(),
        true,
        0,
        false,
    );
    assert!(!r.wp_cli_ok, "couldn't list plugins ⇒ couldn't check");
    assert!(!r.is_clean());
}

#[test]
fn integrity_unverifiable_premium_plugins_are_not_findings() {
    // Elementor Pro publishes no checksums. That is "we could not
    // check this plugin", never "this plugin is compromised" — the
    // difference between a useful panel and one the operator mutes.
    let r = assemble_integrity_result(
        core_verified(),
        integrity::PluginChecksums {
            checked: true,
            failed: Vec::new(),
            unknown: vec!["elementor-pro".into(), "wp-rocket".into()],
        },
        Vec::new(),
        true,
        6,
        true,
    );
    assert_eq!(r.total_findings(), 0, "unknown is not a finding");
    assert_eq!(r.plugins_checked, 4, "6 installed − 2 unverifiable");
    assert_eq!(r.plugins_unknown.len(), 2);
    assert!(r.is_clean());
}

#[test]
fn integrity_finding_keys_separate_buckets_and_drive_the_new_diff() {
    let mut yesterday = assemble_integrity_result(
        integrity::CoreChecksums {
            checked: true,
            missing: vec!["wp-admin/includes/misc.php".into()],
            ..Default::default()
        },
        plugins_verified(),
        Vec::new(),
        true,
        1,
        true,
    );
    yesterday.scanned_at = 1;
    let prior = integrity_finding_keys(&yesterday);

    // Same file, now MODIFIED rather than missing, plus a webshell:
    // two genuinely new events, not a repeat of yesterday's alert.
    let today = assemble_integrity_result(
        integrity::CoreChecksums {
            checked: true,
            modified: vec!["wp-admin/includes/misc.php".into()],
            ..Default::default()
        },
        plugins_verified(),
        vec![hyperion_types::WpMalwareHit {
            path: "/home/x/htdocs/wp-content/uploads/a.php".into(),
            signature: "Php.Trojan.Webshell-1".into(),
        }],
        true,
        1,
        true,
    );
    let new_keys: Vec<String> = integrity_finding_keys(&today)
        .difference(&prior)
        .cloned()
        .collect();
    assert_eq!(new_keys.len(), 2);

    // A standing finding produces no new keys — that's what keeps the
    // nightly sweep from re-alerting on the same file forever.
    assert_eq!(
        integrity_finding_keys(&yesterday)
            .difference(&prior)
            .count(),
        0
    );
}

/// A trashed site keeps its stored scan — un-trashing restores the
/// history — but must not appear on the cluster dashboards.
///
/// It used to: `list()` is `WHERE state != 'trashed'`, the lookup fell
/// back to an empty domain, and the row was pushed anyway. The operator
/// got a line with a node, a count and a timestamp and no site name:
/// nothing to click and nothing to act on, for a site that is deliberately
/// not running.
#[tokio::test]
async fn a_trashed_site_leaves_no_nameless_row_on_the_cluster_lists() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let site = hosting_for_packages(&s, "kos.cz").await;

    // A stored scan of each kind, as the nightly sweep leaves behind.
    let vuln = serde_json::to_string(&StoredVulnScan {
        scanned_at: 1,
        ..Default::default()
    })
    .expect("encode vuln");
    let integrity = serde_json::to_string(&StoredIntegrityScan {
        scanned_at: 1,
        clamav_at: 0,
        clamav_failed_at: 0,
        result: hyperion_types::WpIntegrityScanResult::default(),
    })
    .expect("encode integrity");
    for (key, json) in [("vuln_scan", vuln), (INTEGRITY_KV_KEY, integrity)] {
        hyperion_state::hosting_kv::set(&pool, site.id.as_str(), key, &json, now_secs())
            .await
            .expect("store scan");
    }
    assert_eq!(
        s.vuln_findings_list().await.expect("vulns").len(),
        1,
        "a live site with a stored scan is listed"
    );
    assert_eq!(
        s.integrity_findings_list().await.expect("integrity").len(),
        1,
        "a live site with a stored integrity scan is listed"
    );

    hyperion_state::hostings::mark_trashed(&pool, &site.id, now_secs())
        .await
        .expect("trash");

    let vulns = s.vuln_findings_list().await.expect("vulns");
    assert!(
        vulns.is_empty(),
        "a trashed site must leave no row at all, let alone a nameless one: {vulns:?}"
    );
    let integrity = s.integrity_findings_list().await.expect("integrity");
    assert!(
        integrity.is_empty(),
        "same rule on the integrity list: {integrity:?}"
    );

    // The record itself survives, so un-trashing brings the history back.
    assert!(
        hyperion_state::hosting_kv::get(&pool, site.id.as_str(), "vuln_scan")
            .await
            .expect("kv read")
            .is_some(),
        "the stored scan must not be deleted, only hidden"
    );
}

/// A failed ClamAV pass holds the next one off for an hour — the card scans
/// on view, and a failure that repeats otherwise re-walked the whole docroot
/// on every page load — and a good one for the usual daily cadence.
#[test]
fn clamav_pass_backs_off_after_a_failure() {
    use super::super::wp_integrity::{
        clamav_pass_held_off, CLAMAV_FAILED_RETRY_SECS, CLAMAV_MIN_INTERVAL_SECS,
    };
    let now = 1_700_000_000;
    let rec = |clamav_at, clamav_failed_at| StoredIntegrityScan {
        scanned_at: now,
        clamav_at,
        clamav_failed_at,
        result: Default::default(),
    };
    assert!(!clamav_pass_held_off(None, now), "never ran");
    assert!(!clamav_pass_held_off(Some(&rec(0, 0)), now));
    assert!(
        clamav_pass_held_off(Some(&rec(now - 60, 0)), now),
        "fresh pass"
    );
    assert!(!clamav_pass_held_off(
        Some(&rec(now - CLAMAV_MIN_INTERVAL_SECS, 0)),
        now
    ));
    assert!(
        clamav_pass_held_off(Some(&rec(0, now - 60)), now),
        "just failed"
    );
    assert!(!clamav_pass_held_off(
        Some(&rec(0, now - CLAMAV_FAILED_RETRY_SECS)),
        now
    ));
}
