//! Tests for `service::wp_integrity` and `service::scan_queue`.

use super::*;
use hyperion_adapters::sitescan::discover::{Component, Discovery};
use hyperion_adapters::sitescan::manifest::{
    ComponentKey, ComponentKind, Manifest, ManifestSource,
};
use hyperion_adapters::sitescan::runner::{WorkerJob, WorkerReply};
use hyperion_adapters::sitescan::scan::{ScanMode, SiteScanOutcome, UpstreamResult};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex as StdMutex;

/// A native scan that compared core with its release and found nothing.
fn upstream_verified(plugins: i64) -> SiteScanOutcome {
    SiteScanOutcome {
        upstream: UpstreamResult {
            ran: true,
            ..Default::default()
        },
        coverage: hyperion_types::ScanCoverage {
            upstream_ran: true,
            plugins_verified: plugins,
            plugins_total: plugins,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn webshell_hit() -> hyperion_types::WpMalwareHit {
    hyperion_types::WpMalwareHit {
        path: "/home/x/htdocs/wp-content/uploads/a.php".into(),
        signature: "Php.Trojan.Webshell-1".into(),
    }
}

#[tokio::test]
async fn integrity_scan_storage_round_trips() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), MockAdapterPort::new());
    let mut outcome = upstream_verified(3);
    outcome.upstream.core_modified = vec!["wp-includes/version.php".into()];
    let mut result = assemble_integrity_result(outcome, vec![webshell_hit()], true, true);
    result.scanned_at = 1_700_000_000;
    let stored = StoredIntegrityScan {
        scanned_at: 1_700_000_000,
        clamav_at: 1_699_990_000,
        full_at: 1_699_000_000,
        result: result.clone(),
        ..Default::default()
    };
    s.set_stored_integrity_scan("H1", &stored).await;

    let back = s.stored_integrity_scan("H1").await.expect("stored");
    assert_eq!(back.scanned_at, 1_700_000_000);
    // The ClamAV timestamp is the daily-cadence clock — losing it
    // would re-walk every docroot on every scan.
    assert_eq!(back.clamav_at, 1_699_990_000);
    assert_eq!(back.full_at, 1_699_000_000);
    assert_eq!(back.result, result);
    assert_eq!(back.result.core_modified, vec!["wp-includes/version.php"]);
    assert_eq!(back.result.malware.len(), 1);

    // Absent key and unparseable value both read as "never scanned"
    // rather than exploding a live sweep.
    assert!(s.stored_integrity_scan("H2").await.is_none());
    let _ = hyperion_state::hosting_kv::set(&pool, "H3", INTEGRITY_KV_KEY, "{oops", 1).await;
    assert!(s.stored_integrity_scan("H3").await.is_none());
}

/// A site with no WordPress goes through the native scan like any other, but
/// has no release to compare with: never clean under the old verdict, and not a
/// "couldn't check" row on the dashboard either.
#[tokio::test]
async fn integrity_scan_on_non_wordpress_hosting_is_never_clean_and_stays_off_the_dashboard() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_site_scan_worker().returning(|job| match job {
        WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
            listed: 0,
            partial: false,
        },
        WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
        WorkerJob::Scan(_) => WorkerReply::Scan(SiteScanOutcome {
            coverage: hyperion_types::ScanCoverage {
                no_upstream: true,
                ..Default::default()
            },
            ..Default::default()
        }),
    });
    let s = svc(pool.clone(), a);
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
    assert!(r.native_scan_ran);
    assert!(r.coverage.no_upstream);
    assert!(!r.wp_cli_ok, "nothing was compared with a release");
    assert!(!r.core_ok);
    assert!(
        !r.is_clean(),
        "a site we never looked at must never read as clean"
    );
    assert_eq!(r.total_findings(), 0);
    assert!(
        s.stored_integrity_scan(detail.id.as_str()).await.is_some(),
        "the record is what the scheduler reads next time"
    );
    assert!(
        s.integrity_findings_list().await.expect("list").is_empty(),
        "non-WordPress hostings never reach the dashboard"
    );
}

#[test]
fn integrity_result_without_upstream_is_not_clean() {
    // Core couldn't be compared: broken install, unreadable version, or
    // wordpress.org out of reach. Zero findings here means "we found nothing
    // out", not "there is nothing wrong".
    let r = assemble_integrity_result(SiteScanOutcome::default(), Vec::new(), false, true);
    assert!(!r.wp_cli_ok);
    assert!(!r.core_ok);
    assert!(!r.is_clean(), "unchecked is never clean");
    assert_eq!(r.total_findings(), 0);
    assert_eq!(r.plugins_checked, 0);

    // Same, but ClamAV DID run and found nothing. Still not clean:
    // one working signal doesn't vouch for the other.
    let r = assemble_integrity_result(SiteScanOutcome::default(), Vec::new(), true, true);
    assert!(!r.is_clean(), "clamav alone can't clear a site");
}

#[test]
fn integrity_clean_requires_every_signal_to_have_run() {
    // Both signals ran, both empty: the only shape that is clean.
    let r = assemble_integrity_result(upstream_verified(4), Vec::new(), true, true);
    assert!(r.wp_cli_ok && r.core_ok && r.is_clean());
    assert_eq!(r.plugins_checked, 4);
    assert_eq!(r.plugins_total, 4);

    // No scanner installed on the node: "not scanned", not "clean".
    let r = assemble_integrity_result(upstream_verified(4), Vec::new(), false, true);
    assert!(r.wp_cli_ok, "checksums still verified");
    assert!(!r.is_clean(), "a missing scanner is not a pass");
}

#[test]
fn integrity_empty_plugin_list_does_not_poison_wp_cli_ok() {
    // A site with zero plugins gives nothing to verify; its silence is not a
    // failure...
    let r = assemble_integrity_result(upstream_verified(0), Vec::new(), true, true);
    assert!(r.wp_cli_ok, "nothing to verify is not a failed check");

    // ...but core not being compared reports zero plugins too, and that must
    // not be laundered into "verified".
    let r = assemble_integrity_result(SiteScanOutcome::default(), Vec::new(), true, true);
    assert!(!r.wp_cli_ok, "couldn't compare core: couldn't check");
    assert!(!r.is_clean());
}

#[test]
fn integrity_unverifiable_premium_plugins_are_not_findings() {
    // Elementor Pro publishes no checksums. That is "we could not check this
    // plugin", never "this plugin is compromised": the difference between a
    // useful panel and one the operator mutes.
    let mut outcome = upstream_verified(4);
    outcome.coverage.plugins_total = 6;
    outcome.upstream.plugins_unknown = vec!["elementor-pro".into(), "wp-rocket".into()];
    let r = assemble_integrity_result(outcome, Vec::new(), true, true);
    assert_eq!(r.total_findings(), 0, "unknown is not a finding");
    assert_eq!(r.plugins_checked, 4, "6 installed − 2 unverifiable");
    assert_eq!(r.plugins_total, 6);
    assert_eq!(r.plugins_unknown.len(), 2);
    assert!(r.is_clean());
}

/// Everything the reports and the dashboard read lands in the fields they
/// have always read, and the new layers beside them.
#[test]
fn scan_outcome_maps_onto_the_stored_fields() {
    let issue = |path: &str| hyperion_types::WpIntegrityPluginResult {
        source: None,
        slug: "akismet".into(),
        issues: vec![hyperion_types::WpIntegrityFileIssue {
            path: path.into(),
            message: "Checksum does not match".into(),
        }],
        ..Default::default()
    };
    let finding = |rel: &str| hyperion_types::SiteFileFinding {
        rel: rel.into(),
        severity: "high".into(),
        ..Default::default()
    };
    let outcome = SiteScanOutcome {
        upstream: UpstreamResult {
            ran: true,
            core_modified: vec!["wp-login.php".into()],
            core_unexpected: vec!["wp-admin/x.php".into()],
            core_missing: vec!["wp-admin/gone.php".into()],
            plugins_failed: vec![issue("akismet.php")],
            themes_failed: vec![issue("style.css")],
            plugins_unknown: vec!["elementor-pro".into()],
            themes_unknown: vec![],
        },
        findings: vec![finding("wp-content/uploads/a.php")],
        review: vec![finding("custom.php")],
        coverage: hyperion_types::ScanCoverage {
            plugins_verified: 2,
            plugins_total: 3,
            upstream_ran: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let r = assemble_integrity_result(outcome.clone(), vec![webshell_hit()], true, true);
    assert!(r.native_scan_ran);
    assert!(r.report_only);
    assert!(r.wp_cli_ok);
    assert!(!r.core_ok, "modified core is not ok");
    assert_eq!(r.core_modified, vec!["wp-login.php"]);
    assert_eq!(r.core_unexpected, vec!["wp-admin/x.php"]);
    assert_eq!(r.core_missing, vec!["wp-admin/gone.php"]);
    assert_eq!(r.plugins_failed, outcome.upstream.plugins_failed);
    assert_eq!(r.themes_failed, outcome.upstream.themes_failed);
    assert_eq!(r.plugins_unknown, vec!["elementor-pro"]);
    assert_eq!((r.plugins_checked, r.plugins_total), (2, 3));
    assert_eq!(r.findings, outcome.findings);
    assert_eq!(r.review, outcome.review);
    assert_eq!(r.coverage, outcome.coverage);
    assert_eq!(r.malware, vec![webshell_hit()]);
    assert!(r.clamav_available);
    // Missing alone leaves core "ok", as it did when wp-cli said so.
    let mut only_missing = upstream_verified(0);
    only_missing.upstream.core_missing = vec!["wp-admin/gone.php".into()];
    assert!(assemble_integrity_result(only_missing, Vec::new(), true, false).core_ok);
    let live = assemble_integrity_result(upstream_verified(0), Vec::new(), true, false);
    assert!(!live.report_only);
}

#[test]
fn integrity_finding_keys_separate_buckets_and_drive_the_new_diff() {
    let mut yesterday_scan = upstream_verified(1);
    yesterday_scan.upstream.core_missing = vec!["wp-admin/includes/misc.php".into()];
    let mut yesterday = assemble_integrity_result(yesterday_scan, Vec::new(), true, true);
    yesterday.scanned_at = 1;
    let prior = integrity_finding_keys(&yesterday);

    // Same file, now MODIFIED rather than missing, plus a webshell:
    // two genuinely new events, not a repeat of yesterday's alert.
    let mut today_scan = upstream_verified(1);
    today_scan.upstream.core_modified = vec!["wp-admin/includes/misc.php".into()];
    let today = assemble_integrity_result(today_scan, vec![webshell_hit()], true, true);
    let new_keys: Vec<String> = integrity_finding_keys(&today)
        .difference(&prior)
        .cloned()
        .collect();
    assert_eq!(new_keys.len(), 2);

    // A standing finding produces no new keys: that's what keeps the sweep
    // from re-alerting on the same file forever.
    assert_eq!(
        integrity_finding_keys(&yesterday)
            .difference(&prior)
            .count(),
        0
    );
}

/// A scan's finding in the bucket `kind` names, at `severity`.
fn file_finding(
    rel: &str,
    kind: hyperion_types::FindingKind,
    severity: &str,
) -> hyperion_types::SiteFileFinding {
    hyperion_types::SiteFileFinding {
        rel: rel.into(),
        kind,
        severity: severity.into(),
        rule_id: matches!(kind, hyperion_types::FindingKind::RuleHit).then(|| "php.eval".into()),
        ..Default::default()
    }
}

fn native_result(report_only: bool) -> hyperion_types::WpIntegrityScanResult {
    hyperion_types::WpIntegrityScanResult {
        native_scan_ran: true,
        report_only,
        scanned_at: 100,
        coverage: hyperion_types::ScanCoverage {
            upstream_ran: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Keys come from the record itself, pilot or not, so a pilot's stored record
/// already knows everything that stood when the switch is flipped.
#[test]
fn keys_cover_the_new_buckets_without_counting_a_comparison_twice() {
    use hyperion_types::FindingKind::*;
    let mut r = native_result(true);
    r.core_modified = vec!["wp-includes/load.php".into()];
    r.findings = vec![
        file_finding("wp-includes/load.php", CoreModified, "high"),
        file_finding("wp-content/uploads/a.php", RuleHit, "high"),
    ];
    r.review = vec![file_finding(
        "wp-content/themes/x/f.php",
        BaselineChange,
        "medium",
    )];
    r.themes_failed = vec![hyperion_types::WpIntegrityPluginResult {
        slug: "twenty".into(),
        issues: vec![hyperion_types::WpIntegrityFileIssue {
            path: "style.css".into(),
            ..Default::default()
        }],
        ..Default::default()
    }];
    let keys = integrity_finding_keys(&r);
    assert_eq!(keys.len(), 4, "{keys:?}");
    assert!(keys.contains("core:mod:wp-includes/load.php"));
    assert_eq!(keys.iter().filter(|k| k.starts_with("review:")).count(), 1);
    assert_eq!(keys.iter().filter(|k| k.starts_with("theme:")).count(), 1);
    assert_eq!(legacy_finding_keys(&r).len(), 1);
}

#[test]
fn pilot_scan_alerts_what_it_always_did_and_nothing_more() {
    use hyperion_types::FindingKind::*;
    let prior = native_result(true);
    let mut scan = native_result(true);
    scan.core_modified = vec!["wp-includes/load.php".into()];
    scan.findings = vec![file_finding("wp-content/uploads/a.php", RuleHit, "high")];
    scan.review = vec![file_finding("wp-content/x.php", BaselineChange, "medium")];
    let plan = plan_integrity_alert(Some(&prior), &scan);
    assert_eq!((plan.findings, plan.review), (1, 0));
}

#[test]
fn first_scan_alerts_high_only() {
    use hyperion_types::FindingKind::*;
    let mut scan = native_result(false);
    scan.findings = vec![
        file_finding("wp-content/uploads/a.php", RuleHit, "high"),
        file_finding("wp-content/uploads/b.php", RuleHit, "medium"),
    ];
    scan.review = vec![
        file_finding("wp-content/c.php", BaselineChange, "medium"),
        file_finding("wp-content/d.php", TooLargeToInspect, "high"),
    ];
    // Nothing stored at all, or only a record from before the native scan.
    for prior in [None, Some(hyperion_types::WpIntegrityScanResult::default())] {
        let plan = plan_integrity_alert(prior.as_ref(), &scan);
        assert_eq!((plan.findings, plan.review), (1, 1), "{prior:?}");
        assert!(plan.error);
    }
    // The second scan has a baseline: everything new counts, whatever its level.
    let prior = native_result(false);
    let plan = plan_integrity_alert(Some(&prior), &scan);
    assert_eq!((plan.findings, plan.review), (2, 2));
}

/// Going live: what the pilot already showed is known, only what appears after is new.
#[test]
fn flipping_live_does_not_alert_what_stood_during_the_pilot() {
    use hyperion_types::FindingKind::*;
    let mut pilot = native_result(true);
    pilot.findings = vec![file_finding("wp-content/uploads/a.php", RuleHit, "high")];
    pilot.review = vec![file_finding("wp-content/c.php", BaselineChange, "medium")];
    let mut live = native_result(false);
    live.findings = pilot.findings.clone();
    live.review = pilot.review.clone();
    let plan = plan_integrity_alert(Some(&pilot), &live);
    assert_eq!((plan.findings, plan.review), (0, 0));
    live.review
        .push(file_finding("wp-content/e.php", BaselineChange, "medium"));
    let plan = plan_integrity_alert(Some(&pilot), &live);
    assert_eq!((plan.findings, plan.review), (0, 1));
    assert!(!plan.error, "a review alone is a warning");
}

/// A tampered Hyperion mu-plugin is a comparison no section carries: it is a
/// key of its own and alerts as a suspected compromise, on a first scan too.
#[test]
fn a_tampered_hyperion_file_alerts() {
    let scan = hyperion_types::WpIntegrityScanResult {
        findings: vec![hyperion_types::SiteFileFinding {
            source_label: Some("hyperion".into()),
            ..file_finding(
                "wp-content/mu-plugins/hyperion.php",
                hyperion_types::FindingKind::UpstreamModified,
                "high",
            )
        }],
        ..native_result(false)
    };
    assert!(integrity_finding_keys(&scan).contains("find:wp-content/mu-plugins/hyperion.php:-"));
    for prior in [None, Some(native_result(false))] {
        let plan = plan_integrity_alert(prior.as_ref(), &scan);
        assert_eq!((plan.findings, plan.review), (1, 0), "{prior:?}");
        assert!(plan.error);
    }
    // Standing, it doesn't alert again.
    let plan = plan_integrity_alert(Some(&scan), &scan);
    assert_eq!((plan.findings, plan.review), (0, 0));
}

#[test]
fn a_failed_theme_alerts_once_live() {
    let prior = native_result(false);
    let mut scan = native_result(false);
    scan.themes_failed = vec![hyperion_types::WpIntegrityPluginResult {
        slug: "twenty".into(),
        issues: vec![hyperion_types::WpIntegrityFileIssue::default()],
        ..Default::default()
    }];
    let plan = plan_integrity_alert(Some(&prior), &scan);
    assert_eq!((plan.findings, plan.review), (1, 0));
    // A theme has no severity and counts as High, like core and plugins: it
    // alerts on a first scan too.
    for first in [None, Some(hyperion_types::WpIntegrityScanResult::default())] {
        let plan = plan_integrity_alert(first.as_ref(), &scan);
        assert_eq!((plan.findings, plan.review), (1, 0), "{first:?}");
    }
    // In the pilot themes stay out, as they always did.
    scan.report_only = true;
    let plan = plan_integrity_alert(Some(&prior), &scan);
    assert_eq!((plan.findings, plan.review), (0, 0));
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
        ..Default::default()
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

/// Opening the WordPress tab reads what the last scan left behind; it must
/// never start one. The mock adapter has no expectation for any scan probe
/// (plugin list, wp-cli, clamscan), so a spawn would panic the test.
#[tokio::test]
async fn wp_integrity_stored_never_spawns_a_scan() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let site = hosting_for_packages(&s, "kos.cz").await;
    wordpress::record_install(&pool, &site.id, "https://kos.cz", "6.6.2", "h", 1)
        .await
        .expect("wp install row");
    let sel = HostingSelector::Id(site.id.clone());

    // Never scanned: an empty record that cannot read as clean.
    let r = s.wp_integrity_stored(sel.clone()).await.expect("stored");
    assert_eq!(r.scanned_at, 0);
    assert!(!r.is_clean(), "a site nobody checked is never clean");
    assert!(!r.scan_queued);
    assert!(
        hyperion_state::hosting_kv::get(&pool, site.id.as_str(), INTEGRITY_KV_KEY)
            .await
            .expect("kv get")
            .is_none(),
        "reading must not write a record either"
    );

    // With a record: exactly what was stored comes back.
    let mut outcome = upstream_verified(3);
    outcome.upstream.core_modified = vec!["wp-includes/version.php".into()];
    let mut stored = assemble_integrity_result(outcome, vec![], false, true);
    stored.scanned_at = 1_700_000_000;
    s.set_stored_integrity_scan(
        site.id.as_str(),
        &StoredIntegrityScan {
            scanned_at: 1_700_000_000,
            result: stored.clone(),
            ..Default::default()
        },
    )
    .await;
    let r = s.wp_integrity_stored(sel).await.expect("stored");
    assert_eq!(r.scanned_at, 1_700_000_000);
    assert_eq!(r.core_modified, vec!["wp-includes/version.php"]);
    assert!(!r.is_clean());
}

/// No record means never scanned, WordPress or not: the scheduler reaches every
/// site, so there is no separate answer for one without WordPress.
#[tokio::test]
async fn wp_integrity_stored_with_no_record_is_never_scanned() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let site = hosting_for_packages(&s, "static-site.cz").await;
    let r = s
        .wp_integrity_stored(HostingSelector::Id(site.id))
        .await
        .expect("stored");
    assert_eq!(r.scanned_at, 0);
    assert_eq!(r.error, None);
    assert!(!r.is_clean());
}

/// The weekly pass is due in the night window only, a week after the last one
/// began (a little less than a week, so a late start doesn't skip a night), and a
/// stamp from the future doesn't hold it off.
#[test]
fn clamav_is_due_weekly_in_the_night_window() {
    use super::super::scan_queue::clamav_sweep_due;
    use chrono::TimeZone;
    let at = |day: u32, hour: u32, min: u32| {
        chrono::Utc
            .with_ymd_and_hms(2026, 11, day, hour, min, 0)
            .single()
            .expect("date")
            .timestamp()
    };
    let last = at(2, 3, 0);
    assert!(clamav_sweep_due(0, at(2, 2, 0), &chrono::Utc), "never ran");
    assert!(
        !clamav_sweep_due(0, at(2, 1, 59), &chrono::Utc),
        "before the window"
    );
    assert!(!clamav_sweep_due(0, at(2, 6, 0), &chrono::Utc), "after it");
    assert!(
        !clamav_sweep_due(last, at(3, 3, 0), &chrono::Utc),
        "next night"
    );
    assert!(
        !clamav_sweep_due(last, at(8, 3, 0), &chrono::Utc),
        "six days"
    );
    assert!(
        clamav_sweep_due(last, at(9, 2, 0), &chrono::Utc),
        "a week, early in the window"
    );
    assert!(clamav_sweep_due(last, at(9, 5, 59), &chrono::Utc));
    assert!(
        !clamav_sweep_due(last, at(9, 12, 0), &chrono::Utc),
        "a week, wrong hour"
    );
    // A late start still comes round on the same night next week.
    assert!(clamav_sweep_due(at(2, 5, 50), at(9, 2, 0), &chrono::Utc));
    // The clock went back.
    assert!(clamav_sweep_due(at(20, 3, 0), at(9, 3, 0), &chrono::Utc));
}

/// The start site moves one step a week and the steps join up across ISO years.
#[test]
fn the_rotation_steps_by_week_across_years() {
    use super::super::scan_queue::clamav_rotation;
    use chrono::TimeZone;
    let at = |y, m, d| {
        chrono::Utc
            .with_ymd_and_hms(y, m, d, 3, 0, 0)
            .single()
            .expect("date")
            .timestamp()
    };
    // 2026 has 53 ISO weeks; 2026-12-28 is its Monday, 2027-01-04 is week 1 of 2027.
    let w53 = clamav_rotation(at(2026, 12, 28));
    assert_eq!(clamav_rotation(at(2027, 1, 4)), w53 + 1);
    assert_eq!(clamav_rotation(at(2026, 12, 21)) + 1, w53);
    // Over a year, every start of a 7-site node comes up.
    let starts: std::collections::HashSet<usize> = (0..52)
        .map(|w| clamav_rotation(at(2026, 1, 5) + w * 7 * 86_400) % 7)
        .collect();
    assert_eq!(starts.len(), 7);
}

/// A note said by the list and by the pass is on the card once.
#[test]
fn a_pass_with_more_than_a_thousand_hits_says_so_once() {
    use super::super::scan_queue::{apply_clamav, ClamUpdate};
    let many: Vec<_> = (0..1001)
        .map(|i| hyperion_types::WpMalwareHit {
            path: format!("/home/x/htdocs/{i}.php"),
            signature: "Php.Trojan.Agent-1".into(),
        })
        .collect();
    let mut r = site_scan::scanned(1, 1);
    apply_clamav(
        &mut r,
        ClamUpdate::Pass {
            hits: many,
            end: integrity::SweepEnd::Complete,
            started: 5,
            note: Some(
                "ClamAV found more than 1000 detections here; only the first 1000 are kept".into(),
            ),
        },
    );
    let said = r.result.error.expect("said");
    assert_eq!(said.matches("more than 1000").count(), 1, "{said}");
}

/// What a pass leaves in a record, and only that: a full pass is the answer, a
/// partial one only adds, and a reason moves nothing else.
#[test]
fn a_pass_updates_the_clamav_half_and_nothing_else() {
    use super::super::scan_queue::{apply_clamav, ClamUpdate};
    let old = webshell_hit();
    let new = hyperion_types::WpMalwareHit {
        path: "/home/x/htdocs/b.php".into(),
        signature: "Php.Trojan.Agent-1".into(),
    };
    let base = || {
        let mut r = site_scan::scanned(100, 100);
        r.clamav_at = 50;
        r.result.clamav_available = true;
        r.result.malware = vec![old.clone()];
        r.result.findings = vec![hyperion_types::SiteFileFinding {
            rel: "x.php".into(),
            ..Default::default()
        }];
        r
    };
    let pass = |hits, end, note: Option<&str>| ClamUpdate::Pass {
        hits,
        end,
        started: 900,
        note: note.map(String::from),
    };

    // Full: replaces, so a cleaned file stops being listed.
    let mut r = base();
    apply_clamav(
        &mut r,
        pass(vec![new.clone()], integrity::SweepEnd::Complete, None),
    );
    assert_eq!(r.result.malware, vec![new.clone()]);
    assert_eq!((r.clamav_at, r.result.clamav_available), (900, true));
    assert_eq!(r.result.error, None);
    assert_eq!(r.result.findings.len(), 1, "the native half is left alone");
    assert_eq!(r.scanned_at, 100);

    // Partial: adds, and the old one stands.
    let mut r = base();
    apply_clamav(
        &mut r,
        pass(
            vec![new.clone()],
            integrity::SweepEnd::Partial,
            Some("partial"),
        ),
    );
    assert_eq!(r.result.malware, vec![new.clone(), old.clone()]);
    assert_eq!(r.clamav_at, 900);
    assert_eq!(r.result.error.as_deref(), Some("partial"));

    // Partial and nothing found: proves nothing, so the last verdict stands
    // with the note beside it, and no failure is stamped.
    let mut r = base();
    apply_clamav(
        &mut r,
        pass(vec![], integrity::SweepEnd::TimedOut, Some("out of time")),
    );
    assert_eq!(r.result.malware, vec![old.clone()]);
    assert_eq!(r.clamav_at, 50);
    assert_eq!(r.clamav_failed_at, 0);
    assert_eq!(r.result.error.as_deref(), Some("out of time"));

    // A site never covered, and a partial pass that found nothing in it.
    let mut r = StoredIntegrityScan::default();
    apply_clamav(
        &mut r,
        pass(vec![], integrity::SweepEnd::Partial, Some("partial")),
    );
    assert!(!r.result.clamav_available, "not scanned is not clean");
    assert_eq!(r.clamav_at, 0);

    // A reason alone.
    let mut r = base();
    apply_clamav(&mut r, ClamUpdate::Note(Some("less than 2 GiB".into())));
    assert_eq!(r.result.malware, vec![old]);
    assert_eq!((r.clamav_at, r.result.clamav_available), (50, true));
    assert_eq!(r.result.error.as_deref(), Some("less than 2 GiB"));
    apply_clamav(&mut r, ClamUpdate::Note(None));
    assert_eq!(r.result.error, None);

    // A flood of hits is cut, and says so.
    let mut r = StoredIntegrityScan::default();
    let many = (0..1500)
        .map(|i| hyperion_types::WpMalwareHit {
            path: format!("/home/x/htdocs/{i}.php"),
            signature: "Php.Trojan.Agent-1".into(),
        })
        .collect();
    apply_clamav(&mut r, pass(many, integrity::SweepEnd::Complete, None));
    assert_eq!(r.result.malware.len(), 1000);
    assert!(r.result.error.expect("said").contains("first"));
}

/// A native failure and a ClamAV note each keep their place in the card's reason.
#[test]
fn a_native_failure_and_a_clamav_note_are_both_said() {
    use super::super::scan_queue::{apply_clamav, ClamUpdate};
    let mut r = site_scan::scanned(100, 100);
    r.failed_at = 100;
    apply_clamav(&mut r, ClamUpdate::Note(Some("waiting".into())));
    let said = r.result.error.expect("said");
    assert!(
        said.contains("could not finish") && said.contains("waiting"),
        "{said}"
    );
}

/// Restored hits from before the pass began are old news; from after, they stand.
#[test]
fn restored_hits_count_when_they_came_back_during_the_pass() {
    use super::super::scan_queue::{merge_restored, ClamRestored};
    let before = ClamRestored {
        path: "/home/x/htdocs/old.php".into(),
        signature: "Php.Trojan.Agent-1".into(),
        restored_at: 999,
    };
    let during = ClamRestored {
        path: "/home/x/htdocs/mid.php".into(),
        signature: "Php.Trojan.Agent-1".into(),
        restored_at: 1000,
    };
    let (hits, keep) = merge_restored(vec![webshell_hit()], vec![before, during.clone()], 1000);
    assert_eq!(keep, vec![during.clone()], "older entries are dropped");
    assert_eq!(hits.len(), 2);
    assert!(hits.iter().any(|h| h.path == during.path));
    // Found by the pass as well: once.
    let (hits, _) = merge_restored(
        vec![hyperion_types::WpMalwareHit {
            path: during.path.clone(),
            signature: during.signature.clone(),
        }],
        vec![during],
        1000,
    );
    assert_eq!(hits.len(), 1);
}

// The native scan's scheduler, which replaced the daily wp-cli sweep.
mod site_scan {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Arc;

    const HOUR: i64 = 3600;
    const DAY: i64 = 24 * HOUR;

    /// 2026-11-02 is a Monday.
    fn monday_at(day_offset: u32, hour: u32, min: u32) -> i64 {
        chrono::Utc
            .with_ymd_and_hms(2026, 11, 2 + day_offset, hour, min, 0)
            .single()
            .expect("valid date")
            .timestamp()
    }

    /// The record a finished native scan leaves.
    pub(super) fn scanned(at: i64, full_at: i64) -> StoredIntegrityScan {
        StoredIntegrityScan {
            scanned_at: at,
            full_at,
            result: hyperion_types::WpIntegrityScanResult {
                native_scan_ran: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// A worker that finds nothing to fetch and answers with `outcome`.
    fn answering(mut a: MockAdapterPort, outcome: SiteScanOutcome) -> MockAdapterPort {
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => WorkerReply::Scan(outcome.clone()),
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        a
    }

    async fn site_named(s: &HostingService<MockAdapterPort>, domain: &str) -> HostingDetail {
        s.create(req(domain)).await.expect("create");
        s.get(HostingSelector::Domain(
            Domain::parse(domain).expect("parse"),
        ))
        .await
        .expect("get")
    }

    fn plugin(slug: &str) -> Component {
        component(ComponentKind::Plugin, slug)
    }

    fn component(kind: ComponentKind, slug: &str) -> Component {
        Component {
            key: ComponentKey {
                kind,
                slug: slug.into(),
                version: "1.0".into(),
                locale: None,
            },
            rel_root: format!("wp-content/{slug}"),
            is_child_theme: false,
            single_file: false,
        }
    }

    fn some_manifest() -> Manifest {
        Manifest {
            source: ManifestSource::WordPressOrg,
            files: Default::default(),
            served_locale: None,
        }
    }

    // ---- when is a site due? ----

    #[test]
    fn new_hosting_is_due_immediately_any_time_of_day() {
        let id = "01JABCDEFGHJKMNPQRSTVWXYZ0";
        for hour in 0..24 {
            let now = monday_at(0, hour, 30);
            assert_eq!(
                site_scan_due(None, now, &chrono::Utc, id),
                Some(ScanMode::Delta),
                "no record, {hour}:30"
            );
            // A record from the wp-cli days: there is no baseline behind it.
            let old = StoredIntegrityScan {
                scanned_at: now - 60,
                ..Default::default()
            };
            assert_eq!(
                site_scan_due(Some(&old), now, &chrono::Utc, id),
                Some(ScanMode::Delta),
                "no baseline, {hour}:30"
            );
        }
    }

    #[test]
    fn delta_due_after_six_hours() {
        let id = "01JABCDEFGHJKMNPQRSTVWXYZ0";
        let now = monday_at(0, 12, 0);
        let rec = scanned(now - 6 * HOUR + 1, now);
        assert_eq!(site_scan_due(Some(&rec), now, &chrono::Utc, id), None);
        let rec = scanned(now - 6 * HOUR, now);
        assert_eq!(
            site_scan_due(Some(&rec), now, &chrono::Utc, id),
            Some(ScanMode::Delta)
        );
        // The clock went back: waiting would switch the site off until it
        // caught up.
        let rec = scanned(now + DAY, now);
        assert_eq!(
            site_scan_due(Some(&rec), now, &chrono::Utc, id),
            Some(ScanMode::Delta)
        );
        // Not that: a "Scan now" finished during the sweep, whose clock lags. It
        // must not be scanned again.
        let rec = scanned(now + 59, now);
        assert_eq!(site_scan_due(Some(&rec), now, &chrono::Utc, id), None);
    }

    #[test]
    fn full_rehash_only_in_night_window_and_only_its_weekday() {
        let id = "01JABCDEFGHJKMNPQRSTVWXYZ0";
        let tz = chrono::Utc;
        // Scanned an hour ago, so nothing but the full re-hash can be due.
        let due_at = |now: i64| {
            let rec = scanned(now - HOUR, now - 7 * DAY);
            site_scan_due(Some(&rec), now, &tz, id)
        };
        let full_days: Vec<u32> = (0..7)
            .filter(|d| due_at(monday_at(*d, 3, 0)) == Some(ScanMode::FullRehash))
            .collect();
        assert_eq!(full_days.len(), 1, "one night a week: {full_days:?}");
        let day = full_days[0];
        assert_eq!(due_at(monday_at(day, 2, 0)), Some(ScanMode::FullRehash));
        assert_eq!(due_at(monday_at(day, 5, 59)), Some(ScanMode::FullRehash));
        assert_eq!(due_at(monday_at(day, 1, 59)), None);
        assert_eq!(due_at(monday_at(day, 6, 0)), None);
        // Done this week: not again, and in the window at the local hour.
        let now = monday_at(day, 3, 0);
        let rec = scanned(now - HOUR, now - 5 * DAY);
        assert_eq!(site_scan_due(Some(&rec), now, &tz, id), None);
        let east = chrono::FixedOffset::east_opt(5 * 3600).expect("offset");
        let rec = scanned(now - HOUR, now - 7 * DAY);
        assert_eq!(
            site_scan_due(Some(&rec), now, &east, id),
            None,
            "08:00 there"
        );
        // Beats a plain delta that is due at the same moment.
        let rec = scanned(now - 7 * HOUR, now - 7 * DAY);
        assert_eq!(
            site_scan_due(Some(&rec), now, &tz, id),
            Some(ScanMode::FullRehash)
        );
    }

    #[test]
    fn seventh_of_sites_per_night_is_stable() {
        let mut nights = [0u32; 7];
        for i in 0..7000 {
            let id = format!("01JABCDEFGHJKMNPQRST{i:06}");
            let night = site_scan_weekday(&id);
            assert_eq!(night, site_scan_weekday(&id));
            nights[night as usize] += 1;
        }
        for (night, n) in nights.iter().enumerate() {
            assert!((800..1200).contains(n), "night {night}: {nights:?}");
        }
        // Pinned: a hash that changes with a build would move every site's
        // night on each deploy, and could skip a week.
        assert_eq!(site_scan_weekday("01JABCDEFGHJKMNPQRSTVWXYZ0"), 4);
    }

    #[test]
    fn a_stopped_or_failed_scan_comes_back_after_an_hour() {
        let id = "01JABCDEFGHJKMNPQRSTVWXYZ0";
        let tz = chrono::Utc;
        let now = monday_at(0, 12, 0);
        let mut stopped = scanned(now - HOUR + 1, now);
        stopped.stopped = true;
        assert_eq!(site_scan_due(Some(&stopped), now, &tz, id), None);
        stopped.scanned_at = now - HOUR;
        assert_eq!(
            site_scan_due(Some(&stopped), now, &tz, id),
            Some(ScanMode::Delta)
        );

        // A failed first scan has no baseline, and still must not run the
        // worker every ten minutes.
        let failed = StoredIntegrityScan {
            scanned_at: now - 60,
            failed_at: now - 60,
            ..Default::default()
        };
        assert_eq!(site_scan_due(Some(&failed), now, &tz, id), None);
        assert_eq!(
            site_scan_due(Some(&failed), now - 60 + HOUR, &tz, id),
            Some(ScanMode::Delta)
        );
        // Failed just ahead of a sweep's clock: still held off.
        assert_eq!(site_scan_due(Some(&failed), now - 90, &tz, id), None);
    }

    /// Config that arms the new layers' alerts.
    fn live_config() -> (std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, "[integrity]\nnew_layers_live = true\n").expect("write");
        (path, dir)
    }

    fn review_item(rel: &str) -> hyperion_types::SiteFileFinding {
        file_finding(rel, hyperion_types::FindingKind::BaselineChange, "medium")
    }

    /// Three changes to review on one site are ONE warning, and a standing
    /// review is not told again.
    #[tokio::test]
    async fn alert_batches_review_per_site() {
        use hyperion_state::web_users::WebRole;
        let pool = open_memory().await.expect("open");
        let (cfg, _dir) = live_config();
        let mut outcome = upstream_verified(0);
        outcome.review = ["a.php", "b.php", "c.php"].map(review_item).to_vec();
        let s = svc(pool.clone(), answering(happy_mocks(), outcome)).with_agent_config_path(cfg);
        let admin = seed_web_user(&s, "boss", WebRole::Admin).await;
        let site = site_named(&s, "kos.cz").await;
        let t0 = monday_at(0, 12, 0);
        // A baseline already stands, so this is not the first scan.
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(t0 - 8 * DAY, t0 - 8 * DAY))
            .await;
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick"),
            1
        );
        let feed = s.notifications_feed(admin, 10).await.expect("feed");
        assert_eq!(feed.items.len(), 1, "{:?}", feed.items);
        assert_eq!(feed.items[0].severity, "warn");
        assert!(feed.items[0].body.contains('3'), "{}", feed.items[0].body);
        assert!(feed.items[0].kind.starts_with("wp.integrity.review:"));

        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t0 + 8 * DAY)
                .await
                .expect("tick"),
            0,
            "the same three are known now"
        );
        assert_eq!(
            s.notifications_feed(admin, 10)
                .await
                .expect("feed")
                .items
                .len(),
            1
        );
    }

    /// Through the pilot nothing the new layers find is sent, but it is all
    /// stored, so turning the switch on later alerts only on what comes after.
    #[tokio::test]
    async fn the_pilot_stores_what_going_live_will_treat_as_known() {
        use hyperion_state::web_users::WebRole;
        let pool = open_memory().await.expect("open");
        let mut outcome = upstream_verified(0);
        outcome.review = ["a.php", "b.php"].map(review_item).to_vec();
        outcome.findings = vec![file_finding(
            "wp-content/uploads/x.php",
            hyperion_types::FindingKind::RuleHit,
            "high",
        )];
        let t0 = monday_at(0, 12, 0);
        let s = svc(pool.clone(), answering(happy_mocks(), outcome.clone()));
        let admin = seed_web_user(&s, "boss", WebRole::Admin).await;
        let site = site_named(&s, "kos.cz").await;
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(t0 - 8 * DAY, t0 - 8 * DAY))
            .await;
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick"),
            0
        );
        assert!(s
            .notifications_feed(admin, 10)
            .await
            .expect("feed")
            .items
            .is_empty());
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert!(rec.result.report_only);
        assert_eq!((rec.result.review.len(), rec.result.findings.len()), (2, 1));

        // The owner flips the switch. The same things stand: no flood.
        let (cfg, _dir) = live_config();
        let live = svc(pool.clone(), answering(happy_mocks(), outcome)).with_agent_config_path(cfg);
        assert_eq!(
            live.site_scan_tick_at(&chrono::Utc, t0 + 8 * DAY)
                .await
                .expect("tick"),
            0
        );
        assert!(s
            .notifications_feed(admin, 10)
            .await
            .expect("feed")
            .items
            .is_empty());
        let rec = live
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert!(!rec.result.report_only);
    }

    // ---- the tick ----

    #[tokio::test]
    async fn restart_does_not_retrigger() {
        let pool = open_memory().await.expect("open");
        let t0 = monday_at(0, 12, 0);
        let s = svc(pool.clone(), answering(happy_mocks(), upstream_verified(0)));
        let site = site_named(&s, "kos.cz").await;
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick"),
            0
        );
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.scanned_at, t0);
        assert_eq!(rec.full_at, t0, "a first scan reads every file");

        // The agent after a restart, over the same database: no worker, no
        // eviction either, since neither is due.
        let again = svc(pool.clone(), MockAdapterPort::new());
        again
            .site_scan_tick_at(&chrono::Utc, t0 + 600)
            .await
            .expect("tick");
        again
            .site_scan_tick_at(&chrono::Utc, t0 + 6 * HOUR - 1)
            .await
            .expect("tick");

        let later = svc(
            pool.clone(),
            answering(MockAdapterPort::new(), upstream_verified(0)),
        );
        later
            .site_scan_tick_at(&chrono::Utc, t0 + 6 * HOUR)
            .await
            .expect("tick");
        let rec = later
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.scanned_at, t0 + 6 * HOUR);
    }

    /// A redirect from the wizard is a `static` row with a target set, and has a
    /// docroot like any other: scanned.
    #[tokio::test]
    async fn a_wizard_redirect_is_scanned() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), answering(happy_mocks(), upstream_verified(0)));
        let site = site_named(&s, "go.cz").await;
        sqlx::query(
            "UPDATE hostings SET kind = 'static', redirect_url = 'https://x.cz' WHERE id = ?",
        )
        .bind(site.id.as_str())
        .execute(&pool)
        .await
        .expect("redirect row");
        s.site_scan_tick_at(&chrono::Utc, monday_at(0, 12, 0))
            .await
            .expect("tick");
        assert!(s.stored_integrity_scan(site.id.as_str()).await.is_some());
        assert!(kind_has_files("static"));
        assert!(!kind_has_files("reverse_proxy"));
    }

    #[tokio::test]
    async fn reverse_proxy_is_skipped() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker().never();
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "proxy.cz").await;
        sqlx::query("UPDATE hostings SET kind = 'reverse_proxy' WHERE id = ?")
            .bind(site.id.as_str())
            .execute(&pool)
            .await
            .expect("kind");

        s.site_scan_tick_at(&chrono::Utc, monday_at(0, 12, 0))
            .await
            .expect("tick");
        // Scan now says why rather than running anything.
        let r = s
            .wp_integrity_scan(HostingSelector::Id(site.id.clone()))
            .await
            .expect("scan");
        assert!(r.error.is_some());
        assert!(!r.is_clean());
        assert!(s.stored_integrity_scan(site.id.as_str()).await.is_none());
    }

    #[tokio::test]
    async fn opted_out_hosting_is_skipped() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker().never();
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        hyperion_state::hosting_kv::set(
            &pool,
            site.id.as_str(),
            INTEGRITY_ENABLED_KV_KEY,
            "off",
            1,
        )
        .await
        .expect("kv");
        s.site_scan_tick_at(&chrono::Utc, monday_at(0, 12, 0))
            .await
            .expect("tick");
        assert!(s.stored_integrity_scan(site.id.as_str()).await.is_none());
    }

    /// A record that can't be read is not "never scanned": that would start a
    /// scan on the strength of a database error.
    #[tokio::test]
    async fn a_site_whose_record_is_unreadable_waits() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker().never();
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        site_named(&s, "kos.cz").await;
        sqlx::query("DROP TABLE hosting_kv")
            .execute(&pool)
            .await
            .expect("drop");
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, monday_at(0, 12, 0))
                .await
                .expect("tick"),
            0
        );
    }

    #[tokio::test]
    async fn manifests_are_evicted_once_a_day() {
        let pool = open_memory().await.expect("open");
        let mut a = MockAdapterPort::new();
        a.expect_site_scan_evict_manifests()
            .times(2)
            .returning(|_| ());
        let s = svc(pool.clone(), a);
        let t0 = monday_at(0, 12, 0);
        for now in [t0, t0 + 600, t0 + DAY - 1, t0 + DAY] {
            s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick");
        }
    }

    /// Oldest first, each site's job naming its own docroot and baseline.
    #[tokio::test]
    async fn oldest_scanned_goes_first_with_its_own_paths() {
        let pool = open_memory().await.expect("open");
        let inputs = Arc::new(StdMutex::new(Vec::new()));
        let seen = inputs.clone();
        let mut a = happy_mocks_many();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(input) => {
                seen.lock().expect("lock").push(input);
                WorkerReply::Scan(upstream_verified(0))
            }
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let now = monday_at(0, 12, 0);
        let newer = site_named(&s, "newer.cz").await;
        let older = site_named(&s, "older.cz").await;
        s.set_stored_integrity_scan(newer.id.as_str(), &scanned(now - 7 * HOUR, now))
            .await;
        s.set_stored_integrity_scan(older.id.as_str(), &scanned(now - 8 * HOUR, now))
            .await;

        s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick");

        let inputs = inputs.lock().expect("lock");
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].root, std::path::PathBuf::from(&older.root_dir));
        assert_eq!(inputs[1].root, std::path::PathBuf::from(&newer.root_dir));
        assert_eq!(
            inputs[0].baseline_path,
            std::path::Path::new("/var/lib/hyperion/scan/baselines").join(older.id.as_str())
        );
        assert_eq!(
            inputs[0].manifests_dir,
            std::path::Path::new("/var/lib/hyperion/scan/manifests")
        );
        assert_eq!(inputs[0].mode, ScanMode::Delta);
        assert_eq!(inputs[0].now, now);
    }

    /// A worker held on a site, and a way to let it go.
    fn holding_the_first_discover(
        mut a: MockAdapterPort,
        order: Arc<StdMutex<Vec<std::path::PathBuf>>>,
        started: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    ) -> MockAdapterPort {
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { root } => {
                order.lock().expect("lock").push(root);
                started.store(true, Ordering::SeqCst);
                // The real worker is awaited; a plain block here would also
                // strand the pool connection sqlx is returning on this thread.
                tokio::task::block_in_place(|| {
                    while !release.load(Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                });
                WorkerReply::Discovery(Discovery::default())
            }
            WorkerJob::Scan(_) => WorkerReply::Scan(upstream_verified(0)),
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        a
    }

    /// "Scan now" answers at once, while the worker is busy, and runs after the
    /// current site and before the rest of the sweep, once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn scan_now_goes_to_front() {
        let pool = open_memory().await.expect("open");
        let order = Arc::new(StdMutex::new(Vec::<std::path::PathBuf>::new()));
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let a = holding_the_first_discover(
            happy_mocks_many(),
            order.clone(),
            started.clone(),
            release.clone(),
        );
        let s = Arc::new(svc(pool.clone(), a));
        let now = now_secs();
        let first = site_named(&s, "first.cz").await;
        let second = site_named(&s, "second.cz").await;
        let wanted = site_named(&s, "wanted.cz").await;
        for (site, age) in [(&first, 9), (&second, 8), (&wanted, 7)] {
            s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - age * HOUR, now))
                .await;
        }

        let tick = {
            let s = s.clone();
            tokio::spawn(async move { s.site_scan_tick_at(&chrono::Utc, now).await })
        };
        while !started.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let r = s
            .wp_integrity_scan_request(HostingSelector::Id(wanted.id.clone()))
            .await
            .expect("answers while the worker is busy");
        assert!(r.scan_queued);
        assert!(!release.load(Ordering::SeqCst));
        release.store(true, Ordering::SeqCst);
        tick.await.expect("join").expect("tick");

        let order = order.lock().expect("lock").clone();
        let root = |d: &HostingDetail| std::path::PathBuf::from(&d.root_dir);
        assert_eq!(order, vec![root(&first), root(&wanted), root(&second)]);
        let r = s
            .wp_integrity_stored(HostingSelector::Id(wanted.id.clone()))
            .await
            .expect("stored");
        assert!(!r.scan_queued, "the flag goes when the scan is stored");
    }

    /// Asked for during that very site's run, a request is about what's on disk
    /// now, which that run may have passed: it gets its own run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_request_during_that_sites_run_gets_its_own_run() {
        let pool = open_memory().await.expect("open");
        let order = Arc::new(StdMutex::new(Vec::<std::path::PathBuf>::new()));
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let a = holding_the_first_discover(
            happy_mocks(),
            order.clone(),
            started.clone(),
            release.clone(),
        );
        let s = Arc::new(svc(pool.clone(), a));
        let site = site_named(&s, "kos.cz").await;
        let now = now_secs();
        let tick = {
            let s = s.clone();
            tokio::spawn(async move { s.site_scan_tick_at(&chrono::Utc, now).await })
        };
        while !started.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        s.wp_integrity_scan_request(HostingSelector::Id(site.id.clone()))
            .await
            .expect("request");
        release.store(true, Ordering::SeqCst);
        tick.await.expect("join").expect("tick");
        assert_eq!(order.lock().expect("lock").len(), 2);
        assert!(
            !s.wp_integrity_stored(HostingSelector::Id(site.id.clone()))
                .await
                .expect("stored")
                .scan_queued
        );
    }

    /// Not due, opted out: asked for all the same, as "Scan now" always was. A
    /// double click is one flag and one scan, and the request wakes the tick.
    #[tokio::test]
    async fn a_requested_site_runs_whatever_its_schedule_says() {
        let pool = open_memory().await.expect("open");
        let discovers = Arc::new(AtomicUsize::new(0));
        let counted = discovers.clone();
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => {
                counted.fetch_add(1, Ordering::SeqCst);
                WorkerReply::Discovery(Discovery::default())
            }
            WorkerJob::Scan(_) => WorkerReply::Scan(upstream_verified(0)),
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let id = site.id.as_str();
        let now = monday_at(0, 12, 0);
        s.set_stored_integrity_scan(id, &scanned(now - 60, now))
            .await;
        hyperion_state::hosting_kv::set(&pool, id, INTEGRITY_ENABLED_KV_KEY, "off", 1)
            .await
            .expect("kv");

        // Answering doesn't need the node's lock.
        let held = s.site_scan.node.lock().await;
        for _ in 0..2 {
            let r = s
                .wp_integrity_scan_request(HostingSelector::Id(site.id.clone()))
                .await
                .expect("request");
            assert!(r.scan_queued);
            assert_eq!(r.scanned_at, now - 60, "the stored result comes back");
        }
        drop(held);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            s.site_scan_wait_for_request(),
        )
        .await
        .expect("woken");
        // A reload keeps polling.
        assert!(
            s.wp_integrity_stored(HostingSelector::Id(site.id.clone()))
                .await
                .expect("stored")
                .scan_queued
        );

        s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick");
        assert_eq!(discovers.load(Ordering::SeqCst), 1);
        assert!(
            !s.wp_integrity_stored(HostingSelector::Id(site.id.clone()))
                .await
                .expect("stored")
                .scan_queued
        );
        // Done: the next tick has nothing to do.
        s.site_scan_tick_at(&chrono::Utc, now + 60)
            .await
            .expect("tick");
        assert_eq!(discovers.load(Ordering::SeqCst), 1);
    }

    /// The card stops waiting once something newer than the request is stored,
    /// such as a scan `hctl` ran. The request still stands for the tick.
    #[tokio::test]
    async fn a_result_newer_than_the_request_ends_the_wait() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        let site = site_named(&s, "kos.cz").await;
        let id = site.id.as_str();
        let sel = HostingSelector::Id(site.id.clone());
        hyperion_state::hosting_kv::set(&pool, id, "scan_requested", "1000", 1000)
            .await
            .expect("kv");
        assert!(
            s.wp_integrity_stored(sel.clone())
                .await
                .expect("r")
                .scan_queued
        );
        s.set_stored_integrity_scan(id, &scanned(1000, 1)).await;
        assert!(
            s.wp_integrity_stored(sel.clone())
                .await
                .expect("r")
                .scan_queued,
            "the same second could be a scan from before the request"
        );
        s.set_stored_integrity_scan(id, &scanned(1001, 1)).await;
        assert!(!s.wp_integrity_stored(sel).await.expect("r").scan_queued);
    }

    /// A worker left over from before a restart: the flag stays for next time.
    #[tokio::test]
    async fn a_request_outlives_a_busy_worker() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(|_| WorkerReply::Busy);
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        s.wp_integrity_scan_request(HostingSelector::Id(site.id.clone()))
            .await
            .expect("request");
        s.site_scan_tick_at(&chrono::Utc, monday_at(0, 12, 0))
            .await
            .expect("tick");
        assert!(
            s.wp_integrity_stored(HostingSelector::Id(site.id.clone()))
                .await
                .expect("stored")
                .scan_queued
        );
    }

    /// Suspended since it was asked for: nothing will scan it, and a card must
    /// not wait for it.
    #[tokio::test]
    async fn a_request_for_a_site_no_longer_active_is_dropped() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker().never();
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let id = site.id.as_str();
        hyperion_state::hosting_kv::set(&pool, id, "scan_requested", "5", 5)
            .await
            .expect("kv");
        sqlx::query("UPDATE hostings SET state = 'suspended' WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .expect("suspend");
        s.site_scan_tick_at(&chrono::Utc, monday_at(0, 12, 0))
            .await
            .expect("tick");
        assert_eq!(
            hyperion_state::hosting_kv::get(&pool, id, "scan_requested")
                .await
                .expect("kv"),
            None
        );
    }

    #[tokio::test]
    async fn scan_request_refuses_what_cant_be_scanned() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker().never();
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "go.cz").await;
        let id = site.id.as_str();
        sqlx::query("UPDATE hostings SET kind = 'reverse_proxy' WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .expect("kind");
        let r = s
            .wp_integrity_scan_request(HostingSelector::Id(site.id.clone()))
            .await
            .expect("answers");
        assert!(!r.scan_queued);
        assert!(r.error.is_some());
        assert_eq!(
            hyperion_state::hosting_kv::get(&pool, id, "scan_requested")
                .await
                .expect("kv"),
            None
        );
        sqlx::query("UPDATE hostings SET kind = 'php', state = 'suspended' WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .expect("state");
        assert!(s
            .wp_integrity_scan_request(HostingSelector::Id(site.id.clone()))
            .await
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn only_one_worker_at_a_time() {
        let pool = open_memory().await.expect("open");
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let (running2, most2) = (running.clone(), most.clone());
        let mut a = happy_mocks_many();
        a.expect_site_scan_worker().returning(move |job| {
            let now_running = running2.fetch_add(1, Ordering::SeqCst) + 1;
            most2.fetch_max(now_running, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(20));
            running2.fetch_sub(1, Ordering::SeqCst);
            match job {
                WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                    listed: 0,
                    partial: false,
                },
                WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
                WorkerJob::Scan(_) => WorkerReply::Scan(upstream_verified(0)),
            }
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = Arc::new(svc(pool.clone(), a));
        let mut sites = Vec::new();
        for d in ["a-site.cz", "b-site.cz", "c-site.cz"] {
            sites.push(site_named(&s, d).await);
        }
        let mut joins = Vec::new();
        for site in &sites {
            let s = s.clone();
            let sel = HostingSelector::Id(site.id.clone());
            joins.push(tokio::spawn(async move {
                s.wp_integrity_scan(sel).await.map(|_| 0)
            }));
        }
        {
            let s = s.clone();
            let now = now_secs();
            joins.push(tokio::spawn(async move {
                s.site_scan_tick_at(&chrono::Utc, now).await
            }));
        }
        for j in joins {
            j.await.expect("join").expect("scan");
        }
        assert_eq!(most.load(Ordering::SeqCst), 1);
    }

    /// `Busy` is a worker that survived an agent restart. Nothing failed, and
    /// nothing about the site changed.
    #[tokio::test]
    async fn busy_worker_is_skipped_quietly() {
        let pool = open_memory().await.expect("open");
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let mut a = happy_mocks_many();
        a.expect_site_scan_worker().returning(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            WorkerReply::Busy
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let one = site_named(&s, "one.cz").await;
        let two = site_named(&s, "two.cz").await;

        let flagged = s
            .site_scan_tick_at(&chrono::Utc, monday_at(0, 12, 0))
            .await
            .expect("tick");
        assert_eq!(flagged, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the tick stops at Busy");
        for id in [&one.id, &two.id] {
            assert!(s.stored_integrity_scan(id.as_str()).await.is_none());
        }

        let r = s
            .wp_integrity_scan(HostingSelector::Id(one.id.clone()))
            .await
            .expect("scan");
        assert!(r.error.is_some(), "Scan now has to say why nothing changed");
        assert!(!r.is_clean());
        assert!(s.stored_integrity_scan(one.id.as_str()).await.is_none());
    }

    #[tokio::test]
    async fn failed_run_keeps_prior_findings() {
        let tenant_text = "could not open /home/x/htdocs/<script>evil</script>";
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker()
            .returning(move |_| WorkerReply::Failed(tenant_text.to_string()));
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = monday_at(0, 12, 0);

        let mut prior = scanned(now - 7 * HOUR, now - DAY);
        prior.result.scanned_at = now - 7 * HOUR;
        prior.result.wp_cli_ok = true;
        prior.result.clamav_available = true;
        prior.clamav_at = now - HOUR;
        prior.result.malware = vec![webshell_hit()];
        prior.result.core_modified = vec!["wp-login.php".into()];
        prior.result.findings = vec![hyperion_types::SiteFileFinding {
            rel: "wp-content/uploads/a.php".into(),
            severity: "high".into(),
            ..Default::default()
        }];
        s.set_stored_integrity_scan(site.id.as_str(), &prior).await;

        // The sweep: the same keys as before, so no alert.
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick"),
            0
        );

        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.result.core_modified, prior.result.core_modified);
        assert_eq!(rec.result.findings, prior.result.findings);
        assert_eq!(rec.result.malware, vec![webshell_hit()], "hits stand");
        assert_eq!(rec.clamav_at, now - HOUR);
        assert_eq!(rec.scanned_at, now - 7 * HOUR, "this run proved nothing");
        assert_eq!(rec.full_at, now - DAY);
        assert_eq!(rec.failed_at, now);
        let error = rec.result.error.clone().expect("the failure is on record");
        assert!(
            !error.contains("evil") && !error.contains("/home"),
            "the worker's words can carry tenant text: {error}"
        );
        // Not retried on every tick.
        assert_eq!(
            site_scan_due(Some(&rec), now + 600, &chrono::Utc, site.id.as_str()),
            None
        );

        // Scan now reports a scan that didn't run as one that didn't run.
        let r = s
            .wp_integrity_scan(HostingSelector::Id(site.id.clone()))
            .await
            .expect("scan");
        assert!(!r.wp_cli_ok);
        assert!(
            r.clamav_available,
            "ClamAV's verdict is the weekly pass's, whatever this scan did"
        );
        assert!(!r.is_clean());
        assert_eq!(r.core_modified, prior.result.core_modified);
        assert_eq!(r.malware, vec![webshell_hit()]);
        assert!(!r.error.expect("error").contains("evil"));
    }

    /// A site nobody has ever been able to check still reaches the dashboard
    /// saying so.
    #[tokio::test]
    async fn a_first_scan_that_fails_is_recorded_as_not_checked() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker()
            .returning(|_| WorkerReply::Failed("no".into()));
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = monday_at(0, 12, 0);
        s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick");
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert!(!rec.result.native_scan_ran);
        assert!(!rec.result.is_clean());
        assert!(rec.result.error.is_some());
        assert_eq!(rec.failed_at, now);
        assert_eq!(s.integrity_findings_list().await.expect("list").len(), 1);
    }

    /// A scan that stopped early hasn't looked at the rest of the site. What it
    /// didn't reach stays listed, so the next complete run doesn't alert on a
    /// standing finding as if it were new.
    #[tokio::test]
    async fn stopped_run_keeps_standing_findings() {
        for (stopped, capped) in [(true, false), (false, true)] {
            let pool = open_memory().await.expect("open");
            let reply = Arc::new(StdMutex::new(upstream_verified(0)));
            let current = reply.clone();
            let mut a = happy_mocks();
            a.expect_site_scan_worker().returning(move |job| match job {
                WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                    listed: 0,
                    partial: false,
                },
                WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
                WorkerJob::Scan(_) => WorkerReply::Scan(current.lock().expect("lock").clone()),
            });
            a.expect_site_scan_evict_manifests().returning(|_| ());
            let s = svc(pool.clone(), a);
            let site = site_named(&s, "kos.cz").await;
            let t0 = monday_at(0, 12, 0);

            let mut full = upstream_verified(0);
            full.upstream.core_modified = vec!["wp-login.php".into()];
            *reply.lock().expect("lock") = full.clone();
            assert_eq!(
                s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick"),
                1
            );
            // ClamAV has run too, so nothing else can keep this from clean.
            let mut rec = s
                .stored_integrity_scan(site.id.as_str())
                .await
                .expect("record");
            rec.result.clamav_available = true;
            s.set_stored_integrity_scan(site.id.as_str(), &rec).await;

            let mut cut_short = upstream_verified(0);
            cut_short.stopped = stopped;
            cut_short.capped = capped;
            *reply.lock().expect("lock") = cut_short;
            let t1 = t0 + 6 * HOUR;
            assert_eq!(
                s.site_scan_tick_at(&chrono::Utc, t1).await.expect("tick"),
                0
            );
            let rec = s
                .stored_integrity_scan(site.id.as_str())
                .await
                .expect("record");
            assert_eq!(
                rec.stopped, stopped,
                "a capped site won't get further in an hour"
            );
            assert_eq!(rec.scanned_at, t1);
            assert_eq!(rec.result.core_modified, vec!["wp-login.php"]);
            assert!(!rec.result.core_ok, "worked out after the carry");

            // Clean but for the part it didn't reach: still not clean.
            let mut nothing_standing = upstream_verified(0);
            nothing_standing.stopped = stopped;
            nothing_standing.capped = capped;
            clamp_scan_outcome(&mut nothing_standing);
            assert!(!nothing_standing.coverage.partial_reasons.is_empty());
            let r = assemble_integrity_result(nothing_standing, vec![], true, true);
            assert!(!r.is_clean(), "stopped {stopped}, capped {capped}");

            *reply.lock().expect("lock") = full;
            let t2 = t1 + 6 * HOUR;
            assert_eq!(
                s.site_scan_tick_at(&chrono::Utc, t2).await.expect("tick"),
                0,
                "nothing new"
            );
            let rec = s
                .stored_integrity_scan(site.id.as_str())
                .await
                .expect("record");
            assert!(!rec.stopped);

            // A complete run is the one thing that can clear a finding.
            *reply.lock().expect("lock") = upstream_verified(0);
            let t3 = t2 + 6 * HOUR;
            s.site_scan_tick_at(&chrono::Utc, t3).await.expect("tick");
            let rec = s
                .stored_integrity_scan(site.id.as_str())
                .await
                .expect("record");
            assert!(rec.result.core_modified.is_empty());
            assert!(rec.result.core_ok);
        }
    }

    /// A stopped re-hash didn't read everything, so it's still owed.
    #[tokio::test]
    async fn full_at_moves_only_when_every_file_was_read() {
        let pool = open_memory().await.expect("open");
        let reply = Arc::new(StdMutex::new(upstream_verified(0)));
        let current = reply.clone();
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => WorkerReply::Scan(current.lock().expect("lock").clone()),
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let id = site.id.as_str();
        let night = site_scan_weekday(id);
        let now = monday_at(night, 3, 0);
        let long_ago = now - 7 * DAY;
        s.set_stored_integrity_scan(id, &scanned(now - HOUR, long_ago))
            .await;

        let mut stopped = upstream_verified(0);
        stopped.stopped = true;
        *reply.lock().expect("lock") = stopped;
        s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick");
        let rec = s.stored_integrity_scan(id).await.expect("record");
        assert_eq!(rec.full_at, long_ago);

        *reply.lock().expect("lock") = upstream_verified(0);
        s.site_scan_tick_at(&chrono::Utc, now + HOUR)
            .await
            .expect("tick");
        let rec = s.stored_integrity_scan(id).await.expect("record");
        assert_eq!(rec.full_at, now + HOUR);
    }

    // ---- alerts ----

    #[tokio::test]
    async fn new_layer_findings_do_not_alert_in_report_only() {
        let finding = |rel: &str| hyperion_types::SiteFileFinding {
            rel: rel.into(),
            severity: "high".into(),
            ..Default::default()
        };
        let mut outcome = upstream_verified(0);
        outcome.findings = vec![finding("wp-content/uploads/a.php")];
        outcome.review = vec![finding("custom.php")];
        outcome.upstream.themes_failed = vec![hyperion_types::WpIntegrityPluginResult {
            source: None,
            slug: "hello-elementor".into(),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: "functions.php".into(),
                message: "Checksum does not match".into(),
            }],
            ..Default::default()
        }];
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), answering(happy_mocks(), outcome.clone()));
        let site = site_named(&s, "kos.cz").await;
        let flagged = s
            .site_scan_tick_at(&chrono::Utc, monday_at(0, 12, 0))
            .await
            .expect("tick");
        assert_eq!(flagged, 0, "the pilot is silent");
        // The panel still has them.
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert!(rec.result.report_only);
        assert_eq!(rec.result.findings, outcome.findings);
        assert_eq!(rec.result.review, outcome.review);
        assert_eq!(rec.result.themes_failed, outcome.upstream.themes_failed);
    }

    #[tokio::test]
    async fn upstream_failures_still_alert_in_report_only() {
        let pool = open_memory().await.expect("open");
        let reply = Arc::new(StdMutex::new(upstream_verified(1)));
        let current = reply.clone();
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => WorkerReply::Scan(current.lock().expect("lock").clone()),
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let t0 = monday_at(0, 12, 0);

        let mut tampered = upstream_verified(1);
        tampered.upstream.core_modified = vec!["wp-login.php".into()];
        *reply.lock().expect("lock") = tampered.clone();
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick"),
            1
        );
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert!(rec.result.report_only);

        // Standing: only once.
        let t1 = t0 + 6 * HOUR;
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t1).await.expect("tick"),
            0
        );

        // A plugin failing is new.
        tampered.upstream.plugins_failed = vec![hyperion_types::WpIntegrityPluginResult {
            source: None,
            slug: "akismet".into(),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: "akismet.php".into(),
                message: "Checksum does not match".into(),
            }],
            ..Default::default()
        }];
        *reply.lock().expect("lock") = tampered;
        let t2 = t1 + 6 * HOUR;
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t2).await.expect("tick"),
            1
        );
    }

    // ---- what Scan now does ----

    /// The whole point of this flow. Every wp-cli method is set to fail the test
    /// if touched.
    #[tokio::test]
    async fn wp_integrity_scan_calls_no_wp_cli() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_wp_plugin_list().never();
        a.expect_wp_plugin_action().never();
        a.expect_wp_cli().never();
        a.expect_site_scan_worker().returning(|job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => WorkerReply::Scan(upstream_verified(2)),
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        wordpress::record_install(&pool, &site.id, "https://kos.cz", "6.6.2", "h", 1)
            .await
            .expect("wp install row");
        let r = s
            .wp_integrity_scan(HostingSelector::Id(site.id.clone()))
            .await
            .expect("scan");
        assert!(r.wp_cli_ok && r.native_scan_ran);
        assert_eq!(r.plugins_checked, 2);
    }

    #[tokio::test]
    async fn auto_accepted_files_reach_the_audit_log() {
        let mut outcome = upstream_verified(0);
        outcome.auto_accepted = vec!["wp-content/plugins/pro/x.php".into()];
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => WorkerReply::Scan(outcome.clone()),
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        s.wp_integrity_scan(HostingSelector::Id(site.id.clone()))
            .await
            .expect("scan");
        let entries = hyperion_state::audit::list(&pool, 100)
            .await
            .expect("audit");
        let entry = entries
            .iter()
            .find(|e| e.action == "wp.integrity.auto_accept")
            .expect("audited");
        assert_eq!(entry.target.as_deref(), Some(site.id.as_str()));
    }

    // ---- the reply is untrusted ----

    #[tokio::test]
    async fn an_oversized_reply_is_clamped_before_storing() {
        let long = "x".repeat(5000);
        let finding = hyperion_types::SiteFileFinding {
            rel: long.clone(),
            severity: "catastrophic".into(),
            rule_id: Some(long.clone()),
            domains: vec!["d.example".to_string(); 50],
            snippet: format!("é{long}"),
            sha256: long.clone(),
            component: Some(long.clone()),
            source_label: Some(long.clone()),
            ..Default::default()
        };
        let mut outcome = upstream_verified(0);
        outcome.findings = vec![finding.clone(); 1100];
        outcome.accepted_by_writer = vec![finding.clone(); 300];
        outcome.review = vec![finding; 1100];
        outcome.upstream.core_modified = vec![long.clone(); 1100];
        outcome.upstream.plugins_unknown = vec!["p".to_string(); 10_100];
        outcome.upstream.plugins_failed = vec![
            hyperion_types::WpIntegrityPluginResult {
                source: None,
                slug: long.clone(),
                issues: vec![
                    hyperion_types::WpIntegrityFileIssue {
                        path: long.clone(),
                        message: long.clone(),
                    };
                    600
                ],
                ..Default::default()
            };
            3
        ];
        outcome.coverage.partial_reasons = vec![long.clone(); 30];
        outcome.coverage.plugins_total = -5;
        outcome.coverage.files_watched = -1;
        outcome.auto_accepted = vec![long.clone(); 300];

        clamp_scan_outcome(&mut outcome);

        assert!(outcome.findings.len() <= 1000);
        assert!(outcome.review.len() <= 1000);
        assert!(outcome.upstream.core_modified.len() <= 1000);
        assert!(outcome.upstream.plugins_unknown.len() <= 10_001);
        let issues: usize = outcome
            .upstream
            .plugins_failed
            .iter()
            .map(|p| p.issues.len())
            .sum();
        assert!(issues <= 1000, "{issues}");
        assert!(outcome.auto_accepted.len() <= 200);
        assert!(outcome.accepted_by_writer.len() <= 200);
        assert!(outcome.accepted_by_writer[0].snippet.len() <= 1024);
        assert!(outcome.coverage.partial_reasons.len() <= 24);
        assert!(outcome.coverage.partial_reasons[0].len() <= 512);
        assert!(outcome.upstream.plugins_failed[0].slug.len() <= 256);
        assert!(outcome.upstream.plugins_failed[0].issues[0].path.len() <= 4096);
        assert!(outcome.upstream.plugins_failed[0].issues[0].message.len() <= 1024);
        let f = &outcome.findings[0];
        assert!(f.rel.len() <= 4096);
        assert!(f.snippet.len() <= 1024);
        assert!(f.sha256.len() <= 128);
        assert!(f.domains.len() <= 10);
        assert_eq!(f.severity, "medium", "only the two known levels pass");
        assert!(f.rule_id.as_deref().is_some_and(|r| r.len() <= 128));
        assert_eq!(outcome.coverage.plugins_total, 0);
        assert_eq!(outcome.coverage.files_watched, 0);
        // The JSON a row holds stays bounded whatever the worker sent.
        let json = serde_json::to_string(&outcome).expect("json");
        assert!(json.len() < 64 * 1024 * 1024, "{}", json.len());
    }

    #[test]
    fn a_clamp_never_splits_a_character() {
        let mut outcome = upstream_verified(0);
        outcome.findings = vec![hyperion_types::SiteFileFinding {
            rel: "é".repeat(5000),
            severity: "high".into(),
            ..Default::default()
        }];
        clamp_scan_outcome(&mut outcome);
        assert!(outcome.findings[0].rel.chars().all(|c| c == 'é'));
        assert_eq!(outcome.findings[0].severity, "high");
    }

    // ---- fetching manifests ----

    fn discovery_of(components: Vec<Component>) -> Discovery {
        Discovery {
            is_wordpress: true,
            components,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn fetching_stops_at_the_http_and_zip_budgets() {
        let pool = open_memory().await.expect("open");
        let plugins = Arc::new(AtomicUsize::new(0));
        let themes = Arc::new(AtomicUsize::new(0));
        let (p2, t2) = (plugins.clone(), themes.clone());
        let mut a = MockAdapterPort::new();
        a.expect_site_scan_cached_manifest().returning(|_, _| None);
        a.expect_site_scan_cached_slug()
            .returning(|_, _, _| Some(false));
        a.expect_site_scan_fetch_manifest()
            .returning(move |key, _| {
                match key.kind {
                    ComponentKind::Theme => t2.fetch_add(1, Ordering::SeqCst),
                    _ => p2.fetch_add(1, Ordering::SeqCst),
                };
                Ok(None)
            });
        let s = svc(pool, a);
        let mut comps: Vec<Component> = (0..50)
            .map(|i| component(ComponentKind::Theme, &format!("theme-{i}")))
            .collect();
        comps.extend((0..500).map(|i| plugin(&format!("plugin-{i}"))));
        let pass = s
            .site_scan_fetch_manifests(&discovery_of(comps), std::path::Path::new("/m"))
            .await;
        assert_eq!(themes.load(Ordering::SeqCst), 20);
        assert_eq!(plugins.load(Ordering::SeqCst), 180, "200 fetches in all");
        assert_eq!(
            pass.known_slugs, None,
            "a component nobody asked about may be on wordpress.org"
        );
        assert!(
            pass.reasons.iter().any(|r| r.contains("350")),
            "{:?}",
            pass.reasons
        );
    }

    /// Fifty sites on one version cost one download: an answer from the cache
    /// spends nothing, however many there are.
    #[tokio::test]
    async fn cached_answers_spend_no_budget() {
        let pool = open_memory().await.expect("open");
        let mut a = MockAdapterPort::new();
        a.expect_site_scan_cached_manifest()
            .returning(|_, _| Some(Some(some_manifest())));
        a.expect_site_scan_fetch_manifest().never();
        a.expect_site_scan_slug_known().never();
        let s = svc(pool, a);
        let comps: Vec<Component> = (0..500).map(|i| plugin(&format!("plugin-{i}"))).collect();
        let pass = s
            .site_scan_fetch_manifests(&discovery_of(comps), std::path::Path::new("/m"))
            .await;
        assert!(pass.reasons.is_empty(), "{:?}", pass.reasons);
        let known = pass.known_slugs.expect("nothing errored");
        assert_eq!(known.len(), 500, "a manifest from wordpress.org names it");
    }

    #[tokio::test]
    async fn core_is_fetched_before_a_tenants_plugin_folders() {
        let pool = open_memory().await.expect("open");
        let order = Arc::new(StdMutex::new(Vec::new()));
        let seen = order.clone();
        let mut a = MockAdapterPort::new();
        a.expect_site_scan_cached_manifest().returning(|_, _| None);
        a.expect_site_scan_cached_slug()
            .returning(|_, _, _| Some(false));
        a.expect_site_scan_fetch_manifest()
            .returning(move |key, _| {
                seen.lock().expect("lock").push(key.kind);
                Ok(None)
            });
        let s = svc(pool, a);
        let mut comps: Vec<Component> = (0..300).map(|i| plugin(&format!("p-{i}"))).collect();
        comps.push(component(ComponentKind::Core, "wordpress"));
        s.site_scan_fetch_manifests(&discovery_of(comps), std::path::Path::new("/m"))
            .await;
        assert_eq!(order.lock().expect("lock")[0], ComponentKind::Core);
    }

    #[tokio::test]
    async fn a_network_failure_is_couldnt_check_and_stops_asking() {
        let pool = open_memory().await.expect("open");
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let mut a = MockAdapterPort::new();
        a.expect_site_scan_cached_manifest().returning(|_, _| None);
        a.expect_site_scan_fetch_manifest().returning(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(AdapterError::Other("network down".into()))
        });
        let s = svc(pool, a);
        let mut comps = vec![component(ComponentKind::Core, "wordpress")];
        comps.extend((0..50).map(|i| plugin(&format!("p-{i}"))));
        let pass = s
            .site_scan_fetch_manifests(&discovery_of(comps), std::path::Path::new("/m"))
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3, "the node lock is held");
        assert_eq!(pass.known_slugs, None);
        let all = pass.reasons.join("; ");
        assert!(all.contains("WordPress core"), "{all}");
        assert!(all.contains("reached"), "{all}");
        assert!(!all.contains("network down"), "{all}");
    }

    #[tokio::test]
    async fn slug_answers_build_the_known_set_and_an_error_empties_it() {
        let run = |slug_answer: Result<bool, ()>| async move {
            let pool = open_memory().await.expect("open");
            let mut a = MockAdapterPort::new();
            a.expect_site_scan_cached_manifest()
                .returning(|_, _| Some(None));
            a.expect_site_scan_cached_slug().returning(|_, _, _| None);
            a.expect_site_scan_slug_known().returning(move |_, _, _| {
                slug_answer.map_err(|()| AdapterError::Other("down".into()))
            });
            let s = svc(pool, a);
            s.site_scan_fetch_manifests(
                &discovery_of(vec![plugin("elementor-pro")]),
                std::path::Path::new("/m"),
            )
            .await
            .known_slugs
        };
        assert_eq!(run(Ok(false)).await, Some(Default::default()));
        assert_eq!(
            run(Ok(true)).await,
            Some(std::iter::once("elementor-pro".to_string()).collect())
        );
        assert_eq!(run(Err(())).await, None);
    }

    /// The agent passes the partial reason on, in front of the worker's own so
    /// that its cap doesn't lose it.
    #[tokio::test]
    async fn what_couldnt_be_fetched_reaches_the_coverage() {
        let pool = open_memory().await.expect("open");
        let mut outcome = upstream_verified(0);
        outcome.coverage.partial_reasons = (0..24).map(|i| format!("worker {i}")).collect();
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => {
                WorkerReply::Discovery(discovery_of(vec![plugin("akismet")]))
            }
            WorkerJob::Scan(input) => {
                assert_eq!(input.wporg_known_slugs, None);
                WorkerReply::Scan(outcome.clone())
            }
        });
        a.expect_site_scan_cached_manifest().returning(|_, _| None);
        a.expect_site_scan_fetch_manifest()
            .returning(|_, _| Err(AdapterError::Other("down".into())));
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let r = s
            .wp_integrity_scan(HostingSelector::Id(site.id))
            .await
            .expect("scan");
        assert!(
            r.coverage.partial_reasons[0].contains("reached"),
            "{:?}",
            r.coverage.partial_reasons
        );
        assert!(r.coverage.partial_reasons.len() <= 24);
    }

    // ---- config and clean-up ----

    #[test]
    fn new_layers_stay_off_until_the_node_says_so() {
        assert!(!read_new_layers_live(None));
        let dir = tempfile::tempdir().expect("tmp");
        let cfg = dir.path().join("agent.toml");
        assert!(!read_new_layers_live(Some(&cfg)), "no file");
        std::fs::write(&cfg, "[integrity]\nvendor_refs_live = true\n").expect("write");
        assert!(
            !read_new_layers_live(Some(&cfg)),
            "the section without the key"
        );
        std::fs::write(&cfg, "[integrity]\nnew_layers_live = \"yes\"\n").expect("write");
        assert!(!read_new_layers_live(Some(&cfg)), "not a boolean");
        std::fs::write(&cfg, "[integrity]\nnew_layers_live = true\n").expect("write");
        assert!(read_new_layers_live(Some(&cfg)));
    }

    /// An import fills the site after `create` made it active, and the tick may
    /// have scanned it half-copied. When the import is done the next scan starts
    /// the baseline over, so what arrived later isn't "new since the first scan".
    #[tokio::test]
    async fn a_finished_import_starts_the_baseline_over() {
        let pool = open_memory().await.expect("open");
        let dir = tempfile::tempdir().expect("tmp");
        let scan_dir = dir.path().join("scan");
        let baselines = scan_dir.join("baselines");
        let seen: Arc<StdMutex<Vec<bool>>> = Arc::default();
        let mut a = happy_mocks_many();
        let saw = seen.clone();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(input) => {
                saw.lock().expect("lock").push(input.baseline_path.exists());
                WorkerReply::Scan(upstream_verified(0))
            }
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a).with_paths(HostingPaths {
            scan_dir: scan_dir.display().to_string(),
            ..Default::default()
        });
        let now = monday_at(0, 12, 0);
        let site = site_named(&s, "imported.cz").await;
        let other = site_named(&s, "other.cz").await;
        for h in [&site, &other] {
            s.set_stored_integrity_scan(h.id.as_str(), &scanned(now - HOUR, now))
                .await;
        }
        std::fs::create_dir_all(&baselines).expect("mkdir");
        let baseline = baselines.join(site.id.as_str());
        std::fs::write(&baseline, "half-copied").expect("baseline");
        std::fs::write(baselines.join(other.id.as_str()), "x").expect("baseline");

        s.site_scan_start_over(&site.id).await;
        // Nothing is removed outside a scan: one may be saving right now.
        assert!(baseline.exists());
        assert!(s.scan_request_flag(site.id.as_str()).await.is_some());

        s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick");

        assert_eq!(
            *seen.lock().expect("lock"),
            [false],
            "scanned with no baseline"
        );
        assert!(baselines.join(other.id.as_str()).exists());
        // Once only: the scan after it keeps what it saved.
        std::fs::write(&baseline, "whole site").expect("baseline");
        s.site_scan_maybe_start_over(site.id.as_str()).await;
        assert!(baseline.exists());
    }

    #[tokio::test]
    async fn purge_removes_baseline_and_quarantine_dir() {
        let pool = open_memory().await.expect("open");
        let dir = tempfile::tempdir().expect("tmp");
        let (scan_dir, quarantine_dir) = (dir.path().join("scan"), dir.path().join("quarantine"));
        let s =
            svc(pool.clone(), super::super::trash::hard_delete_mocks()).with_paths(HostingPaths {
                scan_dir: scan_dir.display().to_string(),
                quarantine_dir: quarantine_dir.display().to_string(),
                ..Default::default()
            });
        let gone = s.create(req("gone.cz")).await.expect("create");
        let kept = s.create(req("kept.cz")).await.expect("create");
        std::fs::create_dir_all(scan_dir.join("baselines")).expect("mkdir");
        for id in [gone.id.as_str(), kept.id.as_str()] {
            std::fs::write(scan_dir.join("baselines").join(id), "x").expect("baseline");
            std::fs::create_dir_all(quarantine_dir.join(id)).expect("mkdir");
            std::fs::write(quarantine_dir.join(id).join("1"), "x").expect("held file");
        }

        hostings::mark_trashed(&pool, &gone.id, now_secs())
            .await
            .expect("mark trashed");
        s.purge_from_trash(HostingSelector::Id(gone.id.clone()))
            .await
            .expect("purge");

        assert!(!scan_dir.join("baselines").join(gone.id.as_str()).exists());
        assert!(!quarantine_dir.join(gone.id.as_str()).exists());
        assert!(scan_dir.join("baselines").join(kept.id.as_str()).exists());
        assert!(quarantine_dir.join(kept.id.as_str()).join("1").exists());

        // Nothing there at all is the common case, not a failure.
        hostings::mark_trashed(&pool, &kept.id, now_secs())
            .await
            .expect("mark trashed");
        std::fs::remove_dir_all(dir.path().join("scan")).expect("rm");
        std::fs::remove_dir_all(dir.path().join("quarantine")).expect("rm");
        s.purge_from_trash(HostingSelector::Id(kept.id.clone()))
            .await
            .expect("purge with nothing to remove");
    }

    #[tokio::test]
    async fn clean_up_refuses_a_name_that_is_not_one_hostings_own() {
        let dir = tempfile::tempdir().expect("tmp");
        let paths = HostingPaths {
            scan_dir: dir.path().join("scan").display().to_string(),
            quarantine_dir: dir.path().join("quarantine").display().to_string(),
            ..Default::default()
        };
        std::fs::create_dir_all(dir.path().join("quarantine/other")).expect("mkdir");
        for id in ["", "..", "../quarantine", "a/b", "."] {
            remove_site_scan_state(&paths, id).await;
        }
        assert!(dir.path().join("quarantine/other").exists());
    }

    // ---- carrying what a run couldn't speak for ----

    fn tampered_plugin(slug: &str) -> hyperion_types::WpIntegrityPluginResult {
        hyperion_types::WpIntegrityPluginResult {
            source: None,
            slug: slug.into(),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: "x.php".into(),
                message: "Checksum does not match".into(),
            }],
            ..Default::default()
        }
    }

    /// wordpress.org out of reach at rollout, then back. The first run compared
    /// nothing, so it can't have cleared anything, and the second finds nothing
    /// new.
    #[tokio::test]
    async fn a_network_blip_then_recovery_raises_no_alert() {
        let pool = open_memory().await.expect("open");
        let reply = Arc::new(StdMutex::new(upstream_verified(2)));
        let current = reply.clone();
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => WorkerReply::Scan(current.lock().expect("lock").clone()),
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let t0 = monday_at(0, 12, 0);

        let mut healthy = upstream_verified(2);
        healthy.upstream.core_modified = vec!["wp-login.php".into()];
        healthy.upstream.plugins_failed = vec![tampered_plugin("akismet")];
        *reply.lock().expect("lock") = healthy.clone();
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick"),
            1
        );

        // Nothing compared: core not run, the plugin unverified.
        let mut blip = SiteScanOutcome::default();
        blip.upstream.plugins_unknown = vec!["akismet".into()];
        blip.coverage.partial_reasons = vec!["wordpress.org couldn't be reached".into()];
        *reply.lock().expect("lock") = blip;
        let t1 = t0 + 6 * HOUR;
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t1).await.expect("tick"),
            0
        );
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert!(!rec.result.wp_cli_ok, "still \"couldn't check\"");
        assert!(!rec.result.core_ok);
        assert_eq!(rec.result.core_modified, vec!["wp-login.php"]);
        assert_eq!(rec.result.plugins_failed.len(), 1);

        *reply.lock().expect("lock") = healthy;
        let t2 = t1 + 6 * HOUR;
        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, t2).await.expect("tick"),
            0
        );
    }

    /// Only what this run couldn't speak for is carried. A plugin it verified
    /// clean is clear, a plugin gone is gone, and a site that no longer has
    /// WordPress has no core to carry.
    #[tokio::test]
    async fn carrying_stops_at_what_the_run_could_not_speak_for() {
        let pool = open_memory().await.expect("open");
        let reply = Arc::new(StdMutex::new(upstream_verified(2)));
        let current = reply.clone();
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => WorkerReply::Scan(current.lock().expect("lock").clone()),
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let t0 = monday_at(0, 12, 0);
        let upstream_finding = |rel: &str, component: &str| hyperion_types::SiteFileFinding {
            rel: rel.into(),
            kind: hyperion_types::FindingKind::UpstreamModified,
            severity: "high".into(),
            component: Some(component.into()),
            ..Default::default()
        };

        let mut first = upstream_verified(3);
        first.upstream.plugins_failed = vec![
            tampered_plugin("unreached"),
            tampered_plugin("fixed"),
            tampered_plugin("removed"),
        ];
        first.upstream.themes_failed = vec![tampered_plugin("a-theme")];
        first.findings = vec![
            upstream_finding("wp-content/plugins/unreached/x.php", "unreached"),
            upstream_finding("wp-content/plugins/fixed/x.php", "fixed"),
        ];
        *reply.lock().expect("lock") = first;
        s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick");

        let mut second = upstream_verified(1);
        second.upstream.plugins_unknown = vec!["unreached".into()];
        second.upstream.themes_unknown = vec!["a-theme".into()];
        *reply.lock().expect("lock") = second;
        let t1 = t0 + 6 * HOUR;
        s.site_scan_tick_at(&chrono::Utc, t1).await.expect("tick");
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        let slugs: Vec<&str> = rec
            .result
            .plugins_failed
            .iter()
            .map(|p| p.slug.as_str())
            .collect();
        assert_eq!(slugs, vec!["unreached"]);
        assert_eq!(rec.result.themes_failed.len(), 1);
        assert_eq!(rec.result.findings.len(), 1);
        assert_eq!(
            rec.result.findings[0].component.as_deref(),
            Some("unreached")
        );

        // The site stopped being WordPress: nothing to compare, nothing to carry.
        let mut gone = SiteScanOutcome::default();
        gone.coverage.no_upstream = true;
        *reply.lock().expect("lock") = gone;
        let t2 = t1 + 6 * HOUR;
        s.site_scan_tick_at(&chrono::Utc, t2).await.expect("tick");
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert!(rec.result.plugins_failed.is_empty());
        assert!(rec.result.themes_failed.is_empty());
    }

    /// A run cut short carries what the last one listed, once per file: the new
    /// run's item wins, and a file the worker found gone isn't carried. The
    /// worker is told which names those are.
    #[tokio::test]
    async fn a_capped_run_carries_each_file_once_and_never_a_deleted_one() {
        let pool = open_memory().await.expect("open");
        let reply = Arc::new(StdMutex::new(upstream_verified(2)));
        let current = reply.clone();
        let asked: Arc<StdMutex<Vec<Vec<String>>>> = Arc::default();
        let seen = asked.clone();
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(input) => {
                seen.lock().expect("lock").push(input.carried_rels.clone());
                WorkerReply::Scan(current.lock().expect("lock").clone())
            }
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let t0 = monday_at(0, 12, 0);
        let hit = |rel: &str, sha: &str| hyperion_types::SiteFileFinding {
            rel: rel.into(),
            kind: hyperion_types::FindingKind::RuleHit,
            severity: "high".into(),
            rule_id: Some("php.eval".into()),
            sha256: sha.into(),
            ..Default::default()
        };

        let mut first = upstream_verified(2);
        first.upstream.plugins_failed = vec![tampered_plugin("p")];
        first.findings = vec![
            hit("wp-content/uploads/a.php", "aa"),
            hit("wp-content/uploads/gone.php", "cc"),
            hyperion_types::SiteFileFinding {
                rel: "wp-content/plugins/p/x.php".into(),
                kind: hyperion_types::FindingKind::UpstreamModified,
                severity: "high".into(),
                sha256: "dd".into(),
                component: Some("p".into()),
                ..Default::default()
            },
            hyperion_types::SiteFileFinding {
                rel: "wp-includes/gone.php".into(),
                kind: hyperion_types::FindingKind::CoreMissing,
                severity: "high".into(),
                ..Default::default()
            },
        ];
        first.review = vec![hyperion_types::SiteFileFinding {
            rel: "wp-content/b.php".into(),
            sha256: "ee".into(),
            ..Default::default()
        }];
        *reply.lock().expect("lock") = first;
        s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick");

        let mut capped = upstream_verified(2);
        capped.capped = true;
        capped.findings = vec![hit("wp-content/uploads/a.php", "bb")];
        capped.absent_carried = vec![
            "wp-content/uploads/gone.php".into(),
            "wp-content/plugins/p/x.php".into(),
        ];
        *reply.lock().expect("lock") = capped;
        let t1 = t0 + 6 * HOUR;
        s.site_scan_tick_at(&chrono::Utc, t1).await.expect("tick");

        let asked = asked.lock().expect("lock").clone();
        assert!(asked[0].is_empty(), "nothing stood before the first run");
        let mut second = asked[1].clone();
        second.sort();
        // A missing file is never asked about: it's gone by definition.
        assert_eq!(
            second,
            vec![
                "wp-content/b.php",
                "wp-content/plugins/p/x.php",
                "wp-content/uploads/a.php",
                "wp-content/uploads/gone.php",
            ]
        );
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        let found: Vec<(&str, &str)> = rec
            .result
            .findings
            .iter()
            .map(|f| (f.rel.as_str(), f.sha256.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("wp-content/uploads/a.php", "bb"),
                ("wp-includes/gone.php", "")
            ]
        );
        assert!(rec.result.plugins_failed.is_empty(), "its one file is gone");
        assert_eq!(rec.result.review.len(), 1, "b.php is still there");
    }

    // ---- ClamAV: one weekly pass for the node, beside its lock ----

    const GIB: u64 = 1 << 30;
    const CLAMAV_SIGNATURES_FOR_TEST: &str =
        "ClamAV is waiting: its signatures are still downloading";

    fn facts(mem_available: u64) -> integrity::ClamFacts {
        integrity::ClamFacts {
            installed: true,
            db_present: true,
            mem_available,
        }
    }

    /// What each site hands in: two files, the second of which `found_in` names.
    fn two_files(root: &str) -> Vec<String> {
        vec![
            format!("{root}/index.php"),
            format!("{root}/wp-content/uploads/a.php"),
        ]
    }

    /// A list of two files for each site, nothing left out, unless `tweak` says.
    fn plan_for(
        roots: &[(HostingId, String)],
        tweak: impl Fn(&mut integrity::SiteListing, &str),
    ) -> integrity::ClamPlan {
        let sites = roots
            .iter()
            .map(|(id, root)| {
                let mut l = integrity::SiteListing::new(id.clone());
                l.files = 2;
                tweak(&mut l, root);
                l
            })
            .collect();
        integrity::ClamPlan::in_memory(
            roots.to_vec(),
            sites,
            roots.iter().flat_map(|(_, r)| two_files(r)),
        )
    }

    /// The detection a pass makes on the n-th site of its list.
    fn found_in(plan: &integrity::ClamPlan, n: usize) -> hyperion_types::WpMalwareHit {
        hyperion_types::WpMalwareHit {
            path: two_files(&plan.roots[n].1)[1].clone(),
            signature: "Php.Trojan.Webshell-1".into(),
        }
    }

    fn sweep(
        end: integrity::SweepEnd,
        hits: Vec<hyperion_types::WpMalwareHit>,
    ) -> Result<integrity::ClamSweep, AdapterError> {
        Ok(integrity::ClamSweep {
            hits,
            end,
            ..Default::default()
        })
    }

    /// A node with ClamAV and `mem` free. `answer` is the one pass.
    fn with_clamav(
        mut a: MockAdapterPort,
        mem: u64,
        answer: impl Fn(&integrity::ClamPlan) -> Result<integrity::ClamSweep, AdapterError>
            + Send
            + 'static,
    ) -> MockAdapterPort {
        a.expect_clamav_facts().returning(move || facts(mem));
        a.expect_clamav_prepare()
            .returning(|roots, _, _| Ok(plan_for(roots, |_, _| {})));
        a.expect_clamav_run().returning(move |plan| answer(&plan));
        a.expect_clamav_stop_orphan().returning(|| ());
        a
    }

    async fn record_of(
        s: &HostingService<MockAdapterPort>,
        site: &HostingDetail,
    ) -> StoredIntegrityScan {
        s.stored_integrity_scan(site.id.as_str())
            .await
            .expect("record")
    }

    /// Mondays at 03:00 UTC, the middle of the night window.
    fn night(week: u32) -> i64 {
        monday_at(7 * week, 3, 0)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clamav_runs_without_the_nodes_lock() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), 4 * GIB, |_| {
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = night(0);
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        let _held = s.site_scan.node.lock().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            s.site_scan_clamav_tick_at(&chrono::Utc, now),
        )
        .await
        .expect("didn't wait for the lock")
        .expect("tick");
        let rec = record_of(&s, &site).await;
        assert_eq!(rec.clamav_at, now);
        assert!(rec.result.clamav_available);
    }

    /// One `clamscan` for the node: every scanned site in one list, each listed
    /// once, and a site whose scan is off or has no files of its own left out.
    /// Nothing is walked or scanned per site.
    #[tokio::test]
    async fn old_per_site_pass_is_gone() {
        let pool = open_memory().await.expect("open");
        let lists_seen: Arc<StdMutex<Vec<Vec<HostingId>>>> = Arc::default();
        let (prepared, ran) = (lists_seen.clone(), lists_seen.clone());
        let mut a = happy_mocks_many();
        a.expect_clamav_facts().returning(|| facts(4 * GIB));
        a.expect_clamav_stop_orphan().returning(|| ());
        a.expect_clamav_prepare()
            .times(1)
            .returning(move |roots, path, limits| {
                assert!(path.ends_with("clamav-list"), "{path:?}");
                assert_eq!(limits, integrity::ClamLimits::default());
                assert_eq!(limits.node_bytes, 256 << 20);
                prepared
                    .lock()
                    .expect("lock")
                    .push(roots.iter().map(|(id, _)| id.clone()).collect());
                Ok(plan_for(roots, |_, _| {}))
            });
        a.expect_clamav_run().times(1).returning(move |plan| {
            assert_eq!(ran.lock().expect("lock").len(), 1, "listed first");
            assert_eq!(plan.roots.len(), 2);
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        let (one, two, off) = (
            site_named(&s, "one.cz").await,
            site_named(&s, "two.cz").await,
            site_named(&s, "off.cz").await,
        );
        hyperion_state::hosting_kv::set(&pool, off.id.as_str(), INTEGRITY_ENABLED_KV_KEY, "off", 1)
            .await
            .expect("kv");
        let now = night(0);
        s.site_scan_clamav_tick_at(&chrono::Utc, now)
            .await
            .expect("tick");
        // Later the same night: not again.
        s.site_scan_clamav_tick_at(&chrono::Utc, now + 600)
            .await
            .expect("tick");

        let seen = lists_seen.lock().expect("lock");
        assert_eq!(seen.len(), 1, "one pass, one list");
        let mut got: Vec<&str> = seen[0].iter().map(HostingId::as_str).collect();
        got.sort_unstable();
        let mut want = vec![one.id.as_str(), two.id.as_str()];
        want.sort_unstable();
        assert_eq!(
            got, want,
            "each scanned site once; the one switched off not"
        );
    }

    /// A pass that is cut short can still not be started twice: the stamp is
    /// there before the process is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_stamp_is_written_before_the_pass_starts() {
        let pool = open_memory().await.expect("open");
        let during = pool.clone();
        let stamp: Arc<StdMutex<Option<String>>> = Arc::default();
        let slot = stamp.clone();
        let a = with_clamav(happy_mocks(), 4 * GIB, move |_| {
            let pool = during.clone();
            let v = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    hyperion_state::node_kv::get(&pool, "site_scan_clamav_at")
                        .await
                        .expect("kv")
                })
            });
            *slot.lock().expect("lock") = v;
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        site_named(&s, "kos.cz").await;
        let now = night(0);
        s.site_scan_clamav_tick_at(&chrono::Utc, now)
            .await
            .expect("tick");
        assert_eq!(
            stamp.lock().expect("lock").as_deref(),
            Some(now.to_string().as_str())
        );
    }

    /// The stamp lives in the database: a restarted agent, or a second one on the
    /// same state, neither re-runs the week's pass nor skips the next.
    #[tokio::test]
    async fn weekly_cadence_survives_restart() {
        let pool = open_memory().await.expect("open");
        let runs = Arc::new(AtomicUsize::new(0));
        let count = || {
            let n = runs.clone();
            with_clamav(happy_mocks(), 4 * GIB, move |_| {
                n.fetch_add(1, Ordering::SeqCst);
                sweep(integrity::SweepEnd::Complete, vec![])
            })
        };
        let first = svc(pool.clone(), count());
        site_named(&first, "kos.cz").await;
        first
            .site_scan_clamav_tick_at(&chrono::Utc, night(0))
            .await
            .expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // A new process on the same database.
        let restarted = svc(pool.clone(), count());
        let tick = |t: i64| restarted.site_scan_clamav_tick_at(&chrono::Utc, t);
        tick(night(0) + 600).await.expect("tick");
        tick(night(0) + DAY).await.expect("tick");
        tick(night(0) + 6 * DAY).await.expect("tick");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "nothing before the week is up"
        );
        // A week on, but at midday: not in the window.
        tick(monday_at(7, 12, 0)).await.expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        tick(night(1)).await.expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 2, "the next week's night");
    }

    /// A node that was off through the whole window waits for the next night
    /// rather than starting a pass at midday.
    #[tokio::test]
    async fn a_node_that_missed_the_window_waits_for_the_next_night() {
        let pool = open_memory().await.expect("open");
        let runs = Arc::new(AtomicUsize::new(0));
        let n = runs.clone();
        let a = with_clamav(happy_mocks(), 4 * GIB, move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        site_named(&s, "kos.cz").await;
        hyperion_state::node_kv::set(&pool, "site_scan_clamav_at", &night(0).to_string(), 1)
            .await
            .expect("stamp");
        for t in [
            monday_at(9, 12, 0),
            monday_at(9, 22, 0),
            monday_at(10, 1, 59),
        ] {
            s.site_scan_clamav_tick_at(&chrono::Utc, t)
                .await
                .expect("tick");
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "over a week late, but not in the window"
        );
        s.site_scan_clamav_tick_at(&chrono::Utc, monday_at(10, 3, 0))
            .await
            .expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    /// New hits alert once, and standing ones next week don't.
    #[tokio::test]
    async fn a_new_clamav_hit_alerts_once() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), 4 * GIB, |lists| {
            sweep(integrity::SweepEnd::Complete, vec![found_in(lists, 0)])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = night(0);
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, now)
                .await
                .expect("tick"),
            1
        );
        let rec = record_of(&s, &site).await;
        assert_eq!(rec.clamav_at, now);
        assert!(rec.result.clamav_available);
        assert_eq!(rec.result.malware.len(), 1);
        assert_eq!(
            rec.result.malware[0].path,
            format!("{}/wp-content/uploads/a.php", site.root_dir)
        );
        // Next week the same hit is standing, not new.
        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, night(1))
                .await
                .expect("tick"),
            0
        );
        assert_eq!(record_of(&s, &site).await.clamav_at, night(1));
    }

    /// A site with no WordPress to compare with is covered too. Its hits show on
    /// the card; while the new layers are in their pilot they don't alert.
    #[tokio::test]
    async fn clamav_covers_sites_without_upstream_and_stays_quiet_in_the_pilot() {
        for (report_only, alerts) in [(true, 0), (false, 1)] {
            let pool = open_memory().await.expect("open");
            let a = with_clamav(happy_mocks(), 4 * GIB, |lists| {
                sweep(integrity::SweepEnd::Complete, vec![found_in(lists, 0)])
            });
            let s = svc(pool.clone(), a);
            let plain = site_named(&s, "static.cz").await;
            let mut rec = scanned(1, 1);
            rec.result.coverage.no_upstream = true;
            rec.result.report_only = report_only;
            s.set_stored_integrity_scan(plain.id.as_str(), &rec).await;
            assert_eq!(
                s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
                    .await
                    .expect("tick"),
                alerts,
                "report_only {report_only}"
            );
            assert_eq!(record_of(&s, &plain).await.result.malware.len(), 1);
        }
    }

    /// A site nobody has scanned yet has no card to put a reason on, and no record
    /// is made for it.
    #[tokio::test]
    async fn a_site_never_scanned_gets_no_record_from_a_quiet_pass() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), 4 * GIB, |_| {
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "new.cz").await;
        s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
            .await
            .expect("tick");
        assert!(s.stored_integrity_scan(site.id.as_str()).await.is_none());
    }

    /// A hit on a site no scan has spoken for makes its record, in the pilot like
    /// every other new layer, and doesn't alert before the node says so.
    #[tokio::test]
    async fn a_hit_on_a_site_with_no_record_is_quiet_in_the_pilot() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), 4 * GIB, |plan| {
            sweep(integrity::SweepEnd::Complete, vec![found_in(plan, 0)])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "new.cz").await;
        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
                .await
                .expect("tick"),
            0,
            "shown, not sent"
        );
        let rec = record_of(&s, &site).await;
        assert_eq!(rec.result.malware.len(), 1);
        assert!(rec.result.report_only);
    }

    /// Under 2 GiB free the pass is skipped: the card says so, nothing is stamped
    /// as failed, "clean" is as clean as it was, and the next ten minutes try
    /// again, so the first quiet moment of the night gets the pass.
    #[tokio::test]
    async fn low_memory_is_skip_not_failure_and_does_not_block_clean() {
        let pool = open_memory().await.expect("open");
        let mem = Arc::new(std::sync::atomic::AtomicU64::new(2 * GIB - 1));
        let runs = Arc::new(AtomicUsize::new(0));
        let (m, n) = (mem.clone(), runs.clone());
        let mut a = happy_mocks();
        a.expect_clamav_facts()
            .returning(move || facts(m.load(Ordering::SeqCst)));
        a.expect_clamav_stop_orphan().returning(|| ());
        a.expect_clamav_prepare()
            .returning(|roots, _, _| Ok(plan_for(roots, |_, _| {})));
        a.expect_clamav_run().returning(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let mut clean = scanned(night(0) - 60, night(0));
        clean.result.coverage.no_upstream = true;
        clean.result.scanned_at = clean.scanned_at;
        assert!(clean.result.is_clean());
        s.set_stored_integrity_scan(site.id.as_str(), &clean).await;

        s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
            .await
            .expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        let rec = record_of(&s, &site).await;
        let said = rec.result.error.clone().expect("the card says why");
        assert!(said.contains("2 GiB"), "{said}");
        assert_eq!(rec.clamav_failed_at, 0, "not a failure");
        assert_eq!(rec.clamav_at, 0);
        assert!(!rec.result.clamav_available);
        assert!(rec.result.is_clean(), "ClamAV is not part of clean");
        assert_eq!(rec.result.verdict(), hyperion_types::ScanVerdict::Clean);
        assert!(
            hyperion_state::node_kv::get(&pool, "site_scan_clamav_at")
                .await
                .expect("kv")
                .is_none(),
            "no week was used up"
        );

        // Memory frees up later the same night.
        mem.store(3 * GIB, Ordering::SeqCst);
        s.site_scan_clamav_tick_at(&chrono::Utc, night(0) + 600)
            .await
            .expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        let rec = record_of(&s, &site).await;
        assert_eq!(rec.result.error, None, "the reason is gone");
        assert!(rec.result.clamav_available);
    }

    /// Signatures still downloading is a state of its own and is told at once, at
    /// any hour, and goes when they are there; a node that loses ClamAV stops
    /// vouching for its sites. No pass starts in either case.
    #[tokio::test]
    async fn signatures_downloading_is_its_own_state_told_at_any_hour() {
        let pool = open_memory().await.expect("open");
        let state = Arc::new(StdMutex::new((true, false)));
        let st = state.clone();
        let mut a = happy_mocks();
        a.expect_clamav_facts().returning(move || {
            let (installed, db_present) = *st.lock().expect("lock");
            integrity::ClamFacts {
                installed,
                db_present,
                mem_available: 8 * GIB,
            }
        });
        a.expect_clamav_stop_orphan().returning(|| ());
        a.expect_clamav_prepare().never();
        a.expect_clamav_run().never();
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let mut was = scanned(night(0) - 60, night(0));
        was.clamav_at = 500;
        was.result.clamav_available = true;
        was.result.malware = vec![webshell_hit()];
        s.set_stored_integrity_scan(site.id.as_str(), &was).await;

        // Midday: not the window, and the card still hears of it.
        let midday = monday_at(0, 12, 0);
        s.site_scan_clamav_tick_at(&chrono::Utc, midday)
            .await
            .expect("tick");
        let rec = record_of(&s, &site).await;
        assert!(rec
            .result
            .error
            .clone()
            .expect("said")
            .contains("downloading"));
        assert_eq!(rec.clamav_failed_at, 0);
        assert!(rec.result.clamav_available, "last pass stands");

        // The signatures arrive: the note goes, and only that note.
        *state.lock().expect("lock") = (true, true);
        s.site_scan_clamav_tick_at(&chrono::Utc, midday + 600)
            .await
            .expect("tick");
        assert_eq!(record_of(&s, &site).await.result.error, None);

        // ClamAV is removed: no stale note, and no vouching for the site.
        let mut stale = record_of(&s, &site).await;
        stale.clamav_error = Some(CLAMAV_SIGNATURES_FOR_TEST.into());
        s.set_stored_integrity_scan(site.id.as_str(), &stale).await;
        *state.lock().expect("lock") = (false, false);
        s.site_scan_clamav_tick_at(&chrono::Utc, midday + 1200)
            .await
            .expect("tick");
        let rec = record_of(&s, &site).await;
        assert_eq!(rec.result.error, None, "the stale note is gone");
        assert!(!rec.result.clamav_available);
        assert_eq!(rec.result.malware, vec![webshell_hit()], "last known");
    }

    /// The kernel killed the pass: its hits stand, the card says so, and the node
    /// leaves ClamAV alone for seven days.
    #[tokio::test]
    async fn oom_kill_backs_off_seven_days() {
        let pool = open_memory().await.expect("open");
        let runs = Arc::new(AtomicUsize::new(0));
        let n = runs.clone();
        let a = with_clamav(happy_mocks(), 8 * GIB, move |lists| {
            n.fetch_add(1, Ordering::SeqCst);
            sweep(integrity::SweepEnd::OutOfMemory, vec![found_in(lists, 0)])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(night(0) - 60, night(0)))
            .await;
        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
                .await
                .expect("tick"),
            1,
            "what it found before it died is told"
        );
        let rec = record_of(&s, &site).await;
        assert_eq!(rec.result.malware.len(), 1);
        assert!(rec.result.error.expect("said").contains("lack of memory"));
        assert_eq!(rec.clamav_failed_at, 0);
        let until: i64 = hyperion_state::node_kv::get(&pool, "site_scan_clamav_backoff_until")
            .await
            .expect("kv")
            .expect("set")
            .parse()
            .expect("number");
        assert!(
            (night(0) + 7 * DAY..night(0) + 7 * DAY + 60).contains(&until),
            "seven days from the kill"
        );

        // A week on, an hour into the window and before the back-off ends: no pass,
        // and the card says when it will be tried.
        let early = night(1) - HOUR;
        s.site_scan_clamav_tick_at(&chrono::Utc, early)
            .await
            .expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        let said = record_of(&s, &site).await.result.error.expect("said");
        assert!(said.contains("not tried again until"), "{said}");
        // Once it is over, the next tick of the window runs it.
        s.site_scan_clamav_tick_at(&chrono::Utc, night(1) + 600)
            .await
            .expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    /// Exit 2 or a stop: the hits found are kept and listed, the sites with none
    /// aren't called clean on the strength of it, and no failure is stamped. A full
    /// pass next week is what clears a hit.
    #[tokio::test]
    async fn partial_keeps_hits() {
        let pool = open_memory().await.expect("open");
        let end = Arc::new(StdMutex::new(integrity::SweepEnd::Partial));
        let e = end.clone();
        let a = with_clamav(happy_mocks_many(), 8 * GIB, move |plan| {
            let end = *e.lock().expect("lock");
            let hits = if end.is_partial() {
                // One site's webshell, found before clamscan stopped.
                plan.roots
                    .iter()
                    .position(|(_, r)| r.contains("hit.cz"))
                    .map(|n| vec![found_in(plan, n)])
                    .unwrap_or_default()
            } else {
                vec![]
            };
            sweep(end, hits)
        });
        let s = svc(pool.clone(), a);
        let hit = site_named(&s, "hit.cz").await;
        let other = site_named(&s, "other.cz").await;
        let mut was = scanned(night(0) - 60, night(0));
        was.clamav_at = night(0) - 7 * DAY;
        was.result.clamav_available = true;
        s.set_stored_integrity_scan(other.id.as_str(), &was).await;
        s.set_stored_integrity_scan(hit.id.as_str(), &scanned(night(0) - 60, night(0)))
            .await;

        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
                .await
                .expect("tick"),
            1
        );
        let rec = record_of(&s, &hit).await;
        assert_eq!(rec.result.malware.len(), 1, "the hit is kept");
        assert!(rec.result.clamav_available);
        assert!(rec
            .result
            .error
            .expect("said")
            .contains("more may be hiding"));
        assert_eq!(rec.clamav_failed_at, 0, "real hits are not a failure");
        let rec = record_of(&s, &other).await;
        assert!(rec.result.malware.is_empty());
        assert_eq!(
            rec.clamav_at,
            night(0) - 7 * DAY,
            "last week's verdict, unchanged"
        );
        assert!(
            rec.result.error.is_some(),
            "but the card says this week's didn't finish"
        );

        // The next week's pass is whole and finds nothing: now the hit clears.
        *end.lock().expect("lock") = integrity::SweepEnd::Complete;
        s.site_scan_clamav_tick_at(&chrono::Utc, night(1))
            .await
            .expect("tick");
        let rec = record_of(&s, &hit).await;
        assert!(rec.result.malware.is_empty());
        assert_eq!(rec.clamav_at, night(1));
        assert_eq!(rec.result.error, None);
    }

    /// A partial pass doesn't clear a hit it didn't repeat.
    #[tokio::test]
    async fn a_partial_pass_does_not_clear_an_old_hit() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), 8 * GIB, |_| {
            sweep(integrity::SweepEnd::TimedOut, vec![])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let mut was = scanned(night(0) - 60, night(0));
        was.clamav_at = night(0) - 7 * DAY;
        was.result.clamav_available = true;
        was.result.malware = vec![webshell_hit()];
        s.set_stored_integrity_scan(site.id.as_str(), &was).await;
        s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
            .await
            .expect("tick");
        let rec = record_of(&s, &site).await;
        assert_eq!(rec.result.malware, vec![webshell_hit()]);
        assert_eq!(rec.clamav_at, night(0) - 7 * DAY);
        assert!(rec.result.error.expect("said").contains("six hours"));
    }

    /// The pass didn't start: hits stand, their age stays, and no words from
    /// clamscan (tenant file names) reach the record.
    #[tokio::test]
    async fn a_pass_that_could_not_start_keeps_prior_hits_and_stores_no_tenant_text() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), 8 * GIB, |_| {
            Err(AdapterError::Command {
                cmd: "clamscan".into(),
                code: 2,
                stderr_tail: "/home/x/htdocs/<b>evil</b>.php: Can't open".into(),
            })
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = night(0);
        let mut prior = scanned(now - 60, now);
        prior.clamav_at = now - 7 * DAY;
        prior.result.clamav_available = true;
        prior.result.malware = vec![webshell_hit()];
        s.set_stored_integrity_scan(site.id.as_str(), &prior).await;

        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, now)
                .await
                .expect("tick"),
            0
        );

        let rec = record_of(&s, &site).await;
        assert_eq!(rec.result.malware, vec![webshell_hit()]);
        assert_eq!(rec.clamav_at, now - 7 * DAY);
        assert_eq!(rec.clamav_failed_at, 0);
        assert!(rec.result.clamav_available, "the last pass's word stands");
        let error = rec.result.error.expect("said");
        assert!(
            !error.contains("evil") && !error.contains("/home"),
            "{error}"
        );
        // The week is spent: it isn't retried every ten minutes.
        s.site_scan_clamav_tick_at(&chrono::Utc, now + 600)
            .await
            .expect("tick");
    }

    /// Names ClamAV wasn't given, files the walk skipped and a list cut at its cap
    /// are on that site's card and nowhere else, and they make the pass partial for
    /// that site: it adds hits and clears none, so hiding a file doesn't launder a
    /// detection (`ln shell.php .x`, a renamed `shell\t.php`).
    #[tokio::test]
    async fn what_the_list_left_out_is_noted_and_keeps_the_hit() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks_many();
        a.expect_clamav_facts().returning(|| facts(8 * GIB));
        a.expect_clamav_stop_orphan().returning(|| ());
        a.expect_clamav_prepare().returning(|roots, _, _| {
            Ok(plan_for(roots, |l, root| {
                if root.contains("odd.cz") {
                    l.left_out = 3;
                    l.skipped = 2;
                    l.capped = true;
                    l.node_full = true;
                }
            }))
        });
        a.expect_clamav_run()
            .returning(|_| sweep(integrity::SweepEnd::Complete, vec![]));
        let s = svc(pool.clone(), a);
        let odd = site_named(&s, "odd.cz").await;
        let plain = site_named(&s, "plain.cz").await;
        for d in [&odd, &plain] {
            let mut r = scanned(night(0) - 60, night(0));
            r.clamav_at = night(0) - 7 * DAY;
            r.result.clamav_available = true;
            r.result.malware = vec![hyperion_types::WpMalwareHit {
                path: format!("{}/shell.php", d.root_dir),
                signature: "Php.Trojan.Webshell-1".into(),
            }];
            s.set_stored_integrity_scan(d.id.as_str(), &r).await;
        }
        s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
            .await
            .expect("tick");
        let rec = record_of(&s, &odd).await;
        let said = rec.result.error.clone().expect("said");
        for want in [
            "3 file(s)",
            "2 file(s)",
            "first 2 files",
            "list for this node",
        ] {
            assert!(said.contains(want), "{want} in {said}");
        }
        assert_eq!(
            rec.result.malware.len(),
            1,
            "a pass that missed files clears nothing"
        );
        assert_eq!(rec.clamav_at, night(0) - 7 * DAY);
        // The site with nothing left out is covered, and its cleaned file clears.
        let rec = record_of(&s, &plain).await;
        assert_eq!(rec.result.error, None);
        assert!(rec.result.malware.is_empty());
        assert_eq!(rec.clamav_at, night(0));
    }

    /// A read error on one site's file makes that site partial, and the others
    /// are not.
    #[tokio::test]
    async fn an_unread_site_is_partial_and_the_rest_are_not() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks_many(), 8 * GIB, |plan| {
            Ok(integrity::ClamSweep {
                unread: vec![plan.roots[0].0.clone()],
                hits_capped: vec![plan.roots[1].0.clone()],
                ..Default::default()
            })
        });
        let s = svc(pool.clone(), a);
        let sites = [
            site_named(&s, "one.cz").await,
            site_named(&s, "two.cz").await,
        ];
        for d in &sites {
            let mut r = scanned(night(0) - 60, night(0));
            r.result.malware = vec![webshell_hit()];
            r.result.clamav_available = true;
            s.set_stored_integrity_scan(d.id.as_str(), &r).await;
        }
        s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
            .await
            .expect("tick");
        // The list is sorted by id and rotated by the ISO week, so find them by id.
        let mut seen = 0;
        for d in &sites {
            let rec = record_of(&s, d).await;
            let said = rec.result.error.clone().unwrap_or_default();
            if said.contains("could not read some") {
                seen += 1;
                assert_eq!(rec.result.malware, vec![webshell_hit()], "kept");
                assert!(!said.contains("1000"), "{said}");
            } else {
                assert!(said.contains("more than 1000 detections"), "{said}");
                assert!(
                    !said.contains("could not read"),
                    "not blamed on files: {said}"
                );
                assert!(rec.result.malware.is_empty(), "this one was complete");
            }
        }
        assert_eq!(seen, 1);
    }

    /// One site that can't be walked in full is partial and keeps its verdict.
    #[tokio::test]
    async fn a_site_that_cannot_be_listed_is_partial_with_a_note() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks_many();
        a.expect_clamav_facts().returning(|| facts(8 * GIB));
        a.expect_clamav_stop_orphan().returning(|| ());
        a.expect_clamav_prepare().returning(|roots, _, _| {
            Ok(plan_for(roots, |l, root| {
                l.failed = root.contains("one.cz")
            }))
        });
        a.expect_clamav_run()
            .returning(|_| sweep(integrity::SweepEnd::Complete, vec![]));
        let s = svc(pool.clone(), a);
        let one = site_named(&s, "one.cz").await;
        let two = site_named(&s, "two.cz").await;
        let failing = if one.id.as_str().len() % 2 == 0 {
            &one
        } else {
            &two
        };
        let mut r = scanned(night(0) - 60, night(0));
        r.result.clamav_available = true;
        s.set_stored_integrity_scan(failing.id.as_str(), &r).await;
        s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
            .await
            .expect("tick");
        let rec = record_of(&s, failing).await;
        assert!(rec.result.error.expect("said").contains("could not list"));
        assert_eq!(rec.clamav_at, 0, "no pass vouched for it");
    }

    /// The list starts at a different site each ISO week, so the byte cap isn't
    /// always cutting the same ones.
    #[tokio::test]
    async fn the_list_starts_at_a_different_site_each_week() {
        let pool = open_memory().await.expect("open");
        let firsts: Arc<StdMutex<Vec<String>>> = Arc::default();
        let f = firsts.clone();
        let mut a = happy_mocks_many();
        a.expect_clamav_facts().returning(|| facts(8 * GIB));
        a.expect_clamav_stop_orphan().returning(|| ());
        a.expect_clamav_prepare().returning(move |roots, _, _| {
            f.lock()
                .expect("lock")
                .push(roots[0].0.as_str().to_string());
            Ok(plan_for(roots, |_, _| {}))
        });
        a.expect_clamav_run()
            .returning(|_| sweep(integrity::SweepEnd::Complete, vec![]));
        let s = svc(pool.clone(), a);
        for d in ["a.cz", "b.cz", "c.cz"] {
            site_named(&s, d).await;
        }
        for week in 0..3 {
            s.site_scan_clamav_tick_at(&chrono::Utc, night(week))
                .await
                .expect("tick");
        }
        let firsts = firsts.lock().expect("lock");
        assert_eq!(firsts.len(), 3);
        let distinct: std::collections::HashSet<_> = firsts.iter().collect();
        assert_eq!(distinct.len(), 3, "three weeks, three starts: {firsts:?}");
    }

    /// A restart in the middle of a pass: the next tick stops the orphan unit, the
    /// cards say so, and the pass is tried again the next night, not in a week.
    #[tokio::test]
    async fn a_restart_during_a_pass_retries_the_next_night() {
        let pool = open_memory().await.expect("open");
        let stops = Arc::new(AtomicUsize::new(0));
        let runs = Arc::new(AtomicUsize::new(0));
        let (st, n) = (stops.clone(), runs.clone());
        let mut a = happy_mocks();
        a.expect_clamav_facts().returning(|| facts(8 * GIB));
        a.expect_clamav_stop_orphan().returning(move || {
            st.fetch_add(1, Ordering::SeqCst);
        });
        a.expect_clamav_prepare()
            .returning(|roots, _, _| Ok(plan_for(roots, |_, _| {})));
        a.expect_clamav_run().returning(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(night(0) - 60, night(0)))
            .await;
        // The earlier agent stamped the week and began; it never finished.
        hyperion_state::node_kv::set(
            &pool,
            "site_scan_clamav_at",
            &(night(0) - HOUR).to_string(),
            1,
        )
        .await
        .expect("stamp");
        hyperion_state::node_kv::set(
            &pool,
            "clamav_sweep_state",
            &format!("started {}", night(0) - HOUR),
            1,
        )
        .await
        .expect("state");

        s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
            .await
            .expect("tick");
        assert_eq!(stops.load(Ordering::SeqCst), 1, "the orphan is stopped");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        let said = record_of(&s, &site).await.result.error.expect("said");
        assert!(said.contains("interrupted"), "{said}");
        // Not the rest of this night, and not the week.
        s.site_scan_clamav_tick_at(&chrono::Utc, night(0) + 600)
            .await
            .expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
        s.site_scan_clamav_tick_at(&chrono::Utc, night(0) + DAY)
            .await
            .expect("tick");
        assert_eq!(runs.load(Ordering::SeqCst), 1, "tomorrow night");
        assert_eq!(stops.load(Ordering::SeqCst), 1, "and once");
        assert_eq!(record_of(&s, &site).await.result.error, None);
        let state = hyperion_state::node_kv::get(&pool, "clamav_sweep_state")
            .await
            .expect("kv")
            .expect("set");
        assert!(state.starts_with("finished "), "{state}");
    }

    /// A pass that can't be started or whose unit name is taken is tried again the
    /// next night.
    #[tokio::test]
    async fn a_failed_start_retries_the_next_night_not_next_week() {
        for refused in [true, false] {
            let pool = open_memory().await.expect("open");
            let runs = Arc::new(AtomicUsize::new(0));
            let n = runs.clone();
            let a = with_clamav(happy_mocks(), 8 * GIB, move |_| {
                n.fetch_add(1, Ordering::SeqCst);
                if refused {
                    Err(AdapterError::Other("no".into()))
                } else {
                    sweep(integrity::SweepEnd::Failed, vec![])
                }
            });
            let s = svc(pool.clone(), a);
            let site = site_named(&s, "kos.cz").await;
            s.set_stored_integrity_scan(site.id.as_str(), &scanned(night(0) - 60, night(0)))
                .await;
            s.site_scan_clamav_tick_at(&chrono::Utc, night(0))
                .await
                .expect("tick");
            assert_eq!(runs.load(Ordering::SeqCst), 1);
            assert!(record_of(&s, &site)
                .await
                .result
                .error
                .expect("said")
                .contains("tomorrow night"));
            s.site_scan_clamav_tick_at(&chrono::Utc, night(0) + 600)
                .await
                .expect("tick");
            assert_eq!(runs.load(Ordering::SeqCst), 1, "not the same night");
            s.site_scan_clamav_tick_at(&chrono::Utc, night(0) + DAY)
                .await
                .expect("tick");
            assert_eq!(runs.load(Ordering::SeqCst), 2, "refused {refused}");
        }
    }

    /// A hit restored from quarantine while the pass ran is not lost to a pass
    /// that looked at that place before the file was back; one restored before it
    /// began is the pass's own business and is forgotten.
    #[tokio::test]
    async fn a_hit_restored_during_the_pass_is_not_lost() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), 8 * GIB, |_| {
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = night(0);
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        let mid = hyperion_types::WpMalwareHit {
            path: format!("{}/wp-content/uploads/mid.php", site.root_dir),
            signature: "Php.Trojan.Webshell-1".into(),
        };
        let older = hyperion_types::WpMalwareHit {
            path: format!("{}/wp-content/uploads/older.php", site.root_dir),
            signature: "Php.Trojan.Webshell-1".into(),
        };
        s.clamav_note_restored(site.id.as_str(), std::slice::from_ref(&older), now - 1)
            .await;
        s.clamav_note_restored(site.id.as_str(), std::slice::from_ref(&mid), now + 30)
            .await;

        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, now)
                .await
                .expect("tick"),
            1,
            "the restored hit is told about, being new to the record"
        );
        let rec = record_of(&s, &site).await;
        assert_eq!(rec.result.malware, vec![mid.clone()]);
        let left = s.clamav_restored(site.id.as_str()).await;
        assert_eq!(left.len(), 1, "the older entry is dropped");
        assert_eq!(left[0].path, mid.path);
    }

    /// "Scan now" and the blocking scan leave ClamAV alone, and the weekly
    /// verdict survives them.
    #[tokio::test]
    async fn the_blocking_scan_never_runs_clamav_and_keeps_its_verdict() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_clamav_facts().never();
        a.expect_clamav_prepare().never();
        a.expect_clamav_run().never();
        a.expect_site_scan_worker()
            .returning(|_| WorkerReply::Failed("no".into()));
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let mut prior = scanned(1, 1);
        prior.clamav_at = 777;
        prior.result.clamav_available = true;
        prior.result.malware = vec![webshell_hit()];
        s.set_stored_integrity_scan(site.id.as_str(), &prior).await;
        let r = s
            .wp_integrity_scan(HostingSelector::Id(site.id.clone()))
            .await
            .expect("scan");
        assert!(!r.native_scan_ran);
        assert!(r.clamav_available, "last week's pass still stands");
        assert_eq!(r.malware, vec![webshell_hit()]);
        assert_eq!(r.clamav_at, 777, "the card can say when it last ran");
        assert!(r.error.is_some());
    }

    /// A pass that finishes while a long scan of that site runs keeps its result:
    /// the scan's store doesn't write back what it read when it started.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_scans_store_keeps_a_clamav_result_from_during_its_run() {
        let pool = open_memory().await.expect("open");
        let during = pool.clone();
        let id_slot: Arc<StdMutex<String>> = Arc::new(StdMutex::new(String::new()));
        let id_for_mock = id_slot.clone();
        let now = monday_at(0, 12, 0);
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => {
                let id = id_for_mock.lock().expect("lock").clone();
                let mut rec = scanned(now - 7 * HOUR, now);
                rec.clamav_at = now - 60;
                rec.result.clamav_available = true;
                rec.result.malware = vec![webshell_hit()];
                let json = serde_json::to_string(&rec).expect("json");
                let pool = during.clone();
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        hyperion_state::hosting_kv::set(&pool, &id, INTEGRITY_KV_KEY, &json, 1)
                            .await
                            .expect("kv")
                    })
                });
                WorkerReply::Scan(upstream_verified(0))
            }
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        *id_slot.lock().expect("lock") = site.id.as_str().to_string();
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 7 * HOUR, now))
            .await;

        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick"),
            0
        );
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.scanned_at, now);
        assert_eq!(rec.clamav_at, now - 60);
        assert_eq!(rec.result.malware, vec![webshell_hit()]);
        assert!(rec.result.clamav_available);
    }

    // ---- what other people read ----

    #[tokio::test]
    async fn the_dashboard_list_leaves_file_lists_out() {
        let pool = open_memory().await.expect("open");
        let s = svc(pool.clone(), happy_mocks());
        let site = site_named(&s, "kos.cz").await;
        let finding = hyperion_types::SiteFileFinding {
            rel: "a.php".into(),
            ..Default::default()
        };
        let mut rec = scanned(1, 1);
        rec.result.findings = vec![finding.clone()];
        rec.result.review = vec![finding];
        rec.result.core_modified = vec!["wp-login.php".into()];
        s.set_stored_integrity_scan(site.id.as_str(), &rec).await;
        let list = s.integrity_findings_list().await.expect("list");
        assert_eq!(list.len(), 1);
        assert!(list[0].result.findings.is_empty());
        assert!(list[0].result.review.is_empty());
        assert_eq!(list[0].result.total_findings(), 1, "the counts stay");
    }

    // ---- a request can't take the node for itself ----

    /// Which docroots the worker was asked to look at, in order.
    fn recording_discovers(
        mut a: MockAdapterPort,
        order: Arc<StdMutex<Vec<std::path::PathBuf>>>,
    ) -> MockAdapterPort {
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { root } => {
                order.lock().expect("lock").push(root);
                WorkerReply::Discovery(Discovery::default())
            }
            WorkerJob::Scan(_) => WorkerReply::Scan(upstream_verified(0)),
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        a
    }

    /// After a requested site, one the schedule says is due goes before the next
    /// request. A queued site that turns out not to be due any more doesn't count
    /// as that turn.
    #[tokio::test]
    async fn a_scheduled_site_runs_between_requests() {
        let pool = open_memory().await.expect("open");
        let order = Arc::new(StdMutex::new(Vec::new()));
        let a = recording_discovers(happy_mocks_many(), order.clone());
        let s = svc(pool.clone(), a);
        let now = monday_at(0, 12, 0);
        let asked_first = site_named(&s, "asked-first.cz").await;
        let asked_next = site_named(&s, "asked-next.cz").await;
        let waiting = site_named(&s, "waiting.cz").await;
        // Oldest of all, so it's first in the queue, and its request satisfies it.
        s.set_stored_integrity_scan(asked_first.id.as_str(), &scanned(now - 9 * HOUR, now))
            .await;
        s.set_stored_integrity_scan(asked_next.id.as_str(), &scanned(now - 60, now))
            .await;
        s.set_stored_integrity_scan(waiting.id.as_str(), &scanned(now - 7 * HOUR, now))
            .await;
        for (site, at) in [(&asked_first, "100"), (&asked_next, "200")] {
            hyperion_state::hosting_kv::set(&pool, site.id.as_str(), "scan_requested", at, 1)
                .await
                .expect("kv");
        }

        s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick");

        let root = |d: &HostingDetail| std::path::PathBuf::from(&d.root_dir);
        assert_eq!(
            *order.lock().expect("lock"),
            vec![root(&asked_first), root(&waiting), root(&asked_next)]
        );
    }

    /// One tenant clicking can't keep the worker on their site: a request is
    /// honoured once in ten minutes, and the click stays queued meanwhile.
    #[tokio::test]
    async fn a_site_is_honoured_once_every_ten_minutes() {
        let pool = open_memory().await.expect("open");
        let order = Arc::new(StdMutex::new(Vec::new()));
        let a = recording_discovers(happy_mocks(), order.clone());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let sel = HostingSelector::Id(site.id.clone());
        let t0 = monday_at(0, 12, 0);
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(t0 - 60, t0))
            .await;
        let ran = || order.lock().expect("lock").len();

        s.wp_integrity_scan_request(sel.clone())
            .await
            .expect("request");
        s.site_scan_tick_at(&chrono::Utc, t0).await.expect("tick");
        assert_eq!(ran(), 1);

        s.wp_integrity_scan_request(sel.clone())
            .await
            .expect("request");
        s.site_scan_tick_at(&chrono::Utc, t0 + 599)
            .await
            .expect("tick");
        assert_eq!(ran(), 1, "too soon");
        assert!(
            s.wp_integrity_stored(sel.clone())
                .await
                .expect("stored")
                .scan_queued,
            "still queued, not dropped"
        );

        s.site_scan_tick_at(&chrono::Utc, t0 + 600)
            .await
            .expect("tick");
        assert_eq!(ran(), 2);
        assert!(
            !s.wp_integrity_stored(sel)
                .await
                .expect("stored")
                .scan_queued
        );
    }

    // ---- a record that can't be read isn't one that isn't there ----

    /// The next read of this hosting's record fails, while a write would succeed:
    /// what a passing database error looks like to the code under test.
    fn make_record_unreadable(pool: &SqlitePool, id: &str) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query(
                    "UPDATE hosting_kv SET value = x'7b7d' WHERE hosting_id = ? AND key = ?",
                )
                .bind(id)
                .bind(INTEGRITY_KV_KEY)
                .execute(pool)
                .await
                .expect("poison");
            })
        });
    }

    async fn record_was_left_alone(
        s: &HostingService<MockAdapterPort>,
        pool: &SqlitePool,
        id: &str,
    ) {
        assert!(
            s.integrity_record(id).await.is_err(),
            "the read really fails"
        );
        let (kind,): (String,) =
            sqlx::query_as("SELECT typeof(value) FROM hosting_kv WHERE hosting_id = ? AND key = ?")
                .bind(id)
                .bind(INTEGRITY_KV_KEY)
                .fetch_one(pool)
                .await
                .expect("typeof");
        assert_eq!(kind, "blob", "nothing was written over it");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_clamav_pass_that_cant_reread_the_record_stores_nothing() {
        let pool = open_memory().await.expect("open");
        let id_slot = Arc::new(StdMutex::new(String::new()));
        let (during, slot) = (pool.clone(), id_slot.clone());
        let a = with_clamav(happy_mocks(), 8 * GIB, move |lists| {
            make_record_unreadable(&during, &slot.lock().expect("lock"));
            sweep(integrity::SweepEnd::Complete, vec![found_in(lists, 0)])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        *id_slot.lock().expect("lock") = site.id.as_str().to_string();
        let now = night(0);
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, now)
                .await
                .expect("tick"),
            0
        );
        record_was_left_alone(&s, &pool, site.id.as_str()).await;
    }

    /// The scan's store: nothing written, no alert it couldn't remember sending,
    /// and the request still stands. The blocking scan won't start on such a read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_scan_that_cant_reread_the_record_stores_nothing() {
        let pool = open_memory().await.expect("open");
        let id_slot = Arc::new(StdMutex::new(String::new()));
        let (during, slot) = (pool.clone(), id_slot.clone());
        let mut tampered = upstream_verified(0);
        tampered.upstream.core_modified = vec!["wp-login.php".into()];
        let mut a = happy_mocks();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::WriterHash { .. } => WorkerReply::Hashed {
                listed: 0,
                partial: false,
            },
            WorkerJob::Discover { .. } => WorkerReply::Discovery(Discovery::default()),
            WorkerJob::Scan(_) => {
                make_record_unreadable(&during, &slot.lock().expect("lock"));
                WorkerReply::Scan(tampered.clone())
            }
        });
        a.expect_site_scan_evict_manifests().returning(|_| ());
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let id = site.id.as_str();
        *id_slot.lock().expect("lock") = id.to_string();
        let now = monday_at(0, 12, 0);
        s.set_stored_integrity_scan(id, &scanned(now - 7 * HOUR, now))
            .await;
        hyperion_state::hosting_kv::set(&pool, id, "scan_requested", "100", 1)
            .await
            .expect("kv");

        assert_eq!(
            s.site_scan_tick_at(&chrono::Utc, now).await.expect("tick"),
            0
        );
        record_was_left_alone(&s, &pool, id).await;
        assert_eq!(s.scan_request_flag(id).await.as_deref(), Some("100"));

        assert!(s
            .wp_integrity_scan(HostingSelector::Id(site.id.clone()))
            .await
            .is_err());
    }

    /// A pass can take hours, and a scan can store while it runs. That scan has
    /// told admins about its own finding; the sweep says only what ClamAV found.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_clamav_sweep_alerts_only_on_its_own_hits() {
        let pool = open_memory().await.expect("open");
        let id_slot = Arc::new(StdMutex::new(String::new()));
        let (during, slot) = (pool.clone(), id_slot.clone());
        let now = night(0);
        let a = with_clamav(happy_mocks(), 8 * GIB, move |_| {
            let id = slot.lock().expect("lock").clone();
            let mut rec = scanned(now, now);
            rec.result.core_modified = vec!["wp-login.php".into()];
            let json = serde_json::to_string(&rec).expect("json");
            let pool = during.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    hyperion_state::hosting_kv::set(&pool, &id, INTEGRITY_KV_KEY, &json, 1)
                        .await
                        .expect("kv")
                })
            });
            sweep(integrity::SweepEnd::Complete, vec![])
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        *id_slot.lock().expect("lock") = site.id.as_str().to_string();
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        assert_eq!(
            s.site_scan_clamav_tick_at(&chrono::Utc, now)
                .await
                .expect("tick"),
            0
        );
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.result.core_modified, vec!["wp-login.php"], "kept");
        assert_eq!(rec.clamav_at, now);
    }

    // ---- vendor packages ----

    use crate::service::scan_queue::{
        hold_vendor_differences, VendorPass, VendorSite, VendorStop, VENDOR_DB_UNREADABLE,
        VENDOR_NOT_OWN_DB, VENDOR_NO_CONFIG, VENDOR_NO_LOGIN, VENDOR_NO_UPDATE_DATA,
    };
    use hyperion_adapters::sitescan::vendor::{VendorError, VendorFetched, MAX_UNKNOWN_HOSTS};
    use hyperion_types::{FindingKind, PACKAGES_DISAGREE_LABEL, VENDOR_PACKAGE_LABEL};

    const PLUGINS_OPTION: &str = "_site_transient_update_plugins";
    const THEMES_OPTION: &str = "_site_transient_update_themes";
    const VENDOR_NOW: i64 = 2_000_000;

    fn php(v: &str) -> String {
        format!("s:{}:\"{v}\";", v.len())
    }

    /// Hand-written to the shape `wp_update_plugins()` stores; not from a real site.
    /// Entries are `(slug, version, url)`.
    fn plugins_transient(
        response: &[(&str, &str, &str)],
        no_update: &[(&str, &str, &str)],
    ) -> String {
        let list = |entries: &[(&str, &str, &str)]| {
            let body: String = entries
                .iter()
                .map(|(slug, version, url)| {
                    format!(
                        r#"{}O:8:"stdClass":3:{{{}{}{}{}{}{}}}"#,
                        php(&format!("{slug}/{slug}.php")),
                        php("slug"),
                        php(slug),
                        php("new_version"),
                        php(version),
                        php("package"),
                        php(url),
                    )
                })
                .collect();
            format!("a:{}:{{{body}}}", entries.len())
        };
        format!(
            r#"O:8:"stdClass":2:{{{}{}{}{}}}"#,
            php("response"),
            list(response),
            php("no_update"),
            list(no_update),
        )
    }

    /// A site with these on version 1.0.
    fn site_with(slugs: &[&str]) -> VendorSite {
        VendorSite {
            candidates: slugs.iter().map(|s| plugin(s).key).collect(),
            ..Default::default()
        }
    }

    fn owns_its_config(a: &mut MockAdapterPort) {
        a.expect_site_scan_wp_config_db()
            .returning(|_| Some(("lm_a".to_string(), "wp_".to_string())));
    }

    /// For several hostings, each with a database of its own: every `wp-config.php`
    /// names its own, once it's been told which that is.
    fn configs_by_root(
        a: &mut MockAdapterPort,
    ) -> Arc<StdMutex<std::collections::BTreeMap<String, String>>> {
        let names = Arc::new(StdMutex::new(std::collections::BTreeMap::new()));
        let names2 = names.clone();
        a.expect_site_scan_wp_config_db().returning(move |root| {
            let names = names2.lock().expect("lock");
            names
                .get(&root.display().to_string())
                .map(|db: &String| (db.clone(), "wp_".to_string()))
        });
        names
    }

    fn own_config(
        names: &Arc<StdMutex<std::collections::BTreeMap<String, String>>>,
        detail: &HostingDetail,
    ) {
        names.lock().expect("lock").insert(
            detail.root_dir.clone(),
            detail.database.as_ref().expect("db").db_name.clone(),
        );
    }

    /// Everything the pass can ask for answered, the options by `plugins`.
    fn vendor_mocks(
        plugins: String,
        fetched: Arc<StdMutex<Vec<(String, String, bool)>>>,
    ) -> MockAdapterPort {
        let mut a = happy_mocks();
        owns_its_config(&mut a);
        a.expect_site_scan_read_option()
            .returning(move |_, _, option, _, _| {
                Ok((option == PLUGINS_OPTION).then(|| plugins.clone()))
            });
        a.expect_site_scan_vendor_fetch().returning(move |p, _, _| {
            fetched.lock().expect("lock").push((
                p.slug.clone(),
                p.version.clone(),
                p.verifies_today,
            ));
            Ok(VendorFetched::Confirmed)
        });
        a
    }

    async fn pass_of(
        s: &HostingService<MockAdapterPort>,
        detail: &HostingDetail,
        site: &VendorSite,
        dir: &std::path::Path,
    ) -> VendorPass {
        s.site_scan_vendor_pass(detail, site, dir, VENDOR_NOW).await
    }

    async fn leave_site(pool: &SqlitePool, id: &str, site: &VendorSite) {
        hyperion_state::hosting_kv::set(
            pool,
            id,
            "scan_vendor_site",
            &serde_json::to_string(site).expect("json"),
            1,
        )
        .await
        .expect("kv");
    }

    #[tokio::test]
    async fn wp_config_naming_another_tenants_db_is_ignored() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        // Another hosting's database, by its exact name.
        a.expect_site_scan_wp_config_db()
            .returning(|_| Some(("lm_victim".to_string(), "wp_".to_string())));
        a.expect_site_scan_read_option().never();
        a.expect_site_scan_vendor_fetch().never();
        let s = svc(pool, a);
        let detail = site_named(&s, "a.test").await;
        assert_eq!(detail.database.as_ref().expect("db").db_name, "lm_a");
        let tmp = tempfile::tempdir().expect("tmp");
        let pass = pass_of(&s, &detail, &site_with(&["pro"]), tmp.path()).await;
        assert_eq!(pass.note.as_deref(), Some(VENDOR_NOT_OWN_DB));
        assert!(pass.unknown_hosts.is_empty());
    }

    /// An imported site with no database row: nothing to hold the file's claim
    /// against, so the file isn't even asked.
    #[tokio::test]
    async fn a_hosting_with_no_database_of_its_own_has_no_vendor_step() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_wp_config_db().never();
        a.expect_site_scan_read_option().never();
        a.expect_site_scan_vendor_fetch().never();
        let s = svc(pool, a);
        s.create(req_no_db("a.test")).await.expect("create");
        let detail = s
            .get(HostingSelector::Domain(
                Domain::parse("a.test").expect("parse"),
            ))
            .await
            .expect("get");
        let tmp = tempfile::tempdir().expect("tmp");
        let pass = pass_of(&s, &detail, &site_with(&["pro"]), tmp.path()).await;
        assert_eq!(pass.note.as_deref(), Some(VENDOR_NOT_OWN_DB));
    }

    #[tokio::test]
    async fn the_transients_are_read_as_the_hostings_own_login() {
        let pool = open_memory().await.expect("open");
        let asked = Arc::new(StdMutex::new(Vec::new()));
        let asked2 = asked.clone();
        let mut a = happy_mocks();
        owns_its_config(&mut a);
        a.expect_site_scan_read_option()
            .returning(move |db, prefix, option, user, password| {
                asked2.lock().expect("lock").push((
                    db.to_string(),
                    prefix.to_string(),
                    option.to_string(),
                    user.to_string(),
                    password.to_string(),
                ));
                Ok(Some("a:0:{}".to_string()))
            });
        a.expect_site_scan_vendor_fetch().never();
        let s = svc(pool, a);
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let pass = pass_of(&s, &detail, &site_with(&["pro"]), tmp.path()).await;
        assert_eq!(pass, VendorPass::default());
        let asked = asked.lock().expect("lock").clone();
        let row = |option: &str| {
            (
                "lm_a".to_string(),
                "wp_".to_string(),
                option.to_string(),
                "lm_u".to_string(),
                "p".to_string(),
            )
        };
        assert_eq!(asked, [row(PLUGINS_OPTION), row(THEMES_OPTION)]);
    }

    #[tokio::test]
    async fn no_credentials_is_a_note_on_that_site_alone() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_wp_config_db()
            .returning(|_| Some(("lm_nosecret".to_string(), "wp_".to_string())));
        a.expect_site_scan_read_option().never();
        let s = svc(pool.clone(), a);
        let detail = site_named(&s, "a.test").await;
        databases::insert(
            &pool,
            &detail.id,
            DbProvision::MariaDB,
            "lm_nosecret",
            "lm_nosecret_u",
            &hyperion_types::SecretId("gone".into()),
            1,
        )
        .await
        .expect("insert");
        let tmp = tempfile::tempdir().expect("tmp");
        let pass = pass_of(&s, &detail, &site_with(&["pro"]), tmp.path()).await;
        assert_eq!(pass.note.as_deref(), Some(VENDOR_NO_LOGIN));
    }

    /// A rejected password looks like this too.
    #[tokio::test]
    async fn an_unreadable_database_is_a_note_and_nothing_else() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        owns_its_config(&mut a);
        a.expect_site_scan_read_option()
            .returning(|_, _, _, _, _| Err(hyperion_adapters::AdapterError::Other("down".into())));
        a.expect_site_scan_vendor_fetch().never();
        let s = svc(pool, a);
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let pass = pass_of(&s, &detail, &site_with(&["pro"]), tmp.path()).await;
        assert_eq!(pass.note.as_deref(), Some(VENDOR_DB_UNREADABLE));
    }

    #[tokio::test]
    async fn no_update_data_or_no_config_is_a_note() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        let config = Arc::new(AtomicUsize::new(0));
        let config2 = config.clone();
        a.expect_site_scan_wp_config_db().returning(move |_| {
            // Found once, then gone.
            (config2.fetch_add(1, Ordering::SeqCst) == 0)
                .then(|| ("lm_a".to_string(), "wp_".to_string()))
        });
        // Multisite and an external object cache keep it elsewhere.
        a.expect_site_scan_read_option()
            .returning(|_, _, _, _, _| Ok(None));
        a.expect_site_scan_vendor_fetch().never();
        let s = svc(pool, a);
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let site = site_with(&["pro"]);
        let pass = pass_of(&s, &detail, &site, tmp.path()).await;
        assert_eq!(pass.note.as_deref(), Some(VENDOR_NO_UPDATE_DATA));
        let pass = pass_of(&s, &detail, &site, tmp.path()).await;
        assert_eq!(pass.note.as_deref(), Some(VENDOR_NO_CONFIG));
    }

    #[tokio::test]
    async fn no_update_verifies_current_version_response_only_prepares_next() {
        let pool = open_memory().await.expect("open");
        let fetched = Arc::new(StdMutex::new(Vec::new()));
        let text = plugins_transient(
            &[("aaa", "2.0", "https://wpml.org/next.zip")],
            &[("pro", "1.0", "https://my.elementor.com/today.zip?license=K")],
        );
        let s = svc(pool, vendor_mocks(text, fetched.clone()));
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let pass = pass_of(&s, &detail, &site_with(&["aaa", "pro"]), tmp.path()).await;
        assert_eq!(pass, VendorPass::default());
        assert_eq!(
            *fetched.lock().expect("lock"),
            [
                ("pro".to_string(), "1.0".to_string(), true),
                ("aaa".to_string(), "2.0".to_string(), false),
            ],
            "today's first"
        );
    }

    fn packages(n: usize) -> Vec<(String, String, String)> {
        (0..n)
            .map(|i| {
                (
                    format!("p{i}"),
                    "1.0".to_string(),
                    "https://wpml.org/p.zip".to_string(),
                )
            })
            .collect()
    }

    fn views(p: &[(String, String, String)]) -> Vec<(&str, &str, &str)> {
        p.iter()
            .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
            .collect()
    }

    /// Ten an hour by the clock, however often the tick is woken and whatever a
    /// restart forgets: 3 a pass until the ten are gone, then none till the hour.
    #[tokio::test]
    async fn the_budget_is_by_the_clock_and_a_wake_doesnt_refill_it() {
        let pool = open_memory().await.expect("open");
        let fetched = Arc::new(StdMutex::new(Vec::new()));
        let all = packages(30);
        let text = plugins_transient(&[], &views(&all));
        let mut a = vendor_mocks(text, fetched.clone());
        a.expect_site_scan_evict_manifests().returning(|_| ());
        a.expect_site_scan_worker()
            .returning(|_| WorkerReply::Failed("not this test's concern".into()));
        let s = svc(pool.clone(), a);
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        let slugs: Vec<&str> = all.iter().map(|(p, _, _)| p.as_str()).collect();
        leave_site(&pool, detail.id.as_str(), &site_with(&slugs)).await;
        let count = || fetched.lock().expect("lock").len();

        // Woken over and over within the hour, with a site scan tick between.
        for (i, expected) in [3, 6, 9, 10, 10, 10].into_iter().enumerate() {
            let now = VENDOR_NOW + i64::try_from(i).expect("i") * 60;
            s.site_scan_vendor_tick_at(now).await.expect("tick");
            assert_eq!(count(), expected, "tick {i}");
            s.site_scan_tick_at(&chrono::Utc, now)
                .await
                .expect("scan tick");
        }
        // Past the hour there's more.
        s.site_scan_vendor_tick_at(VENDOR_NOW + 3601)
            .await
            .expect("tick");
        assert_eq!(count(), 13);
    }

    #[tokio::test]
    async fn the_budget_survives_a_restart() {
        let pool = open_memory().await.expect("open");
        let fetched = Arc::new(StdMutex::new(Vec::new()));
        let all = packages(30);
        let text = plugins_transient(&[], &views(&all));
        let s = svc(pool.clone(), vendor_mocks(text.clone(), fetched.clone()));
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        let slugs: Vec<&str> = all.iter().map(|(p, _, _)| p.as_str()).collect();
        leave_site(&pool, detail.id.as_str(), &site_with(&slugs)).await;
        for i in 0..4 {
            s.site_scan_vendor_tick_at(VENDOR_NOW + i)
                .await
                .expect("tick");
        }
        assert_eq!(fetched.lock().expect("lock").len(), 10);

        // The same node's state, a new process.
        let again = svc(pool, vendor_mocks(text, fetched.clone())).with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        again
            .site_scan_vendor_tick_at(VENDOR_NOW + 60)
            .await
            .expect("tick");
        assert_eq!(fetched.lock().expect("lock").len(), 10);
    }

    #[tokio::test]
    async fn the_sweep_doesnt_need_the_nodes_lock() {
        let pool = open_memory().await.expect("open");
        let fetched = Arc::new(StdMutex::new(Vec::new()));
        let text = plugins_transient(&[], &[("pro", "1.0", "https://wpml.org/p.zip")]);
        let s = svc(pool.clone(), vendor_mocks(text, fetched.clone()));
        let detail = site_named(&s, "a.test").await;
        leave_site(&pool, detail.id.as_str(), &site_with(&["pro"])).await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        let _scan_running = s.site_scan.node.lock().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            s.site_scan_vendor_tick_at(VENDOR_NOW),
        )
        .await
        .expect("it doesn't wait for a scan")
        .expect("tick");
        assert_eq!(fetched.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn the_first_timeout_ends_the_sweep() {
        let pool = open_memory().await.expect("open");
        let tries = Arc::new(AtomicUsize::new(0));
        let tries2 = tries.clone();
        let mut a = happy_mocks_many();
        let names = configs_by_root(&mut a);
        let text = plugins_transient(
            &[],
            &[
                ("aaa", "1.0", "https://wpml.org/a.zip"),
                ("pro", "1.0", "https://wpml.org/p.zip"),
            ],
        );
        a.expect_site_scan_read_option()
            .returning(move |_, _, option, _, _| {
                Ok((option == PLUGINS_OPTION).then(|| text.clone()))
            });
        a.expect_site_scan_vendor_fetch().returning(move |_, _, _| {
            tries2.fetch_add(1, Ordering::SeqCst);
            Err(VendorError::TimedOut)
        });
        let s = svc(pool.clone(), a);
        let (one, two) = (
            site_named(&s, "a.test").await,
            site_named(&s, "b.test").await,
        );
        own_config(&names, &one);
        own_config(&names, &two);
        let site = site_with(&["aaa", "pro"]);
        leave_site(&pool, one.id.as_str(), &site).await;
        leave_site(&pool, two.id.as_str(), &site).await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        s.site_scan_vendor_tick_at(VENDOR_NOW).await.expect("tick");
        assert_eq!(
            tries.load(Ordering::SeqCst),
            1,
            "not another package or site"
        );
    }

    #[tokio::test]
    async fn a_pass_isnt_repeated_until_six_hours_or_a_change() {
        let pool = open_memory().await.expect("open");
        let reads = Arc::new(AtomicUsize::new(0));
        let reads2 = reads.clone();
        let mut a = happy_mocks();
        a.expect_site_scan_wp_config_db().returning(move |_| {
            reads2.fetch_add(1, Ordering::SeqCst);
            None
        });
        let s = svc(pool.clone(), a);
        let detail = site_named(&s, "a.test").await;
        leave_site(&pool, detail.id.as_str(), &site_with(&["pro"])).await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        s.site_scan_vendor_tick_at(VENDOR_NOW).await.expect("tick");
        s.site_scan_vendor_tick_at(VENDOR_NOW + 600)
            .await
            .expect("tick");
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        s.site_scan_vendor_tick_at(VENDOR_NOW + 6 * HOUR)
            .await
            .expect("tick");
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    /// A scan that hands the sweep new work during a pass keeps it due.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pass_doesnt_stamp_over_what_a_scan_has_since_asked_for() {
        let pool = open_memory().await.expect("open");
        let pool2 = pool.clone();
        let mut a = happy_mocks();
        // A scan finishing during the pass.
        let id_cell = Arc::new(StdMutex::new(String::new()));
        let id2 = id_cell.clone();
        a.expect_site_scan_wp_config_db().returning(move |_| {
            let (pool, id) = (pool2.clone(), id2.lock().expect("lock").clone());
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(leave_site(
                    &pool,
                    &id,
                    &site_with(&["pro", "new"]),
                ));
            });
            None
        });
        let s = svc(pool.clone(), a);
        let detail = site_named(&s, "a.test").await;
        *id_cell.lock().expect("lock") = detail.id.as_str().to_string();
        leave_site(&pool, detail.id.as_str(), &site_with(&["pro"])).await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        s.site_scan_vendor_tick_at(VENDOR_NOW).await.expect("tick");
        let left = s.vendor_site_for_test(detail.id.as_str()).await;
        assert_eq!(left.pass_at, 0);
        assert_eq!(left.candidates.len(), 2);
    }

    #[tokio::test]
    async fn a_new_manifest_asks_for_a_scan_of_every_site_on_that_version() {
        let pool = open_memory().await.expect("open");
        let answers = Arc::new(StdMutex::new(vec![
            Ok(VendorFetched::Confirmed),
            Ok(VendorFetched::Disputed),
            Ok(VendorFetched::New),
        ]));
        let mut a = happy_mocks_many();
        let names = configs_by_root(&mut a);
        let text = plugins_transient(&[], &[("pro", "1.0", "https://wpml.org/p.zip")]);
        a.expect_site_scan_read_option()
            .returning(move |_, _, option, _, _| {
                Ok((option == PLUGINS_OPTION).then(|| text.clone()))
            });
        let answers2 = answers.clone();
        a.expect_site_scan_vendor_fetch()
            .returning(move |_, _, _| answers2.lock().expect("lock").pop().expect("answer"));
        let s = svc(pool.clone(), a);
        let producer = site_named(&s, "a.test").await;
        let same = site_named(&s, "b.test").await;
        let other = site_named(&s, "c.test").await;
        own_config(&names, &producer);
        leave_site(&pool, producer.id.as_str(), &site_with(&["pro"])).await;
        let mut other_version = site_with(&["pro"]);
        other_version.candidates[0].version = "9.9".into();
        other_version.pass_at = VENDOR_NOW;
        leave_site(&pool, other.id.as_str(), &other_version).await;
        let mut same_version = site_with(&["pro"]);
        same_version.pass_at = VENDOR_NOW;
        leave_site(&pool, same.id.as_str(), &same_version).await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });

        s.site_scan_vendor_tick_at(VENDOR_NOW).await.expect("tick");
        assert!(s.scan_request_flag(producer.id.as_str()).await.is_some());
        assert!(s.scan_request_flag(same.id.as_str()).await.is_some());
        assert!(s.scan_request_flag(other.id.as_str()).await.is_none());
        s.clear_scan_request_for_test(producer.id.as_str()).await;
        s.clear_scan_request_for_test(same.id.as_str()).await;

        // A dispute reaches them too.
        s.site_scan_vendor_tick_at(VENDOR_NOW + 6 * HOUR)
            .await
            .expect("tick");
        assert!(s.scan_request_flag(same.id.as_str()).await.is_some());
        s.clear_scan_request_for_test(producer.id.as_str()).await;
        s.clear_scan_request_for_test(same.id.as_str()).await;

        // A second opinion that agrees changes nothing for anyone.
        s.site_scan_vendor_tick_at(VENDOR_NOW + 12 * HOUR)
            .await
            .expect("tick");
        assert!(s.scan_request_flag(same.id.as_str()).await.is_none());
    }

    #[tokio::test]
    async fn unknown_hosts_reach_the_coverage_and_are_no_failure() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        let text = plugins_transient(
            &[],
            &[
                (
                    "aaa",
                    "1.0",
                    "https://updates.vendor.example/a.zip?license=K",
                ),
                ("pro", "1.0", "https://wpml.org/p.zip"),
            ],
        );
        owns_its_config(&mut a);
        a.expect_site_scan_read_option()
            .returning(move |_, _, option, _, _| {
                Ok((option == PLUGINS_OPTION).then(|| text.clone()))
            });
        // The listed host redirected off the list.
        a.expect_site_scan_vendor_fetch()
            .times(1)
            .returning(|_, _, _| Err(VendorError::UnknownHost("cdn.vendor.example".into())));
        let s = svc(pool, a);
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let pass = pass_of(&s, &detail, &site_with(&["aaa", "pro"]), tmp.path()).await;
        assert_eq!(
            pass.unknown_hosts,
            ["cdn.vendor.example", "updates.vendor.example"]
        );
        assert_eq!(pass.note, None, "the step ran");
        assert_eq!(pass.stop, VendorStop::Done);
    }

    /// A scan leaves the sweep what it needs and nothing from the network happens
    /// under the lock. What the sweep found goes on the coverage, and the worker has
    /// no say in it. A note doesn't make a scan partial.
    #[tokio::test]
    async fn a_scan_leaves_candidates_for_the_sweep_and_takes_its_notes() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_cached_manifest()
            .returning(|_, _| Some(None));
        a.expect_site_scan_cached_slug()
            .returning(|_, _, _| Some(false));
        a.expect_site_scan_wp_config_db().never();
        a.expect_site_scan_read_option().never();
        a.expect_site_scan_vendor_fetch().never();
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::Discover { .. } => WorkerReply::Discovery(discovery_of(vec![plugin("pro")])),
            WorkerJob::Scan(_) => {
                let mut o = upstream_verified(1);
                o.coverage.unknown_vendor_hosts = vec!["forged.example".into()];
                o.coverage.vendor_note = Some("forged".into());
                WorkerReply::Scan(o)
            }
            WorkerJob::WriterHash { .. } => WorkerReply::Failed("unexpected".into()),
        });
        let s = svc(pool.clone(), a);
        let detail = site_named(&s, "a.test").await;
        let id = detail.id.as_str();
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });

        let run = s.site_scan_locked(&detail, ScanMode::Delta, None, VENDOR_NOW);
        let SiteScanRun::Finished { result, native_ran } = run.await else {
            panic!("the scan ran");
        };
        assert!(native_ran);
        assert!(result.coverage.unknown_vendor_hosts.is_empty());
        assert_eq!(result.coverage.vendor_note, None);
        let raw = hyperion_state::hosting_kv::get(&pool, id, "scan_vendor_site")
            .await
            .expect("kv")
            .expect("left");
        let left: VendorSite = serde_json::from_str(&raw).expect("json");
        assert_eq!(left.candidates, [plugin("pro").key]);
        assert_eq!(left.pass_at, 0, "new to the sweep");

        // What the sweep said, on this site's next scan.
        let swept = VendorSite {
            note: Some(VENDOR_NO_CONFIG.to_string()),
            unknown_hosts: vec!["updates.vendor.example".into()],
            pass_at: VENDOR_NOW,
            ..left
        };
        leave_site(&pool, id, &swept).await;
        let run = s.site_scan_locked(&detail, ScanMode::Delta, None, VENDOR_NOW);
        let SiteScanRun::Finished { result, .. } = run.await else {
            panic!("the scan ran");
        };
        assert_eq!(
            result.coverage.vendor_note.as_deref(),
            Some(VENDOR_NO_CONFIG)
        );
        assert_eq!(
            result.coverage.unknown_vendor_hosts,
            ["updates.vendor.example"]
        );
        assert!(!result.scan_partial());
        // Nothing changed, so the stamp stands.
        let raw = hyperion_state::hosting_kv::get(&pool, id, "scan_vendor_site")
            .await
            .expect("kv")
            .expect("left");
        let left: VendorSite = serde_json::from_str(&raw).expect("json");
        assert_eq!(left.pass_at, VENDOR_NOW);
    }

    fn vendor_issue(slug: &str, label: &str) -> hyperion_types::WpIntegrityPluginResult {
        hyperion_types::WpIntegrityPluginResult {
            slug: slug.into(),
            version: "1.0".into(),
            source: Some(label.into()),
            issues: vec![hyperion_types::WpIntegrityFileIssue {
                path: format!("wp-content/plugins/{slug}/a.php"),
                message: "modified".into(),
            }],
        }
    }

    fn vendor_finding(slug: &str, label: &str) -> hyperion_types::SiteFileFinding {
        hyperion_types::SiteFileFinding {
            rel: format!("wp-content/plugins/{slug}/a.php"),
            kind: FindingKind::UpstreamModified,
            severity: "high".into(),
            component: Some(slug.into()),
            source_label: Some(label.into()),
            ..Default::default()
        }
    }

    fn vendor_outcome() -> SiteScanOutcome {
        let mut o = upstream_verified(3);
        o.upstream.plugins_failed = vec![
            vendor_issue("pro", VENDOR_PACKAGE_LABEL),
            vendor_issue("akismet", "wordpress.org"),
            vendor_issue("split", PACKAGES_DISAGREE_LABEL),
        ];
        o.findings = vec![
            vendor_finding("pro", VENDOR_PACKAGE_LABEL),
            vendor_finding("akismet", "wordpress.org"),
            vendor_finding("split", PACKAGES_DISAGREE_LABEL),
        ];
        o
    }

    /// New layers are report-only until the flag flips: a difference from a vendor's
    /// package is a change to review, with no alert and no report.
    #[test]
    fn through_the_pilot_a_vendor_difference_is_a_change_to_review() {
        let mut o = vendor_outcome();
        hold_vendor_differences(&mut o, false);
        let slugs: Vec<&str> = o
            .upstream
            .plugins_failed
            .iter()
            .map(|p| p.slug.as_str())
            .collect();
        assert_eq!(
            slugs,
            ["akismet"],
            "wordpress.org's alerts as it always has"
        );
        let review: Vec<&str> = o
            .review
            .iter()
            .filter_map(|f| f.component.as_deref())
            .collect();
        assert_eq!(review, ["pro", "split"]);
        assert!(o.review.iter().all(|f| f.severity == "medium"));
        assert!(o.review.iter().all(|f| f.held_vendor_note().is_some()));
        let r = assemble_integrity_result(o, vec![], true, true);
        let keys = legacy_finding_keys(&r);
        assert!(
            !keys
                .iter()
                .any(|k| k.contains("pro") || k.contains("split")),
            "{keys:?}"
        );
        let prior = hyperion_types::WpIntegrityScanResult::default();
        assert_eq!(
            plan_integrity_alert(Some(&prior), &r).findings,
            1,
            "wordpress.org's plugin alerts, the held ones do not"
        );
        assert_eq!(r.verdict(), hyperion_types::ScanVerdict::Findings);

        // Live, after a baseline: the held ones still don't reach the review alert.
        let mut o = vendor_outcome();
        hold_vendor_differences(&mut o, false);
        let live = assemble_integrity_result(o, vec![], true, false);
        assert_eq!(live.review.len(), 2);
        let plan = plan_integrity_alert(Some(&native_result(false)), &live);
        assert_eq!(plan.review, 0, "held vendor differences never alert");
        assert_eq!(plan.findings, 1);
    }

    #[test]
    fn once_live_only_a_disputed_version_is_held() {
        let mut o = vendor_outcome();
        hold_vendor_differences(&mut o, true);
        let slugs: Vec<&str> = o
            .upstream
            .plugins_failed
            .iter()
            .map(|p| p.slug.as_str())
            .collect();
        assert_eq!(slugs, ["pro", "akismet"]);
        let review: Vec<&str> = o
            .review
            .iter()
            .filter_map(|f| f.component.as_deref())
            .collect();
        assert_eq!(review, ["split"]);
        // A disputed version stays out of the alerts even with the switch on.
        let live = assemble_integrity_result(o, vec![], true, false);
        let plan = plan_integrity_alert(Some(&native_result(false)), &live);
        assert_eq!(plan.review, 0);
        assert_eq!(plan.findings, 2, "pro and akismet alert as findings");
    }

    /// The filter reads the list's own label, so a capped findings list can't let a
    /// vendor's difference through to the alerts.
    #[test]
    fn the_hold_doesnt_depend_on_the_findings_list() {
        let mut o = vendor_outcome();
        o.findings.clear();
        hold_vendor_differences(&mut o, false);
        assert_eq!(o.upstream.plugins_failed.len(), 1);
    }

    /// A webshell in a disputed plugin is still a webshell.
    #[test]
    fn a_rule_hit_stays_a_finding() {
        let mut o = upstream_verified(1);
        let mut hit = vendor_finding("pro", PACKAGES_DISAGREE_LABEL);
        hit.rule_id = Some("php.eval_post".into());
        o.findings = vec![hit];
        hold_vendor_differences(&mut o, true);
        assert_eq!(o.findings.len(), 1);
        assert_eq!(o.findings[0].severity, "high");
        assert!(o.review.is_empty());
        assert_eq!(o.findings[0].held_vendor_note(), None);
    }

    /// wordpress.org out of reach is why findings are carried. A vendor manifest
    /// that's gone was forgotten, and what it said goes with it.
    #[tokio::test]
    async fn a_forgotten_vendor_difference_isnt_carried() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_cached_manifest()
            .returning(|_, _| Some(None));
        a.expect_site_scan_cached_slug()
            .returning(|_, _, _| Some(false));
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::Discover { .. } => {
                WorkerReply::Discovery(discovery_of(vec![plugin("pro"), plugin("free")]))
            }
            WorkerJob::Scan(_) => {
                let mut o = upstream_verified(0);
                o.upstream.plugins_unknown = vec!["pro".into(), "free".into()];
                WorkerReply::Scan(o)
            }
            WorkerJob::WriterHash { .. } => WorkerReply::Failed("unexpected".into()),
        });
        let s = svc(pool, a);
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        let mut prior = scanned(VENDOR_NOW - DAY, VENDOR_NOW - DAY);
        prior.result.plugins_failed = vec![
            vendor_issue("pro", VENDOR_PACKAGE_LABEL),
            vendor_issue("free", "wordpress.org"),
        ];
        prior.result.findings = vec![
            vendor_finding("pro", VENDOR_PACKAGE_LABEL),
            vendor_finding("free", "wordpress.org"),
        ];
        let run = s.site_scan_locked(&detail, ScanMode::Delta, Some(&prior), VENDOR_NOW);
        let SiteScanRun::Finished { result, .. } = run.await else {
            panic!("the scan ran");
        };
        let slugs: Vec<&str> = result
            .plugins_failed
            .iter()
            .map(|p| p.slug.as_str())
            .collect();
        assert_eq!(slugs, ["free"]);
        assert_eq!(result.findings.len(), 1);
    }

    /// The card's operator list comes from the record beside the manifest.
    #[tokio::test]
    async fn the_packages_behind_a_difference_reach_the_coverage() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_site_scan_cached_manifest()
            .returning(|_, _| Some(None));
        a.expect_site_scan_cached_slug()
            .returning(|_, _, _| Some(false));
        a.expect_site_scan_worker().returning(move |job| match job {
            WorkerJob::Discover { .. } => {
                WorkerReply::Discovery(discovery_of(vec![plugin("pro"), plugin("calm")]))
            }
            WorkerJob::Scan(_) => {
                let mut o = upstream_verified(2);
                o.upstream.plugins_failed = vec![vendor_issue("pro", VENDOR_PACKAGE_LABEL)];
                o.findings = vec![vendor_finding("pro", VENDOR_PACKAGE_LABEL)];
                WorkerReply::Scan(o)
            }
            WorkerJob::WriterHash { .. } => WorkerReply::Failed("unexpected".into()),
        });
        let s = svc(pool.clone(), a);
        let detail = site_named(&s, "a.test").await;
        let tmp = tempfile::tempdir().expect("tmp");
        let s = s.with_paths(HostingPaths {
            scan_dir: tmp.path().display().to_string(),
            ..Default::default()
        });
        for slug in ["pro", "calm"] {
            let dir = tmp.path().join("manifests/vendor/plugin").join(slug);
            std::fs::create_dir_all(&dir).expect("mkdir");
            let sha = "a".repeat(64);
            std::fs::write(
                dir.join("1.0.json"),
                format!(r#"{{"source":"VendorPackage","files":{{"a.php":"sha256:{sha}"}}}}"#),
            )
            .expect("write");
            std::fs::write(
                dir.join("1.0.provenance"),
                r#"{"final_host":"wpml.org","hostings":["h1"],"at":123}"#,
            )
            .expect("write");
        }
        let run = s.site_scan_locked(&detail, ScanMode::Delta, None, VENDOR_NOW);
        let SiteScanRun::Finished { result, .. } = run.await else {
            panic!("the scan ran");
        };
        assert_eq!(
            result.coverage.vendor_packages.len(),
            1,
            "only what differs"
        );
        let p = &result.coverage.vendor_packages[0];
        assert_eq!(
            (
                p.slug.as_str(),
                p.version.as_str(),
                p.final_host.as_str(),
                p.at
            ),
            ("pro", "1.0", "wpml.org", 123)
        );
        // And the sweep knows this slug differs.
        let raw = hyperion_state::hosting_kv::get(&pool, detail.id.as_str(), "scan_vendor_site")
            .await
            .expect("kv")
            .expect("left");
        let left: VendorSite = serde_json::from_str(&raw).expect("json");
        assert!(left.differing.contains("pro"));
    }

    #[test]
    fn vendor_refs_stay_off_until_the_node_says_so() {
        assert!(!read_vendor_refs_live(None));
        let dir = tempfile::tempdir().expect("tmp");
        let cfg = dir.path().join("agent.toml");
        assert!(!read_vendor_refs_live(Some(&cfg)), "no file");
        std::fs::write(&cfg, "[integrity]\nnew_layers_live = true\n").expect("write");
        assert!(!read_vendor_refs_live(Some(&cfg)), "its own switch");
        std::fs::write(&cfg, "[integrity]\nvendor_refs_live = \"yes\"\n").expect("write");
        assert!(!read_vendor_refs_live(Some(&cfg)), "not a boolean");
        std::fs::write(&cfg, "[integrity]\nvendor_refs_live = true\n").expect("write");
        assert!(read_vendor_refs_live(Some(&cfg)));
    }

    #[test]
    fn the_coverage_lists_are_clamped() {
        let mut o = upstream_verified(0);
        o.coverage.unknown_vendor_hosts = vec!["h".repeat(1000); 100];
        o.coverage.vendor_note = Some("n".repeat(5000));
        clamp_scan_outcome(&mut o);
        assert_eq!(o.coverage.unknown_vendor_hosts.len(), MAX_UNKNOWN_HOSTS);
        assert!(o.coverage.unknown_vendor_hosts[0].len() <= 256);
        assert!(o.coverage.vendor_note.expect("note").len() <= 512);
    }
}
