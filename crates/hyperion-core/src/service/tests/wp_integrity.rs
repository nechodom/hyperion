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
        ..Default::default()
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

/// clamscan exit 2 with detections: the hits are kept, the pass counts as
/// having run (so no retry back-off), and the report says it was partial.
#[test]
fn a_partial_clamav_pass_keeps_its_hits_without_a_backoff() {
    use super::super::wp_integrity::malware_scan_outcome;
    let now = 1_700_000_000;
    let hit = webshell_hit();
    let mut errors = Vec::new();
    let (available, hits, at, failed_at) = malware_scan_outcome(
        integrity::MalwareScan {
            available: true,
            hits: vec![hit.clone()],
            partial: true,
        },
        now,
        &mut errors,
    );
    assert!(available);
    assert_eq!(hits, vec![hit]);
    assert_eq!(at, now);
    assert_eq!(failed_at, 0, "real hits are not a failure");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("partial"), "{errors:?}");

    // A complete pass says nothing extra.
    let mut errors = Vec::new();
    let (available, _, at, failed_at) = malware_scan_outcome(
        integrity::MalwareScan {
            available: true,
            ..Default::default()
        },
        now,
        &mut errors,
    );
    assert!(available && at == now && failed_at == 0);
    assert!(errors.is_empty());
}

/// Right after ClamAV is installed freshclam is still downloading
/// signatures. The pass waits: it says so, carries the previous verdict,
/// and leaves no failed stamp, so there is no back-off once they arrive.
#[test]
fn missing_signature_db_waits_without_a_failure_stamp() {
    use super::super::wp_integrity::malware_pass_precheck;
    let now = 1_700_000_000;
    let hit = webshell_hit();
    let prior = StoredIntegrityScan {
        scanned_at: now - 86_400,
        clamav_at: now - 86_400,
        result: hyperion_types::WpIntegrityScanResult {
            clamav_available: true,
            malware: vec![hit.clone()],
            ..Default::default()
        },
        ..Default::default()
    };

    // First ever pass: nothing to carry, and no failure recorded.
    let mut errors = Vec::new();
    let done = malware_pass_precheck(true, false, now, None, &mut errors).expect("pass is over");
    assert_eq!(done, (false, Vec::new(), 0, 0));
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("still downloading"), "{errors:?}");

    // With a previous verdict: carried as it was, failed_at still 0.
    let mut errors = Vec::new();
    let (available, hits, at, failed_at) =
        malware_pass_precheck(true, false, now, Some(&prior), &mut errors).expect("pass is over");
    assert!(available);
    assert_eq!(hits, vec![hit]);
    assert_eq!(at, now - 86_400, "the hits keep their original age");
    assert_eq!(failed_at, 0, "waiting is not a failure");

    // Signatures present and nothing holding it off: the scan goes ahead.
    let mut errors = Vec::new();
    assert!(malware_pass_precheck(true, true, now, None, &mut errors).is_none());
    assert!(errors.is_empty());
    // Not installed: not scanned, no note.
    let mut errors = Vec::new();
    assert_eq!(
        malware_pass_precheck(false, false, now, None, &mut errors),
        Some((false, Vec::new(), 0, 0))
    );
    assert!(errors.is_empty());
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
    fn scanned(at: i64, full_at: i64) -> StoredIntegrityScan {
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

    /// A node with no scanner, for the blocking scan's ClamAV half.
    fn no_clamav(mut a: MockAdapterPort) -> MockAdapterPort {
        a.expect_clamav_facts().returning(|| (false, false));
        a
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
        let s = Arc::new(svc(pool.clone(), no_clamav(a)));
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
        let s = svc(pool.clone(), no_clamav(a));
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
            !r.clamav_available,
            "a verdict carried from an earlier pass isn't this scan's"
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
        let s = svc(pool.clone(), no_clamav(a));
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
        let s = svc(pool.clone(), no_clamav(a));
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
        let s = svc(pool.clone(), no_clamav(a));
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
        std::fs::write(&cfg, "[integrity]\nscan_niceness = 5\n").expect("write");
        assert!(!read_new_layers_live(Some(&cfg)), "not mentioned");
        std::fs::write(&cfg, "[integrity]\nnew_layers_live = \"yes\"\n").expect("write");
        assert!(!read_new_layers_live(Some(&cfg)), "not a boolean");
        std::fs::write(&cfg, "[integrity]\nnew_layers_live = true\n").expect("write");
        assert!(read_new_layers_live(Some(&cfg)));
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

    // ---- ClamAV, beside the node's lock ----

    fn with_clamav(
        mut a: MockAdapterPort,
        answer: impl Fn() -> Result<integrity::MalwareScan, AdapterError> + Send + 'static,
    ) -> MockAdapterPort {
        a.expect_clamav_facts().returning(|| (true, true));
        a.expect_clamav_scan().returning(move |_, _| answer());
        a
    }

    fn found(hits: Vec<hyperion_types::WpMalwareHit>) -> integrity::MalwareScan {
        integrity::MalwareScan {
            available: true,
            hits,
            partial: false,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clamav_runs_without_the_nodes_lock() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), || Ok(found(vec![])));
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = monday_at(0, 12, 0);
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        let _held = s.site_scan.node.lock().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            s.site_scan_clamav_tick_at(now),
        )
        .await
        .expect("didn't wait for the lock")
        .expect("tick");
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.clamav_at, now);
        assert!(rec.result.clamav_available);
    }

    /// The sweep goes on one site at a time as before, with new hits alerting
    /// once and a held-off site left alone.
    #[tokio::test]
    async fn a_new_clamav_hit_alerts_once() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), || Ok(found(vec![webshell_hit()])));
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = monday_at(0, 12, 0);
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        assert_eq!(s.site_scan_clamav_tick_at(now).await.expect("tick"), 1);
        assert_eq!(
            s.site_scan_clamav_tick_at(now + 600).await.expect("tick"),
            0,
            "held off for a day"
        );
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.clamav_at, now);
        assert_eq!(rec.result.malware, vec![webshell_hit()]);
        // Past the hold-off, the same hit is standing, not new.
        assert_eq!(
            s.site_scan_clamav_tick_at(now + DAY).await.expect("tick"),
            0
        );
    }

    /// No release to compare with: no ClamAV either, so no new alerts for sites
    /// that never had this scan. And none before anyone knows what a site is.
    #[tokio::test]
    async fn clamav_skips_what_has_no_upstream() {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks_many();
        a.expect_clamav_facts().returning(|| (true, true));
        a.expect_clamav_scan().never();
        let s = svc(pool.clone(), a);
        let plain = site_named(&s, "static.cz").await;
        let _never_scanned = site_named(&s, "new.cz").await;
        let mut rec = scanned(1, 1);
        rec.result.coverage.no_upstream = true;
        s.set_stored_integrity_scan(plain.id.as_str(), &rec).await;
        assert_eq!(
            s.site_scan_clamav_tick_at(monday_at(0, 12, 0))
                .await
                .expect("tick"),
            0
        );
    }

    /// The pass didn't run, so its hits still stand, its age stays, and no words
    /// from clamscan (tenant file names) reach the record.
    #[tokio::test]
    async fn a_failed_clamav_pass_keeps_prior_hits_and_stores_no_tenant_text() {
        let pool = open_memory().await.expect("open");
        let a = with_clamav(happy_mocks(), || {
            Err(AdapterError::Command {
                cmd: "clamscan".into(),
                code: 2,
                stderr_tail: "/home/x/htdocs/<b>evil</b>.php: Can't open".into(),
            })
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let now = monday_at(0, 12, 0);
        let mut prior = scanned(now - 60, now);
        prior.clamav_at = now - 2 * DAY;
        prior.result.clamav_available = true;
        prior.result.malware = vec![webshell_hit()];
        s.set_stored_integrity_scan(site.id.as_str(), &prior).await;

        assert_eq!(s.site_scan_clamav_tick_at(now).await.expect("tick"), 0);

        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.result.malware, vec![webshell_hit()]);
        assert_eq!(rec.clamav_at, now - 2 * DAY);
        assert_eq!(rec.clamav_failed_at, now);
        assert!(!rec.result.clamav_available, "not this time");
        let error = rec.result.error.expect("said");
        assert!(
            !error.contains("evil") && !error.contains("/home"),
            "{error}"
        );
        // Goes to the back of the sweep and holds off.
        assert_eq!(
            s.site_scan_clamav_tick_at(now + 600).await.expect("tick"),
            0
        );
    }

    /// A site that fails its pass doesn't keep the sweep to itself.
    #[tokio::test]
    async fn the_clamav_sweep_takes_the_longest_waiting_first() {
        let pool = open_memory().await.expect("open");
        let scanned_paths = Arc::new(StdMutex::new(Vec::new()));
        let seen = scanned_paths.clone();
        let mut a = happy_mocks_many();
        a.expect_clamav_facts().returning(|| (true, true));
        a.expect_clamav_scan().returning(move |root, _| {
            seen.lock().expect("lock").push(root.to_string());
            Ok(found(vec![]))
        });
        let s = svc(pool.clone(), a);
        let now = monday_at(0, 12, 0);
        let failed_lately = site_named(&s, "failed.cz").await;
        let waiting = site_named(&s, "waiting.cz").await;
        let mut f = scanned(now - 60, now);
        f.clamav_failed_at = now - 2 * HOUR;
        s.set_stored_integrity_scan(failed_lately.id.as_str(), &f)
            .await;
        let mut w = scanned(now - 60, now);
        w.clamav_at = now - 3 * DAY;
        s.set_stored_integrity_scan(waiting.id.as_str(), &w).await;

        s.site_scan_clamav_tick_at(now).await.expect("tick");
        assert_eq!(
            *scanned_paths.lock().expect("lock"),
            vec![waiting.root_dir.clone(), failed_lately.root_dir.clone()]
        );
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

    /// The blocking scan `hctl` uses: both halves, and it says which ran.
    #[tokio::test]
    async fn the_blocking_scan_reports_a_pass_that_ran_now() {
        let pool = open_memory().await.expect("open");
        let mut a = with_clamav(happy_mocks(), || Ok(found(vec![webshell_hit()])));
        a.expect_site_scan_worker()
            .returning(|_| WorkerReply::Failed("no".into()));
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        let r = s
            .wp_integrity_scan(HostingSelector::Id(site.id.clone()))
            .await
            .expect("scan");
        assert!(!r.native_scan_ran);
        assert!(r.clamav_available, "this one did run");
        assert_eq!(r.malware, vec![webshell_hit()]);
        assert!(r.error.is_some());
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
        let a = with_clamav(happy_mocks(), move || {
            make_record_unreadable(&during, &slot.lock().expect("lock"));
            Ok(found(vec![webshell_hit()]))
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        *id_slot.lock().expect("lock") = site.id.as_str().to_string();
        let now = monday_at(0, 12, 0);
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        assert_eq!(s.site_scan_clamav_tick_at(now).await.expect("tick"), 0);
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
        let now = monday_at(0, 12, 0);
        let a = with_clamav(happy_mocks(), move || {
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
            Ok(found(vec![]))
        });
        let s = svc(pool.clone(), a);
        let site = site_named(&s, "kos.cz").await;
        *id_slot.lock().expect("lock") = site.id.as_str().to_string();
        s.set_stored_integrity_scan(site.id.as_str(), &scanned(now - 60, now))
            .await;
        assert_eq!(s.site_scan_clamav_tick_at(now).await.expect("tick"), 0);
        let rec = s
            .stored_integrity_scan(site.id.as_str())
            .await
            .expect("record");
        assert_eq!(rec.result.core_modified, vec!["wp-login.php"], "kept");
        assert_eq!(rec.clamav_at, now);
    }
}
