//! Tests for `service::scan_actions`: who may do what to which file, and that a
//! form can't name anything the last scan didn't.

use super::*;
use hyperion_adapters::sitescan::quarantine::{QuarantineRequest, RestoreRequest};
use hyperion_adapters::sitescan::runner::{WorkerJob, WorkerReply};
use hyperion_adapters::sitescan::scan::SiteScanOutcome;
use hyperion_types::{FindingKind, QuarantineList, QuarantinedFile, SiteFileFinding};
use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const STALE: &str = "this changed since the last scan; scan again";

fn finding(rel: &str, kind: FindingKind, sha: &str) -> SiteFileFinding {
    SiteFileFinding {
        rel: rel.into(),
        kind,
        severity: "medium".into(),
        sha256: sha.into(),
        ..Default::default()
    }
}

fn rule_hit(rel: &str, sha: &str) -> SiteFileFinding {
    SiteFileFinding {
        rule_id: Some("php.eval_post".into()),
        severity: "high".into(),
        ..finding(rel, FindingKind::RuleHit, sha)
    }
}

const UPSTREAM_KINDS: [FindingKind; 6] = [
    FindingKind::CoreModified,
    FindingKind::CoreUnexpected,
    FindingKind::CoreMissing,
    FindingKind::UpstreamModified,
    FindingKind::UpstreamAdded,
    FindingKind::UpstreamMissing,
];

fn result(
    findings: Vec<SiteFileFinding>,
    review: Vec<SiteFileFinding>,
) -> hyperion_types::WpIntegrityScanResult {
    hyperion_types::WpIntegrityScanResult {
        native_scan_ran: true,
        wp_cli_ok: true,
        scanned_at: 1_000,
        findings,
        review,
        ..Default::default()
    }
}

async fn fixture(
    a: MockAdapterPort,
    r: hyperion_types::WpIntegrityScanResult,
) -> (
    HostingService<MockAdapterPort>,
    SqlitePool,
    HostingSelector,
    String,
) {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), a);
    let site = s.create(req("acts.cz")).await.expect("create");
    let id = site.id.as_str().to_string();
    s.set_stored_integrity_scan(
        &id,
        &StoredIntegrityScan {
            scanned_at: 1_000,
            result: r,
            ..Default::default()
        },
    )
    .await;
    (s, pool, HostingSelector::Id(site.id), id)
}

fn no_file_touched() -> MockAdapterPort {
    let mut a = happy_mocks();
    a.expect_site_scan_quarantine().never();
    a.expect_site_scan_restore().never();
    a
}

fn moved(req: QuarantineRequest) -> QuarantinedFile {
    QuarantinedFile {
        id: "0".repeat(32),
        rel: req.rel,
        sha256: req.sha256,
        kind: req.kind,
        rule_id: req.rule_id,
        time: req.now,
        malware: req.malware,
        ..Default::default()
    }
}

async fn trust_kv(pool: &SqlitePool, id: &str) -> BTreeMap<String, String> {
    hyperion_state::hosting_kv::get(pool, id, "scan_trust")
        .await
        .expect("kv")
        .map(|j| serde_json::from_str(&j).expect("json"))
        .unwrap_or_default()
}

async fn rescan_asked(pool: &SqlitePool, id: &str) -> bool {
    hyperion_state::hosting_kv::get(pool, id, "scan_requested")
        .await
        .expect("kv")
        .is_some()
}

async fn refusal(r: Result<hyperion_types::WpIntegrityScanResult, RpcError>) -> String {
    match r {
        Err(RpcError::Conflict { message }) => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn audit_rows(pool: &SqlitePool, action: &str) -> Vec<(String, String, String)> {
    sqlx::query_as::<_, (String, String, String)>(
        "SELECT actor_label, payload_json, result FROM audit_log WHERE action = ? ORDER BY id",
    )
    .bind(action)
    .fetch_all(pool)
    .await
    .expect("audit")
}

// ---- who ----

#[test]
fn customer_cannot_trust_but_can_quarantine() {
    let customer = hyperion_state::web_users::WebRole::Customer.capabilities();
    assert!(customer.contains(hyperion_state::capabilities::Capability::WpManage));
    assert!(!customer.contains(hyperion_state::capabilities::Capability::WpScanTrust));
}

#[test]
fn viewer_can_do_neither() {
    let viewer = hyperion_state::web_users::WebRole::Viewer.capabilities();
    assert!(!viewer.contains(hyperion_state::capabilities::Capability::WpManage));
    assert!(!viewer.contains(hyperion_state::capabilities::Capability::WpScanTrust));
}

// ---- quarantine ----

#[tokio::test]
async fn quarantine_moves_the_item_named_and_forgets_it() {
    let seen = Arc::new(StdMutex::new(Vec::new()));
    let log = seen.clone();
    let mut a = happy_mocks();
    a.expect_site_scan_quarantine()
        .times(1)
        .returning(move |r| {
            log.lock().expect("lock").push(r.clone());
            Ok(moved(r))
        });
    let r = result(
        vec![rule_hit("wp-content/uploads/a.php", SHA)],
        vec![finding("x.php", FindingKind::BaselineChange, SHA2)],
    );
    let (s, pool, sel, id) = fixture(a, r).await;

    let after = s
        .scan_file_quarantine(
            sel,
            "wp-content/uploads/a.php".into(),
            SHA.into(),
            "kevin".into(),
        )
        .await
        .expect("quarantine");

    let reqs = seen.lock().expect("lock").clone();
    assert_eq!(reqs[0].hosting_id, id);
    assert_eq!(reqs[0].rel, "wp-content/uploads/a.php");
    assert_eq!(reqs[0].sha256, SHA);
    assert_eq!(reqs[0].kind, FindingKind::RuleHit);
    assert_eq!(reqs[0].rule_id.as_deref(), Some("php.eval_post"));
    // Dropped right away, the rest left alone, and a scan on its way.
    assert!(after.findings.is_empty());
    assert_eq!(after.review.len(), 1);
    assert!(after.scan_queued);
    assert!(rescan_asked(&pool, &id).await);
    let stored = s.stored_integrity_scan(&id).await.expect("stored");
    assert!(stored.result.findings.is_empty());
}

/// A file on a list of its own goes from that list too, or the card goes on
/// offering it.
#[tokio::test]
async fn quarantine_takes_the_file_off_the_upstream_lists() {
    let mut a = happy_mocks();
    a.expect_site_scan_quarantine()
        .times(3)
        .returning(|r| Ok(moved(r)));
    let upstream = |rel: &str, slug: &str, kind| SiteFileFinding {
        component: Some(slug.into()),
        source_label: Some("wordpress.org".into()),
        ..finding(rel, kind, SHA)
    };
    let issue = |path: &str| hyperion_types::WpIntegrityFileIssue {
        path: path.into(),
        message: "x".into(),
    };
    let mut r = result(
        vec![
            finding("wp-admin/shell.php", FindingKind::CoreUnexpected, SHA),
            upstream(
                "wp-content/plugins/foo/a/b.php",
                "foo",
                FindingKind::UpstreamModified,
            ),
            upstream(
                "wp-content/plugins/hello.php",
                "hello",
                FindingKind::UpstreamModified,
            ),
        ],
        vec![],
    );
    r.core_unexpected = vec!["wp-admin/shell.php".into(), "wp-admin/other.php".into()];
    r.plugins_failed = vec![
        hyperion_types::WpIntegrityPluginResult {
            slug: "foo".into(),
            issues: vec![issue("a/b.php"), issue("b.php")],
            ..Default::default()
        },
        hyperion_types::WpIntegrityPluginResult {
            slug: "hello".into(),
            issues: vec![issue("hello.php")],
            ..Default::default()
        },
    ];
    r.malware = vec![hyperion_types::WpMalwareHit {
        path: "ABS/wp-admin/shell.php".into(),
        signature: "x".into(),
    }];
    let (s, _pool, sel, id) = fixture(a, r).await;
    let root = s.get(sel.clone()).await.expect("get").root_dir;
    let mut rec = s.stored_integrity_scan(&id).await.expect("stored");
    rec.result.malware[0].path = format!("{root}/wp-admin/shell.php");
    s.set_stored_integrity_scan(&id, &rec).await;

    for rel in [
        "wp-admin/shell.php",
        "wp-content/plugins/foo/a/b.php",
        "wp-content/plugins/hello.php",
    ] {
        s.scan_file_quarantine(sel.clone(), rel.into(), SHA.into(), String::new())
            .await
            .expect("quarantine");
    }
    let after = s.stored_integrity_scan(&id).await.expect("stored").result;
    assert_eq!(after.core_unexpected, ["wp-admin/other.php"]);
    assert_eq!(after.plugins_failed.len(), 1);
    assert_eq!(after.plugins_failed[0].issues[0].path, "b.php");
    assert!(after.malware.is_empty());
}

#[tokio::test]
async fn form_cant_reach_arbitrary_path() {
    let r = result(vec![rule_hit("a.php", SHA)], vec![]);
    let (s, _pool, sel, _id) = fixture(no_file_touched(), r).await;
    for rel in [
        "../../etc/passwd",
        "/etc/passwd",
        "wp-config.php",
        "b.php",
        "",
    ] {
        assert_eq!(
            refusal(
                s.scan_file_quarantine(sel.clone(), rel.into(), SHA.into(), String::new())
                    .await
            )
            .await,
            STALE,
            "{rel}"
        );
    }
    assert_eq!(
        refusal(
            s.scan_file_trust(sel.clone(), "/etc/shadow".into(), SHA.into(), String::new())
                .await
        )
        .await,
        STALE
    );
    for id in ["../other/00", "", "/etc/passwd"] {
        assert!(
            s.scan_file_restore(sel.clone(), id.into(), String::new())
                .await
                .is_err(),
            "{id}"
        );
    }
}

#[tokio::test]
async fn stale_hash_is_refused() {
    let r = result(vec![rule_hit("a.php", SHA)], vec![]);
    let (s, pool, sel, id) = fixture(no_file_touched(), r).await;
    assert_eq!(
        refusal(
            s.scan_file_quarantine(sel.clone(), "a.php".into(), SHA2.into(), String::new())
                .await
        )
        .await,
        STALE
    );
    assert_eq!(
        refusal(
            s.scan_file_trust(sel, "a.php".into(), SHA2.into(), String::new())
                .await
        )
        .await,
        STALE
    );
    assert!(trust_kv(&pool, &id).await.is_empty());
}

/// Never scanned means there's nothing a form could name.
#[tokio::test]
async fn no_stored_scan_refuses_everything() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), no_file_touched());
    let site = s.create(req("never.cz")).await.expect("create");
    let sel = HostingSelector::Id(site.id);
    assert_eq!(
        refusal(
            s.scan_file_quarantine(sel, "a.php".into(), SHA.into(), String::new())
                .await
        )
        .await,
        STALE
    );
}

#[tokio::test]
async fn items_with_no_one_file_behind_them_get_no_action() {
    let cut = format!("{}…", "a/".repeat(100));
    let folder = SiteFileFinding {
        component: Some("foo".into()),
        ..finding("wp-content/plugins/foo", FindingKind::UpstreamModified, SHA)
    };
    let items = vec![
        finding(".", FindingKind::CoreModified, SHA),
        folder,
        finding(&cut, FindingKind::BaselineChange, SHA),
        finding("unread.php", FindingKind::BaselineChange, ""),
    ];
    let names: Vec<(String, String)> = items
        .iter()
        .map(|f| (f.rel.clone(), f.sha256.clone()))
        .collect();
    let (s, _pool, sel, _id) = fixture(no_file_touched(), result(items, vec![])).await;
    for (rel, sha) in names {
        assert!(
            s.scan_file_quarantine(sel.clone(), rel.clone(), sha.clone(), String::new())
                .await
                .is_err(),
            "{rel}"
        );
        assert!(
            s.scan_file_trust(sel.clone(), rel.clone(), sha, String::new())
                .await
                .is_err(),
            "{rel}"
        );
    }
}

#[tokio::test]
async fn quarantine_refuses_what_it_must_not_move_and_says_why() {
    let link = SiteFileFinding {
        symlink: true,
        ..finding("l.php", FindingKind::BaselineChange, SHA)
    };
    let items = vec![
        link,
        finding("wp-config.php", FindingKind::RuleHit, SHA),
        finding("wp-load.php", FindingKind::CoreMissing, SHA),
        finding(
            "wp-content/plugins/a/b.php",
            FindingKind::UpstreamMissing,
            SHA,
        ),
    ];
    let (s, _pool, sel, _id) = fixture(no_file_touched(), result(items, vec![])).await;
    let say = |rel: &'static str| {
        let (s, sel) = (&s, sel.clone());
        async move {
            refusal(
                s.scan_file_quarantine(sel, rel.into(), SHA.into(), String::new())
                    .await,
            )
            .await
        }
    };
    assert!(say("l.php").await.contains("SFTP"));
    let config = say("wp-config.php").await;
    assert!(config.contains("database"), "{config}");
    assert!(say("wp-load.php").await.contains("missing"));
    assert!(say("wp-content/plugins/a/b.php").await.contains("missing"));
}

/// A file a stale list still names is the adapter's to refuse; what it said reaches
/// the card, nothing is dropped and nothing is asked for.
#[tokio::test]
async fn a_refused_move_leaves_the_record_alone() {
    let mut a = happy_mocks();
    a.expect_site_scan_quarantine().times(1).returning(|_| {
        Err(hyperion_adapters::AdapterError::Conflict(
            "this is a symlink".into(),
        ))
    });
    let r = result(vec![rule_hit("a.php", SHA)], vec![]);
    let (s, pool, sel, id) = fixture(a, r).await;
    assert_eq!(
        refusal(
            s.scan_file_quarantine(sel, "a.php".into(), SHA.into(), "kevin".into())
                .await
        )
        .await,
        "this is a symlink"
    );
    let stored = s.stored_integrity_scan(&id).await.expect("stored");
    assert_eq!(stored.result.findings.len(), 1);
    assert!(!rescan_asked(&pool, &id).await);
    let rows = audit_rows(&pool, "wp.integrity.quarantine").await;
    assert_eq!(rows[0].2, "refused");
}

#[tokio::test]
async fn restore_drops_what_said_it_was_missing_and_rescans() {
    let seen = Arc::new(StdMutex::new(Vec::<RestoreRequest>::new()));
    let log = seen.clone();
    let mut a = happy_mocks();
    let id_hex = "1".repeat(32);
    a.expect_site_scan_restore().times(1).returning(move |r| {
        log.lock().expect("lock").push(r);
        Ok(QuarantinedFile {
            rel: "wp-login.php".into(),
            sha256: SHA.into(),
            ..Default::default()
        })
    });
    let mut r = result(
        vec![finding("wp-login.php", FindingKind::CoreMissing, "")],
        vec![],
    );
    r.core_missing = vec!["wp-login.php".into()];
    let (s, pool, sel, id) = fixture(a, r).await;
    let after = s
        .scan_file_restore(sel, id_hex.clone(), "kevin".into())
        .await
        .expect("restore");
    assert_eq!(seen.lock().expect("lock")[0].id, id_hex);
    assert_eq!(seen.lock().expect("lock")[0].hosting_id, id);
    assert!(after.core_missing.is_empty() && after.findings.is_empty());
    assert!(rescan_asked(&pool, &id).await);
}

#[tokio::test]
async fn the_list_is_metadata_up_to_fifty() {
    let mut a = happy_mocks();
    a.expect_site_scan_quarantine_list()
        .times(1)
        .returning(|_, _, cap| {
            assert_eq!(cap, 50);
            Ok(QuarantineList {
                items: vec![QuarantinedFile {
                    rel: "a.php".into(),
                    ..Default::default()
                }],
                total: 70,
            })
        });
    let (s, _pool, sel, _id) = fixture(a, result(vec![], vec![])).await;
    let l = s.scan_quarantine_list(sel).await.expect("list");
    assert_eq!(l.total, 70);
    assert_eq!(l.items[0].rel, "a.php");
}

/// Purge runs from the daily tick under its stamp, and takes only what is old.
#[tokio::test]
async fn the_daily_tick_purges_old_quarantine() {
    let dir = tempfile::tempdir().expect("tmp");
    let base = dir.path().join("quarantine");
    let held = base.join("H1");
    std::fs::create_dir_all(&held).expect("mkdir");
    let id = "2".repeat(32);
    std::fs::write(held.join(&id), b"x").expect("w");
    let rec = QuarantinedFile {
        id: id.clone(),
        rel: "a.php".into(),
        time: 1_000,
        ..Default::default()
    };
    std::fs::write(
        held.join(format!("{id}.json")),
        serde_json::to_vec(&rec).expect("json"),
    )
    .expect("w");

    let pool = open_memory().await.expect("open");
    let mut a = MockAdapterPort::new();
    a.expect_site_scan_evict_manifests().returning(|_| ());
    let s = svc(pool, a).with_paths(HostingPaths {
        quarantine_dir: base.display().to_string(),
        ..Default::default()
    });
    s.site_scan_tick_at(&chrono::Utc, 1_000 + 86_400)
        .await
        .expect("tick");
    assert!(held.join(&id).exists());
    s.site_scan_tick_at(&chrono::Utc, 1_000 + 91 * 86_400)
        .await
        .expect("tick");
    assert!(!held.join(&id).exists());
}

// ---- trust ----

#[tokio::test]
async fn trust_refuses_upstream_failure() {
    for kind in UPSTREAM_KINDS {
        let r = result(vec![finding("wp-admin/x.php", kind, SHA)], vec![]);
        let (s, pool, sel, id) = fixture(no_file_touched(), r).await;
        let m = refusal(
            s.scan_file_trust(sel, "wp-admin/x.php".into(), SHA.into(), String::new())
                .await,
        )
        .await;
        assert!(m.contains("repaired"), "{kind:?}: {m}");
        assert!(trust_kv(&pool, &id).await.is_empty(), "{kind:?}");
    }
}

#[tokio::test]
async fn trust_records_the_hash_and_clears_the_item_at_once() {
    let r = result(
        vec![rule_hit("a.php", SHA)],
        vec![finding("b.php", FindingKind::BaselineChange, SHA2)],
    );
    let (s, pool, sel, id) = fixture(no_file_touched(), r).await;
    let after = s
        .scan_file_trust(sel.clone(), "a.php".into(), SHA.into(), "kevin".into())
        .await
        .expect("trust");
    assert_eq!(trust_kv(&pool, &id).await["a.php"], SHA);
    assert!(after.findings.is_empty());
    assert_eq!(after.review.len(), 1);
    assert!(rescan_asked(&pool, &id).await);

    s.scan_file_trust(sel, "b.php".into(), SHA2.into(), "kevin".into())
        .await
        .expect("trust");
    let kv = trust_kv(&pool, &id).await;
    assert_eq!((kv["a.php"].as_str(), kv["b.php"].as_str()), (SHA, SHA2));
}

/// A symlink's reported hash is what's stored: nothing is hashed through the link
/// and the adapter is never asked.
#[tokio::test]
async fn trusting_a_symlink_stores_what_the_scan_reported() {
    let link = SiteFileFinding {
        symlink: true,
        ..finding("l.php", FindingKind::BaselineChange, SHA)
    };
    let (s, pool, sel, id) = fixture(no_file_touched(), result(vec![], vec![link])).await;
    s.scan_file_trust(sel, "l.php".into(), SHA.into(), String::new())
        .await
        .expect("trust");
    assert_eq!(trust_kv(&pool, &id).await["l.php"], SHA);
}

fn mixed_review() -> hyperion_types::WpIntegrityScanResult {
    let cut = format!("{}…", "a/".repeat(100));
    let upstream_review = SiteFileFinding {
        symlink: true,
        ..finding("wp-admin/l.php", FindingKind::CoreModified, SHA)
    };
    result(
        vec![rule_hit("finding.php", SHA)],
        vec![
            finding("one.php", FindingKind::BaselineChange, SHA),
            finding("two.php", FindingKind::BaselineChange, SHA2),
            SiteFileFinding {
                symlink: true,
                ..finding("link.php", FindingKind::BaselineChange, SHA)
            },
            finding("big.bin", FindingKind::TooLargeToInspect, SHA),
            rule_hit("medium.php", SHA),
            upstream_review,
            finding("unread.php", FindingKind::BaselineChange, ""),
            finding(&cut, FindingKind::BaselineChange, SHA),
        ],
    )
}

#[tokio::test]
async fn trust_all_excludes_rule_hits() {
    let (s, pool, sel, id) = fixture(no_file_touched(), mixed_review()).await;
    let after = s
        .scan_trust_all_review(sel, "kevin".into())
        .await
        .expect("trust all");
    let kv = trust_kv(&pool, &id).await;
    assert!(!kv.contains_key("medium.php"));
    assert!(!kv.contains_key("finding.php"), "not in the review list");
    let left: Vec<&str> = after.review.iter().map(|f| f.rel.as_str()).collect();
    assert!(left.contains(&"medium.php"));
    assert_eq!(after.findings.len(), 1);
}

#[tokio::test]
async fn trust_all_skips_rule_hits_and_upstream() {
    let (s, pool, sel, id) = fixture(no_file_touched(), mixed_review()).await;
    s.scan_trust_all_review(sel, String::new())
        .await
        .expect("trust all");
    let kv = trust_kv(&pool, &id).await;
    let mut names: Vec<&str> = kv.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["link.php", "one.php", "two.php"]);
    assert!(rescan_asked(&pool, &id).await);
}

/// Trust speaks for the scan's new layers only. A ClamAV hit at that path is ClamAV's
/// to clear, and a comparison at that path is the manifest's.
#[tokio::test]
async fn trust_leaves_a_clamav_hit_alone() {
    let review = vec![finding("a.php", FindingKind::BaselineChange, SHA)];
    let mut r = result(vec![], review);
    r.malware = vec![hyperion_types::WpMalwareHit {
        path: "ROOT/a.php".into(),
        signature: "Php.Trojan.Webshell-1".into(),
    }];
    let (s, _pool, sel, id) = fixture(no_file_touched(), r).await;
    let root = s.get(sel.clone()).await.expect("get").root_dir;
    let mut rec = s.stored_integrity_scan(&id).await.expect("stored");
    rec.result.malware[0].path = format!("{root}/a.php");
    s.set_stored_integrity_scan(&id, &rec).await;

    let after = s
        .scan_file_trust(sel, "a.php".into(), SHA.into(), String::new())
        .await
        .expect("trust");
    assert!(after.review.is_empty());
    assert_eq!(after.malware.len(), 1, "a Trust cleared ClamAV's finding");
}

#[tokio::test]
async fn trust_all_leaves_a_carried_comparison_alone() {
    let rel = "wp-content/plugins/foo/x.php";
    let comparison = SiteFileFinding {
        component: Some("foo".into()),
        source_label: Some("wordpress.org".into()),
        ..finding(rel, FindingKind::UpstreamModified, SHA)
    };
    let mut r = result(
        vec![comparison],
        vec![finding(rel, FindingKind::BaselineChange, SHA)],
    );
    r.plugins_failed = vec![failed("foo", "1.0")];
    r.core_modified = vec!["wp-load.php".into()];
    let (s, _pool, sel, _id) = fixture(no_file_touched(), r).await;
    let after = s
        .scan_trust_all_review(sel, String::new())
        .await
        .expect("trust all");
    assert!(after.review.is_empty());
    assert_eq!(after.findings.len(), 1);
    assert_eq!(after.plugins_failed.len(), 1);
    assert_eq!(after.plugins_failed[0].issues.len(), 1);
    assert_eq!(after.core_modified, ["wp-load.php"]);
}

/// Padding a PHP file past what's read must not get it accepted in bulk.
#[tokio::test]
async fn trust_all_leaves_files_never_read() {
    let php = SiteFileFinding {
        snippet: "70000000 bytes: too large to read".into(),
        ..finding("pad.php", FindingKind::TooLargeToInspect, SHA)
    };
    let r = result(
        vec![],
        vec![php, finding("ok.php", FindingKind::BaselineChange, SHA2)],
    );
    let (s, pool, sel, id) = fixture(no_file_touched(), r).await;
    let after = s
        .scan_trust_all_review(sel.clone(), String::new())
        .await
        .expect("trust all");
    assert_eq!(after.review.len(), 1);
    assert_eq!(after.review[0].rel, "pad.php");
    assert!(!trust_kv(&pool, &id).await.contains_key("pad.php"));
    // One at a time it can still be accepted, so it isn't stuck on the card.
    s.scan_file_trust(sel, "pad.php".into(), SHA.into(), String::new())
        .await
        .expect("trust");
    assert!(trust_kv(&pool, &id).await.contains_key("pad.php"));
}

#[tokio::test]
async fn trust_all_with_nothing_to_take_says_so() {
    let r = result(vec![], vec![rule_hit("medium.php", SHA)]);
    let (s, pool, sel, id) = fixture(no_file_touched(), r).await;
    let m = refusal(s.scan_trust_all_review(sel, String::new()).await).await;
    assert!(m.contains("nothing"), "{m}");
    assert!(!rescan_asked(&pool, &id).await);
}

#[tokio::test]
async fn the_trust_list_stops_at_its_cap() {
    let r = result(
        vec![],
        vec![
            finding("new.php", FindingKind::BaselineChange, SHA),
            finding("kept.php", FindingKind::BaselineChange, SHA2),
        ],
    );
    let (s, pool, sel, id) = fixture(no_file_touched(), r).await;
    let mut full: BTreeMap<String, String> = (0..5000)
        .map(|i| (format!("f{i}.php"), SHA.to_string()))
        .collect();
    full.insert("kept.php".into(), SHA.to_string());
    full.remove("f0.php");
    hyperion_state::hosting_kv::set(
        &pool,
        &id,
        "scan_trust",
        &serde_json::to_string(&full).expect("json"),
        1,
    )
    .await
    .expect("set");

    let m = refusal(
        s.scan_file_trust(sel.clone(), "new.php".into(), SHA.into(), String::new())
            .await,
    )
    .await;
    assert!(m.contains("5000"), "{m}");
    assert!(!trust_kv(&pool, &id).await.contains_key("new.php"));
    // A path already on it takes no more room.
    s.scan_file_trust(sel, "kept.php".into(), SHA2.into(), String::new())
        .await
        .expect("replaces");
    assert_eq!(trust_kv(&pool, &id).await["kept.php"], SHA2);
}

/// The worker gets the list from the agent, and an entry that makes no sense
/// isn't passed on as a hash of zeroes or anything else.
#[tokio::test]
async fn the_worker_is_handed_the_trust_list() {
    let inputs = Arc::new(StdMutex::new(Vec::new()));
    let log = inputs.clone();
    let mut a = happy_mocks();
    a.expect_site_scan_worker().returning(move |job| match job {
        WorkerJob::Discover { .. } => WorkerReply::Discovery(Default::default()),
        WorkerJob::Scan(i) => {
            log.lock().expect("lock").push(i);
            WorkerReply::Scan(SiteScanOutcome::default())
        }
    });
    a.expect_site_scan_evict_manifests().returning(|_| ());
    let (s, pool, sel, id) = fixture(a, result(vec![], vec![])).await;
    let kv = serde_json::json!({ "a.php": SHA, "bad.php": "not hex" }).to_string();
    hyperion_state::hosting_kv::set(&pool, &id, "scan_trust", &kv, 1)
        .await
        .expect("set");
    s.wp_integrity_scan_request(sel).await.expect("request");
    s.site_scan_tick_at(&chrono::Utc, 2_000_000)
        .await
        .expect("tick");
    let got = inputs.lock().expect("lock");
    assert_eq!(got[0].trusted.len(), 1);
    assert_eq!(hex::encode(got[0].trusted["a.php"]), SHA);
}

#[tokio::test]
async fn trust_cleared_when_content_changes() {
    let mut a = happy_mocks();
    a.expect_site_scan_worker().returning(move |job| match job {
        WorkerJob::Discover { .. } => WorkerReply::Discovery(Default::default()),
        WorkerJob::Scan(_) => WorkerReply::Scan(SiteScanOutcome {
            review: vec![finding("changed.php", FindingKind::BaselineChange, SHA2)],
            trust_gone: vec!["deleted.php".into()],
            ..Default::default()
        }),
    });
    a.expect_site_scan_evict_manifests().returning(|_| ());
    let (s, pool, sel, id) = fixture(a, result(vec![], vec![])).await;
    let kv = serde_json::json!({
        "changed.php": SHA,
        "deleted.php": SHA,
        "kept.php": SHA,
    })
    .to_string();
    hyperion_state::hosting_kv::set(&pool, &id, "scan_trust", &kv, 1)
        .await
        .expect("set");
    s.wp_integrity_scan_request(sel).await.expect("request");
    s.site_scan_tick_at(&chrono::Utc, 2_000_000)
        .await
        .expect("tick");
    let kv = trust_kv(&pool, &id).await;
    assert_eq!(kv.keys().collect::<Vec<_>>(), ["kept.php"]);
}

#[tokio::test]
async fn trust_travels_with_copy() {
    let (s, pool, sel, id) = fixture(carry_mocks(), result(vec![], vec![])).await;
    assert_eq!(carried_kv_scope("scan_trust"), Some(CarryScope::Always));
    let kv = serde_json::json!({ "a.php": SHA }).to_string();
    hyperion_state::hosting_kv::set(&pool, &id, "scan_trust", &kv, 1)
        .await
        .expect("set");
    let source = s.get(sel).await.expect("get");
    let settings = s.collect_carried_settings(&source).await;

    s.create(req("copy.cz")).await.expect("create target");
    let tsel = HostingSelector::Domain(Domain::parse("copy.cz").expect("parse"));
    let target = s.get(tsel).await.expect("get");
    s.apply_carried_settings(&target, Some(&settings), true)
        .await;
    assert_eq!(trust_kv(&pool, target.id.as_str()).await["a.php"], SHA);
}

/// A bundle is a file someone could have edited, so what it says goes through the
/// same shape a scan's own items have.
#[tokio::test]
async fn a_carried_trust_list_is_checked_on_import() {
    let (s, pool, _sel, _id) = fixture(carry_mocks(), result(vec![], vec![])).await;
    s.create(req("copy.cz")).await.expect("create target");
    let tsel = HostingSelector::Domain(Domain::parse("copy.cz").expect("parse"));
    let target = s.get(tsel).await.expect("get");
    let tid = target.id.as_str();
    let long = "a/".repeat(600);
    let upper = SHA.to_uppercase();
    let settings = hyperion_types::migration::HostingCarriedSettings {
        kv: BTreeMap::from([(
            "scan_trust".to_string(),
            serde_json::json!({
                "ok.php": SHA,
                "upper.php": upper,
                "../../etc/passwd": SHA,
                "/etc/passwd": SHA,
                "a//b.php": SHA,
                "./a.php": SHA,
                "nul\u{0}.php": SHA,
                long: SHA,
                "bad-hash.php": "zz",
                "short-hash.php": "abcd",
                "number.php": 7,
            })
            .to_string(),
        )]),
        ..Default::default()
    };
    s.apply_carried_settings(&target, Some(&settings), true)
        .await;
    let kv = trust_kv(&pool, tid).await;
    assert_eq!(kv.len(), 2, "{kv:?}");
    assert_eq!(kv["ok.php"], SHA);
    // As a scan writes it, so it compares equal to one.
    assert_eq!(kv["upper.php"], SHA);

    let rows = audit_rows(&pool, "wp.integrity.trust_imported").await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].1.contains("\"kept\":2"), "{}", rows[0].1);
    assert!(rows[0].1.contains("\"dropped\":9"), "{}", rows[0].1);
}

#[tokio::test]
async fn a_carried_trust_list_stops_at_the_cap_and_junk_writes_nothing() {
    let (s, pool, _sel, _id) = fixture(carry_mocks(), result(vec![], vec![])).await;
    for (domain, value, kept) in [
        (
            "many.cz",
            serde_json::to_string(
                &(0..5100)
                    .map(|i| (format!("f{i}.php"), SHA.to_string()))
                    .collect::<BTreeMap<_, _>>(),
            )
            .expect("json"),
            5000,
        ),
        ("junk.cz", "not json".to_string(), 0),
    ] {
        s.create(req(domain)).await.expect("create target");
        let tsel = HostingSelector::Domain(Domain::parse(domain).expect("parse"));
        let target = s.get(tsel).await.expect("get");
        let settings = hyperion_types::migration::HostingCarriedSettings {
            kv: BTreeMap::from([("scan_trust".to_string(), value)]),
            ..Default::default()
        };
        s.apply_carried_settings(&target, Some(&settings), true)
            .await;
        assert_eq!(
            trust_kv(&pool, target.id.as_str()).await.len(),
            kept,
            "{domain}"
        );
    }
    assert_eq!(
        audit_rows(&pool, "wp.integrity.trust_imported").await.len(),
        2
    );
}

// ---- an edited record isn't a scan's ----

fn verified_clean() -> hyperion_types::WpIntegrityScanResult {
    let mut r = result(
        vec![],
        vec![finding("a.php", FindingKind::BaselineChange, SHA)],
    );
    r.clamav_available = true;
    r.coverage.upstream_ran = true;
    r
}

/// What the last scan looked like, edited by hand, isn't a scan's result. Nothing
/// may read clean, on the card or in a paid report, until a scan says so.
#[tokio::test]
async fn an_edited_record_is_not_clean_until_a_scan_stores_one() {
    let mut a = happy_mocks();
    a.expect_site_scan_worker().returning(move |job| match job {
        WorkerJob::Discover { .. } => WorkerReply::Discovery(Default::default()),
        WorkerJob::Scan(_) => WorkerReply::Scan(SiteScanOutcome {
            upstream: hyperion_adapters::sitescan::scan::UpstreamResult {
                ran: true,
                ..Default::default()
            },
            coverage: hyperion_types::ScanCoverage {
                upstream_ran: true,
                ..Default::default()
            },
            ..Default::default()
        }),
    });
    a.expect_site_scan_evict_manifests().returning(|_| ());
    let (s, pool, sel, id) = fixture(a, verified_clean()).await;
    let after = s
        .scan_file_trust(sel.clone(), "a.php".into(), SHA.into(), String::new())
        .await
        .expect("trust");
    assert!(after.awaiting_rescan);
    assert!(after.findings.is_empty() && after.review.is_empty());
    assert!(!after.is_clean(), "an edited record read clean");
    assert_eq!(after.verdict(), hyperion_types::ScanVerdict::Running);

    // The care report reads the record itself, and says it was only partly checked.
    let care = hyperion_state::reports::integrity(&pool, &id, 0, i64::MAX)
        .await
        .expect("report")
        .expect("in period");
    assert!(!care.checksums_ran);
    assert!(!care.is_clean());

    s.site_scan_tick_at(&chrono::Utc, 2_000_000)
        .await
        .expect("tick");
    let stored = s.stored_integrity_scan(&id).await.expect("stored");
    assert!(!stored.result.awaiting_rescan, "a stored scan answers it");
    let care = hyperion_state::reports::integrity(&pool, &id, 0, i64::MAX)
        .await
        .expect("report")
        .expect("in period");
    assert!(care.checksums_ran);
}

/// A run that gave no answer hasn't answered anything.
#[tokio::test]
async fn a_failed_run_leaves_the_record_awaiting() {
    let mut a = happy_mocks();
    a.expect_site_scan_worker()
        .returning(|_| WorkerReply::Failed("no".into()));
    a.expect_site_scan_evict_manifests().returning(|_| ());
    let (s, _pool, sel, id) = fixture(a, verified_clean()).await;
    s.scan_file_trust(sel, "a.php".into(), SHA.into(), String::new())
        .await
        .expect("trust");
    s.site_scan_tick_at(&chrono::Utc, 2_000_000)
        .await
        .expect("tick");
    let stored = s.stored_integrity_scan(&id).await.expect("stored");
    assert!(stored.result.awaiting_rescan);
    assert!(!stored.result.is_clean());
}

async fn assert_marked_then_clear(s: &HostingService<MockAdapterPort>, id: &str) {
    let mut rec = s.stored_integrity_scan(id).await.expect("stored");
    assert!(rec.result.awaiting_rescan);
    rec.result.awaiting_rescan = false;
    s.set_stored_integrity_scan(id, &rec).await;
}

#[tokio::test]
async fn every_file_action_marks_the_record() {
    let mut a = happy_mocks();
    a.expect_site_scan_quarantine().returning(|r| Ok(moved(r)));
    a.expect_site_scan_restore().returning(|_| {
        Ok(QuarantinedFile {
            rel: "gone.php".into(),
            ..Default::default()
        })
    });
    let items = vec![
        finding("q.php", FindingKind::BaselineChange, SHA),
        finding("t.php", FindingKind::BaselineChange, SHA),
        finding("all.php", FindingKind::BaselineChange, SHA),
    ];
    let (s, _pool, sel, id) = fixture(a, result(vec![], items)).await;
    s.scan_file_quarantine(sel.clone(), "q.php".into(), SHA.into(), String::new())
        .await
        .expect("quarantine");
    assert_marked_then_clear(&s, &id).await;
    s.scan_file_trust(sel.clone(), "t.php".into(), SHA.into(), String::new())
        .await
        .expect("trust");
    assert_marked_then_clear(&s, &id).await;
    s.scan_trust_all_review(sel.clone(), String::new())
        .await
        .expect("trust all");
    assert_marked_then_clear(&s, &id).await;
    s.scan_file_restore(sel, "1".repeat(32), String::new())
        .await
        .expect("restore");
    assert_marked_then_clear(&s, &id).await;
}

// ---- a ClamAV hit can't be laundered ----

/// Quarantine takes a ClamAV hit with it and restore brings it back. Otherwise a
/// customer clears a paid report with two clicks and the malware back on disk.
#[tokio::test]
async fn quarantine_then_restore_keeps_the_clamav_hit() {
    let held = Arc::new(StdMutex::new(None::<QuarantinedFile>));
    let (put, take) = (held.clone(), held.clone());
    let mut a = happy_mocks();
    a.expect_site_scan_quarantine()
        .times(1)
        .returning(move |r| {
            let rec = moved(r);
            *put.lock().expect("lock") = Some(rec.clone());
            Ok(rec)
        });
    a.expect_site_scan_restore()
        .times(1)
        .returning(move |_| Ok(take.lock().expect("lock").clone().expect("was held")));
    // The scan that follows finds nothing wrong: it doesn't speak for ClamAV.
    a.expect_site_scan_worker().returning(move |job| match job {
        WorkerJob::Discover { .. } => WorkerReply::Discovery(Default::default()),
        WorkerJob::Scan(_) => WorkerReply::Scan(SiteScanOutcome {
            upstream: hyperion_adapters::sitescan::scan::UpstreamResult {
                ran: true,
                ..Default::default()
            },
            coverage: hyperion_types::ScanCoverage {
                upstream_ran: true,
                ..Default::default()
            },
            ..Default::default()
        }),
    });
    a.expect_site_scan_evict_manifests().returning(|_| ());
    let mut r = result(vec![rule_hit("up.php", SHA)], vec![]);
    r.clamav_available = true;
    let (s, _pool, sel, id) = fixture(a, r).await;
    let root = s.get(sel.clone()).await.expect("get").root_dir;
    let other = hyperion_types::WpMalwareHit {
        path: format!("{root}/other.php"),
        signature: "Other".into(),
    };
    let hit = hyperion_types::WpMalwareHit {
        path: format!("{root}/up.php"),
        signature: "Php.Trojan.Webshell-1".into(),
    };
    let mut rec = s.stored_integrity_scan(&id).await.expect("stored");
    rec.result.malware = vec![hit.clone(), other.clone()];
    s.set_stored_integrity_scan(&id, &rec).await;

    let after = s
        .scan_file_quarantine(sel.clone(), "up.php".into(), SHA.into(), String::new())
        .await
        .expect("quarantine");
    // Gone with the file, and written down where it went.
    assert_eq!(after.malware, [other.clone()]);
    assert_eq!(
        held.lock().expect("lock").as_ref().expect("held").malware,
        [hit.clone()]
    );

    let back = s
        .scan_file_restore(sel, "1".repeat(32), String::new())
        .await
        .expect("restore");
    assert!(back.malware.contains(&hit));
    assert!(!back.is_clean());

    // And a scan that runs next carries it, as it does any standing ClamAV hit.
    s.site_scan_tick_at(&chrono::Utc, 2_000_000)
        .await
        .expect("tick");
    let stored = s.stored_integrity_scan(&id).await.expect("stored");
    assert!(stored.result.malware.contains(&hit), "laundered");
    assert!(stored.result.malware.contains(&other));
    assert!(!stored.result.awaiting_rescan);
    assert!(!stored.result.is_clean());
}

// ---- audit ----

#[tokio::test]
async fn actions_are_audited() {
    let mut a = happy_mocks();
    a.expect_site_scan_quarantine()
        .times(1)
        .returning(|r| Ok(moved(r)));
    a.expect_site_scan_restore().times(1).returning(|_| {
        Ok(QuarantinedFile {
            rel: "gone.php".into(),
            sha256: SHA.into(),
            ..Default::default()
        })
    });
    let r = result(
        vec![rule_hit("gone.php", SHA)],
        vec![
            finding("one.php", FindingKind::BaselineChange, SHA),
            finding("two.php", FindingKind::BaselineChange, SHA2),
        ],
    );
    let (s, pool, sel, _id) = fixture(a, r).await;
    let actor = || "kevin".to_string();
    s.scan_file_quarantine(sel.clone(), "gone.php".into(), SHA.into(), actor())
        .await
        .expect("quarantine");
    s.scan_file_restore(sel.clone(), "1".repeat(32), actor())
        .await
        .expect("restore");
    s.scan_file_trust(sel.clone(), "one.php".into(), SHA.into(), actor())
        .await
        .expect("trust");
    s.scan_trust_all_review(sel.clone(), actor())
        .await
        .expect("trust all");

    for (action, path, hash) in [
        ("wp.integrity.quarantine", "gone.php", SHA),
        ("wp.integrity.restore", "gone.php", SHA),
        ("wp.integrity.trust", "one.php", SHA),
        ("wp.integrity.trust_all", "two.php", SHA2),
    ] {
        let rows = audit_rows(&pool, action).await;
        assert_eq!(rows.len(), 1, "{action}");
        let (who, payload, outcome) = &rows[0];
        assert_eq!(who, "kevin", "{action}");
        assert_eq!(outcome, "ok", "{action}");
        assert!(payload.contains(path), "{action}: {payload}");
        assert!(payload.contains(hash), "{action}: {payload}");
    }

    // A refusal is on the record too: someone tried.
    assert!(s
        .scan_file_trust(sel, "/etc/shadow\u{1b}".into(), SHA.into(), actor())
        .await
        .is_err());
    let rows = audit_rows(&pool, "wp.integrity.trust").await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].2, "refused");
    // Control characters a form sent stay out of the row as raw bytes.
    assert!(!rows[1].1.contains('\u{1b}'));
}

/// A bulk trust is every file on the record, in rows of a bounded size.
#[tokio::test]
async fn trust_all_audits_every_file() {
    let review: Vec<SiteFileFinding> = (0..250)
        .map(|i| finding(&format!("f{i}.php"), FindingKind::BaselineChange, SHA))
        .collect();
    let (s, pool, sel, _id) = fixture(no_file_touched(), result(vec![], review)).await;
    s.scan_trust_all_review(sel, String::new())
        .await
        .expect("trust all");
    let rows = audit_rows(&pool, "wp.integrity.trust_all").await;
    assert_eq!(rows.len(), 3);
    let all = rows.iter().map(|r| r.1.as_str()).collect::<String>();
    for i in 0..250 {
        assert!(all.contains(&format!("\"f{i}.php\"")), "f{i}.php");
    }
    assert!(rows.iter().all(|r| r.0 == "agent"), "no actor named: agent");
}

// ---- reinstall ----

fn wporg(slug: &str, label: &str) -> SiteFileFinding {
    SiteFileFinding {
        component: Some(slug.into()),
        source_label: Some(label.into()),
        ..finding(
            &format!("wp-content/plugins/{slug}/x.php"),
            FindingKind::UpstreamModified,
            SHA,
        )
    }
}

fn failed(slug: &str, version: &str) -> hyperion_types::WpIntegrityPluginResult {
    hyperion_types::WpIntegrityPluginResult {
        slug: slug.into(),
        issues: vec![hyperion_types::WpIntegrityFileIssue {
            path: "x.php".into(),
            message: "x".into(),
        }],
        version: version.into(),
    }
}

fn action_ok() -> hyperion_types::WpPluginActionResult {
    hyperion_types::WpPluginActionResult {
        state: "ok".into(),
        message: "done".into(),
        output_tail: String::new(),
    }
}

#[tokio::test]
async fn reinstall_refused_server_side_for_vendor_label() {
    let mut a = happy_mocks();
    a.expect_wp_plugin_action().never();
    a.expect_wp_theme_action().never();
    let mut r = result(vec![wporg("elementor-pro", "vendor package")], vec![]);
    r.plugins_failed = vec![failed("elementor-pro", "3.0")];
    r.themes_failed = vec![failed("elementor-pro", "3.0")];
    let (s, _pool, sel, _id) = fixture(a, r).await;
    for theme in [false, true] {
        let e = s
            .scan_component_reinstall(sel.clone(), "elementor-pro".into(), theme)
            .await
            .expect_err("refused");
        assert!(e.to_string().contains("vendor"), "{e}");
    }
}

#[tokio::test]
async fn reinstall_refused_for_a_record_cut_short_or_a_slug_not_failed() {
    let mut a = happy_mocks();
    a.expect_wp_plugin_action().never();
    let mut r = result(vec![], vec![]);
    // On the failed list with no finding left to say what it was compared with.
    r.plugins_failed = vec![failed("unlabelled", "1.0")];
    let (s, _pool, sel, _id) = fixture(a, r).await;
    for slug in ["unlabelled", "never-failed"] {
        assert!(
            s.scan_component_reinstall(sel.clone(), slug.into(), false)
                .await
                .is_err(),
            "{slug}"
        );
    }
}

#[tokio::test]
async fn reinstall_goes_ahead_for_wordpress_org() {
    let mut a = happy_mocks();
    a.expect_wp_plugin_action()
        .times(1)
        .withf(|_, _, slug, action| {
            slug == "akismet" && *action == hyperion_types::WpPluginAction::Reinstall
        })
        .returning(|_, _, _, _| Ok(action_ok()));
    let mut r = result(vec![wporg("akismet", "wordpress.org")], vec![]);
    r.plugins_failed = vec![failed("akismet", "5.0")];
    let (s, _pool, sel, _id) = fixture(a, r).await;
    let out = s
        .scan_component_reinstall(sel, "akismet".into(), false)
        .await
        .expect("reinstall");
    assert_eq!(out.state, "ok");
}

/// A record from before the labels could only have meant wordpress.org.
#[tokio::test]
async fn reinstall_keeps_its_legacy_pass() {
    let mut a = happy_mocks();
    a.expect_wp_plugin_action()
        .times(1)
        .returning(|_, _, _, _| Ok(action_ok()));
    let mut r = result(vec![], vec![]);
    r.native_scan_ran = false;
    r.plugins_failed = vec![failed("akismet", "")];
    let (s, _pool, sel, _id) = fixture(a, r).await;
    s.scan_component_reinstall(sel, "akismet".into(), false)
        .await
        .expect("reinstall");
}

#[tokio::test]
async fn reinstall_theme_pins_the_stored_version() {
    let mut a = happy_mocks();
    a.expect_wp_theme_action()
        .times(1)
        .withf(|_, _, slug, action| {
            slug == "twentytwenty"
                && *action
                    == hyperion_types::WpThemeAction::Reinstall {
                        version: "2.5".into(),
                    }
        })
        .returning(|_, _, _, _| {
            Ok(hyperion_types::WpThemeActionResult {
                state: "ok".into(),
                message: "done".into(),
                output_tail: String::new(),
            })
        });
    let mut item = wporg("twentytwenty", "wordpress.org");
    item.rel = "wp-content/themes/twentytwenty/x.php".into();
    let mut r = result(vec![item], vec![]);
    r.themes_failed = vec![failed("twentytwenty", "2.5")];
    let (s, _pool, sel, _id) = fixture(a, r).await;
    let out = s
        .scan_component_reinstall(sel, "twentytwenty".into(), true)
        .await
        .expect("reinstall");
    assert_eq!(out.message, "done");
}

/// A record from before the version was stored can't say which release to fetch.
#[tokio::test]
async fn reinstall_theme_needs_a_version() {
    let mut a = happy_mocks();
    a.expect_wp_theme_action().never();
    let mut item = wporg("twentytwenty", "wordpress.org");
    item.rel = "wp-content/themes/twentytwenty/x.php".into();
    let mut r = result(vec![item], vec![]);
    r.themes_failed = vec![failed("twentytwenty", "")];
    let (s, _pool, sel, _id) = fixture(a, r).await;
    let e = s
        .scan_component_reinstall(sel, "twentytwenty".into(), true)
        .await
        .expect_err("refused");
    assert!(e.to_string().contains("scan again"), "{e}");
}
