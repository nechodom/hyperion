//! Tests for `service::offsite`.

use super::*;

#[test]
fn curl_failure_reason_keeps_the_message_not_the_exit_code() {
    use super::curl_failure_reason;
    assert_eq!(
        curl_failure_reason(
            "curl: (7) Failed to connect to a.cz port 443 after 0 ms: Couldn't connect to server\n"
        ),
        "Failed to connect to a.cz port 443 after 0 ms: Couldn't connect to server"
    );
    assert_eq!(
        curl_failure_reason("curl: (28) Operation timed out after 15001 milliseconds"),
        "Operation timed out after 15001 milliseconds"
    );
    // Not curl's shape: passed through untouched, never invented.
    assert_eq!(curl_failure_reason("\n  something odd\n"), "something odd");
    assert_eq!(curl_failure_reason(""), "");
    assert_eq!(curl_failure_reason(&"x".repeat(500)).len(), 200);
}

#[test]
fn offsite_pin_beats_the_node_default_and_unset_changes_nothing() {
    use super::{choose_offsite_targets, OffsiteChoice};
    let resolved = vec![s3_target("wasabi-eu"), s3_target("b2-cold")];

    // Unset: byte-identical to what the code did before pinning existed —
    // the caller's OWN slice, whole and in order, is what gets uploaded to.
    match choose_offsite_targets(None, &resolved) {
        OffsiteChoice::NodeDefault(t) => {
            assert!(std::ptr::eq(t, &resolved[..]), "same slice, untouched");
            assert_eq!(t, &resolved[..]);
        }
        other => panic!("unset must be the node default, got {other:?}"),
    }
    // A blank / whitespace value is stored by nobody, but if it ever is it
    // must mean "unpinned", not "pinned to a target called ''".
    assert_eq!(
        choose_offsite_targets(Some("   "), &resolved),
        OffsiteChoice::NodeDefault(&resolved[..])
    );

    // Pinned: exactly one target, and it's the one named.
    assert_eq!(
        choose_offsite_targets(Some("b2-cold"), &resolved),
        OffsiteChoice::Pinned(&resolved[1])
    );
    // Whitespace around a stored name doesn't break the match.
    assert_eq!(
        choose_offsite_targets(Some(" b2-cold "), &resolved),
        OffsiteChoice::Pinned(&resolved[1])
    );

    // Pinned to something the caller couldn't resolve (disabled, deleted,
    // renamed, unreadable secret): nothing is pushed. Falling back to the
    // node default here would put a client's data in a bucket nobody chose.
    assert_eq!(
        choose_offsite_targets(Some("gone"), &resolved),
        OffsiteChoice::Unresolved("gone")
    );

    // Nothing resolved at all. This used to collapse to "node default",
    // i.e. the empty slice — which reads as "uploaded to every target
    // there was" and is how a worker's scheduled backup ignored a pin in
    // silence. The two ways of getting here now stay apart, because they
    // need opposite fixes and only the caller knows which it is.
    let none: Vec<hyperion_types::S3BackupTarget> = Vec::new();
    assert_eq!(
        choose_offsite_targets(None, &none),
        OffsiteChoice::NoTargets
    );
    assert_eq!(
        choose_offsite_targets(Some("wasabi-eu"), &none),
        OffsiteChoice::Unresolved("wasabi-eu"),
        "a pin nothing could satisfy is a broken pin, not a node default"
    );
}

/// The gate that decides whether the ONLY local copy of a backup gets
/// deleted. Every false branch here is a data-loss bug if it flips.
#[test]
fn drop_local_only_when_a_destination_was_used_and_every_file_confirmed() {
    use super::may_drop_local_after_offsite;
    // The happy path: something off-site, and every local file confirmed.
    assert!(may_drop_local_after_offsite(true, &[true]));
    assert!(may_drop_local_after_offsite(true, &[true, true]));
    // A single unconfirmed file keeps the whole local copy.
    assert!(!may_drop_local_after_offsite(true, &[true, false]));
    assert!(!may_drop_local_after_offsite(true, &[false]));
    // No destination was used → never delete, even if the (empty) file
    // list would otherwise vacuously satisfy `all()`. This is the guard
    // that stops a run with no off-site at all from dropping its copy.
    assert!(!may_drop_local_after_offsite(false, &[]));
    assert!(!may_drop_local_after_offsite(false, &[true]));
    // A destination reported present-for-nothing (empty confirmations)
    // must not license a delete either.
    assert!(!may_drop_local_after_offsite(true, &[]));
}

/// WHICH local copies the drop-local policy goes after. The gate still
/// re-verifies each one, but a row this picks that it should not is one
/// re-verify away from being deleted — so every exclusion is pinned.
#[test]
fn local_copies_to_drop_keeps_the_newest_and_needs_offsite_evidence() {
    use super::local_copies_to_drop;
    use std::collections::HashSet;
    // Newest first, as `list_for` returns them.
    let rows = vec![
        bk_run(1, "ok", true, "verified", false),  // newest
        bk_run(2, "running", true, "", false),     // not finished → never
        bk_run(3, "ok", true, "", false),          // local, no off-site evidence
        bk_run(4, "ok", true, "ok", false),        // uploaded
        bk_run(5, "ok", false, "verified", false), // local copy already gone
        bk_run(6, "ok", true, "verified", true),   // rollback snapshot → never
        bk_run(7, "failed", true, "", false),      // failed → never
        bk_run(8, "ok", true, "failed", false),    // off-site failed
    ];
    let none = HashSet::new();
    // keep 0: everything with evidence that is a real local copy.
    assert_eq!(local_copies_to_drop(&rows, 0, &none), vec![1, 4]);
    // keep 1: the newest LOCAL copy (1) stays.
    assert_eq!(local_copies_to_drop(&rows, 1, &none), vec![4]);
    // keep 2: 1 and 3 are the two newest local copies — 3 counts towards
    // the kept ones even though it has no off-site copy.
    assert_eq!(local_copies_to_drop(&rows, 2, &none), vec![4]);
    assert_eq!(local_copies_to_drop(&rows, 3, &none), Vec::<i64>::new());
    // A run pushed moments ago is a candidate before its row says so (an
    // S3 push writes no remote state) — but never past the keep rule, and
    // never when it is a snapshot or has no local copy.
    let pushed: HashSet<i64> = [3, 8, 6, 5].into_iter().collect();
    assert_eq!(local_copies_to_drop(&rows, 0, &pushed), vec![1, 3, 4, 8]);
    assert_eq!(local_copies_to_drop(&rows, 2, &pushed), vec![4, 8]);
    // A completed S3 push on record is evidence on its own (the S3 push
    // writes no remote_state) — so an S3-only node's older copies are
    // still found once they leave the keep window.
    let mut rows = rows;
    rows[2].s3_ok_targets = vec!["vault".into()]; // run 3
    assert_eq!(local_copies_to_drop(&rows, 0, &none), vec![1, 3, 4]);
    assert_eq!(local_copies_to_drop(&rows, 1, &none), vec![3, 4]);
}

/// A drop and a restore/push exclude each other atomically: no
/// reservation while someone else holds the archive, and no new hold
/// while a drop has it.
#[test]
fn drop_reservation_and_claims_exclude_each_other() {
    use super::{try_reserve_drop, ArchiveInUse};
    let dir = tempfile::tempdir().expect("dir");
    let p = dir.path().join("y.cz-1.tar.gz");
    std::fs::write(&p, b"x").expect("w");

    let restore = ArchiveInUse::try_claim(&p).expect("free");
    assert!(try_reserve_drop(&p, 0).is_none(), "a restore holds it");
    // A caller that holds ONE claim itself (a push about to drop what it
    // just sent) may reserve only if nobody else holds it too.
    let push = ArchiveInUse::try_claim(&p).expect("free");
    assert!(
        try_reserve_drop(&p, 1).is_none(),
        "restore + push = 2 holders"
    );
    drop(restore);
    let r = try_reserve_drop(&p, 1).expect("only the pusher holds it");
    // While reserved, nobody new can start on it.
    assert!(ArchiveInUse::try_claim(&p).is_none());
    assert!(try_reserve_drop(&p, 1).is_none(), "one drop at a time");
    drop(r);
    drop(push);
    assert!(ArchiveInUse::try_claim(&p).is_some());
    assert!(try_reserve_drop(&p, 0).is_some());
}

/// S3 evidence is tied to the target configuration it was earned
/// against: a new age recipient (or bucket/endpoint) makes old evidence
/// inert.
#[test]
fn s3_evidence_key_tracks_the_target_configuration() {
    use super::{s3_evidence_key, s3_evidence_name};
    let t = |rcpt: Option<&str>, bucket: &str| hyperion_types::S3BackupTarget {
        name: "vault".into(),
        endpoint: "https://s3.example".into(),
        bucket: bucket.into(),
        region: "eu".into(),
        access_key_id: "k".into(),
        secret_access_key: "s".into(),
        age_recipient: rcpt.map(Into::into),
        retention_daily: 0,
    };
    let a = s3_evidence_key(&t(Some("age1aaa"), "b"));
    assert_eq!(
        a,
        s3_evidence_key(&t(Some(" age1aaa "), "b")),
        "trimmed, stable"
    );
    assert_ne!(
        a,
        s3_evidence_key(&t(Some("age1bbb"), "b")),
        "new recipient"
    );
    assert_ne!(a, s3_evidence_key(&t(Some("age1aaa"), "c")), "new bucket");
    assert_ne!(a, s3_evidence_key(&t(None, "b")), "encryption switched off");
    assert_eq!(s3_evidence_name(&a), "vault");
    assert_eq!(s3_evidence_name("plain"), "plain");
}

#[test]
fn ftp_said_no_is_an_answer_transport_errors_are_not() {
    use super::ftp_said_no;
    for c in [9, 19, 21, 78] {
        assert!(ftp_said_no(c), "{c}");
    }
    // refused, resolve, timeout, TLS, login denied: could not look.
    for c in [6, 7, 28, 35, 67] {
        assert!(!ftp_said_no(c), "{c}");
    }
}

/// The busy-archive registry counts: two holders of one archive keep it
/// busy until BOTH let go, and a key taken before the file exists matches
/// the path spelled the same way afterwards.
#[test]
fn archive_in_use_registry_counts_holders() {
    use super::{archive_in_use, ArchiveInUse};
    let dir = tempfile::tempdir().expect("dir");
    let p = dir.path().join("x.cz-1.tar.gz");
    assert!(!archive_in_use(&p));
    let a = ArchiveInUse::claim(&p);
    std::fs::write(&p, b"x").expect("w");
    assert!(
        archive_in_use(&p),
        "claimed before it existed, still matches"
    );
    let b = ArchiveInUse::claim(&p.canonicalize().expect("canon"));
    drop(a);
    assert!(archive_in_use(&p), "the second holder still has it");
    drop(b);
    assert!(!archive_in_use(&p));
}

/// The Backups card's "why is the local copy still here" — derived from
/// the node's CURRENT policy, so it can never go stale.
#[test]
fn local_kept_reason_explains_every_kept_copy() {
    use super::{local_kept_reason, LocalCopyPolicy};
    let off = LocalCopyPolicy {
        drop: false,
        keep_latest: 0,
        ..LocalCopyPolicy::default()
    };
    let on = LocalCopyPolicy {
        drop: true,
        keep_latest: 0,
        ..LocalCopyPolicy::default()
    };
    let on_keep2 = LocalCopyPolicy {
        drop: true,
        keep_latest: 2,
        ..LocalCopyPolicy::default()
    };
    let verified = bk_run(1, "ok", true, "verified", false);
    let uploaded = bk_run(1, "ok", true, "ok", false);
    let local_only = bk_run(1, "ok", true, "", false);

    // Option off: only an off-site copy has something to explain.
    assert_eq!(local_kept_reason(&verified, off, Some(0)).0, "setting_off");
    assert_eq!(local_kept_reason(&uploaded, off, Some(0)).0, "setting_off");
    assert_eq!(local_kept_reason(&local_only, off, Some(0)).0, "");
    // Not a local copy at all → nothing, whatever the policy.
    for r in [
        bk_run(1, "ok", false, "verified", false),
        bk_run(1, "ok", true, "verified", true),
        bk_run(1, "running", true, "verified", false),
    ] {
        assert_eq!(local_kept_reason(&r, off, Some(0)).0, "");
        assert_eq!(local_kept_reason(&r, on, Some(0)).0, "");
    }
    // Option on, within the newest N → kept on purpose.
    let (k, words) = local_kept_reason(&verified, on_keep2, Some(1));
    assert_eq!(k, "keep_newest");
    assert!(words.contains('2'), "names the count: {words}");
    // Past N, nothing stored yet → it goes at the next backup.
    assert_eq!(local_kept_reason(&verified, on_keep2, Some(2)).0, "pending");
    assert_eq!(local_kept_reason(&verified, on, Some(0)).0, "pending");
    // The drop step refused it → its stored reason, verbatim.
    let mut refused = verified.clone();
    refused.local_note = "Kept on this node: nope".into();
    assert_eq!(
        local_kept_reason(&refused, on, Some(3)),
        ("unconfirmed", "Kept on this node: nope".to_string())
    );
    // …whatever the policy says now: the note is the most specific answer
    // (an on-demand drop runs with the option off, and ignores keep N).
    assert_eq!(local_kept_reason(&refused, off, Some(0)).0, "unconfirmed");
    assert_eq!(
        local_kept_reason(&refused, on_keep2, Some(0)).0,
        "unconfirmed"
    );
    // …even for a run whose own push failed (no off-site on record).
    let mut refused_local = local_only.clone();
    refused_local.local_note = "Kept on this node: nope".into();
    assert_eq!(
        local_kept_reason(&refused_local, on, Some(3)).0,
        "unconfirmed"
    );
    assert_eq!(
        local_kept_reason(&refused_local, off, Some(3)).0,
        "unconfirmed"
    );
    assert_eq!(local_kept_reason(&local_only, on, Some(3)).0, "");
    // Files listed but not on disk: its own kind, whatever the policy.
    let mut missing = verified.clone();
    missing.local_note = super::LOCAL_FILES_MISSING_NOTE.into();
    assert_eq!(local_kept_reason(&missing, off, Some(0)).0, "missing");
    assert_eq!(local_kept_reason(&missing, on, Some(5)).0, "missing");
    // An S3-only backup with a completed push is on record too.
    let mut s3_only = local_only.clone();
    s3_only.s3_ok_targets = vec!["vault".into()];
    assert_eq!(local_kept_reason(&s3_only, off, Some(0)).0, "setting_off");
    assert_eq!(local_kept_reason(&s3_only, on, Some(0)).0, "pending");
}

#[test]
fn local_kept_unconfirmed_note_names_the_files() {
    use super::local_kept_unconfirmed_note;
    assert!(local_kept_unconfirmed_note(&["archive"]).contains("copy of the archive could"));
    assert!(local_kept_unconfirmed_note(&["archive", "database dump"])
        .contains("copy of the archive and the database dump could"));
    assert!(local_kept_unconfirmed_note(&[]).contains("the off-site copy could"));
}

#[test]
fn manifest_path_for_only_derives_a_real_sibling() {
    use super::manifest_path_for;
    use std::path::Path;
    assert_eq!(
        manifest_path_for(Path::new("/b/u/www.x.cz-1790627073.tar.gz")).as_deref(),
        Some(Path::new("/b/u/www.x.cz-1790627073.manifest.json"))
    );
    // Never guess at anything that is not one of our archives.
    assert_eq!(manifest_path_for(Path::new("/b/u/x.cz-1.sql")), None);
    assert_eq!(manifest_path_for(Path::new("/b/u/.tar.gz")), None);
    assert_eq!(manifest_path_for(Path::new("/")), None);
}

/// The remote folder is per system user and hostings can share one, so
/// a site's card and restore must only ever see the site's own files.
#[test]
fn offsite_file_belongs_only_to_its_own_domain() {
    use super::offsite_file_belongs;
    assert!(offsite_file_belongs("a.cz", "a.cz-1700000000.tar.gz"));
    assert!(offsite_file_belongs("a.cz", "a.cz-1700000000.tgz"));
    assert!(offsite_file_belongs("a.cz", "a.cz-1700000000.sql"));
    // A sibling site under the same system user.
    assert!(!offsite_file_belongs("a.cz", "b.cz-1700000000.tar.gz"));
    // A sibling whose name STARTS with this one — the stamp must be digits.
    assert!(!offsite_file_belongs(
        "a.cz",
        "a.cz-shop.cz-1700000000.tar.gz"
    ));
    assert!(!offsite_file_belongs("shop.a.cz", "a.cz-1700000000.tar.gz"));
    // Not a backup at all.
    assert!(!offsite_file_belongs(
        "a.cz",
        "a.cz-1700000000.manifest.json"
    ));
    assert!(!offsite_file_belongs("a.cz", "a.cz-.tar.gz"));
    assert!(!offsite_file_belongs("a.cz", "a.cz.tar.gz"));
    assert!(!offsite_file_belongs("a.cz", "a.cz-17x.tar.gz"));
}

/// "off-site ✓" must mean every file checked out — the same thing the
/// drop step demands before it deletes.
#[test]
fn ftp_offsite_verdict_needs_every_file() {
    use super::ftp_offsite_verdict;
    assert_eq!(
        ftp_offsite_verdict(&[("archive", Some(true))]).0,
        "verified"
    );
    assert_eq!(
        ftp_offsite_verdict(&[("archive", Some(true)), ("database dump", Some(true))]).0,
        "verified"
    );
    // Could not look at the dump → only "uploaded", never ✓.
    assert_eq!(
        ftp_offsite_verdict(&[("archive", Some(true)), ("database dump", None)]).0,
        "ok"
    );
    // We LOOKED and the dump is not right → failed, naming it.
    let (st, note) =
        ftp_offsite_verdict(&[("archive", Some(true)), ("database dump", Some(false))]);
    assert_eq!(st, "failed");
    assert!(note.contains("database dump"), "{note}");
    let (st, note) = ftp_offsite_verdict(&[("archive", Some(false)), ("database dump", None)]);
    assert_eq!(st, "failed");
    assert!(note.contains("archive"), "{note}");
    assert_eq!(ftp_offsite_verdict(&[("archive", None)]).0, "ok");
    assert_eq!(ftp_offsite_verdict(&[]).0, "ok");
}

/// Both on-demand entry points must REFUSE when the node has nowhere to
/// push — otherwise a "copy off-site then delete local" with no target is
/// an invitation to delete a copy that reached nowhere. The test svc has
/// `remote_backup: None`, and shipping no S3 targets is the empty case, so
/// there is genuinely no destination.
#[tokio::test]
async fn offsite_push_and_backfill_refuse_with_no_target() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("nod.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("nod.cz").unwrap());

    let err = s
        .backup_offsite_push_drop(sel, vec![1], vec![], true)
        .await
        .expect_err("no target → must refuse before any delete");
    assert!(matches!(err, RpcError::Validation { .. }), "got: {err:?}");

    let err = s
        .backup_offsite_backfill(10, true, vec![])
        .await
        .expect_err("no target → must refuse");
    assert!(matches!(err, RpcError::Validation { .. }), "got: {err:?}");
}

/// The remote folder is per system user, so it can hold a sibling site's
/// archives. Restoring one of those over this site — another domain's
/// files and database — is refused before anything is downloaded, and so
/// is a bare database dump.
#[tokio::test]
async fn offsite_restore_refuses_a_file_that_is_not_this_sites() {
    let pool = open_memory().await.expect("open");
    let mut s = svc(pool.clone(), happy_mocks());
    // Port 1 on loopback: any download attempt would fail as a transfer
    // error, not as the validation refusal asserted below.
    s.remote_backup = Some(RemoteBackupConfig {
        scheme: "ftp".into(),
        host: "127.0.0.1".into(),
        port: 1,
        user: "u".into(),
        password: "p".into(),
        base_path: "/backups".into(),
    });
    s.create(req("own.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("own.cz").unwrap());
    for name in [
        "sibling.cz-1700000000.tar.gz",
        "own.cz-shop.cz-1700000000.tar.gz",
        "own.cz-1700000000.sql",
    ] {
        let err = s
            .backup_offsite_restore(
                sel.clone(),
                name.into(),
                hyperion_types::BackupRestoreMode::FilesOnly,
            )
            .await
            .expect_err("a foreign file must be refused");
        assert!(
            matches!(&err, RpcError::Validation { message } if message.contains("not an off-site backup of own.cz")),
            "{name}: {err:?}"
        );
    }
}

/// The FTP keep-latest rule picks by the stamp in the name, only this
/// site's archives, never the copy just sent, and never a dump on its own.
#[test]
fn ftp_keep_latest_drops_only_this_sites_oldest_archives() {
    use super::ftp_archives_beyond_keep;
    let names = [
        "a.cz-500.tar.gz",
        "a.cz-500.sql",
        "a.cz-400.tar.gz",
        "a.cz-300.tar.gz",
        "a.cz-100.tar.gz",
        "b.cz-50.tar.gz",
        "a.cz-shop.cz-10.tar.gz",
        "notes.txt",
    ];
    assert_eq!(
        ftp_archives_beyond_keep("a.cz", names.iter().copied(), 2, "a.cz-500.tar.gz"),
        vec!["a.cz-300.tar.gz".to_string(), "a.cz-100.tar.gz".to_string()]
    );
    // A clock that went backwards: the copy just sent is still kept.
    assert_eq!(
        ftp_archives_beyond_keep("a.cz", names.iter().copied(), 3, "a.cz-100.tar.gz"),
        Vec::<String>::new()
    );
    assert!(ftp_archives_beyond_keep("a.cz", names.iter().copied(), 10, "x").is_empty());
}

/// Missing, zero, negative or not a number is OFF — a typo must never
/// mean "keep nothing" on the off-site server.
#[test]
fn ftp_keep_latest_reads_only_a_positive_whole_number() {
    use super::read_ftp_keep_latest;
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("agent.toml");
    for (body, want) in [
        ("", 0),
        ("[backup_remote]\nkeep_latest = 0\n", 0),
        ("[backup_remote]\nkeep_latest = -3\n", 0),
        ("[backup_remote]\nkeep_latest = \"5\"\n", 0),
        ("[backup_remote]\nkeep_latest = 7\n", 7),
    ] {
        std::fs::write(&cfg, body).expect("cfg");
        assert_eq!(read_ftp_keep_latest(Some(&cfg)), want, "{body:?}");
    }
    assert_eq!(read_ftp_keep_latest(None), 0);
}

/// Once an FTP copy is deleted, the rows stop claiming it: a row with
/// nothing else left goes, any other is `removed` — which the backfill
/// must not send back to the server it was just deleted from.
#[tokio::test]
async fn forgetting_an_ftp_copy_deletes_empty_rows_and_marks_the_rest() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("fg.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("fg.cz").unwrap());
    let detail = s.get(sel.clone()).await.expect("get");
    let mk = |at: i64| {
        let pool = pool.clone();
        let id = detail.id.clone();
        async move {
            let r = backups::start(&pool, &id, "local", at)
                .await
                .expect("start");
            backups::mark_ok(&pool, r, &format!("/b/fg.cz-{at}.tar.gz"), None, 10, at + 1)
                .await
                .expect("ok");
            backups::set_remote(
                &pool,
                r,
                &format!("ftp://h:21/b/u/fg.cz-{at}.tar.gz"),
                "verified",
                "",
            )
            .await
            .expect("remote");
            r
        }
    };
    let only_ftp = mk(100).await;
    backups::clear_local_paths(&pool, only_ftp)
        .await
        .expect("clear");
    let with_local = mk(200).await;
    let untouched = mk(300).await;

    let (marked, deleted) = s
        .forget_ftp_copies(
            &detail,
            &[
                "fg.cz-100.tar.gz".to_string(),
                "fg.cz-200.tar.gz".to_string(),
            ],
            "gone",
            None,
        )
        .await;
    assert_eq!((marked, deleted), (1, 1));
    assert!(backups::get_by_id(&pool, only_ftp)
        .await
        .expect("get")
        .is_none());
    let r = backups::get_by_id(&pool, with_local)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(r.remote_state, "removed");
    assert_eq!(r.remote_blob_key, "");
    assert_eq!(r.remote_error, "gone");
    let r = backups::get_by_id(&pool, untouched)
        .await
        .expect("get")
        .expect("row");
    assert_eq!(r.remote_state, "verified");
    // Not re-queued for an upload.
    let queue = backups::list_needing_offsite(&pool, 100)
        .await
        .expect("queue");
    assert!(queue.iter().all(|r| r.id != with_local), "{queue:?}");
}

/// The web layer reads "has no copy on the FTP target" as "nothing to do"
/// and goes on to delete the local copy, so that refusal must stay that
/// refusal — and come before anything is sent anywhere.
#[tokio::test]
async fn offsite_delete_of_a_backup_with_no_ftp_copy_says_so() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let mut s = svc(pool.clone(), happy_mocks());
    s.remote_backup = Some(RemoteBackupConfig {
        scheme: "ftp".into(),
        host: "127.0.0.1".into(),
        port: 1,
        user: "u".into(),
        password: "p".into(),
        base_path: "/backups".into(),
    });
    s.create(req("nf.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("nf.cz").unwrap());
    let detail = s.get(sel.clone()).await.expect("get");
    let r = backups::start(&pool, &detail.id, "local", 5)
        .await
        .expect("start");
    backups::mark_ok(&pool, r, "/b/nf.cz-5.tar.gz", None, 1, 6)
        .await
        .expect("ok");
    let err = s
        .backup_offsite_delete(sel.clone(), Some(r), None)
        .await
        .expect_err("no FTP copy");
    assert!(
        matches!(&err, RpcError::Validation { message } if message.contains("has no copy on the FTP target")),
        "{err:?}"
    );
    let err = s
        .backup_offsite_delete(sel, None, Some("other.cz-5.tar.gz".into()))
        .await
        .expect_err("foreign");
    assert!(matches!(err, RpcError::Validation { .. }), "{err:?}");
}

/// Against a real FTP server (`HY_FTP_TEST=host:port:user:password:base`):
/// the card's delete takes the archive AND its dump off the server, and
/// the row that only had that copy goes with it. Run with `--ignored`.
#[tokio::test]
#[ignore]
async fn offsite_delete_against_a_real_ftp_server() {
    use hyperion_state::backups;
    let Ok(spec) = std::env::var("HY_FTP_TEST") else {
        return;
    };
    let p: Vec<String> = spec.splitn(5, ':').map(str::to_string).collect();
    let pool = open_memory().await.expect("open");
    let mut s = svc(pool.clone(), happy_mocks());
    s.remote_backup = Some(RemoteBackupConfig {
        scheme: "ftp".into(),
        host: p[0].clone(),
        port: p[1].parse().expect("port"),
        user: p[2].clone(),
        password: p[3].clone(),
        base_path: p[4].clone(),
    });
    s.create(req("e2e.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("e2e.cz").unwrap());
    let detail = s.get(sel.clone()).await.expect("get");
    let (mut up, dir) = s.remote_upload_for(&detail).expect("target");
    up.remote_dir = &dir;
    let tmp = tempfile::tempdir().expect("dir");
    for n in ["e2e.cz-100.tar.gz", "e2e.cz-100.sql", "e2e.cz-200.tar.gz"] {
        let f = tmp.path().join(n);
        std::fs::write(&f, b"x").expect("write");
        hyperion_adapters::backup::upload_remote(&f, &up)
            .await
            .expect("upload");
    }
    let r = backups::start(&pool, &detail.id, "local", 100)
        .await
        .expect("start");
    backups::mark_ok(&pool, r, "/b/e2e.cz-100.tar.gz", None, 1, 101)
        .await
        .expect("ok");
    backups::set_remote(
        &pool,
        r,
        &format!("ftp://h/{dir}/e2e.cz-100.tar.gz"),
        "verified",
        "",
    )
    .await
    .expect("remote");
    backups::clear_local_paths(&pool, r).await.expect("clear");

    let msg = s
        .backup_offsite_delete(sel.clone(), None, Some("e2e.cz-100.tar.gz".into()))
        .await
        .expect("delete");
    assert!(msg.contains("e2e.cz-100.tar.gz"), "{msg}");
    let left = s.backup_offsite_list(sel.clone()).await.expect("list");
    let names: Vec<&str> = left.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["e2e.cz-200.tar.gz"]);
    assert!(backups::get_by_id(&pool, r).await.expect("get").is_none());

    // The backups list's "delete everywhere": by row, and the row must
    // still be there for the delete that follows — it used to be gone
    // already, and the list reported "not found" for a delete that worked.
    let r2 = backups::start(&pool, &detail.id, "local", 200)
        .await
        .expect("start");
    backups::mark_ok(&pool, r2, "/b/e2e.cz-200.tar.gz", None, 1, 201)
        .await
        .expect("ok");
    backups::set_remote(
        &pool,
        r2,
        &format!("ftp://h/{dir}/e2e.cz-200.tar.gz"),
        "verified",
        "",
    )
    .await
    .expect("remote");
    backups::clear_local_paths(&pool, r2).await.expect("clear");
    s.backup_offsite_delete(sel.clone(), Some(r2), None)
        .await
        .expect("delete by row");
    s.backup_delete(sel.clone(), r2)
        .await
        .expect("row still there");
    let left = s.backup_offsite_list(sel.clone()).await.expect("list");
    assert!(left.files.is_empty(), "{:?}", left.files);

    // The keep-latest rule, with the copy "just pushed" protected.
    let kept = tmp.path().join("e2e.cz-300.tar.gz");
    std::fs::write(&kept, b"x").expect("write");
    hyperion_adapters::backup::upload_remote(&kept, &up)
        .await
        .expect("upload");
    let older = tmp.path().join("e2e.cz-250.tar.gz");
    std::fs::write(&older, b"x").expect("write");
    hyperion_adapters::backup::upload_remote(&older, &up)
        .await
        .expect("upload");
    let n = s
        .prune_ftp_keep_latest(&detail, &up, 1, "e2e.cz-300.tar.gz")
        .await
        .expect("prune");
    assert_eq!(n, 1);
    let left = s.backup_offsite_list(sel.clone()).await.expect("list");
    let names: Vec<&str> = left.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["e2e.cz-300.tar.gz"]);
    s.backup_offsite_delete(sel, None, Some("e2e.cz-300.tar.gz".into()))
        .await
        .expect("cleanup");
}

/// The drop step with a destination it cannot reach: the local copy is
/// KEPT (never deleted on "could not look"), the row says why, and the
/// audit row is written once — not again after every later backup that
/// re-asks the same question and gets the same answer.
#[tokio::test]
async fn drop_local_keeps_an_unconfirmed_copy_and_reports_it_once() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let mut s = svc(pool.clone(), happy_mocks());
    // Port 1 on loopback: connection refused at once, so verify_remote
    // answers "could not look".
    s.remote_backup = Some(RemoteBackupConfig {
        scheme: "ftp".into(),
        host: "127.0.0.1".into(),
        port: 1,
        user: "u".into(),
        password: "p".into(),
        base_path: "/backups".into(),
    });
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(&cfg, "[backup]\ndrop_local_after_offsite = true\n").expect("cfg");
    s.agent_config_path = Some(cfg);
    s.create(req("keep.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("keep.cz").unwrap());
    let detail = s.get(sel.clone()).await.expect("get");

    let archive = dir.path().join("keep.cz-100.tar.gz");
    let manifest = dir.path().join("keep.cz-100.manifest.json");
    std::fs::write(&archive, b"archive-bytes").expect("archive");
    std::fs::write(&manifest, b"{}").expect("manifest");
    let run = backups::start(&pool, &detail.id, "local", 100)
        .await
        .expect("start");
    backups::mark_ok(&pool, run, &archive.display().to_string(), None, 13, 101)
        .await
        .expect("ok");
    backups::set_remote(&pool, run, "ftp://x/keep.cz-100.tar.gz", "verified", "")
        .await
        .expect("remote");

    let audit_fails = |pool: SqlitePool| async move {
        hyperion_state::audit::list(&pool, 1000)
            .await
            .expect("audit")
            .into_iter()
            .filter(|e| e.action == "hosting.backup.drop_local" && e.result == "failed")
            .count()
    };

    let empty = std::collections::HashMap::new();
    let out = s.enforce_local_copies(&detail, 0, &[], &empty).await;
    assert_eq!(out, vec![(run, DropLocalOutcome::Unreachable)]);
    assert!(archive.exists(), "could-not-look must never delete");
    assert!(manifest.exists());
    let row = backups::get_by_id(&pool, run).await.unwrap().unwrap();
    assert!(row.archive_path.is_some());
    assert!(row.local_note.contains("archive"), "{}", row.local_note);
    assert_eq!(audit_fails(pool.clone()).await, 1);

    // Same answer next time → no second audit row.
    let out = s.enforce_local_copies(&detail, 0, &[], &empty).await;
    assert_eq!(out, vec![(run, DropLocalOutcome::Unreachable)]);
    assert_eq!(
        audit_fails(pool.clone()).await,
        1,
        "reported once, not per backup"
    );

    // And the card shows the stored reason.
    let list = s.backup_list(sel.clone(), 10).await.expect("list");
    assert_eq!(list[0].local_kept, "unconfirmed");

    // keep 1 → the only local copy is the newest: not even asked about.
    let out = s.enforce_local_copies(&detail, 1, &[], &empty).await;
    assert!(out.is_empty());

    // The on-demand action on the same row: the silent re-check fails,
    // the fallback push cannot reach the FTP either → counted failed,
    // nothing deleted, no extra "kept" audit from the silent probe.
    let r = s
        .backup_offsite_push_drop(sel, vec![run], vec![], true)
        .await
        .expect("push-drop");
    assert_eq!((r.dropped, r.already_offsite, r.failed), (0, 0, 1));
    assert!(archive.exists());
    assert_eq!(audit_fails(pool.clone()).await, 1);
}

/// A stored "could not confirm" goes once the copy is kept on purpose
/// (inside the keep window), and an unreadable keep count stops the
/// estate sweep from dropping anything — it never reads as "keep 0".
#[tokio::test]
async fn stale_notes_clear_and_unreadable_keep_blocks_the_sweep() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let mut s = svc(pool.clone(), happy_mocks());
    s.remote_backup = Some(RemoteBackupConfig {
        scheme: "ftp".into(),
        host: "127.0.0.1".into(),
        port: 1,
        user: "u".into(),
        password: "p".into(),
        base_path: "/backups".into(),
    });
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(
        &cfg,
        "[backup]\ndrop_local_after_offsite = true\nkeep_local_latest = \"3\"\n",
    )
    .expect("cfg");
    s.agent_config_path = Some(cfg);
    s.create(req("stale.cz")).await.expect("create");
    let detail = s
        .get(HostingSelector::Domain(Domain::parse("stale.cz").unwrap()))
        .await
        .expect("get");
    let archive = dir.path().join("stale.cz-100.tar.gz");
    std::fs::write(&archive, b"x").expect("w");
    let run = backups::start(&pool, &detail.id, "local", 100)
        .await
        .expect("start");
    backups::mark_ok(&pool, run, &archive.display().to_string(), None, 1, 101)
        .await
        .expect("ok");
    backups::set_remote(&pool, run, "ftp://x/y", "verified", "")
        .await
        .expect("remote");
    backups::set_local_note(&pool, run, "Kept on this node: old news")
        .await
        .expect("note");

    // Unreadable keep count → the estate sweep drops nothing and says why.
    let r = s
        .backup_offsite_backfill(10, true, vec![])
        .await
        .expect("backfill");
    assert_eq!((r.dropped, r.kept_local), (0, 0));
    assert!(r.note.contains("keep_local_latest"), "{}", r.note);
    assert!(archive.exists());

    // Inside the keep window (keep 1, it is the newest) → not a candidate,
    // so its old warning is cleared.
    let empty = std::collections::HashMap::new();
    let out = s.enforce_local_copies(&detail, 1, &[], &empty).await;
    assert!(out.is_empty());
    let row = backups::get_by_id(&pool, run).await.unwrap().unwrap();
    assert_eq!(row.local_note, "");
}

/// The other ways a candidate is NOT a kept copy, against a destination
/// that cannot be reached (so nothing could ever be confirmed — whatever
/// happens here happens without an off-site answer):
///   * a busy archive (a restore is reading it) is left alone entirely;
///   * an archive already gone from disk, dump too, gets its row set
///     straight and is reported missing — never "kept", never deleted;
///   * an archive gone with its dump still there sends the dump alone
///     through the gate, and the reason names the dump.
#[tokio::test]
async fn drop_local_busy_missing_and_dump_only() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let mut s = svc(pool.clone(), happy_mocks());
    s.remote_backup = Some(RemoteBackupConfig {
        scheme: "ftp".into(),
        host: "127.0.0.1".into(),
        port: 1,
        user: "u".into(),
        password: "p".into(),
        base_path: "/backups".into(),
    });
    s.create(req("odd.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("odd.cz").unwrap());
    let detail = s.get(sel.clone()).await.expect("get");
    let dir = tempfile::tempdir().expect("dir");
    let empty = std::collections::HashMap::new();
    let mk = |at: i64, archive: std::path::PathBuf, dump: Option<std::path::PathBuf>| {
        let pool = pool.clone();
        let id = detail.id.clone();
        async move {
            let r = backups::start(&pool, &id, "local", at)
                .await
                .expect("start");
            let d = dump.map(|p| p.display().to_string());
            backups::mark_ok(
                &pool,
                r,
                &archive.display().to_string(),
                d.as_deref(),
                1,
                at,
            )
            .await
            .expect("ok");
            backups::set_remote(&pool, r, "ftp://x/y", "verified", "")
                .await
                .expect("remote");
            r
        }
    };

    // Busy.
    let busy_archive = dir.path().join("odd.cz-300.tar.gz");
    std::fs::write(&busy_archive, b"x").expect("w");
    let busy = mk(300, busy_archive.clone(), None).await;
    {
        let _restore = ArchiveInUse::claim(&busy_archive);
        let out = s.enforce_local_copies(&detail, 0, &[], &empty).await;
        assert_eq!(out.first(), Some(&(busy, DropLocalOutcome::Busy)));
        let row = backups::get_by_id(&pool, busy).await.unwrap().unwrap();
        assert!(row.archive_path.is_some());
        assert_eq!(row.local_note, "", "busy is not a refusal");
    }
    // Released → asked again (and, unreachable, kept).
    let out = s.enforce_local_copies(&detail, 0, &[], &empty).await;
    assert_eq!(out.first(), Some(&(busy, DropLocalOutcome::Unreachable)));
    backups::delete_by_id(&pool, busy).await.expect("rm");

    // Missing: archive and dump both gone from disk.
    let gone = mk(
        200,
        dir.path().join("odd.cz-200.tar.gz"),
        Some(dir.path().join("odd.cz-200.sql")),
    )
    .await;
    let out = s.enforce_local_copies(&detail, 0, &[], &empty).await;
    assert_eq!(out, vec![(gone, DropLocalOutcome::MissingLocally)]);
    let row = backups::get_by_id(&pool, gone).await.unwrap().unwrap();
    // Absence alone is not proof (an unmounted volume looks the same):
    // the row keeps its paths and says so.
    assert!(row.archive_path.is_some() && row.db_dump_path.is_some());
    assert_eq!(row.local_note, super::LOCAL_FILES_MISSING_NOTE);
    assert_eq!(
        row.remote_state, "verified",
        "the off-site record is untouched"
    );
    let list = s.backup_list(sel.clone(), 10).await.expect("list");
    let b = list.iter().find(|b| b.id == gone).expect("row");
    assert_eq!(b.local_kept, "missing");

    // Dump only: archive gone, dump still on disk → the dump is checked.
    let dump = dir.path().join("odd.cz-100.sql");
    std::fs::write(&dump, b"sql").expect("w");
    let half = mk(
        100,
        dir.path().join("odd.cz-100.tar.gz"),
        Some(dump.clone()),
    )
    .await;
    let out = s.enforce_local_copies(&detail, 0, &[], &empty).await;
    assert_eq!(
        out,
        vec![
            (gone, DropLocalOutcome::MissingLocally),
            (half, DropLocalOutcome::Unreachable)
        ]
    );
    assert!(dump.exists());
    let row = backups::get_by_id(&pool, half).await.unwrap().unwrap();
    assert!(
        row.local_note.contains("database dump"),
        "{}",
        row.local_note
    );

    // The on-demand action on a row that is on record off-site but whose
    // archive is gone: counted missing — not "failed", not "kept" — and
    // nothing is pushed.
    let gone2 = mk(50, dir.path().join("odd.cz-50.tar.gz"), None).await;
    let r = s
        .backup_offsite_push_drop(sel.clone(), vec![gone2], vec![], true)
        .await
        .expect("push-drop");
    assert_eq!(
        (r.missing_locally, r.failed, r.kept_local, r.dropped),
        (1, 0, 0, 0)
    );
}

/// node's table, which on a worker is empty by design.
#[tokio::test]
async fn only_a_worker_scheduled_run_reports_the_missing_off_site_copy() {
    use super::{OffsiteSource, OFFSITE_WORKER_HAS_NO_TARGETS};
    let tmp = tempfile::tempdir().expect("tmp");
    let state = tmp.path().join("node-id.json");

    // Master (no node-state file): a scheduled run reading its OWN table
    // is reading the same table the panel shows, so empty really does
    // mean "no off-site configured" and there is nothing to report.
    let master = svc_with_state_file(None).await;
    assert_eq!(master.offsite_gap_reason(OffsiteSource::ThisNode), None);

    // Worker: the same empty list means the cluster's targets never
    // reached the run. The reason names the fix, and it is the SAME
    // string the audit row carries — one explanation, not two that drift.
    std::fs::write(&state, b"{}").expect("write node-id.json");
    let worker = svc_with_state_file(Some(state)).await;
    assert_eq!(
        worker.offsite_gap_reason(OffsiteSource::ThisNode),
        Some(OFFSITE_WORKER_HAS_NO_TARGETS)
    );
    assert!(
        OFFSITE_WORKER_HAS_NO_TARGETS.contains("exists only on this node"),
        "the reason must say the backup did not leave the node"
    );

    // A run whose targets the CALLER resolved, and an internal snapshot,
    // promised nothing off-site — neither may collect a red row, on a
    // worker least of all (that is every pre-export/pre-push snapshot).
    assert_eq!(worker.offsite_gap_reason(OffsiteSource::Caller), None);
    assert_eq!(worker.offsite_gap_reason(OffsiteSource::NotWanted), None);
}

#[tokio::test]
async fn cluster_sync_reaches_a_worker_scheduled_backup() {
    use super::OffsiteSource;
    let (w, dir) = synced_worker(
        "[backup_retention]\nkeep_latest_n = 9\n[acme]\nchallenge_dir = \"/srv/acme\"\n",
    )
    .await;
    assert_eq!(w.cluster_config_revision().await.unwrap(), None);
    assert!(w.resolve_local_s3_targets().await.is_empty());
    assert!(w.offsite_gap_reason(OffsiteSource::ThisNode).is_some());

    let master_toml = "[backup_retention]\nkeep_latest_n = 3\nmax_age_days = 30\n";
    let sections: Vec<(String, std::collections::BTreeMap<String, String>)> =
        crate::cluster_sync::extract_sections(master_toml)
            .unwrap()
            .into_iter()
            .map(|s| (s.section, s.fields))
            .collect();
    let (restart, ignored) = w
        .cluster_config_apply("rev-1".into(), sections, vec![sync_target("b2")])
        .await
        .unwrap();
    assert!(
        !restart,
        "retention is re-read from disk, no restart needed"
    );
    assert!(ignored.is_empty());

    let file = std::fs::read_to_string(dir.path().join("agent.toml")).unwrap();
    assert!(file.contains("keep_latest_n = 3"), "{file}");
    assert!(file.contains("max_age_days = 30"), "{file}");
    assert!(
        file.contains("challenge_dir = \"/srv/acme\""),
        "node-local key kept: {file}"
    );

    assert_eq!(
        w.cluster_config_revision().await.unwrap().as_deref(),
        Some("rev-1")
    );
    let targets = w.resolve_local_s3_targets().await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].name, "b2");
    assert_eq!(targets[0].secret_access_key, "SK");
    // Synced: an empty list now means "the master has none", not a gap.
    assert_eq!(w.offsite_gap_reason(OffsiteSource::ThisNode), None);
}

/// Deleting the section that reads badly must not delete the
/// disclosure. The operator starts from the built-in letter — preamble
/// and all — and drops `{uptime}` because "not monitored" looks bad
/// next to an invoice.
#[test]
fn a_custom_letter_cannot_drop_an_unmeasured_section() {
    let r = mk_care_report(); // uptime is None
    let (_, body) =
        care_report_render_with(&en(), &r, "example.cz", "{domain}\n{attacks}\n{traffic}");
    assert!(
        !body.contains("AVAILABILITY:"),
        "operator did drop it: {body}"
    );
    assert!(
        body.contains("NOT MEASURED THIS PERIOD: availability."),
        "the disclosure must come back: {body}"
    );

    // Keeping the placeholder is the normal case, and must not produce
    // a second copy of the same disclosure.
    let (_, kept) = care_report_render_with(&en(), &r, "example.cz", "{domain}\n{uptime}");
    assert!(kept.contains("AVAILABILITY: not monitored"));
    assert!(!kept.contains("NOT MEASURED THIS PERIOD"), "{kept}");

    // Dropping a MEASURED section stays the operator's call — a
    // shorter letter is still a true one.
    let (_, short) = care_report_render_with(&en(), &r, "example.cz", "{domain}\n{uptime}");
    assert!(!short.contains("ATTACKS BLOCKED"), "{short}");
    assert!(!short.contains("NOT MEASURED THIS PERIOD"), "{short}");
}

/// The bug that made every SPF check in the panel report "no SPF TXT
/// record at the apex", for every domain, for as long as the function
/// existed: `dig_records` dropped any line containing a space.
///
/// This tests the FILTER, which is the part that was wrong — running
/// `dig` needs a network and a nameserver, and neither belongs in a unit
/// test. The rule under test is "what does each record type keep".
#[test]
fn dig_keeps_records_that_contain_spaces_except_for_addresses() {
    // The exact shape of the answers that were being thrown away.
    let txt = r#""v=spf1 include:_spf.google.com ~all""#;
    let mx = "10 mail.example.cz.";
    assert!(keeps("TXT", txt), "an SPF record is mostly spaces");
    assert!(keeps("MX", mx), "an MX answer is priority, space, host");
    assert!(keeps("NS", "ns1.example.cz."));

    // A and AAAA still drop what they were meant to drop: the hostname
    // lines dig emits for a CNAME chain, which a caller comparing
    // against an IP must not see.
    assert!(keeps("A", "192.0.2.10"));
    assert!(!keeps("A", "alias.example.cz."));
    assert!(
        !keeps("A", "2001:db8::1"),
        "an AAAA answer is not an A answer"
    );
    assert!(keeps("AAAA", "2001:db8::1"));
    assert!(!keeps("AAAA", "192.0.2.10"));
    // Blank lines are never an answer.
    assert!(!keeps("TXT", "   "));
}
