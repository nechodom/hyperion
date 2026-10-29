//! Tests for `service::backups`.

use super::*;

#[test]
fn backup_cadence_and_due_logic() {
    use super::{backup_cadence_secs, backup_due, canonical_backup_cadence};
    // Canonicalisation: only the four known values survive.
    assert_eq!(canonical_backup_cadence("weekly"), "weekly");
    assert_eq!(canonical_backup_cadence("  daily "), "daily");
    assert_eq!(canonical_backup_cadence("hourly"), "off");
    assert_eq!(canonical_backup_cadence(""), "off");
    // off / unknown never schedule.
    assert_eq!(backup_cadence_secs("off"), None);
    assert_eq!(backup_cadence_secs("nonsense"), None);
    assert_eq!(backup_cadence_secs("daily"), Some(86_400));
    assert_eq!(backup_cadence_secs("monthly"), Some(30 * 86_400));
    // Never-run (0) is always due; just-run is not; a full cadence later is.
    assert!(backup_due(86_400, 0, 1_700_000_000));
    assert!(!backup_due(86_400, 1_700_000_000, 1_700_000_000 + 100));
    assert!(backup_due(86_400, 1_700_000_000, 1_700_000_000 + 86_400));
}

#[test]
fn backup_at_parses_hh_mm_only() {
    use super::parse_backup_at;
    assert_eq!(parse_backup_at("03:00"), Some(180));
    assert_eq!(parse_backup_at(" 3:05 "), Some(185));
    assert_eq!(parse_backup_at("23:59"), Some(23 * 60 + 59));
    assert_eq!(parse_backup_at("24:00"), None);
    assert_eq!(parse_backup_at("12:60"), None);
    assert_eq!(parse_backup_at("12:5"), None);
    assert_eq!(parse_backup_at(""), None);
    assert_eq!(parse_backup_at("noon"), None);
}

#[test]
fn backup_due_at_holds_the_time_of_day() {
    use super::backup_due_at;
    use chrono::{FixedOffset, TimeZone};
    // Prague summer time, so a UTC-only implementation would be 2h off.
    let tz = FixedOffset::east_opt(2 * 3600).unwrap();
    let at = |d: u32, h: u32, m: u32| {
        tz.with_ymd_and_hms(2026, 10, d, h, m, 0)
            .unwrap()
            .timestamp()
    };
    let three = Some(3 * 60);
    // No time set: plain elapsed rule, never-run is due at once.
    assert!(backup_due_at(&tz, 86_400, 0, at(8, 12, 0), None));
    // Never ran: only from 03:00 for the grace window, not at noon.
    assert!(!backup_due_at(&tz, 86_400, 0, at(8, 2, 55), three));
    assert!(backup_due_at(&tz, 86_400, 0, at(8, 3, 0), three));
    assert!(backup_due_at(&tz, 86_400, 0, at(8, 4, 30), three));
    assert!(!backup_due_at(&tz, 86_400, 0, at(8, 12, 0), three));
    // Daily, ran 03:04 on the 8th: next is 03:00 on the 9th, not 03:04.
    assert!(!backup_due_at(
        &tz,
        86_400,
        at(8, 3, 4),
        at(9, 2, 59),
        three
    ));
    assert!(backup_due_at(&tz, 86_400, at(8, 3, 4), at(9, 3, 0), three));
    // A late catch-up (ran 17:00) snaps back to 03:00 the next day.
    assert!(!backup_due_at(
        &tz,
        86_400,
        at(8, 17, 0),
        at(8, 23, 0),
        three
    ));
    assert!(backup_due_at(&tz, 86_400, at(8, 17, 0), at(9, 3, 0), three));
    // Every 3 days counts calendar days from the last run.
    assert!(!backup_due_at(
        &tz,
        3 * 86_400,
        at(8, 3, 0),
        at(10, 3, 0),
        three
    ));
    assert!(backup_due_at(
        &tz,
        3 * 86_400,
        at(8, 3, 0),
        at(11, 3, 0),
        three
    ));
    // Node down past the slot: due on the next tick, whenever that is.
    assert!(backup_due_at(
        &tz,
        86_400,
        at(8, 3, 0),
        at(10, 14, 0),
        three
    ));
}

/// Pre-update backups live by their own rule: a site keeps ONE (every run
/// older than the newest successful one goes, held or not), a clean one goes
/// at its `delete_at` — 24 hours after its updates — a held one never by age,
/// and none of them is one of the site's newest N, so a nightly update batch
/// cannot push a real scheduled backup past the floor.
#[tokio::test]
async fn prune_gives_pre_update_backups_their_own_retention() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let mut s = svc(pool.clone(), happy_mocks());
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(
        &cfg,
        "[backup_retention]\nmax_age_days = 30\nkeep_latest_n = 2\n",
    )
    .expect("cfg");
    s.agent_config_path = Some(cfg);
    s.create(req("pre.cz")).await.expect("create");
    let detail = s
        .get(HostingSelector::Domain(Domain::parse("pre.cz").unwrap()))
        .await
        .expect("get");
    let hour = 3_600;
    let day = 24 * hour;
    let now = now_secs();
    // A run started `age` seconds ago: ok (or failed), with a purpose.
    let mk = |age: i64, purpose: &'static str, held: bool, ok: bool| {
        let pool = pool.clone();
        let id = detail.id.clone();
        async move {
            let at = now - age;
            let r = backups::start(&pool, &id, "local", at)
                .await
                .expect("start");
            if ok {
                backups::mark_ok(
                    &pool,
                    r,
                    &format!("/nonexistent/pre.cz-{at}.tar.gz"),
                    None,
                    1,
                    at + 1,
                )
                .await
                .expect("ok");
            } else {
                backups::mark_failed(&pool, r, "disk full", at + 1)
                    .await
                    .expect("failed");
            }
            if !purpose.is_empty() {
                backups::set_purpose(&pool, r, purpose, held)
                    .await
                    .expect("purpose");
            }
            r
        }
    };
    let left = || {
        let pool = pool.clone();
        let id = detail.id.clone();
        async move {
            backups::list_for(&pool, &id, 100)
                .await
                .expect("list")
                .into_iter()
                .map(|r| r.id)
                .collect::<std::collections::HashSet<i64>>()
        }
    };
    let pu = backups::PURPOSE_PRE_UPDATE;
    let failed_new = mk(hour, pu, false, false).await;
    let current = mk(2 * hour, pu, true, true).await;
    backups::release_pre_update(&pool, current, now + hour)
        .await
        .expect("release");
    let older_held = mk(3 * day, pu, true, true).await;
    let older_clean = mk(5 * day, pu, false, true).await;
    let ord_a = mk(40 * day, "", false, true).await;
    let ord_b = mk(41 * day, "", false, true).await;
    let ord_c = mk(42 * day, "", false, true).await;

    let pruned = s.prune_old_backups(&detail.id).await.expect("prune");
    let kept = left().await;
    assert_eq!(pruned, 3, "left: {kept:?}");
    assert!(kept.contains(&current), "the newest one, before its delete_at");
    assert!(kept.contains(&failed_new), "a failed run is listed for 24h");
    assert!(!kept.contains(&older_held), "only one is kept, held or not");
    assert!(!kept.contains(&older_clean), "only one is kept");
    assert!(
        kept.contains(&ord_a) && kept.contains(&ord_b),
        "the newest 2 ORDINARY backups"
    );
    assert!(!kept.contains(&ord_c), "third ordinary, past 30 days");

    // The list says when it goes.
    let row = backups::get_by_id(&pool, current)
        .await
        .expect("get")
        .expect("row");
    assert!(row.is_pre_update() && !row.held);
    assert_eq!(row.pre_update_delete_at(), Some(now + hour));

    // Past its delete_at, the expiry sweep takes it — and only it: an
    // ordinary backup past the age rule waits for the site's next backup.
    let ord_d = mk(50 * day, "", false, true).await;
    backups::release_pre_update(&pool, current, now - 1)
        .await
        .expect("release past");
    assert_eq!(s.pre_update_backups_expire_tick().await.expect("tick"), 1);
    let kept = left().await;
    assert!(!kept.contains(&current), "deleted at its delete_at");
    assert!(kept.contains(&ord_d), "the sweep leaves ordinary backups alone");
    assert!(kept.contains(&failed_new), "still inside its 24h");

    // The newest one held: never by age.
    let held = mk(100 * day, pu, true, true).await;
    assert_eq!(s.prune_pre_update_backups(&detail.id).await.expect("held"), 0);
    assert!(left().await.contains(&held));
}

/// A pre-update row released before `delete_at` existed (0) goes 24 hours
/// after it finished; a failed run 24 hours after it started.
#[test]
fn pre_update_delete_at_falls_back_to_finish_plus_a_day() {
    use hyperion_state::backups::{BackupRun, PRE_UPDATE_KEEP_SECS, PURPOSE_PRE_UPDATE};
    let base = BackupRun {
        started_at: 1_000,
        finished_at: Some(1_500),
        purpose: PURPOSE_PRE_UPDATE.into(),
        ..super::bk_run(1, "ok", true, "", true)
    };
    assert_eq!(base.pre_update_delete_at(), Some(1_500 + PRE_UPDATE_KEEP_SECS));
    let set = BackupRun { delete_at: 9_999, ..base.clone() };
    assert_eq!(set.pre_update_delete_at(), Some(9_999));
    let held = BackupRun { held: true, ..base.clone() };
    assert_eq!(held.pre_update_delete_at(), None);
    let failed = BackupRun { state: "failed".into(), held: true, ..base.clone() };
    assert_eq!(failed.pre_update_delete_at(), Some(1_000 + PRE_UPDATE_KEEP_SECS));
    let running = BackupRun { state: "running".into(), ..base.clone() };
    assert_eq!(running.pre_update_delete_at(), None);
    let ordinary = BackupRun { purpose: String::new(), ..base };
    assert_eq!(ordinary.pre_update_delete_at(), None);
}

/// The Backups card's reason comes from the OWNING node's policy: with the
/// option off (the default — no agent.toml here), an off-site copy that is
/// still local says so; a local-only or dropped one says nothing.
#[tokio::test]
async fn backup_list_says_why_an_offsite_copy_is_still_local() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("why.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("why.cz").unwrap());
    let detail = s.get(sel.clone()).await.expect("get");

    let mk = |at: i64, path: &'static str| {
        let pool = pool.clone();
        let id = detail.id.clone();
        async move {
            let r = backups::start(&pool, &id, "local", at)
                .await
                .expect("start");
            backups::mark_ok(&pool, r, path, None, 10, at + 1)
                .await
                .expect("ok");
            r
        }
    };
    let verified = mk(300, "/b/why.cz-300.tar.gz").await;
    backups::set_remote(&pool, verified, "ftp://v/why.cz-300.tar.gz", "verified", "")
        .await
        .expect("remote");
    let local_only = mk(200, "/b/why.cz-200.tar.gz").await;
    let dropped = mk(100, "/b/why.cz-100.tar.gz").await;
    backups::set_remote(&pool, dropped, "ftp://v/why.cz-100.tar.gz", "verified", "")
        .await
        .expect("remote2");
    backups::clear_local_paths(&pool, dropped)
        .await
        .expect("clear");

    let list = s.backup_list(sel, 10).await.expect("list");
    let by = |id: i64| list.iter().find(|b| b.id == id).expect("row");
    assert_eq!(by(verified).local_kept, "setting_off");
    assert!(!by(verified).local_note.is_empty());
    assert_eq!(by(local_only).local_kept, "");
    assert_eq!(by(dropped).local_kept, "");
}

#[tokio::test]
async fn offsite_pin_round_trips_through_the_key_the_panel_writes() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let detail = s
        .get(HostingSelector::Domain(
            Domain::parse("example.cz").expect("parse"),
        ))
        .await
        .expect("get");
    let hid = detail.id.as_str().to_string();

    // Fresh site: unpinned. A hosting that existed before this key did
    // reads the same way, which is what keeps upgrades behaviour-neutral.
    assert_eq!(s.offsite_pin(&hid).await, None);

    // The panel pins by dispatching the generic kv setter to the owner.
    s.hosting_kv_set(hid.clone(), BACKUP_KV_TARGET.into(), "wasabi-eu".into())
        .await
        .expect("pin");
    assert_eq!(s.offsite_pin(&hid).await.as_deref(), Some("wasabi-eu"));

    // "Node default" posts an empty value — that's an unpin, not a target.
    s.hosting_kv_set(hid.clone(), BACKUP_KV_TARGET.into(), String::new())
        .await
        .expect("unpin");
    assert_eq!(s.offsite_pin(&hid).await, None);
}

/// Whatever this returns is executed as the database superuser, and it is
/// read out of a directory the site's own unix user can write to.
#[tokio::test]
async fn a_planted_symlink_is_never_taken_for_the_restored_dump() {
    let dir = std::env::temp_dir().join(format!("hyp-dump-{}", now_secs()));
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir).await.expect("mkdir");

    // Nothing there yet.
    assert!(find_restored_dump(&dir).await.is_none());

    // A symlink the tenant could have planted, pointing at a file that
    // really exists — so a `metadata().is_file()` check would follow it
    // and pass.
    let elsewhere = dir.join("attacker.sql.real");
    tokio::fs::write(&elsewhere, b"DROP DATABASE hyperion;")
        .await
        .expect("write");
    std::os::unix::fs::symlink(&elsewhere, dir.join("aaa.sql")).expect("symlink");
    assert!(
        find_restored_dump(&dir).await.is_none(),
        "a symlink must never be handed to the database superuser"
    );

    // A real dump is found.
    let real = dir.join("zzz.sql");
    tokio::fs::write(&real, b"-- dump").await.expect("write");
    assert_eq!(find_restored_dump(&dir).await, Some(real));
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// A restored dump that is NOT owned by root is refused before import. The
/// snapshot restore stages inside the tenant-owned site directory, so the
/// dump path is briefly swappable; a file the tenant planted there carries
/// the tenant's uid, and importing it would run their SQL as the database
/// superuser. The test writes the file as the (non-root) test user, which
/// is exactly the tenant-planted case.
#[tokio::test]
async fn a_non_root_owned_restored_dump_is_refused() {
    let dir = std::env::temp_dir().join(format!("lm-dump-owner-{}", std::process::id()));
    tokio::fs::create_dir_all(&dir).await.expect("mkdir");
    let planted = dir.join("evil.sql");
    tokio::fs::write(&planted, b"GRANT ALL ON *.* TO 'attacker'@'%';")
        .await
        .expect("write");
    let err = open_root_owned_dump(&planted)
        .await
        .expect_err("a non-root-owned dump must be refused");
    assert!(
        err.contains("root-owned"),
        "the refusal must name the ownership check: {err}"
    );
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// A care package that sells a CUSTOM schedule + retention seeds all four
/// kv keys on activate, captures the site's prior values, and puts them
/// back on cancel — the same contract profiles got in migration 070, but
/// enforced continuously and restore-aware.
#[tokio::test]
async fn custom_cadence_and_retention_apply_and_restore() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    let detail = hosting_for_packages(&s, "example.cz").await;
    let hid = detail.id.as_str().to_string();
    // What the customer had before buying: a weekly schedule and a
    // 14-day retention floor they set themselves; no keep-last override.
    s.hosting_kv_set(hid.clone(), BACKUP_KV_CADENCE.into(), "weekly".into())
        .await
        .expect("seed cadence");
    s.hosting_kv_set(hid.clone(), BACKUP_KV_KEEP_DAYS.into(), "14".into())
        .await
        .expect("seed keep_days");

    let def = s
        .package_create(care_input(
            "Zálohy Pro",
            PackageFeatures {
                backup_cadence: BackupCadence::Custom,
                backup_interval_days: 3,
                backup_keep_days: 90,
                backup_keep_last: 8,
                ..Default::default()
            },
        ))
        .await
        .expect("define");
    let sel = HostingSelector::Id(detail.id.clone());
    let act = s
        .package_activate(sel.clone(), def.id, None, None)
        .await
        .expect("activate");

    // All four keys are seeded — this is exactly what the scheduler and
    // the prune sweep read.
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_CADENCE).await.as_deref(),
        Some("custom")
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_INTERVAL_DAYS).await.as_deref(),
        Some("3")
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_KEEP_DAYS).await.as_deref(),
        Some("90")
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_KEEP_LAST).await.as_deref(),
        Some("8")
    );

    // Prior state carries the site's values, captured because the package
    // forces backups — so a cancel can put every one of them back.
    let prior: PackagePriorState =
        serde_json::from_str(&act.prior_state_json.expect("captured")).expect("de");
    assert_eq!(prior.backup_cadence, Some(BackupCadence::Weekly));
    assert_eq!(prior.backup_interval_days, Some(0));
    assert_eq!(prior.backup_keep_days, Some(14));
    assert_eq!(prior.backup_keep_last, Some(0));

    // Someone weakens the retention by hand; the drift tick puts it back
    // and touches nothing else.
    s.hosting_kv_set(hid.clone(), BACKUP_KV_KEEP_DAYS.into(), "5".into())
        .await
        .expect("drift");
    assert_eq!(s.package_enforce_tick().await.expect("tick"), 1);
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_KEEP_DAYS).await.as_deref(),
        Some("90"),
        "the tick re-asserts the paid retention"
    );

    // Cancel restores the site to exactly what it had before.
    s.package_cancel(sel, act.id).await.expect("cancel");
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_CADENCE).await.as_deref(),
        Some("weekly")
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_INTERVAL_DAYS).await.as_deref(),
        Some("0")
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_KEEP_DAYS).await.as_deref(),
        Some("14"),
        "the customer's own retention comes back, not the package's"
    );
    assert_eq!(
        kv_of(&pool, &hid, BACKUP_KV_KEEP_LAST).await.as_deref(),
        Some("0")
    );
}
