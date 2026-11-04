//! Tests for `service::trash`.

use super::*;

/// Regression: deleting with trash ENABLED leaves the row as
/// state='trashed' (still holding the domain under UNIQUE), and
/// the create wizard's preflight filters trashed rows out — so
/// re-creating the exact same domain used to fail with a cryptic
/// "entity already exists … UNIQUE constraint failed" even though
/// the hosting was gone from the operator's list. Create must now
/// reclaim the slot: purge the trashed row, then provision fresh.
#[tokio::test]
async fn create_reclaims_trashed_domain() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("reclaim.cz")).await.expect("first create");
    // Simulate the trash path without going through delete()'s
    // config gate: flip the row to trashed in place.
    let row = hostings::get_by_domain(&pool, "reclaim.cz")
        .await
        .expect("query")
        .expect("row exists");
    hostings::mark_trashed(&pool, &row.id, now_secs())
        .await
        .expect("mark trashed");
    // Fresh mock covering BOTH the purge teardown of the trashed
    // row AND a clean re-provision.
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost().returning(|_| Ok(()));
    a.expect_redis_is_available().returning(|| true);
    // Purge teardown:
    // A trashed row with no login record is one an older version trashed
    // (password lock only), and the purge gives the user its password
    // back in case the account outlives the hosting.
    a.expect_linux_unlock_login().returning(|_| Ok(()));
    a.expect_nginx_delete_vhost().returning(|_, _| Ok(()));
    a.expect_acme_delete().returning(|_| Ok(()));
    a.expect_db_drop().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_remove_hosting_tree().returning(|_| Ok(()));
    // The teardown now stops the site's processes before userdel. Without
    // it userdel exits 8 ("user is currently used by process") for as long
    // as a single PHP-FPM worker lives, the failure was swallowed, and the
    // Linux user outlived the hosting whose DB row had already gone.
    a.expect_kill_user_procs().returning(|_| Ok(()));
    a.expect_delete_user().returning(|_| Ok(()));
    let s2 = svc(pool.clone(), a);
    let created = s2
        .create(req("reclaim.cz"))
        .await
        .expect("reclaim create ok");
    assert!(created.db.is_some());
    let detail = s2
        .get(HostingSelector::Domain(
            Domain::parse("reclaim.cz").expect("parse"),
        ))
        .await
        .expect("get");
    assert_eq!(detail.state, HostingState::Active);
    // Exactly one row for the domain — the old trashed one is gone.
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM hostings WHERE domain = ?")
        .bind("reclaim.cz")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count.0, 1);
}

/// A restore must not be undone by the expiry actions that fell due while
/// the site was in the trash.
#[tokio::test]
async fn restore_from_trash_does_not_replay_what_fell_due_meanwhile() {
    use hyperion_state::scheduler::{self, ScheduledKind};
    let pool = open_memory().await.expect("open");
    let mut mocks = package_mocks();
    mocks.expect_linux_unlock_login().returning(|_| Ok(()));
    mocks.expect_db_unlock().returning(|_, _| Ok(()));
    let s = svc(pool.clone(), mocks);
    let site = hosting_for_packages(&s, "kos.cz").await;
    let now = now_secs();
    scheduler::upsert(
        &pool,
        &site.id,
        ScheduledKind::DeleteExpired,
        now - 86_400,
        1,
    )
    .await
    .expect("overdue delete");
    scheduler::upsert(&pool, &site.id, ScheduledKind::Notify7d, now + 86_400, 1)
        .await
        .expect("future notice");
    hyperion_state::hostings::mark_trashed(&pool, &site.id, now - 2 * 86_400)
        .await
        .expect("trash");

    s.restore_from_trash(HostingSelector::Id(site.id.clone()))
        .await
        .expect("restore");

    assert!(
        scheduler::pending_due(&pool, now + 60, 10)
            .await
            .expect("due")
            .is_empty(),
        "the delete that fell due in the trash must not run on the restored site"
    );
    let later = scheduler::pending_due(&pool, now + 2 * 86_400, 10)
        .await
        .expect("later");
    assert_eq!(later.len(), 1, "a future warning stays armed: {later:?}");
    assert_eq!(later[0].action, ScheduledKind::Notify7d);
}

/// Mocks for creating sites and tearing them down, with no expectation on
/// the two things a delete can be told to keep.
fn create_and_teardown_mocks() -> MockAdapterPort {
    let mut a = happy_mocks_many();
    a.expect_nginx_delete_vhost().returning(|_, _| Ok(()));
    a.expect_acme_delete().returning(|_| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_remove_hosting_tree().returning(|_| Ok(()));
    a.expect_kill_user_procs().returning(|_| Ok(()));
    a.expect_linux_unlock_login().returning(|_| Ok(()));
    a.expect_linux_login_expiry()
        .returning(|_| Ok(Some(String::new())));
    a.expect_linux_set_login_expiry().returning(|_, _| Ok(()));
    a
}

/// `service` reading an agent.toml with the trash switched on.
fn with_trash_on(
    service: HostingService<MockAdapterPort>,
) -> (HostingService<MockAdapterPort>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(&cfg, "[cluster]\ntrash_enabled = true\n").expect("write agent.toml");
    (service.with_agent_config_path(cfg), dir)
}

/// What a site's life leaves in the tables no foreign key cleans up.
async fn plant_site_leftovers(pool: &sqlx::SqlitePool, id: &HostingId) {
    let id = id.as_str();
    for key in ["notes", "gitsync_repo"] {
        hyperion_state::hosting_kv::set(pool, id, key, "x", now_secs())
            .await
            .expect("kv");
    }
    for sql in [
        "INSERT INTO waf_hits_hourly (hosting_id, hour, rule, hits) VALUES (?, 1, 'sqli', 1)",
        "INSERT INTO waf_recent (hosting_id, ts, ip, rule, method, uri, ua) \
         VALUES (?, 1, '192.0.2.1', 'sqli', 'GET', '/', 'ua')",
        "INSERT INTO waf_ip_minute (hosting_id, ip, minute, hits) VALUES (?, '192.0.2.1', 1, 1)",
    ] {
        sqlx::query(sql).bind(id).execute(pool).await.expect("waf");
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SiteResidue {
    kv_rows: i64,
    waf_rows: i64,
    purge_audits: usize,
}

/// A clean hard delete: nothing left behind, and one audit entry saying so.
/// That entry is written last, so it also proves the pipeline ran to its end.
const PURGED: SiteResidue = SiteResidue {
    kv_rows: 0,
    waf_rows: 0,
    purge_audits: 1,
};

async fn site_residue(pool: &sqlx::SqlitePool, id: &HostingId) -> SiteResidue {
    let id = id.as_str();
    let count = |sql: &'static str| async move {
        let (n,): (i64,) = sqlx::query_as(sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("count");
        n
    };
    let waf_rows = count("SELECT COUNT(*) FROM waf_hits_hourly WHERE hosting_id = ?").await
        + count("SELECT COUNT(*) FROM waf_recent WHERE hosting_id = ?").await
        + count("SELECT COUNT(*) FROM waf_ip_minute WHERE hosting_id = ?").await;
    let purge_audits = hyperion_state::audit::list(pool, 1000)
        .await
        .expect("audit")
        .iter()
        .filter(|e| e.action == "hosting.purge" && e.target.as_deref() == Some(id))
        .count();
    SiteResidue {
        kv_rows: count("SELECT COUNT(*) FROM hosting_kv WHERE hosting_id = ?").await,
        waf_rows,
        purge_audits,
    }
}

/// Deleting with the trash off is the same end as a purge, reached sooner.
/// The two used to be separate pipelines, and the delete one kept the site's
/// settings, WAF history and (where no test can see them, under fixed
/// root-owned paths) its snapshots, DKIM keys and git deploy secrets.
#[tokio::test]
async fn delete_with_the_trash_off_removes_what_a_purge_removes() {
    let pool = open_memory().await.expect("open");
    let mut mocks = create_and_teardown_mocks();
    mocks.expect_db_drop().returning(|_, _, _| Ok(()));
    mocks.expect_delete_user().returning(|_| Ok(()));
    let s = svc(pool.clone(), mocks);

    let purged = s.create(req("purged.cz")).await.expect("create");
    plant_site_leftovers(&pool, &purged.id).await;
    hostings::mark_trashed(&pool, &purged.id, now_secs())
        .await
        .expect("mark trashed");
    s.purge_from_trash(HostingSelector::Id(purged.id.clone()))
        .await
        .expect("purge");

    let deleted = s.create(req("deleted.cz")).await.expect("create");
    plant_site_leftovers(&pool, &deleted.id).await;
    s.delete(
        HostingSelector::Id(deleted.id.clone()),
        DeleteOpts::default(),
    )
    .await
    .expect("delete");

    assert_eq!(site_residue(&pool, &purged.id).await, PURGED);
    assert_eq!(site_residue(&pool, &deleted.id).await, PURGED);
}

/// The Core Rule Set costs memory in every nginx process, so the last site
/// using it unloads it however that site goes.
#[tokio::test]
async fn delete_with_the_trash_off_unloads_the_rule_set_with_its_last_site() {
    let pool = open_memory().await.expect("open");
    let mut mocks = create_and_teardown_mocks();
    mocks.expect_db_drop().returning(|_, _, _| Ok(()));
    mocks.expect_delete_user().returning(|_| Ok(()));
    mocks.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    mocks.expect_modsec_status().returning(|| engine(true));
    let syncs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<bool>::new()));
    let seen = syncs.clone();
    mocks.expect_modsec_sync_http().returning(move |need| {
        seen.lock().expect("lock").push(need);
        Ok(true)
    });
    let s = svc(pool.clone(), mocks);
    s.create(req("crs.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("crs.cz").expect("parse"));
    let mut on = vh_defaults();
    on.crs_mode = "block".into();
    on.crs_paranoia = 2;
    s.set_vhost_options(sel.clone(), on, None)
        .await
        .expect("turn CRS on");
    assert_eq!(syncs.lock().expect("lock").last(), Some(&true));

    s.delete(sel, DeleteOpts::default()).await.expect("delete");

    assert_eq!(syncs.lock().expect("lock").last(), Some(&false));
}

/// The keep flags hard-delete even with the trash on, and spare exactly what
/// they name: everything else of the site still goes.
#[tokio::test]
async fn delete_keeping_user_and_database_removes_everything_else() {
    let pool = open_memory().await.expect("open");
    let mut mocks = create_and_teardown_mocks();
    mocks.expect_db_drop().times(0);
    mocks.expect_delete_user().times(0);
    let (s, _dir) = with_trash_on(svc(pool.clone(), mocks));
    let site = s.create(req("kept.cz")).await.expect("create");
    plant_site_leftovers(&pool, &site.id).await;
    let user = s
        .get(HostingSelector::Id(site.id.clone()))
        .await
        .expect("get")
        .system_user;

    s.delete(
        HostingSelector::Id(site.id.clone()),
        DeleteOpts {
            keep_user: true,
            keep_database: true,
            delete_offsite_backups: false,
            delete_local_backups: false,
        },
    )
    .await
    .expect("delete");

    assert!(hostings::get_by_domain(&pool, "kept.cz")
        .await
        .expect("query")
        .is_none());
    assert!(
        system_users::get_by_name(&pool, user.as_str())
            .await
            .expect("query")
            .is_some(),
        "the kept user stays on record"
    );
    assert_eq!(site_residue(&pool, &site.id).await, PURGED);
}

/// Undoing a site that never went live is a hard delete whatever the trash
/// setting, and leaves nothing behind either.
#[tokio::test]
async fn roll_back_created_is_a_full_hard_delete_with_the_trash_on() {
    let pool = open_memory().await.expect("open");
    let mut mocks = create_and_teardown_mocks();
    mocks.expect_db_drop().times(1).returning(|_, _, _| Ok(()));
    mocks.expect_delete_user().times(1).returning(|_| Ok(()));
    let (s, _dir) = with_trash_on(svc(pool.clone(), mocks));
    let site = s.create(req("half.cz")).await.expect("create");
    plant_site_leftovers(&pool, &site.id).await;

    s.roll_back_created(&site.id).await;

    assert!(hostings::get_by_domain(&pool, "half.cz")
        .await
        .expect("query")
        .is_none());
    assert_eq!(site_residue(&pool, &site.id).await, PURGED);
}

/// A service whose backup directory is a temp dir the test can look into.
fn with_backup_root(
    service: HostingService<MockAdapterPort>,
) -> (HostingService<MockAdapterPort>, tempfile::TempDir) {
    let root = tempfile::tempdir().expect("tmp");
    let paths = HostingPaths {
        backup_root: root.path().display().to_string(),
        ..HostingPaths::default()
    };
    (service.with_paths(paths), root)
}

/// One finished local backup of a site: its archive, dump and manifest, and
/// the row naming the first two. Returns all three paths.
async fn recorded_backup(
    pool: &sqlx::SqlitePool,
    root: &std::path::Path,
    site: &HostingId,
    user: &str,
    domain: &str,
    ts: i64,
) -> Vec<std::path::PathBuf> {
    let dir = root.join(user);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let files: Vec<_> = ["tar.gz", "sql", "manifest.json"]
        .iter()
        .map(|ext| dir.join(format!("{domain}-{ts}.{ext}")))
        .collect();
    for f in &files {
        std::fs::write(f, "x").expect("write");
    }
    let run = hyperion_state::backups::start(pool, site, "local", ts)
        .await
        .expect("start");
    hyperion_state::backups::mark_ok(
        pool,
        run,
        files[0].to_str().expect("utf8"),
        Some(files[1].to_str().expect("utf8")),
        1,
        ts,
    )
    .await
    .expect("mark ok");
    files
}

fn delete_local() -> DeleteOpts {
    DeleteOpts {
        delete_local_backups: true,
        ..DeleteOpts::default()
    }
}

fn hard_delete_mocks() -> MockAdapterPort {
    let mut mocks = create_and_teardown_mocks();
    mocks.expect_db_drop().returning(|_, _, _| Ok(()));
    mocks.expect_delete_user().returning(|_| Ok(()));
    mocks
}

/// Hard delete, trash on: what moving to the trash and restoring also need.
fn trash_cycle_mocks() -> MockAdapterPort {
    let mut mocks = hard_delete_mocks();
    mocks
        .expect_nginx_apply_suspended()
        .returning(|_, _, _| Ok(()));
    mocks.expect_db_lock().returning(|_, _| Ok(()));
    mocks.expect_db_unlock().returning(|_, _| Ok(()));
    mocks.expect_linux_lock_login().returning(|_| Ok(()));
    mocks
        .expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    mocks
}

/// Local archives can be the last copy of a site, so nothing removes them
/// unless the operator asked.
#[tokio::test]
async fn delete_without_the_opt_in_keeps_local_backups() {
    let pool = open_memory().await.expect("open");
    let (s, root) = with_backup_root(svc(pool.clone(), hard_delete_mocks()));
    let site = s.create(req("kept-copy.cz")).await.expect("create");
    let user = s
        .get(HostingSelector::Id(site.id.clone()))
        .await
        .expect("get")
        .system_user;
    let files = recorded_backup(
        &pool,
        root.path(),
        &site.id,
        user.as_str(),
        "kept-copy.cz",
        100,
    )
    .await;

    s.delete(HostingSelector::Id(site.id.clone()), DeleteOpts::default())
        .await
        .expect("delete");

    assert!(files.iter().all(|f| f.exists()), "{files:?}");
}

/// With the box ticked, everything of this site goes, whether or not a row
/// names it; nothing of anybody else's does, even in the same directory.
#[tokio::test]
async fn delete_with_the_opt_in_removes_only_this_sites_local_backups() {
    let pool = open_memory().await.expect("open");
    let (s, root) = with_backup_root(svc(pool.clone(), hard_delete_mocks()));
    let site = s.create(req("gone.cz")).await.expect("create");
    let sel = HostingSelector::Id(site.id.clone());
    let user = s.get(sel.clone()).await.expect("get").system_user;
    let dir = root.path().join(user.as_str());
    let mut ours =
        recorded_backup(&pool, root.path(), &site.id, user.as_str(), "gone.cz", 100).await;
    ours.push(dir.join("gone.cz-50.tar.gz"));
    let other_users_dir = root.path().join("former-user");
    std::fs::create_dir_all(&other_users_dir).expect("mkdir");
    ours.push(other_users_dir.join("gone.cz-40.sql"));
    let theirs = [
        dir.join("sibling.cz-100.tar.gz"),
        dir.join("gone.cz-shop.cz-100.tar.gz"),
        dir.join("gone.cz-notes.txt"),
    ];
    for f in ours.iter().chain(&theirs) {
        std::fs::write(f, "x").expect("write");
    }

    s.delete(sel, delete_local()).await.expect("delete");

    let left: Vec<_> = ours.iter().filter(|f| f.exists()).collect();
    assert!(left.is_empty(), "left behind: {left:?}");
    for f in &theirs {
        assert!(f.exists(), "not this site's: {}", f.display());
    }
    let audited = hyperion_state::audit::list(&pool, 100)
        .await
        .expect("audit")
        .into_iter()
        .any(|e| {
            e.action == "hosting.backup.local_delete_all"
                && e.target.as_deref() == Some(site.id.as_str())
                && e.result == "ok"
        });
    assert!(audited, "removing backups must leave a trace");
}

/// The trash is where a change of mind still costs nothing, so the files
/// wait for the purge, and the trash list says they are going.
#[tokio::test]
async fn the_opt_in_waits_for_the_purge_when_the_trash_is_on() {
    let pool = open_memory().await.expect("open");
    let (s, _dir) = with_trash_on(svc(pool.clone(), trash_cycle_mocks()));
    let (s, root) = with_backup_root(s);
    let site = s.create(req("later.cz")).await.expect("create");
    let sel = HostingSelector::Id(site.id.clone());
    let user = s.get(sel.clone()).await.expect("get").system_user;
    let files = recorded_backup(&pool, root.path(), &site.id, user.as_str(), "later.cz", 100).await;

    s.delete(sel.clone(), delete_local()).await.expect("trash");

    assert!(files.iter().all(|f| f.exists()), "still in the trash");
    assert!(s.list_trash().await.expect("list")[0].delete_local_backups);

    s.purge_from_trash(sel).await.expect("purge");
    let left: Vec<_> = files.iter().filter(|f| f.exists()).collect();
    assert!(left.is_empty(), "left behind: {left:?}");
}

/// Restoring takes the choice back: a later purge asks nothing of the files.
#[tokio::test]
async fn restoring_from_the_trash_forgets_the_opt_in() {
    let pool = open_memory().await.expect("open");
    let (s, _dir) = with_trash_on(svc(pool.clone(), trash_cycle_mocks()));
    let (s, root) = with_backup_root(s);
    let site = s.create(req("back.cz")).await.expect("create");
    let sel = HostingSelector::Id(site.id.clone());
    let user = s.get(sel.clone()).await.expect("get").system_user;
    let files = recorded_backup(&pool, root.path(), &site.id, user.as_str(), "back.cz", 100).await;

    s.delete(sel.clone(), delete_local()).await.expect("trash");
    s.restore_from_trash(sel.clone()).await.expect("restore");
    s.delete(sel.clone(), DeleteOpts::default())
        .await
        .expect("trash again");

    assert!(!s.list_trash().await.expect("list")[0].delete_local_backups);
    s.purge_from_trash(sel).await.expect("purge");
    assert!(files.iter().all(|f| f.exists()), "{files:?}");
}

/// A run in progress has files no row names yet, and would finish after the
/// delete: the promise to remove everything could not be kept.
#[tokio::test]
async fn the_opt_in_refuses_while_a_backup_is_running_and_leaves_the_site() {
    let pool = open_memory().await.expect("open");
    let (s, root) = with_backup_root(svc(pool.clone(), hard_delete_mocks()));
    let site = s.create(req("busy.cz")).await.expect("create");
    let sel = HostingSelector::Id(site.id.clone());
    let user = s.get(sel.clone()).await.expect("get").system_user;
    let files = recorded_backup(&pool, root.path(), &site.id, user.as_str(), "busy.cz", 100).await;
    hyperion_state::backups::start(&pool, &site.id, "local", 200)
        .await
        .expect("running");

    let err = s
        .delete(sel.clone(), delete_local())
        .await
        .expect_err("refused");

    assert!(matches!(err, RpcError::Conflict { .. }), "{err:?}");
    assert_eq!(
        s.get(sel).await.expect("still there").state,
        HostingState::Active
    );
    assert!(files.iter().all(|f| f.exists()), "{files:?}");
}

/// A restore or a push reading an archive keeps it, and so keeps the site:
/// nothing has been removed by the time the answer is no.
#[tokio::test]
async fn the_opt_in_refuses_while_an_archive_is_in_use_and_removes_nothing() {
    let pool = open_memory().await.expect("open");
    let (s, root) = with_backup_root(svc(pool.clone(), hard_delete_mocks()));
    let site = s.create(req("read.cz")).await.expect("create");
    let sel = HostingSelector::Id(site.id.clone());
    let user = s.get(sel.clone()).await.expect("get").system_user;
    let older = recorded_backup(&pool, root.path(), &site.id, user.as_str(), "read.cz", 100).await;
    let newer = recorded_backup(&pool, root.path(), &site.id, user.as_str(), "read.cz", 200).await;
    let _reading = ArchiveInUse::try_claim(&newer[0]).expect("claim");

    let err = s
        .delete(sel.clone(), delete_local())
        .await
        .expect_err("refused");

    assert!(matches!(err, RpcError::Conflict { .. }), "{err:?}");
    assert_eq!(
        s.get(sel).await.expect("still there").state,
        HostingState::Active
    );
    let left = older.iter().chain(&newer).all(|f| f.exists());
    assert!(left, "a refusal must remove nothing");
}

/// A file that cannot be removed fails the delete with the site still there,
/// and the rows stop claiming the files that did go.
#[tokio::test]
async fn a_failed_removal_leaves_the_site_and_only_the_true_rows() {
    let pool = open_memory().await.expect("open");
    let (s, root) = with_backup_root(svc(pool.clone(), hard_delete_mocks()));
    let site = s.create(req("stuck.cz")).await.expect("create");
    let sel = HostingSelector::Id(site.id.clone());
    let user = s.get(sel.clone()).await.expect("get").system_user;
    recorded_backup(&pool, root.path(), &site.id, user.as_str(), "stuck.cz", 100).await;
    // remove_file refuses a directory for root too, so this holds in CI.
    let stuck = root.path().join(user.as_str()).join("stuck.cz-200.tar.gz");
    std::fs::create_dir_all(&stuck).expect("mkdir");
    let run = hyperion_state::backups::start(&pool, &site.id, "local", 200)
        .await
        .expect("start");
    hyperion_state::backups::mark_ok(&pool, run, stuck.to_str().expect("utf8"), None, 1, 200)
        .await
        .expect("mark ok");

    s.delete(sel.clone(), delete_local())
        .await
        .expect_err("refused");

    assert_eq!(
        s.get(sel).await.expect("still there").state,
        HostingState::Active
    );
    let rows = hyperion_state::backups::list_for(&pool, &site.id, 10)
        .await
        .expect("rows");
    let claiming: Vec<_> = rows.iter().filter_map(|r| r.archive_path.clone()).collect();
    assert_eq!(claiming, vec![stuck.display().to_string()]);
    let audited = hyperion_state::audit::list(&pool, 100)
        .await
        .expect("audit")
        .into_iter()
        .any(|e| e.action == "hosting.backup.local_delete_all" && e.result == "failed");
    assert!(audited, "a failure must leave a trace");
}
