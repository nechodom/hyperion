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
