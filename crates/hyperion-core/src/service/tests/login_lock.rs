//! Tests for `service::login_lock`.

use super::*;

/// After the boot pass has migrated this node, a missing record is never
/// read as an older version's password lock — whatever raced to clear it.
#[tokio::test]
async fn once_migrated_a_missing_record_never_unlocks_a_password() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = with_fake_shadow(offline_cycle_mocks(), &shadow);
    mocks.expect_linux_unlock_login().times(0);
    mocks.expect_nginx_delete_vhost().returning(|_, _| Ok(()));
    mocks.expect_acme_delete().returning(|_| Ok(()));
    mocks.expect_db_drop().returning(|_, _, _| Ok(()));
    mocks.expect_remove_hosting_tree().returning(|_| Ok(()));
    let s = svc(pool.clone(), mocks);
    let site = site_with_extra_login(&s, &pool, &shadow).await;
    s.offline_logins_lock_on_boot()
        .await
        .expect("boot (nothing offline)");
    s.suspend(
        HostingSelector::Id(site.id.clone()),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend");
    // What a reconcile running during the teardown leaves: no record.
    hyperion_state::hosting_kv::delete(&pool, site.id.as_str(), LOGIN_LOCK_KV)
        .await
        .expect("clear record");
    s.delete(
        HostingSelector::Id(site.id.clone()),
        hyperion_rpc::wire::DeleteOpts {
            keep_user: true,
            keep_database: false,
        },
    )
    .await
    .expect("delete");
}
