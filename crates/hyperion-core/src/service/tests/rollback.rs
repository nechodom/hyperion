//! Tests for `service::rollback`.

use super::*;

/// Regression for the field-reported bug:
///   1. Create test5.example.cz on a fresh node.
///   2. ensure_user succeeds (Linux UID 1000 allocated).
///   3. system_users::insert succeeds (DB row with UID 1000).
///   4. nginx_write_vhost fails → rollback.
///   5. PRE-FIX: DeleteUser removes Linux user; system_users
///      DB row stays. UID is now free at Linux level but
///      claimed at DB level.
///   6. Operator retries with DIFFERENT domain (different
///      system_user name). useradd reuses UID 1000.
///   7. PRE-FIX: system_users::insert(uid=1000) → UNIQUE
///      constraint failure. Operator stuck.
///   POST-FIX: DeleteSystemUsersRow rollback removes the DB
///   row alongside DeleteUser, so step 6 starts from a clean
///   DB state and the retry succeeds.
#[tokio::test]
async fn rollback_cleans_system_users_db_row_so_uid_can_be_reused() {
    let pool = open_memory().await.expect("open");
    // First attempt — succeeds through system_users::insert
    // then fails at nginx_write_vhost so DeleteUser +
    // DeleteSystemUsersRow rollbacks fire.
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1000));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost()
        .returning(|_| Err(AdapterError::Other("nginx bad".into())));
    a.expect_acme_delete().returning(|_| Ok(()));
    a.expect_db_drop().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_remove_hosting_tree().returning(|_| Ok(()));
    a.expect_delete_user().returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    let _ = s.create(req("test5.example.cz")).await;
    // After rollback the system_users row MUST be gone — else
    // the next create's UNIQUE(uid) hits a phantom row.
    let leftover = system_users::get_by_uid(&pool, 1000).await.expect("query");
    assert!(
        leftover.is_none(),
        "rollback must DELETE the system_users row, not just the Linux user — \
             otherwise UNIQUE(uid) blocks every subsequent create that gets \
             UID 1000 from useradd"
    );

    // Second attempt with a different domain — Linux freed UID
    // 1000, useradd reuses it, system_users::insert(1000) must
    // succeed (no phantom row).
    let secrets_dir = tempfile::tempdir().expect("dir");
    let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
    let mut a2 = MockAdapterPort::new();
    a2.expect_ensure_user().returning(|_, _| Ok(1000));
    a2.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a2.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a2.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a2.expect_nginx_write_vhost().returning(|_| Ok(()));
    a2.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    let s2 = HostingService {
        pool: pool.clone(),
        adapters: Arc::new(a2),
        secrets,
        paths: HostingPaths::default(),
        // The repair has always run; a service built without an
        // explicit setting keeps it.
        permissions_autoheal: true,
        remote_backup: None,
        retention: BackupRetention::default(),
        snapshots_enabled: true,
        protection_mode: hyperion_types::ProtectionMode::Both,
        slack_default_webhook: None,
        acme_contact_email: "test@example.invalid".into(),
        email_config: None,
        email_default_to: None,
        fail2ban: Fail2banConfig::default(),
        agent_config_path: None,
        update_cache: Arc::new(tokio::sync::RwLock::new(None)),
        current_git_sha: "dev-unknown".into(),
        cert_issue_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        panel_progress: Arc::new(tokio::sync::RwLock::new(None)),
        master_rpc_signer: None,
        node_state_file: None,
        service_install_progress: Arc::new(tokio::sync::Mutex::new(
            hyperion_types::ServiceInstallStatus::default(),
        )),
        backup_progress: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    };
    s2.create(req("test6.example.cz"))
        .await
        .expect("retry with different domain must succeed — DB UID 1000 is free");
}
