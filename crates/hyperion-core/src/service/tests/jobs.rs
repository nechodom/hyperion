//! Tests for `service::jobs`.

use super::*;

/// Regression test for the user-visible bug:
///   1. Create example.cz — nginx_write_vhost fails partway
///      through provisioning.
///   2. Rollback runs; PRE-FIX it set state='failed' on the
///      hostings row, POST-FIX it DELETEs the row.
///   3. Create example.cz AGAIN.
///   4. PRE-FIX: UNIQUE(domain) constraint blocks step 3.
///      POST-FIX: succeeds.
#[tokio::test]
async fn create_after_rolled_back_failure_can_recreate_same_domain() {
    let pool = open_memory().await.expect("open");
    // First attempt — fails at nginx_write_vhost.
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(2042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost()
        .returning(|_| Err(AdapterError::Other("nginx config bad".into())));
    // Rollback adapter calls — all best-effort, fed Ok():
    a.expect_acme_delete().returning(|_| Ok(()));
    a.expect_db_drop().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_remove_hosting_tree().returning(|_| Ok(()));
    a.expect_delete_user().returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    let _ = s.create(req("retry.cz")).await; // expected to fail
                                             // PRE-FIX: list would now contain a state='failed' row.
                                             // POST-FIX: list is empty for that domain.
    let leftover = hostings::get_by_domain(&pool, "retry.cz").await.unwrap();
    assert!(
        leftover.is_none(),
        "rollback must DELETE the row, not leave it as 'failed' — \
             otherwise UNIQUE(domain) blocks the retry"
    );

    // Second attempt — succeeds (the row is gone, no UNIQUE
    // constraint to trip).
    let secrets_dir = tempfile::tempdir().expect("dir");
    let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
    let mut a2 = MockAdapterPort::new();
    a2.expect_ensure_user().returning(|_, _| Ok(2043));
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
    s2.create(req("retry.cz"))
        .await
        .expect("second create must succeed — the orphan row should have been deleted by rollback");
}

#[tokio::test]
async fn list_returns_active_after_create() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    s.create(req("a.cz")).await.expect("a");
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1043));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost().returning(|_| Ok(()));
    // Replace the adapter for the second call using a fresh svc.
    let secrets_dir = tempfile::tempdir().expect("dir");
    let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
    let s2 = HostingService {
        pool: s.pool.clone(),
        adapters: Arc::new(a),
        secrets,
        paths: HostingPaths::default(),
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
    s2.create(HostingCreateReq {
        domain: Domain::parse("b.cz").expect("parse"),
        aliases: vec![],
        php_version: None,
        database: None,
        system_user: None,
        kind: "php".into(),
        proxy_upstream_url: None,
    })
    .await
    .expect("b");
    let rows = s.list().await.expect("list");
    assert_eq!(rows.len(), 2);
}

#[tokio::test]
async fn duplicate_domain_is_already_exists() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("dup.cz")).await.expect("first ok");
    // Second create: fresh mock with the same expectations.
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1043));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_delete_user().returning(|_| Ok(()));
    a.expect_remove_hosting_tree().returning(|_| Ok(()));
    let secrets_dir = tempfile::tempdir().expect("dir");
    let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
    let s2 = HostingService {
        pool: s.pool.clone(),
        adapters: Arc::new(a),
        secrets,
        paths: HostingPaths::default(),
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
    let r = s2.create(req("dup.cz")).await;
    match r {
        Err(RpcError::AlreadyExists { kind, .. }) => assert_eq!(kind, "hosting"),
        other => panic!("expected AlreadyExists, got {other:?}"),
    }
}
