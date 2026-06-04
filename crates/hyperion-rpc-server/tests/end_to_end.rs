//! End-to-end test: real socket + real codec + real HostingService +
//! real SQLite, with mocked AdapterPort.
//!
//! Exercises the full request path:
//!   `hctl` CLI logic → wire frame → server dispatcher → AgentImpl
//!   → HostingService → MockAdapterPort + SQLite.

use async_trait::async_trait;
use hyperion_adapters::AdapterError;
use hyperion_core::{AgentImpl, HostingService, SecretsStore};
use hyperion_rpc::codec::{Request, Response};
use hyperion_rpc::wire::{DbCredentials, DeleteOpts, HostingCreateReq, HostingSelector};
use hyperion_rpc::AgentApi;
use hyperion_state::db::open_memory;
use hyperion_types::{CertInfo, DbProvision, HostingDetail, HostingId, HostingState, PhpVersion};
use hyperion_validate::Domain;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Permissive stub: all calls succeed, db_create returns plausible creds.
struct StubAdapters {
    uid_seq: AtomicU32,
}

impl StubAdapters {
    fn new() -> Self {
        Self {
            uid_seq: AtomicU32::new(2000),
        }
    }
}

#[async_trait]
impl hyperion_core::AdapterPort for StubAdapters {
    async fn ensure_user(&self, _: &str, _: &str) -> Result<u32, AdapterError> {
        Ok(self.uid_seq.fetch_add(1, Ordering::SeqCst))
    }
    async fn delete_user(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn ensure_dirs(&self, _: &str, _: &str, _: &str, _: u32) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn remove_hosting_tree(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn fpm_ensure(&self, _: &str, _: &str, _: PhpVersion) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn fpm_delete(&self, _: &str, _: PhpVersion) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn db_create(
        &self,
        engine: DbProvision,
        hosting_id: &HostingId,
        _domain: &str,
    ) -> Result<DbCredentials, AdapterError> {
        let h: String = hosting_id.as_str().chars().take(6).collect();
        Ok(DbCredentials {
            engine,
            db_name: format!("lm_{}_db", h),
            db_user: format!("lm_{}_u", h),
            password: "test-password-not-real".into(),
        })
    }
    async fn db_drop(&self, _: DbProvision, _: &str, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn acme_issue(&self, domain: &str, sans: &[String]) -> Result<CertInfo, AdapterError> {
        Ok(CertInfo {
            domain: domain.to_string(),
            sans: sans.to_vec(),
            issuer: "stub".into(),
            not_after: 1_900_000_000,
            fingerprint_sha256: "deadbeef".into(),
        })
    }
    async fn acme_delete(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn nginx_write_vhost(&self, _: &HostingDetail) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn nginx_delete_vhost(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn nginx_apply_suspended(&self, _: &str, _: Option<String>) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn apply_php_limits(
        &self,
        _: &str,
        _: &str,
        _: Option<PhpVersion>,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
    ) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn db_lock(&self, _: DbProvision, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn db_unlock(&self, _: DbProvision, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn linux_lock_login(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn linux_unlock_login(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn kill_user_procs(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn wp_install_run(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &hyperion_types::WpInstallRequest,
    ) -> Result<String, AdapterError> {
        Ok("6.5.3".into())
    }
    async fn wp_plugin_list(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(Vec<hyperion_types::WpPlugin>, String), AdapterError> {
        Ok((vec![], "6.5.3".into()))
    }
    async fn wp_plugin_action(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &hyperion_types::WpPluginAction,
    ) -> Result<hyperion_types::WpPluginActionResult, AdapterError> {
        Ok(hyperion_types::WpPluginActionResult {
            state: "ok".into(),
            message: "stub".into(),
            output_tail: String::new(),
        })
    }
}

async fn start_agent() -> (std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("dir");
    let pool = open_memory().await.expect("memory db");
    let secrets = Arc::new(SecretsStore::new(dir.path().join("secrets")));
    let adapters: Arc<dyn hyperion_core::AdapterPort> = Arc::new(StubAdapters::new());
    // Build HostingService with a generic type — we need a concrete type for Arc.
    let svc = Arc::new(HostingService::<StubAdapters> {
        pool,
        adapters: Arc::new(StubAdapters::new()),
        secrets,
        paths: hyperion_core::HostingPaths::default(),
        remote_backup: None,
        retention: hyperion_core::BackupRetention::default(),
        slack_default_webhook: None,
        acme_contact_email: "test@example.invalid".into(),
        email_config: None,
        email_default_to: None,
        agent_config_path: None,
        update_cache: Arc::new(tokio::sync::RwLock::new(None)),
        current_git_sha: "dev-unknown".into(),
        cert_issue_locks: Arc::new(tokio::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        master_rpc_signer: None,
        node_state_file: None,
    });
    let _ = adapters; // silence unused warning
    let agent: Arc<dyn AgentApi> = Arc::new(AgentImpl::new(svc));
    let path = dir.path().join("agent.sock");
    let srv = hyperion_rpc_server::Server::bind(&path, agent)
        .await
        .expect("bind");
    tokio::spawn(srv.run());
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (path, dir)
}

#[tokio::test]
async fn e2e_create_then_list_then_get_then_delete() {
    let (path, _d) = start_agent().await;

    // 1. agent_info
    let resp = hyperion_rpc_client::call(&path, Request::AgentInfo)
        .await
        .expect("info");
    let info = match resp {
        Response::AgentInfo(i) => i,
        other => panic!("expected AgentInfo, got {other:?}"),
    };
    assert_eq!(info.hostings_count, 0);

    // 2. hosting_create
    let req = HostingCreateReq {
        domain: Domain::parse("e2e-example.cz").expect("parse"),
        aliases: vec![Domain::parse("www.e2e-example.cz").expect("parse")],
        php_version: Some(PhpVersion::V8_3),
        database: Some(DbProvision::MariaDB),
        system_user: None,
        kind: "php".into(),
        proxy_upstream_url: None,
    };
    let resp = hyperion_rpc_client::call(&path, Request::HostingCreate(req))
        .await
        .expect("create");
    let created = match resp {
        Response::HostingCreate(c) => c,
        other => panic!("expected HostingCreate, got {other:?}"),
    };
    assert!(created.db.is_some());
    let created_id = created.id.clone();

    // 3. hosting_list
    let resp = hyperion_rpc_client::call(&path, Request::HostingList)
        .await
        .expect("list");
    let rows = match resp {
        Response::HostingList(v) => v,
        other => panic!("expected list, got {other:?}"),
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].domain, "e2e-example.cz");
    assert_eq!(rows[0].state, HostingState::Active);

    // 4. hosting_get by domain
    let resp = hyperion_rpc_client::call(
        &path,
        Request::HostingGet(HostingSelector::Domain(
            Domain::parse("e2e-example.cz").expect("parse"),
        )),
    )
    .await
    .expect("get");
    let detail = match resp {
        Response::HostingGet(d) => d,
        other => panic!("expected get, got {other:?}"),
    };
    assert_eq!(detail.id, created_id);
    assert_eq!(detail.aliases, vec!["www.e2e-example.cz".to_string()]);
    assert_eq!(detail.system_user, "e2e_example_cz");
    assert_eq!(detail.php_version, Some(PhpVersion::V8_3));

    // 5. hosting_delete by id
    let resp = hyperion_rpc_client::call(
        &path,
        Request::HostingDelete {
            sel: HostingSelector::Id(created_id.clone()),
            opts: DeleteOpts::default(),
        },
    )
    .await
    .expect("delete");
    matches!(resp, Response::HostingDelete);

    // 6. agent_info now shows 0
    let resp = hyperion_rpc_client::call(&path, Request::AgentInfo)
        .await
        .expect("info");
    let info = match resp {
        Response::AgentInfo(i) => i,
        other => panic!("expected AgentInfo, got {other:?}"),
    };
    assert_eq!(info.hostings_count, 0);
}

#[tokio::test]
async fn e2e_get_unknown_returns_not_found() {
    let (path, _d) = start_agent().await;
    let resp = hyperion_rpc_client::call(
        &path,
        Request::HostingGet(HostingSelector::Domain(
            Domain::parse("absent.cz").expect("parse"),
        )),
    )
    .await
    .expect("call");
    match resp {
        Response::Error(hyperion_rpc::RpcError::NotFound { kind, .. }) => {
            assert_eq!(kind, "hosting");
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn e2e_duplicate_domain_is_already_exists() {
    let (path, _d) = start_agent().await;
    let req = HostingCreateReq {
        domain: Domain::parse("dup-e2e.cz").expect("parse"),
        aliases: vec![],
        php_version: None,
        database: None,
        system_user: None,
        kind: "php".into(),
        proxy_upstream_url: None,
    };
    hyperion_rpc_client::call(&path, Request::HostingCreate(req.clone()))
        .await
        .expect("first");
    let resp = hyperion_rpc_client::call(&path, Request::HostingCreate(req))
        .await
        .expect("second");
    match resp {
        Response::Error(hyperion_rpc::RpcError::AlreadyExists { kind, .. }) => {
            assert_eq!(kind, "hosting");
        }
        other => panic!("expected AlreadyExists, got {other:?}"),
    }
}

#[tokio::test]
async fn e2e_validation_error_for_bad_domain() {
    let (path, _d) = start_agent().await;
    // Construct an invalid Domain by going through the wire: we can't
    // construct Domain in Rust without parse, so test the client-side
    // refusal in hyperion-validate by feeding it ourselves.
    let bad = Domain::parse("not-a-real-domain");
    assert!(bad.is_err(), "hyperion-validate refuses");
    // Sanity check the wire layer still works for a normal request after.
    let resp = hyperion_rpc_client::call(&path, Request::HostingList)
        .await
        .expect("list");
    matches!(resp, Response::HostingList(_));
}
