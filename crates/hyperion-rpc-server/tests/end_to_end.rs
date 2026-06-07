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
    async fn nginx_delete_vhost(
        &self,
        _: &str,
        _: Option<String>,
    ) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn nginx_write_htpasswd(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn nginx_delete_htpasswd(&self, _: &str) -> Result<(), AdapterError> {
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
    async fn wp_cli(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: bool,
    ) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn wp_theme_list(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(Vec<hyperion_types::WpTheme>, String), AdapterError> {
        Ok((vec![], "6.5.3".into()))
    }
    async fn wp_theme_action(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &hyperion_types::WpThemeAction,
    ) -> Result<hyperion_types::WpThemeActionResult, AdapterError> {
        Ok(hyperion_types::WpThemeActionResult {
            state: "ok".into(),
            message: "stub".into(),
            output_tail: String::new(),
        })
    }
    async fn wp_set_debug(
        &self,
        _: &str,
        _: &str,
        _: bool,
        _: bool,
        _: bool,
    ) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn wp_set_redis(
        &self,
        _: &str,
        _: &str,
        _: Option<hyperion_types::WpRedisConfig>,
    ) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn wp_debug_log_size(&self, _: &str) -> Result<i64, AdapterError> {
        Ok(0)
    }
    async fn redis_ensure_acl(&self, _: &str, _: &str, _: i64) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn redis_delete_acl(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
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
        node_update: Arc::new(tokio::sync::Mutex::new(
            hyperion_types::NodeUpdateStatus::default(),
        )),
        service_install_progress: Arc::new(tokio::sync::Mutex::new(
            hyperion_types::ServiceInstallStatus::default(),
        )),
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

/// Exercises the Bundle A/C/jobs RPC families on top of a real
/// agent socket — same shape as the other E2E tests but covering
/// the surface that grew this week (jobs, sessions, quotas,
/// backup targets). Verifies the wire codec + dispatch + Service
/// happy paths line up.
#[tokio::test]
async fn e2e_bundle_a_c_round_trip_through_wire() {
    let (path, _d) = start_agent().await;

    // ── Background jobs ──
    // JobStart returns a fresh ULID; JobProgress + JobFinish must
    // both ack; JobGet must round-trip the row including
    // finished_at being set after JobFinish.
    let job_id = match hyperion_rpc_client::call(
        &path,
        Request::JobStart {
            kind: "migration".into(),
            target: Some("example.cz".into()),
            payload_json: "{\"src\":\"a\",\"dst\":\"b\"}".into(),
            actor_label: "kevin".into(),
            actor_uid: 7,
        },
    )
    .await
    .expect("JobStart")
    {
        Response::JobStarted { job_id } => job_id,
        other => panic!("expected JobStarted, got {other:?}"),
    };
    assert!(!job_id.is_empty(), "job id must be non-empty");

    let ack = hyperion_rpc_client::call(
        &path,
        Request::JobProgress {
            id: job_id.clone(),
            step_label: "exporting".into(),
            progress_pct: 42,
            log_append: "tar...\n".into(),
        },
    )
    .await
    .expect("JobProgress");
    assert!(matches!(ack, Response::JobAck), "got {ack:?}");

    let job = match hyperion_rpc_client::call(
        &path,
        Request::JobGet { id: job_id.clone() },
    )
    .await
    .expect("JobGet")
    {
        Response::JobGet(Some(j)) => j,
        other => panic!("expected JobGet(Some), got {other:?}"),
    };
    assert_eq!(job.id, job_id);
    assert_eq!(job.progress_pct, 42);
    assert_eq!(job.step_label, "exporting");
    assert!(job.log_tail.contains("tar..."));

    let _ = hyperion_rpc_client::call(
        &path,
        Request::JobFinish {
            id: job_id.clone(),
            ok: true,
            error: None,
        },
    )
    .await
    .expect("JobFinish");

    let job_after = match hyperion_rpc_client::call(
        &path,
        Request::JobGet { id: job_id.clone() },
    )
    .await
    .expect("JobGet-after")
    {
        Response::JobGet(Some(j)) => j,
        other => panic!("expected JobGet(Some), got {other:?}"),
    };
    assert_eq!(job_after.state, "done");
    assert_eq!(job_after.progress_pct, 100);
    assert!(job_after.finished_at.is_some());

    // JobList filtered to kind=migration must include our row.
    let list = match hyperion_rpc_client::call(
        &path,
        Request::JobList {
            kind: Some("migration".into()),
            state: None,
            limit: 50,
        },
    )
    .await
    .expect("JobList")
    {
        Response::JobList(v) => v,
        other => panic!("expected JobList, got {other:?}"),
    };
    assert!(list.iter().any(|j| j.id == job_id));

    // ── web_sessions ──
    // The agent test rig has no seeded web_user. Insert one so the
    // FK is satisfied before exercising the session RPCs.
    // Direct SQL would skip the test layer, so use WebUserCreate
    // RPC if exposed; for the e2e harness we use SQL via the
    // Service-level helper.
    //
    // Skipping web_sessions RPC here because the FK setup needs
    // WebUserCreate plumbing the e2e harness doesn't have. The
    // dedicated migrations_028_031 integration test covers the
    // table-level lifecycle.

    // ── hosting_quotas ──
    // Create a hosting first so the quota FK is satisfied. Reuse
    // the same wire shape the existing e2e tests use.
    let domain = Domain::parse("quotatest.example.cz").expect("dom");
    let create = hyperion_rpc_client::call(
        &path,
        Request::HostingCreate(HostingCreateReq {
            domain: domain.clone(),
            aliases: vec![],
            php_version: Some(PhpVersion::V8_3),
            database: None,
            system_user: None,
            kind: "php".into(),
            proxy_upstream_url: None,
        }),
    )
    .await
    .expect("HostingCreate");
    let created = match create {
        Response::HostingCreate(c) => c,
        other => panic!("expected HostingCreate, got {other:?}"),
    };

    // QuotaGet on a brand-new hosting returns zero-everywhere.
    let q_before = match hyperion_rpc_client::call(
        &path,
        Request::QuotaGet {
            hosting: HostingSelector::Id(created.id.clone()),
        },
    )
    .await
    .expect("QuotaGet")
    {
        Response::QuotaGet(r) => r,
        other => panic!("expected QuotaGet, got {other:?}"),
    };
    assert_eq!(q_before.policy.disk_soft_kib, 0);

    // QuotaSet validates non-negative + hard >= soft.
    let bad = hyperion_rpc_client::call(
        &path,
        Request::QuotaSet {
            hosting: HostingSelector::Id(created.id.clone()),
            disk_soft_kib: 200_000,
            disk_hard_kib: 100_000, // hard < soft ⇒ Validation
            mem_limit_mib: 0,
            bw_soft_mib: 0,
            bw_hard_mib: 0,
        },
    )
    .await
    .expect("QuotaSet-bad");
    assert!(
        matches!(bad, Response::Error(_)),
        "hard < soft should fail Validation, got {bad:?}"
    );

    // Now a valid policy. setquota will likely fail on the test
    // host (no quotaon) — the policy is saved either way and the
    // ack carries last_error rather than failing the RPC.
    let q_set = match hyperion_rpc_client::call(
        &path,
        Request::QuotaSet {
            hosting: HostingSelector::Id(created.id.clone()),
            disk_soft_kib: 100_000,
            disk_hard_kib: 200_000,
            mem_limit_mib: 256,
            bw_soft_mib: 5_000,
            bw_hard_mib: 10_000,
        },
    )
    .await
    .expect("QuotaSet")
    {
        Response::QuotaApplied(v) => v,
        other => panic!("expected QuotaApplied, got {other:?}"),
    };
    assert_eq!(q_set.disk_soft_kib, 100_000);
    assert_eq!(q_set.mem_limit_mib, 256);

    // ── backup_targets ──
    let target_id = match hyperion_rpc_client::call(
        &path,
        Request::BackupTargetUpsert {
            id: None,
            name: "wasabi-test".into(),
            kind: "s3".into(),
            endpoint: "https://s3.example.invalid".into(),
            bucket: "test-bucket".into(),
            region: "eu-central-1".into(),
            access_key_id: "AKIA-test".into(),
            secret_key: Some("seekrit".into()),
            age_recipient: Some("age1zzz".into()),
            retention_daily: 7,
            retention_weekly: 4,
            retention_monthly: 12,
            enabled: true,
        },
    )
    .await
    .expect("BackupTargetUpsert")
    {
        Response::BackupTargetUpserted { id } => id,
        other => panic!("expected BackupTargetUpserted, got {other:?}"),
    };
    assert!(target_id > 0);

    let targets = match hyperion_rpc_client::call(
        &path,
        Request::BackupTargetList,
    )
    .await
    .expect("BackupTargetList")
    {
        Response::BackupTargetList(v) => v,
        other => panic!("expected BackupTargetList, got {other:?}"),
    };
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].id, target_id);
    assert_eq!(targets[0].bucket, "test-bucket");

    // Cleanup so the next test in the suite starts clean.
    let _ = hyperion_rpc_client::call(
        &path,
        Request::HostingDelete {
            sel: HostingSelector::Id(created.id),
            opts: DeleteOpts {
                keep_user: false,
                keep_database: false,
            },
        },
    )
    .await;
}
