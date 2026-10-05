//! A local panel for LOOKING at the UI, not a test.
//!
//! Reuses the same stub agent + real router the e2e tests use, but binds a
//! TCP port and sits there so the pages can be opened in a browser. Stub
//! adapters mean every action "succeeds" without touching the machine; the
//! in-memory database starts empty and is gone when this stops.
//!
//!     cargo test -p hyperion-web --test devserver -- --ignored --nocapture
//!
//! Login: kevin / secret-pw-1. `#[ignore]` so `cargo test` never blocks on it.
//!
//! The fixture below is a copy of the one in `web_e2e.rs`; a shared module
//! would be tidier, but this file is a tool, not a test, and pulling the e2e
//! harness apart to share it is not worth risking those tests for.
#![allow(dead_code)]

use async_trait::async_trait;
use hyperion_adapters::AdapterError;
use hyperion_auth::SessionSigner;
use hyperion_core::{AgentImpl, HostingService, SecretsStore};
use hyperion_rpc::AgentApi;
use hyperion_state::db::open_memory;
use hyperion_types::{CertInfo, DbProvision, HostingDetail, HostingId, PhpVersion};
use hyperion_web::admin_user::{self, AdminUser};
use hyperion_web::config::Config;
use hyperion_web::state::AppState;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

struct StubAdapters {
    uid_seq: AtomicU32,
}
impl StubAdapters {
    fn new() -> Self {
        Self {
            uid_seq: AtomicU32::new(3000),
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
        _: &str,
    ) -> Result<hyperion_rpc::wire::DbCredentials, AdapterError> {
        // The tail, not the head: ids are time-ordered, so sites created in
        // the same instant (the demo seed) share a prefix.
        let id = hosting_id.as_str();
        let h = &id[id.len().saturating_sub(6)..];
        Ok(hyperion_rpc::wire::DbCredentials {
            engine,
            db_name: format!("lm_{h}_db"),
            db_user: format!("lm_{h}_u"),
            password: "TEST-PASSWORD-DONT-USE".into(),
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
    async fn nginx_delete_vhost(&self, _: &str, _: Option<String>) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn nginx_write_htpasswd(&self, _: &str, _: &str, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn nginx_delete_htpasswd(&self, _: &str) -> Result<(), AdapterError> {
        Ok(())
    }
    async fn nginx_apply_suspended(
        &self,
        _: &str,
        _: Vec<String>,
        _: Option<String>,
    ) -> Result<(), AdapterError> {
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
    async fn linux_login_expiry(&self, _: &str) -> Result<Option<String>, AdapterError> {
        Ok(Some(String::new()))
    }
    async fn linux_set_login_expiry(&self, _: &str, _: &str) -> Result<(), AdapterError> {
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
    // Note: migration export/import don't go through AdapterPort — they
    // are higher-level service methods. No stub needed here.
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
    async fn wp_registration_get(
        &self,
        _: &str,
        _: &str,
    ) -> Result<hyperion_types::WpRegistrationView, AdapterError> {
        Ok(Default::default())
    }
    async fn wp_registration_set(&self, _: &str, _: &str, _: bool) -> Result<(), AdapterError> {
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

/// Start a stub hyperion-agent on a temp Unix socket. Returns the socket path
/// and the temp dir guard (drop it last).
async fn start_agent() -> (PathBuf, tempfile::TempDir) {
    let (path, dir, _svc) = start_agent_with_service().await;
    (path, dir)
}

type StubService = HostingService<StubAdapters>;

async fn start_agent_with_service() -> (PathBuf, tempfile::TempDir, Arc<StubService>) {
    let dir = tempfile::tempdir().expect("dir");
    let pool = open_memory().await.expect("memory db");
    let secrets = Arc::new(SecretsStore::new(dir.path().join("secrets")));
    let svc = Arc::new(HostingService::<StubAdapters> {
        pool,
        adapters: Arc::new(StubAdapters::new()),
        secrets,
        paths: hyperion_core::HostingPaths::default(),
        permissions_autoheal: true,
        snapshots_enabled: false,
        protection_mode: hyperion_types::ProtectionMode::Both,
        remote_backup: None,
        retention: hyperion_core::BackupRetention::default(),
        slack_default_webhook: None,
        acme_contact_email: "test@example.invalid".into(),
        email_config: None,
        email_default_to: None,
        fail2ban: hyperion_core::Fail2banConfig::default(),
        agent_config_path: None,
        update_cache: Arc::new(tokio::sync::RwLock::new(None)),
        current_git_sha: "dev-unknown".into(),
        cert_issue_locks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        panel_progress: Arc::new(tokio::sync::RwLock::new(None)),
        master_rpc_signer: None,
        node_state_file: None,
        service_install_progress: Arc::new(tokio::sync::Mutex::new(
            hyperion_types::ServiceInstallStatus::default(),
        )),
        backup_progress: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    });
    let agent: Arc<dyn AgentApi> = Arc::new(AgentImpl::new(svc.clone()));
    let path = dir.path().join("agent.sock");
    let srv = hyperion_rpc_server::Server::bind(&path, agent)
        .await
        .expect("bind");
    tokio::spawn(srv.run());
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (path, dir, svc)
}

fn build_app(agent_socket: PathBuf, admin: AdminUser) -> axum::Router {
    build_app_with_signer(agent_socket, admin, Arc::new(SessionSigner::new_random())).0
}

/// Same as [`build_app`] but lets the test keep a handle on the signer
/// so it can mint tokens that the app will accept as valid signatures.
/// Returned tuple is `(router, signer)`.
fn build_app_with_signer(
    agent_socket: PathBuf,
    admin: AdminUser,
    signer: Arc<SessionSigner>,
) -> (axum::Router, Arc<SessionSigner>) {
    let cfg = Config::default();
    let csrf_key: [u8; 32] = {
        let mut k = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut k);
        k
    };
    let state = Arc::new(AppState {
        cfg: Config {
            web: hyperion_web::config::WebSection {
                secure_cookies: false, // test over plain HTTP
                ..cfg.web
            },
        },
        agent_socket,
        session: signer.clone(),
        csrf_key: Arc::new(csrf_key),
        admin_user: Arc::new(admin),
        ratelimit: Arc::new(hyperion_web::ratelimit::RateLimiter::new()),
        // Tests don't exercise remote dispatch — leave the signer
        // unset so any handler that wires it in later gets a clean
        // "remote disabled" error rather than a stub signature.
        master_rpc_signer: None,
        // Empty hostname ⇒ the enforce_panel_hostname middleware is
        // a no-op, so tests reach handlers regardless of Host header.
        panel_hostname: Arc::new(tokio::sync::RwLock::new(String::new())),
        // Fixtures log in as admins without enrolling 2FA — keep the
        // enforcement gate off so the existing flows render as before.
        enforce_admin_2fa: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        // "master" = draw everything, matching how these fixtures were
        // written. Standalone only ever HIDES chrome, so this keeps the
        // existing assertions honest.
        deployment_mode: Arc::new(tokio::sync::RwLock::new("master".to_string())),
        ftp_password_handoff: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        error_handoff: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    });
    // The login/2FA + enroll handlers extract `ConnectInfo<SocketAddr>` (real
    // peer IP for the rate-limit bucket). `.oneshot()` doesn't go through
    // `into_make_service_with_connect_info`, so inject a mock peer addr the same
    // way axum's own tests do — otherwise those handlers 500 on extraction.
    // No MockConnectInfo here: a real listener supplies the peer address.
    let router = hyperion_web::build_router(state);
    (router, signer)
}

/// `DEVSERVER_DEMO=1`: fill the empty database with a handful of sites and a
/// few hours of plausible metrics, so the Dashboard and Stats pages have
/// something to draw (README screenshots). Pure inserts; nothing is sampled.
async fn seed_demo(svc: &StubService) {
    use hyperion_rpc::wire::HostingCreateReq;
    use hyperion_validate::Domain;

    let sites = [
        ("studio-lumen.cz", Some(DbProvision::MariaDB)),
        ("pekarna-u-mostu.cz", Some(DbProvision::MariaDB)),
        ("kavarna-sever.cz", Some(DbProvision::MariaDB)),
        ("atelier-hora.com", Some(DbProvision::MariaDB)),
        ("fit-centrum-brno.cz", Some(DbProvision::MariaDB)),
        ("docs.example.org", None),
        ("shop.zahrada-plus.cz", Some(DbProvision::MariaDB)),
    ];
    let mut ids = Vec::new();
    for (domain, db) in sites {
        let created = svc
            .create(HostingCreateReq {
                domain: Domain::parse(domain).expect("domain"),
                aliases: vec![],
                php_version: Some(PhpVersion::V8_3),
                database: db,
                system_user: None,
                kind: "php".into(),
                proxy_upstream_url: None,
            })
            .await
            .expect("demo create");
        ids.push(created.id.as_str().to_string());
    }
    let pool = &svc.pool;
    // One suspended site, so the state dots are not all green.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query("UPDATE hostings SET state = 'suspended' WHERE id = ?")
        .bind(&ids[5])
        .execute(pool)
        .await
        .expect("suspend");
    sqlx::query(
        "INSERT INTO hosting_suspension (hosting_id, suspended_at, suspended_by) VALUES (?, ?, 'manual')",
    )
    .bind(&ids[5])
    .bind(now - 3 * 86_400)
    .execute(pool)
    .await
    .expect("suspension");

    // Smooth-ish noise: a couple of sines plus a deterministic jitter.
    let wave = |i: f64, a: f64, b: f64| {
        (i / a).sin() * 0.5 + (i / b).sin() * 0.3 + ((i * 12.9898).sin() * 43_758.545).fract() * 0.4
    };

    // Per-hosting hourly usage for the last 24 h.
    let weights = [9.0, 4.0, 2.5, 6.0, 3.0, 0.4, 7.5];
    let disk_gib = [3.4, 1.2, 0.8, 5.1, 1.9, 0.3, 4.6];
    for (n, id) in ids.iter().enumerate() {
        for h in 0..24 {
            let t = now - h * 3600;
            let period = chrono::DateTime::from_timestamp(t, 0)
                .unwrap()
                .format("%Y-%m-%d-%H")
                .to_string();
            let day = 0.6 + 0.4 * ((h as f64 - 6.0) / 24.0 * std::f64::consts::TAU).cos();
            let w = weights[n] * day * (1.0 + 0.2 * wave(h as f64 + n as f64 * 7.0, 2.0, 5.0));
            sqlx::query(
                "INSERT INTO hosting_usage (hosting_id, period, disk_used_bytes, inodes_used, \
                 bw_out_bytes, php_requests, mem_rss_bytes, cpu_pct_x100) VALUES (?,?,?,?,?,?,?,?)",
            )
            .bind(id)
            .bind(&period)
            .bind((disk_gib[n] * 1_073_741_824.0) as i64)
            .bind((disk_gib[n] * 9_000.0) as i64)
            .bind((w * 38_000_000.0) as i64)
            .bind((w * 410.0) as i64)
            .bind(((80.0 + w * 30.0) * 1_048_576.0) as i64)
            .bind((w * 60.0) as i64)
            .execute(pool)
            .await
            .expect("usage");
        }
    }

    // Node samples every 5 minutes for the last 8 hours.
    let mem_total: i64 = 8 * 1024 * 1024;
    let disk_total: i64 = 160 * 1_073_741_824;
    let hostings_disk: i64 = (disk_gib.iter().sum::<f64>() * 1_073_741_824.0) as i64;
    for k in 0..96i64 {
        let i = (96 - k) as f64;
        let t = now - k * 300;
        let load = (0.45 + 0.35 * wave(i, 3.0, 11.0)).max(0.05);
        let mem = 0.52 + 0.06 * wave(i, 5.0, 17.0);
        let cpu = (load * 22.0).min(100.0);
        let tx = (180_000.0 + 120_000.0 * wave(i, 2.5, 9.0)).max(20_000.0);
        sqlx::query(
            "INSERT INTO node_metrics (sampled_at, hostings_count, hostings_active, \
             hostings_suspended, hostings_failed, total_disk_bytes, total_bw_out_24h, \
             total_requests_24h, loadavg_1m_x100, mem_total_kib, mem_used_kib, uptime_secs, \
             cpu_pct_x100, swap_total_kib, swap_used_kib, psi_cpu_x100, psi_mem_x100, \
             psi_io_x100, net_rx_bps, net_tx_bps, hostings_disk_bytes, node_disk_total_bytes) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(t)
        .bind(7)
        .bind(6)
        .bind(1)
        .bind(0)
        .bind(hostings_disk + 21 * 1_073_741_824)
        .bind((tx * 86_400.0 * 0.35) as i64)
        .bind(86_000 + (wave(i, 4.0, 13.0) * 9_000.0) as i64)
        .bind((load * 100.0) as i64)
        .bind(mem_total)
        .bind((mem * mem_total as f64) as i64)
        .bind(41 * 86_400 + 3 * 3600 - k * 300)
        .bind((cpu * 100.0) as i64)
        .bind(2 * 1024 * 1024)
        .bind(96 * 1024)
        .bind((load * 30.0) as i64)
        .bind(0)
        .bind((load * 12.0) as i64)
        .bind((tx * 0.3) as i64)
        .bind(tx as i64)
        .bind(hostings_disk)
        .bind(disk_total)
        .execute(pool)
        .await
        .expect("node_metrics");
    }

    // The 15 s network sampler, last hour.
    for k in 0..240i64 {
        let i = (240 - k) as f64;
        let tx = (210_000.0 + 140_000.0 * wave(i, 4.0, 15.0)).max(15_000.0);
        sqlx::query("INSERT INTO net_samples (at, rx_bps, tx_bps) VALUES (?,?,?)")
            .bind(now - k * 15)
            .bind((tx * 0.28) as i64)
            .bind(tx as i64)
            .execute(pool)
            .await
            .expect("net_samples");
    }
}

#[tokio::test]
#[ignore]
async fn devserver() {
    let admin = admin_user::create("kevin", "secret-pw-1").expect("create");
    let (sock, _dir, svc) = start_agent_with_service().await;
    if std::env::var_os("DEVSERVER_DEMO").is_some() {
        seed_demo(&svc).await;
    }
    let (router, _signer) =
        build_app_with_signer(sock, admin, Arc::new(SessionSigner::new_random()));
    let port = std::env::var("DEVSERVER_PORT").unwrap_or_else(|_| "8190".into());
    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!("devserver: http://{addr}  (kevin / secret-pw-1)");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("serve");
}
