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
        if std::env::var_os("DEVSERVER_DEMO").is_none() {
            return Ok((vec![], "6.5.3".into()));
        }
        // (slug, name, version, status, latest — "" = up to date, auto-update)
        let demo = [
            (
                "akismet",
                "Akismet Anti-spam",
                "5.3.1",
                "active",
                "5.3.3",
                true,
            ),
            ("wordpress-seo", "Yoast SEO", "22.4", "active", "", true),
            (
                "woocommerce",
                "WooCommerce",
                "8.7.0",
                "active",
                "9.0.1",
                false,
            ),
            ("hello-dolly", "Hello Dolly", "1.7.2", "inactive", "", false),
            (
                "hyperion-mail",
                "Hyperion mail pin",
                "1.0",
                "must-use",
                "",
                false,
            ),
        ];
        let plugins = demo
            .iter()
            .map(
                |(slug, name, v, status, latest, auto)| hyperion_types::WpPlugin {
                    slug: (*slug).into(),
                    name: (*name).into(),
                    version: (*v).into(),
                    status: (*status).into(),
                    update_available: !latest.is_empty(),
                    latest_version: (*latest).into(),
                    auto_update: *auto,
                    auto_update_blocked: false,
                    auto_update_block_reason: None,
                },
            )
            .collect();
        Ok((plugins, "6.5.3".into()))
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
        if std::env::var_os("DEVSERVER_DEMO").is_none() {
            return Ok((vec![], "6.5.3".into()));
        }
        let demo = [
            ("astra", "Astra", "4.6.8", "active", "4.7.0"),
            (
                "twentytwentyfour",
                "Twenty Twenty-Four",
                "1.1",
                "inactive",
                "",
            ),
        ];
        let themes = demo
            .iter()
            .map(|(slug, name, v, status, latest)| hyperion_types::WpTheme {
                slug: (*slug).into(),
                name: (*name).into(),
                version: (*v).into(),
                status: (*status).into(),
                update_available: !latest.is_empty(),
                latest_version: (*latest).into(),
            })
            .collect();
        Ok((themes, "6.5.3".into()))
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

    // Profiles & limits: three plan tiers, most sites on one of them.
    {
        use hyperion_state::profiles::{insert, upsert_apply, NewProfile};
        let tiers = [
            NewProfile {
                name: "Basic".into(),
                description: "Small business sites".into(),
                php_memory_mb: 256,
                php_max_exec_secs: 60,
                php_max_children: 5,
                php_max_requests: 500,
                db_max_connections: 20,
                disk_hard_mb: Some(2048),
                disk_soft_mb: Some(1536),
                expiry_grace_days: 30,
                expiry_warning_offsets: "30,7,1".into(),
                price_minor: Some(19_900),
                price_currency: Some("CZK".into()),
                price_interval: Some("monthly".into()),
                quota_exceed_action: "notify".into(),
                backup_cadence: "weekly".into(),
                backup_keep_days: 30,
                default_php_version: Some("8.3".into()),
                ..NewProfile::default()
            },
            NewProfile {
                name: "WordPress Pro".into(),
                description: "WooCommerce and busier WordPress".into(),
                php_memory_mb: 512,
                php_max_exec_secs: 120,
                php_max_children: 20,
                php_max_requests: 1000,
                db_max_connections: 60,
                disk_hard_mb: Some(10_240),
                disk_soft_mb: Some(8192),
                expiry_grace_days: 30,
                expiry_warning_offsets: "30,7,1".into(),
                price_minor: Some(59_900),
                price_currency: Some("CZK".into()),
                price_interval: Some("monthly".into()),
                quota_exceed_action: "suspend".into(),
                backup_cadence: "daily".into(),
                backup_keep_days: 14,
                backup_keep_last: 3,
                default_php_version: Some("8.3".into()),
                default_db_engine: Some("mariadb".into()),
                wp_plugins: "akismet!\nwordpress-seo!\nwp-mail-smtp".into(),
                wp_themes: "astra!".into(),
                ..NewProfile::default()
            },
            NewProfile {
                name: "Static".into(),
                php_memory_mb: 128,
                php_max_exec_secs: 30,
                php_max_children: 2,
                php_max_requests: 500,
                db_max_connections: 5,
                expiry_grace_days: 14,
                expiry_warning_offsets: "14,3".into(),
                quota_exceed_action: "notify".into(),
                backup_cadence: "off".into(),
                default_db_engine: Some("none".into()),
                ..NewProfile::default()
            },
        ];
        let mut pids = Vec::new();
        for t in &tiers {
            pids.push(insert(pool, t, now - 90 * 86_400).await.expect("profile"));
        }
        for (n, id) in ids.iter().enumerate() {
            let pid = match n {
                0 | 1 | 5 => pids[0],
                2 | 3 | 4 | 6 => pids[1],
                _ => continue,
            };
            upsert_apply(
                pool,
                &HostingId(id.clone()),
                Some(pid),
                None,
                None,
                None,
                None,
                None,
                None,
                now - 30 * 86_400,
            )
            .await
            .expect("profile apply");
        }
    }

    // Hostings-list facts: WordPress on most sites, certificates at a mix
    // of ages (one expiring, one self-signed), backups with one failure,
    // one site in maintenance.
    for (n, id) in ids.iter().enumerate() {
        if n != 5 {
            sqlx::query(
                "INSERT INTO wp_installs (hosting_id, site_url, wp_version, installed_at, last_pack_hash) \
                 VALUES (?, 'https://x', ?, ?, 'demo')",
            )
            .bind(id)
            .bind(if n == 3 { "6.5.5" } else { "6.6.2" })
            .bind(now - 40 * 86_400)
            .execute(pool)
            .await
            .expect("wp");
        }
    }
    let cert_days = [71_i64, 54, 9, 63, 80, 30, 44];
    for (n, (domain, _)) in sites.iter().enumerate() {
        sqlx::query(
            "INSERT INTO certificates (domain, issued_at, not_after, cert_path, key_path, issuer) \
             VALUES (?, ?, ?, '/c', '/k', ?) \
             ON CONFLICT(domain) DO UPDATE SET not_after = excluded.not_after, issuer = excluded.issuer",
        )
        .bind(domain)
        .bind(now - 20 * 86_400)
        .bind(now + cert_days[n] * 86_400)
        .bind(if n == 6 { "self-signed" } else { "letsencrypt" })
        .execute(pool)
        .await
        .expect("cert");
    }
    for (n, id) in ids.iter().enumerate() {
        let started = now - (n as i64 + 1) * 5 * 3600;
        let state = if n == 4 { "failed" } else { "ok" };
        sqlx::query(
            "INSERT INTO backup_runs (hosting_id, started_at, finished_at, state) VALUES (?, ?, ?, ?)",
        )
        .bind(id)
        .bind(started)
        .bind(started + 300)
        .bind(state)
        .execute(pool)
        .await
        .expect("backup");
    }
    sqlx::query("UPDATE hostings SET maintenance_mode = 1 WHERE id = ?")
        .bind(&ids[2])
        .execute(pool)
        .await
        .expect("maintenance");

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

    // Background jobs: two running, a fresh failure, and a few days of history.
    // (id, kind, target, state, step, pct, error, started N secs ago, took N secs)
    type DemoJob<'a> = (
        &'a str,
        &'a str,
        Option<&'a str>,
        &'a str,
        &'a str,
        i64,
        Option<&'a str>,
        i64,
        i64,
    );
    let jobs: [DemoJob; 9] = [
        ("j-run-1", "hosting_backup", Some("studio-lumen.cz"), "running", "Packing files", 42, None, 95, 0),
        ("j-run-2", "acme_issue", Some("kavarna-sever.cz"), "running", "Waiting for HTTP-01 validation", 70, None, 20, 0),
        ("j-fail-1", "migration", Some("atelier-hora.com"), "failed", "Copying database", 55, Some("rsync: connection unexpectedly closed (0 bytes received so far) [sender]\nrsync error: error in rsync protocol data stream (code 12)"), 3 * 3600, 240),
        ("j-done-1", "wp_install", Some("pekarna-u-mostu.cz"), "done", "Done", 100, None, 5 * 3600, 48),
        ("j-done-2", "post_create_setup", Some("pekarna-u-mostu.cz"), "done", "Done", 100, None, 5 * 3600 + 120, 12),
        ("j-done-3", "cert_renew_all", Some("7 certificates"), "done", "Renewed 7, skipped 0", 100, None, 30 * 3600, 95),
        ("j-done-4", "hosting_clone", Some("shop.zahrada-plus.cz"), "done", "Done", 100, None, 31 * 3600, 410),
        ("j-canc-1", "panel_import", Some("CloudPanel @ 10.0.0.4"), "cancelled", "Cancelled by operator", 30, None, 50 * 3600, 60),
        ("j-done-5", "profile_apply", Some("fit-centrum-brno.cz"), "done", "Applied", 100, None, 4 * 86_400, 7),
    ];
    for (id, kind, target, state, step, pct, err, ago, took) in jobs {
        let started = now - ago;
        let finished = (state != "running").then_some(started + took);
        sqlx::query(
            "INSERT INTO jobs (id, kind, target, state, step_label, progress_pct, substeps_json, \
             log_tail, error, payload_json, actor_uid, actor_label, started_at, updated_at, finished_at) \
             VALUES (?,?,?,?,?,?,'[]',?,?,'{}',1,'kevin',?,?,?)",
        )
        .bind(id)
        .bind(kind)
        .bind(target)
        .bind(state)
        .bind(step)
        .bind(pct)
        .bind(format!("[{kind}] started\n[{kind}] {step}\n"))
        .bind(err)
        .bind(started)
        .bind(finished.unwrap_or(now))
        .bind(finished)
        .execute(pool)
        .await
        .expect("jobs");
    }

    // Care packages: two plans on sale, one retired, held by most sites;
    // part of this month's checks ticked so the roster has both states.
    {
        use hyperion_types::package::{
            BackupCadence, FeatureToggle, PackageFeatures, ReportCadence,
        };
        use hyperion_types::PackageInput;
        let care = svc
            .package_create(PackageInput {
                name: "Care plan".into(),
                description:
                    "WordPress updates, daily backups, uptime monitoring and a monthly report."
                        .into(),
                price_minor: Some(49_000),
                price_currency: Some("Kč".into()),
                price_interval: Some("monthly".into()),
                letters_lang: "cs".into(),
                features: PackageFeatures {
                    wp_auto_update: FeatureToggle::On,
                    monitoring: FeatureToggle::On,
                    integrity_scan: FeatureToggle::On,
                    backup_cadence: BackupCadence::Daily,
                    backup_keep_days: 30,
                    report_cadence: ReportCadence::Monthly,
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .expect("care plan");
        let basic = svc
            .package_create(PackageInput {
                name: "Backup only".into(),
                description: "Weekly off-site backups.".into(),
                price_minor: Some(150_000),
                price_currency: Some("Kč".into()),
                price_interval: Some("yearly".into()),
                report_omit: "attacks,traffic,performance,uptime".into(),
                features: PackageFeatures {
                    backup_cadence: BackupCadence::Weekly,
                    report_cadence: ReportCadence::Quarterly,
                    hardening: FeatureToggle::Off,
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .expect("backup plan");
        svc.package_create(PackageInput {
            name: "Legacy support".into(),
            enabled: false,
            features: PackageFeatures {
                monitoring: FeatureToggle::On,
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .expect("legacy plan");
        let holders = [
            (0, &care),
            (1, &care),
            (2, &basic),
            (3, &care),
            (4, &care),
            (6, &basic),
        ];
        for (n, pkg) in holders {
            let sel = hyperion_rpc::wire::HostingSelector::Id(HostingId(ids[n].clone()));
            let _ = svc
                .package_activate(
                    sel,
                    pkg.id,
                    Some(pkg.clone()),
                    Some(now - (n as i64 + 2) * 40 * 86_400),
                )
                .await;
        }
        let period = hyperion_types::care_check::period_key(now);
        let live = hyperion_types::care_check::builtin_check_items();
        for (n, ticks) in [(0usize, 4usize), (1, 4), (3, 2)] {
            let mut checks = hyperion_types::care_check::CareServiceChecks::parse("");
            for item in live.iter().take(ticks) {
                checks.record(&period, &item.id, true, "kevin", "", now, &live);
            }
            sqlx::query("INSERT INTO hosting_kv (hosting_id, key, value, updated_at) VALUES (?, 'care_service_checks', ?, ?)")
                .bind(&ids[n])
                .bind(checks.to_json())
                .bind(now)
                .execute(pool)
                .await
                .expect("care checks");
        }
    }

    // Email log: alerts, customer letters and a test send, with one relay
    // outage and one row in the old `Debug` SMTP-code format.
    // (hosting index, kind, state, to, subject, error, reply, secs ago)
    type DemoMail<'a> = (
        Option<usize>,
        &'a str,
        &'a str,
        &'a str,
        &'a str,
        Option<&'a str>,
        Option<&'a str>,
        i64,
    );
    let mails: [DemoMail; 9] = [
        (Some(4), "monitor", "failed", "ops@digitalka.cz", "DOWN: fit-centrum-brno.cz is not responding", Some("smtp send: Connection error: Connection refused (os error 111)"), None, 25 * 60),
        (Some(4), "monitor", "ok", "ops@digitalka.cz", "UP: fit-centrum-brno.cz is back", None, Some("250 2.0.0 Ok: queued as 4ZQ1xK3mPz"), 15 * 60),
        (None, "test", "ok", "kevin@digitalka.cz", "Hyperion test email", None, Some("250 2.0.0 Ok: queued as 4ZQ0aB9cDe"), 2 * 3600),
        (Some(0), "care_report", "ok", "majitel@studio-lumen.cz", "Měsíční report péče o web — studio-lumen.cz", None, Some("250 2.0.0 Ok: queued as 4ZPz7Yt1Qa"), 26 * 3600),
        (Some(1), "care_report", "ok", "info@pekarna-u-mostu.cz", "Měsíční report péče o web — pekarna-u-mostu.cz", None, Some("250 2.0.0 Ok: queued as 4ZPz7Yt2Rb"), 26 * 3600 + 40),
        (Some(6), "billing", "failed", "objednavky@zahrada-plus.cz", "Faktura za hosting — shop.zahrada-plus.cz", Some("smtp send: permanent error (550): 5.1.1 <objednavky@zahrada-plus.cz>: Recipient address rejected: User unknown in virtual mailbox table"), None, 30 * 3600),
        (Some(3), "quota", "ok", "ops@digitalka.cz", "atelier-hora.com is over its disk quota", None, Some("250 2.0.0 Ok: queued as 4ZPy2Hn8Lw"), 3 * 86_400),
        (Some(2), "expiry", "ok", "kavarna@kavarna-sever.cz", "Váš hosting kavarna-sever.cz brzy vyprší", None, Some("Code { severity: PositiveCompletion, category: MailSystem, detail: Zero }"), 5 * 86_400),
        (None, "test", "failed", "kevin@digitalka.cz", "Hyperion test email", Some("smtp send: Connection error: invalid peer certificate: UnknownIssuer"), None, 6 * 86_400),
    ];
    for (site, kind, state, to, subject, err, reply, ago) in mails {
        hyperion_state::email_log::append(
            pool,
            site.map(|n| ids[n].as_str()),
            to,
            subject,
            "Dobrý den,\n\nposíláme přehled za uplynulý měsíc: zálohy proběhly, certifikát je platný, aktualizace jsou nainstalované.",
            kind,
            state,
            err,
            reply,
            now - ago,
        )
        .await
        .expect("email_log");
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

    // Audit log: sign-ins (one failed), settings and cert changes, a node
    // event, spread over a few days. Appended through the real chain so
    // "Verify chain" passes.
    type DemoAudit<'a> = (i64, &'a str, &'a str, Option<&'a str>, &'a str, &'a str);
    let entries: [DemoAudit; 10] = [
        (
            4 * 86_400,
            "kevin",
            "node.enroll",
            Some("worker-2"),
            r#"{"label":"worker-2","addr":"10.0.0.12"}"#,
            "ok",
        ),
        (
            3 * 86_400 + 600,
            "kevin",
            "web.user.create",
            Some("petra"),
            r#"{"role":"operator"}"#,
            "ok",
        ),
        (
            2 * 86_400 + 4000,
            "agent",
            "cert.renew",
            Some("atelier-hora.com"),
            r#"{"error":"DNS problem: NXDOMAIN looking up A for atelier-hora.com"}"#,
            "failed",
        ),
        (
            2 * 86_400,
            "agent",
            "cert.renew",
            Some("studio-lumen.cz"),
            r#"{"expires_in_days":29}"#,
            "ok",
        ),
        (
            86_400 + 900,
            "petra",
            "hosting.set_limits",
            Some("kavarna-sever.cz"),
            r#"{"domain":"kavarna-sever.cz","php_memory_mb":384,"max_children":12}"#,
            "ok",
        ),
        (
            86_400,
            "agent",
            "php.mem_auto.raise",
            Some("shop.zahrada-plus.cz"),
            r#"{"from_mb":256,"to_mb":384}"#,
            "ok",
        ),
        (
            5400,
            "unknown",
            "web.login.failed",
            Some("admin"),
            r#"{"ip":"203.0.113.7","reason":"bad password"}"#,
            "failed",
        ),
        (
            3000,
            "kevin",
            "web.login.2fa_ok",
            None,
            r#"{"ip":"198.51.100.20"}"#,
            "ok",
        ),
        (
            2400,
            "kevin",
            "firewall.apply_template",
            None,
            r#"{"template":"web","node":"master"}"#,
            "ok",
        ),
        (
            600,
            "kevin",
            "hosting.set_redis",
            Some("pekarna-u-mostu.cz"),
            r#"{"enabled":true}"#,
            "ok",
        ),
    ];
    for (ago, actor, action, target, payload, result) in entries {
        hyperion_state::audit::append(
            pool,
            hyperion_state::audit::AppendReq {
                ts: now - ago,
                actor_uid: if actor == "agent" || actor == "unknown" {
                    0
                } else {
                    1
                },
                actor_label: actor,
                action,
                target,
                payload_json: payload,
                result,
            },
        )
        .await
        .expect("audit");
    }
    seed_demo_waf(svc, &ids, now).await;
}

/// WAF levels, a week of refusals and a few bans, so /protection has a
/// chart, a false-positive suspect, busy addresses and a ban history.
async fn seed_demo_waf(svc: &StubService, ids: &[String], now: i64) {
    use hyperion_types::waf::{WafBatch, WafHit};
    let pool = &svc.pool;
    for (i, level) in [
        (0, "strict"),
        (1, "standard"),
        (2, "standard"),
        (6, "standard"),
    ] {
        sqlx::query("UPDATE hostings SET waf_level = ?, waf_enabled = 1 WHERE id = ?")
            .bind(level)
            .bind(&ids[i])
            .execute(pool)
            .await
            .expect("waf level");
    }
    let hit = |ts: i64, ip: &str, rule: &str, uri: &str, browser: bool| WafHit {
        ts,
        ip: ip.into(),
        rule: rule.into(),
        method: "GET".into(),
        uri: uri.into(),
        ua: if browser {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15"
                .into()
        } else {
            "python-requests/2.31".into()
        },
        browser,
        ..Default::default()
    };
    // (site, rule, address, request, browser, hits per busy hour)
    let streams: [(usize, &str, &str, &str, bool, i64); 7] = [
        (
            0,
            "probe_args",
            "185.220.101.34",
            "/?id=1%27%20OR%201=1--",
            false,
            7,
        ),
        (
            0,
            "scanner_ua",
            "45.148.10.92",
            "/wp-content/plugins/",
            false,
            3,
        ),
        (0, "author_enum", "89.24.17.150", "/?author=2", true, 2),
        (1, "sensitive_files", "194.26.192.77", "/.env", false, 4),
        (1, "dotfiles", "194.26.192.77", "/.git/config", false, 2),
        (
            2,
            "probe_args",
            "185.220.101.34",
            "/index.php?page=../../etc/passwd",
            false,
            3,
        ),
        (6, "xmlrpc", "103.152.220.11", "/xmlrpc.php", false, 5),
    ];
    for (si, (site, rule, ip, uri, browser, per_hour)) in streams.iter().enumerate() {
        let mut hits = Vec::new();
        for h in 0..(7 * 24) {
            // Bursty, not flat: a few busy stretches a day.
            let wave = (h as i64 * 7 + si as i64 * 13) % 24;
            if wave > 9 {
                continue;
            }
            let n = per_hour * (1 + (wave % 3));
            let base = now - (7 * 24 - h as i64) * 3600;
            for k in 0..n {
                // Real browsers come from many addresses, scanners from one.
                let ip = if *browser {
                    format!("89.24.{}.{}", 17 + k % 5, 100 + (h as i64 % 50))
                } else {
                    ip.to_string()
                };
                hits.push(hit(base + k * 37 % 3600, &ip, rule, uri, *browser));
            }
        }
        hyperion_state::waf::record(pool, &ids[*site], &WafBatch::from_hits(hits))
            .await
            .expect("waf hits");
    }
    use hyperion_state::bans;
    let ban = |ip: &'static str, site: Option<usize>, reason: &'static str, ago: i64, ttl: i64| {
        let hosting = site.map(|i| ids[i].clone());
        async move {
            bans::add_or_refresh(
                pool,
                ip,
                hosting.as_deref(),
                reason,
                if reason.starts_with("auto") {
                    "auto"
                } else {
                    "manual"
                },
                now - ago,
                if ttl == 0 { 0 } else { now - ago + ttl },
            )
            .await
            .expect("ban");
        }
    };
    ban(
        "185.220.101.34",
        Some(0),
        "auto: WAF refusals",
        3 * 86_400,
        3600,
    )
    .await;
    ban(
        "194.26.192.77",
        Some(1),
        "auto: WAF refusals",
        2 * 86_400,
        3600,
    )
    .await;
    ban(
        "61.177.172.140",
        None,
        "auto: ssh brute force",
        86_400,
        3600,
    )
    .await;
    ban(
        "103.152.220.11",
        Some(6),
        "auto: wp-login / xmlrpc brute force",
        20 * 3600,
        3600,
    )
    .await;
    ban(
        "80.94.95.15",
        None,
        "manual: spam relay attempts",
        5 * 86_400,
        0,
    )
    .await;
    bans::deactivate(pool, "80.94.95.15", now - 4 * 86_400)
        .await
        .expect("lift");
    bans::reap_expired(pool, now).await.expect("reap");
    // In force right now.
    ban(
        "185.220.101.34",
        Some(0),
        "auto: WAF refusals",
        900,
        24 * 3600,
    )
    .await;
    ban("61.177.172.140", None, "auto: ssh brute force", 300, 3600).await;
    ban(
        "5.188.62.214",
        None,
        "manual: credential stuffing",
        2 * 86_400,
        0,
    )
    .await;
}

/// `DEVSERVER_DEMO_NODES=1`: enroll three fake worker nodes so the Nodes
/// page renders every row state — healthy, drained + test, and one that
/// stopped checking in without pins. Kept apart from `DEVSERVER_DEMO`:
/// nothing answers on their addresses, so every cluster fan-out (hostings
/// list, stats) would show them as offline in the README screenshots.
async fn seed_demo_nodes(svc: &StubService) {
    let pool = &svc.pool;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let nodes: [(&str, &str, &str, i64, Option<&str>); 3] = [
        (
            "web-2",
            "web-2.example.net",
            "203.0.113.12",
            now - 20,
            Some("pin"),
        ),
        (
            "web-3",
            "web-3.example.net",
            "203.0.113.13",
            now - 40,
            Some("pin"),
        ),
        (
            "stage-1",
            "stage-1.example.net",
            "203.0.113.40",
            now - 2 * 3600,
            None,
        ),
    ];
    for (id, label, ip, seen, pin) in nodes {
        sqlx::query(
            "INSERT INTO nodes (node_id, label, enrolled_at, last_seen_at, agent_version, \
             public_ip, enrolled_via, tls_spki_pin, resp_pubkey) VALUES (?, ?, ?, ?, ?, ?, 'demo', ?, ?)",
        )
        .bind(id)
        .bind(label)
        .bind(now - 40 * 86_400)
        .bind(seen)
        .bind(env!("CARGO_PKG_VERSION"))
        .bind(ip)
        .bind(pin)
        .bind(pin)
        .execute(pool)
        .await
        .expect("demo node");
    }
    sqlx::query(
        "INSERT INTO node_drain (node_id, drained_at, reason) VALUES ('web-3', ?, 'Disk swap')",
    )
    .bind(now - 3600)
    .execute(pool)
    .await
    .expect("drain");
}

/// `DEVSERVER_DEMO=1`: a bell's worth of notifications. They belong to a web
/// user, and the first login is what creates that row — so this waits for an
/// admin to exist, then writes the set once (two of them as if collected from
/// a worker).
fn seed_demo_notifications(pool: sqlx::SqlitePool) {
    tokio::spawn(async move {
        let uid = loop {
            let row: Option<(i64,)> = sqlx::query_as(
                "SELECT id FROM web_users WHERE role IN ('super_admin','admin') ORDER BY id LIMIT 1",
            )
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();
            if let Some((id,)) = row {
                break id;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        };
        let now = hyperion_types::now_secs();
        // (severity, title, body, href, kind, seconds ago, read)
        let demo: [(&str, &str, &str, &str, &str, i64, bool); 11] = [
            ("error", "Site is down", "fit-centrum-brno.cz failed its uptime checks — last error: connection refused", "/hostings/fit-centrum-brno.cz", "monitor.down:fit-centrum-brno.cz", 25 * 60, false),
            ("warn", "A WordPress update was paused", "studio-lumen.cz — woocommerce 9.4 broke the home page in the test run and was rolled back.", "/hostings/studio-lumen.cz#wordpress", "wp.update.paused:x:woocommerce", 2 * 3600, false),
            ("info", "PHP memory raised", "pekarna-u-mostu.cz ran out of PHP memory; the limit went from 256 MB to 384 MB (ceiling 512 MB).", "/hostings/pekarna-u-mostu.cz", "php_mem_auto", 5 * 3600, true),
            ("warn", "Site over its disk quota", "atelier-hora.com uses 10420 MiB of 10240 MiB — over its disk quota.", "/hostings/atelier-hora.com", "quota.over:atelier-hora.com", 26 * 3600, false),
            ("error", "Certificate renewal failed", "kavarna-sever.cz — the certificate expires in 6 days and renewal failed: DNS problem: NXDOMAIN looking up A for www.kavarna-sever.cz", "/hostings/kavarna-sever.cz#ssl", "cert.renew_failed:kavarna-sever.cz", 30 * 3600, true),
            ("info", "Site is back up", "fit-centrum-brno.cz passes its uptime checks again.", "/hostings/fit-centrum-brno.cz", "monitor.up:fit-centrum-brno.cz", 50 * 3600, true),
            ("warn", "Hosting moved to trash", "old-promo.cz will be deleted for good after the trash retention window.", "/trash", "hosting.trash", 3 * 86_400, true),
            ("warn", "Sign-up flood on a WordPress site", "pekarna-u-mostu.cz — 212 WordPress sign-ups in the last scan window from 87 address(es).", "/hostings/pekarna-u-mostu.cz#wordpress", "wp.signup_flood:pekarna-u-mostu.cz", 4 * 86_400, true),
            ("error", "Pages on this site are broken", "shop.zahrada-plus.cz — the automatic page check found 3 page(s) that do not work: /kosik, /pokladna, /ucet", "/hostings/shop.zahrada-plus.cz", "site_check_broken", 6 * 86_400, true),
            ("info", "Certificate renewed late", "atelier-hora.com renewed 3 days before expiry after earlier failures.", "/hostings/atelier-hora.com#ssl", "cert.renewed_late:atelier-hora.com", 8 * 86_400, true),
            ("warn", "Site mail is failing", "studio-lumen.cz — 4 contact-form emails failed to send in the last hour.", "/hostings/studio-lumen.cz", "wp_mail_failing", 9 * 86_400, true),
        ];
        for (sev, title, body, href, kind, ago, read) in demo {
            let id = hyperion_state::notifications::insert(
                &pool,
                uid,
                sev,
                title,
                body,
                href,
                kind,
                now - ago,
            )
            .await
            .expect("notification");
            if read {
                hyperion_state::notifications::mark_read(&pool, uid, id, now)
                    .await
                    .expect("read");
            }
        }
        // As if collected from a worker's outbox.
        for (id, sev, title, body, kind, ago) in [
            (1, "error", "Root filesystem is read-only", "web-2: the root filesystem went read-only. Writes fail until it is repaired — see Services → Read-only rootfs.", "system.rofs", 40 * 60),
            (2, "warn", "PHP workers are all busy", "eshop-velo.cz hit pm.max_children (12) 9 times in the last hour.", "php_workers", 7 * 3600),
        ] {
            let row = hyperion_state::notifications::OutboxRow {
                id,
                severity: sev.into(),
                title: title.into(),
                body: body.into(),
                href: "/services".into(),
                kind: kind.into(),
                created_at: now - ago,
            };
            hyperion_state::notifications::insert_from_node(&pool, uid, "web-2", &row)
                .await
                .expect("node notification");
        }
    });
}

#[tokio::test]
#[ignore]
async fn devserver() {
    let admin = admin_user::create("kevin", "secret-pw-1").expect("create");
    let (sock, _dir, svc) = start_agent_with_service().await;
    if std::env::var_os("DEVSERVER_DEMO").is_some() {
        seed_demo(&svc).await;
    }
    if std::env::var_os("DEVSERVER_DEMO_NODES").is_some() {
        seed_demo_nodes(&svc).await;
    }
    if std::env::var_os("DEVSERVER_DEMO").is_some() {
        seed_demo_notifications(svc.pool.clone());
    }
    let (router, _signer) =
        build_app_with_signer(sock, admin, Arc::new(SessionSigner::new_random()));
    // PORT too: the desktop preview hands an auto-assigned port that way.
    let port = std::env::var("DEVSERVER_PORT")
        .or_else(|_| std::env::var("PORT"))
        .unwrap_or_else(|_| "8190".into());
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
