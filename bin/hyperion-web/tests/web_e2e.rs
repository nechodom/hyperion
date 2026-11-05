//! End-to-end test: real hyperion-agent in a fixture + real hyperion-web router +
//! cookie-jar HTTP client simulating a browser. Validates the whole
//! login → dashboard → create hosting → delete cycle.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
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
use tower::ServiceExt;

/// Stands in for public DNS: nothing is delegated and no CNAME exists,
/// and no test sends a query off the machine.
struct OfflineDns;

const OFFLINE_DNS: &str = "offline test resolver";

#[async_trait]
impl hyperion_web::acme_dns_renew::DnsProbe for OfflineDns {
    async fn zone_delegated(&self, zone: &str, _check_token: &str) -> Result<(), String> {
        Err(format!(
            "_hyperion-check.{zone} does not exist: the zone is not delegated to this panel ({OFFLINE_DNS})"
        ))
    }
    async fn cname(
        &self,
        _name: &str,
        _target: &str,
    ) -> Result<(), hyperion_adapters::dns_probe::CnameProblem> {
        Err(hyperion_adapters::dns_probe::CnameProblem::Other(
            OFFLINE_DNS.into(),
        ))
    }
    async fn txt_visible(&self, _name: &str, _values: &[String]) -> Result<(), String> {
        Err(OFFLINE_DNS.into())
    }
}

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
    /// Only `docker logs` answers, so the log viewer has something to draw:
    /// one line that is markup and one that is plain.
    async fn docker_read(
        &self,
        cmd: hyperion_adapters::docker::DockerCmd,
        _max_bytes: usize,
    ) -> Result<Vec<u8>, hyperion_adapters::docker::DockerError> {
        match cmd {
            hyperion_adapters::docker::DockerCmd::Logs { .. } => Ok(
                b"2024-05-01T10:00:01.000000000Z <script>alert(1)</script> \x1b[31mred\x1b[0m\n\
                  2024-05-01T10:00:02.000000000Z second line\n"
                    .to_vec(),
            ),
            _ => Err(hyperion_adapters::docker::DockerError::NotInstalled),
        }
    }
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
        let h: String = hosting_id.as_str().chars().take(6).collect();
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
    async fn wp_install_base_theme(&self, _: &str, _: &str) -> Result<String, AdapterError> {
        Ok("twentytwentyfive".into())
    }
    async fn wp_cron_run(
        &self,
        _system_user: &str,
        _htdocs: &str,
    ) -> Result<(), hyperion_adapters::AdapterError> {
        Ok(())
    }
    async fn wp_core_check_update(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Vec<hyperion_types::WpCoreUpdate>, AdapterError> {
        Ok(vec![])
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
    let (path, dir, _pool) = start_agent_with_pool().await;
    (path, dir)
}

/// [`start_agent`] that also hands back the agent's database, for tests that
/// seed rows no RPC writes directly (the email log).
async fn start_agent_with_pool() -> (PathBuf, tempfile::TempDir, sqlx::SqlitePool) {
    start_agent_with(None).await
}

/// [`start_agent`] with an agent.toml holding `toml`, for tests that save
/// settings through the agent and read the file back. Returns the socket,
/// the temp dir guard and the agent.toml path (inside that dir).
async fn start_agent_with_toml(toml: &str) -> (PathBuf, tempfile::TempDir, PathBuf) {
    let (sock, dir, _pool) = start_agent_with(Some(toml)).await;
    let cfg = dir.path().join("agent.toml");
    (sock, dir, cfg)
}

async fn start_agent_with(toml: Option<&str>) -> (PathBuf, tempfile::TempDir, sqlx::SqlitePool) {
    start_agent_full(toml, None).await
}

/// [`start_agent_with`] whose Docker module already holds `snapshot` as the
/// last thing the daemon said, so `/docker` has stacks to draw without a
/// real daemon.
async fn start_agent_full(
    toml: Option<&str>,
    snapshot: Option<hyperion_types::docker::DockerNodeStatus>,
) -> (PathBuf, tempfile::TempDir, sqlx::SqlitePool) {
    let dir = tempfile::tempdir().expect("dir");
    let agent_config_path = toml.map(|t| {
        let p = dir.path().join("agent.toml");
        std::fs::write(&p, t).expect("agent.toml");
        p
    });
    let pool = open_memory().await.expect("memory db");
    let db = pool.clone();
    let secrets = Arc::new(SecretsStore::new(dir.path().join("secrets")));
    let svc = Arc::new(HostingService::<StubAdapters> {
        pool,
        adapters: Arc::new(StubAdapters::new()),
        secrets,
        paths: hyperion_core::HostingPaths::default(),
        permissions_autoheal: true,
        snapshots_enabled: false,
        fpm_own_masters: false,
        cpu_tracker: Default::default(),
        protection_mode: hyperion_types::ProtectionMode::Both,
        remote_backup: None,
        retention: hyperion_core::BackupRetention::default(),
        slack_default_webhook: None,
        acme_contact_email: "test@example.invalid".into(),
        email_config: None,
        email_default_to: None,
        fail2ban: hyperion_core::Fail2banConfig::default(),
        agent_config_path,
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
        docker_snapshot: Arc::new(tokio::sync::RwLock::new(snapshot)),
        docker_log_gate: hyperion_core::service::new_docker_log_gate(),
    });
    let agent: Arc<dyn AgentApi> = Arc::new(AgentImpl::new(svc));
    let path = dir.path().join("agent.sock");
    let srv = hyperion_rpc_server::Server::bind(&path, agent)
        .await
        .expect("bind");
    tokio::spawn(srv.run());
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (path, dir, db)
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
    let state = test_state(agent_socket, admin, signer.clone());
    // The login/2FA + enroll handlers extract `ConnectInfo<SocketAddr>` (real
    // peer IP for the rate-limit bucket). `.oneshot()` doesn't go through
    // `into_make_service_with_connect_info`, so inject a mock peer addr the same
    // way axum's own tests do — otherwise those handlers 500 on extraction.
    let router =
        hyperion_web::build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
            "127.0.0.1:34567".parse::<std::net::SocketAddr>().unwrap(),
        ));
    (router, signer)
}

fn test_state(
    agent_socket: PathBuf,
    admin: AdminUser,
    signer: Arc<SessionSigner>,
) -> hyperion_web::state::SharedState {
    test_state_with_setup(
        agent_socket,
        admin,
        signer,
        Arc::new(hyperion_web::setup::SetupCtl::inactive(PathBuf::from(
            "/nonexistent/setup.json",
        ))),
    )
}

fn test_state_with_setup(
    agent_socket: PathBuf,
    admin: AdminUser,
    signer: Arc<SessionSigner>,
    setup: Arc<hyperion_web::setup::SetupCtl>,
) -> hyperion_web::state::SharedState {
    let cfg = Config::default();
    let csrf_key: [u8; 32] = {
        let mut k = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut k);
        k
    };
    Arc::new(AppState {
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
        wp_lists: Default::default(),
        caches: Default::default(),
        setup,
        cluster_sync: Default::default(),
        dns_probe: hyperion_web::acme_dns_renew::DnsProbes::new(Arc::new(OfflineDns)),
    })
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect")
        .to_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

#[tokio::test]
async fn login_page_renders_without_auth() {
    let admin = admin_user::create("kevin", "secret-pw-1").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Sign in"), "body: {body}");
    assert!(body.contains("name=\"username\""));
    assert!(body.contains("name=\"password\""));
}

async fn get_body(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("call");
    let status = resp.status();
    (status, body_string(resp).await)
}

/// The sign-in page words its own messages. An unknown `?error=` used to be
/// printed verbatim, so any link could put text of its choosing on the real
/// panel's sign-in page.
#[tokio::test]
async fn login_page_never_echoes_an_unknown_error() {
    let admin = admin_user::create("kevin", "secret-pw-1").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let (status, body) = get_body(
        app.clone(),
        "/login?error=Your+account+is+compromised+call+555",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("compromised"), "query text echoed: {body}");
    assert!(
        body.contains("Sign-in didn&#x27;t go through")
            || body.contains("Sign-in didn't go through")
    );

    // Known codes still get their wording; notices only without an error.
    let (_, body) = get_body(app.clone(), "/login?notice=signed_out").await;
    assert!(
        body.contains("You&#x27;re signed out") || body.contains("You're signed out"),
        "{body}"
    );
    let (_, body) = get_body(app.clone(), "/login?notice=whatever").await;
    assert!(
        !body.contains("flash success"),
        "unknown notice rendered: {body}"
    );
    let (_, body) = get_body(app, "/login?error=locked&notice=signed_out").await;
    assert!(body.contains("account is locked"));
    assert!(!body.contains("flash success"));
}

/// A bounced deep link tells the person where they'll land; the dashboard
/// and anything `redirect_target` would clamp say nothing.
#[tokio::test]
async fn login_page_names_the_return_path() {
    let admin = admin_user::create("kevin", "secret-pw-1").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let (_, body) = get_body(app.clone(), "/login?next=%2Fhostings%2Fexample.com").await;
    assert!(body.contains("login-return"), "{body}");
    assert!(
        body.contains("<code title=\"/hostings/example.com\">"),
        "{body}"
    );
    for next in ["%2F", "%2F%2Fevil.com", ""] {
        let (_, body) = get_body(app.clone(), &format!("/login?next={next}")).await;
        assert!(!body.contains("login-return"), "next={next}: {body}");
    }
}

/// Past the limit the panel answers with its own sign-in page (429 +
/// Retry-After), quoting what is left of the 15-minute window — it used to
/// return bare text promising "5 minutes".
#[tokio::test]
async fn throttled_login_renders_the_page_with_the_real_wait() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let state = test_state(sock, admin, Arc::new(SessionSigner::new_random()));
    // Own peer address: the throttle is process-wide, keyed by peer IP, and
    // every other test logs in from 127.0.0.1.
    let app =
        hyperion_web::build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
            "10.98.76.54:4000".parse::<std::net::SocketAddr>().unwrap(),
        ));
    let attempt = || {
        Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                &b"username=kevin&password=wrong&next=%2Fbans"[..],
            ))
            .unwrap()
    };
    for _ in 0..5 {
        let r = app.clone().oneshot(attempt()).await.expect("call");
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
    }
    let r = app.oneshot(attempt()).await.expect("call");
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: i64 = r.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry > 14 * 60 && retry <= 15 * 60, "retry-after {retry}");
    let body = body_string(r).await;
    assert!(
        body.contains("name=\"password\""),
        "not the sign-in page: {body}"
    );
    assert!(body.contains("Try again in 15 minutes"), "{body}");
    // The deep link survives the refusal too.
    assert!(body.contains("value=\"/bans\""), "{body}");
}

#[tokio::test]
async fn unauthenticated_dashboard_redirects_to_login() {
    let admin = admin_user::create("kevin", "secret-pw-1").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get(header::LOCATION).expect("location");
    assert!(loc.to_str().expect("ascii").starts_with("/login"));
}

/// A job page's 2-second progress poll outliving the session used to get a
/// 302 to /login, which the XHR followed — and htmx swapped the whole
/// sign-in page into the progress card. htmx must get a whole-window
/// navigation back to the PAGE (not the fragment) instead.
#[tokio::test]
async fn unauthenticated_htmx_poll_navigates_window_to_login() {
    let admin = admin_user::create("kevin", "secret-pw-1").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/jobs/01ABC/progress")
                .header("HX-Request", "true")
                .header("HX-Current-URL", "https://panel.example/jobs/01ABC?tab=log")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(resp.headers().get(header::LOCATION).is_none());
    let to = resp.headers().get("HX-Redirect").expect("HX-Redirect");
    assert_eq!(
        to.to_str().expect("ascii"),
        "/login?next=%2Fjobs%2F01ABC%3Ftab%3Dlog"
    );

    // A handler's own 302 to /login followed by the XHR: the login page
    // must not render into the swap target either.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .header("HX-Request", "true")
                .header("HX-Current-URL", "https://panel.example/profile")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let to = resp.headers().get("HX-Redirect").expect("HX-Redirect");
    assert_eq!(to.to_str().expect("ascii"), "/login?next=%2Fprofile");
}

#[tokio::test]
async fn bad_login_redirects_with_error() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let body = b"username=kevin&password=wrong&next=/";
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .expect("loc")
        .to_str()
        .unwrap();
    assert!(loc.contains("error=invalid"), "loc: {loc}");
    assert!(loc.contains("next=%2F"), "loc: {loc}");
}

#[tokio::test]
async fn login_sets_cookie_and_redirect_to_next() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let body = b"username=kevin&password=good-pw&next=/hostings";
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get(header::LOCATION).expect("loc");
    assert_eq!(loc.to_str().expect("ascii"), "/hostings");
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie")
        .to_str()
        .expect("ascii");
    assert!(cookie.starts_with("hyperion_session="));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn open_redirect_via_next_blocked() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    // External URL as next — should be rewritten to "/"
    let body = b"username=kevin&password=good-pw&next=https%3A%2F%2Fevil.example.com%2F";
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let loc = resp.headers().get(header::LOCATION).unwrap();
    assert_eq!(loc.to_str().unwrap(), "/");
}

#[tokio::test]
async fn authenticated_dashboard_renders() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    // Login
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);
    // Fetch dashboard with cookie
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Dashboard"));
    assert!(body.contains("kevin"));
    // Agent info reachable
    assert!(body.contains("Agent"));
}

#[tokio::test]
async fn static_css_is_served() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/app.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/css"));
    let body = body_string(resp).await;
    assert!(body.contains("--bg"), "missing CSS vars");
}

#[tokio::test]
async fn static_htmx_is_served() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/htmx.min.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("application/javascript"));
}

#[tokio::test]
async fn static_app_js_is_served_gzipped_and_cacheable() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/app.js")
                .header(header::ACCEPT_ENCODING, "gzip, br")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_ENCODING], "gzip");
    assert!(resp.headers()[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .contains("immutable"));
    let etag = resp.headers()[header::ETAG].clone();
    // A revalidation with that tag is answered without a body.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static/app.js")
                .header(header::IF_NONE_MATCH, etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn create_hosting_via_form_succeeds() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    // Log in
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);

    // Get the new-hosting form to grab a CSRF token.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let form_body = body_string(resp).await;
    let csrf = extract_csrf(&form_body);

    // POST the form
    let body = format!(
        "_csrf={csrf}&domain=web-e2e.cz&aliases=www.web-e2e.cz&php=8.3&db=mariadb&system_user="
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let detail = body_string(resp).await;
    assert!(detail.contains("web-e2e.cz"));
    assert!(detail.contains("TEST-PASSWORD-DONT-USE")); // shown once
    assert!(detail.contains("Provisioned"));

    // List should show the hosting
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/hostings")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let body = body_string(resp).await;
    assert!(body.contains("web-e2e.cz"));
    assert!(body.contains("active"));
}

#[tokio::test]
async fn create_without_csrf_is_403() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    // Log in
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);

    let body = "domain=no-csrf.cz&php=8.3&db=mariadb";
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn audit_page_renders_with_entries_after_create() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);

    // Create hosting → also creates an audit entry via service-level append
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let csrf = extract_csrf(&body_string(resp).await);
    let body =
        format!("_csrf={csrf}&domain=audit-test.cz&aliases=&php=8.3&db=mariadb&system_user=");
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");

    // Suspend → audit entry should be visible
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/audit-test.cz")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let suspend_csrf = extract_csrf_named(&body_string(resp).await, "/hostings/suspend");
    let body = format!("_csrf={suspend_csrf}&selector=audit-test.cz&reason=test+suspend");
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings/suspend")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");

    let get = |uri: &'static str| {
        let app = app.clone();
        let cookie = cookie.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("call")
        }
    };

    // Fetch the audit page
    let resp = get("/audit").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Audit log"));
    assert!(body.contains("hosting.suspend"), "body: {body}");

    // The search and the segments run on the agent (AuditSearch).
    let body = body_string(get("/audit?q=audit-test.cz&cat=sites").await).await;
    assert!(body.contains("hosting.suspend"), "sites segment: {body}");
    let body = body_string(get("/audit?cat=certs").await).await;
    assert!(
        !body.contains("<code>hosting.suspend</code>"),
        "certs segment: {body}"
    );
    assert!(
        body.contains("No entries match these filters"),
        "certs segment: {body}"
    );

    // CSV export carries the same entry, as an attachment.
    let resp = get("/audit?q=audit-test.cz&export=csv").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("attachment;")));
    let csv = body_string(resp).await;
    assert!(csv.starts_with("id,node,time_utc,"), "csv: {csv}");
    assert!(csv.contains("\"hosting.suspend\""), "csv: {csv}");
}

/// Pull the FIRST csrf token whose surrounding form action matches `path`.
/// This lets a single rendered page hand out distinct tokens per form.
fn extract_csrf_named(html: &str, action_path: &str) -> String {
    let needle = format!("action=\"{action_path}\"");
    let action_idx = html
        .find(&needle)
        .unwrap_or_else(|| panic!("form action {action_path} not in page"));
    // search backwards or forwards for the matching _csrf input within the form
    let form_close = html[action_idx..]
        .find("</form>")
        .map(|n| n + action_idx)
        .unwrap_or(html.len());
    let scope = &html[action_idx..form_close];
    let csrf_needle = "name=\"_csrf\" value=\"";
    let i = scope
        .find(csrf_needle)
        .unwrap_or_else(|| panic!("csrf missing in form action={action_path}"));
    let start = i + csrf_needle.len();
    let end = scope[start..].find('"').expect("quote") + start;
    scope[start..end].to_string()
}

#[tokio::test]
async fn invalid_domain_re_renders_form_with_error() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let csrf = extract_csrf(&body_string(resp).await);
    let body = format!("_csrf={csrf}&domain=BAD%20DOMAIN&aliases=&php=8.3&db=mariadb&system_user=");
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("invalid domain"), "body: {body}");
    assert!(body.contains("BAD DOMAIN")); // value preserved
}

/// `/api/search?q=` returns a JSON envelope with hostings + users
/// substring-matching the query. Behind require_auth — anonymous
/// requests get redirected. Locks in the contract the ⌘K command
/// palette depends on.
#[tokio::test]
async fn api_search_returns_json_envelope() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/search?q=kev")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    // Schema check — both keys present even if empty.
    assert!(body.contains("\"hostings\""), "body: {body}");
    assert!(body.contains("\"users\""), "body: {body}");
}

#[tokio::test]
async fn api_search_requires_auth() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/search?q=x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    // No cookie → middleware redirects to /login.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

/// /login/2fa renders the new split-shell layout with the 6-box OTP
/// input. The page is reachable without a pending-2fa cookie (the
/// server only enforces the cookie on POST); GET just shows the form.
/// Locks in the contract that the redesigned template ships.
#[tokio::test]
async fn login_2fa_page_renders_otp_boxes_and_split_shell() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login/2fa?next=/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    // Split shell — the aside + the form column both render.
    assert!(body.contains("login-shell"), "missing split shell");
    assert!(body.contains("login-aside"), "missing aside");
    assert!(body.contains("login-step-trail"), "missing step trail");
    // 6 separate OTP boxes (data-otp-idx 0..=5).
    for i in 0..6 {
        let needle = format!("data-otp-idx=\"{i}\"");
        assert!(body.contains(&needle), "missing otp box {i}: {body}");
    }
    // The backup-code form + toggle are both there but hidden by default.
    assert!(body.contains("id=\"toggle-mode\""), "missing toggle");
    assert!(body.contains("id=\"backup-form\""), "missing backup form");
    // Back-to-sign-in link preserves next=.
    assert!(body.contains("href=\"/login?next=/"), "missing back link");
}

/// /login/2fa?error=invalid renders the friendly error message —
/// not the raw "invalid" string. Regression test for the audit
/// finding that the template was dumping the raw error code.
#[tokio::test]
async fn login_2fa_renders_friendly_invalid_error() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/login/2fa?error=invalid&next=/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let body = body_string(resp).await;
    // Friendly, human message — never the raw "invalid" error code.
    assert!(
        body.contains("That code didn't match"),
        "expected the friendly invalid-code message, got body: {body}"
    );
    assert!(
        !body.contains(">invalid<"),
        "the raw error code must not be dumped into the page"
    );
}

/// CSRF token accepted from the `X-CSRF-Token` header. Verifies the
/// new header-based path added so HTMX / fetch clients don't have to
/// embed the token in the body. Uses a real authenticated session.
#[tokio::test]
async fn csrf_via_x_csrf_token_header_is_accepted() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);
    // Grab a token off /hostings/new — that page injects the session-wide
    // wildcard CSRF token, which the middleware accepts on any path.
    let form = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let html = body_string(form).await;
    let csrf = extract_csrf(&html);
    // POST a delete with the token ONLY in the header, NOT in the body.
    let body = "selector=does-not-exist";
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings/delete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");
    // Header carried CSRF — middleware passes. Handler then 404s or
    // 400s on the selector (we sent a bogus one); the point is it
    // ISN'T 403.
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "header CSRF should be accepted",
    );
}

/// CSRF token accepted from a `?_csrf=…` query string. This is the path
/// multipart file uploads take — the middleware can't parse a 2 GB
/// upload body to find a hidden form field.
#[tokio::test]
async fn csrf_via_query_string_is_accepted() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);
    let form = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let html = body_string(form).await;
    let csrf = extract_csrf(&html);
    // The token goes in the URL — not the body.
    let urlencoded_csrf: String = url::form_urlencoded::byte_serialize(csrf.as_bytes()).collect();
    let uri = format!("/hostings/delete?_csrf={urlencoded_csrf}");
    let body = "selector=does-not-exist";
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "query-string CSRF should be accepted",
    );
}

/// Logout POST is exempted from CSRF — the base-layout button has no
/// `_csrf` field (and shouldn't need one — a forged logout is annoying,
/// not a vulnerability). Verifies the exemption works.
#[tokio::test]
async fn logout_post_is_exempt_from_csrf() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);
    // No CSRF token. Just a bare logout POST.
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/logout")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    // Logout redirects to /login on success, which then says so.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get(header::LOCATION).expect("loc");
    assert_eq!(loc.to_str().unwrap(), "/login?notice=signed_out");
}

/// Security regression: the pending-2FA cookie and the full-session
/// cookie share the same Ed25519 signer. If `extract_auth` does not
/// gate on the token's `purpose` field, an attacker who knows only the
/// password (no TOTP) can take the `hyperion_session_pending2fa` value
/// from `Set-Cookie` and replant it as `hyperion_session`, bypassing
/// the second factor entirely. This test mints a `pending_2fa`-purpose
/// token, plants it in the session cookie slot, and asserts the app
/// refuses to authenticate it.
#[tokio::test]
async fn pending_2fa_token_in_session_cookie_slot_is_rejected() {
    use hyperion_auth::{Session, PURPOSE_PENDING_2FA};

    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let signer = Arc::new(SessionSigner::new_random());
    let (app, signer) = build_app_with_signer(sock, admin, signer);

    let now = hyperion_types::now_secs();
    let pending = Session {
        sid: "p2fa-test".into(),
        user_id: 1,
        created_at: now,
        expires_at: now + 300,
        username: String::new(),
        role: "pending_2fa".into(),
        purpose: PURPOSE_PENDING_2FA.into(),
        caps: 0,
        scope_all: false,
        caps_present: false,
    };
    let token = signer.sign(&pending).expect("sign");
    let cookie = format!("hyperion_session={token}");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    // require_auth must redirect to /login — NOT serve the dashboard.
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "pending-2FA token must not authenticate as a full session",
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .expect("loc")
        .to_str()
        .unwrap();
    assert!(loc.starts_with("/login"), "redirect target: {loc}");
}

/// RBAC regression: a viewer-role user must NOT be able to mutate
/// hostings via direct POST, even with a valid session + CSRF. Before
/// the per-hosting access guards landed, the role-gating in the
/// templates was the ONLY barrier — anyone with `require_auth` could
/// hand-craft `POST /hostings/delete` and the handler would run.
#[tokio::test]
async fn viewer_cannot_delete_hosting_via_direct_post() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);

    // 1. Log in as bootstrap admin (creates the super_admin DB row).
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let admin_cookie = extract_cookie(&resp);

    // 2. Create a target hosting that the viewer will try to delete.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let csrf = extract_csrf(&body_string(resp).await);
    let body =
        format!("_csrf={csrf}&domain=rbac-victim.cz&aliases=&php=8.3&db=mariadb&system_user=");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Create a viewer-role user directly via RPC.
    let create_resp = hyperion_rpc_client::call(
        &sock,
        hyperion_rpc::codec::Request::WebUserCreate {
            username: "rbac-viewer".into(),
            email: "rbac-viewer@example.invalid".into(),
            password: "viewer-pw-1".into(),
            role: "viewer".into(),
        },
    )
    .await
    .expect("create viewer");
    match create_resp {
        hyperion_rpc::codec::Response::WebUserCreate { .. } => {}
        other => panic!("unexpected create response: {:?}", other),
    }

    // 4. Log in as the viewer.
    let viewer_login = b"username=rbac-viewer&password=viewer-pw-1&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(viewer_login.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let viewer_cookie = extract_cookie(&resp);

    // 5. Grab a session-wide CSRF token bound to the viewer's session.
    //    /hostings would render one normally, but a viewer with no
    //    access grants sees the empty-state branch which omits the
    //    `_csrf` input. /profile is always accessible to a logged-in
    //    user and includes the token.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/profile")
                .header(header::COOKIE, &viewer_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let viewer_csrf = extract_csrf(&body_string(resp).await);

    // 6. Viewer attempts to delete the admin-owned hosting. Must 403.
    let delete_body = format!("_csrf={viewer_csrf}&selector=rbac-victim.cz");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings/delete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &viewer_cookie)
                .body(Body::from(delete_body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "viewer-role user must NOT be able to delete a hosting they have no grant for",
    );

    // 7. Confirm the hosting still exists by listing as the admin again.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/hostings")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("rbac-victim.cz"),
        "hosting should still exist after viewer's failed delete",
    );
}

/// /emails: empty state first, then a seeded log — kind labels instead of
/// raw ids, the failure verdict, the outcome/search filters, and an old
/// row's `Debug`-formatted SMTP code decoded back to "250".
#[tokio::test]
async fn emails_page_renders_with_filters() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock, admin);
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("login");
    let cookie = extract_cookie(&resp);
    let get = |uri: &'static str| {
        let app = app.clone();
        let cookie = cookie.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("call");
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            body_string(resp).await
        }
    };

    let body = get("/emails").await;
    assert!(body.contains("Email log"), "missing page title");
    assert!(body.contains("No emails sent yet"), "missing empty state");

    let now = hyperion_types::now_secs();
    let seed = [
        (
            "test",
            "ok",
            "Hyperion test email",
            None,
            Some("Code { severity: PositiveCompletion, category: MailSystem, detail: Zero }"),
            now - 300,
        ),
        (
            "monitor",
            "failed",
            "Site down: shop.example.cz",
            Some("smtp send: Connection refused (os error 111)"),
            None,
            now - 120,
        ),
        (
            "care_report",
            "ok",
            "Monthly care report",
            None,
            Some("250 2.0.0 Ok: queued as 4ZQ1x"),
            now - 60,
        ),
    ];
    for (kind, st, subject, err, code, at) in seed {
        hyperion_state::email_log::append(
            &pool,
            None,
            "ops@example.cz",
            subject,
            "body",
            kind,
            st,
            err,
            code,
            at,
        )
        .await
        .expect("seed email");
    }

    let body = get("/emails").await;
    for label in ["Test email", "Uptime alert", "Care report"] {
        assert!(body.contains(label), "kind label {label} missing");
    }
    assert!(
        body.contains("1 email failed out of 3 in the last 24 hours"),
        "failure verdict missing"
    );
    assert!(
        !body.contains("PositiveCompletion"),
        "legacy SMTP code must be decoded, not printed"
    );
    assert!(body.contains("queued as 4ZQ1x"), "relay reply missing");
    assert!(
        body.contains("/emails?state=failed"),
        "failed segment missing"
    );

    let body = get("/emails?state=failed").await;
    assert!(body.contains("Site down: shop.example.cz"));
    assert!(!body.contains("Monthly care report"), "state filter leaked");
    // Segment counts are taken before the outcome filter: Sent still says 2.
    assert!(body.contains("Sent <span class=\"seg-count\">2</span>"));

    let body = get("/emails?q=queued+as").await;
    assert!(
        body.contains("Monthly care report"),
        "search on reply missing"
    );

    let body = get("/emails?q=refused").await;
    assert!(body.contains("Site down: shop.example.cz"));
    assert!(!body.contains("Hyperion test email"), "search leaked");
}

/// Migration bundle download endpoint refuses requests without a
/// valid signed token — even with an existing bundle on disk.
/// Locks in the "URL is the access control" contract.
#[tokio::test]
async fn migration_bundle_download_refuses_unsigned() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    // No cookie needed — this is a public endpoint by design.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/migration/bundle/mig_01HQABCDEFGHJKMNPQRSTVWXYZ/manifest.json?t=garbage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn migration_bundle_download_refuses_bad_filename() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    // Even with no signature, a bad filename should 404 immediately.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/migration/bundle/mig_01HQABCDEFGHJKMNPQRSTVWXYZ/../../etc/passwd?t=x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    // axum's path routing rejects ../ in segments — should be 404
    // (routing layer) not 200.
    assert_ne!(resp.status(), StatusCode::OK);
}

/// The node-to-node import is a tab of /import; its old address
/// /hostings/import redirects there with the query kept.
#[tokio::test]
async fn migration_import_page_renders() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/import?error=nope")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/import/hyperion?error=nope"
    );
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/import/hyperion")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Import hosting from another node"));
    // One Import page: all three sources are offered from this tab.
    assert!(body.contains("href=\"/import/ssh\""));
    assert!(body.contains("aria-current=\"page\""));
    assert!(body.contains("name=\"base_url\""));
    assert!(body.contains("name=\"token\""));
}

/// `/api/v1` Bearer auth: a valid key → 200 on a HostingView endpoint;
/// no/invalid key → 401; a key lacking HostingView → 403. Exercises the
/// whole edge against a real agent + the api_keys ledger.
#[tokio::test]
async fn api_v1_bearer_auth_and_cap_gating() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};

    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);

    // api_keys.owner_user_id references web_users(id). Create a real
    // admin row via RPC so the FK is satisfied, and use its id as the
    // key owner (the bootstrap-admin fallback isn't a DB row).
    let owner_id = match hyperion_rpc_client::call(
        &sock,
        RpcReq::WebUserCreate {
            username: "apikey-owner".into(),
            email: "apikey-owner@example.invalid".into(),
            password: "owner-pw-1".into(),
            role: "admin".into(),
        },
    )
    .await
    .expect("create owner")
    {
        RpcResp::WebUserCreate { id } => id,
        other => panic!("unexpected create response: {other:?}"),
    };

    // 1. No key → 401 JSON.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/hostings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "no key → 401");
    let body = body_string(resp).await;
    assert!(body.contains("\"error\""), "401 JSON envelope: {body}");

    // 2. Garbage / non-existent key → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/hostings")
                .header(
                    header::AUTHORIZATION,
                    "Bearer hyp_totallyboguskey000000000000000000",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "bad key → 401");

    // 3. Mint a key WITH HostingView via RPC.
    let view_cap = hyperion_state::capabilities::Capability::HostingView.bit();
    let good = match hyperion_rpc_client::call(
        &sock,
        RpcReq::ApiKeyCreate {
            label: "ci-good".into(),
            owner_user_id: owner_id,
            caps: view_cap,
            scope_all: true,
            expires_at: None,
            ip_allowlist: vec![],
            rate_limit_per_min: 0,
        },
    )
    .await
    .expect("create good key")
    {
        RpcResp::ApiKeyCreated(c) => c.raw_key,
        other => panic!("unexpected: {other:?}"),
    };
    assert!(good.starts_with("hyp_"), "raw key carries prefix");

    // Valid key → 200 on a HostingView endpoint.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/hostings")
                .header(header::AUTHORIZATION, format!("Bearer {good}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK, "valid key → 200");

    // /api/v1/me works for any valid key and reports the cap.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(header::AUTHORIZATION, format!("Bearer {good}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let me = body_string(resp).await;
    assert!(me.contains("ci-good"), "me reports label: {me}");
    assert!(me.contains("hosting_view"), "me lists the cap: {me}");

    // 4. Mint a key WITHOUT HostingView (NodesView only) → 403 on /hostings.
    let nodes_cap = hyperion_state::capabilities::Capability::NodesView.bit();
    let weak = match hyperion_rpc_client::call(
        &sock,
        RpcReq::ApiKeyCreate {
            label: "ci-weak".into(),
            owner_user_id: owner_id,
            caps: nodes_cap,
            scope_all: true,
            expires_at: None,
            ip_allowlist: vec![],
            rate_limit_per_min: 0,
        },
    )
    .await
    .expect("create weak key")
    {
        RpcResp::ApiKeyCreated(c) => c.raw_key,
        other => panic!("unexpected: {other:?}"),
    };
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/hostings")
                .header(header::AUTHORIZATION, format!("Bearer {weak}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "key lacking HostingView → 403",
    );
    let body = body_string(resp).await;
    assert!(body.contains("\"error\""), "403 JSON envelope: {body}");

    // The same weak key CAN read nodes (it holds NodesView).
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/nodes")
                .header(header::AUTHORIZATION, format!("Bearer {weak}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK, "weak key → 200 on /nodes");
}

fn extract_cookie(resp: &axum::response::Response) -> String {
    let raw = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie")
        .to_str()
        .expect("ascii");
    let main = raw.split(';').next().unwrap();
    main.to_string()
}

fn extract_csrf(html: &str) -> String {
    let needle = "name=\"_csrf\" value=\"";
    let i = html
        .find(needle)
        .unwrap_or_else(|| panic!("csrf field missing in: {html}"));
    let start = i + needle.len();
    let end = html[start..].find('"').expect("quote") + start;
    html[start..end].to_string()
}

/// The unified "Move or copy" wizard renders for an active hosting and offers
/// all three modes (move / copy / export) on one page.
#[tokio::test]
async fn transfer_wizard_renders_three_modes() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    b"username=kevin&password=good-pw&next=/".to_vec(),
                ))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);

    // Create an active hosting to move/copy.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let csrf = extract_csrf(&body_string(resp).await);
    let body = format!("_csrf={csrf}&domain=move-test.cz&aliases=&php=8.3&db=mariadb&system_user=");
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");

    // The wizard page renders with all three modes.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/transfer/move-test.cz")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK, "wizard should render 200");
    let html = body_string(resp).await;
    assert!(html.contains("Move or copy move-test.cz"), "page heading");
    assert!(html.contains("Move to another node"), "move mode");
    assert!(html.contains("Copy to a new domain or node"), "copy mode");
    assert!(html.contains("Export a transfer file"), "export mode");
    // The three modes post to the existing, unchanged endpoints.
    assert!(html.contains("/hostings/migration/move"), "move action");
    assert!(html.contains("/hostings/clone"), "copy action");
    assert!(html.contains("/hostings/migration/export"), "export action");
}

/// The p1b write endpoints are wired and gated: every one rejects a
/// request that carries no valid Bearer key with a 401 (never a redirect,
/// a 404, or a 405 — those would mean a routing/extractor mistake). A
/// cookie session must NOT satisfy the Bearer-only edge either.
#[tokio::test]
async fn api_v1_write_endpoints_reject_without_bearer() {
    let admin = admin_user::create("kevin", "secret-pw-1").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);

    // (method, uri) for each mutating endpoint.
    let cases = [
        (Method::DELETE, "/api/v1/hostings/anything"),
        (Method::POST, "/api/v1/hostings/anything/suspend"),
        (Method::POST, "/api/v1/hostings/anything/resume"),
    ];
    for (method, uri) in cases {
        // No Authorization header at all.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("call");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} without a key must be 401"
        );

        // A syntactically-plausible but unknown Bearer key → still 401.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .header(header::AUTHORIZATION, "Bearer hyp_deadbeefdeadbeef")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("call");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} with an unknown key must be 401"
        );
    }
}

/// Create a real admin web_user (api_keys.owner_user_id FK) and return its id.
async fn seed_key_owner(sock: &std::path::Path) -> i64 {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    match hyperion_rpc_client::call(
        sock,
        RpcReq::WebUserCreate {
            username: "apikey-owner".into(),
            email: "apikey-owner@example.invalid".into(),
            password: "owner-pw-1".into(),
            role: "admin".into(),
        },
    )
    .await
    .expect("create owner")
    {
        RpcResp::WebUserCreate { id } => id,
        other => panic!("unexpected: {other:?}"),
    }
}

/// Mint an API key (scope_all) with optional hardening; returns the raw key.
async fn seed_key(
    sock: &std::path::Path,
    owner_id: i64,
    caps: u64,
    ip_allowlist: Vec<String>,
    rate_limit_per_min: i64,
) -> String {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    match hyperion_rpc_client::call(
        sock,
        RpcReq::ApiKeyCreate {
            label: "ci".into(),
            owner_user_id: owner_id,
            caps,
            scope_all: true,
            expires_at: None,
            ip_allowlist,
            rate_limit_per_min,
        },
    )
    .await
    .expect("mint")
    {
        RpcResp::ApiKeyCreated(c) => c.raw_key,
        other => panic!("unexpected: {other:?}"),
    }
}

/// GET a /api/v1 path with a Bearer key; returns (status, body).
async fn api_get(app: &axum::Router, uri: &str, key: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let status = resp.status();
    (status, body_string(resp).await)
}

#[tokio::test]
async fn api_v1_hostings_paginates_and_filters() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    use hyperion_rpc::wire::HostingCreateReq;

    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let owner_id = seed_key_owner(&sock).await;

    // Seed three hostings.
    for d in ["aaa.example.com", "bbb.example.com", "ccc.example.com"] {
        match hyperion_rpc_client::call(
            &sock,
            RpcReq::HostingCreate(HostingCreateReq {
                domain: hyperion_validate::Domain::parse(d).expect("domain"),
                aliases: vec![],
                php_version: None,
                database: None,
                system_user: None,
                kind: "php".into(),
                proxy_upstream_url: None,
            }),
        )
        .await
        .expect("seed hosting")
        {
            RpcResp::HostingCreate(_) => {}
            other => panic!("unexpected create: {other:?}"),
        }
    }

    let view = hyperion_state::capabilities::Capability::HostingView.bit();
    let key = seed_key(&sock, owner_id, view, vec![], 0).await;

    // First page of 2 → 2 items + a cursor + total=3.
    let (st, body) = api_get(&app, "/api/v1/hostings?limit=2", &key).await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v["items"].as_array().unwrap().len(), 2, "page 1 size");
    assert_eq!(v["total"].as_i64(), Some(3), "total is the filtered count");
    let cursor = v["next_cursor"]
        .as_str()
        .expect("cursor present")
        .to_string();

    // Follow the cursor → the remaining 1, no further cursor.
    let (_st, body) = api_get(
        &app,
        &format!("/api/v1/hostings?limit=2&cursor={cursor}"),
        &key,
    )
    .await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("json2");
    assert_eq!(v["items"].as_array().unwrap().len(), 1, "page 2 size");
    assert!(v["next_cursor"].is_null(), "no more pages");

    // Filters: q substring, and state.
    let (_s, body) = api_get(&app, "/api/v1/hostings?q=bbb", &key).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["total"].as_i64(), Some(1), "q=bbb matches one");
    let (_s, body) = api_get(&app, "/api/v1/hostings?state=suspended", &key).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["total"].as_i64(), Some(0), "none suspended yet");
}

/// GET a /api/v1 path with a Bearer key AND an X-Forwarded-For (the real
/// client IP behind the nginx panel vhost). Returns (status, body).
async fn api_get_real_ip(
    app: &axum::Router,
    uri: &str,
    key: &str,
    real_ip: Option<&str>,
    xff: Option<&str>,
) -> (StatusCode, String) {
    let mut b = Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {key}"));
    if let Some(v) = real_ip {
        b = b.header("x-real-ip", v);
    }
    if let Some(v) = xff {
        b = b.header("x-forwarded-for", v);
    }
    let mut req = b.body(Body::empty()).unwrap();
    // Production serves with into_make_service_with_connect_info, so every
    // route sees a loopback peer (the local nginx). MockConnectInfo doesn't
    // reach this merged sub-router, so set the extension on the request.
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "127.0.0.1:34567".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let resp = app.clone().oneshot(req).await.expect("call");
    let status = resp.status();
    (status, body_string(resp).await)
}

#[tokio::test]
async fn api_v1_ip_allowlist_matches_client_ip() {
    // hyperion-web sits behind nginx, so the real client IP is the first
    // X-Forwarded-For hop — that's what the allowlist must match.
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let owner_id = seed_key_owner(&sock).await;
    let view = hyperion_state::capabilities::Capability::HostingView.bit();

    // Key restricted to 10.0.0.0/8.
    let key = seed_key(&sock, owner_id, view, vec!["10.0.0.0/8".into()], 0).await;

    // The peer is loopback (the local nginx), so the trusted client IP is
    // X-Real-IP, which nginx sets to the genuine $remote_addr.
    //
    // Outside the range → 403 before the handler runs.
    let (st, body) = api_get_real_ip(&app, "/api/v1/me", &key, Some("203.0.113.5"), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "client outside allowlist → 403");
    assert!(body.contains("source IP not allowed"), "reason: {body}");

    // Inside the range → 200.
    let (st, _b) = api_get_real_ip(&app, "/api/v1/me", &key, Some("10.1.2.3"), None).await;
    assert_eq!(st, StatusCode::OK, "client inside allowlist → 200");

    // X-Forwarded-For is NOT trusted: an allowlisted value there, with a
    // non-allowlisted X-Real-IP, must still be refused — otherwise the
    // allowlist is bypassable by a header anyone can send.
    let (st, _b) = api_get_real_ip(
        &app,
        "/api/v1/me",
        &key,
        Some("203.0.113.5"),
        Some("10.1.2.3"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "XFF must not satisfy the allowlist"
    );

    // A key with no allowlist ignores the source IP entirely.
    let open = seed_key(&sock, owner_id, view, vec![], 0).await;
    let (st, _b) = api_get_real_ip(&app, "/api/v1/me", &open, Some("203.0.113.5"), None).await;
    assert_eq!(st, StatusCode::OK, "no allowlist → any IP allowed");
}

#[tokio::test]
async fn api_v1_rate_limit_returns_429() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let owner_id = seed_key_owner(&sock).await;
    let view = hyperion_state::capabilities::Capability::HostingView.bit();

    // One request/min. First passes, second is throttled.
    let key = seed_key(&sock, owner_id, view, vec![], 1).await;
    let (st1, _) = api_get(&app, "/api/v1/me", &key).await;
    assert_eq!(st1, StatusCode::OK, "first request allowed");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second request within the minute is throttled"
    );
    assert!(
        resp.headers().contains_key(header::RETRY_AFTER),
        "429 carries Retry-After"
    );
}

#[tokio::test]
async fn api_v1_openapi_spec_and_docs_are_served() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);

    // openapi.json is PUBLIC (no Bearer) and is a valid OpenAPI 3 document.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK, "openapi.json is public");
    let spec: serde_json::Value = serde_json::from_str(&body_string(resp).await).expect("json");
    assert!(
        spec["openapi"].as_str().unwrap_or("").starts_with("3."),
        "declares OpenAPI 3.x: {:?}",
        spec["openapi"]
    );

    // Drift guard: every registered /api/v1 operation must appear in the spec.
    let paths = spec["paths"].as_object().expect("paths object");
    for p in [
        "/api/v1/me",
        "/api/v1/hostings",
        "/api/v1/hostings/{id}",
        "/api/v1/hostings/{id}/suspend",
        "/api/v1/hostings/{id}/resume",
        "/api/v1/hostings/{id}/wp/core-update",
        "/api/v1/nodes",
        "/api/v1/jobs/{id}",
    ] {
        assert!(paths.contains_key(p), "spec is missing path {p}");
    }
    // The two methods that share /hostings/{id} are both documented.
    assert!(
        paths["/api/v1/hostings/{id}"]["get"].is_object(),
        "GET /hostings/{{id}} documented"
    );
    assert!(
        paths["/api/v1/hostings/{id}"]["delete"].is_object(),
        "DELETE /hostings/{{id}} documented"
    );
    // The bearer security scheme is declared.
    assert!(
        spec["components"]["securitySchemes"]["bearer"].is_object(),
        "bearer security scheme present"
    );

    // The human docs page renders (self-hosted, no external deps).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/docs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK, "docs page renders");
    let html = body_string(resp).await;
    assert!(html.contains("Hyperion Remote API"), "docs title present");
    assert!(html.contains("/api/v1/openapi.json"), "docs links the spec");
}

/// Send a JSON body to a /api/v1 path with a Bearer key. Returns (status, body).
async fn api_send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    key: &str,
    json_body: &str,
) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json_body.to_string()))
                .unwrap(),
        )
        .await
        .expect("call");
    let status = resp.status();
    (status, body_string(resp).await)
}

#[tokio::test]
async fn api_v1_create_hosting_conflict_and_validation() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let owner_id = seed_key_owner(&sock).await;
    let create_cap = hyperion_state::capabilities::Capability::HostingCreate.bit();
    let key = seed_key(&sock, owner_id, create_cap, vec![], 0).await;

    // Fresh domain → 201 Created.
    let (st, body) = api_send(
        &app,
        Method::POST,
        "/api/v1/hostings",
        &key,
        r#"{"domain":"api-create.example.com"}"#,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "create → 201: {body}");

    // Same domain again → 409 Conflict (cluster duplicate guard).
    let (st, _b) = api_send(
        &app,
        Method::POST,
        "/api/v1/hostings",
        &key,
        r#"{"domain":"api-create.example.com"}"#,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "duplicate domain → 409");

    // Malformed domain → 400 validation (Domain::try_from rejects it).
    let (st, body) = api_send(
        &app,
        Method::POST,
        "/api/v1/hostings",
        &key,
        r#"{"domain":"nodots"}"#,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "invalid domain → 400: {body}");

    // A key lacking HostingCreate → 403.
    let view = hyperion_state::capabilities::Capability::HostingView.bit();
    let weak = seed_key(&sock, owner_id, view, vec![], 0).await;
    let (st, _b) = api_send(
        &app,
        Method::POST,
        "/api/v1/hostings",
        &weak,
        r#"{"domain":"nope.example.com"}"#,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "no HostingCreate cap → 403");
}

#[tokio::test]
async fn api_v1_patch_limits_applies() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    use hyperion_rpc::wire::HostingCreateReq;

    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let owner_id = seed_key_owner(&sock).await;

    // Seed a hosting to patch.
    match hyperion_rpc_client::call(
        &sock,
        RpcReq::HostingCreate(HostingCreateReq {
            domain: hyperion_validate::Domain::parse("api-patch.example.com").expect("domain"),
            aliases: vec![],
            php_version: None,
            database: None,
            system_user: None,
            kind: "php".into(),
            proxy_upstream_url: None,
        }),
    )
    .await
    .expect("seed")
    {
        RpcResp::HostingCreate(_) => {}
        other => panic!("unexpected: {other:?}"),
    }

    let key = seed_key(
        &sock,
        owner_id,
        hyperion_state::capabilities::Capability::HostingEditConfig.bit(),
        vec![],
        0,
    )
    .await;
    let limits_json =
        serde_json::to_string(&hyperion_types::HostingLimits::defaults()).expect("serialize");
    let (st, body) = api_send(
        &app,
        Method::PATCH,
        "/api/v1/hostings/api-patch.example.com/limits",
        &key,
        &limits_json,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "patch limits → 200: {body}");

    // A key lacking the manage cap → 403.
    let weak = seed_key(
        &sock,
        owner_id,
        hyperion_state::capabilities::Capability::HostingView.bit(),
        vec![],
        0,
    )
    .await;
    let (st, _b) = api_send(
        &app,
        Method::PATCH,
        "/api/v1/hostings/api-patch.example.com/limits",
        &weak,
        &limits_json,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "no manage cap → 403");
}

#[tokio::test]
async fn api_v1_ops_endpoints() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    use hyperion_rpc::wire::HostingCreateReq;

    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let owner_id = seed_key_owner(&sock).await;

    // Seed a hosting to operate on.
    match hyperion_rpc_client::call(
        &sock,
        RpcReq::HostingCreate(HostingCreateReq {
            domain: hyperion_validate::Domain::parse("api-ops.example.com").expect("domain"),
            aliases: vec![],
            php_version: None,
            database: None,
            system_user: None,
            kind: "php".into(),
            proxy_upstream_url: None,
        }),
    )
    .await
    .expect("seed")
    {
        RpcResp::HostingCreate(_) => {}
        other => panic!("unexpected: {other:?}"),
    }

    // An all-caps key satisfies BackupRun / CertManage / HostingEditConfig.
    let key = seed_key(
        &sock,
        owner_id,
        hyperion_state::capabilities::CapSet::all().bits(),
        vec![],
        0,
    )
    .await;
    let base = "/api/v1/hostings/api-ops.example.com";

    // Backup → 202 with a job id.
    let (st, body) = api_send(&app, Method::POST, &format!("{base}/backup"), &key, "").await;
    assert_eq!(st, StatusCode::ACCEPTED, "backup → 202: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["job_id"].is_string(), "backup returns a job id: {body}");

    // Backups list → 200 with an items array.
    let (st, body) = api_send(&app, Method::GET, &format!("{base}/backups"), &key, "").await;
    assert_eq!(st, StatusCode::OK, "backups list → 200");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["items"].is_array(), "backups envelope has items: {body}");

    // Cert issue (staging) → 202 with a job id.
    let (st, body) = api_send(
        &app,
        Method::POST,
        &format!("{base}/cert"),
        &key,
        r#"{"staging":true}"#,
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED, "cert → 202: {body}");

    // Expiry (PATCH) → 200.
    let (st, body) = api_send(
        &app,
        Method::PATCH,
        &format!("{base}/expiry"),
        &key,
        r#"{"expires_at":9999999999,"owner_email":null,"grace_days":7,"warning_offsets_days":"30,7,1"}"#,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "expiry → 200: {body}");

    // Quota (PATCH) → 200.
    let (st, body) = api_send(
        &app,
        Method::PATCH,
        &format!("{base}/quota"),
        &key,
        r#"{"disk_soft_kib":1000000,"disk_hard_kib":2000000,"mem_limit_mib":512,"bw_soft_mib":0,"bw_hard_mib":0,"exceed_action":"notify"}"#,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "quota → 200: {body}");

    // A key lacking BackupRun → 403 on backup.
    let weak = seed_key(
        &sock,
        owner_id,
        hyperion_state::capabilities::Capability::HostingView.bit(),
        vec![],
        0,
    )
    .await;
    let (st, _b) = api_send(&app, Method::POST, &format!("{base}/backup"), &weak, "").await;
    assert_eq!(st, StatusCode::FORBIDDEN, "no BackupRun cap → 403");
}

#[tokio::test]
async fn api_v1_ops_completion_endpoints() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    use hyperion_rpc::wire::HostingCreateReq;

    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let owner_id = seed_key_owner(&sock).await;

    match hyperion_rpc_client::call(
        &sock,
        RpcReq::HostingCreate(HostingCreateReq {
            domain: hyperion_validate::Domain::parse("api-ops2.example.com").expect("domain"),
            aliases: vec![],
            php_version: None,
            database: None,
            system_user: None,
            kind: "php".into(),
            proxy_upstream_url: None,
        }),
    )
    .await
    .expect("seed")
    {
        RpcResp::HostingCreate(_) => {}
        other => panic!("unexpected: {other:?}"),
    }

    let key = seed_key(
        &sock,
        owner_id,
        hyperion_state::capabilities::CapSet::all().bits(),
        vec![],
        0,
    )
    .await;
    let base = "/api/v1/hostings/api-ops2.example.com";

    // WordPress install → 202 job.
    let wp = r#"{"site_url":"https://api-ops2.example.com","title":"Site","admin_user":"admin","admin_email":"a@example.invalid","admin_password":"pw-12345678"}"#;
    let (st, body) = api_send(&app, Method::POST, &format!("{base}/wp/install"), &key, wp).await;
    assert_eq!(st, StatusCode::ACCEPTED, "wp install → 202: {body}");

    // WordPress core update → 202 job; the node judges the version.
    let (st, body) = api_send(
        &app,
        Method::POST,
        &format!("{base}/wp/core-update"),
        &key,
        r#"{"version":"6.7.1"}"#,
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED, "wp core-update → 202: {body}");

    // …without a version → 400, before any job exists.
    let (st, _b) = api_send(
        &app,
        Method::POST,
        &format!("{base}/wp/core-update"),
        &key,
        r#"{"version":" "}"#,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "empty version → 400");

    // Restore → 202 job.
    let (st, body) = api_send(
        &app,
        Method::POST,
        &format!("{base}/restore"),
        &key,
        r#"{"archive_path":"/var/lib/hyperion/backups/local/snap.tar.gz"}"#,
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED, "restore → 202: {body}");

    // Restore without a path → 400.
    let (st, _b) = api_send(
        &app,
        Method::POST,
        &format!("{base}/restore"),
        &key,
        r#"{"archive_path":""}"#,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "empty archive_path → 400");

    // Cluster cert renew-all → 202 job.
    let (st, body) = api_send(&app, Method::POST, "/api/v1/certs/renew-all", &key, "").await;
    assert_eq!(st, StatusCode::ACCEPTED, "renew-all → 202: {body}");

    // A key lacking WpManage → 403 on wp install.
    let weak = seed_key(
        &sock,
        owner_id,
        hyperion_state::capabilities::Capability::HostingView.bit(),
        vec![],
        0,
    )
    .await;
    let (st, _b) = api_send(&app, Method::POST, &format!("{base}/wp/install"), &weak, wp).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "no WpManage cap → 403");
    let (st, _b) = api_send(
        &app,
        Method::POST,
        &format!("{base}/wp/core-update"),
        &weak,
        r#"{"version":"6.7.1"}"#,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "no WpManage cap → 403 on core update"
    );
}

/// /stats must carry a per-site breakdown, not just cluster + node cards.
///
/// The page's own subtitle has always promised "per-hosting snapshots";
/// this locks in that the table is actually there, that a freshly created
/// site appears in it BEFORE the 5 min sampler has written a usage row
/// (all zeros, flagged "not sampled yet" — that is a state, not an
/// error), and that column sorting is a server-side `?sort=` round trip.
#[tokio::test]
async fn stats_page_lists_sites_and_honours_sort() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);

    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);

    // With no sites yet the table must say so in plain language — an
    // empty breakdown is an empty box, not a failure to read it.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/stats")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let empty = body_string(resp).await;
    assert!(empty.contains("Per-site usage"), "breakdown card missing");
    assert!(
        empty.contains("No active sites here yet"),
        "empty state missing"
    );

    // Create a site.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let csrf = extract_csrf(&body_string(resp).await);
    let body = format!("_csrf={csrf}&domain=stats-e2e.cz&aliases=&php=8.3&db=mariadb&system_user=");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);

    // Default view: sorted by disk, site linked to its detail page.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/stats")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(
        page.contains("stats-e2e.cz"),
        "new site missing from the per-site table"
    );
    assert!(
        page.contains("heaviest disk first"),
        "default sort should be disk"
    );
    assert!(
        page.contains("not sampled yet"),
        "a site with no usage rows must render as a zero row, not vanish"
    );
    assert!(
        !page.contains("No active sites here yet"),
        "empty state must be gone once a site exists"
    );
    // The table has to live INSIDE the live-refresh region, otherwise it
    // silently freezes while every other number on the page updates.
    let live_at = page.find("id=\"stats-live\"").expect("live region");
    let table_at = page.find("Per-site usage").expect("breakdown card");
    assert!(live_at < table_at, "breakdown must sit inside #stats-live");

    // Sorting is server-side: ?sort=cpu changes the rendered order.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/stats?sort=cpu")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let sorted = body_string(resp).await;
    assert!(
        sorted.contains("heaviest cpu first"),
        "?sort=cpu must be honoured server-side"
    );
    assert!(
        sorted.contains("th-sort active"),
        "active column header should be marked"
    );
    assert!(
        sorted.contains("CPU now") && !sorted.contains("CPU peak"),
        "the default view is live, where a peak means nothing"
    );

    // The range picker is a server-side round trip too, and the sort survives it.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/stats?sort=cpu&range=6h")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let ranged = body_string(resp).await;
    assert!(ranged.contains("CPU avg") && ranged.contains("CPU peak"));
    assert!(ranged.contains("over the last 6 h"));
    assert!(
        ranged.contains("sort=cpu&amp;range=30m"),
        "picking another range must keep the sort"
    );
    assert!(ranged.contains("range=live"), "live stays reachable");
}

// ─────────────────────────────────────────────────────────────────────────────
// Resumable import upload, driven over the real router.
//
// The offset reconciliation between `begin`, `chunk` and `commit` is the most
// dangerous code in the import path: get it wrong and bytes are concatenated in
// the wrong order, producing a bundle that is the right LENGTH and passes
// `tar tf` while containing garbage. State-layer unit tests cannot see that —
// only assembling a real body through real HTTP and comparing it byte-for-byte
// against the original proves resume does not corrupt.
// ─────────────────────────────────────────────────────────────────────────────

/// Give one upload test exclusive use of a private receive directory.
///
/// Two things force this. `HYPERION_MIGRATION_DIR` is process-wide, and every
/// test here starts a fresh agent with an in-memory database, so the first token
/// each mints has id 1 — meaning they would all reconcile offsets against the
/// same `bundle-1.tar.part`. Holding the guard for the body of the test makes
/// each run alone against its own directory.
///
/// Returned guard must be held, not dropped: `let _g = …`, never `let _ = …`.
async fn exclusive_migration_dir() -> (tempfile::TempDir, tokio::sync::MutexGuard<'static, ()>) {
    // A tokio mutex, not a std one: the guard is deliberately held across the
    // whole test body, which awaits throughout.
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let guard = LOCK.lock().await;
    let dir = tempfile::tempdir().expect("migration tmpdir");
    std::env::set_var("HYPERION_MIGRATION_DIR", dir.path());
    (dir, guard)
}

/// Mint an import token straight through the agent, the way the authenticated
/// wizard would, and hand back the plaintext.
async fn mint_import_token(sock: &std::path::Path) -> String {
    let resp = hyperion_rpc_client::call(
        sock,
        hyperion_rpc::codec::Request::ImportToken(hyperion_types::ImportTokenOp::Mint {
            target_node: "local".into(),
            source_kind: "cloudpanel".into(),
            created_by: "kevin".into(),
            ttl_secs: 3600,
        }),
    )
    .await
    .expect("mint rpc");
    match resp {
        hyperion_rpc::codec::Response::ImportToken(hyperion_types::ImportTokenResult::Minted {
            token,
            ..
        }) => token,
        other => panic!("unexpected mint reply: {other:?}"),
    }
}

fn upload_req(path: &str, token: &str, method: Method, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string()
}

fn field(body: &str, key: &str) -> Option<String> {
    body.lines()
        .find_map(|l| l.strip_prefix(&format!("{key} ")))
        .map(|v| v.trim().to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The assertion that matters: a transfer interrupted mid-flight and resumed
/// must reassemble to EXACTLY the original bytes.
#[tokio::test]
async fn an_interrupted_upload_resumes_without_corrupting_the_bundle() {
    let (_dir, _guard) = exclusive_migration_dir().await;
    let admin = admin_user::create("kevin", "pw").expect("admin");
    let (sock, _dir) = start_agent().await;
    let token = mint_import_token(&sock).await;
    let app = build_app(sock, admin);

    // A body with position-dependent content, so a misplaced chunk cannot pass
    // unnoticed the way a run of identical bytes would.
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let sha = sha256_hex(&payload);

    let begin = app
        .clone()
        .oneshot(upload_req(
            "/import/upload/begin",
            &token,
            Method::POST,
            format!("bytes {}\nsha256 {sha}\n", payload.len()).into_bytes(),
        ))
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::OK);
    let body = body_text(begin).await;
    assert_eq!(field(&body, "offset").as_deref(), Some("0"));

    // First chunk lands.
    let cut = 120_000usize;
    let mut req = upload_req(
        "/import/upload/chunk",
        &token,
        Method::PUT,
        payload[..cut].to_vec(),
    );
    req.headers_mut()
        .insert("x-hyperion-offset", "0".parse().unwrap());
    let r = app.clone().oneshot(req).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        field(&body_text(r).await, "offset").as_deref(),
        Some(cut.to_string().as_str())
    );

    // …the connection drops. The runner comes back and calls `begin` again,
    // which is the whole reason it is idempotent.
    let again = app
        .clone()
        .oneshot(upload_req(
            "/import/upload/begin",
            &token,
            Method::POST,
            format!("bytes {}\nsha256 {sha}\n", payload.len()).into_bytes(),
        ))
        .await
        .unwrap();
    assert_eq!(
        again.status(),
        StatusCode::OK,
        "a resumed upload must be re-admitted, not 403'd"
    );
    let resume_off: usize = field(&body_text(again).await, "offset")
        .expect("offset")
        .parse()
        .unwrap();
    assert_eq!(resume_off, cut, "the server must report where it really is");

    // The rest.
    let mut req = upload_req(
        "/import/upload/chunk",
        &token,
        Method::PUT,
        payload[resume_off..].to_vec(),
    );
    req.headers_mut()
        .insert("x-hyperion-offset", resume_off.to_string().parse().unwrap());
    let r = app.clone().oneshot(req).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // The bundle is not a tar, so commit refuses at the tar check — but only
    // AFTER the digest matched, which is what this test is about. Assert on the
    // message so a future refactor cannot quietly reorder those two checks.
    let commit = app
        .clone()
        .oneshot(upload_req(
            "/import/upload/commit",
            &token,
            Method::POST,
            format!("bytes {}\nsha256 {sha}\n", payload.len()).into_bytes(),
        ))
        .await
        .unwrap();
    let ctext = body_text(commit).await;
    assert!(
        ctext.contains("arrived intact") && ctext.contains("not a"),
        "the digest must have matched over the reassembled bytes; got:\n{ctext}"
    );
}

/// A chunk offered at the wrong offset must be REFUSED and must write nothing —
/// otherwise a stale runner splices bytes into the middle of the file.
#[tokio::test]
async fn a_chunk_at_the_wrong_offset_is_refused_with_the_real_offset() {
    let (_dir, _guard) = exclusive_migration_dir().await;
    let admin = admin_user::create("kevin", "pw").expect("admin");
    let (sock, _dir) = start_agent().await;
    let token = mint_import_token(&sock).await;
    let app = build_app(sock, admin);

    let payload = vec![7u8; 50_000];
    let sha = sha256_hex(&payload);
    app.clone()
        .oneshot(upload_req(
            "/import/upload/begin",
            &token,
            Method::POST,
            format!("bytes {}\nsha256 {sha}\n", payload.len()).into_bytes(),
        ))
        .await
        .unwrap();

    let mut req = upload_req(
        "/import/upload/chunk",
        &token,
        Method::PUT,
        payload[..10_000].to_vec(),
    );
    req.headers_mut()
        .insert("x-hyperion-offset", "0".parse().unwrap());
    app.clone().oneshot(req).await.unwrap();

    // A stale runner believes it is at 0 and tries to send from there again.
    let mut req = upload_req(
        "/import/upload/chunk",
        &token,
        Method::PUT,
        payload[..10_000].to_vec(),
    );
    req.headers_mut()
        .insert("x-hyperion-offset", "0".parse().unwrap());
    let r = app.clone().oneshot(req).await.unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let text = body_text(r).await;
    assert_eq!(
        field(&text, "offset").as_deref(),
        Some("10000"),
        "the 409 must carry the authoritative offset so the client can seek"
    );
}

/// A bundle whose digest does not match must never reach the import job, and the
/// partial must be discarded rather than left to be resumed into for ever.
#[tokio::test]
async fn a_corrupted_bundle_is_refused_at_commit() {
    let (_dir, _guard) = exclusive_migration_dir().await;
    let admin = admin_user::create("kevin", "pw").expect("admin");
    let (sock, _dir) = start_agent().await;
    let token = mint_import_token(&sock).await;
    let app = build_app(sock, admin);

    let payload = vec![3u8; 20_000];
    let lie = sha256_hex(b"a completely different bundle");
    app.clone()
        .oneshot(upload_req(
            "/import/upload/begin",
            &token,
            Method::POST,
            format!("bytes {}\nsha256 {lie}\n", payload.len()).into_bytes(),
        ))
        .await
        .unwrap();
    let mut req = upload_req("/import/upload/chunk", &token, Method::PUT, payload.clone());
    req.headers_mut()
        .insert("x-hyperion-offset", "0".parse().unwrap());
    app.clone().oneshot(req).await.unwrap();

    let commit = app
        .clone()
        .oneshot(upload_req(
            "/import/upload/commit",
            &token,
            Method::POST,
            format!("bytes {}\nsha256 {lie}\n", payload.len()).into_bytes(),
        ))
        .await
        .unwrap();
    assert_eq!(commit.status(), StatusCode::CONFLICT);
    let text = body_text(commit).await;
    assert!(text.contains("corrupted"), "{text}");
    assert_eq!(
        field(&text, "offset").as_deref(),
        Some("0"),
        "the partial must be discarded so the retry starts clean"
    );
}

/// The upload routes must refuse an unauthenticated caller — they are public,
/// and the bearer token is the only thing standing in front of them.
#[tokio::test]
async fn the_upload_routes_require_a_bearer_token() {
    let admin = admin_user::create("kevin", "pw").expect("admin");
    let (sock, _dir) = start_agent().await;
    let app = build_app(sock, admin);

    for (path, method) in [
        ("/import/upload/begin", Method::POST),
        ("/import/upload/chunk", Method::PUT),
        ("/import/upload/commit", Method::POST),
        ("/import/upload/status", Method::GET),
        ("/import/progress", Method::POST),
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "{path} answered without a token"
        );
    }
}

/// The generated bootstrap must be valid bash. It is assembled from a prelude
/// plus an asset, runs as ROOT on somebody else's production server, and CI has
/// no other check on it.
#[tokio::test]
async fn the_generated_bootstrap_is_syntactically_valid_bash() {
    use std::io::Write;
    let admin = admin_user::create("kevin", "pw").expect("admin");
    let (sock, _dir) = start_agent().await;
    let token = mint_import_token(&sock).await;
    let app = build_app(sock, admin);

    let r = app
        .oneshot(
            Request::builder()
                .uri(format!("/import/agent/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let script = body_text(r).await;

    // The three interpolated values must have landed.
    assert!(
        script.contains(&format!("T='{token}'")),
        "token prelude missing"
    );
    assert!(script.contains("K='cloudpanel'"), "kind prelude missing");

    // The credential must never be in a URL: these loops run hundreds of times
    // per transfer and every URL lands in the panel's nginx access log.
    //
    // Asserting on the literal token was vacuous — the script interpolates it
    // once, as `T='<token>'`, and every later use is the VARIABLE `$T`. The
    // check could never fail however many URLs carried the credential. Assert on
    // the shape instead: no line that mentions a URL may also splice `$T` into
    // it. The prelude line that defines T is the one exception.
    // ONE-SHOT bootstrap fetches are exempt, and only these. The operator pastes
    // `curl <panel>/import/agent/<token> | sudo bash` themselves, so that token
    // is already in their shell history and in one access-log line; fetching the
    // exporter the same way adds nothing that is not already there. What must
    // never happen is a LOOP putting it there hundreds of times — the selection
    // poll (up to 2640 requests) and the chunk upload (one per 64 MiB).
    //
    // Listing the exceptions by content rather than loosening the rule means a
    // new URL use of the token fails this test rather than slipping in beside
    // them.
    const ONE_SHOT: &[&str] = &["/import/agent-bin/", "/import/manifest/"];
    for line in script.lines() {
        let l = line.trim();
        if l.starts_with("T=") || l.starts_with('#') {
            continue;
        }
        let exempt = ONE_SHOT.iter().any(|p| l.contains(p));
        let mentions_url = l.contains("http") || l.contains("url =") || l.contains("$B/");
        let splices_token = l.contains("/$T") || l.contains("$T?") || l.contains("${T}");
        assert!(
            exempt || !(mentions_url && splices_token),
            "the token is spliced into a URL, which the access log will keep:\n{line}"
        );
        // The literal value must appear nowhere but the prelude, exempt or not.
        assert!(
            !l.contains(&token),
            "the token's literal value escaped the prelude:\n{line}"
        );
    }

    // And the two loops that run many times per transfer must authenticate by
    // header, from a 0600 config — never on argv, where /proc/<pid>/cmdline
    // hands the token to every local user on a shared panel box.
    assert!(
        script.contains("-K \"$SELCFG\""),
        "the selection poll must read its URL and credential from a config file"
    );
    assert!(
        !script.contains("-H \"Authorization: Bearer $TOKEN\""),
        "the token must not reach curl's argv"
    );

    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("boot.sh");
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(script.as_bytes()).unwrap();
    drop(f);

    let out = std::process::Command::new("bash")
        .arg("-n")
        .arg(&p)
        .output()
        .expect("bash -n");
    assert!(
        out.status.success(),
        "the generated bootstrap is not valid bash:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The happy path, and then the retry an operator's flaky link produces: a
/// commit whose 200 was lost, sent again.
///
/// It must NOT re-import, and it must not answer "cancelled" — which is what a
/// status filter that hid completed transfers used to make it say.
#[tokio::test]
async fn a_repeated_commit_returns_the_same_job_and_does_not_reimport() {
    let (_dir, _guard) = exclusive_migration_dir().await;
    let admin = admin_user::create("kevin", "pw").expect("admin");
    let (sock, _agentdir) = start_agent().await;
    let token = mint_import_token(&sock).await;
    let app = build_app(sock, admin);

    // A real tar, so commit gets past the archive check and actually spawns a
    // job — the state this test is about.
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("manifest.json"), b"{}").unwrap();
    let tar_path = src.path().join("b.tar");
    let ok = std::process::Command::new("tar")
        .arg("cf")
        .arg(&tar_path)
        .arg("-C")
        .arg(src.path())
        .arg("manifest.json")
        .status()
        .expect("tar")
        .success();
    assert!(ok, "could not build a fixture tar");
    let payload = std::fs::read(&tar_path).unwrap();
    let sha = sha256_hex(&payload);

    app.clone()
        .oneshot(upload_req(
            "/import/upload/begin",
            &token,
            Method::POST,
            format!("bytes {}\nsha256 {sha}\n", payload.len()).into_bytes(),
        ))
        .await
        .unwrap();
    let mut req = upload_req("/import/upload/chunk", &token, Method::PUT, payload.clone());
    req.headers_mut()
        .insert("x-hyperion-offset", "0".parse().unwrap());
    let r = app.clone().oneshot(req).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let commit_body = format!("bytes {}\nsha256 {sha}\n", payload.len()).into_bytes();
    let first = app
        .clone()
        .oneshot(upload_req(
            "/import/upload/commit",
            &token,
            Method::POST,
            commit_body.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_text = body_text(first).await;
    let job = field(&first_text, "job").expect("a job id");
    assert!(!job.is_empty());

    // …the reply never reached the source, so it sends it again.
    let second = app
        .clone()
        .oneshot(upload_req(
            "/import/upload/commit",
            &token,
            Method::POST,
            commit_body,
        ))
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "a repeated commit must not read as cancelled"
    );
    assert_eq!(
        field(&body_text(second).await, "job").as_deref(),
        Some(job.as_str()),
        "the SAME job must come back — a second import would duplicate every site"
    );

    // And a stale runner must not be able to append to a committed transfer.
    let mut req = upload_req("/import/upload/chunk", &token, Method::PUT, vec![0u8; 16]);
    req.headers_mut().insert(
        "x-hyperion-offset",
        payload.len().to_string().parse().unwrap(),
    );
    let late = app.oneshot(req).await.unwrap();
    assert_eq!(late.status(), StatusCode::GONE);
}

/// Run the generated bootstrap far enough to reach the point where it detaches
/// the worker, against stubbed external commands.
///
/// `bash -n` cannot catch what this catches. A shell script can be
/// syntactically perfect and still die on its first line of real work — which
/// is exactly what happened in v0.58.0: under `set -euo pipefail`, `sed` on a
/// journal that does not exist yet exited non-zero, that status propagated out
/// of the command substitution and out of the assignment, and the script
/// stopped SILENTLY between "measuring the selected sites" and "export started
/// in the background". The operator's terminal simply ended, the worker was
/// never spawned, and the panel went on saying "waiting for the source to
/// export…" for a transfer that had already died. It cost a real 31 GB
/// migration attempt.
///
/// The stubs are deliberately dumb: they exist to let the script REACH its own
/// logic, not to simulate a panel. Anything that aborts before the detach —
/// an unset variable, a `set -e` trip, a missing file, a bad redirect — fails
/// this test with the script's own output attached.
#[tokio::test]
async fn the_bootstrap_reaches_the_detach_against_stubs() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let admin = admin_user::create("kevin", "pw").expect("admin");
    let (sock, _agentdir) = start_agent().await;
    let token = mint_import_token(&sock).await;
    let app = build_app(sock, admin);

    let r = app
        .oneshot(
            Request::builder()
                .uri(format!("/import/agent/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let script = body_text(r).await;

    let tmp = tempfile::tempdir().unwrap();
    // Canonicalise: `guard_dir` refuses a symlinked ancestor of the run
    // directory, and on macOS a temp dir sits under `/var`, which IS a symlink.
    // (That refusal is correct — root is about to write plaintext database
    // dumps there — so the test gives it a real path rather than weakening it.)
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let bin = root.join("stubbin");
    std::fs::create_dir_all(&bin).unwrap();
    let run_dir = root.join("exportdir");

    // Stubs. `curl` answers each step the setup phase makes: the exporter
    // download writes a file, the manifest POST is ignored, and the selection
    // poll returns one domain so the script stops waiting.
    let stub = |name: &str, body: &str| {
        let p = bin.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/bash\n{body}").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    stub(
        "curl",
        r#"out=""; while [ $# -gt 0 ]; do case "$1" in -o) shift; out="$1";; -K) shift;; esac; shift; done
if [ -n "$out" ]; then
  # The "exporter" the runner downloads. It has to be genuinely executable:
  # the runner probes `--help` for --estimate before it will proceed.
  { echo '#!/bin/bash'
    echo 'case " $* " in'
    echo '  *" --help "*) echo "--estimate --journal --status --watch";;'
    echo '  *" --estimate "*) echo "{\"sites\":1,\"input_bytes\":1024,\"free_bytes\":999999999,\"mode\":\"foreground\"}";;'
    echo 'esac'
    echo 'exit 0'
  } > "$out"
  chmod +x "$out"
fi
printf 'example.cz\n'
exit 0"#,
    );
    // Pin the architecture on both sides so the test reads the same on an
    // arm64 laptop and an x86_64 runner. The script cross-checks `uname -m`
    // against `file`'s wording, and the two spell it differently on purpose
    // ("x86_64" vs "x86-64") — which is exactly what the real guard matches.
    stub("uname", r#"echo x86_64"#);
    stub("file", r#"echo 'ELF 64-bit LSB executable, x86-64'"#);
    // The exporter: --help must advertise --estimate, --estimate must print the
    // JSON the runner seds, and --watch must return promptly.

    // Everything the script shells out to that must simply succeed.
    for name in ["setsid", "nohup", "flock", "sha256sum"] {
        stub(name, "exit 0");
    }
    // guard_dir insists every ancestor of the run dir is root-owned and not
    // group/world-writable. A temp dir is neither, so `stat` is stubbed to the
    // shape a correctly-provisioned box has. The guard's own logic is covered
    // by its unit tests; what is under test here is that the script RUNS.
    stub(
        "stat",
        r#"case "$1" in -c) case "$2" in %u) echo 0;; %a) echo 755;; esac;; esac"#,
    );

    // The exporter is fetched to a temp file and copied to $RUN/hyperion-export,
    // then invoked by that path — so put the stub where the copy lands.
    std::fs::create_dir_all(run_dir.join("run")).unwrap();

    let script_path = root.join("boot.sh");
    std::fs::write(&script_path, &script).unwrap();

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = std::process::Command::new("bash")
        .arg(&script_path)
        .env("PATH", path)
        .env("HYPERION_EXPORT_DIR", &run_dir)
        .output()
        .expect("run the bootstrap");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The measuring line proves it got past the selection poll; the detach line
    // is the one that was never reached in v0.58.0.
    assert!(
        stderr.contains("measuring the selected sites"),
        "the script did not reach the measuring step.\n--- stderr ---\n{stderr}\n--- stdout ---\n{stdout}"
    );
    assert!(
        stderr.contains("export started in the background"),
        "the script died before detaching the worker — the failure that cost a real \
         migration, and that `bash -n` cannot see.\n--- stderr ---\n{stderr}\n--- stdout ---\n{stdout}"
    );
}

/// `PATCH /api/v1/hostings/:id/vhost` must honour the same raw-nginx gate the
/// browser handler enforces: the snippet is spliced verbatim into a config
/// root loads, so CHANGING it needs `HostingEditNginxRaw` on top of the
/// `HostingEditConfig` that carries the rest of the vhost knobs. A key holding
/// only `HostingEditConfig` is refused when it tries to set the snippet, but
/// can still flip the other options. Regression guard for a WAF-audit finding
/// where the API forwarded `body.options` wholesale, bypassing the admin gate.
#[tokio::test]
async fn api_v1_patch_vhost_snippet_needs_nginx_raw_cap() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    use hyperion_state::capabilities::Capability;

    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);

    // Create a hosting to patch (via the admin session + form, like the other
    // e2e cases). Its stored snippet starts empty.
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let csrf = extract_csrf(&body_string(resp).await);
    let create_body =
        format!("_csrf={csrf}&domain=vhost-authz.cz&aliases=&php=8.3&db=mariadb&system_user=");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(create_body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK, "hosting created");

    // A real web_users row for the api_keys FK (bootstrap admin isn't a row).
    let owner_id = match hyperion_rpc_client::call(
        &sock,
        RpcReq::WebUserCreate {
            username: "vhost-authz-owner".into(),
            email: "vhost-authz-owner@example.invalid".into(),
            password: "owner-pw-1".into(),
            role: "admin".into(),
        },
    )
    .await
    .expect("create owner")
    {
        RpcResp::WebUserCreate { id } => id,
        other => panic!("unexpected create response: {other:?}"),
    };

    // Mint a key with HostingEditConfig ONLY (no HostingEditNginxRaw).
    let edit_config = Capability::HostingEditConfig.bit();
    let key = match hyperion_rpc_client::call(
        &sock,
        RpcReq::ApiKeyCreate {
            label: "ci-editconfig".into(),
            owner_user_id: owner_id,
            caps: edit_config,
            scope_all: true,
            expires_at: None,
            ip_allowlist: vec![],
            rate_limit_per_min: 0,
        },
    )
    .await
    .expect("create key")
    {
        RpcResp::ApiKeyCreated(c) => c.raw_key,
        other => panic!("unexpected: {other:?}"),
    };

    // 1. Changing the raw nginx snippet is refused — the admin-only cap gate.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/api/v1/hostings/vhost-authz.cz/vhost")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"custom_nginx_snippet":"location /pwn { deny all; }"}"#,
                ))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "EditConfig-only key must NOT change the raw nginx snippet via the API",
    );
    let body = body_string(resp).await;
    assert!(
        body.contains("hosting_edit_nginx_raw"),
        "403 names the missing capability: {body}",
    );

    // 2. The same key CAN change other vhost options (snippet left at its
    //    stored empty value). The handler returns the applied VhostOptions.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/api/v1/hostings/vhost-authz.cz/vhost")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"waf_enabled":true}"#))
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "EditConfig-only key CAN change non-snippet vhost options",
    );
    let body = body_string(resp).await;
    assert!(
        body.contains("\"waf_enabled\":true"),
        "the non-snippet change was applied: {body}",
    );
    assert!(
        body.contains("\"custom_nginx_snippet\":\"\""),
        "the snippet stayed at its stored empty value: {body}",
    );
}

/// The hostings-list bulk action bar submits a multi-selection to
/// `/hostings/bulk`. Its selectors ride in ONE comma-joined `selected`
/// field, because `axum::Form` (serde_urlencoded) cannot gather a
/// repeated urlencoded key into a `Vec` — it 422s with "expected a
/// sequence", even for a single value (verified against axum 0.7.9).
///
/// So the fixed frontend joins the ticked ids into a single comma-joined
/// `selected` field. This regression guards that such a submission reaches
/// the handler and spawns the background job (303 → /jobs/…) instead of
/// dying on deserialization with a 422.
#[tokio::test]
async fn bulk_action_multi_select_does_not_422() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);

    // Log in.
    let login_body = b"username=kevin&password=good-pw&next=/";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_body.to_vec()))
                .unwrap(),
        )
        .await
        .expect("call");
    let cookie = extract_cookie(&resp);

    // Create a hosting so the list (and its bulk form + CSRF token) renders.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let csrf = extract_csrf(&body_string(resp).await);
    let create =
        format!("_csrf={csrf}&domain=bulk-e2e.cz&aliases=&php=8.3&db=mariadb&system_user=");
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(create))
                .unwrap(),
        )
        .await
        .expect("call");

    // Grab the bulk form's CSRF token off the list page.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let bulk_csrf = extract_csrf_named(&body_string(resp).await, "/hostings/bulk");

    // The shape the fixed frontend sends: one comma-joined `selected` field.
    let body = format!("_csrf={bulk_csrf}&action=suspend&selected=bulk-e2e.cz,other-e2e.cz");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings/bulk")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call");
    assert!(
        !resp.status().is_client_error() && !resp.status().is_server_error(),
        "comma-joined bulk submit errored: {} (a 422 here is the serde_urlencoded \
         Vec-of-repeated-keys bug)",
        resp.status()
    );
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .expect("redirect")
        .to_str()
        .expect("ascii");
    assert!(
        loc.starts_with("/jobs/"),
        "expected a job redirect, got {loc}"
    );
}

/// "Open phpMyAdmin": the Database card links to the separate phpMyAdmin
/// origin, and that origin re-checks the panel session and the hosting grant
/// on every request before anything is relayed to the owning node.
#[tokio::test]
async fn phpmyadmin_relay_is_gated_and_isolated() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let state = test_state(sock.clone(), admin, Arc::new(SessionSigner::new_random()));
    let app = hyperion_web::build_router(state.clone()).layer(
        axum::extract::connect_info::MockConnectInfo(
            "127.0.0.1:34567".parse::<std::net::SocketAddr>().unwrap(),
        ),
    );
    let pma = hyperion_web::handlers::pma::router(state);

    let login = |body: &'static [u8]| {
        Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_vec()))
            .unwrap()
    };
    let admin_cookie = extract_cookie(
        &app.clone()
            .oneshot(login(b"username=kevin&password=good-pw&next=/"))
            .await
            .unwrap(),
    );

    // A MariaDB hosting.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings/new")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csrf = extract_csrf(&body_string(resp).await);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/hostings")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::from(format!(
                    "_csrf={csrf}&domain=pma-e2e.cz&aliases=&php=8.3&db=mariadb&system_user="
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let id = match hyperion_rpc_client::call(
        &sock,
        hyperion_rpc::codec::Request::HostingGet(hyperion_rpc::wire::HostingSelector::Domain(
            hyperion_validate::Domain::parse("pma-e2e.cz").unwrap(),
        )),
    )
    .await
    .unwrap()
    {
        hyperion_rpc::codec::Response::HostingGet(d) => d.id.as_str().to_string(),
        other => panic!("unexpected: {other:?}"),
    };

    // The detail page offers phpMyAdmin on the same host, its own port.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/hostings/{id}"))
                .header(header::HOST, "panel.test:8443")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_string(resp).await;
    assert!(
        html.contains(&format!("https://panel.test:8447/pma/{id}/")),
        "Database card must link to the phpMyAdmin origin"
    );

    // The panel origin never serves phpMyAdmin...
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/pma/{id}/"))
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // ...and the phpMyAdmin origin never serves the panel.
    let resp = pma
        .clone()
        .oneshot(
            Request::builder()
                .uri("/hostings")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let pma_get = |cookie: Option<&str>, method: Method, path: String| {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "panel.test:8447");
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        b.body(Body::empty()).unwrap()
    };

    // No session → 401, with phpMyAdmin's CSP on the error page too.
    let resp = pma
        .clone()
        .oneshot(pma_get(None, Method::GET, format!("/pma/{id}/")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let csp = resp.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'"));

    // Malformed id → 404 before any lookup.
    let resp = pma
        .clone()
        .oneshot(pma_get(
            Some(&admin_cookie),
            Method::GET,
            "/pma/pma-e2e.cz/".into(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Methods phpMyAdmin never uses are refused.
    let resp = pma
        .clone()
        .oneshot(pma_get(
            Some(&admin_cookie),
            Method::PUT,
            format!("/pma/{id}/"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Admin → relayed to the owning node (the local agent here). The test box
    // has no phpMyAdmin socket, so the node's own answer comes back as a 502
    // that says so — proof the request made it through every gate.
    let resp = pma
        .clone()
        .oneshot(pma_get(
            Some(&admin_cookie),
            Method::GET,
            format!("/pma/{id}/"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(body_string(resp)
        .await
        .contains("not installed on this node"));

    // A viewer with no grant on this hosting is stopped at the panel.
    hyperion_rpc_client::call(
        &sock,
        hyperion_rpc::codec::Request::WebUserCreate {
            username: "php-viewer".into(),
            email: "php-viewer@example.invalid".into(),
            password: "viewer-pw-1".into(),
            role: "viewer".into(),
        },
    )
    .await
    .unwrap();
    let viewer_cookie = extract_cookie(
        &app.clone()
            .oneshot(login(b"username=php-viewer&password=viewer-pw-1&next=/"))
            .await
            .unwrap(),
    );
    let resp = pma
        .clone()
        .oneshot(pma_get(
            Some(&viewer_cookie),
            Method::GET,
            format!("/pma/{id}/"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ───────────────────────── first-run setup wizard ─────────────────────────

/// A fresh install: no bootstrap admin, setup pending with a known code.
async fn setup_app() -> (
    axum::Router,
    Arc<hyperion_web::setup::SetupCtl>,
    String,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let (sock, agent_dir) = start_agent().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("setup.json");
    let code = hyperion_web::setup::issue_code(&path, hyperion_types::now_secs())
        .expect("write")
        .expect("code");
    let ctl = Arc::new(hyperion_web::setup::SetupCtl::load(path));
    let state = test_state_with_setup(
        sock,
        AdminUser::disabled(),
        Arc::new(SessionSigner::new_random()),
        ctl.clone(),
    );
    let router =
        hyperion_web::build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
            // Own peer address: the setup code shares the login throttle.
            "127.0.0.9:34567".parse::<std::net::SocketAddr>().unwrap(),
        ));
    (router, ctl, code, dir, agent_dir)
}

/// `name=value` of the Set-Cookie header for `name`, among several.
fn cookie_named(resp: &axum::response::Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|raw| raw.split(';').next().unwrap_or("").to_string())
        .find(|kv| kv.split_once('=').map(|(k, v)| k == name && !v.is_empty()) == Some(true))
}

fn location(resp: &axum::response::Response) -> String {
    resp.headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

async fn get_with(app: &axum::Router, uri: &str, cookie: &str) -> axum::response::Response {
    let mut b = Request::builder().uri(uri);
    if !cookie.is_empty() {
        b = b.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .expect("call")
}

async fn post_form(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
    form: &str,
) -> axum::response::Response {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookie.is_empty() {
        b = b.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(b.body(Body::from(form.to_string())).unwrap())
        .await
        .expect("call")
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// While nobody owns the panel, everything leads to the wizard — and the
/// probes keep answering.
#[tokio::test]
async fn setup_gate_sends_everything_to_the_wizard() {
    let (app, _ctl, code, _d, _a) = setup_app().await;
    for path in ["/", "/login", "/hostings", "/settings", "/install"] {
        let r = get_with(&app, path, "").await;
        assert!(r.status().is_redirection(), "{path}: {}", r.status());
        assert_eq!(location(&r), "/setup", "{path}");
    }
    assert_eq!(
        get_with(&app, "/healthz", "").await.status(),
        StatusCode::OK
    );
    // The installer's link carries the code on to the access step.
    let r = get_with(&app, &format!("/setup?t={code}"), "").await;
    let compact = hyperion_web::setup::normalize_code(&code);
    assert_eq!(location(&r), format!("/setup/access?t={compact}"));
    let (status, body) = get_body(app.clone(), &format!("/setup/access?t={compact}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&code), "code not prefilled: {body}");
}

/// The setup code opens the admin step once; a wrong or used code does not.
#[tokio::test]
async fn setup_code_is_checked_and_single_use() {
    let (app, _ctl, code, _d, _a) = setup_app().await;
    let r = post_form(&app, "/setup/access", "", "code=AAAA-BBBB-CCCC-DDDD").await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(cookie_named(&r, "hyperion_session_setup").is_none());
    let body = body_string(r).await;
    assert!(body.contains("match"), "{body}");

    // No setup cookie → the admin step is not reachable.
    let r = get_with(&app, "/setup/admin", "").await;
    assert_eq!(location(&r), "/setup/access");

    let r = post_form(
        &app,
        "/setup/access",
        "",
        &format!("code={}", enc(&code.to_lowercase())),
    )
    .await;
    assert!(r.status().is_redirection(), "{}", r.status());
    assert_eq!(location(&r), "/setup/admin");
    let setup_cookie = cookie_named(&r, "hyperion_session_setup").expect("setup cookie");

    let r = post_form(&app, "/setup/access", "", &format!("code={}", enc(&code))).await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_string(r).await.contains("already been used"));

    let r = get_with(&app, "/setup/admin", &setup_cookie).await;
    assert_eq!(r.status(), StatusCode::OK);
    // The setup cookie is not a session: the rest of the panel still bounces.
    let r = get_with(&app, "/hostings", &setup_cookie).await;
    assert_eq!(location(&r), "/setup");
}

/// The admin step creates a real super_admin, signs it in, and from then on
/// the panel behaves normally except that `/` leads back to the wizard.
#[tokio::test]
async fn setup_admin_step_creates_the_owner_and_signs_in() {
    let (app, ctl, code, _d, _a) = setup_app().await;
    let r = post_form(&app, "/setup/access", "", &format!("code={}", enc(&code))).await;
    let setup_cookie = cookie_named(&r, "hyperion_session_setup").expect("setup cookie");
    let page = body_string(get_with(&app, "/setup/admin", &setup_cookie).await).await;
    let csrf = extract_csrf(&page);

    // No CSRF token → refused.
    let r = post_form(
        &app,
        "/setup/admin",
        &setup_cookie,
        "username=kevin&email=k%40example.cz&password=correct-horse-battery&password2=correct-horse-battery",
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Too short a password → the form again, with the reason.
    let r = post_form(
        &app,
        "/setup/admin",
        &setup_cookie,
        &format!(
            "username=kevin&email=k%40example.cz&password=short&password2=short&_csrf={}",
            enc(&csrf)
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_string(r).await.contains("at least 12"));

    let r = post_form(
        &app,
        "/setup/admin",
        &setup_cookie,
        &format!(
            "username=kevin&email=k%40example.cz&password=correct-horse-battery&password2=correct-horse-battery&_csrf={}",
            enc(&csrf)
        ),
    )
    .await;
    assert!(r.status().is_redirection(), "{}", r.status());
    assert_eq!(location(&r), "/setup/2fa");
    let session = cookie_named(&r, "hyperion_session").expect("session cookie");
    assert!(ctl.admin_created());

    // Signed in: the dashboard leads back to the wizard, other pages open.
    let r = get_with(&app, "/", &session).await;
    assert_eq!(location(&r), "/setup");
    let r = get_with(&app, "/hostings", &session).await;
    assert_eq!(r.status(), StatusCode::OK);
    // The wizard resumes at the first unfinished step.
    let r = get_with(&app, "/setup", &session).await;
    assert_eq!(location(&r), "/setup/2fa");
    // The two-factor step shows a QR code and backup codes.
    let r = get_with(&app, "/setup/2fa", &session).await;
    assert_eq!(r.status(), StatusCode::OK);
    let body = body_string(r).await;
    assert!(body.contains("<svg"), "no QR: {body}");
    assert!(body.contains("setup-codes"));

    // The admin step cannot run twice.
    let r = post_form(
        &app,
        "/setup/admin",
        &setup_cookie,
        &format!(
            "username=mallory&email=m%40example.cz&password=correct-horse-battery&password2=correct-horse-battery&_csrf={}",
            enc(&csrf)
        ),
    )
    .await;
    assert_eq!(location(&r), "/setup");

    // There is no bootstrap account to sign in as, and saying so is not a 500.
    let r = post_form(
        &app,
        "/login",
        "",
        "username=admin&password=whatever&next=%2F",
    )
    .await;
    assert!(
        r.status().is_redirection() || r.status().is_success(),
        "{}",
        r.status()
    );
    // ... while the real owner signs in normally.
    let r = post_form(
        &app,
        "/login",
        "",
        "username=kevin&password=correct-horse-battery&next=%2F",
    )
    .await;
    assert!(cookie_named(&r, "hyperion_session").is_some());
}

/// Nothing to install yet → the wizard will not finish; a finished setup
/// leaves no trace of the wizard.
#[tokio::test]
async fn setup_finish_needs_php_and_then_the_wizard_is_gone() {
    let (app, ctl, code, _d, _a) = setup_app().await;
    let r = post_form(&app, "/setup/access", "", &format!("code={}", enc(&code))).await;
    let setup_cookie = cookie_named(&r, "hyperion_session_setup").unwrap();
    let csrf =
        extract_csrf(&body_string(get_with(&app, "/setup/admin", &setup_cookie).await).await);
    let r = post_form(
        &app,
        "/setup/admin",
        &setup_cookie,
        &format!(
            "username=kevin&email=k%40example.cz&password=correct-horse-battery&password2=correct-horse-battery&_csrf={}",
            enc(&csrf)
        ),
    )
    .await;
    let session = cookie_named(&r, "hyperion_session").unwrap();

    // An unknown component never reaches the agent's unit.
    let page = body_string(get_with(&app, "/setup/stack", &session).await).await;
    let csrf = extract_csrf(&page);
    let r = post_form(
        &app,
        "/setup/stack",
        &session,
        &format!("php=php7.4&_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_string(r).await.contains("unknown component"));

    let r = post_form(
        &app,
        "/setup/finish",
        &session,
        &format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_string(r).await.contains("Install PHP first"));
    assert!(ctl.is_active());

    ctl.update(|f| f.state = hyperion_web::setup::STATE_COMPLETED.into())
        .unwrap();
    assert_eq!(
        get_with(&app, "/setup", &session).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get_with(&app, "/setup/access", "").await.status(),
        StatusCode::NOT_FOUND
    );
    let r = get_with(&app, "/", &session).await;
    assert_eq!(r.status(), StatusCode::OK);
}

/// /vulns: empty state, then three WordPress sites — one with a major
/// update, one the sweep has not reached, one up to date — sorted into the
/// buckets the page promises, with the segment filter narrowing the list.
#[tokio::test]
async fn wordpress_updates_page_sorts_sites_by_what_they_need() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    use hyperion_rpc::wire::HostingCreateReq;

    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    b"username=kevin&password=good-pw&next=/".to_vec(),
                ))
                .unwrap(),
        )
        .await
        .expect("login");
    let cookie = extract_cookie(&resp);
    let get = |uri: &'static str| {
        let app = app.clone();
        let cookie = cookie.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("call");
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            body_string(resp).await
        }
    };

    let body = get("/vulns").await;
    assert!(
        body.contains("No WordPress sites yet"),
        "missing empty state"
    );

    let now = hyperion_types::now_secs();
    let mut ids = Vec::new();
    for d in ["major.example.cz", "fresh.example.cz", "clean.example.cz"] {
        match hyperion_rpc_client::call(
            &sock,
            RpcReq::HostingCreate(HostingCreateReq {
                domain: hyperion_validate::Domain::parse(d).expect("domain"),
                aliases: vec![],
                php_version: None,
                database: None,
                system_user: None,
                kind: "php".into(),
                proxy_upstream_url: None,
            }),
        )
        .await
        .expect("seed hosting")
        {
            RpcResp::HostingCreate(_) => {}
            other => panic!("unexpected create: {other:?}"),
        }
        let (id,): (String,) = sqlx::query_as("SELECT id FROM hostings WHERE domain = ?")
            .bind(d)
            .fetch_one(&pool)
            .await
            .expect("id");
        sqlx::query(
            "INSERT INTO wp_installs (hosting_id, site_url, wp_version, installed_at, last_pack_hash) \
             VALUES (?, 'https://x', '6.6.2', ?, 'h')",
        )
        .bind(&id)
        .bind(now)
        .execute(&pool)
        .await
        .expect("wp row");
        ids.push(id);
    }
    let stored = |findings: Vec<hyperion_types::WpVulnFinding>| {
        serde_json::json!({
            "scanned_at": now - 3600,
            "result": hyperion_types::WpVulnScanResult {
                findings,
                checked: 7,
                core_version: "6.6.2".into(),
                core_checked: true,
                ..Default::default()
            },
        })
        .to_string()
    };
    let major = hyperion_core::wp_updates::outdated_finding(
        "woocommerce",
        "WooCommerce",
        "plugin",
        "8.7.0",
        "9.0.1",
    );
    for (id, json) in [(&ids[0], stored(vec![major])), (&ids[2], stored(vec![]))] {
        hyperion_state::hosting_kv::set(&pool, id, "vuln_scan", &json, now)
            .await
            .expect("store scan");
    }

    let body = get("/vulns").await;
    assert!(
        body.contains("1 site needs you — 1 major update"),
        "verdict"
    );
    for bucket in ["needs", "unchecked", "ok"] {
        assert!(
            body.contains(&format!("data-bucket=\"{bucket}\"")),
            "bucket {bucket} missing"
        );
    }
    assert!(body.contains("WooCommerce 8.7.0 → 9.0.1"), "headline");
    assert!(
        body.contains("Not checked yet"),
        "never-scanned site must be a row"
    );
    assert!(body.contains("7 plugins &amp; themes current · core current"));

    let body = get("/vulns?show=needs").await;
    assert!(body.contains("major.example.cz"));
    assert!(!body.contains("clean.example.cz"), "segment filter leaked");
    // Counts are taken before the segment: Up to date still says 1.
    assert!(body.contains("Up to date <span class=\"seg-count\">1</span>"));

    let body = get("/vulns?q=woocommerce").await;
    assert!(body.contains("major.example.cz"));
    assert!(!body.contains("fresh.example.cz"), "search leaked");
}

/// Every Settings page renders for an Owner and carries every card the card
/// table puts on it — the ids every save redirect and deep link land on.
/// Runs against the real router and a stub agent, so a page whose handler
/// fails on an empty install (no nodes, no targets, default config) shows up
/// here rather than as a 500 on a fresh box.
#[tokio::test]
async fn every_settings_page_renders_with_its_cards() {
    use hyperion_web::handlers::settings::chrome::{CARDS, SECTIONS};
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    b"username=kevin&password=good-pw&next=/".to_vec(),
                ))
                .unwrap(),
        )
        .await
        .expect("login");
    let cookie = extract_cookie(&resp);
    let get = |uri: String| {
        let app = app.clone();
        let cookie = cookie.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri(&uri)
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("call");
            (resp.status(), body_string(resp).await)
        }
    };

    let (status, body) = get("/settings".into()).await;
    assert_eq!(status, StatusCode::OK, "/settings");
    assert!(body.contains("svc-verdict"), "overview has no verdict line");
    for s in SECTIONS.iter().filter(|s| !s.cluster_only) {
        assert!(
            body.contains(&format!("href=\"/settings/{}\"", s.slug)),
            "overview does not link /settings/{}",
            s.slug
        );
    }

    for s in SECTIONS {
        let (status, body) = get(format!("/settings/{}", s.slug)).await;
        assert_eq!(status, StatusCode::OK, "/settings/{}: {body}", s.slug);
        for (card, page) in CARDS.iter().filter(|(_, p)| *p == s.slug) {
            assert!(
                body.contains(&format!("id=\"{card}\"")),
                "/settings/{page} has no #{card}"
            );
        }
        assert!(
            !body.contains("STUB"),
            "/settings/{} is still the skeleton stub",
            s.slug
        );
    }

    let (status, body) = get("/admin/api-keys".into()).await;
    assert_eq!(status, StatusCode::OK, "/admin/api-keys");
    assert!(body.contains("Create a key"));
}

/// The old per-node Mail link (`/settings?mail_node=X#mail`) still lands on
/// that node's Mail page.
#[tokio::test]
async fn old_mail_node_link_lands_on_the_mail_page() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    b"username=kevin&password=good-pw&next=/".to_vec(),
                ))
                .unwrap(),
        )
        .await
        .expect("login");
    let cookie = extract_cookie(&resp);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/settings?mail_node=web-2")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert!(resp.status().is_redirection());
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/settings/mail?node=web-2")
    );
}

/// The older whole-letter templates in `[notifications]` replace the letter
/// editor for every language. The Customer letters page names them, and
/// "Move into the editor" puts their text into the catalogue strings and
/// empties the templates — after which the page no longer warns.
#[tokio::test]
async fn older_letter_templates_move_into_the_editor() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, cfg) = start_agent_with_toml(
        "[notifications]\n\
         care_report_body_template = \"Dobry den, {domain}.\\r\\n{uptime}\"\n\
         expiry_warning_subject_template = \"Konci {domain}: {days_left}\"\n",
    )
    .await;
    let app = build_app(sock, admin);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    b"username=kevin&password=good-pw&next=/".to_vec(),
                ))
                .unwrap(),
        )
        .await
        .expect("login");
    let cookie = extract_cookie(&resp);
    let get = || {
        let app = app.clone();
        let cookie = cookie.clone();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/settings/letters")
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("call");
            assert_eq!(resp.status(), StatusCode::OK);
            body_string(resp).await
        }
    };

    let page = get().await;
    assert!(page.contains("older template in force"), "no warning");
    assert!(
        page.contains("the care report body and the expiry warning subject"),
        "the warning does not name what is set"
    );
    let csrf = extract_csrf(&page);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/settings/letters/adopt-legacy")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(format!("_csrf={csrf}&mode=move")))
                .unwrap(),
        )
        .await
        .expect("call");
    let to = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        to.starts_with("/settings/letters?flash=") && to.ends_with("#customer-letters"),
        "{to}"
    );

    let toml = std::fs::read_to_string(&cfg).expect("agent.toml");
    let doc: toml_edit::DocumentMut = toml.parse().expect("toml");
    let letters = doc["letters"].as_table().expect("[letters]");
    assert_eq!(
        letters["care.body"].as_str(),
        Some("Dobry den, {domain}.\n{uptime}"),
        "{toml}"
    );
    // The old subject's {days_left} is the catalogue's {days} {unit}.
    assert_eq!(
        letters["expiry.subject.days"].as_str(),
        Some("Konci {domain}: {days} {unit}"),
        "{toml}"
    );
    for key in [
        "care_report_subject_template",
        "care_report_body_template",
        "expiry_warning_subject_template",
        "expiry_warning_body_template",
    ] {
        assert_eq!(
            doc["notifications"][key].as_str(),
            Some(""),
            "{key} left in force: {toml}"
        );
    }

    let page = get().await;
    assert!(!page.contains("older template in force"), "still warns");

    // The Languages card saves all three of its keys. `billing_lang` (and
    // `operator_lang`) used to be refused by the agent, which failed the
    // whole form.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/settings/config")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &cookie)
                .body(Body::from(format!(
                    "_csrf={csrf}&section=letters&_return_tab=letter-language\
                     &lang=cs&overrides_lang=cs&billing_lang=en"
                )))
                .unwrap(),
        )
        .await
        .expect("call");
    let to = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        to.starts_with("/settings/letters?flash=") && to.ends_with("#letter-language"),
        "{to}"
    );
    let toml = std::fs::read_to_string(&cfg).expect("agent.toml");
    assert!(toml.contains("billing_lang = \"en\""), "{toml}");
    assert!(toml.contains("lang = \"cs\""), "{toml}");
}

/// Lifecycle & billing → Price: an admin sets one site's price by hand and
/// pins it; an operator — who may edit the site but not what it costs — is
/// refused.
#[tokio::test]
async fn hosting_price_is_set_on_the_detail_page_and_only_by_admins() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);

    let resp = post_form(&app, "/login", "", "username=kevin&password=good-pw&next=/").await;
    let admin_cookie = extract_cookie(&resp);

    let new_page = body_string(get_with(&app, "/hostings/new", &admin_cookie).await).await;
    let csrf = extract_csrf(&new_page);
    let resp = post_form(
        &app,
        "/hostings",
        &admin_cookie,
        &format!("_csrf={csrf}&domain=cena-e2e.cz&aliases=&php=8.3&db=mariadb&system_user="),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let detail = body_string(get_with(&app, "/hostings/cena-e2e.cz", &admin_cookie).await).await;
    let csrf = extract_csrf_named(&detail, "/hostings/price/set");
    let resp = post_form(
        &app,
        "/hostings/price/set",
        &admin_cookie,
        &format!(
            "_csrf={}&selector=cena-e2e.cz&price_major=2400&price_currency=czk&price_interval=yearly&pinned=on",
            enc(&csrf)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let to = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(to.contains("price=set"), "redirect: {to}");

    let applied = match hyperion_rpc_client::call(
        &sock,
        hyperion_rpc::codec::Request::ProfileGetApply {
            sel: hyperion_rpc::wire::HostingSelector::Domain(
                hyperion_validate::Domain::parse("cena-e2e.cz").unwrap(),
            ),
        },
    )
    .await
    .expect("rpc")
    {
        hyperion_rpc::codec::Response::ProfileGetApply(Some(a)) => a,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(applied.pretty_price(), "2400.00 CZK/year");
    assert!(applied.price_pinned);

    let detail = body_string(get_with(&app, "/hostings/cena-e2e.cz", &admin_cookie).await).await;
    assert!(detail.contains("2400.00 CZK/year"), "price pill missing");
    assert!(detail.contains(">set here<"), "pinned tag missing");

    // An operator holds the per-site edit capability but not ProfilesManage.
    match hyperion_rpc_client::call(
        &sock,
        hyperion_rpc::codec::Request::WebUserCreate {
            username: "price-op".into(),
            email: "price-op@example.invalid".into(),
            password: "operator-pw-1".into(),
            role: "operator".into(),
        },
    )
    .await
    .expect("create operator")
    {
        hyperion_rpc::codec::Response::WebUserCreate { .. } => {}
        other => panic!("unexpected create response: {other:?}"),
    }
    let resp = post_form(
        &app,
        "/login",
        "",
        "username=price-op&password=operator-pw-1&next=/",
    )
    .await;
    let op_cookie = extract_cookie(&resp);
    let profile_page = body_string(get_with(&app, "/profile", &op_cookie).await).await;
    let op_csrf = extract_csrf(&profile_page);
    let resp = post_form(
        &app,
        "/hostings/price/set",
        &op_cookie,
        &format!(
            "_csrf={}&selector=cena-e2e.cz&price_major=1&price_currency=CZK&price_interval=yearly",
            enc(&op_csrf)
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Log in as `user` (created via RPC when not the bootstrap admin) and
/// return the session cookie.
async fn acme_dns_login(app: &axum::Router, user: &str, pw: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("username={user}&password={pw}&next=/")))
                .unwrap(),
        )
        .await
        .expect("login");
    extract_cookie(&resp)
}

async fn acme_dns_post(
    app: &axum::Router,
    cookie: &str,
    uri: &str,
    body: String,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .expect("call")
}

async fn acme_dns_get(app: &axum::Router, cookie: &str, uri: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    let status = resp.status();
    (status, body_string(resp).await)
}

#[tokio::test]
async fn acme_dns_card_renders_records_for_admin() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/settings/https").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("id=\"acme-dns\""), "card missing");
    assert!(page.contains("Delegated acme zone"));
    assert!(page.contains("/settings/https/acme-dns/check"));
    // The deep link resolves through CARDS.
    assert_eq!(
        hyperion_web::handlers::settings::chrome::card_url("acme-dns", ""),
        "/settings/https#acme-dns"
    );

    // Save a zone (responder off) and the records to add appear.
    let csrf = extract_csrf(&page);
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/settings/https/acme-dns",
        format!(
            "_csrf={csrf}&zone=acme.panel.example.com&ns_host=ns-acme.example.com\
             &public_ipv4=203.0.113.9&public_ipv6=2001%3Adb8%3A%3A9"
        ),
    )
    .await;
    let to = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        to.starts_with("/settings/https?flash=") && to.ends_with("#acme-dns"),
        "{to}"
    );
    let (_, page) = acme_dns_get(&app, &cookie, "/settings/https").await;
    for line in [
        "acme.panel.example.com NS ns-acme.example.com.",
        "ns-acme.example.com A 203.0.113.9",
        "ns-acme.example.com AAAA 2001:db8::9",
    ] {
        assert!(page.contains(line), "missing record {line}");
    }
    // Saved but not delegated anywhere: the check never claims it works.
    let csrf = extract_csrf(&page);
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/settings/https/acme-dns/check",
        format!("_csrf={csrf}"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cell = body_string(resp).await;
    assert!(cell.contains("pill") && !cell.contains("working"), "{cell}");
    assert!(cell.contains("delegation missing"), "{cell}");
    assert!(cell.contains(OFFLINE_DNS), "public DNS was asked: {cell}");
}

#[tokio::test]
async fn acme_dns_save_refusal_rerenders_in_place() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (_, page) = acme_dns_get(&app, &cookie, "/settings/https").await;
    let csrf = extract_csrf(&page);
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/settings/https/acme-dns",
        format!("_csrf={csrf}&zone=not+a+zone%21&ns_host=ns.example.com&public_ipv4="),
    )
    .await;
    // No redirect: the card comes back with the message and what was typed.
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_string(resp).await;
    assert!(page.contains("Not saved."), "no refusal shown");
    assert!(page.contains("zone:"), "agent's message missing");
    assert!(page.contains("value=\"not a zone!\""), "input not kept");
}

#[tokio::test]
async fn acme_dns_settings_forbidden_for_customer() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    hyperion_rpc_client::call(
        &sock,
        hyperion_rpc::codec::Request::WebUserCreate {
            username: "acme-cust".into(),
            email: "acme-cust@example.invalid".into(),
            password: "customer-pw-1".into(),
            role: "customer".into(),
        },
    )
    .await
    .expect("create customer");
    let cookie = acme_dns_login(&app, "acme-cust", "customer-pw-1").await;
    let (_, profile) = acme_dns_get(&app, &cookie, "/profile").await;
    let csrf = extract_csrf(&profile);
    for uri in ["/settings/https/acme-dns", "/settings/https/acme-dns/check"] {
        let resp = acme_dns_post(
            &app,
            &cookie,
            uri,
            format!("_csrf={csrf}&zone=acme.example.com&ns_host=ns.example.com"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
    }
}

/// A custom role with every hosting's certificates but no global
/// settings may not change the delegated zone either: the zone lives on
/// Settings -> HTTPS, which needs `SettingsManage`.
#[tokio::test]
async fn acme_dns_settings_need_settings_manage() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    use hyperion_state::capabilities::Capability;
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let role_id = match hyperion_rpc_client::call(
        &sock,
        RpcReq::RoleCreate {
            name: "cert-only".into(),
            capabilities: Capability::CertManage.bit() | Capability::HostingView.bit(),
            scope_all: true,
        },
    )
    .await
    .expect("role")
    {
        RpcResp::RoleCreate { id } => id,
        other => panic!("unexpected role create: {other:?}"),
    };
    let user_id = match hyperion_rpc_client::call(
        &sock,
        RpcReq::WebUserCreate {
            username: "certs".into(),
            email: "certs@example.invalid".into(),
            password: "certs-pw-12345".into(),
            role: "operator".into(),
        },
    )
    .await
    .expect("user")
    {
        RpcResp::WebUserCreate { id } => id,
        other => panic!("unexpected user create: {other:?}"),
    };
    match hyperion_rpc_client::call(
        &sock,
        RpcReq::WebUserSetCustomRole {
            user_id,
            custom_role_id: role_id,
        },
    )
    .await
    .expect("assign")
    {
        RpcResp::WebUserSetCustomRole => {}
        other => panic!("unexpected assign: {other:?}"),
    }
    let cookie = acme_dns_login(&app, "certs", "certs-pw-12345").await;
    let (_, profile) = acme_dns_get(&app, &cookie, "/profile").await;
    let csrf = extract_csrf(&profile);
    for uri in ["/settings/https/acme-dns", "/settings/https/acme-dns/check"] {
        let resp = acme_dns_post(
            &app,
            &cookie,
            uri,
            format!(
                "_csrf={}&zone=acme.example.com&ns_host=ns.example.com",
                enc(&csrf)
            ),
        )
        .await;
        let status = resp.status();
        let body = body_string(resp).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        assert!(
            !body.contains("CSRF check failed"),
            "{uri}: refused by CSRF"
        );
    }
    match hyperion_rpc_client::call(&sock, RpcReq::AcmeDnsConfigGet)
        .await
        .expect("config")
    {
        RpcResp::AcmeDnsConfig(c) => assert_eq!(c.zone, None, "the zone was saved"),
        other => panic!("unexpected config: {other:?}"),
    }
}

// ─── Automatic wildcard renewal from the SSL tab ────────────────────────

/// Seed one hosting through the agent and return its id.
async fn acme_ssl_hosting(sock: &std::path::Path, domain: &str) -> String {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    match hyperion_rpc_client::call(
        sock,
        RpcReq::HostingCreate(hyperion_rpc::wire::HostingCreateReq {
            domain: hyperion_validate::Domain::parse(domain).expect("domain"),
            aliases: vec![],
            php_version: None,
            database: None,
            system_user: None,
            kind: "php".into(),
            proxy_upstream_url: None,
        }),
    )
    .await
    .expect("seed hosting")
    {
        RpcResp::HostingCreate(_) => {}
        other => panic!("unexpected create: {other:?}"),
    }
    match hyperion_rpc_client::call(
        sock,
        RpcReq::HostingGet(hyperion_rpc::wire::HostingSelector::Domain(
            hyperion_validate::Domain::parse(domain).expect("domain"),
        )),
    )
    .await
    .expect("get hosting")
    {
        RpcResp::HostingGet(d) => d.id.as_str().to_string(),
        other => panic!("unexpected get: {other:?}"),
    }
}

/// Save a delegated zone (responder off: nothing binds port 53 in tests).
async fn acme_ssl_zone(sock: &std::path::Path) {
    match hyperion_rpc_client::call(
        sock,
        hyperion_rpc::codec::Request::AcmeDnsConfigSet {
            zone: Some("acme.panel.example.com".into()),
            ns_host: "ns-acme.example.com".into(),
            public_ipv4: Some("203.0.113.9".into()),
            public_ipv6: None,
            enabled: false,
        },
    )
    .await
    .expect("zone")
    {
        hyperion_rpc::codec::Response::AcmeDnsConfig(_) => {}
        other => panic!("unexpected zone save: {other:?}"),
    }
}

async fn acme_ssl_labels(sock: &std::path::Path) -> Vec<hyperion_types::AcmeDnsLabel> {
    match hyperion_rpc_client::call(sock, hyperion_rpc::codec::Request::AcmeDnsLabels)
        .await
        .expect("labels")
    {
        hyperion_rpc::codec::Response::AcmeDnsLabels(l) => l,
        other => panic!("unexpected labels: {other:?}"),
    }
}

/// A customer with manage access to `hosting_id`; returns their cookie.
async fn acme_ssl_customer(app: &axum::Router, sock: &std::path::Path, hosting_id: &str) -> String {
    acme_ssl_user(app, sock, "customer", Some(hosting_id)).await
}

/// A `role` user (named `ssl-<role>`), with manage access to `hosting_id`
/// when given; returns their cookie.
async fn acme_ssl_user(
    app: &axum::Router,
    sock: &std::path::Path,
    role: &str,
    hosting_id: Option<&str>,
) -> String {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    let username = format!("ssl-{role}");
    let user_id = match hyperion_rpc_client::call(
        sock,
        RpcReq::WebUserCreate {
            username: username.clone(),
            email: format!("{username}@example.invalid"),
            password: "role-pw-12345".into(),
            role: role.into(),
        },
    )
    .await
    .expect("create customer")
    {
        RpcResp::WebUserCreate { id } => id,
        other => panic!("unexpected create: {other:?}"),
    };
    if let Some(hosting_id) = hosting_id {
        match hyperion_rpc_client::call(
            sock,
            RpcReq::WebGrantHostingAccess {
                user_id,
                hosting_id: hosting_id.to_string(),
                level: "manage".into(),
                granted_by: None,
            },
        )
        .await
        .expect("grant")
        {
            RpcResp::WebGrantHostingAccess => {}
            other => panic!("unexpected grant: {other:?}"),
        }
    }
    acme_dns_login(app, &username, "role-pw-12345").await
}

/// Wait for a background job to finish; returns its final state.
async fn acme_ssl_wait_job(sock: &std::path::Path, location: &str) -> String {
    let id = location.trim_start_matches("/jobs/").to_string();
    for _ in 0..200 {
        if let Ok(hyperion_rpc::codec::Response::JobGet(Some(j))) = hyperion_rpc_client::call(
            sock,
            hyperion_rpc::codec::Request::JobGet { id: id.clone() },
        )
        .await
        {
            if j.is_terminal() {
                return j.state;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("job {id} did not finish");
}

/// The session-wide CSRF token (valid at any path), from /profile.
async fn acme_ssl_csrf(app: &axum::Router, cookie: &str) -> String {
    let (_, profile) = acme_dns_get(app, cookie, "/profile").await;
    extract_csrf(&profile)
}

#[tokio::test]
async fn ssl_tab_shows_cname_block_to_operator() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-e2e.cz").await;
    acme_ssl_zone(&sock).await;
    // A built-in operator (tenant-scoped) with access to this hosting.
    let cookie = acme_ssl_user(&app, &sock, "operator", Some(&id)).await;

    // Before setup: an offer to set it up, no target yet.
    let (status, page) = acme_dns_get(&app, &cookie, &format!("/hostings/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    let setup = format!("/hostings/{id}/cert/acme-dns/setup");
    assert!(page.contains(&setup), "setup form missing");

    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(&app, &cookie, &setup, format!("_csrf={}", enc(&csrf))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let block = body_string(resp).await;
    let label = acme_ssl_labels(&sock).await;
    assert_eq!(label.len(), 1);
    assert_eq!(label[0].hosting_id.as_deref(), Some(id.as_str()));
    let target = format!("{}.acme.panel.example.com", label[0].label);
    assert!(block.contains("_acme-challenge.acmessl-e2e.cz"), "{block}");
    assert!(block.contains(&target), "target missing: {block}");
    assert!(block.contains(&format!("/hostings/{id}/cert/acme-dns/check")));
    // A second click cannot start a parallel probe.
    assert!(block.contains("hx-disabled-elt=\"find button\""));
    // The CNAME check ran, against the offline resolver.
    assert!(block.contains(OFFLINE_DNS), "public DNS was asked: {block}");
    assert_eq!(
        acme_ssl_labels(&sock).await[0].last_check_error.as_deref(),
        Some(OFFLINE_DNS)
    );

    // The tab now carries the block on every render.
    let (_, page) = acme_dns_get(&app, &cookie, &format!("/hostings/{id}")).await;
    assert!(page.contains("_acme-challenge.acmessl-e2e.cz"));
    assert!(page.contains(&target));
    assert!(
        page.contains("until it is removed"),
        "consent sentence missing"
    );
    // Not verified (no such CNAME exists): no one-click issue yet.
    assert!(!page.contains(&format!("/hostings/{id}/cert/dns01/auto")));
}

#[tokio::test]
async fn ssl_tab_shows_only_state_to_customer() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-cust.cz").await;
    acme_ssl_zone(&sock).await;
    hyperion_rpc_client::call(
        &sock,
        hyperion_rpc::codec::Request::AcmeDnsLabelEnsure {
            base: hyperion_validate::Domain::parse("acmessl-cust.cz").expect("domain"),
            hosting_id: Some(id.clone()),
        },
    )
    .await
    .expect("label");
    let cookie = acme_ssl_customer(&app, &sock, &id).await;
    let (status, page) = acme_dns_get(&app, &cookie, &format!("/hostings/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Automatic renewal"), "state line missing");
    assert!(
        page.contains("acme-ssl-state\">off<"),
        "state should be off"
    );
    assert!(
        !page.contains(".acme."),
        "CNAME target leaked to a customer"
    );
    assert!(!page.contains("/cert/acme-dns/"), "setup/check form leaked");
    assert!(!page.contains("/cert/dns01/auto"), "issue button leaked");
}

/// No wildcard and no label: the customer has nothing to read about
/// automatic renewal, so no "off" line on every site.
#[tokio::test]
async fn ssl_tab_hides_renewal_from_customer_without_a_wildcard() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-plain.cz").await;
    acme_ssl_zone(&sock).await;
    let cookie = acme_ssl_customer(&app, &sock, &id).await;
    let (status, page) = acme_dns_get(&app, &cookie, &format!("/hostings/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!page.contains("acme-ssl-card"), "renewal card shown");
    assert!(!page.contains("Automatic renewal"), "state line shown");
}

#[tokio::test]
async fn acme_dns_setup_forbidden_for_customer() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-forbid.cz").await;
    let cookie = acme_ssl_customer(&app, &sock, &id).await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    for uri in [
        format!("/hostings/{id}/cert/acme-dns/setup"),
        format!("/hostings/{id}/cert/acme-dns/check"),
        format!("/hostings/{id}/cert/dns01/auto"),
        "/settings/https/preview/local/acme-dns/setup".to_string(),
        "/settings/https/preview/local/acme-dns/check".to_string(),
        "/settings/https/preview/local/acme-dns/auto".to_string(),
    ] {
        let resp = acme_dns_post(&app, &cookie, &uri, format!("_csrf={}", enc(&csrf))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
        let body = body_string(resp).await;
        assert!(
            !body.contains("CSRF check failed"),
            "{uri}: refused by CSRF, not authz"
        );
    }
    assert!(
        acme_ssl_labels(&sock).await.is_empty(),
        "a label was minted"
    );
}

#[tokio::test]
async fn operator_without_access_cannot_touch_the_cname() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-other.cz").await;
    acme_ssl_zone(&sock).await;
    let cookie = acme_ssl_user(&app, &sock, "operator", None).await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    for uri in [
        format!("/hostings/{id}/cert/acme-dns/setup"),
        format!("/hostings/{id}/cert/acme-dns/check"),
        format!("/hostings/{id}/cert/dns01/auto"),
        // A tenant-scoped role never sets up a node's preview wildcard.
        "/settings/https/preview/local/acme-dns/setup".to_string(),
    ] {
        let resp = acme_dns_post(&app, &cookie, &uri, format!("_csrf={}", enc(&csrf))).await;
        let status = resp.status();
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
            "{uri}: {status}"
        );
        let body = body_string(resp).await;
        assert!(
            !body.contains("CSRF check failed"),
            "{uri}: refused by CSRF"
        );
    }
    assert!(
        acme_ssl_labels(&sock).await.is_empty(),
        "a label was minted"
    );
}

#[tokio::test]
async fn setup_is_idempotent_label_unchanged() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-idem.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let uri = format!("/hostings/{id}/cert/acme-dns/setup");
    let mut seen = Vec::new();
    for _ in 0..2 {
        let resp = acme_dns_post(&app, &cookie, &uri, format!("_csrf={}", enc(&csrf))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let labels = acme_ssl_labels(&sock).await;
        assert_eq!(labels.len(), 1);
        seen.push(labels[0].label.clone());
    }
    assert_eq!(seen[0], seen[1], "setup minted a second label");
}

#[tokio::test]
async fn auto_issue_starts_a_job() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-auto.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(
        &app,
        &cookie,
        &format!("/hostings/{id}/cert/acme-dns/setup"),
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = acme_dns_post(
        &app,
        &cookie,
        &format!("/hostings/{id}/cert/dns01/auto"),
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let to = location(&resp);
    assert!(to.starts_with("/jobs/"), "{to}");
    // The zone is not enabled here, so the renewal refuses — as a job failure.
    assert_eq!(acme_ssl_wait_job(&sock, &to).await, "failed");
}

#[tokio::test]
async fn purge_deletes_acme_labels() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, _cfg) = start_agent_with_toml("[cluster]\ntrash_enabled = true\n").await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-purge.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    acme_dns_post(
        &app,
        &cookie,
        &format!("/hostings/{id}/cert/acme-dns/setup"),
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_labels(&sock).await.len(), 1);

    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_wait_job(&sock, &location(&resp)).await, "done");
    let (_, trash) = acme_dns_get(&app, &cookie, "/trash").await;
    assert!(
        trash.contains("customer can now remove"),
        "purge dialog should mention the CNAME"
    );
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/trash/purge",
        format!("_csrf={}&selector=acmessl-purge.cz", enc(&csrf)),
    )
    .await;
    assert!(location(&resp).contains("flash="), "{}", location(&resp));
    assert!(acme_ssl_labels(&sock).await.is_empty(), "labels survived");
}

#[tokio::test]
async fn trash_keeps_acme_labels() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, _cfg) = start_agent_with_toml("[cluster]\ntrash_enabled = true\n").await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-trash.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    acme_dns_post(
        &app,
        &cookie,
        &format!("/hostings/{id}/cert/acme-dns/setup"),
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_labels(&sock).await.len(), 1);
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_wait_job(&sock, &location(&resp)).await, "done");
    assert_eq!(
        acme_ssl_labels(&sock).await.len(),
        1,
        "trash dropped the label"
    );
}

#[tokio::test]
async fn final_delete_deletes_acme_labels() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "acmessl-final.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    acme_dns_post(
        &app,
        &cookie,
        &format!("/hostings/{id}/cert/acme-dns/setup"),
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_labels(&sock).await.len(), 1);
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_wait_job(&sock, &location(&resp)).await, "done");
    assert!(acme_ssl_labels(&sock).await.is_empty(), "labels survived");
}

#[tokio::test]
async fn preview_wildcard_sets_up_automatic_renewal() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, _cfg) =
        start_agent_with_toml("[cluster]\ntest_domain_template = \"{name}.preview.example.com\"\n")
            .await;
    let app = build_app(sock.clone(), admin);
    acme_ssl_zone(&sock).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/settings/https").await;
    assert_eq!(status, StatusCode::OK);
    let setup = "/settings/https/preview/local/acme-dns/setup";
    assert!(page.contains(setup), "preview setup form missing");

    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(&app, &cookie, setup, format!("_csrf={}", enc(&csrf))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let block = body_string(resp).await;
    let labels = acme_ssl_labels(&sock).await;
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].base, "preview.example.com");
    assert_eq!(labels[0].hosting_id, None, "a preview label has no hosting");
    assert!(
        block.contains("_acme-challenge.preview.example.com"),
        "{block}"
    );
    assert!(
        block.contains("id=\"acme-ssl-local\""),
        "swap target id missing"
    );
    assert!(block.contains(OFFLINE_DNS), "public DNS was asked: {block}");
}

/// Deleting off-site copies takes `BackupRun` everywhere else, so a role that
/// may delete hostings must not reach them by ticking the box in the delete
/// dialog — and the refusal must leave the site alone.
#[tokio::test]
async fn hosting_delete_with_ftp_backups_needs_backup_run() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    use hyperion_state::capabilities::Capability;
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "offsite-gate.cz").await;
    let role_id = match hyperion_rpc_client::call(
        &sock,
        RpcReq::RoleCreate {
            name: "site-deleter".into(),
            capabilities: Capability::HostingDelete.bit() | Capability::HostingView.bit(),
            scope_all: true,
        },
    )
    .await
    .expect("role")
    {
        RpcResp::RoleCreate { id } => id,
        other => panic!("unexpected role create: {other:?}"),
    };
    let user_id = match hyperion_rpc_client::call(
        &sock,
        RpcReq::WebUserCreate {
            username: "deleter".into(),
            email: "deleter@example.invalid".into(),
            password: "deleter-pw-12345".into(),
            role: "operator".into(),
        },
    )
    .await
    .expect("user")
    {
        RpcResp::WebUserCreate { id } => id,
        other => panic!("unexpected user create: {other:?}"),
    };
    match hyperion_rpc_client::call(
        &sock,
        RpcReq::WebUserSetCustomRole {
            user_id,
            custom_role_id: role_id,
        },
    )
    .await
    .expect("assign")
    {
        RpcResp::WebUserSetCustomRole => {}
        other => panic!("unexpected assign: {other:?}"),
    }
    let cookie = acme_dns_login(&app, "deleter", "deleter-pw-12345").await;
    let (_, profile) = acme_dns_get(&app, &cookie, "/profile").await;
    let csrf = extract_csrf(&profile);

    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}&offsite=1", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // The local copies are behind the same capability, and the box that asks
    // for them is not offered to a role that could not use it.
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}&local_backups=on", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let (_, page) = acme_dns_get(&app, &cookie, &format!("/hostings/{id}")).await;
    assert!(!page.contains("name=\"local_backups\""));
    match hyperion_rpc_client::call(
        &sock,
        RpcReq::HostingGet(hyperion_rpc::wire::HostingSelector::Domain(
            hyperion_validate::Domain::parse("offsite-gate.cz").expect("domain"),
        )),
    )
    .await
    .expect("get")
    {
        RpcResp::HostingGet(_) => {}
        other => panic!("the site should still be there: {other:?}"),
    }

    // Without the box the same role deletes as before.
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_wait_job(&sock, &location(&resp)).await, "done");
}

/// The node has no FTP target: the box must fail the job, not delete the site
/// and quietly leave the backups the operator asked to have removed.
#[tokio::test]
async fn hosting_delete_with_ftp_backups_fails_the_job_without_a_target() {
    use hyperion_rpc::codec::{Request as RpcReq, Response as RpcResp};
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "offsite-notarget.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;

    // No backup has an FTP copy, so the dialog does not offer the box at all.
    let (_, page) = acme_dns_get(&app, &cookie, &format!("/hostings/{id}")).await;
    assert!(page.contains("action=\"/hostings/delete\""), "{page}");
    assert!(!page.contains("data-confirm-check-name=\"offsite\""));

    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}&offsite=1", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_wait_job(&sock, &location(&resp)).await, "failed");
    match hyperion_rpc_client::call(
        &sock,
        RpcReq::HostingGet(hyperion_rpc::wire::HostingSelector::Domain(
            hyperion_validate::Domain::parse("offsite-notarget.cz").expect("domain"),
        )),
    )
    .await
    .expect("get")
    {
        RpcResp::HostingGet(_) => {}
        other => panic!("the site should still be there: {other:?}"),
    }
}

/// A trashed site whose purge will also delete its FTP backups says so on the
/// row and in the purge dialog; one without the choice says neither.
#[tokio::test]
async fn trash_page_warns_about_a_pending_ftp_delete() {
    const WARNING: &str = "FTP backups are deleted with it";
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with(Some("[cluster]\ntrash_enabled = true\n")).await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "offsite-trash.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_wait_job(&sock, &location(&resp)).await, "done");
    let (_, trash) = acme_dns_get(&app, &cookie, "/trash").await;
    assert!(trash.contains("offsite-trash.cz"), "row missing: {trash}");
    assert!(!trash.contains(WARNING));

    // What deleting with the box ticked records; the agent here has no target
    // to tick it against.
    hyperion_state::hosting_kv::set(&pool, &id, "trash.delete_offsite_backups", "1", 1)
        .await
        .expect("kv");
    let (_, trash) = acme_dns_get(&app, &cookie, "/trash").await;
    assert!(trash.contains(WARNING), "{trash}");
    assert!(
        trash.contains("off-site FTP target are deleted too"),
        "{trash}"
    );
}

/// The delete form offers to take the local copies, and its dialog says which
/// way that goes; a trashed site that will take them says so on /trash.
#[tokio::test]
async fn delete_form_offers_local_backups_and_the_trash_warns_about_them() {
    const WARNING: &str = "Backups on this node are deleted with it";
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with(Some("[cluster]\ntrash_enabled = true\n")).await;
    let app = build_app(sock.clone(), admin);
    let id = acme_ssl_hosting(&sock, "local-trash.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (_, page) = acme_dns_get(&app, &cookie, &format!("/hostings/{id}")).await;
    assert!(page.contains("name=\"local_backups\""), "no checkbox");
    assert!(
        page.contains("data-confirm-note-field=\"local_backups\""),
        "the dialog must follow the checkbox"
    );

    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/hostings/delete",
        format!("_csrf={}&selector={id}&local_backups=on", enc(&csrf)),
    )
    .await;
    assert_eq!(acme_ssl_wait_job(&sock, &location(&resp)).await, "done");

    let chosen = hyperion_state::hosting_kv::get(&pool, &id, "trash.delete_local_backups")
        .await
        .expect("kv");
    assert!(chosen.is_some(), "the form field must reach the service");
    let (_, trash) = acme_dns_get(&app, &cookie, "/trash").await;
    assert!(trash.contains(WARNING), "{trash}");
    assert!(trash.contains("on this node are deleted too"), "{trash}");
}

/// Reaches every tenant's backups, so `BackupRun` (which every Customer holds)
/// is not the bar: neither role gets the page, and neither starts a job.
#[tokio::test]
async fn leftover_backups_are_closed_to_anyone_without_the_estate_wide_right() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    for role in ["customer", "operator", "viewer"] {
        let username = format!("left-{role}");
        hyperion_rpc_client::call(
            &sock,
            hyperion_rpc::codec::Request::WebUserCreate {
                username: username.clone(),
                email: format!("{username}@example.invalid"),
                password: "role-pw-12345".into(),
                role: role.into(),
            },
        )
        .await
        .expect("create user");
        let cookie = acme_dns_login(&app, &username, "role-pw-12345").await;
        let (status, _) = acme_dns_get(&app, &cookie, "/settings/backups/orphans").await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{role} got the page");
        let csrf = acme_ssl_csrf(&app, &cookie).await;
        for (uri, body) in [
            ("/settings/backups/orphans/scan", format!("_csrf={csrf}")),
            (
                "/settings/backups/orphans/delete",
                format!("_csrf={csrf}&target=ftp%3A%2F%2Ft&files=web1%2Fgone.cz-1.sql"),
            ),
        ] {
            let resp = acme_dns_post(&app, &cookie, uri, body).await;
            let to = resp.headers()[header::LOCATION].to_str().unwrap();
            assert!(
                !to.starts_with("/jobs/") && to.contains("flash_error"),
                "{role} {uri}: {to}"
            );
        }
    }
}

#[tokio::test]
async fn a_leftover_search_with_no_target_says_so_and_deletes_nothing() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/settings/backups/orphans").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Not searched"), "{page}");
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/settings/backups/orphans/scan",
        format!("_csrf={csrf}"),
    )
    .await;
    let to = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(to.starts_with("/jobs/"), "{to}");
    assert_eq!(acme_ssl_wait_job(&sock, &to).await, "done");
    let (_, page) = acme_dns_get(&app, &cookie, "/settings/backups/orphans").await;
    assert!(page.contains("No node has an FTP/SFTP target"), "{page}");

    // Nothing ticked is not a job.
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/settings/backups/orphans/delete",
        format!("_csrf={csrf}&target=ftp%3A%2F%2Ft&files="),
    )
    .await;
    let to = resp.headers()[header::LOCATION].to_str().unwrap();
    assert!(to.contains("flash_error"), "{to}");
}

/// The silent node could be hosting any of these sites. The search calls
/// nothing left over, and a delete that was ticked before it went quiet does
/// not go ahead.
#[tokio::test]
async fn a_silent_node_stops_both_the_search_and_the_delete() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    sqlx::query(
        "INSERT INTO nodes (node_id, label, enrolled_at, last_seen_at, agent_version, public_ip, \
         enrolled_via) VALUES ('web-2', 'web-2.example.net', 1, 1, '0', '', 'test')",
    )
    .execute(&pool)
    .await
    .expect("node");
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;

    let resp = acme_dns_post(
        &app,
        &cookie,
        "/settings/backups/orphans/scan",
        format!("_csrf={csrf}"),
    )
    .await;
    let to = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(acme_ssl_wait_job(&sock, &to).await, "failed");
    let (_, page) = acme_dns_get(&app, &cookie, "/settings/backups/orphans").await;
    assert!(page.contains("id=\"orphan-refused\""), "{page}");
    assert!(page.contains("web-2.example.net"), "{page}");
    assert!(!page.contains("class=\"orphan-file\""), "{page}");

    let resp = acme_dns_post(
        &app,
        &cookie,
        "/settings/backups/orphans/delete",
        format!("_csrf={csrf}&target=ftp%3A%2F%2Ft&files=web1%2Fgone.cz-1.sql"),
    )
    .await;
    let to = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(acme_ssl_wait_job(&sock, &to).await, "failed");
    let id = to.trim_start_matches("/jobs/").to_string();
    let job = match hyperion_rpc_client::call(&sock, hyperion_rpc::codec::Request::JobGet { id })
        .await
        .expect("job")
    {
        hyperion_rpc::codec::Response::JobGet(Some(j)) => j,
        other => panic!("{other:?}"),
    };
    let err = job.error.unwrap_or_default();
    assert!(err.contains("Nothing was deleted"), "{err}");
    assert!(err.contains("web-2.example.net"), "{err}");
}

/// The Nodes page loads each node's PHP-masters verdict lazily, so one dead
/// node cannot hold the page; the row carries the hook for it.
#[tokio::test]
async fn own_masters_row_loads_its_verdict_lazily() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/install").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("hx-get=\"/install/node-php-masters?node_id=local\""),
        "the master's row must fetch its own verdict"
    );
}

/// The stub node has no cgroup facts at all, so the fragment must say it
/// cannot and why, rather than claiming nothing or crashing the row.
#[tokio::test]
async fn own_masters_fragment_names_what_blocks_the_node() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, html) =
        acme_dns_get(&app, &cookie, "/install/node-php-masters?node_id=local").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Own PHP masters: not possible"), "{html}");
    assert!(html.contains("cgroup v2"), "{html}");

    let (status, _) = acme_dns_get(&app, &cookie, "/install/node-php-masters?node_id=a/b").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The verdict is the owner's to read: a logged-in user without the owner
/// role gets a 403, and the fragment says nothing about the node.
#[tokio::test]
async fn own_masters_fragment_is_refused_to_a_non_admin() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    match hyperion_rpc_client::call(
        &sock,
        hyperion_rpc::codec::Request::WebUserCreate {
            username: "php-viewer".into(),
            email: "php-viewer@example.invalid".into(),
            password: "viewer-pw-1".into(),
            role: "viewer".into(),
        },
    )
    .await
    .expect("create viewer")
    {
        hyperion_rpc::codec::Response::WebUserCreate { .. } => {}
        other => panic!("unexpected create response: {other:?}"),
    }
    let cookie = acme_dns_login(&app, "php-viewer", "viewer-pw-1").await;
    let (status, html) =
        acme_dns_get(&app, &cookie, "/install/node-php-masters?node_id=local").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{html}");
    assert!(!html.contains("Own PHP masters:"), "{html}");
}

/// The setting is a checkbox on the node's own settings page, with its
/// copy, and it starts unticked on a node that never heard of it.
#[tokio::test]
async fn own_masters_checkbox_is_on_the_node_settings_page() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, _cfg) = start_agent_with_toml("[agent]\n").await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/install/node-settings?node_id=local").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("name=\"own_masters\""), "checkbox missing");
    assert!(page.contains("value=\"php\""), "section field missing");
    assert!(page.contains("name=\"_checkboxes\" value=\"own_masters\""));
    assert!(page.contains(
        "New sites and sites you convert run on their own PHP process. About 11 MB per site."
    ));
    assert!(
        !page.contains("name=\"own_masters\" value=\"true\" checked"),
        "off by default"
    );
    assert!(
        page.contains("This version only reports. A ticked box starts applying in a later update.")
    );
}

/// What the node's file says is what the box shows.
#[tokio::test]
async fn own_masters_checkbox_is_ticked_when_the_file_says_so() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, _cfg) = start_agent_with_toml("[php]\nown_masters = true\n").await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/install/node-settings?node_id=local").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("name=\"own_masters\" value=\"true\" checked"),
        "ticked box missing"
    );
}

/// A file that cannot be read, or does not parse, must not render a box: an
/// unticked guess saved with one click would overwrite the real value.
#[tokio::test]
async fn own_masters_card_has_no_form_when_the_file_is_unknown() {
    // No agent.toml wired: NodeConfigRead answers an error.
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/install/node-settings?node_id=local").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("id=\"php-masters\""), "card missing");
    assert!(!page.contains("name=\"own_masters\""), "form on a guess");
    assert!(page.contains("a form here would be guessing"));

    // A file that does not parse.
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, _cfg) = start_agent_with_toml("[php\nown_masters = true\n").await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/install/node-settings?node_id=local").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!page.contains("name=\"own_masters\""), "form on a guess");
    assert!(page.contains("a form here would be guessing"));
}

// ---------------------------------------------------------------------------
// Docker module pages.
// ---------------------------------------------------------------------------

use hyperion_rpc::codec::{Request as DockerReq, Response as DockerResp};
use hyperion_types::docker::{DockerContainer, DockerNodeStatus, DockerProject};

/// Create `name` with a built-in `role` and return its session cookie.
async fn docker_user(app: &axum::Router, sock: &std::path::Path, name: &str, role: &str) -> String {
    match hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserCreate {
            username: name.into(),
            email: format!("{name}@example.invalid"),
            password: "docker-pw-12345".into(),
            role: role.into(),
        },
    )
    .await
    .expect("create user")
    {
        DockerResp::WebUserCreate { .. } => {}
        other => panic!("unexpected user create: {other:?}"),
    }
    acme_dns_login(app, name, "docker-pw-12345").await
}

/// A user on a custom role holding `DockerView`, with or without every
/// hosting in scope.
async fn docker_custom_user(
    app: &axum::Router,
    sock: &std::path::Path,
    name: &str,
    scope_all: bool,
) -> String {
    use hyperion_state::capabilities::Capability;
    let role_id = match hyperion_rpc_client::call(
        sock,
        DockerReq::RoleCreate {
            name: format!("docker-{name}"),
            capabilities: Capability::DockerView.bit(),
            scope_all,
        },
    )
    .await
    .expect("role")
    {
        DockerResp::RoleCreate { id } => id,
        other => panic!("unexpected role create: {other:?}"),
    };
    let user_id = match hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserCreate {
            username: name.into(),
            email: format!("{name}@example.invalid"),
            password: "docker-pw-12345".into(),
            role: "operator".into(),
        },
    )
    .await
    .expect("user")
    {
        DockerResp::WebUserCreate { id } => id,
        other => panic!("unexpected user create: {other:?}"),
    };
    hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserSetCustomRole {
            user_id,
            custom_role_id: role_id,
        },
    )
    .await
    .expect("assign");
    acme_dns_login(app, name, "docker-pw-12345").await
}

/// Turn the module on for the cluster and for the master itself, the way the
/// install buttons do once Docker answers.
async fn docker_enable_master(sock: &std::path::Path, pool: &sqlx::SqlitePool) {
    hyperion_rpc_client::call(sock, DockerReq::DockerClusterInstall)
        .await
        .expect("cluster");
    hyperion_state::docker::set_node_installed(pool, false, 1)
        .await
        .expect("node installed");
    hyperion_rpc_client::call(
        sock,
        DockerReq::DockerNodeRegister {
            node_id: "local".into(),
            installed: true,
        },
    )
    .await
    .expect("register master");
}

async fn docker_add_worker(sock: &std::path::Path, pool: &sqlx::SqlitePool, id: &str, label: &str) {
    // No address on record: the master cannot reach it, which is how a node
    // that went quiet looks from here.
    sqlx::query(
        "INSERT INTO nodes (node_id, label, enrolled_at, last_seen_at, agent_version, public_ip, \
         enrolled_via) VALUES (?, ?, 1, 1, '0', '', 'test')",
    )
    .bind(id)
    .bind(label)
    .execute(pool)
    .await
    .expect("node");
    hyperion_rpc_client::call(
        sock,
        DockerReq::DockerNodeRegister {
            node_id: id.into(),
            installed: true,
        },
    )
    .await
    .expect("register worker");
}

fn docker_container(project: &str, service: &str, state: &str) -> DockerContainer {
    DockerContainer {
        id: format!("{project}-{service}-id"),
        name: format!("{project}-{service}-1"),
        project: project.into(),
        service: service.into(),
        image: "nginx:1.27".into(),
        state: state.into(),
        started_at: 1_700_000_000,
        ..Default::default()
    }
}

fn docker_snapshot() -> DockerNodeStatus {
    let mut big_log = docker_container("shop", "web", "running");
    big_log.log_size_bytes = 2 * 1024 * 1024 * 1024;
    let mut dead = docker_container("blog", "db", "exited");
    dead.exit_code = 137;
    dead.oom_killed = true;
    DockerNodeStatus {
        read_at: 1_700_000_100,
        daemon_ok: true,
        projects: vec![
            DockerProject {
                name: "shop".into(),
                containers: vec![big_log, docker_container("shop", "cache", "running")],
                verdict: "ok".into(),
                ..Default::default()
            },
            DockerProject {
                name: "blog".into(),
                containers: vec![dead],
                verdict: "problem".into(),
                summary: "db: exit 137, out of memory".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

#[tokio::test]
async fn docker_requires_capability() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    for role in ["viewer", "customer"] {
        let cookie = docker_user(&app, &sock, &format!("dk-{role}"), role).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/docker")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("call");
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{role}");
        assert_eq!(resp.headers()[header::LOCATION], "/", "{role}");
    }
    let (status, page) = acme_dns_get(&app, &cookie, "/docker").await;
    assert_eq!(status, StatusCode::OK, "{page}");
}

/// The rows span every tenant, so the capability alone is not enough.
#[tokio::test]
async fn custom_role_without_scope_all_refused() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;

    let narrow = docker_custom_user(&app, &sock, "dk-narrow", false).await;
    for uri in ["/docker", "/docker/local/shop"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::COOKIE, &narrow)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("call");
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "{uri}");
        assert_eq!(resp.headers()[header::LOCATION], "/", "{uri}");
    }
    // And a write through the same role is refused, not just hidden.
    let csrf = acme_ssl_csrf(&app, &narrow).await;
    let resp = acme_dns_post(
        &app,
        &narrow,
        "/docker/local/shop/forget",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let wide = docker_custom_user(&app, &sock, "dk-wide", true).await;
    let (status, _) = acme_dns_get(&app, &wide, "/docker").await;
    assert_eq!(status, StatusCode::OK, "scope_all + docker_view reads");
    // Reading is not installing.
    let csrf = acme_ssl_csrf(&app, &wide).await;
    let resp = acme_dns_post(
        &app,
        &wide,
        "/docker/nodes/local/install",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = acme_dns_post(
        &app,
        &wide,
        "/docker/remove-cluster",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Forgetting a stack is a write too: the same role is refused.
    let resp = acme_dns_post(
        &app,
        &wide,
        "/docker/local/shop/forget",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A reader who may not forget is not offered the button either.
#[tokio::test]
async fn forget_button_is_for_administrators() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let mut snap = docker_snapshot();
    snap.projects.push(DockerProject {
        name: "old-forum".into(),
        verdict: "gone".into(),
        gone_since: Some(1_700_000_000),
        ..Default::default()
    });
    let (sock, _d, pool) = start_agent_full(None, Some(snap)).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let wide = docker_custom_user(&app, &sock, "dk-wide-forget", true).await;
    let form = "action=\"/docker/local/old-forum/forget\"";

    for uri in ["/docker", "/docker/local/old-forum"] {
        let (status, page) = acme_dns_get(&app, &cookie, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(page.contains(form), "admin sees Forget on {uri}");
        let (status, page) = acme_dns_get(&app, &wide, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(
            !page.contains(form),
            "a wide reader is not offered Forget on {uri}"
        );
        assert!(
            page.contains("old-forum"),
            "{uri}: the stack itself is listed"
        );
    }
}

/// The module is off for the cluster: a direct POST must not turn a node on.
#[tokio::test]
async fn node_install_is_refused_while_the_module_is_off() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/docker/nodes/local/install",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    match hyperion_rpc_client::call(
        &sock,
        DockerReq::JobList {
            kind: Some("docker_node_install".into()),
            state: None,
            limit: 10,
        },
    )
    .await
    .expect("jobs")
    {
        DockerResp::JobList(v) => assert!(v.is_empty(), "no job was started: {v:?}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn docker_off_redirects_to_settings() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/docker")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers()[header::LOCATION],
        "/settings/panel#docker-module"
    );

    // Nobody else learns the module exists.
    let viewer = docker_user(&app, &sock, "dk-off-viewer", "viewer").await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/docker")
                .header(header::COOKIE, &viewer)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.headers()[header::LOCATION], "/");

    let (_, nav) = acme_dns_get(&app, &cookie, "/api/nav-status").await;
    let nav: serde_json::Value = serde_json::from_str(&nav).expect("json");
    assert_eq!(nav["docker_installed"], false, "{nav}");
    assert_eq!(nav["docker_problems"], 0, "{nav}");

    // The nav entry exists but starts hidden; the poller shows it.
    let (_, home) = acme_dns_get(&app, &cookie, "/profile").await;
    assert!(
        home.contains("id=\"nav-docker\"") && home.contains("data-require-caps=\"docker_view\""),
        "nav entry missing"
    );

    // Installing it is the Settings card's job; afterwards the nav says so
    // at once, not a minute later.
    let (_, panel) = acme_dns_get(&app, &cookie, "/settings/panel").await;
    assert!(panel.contains("id=\"docker-module\""), "card missing");
    assert!(panel.contains("action=\"/docker/install-cluster\""));
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/docker/install-cluster",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let (_, nav) = acme_dns_get(&app, &cookie, "/api/nav-status").await;
    let nav: serde_json::Value = serde_json::from_str(&nav).expect("json");
    assert_eq!(nav["docker_installed"], true, "{nav}");
    let (status, page) = acme_dns_get(&app, &cookie, "/docker").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("action=\"/docker/nodes/local/install\""),
        "the master offers the node install: {page}"
    );
}

/// A node that does not answer is named, and the page says the list is
/// short, rather than reading as a cluster with nothing running.
#[tokio::test]
async fn failed_node_shows_incomplete_warning() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    docker_add_worker(&sock, &pool, "web-2", "web-2.example.net").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/docker").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("web-2.example.net"), "{page}");
    assert!(page.contains("did not answer"), "{page}");
    assert!(page.contains("list is incomplete"), "{page}");
    // It stays where it can be removed later.
    assert!(
        page.contains("action=\"/docker/nodes/web-2/remove\""),
        "{page}"
    );
}

#[tokio::test]
async fn node_install_is_a_job() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, _pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    hyperion_rpc_client::call(&sock, DockerReq::DockerClusterInstall)
        .await
        .expect("cluster");

    let resp = acme_dns_post(
        &app,
        &cookie,
        "/docker/nodes/local/install",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let to = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(to.starts_with("/jobs/"), "{to}");
    // The test box has no Docker, which the job says in plain words and
    // leaves the node unregistered.
    assert_eq!(acme_ssl_wait_job(&sock, &to).await, "failed");
    let id = to.trim_start_matches("/jobs/").to_string();
    let job = match hyperion_rpc_client::call(&sock, DockerReq::JobGet { id })
        .await
        .expect("job")
    {
        DockerResp::JobGet(Some(j)) => j,
        other => panic!("{other:?}"),
    };
    assert_eq!(job.kind, "docker_node_install");
    assert!(
        job.error
            .unwrap_or_default()
            .contains("Install Docker first"),
        "the reason must reach the operator"
    );
    match hyperion_rpc_client::call(&sock, DockerReq::DockerNodeList)
        .await
        .expect("list")
    {
        DockerResp::DockerNodeList(l) => assert!(l.nodes.is_empty(), "{l:?}"),
        other => panic!("{other:?}"),
    }

    // A node the master does not know is refused before any job exists.
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/docker/nodes/node_nope/install",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // And without the token nothing starts either.
    let resp = acme_dns_post(&app, &cookie, "/docker/nodes/local/install", String::new()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Removing the module asks every registered node first. A node that is
/// silent stays registered, so it can be removed once it answers.
#[tokio::test]
async fn removing_the_module_keeps_a_node_that_did_not_answer() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    docker_add_worker(&sock, &pool, "web-2", "web-2.example.net").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;

    let resp = acme_dns_post(
        &app,
        &cookie,
        "/docker/remove-cluster",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    let to = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(to.starts_with("/jobs/"), "{to}");
    assert_eq!(acme_ssl_wait_job(&sock, &to).await, "failed");
    let id = to.trim_start_matches("/jobs/").to_string();
    let job = match hyperion_rpc_client::call(&sock, DockerReq::JobGet { id })
        .await
        .expect("job")
    {
        DockerResp::JobGet(Some(j)) => j,
        other => panic!("{other:?}"),
    };
    assert!(
        job.error.unwrap_or_default().contains("web-2.example.net"),
        "the silent node is named"
    );
    let list = match hyperion_rpc_client::call(&sock, DockerReq::DockerNodeList)
        .await
        .expect("list")
    {
        DockerResp::DockerNodeList(l) => l,
        other => panic!("{other:?}"),
    };
    assert!(list.cluster_installed, "the module is not half removed");
    assert_eq!(
        list.nodes
            .iter()
            .map(|n| n.node_id.as_str())
            .collect::<Vec<_>>(),
        ["web-2"],
        "the master was removed, the silent node was not forgotten"
    );
    assert!(
        !hyperion_state::docker::node_installed(&pool)
            .await
            .expect("state"),
        "the master's own module data is gone"
    );

    // Once the node is out of the way, removing the module completes.
    hyperion_rpc_client::call(
        &sock,
        DockerReq::DockerNodeRegister {
            node_id: "web-2".into(),
            installed: false,
        },
    )
    .await
    .expect("unregister");
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/docker/remove-cluster",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    let to = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(acme_ssl_wait_job(&sock, &to).await, "done");
    match hyperion_rpc_client::call(&sock, DockerReq::DockerNodeList)
        .await
        .expect("list")
    {
        DockerResp::DockerNodeList(l) => assert!(!l.cluster_installed, "{l:?}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn stacks_list_problems_first_and_escape_their_names() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let mut snap = docker_snapshot();
    snap.projects.push(DockerProject {
        name: "a<b>&c".into(),
        containers: vec![docker_container("a<b>&c", "app", "running")],
        verdict: "ok".into(),
        ..Default::default()
    });
    let (sock, _d, pool) = start_agent_full(None, Some(snap)).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (status, page) = acme_dns_get(&app, &cookie, "/docker").await;
    assert_eq!(status, StatusCode::OK);

    let blog = page.find("/docker/local/blog").expect("blog link");
    let shop = page.find("/docker/local/shop").expect("shop link");
    assert!(blog < shop, "the stack with a problem comes first");
    assert!(page.contains("db: exit 137, out of memory"));
    assert!(
        !page.contains("a<b>"),
        "a project name is data, never markup"
    );
    assert!(page.contains("a%3Cb%3E%26c"), "links are URL-encoded");
    assert!(page.contains("a&lt;b&gt;&amp;c"), "{page}");
    assert!(
        !page.contains("other containers"),
        "the catch-all group is shown only when it has containers"
    );
    // 2 GiB of log with no max-size is how Docker fills a disk.
    assert!(page.contains("no max-size"), "{page}");
}

#[tokio::test]
async fn other_containers_group_is_labelled_and_reachable() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let mut snap = docker_snapshot();
    snap.projects.push(DockerProject {
        name: String::new(),
        containers: vec![docker_container("", "", "running")],
        verdict: "ok".into(),
        ..Default::default()
    });
    let (sock, _d, pool) = start_agent_full(None, Some(snap)).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (_, page) = acme_dns_get(&app, &cookie, "/docker").await;
    assert!(page.contains("other containers"), "{page}");
    let (status, detail) = acme_dns_get(&app, &cookie, "/docker/local/%28other%29").await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert!(detail.contains("other containers"));
}

#[tokio::test]
async fn stack_detail_shows_container_facts_and_refuses_strangers() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(docker_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let (status, page) = acme_dns_get(&app, &cookie, "/docker/local/blog").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("blog-db-1"));
    assert!(page.contains("137"), "exit code");
    assert!(page.contains("out of memory"), "OOM is stated");

    // A node that is not registered, a project that does not exist, and a
    // name made of markup are all plain 404s that echo nothing back.
    for uri in [
        "/docker/node_unknown/blog",
        "/docker/local/nothing-here",
        "/docker/local/%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    ] {
        let (status, body) = acme_dns_get(&app, &cookie, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert!(!body.contains("<script>alert"), "{uri}: {body}");
    }
}

#[tokio::test]
async fn forgetting_a_project_needs_a_registered_node() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/docker/node_unknown/blog/forget",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = acme_dns_post(
        &app,
        &cookie,
        "/docker/local/blog/forget",
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .starts_with("/docker"));
}

// ---------------------------------------------------------------------------
// Docker logs.
// ---------------------------------------------------------------------------

/// A user on a custom role holding exactly `caps`, with every hosting in scope
/// unless `scope_all` says otherwise.
async fn docker_cap_user(
    app: &axum::Router,
    sock: &std::path::Path,
    name: &str,
    caps: u64,
    scope_all: bool,
) -> String {
    let role_id = match hyperion_rpc_client::call(
        sock,
        DockerReq::RoleCreate {
            name: format!("docker-caps-{name}"),
            capabilities: caps,
            scope_all,
        },
    )
    .await
    .expect("role")
    {
        DockerResp::RoleCreate { id } => id,
        other => panic!("unexpected role create: {other:?}"),
    };
    let user_id = match hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserCreate {
            username: name.into(),
            email: format!("{name}@example.invalid"),
            password: "docker-pw-12345".into(),
            role: "operator".into(),
        },
    )
    .await
    .expect("user")
    {
        DockerResp::WebUserCreate { id } => id,
        other => panic!("unexpected user create: {other:?}"),
    };
    hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserSetCustomRole {
            user_id,
            custom_role_id: role_id,
        },
    )
    .await
    .expect("assign");
    acme_dns_login(app, name, "docker-pw-12345").await
}

/// The `shop` stack with real-looking container ids, which is what the log
/// viewer needs to hand docker.
fn docker_log_snapshot() -> DockerNodeStatus {
    let mut snap = docker_snapshot();
    for (i, c) in snap.projects[0].containers.iter_mut().enumerate() {
        c.id = format!("{:064x}", i + 1);
    }
    snap
}

fn audit_rows_sql() -> &'static str {
    "SELECT actor_label, target, payload_json FROM audit_log WHERE action = 'docker.logs.read'"
}

#[tokio::test]
async fn logs_need_their_own_capability() {
    use hyperion_state::capabilities::Capability;
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(docker_log_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;

    let view = Capability::DockerView.bit();
    let logs = Capability::DockerLogs.bit();
    let only_view = docker_cap_user(&app, &sock, "dk-viewonly", view, true).await;
    let both = docker_cap_user(&app, &sock, "dk-both", view | logs, true).await;
    let narrow = docker_cap_user(&app, &sock, "dk-narrow-logs", view | logs, false).await;

    // Seeing the stack is not reading what it prints: no link, and the route
    // refuses.
    let (status, page) = acme_dns_get(&app, &only_view, "/docker/local/shop").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!page.contains("docker-logs"), "no log viewer offered");
    assert!(!page.contains("/docker/local/shop/logs"), "{page}");
    let (status, body) = acme_dns_get(&app, &only_view, "/docker/local/shop/logs").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Every tenant's containers: the capability alone is not enough.
    let (status, _) = acme_dns_get(&app, &narrow, "/docker/local/shop/logs").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // With both, the viewer is on the page but reads nothing until asked.
    let (status, page) = acme_dns_get(&app, &both, "/docker/local/shop").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("id=\"docker-logs\""));
    assert!(page.contains("/docker/local/shop/logs"));
    assert!(!page.contains("dl-lines") && !page.contains("hx-trigger=\"poll-tick\""));
    let (status, body) = acme_dns_get(&app, &both, "/docker/local/shop/logs").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("second line"), "{body}");

    // The node must be one of the registered ones, and the stack real.
    let (status, _) = acme_dns_get(&app, &both, "/docker/node_unknown/shop/logs").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn log_markup_is_escaped() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(docker_log_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let (status, body) = acme_dns_get(&app, &cookie, "/docker/local/shop/logs").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{body}"
    );
    assert!(!body.contains("<script>alert"), "{body}");
    assert!(body.contains(" red"), "ANSI colours are removed: {body}");
    assert!(!body.contains('\u{1b}') && !body.contains("[31m"), "{body}");

    // What was typed in the filter comes back as text too.
    let (status, body) = acme_dns_get(
        &app,
        &cookie,
        "/docker/local/shop/logs?filter=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.contains("<img"), "{body}");
    assert!(
        body.contains("&lt;img") || body.contains("&#60;img"),
        "{body}"
    );
    // And so is a container name from the query that matches nothing.
    let (status, body) = acme_dns_get(
        &app,
        &cookie,
        "/docker/local/shop/logs?container=%3Cb%3Ex%3C%2Fb%3E",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("<b>x"), "{body}");
}

#[tokio::test]
async fn following_polls_only_while_asked_and_is_audited_once() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(docker_log_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    // Follow off: nothing that polls.
    let (_, body) = acme_dns_get(
        &app,
        &cookie,
        "/docker/local/shop/logs?container=shop-web-1",
    )
    .await;
    assert!(
        !body.contains("poll-tick") && !body.contains("dl-poll"),
        "{body}"
    );

    // Follow on: one element that asks again, with a cursor it was given.
    let (status, body) = acme_dns_get(
        &app,
        &cookie,
        "/docker/local/shop/logs?container=shop-web-1&follow=on",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("hx-trigger=\"poll-tick\""), "{body}");
    assert!(body.contains("data-poll-visible") && body.contains("data-poll-ms=\"5000\""));
    let url = body
        .split("id=\"dl-poll\"")
        .nth(1)
        .and_then(|t| t.split("hx-get=\"").nth(1))
        .and_then(|t| t.split('"').next())
        .expect("poll url")
        .replace("&amp;", "&");
    assert!(
        url.contains("poll=1") && url.contains("cursor=") && url.contains("proof="),
        "{url}"
    );

    // The poll reads what is new (nothing), carries on, and is not audited.
    let (status, again) = acme_dns_get(&app, &cookie, &url).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert!(!again.contains("second line"), "already seen: {again}");
    assert!(again.contains("id=\"dl-poll\""), "keeps following: {again}");

    // A cursor the page was not given reads nothing and stops.
    let (status, forged) = acme_dns_get(
        &app,
        &cookie,
        "/docker/local/shop/logs?container=shop-web-1&follow=on&poll=1&cursor=0&proof=forged",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !forged.contains("second line") && !forged.contains("dl-poll\""),
        "{forged}"
    );
    assert!(forged.contains("Following stopped"), "{forged}");
    // A real proof for another log does not work here either.
    let other = url.replace("container=shop-web-1", "container=shop-cache-1");
    let (_, swapped) = acme_dns_get(&app, &cookie, &other).await;
    assert!(
        swapped.contains("Following stopped") && !swapped.contains("second"),
        "{swapped}"
    );

    let rows: Vec<(String, Option<String>, String)> = sqlx::query_as(audit_rows_sql())
        .fetch_all(&pool)
        .await
        .expect("audit");
    // Two opens (follow off, follow on); the polls wrote nothing.
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows
        .iter()
        .all(|(who, t, _)| who == "kevin" && t.as_deref() == Some("shop/shop-web-1")));
}

// ---------------------------------------------------------------------------
// URL checks on /monitoring.
// ---------------------------------------------------------------------------

use hyperion_types::url_monitor::UrlMonitorList;

async fn url_checks(sock: &std::path::Path) -> UrlMonitorList {
    match hyperion_rpc_client::call(sock, DockerReq::UrlMonitorList)
        .await
        .expect("list")
    {
        DockerResp::UrlMonitorList(l) => l,
        other => panic!("unexpected list: {other:?}"),
    }
}

/// A urlencoded body for the URL check form.
fn url_form_body(csrf: &str, fields: &[(&str, &str)]) -> String {
    let mut body = format!("_csrf={}", enc(csrf));
    for (k, v) in fields {
        body.push_str(&format!("&{k}={}", enc(v)));
    }
    body
}

async fn url_save(
    app: &axum::Router,
    cookie: &str,
    fields: &[(&str, &str)],
) -> axum::response::Response {
    let csrf = acme_ssl_csrf(app, cookie).await;
    acme_dns_post(
        app,
        cookie,
        "/monitoring/urls",
        url_form_body(&csrf, fields),
    )
    .await
}

/// A user on a custom role holding exactly `caps`, with or without every
/// hosting in scope.
async fn url_role_user(
    app: &axum::Router,
    sock: &std::path::Path,
    name: &str,
    caps: u64,
    scope_all: bool,
) -> String {
    let role_id = match hyperion_rpc_client::call(
        sock,
        DockerReq::RoleCreate {
            name: format!("url-{name}"),
            capabilities: caps,
            scope_all,
        },
    )
    .await
    .expect("role")
    {
        DockerResp::RoleCreate { id } => id,
        other => panic!("unexpected role create: {other:?}"),
    };
    let user_id = match hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserCreate {
            username: name.into(),
            email: format!("{name}@example.invalid"),
            password: "docker-pw-12345".into(),
            role: "operator".into(),
        },
    )
    .await
    .expect("user")
    {
        DockerResp::WebUserCreate { id } => id,
        other => panic!("unexpected user create: {other:?}"),
    };
    hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserSetCustomRole {
            user_id,
            custom_role_id: role_id,
        },
    )
    .await
    .expect("assign");
    acme_dns_login(app, name, "docker-pw-12345").await
}

#[tokio::test]
async fn monitoring_lists_both_kinds() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    acme_ssl_hosting(&sock, "hosted-e2e.cz").await;
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let resp = url_save(
        &app,
        &cookie,
        &[
            ("url", "https://status.example.org/health"),
            ("interval_secs", "60"),
            ("expected_status", "204"),
            ("alert_after_fails", "3"),
            ("node", "auto"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/monitoring?flash=saved");

    let (status, page) = acme_dns_get(&app, &cookie, "/monitoring?flash=saved").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page.contains("hosted-e2e.cz"),
        "the per-hosting monitor: {page}"
    );
    assert!(page.contains("URL checks"), "{page}");
    assert!(page.contains("https://status.example.org/health"), "{page}");
    assert!(page.contains("expects 204"), "{page}");
    assert!(page.contains("URL check saved."), "{page}");
    assert!(
        page.contains("no outside vantage point"),
        "the master's blind spot is stated: {page}"
    );
    // Both kinds are in the counts at the top: two monitors, no sample yet.
    assert!(page.contains("No samples yet"), "{page}");
    let unknown = page
        .split("No samples yet")
        .nth(1)
        .and_then(|rest| rest.split("font-weight:700").nth(1))
        .and_then(|rest| rest.split('>').nth(1))
        .and_then(|rest| rest.split('<').next())
        .map(str::trim)
        .map(str::to_string);
    assert_eq!(unknown.as_deref(), Some("2"), "{page}");
}

#[tokio::test]
async fn node_derived_on_save_and_override_wins() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    acme_ssl_hosting(&sock, "owned-e2e.cz").await;
    docker_enable_master(&sock, &pool).await;
    docker_add_worker(&sock, &pool, "node_w", "Worker").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    // The host name is a hosting on the master: that is the owner.
    let resp = url_save(
        &app,
        &cookie,
        &[("url", "https://owned-e2e.cz/health"), ("node", "auto")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let list = url_checks(&sock).await;
    let id = list.monitors[0].id;
    assert_eq!(list.monitors[0].node_id.as_deref(), Some("local"));
    assert!(!list.monitors[0].node_manual);
    let id_s = id.to_string();

    // The operator pins it elsewhere, and that wins.
    let resp = url_save(
        &app,
        &cookie,
        &[
            ("id", &id_s),
            ("url", "https://owned-e2e.cz/health"),
            ("node", "node_w"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let m = &url_checks(&sock).await.monitors[0];
    assert_eq!(m.node_id.as_deref(), Some("node_w"));
    assert!(m.node_manual);
    // The page says where it is pinned, by the node's label.
    let (_, page) = acme_dns_get(&app, &cookie, "/monitoring").await;
    assert!(page.contains("node: Worker"), "{page}");
    // ...and keeps the choice on the form.
    let (_, edit) = acme_dns_get(&app, &cookie, &format!("/monitoring?edit={id}")).await;
    assert!(edit.contains("Change the URL check"), "{edit}");
    assert!(
        edit.contains("value=\"node_w\" selected"),
        "the pinned node is the selected one: {edit}"
    );

    // A node that is not enrolled is refused, and nothing changes.
    let resp = url_save(
        &app,
        &cookie,
        &[
            ("id", &id_s),
            ("url", "https://owned-e2e.cz/health"),
            ("node", "node_made_up"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("not enrolled"));
    assert_eq!(
        url_checks(&sock).await.monitors[0].node_id.as_deref(),
        Some("node_w")
    );

    // Back to automatic: worked out again.
    let resp = url_save(
        &app,
        &cookie,
        &[
            ("id", &id_s),
            ("url", "https://owned-e2e.cz/health"),
            ("node", "auto"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let m = &url_checks(&sock).await.monitors[0];
    assert_eq!(m.node_id.as_deref(), Some("local"));
    assert!(!m.node_manual);

    // A node that cannot be asked cannot disown its domain: moving the
    // address to a host no hosting here has keeps what was stored.
    let resp = url_save(
        &app,
        &cookie,
        &[
            ("id", &id_s),
            ("url", "https://elsewhere.example.org/"),
            ("node", "auto"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        url_checks(&sock).await.monitors[0].node_id.as_deref(),
        Some("local"),
        "the worker did not answer, so no hosting was ruled out"
    );
}

#[tokio::test]
async fn no_matching_hosting_is_allowed() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let resp = url_save(
        &app,
        &cookie,
        &[
            ("url", "https://nobody-hosts-this.example.org/"),
            ("node", "auto"),
        ],
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "no owner is not an error"
    );
    let m = &url_checks(&sock).await.monitors[0];
    assert_eq!(m.node_id, None);
    assert!(!m.node_manual);
    let (_, page) = acme_dns_get(&app, &cookie, "/monitoring").await;
    assert!(page.contains("node: no hosting"), "{page}");

    // An address that is an IP has no host name to match either.
    let resp = url_save(
        &app,
        &cookie,
        &[("url", "http://10.0.0.5:8080/"), ("node", "auto")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(url_checks(&sock).await.monitors.len(), 2);
}

#[tokio::test]
async fn a_refused_check_comes_back_in_the_form() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    for (fields, wanted) in [
        (vec![("url", "ftp://example.org/")], "only http"),
        (
            vec![("url", "https://user:pw@example.org/")],
            "user name or password",
        ),
        (
            vec![("url", "https://example.org/"), ("interval_secs", "10")],
            "at least 30",
        ),
        (
            vec![("url", "https://example.org/"), ("interval_secs", "soon")],
            "whole number",
        ),
        (
            vec![
                ("url", "https://example.org/"),
                ("alert_slack_webhook", "ftp://x"),
            ],
            "Slack webhook",
        ),
    ] {
        let resp = url_save(&app, &cookie, &fields).await;
        assert_eq!(resp.status(), StatusCode::OK, "{fields:?}");
        let page = body_string(resp).await;
        assert!(page.contains(wanted), "{fields:?}: {page}");
        assert!(
            page.contains("Add a URL check"),
            "the form is still open: {page}"
        );
        let typed = fields[0].1;
        assert!(
            page.contains(&format!("value=\"{typed}\"")),
            "what was typed stays: {page}"
        );
    }
    assert!(url_checks(&sock).await.monitors.is_empty());
}

#[tokio::test]
async fn webhooks_are_never_drawn() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let resp = url_save(
        &app,
        &cookie,
        &[
            ("url", "https://example.org/"),
            (
                "alert_slack_webhook",
                "https://hooks.example.test/slack-s3cr3t",
            ),
            (
                "alert_webhook_url",
                "https://hooks.example.test/json-s3cr3t",
            ),
            ("alert_email", "ops@example.cz"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let id = url_checks(&sock).await.monitors[0].id;

    for uri in ["/monitoring".to_string(), format!("/monitoring?edit={id}")] {
        let (_, page) = acme_dns_get(&app, &cookie, &uri).await;
        assert!(
            !page.contains("s3cr3t") && !page.contains("hooks.example.test"),
            "{uri}: {page}"
        );
    }
    let (_, edit) = acme_dns_get(&app, &cookie, &format!("/monitoring?edit={id}")).await;
    assert!(
        edit.contains("ops@example.cz"),
        "the addresses are shown: {edit}"
    );
    assert!(edit.contains("clear_slack_webhook"), "{edit}");

    // Saved again with the webhook fields empty, both are kept.
    let resp = url_save(
        &app,
        &cookie,
        &[
            ("id", &id.to_string()),
            ("url", "https://example.org/changed"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let m = &url_checks(&sock).await.monitors[0];
    assert!(m.alert_slack_set && m.alert_webhook_set);
    assert_eq!(m.url, "https://example.org/changed");
    assert_eq!(m.alert_email, "", "an emptied field is an emptied list");

    // Removing is a box, not a blank.
    let resp = url_save(
        &app,
        &cookie,
        &[
            ("id", &id.to_string()),
            ("url", "https://example.org/changed"),
            ("clear_slack_webhook", "on"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let m = &url_checks(&sock).await.monitors[0];
    assert!(!m.alert_slack_set && m.alert_webhook_set);
}

#[tokio::test]
async fn url_checks_need_manage_and_scope_all() {
    use hyperion_state::capabilities::Capability;
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let boss = acme_dns_login(&app, "kevin", "good-pw").await;
    url_save(&app, &boss, &[("url", "https://example.org/")]).await;
    let id = url_checks(&sock).await.monitors[0].id;

    let view = Capability::MonitoringView.bit();
    let manage = view | Capability::MonitoringManage.bit();

    // Read only: the list, without the means to change it.
    let reader = url_role_user(&app, &sock, "url-reader", view, true).await;
    let (status, page) = acme_dns_get(&app, &reader, "/monitoring").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("https://example.org/"), "{page}");
    assert!(
        !page.contains("Add a URL check") && !page.contains("/delete"),
        "{page}"
    );
    let (_, asked) = acme_dns_get(&app, &reader, "/monitoring?new=1").await;
    assert!(
        !asked.contains("id=\"url-form\""),
        "no form for a reader: {asked}"
    );
    let csrf = acme_ssl_csrf(&app, &reader).await;
    let resp = acme_dns_post(
        &app,
        &reader,
        "/monitoring/urls",
        url_form_body(&csrf, &[("url", "https://other.example.org/")]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = acme_dns_post(
        &app,
        &reader,
        &format!("/monitoring/urls/{id}/delete"),
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Not every hosting in scope: not even the list.
    let narrow = url_role_user(&app, &sock, "url-narrow", manage, false).await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/monitoring")
                .header(header::COOKIE, &narrow)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let csrf = acme_ssl_csrf(&app, &narrow).await;
    let resp = acme_dns_post(
        &app,
        &narrow,
        "/monitoring/urls",
        url_form_body(&csrf, &[("url", "https://other.example.org/")]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // May manage, but is not an administrator: no webhooks, none stored.
    let manager = url_role_user(&app, &sock, "url-manager", manage, true).await;
    let (_, form) = acme_dns_get(&app, &manager, "/monitoring?new=1").await;
    assert!(form.contains("id=\"url-form\""), "{form}");
    assert!(!form.contains("alert_slack_webhook"), "{form}");
    let resp = url_save(
        &app,
        &manager,
        &[
            ("url", "https://managed.example.org/"),
            ("alert_slack_webhook", "https://hooks.example.test/sneaky"),
            ("alert_email", "mine@example.cz"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let list = url_checks(&sock).await;
    let m = list
        .monitors
        .iter()
        .find(|m| m.url == "https://managed.example.org/")
        .expect("saved");
    assert!(!m.alert_slack_set, "webhooks are administrators' input");
    assert_eq!(m.alert_email, "mine@example.cz");

    // And deleting is for managers.
    let csrf = acme_ssl_csrf(&app, &manager).await;
    let resp = acme_dns_post(
        &app,
        &manager,
        &format!("/monitoring/urls/{}/delete", m.id),
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(url_checks(&sock).await.monitors.len(), 1);
}

#[tokio::test]
async fn module_off_shows_no_url_checks() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let (status, page) = acme_dns_get(&app, &cookie, "/monitoring?new=1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !page.contains("id=\"url-checks\"") && !page.contains("id=\"url-form\""),
        "{page}"
    );
    assert!(!page.contains("no outside vantage point"), "{page}");

    let resp = url_save(&app, &cookie, &[("url", "https://example.org/")]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_string(resp).await.contains("Docker module"));

    // Turned on, they appear; turned off again, they and their history go.
    docker_enable_master(&sock, &pool).await;
    url_save(&app, &cookie, &[("url", "https://example.org/")]).await;
    let (_, page) = acme_dns_get(&app, &cookie, "/monitoring").await;
    assert!(page.contains("id=\"url-checks\""), "{page}");
    hyperion_rpc_client::call(&sock, DockerReq::DockerClusterRemove)
        .await
        .expect("remove");
    let (_, page) = acme_dns_get(&app, &cookie, "/monitoring").await;
    assert!(!page.contains("id=\"url-checks\""), "{page}");
    assert!(url_checks(&sock).await.monitors.is_empty());
}

#[tokio::test]
async fn deleting_a_url_check_removes_it() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    url_save(&app, &cookie, &[("url", "https://example.org/")]).await;
    let id = url_checks(&sock).await.monitors[0].id;

    let (_, page) = acme_dns_get(&app, &cookie, "/monitoring").await;
    assert!(
        page.contains(&format!("action=\"/monitoring/urls/{id}/delete\"")),
        "{page}"
    );
    // The confirmation rides on the form, not on the button.
    assert!(
        page.contains("data-confirm-title=\"Delete this URL check\""),
        "{page}"
    );

    let csrf = acme_ssl_csrf(&app, &cookie).await;
    let resp = acme_dns_post(
        &app,
        &cookie,
        &format!("/monitoring/urls/{id}/delete"),
        format!("_csrf={}", enc(&csrf)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/monitoring?flash=deleted");
    assert!(url_checks(&sock).await.monitors.is_empty());
    // Without a token nothing is deleted.
    url_save(&app, &cookie, &[("url", "https://example.org/")]).await;
    let id = url_checks(&sock).await.monitors[0].id;
    let resp = acme_dns_post(
        &app,
        &cookie,
        &format!("/monitoring/urls/{id}/delete"),
        String::new(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(url_checks(&sock).await.monitors.len(), 1);
}

// ---------------------------------------------------------------------------
// Docker: reverse proxy from a discovered stack.
// ---------------------------------------------------------------------------

/// A user on a custom role with exactly `caps`, every hosting in scope.
async fn docker_caps_user(
    app: &axum::Router,
    sock: &std::path::Path,
    name: &str,
    caps: &[hyperion_state::capabilities::Capability],
) -> String {
    let role_id = match hyperion_rpc_client::call(
        sock,
        DockerReq::RoleCreate {
            name: format!("caps-{name}"),
            capabilities: caps.iter().fold(0, |a, c| a | c.bit()),
            scope_all: true,
        },
    )
    .await
    .expect("role")
    {
        DockerResp::RoleCreate { id } => id,
        other => panic!("unexpected role create: {other:?}"),
    };
    let user_id = match hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserCreate {
            username: name.into(),
            email: format!("{name}@example.invalid"),
            password: "docker-pw-12345".into(),
            role: "operator".into(),
        },
    )
    .await
    .expect("user")
    {
        DockerResp::WebUserCreate { id } => id,
        other => panic!("unexpected user create: {other:?}"),
    };
    hyperion_rpc_client::call(
        sock,
        DockerReq::WebUserSetCustomRole {
            user_id,
            custom_role_id: role_id,
        },
    )
    .await
    .expect("assign");
    acme_dns_login(app, name, "docker-pw-12345").await
}

/// A reverse-proxy hosting on `upstream`; returns its id.
async fn docker_proxy_hosting(sock: &std::path::Path, domain: &str, upstream: &str) -> String {
    match hyperion_rpc_client::call(
        sock,
        DockerReq::HostingCreate(hyperion_rpc::wire::HostingCreateReq {
            domain: hyperion_validate::Domain::parse(domain).expect("domain"),
            aliases: vec![],
            php_version: None,
            database: None,
            system_user: None,
            kind: "reverse_proxy".into(),
            proxy_upstream_url: Some(upstream.into()),
        }),
    )
    .await
    .expect("seed proxy")
    {
        DockerResp::HostingCreate(c) => c.id.as_str().to_string(),
        other => panic!("unexpected create: {other:?}"),
    }
}

fn port_of(ip: &str, host: u16, container: u16, proto: &str) -> hyperion_types::docker::DockerPort {
    hyperion_types::docker::DockerPort {
        host_ip: ip.into(),
        host_port: host,
        container_port: container,
        proto: proto.into(),
    }
}

/// Stacks for the proxy tests: one per kind of published port.
fn proxy_snapshot() -> DockerNodeStatus {
    let stack = |name: &str, ports: Vec<hyperion_types::docker::DockerPort>| {
        let mut c = docker_container(name, "web", "running");
        c.ports = ports;
        DockerProject {
            name: name.into(),
            containers: vec![c],
            verdict: "ok".into(),
            ..Default::default()
        }
    };
    DockerNodeStatus {
        read_at: 1_700_000_100,
        daemon_ok: true,
        projects: vec![
            stack("loop", vec![port_of("127.0.0.1", 18080, 80, "tcp")]),
            stack(
                "wide",
                vec![
                    port_of("0.0.0.0", 18081, 80, "tcp"),
                    port_of("::", 18081, 80, "tcp"),
                ],
            ),
            stack("nginx-clash", vec![port_of("0.0.0.0", 80, 80, "tcp")]),
            stack("dns", vec![port_of("0.0.0.0", 5353, 53, "udp")]),
            stack("closed", vec![]),
        ],
        ..Default::default()
    }
}

#[tokio::test]
async fn stack_offers_a_reverse_proxy_per_published_port() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(proxy_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let (st, page) = acme_dns_get(&app, &cookie, "/docker/local/loop").await;
    assert_eq!(st, StatusCode::OK);
    let want = format!(
        "/hostings/new?site_type=reverse_proxy&amp;proxy_upstream_url={}&amp;target_node=local",
        enc("http://127.0.0.1:18080")
    );
    assert!(page.contains(&want), "{page}");
    assert!(
        !page.contains("bypass"),
        "a loopback bind carries no warning"
    );

    // 0.0.0.0 and :: of one port are one offer, and it is flagged.
    let (_, page) = acme_dns_get(&app, &cookie, "/docker/local/wide").await;
    assert_eq!(page.matches("Add reverse proxy").count(), 1, "{page}");
    assert!(page.contains("127.0.0.1:18081:80"), "{page}");
    assert!(page.contains("bypass"), "{page}");

    // nginx owns 80 and 443.
    let (_, page) = acme_dns_get(&app, &cookie, "/docker/local/nginx-clash").await;
    assert!(!page.contains("proxy_upstream_url="), "{page}");
    assert!(page.contains("nginx"), "{page}");

    // A UDP port is nothing to proxy to.
    let (_, page) = acme_dns_get(&app, &cookie, "/docker/local/dns").await;
    assert!(!page.contains("proxy_upstream_url="), "{page}");
}

#[tokio::test]
async fn no_published_port_explains_itself() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(proxy_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let (st, page) = acme_dns_get(&app, &cookie, "/docker/local/closed").await;
    assert_eq!(st, StatusCode::OK);
    assert!(page.contains("No published port"), "{page}");
    assert!(
        page.contains("127.0.0.1:"),
        "suggests how to publish: {page}"
    );
    assert!(
        page.contains("container address"),
        "says why not the container address: {page}"
    );
    assert!(!page.contains("Add reverse proxy"), "{page}");
}

#[tokio::test]
async fn add_reverse_proxy_is_for_those_who_may_create_hostings() {
    use hyperion_state::capabilities::Capability;
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(proxy_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;

    let reader = docker_caps_user(&app, &sock, "dk-reader", &[Capability::DockerView]).await;
    let (st, page) = acme_dns_get(&app, &reader, "/docker/local/loop").await;
    assert_eq!(st, StatusCode::OK);
    assert!(!page.contains("Add reverse proxy"), "{page}");
    assert!(page.contains("18080"), "the port is still shown: {page}");

    let maker = docker_caps_user(
        &app,
        &sock,
        "dk-maker",
        &[Capability::DockerView, Capability::HostingCreate],
    )
    .await;
    let (_, page) = acme_dns_get(&app, &maker, "/docker/local/loop").await;
    assert!(page.contains("Add reverse proxy"), "{page}");
}

#[tokio::test]
async fn stack_and_list_show_the_hosting_that_proxies_to_it() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(proxy_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    docker_proxy_hosting(&sock, "app.example.cz", "http://127.0.0.1:18080").await;
    docker_proxy_hosting(&sock, "other.example.cz", "http://10.0.0.5:18080").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    for uri in ["/docker/local/loop", "/docker"] {
        let (_, page) = acme_dns_get(&app, &cookie, uri).await;
        assert!(
            page.contains("href=\"/hostings/app.example.cz\""),
            "{uri}: {page}"
        );
        assert!(!page.contains("other.example.cz"), "{uri}");
    }
}

#[tokio::test]
async fn hosting_chip_names_the_stack_and_nothing_else() {
    use hyperion_state::capabilities::Capability;
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_full(None, Some(proxy_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_enable_master(&sock, &pool).await;
    let proxy_id = docker_proxy_hosting(&sock, "app.example.cz", "http://127.0.0.1:18080").await;
    docker_proxy_hosting(&sock, "lonely.example.cz", "http://127.0.0.1:9").await;
    let php_id = acme_ssl_hosting(&sock, "plain.example.cz").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;

    let (st, chip) = acme_dns_get(
        &app,
        &cookie,
        "/docker/hosting-chip?selector=app.example.cz",
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{chip}");
    assert!(chip.contains("loop"), "{chip}");
    assert!(chip.contains("href=\"/docker/local/loop\""), "{chip}");
    for other in ["wide", "nginx-clash", "closed", "dns"] {
        assert!(!chip.contains(other), "never lists other stacks: {chip}");
    }
    assert!(!chip.contains("logs"), "no log access from here: {chip}");
    // The id works as a selector too.
    let (_, by_id) = acme_dns_get(
        &app,
        &cookie,
        &format!("/docker/hosting-chip?selector={proxy_id}"),
    )
    .await;
    assert!(by_id.contains("href=\"/docker/local/loop\""), "{by_id}");

    // No stack behind it, not a proxy, not a hosting: nothing, not an error.
    for sel in [
        "lonely.example.cz",
        "plain.example.cz",
        &php_id,
        "nope.example.cz",
        "x",
    ] {
        let (st, body) = acme_dns_get(
            &app,
            &cookie,
            &format!("/docker/hosting-chip?selector={sel}"),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{sel}");
        assert!(body.trim().is_empty(), "{sel}: {body}");
    }

    // The hosting page carries the lazy slot for a proxy and only for one.
    let slot = "hx-get=\"/docker/hosting-chip?selector=";
    let (_, detail) = acme_dns_get(&app, &cookie, &format!("/hostings/{proxy_id}")).await;
    assert!(detail.contains(slot), "{detail}");
    let (_, detail) = acme_dns_get(&app, &cookie, &format!("/hostings/{php_id}")).await;
    assert!(!detail.contains(slot));

    // A reader without DockerView, or without every hosting in scope, gets
    // neither the slot nor the chip.
    let blind = docker_caps_user(&app, &sock, "dk-blind", &[Capability::HostingView]).await;
    let (_, detail) = acme_dns_get(&app, &blind, &format!("/hostings/{proxy_id}")).await;
    assert!(!detail.contains(slot));
    let (st, body) =
        acme_dns_get(&app, &blind, "/docker/hosting-chip?selector=app.example.cz").await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.trim().is_empty(), "{body}");
    let narrow = docker_custom_user(&app, &sock, "dk-narrow-chip", false).await;
    let (_, body) = acme_dns_get(
        &app,
        &narrow,
        "/docker/hosting-chip?selector=app.example.cz",
    )
    .await;
    assert!(body.trim().is_empty(), "{body}");
}

#[tokio::test]
async fn hosting_chip_is_empty_while_the_module_is_off() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, _pool) = start_agent_full(None, Some(proxy_snapshot())).await;
    let app = build_app(sock.clone(), admin);
    docker_proxy_hosting(&sock, "app.example.cz", "http://127.0.0.1:18080").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (st, body) = acme_dns_get(
        &app,
        &cookie,
        "/docker/hosting-chip?selector=app.example.cz",
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.trim().is_empty(), "{body}");
}

/// The wizard's page for the given query, with one worker enrolled so the
/// node picker is drawn.
async fn wizard_page(query: &str) -> String {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d, pool) = start_agent_with_pool().await;
    let app = build_app(sock.clone(), admin);
    docker_add_worker(&sock, &pool, "w1", "Worker one").await;
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (st, page) = acme_dns_get(&app, &cookie, &format!("/hostings/new{query}")).await;
    assert_eq!(st, StatusCode::OK, "{page}");
    page
}

/// The opening tag of the first element whose tag starts with `prefix`.
fn tag_at<'a>(page: &'a str, prefix: &str) -> &'a str {
    let at = page.find(prefix).unwrap_or_else(|| panic!("no {prefix}"));
    let end = page[at..].find('>').expect("tag end");
    &page[at..at + end]
}

#[tokio::test]
async fn prefill_fills_the_wizard() {
    let q = format!(
        "?site_type=reverse_proxy&proxy_upstream_url={}&target_node=w1&domain=evil.cz",
        enc("http://127.0.0.1:18080")
    );
    let page = wizard_page(&q).await;
    assert!(tag_at(
        &page,
        "<label class=\"type-card selected\" data-site-type=\"reverse_proxy\""
    )
    .contains("selected"));
    assert!(tag_at(
        &page,
        "<input type=\"radio\" name=\"site_type\" value=\"reverse_proxy\""
    )
    .contains("checked"));
    assert!(
        tag_at(&page, "<input id=\"proxy_upstream_url\"").contains("http://127.0.0.1:18080"),
        "{page}"
    );
    assert!(
        tag_at(&page, "<option value=\"w1\"").contains("selected"),
        "the container's node is the chosen server"
    );
    assert!(
        !page.contains("evil.cz"),
        "the domain is the admin's to type"
    );

    // The master is a target too.
    let q = format!(
        "?site_type=reverse_proxy&proxy_upstream_url={}&target_node=local",
        enc("http://localhost:3000/")
    );
    let page = wizard_page(&q).await;
    let master = page.find("<option value=\"local\"").expect("master option");
    assert!(page[master..]
        .split("</option>")
        .next()
        .unwrap()
        .contains("selected"));
    assert!(page.contains("http://localhost:3000/"));
}

#[tokio::test]
async fn prefill_ignores_bad_values() {
    for q in [
        format!("?proxy_upstream_url={}", enc("javascript:alert(1)")),
        format!(
            "?proxy_upstream_url={}",
            enc("\"><script>alert(1)</script>")
        ),
        format!("?proxy_upstream_url={}", enc("http://10.9.8.7:3000")),
        format!(
            "?proxy_upstream_url={}",
            enc("http://user:pw@127.0.0.1:3000")
        ),
        format!("?proxy_upstream_url={}", enc("http://127.0.0.1:3000;}")),
        format!("?proxy_upstream_url={}", enc("http://127.0.0.1")),
        "?site_type=php".to_string(),
        format!("?site_type={}", enc("\"><script>alert(1)</script>")),
        "?site_type=nonsense".to_string(),
        "?target_node=nope".to_string(),
        format!("?target_node={}", enc("\"><script>alert(1)</script>")),
    ] {
        let page = wizard_page(&q).await;
        assert!(!page.contains("<script>alert"), "{q}: reflected");
        assert!(!page.contains("javascript:alert"), "{q}: reflected");
        assert!(!page.contains("10.9.8.7"), "{q}: {page}");
        assert!(!page.contains("user:pw"), "{q}");
        assert!(
            tag_at(&page, "<input id=\"proxy_upstream_url\"").contains("value=\"\""),
            "{q}"
        );
        assert!(
            tag_at(
                &page,
                "<input type=\"radio\" name=\"site_type\" value=\"reverse_proxy\""
            )
            .find("checked")
            .is_none(),
            "{q}"
        );
        assert!(
            tag_at(
                &page,
                "<input type=\"radio\" name=\"site_type\" value=\"wordpress\""
            )
            .contains("checked"),
            "{q}: falls back to the default card"
        );
        let w1 = page.find("<option value=\"w1\"").expect("worker option");
        assert!(
            !page[w1..]
                .split("</option>")
                .next()
                .unwrap()
                .contains("selected"),
            "{q}: an unknown node selects nothing"
        );
    }
}

#[tokio::test]
async fn prefill_leaves_the_test_form_alone() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock, admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let (st, page) = acme_dns_get(
        &app,
        &cookie,
        &format!(
            "/hostings/new?test=1&site_type=reverse_proxy&proxy_upstream_url={}",
            enc("http://127.0.0.1:18080")
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !page.contains("18080"),
        "?test=1 is still the plain test form"
    );
}

#[tokio::test]
async fn submit_still_validates() {
    let admin = admin_user::create("kevin", "good-pw").expect("create");
    let (sock, _d) = start_agent().await;
    let app = build_app(sock.clone(), admin);
    let cookie = acme_dns_login(&app, "kevin", "good-pw").await;
    let csrf = acme_ssl_csrf(&app, &cookie).await;
    for (bad, why) in [
        ("javascript:alert(1)", "http"),
        ("http://user:pw@127.0.0.1:3000", "username or password"),
        ("http://127.0.0.1:3000;}", "upstream"),
    ] {
        let resp = acme_dns_post(
            &app,
            &cookie,
            "/hostings",
            format!(
                "_csrf={}&domain=prefilled-bad.example.cz&site_type=reverse_proxy&proxy_upstream_url={}&target_node=local",
                enc(&csrf),
                enc(bad)
            ),
        )
        .await;
        let page = body_string(resp).await;
        assert!(page.contains(why), "{bad}: {page}");
        assert!(
            !page.contains("<script>alert"),
            "{bad}: the error page does not reflect markup"
        );
    }
    // And nothing was created by any of them.
    let (_, list) = acme_dns_get(&app, &cookie, "/hostings").await;
    assert!(!list.contains("prefilled-bad.example.cz"));
}
