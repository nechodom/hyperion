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
    let dir = tempfile::tempdir().expect("dir");
    let pool = open_memory().await.expect("memory db");
    let secrets = Arc::new(SecretsStore::new(dir.path().join("secrets")));
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
        panel_progress: Arc::new(tokio::sync::RwLock::new(None)),
        master_rpc_signer: None,
        node_state_file: None,
        node_update: Arc::new(tokio::sync::Mutex::new(
            hyperion_types::NodeUpdateStatus::default(),
        )),
        service_install_progress: Arc::new(tokio::sync::Mutex::new(
            hyperion_types::ServiceInstallStatus::default(),
        )),
    });
    let agent: Arc<dyn AgentApi> = Arc::new(AgentImpl::new(svc));
    let path = dir.path().join("agent.sock");
    let srv = hyperion_rpc_server::Server::bind(&path, agent)
        .await
        .expect("bind");
    tokio::spawn(srv.run());
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (path, dir)
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
        enforce_admin_2fa: false,
    });
    (hyperion_web::build_router(state), signer)
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

    // Fetch the audit page
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/audit")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Audit log"));
    assert!(body.contains("hosting.suspend"), "body: {body}");
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
    assert!(
        body.contains("Wrong code"),
        "expected friendly 'Wrong code' message, got body: {body}"
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
    // Logout redirects to /login on success.
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get(header::LOCATION).expect("loc");
    assert_eq!(loc.to_str().unwrap(), "/login");
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
    let body = format!(
        "_csrf={csrf}&domain=rbac-victim.cz&aliases=&php=8.3&db=mariadb&system_user="
    );
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

/// /emails renders the global email log table — even when the
/// agent has zero rows, the page is reachable + shows the empty
/// state with a pointer to /settings. Locks in the route + the
/// "show migration error hint" path.
#[tokio::test]
async fn emails_page_renders_with_filters() {
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
        .expect("login");
    let cookie = extract_cookie(&resp);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/emails")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Email log"), "missing page title");
    assert!(body.contains("/emails?kind=test"), "kind=test filter missing");
    assert!(body.contains("/emails?state=failed"), "state=failed filter missing");
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

/// /hostings/import page renders with the URL + token form.
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
        .oneshot(
            Request::builder()
                .uri("/hostings/import")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("call");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Import hosting from another node"));
    assert!(body.contains("name=\"base_url\""));
    assert!(body.contains("name=\"token\""));
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
