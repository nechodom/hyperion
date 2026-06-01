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
    let cfg = Config::default();
    let signer = SessionSigner::new_random();
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
        session: Arc::new(signer),
        csrf_key: Arc::new(csrf_key),
        admin_user: Arc::new(admin),
    });
    hyperion_web::build_router(state)
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
