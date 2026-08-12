//! Shared application state for axum handlers.

use crate::admin_user::AdminUser;
use crate::config::Config;
use crate::ratelimit::RateLimiter;
use hyperion_auth::SessionSigner;
use hyperion_core::master_rpc::MasterRpcSigner;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AppState {
    pub cfg: Config,
    pub agent_socket: PathBuf,
    pub session: Arc<SessionSigner>,
    pub csrf_key: Arc<[u8; 32]>,
    pub admin_user: Arc<AdminUser>,
    /// In-process per-IP token-bucket limiter shared across handlers.
    /// See [`crate::ratelimit`] for the thread model.
    pub ratelimit: Arc<RateLimiter>,
    /// Ed25519 signing key for master→node remote RPC. `Some` when
    /// `/etc/hyperion/master-rpc.key` was readable at startup
    /// (created by hyperion-agent on first boot); `None` otherwise
    /// — the dispatcher refuses remote calls with a clean error.
    pub master_rpc_signer: Option<Arc<MasterRpcSigner>>,
    /// Cached `cluster.panel_hostname` from agent.toml, refreshed
    /// every 30 s by a background tokio task spawned at startup.
    /// Drives the host-enforcement middleware that redirects raw-IP
    /// requests to the configured hostname once the operator's
    /// finished the panel-domain setup. Empty string = no panel
    /// hostname set yet (middleware is a no-op).
    pub panel_hostname: Arc<RwLock<String>>,
    /// When true, an admin/super_admin who logs in without 2FA enrolled
    /// is corralled to the enrolment card before they can use the panel.
    /// Backed by the `cluster.enforce_admin_2fa` setting and refreshed
    /// live by the background poller (mirrors `panel_hostname`), so the
    /// operator can flip it from /settings without restarting by hand.
    /// In the test harness it's seeded to `false` (fixtures don't enrol).
    pub enforce_admin_2fa: Arc<std::sync::atomic::AtomicBool>,
    /// Cached `cluster.mode` — `"standalone"` or `"master"`. Refreshed by
    /// the same 30 s poller as `panel_hostname`, so the UI does not pay an
    /// extra RPC per page load just to know whether to draw cluster chrome.
    /// Presentation only: it decides what is worth SHOWING, never what is
    /// allowed. Defaults to `"master"` so a cold cache shows too much
    /// rather than hiding a real cluster.
    pub deployment_mode: Arc<RwLock<String>>,
    /// One-shot store for a freshly generated FTP password, keyed by a
    /// random token.
    ///
    /// The password used to be handed back in the redirect's QUERY STRING,
    /// which put a live credential into the browser history, the `Referer`
    /// of anything the page loads, and — the one that matters — nginx's
    /// access log, where it sits in plaintext for as long as logs are kept.
    /// The token goes in the URL instead: single-use, and useless once
    /// taken.
    ///
    /// In memory on purpose. It must not outlive the process, and a
    /// password that survives a restart is a password sitting somewhere it
    /// does not need to be.
    pub ftp_password_handoff:
        Arc<tokio::sync::Mutex<std::collections::HashMap<String, (String, i64)>>>,
}

impl AppState {
    pub fn cookie_name(&self) -> &str {
        &self.cfg.web.session_cookie_name
    }

    pub fn session_ttl(&self) -> i64 {
        self.cfg.web.session_ttl_secs
    }

    pub fn secure_cookies(&self) -> bool {
        self.cfg.web.secure_cookies
    }

    pub fn enforce_admin_2fa(&self) -> bool {
        self.enforce_admin_2fa
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub type SharedState = Arc<AppState>;
