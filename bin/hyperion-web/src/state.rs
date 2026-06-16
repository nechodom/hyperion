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
