//! Shared application state for axum handlers.

use crate::admin_user::AdminUser;
use crate::config::Config;
use crate::ratelimit::RateLimiter;
use hyperion_auth::SessionSigner;
use hyperion_core::master_rpc::MasterRpcSigner;
use std::path::PathBuf;
use std::sync::Arc;

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
}

pub type SharedState = Arc<AppState>;
