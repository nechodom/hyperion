//! Shared application state for axum handlers.

use crate::admin_user::AdminUser;
use crate::config::Config;
use crate::ratelimit::RateLimiter;
use hyperion_auth::SessionSigner;
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
