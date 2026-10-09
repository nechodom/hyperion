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
    /// One-shot store for a long failure message, keyed by a random token.
    ///
    /// Same mechanism as `ftp_password_handoff`, for the opposite reason.
    /// Errors used to travel in the redirect's query string, and a wp-cli
    /// failure is easily longer than a URL can carry — so the operator got a
    /// message cut off mid-command, with the actual reason (the tail) gone.
    /// Query strings also land in nginx's access log, and a failure message
    /// can quote a path or a database error.
    ///
    /// In memory and single-use: a diagnostic that outlives the page that
    /// showed it is just another place for it to leak from.
    pub error_handoff: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (String, i64)>>>,
    /// WordPress plugin + theme lists per hosting, so the detail page does
    /// not bootstrap WordPress twice on every render. See
    /// [`crate::wp_list_cache`].
    pub wp_lists: Arc<crate::wp_list_cache::WpListCache>,
    /// Short-lived answers that are the same for every caller and asked
    /// for far more often than they change. See [`PanelCaches`].
    pub caches: Arc<PanelCaches>,
    /// First-run wizard: whether setup is pending, its one-time code, and
    /// the domain hand-off tokens. See [`crate::setup`].
    pub setup: Arc<crate::setup::SetupCtl>,
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

/// Per-process caches of cluster-wide answers, each a single-flight
/// [`TtlCell`](crate::ttl_cache::TtlCell). Per `AppState` rather than
/// `static` so two panels in one process (the test harness) never share.
pub struct PanelCaches {
    /// The master's `NodesList`. Read by EVERY remote dispatch (endpoint,
    /// pins) and by every aggregate page before its fan-out — a page
    /// fanning out to N nodes used to make N+1 identical local RPCs.
    pub nodes: crate::ttl_cache::TtlCell<Vec<hyperion_types::NodeSummary>>,
    /// The master's `AgentConfigView` (agent.toml, secrets masked). Read
    /// on every remote dispatch for the `[cluster]` enforcement toggles —
    /// it used to be one RPC (and a TOML parse) per dispatch — and by the
    /// pages that render from it.
    pub agent_config: crate::ttl_cache::TtlCell<std::sync::Arc<hyperion_types::AgentConfigView>>,
    /// Cluster-wide trash total behind the sidebar badge (a fan-out).
    pub trash_count: crate::ttl_cache::TtlCell<usize>,
    /// Sites that need a person, behind the sidebar dot (a fan-out).
    pub needs_you: crate::ttl_cache::TtlCell<usize>,
}

impl PanelCaches {
    /// Short: a node enrolled from its own shell, or a toggle edited in
    /// agent.toml by hand, shows up within seconds. Everything the PANEL
    /// changes is dropped at once by [`Self::invalidate_on_write`].
    pub const NODES_TTL: std::time::Duration = std::time::Duration::from_secs(5);
    pub const TRASH_TTL: std::time::Duration = std::time::Duration::from_secs(60);
    /// A number read at a glance; the /vulns page refreshes it on view.
    pub const NEEDS_YOU_TTL: std::time::Duration = std::time::Duration::from_secs(300);

    /// Called around every request [`Self::invalidated_by`] picks (see
    /// `drop_caches_on_write` in lib.rs). A node reset, an enforcement toggle or a trash/restore must
    /// never be answered from before it happened — an enforcement toggle
    /// switched ON in particular must hold from the very next dispatch.
    /// The needs-you count is left alone: it is a 5-minute summary, and
    /// dropping it on every save would put a cluster fan-out behind the
    /// next sidebar poll.
    /// Does this request drop the caches? Every write except the
    /// machine traffic that arrives on its own clock and changes none of
    /// them: node heartbeats (one per node per minute — on a big cluster
    /// these would keep the caches permanently empty; a pin a heartbeat
    /// fills in still lands within [`Self::NODES_TTL`]), import upload
    /// chunks, notification read-marks.
    pub fn invalidated_by(method: &axum::http::Method, path: &str) -> bool {
        use axum::http::Method;
        const NOT_PANEL_WRITES: &[&str] = &[
            "/api/heartbeat",
            "/import/upload/",
            "/import/progress",
            "/api/notifications/",
            "/notifications/",
        ];
        !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
            && !NOT_PANEL_WRITES.iter().any(|p| path.starts_with(p))
    }

    pub fn invalidate_on_write(&self) {
        self.nodes.invalidate();
        self.agent_config.invalidate();
        self.trash_count.invalidate();
    }
}

impl Default for PanelCaches {
    fn default() -> Self {
        PanelCaches {
            nodes: crate::ttl_cache::TtlCell::new(Self::NODES_TTL),
            agent_config: crate::ttl_cache::TtlCell::new(Self::NODES_TTL),
            trash_count: crate::ttl_cache::TtlCell::new(Self::TRASH_TTL),
            needs_you: crate::ttl_cache::TtlCell::new(Self::NEEDS_YOU_TTL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PanelCaches;
    use axum::http::Method;

    #[test]
    fn which_requests_drop_the_panel_caches() {
        assert!(!PanelCaches::invalidated_by(&Method::GET, "/install"));
        assert!(PanelCaches::invalidated_by(
            &Method::POST,
            "/install/reset-node-crypto"
        ));
        assert!(PanelCaches::invalidated_by(
            &Method::POST,
            "/settings/config"
        ));
        assert!(PanelCaches::invalidated_by(&Method::POST, "/trash/restore"));
        assert!(PanelCaches::invalidated_by(
            &Method::DELETE,
            "/api/v1/hostings/x"
        ));
        assert!(!PanelCaches::invalidated_by(
            &Method::POST,
            "/api/heartbeat"
        ));
        assert!(!PanelCaches::invalidated_by(
            &Method::POST,
            "/import/upload/chunk"
        ));
        assert!(!PanelCaches::invalidated_by(
            &Method::POST,
            "/api/notifications/mark-read"
        ));
    }
}
