//! `hyperion-web` — modern axum-based admin UI for hyperion-agent.

use anyhow::Context;
use clap::{Parser, Subcommand};
use hyperion_auth::{keys, SessionSigner};
use hyperion_web::config::Config;
use hyperion_web::state::AppState;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "hyperion-web", version, about = "hyperion web admin UI")]
struct Cli {
    /// Path to web.toml config.
    #[arg(long, default_value = "/etc/hyperion/web.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the HTTP server (default if no subcommand).
    Serve,
    /// Create or replace the bootstrap admin user.
    Bootstrap {
        #[arg(long)]
        username: Option<String>,
        /// Provide password non-interactively (e.g. for scripts).
        #[arg(long)]
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,hyperion_web=debug")),
        )
        .init();
    let cli = Cli::parse();
    let cfg = Config::load_from_path(&cli.config)?;
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Serve => serve(cfg).await,
        Cmd::Bootstrap { username, password } => bootstrap(cfg, username, password),
    }
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    let admin = hyperion_web::admin_user::load(&cfg.web.admin_user_file)
        .context("loading admin user (run `hyperion-web bootstrap` first)")?;
    let session_secret = keys::load_or_init(&cfg.web.session_key_file)?;
    let signer = SessionSigner::from_secret_bytes(&session_secret)
        .map_err(|e| anyhow::anyhow!("session signer: {e}"))?;
    let csrf_key = keys::load_or_init(&cfg.web.csrf_key_file)?;
    let listen = cfg.web.listen.clone();
    let agent_socket = cfg.web.agent_socket.clone();
    let tls_enabled = cfg.web.tls_enabled;
    let tls_cert = cfg.web.tls_cert_file.clone();
    let tls_key = cfg.web.tls_key_file.clone();
    // Master remote-RPC signing key. Owned by hyperion-agent (which
    // generates it at first boot, mode 0600); hyperion-web just
    // reads. If the file isn't present yet (agent hasn't started
    // once), load_or_init would CREATE it under web's uid which is
    // fine — both processes run as root. Failure here logs and
    // leaves the dispatcher in "remote calls disabled" mode.
    let master_rpc_signer = match hyperion_core::master_rpc::MasterRpcSigner::load_or_init(
        std::path::Path::new("/etc/hyperion/master-rpc.key"),
    ) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            tracing::warn!(error=%e, "master-rpc.key not loaded — remote-node UI dispatch disabled");
            None
        }
    };

    let state = Arc::new(AppState {
        cfg,
        agent_socket,
        session: Arc::new(signer),
        csrf_key: Arc::new(csrf_key),
        admin_user: Arc::new(admin),
        ratelimit: Arc::new(hyperion_web::ratelimit::RateLimiter::new()),
        master_rpc_signer,
        panel_hostname: Arc::new(tokio::sync::RwLock::new(String::new())),
        // Seed on = mandatory for admin+. The poller below replaces this
        // with the live `cluster.enforce_admin_2fa` setting within 30 s.
        enforce_admin_2fa: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    // Spawn a background refresher that polls the agent for the
    // current `cluster.panel_hostname` every 30 s. The host-enforce
    // middleware (in lib.rs) reads from this cache to redirect raw-IP
    // requests once the operator's set up the panel domain.
    {
        let state_for_refresh = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            tick.set_missed_tick_behavior(
                tokio::time::MissedTickBehavior::Delay,
            );
            loop {
                tick.tick().await;
                let resp = hyperion_rpc_client::call(
                    &state_for_refresh.agent_socket,
                    hyperion_rpc::codec::Request::AgentConfigView,
                )
                .await;
                if let Ok(hyperion_rpc::codec::Response::AgentConfigView(cfg)) = resp {
                    state_for_refresh.enforce_admin_2fa.store(
                        cfg.cluster.enforce_admin_2fa,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    let mut g = state_for_refresh.panel_hostname.write().await;
                    *g = cfg.cluster.panel_hostname;
                }
            }
        });
    }
    let app = hyperion_web::build_router(state);
    let bind_addr: std::net::SocketAddr = listen
        .parse()
        .with_context(|| format!("bad listen address: {listen}"))?;

    if tls_enabled {
        // rustls 0.23 wants an explicit process-wide CryptoProvider.
        // Set the `ring` provider once at startup; subsequent calls
        // (e.g. in tests) are harmless no-ops.
        let _ = rustls::crypto::ring::default_provider().install_default();
        ensure_self_signed(&tls_cert, &tls_key)
            .context("TLS cert/key auto-provision")?;
        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls_cert, &tls_key)
                .await
                .with_context(|| {
                    format!(
                        "load TLS cert + key from {} / {}",
                        tls_cert.display(),
                        tls_key.display()
                    )
                })?;
        tracing::info!(addr=%bind_addr, "hyperion-web ready (TLS)");
        // Per-IP rate-limit handlers need ConnectInfo<SocketAddr>;
        // wiring it here makes axum extract it for every request.
        axum_server::bind_rustls(bind_addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        tracing::info!(addr=%bind_addr, "hyperion-web ready (PLAINTEXT)");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

/// Materialize a self-signed cert + key pair if they don't already
/// exist. Operator can replace them later with a real LE cert by
/// dropping files into the same paths and restarting hyperion-web.
fn ensure_self_signed(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<()> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    tracing::info!(
        cert=%cert_path.display(),
        key=%key_path.display(),
        "TLS cert/key missing — generating self-signed"
    );
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let hostname = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "hyperion".to_string());
    let mut names = vec![hostname.clone(), "localhost".to_string()];
    if let Ok(local_addr) = std::env::var("HYPERION_TLS_SAN") {
        for s in local_addr.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            names.push(s.to_string());
        }
    }
    let params = rcgen::CertificateParams::new(names.clone())
        .map_err(|e| anyhow::anyhow!("rcgen params: {e}"))?;
    let kp = rcgen::KeyPair::generate().map_err(|e| anyhow::anyhow!("rcgen kp: {e}"))?;
    let cert = params
        .self_signed(&kp)
        .map_err(|e| anyhow::anyhow!("rcgen sign: {e}"))?;
    std::fs::write(cert_path, cert.pem().as_bytes())?;
    std::fs::write(key_path, kp.serialize_pem().as_bytes())?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644));
    let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

fn bootstrap(
    cfg: Config,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<()> {
    let username = username.unwrap_or_else(|| "admin".to_string());
    let password = match password {
        Some(p) => p,
        None => prompt_password()?,
    };
    let user = hyperion_web::admin_user::create(&username, &password)?;
    hyperion_web::admin_user::save(&cfg.web.admin_user_file, &user)?;
    println!(
        "✓ wrote {} (user={}, id={})",
        cfg.web.admin_user_file.display(),
        user.username,
        user.id
    );
    Ok(())
}

fn prompt_password() -> anyhow::Result<String> {
    let mut s = String::new();
    print!("password: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim_end_matches('\n').trim_end_matches('\r').to_string())
}
