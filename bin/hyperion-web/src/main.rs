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
    let state = Arc::new(AppState {
        cfg,
        agent_socket,
        session: Arc::new(signer),
        csrf_key: Arc::new(csrf_key),
        admin_user: Arc::new(admin),
    });
    let app = hyperion_web::build_router(state);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(addr=%listen, "hyperion-web ready");
    axum::serve(listener, app).await?;
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
