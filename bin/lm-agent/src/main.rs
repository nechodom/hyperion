//! `lm-agent` — the privileged daemon.

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

mod config;

#[derive(Parser, Debug)]
#[command(name = "lm-agent", version, about = "linux-manager agent daemon")]
struct Cli {
    /// Path to the agent.toml config file.
    #[arg(long, default_value = "/etc/linux-manager/agent.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,lm=debug")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = config::Config::load_from_path(&cli.config)?;

    tracing::info!(socket=%cfg.agent.socket_path.display(), "starting lm-agent");

    let pool = lm_state::open(&cfg.agent.state_db).await?;
    let secrets = Arc::new(lm_core::SecretsStore::new(cfg.agent.secrets_dir.clone()));
    let adapter = Arc::new(lm_core::RealAdapter {
        acme_email: cfg.acme.contact_email.clone(),
        acme_directory_url: cfg.acme.directory_url.clone(),
        acme_challenge_root: cfg.acme.challenge_dir.clone(),
        ..Default::default()
    });
    let paths = lm_core::HostingPaths {
        home_root: cfg.agent.home_root.to_string_lossy().to_string(),
        acme_challenge_root: cfg.acme.challenge_dir.to_string_lossy().to_string(),
    };
    let svc = Arc::new(lm_core::HostingService::new(pool, adapter, secrets).with_paths(paths));
    // Background scheduler: fire scheduler_tick every 5 minutes.
    {
        let tick_svc = svc.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
            // Skip the immediate first tick — give the server a moment to bind.
            interval.tick().await;
            loop {
                interval.tick().await;
                match tick_svc.scheduler_tick().await {
                    Ok(n) if n > 0 => tracing::info!(processed = n, "scheduler tick"),
                    Ok(_) => tracing::debug!("scheduler tick: nothing due"),
                    Err(e) => tracing::warn!(error=%e, "scheduler tick failed"),
                }
            }
        });
    }
    let agent = Arc::new(lm_core::AgentImpl::new(svc));
    let server = lm_rpc_server::Server::bind(&cfg.agent.socket_path, agent).await?;
    tracing::info!("ready");
    server.run().await?;
    Ok(())
}
