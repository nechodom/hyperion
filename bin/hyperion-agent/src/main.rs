//! `hyperion-agent` — the privileged daemon.

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

mod config;
mod enroll;

fn hostname_or_unknown() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[derive(Parser, Debug)]
#[command(name = "hyperion-agent", version, about = "hyperion agent daemon")]
struct Cli {
    /// Path to the agent.toml config file.
    #[arg(long, default_value = "/etc/hyperion/agent.toml")]
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

    tracing::info!(socket=%cfg.agent.socket_path.display(), "starting hyperion-agent");

    let pool = hyperion_state::open(&cfg.agent.state_db).await?;
    let secrets = Arc::new(hyperion_core::SecretsStore::new(
        cfg.agent.secrets_dir.clone(),
    ));
    let adapter = Arc::new(hyperion_core::RealAdapter {
        acme_email: cfg.acme.contact_email.clone(),
        acme_directory_url: cfg.acme.directory_url.clone(),
        acme_challenge_root: cfg.acme.challenge_dir.clone(),
        ..Default::default()
    });
    let paths = hyperion_core::HostingPaths {
        home_root: cfg.agent.home_root.to_string_lossy().to_string(),
        acme_challenge_root: cfg.acme.challenge_dir.to_string_lossy().to_string(),
        backup_root: cfg.agent.backup_root.to_string_lossy().to_string(),
    };
    let remote_backup = if cfg.backup_remote.enabled {
        Some(hyperion_core::RemoteBackupConfig {
            scheme: cfg.backup_remote.scheme.clone(),
            host: cfg.backup_remote.host.clone(),
            port: cfg.backup_remote.port,
            user: cfg.backup_remote.user.clone(),
            password: cfg.backup_remote.password.clone(),
            base_path: cfg.backup_remote.base_path.clone(),
        })
    } else {
        None
    };
    let retention = hyperion_core::BackupRetention {
        max_age_days: cfg.backup_retention.max_age_days.max(1),
        keep_latest_n: cfg.backup_retention.keep_latest_n.max(1),
    };
    let slack_webhook = if cfg.slack.default_webhook.trim().is_empty() {
        None
    } else {
        Some(cfg.slack.default_webhook.clone())
    };
    let svc = Arc::new(
        hyperion_core::HostingService::new(pool, adapter, secrets)
            .with_paths(paths)
            .with_remote_backup(remote_backup)
            .with_retention(retention)
            .with_slack_webhook(slack_webhook),
    );
    // Background scheduler: fire scheduler_tick (expiry sweep) every 5 minutes.
    {
        let tick_svc = svc.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
            interval.tick().await; // skip the immediate first tick
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
    // Background stats sampler: fire stats_tick every 5 minutes. Offset
    // by 30s so it doesn't collide with the scheduler tick.
    {
        let stats_svc = svc.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
            interval.tick().await; // immediate first tick now that we're past the offset
            loop {
                match stats_svc.stats_tick().await {
                    Ok(n) => tracing::info!(sampled = n, "stats tick"),
                    Err(e) => tracing::warn!(error=%e, "stats tick failed"),
                }
                interval.tick().await;
            }
        });
    }
    // Billing sweep — once per hour. Sends Slack reminders for hostings
    // with next_billing_at <= now + 3d.
    {
        let bs = svc.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.tick().await;
            loop {
                match bs.billing_sweep().await {
                    Ok(n) if n > 0 => tracing::info!(notified = n, "billing sweep"),
                    Ok(_) => tracing::debug!("billing sweep: nothing due"),
                    Err(e) => tracing::warn!(error=%e, "billing sweep failed"),
                }
                interval.tick().await;
            }
        });
    }
    // One-shot enrollment with the master, if configured and not yet done.
    let state_file = cfg
        .enrollment
        .state_file
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/hyperion/node-id.json"));
    if !cfg.enrollment.master_url.is_empty() && !cfg.enrollment.invite_token.is_empty() {
        let enr = enroll::EnrollmentConfig {
            master_url: cfg.enrollment.master_url.clone(),
            token: cfg.enrollment.invite_token.clone(),
            label: if cfg.enrollment.node_label.is_empty() {
                hostname_or_unknown()
            } else {
                cfg.enrollment.node_label.clone()
            },
            state_file: state_file.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = enroll::ensure_enrolled(enr).await {
                tracing::warn!(error=%e, "enrollment failed (will retry next boot)");
            }
        });
    }
    // Periodic heartbeat (60s interval). No-op until enrolled.
    {
        let path = state_file.clone();
        tokio::spawn(async move {
            enroll::heartbeat_loop(path, 60).await;
        });
    }

    let agent = Arc::new(hyperion_core::AgentImpl::new(svc));
    let server = hyperion_rpc_server::Server::bind(&cfg.agent.socket_path, agent).await?;
    tracing::info!("ready");
    server.run().await?;
    Ok(())
}
