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

    // Self-heal: every ancestor of the ACME challenge dir must be
    // world-traversable (the x-bit for "others"), otherwise nginx
    // (running as www-data) cannot reach challenge tokens and every
    // HTTP-01 cert issuance returns 404 → Invalid. Older install
    // scripts created /var/lib/hyperion at mode 0o700; this OR-s in
    // the traverse bits on every restart so an in-place upgrade
    // (via update.sh) is enough — no manual chmod required.
    if let Err(e) = tokio::fs::create_dir_all(&cfg.acme.challenge_dir).await {
        tracing::warn!(
            error = %e,
            path = %cfg.acme.challenge_dir.display(),
            "could not create ACME challenge dir at startup (HTTP-01 will fail)"
        );
    }
    hyperion_core::ensure_ancestors_traversable(&cfg.acme.challenge_dir).await;

    // Same shape of self-heal for /run/php/<ver>/ socket dirs. Without
    // these, PHP-FPM can't open its per-pool sockets and nginx 502s.
    // /run is tmpfs (wiped on reboot) — the install scripts drop a
    // tmpfiles.d snippet so systemd recreates them at boot, but this
    // call covers in-place upgrades where the snippet isn't installed
    // yet or systemd-tmpfiles hasn't run since.
    hyperion_core::ensure_phpfpm_socket_dirs().await;

    let pool = hyperion_state::open(&cfg.agent.state_db).await?;
    let secrets = Arc::new(hyperion_core::SecretsStore::new(
        cfg.agent.secrets_dir.clone(),
    ));
    // Detect the user nginx workers run as so FPM pool sockets get the
    // right `listen.owner`. Without this, a system where nginx inherited
    // a non-default user (e.g. CloudPanel sets `user vito;`) gets 502
    // Bad Gateway on every PHP request because nginx can't connect to a
    // socket owned by www-data. Build the adapter mutable, detect, then
    // freeze into Arc.
    let mut adapter_inner = hyperion_core::RealAdapter {
        acme_email: cfg.acme.contact_email.clone(),
        acme_directory_url: cfg.acme.directory_url.clone(),
        acme_challenge_root: cfg.acme.challenge_dir.clone(),
        ..Default::default()
    };
    adapter_inner.detect_nginx_user().await;
    let adapter = Arc::new(adapter_inner);

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
    let email_cfg = if cfg.email.enabled {
        Some(hyperion_core::EmailConfig {
            smtp_host: cfg.email.smtp_host.clone(),
            smtp_port: cfg.email.smtp_port,
            smtp_user: cfg.email.smtp_user.clone(),
            smtp_password: cfg.email.smtp_password.clone(),
            from_address: cfg.email.from_address.clone(),
            from_name: cfg.email.from_name.clone(),
            security: cfg.email.security.clone(),
        })
    } else {
        None
    };
    let email_to = if cfg.email.default_to.trim().is_empty() {
        None
    } else {
        Some(cfg.email.default_to.clone())
    };
    let svc = Arc::new(
        hyperion_core::HostingService::new(pool, adapter, secrets)
            .with_paths(paths)
            .with_remote_backup(remote_backup)
            .with_retention(retention)
            .with_slack_webhook(slack_webhook)
            .with_acme_email(cfg.acme.contact_email.clone())
            .with_email(email_cfg, email_to),
    );

    // Self-heal: re-render every Active hosting's FPM pool with the
    // detected nginx user. Old pool files on disk may still encode a
    // stale `listen.owner` (e.g. www-data when nginx now runs as
    // `vito`). Without this an in-place upgrade via update.sh wouldn't
    // unbreak existing 502'ing hostings.
    {
        let rerender_svc = svc.clone();
        tokio::spawn(async move {
            let n = rerender_svc.rerender_fpm_pools().await;
            if n > 0 {
                tracing::info!(count = n, "boot: re-rendered FPM pools with current nginx user");
            }
        });
    }
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
    // Background per-hosting HTTP monitor: every 60s the tick walks all
    // enabled hostings whose `monitor_interval_secs` has elapsed since
    // the last sample, probes each, records, and dispatches alerts.
    // 60s is a fine outer cadence because the per-hosting interval
    // gates work; we just want enough resolution that a 60s interval
    // (the minimum) actually fires every minute.
    {
        let monitor_svc = svc.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(45)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // immediate-first-tick consumption
            loop {
                match monitor_svc.monitor_tick().await {
                    Ok(0) => tracing::debug!("monitor tick: nothing due"),
                    Ok(n) => tracing::info!(sampled = n, "monitor tick"),
                    Err(e) => tracing::warn!(error=%e, "monitor tick failed"),
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
