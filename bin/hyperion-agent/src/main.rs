//! `hyperion-agent` — the privileged daemon.

use clap::Parser;
use hyperion_core::AdapterPort;
use std::path::PathBuf;
use std::sync::Arc;

mod config;
mod enroll;
mod inbound_rpc;

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
    // Master-RPC signing key — auto-generated on first start, mode
    // 0600. Only the master node really needs it (it's the one
    // that ACKs enrollments and heartbeats), but on a worker the
    // file just sits unused — harmless. Failure to load/generate
    // is logged and `with_master_rpc_signer` is simply skipped;
    // the node becomes a "remote RPC disabled" master.
    let master_rpc_key_path = std::path::PathBuf::from("/etc/hyperion/master-rpc.key");
    let master_rpc_signer = match hyperion_core::master_rpc::MasterRpcSigner::load_or_init(
        &master_rpc_key_path,
    ) {
        Ok(s) => {
            tracing::info!(path=%master_rpc_key_path.display(), "master_rpc signing key ready");
            Some(Arc::new(s))
        }
        Err(e) => {
            tracing::warn!(
                error=%e,
                path=%master_rpc_key_path.display(),
                "master_rpc signing key unavailable — remote-node RPC will be disabled"
            );
            None
        }
    };

    // The agent's enrollment state file path. Service checks its
    // existence at services_health() time as the "is this a worker?"
    // signal (workers have the file → hyperion-web is a non-issue;
    // master doesn't → hyperion-web is critical). Same path used by
    // the heartbeat loop + AgentImpl::with_state_file below.
    let state_file_for_svc = cfg
        .enrollment
        .state_file
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/hyperion/node-id.json"));

    let mut builder = hyperion_core::HostingService::new(pool, adapter, secrets)
        .with_paths(paths)
        .with_remote_backup(remote_backup)
        .with_retention(retention)
        .with_slack_webhook(slack_webhook)
        .with_acme_email(cfg.acme.contact_email.clone())
        .with_email(email_cfg, email_to)
        .with_agent_config_path(cli.config.clone())
        .with_node_state_file(state_file_for_svc)
        .with_git_sha(env!("HYPERION_GIT_SHA"));
    if let Some(signer) = master_rpc_signer {
        builder = builder.with_master_rpc_signer(signer);
    }
    let svc = Arc::new(builder);

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
    // Self-heal: scan every enabled nginx vhost for `ssl_certificate`
    // paths that no longer exist on disk. For each missing cert we
    // generate a self-signed bootstrap so `nginx -t` passes — without
    // this a single deleted cert dir bricks the WHOLE nginx process
    // and every hosting create/update/delete fails with `nginx -t`
    // exit 1. (Real LE cert gets reissued on the next renewal tick.)
    {
        let repair_svc = svc.clone();
        tokio::spawn(async move {
            match repair_svc.adapters.repair_orphan_certs().await {
                Ok((0, _scanned)) => {
                    tracing::debug!("boot: orphan cert sweep clean");
                }
                Ok((repaired, scanned)) => {
                    tracing::warn!(
                        repaired,
                        scanned,
                        "boot: regenerated self-signed certs for orphan vhosts — \
                         reloading nginx to recover"
                    );
                    // Best-effort reload. If nginx was already down
                    // because of this exact issue, `reload` will
                    // auto-promote to `start` (see nginx::reload
                    // self-heal). On reload failure the operator will
                    // see the error in journalctl and can investigate.
                    if let Err(e) = repair_svc.adapters.nginx_reload().await {
                        tracing::error!(
                            error = %e,
                            "boot: nginx reload after cert repair failed — \
                             manual `systemctl restart nginx` may be needed"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "boot: orphan cert sweep failed"
                    );
                }
            }
        });
    }
    // Self-heal: scan every PHP-FPM pool file for `user` /
    // `listen.owner` references to Unix users that no longer exist.
    // A single such pool makes php<ver>-fpm exit 78 EX_CONFIG on
    // start, systemd gives up after 5 retries, and EVERY hosting on
    // that PHP version starts returning 502. We quarantine the bad
    // file (rename → `.conf.hyperion-quarantined-<ts>`) and restart
    // FPM so healthy pools can serve again. Operator can inspect or
    // recover the quarantined file under /etc/php/<ver>/fpm/pool.d/.
    {
        let repair_svc = svc.clone();
        tokio::spawn(async move {
            match repair_svc.adapters.repair_orphan_fpm_pools().await {
                Ok((0, _scanned)) => {
                    tracing::debug!("boot: orphan FPM pool sweep clean");
                }
                Ok((quarantined, scanned)) => {
                    tracing::warn!(
                        quarantined,
                        scanned,
                        "boot: quarantined FPM pools that referenced missing Unix users — \
                         restarting affected php<ver>-fpm services"
                    );
                    // We don't know which PHP versions had a bad
                    // pool, but the cost of restarting all four is
                    // tiny (~50ms each) and idempotent for healthy
                    // versions (`reset-failed` + `start` is a no-op
                    // on a running service).
                    for ver in hyperion_types::PhpVersion::all() {
                        if let Err(e) = repair_svc.adapters.fpm_restart(*ver).await {
                            // Most likely the version isn't installed
                            // on this node — log at debug to keep the
                            // boot output clean.
                            tracing::debug!(
                                version = %ver,
                                error = %e,
                                "boot: FPM restart after quarantine returned non-zero \
                                 (often means this version isn't installed)"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "boot: orphan FPM pool sweep failed"
                    );
                }
            }
        });
    }
    // One-shot backfill: tag every hostings row that has NULL node_id
    // with this node's identifier. Pre-migration-016 rows still show
    // "—" in the UI until this completes — usually within a second of
    // boot — and after that every list/detail render carries a real
    // node chip.
    {
        let backfill_svc = svc.clone();
        tokio::spawn(async move {
            match backfill_svc.backfill_local_node_id().await {
                Ok(0) => {}
                Ok(n) => tracing::info!(rows = n, "boot: backfilled node_id on legacy rows"),
                Err(e) => tracing::warn!(error = %e, "boot: node_id backfill failed"),
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
    // Cert renewal — every 24h, sweep certificates for LE certs whose
    // `not_after` is within `renewal_window_days` (default 30) and
    // re-issue. Without this tick every LE cert silently expires at
    // day 90. Daily cadence is fine: LE certs are 90-day-lived and
    // the renewal window gives 30 days of retry headroom; an
    // operator restart never lengthens that window because the next
    // tick lines up within 24h of boot.
    {
        let renew_svc = svc.clone();
        let threshold = cfg.acme.renewal_window_days.max(1);
        tokio::spawn(async move {
            // 3-minute offset so we don't collide with scheduler /
            // stats / monitor ticks at boot.
            tokio::time::sleep(std::time::Duration::from_secs(180)).await;
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
            interval.tick().await; // immediate-first-tick consumption
            loop {
                let now = hyperion_types::now_secs();
                match renew_svc.cert_renew_tick(now, threshold).await {
                    Ok(results) if !results.is_empty() => {
                        let renewed = results
                            .iter()
                            .filter(|r| {
                                matches!(
                                    r.outcome,
                                    hyperion_types::CertRenewOutcome::Renewed { .. }
                                )
                            })
                            .count();
                        let failed = results
                            .iter()
                            .filter(|r| {
                                matches!(
                                    r.outcome,
                                    hyperion_types::CertRenewOutcome::Failed { .. }
                                )
                            })
                            .count();
                        tracing::info!(
                            due = results.len(),
                            renewed,
                            failed,
                            "cert renewal tick"
                        );
                    }
                    Ok(_) => tracing::debug!("cert renewal tick: nothing due"),
                    Err(e) => tracing::warn!(error=%e, "cert renewal tick failed"),
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
            verify_tls: cfg.enrollment.verify_tls,
            config_file: Some(cli.config.clone()),
        };
        // Outer loop — if the 5-attempt inner burst (~9 min) doesn't
        // succeed, sleep 30 min and try the burst again, indefinitely.
        // This is a daemon — there's no reason to ever give up. Without
        // this, a master that's unreachable for the first 10 min after
        // install leaves the node in a permanent zombie state until the
        // operator restarts hyperion-agent.
        //
        // Loop exits cleanly once node-id.json exists (either we
        // enrolled successfully, or `hctl enroll` ran on the side).
        tokio::spawn(async move {
            let mut consecutive_failures = 0u32;
            loop {
                if enr.state_file.exists() {
                    if consecutive_failures > 0 {
                        tracing::info!("enrollment succeeded out-of-band, exiting retry loop");
                    }
                    return;
                }
                match enroll::ensure_enrolled(enr.clone()).await {
                    Ok(()) => return,
                    Err(e) => {
                        consecutive_failures += 1;
                        tracing::warn!(
                            error = %e,
                            failure_streak = consecutive_failures,
                            "enrollment burst exhausted — sleeping 30 min before next burst"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(30 * 60)).await;
                    }
                }
            }
        });
    }
    // Periodic heartbeat (60s interval). No-op until enrolled.
    {
        let path = state_file.clone();
        let verify = cfg.enrollment.verify_tls;
        tokio::spawn(async move {
            enroll::heartbeat_loop(path, 60, verify).await;
        });
    }

    // Pass the resolved state_file path so agent_info() can read
    // enrollment state without re-deriving it. `with_version`
    // stamps the build-time git SHA so /install + the connectivity
    // test see the actual deployed revision instead of the
    // hardcoded Cargo.toml version (which never changes).
    let agent_version: String = {
        let short: String = env!("HYPERION_GIT_SHA").chars().take(12).collect();
        if short == "dev-unknown" || short.is_empty() {
            // Fallback for dev builds outside a git checkout.
            env!("CARGO_PKG_VERSION").to_string()
        } else {
            short
        }
    };
    let agent: Arc<dyn hyperion_rpc::AgentApi> = Arc::new(
        hyperion_core::AgentImpl::with_state_file(svc, state_file.clone())
            .with_version(agent_version),
    );

    // Inbound master→node remote RPC HTTPS listener. Disabled by
    // default; opt-in via `[remote_rpc] enabled = true`. The local
    // Unix socket always works regardless of this flag.
    if cfg.remote_rpc.enabled {
        match cfg.remote_rpc.bind.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                if let Err(e) = inbound_rpc::spawn_listener(
                    addr,
                    agent.clone(),
                    state_file.clone(),
                    cfg.remote_rpc.tls_cert_file.clone(),
                    cfg.remote_rpc.tls_key_file.clone(),
                )
                .await
                {
                    tracing::error!(
                        error=%e,
                        "could not start inbound RPC listener — node will only be reachable via local socket"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    bind=%cfg.remote_rpc.bind, error=%e,
                    "remote_rpc.bind is not a valid SocketAddr — inbound RPC disabled"
                );
            }
        }
    }

    let server = hyperion_rpc_server::Server::bind(&cfg.agent.socket_path, agent).await?;
    tracing::info!("ready");
    server.run().await?;
    Ok(())
}
