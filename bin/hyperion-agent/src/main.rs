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

/// The version token the agent reports to the master: the human git-describe
/// string (`HYPERION_DESCRIBE`, e.g. `v1.2.0-5-gf718fd1`, stamped by build.rs),
/// falling back to CARGO_PKG_VERSION only for dev builds outside a git checkout.
/// This is the SINGLE source of the value — `AgentInfo`, enroll, and heartbeat
/// all call it, so the `nodes.agent_version` column behind the cluster
/// version-skew pill carries a real, comparable version instead of the useless
/// hardcoded "0.1.0". Two nodes on the same commit describe identically (match);
/// different commits describe differently (flagged).
pub(crate) fn agent_version() -> String {
    let describe = env!("HYPERION_DESCRIBE");
    if describe.is_empty() || describe == "dev-unknown" {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        describe.to_string()
    }
}

/// `--version` output: the human git-describe version + the full git SHA stamped
/// at build time (build.rs), e.g. `v1.2.0-5-gf718fd1 (f718fd1a…40 chars…)`. The
/// bare CARGO_PKG_VERSION is a useless "0.1.0" for every build, so we lead with
/// the describe string for humans and keep the full 40-char SHA in parens —
/// the latter is what `update.sh`'s post-install check greps to verify exactly
/// which commit the installed binary was built from.
const HYPERION_VERSION: &str = concat!(
    env!("HYPERION_DESCRIBE"),
    " (",
    env!("HYPERION_GIT_SHA"),
    ")"
);

#[derive(Parser, Debug)]
#[command(name = "hyperion-agent", version = HYPERION_VERSION, about = "hyperion agent daemon")]
struct Cli {
    /// Path to the agent.toml config file.
    #[arg(long, default_value = "/etc/hyperion/agent.toml")]
    config: PathBuf,

    /// Validate that all embedded DB migrations apply cleanly to a COPY of the
    /// current state DB, then exit (0 = ok, 1 = failure). Never touches the
    /// real database — used by update.sh as a pre-restart safety gate so a
    /// migration that fails on the production schema is caught before the
    /// agent is restarted into a crash-loop.
    #[arg(long)]
    dry_run_migrations: bool,
}

/// Apply the embedded migrations to a throwaway copy of the real state DB and
/// report whether they succeed. Exits the process (0 ok / 1 fail).
async fn dry_run_migrations(real_db: &std::path::Path) -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!("hyperion-migcheck-{}", std::process::id()));
    tokio::fs::create_dir_all(&dir).await?;
    let temp_db = dir.join("state.db");
    if real_db.exists() {
        // Copy the main DB plus any WAL/SHM sidecars so we validate against the
        // real, current schema rather than an empty one.
        for suffix in ["", "-wal", "-shm"] {
            let src = std::path::PathBuf::from(format!("{}{}", real_db.display(), suffix));
            if src.exists() {
                let dst = dir.join(format!("state.db{suffix}"));
                if let Err(e) = tokio::fs::copy(&src, &dst).await {
                    tracing::warn!(error=%e, ?src, "could not copy DB sidecar for dry-run");
                }
            }
        }
        tracing::info!(db = %real_db.display(), "validating migrations against a copy of the live DB");
    } else {
        tracing::info!(db = %real_db.display(), "no existing state DB — validating migrations on a fresh DB");
    }
    let result = hyperion_state::open(&temp_db).await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    match result {
        Ok(_) => {
            println!("migrations OK");
            Ok(())
        }
        Err(e) => {
            eprintln!("migration dry-run FAILED: {e}");
            std::process::exit(1);
        }
    }
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

    if cli.dry_run_migrations {
        return dry_run_migrations(&cfg.agent.state_db).await;
    }

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
    // Postfix self-heal. Postfix is always brought to one of two
    // known-good states at boot (idempotent):
    //
    //   (A) Smart-host mode — when [email] is enabled AND has a
    //       non-empty smtp_host. Site mail() and Hyperion's own
    //       outbound share the same authenticated SMTP relay.
    //
    //   (B) Direct-MX mode — when [email] is empty / disabled.
    //       Postfix does its own MX lookup and SMTPs the recipient
    //       directly from this node's IP. Works fine for operators
    //       who handle their own PTR / SPF / DKIM and aren't behind
    //       a port-25-blocked provider. We harden the defaults:
    //       myhostname = `hostname -f`, smtp_helo_name = $myhostname,
    //       myorigin = $myhostname, inet_interfaces = loopback-only
    //       (the public port 25 listener stays closed so this box
    //       can never accidentally be an open relay).
    //
    // The two modes share a single marker file so a future operator
    // can `cat /etc/postfix/hyperion-relay.marker` to see which one
    // the agent picked.
    {
        let email_cfg_for_postfix = email_cfg.clone();
        let agent_hostname = hostname_or_unknown();
        tokio::spawn(async move {
            if !hyperion_core::postfix_is_installed().await {
                tracing::debug!("boot: postfix not installed — skipping mail config");
                return;
            }
            match email_cfg_for_postfix {
                Some(cfg) if !cfg.smtp_host.trim().is_empty() => {
                    match hyperion_core::postfix_ensure_relay_config(&cfg).await {
                        Ok(()) => {
                            tracing::info!(
                                relay = %cfg.smtp_host,
                                port = cfg.smtp_port,
                                "boot: postfix configured as smart-host via [email] relay"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "boot: postfix smart-host config FAILED — PHP mail() will \
                                 not deliver. Fix the error and restart hyperion-agent."
                            );
                        }
                    }
                }
                _ => {
                    // Direct-MX mode. Resolve a real FQDN from
                    // `hostname -f`; fall back to the short hostname
                    // if the box doesn't have a configured DNS
                    // domain (operator can still send, just from an
                    // unqualified HELO — many receivers reject this,
                    // so we log a warning).
                    let fqdn = match tokio::process::Command::new("/bin/hostname")
                        .arg("-f")
                        .output()
                        .await
                    {
                        Ok(o) if o.status.success() => {
                            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            if s.is_empty() {
                                agent_hostname.clone()
                            } else {
                                s
                            }
                        }
                        _ => agent_hostname.clone(),
                    };
                    if !fqdn.contains('.') {
                        tracing::warn!(
                            hostname = %fqdn,
                            "boot: postfix direct-MX configured with a non-FQDN HELO — \
                             most receivers will reject mail. Set a proper FQDN with \
                             `hostnamectl set-hostname <name>.<domain>` and ensure the IP's \
                             PTR record matches."
                        );
                    }
                    match hyperion_core::postfix_ensure_direct_delivery_config(&fqdn).await {
                        Ok(()) => {
                            tracing::info!(
                                myhostname = %fqdn,
                                "boot: postfix configured for direct MX delivery — \
                                 operator handles PTR / SPF / DKIM"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "boot: postfix direct-MX config FAILED — PHP mail() may not \
                                 deliver. Fix the error and restart hyperion-agent."
                            );
                        }
                    }
                }
            }
        });
    }
    // Master-RPC signing key — auto-generated on first start, mode
    // 0600. Only the master node really needs it (it's the one
    // that ACKs enrollments and heartbeats), but on a worker the
    // file just sits unused — harmless. Failure to load/generate
    // is logged and `with_master_rpc_signer` is simply skipped;
    // the node becomes a "remote RPC disabled" master.
    let master_rpc_key_path = std::path::PathBuf::from("/etc/hyperion/master-rpc.key");
    let master_rpc_signer =
        match hyperion_core::master_rpc::MasterRpcSigner::load_or_init(&master_rpc_key_path) {
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
                tracing::info!(
                    count = n,
                    "boot: re-rendered FPM pools with current nginx user"
                );
            }
        });
    }
    // Self-heal / upgrade: re-assert the master panel vhost so template changes
    // take effect after an in-place update — notably the upstream-down
    // "updating" page that replaces a bare 502 while update.sh has hyperion-web
    // stopped. No-op unless a panel hostname + cert are already present.
    {
        let panel_svc = svc.clone();
        tokio::spawn(async move {
            match panel_svc.ensure_panel_vhost().await {
                Ok(true) => tracing::info!("boot: re-asserted master panel vhost"),
                Ok(false) => tracing::debug!("boot: no panel vhost to assert"),
                Err(e) => tracing::warn!(error=%e, "boot: panel vhost re-assert failed"),
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
            // ALSO heal missing log dirs in the same pass. nginx opens
            // every access_log / error_log file at startup; a missing
            // parent dir produces the same emerg-exit as a missing
            // cert. We do this BEFORE the cert sweep so a node whose
            // certs AND log dirs are both broken can recover in one
            // nginx_reload at the end.
            let log_dirs = repair_svc.adapters.ensure_vhost_log_dirs().await;
            let mut need_reload = false;
            match log_dirs {
                Ok((0, _)) => tracing::debug!("boot: vhost log dir sweep clean"),
                Ok((created, scanned)) => {
                    tracing::warn!(
                        created,
                        scanned,
                        "boot: created missing nginx log dirs — will reload"
                    );
                    need_reload = true;
                }
                Err(e) => tracing::error!(error = %e, "boot: vhost log dir sweep failed"),
            }
            match repair_svc.adapters.repair_orphan_certs().await {
                Ok((0, _scanned)) => {
                    tracing::debug!("boot: orphan cert sweep clean");
                    if need_reload {
                        let _ = repair_svc.adapters.nginx_reload().await;
                    }
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
            // Belt-and-braces: regardless of what the quarantine
            // pass did, walk every installed php<ver>-fpm service
            // and recover any in "failed" state. This handles the
            // exact stav scenario: an older boot wrote a broken
            // pool, FPM died, systemd marked it failed after 5
            // retries. A later boot fixed the pool (via rerender)
            // but never reset the failed flag — so the service
            // stays dead until we explicitly reset-failed + start.
            // Idempotent for healthy services: is-failed returns
            // false → we skip them.
            match repair_svc.adapters.fpm_recover_failed().await {
                Ok(0) => {
                    tracing::debug!("boot: no FPM services in failed state");
                }
                Ok(n) => {
                    tracing::warn!(recovered = n, "boot: kicked failed FPM services back up");
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "boot: FPM failed-state recovery sweep errored"
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
            // Reap orphaned jobs ONCE at startup: background-job closures
            // run in the hyperion-web process, so a web restart/redeploy
            // (or a panicking closure / failed JobFinish) leaves the row
            // stuck in `running` forever — the /jobs card spins, the
            // sidebar badge over-counts, and retry is permanently blocked
            // ("job is still running"). The reaper marks rows whose
            // updated_at is older than the stale threshold as failed.
            // JobReporter::step bumps updated_at, so a genuinely-live job
            // is never reaped.
            const JOB_STALE_SECS: i64 = 3600; // 1h with no progress update
            if let Ok(n) = tick_svc.jobs_reap_stale(JOB_STALE_SECS).await {
                if n > 0 {
                    tracing::warn!(rows = n, "startup: reaped stale jobs");
                }
            }
            // Re-apply persisted IP bans to nftables ONCE at startup —
            // nft sets are in-memory and lost across reboots.
            match tick_svc.bans_reapply_on_boot().await {
                Ok(n) if n > 0 => tracing::info!(bans = n, "startup: re-applied IP bans"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error=%e, "startup: ban re-apply failed"),
            }
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                match tick_svc.scheduler_tick().await {
                    Ok(n) if n > 0 => tracing::info!(processed = n, "scheduler tick"),
                    Ok(_) => tracing::debug!("scheduler tick: nothing due"),
                    Err(e) => tracing::warn!(error=%e, "scheduler tick failed"),
                }
                // Also sweep stale jobs each tick (cheap UPDATE).
                if let Ok(n) = tick_svc.jobs_reap_stale(JOB_STALE_SECS).await {
                    if n > 0 {
                        tracing::warn!(rows = n, "reaped stale jobs");
                    }
                }
                // Brute-force scan + auto-ban each tick.
                match tick_svc.fail2ban_tick().await {
                    Ok(n) if n > 0 => tracing::info!(banned = n, "fail2ban: new bans"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error=%e, "fail2ban tick failed"),
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
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
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
                                matches!(r.outcome, hyperion_types::CertRenewOutcome::Failed { .. })
                            })
                            .count();
                        tracing::info!(due = results.len(), renewed, failed, "cert renewal tick");
                    }
                    Ok(_) => tracing::debug!("cert renewal tick: nothing due"),
                    Err(e) => tracing::warn!(error=%e, "cert renewal tick failed"),
                }
                interval.tick().await;
            }
        });
    }
    // WordPress defender sweep — once per day. Scans every active WP
    // hosting for outdated plugins/themes (keyless — via wp-cli's own
    // update status), auto-applies safe minor/patch updates when enabled,
    // stores the result for the cluster dashboard, and notifies admins
    // about NEW major updates needing manual review.
    {
        let vuln_svc = svc.clone();
        tokio::spawn(async move {
            // 4-minute offset so it doesn't collide with the cert-renew
            // tick (3 min) or the boot ticks.
            tokio::time::sleep(std::time::Duration::from_secs(240)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
            interval.tick().await; // immediate-first-tick consumption
            loop {
                match vuln_svc.wp_vuln_scan_tick().await {
                    Ok(n) if n > 0 => tracing::info!(new_majors = n, "wp defender tick"),
                    Ok(_) => tracing::debug!("wp defender tick: no new major updates"),
                    Err(e) => tracing::warn!(error=%e, "wp defender tick failed"),
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
        // Loop exits cleanly once we're enrolled AND no fresh invite_token
        // remains. A non-blank token on an already-enrolled node is the
        // Block B re-enroll trigger (see ensure_enrolled) — let it through
        // so enroll_now can present our existing identity for id reuse.
        tokio::spawn(async move {
            let mut consecutive_failures = 0u32;
            loop {
                if enr.state_file.exists() && enr.token.trim().is_empty() {
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
        // Same cert the inbound listener serves — the heartbeat reports
        // its SPKI pin so the master can detect cert changes (Block C).
        let inbound_cert = cfg.remote_rpc.tls_cert_file.clone();
        tokio::spawn(async move {
            enroll::heartbeat_loop(path, 60, verify, inbound_cert).await;
        });
    }

    // `with_version` stamps the build-time git SHA (see agent_version) so
    // /install + the connectivity test see the actual deployed revision.
    let agent_version: String = agent_version();
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
