//! `hyperion-agent` — the privileged daemon.

// Doc-formatting style lints we accept crate-wide.
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

mod acme_dns;
mod boot;
mod config;
mod enroll;
mod inbound_rpc;
mod ticks;

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

    /// One-shot subcommand (the daemon runs when none is given).
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Export an in-place source panel (CloudPanel / HestiaCP) to a portable
    /// bundle for offline import. Run on the SOURCE box as root/sudo — no
    /// agent.toml or Hyperion install is needed there. Hand the resulting tar to
    /// Hyperion (Import → Upload bundle); no inbound SSH/root to the source.
    ExportBundle {
        /// `cloudpanel` | `hestiacp`. Auto-detected if omitted.
        #[arg(long)]
        kind: Option<String>,
        /// Output bundle path, e.g. /root/hyperion-bundle.tar (`-` = stdout).
        #[arg(long, default_value = "-")]
        out: PathBuf,
        /// Export only these domains (comma-separated). Default: every site.
        #[arg(long)]
        only: Option<String>,
        /// Dry run: print the sites that WOULD be exported and pack nothing.
        #[arg(long)]
        list: bool,
        /// With --list, emit the site list as JSON (interactive wizard).
        #[arg(long)]
        json: bool,
    },
}

/// `export-bundle`: detect + extract the local source panel, then pack docroots,
/// DB dumps, and the IR manifest into one portable tar for offline import.
async fn run_export_bundle(
    kind: Option<String>,
    out: PathBuf,
    only: Option<String>,
    list: bool,
    json: bool,
) -> anyhow::Result<()> {
    // Delegate to the shared driver (also used by the standalone hyperion-export
    // binary the wizard serves). All messages go to stderr; stdout may be the tar.
    let n = hyperion_import::export::run(kind.as_deref(), &out, only.as_deref(), list, json)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if list {
        eprintln!("✓ dry run — {n} site(s) would be exported.");
    } else if out.as_os_str() == "-" {
        eprintln!("✓ streamed bundle — {n} site(s).");
    } else {
        eprintln!("✓ wrote {n} site(s) to {}.", out.display());
    }
    Ok(())
}

/// Apply the embedded migrations to a throwaway copy of the real state DB and
/// report whether they succeed. Exits the process (0 ok / 1 fail).
async fn dry_run_migrations(real_db: &std::path::Path) -> anyhow::Result<()> {
    // Staged NEXT TO the real database, never in /tmp.
    //
    // /tmp is world-writable, `create_dir_all` succeeds on a pre-existing
    // directory whatever its owner or mode, and `fs::copy` opens the
    // destination O_CREAT|O_TRUNC, FOLLOWING a symlink. So any local user —
    // on this product, any tenant with shell or PHP on the node — could
    // pre-create /tmp/hyperion-migcheck-<pid> (the pid is guessable, and they
    // can simply create many) holding a symlink named `state.db`, and have
    // root write the entire panel database through it: argon2 password
    // hashes, live session rows, TOTP secrets, API keys. Their own directory
    // is not sticky and they own the symlink, which is exactly why
    // fs.protected_symlinks does not stop it.
    //
    // The database's own directory is root-owned and 0700, so nothing can be
    // planted there in the first place. `create_dir` — not `create_dir_all` —
    // so a directory that somehow already exists is an error rather than
    // something we adopt.
    let parent = real_db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("/var/lib/hyperion"));
    tokio::fs::create_dir_all(parent).await?;
    let dir = parent.join(format!("migcheck-{}", std::process::id()));
    // A leftover from a run that was killed before its cleanup. Removing it
    // is safe HERE precisely because this directory is not world-writable.
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .await?;
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
        // Log to STDERR, never stdout. The daemon doesn't care (journald
        // captures both), but `export-bundle --out -` streams the bundle tar to
        // stdout — any log line on stdout would corrupt it ("not a tar
        // archive"). Keeping logs on stderr guarantees a clean tar stream.
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,lm=debug")),
        )
        .init();

    let cli = Cli::parse();

    // `export-bundle` runs standalone on a SOURCE panel box that has no
    // agent.toml — handle it BEFORE loading the agent config.
    if let Some(Command::ExportBundle {
        kind,
        out,
        only,
        list,
        json,
    }) = cli.command
    {
        return run_export_bundle(kind, out, only, list, json).await;
    }

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

    // Say so at BOOT if this unit cannot write /usr, rather than letting
    // the operator discover it from a wall of dpkg output the first time
    // they enable DKIM or install a service. The message tells systemd's
    // ProtectSystem= sandbox (the usual cause, invisible from the
    // operator's shell) apart from a genuinely read-only disk.
    if let Some(msg) = hyperion_core::check_usr_writable().await {
        tracing::warn!("boot: {msg}");
    }

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
        // Give the adapter the local state DB + agent.toml path so
        // nginx_write_vhost can emit the internal-preview server block
        // when this node carries a `*.<base>` wildcard cert.
        state_pool: Some(pool.clone()),
        agent_config_path: Some(cli.config.clone()),
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
    // Blank ⇒ the adapter's defaults (ipv4, kernel's choice of source
    // address), so a node whose agent.toml predates these keys still gets
    // the deliverability-safe policy.
    boot::spawn_postfix_config(
        email_cfg.clone(),
        hyperion_core::PostfixDirectDeliveryOpts {
            inet_protocols: Some(cfg.email.inet_protocols.clone()).filter(|s| !s.trim().is_empty()),
            bind_address: Some(cfg.email.bind_address.clone()).filter(|s| !s.trim().is_empty()),
        },
        cfg.email.message_size_limit_mb,
    );
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

    // Node RESPONSE-signing key — the mirror image of the key above.
    // That one authenticates requests master→node; this one
    // authenticates the answers node→master, so an on-path attacker
    // on the RPC connection can no longer forge a reply (substitute
    // a reset password, fake a provisioning success).
    //
    // Deliberately a SEPARATE key file, not master-rpc.key: on a
    // worker that file holds a locally generated key the master has
    // never seen, so a response signed with it would verify against
    // nothing. Not the inbound TLS key either — that one is
    // self-signed and unverified by design.
    //
    // A load failure is not fatal: the master accepts unsigned
    // responses from any node it has no pubkey for (rolling-upgrade
    // compatibility), so a broken key file degrades this node to the
    // old unauthenticated behaviour instead of taking it offline.
    let node_rpc_key_path = PathBuf::from(hyperion_core::node_rpc::NODE_RPC_KEY_PATH);
    let node_rpc_signer =
        match hyperion_core::node_rpc::NodeRpcSigner::load_or_init(&node_rpc_key_path) {
            Ok(s) => {
                tracing::info!(path=%node_rpc_key_path.display(), "response-signing key ready");
                Some(Arc::new(s))
            }
            Err(e) => {
                tracing::warn!(
                    error=%e,
                    path=%node_rpc_key_path.display(),
                    "node_rpc response-signing key unavailable — responses will be unsigned"
                );
                None
            }
        };
    // Advertised to the master at enrollment AND on every heartbeat.
    // Derived once, here, from the very key that will do the signing —
    // so what we advertise and what we sign with can never drift
    // apart, and the master's capability check (does it hold a pubkey
    // for us?) flips at the same moment we start signing.
    let resp_pubkey: Option<String> = node_rpc_signer.as_ref().map(|s| s.pubkey_b64().to_string());

    // The agent's enrollment state file path. Service checks its
    // existence at services_health() time as the "is this a worker?"
    // signal (workers have the file → hyperion-web is a non-issue;
    // master doesn't → hyperion-web is critical). Same path used by
    // the heartbeat loop + AgentImpl::with_state_file below.
    let state_file = cfg
        .enrollment
        .state_file
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/hyperion/node-id.json"));

    // Keep a handle to the adapter for the boot-time preview-shim
    // reconcile below; `HostingService::new` takes ownership of the Arc.
    let adapter_for_shims = adapter.clone();
    let mut builder = hyperion_core::HostingService::new(pool, adapter, secrets)
        .with_paths(paths)
        .with_remote_backup(remote_backup)
        .with_retention(retention)
        .with_slack_webhook(slack_webhook)
        .with_acme_email(cfg.acme.contact_email.clone())
        .with_email(email_cfg, email_to)
        .with_fail2ban(
            hyperion_core::Fail2banConfig {
                enabled: cfg.fail2ban.enabled,
                window_secs: cfg.fail2ban.window_secs,
                ban_ttl_secs: cfg.fail2ban.ban_ttl_secs,
                repeat_ttl_secs: cfg.fail2ban.repeat_ttl_secs,
                repeat_lookback_secs: cfg.fail2ban.repeat_lookback_secs,
                http_threshold: cfg.fail2ban.http_threshold,
                ssh_threshold: cfg.fail2ban.ssh_threshold,
                ftp_threshold: cfg.fail2ban.ftp_threshold,
                mail_threshold: cfg.fail2ban.mail_threshold,
                waf_threshold: cfg.fail2ban.waf_threshold,
            }
            .sanitized(),
        )
        .with_permissions_autoheal(cfg.permissions.enabled)
        .with_snapshots(cfg.snapshots.enabled)
        .with_agent_config_path(cli.config.clone())
        .with_node_state_file(state_file.clone())
        .with_git_sha(env!("HYPERION_GIT_SHA"));
    if let Some(signer) = master_rpc_signer {
        builder = builder.with_master_rpc_signer(signer);
    }
    let svc = Arc::new(builder);

    boot::spawn_repairs(&svc, adapter_for_shims);
    ticks::spawn_all(&svc, cfg.acme.renewal_window_days);

    spawn_cluster_link(&cfg, &cli.config, &state_file, resp_pubkey);

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
                    node_rpc_signer.clone(),
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

/// Join the cluster: the one-shot enrollment with the master (if configured
/// and not yet done) and the periodic heartbeat (60s, a no-op until
/// enrolled).
fn spawn_cluster_link(
    cfg: &config::Config,
    config_path: &std::path::Path,
    state_file: &std::path::Path,
    resp_pubkey: Option<String>,
) {
    if !cfg.enrollment.master_url.is_empty() && !cfg.enrollment.invite_token.is_empty() {
        let enr = enroll::EnrollmentConfig {
            master_url: cfg.enrollment.master_url.clone(),
            token: cfg.enrollment.invite_token.clone(),
            label: if cfg.enrollment.node_label.is_empty() {
                hostname_or_unknown()
            } else {
                cfg.enrollment.node_label.clone()
            },
            state_file: state_file.to_path_buf(),
            verify_tls: cfg.enrollment.verify_tls,
            config_file: Some(config_path.to_path_buf()),
            advertise_addr: {
                let a = cfg.remote_rpc.advertise_addr.trim();
                (!a.is_empty()).then(|| a.to_string())
            },
            resp_pubkey: resp_pubkey.clone(),
            rpc_port: enroll::rpc_port_from_bind(cfg.remote_rpc.enabled, &cfg.remote_rpc.bind),
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
        let path = state_file.to_path_buf();
        let verify = cfg.enrollment.verify_tls;
        // Same cert the inbound listener serves — the heartbeat reports
        // its SPKI pin so the master can detect cert changes (Block C).
        let inbound_cert = cfg.remote_rpc.tls_cert_file.clone();
        // Response-signing pubkey, re-advertised every tick. Nodes that
        // were enrolled before this existed get pinned on their next
        // heartbeat without needing a re-enrollment.
        let hb_resp_pubkey = resp_pubkey;
        // Re-reported every tick so a changed bind port reaches the master
        // without a re-enrollment.
        let rpc_port = enroll::rpc_port_from_bind(cfg.remote_rpc.enabled, &cfg.remote_rpc.bind);
        let advertise = {
            let a = cfg.remote_rpc.advertise_addr.trim();
            (!a.is_empty()).then(|| a.to_string())
        };
        tokio::spawn(async move {
            enroll::heartbeat_loop(
                path,
                60,
                verify,
                inbound_cert,
                hb_resp_pubkey,
                rpc_port,
                advertise,
            )
            .await;
        });
    }
}
