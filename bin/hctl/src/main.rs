//! `hctl` — unprivileged CLI client (hyperion control).

use clap::{Parser, Subcommand};
use hyperion_rpc::codec::{Request, Response};
use hyperion_rpc::wire::{DeleteOpts, HostingCreateReq, HostingSelector};
use hyperion_types::{DbProvision, HostingId, HostingLimits, PhpVersion, SuspendReason};
use hyperion_validate::{Domain, SystemUserName};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(name = "hctl", version, about = "hyperion CLI")]
struct Cli {
    /// Path to hyperion-agent's Unix socket.
    #[arg(long, default_value = "/run/hyperion.sock")]
    socket: PathBuf,
    /// Emit JSON instead of a human-friendly table.
    #[arg(long)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print agent info.
    Info,
    /// Hosting management.
    #[command(subcommand)]
    Hosting(HostingCmd),
    /// Certificate management.
    #[command(subcommand)]
    Cert(CertCmd),
    /// Print recent audit log entries.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
}

#[derive(Subcommand, Debug)]
enum HostingCmd {
    /// Create a new hosting.
    Create {
        domain: String,
        #[arg(long = "alias", value_name = "DOMAIN")]
        aliases: Vec<String>,
        /// PHP version (8.1 | 8.2 | 8.3 | 8.4). Omit for a static site.
        #[arg(long)]
        php: Option<String>,
        /// Database engine (mariadb | postgres). Omit for no DB.
        #[arg(long)]
        db: Option<String>,
        /// Override system user (default: derived from domain).
        #[arg(long)]
        user: Option<String>,
    },
    /// List all hostings.
    List,
    /// Get detail for a hosting (by id or domain).
    Get { selector: String },
    /// Delete a hosting (by id or domain).
    Delete {
        selector: String,
        #[arg(long)]
        keep_user: bool,
        #[arg(long)]
        keep_db: bool,
    },
    /// Suspend a hosting (best-effort cascade).
    Suspend {
        selector: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Resume a previously suspended hosting.
    Resume { selector: String },
    /// Update per-hosting PHP / DB / disk / bandwidth limits.
    SetLimits {
        selector: String,
        #[arg(long)]
        php_memory_mb: Option<i64>,
        #[arg(long)]
        php_max_exec_secs: Option<i64>,
        #[arg(long)]
        php_max_children: Option<i64>,
        #[arg(long)]
        php_max_requests: Option<i64>,
        #[arg(long)]
        db_max_connections: Option<i64>,
        #[arg(long)]
        disk_hard_bytes: Option<i64>,
        #[arg(long)]
        bw_monthly_bytes: Option<i64>,
    },
    /// Show current limits for a hosting.
    GetLimits { selector: String },
    /// Show recent usage observations for a hosting.
    Usage {
        selector: String,
        #[arg(long, default_value_t = 24)]
        limit: i64,
    },
    /// Export a hosting as a migration bundle (archive + manifest)
    /// on this node's disk. The bundle lives at
    /// /var/lib/hyperion/migration/<bundle_id>/. Transfer it to the
    /// target node out-of-band, then `hctl hosting import` there.
    Export { selector: String },
    /// Import a migration bundle produced by `hosting export` on
    /// another node. The manifest's sibling archive.tar.gz must be
    /// in the same directory. Re-creates the hosting from scratch
    /// (re-issues the cert; never copies private keys across nodes)
    /// and restores the archive + DB dump.
    Import {
        /// Path to manifest.json on this node's disk.
        #[arg(long)]
        manifest: String,
    },
    /// Import a migration bundle directly from a source node's
    /// signed URL. Equivalent to `Import` but downloads the bundle
    /// from the source's `/api/migration/bundle/<id>` instead of
    /// requiring scp/rsync.
    ///
    /// Example:
    ///   hctl hosting import-from-url \
    ///     --base-url=https://source.example.com/api/migration/bundle/mig_abc \
    ///     --token=AAAA.BBBB
    ImportFromUrl {
        /// Base URL printed by `hosting export` on the source.
        #[arg(long = "base-url")]
        base_url: String,
        /// Signed token from the source's export response. Expires
        /// 1h after the export — re-export on the source if stale.
        #[arg(long)]
        token: String,
    },
}

#[derive(Subcommand, Debug)]
enum CertCmd {
    /// Renew all expiring certs.
    RenewAll,
    /// Issue a cert for a single domain (administrative).
    Issue { domain: String },
}

fn parse_selector(s: &str) -> anyhow::Result<HostingSelector> {
    if s.contains('.') {
        Ok(HostingSelector::Domain(Domain::parse(s)?))
    } else {
        Ok(HostingSelector::Id(HostingId(s.to_string())))
    }
}

fn build_create(
    domain: String,
    aliases: Vec<String>,
    php: Option<String>,
    db: Option<String>,
    user: Option<String>,
) -> anyhow::Result<HostingCreateReq> {
    let domain = Domain::parse(&domain)?;
    let aliases = aliases
        .into_iter()
        .map(|a| Domain::parse(&a))
        .collect::<Result<Vec<_>, _>>()?;
    let php_version = php
        .as_deref()
        .map(PhpVersion::from_str)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let database = db
        .as_deref()
        .map(DbProvision::from_str)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let system_user = user.as_deref().map(SystemUserName::parse).transpose()?;
    Ok(HostingCreateReq {
        domain,
        aliases,
        php_version,
        database,
        system_user,
        kind: "php".into(),
        proxy_upstream_url: None,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let resp = call(&cli).await?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        print_pretty(&resp);
    }
    if let Response::Error(_) = resp {
        std::process::exit(1);
    }
    Ok(())
}

async fn call(cli: &Cli) -> anyhow::Result<Response> {
    let req = match &cli.cmd {
        Cmd::Info => Request::AgentInfo,
        Cmd::Hosting(HostingCmd::Create {
            domain,
            aliases,
            php,
            db,
            user,
        }) => {
            let r = build_create(
                domain.clone(),
                aliases.clone(),
                php.clone(),
                db.clone(),
                user.clone(),
            )?;
            Request::HostingCreate(r)
        }
        Cmd::Hosting(HostingCmd::List) => Request::HostingList,
        Cmd::Hosting(HostingCmd::Get { selector }) => {
            Request::HostingGet(parse_selector(selector)?)
        }
        Cmd::Hosting(HostingCmd::Delete {
            selector,
            keep_user,
            keep_db,
        }) => Request::HostingDelete {
            sel: parse_selector(selector)?,
            opts: DeleteOpts {
                keep_user: *keep_user,
                keep_database: *keep_db,
            },
        },
        Cmd::Hosting(HostingCmd::Suspend { selector, reason }) => Request::HostingSuspend {
            sel: parse_selector(selector)?,
            reason: SuspendReason::Manual {
                message: reason.clone(),
            },
        },
        Cmd::Hosting(HostingCmd::Resume { selector }) => {
            Request::HostingResume(parse_selector(selector)?)
        }
        Cmd::Hosting(HostingCmd::SetLimits {
            selector,
            php_memory_mb,
            php_max_exec_secs,
            php_max_children,
            php_max_requests,
            db_max_connections,
            disk_hard_bytes,
            bw_monthly_bytes,
        }) => {
            let mut l = HostingLimits::defaults();
            if let Some(v) = php_memory_mb {
                l.php_memory_mb = *v;
            }
            if let Some(v) = php_max_exec_secs {
                l.php_max_exec_secs = *v;
            }
            if let Some(v) = php_max_children {
                l.php_max_children = *v;
            }
            if let Some(v) = php_max_requests {
                l.php_max_requests = *v;
            }
            if let Some(v) = db_max_connections {
                l.db_max_connections = *v;
            }
            if let Some(v) = disk_hard_bytes {
                l.disk_hard_bytes = Some(*v);
            }
            if let Some(v) = bw_monthly_bytes {
                l.bw_monthly_bytes = Some(*v);
            }
            Request::HostingSetLimits {
                sel: parse_selector(selector)?,
                limits: l,
            }
        }
        Cmd::Hosting(HostingCmd::GetLimits { selector }) => {
            Request::HostingGetLimits(parse_selector(selector)?)
        }
        Cmd::Hosting(HostingCmd::Usage { selector, limit }) => Request::HostingUsage {
            sel: parse_selector(selector)?,
            limit: *limit,
        },
        Cmd::Hosting(HostingCmd::Export { selector }) => Request::HostingExport {
            hosting: parse_selector(selector)?,
        },
        Cmd::Hosting(HostingCmd::Import { manifest }) => Request::HostingImport {
            manifest_path: manifest.clone(),
        },
        Cmd::Hosting(HostingCmd::ImportFromUrl { base_url, token }) => {
            Request::HostingImportFromUrl {
                base_url: base_url.clone(),
                token: token.clone(),
                override_domain: None,
                override_aliases: Vec::new(),
            }
        }
        Cmd::Audit { limit } => Request::AuditList { limit: *limit },
        Cmd::Cert(CertCmd::RenewAll) => Request::CertRenewAll,
        Cmd::Cert(CertCmd::Issue { domain }) => Request::CertIssue {
            domain: Domain::parse(domain)?,
        },
    };
    Ok(hyperion_rpc_client::call(&cli.socket, req).await?)
}

fn print_pretty(resp: &Response) {
    match resp {
        Response::AgentInfo(i) => {
            println!(
                "agent:  {} version={} hostings={}",
                i.hostname, i.version, i.hostings_count
            );
            // Enrollment block — answers "did this node phone home to
            // the master OK?" without SSHing in to cat node-id.json.
            match (&i.node_id, &i.master_url) {
                (Some(node_id), Some(master_url)) => {
                    let when = i.enrolled_at
                        .map(|t| format!("unix:{t}"))
                        .unwrap_or_else(|| "?".into());
                    println!("node:   {node_id} → {master_url} (enrolled {when})");
                }
                _ => {
                    println!(
                        "node:   NOT ENROLLED — check /etc/hyperion/agent.toml [enrollment] \
                         and `journalctl -u hyperion-agent | grep -i enroll`"
                    );
                }
            }
        }
        Response::HostingCreate(c) => {
            println!("✓ created {} (id={})", c.system_user, c.id);
            println!("  root: {}", c.root_dir);
            if let Some(db) = &c.db {
                println!(
                    "  db:   {} (user={}, password={})",
                    db.db_name, db.db_user, db.password
                );
            }
            if let Some(cert) = &c.cert {
                println!(
                    "  cert: issuer={}, not_after={}",
                    cert.issuer, cert.not_after
                );
            }
        }
        Response::HostingList(rows) => {
            println!("{:<28} {:<14} {:<6} {:<10}", "DOMAIN", "ID", "PHP", "STATE");
            for r in rows {
                println!(
                    "{:<28} {:<14} {:<6} {:<10}",
                    r.domain,
                    short(&r.id.0),
                    r.php_version.map(|v| v.as_str()).unwrap_or("-"),
                    r.state.as_str()
                );
            }
        }
        Response::HostingGet(d) => {
            println!("{}  ({})", d.domain, d.id);
            println!("  state:       {}", d.state.as_str());
            println!("  system user: {}", d.system_user);
            if let Some(v) = d.php_version {
                println!("  PHP:         {}", v.as_str());
            }
            println!("  root:        {}", d.root_dir);
            if !d.aliases.is_empty() {
                println!("  aliases:     {}", d.aliases.join(", "));
            }
            if let Some(db) = &d.database {
                println!("  db:          {} (user={})", db.db_name, db.db_user);
            }
            if let Some(cert) = &d.cert {
                println!(
                    "  cert:        {} (not_after={})",
                    cert.issuer, cert.not_after
                );
            }
        }
        Response::HostingDelete => {
            println!("✓ deleted");
        }
        Response::HostingSetLimits(l) | Response::HostingGetLimits(l) => {
            println!("limits:");
            println!("  php_memory_mb       = {}", l.php_memory_mb);
            println!("  php_max_exec_secs   = {}", l.php_max_exec_secs);
            println!("  php_max_children    = {}", l.php_max_children);
            println!("  php_max_requests    = {}", l.php_max_requests);
            println!("  db_max_connections  = {}", l.db_max_connections);
            println!(
                "  disk_hard_bytes     = {}",
                l.disk_hard_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!(
                "  bw_monthly_bytes    = {}",
                l.bw_monthly_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!("  over_bw_policy      = {}", l.over_bw_policy.as_str());
        }
        Response::HostingSuspend => println!("✓ suspended"),
        Response::HostingResume => println!("✓ resumed"),
        Response::HostingSetPhpVersion(v) => println!("✓ PHP version set to {v}"),
        Response::MtaDiagnostics(d) => {
            println!("mode             {}", d.mode);
            println!("sendmail exec    {}", d.sendmail_executable);
            println!("service active   {}", d.service_active);
            println!("service enabled  {}", d.service_enabled);
            println!("myhostname       {}", d.myhostname);
            println!("myhostname FQDN  {}", d.myhostname_is_fqdn);
            println!("relayhost        {}", if d.relayhost.is_empty() { "(direct MX)" } else { d.relayhost.as_str() });
            println!("mailq            {}", d.mailq_summary);
            if !d.recent_log_tail.is_empty() {
                println!("recent log tail:");
                for line in d.recent_log_tail.iter() {
                    println!("  {line}");
                }
            }
        }
        Response::MtaReconfigure { mode } => println!("✓ postfix reconfigured: {mode}"),
        Response::MtaTestSend { exit_code, output } => {
            if *exit_code == 0 {
                println!("✓ sendmail queued the message (exit 0)");
            } else {
                println!("✗ sendmail exit {exit_code}");
                if !output.is_empty() {
                    println!("{output}");
                }
            }
        }
        Response::MtaQueueFlush { attempted, output } => {
            println!("✓ queue flush requested · {attempted} message(s) still in queue after flush");
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Response::MtaQueueClear { cleared, output } => {
            println!("✓ queue clear · {cleared} message(s) discarded");
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Response::PanelProvision { status, message, panel_url } => {
            println!("status: {status}");
            if !panel_url.is_empty() {
                println!("panel:  {panel_url}");
            }
            println!("{message}");
        }
        Response::PanelCertStatus(snap) => match snap {
            None => println!("panel cert: no issuance in progress"),
            Some(p) => {
                println!("panel:    {}", p.hostname);
                println!("stage:    {}", p.stage);
                println!("message:  {}", p.message);
                if p.not_after > 0 {
                    println!("not_after: {} (unix)", p.not_after);
                }
            }
        },
        Response::RemountUsrRw { success, message } => {
            if *success {
                println!("✓ /usr is now writable");
            } else {
                println!("✗ remount failed");
            }
            if !message.is_empty() {
                println!("{message}");
            }
        }
        Response::TrashList(entries) => {
            println!("{:<32} {:<14} {:<14} NODE", "DOMAIN", "TRASHED_AT", "PURGE_IN");
            for e in entries.iter() {
                println!(
                    "{:<32} {:<14} {:<14} {}",
                    e.domain, e.trashed_at, e.seconds_remaining, e.node_id
                );
            }
        }
        Response::TrashRestore => println!("✓ restored"),
        Response::TrashPurge => println!("✓ purged"),
        Response::FtpAccountsList(accounts) => {
            println!("{:<24} {:<28} {:<10} STATUS", "USER", "DOMAIN", "STATE");
            for a in accounts.iter() {
                println!(
                    "{:<24} {:<28} {:<10} {}",
                    a.user,
                    a.domain,
                    a.hosting_state,
                    if a.has_password { "set" } else { "disabled" }
                );
            }
        }
        Response::FtpVerifyLogin { accepted } => {
            if *accepted {
                println!("✓ FTP login OK");
            } else {
                println!("✗ FTP login refused (530)");
            }
        }
        Response::SiteEmailLogList(entries) => {
            println!("{:<14} {:<28} {:<28} SUBJECT", "TS", "FROM", "TO");
            for e in entries.iter() {
                println!(
                    "{:<14} {:<28} {:<28} {}",
                    e.ts, e.from_address, e.to_address, e.subject
                );
            }
        }
        Response::HostingSetVhostOptions(o) => {
            println!("✓ vhost options applied");
            println!("  basic_auth_enabled  = {}", o.basic_auth_enabled);
            println!("  basic_auth_user     = {}", o.basic_auth_user);
            println!("  basic_auth_set      = {}", o.basic_auth_set);
            println!("  force_https         = {}", o.force_https);
            println!("  hsts_max_age        = {}", o.hsts_max_age);
            println!("  maintenance_mode    = {}", o.maintenance_mode);
            println!("  fastcgi_cache       = {}", o.fastcgi_cache_enabled);
            println!("  fastcgi_cache_ttl   = {}", o.fastcgi_cache_ttl);
            println!("  custom_snippet_len  = {}", o.custom_nginx_snippet.len());
            println!("  redirect_url        = {}", o.redirect_url);
            println!("  redirect_code       = {}", o.redirect_code);
            println!("  redirect_preserve   = {}", o.redirect_preserve_path);
        }
        Response::HostingSetWpDebug(e)
        | Response::HostingSetRedis(e)
        | Response::HostingRotateRedisPassword(e) => {
            println!("✓ WP extras applied");
            println!("  wp_debug_enabled    = {}", e.wp_debug_enabled);
            println!("  wp_debug_log        = {}", e.wp_debug_log);
            println!("  wp_debug_display    = {}", e.wp_debug_display);
            println!("  debug_log_size_bytes= {}", e.wp_debug_log_size_bytes);
            println!("  redis_enabled       = {}", e.redis_enabled);
            println!(
                "  redis_db_number     = {}",
                e.redis_db_number
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!("  redis_password_set  = {}", e.redis_password_set);
        }
        Response::HostingRotateWpDebugLog => println!("✓ debug.log rotated"),
        Response::NotificationsFeed(f) => {
            println!("unread total: {}", f.unread_total);
            for n in &f.items {
                let mark = if n.read_at.is_some() { " " } else { "•" };
                println!(
                    "  [{}] {:>5} {} {:<8} {}",
                    mark, n.id, n.created_at, n.severity, n.title
                );
                if !n.body.is_empty() {
                    println!("           {}", n.body);
                }
            }
        }
        Response::NotificationsMarkRead => println!("✓ marked read"),
        Response::NotificationsMarkAllRead { marked } => {
            println!("✓ marked {marked} notifications read");
        }
        Response::HostingFileDownload { rel_path, bytes_b64, mime } => {
            println!("✓ downloaded {rel_path} ({mime}, {} bytes b64)", bytes_b64.len());
        }
        Response::HostingFileWrite => println!("✓ file written"),
        Response::HostingFileDelete => println!("✓ file deleted"),
        Response::HostingFileMkdir => println!("✓ directory created"),
        Response::HostingFileRename => println!("✓ renamed"),
        Response::HostingMigrationFetchBundleFile { bytes_b64 } => {
            println!("✓ fetched bundle file ({} bytes b64)", bytes_b64.len());
        }
        Response::AvatarFilename(f) => match f {
            Some(name) => println!("avatar: {name}"),
            None => println!("avatar: (none)"),
        },
        Response::AvatarSet => println!("✓ avatar updated"),
        Response::EmailChangeRequest { masked_to } => {
            println!("✓ verification code sent to {masked_to}");
        }
        Response::EmailChangeConfirm => println!("✓ email changed"),
        Response::EmailChangeCancel => println!("✓ pending email change cancelled"),
        Response::MonitorOverview(items) => {
            println!(
                "{:<32} {:<10} {:>5} {:>7} {:>4} {}",
                "DOMAIN", "STATE", "SUCC%", "AVG_MS", "SAMP", "NODE"
            );
            for it in items.iter() {
                println!(
                    "{:<32} {:<10} {:>5} {:>7} {:>4} {}",
                    it.domain,
                    it.alert_state,
                    it.success_pct_24h,
                    it.avg_response_ms_24h,
                    it.samples_24h,
                    it.node_id
                );
            }
        }
        Response::HostingUsage(rows) => {
            println!(
                "{:<14} {:>10} {:>10} {:>10} {:>10}",
                "PERIOD", "DISK", "BW IN", "BW OUT", "PHP REQ"
            );
            for r in rows {
                println!(
                    "{:<14} {:>10} {:>10} {:>10} {:>10}",
                    r.period, r.disk_used_bytes, r.bw_in_bytes, r.bw_out_bytes, r.php_requests
                );
            }
        }
        Response::AuditVerifyChain {
            ok,
            rows_checked,
            message,
        } => {
            if *ok {
                println!("audit chain OK ({rows_checked} rows verified)");
            } else {
                println!(
                    "audit chain BROKEN — {rows_checked} rows checked, error: {message}"
                );
            }
        }
        Response::AuditList(rows) => {
            println!(
                "{:>5} {:<19} {:<14} {:<22} {:<10}",
                "ID", "TS", "ACTOR", "ACTION", "RESULT"
            );
            for r in rows {
                println!(
                    "{:>5} {:<19} {:<14} {:<22} {:<10}",
                    r.id, r.ts, r.actor_label, r.action, r.result
                );
            }
        }
        Response::HostingSetExpiry(e) | Response::HostingGetExpiry(e) => {
            println!("expiry:");
            println!(
                "  expires_at = {}",
                e.expires_at
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "—".into())
            );
            println!(
                "  owner_email = {}",
                e.owner_email.as_deref().unwrap_or("—")
            );
            println!("  grace_days  = {}", e.grace_days);
            println!("  warnings    = {}", e.warning_offsets_days);
        }
        Response::HostingClearExpiry => println!("✓ cleared"),
        Response::HostingKvSet => println!("✓ saved"),
        Response::HostingKvList(pairs) => {
            for (k, v) in pairs {
                println!("{k} = {v}");
            }
        }
        Response::UpcomingExpiries(rows) => {
            println!("{:<24} {:>14} {:<25}", "DOMAIN", "EXPIRES AT", "OWNER");
            for r in rows {
                println!(
                    "{:<24} {:>14} {:<25}",
                    r.domain,
                    r.expires_at,
                    r.owner_email.as_deref().unwrap_or("—")
                );
            }
        }
        Response::SchedulerTick { actions_processed } => {
            println!("scheduler tick processed {} action(s)", actions_processed);
        }
        Response::BackupNow(r) => {
            println!("✓ backup {} {}", r.id, r.state);
            if let Some(p) = &r.archive_path {
                println!("  archive: {p}");
            }
            if let Some(p) = &r.db_dump_path {
                println!("  db_dump: {p}");
            }
            println!("  bytes:   {}", r.bytes_total);
        }
        Response::BackupList(rows) => {
            println!(
                "{:>4} {:<19} {:<8} {:>12} {}",
                "ID", "STARTED", "STATE", "BYTES", "ARCHIVE"
            );
            for r in rows {
                println!(
                    "{:>4} {:<19} {:<8} {:>12} {}",
                    r.id,
                    r.started_at,
                    r.state,
                    r.bytes_total,
                    r.archive_path.as_deref().unwrap_or("—")
                );
            }
        }
        Response::InviteCreate(m) => {
            println!(
                "✓ invite minted for '{}' (expires {})",
                m.label, m.expires_at
            );
            println!();
            println!("  Token (shown ONCE — copy it now):");
            println!("    {}", m.token);
            println!();
            println!("  Hash (use to revoke): {}", m.token_hash);
        }
        Response::InviteList(rows) => {
            println!(
                "{:<32} {:>12} {:>12} {}",
                "LABEL", "CREATED", "EXPIRES", "TOKEN HASH"
            );
            for r in rows {
                println!(
                    "{:<32} {:>12} {:>12} {}",
                    r.label, r.created_at, r.expires_at, r.token_hash
                );
            }
        }
        Response::InviteRevoke => println!("✓ invite revoked"),
        Response::CertIssue(c) => {
            println!("✓ issued {} (not_after={})", c.domain, c.not_after);
        }
        Response::CertRenewAll(rows) => {
            for r in rows {
                println!("{} -> {:?}", r.domain, r.outcome);
            }
        }
        Response::WpInstall(s) => {
            println!("✓ WordPress installed");
            println!("  site:    {}", s.site_url);
            println!("  version: {}", s.wp_version);
        }
        Response::WpStatus(maybe) => match maybe {
            Some(s) => {
                println!("site:    {}", s.site_url);
                println!("version: {}", s.wp_version);
                println!("at:      {}", s.installed_at);
            }
            None => println!("(no WordPress install on this hosting)"),
        },
        Response::DnsSpfCheck(s) => {
            println!("domain:    {}", s.domain);
            println!("status:    {}", s.status);
            println!("existing:  {:?}", s.existing);
            println!("suggested: {}", s.suggested);
        }
        Response::DnsCheck(c) => {
            println!("domain:   {}", c.domain);
            println!("A:        {:?}", c.resolved_a);
            println!("AAAA:     {:?}", c.resolved_aaaa);
            println!(
                "our v4:   {}",
                c.our_public_ipv4.as_deref().unwrap_or("?")
            );
            println!(
                "our v6:   {}",
                c.our_public_ipv6.as_deref().unwrap_or("?")
            );
            println!(
                "matches:  {}",
                if c.matches { "yes ✓" } else { "no ✗" }
            );
            println!("note:     {}", c.note);
        }
        Response::CertIssueAcme(c) => {
            println!("✓ certificate issued");
            println!("  issuer:    {}", c.issuer);
            println!("  not_after: {}", c.not_after);
            println!("  fp:        {}", c.fingerprint_sha256);
        }
        Response::HostingStats(s) => {
            println!("{}", s.domain);
            println!("  disk:     {} B", s.disk_bytes);
            println!("  bw_in:    {} B (24h)", s.bw_in_bytes_24h);
            println!("  bw_out:   {} B (24h)", s.bw_out_bytes_24h);
            println!("  requests: {} (24h)", s.requests_24h);
        }
        Response::NodeStats(n) => {
            println!("{} ({})", n.label, n.node_id);
            println!(
                "  hostings: {} (active={}, suspended={}, failed={})",
                n.hostings_count, n.hostings_active, n.hostings_suspended, n.hostings_failed
            );
            println!("  disk:     {} B total", n.total_disk_bytes);
            println!("  bw_out:   {} B (24h)", n.total_bw_out_24h);
            println!("  reqs:     {} (24h)", n.total_requests_24h);
            println!(
                "  load1:    {:.2}",
                n.loadavg_1m_x100 as f64 / 100.0
            );
            println!("  mem:      {} / {} kiB", n.mem_used_kib, n.mem_total_kib);
            println!("  uptime:   {}s", n.uptime_secs);
        }
        Response::ClusterStats(c) => {
            println!("nodes: {}", c.nodes.len());
            for n in &c.nodes {
                println!("  - {} ({}), {} hostings", n.label, n.node_id, n.hostings_count);
            }
            println!(
                "totals: hostings={} (active={}/susp={}/fail={}), disk={} B, bw_out_24h={} B",
                c.total_hostings,
                c.total_active,
                c.total_suspended,
                c.total_failed,
                c.total_disk_bytes,
                c.total_bw_out_24h
            );
        }
        Response::StatsTick { hostings_sampled } => {
            println!("✓ {} hostings sampled", hostings_sampled);
        }
        Response::BackupRestore => println!("✓ backup restored"),
        Response::HostingLogs(s) => print!("{s}"),
        Response::CronList(s) => print!("{s}"),
        Response::CronReplace => println!("✓ crontab updated"),
        Response::EnrollConsume {
            secret,
            master_rpc_pubkey,
        } => {
            println!("✓ node enrolled");
            println!("  secret: {secret}");
            if let Some(pk) = master_rpc_pubkey {
                println!("  master_rpc_pubkey: {pk}");
            }
        }
        Response::NodeHeartbeat { master_rpc_pubkey } => {
            print!("✓ heartbeat ok");
            if master_rpc_pubkey.is_some() {
                print!(" (master_rpc available)");
            }
            println!();
        }
        Response::NodesList(rows) => {
            for n in rows {
                println!(
                    "{}\t{}\tv{}\t{}",
                    n.node_id, n.label, n.agent_version, n.last_seen_at
                );
            }
        }
        Response::WpResetPassword => println!("✓ WordPress admin password reset"),
        Response::DbResetPassword => println!("✓ DB password reset (secret updated)"),
        Response::FtpSetPassword { password } => {
            println!("✓ FTP password set");
            println!("  password (shown once): {password}");
        }
        Response::FtpDisable => println!("✓ FTP disabled (password cleared)"),
        Response::ProfileList(rows) => {
            for p in rows {
                println!(
                    "{}\t{}\t{}",
                    p.id,
                    p.name,
                    p.pretty_price()
                );
            }
        }
        Response::ProfileGet(p) | Response::ProfileCreate(p) | Response::ProfileUpdate(p) => {
            println!("id:    {}", p.id);
            println!("name:  {}", p.name);
            println!("price: {}", p.pretty_price());
        }
        Response::ProfileDelete => println!("✓ profile deleted"),
        Response::ProfileApply(a) => {
            println!("✓ profile applied");
            if let Some(ts) = a.next_billing_at {
                println!("  next billing: {ts}");
            }
        }
        Response::ProfileWpItemInstalled { label, activated } => {
            println!(
                "✓ installed {label}{}",
                if *activated { " (activated)" } else { "" }
            );
        }
        Response::ProfileGetApply(maybe) => match maybe {
            Some(a) => {
                println!("profile_id: {:?}", a.profile_id);
                println!("price_minor: {:?}", a.price_minor);
                println!("next_billing_at: {:?}", a.next_billing_at);
            }
            None => println!("(no profile applied to this hosting)"),
        },
        Response::DashboardAlerts(alerts) => {
            if alerts.is_empty() {
                println!("(no alerts)");
            } else {
                for a in alerts {
                    println!(
                        "{}  {}  {}",
                        a.severity.to_uppercase(),
                        a.kind,
                        a.message
                    );
                }
            }
        }
        Response::Error(e) => {
            eprintln!("ERROR: {e}");
        }
        Response::NodeMetricsHistory(h) => {
            println!("metrics-history: {} samples", h.samples.len());
            for s in h.samples.iter().rev().take(20) {
                println!(
                    "  ts={} load={:.2} mem={}/{} hosts={}",
                    s.at,
                    s.loadavg_1m_x100 as f64 / 100.0,
                    s.mem_used_kib,
                    s.mem_total_kib,
                    s.hostings_count
                );
            }
        }
        Response::SetHostingAcmeEmail => {
            println!("acme email override updated");
        }
        Response::ServicesHealth(h) => {
            println!(
                "services health: {} critical down, {} optional down",
                h.critical_down, h.warn_down
            );
            for s in &h.services {
                println!(
                    "  [{}] {} active={} enabled={} sub={}",
                    s.severity, s.name, s.active, s.enabled, s.sub_state
                );
            }
        }
        Response::BackupDelete => {
            println!("backup deleted");
        }
        Response::FirewallList(v) => {
            println!("firewall backend: {}", v.backend);
            if !v.ports.is_empty() {
                println!("{:<8} {:<6} {:<10} {}", "PORT", "PROTO", "CATEGORY", "REASON");
                for p in &v.ports {
                    println!(
                        "{:<8} {:<6} {:<10} {}",
                        p.port, p.proto, p.category, p.label
                    );
                }
            }
            if !v.error.is_empty() {
                eprintln!("error: {}", v.error);
            }
            if !v.raw.is_empty() {
                println!("--- raw ---");
                println!("{}", v.raw);
            }
        }
        Response::FirewallTemplateApplied { applied, output, error } => {
            if *applied {
                println!("✓ template applied + persisted to /etc/nftables.conf");
            } else {
                eprintln!("✗ template apply failed");
            }
            if !output.is_empty() {
                println!("{output}");
            }
            if !error.is_empty() {
                eprintln!("error: {error}");
            }
        }
        Response::AgentConfigView(c) => {
            println!("agent: {} v{} (nginx user: {})",
                c.hostname, c.agent_version,
                if c.nginx_user.is_empty() { "unknown" } else { c.nginx_user.as_str() });
            println!("acme: contact={} challenge_dir={}",
                c.acme.contact_email, c.acme.challenge_dir);
            println!("email: enabled={} smtp={}:{} from={} security={}",
                c.email.enabled, c.email.smtp_host, c.email.smtp_port,
                c.email.from_address, c.email.security);
            println!("slack: webhook_set={}", c.slack.default_webhook_set);
            println!("backup_remote: enabled={} {}://{}@{}:{}{}",
                c.backup_remote.enabled, c.backup_remote.scheme,
                c.backup_remote.user, c.backup_remote.host,
                c.backup_remote.port, c.backup_remote.base_path);
            println!("backup_retention: max_age_days={} keep_latest_n={}",
                c.backup_retention.max_age_days, c.backup_retention.keep_latest_n);
        }
        Response::EmailSendTest { smtp_code } => {
            println!("test email sent — SMTP response: {smtp_code}");
        }
        Response::WebLogin(r) => match r {
            hyperion_types::WebLoginResult::Ok { user_id, username, role, .. } => {
                println!("login ok: id={user_id} user={username} role={role}");
            }
            hyperion_types::WebLoginResult::NeedsTotp { user_id, username } => {
                println!("needs 2FA: id={user_id} user={username}");
            }
            hyperion_types::WebLoginResult::Invalid => {
                println!("invalid credentials");
            }
            hyperion_types::WebLoginResult::Locked { reason } => {
                println!("locked: {reason}");
            }
        },
        Response::WebVerify2fa(r) => match r {
            hyperion_types::WebVerify2faResult::Ok { user_id, username, .. } => {
                println!("2FA ok: id={user_id} user={username}");
            }
            hyperion_types::WebVerify2faResult::Invalid => {
                println!("2FA invalid");
            }
        },
        Response::WebUserList(users) => {
            println!("{} users:", users.len());
            for u in users {
                println!(
                    "  id={} {} <{}> role={}{}{}",
                    u.id, u.username, u.email, u.role,
                    if u.totp_enrolled { " 2FA✓" } else { "" },
                    if u.locked { " LOCKED" } else { "" }
                );
            }
        }
        Response::WebUserGet(Some(u)) => {
            println!("user id={} {} <{}> role={}", u.id, u.username, u.email, u.role);
        }
        Response::WebUserGet(None) => {
            println!("user not found");
        }
        Response::WebUserCreate { id } => {
            println!("user created: id={id}");
        }
        Response::WebUserSetPassword => println!("password set"),
        Response::WebUserSetRole => println!("role set"),
        Response::WebUserSetLocked => println!("lock state changed"),
        Response::WebUserDelete => println!("user deleted"),
        Response::Web2faEnrollStart(e) => {
            println!("2FA enrollment started:");
            println!("  secret: {}", e.secret_base32);
            println!("  url:    {}", e.otpauth_url);
            println!("  backup codes (save NOW):");
            for c in &e.backup_codes {
                println!("    {}", c);
            }
        }
        Response::Web2faConfirmEnroll { ok } => {
            println!("2FA enrollment {}", if *ok { "confirmed" } else { "rejected" });
        }
        Response::Web2faDisable => println!("2FA disabled"),
        Response::WebGrantHostingAccess => println!("access granted"),
        Response::WebRevokeHostingAccess => println!("access revoked"),
        Response::WebListHostingAccess(rows) => {
            println!("{} grants:", rows.len());
            for r in rows {
                println!(
                    "  user={} ({}) {} level={}",
                    r.user_id, r.username, r.email, r.level
                );
            }
        }
        Response::HostingFileList { rel_path, entries } => {
            println!("{} ({} entries):", rel_path, entries.len());
            for e in entries {
                println!(
                    "  [{}] {:>10} {} {}",
                    e.kind, e.size, e.mime, e.name
                );
            }
        }
        Response::HostingFileRead(c) => {
            println!("{} ({} bytes, {}){}", c.rel_path, c.size, c.mime,
                if c.truncated { " — TRUNCATED" } else { "" });
            println!("---");
            println!("{}", c.content);
        }
        Response::MonitorGet { config, history } => {
            println!("monitor: enabled={} interval={}s alert_after={} state={}",
                config.enabled, config.interval_secs,
                config.alert_after_fails, config.alert_state);
            println!("samples (last {}):", history.samples.len());
            for s in history.samples.iter().rev().take(10) {
                println!("  ts={} ok={} status={:?} ms={}",
                    s.at, s.success, s.http_status, s.response_ms);
            }
        }
        Response::MonitorSet => println!("monitor config saved"),
        Response::MonitorProbeNow(s) => {
            println!("probe: ok={} status={:?} ms={}",
                s.success, s.http_status, s.response_ms);
        }
        Response::MonitorTick { sampled } => {
            println!("monitor tick: {sampled} hosting(s) sampled");
        }
        Response::ServiceRestart => println!("service restarted"),
        Response::ServiceInstall => println!("service installed"),
        Response::AgentConfigUpdate => println!("agent.toml updated"),
        Response::UpdateCheck(s) => {
            println!("update check:");
            println!("  current: {}", s.current_sha);
            println!("  latest:  {} (tag {})", s.latest_sha, s.latest_tag);
            println!("  status:  {}", s.message);
            if s.update_available {
                println!("  → run `sudo /opt/hyperion/packaging/install/update.sh` to upgrade");
            }
        }
        Response::WpPluginList(r) => {
            println!("WordPress {} — {} plugin(s), {} update(s) pending:",
                r.wp_version, r.plugins.len(), r.updates_pending);
            println!("{:<40} {:<10} {:<14} {:<20}", "SLUG", "STATUS", "VERSION", "LATEST");
            for p in &r.plugins {
                let latest = if p.update_available { &p.latest_version[..] } else { "-" };
                println!("{:<40} {:<10} {:<14} {:<20}", p.slug, p.status, p.version, latest);
            }
        }
        Response::WpPluginAction(r) => {
            println!("wp plugin action: {} — {}", r.state, r.message);
            if !r.output_tail.is_empty() {
                println!("--- tail ---");
                println!("{}", r.output_tail);
            }
        }
        Response::HostingExport(b) => {
            println!("migration bundle ready:");
            println!("  archive : {}", b.archive_path);
            println!("  manifest: {}", b.manifest_path);
            println!("  size    : {} bytes", b.archive_bytes);
            println!("  digest  : {}", b.archive_sha256);
            println!();
            println!("transfer to the target node, then on the target run:");
            println!("  sudo hctl hosting import --manifest {}", b.manifest_path);
            println!("(typical transfer: scp -r {} root@target:/var/lib/hyperion/migration/)",
                std::path::Path::new(&b.manifest_path).parent().map(|p| p.display().to_string()).unwrap_or_default());
        }
        Response::EmailLogList(rows) => {
            println!("{} email log entr{}:", rows.len(), if rows.len() == 1 { "y" } else { "ies" });
            for r in rows.iter().take(50) {
                println!("  [{}] {} → {} · {} · {} · {}",
                    r.sent_at, r.kind, r.to_address, r.state,
                    r.subject,
                    r.error.as_deref().unwrap_or(r.smtp_code.as_deref().unwrap_or("-")));
            }
        }
        Response::EmailSmtpAutodetect(a) => {
            if a.found {
                println!("found local SMTP: {}:{} ({})", a.smtp_host, a.smtp_port, a.security);
                println!("  suggested_from = {}", a.suggested_from);
                println!("  note: {}", a.notes);
            } else {
                println!("no local SMTP relay detected");
                println!("  note: {}", a.notes);
            }
        }
        Response::HostingImportFromUrl(r) => {
            println!("imported (via url) hosting {}", r.domain);
            println!("  new id : {}", r.new_hosting_id.as_str());
            println!("  bytes  : {}", r.restored_bytes);
            println!("  state  : {}", r.state);
            println!("  note   : {}", r.message);
        }
        Response::HostingImport(r) => {
            println!("imported hosting {}", r.domain);
            println!("  new id : {}", r.new_hosting_id.as_str());
            println!("  bytes  : {}", r.restored_bytes);
            println!("  state  : {}", r.state);
            println!("  note   : {}", r.message);
        }
        Response::WpAssetUpload { id, deduped } => {
            if *deduped {
                println!("wp asset deduped: id={id} (same SHA-256 already in library)");
            } else {
                println!("wp asset uploaded: id={id}");
            }
        }
        Response::WpAssetList(assets) => {
            if assets.is_empty() {
                println!("(no wp assets uploaded yet)");
            } else {
                println!("{:<5} {:<7} {:<10} {}", "ID", "KIND", "SIZE", "FILENAME");
                for a in assets {
                    println!(
                        "{:<5} {:<7} {:<10} {}",
                        a.id,
                        a.kind,
                        format!("{} KB", a.size_bytes / 1024),
                        a.original_name
                    );
                }
            }
        }
        Response::WpAssetDelete => {
            println!("wp asset deleted");
        }
        Response::WpInstallFromAsset {
            kind,
            original_name,
        } => {
            println!("wp {kind} installed from library: {original_name}");
        }
        Response::WpAssetReplace => {
            println!("wp asset replaced");
        }
        Response::WpAssetReinstallAll {
            installed_ok,
            installed_failed,
            failure_tail,
        } => {
            println!("wp asset reinstall: {installed_ok} ok, {installed_failed} failed");
            if !failure_tail.is_empty() {
                println!("--- failures ---");
                println!("{failure_tail}");
            }
        }
        Response::WpThemeList(r) => {
            println!("wp core: {}", r.wp_version);
            println!(
                "{:<24} {:<10} {:<10} {}",
                "SLUG", "STATUS", "VERSION", "UPDATE"
            );
            for t in &r.themes {
                println!(
                    "{:<24} {:<10} {:<10} {}",
                    t.slug,
                    t.status,
                    t.version,
                    if t.update_available {
                        t.latest_version.clone()
                    } else {
                        "-".into()
                    }
                );
            }
        }
        Response::WpThemeAction(r) => {
            println!("theme action: {}", r.state);
            println!("  {}", r.message);
        }
        Response::ServiceInstallStatus(s) => {
            if s.started_at == 0 {
                println!("no service install has run on this node");
            } else {
                println!("service install ({}):", s.service_name);
                println!("  state      : {}", s.state);
                println!("  pkg        : {}", s.pkg);
                println!("  started_at : {}", s.started_at);
                println!("  finished_at: {}", s.finished_at);
                println!("  exit_code  : {}", s.exit_code);
                println!("  --- log tail ---");
                print!("{}", s.log_tail);
                if !s.log_tail.ends_with('\n') {
                    println!();
                }
            }
        }
        Response::NodeUpdateRun { started_at } => {
            println!("node update started: unix:{started_at}");
            println!("poll with: hctl node-update-status");
        }
        Response::NodeUpdateStatus(s) => {
            println!("node update:");
            println!("  state      : {}", s.state);
            println!("  started_at : {}", s.started_at);
            println!("  finished_at: {}", s.finished_at);
            println!("  do_apt     : {}", s.do_apt);
            println!("  do_hyperion: {}", s.do_hyperion);
            println!("  exit_code  : {}", s.exit_code);
            println!("  --- log tail ---");
            print!("{}", s.log_tail);
            if !s.log_tail.ends_with('\n') {
                println!();
            }
        }
        Response::FsDiagnoseAndFix(d) => {
            println!("filesystem diagnose:");
            println!("  final_state          : {}", d.final_state);
            println!("  image_kind           : {}", d.image_kind);
            println!("  /  writable now      : {}", d.usr_writable_now);
            println!("  /  writable before   : {}", d.usr_writable_before);
            if !d.root_mount_line.is_empty() {
                println!("  /proc/mounts /       : {}", d.root_mount_line);
            }
            if !d.usr_mount_line.is_empty() {
                println!("  /proc/mounts /usr    : {}", d.usr_mount_line);
            }
            if !d.fstab_root_line.is_empty() {
                println!("  /etc/fstab /         : {}", d.fstab_root_line);
            }
            println!("  /usr immutable attr  : {}", d.immutable_attr_set);
            if !d.fix_steps.is_empty() {
                println!("  fix steps:");
                for s in &d.fix_steps {
                    println!(
                        "    [{:>3}] {}  → {}",
                        s.exit_code,
                        if s.now_writable { "rw" } else { "ro" },
                        s.label
                    );
                    if !s.message.is_empty() {
                        for line in s.message.lines() {
                            println!("        {line}");
                        }
                    }
                }
            }
            if !d.recommendations.is_empty() {
                println!("  recommendations:");
                for r in &d.recommendations {
                    println!("    - {r}");
                }
            }
        }
        Response::JobGet(Some(j)) => print_job(j),
        Response::JobGet(None) => println!("job not found"),
        Response::JobList(list) => {
            if list.is_empty() {
                println!("no jobs");
            } else {
                println!(
                    "{:<26} {:<14} {:<10} {:>4}% {:<8} {}",
                    "id", "kind", "state", "pct", "elapsed", "target"
                );
                for j in list {
                    let elapsed = match j.finished_at {
                        Some(f) => f - j.started_at,
                        None => j.updated_at - j.started_at,
                    };
                    println!(
                        "{:<26} {:<14} {:<10} {:>4}% {:<8} {}",
                        j.id,
                        j.kind,
                        j.state,
                        j.progress_pct,
                        format_args!("{}s", elapsed),
                        j.target.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        Response::JobStarted { job_id } => println!("job started: {job_id}"),
        Response::JobAck => println!("ack"),
        Response::BackupTargetList(list) => {
            if list.is_empty() {
                println!("no backup targets configured");
            } else {
                println!(
                    "{:<5} {:<24} {:<10} {:<40} {:<10}",
                    "id", "name", "enabled", "endpoint", "bucket"
                );
                for t in list {
                    println!(
                        "{:<5} {:<24} {:<10} {:<40} {:<10}",
                        t.id, t.name, t.enabled, t.endpoint, t.bucket
                    );
                }
            }
        }
        Response::BackupTargetUpserted { id } => println!("backup target upserted: id={id}"),
        Response::BackupTargetDeleted => println!("backup target deleted"),
        Response::BackupTargetProbe(p) => {
            println!(
                "probe: ok={} latency={}ms message={}",
                p.ok, p.put_latency_ms, p.message
            );
        }
        Response::QuotaGet(r) => {
            println!("quota:");
            println!("  current disk         : {} KiB", r.current_disk_kib);
            println!("  kernel quotas enabled: {}", r.quotas_enabled_on_fs);
            println!("  policy:");
            println!("    disk_soft_kib  : {}", r.policy.disk_soft_kib);
            println!("    disk_hard_kib  : {}", r.policy.disk_hard_kib);
            println!("    mem_limit_mib  : {}", r.policy.mem_limit_mib);
            println!("    bw_soft_mib    : {}", r.policy.bw_soft_mib);
            println!("    bw_hard_mib    : {}", r.policy.bw_hard_mib);
            if let Some(at) = r.policy.applied_at {
                println!("    applied_at     : {at}");
            }
            if let Some(err) = &r.policy.last_error {
                println!("    last_error     : {err}");
            }
            if !r.setup_hint.is_empty() {
                println!("  setup hint:");
                for line in r.setup_hint.lines() {
                    println!("    {line}");
                }
            }
        }
        Response::QuotaApplied(v) => {
            println!("quota saved:");
            println!(
                "  disk soft={} KiB  hard={} KiB  mem={} MiB  bw_soft={} MiB  bw_hard={} MiB",
                v.disk_soft_kib, v.disk_hard_kib, v.mem_limit_mib, v.bw_soft_mib, v.bw_hard_mib
            );
            if let Some(at) = v.applied_at {
                println!("  applied to kernel at: {at}");
            }
            if let Some(err) = &v.last_error {
                println!("  kernel error: {err}");
            }
        }
        Response::NodeLabelUpdated => println!("node label updated"),
        Response::NodeDrainUpdated => println!("node drain flag updated"),
        Response::NodeRemoved { removed, hostings_blocking } => {
            if *removed {
                println!("✓ node removed (orphaned hostings: {hostings_blocking})");
            } else if *hostings_blocking > 0 {
                eprintln!(
                    "✗ refused — {hostings_blocking} hosting(s) still here. Re-run with --force to orphan and delete."
                );
            } else {
                eprintln!("✗ node not found");
            }
        }
        Response::CertOverview(items) => {
            if items.is_empty() {
                println!("no certificates");
            } else {
                println!(
                    "{:<40} {:<14} {:>5} {}",
                    "domain", "issuer", "days", "band"
                );
                for it in items {
                    println!(
                        "{:<40} {:<14} {:>5} {}",
                        it.domain, it.issuer, it.days_left, it.band
                    );
                }
            }
        }
        Response::WebSessionAck => println!("session ack"),
        Response::WebSessionTouch(b) => {
            println!("session {}", if *b { "live" } else { "revoked/unknown" })
        }
        Response::WebSessionList(rows) => {
            if rows.is_empty() {
                println!("no sessions");
            } else {
                println!(
                    "{:<26} {:<16} {:<10} {:<10} {:<8}",
                    "sid", "ip", "created", "last_seen", "state"
                );
                for r in rows {
                    println!(
                        "{:<26} {:<16} {:<10} {:<10} {:<8}",
                        r.sid,
                        r.ip.as_deref().unwrap_or("-"),
                        r.created_at,
                        r.last_seen_at,
                        if r.is_revoked() { "revoked" } else { "live" }
                    );
                }
            }
        }
    }
}

/// Pretty-print one job — same fields as the live progress card
/// shows in the web UI, but for the CLI / SSH operator.
fn print_job(j: &hyperion_types::JobView) {
    println!("job {}:", j.id);
    println!("  kind        : {}", j.kind);
    println!("  state       : {}", j.state);
    println!(
        "  target      : {}",
        j.target.as_deref().unwrap_or("(none)")
    );
    println!("  actor       : {} (uid={})", j.actor_label, j.actor_uid);
    println!("  started_at  : {}", j.started_at);
    println!("  updated_at  : {}", j.updated_at);
    if let Some(f) = j.finished_at {
        println!("  finished_at : {f} (Δ={}s)", f - j.started_at);
    }
    println!("  step        : {}", j.step_label);
    println!("  progress    : {}%", j.progress_pct);
    if let Some(e) = &j.error {
        println!("  error       : {e}");
    }
    if !j.payload_json.is_empty() && j.payload_json != "{}" {
        println!("  payload     : {}", j.payload_json);
    }
    if !j.log_tail.is_empty() {
        println!("  --- log tail ---");
        print!("{}", j.log_tail);
        if !j.log_tail.ends_with('\n') {
            println!();
        }
    }
}

fn short(s: &str) -> String {
    s.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_selector_domain_vs_id() {
        match parse_selector("example.cz").expect("ok") {
            HostingSelector::Domain(d) => assert_eq!(d.as_str(), "example.cz"),
            other => panic!("wrong: {other:?}"),
        }
        match parse_selector("01J7A8GQX").expect("ok") {
            HostingSelector::Id(id) => assert_eq!(id.0, "01J7A8GQX"),
            other => panic!("wrong: {other:?}"),
        }
    }

    #[test]
    fn build_create_full() {
        let r = build_create(
            "example.cz".into(),
            vec!["www.example.cz".into()],
            Some("8.3".into()),
            Some("mariadb".into()),
            None,
        )
        .expect("build");
        assert_eq!(r.domain.as_str(), "example.cz");
        assert_eq!(r.aliases.len(), 1);
        assert_eq!(r.php_version, Some(PhpVersion::V8_3));
        assert_eq!(r.database, Some(DbProvision::MariaDB));
    }

    #[test]
    fn build_create_static() {
        let r = build_create("a.cz".into(), vec![], None, None, None).expect("build");
        assert_eq!(r.php_version, None);
        assert_eq!(r.database, None);
        assert_eq!(r.system_user, None);
    }

    #[test]
    fn cli_parses_create() {
        let cli = Cli::parse_from([
            "hctl",
            "hosting",
            "create",
            "ex.cz",
            "--alias",
            "www.ex.cz",
            "--php",
            "8.3",
            "--db",
            "mariadb",
        ]);
        match cli.cmd {
            Cmd::Hosting(HostingCmd::Create { domain, .. }) => {
                assert_eq!(domain, "ex.cz");
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn cli_parses_info() {
        let cli = Cli::parse_from(["hctl", "info"]);
        matches!(cli.cmd, Cmd::Info);
    }

    #[test]
    fn cli_parses_delete_with_flags() {
        let cli = Cli::parse_from([
            "hctl",
            "hosting",
            "delete",
            "example.cz",
            "--keep-user",
            "--keep-db",
        ]);
        match cli.cmd {
            Cmd::Hosting(HostingCmd::Delete {
                keep_user, keep_db, ..
            }) => {
                assert!(keep_user);
                assert!(keep_db);
            }
            _ => panic!("wrong"),
        }
    }
}
