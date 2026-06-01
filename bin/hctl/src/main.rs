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
                "agent: {} version={} hostings={}",
                i.hostname, i.version, i.hostings_count
            );
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
        Response::Error(e) => {
            eprintln!("ERROR: {e}");
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
