//! Turn a parsed command into agent RPC calls.
//!
//! Most commands are one request → one response. A few need a lookup first
//! (a username → user id, a backup id → its archive path, the current limits
//! before overlaying the flags that changed), and `job wait` / `node update
//! --follow` poll. Whatever the path, the caller gets back the one response
//! to print plus any secrets this run generated.

use crate::util::{confirm, new_secret, parse_selector};
use crate::*;
use anyhow::{anyhow, bail, Context, Result};
use hyperion_rpc::codec::{AuditSearchFilter, Request, Response};
use hyperion_rpc::wire::DeleteOpts;
use hyperion_types::{
    BackupRestoreMode, CertIssueRequest, HostingLimits, OverBwPolicy, PhpVersion, SuspendReason,
    WpPluginAction, WpThemeAction,
};
use hyperion_validate::Domain;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};

pub struct Outcome {
    pub resp: Response,
    /// Lines to show after the response — generated passwords.
    pub notes: Vec<String>,
    /// Exit non-zero even though the agent answered (a job that failed).
    pub failed: bool,
}

impl From<Response> for Outcome {
    fn from(resp: Response) -> Self {
        Self {
            resp,
            notes: Vec::new(),
            failed: false,
        }
    }
}

struct Agent<'a> {
    socket: &'a Path,
}

impl Agent<'_> {
    /// One round trip. Connection failures get the fix in the message
    /// rather than a bare `io: Permission denied (os error 13)`.
    async fn call(&self, req: Request) -> Result<Response> {
        hyperion_rpc_client::call(self.socket, req)
            .await
            .map_err(|e| {
                let hyperion_rpc_client::ClientError::Io(io) = &e;
                let path = self.socket.display();
                match io.kind() {
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                        anyhow!(
                            "cannot reach the agent at {path} ({io}) — is it running? \
                         `systemctl status hyperion-agent`"
                        )
                    }
                    std::io::ErrorKind::PermissionDenied => anyhow!(
                        "permission denied on {path} — run with sudo, or add your user to \
                         the hyperion-admin group (`sudo usermod -aG hyperion-admin $USER`, \
                         then log in again)"
                    ),
                    _ => anyhow!("agent call failed: {e}"),
                }
            })
    }

    /// A call whose answer feeds the next step: an agent error ends the run.
    async fn ok(&self, req: Request) -> Result<Response> {
        match self.call(req).await? {
            Response::Error(e) => Err(anyhow!("{e}")),
            r => Ok(r),
        }
    }

    /// Hosting id for requests that take a bare id string — accepts a
    /// domain too, and resolves it.
    async fn hosting_id(&self, s: &str) -> Result<String> {
        if !s.contains('.') {
            return Ok(s.to_string());
        }
        match self.ok(Request::HostingGet(parse_selector(s)?)).await? {
            Response::HostingGet(d) => Ok(d.id.0),
            other => Err(unexpected(&other)),
        }
    }

    /// A panel user by username (preferred) or numeric id.
    async fn user_id(&self, s: &str) -> Result<i64> {
        let users = match self.ok(Request::WebUserList).await? {
            Response::WebUserList(u) => u,
            other => return Err(unexpected(&other)),
        };
        if let Some(u) = users.iter().find(|u| u.username.eq_ignore_ascii_case(s)) {
            return Ok(u.id);
        }
        if let Ok(id) = s.parse::<i64>() {
            if users.iter().any(|u| u.id == id) {
                return Ok(id);
            }
        }
        bail!("no panel user {s:?} — `hctl user list` shows who exists (users live on the master)")
    }
}

/// Names the variant only (via its serde tag) — never its fields, which
/// can carry secrets.
fn unexpected(r: &Response) -> anyhow::Error {
    let method = serde_json::to_value(r)
        .ok()
        .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_string))
        .unwrap_or_else(|| "?".into());
    anyhow!("unexpected agent response: {method}")
}

fn restore_mode(m: RestoreMode) -> BackupRestoreMode {
    match m {
        RestoreMode::All => BackupRestoreMode::FilesAndDb,
        RestoreMode::Db => BackupRestoreMode::DbOnly,
        RestoreMode::Files => BackupRestoreMode::FilesOnly,
    }
}

fn role_name(r: Role) -> String {
    r.to_possible_value()
        .map(|v| v.get_name().to_string())
        .unwrap_or_default()
}

fn domain(s: &str) -> Result<Domain> {
    Ok(Domain::parse(s)?)
}

pub async fn execute(socket: &Path, cmd: &Cmd) -> Result<Outcome> {
    let a = Agent { socket };
    let mut notes = Vec::new();
    // Every arm either returns early (multi-step commands) or yields the
    // single request to send.
    let req = match cmd {
        Cmd::Remote { .. } | Cmd::Completions { .. } => unreachable!("handled in main()"),
        Cmd::Info => Request::AgentInfo,

        // ── hosting ────────────────────────────────────────────────────
        Cmd::Hosting(h) => match h {
            HostingCmd::Create {
                domain,
                aliases,
                php,
                db,
                user,
                proxy,
            } => Request::HostingCreate(util::build_create(
                domain,
                aliases,
                php.as_deref(),
                db.as_deref(),
                user.as_deref(),
                proxy.as_deref(),
            )?),
            HostingCmd::List { state, search } => {
                let resp = a.call(Request::HostingList).await?;
                let Response::HostingList(mut rows) = resp else {
                    return Ok(resp.into());
                };
                if let Some(s) = state {
                    rows.retain(|r| r.state.as_str().eq_ignore_ascii_case(s));
                }
                if let Some(q) = search {
                    let q = q.to_ascii_lowercase();
                    rows.retain(|r| r.domain.to_ascii_lowercase().contains(&q));
                }
                return Ok(Response::HostingList(rows).into());
            }
            HostingCmd::Get { selector } => Request::HostingGet(parse_selector(selector)?),
            HostingCmd::Delete {
                selector,
                keep_user,
                keep_db,
                yes,
            } => {
                let sel = parse_selector(selector)?;
                confirm(&format!("Delete hosting {selector}?"), *yes)?;
                Request::HostingDelete {
                    sel,
                    opts: DeleteOpts {
                        keep_user: *keep_user,
                        keep_database: *keep_db,
                    },
                }
            }
            HostingCmd::Suspend { selector, reason } => Request::HostingSuspend {
                sel: parse_selector(selector)?,
                reason: SuspendReason::Manual {
                    message: reason.clone(),
                },
            },
            HostingCmd::Resume { selector } => Request::HostingResume(parse_selector(selector)?),
            HostingCmd::SetPhp { selector, version } => Request::HostingSetPhpVersion {
                sel: parse_selector(selector)?,
                version: PhpVersion::from_str(version).map_err(anyhow::Error::msg)?,
            },
            HostingCmd::SetAliases {
                selector,
                aliases,
                clear: _,
            } => Request::HostingSetAliases {
                sel: parse_selector(selector)?,
                aliases: aliases
                    .iter()
                    .map(|d| domain(d))
                    .collect::<Result<Vec<_>>>()?,
            },
            HostingCmd::SetUpstream { selector, url } => Request::HostingSetProxyUpstream {
                sel: parse_selector(selector)?,
                upstream_url: url.clone(),
            },
            HostingCmd::GetLimits { selector } => {
                Request::HostingGetLimits(parse_selector(selector)?)
            }
            HostingCmd::SetLimits {
                selector,
                php_memory_mb,
                php_max_exec_secs,
                php_max_children,
                php_max_requests,
                db_max_connections,
                disk_soft,
                disk_hard,
                bw_monthly,
                over_bw_policy,
            } => {
                let sel = parse_selector(selector)?;
                // The agent REPLACES the whole limits row. Start from what
                // the hosting has now — starting from defaults() silently
                // reset every limit the operator did not name.
                let mut l: HostingLimits =
                    match a.ok(Request::HostingGetLimits(sel.clone())).await? {
                        Response::HostingGetLimits(l) => l,
                        other => return Err(unexpected(&other)),
                    };
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
                if let Some(v) = disk_soft {
                    l.disk_soft_bytes = v.0;
                }
                if let Some(v) = disk_hard {
                    l.disk_hard_bytes = v.0;
                }
                if let Some(v) = bw_monthly {
                    l.bw_monthly_bytes = v.0;
                }
                if let Some(p) = over_bw_policy {
                    l.over_bw_policy = OverBwPolicy::from_str(p).map_err(anyhow::Error::msg)?;
                }
                Request::HostingSetLimits { sel, limits: l }
            }
            HostingCmd::Usage { selector, limit } => Request::HostingUsage {
                sel: parse_selector(selector)?,
                limit: *limit,
            },
            HostingCmd::Stats { selector } => match selector {
                Some(s) => Request::HostingStats {
                    sel: parse_selector(s)?,
                },
                None => Request::HostingStatsAll,
            },
            HostingCmd::Logs {
                selector,
                kind,
                lines,
            } => Request::HostingLogs {
                sel: parse_selector(selector)?,
                log_kind: kind.clone(),
                lines: *lines,
            },
            HostingCmd::RepairPerms { selector } => Request::HostingRepairPermissions {
                sel: parse_selector(selector)?,
            },
            HostingCmd::PurgeCache { selector } => Request::HostingPageCachePurge {
                sel: parse_selector(selector)?,
            },
            HostingCmd::Export { selector } => Request::HostingExport {
                hosting: parse_selector(selector)?,
            },
            HostingCmd::Import { manifest } => Request::HostingImport {
                manifest_path: manifest.clone(),
            },
            HostingCmd::ImportFromUrl { base_url, token } => Request::HostingImportFromUrl {
                base_url: base_url.clone(),
                token: token.clone(),
                override_domain: None,
                override_aliases: Vec::new(),
            },
            HostingCmd::ImportPanel {
                source,
                mode,
                dry_run,
                ssh_host,
                ssh_user,
                ssh_port,
                ssh_key,
                archive,
            } => {
                let ssh = if mode == "remote" {
                    let host = ssh_host
                        .clone()
                        .ok_or_else(|| anyhow!("remote mode requires --ssh-host"))?;
                    let key_path = ssh_key.clone().ok_or_else(|| {
                        anyhow!("remote mode requires --ssh-key (path to private key)")
                    })?;
                    let key = std::fs::read_to_string(&key_path)
                        .with_context(|| format!("read --ssh-key {key_path}"))?;
                    Some(hyperion_import::SshConn {
                        host,
                        user: ssh_user.clone(),
                        port: *ssh_port,
                        key,
                    })
                } else {
                    None
                };
                if mode == "archive" && archive.is_none() {
                    bail!("archive mode requires --archive <path to bundle.tar>");
                }
                let req = hyperion_import::ImportPanelReq {
                    source_kind: source.clone(),
                    mode: mode.clone(),
                    ssh,
                    archive_path: archive.clone(),
                    site_overrides: Vec::new(),
                };
                if *dry_run {
                    Request::HostingImportPanelPlan { req }
                } else {
                    Request::HostingImportPanel { req }
                }
            }
        },

        // ── trash ──────────────────────────────────────────────────────
        Cmd::Trash(t) => match t {
            TrashCmd::List => Request::TrashList,
            TrashCmd::Restore { selector } => Request::TrashRestore(parse_selector(selector)?),
            TrashCmd::Purge { selector, yes } => {
                let sel = parse_selector(selector)?;
                confirm(
                    &format!("Permanently delete {selector} — files, database and user?"),
                    *yes,
                )?;
                Request::TrashPurge(sel)
            }
        },

        // ── backup ─────────────────────────────────────────────────────
        Cmd::Backup(b) => match b {
            BackupCmd::List { selector, limit } => Request::BackupList {
                sel: parse_selector(selector)?,
                limit: *limit,
            },
            BackupCmd::Now { selector } => Request::BackupNow {
                sel: parse_selector(selector)?,
                // Off-site targets (and their secrets) live in the panel's
                // database; a CLI backup is the local copy only.
                s3_targets: Vec::new(),
                progress_job_id: None,
            },
            BackupCmd::Restore {
                selector,
                id,
                mode,
                yes,
            } => {
                let sel = parse_selector(selector)?;
                let rows = match a
                    .ok(Request::BackupList {
                        sel: sel.clone(),
                        limit: 1000,
                    })
                    .await?
                {
                    Response::BackupList(rows) => rows,
                    other => return Err(unexpected(&other)),
                };
                let row = rows.iter().find(|r| r.id == *id).ok_or_else(|| {
                    anyhow!("{selector} has no backup #{id} — see `hctl backup list {selector}`")
                })?;
                let archive_path = row.archive_path.clone().ok_or_else(|| {
                    anyhow!("backup #{id} has no local archive (pruned, or off-site only)")
                })?;
                confirm(
                    &format!(
                        "Restore backup #{id} ({}) over the live site {selector}?",
                        row.started_at
                    ),
                    *yes,
                )?;
                Request::BackupRestore {
                    sel,
                    archive_path,
                    mode: restore_mode(*mode),
                }
            }
            BackupCmd::Delete { selector, id, yes } => {
                let sel = parse_selector(selector)?;
                confirm(&format!("Delete backup #{id} of {selector}?"), *yes)?;
                Request::BackupDelete {
                    sel,
                    backup_id: *id,
                }
            }
        },

        // ── snapshot ───────────────────────────────────────────────────
        Cmd::Snapshot(s) => match s {
            SnapshotCmd::List { selector } => Request::SnapshotList {
                sel: parse_selector(selector)?,
            },
            SnapshotCmd::Now { selector } => Request::SnapshotNow {
                sel: parse_selector(selector)?,
            },
            SnapshotCmd::Restore {
                selector,
                snapshot,
                mode,
                yes,
            } => {
                let sel = parse_selector(selector)?;
                confirm(
                    &format!("Restore snapshot {snapshot} over the live site {selector}?"),
                    *yes,
                )?;
                Request::SnapshotRestore {
                    sel,
                    snapshot: snapshot.clone(),
                    mode: restore_mode(*mode),
                }
            }
        },

        // ── cert ───────────────────────────────────────────────────────
        Cmd::Cert(c) => match c {
            CertCmd::List => Request::CertOverview,
            CertCmd::Request {
                selector,
                staging,
                skip_dns_check,
            } => Request::CertIssueAcme {
                sel: parse_selector(selector)?,
                req: CertIssueRequest {
                    staging: *staging,
                    require_dns_match: !skip_dns_check,
                    extra_sans: Vec::new(),
                },
            },
            CertCmd::RenewAll => Request::CertRenewAll,
            CertCmd::Delete { selector, yes } => {
                let sel = parse_selector(selector)?;
                confirm(&format!("Delete the certificate of {selector}?"), *yes)?;
                Request::CertDelete { sel }
            }
        },

        // ── dns ────────────────────────────────────────────────────────
        Cmd::Dns(d) => match d {
            DnsCmd::Check { domain: d } => Request::DnsCheck { domain: domain(d)? },
            DnsCmd::Spf { domain: d } => Request::DnsSpfCheck { domain: domain(d)? },
        },

        // ── wp ─────────────────────────────────────────────────────────
        Cmd::Wp(w) => match w {
            WpCmd::Status { selector } => Request::WpStatus {
                sel: parse_selector(selector)?,
            },
            WpCmd::FatalCheck { selector } => Request::WpFatalCheck {
                sel: parse_selector(selector)?,
            },
            WpCmd::Plugins { selector } => Request::WpPluginList {
                hosting: parse_selector(selector)?,
            },
            WpCmd::Plugin {
                selector,
                action,
                slug,
                no_activate,
            } => {
                let slug = slug.clone().unwrap_or_default();
                let action = match action {
                    PluginAction::Install => WpPluginAction::Install {
                        source: slug.clone(),
                        activate: !no_activate,
                    },
                    PluginAction::Activate => WpPluginAction::Activate,
                    PluginAction::Deactivate => WpPluginAction::Deactivate,
                    PluginAction::Update => WpPluginAction::Update,
                    PluginAction::UpdateAll => WpPluginAction::UpdateAll,
                    PluginAction::Delete => WpPluginAction::Delete,
                    PluginAction::AutoUpdateOn => WpPluginAction::SetAutoUpdate { enabled: true },
                    PluginAction::AutoUpdateOff => WpPluginAction::SetAutoUpdate { enabled: false },
                };
                Request::WpPluginAction {
                    hosting: parse_selector(selector)?,
                    slug,
                    action,
                }
            }
            WpCmd::Themes { selector } => Request::WpThemeList {
                hosting: parse_selector(selector)?,
            },
            WpCmd::Theme {
                selector,
                action,
                slug,
            } => {
                let slug = slug.clone().unwrap_or_default();
                let action = match action {
                    ThemeAction::Install => WpThemeAction::Install {
                        source: slug.clone(),
                    },
                    ThemeAction::Activate => WpThemeAction::Activate,
                    ThemeAction::Update => WpThemeAction::Update,
                    ThemeAction::UpdateAll => WpThemeAction::UpdateAll,
                    ThemeAction::Delete => WpThemeAction::Delete,
                };
                Request::WpThemeAction {
                    sel: parse_selector(selector)?,
                    slug,
                    action,
                }
            }
            WpCmd::DisablePlugin { selector, slug } => Request::WpEmergencyDisable {
                sel: parse_selector(selector)?,
                slug: slug.clone(),
            },
            WpCmd::RestorePlugin { selector, slug } => Request::WpEmergencyRestore {
                sel: parse_selector(selector)?,
                slug: slug.clone(),
            },
            WpCmd::ResetPassword {
                selector,
                wp_user,
                password_stdin,
            } => {
                let sel = parse_selector(selector)?;
                let (pw, generated) = new_secret(*password_stdin)?;
                if generated {
                    notes.push(format!("new password for {wp_user} (shown once): {pw}"));
                }
                Request::WpResetPassword {
                    sel,
                    wp_user: wp_user.clone(),
                    new_password: pw,
                }
            }
            WpCmd::VulnScan { selector } => Request::WpVulnScan {
                hosting: parse_selector(selector)?,
            },
            WpCmd::IntegrityScan { selector } => Request::WpIntegrityScan {
                hosting: parse_selector(selector)?,
            },
            WpCmd::CoreRepair { selector } => Request::WpCoreRepair {
                sel: parse_selector(selector)?,
            },
        },

        // ── db ─────────────────────────────────────────────────────────
        Cmd::Db(DbCmd::ResetPassword {
            selector,
            password_stdin,
        }) => {
            let sel = parse_selector(selector)?;
            let (pw, generated) = new_secret(*password_stdin)?;
            if generated {
                notes.push(format!("new database password (shown once): {pw}"));
            }
            Request::DbResetPassword {
                sel,
                new_password: pw,
            }
        }

        // ── ftp ────────────────────────────────────────────────────────
        Cmd::Ftp(f) => match f {
            FtpCmd::List => Request::FtpAccountsList,
            FtpCmd::Check { selector } => Request::FtpSelfCheck {
                sel: parse_selector(selector)?,
            },
            FtpCmd::Repair { selector } => Request::FtpRepairSite {
                sel: parse_selector(selector)?,
            },
            FtpCmd::Perms { selector } => Request::WpPermCheck {
                sel: parse_selector(selector)?,
            },
            FtpCmd::SetPassword {
                selector,
                password_stdin,
            } => {
                let sel = parse_selector(selector)?;
                // Empty asks the agent to generate one; it echoes it back.
                let pw = if *password_stdin {
                    new_secret(true)?.0
                } else {
                    String::new()
                };
                Request::FtpSetPassword {
                    sel,
                    new_password: pw,
                }
            }
            FtpCmd::Disable { selector } => Request::FtpDisable {
                sel: parse_selector(selector)?,
            },
            FtpCmd::Logins { selector } => Request::FtpAccountList {
                sel: parse_selector(selector)?,
            },
            FtpCmd::RepairNode => Request::FtpRepairNodeConfig,
            FtpCmd::Ftps { off } => Request::FtpSetFtps {
                enabled: !off,
                require_tls: !off,
            },
        },

        // ── mail ───────────────────────────────────────────────────────
        Cmd::Mail(m) => match m {
            MailCmd::Status => Request::MtaDiagnostics,
            MailCmd::Test { to } => Request::MtaTestSend { to: to.clone() },
            MailCmd::Flush => Request::MtaQueueFlush,
            MailCmd::Clear { yes } => {
                confirm("Discard every message in the mail queue?", *yes)?;
                Request::MtaQueueClear
            }
            MailCmd::Log { hosting, limit } => Request::EmailLogList {
                hosting_id: match hosting {
                    Some(h) => Some(a.hosting_id(h).await?),
                    None => None,
                },
                limit: *limit,
            },
        },

        // ── dkim ───────────────────────────────────────────────────────
        Cmd::Dkim(d) => match d {
            DkimCmd::Status { selector } => Request::DkimStatus {
                sel: parse_selector(selector)?,
            },
            DkimCmd::Enable { selector } => Request::DkimEnable {
                sel: parse_selector(selector)?,
            },
            DkimCmd::Disable { selector } => Request::DkimDisable {
                sel: parse_selector(selector)?,
            },
            DkimCmd::Verify { selector } => Request::DkimVerify {
                sel: parse_selector(selector)?,
            },
        },

        // ── cron ───────────────────────────────────────────────────────
        Cmd::Cron(c) => match c {
            CronCmd::List { selector } => Request::CronList {
                sel: parse_selector(selector)?,
            },
            CronCmd::Set { selector, file } => {
                let sel = parse_selector(selector)?;
                let body = if file.as_os_str() == "-" {
                    let mut s = String::new();
                    std::io::stdin()
                        .read_to_string(&mut s)
                        .context("read crontab from stdin")?;
                    s
                } else {
                    std::fs::read_to_string(file)
                        .with_context(|| format!("read {}", file.display()))?
                };
                Request::CronReplace { sel, body }
            }
        },

        // ── ban ────────────────────────────────────────────────────────
        Cmd::Ban(b) => match b {
            BanCmd::List { hosting } => Request::BanList {
                hosting_id: match hosting {
                    Some(h) => Some(a.hosting_id(h).await?),
                    None => None,
                },
            },
            BanCmd::Add {
                ip,
                reason,
                ttl,
                hosting,
            } => Request::BanAdd {
                ip: ip.trim().to_string(),
                hosting_id: match hosting {
                    Some(h) => Some(a.hosting_id(h).await?),
                    None => None,
                },
                reason: reason.clone(),
                ttl_secs: ttl.unwrap_or(0),
                source: "manual".into(),
            },
            BanCmd::Remove { ip, hosting } => Request::BanRemove {
                ip: ip.trim().to_string(),
                sel: hosting.as_deref().map(parse_selector).transpose()?,
            },
        },

        // ── firewall ───────────────────────────────────────────────────
        Cmd::Firewall(f) => match f {
            FirewallCmd::Status => Request::FirewallList,
            FirewallCmd::Confirm => Request::FirewallConfirmDefaultDrop,
            FirewallCmd::DisableDrop { yes } => {
                confirm(
                    "Switch the firewall to accept-by-default (every port reachable)?",
                    *yes,
                )?;
                Request::FirewallDisableDefaultDrop
            }
        },

        // ── service / monitor ──────────────────────────────────────────
        Cmd::Service(s) => match s {
            ServiceCmd::List => Request::ServicesHealth,
            ServiceCmd::Restart { name } => Request::ServiceRestart { name: name.clone() },
        },
        Cmd::Monitor(m) => match m {
            MonitorCmd::List => Request::MonitorOverview,
            MonitorCmd::Get { selector } => Request::MonitorGet {
                sel: parse_selector(selector)?,
            },
            MonitorCmd::Probe { selector } => Request::MonitorProbeNow {
                sel: parse_selector(selector)?,
            },
        },

        // ── job ────────────────────────────────────────────────────────
        Cmd::Job(j) => match j {
            JobCmd::List { kind, state, limit } => Request::JobList {
                kind: kind.clone(),
                state: state.clone(),
                limit: *limit,
            },
            JobCmd::Get { id } => Request::JobGet { id: id.clone() },
            JobCmd::Wait { id, timeout } => return wait_job(&a, id, *timeout).await,
        },

        // ── user ───────────────────────────────────────────────────────
        Cmd::User(u) => match u {
            UserCmd::List => Request::WebUserList,
            UserCmd::Create {
                username,
                email,
                role,
                password_stdin,
            } => {
                let (pw, generated) = new_secret(*password_stdin)?;
                if generated {
                    notes.push(format!("password for {username} (shown once): {pw}"));
                }
                Request::WebUserCreate {
                    username: username.clone(),
                    email: email.clone(),
                    password: pw,
                    role: role_name(*role),
                }
            }
            UserCmd::ResetPassword {
                user,
                password_stdin,
            } => {
                let user_id = a.user_id(user).await?;
                let (pw, generated) = new_secret(*password_stdin)?;
                if generated {
                    notes.push(format!("new password for {user} (shown once): {pw}"));
                }
                Request::WebUserSetPassword {
                    user_id,
                    new_password: pw,
                    current_password: None,
                }
            }
            UserCmd::SetRole { user, role } => Request::WebUserSetRole {
                user_id: a.user_id(user).await?,
                role: role_name(*role),
            },
            UserCmd::Lock { user, reason } => Request::WebUserSetLocked {
                user_id: a.user_id(user).await?,
                locked: true,
                reason: reason.clone(),
            },
            UserCmd::Unlock { user } => Request::WebUserSetLocked {
                user_id: a.user_id(user).await?,
                locked: false,
                reason: None,
            },
            UserCmd::Disable2fa { user } => Request::Web2faDisable {
                user_id: a.user_id(user).await?,
            },
            UserCmd::Delete { user, yes } => {
                let user_id = a.user_id(user).await?;
                confirm(&format!("Delete panel user {user}?"), *yes)?;
                Request::WebUserDelete { user_id }
            }
        },

        // ── node ───────────────────────────────────────────────────────
        Cmd::Node(n) => match n {
            NodeCmd::List => Request::NodesList,
            NodeCmd::Stats => Request::NodeStats,
            NodeCmd::Label { node_id, label } => Request::NodeSetLabel {
                node_id: node_id.clone(),
                label: label.clone(),
            },
            NodeCmd::Drain { node_id, reason } => Request::NodeSetDrain {
                node_id: node_id.clone(),
                drain: true,
                reason: reason.clone(),
            },
            NodeCmd::Undrain { node_id } => Request::NodeSetDrain {
                node_id: node_id.clone(),
                drain: false,
                reason: String::new(),
            },
            NodeCmd::Remove {
                node_id,
                force,
                yes,
            } => {
                confirm(&format!("Remove node {node_id} from the cluster?"), *yes)?;
                Request::NodeRemove {
                    node_id: node_id.clone(),
                    force: *force,
                }
            }
            NodeCmd::ResetCrypto { node_id } => Request::NodeResetCrypto {
                node_id: node_id.clone(),
            },
            NodeCmd::Reassign { from, to } => Request::NodeReassignHostings {
                from_node_id: from.clone(),
                to_node_id: to.clone(),
            },
            NodeCmd::Update {
                apt,
                hyperion,
                safe,
                follow,
            } => {
                if !apt && !hyperion {
                    bail!("nothing to update — pass --apt, --hyperion, or both");
                }
                let started = a
                    .call(Request::NodeUpdateRun {
                        safe: *safe,
                        do_apt: *apt,
                        do_hyperion: *hyperion,
                    })
                    .await?;
                if !follow || !matches!(started, Response::NodeUpdateRun { .. }) {
                    return Ok(started.into());
                }
                return follow_node_update(&a).await;
            }
            NodeCmd::UpdateStatus => Request::NodeUpdateStatus,
            NodeCmd::UpdateCheck { refresh } => Request::UpdateCheck {
                force_refresh: *refresh,
            },
            NodeCmd::OsUpdates { refresh } => {
                if *refresh {
                    Request::OsUpdatesCheck { refresh: true }
                } else {
                    Request::OsUpdatesStatus
                }
            }
            NodeCmd::FsCheck { fix } => Request::FsDiagnoseAndFix { dry_run: !fix },
        },

        // ── agent / stats / audit ──────────────────────────────────────
        Cmd::Agent(AgentCmd::Repin) => Request::AgentRepin,
        Cmd::Agent(AgentCmd::Config) => Request::AgentConfigView,
        Cmd::Stats(s) => match s {
            StatsCmd::Node => Request::NodeStats,
            StatsCmd::Cluster => Request::ClusterStats,
            StatsCmd::Sites => Request::HostingStatsAll,
        },
        Cmd::Audit { limit, cmd } => match cmd {
            None => Request::AuditList { limit: *limit },
            Some(AuditCmd::Verify) => Request::AuditVerifyChain,
            Some(AuditCmd::Search(s)) => Request::AuditSearch {
                filter: AuditSearchFilter {
                    q: s.query.clone().unwrap_or_default(),
                    action: s.action.clone().unwrap_or_default(),
                    failed_only: s.failed,
                    limit: s.limit,
                    ..Default::default()
                },
            },
        },
    };
    let resp = a.call(req).await?;
    Ok(Outcome {
        resp,
        notes,
        failed: false,
    })
}

/// Poll a job until it is terminal, echoing step changes to stderr.
async fn wait_job(a: &Agent<'_>, id: &str, timeout: u64) -> Result<Outcome> {
    let start = Instant::now();
    let mut last = String::new();
    loop {
        let resp = a.call(Request::JobGet { id: id.to_string() }).await?;
        let Response::JobGet(Some(j)) = &resp else {
            return Ok(resp.into());
        };
        let line = format!("{} {}% {}", j.state, j.progress_pct, j.step_label);
        if line != last {
            eprintln!("  {line}");
            last = line;
        }
        if j.is_terminal() {
            let failed = j.state != "done";
            return Ok(Outcome {
                resp,
                notes: Vec::new(),
                failed,
            });
        }
        if timeout > 0 && start.elapsed() >= Duration::from_secs(timeout) {
            bail!("job {id} still {} after {timeout}s", j.state);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Follow `node update` to the end. A Hyperion update restarts the agent
/// that answers us, so a few failed connections in the middle are expected
/// and waited out rather than reported.
async fn follow_node_update(a: &Agent<'_>) -> Result<Outcome> {
    let mut misses = 0;
    let mut shown = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let resp = match a.call(Request::NodeUpdateStatus).await {
            Ok(r) => {
                misses = 0;
                r
            }
            Err(e) => {
                misses += 1;
                if misses > 60 {
                    return Err(e.context("agent did not come back within 3 minutes"));
                }
                continue;
            }
        };
        let Response::NodeUpdateStatus(s) = &resp else {
            return Ok(resp.into());
        };
        // Stream the log: print only what is new since the last poll.
        eprint!("{}", unseen(&shown, &s.log_tail));
        shown = s.log_tail.clone();
        if s.state != "running" {
            let failed = s.state != "succeeded";
            return Ok(Outcome {
                resp,
                notes: Vec::new(),
                failed,
            });
        }
    }
}

/// The part of `cur` not already printed as `prev`. The agent keeps only
/// the last ~8 kB of the log, so once it fills up the window slides and
/// `cur` no longer starts with `prev`; then resync on `prev`'s last line.
fn unseen<'a>(prev: &str, cur: &'a str) -> &'a str {
    if prev.is_empty() {
        return cur;
    }
    if let Some(rest) = cur.strip_prefix(prev) {
        return rest;
    }
    let last = prev
        .trim_end_matches('\n')
        .rsplit('\n')
        .next()
        .unwrap_or("");
    if !last.is_empty() {
        if let Some(pos) = cur.rfind(last) {
            let rest = &cur[pos + last.len()..];
            return rest.strip_prefix('\n').unwrap_or(rest);
        }
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;
    use hyperion_rpc::codec::{read_frame, write_frame};
    use std::sync::{Arc, Mutex};
    use tokio::net::UnixListener;

    /// A stand-in agent: answers each request with `reply(&req)` and records
    /// what it was sent, so a test can assert on the exact RPCs a command
    /// makes.
    fn fake_agent(
        dir: &tempfile::TempDir,
        reply: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> (std::path::PathBuf, Arc<Mutex<Vec<Request>>>) {
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let req: Request = read_frame(&mut s).await.expect("frame");
                let resp = reply(&req);
                log.lock().expect("lock").push(req);
                write_frame(&mut s, &resp).await.expect("write");
            }
        });
        (path, seen)
    }

    async fn run(socket: &Path, args: &[&str]) -> Result<Outcome> {
        let mut argv = vec!["hctl"];
        argv.extend_from_slice(args);
        let cli = Cli::parse_from(argv);
        execute(socket, &cli.cmd).await
    }

    #[tokio::test]
    async fn set_limits_keeps_every_limit_it_was_not_told_to_change() {
        let dir = tempfile::tempdir().expect("dir");
        let mut current = HostingLimits::defaults();
        current.php_memory_mb = 1024;
        current.disk_hard_bytes = Some(5 << 30);
        current.over_bw_policy = OverBwPolicy::Throttle;
        let (sock, seen) = fake_agent(&dir, move |req| match req {
            Request::HostingGetLimits(_) => Response::HostingGetLimits(current.clone()),
            Request::HostingSetLimits { limits, .. } => Response::HostingSetLimits(limits.clone()),
            _ => panic!("unexpected request"),
        });
        run(
            &sock,
            &["hosting", "set-limits", "a.cz", "--php-max-children", "12"],
        )
        .await
        .expect("run");
        let seen = seen.lock().expect("lock");
        let Request::HostingSetLimits { limits, .. } = &seen[1] else {
            panic!("second call should set limits");
        };
        assert_eq!(limits.php_max_children, 12);
        // Before the fix these came back as defaults (256 MiB, no disk cap,
        // suspend).
        assert_eq!(limits.php_memory_mb, 1024);
        assert_eq!(limits.disk_hard_bytes, Some(5 << 30));
        assert_eq!(limits.over_bw_policy, OverBwPolicy::Throttle);
    }

    fn users() -> Response {
        Response::WebUserList(
            serde_json::from_value(serde_json::json!([
                {"id": 1, "username": "admin", "email": "a@x.cz", "role": "super_admin",
                 "totp_enrolled": true, "totp_required": false, "locked": false,
                 "locked_reason": null, "last_login_at": null, "created_at": 0},
                {"id": 7, "username": "Kevin", "email": "k@x.cz", "role": "operator",
                 "totp_enrolled": false, "totp_required": false, "locked": true,
                 "locked_reason": "too many attempts", "last_login_at": null, "created_at": 0}
            ]))
            .expect("users"),
        )
    }

    #[tokio::test]
    async fn user_commands_resolve_a_username_to_its_id() {
        let dir = tempfile::tempdir().expect("dir");
        let (sock, seen) = fake_agent(&dir, |req| match req {
            Request::WebUserList => users(),
            Request::WebUserSetPassword { .. } => Response::WebUserSetPassword,
            Request::Web2faDisable { .. } => Response::Web2faDisable,
            _ => panic!("unexpected request"),
        });
        let out = run(&sock, &["user", "reset-password", "kevin"])
            .await
            .expect("run");
        // The generated password is surfaced once, and only in the notes.
        assert_eq!(out.notes.len(), 1);
        run(&sock, &["user", "disable-2fa", "1"])
            .await
            .expect("run");
        let seen = seen.lock().expect("lock");
        assert!(matches!(
            &seen[1],
            Request::WebUserSetPassword { user_id: 7, current_password: None, new_password }
                if new_password.len() == 24
        ));
        assert!(matches!(&seen[3], Request::Web2faDisable { user_id: 1 }));
    }

    #[tokio::test]
    async fn unknown_user_is_an_error_not_a_guess() {
        let dir = tempfile::tempdir().expect("dir");
        let (sock, _) = fake_agent(&dir, |_| users());
        let err = run(&sock, &["user", "unlock", "nobody"])
            .await
            .err()
            .expect("error");
        assert!(err.to_string().contains("no panel user"), "{err}");
    }

    #[tokio::test]
    async fn backup_restore_finds_the_archive_by_id() {
        let dir = tempfile::tempdir().expect("dir");
        let (sock, seen) = fake_agent(&dir, |req| match req {
            Request::BackupList { .. } => Response::BackupList(
                serde_json::from_value(serde_json::json!([
                    {"id": 3, "hosting_id": "01H", "target": "local", "started_at": 1,
                     "finished_at": 2, "state": "done", "archive_path": "/b/3.tar.gz",
                     "db_dump_path": null, "bytes_total": 10, "error_message": null}
                ]))
                .expect("rows"),
            ),
            Request::BackupRestore { .. } => Response::BackupRestore,
            _ => panic!("unexpected request"),
        });
        run(
            &sock,
            &["backup", "restore", "a.cz", "3", "--mode", "db", "--yes"],
        )
        .await
        .expect("run");
        let err = run(&sock, &["backup", "restore", "a.cz", "9", "--yes"])
            .await
            .err()
            .expect("no such backup");
        assert!(err.to_string().contains("no backup #9"), "{err}");
        let seen = seen.lock().expect("lock");
        assert!(matches!(
            &seen[1],
            Request::BackupRestore { archive_path, mode: BackupRestoreMode::DbOnly, .. }
                if archive_path == "/b/3.tar.gz"
        ));
    }

    #[tokio::test]
    async fn a_missing_socket_says_how_to_fix_it() {
        let dir = tempfile::tempdir().expect("dir");
        let err = run(&dir.path().join("nope.sock"), &["info"])
            .await
            .err()
            .expect("error");
        assert!(
            err.to_string().contains("systemctl status hyperion-agent"),
            "{err}"
        );
    }

    #[test]
    fn unseen_appends_and_resyncs_after_the_window_slides() {
        assert_eq!(unseen("", "a\nb\n"), "a\nb\n");
        assert_eq!(unseen("a\nb\n", "a\nb\nc\n"), "c\n");
        assert_eq!(unseen("a\nb\n", "a\nb\n"), "");
        // Window slid: "a" fell off the front, "c" and "d" arrived.
        assert_eq!(unseen("a\nb\n", "b\nc\nd\n"), "c\nd\n");
        // Nothing in common: print it all rather than nothing.
        assert_eq!(unseen("a\n", "x\ny\n"), "x\ny\n");
    }
}
