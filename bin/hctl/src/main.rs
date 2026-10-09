//! `hctl` — hyperion control: the operator CLI.
//!
//! Two transports:
//! * every command except `remote` speaks the local agent's Unix socket
//!   (`/run/hyperion.sock`, mode 0660, group `hyperion-admin`), so it works
//!   on a node whose panel is down;
//! * `hctl remote …` drives the `/api/v1` HTTP API with a Bearer key from
//!   any machine.
//!
//! The full reference — one entry per command, with examples — lives in
//! `docs/cli.md`. A test (`docs_cover_every_command`) fails when a command is
//! added here without a matching entry there.

#![forbid(unsafe_code)]

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use hyperion_rpc::codec::Response;
use std::path::PathBuf;

mod exec;
mod print;
mod remote;
mod util;

/// `--version` output: human git-describe version + full git SHA stamped at
/// build time (build.rs), e.g. `v1.2.0-5-gf718fd1 (f718fd1a…40 chars…)`. See
/// hyperion-agent's HYPERION_VERSION for the rationale.
const HYPERION_VERSION: &str = concat!(
    env!("HYPERION_DESCRIBE"),
    " (",
    env!("HYPERION_GIT_SHA"),
    ")"
);

#[derive(Parser, Debug)]
#[command(
    name = "hctl",
    version = HYPERION_VERSION,
    about = "hyperion CLI — manage this node through the local agent socket",
    after_help = "Full reference: docs/cli.md (https://github.com/nechodom/hyperion/blob/main/docs/cli.md)"
)]
pub struct Cli {
    /// Path to hyperion-agent's Unix socket.
    #[arg(
        long,
        global = true,
        env = "HYPERION_SOCKET",
        default_value = "/run/hyperion.sock"
    )]
    socket: PathBuf,
    /// Emit the agent's raw response as JSON instead of a human-friendly view.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Show the agent's hostname, version, hosting count and enrollment.
    Info,
    /// Create, inspect, change and remove hostings.
    #[command(subcommand)]
    Hosting(HostingCmd),
    /// Deleted hostings waiting in the trash.
    #[command(subcommand)]
    Trash(TrashCmd),
    /// Per-site backups: list, take, restore, delete.
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Per-site file snapshots (restic).
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// TLS certificates.
    #[command(subcommand)]
    Cert(CertCmd),
    /// DNS checks for a domain.
    #[command(subcommand)]
    Dns(DnsCmd),
    /// WordPress tools for a hosting.
    #[command(subcommand)]
    Wp(WpCmd),
    /// A hosting's database.
    #[command(subcommand)]
    Db(DbCmd),
    /// FTP logins, diagnosis and node-wide FTPS.
    #[command(subcommand)]
    Ftp(FtpCmd),
    /// The node's outgoing mail (postfix).
    #[command(subcommand)]
    Mail(MailCmd),
    /// Per-hosting DKIM signing.
    #[command(subcommand)]
    Dkim(DkimCmd),
    /// A hosting's crontab.
    #[command(subcommand)]
    Cron(CronCmd),
    /// Banned IP addresses.
    #[command(subcommand)]
    Ban(BanCmd),
    /// The node firewall.
    #[command(subcommand)]
    Firewall(FirewallCmd),
    /// System services Hyperion depends on.
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Uptime monitoring.
    #[command(subcommand)]
    Monitor(MonitorCmd),
    /// Background jobs (backups, imports, deletes, …).
    #[command(subcommand)]
    Job(JobCmd),
    /// Panel users — including lock-out recovery (run on the master).
    #[command(subcommand)]
    User(UserCmd),
    /// Cluster nodes and this node's updates.
    #[command(subcommand)]
    Node(NodeCmd),
    /// Node-side agent maintenance.
    #[command(subcommand)]
    Agent(AgentCmd),
    /// Resource statistics.
    #[command(subcommand)]
    Stats(StatsCmd),
    /// Print recent audit log entries, or verify / search the log.
    Audit {
        /// How many entries to print.
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[command(subcommand)]
        cmd: Option<AuditCmd>,
    },
    /// Print a shell completion script (bash, zsh, fish, elvish, powershell).
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Drive the remote /api/v1 HTTP API with a Bearer key (works from any host).
    Remote {
        #[command(flatten)]
        conn: remote::RemoteConn,
        #[command(subcommand)]
        cmd: remote::RemoteCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum HostingCmd {
    /// Create a new hosting.
    Create {
        /// Primary domain, e.g. example.com.
        domain: String,
        /// Extra domain served by the same site (repeatable).
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
        /// Make it a reverse proxy to this upstream URL instead of a PHP/static site.
        #[arg(long, value_name = "URL", conflicts_with_all = ["php", "db"])]
        proxy: Option<String>,
    },
    /// List hostings on this node.
    List {
        /// Only hostings in this state (active | suspended | provisioning | failed | trashed).
        #[arg(long)]
        state: Option<String>,
        /// Only domains containing this text.
        #[arg(long)]
        search: Option<String>,
    },
    /// Show one hosting (by id or domain).
    Get { selector: String },
    /// Delete a hosting (to the trash when trash is enabled).
    Delete {
        selector: String,
        /// Keep the system user.
        #[arg(long)]
        keep_user: bool,
        /// Keep the database.
        #[arg(long)]
        keep_db: bool,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Suspend a hosting (best-effort cascade).
    Suspend {
        selector: String,
        /// Note recorded with the suspension.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Resume a previously suspended hosting.
    Resume { selector: String },
    /// Switch a hosting's PHP version.
    SetPhp {
        selector: String,
        /// 8.1 | 8.2 | 8.3 | 8.4
        version: String,
    },
    /// Replace a hosting's aliases (extra domains).
    SetAliases {
        selector: String,
        /// The complete new alias list.
        #[arg(value_name = "DOMAIN", required_unless_present = "clear")]
        aliases: Vec<String>,
        /// Remove every alias.
        #[arg(long, conflicts_with = "aliases")]
        clear: bool,
    },
    /// Change a reverse-proxy hosting's upstream URL.
    SetUpstream { selector: String, url: String },
    /// Show current limits for a hosting.
    #[command(visible_alias = "limits")]
    GetLimits { selector: String },
    /// Change per-hosting PHP / DB / disk / bandwidth limits. Flags you omit
    /// keep their current value.
    SetLimits {
        selector: String,
        /// PHP memory_limit in MiB.
        #[arg(long)]
        php_memory_mb: Option<i64>,
        /// PHP max_execution_time in seconds.
        #[arg(long)]
        php_max_exec_secs: Option<i64>,
        /// PHP-FPM pm.max_children.
        #[arg(long)]
        php_max_children: Option<i64>,
        /// PHP-FPM pm.max_requests.
        #[arg(long)]
        php_max_requests: Option<i64>,
        /// Database max_user_connections.
        #[arg(long)]
        db_max_connections: Option<i64>,
        /// Disk soft limit (bytes, or 500M / 10G / 1T; "none" clears).
        #[arg(long, value_parser = util::parse_opt_size)]
        disk_soft: Option<util::SizeLimit>,
        /// Disk hard limit (bytes, or 500M / 10G / 1T; "none" clears).
        #[arg(long, alias = "disk-hard-bytes", value_parser = util::parse_opt_size)]
        disk_hard: Option<util::SizeLimit>,
        /// Monthly bandwidth cap (bytes, or 500M / 10G / 1T; "none" clears).
        #[arg(long, alias = "bw-monthly-bytes", value_parser = util::parse_opt_size)]
        bw_monthly: Option<util::SizeLimit>,
        /// What happens over the bandwidth cap: suspend | throttle.
        #[arg(long)]
        over_bw_policy: Option<String>,
    },
    /// Show recent hourly usage samples for a hosting.
    Usage {
        selector: String,
        /// How many samples.
        #[arg(long, default_value_t = 24)]
        limit: i64,
    },
    /// Disk, bandwidth and request totals — one hosting, or all of them.
    Stats { selector: Option<String> },
    /// Print the tail of a hosting's access, error or PHP slow log.
    Logs {
        selector: String,
        /// access | error | slow
        #[arg(long, default_value = "error")]
        kind: String,
        /// How many lines.
        #[arg(long, short = 'n', default_value_t = 100)]
        lines: i64,
    },
    /// Repair ownership and modes under a hosting's document root.
    RepairPerms { selector: String },
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
    ImportFromUrl {
        /// Base URL printed by `hosting export` on the source.
        #[arg(long = "base-url")]
        base_url: String,
        /// Signed token from the source's export response. Expires
        /// 1h after the export — re-export on the source if stale.
        #[arg(long)]
        token: String,
    },
    /// Import sites from a third-party control panel (HestiaCP /
    /// CloudPanel). Reuses `hosting create` per site + copies files &
    /// databases. Mail and DNS are intentionally out of scope (reported,
    /// never imported). Preview with --dry-run first.
    ImportPanel {
        /// Source panel: cloudpanel | hestiacp.
        #[arg(long)]
        source: String,
        /// Where to read from: inplace | remote | archive.
        #[arg(long, default_value = "inplace")]
        mode: String,
        /// Preview the plan without creating anything.
        #[arg(long)]
        dry_run: bool,
        /// remote mode: source host (ip/hostname).
        #[arg(long)]
        ssh_host: Option<String>,
        /// remote mode: ssh user.
        #[arg(long, default_value = "root")]
        ssh_user: String,
        /// remote mode: ssh port.
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// remote mode: path to the private key file used to reach the source.
        #[arg(long)]
        ssh_key: Option<String>,
        /// archive mode: node-local path to an export bundle (`bundle.tar`).
        #[arg(long)]
        archive: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TrashCmd {
    /// List trashed hostings and when each is purged.
    List,
    /// Bring a trashed hosting back.
    Restore { selector: String },
    /// Permanently delete a trashed hosting now.
    Purge {
        selector: String,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
}

/// Which parts of a backup / snapshot to put back.
#[derive(ValueEnum, Clone, Copy, Debug, Default)]
pub enum RestoreMode {
    /// Files and database.
    #[default]
    All,
    /// Database only.
    Db,
    /// Files only.
    Files,
}

#[derive(Subcommand, Debug)]
pub enum BackupCmd {
    /// List a hosting's backups.
    List {
        selector: String,
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },
    /// Take a backup now (local copy; the panel adds the off-site push).
    Now { selector: String },
    /// Restore a backup by its id (see `backup list`).
    Restore {
        selector: String,
        id: i64,
        #[arg(long, value_enum, default_value_t = RestoreMode::All)]
        mode: RestoreMode,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Delete one backup.
    Delete {
        selector: String,
        id: i64,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SnapshotCmd {
    /// List a hosting's snapshots.
    List { selector: String },
    /// Take a snapshot now.
    Now { selector: String },
    /// Restore a snapshot (the replaced state is snapshotted first).
    Restore {
        selector: String,
        snapshot: String,
        #[arg(long, value_enum, default_value_t = RestoreMode::All)]
        mode: RestoreMode,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum CertCmd {
    /// List every certificate on the node with days left.
    List,
    /// Request a Let's Encrypt certificate for a hosting (all its domains).
    ///
    /// `issue` is an alias: the old administrative `cert issue <domain>`
    /// was never implemented by the agent and always failed.
    #[command(visible_alias = "issue")]
    Request {
        selector: String,
        /// Use the Let's Encrypt staging CA (untrusted, no rate limits).
        #[arg(long)]
        staging: bool,
        /// Issue even if DNS does not point at this node yet.
        #[arg(long)]
        skip_dns_check: bool,
    },
    /// Renew every certificate that is close to expiry.
    #[command(visible_alias = "renew")]
    RenewAll,
    /// Delete a hosting's certificate (falls back to a self-signed one).
    Delete {
        selector: String,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum DnsCmd {
    /// Does the domain's A/AAAA point at this node?
    Check { domain: String },
    /// Show the domain's SPF record and a suggested one.
    Spf { domain: String },
}

/// Plugin actions `hctl wp plugin` accepts.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum PluginAction {
    Install,
    Activate,
    Deactivate,
    Update,
    UpdateAll,
    Delete,
    AutoUpdateOn,
    AutoUpdateOff,
}

/// Theme actions `hctl wp theme` accepts.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ThemeAction {
    Install,
    Activate,
    Update,
    UpdateAll,
    Delete,
}

#[derive(Subcommand, Debug)]
pub enum WpCmd {
    /// Is WordPress installed, and which version?
    Status { selector: String },
    /// Is the site answering, or is WordPress dying with a fatal error?
    FatalCheck { selector: String },
    /// List plugins with pending updates.
    Plugins { selector: String },
    /// Install / activate / deactivate / update / delete a plugin.
    Plugin {
        selector: String,
        #[arg(value_enum)]
        action: PluginAction,
        /// Plugin slug (or a zip URL for install). Not needed for update-all.
        #[arg(required_if_eq_any = [
            ("action", "install"), ("action", "activate"), ("action", "deactivate"),
            ("action", "update"), ("action", "delete"),
            ("action", "auto-update-on"), ("action", "auto-update-off"),
        ])]
        slug: Option<String>,
        /// install: leave the plugin inactive.
        #[arg(long)]
        no_activate: bool,
    },
    /// List themes.
    Themes { selector: String },
    /// Install / activate / update / delete a theme.
    Theme {
        selector: String,
        #[arg(value_enum)]
        action: ThemeAction,
        /// Theme slug (or a zip URL for install). Not needed for update-all.
        #[arg(required_if_eq_any = [
            ("action", "install"), ("action", "activate"),
            ("action", "update"), ("action", "delete"),
        ])]
        slug: Option<String>,
    },
    /// Park a plugin's folder so a site that fatals on it boots again.
    DisablePlugin { selector: String, slug: String },
    /// Put back a plugin parked by `disable-plugin` (left inactive).
    RestorePlugin { selector: String, slug: String },
    /// Set a WordPress user's password.
    ResetPassword {
        selector: String,
        /// WordPress login or e-mail.
        wp_user: String,
        /// Read the new password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Check plugins, themes and core for known-vulnerable versions.
    VulnScan { selector: String },
    /// Verify core + plugin checksums and scan for malware.
    IntegrityScan { selector: String },
    /// Re-download WordPress core files over the existing ones.
    CoreRepair { selector: String },
}

#[derive(Subcommand, Debug)]
pub enum DbCmd {
    /// Set a new password for the hosting's database user.
    ResetPassword {
        selector: String,
        /// Read the new password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum FtpCmd {
    /// List every FTP login on the node.
    List,
    /// Diagnose one hosting's FTP setup.
    Check { selector: String },
    /// Repair one hosting's FTP (landing directory, ownership, traversal).
    Repair { selector: String },
    /// Diagnose a hosting's file permissions.
    Perms { selector: String },
    /// Set the hosting's main FTP password.
    SetPassword {
        selector: String,
        /// Read the new password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Turn the hosting's main FTP login off (clears its password).
    Disable { selector: String },
    /// List a hosting's extra FTP logins.
    Logins { selector: String },
    /// Rewrite the node-wide FTP server config.
    RepairNode,
    /// Turn node-wide FTPS on (required) or off.
    ///
    /// The OFF direction is the reason this exists: enabling FTPS can lock
    /// out a client, and the operator must not need a working browser
    /// session to undo it.
    Ftps {
        #[arg(long)]
        off: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum MailCmd {
    /// Postfix mode, relay, queue and recent log lines.
    Status,
    /// Send a test message through the local sendmail.
    Test { to: String },
    /// Retry everything in the mail queue now.
    Flush,
    /// Discard everything in the mail queue.
    Clear {
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Panel e-mail log (notifications, reports, …).
    Log {
        /// Only mail about this hosting (id or domain).
        #[arg(long)]
        hosting: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum DkimCmd {
    /// Show DKIM state and the DNS record to publish.
    Status { selector: String },
    /// Generate a key and start signing.
    Enable { selector: String },
    /// Stop signing.
    Disable { selector: String },
    /// Check the published DNS record against the key.
    Verify { selector: String },
}

#[derive(Subcommand, Debug)]
pub enum CronCmd {
    /// Print the hosting's crontab.
    List { selector: String },
    /// Replace the hosting's crontab with a file ("-" = stdin).
    Set { selector: String, file: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum BanCmd {
    /// List active bans.
    List {
        /// Only bans scoped to this hosting (id or domain).
        #[arg(long)]
        hosting: Option<String>,
    },
    /// Ban an IP address (node-wide unless --hosting).
    Add {
        ip: String,
        #[arg(long, default_value = "manual ban (hctl)")]
        reason: String,
        /// Lift automatically after this long (e.g. 3600, 30m, 12h, 7d). Default: permanent.
        #[arg(long, value_parser = util::parse_duration)]
        ttl: Option<i64>,
        /// Only for this hosting (id or domain).
        #[arg(long)]
        hosting: Option<String>,
    },
    /// Lift a ban.
    Remove {
        ip: String,
        /// The hosting the ban is scoped to (id or domain).
        #[arg(long)]
        hosting: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum FirewallCmd {
    /// Show the firewall backend and open ports.
    Status,
    /// Keep a pending default-drop policy (stops the automatic rollback).
    Confirm,
    /// Switch the firewall back to accept-by-default (lock-out escape hatch).
    DisableDrop {
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    /// Health of every service Hyperion depends on.
    List,
    /// Restart one service (whitelisted names only).
    Restart { name: String },
}

#[derive(Subcommand, Debug)]
pub enum MonitorCmd {
    /// Uptime overview for every monitored hosting.
    List,
    /// Monitor config and recent samples for one hosting.
    Get { selector: String },
    /// Probe one hosting right now.
    Probe { selector: String },
}

#[derive(Subcommand, Debug)]
pub enum JobCmd {
    /// List recent background jobs.
    List {
        /// Only this kind (e.g. backup, hosting_delete, panel_import).
        #[arg(long)]
        kind: Option<String>,
        /// Only this state (running | done | failed | cancelled).
        #[arg(long)]
        state: Option<String>,
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },
    /// Show one job with its log tail.
    Get { id: String },
    /// Follow a job until it finishes; exits 1 if it failed.
    Wait {
        id: String,
        /// Give up after this many seconds (0 = never).
        #[arg(long, default_value_t = 0)]
        timeout: u64,
    },
}

/// Built-in panel roles.
#[derive(ValueEnum, Clone, Copy, Debug)]
#[value(rename_all = "snake_case")]
pub enum Role {
    SuperAdmin,
    Admin,
    Operator,
    Customer,
    Viewer,
}

#[derive(Subcommand, Debug)]
pub enum UserCmd {
    /// List panel users.
    List,
    /// Create a panel user.
    Create {
        username: String,
        #[arg(long)]
        email: String,
        #[arg(long, value_enum, default_value_t = Role::Operator)]
        role: Role,
        /// Read the password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Set a user's password (username or id).
    ResetPassword {
        user: String,
        /// Read the new password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Change a user's built-in role.
    SetRole {
        user: String,
        #[arg(value_enum)]
        role: Role,
    },
    /// Lock a user out of the panel.
    Lock {
        user: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Let a locked user sign in again.
    Unlock { user: String },
    /// Remove a user's two-factor enrollment (lost phone).
    #[command(name = "disable-2fa")]
    Disable2fa { user: String },
    /// Delete a panel user.
    Delete {
        user: String,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum NodeCmd {
    /// List enrolled nodes (run on the master).
    List,
    /// This node's load, memory and hosting counts.
    Stats,
    /// Set a node's display label (run on the master).
    Label { node_id: String, label: String },
    /// Stop placing new hostings on a node (run on the master).
    Drain {
        node_id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Accept new hostings on a node again (run on the master).
    Undrain { node_id: String },
    /// Remove a node from the cluster (run on the master).
    Remove {
        node_id: String,
        /// Remove even if hostings still reference it (they become orphans).
        #[arg(long)]
        force: bool,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Forget a node's pinned TLS / signing keys so it re-pins (run on the master).
    ResetCrypto { node_id: String },
    /// Re-point hostings from a dead node id onto a live one (orphan
    /// adoption). Use after a box re-enrolled under a new id so its
    /// hostings still carry the old, now-removed id. Run on the master.
    Reassign {
        /// The dead/old node id the hostings currently reference.
        #[arg(long)]
        from: String,
        /// The live, enrolled node id to move them to (the same box).
        #[arg(long)]
        to: String,
    },
    /// Update this node: OS packages (--apt) and/or Hyperion (--hyperion).
    Update {
        /// Run apt upgrade.
        #[arg(long)]
        apt: bool,
        /// Run Hyperion's update.sh.
        #[arg(long)]
        hyperion: bool,
        /// Snapshot first and roll back if the health check fails.
        #[arg(long)]
        safe: bool,
        /// Follow the run until it finishes.
        #[arg(long, short)]
        follow: bool,
    },
    /// State and log tail of the last `node update`.
    UpdateStatus,
    /// Is a newer Hyperion release available?
    UpdateCheck {
        /// Ask GitHub now instead of using the cached answer.
        #[arg(long)]
        refresh: bool,
    },
    /// Pending OS package updates and whether a reboot is required.
    OsUpdates {
        /// Refresh the package index first (apt update).
        #[arg(long)]
        refresh: bool,
    },
    /// Diagnose a read-only root or /usr, and repair it with --fix.
    FsCheck {
        #[arg(long)]
        fix: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum AgentCmd {
    /// Clear the pinned master_rpc_pubkey so the next heartbeat re-adopts
    /// the master's CURRENT key. Use this on a worker after you have
    /// deliberately rotated the master's remote-RPC key — the agent
    /// otherwise refuses a silently-changed key (anti-MITM).
    Repin,
    /// Show the agent's effective configuration (secrets masked).
    Config,
}

#[derive(Subcommand, Debug)]
pub enum StatsCmd {
    /// This node's totals.
    Node,
    /// Every node's totals (run on the master).
    Cluster,
    /// One line per hosting: disk, bandwidth, requests, memory, CPU.
    Sites,
}

#[derive(Subcommand, Debug)]
pub enum AuditCmd {
    /// Verify the audit log's hash chain has not been tampered with.
    Verify,
    /// Search the audit log.
    Search(AuditSearchArgs),
}

#[derive(Args, Debug)]
pub struct AuditSearchArgs {
    /// Free text (actor, target, domain, …).
    #[arg(long, short)]
    pub query: Option<String>,
    /// Exact action, e.g. hosting.create.
    #[arg(long)]
    pub action: Option<String>,
    /// Only failed actions.
    #[arg(long)]
    pub failed: bool,
    #[arg(long, default_value_t = 100)]
    pub limit: i64,
}

#[tokio::main]
async fn main() {
    quiet_on_broken_pipe();
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("hctl: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Rust ignores SIGPIPE, so `println!` into a closed pipe
/// (`hctl stats sites | head`) panicked with "Broken pipe". Exit the way a
/// SIGPIPE'd Unix tool does (status 141, no message) instead — without the
/// `unsafe` a `signal(SIGPIPE, SIG_DFL)` call would need.
fn quiet_on_broken_pipe() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let p = info.payload();
        let msg = p
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| p.downcast_ref::<&str>().copied())
            .unwrap_or("");
        if msg.contains("Broken pipe") || msg.contains("BrokenPipe") {
            std::process::exit(141);
        }
        default(info)
    }));
}

async fn run(cli: Cli) -> anyhow::Result<i32> {
    match &cli.cmd {
        // Remote commands talk to the HTTP /api/v1 edge, not the local socket.
        Cmd::Remote { conn, cmd } => {
            remote::run(conn, cmd).await?;
            return Ok(0);
        }
        Cmd::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), "hctl", &mut std::io::stdout());
            return Ok(0);
        }
        _ => {}
    }
    let out = exec::execute(&cli.socket, &cli.cmd).await?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&out.resp)?);
    } else {
        print::print_pretty(&out.resp);
    }
    // Secrets this run generated (passwords). On stdout next to the
    // human view; on stderr under --json so stdout stays valid JSON.
    for note in &out.notes {
        if cli.json {
            eprintln!("{note}");
        } else {
            println!("{note}");
        }
    }
    Ok(if matches!(out.resp, Response::Error(_)) || out.failed {
        1
    } else {
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
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
            Cmd::Hosting(HostingCmd::Create { domain, .. }) => assert_eq!(domain, "ex.cz"),
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn cli_parses_info() {
        let cli = Cli::parse_from(["hctl", "info"]);
        assert!(matches!(cli.cmd, Cmd::Info));
    }

    #[test]
    fn json_flag_works_after_the_subcommand() {
        // `--json` used to be accepted only before the subcommand, so the
        // natural `hctl hosting list --json` was a parse error.
        let cli = Cli::parse_from(["hctl", "hosting", "list", "--json"]);
        assert!(cli.json);
        let cli = Cli::parse_from(["hctl", "--json", "info"]);
        assert!(cli.json);
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

    #[test]
    fn set_limits_accepts_old_flag_names_and_sizes() {
        let cli = Cli::parse_from([
            "hctl",
            "hosting",
            "set-limits",
            "a.cz",
            "--disk-hard-bytes",
            "10G",
            "--bw-monthly",
            "none",
        ]);
        match cli.cmd {
            Cmd::Hosting(HostingCmd::SetLimits {
                disk_hard,
                bw_monthly,
                php_memory_mb,
                ..
            }) => {
                assert_eq!(
                    disk_hard,
                    Some(util::SizeLimit(Some(10 * 1024 * 1024 * 1024)))
                );
                assert_eq!(bw_monthly, Some(util::SizeLimit(None)));
                assert_eq!(php_memory_mb, None);
            }
            _ => panic!("wrong"),
        }
    }

    #[test]
    fn cert_renew_is_an_alias_of_renew_all() {
        // Error messages across the agent tell operators to run
        // `hctl cert renew`; it must exist.
        let cli = Cli::parse_from(["hctl", "cert", "renew"]);
        assert!(matches!(cli.cmd, Cmd::Cert(CertCmd::RenewAll)));
    }

    #[test]
    fn cert_issue_is_an_alias_of_request() {
        let cli = Cli::parse_from(["hctl", "cert", "issue", "example.com"]);
        assert!(matches!(cli.cmd, Cmd::Cert(CertCmd::Request { .. })));
    }

    #[test]
    fn plugin_update_all_needs_no_slug_but_activate_does() {
        assert!(Cli::try_parse_from(["hctl", "wp", "plugin", "a.cz", "update-all"]).is_ok());
        assert!(Cli::try_parse_from(["hctl", "wp", "plugin", "a.cz", "activate"]).is_err());
    }

    #[test]
    fn audit_keeps_bare_limit_form() {
        let cli = Cli::parse_from(["hctl", "audit", "--limit", "5"]);
        match cli.cmd {
            Cmd::Audit { limit, cmd: None } => assert_eq!(limit, 5),
            _ => panic!("wrong"),
        }
        let cli = Cli::parse_from(["hctl", "audit", "verify"]);
        assert!(matches!(
            cli.cmd,
            Cmd::Audit {
                cmd: Some(AuditCmd::Verify),
                ..
            }
        ));
    }

    /// Every leaf command has a `### hctl …` entry in docs/cli.md, and
    /// every entry there names a real command. Keeps the reference honest.
    #[test]
    fn docs_cover_every_command() {
        fn walk(cmd: &clap::Command, prefix: &str, out: &mut Vec<String>) {
            let subs: Vec<_> = cmd
                .get_subcommands()
                .filter(|c| c.get_name() != "help")
                .collect();
            if subs.is_empty() {
                out.push(prefix.to_string());
            }
            for s in subs {
                walk(s, &format!("{prefix} {}", s.get_name()), out);
            }
        }
        let mut leaves = Vec::new();
        walk(&Cli::command(), "hctl", &mut leaves);
        // `audit` is both a command (bare form) and a group.
        leaves.push("hctl audit".into());

        let docs =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/cli.md"))
                .expect("docs/cli.md");
        let documented: Vec<String> = docs
            .lines()
            .filter_map(|l| l.strip_prefix("### "))
            .filter(|l| l.starts_with("hctl"))
            .map(|l| l.trim().to_string())
            .collect();

        let missing: Vec<_> = leaves.iter().filter(|l| !documented.contains(l)).collect();
        assert!(
            missing.is_empty(),
            "commands missing from docs/cli.md: {missing:?}"
        );
        let stale: Vec<_> = documented.iter().filter(|d| !leaves.contains(d)).collect();
        assert!(
            stale.is_empty(),
            "docs/cli.md documents unknown commands: {stale:?}"
        );
    }
}
