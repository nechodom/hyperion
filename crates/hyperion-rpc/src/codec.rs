//! JSON length-prefixed framing.
//!
//! Each frame on the wire is `u32be length || JSON bytes`.
//! `MAX_FRAME` is enforced both at write and read.

use crate::{
    error::RpcError,
    wire::{AgentInfo, DeleteOpts, HostingCreateReq, HostingCreated, HostingSelector},
};
use hyperion_types::{
    BackupRunWire, CertInfo, CertIssueRequest, CertRenewResult, ClusterStats, DashboardAlert,
    DnsCheckResult, ExpiringHosting, HostingDetail, HostingExpiry, HostingLimits, HostingProfile,
    HostingStats, HostingSummary, HostingUsageBucket, NodeInviteMint, NodeInviteSummary, NodeStats,
    NodeSummary, ProfileApply, ProfileInput, SuspendReason, WpInstallRequest, WpInstallStatus,
};
use hyperion_validate::Domain;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single JSON frame (length-prefixed).
///
/// History:
///   v0: 4 MiB. Plugin / theme upload (WpAssetUpload) blew past
///       this on 17 MB ZIPs because Vec<u8> serialised as a JSON
///       byte-array balloons to ~4x the binary size.
///   v1: Switched WpAssetUpload/Replace `bytes` to base64-encoded
///       String (~1.37x wire), and raised the cap to 128 MiB so
///       the 100 MB web body limit + base64 overhead + envelope
///       all fit comfortably with headroom for backup restores.
///
/// The cap is shared by Unix-socket RPC (master ↔ local agent)
/// and signed HTTPS RPC (master ↔ worker on :9443). The latter
/// is bounded by network MTU rather than memory pressure, so the
/// real ceiling is whatever the operator's plumbing tolerates.
pub const MAX_FRAME: usize = 128 * 1024 * 1024;

/// Default `limit` for `Request::JobList` when the caller omits one.
/// 50 is enough for the dashboard "recent jobs" widget without
/// blowing past frame size; the explicit cap is 1000 server-side.
fn default_job_limit() -> i64 {
    50
}

/// A PEM blob carried inside an RPC request. On the wire it is just its
/// inner string (`#[serde(transparent)]`), but its `Debug` deliberately
/// prints nothing — so the `debug!(?req, "received request")` at the
/// socket boundary can't spill an uploaded **private key** (or a wall of
/// cert text) into the agent log. Use [`RedactedPem::into_inner`] to get
/// the bytes; `String` converts in via `Into`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct RedactedPem(pub String);

impl RedactedPem {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<String> for RedactedPem {
    fn from(s: String) -> Self {
        RedactedPem(s)
    }
}

impl std::fmt::Debug for RedactedPem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactedPem(<redacted>)")
    }
}

/// A `field → value` config map carried in an RPC request. On the wire it is
/// exactly its inner `BTreeMap` (`#[serde(transparent)]`), but its `Debug`
/// masks the VALUE of any secret-looking key (password / secret / token /
/// passphrase / webhook / key) so the `debug!(?req, "received request")` at
/// the socket boundary can't spill an SMTP password, S3 secret key, or Slack
/// webhook into the agent log. Non-secret keys (section names, hosts, ports,
/// booleans) still print, which keeps the log useful for config writes. Use
/// [`RedactedFields::into_inner`] to get the map back; a `BTreeMap` converts
/// in via `Into`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(transparent)]
pub struct RedactedFields(pub std::collections::BTreeMap<String, String>);

impl RedactedFields {
    pub fn into_inner(self) -> std::collections::BTreeMap<String, String> {
        self.0
    }

    /// True when the key names a credential whose value must not be logged.
    /// Deliberately broad (substring match): over-redaction only costs a
    /// little debug visibility, while a missed secret costs a log leak.
    fn is_secret_key(key: &str) -> bool {
        let k = key.to_ascii_lowercase();
        [
            "password",
            "secret",
            "token",
            "passphrase",
            "webhook",
            "key",
        ]
        .iter()
        .any(|needle| k.contains(needle))
    }
}

impl From<std::collections::BTreeMap<String, String>> for RedactedFields {
    fn from(m: std::collections::BTreeMap<String, String>) -> Self {
        RedactedFields(m)
    }
}

impl std::fmt::Debug for RedactedFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for (k, v) in &self.0 {
            if Self::is_secret_key(k) {
                m.entry(k, &"<redacted>");
            } else {
                m.entry(k, v);
            }
        }
        m.finish()
    }
}

// `IntoStaticStr` gives `<&'static str>::from(&req)` = the variant name, so the
// rpc-server can log WHICH request arrived without formatting its params via
// `Debug` (params can carry plaintext secrets — passwords, tokens, S3 keys,
// webhooks — that `debug!(?req)` would otherwise spill into the agent log).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, strum::IntoStaticStr)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    AgentInfo,
    /// Operator escape hatch (Block B re-pin): clear the pinned
    /// master_rpc_pubkey so the next heartbeat re-adopts the master's
    /// current key after a deliberate master-key rotation.
    AgentRepin,
    HostingCreate(HostingCreateReq),
    HostingList,
    HostingGet(HostingSelector),
    HostingDelete {
        sel: HostingSelector,
        opts: DeleteOpts,
    },
    HostingSetLimits {
        sel: HostingSelector,
        limits: HostingLimits,
    },
    HostingGetLimits(HostingSelector),
    HostingSuspend {
        sel: HostingSelector,
        reason: SuspendReason,
    },
    HostingResume(HostingSelector),
    /// Change a hosting's PHP runtime version. The agent will tear
    /// down the old FPM pool, persist the new version, bring up the
    /// new pool, re-apply per-hosting PHP limits, and rewrite the
    /// nginx vhost so fastcgi_pass points at the new socket. Fails
    /// if the hosting isn't PHP-kind or is suspended/deleting.
    HostingSetPhpVersion {
        sel: HostingSelector,
        version: hyperion_types::PhpVersion,
    },
    TrashList,
    TrashRestore(HostingSelector),
    TrashPurge(HostingSelector),
    /// Apply per-hosting vhost options. See `AgentRpc::hosting_set_vhost_options`.
    HostingSetVhostOptions {
        sel: HostingSelector,
        options: hyperion_types::VhostOptions,
        /// `None` = leave existing hash alone. `Some("")` also
        /// treated as "leave alone" by the agent.
        basic_auth_password: Option<String>,
    },
    /// Replace a hosting's alias domains (SANs). Rewrites nginx server_name +
    /// reloads. New aliases are not covered by the existing cert until re-issued.
    HostingSetAliases {
        sel: HostingSelector,
        aliases: Vec<hyperion_validate::Domain>,
    },
    HostingSetWpDebug {
        sel: HostingSelector,
        enabled: bool,
        log: bool,
        display: bool,
    },
    HostingSetRedis {
        sel: HostingSelector,
        enabled: bool,
    },
    HostingRotateRedisPassword {
        sel: HostingSelector,
    },
    HostingRotateWpDebugLog {
        sel: HostingSelector,
    },
    HostingUsage {
        sel: HostingSelector,
        limit: i64,
    },
    HostingSetExpiry {
        sel: HostingSelector,
        expiry: HostingExpiry,
    },
    HostingGetExpiry(HostingSelector),
    HostingClearExpiry(HostingSelector),
    /// Generic per-hosting key/value store (notes, tags, …). Keyed by
    /// the hosting's ULID string directly (panel-side metadata, not
    /// node-specific) so no selector resolution is needed.
    HostingKvSet {
        hosting_id: String,
        key: String,
        value: String,
    },
    HostingKvList {
        hosting_id: String,
    },
    UpcomingExpiries {
        within_seconds: i64,
    },
    SchedulerTick,
    BackupNow {
        sel: HostingSelector,
        /// Enabled S3 targets resolved on the master (secrets inline) — the
        /// node uploads to these after the local backup. Empty for internal /
        /// transient backups. `#[serde(default)]` so a pre-field master/worker
        /// pair stays compatible.
        #[serde(default)]
        s3_targets: Vec<hyperion_types::S3BackupTarget>,
    },
    BackupList {
        sel: HostingSelector,
        limit: i64,
    },
    InviteCreate {
        label: String,
        ttl_secs: i64,
    },
    InviteList,
    InviteRevoke {
        token_hash: String,
    },
    AuditList {
        limit: i64,
    },
    CertIssue {
        domain: Domain,
    },
    CertRenewAll,
    WpInstall {
        sel: HostingSelector,
        req: WpInstallRequest,
    },
    WpStatus {
        sel: HostingSelector,
    },
    DnsCheck {
        domain: Domain,
    },
    DnsSpfCheck {
        domain: Domain,
    },
    CertIssueAcme {
        sel: HostingSelector,
        req: CertIssueRequest,
    },
    /// Phase 1 of a DNS-01 wildcard issuance. `provider` is "manual"
    /// (default) or "cloudflare". Manual returns the TXT records to
    /// publish; cloudflare publishes them + finishes in one shot.
    CertDns01Begin {
        sel: HostingSelector,
        staging: bool,
        provider: String,
    },
    /// Phase 2 of a manual DNS-01 issuance — the TXT is live, validate
    /// + install the cert.
    CertDns01Finish {
        sel: HostingSelector,
    },
    /// DNS-01 phase 1 for a bare domain NOT tied to a hosting — a test
    /// node's `*.<base>` wildcard, issued once and reused by every
    /// auto-subdomain. `email` falls back to the agent `[acme]` default
    /// when `None`.
    CertDns01BeginDomain {
        domain: Domain,
        #[serde(default)]
        email: Option<String>,
        staging: bool,
        provider: String,
    },
    /// DNS-01 phase 2 for a bare (hosting-less) domain.
    CertDns01FinishDomain {
        domain: Domain,
    },
    /// Install an operator-supplied certificate (non-ACME: private CA,
    /// pre-purchased, or self-signed bootstrap). The service validates the
    /// PEM, confirms the key matches the cert and the cert covers the
    /// hosting's domain + aliases, then marks it `renewal_type = "manual"`
    /// so the ACME sweep never overwrites it.
    CertUpload {
        sel: HostingSelector,
        cert_pem: RedactedPem,
        key_pem: RedactedPem,
        #[serde(default)]
        ca_bundle_pem: Option<RedactedPem>,
    },
    HostingStats {
        sel: HostingSelector,
    },
    NodeStats,
    ClusterStats,
    NodeMetricsHistory {
        /// Max samples to return (clamped 1..=2000). Typical: 48 for
        /// ~4 hours @ 5min tick.
        limit: i64,
    },
    /// Set or clear the per-hosting ACME contact email override.
    /// `email: None` means "clear → fall back to agent-wide default".
    SetHostingAcmeEmail {
        sel: HostingSelector,
        email: Option<String>,
    },
    /// Get status of all system services Hyperion depends on
    /// (nginx, mariadb, postgresql, php-fpm versions, vsftpd, etc.)
    /// for the /health page + dashboard widget.
    ServicesHealth,
    /// Dump the node's firewall ruleset. Tries `nft list ruleset`
    /// first (modern Debian); falls back to `iptables -L -n -v`
    /// when nftables isn't installed or returns empty. Read-only —
    /// the operator inspects, doesn't mutate, via this RPC.
    FirewallList,
    /// Apply a hardcoded firewall template (one of the `port_templates()`
    /// IDs: "web" | "mail" | "hyperion" | "worker_rpc" | "ssh" | "ftp")
    /// on this node. Rules go into our own `inet hyperion` table —
    /// any pre-existing operator nft rules in other tables/chains
    /// stay untouched. Each rule carries a `hyperion:<template_id>`
    /// comment so the operator can grep them later. Persists to
    /// `/etc/nftables.conf` so the rules survive reboot.
    FirewallApplyTemplate {
        template_id: String,
    },
    /// `systemctl restart <name>` on a whitelisted unit. Restarts
    /// hyperion-agent itself are refused (would terminate this RPC
    /// session); operator must SSH for self-restart.
    ServiceRestart {
        name: String,
    },
    /// `apt-get install -y <pkg>` then `systemctl enable --now <name>`.
    /// `name` must be in the same whitelist as restart. Maps service
    /// name to apt package name (typically identical).
    ///
    /// Returns IMMEDIATELY after spawning the install in the
    /// background. Operator polls `ServiceInstallStatus` to follow
    /// the live log tail.
    ServiceInstall {
        name: String,
    },
    /// Read the state of the most-recent / in-progress
    /// service-install job. Empty when no install has ever run.
    ServiceInstallStatus,
    /// Upload bytes for a new WordPress asset (plugin or theme ZIP).
    /// The kind + filename + bytes already arrived on the web handler;
    /// this RPC asks the agent to write the file under
    /// /var/lib/hyperion/wp-assets/<id>/ + insert the DB row.
    /// Deduplicates on SHA-256 — re-uploading the same bytes returns
    /// the existing row id instead of inserting a second copy.
    WpAssetUpload {
        /// "plugin" or "theme".
        kind: String,
        /// Original filename the operator picked.
        original_name: String,
        /// Raw ZIP bytes, base64-encoded (standard alphabet, padding).
        /// JSON byte-arrays were ~4x the binary size and started
        /// hitting MAX_FRAME on real plugin uploads (17 MB ZIPs
        /// → ~65 MB JSON). Base64 is ~1.37x and survives JSON
        /// without escapes.
        bytes_b64: String,
        /// Web user who triggered the upload.
        uploaded_by: String,
    },
    /// List every uploaded asset. Used by /profiles/wp-assets.
    WpAssetList,
    /// Delete an asset row + the on-disk file. The asset is just a
    /// pointer-target for hosting profiles; deleting it doesn't
    /// touch hostings that previously installed the plugin from
    /// it. Profiles that still reference @asset:<id> will fail at
    /// next apply with a clear error.
    WpAssetDelete {
        id: i64,
    },
    /// Install one uploaded asset (plugin or theme ZIP) onto a
    /// WordPress hosting via wp-cli. Reuses the same `wp_cli`
    /// adapter the profile-apply flow uses, but lets the operator
    /// trigger a one-off install without creating a profile first.
    WpInstallFromAsset {
        sel: HostingSelector,
        asset_id: i64,
        /// Whether to also `wp plugin activate` / `wp theme activate`
        /// after install.
        activate: bool,
    },
    /// Replace an existing asset's on-disk ZIP. Keeps the asset's
    /// id, so profiles + tracking rows that reference `@asset:<id>`
    /// continue to work — they'll just install the NEW bytes next
    /// time around. Operator's intent: "I uploaded a newer version
    /// of this plugin, point the existing entry at it".
    WpAssetReplace {
        id: i64,
        original_name: String,
        /// See WpAssetUpload.bytes_b64.
        bytes_b64: String,
        uploaded_by: String,
    },
    /// Push the current bytes of `asset_id` onto every hosting that
    /// the master previously dispatched a one-off / bulk install
    /// of this asset to (tracked in master-side `wp_asset_installs`).
    /// Each install runs `wp <kind> install --force` so the new
    /// version replaces the old. Returns (installed_ok,
    /// installed_failed, error_messages_tail).
    WpAssetReinstallAll {
        asset_id: i64,
        /// Force activate even if some hostings had activate=false
        /// originally. None = use the per-row activate value
        /// recorded at last install.
        force_activate: Option<bool>,
    },
    /// `wp theme list --format=json` against this hosting.
    WpThemeList {
        hosting: HostingSelector,
    },
    /// Whitelisted theme action via wp-cli (activate / delete /
    /// install / update / update-all).
    WpThemeAction {
        sel: HostingSelector,
        slug: String,
        action: hyperion_types::WpThemeAction,
    },
    /// Scan a hosting's installed plugins + themes against the
    /// Wordfence Intelligence feed (cached on the owning node).
    WpVulnScan {
        hosting: HostingSelector,
    },
    /// Every hosting's last stored vuln scan on this node — drives the
    /// cluster-wide vulnerability dashboard.
    VulnFindingsList,
    /// Create a `staging.<domain>` copy of a hosting (files + DB + WP
    /// URL rewrite). Same-node only. `staging_domain` overrides the
    /// default `staging.<domain>` hostname when `Some` + non-empty.
    WpStagingCreate {
        sel: HostingSelector,
        #[serde(default)]
        staging_domain: Option<String>,
    },
    /// Push the `staging.<domain>` site back over production, after a
    /// pre-push safety backup of prod. `staging_domain` selects the
    /// custom staging hostname (must match what create used).
    WpStagingPush {
        sel: HostingSelector,
        #[serde(default)]
        staging_domain: Option<String>,
    },
    /// Run system + hyperion updates on the target node. Both jobs
    /// run in the background; the call returns immediately with a
    /// "started" marker. Operator polls `NodeUpdateStatus` (see
    /// below) to follow the log tail.
    NodeUpdateRun {
        /// `apt-get update && apt-get dist-upgrade -y --quiet`.
        /// Typically 1–10 min depending on what's outdated.
        do_apt: bool,
        /// `/opt/hyperion/packaging/install/update.sh`. Rebuilds
        /// hyperion-agent (+ hyperion-web on master) from
        /// upstream main + restarts the services.
        do_hyperion: bool,
    },
    /// Read the last N kB of the in-progress / most-recent update
    /// log. Empty when no update has ever run on this node.
    NodeUpdateStatus,
    /// Update one section of agent.toml. Validated server-side per
    /// section + field. Operator must `systemctl restart hyperion-agent`
    /// to load the new values (UI tells them).
    AgentConfigUpdate {
        /// "acme" | "email" | "slack" | "backup_remote" | "backup_retention"
        section: String,
        /// Field → string-encoded value. Service knows the expected
        /// types per (section, field) and parses accordingly. Wrapped so
        /// the request `Debug` masks secret values (S3 keys, Slack webhook).
        fields: RedactedFields,
    },
    /// Set THIS node's `[email]` config and apply it (writes agent.toml,
    /// reconfigures postfix live, schedules a self-restart to refresh the
    /// agent's in-memory config). Dispatchable to any node — that's how the
    /// panel edits per-node mail without SSH. `fields` is redacted in `Debug`
    /// so the SMTP password can't leak into the worker's request log.
    EmailConfigSet {
        fields: RedactedFields,
    },
    /// Report whether THIS node has a usable Cloudflare DNS-01 token (drives the
    /// Settings card + whether one-click DNS-01-via-Cloudflare is offered).
    CloudflareTokenStatus,
    /// Validate + persist THIS node's Cloudflare DNS-01 token (0600). The token
    /// is `RedactedPem` so it can't leak into a worker's request log.
    CloudflareTokenSet {
        token: RedactedPem,
    },
    /// Compare the running binary's git SHA against the upstream
    /// `rolling` release tag's SHA. Cached agent-side for an hour
    /// so the dashboard banner doesn't hammer the GitHub API.
    UpdateCheck {
        /// If true, bypass the cache and re-probe the upstream.
        force_refresh: bool,
    },
    /// Produce a migration bundle (archive + manifest) for `hosting`.
    /// The bundle lives on the source node's disk; the operator
    /// transfers it out-of-band and imports on the target.
    HostingExport {
        hosting: HostingSelector,
    },
    /// Read one file from `/var/lib/hyperion/migration/<bundle_id>/`
    /// and return its raw bytes (base64). Used by the master to pull
    /// a bundle off a WORKER source during worker-to-X migration —
    /// the master then re-serves the bytes on its existing
    /// `/api/migration/bundle/<id>/<filename>` route so the target
    /// node sees one canonical download URL regardless of where
    /// the bundle was produced.
    ///
    /// `filename` is whitelisted: only "manifest.json" or
    /// "archive.tar.gz" are accepted.
    HostingMigrationFetchBundleFile {
        bundle_id: String,
        filename: String,
    },
    /// Import a migration bundle by manifest path. Sibling
    /// `archive.tar.gz` is expected next to the manifest.
    HostingImport {
        manifest_path: String,
    },
    /// Dry-run a third-party panel import (HestiaCP/CloudPanel) on this node.
    HostingImportPanelPlan {
        req: hyperion_import::ImportPanelReq,
    },
    /// Apply a third-party panel import on this node.
    HostingImportPanel {
        req: hyperion_import::ImportPanelReq,
    },
    /// Per-hosting (or cluster-wide) email log.
    EmailLogList {
        /// `None` returns the cluster-wide stream; `Some(hosting_id)`
        /// filters to that hosting only.
        hosting_id: Option<String>,
        limit: i64,
    },
    /// Outbound mail sent BY a hosted PHP site, captured by the
    /// site-mail-wrapper. Reads
    /// /var/lib/hyperion/site-mail/<system_user>.jsonl
    SiteEmailLogList {
        system_user: String,
        limit: i64,
    },
    /// Per-node: list every Linux user with an FTP-usable shadow
    /// password + map back to the matching hosting (if any).
    FtpAccountsList,
    /// Probe vsftpd at localhost with the given credentials.
    /// Returns Ok(true)=login ok, Ok(false)=auth refused, Err=transport.
    FtpVerifyLogin {
        user: String,
        password: String,
    },
    /// Probe localhost for a usable SMTP relay so the UI can
    /// pre-fill the email config form. Cheap — just TCP connect.
    EmailSmtpAutodetect,
    /// Read live MTA (postfix) state: mode, myhostname, relayhost,
    /// mailq depth, recent log tail. Drives the /settings MTA card.
    /// No remote network calls — all probes are local.
    MtaDiagnostics,
    /// Re-apply the boot-time postfix configuration on demand. Picks
    /// the right mode (relay vs direct-MX) based on the current
    /// [email] section. Used by the /settings "Reconfigure" button
    /// when the operator changed agent.toml without restarting
    /// hyperion-agent.
    MtaReconfigure,
    /// Send a one-line test email via `/usr/sbin/sendmail` (which is
    /// postfix once installed). Different from EmailSendTest which
    /// uses the lettre SMTP client directly — this exercises the
    /// PHP `mail()` → wrapper → sendmail → relay/MX chain end-to-end.
    MtaTestSend {
        to: String,
    },
    /// `postqueue -f` — tell postfix to attempt delivery of every
    /// deferred message now (instead of waiting for the next
    /// retry tick). Useful right after fixing the underlying
    /// connectivity issue (port 25 unblock, PTR fix).
    MtaQueueFlush,
    /// `postsuper -d ALL` — discard every queued message. Used
    /// when the operator gave up on stuck mail (deferred forever
    /// because the recipient is wrong / domain gone). Destructive
    /// — UI shows a type-to-confirm modal.
    MtaQueueClear,
    /// Provision the master panel on a public hostname. Writes
    /// `panel.hostname` to agent.toml, generates self-signed cert
    /// so nginx can start, writes the panel vhost
    /// (`/etc/nginx/sites-enabled/hyperion-panel.conf`), reloads
    /// nginx, then triggers a real ACME issuance in the
    /// background. Returns a status describing what landed.
    PanelProvision {
        hostname: String,
        /// When true, skip the DNS preflight (operator knows the
        /// record propagated but our resolver hasn't caught up).
        #[serde(default)]
        skip_dns_check: bool,
    },
    /// Read the current panel-vhost ACME progress for the live
    /// progress card on /settings#cluster. Returns None when no
    /// panel hostname is configured yet.
    PanelCertStatus,
    /// `mount -o remount,rw /` — attempt to flip the rootfs to
    /// read-write so apt-get can install packages. Used when the
    /// service-install preflight detects /usr is read-only.
    /// Refused (validation error) if /usr is already writable.
    RemountUsrRw,
    /// Full ROFS diagnose + auto-fix sequence. When `dry_run` is
    /// true we only gather the diagnostic state and return without
    /// running any fixes. When false we walk through:
    ///   1. `mount -o remount,rw /`
    ///   2. `chattr -i /usr` (if immutable attr was set)
    ///   3. `mount -o remount,rw /usr` (when /usr is a separate
    ///      mountpoint)
    /// Each step's outcome lands in the returned `FsDiagnostics`
    /// `fix_steps` so the UI can render a step-by-step report.
    FsDiagnoseAndFix {
        #[serde(default)]
        dry_run: bool,
    },
    /// Look up a single background job by id. Returns `None` if the
    /// id has been rotated out of the table (very rare; rows are
    /// retained for at least 30 days).
    JobGet {
        id: String,
    },
    /// List background jobs, newest first. `kind=None` returns all
    /// kinds; `state=None` returns all states. `limit` is clamped to
    /// 1..=1000 server-side.
    JobList {
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        state: Option<String>,
        #[serde(default = "default_job_limit")]
        limit: i64,
    },
    /// Insert a row in `web_sessions` immediately after a
    /// successful login. The `sid` comes from the signed-cookie
    /// Session token the panel mints. The agent is the source of
    /// truth for which sids are live; the cookie alone is no
    /// longer enough.
    WebSessionInsert {
        sid: String,
        user_id: i64,
        #[serde(default)]
        ip: Option<String>,
        #[serde(default)]
        user_agent: Option<String>,
    },
    /// Per-request liveness probe + last_seen update. Returns
    /// `Response::Bool(true)` when the session is live (row
    /// present, revoked_at IS NULL); `false` for revoked /
    /// missing rows (treat as anonymous).
    WebSessionTouch {
        sid: String,
    },
    /// Newest-first list of `user_id`'s sessions (used by
    /// /settings/sessions).
    WebSessionList {
        user_id: i64,
    },
    /// Flip `revoked_at`. Caller (panel) checks ownership before
    /// dispatching — server only enforces existence.
    WebSessionRevoke {
        sid: String,
        revoked_by: i64,
    },
    /// List configured off-site backup destinations.
    BackupTargetList,
    /// Create or update a backup target. `id=None` ⇒ insert.
    /// `secret_key` is the plaintext access secret; the agent
    /// writes it to /etc/hyperion/secrets/backup-<id>.key (mode
    /// 0600) and stores only the path back in the row.
    BackupTargetUpsert {
        id: Option<i64>,
        name: String,
        kind: String,
        endpoint: String,
        bucket: String,
        region: String,
        access_key_id: String,
        #[serde(default)]
        secret_key: Option<String>,
        #[serde(default)]
        age_recipient: Option<String>,
        retention_daily: i64,
        retention_weekly: i64,
        retention_monthly: i64,
        enabled: bool,
    },
    /// Delete a backup target. Existing backup_runs rows that
    /// reference it have target_id set to NULL (history is
    /// preserved).
    BackupTargetDelete {
        id: i64,
    },
    /// Probe the configured target with a small PUT + DELETE
    /// round-trip. Returns latency + a human-readable message.
    BackupTargetProbe {
        id: i64,
    },
    /// Read the current quota policy + usage report for one
    /// hosting. Returns zero-everywhere when no row exists.
    QuotaGet {
        hosting: HostingSelector,
    },
    /// Persist the policy + invoke `setquota` against the owner
    /// uid. Returns `Response::QuotaApplied` with the applied row
    /// (success) or `Response::Error` (validation / kernel failure).
    QuotaSet {
        hosting: HostingSelector,
        disk_soft_kib: i64,
        disk_hard_kib: i64,
        mem_limit_mib: i64,
        bw_soft_mib: i64,
        bw_hard_mib: i64,
        /// What to do when this hosting exceeds its disk hard cap:
        /// "notify" (default) or "suspend". Defaulted for back-compat so
        /// an older web binary's QuotaSet still decodes.
        #[serde(default)]
        exceed_action: String,
    },
    /// Automatically enable Linux kernel disk quotas on the filesystem
    /// carrying this hosting's home tree (edits /etc/fstab + remount +
    /// quotacheck + quotaon where possible).
    QuotaEnableKernel {
        hosting: HostingSelector,
    },
    /// Walk the entire audit_log hash chain and verify each row's
    /// `row_hash = BLAKE3(prev_hash || canonical_fields)`. Returns
    /// `Response::AuditVerifyChain { ok, broken_at_id, message }`
    /// where `ok=false` flags the first row that doesn't match —
    /// strong signal of either DB corruption or someone editing
    /// audit_log directly.
    AuditVerifyChain,
    /// Open a new background job row, returning a freshly-minted
    /// `job_id`. Called by the panel (or hctl) when it kicks off a
    /// tokio::spawn for migration / install / backup / clone / cert
    /// renewal / etc. Subsequent `JobProgress` + `JobFinish` calls
    /// reference the same id.
    JobStart {
        kind: String,
        target: Option<String>,
        #[serde(default)]
        payload_json: String,
        actor_label: String,
        #[serde(default)]
        actor_uid: i64,
    },
    /// Append a progress tick. `step_label` is what the UI shows
    /// big; `progress_pct` drives the bar; `log_append` is appended
    /// to the bounded `log_tail`. All three are independently
    /// optional in practice (empty string / 0 / empty are fine).
    JobProgress {
        id: String,
        step_label: String,
        progress_pct: i64,
        #[serde(default)]
        log_append: String,
    },
    /// Flip a job to a terminal state. `ok=false` records the
    /// `error` message for the UI; `ok=true` ignores it.
    JobFinish {
        id: String,
        ok: bool,
        #[serde(default)]
        error: Option<String>,
    },
    /// Import a migration bundle from a source node's signed URL.
    /// `base_url` is e.g. `https://source-master/api/migration/bundle/<id>`
    /// — the agent appends `/manifest.json?t=<token>` and
    /// `/archive.tar.gz?t=<token>`, downloads both, then runs the
    /// regular import.
    HostingImportFromUrl {
        base_url: String,
        token: String,
        /// When Some, the importer creates the new hosting under this
        /// domain instead of the one captured in the manifest. Used
        /// by `hosting clone` so the operator can duplicate
        /// `example.cz` as `staging.example.cz` on a different node
        /// without colliding with the live row. Default = None ⇒
        /// preserves migration semantics (use manifest.domain).
        #[serde(default)]
        override_domain: Option<String>,
        /// Likewise for aliases. Empty vec ⇒ use manifest aliases.
        #[serde(default)]
        override_aliases: Vec<String>,
    },
    /// List installed WordPress plugins for `hosting`.
    WpPluginList {
        hosting: HostingSelector,
    },
    /// Apply one plugin action via wp-cli. `slug` is the plugin
    /// folder name (ignored for `UpdateAll`).
    WpPluginAction {
        hosting: HostingSelector,
        slug: String,
        action: hyperion_types::WpPluginAction,
    },
    /// Delete a single backup run + its archive file(s) on disk.
    /// Refuses if the backup is still "running". Audits the action.
    BackupDelete {
        backup_id: i64,
    },
    /// View the agent's effective config — agent.toml minus secrets,
    /// plus a few derived bits (detected nginx user, cluster role).
    /// Operator-facing settings page reads from this.
    AgentConfigView,
    /// Send a test email through the configured SMTP relay to verify
    /// deliverability. Returns ok or a clean error string the
    /// operator can act on.
    EmailSendTest {
        to: String,
    },

    // ─── Web users / roles / 2FA ───────────────────────────────
    /// Verify a username + password. Does NOT mint a session — the web
    /// binary keeps its own session signer. Returns enough info for web
    /// to either mint a session or prompt for 2FA / show locked state.
    WebLogin {
        username: String,
        password: String,
        client_ip: Option<String>,
    },
    /// Second step of a 2FA-required login. `user_id` comes from a
    /// prior `WebLogin → NeedsTotp`. `code` is either the 6-digit TOTP
    /// or a backup code (the agent disambiguates by length).
    WebVerify2fa {
        user_id: i64,
        code: String,
    },
    /// List all web users (super_admin only — web enforces).
    WebUserList,
    /// Get one user's sanitised summary by id.
    WebUserGet {
        id: i64,
    },
    /// Create a new user directly (without invite). super_admin only.
    /// Returns the new user id.
    WebUserCreate {
        username: String,
        email: String,
        password: String,
        role: String,
    },
    /// Set a user's password. `current_password` is `Some` for a self-service
    /// change (the service re-verifies it) and `None` for a super_admin reset
    /// (already authorized at the web layer). The value is a secret but the
    /// rpc-server logs only the method name, so it never reaches the log.
    WebUserSetPassword {
        user_id: i64,
        new_password: String,
        #[serde(default)]
        current_password: Option<String>,
    },
    /// Change role. super_admin only.
    WebUserSetRole {
        user_id: i64,
        role: String,
    },
    /// Self-service import wizard token op (mint/resolve/update/list/cancel).
    /// One variant keeps the RPC surface small; the op enum carries the rest.
    ImportToken(hyperion_types::ImportTokenOp),
    /// List all custom roles (granular RBAC). Each summary carries a
    /// capability bitmask, its scope, and a live in-use count.
    RoleList,
    /// Create a custom role. `capabilities` is a plain bitmask. Returns
    /// the new role id.
    RoleCreate {
        name: String,
        capabilities: u64,
        scope_all: bool,
    },
    /// Update a custom role's name / capabilities / scope.
    RoleUpdate {
        id: i64,
        name: String,
        capabilities: u64,
        scope_all: bool,
    },
    /// Delete a custom role. Refuses if any user is still assigned it.
    RoleDelete {
        id: i64,
    },
    /// Assign a custom role to a user (links `custom_role_id`).
    WebUserSetCustomRole {
        user_id: i64,
        custom_role_id: i64,
    },
    /// Resolve a user's effective authorization (capabilities + scope).
    WebUserEffectiveRole {
        user_id: i64,
    },
    /// Lock / unlock a user. super_admin only.
    WebUserSetLocked {
        user_id: i64,
        locked: bool,
        reason: Option<String>,
    },
    /// Delete a user. super_admin only. Refuses to delete the last
    /// super_admin to prevent locking out the cluster.
    WebUserDelete {
        user_id: i64,
    },
    /// Start TOTP 2FA enrollment for `user_id` — returns secret + URL +
    /// fresh backup codes. The secret is stored on the user record but
    /// `totp_enrolled_at` stays NULL until `Web2faConfirmEnroll`.
    Web2faEnrollStart {
        user_id: i64,
    },
    /// Confirm enrollment with the first TOTP code. Flips
    /// `totp_enrolled_at` on success.
    Web2faConfirmEnroll {
        user_id: i64,
        code: String,
    },
    /// Disable 2FA on a user (admin override OR self-disable). Clears
    /// the secret + enrollment marker + backup codes.
    Web2faDisable {
        user_id: i64,
    },
    /// Grant a non-admin user access to one hosting at a specific
    /// level (`"read"` for viewer-style, `"manage"` for operator-style).
    /// super_admin / admin ignore this — they see everything.
    WebGrantHostingAccess {
        user_id: i64,
        hosting_id: String,
        level: String,
        granted_by: Option<i64>,
    },
    /// Revoke a previously granted hosting access.
    WebRevokeHostingAccess {
        user_id: i64,
        hosting_id: String,
    },
    /// List all access grants for a given hosting (used to render the
    /// per-hosting access tab).
    WebListHostingAccess {
        hosting_id: String,
    },

    /// List one directory under a hosting's htdocs root. Path is
    /// RELATIVE to htdocs; empty / "/" mean the root itself.
    /// Read-only — file browser MVP.
    HostingFileList {
        sel: HostingSelector,
        rel_path: String,
    },
    /// Read a single text file (≤ 1 MiB) under a hosting's htdocs root.
    /// Binary files are refused — UI offers a download link instead.
    HostingFileRead {
        sel: HostingSelector,
        rel_path: String,
    },
    /// Download any file (≤ 64 MiB) as raw bytes — used for binary
    /// files the inline reader refuses (images, PDFs, ZIPs).
    HostingFileDownload {
        sel: HostingSelector,
        rel_path: String,
    },
    /// Write or overwrite a file. Caller must have manage rights.
    /// `bytes` is base64-encoded for wire safety.
    HostingFileWrite {
        sel: HostingSelector,
        rel_path: String,
        bytes_b64: String,
    },
    /// Delete one file OR one empty directory.
    HostingFileDelete {
        sel: HostingSelector,
        rel_path: String,
    },
    /// Create one new empty directory.
    HostingFileMkdir {
        sel: HostingSelector,
        rel_path: String,
    },
    /// Rename / move a path inside the jail.
    HostingFileRename {
        sel: HostingSelector,
        from: String,
        to: String,
    },

    /// Cluster-wide monitor list — every enabled monitor on this
    /// node with computed 24h success rate + avg latency.
    MonitorOverview,
    /// Look up the avatar basename for one web_user.
    AvatarFilename {
        user_id: i64,
    },
    /// Request an email change: store the pending new_email +
    /// hashed code + send the code to the new address. Returns
    /// the (masked) email address so the UI can confirm where
    /// the code went without echoing the full address.
    EmailChangeRequest {
        user_id: i64,
        new_email: String,
        current_password: String,
    },
    /// Confirm an email change with the 6-digit code that landed
    /// in the new address's inbox.
    EmailChangeConfirm {
        user_id: i64,
        code: String,
    },
    /// Cancel a pending change.
    EmailChangeCancel {
        user_id: i64,
    },
    /// Set or clear the avatar basename. `None` clears.
    AvatarSet {
        user_id: i64,
        filename: Option<String>,
    },
    /// Read the per-hosting monitor config + sample history.
    MonitorGet {
        sel: HostingSelector,
    },
    /// Write the per-hosting monitor config.
    MonitorSet {
        sel: HostingSelector,
        enabled: bool,
        url_path: Option<String>,
        interval_secs: Option<i64>,
        alert_after_fails: Option<i64>,
        alert_email: Option<String>,
        alert_slack_webhook: Option<String>,
        alert_webhook_url: Option<String>,
    },
    /// Operator-driven manual probe (the "Test now" button). Always
    /// records a sample regardless of `monitor_enabled`.
    MonitorProbeNow {
        sel: HostingSelector,
    },
    /// One tick of the background monitor scheduler. Returns the count
    /// of hostings sampled.
    MonitorTick,

    StatsTick,
    BackupRestore {
        sel: HostingSelector,
        archive_path: String,
        /// Which parts of the snapshot to put back. Defaults to a full
        /// files+DB restore for older callers that omit it.
        #[serde(default)]
        mode: hyperion_types::BackupRestoreMode,
    },
    /// Stream one slice of a backup archive off the owning node for
    /// download. `len == 0` returns metadata only (total_size +
    /// filename) so the web layer can set Content-Length before the
    /// first byte. Chunked so arbitrarily-large archives never hit
    /// MAX_FRAME.
    BackupFetchChunk {
        backup_id: i64,
        offset: u64,
        len: u32,
    },
    /// Restore a backup archive into a BRAND-NEW hosting at `new_domain`
    /// (mirroring the source's php/db/kind), running `wp search-replace`
    /// afterwards when the snapshot is a WordPress site. Same-node only.
    BackupRestoreAsNew {
        sel: HostingSelector,
        archive_path: String,
        new_domain: String,
    },
    // ── Bell-icon notification feed ──
    NotificationsFeed {
        user_id: i64,
        limit: i64,
    },
    NotificationsMarkRead {
        user_id: i64,
        notification_id: i64,
    },
    NotificationsMarkAllRead {
        user_id: i64,
    },
    HostingLogs {
        sel: HostingSelector,
        log_kind: String,
        lines: i64,
    },
    CronList {
        sel: HostingSelector,
    },
    CronReplace {
        sel: HostingSelector,
        body: String,
    },
    EnrollConsume {
        token: String,
        caller_ip: String,
        node_id: String,
        label: String,
        agent_version: String,
        public_ip: Option<String>,
        /// Block B idempotent re-enrollment: the node_id + per-node secret
        /// the re-enrolling box already had on disk (node-id.json), if
        /// any. The master reuses the id on a matching secret (continuity)
        /// or adopts a free id; otherwise it mints a fresh one. `#[serde(
        /// default)]` so older agents that don't send these still enroll.
        #[serde(default)]
        prior_node_id: Option<String>,
        #[serde(default)]
        prior_secret: Option<String>,
    },
    NodesList,
    /// Cluster-wide certificate inventory — every cert this agent
    /// has issued or imported. Sorted by `not_after` ASC so the
    /// expiring-soonest sit at the top.
    CertOverview,
    /// Rename an enrolled node's display label. `node_id` is the
    /// immutable enrollment identifier; only `label` changes.
    NodeSetLabel {
        node_id: String,
        label: String,
    },
    /// Toggle a node's drain flag. `drain=true` marks the node as
    /// maintenance — auto-placer + create wizard skip it; existing
    /// hostings keep serving. `drain=false` lifts the flag.
    NodeSetDrain {
        node_id: String,
        drain: bool,
        #[serde(default)]
        reason: String,
    },
    /// Remove an enrolled node from the master's registry. Refuses
    /// unless `force=true` when hostings still reference the node —
    /// the UI surfaces the count and asks the operator to either
    /// migrate them away first or confirm the orphan-them path. The
    /// agent on the removed node keeps running locally; this RPC
    /// only mutates master state.
    NodeRemove {
        node_id: String,
        #[serde(default)]
        force: bool,
    },
    /// Block B orphan adoption: re-point every hosting routed to
    /// `from_node_id` onto the (enrolled) `to_node_id`. Used after a box
    /// re-enrolled under a new id so its hostings still carry the dead
    /// old id.
    NodeReassignHostings {
        from_node_id: String,
        to_node_id: String,
    },
    NodeHeartbeat {
        node_id: String,
        secret: String,
        agent_version: String,
        /// Worker's inbound-listener TLS SPKI pin (curl --pinnedpubkey
        /// form). `#[serde(default)]` so older agents that don't send it
        /// (and the enroll path) parse fine — the master keeps any
        /// previously-recorded pin via COALESCE. Block C, warn-only.
        #[serde(default)]
        tls_spki_pin: Option<String>,
    },
    WpResetPassword {
        sel: HostingSelector,
        wp_user: String,
        new_password: String,
    },
    DbResetPassword {
        sel: HostingSelector,
        new_password: String,
    },
    FtpSetPassword {
        sel: HostingSelector,
        new_password: String,
    },
    FtpDisable {
        sel: HostingSelector,
    },
    /// Current key-only SFTP status for a hosting's system user.
    SftpStatus {
        sel: HostingSelector,
    },
    /// Enable/disable key-only chrooted SFTP + replace the authorized
    /// public keys. `enabled=false` clears keys and drops group access.
    SftpSet {
        sel: HostingSelector,
        enabled: bool,
        public_keys: Vec<String>,
    },
    /// List active IP bans. `hosting_id = Some` filters to that hosting
    /// plus node-wide manual bans.
    BanList {
        hosting_id: Option<String>,
    },
    /// Add an IP ban. `ttl_secs = 0` ⇒ permanent.
    BanAdd {
        ip: String,
        hosting_id: Option<String>,
        reason: String,
        ttl_secs: i64,
        source: String,
    },
    /// Lift an IP ban.
    BanRemove {
        ip: String,
    },
    DashboardAlerts,
    ProfileList,
    ProfileGet {
        id: i64,
    },
    ProfileCreate(ProfileInput),
    ProfileUpdate {
        id: i64,
        input: ProfileInput,
    },
    ProfileDelete {
        id: i64,
    },
    /// Hosting ids currently on this profile (rows in hosting_profile_apply on
    /// THIS node). Fanned out across nodes + unioned for cluster-wide re-apply.
    ProfileUsage {
        id: i64,
    },
    /// (profile_id, live-hosting count) for every profile with apply rows on
    /// THIS node. Fanned out + summed for the cluster-wide "in use: N" badge.
    ProfileUsageCounts,
    ProfileApply {
        sel: HostingSelector,
        profile_id: i64,
        /// When true, apply limits + expiry + pricing but SKIP the
        /// profile's wp_plugins / wp_themes installs. The caller is
        /// doing item-by-item installs itself (via
        /// `ProfileWpItemInstall`) so it can report per-plugin
        /// progress. `#[serde(default)]` keeps old callers (and
        /// old masters talking to new agents) on the original
        /// everything-in-one behaviour.
        #[serde(default)]
        skip_wp_items: bool,
        /// The resolved profile, supplied by the master. `hosting_profiles`
        /// only lives in the master's DB, so a worker can't look it up by id —
        /// the master passes it inline. `None` (old callers) → the node falls
        /// back to its local DB (correct only when the node IS the master).
        #[serde(default)]
        profile: Option<hyperion_types::HostingProfile>,
    },
    ProfileGetApply {
        sel: HostingSelector,
    },
    /// Install ONE line of a profile's wp_plugins / wp_themes list
    /// on a hosting. `line` uses the same syntax as the profile
    /// fields: `slug`, `@asset:<id>`, trailing `!` = activate,
    /// `#` comments are rejected (callers filter those). The agent
    /// resolves `@asset:` to the on-disk ZIP and shells to wp-cli.
    /// Exists so the post-create WP install job can report
    /// per-item progress instead of one opaque "applying profile"
    /// step.
    ProfileWpItemInstall {
        sel: HostingSelector,
        /// "plugin" | "theme" — picks the wp-cli subcommand.
        item_kind: String,
        line: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", content = "result", rename_all = "snake_case")]
pub enum Response {
    AgentInfo(AgentInfo),
    /// Result of AgentRepin: the master_rpc_pubkey that was cleared
    /// (`None` if nothing was pinned).
    AgentRepin {
        cleared: Option<String>,
    },
    HostingCreate(HostingCreated),
    HostingList(Vec<HostingSummary>),
    HostingGet(HostingDetail),
    HostingDelete,
    HostingSetLimits(HostingLimits),
    HostingGetLimits(HostingLimits),
    HostingSuspend,
    HostingResume,
    /// Echoes the new (or already-current, on no-op) PHP version
    /// so the caller's UI flash can confirm.
    HostingSetPhpVersion(hyperion_types::PhpVersion),
    TrashList(Vec<hyperion_types::TrashEntry>),
    TrashRestore,
    TrashPurge,
    HostingSetVhostOptions(hyperion_types::VhostOptions),
    HostingSetAliases(hyperion_types::HostingDetail),
    HostingSetWpDebug(hyperion_types::WpExtras),
    HostingSetRedis(hyperion_types::WpExtras),
    HostingRotateRedisPassword(hyperion_types::WpExtras),
    HostingRotateWpDebugLog,
    HostingUsage(Vec<HostingUsageBucket>),
    HostingSetExpiry(HostingExpiry),
    HostingGetExpiry(HostingExpiry),
    HostingClearExpiry,
    HostingKvSet,
    HostingKvList(Vec<(String, String)>),
    UpcomingExpiries(Vec<ExpiringHosting>),
    SchedulerTick {
        actions_processed: i64,
    },
    BackupNow(BackupRunWire),
    BackupList(Vec<BackupRunWire>),
    InviteCreate(NodeInviteMint),
    InviteList(Vec<NodeInviteSummary>),
    InviteRevoke,
    AuditList(Vec<AuditEntryWire>),
    CertIssue(CertInfo),
    CertRenewAll(Vec<CertRenewResult>),
    WpInstall(WpInstallStatus),
    WpStatus(Option<WpInstallStatus>),
    DnsCheck(DnsCheckResult),
    DnsSpfCheck(hyperion_types::SpfCheckResult),
    CertIssueAcme(CertInfo),
    /// `completed = true` ⇒ the cert was issued (cloudflare path);
    /// otherwise `record_name` + `values` must be published as TXT and
    /// the caller follows up with `CertDns01Finish`.
    CertDns01Begin {
        completed: bool,
        record_name: String,
        values: Vec<String>,
    },
    CertDns01Finish(CertInfo),
    CertDns01BeginDomain {
        completed: bool,
        record_name: String,
        values: Vec<String>,
    },
    CertDns01FinishDomain(CertInfo),
    CertUpload(CertInfo),
    HostingStats(HostingStats),
    NodeStats(NodeStats),
    ClusterStats(ClusterStats),
    NodeMetricsHistory(hyperion_types::NodeMetricsHistory),
    SetHostingAcmeEmail,
    ServicesHealth(hyperion_types::ServicesHealth),
    FirewallList(hyperion_types::FirewallView),
    /// Result of FirewallApplyTemplate. `applied=true` ⇒ every
    /// nft command in the template ran successfully + the ruleset
    /// got persisted. `applied=false` ⇒ the operator should read
    /// `error` and decide whether to retry / fix manually.
    FirewallTemplateApplied {
        applied: bool,
        /// Joined stdout from every nft command we ran. Operators
        /// can spot-check what landed by scanning this.
        output: String,
        /// First non-empty stderr line that's NOT "already exists"
        /// (those are benign — re-applying a template is idempotent).
        /// Empty on full success.
        error: String,
    },
    BackupDelete,
    AgentConfigView(hyperion_types::AgentConfigView),
    /// SMTP response code from the relay (e.g. `Code(250)`).
    /// Surfaced in the UI flash so the operator can verify the
    /// relay actually accepted the message.
    EmailSendTest {
        smtp_code: String,
    },
    ServiceRestart,
    ServiceInstall,
    /// Current state of the most-recent / in-progress
    /// service-install job + log tail.
    ServiceInstallStatus(hyperion_types::ServiceInstallStatus),
    /// Upload accepted. `id` is the newly-inserted row id (or the
    /// existing one if dedupe matched on SHA-256).
    WpAssetUpload {
        id: i64,
        deduped: bool,
    },
    /// Library snapshot — never empty unless no uploads have ever
    /// happened on this node.
    WpAssetList(Vec<hyperion_types::WpAssetSummary>),
    WpAssetDelete,
    /// Plugin / theme was installed from the asset library. Carries
    /// the resolved kind ("plugin" / "theme") + the asset's
    /// original filename for the success flash.
    WpInstallFromAsset {
        kind: String,
        original_name: String,
    },
    WpAssetReplace,
    /// Result of a "re-install on all" run.
    WpAssetReinstallAll {
        installed_ok: i64,
        installed_failed: i64,
        /// Up to ~10 lines of per-hosting failure messages so the
        /// UI flash can show something concrete instead of just a
        /// count. Empty when everything succeeded.
        failure_tail: String,
    },
    WpThemeList(hyperion_types::WpThemeListResponse),
    WpThemeAction(hyperion_types::WpThemeActionResult),
    WpVulnScan(hyperion_types::WpVulnScanResult),
    VulnFindingsList(Vec<hyperion_types::HostingVulnSummary>),
    WpStagingCreate {
        staging_domain: String,
    },
    WpStagingPush,
    /// Acknowledgement that the background update task spawned.
    /// Failures during the actual update show up in the log tail,
    /// not here.
    NodeUpdateRun {
        started_at: i64,
    },
    /// Current update job state + the last ~8 kB of stdout/stderr.
    NodeUpdateStatus(hyperion_types::NodeUpdateStatus),
    AgentConfigUpdate,
    EmailConfigSet,
    CloudflareToken(hyperion_types::CloudflareTokenInfo),
    UpdateCheck(hyperion_types::UpdateStatus),
    HostingExport(hyperion_types::HostingMigrationBundle),
    HostingMigrationFetchBundleFile {
        bytes_b64: String,
    },
    HostingImport(hyperion_types::HostingImportResult),
    HostingImportPanelPlan(hyperion_import::ImportPlan),
    HostingImportPanel(hyperion_import::ImportPanelResult),
    HostingImportFromUrl(hyperion_types::HostingImportResult),
    EmailLogList(Vec<hyperion_types::EmailLogEntry>),
    SiteEmailLogList(Vec<hyperion_types::SiteEmailLogEntry>),
    FtpAccountsList(Vec<hyperion_types::FtpAccountSummary>),
    /// True = login accepted, false = refused. Transport failure
    /// surfaces as Response::Error so the UI can distinguish.
    FtpVerifyLogin {
        accepted: bool,
    },
    EmailSmtpAutodetect(hyperion_types::SmtpAutodetect),
    MtaDiagnostics(hyperion_types::MtaDiagnostics),
    /// Echoes the mode that was just applied — `"direct-mx"`,
    /// `"smart-host"`, or `"skipped"` (postfix not installed).
    MtaReconfigure {
        mode: String,
    },
    /// `exit_code` from /usr/sbin/sendmail (0 = queued). `output`
    /// is whatever sendmail printed to stderr (usually empty on
    /// success).
    MtaTestSend {
        exit_code: i32,
        output: String,
    },
    /// Number of deferred messages postfix attempted to retry +
    /// stderr from postqueue. (operator may want to see "Mail
    /// queue is empty" → "0 attempted").
    MtaQueueFlush {
        attempted: usize,
        output: String,
    },
    /// Number of messages discarded by `postsuper -d ALL`.
    MtaQueueClear {
        cleared: usize,
        output: String,
    },
    /// Result of the panel provisioning flow. `status` is one of
    /// "ok" / "ok-cert-pending" / "dns-failed" / "nginx-failed".
    /// `message` is a multi-line human description. `panel_url` is
    /// the final HTTPS URL when status starts with "ok".
    PanelProvision {
        status: String,
        message: String,
        panel_url: String,
    },
    /// Live snapshot of the panel ACME issuance. `None` when no
    /// panel hostname is configured (or the bg task hasn't seeded
    /// the state yet — UI shows "not started" in that case).
    PanelCertStatus(Option<hyperion_types::PanelCertProgress>),
    /// Result of `mount -o remount,rw /`. `success` true → /usr
    /// is now writable; `message` is the mount output (often
    /// empty on success). `success` false + message = failed
    /// remount (e.g. snap-managed rootfs that genuinely cannot
    /// be made RW — operator needs a different base image).
    RemountUsrRw {
        success: bool,
        message: String,
    },
    FsDiagnoseAndFix(hyperion_types::FsDiagnostics),
    BackupTargetList(Vec<hyperion_types::BackupTargetView>),
    BackupTargetUpserted {
        id: i64,
    },
    BackupTargetDeleted,
    BackupTargetProbe(hyperion_types::BackupTargetProbe),
    /// Per-hosting quota report (policy + current usage).
    QuotaGet(hyperion_types::HostingQuotaReport),
    /// Ack for QuotaSet — returns the persisted (and possibly
    /// kernel-applied) row.
    QuotaApplied(hyperion_types::HostingQuotaView),
    /// Outcome of an automatic kernel-quota enablement attempt.
    QuotaEnableKernel(hyperion_types::QuotaEnableSummary),
    /// Plain ack for write operations on web_sessions.
    WebSessionAck,
    /// Liveness probe response. `true` ⇒ session is live and
    /// `last_seen_at` was updated.
    WebSessionTouch(bool),
    /// `/settings/sessions` list payload.
    WebSessionList(Vec<hyperion_types::WebSessionView>),
    /// Audit chain verification result. `ok=true` means every
    /// row's `row_hash` reproduces from `prev_hash + canonical
    /// fields`; `message` is the empty string on success.
    AuditVerifyChain {
        ok: bool,
        rows_checked: i64,
        message: String,
    },
    /// Look-up response for `JobGet`. `None` = job id unknown.
    JobGet(Option<hyperion_types::JobView>),
    /// Newest-first list of jobs. Empty when no rows match.
    JobList(Vec<hyperion_types::JobView>),
    /// Returns the `job_id` minted by `JobStart` (and reused for
    /// later `JobProgress` / `JobFinish` ticks).
    JobStarted {
        job_id: String,
    },
    /// Plain ack for `JobProgress` / `JobFinish`. No payload — the
    /// caller already knows the id.
    JobAck,
    WpPluginList(hyperion_types::WpPluginListResponse),
    WpPluginAction(hyperion_types::WpPluginActionResult),
    // Web users / roles / 2FA
    WebLogin(hyperion_types::WebLoginResult),
    WebVerify2fa(hyperion_types::WebVerify2faResult),
    WebUserList(Vec<hyperion_types::WebUserSummary>),
    WebUserGet(Option<hyperion_types::WebUserSummary>),
    WebUserCreate {
        id: i64,
    },
    WebUserSetPassword,
    WebUserSetRole,
    RoleList(Vec<hyperion_types::CustomRoleSummary>),
    RoleCreate {
        id: i64,
    },
    RoleUpdate,
    RoleDelete,
    WebUserSetCustomRole,
    WebUserEffectiveRole(hyperion_types::EffectiveRoleWire),
    ImportToken(hyperion_types::ImportTokenResult),
    WebUserSetLocked,
    WebUserDelete,
    Web2faEnrollStart(hyperion_types::Web2faEnrollment),
    Web2faConfirmEnroll {
        ok: bool,
    },
    Web2faDisable,
    WebGrantHostingAccess,
    WebRevokeHostingAccess,
    WebListHostingAccess(Vec<hyperion_types::WebHostingAccess>),
    HostingFileList {
        rel_path: String,
        entries: Vec<hyperion_types::HostingFileEntry>,
    },
    HostingFileRead(hyperion_types::HostingFileContent),
    HostingFileDownload {
        rel_path: String,
        bytes_b64: String,
        mime: String,
    },
    HostingFileWrite,
    HostingFileDelete,
    HostingFileMkdir,
    HostingFileRename,
    MonitorOverview(Vec<hyperion_types::MonitorOverviewItem>),
    AvatarFilename(Option<String>),
    AvatarSet,
    /// Returns the masked target address (e.g. "k****@example.cz").
    EmailChangeRequest {
        masked_to: String,
    },
    EmailChangeConfirm,
    EmailChangeCancel,
    MonitorGet {
        config: hyperion_types::MonitorConfigView,
        history: hyperion_types::MonitorHistory,
    },
    MonitorSet,
    MonitorProbeNow(hyperion_types::MonitorSamplePoint),
    MonitorTick {
        sampled: i64,
    },
    StatsTick {
        hostings_sampled: i64,
    },
    BackupRestore,
    BackupFetchChunk {
        data_b64: String,
        total_size: u64,
        filename: String,
        eof: bool,
    },
    BackupRestoreAsNew {
        hosting_id: String,
        domain: String,
    },
    NotificationsFeed(hyperion_types::NotificationFeed),
    NotificationsMarkRead,
    NotificationsMarkAllRead {
        marked: i64,
    },
    HostingLogs(String),
    CronList(String),
    CronReplace,
    EnrollConsume {
        /// The EFFECTIVE node_id the master assigned. Usually the freshly
        /// minted candidate, but on an idempotent re-enroll it's the
        /// reused/adopted prior id. The node persists THIS, not the id it
        /// presented. `#[serde(default)]` keeps older masters (that don't
        /// echo it) parseable — the node then falls back to the id it
        /// already had / the response's own node_id field.
        #[serde(default)]
        node_id: String,
        secret: String,
        /// Base64 (no-pad) of the master's Ed25519 public key for
        /// the master→node remote-RPC channel. `None` on masters
        /// that haven't been upgraded past the introduction of
        /// signed remote RPC; nodes treat that as "remote RPC not
        /// available from this master" and continue as before.
        #[serde(default)]
        master_rpc_pubkey: Option<String>,
    },
    NodesList(Vec<NodeSummary>),
    CertOverview(Vec<hyperion_types::CertOverviewItem>),
    /// Plain ack for NodeSetLabel.
    NodeLabelUpdated,
    /// Plain ack for NodeSetDrain.
    NodeDrainUpdated,
    /// Result of NodeRemove. `removed=true` ⇒ the row is gone;
    /// `removed=false` + a non-zero `hostings_blocking` ⇒ refusal,
    /// operator must either move hostings off the node first or
    /// resubmit with `force=true`.
    NodeRemoved {
        removed: bool,
        hostings_blocking: i64,
    },
    /// Result of NodeReassignHostings: how many hostings were re-pointed.
    NodeHostingsReassigned {
        moved: i64,
    },
    NodeHeartbeat {
        /// Same as EnrollConsume — included on every heartbeat ack
        /// so already-enrolled nodes pick up the master pubkey
        /// within one tick after the master is upgraded, without
        /// needing a re-enrollment.
        #[serde(default)]
        master_rpc_pubkey: Option<String>,
    },
    WpResetPassword,
    DbResetPassword,
    FtpSetPassword {
        password: String,
    },
    FtpDisable,
    SftpStatus(hyperion_types::SftpStatus),
    SftpSet(hyperion_types::SftpStatus),
    BanList(Vec<hyperion_types::IpBanWire>),
    BanAdd,
    BanRemove,
    DashboardAlerts(Vec<DashboardAlert>),
    ProfileList(Vec<HostingProfile>),
    ProfileGet(HostingProfile),
    ProfileCreate(HostingProfile),
    ProfileUpdate(HostingProfile),
    ProfileDelete,
    /// Hosting ids currently on a profile (for ProfileUsage).
    ProfileUsage(Vec<String>),
    /// (profile_id, count) per profile on a node (for ProfileUsageCounts).
    ProfileUsageCounts(Vec<(i64, i64)>),
    ProfileApply(ProfileApply),
    ProfileGetApply(Option<ProfileApply>),
    /// Ack for ProfileWpItemInstall. `label` is the human-readable
    /// name of what got installed (asset original_name for
    /// `@asset:` lines, the slug otherwise); `activated` echoes
    /// whether the trailing-`!` activate ran.
    ProfileWpItemInstalled {
        label: String,
        activated: bool,
    },
    Error(RpcError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntryWire {
    pub id: i64,
    pub ts: i64,
    pub actor_uid: i64,
    pub actor_label: String,
    pub action: String,
    pub target: Option<String>,
    pub payload_json: String,
    pub result: String,
    /// Which node this entry came from, as a display label. The agent
    /// leaves this `None` (it doesn't know its own cluster label); the
    /// master TAGS it after a cross-node fan-in so /audit can show a node
    /// column. `#[serde(default)]` keeps older agents' entries parseable.
    #[serde(default)]
    pub node: Option<String>,
}

pub async fn write_frame<W, T>(w: &mut W, value: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("frame {} exceeds MAX_FRAME {}", bytes.len(), MAX_FRAME),
        ));
    }
    let len = bytes.len() as u32;
    w.write_u32(len).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(r: &mut R) -> std::io::Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let len = r.read_u32().await? as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame {len} exceeds MAX_FRAME"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn request_round_trip_through_duplex() {
        let (mut a, mut b) = duplex(8192);
        let req = Request::HostingList;
        write_frame(&mut a, &req).await.expect("write");
        let got: Request = read_frame(&mut b).await.expect("read");
        assert_eq!(req, got);
    }

    #[tokio::test]
    async fn response_round_trip() {
        let (mut a, mut b) = duplex(8192);
        let resp = Response::AgentInfo(AgentInfo {
            hostname: "test".into(),
            version: "0".into(),
            schema_version: 1,
            hostings_count: 0,
            node_id: None,
            master_url: None,
            enrolled_at: None,
        });
        write_frame(&mut a, &resp).await.expect("write");
        let got: Response = read_frame(&mut b).await.expect("read");
        assert_eq!(resp, got);
    }

    #[tokio::test]
    async fn error_response_round_trip() {
        let (mut a, mut b) = duplex(8192);
        let resp = Response::Error(RpcError::NotFound {
            kind: "hosting".into(),
            id: "x".into(),
        });
        write_frame(&mut a, &resp).await.expect("write");
        let got: Response = read_frame(&mut b).await.expect("read");
        assert_eq!(resp, got);
    }

    #[test]
    fn cert_upload_debug_redacts_key_but_serde_preserves_it() {
        // The socket handler logs `debug!(?req)`, so Debug of an upload
        // request must never contain the private key — while the wire form
        // must still carry the real bytes to the node.
        let secret =
            "-----BEGIN PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END PRIVATE KEY-----";
        let req = Request::CertUpload {
            sel: HostingSelector::Domain(Domain::parse("example.com").expect("domain")),
            cert_pem: "-----BEGIN CERTIFICATE-----\nCERTDATA\n-----END CERTIFICATE-----"
                .to_string()
                .into(),
            key_pem: secret.to_string().into(),
            ca_bundle_pem: None,
        };
        let dbg = format!("{req:?}");
        assert!(
            !dbg.contains("SUPERSECRETKEYMATERIAL"),
            "private key leaked into Debug: {dbg}"
        );
        assert!(
            dbg.contains("redacted"),
            "Debug should mark the field redacted"
        );

        let json = serde_json::to_string(&req).expect("serialize");
        assert!(
            json.contains("SUPERSECRETKEYMATERIAL"),
            "wire form must preserve the key bytes"
        );
        let back: Request = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, back, "CertUpload must round-trip through serde");
    }

    #[test]
    fn email_config_set_debug_redacts_password_but_serde_preserves_it() {
        // EmailConfigSet is dispatched to workers, whose rpc-server logs
        // `debug!(?req)`. The SMTP password rides in `fields` and must be
        // masked in Debug — but the wire form must still carry it so the
        // node can write agent.toml. Non-secret keys (host) stay visible.
        let mut map = std::collections::BTreeMap::new();
        map.insert("smtp_host".to_string(), "smtp.postmarkapp.com".to_string());
        map.insert(
            "smtp_password".to_string(),
            "hunter2-SUPERSECRET".to_string(),
        );
        let req = Request::EmailConfigSet {
            fields: map.clone().into(),
        };

        let dbg = format!("{req:?}");
        assert!(
            !dbg.contains("hunter2-SUPERSECRET"),
            "SMTP password leaked into Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Debug should mark the password redacted: {dbg}"
        );
        assert!(
            dbg.contains("smtp.postmarkapp.com"),
            "non-secret host should stay visible for debugging: {dbg}"
        );

        // Wire form is `#[serde(transparent)]` → identical to the bare map,
        // and carries the real password to the node.
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(
            json.contains("hunter2-SUPERSECRET"),
            "wire form must preserve the password"
        );
        let back: Request = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, back, "EmailConfigSet must round-trip through serde");
    }

    #[test]
    fn redacted_fields_is_wire_compatible_with_bare_map() {
        // Transparent encoding means an old/peer serialization of a plain
        // BTreeMap deserializes straight into RedactedFields — so changing
        // the field type can't break a mixed-version master↔worker pair.
        let mut map = std::collections::BTreeMap::new();
        map.insert("section".to_string(), "email".to_string());
        let bare = serde_json::to_string(&map).expect("serialize map");
        let fields: RedactedFields = serde_json::from_str(&bare).expect("into RedactedFields");
        assert_eq!(fields.into_inner(), map);
        // S3 secret + slack webhook keys are masked too (used by AgentConfigUpdate).
        assert!(RedactedFields::is_secret_key("secret_access_key"));
        assert!(RedactedFields::is_secret_key("slack_webhook"));
        assert!(RedactedFields::is_secret_key("api_token"));
        assert!(!RedactedFields::is_secret_key("smtp_host"));
        assert!(!RedactedFields::is_secret_key("from_address"));
    }

    #[tokio::test]
    async fn refuses_overlarge_frame_on_read() {
        let (mut a, mut b) = duplex(8192);
        a.write_u32((MAX_FRAME + 1) as u32)
            .await
            .expect("write len");
        let result: std::io::Result<Request> = read_frame(&mut b).await;
        assert!(result.is_err());
    }

    #[test]
    fn web_user_set_password_current_is_wire_optional() {
        // Self-service: current_password present, round-trips.
        let req = Request::WebUserSetPassword {
            user_id: 7,
            new_password: "newpw1234".into(),
            current_password: Some("oldpw".into()),
        };
        let json = serde_json::to_string(&req).expect("ser");
        let back: Request = serde_json::from_str(&json).expect("de");
        assert_eq!(req, back);
        // Old wire form (no current_password field) must still deserialize to
        // `None` so a mixed-version master/worker pair keeps working.
        let old = r#"{"method":"web_user_set_password","params":{"user_id":7,"new_password":"x"}}"#;
        let parsed: Request = serde_json::from_str(old).expect("old de");
        assert_eq!(
            parsed,
            Request::WebUserSetPassword {
                user_id: 7,
                new_password: "x".into(),
                current_password: None,
            }
        );
        // The logged method name carries no param value.
        assert_eq!(<&'static str>::from(&req), "WebUserSetPassword");
    }

    #[test]
    fn request_method_name_is_safe_to_log() {
        // The rpc-server logs `<&'static str>::from(&req)` instead of `?req`.
        // It must yield the variant name and NEVER any param value — including
        // secrets nested in the params map.
        let mut map = std::collections::BTreeMap::new();
        map.insert("smtp_password".to_string(), "TOPSECRETvalue".to_string());
        let req = Request::AgentConfigUpdate {
            section: "email".into(),
            fields: map.into(),
        };
        let name: &'static str = (&req).into();
        assert_eq!(name, "AgentConfigUpdate");
        assert!(
            !name.contains("TOPSECRET"),
            "method name must not carry param secrets"
        );
        assert_eq!(<&'static str>::from(&Request::HostingList), "HostingList");
    }

    #[test]
    fn request_method_tag_in_json() {
        let req = Request::HostingList;
        let s = serde_json::to_string(&req).expect("serialize");
        assert!(s.contains("hosting_list"), "got: {s}");
    }
}
