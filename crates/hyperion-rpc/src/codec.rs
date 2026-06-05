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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    AgentInfo,
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
    UpcomingExpiries {
        within_seconds: i64,
    },
    SchedulerTick,
    BackupNow {
        sel: HostingSelector,
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
        /// types per (section, field) and parses accordingly.
        fields: std::collections::BTreeMap<String, String>,
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
    HostingExport { hosting: HostingSelector },
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
    HostingImport { manifest_path: String },
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
    /// Import a migration bundle from a source node's signed URL.
    /// `base_url` is e.g. `https://source-master/api/migration/bundle/<id>`
    /// — the agent appends `/manifest.json?t=<token>` and
    /// `/archive.tar.gz?t=<token>`, downloads both, then runs the
    /// regular import.
    HostingImportFromUrl { base_url: String, token: String },
    /// List installed WordPress plugins for `hosting`.
    WpPluginList { hosting: HostingSelector },
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
    /// Force-set a user's password (admin reset). super_admin only.
    WebUserSetPassword {
        user_id: i64,
        new_password: String,
    },
    /// Change role. super_admin only.
    WebUserSetRole {
        user_id: i64,
        role: String,
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
    },
    NodesList,
    NodeHeartbeat {
        node_id: String,
        secret: String,
        agent_version: String,
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
    DashboardAlerts,
    ProfileList,
    ProfileGet { id: i64 },
    ProfileCreate(ProfileInput),
    ProfileUpdate { id: i64, input: ProfileInput },
    ProfileDelete { id: i64 },
    ProfileApply { sel: HostingSelector, profile_id: i64 },
    ProfileGetApply { sel: HostingSelector },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", content = "result", rename_all = "snake_case")]
pub enum Response {
    AgentInfo(AgentInfo),
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
    HostingSetWpDebug(hyperion_types::WpExtras),
    HostingSetRedis(hyperion_types::WpExtras),
    HostingRotateRedisPassword(hyperion_types::WpExtras),
    HostingRotateWpDebugLog,
    HostingUsage(Vec<HostingUsageBucket>),
    HostingSetExpiry(HostingExpiry),
    HostingGetExpiry(HostingExpiry),
    HostingClearExpiry,
    UpcomingExpiries(Vec<ExpiringHosting>),
    SchedulerTick { actions_processed: i64 },
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
    HostingStats(HostingStats),
    NodeStats(NodeStats),
    ClusterStats(ClusterStats),
    NodeMetricsHistory(hyperion_types::NodeMetricsHistory),
    SetHostingAcmeEmail,
    ServicesHealth(hyperion_types::ServicesHealth),
    BackupDelete,
    AgentConfigView(hyperion_types::AgentConfigView),
    /// SMTP response code from the relay (e.g. `Code(250)`).
    /// Surfaced in the UI flash so the operator can verify the
    /// relay actually accepted the message.
    EmailSendTest { smtp_code: String },
    ServiceRestart,
    ServiceInstall,
    /// Current state of the most-recent / in-progress
    /// service-install job + log tail.
    ServiceInstallStatus(hyperion_types::ServiceInstallStatus),
    /// Upload accepted. `id` is the newly-inserted row id (or the
    /// existing one if dedupe matched on SHA-256).
    WpAssetUpload { id: i64, deduped: bool },
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
    /// Acknowledgement that the background update task spawned.
    /// Failures during the actual update show up in the log tail,
    /// not here.
    NodeUpdateRun { started_at: i64 },
    /// Current update job state + the last ~8 kB of stdout/stderr.
    NodeUpdateStatus(hyperion_types::NodeUpdateStatus),
    AgentConfigUpdate,
    UpdateCheck(hyperion_types::UpdateStatus),
    HostingExport(hyperion_types::HostingMigrationBundle),
    HostingMigrationFetchBundleFile { bytes_b64: String },
    HostingImport(hyperion_types::HostingImportResult),
    HostingImportFromUrl(hyperion_types::HostingImportResult),
    EmailLogList(Vec<hyperion_types::EmailLogEntry>),
    SiteEmailLogList(Vec<hyperion_types::SiteEmailLogEntry>),
    FtpAccountsList(Vec<hyperion_types::FtpAccountSummary>),
    /// True = login accepted, false = refused. Transport failure
    /// surfaces as Response::Error so the UI can distinguish.
    FtpVerifyLogin { accepted: bool },
    EmailSmtpAutodetect(hyperion_types::SmtpAutodetect),
    WpPluginList(hyperion_types::WpPluginListResponse),
    WpPluginAction(hyperion_types::WpPluginActionResult),
    // Web users / roles / 2FA
    WebLogin(hyperion_types::WebLoginResult),
    WebVerify2fa(hyperion_types::WebVerify2faResult),
    WebUserList(Vec<hyperion_types::WebUserSummary>),
    WebUserGet(Option<hyperion_types::WebUserSummary>),
    WebUserCreate { id: i64 },
    WebUserSetPassword,
    WebUserSetRole,
    WebUserSetLocked,
    WebUserDelete,
    Web2faEnrollStart(hyperion_types::Web2faEnrollment),
    Web2faConfirmEnroll { ok: bool },
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
    EmailChangeRequest { masked_to: String },
    EmailChangeConfirm,
    EmailChangeCancel,
    MonitorGet {
        config: hyperion_types::MonitorConfigView,
        history: hyperion_types::MonitorHistory,
    },
    MonitorSet,
    MonitorProbeNow(hyperion_types::MonitorSamplePoint),
    MonitorTick { sampled: i64 },
    StatsTick { hostings_sampled: i64 },
    BackupRestore,
    NotificationsFeed(hyperion_types::NotificationFeed),
    NotificationsMarkRead,
    NotificationsMarkAllRead { marked: i64 },
    HostingLogs(String),
    CronList(String),
    CronReplace,
    EnrollConsume {
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
    FtpSetPassword { password: String },
    FtpDisable,
    DashboardAlerts(Vec<DashboardAlert>),
    ProfileList(Vec<HostingProfile>),
    ProfileGet(HostingProfile),
    ProfileCreate(HostingProfile),
    ProfileUpdate(HostingProfile),
    ProfileDelete,
    ProfileApply(ProfileApply),
    ProfileGetApply(Option<ProfileApply>),
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
    fn request_method_tag_in_json() {
        let req = Request::HostingList;
        let s = serde_json::to_string(&req).expect("serialize");
        assert!(s.contains("hosting_list"), "got: {s}");
    }
}
