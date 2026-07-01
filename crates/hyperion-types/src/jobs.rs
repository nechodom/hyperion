//! Generic background-job descriptor surfaced to the UI + hctl.
//!
//! The agent's `jobs` table stores the authoritative state; this is
//! the wire-format projection that flows through RPC and renders
//! into the HTMX-polled progress card.

use serde::{Deserialize, Serialize};

/// One job (e.g. "migrating example.cz from node-01 to node-02") at
/// the moment the agent was queried. The UI polls on a 2s cadence
/// while `state == "running"` and stops once it goes terminal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct JobView {
    pub id: String,
    /// Free-text discriminator — `migration`, `install`, `backup`,
    /// `acme_issue`, `node_update`, `wp_reinstall_all`, `db_reset`,
    /// `hosting_clone`, `rofs_fix`, `cert_renew`. The UI uses this
    /// to pick an icon and humanise the title.
    pub kind: String,
    /// Optional human-friendly subject (usually a domain).
    pub target: Option<String>,
    /// `running` | `done` | `failed` | `cancelled`.
    pub state: String,
    /// Short label for the current step. Operators read this most.
    pub step_label: String,
    /// 0-100. Monotonic by convention; not enforced.
    pub progress_pct: i64,
    /// Bounded ~16 KiB tail of the operation's log. Older bytes are
    /// dropped as the operation produces new output.
    pub log_tail: String,
    /// Set when `state == failed`.
    pub error: Option<String>,
    /// Per-kind opaque context (e.g. migration stores src + dst node
    /// IDs so the UI can render a richer card without a second
    /// lookup).
    pub payload_json: String,
    /// Username / "system" / "agent". `0` for non-human actors.
    pub actor_uid: i64,
    pub actor_label: String,
    pub started_at: i64,
    pub updated_at: i64,
    /// Set once `state` goes terminal.
    pub finished_at: Option<i64>,
}

impl JobView {
    /// True when the operation has finished one way or the other.
    pub fn is_terminal(&self) -> bool {
        matches!(self.state.as_str(), "done" | "failed" | "cancelled")
    }
}

/// One row from `web_sessions`. The signed-cookie Session in
/// `hyperion-auth` is the wire-format the COOKIE carries; this is
/// the projection the agent stores + the panel renders into
/// /settings/sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WebSessionView {
    pub sid: String,
    pub user_id: i64,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<i64>,
}

impl WebSessionView {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// One row from `api_keys`, projected for admin display. NEVER carries
/// the raw key or its hash — only the safe-to-show `key_prefix`. Backs
/// the "API keys" Settings card + the `ApiKeyList` RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ApiKeyView {
    pub id: i64,
    pub key_prefix: String,
    pub label: String,
    pub owner_user_id: i64,
    /// CapSet u64 bitmask (already clamped to the owner at creation).
    pub caps: u64,
    pub scope_all: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<i64>,
}

impl ApiKeyView {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// The identity behind a presented API key, resolved by hash. Returned
/// from the `ApiKeyResolve` RPC; `None` ⇒ the key is unknown, revoked,
/// or expired. The web Bearer extractor builds an `AuthCtx` from this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ApiKeyResolved {
    pub id: i64,
    pub label: String,
    pub owner_user_id: i64,
    pub caps: u64,
    pub scope_all: bool,
}

/// Result of minting an API key: the row id + the **raw** key, shown to
/// the operator exactly once (and never recoverable afterwards).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ApiKeyCreated {
    pub id: i64,
    pub raw_key: String,
    pub key_prefix: String,
}

/// Per-hosting quota policy + last-applied state. Powers the
/// "Quota" tab on the hosting detail page and the QuotaSet /
/// QuotaGet RPCs. Zero values mean "no cap".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingQuotaView {
    pub hosting_id: String,
    pub disk_soft_kib: i64,
    pub disk_hard_kib: i64,
    pub mem_limit_mib: i64,
    pub bw_soft_mib: i64,
    pub bw_hard_mib: i64,
    /// Set when the kernel last accepted a setquota call.
    pub applied_at: Option<i64>,
    /// Set when the last setquota call failed (e.g. quotaon not
    /// enabled on the filesystem hosting the user's home dir).
    pub last_error: Option<String>,
    pub updated_at: i64,
    /// Action when disk usage crosses the hard cap: "notify" (default) or
    /// "suspend". Read from `hosting_kv`; seeded from the create profile.
    #[serde(default)]
    pub exceed_action: String,
}

/// Off-site backup destination (S3-compatible or local dir).
/// Wire-format projection of the `backup_targets` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BackupTargetView {
    pub id: i64,
    pub name: String,
    /// "s3" | "local-dir".
    pub kind: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    /// On-disk path under /etc/hyperion/secrets/ where the
    /// secret_access_key plaintext lives. Caller never sees the
    /// secret itself — it's read only by the backup runner at
    /// upload time.
    pub secret_key_id: Option<String>,
    /// age public key the agent encrypts blobs to. Operator
    /// keeps the matching identity OFF the node.
    pub age_recipient: Option<String>,
    pub retention_daily: i64,
    pub retention_weekly: i64,
    pub retention_monthly: i64,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A backup S3 target RESOLVED for upload — the secret is inline (read from
/// its 0600 file on the master). Travels in the `BackupNow` request so a
/// worker can push its backup off-site even though the `backup_targets` table
/// only lives in the master's DB. The request is signed + TLS-encrypted
/// master→worker, and the rpc-server logs method names only, so the secret
/// neither leaks on the wire nor into logs. `Debug` masks the secret anyway.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct S3BackupTarget {
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub age_recipient: Option<String>,
    pub retention_daily: i64,
}

impl std::fmt::Debug for S3BackupTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3BackupTarget")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("age_recipient", &self.age_recipient)
            .field("retention_daily", &self.retention_daily)
            .finish()
    }
}

/// Outcome of a "test connection" probe — operator clicks the
/// button on /settings/backups; the agent does a PUT + DELETE
/// round-trip against the configured target and reports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BackupTargetProbe {
    pub ok: bool,
    pub message: String,
    /// Latency (ms) of the PUT round-trip. 0 when the probe
    /// short-circuited before the upload.
    pub put_latency_ms: i64,
}

/// Report of current vs policy. `current_usage_kib` reads from
/// `quota -u <user>` (or `du -sk <home>` as fallback when the
/// kernel-level quota subsystem isn't enabled).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostingQuotaReport {
    pub policy: HostingQuotaView,
    pub current_disk_kib: i64,
    /// True when `quotaon` is enabled on the mount carrying the
    /// hosting's home dir. False ⇒ `setquota` would no-op; the UI
    /// shows a setup-guidance banner.
    pub quotas_enabled_on_fs: bool,
    /// Human-readable hint when quotas_enabled_on_fs is false.
    pub setup_hint: String,
}

/// Outcome of an automatic "enable kernel quotas on the filesystem"
/// attempt (the `QuotaEnableKernel` RPC). The action edits `/etc/fstab`,
/// remounts, and runs quotacheck + quotaon where possible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QuotaEnableSummary {
    /// True when quotas are active on the filesystem after the attempt.
    pub ok: bool,
    /// True when fstab was updated but the filesystem couldn't be
    /// remounted live (busy, or rootfs) — a reboot will activate it.
    pub requires_reboot: bool,
    /// Filesystem type of the target mount (ext4, xfs, …).
    pub fs_type: String,
    /// Mount point quotas were enabled on (e.g. `/home` or `/`).
    pub mount_point: String,
    /// Human-readable result / next-step message.
    pub message: String,
}
