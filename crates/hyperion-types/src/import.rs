//! Wire DTOs for the self-service import wizard (one-time tokens + server→server
//! bundle push). Carried by the single generic `ImportToken` RPC. See
//! docs/superpowers/specs/2026-06-28-self-service-import-wizard-design.md.

use serde::{Deserialize, Serialize};

/// Operations the web layer asks the agent to perform on import tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImportTokenOp {
    /// Mint a fresh one-time token (agent generates the plaintext + stores its
    /// hash) scoped to a target node + source kind, valid for `ttl_secs`.
    Mint {
        target_node: String,
        source_kind: String,
        created_by: String,
        ttl_secs: i64,
    },
    /// Look the token up by plaintext. `consume=false` = read-only validity check
    /// (the bootstrap-script GET); `consume=true` = atomic single-use claim for
    /// ingest (flips pending→receiving).
    Resolve { token: String, consume: bool },
    /// Update progress / lifecycle of a token row.
    Update {
        id: i64,
        status: Option<String>,
        job_id: Option<String>,
        received_bytes: Option<i64>,
    },
    /// List in-flight tokens (wizard "transfers" panel + status polling).
    List,
    /// Record the site list the source reported (interactive import). By token
    /// plaintext (the source has no session); only updates a still-pending row.
    SetManifest {
        token: String,
        manifest_json: String,
    },
    /// Record the operator's site pick (`["*"]` = all). By row id (set from the
    /// authenticated wizard).
    SetSelection { id: i64, selection_json: String },
    /// Revoke a token.
    Cancel { id: i64 },
    /// Admit an upload attempt and declare what is coming.
    ///
    /// Separate from `Resolve { consume: true }` because it is IDEMPOTENT: a
    /// resumed upload calls this again after a dropped connection, and the reply
    /// carries the offset to continue from. The single-use `Resolve` stays for
    /// the legacy `/import/ingest` path so a token minted before this change
    /// still works.
    ClaimUpload {
        token: String,
        expected_bytes: i64,
        bundle_sha256: String,
    },
    /// Record upload progress (drives the panel's measured rate + ETA) and push
    /// the token's expiry out while the transfer is demonstrably moving.
    RecordUpload { id: i64, received_bytes: i64 },
    /// Store what the source reports while it is still PACKING — the phase that
    /// showed as dead air before, and is usually the longest part of a run.
    SetSourceProgress {
        token: String,
        progress_json: String,
    },
}

/// A token's current state (never carries the plaintext or hash).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportTokenInfo {
    pub id: i64,
    pub target_node: String,
    pub source_kind: String,
    pub status: String,
    pub received_bytes: i64,
    pub job_id: Option<String>,
    pub expires_at: i64,
    pub created_by: String,
    pub created_at: i64,
    /// JSON site list the source reported (empty until it does).
    #[serde(default)]
    pub manifest_json: String,
    /// JSON of the operator's pick (empty until chosen; `["*"]` = all).
    #[serde(default)]
    pub selection_json: String,
    /// Total bundle size the source declared. 0 = unknown, which the UI must
    /// render as "total unknown" rather than as 0%.
    #[serde(default)]
    pub expected_bytes: i64,
    /// Hex sha256 the source promised for the finished bundle.
    #[serde(default)]
    pub bundle_sha256: String,
    /// When `received_bytes` was last written (0 = never).
    #[serde(default)]
    pub received_at: i64,
    /// Measured bytes/second, or 0 when there is not enough evidence for a
    /// figure. Zero means "do not render a rate" — never "the transfer stalled".
    #[serde(default)]
    pub rate_bytes_per_sec: i64,
    /// Verbatim packing-phase report from the source (empty until it sends one).
    #[serde(default)]
    pub source_progress_json: String,
    #[serde(default)]
    pub source_progress_at: i64,
}

/// Result of an [`ImportTokenOp`].
// `Resolved` carries a whole ImportTokenInfo and is much larger than `Ack`.
// Boxing it to even the variants out would change nothing at the wire level
// (serde is transparent through Box) but would add an indirection to every
// call site for a lint about a type that is constructed a few times per
// transfer, not in a hot loop.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImportTokenResult {
    /// Plaintext shown ONCE to the operator in the wizard; only its hash is stored.
    Minted {
        token: String,
        id: i64,
        expires_at: i64,
    },
    Resolved(Option<ImportTokenInfo>),
    Listed(Vec<ImportTokenInfo>),
    Ack,
}
