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
    /// Revoke a token.
    Cancel { id: i64 },
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
}

/// Result of an [`ImportTokenOp`].
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
