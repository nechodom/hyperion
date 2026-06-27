//! Panel-neutral intermediate representation produced by a [`SourceAdapter`].
//!
//! The IR is deliberately self-contained (plain strings / small enums, no
//! dependency on `hyperion-types`/`hyperion-rpc`) so adapters never reach into
//! Hyperion's target vocabulary. The core-side engine maps IR → `HostingCreateReq`.

use serde::{Deserialize, Serialize};

/// Everything an adapter could extract from one source panel.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ImportIR {
    pub source: SourceSummary,
    pub hostings: Vec<IrHosting>,
    /// Things the source manages but Hyperion can't import yet — surfaced to the
    /// operator in the report rather than silently dropped (the "honesty rule").
    pub unsupported: Vec<IrUnsupported>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SourceSummary {
    /// `"hestiacp"` | `"cloudpanel"`.
    pub kind: String,
    pub version: String,
    /// Hostname / ssh target / archive path — for the operator report.
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrHosting {
    /// Stable idempotency key: `"<panel>:<owner>:<domain>"`. Recorded on the
    /// created Hyperion hosting so a re-run detects it and reports `Skip`.
    pub source_key: String,
    pub domain: String,
    pub aliases: Vec<String>,
    /// The owning source linux / site user.
    pub owner_user: String,
    pub kind: IrSiteKind,
    /// `"8.2"` etc.; `None` for static / reverse-proxy sites.
    pub php_version: Option<String>,
    /// Absolute docroot path on the source box.
    pub docroot: String,
    /// Upstream URL for reverse-proxy sites.
    pub proxy_upstream: Option<String>,
    pub databases: Vec<IrDatabase>,
    /// Raw crontab lines belonging to this site's user.
    pub crons: Vec<String>,
    pub tls: Option<IrCert>,
    /// `authorized_keys` lines for the site user.
    pub ssh_keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IrSiteKind {
    Php,
    Static,
    ReverseProxy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrDatabase {
    pub name: String,
    pub engine: IrDbEngine,
    /// Captured at dump time when not known up front.
    pub charset: Option<String>,
    pub user: String,
    /// How to obtain the dump at apply-time (a command to run on the source).
    pub dump_hint: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IrDbEngine {
    MySql,
    MariaDb,
    Postgres,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrCert {
    pub cert_path: String,
    pub key_path: String,
    /// If true, prefer re-issuing via ACME over copying the existing pair.
    pub letsencrypt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrUnsupported {
    /// `"mail"` | `"dns"` | `"ftp"`.
    pub category: String,
    /// Human note for the operator report.
    pub detail: String,
}
