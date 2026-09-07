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
    /// Artefacts the exporter tried to pack and could not — one entry per
    /// skipped docroot or database, written into the bundle's own manifest.
    ///
    /// This is what lets the IMPORT side tell "the exporter deliberately left
    /// this out" apart from "the bundle arrived truncated". Without it a missing
    /// `docroot.tar.gz` is ambiguous, and the import resolved that ambiguity by
    /// creating an EMPTY site and reporting success.
    #[serde(default)]
    pub skipped: Vec<IrSkipped>,
}

/// One artefact the exporter could not pack, and why.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct IrSkipped {
    /// The hosting this belongs to.
    pub domain: String,
    /// `"docroot"` or `"db:<name>"`.
    pub what: String,
    pub why: String,
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
    /// Apparent size of the docroot on the SOURCE box (`du -sb`), in bytes —
    /// i.e. what this site will occupy again, UNCOMPRESSED, once its
    /// `docroot.tar.gz` is inflated into the target hosting tree.
    ///
    /// This travels in the bundle because the import side has no other way to
    /// know it: the compressed tarball is all it can see, and a 13 GB bundle
    /// routinely inflates to 30 GB+. Without it the target node's only space
    /// check was "can I receive the bundle", which approved a transfer that
    /// then ran the disk out mid-import, hours later, after some sites had
    /// already been created.
    ///
    /// `0` means NOT MEASURED (an unreadable docroot, or a bundle packed by an
    /// older exporter — hence `serde(default)`). Callers must treat `0` as "no
    /// figure" and skip the check rather than refuse work on a guess; `du -sb`
    /// never reports 0 for a directory that exists.
    #[serde(default)]
    pub docroot_bytes: u64,
    /// Σ of this site's database dumps as packed into the bundle, in bytes.
    /// Measured at pack time (the dumps do not exist before that), so it is
    /// `0` on a plan/scan and on bundles from an older exporter.
    ///
    /// Same convention as [`IrHosting::docroot_bytes`]: `0` = no figure.
    #[serde(default)]
    pub db_bytes: u64,
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
