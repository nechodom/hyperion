# Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build sub-project 1 (Foundation) of hyperion: privileged
`hyperion-agent` daemon + unprivileged `lm` CLI client communicating over a
local Unix-socket RPC, capable of provisioning + managing PHP/static
hostings on Debian 12 with nginx, PHP-FPM, MariaDB/PostgreSQL, and
Let's Encrypt certificates.

**Architecture:** Rust workspace with 9 library crates + 2 binaries.
Transport-agnostic `AgentApi` trait shared by Unix socket today and mTLS
TCP in sub-project 1.5. SQLite-backed state with WAL + foreign keys +
hash-chain audit log. LIFO rollback stack for multi-step provisioning.

**Tech Stack:** Rust 2024 (MSRV 1.80), `tokio`, `axum` (later),
`sqlx` + SQLite, `askama` (templating), `instant-acme` (ACME), `rustls`
(later, sub-project 1.5), `clap` (CLI), `tracing` (logs), `serde` +
`serde_json` (wire), `blake3` (audit hash), `argon2` (passwords later),
`thiserror` (lib errors), `anyhow` (binary errors), `proptest` /
`mockall` (tests).

---

## Phase A — Workspace + Foundational Crates

### Task 1: Workspace bootstrap

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `deny.toml`
- Create: `.gitignore` (already exists; verify)

- [ ] **Step 1: Write Cargo workspace root**

`Cargo.toml`:
```toml
[workspace]
resolver = "3"
members = [
    "crates/hyperion-types",
    "crates/hyperion-validate",
    "crates/hyperion-rpc",
    "crates/hyperion-rpc-server",
    "crates/hyperion-rpc-client",
    "crates/hyperion-state",
    "crates/hyperion-adapters",
    "crates/hyperion-core",
    "bin/hyperion-agent",
    "bin/lm",
]

[workspace.package]
edition = "2024"
rust-version = "1.80"
license = "AGPL-3.0-only"
repository = "https://github.com/kevinnechodom/hyperion"

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
anyhow = "1"
async-trait = "0.1"
sqlx = { version = "0.8", default-features = false, features = [
    "runtime-tokio", "sqlite", "macros", "migrate", "chrono"
] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v7", "serde"] }
ulid = { version = "1", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
blake3 = "1"
clap = { version = "4", features = ["derive"] }
askama = "0.12"
instant-acme = "0.7"
rcgen = "0.13"
regex = "1"
proptest = "1"
mockall = "0.13"
tempfile = "3"
nix = { version = "0.29", features = ["user", "fs"] }
once_cell = "1"
hex = "0.4"
zeroize = { version = "1", features = ["derive"] }
rand = "0.8"
rand_core = "0.6"

[profile.release]
strip = "symbols"
lto = "thin"
codegen-units = 1
```

- [ ] **Step 2: Write rust-toolchain.toml**

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
profile = "minimal"
```

- [ ] **Step 3: Write deny.toml**

`deny.toml`:
```toml
[graph]
all-features = true

[advisories]
yanked = "warn"

[licenses]
allow = ["MIT","Apache-2.0","Apache-2.0 WITH LLVM-exception","BSD-3-Clause","BSD-2-Clause","Unicode-DFS-2016","Unicode-3.0","ISC","Zlib","CC0-1.0","MPL-2.0"]
confidence-threshold = 0.92

[bans]
multiple-versions = "warn"
```

- [ ] **Step 4: Run `cargo check --workspace` — expected: error because
      no crate sources yet. This is expected; ignore.**

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml rust-toolchain.toml deny.toml
git commit -m "feat(workspace): bootstrap Cargo workspace + pinned toolchain"
```

---

### Task 2: `hyperion-types` crate — shared serde types

**Files:**
- Create: `crates/hyperion-types/Cargo.toml`
- Create: `crates/hyperion-types/src/lib.rs`
- Create: `crates/hyperion-types/src/ids.rs`
- Create: `crates/hyperion-types/src/php.rs`
- Create: `crates/hyperion-types/src/db.rs`
- Create: `crates/hyperion-types/src/cert.rs`
- Create: `crates/hyperion-types/src/hosting.rs`
- Test: inline `#[cfg(test)]` modules in each source

- [ ] **Step 1: Write crate manifest**

`crates/hyperion-types/Cargo.toml`:
```toml
[package]
name = "hyperion-types"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
uuid.workspace = true
ulid.workspace = true
chrono.workspace = true
```

- [ ] **Step 2: Write `src/lib.rs` re-exporting modules**

```rust
//! Shared serde types for hyperion.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

pub mod cert;
pub mod db;
pub mod hosting;
pub mod ids;
pub mod php;

pub use cert::{CertInfo, CertRenewOutcome, CertRenewResult};
pub use db::{DbProvision, DbSummary};
pub use hosting::{HostingDetail, HostingState, HostingSummary};
pub use ids::{AgentId, HostingId, SecretId};
pub use php::PhpVersion;
```

- [ ] **Step 3: Write `ids.rs` with tests**

```rust
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostingId(pub String);

impl HostingId {
    pub fn new_v7() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }
    pub fn as_str(&self) -> &str { &self.0 }
}
impl fmt::Display for HostingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new_v7() -> Self { Self(uuid::Uuid::now_v7().to_string()) }
    pub fn as_str(&self) -> &str { &self.0 }
}
impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(pub String);

impl SecretId {
    pub fn new() -> Self { Self(ulid::Ulid::new().to_string()) }
    pub fn as_str(&self) -> &str { &self.0 }
}
impl Default for SecretId { fn default() -> Self { Self::new() } }
impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hosting_id_serde_roundtrip() {
        let id = HostingId::new_v7();
        let s = serde_json::to_string(&id).unwrap();
        let back: HostingId = serde_json::from_str(&s).unwrap();
        assert_eq!(id, back);
    }
    #[test]
    fn hosting_id_v7_is_time_ordered() {
        let a = HostingId::new_v7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = HostingId::new_v7();
        assert!(a.as_str() < b.as_str(), "{} >= {}", a, b);
    }
    #[test]
    fn secret_id_uniqueness() {
        let mut set = std::collections::HashSet::new();
        for _ in 0..1000 { assert!(set.insert(SecretId::new())); }
    }
}
```

(serde_json is referenced in tests; add to dev-dependencies later in
`Cargo.toml`: `[dev-dependencies] serde_json.workspace = true`)

- [ ] **Step 4: Write `php.rs` with tests**

```rust
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PhpVersion { V8_1, V8_2, V8_3, V8_4 }

impl PhpVersion {
    pub fn as_str(self) -> &'static str {
        match self { Self::V8_1=>"8.1", Self::V8_2=>"8.2", Self::V8_3=>"8.3", Self::V8_4=>"8.4" }
    }
    pub fn pkg_name(self) -> String { format!("php{}-fpm", self.as_str()) }
    pub fn service_name(self) -> String { format!("php{}-fpm", self.as_str()) }
    pub fn pool_dir(self) -> String { format!("/etc/php/{}/fpm/pool.d", self.as_str()) }
}

impl fmt::Display for PhpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

impl FromStr for PhpVersion {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "8.1" => Ok(Self::V8_1), "8.2" => Ok(Self::V8_2),
            "8.3" => Ok(Self::V8_3), "8.4" => Ok(Self::V8_4),
            _ => Err(format!("unsupported php version: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn known_versions() {
        for v in ["8.1","8.2","8.3","8.4"] { assert!(PhpVersion::from_str(v).is_ok()); }
    }
    #[test] fn rejected_versions() {
        for v in ["7.4","9.0","","8","8.1.0"," 8.3"] {
            assert!(PhpVersion::from_str(v).is_err(), "should reject: {v}");
        }
    }
    #[test] fn pool_dir_shape() {
        assert_eq!(PhpVersion::V8_3.pool_dir(), "/etc/php/8.3/fpm/pool.d");
    }
}
```

- [ ] **Step 5: Write `db.rs` with tests**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbProvision { MariaDB, Postgres }

impl DbProvision {
    pub fn as_str(self) -> &'static str {
        match self { Self::MariaDB => "mariadb", Self::Postgres => "postgres" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbSummary {
    pub engine: DbProvision,
    pub db_name: String,
    pub db_user: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn serde_lowercase() {
        let v = DbProvision::MariaDB;
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "\"mariadb\"");
    }
    #[test] fn roundtrip() {
        let v = DbSummary { engine: DbProvision::Postgres,
            db_name: "x".into(), db_user: "y".into() };
        let s = serde_json::to_string(&v).unwrap();
        let back: DbSummary = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }
}
```

- [ ] **Step 6: Write `cert.rs` with tests**

```rust
use crate::ids::HostingId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertInfo {
    pub domain: String,
    pub sans: Vec<String>,
    pub issuer: String,
    pub not_after: i64,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertRenewResult {
    pub domain: String,
    pub outcome: CertRenewOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CertRenewOutcome {
    Renewed { new_not_after: i64 },
    Skipped { reason: String },
    Failed { error: String },
}

// avoid unused-import warning when HostingId only re-exported elsewhere
const _: Option<HostingId> = None;

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn roundtrip() {
        let r = CertRenewResult { domain: "x".into(),
            outcome: CertRenewOutcome::Renewed { new_not_after: 1 } };
        let s = serde_json::to_string(&r).unwrap();
        let back: CertRenewResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }
}
```

- [ ] **Step 7: Write `hosting.rs` with tests**

```rust
use crate::{cert::CertInfo, db::DbSummary, ids::HostingId, php::PhpVersion};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostingState { Provisioning, Active, Failed, Deleting }

impl HostingState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active       => "active",
            Self::Failed       => "failed",
            Self::Deleting     => "deleting",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingSummary {
    pub id: HostingId,
    pub domain: String,
    pub state: HostingState,
    pub php_version: Option<PhpVersion>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingDetail {
    pub id: HostingId,
    pub domain: String,
    pub aliases: Vec<String>,
    pub state: HostingState,
    pub system_user: String,
    pub php_version: Option<PhpVersion>,
    pub root_dir: String,
    pub database: Option<DbSummary>,
    pub cert: Option<CertInfo>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbProvision;
    #[test] fn roundtrip() {
        let d = HostingDetail {
            id: HostingId::new_v7(), domain: "example.cz".into(),
            aliases: vec!["www.example.cz".into()],
            state: HostingState::Active, system_user: "example_cz".into(),
            php_version: Some(PhpVersion::V8_3),
            root_dir: "/home/example_cz/example.cz/htdocs".into(),
            database: Some(DbSummary { engine: DbProvision::MariaDB,
                db_name: "lm_a_db".into(), db_user: "lm_a_u".into() }),
            cert: None, created_at: 1, updated_at: 2,
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: HostingDetail = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }
}
```

- [ ] **Step 8: Add dev-dependencies and run tests**

Update `crates/hyperion-types/Cargo.toml`:
```toml
[dev-dependencies]
serde_json.workspace = true
```

Run:
```bash
cargo test -p hyperion-types
```

Expected: all tests pass (≥ 10 tests).

- [ ] **Step 9: Commit**

```bash
git add crates/hyperion-types
git commit -m "feat(hyperion-types): shared serde types (ids, php, db, cert, hosting)"
```

---

### Task 3: `hyperion-validate` crate — input parsers

**Files:**
- Create: `crates/hyperion-validate/Cargo.toml`
- Create: `crates/hyperion-validate/src/lib.rs`
- Create: `crates/hyperion-validate/src/domain.rs`
- Create: `crates/hyperion-validate/src/sysuser.rs`

- [ ] **Step 1: Manifest**

```toml
[package]
name = "hyperion-validate"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
once_cell.workspace = true
regex.workspace = true
thiserror.workspace = true

[dev-dependencies]
proptest.workspace = true
serde_json.workspace = true
```

- [ ] **Step 2: `lib.rs`**

```rust
//! Input validation primitives. Every public type carries proof that
//! its value matches a strict whitelist regex.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

pub mod domain;
pub mod sysuser;

pub use domain::Domain;
pub use sysuser::SystemUserName;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("invalid domain '{0}': {1}")]
    InvalidDomain(String, &'static str),
    #[error("invalid system user '{0}': {1}")]
    InvalidSystemUser(String, &'static str),
}
```

- [ ] **Step 3: `domain.rs` with proptest**

```rust
use crate::ValidationError;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

// RFC 1035-ish: labels 1..=63 chars, total <= 253, alphanumeric + hyphen,
// no leading/trailing hyphen, TLD must contain at least one alpha char.
static LABEL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap()
});

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Domain(String);

impl Domain {
    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
        if s.is_empty()          { return Err(err(&s, "empty")); }
        if s.len() > 253         { return Err(err(&s, "longer than 253 chars")); }
        let labels: Vec<&str> = s.split('.').collect();
        if labels.len() < 2      { return Err(err(&s, "needs at least 2 labels")); }
        if labels.iter().any(|l| l.is_empty()) {
            return Err(err(&s, "empty label"));
        }
        for l in &labels {
            if l.len() > 63 || !LABEL.is_match(l) {
                return Err(err(&s, "label fails regex"));
            }
        }
        if !labels.last().unwrap().chars().any(|c| c.is_ascii_alphabetic()) {
            return Err(err(&s, "TLD must contain a letter"));
        }
        Ok(Self(s))
    }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn into_inner(self) -> String { self.0 }
}

fn err(s: &str, m: &'static str) -> ValidationError {
    ValidationError::InvalidDomain(s.to_string(), m)
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl FromStr for Domain {
    type Err = ValidationError;
    fn from_str(s: &str) -> Result<Self, ValidationError> { Self::parse(s) }
}
impl TryFrom<String> for Domain {
    type Error = ValidationError;
    fn try_from(s: String) -> Result<Self, ValidationError> { Self::parse(&s) }
}
impl From<Domain> for String { fn from(d: Domain) -> Self { d.0 } }

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test] fn accepts_common() {
        for d in ["example.cz","www.example.cz","sub.do-main.co.uk",
                  "xn--bcher-kva.de","a.io","ABC.example.com","example.cz."] {
            assert!(Domain::parse(d).is_ok(), "should accept: {d}");
        }
    }
    #[test] fn rejects_bad() {
        for d in ["","example","-bad.cz","bad-.cz",".cz","cz.",
                  "exa mple.cz","very-very-very-very-very-very-very-very-very-very-very-very-long-label-no-good.cz"] {
            assert!(Domain::parse(d).is_err(), "should reject: {d}");
        }
        // length > 253
        let too_long = format!("{}.cz", "a".repeat(252));
        assert!(Domain::parse(&too_long).is_err());
    }
    #[test] fn lowercased() {
        let d = Domain::parse("Example.CZ").unwrap();
        assert_eq!(d.as_str(), "example.cz");
    }
    #[test] fn serde_round_trip() {
        let d = Domain::parse("example.cz").unwrap();
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(s, "\"example.cz\"");
        let back: Domain = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }
    proptest! {
        #[test] fn never_panics_on_random_input(s in "\\PC{0,300}") {
            let _ = Domain::parse(&s);
        }
    }
}
```

- [ ] **Step 4: `sysuser.rs` with proptest**

```rust
use crate::ValidationError;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z][a-z0-9_]{2,31}$").unwrap());

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SystemUserName(String);

impl SystemUserName {
    pub fn parse(s: &str) -> Result<Self, ValidationError> {
        if !RE.is_match(s) {
            return Err(ValidationError::InvalidSystemUser(
                s.to_string(),
                "must match ^[a-z][a-z0-9_]{2,31}$",
            ));
        }
        Ok(Self(s.to_string()))
    }
    pub fn derive_from_domain(domain: &str) -> Result<Self, ValidationError> {
        let mut out = String::with_capacity(32);
        let mut chars = domain.chars().filter_map(|c| match c {
            'a'..='z' | '0'..='9' => Some(c),
            'A'..='Z' => Some(c.to_ascii_lowercase()),
            '.' | '-' => Some('_'),
            _ => None,
        });
        // Ensure first char is alpha
        let first = chars.next().unwrap_or('x');
        if first.is_ascii_alphabetic() { out.push(first); }
        else { out.push('x'); out.push(first); }
        for c in chars { if out.len() >= 32 { break; } out.push(c); }
        while out.len() < 3 { out.push('_'); }
        // collapse repeats of '_'
        let mut collapsed = String::with_capacity(out.len());
        let mut prev_underscore = false;
        for c in out.chars() {
            if c == '_' && prev_underscore { continue; }
            prev_underscore = c == '_';
            collapsed.push(c);
        }
        if collapsed.ends_with('_') { collapsed.pop(); while collapsed.len() < 3 { collapsed.push('x'); } }
        Self::parse(&collapsed)
    }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn into_inner(self) -> String { self.0 }
}

impl fmt::Display for SystemUserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl FromStr for SystemUserName {
    type Err = ValidationError;
    fn from_str(s: &str) -> Result<Self, ValidationError> { Self::parse(s) }
}
impl TryFrom<String> for SystemUserName {
    type Error = ValidationError;
    fn try_from(s: String) -> Result<Self, ValidationError> { Self::parse(&s) }
}
impl From<SystemUserName> for String { fn from(d: SystemUserName) -> Self { d.0 } }

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test] fn accepts() {
        for s in ["abc","example_cz","kev1n_test","aaa"] {
            assert!(SystemUserName::parse(s).is_ok(), "{s}");
        }
    }
    #[test] fn rejects() {
        for s in ["", "ab", "1abc", "_abc", "Abc", "abc!", "a".repeat(33).as_str()] {
            assert!(SystemUserName::parse(s).is_err(), "{s}");
        }
    }
    #[test] fn derive_from_domain_basic() {
        assert_eq!(SystemUserName::derive_from_domain("example.cz").unwrap().as_str(), "example_cz");
        assert_eq!(SystemUserName::derive_from_domain("www.example.cz").unwrap().as_str(), "www_example_cz");
        assert_eq!(SystemUserName::derive_from_domain("foo-bar.io").unwrap().as_str(), "foo_bar_io");
        let n = SystemUserName::derive_from_domain("a-very-extremely-long-subdomain-name-here.cz").unwrap();
        assert!(n.as_str().len() <= 32);
    }
    proptest! {
        #[test] fn never_panics(s in "\\PC{0,300}") { let _ = SystemUserName::parse(&s); }
        #[test] fn derive_never_panics(s in "[a-zA-Z0-9.-]{1,80}") {
            let _ = SystemUserName::derive_from_domain(&s);
        }
    }
}
```

- [ ] **Step 5: Run**

```bash
cargo test -p hyperion-validate
```

Expected: all tests pass; proptest runs 256 cases each by default.

- [ ] **Step 6: Commit**

```bash
git add crates/hyperion-validate
git commit -m "feat(hyperion-validate): Domain + SystemUserName parsers with property tests"
```

---

### Task 4: `hyperion-rpc` crate — trait + wire types + error + frame codec

**Files:**
- Create: `crates/hyperion-rpc/Cargo.toml`
- Create: `crates/hyperion-rpc/src/lib.rs`
- Create: `crates/hyperion-rpc/src/error.rs`
- Create: `crates/hyperion-rpc/src/wire.rs`
- Create: `crates/hyperion-rpc/src/api.rs`
- Create: `crates/hyperion-rpc/src/codec.rs`

- [ ] **Step 1: Manifest**

```toml
[package]
name = "hyperion-rpc"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
hyperion-types = { path = "../hyperion-types" }
hyperion-validate = { path = "../hyperion-validate" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
async-trait.workspace = true
tokio = { workspace = true, features = ["io-util"] }

[dev-dependencies]
tokio = { workspace = true, features = ["macros","rt"] }
proptest.workspace = true
```

- [ ] **Step 2: `error.rs`**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum RpcError {
    #[error("validation failed: {message}")]
    Validation { message: String },
    #[error("entity already exists: {kind} {id}")]
    AlreadyExists { kind: String, id: String },
    #[error("not found: {kind} {id}")]
    NotFound { kind: String, id: String },
    #[error("provisioning failed at stage '{stage}': {reason}")]
    ProvisioningFailed { stage: String, reason: String },
    #[error("system command failed: {cmd} exit {code}")]
    SystemCommand { cmd: String, code: i32, stderr_tail: String },
    #[error("conflict: {message}")]
    Conflict { message: String },
    #[error("internal error")]
    Internal,
}

impl From<hyperion_validate::ValidationError> for RpcError {
    fn from(e: hyperion_validate::ValidationError) -> Self {
        Self::Validation { message: e.to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn serde_round_trip_each_variant() {
        let cases = vec![
            RpcError::Validation { message: "m".into() },
            RpcError::AlreadyExists { kind: "k".into(), id: "i".into() },
            RpcError::NotFound { kind: "k".into(), id: "i".into() },
            RpcError::ProvisioningFailed { stage: "s".into(), reason: "r".into() },
            RpcError::SystemCommand { cmd: "c".into(), code: 1, stderr_tail: "e".into() },
            RpcError::Conflict { message: "c".into() },
            RpcError::Internal,
        ];
        for c in cases {
            let s = serde_json::to_string(&c).unwrap();
            let back: RpcError = serde_json::from_str(&s).unwrap();
            assert_eq!(c, back);
        }
    }
    #[test] fn from_validation_error() {
        let e: RpcError = hyperion_validate::ValidationError::InvalidDomain("x".into(), "bad").into();
        match e { RpcError::Validation { .. } => {}, _ => panic!("wrong variant") }
    }
}
```

- [ ] **Step 3: `wire.rs`**

```rust
use hyperion_types::*;
use hyperion_validate::{Domain, SystemUserName};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentInfo {
    pub hostname: String,
    pub version: String,
    pub schema_version: i64,
    pub hostings_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingCreateReq {
    pub domain: Domain,
    pub aliases: Vec<Domain>,
    pub php_version: Option<PhpVersion>,
    pub database: Option<DbProvision>,
    pub system_user: Option<SystemUserName>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostingCreated {
    pub id: HostingId,
    pub system_user: String,
    pub root_dir: String,
    pub db: Option<DbCredentials>,
    pub cert: Option<CertInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbCredentials {
    pub engine: DbProvision,
    pub db_name: String,
    pub db_user: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum HostingSelector { Id(HostingId), Domain(Domain) }

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DeleteOpts {
    pub keep_user: bool,
    pub keep_database: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn selector_variants_roundtrip() {
        let s = HostingSelector::Id(HostingId::new_v7());
        let j = serde_json::to_string(&s).unwrap();
        let back: HostingSelector = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
        let d = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
        let j = serde_json::to_string(&d).unwrap();
        let back: HostingSelector = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
```

- [ ] **Step 4: `api.rs`**

```rust
use crate::{error::RpcError, wire::*};
use async_trait::async_trait;
use hyperion_types::*;
use hyperion_validate::Domain;

#[async_trait]
pub trait AgentApi: Send + Sync + 'static {
    async fn agent_info(&self) -> Result<AgentInfo, RpcError>;

    async fn hosting_create(&self, req: HostingCreateReq)
        -> Result<HostingCreated, RpcError>;
    async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError>;
    async fn hosting_get(&self, sel: HostingSelector)
        -> Result<HostingDetail, RpcError>;
    async fn hosting_delete(&self, sel: HostingSelector, opts: DeleteOpts)
        -> Result<(), RpcError>;

    async fn cert_issue(&self, domain: Domain) -> Result<CertInfo, RpcError>;
    async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError>;
}
```

- [ ] **Step 5: `codec.rs` — JSON length-prefixed framing**

```rust
use crate::{error::RpcError, wire::*};
use hyperion_types::*;
use hyperion_validate::Domain;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    AgentInfo,
    HostingCreate(HostingCreateReq),
    HostingList,
    HostingGet(HostingSelector),
    HostingDelete { sel: HostingSelector, opts: DeleteOpts },
    CertIssue { domain: Domain },
    CertRenewAll,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(tag = "method", content = "result", rename_all = "snake_case")]
pub enum Response {
    AgentInfo(AgentInfo),
    HostingCreate(HostingCreated),
    HostingList(Vec<HostingSummary>),
    HostingGet(HostingDetail),
    HostingDelete,
    CertIssue(CertInfo),
    CertRenewAll(Vec<CertRenewResult>),
    Error(RpcError),
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W, value: &T,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("frame {} exceeds MAX_FRAME {}", bytes.len(), MAX_FRAME),
        ));
    }
    w.write_u32(bytes.len() as u32).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> std::io::Result<T> {
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
    async fn round_trip_request_response() {
        let (mut a, mut b) = duplex(8192);
        let req = Request::HostingList;
        write_frame(&mut a, &req).await.unwrap();
        let got: Request = read_frame(&mut b).await.unwrap();
        assert_eq!(req, got);
    }
    #[tokio::test]
    async fn refuses_overlarge_frame_read() {
        let (mut a, mut b) = duplex(8192);
        a.write_u32((MAX_FRAME + 1) as u32).await.unwrap();
        let r: std::io::Result<Request> = read_frame(&mut b).await;
        assert!(r.is_err());
    }
}
```

- [ ] **Step 6: `lib.rs`**

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

pub mod api;
pub mod codec;
pub mod error;
pub mod wire;

pub use api::AgentApi;
pub use codec::{read_frame, write_frame, Request, Response, MAX_FRAME};
pub use error::RpcError;
pub use wire::*;
```

- [ ] **Step 7: Run**

```bash
cargo test -p hyperion-rpc
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add crates/hyperion-rpc
git commit -m "feat(hyperion-rpc): typed trait + wire types + JSON frame codec"
```

---

## Phase B — State Layer

### Task 5: `hyperion-state` crate — schema, migrations, queries

**Files:**
- Create: `crates/hyperion-state/Cargo.toml`
- Create: `crates/hyperion-state/migrations/001_initial.sql`
- Create: `crates/hyperion-state/src/lib.rs`
- Create: `crates/hyperion-state/src/db.rs`
- Create: `crates/hyperion-state/src/system_users.rs`
- Create: `crates/hyperion-state/src/hostings.rs`
- Create: `crates/hyperion-state/src/databases.rs`
- Create: `crates/hyperion-state/src/certificates.rs`
- Create: `crates/hyperion-state/src/audit.rs`

- [ ] **Step 1: Manifest**

```toml
[package]
name = "hyperion-state"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
hyperion-types = { path = "../hyperion-types" }
hyperion-validate = { path = "../hyperion-validate" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
sqlx = { workspace = true }
chrono.workspace = true
blake3.workspace = true
hex.workspace = true
tokio.workspace = true
tracing.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["macros","rt"] }
tempfile.workspace = true
```

- [ ] **Step 2: Migration `001_initial.sql`** — copy DDL from Foundation spec §8.2

(Use the SQL from `docs/superpowers/specs/2026-05-31-foundation-design.md`
§8.2 verbatim.)

- [ ] **Step 3: `src/db.rs` — pool open + migrations**

```rust
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("sqlx: {0}")] Sqlx(#[from] sqlx::Error),
    #[error("migrate: {0}")] Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("audit chain broken at row {row}: expected {expected}, got {got}")]
    AuditChain { row: i64, expected: String, got: String },
}

pub async fn open(path: &Path) -> Result<SqlitePool, StateError> {
    if let Some(parent) = path.parent() { let _ = std::fs::create_dir_all(parent); }
    let url = format!("sqlite://{}", path.display());
    let opts = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new().max_connections(8).connect_with(opts).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub async fn open_memory() -> Result<SqlitePool, StateError> {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
    let pool = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test] async fn memory_db_runs_migrations() {
        let pool = open_memory().await.unwrap();
        let row: (i64,) = sqlx::query_as("SELECT count(*) FROM hostings")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(row.0, 0);
    }
}
```

- [ ] **Step 4-8: `system_users.rs`, `hostings.rs`, `databases.rs`,
       `certificates.rs`, `audit.rs`** — each implements typed query
       helpers + tests using `open_memory`. See spec §11 for the data
       shapes and §13 for hash-chain requirements.

**Tests required (in-memory SQLite, each gets a fresh DB):**
- `system_users::insert + get_by_name + uid_uniqueness`
- `hostings::insert + list + get_by_id + get_by_domain + state transitions`
- `hostings::cascade_deletes_aliases_and_databases`
- `databases::insert_unique_per_engine_dbname`
- `certificates::find_expiring_within(days)`
- `audit::append_chains_correctly + verify_chain`
- `audit::detects_tampering`

(Each file is ≈80–150 lines; structured queries + a tests module.)

- [ ] **Step 9: Run `cargo test -p hyperion-state`** — expect all tests pass.

- [ ] **Step 10: Commit**

```bash
git add crates/hyperion-state
git commit -m "feat(hyperion-state): SQLite schema, queries, hash-chain audit log"
```

---

## Phase C — RPC Transport (Unix socket)

### Task 6: `hyperion-rpc-server` + `hyperion-rpc-client` crates

**Files:**
- Create: `crates/hyperion-rpc-server/Cargo.toml`
- Create: `crates/hyperion-rpc-server/src/lib.rs`
- Create: `crates/hyperion-rpc-client/Cargo.toml`
- Create: `crates/hyperion-rpc-client/src/lib.rs`

- [ ] **Step 1: Server manifest + lib.rs**

Manifest depends on `hyperion-rpc`, `tokio` (features: `net`), `tracing`,
`thiserror`, `async-trait`.

`lib.rs`:
```rust
//! Unix-socket RPC server: listens on a path, dispatches each frame
//! through an Arc<dyn AgentApi>.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

use hyperion_rpc::codec::{read_frame, write_frame, Request, Response};
use hyperion_rpc::{AgentApi, RpcError};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io: {0}")] Io(#[from] std::io::Error),
}

pub struct Server {
    listener: UnixListener,
    api: Arc<dyn AgentApi>,
    socket_path: PathBuf,
}

impl Server {
    pub async fn bind(path: &Path, api: Arc<dyn AgentApi>) -> Result<Self, ServerError> {
        if path.exists() { std::fs::remove_file(path)?; }
        let listener = UnixListener::bind(path)?;
        // mode 0660 (group hyperion-admin will be added by deployment; here just owner+group rw)
        let perms = std::fs::Permissions::from_mode(0o660);
        std::fs::set_permissions(path, perms)?;
        Ok(Self { listener, api, socket_path: path.to_owned() })
    }
    pub async fn run(self) -> Result<(), ServerError> {
        loop {
            let (stream, _addr) = self.listener.accept().await?;
            let api = self.api.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, api).await {
                    error!(error=%e, "conn handler failed");
                }
            });
        }
    }
    pub fn socket_path(&self) -> &Path { &self.socket_path }
}

async fn handle_conn(mut stream: UnixStream, api: Arc<dyn AgentApi>) -> std::io::Result<()> {
    let req: Request = read_frame(&mut stream).await?;
    debug!(?req, "received request");
    let resp = dispatch(api, req).await;
    write_frame(&mut stream, &resp).await?;
    Ok(())
}

async fn dispatch(api: Arc<dyn AgentApi>, req: Request) -> Response {
    match req {
        Request::AgentInfo => match api.agent_info().await {
            Ok(v) => Response::AgentInfo(v), Err(e) => Response::Error(e) },
        Request::HostingCreate(r) => match api.hosting_create(r).await {
            Ok(v) => Response::HostingCreate(v), Err(e) => Response::Error(e) },
        Request::HostingList => match api.hosting_list().await {
            Ok(v) => Response::HostingList(v), Err(e) => Response::Error(e) },
        Request::HostingGet(s) => match api.hosting_get(s).await {
            Ok(v) => Response::HostingGet(v), Err(e) => Response::Error(e) },
        Request::HostingDelete { sel, opts } => match api.hosting_delete(sel, opts).await {
            Ok(_) => Response::HostingDelete, Err(e) => Response::Error(e) },
        Request::CertIssue { domain } => match api.cert_issue(domain).await {
            Ok(v) => Response::CertIssue(v), Err(e) => Response::Error(e) },
        Request::CertRenewAll => match api.cert_renew_all().await {
            Ok(v) => Response::CertRenewAll(v), Err(e) => Response::Error(e) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hyperion_rpc::wire::*;
    use hyperion_types::*;
    use hyperion_validate::Domain;

    struct EchoApi;
    #[async_trait]
    impl AgentApi for EchoApi {
        async fn agent_info(&self) -> Result<AgentInfo, RpcError> {
            Ok(AgentInfo { hostname: "h".into(), version: "0".into(), schema_version: 1, hostings_count: 0 })
        }
        async fn hosting_create(&self, _: HostingCreateReq) -> Result<HostingCreated, RpcError> {
            Err(RpcError::Internal)
        }
        async fn hosting_list(&self) -> Result<Vec<HostingSummary>, RpcError> { Ok(vec![]) }
        async fn hosting_get(&self, _: HostingSelector) -> Result<HostingDetail, RpcError> {
            Err(RpcError::NotFound { kind: "hosting".into(), id: "x".into() })
        }
        async fn hosting_delete(&self, _: HostingSelector, _: DeleteOpts) -> Result<(), RpcError> { Ok(()) }
        async fn cert_issue(&self, _: Domain) -> Result<CertInfo, RpcError> { Err(RpcError::Internal) }
        async fn cert_renew_all(&self) -> Result<Vec<CertRenewResult>, RpcError> { Ok(vec![]) }
    }

    #[tokio::test]
    async fn agent_info_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let srv = Server::bind(&path, Arc::new(EchoApi)).await.unwrap();
        let p = path.clone();
        tokio::spawn(srv.run());
        // give it a tick
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let resp = hyperion_rpc_client::call(&p, Request::AgentInfo).await.unwrap();
        match resp { Response::AgentInfo(_) => {}, _ => panic!("bad resp") }
    }
}
```

- [ ] **Step 2: Client manifest + lib.rs**

```rust
//! Unix-socket RPC client. One call per connection.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

use hyperion_rpc::codec::{read_frame, write_frame, Request, Response};
use std::path::Path;
use tokio::net::UnixStream;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io: {0}")] Io(#[from] std::io::Error),
}

pub async fn call(socket: &Path, req: Request) -> Result<Response, ClientError> {
    let mut stream = UnixStream::connect(socket).await?;
    write_frame(&mut stream, &req).await?;
    let resp: Response = read_frame(&mut stream).await?;
    Ok(resp)
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p hyperion-rpc-server -p hyperion-rpc-client
```

- [ ] **Step 4: Commit**

```bash
git add crates/hyperion-rpc-server crates/hyperion-rpc-client
git commit -m "feat(hyperion-rpc): Unix-socket server + client transport"
```

---

## Phase D — Adapters

### Task 7: `hyperion-adapters` crate skeleton + `fs` + `users` + rollback trait

**Files:**
- Create: `crates/hyperion-adapters/Cargo.toml`
- Create: `crates/hyperion-adapters/src/lib.rs`
- Create: `crates/hyperion-adapters/src/rollback.rs`
- Create: `crates/hyperion-adapters/src/fs.rs`
- Create: `crates/hyperion-adapters/src/users.rs`
- Create: `crates/hyperion-adapters/src/cmd.rs`
- Create: `crates/hyperion-adapters/src/nginx.rs`
- Create: `crates/hyperion-adapters/src/phpfpm.rs`
- Create: `crates/hyperion-adapters/src/mariadb.rs`
- Create: `crates/hyperion-adapters/src/postgres.rs`
- Create: `crates/hyperion-adapters/src/acme.rs`
- Create: `crates/hyperion-adapters/templates/nginx-vhost.conf.j2`
- Create: `crates/hyperion-adapters/templates/nginx-vhost-suspended.conf.j2`
- Create: `crates/hyperion-adapters/templates/phpfpm-pool.conf.j2`

- [ ] **Step 1: Manifest**

```toml
[package]
name = "hyperion-adapters"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
hyperion-types = { path = "../hyperion-types" }
hyperion-validate = { path = "../hyperion-validate" }
hyperion-rpc = { path = "../hyperion-rpc" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = { workspace = true }
tracing.workspace = true
askama.workspace = true
instant-acme.workspace = true
rcgen.workspace = true
nix.workspace = true
rand.workspace = true
hex.workspace = true
async-trait.workspace = true
mockall = { workspace = true, optional = true }
sqlx = { workspace = true }

[dev-dependencies]
tempfile.workspace = true
tokio = { workspace = true, features = ["macros","rt"] }
mockall.workspace = true
```

- [ ] **Step 2: `lib.rs`**

```rust
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]

pub mod cmd;
pub mod fs;
pub mod rollback;
pub mod users;
pub mod nginx;
pub mod phpfpm;
pub mod mariadb;
pub mod postgres;
pub mod acme;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("command {cmd} failed with exit {code}: {stderr_tail}")]
    Command { cmd: String, code: i32, stderr_tail: String },
    #[error("template render: {0}")] Render(#[from] askama::Error),
    #[error("validation: {0}")] Validation(#[from] hyperion_validate::ValidationError),
    #[error("acme: {0}")] Acme(String),
    #[error("conflict: {0}")] Conflict(String),
    #[error("other: {0}")] Other(String),
}

impl From<AdapterError> for hyperion_rpc::RpcError {
    fn from(e: AdapterError) -> Self {
        match e {
            AdapterError::Command { cmd, code, stderr_tail } =>
                hyperion_rpc::RpcError::SystemCommand { cmd, code, stderr_tail },
            AdapterError::Conflict(m) => hyperion_rpc::RpcError::Conflict { message: m },
            AdapterError::Validation(v) => v.into(),
            _ => hyperion_rpc::RpcError::Internal,
        }
    }
}
```

- [ ] **Step 3: `rollback.rs` — LIFO stack of trait objects**

```rust
use std::fmt;

#[async_trait::async_trait]
pub trait Rollback: Send + Sync {
    async fn run(&self) -> Result<(), String>;
    fn label(&self) -> &str;
}

pub struct RollbackStack {
    actions: Vec<Box<dyn Rollback>>,
}

impl RollbackStack {
    pub fn new() -> Self { Self { actions: vec![] } }
    pub fn push(&mut self, a: Box<dyn Rollback>) { self.actions.push(a); }
    /// Pop and run all actions in LIFO; collect failures (do not stop).
    pub async fn rollback_all(&mut self) -> Vec<String> {
        let mut errs = vec![];
        while let Some(a) = self.actions.pop() {
            let label = a.label().to_string();
            if let Err(e) = a.run().await { errs.push(format!("{}: {}", label, e)); }
            tracing::info!(action=%label, "rollback executed");
        }
        errs
    }
    /// Consume the stack and discard (success path).
    pub fn forget(self) { drop(self.actions); }
    pub fn len(&self) -> usize { self.actions.len() }
    pub fn is_empty(&self) -> bool { self.actions.is_empty() }
}
impl Default for RollbackStack { fn default() -> Self { Self::new() } }
impl fmt::Debug for RollbackStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RollbackStack {{ depth: {} }}", self.actions.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicU32, Ordering}};

    struct R { name: String, counter: Arc<AtomicU32>, mine: u32 }
    #[async_trait::async_trait]
    impl Rollback for R {
        async fn run(&self) -> Result<(), String> {
            // assert LIFO: each action sees current value == its own ordinal
            let cur = self.counter.fetch_sub(1, Ordering::SeqCst);
            assert_eq!(cur, self.mine, "LIFO violated by {}", self.name);
            Ok(())
        }
        fn label(&self) -> &str { &self.name }
    }
    #[tokio::test] async fn lifo_order() {
        let c = Arc::new(AtomicU32::new(3));
        let mut s = RollbackStack::new();
        s.push(Box::new(R { name: "a".into(), counter: c.clone(), mine: 1 }));
        s.push(Box::new(R { name: "b".into(), counter: c.clone(), mine: 2 }));
        s.push(Box::new(R { name: "c".into(), counter: c.clone(), mine: 3 }));
        let errs = s.rollback_all().await;
        assert!(errs.is_empty());
        assert_eq!(c.load(Ordering::SeqCst), 0);
    }
}
```

- [ ] **Step 4: `cmd.rs` — typed Command runner with stderr capture**

```rust
use crate::AdapterError;
use tokio::process::Command;
use tracing::debug;

pub async fn run(program: &str, args: &[&str]) -> Result<String, AdapterError> {
    debug!(program, ?args, "exec");
    let out = Command::new(program).args(args).output().await?;
    if !out.status.success() {
        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail = stderr.chars().rev().take(4096).collect::<String>().chars().rev().collect();
        return Err(AdapterError::Command {
            cmd: format!("{program} {}", args.join(" ")),
            code, stderr_tail: tail,
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
```

- [ ] **Step 5: `fs.rs` — atomic write, ensure_dir, no symlink TOCTOU**

```rust
use crate::AdapterError;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs;

pub async fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AdapterError> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).await?; }
    let tmp = with_extension(path, "tmp");
    fs::write(&tmp, bytes).await?;
    let perms = std::fs::Permissions::from_mode(mode);
    fs::set_permissions(&tmp, perms).await?;
    fs::rename(&tmp, path).await?;
    Ok(())
}

pub async fn ensure_dir(path: &Path, mode: u32) -> Result<(), AdapterError> {
    if let Ok(md) = fs::symlink_metadata(path).await {
        if md.file_type().is_symlink() {
            return Err(AdapterError::Other(format!("refusing to use symlink: {}", path.display())));
        }
        if md.file_type().is_dir() {
            fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
            return Ok(());
        }
    }
    fs::create_dir_all(path).await?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    Ok(())
}

fn with_extension(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test] async fn atomic_write_creates_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a/b/c.txt");
        atomic_write(&p, b"hi", 0o644).await.unwrap();
        let s = fs::read_to_string(&p).await.unwrap();
        assert_eq!(s, "hi");
        let m = fs::metadata(&p).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o644);
    }
    #[tokio::test] async fn ensure_dir_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x/y");
        ensure_dir(&p, 0o750).await.unwrap();
        ensure_dir(&p, 0o750).await.unwrap(); // no panic
        let m = fs::metadata(&p).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o750);
    }
    #[tokio::test] async fn refuses_symlink() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("real");
        std::fs::create_dir_all(&target).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = ensure_dir(&link, 0o750).await.unwrap_err();
        match err { AdapterError::Other(m) => assert!(m.contains("symlink")),
                    _ => panic!("wrong err") }
    }
}
```

- [ ] **Step 6: `users.rs`** — `ensure_user` via `useradd`, `delete_user`
       via `userdel`. Tests gated by `#[ignore]` (require root).

(Skeleton + tests pattern provided; integration tests `#[ignore]`.)

- [ ] **Step 7-10: `nginx.rs`, `phpfpm.rs`, `mariadb.rs`, `postgres.rs`**

Each follows the same shape:
- Template render (askama)
- `cmd::run` for `systemctl reload <service>`
- Idempotent ensure functions
- Rollback handles returned

Tests:
- Template rendering tested with snapshot strings on macOS (no system tools needed).
- Actual command invocation tests gated with `#[ignore]`.

- [ ] **Step 11: `acme.rs` — instant-acme integration**

Implements:
- `AcmeClient::new(directory_url, contact_email, account_key_path)`
- `issue_cert(domain, sans, challenge_dir, write_files)`
- `renew_all(threshold_days, certs)`

`instant-acme` is a Rust crate and works on macOS for tests against
staging directory. Unit tests use letsencrypt staging.
(Skip in CI without network; mark `#[ignore]`.)

- [ ] **Step 12: Templates**

`nginx-vhost.conf.j2`:
```
server {
    listen 80;
    listen [::]:80;
    server_name {{ domain }}{% for a in aliases %} {{ a }}{% endfor %};
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {{ domain }}{% for a in aliases %} {{ a }}{% endfor %};
    root {{ root_dir }};
    index index.php index.html;
    ssl_certificate     {{ cert_path }};
    ssl_certificate_key {{ key_path }};
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000" always;
    {% if has_php %}
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/{{ php_version }}/{{ system_user }}.sock;
    }
    {% endif %}
    location ~ /\.(?!well-known) { deny all; }
    location / { try_files $uri $uri/ {% if has_php %}/index.php?$args{% else %}=404{% endif %}; }
    access_log {{ logs_dir }}/access.log;
    error_log  {{ logs_dir }}/error.log;
}
```

`phpfpm-pool.conf.j2`:
```
[{{ system_user }}]
user = {{ system_user }}
group = {{ system_user }}
listen = /run/php/{{ php_version }}/{{ system_user }}.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = {{ max_children }}
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = {{ max_requests }}
php_admin_value[memory_limit] = {{ memory_mb }}M
php_admin_value[max_execution_time] = {{ max_exec_secs }}
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 64M
php_admin_value[open_basedir] = /home/{{ system_user }}/{{ domain }}:/tmp
catch_workers_output = yes
chdir = /
```

- [ ] **Step 13: Run + commit**

```bash
cargo test -p hyperion-adapters
git add crates/hyperion-adapters
git commit -m "feat(hyperion-adapters): fs, users, nginx, phpfpm, mariadb, postgres, acme adapters + rollback"
```

---

## Phase E — Orchestration

### Task 8: `hyperion-core` crate — `HostingService`

**Files:**
- Create: `crates/hyperion-core/Cargo.toml`
- Create: `crates/hyperion-core/src/lib.rs`
- Create: `crates/hyperion-core/src/service.rs`
- Create: `crates/hyperion-core/src/agent.rs`     (implements `AgentApi`)
- Create: `crates/hyperion-core/src/secrets.rs`

- [ ] **Step 1: Manifest + lib.rs**

`lib.rs` re-exports `HostingService` and `AgentImpl` (the `AgentApi`
impl wired to state + adapters).

- [ ] **Step 2: `secrets.rs` — write/read secret files mode 0600**

```rust
use hyperion_types::SecretId;
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use tokio::fs;
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("json: {0}")] Json(#[from] serde_json::Error),
}

pub struct SecretsStore { root: PathBuf }

impl SecretsStore {
    pub fn new(root: impl Into<PathBuf>) -> Self { Self { root: root.into() } }
    pub async fn put<T: Serialize>(&self, id: &SecretId, v: &T) -> Result<(), SecretsError> {
        fs::create_dir_all(&self.root).await?;
        let path = self.path(id);
        let bytes = serde_json::to_vec(v)?;
        let tmp = with_ext(&path, "tmp");
        fs::write(&tmp, bytes).await?;
        fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
        fs::rename(&tmp, &path).await?;
        Ok(())
    }
    pub async fn get<T: DeserializeOwned>(&self, id: &SecretId) -> Result<T, SecretsError> {
        let bytes = fs::read(self.path(id)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub async fn delete(&self, id: &SecretId) -> Result<(), SecretsError> {
        let p = self.path(id); if p.exists() { fs::remove_file(p).await?; } Ok(())
    }
    fn path(&self, id: &SecretId) -> PathBuf { self.root.join(format!("{}.json", id.0)) }
}

fn with_ext(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned(); s.push("."); s.push(ext); s.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test] async fn round_trip() {
        let d = tempfile::tempdir().unwrap();
        let store = SecretsStore::new(d.path());
        let id = SecretId::new();
        store.put(&id, &"hi".to_string()).await.unwrap();
        let back: String = store.get(&id).await.unwrap();
        assert_eq!(back, "hi");
        let m = std::fs::metadata(d.path().join(format!("{}.json", id.0)))
            .unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600);
    }
}
```

- [ ] **Step 3: `service.rs` — `HostingService` with trait-injected adapters**

Define a `AdapterPort` trait that abstracts the system adapters; in
production `AgentImpl` injects the real ones; in tests we mock via
`mockall`.

```rust
use hyperion_rpc::{RpcError, wire::*};
use hyperion_types::*;
use hyperion_validate::{Domain, SystemUserName};
use sqlx::SqlitePool;
use std::sync::Arc;

#[async_trait::async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AdapterPort: Send + Sync {
    async fn ensure_user(&self, name: &str, home: &str) -> Result<u32, hyperion_adapters::AdapterError>;
    async fn delete_user(&self, name: &str) -> Result<(), hyperion_adapters::AdapterError>;
    async fn ensure_dirs(&self, htdocs: &str, logs: &str, tmp: &str, owner: &str)
        -> Result<(), hyperion_adapters::AdapterError>;
    async fn rm_tree(&self, root: &str) -> Result<(), hyperion_adapters::AdapterError>;
    async fn fpm_ensure(&self, user: &str, ver: PhpVersion, domain: &str)
        -> Result<(), hyperion_adapters::AdapterError>;
    async fn fpm_delete(&self, user: &str, ver: PhpVersion) -> Result<(), hyperion_adapters::AdapterError>;
    async fn db_create(&self, eng: DbProvision, id: &HostingId)
        -> Result<DbCredentials, hyperion_adapters::AdapterError>;
    async fn db_drop(&self, eng: DbProvision, name: &str, user: &str)
        -> Result<(), hyperion_adapters::AdapterError>;
    async fn acme_issue(&self, domain: &str, sans: &[String])
        -> Result<CertInfo, hyperion_adapters::AdapterError>;
    async fn acme_delete(&self, domain: &str) -> Result<(), hyperion_adapters::AdapterError>;
    async fn nginx_write_vhost(&self, detail: &HostingDetail)
        -> Result<(), hyperion_adapters::AdapterError>;
    async fn nginx_delete_vhost(&self, domain: &str) -> Result<(), hyperion_adapters::AdapterError>;
}

pub struct HostingService<A: AdapterPort> {
    pub pool: SqlitePool,
    pub adapters: Arc<A>,
}

impl<A: AdapterPort + 'static> HostingService<A> {
    pub async fn create(&self, req: HostingCreateReq) -> Result<HostingCreated, RpcError> {
        // … implement steps from spec §11.1 with RollbackStack
        // 1. validate (hyperion-validate already does it on parse)
        // 2. derive system user
        // 3. adapters.ensure_user
        // 4. adapters.ensure_dirs
        // 5. hyperion-state hostings::insert(state=provisioning)
        // 6. fpm_ensure if php
        // 7. db_create if db
        // 8. acme_issue
        // 9. nginx_write_vhost
        // 10. UPDATE state=active
        // 11. return HostingCreated
        todo!("implement; on any err, run rollback stack LIFO, mark state=failed")
    }
    pub async fn list(&self) -> Result<Vec<HostingSummary>, RpcError> {
        hyperion_state::hostings::list(&self.pool).await
            .map_err(|_| RpcError::Internal)
    }
    pub async fn get(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError> {
        // resolve, JOIN aliases + databases + cert
        todo!()
    }
    pub async fn delete(&self, sel: HostingSelector, opts: DeleteOpts) -> Result<(), RpcError> {
        // implement per spec §11.4
        todo!()
    }
}
```

(Implementation bodies filled during execution — they're straight
sequencing per the spec; tests below cover them.)

- [ ] **Step 4: Tests for `HostingService` using `MockAdapterPort`**

```rust
#[cfg(test)] mod tests {
    use super::*;
    use mockall::predicate::*;
    use hyperion_state::db::open_memory;

    fn req(d: &str) -> HostingCreateReq {
        HostingCreateReq {
            domain: Domain::parse(d).unwrap(), aliases: vec![],
            php_version: Some(PhpVersion::V8_3),
            database: Some(DbProvision::MariaDB), system_user: None,
        }
    }

    #[tokio::test]
    async fn create_happy_path() {
        let pool = open_memory().await.unwrap();
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_,_| Ok(1042));
        a.expect_ensure_dirs().returning(|_,_,_,_| Ok(()));
        a.expect_fpm_ensure().returning(|_,_,_| Ok(()));
        a.expect_db_create().returning(|_,_| Ok(DbCredentials {
            engine: DbProvision::MariaDB,
            db_name: "x".into(), db_user: "y".into(), password: "p".into(),
        }));
        a.expect_acme_issue().returning(|d,_| Ok(CertInfo {
            domain: d.into(), sans: vec![], issuer: "le".into(),
            not_after: 0, fingerprint_sha256: "abc".into() }));
        a.expect_nginx_write_vhost().returning(|_| Ok(()));
        let svc = HostingService { pool, adapters: Arc::new(a) };
        let r = svc.create(req("example.cz")).await.unwrap();
        assert!(r.db.is_some());
    }
    #[tokio::test]
    async fn create_rolls_back_on_nginx_fail() {
        let pool = open_memory().await.unwrap();
        let mut a = MockAdapterPort::new();
        a.expect_ensure_user().returning(|_,_| Ok(1043));
        a.expect_ensure_dirs().returning(|_,_,_,_| Ok(()));
        a.expect_fpm_ensure().returning(|_,_,_| Ok(()));
        a.expect_db_create().returning(|_,_| Ok(DbCredentials {
            engine: DbProvision::MariaDB,
            db_name: "x".into(), db_user: "y".into(), password: "p".into(),
        }));
        a.expect_acme_issue().returning(|d,_| Ok(CertInfo {
            domain: d.into(), sans: vec![], issuer: "le".into(),
            not_after: 0, fingerprint_sha256: "abc".into() }));
        a.expect_nginx_write_vhost().returning(|_| Err(hyperion_adapters::AdapterError::Other("boom".into())));
        // Expect rollbacks invoked:
        a.expect_acme_delete().returning(|_| Ok(()));
        a.expect_db_drop().returning(|_,_,_| Ok(()));
        a.expect_fpm_delete().returning(|_,_| Ok(()));
        a.expect_rm_tree().returning(|_| Ok(()));
        a.expect_delete_user().returning(|_| Ok(()));
        let svc = HostingService { pool: pool.clone(), adapters: Arc::new(a) };
        let r = svc.create(req("example.cz")).await;
        assert!(r.is_err());
        // hostings row state should be 'failed' or row absent
        let rows: Vec<(String,String)> = sqlx::query_as("SELECT id,state FROM hostings")
            .fetch_all(&pool).await.unwrap();
        // Acceptable: row marked failed; if implementation deletes pre-insert, vec is empty
        for (_, s) in &rows { assert!(s == "failed" || s == "deleting"); }
    }
}
```

- [ ] **Step 5: `agent.rs` — production `AgentImpl: AgentApi` glue**

Implements the `AgentApi` trait by delegating to `HostingService` and
binding the real `AdapterPort` from `hyperion-adapters`.

- [ ] **Step 6: Run + commit**

```bash
cargo test -p hyperion-core
git add crates/hyperion-core
git commit -m "feat(hyperion-core): orchestration with mockable AdapterPort + secrets store"
```

---

## Phase F — Binaries

### Task 9: `bin/hyperion-agent` — daemon

**Files:**
- Create: `bin/hyperion-agent/Cargo.toml`
- Create: `bin/hyperion-agent/src/main.rs`
- Create: `bin/hyperion-agent/src/config.rs`

- [ ] **Step 1: Manifest depends on `hyperion-core`, `hyperion-rpc-server`,
       `hyperion-state`, `tokio`, `tracing-subscriber`, `clap`, `toml`,
       `serde`, `anyhow`, `tracing`.**

- [ ] **Step 2: `config.rs`** — load `agent.toml`, validate paths.

- [ ] **Step 3: `main.rs`** —
```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    let cfg = config::load_default()?;
    let pool = hyperion_state::db::open(&cfg.state_db).await?;
    let adapters = std::sync::Arc::new(hyperion_adapters_facade::Real::new(/* cfg */));
    let svc = std::sync::Arc::new(hyperion_core::HostingService { pool, adapters });
    let agent = std::sync::Arc::new(hyperion_core::AgentImpl::new(svc));
    let srv = hyperion_rpc_server::Server::bind(&cfg.socket_path, agent).await?;
    tracing::info!(socket=%cfg.socket_path.display(), "hyperion-agent ready");
    srv.run().await?;
    Ok(())
}
```

- [ ] **Step 4: Run `cargo build -p hyperion-agent` and `cargo run --bin hyperion-agent -- --help`** (we'll add a `--help` flag via clap).

- [ ] **Step 5: Commit**

```bash
git add bin/hyperion-agent
git commit -m "feat(hyperion-agent): daemon binary"
```

---

### Task 10: `bin/lm` — CLI

**Files:**
- Create: `bin/lm/Cargo.toml`
- Create: `bin/lm/src/main.rs`
- Create: `bin/lm/src/cmd_hosting.rs`
- Create: `bin/lm/src/cmd_cert.rs`

- [ ] **Step 1: Manifest** — depends on `hyperion-rpc`, `hyperion-rpc-client`,
       `hyperion-types`, `hyperion-validate`, `clap`, `tokio`, `anyhow`, `serde_json`.

- [ ] **Step 2: clap subcommand tree**

```rust
#[derive(clap::Parser)]
#[command(name = "lm", version)]
struct Cli {
    #[arg(long, default_value = "/run/hyperion.sock")]
    socket: std::path::PathBuf,
    #[command(subcommand)] cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    AgentInfo,
    #[command(subcommand)] Hosting(HostingCmd),
    #[command(subcommand)] Cert(CertCmd),
}

#[derive(clap::Subcommand)]
enum HostingCmd {
    Create {
        domain: String,
        #[arg(long)] alias: Vec<String>,
        #[arg(long)] php: Option<String>,
        #[arg(long)] db: Option<String>,
        #[arg(long)] user: Option<String>,
    },
    List,
    Get { sel: String },
    Delete { sel: String, #[arg(long)] keep_user: bool, #[arg(long)] keep_db: bool },
}

#[derive(clap::Subcommand)]
enum CertCmd { RenewAll, Issue { domain: String } }
```

- [ ] **Step 3: Map clap args → `Request` → `call(...)` → render `Response` as pretty text or JSON (`--json` flag).**

- [ ] **Step 4: Commit**

```bash
git add bin/lm
git commit -m "feat(lm): CLI with hosting + cert subcommands"
```

---

## Phase G — Cross-cutting & verification

### Task 11: Workspace-level checks

- [ ] **Step 1:** `cargo fmt --all -- --check`
- [ ] **Step 2:** `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] **Step 3:** `cargo test --workspace`
- [ ] **Step 4:** Commit any fixes.

### Task 12: README + RUNBOOK

- [ ] **Step 1:** `README.md` with build instructions, `lm hosting create --help` example.
- [ ] **Step 2:** `docs/RUNBOOK.md` with prod deploy notes (deferred details OK).
- [ ] **Step 3:** Commit.

---

## Self-Review Note

Plan covers Foundation spec sections 5–17 by mapping each to a task:
- §5 architecture → Tasks 9, 10
- §6 workspace layout → Task 1 + each crate's Task
- §7 RPC trait + wire + error → Task 4
- §8 SQLite schema → Task 5
- §9 filesystem layout → Tasks 7, 9
- §10 adapters → Task 7
- §11 flows → Task 8 (`HostingService`)
- §12 error handling → Tasks 4, 7, 8
- §13 security model → Tasks 6 (socket perms), 7 (no shell), 8 (secrets)
- §14 config → Task 9
- §15 logging/audit → Tasks 5, 9
- §16 testing → all tasks
- §17 packaging → deferred (post-implementation)

Types named consistently with spec: `HostingId`, `Domain`,
`SystemUserName`, `PhpVersion`, `DbProvision`, `CertInfo`,
`HostingDetail`, `HostingSummary`, `HostingState`, `HostingCreateReq`,
`HostingCreated`, `DbCredentials`, `HostingSelector`, `DeleteOpts`,
`AgentInfo`, `CertRenewResult`, `CertRenewOutcome`, `RpcError`,
`AgentApi`, `AgentImpl`, `HostingService`, `AdapterPort`,
`RollbackStack`, `Rollback`, `AdapterError`, `StateError`,
`SecretsStore`, `SecretId`.

---

*End of plan.*
