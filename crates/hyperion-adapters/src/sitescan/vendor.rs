//! Premium plugins and themes, checked against the package WordPress already
//! knows the download link of.
//!
//! A licensed plugin's updater leaves its package URL in the `update_plugins` and
//! `update_themes` site transients. Those rows are the tenant's to write, and the
//! URL often carries a licence key, so everything here reads attacker text and
//! holds a secret: the URL is a [`Secret`], goes to curl on stdin and never into a
//! message, a log or a file, and it is only ever fetched from a compiled-in host
//! list with every hop re-checked and pinned. A manifest is keyed by slug and
//! version, so one site with a working licence verifies every site on that
//! version. The first one for a key stays, with a record of where it came from, and
//! another site's different package disputes it rather than replacing it.
//!
//! None of the hosts below is confirmed against a real licence yet.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

use hyperion_types::VendorPackageInfo;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;
use url::Url;

use super::discover::Discovery;
use super::manifest::{
    cache_path_for, manifest_from_zip, package_identity, valid_slug, valid_version,
    vendor_disputed_path, vendor_provenance_path, ComponentKey, ComponentKind, Manifest,
    ManifestSource,
};
use super::walk::TenantRoot;
use crate::cmd::curl_config_quote;
use crate::mariadb::valid_table_prefix;

/// Hosts a package URL may start on: exact names. No wildcards, here or below:
/// anyone can rent a name under a CDN, and an open redirect on a listed host would
/// then make their ZIP the reference for every site on that version.
const VENDOR_HOSTS: [&str; 6] = [
    "my.elementor.com",
    "connect.advancedcustomfields.com",
    "wp-rocket.me",
    "my.yoast.com",
    "wpml.org",
    "wpforms.com",
];
/// Hosts only a vendor's redirect may lead to, by exact name, as real data names
/// them: a redirect anywhere else is recorded in `unknown_vendor_hosts`.
const REDIRECT_HOSTS: [&str; 0] = [];

pub(crate) const MAX_PACKAGE_BYTES: u64 = 200 * 1024 * 1024;
/// One package, every hop included.
const TIME_CAP: Duration = Duration::from_secs(300);
/// Requests one package may take.
const MAX_HOPS: usize = 5;
const CONNECT_SECS: u32 = 15;
/// Under this many bytes a second for [`SLOW_SECS`], a download is given up on.
const SLOW_BYTES_PER_SEC: u32 = 10 * 1024;
const SLOW_SECS: u32 = 60;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);
const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

pub(crate) const CURL: &str = "/usr/bin/curl";

/// How much of `wp-config.php` is read.
pub(crate) const WP_CONFIG_MAX_BYTES: u64 = 256 * 1024;

/// A failed slug and version waits this long, so a vendor never sees a licence
/// asking again and again.
const FAILED_BACKOFF: Duration = Duration::from_secs(24 * 3600);
/// A download in `vendor/tmp` this old was cut off by a restart.
const TMP_MAX_AGE: Duration = Duration::from_secs(3600);

/// Hostnames one site can put in its coverage.
pub const MAX_UNKNOWN_HOSTS: usize = 20;

// Bounds on a value of up to 8 MiB of attacker text. A real transient has a few
// thousand values and nests six deep.
const MAX_PHP_DEPTH: usize = 8;
const MAX_PHP_VALUES: usize = 200_000;
pub(crate) const MAX_REFS: usize = 2000;
const MAX_URL_BYTES: usize = 8192;
/// curl's report: a status and a location.
pub(crate) const MAX_REPORT_BYTES: usize = MAX_URL_BYTES + 64;
/// Hostings a provenance record names.
const MAX_PROVENANCE_HOSTINGS: usize = 20;

const VENDOR_DIR: &str = "vendor";
const TMP_DIR: &str = "tmp";
const FAILED_DIR: &str = "failed";

/// A value that must not be seen: a package URL, which often holds a licence key.
/// It has no way to be printed, and is read with [`Secret::expose`] only where it
/// goes to curl or gets parsed.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Which list of the transient an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageBucket {
    /// An update is on offer: the package is the next version.
    Response,
    /// Up to date: the package can be the version installed today.
    NoUpdate,
}

/// One package a transient names. Nothing here has been checked but its shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub kind: ComponentKind,
    /// The folder: the transient's key, not the slug field beside it.
    pub slug: String,
    /// `new_version`.
    pub version: Option<String>,
    pub url: Secret,
    pub bucket: PackageBucket,
}

/// A package worth asking for: wanted by this site, not cached, not backing off,
/// on a listed host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPackage {
    pub kind: ComponentKind,
    pub slug: String,
    /// What its header must say.
    pub version: String,
    pub url: Secret,
    pub bucket: PackageBucket,
    /// A `no_update` entry for the version the site runs. Anything else only
    /// prepares a version this site isn't on.
    pub verifies_today: bool,
}

/// What went wrong with a package. No variant can hold a URL: curl's stderr can
/// include one, so it never reaches a message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VendorError {
    /// Holds a validated hostname and nothing else.
    #[error("host {0} is not on the vendor list")]
    UnknownHost(String),
    #[error("the package URL is not https")]
    NotHttps,
    #[error("the package URL is refused")]
    BadUrl,
    #[error("the package URL leads to a private address")]
    PrivateAddress,
    #[error("the package's host did not resolve")]
    NoAddress,
    #[error("the package redirects too many times")]
    TooManyRedirects,
    #[error("the vendor answered HTTP {0}")]
    HttpStatus(u16),
    #[error("the package is over the size cap")]
    TooLarge,
    #[error("the download took too long")]
    TimedOut,
    #[error("the download failed")]
    Transport,
    #[error("the download is not a package for this component")]
    BadPackage,
    #[error("the package's version isn't the one the site was told about")]
    VersionMismatch,
    #[error("the package could not be handled on this machine")]
    Local,
}

// ---- hosts and addresses ----

fn on_list(list: &[&str], host: &str) -> bool {
    valid_hostname(host) && list.contains(&host)
}

/// May a package URL start on this host?
pub fn vendor_host_allowed(host: &str) -> bool {
    on_list(&VENDOR_HOSTS, host)
}

/// May a redirect lead to this host?
pub fn redirect_host_allowed(host: &str) -> bool {
    vendor_host_allowed(host) || on_list(&REDIRECT_HOSTS, host)
}

// The patterns are constants and the tests below use every one of them, so a
// compile failure is caught by the suite, never in production.
#[allow(clippy::expect_used)]
static HOSTNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")
        .expect("hostname regex")
});

/// A plain lowercase DNS name, the only thing a stored host can be. Its last label
/// starts with a letter, so an address isn't one.
fn valid_hostname(host: &str) -> bool {
    host.len() <= 253 && HOSTNAME_RE.is_match(host)
}

/// May a request reach this address? Only one on the public internet. The
/// transition forms that embed an IPv4 address answer for what they embed.
pub(crate) fn address_allowed(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_allowed(v4),
        IpAddr::V6(v6) => v6_allowed(v6),
    }
}

fn v4_allowed(ip: &Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    let refused = ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local() // 169.254.0.0/16, cloud metadata included
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || a >= 240 // reserved
        || (a == 100 && (64..=127).contains(&b)) // carrier-grade NAT, Alibaba's metadata
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (18..=19).contains(&b)) // benchmarking
        || (a, b, c, d) == (168, 63, 129, 16); // Azure's metadata and DNS
    !refused
}

fn v6_allowed(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    let embedded = |hi: u16, lo: u16| {
        let [a, b] = hi.to_be_bytes();
        let [c, d] = lo.to_be_bytes();
        v4_allowed(&Ipv4Addr::new(a, b, c, d))
    };
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_allowed(&v4);
    }
    let refused = ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00 // unique local, AWS's metadata included
        || (seg[0] & 0xffc0) == 0xfe80 // link-local
        || (seg[0] & 0xffc0) == 0xfec0 // site-local, deprecated and never public
        || seg[..3] == [0x64, 0xff9b, 1] // local-use NAT64
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // documentation
        || (seg[0] == 0x2001 && seg[1] == 0) // Teredo: hides an address
        || (seg[0] == 0x0100 && seg[1..4] == [0, 0, 0]) // discard
        // IPv4-compatible, deprecated and never public.
        || seg[..6] == [0, 0, 0, 0, 0, 0]
        // NAT64 and 6to4 reach what they embed.
        || (seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] && !embedded(seg[6], seg[7]))
        || (seg[0] == 0x2002 && !embedded(seg[1], seg[2]));
    !refused
}

/// What may be asked of one URL: https on port 443 with no userinfo, on a listed
/// host. `first` is the URL from the database; a redirect may also lead to a CDN.
/// Returns the URL as the parser reads it, which is what curl is then given, so
/// the host checked is the host curl connects to.
fn check_target(raw: &str, first: bool) -> Result<(Url, String), VendorError> {
    let mut url = Url::parse(raw).map_err(|_| VendorError::BadUrl)?;
    if url.scheme() != "https" {
        return Err(VendorError::NotHttps);
    }
    // The parser drops a port that is the scheme's own, so only others are left.
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return Err(VendorError::BadUrl);
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(ip)) => return Err(literal_refusal(IpAddr::V4(ip))),
        Some(url::Host::Ipv6(ip)) => return Err(literal_refusal(IpAddr::V6(ip))),
        None => return Err(VendorError::BadUrl),
    };
    if !valid_hostname(&host) {
        return Err(VendorError::BadUrl);
    }
    let allowed = if first {
        vendor_host_allowed(&host)
    } else {
        redirect_host_allowed(&host)
    };
    if !allowed {
        return Err(VendorError::UnknownHost(host));
    }
    url.set_fragment(None);
    Ok((url, host))
}

fn literal_refusal(ip: IpAddr) -> VendorError {
    if address_allowed(&ip) {
        // No list holds an address.
        VendorError::BadUrl
    } else {
        VendorError::PrivateAddress
    }
}

// ---- reading what the tenant wrote ----

#[allow(clippy::expect_used)]
static DB_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^[^/#*\n]*?\bdefine\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"\n]{1,64})['"]\s*\)"#,
    )
    .expect("db name regex")
});
#[allow(clippy::expect_used)]
static TABLE_PREFIX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[^/#*\n]*?\$table_prefix\s*=\s*['"]([^'"\n]*)['"]\s*;"#)
        .expect("prefix regex")
});

/// `DB_NAME` and `$table_prefix`, by pattern alone: this is attacker text, and what
/// it names means nothing until the caller finds the database among the hosting's
/// own. A commented-out line doesn't count, and a value worked out in PHP isn't one.
pub fn parse_wp_config_db(text: &str) -> Option<(String, String)> {
    let db = DB_NAME_RE.captures(text)?.get(1)?.as_str();
    let prefix = TABLE_PREFIX_RE.captures(text)?.get(1)?.as_str();
    valid_table_prefix(prefix).then(|| (db.to_string(), prefix.to_string()))
}

/// [`parse_wp_config_db`] over the docroot's `wp-config.php`, reached through
/// [`TenantRoot`]: root, in a tree the tenant controls. A config above the docroot
/// isn't reached, and that site simply has no vendor step.
pub fn read_wp_config_db(root: &Path) -> Option<(String, String)> {
    let file = TenantRoot::open(root)
        .ok()?
        .open_file("wp-config.php")
        .ok()?;
    let mut bytes = Vec::new();
    file.take(WP_CONFIG_MAX_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    parse_wp_config_db(&String::from_utf8_lossy(&bytes))
}

/// One value of a PHP-serialized text, as far as this needs to know.
enum Php<'a> {
    Str(&'a [u8]),
    /// An array or an object's properties, in order.
    Map(Vec<(Php<'a>, Php<'a>)>),
    Scalar,
}

impl<'a> Php<'a> {
    fn get(&self, key: &str) -> Option<&Php<'a>> {
        let Php::Map(pairs) = self else {
            return None;
        };
        pairs
            .iter()
            .find(|(k, _)| matches!(k, Php::Str(s) if *s == key.as_bytes()))
            .map(|(_, v)| v)
    }

    fn text(&self) -> Option<&'a str> {
        match self {
            Php::Str(s) => std::str::from_utf8(s).ok(),
            _ => None,
        }
    }
}

/// A tokenizer for `serialize()`'s output, never `unserialize()`: no class is
/// looked at, a string ends where its length says, and depth and value count are
/// bounded before anything is allocated for them. `None` for anything else.
struct PhpReader<'a> {
    bytes: &'a [u8],
    at: usize,
    values_left: usize,
}

impl<'a> PhpReader<'a> {
    fn eat(&mut self, expected: &[u8]) -> Option<()> {
        let end = self.at.checked_add(expected.len())?;
        (self.bytes.get(self.at..end)? == expected).then(|| self.at = end)
    }

    /// Digits up to `end`. A length never needs more than ten.
    fn number(&mut self, end: u8) -> Option<usize> {
        let digits = self
            .bytes
            .get(self.at..)?
            .iter()
            .take(11)
            .position(|b| *b == end)?;
        let text = std::str::from_utf8(self.bytes.get(self.at..self.at + digits)?).ok()?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        self.at += digits + 1;
        text.parse().ok()
    }

    /// `N:"...` up to the closing quote, the part strings and class names share.
    fn counted(&mut self) -> Option<&'a [u8]> {
        let len = self.number(b':')?;
        self.eat(b"\"")?;
        let end = self.at.checked_add(len)?;
        let s = self.bytes.get(self.at..end)?;
        self.at = end;
        self.eat(b"\"")?;
        Some(s)
    }

    fn value(&mut self, depth: usize) -> Option<Php<'a>> {
        self.values_left = self.values_left.checked_sub(1)?;
        match *self.bytes.get(self.at)? {
            b'N' => {
                self.eat(b"N;")?;
                Some(Php::Scalar)
            }
            // Numbers, booleans and references: their values don't matter here.
            b'i' | b'b' | b'd' | b'r' | b'R' => {
                self.at += 1;
                self.eat(b":")?;
                let rest = self.bytes.get(self.at..)?;
                let len = rest.iter().take(64).position(|b| *b == b';')?;
                self.at += len + 1;
                Some(Php::Scalar)
            }
            b's' => {
                self.eat(b"s:")?;
                let s = self.counted()?;
                self.eat(b";")?;
                Some(Php::Str(s))
            }
            b'a' => {
                self.eat(b"a:")?;
                self.pairs(depth)
            }
            b'O' => {
                self.eat(b"O:")?;
                self.counted()?;
                self.eat(b":")?;
                self.pairs(depth)
            }
            // `C:` is a class's own format, and nothing else is PHP's.
            _ => None,
        }
    }

    fn pairs(&mut self, depth: usize) -> Option<Php<'a>> {
        if depth >= MAX_PHP_DEPTH {
            return None;
        }
        let count = self.number(b':')?;
        self.eat(b"{")?;
        // The count is the tenant's: the budget ends a lie before memory does.
        let mut pairs = Vec::new();
        for _ in 0..count {
            let key = self.value(depth + 1)?;
            let value = self.value(depth + 1)?;
            pairs.push((key, value));
        }
        self.eat(b"}")?;
        Some(Php::Map(pairs))
    }
}

fn parse_php(text: &str) -> Option<Php<'_>> {
    let mut r = PhpReader {
        bytes: text.as_bytes(),
        at: 0,
        values_left: MAX_PHP_VALUES,
    };
    let value = r.value(0)?;
    (r.at == text.len()).then_some(value)
}

/// The packages an `update_plugins` or `update_themes` site transient names, by
/// the folder each is keyed under. Anything malformed anywhere yields nothing: the
/// components stay on the baseline. Never panics.
pub fn parse_update_transient(value: &str, kind: ComponentKind) -> Vec<PackageRef> {
    if kind == ComponentKind::Core {
        return Vec::new();
    }
    let Some(top) = parse_php(value) else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    for (field, bucket) in [
        ("response", PackageBucket::Response),
        ("no_update", PackageBucket::NoUpdate),
    ] {
        let Some(Php::Map(entries)) = top.get(field) else {
            continue;
        };
        for (name, entry) in entries {
            if refs.len() >= MAX_REFS {
                return refs;
            }
            if let Some(r) = package_ref(name, entry, kind, bucket) {
                refs.push(r);
            }
        }
    }
    refs
}

fn package_ref(
    name: &Php<'_>,
    entry: &Php<'_>,
    kind: ComponentKind,
    bucket: PackageBucket,
) -> Option<PackageRef> {
    let name = name.text()?;
    // A plugin is keyed `folder/main.php`, a theme by its folder. A single-file
    // plugin has no folder, and a package always has.
    let slug = match kind {
        ComponentKind::Plugin => {
            let (folder, file) = name.split_once('/')?;
            if file.contains('/') {
                return None;
            }
            folder
        }
        _ => name,
    };
    if !valid_slug(slug) {
        return None;
    }
    let url = entry.get("package")?.text()?;
    if url.is_empty() || url.len() > MAX_URL_BYTES {
        return None;
    }
    let version = match entry.get("new_version").and_then(Php::text) {
        Some(v) if !valid_version(v) => return None,
        v => v.map(str::to_string),
    };
    Some(PackageRef {
        kind,
        slug: slug.to_string(),
        version,
        url: Secret::new(url.to_string()),
        bucket,
    })
}

// ---- what is worth asking for ----

/// What a package could verify: a plugin or theme in a folder, with a version,
/// that wordpress.org doesn't know. A slug it does know has its checksums to
/// answer to, and those are never replaced by a URL from the tenant's database.
pub fn vendor_candidates(
    discovery: &Discovery,
    wporg_known: &BTreeSet<String>,
) -> Vec<ComponentKey> {
    if !discovery.is_wordpress {
        return Vec::new();
    }
    discovery
        .components
        .iter()
        .filter(|c| {
            c.key.kind != ComponentKind::Core
                && !c.is_child_theme
                && !c.single_file
                && valid_slug(&c.key.slug)
                && valid_version(&c.key.version)
                && !wporg_known.contains(&c.key.slug)
        })
        .map(|c| c.key.clone())
        .collect()
}

/// What to fetch for one site, and the hosts it named that nobody has listed.
#[derive(Debug, Default)]
pub struct VendorPlan {
    /// What verifies the site today comes first, then what only prepares.
    pub fetch: Vec<PlannedPackage>,
    pub unknown_hosts: Vec<String>,
}

/// Match a site's transients with its candidates, for at most the version it runs
/// and one on offer per slug: a transient can hold any number of entries and one
/// folder can have many main files. A `no_update` entry that names no version is
/// taken to be what the site runs, and one that names another is neither; a
/// `response` entry has to say, or nothing could tell the next scan it was fetched.
///
/// A version already cached isn't fetched, unless `differing` says this site has a
/// difference from that manifest and this site hasn't had its say: its own package
/// then settles whether the reference or the site is wrong.
pub fn plan_downloads(
    refs: Vec<PackageRef>,
    candidates: &[ComponentKey],
    differing: &BTreeSet<String>,
    hosting_id: &str,
    cache_dir: &Path,
    now: SystemTime,
) -> VendorPlan {
    let running: BTreeMap<(ComponentKind, &str), &str> = candidates
        .iter()
        .map(|k| ((k.kind, k.slug.as_str()), k.version.as_str()))
        .collect();
    let mut plan = VendorPlan::default();
    let mut unknown = BTreeSet::new();
    for r in refs {
        let Some(site_runs) = running.get(&(r.kind, r.slug.as_str())).copied() else {
            continue;
        };
        let version = match (r.version, r.bucket) {
            (Some(v), PackageBucket::NoUpdate) if v != site_runs => continue,
            (Some(v), _) => v,
            (None, PackageBucket::NoUpdate) => site_runs.to_string(),
            (None, PackageBucket::Response) => continue,
        };
        let key = vendor_key(r.kind, &r.slug, &version);
        // A key that can't be a file name can't be cached, so it isn't asked for.
        let Ok(path) = cache_path_for(cache_dir, &key, ManifestSource::VendorPackage) else {
            continue;
        };
        if read_vendor_manifest(&path).is_some() {
            let compare = version == site_runs
                && differing.contains(&r.slug)
                && !vendor_disputed_path(&path).exists()
                && !read_provenance(&path)
                    .is_some_and(|p| p.hostings.iter().any(|h| h == hosting_id));
            if !compare {
                continue;
            }
        }
        if backing_off(cache_dir, hosting_id, &r.slug, &version, now) {
            continue;
        }
        match check_target(r.url.expose(), true) {
            Ok(_) => plan.fetch.push(PlannedPackage {
                kind: r.kind,
                verifies_today: r.bucket == PackageBucket::NoUpdate,
                slug: r.slug,
                version,
                url: r.url,
                bucket: r.bucket,
            }),
            Err(VendorError::UnknownHost(host)) => {
                if unknown.len() < MAX_UNKNOWN_HOSTS {
                    unknown.insert(host);
                }
            }
            // Not https, not a URL, an address: nothing to ask, nothing to name.
            Err(_) => {}
        }
    }
    plan.fetch.sort_by(|a, b| plan_rank(a).cmp(&plan_rank(b)));
    // After the sort, so a key on offer twice keeps its better reason.
    let mut seen = BTreeSet::new();
    let mut prepared = BTreeSet::new();
    plan.fetch.retain(|p| {
        let runs = running.get(&(p.kind, p.slug.as_str())) == Some(&p.version.as_str());
        seen.insert((p.kind, p.slug.clone(), p.version.clone()))
            && (runs || prepared.insert((p.kind, p.slug.clone())))
    });
    plan.unknown_hosts = unknown.into_iter().collect();
    plan
}

fn plan_rank(p: &PlannedPackage) -> (bool, bool, &str, &str) {
    (
        !p.verifies_today,
        p.bucket != PackageBucket::NoUpdate,
        &p.slug,
        &p.version,
    )
}

fn vendor_key(kind: ComponentKind, slug: &str, version: &str) -> ComponentKey {
    ComponentKey {
        kind,
        slug: slug.to_string(),
        version: version.to_string(),
        locale: None,
    }
}

// ---- backing off ----

/// One hosting's own wait, so a tenant planting a bad link backs off nobody else.
/// The marker's name says neither what failed nor whose.
fn failed_marker(cache_dir: &Path, hosting_id: &str, slug: &str, version: &str) -> PathBuf {
    let mut h = Sha256::new();
    h.update(slug.as_bytes());
    h.update([0]);
    h.update(version.as_bytes());
    h.update([0]);
    h.update(hosting_id.as_bytes());
    cache_dir
        .join(VENDOR_DIR)
        .join(FAILED_DIR)
        .join(hex::encode(h.finalize()))
}

fn younger_than(path: &Path, limit: Duration, now: SystemTime) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|at| now.duration_since(at).ok())
        .is_some_and(|age| age < limit)
}

fn backing_off(
    cache_dir: &Path,
    hosting_id: &str,
    slug: &str,
    version: &str,
    now: SystemTime,
) -> bool {
    younger_than(
        &failed_marker(cache_dir, hosting_id, slug, version),
        FAILED_BACKOFF,
        now,
    )
}

fn root_only_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

fn mark_failed(cache_dir: &Path, hosting_id: &str, slug: &str, version: &str, now: SystemTime) {
    let marker = failed_marker(cache_dir, hosting_id, slug, version);
    let written = marker
        .parent()
        .map_or(Ok(()), root_only_dir)
        .and_then(|()| fs::File::create(&marker))
        .and_then(|f| f.set_modified(now));
    if let Err(e) = written {
        tracing::warn!(error = %e, "site scan: vendor backoff marker not written");
    }
}

/// Drop downloads a restart cut off, and markers past their wait. What's cached has
/// its own sweep, by whether any site still runs it.
pub fn sweep_leftovers(cache_dir: &Path, now: SystemTime) {
    let vendor = cache_dir.join(VENDOR_DIR);
    for (dir, limit) in [(TMP_DIR, TMP_MAX_AGE), (FAILED_DIR, FAILED_BACKOFF)] {
        let Ok(entries) = fs::read_dir(vendor.join(dir)) else {
            continue;
        };
        for e in entries.flatten() {
            if !younger_than(&e.path(), limit, now) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

// ---- fetching ----

/// One request: where to, and the only addresses curl may use for it.
pub(crate) struct Hop<'a> {
    pub(crate) url: &'a Secret,
    pub(crate) host: &'a str,
    pub(crate) addrs: &'a [IpAddr],
    pub(crate) max_secs: u64,
}

#[derive(Debug)]
pub(crate) struct HopAnswer {
    pub(crate) status: u16,
    /// Where a redirect leads. Can carry a key just as the first URL can.
    pub(crate) location: Option<Secret>,
}

/// The DNS and HTTP a download needs, so its rules can be tested with no network.
#[async_trait::async_trait]
pub(crate) trait HopFetch: Sync {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, VendorError>;
    /// One GET with no redirect followed, the body in `dest` (replacing any).
    async fn get(&self, hop: &Hop<'_>, dest: &Path) -> Result<HopAnswer, VendorError>;
}

/// argv holds options only: `/proc/<pid>/cmdline` is world-readable, and tenants
/// are local users here. `-q` keeps root's `.curlrc` out of it.
pub(crate) fn curl_command() -> Command {
    let mut cmd = Command::new(CURL);
    cmd.args(["-q", "--config", "-"]).kill_on_drop(true);
    cmd
}

/// The config curl reads on stdin. The URL is the one [`check_target`] returned,
/// and the addresses are the only ones curl may connect to: it can't resolve the
/// name again and get another answer. No `location`: each hop is checked here.
pub(crate) fn hop_config(hop: &Hop<'_>) -> String {
    let addrs: Vec<String> = hop
        .addrs
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        })
        .collect();
    let mut cfg = String::new();
    cfg.push_str(&format!(
        "url = \"{}\"\n",
        curl_config_quote(hop.url.expose())
    ));
    cfg.push_str(&format!(
        "resolve = \"{}\"\n",
        curl_config_quote(&format!("{}:443:{}", hop.host, addrs.join(",")))
    ));
    cfg.push_str("silent\n");
    cfg.push_str("globoff\n");
    cfg.push_str("max-redirs = 0\n");
    cfg.push_str("proto = \"=https\"\n");
    cfg.push_str("proto-redir = \"=https\"\n");
    // An environment's proxy would make the pin mean nothing.
    cfg.push_str("noproxy = \"*\"\n");
    cfg.push_str(&format!("max-filesize = {MAX_PACKAGE_BYTES}\n"));
    cfg.push_str(&format!("max-time = {}\n", hop.max_secs));
    cfg.push_str(&format!("connect-timeout = {CONNECT_SECS}\n"));
    cfg.push_str(&format!("speed-limit = {SLOW_BYTES_PER_SEC}\n"));
    cfg.push_str(&format!("speed-time = {SLOW_SECS}\n"));
    cfg.push_str("user-agent = \"hyperion-sitescan\"\n");
    // The body takes stdout, so the report goes to stderr. Nothing else does:
    // `silent` without `show-error`.
    cfg.push_str("write-out = \"%{stderr}%{http_code} %{redirect_url}\"\n");
    cfg
}

pub(crate) struct CurlFetch;

#[async_trait::async_trait]
impl HopFetch for CurlFetch {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, VendorError> {
        let found = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, 443)))
            .await
            .map_err(|_| VendorError::NoAddress)?
            .map_err(|_| VendorError::NoAddress)?;
        Ok(found.map(|a| a.ip()).collect())
    }

    async fn get(&self, hop: &Hop<'_>, dest: &Path) -> Result<HopAnswer, VendorError> {
        let run = run_curl(hop, dest);
        // curl has its own `max-time`. This is for a curl that doesn't stop.
        match tokio::time::timeout(Duration::from_secs(hop.max_secs + 5), run).await {
            Ok(answer) => answer,
            Err(_) => Err(VendorError::TimedOut),
        }
    }
}

/// Run one request, keeping the body in `dest` up to the cap whatever curl does:
/// before curl 8.4 `max-filesize` does nothing for a body of unknown length, which
/// is the whole disk to a hostile server. The body comes through here for that.
async fn run_curl(hop: &Hop<'_>, dest: &Path) -> Result<HopAnswer, VendorError> {
    let mut child = curl_command()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| VendorError::Local)?;
    let mut stdin = child.stdin.take().ok_or(VendorError::Local)?;
    let stdout = child.stdout.take().ok_or(VendorError::Local)?;
    let mut stderr = child.stderr.take().ok_or(VendorError::Local)?;
    stdin
        .write_all(hop_config(hop).as_bytes())
        .await
        .map_err(|_| VendorError::Transport)?;
    stdin.shutdown().await.map_err(|_| VendorError::Transport)?;
    drop(stdin);

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|_| VendorError::Local)?;
    let mut limited = stdout.take(MAX_PACKAGE_BYTES + 1);
    let kill = &mut child;
    let body = async {
        let copied = tokio::io::copy(&mut limited, &mut file).await;
        // A curl with its pipe no longer read would sit there until the timeout.
        if copied.as_ref().map_or(true, |n| *n > MAX_PACKAGE_BYTES) {
            let _ = kill.start_kill();
        }
        copied
    };
    let report = async {
        let mut report = Vec::new();
        let _ = (&mut stderr)
            .take(MAX_REPORT_BYTES as u64 + 1)
            .read_to_end(&mut report)
            .await;
        // To the end: a curl writing to a pipe nobody reads never exits.
        let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        report
    };
    let (copied, report) = tokio::join!(body, report);
    let copied = copied.map_err(|_| VendorError::Local)?;
    if copied > MAX_PACKAGE_BYTES {
        return Err(VendorError::TooLarge);
    }
    file.flush().await.map_err(|_| VendorError::Local)?;
    let status = child.wait().await.map_err(|_| VendorError::Transport)?;
    // Its exit code is all anyone hears about a failure: stderr can hold the URL.
    match status.code() {
        Some(0) => {}
        Some(63) => return Err(VendorError::TooLarge),
        Some(28) => return Err(VendorError::TimedOut),
        // The config itself, or curl can't start: this machine's doing.
        Some(2) => return Err(VendorError::Local),
        _ => return Err(VendorError::Transport),
    }
    parse_report(&report).ok_or(VendorError::Transport)
}

/// `<status> <redirect url>`. One past the bound had its location cut, and a cut
/// location is another URL.
fn parse_report(report: &[u8]) -> Option<HopAnswer> {
    if report.len() > MAX_REPORT_BYTES {
        return None;
    }
    let text = std::str::from_utf8(report).ok()?;
    let (status, location) = text.split_once(' ')?;
    let location = location.trim();
    Some(HopAnswer {
        status: status.parse().ok()?,
        location: (!location.is_empty()).then(|| Secret::new(location.to_string())),
    })
}

/// Fetch a package into `dest`, which the caller keeps private. Returns the host it
/// finally came from.
pub async fn download_package(url: &Secret, dest: &Path) -> Result<String, VendorError> {
    download_with(&CurlFetch, url, dest).await
}

pub(crate) async fn download_with(
    fetch: &dyn HopFetch,
    url: &Secret,
    dest: &Path,
) -> Result<String, VendorError> {
    let deadline = Instant::now() + TIME_CAP;
    let mut current = url.clone();
    for hop in 0..MAX_HOPS {
        let (target, host) = check_target(current.expose(), hop == 0)?;
        // Asked again for each hop, and every address has to pass: a name a
        // hostile server controls can answer differently each time.
        let addrs = fetch.resolve(&host).await?;
        if addrs.is_empty() {
            return Err(VendorError::NoAddress);
        }
        if !addrs.iter().all(address_allowed) {
            return Err(VendorError::PrivateAddress);
        }
        let max_secs = deadline.saturating_duration_since(Instant::now()).as_secs();
        if max_secs == 0 {
            return Err(VendorError::TimedOut);
        }
        let target = Secret::new(target.into());
        let answer = fetch
            .get(
                &Hop {
                    url: &target,
                    host: &host,
                    addrs: &addrs,
                    max_secs,
                },
                dest,
            )
            .await?;
        if REDIRECT_STATUSES.contains(&answer.status) {
            current = answer.location.ok_or(VendorError::Transport)?;
            continue;
        }
        if answer.status != 200 {
            return Err(VendorError::HttpStatus(answer.status));
        }
        let size = fs::metadata(dest).map_err(|_| VendorError::Local)?.len();
        if size > MAX_PACKAGE_BYTES {
            return Err(VendorError::TooLarge);
        }
        return Ok(host);
    }
    Err(VendorError::TooManyRedirects)
}

/// What a package turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorFetched {
    /// The first for its slug and version: sites on it are verified from now.
    New,
    /// The same as the cached one, which now has a second hosting behind it.
    Confirmed,
    /// Not the same: the version is disputed until someone forgets it.
    Disputed,
}

/// Download a planned package and compare it with, or cache it as, the manifest for
/// its version. A failure backs this hosting's slug and version off, unless the
/// failure is this machine's (a full disk). Only hashes are kept: no ZIP, no URL.
pub async fn fetch_package(
    p: &PlannedPackage,
    hosting_id: &str,
    cache_dir: &Path,
) -> Result<VendorFetched, VendorError> {
    fetch_with(&CurlFetch, p, hosting_id, cache_dir, SystemTime::now()).await
}

pub(crate) async fn fetch_with(
    fetch: &dyn HopFetch,
    p: &PlannedPackage,
    hosting_id: &str,
    cache_dir: &Path,
    now: SystemTime,
) -> Result<VendorFetched, VendorError> {
    let result = download_and_store(fetch, p, hosting_id, cache_dir, now).await;
    if matches!(&result, Err(e) if *e != VendorError::Local) {
        mark_failed(cache_dir, hosting_id, &p.slug, &p.version, now);
    }
    result
}

async fn download_and_store(
    fetch: &dyn HopFetch,
    p: &PlannedPackage,
    hosting_id: &str,
    cache_dir: &Path,
    now: SystemTime,
) -> Result<VendorFetched, VendorError> {
    let tmp_dir = cache_dir.join(VENDOR_DIR).join(TMP_DIR);
    root_only_dir(&tmp_dir).map_err(|_| VendorError::Local)?;
    // 0600, and gone when dropped, on every path out of here.
    let tmp = tempfile::NamedTempFile::new_in(&tmp_dir).map_err(|_| VendorError::Local)?;
    let final_host = download_with(fetch, &p.url, tmp.path()).await?;
    let key = vendor_key(p.kind, &p.slug, &p.version);
    let hosting_id = hosting_id.to_string();
    let cache_dir = cache_dir.to_path_buf();
    // Hashing a large package is CPU and disk work: off the async threads.
    tokio::task::spawn_blocking(move || {
        let stored = store_manifest(tmp.path(), &key, &final_host, &hosting_id, &cache_dir, now);
        drop(tmp);
        stored
    })
    .await
    .map_err(|_| VendorError::Local)?
}

/// Check a downloaded package is what was asked for, under the version its own
/// header says. The first manifest for a key stays; one that can't be parsed is no
/// manifest. Any later one only says whether it agrees.
fn store_manifest(
    zip: &Path,
    key: &ComponentKey,
    final_host: &str,
    hosting_id: &str,
    cache_dir: &Path,
    now: SystemTime,
) -> Result<VendorFetched, VendorError> {
    let (top, version) =
        package_identity(zip, key.kind, &key.slug).map_err(|_| VendorError::BadPackage)?;
    if top != key.slug {
        return Err(VendorError::BadPackage);
    }
    if version != key.version {
        return Err(VendorError::VersionMismatch);
    }
    let dest = cache_path_for(cache_dir, key, ManifestSource::VendorPackage)
        .map_err(|_| VendorError::BadPackage)?;
    let manifest = manifest_from_zip(zip, key, ManifestSource::VendorPackage)
        .map_err(|_| VendorError::BadPackage)?;
    if let Some(cached) = read_vendor_manifest(&dest) {
        if cached.files != manifest.files {
            write_synced(&vendor_disputed_path(&dest), b"")?;
            return Ok(VendorFetched::Disputed);
        }
        let mut record = read_provenance(&dest).unwrap_or_default();
        if record.hostings.len() < MAX_PROVENANCE_HOSTINGS
            && !record.hostings.iter().any(|h| h == hosting_id)
        {
            record.hostings.push(hosting_id.to_string());
            write_provenance(&dest, &record)?;
        }
        return Ok(VendorFetched::Confirmed);
    }
    let record = Provenance {
        final_host: final_host.to_string(),
        hostings: vec![hosting_id.to_string()],
        at: now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
    };
    write_provenance(&dest, &record)?;
    let json = serde_json::to_vec(&manifest).map_err(|_| VendorError::Local)?;
    write_synced(&dest, &json)?;
    Ok(VendorFetched::New)
}

/// Written whole and on disk before the name appears: a reader sees a complete file
/// or none, even after a crash.
fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), VendorError> {
    let dir = path.parent().ok_or(VendorError::Local)?;
    fs::create_dir_all(dir).map_err(|_| VendorError::Local)?;
    let mut out = tempfile::NamedTempFile::new_in(dir).map_err(|_| VendorError::Local)?;
    out.write_all(bytes).map_err(|_| VendorError::Local)?;
    out.as_file().sync_all().map_err(|_| VendorError::Local)?;
    out.persist(path).map_err(|_| VendorError::Local)?;
    Ok(())
}

/// A cached vendor manifest, or `None` for anything that isn't a usable one.
fn read_vendor_manifest(path: &Path) -> Option<Manifest> {
    let m: Manifest = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    (m.source == ManifestSource::VendorPackage && !m.files.is_empty()).then_some(m)
}

// ---- where a manifest came from ----

#[derive(Debug, Default, Serialize, Deserialize)]
struct Provenance {
    #[serde(default)]
    final_host: String,
    #[serde(default)]
    hostings: Vec<String>,
    #[serde(default)]
    at: i64,
}

fn read_provenance(manifest_path: &Path) -> Option<Provenance> {
    serde_json::from_slice(&fs::read(vendor_provenance_path(manifest_path)).ok()?).ok()
}

fn write_provenance(manifest_path: &Path, record: &Provenance) -> Result<(), VendorError> {
    let json = serde_json::to_vec(record).map_err(|_| VendorError::Local)?;
    write_synced(&vendor_provenance_path(manifest_path), &json)
}

/// What the operator is shown about a cached manifest. `None` when there is none.
pub fn package_info(cache_dir: &Path, key: &ComponentKey) -> Option<VendorPackageInfo> {
    let path = cache_path_for(cache_dir, key, ManifestSource::VendorPackage).ok()?;
    read_vendor_manifest(&path)?;
    let record = read_provenance(&path).unwrap_or_default();
    Some(VendorPackageInfo {
        theme: key.kind == ComponentKind::Theme,
        slug: key.slug.clone(),
        version: key.version.clone(),
        final_host: record.final_host,
        hostings: record.hostings,
        at: record.at,
        disputed: vendor_disputed_path(&path).exists(),
    })
}

/// Delete a manifest, its record and any dispute, for one slug and version. Says
/// whether there was a manifest. The next site with a link for it starts over.
pub fn forget_package(cache_dir: &Path, key: &ComponentKey) -> std::io::Result<bool> {
    let Ok(path) = cache_path_for(cache_dir, key, ManifestSource::VendorPackage) else {
        return Ok(false);
    };
    for marker in [vendor_provenance_path(&path), vendor_disputed_path(&path)] {
        match fs::remove_file(marker) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    //! The serialized transients here are hand-written to the shape WordPress's
    //! `wp_update_plugins()` and `wp_update_themes()` store. None comes from a real
    //! site. The package hosts are not confirmed against a real licence either.

    use super::*;
    use crate::sitescan::discover::{discover, Component, Discovery};
    use crate::sitescan::manifest::{cache_path_for, ComponentKey, Manifest, ManifestSource};
    use crate::sitescan::scan::{scan_site, ScanInput, ScanMode};
    use crate::sitescan::TenantRoot;
    use hyperion_types::FindingKind;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};
    use zip::write::SimpleFileOptions;

    const LICENCE: &str = "LICENCE-KEY-do-not-leak";
    const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    fn secret(url: &str) -> Secret {
        Secret::new(url.to_string())
    }

    fn elementor_url(file: &str) -> String {
        format!("https://my.elementor.com/{file}?license={LICENCE}")
    }

    /// `s:N:"...";`, with N in bytes as PHP counts it.
    fn s(v: &str) -> String {
        format!("s:{}:\"{v}\";", v.len())
    }

    /// One `$transient->response` entry as an updater leaves it: a stdClass.
    fn plugin_entry(slug: &str, file: &str, version: &str, package: &str) -> String {
        let fields = [
            ("id", s(&format!("w.org/plugins/{slug}"))),
            ("slug", s(slug)),
            ("plugin", s(file)),
            ("new_version", s(version)),
            ("url", s("https://example.test/")),
            ("package", s(package)),
            (
                "icons",
                format!("a:1:{{{}{}}}", s("1x"), s("https://example.test/i.png")),
            ),
            ("banners", "a:0:{}".to_string()),
            ("requires_php", s("7.4")),
            ("compatibility", r#"O:8:"stdClass":0:{}"#.to_string()),
        ];
        let body: String = fields.iter().map(|(k, v)| format!("{}{v}", s(k))).collect();
        format!(r#"O:8:"stdClass":{}:{{{body}}}"#, fields.len())
    }

    fn plugins_transient(response: &[(&str, String)], no_update: &[(&str, String)]) -> String {
        let map = |entries: &[(&str, String)]| -> String {
            let body: String = entries
                .iter()
                .map(|(k, v)| format!("{}{v}", s(k)))
                .collect();
            format!("a:{}:{{{body}}}", entries.len())
        };
        format!(
            r#"O:8:"stdClass":5:{{{}i:1798000000;{}a:1:{{{}{}}}{}{}{}a:0:{{}}{}{}}}"#,
            s("last_checked"),
            s("checked"),
            s("elementor-pro/elementor-pro.php"),
            s("3.25.0"),
            s("response"),
            map(response),
            s("translations"),
            s("no_update"),
            map(no_update),
        )
    }

    fn theme_entry(theme: &str, version: &str, package: &str) -> String {
        let fields = [
            ("theme", s(theme)),
            ("new_version", s(version)),
            ("url", s("https://example.test/")),
            ("package", s(package)),
            ("requires", "b:0;".to_string()),
            ("requires_php", "d:7.4;".to_string()),
        ];
        let body: String = fields.iter().map(|(k, v)| format!("{}{v}", s(k))).collect();
        format!("a:{}:{{{body}}}", fields.len())
    }

    fn plugin_zip_bytes(slug: &str, version: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
        let main = format!("<?php\n/*\nPlugin Name: {slug}\nVersion: {version}\n*/\n");
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        w.start_file(format!("{slug}/{slug}.php"), SimpleFileOptions::default())
            .expect("start");
        w.write_all(main.as_bytes()).expect("write");
        for (name, body) in extra {
            w.start_file(format!("{slug}/{name}"), SimpleFileOptions::default())
                .expect("start");
            w.write_all(body).expect("write");
        }
        w.finish().expect("finish").into_inner()
    }

    #[derive(Clone)]
    enum Answer {
        Body(Vec<u8>),
        /// A file of this length, without writing it.
        SizedBody(u64),
        Redirect(String),
        Status(u16),
    }

    /// DNS and HTTP with no network: what each name resolves to and what each
    /// request answers, in order, with every request recorded.
    struct Fake {
        dns: BTreeMap<String, Vec<IpAddr>>,
        answers: Mutex<VecDeque<Answer>>,
        asked: Mutex<Vec<String>>,
        pinned: Mutex<Vec<Vec<IpAddr>>>,
    }

    impl Fake {
        fn new(answers: Vec<Answer>) -> Fake {
            Fake {
                dns: BTreeMap::new(),
                answers: Mutex::new(answers.into()),
                asked: Mutex::default(),
                pinned: Mutex::default(),
            }
        }

        fn resolving(mut self, host: &str, addrs: &[IpAddr]) -> Fake {
            self.dns.insert(host.to_string(), addrs.to_vec());
            self
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().expect("lock").clone()
        }
    }

    #[async_trait::async_trait]
    impl HopFetch for Fake {
        async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, VendorError> {
            Ok(self.dns.get(host).cloned().unwrap_or_else(|| vec![PUBLIC]))
        }

        async fn get(&self, hop: &Hop<'_>, dest: &Path) -> Result<HopAnswer, VendorError> {
            self.asked
                .lock()
                .expect("lock")
                .push(hop.url.expose().to_string());
            self.pinned.lock().expect("lock").push(hop.addrs.to_vec());
            let answer = self
                .answers
                .lock()
                .expect("lock")
                .pop_front()
                .unwrap_or(Answer::Status(500));
            Ok(match answer {
                Answer::Body(b) => {
                    fs::write(dest, b).expect("write");
                    HopAnswer {
                        status: 200,
                        location: None,
                    }
                }
                Answer::SizedBody(len) => {
                    fs::File::create(dest)
                        .and_then(|f| f.set_len(len))
                        .expect("size");
                    HopAnswer {
                        status: 200,
                        location: None,
                    }
                }
                Answer::Redirect(to) => HopAnswer {
                    status: 302,
                    location: Some(Secret::new(to)),
                },
                Answer::Status(status) => HopAnswer {
                    status,
                    location: None,
                },
            })
        }
    }

    fn planned(slug: &str, version: &str, bucket: PackageBucket, url: &str) -> PlannedPackage {
        PlannedPackage {
            kind: ComponentKind::Plugin,
            slug: slug.into(),
            version: version.into(),
            url: secret(url),
            bucket,
            verifies_today: bucket == PackageBucket::NoUpdate,
        }
    }

    fn component(slug: &str, version: &str) -> Component {
        Component {
            key: ComponentKey {
                kind: ComponentKind::Plugin,
                slug: slug.into(),
                version: version.into(),
                locale: None,
            },
            rel_root: format!("wp-content/plugins/{slug}"),
            is_child_theme: false,
            single_file: false,
        }
    }

    fn key(slug: &str, version: &str) -> ComponentKey {
        component(slug, version).key
    }

    const SITE_A: &str = "01JAAAAAAAAAAAAAAAAAAAAAAA";
    const SITE_B: &str = "01JBBBBBBBBBBBBBBBBBBBBBBB";

    fn no_differences() -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn plan_for(
        refs: Vec<PackageRef>,
        candidates: &[ComponentKey],
        hosting: &str,
        cache: &Path,
        now: SystemTime,
    ) -> VendorPlan {
        plan_downloads(refs, candidates, &no_differences(), hosting, cache, now)
    }

    fn cached(cache: &Path, slug: &str, version: &str) -> PathBuf {
        cache_path_for(cache, &key(slug, version), ManifestSource::VendorPackage).expect("path")
    }

    /// Everything under `dir`, names and contents, as one text.
    fn everything_under(dir: &Path) -> String {
        let mut out = String::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return out;
        };
        for e in entries.flatten() {
            out.push_str(&e.path().display().to_string());
            out.push('\n');
            if e.path().is_dir() {
                out.push_str(&everything_under(&e.path()));
            } else {
                out.push_str(&String::from_utf8_lossy(&fs::read(e.path()).expect("read")));
                out.push('\n');
            }
        }
        out
    }

    fn tmp_is_empty(cache: &Path) -> bool {
        fs::read_dir(cache.join("vendor").join("tmp"))
            .map(|mut d| d.next().is_none())
            .unwrap_or(true)
    }

    // ---- parsing what a tenant can write ----

    #[test]
    fn parses_response_and_no_update_entries() {
        let text = plugins_transient(
            &[(
                "elementor-pro/elementor-pro.php",
                plugin_entry(
                    "elementor-pro",
                    "elementor-pro/elementor-pro.php",
                    "3.26.0",
                    &elementor_url("next.zip"),
                ),
            )],
            &[
                (
                    "wp-rocket/wp-rocket.php",
                    plugin_entry(
                        "wp-rocket",
                        "wp-rocket/wp-rocket.php",
                        "3.17",
                        "https://wp-rocket.me/d.zip",
                    ),
                ),
                // No package: nothing to download.
                (
                    "acf-free/acf.php",
                    plugin_entry("acf-free", "acf-free/acf.php", "6.0", ""),
                ),
            ],
        );
        let refs = parse_update_transient(&text, ComponentKind::Plugin);
        assert_eq!(refs.len(), 2, "{refs:?}");
        let next = refs
            .iter()
            .find(|r| r.bucket == PackageBucket::Response)
            .expect("response");
        assert_eq!(next.slug, "elementor-pro");
        assert_eq!(next.kind, ComponentKind::Plugin);
        assert_eq!(next.version.as_deref(), Some("3.26.0"));
        assert_eq!(next.url.expose(), elementor_url("next.zip"));
        let today = refs
            .iter()
            .find(|r| r.bucket == PackageBucket::NoUpdate)
            .expect("no_update");
        assert_eq!(today.slug, "wp-rocket");
        assert_eq!(today.version.as_deref(), Some("3.17"));

        let themes = format!(
            r#"O:8:"stdClass":2:{{{}a:1:{{{}{}}}{}a:0:{{}}}}"#,
            s("response"),
            s("divi"),
            theme_entry("divi", "4.27", "https://wpforms.com/divi.zip"),
            s("no_update"),
        );
        let refs = parse_update_transient(&themes, ComponentKind::Theme);
        assert_eq!(refs.len(), 1, "an array entry reads like an object one");
        assert_eq!(refs[0].slug, "divi");
        assert_eq!(refs[0].kind, ComponentKind::Theme);
    }

    /// The literal below is counted by hand, multi-byte name included: a length in
    /// characters instead of bytes would lose it.
    #[test]
    fn string_lengths_are_bytes_not_characters() {
        let text = concat!(
            r#"a:1:{s:9:"no_update";a:1:{s:9:"pro/p.php";a:3:{"#,
            r#"s:4:"name";s:7:"Přílo";"#,
            r#"s:11:"new_version";s:3:"1.0";"#,
            r#"s:7:"package";s:27:"https://wpml.org/p.zip?a=b;";}}}"#,
        );
        let refs = parse_update_transient(text, ComponentKind::Plugin);
        assert_eq!(refs.len(), 1, "{refs:?}");
        assert_eq!(refs[0].url.expose(), "https://wpml.org/p.zip?a=b;");
        // The `;` inside the value is data: the length says where it ends.
        assert_eq!(refs[0].slug, "pro");
    }

    #[test]
    fn garbage_transient_yields_nothing() {
        let good = plugins_transient(
            &[(
                "pro/p.php",
                plugin_entry("pro", "pro/p.php", "1.0", "https://wpml.org/p.zip"),
            )],
            &[],
        );
        assert_eq!(
            parse_update_transient(&good, ComponentKind::Plugin).len(),
            1
        );
        let huge_count = "a:4294967295:{".to_string();
        let lying_length = r#"a:1:{s:999999:"response";a:0:{}}"#.to_string();
        let overflow = format!("s:{}:\"x\";", u64::MAX);
        let negative = r#"s:-1:"x";"#.to_string();
        let deep = "a:1:{i:0;".repeat(50);
        let mut cases = vec![
            String::new(),
            "not serialized".to_string(),
            "N;".to_string(),
            "b:1;".to_string(),
            huge_count,
            lying_length,
            overflow,
            negative,
            deep,
            // Custom serialization: never interpreted.
            r#"C:3:"Foo":3:{abc}"#.to_string(),
            // A whole value cut short, as the database's 8 MiB bound would.
            good[..good.len() / 2].to_string(),
            format!("{good}trailing"),
        ];
        // Every prefix: no slice of a good value panics.
        for end in 0..good.len() {
            if good.is_char_boundary(end) {
                cases.push(good[..end].to_string());
            }
        }
        for case in &cases {
            assert!(
                parse_update_transient(case, ComponentKind::Plugin).is_empty(),
                "{}",
                case.chars().take(60).collect::<String>()
            );
        }
        // Core has no package.
        assert!(parse_update_transient(&good, ComponentKind::Core).is_empty());
    }

    #[test]
    fn a_name_that_cannot_be_a_folder_is_dropped() {
        for name in [
            "../evil/p.php",
            "a/b/p.php",
            "single.php",
            "UP/p.php",
            "/p.php",
        ] {
            let text = plugins_transient(
                &[(
                    name,
                    plugin_entry("x", name, "1.0", "https://wpml.org/p.zip"),
                )],
                &[],
            );
            assert!(
                parse_update_transient(&text, ComponentKind::Plugin).is_empty(),
                "{name}"
            );
        }
        let text = plugins_transient(
            &[(
                "pro/p.php",
                plugin_entry("pro", "pro/p.php", "../../x", "https://wpml.org/p.zip"),
            )],
            &[],
        );
        assert!(
            parse_update_transient(&text, ComponentKind::Plugin).is_empty(),
            "a version that can't be a file name"
        );
    }

    #[test]
    fn the_refs_one_value_can_hold_are_capped() {
        let entries: Vec<(String, String)> = (0..MAX_REFS + 50)
            .map(|i| {
                let name = format!("p{i}/p.php");
                let entry = plugin_entry(&format!("p{i}"), &name, "1.0", "https://wpml.org/p.zip");
                (name, entry)
            })
            .collect();
        let view: Vec<(&str, String)> = entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let refs = parse_update_transient(&plugins_transient(&view, &[]), ComponentKind::Plugin);
        assert!(refs.len() <= MAX_REFS, "{}", refs.len());
    }

    #[test]
    fn reads_the_database_name_and_prefix_from_wp_config() {
        let text = r#"<?php
// define('DB_NAME', 'old_commented_out');
define( 'DB_NAME', 'lm_abc_site' );
define( "DB_USER", "lm_abc_u" );
$table_prefix  = 'wp_x1_';
"#;
        assert_eq!(
            parse_wp_config_db(text),
            Some(("lm_abc_site".to_string(), "wp_x1_".to_string()))
        );
        assert_eq!(
            parse_wp_config_db(r#"<?php define("DB_NAME","a");$table_prefix="b_";"#),
            Some(("a".to_string(), "b_".to_string()))
        );
        for bad in [
            "",
            "<?php $table_prefix = 'wp_';",
            "<?php define('DB_NAME', 'a');",
            "<?php define('DB_NAME', getenv('X')); $table_prefix = 'wp_';",
        ] {
            assert_eq!(parse_wp_config_db(bad), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn malicious_prefix_is_refused() {
        for bad in [
            "",
            "wp_`; DROP TABLE x;-- ",
            "wp` FROM mysql.user#",
            "wp'",
            "wp options",
            "wp\n",
            &"a".repeat(65),
        ] {
            assert!(!valid_table_prefix(bad), "{bad:?}");
            let refused = crate::mariadb::read_option(
                "lm_abc",
                bad,
                crate::mariadb::UPDATE_PLUGINS_OPTION,
                &crate::backup::DbLogin {
                    user: "lm_u",
                    password: "p",
                },
            )
            .await;
            assert!(refused.is_err(), "{bad:?}");
            let text = format!("<?php define('DB_NAME', 'a'); $table_prefix = '{bad}';");
            assert_eq!(parse_wp_config_db(&text), None, "{bad:?}");
        }
        assert!(valid_table_prefix("wp_X9_"));
        assert!(valid_table_prefix(&"a".repeat(64)));
    }

    #[test]
    fn wp_config_is_read_through_the_tenant_root_and_bounded() {
        let t = tempfile::tempdir().expect("tmp");
        let root = t.path().canonicalize().expect("canonical").join("htdocs");
        fs::create_dir(&root).expect("mkdir");
        assert_eq!(read_wp_config_db(&root), None, "no file");

        fs::write(
            root.join("wp-config.php"),
            "<?php define('DB_NAME','own'); $table_prefix='wp_';",
        )
        .expect("write");
        assert_eq!(
            read_wp_config_db(&root),
            Some(("own".to_string(), "wp_".to_string()))
        );

        // Past the bound isn't read.
        let mut big = " ".repeat(WP_CONFIG_MAX_BYTES as usize);
        big.push_str("<?php define('DB_NAME','own'); $table_prefix='wp_';");
        fs::write(root.join("wp-config.php"), big).expect("write");
        assert_eq!(read_wp_config_db(&root), None);

        // A link to someone else's config is not followed.
        let theirs = root.parent().expect("parent").join("theirs.php");
        fs::write(
            &theirs,
            "<?php define('DB_NAME','victim'); $table_prefix='wp_';",
        )
        .expect("write");
        fs::remove_file(root.join("wp-config.php")).expect("rm");
        std::os::unix::fs::symlink(&theirs, root.join("wp-config.php")).expect("link");
        assert_eq!(read_wp_config_db(&root), None);
    }

    // ---- secrets ----

    #[test]
    fn secret_never_in_debug_output() {
        let url = elementor_url("p.zip");
        let r = PackageRef {
            kind: ComponentKind::Plugin,
            slug: "pro".into(),
            version: Some("1.0".into()),
            url: secret(&url),
            bucket: PackageBucket::NoUpdate,
        };
        for shown in [
            format!("{:?}", r.url),
            format!("{}", r.url),
            format!("{r:?}"),
            format!("{:?}", planned("pro", "1.0", PackageBucket::NoUpdate, &url)),
            format!(
                "{:?}",
                HopAnswer {
                    status: 302,
                    location: Some(secret(&url))
                }
            ),
        ] {
            assert!(!shown.contains(LICENCE), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
        assert_eq!(format!("{}", r.url), "<redacted>");
    }

    #[test]
    fn url_not_on_argv() {
        let url = elementor_url("p.zip");
        let s = secret(&url);
        let addrs = [PUBLIC];
        let hop = Hop {
            url: &s,
            host: "my.elementor.com",
            addrs: &addrs,
            max_secs: 300,
        };
        let cmd = curl_command();
        let std = cmd.as_std();
        let argv: Vec<String> = std
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(argv, ["-q", "--config", "-"], "only options, never the URL");
        assert!(!argv.iter().any(|a| a.contains(LICENCE)));

        // It goes on stdin instead, with what keeps curl where it was checked.
        let cfg = hop_config(&hop);
        assert!(cfg.contains(LICENCE), "{cfg}");
        for line in [
            "max-redirs = 0",
            "proto = \"=https\"",
            "proto-redir = \"=https\"",
            "max-filesize = 209715200",
            "max-time = 300",
            "noproxy = \"*\"",
            "globoff",
            "speed-limit = 10240",
            "speed-time = 60",
            "resolve = \"my.elementor.com:443:93.184.216.34\"",
        ] {
            assert!(cfg.lines().any(|l| l == line), "{line} in {cfg}");
        }
        for never in ["location", "insecure", "output"] {
            assert!(
                !cfg.lines().any(|l| l.starts_with(never)),
                "{never} in {cfg}"
            );
        }
    }

    #[test]
    fn a_pin_to_ipv6_is_bracketed() {
        let s = secret("https://my.elementor.com/p.zip");
        let addrs: [IpAddr; 2] = [PUBLIC, "2606:2800:220:1::1".parse().expect("ip")];
        let hop = Hop {
            url: &s,
            host: "my.elementor.com",
            addrs: &addrs,
            max_secs: 10,
        };
        let cfg = hop_config(&hop);
        assert!(
            cfg.contains("resolve = \"my.elementor.com:443:93.184.216.34,[2606:2800:220:1::1]\""),
            "{cfg}"
        );
    }

    /// The real curl parses the config: anything but its "failed to start" means it
    /// got as far as trying to connect.
    #[tokio::test]
    async fn curl_accepts_the_config() {
        if !Path::new(CURL).exists() {
            return;
        }
        let s = secret("https://my.elementor.com:443/p.zip");
        let addrs = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
        let hop = Hop {
            url: &s,
            host: "my.elementor.com",
            addrs: &addrs,
            max_secs: 5,
        };
        let t = tempfile::tempdir().expect("tmp");
        let got = CurlFetch.get(&hop, &t.path().join("body")).await;
        // Refused, most likely. Whatever is on this machine's :443 is its own answer.
        assert_ne!(got.err(), Some(VendorError::Local));
    }

    /// One real TLS round trip. Run in a container with a server on 127.0.0.1:443
    /// for `my.elementor.com` under a trusted test CA, answering `/body` with
    /// `hello`, `/moved` with a 302 to `/body` and `/big` with 300 MiB of no declared
    /// length, which before curl 8.4 `max-filesize` doesn't stop.
    #[tokio::test]
    #[ignore = "needs the local TLS server described above"]
    async fn curl_fetch_against_a_local_tls_server() {
        let t = tempfile::tempdir().expect("tmp");
        let dest = t.path().join("body");
        let addrs = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
        let body = secret("https://my.elementor.com/body");
        let hop = Hop {
            url: &body,
            host: "my.elementor.com",
            addrs: &addrs,
            max_secs: 10,
        };
        let a = CurlFetch.get(&hop, &dest).await.expect("get");
        assert_eq!(a.status, 200);
        assert!(a.location.is_none());
        assert_eq!(fs::read(&dest).expect("read"), b"hello");

        let moved = secret("https://my.elementor.com/moved");
        let hop = Hop {
            url: &moved,
            host: "my.elementor.com",
            addrs: &addrs,
            max_secs: 10,
        };
        let a = CurlFetch.get(&hop, &dest).await.expect("get");
        assert_eq!(a.status, 302);
        assert_eq!(
            a.location.expect("location").expose(),
            "https://my.elementor.com/body"
        );

        let big = secret("https://my.elementor.com/big");
        let hop = Hop {
            url: &big,
            host: "my.elementor.com",
            addrs: &addrs,
            max_secs: 60,
        };
        let got = CurlFetch.get(&hop, &dest).await;
        assert!(matches!(got, Err(VendorError::TooLarge)), "{got:?}");
        let written = fs::metadata(&dest).expect("meta").len();
        assert!(written <= MAX_PACKAGE_BYTES + 1024 * 1024, "{written}");
    }

    // ---- where a request may go ----

    #[test]
    fn host_lists() {
        for host in [
            "my.elementor.com",
            "connect.advancedcustomfields.com",
            "wp-rocket.me",
            "my.yoast.com",
            "wpml.org",
            "wpforms.com",
        ] {
            assert!(vendor_host_allowed(host), "{host}");
            assert!(redirect_host_allowed(host), "{host}");
        }
        // Anyone can rent a name under these, so no wildcard is ever on a list.
        assert!(VENDOR_HOSTS
            .iter()
            .chain(&REDIRECT_HOSTS)
            .all(|h| !h.contains('*')));
        for host in [
            "",
            "bucket.s3.amazonaws.com",
            "d1234.cloudfront.net",
            "s3.amazonaws.com",
            "cloudfront.net",
            ".cloudfront.net",
            "evilcloudfront.net",
            "my.elementor.com.evil.example",
            "my.elementor.com.",
            "evil-wpml.org",
            "sub.wpml.org",
            "example.com",
            "169.254.169.254",
        ] {
            assert!(!vendor_host_allowed(host), "{host}");
            assert!(!redirect_host_allowed(host), "{host}");
        }
    }

    #[test]
    fn addresses_that_may_not_be_reached() {
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.100.100.200",
            "168.63.129.16",
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
            "2001:0:1::1",
            "fec0::1",
            "feff::1",
            "64:ff9b:1::1",
            "64:ff9b:1:ffff::a9fe:a9fe",
        ] {
            let ip: IpAddr = ip.parse().expect("ip");
            assert!(!address_allowed(&ip), "{ip}");
        }
        for ip in [
            "93.184.216.34",
            "2606:2800:220:1::1",
            "::ffff:93.184.216.34",
        ] {
            let ip: IpAddr = ip.parse().expect("ip");
            assert!(address_allowed(&ip), "{ip}");
        }
    }

    async fn download(fake: &Fake, url: &str) -> Result<Vec<u8>, VendorError> {
        let t = tempfile::tempdir().expect("tmp");
        let dest = t.path().join("out");
        download_with(fake, &secret(url), &dest).await?;
        Ok(fs::read(dest).expect("read"))
    }

    #[tokio::test]
    async fn a_listed_host_downloads() {
        let fake = Fake::new(vec![Answer::Body(b"zip".to_vec())]);
        let url = elementor_url("p.zip");
        assert_eq!(download(&fake, &url).await.expect("ok"), b"zip");
        assert_eq!(fake.asked(), [url], "the URL reaches curl as it is");
        assert_eq!(*fake.pinned.lock().expect("lock"), [vec![PUBLIC]]);
    }

    #[tokio::test]
    async fn http_url_refused() {
        let fake = Fake::new(vec![Answer::Body(b"zip".to_vec())]);
        let got = download(&fake, "http://my.elementor.com/p.zip").await;
        assert!(matches!(got, Err(VendorError::NotHttps)), "{got:?}");
        for url in [
            "ftp://my.elementor.com/p.zip",
            "file:///etc/passwd",
            "gopher://my.elementor.com/",
        ] {
            assert!(download(&fake, url).await.is_err(), "{url}");
        }
        assert!(fake.asked().is_empty());
    }

    #[tokio::test]
    async fn userinfo_and_other_ports_refused() {
        let fake = Fake::new(vec![Answer::Body(b"zip".to_vec())]);
        for url in [
            "https://user@my.elementor.com/p.zip",
            "https://user:pw@my.elementor.com/p.zip",
            "https://my.elementor.com:8443/p.zip",
            "https://my.elementor.com:80/p.zip",
            "not a url",
        ] {
            let got = download(&fake, url).await;
            assert!(matches!(got, Err(VendorError::BadUrl)), "{url}: {got:?}");
        }
        assert!(fake.asked().is_empty());
        // 443 is what https means.
        download(&fake, "https://my.elementor.com:443/p.zip")
            .await
            .expect("443");
    }

    #[tokio::test]
    async fn a_url_that_hides_its_host_is_read_the_way_curl_would() {
        let fake = Fake::new(vec![]);
        // The authority here is the second host: refused, whatever it looks like.
        let got = download(&fake, "https://my.elementor.com@evil.example/p.zip").await;
        assert!(got.is_err(), "{got:?}");
        assert!(fake.asked().is_empty());
        // A backslash ends the authority: what's checked is what curl is given.
        let fake = Fake::new(vec![Answer::Body(b"zip".to_vec())]);
        download(&fake, "https://my.elementor.com\\@evil.example/p.zip")
            .await
            .expect("ok");
        assert_eq!(
            fake.asked(),
            ["https://my.elementor.com/@evil.example/p.zip"]
        );
    }

    #[tokio::test]
    async fn unknown_host_is_recorded_not_fetched() {
        let fake = Fake::new(vec![Answer::Body(b"zip".to_vec())]);
        let url = format!("https://updates.vendor.example/p.zip?license={LICENCE}");
        let got = download(&fake, &url).await.expect_err("refused");
        let shown = format!("{got:?} {got}");
        assert!(
            matches!(&got, VendorError::UnknownHost(h) if h == "updates.vendor.example"),
            "{shown}"
        );
        assert!(!shown.contains(LICENCE), "{shown}");
        assert!(!shown.contains("p.zip"), "the host only: {shown}");
        assert!(fake.asked().is_empty());

        // The plan: named in the coverage, not planned, and not a failure.
        let t = tempfile::tempdir().expect("tmp");
        let refs = vec![PackageRef {
            kind: ComponentKind::Plugin,
            slug: "pro".into(),
            version: Some("1.0".into()),
            url: secret(&url),
            bucket: PackageBucket::NoUpdate,
        }];
        let plan = plan_for(
            refs,
            &[key("pro", "1.0")],
            SITE_A,
            t.path(),
            SystemTime::now(),
        );
        assert!(plan.fetch.is_empty());
        assert_eq!(plan.unknown_hosts, ["updates.vendor.example"]);
        assert!(everything_under(t.path()).is_empty(), "no marker for this");
    }

    #[test]
    fn unknown_hosts_are_capped_and_never_a_mangled_name() {
        let t = tempfile::tempdir().expect("tmp");
        let mut refs: Vec<PackageRef> = (0..50)
            .map(|i| PackageRef {
                kind: ComponentKind::Plugin,
                slug: "pro".into(),
                version: Some(format!("1.{i}")),
                url: secret(&format!("https://h{i}.vendor.example/p.zip")),
                bucket: PackageBucket::Response,
            })
            .collect();
        // Not hostnames at all: nothing to record.
        for url in [
            "https://[::1]/p",
            "https://93.184.216.34/p",
            "http://plain.example/p",
        ] {
            refs.push(PackageRef {
                kind: ComponentKind::Plugin,
                slug: "pro".into(),
                version: Some("2.0".into()),
                url: secret(url),
                bucket: PackageBucket::Response,
            });
        }
        let plan = plan_for(
            refs,
            &[key("pro", "1.0")],
            SITE_A,
            t.path(),
            SystemTime::now(),
        );
        assert!(plan.fetch.is_empty());
        assert_eq!(plan.unknown_hosts.len(), MAX_UNKNOWN_HOSTS);
        assert!(plan
            .unknown_hosts
            .iter()
            .all(|h| h.ends_with(".vendor.example")));
    }

    #[tokio::test]
    async fn private_ip_refused() {
        // Written into the URL.
        for url in [
            "https://10.0.0.1/p.zip",
            "https://127.0.0.1/p.zip",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/p.zip",
            "https://[::ffff:169.254.169.254]/p.zip",
            // The URL parser's other spellings of 127.0.0.1.
            "https://2130706433/p.zip",
            "https://0x7f.1/p.zip",
        ] {
            let fake = Fake::new(vec![]);
            let got = download(&fake, url).await;
            assert!(
                matches!(got, Err(VendorError::PrivateAddress)),
                "{url}: {got:?}"
            );
            assert!(fake.asked().is_empty());
        }
        // Or a listed name pointing there, in any of its addresses.
        for addrs in [
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            vec![PUBLIC, IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        ] {
            let fake = Fake::new(vec![]).resolving("wpml.org", &addrs);
            let got = download(&fake, "https://wpml.org/p.zip").await;
            assert!(matches!(got, Err(VendorError::PrivateAddress)), "{got:?}");
            assert!(fake.asked().is_empty());
        }
        // Or nothing at all.
        let fake = Fake::new(vec![]).resolving("wpml.org", &[]);
        assert!(download(&fake, "https://wpml.org/p.zip").await.is_err());
        assert!(fake.asked().is_empty());
    }

    #[tokio::test]
    async fn redirect_to_private_ip_refused() {
        // Literal.
        let fake = Fake::new(vec![Answer::Redirect(
            "https://169.254.169.254/latest/meta-data/".into(),
        )]);
        let got = download(&fake, "https://wpml.org/p.zip").await;
        assert!(matches!(got, Err(VendorError::PrivateAddress)), "{got:?}");
        assert_eq!(fake.asked().len(), 1, "the hop is never requested");

        // A listed name that resolves inside: asked again for each hop.
        let fake = Fake::new(vec![Answer::Redirect("https://wpforms.com/p.zip".into())])
            .resolving("wpforms.com", &[IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))]);
        let got = download(&fake, "https://wpml.org/p.zip").await;
        assert!(matches!(got, Err(VendorError::PrivateAddress)), "{got:?}");
        assert_eq!(fake.asked().len(), 1);
    }

    #[tokio::test]
    async fn redirect_off_allowlist_refused() {
        for to in [
            format!("https://evil.example/p.zip?license={LICENCE}"),
            format!("https://d1.cloudfront.net/p.zip?license={LICENCE}"),
            format!("https://bucket.s3.amazonaws.com/p.zip?license={LICENCE}"),
        ] {
            let fake = Fake::new(vec![Answer::Redirect(to)]);
            let got = download(&fake, "https://wpml.org/p.zip")
                .await
                .expect_err("refused");
            // The host only, so the list can grow from real data.
            assert!(matches!(got, VendorError::UnknownHost(_)), "{got:?}");
            assert!(!format!("{got:?} {got}").contains(LICENCE));
            assert_eq!(fake.asked().len(), 1);
        }

        for bad in [
            "http://wpforms.com/p.zip",
            "https://u:p@wpforms.com/p.zip",
            "https://wpforms.com:8443/p.zip",
            "file:///etc/passwd",
        ] {
            let fake = Fake::new(vec![Answer::Redirect(bad.into())]);
            assert!(
                download(&fake, "https://wpml.org/p.zip").await.is_err(),
                "{bad}"
            );
            assert_eq!(fake.asked().len(), 1, "{bad}");
        }
    }

    #[tokio::test]
    async fn a_redirect_to_a_listed_host_is_followed_and_each_hop_pinned() {
        let second: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 99));
        let fake = Fake::new(vec![
            Answer::Redirect("https://wpforms.com/p.zip?sig=abc".into()),
            Answer::Body(b"zip".to_vec()),
        ])
        .resolving("wpforms.com", &[second]);
        let t = tempfile::tempdir().expect("tmp");
        let dest = t.path().join("out");
        let host = download_with(&fake, &secret("https://wpml.org/p.zip"), &dest)
            .await
            .expect("ok");
        assert_eq!(host, "wpforms.com", "where it finally came from");
        assert_eq!(fs::read(dest).expect("read"), b"zip");
        assert_eq!(fake.asked()[1], "https://wpforms.com/p.zip?sig=abc");
        assert_eq!(
            *fake.pinned.lock().expect("lock"),
            [vec![PUBLIC], vec![second]]
        );
    }

    #[tokio::test]
    async fn a_cdn_is_on_no_list() {
        let fake = Fake::new(vec![Answer::Body(b"zip".to_vec())]);
        let got = download(&fake, "https://d1.cloudfront.net/p.zip").await;
        assert!(matches!(got, Err(VendorError::UnknownHost(_))), "{got:?}");
        assert!(fake.asked().is_empty());
    }

    #[test]
    fn a_report_past_the_bound_is_a_failure_not_a_cut_location() {
        let at_limit = format!("302 https://wpml.org/{}", "a".repeat(2000));
        assert!(parse_report(at_limit.as_bytes()).is_some());
        let over = format!("302 https://wpml.org/{}", "a".repeat(MAX_REPORT_BYTES));
        assert!(parse_report(over.as_bytes()).is_none());
    }

    #[tokio::test]
    async fn at_most_five_hops() {
        let fake = Fake::new(vec![Answer::Redirect("https://wpml.org/2".into()); 20]);
        let got = download(&fake, "https://wpml.org/1").await;
        assert!(matches!(got, Err(VendorError::TooManyRedirects)), "{got:?}");
        assert_eq!(fake.asked().len(), 5);
    }

    #[tokio::test]
    async fn over_the_size_cap_refused() {
        let fake = Fake::new(vec![Answer::SizedBody(MAX_PACKAGE_BYTES + 1)]);
        let got = download(&fake, "https://wpml.org/p.zip").await;
        assert!(matches!(got, Err(VendorError::TooLarge)), "{got:?}");
    }

    #[tokio::test]
    async fn other_statuses_are_failures() {
        for status in [204, 304, 401, 403, 404, 500] {
            let fake = Fake::new(vec![Answer::Status(status)]);
            let got = download(&fake, "https://wpml.org/p.zip").await;
            assert!(
                matches!(got, Err(VendorError::HttpStatus(s)) if s == status),
                "{status}: {got:?}"
            );
        }
    }

    // ---- what a package has to be ----

    #[tokio::test]
    async fn a_package_fills_the_cache_and_keeps_no_url() {
        let t = tempfile::tempdir().expect("tmp");
        let zip = plugin_zip_bytes("pro", "1.0", &[("a.php", b"<?php // a\n")]);
        let fake = Fake::new(vec![Answer::Body(zip)]);
        let url = elementor_url("p.zip");
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &url);
        fetch_with(&fake, &p, SITE_A, t.path(), SystemTime::now())
            .await
            .expect("fetch");
        let m: Manifest =
            serde_json::from_slice(&fs::read(cached(t.path(), "pro", "1.0")).expect("read"))
                .expect("json");
        assert_eq!(m.source, ManifestSource::VendorPackage);
        assert_eq!(m.files.len(), 2);
        assert!(tmp_is_empty(t.path()), "no ZIP is kept");
        let all = everything_under(t.path());
        assert!(!all.contains(LICENCE), "{all}");
        assert!(!all.contains("p.zip"), "{all}");
    }

    #[tokio::test]
    async fn zip_version_mismatch_discards_manifest() {
        let t = tempfile::tempdir().expect("tmp");
        let zip = plugin_zip_bytes("pro", "9.9", &[]);
        let fake = Fake::new(vec![Answer::Body(zip)]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let got = fetch_with(&fake, &p, SITE_A, t.path(), SystemTime::now()).await;
        assert!(matches!(got, Err(VendorError::VersionMismatch)), "{got:?}");
        assert!(!cached(t.path(), "pro", "1.0").exists());
        assert!(!cached(t.path(), "pro", "9.9").exists());
        assert!(tmp_is_empty(t.path()));
    }

    #[tokio::test]
    async fn a_package_for_another_folder_is_refused() {
        let t = tempfile::tempdir().expect("tmp");
        let zip = plugin_zip_bytes("other", "1.0", &[]);
        let fake = Fake::new(vec![Answer::Body(zip)]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let got = fetch_with(&fake, &p, SITE_A, t.path(), SystemTime::now()).await;
        assert!(matches!(got, Err(VendorError::BadPackage)), "{got:?}");
        assert!(!cached(t.path(), "pro", "1.0").exists());
        assert!(tmp_is_empty(t.path()));
    }

    #[tokio::test]
    async fn not_a_zip_is_refused_and_leaves_nothing() {
        let t = tempfile::tempdir().expect("tmp");
        let fake = Fake::new(vec![Answer::Body(b"<html>log in</html>".to_vec())]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let got = fetch_with(&fake, &p, SITE_A, t.path(), SystemTime::now()).await;
        assert!(matches!(got, Err(VendorError::BadPackage)), "{got:?}");
        assert!(tmp_is_empty(t.path()));
    }

    fn manifest_bytes(cache: &Path, slug: &str, version: &str) -> Vec<u8> {
        fs::read(cached(cache, slug, version)).expect("read")
    }

    #[tokio::test]
    async fn provenance_says_where_and_who_and_holds_no_url() {
        let t = tempfile::tempdir().expect("tmp");
        let fake = Fake::new(vec![
            Answer::Redirect(format!("https://wpforms.com/final.zip?license={LICENCE}")),
            Answer::Body(plugin_zip_bytes("pro", "1.0", &[])),
        ]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let got = fetch_with(&fake, &p, SITE_A, t.path(), now)
            .await
            .expect("fetch");
        assert_eq!(got, VendorFetched::New);
        let info = package_info(t.path(), &key("pro", "1.0")).expect("info");
        assert_eq!(info.final_host, "wpforms.com");
        assert_eq!(info.hostings, [SITE_A]);
        assert_eq!(info.at, 1_800_000_000);
        assert!(!info.disputed);
        assert!(!everything_under(t.path()).contains(LICENCE));
    }

    #[tokio::test]
    async fn a_second_package_that_agrees_records_a_second_hosting() {
        let t = tempfile::tempdir().expect("tmp");
        let zip = plugin_zip_bytes("pro", "1.0", &[("a.php", b"<?php // a\n")]);
        let fake = Fake::new(vec![Answer::Body(zip.clone()), Answer::Body(zip)]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let now = SystemTime::now();
        fetch_with(&fake, &p, SITE_A, t.path(), now)
            .await
            .expect("first");
        let kept = manifest_bytes(t.path(), "pro", "1.0");
        let got = fetch_with(&fake, &p, SITE_B, t.path(), now)
            .await
            .expect("second");
        assert_eq!(got, VendorFetched::Confirmed);
        assert_eq!(
            manifest_bytes(t.path(), "pro", "1.0"),
            kept,
            "nothing changes"
        );
        let info = package_info(t.path(), &key("pro", "1.0")).expect("info");
        assert_eq!(info.hostings, [SITE_A, SITE_B]);
        assert!(!info.disputed);
    }

    #[tokio::test]
    async fn a_second_package_that_differs_disputes_the_version_and_keeps_the_first() {
        let t = tempfile::tempdir().expect("tmp");
        let first = plugin_zip_bytes("pro", "1.0", &[("a.php", b"<?php // first\n")]);
        let second = plugin_zip_bytes("pro", "1.0", &[("a.php", b"<?php // second\n")]);
        let fake = Fake::new(vec![Answer::Body(first), Answer::Body(second)]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let now = SystemTime::now();
        fetch_with(&fake, &p, SITE_A, t.path(), now)
            .await
            .expect("first");
        let kept = manifest_bytes(t.path(), "pro", "1.0");
        let got = fetch_with(&fake, &p, SITE_B, t.path(), now)
            .await
            .expect("second");
        assert_eq!(got, VendorFetched::Disputed);
        assert_eq!(manifest_bytes(t.path(), "pro", "1.0"), kept);
        assert!(
            package_info(t.path(), &key("pro", "1.0"))
                .expect("info")
                .disputed
        );
        assert!(tmp_is_empty(t.path()));
    }

    #[tokio::test]
    async fn forgetting_removes_the_manifest_its_record_and_the_dispute() {
        let t = tempfile::tempdir().expect("tmp");
        let fake = Fake::new(vec![
            Answer::Body(plugin_zip_bytes("pro", "1.0", &[("a", b"1")])),
            Answer::Body(plugin_zip_bytes("pro", "1.0", &[("a", b"2")])),
            Answer::Body(plugin_zip_bytes("pro", "1.1", &[])),
        ]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let now = SystemTime::now();
        fetch_with(&fake, &p, SITE_A, t.path(), now)
            .await
            .expect("first");
        fetch_with(&fake, &p, SITE_B, t.path(), now)
            .await
            .expect("second");
        let other = planned("pro", "1.1", PackageBucket::Response, &elementor_url("p"));
        fetch_with(&fake, &other, SITE_A, t.path(), now)
            .await
            .expect("other");

        assert!(forget_package(t.path(), &key("pro", "1.0")).expect("forget"));
        assert!(package_info(t.path(), &key("pro", "1.0")).is_none());
        assert!(!cached(t.path(), "pro", "1.0").exists());
        let dir = cached(t.path(), "pro", "1.0");
        let names = everything_under(dir.parent().expect("parent"));
        assert!(!names.contains("1.0."), "{names}");
        assert!(
            cached(t.path(), "pro", "1.1").exists(),
            "per slug and version"
        );

        assert!(!forget_package(t.path(), &key("pro", "1.0")).expect("again"));
        let bad = ComponentKey {
            slug: "../x".into(),
            ..key("pro", "1.0")
        };
        assert!(!forget_package(t.path(), &bad).expect("bad key"));
    }

    #[tokio::test]
    async fn an_unparsable_cached_file_counts_as_absent() {
        let t = tempfile::tempdir().expect("tmp");
        let path = cached(t.path(), "pro", "1.0");
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, b"{ half a manif").expect("write");
        let url = elementor_url("p");
        let plan = plan_for(
            vec![refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, &url)],
            &[key("pro", "1.0")],
            SITE_A,
            t.path(),
            SystemTime::now(),
        );
        assert_eq!(plan.fetch.len(), 1);
        let fake = Fake::new(vec![Answer::Body(plugin_zip_bytes("pro", "1.0", &[]))]);
        let got = fetch_with(&fake, &plan.fetch[0], SITE_A, t.path(), SystemTime::now())
            .await
            .expect("fetch");
        assert_eq!(got, VendorFetched::New);
        let m: Manifest = serde_json::from_slice(&fs::read(&path).expect("read")).expect("json");
        assert_eq!(m.source, ManifestSource::VendorPackage);
    }

    fn refs_for(slug: &str, version: Option<&str>, bucket: PackageBucket, url: &str) -> PackageRef {
        PackageRef {
            kind: ComponentKind::Plugin,
            slug: slug.into(),
            version: version.map(str::to_string),
            url: secret(url),
            bucket,
        }
    }

    #[tokio::test]
    async fn one_site_fills_cache_for_all() {
        let t = tempfile::tempdir().expect("tmp");
        let zip = plugin_zip_bytes("pro", "1.0", &[]);
        let fake = Fake::new(vec![Answer::Body(zip)]);
        let now = SystemTime::now();
        let candidates = [key("pro", "1.0")];

        let site_a = vec![refs_for(
            "pro",
            Some("1.0"),
            PackageBucket::NoUpdate,
            &elementor_url("a"),
        )];
        let plan = plan_for(site_a, &candidates, SITE_A, t.path(), now);
        assert_eq!(plan.fetch.len(), 1);
        fetch_with(&fake, &plan.fetch[0], SITE_A, t.path(), now)
            .await
            .expect("fetch");

        // Another site on the same version, with a licence of its own, spends nothing.
        let site_b = vec![refs_for(
            "pro",
            Some("1.0"),
            PackageBucket::NoUpdate,
            &elementor_url("b"),
        )];
        let plan = plan_for(site_b, &candidates, SITE_B, t.path(), now);
        assert!(plan.fetch.is_empty());
        assert!(plan.unknown_hosts.is_empty());
        assert_eq!(fake.asked().len(), 1);
    }

    /// A site with a difference that holds its own link compares once, and only
    /// where it hasn't already had a say.
    #[tokio::test]
    async fn a_difference_with_its_own_link_asks_for_a_comparison() {
        let t = tempfile::tempdir().expect("tmp");
        let now = SystemTime::now();
        let zip = plugin_zip_bytes("pro", "1.0", &[]);
        let fake = Fake::new(vec![Answer::Body(zip.clone()), Answer::Body(zip)]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("a"));
        fetch_with(&fake, &p, SITE_A, t.path(), now)
            .await
            .expect("first");

        let url = elementor_url("b");
        let candidates = [key("pro", "1.0")];
        let refs = || vec![refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, &url)];
        let differing: BTreeSet<String> = ["pro".to_string()].into();
        let wanted = |hosting: &str, diff: &BTreeSet<String>| {
            plan_downloads(refs(), &candidates, diff, hosting, t.path(), now)
                .fetch
                .len()
        };
        assert_eq!(
            wanted(SITE_B, &no_differences()),
            0,
            "no difference, no download"
        );
        assert_eq!(wanted(SITE_B, &differing), 1);
        assert_eq!(
            wanted(SITE_A, &differing),
            0,
            "its own package is the reference"
        );

        fetch_with(&fake, &p, SITE_B, t.path(), now)
            .await
            .expect("second");
        assert_eq!(wanted(SITE_B, &differing), 0, "already compared");

        // Disputed already: there's nothing more to learn.
        fs::write(vendor_disputed_path(&cached(t.path(), "pro", "1.0")), b"").expect("write");
        let third = "01JCCCCCCCCCCCCCCCCCCCCCCC";
        assert_eq!(wanted(third, &differing), 0);
    }

    #[tokio::test]
    async fn failed_download_backs_off_per_slug_and_version() {
        let t = tempfile::tempdir().expect("tmp");
        let fake = Fake::new(vec![Answer::Status(403)]);
        let url = elementor_url("p");
        let now = SystemTime::now();
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &url);
        assert!(fetch_with(&fake, &p, SITE_A, t.path(), now).await.is_err());

        let wanted = |hosting: &str, version: &str, at: SystemTime| {
            plan_for(
                vec![refs_for(
                    "pro",
                    Some(version),
                    PackageBucket::NoUpdate,
                    &url,
                )],
                &[key("pro", version)],
                hosting,
                t.path(),
                at,
            )
            .fetch
            .len()
        };
        assert_eq!(wanted(SITE_A, "1.0", now), 0, "this version waits");
        assert_eq!(
            wanted(SITE_A, "1.0", now + Duration::from_secs(23 * 3600)),
            0,
            "still waiting"
        );
        assert_eq!(wanted(SITE_A, "1.1", now), 1, "another version doesn't");
        assert_eq!(
            wanted(SITE_A, "1.0", now + Duration::from_secs(24 * 3600 + 1)),
            1,
            "and after a day it's asked again"
        );

        // The marker says nothing about who failed or how.
        let all = everything_under(t.path());
        assert!(!all.contains(LICENCE), "{all}");
        assert!(!all.contains("pro"), "named by a hash: {all}");
        assert!(!all.contains(SITE_A), "named by a hash: {all}");
        assert!(tmp_is_empty(t.path()));
    }

    /// A tenant planting a bad link backs off itself, and the site with a working
    /// licence still fills the cache.
    #[tokio::test]
    async fn a_failing_site_doesnt_stop_a_good_one() {
        let t = tempfile::tempdir().expect("tmp");
        let now = SystemTime::now();
        let candidates = [key("pro", "1.0")];
        let bad = elementor_url("planted");
        let good = elementor_url("licensed");
        let fake = Fake::new(vec![
            Answer::Status(404),
            Answer::Body(plugin_zip_bytes("pro", "1.0", &[])),
        ]);

        let plan = plan_for(
            vec![refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, &bad)],
            &candidates,
            SITE_A,
            t.path(),
            now,
        );
        assert!(fetch_with(&fake, &plan.fetch[0], SITE_A, t.path(), now)
            .await
            .is_err());
        let attacker_again = plan_for(
            vec![refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, &bad)],
            &candidates,
            SITE_A,
            t.path(),
            now,
        );
        assert!(
            attacker_again.fetch.is_empty(),
            "the attacker backs off itself"
        );

        let plan = plan_for(
            vec![refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, &good)],
            &candidates,
            SITE_B,
            t.path(),
            now,
        );
        assert_eq!(plan.fetch.len(), 1, "the good site isn't held up");
        let got = fetch_with(&fake, &plan.fetch[0], SITE_B, t.path(), now).await;
        assert_eq!(got, Ok(VendorFetched::New));
    }

    /// A full disk says nothing about the vendor or the licence.
    #[tokio::test]
    async fn a_local_failure_sets_no_marker() {
        let t = tempfile::tempdir().expect("tmp");
        // The temp folder can't be made: a file is where it should go.
        fs::create_dir_all(t.path().join("vendor")).expect("mkdir");
        fs::write(t.path().join("vendor").join("tmp"), b"").expect("write");
        let fake = Fake::new(vec![]);
        let url = elementor_url("p");
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &url);
        let now = SystemTime::now();
        let got = fetch_with(&fake, &p, SITE_A, t.path(), now).await;
        assert_eq!(got, Err(VendorError::Local));
        let plan = plan_for(
            vec![refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, &url)],
            &[key("pro", "1.0")],
            SITE_A,
            t.path(),
            now,
        );
        assert_eq!(plan.fetch.len(), 1, "it's asked again next time");
    }

    #[tokio::test]
    async fn each_failure_leaves_a_marker() {
        for answer in [
            Answer::Status(500),
            Answer::Redirect("https://evil.example/".into()),
            Answer::Body(b"not a zip".to_vec()),
            Answer::Body(plugin_zip_bytes("pro", "9.9", &[])),
        ] {
            let t = tempfile::tempdir().expect("tmp");
            let fake = Fake::new(vec![answer]);
            let url = elementor_url("p");
            let now = SystemTime::now();
            let p = planned("pro", "1.0", PackageBucket::NoUpdate, &url);
            assert!(fetch_with(&fake, &p, SITE_A, t.path(), now).await.is_err());
            let plan = plan_for(
                vec![refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, &url)],
                &[key("pro", "1.0")],
                SITE_A,
                t.path(),
                now,
            );
            assert!(plan.fetch.is_empty());
        }
    }

    #[test]
    fn leftovers_are_swept() {
        let t = tempfile::tempdir().expect("tmp");
        let tmp = t.path().join("vendor").join("tmp");
        let failed = t.path().join("vendor").join("failed");
        fs::create_dir_all(&tmp).expect("mkdir");
        fs::create_dir_all(&failed).expect("mkdir");
        fs::write(tmp.join("crashed"), b"zip").expect("write");
        fs::write(failed.join("old"), b"").expect("write");
        let manifest = cached(t.path(), "pro", "1.0");
        fs::create_dir_all(manifest.parent().expect("parent")).expect("mkdir");
        fs::write(&manifest, b"{}").expect("write");

        sweep_leftovers(t.path(), SystemTime::now());
        assert!(tmp.join("crashed").exists(), "could be today's download");
        assert!(failed.join("old").exists(), "still backing off");

        sweep_leftovers(t.path(), SystemTime::now() + Duration::from_secs(25 * 3600));
        assert!(!tmp.join("crashed").exists());
        assert!(!failed.join("old").exists());
        assert!(
            manifest.exists(),
            "nothing can fetch a vendor's manifest again"
        );
    }

    // ---- the plan ----

    #[test]
    fn only_what_wordpress_org_doesnt_know_is_a_candidate() {
        let mut child = component("child", "1.0");
        child.is_child_theme = true;
        let mut single = component("hello", "1.0");
        single.single_file = true;
        let mut core = component("wordpress", "6.8");
        core.key.kind = ComponentKind::Core;
        let d = Discovery {
            is_wordpress: true,
            components: vec![
                component("pro", "1.0"),
                component("akismet", "5.0"),
                component("no-version", ""),
                child,
                single,
                core,
            ],
            ..Default::default()
        };
        let known = ["akismet".to_string()].into_iter().collect();
        let slugs: Vec<String> = vendor_candidates(&d, &known)
            .into_iter()
            .map(|k| k.slug)
            .collect();
        assert_eq!(slugs, ["pro"]);
        let not_wp = Discovery {
            is_wordpress: false,
            ..d
        };
        assert!(vendor_candidates(&not_wp, &known).is_empty());
    }

    #[test]
    fn the_plan_takes_todays_version_first_and_ignores_what_isnt_a_candidate() {
        let t = tempfile::tempdir().expect("tmp");
        let u = "https://wpml.org/p.zip";
        let refs = vec![
            // The next version of another plugin comes after what verifies today.
            refs_for("alpha", Some("2.0"), PackageBucket::Response, u),
            refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, u),
            // A stale no_update entry is neither what it runs nor on offer.
            refs_for("alpha", Some("0.5"), PackageBucket::NoUpdate, u),
            // No declared version: what the site runs, for no_update.
            refs_for("beta", None, PackageBucket::NoUpdate, u),
            // A response entry must say what it's for.
            refs_for("gamma", None, PackageBucket::Response, u),
            // Same key twice is one download.
            refs_for("pro", Some("1.0"), PackageBucket::Response, u),
            // Not on this site, or not a candidate.
            refs_for("stranger", Some("1.0"), PackageBucket::NoUpdate, u),
        ];
        let candidates = [
            key("alpha", "1.0"),
            key("beta", "3.0"),
            key("gamma", "1.0"),
            key("pro", "1.0"),
        ];
        let plan = plan_for(refs, &candidates, SITE_A, t.path(), SystemTime::now());
        let got: Vec<(&str, &str, bool)> = plan
            .fetch
            .iter()
            .map(|p| (p.slug.as_str(), p.version.as_str(), p.verifies_today))
            .collect();
        assert_eq!(
            got,
            [
                ("beta", "3.0", true),
                ("pro", "1.0", true),
                ("alpha", "2.0", false),
            ]
        );
    }

    /// One slug's many main files can't spend the budget: the running version and
    /// one on offer, whatever the transient claims.
    #[test]
    fn many_files_of_one_slug_are_two_downloads_at_most() {
        let t = tempfile::tempdir().expect("tmp");
        let u = "https://wpml.org/p.zip";
        let mut refs: Vec<PackageRef> = (0..40)
            .map(|i| refs_for("pro", Some(&format!("2.{i}")), PackageBucket::Response, u))
            .collect();
        refs.push(refs_for("pro", Some("1.0"), PackageBucket::NoUpdate, u));
        let plan = plan_for(
            refs,
            &[key("pro", "1.0")],
            SITE_A,
            t.path(),
            SystemTime::now(),
        );
        assert_eq!(plan.fetch.len(), 2, "{:?}", plan.fetch);
        assert_eq!(plan.fetch[0].version, "1.0");
        assert!(plan.fetch[0].verifies_today);
        assert!(!plan.fetch[1].verifies_today);
    }

    // ---- what the scan makes of it ----

    /// A WordPress tree with one plugin, and a scan of it the way the worker runs it.
    struct Tree {
        _t: tempfile::TempDir,
        root: PathBuf,
        cache: PathBuf,
        baseline: PathBuf,
    }

    impl Tree {
        fn new(slug: &str, version: &str, files: &[(&str, &[u8])]) -> Tree {
            let t = tempfile::tempdir().expect("tmp");
            let base = t.path().canonicalize().expect("canonical");
            let root = base.join("htdocs");
            let tree = Tree {
                cache: base.join("manifests"),
                baseline: base.join("baselines").join("7"),
                root,
                _t: t,
            };
            tree.write("wp-load.php", b"<?php // load\n");
            tree.write("wp-settings.php", b"<?php // settings\n");
            tree.write("wp-config.php", b"<?php // config\n");
            tree.write(
                "wp-includes/version.php",
                b"<?php\n$wp_version = '6.8.1';\n",
            );
            let main = format!("<?php\n/*\nPlugin Name: {slug}\nVersion: {version}\n*/\n");
            tree.write(
                &format!("wp-content/plugins/{slug}/{slug}.php"),
                main.as_bytes(),
            );
            for (name, body) in files {
                tree.write(&format!("wp-content/plugins/{slug}/{name}"), body);
            }
            tree
        }

        fn write(&self, rel: &str, body: &[u8]) {
            let p = self.root.join(rel);
            fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            fs::write(p, body).expect("write");
        }

        fn scan(&self) -> crate::sitescan::scan::SiteScanOutcome {
            let root = TenantRoot::open(&self.root).expect("open");
            let input = ScanInput {
                root: self.root.clone(),
                discovery: discover(&root),
                manifests_dir: self.cache.clone(),
                baseline_path: self.baseline.clone(),
                mode: ScanMode::Delta,
                now: 1_800_000_000,
                wporg_known_slugs: Some(Default::default()),
                accepted: None,
                own_expected: BTreeMap::new(),
                own_files_since: 0,
                trusted: BTreeMap::new(),
                carried_rels: Vec::new(),
            };
            scan_site(&input, &|| false).expect("scan")
        }
    }

    #[tokio::test]
    async fn added_file_is_review_changed_file_is_finding() {
        let files: [(&str, &[u8]); 1] = [("a.php", b"<?php // a\n")];
        let tree = Tree::new("pro", "1.0", &files);
        let fake = Fake::new(vec![Answer::Body(plugin_zip_bytes("pro", "1.0", &files))]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        fetch_with(&fake, &p, SITE_A, &tree.cache, SystemTime::now())
            .await
            .expect("fetch");

        let out = tree.scan();
        assert_eq!(out.coverage.plugins_verified, 1);
        assert!(out.findings.is_empty(), "{:?}", out.findings);

        tree.write("wp-content/plugins/pro/a.php", b"<?php // tampered\n");
        tree.write("wp-content/plugins/pro/generated.php", b"<?php // gen\n");
        let out = tree.scan();
        let changed: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.rel == "wp-content/plugins/pro/a.php")
            .collect();
        assert_eq!(changed.len(), 1, "{:?}", out.findings);
        assert_eq!(changed[0].kind, FindingKind::UpstreamModified);
        assert_eq!(changed[0].source_label.as_deref(), Some("vendor package"));
        assert!(
            out.review
                .iter()
                .any(|f| f.rel == "wp-content/plugins/pro/generated.php"),
            "{:?}",
            out.review
        );
        assert!(!out
            .findings
            .iter()
            .any(|f| f.rel == "wp-content/plugins/pro/generated.php"));
    }

    #[tokio::test]
    async fn no_update_verifies_current_version_response_only_prepares_next() {
        let tree = Tree::new("pro", "1.0", &[]);
        let now = SystemTime::now();
        let candidates = [key("pro", "1.0")];

        // Only the next version on offer: cached, and this site is no better off.
        let next = vec![refs_for(
            "pro",
            Some("2.0"),
            PackageBucket::Response,
            &elementor_url("n"),
        )];
        let plan = plan_for(next, &candidates, SITE_A, &tree.cache, now);
        assert_eq!(plan.fetch.len(), 1);
        assert!(!plan.fetch[0].verifies_today);
        let fake = Fake::new(vec![
            Answer::Body(plugin_zip_bytes("pro", "2.0", &[])),
            Answer::Body(plugin_zip_bytes("pro", "1.0", &[])),
        ]);
        fetch_with(&fake, &plan.fetch[0], SITE_A, &tree.cache, now)
            .await
            .expect("fetch");
        assert!(cached(&tree.cache, "pro", "2.0").exists());
        assert_eq!(tree.scan().coverage.plugins_verified, 0);

        // A no_update entry for what it runs verifies it.
        let today = vec![refs_for(
            "pro",
            Some("1.0"),
            PackageBucket::NoUpdate,
            &elementor_url("t"),
        )];
        let plan = plan_for(today, &candidates, SITE_A, &tree.cache, now);
        assert!(plan.fetch[0].verifies_today);
        fetch_with(&fake, &plan.fetch[0], SITE_A, &tree.cache, now)
            .await
            .expect("fetch");
        assert_eq!(tree.scan().coverage.plugins_verified, 1);
    }

    #[test]
    fn a_no_update_entry_for_another_version_is_not_fetched() {
        let t = tempfile::tempdir().expect("tmp");
        let stale = vec![refs_for(
            "pro",
            Some("0.9"),
            PackageBucket::NoUpdate,
            &elementor_url("s"),
        )];
        let plan = plan_for(
            stale,
            &[key("pro", "1.0")],
            SITE_A,
            t.path(),
            SystemTime::now(),
        );
        assert!(plan.fetch.is_empty());
    }

    /// Everywhere on the node, until forgotten: a difference is a change to review
    /// with that label, and a rule hit is still a finding.
    #[tokio::test]
    async fn a_disputed_version_labels_differences_for_review() {
        let files: [(&str, &[u8]); 1] = [("a.php", b"<?php // a\n")];
        let tree = Tree::new("pro", "1.0", &files);
        let other: [(&str, &[u8]); 1] = [("a.php", b"<?php // other\n")];
        let fake = Fake::new(vec![
            Answer::Body(plugin_zip_bytes("pro", "1.0", &files)),
            Answer::Body(plugin_zip_bytes("pro", "1.0", &other)),
        ]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let now = SystemTime::now();
        fetch_with(&fake, &p, SITE_A, &tree.cache, now)
            .await
            .expect("first");
        tree.write("wp-content/plugins/pro/a.php", b"<?php // tampered\n");
        let out = tree.scan();
        let before = out
            .upstream
            .plugins_failed
            .iter()
            .find(|c| c.slug == "pro")
            .expect("failed");
        assert_eq!(
            before.source.as_deref(),
            Some(hyperion_types::VENDOR_PACKAGE_LABEL)
        );

        fetch_with(&fake, &p, SITE_B, &tree.cache, now)
            .await
            .expect("second");
        let out = tree.scan();
        let item = out
            .findings
            .iter()
            .find(|f| f.rel == "wp-content/plugins/pro/a.php")
            .expect("item");
        assert_eq!(
            item.source_label.as_deref(),
            Some(hyperion_types::PACKAGES_DISAGREE_LABEL)
        );
        let failed = out
            .upstream
            .plugins_failed
            .iter()
            .find(|c| c.slug == "pro")
            .expect("failed");
        assert_eq!(
            failed.source.as_deref(),
            Some(hyperion_types::PACKAGES_DISAGREE_LABEL)
        );
    }

    /// A forgotten manifest and a different one under the same version: what the
    /// old one verified isn't verified by the new one.
    #[tokio::test]
    async fn a_replaced_manifest_doesnt_inherit_what_the_old_one_verified() {
        let files: [(&str, &[u8]); 1] = [("a.php", b"<?php // a\n")];
        let tree = Tree::new("pro", "1.0", &files);
        let other: [(&str, &[u8]); 1] = [("a.php", b"<?php // other\n")];
        let fake = Fake::new(vec![
            Answer::Body(plugin_zip_bytes("pro", "1.0", &files)),
            Answer::Body(plugin_zip_bytes("pro", "1.0", &other)),
        ]);
        let p = planned("pro", "1.0", PackageBucket::NoUpdate, &elementor_url("p"));
        let now = SystemTime::now();
        fetch_with(&fake, &p, SITE_A, &tree.cache, now)
            .await
            .expect("first");
        assert!(tree.scan().findings.is_empty());
        forget_package(&tree.cache, &key("pro", "1.0")).expect("forget");
        fetch_with(&fake, &p, SITE_A, &tree.cache, now)
            .await
            .expect("again");
        let out = tree.scan();
        assert!(
            out.findings
                .iter()
                .any(|f| f.rel == "wp-content/plugins/pro/a.php"),
            "compared with the new one: {:?}",
            out.findings
        );
    }

    #[test]
    fn coverage_counts_what_a_vendor_verified_apart() {
        let tree = Tree::new("pro", "1.0", &[]);
        let path = cached(&tree.cache, "pro", "1.0");
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        let main = "<?php\n/*\nPlugin Name: pro\nVersion: 1.0\n*/\n";
        let digest = crate::sitescan::manifest::Digest::Sha256(Sha256::digest(main).into());
        let m = Manifest {
            source: ManifestSource::VendorPackage,
            files: [("pro.php".to_string(), digest)].into(),
            served_locale: None,
        };
        fs::write(&path, serde_json::to_vec(&m).expect("json")).expect("write");
        let c = tree.scan().coverage;
        assert_eq!(c.plugins_verified, 1);
        assert_eq!(c.plugins_vendor_verified, 1);
        assert_eq!(c.themes_vendor_verified, 0);
    }
}
