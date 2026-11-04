//! Upstream manifests: what wordpress.org (or a vendor package) says each file
//! of a core, plugin or theme release hashes to.
//!
//! Slug, version and locale come from tenant files, so they are validated
//! before they reach a URL or a cache path. The cache directory is root-owned;
//! `cache_path`'s validation is what keeps a tenant's `Version:` header from
//! choosing where root writes.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use md5::Md5;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use super::discover::{header_field, plugin_candidates, Field, HEADER_BYTES};
use crate::AdapterError;

/// Files a site legitimately edits (a readme is rewritten by translation
/// plugins and hand edits); a difference in them is not a finding. Relative to
/// the component root, compared case-insensitively.
const SOFT_FILES: [&str; 2] = ["readme.txt", "readme.md"];

/// True for a file whose content difference from upstream is not a finding.
pub fn is_soft_file(rel: &str) -> bool {
    SOFT_FILES.iter().any(|s| rel.eq_ignore_ascii_case(s))
}

/// What one upstream file hashes to. wordpress.org publishes core as MD5 and
/// plugins as MD5 and/or SHA-256, and may list several acceptable values for
/// one file, so the `*Any` forms hold alternatives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Digest {
    Md5([u8; 16]),
    Sha256([u8; 32]),
    Md5Any(Vec<[u8; 16]>),
    Sha256Any(Vec<[u8; 32]>),
}

impl Digest {
    /// Stream `r` through the algorithm this digest uses and say whether the
    /// result is one of the accepted values.
    pub fn matches_reader(&self, mut r: impl Read) -> std::io::Result<bool> {
        let mut buf = [0u8; 64 * 1024];
        match self {
            Digest::Md5(_) | Digest::Md5Any(_) => {
                let mut h = Md5::new();
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                let got: [u8; 16] = h.finalize().into();
                Ok(match self {
                    Digest::Md5(d) => *d == got,
                    Digest::Md5Any(v) => v.contains(&got),
                    _ => false,
                })
            }
            Digest::Sha256(_) | Digest::Sha256Any(_) => {
                let mut h = Sha256::new();
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                let got: [u8; 32] = h.finalize().into();
                Ok(match self {
                    Digest::Sha256(d) => *d == got,
                    Digest::Sha256Any(v) => v.contains(&got),
                    _ => false,
                })
            }
        }
    }
}

// Stored as `md5:<hex>[,<hex>...]` / `sha256:<hex>[,...]`: a cached core
// manifest has thousands of entries, and byte arrays in JSON cost three times
// the space.
impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (alg, hexes): (&str, Vec<String>) = match self {
            Digest::Md5(d) => ("md5", vec![hex::encode(d)]),
            Digest::Md5Any(v) => ("md5", v.iter().map(hex::encode).collect()),
            Digest::Sha256(d) => ("sha256", vec![hex::encode(d)]),
            Digest::Sha256Any(v) => ("sha256", v.iter().map(hex::encode).collect()),
        };
        s.serialize_str(&format!("{alg}:{}", hexes.join(",")))
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let bad = || serde::de::Error::custom(format!("bad digest {raw:?}"));
        let (alg, list) = raw.split_once(':').ok_or_else(bad)?;
        match alg {
            "md5" => digest_list::<16>(list)
                .map(|v| pack(v, Digest::Md5, Digest::Md5Any))
                .ok_or_else(bad),
            "sha256" => digest_list::<32>(list)
                .map(|v| pack(v, Digest::Sha256, Digest::Sha256Any))
                .ok_or_else(bad),
            _ => Err(bad()),
        }
    }
}

/// `a,b,c` of fixed-width hex values; None when any is malformed or the list
/// is empty.
fn digest_list<const N: usize>(list: &str) -> Option<Vec<[u8; N]>> {
    let v: Option<Vec<[u8; N]>> = list.split(',').map(hex_array::<N>).collect();
    v.filter(|v| !v.is_empty())
}

fn hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

fn pack<const N: usize>(
    mut v: Vec<[u8; N]>,
    one: fn([u8; N]) -> Digest,
    many: fn(Vec<[u8; N]>) -> Digest,
) -> Digest {
    if v.len() == 1 {
        one(v.remove(0))
    } else {
        many(v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestSource {
    WordPressOrg,
    VendorPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub source: ManifestSource,
    /// Path relative to the component root (core: the docroot).
    #[serde(default)]
    pub files: BTreeMap<String, Digest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentKind {
    Core,
    Plugin,
    Theme,
}

impl ComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ComponentKind::Core => "core",
            ComponentKind::Plugin => "plugin",
            ComponentKind::Theme => "theme",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ComponentKey {
    pub kind: ComponentKind,
    /// Core is `wordpress`.
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub version: String,
    /// Core only: `$wp_local_package` (`cs_CZ`); None is en_US.
    #[serde(default)]
    pub locale: Option<String>,
}

// The patterns are constants and the tests below use every one of them, so a
// compile failure is caught by the suite, never in production.
#[allow(clippy::expect_used)]
static SLUG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,127}$").expect("slug regex"));
// A leading letter or digit keeps `.` and `..` out of a path component.
#[allow(clippy::expect_used)]
static VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$").expect("version regex"));
#[allow(clippy::expect_used)]
static LOCALE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z]{2,3}(_[A-Za-z0-9]{2,8}){0,2}$").expect("locale regex"));

pub fn valid_slug(s: &str) -> bool {
    SLUG_RE.is_match(s)
}

pub fn valid_version(s: &str) -> bool {
    VERSION_RE.is_match(s)
}

pub fn valid_locale(s: &str) -> bool {
    LOCALE_RE.is_match(s)
}

fn refuse_key(what: &str, value: &str) -> AdapterError {
    AdapterError::Other(format!(
        "refusing manifest key: bad {what} {:?}",
        value.chars().take(40).collect::<String>()
    ))
}

fn check_key(key: &ComponentKey) -> Result<(), AdapterError> {
    if !valid_slug(&key.slug) {
        return Err(refuse_key("slug", &key.slug));
    }
    if !valid_version(&key.version) {
        return Err(refuse_key("version", &key.version));
    }
    if let Some(l) = &key.locale {
        if !valid_locale(l) {
            return Err(refuse_key("locale", l));
        }
    }
    Ok(())
}

/// Where the manifest for `key` is cached:
/// `<cache_dir>/<kind>/<slug>/<version>[@<locale>].json`. Fails for a slug,
/// version or locale that could be anything but a plain file name.
pub fn cache_path(cache_dir: &Path, key: &ComponentKey) -> Result<PathBuf, AdapterError> {
    check_key(key)?;
    let mut name = key.version.clone();
    if let Some(l) = &key.locale {
        name.push('@');
        name.push_str(l);
    }
    Ok(cache_dir
        .join(key.kind.as_str())
        .join(&key.slug)
        .join(format!("{name}.json")))
}

/// The marker left when wordpress.org had nothing for `key`.
fn miss_path(manifest_path: &Path) -> PathBuf {
    manifest_path.with_extension("404")
}

/// How long "wordpress.org has nothing for this" is believed.
const MISS_TTL: Duration = Duration::from_secs(24 * 3600);
/// How long "wordpress.org knows / doesn't know this slug" is believed.
const SLUG_TTL_SECS: u64 = 7 * 24 * 3600;

fn md5_of(hex_str: &str, what: &str) -> Result<[u8; 16], AdapterError> {
    hex_array::<16>(hex_str)
        .ok_or_else(|| AdapterError::Other(format!("bad md5 for {what} in checksums")))
}

/// `{"checksums":{"<path>":"<md5>",...}}`. `None` when wordpress.org has no
/// checksums for this version and locale (it answers `{"checksums":false}`).
pub fn parse_core_checksums(json: &str) -> Result<Option<BTreeMap<String, Digest>>, AdapterError> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| AdapterError::Other(format!("core checksums: {e}")))?;
    match v.get("checksums") {
        Some(serde_json::Value::Bool(false)) | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Object(map)) => {
            let mut files = BTreeMap::new();
            for (path, val) in map {
                let h = val
                    .as_str()
                    .ok_or_else(|| AdapterError::Other("core checksums: non-string hash".into()))?;
                files.insert(path.clone(), Digest::Md5(md5_of(h, path)?));
            }
            Ok(Some(files))
        }
        _ => Err(AdapterError::Other(
            "core checksums: unexpected answer".into(),
        )),
    }
}

/// A hash field that is one string or a list of strings.
fn hash_strings(v: &serde_json::Value) -> Option<Vec<&str>> {
    match v {
        serde_json::Value::String(s) => Some(vec![s.as_str()]),
        serde_json::Value::Array(a) => a.iter().map(|x| x.as_str()).collect(),
        _ => None,
    }
}

/// `{"files":{"<path>":{"md5":"…"|[…],"sha256":"…"|[…]}}}`. SHA-256 wins when
/// both are given.
pub fn parse_plugin_checksums(json: &str) -> Result<BTreeMap<String, Digest>, AdapterError> {
    let bad = |m: &str| AdapterError::Other(format!("plugin checksums: {m}"));
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| bad(&e.to_string()))?;
    let files = v
        .get("files")
        .and_then(|f| f.as_object())
        .ok_or_else(|| bad("no files"))?;
    let mut out = BTreeMap::new();
    for (path, entry) in files {
        let sha = entry.get("sha256").and_then(hash_strings).map(|l| {
            l.into_iter()
                .map(hex_array::<32>)
                .collect::<Option<Vec<_>>>()
        });
        let digest = match sha {
            Some(Some(list)) if !list.is_empty() => pack(list, Digest::Sha256, Digest::Sha256Any),
            Some(_) => return Err(bad("malformed sha256")),
            None => {
                let list = entry.get("md5").and_then(hash_strings).map(|l| {
                    l.into_iter()
                        .map(hex_array::<16>)
                        .collect::<Option<Vec<_>>>()
                });
                match list {
                    Some(Some(list)) if !list.is_empty() => pack(list, Digest::Md5, Digest::Md5Any),
                    _ => return Err(bad("file without a usable hash")),
                }
            }
        };
        out.insert(path.clone(), digest);
    }
    Ok(out)
}

/// Locales to ask wordpress.org for, in order. A localized release has its own
/// checksums only when wordpress.org built them, so en_US is the fallback.
pub fn core_locale_chain(locale: Option<&str>) -> Vec<String> {
    match locale {
        Some(l) if l != "en_US" => vec![l.to_string(), "en_US".to_string()],
        _ => vec!["en_US".to_string()],
    }
}

/// Caps for reading a ZIP: the package is attacker-influenced (a vendor URL
/// comes from the site's database).
#[derive(Debug, Clone, Copy)]
pub struct ZipLimits {
    pub max_total_bytes: u64,
    pub max_entries: usize,
}

impl Default for ZipLimits {
    fn default() -> Self {
        ZipLimits {
            max_total_bytes: 512 * 1024 * 1024,
            max_entries: 50_000,
        }
    }
}

/// Build a manifest from a plugin or theme ZIP: SHA-256 of every file,
/// streamed, nothing written to disk. The ZIP's single top-level folder is
/// stripped so paths are relative to the component root. The version in the
/// package's own header must equal `expected.version`.
pub fn manifest_from_zip(
    path: &Path,
    expected: &ComponentKey,
    source: ManifestSource,
) -> Result<Manifest, AdapterError> {
    manifest_from_zip_with(path, expected, source, ZipLimits::default())
}

fn zip_err(m: impl std::fmt::Display) -> AdapterError {
    AdapterError::Other(format!("zip: {m}"))
}

/// An entry name checked for anything that could name a place outside the
/// package, split into the top-level folder and the path below it. None for
/// entries to ignore (`__MACOSX`).
fn split_entry_name(name: &str) -> Result<Option<(&str, &str)>, AdapterError> {
    let bad = || {
        zip_err(format!(
            "refusing entry name {:?}",
            name.chars().take(80).collect::<String>()
        ))
    };
    let b = name.as_bytes();
    if name.contains('\\') || name.contains('\0') || name.starts_with('/') {
        return Err(bad());
    }
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return Err(bad());
    }
    let trimmed = name.strip_suffix('/').unwrap_or(name);
    if trimmed
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(bad());
    }
    let (top, rest) = match trimmed.split_once('/') {
        Some(split) => split,
        // The top-level folder's own entry.
        None if trimmed.len() < name.len() => (trimmed, ""),
        None => return Err(zip_err("file outside the top-level folder")),
    };
    if top == "__MACOSX" {
        return Ok(None);
    }
    Ok(Some((top, rest)))
}

pub(crate) fn manifest_from_zip_with(
    path: &Path,
    expected: &ComponentKey,
    source: ManifestSource,
    limits: ZipLimits,
) -> Result<Manifest, AdapterError> {
    if expected.kind == ComponentKind::Core {
        return Err(zip_err("core has no package manifest"));
    }
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file).map_err(zip_err)?;
    if archive.len() > limits.max_entries {
        return Err(zip_err(format!("more than {} entries", limits.max_entries)));
    }
    // Declared sizes first: a package that announces more than the cap is
    // refused before anything is decompressed.
    let mut declared_total = 0u64;
    for i in 0..archive.len() {
        let f = archive.by_index_raw(i).map_err(zip_err)?;
        declared_total = declared_total.saturating_add(f.size());
    }
    if declared_total > limits.max_total_bytes {
        return Err(zip_err("uncompressed size over the cap"));
    }

    let mut top_dir: Option<String> = None;
    let mut files: BTreeMap<String, Digest> = BTreeMap::new();
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    let mut actual_total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(zip_err)?;
        let name = entry.name().to_string();
        let Some((top, rest)) = split_entry_name(&name)? else {
            continue;
        };
        match &top_dir {
            None => top_dir = Some(top.to_string()),
            Some(t) if t == top => {}
            Some(_) => return Err(zip_err("more than one top-level folder")),
        }
        if entry.is_dir() {
            continue;
        }
        // A link entry would be written by an extractor as a link.
        if entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            continue;
        }
        let declared = entry.size();
        let mut hasher = Sha256::new();
        let mut got = 0u64;
        // Never trust the declared size to bound the read.
        let mut limited = (&mut entry).take(declared.saturating_add(1));
        loop {
            let n = limited.read(&mut buf).map_err(zip_err)?;
            if n == 0 {
                break;
            }
            got += n as u64;
            actual_total += n as u64;
            if got > declared || actual_total > limits.max_total_bytes {
                return Err(zip_err("entry larger than allowed"));
            }
            hasher.update(&buf[..n]);
        }
        if files
            .insert(rest.to_string(), Digest::Sha256(hasher.finalize().into()))
            .is_some()
        {
            return Err(zip_err("duplicate entry"));
        }
        index.insert(rest.to_string(), i);
    }
    if files.is_empty() {
        return Err(zip_err("no files"));
    }

    let found = package_version(&mut archive, &index, expected)?;
    if found != expected.version {
        return Err(AdapterError::Other(format!(
            "package header version {:?} does not match {:?}",
            found.chars().take(64).collect::<String>(),
            expected.version
        )));
    }
    Ok(Manifest { source, files })
}

/// The `Version:` the package's own header declares.
fn package_version(
    archive: &mut zip::ZipArchive<std::fs::File>,
    index: &BTreeMap<String, usize>,
    expected: &ComponentKey,
) -> Result<String, AdapterError> {
    let mut head = |rel: &str| -> Result<Vec<u8>, AdapterError> {
        let i = index
            .get(rel)
            .ok_or_else(|| zip_err("missing header file"))?;
        let f = archive.by_index(*i).map_err(zip_err)?;
        let mut v = Vec::new();
        f.take(HEADER_BYTES).read_to_end(&mut v).map_err(zip_err)?;
        Ok(v)
    };
    match expected.kind {
        ComponentKind::Theme => {
            let h = head("style.css")?;
            header_field(&h, Field::ThemeName)
                .ok_or_else(|| zip_err("style.css has no Theme Name"))?;
            header_field(&h, Field::Version).ok_or_else(|| zip_err("style.css has no Version"))
        }
        _ => {
            let names: Vec<String> = index
                .keys()
                .filter(|k| !k.contains('/') && k.ends_with(".php"))
                .cloned()
                .collect();
            for n in plugin_candidates(&expected.slug, names) {
                let h = head(&n)?;
                if header_field(&h, Field::PluginName).is_some() {
                    return header_field(&h, Field::Version)
                        .ok_or_else(|| zip_err("plugin header has no Version"));
                }
            }
            Err(zip_err("no plugin header"))
        }
    }
}

// ---- fetching ----

const CURL: &str = "/usr/bin/curl";
const MAX_JSON_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INFO_BYTES: u64 = 8 * 1024 * 1024;
const MAX_THEME_ZIP_BYTES: u64 = 256 * 1024 * 1024;

/// One HTTPS GET with curl into `dest`. Returns the HTTP status; a transport
/// failure (DNS, timeout, size cap) is an error. The URL is built by the
/// caller from validated parts only.
async fn curl_get(
    url: &str,
    dest: &Path,
    max_bytes: u64,
    max_secs: u32,
) -> Result<u16, AdapterError> {
    let out = tokio::process::Command::new(CURL)
        .kill_on_drop(true)
        .args([
            "-sS",
            "--globoff",
            "-L",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
        ])
        .args(["--max-redirs", "3", "--connect-timeout", "15"])
        .args(["--max-time", &max_secs.to_string()])
        .args(["--max-filesize", &max_bytes.to_string()])
        .args(["-A", "hyperion-sitescan"])
        .arg("-o")
        .arg(dest)
        .args(["-w", "%{http_code}"])
        .arg(url)
        .output()
        .await?;
    if !out.status.success() {
        let tail = String::from_utf8_lossy(&out.stderr);
        return Err(AdapterError::Command {
            cmd: "curl (wordpress.org)".into(),
            code: out.status.code().unwrap_or(-1),
            stderr_tail: tail.trim().chars().take(200).collect(),
        });
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u16>()
        .map_err(|_| AdapterError::Other("curl gave no HTTP status".into()))
}

/// A temp file in `<cache_dir>/.tmp`, removed when dropped.
fn temp_in(cache_dir: &Path) -> Result<tempfile::NamedTempFile, AdapterError> {
    let dir = cache_dir.join(".tmp");
    std::fs::create_dir_all(&dir)?;
    Ok(tempfile::NamedTempFile::new_in(dir)?)
}

/// GET `url` and return the body; `None` for a 404. Any other non-200 is an
/// error, so an outage is never read as "nothing there".
async fn get_body(
    url: &str,
    cache_dir: &Path,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, AdapterError> {
    let tmp = temp_in(cache_dir)?;
    let status = curl_get(url, tmp.path(), max_bytes, 60).await?;
    match status {
        200 => {
            let mut body = Vec::new();
            std::fs::File::open(tmp.path())?
                .take(max_bytes + 1)
                .read_to_end(&mut body)?;
            if body.len() as u64 > max_bytes {
                return Err(AdapterError::Other("wordpress.org answer too large".into()));
            }
            Ok(Some(body))
        }
        404 => Ok(None),
        s => Err(AdapterError::Other(format!(
            "wordpress.org answered HTTP {s}"
        ))),
    }
}

/// Write `bytes` to `path` through a temp file and a rename, so a reader never
/// sees half a manifest.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AdapterError> {
    let dir = path
        .parent()
        .ok_or_else(|| AdapterError::Other("cache path has no parent".into()))?;
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.persist(path).map_err(|e| AdapterError::Io(e.error))?;
    Ok(())
}

fn read_cached(path: &Path) -> Option<Manifest> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_JSON_BYTES {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn miss_is_fresh(marker: &Path) -> bool {
    std::fs::metadata(marker)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < MISS_TTL)
}

/// The manifest wordpress.org implies for `key`, from the cache or the
/// network. `Ok(None)` is "wordpress.org has nothing for this slug and
/// version" (unverifiable, cached for 24 h); a network failure is `Err` and
/// is never cached.
pub async fn fetch_wporg_manifest(
    key: &ComponentKey,
    cache_dir: &Path,
) -> Result<Option<Manifest>, AdapterError> {
    let path = cache_path(cache_dir, key)?;
    if let Some(m) = read_cached(&path) {
        return Ok(Some(m));
    }
    let marker = miss_path(&path);
    if miss_is_fresh(&marker) {
        return Ok(None);
    }
    let fetched = match key.kind {
        ComponentKind::Core => fetch_core(key, cache_dir).await?,
        ComponentKind::Plugin => {
            let url = format!(
                "https://downloads.wordpress.org/plugin-checksums/{}/{}.json",
                key.slug, key.version
            );
            match get_body(&url, cache_dir, MAX_JSON_BYTES).await? {
                None => None,
                Some(body) => Some(Manifest {
                    source: ManifestSource::WordPressOrg,
                    files: parse_plugin_checksums(&String::from_utf8_lossy(&body))?,
                }),
            }
        }
        ComponentKind::Theme => fetch_theme(key, cache_dir).await?,
    };
    match &fetched {
        Some(m) => {
            let json = serde_json::to_vec(m).map_err(|e| AdapterError::Other(e.to_string()))?;
            write_atomic(&path, &json)?;
            let _ = std::fs::remove_file(&marker);
        }
        None => write_atomic(&marker, b"")?,
    }
    Ok(fetched)
}

async fn fetch_core(
    key: &ComponentKey,
    cache_dir: &Path,
) -> Result<Option<Manifest>, AdapterError> {
    for locale in core_locale_chain(key.locale.as_deref()) {
        let url = format!(
            "https://api.wordpress.org/core/checksums/1.0/?version={}&locale={locale}",
            key.version
        );
        let Some(body) = get_body(&url, cache_dir, MAX_JSON_BYTES).await? else {
            continue;
        };
        if let Some(files) = parse_core_checksums(&String::from_utf8_lossy(&body))? {
            return Ok(Some(Manifest {
                source: ManifestSource::WordPressOrg,
                files,
            }));
        }
    }
    Ok(None)
}

/// wordpress.org publishes no theme checksums: download the release ZIP, hash
/// it, drop it.
async fn fetch_theme(
    key: &ComponentKey,
    cache_dir: &Path,
) -> Result<Option<Manifest>, AdapterError> {
    let url = format!(
        "https://downloads.wordpress.org/theme/{}.{}.zip",
        key.slug, key.version
    );
    let tmp = temp_in(cache_dir)?;
    match curl_get(&url, tmp.path(), MAX_THEME_ZIP_BYTES, 300).await? {
        200 => {}
        404 => return Ok(None),
        s => {
            return Err(AdapterError::Other(format!(
                "wordpress.org answered HTTP {s}"
            )))
        }
    }
    let zip_path = tmp.path().to_path_buf();
    let key = key.clone();
    // Hashing a large package is CPU and disk work: off the async threads.
    let m = tokio::task::spawn_blocking(move || {
        let r = manifest_from_zip(&zip_path, &key, ManifestSource::WordPressOrg);
        drop(tmp);
        r
    })
    .await
    .map_err(|e| AdapterError::Other(e.to_string()))??;
    Ok(Some(m))
}

// ---- does wordpress.org know this slug? ----

/// What wordpress.org's info answer means for a slug. 404 and "not found"
/// bodies are `false`; anything that is not clearly one or the other is an
/// error, so an outage or a changed API is never read as "premium".
pub fn interpret_slug_info(
    kind: ComponentKind,
    status: u16,
    body: &str,
) -> Result<bool, AdapterError> {
    let bad = |m: &str| AdapterError::Other(format!("wordpress.org {} info: {m}", kind.as_str()));
    match status {
        404 => return Ok(false),
        200 => {}
        s => return Err(bad(&format!("HTTP {s}"))),
    }
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| bad(&e.to_string()))?;
    match &v {
        serde_json::Value::Null | serde_json::Value::Bool(false) => Ok(false),
        serde_json::Value::Object(o) if o.contains_key("error") => Ok(false),
        serde_json::Value::Object(o) if o.get("slug").is_some_and(|s| s.is_string()) => Ok(true),
        _ => Err(bad("unrecognised answer")),
    }
}

/// True when wordpress.org lists a plugin or theme with this slug. Cached per
/// slug for 7 days; a network failure is `Err`, never `false`.
pub async fn wporg_slug_known(
    kind: ComponentKind,
    slug: &str,
    cache_dir: &Path,
) -> Result<bool, AdapterError> {
    if kind == ComponentKind::Core {
        return Err(refuse_key("kind", "core"));
    }
    if !valid_slug(slug) {
        return Err(refuse_key("slug", slug));
    }
    let url = if kind == ComponentKind::Plugin {
        format!("https://api.wordpress.org/plugins/info/1.0/{slug}.json")
    } else {
        format!("https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={slug}")
    };
    let cache = cache_dir
        .join("slugs")
        .join(kind.as_str())
        .join(format!("{slug}.json"));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if let Some(known) = read_slug_cache(&cache, now) {
        return Ok(known);
    }
    let tmp = temp_in(cache_dir)?;
    let status = curl_get(&url, tmp.path(), MAX_INFO_BYTES, 60).await?;
    let mut body = Vec::new();
    std::fs::File::open(tmp.path())?
        .take(MAX_INFO_BYTES)
        .read_to_end(&mut body)?;
    let known = interpret_slug_info(kind, status, &String::from_utf8_lossy(&body))?;
    let stamp = serde_json::json!({ "known": known, "checked_at": now });
    write_atomic(&cache, stamp.to_string().as_bytes())?;
    Ok(known)
}

fn read_slug_cache(path: &Path, now: u64) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let at = v.get("checked_at")?.as_u64()?;
    if now.saturating_sub(at) >= SLUG_TTL_SECS {
        return None;
    }
    v.get("known")?.as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    const MD5_A: &str = "0123456789abcdef0123456789abcdef";
    const MD5_B: &str = "fedcba9876543210fedcba9876543210";
    const SHA_A: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn key(kind: ComponentKind, slug: &str, version: &str) -> ComponentKey {
        ComponentKey {
            kind,
            slug: slug.into(),
            version: version.into(),
            locale: None,
        }
    }

    fn make_zip(dir: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
        let p = dir.join("pkg.zip");
        let mut w = zip::ZipWriter::new(std::fs::File::create(&p).expect("create"));
        for (name, body) in entries {
            w.start_file(*name, SimpleFileOptions::default())
                .expect("start");
            w.write_all(body).expect("write");
        }
        w.finish().expect("finish");
        p
    }

    const PLUGIN_HEAD: &[u8] = b"<?php\n/*\nPlugin Name: Demo\nVersion: 1.2.3\n*/\n";

    #[test]
    fn core_falls_back_to_en_us_when_locale_has_no_checksums() {
        assert_eq!(core_locale_chain(Some("cs_CZ")), vec!["cs_CZ", "en_US"]);
        assert_eq!(core_locale_chain(Some("en_US")), vec!["en_US"]);
        assert_eq!(core_locale_chain(None), vec!["en_US"]);
        // What wordpress.org answers for a locale it has no checksums for.
        assert_eq!(
            parse_core_checksums(r#"{"checksums":false}"#).expect("parse"),
            None
        );
        let ok = parse_core_checksums(&format!(r#"{{"checksums":{{"wp-login.php":"{MD5_A}"}}}}"#))
            .expect("parse")
            .expect("some");
        assert_eq!(ok.len(), 1);
        assert!(matches!(ok["wp-login.php"], Digest::Md5(_)));
        assert!(parse_core_checksums(r#"{"checksums":{"a":"nothex"}}"#).is_err());
        assert!(parse_core_checksums("<html>").is_err());
    }

    #[test]
    fn plugin_prefers_sha256() {
        let json = format!(
            r#"{{"files":{{"a.php":{{"md5":"{MD5_A}","sha256":"{SHA_A}"}},"b.php":{{"md5":"{MD5_A}"}}}}}}"#
        );
        let f = parse_plugin_checksums(&json).expect("parse");
        assert!(matches!(f["a.php"], Digest::Sha256(_)));
        assert!(matches!(f["b.php"], Digest::Md5(_)));
    }

    #[test]
    fn plugin_md5_array_accepted() {
        let json = format!(r#"{{"files":{{"a.php":{{"md5":["{MD5_A}","{MD5_B}"]}}}}}}"#);
        let f = parse_plugin_checksums(&json).expect("parse");
        let Digest::Md5Any(v) = &f["a.php"] else {
            panic!("expected Md5Any, got {:?}", f["a.php"]);
        };
        assert_eq!(v.len(), 2);
        // Either listed value verifies the file (md5 of "hello" is the second).
        let json = r#"{"files":{"a.php":{"md5":["00000000000000000000000000000000","5d41402abc4b2a76b9719d911017c592"]}}}"#;
        let f = parse_plugin_checksums(json).expect("parse");
        assert!(f["a.php"]
            .matches_reader(Cursor::new(b"hello"))
            .expect("read"));
        assert!(!f["a.php"]
            .matches_reader(Cursor::new(b"other"))
            .expect("read"));
        assert!(parse_plugin_checksums(r#"{"files":{"a.php":{}}}"#).is_err());
        assert!(parse_plugin_checksums(r#"{"nope":1}"#).is_err());
    }

    #[test]
    fn digest_roundtrips_and_matches_content() {
        use md5::Digest as _;
        let md5: [u8; 16] = Md5::digest(b"hello").into();
        let sha: [u8; 32] = Sha256::digest(b"hello").into();
        let cases = [
            Digest::Md5(md5),
            Digest::Sha256(sha),
            Digest::Md5Any(vec![[1; 16], md5]),
            Digest::Sha256Any(vec![sha, [2; 32]]),
        ];
        for d in cases {
            let back: Digest =
                serde_json::from_str(&serde_json::to_string(&d).expect("ser")).expect("de");
            assert_eq!(back, d);
            assert!(d.matches_reader(Cursor::new(b"hello")).expect("read"));
            assert!(!d.matches_reader(Cursor::new(b"hellp")).expect("read"));
        }
        assert!(serde_json::from_str::<Digest>("\"md5:zz\"").is_err());
        assert!(serde_json::from_str::<Digest>("\"crc:00\"").is_err());
    }

    #[test]
    fn manifest_roundtrips_as_json() {
        let m = Manifest {
            source: ManifestSource::VendorPackage,
            files: BTreeMap::from([("a.php".to_string(), Digest::Sha256([7; 32]))]),
        };
        let back: Manifest =
            serde_json::from_str(&serde_json::to_string(&m).expect("ser")).expect("de");
        assert_eq!(back, m);
    }

    #[test]
    fn readme_is_soft_file() {
        assert!(is_soft_file("readme.txt"));
        assert!(is_soft_file("README.md"));
        assert!(!is_soft_file("readme.php"));
        assert!(!is_soft_file("lib/readme.txt"));
        assert!(!is_soft_file("wp-login.php"));
    }

    #[test]
    fn cache_key_rejects_path_chars_in_slug_and_version() {
        let dir = Path::new("/var/lib/hyperion/scan/manifests");
        let ok = cache_path(dir, &key(ComponentKind::Plugin, "akismet", "5.3.1")).expect("ok");
        assert_eq!(ok, dir.join("plugin/akismet/5.3.1.json"));
        let mut cz = key(ComponentKind::Core, "wordpress", "6.5.3");
        cz.locale = Some("cs_CZ".into());
        assert_eq!(
            cache_path(dir, &cz).expect("ok"),
            dir.join("core/wordpress/6.5.3@cs_CZ.json")
        );
        for slug in [
            "../x",
            "a/b",
            "",
            ".",
            "..",
            "A",
            "a b",
            "-x",
            "a\0",
            &"a".repeat(129),
        ] {
            assert!(
                cache_path(dir, &key(ComponentKind::Plugin, slug, "1")).is_err(),
                "slug {slug:?}"
            );
        }
        for ver in [
            "../1",
            "1/2",
            "",
            ".",
            "..",
            "1 2",
            "1\0",
            "-1",
            &"1".repeat(65),
        ] {
            assert!(
                cache_path(dir, &key(ComponentKind::Plugin, "a", ver)).is_err(),
                "version {ver:?}"
            );
        }
        for loc in ["../x", "cs/CZ", "", "c", "cs_CZ_x_y"] {
            let mut k = key(ComponentKind::Core, "wordpress", "6.5");
            k.locale = Some(loc.into());
            assert!(cache_path(dir, &k).is_err(), "locale {loc:?}");
        }
    }

    #[test]
    fn zip_manifest_strips_top_folder_and_hashes() {
        let t = tempfile::tempdir().expect("tmp");
        let zp = make_zip(
            t.path(),
            &[
                ("demo/", b""),
                ("demo/demo.php", PLUGIN_HEAD),
                ("demo/lib/a.php", b"<?php echo 1;"),
                ("__MACOSX/demo/._demo.php", b"junk"),
            ],
        );
        let m = manifest_from_zip(
            &zp,
            &key(ComponentKind::Plugin, "demo", "1.2.3"),
            ManifestSource::VendorPackage,
        )
        .expect("manifest");
        assert_eq!(m.source, ManifestSource::VendorPackage);
        assert_eq!(
            m.files.keys().collect::<Vec<_>>(),
            vec!["demo.php", "lib/a.php"]
        );
        assert!(m.files["lib/a.php"]
            .matches_reader(Cursor::new(b"<?php echo 1;"))
            .expect("read"));
    }

    #[test]
    fn theme_zip_version_comes_from_style_css() {
        let t = tempfile::tempdir().expect("tmp");
        let zp = make_zip(
            t.path(),
            &[
                (
                    "hello-elementor/style.css",
                    b"/*\nTheme Name: Hello\nVersion: 3.0.1\n*/",
                ),
                ("hello-elementor/functions.php", b"<?php"),
            ],
        );
        let k = key(ComponentKind::Theme, "hello-elementor", "3.0.1");
        let m = manifest_from_zip(&zp, &k, ManifestSource::WordPressOrg).expect("manifest");
        assert_eq!(m.files.len(), 2);
        let wrong = key(ComponentKind::Theme, "hello-elementor", "3.0.2");
        assert!(manifest_from_zip(&zp, &wrong, ManifestSource::WordPressOrg).is_err());
    }

    #[test]
    fn zip_with_wrong_version_is_rejected() {
        let t = tempfile::tempdir().expect("tmp");
        let zp = make_zip(t.path(), &[("demo/demo.php", PLUGIN_HEAD)]);
        let err = manifest_from_zip(
            &zp,
            &key(ComponentKind::Plugin, "demo", "9.9.9"),
            ManifestSource::VendorPackage,
        )
        .expect_err("version mismatch");
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn zip_bomb_entry_over_cap_is_rejected() {
        let t = tempfile::tempdir().expect("tmp");
        // 4 MiB of zeros deflates to a few KiB.
        let big = vec![0u8; 4 * 1024 * 1024];
        let zp = make_zip(
            t.path(),
            &[("demo/demo.php", PLUGIN_HEAD), ("demo/big.bin", &big)],
        );
        let k = key(ComponentKind::Plugin, "demo", "1.2.3");
        let small = ZipLimits {
            max_total_bytes: 1024 * 1024,
            max_entries: 100,
        };
        assert!(manifest_from_zip_with(&zp, &k, ManifestSource::VendorPackage, small).is_err());
        let few = ZipLimits {
            max_total_bytes: u64::MAX,
            max_entries: 1,
        };
        assert!(manifest_from_zip_with(&zp, &k, ManifestSource::VendorPackage, few).is_err());
        // Under the caps the same package is fine.
        manifest_from_zip(&zp, &k, ManifestSource::VendorPackage).expect("within defaults");
    }

    #[test]
    fn zip_path_traversal_entry_rejected() {
        let t = tempfile::tempdir().expect("tmp");
        for bad in [
            "demo/../../evil.php",
            "/abs.php",
            "demo/a\\b.php",
            "../demo/x.php",
            "C:/x.php",
            "demo//x.php",
        ] {
            let zp = make_zip(t.path(), &[("demo/demo.php", PLUGIN_HEAD), (bad, b"x")]);
            let r = manifest_from_zip(
                &zp,
                &key(ComponentKind::Plugin, "demo", "1.2.3"),
                ManifestSource::VendorPackage,
            );
            assert!(r.is_err(), "{bad:?} accepted");
        }
        // Files outside one top-level folder are refused too.
        let zp = make_zip(
            t.path(),
            &[("demo/demo.php", PLUGIN_HEAD), ("other/x.php", b"x")],
        );
        assert!(manifest_from_zip(
            &zp,
            &key(ComponentKind::Plugin, "demo", "1.2.3"),
            ManifestSource::VendorPackage
        )
        .is_err());
    }

    #[test]
    fn slug_info_answers() {
        let p = ComponentKind::Plugin;
        let t = ComponentKind::Theme;
        assert!(
            interpret_slug_info(p, 200, r#"{"name":"Akismet","slug":"akismet"}"#).expect("known")
        );
        assert!(!interpret_slug_info(p, 404, r#"{"error":"Plugin not found."}"#).expect("404"));
        assert!(!interpret_slug_info(p, 200, "null").expect("null"));
        assert!(!interpret_slug_info(t, 200, "false").expect("false"));
        assert!(!interpret_slug_info(t, 200, r#"{"error":"Theme not found"}"#).expect("error"));
        assert!(interpret_slug_info(t, 200, r#"{"slug":"twentytwentyfour"}"#).expect("known"));
        // An outage or a changed answer is never "unknown slug".
        assert!(interpret_slug_info(p, 503, "").is_err());
        assert!(interpret_slug_info(p, 200, "<html>").is_err());
        assert!(interpret_slug_info(p, 200, r#"{"foo":1}"#).is_err());
    }

    #[test]
    fn slug_cache_honours_ttl() {
        let t = tempfile::tempdir().expect("tmp");
        let f = t.path().join("a.json");
        std::fs::write(&f, r#"{"known":true,"checked_at":1000}"#).expect("w");
        assert_eq!(read_slug_cache(&f, 1000 + SLUG_TTL_SECS - 1), Some(true));
        assert_eq!(read_slug_cache(&f, 1000 + SLUG_TTL_SECS), None);
        assert_eq!(read_slug_cache(&t.path().join("none.json"), 5), None);
    }

    #[test]
    fn cached_manifest_and_fresh_miss_need_no_network() {
        let t = tempfile::tempdir().expect("tmp");
        let k = key(ComponentKind::Plugin, "demo", "1.0");
        let path = cache_path(t.path(), &k).expect("path");
        let m = Manifest {
            source: ManifestSource::WordPressOrg,
            files: BTreeMap::from([("a.php".to_string(), Digest::Md5([1; 16]))]),
        };
        write_atomic(&path, &serde_json::to_vec(&m).expect("ser")).expect("write");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        let got = rt
            .block_on(fetch_wporg_manifest(&k, t.path()))
            .expect("cached");
        assert_eq!(got, Some(m));

        let k2 = key(ComponentKind::Plugin, "gone", "1.0");
        let p2 = cache_path(t.path(), &k2).expect("path");
        write_atomic(&miss_path(&p2), b"").expect("marker");
        assert_eq!(
            rt.block_on(fetch_wporg_manifest(&k2, t.path()))
                .expect("miss"),
            None
        );
    }
}
