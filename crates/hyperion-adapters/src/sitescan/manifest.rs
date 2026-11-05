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

use super::discover::{
    header_field, plugin_candidates, Field, HEADER_BYTES, MAX_PLUGIN_CANDIDATES,
};
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
    /// Core only: the locale whose checksums these are. It differs from the
    /// key's locale when wordpress.org had none for it and en_US stood in, and
    /// translated files are then not comparable.
    #[serde(default)]
    pub served_locale: Option<String>,
}

impl Manifest {
    /// Built from en_US checksums for a key that asked for another locale.
    pub fn is_locale_fallback(&self, key: &ComponentKey) -> bool {
        key.kind == ComponentKind::Core
            && key.locale.is_some()
            && self.served_locale.as_deref() != key.locale.as_deref()
    }
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
    cache_path_for(cache_dir, key, ManifestSource::WordPressOrg)
}

/// Like [`cache_path`] for a manifest of `source`. Vendor packages live under
/// `vendor/` so they can never stand in for (or be overwritten by) upstream's.
pub fn cache_path_for(
    cache_dir: &Path,
    key: &ComponentKey,
    source: ManifestSource,
) -> Result<PathBuf, AdapterError> {
    check_key(key)?;
    let mut name = key.version.clone();
    if let Some(l) = &key.locale {
        name.push('@');
        name.push_str(l);
    }
    let base = match source {
        ManifestSource::WordPressOrg => cache_dir.to_path_buf(),
        ManifestSource::VendorPackage => cache_dir.join("vendor"),
    };
    Ok(base
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
/// A cached answer nothing has read for this long is dropped.
const EVICT_AFTER: Duration = Duration::from_secs(90 * 24 * 3600);
/// Reading a manifest marks it read at most this often: each mark is a write.
const MARK_READ_EVERY: Duration = Duration::from_secs(24 * 3600);
/// `<kind>/<slug>/<file>` and `slugs/<kind>/<file>`.
const CACHE_DEPTH: usize = 3;

fn md5_of(hex_str: &str, what: &str) -> Result<[u8; 16], AdapterError> {
    hex_array::<16>(hex_str)
        .ok_or_else(|| AdapterError::Other(format!("bad md5 for {what} in checksums")))
}

/// A manifest key is a path below the component root. It is only compared, but
/// a hostile or broken answer must not carry names that mean something else.
pub fn rel_path_ok(p: &str) -> bool {
    let b = p.as_bytes();
    !(p.is_empty()
        || p.contains('\\')
        || p.contains('\0')
        || p.starts_with('/')
        || (b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic())
        || p.split('/').any(|c| c.is_empty() || c == "." || c == ".."))
}

fn checked_path<'a>(what: &str, p: &'a str) -> Result<&'a str, AdapterError> {
    if rel_path_ok(p) {
        Ok(p)
    } else {
        Err(AdapterError::Other(format!(
            "{what}: refusing path {:?}",
            p.chars().take(80).collect::<String>()
        )))
    }
}

/// `{"checksums":{"<path>":"<md5>",...}}`. `None` when wordpress.org has no
/// checksums for this version and locale (it answers `{"checksums":false}`).
/// An empty list is an error, not "nothing to check".
pub fn parse_core_checksums(json: &str) -> Result<Option<BTreeMap<String, Digest>>, AdapterError> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| AdapterError::Other(format!("core checksums: {e}")))?;
    match v.get("checksums") {
        Some(serde_json::Value::Bool(false)) | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Object(map)) => {
            let mut files = BTreeMap::new();
            for (path, val) in map {
                checked_path("core checksums", path)?;
                let h = val
                    .as_str()
                    .ok_or_else(|| AdapterError::Other("core checksums: non-string hash".into()))?;
                files.insert(path.clone(), Digest::Md5(md5_of(h, path)?));
            }
            if files.is_empty() {
                return Err(AdapterError::Other("core checksums: empty list".into()));
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
        checked_path("plugin checksums", path)?;
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
    if out.is_empty() {
        return Err(bad("empty list"));
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
    /// Size of the ZIP file itself.
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_entries: usize,
}

impl Default for ZipLimits {
    fn default() -> Self {
        ZipLimits {
            max_file_bytes: MAX_THEME_ZIP_BYTES,
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

/// The most entries any end-of-central-directory record in the file could make
/// the zip crate read, found without parsing a directory.
///
/// The crate is lenient, so this is deliberately wider than one record:
/// - it falls back to earlier `PK\5\6` candidates when later ones fail, so the
///   whole file is searched (one streaming pass), not just the tail;
/// - on the zip32 path it uses the entries-on-this-disk field, not the total,
///   so the larger of the two counts;
/// - it switches to zip64 when the total is 0xFFFF OR the directory offset is
///   0xFFFFFFFF, and may find the zip64 record away from where the locator
///   says (prepended data), so every `PK\6\6` record counts, and a saturated
///   field with no zip64 record at all is refused. A package within our size
///   and entry caps never needs zip64, so this costs no real package.
fn declared_entry_count(file: &mut std::fs::File, size: u64) -> Result<u64, AdapterError> {
    use std::io::{Seek, SeekFrom};
    const EOCD_LEN: usize = 22;
    const EOCD64_LEN: usize = 56;
    // A candidate starting in the last CARRY bytes of a chunk is handled with
    // the next one, when all of it is in the buffer.
    const CARRY: usize = EOCD64_LEN - 1;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = file.take(size);
    let mut chunk = vec![0u8; 1024 * 1024];
    let mut buf: Vec<u8> = Vec::with_capacity(chunk.len() + CARRY);
    let (mut count, mut candidates) = (0u64, 0u64);
    let (mut saturated, mut zip64) = (false, None::<u64>);
    loop {
        let n = reader.read(&mut chunk)?;
        let last = n == 0;
        buf.extend_from_slice(&chunk[..n]);
        let limit = if last {
            buf.len()
        } else {
            buf.len().saturating_sub(CARRY)
        };
        let mut i = 0;
        while i < limit {
            let Some(off) = buf[i..limit].iter().position(|&b| b == b'P') else {
                break;
            };
            i += off;
            let rest = &buf[i..];
            if rest.starts_with(b"PK\x05\x06") && rest.len() >= EOCD_LEN {
                candidates += 1;
                let on_disk = u16::from_le_bytes([rest[8], rest[9]]);
                let total = u16::from_le_bytes([rest[10], rest[11]]);
                let dir_offset = u32::from_le_bytes([rest[16], rest[17], rest[18], rest[19]]);
                count = count.max(on_disk as u64).max(total as u64);
                saturated |= on_disk == u16::MAX || total == u16::MAX || dir_offset == u32::MAX;
            } else if rest.starts_with(b"PK\x06\x06") && rest.len() >= EOCD64_LEN {
                let le = |at: usize| {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&rest[at..at + 8]);
                    u64::from_le_bytes(b)
                };
                zip64 = Some(zip64.unwrap_or(0).max(le(24)).max(le(32)));
            }
            i += 1;
        }
        if last {
            break;
        }
        buf.drain(..limit);
    }
    if candidates == 0 {
        return Err(zip_err("no end-of-central-directory record"));
    }
    if saturated {
        let z = zip64.ok_or_else(|| zip_err("zip64 fields without a zip64 record"))?;
        count = count.max(z);
    }
    Ok(count)
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
    let trimmed = name.strip_suffix('/').unwrap_or(name);
    if !rel_path_ok(trimmed) {
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
    let mut file = std::fs::File::open(path)?;
    // Before the zip crate parses the central directory, whose size is
    // proportional to the entry count a file declares: measured, a 55 MB ZIP
    // of a million entries costs over 500 MB to open.
    let size = file.metadata()?.len();
    if size > limits.max_file_bytes {
        return Err(zip_err("file over the size cap"));
    }
    let declared = declared_entry_count(&mut file, size)?;
    if declared > limits.max_entries as u64 {
        return Err(zip_err(format!(
            "declares more than {} entries",
            limits.max_entries
        )));
    }
    let mut archive = zip::ZipArchive::new(file).map_err(zip_err)?;
    // The crate collapses entries with the same name, so this can only be
    // lower than the declared count; it is the bound the loops below use.
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
            // Defensive: the crate already merges equal names.
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
    Ok(Manifest {
        source,
        files,
        served_locale: None,
    })
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
            for n in plugin_candidates(&expected.slug, names)
                .into_iter()
                .take(MAX_PLUGIN_CANDIDATES)
            {
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

/// A cached upstream manifest and how old it is. Anything that isn't a usable
/// wordpress.org manifest (another source, no files, unreadable) is a miss.
fn read_cached(path: &Path, now: SystemTime) -> Option<(Manifest, Duration)> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_JSON_BYTES {
        return None;
    }
    let m: Manifest = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    if m.source != ManifestSource::WordPressOrg || m.files.is_empty() {
        return None;
    }
    let age = now
        .duration_since(meta.modified().ok()?)
        .unwrap_or(Duration::ZERO);
    Some((m, age))
}

fn miss_is_fresh(marker: &Path, now: SystemTime) -> bool {
    std::fs::metadata(marker)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| now.duration_since(t).ok())
        .is_some_and(|age| age < MISS_TTL)
}

/// The HTTP access `fetch_wporg_manifest` needs, so the fallback and cache
/// rules can be tested without a network.
#[async_trait::async_trait]
trait Http: Sync {
    /// GET `url`: the body, or `None` for a 404. Anything else that isn't a
    /// 200 is an error, so an outage is never read as "nothing there".
    async fn get(&self, url: &str, max_bytes: u64) -> Result<Option<Vec<u8>>, AdapterError>;
}

struct Curl<'a> {
    cache_dir: &'a Path,
}

#[async_trait::async_trait]
impl Http for Curl<'_> {
    async fn get(&self, url: &str, max_bytes: u64) -> Result<Option<Vec<u8>>, AdapterError> {
        get_body(url, self.cache_dir, max_bytes).await
    }
}

/// The manifest wordpress.org implies for `key`, from the cache or the
/// network. `Ok(None)` is "wordpress.org has nothing for this" (unverifiable;
/// cached for 24 h), including a key no wordpress.org URL could hold (a
/// tenant picks its slug and version). A network failure is `Err` and is
/// never cached. A core manifest built from en_US for another locale carries
/// `served_locale` and is looked up again after 24 h.
pub async fn fetch_wporg_manifest(
    key: &ComponentKey,
    cache_dir: &Path,
) -> Result<Option<Manifest>, AdapterError> {
    fetch_with(&Curl { cache_dir }, key, cache_dir, SystemTime::now()).await
}

/// What the cache can say about `key` with no network, for a caller counting what
/// it spends. `None` means only [`fetch_wporg_manifest`] can tell; `Some(None)`
/// means wordpress.org has nothing, including for a key no URL could hold.
pub fn cached_wporg_manifest(key: &ComponentKey, cache_dir: &Path) -> Option<Option<Manifest>> {
    let Ok(path) = cache_path(cache_dir, key) else {
        return Some(None);
    };
    local_answer(key, &path, SystemTime::now())
}

/// The cached answer that is still good, and the mark that keeps it cached. A
/// locale fallback isn't marked: its age is what sends it back to wordpress.org.
fn local_answer(key: &ComponentKey, path: &Path, now: SystemTime) -> Option<Option<Manifest>> {
    if let Some((m, age)) = read_cached(path, now) {
        let fallback = m.is_locale_fallback(key);
        if !fallback && age >= MARK_READ_EVERY {
            mark_read(path, now);
        }
        if !(fallback && age >= MISS_TTL) {
            return Some(Some(m));
        }
    }
    miss_is_fresh(&miss_path(path), now).then_some(None)
}

/// The worker reads manifests through a read-only mount, so the agent's lookup
/// before each scan is what says one is in use. A mark that fails costs at worst
/// a download.
fn mark_read(path: &Path, now: SystemTime) {
    let _ = std::fs::File::options()
        .write(true)
        .open(path)
        .and_then(|f| f.set_modified(now));
}

/// Drop what nothing has read for [`EVICT_AFTER`], with folders left empty.
/// Returns the number of files removed. Vendor packages stay: nothing can fetch
/// those again.
pub fn evict_stale_manifests(cache_dir: &Path, now: SystemTime) -> usize {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.file_name() != "vendor")
        .map(|e| evict_entry(&e.path(), now, CACHE_DEPTH))
        .sum()
}

fn evict_entry(path: &Path, now: SystemTime, depth: usize) -> usize {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.is_dir() {
        if depth == 0 {
            return 0;
        }
        let swept = std::fs::read_dir(path).map_or(0, |entries| {
            entries
                .flatten()
                .map(|e| evict_entry(&e.path(), now, depth - 1))
                .sum()
        });
        // Fails unless it's empty, which is the point.
        let _ = std::fs::remove_dir(path);
        return swept;
    }
    let stale = meta.is_file()
        && meta
            .modified()
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age >= EVICT_AFTER);
    usize::from(stale && std::fs::remove_file(path).is_ok())
}

async fn fetch_with(
    http: &dyn Http,
    key: &ComponentKey,
    cache_dir: &Path,
    now: SystemTime,
) -> Result<Option<Manifest>, AdapterError> {
    let Ok(path) = cache_path(cache_dir, key) else {
        return Ok(None);
    };
    if let Some(answer) = local_answer(key, &path, now) {
        return Ok(answer);
    }
    let marker = miss_path(&path);
    let fetched = match key.kind {
        ComponentKind::Core => fetch_core(http, key).await?,
        ComponentKind::Plugin => {
            let url = format!(
                "https://downloads.wordpress.org/plugin-checksums/{}/{}.json",
                key.slug, key.version
            );
            match http.get(&url, MAX_JSON_BYTES).await? {
                None => None,
                Some(body) => Some(Manifest {
                    source: ManifestSource::WordPressOrg,
                    files: parse_plugin_checksums(&String::from_utf8_lossy(&body))?,
                    served_locale: None,
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

/// Core checksums for the key's locale, else en_US (marked in
/// `served_locale`). Only a definite "no checksums" answer falls back; a
/// network failure is an error.
async fn fetch_core(http: &dyn Http, key: &ComponentKey) -> Result<Option<Manifest>, AdapterError> {
    for locale in core_locale_chain(key.locale.as_deref()) {
        let url = format!(
            "https://api.wordpress.org/core/checksums/1.0/?version={}&locale={locale}",
            key.version
        );
        let Some(body) = http.get(&url, MAX_JSON_BYTES).await? else {
            continue;
        };
        if let Some(files) = parse_core_checksums(&String::from_utf8_lossy(&body))? {
            return Ok(Some(Manifest {
                source: ManifestSource::WordPressOrg,
                files,
                served_locale: Some(locale),
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
    if std::fs::metadata(tmp.path())?.len() > MAX_THEME_ZIP_BYTES {
        return Err(AdapterError::Other("theme package too large".into()));
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

/// What wordpress.org's info answer means for a slug. A body that names the
/// slug, or says the plugin is closed (live: HTTP 404 with
/// `{"error":"closed","slug":...}`), means it is known, whatever the status.
/// Only a recognised "not found" answer is `false`; anything else is an error,
/// so an outage or a changed API is never read as "premium".
pub fn interpret_slug_info(
    kind: ComponentKind,
    status: u16,
    body: &str,
) -> Result<bool, AdapterError> {
    let bad = |m: &str| AdapterError::Other(format!("wordpress.org {} info: {m}", kind.as_str()));
    if status != 200 && status != 404 {
        return Err(bad(&format!("HTTP {status}")));
    }
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(o)) => {
            let error = o.get("error").and_then(|e| e.as_str()).unwrap_or("");
            if o.get("slug").is_some_and(|s| s.is_string())
                || o.get("closed").and_then(|c| c.as_bool()) == Some(true)
                || error.eq_ignore_ascii_case("closed")
            {
                Ok(true)
            } else if error.to_ascii_lowercase().contains("not found") {
                Ok(false)
            } else {
                Err(bad("unrecognised answer"))
            }
        }
        Ok(serde_json::Value::Null | serde_json::Value::Bool(false)) if status == 200 => Ok(false),
        Err(_) if status == 404 && body.trim().is_empty() => Ok(false),
        _ => Err(bad("unrecognised answer")),
    }
}

/// True when wordpress.org lists a plugin or theme with this slug (a closed
/// one counts). Cached per slug for 7 days; a network failure is `Err`, never
/// `false`. A slug that can't be a wordpress.org slug (the tenant names its
/// folder) is `false`.
pub async fn wporg_slug_known(
    kind: ComponentKind,
    slug: &str,
    cache_dir: &Path,
) -> Result<bool, AdapterError> {
    if kind == ComponentKind::Core {
        return Err(refuse_key("kind", "core"));
    }
    if !valid_slug(slug) {
        return Ok(false);
    }
    let url = if kind == ComponentKind::Plugin {
        format!("https://api.wordpress.org/plugins/info/1.0/{slug}.json")
    } else {
        format!("https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={slug}")
    };
    let cache = slug_cache_path(cache_dir, kind, slug);
    let now = unix_now();
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

/// [`wporg_slug_known`]'s answer when it needs no network. `None` means only a
/// lookup can tell.
pub fn cached_slug_known(kind: ComponentKind, slug: &str, cache_dir: &Path) -> Option<bool> {
    if kind == ComponentKind::Core {
        return None;
    }
    if !valid_slug(slug) {
        return Some(false);
    }
    read_slug_cache(&slug_cache_path(cache_dir, kind, slug), unix_now())
}

fn slug_cache_path(cache_dir: &Path, kind: ComponentKind, slug: &str) -> PathBuf {
    cache_dir
        .join("slugs")
        .join(kind.as_str())
        .join(format!("{slug}.json"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
            served_locale: Some("en_US".into()),
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
            max_file_bytes: u64::MAX,
            max_total_bytes: 1024 * 1024,
            max_entries: 100,
        };
        assert!(manifest_from_zip_with(&zp, &k, ManifestSource::VendorPackage, small).is_err());
        let few = ZipLimits {
            max_file_bytes: u64::MAX,
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
        assert!(
            !interpret_slug_info(p, 404, r#"{"error":"Plugin not found."}"#).expect("not found")
        );
        assert!(!interpret_slug_info(p, 200, "null").expect("null"));
        assert!(!interpret_slug_info(t, 200, "false").expect("false"));
        assert!(!interpret_slug_info(t, 404, "").expect("empty 404"));
        assert!(!interpret_slug_info(t, 200, r#"{"error":"Theme not found"}"#).expect("error"));
        assert!(interpret_slug_info(t, 200, r#"{"slug":"twentytwentyfour"}"#).expect("known"));
        // Live: a plugin closed for security answers 404 with its slug. It is
        // known to wordpress.org, not premium.
        let closed = r#"{"error":"closed","slug":"display-widgets","name":"Display Widgets","closed":true,"reason":"security-issue"}"#;
        assert!(interpret_slug_info(p, 404, closed).expect("closed 404"));
        assert!(interpret_slug_info(p, 200, closed).expect("closed 200"));
        assert!(interpret_slug_info(p, 404, r#"{"error":"closed"}"#).expect("closed, no slug"));
        // Not recognised: never "unknown slug".
        assert!(interpret_slug_info(p, 200, r#"{"error":"Rate limited"}"#).is_err());
        assert!(interpret_slug_info(p, 404, r#"{"error":"Maintenance"}"#).is_err());
        assert!(interpret_slug_info(p, 503, "").is_err());
        assert!(interpret_slug_info(p, 200, "<html>").is_err());
        assert!(interpret_slug_info(p, 404, "<html>").is_err());
        assert!(interpret_slug_info(p, 200, r#"{"foo":1}"#).is_err());
        assert!(interpret_slug_info(p, 404, "null").is_err());
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
            served_locale: None,
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

    fn demo_manifest() -> Manifest {
        Manifest {
            source: ManifestSource::WordPressOrg,
            files: BTreeMap::from([("a.php".to_string(), Digest::Md5([1; 16]))]),
            served_locale: None,
        }
    }

    fn mtime(p: &Path) -> SystemTime {
        std::fs::metadata(p)
            .expect("meta")
            .modified()
            .expect("mtime")
    }

    fn set_mtime(p: &Path, t: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(p)
            .expect("open")
            .set_modified(t)
            .expect("set mtime");
    }

    #[test]
    fn cached_answer_says_what_needs_no_network() {
        let t = tempfile::tempdir().expect("tmp");
        let k = key(ComponentKind::Plugin, "demo", "1.0");
        assert_eq!(cached_wporg_manifest(&k, t.path()), None, "nothing known");

        let path = cache_path(t.path(), &k).expect("path");
        let m = demo_manifest();
        write_atomic(&path, &serde_json::to_vec(&m).expect("ser")).expect("write");
        assert_eq!(cached_wporg_manifest(&k, t.path()), Some(Some(m)));

        let gone = key(ComponentKind::Plugin, "gone", "1.0");
        let p = cache_path(t.path(), &gone).expect("path");
        write_atomic(&miss_path(&p), b"").expect("marker");
        assert_eq!(cached_wporg_manifest(&gone, t.path()), Some(None));
        // A stale miss is worth asking again.
        set_mtime(
            &miss_path(&p),
            SystemTime::now() - MISS_TTL - Duration::from_secs(60),
        );
        assert_eq!(cached_wporg_manifest(&gone, t.path()), None);

        // A key no URL could hold costs nothing: a tenant picks its slug.
        let bad = key(ComponentKind::Plugin, "../evil", "1.0");
        assert_eq!(cached_wporg_manifest(&bad, t.path()), Some(None));
        let unversioned = key(ComponentKind::Plugin, "demo", "");
        assert_eq!(cached_wporg_manifest(&unversioned, t.path()), Some(None));
    }

    #[test]
    fn cached_slug_answer_needs_no_network() {
        let t = tempfile::tempdir().expect("tmp");
        assert_eq!(
            cached_slug_known(ComponentKind::Plugin, "demo", t.path()),
            None
        );
        assert_eq!(
            cached_slug_known(ComponentKind::Plugin, "../evil", t.path()),
            Some(false)
        );
        let f = t.path().join("slugs/plugin/demo.json");
        std::fs::create_dir_all(f.parent().expect("parent")).expect("mkdir");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        std::fs::write(&f, format!(r#"{{"known":true,"checked_at":{now}}}"#)).expect("w");
        assert_eq!(
            cached_slug_known(ComponentKind::Plugin, "demo", t.path()),
            Some(true)
        );
    }

    #[test]
    fn reading_a_manifest_marks_it_as_read() {
        let t = tempfile::tempdir().expect("tmp");
        let k = key(ComponentKind::Plugin, "demo", "1.0");
        let path = cache_path(t.path(), &k).expect("path");
        write_atomic(&path, &serde_json::to_vec(&demo_manifest()).expect("ser")).expect("write");
        let long_ago = SystemTime::now() - Duration::from_secs(80 * 24 * 3600);
        set_mtime(&path, long_ago);
        assert!(cached_wporg_manifest(&k, t.path()).is_some());
        assert!(
            mtime(&path) > long_ago + Duration::from_secs(79 * 24 * 3600),
            "read today, so 90 days start again"
        );
    }

    /// A locale fallback's age decides when it is asked for again, so reading
    /// it must not make it look new.
    #[test]
    fn reading_a_locale_fallback_keeps_its_age() {
        let t = tempfile::tempdir().expect("tmp");
        let mut k = key(ComponentKind::Core, "wordpress", "6.6.2");
        k.locale = Some("cs_CZ".to_string());
        let path = cache_path(t.path(), &k).expect("path");
        let mut m = demo_manifest();
        m.served_locale = Some("en_US".to_string());
        write_atomic(&path, &serde_json::to_vec(&m).expect("ser")).expect("write");
        let hours_ago = SystemTime::now() - Duration::from_secs(3 * 3600);
        set_mtime(&path, hours_ago);
        assert!(cached_wporg_manifest(&k, t.path()).is_some());
        let drift = mtime(&path)
            .duration_since(hours_ago)
            .unwrap_or(Duration::ZERO);
        assert!(drift < Duration::from_secs(5), "{drift:?}");
    }

    #[test]
    fn eviction_takes_what_was_not_read_for_ninety_days() {
        let t = tempfile::tempdir().expect("tmp");
        let now = SystemTime::now();
        let old = now - Duration::from_secs(91 * 24 * 3600);
        let write = |rel: &str, when: SystemTime| {
            let p = t.path().join(rel);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(&p, b"{}").expect("write");
            set_mtime(&p, when);
            p
        };
        let stale = write("plugin/old/1.0.json", old);
        let stale_miss = write("plugin/other/1.0.404", old);
        let stale_slug = write("slugs/plugin/old.json", old);
        let stale_temp = write(".tmpABC", old);
        let fresh = write("plugin/live/2.0.json", now);
        let bought = write("vendor/plugin/pro/1.0.json", old);

        assert_eq!(evict_stale_manifests(t.path(), now), 4);

        for gone in [&stale, &stale_miss, &stale_slug, &stale_temp] {
            assert!(!gone.exists(), "{}", gone.display());
        }
        assert!(fresh.exists());
        assert!(
            bought.exists(),
            "a vendor package can't be fetched again: not this sweep's to drop"
        );
        assert!(
            !t.path().join("plugin/old").exists(),
            "emptied folders go too"
        );
        assert!(t.path().join("plugin/live").exists());
        // A cache that isn't there yet is nothing to do.
        assert_eq!(evict_stale_manifests(&t.path().join("none"), now), 0);
    }

    #[cfg(unix)]
    #[test]
    fn eviction_does_not_follow_a_link() {
        let t = tempfile::tempdir().expect("tmp");
        let outside = tempfile::tempdir().expect("tmp");
        let keep = outside.path().join("keep.json");
        std::fs::write(&keep, b"{}").expect("write");
        let old = SystemTime::now() - Duration::from_secs(91 * 24 * 3600);
        set_mtime(&keep, old);
        std::os::unix::fs::symlink(outside.path(), t.path().join("plugin")).expect("link");
        evict_stale_manifests(t.path(), SystemTime::now());
        assert!(keep.exists());
    }

    /// Answers `get` from a closure and records every URL asked for.
    struct Mock {
        calls: std::sync::Mutex<Vec<String>>,
        answer: Box<dyn Fn(&str) -> Result<Option<Vec<u8>>, AdapterError> + Send + Sync>,
    }

    impl Mock {
        fn new(
            answer: impl Fn(&str) -> Result<Option<Vec<u8>>, AdapterError> + Send + Sync + 'static,
        ) -> Mock {
            Mock {
                calls: Default::default(),
                answer: Box::new(answer),
            }
        }
        fn calls(&self) -> usize {
            self.calls.lock().expect("lock").len()
        }
    }

    #[async_trait::async_trait]
    impl Http for Mock {
        async fn get(&self, url: &str, _max: u64) -> Result<Option<Vec<u8>>, AdapterError> {
            self.calls.lock().expect("lock").push(url.to_string());
            (self.answer)(url)
        }
    }

    fn core_json() -> Vec<u8> {
        format!(r#"{{"checksums":{{"wp-login.php":"{MD5_A}"}}}}"#).into_bytes()
    }

    #[tokio::test]
    async fn core_en_us_fallback_is_marked_and_retried_after_a_day() {
        let t = tempfile::tempdir().expect("tmp");
        let mut k = key(ComponentKind::Core, "wordpress", "6.5.3");
        k.locale = Some("cs_CZ".into());
        let now = SystemTime::now();
        let day = Duration::from_secs(24 * 3600);

        // wordpress.org has no cs_CZ checksums yet: en_US stands in, marked.
        let cs_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = cs_ready.clone();
        let mock = Mock::new(move |url| {
            if url.contains("locale=cs_CZ") && !flag.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(Some(br#"{"checksums":false}"#.to_vec()))
            } else {
                Ok(Some(core_json()))
            }
        });
        let m = fetch_with(&mock, &k, t.path(), now)
            .await
            .expect("fetch")
            .expect("manifest");
        assert_eq!(m.served_locale.as_deref(), Some("en_US"));
        assert!(m.is_locale_fallback(&k));
        assert_eq!(mock.calls(), 2);

        // Within a day the fallback is served from the cache.
        fetch_with(&mock, &k, t.path(), now + Duration::from_secs(3600))
            .await
            .expect("cached");
        assert_eq!(mock.calls(), 2);

        // After a day it is looked up again, and once cs_CZ exists it sticks.
        cs_ready.store(true, std::sync::atomic::Ordering::SeqCst);
        let m = fetch_with(&mock, &k, t.path(), now + day + Duration::from_secs(60))
            .await
            .expect("refetch")
            .expect("manifest");
        assert_eq!(mock.calls(), 3);
        assert_eq!(m.served_locale.as_deref(), Some("cs_CZ"));
        assert!(!m.is_locale_fallback(&k));
        let years = Duration::from_secs(3 * 365 * 24 * 3600);
        fetch_with(&mock, &k, t.path(), now + years)
            .await
            .expect("cached");
        assert_eq!(mock.calls(), 3);
    }

    #[tokio::test]
    async fn core_fallback_only_on_a_definite_answer() {
        let t = tempfile::tempdir().expect("tmp");
        let mut k = key(ComponentKind::Core, "wordpress", "6.5.3");
        k.locale = Some("cs_CZ".into());
        let mock = Mock::new(|url| {
            if url.contains("locale=cs_CZ") {
                Err(AdapterError::Other("timeout".into()))
            } else {
                Ok(Some(core_json()))
            }
        });
        assert!(fetch_with(&mock, &k, t.path(), SystemTime::now())
            .await
            .is_err());
        assert_eq!(mock.calls(), 1);

        // No locale: en_US is simply the answer, not a fallback.
        let plain = key(ComponentKind::Core, "wordpress", "6.5.3");
        let mock = Mock::new(|_| Ok(Some(core_json())));
        let m = fetch_with(&mock, &plain, t.path(), SystemTime::now())
            .await
            .expect("fetch")
            .expect("manifest");
        assert!(!m.is_locale_fallback(&plain));
    }

    #[tokio::test]
    async fn refused_keys_are_unverifiable_not_errors() {
        let t = tempfile::tempdir().expect("tmp");
        let mock = Mock::new(|_| Err(AdapterError::Other("must not be called".into())));
        for (slug, ver) in [
            ("MyPlugin", "1.0"),
            ("demo", "1.0 beta"),
            ("demo", ""),
            ("../x", "1"),
        ] {
            let k = key(ComponentKind::Plugin, slug, ver);
            let got = fetch_with(&mock, &k, t.path(), SystemTime::now()).await;
            assert_eq!(got.expect("not an error"), None, "{slug:?} {ver:?}");
            assert!(!wporg_slug_known(ComponentKind::Plugin, slug, t.path())
                .await
                .expect("not an error"));
        }
        assert_eq!(mock.calls(), 0);
    }

    #[tokio::test]
    async fn vendor_manifest_is_never_served_as_upstream() {
        let t = tempfile::tempdir().expect("tmp");
        let k = key(ComponentKind::Plugin, "demo", "1.0");
        let vendor = Manifest {
            source: ManifestSource::VendorPackage,
            files: BTreeMap::from([("x.php".to_string(), Digest::Md5([1; 16]))]),
            served_locale: None,
        };
        let bytes = serde_json::to_vec(&vendor).expect("ser");
        // Even planted at the upstream path it is a miss...
        write_atomic(&cache_path(t.path(), &k).expect("path"), &bytes).expect("write");
        let json = format!(r#"{{"files":{{"a.php":{{"md5":"{MD5_A}"}}}}}}"#);
        let mock = Mock::new(move |_| Ok(Some(json.clone().into_bytes())));
        let m = fetch_with(&mock, &k, t.path(), SystemTime::now())
            .await
            .expect("fetch")
            .expect("manifest");
        assert_eq!(m.source, ManifestSource::WordPressOrg);
        assert!(m.files.contains_key("a.php"));
        assert_eq!(mock.calls(), 1);
        // ...and vendor manifests have their own place.
        let up = cache_path(t.path(), &k).expect("path");
        let ven = cache_path_for(t.path(), &k, ManifestSource::VendorPackage).expect("path");
        assert_ne!(up, ven);
        assert!(ven.starts_with(t.path().join("vendor")));
    }

    #[test]
    fn empty_and_hostile_manifests_are_refused() {
        assert!(parse_core_checksums(r#"{"checksums":{}}"#).is_err());
        assert!(parse_plugin_checksums(r#"{"files":{}}"#).is_err());
        for bad in ["../x", "/etc/x", "a/../b", "a//b", "a\\b", "C:x", ""] {
            let core = format!(r#"{{"checksums":{{{bad:?}:"{MD5_A}"}}}}"#);
            assert!(parse_core_checksums(&core).is_err(), "core {bad:?}");
            let plugin = format!(r#"{{"files":{{{bad:?}:{{"md5":"{MD5_A}"}}}}}}"#);
            assert!(parse_plugin_checksums(&plugin).is_err(), "plugin {bad:?}");
        }
        assert!(rel_path_ok("wp-admin/index.php"));
        // An empty manifest on disk is a cache miss, not a verdict.
        let t = tempfile::tempdir().expect("tmp");
        let p = t.path().join("m.json");
        let empty = Manifest {
            source: ManifestSource::WordPressOrg,
            files: BTreeMap::new(),
            served_locale: None,
        };
        std::fs::write(&p, serde_json::to_vec(&empty).expect("ser")).expect("w");
        assert!(read_cached(&p, SystemTime::now()).is_none());
    }

    #[test]
    fn entry_count_is_read_from_the_end_record_before_parsing() {
        let t = tempfile::tempdir().expect("tmp");
        let k = key(ComponentKind::Plugin, "demo", "1.2.3");
        let zp = make_zip(t.path(), &[("demo/demo.php", PLUGIN_HEAD)]);
        let mut bytes = std::fs::read(&zp).expect("read");
        let n = bytes.len();
        // A small file whose end record claims 60,000 entries.
        bytes[n - 14..n - 12].copy_from_slice(&60_000u16.to_le_bytes());
        bytes[n - 12..n - 10].copy_from_slice(&60_000u16.to_le_bytes());
        let lying = t.path().join("lying.zip");
        std::fs::write(&lying, &bytes).expect("w");
        let err = manifest_from_zip(&lying, &k, ManifestSource::VendorPackage).expect_err("cap");
        assert!(err.to_string().contains("more than"), "{err}");
        // The honest file is fine, and its count is read right.
        let mut f = std::fs::File::open(&zp).expect("open");
        assert_eq!(declared_entry_count(&mut f, n as u64).expect("count"), 1);
        manifest_from_zip(&zp, &k, ManifestSource::VendorPackage).expect("honest");
    }

    #[test]
    fn zip64_entry_count_is_checked_too() {
        let t = tempfile::tempdir().expect("tmp");
        let mut b = Vec::new();
        // zip64 end record: total entries (offset 32) = 1,000,000.
        b.extend_from_slice(b"PK\x06\x06");
        b.extend_from_slice(&44u64.to_le_bytes());
        b.extend_from_slice(&[45, 0, 45, 0]);
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&1_000_000u64.to_le_bytes());
        b.extend_from_slice(&1_000_000u64.to_le_bytes());
        b.extend_from_slice(&[0; 16]);
        assert_eq!(b.len(), 56);
        // locator pointing at it, then the end record with 0xFFFF counts.
        b.extend_from_slice(b"PK\x06\x07");
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(b"PK\x05\x06");
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&0xFFFFu16.to_le_bytes());
        b.extend_from_slice(&0xFFFFu16.to_le_bytes());
        b.extend_from_slice(&[0; 10]);
        let p = t.path().join("z64.zip");
        std::fs::write(&p, &b).expect("w");
        let mut f = std::fs::File::open(&p).expect("open");
        assert_eq!(
            declared_entry_count(&mut f, b.len() as u64).expect("count"),
            1_000_000
        );
        let k = key(ComponentKind::Plugin, "demo", "1");
        let err = manifest_from_zip(&p, &k, ManifestSource::VendorPackage).expect_err("cap");
        assert!(err.to_string().contains("more than"), "{err}");
        // Not a zip at all.
        std::fs::write(&p, b"hello").expect("w");
        assert!(manifest_from_zip(&p, &k, ManifestSource::VendorPackage).is_err());
    }

    #[test]
    fn zip_file_over_the_size_cap_is_refused() {
        let t = tempfile::tempdir().expect("tmp");
        let zp = make_zip(t.path(), &[("demo/demo.php", PLUGIN_HEAD)]);
        let k = key(ComponentKind::Plugin, "demo", "1.2.3");
        let tiny = ZipLimits {
            max_file_bytes: 10,
            ..ZipLimits::default()
        };
        let err = manifest_from_zip_with(&zp, &k, ManifestSource::VendorPackage, tiny)
            .expect_err("size cap");
        assert!(err.to_string().contains("size cap"), "{err}");
    }

    /// An end-of-central-directory record.
    fn eocd(on_disk: u16, total: u16, dir_offset: u32) -> Vec<u8> {
        let mut b = b"PK\x05\x06\0\0\0\0".to_vec();
        b.extend_from_slice(&on_disk.to_le_bytes());
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&dir_offset.to_le_bytes());
        b.extend_from_slice(&[0; 2]);
        assert_eq!(b.len(), 22);
        b
    }

    /// A zip64 end-of-central-directory record claiming `count` entries.
    fn eocd64(count: u64) -> Vec<u8> {
        let mut b = b"PK\x06\x06".to_vec();
        b.extend_from_slice(&44u64.to_le_bytes());
        b.extend_from_slice(&[45, 0, 45, 0]);
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&count.to_le_bytes());
        b.extend_from_slice(&count.to_le_bytes());
        b.extend_from_slice(&[0; 16]);
        assert_eq!(b.len(), 56);
        b
    }

    /// The count `manifest_from_zip` sees for these bytes, as the error text.
    fn refused(t: &Path, bytes: &[u8]) -> String {
        let p = t.join("crafted.zip");
        std::fs::write(&p, bytes).expect("w");
        manifest_from_zip(
            &p,
            &key(ComponentKind::Plugin, "demo", "1.2.3"),
            ManifestSource::VendorPackage,
        )
        .expect_err("must be refused")
        .to_string()
    }

    #[test]
    fn crafted_counts_are_refused_before_the_crate_parses_anything() {
        let t = tempfile::tempdir().expect("tmp");
        // "declares" is our pre-check; the crate's own messages never say it,
        // so this shows the file was refused before `ZipArchive::new`.
        let pre = |bytes: &[u8]| {
            let e = refused(t.path(), bytes);
            assert!(e.contains("declares more than"), "{e}");
        };
        // (a) small 16-bit counts, offset saturated, zip64 record says 1M.
        let mut b = eocd64(1_000_000);
        b.extend(eocd(3, 3, u32::MAX));
        pre(&b);
        // ... with a locator in front as a writer would put it.
        let mut b = eocd64(1_000_000);
        b.extend_from_slice(b"PK\x06\x07\0\0\0\0");
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend(eocd(3, 3, u32::MAX));
        pre(&b);
        // (b) mismatched 16-bit fields, either way round.
        pre(&eocd(60_000, 1, 0));
        pre(&eocd(1, 60_000, 0));
        // total saturated with the big count only in the zip64 record.
        let mut b = eocd64(1_000_000);
        b.extend(eocd(0xFFFF, 0xFFFF, 0));
        pre(&b);
        // (c) a later, small-looking record does not hide an earlier big one,
        // and the reverse.
        let mut b = eocd(60_000, 60_000, 0);
        b.extend(eocd(1, 1, 0));
        pre(&b);
        let mut b = eocd(1, 1, 0);
        b.extend(eocd(60_000, 60_000, 0));
        pre(&b);
        // a record that straddles a read chunk boundary is still seen.
        let mut b = vec![0u8; 1024 * 1024 - 10];
        b.extend(eocd(60_000, 60_000, 0));
        pre(&b);
        let mut b = vec![0u8; 1024 * 1024 - 30];
        b.extend(eocd64(1_000_000));
        b.extend(eocd(1, 1, u32::MAX));
        pre(&b);
    }

    #[test]
    fn saturated_field_without_a_zip64_record_is_refused() {
        let t = tempfile::tempdir().expect("tmp");
        for b in [eocd(3, 0xFFFF, 0), eocd(0xFFFF, 3, 0), eocd(3, 3, u32::MAX)] {
            let e = refused(t.path(), &b);
            assert!(e.contains("zip64"), "{e}");
        }
    }

    #[test]
    fn tiny_and_empty_files_do_not_panic() {
        let t = tempfile::tempdir().expect("tmp");
        for len in [0usize, 1, 4, 5, 11, 21] {
            let mut b = b"PK\x05\x06".to_vec();
            b.resize(len, 0);
            b.truncate(len);
            let e = refused(t.path(), &b);
            assert!(e.contains("end-of-central-directory"), "{len}: {e}");
        }
        // And a 4-byte zip64 signature with nothing after it.
        let e = refused(t.path(), b"PK\x06\x06");
        assert!(e.contains("end-of-central-directory"), "{e}");
    }

    #[test]
    fn honest_counts_pass_the_precheck() {
        let t = tempfile::tempdir().expect("tmp");
        let zp = make_zip(
            t.path(),
            &[("demo/demo.php", PLUGIN_HEAD), ("demo/a.php", b"<?php")],
        );
        let n = std::fs::metadata(&zp).expect("meta").len();
        let mut f = std::fs::File::open(&zp).expect("open");
        assert_eq!(declared_entry_count(&mut f, n).expect("count"), 2);
    }
}
