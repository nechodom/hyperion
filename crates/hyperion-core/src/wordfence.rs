//! WordPress vulnerability matching against the Wordfence Intelligence
//! feed (free, no API key).
//!
//! The raw production feed is large (tens of MB), so we fetch it at most
//! once per day, distil it into a slim per-slug index on disk, and match
//! a hosting's installed plugins/themes against that small index on each
//! scan. Matching is best-effort: version ranges in the feed use a
//! dotted-numeric scheme that we compare segment-by-segment.

use hyperion_types::{WpVulnFinding, WpVulnScanResult};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const FEED_URL: &str =
    "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production/";
const CACHE_DIR: &str = "/var/lib/hyperion/cache";
const SLIM_FILE: &str = "/var/lib/hyperion/cache/wordfence-plugins.json";
const RAW_FILE: &str = "/var/lib/hyperion/cache/wordfence-raw.json";
/// Re-fetch when the slim index is older than this.
const TTL_SECS: i64 = 24 * 3600;

// ---- slim on-disk index --------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SlimRange {
    from: String,
    from_incl: bool,
    to: String,
    to_incl: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SlimVuln {
    title: String,
    severity: String,
    cve: String,
    patched_version: String,
    kind: String, // "plugin" | "theme"
    ranges: Vec<SlimRange>,
}

type SlimIndex = HashMap<String, Vec<SlimVuln>>; // slug -> vulns

// ---- raw feed shapes (only the fields we need) ---------------------

#[derive(serde::Deserialize)]
struct WfRecord {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    software: Vec<WfSoftware>,
    #[serde(default)]
    cvss: Option<WfCvss>,
}

#[derive(serde::Deserialize)]
struct WfSoftware {
    #[serde(rename = "type")]
    kind: String,
    slug: String,
    #[serde(default)]
    affected_versions: HashMap<String, WfRange>,
    #[serde(default)]
    patched_versions: Option<String>,
}

#[derive(serde::Deserialize)]
struct WfRange {
    #[serde(default)]
    from_version: String,
    #[serde(default)]
    from_inclusive: bool,
    #[serde(default)]
    to_version: String,
    #[serde(default)]
    to_inclusive: bool,
}

#[derive(serde::Deserialize)]
struct WfCvss {
    #[serde(default)]
    rating: Option<String>,
}

/// A plugin/theme to scan (slug, name, installed version, kind).
pub struct InstalledItem {
    pub slug: String,
    pub name: String,
    pub version: String,
    pub kind: String, // "plugin" | "theme"
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn file_age_secs(path: &Path) -> Option<i64> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some((now_secs() - secs).max(0))
}

/// Compare two dotted version strings segment-by-segment, numerically.
/// Non-numeric leading parts of a segment are parsed as far as they go
/// (e.g. "3" from "3rc1"); a missing segment counts as 0.
fn cmp_version(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let split = |s: &str| -> Vec<u64> {
        s.split(|c| c == '.' || c == '-' || c == '+')
            .map(|seg| {
                let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
                digits.parse::<u64>().unwrap_or(0)
            })
            .collect()
    };
    let av = split(a);
    let bv = split(b);
    let n = av.len().max(bv.len());
    for i in 0..n {
        let x = av.get(i).copied().unwrap_or(0);
        let y = bv.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

fn version_in_range(v: &str, r: &SlimRange) -> bool {
    use std::cmp::Ordering;
    // Lower bound.
    if !r.from.is_empty() && r.from != "*" {
        match cmp_version(v, &r.from) {
            Ordering::Less => return false,
            Ordering::Equal if !r.from_incl => return false,
            _ => {}
        }
    }
    // Upper bound.
    if !r.to.is_empty() && r.to != "*" {
        match cmp_version(v, &r.to) {
            Ordering::Greater => return false,
            Ordering::Equal if !r.to_incl => return false,
            _ => {}
        }
    }
    true
}

/// Fetch + distil the feed into the slim index if the cache is stale.
/// Returns the slim index file's age in seconds on success.
async fn ensure_slim_index() -> Result<i64, String> {
    if let Some(age) = file_age_secs(Path::new(SLIM_FILE)) {
        if age < TTL_SECS {
            return Ok(age);
        }
    }
    // Stale or missing → fetch raw feed.
    std::fs::create_dir_all(CACHE_DIR).map_err(|e| format!("mkdir cache: {e}"))?;
    let raw = PathBuf::from(RAW_FILE);
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args([
            "-fsS",
            "--max-time",
            "120",
            "--max-filesize",
            "209715200", // 200 MB ceiling
            "--proto",
            "=https",
            "-o",
            RAW_FILE,
            FEED_URL,
        ])
        .output()
        .await
        .map_err(|e| format!("curl spawn: {e}"))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&raw);
        return Err(format!(
            "curl exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let bytes = tokio::fs::read(&raw)
        .await
        .map_err(|e| format!("read raw: {e}"))?;
    let records: HashMap<String, WfRecord> =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse feed: {e}"))?;
    let _ = std::fs::remove_file(&raw); // raw is big; drop it

    let mut index: SlimIndex = HashMap::new();
    for (_uuid, rec) in records {
        let severity = rec
            .cvss
            .as_ref()
            .and_then(|c| c.rating.clone())
            .unwrap_or_default()
            .to_lowercase();
        let cve = rec.cve.unwrap_or_default();
        let title = rec.title.unwrap_or_default();
        for sw in rec.software {
            if sw.kind != "plugin" && sw.kind != "theme" {
                continue;
            }
            let ranges: Vec<SlimRange> = sw
                .affected_versions
                .into_values()
                .map(|r| SlimRange {
                    from: r.from_version,
                    from_incl: r.from_inclusive,
                    to: r.to_version,
                    to_incl: r.to_inclusive,
                })
                .collect();
            if ranges.is_empty() {
                continue;
            }
            index.entry(sw.slug.clone()).or_default().push(SlimVuln {
                title: title.clone(),
                severity: severity.clone(),
                cve: cve.clone(),
                patched_version: sw.patched_versions.unwrap_or_default(),
                kind: sw.kind,
                ranges,
            });
        }
    }
    let slim_json = serde_json::to_vec(&index).map_err(|e| format!("ser slim: {e}"))?;
    tokio::fs::write(SLIM_FILE, &slim_json)
        .await
        .map_err(|e| format!("write slim: {e}"))?;
    Ok(0)
}

fn load_slim_index() -> Result<SlimIndex, String> {
    let bytes = std::fs::read(SLIM_FILE).map_err(|e| format!("read slim: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse slim: {e}"))
}

/// Scan installed items against the (cached) Wordfence feed.
pub async fn scan(items: &[InstalledItem]) -> WpVulnScanResult {
    let feed_age = match ensure_slim_index().await {
        Ok(age) => age,
        Err(e) => {
            tracing::warn!(error = %e, "wordfence: feed unavailable");
            return WpVulnScanResult {
                feed_unavailable: true,
                checked: items.len() as i64,
                ..Default::default()
            };
        }
    };
    let index = match load_slim_index() {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = %e, "wordfence: slim index unreadable");
            return WpVulnScanResult {
                feed_unavailable: true,
                checked: items.len() as i64,
                ..Default::default()
            };
        }
    };
    let mut findings = Vec::new();
    for item in items {
        let Some(vulns) = index.get(&item.slug) else {
            continue;
        };
        for v in vulns {
            if v.kind != item.kind {
                continue;
            }
            if v.ranges.iter().any(|r| version_in_range(&item.version, r)) {
                findings.push(WpVulnFinding {
                    slug: item.slug.clone(),
                    name: item.name.clone(),
                    installed_version: item.version.clone(),
                    title: v.title.clone(),
                    severity: if v.severity.is_empty() {
                        "unknown".into()
                    } else {
                        v.severity.clone()
                    },
                    cve: v.cve.clone(),
                    patched_version: v.patched_version.clone(),
                    kind: v.kind.clone(),
                });
            }
        }
    }
    // Highest severity first.
    let rank = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    findings.sort_by_key(|f| rank(&f.severity));
    WpVulnScanResult {
        findings,
        feed_unavailable: false,
        feed_age_secs: feed_age,
        checked: items.len() as i64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn version_compare() {
        assert_eq!(cmp_version("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp_version("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(cmp_version("1.10.0", "1.9.9"), Ordering::Greater);
        assert_eq!(cmp_version("2.0", "2.0.0"), Ordering::Equal);
        assert_eq!(cmp_version("5.7", "5.7.1"), Ordering::Less);
    }

    #[test]
    fn range_inclusivity() {
        let r = SlimRange { from: "1.0".into(), from_incl: true, to: "2.0".into(), to_incl: false };
        assert!(version_in_range("1.0", &r));
        assert!(version_in_range("1.9.9", &r));
        assert!(!version_in_range("2.0", &r)); // upper exclusive
        assert!(!version_in_range("0.9", &r));
        let open = SlimRange { from: "*".into(), from_incl: true, to: "3.1.4".into(), to_incl: true };
        assert!(version_in_range("0.1", &open));
        assert!(version_in_range("3.1.4", &open));
        assert!(!version_in_range("3.1.5", &open));
    }
}
