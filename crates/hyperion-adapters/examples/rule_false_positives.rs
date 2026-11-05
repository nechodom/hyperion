//! The rule pack over the current most popular wordpress.org plugins and themes: a
//! dev tool, not in CI (network). Layer A proves these files in production, so the
//! rules never see them there; the point is what they would say about comparable
//! premium code, which nothing can prove.
//!
//! ```text
//! cargo run --release -p hyperion-adapters --example rule_false_positives -- <scratch-dir> [count]
//! ```
//!
//! ZIPs go in `<scratch-dir>` and are read in place, never unpacked. Every hit goes
//! to `<scratch-dir>/hits.jsonl`; the summary goes to stdout. Exits 1 on a High hit.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

use hyperion_adapters::sitescan::manifest::{valid_slug, valid_version};
use hyperion_adapters::sitescan::rules::{inspect, is_php_like, Severity, INSPECT_MAX_BYTES};
use hyperion_adapters::sitescan::scan::is_layer_b_code;
use serde_json::{json, Value};

type Res<T> = Result<T, Box<dyn Error>>;

/// Same as the scan: only what PHP runs is a loose end when too big to read.
const TOO_LARGE: &str = "too_large_to_inspect";

fn curl(url: &str, out: Option<&Path>) -> Res<Vec<u8>> {
    let mut cmd = Command::new("curl");
    cmd.args(["-q", "-fsSL", "-g", "--max-time", "300", url]);
    if let Some(p) = out {
        cmd.arg("-o").arg(p);
    }
    let got = cmd.output()?;
    if !got.status.success() {
        return Err(format!("curl {url}: {}", got.status).into());
    }
    Ok(got.stdout)
}

/// Slug, version and where to get it. A plugin's own link: one released from trunk
/// has no ZIP under its version.
fn popular(kind: &str, count: usize) -> Res<Vec<(String, String, String)>> {
    let body = curl(
        &format!(
            "https://api.wordpress.org/{kind}s/info/1.2/?action=query_{kind}s\
             &request[browse]=popular&request[per_page]={count}"
        ),
        None,
    )?;
    let v: Value = serde_json::from_slice(&body)?;
    let list = v[format!("{kind}s")]
        .as_array()
        .ok_or("no list in the answer")?;
    Ok(list
        .iter()
        .filter_map(|e| {
            let (slug, version) = (e["slug"].as_str()?, e["version"].as_str()?);
            (valid_slug(slug) && valid_version(version)).then(|| {
                let url = e["download_link"]
                    .as_str()
                    .filter(|u| u.starts_with("https://downloads.wordpress.org/"))
                    .map_or_else(
                        || format!("https://downloads.wordpress.org/{kind}/{slug}.{version}.zip"),
                        str::to_string,
                    );
                (slug.to_string(), version.to_string(), url)
            })
        })
        .collect())
}

#[derive(Default)]
struct Tally {
    packages: u64,
    files: u64,
    unreadable: Vec<String>,
    by_rule: BTreeMap<String, (&'static str, u64)>,
    high: u64,
    medium: u64,
}

fn check_zip(zip_path: &Path, kind: &str, slug: &str, out: &mut File, t: &mut Tally) -> Res<()> {
    let mut archive = zip::ZipArchive::new(File::open(zip_path)?)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        let rel = format!("wp-content/{kind}s/{name}");
        if !entry.is_file() || !is_layer_b_code(&rel) {
            continue;
        }
        let mut bytes = Vec::new();
        if let Err(e) = (&mut entry)
            .take(INSPECT_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
        {
            t.unreadable.push(format!("{rel}: {e}"));
            continue;
        }
        t.files += 1;
        for hit in inspect(&rel, &bytes) {
            if hit.rule_id == TOO_LARGE && !is_php_like(&rel) {
                continue;
            }
            let high = hit.severity == Severity::High;
            let label = if high { "high" } else { "medium" };
            if high {
                t.high += 1;
            } else {
                t.medium += 1;
            }
            t.by_rule
                .entry(hit.rule_id.to_string())
                .or_insert((label, 0))
                .1 += 1;
            writeln!(
                out,
                "{}",
                json!({
                    "severity": label, "rule": hit.rule_id, "kind": kind, "slug": slug,
                    "file": name, "line": hit.line, "domains": hit.domains,
                    "snippet": hit.snippet,
                })
            )?;
        }
    }
    Ok(())
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let scratch = Path::new(args.first().ok_or("usage: <scratch-dir> [count]")?);
    let count: usize = args.get(1).map_or(Ok(50), |c| c.parse())?;
    std::fs::create_dir_all(scratch)?;
    let mut out = File::create(scratch.join("hits.jsonl"))?;
    let mut t = Tally::default();
    for kind in ["plugin", "theme"] {
        for (slug, version, url) in popular(kind, count)? {
            let zip_path = scratch.join(format!("{kind}-{slug}.{version}.zip"));
            if !zip_path.exists() {
                if let Err(e) = curl(&url, Some(&zip_path)) {
                    t.unreadable.push(format!("{kind} {slug}: {e}"));
                    continue;
                }
            }
            println!("{kind} {slug} {version}");
            match check_zip(&zip_path, kind, &slug, &mut out, &mut t) {
                Ok(()) => t.packages += 1,
                Err(e) => t.unreadable.push(format!("{kind} {slug}: {e}")),
            }
        }
    }
    println!(
        "packages={} files_inspected={} high={} medium={} unreadable={}",
        t.packages,
        t.files,
        t.high,
        t.medium,
        t.unreadable.len()
    );
    for (rule, (label, n)) in &t.by_rule {
        println!("  {label:6} {rule:28} {n}");
    }
    for u in &t.unreadable {
        println!("  unreadable: {u}");
    }
    if t.high > 0 {
        std::process::exit(1);
    }
    Ok(())
}
