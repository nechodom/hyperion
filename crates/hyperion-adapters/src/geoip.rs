//! IP → country, from MaxMind's GeoLite2 **Country CSV** edition.
//!
//! CSV rather than the `.mmdb` binary on purpose. Two consumers need this
//! data and they want it in different shapes:
//!
//!   * the panel resolves access-log IPs to countries, which wants an
//!     in-memory table it can binary-search;
//!   * nginx blocks countries, which wants a `geo` map of CIDR → code.
//!     `geo` is a CORE nginx directive, so building the map from CIDRs
//!     avoids `ngx_http_geoip2_module` — a third-party module the operator
//!     would have to compile, which is a large ask for a checkbox.
//!
//! One download, both shapes, no extra nginx module.
//!
//! Credentials are never stored by this module and never logged. They are
//! read at call time from the operator's own `/etc/GeoIP.conf` (the file
//! MaxMind's `geoipupdate` already uses) or from `[geoip]` in agent.toml,
//! and passed to curl through a config file on stdin — never argv, where
//! every process on the box could read them out of `ps`.

use crate::AdapterError;
use std::net::Ipv4Addr;
use std::path::Path;

/// Where the derived artifacts live.
pub const GEOIP_DIR: &str = "/var/lib/hyperion/geoip";
/// Compact `start_u32,end_u32,CC` table — what the panel loads.
pub const RANGES_CSV: &str = "/var/lib/hyperion/geoip/country-ipv4.csv";
/// nginx `geo` map, included from conf.d at http{} level.
pub const NGINX_GEO_CONF: &str = "/etc/nginx/conf.d/hyperion-geo.conf";

/// MaxMind account credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxmindCreds {
    pub account_id: String,
    pub license_key: String,
}

/// Parse an `AccountID` / `LicenseKey` pair out of a `GeoIP.conf`.
///
/// Deliberately tolerant of the real file: comments, blank lines, extra
/// keys (`EditionIDs`), and any amount of whitespace between key and value.
/// Returns `None` rather than a partial pair — half a credential is not
/// usable and reporting it as usable produces a confusing 401 later.
pub fn parse_geoip_conf(text: &str) -> Option<MaxmindCreds> {
    let mut account_id = None;
    let mut license_key = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some("AccountID"), Some(v)) => account_id = Some(v.to_string()),
            (Some("LicenseKey"), Some(v)) => license_key = Some(v.to_string()),
            _ => {}
        }
    }
    match (account_id, license_key) {
        (Some(a), Some(l)) if !a.is_empty() && !l.is_empty() => Some(MaxmindCreds {
            account_id: a,
            license_key: l,
        }),
        _ => None,
    }
}

/// One country range, as inclusive u32 bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub start: u32,
    pub end: u32,
    /// ASCII ISO-3166-1 alpha-2, uppercase.
    pub cc: [u8; 2],
}

impl Range {
    pub fn country(&self) -> String {
        String::from_utf8_lossy(&self.cc).to_string()
    }
}

/// Expand `1.2.3.0/24` into inclusive u32 bounds.
///
/// Returns `None` for anything that is not an IPv4 CIDR — a malformed row
/// is skipped rather than aborting the whole import, because one bad line
/// in a 400 000-line file should not cost the operator the feature.
pub fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
    let (ip, bits) = cidr.split_once('/')?;
    let addr: Ipv4Addr = ip.parse().ok()?;
    let bits: u32 = bits.parse().ok()?;
    if bits > 32 {
        return None;
    }
    let base = u32::from(addr);
    // A /0 shifts by 32, which is UB-adjacent in release and panics in
    // debug — hence the explicit branch rather than `!0u32 >> bits`.
    let size = if bits == 0 {
        u32::MAX
    } else {
        (1u32 << (32 - bits)) - 1
    };
    Some((base, base.saturating_add(size)))
}

/// Look a v4 address up in a table sorted by `start`.
///
/// Binary search, so the cost is ~18 comparisons against a 400 000-row
/// table rather than a scan — this runs once per access-log line.
pub fn lookup(sorted: &[Range], ip: Ipv4Addr) -> Option<&Range> {
    let v = u32::from(ip);
    let idx = match sorted.binary_search_by(|r| r.start.cmp(&v)) {
        Ok(i) => i,
        // `Err(0)` means the address is below every range.
        Err(0) => return None,
        Err(i) => i - 1,
    };
    let cand = sorted.get(idx)?;
    if v >= cand.start && v <= cand.end {
        Some(cand)
    } else {
        None
    }
}

/// Read the compact table written by [`refresh`].
pub async fn load_ranges(path: &Path) -> Result<Vec<Range>, AdapterError> {
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: read {}: {e}", path.display())))?;
    let mut out = Vec::with_capacity(text.len() / 20);
    for line in text.lines() {
        let mut it = line.split(',');
        let (Some(s), Some(e), Some(cc)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let (Ok(start), Ok(end)) = (s.parse::<u32>(), e.parse::<u32>()) else {
            continue;
        };
        let b = cc.as_bytes();
        if b.len() != 2 {
            continue;
        }
        out.push(Range {
            start,
            end,
            cc: [b[0], b[1]],
        });
    }
    out.sort_unstable_by_key(|r| r.start);
    Ok(out)
}

/// Turn MaxMind's two CSVs into our compact table.
///
/// `blocks` is `GeoLite2-Country-Blocks-IPv4.csv`, `locations` is
/// `GeoLite2-Country-Locations-en.csv`. A block row carries a geoname_id,
/// which only the locations file can turn into a country code.
///
/// Rows whose geoname_id is blank (MaxMind emits these for anonymous
/// proxies and satellite providers) are dropped: they belong to no
/// country, and inventing one would put real visitors behind a flag that
/// is not theirs.
pub fn build_table(blocks_csv: &str, locations_csv: &str) -> Vec<Range> {
    let mut geo_to_cc: std::collections::HashMap<&str, [u8; 2]> = std::collections::HashMap::new();
    for (i, line) in locations_csv.lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        let cols: Vec<&str> = line.split(',').collect();
        // geoname_id,locale_code,continent_code,continent_name,country_iso_code,...
        let (Some(gid), Some(iso)) = (cols.first(), cols.get(4)) else {
            continue;
        };
        let iso = iso.trim_matches('"');
        if iso.len() == 2 {
            let b = iso.as_bytes();
            geo_to_cc.insert(gid.trim_matches('"'), [b[0], b[1]]);
        }
    }

    let mut out = Vec::new();
    for (i, line) in blocks_csv.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        // network,geoname_id,registered_country_geoname_id,...
        let Some(network) = cols.first() else {
            continue;
        };
        // Prefer the network's own country; fall back to the REGISTERED
        // country, which is what MaxMind fills in for ranges it can place
        // to an owner but not to a location. Without the fallback a
        // noticeable slice of traffic resolves to nothing.
        let cc = cols
            .get(1)
            .filter(|g| !g.is_empty())
            .and_then(|g| geo_to_cc.get(g.trim_matches('"')))
            .or_else(|| {
                cols.get(2)
                    .filter(|g| !g.is_empty())
                    .and_then(|g| geo_to_cc.get(g.trim_matches('"')))
            });
        let (Some(cc), Some((start, end))) = (cc, parse_cidr_v4(network.trim_matches('"'))) else {
            continue;
        };
        out.push(Range {
            start,
            end,
            cc: *cc,
        });
    }
    out.sort_unstable_by_key(|r| r.start);
    out
}

/// Render the nginx `geo` map.
///
/// `geo` is core nginx, so this needs no third-party module. The variable
/// defaults to `ZZ` — an ISO-3166 user-assigned code that can never be a
/// real country — so a rule matching a country list can never accidentally
/// match an address the database does not know.
pub fn render_nginx_geo(ranges: &[Range]) -> String {
    let mut s = String::with_capacity(ranges.len() * 24 + 512);
    s.push_str(
        "# Generated by Hyperion from MaxMind GeoLite2 Country. Do not edit.\n\
         # $hyperion_country is the visitor's ISO-3166-1 alpha-2 code, or ZZ\n\
         # when the database has no answer. ZZ is user-assigned and can never\n\
         # be a real country, so a country rule cannot match an unknown IP by\n\
         # accident.\n\
         geo $hyperion_country {\n    default ZZ;\n",
    );
    for r in ranges {
        // nginx `geo` takes CIDRs, and our table is ranges — emit the
        // covering CIDRs for each range so nothing is widened.
        for (base, bits) in range_to_cidrs(r.start, r.end) {
            let a = Ipv4Addr::from(base);
            s.push_str("    ");
            s.push_str(&format!("{a}/{bits} {};\n", r.country()));
        }
    }
    s.push_str("}\n");
    s
}

/// Split an inclusive range into the minimal set of aligned CIDRs.
fn range_to_cidrs(mut start: u32, end: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    while start <= end {
        // Largest block that is aligned to `start` and fits inside the range.
        let max_by_align = if start == 0 {
            32
        } else {
            start.trailing_zeros()
        };
        let remaining = (end - start).saturating_add(1);
        let max_by_size = 31u32.saturating_sub(remaining.leading_zeros().min(31));
        let size = max_by_align.min(max_by_size);
        out.push((start, 32 - size));
        let step = 1u64 << size;
        let next = start as u64 + step;
        if next > u32::MAX as u64 {
            break;
        }
        start = next as u32;
    }
    out
}

/// Extract a zip archive into `dest`, refusing entries that escape it.
///
/// The archive comes from MaxMind over TLS, but "trusted source" is not a
/// reason to skip the zip-slip check: `enclosed_name` rejects `../` and
/// absolute paths, so a hostile or corrupted archive cannot write outside
/// the extraction directory — which for a process running as root is the
/// difference between a failed refresh and a rewritten /etc.
fn extract_zip(zip_path: &Path, dest: &Path) -> Result<(), AdapterError> {
    let file = std::fs::File::open(zip_path)
        .map_err(|e| AdapterError::Other(format!("geoip: open archive: {e}")))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| AdapterError::Other(format!("geoip: not a zip archive: {e}")))?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| AdapterError::Other(format!("geoip: read entry: {e}")))?;
        let Some(rel) = entry.enclosed_name() else {
            return Err(AdapterError::Other(
                "geoip: archive entry escapes the extraction directory — refusing".into(),
            ));
        };
        let out = dest.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)
                .map_err(|e| AdapterError::Other(format!("geoip: mkdir: {e}")))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AdapterError::Other(format!("geoip: mkdir: {e}")))?;
        }
        let mut f = std::fs::File::create(&out)
            .map_err(|e| AdapterError::Other(format!("geoip: create {}: {e}", out.display())))?;
        std::io::copy(&mut entry, &mut f)
            .map_err(|e| AdapterError::Other(format!("geoip: extract: {e}")))?;
    }
    Ok(())
}

/// Find MaxMind credentials: the operator's own `geoipupdate` config
/// first, then an explicit path.
///
/// Preferring `/etc/GeoIP.conf` means an operator who already runs
/// `geoipupdate` needs to configure nothing here at all — and it keeps the
/// key in the file that already has the right ownership, rather than
/// copying a secret into a second place.
pub async fn discover_creds(explicit: Option<&Path>) -> Option<MaxmindCreds> {
    let candidates: Vec<std::path::PathBuf> = match explicit {
        Some(p) => vec![p.to_path_buf()],
        None => vec![
            std::path::PathBuf::from("/etc/GeoIP.conf"),
            std::path::PathBuf::from("/usr/local/etc/GeoIP.conf"),
        ],
    };
    for c in candidates {
        if let Ok(text) = tokio::fs::read_to_string(&c).await {
            if let Some(creds) = parse_geoip_conf(&text) {
                return Some(creds);
            }
        }
    }
    None
}

/// Write credentials to `/etc/GeoIP.conf`, 0600 root.
///
/// The same file `geoipupdate` reads, so configuring it here does not
/// create a second place for the key to live — and an operator who later
/// runs that tool inherits what was set in the panel.
///
/// `EditionIDs` is preserved when the file already has one, because
/// replacing it would silently narrow what an existing `geoipupdate` cron
/// fetches. A fresh file gets Country, which is all Hyperion uses.
pub async fn write_creds(creds: &MaxmindCreds, path: &Path) -> Result<(), AdapterError> {
    let editions = tokio::fs::read_to_string(path)
        .await
        .ok()
        .and_then(|t| {
            t.lines()
                .map(str::trim)
                .find(|l| l.starts_with("EditionIDs"))
                .map(|l| l.to_string())
        })
        .unwrap_or_else(|| "EditionIDs GeoLite2-Country".to_string());

    let body = format!(
        "# Managed by Hyperion (Settings -> GeoIP). Also read by geoipupdate.\n\
         AccountID {}\n\
         LicenseKey {}\n\
         {}\n",
        creds.account_id.trim(),
        creds.license_key.trim(),
        editions
    );

    // Write with the final permissions from the start rather than
    // chmod-ing afterwards: between a 0644 create and a later chmod there
    // is a window in which any local user can read the key.
    let tmp = path.with_extension("hyperion-new");
    {
        use std::os::unix::fs::OpenOptionsExt;
        use tokio::io::AsyncWriteExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| AdapterError::Other(format!("geoip: open {}: {e}", tmp.display())))?;
        let mut f = tokio::fs::File::from_std(file);
        f.write_all(body.as_bytes())
            .await
            .map_err(|e| AdapterError::Other(format!("geoip: write creds: {e}")))?;
        f.flush()
            .await
            .map_err(|e| AdapterError::Other(format!("geoip: flush creds: {e}")))?;
    }
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: install creds: {e}")))?;
    Ok(())
}

/// Download the Country CSV edition and regenerate both artifacts.
///
/// Returns how many ranges were imported. Everything is written to a temp
/// path and moved into place, so a failed or truncated download can never
/// leave nginx including half a map — an invalid `geo` block fails
/// `nginx -t` and would take every site on the box down.
pub async fn refresh(creds: &MaxmindCreds) -> Result<usize, AdapterError> {
    let dir = Path::new(GEOIP_DIR);
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: mkdir: {e}")))?;
    let tmp = dir.join("dl");
    let _ = tokio::fs::remove_dir_all(&tmp).await;
    tokio::fs::create_dir_all(&tmp)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: mkdir tmp: {e}")))?;

    let zip = tmp.join("country.zip");
    // Credentials go to curl through a config file on STDIN. Not argv:
    // every process on the box can read another's command line out of
    // /proc, so a licence key there is readable by any local user.
    let cfg = format!(
        "user = \"{}:{}\"\nsilent\nshow-error\nlocation\nfail\nmax-time = 180\noutput = \"{}\"\nurl = \"https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip\"\n",
        creds.account_id,
        creds.license_key,
        zip.display()
    );
    let mut child = tokio::process::Command::new("curl")
        .arg("--config")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| AdapterError::Other(format!("geoip: spawn curl: {e}")))?;
    if let Some(mut si) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = si.write_all(cfg.as_bytes()).await;
        let _ = si.shutdown().await;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: curl: {e}")))?;
    if !out.status.success() {
        // The stderr tail can contain the URL but never the credentials —
        // curl does not echo a --config body.
        return Err(AdapterError::Other(format!(
            "geoip: download failed ({}). Check the MaxMind account id and licence key.",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    // Pure-Rust extraction. This used to shell out to `unzip`, which no
    // installer ever installed — so on a minimal Debian the whole feature
    // failed at this exact step, every time, with nothing the operator
    // could do about it short of guessing the missing package. A runtime
    // dependency nobody guarantees is a failure mode; a compiled-in one is
    // not.
    let zip_path = zip.clone();
    let dest = tmp.clone();
    tokio::task::spawn_blocking(move || extract_zip(&zip_path, &dest))
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: unzip task: {e}")))??;

    // MaxMind nests the CSVs in a dated directory, so find them.
    let (mut blocks, mut locations) = (None, None);
    let mut stack = vec![tmp.clone()];
    while let Some(d) = stack.pop() {
        let mut rd = match tokio::fs::read_dir(&d).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        while let Ok(Some(ent)) = rd.next_entry().await {
            let p = ent.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name.ends_with("Country-Blocks-IPv4.csv") {
                blocks = Some(p);
            } else if name.ends_with("Country-Locations-en.csv") {
                locations = Some(p);
            }
        }
    }
    let (Some(bp), Some(lp)) = (blocks, locations) else {
        return Err(AdapterError::Other(
            "geoip: the archive did not contain the expected Country CSVs".into(),
        ));
    };

    let blocks_csv = tokio::fs::read_to_string(&bp)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: read blocks: {e}")))?;
    let locations_csv = tokio::fs::read_to_string(&lp)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: read locations: {e}")))?;
    let table = build_table(&blocks_csv, &locations_csv);
    if table.is_empty() {
        return Err(AdapterError::Other(
            "geoip: the archive parsed to zero ranges — refusing to install an empty map".into(),
        ));
    }

    // Country names for the traffic table — without this file the panel
    // falls back to bare ISO codes, which is technically correct and
    // useless to read.
    {
        let mut names = String::new();
        for (i, line) in locations_csv.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let cols: Vec<&str> = line.split(',').collect();
            if let (Some(iso), Some(name)) = (cols.get(4), cols.get(5)) {
                let iso = iso.trim_matches('"');
                let name = name.trim_matches('"');
                if iso.len() == 2 && !name.is_empty() {
                    names.push_str(&format!("{iso},{name}\n"));
                }
            }
        }
        let names_tmp = dir.join("country-names.csv.new");
        tokio::fs::write(&names_tmp, names)
            .await
            .map_err(|e| AdapterError::Other(format!("geoip: write names: {e}")))?;
        tokio::fs::rename(&names_tmp, dir.join("country-names.csv"))
            .await
            .map_err(|e| AdapterError::Other(format!("geoip: install names: {e}")))?;
    }

    // Compact table for the panel.
    let mut compact = String::with_capacity(table.len() * 20);
    for r in &table {
        compact.push_str(&format!("{},{},{}\n", r.start, r.end, r.country()));
    }
    let ranges_tmp = dir.join("country-ipv4.csv.new");
    tokio::fs::write(&ranges_tmp, compact)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: write ranges: {e}")))?;
    tokio::fs::rename(&ranges_tmp, RANGES_CSV)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: install ranges: {e}")))?;

    // nginx map, written aside and moved in, then validated by the caller.
    let geo_tmp = format!("{NGINX_GEO_CONF}.new");
    tokio::fs::write(&geo_tmp, render_nginx_geo(&table))
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: write geo map: {e}")))?;
    tokio::fs::rename(&geo_tmp, NGINX_GEO_CONF)
        .await
        .map_err(|e| AdapterError::Other(format!("geoip: install geo map: {e}")))?;

    let _ = tokio::fs::remove_dir_all(&tmp).await;
    Ok(table.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_real_geoip_conf_shape() {
        let c = parse_geoip_conf(
            "# comment\n\nAccountID 000000\nLicenseKey abc_DEF-123\nEditionIDs GeoLite2-Country\n",
        )
        .expect("parses");
        assert_eq!(c.account_id, "000000");
        assert_eq!(c.license_key, "abc_DEF-123");
    }

    /// Half a credential is not usable, and reporting it as usable turns a
    /// clear "not configured" into a confusing 401 much later.
    #[test]
    fn half_a_credential_is_none() {
        assert!(parse_geoip_conf("AccountID 1\n").is_none());
        assert!(parse_geoip_conf("LicenseKey k\n").is_none());
        assert!(parse_geoip_conf("# nothing\n").is_none());
    }

    #[tokio::test]
    async fn writing_creds_preserves_existing_editions() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("GeoIP.conf");
        std::fs::write(
            &p,
            "AccountID 1\nLicenseKey old\nEditionIDs GeoLite2-ASN GeoLite2-City\n",
        )
        .expect("seed");
        write_creds(
            &MaxmindCreds {
                account_id: "42".into(),
                license_key: "newkey".into(),
            },
            &p,
        )
        .await
        .expect("write");
        let back = std::fs::read_to_string(&p).expect("read");
        let parsed = parse_geoip_conf(&back).expect("round-trips");
        assert_eq!(parsed.account_id, "42");
        assert_eq!(parsed.license_key, "newkey");
        // Narrowing someone's editions would silently change what their
        // existing geoipupdate cron fetches.
        assert!(
            back.contains("GeoLite2-ASN GeoLite2-City"),
            "editions lost:\n{back}"
        );
    }

    /// The key must never be world-readable, not even briefly.
    #[tokio::test]
    async fn creds_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("GeoIP.conf");
        write_creds(
            &MaxmindCreds {
                account_id: "1".into(),
                license_key: "k".into(),
            },
            &p,
        )
        .await
        .expect("write");
        let mode = std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "creds file is {mode:o}, must be 600");
    }

    /// Extraction must handle the shape MaxMind actually ships: CSVs nested
    /// in a dated directory the archive also declares as an entry.
    #[test]
    fn extracts_a_maxmind_shaped_zip() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tmp");
        let zp = dir.path().join("a.zip");
        {
            let f = std::fs::File::create(&zp).expect("create");
            let mut w = zip::ZipWriter::new(f);
            let o = zip::write::SimpleFileOptions::default();
            w.add_directory("GeoLite2-Country-CSV_20260821/", o)
                .expect("dir");
            w.start_file(
                "GeoLite2-Country-CSV_20260821/GeoLite2-Country-Blocks-IPv4.csv",
                o,
            )
            .expect("start");
            w.write_all(
                b"network,geoname_id
1.2.3.0/24,1
",
            )
            .expect("write");
            w.finish().expect("finish");
        }
        let out = dir.path().join("out");
        extract_zip(&zp, &out).expect("extract");
        let extracted = out
            .join("GeoLite2-Country-CSV_20260821")
            .join("GeoLite2-Country-Blocks-IPv4.csv");
        let body = std::fs::read_to_string(extracted).expect("read back");
        assert!(body.contains("1.2.3.0/24"));
    }

    /// A path that escapes the destination is refused outright. The agent
    /// runs as root; "failed refresh" and "rewrote /etc" must never be the
    /// same bug.
    #[test]
    fn zip_slip_is_refused() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tmp");
        let zp = dir.path().join("evil.zip");
        {
            let f = std::fs::File::create(&zp).expect("create");
            let mut w = zip::ZipWriter::new(f);
            let o = zip::write::SimpleFileOptions::default();
            w.start_file("../evil.txt", o).expect("start");
            w.write_all(b"nope").expect("write");
            w.finish().expect("finish");
        }
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).expect("mkdir");
        assert!(
            extract_zip(&zp, &out).is_err(),
            "escaping entry must be refused"
        );
        assert!(
            !dir.path().join("evil.txt").exists(),
            "file escaped the sandbox"
        );
    }

    #[test]
    fn cidr_bounds_are_inclusive() {
        assert_eq!(parse_cidr_v4("1.2.3.0/24"), Some((0x01020300, 0x010203FF)));
        assert_eq!(parse_cidr_v4("10.0.0.1/32"), Some((0x0A000001, 0x0A000001)));
        assert_eq!(parse_cidr_v4("0.0.0.0/0"), Some((0, u32::MAX)));
        assert_eq!(parse_cidr_v4("nonsense"), None);
        assert_eq!(parse_cidr_v4("1.2.3.0/33"), None);
    }

    #[test]
    fn lookup_finds_the_containing_range_only() {
        let t = vec![
            Range {
                start: 100,
                end: 199,
                cc: *b"CZ",
            },
            Range {
                start: 300,
                end: 399,
                cc: *b"SK",
            },
        ];
        assert_eq!(
            lookup(&t, Ipv4Addr::from(150)).map(|r| r.country()),
            Some("CZ".into())
        );
        assert_eq!(
            lookup(&t, Ipv4Addr::from(350)).map(|r| r.country()),
            Some("SK".into())
        );
        // Gaps and the space below the first range resolve to nothing
        // rather than to the nearest neighbour.
        assert!(lookup(&t, Ipv4Addr::from(250)).is_none());
        assert!(lookup(&t, Ipv4Addr::from(50)).is_none());
        assert!(lookup(&t, Ipv4Addr::from(400)).is_none());
    }

    #[test]
    fn builds_a_table_from_maxmind_shaped_csv() {
        let locations =
            "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name\n\
                         3077311,en,EU,Europe,CZ,Czechia\n\
                         3057568,en,EU,Europe,SK,Slovakia\n";
        let blocks = "network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n\
                      81.0.0.0/24,3077311,3077311,,0,0\n\
                      82.0.0.0/24,,3057568,,0,0\n\
                      83.0.0.0/24,,,,0,0\n";
        let t = build_table(blocks, locations);
        assert_eq!(t.len(), 2, "the row with no country at all must be dropped");
        assert_eq!(
            lookup(&t, "81.0.0.5".parse().unwrap()).map(|r| r.country()),
            Some("CZ".into())
        );
        // Falls back to the REGISTERED country when the network has none.
        assert_eq!(
            lookup(&t, "82.0.0.5".parse().unwrap()).map(|r| r.country()),
            Some("SK".into())
        );
        assert!(lookup(&t, "83.0.0.5".parse().unwrap()).is_none());
    }

    #[test]
    fn range_to_cidrs_covers_exactly() {
        // A range that is not CIDR-aligned must split, and the pieces must
        // cover it exactly — widening one would block bystanders.
        let parts = range_to_cidrs(0x01020301, 0x010203FE);
        let mut covered: u64 = 0;
        for (base, bits) in &parts {
            let size = 1u64 << (32 - bits);
            covered += size;
            assert_eq!(base % (size as u32).max(1), 0, "unaligned CIDR emitted");
        }
        assert_eq!(covered, (0x010203FE - 0x01020301 + 1) as u64);
    }

    #[test]
    fn nginx_geo_defaults_to_a_code_that_is_never_a_country() {
        let out = render_nginx_geo(&[Range {
            start: 0x01020300,
            end: 0x010203FF,
            cc: *b"CZ",
        }]);
        assert!(out.contains("default ZZ;"));
        assert!(out.contains("1.2.3.0/24 CZ;"));
        assert!(out.starts_with("# Generated by Hyperion"));
    }
}
