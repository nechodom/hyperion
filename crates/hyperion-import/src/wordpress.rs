//! WordPress plugin source: a single site that pushed itself here from its own
//! wp-admin, with no panel and no shell on the source.
//!
//! The plugin cannot build a bundle: PHP on a shared host gets seconds per
//! request and may have no disk to spare. So it streams a site's files and its
//! database dump in slices, and this module turns those two streams into the
//! ordinary bundle the archive import already understands. From there on a
//! WordPress site is imported like any other.
//!
//! Everything in the manifest is decided on this side from a few validated
//! fields. The source is somebody else's PHP, so it never supplies a path, a
//! database name or a raw manifest.

use crate::adapter::{Location, SourceAdapter, SourceKind, SourcePanelInfo};
use crate::bundle;
use crate::error::ImportError;
use crate::ir::{
    ImportIR, IrDatabase, IrDbEngine, IrHosting, IrSiteKind, IrUnsupported, SourceSummary,
};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// The file a site's files stream lands in while it arrives.
pub const FILES_STREAM: &str = "docroot.tar.gz";
/// The file a site's database stream lands in while it arrives.
pub const DB_STREAM: &str = "db.sql.gz";
/// The dump's name in the bundle. Fixed, because a name from the source would be
/// a path on this node.
const DUMP_NAME: &str = "wordpress";
/// How the plugin ends a complete dump. A dump cut short at a statement boundary
/// is valid SQL, so it would otherwise restore as a site missing its last tables.
const DUMP_END_MARKER: &str = "-- hyperion-migrate: dump complete";

const MAX_NOTES: usize = 40;
const MAX_NOTE_CHARS: usize = 300;

pub struct WordPressAdapter;

#[async_trait::async_trait]
impl SourceAdapter for WordPressAdapter {
    fn kind(&self) -> SourceKind {
        SourceKind::WordPress
    }

    async fn detect(&self, location: &Location) -> Option<SourcePanelInfo> {
        let Location::Archive(dir) = location else {
            return None;
        };
        let ir = bundle::read_manifest(dir).await?;
        (ir.source.kind == SourceKind::WordPress.as_str()).then_some(SourcePanelInfo {
            kind: SourceKind::WordPress,
            version: ir.source.version,
            has_mail: false,
            has_dns: false,
        })
    }

    async fn extract(&self, location: &Location) -> Result<ImportIR, ImportError> {
        let Location::Archive(dir) = location else {
            return Err(ImportError::NotDetected);
        };
        bundle::read_manifest(dir).await.ok_or(ImportError::Parse {
            what: "bundle manifest".into(),
            msg: "manifest.json missing or invalid in the assembled bundle".into(),
        })
    }
}

/// Where a site lands and what has to change for it to work there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WpTarget {
    pub domain: String,
    pub aliases: Vec<String>,
    /// `(from, to)` pairs for `wp search-replace //from //to`, in order.
    pub url_rewrites: Vec<(String, String)>,
}

/// Work out the target from the site's home URL and the operator's optional
/// "import as" domain.
///
/// A hosting's domain never carries `www.`; that is an alias. A site that lives
/// on `www.` keeps its URLs unless it is renamed, because its visitors and search
/// results are on that name. A site in a subfolder moves to the document root, so
/// its URLs lose the folder either way.
pub fn resolve_target(home_url: &str, import_as: Option<&str>) -> Result<WpTarget, String> {
    let rest = home_url
        .trim()
        .strip_prefix("https://")
        .or_else(|| home_url.trim().strip_prefix("http://"))
        .ok_or_else(|| format!("home URL {home_url:?} is not http(s)"))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let authority = authority.to_ascii_lowercase();
    let host = authority.split(':').next().unwrap_or("").to_string();
    if host.is_empty() {
        return Err(format!("home URL {home_url:?} has no host"));
    }
    let path = path.trim_end_matches('/');
    // The path comes from the source and ends up as a search-replace argument.
    if path
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\'))
    {
        return Err(format!("home URL {home_url:?} has an unusable path"));
    }
    let with_path = |h: &str| {
        if path.is_empty() {
            h.to_string()
        } else {
            format!("{h}/{path}")
        }
    };
    let from = with_path(&authority);

    let bare = |h: &str| h.strip_prefix("www.").unwrap_or(h).to_string();
    let source = bare(&host);
    let wanted = import_as
        .map(|t| bare(&t.trim().to_ascii_lowercase()))
        .filter(|t| !t.is_empty());
    let renamed = wanted.as_ref().is_some_and(|t| *t != source);
    let domain = wanted.unwrap_or_else(|| source.clone());

    let to = if renamed {
        domain.clone()
    } else {
        host.clone()
    };
    let mut url_rewrites = Vec::new();
    if from != to {
        url_rewrites.push((from, to.clone()));
    }
    if renamed || !path.is_empty() {
        // The other spelling of the old name still appears in old content, and
        // it has to lose the same folder or its links lead nowhere.
        let other = if host == source {
            format!("www.{source}")
        } else {
            source.clone()
        };
        url_rewrites.push((with_path(&other), to));
    }

    // `www.` on a third-level name is rarely real, and an alias with no DNS makes
    // a certificate request for the whole hosting fail. A site that was on `www.`
    // has shown it is real, whatever its depth.
    let was_on_www = host != source && !renamed;
    let aliases = if was_on_www || domain.matches('.').count() == 1 {
        vec![format!("www.{domain}")]
    } else {
        Vec::new()
    };
    Ok(WpTarget {
        domain,
        aliases,
        url_rewrites,
    })
}

/// The facts the plugin reported about a site.
#[derive(Debug, Clone, Default)]
pub struct WpSource {
    pub home_url: String,
    pub wp_version: String,
    pub php_version: String,
    pub files_bytes: u64,
    pub warnings: Vec<String>,
}

/// `"8.2.10"` → `"8.2"`, and anything that is not a version → `None`.
fn php_major_minor(raw: &str) -> Option<String> {
    let mut parts = raw.trim().split('.');
    let (major, minor) = (parts.next()?, parts.next()?);
    let is_num = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    (is_num(major) && is_num(minor)).then(|| format!("{major}.{minor}"))
}

/// Replace anything that is not plain printable text, then cap the length. These
/// strings come from the source and end up in a job log.
fn clean(raw: &str, max: usize) -> String {
    raw.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect()
}

/// The manifest for one site. Both sizes are measured from what arrived, not what
/// the source claimed, because the import's disk check goes by them.
pub fn manifest(source: &WpSource, target: &WpTarget, files_bytes: u64, db_bytes: u64) -> ImportIR {
    let source_url = clean(&source.home_url, MAX_NOTE_CHARS);
    let mut unsupported: Vec<IrUnsupported> = source
        .warnings
        .iter()
        .take(MAX_NOTES)
        .map(|w| IrUnsupported {
            category: "wordpress".into(),
            detail: clean(w, MAX_NOTE_CHARS),
        })
        .collect();
    unsupported.push(IrUnsupported {
        category: "mail/dns".into(),
        detail: "the plugin moves files and the database. Mailboxes and DNS records stay \
                 where they are."
            .into(),
    });
    ImportIR {
        source: SourceSummary {
            kind: SourceKind::WordPress.as_str().into(),
            version: clean(&source.wp_version, 40),
            host: source_url.clone(),
        },
        hostings: vec![IrHosting {
            // Includes the target so one site can land twice, as `staging.` and
            // then for real, without the second reading as already imported.
            source_key: format!("wordpress:{source_url}:{}", target.domain),
            domain: target.domain.clone(),
            aliases: target.aliases.clone(),
            owner_user: "wordpress".into(),
            kind: IrSiteKind::Php,
            php_version: php_major_minor(&source.php_version),
            docroot: ".".into(),
            proxy_upstream: None,
            databases: vec![IrDatabase {
                name: DUMP_NAME.into(),
                engine: IrDbEngine::MariaDb,
                charset: Some("utf8mb4".into()),
                user: String::new(),
                dump_hint: String::new(),
            }],
            crons: Vec::new(),
            tls: None,
            ssh_keys: Vec::new(),
            docroot_bytes: files_bytes,
            db_bytes,
        }],
        unsupported,
        skipped: Vec::new(),
    }
}

/// Decompress the dump to `out` and prove it is complete. Returns its size.
///
/// `max_bytes` is what the disk can spare. Gzip reaches about 1000:1, so a small
/// stream from a hostile source could otherwise fill the disk from here.
fn unpack_dump(gz: &Path, out: &Path, max_bytes: Option<u64>) -> Result<u64, String> {
    let open_err = |e: std::io::Error| format!("read the database stream: {e}");
    let mut decoder = flate2::read::MultiGzDecoder::new(std::fs::File::open(gz).map_err(open_err)?);
    let mut file = std::fs::File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(out)
        .map_err(|e| format!("write the database dump: {e}"))?;
    let limit = max_bytes.unwrap_or(u64::MAX);
    let mut capped = (&mut decoder).take(limit.saturating_add(1));
    let bytes = std::io::copy(&mut capped, &mut file)
        .map_err(|e| format!("the database stream is corrupt: {e}"))?;
    if bytes > limit {
        drop(file);
        let _ = std::fs::remove_file(out);
        return Err(format!(
            "the database dump does not fit on this disk: it is over {} once unpacked.",
            crate::progress::human_bytes(limit)
        ));
    }
    file.flush()
        .map_err(|e| format!("write the database dump: {e}"))?;

    let tail_len = bytes.min(256);
    file.seek(SeekFrom::End(-(tail_len as i64)))
        .map_err(|e| format!("read the database dump: {e}"))?;
    let mut tail = Vec::with_capacity(tail_len as usize);
    file.read_to_end(&mut tail)
        .map_err(|e| format!("read the database dump: {e}"))?;
    if !String::from_utf8_lossy(&tail).contains(DUMP_END_MARKER) {
        return Err(
            "the database dump stops before its end marker, so tables are missing. \
                    Run the transfer again."
                .into(),
        );
    }
    Ok(bytes)
}

/// Read the whole files stream, returning its member count and the size of its
/// contents. The gzip checksums catch corruption, the tar reader catches truncation
/// inside a member, and the count catches a stream cut at a clean member boundary.
fn measure_files(gz: &Path) -> Result<(u64, u64), String> {
    let file = std::fs::File::open(gz).map_err(|e| format!("read the files stream: {e}"))?;
    let mut archive = tar::Archive::new(flate2::read::MultiGzDecoder::new(file));
    let (mut count, mut bytes) = (0u64, 0u64);
    let entries = archive
        .entries()
        .map_err(|e| format!("the files stream is not a tar archive: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("the files stream is corrupt: {e}"))?;
        bytes = bytes.saturating_add(entry.size());
        count += 1;
    }
    Ok((count, bytes))
}

/// Turn the two streams in `dir` into a `bundle.tar` at `out`.
///
/// Blocking, and as long as the site is large: run it off the async runtime.
/// Removes each stream once it is in the bundle, so the site is not on disk three
/// times over at the peak.
pub fn assemble_bundle(
    dir: &Path,
    out: &Path,
    source: &WpSource,
    target: &WpTarget,
    files_members: u64,
    max_dump_bytes: Option<u64>,
) -> Result<(), String> {
    let files_gz = dir.join(FILES_STREAM);
    let db_gz = dir.join(DB_STREAM);
    let dump = dir.join("db.sql");

    let (got, files_bytes) = measure_files(&files_gz)?;
    if got != files_members {
        return Err(format!(
            "the source sent {files_members} files and folders but {got} arrived. Run the \
             transfer again."
        ));
    }
    let db_bytes = unpack_dump(&db_gz, &dump, max_dump_bytes)?;
    let _ = std::fs::remove_file(&db_gz);

    let write_err = |e: std::io::Error| format!("write the bundle: {e}");
    let manifest_json = serde_json::to_vec_pretty(&manifest(source, target, files_bytes, db_bytes))
        .map_err(|e| format!("encode the manifest: {e}"))?;
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600: this is the site's database and wp-config in plaintext.
        std::fs::File::options()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(out)
            .map_err(write_err)?
    };
    let mut tar = tar::Builder::new(file);
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_json.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, bundle::MANIFEST, manifest_json.as_slice())
        .map_err(write_err)?;
    let site = format!("sites/{}", bundle::site_dir(&target.domain));
    tar.append_path_with_name(&dump, format!("{site}/db/{DUMP_NAME}.dump"))
        .map_err(write_err)?;
    let _ = std::fs::remove_file(&dump);
    tar.append_path_with_name(&files_gz, format!("{site}/{FILES_STREAM}"))
        .map_err(write_err)?;
    let _ = std::fs::remove_file(&files_gz);
    tar.into_inner()
        .and_then(|mut f| f.flush())
        .map_err(write_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn a_plain_site_lands_unchanged() {
        let t = resolve_target("https://example.cz", None).unwrap();
        assert_eq!(t.domain, "example.cz");
        assert_eq!(t.aliases, vec!["www.example.cz"]);
        assert!(t.url_rewrites.is_empty());
    }

    #[test]
    fn a_www_site_keeps_its_urls_but_its_hosting_is_the_bare_name() {
        let t = resolve_target("https://www.example.cz/", None).unwrap();
        assert_eq!(t.domain, "example.cz");
        assert_eq!(t.aliases, vec!["www.example.cz"]);
        assert!(t.url_rewrites.is_empty());
    }

    #[test]
    fn a_subfolder_site_moves_to_the_root() {
        let t = resolve_target("https://www.example.cz/blog/", None).unwrap();
        assert_eq!(t.domain, "example.cz");
        assert_eq!(
            t.url_rewrites,
            pairs(&[
                ("www.example.cz/blog", "www.example.cz"),
                ("example.cz/blog", "www.example.cz"),
            ])
        );
    }

    /// Left on the folder, `www.old.cz/blog/page` would become `new.cz/blog/page`,
    /// which is a 404: the site is at the root now.
    #[test]
    fn a_renamed_subfolder_site_loses_the_folder_on_both_spellings() {
        let t = resolve_target("https://old.cz/blog", Some("new.cz")).unwrap();
        assert_eq!(
            t.url_rewrites,
            pairs(&[("old.cz/blog", "new.cz"), ("www.old.cz/blog", "new.cz")])
        );
    }

    #[test]
    fn a_home_url_path_that_could_not_be_a_folder_is_refused() {
        assert!(resolve_target("https://example.cz/a b", None).is_err());
        assert!(resolve_target("https://example.cz/a\nb", None).is_err());
        assert!(resolve_target("https://example.cz/a'b", None).is_err());
    }

    #[test]
    fn a_rename_covers_both_spellings_of_the_old_name() {
        let t = resolve_target("https://www.old.cz", Some("new.cz")).unwrap();
        assert_eq!(t.domain, "new.cz");
        assert_eq!(
            t.url_rewrites,
            pairs(&[("www.old.cz", "new.cz"), ("old.cz", "new.cz")])
        );
    }

    #[test]
    fn asking_for_the_same_name_is_not_a_rename() {
        let t = resolve_target("https://example.cz", Some("www.example.cz")).unwrap();
        assert_eq!(t.domain, "example.cz");
        assert!(t.url_rewrites.is_empty());
    }

    #[test]
    fn a_port_in_the_home_url_is_rewritten_away() {
        let t = resolve_target("http://example.cz:8080", None).unwrap();
        assert_eq!(t.domain, "example.cz");
        assert_eq!(t.url_rewrites, pairs(&[("example.cz:8080", "example.cz")]));
    }

    #[test]
    fn a_third_level_name_gets_no_guessed_alias() {
        let t = resolve_target("https://blog.example.cz", None).unwrap();
        assert!(t.aliases.is_empty());
    }

    #[test]
    fn a_home_url_that_is_not_http_is_refused() {
        assert!(resolve_target("ftp://example.cz", None).is_err());
        assert!(resolve_target("https:///x", None).is_err());
    }

    #[test]
    fn php_versions_are_reduced_or_dropped() {
        assert_eq!(php_major_minor("8.2.10-1").as_deref(), Some("8.2"));
        assert_eq!(php_major_minor("7.4").as_deref(), Some("7.4"));
        assert_eq!(php_major_minor("../../etc"), None);
        assert_eq!(php_major_minor(""), None);
    }

    fn gz(bytes: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    fn docroot_tar() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, body) in [("wp-config.php", "<?php"), ("index.php", "<?php")] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, path, body.as_bytes()).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn fixture(dump: &str) -> (tempfile::TempDir, WpSource, WpTarget) {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(FILES_STREAM), gz(&docroot_tar())).unwrap();
        // Two members, the way the plugin writes it.
        let (a, b) = dump.split_at(dump.len() / 2);
        let mut stream = gz(a.as_bytes());
        stream.extend(gz(b.as_bytes()));
        std::fs::write(d.path().join(DB_STREAM), stream).unwrap();
        let source = WpSource {
            home_url: "https://example.cz".into(),
            wp_version: "6.7".into(),
            php_version: "8.2.3".into(),
            files_bytes: 10,
            warnings: vec!["note\nwith a newline".into()],
        };
        let target = resolve_target(&source.home_url, None).unwrap();
        (d, source, target)
    }

    #[tokio::test]
    async fn the_assembled_bundle_is_one_the_archive_import_reads() {
        let (d, source, target) =
            fixture("CREATE TABLE t(i int);\n-- hyperion-migrate: dump complete tables=1\n");
        let out = d.path().join("bundle.tar");
        assemble_bundle(d.path(), &out, &source, &target, 2, None).unwrap();

        let staged = d.path().join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        tar::Archive::new(std::fs::File::open(&out).unwrap())
            .unpack(&staged)
            .unwrap();
        let ir = bundle::read_manifest(&staged).await.expect("manifest");
        assert_eq!(ir.source.kind, "wordpress");
        assert_eq!(ir.hostings[0].domain, "example.cz");
        assert_eq!(ir.hostings[0].php_version.as_deref(), Some("8.2"));
        assert!(ir.hostings[0].db_bytes > 0);
        assert!(!ir.unsupported[0].detail.contains('\n'));

        let site = staged.join("sites/example.cz");
        assert!(site.join("docroot.tar.gz").is_file());
        let dump = std::fs::read_to_string(site.join("db/wordpress.dump")).unwrap();
        assert!(dump.starts_with("CREATE TABLE"), "both gzip members read");
        assert!(dump.contains("dump complete"));

        let info = WordPressAdapter
            .detect(&Location::Archive(staged))
            .await
            .expect("detected");
        assert_eq!(info.kind, SourceKind::WordPress);
    }

    #[test]
    fn a_dump_with_no_end_marker_is_refused() {
        let (d, source, target) = fixture("CREATE TABLE t(i int);\n");
        let err = assemble_bundle(d.path(), &d.path().join("b.tar"), &source, &target, 2, None)
            .unwrap_err();
        assert!(err.contains("end marker"), "got: {err}");
    }

    #[test]
    fn a_files_stream_short_of_members_is_refused() {
        let (d, source, target) = fixture("-- hyperion-migrate: dump complete tables=0\n");
        let err = assemble_bundle(d.path(), &d.path().join("b.tar"), &source, &target, 3, None)
            .unwrap_err();
        assert!(err.contains("3 files"), "got: {err}");
    }

    /// A few KB of gzip can unpack to the whole disk.
    #[test]
    fn a_dump_larger_than_the_disk_can_spare_is_refused_and_removed() {
        let dump = format!(
            "{}\n-- hyperion-migrate: dump complete tables=1\n",
            "x".repeat(100_000)
        );
        let (d, source, target) = fixture(&dump);
        let err = assemble_bundle(
            d.path(),
            &d.path().join("b.tar"),
            &source,
            &target,
            2,
            Some(1000),
        )
        .unwrap_err();
        assert!(err.contains("does not fit"), "got: {err}");
        assert!(!d.path().join("db.sql").exists());
    }

    /// The import's disk check goes by these, and a source can claim anything.
    #[tokio::test]
    async fn the_manifest_states_what_arrived_not_what_the_source_claimed() {
        let (d, mut source, target) =
            fixture("CREATE TABLE t(i int);\n-- hyperion-migrate: dump complete tables=1\n");
        source.files_bytes = 1;
        let out = d.path().join("bundle.tar");
        assemble_bundle(d.path(), &out, &source, &target, 2, None).unwrap();
        let staged = d.path().join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        tar::Archive::new(std::fs::File::open(&out).unwrap())
            .unpack(&staged)
            .unwrap();
        let ir = bundle::read_manifest(&staged).await.expect("manifest");
        assert_eq!(ir.hostings[0].docroot_bytes, 10, "two 5-byte files");
    }
}
