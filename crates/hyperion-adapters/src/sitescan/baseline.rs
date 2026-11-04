//! Per-hosting baseline: what every file in Layer B scope looked like at the
//! last scan. Lives outside the tenant tree, root-owned 0600, so a tenant can
//! neither read nor forge it.
//!
//! The file is gzip over JSON lines: a header line carrying the format
//! version, `since` and the rule-pack version, then one line per scanned file
//! and one per trusted file. Paths are JSON strings (any odd character
//! survives), hashes are hex.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

use super::walk::FileMeta;

/// Bumped when a line changes shape; an older or newer file then reads as
/// "no baseline" and the site is scanned as a first scan.
const FORMAT_VERSION: u32 = 1;

/// What `load` will read. A corrupt or hostile file must not exhaust the
/// worker's 256 MiB: the file is decoded as a stream and never held whole, and
/// each of these ends the read as "damaged" instead.
struct Limits {
    /// Size of the file on disk.
    compressed: u64,
    /// Total decoded bytes.
    inflated: u64,
    /// One line. Longest real line is a path (at most 4096 bytes, six times
    /// that when every character is escaped) plus a hash.
    line: usize,
}

const LIMITS: Limits = Limits {
    compressed: 64 * 1024 * 1024,
    inflated: 200 * 1024 * 1024,
    line: 64 * 1024,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    pub size: u64,
    pub ctime: i64,
    pub ctime_nsec: i64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Baseline {
    /// Unix time of the first scan this baseline was started by.
    pub since: i64,
    pub rule_pack: u32,
    pub entries: BTreeMap<String, BaselineEntry>,
    /// Files someone vouched for, by path and the hash they vouched for.
    pub trusted: BTreeMap<String, [u8; 32]>,
}

/// What the metadata alone says about a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Not in the baseline.
    New,
    /// Metadata differs: hash it to learn whether the content really changed.
    NeedsHash,
    /// Size and ctime match: the recorded hash still stands.
    Unchanged,
}

/// Size and ctime, never mtime: a site user can set mtime to anything but
/// cannot set ctime.
pub fn classify(entry: Option<&BaselineEntry>, meta: &FileMeta) -> Change {
    match entry {
        None => Change::New,
        Some(e)
            if e.size == meta.size && e.ctime == meta.ctime && e.ctime_nsec == meta.ctime_nsec =>
        {
            Change::Unchanged
        }
        Some(_) => Change::NeedsHash,
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    v: u32,
    #[serde(default)]
    since: i64,
    #[serde(default)]
    rule_pack: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "k")]
enum Line {
    #[serde(rename = "f")]
    File {
        p: String,
        s: u64,
        c: i64,
        #[serde(default)]
        n: i64,
        h: String,
    },
    #[serde(rename = "t")]
    Trusted { p: String, h: String },
}

fn parse_hash(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

impl Baseline {
    /// `Ok(None)` for a missing, damaged, oversized or other-version file: the
    /// caller scans as a first scan. `Err` only for a real I/O failure.
    pub fn load(path: &Path) -> io::Result<Option<Baseline>> {
        load_with_limits(path, &LIMITS)
    }

    /// Writes next to `path` under a fresh O_EXCL 0600 name, fsyncs, renames
    /// over `path` and fsyncs the directory. A crash leaves the old baseline
    /// or the new one, never half of either.
    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;

        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;

        // NamedTempFile is created O_EXCL with 0600 and removed again if we
        // bail out before the rename.
        let tmp = tempfile::Builder::new()
            .prefix(".baseline-")
            .tempfile_in(dir)?;
        let mut gz = GzEncoder::new(BufWriter::new(tmp.as_file()), Compression::default());
        self.write_lines(&mut gz)?;
        gz.finish()?.flush()?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        File::open(dir)?.sync_all()
    }

    fn write_lines(&self, out: &mut impl Write) -> io::Result<()> {
        write_line(
            out,
            &Header {
                v: FORMAT_VERSION,
                since: self.since,
                rule_pack: self.rule_pack,
            },
        )?;
        for (p, e) in &self.entries {
            write_line(
                out,
                &Line::File {
                    p: p.clone(),
                    s: e.size,
                    c: e.ctime,
                    n: e.ctime_nsec,
                    h: hex::encode(e.sha256),
                },
            )?;
        }
        for (p, h) in &self.trusted {
            write_line(
                out,
                &Line::Trusted {
                    p: p.clone(),
                    h: hex::encode(h),
                },
            )?;
        }
        Ok(())
    }
}

fn write_line(out: &mut impl Write, v: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *out, v)?;
    out.write_all(b"\n")
}

fn load_with_limits(path: &Path, lim: &Limits) -> io::Result<Option<Baseline>> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if f.metadata()?.len() > lim.compressed {
        return Ok(None);
    }
    parse(BufReader::with_capacity(64 * 1024, f), lim)
}

/// Errors the gzip decoder raises for bad data. Anything else came from the
/// disk underneath it and stays an error.
fn is_damage(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::UnexpectedEof
    )
}

enum Step {
    Line,
    Eof,
    Damaged,
}

/// Reads one line into `buf`, holding at most `lim.line` bytes of it.
fn next_line(
    rd: &mut impl BufRead,
    buf: &mut Vec<u8>,
    seen: &mut u64,
    lim: &Limits,
) -> io::Result<Step> {
    buf.clear();
    // One byte over the cap tells a line that fits from one that does not.
    let n = match rd.by_ref().take(lim.line as u64 + 1).read_until(b'\n', buf) {
        Ok(n) => n,
        Err(e) if is_damage(&e) => return Ok(Step::Damaged),
        Err(e) => return Err(e),
    };
    *seen += n as u64;
    if n > lim.line || *seen > lim.inflated {
        return Ok(Step::Damaged);
    }
    Ok(if n == 0 { Step::Eof } else { Step::Line })
}

fn parse(src: impl Read, lim: &Limits) -> io::Result<Option<Baseline>> {
    let mut rd = BufReader::new(GzDecoder::new(src));
    let (mut seen, mut buf) = (0u64, Vec::new());

    if !matches!(next_line(&mut rd, &mut buf, &mut seen, lim)?, Step::Line) {
        return Ok(None);
    }
    let Ok(head) = serde_json::from_slice::<Header>(&buf) else {
        return Ok(None);
    };
    if head.v != FORMAT_VERSION {
        return Ok(None);
    }
    let mut b = Baseline {
        since: head.since,
        rule_pack: head.rule_pack,
        ..Baseline::default()
    };
    loop {
        match next_line(&mut rd, &mut buf, &mut seen, lim)? {
            Step::Line => {}
            Step::Eof => return Ok(Some(b)),
            Step::Damaged => return Ok(None),
        }
        if buf.trim_ascii().is_empty() {
            continue;
        }
        match serde_json::from_slice(&buf) {
            Ok(Line::File { p, s, c, n, h }) => {
                let Some(sha256) = parse_hash(&h) else {
                    return Ok(None);
                };
                b.entries.insert(
                    p,
                    BaselineEntry {
                        size: s,
                        ctime: c,
                        ctime_nsec: n,
                        sha256,
                    },
                );
            }
            Ok(Line::Trusted { p, h }) => {
                let Some(h) = parse_hash(&h) else {
                    return Ok(None);
                };
                b.trusted.insert(p, h);
            }
            Err(_) => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;

    fn entry(n: u8) -> BaselineEntry {
        BaselineEntry {
            size: 100 + n as u64,
            ctime: 1_700_000_000 + n as i64,
            ctime_nsec: 123_456_789,
            sha256: [n; 32],
        }
    }

    fn meta_of(rel: &str, md: &fs::Metadata) -> FileMeta {
        FileMeta {
            rel: rel.to_string(),
            size: md.len(),
            ctime: md.ctime(),
            ctime_nsec: md.ctime_nsec(),
            mode: md.mode(),
            uid: md.uid(),
            nlink: md.nlink(),
        }
    }

    fn sample() -> Baseline {
        let mut b = Baseline {
            since: 1_699_999_999,
            rule_pack: 7,
            ..Baseline::default()
        };
        b.entries
            .insert("wp-content/mu-plugins/a.php".into(), entry(1));
        b.entries.insert("index.php".into(), entry(2));
        b.entries
            .insert("sp ace/\"quote\"\\\u{e9}\t.php".into(), entry(3));
        b.trusted.insert("index.php".into(), [9; 32]);
        b
    }

    #[test]
    fn forged_mtime_is_still_a_change() {
        let t = tempfile::tempdir().expect("tmp");
        let f = t.path().join("shell.php");
        fs::write(&f, "AAAA").expect("write");
        let before = fs::metadata(&f).expect("stat");
        let old = BaselineEntry {
            sha256: [1; 32],
            ..entry_from(&meta_of("shell.php", &before))
        };

        // Rewrite with the same size, then put the old mtime back.
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&f, "BBBB").expect("rewrite");
        File::options()
            .write(true)
            .open(&f)
            .expect("open")
            .set_modified(before.modified().expect("mtime"))
            .expect("forge mtime");

        let after = fs::metadata(&f).expect("stat");
        assert_eq!(after.len(), before.len());
        assert_eq!(after.modified().expect("m"), before.modified().expect("m"));
        assert_eq!(
            classify(Some(&old), &meta_of("shell.php", &after)),
            Change::NeedsHash
        );
    }

    fn entry_from(m: &FileMeta) -> BaselineEntry {
        BaselineEntry {
            size: m.size,
            ctime: m.ctime,
            ctime_nsec: m.ctime_nsec,
            sha256: [0; 32],
        }
    }

    #[test]
    fn same_size_and_ctime_needs_no_hash() {
        let t = tempfile::tempdir().expect("tmp");
        let f = t.path().join("a.php");
        fs::write(&f, "<?php").expect("write");
        let m = meta_of("a.php", &fs::metadata(&f).expect("stat"));
        let e = entry_from(&m);
        assert_eq!(classify(Some(&e), &m), Change::Unchanged);
    }

    #[test]
    fn classify_covers_new_and_each_metadata_field() {
        let m = FileMeta {
            rel: "a.php".into(),
            size: 10,
            ctime: 50,
            ctime_nsec: 7,
            mode: 0o644,
            uid: 1000,
            nlink: 1,
        };
        let e = entry_from(&m);
        assert_eq!(classify(None, &m), Change::New);
        assert_eq!(classify(Some(&e), &m), Change::Unchanged);
        for tweak in [
            FileMeta {
                size: 11,
                ..m.clone()
            },
            FileMeta {
                ctime: 51,
                ..m.clone()
            },
            // Same second, later nanosecond: a quick same-size rewrite.
            FileMeta {
                ctime_nsec: 8,
                ..m.clone()
            },
        ] {
            assert_eq!(classify(Some(&e), &tweak), Change::NeedsHash);
        }
    }

    #[test]
    fn roundtrip_preserves_entries() {
        let t = tempfile::tempdir().expect("tmp");
        let p = t.path().join("7");
        let b = sample();
        b.save_atomic(&p).expect("save");
        assert_eq!(Baseline::load(&p).expect("load"), Some(b));
    }

    #[test]
    fn empty_baseline_roundtrips() {
        let t = tempfile::tempdir().expect("tmp");
        let p = t.path().join("1");
        let b = Baseline::default();
        b.save_atomic(&p).expect("save");
        assert_eq!(Baseline::load(&p).expect("load"), Some(b));
    }

    #[test]
    fn missing_file_is_none() {
        let t = tempfile::tempdir().expect("tmp");
        assert_eq!(Baseline::load(&t.path().join("nope")).expect("load"), None);
    }

    #[test]
    fn unreadable_path_is_an_error_not_none() {
        let t = tempfile::tempdir().expect("tmp");
        // Reading a directory fails with a real I/O error.
        assert!(Baseline::load(t.path()).is_err());
    }

    #[test]
    fn corrupt_file_loads_as_none() {
        let t = tempfile::tempdir().expect("tmp");
        let good = t.path().join("good");
        sample().save_atomic(&good).expect("save");
        let bytes = fs::read(&good).expect("read");

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("garbage", b"not gzip at all".to_vec()),
            ("empty", Vec::new()),
            ("truncated", bytes[..bytes.len() / 2].to_vec()),
            ("flipped", {
                let mut b = bytes.clone();
                let mid = b.len() / 2;
                b[mid] ^= 0xff;
                b
            }),
            ("plain json", b"{\"v\":1}\n".to_vec()),
        ];
        for (name, data) in cases {
            let p = t.path().join(name);
            fs::write(&p, data).expect("write");
            assert_eq!(Baseline::load(&p).expect("load"), None, "{name}");
        }
    }

    fn gz_file(path: &Path, text: &str) {
        let mut gz = GzEncoder::new(File::create(path).expect("create"), Compression::default());
        gz.write_all(text.as_bytes()).expect("write");
        gz.finish().expect("finish");
    }

    #[test]
    fn other_format_version_or_bad_line_loads_as_none() {
        let t = tempfile::tempdir().expect("tmp");
        let hash = "00".repeat(32);
        let file =
            format!("{{\"k\":\"f\",\"p\":\"a\",\"s\":1,\"c\":2,\"n\":3,\"h\":\"{hash}\"}}\n");
        let cases = [
            ("future", format!("{{\"v\":2,\"since\":1}}\n{file}")),
            ("no header", file.clone()),
            (
                "short hash",
                "{\"v\":1}\n{\"k\":\"f\",\"p\":\"a\",\"s\":1,\"c\":2,\"h\":\"ab\"}\n".to_string(),
            ),
            ("bad line", "{\"v\":1}\nnonsense\n".to_string()),
        ];
        for (name, text) in cases {
            let p = t.path().join(name.replace(' ', "_"));
            gz_file(&p, &text);
            assert_eq!(Baseline::load(&p).expect("load"), None, "{name}");
        }
        // The same lines under the current version do load.
        let p = t.path().join("ok");
        gz_file(&p, &format!("{{\"v\":1,\"since\":4}}\n{file}"));
        let b = Baseline::load(&p).expect("load").expect("some");
        assert_eq!(b.since, 4);
        assert_eq!(b.entries["a"].ctime_nsec, 3);
    }

    fn lim(compressed: u64, inflated: u64, line: usize) -> Limits {
        Limits {
            compressed,
            inflated,
            line,
        }
    }

    #[test]
    fn inflating_past_the_limit_loads_as_none() {
        let t = tempfile::tempdir().expect("tmp");
        let p = t.path().join("bomb");
        // Megabytes of lines inflate to far more than the test limit.
        let line = format!("{}\n", " ".repeat(1023));
        gz_file(&p, &line.repeat(4096));
        assert_eq!(
            load_with_limits(&p, &lim(1 << 30, 1 << 20, 4096)).expect("load"),
            None
        );
        // Under the limit the same helper still reads real baselines.
        let q = t.path().join("ok");
        sample().save_atomic(&q).expect("save");
        let big = lim(1 << 30, 1 << 20, 4096);
        assert_eq!(load_with_limits(&q, &big).expect("load"), Some(sample()));
        // Exactly at the limit is fine; one byte less is not.
        let mut plain = Vec::new();
        sample().write_lines(&mut plain).expect("lines");
        let n = plain.len() as u64;
        assert!(load_with_limits(&q, &lim(1 << 30, n, 4096))
            .expect("load")
            .is_some());
        assert_eq!(
            load_with_limits(&q, &lim(1 << 30, n - 1, 4096)).expect("load"),
            None
        );
    }

    #[test]
    fn a_line_without_a_newline_is_cut_off_at_the_line_limit() {
        let t = tempfile::tempdir().expect("tmp");
        let p = t.path().join("endless");
        // One "line" of 1 MiB with no newline anywhere, under every other cap.
        gz_file(&p, &"x".repeat(1 << 20));
        assert_eq!(
            load_with_limits(&p, &lim(1 << 30, 1 << 30, 1024)).expect("load"),
            None
        );
        // The same after a valid header, where an entry line should be.
        let q = t.path().join("endless-entry");
        gz_file(&q, &format!("{{\"v\":1}}\n{}", "y".repeat(1 << 20)));
        assert_eq!(
            load_with_limits(&q, &lim(1 << 30, 1 << 30, 1024)).expect("load"),
            None
        );
        // A line exactly at the cap (newline included) is accepted, one over is not.
        let r = t.path().join("real");
        sample().save_atomic(&r).expect("save");
        let mut plain = Vec::new();
        sample().write_lines(&mut plain).expect("lines");
        let longest = plain
            .split_inclusive(|b| *b == b'\n')
            .map(<[u8]>::len)
            .max();
        let longest = longest.expect("lines");
        assert_eq!(
            load_with_limits(&r, &lim(1 << 30, 1 << 30, longest)).expect("load"),
            Some(sample())
        );
        assert_eq!(
            load_with_limits(&r, &lim(1 << 30, 1 << 30, longest - 1)).expect("load"),
            None
        );
    }

    #[test]
    fn oversized_compressed_file_loads_as_none() {
        let t = tempfile::tempdir().expect("tmp");
        let p = t.path().join("big");
        fs::write(&p, vec![7u8; 4096]).expect("write");
        assert_eq!(
            load_with_limits(&p, &lim(1024, 1 << 30, 4096)).expect("load"),
            None
        );
    }

    #[test]
    fn save_is_atomic_and_0600() {
        let t = tempfile::tempdir().expect("tmp");
        let p = t.path().join("baselines").join("42");
        sample().save_atomic(&p).expect("first save");

        let mode = |p: &Path| fs::metadata(p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode(&p), 0o600);
        // The directory this created is private too.
        assert_eq!(mode(p.parent().expect("dir")), 0o700);

        // Replacing leaves only the new content and no temp file behind.
        let mut next = sample();
        next.since = 5;
        next.entries.clear();
        next.save_atomic(&p).expect("second save");
        assert_eq!(Baseline::load(&p).expect("load"), Some(next));
        assert_eq!(mode(&p), 0o600);
        let names: Vec<_> = fs::read_dir(p.parent().expect("dir"))
            .expect("ls")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("42")]);
    }

    #[test]
    fn a_failed_rename_leaves_no_temp_file() {
        let t = tempfile::tempdir().expect("tmp");
        // A directory squatting on the target name makes the rename fail.
        let blocked = t.path().join("blocked");
        fs::create_dir(&blocked).expect("mkdir");
        assert!(Baseline::default().save_atomic(&blocked).is_err());
        let names: Vec<_> = fs::read_dir(t.path())
            .expect("ls")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["blocked".to_string()]);
    }

    #[test]
    fn a_failed_save_keeps_the_old_baseline() {
        // Root ignores directory permissions, so the save would succeed.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let t = tempfile::tempdir().expect("tmp");
        let dir = t.path().join("baselines");
        let p = dir.join("42");
        sample().save_atomic(&p).expect("save");

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).expect("chmod");
        let mut other = sample();
        other.since = 1;
        let res = other.save_atomic(&p);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod back");

        assert!(res.is_err());
        assert_eq!(Baseline::load(&p).expect("load"), Some(sample()));
        let names: Vec<_> = fs::read_dir(&dir).expect("ls").collect();
        assert_eq!(names.len(), 1);
    }
}
