//! Reader for the per-hosting WAF hit log (`/var/log/hyperion/waf/<id>.log`).
//!
//! The writer is the `hyperion_waf` log_format in `nginx::render_waf_conf`:
//! six tab-separated fields — `$msec`, `$remote_addr`, `$hyperion_waf`,
//! `$request_method`, `$request_uri`, `$http_user_agent` — with
//! `escape=json`, so a value can never contain a raw tab or newline and a
//! client cannot forge a field boundary. Change both or neither.
//!
//! Everything after the address is attacker-controlled. The parser is
//! strict about the fields a ban decision rests on (time, address, rule
//! tag) and only unescapes + bounds the rest.

use hyperion_types::waf::{WafBatch, WafHit};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// What one ingest pass reads from one log at most.
///
/// The ingest runs on the 5-minute fail2ban tick, and a ban needs hits
/// from inside the ban window. A reader that falls behind would decide
/// bans on stale lines and never catch an ongoing flood, so a backlog past
/// this budget is SKIPPED from its oldest end (see [`read_new`]) rather
/// than queued. 64 MiB per tick is ~1,800 refusals a second sustained.
pub const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;

/// Where the last pass stopped in one log: the file's inode (a rotation
/// replaces the file) and the byte offset of the first unread line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogPos {
    pub inode: u64,
    pub offset: u64,
}

impl LogPos {
    /// Stored form in `hosting_kv` (`"<inode>:<offset>"`).
    pub fn encode(&self) -> String {
        format!("{}:{}", self.inode, self.offset)
    }

    pub fn decode(s: &str) -> Option<Self> {
        let (i, o) = s.trim().split_once(':')?;
        Some(Self {
            inode: i.parse().ok()?,
            offset: o.parse().ok()?,
        })
    }
}

/// Undo nginx's `escape=json`. Unknown escapes are kept literally.
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('u') => {
                let hex: String = it.by_ref().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                }
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// A rule tag as nginx wrote it: the ids in the catalogue are short
/// `[a-z_]` words. Anything else is reported as `other`.
fn clean_rule(s: &str) -> String {
    if !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        s.to_string()
    } else {
        "other".to_string()
    }
}

/// Parse one log line. `None` for anything malformed — including an
/// address that does not parse, since a hit without a real address can
/// neither be shown honestly nor banned.
pub fn parse_line(line: &str) -> Option<WafHit> {
    let mut f = line.trim_end_matches(['\r', '\n']).splitn(7, '\t');
    let msec = f.next()?;
    let ip = f.next()?;
    let rule = f.next()?;
    let method = f.next()?;
    let uri = f.next()?;
    let ua = f.next()?;
    // `$http_sec_fetch_site`, absent from lines written before it was added.
    // Browsers send it on every request and a page cannot forge it: a
    // `cross-site`/`same-site` request was made BY ANOTHER PAGE — an <img>
    // or a script on someone else's site — so its refusal says nothing
    // about the visitor and must never earn them a ban.
    let fetch_site = f.next().unwrap_or("");
    let ts = msec.split('.').next()?.parse::<i64>().ok()?;
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let method = if method.len() <= 16 && method.bytes().all(|b| b.is_ascii_alphabetic()) {
        method.to_string()
    } else {
        "?".to_string()
    };
    Some(WafHit {
        ts,
        ip: ip.to_string(),
        rule: clean_rule(rule),
        method,
        uri: unescape(uri),
        ua: unescape(ua),
        cross_site: matches!(fetch_site, "cross-site" | "same-site"),
        detail: String::new(),
    })
}

/// Where logrotate (`delaycompress`) leaves yesterday's file — the renamed
/// original (`create`) or the copy (`copytruncate`).
fn rotated_sibling(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    Some(path.with_file_name(format!("{name}.1")))
}

/// Feed every complete line of `reader` (at most `budget` bytes) into
/// `batch`. Returns the bytes consumed: a trailing line without its newline
/// is still being written and is left for the next pass.
fn read_lines<R: Read>(
    reader: R,
    budget: u64,
    on_line: &mut dyn FnMut(&str),
) -> std::io::Result<u64> {
    let mut r = BufReader::new(reader.take(budget));
    let mut line = Vec::with_capacity(512);
    let mut consumed = 0u64;
    loop {
        line.clear();
        let n = r.read_until(b'\n', &mut line)?;
        if n == 0 || line.last() != Some(&b'\n') {
            break;
        }
        consumed += n as u64;
        on_line(&String::from_utf8_lossy(&line));
    }
    Ok(consumed)
}

/// Read the whole lines appended since `pos`, aggregated. Returns the batch
/// and the position to store for next time. See [`read_new_lines`].
pub fn read_new(path: &Path, pos: Option<LogPos>) -> std::io::Result<(WafBatch, LogPos)> {
    read_new_with_budget(path, pos, MAX_READ_BYTES)
}

fn read_new_with_budget(
    path: &Path,
    pos: Option<LogPos>,
    budget: u64,
) -> std::io::Result<(WafBatch, LogPos)> {
    let mut batch = WafBatch::default();
    let (pos, skipped) = read_new_lines(path, pos, budget, &mut |line| {
        if let Some(hit) = parse_line(line) {
            batch.push(hit);
        }
    })?;
    batch.skipped_bytes = skipped;
    Ok((batch, pos))
}

/// Hand every whole line appended to `path` since `pos` to `on_line`.
/// Returns the position to store for next time and the bytes skipped.
///
/// - Rotated (the inode changed): the rest of the previous file is read
///   from `<log>.1` first, so the lines written between the last pass and
///   the rotation are not lost, then the new file from the start.
/// - Truncated in place (`copytruncate`): the rest is read from the copy in
///   `<log>.1`, then the live file from the start.
/// - More than `budget` unread: skip to the newest `budget` bytes, starting
///   at a line boundary. Bans are decided on recent hits; old ones only feed
///   totals.
/// - A trailing line without its newline is still being written and is
///   left for the next pass.
pub fn read_new_lines(
    path: &Path,
    pos: Option<LogPos>,
    budget: u64,
    on_line: &mut dyn FnMut(&str),
) -> std::io::Result<(LogPos, u64)> {
    use std::os::unix::fs::MetadataExt;
    let mut skipped = 0u64;
    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    let inode = meta.ino();
    let len = meta.len();

    let mut offset = match pos {
        Some(p) if p.inode == inode && p.offset <= len => p.offset,
        Some(p) if p.inode == inode => {
            // Shrank under us: logrotate's `copytruncate` copied the file to
            // `<log>.1` and emptied it. The lines we had not read yet are in
            // the copy, from our old offset on.
            if let Some(rot) = rotated_sibling(path) {
                if let Ok(mut copy) = std::fs::File::open(&rot) {
                    let copy_len = copy.metadata().map(|m| m.len()).unwrap_or(0);
                    if p.offset < copy_len {
                        copy.seek(SeekFrom::Start(p.offset))?;
                        read_lines(copy, (copy_len - p.offset).min(budget), on_line)?;
                    }
                }
            }
            0
        }
        Some(p) => {
            // Finish the file we were reading before it was rotated away.
            if let Some(rot) = rotated_sibling(path) {
                if let Ok(old) = std::fs::File::open(&rot) {
                    if let Ok(m) = old.metadata() {
                        if m.ino() == p.inode && p.offset < m.len() {
                            let mut old = old;
                            old.seek(SeekFrom::Start(p.offset))?;
                            read_lines(old, (m.len() - p.offset).min(budget), on_line)?;
                        }
                    }
                }
            }
            0
        }
        _ => 0,
    };

    if len - offset > budget {
        let start = len - budget;
        skipped += start - offset;
        // Land on a line boundary: unless `start` already is one, drop the
        // rest of the line it falls inside.
        file.seek(SeekFrom::Start(start - 1))?;
        let mut prev = [0u8; 1];
        file.read_exact(&mut prev)?;
        let mut n = 0;
        if prev[0] != b'\n' {
            let mut partial = Vec::new();
            n = BufReader::new((&mut file).take(budget)).read_until(b'\n', &mut partial)? as u64;
        }
        skipped += n;
        offset = start + n;
    }
    file.seek(SeekFrom::Start(offset))?;
    offset += read_lines(&mut file, len - offset, on_line)?;
    Ok((LogPos { inode, offset }, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn line(ts: i64, ip: &str, rule: &str) -> String {
        format!("{ts}.000\t{ip}\t{rule}\tGET\t/\tua\n")
    }

    fn ts_of(b: &WafBatch) -> Vec<i64> {
        b.recent.iter().map(|h| h.ts).collect()
    }

    #[test]
    fn parses_a_real_nginx_line() {
        // Captured from nginx 1.22 with the hyperion_waf log_format.
        let h = parse_line("1791282886.136\t127.0.0.1\txmlrpc\tGET\t/xmlrpc.php\ta\\tb")
            .expect("parse");
        assert_eq!(h.ts, 1_791_282_886);
        assert_eq!(h.ip, "127.0.0.1");
        assert_eq!(h.rule, "xmlrpc");
        assert_eq!(h.method, "GET");
        assert_eq!(h.uri, "/xmlrpc.php");
        assert_eq!(h.ua, "a\tb", "escaped tab restored, not a field split");
    }

    #[test]
    fn rejects_malformed_and_cleans_hostile_fields() {
        assert!(parse_line("").is_none());
        assert!(
            parse_line("x\t1.1.1.1\tr\tGET\t/\tua").is_none(),
            "bad time"
        );
        assert!(parse_line("1.0\tnot-ip\tr\tGET\t/\tua").is_none(), "bad ip");
        assert!(parse_line("1.0\t1.1.1.1\tr\tGET\t/").is_none(), "short");
        let h = parse_line("1.0\t2001:db8::1\tDROP TABLE\tG E T\t/\\\"x\t\\u003cscript\\u003e")
            .expect("parse");
        assert_eq!(h.rule, "other");
        assert_eq!(h.method, "?");
        assert_eq!(h.uri, "/\"x");
        assert_eq!(h.ua, "<script>");
        assert_eq!(h.ip, "2001:db8::1");
    }

    #[test]
    fn pos_round_trips() {
        let p = LogPos {
            inode: 42,
            offset: 7,
        };
        assert_eq!(LogPos::decode(&p.encode()), Some(p));
        assert_eq!(LogPos::decode("junk"), None);
    }

    #[test]
    fn reads_incrementally_and_waits_for_partial_lines() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("h.log");
        std::fs::write(
            &path,
            line(1, "1.1.1.1", "probe_args") + &line(2, "1.1.1.1", "probe_args"),
        )
        .expect("w");
        let (b, pos) = read_new(&path, None).expect("read");
        assert_eq!(ts_of(&b), vec![1, 2]);

        // Nothing new: nothing read, position unchanged.
        let (b, pos2) = read_new(&path, Some(pos)).expect("read");
        assert!(b.is_empty());
        assert_eq!(pos, pos2);

        // A half-written line waits for its newline.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        f.write_all(b"3.000\t1.1.1.1\tprobe_args\tGET").expect("w");
        let (b, pos3) = read_new(&path, Some(pos2)).expect("read");
        assert!(b.is_empty());
        assert_eq!(pos3, pos2);
        f.write_all(b"\t/\tua\n").expect("w");
        let (b, _) = read_new(&path, Some(pos3)).expect("read");
        assert_eq!(ts_of(&b), vec![3]);
    }

    /// The lines written between the last pass and a logrotate are read
    /// from `<log>.1`, then the new file from its start.
    #[test]
    fn rotation_keeps_the_lines_written_just_before_it() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("h.log");
        std::fs::write(&path, line(1, "1.1.1.1", "probe_args")).expect("w");
        let (_, pos) = read_new(&path, None).expect("read");
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        f.write_all(line(2, "1.1.1.1", "probe_args").as_bytes())
            .expect("w");
        std::fs::rename(&path, dir.path().join("h.log.1")).expect("mv");
        std::fs::write(&path, line(9, "1.1.1.1", "probe_args")).expect("w");
        let (b, pos2) = read_new(&path, Some(pos)).expect("read");
        assert_eq!(ts_of(&b), vec![2, 9]);
        // And the new file is tracked from here on.
        let (b, _) = read_new(&path, Some(pos2)).expect("read");
        assert!(b.is_empty());
    }

    /// logrotate `copytruncate`: same inode, emptied; the unread tail is in
    /// the copy.
    #[test]
    fn copytruncate_keeps_the_lines_written_just_before_it() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("h.log");
        std::fs::write(&path, line(1, "1.1.1.1", "r") + &line(2, "1.1.1.1", "r")).expect("w");
        let (_, pos) = read_new(&path, None).expect("read");
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        f.write_all(line(3, "1.1.1.1", "r").as_bytes()).expect("w");
        std::fs::copy(&path, dir.path().join("h.log.1")).expect("copy");
        f.set_len(0).expect("truncate");
        f.write_all(line(4, "1.1.1.1", "r").as_bytes()).expect("w");
        let (b, pos2) = read_new(&path, Some(pos)).expect("read");
        assert_eq!(ts_of(&b), vec![3, 4]);
        assert_eq!(pos2.inode, pos.inode);
        let (b, _) = read_new(&path, Some(pos2)).expect("read");
        assert!(b.is_empty());
    }

    #[test]
    fn cross_site_requests_never_count_towards_a_ban() {
        let ok = |tail: &str| {
            parse_line(&format!(
                "1.0\t8.8.8.8\tprobe_args\tGET\t/?x=../a\tua{tail}"
            ))
            .expect("parse")
        };
        assert!(!ok("").cross_site, "old 6-field lines");
        assert!(!ok("\t").cross_site);
        assert!(!ok("\tnone").cross_site);
        assert!(!ok("\tsame-origin").cross_site);
        assert!(ok("\tcross-site").cross_site);
        assert!(ok("\tsame-site").cross_site);
        let b = WafBatch::from_hits([ok("\tcross-site"), ok("\tnone")]);
        assert_eq!(b.ip_minute.values().sum::<i64>(), 1);
        assert_eq!(b.hourly.values().sum::<i64>(), 2, "still shown");
    }

    #[test]
    fn truncation_restarts_from_zero() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("h.log");
        std::fs::write(&path, line(1, "1.1.1.1", "r").repeat(3)).expect("w");
        let (_, pos) = read_new(&path, None).expect("read");
        std::fs::write(&path, line(5, "1.1.1.1", "r")).expect("w");
        let (b, _) = read_new(&path, Some(pos)).expect("read");
        assert_eq!(ts_of(&b), vec![5]);
    }

    /// A backlog over the budget is skipped from its OLDEST end, starting at
    /// a line boundary, so the newest hits — the ones a ban needs — are read.
    #[test]
    fn a_backlog_over_budget_reads_the_newest_lines() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("h.log");
        let body: String = (100..200)
            .map(|t| line(t, "1.1.1.1", "probe_args"))
            .collect();
        std::fs::write(&path, &body).expect("w");
        let one = line(100, "1.1.1.1", "probe_args").len() as u64;
        // Budget for ten and a half lines: the half line is dropped.
        let (b, pos) = read_new_with_budget(&path, None, one * 10 + one / 2).expect("read");
        assert_eq!(ts_of(&b), (190..200).collect::<Vec<_>>());
        assert_eq!(b.skipped_bytes, one * 90);
        assert_eq!(pos.offset, body.len() as u64);
        // A budget that ends exactly on a line boundary loses no whole line.
        let (b, _) = read_new_with_budget(&path, None, one * 10).expect("read");
        assert_eq!(ts_of(&b), (190..200).collect::<Vec<_>>());
    }
}
