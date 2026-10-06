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

use hyperion_types::waf::WafHit;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Upper bound on what one ingest pass reads from one log, so a flood
/// cannot stall the tick. The rest is picked up next time.
pub const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;

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
    let mut f = line.trim_end_matches(['\r', '\n']).splitn(6, '\t');
    let msec = f.next()?;
    let ip = f.next()?;
    let rule = f.next()?;
    let method = f.next()?;
    let uri = f.next()?;
    let ua = f.next()?;
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
    })
}

/// Read the whole lines appended since `pos`. Returns the parsed hits and
/// the position to store for next time.
///
/// A different inode (rotated) or a file shorter than the offset
/// (truncated) restarts at 0. A partial last line is left for the next
/// pass. A single line longer than [`MAX_READ_BYTES`] is skipped rather
/// than wedging the reader forever.
pub fn read_new(path: &Path, pos: Option<LogPos>) -> std::io::Result<(Vec<WafHit>, LogPos)> {
    use std::os::unix::fs::MetadataExt;
    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    let inode = meta.ino();
    let len = meta.len();
    let mut offset = match pos {
        Some(p) if p.inode == inode && p.offset <= len => p.offset,
        _ => 0,
    };
    if offset == len {
        return Ok((Vec::new(), LogPos { inode, offset }));
    }
    file.seek(SeekFrom::Start(offset))?;
    let want = (len - offset).min(MAX_READ_BYTES);
    let mut buf = Vec::with_capacity(want as usize);
    file.take(want).read_to_end(&mut buf)?;
    let consumed = match buf.iter().rposition(|&b| b == b'\n') {
        Some(i) => i + 1,
        // No newline in a full window: one absurd line. Skip it.
        None if want == MAX_READ_BYTES => buf.len(),
        // A line still being written — leave it for next time.
        None => 0,
    };
    let hits = String::from_utf8_lossy(&buf[..consumed])
        .lines()
        .filter_map(parse_line)
        .collect();
    offset += consumed as u64;
    Ok((hits, LogPos { inode, offset }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
    fn reads_incrementally_and_survives_rotation_and_partial_lines() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("h.log");
        let line = |n: i64| format!("{n}.000\t1.1.1.1\tprobe_args\tGET\t/\tua\n");
        std::fs::write(&path, line(1) + &line(2)).expect("w");
        let (hits, pos) = read_new(&path, None).expect("read");
        assert_eq!(hits.len(), 2);

        // Nothing new: nothing read, position unchanged.
        let (hits, pos2) = read_new(&path, Some(pos)).expect("read");
        assert!(hits.is_empty());
        assert_eq!(pos, pos2);

        // A half-written line waits for its newline.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        f.write_all(b"3.000\t1.1.1.1\tprobe_args\tGET").expect("w");
        let (hits, pos3) = read_new(&path, Some(pos2)).expect("read");
        assert!(hits.is_empty());
        f.write_all(b"\t/\tua\n").expect("w");
        let (hits, pos4) = read_new(&path, Some(pos3)).expect("read");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ts, 3);

        // Rotation: a new file at the same path starts from 0.
        std::fs::rename(&path, dir.path().join("h.log.1")).expect("mv");
        std::fs::write(&path, line(9)).expect("w");
        let (hits, _) = read_new(&path, Some(pos4)).expect("read");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ts, 9);
    }

    #[test]
    fn truncation_restarts_from_zero() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("h.log");
        std::fs::write(&path, "1.0\t1.1.1.1\tr\tGET\t/\tua\n".repeat(3)).expect("w");
        let (_, pos) = read_new(&path, None).expect("read");
        std::fs::write(&path, "5.0\t1.1.1.1\tr\tGET\t/\tua\n").expect("w");
        let (hits, _) = read_new(&path, Some(pos)).expect("read");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ts, 5);
    }
}
