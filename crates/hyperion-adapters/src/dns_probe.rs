//! DNS-01 pre-flight: do the zone's AUTHORITATIVE nameservers serve the
//! challenge TXT values yet?
//!
//! Telling Let's Encrypt "ready" is a one-shot: if its resolvers then see
//! NXDOMAIN, the authorization goes Invalid, the order dies, and the next
//! attempt gets a brand-new order with brand-new TXT values — the operator
//! publishes, clicks too early, and is handed different values every time.
//! So before `set_ready` we ask the nameservers Let's Encrypt itself ends
//! up asking (the zone's NS set, queried directly with recursion off, so no
//! resolver cache can hide a missing or stale record) and refuse to go on
//! until every one that answers has every expected value.
//!
//! A deliberately small client — UDP with EDNS0, TCP on truncation, the
//! handful of record types the walk needs — rather than a resolver crate.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

const T_A: u16 = 1;
const T_NS: u16 = 2;
const T_CNAME: u16 = 5;
const T_TXT: u16 = 16;
const T_AAAA: u16 = 28;
const T_OPT: u16 = 41;

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const ATTEMPTS: u32 = 2;
/// Public recursors tried after the host's own (`/etc/resolv.conf`). They
/// are only used to FIND the zone's nameservers; the verdict itself always
/// comes from those nameservers.
const PUBLIC_RESOLVERS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
];
/// `_acme-challenge` delegated by CNAME (acme-dns and friends) is followed,
/// like Let's Encrypt does — but not forever.
const MAX_CNAME_HOPS: usize = 5;

#[derive(Debug, Clone, PartialEq)]
enum RData {
    /// NS / CNAME target.
    Name(String),
    /// One TXT record, its character-strings joined.
    Txt(String),
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Other,
}

#[derive(Debug, Clone)]
struct Rr {
    name: String,
    rtype: u16,
    data: RData,
}

#[derive(Debug, Clone)]
struct Reply {
    id: u16,
    rcode: u8,
    aa: bool,
    tc: bool,
    answers: Vec<Rr>,
}

fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn build_query(id: u16, name: &str, qtype: u16, recursion: bool) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.push(if recursion { 0x01 } else { 0x00 }); // QR=0 OPCODE=0 RD
    q.push(0x00);
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT (EDNS0 OPT)
    for label in norm(name).split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 {
            return Err(format!("label too long in {name}"));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
                                              // OPT: root owner, 1232-byte payload, no flags, no options.
    q.push(0);
    q.extend_from_slice(&T_OPT.to_be_bytes());
    q.extend_from_slice(&1232u16.to_be_bytes());
    q.extend_from_slice(&0u32.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    Ok(q)
}

fn read_u16(buf: &[u8], pos: usize) -> Result<u16, String> {
    buf.get(pos..pos + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| "truncated DNS message".to_string())
}

/// Decode a (possibly compressed) name at `pos`; returns it and the offset
/// just past it in the original stream.
fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos).ok_or("truncated name")? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Ok((labels.join("."), end.unwrap_or(pos + 1)));
                }
                let label = buf.get(pos + 1..pos + 1 + len).ok_or("truncated label")?;
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                pos += 1 + len;
            }
            0xC0 => {
                let ptr = (read_u16(buf, pos)? & 0x3FFF) as usize;
                end.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > 32 {
                    return Err("name compression loop".into());
                }
                pos = ptr;
            }
            _ => return Err("unsupported label type".into()),
        }
    }
}

fn parse_reply(buf: &[u8]) -> Result<Reply, String> {
    if buf.len() < 12 {
        return Err("short DNS reply".into());
    }
    let id = read_u16(buf, 0)?;
    let flags = read_u16(buf, 2)?;
    let qd = read_u16(buf, 4)?;
    let an = read_u16(buf, 6)?;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, p) = read_name(buf, pos)?;
        pos = p + 4;
    }
    let mut answers = Vec::with_capacity(an as usize);
    for _ in 0..an {
        let (name, p) = read_name(buf, pos)?;
        let rtype = read_u16(buf, p)?;
        let rdlen = read_u16(buf, p + 8)? as usize;
        let start = p + 10;
        let rdata = buf.get(start..start + rdlen).ok_or("truncated rdata")?;
        let data = match rtype {
            T_NS | T_CNAME => RData::Name(read_name(buf, start)?.0),
            T_TXT => {
                let mut s = String::new();
                let mut i = 0;
                while i < rdata.len() {
                    let l = rdata[i] as usize;
                    let chunk = rdata.get(i + 1..i + 1 + l).ok_or("truncated TXT")?;
                    s.push_str(&String::from_utf8_lossy(chunk));
                    i += 1 + l;
                }
                RData::Txt(s)
            }
            T_A if rdlen == 4 => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            T_AAAA if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                RData::Aaaa(Ipv6Addr::from(o))
            }
            _ => RData::Other,
        };
        answers.push(Rr { name, rtype, data });
        pos = start + rdlen;
    }
    Ok(Reply {
        id,
        rcode: (flags & 0x000F) as u8,
        aa: flags & 0x0400 != 0,
        tc: flags & 0x0200 != 0,
        answers,
    })
}

async fn query_udp(server: SocketAddr, packet: &[u8], id: u16) -> Result<Reply, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("bind: {e}"))?;
    sock.connect(server)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    sock.send(packet).await.map_err(|e| format!("send: {e}"))?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock
            .recv(&mut buf)
            .await
            .map_err(|e| format!("recv: {e}"))?;
        // A stray datagram with another id is ignored, not trusted.
        if let Ok(r) = parse_reply(&buf[..n]) {
            if r.id == id {
                return Ok(r);
            }
        }
    }
}

async fn query_tcp(server: SocketAddr, packet: &[u8], id: u16) -> Result<Reply, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(server)
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;
    let mut framed = (packet.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(packet);
    s.write_all(&framed)
        .await
        .map_err(|e| format!("tcp send: {e}"))?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len)
        .await
        .map_err(|e| format!("tcp recv: {e}"))?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)
        .await
        .map_err(|e| format!("tcp recv: {e}"))?;
    let r = parse_reply(&buf)?;
    if r.id != id {
        return Err("tcp reply id mismatch".into());
    }
    Ok(r)
}

async fn query(server: IpAddr, name: &str, qtype: u16, recursion: bool) -> Result<Reply, String> {
    let addr = SocketAddr::new(server, 53);
    let mut last = String::from("no attempt");
    for _ in 0..ATTEMPTS {
        let id: u16 = rand::random();
        let packet = build_query(id, name, qtype, recursion)?;
        match tokio::time::timeout(QUERY_TIMEOUT, query_udp(addr, &packet, id)).await {
            Ok(Ok(r)) if r.tc => {
                return tokio::time::timeout(QUERY_TIMEOUT, query_tcp(addr, &packet, id))
                    .await
                    .map_err(|_| "timed out (tcp)".to_string())?;
            }
            Ok(Ok(r)) => return Ok(r),
            Ok(Err(e)) => last = e,
            Err(_) => last = "timed out".into(),
        }
    }
    Err(last)
}

/// The host's own recursors, then the public fallbacks. A node whose
/// resolv.conf points at a local stub (systemd-resolved) still works: the
/// stub recurses.
fn recursors() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some("nameserver"))
                .then(|| it.next())
                .flatten()
                .and_then(|ip| ip.split('%').next()?.parse().ok())
        })
        .collect();
    for ip in PUBLIC_RESOLVERS {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// Ask the recursors in turn; the first that answers at all wins.
async fn recursive(resolvers: &[IpAddr], name: &str, qtype: u16) -> Result<Reply, String> {
    let mut errs = Vec::new();
    for r in resolvers {
        match query(*r, name, qtype, true).await {
            Ok(reply) => return Ok(reply),
            Err(e) => errs.push(format!("{r}: {e}")),
        }
    }
    Err(format!("no DNS resolver answered ({})", errs.join("; ")))
}

/// The zone `name` lives in and that zone's NS host names: the closest
/// enclosing name that has its own NS set.
async fn find_zone(resolvers: &[IpAddr], name: &str) -> Result<(String, Vec<String>), String> {
    let name = norm(name);
    let labels: Vec<&str> = name.split('.').collect();
    for i in 0..labels.len().saturating_sub(1) {
        let candidate = labels[i..].join(".");
        let reply = recursive(resolvers, &candidate, T_NS).await?;
        let ns: Vec<String> = reply
            .answers
            .iter()
            .filter(|rr| rr.rtype == T_NS && rr.name == candidate)
            .filter_map(|rr| match &rr.data {
                RData::Name(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        if !ns.is_empty() {
            return Ok((candidate, ns));
        }
    }
    Err(format!(
        "could not find the DNS zone (nameservers) for {name}"
    ))
}

/// IPv4 addresses of a nameserver, or IPv6 when it has no IPv4 at all.
async fn ns_addresses(resolvers: &[IpAddr], host: &str) -> Vec<IpAddr> {
    for qtype in [T_A, T_AAAA] {
        if let Ok(r) = recursive(resolvers, host, qtype).await {
            let ips: Vec<IpAddr> = r
                .answers
                .iter()
                .filter_map(|rr| match rr.data {
                    RData::A(ip) => Some(IpAddr::V4(ip)),
                    RData::Aaaa(ip) => Some(IpAddr::V6(ip)),
                    _ => None,
                })
                .collect();
            if !ips.is_empty() {
                return ips;
            }
        }
    }
    Vec::new()
}

/// What one authoritative server said about one TXT name.
#[derive(Debug, Clone, PartialEq)]
pub enum Seen {
    Values(Vec<String>),
    NxDomain,
    /// The name is a CNAME to this target (Let's Encrypt follows it).
    Cname(String),
    Unreachable(String),
}

#[derive(Debug, Clone)]
pub struct NsAnswer {
    pub server: String,
    pub seen: Seen,
}

fn interpret(name: &str, reply: &Reply) -> Seen {
    let name = norm(name);
    if reply.rcode == RCODE_NXDOMAIN {
        return Seen::NxDomain;
    }
    if reply.rcode != RCODE_NOERROR {
        return Seen::Unreachable(format!("rcode {}", reply.rcode));
    }
    if !reply.aa {
        return Seen::Unreachable("answer was not authoritative".into());
    }
    if let Some(target) = reply.answers.iter().find_map(|rr| match &rr.data {
        RData::Name(t) if rr.rtype == T_CNAME && rr.name == name => Some(t.clone()),
        _ => None,
    }) {
        return Seen::Cname(target);
    }
    Seen::Values(
        reply
            .answers
            .iter()
            .filter(|rr| rr.rtype == T_TXT && rr.name == name)
            .filter_map(|rr| match &rr.data {
                RData::Txt(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
    )
}

/// Ask every authoritative server of `name`'s zone, concurrently.
async fn ask_authorities(
    resolvers: &[IpAddr],
    name: &str,
) -> Result<(String, Vec<NsAnswer>), String> {
    let (zone, hosts) = find_zone(resolvers, name).await?;
    let mut set = tokio::task::JoinSet::new();
    for host in hosts {
        let resolvers = resolvers.to_vec();
        let name = name.to_string();
        set.spawn(async move {
            let ips = ns_addresses(&resolvers, &host).await;
            let Some(ip) = ips.first().copied() else {
                return NsAnswer {
                    server: host.clone(),
                    seen: Seen::Unreachable("no address".into()),
                };
            };
            let seen = match query(ip, &name, T_TXT, false).await {
                Ok(r) => interpret(&name, &r),
                Err(e) => Seen::Unreachable(e),
            };
            NsAnswer {
                server: format!("{host} ({ip})"),
                seen,
            }
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(a) = r {
            out.push(a);
        }
    }
    out.sort_by(|a, b| a.server.cmp(&b.server));
    Ok((zone, out))
}

/// The pure verdict for one record name: `Ok` when at least one
/// authoritative server answered and every one that answered serves all
/// of `expected`. Extra (stale) values are fine — Let's Encrypt accepts any
/// match. An unreachable server alone doesn't block (it may well be
/// reachable from Let's Encrypt), but nobody answering does.
pub fn verdict(name: &str, expected: &[String], answers: &[NsAnswer]) -> Result<(), String> {
    let mut problems = Vec::new();
    let mut answered = 0;
    for a in answers {
        match &a.seen {
            Seen::Values(vals) => {
                answered += 1;
                let missing: Vec<&String> = expected.iter().filter(|e| !vals.contains(e)).collect();
                if !missing.is_empty() {
                    let have = match vals.len() {
                        0 => "no TXT values".to_string(),
                        1..=3 => format!("only {}", vals.join(", ")),
                        n => format!("{n} other values, e.g. {}", vals[..2].join(", ")),
                    };
                    problems.push(format!(
                        "{}: missing {} (has {have})",
                        a.server,
                        missing
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            Seen::NxDomain => {
                answered += 1;
                problems.push(format!("{}: NXDOMAIN — the name does not exist", a.server));
            }
            Seen::Cname(t) => {
                answered += 1;
                problems.push(format!("{}: unexpected CNAME to {t}", a.server));
            }
            Seen::Unreachable(_) => {}
        }
    }
    if answered == 0 {
        let why: Vec<String> = answers
            .iter()
            .map(|a| match &a.seen {
                Seen::Unreachable(e) => format!("{}: {e}", a.server),
                _ => a.server.clone(),
            })
            .collect();
        return Err(format!(
            "{name}: no authoritative nameserver answered ({})",
            why.join("; ")
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!("{name}: {}", problems.join("; ")))
    }
}

/// The name as typed into a DNS provider's zone editor, most of which
/// append the zone themselves.
fn relative_to_zone(name: &str, zone: &str) -> String {
    let name = norm(name);
    name.strip_suffix(&format!(".{zone}"))
        .map(str::to_string)
        .unwrap_or(name)
}

/// Check every `(name, value)` pair against the authoritative servers.
/// `Err` carries an operator-facing report of what each server serves.
///
/// Only a failure to reach any recursor at all (outbound DNS blocked on
/// this node) is surfaced as [`ProbeError::NoResolver`] so the caller can
/// decide to proceed: that says nothing about the record.
pub async fn check_txt_published(records: &[(String, String)]) -> Result<(), ProbeError> {
    let resolvers = recursors();
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (n, v) in records {
        by_name.entry(norm(n)).or_default().push(v.clone());
    }
    let mut problems = Vec::new();
    for (name, expected) in &by_name {
        let mut current = name.clone();
        let mut hops = 0;
        loop {
            let (zone, answers) = match ask_authorities(&resolvers, &current).await {
                Ok(v) => v,
                Err(e) if e.starts_with("no DNS resolver answered") => {
                    return Err(ProbeError::NoResolver(e))
                }
                Err(e) => {
                    problems.push(format!("{current}: {e}"));
                    break;
                }
            };
            // Every server agreeing on one CNAME = a delegated challenge
            // name; follow it the way Let's Encrypt will.
            let cnames: Vec<&String> = answers
                .iter()
                .filter_map(|a| match &a.seen {
                    Seen::Cname(t) => Some(t),
                    _ => None,
                })
                .collect();
            if !cnames.is_empty()
                && cnames.len() == answers.len()
                && cnames.iter().all(|t| *t == cnames[0])
                && hops < MAX_CNAME_HOPS
            {
                current = cnames[0].clone();
                hops += 1;
                continue;
            }
            if let Err(e) = verdict(&current, expected, &answers) {
                let nx = answers.iter().any(|a| a.seen == Seen::NxDomain);
                let hint = if nx {
                    format!(
                        " — in the zone editor for {zone} the record name is usually just \
                         \"{}\" (many editors append .{zone} themselves)",
                        relative_to_zone(&current, &zone)
                    )
                } else {
                    String::new()
                };
                problems.push(format!("{e}{hint}"));
            }
            break;
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(ProbeError::NotVisible(problems.join(" || ")))
    }
}

#[derive(Debug, Clone)]
pub enum ProbeError {
    /// The authoritative servers don't (all) serve the values yet.
    NotVisible(String),
    /// No recursor reachable — the check could not run.
    NoResolver(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built authoritative reply: question + answers, with a
    /// compression pointer back to the question name.
    fn reply_with(flags: u16, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x1234u16.to_be_bytes());
        b.extend_from_slice(&flags.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        for l in ["_acme-challenge", "example", "com"] {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&T_TXT.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        for (rtype, rdata) in answers {
            b.extend_from_slice(&[0xC0, 12]);
            b.extend_from_slice(&rtype.to_be_bytes());
            b.extend_from_slice(&1u16.to_be_bytes());
            b.extend_from_slice(&60u32.to_be_bytes());
            b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            b.extend_from_slice(rdata);
        }
        b
    }

    fn txt(parts: &[&str]) -> Vec<u8> {
        let mut r = Vec::new();
        for p in parts {
            r.push(p.len() as u8);
            r.extend_from_slice(p.as_bytes());
        }
        r
    }

    #[test]
    fn query_packet_round_trips_through_the_parser() {
        let q = build_query(7, "_acme-challenge.Example.com.", T_TXT, false).unwrap();
        assert_eq!(&q[0..2], &7u16.to_be_bytes());
        assert_eq!(q[2] & 0x01, 0, "recursion must be off for authorities");
        let (name, _) = read_name(&q, 12).unwrap();
        assert_eq!(name, "_acme-challenge.example.com");
    }

    #[test]
    fn txt_answers_are_parsed_and_split_strings_joined() {
        let buf = reply_with(
            0x8400,
            &[(T_TXT, txt(&["abc", "def"])), (T_TXT, txt(&["xyz"]))],
        );
        let r = parse_reply(&buf).unwrap();
        assert!(r.aa);
        let seen = interpret("_acme-challenge.example.com.", &r);
        assert_eq!(seen, Seen::Values(vec!["abcdef".into(), "xyz".into()]));
    }

    #[test]
    fn nxdomain_and_non_authoritative_are_distinguished() {
        let nx = parse_reply(&reply_with(0x8403, &[])).unwrap();
        assert_eq!(
            interpret("_acme-challenge.example.com", &nx),
            Seen::NxDomain
        );
        let referral = parse_reply(&reply_with(0x8000, &[])).unwrap();
        assert!(matches!(
            interpret("_acme-challenge.example.com", &referral),
            Seen::Unreachable(_)
        ));
    }

    #[test]
    fn cname_is_reported_for_following() {
        let mut target = Vec::new();
        for l in ["x", "acme-dns", "org"] {
            target.push(l.len() as u8);
            target.extend_from_slice(l.as_bytes());
        }
        target.push(0);
        let r = parse_reply(&reply_with(0x8400, &[(T_CNAME, target)])).unwrap();
        assert_eq!(
            interpret("_acme-challenge.example.com", &r),
            Seen::Cname("x.acme-dns.org".into())
        );
    }

    #[test]
    fn compression_loops_are_refused() {
        let buf = [0xC0u8, 0x00];
        assert!(read_name(&buf, 0).is_err());
    }

    fn ns(server: &str, seen: Seen) -> NsAnswer {
        NsAnswer {
            server: server.into(),
            seen,
        }
    }

    #[test]
    fn verdict_needs_every_value_on_every_answering_server() {
        let name = "_acme-challenge.example.com";
        let want = vec!["apex".to_string(), "wild".to_string()];
        // Both values everywhere, plus a stale leftover: fine.
        let ok = [
            ns(
                "a",
                Seen::Values(vec!["apex".into(), "wild".into(), "old".into()]),
            ),
            ns("b", Seen::Values(vec!["wild".into(), "apex".into()])),
        ];
        assert!(verdict(name, &want, &ok).is_ok());
        // One server still lagging behind (secondary not yet transferred).
        let lag = [
            ns("a", Seen::Values(vec!["apex".into(), "wild".into()])),
            ns("b", Seen::Values(vec!["apex".into()])),
        ];
        let e = verdict(name, &want, &lag).unwrap_err();
        assert!(e.contains("b: missing wild"), "{e}");
        // The wildcard+apex trap: the second value REPLACED the first.
        let replaced = [ns("a", Seen::Values(vec!["wild".into()]))];
        assert!(verdict(name, &want, &replaced).is_err());
        // The reported failure.
        let nx = [ns("a", Seen::NxDomain), ns("b", Seen::NxDomain)];
        assert!(verdict(name, &want, &nx).unwrap_err().contains("NXDOMAIN"));
    }

    #[test]
    fn verdict_tolerates_one_unreachable_but_not_all() {
        let name = "_acme-challenge.example.com";
        let want = vec!["v".to_string()];
        let one_down = [
            ns("a", Seen::Unreachable("timed out".into())),
            ns("b", Seen::Values(vec!["v".into()])),
        ];
        assert!(verdict(name, &want, &one_down).is_ok());
        let all_down = [ns("a", Seen::Unreachable("timed out".into()))];
        assert!(verdict(name, &want, &all_down)
            .unwrap_err()
            .contains("no authoritative nameserver answered"));
        assert!(verdict(name, &want, &[]).is_err());
    }

    #[test]
    fn relative_name_strips_the_zone() {
        assert_eq!(
            relative_to_zone("_acme-challenge.hos-1.digitalka.cz.", "digitalka.cz"),
            "_acme-challenge.hos-1"
        );
        assert_eq!(
            relative_to_zone("a.other.org", "digitalka.cz"),
            "a.other.org"
        );
    }

    /// Live end-to-end against real DNS: a name that certainly has no
    /// challenge record must be refused. `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_missing_record_is_refused() {
        let r = check_txt_published(&[(
            "_acme-challenge.hyperion-probe-test.example.com".into(),
            "nope".into(),
        )])
        .await;
        assert!(matches!(r, Err(ProbeError::NotVisible(_))), "{r:?}");
    }
}
