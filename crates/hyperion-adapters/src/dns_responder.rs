//! Answer logic of the tiny authoritative-only DNS server that serves the
//! acme-dns zone (`_acme-challenge` CNAME delegation). Pure packet in,
//! packet out: sockets, rate limiting and DB reads live in the caller.
//!
//! Deliberately not a resolver: it never recurses, refuses everything
//! outside its zone without the AA bit, gives ANY no records, and truncates
//! instead of sending more than the caller allows, so it is useless as an
//! open resolver or amplification source.

use std::collections::{HashMap, HashSet};

use crate::dns_probe::{encode_name, read_name, T_NS, T_OPT, T_TXT};

const T_SOA: u16 = 6;
const CLASS_IN: u16 = 1;

const RCODE_NOERROR: u16 = 0;
const RCODE_FORMERR: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_NOTIMP: u16 = 4;
const RCODE_REFUSED: u16 = 5;

const TTL: u32 = 60;
const SOA_REFRESH: u32 = 3600;
const SOA_RETRY: u32 = 600;
const SOA_EXPIRE: u32 = 86400;
const SOA_MINIMUM: u32 = 60;

/// The record name (under the zone) that proves the server is reachable
/// and authoritative, without touching any real challenge.
const CHECK_LABEL: &str = "_hyperion-check";

/// A snapshot of what the zone serves; the caller rebuilds it per query
/// (or per refresh) from the database.
pub struct ZoneView {
    /// Lowercase, no trailing dot.
    pub zone: String,
    pub ns_host: String,
    pub check_token: String,
    pub serial: u32,
    /// label -> values (already filtered for expiry).
    pub txt: HashMap<String, Vec<String>>,
    /// Labels that exist even with no values.
    pub known_labels: HashSet<String>,
}

struct Question {
    /// The name exactly as received, for echoing.
    raw: Vec<u8>,
    /// Lowercase, no trailing dot.
    name: String,
    qtype: u16,
    qclass: u16,
    /// Offset just past the question section.
    end: usize,
}

/// The reply to `query`, or `None` to drop it silently (unparseable, or a
/// response packet — answering those is how reflection loops start).
///
/// The size limit follows EDNS0: a query with an OPT record may be answered
/// up to its advertised payload size (never below 512), and the reply then
/// carries an OPT record of its own; a query without one gets at most 512
/// bytes. `max_udp` caps both. A reply over the limit is cut to the header
/// and question with `tc=1`.
pub fn answer(query: &[u8], zone: &ZoneView, max_udp: usize) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let id = [query[0], query[1]];
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let opcode = (flags >> 11) & 0xF;
    let rd = flags & 0x0100;
    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    if opcode != 0 {
        return Some(header(id, rd, false, false, RCODE_NOTIMP, 0, [0; 3]));
    }
    if qdcount != 1 {
        return Some(header(id, rd, false, false, RCODE_FORMERR, 0, [0; 3]));
    }
    let Some(q) = parse_question(query) else {
        return Some(header(id, rd, false, false, RCODE_FORMERR, 0, [0; 3]));
    };

    let edns = query_opt_payload(query, &q);
    let limit = edns.map_or(512, |p| p.max(512)).min(max_udp);
    let lim = Limit {
        bytes: limit,
        opt: edns.is_some(),
    };

    let Some(rel) = relative(&q.name, &zone.zone) else {
        return Some(finish(id, rd, false, RCODE_REFUSED, &q, &[], &[], lim));
    };
    if q.qclass != CLASS_IN {
        return Some(finish(id, rd, false, RCODE_REFUSED, &q, &[], &[], lim));
    }

    let soa = soa_record(zone);
    let (rcode, answers) = if rel.is_empty() {
        match q.qtype {
            T_SOA => (RCODE_NOERROR, vec![soa.clone()]),
            T_NS => (
                RCODE_NOERROR,
                encode_name(&zone.ns_host)
                    .ok()
                    .map(|n| rr(T_NS, &n))
                    .into_iter()
                    .collect(),
            ),
            _ => (RCODE_NOERROR, Vec::new()),
        }
    } else if rel == CHECK_LABEL {
        match q.qtype {
            T_TXT => (RCODE_NOERROR, vec![txt_rr(&zone.check_token)]),
            _ => (RCODE_NOERROR, Vec::new()),
        }
    } else if zone.known_labels.contains(rel) {
        match q.qtype {
            T_TXT => (
                RCODE_NOERROR,
                zone.txt
                    .get(rel)
                    .map(|vals| vals.iter().map(|v| txt_rr(v)).collect())
                    .unwrap_or_default(),
            ),
            _ => (RCODE_NOERROR, Vec::new()),
        }
    } else {
        (RCODE_NXDOMAIN, Vec::new())
    };

    // Negative answers (NODATA / NXDOMAIN) carry the SOA so resolvers can
    // cache them; a SOA answer at the apex already has it in the answer.
    let authority = if answers.is_empty() {
        vec![soa]
    } else {
        Vec::new()
    };
    Some(finish(id, rd, true, rcode, &q, &answers, &authority, lim))
}

/// The reply size limit and whether to echo an OPT record.
#[derive(Clone, Copy)]
struct Limit {
    bytes: usize,
    opt: bool,
}

/// The UDP payload size from the query's OPT record, if it has one.
fn query_opt_payload(buf: &[u8], q: &Question) -> Option<usize> {
    let count = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    let mut pos = q.end;
    for _ in 0..count(6) + count(8) {
        let (_, p) = read_name(buf, pos).ok()?;
        let rdlen = u16::from_be_bytes(buf.get(p + 8..p + 10)?.try_into().ok()?) as usize;
        pos = p + 10 + rdlen;
    }
    for _ in 0..count(10) {
        let (name, p) = read_name(buf, pos).ok()?;
        let rtype = u16::from_be_bytes(buf.get(p..p + 2)?.try_into().ok()?);
        let class = u16::from_be_bytes(buf.get(p + 2..p + 4)?.try_into().ok()?);
        let rdlen = u16::from_be_bytes(buf.get(p + 8..p + 10)?.try_into().ok()?) as usize;
        if rtype == T_OPT && name.is_empty() {
            return Some(class as usize);
        }
        pos = p + 10 + rdlen;
    }
    None
}

/// `Some("")` for the apex, `Some(label...)` below it, `None` outside.
fn relative<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
    if name == zone {
        return Some("");
    }
    name.strip_suffix(zone)?.strip_suffix('.')
}

/// The single question, with its name copied as received. A compression
/// pointer in a question has nothing to point at, so it is malformed.
fn parse_question(buf: &[u8]) -> Option<Question> {
    let mut pos = 12;
    loop {
        let len = *buf.get(pos)? as usize;
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + len;
        if len == 0 {
            break;
        }
    }
    let raw = buf.get(12..pos)?.to_vec();
    let tail = buf.get(pos..pos + 4)?;
    let (name, _) = read_name(buf, 12).ok()?;
    Some(Question {
        raw,
        name,
        qtype: u16::from_be_bytes([tail[0], tail[1]]),
        qclass: u16::from_be_bytes([tail[2], tail[3]]),
        end: pos + 4,
    })
}

/// A resource record with the owner compressed to the question name.
fn rr(rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + rdata.len());
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&TTL.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

fn txt_rr(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut rdata = Vec::with_capacity(bytes.len() + 2);
    if bytes.is_empty() {
        rdata.push(0);
    }
    for chunk in bytes.chunks(255) {
        rdata.push(chunk.len() as u8);
        rdata.extend_from_slice(chunk);
    }
    rr(T_TXT, &rdata)
}

/// The apex SOA. Its owner is the zone itself, so unlike the other records
/// it is written out in full: in the authority section the question name
/// is usually a different name.
fn soa_record(zone: &ZoneView) -> Vec<u8> {
    let mut rdata = encode_name(&zone.ns_host).unwrap_or_else(|_| vec![0]);
    rdata.extend_from_slice(&encode_name(&format!("hostmaster.{}", zone.zone)).unwrap_or(vec![0]));
    for n in [zone.serial, SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_MINIMUM] {
        rdata.extend_from_slice(&n.to_be_bytes());
    }
    let mut out = encode_name(&zone.zone).unwrap_or_else(|_| vec![0]);
    out.extend_from_slice(&T_SOA.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&TTL.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

fn header(
    id: [u8; 2],
    rd: u16,
    aa: bool,
    tc: bool,
    rcode: u16,
    qd: u16,
    [an, ns, ar]: [u16; 3],
) -> Vec<u8> {
    let mut flags = 0x8000 | rd | rcode;
    if aa {
        flags |= 0x0400;
    }
    if tc {
        flags |= 0x0200;
    }
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id);
    out.extend_from_slice(&flags.to_be_bytes());
    for n in [qd, an, ns, ar] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out
}

/// Assemble the reply, or a header-only `tc=1` one when it would not fit.
#[allow(clippy::too_many_arguments)]
fn finish(
    id: [u8; 2],
    rd: u16,
    aa: bool,
    rcode: u16,
    q: &Question,
    answers: &[Vec<u8>],
    authority: &[Vec<u8>],
    lim: Limit,
) -> Vec<u8> {
    let mut out = header(
        id,
        rd,
        aa,
        false,
        rcode,
        1,
        [
            answers.len() as u16,
            authority.len() as u16,
            u16::from(lim.opt),
        ],
    );
    out.extend_from_slice(&q.raw);
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());
    for r in answers.iter().chain(authority) {
        out.extend_from_slice(r);
    }
    if lim.opt {
        // OPT: root owner, our payload size, extended rcode/version/flags 0.
        out.push(0);
        out.extend_from_slice(&T_OPT.to_be_bytes());
        out.extend_from_slice(&(lim.bytes.min(u16::MAX as usize) as u16).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    if out.len() > lim.bytes {
        let mut tc = header(id, rd, aa, true, rcode, 1, [0; 3]);
        tc.extend_from_slice(&q.raw);
        tc.extend_from_slice(&q.qtype.to_be_bytes());
        tc.extend_from_slice(&q.qclass.to_be_bytes());
        return tc;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_probe::{
        build_query, interpret, parse_reply, verdict, NsAnswer, RData, Seen, T_NS, T_TXT,
    };

    const ZONE: &str = "acme.example.net";

    fn view() -> ZoneView {
        let mut txt = HashMap::new();
        txt.insert(
            "abc123".to_string(),
            vec!["tokenone".to_string(), "tokentwo".to_string()],
        );
        let known_labels = ["abc123", "emptylabel"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        ZoneView {
            zone: ZONE.into(),
            ns_host: "ns.example.net".into(),
            check_token: "check-token-value".into(),
            serial: 2026102301,
            txt,
            known_labels,
        }
    }

    fn q(name: &str, qtype: u16, rd: bool) -> Vec<u8> {
        build_query(0x4242, name, qtype, rd).unwrap()
    }

    fn ask(name: &str, qtype: u16) -> Vec<u8> {
        answer(&q(name, qtype, false), &view(), 1232).unwrap()
    }

    fn flags(r: &[u8]) -> u16 {
        u16::from_be_bytes([r[2], r[3]])
    }
    fn count(r: &[u8], i: usize) -> u16 {
        u16::from_be_bytes([r[4 + 2 * i], r[5 + 2 * i]])
    }

    fn txt_values(r: &[u8]) -> Vec<String> {
        parse_reply(r)
            .unwrap()
            .answers
            .into_iter()
            .filter_map(|a| match a.data {
                RData::Txt(t) => Some(t),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn txt_for_label_returns_both_values_authoritatively() {
        let r = ask("abc123.acme.example.net", T_TXT);
        let p = parse_reply(&r).unwrap();
        assert_eq!(p.id, 0x4242);
        assert_eq!(p.rcode, 0);
        assert!(p.aa);
        assert!(!p.tc);
        assert_eq!(txt_values(&r), vec!["tokenone", "tokentwo"]);
        assert!(p
            .answers
            .iter()
            .all(|a| a.name == "abc123.acme.example.net"));
    }

    #[test]
    fn known_label_without_values_is_empty_noerror_not_nxdomain() {
        let r = ask("emptylabel.acme.example.net", T_TXT);
        let p = parse_reply(&r).unwrap();
        assert_eq!(p.rcode, 0);
        assert!(p.aa);
        assert!(p.answers.is_empty());
        assert_eq!(count(&r, 2), 1, "SOA in authority");
    }

    #[test]
    fn unknown_label_is_nxdomain_with_soa() {
        let r = ask("nope.acme.example.net", T_TXT);
        let p = parse_reply(&r).unwrap();
        assert_eq!(p.rcode, 3);
        assert!(p.aa);
        assert_eq!(count(&r, 1), 0);
        assert_eq!(count(&r, 2), 1);
        // A deeper name under a known label does not exist either.
        let r = ask("x.abc123.acme.example.net", T_TXT);
        assert_eq!(parse_reply(&r).unwrap().rcode, 3);
    }

    #[test]
    fn out_of_zone_is_refused_and_not_authoritative() {
        for name in ["example.com", "evilacme.example.net", "example.net"] {
            let r = ask(name, T_TXT);
            let p = parse_reply(&r).unwrap();
            assert_eq!(p.rcode, 5, "{name}");
            assert!(!p.aa, "{name}");
            assert!(p.answers.is_empty());
            assert_eq!(count(&r, 2), 0);
        }
    }

    #[test]
    fn recursion_desired_is_never_honoured() {
        let r = answer(&q("example.com", T_TXT, true), &view(), 1232).unwrap();
        assert_eq!(flags(&r) & 0x0080, 0, "ra must stay clear");
        assert_ne!(flags(&r) & 0x0100, 0, "rd is copied");
        let p = parse_reply(&r).unwrap();
        assert_eq!(p.rcode, 5);
        assert!(!p.aa);
        let r = answer(&q("abc123.acme.example.net", T_TXT, true), &view(), 1232).unwrap();
        assert_eq!(flags(&r) & 0x0080, 0);
    }

    #[test]
    fn apex_soa_and_ns() {
        let r = ask(ZONE, 6);
        let p = parse_reply(&r).unwrap();
        assert!(p.aa);
        assert_eq!(p.answers.len(), 1);
        assert_eq!(p.answers[0].rtype, 6);
        // mname, rname, then serial/refresh/retry/expire/minimum.
        let tail = &r[r.len() - 31..r.len() - 11]; // before the echoed OPT
        let n = |i: usize| u32::from_be_bytes(tail[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!(
            [n(0), n(1), n(2), n(3), n(4)],
            [2026102301, 3600, 600, 86400, 60]
        );
        assert!(r.windows(11).any(|w| w == b"\x0ahostmaster"));

        let r = ask(ZONE, T_NS);
        let p = parse_reply(&r).unwrap();
        assert!(p.aa);
        assert_eq!(p.answers[0].rtype, T_NS);
        assert_eq!(p.answers[0].data, RData::Name("ns.example.net".into()));
        assert_eq!(count(&r, 2), 0);
    }

    #[test]
    fn check_token_is_served() {
        let r = ask("_hyperion-check.acme.example.net", T_TXT);
        assert_eq!(txt_values(&r), vec!["check-token-value"]);
        assert!(parse_reply(&r).unwrap().aa);
    }

    #[test]
    fn name_match_is_case_insensitive_and_echoes_case() {
        // build_query lowercases, so splice a mixed-case name in by hand.
        let mut query = q("abc123.acme.example.net", T_TXT, false);
        let mixed = b"AbC123";
        query[13..13 + mixed.len()].copy_from_slice(mixed);
        let r = answer(&query, &view(), 1232).unwrap();
        assert_eq!(txt_values(&r), vec!["tokenone", "tokentwo"]);
        assert_eq!(&r[13..13 + 6], mixed, "question echoed as received");
    }

    #[test]
    fn any_query_gets_no_records() {
        for name in ["abc123.acme.example.net", ZONE] {
            let r = ask(name, 255);
            let p = parse_reply(&r).unwrap();
            assert_eq!(p.rcode, 0);
            assert!(p.answers.is_empty(), "{name}");
            assert_eq!(count(&r, 2), 1);
        }
    }

    #[test]
    fn oversize_reply_sets_tc() {
        let r = answer(&q("abc123.acme.example.net", T_TXT, false), &view(), 40).unwrap();
        let p = parse_reply(&r).unwrap();
        assert!(p.tc);
        assert!(p.aa);
        assert!(p.answers.is_empty());
        assert_eq!(count(&r, 0), 1);
        assert_eq!(count(&r, 1), 0);
        let query = q("abc123.acme.example.net", T_TXT, false);
        assert_eq!(&r[12..], &query[12..12 + (r.len() - 12)], "question echoed");
        assert_eq!(r.len(), 12 + 25 + 4);
    }

    #[test]
    fn garbage_is_dropped() {
        assert_eq!(answer(&[1, 2, 3], &view(), 1232), None);
        assert_eq!(answer(&[], &view(), 1232), None);
    }

    #[test]
    fn response_packets_are_dropped() {
        let mut query = q("abc123.acme.example.net", T_TXT, false);
        query[2] |= 0x80;
        assert_eq!(answer(&query, &view(), 1232), None);
    }

    #[test]
    fn other_opcode_is_notimp_and_bad_counts_are_formerr() {
        let mut query = q(ZONE, T_NS, false);
        query[2] |= 4 << 3; // NOTIFY
        assert_eq!(flags(&answer(&query, &view(), 1232).unwrap()) & 0xF, 4);

        let mut query = q(ZONE, T_NS, false);
        query[5] = 2;
        assert_eq!(flags(&answer(&query, &view(), 1232).unwrap()) & 0xF, 1);
        query[5] = 0;
        assert_eq!(flags(&answer(&query, &view(), 1232).unwrap()) & 0xF, 1);

        // Truncated question section.
        let query = q(ZONE, T_NS, false);
        assert_eq!(
            flags(&answer(&query[..20], &view(), 1232).unwrap()) & 0xF,
            1
        );
    }

    #[test]
    fn probe_verdict_accepts_the_served_txt() {
        let r = ask("abc123.acme.example.net", T_TXT);
        let p = parse_reply(&r).unwrap();
        let name = "abc123.acme.example.net";
        let seen = interpret(name, &p);
        assert!(matches!(seen, Seen::Values(_)));
        let answers = [NsAnswer {
            server: "ns.example.net (192.0.2.1)".into(),
            seen,
        }];
        let expected = vec!["tokenone".to_string(), "tokentwo".to_string()];
        assert_eq!(verdict(name, &expected, &answers), Ok(()));
    }

    /// A zone with enough values that the full reply exceeds 512 bytes.
    fn big_view() -> ZoneView {
        let mut v = view();
        v.txt.insert(
            "abc123".to_string(),
            (0..20).map(|i| format!("{i:0>43}")).collect(),
        );
        v
    }

    fn without_opt(mut query: Vec<u8>) -> Vec<u8> {
        query.truncate(query.len() - 11);
        query[11] = 0; // ARCOUNT
        query
    }

    fn with_payload(mut query: Vec<u8>, payload: u16) -> Vec<u8> {
        let n = query.len();
        query[n - 8..n - 6].copy_from_slice(&payload.to_be_bytes());
        query
    }

    #[test]
    fn non_edns_query_is_capped_at_512() {
        let query = without_opt(q("abc123.acme.example.net", T_TXT, false));
        let r = answer(&query, &big_view(), 1232).unwrap();
        assert!(parse_reply(&r).unwrap().tc);
        assert!(r.len() <= 512);
        assert_eq!(count(&r, 3), 0, "no OPT for a non-EDNS client");
    }

    #[test]
    fn edns_query_gets_full_reply_with_opt_echoed() {
        let query = q("abc123.acme.example.net", T_TXT, false);
        let r = answer(&query, &big_view(), 1232).unwrap();
        let p = parse_reply(&r).unwrap();
        assert!(!p.tc);
        assert_eq!(p.answers.len(), 20);
        assert!(r.len() > 512 && r.len() <= 1232);
        assert_eq!(count(&r, 3), 1);
        assert_eq!(
            &r[r.len() - 11..],
            &[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn advertised_payload_is_capped_by_max_udp_and_floored_at_512() {
        let big = with_payload(q("abc123.acme.example.net", T_TXT, false), 4096);
        let r = answer(&big, &big_view(), 1232).unwrap();
        assert!(!parse_reply(&r).unwrap().tc);
        assert_eq!(&r[r.len() - 8..r.len() - 6], &1232u16.to_be_bytes());
        assert!(answer(&big, &big_view(), 600).unwrap().len() <= 600);

        let tiny = with_payload(q("abc123.acme.example.net", T_TXT, false), 100);
        let r = answer(&tiny, &big_view(), 1232).unwrap();
        assert!(parse_reply(&r).unwrap().tc);
        assert!(r.len() <= 512);
    }
}
