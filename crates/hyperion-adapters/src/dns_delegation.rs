//! Which link of the acme-dns delegation is missing?
//!
//! [`check_zone_delegated`](crate::dns_probe::check_zone_delegated) proves
//! the whole chain through a public recursor, which is what a renewal needs
//! and useless for setting the thing up: "no TXT record" is the answer for a
//! missing NS record, a missing address record, a closed port and a stale
//! resolver cache alike. This asks every link on its own:
//!
//! - the responder, directly on its public address;
//! - the NS record, at the parent zone's own name servers (recursion off,
//!   so a cached "no such record" cannot hide one added a minute ago);
//! - the name server host's A / AAAA record, the same way;
//! - the whole chain, through the public recursors.

use crate::dns_probe::{
    find_zone, interpret, interpret_as, norm, ns_addresses, query, recursive, RData, Reply, Seen,
    PUBLIC_RESOLVERS, T_A, T_AAAA, T_CNAME, T_NS, T_TXT,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// One link may take this long before it reads as unknown, so a slow
/// lookup cannot take the answers of the others with it.
const LINK_TIMEOUT: Duration = Duration::from_secs(12);

/// The state of one link. The text is operator-facing and names what was
/// seen, not what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// In place.
    Ok(String),
    /// Not there (yet).
    Missing(String),
    /// There, but it leads somewhere else.
    Wrong(String),
    /// The lookup itself failed, so nothing is known about the link.
    Unknown(String),
}

impl Link {
    pub fn is_ok(&self) -> bool {
        matches!(self, Link::Ok(_))
    }

    pub fn detail(&self) -> &str {
        match self {
            Link::Ok(s) | Link::Missing(s) | Link::Wrong(s) | Link::Unknown(s) => s,
        }
    }
}

/// What the delegation is supposed to look like.
#[derive(Debug, Clone)]
pub struct DelegationSetup {
    pub zone: String,
    pub ns_host: String,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub check_token: String,
}

/// Every link, asked on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationReport {
    /// The responder, asked directly on the public address.
    pub responder: Link,
    /// The NS record in the parent zone.
    pub ns: Link,
    /// The name server host's A record; `None` when no IPv4 is set.
    pub a: Option<Link>,
    /// Its AAAA record; `None` when no IPv6 is set.
    pub aaaa: Option<Link>,
    /// The whole chain, as a public recursor sees it.
    pub public: Link,
}

fn check_name(zone: &str) -> String {
    format!("_hyperion-check.{}", norm(zone))
}

/// The responder's own answer on `addr`. `local` says whether the address
/// belongs to this machine: one behind NAT cannot be asked from here, so a
/// silence there says nothing.
fn responder_verdict(
    zone: &str,
    token: &str,
    addr: SocketAddr,
    local: bool,
    reply: &Result<Reply, String>,
) -> Link {
    let name = check_name(zone);
    match reply {
        Ok(r) => match interpret(&name, r) {
            Seen::Values(v) if v.iter().any(|t| t == token) => {
                Link::Ok(format!("answers on {addr}"))
            }
            Seen::Values(v) if !v.is_empty() => Link::Wrong(format!(
                "{addr} answers for this zone with another panel's token"
            )),
            _ => Link::Wrong(format!(
                "another DNS server answers on {addr}, not this panel"
            )),
        },
        Err(e) if local => Link::Missing(format!("nothing answers on {addr} ({e})")),
        Err(_) => Link::Unknown(format!(
            "{} is not an address of this server, so it cannot be asked from here",
            addr.ip()
        )),
    }
}

/// The NS set of `zone` in a parent server's reply: in the authority
/// section for a referral, in the answer when the server holds both zones.
fn ns_verdict(zone: &str, ns_host: &str, parent: &str, reply: &Reply) -> Link {
    let zone = norm(zone);
    let want = norm(ns_host);
    let mut hosts: Vec<String> = reply
        .answers
        .iter()
        .chain(&reply.authority)
        .filter(|rr| rr.rtype == T_NS && rr.name == zone)
        .filter_map(|rr| match &rr.data {
            RData::Name(n) => Some(norm(n)),
            _ => None,
        })
        .collect();
    hosts.sort();
    hosts.dedup();
    if hosts.contains(&want) {
        Link::Ok(format!("{parent} delegates {zone} to {want}"))
    } else if hosts.is_empty() {
        Link::Missing(format!("{parent} has no NS record for {zone}"))
    } else {
        Link::Wrong(format!("{parent} delegates {zone} to {}", hosts.join(", ")))
    }
}

/// The address record of `host` in an authoritative reply.
fn address_verdict(host: &str, expected: IpAddr, reply: &Reply) -> Link {
    let host = norm(host);
    let kind = if expected.is_ipv4() { "A" } else { "AAAA" };
    if let Some(target) = reply.answers.iter().find_map(|rr| match &rr.data {
        RData::Name(t) if rr.rtype == T_CNAME && rr.name == host => Some(t.clone()),
        _ => None,
    }) {
        return Link::Wrong(format!(
            "{host} is a CNAME to {target}; a name server needs its own {kind} record"
        ));
    }
    let have: Vec<IpAddr> = reply
        .answers
        .iter()
        .filter(|rr| rr.name == host)
        .filter_map(|rr| match rr.data {
            RData::A(ip) if expected.is_ipv4() => Some(IpAddr::V4(ip)),
            RData::Aaaa(ip) if expected.is_ipv6() => Some(IpAddr::V6(ip)),
            _ => None,
        })
        .collect();
    if have.contains(&expected) {
        Link::Ok(format!("{host} points at {expected}"))
    } else if have.is_empty() {
        Link::Missing(format!("{host} has no {kind} record"))
    } else {
        let list: Vec<String> = have.iter().map(IpAddr::to_string).collect();
        Link::Wrong(format!(
            "{host} points at {}, not {expected}",
            list.join(", ")
        ))
    }
}

/// What a public recursor makes of the check name.
fn public_verdict(token: &str, seen: &Seen) -> Link {
    match seen {
        Seen::Values(v) if v.iter().any(|t| t == token) => {
            Link::Ok("public resolvers get this panel's answer".into())
        }
        Seen::Values(v) if !v.is_empty() => {
            Link::Wrong("public resolvers reach another panel for this zone".into())
        }
        Seen::Values(_) | Seen::NxDomain => {
            Link::Missing("public resolvers do not see the delegation".into())
        }
        Seen::Cname(t) => Link::Wrong(format!("the check name is a CNAME to {t}")),
        // SERVFAIL and friends: the recursor found the delegation, followed
        // it, and got nothing back.
        Seen::Unreachable(e) => Link::Wrong(format!(
            "public resolvers follow the delegation but get no answer from this server ({e})"
        )),
    }
}

/// Ask the name servers of the zone `start` lives in for `name`, recursion
/// off. The first server that answers decides; the zone comes back with it.
async fn ask_zone_servers(start: &str, name: &str, qtype: u16) -> Result<(String, Reply), String> {
    let (zone, hosts) = find_zone(&PUBLIC_RESOLVERS, start).await?;
    let mut errs = Vec::new();
    for host in hosts {
        let Some(ip) = ns_addresses(&PUBLIC_RESOLVERS, &host)
            .await
            .first()
            .copied()
        else {
            errs.push(format!("{host}: no address"));
            continue;
        };
        match query(ip, name, qtype, false).await {
            Ok(r) => return Ok((zone, r)),
            Err(e) => errs.push(format!("{host}: {e}")),
        }
    }
    Err(format!(
        "no name server of {zone} answered ({})",
        errs.join("; ")
    ))
}

async fn responder_link(setup: &DelegationSetup) -> Link {
    let ip = match (setup.ipv4, setup.ipv6) {
        (Some(v4), _) => IpAddr::V4(v4),
        (None, Some(v6)) => IpAddr::V6(v6),
        (None, None) => return Link::Unknown("no public address is set".into()),
    };
    // Binding succeeds only for an address this machine holds.
    let local = std::net::UdpSocket::bind((ip, 0)).is_ok();
    let reply = query(ip, &check_name(&setup.zone), T_TXT, false).await;
    responder_verdict(
        &setup.zone,
        &setup.check_token,
        SocketAddr::new(ip, 53),
        local,
        &reply,
    )
}

async fn ns_link(setup: &DelegationSetup) -> Link {
    let zone = norm(&setup.zone);
    let Some((_, above)) = zone.split_once('.') else {
        return Link::Unknown(format!("{zone} has no parent zone to delegate it"));
    };
    match ask_zone_servers(above, &zone, T_NS).await {
        Ok((parent, reply)) => ns_verdict(&zone, &setup.ns_host, &parent, &reply),
        Err(e) => Link::Unknown(e),
    }
}

async fn address_link(setup: &DelegationSetup, expected: IpAddr) -> Link {
    let qtype = if expected.is_ipv4() { T_A } else { T_AAAA };
    match ask_zone_servers(&setup.ns_host, &setup.ns_host, qtype).await {
        Ok((_, reply)) => address_verdict(&setup.ns_host, expected, &reply),
        Err(e) => Link::Unknown(e),
    }
}

async fn public_link(setup: &DelegationSetup) -> Link {
    let name = check_name(&setup.zone);
    match recursive(&PUBLIC_RESOLVERS, &name, T_TXT).await {
        Ok(reply) => public_verdict(&setup.check_token, &interpret_as(&name, &reply, false)),
        Err(e) => Link::Unknown(e),
    }
}

async fn bounded(link: impl std::future::Future<Output = Link>) -> Link {
    tokio::time::timeout(LINK_TIMEOUT, link)
        .await
        .unwrap_or_else(|_| Link::Unknown("the lookup timed out".into()))
}

/// Ask every link of the delegation, concurrently.
pub async fn check_delegation(setup: &DelegationSetup) -> DelegationReport {
    let a = async {
        match setup.ipv4 {
            Some(ip) => Some(bounded(address_link(setup, IpAddr::V4(ip))).await),
            None => None,
        }
    };
    let aaaa = async {
        match setup.ipv6 {
            Some(ip) => Some(bounded(address_link(setup, IpAddr::V6(ip))).await),
            None => None,
        }
    };
    let (responder, ns, a, aaaa, public) = tokio::join!(
        bounded(responder_link(setup)),
        bounded(ns_link(setup)),
        a,
        aaaa,
        bounded(public_link(setup)),
    );
    DelegationReport {
        responder,
        ns,
        a,
        aaaa,
        public,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_probe::Rr;

    const ZONE: &str = "acme.panel.example.com";
    const NS: &str = "ns-acme.example.com";

    fn reply(aa: bool, rcode: u8, answers: Vec<Rr>, authority: Vec<Rr>) -> Reply {
        Reply {
            id: 1,
            rcode,
            aa,
            tc: false,
            answers,
            authority,
        }
    }

    fn rr(name: &str, rtype: u16, data: RData) -> Rr {
        Rr {
            name: name.into(),
            rtype,
            data,
        }
    }

    fn ns_rr(owner: &str, host: &str) -> Rr {
        rr(owner, T_NS, RData::Name(host.into()))
    }

    fn addr() -> SocketAddr {
        "203.0.113.5:53".parse().expect("addr")
    }

    fn token_reply(aa: bool, token: &str) -> Result<Reply, String> {
        let name = check_name(ZONE);
        Ok(reply(
            aa,
            0,
            vec![rr(&name, T_TXT, RData::Txt(token.into()))],
            vec![],
        ))
    }

    #[test]
    fn a_referral_names_the_delegation_in_the_authority_section() {
        // A parent that only delegates answers without AA and without an
        // answer: the NS set sits in the authority section.
        let referral = reply(false, 0, vec![], vec![ns_rr(ZONE, "NS-Acme.Example.com.")]);
        assert!(ns_verdict(ZONE, NS, "example.com", &referral).is_ok());
        // A server holding both zones puts it in the answer.
        let both = reply(true, 0, vec![ns_rr(ZONE, NS)], vec![]);
        assert!(ns_verdict(ZONE, NS, "example.com", &both).is_ok());
    }

    #[test]
    fn a_parent_without_the_ns_record_is_missing_not_wrong() {
        // What a provider answers before the record is added: the parent's
        // own SOA in the authority section, which is not an NS for the zone.
        let nodata = reply(true, 0, vec![], vec![rr("example.com", 6, RData::Other)]);
        assert_eq!(
            ns_verdict(ZONE, NS, "example.com", &nodata),
            Link::Missing(format!("example.com has no NS record for {ZONE}"))
        );
        // The parent's own NS set must not be mistaken for the zone's.
        let own = reply(
            true,
            0,
            vec![],
            vec![ns_rr("example.com", "ns.provider.net")],
        );
        assert!(matches!(
            ns_verdict(ZONE, NS, "example.com", &own),
            Link::Missing(_)
        ));
    }

    #[test]
    fn a_delegation_to_another_host_is_named() {
        let other = reply(false, 0, vec![], vec![ns_rr(ZONE, "ns1.elsewhere.net")]);
        assert_eq!(
            ns_verdict(ZONE, NS, "example.com", &other),
            Link::Wrong(format!("example.com delegates {ZONE} to ns1.elsewhere.net"))
        );
    }

    #[test]
    fn the_address_record_is_matched_per_family() {
        let v4: IpAddr = "203.0.113.5".parse().expect("ip");
        let v6: IpAddr = "2001:db8::5".parse().expect("ip");
        let a = |ip: &str| rr(NS, T_A, RData::A(ip.parse().expect("v4")));
        let ok = reply(true, 0, vec![a("203.0.113.5")], vec![]);
        assert!(address_verdict(NS, v4, &ok).is_ok());
        // An A record says nothing about the AAAA one.
        assert_eq!(
            address_verdict(NS, v6, &ok),
            Link::Missing(format!("{NS} has no AAAA record"))
        );
        let elsewhere = reply(true, 0, vec![a("198.51.100.9")], vec![]);
        assert_eq!(
            address_verdict(NS, v4, &elsewhere),
            Link::Wrong(format!("{NS} points at 198.51.100.9, not 203.0.113.5"))
        );
        let none = reply(true, 3, vec![], vec![]);
        assert!(matches!(address_verdict(NS, v4, &none), Link::Missing(_)));
        let cname = reply(
            true,
            0,
            vec![rr(NS, T_CNAME, RData::Name("host.example.net".into()))],
            vec![],
        );
        assert!(matches!(address_verdict(NS, v4, &cname), Link::Wrong(_)));
    }

    #[test]
    fn the_responder_must_answer_authoritatively_with_this_token() {
        let ok = token_reply(true, "tok");
        assert_eq!(
            responder_verdict(ZONE, "tok", addr(), true, &ok),
            Link::Ok("answers on 203.0.113.5:53".into())
        );
        // A recursor on the same address would answer without AA.
        let recursor = token_reply(false, "tok");
        assert!(matches!(
            responder_verdict(ZONE, "tok", addr(), true, &recursor),
            Link::Wrong(_)
        ));
        let other = token_reply(true, "someone-else");
        assert!(matches!(
            responder_verdict(ZONE, "tok", addr(), true, &other),
            Link::Wrong(_)
        ));
        let refused: Result<Reply, String> = Ok(reply(false, 5, vec![], vec![]));
        assert!(matches!(
            responder_verdict(ZONE, "tok", addr(), true, &refused),
            Link::Wrong(_)
        ));
    }

    #[test]
    fn silence_on_a_foreign_address_is_unknown_not_missing() {
        let silent: Result<Reply, String> = Err("timed out".into());
        assert!(matches!(
            responder_verdict(ZONE, "tok", addr(), true, &silent),
            Link::Missing(_)
        ));
        // Behind NAT the public address is the router's: asking it from
        // here proves nothing either way.
        assert!(matches!(
            responder_verdict(ZONE, "tok", addr(), false, &silent),
            Link::Unknown(_)
        ));
    }

    /// Against real DNS: `LIVE_ZONE`, `LIVE_NS`, `LIVE_V4`, `LIVE_TOKEN`.
    #[tokio::test]
    #[ignore = "queries public DNS"]
    async fn live_report() {
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
        let setup = DelegationSetup {
            zone: var("LIVE_ZONE"),
            ns_host: var("LIVE_NS"),
            ipv4: var("LIVE_V4").parse().ok(),
            ipv6: None,
            check_token: var("LIVE_TOKEN"),
        };
        println!("{:#?}", check_delegation(&setup).await);
    }

    #[test]
    fn a_public_servfail_is_told_apart_from_a_missing_delegation() {
        assert!(public_verdict("tok", &Seen::Values(vec!["tok".into()])).is_ok());
        assert!(matches!(
            public_verdict("tok", &Seen::Values(vec![])),
            Link::Missing(_)
        ));
        assert!(matches!(
            public_verdict("tok", &Seen::NxDomain),
            Link::Missing(_)
        ));
        assert!(matches!(
            public_verdict("tok", &Seen::Values(vec!["other".into()])),
            Link::Wrong(_)
        ));
        let servfail = public_verdict("tok", &Seen::Unreachable("rcode 2".into()));
        assert!(matches!(servfail, Link::Wrong(_)));
        assert!(servfail.detail().contains("rcode 2"));
    }
}
