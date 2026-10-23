//! Network lookups: DNS records, public IP discovery, SSRF-safe URL resolution.

/// Resolve `kind` records for `domain` by asking the zone's AUTHORITATIVE
/// nameservers directly, bypassing every cache.
///
/// This is the answer Let's Encrypt will get. The ordinary lookup goes
/// through this box's resolver, which can hold a stale record for as long as
/// the old TTL — so the pre-check would report "DNS points elsewhere" for a
/// domain that had already been repointed and that LE would validate without
/// complaint. It fails the other way too: a cached correct answer here while
/// the authoritative zone still says something else.
///
/// Returns `Ok(None)` when the authoritative servers could not be determined
/// (no `dig`, an unusual delegation), which is different from "no records"
/// and must not be reported as a mismatch.
pub(super) async fn dig_records_authoritative(
    domain: &str,
    kind: &str,
) -> Result<Option<Vec<String>>, std::io::Error> {
    // Walk up until a label has NS records: `www.example.com` is rarely a
    // zone of its own, and asking for its NS returns nothing.
    let mut zone = domain.trim_end_matches('.').to_string();
    let mut servers: Vec<String> = Vec::new();
    for _ in 0..4 {
        if zone.matches('.').count() < 1 {
            break;
        }
        if let Ok(ns) = dig_records(&zone, "NS").await {
            let ns: Vec<String> = ns
                .into_iter()
                .map(|n| n.trim_end_matches('.').to_string())
                .filter(|n| !n.is_empty())
                .collect();
            if !ns.is_empty() {
                servers = ns;
                break;
            }
        }
        match zone.split_once('.') {
            Some((_, rest)) => zone = rest.to_string(),
            None => break,
        }
    }
    if servers.is_empty() {
        return Ok(None);
    }
    // One authoritative server is enough — they are meant to agree, and
    // querying all of them turns a slow zone into a slow page. Try them in
    // turn so a single dead nameserver does not decide the answer.
    for ns in servers.iter().take(3) {
        let out = tokio::process::Command::new("/usr/bin/dig")
            .args([
                "+short",
                "+time=3",
                "+tries=1",
                kind,
                domain,
                &format!("@{ns}"),
            ])
            .output()
            .await?;
        if out.status.success() {
            return Ok(Some(
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.contains(' '))
                    .collect(),
            ));
        }
    }
    Ok(None)
}

pub(super) async fn dig_records(domain: &str, kind: &str) -> Result<Vec<String>, std::io::Error> {
    let out = match tokio::process::Command::new("/usr/bin/dig")
        .args(["+short", "+time=3", "+tries=2", kind, domain])
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // dig is simply NOT INSTALLED — minimal Debian ships without
            // bind9-dnsutils, and until update.sh healed it, a fresh
            // worker node answered every DNS question with a failure the
            // cards rendered as "record missing". An operator who HAD
            // published the record then re-checked their DNS for hours.
            // Name the real cause; the error text reaches the cards'
            // "unknown" copy.
            return Err(std::io::Error::other(
                "dig is not installed on this node (bind9-dnsutils) — DNS cannot be                  checked from here. Run update.sh on this node, or                  `apt-get install -y bind9-dnsutils`.",
            ));
        }
        Err(e) => return Err(e),
    };
    if !out.status.success() {
        // A non-zero dig exit (SERVFAIL, timeout, network down) is a
        // *transient* failure, not "no records". Callers `unwrap_or_default`
        // and can't tell the two apart, so at least make it visible here —
        // otherwise an operator sees "SPF doesn't authorize us" when the real
        // cause is DNS being unreachable.
        tracing::warn!(
            domain = %domain,
            kind = %kind,
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "dig lookup failed (transient) — treating as no records"
        );
        return Ok(vec![]);
    }
    let body = String::from_utf8_lossy(&out.stdout);
    // Filtering depends on the RECORD TYPE, and getting that wrong is how
    // every SPF check in the panel reported "no SPF TXT record at the apex"
    // for every domain, for as long as this function has existed.
    //
    // The old rule was a single `!l.contains(' ')`, meant to drop the
    // hostname lines `dig +short A` emits for a CNAME chain so a caller
    // comparing against an IP does not see one. For A and AAAA that is
    // right. For everything else it is a disaster:
    //
    //   TXT  "v=spf1 include:_spf.example.com ~all"   — spaces everywhere
    //   MX   "10 mail.example.com."                   — priority, space, host
    //
    // Both were silently dropped, so TXT always came back empty and SPF was
    // always "missing". The fix is to say what each type actually wants
    // rather than to guess from punctuation: A and AAAA keep only lines that
    // parse as an address of that family; everything else keeps every
    // non-empty line, because for those types `+short` prints one rdata per
    // line and all of it is the answer.
    let keep_only_addresses = matches!(kind, "A" | "AAAA");
    Ok(body
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter(|l| {
            if !keep_only_addresses {
                return true;
            }
            match l.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) => kind == "A",
                Ok(std::net::IpAddr::V6(_)) => kind == "AAAA",
                Err(_) => false,
            }
        })
        .map(String::from)
        .collect())
}

/// This node's public IPv4 address, or an error.
///
/// The result is PARSED and the family CHECKED, which is the whole point.
/// `api.ipify.org` answers over whichever family the request went out on,
/// so a dual-stack node gets an IPv6 literal back — and the caller was
/// interpolating it straight into `format!("v=spf1 ip4:{ip} a mx ~all")`.
/// An operator who pasted that into DNS published a record every receiver
/// evaluates as PERMERROR, which is worse than publishing nothing: the
/// domain's mail gets junked, and the panel's own SPF card kept reporting
/// "differs" no matter what they did, because the comparison parsed the
/// same broken string.
///
/// `api4.` pins the lookup to A-records only; the parse is the backstop
/// for the day that host starts answering differently.
/// This node's public IPv4, fetched once per process.
///
/// It does not change under a running agent, so a probe per request would add
/// a network round trip and a failure mode to every panel load for a value
/// that is always the same. A failed probe stays `None` and simply is not
/// shown.
pub async fn own_public_ipv4() -> Option<String> {
    static OWN_PUBLIC_IP_V4: tokio::sync::OnceCell<Option<String>> =
        tokio::sync::OnceCell::const_new();
    OWN_PUBLIC_IP_V4
        .get_or_init(|| async { fetch_public_ip_v4("https://api4.ipify.org").await.ok() })
        .await
        .clone()
}

pub(super) async fn fetch_public_ip_v4(url: &str) -> Result<String, std::io::Error> {
    let raw = fetch_public_ip_raw(url).await?;
    match raw.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => Ok(v4.to_string()),
        Ok(std::net::IpAddr::V6(_)) => Err(std::io::Error::other(format!(
            "{url} returned an IPv6 address ({raw}); need IPv4 for an SPF ip4: term"
        ))),
        Err(_) => Err(std::io::Error::other(format!(
            "{url} returned something that is not an IP address: {raw:?}"
        ))),
    }
}

/// This node's public IPv6 address. Same family check as
/// [`fetch_public_ip_v4`], in the other direction — the DNS preflight
/// compares this against the domain's AAAA records, and an IPv4 literal
/// leaking in here would report a mismatch that does not exist.
pub(super) async fn fetch_public_ip_v6(url: &str) -> Result<String, std::io::Error> {
    let raw = fetch_public_ip_raw(url).await?;
    match raw.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => Ok(v6.to_string()),
        Ok(std::net::IpAddr::V4(_)) => Err(std::io::Error::other(format!(
            "{url} returned an IPv4 address ({raw}); expected IPv6"
        ))),
        Err(_) => Err(std::io::Error::other(format!(
            "{url} returned something that is not an IP address: {raw:?}"
        ))),
    }
}

/// This node's fully-qualified hostname, falling back to the short name
/// and then to `localhost`.
///
/// Same resolution `mta_reconfigure` does for postfix's `myhostname`, so
/// the left-hand side of the envelope-rewrite map is guaranteed to be the
/// string postfix actually stamps on unqualified senders.
pub(super) async fn my_fqdn() -> String {
    let out = tokio::process::Command::new("/bin/hostname")
        .arg("-f")
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    out.unwrap_or_else(|| "localhost".to_string())
}

pub(super) async fn fetch_public_ip_raw(url: &str) -> Result<String, std::io::Error> {
    let out = tokio::process::Command::new("/usr/bin/curl")
        .args(["-fsS", "--max-time", "4", url])
        .output()
        .await?;
    if !out.status.success() {
        return Err(std::io::Error::other("curl exit non-zero"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The host of an `https://host[:port]/…` URL, resolved to addresses. A
/// literal IP needs no lookup; a name gets a short, bounded one.
pub(super) async fn resolve_url_host(url: &str) -> Vec<std::net::IpAddr> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Vec::new();
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip];
    }
    match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::lookup_host((host, 443)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        _ => Vec::new(),
    }
}

/// Resolve `url`'s host and reject internal/loopback/link-local destinations,
/// returning `host:port:ip` strings for curl `--resolve` so the connection is
/// pinned to the validated address (defeats DNS rebinding). SSRF guard for
/// operator-supplied outbound URLs (e.g. alert webhooks).
pub(super) async fn ssrf_guard_resolve(url: &str) -> Result<Vec<String>, String> {
    resolve_url_pins(url, InternalAddrs::Refuse).await
}

/// Which internal addresses [`resolve_url_pins`] lets through.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum InternalAddrs {
    /// None — every operator- or user-supplied URL.
    Refuse,
    /// Loopback and private networks (RFC1918, CGNAT, IPv6 ULA) — and only
    /// for a URL the master minted to its own bundle endpoint. Link-local
    /// (cloud metadata), unspecified, broadcast and documentation ranges
    /// stay refused.
    AllowOwnNetwork,
}

/// True for the addresses a master can legitimately be reached on from its
/// own cluster: itself (127.0.0.0/8, ::1) or a private network.
pub(super) fn is_own_network_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|m| is_own_network_ip(&std::net::IpAddr::V4(m)))
        }
    }
}

/// [`ssrf_guard_resolve`] with a choice of [`InternalAddrs`] policy. The
/// scheme check, the single resolution and the `--resolve` pins stay on
/// either way.
pub(super) async fn resolve_url_pins(
    url: &str,
    policy: InternalAddrs,
) -> Result<Vec<String>, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid url: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(format!("unsupported url scheme: {other}")),
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "url has no host".to_string())?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::IpAddr> = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| format!("dns resolve {host}: {e}"))?
            .map(|sa| sa.ip())
            .collect(),
    };
    if addrs.is_empty() {
        return Err(format!("{host} did not resolve"));
    }
    for ip in &addrs {
        let allowed = policy == InternalAddrs::AllowOwnNetwork && is_own_network_ip(ip);
        if is_internal_ip(ip) && !allowed {
            return Err(format!(
                "refusing outbound request to internal address {ip} ({host})"
            ));
        }
    }
    Ok(addrs
        .iter()
        .map(|ip| format!("{host}:{port}:{ip}"))
        .collect())
}

/// True for IP ranges an outbound webhook must never reach — loopback,
/// RFC1918 private, link-local (incl. 169.254.169.254 cloud metadata),
/// CGNAT, unspecified, and the IPv6 equivalents (ULA, link-local, mapped).
pub(super) fn is_internal_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || v6
                    .to_ipv4_mapped()
                    .map(|m| is_internal_ip(&std::net::IpAddr::V4(m)))
                    .unwrap_or(false)
        }
    }
}
