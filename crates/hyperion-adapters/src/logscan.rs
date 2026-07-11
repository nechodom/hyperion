//! Pure log-line parsers for the native brute-force scanner. Each takes a
//! blob of log / journal text and returns a per-source-IP failure count. The
//! async plumbing that actually runs `journalctl` / reads a log file lives in
//! `hyperion-core`'s scanner tick; keeping the parsing here makes it a fast,
//! dependency-free unit to test (and reuse across sources).

use std::collections::HashMap;
use std::net::IpAddr;

/// First `[...]`-bracketed token in `line` that parses as an IP. postfix
/// logs the peer as `hostname[1.2.3.4]`; the *last* bracket wins so a
/// bracketed pid earlier in the line can't shadow the real address.
fn bracketed_ip(line: &str) -> Option<String> {
    let mut best = None;
    let mut i = 0;
    while let Some(open) = line[i..].find('[') {
        let start = i + open + 1;
        let Some(close_rel) = line[start..].find(']') else {
            break;
        };
        let cand = &line[start..start + close_rel];
        if cand.parse::<IpAddr>().is_ok() {
            best = Some(cand.to_string());
        }
        i = start + close_rel + 1;
    }
    best
}

/// The `rip=<ip>` field dovecot attaches to a failed login line. The value
/// runs to the next comma or whitespace.
fn rip_ip(line: &str) -> Option<String> {
    let p = line.find("rip=")? + 4;
    let rest = &line[p..];
    let end = rest
        .find(|c: char| c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    let cand = &rest[..end];
    cand.parse::<IpAddr>().ok().map(|_| cand.to_string())
}

/// Count vsftpd failed logins per source IP. vsftpd writes one line per
/// failed attempt: `… FAIL LOGIN: Client "1.2.3.4"`. Successful `OK LOGIN`
/// lines and everything else are ignored.
pub fn parse_vsftpd_fail_logins(text: &str) -> HashMap<String, u32> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for line in text.lines() {
        if !line.contains("FAIL LOGIN") {
            continue;
        }
        let Some(p) = line.find("Client \"") else {
            continue;
        };
        let rest = &line[p + 8..];
        let Some(end) = rest.find('"') else { continue };
        let cand = &rest[..end];
        if cand.parse::<IpAddr>().is_ok() {
            *counts.entry(cand.to_string()).or_insert(0) += 1;
        }
    }
    counts
}

/// Count mail SASL auth failures per source IP from combined postfix +
/// dovecot journal text. Recognises:
///   * postfix/smtpd: `… [1.2.3.4]: SASL LOGIN authentication failed …`
///   * dovecot:       `… auth failed …, rip=1.2.3.4, …`
pub fn parse_mail_fail_logins(text: &str) -> HashMap<String, u32> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for line in text.lines() {
        let ip = if line.contains("SASL") && line.contains("authentication failed") {
            bracketed_ip(line)
        } else if line.contains("auth failed") {
            // dovecot login-abort line; prefer the explicit rip= field, fall
            // back to a bracketed address if a future format carries one.
            rip_ip(line).or_else(|| bracketed_ip(line))
        } else {
            None
        };
        if let Some(ip) = ip {
            *counts.entry(ip).or_insert(0) += 1;
        }
    }
    counts
}

/// Whether `ip` is a public address it's safe to *auto-ban* for panel-login
/// brute force. Rejects loopback / unspecified / private / link-local / CGNAT
/// (v4 100.64/10) and v6 ULA (fc00::/7) + link-local (fe80::/10): those can't
/// be the real remote attacker, and one of them might be a shared proxy or
/// NAT whose ban would lock out every legitimate user behind it.
pub fn is_public_bannable_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || o[0] == 0
                // 100.64.0.0/10 — carrier-grade NAT.
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        Ok(IpAddr::V6(a)) => {
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                // fc00::/7 — unique-local.
                || (s[0] & 0xfe00) == 0xfc00
                // fe80::/10 — link-local.
                || (s[0] & 0xffc0) == 0xfe80)
        }
        Err(_) => false,
    }
}

/// IPs in `counts` whose failure count reached `threshold`.
pub fn over_threshold(counts: &HashMap<String, u32>, threshold: u32) -> Vec<String> {
    counts
        .iter()
        .filter(|(_, c)| **c >= threshold)
        .map(|(ip, _)| ip.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsftpd_counts_fail_logins_only() {
        let log = r#"Mon Jul  6 12:00:01 2026 [pid 5] [bob] FAIL LOGIN: Client "203.0.113.7"
Mon Jul  6 12:00:02 2026 [pid 6] [bob] FAIL LOGIN: Client "203.0.113.7"
Mon Jul  6 12:00:03 2026 [pid 7] [al] OK LOGIN: Client "198.51.100.9"
Mon Jul  6 12:00:04 2026 [pid 8] [x] FAIL LOGIN: Client "2001:db8::42"
"#;
        let c = parse_vsftpd_fail_logins(log);
        assert_eq!(c.get("203.0.113.7"), Some(&2));
        assert_eq!(c.get("2001:db8::42"), Some(&1));
        assert_eq!(c.get("198.51.100.9"), None); // OK LOGIN ignored
    }

    #[test]
    fn mail_counts_postfix_and_dovecot_failures() {
        let log = r#"Jul  6 12:00:01 s4 postfix/smtpd[999]: warning: unknown[203.0.113.7]: SASL LOGIN authentication failed: authentication failure
Jul  6 12:00:02 s4 postfix/smtpd[999]: connect from mail.good.com[198.51.100.4]
Jul  6 12:00:03 s4 dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<bob>, rip=203.0.113.7, lip=10.0.0.1
Jul  6 12:00:04 s4 dovecot: imap-login: Login: user=<al>, rip=198.51.100.5
"#;
        let c = parse_mail_fail_logins(log);
        assert_eq!(c.get("203.0.113.7"), Some(&2)); // one postfix + one dovecot
        assert_eq!(c.get("198.51.100.4"), None); // successful connect
        assert_eq!(c.get("198.51.100.5"), None); // successful login
    }

    #[test]
    fn public_ips_are_bannable() {
        assert!(is_public_bannable_ip("203.0.113.7"));
        assert!(is_public_bannable_ip("2606:4700:4700::1111"));
    }

    #[test]
    fn private_and_special_ips_are_not_bannable() {
        for ip in [
            "127.0.0.1",       // loopback
            "10.0.0.5",        // private
            "192.168.1.10",    // private
            "172.16.4.4",      // private
            "169.254.1.1",     // link-local
            "100.64.0.1",      // CGNAT
            "0.0.0.0",         // unspecified
            "::1",             // v6 loopback
            "fd00::1",         // v6 ULA
            "fe80::1",         // v6 link-local
            "not-an-ip",       // garbage
        ] {
            assert!(!is_public_bannable_ip(ip), "{ip} must not be bannable");
        }
    }

    #[test]
    fn over_threshold_filters() {
        let mut c = HashMap::new();
        c.insert("1.1.1.1".to_string(), 5u32);
        c.insert("2.2.2.2".to_string(), 2u32);
        let mut hit = over_threshold(&c, 5);
        hit.sort();
        assert_eq!(hit, vec!["1.1.1.1".to_string()]);
    }
}
