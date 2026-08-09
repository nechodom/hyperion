//! Send-only SMTP email via lettre + rustls.
//!
//! Designed for transactional notifications (billing, backup failures,
//! cert expiry) — NOT for receiving mail or running a full server.
//! Operator points us at any SMTP relay that accepts STARTTLS or
//! implicit TLS — gmail, postmark, sendgrid, mailgun, sendinblue,
//! self-hosted postfix-with-auth, etc. The protocol is the same.

use crate::AdapterError;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// Operator-provided SMTP relay configuration.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    /// Address that goes into the From header (and SMTP MAIL FROM).
    pub from_address: String,
    /// Display name shown in mail clients ("Hyperion Notifications").
    pub from_name: String,
    /// "starttls" (default, port 587) | "tls" (implicit TLS, port 465) | "plain" (no encryption, dev only).
    pub security: String,
}

/// Split a possibly-`host:port` SMTP host into `(host, embedded_port)`.
///
/// lettre wants a BARE hostname — passing `"localhost:25"` makes it try to
/// DNS-resolve the literal string `localhost:25` → "Name or service not
/// known". Operators (and older saved configs) routinely paste the port into
/// the host field, so we strip it. IPv6 is handled: a bracketed `"[::1]:25"`
/// is unwrapped, a bare IPv6 literal (`"::1"`, 2+ colons, no brackets) is
/// returned unchanged.
/// True when the SMTP host is the LOOPBACK interface of this machine.
///
/// Deliberately narrower than `postfix::host_is_local`, which also counts
/// this node's own FQDN — that name can resolve to a public address and
/// leave the box, so it must not relax TLS. Only `localhost`, the
/// `127.0.0.0/8` range and `::1` qualify here.
///
/// Used to skip certificate VERIFICATION (not encryption) when talking to
/// our own postfix. Debian's postfix presents the self-signed
/// `ssl-cert-snakeoil` certificate, so a `starttls` config against
/// `localhost` fails with `invalid peer certificate: UnknownIssuer` and
/// no mail goes out at all. Verifying it would prove nothing: the bytes
/// never leave the kernel's loopback interface, and anyone able to
/// intercept them already has root on this machine.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

pub fn normalize_smtp_host(raw: &str) -> (String, Option<u16>) {
    let s = raw.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // "[ipv6]:port" or "[ipv6]"
        if let Some((addr, port)) = rest.split_once("]:") {
            return (addr.to_string(), port.trim().parse().ok());
        }
        return (rest.trim_end_matches(']').to_string(), None);
    }
    // Bare IPv6 literal (more than one colon, unbracketed) — leave as-is.
    if s.matches(':').count() > 1 {
        return (s.to_string(), None);
    }
    // "host:port" — split only when the suffix is a valid port number.
    if let Some((host, port)) = s.split_once(':') {
        if let Ok(p) = port.trim().parse::<u16>() {
            return (host.to_string(), Some(p));
        }
    }
    (s.to_string(), None)
}

/// Send a plain-text email. Returns the SMTP server's response on
/// success (mostly diagnostic). Errors are mapped to AdapterError::Other
/// with a leading "smtp:" prefix so they're easy to grep in logs.
pub async fn send_text(
    cfg: &EmailConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<String, AdapterError> {
    // The dedicated port field is authoritative; only fall back to a port
    // embedded in the host (legacy "host:port" configs) when it's unset.
    let (host, embedded_port) = normalize_smtp_host(&cfg.smtp_host);
    let port = if cfg.smtp_port != 0 {
        cfg.smtp_port
    } else {
        embedded_port.unwrap_or(25)
    };
    let from_full = if cfg.from_name.trim().is_empty() {
        cfg.from_address.clone()
    } else {
        format!("{} <{}>", cfg.from_name, cfg.from_address)
    };

    let msg = Message::builder()
        .from(
            from_full
                .parse()
                .map_err(|e| AdapterError::Other(format!("smtp: bad from address: {e}")))?,
        )
        .to(to
            .parse()
            .map_err(|e| AdapterError::Other(format!("smtp: bad to address: {e}")))?)
        .subject(subject)
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| AdapterError::Other(format!("smtp: build message: {e}")))?;

    // Only authenticate when a username is configured. A local/anonymous relay
    // (e.g. postfix on localhost:25 that accepts mail without auth) advertises
    // no AUTH mechanism, and forcing credentials makes lettre fail with
    // "No compatible authentication mechanism was found" instead of just
    // sending. Empty user ⇒ no AUTH; non-empty user ⇒ authenticate.
    let creds = if cfg.smtp_user.trim().is_empty() {
        None
    } else {
        Some(Credentials::new(
            cfg.smtp_user.clone(),
            cfg.smtp_password.clone(),
        ))
    };
    // Our own postfix answers with Debian's self-signed snakeoil
    // certificate. Verifying it is not a security property here — see
    // `is_loopback_host` — it just stops the mail.
    let loopback = is_loopback_host(&host);
    let tls_params = |host: &str| -> Result<TlsParameters, AdapterError> {
        let b = TlsParameters::builder(host.to_string());
        let b = if loopback {
            b.dangerous_accept_invalid_certs(true)
                .dangerous_accept_invalid_hostnames(true)
        } else {
            b
        };
        b.build()
            .map_err(|e| AdapterError::Other(format!("smtp: tls params: {e}")))
    };

    let transport: AsyncSmtpTransport<Tokio1Executor> = match cfg.security.as_str() {
        "tls" => {
            let mut b = AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
                .map_err(|e| AdapterError::Other(format!("smtp: relay: {e}")))?
                .port(port)
                .tls(Tls::Wrapper(tls_params(&host)?));
            if let Some(c) = creds {
                b = b.credentials(c);
            }
            b.build()
        }
        "plain" => {
            // No TLS at all — useful for local dev with a mail catcher
            // like mailhog, or a localhost postfix relay. Wrap in builder() so
            // we can set port + no TLS.
            let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host).port(port);
            if let Some(c) = creds {
                b = b.credentials(c);
            }
            b.build()
        }
        _ => {
            // Default: STARTTLS upgrade (most relays expect this on 587).
            let tls = tls_params(&host)?;
            let mut b = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                .map_err(|e| AdapterError::Other(format!("smtp: starttls: {e}")))?
                .port(port)
                .tls(Tls::Required(tls));
            if let Some(c) = creds {
                b = b.credentials(c);
            }
            b.build()
        }
    };

    let response = transport
        .send(msg)
        .await
        .map_err(|e| AdapterError::Other(format!("smtp send: {e}")))?;

    Ok(format!("{:?}", response.code()))
}

#[cfg(test)]
mod tests {
    use super::is_loopback_host;
    use super::normalize_smtp_host;

    /// Certificate verification is skipped for these hosts, so the set has
    /// to be exactly the addresses that never leave the machine. A false
    /// positive here would silently disable verification against a real
    /// relay — the failure this whole helper exists to avoid, inverted.
    #[test]
    fn loopback_detection_covers_local_and_nothing_else() {
        for h in [
            "localhost",
            "LOCALHOST",
            " localhost ",
            "mail.localhost",
            "127.0.0.1",
            "127.1.2.3", // the whole /8 is loopback
            "::1",
            "[::1]",
        ] {
            assert!(is_loopback_host(h), "{h:?} must count as loopback");
        }
        for h in [
            "smtp.gmail.com",
            "s4.digitalka.cz",
            // Not loopback: a public address, however local it looks.
            "10.0.0.1",
            "192.168.1.1",
            "0.0.0.0",
            "::",
            // Names that merely CONTAIN the word must not match — this is
            // the one an attacker would register.
            "localhost.evil.com",
            "notlocalhost",
            "",
        ] {
            assert!(!is_loopback_host(h), "{h:?} must NOT count as loopback");
        }
    }

    #[test]
    fn strips_embedded_port_but_keeps_bare_host() {
        assert_eq!(normalize_smtp_host("localhost"), ("localhost".into(), None));
        assert_eq!(
            normalize_smtp_host("localhost:25"),
            ("localhost".into(), Some(25))
        );
        assert_eq!(
            normalize_smtp_host("smtp.example.com:587"),
            ("smtp.example.com".into(), Some(587))
        );
        // whitespace tolerated
        assert_eq!(
            normalize_smtp_host("  mail.cz:465 "),
            ("mail.cz".into(), Some(465))
        );
    }

    #[test]
    fn ipv6_literals_are_handled() {
        // bare IPv6 (unbracketed) — left intact, no port split
        assert_eq!(normalize_smtp_host("::1"), ("::1".into(), None));
        assert_eq!(
            normalize_smtp_host("2001:db8::1"),
            ("2001:db8::1".into(), None)
        );
        // bracketed forms
        assert_eq!(normalize_smtp_host("[::1]:25"), ("::1".into(), Some(25)));
        assert_eq!(
            normalize_smtp_host("[2001:db8::1]:465"),
            ("2001:db8::1".into(), Some(465))
        );
        assert_eq!(normalize_smtp_host("[::1]"), ("::1".into(), None));
    }

    #[test]
    fn non_numeric_suffix_left_alone() {
        // not a port → don't split (garbage in, garbage out, but no panic)
        assert_eq!(
            normalize_smtp_host("host:notaport"),
            ("host:notaport".into(), None)
        );
    }
}
