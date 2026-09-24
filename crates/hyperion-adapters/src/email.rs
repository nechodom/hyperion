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

/// Re-exported so callers that already depend on the adapter keep working.
pub use hyperion_types::render_html_shell;

/// Content-ID the HTML shell references as `cid:hyperion-logo` when a logo is
/// attached inline. Mail clients block `data:` image URIs (Gmail strips them
/// outright), so the logo has to ride as a real MIME part, not a data URI in
/// the `src`.
pub const LOGO_CID: &str = "hyperion-logo";

/// Send a notification as multipart/alternative — the plain text exactly as
/// composed, plus the HTML shell around it.
///
/// Multipart rather than HTML-only on purpose: a text/html-only message reads
/// as spam to several filters, and some operators genuinely prefer text.
///
/// `logo` = `(bytes, mime)` attaches the image as an inline `multipart/related`
/// part with Content-ID [`LOGO_CID`]; the HTML must reference it as
/// `cid:hyperion-logo`. `None` sends without one.
pub async fn send_html(
    cfg: &EmailConfig,
    to: &str,
    subject: &str,
    body_text: &str,
    body_html: &str,
    logo: Option<(&[u8], &str)>,
) -> Result<String, AdapterError> {
    send_inner(cfg, to, subject, Some((body_text, body_html)), None, logo).await
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
    send_inner(cfg, to, subject, None, Some(body), None).await
}

/// Build the MIME message (no I/O). Pure so the multipart shape — and the
/// inline logo part in particular — can be unit-tested without a live SMTP
/// server.
fn build_message(
    from_full: &str,
    to: &str,
    subject: &str,
    alt: Option<(&str, &str)>,
    plain: Option<&str>,
    logo: Option<(&[u8], &str)>,
) -> Result<Message, AdapterError> {
    let msg = Message::builder()
        .from(
            from_full
                .parse()
                .map_err(|e| AdapterError::Other(format!("smtp: bad from address: {e}")))?,
        )
        .to(to
            .parse()
            .map_err(|e| AdapterError::Other(format!("smtp: bad to address: {e}")))?)
        .subject(subject);
    match (alt, plain) {
        (Some((text, html)), _) => {
            use lettre::message::{header, MultiPart, SinglePart};
            let alternative = MultiPart::alternative_plain_html(text.to_string(), html.to_string());
            // With a logo, wrap the alternative + the image in multipart/related
            // so the HTML's `cid:hyperion-logo` resolves to a real inline part.
            let body = match logo {
                Some((bytes, mime)) if !bytes.is_empty() => {
                    let ctype = header::ContentType::parse(mime).map_err(|e| {
                        AdapterError::Other(format!("smtp: logo content-type {mime:?}: {e}"))
                    })?;
                    let image = SinglePart::builder()
                        .header(ctype)
                        .header(header::ContentTransferEncoding::Base64)
                        .header(header::ContentDisposition::inline())
                        .header(header::ContentId::from(format!("<{LOGO_CID}>")))
                        .body(bytes.to_vec());
                    MultiPart::related()
                        .multipart(alternative)
                        .singlepart(image)
                }
                _ => alternative,
            };
            msg.multipart(body)
                .map_err(|e| AdapterError::Other(format!("smtp: build message: {e}")))
        }
        (None, Some(text)) => msg
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .body(text.to_string())
            .map_err(|e| AdapterError::Other(format!("smtp: build message: {e}"))),
        (None, None) => Err(AdapterError::Other("smtp: no message body".into())),
    }
}

/// Shared transport for both shapes. `alt` carries (plain, html) for a
/// multipart/alternative message; `plain` is the text-only form. Exactly one
/// is set — the two public wrappers above are the only callers.
async fn send_inner(
    cfg: &EmailConfig,
    to: &str,
    subject: &str,
    alt: Option<(&str, &str)>,
    plain: Option<&str>,
    logo: Option<(&[u8], &str)>,
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

    let msg = build_message(&from_full, to, subject, alt, plain, logo)?;

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
    use super::build_message;
    use super::is_loopback_host;
    use super::normalize_smtp_host;
    use super::LOGO_CID;

    #[test]
    fn logo_rides_as_an_inline_content_id_part() {
        // A `data:` URI in the HTML is stripped by mail clients; the logo must
        // be a real inline part the HTML points at with `cid:`.
        let png = [0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4];
        let html = format!("<img src=\"cid:{LOGO_CID}\">");
        let msg = build_message(
            "Acme <a@example.com>",
            "b@example.com",
            "Subj",
            Some(("text body", &html)),
            None,
            Some((&png, "image/png")),
        )
        .expect("build");
        let bytes = msg.formatted();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("multipart/related"), "expected related: {raw}");
        assert!(
            raw.contains("Content-ID: <hyperion-logo>"),
            "expected the CID header: {raw}"
        );
        assert!(raw.to_lowercase().contains("content-disposition: inline"));
        assert!(
            raw.contains("cid:hyperion-logo"),
            "the HTML must reference the CID"
        );
    }

    #[test]
    fn no_logo_stays_a_plain_alternative() {
        let msg = build_message(
            "a@example.com",
            "b@example.com",
            "S",
            Some(("t", "<p>h</p>")),
            None,
            None,
        )
        .expect("build");
        let bytes = msg.formatted();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("multipart/alternative"));
        assert!(!raw.contains("Content-ID"), "no logo → no CID part");
    }

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
