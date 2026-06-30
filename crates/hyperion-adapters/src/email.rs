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

    let creds = Credentials::new(cfg.smtp_user.clone(), cfg.smtp_password.clone());
    let transport: AsyncSmtpTransport<Tokio1Executor> = match cfg.security.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
            .map_err(|e| AdapterError::Other(format!("smtp: relay: {e}")))?
            .port(port)
            .credentials(creds)
            .build(),
        "plain" => {
            // No TLS at all — useful for local dev with a mail catcher
            // like mailhog. Wrap in builder() so we can set port + no TLS.
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                .port(port)
                .credentials(creds)
                .build()
        }
        _ => {
            // Default: STARTTLS upgrade (most relays expect this on 587).
            let tls = TlsParameters::new(host.clone())
                .map_err(|e| AdapterError::Other(format!("smtp: tls params: {e}")))?;
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                .map_err(|e| AdapterError::Other(format!("smtp: starttls: {e}")))?
                .port(port)
                .credentials(creds)
                .tls(Tls::Required(tls))
                .build()
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
    use super::normalize_smtp_host;

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
