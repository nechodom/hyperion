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

/// Send a plain-text email. Returns the SMTP server's response on
/// success (mostly diagnostic). Errors are mapped to AdapterError::Other
/// with a leading "smtp:" prefix so they're easy to grep in logs.
pub async fn send_text(
    cfg: &EmailConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<String, AdapterError> {
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
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)
            .map_err(|e| AdapterError::Other(format!("smtp: relay: {e}")))?
            .port(cfg.smtp_port)
            .credentials(creds)
            .build(),
        "plain" => {
            // No TLS at all — useful for local dev with a mail catcher
            // like mailhog. Wrap in builder() so we can set port + no TLS.
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
                .port(cfg.smtp_port)
                .credentials(creds)
                .build()
        }
        _ => {
            // Default: STARTTLS upgrade (most relays expect this on 587).
            let tls = TlsParameters::new(cfg.smtp_host.clone())
                .map_err(|e| AdapterError::Other(format!("smtp: tls params: {e}")))?;
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)
                .map_err(|e| AdapterError::Other(format!("smtp: starttls: {e}")))?
                .port(cfg.smtp_port)
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
