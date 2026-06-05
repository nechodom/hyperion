//! Postfix smart-host configuration.
//!
//! Why this exists: default `postfix` Internet Site config delivers via
//! direct MX lookup from the host's IP. In practice this fails for most
//! real-world recipients because (a) the VPS IP has no SPF / DKIM /
//! reverse DNS proving authorisation to send for the From domain,
//! (b) the IP is often on consumer-ISP blocklists, (c) some cloud
//! providers (AWS, GCP) block outbound TCP/25 by default.
//!
//! Hyperion's `[email]` section in agent.toml already carries SMTP
//! relay settings (used for the panel's own notifications: cert
//! reminders, monitor alerts, etc.). It's the same relay that should
//! handle PHP `mail()` from hosted sites. We translate that config
//! into postfix's `relayhost` + `smtp_sasl_password_maps` so site mail
//! flows through the same authenticated provider.
//!
//! The module is intentionally narrow: render config files atomically,
//! call `postconf` / `postmap` / `systemctl reload postfix`, return.
//! No SMTP semantics (lettre handles that for Hyperion's own outbound).

use crate::cmd;
use crate::fs::atomic_write;
use crate::AdapterError;
use crate::email::EmailConfig;
use std::path::Path;

/// `/etc/postfix/sasl_passwd` holds the relay credentials. We rewrite
/// it atomically + run `postmap` to produce the `.db` hash file
/// postfix actually reads.
const SASL_PASSWD_PATH: &str = "/etc/postfix/sasl_passwd";
/// Marker file written when our smart-host config is applied, so we
/// can clean up on `[email] enabled = false` rollback. Plain-text
/// breadcrumb the operator can `cat` for diagnostics.
const HYPERION_MARKER: &str = "/etc/postfix/hyperion-relay.marker";

/// Decide whether postfix is even on this node. Used by callers to
/// skip the configure-step on nodes that haven't installed an MTA.
/// `systemctl cat` is the canonical "unit known" probe — same shape
/// the boot self-heal already uses.
pub async fn is_installed() -> bool {
    tokio::process::Command::new("/usr/bin/systemctl")
        .args(["cat", "postfix.service"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Apply Hyperion's `[email]` SMTP relay settings to postfix.
///
/// Side effects (all idempotent + atomic):
/// 1. `postconf -e relayhost=...` + the SASL/TLS knobs that
///    relayhost relies on.
/// 2. Write `/etc/postfix/sasl_passwd` (chmod 0600 — contains the
///    smtp_password verbatim).
/// 3. `postmap` it to build the lookup hash file (`.db` or
///    `.lmdb` depending on postfix build).
/// 4. Write `hyperion-relay.marker` so the rollback path can tell
///    "this is our config" apart from "operator hand-edited".
/// 5. `systemctl reload postfix` so the new main.cf takes effect.
///
/// Pre-conditions:
/// - postfix must already be installed (call `is_installed()` first).
/// - `cfg.smtp_host` non-empty (otherwise we'd write
///   `relayhost = []:587` which postfix accepts but rejects every
///   mail with "lost connection").
pub async fn ensure_relay_config(cfg: &EmailConfig) -> Result<(), AdapterError> {
    if cfg.smtp_host.trim().is_empty() {
        return Err(AdapterError::Other(
            "postfix relay: smtp_host is empty — cannot configure smart-host".into(),
        ));
    }

    // Port defaults to 587 (submission) which is the right choice
    // for STARTTLS / explicit-TLS. For implicit TLS (port 465) the
    // operator should set smtp_port = 465 in agent.toml AND
    // security = "tls". We honour whatever's in cfg.
    let relayhost = format!("[{}]:{}", cfg.smtp_host.trim(), cfg.smtp_port);

    // Step 1: main.cf via postconf. Each `-e key=value` is a separate
    // invocation because postconf needs them one-at-a-time on older
    // releases. The list is short so this is fine.
    //
    // smtp_tls_security_level=encrypt:
    //   require STARTTLS on the relay leg — modern providers
    //   (Mailgun, SendGrid, AWS SES) all support it, plain SMTP
    //   would expose the SASL password over the wire.
    //
    // smtp_tls_CAfile:
    //   point at the Debian ca-certificates bundle so the relay's
    //   cert verifies (without this postfix logs "Untrusted TLS
    //   connection established" but still sends, which is sloppy).
    //
    // smtp_sasl_security_options=noanonymous:
    //   refuse to fall back to no-auth even if the relay accepts it.
    //
    // smtp_sasl_tls_security_options=noanonymous:
    //   same but for the post-STARTTLS auth phase.
    let postconf_lines: &[&str] = &[
        &format!("relayhost={relayhost}"),
        "smtp_sasl_auth_enable=yes",
        &format!("smtp_sasl_password_maps=hash:{SASL_PASSWD_PATH}"),
        "smtp_sasl_security_options=noanonymous",
        "smtp_sasl_tls_security_options=noanonymous",
        "smtp_tls_security_level=encrypt",
        "smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt",
        "smtp_use_tls=yes",
    ];
    for line in postconf_lines {
        cmd::run("/usr/sbin/postconf", &["-e", line]).await?;
    }

    // Step 2: sasl_passwd. Atomic write at 0600 so the password
    // never lives in a world-readable temp file even briefly.
    // Format is one line per relayhost:
    //   [smtp.host]:port  user:password
    let sasl_body = format!(
        "{relayhost}    {user}:{password}\n",
        user = cfg.smtp_user,
        password = cfg.smtp_password,
    );
    atomic_write(Path::new(SASL_PASSWD_PATH), sasl_body.as_bytes(), 0o600).await?;

    // Step 3: postmap to build the lookup db. We also need to
    // chmod the .db file — postfix accepts either `.db` or `.lmdb`
    // depending on its build; postmap auto-picks the right one.
    cmd::run("/usr/sbin/postmap", &[SASL_PASSWD_PATH]).await?;
    // Belt-and-braces: chmod every sibling hash file. Wildcard
    // expansion via shell is unsafe, so we list both common shapes.
    for ext in ["db", "lmdb"] {
        let path = format!("{SASL_PASSWD_PATH}.{ext}");
        if tokio::fs::metadata(&path).await.is_ok() {
            let _ = tokio::fs::set_permissions(
                &path,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            )
            .await;
        }
    }

    // Step 4: marker so we can later detect "we wrote this config"
    // vs. "operator hand-edited". Contains the relayhost for
    // operator-friendly grep — no secrets.
    let marker = format!(
        "# managed by hyperion-agent — DO NOT EDIT by hand.\n\
         # to disable smart-host: set [email] enabled = false in agent.toml\n\
         relayhost={relayhost}\n",
    );
    atomic_write(Path::new(HYPERION_MARKER), marker.as_bytes(), 0o644).await?;

    // Step 5: reload (NOT restart — postfix reload is graceful and
    // doesn't drop in-flight deliveries).
    cmd::run("/usr/bin/systemctl", &["reload", "postfix"]).await?;
    Ok(())
}

/// Undo `ensure_relay_config`. Called when `[email] enabled = false`
/// in agent.toml — we leave postfix running in default-Internet-Site
/// mode rather than tearing it down completely, so the operator can
/// re-enable later without re-installing.
///
/// Only touches files when our marker is present. If an operator
/// hand-edited main.cf we leave it alone.
pub async fn rollback_relay_config() -> Result<(), AdapterError> {
    if tokio::fs::metadata(HYPERION_MARKER).await.is_err() {
        // Marker absent — either we never configured, or the
        // operator already cleaned up. Either way: no-op.
        return Ok(());
    }
    // Reset the keys we set, back to postfix defaults. postconf -X
    // removes a parameter entirely; postfix then uses its built-in
    // default (no relayhost = direct MX lookup).
    for key in [
        "relayhost",
        "smtp_sasl_auth_enable",
        "smtp_sasl_password_maps",
        "smtp_sasl_security_options",
        "smtp_sasl_tls_security_options",
        "smtp_tls_security_level",
        "smtp_tls_CAfile",
        "smtp_use_tls",
    ] {
        let _ = cmd::run("/usr/sbin/postconf", &["-X", key]).await;
    }
    // Strip credentials. Best-effort — if they fail we're not in a
    // worse place than before, since postfix no longer references them.
    for path in [
        SASL_PASSWD_PATH,
        &format!("{SASL_PASSWD_PATH}.db"),
        &format!("{SASL_PASSWD_PATH}.lmdb"),
        HYPERION_MARKER,
    ] {
        let _ = tokio::fs::remove_file(path).await;
    }
    let _ = cmd::run("/usr/bin/systemctl", &["reload", "postfix"]).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::EmailConfig;

    fn cfg() -> EmailConfig {
        EmailConfig {
            smtp_host: "smtp.mailgun.org".into(),
            smtp_port: 587,
            smtp_user: "postmaster@mg.example.com".into(),
            smtp_password: "abc-secret-pw".into(),
            from_address: "hyperion@example.com".into(),
            from_name: "Hyperion".into(),
            security: "starttls".into(),
        }
    }

    #[tokio::test]
    async fn ensure_relay_config_rejects_empty_host() {
        let mut c = cfg();
        c.smtp_host = "".into();
        let err = ensure_relay_config(&c).await.expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("smtp_host is empty"),
            "unexpected error message: {msg}"
        );
    }

    #[tokio::test]
    async fn ensure_relay_config_rejects_whitespace_host() {
        let mut c = cfg();
        c.smtp_host = "   ".into();
        let err = ensure_relay_config(&c).await.expect_err("must reject");
        assert!(err.to_string().contains("smtp_host is empty"));
    }
}
