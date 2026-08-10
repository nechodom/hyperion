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
use crate::email::EmailConfig;
use crate::fs::atomic_write;
use crate::AdapterError;
use std::path::Path;

/// `/etc/postfix/sasl_passwd` holds the relay credentials. We rewrite
/// it atomically + run `postmap` to produce the `.db` hash file
/// postfix actually reads.
const SASL_PASSWD_PATH: &str = "/etc/postfix/sasl_passwd";
/// Marker file written when our smart-host config is applied, so we
/// can clean up on `[email] enabled = false` rollback. Plain-text
/// breadcrumb the operator can `cat` for diagnostics.
const HYPERION_MARKER: &str = "/etc/postfix/hyperion-relay.marker";

/// Envelope-sender rewrite map: `<system_user>@<node fqdn>` on the left,
/// `bounce@<site domain>` on the right. One line per hosting that has
/// envelope alignment switched on.
///
/// Why this exists: PHP `mail()` produces an envelope sender of
/// `<php-fpm user>@<node fqdn>`, and SPF is evaluated against the
/// ENVELOPE domain. So the per-site SPF record the panel tells the
/// operator to publish was never consulted by anyone — receivers were
/// checking the node's own FQDN instead. Rewriting the envelope is what
/// makes that record real.
const SENDER_CANONICAL_PATH: &str = "/etc/postfix/hyperion_sender_canonical";

/// Settings for [`ensure_direct_delivery_config`] beyond the hostname.
/// A struct rather than more positional arguments — every field here is
/// an address or a protocol token, so a swapped pair would type-check.
#[derive(Debug, Clone, Default)]
pub struct DirectDeliveryOpts {
    /// `inet_protocols`. `None` ⇒ `ipv4`.
    ///
    /// IPv4-only is the deliverability-safe default for a send-only box:
    /// Postfix prefers AAAA when a receiving MX has one, and a node whose
    /// PTR and SPF cover only its IPv4 address then gets a hard 5xx from
    /// the large receivers with no IPv4 retry. An operator who has set up
    /// a v6 PTR and `ip6:` in SPF can set this to `all`.
    pub inet_protocols: Option<String>,
    /// `smtp_bind_address` — the source address for outbound SMTP.
    ///
    /// Unset means the kernel chooses, which on a multi-homed node can
    /// pick an address whose PTR does not match `myhostname` and which no
    /// SPF record lists. Pin it to the address the PTR belongs to.
    pub bind_address: Option<String>,
}

/// True when an SMTP relay host refers to THIS machine — `localhost`, a loopback
/// IP, or our own (short or fully-qualified) hostname. Such a "relay" can't be a
/// postfix smart-host: postfix would try to relay through itself and defer every
/// message with "mail for localhost loops back to myself". Callers must fall back
/// to direct-MX delivery instead. `my_fqdn` is this node's `hostname -f`.
pub fn host_is_local(smtp_host: &str, my_fqdn: &str) -> bool {
    let (h, _) = crate::email::normalize_smtp_host(smtp_host);
    let h = h.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if h.is_empty()
        || h == "localhost"
        || h == "::1"
        || h == "0.0.0.0"
        || h == "::"
        || h.starts_with("127.")
        || h.ends_with(".localhost")
    {
        return true;
    }
    let fqdn = my_fqdn.trim().to_ascii_lowercase();
    if fqdn.is_empty() {
        return false;
    }
    // Relay is exactly our FQDN, or our FQDN's short label (relay typed as
    // the bare hostname while we know our full name).
    if h == fqdn || fqdn.split('.').next() == Some(h.as_str()) {
        return true;
    }
    // Degraded: we only know our SHORT name (`hostname -f` returned no
    // domain), so `h == fqdn` can't catch a relay typed as our full FQDN.
    // Fall back to a short-label compare in THAT case only — when we DO
    // know our real FQDN we skip this, so a legitimate external relay that
    // merely shares our short label (our `mail.acme.com` vs a relay
    // `mail.sendgrid.net`) is still configured as a smart-host.
    if !fqdn.contains('.') && h.split('.').next() == Some(fqdn.as_str()) {
        return true;
    }
    false
}

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
    // `smtp_host` is interpolated into `relayhost=[host]:port` (a postconf arg)
    // and into the sasl_passwd map body. Restrict it to hostname/IP characters
    // so it can't carry whitespace/newlines that corrupt the map or smuggle a
    // second postconf token — parity with the direct-delivery path's myhostname
    // check. `smtp_user` lands in `host  user:password`, so reject `:`/controls.
    // Strip a port the operator may have pasted into the host field
    // ("localhost:25") so the relayhost isn't built as "[localhost:25]:25".
    let (host, embedded_port) = crate::email::normalize_smtp_host(&cfg.smtp_host);
    let host = host.trim().to_string();
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
    {
        return Err(AdapterError::Other(
            "postfix relay: smtp_host has invalid characters".into(),
        ));
    }
    if cfg.smtp_user.contains([':', '\n', '\r', '\0', ' ', '\t'])
        || cfg.smtp_password.contains(['\n', '\r', '\0'])
    {
        return Err(AdapterError::Other(
            "postfix relay: smtp_user/smtp_password contains an illegal character".into(),
        ));
    }

    // Port defaults to 587 (submission) which is the right choice
    // for STARTTLS / explicit-TLS. For implicit TLS (port 465) the
    // operator should set smtp_port = 465 in agent.toml AND
    // security = "tls". We honour whatever's in cfg.
    let port = if cfg.smtp_port != 0 {
        cfg.smtp_port
    } else {
        embedded_port.unwrap_or(587)
    };
    let relayhost = format!("[{host}]:{port}");

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

/// Configure postfix for **direct MX delivery** — no SMTP relay,
/// no third-party provider. The operator handles SPF / DKIM / PTR
/// records themselves and accepts that delivery success depends on
/// their VPS IP's reputation. This is the "I just want to send mail
/// from my own box" path.
///
/// What we set (via `postconf -e`):
/// * `myhostname` = the operator-supplied FQDN. This is what postfix
///   uses as the SMTP HELO/EHLO greeting AND as the @ domain on
///   local mail. It MUST be a real FQDN matching the IP's PTR
///   record — receiving servers reject anything else.
/// * `smtp_helo_name = $myhostname` — belt-and-braces so a future
///   distro default doesn't override HELO with something dumb.
/// * `myorigin = $myhostname` — From-stamp on local-originated mail
///   (without this, "root@stav" appears, which receiving servers
///   often reject as a hostname-only domain).
/// * `mydestination = $myhostname, localhost.$mydomain, localhost`
///   — postfix only accepts mail TO these (we don't want this box
///   to be an open relay).
/// * `relayhost = ` (cleared) — direct MX lookup for every send.
/// * `inet_interfaces = loopback-only` — refuse to listen for
///   inbound SMTP on the public IP. Hyperion's not a mail-server
///   panel; the only legitimate SMTP traffic INTO this box is from
///   localhost (the PHP wrapper → /usr/sbin/sendmail). Closing the
///   public port 25 listener eliminates a whole class of relay/
///   abuse risk.
/// * `inet_protocols = all` — IPv4 + IPv6 outbound (some recipients
///   only have v6 MX records).
/// * `smtputf8_enable = yes` — non-ASCII headers / addresses go
///   through unmangled.
///
/// The same marker file (`hyperion-relay.marker`) used by relay
/// mode is written here too — its body just changes to reflect
/// the active mode, so an operator can `cat` it to see which path
/// the agent picked.
pub async fn ensure_direct_delivery_config(
    myhostname: &str,
    opts: &DirectDeliveryOpts,
) -> Result<(), AdapterError> {
    let myhostname = myhostname.trim();
    if myhostname.is_empty() {
        return Err(AdapterError::Other(
            "postfix direct delivery: myhostname is empty — pass a real FQDN".into(),
        ));
    }
    // Sanity-check the FQDN shape so we never paste shell garbage
    // into main.cf. Letters, digits, dots, hyphens — POSIX hostname
    // chars plus dot.
    if !myhostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(AdapterError::Other(format!(
            "postfix direct delivery: myhostname `{myhostname}` has invalid chars"
        )));
    }

    // Validate before it reaches `postconf`, same reason as the hostname
    // above: this string ends up in main.cf.
    let protocols = match opts.inet_protocols.as_deref().map(str::trim) {
        Some(p) if matches!(p, "ipv4" | "ipv6" | "all") => p,
        Some(p) if !p.is_empty() => {
            return Err(AdapterError::Other(format!(
                "postfix direct delivery: inet_protocols `{p}` must be ipv4, ipv6 or all"
            )))
        }
        _ => "ipv4",
    };
    if let Some(ip) = opts.bind_address.as_deref().map(str::trim) {
        if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_err() {
            return Err(AdapterError::Other(format!(
                "postfix direct delivery: smtp_bind_address `{ip}` is not an IP address"
            )));
        }
    }

    let postconf_lines: &[&str] = &[
        &format!("myhostname={myhostname}"),
        "smtp_helo_name=$myhostname",
        "myorigin=$myhostname",
        // Loopback aliases plus our own hostname. Operator can
        // expand this later if they really want this box to accept
        // mail for additional domains, but the safe default is no.
        "mydestination=$myhostname, localhost.$mydomain, localhost",
        // Closed listener: public port 25 returns "connection refused"
        // so we can't be turned into an open relay. The wrapper still
        // reaches /usr/sbin/sendmail because PHP execs it locally —
        // /usr/sbin/sendmail talks to the postfix master via UNIX
        // socket (/var/spool/postfix/...), not the network listener.
        "inet_interfaces=loopback-only",
        &format!("inet_protocols={protocols}"),
        "smtputf8_enable=yes",
        // Opportunistic TLS, set EXPLICITLY rather than left to whatever
        // the box happens to hold. Two failures ride on this being
        // stated: a node switched here from a smart host inherits
        // `encrypt` from `ensure_relay_config`, which is MANDATORY TLS —
        // correct for one known relay, wrong for public MX delivery,
        // where it defers and then bounces every message to a receiver
        // that offers no STARTTLS. And a box whose main.cf never had the
        // key sends in cleartext. `may` is the only correct policy here:
        // encrypt when the far side offers it, deliver either way, and
        // do not verify certificates (public MXs routinely present names
        // that do not match).
        "smtp_tls_security_level=may",
        // Retry a deferred delivery after 1 minute instead of postfix's
        // default 5. The dominant deferral for a send-only box with a
        // young IP is GREYLISTING — the receiver 450s the first attempt
        // on purpose and accepts the retry — and with the default
        // backoff every greylisted message costs five minutes of
        // "where is my e-mail". Most greylisters require ~60 s of age,
        // so retrying sooner than this buys nothing, and retrying at
        // this rate is well within polite behaviour.
        "minimal_backoff_time=60s",
        "maximal_backoff_time=600s",
    ];
    for line in postconf_lines {
        cmd::run("/usr/sbin/postconf", &["-e", line]).await?;
    }
    // Pin the source address when the operator has told us which one the
    // PTR belongs to; otherwise leave the kernel's choice alone rather
    // than guessing at an address and breaking a working node.
    match opts.bind_address.as_deref().map(str::trim) {
        Some(ip) if !ip.is_empty() => {
            cmd::run(
                "/usr/sbin/postconf",
                &["-e", &format!("smtp_bind_address={ip}")],
            )
            .await?;
        }
        _ => {
            let _ = cmd::run("/usr/sbin/postconf", &["-X", "smtp_bind_address"]).await;
        }
    }
    // Explicitly clear the relayhost (in case we were in smart-host
    // mode before). postconf -X drops the parameter, postfix then
    // falls back to its built-in default (empty = direct MX).
    let _ = cmd::run("/usr/sbin/postconf", &["-X", "relayhost"]).await;
    // Same with SASL knobs — they were set by ensure_relay_config
    // and would otherwise sit there inert but confusing.
    for key in [
        "smtp_sasl_auth_enable",
        "smtp_sasl_password_maps",
        "smtp_sasl_security_options",
        "smtp_sasl_tls_security_options",
        // Obsolete boolean from the relay config. Harmless beside an
        // explicit `smtp_tls_security_level`, but leaving two knobs that
        // both claim to control TLS is how the next reader gets it wrong.
        "smtp_use_tls",
    ] {
        let _ = cmd::run("/usr/sbin/postconf", &["-X", key]).await;
    }
    // Best-effort: remove the sasl_passwd files left behind by an
    // earlier smart-host config. Failure is fine — postfix doesn't
    // care about a stale unreferenced file.
    for path in [
        SASL_PASSWD_PATH,
        &format!("{SASL_PASSWD_PATH}.db"),
        &format!("{SASL_PASSWD_PATH}.lmdb"),
    ] {
        let _ = tokio::fs::remove_file(path).await;
    }

    let marker = format!(
        "# managed by hyperion-agent — DO NOT EDIT by hand.\n\
         mode=direct-mx\n\
         myhostname={myhostname}\n\
         inet_protocols={protocols}\n\
         smtp_bind_address={}\n\
         # Operator is responsible for the IP's PTR record + SPF\n\
         # on every domain hosted on this node.\n",
        opts.bind_address.as_deref().unwrap_or("").trim(),
    );
    atomic_write(Path::new(HYPERION_MARKER), marker.as_bytes(), 0o644).await?;
    // RESTART, not reload: `inet_protocols` is read once when the master
    // process starts and binds its sockets, so a reload leaves a node
    // still talking IPv6 while main.cf says otherwise — the config would
    // look applied and the mail would keep bouncing. Restarting is
    // acceptable here because postfix is send-only (`inet_interfaces =
    // loopback-only`), so nothing inbound is dropped, and queued mail
    // survives a restart.
    cmd::run("/usr/bin/systemctl", &["restart", "postfix"]).await?;
    Ok(())
}

/// Rewrite the envelope-sender map and point postfix at it.
///
/// `entries` is `(local_part_source, site_domain)` — the caller passes
/// each hosting's system user and the domain its mail should appear to
/// come from. An empty list REMOVES the mapping entirely rather than
/// leaving an empty map behind, so "switched off everywhere" and "never
/// switched on" are the same state on disk.
///
/// Only `envelope_sender` is rewritten. That is load-bearing: OpenDKIM
/// signs the `From:` HEADER, so touching headers here would invalidate
/// every signature this node produces. `sender_canonical_classes` is set
/// explicitly because Postfix's default for it covers headers too.
pub async fn ensure_sender_canonical(
    my_fqdn: &str,
    entries: &[(String, String)],
) -> Result<(), AdapterError> {
    let my_fqdn = my_fqdn.trim().to_ascii_lowercase();
    if my_fqdn.is_empty() {
        return Err(AdapterError::Other(
            "postfix sender canonical: node FQDN is empty".into(),
        ));
    }
    if entries.is_empty() {
        let _ = cmd::run("/usr/sbin/postconf", &["-X", "sender_canonical_maps"]).await;
        let _ = cmd::run("/usr/sbin/postconf", &["-X", "sender_canonical_classes"]).await;
        for path in [
            SENDER_CANONICAL_PATH,
            &format!("{SENDER_CANONICAL_PATH}.db"),
            &format!("{SENDER_CANONICAL_PATH}.lmdb"),
        ] {
            let _ = tokio::fs::remove_file(path).await;
        }
        cmd::run("/usr/bin/systemctl", &["reload", "postfix"]).await?;
        return Ok(());
    }

    let mut body = String::from(
        "# managed by hyperion-agent — DO NOT EDIT by hand.\n\
         # Envelope sender only. SPF is checked against the envelope\n\
         # domain, so without these lines the per-site SPF record is\n\
         # never consulted — receivers evaluate this node's FQDN.\n",
    );
    for (system_user, domain) in entries {
        let (u, d) = (system_user.trim(), domain.trim().to_ascii_lowercase());
        // Refuse anything that could add a second field or a comment to
        // a line postfix parses on whitespace.
        if u.is_empty()
            || d.is_empty()
            || !u
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            || !d
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(AdapterError::Other(format!(
                "postfix sender canonical: refusing entry `{u}` -> `{d}`"
            )));
        }
        body.push_str(&format!("{u}@{my_fqdn}\tbounce@{d}\n"));
        // PHP hands sendmail a bare local part when the pool has no
        // domain of its own; postfix qualifies it with `myorigin`, but
        // mapping it directly costs one line and removes the dependency.
        body.push_str(&format!("{u}\tbounce@{d}\n"));
    }
    atomic_write(Path::new(SENDER_CANONICAL_PATH), body.as_bytes(), 0o644).await?;
    cmd::run("/usr/sbin/postmap", &[SENDER_CANONICAL_PATH]).await?;
    for line in [
        &format!("sender_canonical_maps=hash:{SENDER_CANONICAL_PATH}"),
        "sender_canonical_classes=envelope_sender",
    ] {
        cmd::run("/usr/sbin/postconf", &["-e", line]).await?;
    }
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

    /// The direct-MX knobs reach `postconf` as strings, so they are
    /// validated before they get there — same reason `myhostname` is.
    #[tokio::test]
    async fn direct_delivery_rejects_junk_before_it_reaches_postconf() {
        // Nothing here should ever execute postconf; each call must fail
        // on validation. (A machine WITH postfix would otherwise be
        // reconfigured by its own test suite.)
        let bad_proto = DirectDeliveryOpts {
            inet_protocols: Some("ipv4; rm -rf /".into()),
            ..Default::default()
        };
        let e = ensure_direct_delivery_config("mail.example.com", &bad_proto)
            .await
            .expect_err("must reject");
        assert!(format!("{e}").contains("inet_protocols"), "{e}");

        let bad_bind = DirectDeliveryOpts {
            bind_address: Some("not-an-ip".into()),
            ..Default::default()
        };
        let e = ensure_direct_delivery_config("mail.example.com", &bad_bind)
            .await
            .expect_err("must reject");
        assert!(format!("{e}").contains("smtp_bind_address"), "{e}");

        // The hostname guard predates this and must still fire first.
        let e = ensure_direct_delivery_config("mail example com", &DirectDeliveryOpts::default())
            .await
            .expect_err("must reject");
        assert!(format!("{e}").contains("invalid chars"), "{e}");
    }

    /// A map line is parsed by postfix on whitespace, so anything that
    /// could introduce a second field — or a comment — is refused rather
    /// than escaped. An entry that silently failed to match would leave
    /// that site's envelope on the node hostname while the panel reported
    /// its SPF as fine.
    #[tokio::test]
    async fn sender_canonical_refuses_entries_that_could_forge_a_line() {
        for (user, domain) in [
            ("site1 evil", "example.cz"),
            ("site1", "example.cz nope"),
            ("site1", "example.cz\n@other"),
            ("site1\t", "exa mple.cz"),
            ("", "example.cz"),
            ("site1", ""),
            ("site1", "example.cz#comment"),
        ] {
            let e = ensure_sender_canonical(
                "node.example.com",
                &[(user.to_string(), domain.to_string())],
            )
            .await
            .expect_err("must refuse {user:?} -> {domain:?}");
            assert!(
                format!("{e}").contains("refusing entry"),
                "{user:?} -> {domain:?} gave {e}"
            );
        }

        // A node with no FQDN cannot build a left-hand side at all.
        let e = ensure_sender_canonical("  ", &[("site1".into(), "example.cz".into())])
            .await
            .expect_err("must refuse");
        assert!(format!("{e}").contains("FQDN is empty"), "{e}");
    }

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

    #[tokio::test]
    async fn ensure_direct_delivery_rejects_empty_hostname() {
        let err = ensure_direct_delivery_config("", &DirectDeliveryOpts::default())
            .await
            .expect_err("must reject");
        assert!(err.to_string().contains("myhostname is empty"));
    }

    #[tokio::test]
    async fn ensure_direct_delivery_rejects_whitespace_hostname() {
        let err = ensure_direct_delivery_config("   ", &DirectDeliveryOpts::default())
            .await
            .expect_err("must reject");
        assert!(err.to_string().contains("myhostname is empty"));
    }

    /// Path-injection guard: hostname with shell metachars must NOT
    /// reach `postconf -e myhostname=...` — they're passed as argv
    /// so no shell, but bad input also signals we'd never get a
    /// real FQDN out of this.
    #[tokio::test]
    async fn ensure_direct_delivery_rejects_shell_metachars() {
        let err = ensure_direct_delivery_config("stav;rm -rf /", &DirectDeliveryOpts::default())
            .await
            .expect_err("must reject");
        assert!(err.to_string().contains("invalid chars"));
        let err = ensure_direct_delivery_config("$(whoami).cz", &DirectDeliveryOpts::default())
            .await
            .expect_err("must reject");
        assert!(err.to_string().contains("invalid chars"));
    }

    /// Real FQDNs pass the input validation. We don't actually run
    /// postconf in tests, so the test only proves "input validation
    /// doesn't false-positive on legitimate hostnames".
    #[test]
    fn fqdn_charset_accepts_real_hostnames() {
        for fqdn in [
            "stav.example.cz",
            "mail-01.eu-central-1.aws.example.com",
            "01-prod.tvujkluster.cz",
        ] {
            assert!(
                fqdn.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
                "false-positive reject for: {fqdn}"
            );
        }
    }

    #[test]
    fn host_is_local_detects_self_and_loopback() {
        let fqdn = "s4.digitalka.cz";
        // Self-referential relays → must be treated as local (→ direct MX).
        for h in [
            "localhost",
            "localhost:25",
            "127.0.0.1",
            "127.0.0.53",
            "::1",
            "[::1]:25",
            "s4",              // our short hostname
            "s4.digitalka.cz", // our fqdn
            "S4.DIGITALKA.CZ", // case-insensitive
            "",                // empty ⇒ no relay
        ] {
            assert!(host_is_local(h, fqdn), "should be local: {h:?}");
        }
        // Real external relays → NOT local.
        for h in [
            "smtp.postmarkapp.com",
            "smtp.mailgun.org:587",
            "10.0.0.5",
            "mail.digitalka.cz", // different host under same domain
        ] {
            assert!(!host_is_local(h, fqdn), "should NOT be local: {h:?}");
        }
    }

    #[test]
    fn host_is_local_degraded_short_fqdn() {
        // Boot regression: `hostname -f` returned no domain, so we only know
        // the SHORT name "s4". A relay typed as the node's OWN full FQDN must
        // STILL be caught as local — otherwise it becomes relayhost= and
        // postfix loops back to itself.
        assert!(
            host_is_local("s4.digitalka.cz", "s4"),
            "relay = our full fqdn while we only know our short name → local"
        );
        assert!(host_is_local("s4", "s4"), "short == short → local");

        // But sharing a short label with an EXTERNAL relay must NOT be
        // treated as local when it can't be our own box. With a short-only
        // self-name this is unavoidable (we can't tell them apart), so the
        // guard is deliberately scoped: once we DO know our full fqdn, a
        // relay sharing only the short label is external.
        assert!(
            !host_is_local("mail.sendgrid.net", "mail.acme.com"),
            "external relay sharing our short label, full fqdn known → NOT local"
        );
    }
}
