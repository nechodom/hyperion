//! DKIM signing for outbound mail via OpenDKIM, driven as a postfix milter.
//!
//! Architecture: OpenDKIM runs once per node as a milter on a loopback socket
//! (`inet:8891@127.0.0.1`). Postfix is wired to call it for BOTH SMTP-received
//! and locally-injected mail — `non_smtpd_milters` is the load-bearing one,
//! because a hosted site's `mail()` reaches postfix through the local
//! `/usr/sbin/sendmail` pickup path, never over SMTP. `milter_default_action =
//! accept` makes signing fail-OPEN: if OpenDKIM is down, mail still flows
//! (unsigned) rather than deferring in the queue.
//!
//! Per signing domain we keep an RSA keypair under
//! `/etc/opendkim/keys/<domain>/<selector>.private` and two table entries:
//!   * `KeyTable`     — `<sel>._domainkey.<domain> <domain>:<sel>:<keypath>`
//!   * `SigningTable` — `*@<domain> <sel>._domainkey.<domain>`
//! OpenDKIM re-reads the tables on reload, so enabling/disabling a domain is
//! an edit + `systemctl reload opendkim`, never a restart.
//!
//! Hyperion does NOT publish DNS. Enabling a domain generates the key and
//! returns the public half; the operator publishes the
//! `<sel>._domainkey.<domain>` TXT record themselves, and a later verify step
//! (see `service::dkim_*`) confirms it — exactly the SPF-check pattern.

use crate::fs::atomic_write;
use crate::{cmd, AdapterError};
use std::path::{Path, PathBuf};

const OPENDKIM_CONF: &str = "/etc/opendkim.conf";
const KEY_TABLE: &str = "/etc/opendkim/KeyTable";
const SIGNING_TABLE: &str = "/etc/opendkim/SigningTable";
const TRUSTED_HOSTS: &str = "/etc/opendkim/TrustedHosts";
const KEYS_DIR: &str = "/etc/opendkim/keys";
const DEFAULTS_FILE: &str = "/etc/default/opendkim";
/// Milter endpoint shared by OpenDKIM (`Socket`) and postfix (`*_milters`).
/// Pinned to a literal 127.0.0.1 (not `localhost`) so the daemon's bind and
/// postfix's connect can't disagree over a hosts-file `localhost → ::1`.
const MILTER_SOCKET_OPENDKIM: &str = "inet:8891@127.0.0.1";
const MILTER_SOCKET_POSTFIX: &str = "inet:127.0.0.1:8891";

/// The fixed selector Hyperion signs with. A single stable selector means the
/// published DNS TXT record never has to change; key rotation (a new selector)
/// is a separate, explicit operation we don't do yet.
pub const DEFAULT_SELECTOR: &str = "hyperion";

/// Guard a domain before it reaches a shell arg, a file path, or a table line.
/// Letters, digits, dots, hyphens — nothing that could break out of an
/// `opendkim-genkey -d <domain>` invocation or traverse the keys directory.
pub fn is_safe_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain != "."
        && !domain.starts_with('.')
        && !domain.contains("..")
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Guard a selector — the DNS label left of `._domainkey`. Alphanumeric plus
/// `-`/`_`, which is the DKIM selector charset.
pub fn is_safe_selector(selector: &str) -> bool {
    !selector.is_empty()
        && selector.len() <= 63
        && selector
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// DNS name the public key is published at: `<selector>._domainkey.<domain>`.
pub fn dkim_dns_name(domain: &str, selector: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

/// One `KeyTable` line: maps the signing-key name to `domain:selector:keypath`.
fn key_table_line(domain: &str, selector: &str, key_path: &str) -> String {
    format!(
        "{sel}._domainkey.{domain} {domain}:{sel}:{key_path}",
        sel = selector
    )
}

/// One `SigningTable` line: every `user@domain` sender signs with this key.
/// Read via `refile:` (regex map), where `*` matches the local part.
fn signing_table_line(domain: &str, selector: &str) -> String {
    format!("*@{domain} {selector}._domainkey.{domain}")
}

/// Absolute path of a domain's private key.
fn key_path(domain: &str, selector: &str) -> PathBuf {
    PathBuf::from(KEYS_DIR)
        .join(domain)
        .join(format!("{selector}.private"))
}

/// The DNS TXT *value* an operator should publish for `pubkey`.
pub fn dkim_txt_value(pubkey: &str) -> String {
    format!("v=DKIM1; k=rsa; p={pubkey}")
}

/// The static `opendkim.conf` body. Sign-only (`Mode s`) — this node is a
/// sender, not an inbound verifier (its postfix listens on loopback only).
fn opendkim_conf() -> String {
    format!(
        "# managed by hyperion-agent — DO NOT EDIT by hand.\n\
         Syslog                  yes\n\
         SyslogSuccess           yes\n\
         UMask                   007\n\
         Mode                    s\n\
         Canonicalization        relaxed/relaxed\n\
         Socket                  {MILTER_SOCKET_OPENDKIM}\n\
         PidFile                 /run/opendkim/opendkim.pid\n\
         UserID                  opendkim\n\
         KeyTable                {KEY_TABLE}\n\
         SigningTable            refile:{SIGNING_TABLE}\n\
         InternalHosts           {TRUSTED_HOSTS}\n\
         OversignHeaders         From\n\
         SubDomains              no\n\
         AutoRestart             yes\n\
         AutoRestartRate         10/1h\n"
    )
}

/// Hosts OpenDKIM signs FOR rather than verifies — just this box.
fn trusted_hosts() -> &'static str {
    "127.0.0.1\n::1\nlocalhost\n"
}

/// Extract the base64 public key (`p=` tag value) from a DKIM TXT blob —
/// works on both OpenDKIM's generated `.txt` (BIND zone syntax, the value
/// split across several `"…"` continuation strings) and a raw published TXT
/// record. Joins every quoted segment, then reads `p=` up to the next `;`,
/// stripping ALL whitespace so a wrapped key compares equal to a flat one.
/// Returns `None` when there's no non-empty `p=`.
pub fn extract_p_tag(dkim_txt: &str) -> Option<String> {
    // Stitch the contents of every "..." run; if there are no quotes, take
    // the string as-is.
    let stitched = if dkim_txt.contains('"') {
        let mut out = String::new();
        let mut in_q = false;
        for ch in dkim_txt.chars() {
            match ch {
                '"' => in_q = !in_q,
                _ if in_q => out.push(ch),
                _ => {}
            }
        }
        out
    } else {
        dkim_txt.to_string()
    };
    let start = stitched.find("p=")? + 2;
    let rest = &stitched[start..];
    let end = rest.find(';').unwrap_or(rest.len());
    let key: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

/// Is `published` (a TXT record fetched from DNS) a DKIM record whose public
/// key matches `our_pubkey`? Both sides are reduced to their `p=` base64.
pub fn published_key_matches(published: &str, our_pubkey: &str) -> bool {
    match extract_p_tag(published) {
        Some(p) => {
            p == our_pubkey
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        }
        None => false,
    }
}

/// Is OpenDKIM installed on this node?
pub async fn is_installed() -> bool {
    Path::new("/usr/sbin/opendkim").exists() || Path::new("/usr/bin/opendkim-genkey").exists()
}

/// Install OpenDKIM (best-effort apt). No-op if already present.
pub async fn ensure_installed() -> Result<(), AdapterError> {
    if is_installed().await {
        return Ok(());
    }
    // Force DEBIAN_FRONTEND=noninteractive via env(1): cmd::run doesn't set
    // env vars, and opendkim's postinst can otherwise block on a debconf
    // prompt and hang the whole enable request. -qq keeps apt output quiet.
    cmd::run(
        "/usr/bin/env",
        &[
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "-y",
            "-qq",
            "opendkim",
            "opendkim-tools",
        ],
    )
    .await?;
    Ok(())
}

/// Ensure the node-wide OpenDKIM config, tables and the postfix milter wiring
/// exist. Idempotent: writes the static config + empty tables only if missing
/// (never clobbers accumulated per-domain table rows), then re-asserts the
/// postfix `*_milters` knobs (targeted `postconf -e`, so postfix mode
/// reconfigures don't drop them) and reloads both daemons.
pub async fn ensure_configured() -> Result<(), AdapterError> {
    // Key + table directories.
    for dir in [KEYS_DIR, "/etc/opendkim"] {
        cmd::run("/bin/mkdir", &["-p", dir]).await?;
    }
    atomic_write(Path::new(OPENDKIM_CONF), opendkim_conf().as_bytes(), 0o644).await?;
    atomic_write(Path::new(TRUSTED_HOSTS), trusted_hosts().as_bytes(), 0o644).await?;
    // CRITICAL: on Debian/Ubuntu the opendkim systemd unit sources
    // /etc/default/opendkim, and a `SOCKET=` there is passed as `opendkim -p
    // <socket>`, which OVERRIDES the `Socket` directive in opendkim.conf.
    // Distros that ship `SOCKET="local:/run/opendkim/opendkim.sock"` would
    // leave the daemon on a unix socket while postfix dials inet:127.0.0.1:8891
    // — the milter connect is refused and (milter_default_action=accept) every
    // message ships UNSIGNED, silently. Pin SOCKET to the same inet endpoint.
    atomic_write(
        Path::new(DEFAULTS_FILE),
        format!(
            "# managed by hyperion-agent — DO NOT EDIT by hand.\n\
             SOCKET=\"{MILTER_SOCKET_OPENDKIM}\"\n"
        )
        .as_bytes(),
        0o644,
    )
    .await?;
    // Create the tables only if absent — they carry per-domain state.
    for tbl in [KEY_TABLE, SIGNING_TABLE] {
        if !Path::new(tbl).exists() {
            atomic_write(Path::new(tbl), b"", 0o644).await?;
        }
    }
    // opendkim must own its keys tree.
    let _ = cmd::run("/bin/chown", &["-R", "opendkim:opendkim", "/etc/opendkim"]).await;

    // Wire postfix to the milter. Targeted postconf -e survives both
    // direct-MX and smart-host reconfigures (they set different keys).
    for kv in [
        &format!("smtpd_milters={MILTER_SOCKET_POSTFIX}"),
        &format!("non_smtpd_milters={MILTER_SOCKET_POSTFIX}"),
        "milter_default_action=accept",
        "milter_protocol=6",
    ] {
        cmd::run("/usr/sbin/postconf", &["-e", kv]).await?;
    }

    let _ = cmd::run("/usr/bin/systemctl", &["enable", "opendkim"]).await;
    let _ = cmd::run("/usr/bin/systemctl", &["restart", "opendkim"]).await;
    let _ = cmd::run("/usr/bin/systemctl", &["reload", "postfix"]).await;
    Ok(())
}

/// Generate a 2048-bit keypair for `domain`/`selector` under the keys tree if
/// one isn't already there, and return the public key (base64 `p=` value).
/// Re-enabling a domain reuses the existing key so a published TXT record
/// stays valid — regeneration is a separate, explicit rotate.
pub async fn genkey(domain: &str, selector: &str) -> Result<String, AdapterError> {
    if !is_safe_domain(domain) {
        return Err(AdapterError::Other(format!("unsafe DKIM domain: {domain}")));
    }
    if !is_safe_selector(selector) {
        return Err(AdapterError::Other(format!(
            "unsafe DKIM selector: {selector}"
        )));
    }
    let dir = PathBuf::from(KEYS_DIR).join(domain);
    cmd::run("/bin/mkdir", &["-p", &dir.to_string_lossy()]).await?;
    let priv_path = key_path(domain, selector);
    let txt_path = dir.join(format!("{selector}.txt"));
    if !priv_path.exists() {
        cmd::run(
            "/usr/bin/opendkim-genkey",
            &[
                "-b",
                "2048",
                "-s",
                selector,
                "-d",
                domain,
                "-D",
                &dir.to_string_lossy(),
            ],
        )
        .await?;
        // opendkim must read the private key; lock it to that user, 600.
        let _ = cmd::run(
            "/bin/chown",
            &["opendkim:opendkim", &priv_path.to_string_lossy()],
        )
        .await;
        let _ = cmd::run("/bin/chmod", &["600", &priv_path.to_string_lossy()]).await;
    }
    let txt = tokio::fs::read_to_string(&txt_path)
        .await
        .map_err(|e| AdapterError::Other(format!("read {}: {e}", txt_path.display())))?;
    extract_p_tag(&txt)
        .ok_or_else(|| AdapterError::Other(format!("no p= in generated {}", txt_path.display())))
}

/// Read back a domain's already-generated public key, if present.
pub async fn read_pubkey(domain: &str, selector: &str) -> Option<String> {
    if !is_safe_domain(domain) || !is_safe_selector(selector) {
        return None;
    }
    let txt_path = PathBuf::from(KEYS_DIR)
        .join(domain)
        .join(format!("{selector}.txt"));
    let txt = tokio::fs::read_to_string(&txt_path).await.ok()?;
    extract_p_tag(&txt)
}

/// Add `domain`'s KeyTable + SigningTable rows (idempotent) and reload
/// OpenDKIM so it starts signing that domain's mail.
pub async fn enable_signing(domain: &str, selector: &str) -> Result<(), AdapterError> {
    if !is_safe_domain(domain) || !is_safe_selector(selector) {
        return Err(AdapterError::Other("unsafe DKIM domain/selector".into()));
    }
    let kp = key_path(domain, selector);
    ensure_line(
        KEY_TABLE,
        &key_table_line(domain, selector, &kp.to_string_lossy()),
    )
    .await?;
    ensure_line(SIGNING_TABLE, &signing_table_line(domain, selector)).await?;
    reload().await
}

/// Remove `domain`'s table rows (idempotent) and reload OpenDKIM. Leaves the
/// key material on disk so a re-enable doesn't invalidate a published record;
/// `purge_keys` deletes it.
pub async fn disable_signing(domain: &str, selector: &str) -> Result<(), AdapterError> {
    if !is_safe_domain(domain) || !is_safe_selector(selector) {
        return Err(AdapterError::Other("unsafe DKIM domain/selector".into()));
    }
    remove_line_containing(KEY_TABLE, &format!("{selector}._domainkey.{domain} ")).await?;
    remove_line_containing(SIGNING_TABLE, &format!("*@{domain} ")).await?;
    reload().await
}

/// Delete a domain's key material entirely (after `disable_signing`).
pub async fn purge_keys(domain: &str) -> Result<(), AdapterError> {
    if !is_safe_domain(domain) {
        return Err(AdapterError::Other(format!("unsafe DKIM domain: {domain}")));
    }
    let dir = PathBuf::from(KEYS_DIR).join(domain);
    let _ = tokio::fs::remove_dir_all(&dir).await;
    Ok(())
}

async fn reload() -> Result<(), AdapterError> {
    cmd::run("/usr/bin/systemctl", &["reload-or-restart", "opendkim"]).await?;
    Ok(())
}

/// Append `line` to `path` unless a byte-identical line is already there.
async fn ensure_line(path: &str, line: &str) -> Result<(), AdapterError> {
    let body = tokio::fs::read_to_string(path).await.unwrap_or_default();
    if body.lines().any(|l| l == line) {
        return Ok(());
    }
    let mut next = body;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(line);
    next.push('\n');
    atomic_write(Path::new(path), next.as_bytes(), 0o644).await
}

/// Drop every line from `path` that starts with `prefix`.
async fn remove_line_containing(path: &str, prefix: &str) -> Result<(), AdapterError> {
    let Ok(body) = tokio::fs::read_to_string(path).await else {
        return Ok(());
    };
    let kept: Vec<&str> = body.lines().filter(|l| !l.starts_with(prefix)).collect();
    let mut next = kept.join("\n");
    if !next.is_empty() {
        next.push('\n');
    }
    atomic_write(Path::new(path), next.as_bytes(), 0o644).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_guard_rejects_shell_and_traversal() {
        assert!(is_safe_domain("example.com"));
        assert!(is_safe_domain("sub.example.co.uk"));
        assert!(!is_safe_domain("ex;rm -rf /.com"));
        assert!(!is_safe_domain("$(whoami).com"));
        assert!(!is_safe_domain("../../etc"));
        assert!(!is_safe_domain("a..b.com"));
        assert!(!is_safe_domain(""));
    }

    #[test]
    fn selector_guard() {
        assert!(is_safe_selector("hyperion"));
        assert!(is_safe_selector("hyp_2026"));
        assert!(!is_safe_selector("has space"));
        assert!(!is_safe_selector("dot.sel"));
        assert!(!is_safe_selector(""));
    }

    #[test]
    fn dns_name_and_txt_value() {
        assert_eq!(
            dkim_dns_name("example.com", "hyperion"),
            "hyperion._domainkey.example.com"
        );
        assert_eq!(dkim_txt_value("ABC123"), "v=DKIM1; k=rsa; p=ABC123");
    }

    #[test]
    fn key_and_signing_table_lines() {
        assert_eq!(
            key_table_line("example.com", "hyperion", "/etc/opendkim/keys/example.com/hyperion.private"),
            "hyperion._domainkey.example.com example.com:hyperion:/etc/opendkim/keys/example.com/hyperion.private"
        );
        assert_eq!(
            signing_table_line("example.com", "hyperion"),
            "*@example.com hyperion._domainkey.example.com"
        );
    }

    #[test]
    fn extract_p_tag_from_genkey_bind_txt() {
        // opendkim-genkey splits the key across quoted continuation strings.
        let genkey = "hyperion._domainkey\tIN\tTXT\t( \"v=DKIM1; h=sha256; k=rsa; \"\n\
                      \t  \"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDabc\"\n\
                      \t  \"defGHIjkl0123456789+/==\" )  ; ----- DKIM key hyperion for example.com";
        assert_eq!(
            extract_p_tag(genkey).as_deref(),
            Some("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDabcdefGHIjkl0123456789+/==")
        );
    }

    #[test]
    fn extract_p_tag_from_flat_published_record() {
        let published = "v=DKIM1; k=rsa; p=FLATKEY123+/==";
        assert_eq!(extract_p_tag(published).as_deref(), Some("FLATKEY123+/=="));
    }

    #[test]
    fn extract_p_tag_none_when_empty_or_missing() {
        assert_eq!(extract_p_tag("v=DKIM1; k=rsa; p="), None); // revoked key
        assert_eq!(extract_p_tag("v=spf1 a mx ~all"), None);
    }

    #[test]
    fn opendkim_conf_pins_inet_socket_and_relaxed_canon() {
        let c = opendkim_conf();
        // Must match the postfix milter endpoint exactly (literal 127.0.0.1,
        // never `localhost`) and use relaxed/relaxed so a forwarder's whitespace
        // fixups don't break the signature.
        assert!(
            c.contains("Socket                  inet:8891@127.0.0.1"),
            "{c}"
        );
        assert!(c.contains("Canonicalization        relaxed/relaxed"), "{c}");
        assert_eq!(MILTER_SOCKET_POSTFIX, "inet:127.0.0.1:8891");
    }

    #[test]
    fn published_matches_ignoring_wrapping_and_quotes() {
        let ours = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDabcdef";
        // DNS may hand it back split into two quoted chunks with whitespace.
        let published = "\"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNAD\" \"CBiQKBgQDabcdef\"";
        assert!(published_key_matches(published, ours));
        assert!(!published_key_matches("v=DKIM1; k=rsa; p=DIFFERENT", ours));
        assert!(!published_key_matches("", ours));
    }
}
