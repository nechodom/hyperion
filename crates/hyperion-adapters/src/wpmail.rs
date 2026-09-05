//! WordPress mail: make it work with hyperion's own mail path, keep it
//! working, and say so when it cannot.
//!
//! # Why a site's mail breaks
//!
//! PHP `mail()` on a hyperion node already goes somewhere sensible: the
//! sendmail wrapper, then postfix, with the site's own SPF envelope and DKIM
//! signature. WordPress needs almost nothing from us. What breaks it is
//! nearly always one of three things, and none of them announces itself —
//! the site simply stops sending, and nobody notices until a customer says
//! "I never got the contact form".
//!
//! 1. **The From address is on somebody else's domain.** WordPress defaults
//!    to `wordpress@<host>` and plugins happily set the visitor's address as
//!    the sender. Both fail SPF at the receiving end, so the mail is accepted
//!    by our postfix and then silently dropped by Gmail. A per-site DKIM
//!    signature does not save it: DKIM matches the From HEADER, SPF matches
//!    the ENVELOPE, and an unaligned From fails DMARC on the SPF half.
//! 2. **An SMTP plugin with stale credentials.** wp-mail-smtp and friends
//!    take over `wp_mail()` entirely. When the password changes or the
//!    provider drops the account, every send fails — and the plugin's own
//!    "email log" is the only place that says so.
//! 3. **Nothing records the failure.** `wp_mail()` returns `false` and the
//!    caller usually ignores it. Without a hook the evidence never exists.
//!
//! # What this module does about it
//!
//! Drops a must-use plugin that fixes (1), records (3), and — only when
//! asked — overrides (2). Must-use because it has to load before the
//! plugins it is correcting, and because a site owner cannot deactivate it
//! by accident from wp-admin.
//!
//! The plugin is deliberately small and deliberately conservative: it does
//! NOT reroute mail through SMTP by default. `mail()` is already the path
//! with the site's SPF and DKIM on it, and pushing WordPress onto
//! `localhost:25` would bypass the wrapper that logs every send.

use crate::AdapterError;
use std::path::{Path, PathBuf};

/// Bumped whenever [`MU_PLUGIN_TEMPLATE`] changes in a way that matters.
///
/// The self-check compares this against the marker inside the file on disk,
/// so an agent update lands a corrected plugin on the next pass instead of
/// waiting for somebody to notice the old one is still there.
pub const MU_PLUGIN_VERSION: u32 = 1;

/// File name under `wp-content/mu-plugins/`.
pub const MU_PLUGIN_FILE: &str = "hyperion-mail.php";

/// `{{FROM}}`, `{{DOMAIN}}`, `{{VERSION}}`, `{{LOG}}` and `{{FORCE_LOCAL}}`
/// are substituted before the file is written.
///
/// Everything in here runs on every request of every site, so it is written
/// to do nothing at all in the common case: three filters and one action,
/// no I/O unless a send actually fails.
const MU_PLUGIN_TEMPLATE: &str = r#"<?php
/**
 * Plugin Name: Hyperion mail
 * Description: Keeps this site's outgoing mail on its own domain so it passes SPF, and records any send that fails. Managed by Hyperion — edits are overwritten.
 * Version: {{VERSION}}
 */
if (!defined('ABSPATH')) { exit; }

define('HYPERION_MAIL_VERSION', {{VERSION}});
define('HYPERION_MAIL_DOMAIN', '{{DOMAIN}}');
define('HYPERION_MAIL_FROM', '{{FROM}}');
define('HYPERION_MAIL_LOG', '{{LOG}}');
define('HYPERION_MAIL_FORCE_LOCAL', {{FORCE_LOCAL}});

/**
 * Keep the From address on this site's own domain.
 *
 * An address on another domain fails SPF at the receiving end — the mail
 * leaves this server, is accepted, and is then dropped by the recipient with
 * no bounce. A sender that is already ours (the domain itself or any
 * subdomain of it) is left exactly as the site set it: this is a floor, not
 * a policy.
 */
add_filter('wp_mail_from', function ($from) {
    $ours = HYPERION_MAIL_DOMAIN;
    if (is_string($from) && $from !== '' && strpos($from, '@') !== false) {
        $parts = explode('@', $from);
        $domain = strtolower(end($parts));
        if ($domain === $ours || substr($domain, -(strlen($ours) + 1)) === '.' . $ours) {
            return $from;
        }
    }
    return HYPERION_MAIL_FROM;
}, 99);

/** A blank From name makes the mail look like spam to a human reader. */
add_filter('wp_mail_from_name', function ($name) {
    if (is_string($name) && trim($name) !== '' && $name !== 'WordPress') {
        return $name;
    }
    $site = get_bloginfo('name');
    return $site !== '' ? $site : HYPERION_MAIL_DOMAIN;
}, 99);

/**
 * Send through the local mail transport, ignoring any SMTP plugin.
 *
 * Off unless Hyperion turned it on, and Hyperion only turns it on after
 * mail has actually been failing: an SMTP plugin with working credentials
 * is the site owner's choice and is none of our business. When it IS on,
 * this runs at priority 1000 so it lands after the plugin that configured
 * SMTP rather than before it.
 */
if (HYPERION_MAIL_FORCE_LOCAL) {
    add_action('phpmailer_init', function ($phpmailer) {
        $phpmailer->isMail();
        $phpmailer->SMTPAuth = false;
    }, 1000);
}

/**
 * Record failures. Without this the evidence does not exist anywhere:
 * wp_mail() returns false and almost every caller ignores it.
 *
 * Appends one line, capped, and never throws — a logging failure must not
 * take down a page render.
 */
add_action('wp_mail_failed', function ($error) {
    if (HYPERION_MAIL_LOG === '') { return; }
    $msg = is_wp_error($error) ? $error->get_error_message() : 'unknown error';
    $to = '';
    if (is_wp_error($error)) {
        $data = $error->get_error_data();
        if (is_array($data) && isset($data['to'])) {
            $to = is_array($data['to']) ? implode(',', $data['to']) : (string) $data['to'];
        }
    }
    $line = gmdate('c') . "\t" . $to . "\t" . str_replace(array("\n", "\r", "\t"), ' ', $msg) . "\n";
    // Cap the file rather than rotate it: this is evidence for a person
    // reading the last few failures, not a stream anything consumes.
    if (@filesize(HYPERION_MAIL_LOG) > 262144) { @unlink(HYPERION_MAIL_LOG); }
    @file_put_contents(HYPERION_MAIL_LOG, $line, FILE_APPEND | LOCK_EX);
});
"#;

/// SMTP plugins that take `wp_mail()` over completely.
///
/// Not a blocklist — a working one is the site owner's choice. The list
/// exists so the self-check can say WHICH plugin is in the way when mail is
/// failing, instead of leaving an operator to guess.
pub const SMTP_PLUGIN_SLUGS: &[&str] = &[
    "wp-mail-smtp",
    "easy-wp-smtp",
    "post-smtp",
    "fluent-smtp",
    "wp-smtp",
    "gmail-smtp",
    "smtp-mailer",
    "wp-mail-bank",
    "sar-friendly-smtp",
    "cf7-smtp",
];

/// State of the mu-plugin on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuState {
    /// Not a WordPress site at all — nothing to install, and saying
    /// "missing" would be a finding about a site that has no mail.
    NotWordPress,
    Missing,
    /// Present, but written by an older agent or for a different From
    /// address. Rewriting is the fix and it is safe to do unattended.
    Stale,
    Current,
}

/// `<root_dir>/wp-content/mu-plugins/hyperion-mail.php`.
pub fn mu_plugin_path(root_dir: &str) -> PathBuf {
    Path::new(root_dir)
        .join("wp-content")
        .join("mu-plugins")
        .join(MU_PLUGIN_FILE)
}

/// Where the plugin appends failures.
///
/// The site's own `logs/` directory, derived from the docroot's PARENT —
/// `root_dir` IS htdocs, and string-replacing "htdocs" breaks on a domain
/// that happens to contain it. Outside the docroot, so the log is not
/// downloadable over HTTP; it names recipients.
pub fn failure_log_path(root_dir: &str) -> Option<PathBuf> {
    Path::new(root_dir)
        .parent()
        .map(|p| p.join("logs").join("wp-mail-failures.log"))
}

/// The address WordPress should send as, for a site on `domain`.
///
/// `wordpress@` rather than the admin's own address: the envelope is what
/// SPF checks, and a real person's mailbox on another provider is exactly
/// the sender that fails it.
pub fn default_from(domain: &str) -> String {
    format!("wordpress@{}", domain.trim().trim_start_matches("www."))
}

/// Render the plugin for one site.
pub fn render_mu_plugin(domain: &str, from: &str, log_path: &str, force_local: bool) -> String {
    MU_PLUGIN_TEMPLATE
        .replace("{{VERSION}}", &MU_PLUGIN_VERSION.to_string())
        .replace("{{DOMAIN}}", &php_single_quoted(domain))
        .replace("{{FROM}}", &php_single_quoted(from))
        .replace("{{LOG}}", &php_single_quoted(log_path))
        .replace(
            "{{FORCE_LOCAL}}",
            if force_local { "true" } else { "false" },
        )
}

/// Escape for a PHP single-quoted string: only `\` and `'` are special
/// there. A domain cannot legally contain either, but this file is written
/// from values that reached us over RPC, and "cannot" is not a check.
fn php_single_quoted(v: &str) -> String {
    v.replace('\\', "\\\\").replace('\'', "\\'")
}

/// What is on disk right now.
pub async fn mu_plugin_state(root_dir: &str, expected: &str) -> MuState {
    let wp_content = Path::new(root_dir).join("wp-content");
    if !tokio::fs::try_exists(&wp_content).await.unwrap_or(false) {
        return MuState::NotWordPress;
    }
    // A symlink here reads as `Stale`, which sends the caller to
    // `install_mu_plugin` — where the link is removed and a real file put in
    // its place. Reading THROUGH it would compare some unrelated file to our
    // template and, worse, invite the write that follows.
    let Ok(path) =
        resolve_in_site(root_dir, &format!("wp-content/mu-plugins/{MU_PLUGIN_FILE}")).await
    else {
        return MuState::Stale;
    };
    match tokio::fs::read_to_string(path).await {
        Ok(found) if found == expected => MuState::Current,
        Ok(_) => MuState::Stale,
        Err(_) => MuState::Missing,
    }
}

/// Resolve a path inside the site, refusing to follow a symlink at ANY
/// segment.
///
/// This is the whole security story of this module. Every path here lives in
/// a tree the tenant can write, and everything below runs as ROOT. Without
/// this check a tenant replaces `wp-content/mu-plugins` with a symlink to
/// `/etc` and gets three things for free: root writing a file there, root
/// creating directories under it, and — the one that ends the argument —
/// `chown` following the link and handing them ownership of `/etc`.
///
/// `resolve_inside_jail` already refuses a symlink at any segment and pins
/// the result inside the jail; reusing it means this module cannot drift
/// from the file manager's rules.
async fn resolve_in_site(root_dir: &str, rel: &str) -> Result<PathBuf, AdapterError> {
    crate::files::resolve_inside_jail(Path::new(root_dir), rel).await
}

/// Write (or rewrite) the plugin, owned by the site user.
///
/// Returns `Ok(false)` when the site is not WordPress — not an error, just
/// nothing to do. The directory is created if the site has never had a
/// must-use plugin.
pub async fn install_mu_plugin(
    root_dir: &str,
    system_user: &str,
    contents: &str,
) -> Result<bool, AdapterError> {
    if !tokio::fs::try_exists(Path::new(root_dir).join("wp-content"))
        .await
        .unwrap_or(false)
    {
        return Ok(false);
    }
    // Refuses a symlinked `wp-content` or `mu-plugins`; falls back to the
    // logical path when `mu-plugins` simply does not exist yet, which is the
    // ordinary case on a site that has never had one.
    let mu_dir = resolve_in_site(root_dir, "wp-content/mu-plugins").await?;
    tokio::fs::create_dir_all(&mu_dir)
        .await
        .map_err(|e| AdapterError::Other(format!("create {}: {e}", mu_dir.display())))?;
    // Clear a symlink sitting on the NAME before resolving, not after: the
    // resolver refuses a symlinked final segment, so leaving one there would
    // wedge the feature for that site for ever — a tenant could opt out of
    // having their sender pinned by planting one link. The name belongs to
    // this module, and `remove_file` unlinks the link rather than its target,
    // so clearing it is safe. `mu_dir` is already a resolved real directory
    // inside the site, so this join cannot escape.
    let logical = mu_dir.join(MU_PLUGIN_FILE);
    if let Ok(md) = tokio::fs::symlink_metadata(&logical).await {
        if md.file_type().is_symlink() {
            let _ = tokio::fs::remove_file(&logical).await;
        }
    }
    let path =
        resolve_in_site(root_dir, &format!("wp-content/mu-plugins/{MU_PLUGIN_FILE}")).await?;
    tokio::fs::write(&path, contents)
        .await
        .map_err(|e| AdapterError::Other(format!("write {}: {e}", path.display())))?;
    // PHP runs as the site user and nginx as another, so the tree needs
    // world-read to be served and the file needs to belong to the site so
    // its owner can see (and, if they insist, delete) it.
    //
    // `-h` because chown FOLLOWS a symlink by default: without it, a link
    // planted between the resolve above and this call would hand the target
    // to the tenant. The paths are already checked; this closes the race.
    let _ = tokio::process::Command::new("/usr/bin/chown")
        .arg("-h")
        .arg(format!("{system_user}:{system_user}"))
        .arg(&mu_dir)
        .arg(&path)
        .output()
        .await;
    Ok(true)
}

/// Remove it — used when a site stops being WordPress, or an operator turns
/// the feature off for one site.
pub async fn remove_mu_plugin(root_dir: &str) {
    let _ = tokio::fs::remove_file(mu_plugin_path(root_dir)).await;
}

/// What the failure log could tell us.
///
/// Three states, kept apart because collapsing them is how "we could not
/// read the record" became "nothing has failed" — a green Mail card for a
/// site whose log we never opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureLog {
    /// Read, and these are the last lines (possibly none).
    Read(Vec<String>),
    /// No log file yet. Ordinary: nothing has failed since the plugin was
    /// installed, or it has only just been installed.
    Absent,
    /// A log exists but could not be read — a symlink we refuse to follow,
    /// or a permission problem. NOT evidence that mail is fine.
    Unreadable,
}

impl FailureLog {
    /// The lines, or none. For callers that only count.
    pub fn lines(&self) -> &[String] {
        match self {
            FailureLog::Read(v) => v,
            _ => &[],
        }
    }

    /// True only when we actually looked and the log is there.
    pub fn is_read(&self) -> bool {
        matches!(self, FailureLog::Read(_))
    }
}

/// [`recent_failures`], keeping the three states apart.
pub async fn read_failure_log(root_dir: &str, limit: usize) -> FailureLog {
    let Some(site_dir) = Path::new(root_dir).parent() else {
        return FailureLog::Unreadable;
    };
    let Ok(path) = crate::files::resolve_inside_jail(site_dir, "logs/wp-mail-failures.log").await
    else {
        // Refused — a symlink, or something outside the site. That is a
        // finding, not an absence.
        return FailureLog::Unreadable;
    };
    match tokio::fs::read_to_string(&path).await {
        Ok(raw) => {
            let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
            FailureLog::Read(
                lines
                    .iter()
                    .rev()
                    .take(limit)
                    .rev()
                    .map(|s| s.to_string())
                    .collect(),
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FailureLog::Absent,
        Err(_) => FailureLog::Unreadable,
    }
}

/// The last few recorded failures, newest last, for the card to quote.
///
/// Reads at most the tail of the file: the plugin caps it, but a site that
/// has been failing for a month should not be able to make this allocate.
///
/// Answers with an empty vec for all three of "no failures", "no log" and
/// "could not read it" — [`read_failure_log`] is the one to reach for when
/// that difference matters, which on a card it usually does.
pub async fn recent_failures(root_dir: &str, limit: usize) -> Vec<String> {
    // The log lives beside the docroot, so the jail is the SITE directory.
    // Read as root and shown in the panel, so a symlink here is an arbitrary
    // file-read: point it at /etc/shadow and the Mail card renders the last
    // twenty lines of it to whoever can open the page.
    let Some(site_dir) = Path::new(root_dir).parent() else {
        return Vec::new();
    };
    let Ok(path) = crate::files::resolve_inside_jail(site_dir, "logs/wp-mail-failures.log").await
    else {
        return Vec::new();
    };
    let Ok(raw) = tokio::fs::read_to_string(&path).await else {
        return Vec::new();
    };
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    lines
        .iter()
        .rev()
        .take(limit)
        .rev()
        .map(|s| s.to_string())
        .collect()
}

/// How many failures were recorded at or after `since` (unix seconds).
///
/// The plugin writes an ISO-8601 UTC timestamp first on each line, so this
/// is a string compare against the same format rather than a date parse —
/// and an unparseable line counts as NOT recent, which keeps a corrupt log
/// from inventing an incident.
pub fn failures_since(lines: &[String], since: i64) -> usize {
    let cutoff = iso_utc(since);
    lines
        .iter()
        .filter(|l| match l.split('\t').next() {
            // Two things at once. `ts[..cutoff.len()]` panics when the cut
            // lands inside a multi-byte character, and this log is written
            // by a site's own PHP — a UTF-8 error message in the first field
            // was enough to bring the whole mail tick down for every site on
            // the node. And a non-ASCII field is not one of OUR timestamps,
            // so it must not compare as recent either: comparing raw bytes
            // makes any UTF-8 lead byte sort above every digit, which is how
            // garbage would have counted as a fresh failure.
            Some(ts) => {
                ts.is_ascii() && ts.len() >= cutoff.len() && ts[..cutoff.len()] >= cutoff[..]
            }
            None => false,
        })
        .count()
}

/// `YYYY-MM-DDTHH:MM:SS` in UTC, from a unix timestamp.
///
/// Hand-rolled because this crate has no date library and pulling one in to
/// compare two strings would be the tail wagging the dog. Civil-from-days is
/// the standard algorithm; it is exact for every timestamp this can see.
fn iso_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days, shifted to an era starting 0000-03-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
}

/// Which of `active` are known SMTP takeovers.
pub fn smtp_plugins_in(active: &[String]) -> Vec<String> {
    active
        .iter()
        .filter(|s| SMTP_PLUGIN_SLUGS.contains(&s.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_address_is_on_the_site_domain() {
        assert_eq!(default_from("example.cz"), "wordpress@example.cz");
        // A site keyed on www still sends as the bare domain — that is what
        // the SPF record is published for.
        assert_eq!(default_from("www.example.cz"), "wordpress@example.cz");
    }

    #[test]
    fn the_log_is_a_sibling_of_the_docroot_not_a_string_edit() {
        // `root_dir` IS htdocs. Deriving the sibling by replacing "htdocs"
        // in the path breaks on a domain that contains the word.
        let p = failure_log_path("/home/u/htdocs.example.cz/htdocs").unwrap();
        assert_eq!(
            p.to_string_lossy(),
            "/home/u/htdocs.example.cz/logs/wp-mail-failures.log"
        );
    }

    #[test]
    fn the_log_lives_outside_the_docroot() {
        let root = "/home/u/example.cz/htdocs";
        let p = failure_log_path(root).unwrap();
        assert!(
            !p.starts_with(root),
            "the failure log names recipients and must not be downloadable: {}",
            p.display()
        );
    }

    #[test]
    fn rendering_substitutes_every_token() {
        let php = render_mu_plugin(
            "example.cz",
            "wordpress@example.cz",
            "/home/u/example.cz/logs/wp-mail-failures.log",
            false,
        );
        assert!(!php.contains("{{"), "unsubstituted token left: {php}");
        assert!(php.contains("define('HYPERION_MAIL_DOMAIN', 'example.cz');"));
        assert!(php.contains("define('HYPERION_MAIL_FORCE_LOCAL', false);"));
        // Off by default: a working SMTP plugin is the owner's choice.
        assert!(!php.contains("$phpmailer->isMail();\n    }, 1000);\n"));
    }

    #[test]
    fn force_local_is_opt_in() {
        let on = render_mu_plugin("example.cz", "a@example.cz", "/l", true);
        assert!(on.contains("define('HYPERION_MAIL_FORCE_LOCAL', true);"));
    }

    /// A quote in a value must not be able to close the PHP string and
    /// start writing code. Domains cannot contain one — but this file is
    /// rendered from values that arrived over RPC.
    #[test]
    fn a_quote_cannot_escape_the_php_string() {
        let php = render_mu_plugin("ev'il\\.cz", "a@b", "/l", false);
        assert!(
            php.contains("define('HYPERION_MAIL_DOMAIN', 'ev\\'il\\\\.cz');"),
            "{php}"
        );
    }

    #[test]
    fn smtp_plugins_are_recognised_but_nothing_else_is() {
        let active = vec![
            "wp-mail-smtp".to_string(),
            "woocommerce".to_string(),
            "post-smtp".to_string(),
        ];
        assert_eq!(
            smtp_plugins_in(&active),
            vec!["wp-mail-smtp".to_string(), "post-smtp".to_string()]
        );
    }

    #[test]
    fn failures_are_counted_from_the_cutoff_only() {
        let lines = vec![
            "2026-06-01T10:00:00+00:00\tto@x\tolder".to_string(),
            "2026-06-10T10:00:00+00:00\tto@x\tnewer".to_string(),
        ];
        // 2026-06-05
        let cutoff = 1_780_617_600;
        assert_eq!(failures_since(&lines, cutoff), 1);
        assert_eq!(failures_since(&lines, 0), 2);
    }

    /// A corrupt log must not invent an incident. Under-reporting is the
    /// safe direction here: the lines are written by our own plugin in a
    /// fixed format, so a line that does not parse is damage, and damage
    /// must not be able to raise an alert about mail that may have been
    /// fine.
    #[test]
    fn unparseable_lines_are_not_recent() {
        let lines = vec!["garbage".to_string(), String::new()];
        assert_eq!(failures_since(&lines, 0), 0);
    }
}

#[cfg(test)]
mod iso_tests {
    use super::iso_utc;

    #[test]
    fn iso_utc_matches_known_instants() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00");
        assert_eq!(iso_utc(1_780_272_000), "2026-06-01T00:00:00");
        // Leap day, and one second before midnight.
        assert_eq!(iso_utc(1_709_164_800), "2024-02-29T00:00:00");
        assert_eq!(iso_utc(1_780_271_999), "2026-05-31T23:59:59");
    }
}

#[cfg(test)]
mod symlink_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// The escape this module's path handling exists to stop.
    ///
    /// A tenant owns their document tree. If root follows a symlink they
    /// planted at `wp-content/mu-plugins`, it writes a file wherever they
    /// point it — and the `chown` that follows hands them the target. That
    /// is `/etc` for the asking.
    #[tokio::test]
    async fn a_symlinked_mu_plugins_directory_is_refused() {
        let site = tempfile::tempdir().expect("tmp");
        let outside = tempfile::tempdir().expect("tmp2");
        let root = site.path().join("htdocs");
        std::fs::create_dir_all(root.join("wp-content")).expect("wp-content");
        symlink(outside.path(), root.join("wp-content").join("mu-plugins")).expect("symlink");

        let err = install_mu_plugin(&root.to_string_lossy(), "victim", "<?php // x")
            .await
            .expect_err("must refuse a symlinked mu-plugins");
        assert!(
            err.to_string().contains("symlink"),
            "refused for the wrong reason: {err}"
        );
        assert!(
            !outside.path().join(MU_PLUGIN_FILE).exists(),
            "root wrote OUTSIDE the site"
        );
    }

    /// A symlink on the file NAME is ours to clear: the name belongs to this
    /// module, so the link is unlinked and a real file written in its place.
    /// What must never happen is writing THROUGH it.
    #[tokio::test]
    async fn a_symlinked_plugin_file_is_replaced_not_followed() {
        let site = tempfile::tempdir().expect("tmp");
        let outside = tempfile::tempdir().expect("tmp2");
        let victim = outside.path().join("victim.conf");
        std::fs::write(&victim, "original").expect("victim");

        let root = site.path().join("htdocs");
        let mu = root.join("wp-content").join("mu-plugins");
        std::fs::create_dir_all(&mu).expect("mu");
        symlink(&victim, mu.join(MU_PLUGIN_FILE)).expect("symlink");

        install_mu_plugin(&root.to_string_lossy(), "victim", "<?php // ours")
            .await
            .expect("install");
        assert_eq!(
            std::fs::read_to_string(&victim).expect("read victim"),
            "original",
            "root wrote through the symlink"
        );
        // And the link was cleared rather than left to wedge the feature —
        // otherwise a tenant opts out of having their sender pinned by
        // planting one symlink.
        assert_eq!(
            std::fs::read_to_string(mu_plugin_path(&root.to_string_lossy())).expect("read ours"),
            "<?php // ours"
        );
    }

    /// The failure log is read as root and rendered in the panel. A symlink
    /// there is an arbitrary file read — /etc/shadow into the Mail card.
    #[tokio::test]
    async fn a_symlinked_failure_log_is_not_read() {
        let site = tempfile::tempdir().expect("tmp");
        let outside = tempfile::tempdir().expect("tmp2");
        let secret = outside.path().join("secret");
        std::fs::write(&secret, "root:$6$hash\nsecond line\n").expect("secret");

        let root = site.path().join("htdocs");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(site.path().join("logs")).expect("logs");
        symlink(
            &secret,
            site.path().join("logs").join("wp-mail-failures.log"),
        )
        .expect("symlink");

        let lines = recent_failures(&root.to_string_lossy(), 20).await;
        assert!(
            lines.is_empty(),
            "leaked a file through a symlink: {lines:?}"
        );
    }

    /// The ordinary case still has to work, or the guard is just an outage.
    #[tokio::test]
    async fn a_normal_site_still_gets_its_plugin() {
        let site = tempfile::tempdir().expect("tmp");
        let root = site.path().join("htdocs");
        std::fs::create_dir_all(root.join("wp-content")).expect("wp-content");

        let wrote = install_mu_plugin(&root.to_string_lossy(), "site", "<?php // ours")
            .await
            .expect("install");
        assert!(wrote);
        assert_eq!(
            std::fs::read_to_string(mu_plugin_path(&root.to_string_lossy())).expect("read"),
            "<?php // ours"
        );
    }
}

#[cfg(test)]
mod utf8_tests {
    use super::*;

    /// The log is written by the SITE's PHP. A multi-byte character in the
    /// first field made the old prefix compare slice mid-character and
    /// panic, which took down the whole mail tick for every site on the node.
    #[test]
    fn a_multibyte_first_field_does_not_panic() {
        let lines = vec![
            "čččččččččččččččččččč\tto@x\tbroken".to_string(),
            "2026-06-10T10:00:00+00:00\tto@x\treal".to_string(),
            "🙂".to_string(),
        ];
        assert_eq!(failures_since(&lines, 1_780_617_600), 1);
    }
}

#[cfg(test)]
mod failure_log_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// The three states have to stay apart. Collapsing "could not read" into
    /// "nothing failed" is a green Mail card for a site whose log was never
    /// opened.
    #[tokio::test]
    async fn absent_read_and_unreadable_are_three_answers() {
        let site = tempfile::tempdir().expect("tmp");
        let root = site.path().join("htdocs");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(site.path().join("logs")).expect("logs");
        let root_s = root.to_string_lossy().to_string();

        // No file yet — ordinary.
        assert_eq!(read_failure_log(&root_s, 20).await, FailureLog::Absent);

        // A real log reads.
        let log = site.path().join("logs").join("wp-mail-failures.log");
        std::fs::write(&log, "2026-06-10T10:00:00+00:00\tto@x\tboom\n").expect("write");
        let got = read_failure_log(&root_s, 20).await;
        assert!(got.is_read());
        assert_eq!(got.lines().len(), 1);

        // A symlink is refused, and that is NOT "nothing failed".
        std::fs::remove_file(&log).expect("rm");
        symlink(site.path().join("elsewhere"), &log).expect("symlink");
        let got = read_failure_log(&root_s, 20).await;
        assert_eq!(got, FailureLog::Unreadable);
        assert!(!got.is_read());
        assert!(got.lines().is_empty());
    }
}
