//! File-integrity + malware adapters — the "has anything been *tampered
//! with*?" half of the defender, sibling to `wpcli`'s outdated-component
//! scan.
//!
//! Two independent, keyless signals (this project deliberately runs the
//! defender without any vendor API key):
//!
//!   1. **wp-cli checksum verification.** `wp core verify-checksums` and
//!      `wp plugin verify-checksums --all` compare every file on disk with
//!      the MD5s WordPress.org publishes for that exact version. This is
//!      the signal that catches the actual common compromise: injected or
//!      modified core/plugin PHP.
//!   2. **ClamAV.** `clamscan` over the docroot. Core verification
//!      deliberately *skips* `wp-content`, so a webshell dropped in
//!      `wp-content/uploads` is invisible to signal 1 — ClamAV covers
//!      exactly that gap. It is OPTIONAL: clamd is heavy for a shared host,
//!      so a missing binary means "not available", never an error and never
//!      a false "clean".
//!
//! Everything that shells out lives at the top of this module; everything
//! that *parses* is a pure function at the bottom, unit-tested against
//! real-shaped wp-cli / clamscan output. Getting the parsing wrong is how
//! this feature would lie to a paying customer, so it is the part that is
//! tested hardest.

use crate::{wpcli, AdapterError};
use hyperion_types::{WpIntegrityFileIssue, WpIntegrityPluginResult, WpMalwareHit};
use serde::Deserialize;
use std::path::Path;
use tokio::process::Command;
use tracing::debug;

/// Mirrors `wpcli::run` — wp-cli always runs under the hosting's own system
/// user so file ownership inside `htdocs/` stays correct.
const SUDO: &str = "/usr/bin/sudo";

/// Where `clamscan` may live. Debian's `clamav` package ships
/// `/usr/bin/clamscan`; source builds land in `/usr/local/bin`.
const CLAMSCAN_BINS: &[&str] = &["/usr/bin/clamscan", "/usr/local/bin/clamscan"];

// ---------------------------------------------------------------------------
// Command plumbing
// ---------------------------------------------------------------------------

/// Raw outcome of a command whose non-zero exit is a legitimate *result*.
#[derive(Debug, Clone)]
pub struct Captured {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run a command and return its exit code together with BOTH streams,
/// treating a non-zero exit as data rather than as a failure.
///
/// Neither `cmd::run` nor `cmd::run_capturing_all` fits this module: both
/// turn a non-zero exit into `AdapterError`, and both keep only the last
/// 4 KiB of output. Here non-zero is the *normal* case — wp-cli exits 1
/// whenever verification finds anything and clamscan exits 1 on every
/// detection — and the text they emit alongside it is precisely the finding
/// list we must not lose or truncate. wp-cli also writes its findings to
/// STDERR (`Warning:` lines) while the summary table goes to STDOUT, so we
/// need both streams intact. Only a failure to *spawn* (binary missing,
/// fork failure) is an error.
async fn run_capturing(program: &str, args: &[&str]) -> Result<Captured, AdapterError> {
    // No redaction pass here (unlike `cmd::run`): every argument this module
    // builds is a subcommand name, a system-user name or a docroot path —
    // no credential ever reaches this argv.
    debug!(program, ?args, "exec (exit code is a result)");
    let out = Command::new(program).args(args).output().await?;
    Ok(Captured {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Refuse a system-user name that isn't a valid POSIX login. Reuses the
/// canonical `^[a-z][a-z0-9_]{2,31}$` parser so this adapter can't be the
/// one place with a looser rule than the rest of the codebase.
fn guard_user(user: &str) -> Result<(), AdapterError> {
    hyperion_validate::SystemUserName::parse(user)?;
    Ok(())
}

/// Refuse anything that isn't a plain absolute path. `..` is rejected
/// outright rather than normalised: every caller passes a hosting's own
/// docroot straight from the state table, so a traversal component means
/// something upstream is wrong and we would rather fail loudly than scan
/// (or report on) another tenant's tree.
fn guard_path(path: &str) -> Result<(), AdapterError> {
    let ok = path.starts_with('/')
        && path.len() <= 4096
        && !path.contains("..")
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'));
    if !ok {
        return Err(AdapterError::Other(format!("unsafe path: {path}")));
    }
    Ok(())
}

/// Run a wp-cli subcommand as `user` against `htdocs`, keeping the exit code
/// and both streams. Same argv construction as `wpcli::run` (including its
/// arg whitelist) — only the exit-code handling differs.
async fn wp_capture(user: &str, htdocs: &str, args: &[&str]) -> Result<Captured, AdapterError> {
    guard_user(user)?;
    guard_path(htdocs)?;
    wpcli::validate_args(args)?;
    let argv = wpcli::build_argv(user, htdocs, args);
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_capturing(SUDO, &refs).await
}

// ---------------------------------------------------------------------------
// Core checksum verification
// ---------------------------------------------------------------------------

/// Outcome of `wp core verify-checksums`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoreChecksums {
    /// True only when wp-cli demonstrably performed the comparison. False
    /// for a broken install, a missing wp-cli, or a WordPress.org lookup
    /// that failed — callers must render that as "couldn't check", never as
    /// "clean".
    pub checked: bool,
    /// Files present but different from the official release.
    pub modified: Vec<String>,
    /// Files that are not part of the official release at all.
    pub unexpected: Vec<String>,
    /// Official files that are missing from disk.
    pub missing: Vec<String>,
}

impl CoreChecksums {
    /// Verification ran and found nothing.
    pub fn is_clean(&self) -> bool {
        self.checked && self.modified.is_empty() && self.unexpected.is_empty()
    }
}

/// Verify WordPress core against the checksums WordPress.org publishes for
/// the installed version.
///
/// Note what this does *not* cover: wp-cli skips the whole `wp-content`
/// tree (themes, plugins, uploads all legitimately differ per site), which
/// is why [`scan_malware`] exists as the second signal.
pub async fn verify_core(user: &str, htdocs: &str) -> Result<CoreChecksums, AdapterError> {
    let out = wp_capture(user, htdocs, &["core", "verify-checksums"]).await?;
    Ok(parse_core_verification(&out.stdout, &out.stderr))
}

// ---------------------------------------------------------------------------
// Plugin checksum verification
// ---------------------------------------------------------------------------

/// Outcome of `wp plugin verify-checksums --all`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PluginChecksums {
    /// See [`CoreChecksums::checked`].
    pub checked: bool,
    /// Plugins with at least one file that failed verification, grouped per
    /// plugin.
    pub failed: Vec<WpIntegrityPluginResult>,
    /// Plugins WordPress.org publishes no checksums for — every premium or
    /// private plugin. NOT a finding.
    pub unknown: Vec<String>,
}

/// Verify every installed plugin against its published WordPress.org
/// checksums.
///
/// Deliberately **without** `--strict`: strict mode turns "this plugin has
/// no published checksums" into a failure, which would flag Elementor Pro,
/// ACF Pro, WP Rocket and every other commercial plugin on every run. Those
/// land in [`PluginChecksums::unknown`] instead — "we could not check this",
/// which is the truth and does not train the operator to ignore the panel.
pub async fn verify_plugins(user: &str, htdocs: &str) -> Result<PluginChecksums, AdapterError> {
    // No `--format=json`: the default table has been stable for years and is
    // supported by every wp-cli that has the command at all, whereas an
    // unsupported `--format` would abort the whole check with a parameter
    // error. `parse_plugin_verification` accepts JSON too, so switching
    // later costs nothing.
    let out = wp_capture(user, htdocs, &["plugin", "verify-checksums", "--all"]).await?;
    Ok(parse_plugin_verification(&out.stdout, &out.stderr))
}

// ---------------------------------------------------------------------------
// ClamAV
// ---------------------------------------------------------------------------

/// Outcome of a ClamAV pass. `available == false` means "not scanned" —
/// callers must never render an empty `hits` from an unavailable scanner as
/// a clean bill of health.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MalwareScan {
    pub available: bool,
    pub hits: Vec<WpMalwareHit>,
}

/// First `clamscan` binary that exists on this node, if any.
fn clamscan_bin() -> Option<&'static str> {
    CLAMSCAN_BINS
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
}

/// Is an on-demand ClamAV scanner installed here? Absence is a normal
/// state, not an error — the operator may simply not want a scanner
/// resident on a shared host.
pub fn clamav_available() -> bool {
    clamscan_bin().is_some()
}

/// Recursively scan `path` for malware signatures.
///
/// Exit-code contract (`clamscan(1)`): 0 = nothing found, 1 = infections
/// found, 2 = an error occurred. Only 1 is a *result*; we deliberately
/// surface 2 as an error rather than as "clean", because 2 means some part
/// of the tree could not be read and a partial pass must not be reported as
/// a pass.
pub async fn scan_malware(path: &str) -> Result<MalwareScan, AdapterError> {
    guard_path(path)?;
    let Some(bin) = clamscan_bin() else {
        return Ok(MalwareScan::default());
    };
    // `--infected` prints detections only, `--no-summary` drops the trailing
    // stats block — both keep the output to exactly the lines we parse.
    let out = run_capturing(bin, &["-r", "--infected", "--no-summary", path]).await?;
    match out.code {
        0 => Ok(MalwareScan {
            available: true,
            hits: Vec::new(),
        }),
        1 => Ok(MalwareScan {
            available: true,
            // Detections go to stdout; stderr carries only diagnostics.
            hits: parse_clamscan_output(&out.stdout),
        }),
        code => Err(AdapterError::Command {
            cmd: format!("{bin} -r --infected --no-summary {path}"),
            code,
            stderr_tail: out.stderr,
        }),
    }
}

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

/// Fold typographic apostrophes back to ASCII before matching. wp-cli emits
/// plain `'` today, but a locale or a future release that pretty-prints
/// "doesn't" must not silently turn every finding into a miss.
fn normalize(line: &str) -> String {
    line.replace('\u{2019}', "'")
}

/// Text after `marker` in `line`, trimmed. `None` when the marker is absent
/// or nothing follows it.
fn after_marker(line: &str, marker: &str) -> Option<String> {
    let idx = line.find(marker)? + marker.len();
    let val = line[idx..].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Parse `wp core verify-checksums` output.
///
/// wp-cli writes one `Warning:` line per finding to STDERR and exits
/// non-zero, then a single summary line:
///
/// ```text
/// Warning: File doesn't verify against checksum: wp-includes/version.php
/// Warning: File should not exist: wp-admin/eval.php
/// Warning: File doesn't exist: wp-admin/includes/misc.php
/// Error: WordPress installation doesn't verify against checksums.
/// ```
///
/// Both streams are scanned because the split between them has moved across
/// wp-cli versions, and because a `Success:` line on STDOUT is one of the
/// two proofs that the comparison actually happened.
pub fn parse_core_verification(stdout: &str, stderr: &str) -> CoreChecksums {
    let mut out = CoreChecksums::default();
    for raw in stdout.lines().chain(stderr.lines()) {
        let line = normalize(raw);
        if let Some(p) = after_marker(&line, "File doesn't verify against checksum:") {
            out.modified.push(p);
        } else if let Some(p) = after_marker(&line, "File should not exist:") {
            out.unexpected.push(p);
        } else if let Some(p) = after_marker(&line, "File doesn't exist:") {
            out.missing.push(p);
        }
    }
    // "Checked" needs positive evidence. An empty or unrecognised output —
    // "Error: This does not seem to be a WordPress installation.", a wp-cli
    // that isn't installed, a WordPress.org lookup failure — must NOT read
    // as a clean core.
    let saw_summary = [stdout, stderr].iter().any(|s| {
        let n = normalize(s);
        n.contains("verifies against checksums") || n.contains("doesn't verify against checksums")
    });
    out.checked = saw_summary
        || !out.modified.is_empty()
        || !out.unexpected.is_empty()
        || !out.missing.is_empty();
    out
}

/// One row of wp-cli's plugin verification report, in its `--format=json`
/// shape. Also the shape of a parsed table row.
#[derive(Debug, Deserialize)]
struct PluginIssueRow {
    #[serde(default)]
    plugin_name: String,
    #[serde(default)]
    file: String,
    #[serde(default)]
    message: String,
}

/// Split one ASCII table line (`| a | b | c |`) into trimmed cells, or
/// `None` if it isn't a data row.
fn table_cells(line: &str) -> Option<Vec<String>> {
    let t = line.trim();
    if !t.starts_with('|') || !t.ends_with('|') {
        return None;
    }
    let cells: Vec<String> = t
        .trim_matches('|')
        .split('|')
        .map(|c| c.trim().to_string())
        .collect();
    Some(cells)
}

/// Extract the failure rows from wp-cli's STDOUT, accepting either the
/// default ASCII table or a `--format=json` array.
fn parse_plugin_issue_rows(stdout: &str) -> Vec<PluginIssueRow> {
    // JSON first: if the caller asked for it, the payload is the whole of
    // stdout between the outermost brackets.
    if let (Some(start), Some(end)) = (stdout.find('['), stdout.rfind(']')) {
        if start < end {
            if let Ok(rows) = serde_json::from_str::<Vec<PluginIssueRow>>(&stdout[start..=end]) {
                return rows;
            }
        }
    }
    stdout
        .lines()
        .filter_map(table_cells)
        .filter(|cells| cells.len() == 3)
        // Drop the header row; its first cell is the column name.
        .filter(|cells| cells[0] != "plugin_name")
        .map(|cells| PluginIssueRow {
            plugin_name: cells[0].clone(),
            file: cells[1].clone(),
            message: cells[2].clone(),
        })
        .collect()
}

/// Parse `wp plugin verify-checksums --all` output into "genuinely failed"
/// vs "could not be checked".
///
/// STDOUT carries the failure report; STDERR carries one warning per plugin
/// WordPress.org has no checksums for:
///
/// ```text
/// Warning: Could not retrieve the checksums for version 3.21.0 of plugin elementor-pro, skipping.
/// ```
///
/// That distinction is the whole point of this parser. A premium plugin has
/// no published hashes by definition, so treating "unknown" as "failed"
/// would raise an alarm on every commercial plugin, every run, forever.
pub fn parse_plugin_verification(stdout: &str, stderr: &str) -> PluginChecksums {
    let mut out = PluginChecksums::default();

    // Failures, grouped per plugin preserving wp-cli's ordering.
    for row in parse_plugin_issue_rows(stdout) {
        if row.plugin_name.is_empty() {
            continue;
        }
        match out.failed.iter_mut().find(|p| p.slug == row.plugin_name) {
            Some(existing) => existing.issues.push(WpIntegrityFileIssue {
                path: row.file,
                message: row.message,
            }),
            None => out.failed.push(WpIntegrityPluginResult {
                slug: row.plugin_name,
                issues: vec![WpIntegrityFileIssue {
                    path: row.file,
                    message: row.message,
                }],
            }),
        }
    }

    // Unchecked plugins. The slug sits between " of plugin " and the next
    // comma (or the end of the line, for wordings without ", skipping.").
    for raw in stderr.lines().chain(stdout.lines()) {
        let line = normalize(raw);
        if !line.contains("Could not retrieve the checksums") {
            continue;
        }
        let Some(rest) = after_marker(&line, " of plugin ") else {
            continue;
        };
        let slug = rest
            .split(',')
            .next()
            .unwrap_or(&rest)
            .trim()
            .trim_end_matches('.')
            .to_string();
        if !slug.is_empty() && !out.unknown.contains(&slug) {
            out.unknown.push(slug);
        }
    }

    // Positive evidence that verification ran: wp-cli's batch summary always
    // says "Verified N of M plugins." / "No plugins verified (…)". Without it
    // (and without any row) we report "couldn't check" rather than "clean".
    let saw_summary = [stdout, stderr]
        .iter()
        .any(|s| s.contains("verified") || s.contains("Verified"));
    out.checked = saw_summary || !out.failed.is_empty() || !out.unknown.is_empty();
    out
}

/// Parse `clamscan --infected --no-summary` output.
///
/// Every detection is one line, `<path>: <Signature> FOUND`. Non-detection
/// lines — `ERROR` lines for unreadable files, blank lines, whatever a
/// future clamscan adds — are ignored rather than guessed at.
pub fn parse_clamscan_output(text: &str) -> Vec<WpMalwareHit> {
    let mut hits = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        // Only " FOUND" lines are detections; "… ERROR" / "… OK" are not.
        let Some(body) = line.strip_suffix(" FOUND") else {
            continue;
        };
        // Split from the RIGHT: a path may itself contain ": ", the
        // signature name never does.
        let Some((path, signature)) = body
            .rsplit_once(": ")
            .or_else(|| body.rsplit_once(':'))
            .map(|(p, s)| (p.trim(), s.trim()))
        else {
            continue;
        };
        if path.is_empty() || signature.is_empty() {
            continue;
        }
        hits.push(WpMalwareHit {
            path: path.to_string(),
            signature: signature.to_string(),
        });
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- core --------------------------------------------------------------

    #[test]
    fn core_clean_install_verifies() {
        let stdout = "Success: WordPress installation verifies against checksums.\n";
        let r = parse_core_verification(stdout, "");
        assert!(r.checked, "the success line proves the comparison ran");
        assert!(r.is_clean());
        assert!(r.modified.is_empty() && r.unexpected.is_empty() && r.missing.is_empty());
    }

    #[test]
    fn core_modified_and_extra_files_are_split() {
        let stderr = "\
Warning: File doesn't verify against checksum: wp-includes/version.php
Warning: File doesn't verify against checksum: wp-login.php
Warning: File should not exist: wp-includes/wp-vcd.php
Warning: File doesn't exist: wp-admin/includes/misc.php
Error: WordPress installation doesn't verify against checksums.
";
        let r = parse_core_verification("", stderr);
        assert!(r.checked);
        assert!(!r.is_clean());
        assert_eq!(
            r.modified,
            vec![
                "wp-includes/version.php".to_string(),
                "wp-login.php".to_string()
            ]
        );
        // The dropped file must NOT be conflated with the modified ones.
        assert_eq!(r.unexpected, vec!["wp-includes/wp-vcd.php".to_string()]);
        assert_eq!(r.missing, vec!["wp-admin/includes/misc.php".to_string()]);
    }

    #[test]
    fn core_typographic_apostrophe_still_parses() {
        let stderr = "Warning: File doesn\u{2019}t verify against checksum: wp-settings.php\n";
        let r = parse_core_verification("", stderr);
        assert_eq!(r.modified, vec!["wp-settings.php".to_string()]);
    }

    #[test]
    fn core_broken_install_is_unchecked_not_clean() {
        // wp-cli couldn't bootstrap WordPress at all.
        let stderr = "Error: This does not seem to be a WordPress installation.\n";
        let r = parse_core_verification("", stderr);
        assert!(!r.checked, "must not claim the core was checked");
        assert!(!r.is_clean(), "unchecked is never clean");
    }

    #[test]
    fn core_empty_and_garbage_input_is_unchecked() {
        for (o, e) in [
            ("", ""),
            ("\n\n\n", ""),
            ("", "\u{0}\u{1}\u{2} not: even: text\n"),
            ("File", "checksum:"),
            ("Warning: File should not exist:", ""), // marker with no value
        ] {
            let r = parse_core_verification(o, e);
            assert!(!r.checked, "garbage must not read as checked: {o:?} {e:?}");
            assert!(r.modified.is_empty() && r.unexpected.is_empty() && r.missing.is_empty());
        }
    }

    // -- plugins -----------------------------------------------------------

    #[test]
    fn plugins_all_clean() {
        let stdout = "Success: Verified 3 of 3 plugins.\n";
        let r = parse_plugin_verification(stdout, "");
        assert!(r.checked);
        assert!(r.failed.is_empty());
        assert!(r.unknown.is_empty());
    }

    #[test]
    fn plugins_table_failures_group_per_plugin() {
        let stdout = "\
+-------------+--------------------------+-------------------------+
| plugin_name | file                     | message                 |
+-------------+--------------------------+-------------------------+
| akismet     | akismet.php              | Checksum does not match |
| akismet     | inc/backdoor.php         | File was added          |
| hello-dolly | hello.php                | File is missing         |
+-------------+--------------------------+-------------------------+
Error: Only 1 of 3 plugins verified (2 failed).
";
        let r = parse_plugin_verification(stdout, "");
        assert!(r.checked);
        assert_eq!(r.failed.len(), 2, "two distinct plugins");
        assert_eq!(r.failed[0].slug, "akismet");
        assert_eq!(r.failed[0].issues.len(), 2);
        assert_eq!(r.failed[0].issues[0].path, "akismet.php");
        assert_eq!(r.failed[0].issues[0].message, "Checksum does not match");
        assert_eq!(r.failed[1].slug, "hello-dolly");
        assert_eq!(r.failed[1].issues[0].message, "File is missing");
        // The header row must never become a finding.
        assert!(r.failed.iter().all(|p| p.slug != "plugin_name"));
    }

    #[test]
    fn plugins_json_format_is_accepted_too() {
        let stdout = r#"[{"plugin_name":"akismet","file":"akismet.php","message":"Checksum does not match"}]"#;
        let r = parse_plugin_verification(stdout, "");
        assert_eq!(r.failed.len(), 1);
        assert_eq!(r.failed[0].slug, "akismet");
        assert_eq!(r.failed[0].issues[0].path, "akismet.php");
    }

    #[test]
    fn premium_plugins_are_unknown_not_failed() {
        // The whole point: Elementor Pro has no published checksums, and
        // that must never show up as a compromised site.
        let stderr = "\
Warning: Could not retrieve the checksums for version 3.21.0 of plugin elementor-pro, skipping.
Warning: Could not retrieve the checksums for version 6.2.9 of plugin advanced-custom-fields-pro, skipping.
";
        let stdout = "Success: Verified 4 of 6 plugins (2 skipped).\n";
        let r = parse_plugin_verification(stdout, stderr);
        assert!(r.checked);
        assert!(r.failed.is_empty(), "no checksums != tampered");
        assert_eq!(
            r.unknown,
            vec![
                "elementor-pro".to_string(),
                "advanced-custom-fields-pro".to_string()
            ]
        );
    }

    #[test]
    fn plugins_mixed_failed_and_unknown() {
        let stdout = "\
+-------------+-------------+-------------------------+
| plugin_name | file        | message                 |
+-------------+-------------+-------------------------+
| akismet     | akismet.php | Checksum does not match |
+-------------+-------------+-------------------------+
Error: Only 4 of 6 plugins verified (1 failed, 1 skipped).
";
        let stderr =
            "Warning: Could not retrieve the checksums for version 7.6 of plugin wp-rocket, skipping.\n";
        let r = parse_plugin_verification(stdout, stderr);
        assert_eq!(r.failed.len(), 1);
        assert_eq!(r.failed[0].slug, "akismet");
        assert_eq!(r.unknown, vec!["wp-rocket".to_string()]);
    }

    #[test]
    fn plugins_unknown_is_deduped_and_survives_missing_skipping_suffix() {
        let stderr = "\
Warning: Could not retrieve the checksums for version 1.0 of plugin foo-pro
Warning: Could not retrieve the checksums for version 1.0 of plugin foo-pro, skipping.
";
        let r = parse_plugin_verification("", stderr);
        assert_eq!(r.unknown, vec!["foo-pro".to_string()]);
    }

    #[test]
    fn plugins_empty_and_garbage_input_is_unchecked() {
        for (o, e) in [
            ("", ""),
            ("|||||\n", ""),
            ("| only | two |\n", ""),
            ("[not json", "Could not retrieve the checksums"),
            ("\u{0}\u{1}\n", "\n\n"),
        ] {
            let r = parse_plugin_verification(o, e);
            assert!(!r.checked, "garbage must not read as checked: {o:?} {e:?}");
            assert!(r.failed.is_empty());
        }
    }

    // -- clamav ------------------------------------------------------------

    #[test]
    fn clamscan_parses_multiple_hits() {
        let out = "\
/home/site/htdocs/wp-content/uploads/2026/01/x.php: Php.Trojan.Webshell-1 FOUND
/home/site/htdocs/wp-content/plugins/evil/a.php: Php.Malware.Agent-9876543-0 FOUND
";
        let hits = parse_clamscan_output(out);
        assert_eq!(hits.len(), 2);
        assert_eq!(
            hits[0].path,
            "/home/site/htdocs/wp-content/uploads/2026/01/x.php"
        );
        assert_eq!(hits[0].signature, "Php.Trojan.Webshell-1");
        assert_eq!(hits[1].signature, "Php.Malware.Agent-9876543-0");
    }

    #[test]
    fn clamscan_ignores_errors_and_noise() {
        let out = "\
/home/site/htdocs/broken-link: Can't open file or directory ERROR
/home/site/htdocs/ok.php: OK

LibClamAV Warning: something
/home/site/htdocs/bad.php: Php.Trojan.Webshell-1 FOUND
";
        let hits = parse_clamscan_output(out);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/home/site/htdocs/bad.php");
    }

    #[test]
    fn clamscan_path_containing_colon_space_keeps_full_path() {
        let out = "/home/site/htdocs/weird: name/x.php: Php.Trojan.Agent-1 FOUND\n";
        let hits = parse_clamscan_output(out);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/home/site/htdocs/weird: name/x.php");
        assert_eq!(hits[0].signature, "Php.Trojan.Agent-1");
    }

    #[test]
    fn clamscan_empty_and_garbage_input_yields_nothing() {
        for s in ["", "\n\n", "FOUND", " FOUND", ": FOUND", "\u{0}\u{1} FOUND"] {
            assert!(
                parse_clamscan_output(s).is_empty(),
                "must not invent a hit from {s:?}"
            );
        }
    }

    // -- guards ------------------------------------------------------------

    #[test]
    fn guards_refuse_injection_shaped_input() {
        for bad in [
            "htdocs",                     // not absolute
            "/home/site/../other/htdocs", // traversal
            "/home/site/htdocs; rm -rf /",
            "/home/site/$(id)",
            "/home/site/htdocs\n",
        ] {
            assert!(guard_path(bad).is_err(), "must refuse path {bad:?}");
        }
        assert!(guard_path("/home/site_1/htdocs").is_ok());

        for bad in ["", "ro ot", "root;id", "-x", "Site", "ab"] {
            assert!(guard_user(bad).is_err(), "must refuse user {bad:?}");
        }
        assert!(guard_user("site_1").is_ok());
    }
}
