//! What the operating system has waiting to install, and whether it needs a
//! reboot.
//!
//! # Why this exists
//!
//! The panel could already RUN `apt-get upgrade -y` on a node. It could not say
//! what that would install, whether any of it was a security fix, or whether
//! the machine had been waiting on a reboot since the last kernel update. The
//! button was pressed blind.
//!
//! # What this deliberately does not do
//!
//! It never upgrades anything. It asks apt what is pending, reads the reboot
//! marker Debian and Ubuntu both maintain, and reports. Refreshing the package
//! index (`apt-get update`) is separate and explicit, because it is the part
//! that talks to the network and the part that can be slow or fail.

use crate::AdapterError;
use std::path::Path;
use tokio::process::Command;

/// Run an apt tool in the C locale and return (stdout, stderr).
///
/// The locale is not cosmetic. systemd hands the agent the system `LANG`, and on
/// a machine installed in Czech apt prints `[aktualizovatelný z: …]` where the
/// parser looks for `[upgradable from: …]` — every line was skipped and the
/// node read as fully up to date.
async fn apt(program: &str, args: &[&str]) -> Result<(String, String), AdapterError> {
    let out = Command::new(program)
        .args(args)
        .env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8")
        .env_remove("LANGUAGE")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        return Err(AdapterError::Command {
            cmd: format!("{program} {}", args.join(" ")),
            code: out.status.code().unwrap_or(-1),
            stderr_tail: tail(&stderr, 4096),
        });
    }
    Ok((stdout, stderr))
}

/// The last `max` characters of `s`.
fn tail(s: &str, max: usize) -> String {
    let n = s.chars().count();
    s.chars().skip(n.saturating_sub(max)).collect()
}

/// One package apt would upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPackage {
    pub name: String,
    pub installed: String,
    pub candidate: String,
    /// The suites the candidate comes from, e.g. `bookworm-security`.
    pub suites: Vec<String>,
}

impl PendingPackage {
    /// Is this a security update?
    ///
    /// Decided by where the candidate comes FROM, which is how Debian and
    /// Ubuntu both mark it: a suite ending in `-security`. A package offered
    /// from both `bookworm-security` and `bookworm-updates` is a security
    /// update — the fix is in the security pocket regardless of what else
    /// also carries it.
    pub fn is_security(&self) -> bool {
        self.suites.iter().any(|s| s.ends_with("-security"))
    }
}

/// Parse `apt list --upgradable`.
///
/// ```text
/// Listing...
/// libssl3/bookworm-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]
/// tzdata/bookworm-updates,bookworm 2024b-0+deb12u1 all [upgradable from: 2024a-0+deb12u1]
/// ```
///
/// A line that does not have that shape is skipped rather than guessed at —
/// including the `Listing...` header and apt's own stability warning. A wrong
/// count here would be a claim about the security of a server, so unreadable
/// lines contribute nothing rather than something invented.
pub fn parse_upgradable(out: &str) -> Vec<PendingPackage> {
    let mut v = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        let Some(from_at) = line.find("[upgradable from:") else {
            continue;
        };
        let installed = line[from_at + "[upgradable from:".len()..]
            .trim()
            .trim_end_matches(']')
            .trim()
            .to_string();
        let mut fields = line[..from_at].split_whitespace();
        let (Some(name_suites), Some(candidate)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Some((name, suites)) = name_suites.split_once('/') else {
            continue;
        };
        if name.is_empty() || candidate.is_empty() || installed.is_empty() {
            continue;
        }
        v.push(PendingPackage {
            name: name.to_string(),
            installed,
            candidate: candidate.to_string(),
            suites: suites
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
        });
    }
    v
}

/// What apt has waiting, from the index as it currently is on disk.
///
/// Does NOT refresh the index — see [`refresh_index`]. Reading a stale index
/// is cheap and harmless; the caller is responsible for saying how old it is.
pub async fn list_pending() -> Result<Vec<PendingPackage>, AdapterError> {
    let (out, _) = apt("/usr/bin/apt", &["list", "--upgradable"]).await?;
    let parsed = parse_upgradable(&out);
    // Skipping a line the parser does not understand keeps it from inventing a
    // package — but a list that silently comes back SHORTER is a false "fewer
    // updates", and an empty one is a false "up to date". If apt printed more
    // package lines than were read, say the list could not be read.
    let package_lines = count_package_lines(&out);
    if package_lines > parsed.len() {
        return Err(AdapterError::Other(format!(
            "apt listed {package_lines} upgradable packages but only {} could be read — \
             the output is not in the format this version of Hyperion understands",
            parsed.len()
        )));
    }
    Ok(parsed)
}

/// Lines of `apt list` output shaped like a package entry
/// (`name/suite version arch [...]`), whatever language the bracket is in.
fn count_package_lines(out: &str) -> usize {
    out.lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            let Some(first) = fields.next() else {
                return false;
            };
            let named = first
                .split_once('/')
                .is_some_and(|(name, suite)| !name.is_empty() && !suite.is_empty());
            named && fields.count() >= 3 && line.trim_end().ends_with(']')
        })
        .count()
}

/// Refresh the package index — the network half.
///
/// Separate from [`list_pending`] because it is slow, it needs the mirrors to
/// answer, and it is what fails when they do not. A failed refresh must never
/// be reported as "no updates": the index it leaves behind is the OLD one.
pub async fn refresh_index() -> Result<(), AdapterError> {
    // `apt-get update` exits 0 when a mirror cannot be reached: DNS failures,
    // timeouts and refused connections are "transient", reported as a `W:`
    // warning, and the old index stays in place. Counted as a success, a node
    // cut off from its mirrors for months showed "index refreshed just now,
    // no updates pending". `--error-on=any` (apt 2.1.16+, so Debian 11 and
    // later) turns those into a non-zero exit; the stderr check below is the
    // backstop for whatever it still lets through.
    let (_, stderr) = apt("/usr/bin/apt-get", &["update", "-qq", "--error-on=any"]).await?;
    if let Some(line) = fetch_failure(&stderr) {
        return Err(AdapterError::Other(format!(
            "apt-get update finished but not every index was fetched: {line}"
        )));
    }
    Ok(())
}

/// The first line of `apt-get update` stderr that means an index was NOT
/// fetched. Other warnings — a key in the legacy keyring, a repository that
/// changed its label — do not make the index stale and are not failures.
fn fetch_failure(stderr: &str) -> Option<&str> {
    stderr.lines().map(str::trim).find(|l| {
        l.starts_with("E:")
            || l.starts_with("Err:")
            || l.starts_with("W: Failed to fetch")
            || l.starts_with("W: Some index files failed to download")
    })
}

/// Is the machine waiting on a reboot, and for which packages?
///
/// Reads the marker files `update-notifier-common` and Debian's own
/// packaging leave behind. `None` for the list means the marker says a reboot
/// is needed but does not say why — that is still a reboot.
pub async fn reboot_required() -> (bool, Vec<String>) {
    const MARKER: &str = "/var/run/reboot-required";
    const PKGS: &str = "/var/run/reboot-required.pkgs";
    // The marker is written by Ubuntu's update-notifier and by Debian's
    // unattended-upgrades — NOT by a stock Debian kernel upgrade, which is the
    // reboot that matters most. So the running kernel is checked against the
    // installed ones as well, whatever the marker says.
    let kernel = kernel_reboot_reason().await;
    if !Path::new(MARKER).exists() {
        return match kernel {
            Some(k) => (true, vec![k]),
            None => (false, Vec::new()),
        };
    }
    let mut pkgs = tokio::fs::read_to_string(PKGS)
        .await
        .map(|s| {
            let mut v: Vec<String> = s
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            v.sort();
            v.dedup();
            v
        })
        .unwrap_or_default();
    if let Some(k) = kernel {
        pkgs.push(k);
    }
    (true, pkgs)
}

/// Why the running kernel is not the one the machine would boot, if it is not.
async fn kernel_reboot_reason() -> Option<String> {
    let running = tokio::fs::read_to_string("/proc/sys/kernel/osrelease")
        .await
        .ok()?;
    let mut installed = Vec::new();
    let mut dir = tokio::fs::read_dir("/boot").await.ok()?;
    while let Ok(Some(entry)) = dir.next_entry().await {
        if let Some(v) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.strip_prefix("vmlinuz-"))
        {
            installed.push(v.to_string());
        }
    }
    newer_kernel_installed(running.trim(), &installed)
        .map(|newest| format!("kernel {newest} (running {})", running.trim()))
}

/// The newest installed kernel version, when it is newer than `running`.
///
/// Compared version-wise, not by file time: `6.1.0-26-amd64` is newer than
/// `6.1.0-9-amd64`, and reinstalling an old kernel must not look like a new one.
fn newer_kernel_installed<'a>(running: &str, installed: &'a [String]) -> Option<&'a str> {
    let newest = installed
        .iter()
        .max_by(|a, b| compare_versions(a, b))?
        .as_str();
    (compare_versions(newest, running) == std::cmp::Ordering::Greater).then_some(newest)
}

/// Compare two kernel release strings chunk by chunk: runs of digits as
/// numbers, everything else as text.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    fn chunks(s: &str) -> Vec<(bool, &str)> {
        let mut out = Vec::new();
        let mut start = 0;
        let bytes = s.as_bytes();
        for i in 1..=bytes.len() {
            if i == bytes.len() || bytes[i].is_ascii_digit() != bytes[start].is_ascii_digit() {
                out.push((bytes[start].is_ascii_digit(), &s[start..i]));
                start = i;
            }
        }
        out
    }
    let (ca, cb) = (chunks(a), chunks(b));
    for (x, y) in ca.iter().zip(cb.iter()) {
        let ord = match (x, y) {
            ((true, x), (true, y)) => {
                let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
                x.len().cmp(&y.len()).then_with(|| x.cmp(y))
            }
            ((_, x), (_, y)) => x.cmp(y),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    ca.len().cmp(&cb.len())
}

/// When dpkg's database last changed, in unix seconds.
///
/// `/var/lib/dpkg/status` is rewritten by every install, upgrade and removal —
/// whether it came from this panel, from unattended-upgrades or from someone at
/// a root shell. A stored pending list older than this is describing packages
/// that may no longer be pending. `None` when there is no dpkg (not Debian).
pub async fn dpkg_changed_at() -> Option<i64> {
    let meta = tokio::fs::metadata("/var/lib/dpkg/status").await.ok()?;
    let modified = meta.modified().ok()?;
    modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `apt list --upgradable` output from a Debian 12 host, including the
    /// header line and a package offered from two suites.
    const SAMPLE: &str = "Listing...
libssl3/bookworm-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]
openssl/bookworm-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]
tzdata/bookworm-updates,bookworm 2024b-0+deb12u1 all [upgradable from: 2024a-0+deb12u1]
linux-image-amd64/bookworm-security,bookworm-updates 6.1.115-1 amd64 [upgradable from: 6.1.112-1]
";

    #[test]
    fn upgradable_output_parses_every_package_and_nothing_else() {
        let v = parse_upgradable(SAMPLE);
        assert_eq!(v.len(), 4, "the Listing... header is not a package: {v:?}");
        assert_eq!(v[0].name, "libssl3");
        assert_eq!(v[0].candidate, "3.0.15-1~deb12u1");
        assert_eq!(v[0].installed, "3.0.14-1~deb12u2");
        assert_eq!(v[2].suites, vec!["bookworm-updates", "bookworm"]);
    }

    #[test]
    fn security_is_decided_by_the_suite_the_fix_comes_from() {
        let v = parse_upgradable(SAMPLE);
        let by = |n: &str| v.iter().find(|p| p.name == n).expect(n);
        assert!(by("libssl3").is_security());
        assert!(
            !by("tzdata").is_security(),
            "an -updates package is not security"
        );
        // Offered from BOTH pockets: still a security update, because the fix
        // is in the security pocket whatever else also carries it.
        assert!(by("linux-image-amd64").is_security());
        // Ubuntu names it the same way.
        let ubuntu = parse_upgradable(
            "curl/jammy-security 7.81.0-1ubuntu1.18 amd64 [upgradable from: 7.81.0-1ubuntu1.16]",
        );
        assert!(ubuntu[0].is_security());
    }

    /// apt prints a stability warning, sometimes to stdout depending on the
    /// version, and a malformed line must never become an invented package.
    #[test]
    fn noise_and_malformed_lines_contribute_nothing() {
        let out = "WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Listing...
garbage line with no marker
/bookworm-security 1.0 amd64 [upgradable from: 0.9]
nameonly [upgradable from: 0.9]
";
        assert!(
            parse_upgradable(out).is_empty(),
            "{:?}",
            parse_upgradable(out)
        );
        assert!(parse_upgradable("").is_empty());
        assert!(parse_upgradable("Listing...\n").is_empty());
    }

    /// Localized output (a Czech-installed machine) must not come back as an
    /// empty list: the package lines are counted whatever the bracket says.
    #[test]
    fn localized_package_lines_are_counted_so_they_cannot_vanish() {
        let cs = "Vypisuje se…
libssl3/bookworm-security 3.0.15-1~deb12u1 amd64 [aktualizovatelný z: 3.0.14-1~deb12u2]
tzdata/bookworm-updates 2024b-0+deb12u1 all [aktualizovatelný z: 2024a-0+deb12u1]
";
        assert!(parse_upgradable(cs).is_empty());
        assert_eq!(count_package_lines(cs), 2);
        assert_eq!(count_package_lines(SAMPLE), parse_upgradable(SAMPLE).len());
        assert_eq!(
            count_package_lines("WARNING: apt does not have a stable CLI interface.\nListing...\n"),
            0
        );
    }

    #[test]
    fn a_mirror_that_could_not_be_fetched_is_a_failed_refresh() {
        let w = "W: Failed to fetch http://deb.debian.org/debian/dists/bookworm/InRelease  Temporary failure resolving 'deb.debian.org'
W: Some index files failed to download. They have been ignored, or old ones used instead.";
        assert!(fetch_failure(w).is_some());
        assert!(fetch_failure("E: Could not get lock /var/lib/apt/lists/lock").is_some());
        // A keyring notice does not make the index stale.
        assert!(fetch_failure(
            "W: http://repo.example/dists/x/InRelease: Key is stored in legacy trusted.gpg keyring"
        )
        .is_none());
        assert!(fetch_failure("").is_none());
    }

    #[test]
    fn a_newer_installed_kernel_means_a_reboot() {
        let installed = vec![
            "6.1.0-9-amd64".to_string(),
            "6.1.0-26-amd64".to_string(),
            "6.1.0-25-amd64".to_string(),
        ];
        assert_eq!(
            newer_kernel_installed("6.1.0-25-amd64", &installed),
            Some("6.1.0-26-amd64"),
            "26 is newer than 25 and than 9, numerically"
        );
        assert_eq!(newer_kernel_installed("6.1.0-26-amd64", &installed), None);
        assert_eq!(newer_kernel_installed("6.12.9-amd64", &installed), None);
        assert_eq!(newer_kernel_installed("6.1.0-26-amd64", &[]), None);
    }
}
