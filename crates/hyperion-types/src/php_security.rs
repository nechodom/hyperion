//! Which installed PHP builds carry published security holes.
//!
//! The panel cannot ask anyone whether a PHP build is safe — there is no
//! machine-readable feed it could trust on every node — so the advisories it
//! warns about are compiled in here, and a release that ships a new one adds a
//! row to [`PHP_ADVISORIES`]. The verdict is worked out on the MASTER from the
//! raw facts a node reports ([`PhpRuntime`]), so a worker still running an
//! older agent is judged against the master's newer table.
//!
//! Three answers matter to an operator, and they need different actions:
//!
//! * **unfixable** — the branch is older than every branch that got a fix
//!   (8.1 and below for the 2026-10 advisories). No update will ever close
//!   the hole; the only way out is to move the sites to a newer branch and
//!   uninstall this one.
//! * **outdated** — a fixed release exists for the branch but this node has
//!   an older build. A node update (apt upgrade) closes it.
//! * **patched** — at or above every fix.

use serde::{Deserialize, Serialize};

/// One upstream PHP advisory the panel warns about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhpAdvisory {
    /// GitHub advisory id, e.g. `GHSA-w8hw-w9fx-j79w`.
    pub id: &'static str,
    pub cve: &'static str,
    pub title: &'static str,
    /// The first fixed release on every branch that got one. A branch older
    /// than the oldest of these never will — it is past end of life.
    pub fixed_in: &'static [(u32, u32, u32)],
}

impl PhpAdvisory {
    pub fn url(&self) -> String {
        format!(
            "https://github.com/php/php-src/security/advisories/{}",
            self.id
        )
    }

    /// Whether `version` is hit, and the release that fixes it on that
    /// branch (`None` = the branch never got a fix).
    fn hits(&self, (major, minor, patch): (u32, u32, u32)) -> Option<Option<(u32, u32, u32)>> {
        if let Some(&fix) = self
            .fixed_in
            .iter()
            .find(|(fmaj, fmin, _)| (*fmaj, *fmin) == (major, minor))
        {
            return (patch < fix.2).then_some(Some(fix));
        }
        let oldest = self.fixed_in.iter().map(|(a, b, _)| (*a, *b)).min()?;
        // Newer than every listed branch: released after the fix, not hit.
        // Older than all of them: end of life, hit with nothing to update to.
        ((major, minor) < oldest).then_some(None)
    }
}

const FIXED_2026_10: &[(u32, u32, u32)] = &[(8, 2, 35), (8, 3, 36), (8, 4, 27), (8, 5, 12)];

/// Every advisory the panel warns about, newest first.
pub const PHP_ADVISORIES: &[PhpAdvisory] = &[
    PhpAdvisory {
        id: "GHSA-6wmf-4rv5-p3rp",
        cve: "CVE-2026-109619",
        title: "remote code execution via stale global state",
        fixed_in: FIXED_2026_10,
    },
    PhpAdvisory {
        id: "GHSA-w8hw-w9fx-j79w",
        cve: "CVE-2026-109618",
        title: "remote code execution via out-of-memory corruption",
        fixed_in: FIXED_2026_10,
    },
];

/// What a node reports about one installed PHP branch. Raw facts only — the
/// verdict is the master's job, see the module docs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhpRuntime {
    /// `major.minor`, e.g. "8.1".
    pub branch: String,
    /// dpkg `Version` of the branch's build (`php8.3-fpm`, else `-cli`, else
    /// `-common`), e.g. `8.3.14-1+0~20241128.1+debian12~1.gbp9d0ad7`.
    /// Empty when nothing readable is installed.
    #[serde(default)]
    pub package_version: String,
    /// `php<branch>-fpm` is installed — sites can run on it.
    #[serde(default)]
    pub fpm: bool,
    /// Every site on this node set to this branch, trashed ones included:
    /// restoring one onto a removed branch would fail.
    #[serde(default)]
    pub sites: Vec<PhpRuntimeSite>,
    /// The node-local phpMyAdmin pool runs on this branch.
    #[serde(default)]
    pub pma: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhpRuntimeSite {
    pub id: String,
    pub domain: String,
    #[serde(default)]
    pub trashed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpPatchState {
    /// At or above every fix.
    Patched,
    /// A fixed build exists for this branch; this one is older.
    Outdated,
    /// The branch never gets a fix.
    Unfixable,
    /// A Debian build whose number is below the fix. Debian backports
    /// security fixes without raising the upstream number, so it may or may
    /// not carry them — the number cannot tell.
    DistroBuild,
    /// No readable version.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpSecurityVerdict {
    pub state: PhpPatchState,
    /// The release to update to (the highest fix any hitting advisory needs
    /// on this branch). Set for `Outdated` and `DistroBuild`.
    pub update_to: Option<String>,
    /// The advisories that hit this build. Empty for `Patched`.
    pub advisories: Vec<&'static PhpAdvisory>,
}

/// `(major, minor, patch)` from a dpkg version, plus whether it is Debian's
/// own build rather than an upstream-numbered one (sury.org, PHP's own).
pub fn parse_package_version(raw: &str) -> Option<((u32, u32, u32), bool)> {
    let raw = raw.trim();
    // Epoch ("1:8.2.29-1") is dpkg's ordering hint, not part of the release.
    let raw = raw.split_once(':').map_or(raw, |(_, rest)| rest);
    let (upstream, revision) = raw.split_once('-').unwrap_or((raw, ""));
    let mut it = upstream.split(['.', '+', '~']);
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    Some(((major, minor, patch), is_debian_build(revision)))
}

/// Debian stable updates are revisioned `~debNNuN` / `+debNNuN`; sury.org
/// builds carry `+0~<date>` and follow upstream numbers exactly.
fn is_debian_build(revision: &str) -> bool {
    if revision.contains("+0~") {
        return false;
    }
    revision.match_indices("deb").any(|(i, _)| {
        let tail = &revision[i + 3..];
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        digits > 0 && tail[digits..].starts_with('u')
    })
}

/// `major.minor` → `(major, minor)`.
pub fn parse_branch(branch: &str) -> Option<(u32, u32)> {
    let (a, b) = branch.trim().split_once('.')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// Judge one branch, given its installed build if one was readable.
pub fn verdict(branch: (u32, u32), package_version: &str) -> PhpSecurityVerdict {
    let unfixable: Vec<&'static PhpAdvisory> = PHP_ADVISORIES
        .iter()
        .filter(|a| matches!(a.hits((branch.0, branch.1, 0)), Some(None)))
        .collect();
    if !unfixable.is_empty() {
        return PhpSecurityVerdict {
            state: PhpPatchState::Unfixable,
            update_to: None,
            advisories: unfixable,
        };
    }
    let parsed =
        parse_package_version(package_version).filter(|((maj, min, _), _)| (*maj, *min) == branch);
    let Some((version, debian)) = parsed else {
        let any = PHP_ADVISORIES
            .iter()
            .any(|a| a.hits((branch.0, branch.1, 0)).is_some());
        return PhpSecurityVerdict {
            state: if any {
                PhpPatchState::Unknown
            } else {
                PhpPatchState::Patched
            },
            update_to: None,
            advisories: Vec::new(),
        };
    };
    let mut advisories = Vec::new();
    let mut update_to: Option<(u32, u32, u32)> = None;
    for a in PHP_ADVISORIES {
        if let Some(Some(fix)) = a.hits(version) {
            advisories.push(a);
            update_to = update_to.max(Some(fix));
        }
    }
    let state = match (advisories.is_empty(), debian) {
        (true, _) => PhpPatchState::Patched,
        (false, true) => PhpPatchState::DistroBuild,
        (false, false) => PhpPatchState::Outdated,
    };
    PhpSecurityVerdict {
        state,
        update_to: update_to.map(|(a, b, c)| format!("{a}.{b}.{c}")),
        advisories,
    }
}

/// Whether a branch can never be fixed — a site on it is exposed whatever
/// the node runs. Cheap enough for list and detail pages that only know a
/// site's `php_version`.
pub fn branch_unfixable(branch: &str) -> bool {
    parse_branch(branch).is_some_and(|b| verdict(b, "").state == PhpPatchState::Unfixable)
}

/// The CVE ids that hit a branch with no fix, joined for a sentence.
pub fn unfixable_cves(branch: &str) -> String {
    parse_branch(branch)
        .map(|b| verdict(b, "").advisories)
        .unwrap_or_default()
        .iter()
        .map(|a| a.cve)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_versions_parse() {
        assert_eq!(
            parse_package_version("8.3.14-1+0~20241128.1+debian12~1.gbp9d0ad7"),
            Some(((8, 3, 14), false))
        );
        assert_eq!(
            parse_package_version("8.2.29-1~deb12u1"),
            Some(((8, 2, 29), true))
        );
        assert_eq!(
            parse_package_version("8.4.11-1+deb13u2"),
            Some(((8, 4, 11), true))
        );
        assert_eq!(parse_package_version("1:8.1.2-1"), Some(((8, 1, 2), false)));
        assert_eq!(parse_package_version(""), None);
        assert_eq!(parse_package_version("8.3"), None);
    }

    /// 8.1 got no fix for the 2026-10 advisories — whatever build is there.
    #[test]
    fn an_end_of_life_branch_is_unfixable() {
        for v in ["", "8.1.34-1+0~20260101.1+debian12~1.gbp1"] {
            let got = verdict((8, 1), v);
            assert_eq!(got.state, PhpPatchState::Unfixable, "{v:?}");
            assert_eq!(got.advisories.len(), 2);
            assert_eq!(got.update_to, None);
        }
        assert_eq!(verdict((7, 4), "").state, PhpPatchState::Unfixable);
        assert_eq!(verdict((8, 0), "").state, PhpPatchState::Unfixable);
        assert!(branch_unfixable("8.1"));
        assert!(!branch_unfixable("8.2"));
        assert_eq!(unfixable_cves("8.1"), "CVE-2026-109619, CVE-2026-109618");
    }

    #[test]
    fn a_build_below_the_fix_is_outdated() {
        let got = verdict((8, 3), "8.3.35-1+0~20260901.1+debian12~1.gbp1");
        assert_eq!(got.state, PhpPatchState::Outdated);
        assert_eq!(got.update_to.as_deref(), Some("8.3.36"));
        let got = verdict((8, 2), "8.2.34-1+0~x");
        assert_eq!(got.update_to.as_deref(), Some("8.2.35"));
    }

    #[test]
    fn the_fixed_release_and_later_are_patched() {
        for (b, v) in [
            ((8, 2), "8.2.35-1+0~x"),
            ((8, 3), "8.3.36-1+0~x"),
            ((8, 4), "8.4.27-1+0~x"),
            ((8, 4), "8.4.30-1+0~x"),
            ((8, 5), "8.5.12-1+0~x"),
        ] {
            assert_eq!(verdict(b, v).state, PhpPatchState::Patched, "{v}");
        }
    }

    /// A branch newer than every fix was released with the fix in it.
    #[test]
    fn a_newer_branch_is_not_hit() {
        assert_eq!(verdict((8, 6), "").state, PhpPatchState::Patched);
        assert_eq!(verdict((9, 0), "9.0.0-1").state, PhpPatchState::Patched);
    }

    /// Debian backports fixes under the old number — say so, don't cry wolf.
    #[test]
    fn a_debian_build_below_the_fix_cannot_be_judged_by_number() {
        let got = verdict((8, 4), "8.4.11-1+deb13u2");
        assert_eq!(got.state, PhpPatchState::DistroBuild);
        assert_eq!(got.update_to.as_deref(), Some("8.4.27"));
    }

    #[test]
    fn an_unreadable_version_on_a_fixable_branch_is_unknown() {
        assert_eq!(verdict((8, 3), "").state, PhpPatchState::Unknown);
        // A version from another branch is not this branch's build.
        assert_eq!(verdict((8, 3), "8.4.30-1").state, PhpPatchState::Unknown);
    }
}
