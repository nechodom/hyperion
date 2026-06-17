//! Keyless WordPress "defender": outdated plugin/theme detection +
//! minor/patch auto-update classification.
//!
//! There is no external CVE feed. wp-cli already reports whether each
//! plugin/theme has an update available and what the latest version is
//! (it queries WordPress.org), so the defender simply flags outdated
//! components — the dominant real-world WordPress attack vector — and
//! decides which are safe to auto-apply (same-major = minor/patch).

use hyperion_types::WpVulnFinding;

/// Leading numeric segments of a version string. `"1.2.3-rc1"` → `[1,2,3]`
/// (`rc1` has no leading digit → dropped); `"3rc1"` → `[3]`. A fully
/// non-numeric segment is dropped entirely (not coerced to 0), so a
/// garbage version yields `[]` and is never treated as same-major.
fn numeric_segments(v: &str) -> Vec<u64> {
    v.split(['.', '-', '+', '_'])
        .filter_map(|seg| {
            let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u64>().ok()
        })
        .collect()
}

/// True when `latest` is a same-MAJOR bump over `current` — i.e. a
/// minor/patch update that's safe to apply automatically. An unknown or
/// missing major on either side is treated as NOT same-major (never
/// auto-update something we can't reason about).
pub fn is_same_major(current: &str, latest: &str) -> bool {
    match (
        numeric_segments(current).first(),
        numeric_segments(latest).first(),
    ) {
        (Some(c), Some(l)) => c == l,
        _ => false,
    }
}

/// Classify how far `latest` is ahead of `current`: "major" (different
/// first segment), "minor" (same major, different second), else "patch".
pub fn update_type(current: &str, latest: &str) -> &'static str {
    let c = numeric_segments(current);
    let l = numeric_segments(latest);
    match (c.first(), l.first()) {
        (Some(cm), Some(lm)) if cm != lm => "major",
        _ => match (c.get(1), l.get(1)) {
            (Some(cn), Some(ln)) if cn != ln => "minor",
            _ => "patch",
        },
    }
}

/// Dashboard severity bucket for an outdated component. Major-behind is
/// the riskiest, patch the least.
pub fn severity_for(update_type: &str) -> &'static str {
    match update_type {
        "major" => "high",
        "minor" => "medium",
        _ => "low",
    }
}

/// Sort rank for a finding's severity (high first).
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

/// Build an "outdated component" finding for the defender dashboard +
/// per-hosting card.
pub fn outdated_finding(
    slug: &str,
    name: &str,
    kind: &str,
    current: &str,
    latest: &str,
) -> WpVulnFinding {
    let ut = update_type(current, latest);
    WpVulnFinding {
        slug: slug.to_string(),
        name: name.to_string(),
        installed_version: current.to_string(),
        title: format!("Update available: {current} → {latest}"),
        severity: severity_for(ut).to_string(),
        cve: String::new(),
        patched_version: latest.to_string(),
        kind: kind.to_string(),
        update_type: ut.to_string(),
        auto_updatable: is_same_major(current, latest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_major_minor_patch() {
        assert_eq!(update_type("1.2.3", "2.0.0"), "major");
        assert_eq!(update_type("1.2.3", "1.3.0"), "minor");
        assert_eq!(update_type("1.2.3", "1.2.9"), "patch");
        assert_eq!(update_type("1.2", "1.2.5"), "patch");
    }

    #[test]
    fn same_major_drives_auto_update() {
        assert!(is_same_major("1.2.3", "1.9.9"));
        assert!(!is_same_major("1.2.3", "2.0.0"));
        // Unparseable major ⇒ never auto-update.
        assert!(!is_same_major("", "1.0.0"));
        assert!(!is_same_major("abc", "def"));
    }

    #[test]
    fn outdated_finding_marks_minor_patch_auto() {
        let f = outdated_finding("akismet", "Akismet", "plugin", "5.1", "5.3");
        assert_eq!(f.update_type, "minor");
        assert_eq!(f.severity, "medium");
        assert_eq!(f.patched_version, "5.3");
        assert!(f.auto_updatable);

        let major = outdated_finding("woo", "WooCommerce", "plugin", "7.9", "8.0");
        assert_eq!(major.update_type, "major");
        assert_eq!(major.severity, "high");
        assert!(!major.auto_updatable);
    }
}
