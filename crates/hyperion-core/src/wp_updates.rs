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

// ---------------------------------------------------------------------------
// Auto-update pause (skip-list)
//
// Some plugins are commercial: wp-cli reports an update is available, but the
// package download is gated behind a license key, so `wp plugin update` fails.
// Retrying every daily sweep is pointless noise. We don't keep a hardcoded
// "premium" list — that would wrongly block plugins the customer HAS licensed
// (those update fine). Instead we learn from the failure itself: after a couple
// of consecutive failed attempts, PAUSE that one plugin for a while. A later
// success (license added) or an operator "Resume" clears the pause.
// ---------------------------------------------------------------------------

/// Pause after this many consecutive failed auto-update attempts. The first
/// failure can be a transient network/registry blip; a second makes "needs a
/// license key" the overwhelmingly likely cause.
pub const AUTO_UPDATE_FAIL_THRESHOLD: u32 = 2;

/// How long a pause lasts before the sweep retries it once (covers the case
/// where a license was added in the meantime). A manual "Resume" clears it
/// immediately. 30 days.
pub const AUTO_UPDATE_PAUSE_SECS: i64 = 30 * 24 * 3600;

/// Per-plugin pause state, stored as JSON in hosting_kv key `wp_update_skips`
/// as a map `{ slug -> AutoUpdateSkip }`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AutoUpdateSkip {
    pub fail_count: u32,
    pub first_failed_at: i64,
    pub last_failed_at: i64,
    /// Unix secs until which auto-update is paused. `0` = not paused yet
    /// (still below the failure threshold and being retried). `> now` = paused.
    pub paused_until: i64,
    /// Trimmed last error, shown next to the "paused" badge.
    pub last_error: String,
}

/// `{ slug -> AutoUpdateSkip }`. BTreeMap so serialization is stable/diffable.
pub type SkipMap = std::collections::BTreeMap<String, AutoUpdateSkip>;

/// Deserialize the skip-list JSON; an absent/garbage value yields an empty map
/// (never an error — the feature must degrade to "nothing paused").
pub fn parse_skip_map(s: &str) -> SkipMap {
    serde_json::from_str(s).unwrap_or_default()
}

/// Is this slug currently paused (so the sweep must NOT attempt it)?
pub fn is_paused(map: &SkipMap, slug: &str, now: i64) -> bool {
    match map.get(slug) {
        Some(e) => e.paused_until > now,
        None => false,
    }
}

/// Record a failed auto-update attempt for `slug`. Returns `true` iff this call
/// newly crossed into the PAUSED state (so the caller notifies admins exactly
/// once, not on every subsequent failure).
pub fn record_failure(map: &mut SkipMap, slug: &str, now: i64, err: &str) -> bool {
    let e = map.entry(slug.to_string()).or_default();
    let was_paused = e.paused_until > now;
    if e.first_failed_at == 0 {
        e.first_failed_at = now;
    }
    e.fail_count = e.fail_count.saturating_add(1);
    e.last_failed_at = now;
    e.last_error = err.chars().take(200).collect();
    if e.fail_count >= AUTO_UPDATE_FAIL_THRESHOLD {
        e.paused_until = now + AUTO_UPDATE_PAUSE_SECS;
    }
    !was_paused && e.paused_until > now
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

    #[test]
    fn skip_pauses_after_threshold_failures() {
        let mut m = SkipMap::new();
        let now = 1_000_000;
        // First failure: recorded but NOT paused yet (could be transient).
        assert!(!record_failure(
            &mut m,
            "wp-rocket",
            now,
            "could not download"
        ));
        assert!(!is_paused(&m, "wp-rocket", now));
        // Second failure: crosses the threshold → newly paused (notify once).
        assert!(record_failure(
            &mut m,
            "wp-rocket",
            now + 86_400,
            "could not download"
        ));
        assert!(is_paused(&m, "wp-rocket", now + 86_400));
        // Third failure: still paused, but NOT "newly" → no repeat notify.
        assert!(!record_failure(
            &mut m,
            "wp-rocket",
            now + 172_800,
            "could not download"
        ));
        // Pause lapses after the window.
        assert!(!is_paused(
            &m,
            "wp-rocket",
            now + AUTO_UPDATE_PAUSE_SECS + 200_000
        ));
    }

    #[test]
    fn skip_map_round_trips_and_tolerates_garbage() {
        let mut m = SkipMap::new();
        record_failure(&mut m, "acf-pro", 5, "boom");
        let json = serde_json::to_string(&m).unwrap();
        let back = parse_skip_map(&json);
        assert_eq!(back.get("acf-pro").unwrap().fail_count, 1);
        // Garbage / absent → empty map, never an error.
        assert!(parse_skip_map("not json").is_empty());
        assert!(parse_skip_map("").is_empty());
    }
}
