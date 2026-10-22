//! Tests for `service::system`.

use super::*;

/// SHA comparison: identical full SHAs ⇒ no update.
#[test]
fn compare_git_shas_identical_no_update() {
    let (avail, msg) = compare_git_shas(
        "abcdef0123456789abcdef0123456789abcdef01",
        "abcdef0123456789abcdef0123456789abcdef01",
    );
    assert!(!avail);
    assert_eq!(msg, "up to date");
}

/// Mixed-length prefix match — agent compiled with 12-char short,
/// remote returns full 40-char. Must NOT report "update available".
#[test]
fn compare_git_shas_prefix_match() {
    let cur = "abcdef012345"; // 12-char short
    let lat = "abcdef0123456789abcdef0123456789abcdef01"; // 40-char full
    let (avail, msg) = compare_git_shas(cur, lat);
    assert!(
        !avail,
        "12-char prefix of 40-char SHA should not flag update"
    );
    assert_eq!(msg, "up to date");
}

/// Different SHAs ⇒ flag update.
#[test]
fn compare_git_shas_different_flags_update() {
    let (avail, msg) = compare_git_shas("aaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb");
    assert!(avail);
    assert_eq!(msg, "update available");
}

/// "dev-unknown" current ⇒ never nag the operator.
#[test]
fn compare_git_shas_dev_unknown_suppresses_banner() {
    let (avail, msg) = compare_git_shas("dev-unknown", "abc123def456");
    assert!(!avail);
    assert_eq!(msg, "running an unversioned dev build");
}

/// Empty current ⇒ same as dev-unknown.
#[test]
fn compare_git_shas_empty_current_suppresses_banner() {
    let (avail, _) = compare_git_shas("", "abc123def456");
    assert!(!avail);
}

/// Empty latest ⇒ probe-failure path, no nag.
#[test]
fn compare_git_shas_empty_latest_no_update() {
    let (avail, msg) = compare_git_shas("abc123", "");
    assert!(!avail);
    assert!(msg.starts_with("probe failed"));
}

/// Case-insensitive: GitHub's lowercase SHA vs. a mixed-case
/// build-time embed must still match.
#[test]
fn compare_git_shas_case_insensitive() {
    let (avail, _) = compare_git_shas("ABCDEF012345", "abcdef012345xyz");
    assert!(!avail);
}
