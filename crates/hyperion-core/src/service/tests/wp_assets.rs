//! Tests for `service::wp_assets`.

use super::*;

/// The stored name is joined onto `/var/lib/hyperion/wp-assets/<id>/`
/// as root — on a worker it now comes from the master's row, so nothing
/// in it may climb out of that directory.
#[test]
fn wp_asset_stored_filename_stays_inside_its_directory() {
    assert_eq!(
        wp_asset_stored_filename("akismet.5.3.zip"),
        "akismet.5.3.zip"
    );
    assert_eq!(
        wp_asset_stored_filename("My Plugin (1).zip"),
        "MyPlugin1.zip"
    );
    assert_eq!(wp_asset_stored_filename("theme"), "theme.zip");
    assert_eq!(
        wp_asset_stored_filename("../../etc/passwd"),
        "....etcpasswd.zip"
    );
    for dots in ["", ".", "..", "/", "///"] {
        assert_eq!(wp_asset_stored_filename(dots), "asset.zip", "{dots:?}");
    }
}

#[test]
fn count_asset_refs_basic_match() {
    let profiles = vec![mk_profile("akismet\n@asset:7\n", "")];
    assert_eq!(count_profile_asset_refs(&profiles, 7), 1);
}

#[test]
fn count_asset_refs_trailing_activate_mark() {
    let profiles = vec![mk_profile("@asset:7!\n", "@asset:7\n")];
    // Two refs: one with !, one plain.
    assert_eq!(count_profile_asset_refs(&profiles, 7), 2);
}

#[test]
fn count_asset_refs_boundary_rejects_prefix_match() {
    // @asset:7 should NOT match @asset:70 / @asset:777.
    let profiles = vec![mk_profile("@asset:70\n@asset:777\n@asset:7x\n", "")];
    assert_eq!(count_profile_asset_refs(&profiles, 7), 0);
}

#[test]
fn count_asset_refs_inline_comment_after_ok() {
    let profiles = vec![mk_profile("@asset:7    # internal client plugin\n", "")];
    assert_eq!(count_profile_asset_refs(&profiles, 7), 1);
}

#[test]
fn count_asset_refs_across_plugins_and_themes() {
    let profiles = vec![mk_profile("@asset:7\n", "@asset:7!\n")];
    assert_eq!(count_profile_asset_refs(&profiles, 7), 2);
}

#[test]
fn count_asset_refs_no_match() {
    let profiles = vec![mk_profile("akismet\nwordpress-seo\n", "")];
    assert_eq!(count_profile_asset_refs(&profiles, 7), 0);
}
