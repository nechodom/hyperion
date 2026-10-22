//! Tests for `service::fs_health`.

use super::*;

/// classify_image_kind drives the auto-fix UX: snap/overlay
/// images can NOT be made writable, so the diagnose card must
/// surface "this image is immutable, switch to standard Debian"
/// instead of pointlessly suggesting `mount -o remount,rw`.
/// Guard the heuristic against silent regressions.
#[test]
fn classify_image_kind_signatures() {
    // Real-world fingerprints from /proc/mounts.
    assert_eq!(classify_image_kind("ext4", "squashfs"), "snap-managed");
    assert_eq!(classify_image_kind("squashfs", "ext4"), "snap-managed");
    assert_eq!(classify_image_kind("overlay", ""), "overlay-immutable");
    assert_eq!(classify_image_kind("ext4", ""), "standard");
    assert_eq!(classify_image_kind("xfs", ""), "standard");
    assert_eq!(classify_image_kind("btrfs", ""), "standard");
    // Genuinely unknown filesystem → "unknown" (NOT "standard");
    // the renderer downgrades guidance so we don't tell the
    // operator to remount something we don't understand.
    assert_eq!(classify_image_kind("zfs", ""), "unknown");
    assert_eq!(classify_image_kind("", ""), "unknown");
}
