//! Tests for `service::fs_util`.

use super::*;

/// `join_absolute` is what tells a restore where restic put things.
///
/// `Path::join` with an ABSOLUTE argument throws the base away and returns
/// the argument. Used naively here that would point every restore at the
/// live tree instead of the staging copy — the swap would move the site
/// onto itself and the "restored" dump being imported would be the one
/// still sitting in the real staging directory.
#[test]
fn join_absolute_puts_the_path_under_the_target_instead_of_replacing_it() {
    let target = std::path::Path::new("/home/u/example.cz/.hyperion-restore-1");
    assert_eq!(
        join_absolute(target, "/home/u/example.cz/htdocs"),
        std::path::PathBuf::from("/home/u/example.cz/.hyperion-restore-1/home/u/example.cz/htdocs")
    );
    // The dump lives at a completely different absolute path and has to
    // land under the same target.
    assert_eq!(
        join_absolute(target, "/var/lib/hyperion/snapshot-db-staging/h1"),
        std::path::PathBuf::from(
            "/home/u/example.cz/.hyperion-restore-1/var/lib/hyperion/snapshot-db-staging/h1"
        )
    );
    // And the naive version would have done this, which is the bug. The
    // lint fires on exactly the mistake being demonstrated, which is why
    // it is allowed HERE and nowhere else.
    #[allow(clippy::join_absolute_paths)]
    let naive = target.join("/home/u/example.cz/htdocs");
    assert_eq!(
        naive,
        std::path::PathBuf::from("/home/u/example.cz/htdocs"),
        "Path::join with an absolute argument throws the base away"
    );
}
