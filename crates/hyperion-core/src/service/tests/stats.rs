//! Tests for `service::stats`.

use super::*;

/// The net-rate math the realtime sampler runs each tick. Every branch here
/// is one the adversarial review flagged as a false-spike source.
#[test]
fn net_rate_from_delta_handles_resets_and_new_interfaces() {
    use super::net_rate_from_delta;
    use std::collections::HashMap;
    let m = |v: &[(&str, u64, u64)]| -> HashMap<String, (u64, u64)> {
        v.iter()
            .map(|(n, r, t)| (n.to_string(), (*r, *t)))
            .collect()
    };

    // Plain delta over 10s: (2000-1000)/10 = 100 rx, (400-200)/10 = 20 tx.
    let (rx, tx) = net_rate_from_delta(&m(&[("eth0", 1000, 200)]), &m(&[("eth0", 2000, 400)]), 10);
    assert_eq!((rx, tx), (100, 20));

    // dt floored at 1 — a 0 window never divides by zero.
    let (rx, _) = net_rate_from_delta(&m(&[("eth0", 0, 0)]), &m(&[("eth0", 50, 0)]), 0);
    assert_eq!(rx, 50);

    // A NEW interface (no prior baseline) contributes nothing, even with a
    // huge lifetime counter — no spike.
    let (rx, tx) = net_rate_from_delta(
        &m(&[("eth0", 1000, 200)]),
        &m(&[("eth0", 1000, 200), ("veth9", 5_000_000_000, 5_000_000_000)]),
        10,
    );
    assert_eq!((rx, tx), (0, 0));

    // A per-interface counter RESET is skipped for that interface only; a
    // sibling interface's real delta still counts.
    let (rx, tx) = net_rate_from_delta(
        &m(&[("eth0", 9000, 0), ("eth1", 100, 0)]),
        &m(&[("eth0", 10, 0), ("eth1", 1100, 0)]),
        10,
    );
    assert_eq!(rx, 100, "eth0 reset skipped; eth1 (1100-100)/10 counted");
    assert_eq!(tx, 0);
}

/// The "Backups on disk" figure must count a backup ONLY while its archive
/// is still on disk, and the per-site review must credit a dropped-then-
/// off-site copy under off-site — otherwise "I deleted it locally and it's
/// on FTP" still reports gigabytes on the node.
#[tokio::test]
async fn node_stats_splits_local_vs_offsite_backups() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("bk.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("bk.cz").unwrap());
    let detail = s.get(sel).await.expect("get");

    // A local-only backup: on disk, not off-site.
    let id = backups::start(&pool, &detail.id, "local", 100)
        .await
        .expect("start");
    backups::mark_ok(&pool, id, "/backups/bk.cz-100.tar.gz", None, 1_000_000, 200)
        .await
        .expect("ok");

    let ns = s.node_stats("s4", "dev").await.expect("stats");
    assert_eq!(ns.backup_bytes, 1_000_000, "the on-disk archive counts");
    assert_eq!(ns.backup_count, 1);
    let row = ns
        .backup_storage
        .iter()
        .find(|r| r.domain == "bk.cz")
        .expect("a row for the site");
    assert_eq!(row.local_bytes, 1_000_000);
    assert_eq!(row.offsite_bytes, 0);

    // Push it off-site, then drop the local copy (verified remote, paths
    // cleared) — exactly what the on-demand action does.
    backups::set_remote(&pool, id, "ftp://vault/bk.cz-100.tar.gz", "verified", "")
        .await
        .expect("set_remote");
    backups::clear_local_paths(&pool, id).await.expect("clear");

    let ns = s.node_stats("s4", "dev").await.expect("stats2");
    assert_eq!(
        ns.backup_bytes, 0,
        "a backup whose local copy was dropped must NOT count as on-disk"
    );
    assert_eq!(ns.backup_count, 0);
    let row = ns
        .backup_storage
        .iter()
        .find(|r| r.domain == "bk.cz")
        .expect("row still present, now off-site only");
    assert_eq!(row.local_bytes, 0);
    assert_eq!(row.local_count, 0);
    assert_eq!(row.offsite_bytes, 1_000_000, "credited off-site");
    assert_eq!(row.offsite_count, 1);
}

/// The backup directory can hold far more than the records say — a deleted
/// or moved site's archives, a run that died before it was recorded, leftover
/// manifests. "On server" must count those (and say they are untracked)
/// instead of reporting "0 B" over gigabytes of real files.
#[tokio::test]
async fn node_stats_counts_untracked_backup_files() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let root = tempfile::tempdir().expect("dir");
    let s = svc(pool.clone(), happy_mocks()).with_paths(HostingPaths {
        backup_root: root.path().display().to_string(),
        ..HostingPaths::default()
    });
    s.create(req("bk.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("bk.cz").unwrap());
    let detail = s.get(sel).await.expect("get");
    let user = root.path().join(&detail.system_user);
    std::fs::create_dir_all(&user).expect("mkdir");
    let write = |dir: &std::path::Path, name: &str, len: usize| {
        std::fs::write(dir.join(name), vec![0u8; len]).expect("write");
    };

    // Recorded: its archive and the manifest beside it are accounted for.
    write(&user, "bk.cz-100.tar.gz", 300);
    write(&user, "bk.cz-100.manifest.json", 30);
    let id = backups::start(&pool, &detail.id, "local", 100)
        .await
        .expect("start");
    let archive = user.join("bk.cz-100.tar.gz").display().to_string();
    backups::mark_ok(&pool, id, &archive, None, 300, 200)
        .await
        .expect("ok");
    // Not recorded: an archive + dump nobody names.
    write(&user, "bk.cz-50.tar.gz", 1000);
    write(&user, "bk.cz-50.sql", 200);
    // In progress: no row names its file yet, and it must not be called stray.
    backups::start(&pool, &detail.id, "local", 900)
        .await
        .expect("running");
    write(&user, "bk.cz-901.tar.gz", 4000);
    // A site that is no longer on this node, and a file that is not ours by name.
    let gone = root.path().join("gone_cz");
    std::fs::create_dir_all(&gone).expect("mkdir");
    write(&gone, "gone.cz-10.tar.gz", 500);
    write(&user, "notes.txt", 7);

    let ns = s.node_stats("s4", "dev").await.expect("stats");
    assert_eq!(
        ns.backup_bytes,
        300 + 1200 + 500 + 7,
        "what the disk really holds"
    );
    assert_eq!(
        ns.backup_count, 1,
        "only recorded archives count as backups"
    );
    let row = |d: &str| {
        ns.backup_storage
            .iter()
            .find(|r| r.domain == d)
            .unwrap_or_else(|| panic!("a row for {d}"))
            .clone()
    };
    let bk = row("bk.cz");
    assert_eq!((bk.local_bytes, bk.local_count), (300, 1));
    assert_eq!((bk.untracked_bytes, bk.untracked_count), (1200, 1));
    let g = row("gone.cz");
    assert!(g.hosting_id.as_str().is_empty(), "no hosting to link to");
    assert_eq!((g.untracked_bytes, g.untracked_count), (500, 1));
    let stray = row(&format!("{}/", detail.system_user));
    assert_eq!((stray.untracked_bytes, stray.untracked_count), (7, 0));
    assert_eq!(
        ns.backup_storage[0].domain, "bk.cz",
        "biggest on-disk first"
    );
}

/// "Delete untracked" removes exactly the files the row reported: this
/// domain's, named like ours, that no record names and no running backup is
/// writing. Everything else in the directory stays.
#[tokio::test]
async fn backup_untracked_delete_removes_only_unrecorded_files_of_the_domain() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let root = tempfile::tempdir().expect("dir");
    let s = svc(pool.clone(), happy_mocks()).with_paths(HostingPaths {
        backup_root: root.path().display().to_string(),
        ..HostingPaths::default()
    });
    s.create(req("bk.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("bk.cz").unwrap());
    let detail = s.get(sel).await.expect("get");
    let user = root.path().join(&detail.system_user);
    std::fs::create_dir_all(&user).expect("mkdir");
    let write = |name: &str, len: usize| {
        std::fs::write(user.join(name), vec![0u8; len]).expect("write");
    };
    write("bk.cz-100.tar.gz", 300);
    write("bk.cz-100.manifest.json", 30);
    let id = backups::start(&pool, &detail.id, "local", 100)
        .await
        .expect("start");
    let archive = user.join("bk.cz-100.tar.gz").display().to_string();
    backups::mark_ok(&pool, id, &archive, None, 300, 200)
        .await
        .expect("ok");
    write("bk.cz-50.tar.gz", 1000);
    write("bk.cz-50.sql", 200);
    write("bk.cz-50.manifest.json", 20);
    backups::start(&pool, &detail.id, "local", 900)
        .await
        .expect("running");
    write("bk.cz-901.tar.gz", 4000);
    write("other.cz-50.tar.gz", 70);
    write("notes.txt", 7);

    let (files, bytes) = s.backup_untracked_delete("bk.cz").await.expect("delete");
    assert_eq!((files, bytes), (3, 1220));
    let left: std::collections::BTreeSet<String> = std::fs::read_dir(&user)
        .expect("ls")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    let want: std::collections::BTreeSet<String> = [
        "bk.cz-100.tar.gz",
        "bk.cz-100.manifest.json",
        "bk.cz-901.tar.gz",
        "other.cz-50.tar.gz",
        "notes.txt",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(left, want);
    assert!(s.backup_untracked_delete("").await.is_err());
}

/// A run the agent died in the middle of is reaped as failed AND its
/// half-written files go: nothing else ever names them, and retention later
/// deletes the failed row without touching them (an 18 GiB archive lived on
/// that way). A recorded run's files a second later are left alone.
#[tokio::test]
async fn reaping_a_dead_backup_run_removes_its_files() {
    use hyperion_state::backups;
    let pool = open_memory().await.expect("open");
    let root = tempfile::tempdir().expect("dir");
    let s = svc(pool.clone(), happy_mocks()).with_paths(HostingPaths {
        backup_root: root.path().display().to_string(),
        ..HostingPaths::default()
    });
    s.create(req("bk.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("bk.cz").unwrap());
    let detail = s.get(sel).await.expect("get");
    let user = root.path().join(&detail.system_user);
    std::fs::create_dir_all(&user).expect("mkdir");
    let t = 1_000_000;
    // Dead run: row at t, files stamped a second later (the old naming).
    backups::start(&pool, &detail.id, "local", t)
        .await
        .expect("dead");
    let dead = user.join(format!("bk.cz-{}.tar.gz", t + 1));
    let dead_manifest = user.join(format!("bk.cz-{}.manifest.json", t + 1));
    std::fs::write(&dead, b"partial").expect("write");
    std::fs::write(&dead_manifest, b"{}").expect("write");
    // A recorded run two seconds after it, inside the name window.
    let kept = user.join(format!("bk.cz-{}.tar.gz", t + 2));
    std::fs::write(&kept, b"real").expect("write");
    let ok = backups::start(&pool, &detail.id, "local", t + 2)
        .await
        .expect("ok");
    backups::mark_ok(&pool, ok, &kept.display().to_string(), None, 4, t + 3)
        .await
        .expect("mark ok");

    let n = s.backups_reap_stale(3600).await.expect("reap");
    assert_eq!(n, 1);
    assert!(!dead.exists(), "the dead run's archive is removed");
    assert!(!dead_manifest.exists(), "and its manifest");
    assert!(kept.exists(), "a recorded run's file is never touched");
}

#[test]
fn parse_backup_file_name_reads_only_our_names() {
    use super::parse_backup_file_name as p;
    assert_eq!(
        p("www.a-b.cz-1790255288.tar.gz"),
        Some(("www.a-b.cz", 1790255288, "tar.gz"))
    );
    assert_eq!(p("a.cz-5.sql"), Some(("a.cz", 5, "sql")));
    assert_eq!(
        p("a.cz-5.manifest.json"),
        Some(("a.cz", 5, "manifest.json"))
    );
    assert_eq!(p("a.cz-shop.tar.gz"), None);
    assert_eq!(p("a.cz-.sql"), None);
    assert_eq!(p("-5.sql"), None);
    assert_eq!(p("notes.txt"), None);
}

/// human_bytes feeds the disk-warning banner — round-trip
/// readability matters because operators read these numbers
/// off a dashboard and act on them. Boundary at the 1024
/// flip from KiB→MiB→GiB→TiB.
#[test]
fn human_bytes_picks_right_unit() {
    assert_eq!(human_bytes(0), "0 B");
    assert_eq!(human_bytes(512), "512 B");
    assert_eq!(human_bytes(1024), "1.0 KiB");
    assert_eq!(human_bytes(1536), "1.5 KiB");
    assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
    assert_eq!(human_bytes(2_500_000_000), "2.3 GiB");
    assert_eq!(human_bytes(2 * 1024i64.pow(4)), "2.0 TiB");
}
