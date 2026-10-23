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
