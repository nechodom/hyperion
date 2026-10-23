//! Tests for `service::snapshots`.

use super::*;

#[test]
fn retention_rules_read_from_agent_toml_default_to_what_the_agent_runs() {
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("agent.toml");
    // No retention tables at all: the agent's compiled defaults.
    std::fs::write(&cfg, "[agent]\n").expect("write");
    let archives = read_backup_retention_section(Some(&cfg));
    assert_eq!((archives.max_age_days, archives.keep_latest_n), (30, 5));
    let snaps = read_snapshot_retention(Some(&cfg));
    assert_eq!((snaps.keep_days, snaps.keep_last), (30, 5));
    // Snapshots follow [backup_retention] until they have their own rule.
    std::fs::write(
        &cfg,
        "[backup_retention]\nmax_age_days = 60\nkeep_latest_n = 2\n",
    )
    .expect("write");
    let snaps = read_snapshot_retention(Some(&cfg));
    assert_eq!((snaps.keep_days, snaps.keep_last), (60, 2));
    std::fs::write(
        &cfg,
        "[backup_retention]\nmax_age_days = 60\n[snapshots]\nkeep_days = 14\nkeep_last = 0\n",
    )
    .expect("write");
    let snaps = read_snapshot_retention(Some(&cfg));
    assert_eq!((snaps.keep_days, snaps.keep_last), (14, 0));
    // A negative value on disk is clamped, never wrapped into a huge u32.
    std::fs::write(&cfg, "[snapshots]\nkeep_days = -4\n").expect("write");
    assert_eq!(read_snapshot_retention(Some(&cfg)).keep_days, 0);
}

/// Snapshots end to end against a REAL restic. Run on a Linux box with
/// restic installed, as root (the repository root is /var/lib/hyperion):
/// `HYPERION_RESTIC_IT=1 cargo test -p hyperion-core --lib real_restic -- --ignored`
#[tokio::test]
#[ignore]
async fn snapshots_against_real_restic() {
    if std::env::var("HYPERION_RESTIC_IT").is_err() {
        return;
    }
    let pool = open_memory().await.expect("open");
    let cfg_dir = tempfile::tempdir().expect("cfg dir");
    let cfg = cfg_dir.path().join("agent.toml");
    std::fs::write(&cfg, "[snapshots]\nkeep_days = 0\nkeep_last = 0\n").expect("cfg");
    let s = svc(pool.clone(), happy_mocks())
        .with_snapshots(true)
        .with_agent_config_path(cfg.clone());
    s.create(req("realrestic.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("realrestic.cz").expect("parse"));
    let detail = s.get(sel.clone()).await.expect("get");
    std::fs::create_dir_all(&detail.root_dir).expect("root dir");

    // Three snapshots.
    for i in 0..3 {
        std::fs::write(
            std::path::Path::new(&detail.root_dir).join(format!("page{i}.php")),
            format!("<?php echo {i};"),
        )
        .expect("write");
        let id = s
            .snapshot_before_change(&detail, "manual")
            .await
            .expect("a snapshot is taken");
        assert!(hyperion_adapters::restic::is_snapshot_id(&id), "{id}");
    }
    let o = s.snapshot_overview(sel.clone()).await.expect("overview");
    assert_eq!(o.engine, "ready");
    assert_eq!(o.snapshots.len(), 3, "{o:?}");
    assert!(o.repo_bytes > 0);
    assert_eq!(o.retention.keep_days, 0);

    // Delete one by id; the listing agrees.
    let first = o.snapshots[0].id.clone();
    assert_eq!(
        s.snapshot_delete(sel.clone(), vec![first.clone()], false)
            .await
            .expect("delete one"),
        1
    );
    let o = s.snapshot_overview(sel.clone()).await.expect("overview");
    assert_eq!(o.snapshots.len(), 2);
    assert!(!o.snapshots.iter().any(|x| x.id == first));

    // A snapshot that is not there is an error, not a silent success.
    let err = s
        .snapshot_delete(sel.clone(), vec![first.clone()], false)
        .await
        .expect_err("already gone");
    assert!(matches!(err, RpcError::NotFound { .. }), "{err:?}");

    // Retention measured from now: add a snapshot dated 2020, then keep 30
    // days with the newest one always kept. Only the 2020 one goes.
    let repo = hyperion_adapters::restic::Repo::for_hosting(
        hyperion_adapters::restic::REPO_BASE,
        detail.id.as_str(),
    );
    let out = std::process::Command::new("restic")
        .args([
            "-r",
            repo.path.to_str().expect("utf8"),
            "--password-file",
            repo.password_file.to_str().expect("utf8"),
            "--no-cache",
            "backup",
            "--tag",
            "manual",
            "--time",
            "2020-01-01 00:00:00",
            &detail.root_dir,
        ])
        .output()
        .expect("restic");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        s.snapshot_overview(sel.clone())
            .await
            .expect("o")
            .snapshots
            .len(),
        3
    );
    std::fs::write(&cfg, "[snapshots]\nkeep_days = 30\nkeep_last = 1\n").expect("cfg");
    assert_eq!(s.snapshot_retention_tick().await.expect("sweep"), 1);
    let o = s.snapshot_overview(sel.clone()).await.expect("overview");
    assert_eq!(o.snapshots.len(), 2);
    assert!(o
        .snapshots
        .iter()
        .all(|x| x.taken_at().unwrap_or(0) > 1_700_000_000));
    // Nothing else is old: a second sweep deletes nothing.
    assert_eq!(s.snapshot_retention_tick().await.expect("sweep"), 0);

    // "Archives only" takes no new snapshot, and says so.
    std::fs::write(
        &cfg,
        "[snapshots]\nkeep_days = 30\nkeep_last = 1\n[protection]\nmode = \"backups\"\n",
    )
    .expect("cfg");
    assert!(s.snapshot_before_change(&detail, "manual").await.is_none());
    let o = s.snapshot_overview(sel.clone()).await.expect("overview");
    assert_eq!(o.engine, "mode_off");
    assert_eq!(o.snapshots.len(), 2, "existing snapshots are still listed");

    // Delete all.
    assert_eq!(
        s.snapshot_delete(sel.clone(), vec![], true)
            .await
            .expect("delete all"),
        2
    );
    let o = s.snapshot_overview(sel.clone()).await.expect("overview");
    assert!(o.snapshots.is_empty());
    // A retry of "delete all" on an empty repository prunes on its own
    // (the recovery path after a prune that failed) and succeeds.
    assert_eq!(
        s.snapshot_delete(sel.clone(), vec![], true)
            .await
            .expect("delete all again"),
        0
    );
    // An id that was never there is refused before restic runs.
    assert!(s
        .snapshot_delete(sel.clone(), vec!["latest".into()], false)
        .await
        .is_err());
    let _ = std::fs::remove_dir_all(&repo.path);
}
