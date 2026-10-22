//! Tests for `service::cluster`.

use super::*;

#[tokio::test]
async fn cluster_sync_refuses_an_invalid_value_and_keeps_the_old_revision() {
    let (w, dir) = synced_worker("[backup_retention]\nkeep_latest_n = 9\n").await;
    let bad = vec![(
        "backup_retention".to_string(),
        [("keep_latest_n".to_string(), "0".to_string())].into(),
    )];
    let err = w
        .cluster_config_apply("rev-bad".into(), bad, vec![])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("keep_latest_n"), "{err}");
    assert_eq!(w.cluster_config_revision().await.unwrap(), None);
    let file = std::fs::read_to_string(dir.path().join("agent.toml")).unwrap();
    assert!(file.contains("keep_latest_n = 9"));
}

#[tokio::test]
async fn cluster_sync_is_refused_on_the_master() {
    let (m, _dir) = svc_with_mode(Some("master")).await;
    let err = m
        .cluster_config_apply("rev".into(), vec![], vec![])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not an enrolled worker"), "{err}");
}
