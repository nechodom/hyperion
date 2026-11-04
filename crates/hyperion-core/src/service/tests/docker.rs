//! Tests for `service::docker`: the module's install state.

use super::*;
use hyperion_adapters::docker::{DockerCmd, DockerError};

const VERSION_JSON: &[u8] = br#"{"Client":{"Version":"27.3.1"},"Server":{"Version":"27.3.1"}}"#;

/// A mock whose docker answers `version` and answers `buildx version` with
/// `buildx`.
fn docker_mock(buildx: Result<Vec<u8>, DockerError>) -> MockAdapterPort {
    let mut a = happy_mocks();
    a.expect_docker_read().returning(move |cmd, _| match cmd {
        DockerCmd::Version => Ok(VERSION_JSON.to_vec()),
        DockerCmd::BuildxVersion => buildx.clone(),
        other => panic!("install may only ask for versions, not {other:?}"),
    });
    a
}

#[tokio::test]
async fn install_without_docker_says_so() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_docker_read()
        .returning(|_, _| Err(DockerError::NotInstalled));
    let s = svc(pool, a);

    let err = s
        .docker_node_install()
        .await
        .expect_err("no docker, no module");
    assert!(
        err.to_string().contains("Install Docker first"),
        "the operator must be told what to do: {err}"
    );
    assert!(!s.docker_module_enabled().await, "state stays off");
}

#[tokio::test]
async fn install_with_a_silent_daemon_is_refused() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_docker_read()
        .returning(|_, _| Err(DockerError::NotResponding));
    let s = svc(pool, a);

    let err = s.docker_node_install().await.expect_err("daemon is down");
    assert!(err.to_string().contains("not responding"), "{err}");
    assert!(!s.docker_module_enabled().await);
}

#[tokio::test]
async fn install_records_buildx() {
    let pool = open_memory().await.expect("open");
    let s = svc(
        pool,
        docker_mock(Err(DockerError::Failed("unknown command".into()))),
    );

    let st = s.docker_node_install().await.expect("install");
    assert!(st.node_installed);
    assert!(!st.buildx, "buildx failed, so it is recorded as missing");
    assert_eq!(st.docker_version.as_deref(), Some("27.3.1"));
    assert!(s.docker_module_enabled().await);

    let again = s.docker_module_status().await.expect("status");
    assert!(again.node_installed && !again.buildx);
}

#[tokio::test]
async fn install_with_buildx_present() {
    let pool = open_memory().await.expect("open");
    let s = svc(
        pool,
        docker_mock(Ok(b"github.com/docker/buildx v0.17.1 abc\n".to_vec())),
    );
    let st = s.docker_node_install().await.expect("install");
    assert!(st.node_installed && st.buildx);
}

#[tokio::test]
async fn remove_deletes_module_data() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), docker_mock(Ok(b"buildx".to_vec())));
    s.create(req("keep.cz")).await.expect("create hosting");
    s.docker_node_install().await.expect("install");

    for sql in [
        "INSERT INTO docker_projects (project, last_seen_at) VALUES ('shop', 10)",
        "INSERT INTO docker_container_watch (project, service, restart_count) VALUES ('shop', 'web', 3)",
        "INSERT INTO docker_image_checks (image_ref, state) VALUES ('nginx:alpine', 'current')",
        "UPDATE docker_module SET disk_json = '{}', disk_at = 5",
    ] {
        sqlx::query(sql).execute(&pool).await.expect("seed");
    }

    let st = s.docker_node_remove().await.expect("remove");
    assert!(!st.node_installed && !st.buildx);
    assert!(!s.docker_module_enabled().await);

    for table in [
        "docker_projects",
        "docker_container_watch",
        "docker_image_checks",
    ] {
        let (n,): (i64,) = sqlx::query_as(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(n, 0, "{table} must be empty after removal");
    }
    let (disk, at): (String, i64) = sqlx::query_as("SELECT disk_json, disk_at FROM docker_module")
        .fetch_one(&pool)
        .await
        .expect("module row");
    assert_eq!((disk.as_str(), at), ("", 0), "cached disk figures go too");

    let kept = s
        .get(HostingSelector::Domain(
            Domain::parse("keep.cz").expect("parse"),
        ))
        .await;
    assert!(kept.is_ok(), "hostings are untouched by module removal");
}

#[tokio::test]
async fn cluster_install_and_remove_manage_the_master_bookkeeping() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());

    let st = s.docker_cluster_install().await.expect("cluster install");
    assert!(st.cluster_installed && !st.node_installed);

    s.docker_node_register("s4", true).await.expect("register");
    s.docker_node_register("w1", true).await.expect("register");
    s.docker_node_register("w1", true)
        .await
        .expect("registering twice is fine");
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM docker_nodes")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 2);

    s.docker_node_register("w1", false)
        .await
        .expect("unregister");
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM docker_nodes")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 1);

    let st = s.docker_cluster_remove().await.expect("cluster remove");
    assert!(!st.cluster_installed);
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM docker_nodes")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(n, 0, "docker_nodes is cleared with the cluster state");
}

#[tokio::test]
async fn a_node_id_that_is_not_a_node_id_is_refused() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let err = s
        .docker_node_register("  ", true)
        .await
        .expect_err("blank id");
    assert!(matches!(err, RpcError::Validation { .. }), "{err}");
}

#[tokio::test]
async fn status_with_the_module_off_runs_no_docker() {
    // `happy_mocks` has no docker_read expectation, so any call panics.
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let st = s.docker_module_status().await.expect("status");
    assert!(!st.cluster_installed && !st.node_installed && !st.buildx);
    assert_eq!(st.docker_version, None);
}
