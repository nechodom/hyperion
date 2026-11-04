//! The Docker read adapter against a REAL daemon.
//!
//! Ignored by default: it needs `docker` installed and answering, with at
//! least one container on the box. It only reads.
//!
//! ```text
//! cargo test -p hyperion-adapters --test docker_live -- --ignored --test-threads=1
//! ```

use hyperion_adapters::docker::{self, DockerCmd};

const MAX: usize = 4 << 20;

#[tokio::test]
#[ignore = "needs a running docker daemon"]
async fn every_read_command_parses_against_real_docker() {
    let v = docker::run(&DockerCmd::Version, MAX).await.unwrap();
    let v = docker::parse_version(&v).unwrap();
    assert!(!v.client.is_empty());
    assert!(v.server.is_some(), "daemon not answering");

    let b = docker::run(&DockerCmd::BuildxVersion, MAX).await;
    println!("buildx: {:?}", b.map(|o| String::from_utf8_lossy(&o).into_owned()));

    let ps = docker::run(&DockerCmd::PsAll, MAX).await.unwrap();
    let ids = docker::parse_ps(&ps).unwrap();

    if !ids.is_empty() {
        let raw = docker::run(&DockerCmd::Inspect(ids.clone()), MAX).await.unwrap();
        let cs = docker::parse_inspect(&raw).unwrap();
        assert_eq!(cs.len(), ids.len());

        let first = docker::ContainerId::parse(&cs[0].id).unwrap();
        let logs = DockerCmd::Logs { id: first, tail: 20, since: None };
        docker::run(&logs, MAX).await.unwrap();

        let img = docker::ImageRef::parse(&cs[0].image_id).unwrap();
        docker::run(&DockerCmd::ImageInspect(img), MAX).await.unwrap();
    }

    let st = docker::run(&DockerCmd::Stats, MAX).await.unwrap();
    docker::parse_stats(&st).unwrap();

    let df = docker::run(&DockerCmd::SystemDf, MAX).await.unwrap();
    docker::parse_system_df(&df).unwrap();
}
