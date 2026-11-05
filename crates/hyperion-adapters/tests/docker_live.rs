//! The Docker read adapter against a REAL daemon.
//!
//! Ignored by default: it needs `docker` installed and answering, with at
//! least one container on the box. It only reads. The registry tests also
//! need the box to reach the registry of the container's image.
//!
//! ```text
//! cargo test -p hyperion-adapters --test docker_live -- --ignored --test-threads=1
//! ```

use hyperion_adapters::docker::{self, DockerCmd};
use hyperion_adapters::docker_registry;

const MAX: usize = 4 << 20;

/// The containers on this box, inspected.
async fn containers() -> Vec<hyperion_types::docker::DockerContainer> {
    let ps = docker::run(&DockerCmd::PsAll, MAX).await.unwrap();
    let ids = docker::parse_ps(&ps).unwrap();
    if ids.is_empty() {
        return Vec::new();
    }
    let raw = docker::run(&DockerCmd::Inspect(ids), MAX).await.unwrap();
    docker::parse_inspect(&raw).unwrap()
}

/// The first container whose image is named by a plain tag (not a digest,
/// not an id), as a reference.
fn tagged_image(cs: &[hyperion_types::docker::DockerContainer]) -> Option<docker::ImageRef> {
    cs.iter()
        .filter(|c| !c.image.contains('@') && !c.image.starts_with("sha256:"))
        .find_map(|c| docker::ImageRef::parse(&c.image).ok())
}

#[tokio::test]
#[ignore = "needs a running docker daemon with a container"]
async fn an_image_is_read_by_its_tag() {
    let cs = containers().await;
    let Some(tag) = tagged_image(&cs) else {
        println!("skipped: no container runs a tagged image");
        return;
    };
    let raw = docker::run(&DockerCmd::ImageInspect(tag.clone()), MAX)
        .await
        .unwrap();
    let local = docker::parse_image_inspect(&raw, tag.as_str())
        .unwrap()
        .expect("the image a container runs exists");
    assert!(local.image_id.starts_with("sha256:"), "{local:?}");
    assert!(!local.pinned);
    println!("{}: {:?}", tag.as_str(), local.repo_digests);
}

#[tokio::test]
#[ignore = "needs a running docker daemon with a container, and the registry reachable"]
async fn the_registry_is_asked_for_the_digest_of_a_tag() {
    let cs = containers().await;
    let Some(tag) = tagged_image(&cs) else {
        println!("skipped: no container runs a tagged image");
        return;
    };
    // `docker buildx imagetools inspect`, the way the update check asks
    // when Docker Hub's anonymous route does not apply.
    let tools = docker::run(&DockerCmd::ImagetoolsInspect(tag.clone()), MAX).await;
    println!(
        "imagetools: {:?}",
        tools.map(|o| String::from_utf8_lossy(&o)
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | "))
    );
    // The whole route: Hub by HEAD, anything else by imagetools.
    match docker_registry::remote_digest(&tag).await {
        Ok(d) => assert!(d.starts_with("sha256:"), "{d}"),
        Err(e) => println!("remote_digest({}): {e:?}", tag.as_str()),
    }
}

#[tokio::test]
#[ignore = "needs a running docker daemon with a container"]
async fn a_follow_up_log_read_asks_only_for_what_came_after() {
    let cs = containers().await;
    let Some(c) = cs.iter().find(|c| c.state == "running") else {
        println!("skipped: no running container");
        return;
    };
    let id = docker::ContainerId::parse(&c.id).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Everything of the last hour, then only what is newer than a point in
    // the future (nothing), through the same command a follow poll sends.
    let first = DockerCmd::Logs {
        id: id.clone(),
        tail: 50,
        since: Some(now - 3600),
    };
    let all = docker::run(&first, MAX).await.unwrap();
    let later = DockerCmd::Logs {
        id,
        tail: 50,
        since: Some(now + 3600),
    };
    let none = docker::run(&later, MAX).await.unwrap();
    assert!(none.is_empty(), "nothing is newer than the future");
    println!("last hour: {} bytes", all.len());
}

#[tokio::test]
#[ignore = "needs a running docker daemon"]
async fn every_read_command_parses_against_real_docker() {
    let v = docker::run(&DockerCmd::Version, MAX).await.unwrap();
    let v = docker::parse_version(&v).unwrap();
    assert!(!v.client.is_empty());
    assert!(v.server.is_some(), "daemon not answering");

    let b = docker::run(&DockerCmd::BuildxVersion, MAX).await;
    println!(
        "buildx: {:?}",
        b.map(|o| String::from_utf8_lossy(&o).into_owned())
    );

    let ps = docker::run(&DockerCmd::PsAll, MAX).await.unwrap();
    let ids = docker::parse_ps(&ps).unwrap();

    if !ids.is_empty() {
        let raw = docker::run(&DockerCmd::Inspect(ids.clone()), MAX)
            .await
            .unwrap();
        let cs = docker::parse_inspect(&raw).unwrap();
        assert_eq!(cs.len(), ids.len());

        let first = docker::ContainerId::parse(&cs[0].id).unwrap();
        let logs = DockerCmd::Logs {
            id: first,
            tail: 20,
            since: None,
        };
        docker::run(&logs, MAX).await.unwrap();

        let img = docker::ImageRef::parse(&cs[0].image_id).unwrap();
        let raw = docker::run(&DockerCmd::ImageInspect(img), MAX)
            .await
            .unwrap();
        // The tag the container names, read the way the update check reads it.
        let local = docker::parse_image_inspect(&raw, &cs[0].image_id)
            .unwrap()
            .expect("the container's image exists");
        assert_eq!(local.image_id, cs[0].image_id);
    }

    let st = docker::run(&DockerCmd::Stats, MAX).await.unwrap();
    docker::parse_stats(&st).unwrap();

    let df = docker::run(&DockerCmd::SystemDf, MAX).await.unwrap();
    docker::parse_system_df(&df).unwrap();
}
