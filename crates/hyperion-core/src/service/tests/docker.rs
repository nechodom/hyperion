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

    let list = s.docker_node_list().await.expect("list");
    assert!(list.cluster_installed);
    assert_eq!(
        list.nodes
            .iter()
            .map(|n| n.node_id.as_str())
            .collect::<Vec<_>>(),
        ["s4"],
        "the web layer fans out to exactly what is registered"
    );

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

// ---------------------------------------------------------------------------
// The node tick: verdicts, alerts and the snapshot the overview serves.
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex};

const FIXTURE_PS: &[u8] =
    include_bytes!("../../../../hyperion-adapters/tests/fixtures/docker/ps.jsonl");
const FIXTURE_INSPECT: &[u8] =
    include_bytes!("../../../../hyperion-adapters/tests/fixtures/docker/inspect.json");
const FIXTURE_STATS: &[u8] =
    include_bytes!("../../../../hyperion-adapters/tests/fixtures/docker/stats.jsonl");
const FIXTURE_DF: &[u8] =
    include_bytes!("../../../../hyperion-adapters/tests/fixtures/docker/system_df.jsonl");

const T0: i64 = 1_000_000;

/// One container of the simulated daemon.
#[derive(Clone)]
struct Ct {
    n: u32,
    project: &'static str,
    service: &'static str,
    state: &'static str,
    exit: i64,
    policy: &'static str,
    restarts: i64,
    health: Option<&'static str>,
    oneoff: bool,
    oom: bool,
    log_path: String,
}

impl Ct {
    fn id(&self) -> String {
        format!("{:064x}", self.n)
    }
    fn exited(self, exit: i64) -> Self {
        Self {
            state: "exited",
            exit,
            ..self
        }
    }
    fn restarts(self, restarts: i64) -> Self {
        Self { restarts, ..self }
    }
    fn health(self, h: &'static str) -> Self {
        Self {
            health: Some(h),
            ..self
        }
    }
    fn oneoff(self) -> Self {
        Self {
            oneoff: true,
            ..self
        }
    }
}

fn ct(n: u32, project: &'static str, service: &'static str) -> Ct {
    Ct {
        n,
        project,
        service,
        state: "running",
        exit: 0,
        policy: "no",
        restarts: 0,
        health: None,
        oneoff: false,
        oom: false,
        log_path: String::new(),
    }
}

#[derive(Default)]
struct World {
    cts: Vec<Ct>,
    ps_err: Option<DockerError>,
    inspect_err: Option<DockerError>,
    /// Containers `ps` lists that are gone by the time `inspect` asks.
    vanish_before_inspect: Vec<u32>,
    reads: Vec<String>,
    /// What `docker logs` prints for container number n.
    logs: std::collections::HashMap<u32, Vec<u8>>,
    logs_err: Option<DockerError>,
    /// Containers (by number) whose `docker logs` fails.
    logs_fail: Vec<u32>,
    /// The byte limit each `docker logs` was given.
    log_limits: Vec<usize>,
}

type Shared = Arc<Mutex<World>>;

fn world(cts: Vec<Ct>) -> Shared {
    Arc::new(Mutex::new(World {
        cts,
        ..Default::default()
    }))
}

fn set(w: &Shared, cts: Vec<Ct>) {
    w.lock().expect("world").cts = cts;
}

fn reads_of(w: &Shared, what: &str) -> usize {
    w.lock()
        .expect("world")
        .reads
        .iter()
        .filter(|r| r.starts_with(what))
        .count()
}

fn inspect_json(c: &Ct) -> serde_json::Value {
    let mut labels = serde_json::Map::new();
    if !c.project.is_empty() {
        labels.insert("com.docker.compose.project".into(), c.project.into());
        labels.insert("com.docker.compose.service".into(), c.service.into());
        labels.insert(
            "com.docker.compose.oneoff".into(),
            if c.oneoff { "True" } else { "False" }.into(),
        );
    }
    labels.insert("secret.label".into(), "do-not-leak-7f3a".into());
    let mut state = serde_json::json!({
        "Status": c.state, "ExitCode": c.exit, "OOMKilled": c.oom,
    });
    if let Some(h) = c.health {
        state["Health"] = serde_json::json!({"Status": h});
    }
    serde_json::json!({
        "Id": c.id(),
        "Name": format!("/{}-{}-1", c.project, c.service),
        "RestartCount": c.restarts,
        "LogPath": c.log_path,
        "State": state,
        "HostConfig": {"RestartPolicy": {"Name": c.policy}},
        "Config": {"Image": "img", "Labels": labels, "Env": ["SECRET_VALUE=do-not-leak-7f3a"]},
    })
}

/// A daemon that answers from `w` and records what it was asked.
fn world_mock(w: &Shared) -> MockAdapterPort {
    let w = w.clone();
    let mut a = happy_mocks();
    a.expect_docker_read().returning(move |cmd, max| {
        let mut w = w.lock().expect("world");
        w.reads.push(format!("{cmd:?}"));
        match cmd {
            DockerCmd::PsAll => {
                if let Some(e) = w.ps_err.clone() {
                    return Err(e);
                }
                let mut out = String::new();
                for c in &w.cts {
                    out.push_str(&format!("{{\"ID\":\"{}\"}}\n", c.id()));
                }
                Ok(out.into_bytes())
            }
            DockerCmd::Inspect(ids) => {
                if let Some(e) = w.inspect_err.clone() {
                    return Err(e);
                }
                let rows: Vec<_> = w
                    .cts
                    .iter()
                    .filter(|c| ids.iter().any(|i| i.as_str() == c.id()))
                    .filter(|c| !w.vanish_before_inspect.contains(&c.n))
                    .map(inspect_json)
                    .collect();
                Ok(serde_json::to_vec(&rows).expect("json"))
            }
            DockerCmd::Stats => {
                let mut out = String::new();
                for c in w.cts.iter().filter(|c| c.state == "running") {
                    out.push_str(&format!(
                        "{{\"Container\":\"{}\",\"ID\":\"{}\",\"Name\":\"x\",\
                         \"CPUPerc\":\"1.50%\",\"MemUsage\":\"10MiB / 1GiB\"}}\n",
                        c.id(),
                        &c.id()[..12]
                    ));
                }
                Ok(out.into_bytes())
            }
            DockerCmd::SystemDf => Ok(b"{\"Type\":\"Images\",\"Size\":\"1GB\"}\n".to_vec()),
            DockerCmd::Logs { id, tail, .. } => {
                w.log_limits.push(max);
                if let Some(e) = w.logs_err.clone() {
                    return Err(e);
                }
                let n = w.cts.iter().find(|c| c.id() == id.as_str()).map(|c| c.n);
                if n.is_some_and(|n| w.logs_fail.contains(&n)) {
                    return Err(DockerError::Failed("boom secret-stderr".into()));
                }
                let all = n.and_then(|n| w.logs.get(&n).cloned()).unwrap_or_default();
                // What docker does: the last `tail` lines, oldest first, and a
                // run that reaches the byte limit is killed there, which
                // leaves the START of those lines.
                let starts: Vec<usize> = std::iter::once(0)
                    .chain(
                        all.iter()
                            .enumerate()
                            .filter(|(i, b)| **b == b'\n' && i + 1 < all.len())
                            .map(|(i, _)| i + 1),
                    )
                    .collect();
                let from = starts[starts.len().saturating_sub(tail as usize)];
                let mut out = all[from..].to_vec();
                out.truncate(max);
                Ok(out)
            }
            other => panic!("the tick may only list, inspect and measure: {other:?}"),
        }
    });
    a
}

/// A worker node (its alerts land in the outbox, one row per alert, which is
/// what lets these tests count them) with the Docker module on. The
/// directory must outlive the service.
async fn worker_with(a: MockAdapterPort) -> (HostingService<MockAdapterPort>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("dir");
    let state = dir.path().join("node-id.json");
    std::fs::write(&state, b"{}").expect("state file");
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), a).with_node_state_file(state);
    hyperion_state::docker::set_node_installed(&pool, false, 1)
        .await
        .expect("module on");
    (s, dir)
}

/// (kind, severity, title, body) of every alert raised so far, oldest first.
async fn alerts(s: &HostingService<MockAdapterPort>) -> Vec<(String, String, String, String)> {
    s.notifications_outbox(0, 100)
        .await
        .expect("outbox")
        .into_iter()
        .map(|n| (n.kind, n.severity, n.title, n.body))
        .collect()
}

async fn tick_at(s: &HostingService<MockAdapterPort>, t: i64) {
    s.docker_tick_at(t).await.expect("tick");
}

/// Tick every 30 s from `from` to `to`, both included.
async fn tick_through(s: &HostingService<MockAdapterPort>, from: i64, to: i64) {
    let mut t = from;
    while t <= to {
        tick_at(s, t).await;
        t += 30;
    }
}

#[tokio::test]
async fn tick_does_nothing_when_not_installed() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_docker_read().times(0);
    let s = svc(pool, a);
    s.docker_tick()
        .await
        .expect("an off module ticks as a no-op");
    assert!(s.docker_snapshot.read().await.is_none());
}

#[tokio::test]
async fn snapshot_has_no_secret() {
    let mut a = happy_mocks();
    a.expect_docker_read().returning(|cmd, _| match cmd {
        DockerCmd::PsAll => Ok(FIXTURE_PS.to_vec()),
        DockerCmd::Inspect(_) => Ok(FIXTURE_INSPECT.to_vec()),
        DockerCmd::Stats => Ok(FIXTURE_STATS.to_vec()),
        DockerCmd::SystemDf => Ok(FIXTURE_DF.to_vec()),
        other => panic!("unexpected {other:?}"),
    });
    let (s, _dir) = worker_with(a).await;
    s.docker_tick().await.expect("tick");

    let st = s.docker_overview().await.expect("overview");
    let wire = serde_json::to_string(&st).expect("json");
    assert!(
        !wire.contains("do-not-leak-7f3a"),
        "neither Env nor a foreign label may reach the snapshot"
    );
    assert!(st.daemon_ok && st.daemon_error.is_none());
    assert!(st.disk.is_some(), "system df is read on the first tick");

    let fixture = st
        .projects
        .iter()
        .find(|p| p.name == "fixture")
        .expect("compose project");
    assert_eq!(fixture.verdict, "problem");
    assert!(
        fixture.summary.contains("exit 3"),
        "the crashed service is named with its exit code: {}",
        fixture.summary
    );
    assert!(
        fixture.containers.iter().any(|c| c.cpu_pct_x100.is_some()),
        "stats are merged in"
    );
    let other = st.projects.iter().find(|p| p.name.is_empty());
    assert!(other.is_some(), "containers of no project are listed too");
}

#[tokio::test]
async fn overview_reads_once_when_no_tick_has_run_yet() {
    let w = world(vec![ct(1, "shop", "web")]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    let st = s.docker_overview().await.expect("overview");
    assert_eq!(st.projects.len(), 1);
    let before = reads_of(&w, "PsAll");
    assert_eq!(before, 1);
    s.docker_overview().await.expect("again");
    s.docker_overview().await.expect("and again");
    assert_eq!(
        reads_of(&w, "PsAll"),
        before,
        "the overview only reads while it has nothing to show"
    );
}

#[tokio::test]
async fn overview_with_the_module_off_is_refused() {
    let s = svc(open_memory().await.expect("open"), happy_mocks());
    let err = s.docker_overview().await.expect_err("module is off");
    assert!(matches!(err, RpcError::Validation { .. }), "{err}");
}

#[tokio::test]
async fn no_alert_inside_the_grace_and_one_down_after_it() {
    let w = world(vec![ct(1, "shop", "web").health("unhealthy")]);
    let (s, _dir) = worker_with(world_mock(&w)).await;

    tick_through(&s, T0, T0 + 150).await;
    assert!(
        alerts(&s).await.is_empty(),
        "inside the grace nothing goes out"
    );

    tick_at(&s, T0 + 180).await;
    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, "docker.project:shop");
    assert_eq!(sent[0].1, "error");
    assert_eq!(sent[0].2, "Docker project has a problem");
    assert!(sent[0].3.contains("shop") && sent[0].3.contains("web: unhealthy"));

    tick_through(&s, T0 + 210, T0 + 600).await;
    assert_eq!(alerts(&s).await.len(), 1, "a standing problem alerts once");

    set(&w, vec![ct(1, "shop", "web")]);
    tick_at(&s, T0 + 630).await;
    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].0, "docker.project:shop", "same card as the problem");
    assert_eq!(sent[1].1, "info");
    assert_eq!(sent[1].2, "Docker project recovered");
}

#[tokio::test]
async fn redeploy_is_quiet() {
    let w = world(vec![ct(1, "shop", "web").health("unhealthy")]);
    let (s, pool_dir) = worker_with(world_mock(&w)).await;
    let _keep = pool_dir;
    tick_through(&s, T0, T0 + 120).await;
    let row = hyperion_state::docker::get_project(&s.pool, "shop")
        .await
        .expect("row")
        .expect("known");
    assert_eq!(row.problem_since, T0);

    set(&w, vec![ct(1, "shop", "web")]);
    tick_at(&s, T0 + 150).await;
    let row = hyperion_state::docker::get_project(&s.pool, "shop")
        .await
        .expect("row")
        .expect("known");
    assert_eq!(row.problem_since, 0, "a recovered project starts over");

    // A new streak counts from its own start, not from the old one.
    set(&w, vec![ct(2, "shop", "web").health("unhealthy")]);
    tick_through(&s, T0 + 180, T0 + 330).await;
    assert!(alerts(&s).await.is_empty(), "a redeploy never alerted");
}

#[tokio::test]
async fn a_restart_loop_alerts_after_three_rises() {
    let w = world(vec![ct(1, "shop", "web")]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;
    for (i, n) in [1, 2, 3].into_iter().enumerate() {
        set(&w, vec![ct(1, "shop", "web").restarts(n)]);
        tick_at(&s, T0 + 30 * (i as i64 + 1)).await;
    }
    let st = s.docker_overview().await.expect("overview");
    assert_eq!(st.projects[0].verdict, "problem");
    assert_eq!(st.projects[0].summary, "web: restart loop");

    tick_through(&s, T0 + 120, T0 + 300).await;
    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].3.contains("web: restart loop"));
}

#[tokio::test]
async fn recreated_container_keeps_watch() {
    let w = world(vec![ct(1, "shop", "web").restarts(2)]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;

    // `compose up` replaced the container: new id, counter back to 0.
    set(&w, vec![ct(2, "shop", "web")]);
    tick_at(&s, T0 + 30).await;
    let watch = hyperion_state::docker::load_watch(&s.pool)
        .await
        .expect("watch");
    assert_eq!(watch.len(), 1);
    assert!(
        watch[0].rises.is_empty(),
        "a new id is not a restart: {:?}",
        watch[0].rises
    );
    let st = s.docker_overview().await.expect("overview");
    assert_eq!(st.projects[0].verdict, "ok", "and it is not gone either");

    // The history follows the service across ids: one rise on the old
    // container, two on the new one make a loop.
    set(&w, vec![ct(2, "shop", "web").restarts(1)]);
    tick_at(&s, T0 + 60).await;
    set(&w, vec![ct(3, "shop", "web")]);
    tick_at(&s, T0 + 90).await;
    set(&w, vec![ct(3, "shop", "web").restarts(2)]);
    tick_at(&s, T0 + 120).await;
    let st = s.docker_overview().await.expect("overview");
    assert_eq!(st.projects[0].summary, "web: restart loop");
}

#[tokio::test]
async fn oneoff_never_alerts() {
    let w = world(vec![
        ct(1, "shop", "web"),
        ct(2, "shop", "run").oneoff().exited(1),
        ct(3, "tool", "run").oneoff().exited(1),
    ]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_through(&s, T0, T0 + 400).await;
    assert!(alerts(&s).await.is_empty());

    let known: Vec<_> = hyperion_state::docker::list_projects(&s.pool)
        .await
        .expect("rows")
        .into_iter()
        .map(|r| r.project)
        .collect();
    assert_eq!(
        known,
        ["shop"],
        "a project of one-offs is not a known project"
    );

    // ... so it cannot go missing either.
    set(&w, vec![ct(1, "shop", "web")]);
    tick_through(&s, T0 + 430, T0 + 700).await;
    assert!(alerts(&s).await.is_empty());
}

#[tokio::test]
async fn a_finished_job_is_not_a_problem() {
    let w = world(vec![
        ct(1, "shop", "web"),
        ct(2, "shop", "migrate").exited(0),
    ]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_through(&s, T0, T0 + 400).await;
    assert!(alerts(&s).await.is_empty());
    set(&w, vec![ct(2, "batch", "migrate").exited(0)]);
    tick_through(&s, T0 + 430, T0 + 700).await;
    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 1, "only shop going away is news: {sent:?}");
    assert_eq!(sent[0].0, "docker.project:shop");
}

#[tokio::test]
async fn project_gone_alerts_once_and_forget_clears_it() {
    let w = world(vec![ct(1, "shop", "web")]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;

    set(&w, vec![]);
    tick_through(&s, T0 + 30, T0 + 600).await;
    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, "docker.project:shop");
    assert_eq!(sent[0].2, "Docker project is gone");
    let st = s.docker_overview().await.expect("overview");
    assert_eq!(st.projects[0].verdict, "gone");
    assert_eq!(st.projects[0].gone_since, Some(T0 + 30));
    assert!(st.projects[0].containers.is_empty());

    s.docker_forget_project("shop".into())
        .await
        .expect("forget");
    assert!(hyperion_state::docker::list_projects(&s.pool)
        .await
        .expect("rows")
        .is_empty());
    assert!(hyperion_state::docker::load_watch(&s.pool)
        .await
        .expect("watch")
        .is_empty());
    tick_through(&s, T0 + 630, T0 + 900).await;
    assert_eq!(
        alerts(&s).await.len(),
        1,
        "forgetting sends no Up and no Down"
    );
    assert!(s
        .docker_overview()
        .await
        .expect("overview")
        .projects
        .is_empty());

    // If it comes back it is simply known again.
    set(&w, vec![ct(1, "shop", "web")]);
    tick_at(&s, T0 + 930).await;
    assert_eq!(
        hyperion_state::docker::list_projects(&s.pool)
            .await
            .expect("rows")
            .len(),
        1
    );
    assert_eq!(
        alerts(&s).await.len(),
        1,
        "a forgotten alert has no recovery"
    );
}

#[tokio::test]
async fn a_gone_project_that_returns_says_so_on_the_same_card() {
    use hyperion_state::web_users::WebRole;
    let w = world(vec![ct(1, "shop", "web")]);
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), world_mock(&w));
    hyperion_state::docker::set_node_installed(&pool, false, 1)
        .await
        .expect("module on");
    let me = seed_web_user(&s, "boss", WebRole::Admin).await;

    tick_at(&s, T0).await;
    set(&w, vec![]);
    tick_through(&s, T0 + 30, T0 + 300).await;
    assert_eq!(manual_kinds(&s, me).await, ["docker.project:shop"]);

    set(&w, vec![ct(1, "shop", "web")]);
    tick_at(&s, T0 + 330).await;
    let feed = s.notifications_feed(me, 10).await.expect("feed");
    assert_eq!(
        feed.items.len(),
        1,
        "problem and recovery fold into one card"
    );
    assert_eq!(feed.items[0].title, "Docker project recovered");
    assert_eq!(feed.items[0].href, "/docker");
    assert_eq!(feed.unread_total, 1, "and it is unread again");
}

#[tokio::test]
async fn daemon_down_is_one_alert_and_keeps_projects() {
    let w = world(vec![ct(1, "shop", "web")]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;

    w.lock().expect("world").ps_err = Some(DockerError::NotResponding);
    tick_through(&s, T0 + 30, T0 + 180).await;
    assert!(
        alerts(&s).await.is_empty(),
        "a daemon restart is over before the grace is"
    );

    tick_through(&s, T0 + 210, T0 + 600).await;
    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 1, "one card for the node: {sent:?}");
    assert_eq!(sent[0].0, "docker.daemon");
    assert_eq!(sent[0].1, "error");
    assert_eq!(sent[0].2, "Docker is not responding");

    let st = s.docker_overview().await.expect("overview");
    assert!(!st.daemon_ok && st.daemon_error.is_some());
    assert_eq!(st.read_at, T0, "the facts are as old as the last read");
    assert_eq!(st.projects.len(), 1);
    assert_eq!(st.projects[0].verdict, "ok", "no project reads as gone");
    assert_eq!(st.projects[0].containers.len(), 1);
    let row = hyperion_state::docker::get_project(&s.pool, "shop")
        .await
        .expect("row")
        .expect("known");
    assert_eq!((row.gone_since, row.alert_state.as_str()), (0, "ok"));

    w.lock().expect("world").ps_err = None;
    tick_at(&s, T0 + 630).await;
    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[1].0, "docker.daemon");
    assert_eq!(sent[1].1, "info");
    assert_eq!(sent[1].2, "Docker responds again");
    assert!(s.docker_overview().await.expect("overview").daemon_ok);
}

#[tokio::test]
async fn a_failing_inspect_is_the_daemons_problem_not_the_projects() {
    let w = world(vec![ct(1, "shop", "web")]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;
    w.lock().expect("world").inspect_err = Some(DockerError::Failed("boom".into()));
    tick_through(&s, T0 + 30, T0 + 400).await;

    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, "docker.daemon");
    let row = hyperion_state::docker::get_project(&s.pool, "shop")
        .await
        .expect("row")
        .expect("known");
    assert_eq!((row.gone_since, row.problem_since), (0, 0));
}

#[tokio::test]
async fn a_container_removed_between_ps_and_inspect_does_not_fail_the_tick() {
    let w = world(vec![ct(1, "shop", "web"), ct(2, "shop", "worker")]);
    w.lock().expect("world").vanish_before_inspect = vec![2];
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;
    let st = s.docker_overview().await.expect("overview");
    assert!(st.daemon_ok);
    assert_eq!(st.projects[0].containers.len(), 1);
}

#[tokio::test]
async fn log_size_is_the_file_size_and_a_missing_file_is_zero() {
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("web-json.log");
    std::fs::write(&log, b"12345").expect("log");
    let mut with_log = ct(1, "shop", "web");
    with_log.log_path = log.to_string_lossy().into_owned();
    let mut without = ct(2, "shop", "worker");
    without.log_path = dir.path().join("nope.log").to_string_lossy().into_owned();
    let w = world(vec![with_log, without]);
    let (s, _keep) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;
    let st = s.docker_overview().await.expect("overview");
    let size = |name: &str| {
        st.projects[0]
            .containers
            .iter()
            .find(|c| c.name.contains(name))
            .map(|c| c.log_size_bytes)
    };
    assert_eq!(size("web"), Some(5));
    assert_eq!(size("worker"), Some(0));
}

#[tokio::test]
async fn stats_every_second_tick_and_df_hourly() {
    let w = world(vec![ct(1, "shop", "web")]);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;
    assert_eq!((reads_of(&w, "Stats"), reads_of(&w, "SystemDf")), (1, 1));

    tick_at(&s, T0 + 30).await;
    assert_eq!(reads_of(&w, "Stats"), 1, "stats skip this tick");
    let st = s.docker_overview().await.expect("overview");
    assert_eq!(
        st.projects[0].containers[0].cpu_pct_x100,
        Some(150),
        "and the last figures are carried over"
    );
    assert_eq!(st.stats_at, T0);

    tick_at(&s, T0 + 60).await;
    assert_eq!(reads_of(&w, "Stats"), 2);
    tick_through(&s, T0 + 90, T0 + 3500).await;
    assert_eq!(reads_of(&w, "SystemDf"), 1, "df is cached for an hour");
    tick_at(&s, T0 + 3600).await;
    assert_eq!(reads_of(&w, "SystemDf"), 2);
    let cached = hyperion_state::docker::get_module(&s.pool)
        .await
        .expect("module");
    assert!(cached.disk_json.contains("images_bytes") && cached.disk_at == T0 + 3600);
}

#[tokio::test]
async fn forgetting_needs_a_real_project_name() {
    let (s, _dir) = worker_with(happy_mocks()).await;
    let err = s
        .docker_forget_project("a\nb".into())
        .await
        .expect_err("control characters");
    assert!(matches!(err, RpcError::Validation { .. }), "{err}");
    s.docker_forget_project("never-seen".into())
        .await
        .expect("an unknown project is nothing to forget");
}

// ---------------------------------------------------------------------------
// Logs.
// ---------------------------------------------------------------------------

use super::super::docker_logs::{lines_after, merge_by_ts, strip_ansi, LogCursor};
use hyperion_types::docker::{DockerLogLine, DockerLogRequest, MAX_LOG_BYTES, MAX_LOG_LINES};

/// A docker timestamp `sec` seconds and `ns` nanoseconds past 10:00:00.
fn ts(sec: u32, ns: u32) -> String {
    format!("2024-05-01T10:00:{sec:02}.{ns:09}Z")
}

/// What `docker logs --timestamps` prints for these (timestamp, text) pairs.
fn printed(lines: &[(String, &str)]) -> Vec<u8> {
    lines
        .iter()
        .map(|(t, x)| format!("{t} {x}\n"))
        .collect::<String>()
        .into_bytes()
}

fn line(t: String, service: &str, text: &str) -> DockerLogLine {
    DockerLogLine {
        ts: t,
        service: service.into(),
        text: text.into(),
    }
}

fn logs_for(project: &str, container: Option<&str>) -> DockerLogRequest {
    DockerLogRequest {
        project: project.into(),
        container: container.map(str::to_string),
        ..Default::default()
    }
}

fn set_logs(w: &Shared, n: u32, bytes: Vec<u8>) {
    w.lock().expect("world").logs.insert(n, bytes);
}

/// A node with one stack, `shop`, of the given services (container n+1 for
/// the n-th), already ticked once. Container names are `shop-<service>-1`.
async fn shop_with(
    services: &[&'static str],
) -> (HostingService<MockAdapterPort>, Shared, tempfile::TempDir) {
    let w = world(
        services
            .iter()
            .enumerate()
            .map(|(i, svc)| ct(i as u32 + 1, "shop", svc))
            .collect(),
    );
    let (s, dir) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;
    (s, w, dir)
}

#[tokio::test]
async fn container_must_exist_in_snapshot() {
    let (s, w, _d) = shop_with(&["web"]).await;
    let err = s
        .docker_logs(logs_for("shop", Some("shop-nope-1")))
        .await
        .expect_err("no such container");
    assert!(matches!(err, RpcError::Validation { .. }), "{err}");
    let err = s
        .docker_logs(logs_for("elsewhere", None))
        .await
        .expect_err("no such stack");
    assert!(matches!(err, RpcError::Validation { .. }), "{err}");
    assert_eq!(reads_of(&w, "Logs"), 0, "docker was never asked");
}

#[tokio::test]
async fn form_value_never_reaches_docker() {
    let (s, w, _d) = shop_with(&["web"]).await;
    let id = format!("{:064x}", 1);
    for hostile in [
        "--help",
        "-f",
        "shop-web-1; id",
        &id,
        "../../etc",
        "shop-web-1\n",
    ] {
        let r = s.docker_logs(logs_for("shop", Some(hostile))).await;
        assert!(
            matches!(r, Err(RpcError::Validation { .. })),
            "{hostile:?}: {r:?}"
        );
    }
    assert_eq!(
        reads_of(&w, "Logs"),
        0,
        "no hostile value became an argument"
    );

    // A real name works, and what docker is given is the id the node found.
    set_logs(&w, 1, printed(&[(ts(1, 0), "hello")]));
    s.docker_logs(logs_for("shop", Some("shop-web-1")))
        .await
        .expect("real container");
    let reads = w.lock().expect("world").reads.clone();
    let logs: Vec<_> = reads.iter().filter(|r| r.starts_with("Logs")).collect();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].contains(&id), "{}", logs[0]);
    assert!(!logs[0].contains("shop-web-1"), "{}", logs[0]);
}

#[tokio::test]
async fn lines_are_capped() {
    let (s, w, _d) = shop_with(&["web"]).await;
    set_logs(&w, 1, printed(&[(ts(1, 0), "x")]));
    let mut req = logs_for("shop", Some("shop-web-1"));
    req.lines = 999_999;
    s.docker_logs(req).await.expect("logs");
    let reads = w.lock().expect("world").reads.clone();
    let last = reads
        .iter()
        .rev()
        .find(|r| r.starts_with("Logs"))
        .expect("read");
    assert!(
        last.contains(&format!("tail: {MAX_LOG_LINES}")),
        "asked docker for too much: {last}"
    );

    let mut req = logs_for("shop", Some("shop-web-1"));
    req.lines = 0;
    s.docker_logs(req).await.expect("logs");
    let reads = w.lock().expect("world").reads.clone();
    let last = reads
        .iter()
        .rev()
        .find(|r| r.starts_with("Logs"))
        .expect("read");
    assert!(last.contains("tail: 200"), "the default is 200: {last}");
}

/// Second `i` of the day as a docker timestamp.
fn tsi(i: u32) -> String {
    format!(
        "2024-05-01T{:02}:{:02}:{:02}.000000000Z",
        i / 3600,
        (i / 60) % 60,
        i % 60
    )
}

/// `n` log lines of about 1 KiB, numbered from `first`, each a second apart.
fn kib_lines(first: u32, n: u32, mark: &str) -> Vec<(String, String)> {
    let filler = "x".repeat(1000);
    (first..first + n)
        .map(|i| (tsi(i), format!("{mark}{i:05} {filler}")))
        .collect()
}

fn printed_owned(lines: &[(String, String)]) -> Vec<u8> {
    let refs: Vec<(String, &str)> = lines.iter().map(|(t, x)| (t.clone(), x.as_str())).collect();
    printed(&refs)
}

#[tokio::test]
async fn huge_output_is_truncated() {
    let (s, w, _d) = shop_with(&["web"]).await;
    // 5 MiB in 1 KiB lines.
    set_logs(&w, 1, printed_owned(&kib_lines(0, 5200, "n")));
    let mut req = logs_for("shop", Some("shop-web-1"));
    req.lines = 2000;
    let chunk = s.docker_logs(req).await.expect("logs");
    let size: usize = chunk
        .lines
        .iter()
        .map(|l| l.ts.len() + l.service.len() + l.text.len())
        .sum();
    assert!(size < MAX_LOG_BYTES, "{size} bytes");
    assert!(chunk.truncated);
    assert!(!chunk.lines.is_empty());
    assert!(chunk.lines.len() <= 2000);
    // What survives is the END of the log, the part that matters.
    let last = chunk.lines.last().expect("a line");
    assert!(last.text.starts_with("n05199 "), "{}", &last.text[..10]);
}

#[tokio::test]
async fn an_overflowing_tail_is_read_again_with_less_until_it_fits() {
    let (s, w, _d) = shop_with(&["web"]).await;
    set_logs(&w, 1, printed_owned(&kib_lines(0, 5200, "n")));
    let mut req = logs_for("shop", Some("shop-web-1"));
    req.lines = 2000;
    s.docker_logs(req).await.expect("logs");
    let reads = w.lock().expect("world").reads.clone();
    let tails: Vec<&str> = reads
        .iter()
        .filter(|r| r.starts_with("Logs"))
        .map(String::as_str)
        .collect();
    assert!(tails[0].contains("tail: 2000"), "{tails:?}");
    assert!(tails[1].contains("tail: 1000"), "{tails:?}");
    assert!(tails.len() <= 3, "{tails:?}");
    // Every read was allowed the whole cap (plus the byte that detects a cut).
    let limits = w.lock().expect("world").log_limits.clone();
    assert!(limits.iter().all(|l| *l == MAX_LOG_BYTES + 1), "{limits:?}");
}

#[tokio::test]
async fn a_noisy_container_does_not_push_out_a_quiet_one() {
    let (s, w, _d) = shop_with(&["noisy", "quiet"]).await;
    // The noisy one alone is five times the cap; the quiet one is about 600 KiB
    // and newer than all of it.
    set_logs(&w, 1, printed_owned(&kib_lines(0, 5000, "noisy")));
    set_logs(&w, 2, printed_owned(&kib_lines(5000, 600, "quiet")));
    let mut req = logs_for("shop", None);
    req.lines = 2000;
    let chunk = s.docker_logs(req).await.expect("stack");
    let texts: Vec<&str> = chunk.lines.iter().map(|l| l.text.as_str()).collect();
    assert!(
        texts.iter().any(|t| t.starts_with("quiet05599 ")),
        "the newest line of the quiet container"
    );
    assert!(
        texts.iter().filter(|t| t.starts_with("quiet")).count() >= 500,
        "most of the quiet container is there"
    );
    assert!(
        texts.iter().any(|t| t.starts_with("noisy04999 ")),
        "and the newest line of the noisy one, not its oldest"
    );
    assert!(!texts.iter().any(|t| t.starts_with("noisy00000 ")));
    assert!(chunk.truncated);
    let size: usize = chunk.lines.iter().map(|l| l.text.len() + l.ts.len()).sum();
    assert!(size < MAX_LOG_BYTES);
}

#[tokio::test]
async fn a_filter_finds_a_match_in_the_newest_lines_when_older_ones_overflow() {
    let (s, w, _d) = shop_with(&["web"]).await;
    let mut lines = kib_lines(0, 5200, "n");
    lines[5199].1.push_str(" needle");
    set_logs(&w, 1, printed_owned(&lines));
    let mut req = logs_for("shop", Some("shop-web-1"));
    req.filter = Some("NEEDLE".into());
    let chunk = s.docker_logs(req).await.expect("logs");
    assert_eq!(chunk.lines.len(), 1, "{}", chunk.lines.len());
    assert!(chunk.lines[0].text.starts_with("n05199 "));
    assert!(chunk.truncated, "older lines were left out");
}

#[tokio::test]
async fn gigantic_single_line_is_cut() {
    let (s, w, _d) = shop_with(&["web"]).await;
    // Two-byte characters, so a cut at the wrong byte would split one.
    let huge = "é".repeat(5 * 1024 * 1024 / 2);
    set_logs(&w, 1, printed(&[(ts(1, 0), huge.as_str())]));
    let chunk = s
        .docker_logs(logs_for("shop", Some("shop-web-1")))
        .await
        .expect("logs");
    assert_eq!(chunk.lines.len(), 1);
    let text = &chunk.lines[0].text;
    assert!(text.len() < MAX_LOG_BYTES, "{}", text.len());
    assert!(
        !text.is_empty() && text.chars().all(|c| c == 'é'),
        "cut on a boundary"
    );
    assert!(chunk.truncated);
    let reads = w.lock().expect("world").reads.clone();
    assert!(
        reads
            .iter()
            .rev()
            .find(|r| r.starts_with("Logs"))
            .expect("read")
            .contains("tail: 1,"),
        "a single line over the cap is read down to one line and cut there"
    );
}

#[test]
fn ansi_stripped() {
    assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
    assert_eq!(strip_ansi("\x1b[1;38;5;196mbold\x1b[m!"), "bold!");
    assert_eq!(strip_ansi("a\x1b]0;window title\x07b"), "ab");
    assert_eq!(
        strip_ansi("a\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\b"),
        "alinkb"
    );
    assert_eq!(strip_ansi("\x1b[2K\x1b[1Gdone"), "done");
    assert_eq!(strip_ansi("lone \x1b"), "lone ");
    assert_eq!(strip_ansi("cut \x1b[31"), "cut ");
    assert_eq!(strip_ansi("plain ünïcode"), "plain ünïcode");
}

#[tokio::test]
async fn ansi_and_control_characters_are_gone_from_what_is_served() {
    let (s, w, _d) = shop_with(&["web"]).await;
    let mut out = printed(&[(ts(1, 0), "\x1b[31mred\x1b[0m\x07 bell \u{202e}rtl")]);
    // Not UTF-8 at all, and a NUL.
    out.extend_from_slice(format!("{} bin ", ts(2, 0)).as_bytes());
    out.extend_from_slice(&[0xff, 0xfe, 0x00]);
    out.extend_from_slice(b" end\n");
    out.extend_from_slice(&[0xff, 0xfe, b'\n', 0x00, b'\n']);
    set_logs(&w, 1, out);
    let chunk = s
        .docker_logs(logs_for("shop", Some("shop-web-1")))
        .await
        .expect("never panics");
    assert_eq!(chunk.lines[0].text, "red bell rtl");
    assert!(
        chunk.lines[1].text.starts_with("bin "),
        "{:?}",
        chunk.lines[1]
    );
    assert!(chunk
        .lines
        .iter()
        .all(|l| !l.text.chars().any(|c| c.is_control())));
}

#[tokio::test]
async fn filter_is_case_insensitive() {
    let (s, w, _d) = shop_with(&["web"]).await;
    set_logs(
        &w,
        1,
        printed(&[
            (ts(1, 0), "ERROR boom"),
            (ts(2, 0), "info all fine"),
            (ts(3, 0), "an Error again"),
            (ts(4, 0), "\x1b[31mer\x1b[0mror coloured"),
            (ts(5, 0), "e.r not a pattern"),
        ]),
    );
    let ask = |f: &str| {
        let mut r = logs_for("shop", Some("shop-web-1"));
        r.filter = Some(f.into());
        r
    };
    let got = s.docker_logs(ask("error")).await.expect("logs");
    let texts: Vec<_> = got.lines.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(texts, ["ERROR boom", "an Error again", "error coloured"]);
    // A pattern is just characters.
    let got = s.docker_logs(ask("e.r")).await.expect("logs");
    assert_eq!(got.lines.len(), 1);
    assert_eq!(got.lines[0].text, "e.r not a pattern");
    assert!(s
        .docker_logs(ask(".*"))
        .await
        .expect("logs")
        .lines
        .is_empty());
    // And the filter is bounded.
    let err = s
        .docker_logs(ask(&"a".repeat(201)))
        .await
        .expect_err("long");
    assert!(matches!(err, RpcError::Validation { .. }));
    let err = s.docker_logs(ask("a\nb")).await.expect_err("control");
    assert!(matches!(err, RpcError::Validation { .. }));
}

#[test]
fn follow_does_not_repeat() {
    let a = line(ts(1, 0), "web", "a");
    let b = line(ts(2, 5), "web", "b");
    let c = line(ts(2, 5), "web", "c");
    let nanos = |l: &DockerLogLine| {
        chrono::DateTime::parse_from_rfc3339(&l.ts)
            .expect("ts")
            .timestamp_nanos_opt()
            .expect("nanos")
    };

    // Without a cursor, everything.
    assert_eq!(lines_after(vec![a.clone(), b.clone()], None).len(), 2);

    // At or before the cursor is dropped; a bare timestamp has seen no line
    // at that exact instant, so b and c are both still news.
    let at_b = LogCursor::parse(&nanos(&b).to_string()).expect("cursor");
    assert_eq!(
        lines_after(vec![a.clone(), b.clone(), c.clone()], Some(&at_b)),
        [b.clone(), c.clone()]
    );
    // Once b has been seen, only c is.
    let seen_b = LogCursor::parse(&format!(
        "{}:{:x}",
        nanos(&b),
        super::super::docker_logs::fingerprint(&b)
    ))
    .expect("cursor");
    assert_eq!(
        lines_after(vec![a, b, c.clone()], Some(&seen_b)),
        [c],
        "the line already seen at that instant is dropped, its neighbour is not"
    );
}

#[tokio::test]
async fn follow_polls_never_repeat_and_never_lose_a_line() {
    let (s, w, _d) = shop_with(&["web"]).await;
    let a = (ts(1, 0), "a");
    let b = (ts(2, 5), "b");
    let c = (ts(2, 5), "c same instant as b");
    let d = (ts(3, 0), "d");
    let texts = |ch: &hyperion_types::docker::DockerLogChunk| {
        ch.lines.iter().map(|l| l.text.clone()).collect::<Vec<_>>()
    };

    set_logs(&w, 1, printed(&[a.clone(), b.clone()]));
    let first = s
        .docker_logs(logs_for("shop", Some("shop-web-1")))
        .await
        .expect("first");
    assert_eq!(texts(&first), ["a", "b"]);
    let cur = first.cursor.clone().expect("a cursor");

    let poll = |cur: String| {
        let mut r = logs_for("shop", Some("shop-web-1"));
        r.since_cursor = Some(cur);
        r
    };

    // Docker re-sends from the whole second; the same lines are not repeated.
    let quiet = s.docker_logs(poll(cur.clone())).await.expect("quiet");
    assert!(quiet.lines.is_empty(), "{:?}", quiet.lines);
    assert_eq!(
        quiet.cursor.as_deref(),
        Some(cur.as_str()),
        "nothing new, same cursor"
    );
    let reads = w.lock().expect("world").reads.clone();
    let last = reads
        .iter()
        .rev()
        .find(|r| r.starts_with("Logs"))
        .expect("read");
    let secs = chrono::DateTime::parse_from_rfc3339(&b.0)
        .expect("ts")
        .timestamp();
    assert!(
        last.contains(&format!("since: Some({secs})")),
        "whole seconds: {last}"
    );

    // A line with the very same timestamp as the newest one arrives later.
    set_logs(&w, 1, printed(&[a.clone(), b.clone(), c.clone()]));
    let next = s
        .docker_logs(poll(cur.clone()))
        .await
        .expect("same instant");
    assert_eq!(
        texts(&next),
        ["c same instant as b"],
        "not lost, not repeated"
    );
    let cur2 = next.cursor.clone().expect("cursor");

    set_logs(
        &w,
        1,
        printed(&[a.clone(), b.clone(), c.clone(), d.clone()]),
    );
    let next = s.docker_logs(poll(cur2.clone())).await.expect("later");
    assert_eq!(texts(&next), ["d"]);
    let cur3 = next.cursor.expect("cursor");
    let none = s.docker_logs(poll(cur3.clone())).await.expect("none");
    assert!(none.lines.is_empty());

    // Two identical lines at one instant are two lines.
    let e = (ts(4, 0), "same");
    set_logs(&w, 1, printed(&[d.clone(), e.clone()]));
    let one = s.docker_logs(poll(cur3.clone())).await.expect("one");
    assert_eq!(texts(&one), ["same"]);
    set_logs(&w, 1, printed(&[d.clone(), e.clone(), e.clone()]));
    let two = s
        .docker_logs(poll(one.cursor.expect("cursor")))
        .await
        .expect("two");
    assert_eq!(texts(&two), ["same"], "the second identical line is new");
}

#[tokio::test]
async fn a_cursor_that_is_not_one_is_refused() {
    let (s, w, _d) = shop_with(&["web"]).await;
    for bad in ["x", "-5", "12:zz", "1:2.3.", &"1".repeat(3000), "1:1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1"] {
        let mut r = logs_for("shop", Some("shop-web-1"));
        r.since_cursor = Some(bad.to_string());
        let e = s.docker_logs(r).await.expect_err(bad);
        assert!(matches!(e, RpcError::Validation { .. }), "{bad}: {e}");
    }
    assert_eq!(reads_of(&w, "Logs"), 0);
}

#[tokio::test]
async fn stack_logs_merge_by_time() {
    let (s, w, _d) = shop_with(&["web", "worker"]).await;
    set_logs(
        &w,
        1,
        printed(&[(ts(1, 0), "web one"), (ts(4, 0), "web four")]),
    );
    set_logs(
        &w,
        2,
        printed(&[(ts(2, 0), "worker two"), (ts(3, 0), "worker three")]),
    );
    let chunk = s.docker_logs(logs_for("shop", None)).await.expect("stack");
    let got: Vec<(&str, &str)> = chunk
        .lines
        .iter()
        .map(|l| (l.service.as_str(), l.text.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("web", "web one"),
            ("worker", "worker two"),
            ("worker", "worker three"),
            ("web", "web four"),
        ]
    );
    assert_eq!(reads_of(&w, "Logs"), 2, "one docker logs per container");

    // The pure part.
    let merged = merge_by_ts(
        vec![
            vec![line(ts(1, 0), "a", "1"), line(ts(3, 0), "a", "3")],
            vec![line(ts(2, 0), "b", "2"), line(ts(4, 0), "b", "4")],
        ],
        3,
    );
    let order: Vec<_> = merged.iter().map(|l| l.text.as_str()).collect();
    assert_eq!(order, ["2", "3", "4"], "the newest three, oldest first");
}

#[tokio::test]
async fn stack_reads_each_get_the_whole_cap_and_ask_for_the_requested_tail() {
    let names: Vec<String> = (1..=20).map(|i| format!("s{i:02}")).collect();
    let cts: Vec<Ct> = names
        .iter()
        .enumerate()
        .map(|(i, n)| ct(i as u32 + 1, "shop", Box::leak(n.clone().into_boxed_str())))
        .collect();
    let w = world(cts);
    let (s, _d) = worker_with(world_mock(&w)).await;
    tick_at(&s, T0).await;
    for i in 1..=20u32 {
        set_logs(&w, i, printed(&[(ts(i, 0), "hi")]));
    }

    let chunk = s.docker_logs(logs_for("shop", None)).await.expect("stack");
    assert_eq!(chunk.lines.len(), 20);
    assert_eq!(reads_of(&w, "Logs"), 20);
    // Each read may use the cap (what is kept is fitted across the merge).
    let limits = w.lock().expect("world").log_limits.clone();
    assert_eq!(limits.len(), 20);
    assert!(limits.iter().all(|l| *l == MAX_LOG_BYTES + 1), "{limits:?}");
    // And each was asked for the tail the request named.
    let reads = w.lock().expect("world").reads.clone();
    assert!(reads
        .iter()
        .filter(|r| r.starts_with("Logs"))
        .all(|r| r.contains("tail: 200")));
}

#[tokio::test]
async fn a_stack_with_one_unreadable_container_still_shows_the_rest() {
    let (s, w, _d) = shop_with(&["web", "worker"]).await;
    set_logs(&w, 1, printed(&[(ts(1, 0), "web line")]));
    w.lock().expect("world").logs_fail = vec![2];
    let chunk = s
        .docker_logs(logs_for("shop", None))
        .await
        .expect("partial");
    assert_eq!(chunk.lines.len(), 1);
    assert_eq!(chunk.unreadable, 1, "and the page can say so");

    w.lock().expect("world").logs_fail = vec![1, 2];
    let err = s
        .docker_logs(logs_for("shop", None))
        .await
        .expect_err("all unreadable");
    assert!(
        !err.to_string().contains("secret-stderr"),
        "docker's words stay out: {err}"
    );
}

#[tokio::test]
async fn docker_down_is_an_error_not_an_empty_log() {
    let (s, w, _d) = shop_with(&["web"]).await;
    w.lock().expect("world").logs_err = Some(DockerError::NotResponding);
    let err = s
        .docker_logs(logs_for("shop", Some("shop-web-1")))
        .await
        .expect_err("down");
    assert!(err.to_string().contains("not responding"), "{err}");
}

#[tokio::test]
async fn audit_only_when_actor_given() {
    let (s, w, _d) = shop_with(&["web"]).await;
    set_logs(&w, 1, printed(&[(ts(1, 0), "secret-looking line")]));
    let rows = |s: &HostingService<MockAdapterPort>| {
        let pool = s.pool.clone();
        async move {
            sqlx::query_as::<_, (String, String, Option<String>, String, String)>(
                "SELECT actor_label, action, target, payload_json, result FROM audit_log \
                 WHERE action = 'docker.logs.read'",
            )
            .fetch_all(&pool)
            .await
            .expect("audit")
        }
    };

    let mut poll = logs_for("shop", Some("shop-web-1"));
    poll.filter = Some("needle".into());
    s.docker_logs(poll).await.expect("poll");
    assert!(rows(&s).await.is_empty(), "no actor, no entry");

    let mut open = logs_for("shop", Some("shop-web-1"));
    open.audit_actor = Some("kevin".into());
    open.filter = Some("needle".into());
    s.docker_logs(open).await.expect("open");
    let got = rows(&s).await;
    assert_eq!(got.len(), 1, "{got:?}");
    let (actor, _, target, payload, result) = &got[0];
    assert_eq!(actor, "kevin");
    assert_eq!(target.as_deref(), Some("shop/shop-web-1"));
    assert_eq!(result, "ok");
    assert!(
        !payload.contains("needle"),
        "the filter is not recorded: {payload}"
    );
    assert!(!payload.contains("secret-looking"), "{payload}");

    let mut whole = logs_for("shop", None);
    whole.audit_actor = Some("kevin".into());
    s.docker_logs(whole).await.expect("stack");
    let got = rows(&s).await;
    assert_eq!(got.len(), 2);
    assert_eq!(got[1].2.as_deref(), Some("shop"));

    // A refused request leaves nothing behind.
    let mut bad = logs_for("shop", Some("nope"));
    bad.audit_actor = Some("kevin".into());
    s.docker_logs(bad).await.expect_err("refused");
    assert_eq!(rows(&s).await.len(), 2);
}

#[tokio::test]
async fn log_text_stays_out_of_alerts() {
    let (s, w, _d) = shop_with(&["web"]).await;
    set_logs(&w, 1, printed(&[(ts(1, 0), "needle-in-the-log")]));
    s.docker_logs(logs_for("shop", None)).await.expect("logs");
    let sent = alerts(&s).await;
    assert!(
        sent.iter()
            .all(|a| !format!("{a:?}").contains("needle-in-the-log")),
        "{sent:?}"
    );
}

#[tokio::test]
async fn logs_need_the_module_on() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let err = s
        .docker_logs(logs_for("shop", None))
        .await
        .expect_err("module off runs no docker");
    assert!(matches!(err, RpcError::Validation { .. }), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_map_runs_at_most_the_limit_at_once_and_keeps_order() {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (r, p) = (running.clone(), peak.clone());
    let out = super::super::docker_logs::bounded_map((0..30u32).collect(), 8, move |i| {
        let (r, p) = (r.clone(), p.clone());
        async move {
            let now = r.fetch_add(1, SeqCst) + 1;
            p.fetch_max(now, SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
            r.fetch_sub(1, SeqCst);
            i * 2
        }
    })
    .await;
    assert_eq!(out, (0..30u32).map(|i| Some(i * 2)).collect::<Vec<_>>());
    assert_eq!(running.load(SeqCst), 0);
    let peak = peak.load(SeqCst);
    assert!(peak <= 8, "{peak} at once");
    assert!(peak >= 4, "and they do overlap ({peak})");
}

#[test]
fn a_last_line_without_a_newline_is_kept_unless_the_run_was_cut() {
    use super::super::docker_logs::parse_log_bytes;
    let whole = format!("{} one\n{} two", ts(1, 0), ts(2, 0));
    let got = parse_log_bytes(whole.as_bytes(), "web", false);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[1].text, "two");
    let cut = parse_log_bytes(whole.as_bytes(), "web", true);
    assert_eq!(
        cut.len(),
        1,
        "the partial line is not shown as if it were whole"
    );
    // Text with no timestamp rides on the line before it.
    let odd = format!("{} one\nno stamp\n", ts(1, 0));
    let got = parse_log_bytes(odd.as_bytes(), "web", false);
    assert_eq!(
        (got[1].ts.as_str(), got[1].text.as_str()),
        (ts(1, 0).as_str(), "no stamp")
    );
}

// ---------------------------------------------------------------------------
// Outbound alerts and silent nodes (the master sends; a worker only parks).
// ---------------------------------------------------------------------------

use hyperion_types::NotificationOutboxItem;

/// A master (no node state file) with Slack and one alert address set, whose
/// every send fails fast: loopback is refused as a webhook and the relay is
/// not a mailbox. What was ATTEMPTED is what the tests count.
async fn outbound_master(admins: &[&str]) -> HostingService<MockAdapterPort> {
    use hyperion_state::web_users::WebRole;
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks())
        .with_email(Some(refusing_relay()), Some("ops@example.cz".into()))
        .with_slack_webhook(Some("https://127.0.0.1/hook".into()));
    for a in admins {
        seed_web_user(&s, a, WebRole::Admin).await;
    }
    s
}

/// Slack posts attempted for Docker alerts.
async fn slack_sends(s: &HostingService<MockAdapterPort>) -> i64 {
    let (n,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE action = 'notify.docker.slack'")
            .fetch_one(&s.pool)
            .await
            .expect("count");
    n
}

/// (subject, body) of every Docker mail attempted, oldest first.
async fn mail_sends(s: &HostingService<MockAdapterPort>) -> Vec<(String, String)> {
    let mut rows = hyperion_state::email_log::list(&s.pool, None, 100)
        .await
        .expect("email log");
    rows.reverse();
    rows.into_iter()
        .filter(|r| r.kind == "docker")
        .map(|r| (r.subject, r.body_preview))
        .collect()
}

fn outbox_item(id: i64, kind: &str) -> NotificationOutboxItem {
    NotificationOutboxItem {
        id,
        severity: "error".into(),
        title: "Docker project has a problem".into(),
        body: "x: web: exited (1)".into(),
        href: "/docker".into(),
        kind: kind.into(),
        created_at: T0,
    }
}

#[tokio::test]
async fn ingest_sends_docker_alert_outbound() {
    let s = outbound_master(&["boss"]).await;
    let n = s
        .notifications_ingest("node_a", vec![outbox_item(1, "docker.project:x")])
        .await
        .expect("ingest");
    assert_eq!(n, 1);
    assert_eq!(slack_sends(&s).await, 1, "one Slack post");
    let mail = mail_sends(&s).await;
    assert_eq!(mail.len(), 1, "one mail to the one address: {mail:?}");
    assert_eq!(mail[0].0, "Docker project has a problem");
    assert!(mail[0].1.contains("x: web: exited (1)"), "{mail:?}");
}

#[tokio::test]
async fn reingesting_a_batch_sends_nothing() {
    let s = outbound_master(&["boss"]).await;
    let batch = vec![
        outbox_item(1, "docker.project:x"),
        outbox_item(2, "docker.daemon"),
        outbox_item(3, "docker.node:node_b"),
    ];
    assert_eq!(
        s.notifications_ingest("node_a", batch.clone())
            .await
            .expect("first"),
        3
    );
    assert_eq!(slack_sends(&s).await, 3);
    assert_eq!(mail_sends(&s).await.len(), 3);

    assert_eq!(
        s.notifications_ingest("node_a", batch)
            .await
            .expect("again"),
        0,
        "nothing new was written"
    );
    assert_eq!(slack_sends(&s).await, 3, "so nothing new is sent");
    assert_eq!(mail_sends(&s).await.len(), 3);
}

#[tokio::test]
async fn several_admins_still_mean_one_send_per_alert() {
    let s = outbound_master(&["a", "b", "c"]).await;
    // A card kind (folded per admin) and a plain one (a row per admin).
    let batch = vec![
        outbox_item(1, "docker.project:x"),
        outbox_item(2, "docker.node:node_b"),
    ];
    let n = s
        .notifications_ingest("node_a", batch.clone())
        .await
        .expect("ingest");
    assert_eq!(n, 6, "every admin gets both cards");
    assert_eq!(slack_sends(&s).await, 2, "but each alert leaves once");
    assert_eq!(mail_sends(&s).await.len(), 2);

    s.notifications_ingest("node_a", batch)
        .await
        .expect("again");
    assert_eq!(slack_sends(&s).await, 2);
    assert_eq!(mail_sends(&s).await.len(), 2);

    // A later alert of the same kind is news again.
    s.notifications_ingest("node_a", vec![outbox_item(3, "docker.project:x")])
        .await
        .expect("next");
    assert_eq!(slack_sends(&s).await, 3);
}

#[tokio::test]
async fn other_kinds_stay_bell_only() {
    let s = outbound_master(&["boss"]).await;
    let n = s
        .notifications_ingest(
            "node_a",
            vec![
                outbox_item(1, "monitor.down:x"),
                outbox_item(2, "dockerish"),
                outbox_item(3, "php_workers:a.cz"),
            ],
        )
        .await
        .expect("ingest");
    assert_eq!(n, 3, "they reach the bell");
    assert_eq!(slack_sends(&s).await, 0);
    assert!(mail_sends(&s).await.is_empty());
}

#[tokio::test]
async fn ingest_with_no_channel_set_just_fills_the_bell() {
    use hyperion_state::web_users::WebRole;
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    seed_web_user(&s, "boss", WebRole::Admin).await;
    let n = s
        .notifications_ingest("node_a", vec![outbox_item(1, "docker.project:x")])
        .await
        .expect("a master with nowhere to send still ingests");
    assert_eq!(n, 1);
    assert_eq!(slack_sends(&s).await, 0);
    assert!(mail_sends(&s).await.is_empty());
}

#[tokio::test]
async fn master_own_alert_goes_outbound_once() {
    let s = outbound_master(&["a", "b"]).await;
    s.notify_admins(
        "error",
        "Docker project has a problem",
        "x: web: exited (1)",
        "/docker",
        "docker.project:x",
    )
    .await;
    assert_eq!(slack_sends(&s).await, 1, "one send, not one per admin");
    assert_eq!(mail_sends(&s).await.len(), 1);

    s.notify_admins("error", "Disk", "full", "/", "system.rofs")
        .await;
    assert_eq!(slack_sends(&s).await, 1, "a non-Docker kind stays home");
}

#[tokio::test]
async fn worker_parks_and_does_not_send() {
    let dir = tempfile::tempdir().expect("dir");
    let state = dir.path().join("node-id.json");
    std::fs::write(&state, b"{}").expect("state file");
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks())
        .with_node_state_file(state)
        .with_email(Some(refusing_relay()), Some("ops@example.cz".into()))
        .with_slack_webhook(Some("https://127.0.0.1/hook".into()));

    s.notify_admins("error", "t", "b", "/docker", "docker.project:x")
        .await;
    s.docker_outbound("t", "b", "docker.project:x").await;

    assert_eq!(alerts(&s).await.len(), 1, "parked for the master");
    assert_eq!(slack_sends(&s).await, 0);
    assert!(mail_sends(&s).await.is_empty());
}

#[tokio::test]
async fn outbound_body_has_no_log_lines() {
    let w = world(vec![ct(1, "shop", "web")]);
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), world_mock(&w))
        .with_email(Some(refusing_relay()), Some("ops@example.cz".into()));
    hyperion_state::docker::set_node_installed(&pool, false, 1)
        .await
        .expect("module on");
    set_logs(&w, 1, printed(&[(ts(1, 0), "needle-in-the-log")]));

    tick_at(&s, T0).await;
    set(&w, vec![ct(1, "shop", "web").exited(1)]);
    tick_through(&s, T0 + 30, T0 + 400).await;
    // Reading the log must not feed an alert either.
    s.docker_logs(logs_for("shop", None)).await.expect("logs");

    let mail = mail_sends(&s).await;
    assert_eq!(mail.len(), 1, "{mail:?}");
    assert!(mail[0].1.contains("web"), "the summary is there: {mail:?}");
    assert!(
        !format!("{mail:?}").contains("needle-in-the-log"),
        "{mail:?}"
    );
    assert_eq!(
        docker_outbound_text("Title", "Body"),
        "*Title*\nBody",
        "Slack carries the title and the body, nothing else"
    );
    assert_eq!(docker_outbound_text("Title", ""), "Title");
}

#[tokio::test]
async fn a_flood_is_capped_then_summarised_and_the_graver_news_goes_first() {
    let s = outbound_master(&["boss"]).await;
    // 28 project alerts first, then the daemon and a node: the order they
    // arrive in must not decide which of them leave.
    let mut batch: Vec<_> = (1..=28)
        .map(|i| outbox_item(i, &format!("docker.project:p{i}")))
        .collect();
    batch.push(outbox_item(29, "docker.daemon"));
    batch.push(outbox_item(30, "docker.node:node_b"));
    for it in &mut batch {
        it.title = it.kind.clone();
    }
    let n = s
        .notifications_ingest("node_a", batch)
        .await
        .expect("ingest");
    assert_eq!(n, 30, "every alert reaches the bell");
    assert_eq!(
        slack_sends(&s).await,
        OUTBOUND_PER_INGEST as i64 + 1,
        "the cap, plus one summary"
    );
    let mail = mail_sends(&s).await;
    assert_eq!(mail.len(), OUTBOUND_PER_INGEST + 1, "{mail:?}");
    assert_eq!(mail[0].0, "docker.daemon");
    assert_eq!(mail[1].0, "docker.node:node_b");
    assert!(mail[2].0.starts_with("docker.project:p"), "{mail:?}");
    let (subject, body) = &mail[OUTBOUND_PER_INGEST];
    assert_eq!(subject, "More Docker alerts");
    assert!(body.contains("20 more"), "30 - 10 = 20 unsent: {body}");
    assert!(body.contains("/docker"), "and where to read them: {body}");
}

#[tokio::test]
async fn an_item_half_written_when_the_database_fails_is_still_sent() {
    let s = outbound_master(&["a", "b"]).await;
    let mut ids: Vec<i64> = hyperion_state::web_users::list(&s.pool)
        .await
        .expect("users")
        .into_iter()
        .map(|u| u.id)
        .collect();
    ids.sort_unstable();
    // The first admin's row goes in; the second admin's write fails.
    sqlx::query(&format!(
        "CREATE TRIGGER fail_second BEFORE INSERT ON notifications \
         WHEN NEW.user_id = {} BEGIN SELECT RAISE(ABORT, 'boom'); END",
        ids[1]
    ))
    .execute(&s.pool)
    .await
    .expect("trigger");

    s.notifications_ingest("node_a", vec![outbox_item(1, "docker.node:node_b")])
        .await
        .expect_err("the second write fails");
    assert_eq!(
        slack_sends(&s).await,
        1,
        "the first row is written, so on the next read it would be 'seen'"
    );
    assert_eq!(mail_sends(&s).await.len(), 1);

    // The retry finds the first admin's row there, writes the second's, and
    // must not send the item a second time.
    sqlx::query("DROP TRIGGER fail_second")
        .execute(&s.pool)
        .await
        .expect("drop trigger");
    let n = s
        .notifications_ingest("node_a", vec![outbox_item(1, "docker.node:node_b")])
        .await
        .expect("retry");
    assert_eq!(n, 1, "only the second admin's row was missing");
    assert_eq!(slack_sends(&s).await, 1, "still one Slack post");
    assert_eq!(mail_sends(&s).await.len(), 1, "still one mail");
}

#[tokio::test]
async fn a_failed_first_write_sends_nothing_and_the_retry_sends_once() {
    let s = outbound_master(&["a", "b"]).await;
    let mut ids: Vec<i64> = hyperion_state::web_users::list(&s.pool)
        .await
        .expect("users")
        .into_iter()
        .map(|u| u.id)
        .collect();
    ids.sort_unstable();
    sqlx::query(&format!(
        "CREATE TRIGGER fail_first BEFORE INSERT ON notifications \
         WHEN NEW.user_id = {} BEGIN SELECT RAISE(ABORT, 'boom'); END",
        ids[0]
    ))
    .execute(&s.pool)
    .await
    .expect("trigger");
    let batch = vec![outbox_item(1, "docker.node:node_b")];
    s.notifications_ingest("node_a", batch.clone())
        .await
        .expect_err("the first write fails");
    assert_eq!(slack_sends(&s).await, 0);
    assert!(mail_sends(&s).await.is_empty());

    sqlx::query("DROP TRIGGER fail_first")
        .execute(&s.pool)
        .await
        .expect("drop trigger");
    s.notifications_ingest("node_a", batch)
        .await
        .expect("retry");
    assert_eq!(slack_sends(&s).await, 1);
    assert_eq!(mail_sends(&s).await.len(), 1);
}

#[test]
fn only_docker_kinds_go_outbound() {
    assert!(is_outbound_docker_kind("docker.project:x"));
    assert!(is_outbound_docker_kind("docker.daemon"));
    assert!(is_outbound_docker_kind("docker.node:n"));
    assert!(!is_outbound_docker_kind("docker"));
    assert!(!is_outbound_docker_kind("dockerish"));
    assert!(!is_outbound_docker_kind("monitor.down:x"));
    assert!(!is_outbound_docker_kind(""));
}

/// A registered node `node_a` that the `nodes` table knows as "Frankfurt".
async fn master_with_labelled_node() -> HostingService<MockAdapterPort> {
    let s = outbound_master(&["boss"]).await;
    hyperion_state::nodes::insert(
        &s.pool,
        &hyperion_state::nodes::NewNode {
            node_id: "node_a".into(),
            label: "Frankfurt".into(),
            master_url: None,
            agent_version: "t".into(),
            public_ip: None,
            enrolled_via_hash: "h".into(),
            secret_hash: "s".into(),
        },
        1,
    )
    .await
    .expect("node row");
    s.docker_node_register("node_a", true).await.expect("reg");
    s
}

#[tokio::test]
async fn node_silent_alerts_once_and_recovers() {
    let s = master_with_labelled_node().await;

    assert!(s.docker_node_silent("node_a", true).await.expect("down"));
    assert!(
        !s.docker_node_silent("node_a", true).await.expect("again"),
        "already silent: no transition"
    );
    let mail = mail_sends(&s).await;
    assert_eq!(mail.len(), 1, "one Down: {mail:?}");
    assert_eq!(mail[0].0, "Docker node has gone silent");
    assert!(
        mail[0].1.contains("Frankfurt"),
        "the label, not the id: {mail:?}"
    );
    assert_eq!(slack_sends(&s).await, 1);

    assert!(s.docker_node_silent("node_a", false).await.expect("up"));
    assert!(
        !s.docker_node_silent("node_a", false).await.expect("again"),
        "already back"
    );
    let mail = mail_sends(&s).await;
    assert_eq!(mail.len(), 2, "one Up: {mail:?}");
    assert_eq!(mail[1].0, "Docker node answers again");
    assert_eq!(slack_sends(&s).await, 2);

    // Both land on the bell under the node's kind, on one card.
    let me = hyperion_state::web_users::list(&s.pool)
        .await
        .expect("users")[0]
        .id;
    assert_eq!(manual_kinds(&s, me).await, ["docker.node:node_a"]);
}

#[tokio::test]
async fn a_node_the_master_never_registered_is_not_alerted_about() {
    let s = outbound_master(&["boss"]).await;
    assert!(!s.docker_node_silent("ghost", true).await.expect("ok"));
    assert!(!s.docker_node_silent("local", true).await.expect("ok"));
    assert!(mail_sends(&s).await.is_empty());
    assert_eq!(slack_sends(&s).await, 0);
}

#[tokio::test]
async fn an_unlabelled_node_is_named_by_its_id() {
    let s = outbound_master(&["boss"]).await;
    s.docker_node_register("node_z", true).await.expect("reg");
    assert!(s.docker_node_silent("node_z", true).await.expect("down"));
    assert!(mail_sends(&s).await[0].1.contains("node_z"));
}

#[tokio::test]
async fn forgetting_a_silent_node_takes_its_open_alert_with_it() {
    let s = master_with_labelled_node().await;
    assert!(s.docker_node_silent("node_a", true).await.expect("down"));
    let list = s.docker_node_list().await.expect("list");
    assert!(list.nodes[0].silent, "the list says so for the watcher");

    s.docker_node_register("node_a", false).await.expect("off");
    s.docker_node_register("node_a", true).await.expect("on");
    let list = s.docker_node_list().await.expect("list");
    assert!(!list.nodes[0].silent, "a fresh row starts quiet");
    assert!(
        !s.docker_node_silent("node_a", false).await.expect("up"),
        "so there is no recovery to announce"
    );
    assert_eq!(mail_sends(&s).await.len(), 1, "only the Down was sent");
}

#[tokio::test]
async fn a_worker_cannot_flag_nodes_silent() {
    let (s, _d) = worker_with(happy_mocks()).await;
    let err = s
        .docker_node_silent("node_a", true)
        .await
        .expect_err("master only");
    assert!(matches!(err, RpcError::Validation { .. }), "{err}");
}
