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
    a.expect_docker_read().returning(move |cmd, _| {
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
