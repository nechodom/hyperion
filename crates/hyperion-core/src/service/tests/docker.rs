//! Tests for `service::docker`: the module's install state.

use super::*;
use crate::service::docker_updates::image_state;
use hyperion_adapters::docker::{DockerCmd, DockerError, LocalImage};
use hyperion_adapters::docker_registry::RemoteDigestError;
use hyperion_state::docker::ImageCheckRow;
use hyperion_types::docker::ImageUpdateState;

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

/// A Docker whose `version` output cannot be read, or whose CLI does not
/// know the template, is called too old, not an internal error.
#[tokio::test]
async fn install_on_a_docker_too_old_to_read_says_so() {
    for answer in [
        Ok(b"Client: Docker Engine 1.12\n".to_vec()),
        Err(DockerError::Parse("expected value".into())),
        Err(DockerError::Failed(
            "Template parsing error: template: :1: function \"json\" not defined".into(),
        )),
        Err(DockerError::Failed("unknown flag: --format".into())),
    ] {
        let pool = open_memory().await.expect("open");
        let mut a = happy_mocks();
        a.expect_docker_read().returning(move |_, _| answer.clone());
        let s = svc(pool, a);
        let err = s.docker_node_install().await.expect_err("too old");
        let text = err.to_string();
        assert!(text.contains("too old"), "{text}");
        assert!(text.contains("Update Docker"), "{text}");
        assert!(!s.docker_module_enabled().await);
    }
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
    image: String,
    image_id: String,
    /// `State.StartedAt`, RFC 3339; empty for "never started".
    started: &'static str,
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
    fn on_image(self, image: &str, image_id: &str) -> Self {
        Self {
            image: image.into(),
            image_id: image_id.into(),
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
        image: "img".into(),
        image_id: format!("sha256:{n:064x}"),
        started: "",
    }
}

#[derive(Default)]
struct World {
    cts: Vec<Ct>,
    ps_err: Option<DockerError>,
    /// The node's `docker logs` limit, when a test wants every read checked
    /// against it, and how many reads ran without holding one of its permits.
    gate_probe: Option<Arc<tokio::sync::Semaphore>>,
    logs_without_permit: usize,
    /// Held in `inspect` until the test lets it go, to stage a removal in the
    /// middle of a slow read.
    inspect_gate: Option<Gate>,
    /// `docker inspect` as the real adapter hands it back when docker
    /// itself fails: it exits 1 having printed `[]`, which the adapter
    /// returns as an answer.
    inspect_blank: bool,
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
    /// What `docker image inspect <ref>` finds locally: the image id and its
    /// repo digests. A reference that is not here is not on the node.
    locals: std::collections::HashMap<String, (String, Vec<String>)>,
    /// `Identity` of a local image, as Docker 29 prints it.
    identities: std::collections::HashMap<String, serde_json::Value>,
    /// What the registry answers for a reference.
    remote: std::collections::HashMap<String, Result<String, RemoteDigestError>>,
    /// The references the registry was asked about, in order.
    lookups: Vec<String>,
}

/// The tick says it is inside `inspect` on `entered`, and stays there until
/// `release` is sent to.
#[derive(Clone)]
struct Gate {
    entered: std::sync::mpsc::Sender<()>,
    release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
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
    if !c.started.is_empty() {
        state["StartedAt"] = c.started.into();
    }
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
        "Image": c.image_id,
        "Config": {"Image": c.image, "Labels": labels, "Env": ["SECRET_VALUE=do-not-leak-7f3a"]},
    })
}

/// A daemon that answers from `w` and records what it was asked.
fn world_mock(world: &Shared) -> MockAdapterPort {
    let w = world.clone();
    let mut a = happy_mocks();
    a.expect_docker_read().returning(move |cmd, max| {
        if matches!(cmd, DockerCmd::Inspect(_)) {
            let gate = w.lock().expect("world").inspect_gate.clone();
            if let Some(g) = gate {
                let _ = g.entered.send(());
                // `block_in_place`, so the worker's queued tasks (the pool
                // returning its connection among them) move to another
                // worker instead of starving behind this wait.
                tokio::task::block_in_place(|| {
                    let _ = g.release.lock().expect("gate").recv();
                });
            }
        }
        if matches!(cmd, DockerCmd::Logs { .. }) {
            let mut w = w.lock().expect("world");
            // The caller of a read holds a permit while it runs, so a gate
            // with one permit has none left to give.
            if w.gate_probe
                .as_ref()
                .is_some_and(|g| g.available_permits() != 0)
            {
                w.logs_without_permit += 1;
            }
        }
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
                if w.inspect_blank {
                    return Ok(b"[]\n".to_vec());
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
            DockerCmd::ImageInspect(r) => match w.locals.get(r.as_str()) {
                Some((id, digests)) => Ok(serde_json::to_vec(&serde_json::json!([{
                    "Id": id,
                    "RepoTags": [r.as_str()],
                    "RepoDigests": digests,
                    "Identity": w.identities.get(r.as_str()),
                    "Config": {
                        "Env": ["SECRET_VALUE=do-not-leak-7f3a"],
                        "Labels": {"secret.label": "do-not-leak-7f3a"},
                    },
                }]))
                .expect("json")),
                // What docker prints for an image it does not have.
                None => Ok(b"[]\n".to_vec()),
            },
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
    let w = world.clone();
    a.expect_docker_remote_digest().returning(move |image| {
        let mut w = w.lock().expect("world");
        w.lookups.push(image.as_str().to_string());
        w.remote
            .get(image.as_str())
            .cloned()
            .unwrap_or_else(|| Err(RemoteDigestError::Unavailable("no route".into())))
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

/// Log lines written while a test runs, to read back.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

/// A database that cannot be read reads as "off", and says so in the log.
#[tokio::test]
async fn an_unreadable_module_state_reads_as_off_with_a_warning() {
    let log = LogBuf::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish(),
    );
    let pool = open_memory().await.expect("open");
    hyperion_state::docker::set_node_installed(&pool, false, 1)
        .await
        .expect("on");
    let s = svc(pool.clone(), happy_mocks());
    assert!(s.docker_module_enabled().await);
    assert!(log.0.lock().expect("log").is_empty(), "nothing to say yet");

    pool.close().await;
    assert!(!s.docker_module_enabled().await);
    let said = String::from_utf8_lossy(&log.0.lock().expect("log")).into_owned();
    assert!(said.contains("WARN"), "{said}");
    assert!(said.contains("docker module state unreadable"), "{said}");
    assert_eq!(said.lines().count(), 1, "one line: {said}");
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
    w.lock().expect("world").inspect_blank = true;
    tick_through(&s, T0 + 30, T0 + 400).await;

    let sent = alerts(&s).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, "docker.daemon");
    let row = hyperion_state::docker::get_project(&s.pool, "shop")
        .await
        .expect("row")
        .expect("known");
    assert_eq!((row.gone_since, row.problem_since), (0, 0));
    // The last good picture stays on the page, marked as not current.
    let st = s.docker_overview().await.expect("overview");
    assert!(!st.daemon_ok);
    assert_eq!(st.projects.len(), 1, "the stack is still listed");
    assert_eq!(st.projects[0].containers.len(), 1);
}

/// A tick whose reads are overtaken by a removal of the module writes
/// nothing back: no project rows, no snapshot, no alert.
async fn tick_overtaken_by_removal(blank_inspect: bool) {
    let w = world(vec![ct(1, "shop", "web")]);
    let (entered, entered_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    {
        let mut w = w.lock().expect("world");
        w.inspect_gate = Some(Gate {
            entered,
            release: Arc::new(Mutex::new(release_rx)),
        });
        w.inspect_blank = blank_inspect;
    }
    let (s, _dir) = worker_with(world_mock(&w)).await;
    let s = Arc::new(s);
    let ticking = {
        let s = s.clone();
        tokio::spawn(async move { s.docker_tick_at(T0).await })
    };
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .expect("join")
        .expect("the tick reached inspect");
    s.docker_node_remove().await.expect("removed meanwhile");
    release.send(()).expect("let it go");
    ticking.await.expect("join").expect("tick");

    let rows = hyperion_state::docker::list_projects(&s.pool)
        .await
        .expect("rows");
    assert!(rows.is_empty(), "nothing written back: {rows:?}");
    assert!(s.docker_snapshot.read().await.is_none());
    assert!(!s.docker_module_enabled().await);
    assert!(alerts(&s).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_during_a_slow_tick_is_not_rewritten() {
    tick_overtaken_by_removal(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_during_a_failing_tick_is_not_rewritten_either() {
    tick_overtaken_by_removal(true).await;
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

/// `--log-driver none`: reloading the page will never help, so the answer
/// must not suggest it.
#[tokio::test]
async fn a_log_driver_that_cannot_be_read_says_so() {
    let (s, w, _d) = shop_with(&["web"]).await;
    w.lock().expect("world").logs_err = Some(DockerError::Failed(
        "Error response from daemon: configured logging driver does not support reading".into(),
    ));
    let err = s
        .docker_logs(logs_for("shop", Some("shop-web-1")))
        .await
        .expect_err("no log to read");
    let text = err.to_string();
    assert!(text.contains("logging driver"), "{text}");
    assert!(!text.contains("reload"), "{text}");
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

/// Two people reading whole stacks at the same moment still run no more
/// `docker logs` than the node's limit allows: the limit is the node's, not
/// each request's. With one permit, every read of every request must hold it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_stack_reads_share_one_limit() {
    let services: Vec<&'static str> = vec!["a", "b", "c", "d", "e", "f"];
    let (mut s, w, _d) = shop_with(&services).await;
    let gate = Arc::new(tokio::sync::Semaphore::new(1));
    s.docker_log_gate = gate.clone();
    {
        let mut w = w.lock().expect("world");
        w.gate_probe = Some(gate.clone());
        for n in 1..=6u32 {
            w.logs.insert(n, printed(&[(ts(n, 0), "x")]));
        }
    }
    let s = Arc::new(s);
    let readers: Vec<_> = (0..3)
        .map(|_| {
            let s = s.clone();
            tokio::spawn(async move { s.docker_logs(logs_for("shop", None)).await })
        })
        .collect();
    for r in readers {
        let chunk = r.await.expect("join").expect("logs");
        assert_eq!(chunk.lines.len(), 6, "every read got its lines");
    }
    let reads = reads_of(&w, "Logs");
    let unheld = w.lock().expect("world").logs_without_permit;
    assert_eq!(reads, 18, "3 requests of 6 containers");
    assert_eq!(unheld, 0, "a docker logs ran without the node's permit");
    assert_eq!(gate.available_permits(), 1, "every permit came back");
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
    assert_eq!(mail[0].0, "Docker project has a problem (node_a)");
    assert!(mail[0].1.contains("x: web: exited (1)"), "{mail:?}");
    assert!(mail[0].1.contains("node_a"), "the body names the node too");
}

/// A master whose agent.toml gives the panel address `panel.example`.
async fn panel_master(admins: &[&str]) -> (HostingService<MockAdapterPort>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("dir");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(&cfg, b"[cluster]\npanel_hostname = \"panel.example\"\n").expect("write");
    let s = outbound_master(admins).await.with_agent_config_path(cfg);
    (s, dir)
}

#[tokio::test]
async fn outbound_text_names_the_node_and_links_the_panel() {
    let (s, _dir) = panel_master(&["boss"]).await;
    hyperion_state::nodes::insert(
        &s.pool,
        &hyperion_state::nodes::NewNode {
            node_id: "node_a".into(),
            label: "Tes One".into(),
            master_url: None,
            agent_version: "t".into(),
            public_ip: None,
            enrolled_via_hash: "h".into(),
            secret_hash: "s".into(),
        },
        1,
    )
    .await
    .expect("node");
    s.notifications_ingest("node_a", vec![outbox_item(1, "docker.project:x")])
        .await
        .expect("ingest");
    let mail = mail_sends(&s).await;
    assert_eq!(mail.len(), 1, "{mail:?}");
    assert_eq!(mail[0].0, "Docker project has a problem (Tes One)");
    assert!(mail[0].1.contains("Server: Tes One"), "{mail:?}");
    assert!(
        mail[0].1.ends_with("\nhttps://panel.example/docker"),
        "the link is absolute and last: {mail:?}"
    );

    // What Slack gets is the same subject and body, set into the template.
    let (subject, body) = (mail[0].0.clone(), mail[0].1.clone());
    let text = docker_outbound_text(&subject, &body);
    assert_eq!(
        text,
        "*Docker project has a problem (Tes One)*\nServer: Tes One\nx: web: exited (1)\nhttps://panel.example/docker"
    );
}

#[tokio::test]
async fn the_masters_own_alert_says_master_and_a_node_alert_is_not_relabelled() {
    let (s, _dir) = panel_master(&["boss"]).await;
    s.notify_admins(
        "error",
        "Docker project has a problem",
        "x: web: exited (1)",
        "/docker",
        "docker.project:x",
    )
    .await;
    s.notify_admins(
        "error",
        "Docker node has gone silent",
        "Tes One has not answered",
        "/docker",
        "docker.node:node_a",
    )
    .await;
    let mail = mail_sends(&s).await;
    assert_eq!(mail.len(), 2, "{mail:?}");
    assert_eq!(mail[0].0, "Docker project has a problem (master)");
    assert!(mail[0].1.contains("Server: master"), "{mail:?}");
    assert_eq!(
        mail[1].0, "Docker node has gone silent",
        "it is about another node and names it already"
    );
    assert!(!mail[1].1.contains("Server:"), "{mail:?}");
}

#[tokio::test]
async fn with_no_panel_address_no_relative_link_is_sent() {
    let s = outbound_master(&["boss"]).await;
    s.notify_admins("error", "T", "B", "/docker", "docker.daemon")
        .await;
    let mail = mail_sends(&s).await;
    assert_eq!(mail.len(), 1);
    assert!(!mail[0].1.contains("/docker"), "{mail:?}");
}

#[test]
fn the_daemon_letters_do_not_say_this_server() {
    use crate::letters::{LetterCatalog, LetterLang};
    for id in ["ops.docker_daemon_down.body", "ops.docker_daemon_up.body"] {
        for lang in [LetterLang::En, LetterLang::Cs] {
            let text = LetterCatalog::new(lang).render(id, &[("error", "e")]);
            assert!(!text.to_lowercase().contains("this server"), "{text}");
            assert!(!text.contains("tomto serveru"), "{text}");
        }
    }
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
    s.docker_outbound("master", "t", "b", "/docker", "docker.project:x")
        .await;

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
    assert_eq!(mail[0].0, "docker.daemon (node_a)");
    assert_eq!(mail[1].0, "docker.node:node_b");
    assert!(mail[2].0.starts_with("docker.project:p"), "{mail:?}");
    let (subject, body) = &mail[OUTBOUND_PER_INGEST];
    assert_eq!(subject, "More Docker alerts");
    assert!(body.contains("20 more"), "30 - 10 = 20 unsent: {body}");
    assert!(body.contains("node_a"), "from which server: {body}");
    assert!(
        !body.contains("/docker"),
        "no panel address, no relative link: {body}"
    );
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

// ---------------------------------------------------------------------------
// Reverse proxy from a discovered stack
// ---------------------------------------------------------------------------

use crate::service::docker::{link_hostings, loopback_port, proxy_offer, ProxyOffer};
use hyperion_types::docker::{DockerContainer, DockerPort, DockerProject};

fn port(ip: &str, host: u16, proto: &str) -> DockerPort {
    DockerPort {
        host_ip: ip.into(),
        host_port: host,
        container_port: 80,
        proto: proto.into(),
    }
}

fn stack_with(name: &str, ports: Vec<DockerPort>) -> DockerProject {
    DockerProject {
        name: name.into(),
        containers: vec![DockerContainer {
            name: format!("{name}-web-1"),
            project: name.into(),
            service: "web".into(),
            state: "running".into(),
            ports,
            ..Default::default()
        }],
        verdict: "ok".into(),
        ..Default::default()
    }
}

fn proxies(rows: &[(&str, &str)]) -> Vec<(String, String)> {
    rows.iter()
        .map(|(d, u)| (d.to_string(), u.to_string()))
        .collect()
}

#[test]
fn loopback_port_only_for_this_machine() {
    assert_eq!(loopback_port("http://127.0.0.1:3000"), Some(3000));
    assert_eq!(loopback_port("http://localhost:3000/"), Some(3000));
    assert_eq!(loopback_port("http://LocalHost:3000/app"), Some(3000));
    assert_eq!(loopback_port("https://[::1]:8443"), Some(8443));
    assert_eq!(loopback_port("http://10.0.0.1:3000"), None);
    assert_eq!(loopback_port("http://127.0.0.1"), None, "no port to match");
    assert_eq!(loopback_port("http://example.com:3000"), None);
    assert_eq!(
        loopback_port("http://127.0.0.1.evil.example:3000"),
        None,
        "a name that starts like an address is a name"
    );
    assert_eq!(loopback_port("ftp://127.0.0.1:21"), None);
    assert_eq!(loopback_port("not a url"), None);
    assert_eq!(loopback_port(""), None);
}

#[test]
fn link_found_for_hand_made_proxy() {
    let mut ps = vec![
        stack_with("shop", vec![port("127.0.0.1", 3000, "tcp")]),
        stack_with("blog", vec![port("0.0.0.0", 8080, "tcp")]),
    ];
    link_hostings(
        &mut ps,
        &proxies(&[
            ("shop.example.cz", "http://127.0.0.1:3000/"),
            ("www.blog.cz", "http://localhost:8080"),
        ]),
    );
    assert_eq!(ps[0].hostings, vec!["shop.example.cz".to_string()]);
    assert_eq!(ps[1].hostings, vec!["www.blog.cz".to_string()]);
}

#[test]
fn link_ignores_other_hosts() {
    let mut ps = vec![stack_with("shop", vec![port("0.0.0.0", 3000, "tcp")])];
    link_hostings(
        &mut ps,
        &proxies(&[
            ("a.cz", "http://10.0.0.5:3000"),
            ("b.cz", "http://127.0.0.1:3001"),
            ("c.cz", "http://127.0.0.1"),
        ]),
    );
    assert!(ps[0].hostings.is_empty(), "{:?}", ps[0].hostings);
}

#[test]
fn link_needs_a_tcp_port_that_loopback_reaches() {
    let mut ps = vec![
        stack_with("udp", vec![port("0.0.0.0", 3000, "udp")]),
        stack_with("lan", vec![port("10.0.0.2", 3001, "tcp")]),
        stack_with("v6", vec![port("::", 3002, "tcp")]),
        stack_with("bare", vec![port("", 3003, "tcp")]),
        stack_with("unpub", vec![port("", 0, "tcp")]),
    ];
    link_hostings(
        &mut ps,
        &proxies(&[
            ("a.cz", "http://127.0.0.1:3000"),
            ("b.cz", "http://127.0.0.1:3001"),
            ("c.cz", "http://127.0.0.1:3002"),
            ("d.cz", "http://127.0.0.1:3003"),
            ("e.cz", "http://127.0.0.1:80"),
        ]),
    );
    let linked: Vec<(&str, usize)> = ps
        .iter()
        .map(|p| (p.name.as_str(), p.hostings.len()))
        .collect();
    assert_eq!(
        linked,
        [("udp", 0), ("lan", 0), ("v6", 1), ("bare", 1), ("unpub", 0)]
    );
}

#[test]
fn link_lists_each_hosting_once_and_starts_clean() {
    let mut p = stack_with(
        "shop",
        vec![port("0.0.0.0", 3000, "tcp"), port("::", 3000, "tcp")],
    );
    p.hostings = vec!["stale.cz".into()];
    let mut ps = vec![p];
    link_hostings(
        &mut ps,
        &proxies(&[
            ("b.cz", "http://127.0.0.1:3000"),
            ("a.cz", "http://localhost:3000"),
            ("b.cz", "http://127.0.0.1:3000"),
        ]),
    );
    assert_eq!(ps[0].hostings, vec!["a.cz".to_string(), "b.cz".to_string()]);
}

#[test]
fn proxy_offer_by_bind() {
    let offer = |ip: &str, host: u16, proto: &str| proxy_offer(&port(ip, host, proto));
    assert_eq!(
        offer("127.0.0.1", 18080, "tcp"),
        ProxyOffer::Offer {
            url: "http://127.0.0.1:18080".into(),
            public_bind: false
        }
    );
    assert_eq!(
        offer("::1", 18080, "tcp"),
        ProxyOffer::Offer {
            url: "http://127.0.0.1:18080".into(),
            public_bind: false
        }
    );
    for ip in ["0.0.0.0", "::", ""] {
        assert_eq!(
            offer(ip, 18080, "tcp"),
            ProxyOffer::Offer {
                url: "http://127.0.0.1:18080".into(),
                public_bind: true
            },
            "{ip:?}"
        );
    }
    assert_eq!(offer("0.0.0.0", 80, "tcp"), ProxyOffer::Conflict);
    assert_eq!(offer("127.0.0.1", 443, "tcp"), ProxyOffer::Conflict);
    assert_eq!(offer("0.0.0.0", 53, "udp"), ProxyOffer::NotTcp);
    assert_eq!(offer("0.0.0.0", 0, "tcp"), ProxyOffer::NotTcp);
    assert_eq!(
        offer("10.0.0.2", 18080, "tcp"),
        ProxyOffer::OtherAddress,
        "127.0.0.1 would not reach a port bound to one other address"
    );
}

/// A reverse-proxy hosting on `upstream`, as the wizard or a hand edit leaves it.
async fn make_proxy(s: &HostingService<MockAdapterPort>, domain: &str, upstream: &str) {
    let mut r = req(domain);
    r.php_version = None;
    r.database = None;
    r.kind = "reverse_proxy".into();
    r.proxy_upstream_url = Some(upstream.into());
    s.create(r).await.expect("create proxy");
}

#[tokio::test]
async fn list_reverse_proxies_skips_trash_and_other_kinds() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks_many());
    make_proxy(&s, "live.cz", "http://127.0.0.1:18080").await;
    make_proxy(&s, "gone.cz", "http://127.0.0.1:18081").await;
    s.create(req("plain.cz")).await.expect("php site");
    let gone = s
        .get(HostingSelector::Domain(Domain::parse("gone.cz").unwrap()))
        .await
        .expect("get");
    hyperion_state::hostings::mark_trashed(&pool, &gone.id, 5)
        .await
        .expect("trash");

    let rows = hyperion_state::hostings::list_reverse_proxies(&pool)
        .await
        .expect("list");
    assert_eq!(
        rows,
        vec![("live.cz".to_string(), "http://127.0.0.1:18080".to_string())]
    );
}

#[tokio::test]
async fn overview_links_the_hosting_that_proxies_to_a_published_port() {
    let mut a = happy_mocks_many();
    a.expect_docker_read().returning(|cmd, _| match cmd {
        DockerCmd::PsAll => Ok(FIXTURE_PS.to_vec()),
        DockerCmd::Inspect(_) => Ok(FIXTURE_INSPECT.to_vec()),
        DockerCmd::Stats => Ok(FIXTURE_STATS.to_vec()),
        DockerCmd::SystemDf => Ok(FIXTURE_DF.to_vec()),
        other => panic!("unexpected {other:?}"),
    });
    let (s, _dir) = worker_with(a).await;
    make_proxy(&s, "app.cz", "http://127.0.0.1:18080").await;
    make_proxy(&s, "elsewhere.cz", "http://10.0.0.9:18080").await;

    s.docker_tick().await.expect("tick");
    let st = s.docker_overview().await.expect("overview");
    let fixture = st.projects.iter().find(|p| p.name == "fixture").expect("p");
    assert_eq!(fixture.hostings, vec!["app.cz".to_string()]);
    assert!(
        st.projects
            .iter()
            .filter(|p| p.name != "fixture")
            .all(|p| p.hostings.is_empty()),
        "only the stack that publishes the port is linked"
    );

    // A hosting made after the tick shows up on the next read, not the next tick.
    make_proxy(&s, "second.cz", "http://localhost:18080/").await;
    let st = s.docker_overview().await.expect("overview");
    let fixture = st.projects.iter().find(|p| p.name == "fixture").expect("p");
    assert_eq!(
        fixture.hostings,
        vec!["app.cz".to_string(), "second.cz".to_string()]
    );
}

// ---------------------------------------------------------------------------
// Image updates
// ---------------------------------------------------------------------------

const NEW_D: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const OLD_D: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn local_of(image_ref: &str, repo_digests: &[&str], id: &str) -> LocalImage {
    LocalImage {
        image_ref: image_ref.into(),
        repo_digests: repo_digests.iter().map(|s| s.to_string()).collect(),
        image_id: id.into(),
        pinned: image_ref.contains("@sha256:"),
        built_here: false,
        pulled_from: Vec::new(),
    }
}

fn nginx_local(d: &str) -> LocalImage {
    local_of("nginx:alpine", &[&format!("nginx@{d}")], d)
}

fn cannot(s: &ImageUpdateState) -> &str {
    match s {
        ImageUpdateState::CannotVerify { reason } => reason,
        other => panic!("expected cannot verify, got {other:?}"),
    }
}

#[test]
fn same_digest_is_up_to_date() {
    let l = nginx_local(OLD_D);
    assert_eq!(
        image_state(&l, OLD_D, Ok(OLD_D), None),
        ImageUpdateState::UpToDate
    );
}

#[test]
fn new_digest_is_update_available() {
    let l = nginx_local(OLD_D);
    assert_eq!(
        image_state(&l, OLD_D, Ok(NEW_D), None),
        ImageUpdateState::UpdateAvailable
    );
}

#[test]
fn the_fixtures_repo_digest_is_the_index_digest_and_compares_equal() {
    let raw =
        include_bytes!("../../../../hyperion-adapters/tests/fixtures/docker/image_inspect.json");
    let l = hyperion_adapters::docker::parse_image_inspect(raw, "nginx:alpine")
        .expect("parse")
        .expect("one image");
    let index = "sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606";
    assert_eq!(l.repo_digests, [format!("nginx@{index}")]);
    assert_eq!(
        image_state(&l, &l.image_id, Ok(index), None),
        ImageUpdateState::UpToDate
    );
    assert_eq!(
        image_state(&l, &l.image_id, Ok(NEW_D), None),
        ImageUpdateState::UpdateAvailable
    );
}

#[test]
fn a_digest_is_matched_by_repository_name() {
    // The same image can carry digests of several repositories. Only the
    // repository the container names counts, whatever the order.
    let l = local_of(
        "nginx:alpine",
        &[&format!("other/thing@{NEW_D}"), &format!("nginx@{OLD_D}")],
        OLD_D,
    );
    assert_eq!(
        image_state(&l, OLD_D, Ok(OLD_D), None),
        ImageUpdateState::UpToDate
    );
    assert_eq!(
        image_state(&l, OLD_D, Ok(NEW_D), None),
        ImageUpdateState::UpdateAvailable,
        "a digest of another repository is not this tag's"
    );
    // Hub spellings of one repository are one repository.
    let l = local_of(
        "docker.io/library/nginx:alpine",
        &[&format!("nginx@{OLD_D}")],
        OLD_D,
    );
    assert_eq!(
        image_state(&l, OLD_D, Ok(OLD_D), None),
        ImageUpdateState::UpToDate
    );
    let l = local_of(
        "ghcr.io/o/app:1",
        &[&format!("ghcr.io/o/app@{OLD_D}")],
        OLD_D,
    );
    assert_eq!(
        image_state(&l, OLD_D, Ok(OLD_D), None),
        ImageUpdateState::UpToDate
    );
    // Nothing from this repository at all: it was pulled under another name.
    let l = local_of("mine/app:1", &[&format!("nginx@{OLD_D}")], OLD_D);
    assert!(cannot(&image_state(&l, OLD_D, Ok(OLD_D), None)).contains("another repository"));
}

#[test]
fn local_build_cannot_verify() {
    let l = local_of("shop-web:latest", &[], "sha256:abc");
    let s = image_state(&l, "sha256:abc", Ok(NEW_D), None);
    assert!(cannot(&s).contains("built on this node"), "{s:?}");
}

#[test]
fn digest_pinned_cannot_verify() {
    let l = local_of(
        &format!("nginx@{OLD_D}"),
        &[&format!("nginx@{OLD_D}")],
        OLD_D,
    );
    assert!(l.pinned);
    let s = image_state(&l, OLD_D, Ok(NEW_D), None);
    assert!(cannot(&s).contains("pinned"), "{s:?}");
}

#[test]
fn registry_error_never_says_up_to_date() {
    let l = nginx_local(OLD_D);
    for (e, word) in [
        (RemoteDigestError::RateLimited, "rate limit"),
        (RemoteDigestError::Unauthorized, "unauthorized"),
        (
            RemoteDigestError::Unavailable("timed out".into()),
            "timed out",
        ),
        (RemoteDigestError::Unsupported, "buildx missing"),
    ] {
        let s = image_state(&l, OLD_D, Err(&e), None);
        assert!(cannot(&s).contains(word), "{e:?}: {s:?}");
    }
}

#[test]
fn failed_check_keeps_last_answer() {
    let l = nginx_local(OLD_D);
    let update = ImageCheckRow {
        image_ref: "nginx:alpine".into(),
        local_digest: OLD_D.into(),
        remote_digest: NEW_D.into(),
        state: "update".into(),
        checked_at: 5,
        ..Default::default()
    };
    for e in [
        RemoteDigestError::RateLimited,
        RemoteDigestError::Unauthorized,
        RemoteDigestError::Unavailable("x".into()),
        RemoteDigestError::Unsupported,
    ] {
        assert_eq!(
            image_state(&l, OLD_D, Err(&e), Some(&update)),
            ImageUpdateState::UpdateAvailable,
            "{e:?}"
        );
    }
    let current = ImageCheckRow {
        remote_digest: OLD_D.into(),
        state: "current".into(),
        ..update.clone()
    };
    assert_eq!(
        image_state(
            &l,
            OLD_D,
            Err(&RemoteDigestError::RateLimited),
            Some(&current)
        ),
        ImageUpdateState::UpToDate
    );
    // The node pulled another image since the answer: the answer was about
    // the old one and says nothing now. An error never makes a state.
    let pulled = nginx_local(NEW_D);
    for last in [&update, &current] {
        let s = image_state(
            &pulled,
            NEW_D,
            Err(&RemoteDigestError::RateLimited),
            Some(last),
        );
        assert!(cannot(&s).contains("rate limit"), "{s:?}");
    }
    // A row that does not say which image it described is no basis either.
    let nameless = ImageCheckRow {
        local_digest: String::new(),
        ..update.clone()
    };
    assert!(matches!(
        image_state(
            &l,
            OLD_D,
            Err(&RemoteDigestError::RateLimited),
            Some(&nameless)
        ),
        ImageUpdateState::CannotVerify { .. }
    ));
    // A last row that never got an answer is no answer.
    let none = ImageCheckRow {
        state: "cannot:x".into(),
        ..Default::default()
    };
    assert!(matches!(
        image_state(&l, OLD_D, Err(&RemoteDigestError::RateLimited), Some(&none)),
        ImageUpdateState::CannotVerify { .. }
    ));
}

/// Docker 29's containerd store gives a built image a `RepoDigests` entry of
/// its own name, so "no digests" no longer means "built here".
#[test]
fn an_image_built_here_is_told_by_its_identity_too() {
    let mut l = local_of("app:1", &[&format!("app@{OLD_D}")], OLD_D);
    l.built_here = true;
    for remote in [Ok(OLD_D), Err(&RemoteDigestError::Unauthorized)] {
        let s = image_state(&l, OLD_D, remote, None);
        assert!(cannot(&s).contains("built on this node"), "{s:?}");
    }
}

/// `docker tag busybox reg/x:1` makes Docker 29 report a digest under
/// `reg/x`. The image came from elsewhere, and what the registry holds under
/// that name is no comparison for it: a push of a multi-arch image's one
/// local platform gets another digest there.
#[test]
fn an_image_pulled_under_another_name_cannot_be_compared() {
    let mut l = local_of(
        "127.0.0.1:15000/priv/bb:1",
        &[
            &format!("127.0.0.1:15000/priv/bb@{OLD_D}"),
            &format!("busybox@{OLD_D}"),
        ],
        OLD_D,
    );
    l.pulled_from = vec!["docker.io/library/busybox".into()];
    let s = image_state(&l, OLD_D, Ok(NEW_D), None);
    assert!(cannot(&s).contains("another repository"), "{s:?}");

    // Pulled from that repository after all: compared. Docker 29 leaves the
    // registry's port out of `Identity` (seen on a node: `127.0.0.1/priv/bb`
    // for an image pulled from `127.0.0.1:15000/priv/bb`).
    l.pulled_from.push("127.0.0.1/priv/bb".into());
    assert_eq!(
        image_state(&l, OLD_D, Ok(NEW_D), None),
        ImageUpdateState::UpdateAvailable
    );
    l.pulled_from = vec!["127.0.0.1:15000/priv/bb".into()];
    assert_eq!(
        image_state(&l, OLD_D, Ok(NEW_D), None),
        ImageUpdateState::UpdateAvailable
    );
    // The same path on another host is another repository.
    l.pulled_from = vec!["ghcr.io/priv/bb".into()];
    let s = image_state(&l, OLD_D, Ok(NEW_D), None);
    assert!(cannot(&s).contains("another repository"), "{s:?}");
    let mut hub = nginx_local(OLD_D);
    hub.pulled_from = vec!["docker.io/library/nginx".into()];
    assert_eq!(
        image_state(&hub, OLD_D, Ok(OLD_D), None),
        ImageUpdateState::UpToDate
    );
}

#[test]
fn pulled_not_recreated_is_told_before_anything_else() {
    let l = nginx_local(NEW_D);
    assert_eq!(
        image_state(&l, OLD_D, Ok(NEW_D), None),
        ImageUpdateState::NotRecreated
    );
    assert_eq!(
        image_state(&l, OLD_D, Err(&RemoteDigestError::Unauthorized), None),
        ImageUpdateState::NotRecreated
    );
}

fn nginx_world(n: u32) -> Shared {
    let w = world(
        (1..=n)
            .map(|i| {
                ct(
                    i,
                    "shop",
                    ["web", "api", "worker", "x", "y", "z"][i as usize % 6],
                )
                .on_image("nginx:alpine", OLD_D)
            })
            .collect(),
    );
    {
        let mut g = w.lock().expect("world");
        g.locals.insert(
            "nginx:alpine".into(),
            (OLD_D.into(), vec![format!("nginx@{OLD_D}")]),
        );
        g.remote.insert("nginx:alpine".into(), Ok(NEW_D.into()));
    }
    w
}

fn lookups(w: &Shared) -> Vec<String> {
    w.lock().expect("world").lookups.clone()
}

async fn updates_at(s: &HostingService<MockAdapterPort>, t: i64) {
    s.docker_updates_tick_at(t).await.expect("updates tick");
}

async fn update_cards(
    s: &HostingService<MockAdapterPort>,
) -> Vec<(String, String, String, String)> {
    alerts(s)
        .await
        .into_iter()
        .filter(|a| a.0.starts_with("docker.update:"))
        .collect()
}

async fn container_updates(s: &HostingService<MockAdapterPort>) -> Vec<Option<ImageUpdateState>> {
    let st = s.docker_overview().await.expect("overview");
    st.projects
        .iter()
        .flat_map(|p| p.containers.iter())
        .map(|c| c.update.clone())
        .collect()
}

const DAY: i64 = 86_400;

#[tokio::test]
async fn updates_tick_does_nothing_when_not_installed() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_docker_read().times(0);
    a.expect_docker_remote_digest().times(0);
    let s = svc(pool, a);
    s.docker_updates_tick()
        .await
        .expect("an off module is a no-op");
}

/// The name of an image built on this node says nothing to a registry, and
/// must not be sent to one.
#[tokio::test]
async fn an_image_built_here_is_not_asked_about_at_any_registry() {
    let w = world(vec![ct(1, "shop", "web").on_image("app:1", OLD_D)]);
    {
        let mut g = w.lock().expect("world");
        g.locals
            .insert("app:1".into(), (OLD_D.into(), vec![format!("app@{OLD_D}")]));
        g.identities.insert(
            "app:1".into(),
            serde_json::json!({"Build": [{"Ref": "abc", "CreatedAt": "2026-11-05T08:00:35Z"}]}),
        );
    }
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    assert!(lookups(&w).is_empty(), "{:?}", lookups(&w));
    let got = container_updates(&s).await;
    let state = got[0].as_ref().expect("an answer");
    assert!(cannot(state).contains("built on this node"), "{state:?}");
}

#[tokio::test]
async fn one_lookup_per_unique_image() {
    let w = nginx_world(3);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    assert_eq!(
        lookups(&w),
        ["nginx:alpine"],
        "three containers, one question"
    );
    assert_eq!(reads_of(&w, "ImageInspect"), 1);
    assert_eq!(
        container_updates(&s).await,
        vec![Some(ImageUpdateState::UpdateAvailable); 3]
    );
}

#[tokio::test]
async fn only_images_of_known_containers_are_looked_up() {
    let w = nginx_world(1);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    hyperion_state::docker::put_image_check(
        &s.pool,
        &ImageCheckRow {
            image_ref: "gone/app:1".into(),
            state: "current".into(),
            ..Default::default()
        },
    )
    .await
    .expect("seed");
    updates_at(&s, T0).await;
    assert_eq!(lookups(&w), ["nginx:alpine"]);
}

#[tokio::test]
async fn a_node_with_a_hundred_and_ten_images_looks_up_a_hundred() {
    let w = world(
        (1..=110)
            .map(|i| ct(i, "p", "s").on_image(&format!("reg.example/app{i:03}:1"), OLD_D))
            .collect(),
    );
    let (s, _dir) = worker_with(world_mock(&w)).await;
    {
        let mut g = w.lock().expect("world");
        for i in 1..=110 {
            g.locals.insert(
                format!("reg.example/app{i:03}:1"),
                (OLD_D.into(), vec![format!("reg.example/app{i:03}@{OLD_D}")]),
            );
        }
    }
    updates_at(&s, T0).await;
    assert_eq!(lookups(&w).len(), 100);
}

#[tokio::test]
async fn a_checked_reference_is_not_asked_again_within_twenty_hours() {
    let w = nginx_world(1);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    // A restart of the agent: the books are in the database.
    updates_at(&s, T0 + 19 * 3600).await;
    assert_eq!(lookups(&w).len(), 1);
    updates_at(&s, T0 + 21 * 3600).await;
    assert_eq!(lookups(&w).len(), 2);
}

#[tokio::test]
async fn rate_limit_backs_off_a_day() {
    let w = nginx_world(1);
    w.lock()
        .expect("world")
        .remote
        .insert("nginx:alpine".into(), Err(RemoteDigestError::RateLimited));
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    assert_eq!(lookups(&w).len(), 1);

    let row = hyperion_state::docker::get_image_check(&s.pool, "nginx:alpine")
        .await
        .expect("row")
        .expect("exists");
    let next_midnight = (T0 / DAY + 1) * DAY;
    assert!(
        row.retry_after >= next_midnight && row.retry_after >= T0 + 20 * 3600,
        "{} is not past the next day",
        row.retry_after
    );
    updates_at(&s, T0 + 3600).await;
    updates_at(&s, row.retry_after - 1).await;
    assert_eq!(lookups(&w).len(), 1, "no call before retry_after");
    // The shown state is not "up to date" and not an alarm: no answer yet.
    assert!(
        cannot(&container_updates(&s).await[0].clone().expect("a state")).contains("rate limit")
    );

    w.lock()
        .expect("world")
        .remote
        .insert("nginx:alpine".into(), Ok(NEW_D.into()));
    updates_at(&s, row.retry_after).await;
    assert_eq!(lookups(&w).len(), 2);
}

#[tokio::test]
async fn one_rate_limit_ends_the_pass() {
    let w = world(vec![
        ct(1, "p", "a").on_image("a/one:1", OLD_D),
        ct(2, "p", "b").on_image("b/two:1", OLD_D),
    ]);
    {
        let mut g = w.lock().expect("world");
        for r in ["a/one:1", "b/two:1"] {
            g.locals.insert(
                r.into(),
                (
                    OLD_D.into(),
                    vec![format!("{r}@{OLD_D}").replace(":1@", "@")],
                ),
            );
            g.remote
                .insert(r.into(), Err(RemoteDigestError::RateLimited));
        }
    }
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    assert_eq!(
        lookups(&w).len(),
        1,
        "the registry said stop; the rest wait for tomorrow"
    );
}

#[tokio::test]
async fn failed_check_keeps_last_answer_across_ticks() {
    let w = nginx_world(1);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    assert_eq!(
        container_updates(&s).await,
        vec![Some(ImageUpdateState::UpdateAvailable)]
    );
    w.lock()
        .expect("world")
        .remote
        .insert("nginx:alpine".into(), Err(RemoteDigestError::RateLimited));
    updates_at(&s, T0 + 2 * DAY).await;
    assert_eq!(lookups(&w).len(), 2);
    assert_eq!(
        container_updates(&s).await,
        vec![Some(ImageUpdateState::UpdateAvailable)],
        "an error does not erase what was learnt"
    );
}

async fn nginx_row(s: &HostingService<MockAdapterPort>) -> ImageCheckRow {
    hyperion_state::docker::get_image_check(&s.pool, "nginx:alpine")
        .await
        .expect("row")
        .expect("exists")
}

/// 1970-01-20, after T0 and after any check made at T0 + 2 days or less.
const RESTARTED: &str = "1970-01-20T00:00:00Z";

#[tokio::test]
async fn a_restarted_container_keeps_its_answer_while_the_registry_fails() {
    let w = nginx_world(2);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    // Reboot, `docker restart`, restart policy: the containers start again on
    // the same image, and the registry is down.
    {
        let mut g = w.lock().expect("world");
        g.cts[0].started = RESTARTED;
        g.cts[1].started = RESTARTED;
        g.remote
            .insert("nginx:alpine".into(), Err(RemoteDigestError::Unauthorized));
    }
    updates_at(&s, T0 + 2 * DAY).await;
    tick_at(&s, T0 + 2 * DAY + 30).await;
    let st = s.docker_overview().await.expect("overview");
    let cs: Vec<_> = st
        .projects
        .iter()
        .flat_map(|p| p.containers.iter())
        .collect();
    assert_eq!(cs.len(), 2);
    for c in cs {
        assert!(c.started_at > T0 + 2 * DAY, "restarted after the check");
        assert_eq!(
            c.update,
            Some(ImageUpdateState::UpdateAvailable),
            "the image did not change, so the answer still holds"
        );
        assert!(
            c.update_error.contains("unauthorized"),
            "{}",
            c.update_error
        );
    }
}

#[tokio::test]
async fn a_container_started_on_another_image_after_the_check_is_unchecked() {
    let w = nginx_world(1);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    {
        let mut g = w.lock().expect("world");
        g.cts[0].started = RESTARTED;
        g.cts[0].image_id = "sha256:other".into();
    }
    tick_at(&s, T0 + 30).await;
    assert_eq!(container_updates(&s).await, vec![None]);
}

#[tokio::test]
async fn a_failed_check_after_a_pull_is_not_an_answer_and_sends_no_card() {
    let w = nginx_world(1);
    // The registry still holds the digest the node has: up to date.
    w.lock()
        .expect("world")
        .remote
        .insert("nginx:alpine".into(), Ok(OLD_D.into()));
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    assert_eq!(
        container_updates(&s).await,
        vec![Some(ImageUpdateState::UpToDate)]
    );
    // The owner pulls a newer image and recreates the container on it; the
    // next check fails.
    {
        let mut g = w.lock().expect("world");
        g.locals.insert(
            "nginx:alpine".into(),
            (NEW_D.into(), vec![format!("nginx@{NEW_D}")]),
        );
        g.cts[0].image_id = NEW_D.into();
        g.remote
            .insert("nginx:alpine".into(), Err(RemoteDigestError::Unauthorized));
    }
    for day in [2, 4] {
        updates_at(&s, T0 + day * DAY).await;
        tick_at(&s, T0 + day * DAY + 30).await;
        let st = container_updates(&s).await;
        assert!(
            cannot(st[0].as_ref().expect("a state")).contains("unauthorized"),
            "day {day}: {st:?}"
        );
        let row = hyperion_state::docker::get_image_check(&s.pool, "nginx:alpine")
            .await
            .expect("row")
            .expect("exists");
        assert!(row.state.starts_with("cannot:"), "day {day}: {}", row.state);
        assert!(row.remote_digest.is_empty(), "the old answer is dropped");
    }
    assert!(update_cards(&s).await.is_empty(), "an error is not news");
}

#[tokio::test]
async fn the_latest_error_is_kept_beside_an_older_answer_and_cleared_by_an_answer() {
    let w = nginx_world(1);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    assert_eq!(nginx_row(&s).await.last_error, "");
    w.lock()
        .expect("world")
        .remote
        .insert("nginx:alpine".into(), Err(RemoteDigestError::Unauthorized));
    updates_at(&s, T0 + 2 * DAY).await;
    let r = nginx_row(&s).await;
    assert!(r.last_error.contains("unauthorized"), "{}", r.last_error);
    assert_eq!(r.checked_at, T0, "the answer keeps its age");
    w.lock()
        .expect("world")
        .remote
        .insert("nginx:alpine".into(), Ok(NEW_D.into()));
    updates_at(&s, T0 + 4 * DAY).await;
    assert_eq!(nginx_row(&s).await.last_error, "");
}

#[tokio::test]
async fn unreachable_registry_without_history_is_cannot_verify() {
    let w = nginx_world(1);
    w.lock()
        .expect("world")
        .remote
        .insert("nginx:alpine".into(), Err(RemoteDigestError::Unauthorized));
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    let st = container_updates(&s).await;
    assert!(cannot(st[0].as_ref().expect("state")).contains("unauthorized"));
    assert!(update_cards(&s).await.is_empty(), "no news, no card");
}

#[tokio::test]
async fn pinned_and_local_images_ask_nobody() {
    let w = world(vec![
        ct(1, "p", "pinned").on_image(&format!("nginx@{OLD_D}"), OLD_D),
        ct(2, "p", "built").on_image("shop-web:latest", "sha256:built"),
        ct(3, "p", "byid").on_image("sha256:0123456789ab", "sha256:0123456789ab"),
    ]);
    {
        let mut g = w.lock().expect("world");
        g.locals.insert(
            format!("nginx@{OLD_D}"),
            (OLD_D.into(), vec![format!("nginx@{OLD_D}")]),
        );
        g.locals
            .insert("shop-web:latest".into(), ("sha256:built".into(), vec![]));
    }
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    assert!(lookups(&w).is_empty(), "nothing a registry could answer");
    let st = s.docker_overview().await.expect("overview");
    let reason = |service: &str| {
        let c = st
            .projects
            .iter()
            .flat_map(|p| p.containers.iter())
            .find(|c| c.service == service)
            .expect("container");
        cannot(c.update.as_ref().expect("a state")).to_string()
    };
    assert!(reason("pinned").contains("pinned"));
    assert!(reason("built").contains("built on this node"));
    assert!(reason("byid").contains("no tag"));
}

#[tokio::test]
async fn pulled_not_recreated() {
    let w = nginx_world(2);
    {
        let mut g = w.lock().expect("world");
        // The node pulled the tag again; one container was recreated on it.
        g.locals.insert(
            "nginx:alpine".into(),
            (NEW_D.into(), vec![format!("nginx@{NEW_D}")]),
        );
        g.cts[1].image_id = NEW_D.into();
    }
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    let mut states = container_updates(&s).await;
    states.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(
        states,
        vec![
            Some(ImageUpdateState::NotRecreated),
            Some(ImageUpdateState::UpToDate)
        ]
    );
}

#[tokio::test]
async fn the_marks_survive_the_next_ordinary_tick_and_a_restart() {
    let w = nginx_world(1);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    tick_at(&s, T0 + 30).await;
    assert_eq!(
        container_updates(&s).await,
        vec![Some(ImageUpdateState::UpdateAvailable)],
        "the 30 s tick keeps the answers"
    );
    // An agent that restarted has no snapshot; what it reads first still
    // carries the answers, because they are in the database.
    *s.docker_snapshot.write().await = None;
    assert_eq!(
        container_updates(&s).await,
        vec![Some(ImageUpdateState::UpdateAvailable)]
    );
}

#[tokio::test]
async fn notifies_once_per_digest() {
    let w = nginx_world(1);
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    let cards = update_cards(&s).await;
    assert_eq!(cards.len(), 1);
    let (kind, severity, title, body) = &cards[0];
    assert!(kind.starts_with("docker.update:"), "{kind}");
    assert_eq!(severity, "info");
    assert!(!title.is_empty() && body.contains('1'), "{title} / {body}");

    // The next day: same digest, nothing new to say.
    updates_at(&s, T0 + DAY + 600).await;
    assert_eq!(lookups(&w).len(), 2, "it did ask again");
    assert_eq!(update_cards(&s).await.len(), 1);

    // A newer digest is news again.
    let newer = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    w.lock()
        .expect("world")
        .remote
        .insert("nginx:alpine".into(), Ok(newer.into()));
    updates_at(&s, T0 + 2 * DAY + 1200).await;
    assert_eq!(update_cards(&s).await.len(), 2);
}

#[tokio::test]
async fn the_update_card_counts_images_and_is_bell_only() {
    let w = world(vec![
        ct(1, "p", "a").on_image("a/one:1", OLD_D),
        ct(2, "p", "b").on_image("b/two:1", OLD_D),
        ct(3, "p", "c").on_image("c/three:1", OLD_D),
    ]);
    {
        let mut g = w.lock().expect("world");
        for r in ["a/one:1", "b/two:1", "c/three:1"] {
            let name = r.split(':').next().expect("name");
            g.locals
                .insert(r.into(), (OLD_D.into(), vec![format!("{name}@{OLD_D}")]));
        }
        g.remote.insert("a/one:1".into(), Ok(NEW_D.into()));
        g.remote.insert("b/two:1".into(), Ok(NEW_D.into()));
        g.remote.insert("c/three:1".into(), Ok(OLD_D.into()));
    }
    let (s, _dir) = worker_with(world_mock(&w)).await;
    updates_at(&s, T0).await;
    let cards = update_cards(&s).await;
    assert_eq!(cards.len(), 1, "one folded card per node");
    assert!(
        cards[0].3.contains('2'),
        "two images have updates: {}",
        cards[0].3
    );
}

#[test]
fn update_notices_never_leave_the_bell() {
    assert!(!is_outbound_docker_kind("docker.update:s4"));
    assert!(!is_outbound_docker_kind("docker.update:"));
    assert!(
        is_outbound_docker_kind("docker.project:x"),
        "the rest is unchanged"
    );
    assert!(is_outbound_docker_kind("docker.daemon"));
}

#[tokio::test]
async fn an_ingested_update_notice_sends_nothing_outbound() {
    // A worker's update card reaches the master's bell like any alert, and
    // stops there: Slack and mail stay quiet, and the same item sent again
    // is still not news.
    let s = outbound_master(&["boss"]).await;
    let n = s
        .notifications_ingest("node_a", vec![outbox_item(1, "docker.update:node_a")])
        .await
        .expect("ingest");
    assert_eq!(n, 1, "the bell gets it");
    assert_eq!(slack_sends(&s).await, 0);
    assert!(mail_sends(&s).await.is_empty());
}

#[test]
fn the_wire_field_is_optional() {
    let c: hyperion_types::docker::DockerContainer =
        serde_json::from_str(r#"{"name":"x"}"#).expect("an older node's container");
    assert_eq!(c.update, None);
    let c: hyperion_types::docker::DockerContainer =
        serde_json::from_str(r#"{"name":"x","update":{"cannot_verify":{"reason":"pinned"}}}"#)
            .expect("with a state");
    assert!(matches!(
        c.update,
        Some(ImageUpdateState::CannotVerify { .. })
    ));
}
