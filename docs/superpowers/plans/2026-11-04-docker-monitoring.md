# Docker Monitoring Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An optional, installable Hyperion module that reads Docker and compose state on nodes, shows logs, alerts on problems, checks URLs from the master in place of Uptime Kuma, reports image updates, and can prefill a reverse-proxy hosting for a discovered stack.

**Architecture:** One read-only adapter (`hyperion-adapters/src/docker.rs`) is the only code that runs `docker`. A node tick turns its output into a cached status and alert transitions; `hyperion-web` fans out to read it. URL checks are sampled by the master agent and scheduled from a `hyperion-web` loop, because only the web process can reach other nodes.

**Tech Stack:** Rust, axum, askama, htmx, sqlx/SQLite, the `docker` CLI, curl.

**Spec:** `docs/superpowers/specs/2026-11-04-docker-monitoring-design.md`

## Global Constraints

- Read-only towards Docker: no start, stop, restart, pull, exec, `compose up` or delete.
- Module off means no `docker` process, no module tick work, no nav item, no URL checks.
- `Config.Env` and labels outside `com.docker.compose.*` never leave the adapter.
- Log lines never go into email, Slack or webhooks.
- Hyperion never reads or stores registry passwords.
- Destructive tests only on `tes-1`, never another node.
- All `/docker` routes need the capability and `ctx.scope_all()`; module install and removal need `ctx.is_admin_or_higher()`.
- Slow web actions use `spawn_job`, then redirect to `/jobs/<id>`.
- New wire fields are `#[serde(default)]`. New capabilities are appended at the END of the enum.
- Panel copy is English. New alert text is keyed in `crates/hyperion-core/src/letters.rs` with `en` and `cs`.
- UI uses `.group`, `.ghead`, `.item`. `data-confirm-*` goes on the `<form>`, not the button.
- After adding a migration run `touch crates/hyperion-state/src/lib.rs` before `cargo test --workspace`.
- `cargo check` skips test targets; use `cargo test --workspace --no-run` or a full test run.

## Review Focus

1. Docker daemon hangs instead of failing: every call times out and reports "daemon not responding", and the tick never blocks other agent work. Test in Task 2.
2. `compose up -d` during a deploy recreates containers: no alert inside the 180 s grace, and new container IDs under the same service do not read as a problem. Test in Task 4.
3. One container logs a gigantic line or floods output: the response stays within the byte cap and the agent does not buffer it all. Test in Task 6.
4. A worker's alert batch is re-read after a lost reply: Slack and email fire once, not twice. Test in Task 7.
5. A registry error, 429 or missing buildx never shows "up to date" and never erases the last known answer. Test in Task 10.

---

## File Map

| File | Responsibility |
|---|---|
| `crates/hyperion-adapters/src/docker.rs` | Closed `DockerCmd`, timeouts, parsers, secret reduction |
| `crates/hyperion-adapters/src/docker_registry.rs` | Remote digest lookup |
| `crates/hyperion-types/src/docker.rs` | Wire types |
| `crates/hyperion-state/migrations/091_docker_module.sql` | All tables |
| `crates/hyperion-state/src/docker.rs`, `url_monitors.rs` | Queries |
| `crates/hyperion-core/src/service/docker.rs` | Node module: install, tick, overview, logs |
| `crates/hyperion-core/src/service/docker_verdict.rs` | Pure verdict and transition rules |
| `crates/hyperion-core/src/service/docker_updates.rs` | Daily image check |
| `crates/hyperion-core/src/service/url_monitor.rs` | URL sampling and transitions |
| `bin/hyperion-web/src/docker_watch.rs` | Master loop: URL ticks, enrichment, silent nodes |
| `bin/hyperion-web/src/handlers/docker.rs` | `/docker` pages and logs |
| `bin/hyperion-web/templates/docker*.html` | Pages |

Each RPC touches the same four places, following `MonitorOverview`: variant in `Request` and `Response` (`hyperion-rpc/src/codec.rs`), method on `AgentApi` (`api.rs`), arm in `hyperion-rpc-server/src/lib.rs` plus its test fake (:3529), and delegation in `hyperion-core/src/agent.rs`.

---

### Task 1: Commit the design, record real Docker fixtures

**Files:**
- Create: `crates/hyperion-adapters/tests/fixtures/docker/{ps.jsonl,inspect.json,stats.jsonl,system_df.jsonl,image_inspect.json,version.json}`

- [ ] **Step 1: Run a throwaway stack on tes-1.** Compose project `fixture` with: `web` (`nginx:alpine`, healthcheck, published `127.0.0.1:18080:80`), `job` (`alpine`, exit 0, `restart: "no"`), `crash` (`alpine`, `exit 3`, `restart: on-failure:2`), `env: SECRET_VALUE=do-not-leak-7f3a` on `web`, plus one non-compose container with a custom label `secret.label=do-not-leak-7f3a`.
- [ ] **Step 2: Save the output** of `docker ps -a --format json --no-trunc`, `docker inspect <all ids>`, `docker stats --no-stream --format json`, `docker system df --format json`, `docker image inspect nginx:alpine`, `docker version --format json`.
- [ ] **Step 3: Tear down.** `docker compose -p fixture down --rmi all`, remove the extra container. Expected: `docker ps -aq | wc -l` prints `0`.
- [ ] **Step 4: Confirm no real secret is in the fixtures.** `grep -rn "do-not-leak-7f3a" crates/hyperion-adapters/tests/fixtures/docker | cut -d: -f1 | sort -u` lists only `inspect.json`. Inspect the files for hostnames or anything else that should not be committed.
- [ ] **Step 5: Commit** spec, plan and fixtures.

```bash
git add docs/superpowers crates/hyperion-adapters/tests/fixtures/docker
git commit -m "docs(docker): design and plan for the monitoring module, recorded fixtures"
```

---

### Task 2: Read-only adapter and types

**Files:**
- Create: `crates/hyperion-adapters/src/docker.rs`, `crates/hyperion-types/src/docker.rs`, `crates/hyperion-adapters/tests/docker_live.rs`
- Modify: `crates/hyperion-adapters/src/lib.rs`, `crates/hyperion-types/src/lib.rs`, `crates/hyperion-core/src/service/mod.rs` (`AdapterPort`), `crates/hyperion-core/src/real_adapter.rs`

**Interfaces:**
- Produces in `hyperion-types::docker`:
  - `DockerContainer { id, name, project: String, service: String, oneoff: bool, working_dir: String, image: String, image_id: String, state: String, health: Option<String>, exit_code: i64, oom_killed: bool, restart_count: i64, restart_policy: String, started_at: i64, finished_at: i64, ports: Vec<DockerPort>, cpu_pct_x100: Option<i64>, mem_bytes: Option<u64>, log_path: String, log_size_bytes: u64, log_max_size: Option<String> }`
  - `DockerPort { host_ip: String, host_port: u16, container_port: u16, proto: String }`
  - `DockerDisk { images_bytes: u64, volumes_bytes: u64, build_cache_bytes: u64, containers_bytes: u64, read_at: i64 }`
- Produces in `hyperion-adapters::docker`:
  - `ContainerId::parse(&str) -> Result<ContainerId, DockerError>` (`^[0-9a-f]{12,64}$`), `ImageRef::parse(&str)` (no leading `-`, charset `[A-Za-z0-9._:/@-]`, max 512)
  - `enum DockerCmd { Version, BuildxVersion, PsAll, Inspect(Vec<ContainerId>), Logs { id: ContainerId, tail: u32, since: Option<i64> }, Stats, SystemDf, ImageInspect(ImageRef) }` with `fn args(&self) -> Vec<String>`
  - `enum DockerError { NotInstalled, NotResponding, Failed(String), Parse(String) }`
  - `pub async fn run(cmd: &DockerCmd, max_bytes: usize) -> Result<Vec<u8>, DockerError>`
  - `parse_ps(&[u8])`, `parse_inspect(&[u8]) -> Result<Vec<DockerContainer>, DockerError>`, `parse_stats`, `parse_system_df`, `parse_version`
- Produces on `AdapterPort`: `async fn docker_read(&self, cmd: DockerCmd, max_bytes: usize) -> Result<Vec<u8>, DockerError>`, default `Err(NotInstalled)`.

- [ ] **Step 1: Write failing tests in `docker.rs`:**

```rust
#[test]
fn every_command_is_a_read() {
    const READS: &[&[&str]] = &[
        &["version"], &["buildx", "version"], &["ps"], &["inspect"], &["logs"],
        &["stats"], &["system", "df"], &["image", "inspect"],
    ];
    for cmd in sample_of_every_variant() {
        let args = cmd.args();
        assert!(READS.iter().any(|p| args.starts_with(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>())), "{args:?}");
    }
}

#[test]
fn inspect_drops_env_and_foreign_labels() {
    let parsed = parse_inspect(include_bytes!("../tests/fixtures/docker/inspect.json")).unwrap();
    assert!(!serde_json::to_string(&parsed).unwrap().contains("do-not-leak-7f3a"));
}

#[test]
fn inspect_reads_the_facts() { /* web: service "web", project "fixture", health, port 127.0.0.1:18080->80;
    crash: exit_code 3, restart_policy "on-failure"; job: exit_code 0; the plain container: project "" */ }

#[test]
fn ids_refuse_injection() {
    for bad in ["--help", "abc", "web;rm", "../x", ""] { assert!(ContainerId::parse(bad).is_err()); }
    assert!(ImageRef::parse("--output=/x").is_err());
    assert!(ImageRef::parse("ghcr.io/a/b:1.2@sha256:abc").is_ok());
}

#[tokio::test]
async fn hung_daemon_is_not_responding() {
    // Point a test-only binary path at a script that sleeps 30 s, timeout 1 s.
    assert!(matches!(run_with(&sleeper, &DockerCmd::PsAll, 1024, Duration::from_secs(1)).await,
                     Err(DockerError::NotResponding)));
}
```

- [ ] **Step 2: Run:** `cargo test -p hyperion-adapters docker`. Expected: FAIL, module missing.
- [ ] **Step 3: Implement.** Deserialize into private structs that have no `Env` field, so secrets are dropped by construction; keep only `com.docker.compose.*` labels. `kill_on_drop(true)`. Timeouts: 15 s default, 120 s for `SystemDf`. Binary missing = `NotInstalled`. `run` reads stdout and stderr with a hard `max_bytes` limit and stops the child beyond it. Paths: try `/usr/bin/docker`, then `/usr/local/bin/docker`.
- [ ] **Step 4: Run:** `cargo test -p hyperion-adapters docker`. Expected: PASS.
- [ ] **Step 5: Add `docker_live.rs`,** `#[ignore]`, in the style of `gitsync_live.rs`: runs each read command against real Docker and parses it.
- [ ] **Step 6: Commit.** `feat(docker): read-only adapter that cannot return secrets`

---

### Task 3: Schema, capabilities, module install state

**Files:**
- Create: `crates/hyperion-state/migrations/091_docker_module.sql`, `crates/hyperion-state/src/docker.rs`, `crates/hyperion-core/src/service/docker.rs`, `crates/hyperion-core/src/service/tests/docker.rs`
- Modify: `crates/hyperion-state/src/lib.rs`, `crates/hyperion-state/src/capabilities.rs`, `crates/hyperion-rpc/src/{codec,api}.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`

**Interfaces:**
- Tables: `docker_module` (single row: `cluster_installed`, `node_installed`, `buildx`, `installed_at`, `disk_json`, `disk_at`); `docker_nodes` (master: `node_id`, `installed_at`, `silent_since`, `alert_state`); `docker_projects` (`project`, `last_seen_at`, `gone_since`, `problem_since`, `alert_state`, `last_summary`); `docker_container_watch` (`project`, `service`, `restart_count`, `restart_window_json`); `docker_image_checks` (`image_ref`, `local_digest`, `remote_digest`, `state`, `checked_at`, `notified_digest`, `retry_after`); `url_monitors` and `url_monitor_samples` (Task 8).
- Capabilities appended at the end: `DockerView` (`docker_view`), `DockerLogs` (`docker_logs`). Admin gets them through `CapSet::all()`; Operator, Customer and Viewer do not.
- `DockerModuleState { cluster_installed: bool, node_installed: bool, buildx: bool, docker_version: Option<String> }`
- RPCs: `DockerModuleStatus`, `DockerClusterInstall`, `DockerClusterRemove`, `DockerNodeInstall`, `DockerNodeRemove`, `DockerNodeRegister { node_id, installed: bool }` (master's `docker_nodes`).
- `HostingService::docker_node_install(&self) -> Result<DockerModuleState, RpcError>`; `docker_module_enabled(&self) -> bool`.

- [ ] **Step 1: Write failing tests** in `service/tests/docker.rs`: `install_without_docker_says_so` (mock `docker_read` returns `NotInstalled`; error contains `Install Docker first`; state stays off); `install_records_buildx` (version ok, buildx `Failed`: installed, `buildx=false`); `remove_deletes_module_data` (rows seeded in all node tables are gone, hostings untouched); and in `capabilities.rs`: `docker_caps_are_appended_and_admin_only` (existing bits keep their numbers; `Admin` has both; `Operator`, `Customer`, `Viewer` have neither).
- [ ] **Step 2: Run:** `touch crates/hyperion-state/src/lib.rs && cargo test -p hyperion-core -p hyperion-state -- docker`. Expected: FAIL.
- [ ] **Step 3: Implement** migration, queries, capabilities, service methods and RPCs.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(docker): module install state and capabilities`

---

### Task 4: Verdict rules and node tick

**Files:**
- Create: `crates/hyperion-core/src/service/docker_verdict.rs`
- Modify: `service/docker.rs`, `service/mod.rs` (add `docker_snapshot: Arc<RwLock<Option<DockerNodeStatus>>>`, as `service_install_progress`), `service/tests/docker.rs`, `bin/hyperion-agent/src/ticks.rs`, `crates/hyperion-core/src/letters.rs`, `crates/hyperion-types/src/docker.rs`

**Interfaces:**
- `enum ContainerVerdict { Ok, Finished, Unhealthy, RestartLoop, Exited { code: i64, oom: bool } }`
- `enum ProjectVerdict { Ok, Problem { summary: String }, Gone }`
- `fn container_verdict(c: &DockerContainer, restarts_in_window: u32) -> ContainerVerdict`
- `struct RestartWatch { rises: HashMap<(String, String), Vec<i64>> }`, keyed by project and service, so recreating a container keeps its history, and stored in `docker_container_watch`
- `fn project_verdict(containers: &[DockerContainer], watch: &RestartWatch, now: i64) -> ProjectVerdict`
- `fn project_transition(alerting: bool, problem_since: Option<i64>, verdict: &ProjectVerdict, now: i64) -> Option<ProjectTransition>` with `const ALERT_GRACE_SECS: i64 = 180` and `enum ProjectTransition { Down, Up }`
- `DockerProject { name, containers: Vec<DockerContainer>, verdict: String, summary: String, hostings: Vec<String>, gone_since: Option<i64> }`
- `DockerNodeStatus { read_at: i64, daemon_ok: bool, daemon_error: Option<String>, projects: Vec<DockerProject>, disk: Option<DockerDisk> }`
- `HostingService::docker_tick(&self) -> Result<(), RpcError>`; `docker_overview(&self) -> Result<DockerNodeStatus, RpcError>`; `docker_forget_project(&self, project: String)`
- RPCs: `DockerOverview`, `DockerForgetProject { project }`.
- Alert kinds, `notify_admins_say`: `docker.project:<name>`, `docker.daemon`. Letter ids: `ops.docker_project_down`, `ops.docker_project_up`, `ops.docker_project_gone`, `ops.docker_daemon_down`, `ops.docker_daemon_up`.

- [ ] **Step 1: Write the failing table test** `verdict_table` with every row of the spec's table: running + no healthcheck = `Ok`; running + `unhealthy` = `Unhealthy`; `restarting` = `RestartLoop`; running with 3 restarts in window = `RestartLoop`; exited, policy `no`, code 0 = `Finished`; exited, policy `no`, code 1 = `Exited`; exited, policy `always`, code 0 = `Exited`; `oom_killed` = `Exited { oom: true }`.
- [ ] **Step 2: Write failing behaviour tests:**
  - `no_alert_inside_grace`: problem at t, no transition until t+180, `Down` at t+180.
  - `redeploy_is_quiet`: problem clears at t+120, no transition ever, `problem_since` reset.
  - `recreated_container_keeps_watch`: same project and service with a new id does not add restarts and does not read as gone.
  - `oneoff_never_alerts`: `oneoff: true` and exited 1 counts as nothing.
  - `project_gone_alerts_once`: known project with no containers gives one `Down`, no repeat, `Forget` clears it with no `Up`.
  - `daemon_down_is_one_alert_and_keeps_projects`: `NotResponding` gives one `docker.daemon`, projects not marked gone, `Up` on return.
  - `tick_does_nothing_when_not_installed`: `expect_docker_read().times(0)`.
  - `snapshot_has_no_secret`: fixture through `docker_tick`, serialized `docker_overview` has no `do-not-leak-7f3a`.
- [ ] **Step 3: Run:** `cargo test -p hyperion-core docker`. Expected: FAIL.
- [ ] **Step 4: Implement.** Restarts: 3 or more rises in the last 600 s. Tick every 30 s (`spawn_docker` with `every`): `PsAll` + `Inspect`, `Stats` every second tick, `log_size_bytes` by `fs::metadata` on `LogPath` (root-owned Docker directory), `SystemDf` hourly and cached in `docker_module.disk_json`. Project with empty compose label is `""`, shown as "other containers". `docker_overview` returns the cached snapshot, or reads once if none exists yet.
- [ ] **Step 5: Run** the same command. Expected: PASS.
- [ ] **Step 6: Commit.** `feat(docker): node tick, verdicts and problem alerts`

---

### Task 5: `/docker` page and module install UI

**Files:**
- Create: `bin/hyperion-web/src/handlers/docker.rs`, `bin/hyperion-web/templates/docker.html`, `docker_stack.html`
- Modify: `bin/hyperion-web/src/lib.rs` (routes), `handlers/mod.rs`, `handlers/jobs.rs` (labels, `get_nav_status`), `handlers/settings/chrome.rs` (`CARDS`: `("docker-module", "panel")`), `handlers/settings/page_panel.rs`, `templates/settings_panel.html`, `templates/base.html`, `static/app.js`, `bin/hyperion-web/tests/devserver.rs`, `tests/web_e2e.rs`

**Interfaces:**
- Consumes: `DockerOverview`, `DockerModuleStatus`, install RPCs from Tasks 3 and 4; `fan_out_reporting` and `node_auth_warning`.
- Routes: `GET /docker`, `GET /docker/{node}/{project}`, `POST /docker/install-cluster`, `POST /docker/remove-cluster`, `POST /docker/nodes/{node}/install`, `POST /docker/nodes/{node}/remove`, `POST /docker/{node}/{project}/forget`.
- Job kinds: `docker_node_install`, `docker_node_remove`.
- `pub(crate) async fn collect_status(state: &SharedState) -> (Vec<NodeDockerRow>, Vec<(NodeSummary, DispatchError)>)`, only nodes in `docker_nodes`. `NodeDockerRow { node_id, label, status: NodeDockerState }` with `enum NodeDockerState { Ok(DockerNodeStatus), OldAgent, Unreachable }`.
- `/api/nav-status` gains `docker_installed: bool`, `docker_problems: i64`. The nav link has `hidden`, `data-require-caps="docker_view"`, `data-require-scope-all`, and the poller unhides it.

- [ ] **Step 1: Write failing e2e tests** in `web_e2e.rs`: `docker_requires_capability` (viewer and customer redirected, admin 200); `custom_role_without_scope_all_refused` (has `docker_view`, assigned scope, redirected); `docker_off_redirects_to_settings` (not installed: `/docker` goes to `/settings/panel#docker-module`, nav status `docker_installed: false`); `old_agent_says_update_first`; `failed_node_shows_incomplete_warning`; `node_install_is_a_job` (303 to `/jobs/`).
- [ ] **Step 2: Run:** `cargo test -p hyperion-web --test web_e2e`. Expected: FAIL.
- [ ] **Step 3: Implement.** Page: verdict line, then stacks per node, problems first. Stack row: services, state, placeholders for the update badge and hosting. Stack detail: container facts, largest logs, disk. Log warning when a log exceeds 1 GiB with no `log_max_size`. Removal uses `data-confirm-*` on the form and names what is deleted and that Docker is left alone. Normalize the master's rows to `LOCAL_NODE_SENTINEL`. Classify `OldAgent` as `cluster_sync.rs` does. Node install and removal also call `DockerNodeRegister` on the master, so `docker_nodes` holds the fan-out list. Add a seeded stub to `devserver.rs`.
- [ ] **Step 4: Run** the same command, then `cargo test -p hyperion-web --test template_lint`. Expected: PASS.
- [ ] **Step 5: Walk it.** `preview_start devpanel`, log in, open `/settings/panel`, install, open `/docker`, then a screenshot at desktop and mobile width. Expected: no console errors, no nav item before install.
- [ ] **Step 6: Commit.** `feat(docker): status pages and module install`

---

### Task 6: Logs

**Files:**
- Create: `bin/hyperion-web/templates/_docker_logs.html`
- Modify: `service/docker.rs`, `service/tests/docker.rs`, `handlers/docker.rs`, `templates/docker_stack.html`, RPC files

**Interfaces:**
- `DockerLogRequest { project: String, container: Option<String>, lines: u32, since_cursor: Option<String>, filter: Option<String>, audit_actor: Option<String> }`
- `DockerLogChunk { lines: Vec<DockerLogLine>, cursor: Option<String>, truncated: bool }`, `DockerLogLine { ts: String, service: String, text: String }`
- `HostingService::docker_logs(&self, req: DockerLogRequest) -> Result<DockerLogChunk, RpcError>`; RPC `DockerLogs(DockerLogRequest)`.
- Pure: `strip_ansi(&str) -> String`; `lines_after(lines, cursor)`; `merge_by_ts(Vec<Vec<DockerLogLine>>, limit)`.
- Constants: default 200, `MAX_LOG_LINES = 2000`, `MAX_LOG_BYTES = 1024 * 1024`.
- Routes: `GET /docker/{node}/{project}/logs` (needs `DockerLogs`, `scope_all`, returns the partial for htmx).

- [ ] **Step 1: Write failing tests:**
  - `container_must_exist_in_snapshot`: unknown name gives a validation error, no `docker_read` call.
  - `form_value_never_reaches_docker`: `--help` as `container` gives no `docker_read` call.
  - `lines_are_capped`: `lines: 999999` requests tail 2000.
  - `huge_output_is_truncated`: mock returns 5 MiB; response under `MAX_LOG_BYTES`, `truncated: true`.
  - `gigantic_single_line_is_cut`: one 5 MiB line, same result.
  - `ansi_stripped`: `"\x1b[31mred\x1b[0m"` gives `"red"`.
  - `filter_is_case_insensitive`.
  - `follow_does_not_repeat`: `lines_after` drops lines at or before the cursor.
  - `stack_logs_merge_by_time`: two containers, sorted, each tagged with its service.
  - `audit_only_when_actor_given`: one audit row with `audit_actor: Some(..)`, none with `None`.
  - In `web_e2e.rs`: `logs_need_their_own_capability`, a role with `docker_view` but not `docker_logs` gets refused; `log_markup_is_escaped`: a `<script>` line renders as text.
- [ ] **Step 2: Run:** `cargo test -p hyperion-core docker`, then `cargo test -p hyperion-web --test web_e2e`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Logs` uses `--timestamps`. `since` comes from the cursor. Follow polls every 5 s via htmx, stop when the panel is closed, and send no `audit_actor`. First open sends `ctx.username`.
- [ ] **Step 4: Run** the same commands. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(docker): read container and stack logs`

---

### Task 7: Outbound alerts and silent nodes

**Files:**
- Create: `bin/hyperion-web/src/docker_watch.rs`
- Modify: `crates/hyperion-core/src/service/notify.rs`, `service/docker.rs`, `service/tests/docker.rs`, `bin/hyperion-web/src/main.rs` or wherever `notify_collector::spawn` is called, RPC files, `letters.rs`

**Interfaces:**
- `HostingService::docker_outbound(&self, subject: &str, body: &str, kind: &str)`: sends to `self.slack_default_webhook` through `http_post_json` and to the master's alert recipient list (the same source `get_alert_recipients` in `page_alerts.rs` reads) through `notify_email`, kind `"docker"`. No-op on a worker.
- `fn is_outbound_docker_kind(kind: &str) -> bool`, true for the `docker.` prefix.
- RPC `DockerNodeSilent { node_id: String, silent: bool }`: records in `docker_nodes`, returns whether a transition happened, and alerts with `docker.node:<id>`.
- `pub fn spawn(state: SharedState)` in `docker_watch.rs`; `const SILENT_AFTER_SECS: i64 = 180`, 60 s loop, master only, cluster module installed only.

- [ ] **Step 1: Write failing tests:**
  - `ingest_sends_docker_alert_outbound`: a `docker.project:x` row produces one Slack POST and email.
  - `reingesting_a_batch_sends_nothing`: same batch twice, still one send (**Review Focus 4**). Send only for rows actually written.
  - `other_kinds_stay_bell_only`: `monitor.down:x` sends nothing here.
  - `master_own_alert_goes_outbound`: `notify_admins` with a `docker.` kind on a non-worker sends once.
  - `worker_parks_and_does_not_send`.
  - `outbound_body_has_no_log_lines`: body built from a project summary has no log text.
  - `node_silent_alerts_once_and_recovers`: `DockerNodeSilent` true twice gives one `Down`; false gives one `Up`.
- [ ] **Step 2: Run:** `cargo test -p hyperion-core docker`. Expected: FAIL.
- [ ] **Step 3: Implement.** Real Slack delivery from a worker's alert is confirmed in Task 12 Step 7. `docker_watch` keeps first-failed time in memory; a transient failure under 180 s never calls the RPC.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(docker): send alerts out through the master, flag silent nodes`

---

### Task 8: URL checks

**Files:**
- Create: `crates/hyperion-state/src/url_monitors.rs`, `crates/hyperion-core/src/service/url_monitor.rs`, `service/tests/url_monitor.rs`, `bin/hyperion-web/templates/_url_monitors.html`
- Modify: migration `091`, `docker_watch.rs`, `handlers/monitoring.rs`, `templates/monitoring.html`, `handlers/docker.rs` (routes), RPC files, `service/mod.rs`

**Interfaces:**
- `url_monitors`: `id`, `url`, `interval_secs` (min 30, default 60), `expected_status` nullable, `alert_after_fails` (default 3), `alert_email`, `alert_slack_webhook`, `alert_webhook_url`, `node_id` nullable, `node_manual`, `alert_state`, `last_alert_at`, `pending_alert` nullable (`down`, `up`), `cert_expires_at`, `cert_alert_day`.
- `url_monitor_samples`: `monitor_id`, `sampled_at`, `success`, `http_status`, `response_ms`, `error_message`. Pruned to 7 days by the tick.
- `UrlMonitorView { id, url, node_id, alert_state, success_pct_24h, avg_ms_24h, last_error, cert_expires_at, .. }`
- `UrlMonitorEvent { id, url, node_id: Option<String>, down: bool, error: Option<String> }`
- RPCs: `UrlMonitorList`, `UrlMonitorSet(UrlMonitorInput)`, `UrlMonitorDelete { id }`, `UrlMonitorTick` (returns events still pending), `UrlMonitorAlert { id, context: UrlAlertContext }` with `UrlAlertContext { node_unreachable: bool, stack_summary: Option<String> }`.
- `pub(super) fn url_check_outcome(result: HttpProbeResult, expected: Option<i64>) -> HttpProbeResult`
- `pub(super) fn parse_cert_expiry(curl_certs: &str) -> Option<i64>`; `fn cert_alert_due(expires_at, now, last_day) -> Option<i64>`, days `14` and `3`.
- Web: `fn derive_node(state, url) -> Option<String>` calls `find_hosting_anywhere` on the URL's hostname.

- [ ] **Step 1: Write failing tests,** using `spawn_test_site` and `replay_monitor` conventions:
  - `reuses_anti_flapping`: replay of a flapping sequence gives the same transitions as `replay_probes`.
  - `expected_status_is_honoured`: 401 with `expected: 401` passes; 200 with `expected: 401` fails.
  - `one_slow_site_does_not_delay_others`: a hanging site and an up one, both sampled within one tick, under `PROBE_MAX_TIME`.
  - `pending_alert_survives_until_acknowledged`: `UrlMonitorTick` twice returns the event twice; after `UrlMonitorAlert`, none.
  - `alert_includes_context`: `stack_summary` in the outbound body; `node_unreachable` changes the wording.
  - `no_check_runs_when_module_off`.
  - `set_validates_url`: refuses non-http(s), embedded credentials, and an interval under 30.
  - `cert_alerts_at_14_and_3_days_once_each`.
  - `samples_pruned_after_7_days`.
  - In `web_e2e.rs`: `monitoring_lists_both_kinds`; `node_derived_on_save_and_override_wins`; `no_matching_hosting_is_allowed`.
- [ ] **Step 2: Run:** `touch crates/hyperion-state/src/lib.rs && cargo test -p hyperion-core url_monitor`. Expected: FAIL.
- [ ] **Step 3: Implement.** Sample through `probe_http` concurrently, bound 20. Decide through `monitor_transition`. Cert: `curl --certinfo -w '%{certs}'` once per check per hour on https; test the parse against a real curl output captured on tes-1, since macOS curl differs. `docker_watch` calls `UrlMonitorTick` every 15 s. For each event it pings the stored node with `dispatch_to_node`, reads its `DockerOverview`, finds the stack whose `hostings` holds the URL's hostname, and calls `UrlMonitorAlert`. Re-derive the node on save and on recovery unless `node_manual`. Show the master-box limitation on the form. Channels: per check, falling back to the global ones.
- [ ] **Step 4: Run** the same command, then `cargo test -p hyperion-web --test web_e2e`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(monitoring): URL checks run from the master`

---

### Task 9: Reverse proxy from a stack

**Files:**
- Modify: `bin/hyperion-web/src/handlers/hostings/create.rs` (`NewQuery`, `get_new`), `crates/hyperion-core/src/service/docker.rs`, `service/tests/docker.rs`, `crates/hyperion-state/src/hostings.rs`, `handlers/docker.rs`, `templates/docker_stack.html`, `templates/docker.html`, `templates/hostings_detail.html`, `tests/web_e2e.rs`

**Interfaces:**
- `hostings::list_reverse_proxies(pool) -> Result<Vec<(String, String)>, StateError>`: `(domain, upstream)` for live reverse-proxy hostings.
- `pub fn loopback_port(url: &str) -> Option<u16>`: true only for `127.0.0.1`, `localhost`, `[::1]`.
- `fn link_hostings(projects: &mut [DockerProject], proxies: &[(String, String)])`
- `enum ProxyOffer { Offer { url: String, public_bind: bool }, Conflict, NotTcp }`; `pub fn proxy_offer(p: &DockerPort) -> ProxyOffer`
- `NewQuery` gains `site_type`, `proxy_upstream_url`, `target_node`.
- `GET /docker/hosting-chip?selector=` (lazy partial for hosting detail, needs `DockerView` and `scope_all`).

- [ ] **Step 1: Write failing tests:**
  - `loopback_port` for `http://127.0.0.1:3000` = 3000, `http://localhost:3000/` = 3000, `https://[::1]:8443` = 8443, `http://10.0.0.1:3000` = None, `http://127.0.0.1` = None.
  - `link_found_for_hand_made_proxy`: hosting upstream on a published port links it.
  - `link_ignores_other_hosts`: `http://10.0.0.5:3000` does not.
  - `proxy_offer`: `127.0.0.1:18080` = Offer, not public; `0.0.0.0:18080` and `:::18080` = Offer, public; host port 80 or 443 = Conflict; udp = NotTcp.
  - In `web_e2e.rs`: `prefill_fills_the_wizard`; `prefill_ignores_bad_values` (`javascript:alert(1)`, `"><script>`, an unknown `site_type`, an unknown `target_node` all fall back to empty); `submit_still_validates` (`validate_upstream_url` still refuses on POST); `no_published_port_explains_itself`.
- [ ] **Step 2: Run:** `cargo test -p hyperion-core docker && cargo test -p hyperion-web --test web_e2e`. Expected: FAIL.
- [ ] **Step 3: Implement.** Upstream is `http://127.0.0.1:<port>`. A stack shows one "Add reverse proxy" per offered port and the linked hostings. No link table.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Verify the firewall claim on tes-1.** Publish `0.0.0.0:18081` from a throwaway container, add a temporary table `nft add table inet hyperion_test`, with an input-hook chain dropping `tcp dport 18081`, and `curl` from outside. Expected to answer 200, proving the bypass. Delete the table and the container, then word the warning from what was seen. This only drops one test port and cannot affect SSH.
- [ ] **Step 6: Commit.** `feat(docker): add a reverse-proxy hosting from a discovered stack`

---

### Task 10: Image updates

**Files:**
- Create: `crates/hyperion-adapters/src/docker_registry.rs`, `crates/hyperion-core/src/service/docker_updates.rs`
- Modify: `service/tests/docker.rs`, `service/mod.rs` (`AdapterPort`), `real_adapter.rs`, `bin/hyperion-agent/src/ticks.rs`, `templates/docker.html`, `docker_stack.html`, `letters.rs`

**Interfaces:**
- `enum RemoteDigestError { RateLimited, Unauthorized, Unavailable(String), Unsupported }`
- `AdapterPort::docker_remote_digest(&self, image: ImageRef) -> Result<String, RemoteDigestError>`, default `Unsupported`.
- `enum ImageUpdateState { UpToDate, UpdateAvailable, NotRecreated, CannotVerify { reason: String } }`
- `struct LocalImage { image_ref: String, repo_digests: Vec<String>, image_id: String, pinned: bool }`; `ImageCheckRow` is the `docker_image_checks` row in `hyperion-state`
- `fn image_state(local: &LocalImage, container_image_id: &str, remote: Result<&str, &RemoteDigestError>, last: Option<&ImageCheckRow>) -> ImageUpdateState`
- `HostingService::docker_updates_tick(&self)`: daily, offset by a random delay under 6 h, once per unique reference, 429 sets `retry_after` to next day.
- `DockerContainer` gains `update: Option<ImageUpdateState>`, `#[serde(default)]`.

- [ ] **Step 1: Measure on tes-1.** Using Docker's documented `ratelimit-remaining` header on `ratelimitpreview/test`, read the budget, run `docker buildx imagetools inspect nginx:alpine` 3 times and read it again, then repeat with a `HEAD` on the manifest using an anonymous token. Keep to these few calls. Pick the mechanism that leaves the budget untouched. Private images must still work through Docker's own credential store, so combine if needed. If buildx is used, add `DockerCmd::ImagetoolsInspect(ImageRef)` and its allow-list entry. Note the numbers in the commit message.
- [ ] **Step 2: Write failing tests:**
  - `same_digest_is_up_to_date`; `new_digest_is_update_available`.
  - `local_build_cannot_verify`: no `RepoDigests`.
  - `digest_pinned_cannot_verify`.
  - `registry_error_never_says_up_to_date`: `Unavailable` with no history = `CannotVerify`.
  - `failed_check_keeps_last_answer`: `UpdateAvailable` then `RateLimited` stays `UpdateAvailable`.
  - `rate_limit_backs_off_a_day`: no further call before `retry_after`.
  - `pulled_not_recreated`: container `image_id` differs from the tag's local id.
  - `notifies_once_per_digest`: same digest on the next day sends nothing; a newer one sends again.
  - `one_lookup_per_unique_image`: 3 containers on the same image, one `docker_remote_digest` call.
  - `tick_does_nothing_when_not_installed`.
- [ ] **Step 3: Run:** `cargo test -p hyperion-core docker`. Expected: FAIL.
- [ ] **Step 4: Implement.** Never read `~/.docker/config.json` from Hyperion code; if `HEAD` needs a token, only anonymous tokens are fetched.
- [ ] **Step 5: Run** the same command. Expected: PASS.
- [ ] **Step 6: Commit.** `feat(docker): report available image updates`

---

### Task 11: Docs and full suite

**Files:**
- Modify: `README.md`, `docs/RUNBOOK.md`

- [ ] **Step 1: Document** the module: what it does and does not do, how to install and remove it, Docker as a prerequisite. README's feature list and the "Docker" line near :144.
- [ ] **Step 2: Run:** `touch crates/hyperion-state/src/lib.rs && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo deny check`. Expected: all pass.
- [ ] **Step 3: Commit.** `docs(docker): describe the monitoring module`

---

### Task 12: Real node verification on tes-1

tes-1 is a worker of the production master `hos-1`. Do not touch `hos-1`. **Ask the owner before Step 1** whether the branch's agent may run on tes-1; it has one test hosting. RPC is additive, so the master keeps working with it, but the panel UI cannot be walked on `hos-1` until a release. This task exercises the agent through its RPC socket; the UI walk uses the dev panel.

**Files:**
- Create: `crates/hyperion-core/tests/docker_live_rpc.rs` (`#[ignore]`): calls the agent socket through `hyperion_rpc_client::call`, with the request chosen by the `DOCKER_RPC` environment variable (`install`, `overview`, `logs`, `forget`, `updates`), and prints the JSON. It is a test harness, not a CLI.

- [ ] **Step 1: Build the branch on tes-1** in a scratch directory. Keep the installed `hyperion-agent` binary for rollback, swap in the new one, restart the agent. Expected: `systemctl is-active hyperion-agent` prints `active`, the test hosting returns 200.
- [ ] **Step 2: Off is off.** Before install, sample `pgrep -a -P $(pidof hyperion-agent)` every second for 70 s and read the agent log. Expected: no `docker` child process, no module log lines.
- [ ] **Step 3: Install the module** through `docker_live_rpc`. Start a stack with `web`, `crash`.
- [ ] **Step 4: Scenarios, one at a time, checking `DockerOverview` and the outbox after each:**
  - `docker kill` on `web`: problem after about 180 s, exit code 137 shown; recovery alert after start.
  - `compose up -d --force-recreate`: quiet.
  - `crash` with `restart: always`: restart loop.
  - `compose down`: one "gone" alert; `DockerForgetProject` clears it.
  - `systemctl stop docker docker.socket`: one daemon alert, projects kept; start again: recovery. Confirm nginx, the agent and the hosting are unaffected.
  - A `docker logs` flood container: `DockerLogs` within the byte cap, agent RSS steady.
  - `docker_updates_tick` with an unreachable registry (temporary `/etc/hosts` entry, removed after): `CannotVerify`, then real result.
- [ ] **Step 5: Secrets.** Stack with `SECRET=do-not-leak-7f3a` in env; the string is absent from `DockerOverview` output and from the state DB (`grep -c` on a `.dump`).
- [ ] **Step 6: Clean up.** Remove test stacks and images, restore the original agent binary unless the owner says keep it. Expected: `docker ps -aq | wc -l` prints `0`, site returns 200.
- [ ] **Step 7: Open the PR.** After this, ask the owner about a release tag and a panel walk on `hos-1` with a real Slack delivery from tes-1, then with their real stacks. Those two cannot be proved before release.
