# PHP own masters, phases 0 and 1: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator run one system user's PHP on its own FPM master inside its own slice, on nodes that opt in, and report per node whether that is possible. No caps yet.

**Architecture:** A per-version systemd template runs one master per system user, configured outside `pool.d`, listening on a new socket path. A small table records which users are converted. One routing layer in the service decides between shared and own for every pool write and removal, so callers do not branch. Conversion is a background job and is reversible.

**Tech Stack:** Rust, askama, sqlx/SQLite, axum, mockall `MockAdapterPort`, systemd 252+, cgroup v2.

**Spec:** `docs/superpowers/specs/2026-11-03-php-site-hard-caps-design.md`

**Out of scope, deliberately:** phase 2 (bulk), phase 3 (wp-cli and cron in the slice), phase 4 (caps, `cpu_cap_pct`, `mem_cap_pct`, `raise_room`, OOM scan split). The pilot's results decide those, so they get their own plan. **This plan has a stop gate after Task 2.**

## Global Constraints

- Debian 12+ only, systemd 252 or later, cgroup v2 with `cpu` and `memory` controllers.
- Node setting `[php] own_masters` defaults to `false`. With it off, every rendered file, vhost and code path behaves exactly as today.
- Unit template must contain `CPUWeight=100`, `OOMPolicy=continue`, `Slice=hyperion-sites-%i.slice`, `PartOf=php<ver>-fpm.service`, `Restart=on-failure`, `RestartSec=2`.
- Config path `/etc/hyperion/fpm/<ver>/<user>.conf`. Socket `/run/php/<ver>/site/<user>.sock`. PID `/run/php/<ver>/site/<user>.pid`. Log `/var/log/php<ver>-fpm.log`.
- `process_control_timeout = 10s` in each own master's `[global]`. `opcache.memory_consumption=256` via `-d` on `ExecStart`.
- Units are instantiated with the `systemd-escape` form of the user (`im-port.ed` becomes `im\x2dport.ed`), `%I` recovers the real name.
- Mode is keyed by system user, on the node. Converting a user converts all of that user's PHP versions.
- Conversion order: start own master, set mode, rewrite vhosts, `nginx -t` and reload, drop old pool file, **no shared reload**.
- RAM estimate 11 MB per system user, floor from `phpworkers::NODE_FREE_RAM_DIVISOR` (free RAM stays at or above total / 5).
- Pool files use `;` comments only (`render_uses_only_semicolon_comments`).
- Every slow web action goes through `spawn_job`. Confirm dialogs go on the `<form>`, not the button.
- Rewrites of an existing pool must keep stored limits (`fpm_ensure_with_limits` rule, PR #230).
- Run `cargo test --workspace --all-targets`; plain `cargo check --workspace` skips `mod tests`. A new migration may need `touch crates/hyperion-state/src/lib.rs` before `--workspace` sees it.

## Review Focus

- **User with two hostings, one suspended:** the active one keeps serving, and resume uses the own master. Pinned in Task 5.
- **User on two PHP versions:** both versions convert or neither does, with no half-state after a failure on the second. Pinned in Task 6.
- **Agent restart on a converted node:** no shared or own master restarts when no file changed, and stored limits survive. Pinned in Task 7.
- **Hyphenated or dotted imported user:** unit name, slice name and config path all resolve. Pinned in Task 1 and Task 8's script.
- **Node set back to off with converted users:** those users keep working and can be rolled back; only new conversions stop. Pinned in Task 6.

---

### Task 1: Names and preflight verdict (pure)

**Files:**
- Create: `crates/hyperion-types/src/fpm_own.rs`
- Modify: `crates/hyperion-types/src/lib.rs`, `crates/hyperion-types/src/php.rs`

**Interfaces:**
- Produces:
  - `fpm_own::instance_name(user: &str) -> String`, `unit_name(ver: PhpVersion, user: &str) -> String`, `template_name(ver: PhpVersion) -> String`, `slice_name(user: &str) -> String`
  - `PhpVersion::own_socket_path(self, user: &str) -> String`, `own_config_path(self, user: &str) -> String`, `own_config_dir(self) -> String`
  - `fpm_own::MB_PER_USER: i64 = 11`
  - `#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)] pub struct PreflightFacts { cgroup_controllers: Option<String>, systemd_version: Option<u32>, swap_total_kib: i64, mem_total_mb: Option<i64>, mem_available_mb: Option<i64>, php_users: i64, own_users: i64 }`
  - `pub enum PreflightBlock { NoCgroup2, MissingController(String), OldSystemd(u32), UnknownSystemd, LowRam { need_mb: i64, free_after_mb: i64, floor_mb: i64 } }` (serde)
  - `pub struct Preflight { blocks: Vec<PreflightBlock>, has_swap: bool, extra_mb: i64, php_users: i64, own_users: i64 }`, `Preflight::ok(&self) -> bool`
  - `fpm_own::judge(facts: &PreflightFacts) -> Preflight`

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn escapes_like_systemd_escape() {
    assert_eq!(instance_name("alice_cz"), "alice_cz");
    assert_eq!(instance_name("im-port.ed"), r"im\x2dport.ed");
    assert_eq!(unit_name(PhpVersion::V8_4, "im-port.ed"), r"hyperion-fpm8.4@im\x2dport.ed.service");
    assert_eq!(slice_name("im-port.ed"), r"hyperion-sites-im\x2dport.ed.slice");
    assert_eq!(template_name(PhpVersion::V8_3), "hyperion-fpm8.3@.service");
}
#[test] fn own_paths() {
    assert_eq!(PhpVersion::V8_3.own_socket_path("a"), "/run/php/8.3/site/a.sock");
    assert_eq!(PhpVersion::V8_3.own_config_path("a"), "/etc/hyperion/fpm/8.3/a.conf");
}
#[test] fn judge_blocks_what_cannot_work() { /* no controllers file: NoCgroup2; "memory pids": MissingController("cpu"); systemd 251: OldSystemd(251); None: UnknownSystemd */ }
#[test] fn judge_counts_only_unconverted_users_against_ram() {
    // total 4096, floor 819. available 1000, 30 users, 10 already own: need 220, free_after 780: LowRam.
    // available 1100: ok, extra_mb 220.
}
#[test] fn swap_is_reported_but_never_a_block() { /* swap_total_kib 1024: has_swap, ok() */ }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hyperion-types fpm_own`
Expected: FAIL, module does not exist.

- [ ] **Step 3: Implement.** Escape per `systemd.unit(5)`: ASCII alphanumerics, `:`, `_`, `.` stay (a leading `.` is escaped), everything else becomes `\xHH`. Floor from `phpworkers::NODE_FREE_RAM_DIVISOR`. Unknown RAM (`None`) is not a block, matching `raise_room`.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p hyperion-types fpm_own`
Expected: PASS

- [ ] **Step 5: Commit** `feat(php): name own FPM units and judge whether a node can run them`

### Task 2: Fleet report on the Nodes page, and the node setting (phase 0)

**Files:**
- Modify: `crates/hyperion-adapters/src/phpfpm.rs`, `crates/hyperion-core/src/service/mod.rs` (`AdapterPort`, `HostingService` field and `with_fpm_own_masters`), `crates/hyperion-core/src/real_adapter.rs`, `crates/hyperion-core/src/service/stats.rs`, `crates/hyperion-rpc/src/codec.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`, `bin/hyperion-agent/src/config.rs`, `bin/hyperion-agent/src/main.rs:439`, `bin/hyperion-web/src/handlers/install.rs`, `bin/hyperion-web/src/handlers/node_settings.rs`, their templates
- Test: `crates/hyperion-core/src/service/tests/nodes.rs`, `bin/hyperion-web/tests/web_e2e.rs`, `bin/hctl` docs only if the setting is listed there

**Interfaces:**
- Consumes: `PreflightFacts`, `judge`
- Produces:
  - `phpfpm::preflight_facts() -> PreflightFacts` (reads `/sys/fs/cgroup/cgroup.controllers`, `systemctl --version`, `/proc/swaps` or `SwapTotal`, `redis::mem_total_kib`, `MemAvailable`)
  - `AdapterPort::fpm_preflight_facts(&self) -> PreflightFacts`, default `PreflightFacts::default()`
  - `HostingService::fpm_own_preflight(&self) -> Result<Preflight, RpcError>`: fills `php_users` (distinct `system_user` of active PHP hostings) and `own_users` (0 until Task 3)
  - `Request::NodeFpmPreflight`, `Response::NodeFpmPreflight(Preflight)`
  - `HostingService.fpm_own_masters: bool`, agent `[php] own_masters`, `PhpSection`, following `[snapshots]` end to end

- [ ] **Step 1: Write failing tests.** Service: `preflight_counts_distinct_php_users` (two hostings sharing a user count 1; static and suspended count 0). Config: `own_masters_defaults_off` (a TOML with no `[php]` parses to `false`). Web: Nodes page shows `Own PHP masters: possible, about N MB more` for an ok verdict, and names the block otherwise; an older node answering 400 shows `not reported` and does not break the row (pattern: `HostingUsageRange` fallback).

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hyperion-core preflight_counts && cargo test -p hyperion-web own_masters`
Expected: FAIL

- [ ] **Step 3: Implement.** Read facts once per Nodes page load, per node, through `dispatch_to_node`. Show in the row's details, plus swap present or absent. Setting is a checkbox on `/install/node-settings` (mind `synthesize_unchecked_checkboxes`), and `NodeConfigSet` must accept the `php` section. Help text: "New sites and sites you convert run on their own PHP process. About 11 MB per site."

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --workspace --all-targets preflight own_masters`
Expected: PASS

- [ ] **Step 5: Commit** `feat(nodes): report whether each node can run per-site PHP masters`

> **STOP GATE. Ship this and read the Nodes page across the fleet before Task 3.** If many production nodes fail preflight, stop and go back to the operator (spec, phase 0). Also record whether any node has swap, because the pilot node must have swap if any does. **Ask the operator to name the pilot node here (spec open question 3).**

### Task 3: Own-master files and lifecycle in the adapter

**Files:**
- Create: `crates/hyperion-adapters/templates/systemd-fpm-own.service.j2`
- Modify: `crates/hyperion-adapters/src/phpfpm.rs`, `crates/hyperion-adapters/templates/phpfpm-pool.conf.j2`
- Create: `crates/hyperion-state/migrations/091_fpm_own_master.sql`, `crates/hyperion-state/src/fpm_own.rs`

**Interfaces:**
- Produces:
  - `PoolInput.own_master: bool`, default `false`; `render` emits the `[global]` block and own `listen` when true
  - `phpfpm::render_own_unit(ver: PhpVersion) -> Result<String, AdapterError>`
  - `pub enum OwnAction { Nothing, Start, Reload, Restart }`
  - `phpfpm::own_change_action(prev: Option<&str>, next: &str, unit_active: bool) -> OwnAction`
  - `phpfpm::ensure_own_pool(input: &PoolInput<'_>) -> Result<OwnAction, AdapterError>`
  - `phpfpm::delete_own_pool(user: &str, ver: PhpVersion) -> Result<(), AdapterError>`
  - `phpfpm::own_ready(user: &str, ver: PhpVersion) -> bool`
  - `phpfpm::drop_shared_pool_file(user: &str, ver: PhpVersion) -> Result<(), AdapterError>` (no reload)
  - `phpfpm::ensure_own_units() -> Result<(), AdapterError>`
  - `phpfpm::test_own_config(ver: PhpVersion, path: &Path) -> Result<(), AdapterError>`
  - `hyperion_state::fpm_own::{is_own(pool, user) -> Result<bool>, set_own(pool, user, now), clear_own(pool, user), list_own(pool) -> Result<Vec<String>>}`
  - Table `fpm_own_master(system_user TEXT PRIMARY KEY, converted_at INTEGER NOT NULL)`

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn own_config_has_global_and_new_socket() {
    let mut i = PoolInput::defaults("alice_cz", "alice.cz", PhpVersion::V8_3); i.own_master = true;
    let out = render(&i).unwrap();
    assert!(out.starts_with("[global]\n"));
    assert!(out.contains("pid = /run/php/8.3/site/alice_cz.pid\n"));
    assert!(out.contains("error_log = /var/log/php8.3-fpm.log\n"));
    assert!(out.contains("daemonize = no\n"));
    assert!(out.contains("process_control_timeout = 10s\n"));
    assert!(out.contains("listen = /run/php/8.3/site/alice_cz.sock\n"));
    assert!(out.contains("pm.max_children = 5"));
}
#[test] fn shared_render_is_unchanged() { /* own_master false: no "[global]", listen = /run/php/8.3/alice_cz.sock */ }
#[test] fn unit_template_carries_every_required_line() {
    let u = render_own_unit(PhpVersion::V8_4).unwrap();
    for l in ["CPUWeight=100","OOMPolicy=continue","Slice=hyperion-sites-%i.slice","PartOf=php8.4-fpm.service","Type=notify",
              "Restart=on-failure","RestartSec=2","ExecReload=/bin/kill -USR2 $MAINPID",
              "/etc/hyperion/fpm/8.4/%I.conf -d opcache.memory_consumption=256",
              "ExecStartPre=/usr/bin/install -d -m 0755 /run/php/8.4/site"] { assert!(u.contains(l), "{l}"); }
}
#[test] fn change_action_table() {
    // same text + active: Nothing. same text + inactive: Start. None + any: Start.
    // changed + active: Reload. listen.owner changed + active: Restart. changed + inactive: Start.
}
```

State: `set_get_clear_round_trip`, in `crates/hyperion-state/src/fpm_own.rs`.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hyperion-adapters phpfpm && cargo test -p hyperion-state fpm_own`
Expected: FAIL

- [ ] **Step 3: Implement.** `ensure_own_pool`: write with the same backup and rollback shape as `ensure_pool`, gate on `test_own_config`, then act. `Start` is `systemctl enable --now <unit>` after `reset-failed`. `delete_own_pool`: `systemctl disable --now`, then remove the file, tolerating both already gone. `ensure_own_units`: for each version whose `/etc/php/<ver>/fpm` exists, write the template if changed, create the config dir at 0755 root, `daemon-reload` only if anything changed. Why `Restart` exists: `chown` is not reapplied to a bound socket (see `rerender_fpm_pools` doc).

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p hyperion-adapters phpfpm && cargo test -p hyperion-state fpm_own`
Expected: PASS

- [ ] **Step 5: Commit** `feat(php): render and manage a per-user FPM master unit`

### Task 4: Socket path in the vhost

**Files:**
- Modify: `crates/hyperion-types/src/hosting.rs`, `crates/hyperion-core/src/service/provision.rs:770` (`get`), `crates/hyperion-adapters/src/nginx.rs`, `crates/hyperion-adapters/templates/nginx-vhost.conf.j2:319,334,354,379`, `crates/hyperion-core/src/real_adapter.rs:1053`, `bin/hyperion-web/templates/hostings_detail.html:996`

**Interfaces:**
- Consumes: `fpm_own::is_own`, `own_socket_path`
- Produces: `HostingDetail.fpm_own_master: bool` (`#[serde(default)]`), `VhostInput.fpm_own_master: bool`, template variable `fpm_socket`

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn vhost_points_at_the_own_socket() {
    // php_version Some("8.3"), fpm_own_master true:
    assert_eq!(out.matches("fastcgi_pass unix:/run/php/8.3/site/shop.sock").count(), out.matches("fastcgi_pass").count());
}
// Existing nginx.rs:2486 and :2584 assertions must keep passing untouched: shared output is unchanged.
```
Service: `get_reports_own_master_for_a_converted_user`.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hyperion-adapters vhost_points && cargo test -p hyperion-core get_reports_own`
Expected: FAIL

- [ ] **Step 3: Implement.** Compute `fpm_socket` once in `render` through `PhpVersion` helpers, so the template holds no path logic. Do not bump `VHOST_GEN`: shared output is byte-identical, and a converted vhost is rewritten by the conversion.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p hyperion-adapters nginx`
Expected: PASS

- [ ] **Step 5: Commit** `feat(nginx): let a vhost use a per-user FPM socket`

### Task 5: One routing layer for every pool write and removal

**Before starting:** check whether the session on suspend and trash (`local_4a182941-588d-4bf6-9820-2c9cc2c330e7`, branch `claude/nostalgic-noether-7701ef`) merged a sibling check. Reuse its helper in place of `fpm_user_still_needs` below. Do not write a second one.

**Files:**
- Create: `crates/hyperion-core/src/service/fpm_own.rs`
- Modify: `crates/hyperion-core/src/service/mod.rs`, `crates/hyperion-core/src/real_adapter.rs`, `service/provision.rs:273,645,660`, `service/limits.rs:68,1026,1043,1072,1089`, `service/site_config.rs:212`, `service/trash.rs:37,293`, `service/rollback.rs:109`
- Test: `crates/hyperion-core/src/service/tests/fpm_own.rs`

**Interfaces:**
- Consumes: Task 3 state and adapter functions
- Produces:
  - `AdapterPort` methods with no-op defaults, so the four `StubAdapters` need no change: `fpm_own_ensure(user, domain, ver, memory_mb, max_exec, max_children, max_requests) -> Result<(), AdapterError>`, `fpm_own_delete(user, ver)`, `fpm_own_ready(user, ver) -> bool`, `fpm_shared_pool_drop(user, ver)`, `fpm_shared_reload(ver)`
  - `HostingService::is_own_master(&self, user: &str) -> bool`, failing closed: on a read error return an `Err` to callers that write. Never guess shared, or a converted site gets a stale pool.
  - `HostingService::fpm_write_pool(&self, detail: &HostingDetail, ver: PhpVersion, limits: Option<&HostingLimits>) -> Result<(), AdapterError>`
  - `HostingService::fpm_remove_pool(&self, detail: &HostingDetail, ver: PhpVersion) -> Result<(), AdapterError>`
  - `HostingService::fpm_user_still_needs(&self, user, ver, except: &HostingId) -> bool`

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn set_limits_on_a_converted_user_goes_to_its_own_master() {
    // expect_fpm_own_ensure().times(1) with the stored limits; expect_apply_php_limits().never()
}
#[tokio::test] async fn set_limits_on_a_shared_user_is_as_before() { /* apply_php_limits once, fpm_own_ensure never */ }
#[tokio::test] async fn suspending_one_of_two_sites_keeps_the_masters_running() { /* fpm_own_delete never */ }
#[tokio::test] async fn suspending_the_last_site_stops_it_and_resume_starts_it() { /* delete once, then own_ensure once, limits intact */ }
#[tokio::test] async fn php_version_switch_on_converted_user_creates_new_before_removing_old() { /* own_ensure(new) before own_delete(old) */ }
#[tokio::test] async fn hard_delete_of_last_site_stops_unit_and_clears_mode() { /* own_delete once; is_own false */ }
#[tokio::test] async fn new_site_on_converted_user_uses_own_master() { /* provision path */ }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hyperion-core fpm_own`
Expected: FAIL

- [ ] **Step 3: Implement.** Replace each listed direct call with the routed one. `rollback.rs:109` runs without `self`, so its step records the mode when pushed. Keep the shared branch byte-for-byte what it does today, apart from whatever the sibling session's fix changed.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p hyperion-core`
Expected: PASS, including every existing FPM test unchanged.

- [ ] **Step 5: Commit** `refactor(php): route every pool write and removal by the user's FPM mode`

### Task 6: Convert and roll back one system user

**Files:**
- Modify: `crates/hyperion-core/src/service/fpm_own.rs`, `service/provision.rs` (new-user adoption), `crates/hyperion-rpc/src/codec.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`
- Test: `crates/hyperion-core/src/service/tests/fpm_own.rs`

**Interfaces:**
- Consumes: Task 5 routing; `write_vhost_for_state`
- Produces:
  - `HostingService::fpm_convert_user(&self, sel: HostingSelector) -> Result<FpmConvertReport, RpcError>`
  - `HostingService::fpm_unconvert_user(&self, sel: HostingSelector) -> Result<FpmConvertReport, RpcError>`
  - `pub struct FpmConvertReport { system_user: String, versions: Vec<PhpVersion>, hostings: Vec<String> }` (serde, in `hyperion-types`)
  - `Request::HostingFpmOwnSet { sel, own: bool }`, `Response::HostingFpmOwnSet(FpmConvertReport)`

Convert sequence, with one job per user:

1. Refuse if `fpm_own_masters` is off, if preflight has blocks, or if the user has no active PHP hosting (`resume first`). Already own: return the report, no changes.
2. For each PHP version among the user's active hostings: `fpm_own_ensure` with stored limits, then require `fpm_own_ready`, polled up to 10 s.
3. `set_own`.
4. For each of the user's active PHP hostings: fresh `get`, `write_vhost_for_state`.
5. For each version: `fpm_shared_pool_drop`. No reload.
6. Audit `hosting.fpm_own`.

On failure at step 2, 3 or 4: `clear_own`, rewrite any vhost already switched, `fpm_own_delete` each started unit, return the error. The shared pools were never touched, so the site keeps serving.

Unconvert: `apply_php_limits` per version (pool back in `pool.d`, this reloads shared), `clear_own`, rewrite vhosts, `fpm_own_delete` per version, audit. It is allowed with the node setting off.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn convert_keeps_this_order() { /* mockall Sequence: own_ensure, own_ready, vhost write, shared_pool_drop. Asserts shared_reload never. */ }
#[tokio::test] async fn convert_covers_every_hosting_and_version_of_the_user() { /* 2 hostings, 8.2 + 8.4: own_ensure twice, vhost twice */ }
#[tokio::test] async fn failure_on_second_version_leaves_the_user_shared() { /* own_ready false for 8.4: own_delete(8.2), is_own false, shared_pool_drop never */ }
#[tokio::test] async fn vhost_failure_rolls_back() { /* second vhost write Err: first vhost rewritten shared, own_delete, is_own false */ }
#[tokio::test] async fn convert_refused_when_node_setting_off() {}
#[tokio::test] async fn unconvert_works_with_node_setting_off() { /* Review Focus */ }
#[tokio::test] async fn unconvert_restores_stored_limits_before_switching_vhosts() {}
#[tokio::test] async fn new_user_adopted_only_when_on_and_ram_floor_holds() { /* on+ok: own. off: shared. on+LowRam: shared, no error */ }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hyperion-core convert`
Expected: FAIL

- [ ] **Step 3: Implement.** Serialise per user with the existing per-hosting lock pattern if one applies. Adoption in `provision.rs:273`: a brand-new system user only; an existing user follows its recorded mode through routing. Fill `own_users` in `fpm_own_preflight` from `list_own` here, with a test that a converted user no longer counts against RAM.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p hyperion-core fpm_own`
Expected: PASS

- [ ] **Step 5: Commit** `feat(php): convert a system user to its own FPM master and back`

### Task 7: Boot, recovery, logs and health

**Files:**
- Modify: `crates/hyperion-core/src/service/provision.rs:689-760`, `bin/hyperion-agent/src/main.rs:250`, `bin/hyperion-agent/src/boot.rs`, `crates/hyperion-core/src/real_adapter.rs:558,635`, `crates/hyperion-adapters/src/phpfpm.rs` (`ensure_socket_dirs`), `crates/hyperion-core/src/service/limits.rs` (`php_workers_tick`), `crates/hyperion-core/src/service/system.rs:733`
- Test: `service/tests/fpm_own.rs`, `service/tests/limits.rs`, `real_adapter.rs` tests

**Interfaces:**
- Consumes: routing, `ensure_own_units`, `list_own`
- Produces:
  - `AdapterPort::fpm_own_reopen_logs(ver)`, default no-op: `systemctl kill -s USR1 'hyperion-fpm<ver>@*'`
  - `phpfpm::failed_own_units() -> Vec<String>`
  - `real_adapter::extract_fpm_test_failed_path` also accepts paths in `own_config_dir`

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test] async fn boot_rerender_keeps_limits_and_does_not_restart_shared_for_own_users() { /* only own users: no restart of php<ver>-fpm; own_ensure gets stored limits */ }
#[tokio::test] async fn mixed_node_restarts_shared_only_for_shared_users_versions() {}
#[tokio::test] async fn workers_tick_reopens_own_logs_when_the_inode_changes() { /* rotate tempfile: reopen once. Second tick: not again. No own users: never. */ }
#[test] fn bad_own_config_is_attributed_to_its_file() { /* stderr "ERROR: [/etc/hyperion/fpm/8.3/x.conf:5]" */ }
```
Health: `health_reports_failed_own_units`.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hyperion-core boot_rerender workers_tick_reopens bad_own_config health_reports`
Expected: FAIL

- [ ] **Step 3: Implement.** Call `ensure_own_units` beside `ensure_phpfpm_socket_dirs`. `ensure_own_pool` already does nothing for an unchanged file, so a boot leaves own masters untouched. `repair_orphan_fpm_pools` also walks `own_config_dir`, with a failing own config quarantined as the shared ones are, and that user's unit stopped; only that site is affected. `fpm_recover_failed` also does `reset-failed` plus `start` on `failed_own_units`. The `PartOf` restart on a PHP package upgrade needs no code.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --workspace --all-targets`
Expected: PASS

- [ ] **Step 5: Commit** `feat(php): keep own FPM masters healthy across boots, rotation and failures`

### Task 8: The action in the panel, and the pilot script

**Files:**
- Modify: `bin/hyperion-web/src/lib.rs:91`, `bin/hyperion-web/src/handlers/hostings/php.rs`, `bin/hyperion-web/templates/hostings_detail.html`
- Create: `packaging/install/tests/fpm-own-pilot.sh`
- Test: `bin/hyperion-web/tests/web_e2e.rs`, `bin/hyperion-web/tests/template_lint.rs` if a new template rule applies

**Interfaces:**
- Consumes: `Request::HostingFpmOwnSet`, `Request::NodeFpmPreflight`
- Produces: `POST /hostings/set-fpm-own` (`selector`, `own`), gated by `require_manage_for_selector(.., Capability::HostingEditConfig)`, running through `spawn_job` with kind `hosting.fpm_own`

- [ ] **Step 1: Write the failing tests.** Web: viewer refused; POST creates a job and redirects to `/jobs/<id>`; the card shows the action only if the node setting is on and preflight is ok, shows rollback whenever the user is converted, and the confirm on the form names all hostings of that user. Rollback's confirm says it reloads the shared master, which can cut in-flight requests on other shared sites.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hyperion-web fpm_own`
Expected: FAIL

- [ ] **Step 3: Implement the handler and card.** Copy: "Run on its own PHP process" and "Move back to the shared PHP process". Walk the page in the dev panel (`preview_start devpanel`) and take a screenshot.

- [ ] **Step 4: Write `fpm-own-pilot.sh <system_user> <domain>`.** Read-only, run as root on the pilot node, exit 1 on any failure. Checks: unit active using `systemd-escape`; cgroup path under `hyperion.slice/hyperion-sites.slice/hyperion-sites-<esc>.slice`; `cpu` in the unit's `cgroup.controllers`; `/proc/<master>/exe` not `(deleted)`; own socket owned by the nginx user; `curl` of the domain gives a non-5xx; no pool for the user in `pool.d`; prints `memory.current` of the slice. Run `shellcheck` on it.

- [ ] **Step 5: Test the whole path in a container.** Debian 13 and 12 systemd containers as in the spec's lab (scripts in the session notes, `fpm-hard-caps-lab/`): install the actual agent binary built for Linux, a user `im-port.ed` with two hostings, convert through the RPC, run the pilot script, then roll back. Use `docker cp`; bind mounts from the scratchpad show up empty. Expected: script exits 0, the site never returns 502 under a request loop during conversion and rollback, and after an agent restart the master PID is unchanged.

- [ ] **Step 6: Commit** `feat(hostings): run a site's PHP on its own process from the panel`

### Task 9: Pilot on the real node (no code)

Needs the operator's node choice from the stop gate, and the operator's go-ahead, since this changes a production node. Run the spec's phase 1 exit criteria through the real agent and record results in the spec, with these commands where one applies:

- [ ] A converted site serves through an agent restart, an `update.sh` run, a real PHP package upgrade and a reboot, with limits intact. Run `fpm-own-pilot.sh` after each.
- [ ] Suspend, resume, trash, restore, PHP version change, Move and Copy work on a converted user, including one with two hostings.
- [ ] Rollback leaves the site as it was.
- [ ] On a node with swap, a test site at a temporary `MemoryMax` is killed without the node swapping (`systemctl set-property --runtime`, then revert). Note: this is the only cap touched in this plan, and it is on a test site.
- [ ] Measured cost per site is within about 20% of 11 MB.
- [ ] Write a follow-up plan for phases 2 to 4 from what this found.
