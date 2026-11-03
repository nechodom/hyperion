# Hard per-site CPU and memory caps for PHP-FPM sites

Status: design, not approved, nothing implemented. Written 2026-11-03. File and
line references are to `origin/main` at 54a3fb8c.

## Why

Every PHP site on a node shares one FPM master per PHP version, inside one
cgroup. Nothing in the kernel separates them. PR #326 (automatic
`max_children`, merged) limits only the
workers the automation adds. A site at its own hand-set value can still take
nearly the whole server, and the operator does not want one site using 90% of
one.

## Recommendation

Give each site's system user **its own FPM master, as a templated systemd unit,
inside a per-user slice**. Put `CPUQuota`, `MemoryMax` and `MemoryHigh` on that
slice. Roll it out per system user, on nodes that opt in, on a new socket path,
with weights first and caps switched on later.

The price is about 11 MB of RAM per site, or 1.1 GB per 100 sites. The same
change also fixes two problems that exist today: a reload of any pool cuts
in-flight requests on every site of that PHP version and wipes their OPcache,
and one shared OPcache that already fills up at around a dozen sites.

## The three options, measured

All numbers come from a Debian 13 container (systemd 257, PHP 8.4, real
WordPress and nginx) on 4 cores, 8 GB, no swap. Lab scripts are in the session
notes folder (`fpm-hard-caps-lab/`). "Noisy" means 12 clients burning CPU on a
site with `max_children = 20`. The victim is another site.

| Scenario | Noisy site's share of node | Victim fixed-work request | Victim WP page, worst | MariaDB query, worst |
|---|---|---|---|---|
| Baseline, idle node | n/a | 0.29 s | 0.03 s | 0.75 s |
| Today, 1 noisy site | 99% | 0.88 s | 0.12 s | 2.49 s |
| Today, 3 noisy sites | 51 / 24 / 23% | 2.63 s | 0.34 s | 6.76 s |
| `process.priority = 19` on the noisy site | 99% | 0.32 s | 0.03 s | 0.78 s |
| Own master, equal weight, no quota, 1 noisy | 99% | 0.32 s | 0.04 s | 0.80 s |
| Own master, equal weight, no quota, 3 noisy | 33 / 32 / 34% | 0.39 s | 0.10 s | 0.80 s |
| Own master, `CPUQuota=200%`, 1 noisy | **50%** | 0.35 s | 0.05 s | 0.79 s |
| Own master, quota, in a parent slice, 3 noisy | 33 / 33 / 32% | 0.34 s | 0.04 s | 0.80 s |

### `process.priority`: rejected

It protects neighbours only if somebody already knows which site is the noisy
one, and it does nothing if every site gets the same nice value. The noisy site
still took 99% of an otherwise idle node, which is the thing the operator asked
to prevent. It has no effect on memory.

### Moving worker PIDs into per-site cgroups: works, but rejected

This keeps the shared master, sets `Delegate=yes`, and has the agent write
workers into `<unit>/site-<user>/cgroup.procs`. Workers fork inside the master's
cgroup, so each one is uncapped until something moves it.

| Mover interval | Site capped at 25% of node actually used |
|---|---|
| 10 s (the existing CPU tracker tick) | 69–73% |
| 1 s | 36–40% |
| 50 ms | 26% |

So a very fast watcher does hold the cap. I expected memory charging to be the
fatal flaw, and it was not: OPcache pages keyed by path were charged about
evenly (around 20 MB per site, 2 MB extra to the first). What rules this option
out:

- **Fail-open.** With the agent stopped, every newly forked worker runs
  uncapped, with no error anywhere. Agent restarts happen on every deploy, and a
  reload respawns all workers at once (measured: 0 of 3 in the site cgroup, all
  27 in the master's, one second after reload).
- **Lock inversion through the shared OPcache.** A throttled site can stall
  other sites while it holds the OPcache write lock. With one site compiling at
  a 2% quota, a neighbour's compile went from p90 1.7 ms to p90 94 ms, max 196 ms
  (N=30). 2% is deliberately extreme, so this shows the mechanism and not a
  typical magnitude.
- **It fixes nothing else.** The reload, crash and OPcache problems below all
  remain.

A kernel fork-event listener (proc connector) would narrow the window but is
still fail-open, and adds a privileged netlink listener to maintain. Not tested.

### One master per site: recommended

The cap is enforced by systemd and the kernel whether or not the agent is
running, and it cannot be escaped by forking. Measured on top of that:

| Event | Today (shared master) | Own master |
|---|---|---|
| Reload one pool, in-flight requests on other sites | **502** | untouched, ran to completion |
| Reload one pool, other sites' OPcache | **wiped**, first page 0.24 s, was 0.03 s | kept, hit counter continued |
| Same with `process_control_timeout = 30s`, 8 s request in flight | neighbour **stalled 7.3 s** | own site's new request waited 5.1 s, neighbour 0.08 s |
| Master killed with SIGKILL | **every site 502** | that site only, back in about 2 s |
| Worker OOM-killed by a cap, default `OOMPolicy=stop` | **every site 502** | avoided by `OOMPolicy=continue` |
| Bad pool file (from code, `ensure_pool` and `repair_orphan_fpm_pools`; not run) | blocks every site's reload | only that site's |
| OPcache past full (128 MB shared, 12 bare WP) | last site 0.12 s per page vs 0.03 s | each site has its own |

Per-pool reloads are not rare. `store_and_apply_limits` reloads through
`apply_php_limits`, and both `php_mem_auto_tick` and PR #326 call it on a timer.
Every one of those currently takes down in-flight requests across that PHP
version. Fixing this with `process_control_timeout` alone would swap the 502s
for a stall on every site (row 3).

## Memory cost of many masters

| Measurement | Shared | Own masters | Difference |
|---|---|---|---|
| 100 idle sites, `MemAvailable` drop | 174 MB | 1263 MB | **10.9 MB per site** |
| 12 warm WP sites, cgroup total excl. page cache | 393 MB (anon 133, shm 245, kernel 15) | 515 MB (anon 199, shm 297, kernel 19) | **10.2 MB per site** |

For that comparison the shared OPcache was raised to 1024 MB so that it was not
truncated. Other findings:

- One master alone costs about 10.7 MB (anon 7.4, shm 2.8, kernel 0.5). Using
  `pm = ondemand` to remove idle workers saves little, so this design keeps
  `dynamic`.
- OPcache is lazily touched. `memory_consumption` of 64 MB and 128 MB both used
  25 MB of real shm on a bare WP, so a generous per-site reservation costs
  nothing until it is used.
- Compiled scripts are keyed by path, so sites never shared them anyway (about
  21 MB per site either way). The real loss is interned strings: about 4 MB per
  site.
- systemd overhead is negligible: PID 1 grew 0.4 MB for 100 units. Starting 100
  masters took 1.26 s, `daemon-reload` 0.2 s, `set-property` 26 ms.

Sense check: 11 MB × 100 sites is 1.7% of a 64 GB node. 11 MB × 30 sites is 8% of
a 4 GB VPS. That second case is one reason a node opts in.

**An existing problem this removes:** the shared 256 MB OPcache filled at 12 bare
WordPress sites with no plugins (`cache_full: true`, `oom_restarts: 0`). Past
that point new scripts are simply not cached. Real sites with plugins will reach
it sooner.

## Design

### Units

One template per PHP version, `hyperion-fpm<ver>@.service`. Tested on systemd 257
and, as a smoke test, on Debian 12 (systemd 252, PHP 8.2), both with a 128 MB
OPcache reservation rather than the 256 MB shown here:

```ini
[Unit]
Description=PHP <ver> FPM for %I
After=network.target
PartOf=php<ver>-fpm.service

[Service]
Type=notify
Slice=hyperion-sites-%i.slice
ExecStartPre=/usr/bin/install -d -m 0755 /run/php/<ver>/site
ExecStart=/usr/sbin/php-fpm<ver> --nodaemonize --fpm-config /etc/hyperion/fpm/<ver>/%I.conf -d opcache.memory_consumption=256
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=2
OOMPolicy=continue

[Install]
WantedBy=multi-user.target
```

The reasons these lines matter, each checked:

- `OOMPolicy=continue` is **required**. systemd's default is `stop`: one worker
  killed at the cap stopped the whole unit, failed all 5 in-flight requests,
  restarted it and lost the OPcache. With `continue`, 3 of 5 requests got 502, 2
  completed, the master stayed up and the site kept serving.
- `Slice=hyperion-sites-%i.slice` makes the tree
  `hyperion.slice/hyperion-sites.slice/hyperion-sites-<user>.slice/<unit>`
  without any per-site drop-in. Hyphenated users (imports, #317) must be
  instantiated with `systemd-escape`: `im-port.ed` became `im\x2dport.ed` and
  worked, with `%I` giving back the real name for the config path.
- The parent slice gives all sites together one share against `system.slice`, so
  many busy sites cannot outweigh MariaDB, nginx and the agent however many there
  are. The lab cannot show this benefit: separate cgroups alone already kept
  MariaDB at 0.80 s with three noisy sites, with or without the parent slice. It
  costs nothing, because the per-user slices nest under it anyway.
- `PartOf=` makes a dpkg restart of `php<ver>-fpm` restart the site masters too.
  Verified with a real `apt-get install --reinstall`: without a restart a master
  keeps running `/usr/sbin/php-fpm8.4 (deleted)`, which would mean missing
  security updates. `PartOf` does not propagate reload, which is what we want.

**The cap belongs on the slice, not the service,** because the pool is per system
user and one user can have sites on two PHP versions. Two units sharing one slice
at `CPUQuota=100%` used 11% + 14% = 25% of 4 cores. `systemctl set-property
<slice>` applies live (same master PID) and survived a cold boot.

### Files

- `/etc/hyperion/fpm/<ver>/<user>.conf`: `[global]` (`pid`, `error_log`,
  `daemonize = no`, `process_control_timeout`) followed by today's pool template,
  unchanged except for `listen`. It sits outside `pool.d`, so the shared master
  does not load it.
- `listen = /run/php/<ver>/site/<user>.sock`. A new path is deliberate, see
  migration.
- `php-fpm<ver>.service` keeps running. It still hosts Debian's `www.conf` and
  the phpMyAdmin pool (`packaging/install/phpmyadmin.sh`), costs about 31 MB, and
  is the anchor for `PartOf`. There is no "no pools defined" failure to handle.

### What is keyed by what (my call)

The pool and the unit belong to a **system user and PHP version**, not a hosting:
`pool_path` is `<user>.conf`, and hostings can share a system user. So:

- `fpm_mode` is per system user on the node, not per hosting. `hosting_kv` is the
  wrong home for it. A small table keyed by system user fits.
- Converting a user converts all of that user's PHP versions in one job. Otherwise
  a sibling's vhost loses its pool, and part of the user's PHP sits outside the cap.
- A unit stops only when the user's last active hosting on that version goes
  offline. Vhosts of all that user's hostings on that version switch socket together.

Today's code has this bug already: suspend and trash call `fpm_delete(user, ver)`
without looking for siblings (`site_config.rs:212`, `trash.rs:37`), which by reading
the code removes the pool a sibling on the same user and version still needs. The
pool is also rendered for one domain, so its `open_basedir` names only that domain.
Neither was run in the lab. The new path must not copy the first; the second is
outside this design.

### Defaults (my call, see open questions)

| Setting | Default | Reason |
|---|---|---|
| `CPUQuota` | 50% of the node's cores, never below 1 core | Same 50% as `SITE_CPU_SHARE_PCT`. On a 1-core node the cap does nothing and weights do the work. |
| `CPUWeight` | systemd default, equal | Measured to protect neighbours at any load. |
| `MemoryMax` | 1/3 of RAM, floor 128 MB | Same 1/3 as `SITE_RAM_SHARE_DIVISOR`. A master failed to start at 32 MB and a bare WP served at 48 MB. Includes OPcache and page cache. |
| `MemoryHigh` | 90% of `MemoryMax` | Throttles before killing: 300 MB requested with `MemoryHigh=250M` gave no kills and 2–4 s responses. |
| `MemorySwapMax` | 0 | A capped site must not push the node into swap. **Not tested on a node with swap.** |
| `process_control_timeout` | 10 s | Lets a reload finish in-flight requests. It stalls only this site now. |

### How caps are stored (my call)

Two new nullable fields on the per-hosting limits row, `cpu_cap_pct` and
`mem_cap_pct`, both as a percentage of the node, so `set_limits`, profiles and
`hctl` carry them. `cpu_usage.rs` already reports CPU as a share of the whole node,
and a percentage still means something after a move to a node of another size.

- `NULL` means use the node default. `0` means no cap. This differs from the disk
  fields, where `None` means no limit, because these need a third state.
- Node defaults are one setting each, read at apply time and never copied onto rows.
  `CPUQuota` and `MemoryMax` are worked out from them plus core count and RAM.
- Profile values are percentages too, and `/profiles/reapply` overwrites them like
  every other limit it re-pushes. A per-site override does not survive a reapply.
- If several hostings share a system user, the slice takes the highest of their
  values, and `0` beats any number.

## What happens when a cap is hit

| Cap | What visitors see | What the logs show | Effect on others |
|---|---|---|---|
| CPU, normal | Slower pages. Own page 0.03 s became 0.3–5.7 s with 10 busy workers at 1 core. | `cpu.stat`: `nr_throttled`, `throttled_usec` | None measured |
| CPU, long request | **502 once `request_terminate_timeout` fires.** It is wall-clock while `max_execution_time` counts CPU time. At a 5% quota with `max_execution_time=3`, `request_terminate_timeout=6`, the request got its 502 at 7.6 s wall; unthrottled, the same request stopped cleanly at 3.0 s with a PHP fatal. Defaults are 60 s / 90 s. nginx's own timeout is 3600 s, so it does not interfere. | FPM: `execution timed out`, `exited on signal 15` | None |
| CPU, sustained | Workers all busy, queueing, then the existing `reached pm.max_children` warning | As today | None |
| `MemoryHigh` | Slow responses, no errors | `memory.events`: `high`; `memory.pressure` | None |
| `MemoryMax` | 502 on the requests whose workers were killed. Site keeps serving; respawn is automatic. | FPM: `exited on signal 9`; kernel: `Memory cgroup out of memory: Killed process`; `memory.events`: `oom_kill` | None. Neighbour returned 200. |
| Master killed | Site 502 for about 2 s, OPcache cold | systemd restart | None |

A 1 GB `fread` loop under `MemoryMax=300M` completed with no OOM kill: page cache
is reclaimed. OPcache shm and anon memory are not reclaimable without swap, which
is why `MemoryMax` must leave room for OPcache.

### Required changes to existing features

- **PR #326 `raise_room`:** add `RaiseBlock::Throttled`. Throttled workers are
  waiting for quota, so more of them cost memory and buy nothing. The existing
  `site_cpu_pct >= 50` check does not catch a site capped below 50%. Also limit
  `site_share` by the site's `MemoryMax`.
- **`stats.rs:263` OOM scan:** it greps `Killed process`, so every cap kill would
  count as a node-wide OOM event. Separate `Memory cgroup out of memory` from
  global OOM and attribute it to the site.
- **Site alerts:** a warning from `throttled_usec` and `oom_kill` deltas, read on
  the existing 10 s CPU tick, shown on the limits card. Otherwise a capped site
  just looks mysteriously slow.
- **`cpu_usage.rs`:** attribution needs no change, by reading the code: it works
  per uid, and masters remain uid 0 class Web. Not run against the lab.

## What the cap does not cover

Be clear about this with operators:

- **MariaDB.** A site's queries run in `mariadb.service`. An expensive query uses
  uncapped CPU while its PHP worker waits. Separate cgroups keep the database
  responsive against PHP, but this design does not limit one site's share of the
  database. `db_max_connections` is the only existing bound.
- **Anything run as the site user outside FPM:** crontab jobs (`cron.service`),
  wp-cli (`sudo -u` from the agent, so the agent's cgroup), SSH sessions, git
  deploys. **PR #326 matters here**: `wp_system_cron_tick` moves WP-Cron from FPM to
  the CLI, on by default (`wpcron::enabled`), 3 sites at once, up to 10 minutes a
  run. So phase 3 below moves panel-started work into the slice **before** caps go
  on. Crontab and SSH stay uncapped after that, as a known gap.
- **Disk I/O.** Not in scope.
- **Node apps** already have their own unit with `MemoryMax` and `CPUQuota`
  (`systemd-node-app.service.j2`).

## Migration

Order matters. FPM refuses to bind a socket another instance is listening on
(`Another FPM instance seems to already listen on`), and the old master unlinks
the path when its pool is removed. Measured with 4 clients at about 350 req/s:

| Cutover | Failed requests |
|---|---|
| Same socket path, shared reload first, then start | 810 of 2085, 2.3 s of 502 |
| Same socket path, start first, then shared reload | 399 of 2395, 1.1 s of 502 |
| **New socket path, nginx switched, then old pool dropped** | **0 of 2394** |

### Phase 0: preparation and fleet report, no behaviour change

- Write the template units from agent startup, the way `ensure_opcache_ini` works
  today.
- A read-only preflight on every node: cgroup v2, `cpu` and `memory` controllers
  available, systemd 252 or later, swap present or not, and free RAM against
  `11 MB × PHP users`. The result shows on the Nodes page. A failing node (for
  example an LXC guest without delegated controllers) stays on the shared master.
  **This answers how much of the fleet the design can protect, before more is
  built.** If many nodes fail, stop and reconsider.
- A per-node setting, **off by default**, and the `fpm_mode` table. Every FPM path
  branches on it.

### Phase 1: pilot on one real node, with exit criteria

The operator turns the setting on for one node. A "Run on its own PHP process"
action runs as a background job, per system user:

1. Write the config, enable and start the units on the new socket.
2. Rewrite the vhosts to the new socket, `nginx -t`, reload.
3. Set `fpm_mode`.
4. Remove the old pool files. **Do not reload the shared master yet:** the old pools
   sit idle and harmless.

New sites on a node with the setting on start in the new mode, unless free RAM is
under the 20% floor (`NODE_FREE_RAM_DIVISOR`), in which case they go on the shared
master and the page says why.

Exit criteria, all on the pilot node through the real agent:

- A converted site serves through an agent restart, an `update.sh` run, a real PHP
  package upgrade and a reboot, with its limits intact.
- Suspend, resume, trash, restore, PHP version change, Move and Copy all work on a
  converted user, including one with two hostings.
- Rollback leaves the site as it was.
- On a node with swap, a test site at `MemoryMax` is killed without the node swapping.
- Measured cost per site is within about 20% of the 11 MB here.

### Phase 2: bulk, per node, operator-triggered

Run phase 1 across all users with a stagger, then one shared reload per PHP version
at the end of the batch. That single reload hits only what is left on the shared
master, so run it in a quiet hour if any shared sites remain. Refuse to start, and
show the numbers, if `11 MB × users` would take free RAM under the 20% floor.

During this phase sites have weights only, no quota. That alone was enough to
protect neighbours in every test, and it cannot slow any site down on an idle node.

### Phase 3: panel-started work joins the slice

Run wp-cli, `wp_cron_run` and git deploy under `systemd-run --scope
--slice=hyperion-sites-<user>.slice`. The agent already uses `systemd-run`. Checked:
4 parallel `sudo -u <user> php` scopes, in a slice at `CPUQuota=100%`, ran as that
user and used 25% of 4 cores between them. Without this phase, a cap would leave
WP-Cron out on every WordPress site where the system cron is active.

### Phase 4: turn caps on

Before enabling, list the sites that would have been throttled, using
`hosting_usage_samples.cpu_peak_x100` (per-site peak one-minute average, already
collected, 49 h of history). The operator enables caps per node, with overrides per
site. Applying a cap needs no FPM reload.

### Later, separate design

Crontab wrapping and a `user-<uid>.slice` drop-in for SSH. Crontabs are validated and
carried through migrations, so changing what they run touches more than this design.

### Rollback

Per site, the same steps reversed: pool back in `pool.d`, shared reload, vhost
back, stop and disable the unit, clear `fpm_mode`. Measured under load: 0 of 2828
requests failed. Rollback goes through the current agent. An older agent does not understand `fpm_mode`, so its
boot re-render would write duplicate pools. Do not downgrade across phase 1
without rolling sites back first. Turning the node setting off stops new conversions
and leaves converted users as they are.

## Code that changes

| Where | Change |
|---|---|
| `hyperion-adapters/src/phpfpm.rs` | `ensure_pool`, `delete_pool`, `reload`, `test_config` (`-t --fpm-config <file>`), `pool_path`, per-site `[global]`. Skip the reload when the rendered file is unchanged. |
| `hyperion-types/src/php.rs:38` and `nginx-vhost.conf.j2:319,334,354,379` | Socket path becomes a value, not a hard-coded string |
| `hyperion-core/src/real_adapter.rs:558,600,635` | `fpm_recover_failed`, `fpm_restart`, `repair_orphan_fpm_pools` must also walk the instances; quarantine moves to the per-site directory |
| `hyperion-core/src/service/provision.rs:747` | Boot self-heal restarts every touched version on each agent start. Restart only sites whose file changed. |
| `service/limits.rs` | `set_php_version` for the new paths; `set_limits` applies slice properties |
| `service/site_config.rs:212`, `trash.rs:37,227` | Suspend and trash stop and disable the unit. `delete_pool` must stop it before `userdel` (see the shared-UID exit 8 rule). |
| `service/system.rs:733` | Service health gains "site PHP units failed" |
| `service/migration.rs` | Carry the cap through Move/Copy. Convert the user on arrival if the target node has the setting on. |
| New table and migration, `HostingLimits`, profile form, `hctl`, RPC wire type | `fpm_mode`, `cpu_cap_pct`, `mem_cap_pct`, node settings |
| `bin/hyperion-web/templates/hostings_detail.html:996` | Shown socket path; cap fields and throttle state on the limits card |

`php_workers_tick` and `wp_mail.rs` need no change. Per-site masters append to the
same `/var/log/php<ver>-fpm.log`, and the line is unchanged (checked: `[pool s08]
server reached pm.max_children setting (2)`). One catch:
Debian's logrotate hook signals only the shared master's PID file, so site masters
keep writing to the rotated file until they get `USR1`. `systemctl kill -s USR1
'hyperion-fpm<ver>@*'` reopened them correctly. The cursor in `php_workers_tick`
already sees the inode change, so that is the natural place to send it.

## What was not verified

- **Never run on a real node.** The kernel was colima's 6.8 on aarch64 for both
  containers. Debian 12 ships 6.1 and Debian 13 ships 6.12.
- A node with swap, so `MemorySwapMax=0` is untested in the case it exists for.
- A global (not cgroup) OOM kill on today's shared master. Taking it down was only
  demonstrated with a cgroup limit on the shared unit. systemd documents the policy
  as also covering the kernel OOM killer, but I did not fill the VM's RAM to prove
  it, because other containers run on it.
- Scale above 100 masters, and any scale under real traffic. Warm numbers are from
  12 bare WordPress sites, all on one database.
- Any of this through the actual agent. Everything was scripted by hand.
- Socket activation for idle sites was considered as a further saving and not tried.

## Open questions for the operator

1. Are 50% of CPU and 1/3 of RAM the right node defaults, and once a node enables
   caps, should they apply to every site or only those on a plan or profile that
   sets one? The second part changes the schema; the first is cheap to change later.
2. Is it acceptable that crontab jobs and SSH sessions stay uncapped until a later
   design? A tenant with a crontab can still use the whole node's spare CPU.
3. Which real node should be the pilot? It should have swap if any production node
   does, and a mix of WordPress sites and a shared system user.

## Calls made without asking

Check these while reading:

- Rejecting PID moving despite it holding the cap at a 50 ms interval.
- Per-node opt-in, off by default, for existing and new sites alike, because none of
  this has run on a real node. Revisit after the pilot.
- Mode keyed by system user, with all of a user's PHP versions converting together.
- Caps stored as percentages of the node, `NULL` for node default, `0` for none, and
  profile reapply overwriting per-site overrides.
- Panel-started work under the slice before caps go on (phases 3 and 4 in that order).
- New socket path instead of a 1–2 s outage per site.
- `process_control_timeout = 10s`, `MemoryHigh` at 90% of `MemoryMax`, `MemorySwapMax=0`.
