# Docker monitoring module

Status: draft 2026-11-04, nothing implemented. References are to `27bfb5e3`.

## Why

The owner runs docker compose stacks on every node and watches their websites
with Uptime Kuma. Kuma says a site is down, but not why, so the next step is SSH,
`docker compose ps` and `docker compose logs`. Hyperion should answer that first
question itself and replace Kuma, without becoming a Docker management tool.

## Decided by the owner

- **Optional.** An add-on an operator installs on purpose. It is not part of a
  default install, and an install that does not want it pays nothing for it.
- **Read-only towards Docker.** Watching and reading. No start, stop, restart,
  pull, exec, `compose up` or delete, anywhere.
- **Status and logs** for compose stacks and their containers.
- **Replaces Uptime Kuma.**
- **Reports available image updates.**
- **All of these extras:** alert on restart loops and unhealthy containers, disk
  used by images, volumes and logs, CPU and RAM per container, TLS expiry checks.
- **Reverse proxy from discovery.** A discovered stack can get a reverse-proxy
  hosting assigned to it.
- **Admin-only logs.** Tenants never see any of this.

## Non-goals

- Any action on containers, images, volumes or networks (see above).
- Installing or upgrading Docker itself, or editing compose files.
- Listing newer version tags (`1.2` to `1.3`). Update detection compares digests
  of the tag already in use.
- Kubernetes, Swarm, Podman.
- Public status pages, and Kuma's non-HTTP check types.
- CPU and RAM history graphs. Current values only.
- `/api/v1` and `hctl` coverage in the first version.

**Anti-goal:** a panel account must not become a way to read secrets. Container
environment variables never leave the node, and log lines never leave the panel.

## What exists today

- `crates/hyperion-core/src/service/monitor.rs`: uptime checks, per hosting only,
  running on the hosting's own node. `monitor_transition` (:494) and `probe_http`
  (:615) hold hard-won anti-flapping and timeout behaviour and must be reused, not
  rewritten.
- Reverse-proxy hostings exist (`site_type = reverse_proxy`,
  `proxy_upstream_url`, `validate_upstream_url` in `hyperion-adapters/src/nginx.rs`).
  `/hostings/new` takes no prefill parameters today (`NewQuery` in
  `handlers/hostings/create.rs`).
- Optional-install precedent: `post_modsec_install`
  (`handlers/hostings/waf.rs:716`), an admin-only background job dispatched to a
  node.
- Worker alerts: `notify_admins` parks them in `notification_outbox`;
  `notify_collector.rs` pulls them to the master.
- Fan-out read page precedent: `handlers/monitoring.rs`, including the "a node's
  rows were discarded, this list is incomplete" warning.
- Adapters shell out through `Command::new(..).arg(..)`, never `sh -c`. There is
  no Docker code besides port-conflict handling in `install-node.sh`.

## The module

Everyone gets the same binaries. "Installed" is state, not a package, because the
agent is one binary and a separate one would multiply the release and update path
for code that is small and idle when off. This is the builder's default unless
the check on the real code shows a reason against it.

Two levels:

1. **Cluster level, on the master.** Admin installs the module from a card in
   Settings. That adds the `Docker` nav item and enables URL checks. It needs no
   Docker on the master.
2. **Node level.** From the module page, admin installs it per node, as a background
   job (`spawn_job`, redirect to `/jobs/<id>`), the master included. The job checks
   that the Docker daemon answers and records whether buildx exists. Docker missing
   fails the job with a plain message saying to install Docker first. Hyperion does
   not install it.

When not installed, a node makes no `docker` calls and runs no module ticks, and
the master shows no nav item and runs no URL checks. Schema migrations still run
everywhere; empty tables are the accepted cost.

**Removing** turns the ticks off and deletes the module's own stored data after a
confirm. It never touches Docker. Reverse-proxy hostings created through it stay,
since they are ordinary hostings. A URL check's history goes with the module.

An older worker that does not know the new RPCs shows as "update the node first",
the same way the settings sync handles `OldAgent`.

## Reading Docker

Only a fixed set of read commands through one adapter, each with a timeout: `docker
ps -a`, `inspect`, `logs`, `stats --no-stream`, `system df`, `image inspect`,
`version`. The adapter is the single place that runs `docker`, and a test asserts
no other subcommand can be built from it. A timeout means "daemon not responding",
which is itself a reported state.

`inspect` output is reduced to an allow-list on the node before it goes anywhere.
**`Config.Env` and labels outside `com.docker.compose.*` are dropped there**, since
both routinely hold passwords.

Grouping uses compose labels (`com.docker.compose.project`, `.service`,
`.project.working_dir`, `.oneoff`). Containers without them form an "other
containers" group. One-off containers (`compose run`) are ignored for alerts.

Facts per container: service, image, state, health, exit code, `OOMKilled`, restart
count, restart policy, started and finished times, published ports with bind
address, CPU, RAM, log file size. The compose binary and compose files are not
needed or read.

## Deciding what counts as a problem

Evaluated on a node tick (about 30 s). A state must persist for about 3 minutes
before alerting, so `compose up -d` and deploys stay quiet.

| Situation | Verdict |
|---|---|
| Running, healthy or no healthcheck | ok |
| Running, `unhealthy` | problem |
| Restart count rose repeatedly inside the window, or `restarting` | problem (restart loop) |
| Exited, restart policy `no`, exit 0 | ok (finished job) |
| Exited otherwise, or `OOMKilled` | problem, with exit code and cause |
| Known project with no containers left | problem once ("project gone") |
| Daemon not responding | problem for the whole node |

Known projects are remembered per node so "gone" can be detected. A "Forget" on a
gone project clears panel state only and is the one write on this page besides
the reverse proxy link. Alert on transition and on recovery, one card per
project, reusing the `notify_admins` replace and fold behaviour.

## Pages

`/docker`, admin only, fans out to nodes with the module, with the incomplete-list
warning when a node fails to answer:

- Verdict line, then stacks grouped per node, problems first. A stack row shows
  its services, state, update badge and linked hosting.
- Stack detail: containers with the facts above, disk use, and logs.
- Node section: disk used by images, volumes and build cache (`docker system df`,
  hourly and cached, because it can be slow). Largest container logs, with a
  warning when a container's log is large and has no `max-size`, since that is how
  Docker fills a disk.

Follows the grouped-flat UI (`.group`, `.ghead`, `.item`) and English panel copy.

## Logs

Pick a stack or a container. Last N lines (default 200, cap 2000) with a byte cap
per response, a text filter applied on the node, and a "follow" toggle that polls
with `--since` over htmx every few seconds, because RPC here is not streaming.

- The container is resolved against the current inspect result, never passed
  through from the form to `docker`.
- ANSI codes are stripped, output is escaped.
- Opening logs writes an audit entry with who and which container. Follow polls do
  not write one each.

## URL checks (the Kuma replacement)

Run from the master, so a whole node dying is seen from outside. Limitation to
state in the UI: apps on the master's own box have no outside vantage point.

- Admin adds a URL, interval, expected status, and alert channels. Stored in new
  master tables, sampled with `probe_http`, decided by `monitor_transition`.
- The existing per-hosting monitor stays as it is. The new list and the per-hosting
  rows appear together on `/monitoring`, so there is one place to look.
- TLS expiry warning for https URLs, at 14 and 3 days.
- **Scope of the replacement (design call).** Kuma monitors are re-entered by hand,
  with no import and no history carried over, and the page keeps today's 24-hour
  view. Probes run concurrently, unlike the sequential `monitor_tick`, so one slow
  site cannot delay the rest.
- **Owning node (design call).** The master has no domain index and
  `find_hosting_anywhere` asks nodes live, so a dead node could not claim its
  domain. On save, derive the node from the URL's hostname and store it, with an
  admin override on the form. No match, such as a hand-written vhost, is allowed
  and means "no owning node". The stored node goes stale after a hosting Move, so
  re-derive it on each save and whenever a check recovers.
- Node-unreachable: when a check fails and its stored node also does not answer,
  the alert says so.

**Alert content.** The stack is looked up live at alert time, through the stored
node and the derived hosting link below. If it answers, the alert adds the stack
verdict, for example "`web` exited 137, OOM-killed". Email and Slack carry that
summary and a panel link. **Log lines appear only in the panel, never in outbound
alerts.**

**Delivery (design call).** `notify_admins` reaches only the bell, and global Slack
and admin addresses are per node, so a worker sending its own alert can reach
nobody or the wrong people. So all outbound Docker alerts are sent by the master
to the master's global channels, after `notify_collector.rs` brings the worker's
row in. Per-stack routing is out of scope. URL checks keep their per-check
channels and fall back to the global ones.

**Silent nodes (design call).** A dead node cannot report its stacks, and
`node_unreachable` is computed only when the dashboard renders. The master
therefore sends its own outbound alert, with recovery, when a node with the module
stops answering for about 3 minutes, whether or not it has a URL check.

## Image updates

A daily node tick, staggered, once per unique image reference.

- Compares the digest the local image was pulled with against the registry's
  current digest for that tag.
- States: up to date, update available, cannot verify (locally built, no repo
  digest, pinned by digest, registry error, or buildx missing). Keep the last known
  answer across a failed check. Never show an error as "up to date".
- Also shows "pulled, container not recreated" when a container runs an older image
  than the tag's local copy.
- Notifies once per new digest, severity info, folded per node.

**Constraint:** Docker Hub rate-limits anonymous pulls per IP, sometimes shared by a
whole node. The check must not eat that budget, or it would break the owner's own
`docker pull`. A 429 backs off until the next day. Credentials stay in Docker's own
store; Hyperion never reads or stores registry passwords.

Mechanism is the builder's call: `docker buildx imagetools inspect` handles private
registries through Docker's store; a `HEAD` on the manifest is known not to count
as a pull on Hub. Test on a real node which one meets the constraint, and pick that
or a combination.

## Reverse proxy from a discovered stack

On a stack with published ports, "Add reverse proxy" opens `/hostings/new` prefilled:
`site_type=reverse_proxy`, upstream `http://127.0.0.1:<port>`, target node set to the
container's node. The admin types the domain and confirms through the normal wizard
with its normal checks. `NewQuery` gains these parameters; each is validated as user
input and `validate_upstream_url` still applies on submit.

- **No link table.** A stack and hosting are linked by derivation: a reverse-proxy
  hosting on the same node whose upstream is loopback with a port a container
  publishes. This also finds proxies the owner already made by hand, and the link
  cannot go stale. The stack shows the hosting, the hosting detail shows the stack
  verdict.
- No published port: say so and suggest publishing one. Never proxy to a container
  IP, as it changes on recreate.
- Ports 80 and 443: not offered, since nginx owns them. Show it as a conflict.
- Bound to `0.0.0.0`: warn that Docker-published ports go through forwarding and
  are expected to bypass the panel's firewall input rules, so the app is reachable
  directly. Suggest `127.0.0.1:<port>:<port>` in compose. Verify this behaviour
  against Hyperion's nft ruleset on a real node before wording the warning.

## Permissions

New capabilities `DockerView` and `DockerLogs`, admin-level by default, assignable
to custom roles, and always combined with `scope_all()`, because these rows span all
tenants. Installing or removing the module is admin-only.

## Testing

Adapter parsers against recorded `docker` JSON fixtures, including the reduction
that drops `Config.Env`. An exhaustive table test of the verdict rules and alert
transitions, in the style of the existing `monitor_transition` tests. Real Docker
on a real node before calling it done: install, kill a container, `compose down`,
stop the daemon, a restart loop, an unreachable registry, and the reverse-proxy flow
end to end. Dev panel walk through `/docker` with a stub.

**Test node:** `tes-1`, named by the owner. Debian 13,
a Hyperion worker with one test hosting (the test hosting), SSH as root
with `-o IdentitiesOnly=no`. Docker Engine 29.9.3, Compose v5.7.0 and buildx 0.38.1
were installed there on 2026-11-04 from Docker's apt repository, with default daemon
settings, and no stacks are left running. All destructive tests run here and on no
other node. Its firewall is `policy accept`, so testing the `0.0.0.0` bypass warning
needs a stricter ruleset turned on first. Registry tests spend this node's Docker Hub
budget, so keep them few. The FORWARD chain is now policy DROP, set by Docker.

## Left to the builder

Tables and RPC shapes, tick intervals within the stated ranges, the exact facts
fetched by `stats` versus `inspect`, page layout within the existing design
language, and how the phases are cut. Suggested order: module install state and
adapter, status page, logs, alerts, URL checks, updates, reverse proxy.
