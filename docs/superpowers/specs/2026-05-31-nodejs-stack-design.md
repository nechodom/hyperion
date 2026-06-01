# Sub-project 8 — Node.js Stack — Design Spec

| Field | Value |
|---|---|
| Sub-project | 8 of N — Node.js |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation, Controller (1.5), Admin UI (2), Limits/Suspend (3) |

## 1. Summary

Adds **Node.js** as a hosting runtime: each Node app runs as a dedicated
**systemd service** under the hosting's system user, listens on an
auto-allocated localhost port, and is reverse-proxied by nginx. Multiple
Node.js versions supported simultaneously via **NodeSource** apt repo +
selectable per hosting.

Resource limits enforced via systemd unit `MemoryMax`, `CPUQuota`, and
`TasksMax`. Logs go to systemd-journald and are also persisted to the
hosting's `logs/` dir via journal forwarding. Standard `package.json`
scripts (`start`, `build`) are honored.

## 2. Goals

1. `lm hosting create example.app --node 20 --app-entry server.js` provisions
   a hosting with Node 20, generates a systemd unit, allocates a port,
   wires nginx reverse proxy.
2. `lm hosting node app deploy <id>` runs `npm ci --omit=dev && npm run
   build` as the hosting user inside `htdocs/`.
3. `lm hosting node app start|stop|restart|status <id>` controls the
   service.
4. Supports Node 18 / 20 / 22 (LTS) installed in parallel via NodeSource.
5. Per-app memory & CPU limits applied via systemd; defaults from
   `hosting_limits` (sub-project 3) extended for Node.
6. App stdout/stderr aggregated to `/home/<u>/<dom>/logs/app.log` with
   rotation.

## 3. Non-Goals

- Yarn, pnpm, bun. npm only in v1 (bun-friendly path: future flag).
- Multi-app per hosting. One app per hosting in v1.
- Process clustering / PM2-style features. systemd + a single Node
  process is the model; app code can fork workers itself if it wants.
- Hot reload during deploy. Restart-based deploys.
- Build artifacts to S3 or external storage.

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **NodeSource** apt repo (deb.nodesource.com) for multi-version Node | Mature, fast updates, signed |
| D2 | Each app = a systemd unit named `hyperion-app-<hosting_user>.service` | Standard, slice-aware, observable |
| D3 | Port allocation pool `30000–39999`; tracked in agent state | Simple, predictable, plenty of room |
| D4 | nginx reverse proxies to `127.0.0.1:<allocated_port>` | Loopback only; no public port exposure |
| D5 | Node version per hosting recorded; binary is `/usr/bin/node<ver>` symlinks (from NodeSource) | Coexistence |
| D6 | `package.json` `scripts.start` is the entrypoint; fallback `node <app-entry>` | Standard idiom |
| D7 | Resource limits via systemd: MemoryMax, CPUQuota, TasksMax | Clean kernel-level |
| D8 | Log collection via systemd journal + a `journalctl` forwarder writes to disk hourly | Survives reboots; per-hosting log file |
| D9 | Deploys block until `npm ci` succeeds; on failure, old service stays running | Safe deploys |
| D10 | `npm` cache shared per-user at `/home/<u>/.npm/` | npm's default |

## 5. State Schema Additions (Agent)

```sql
-- Extend hostings table effectively: a Node hosting has php_version=NULL
-- and a row in node_apps.
CREATE TABLE node_apps (
    hosting_id          TEXT PRIMARY KEY REFERENCES hostings(id) ON DELETE CASCADE,
    node_version        TEXT NOT NULL,                   -- '18'|'20'|'22'
    app_entry           TEXT NOT NULL,                   -- e.g. 'server.js'
    listen_port         INTEGER NOT NULL UNIQUE,
    env_vars_secret_id  TEXT NOT NULL,                   -- ref to /etc/lm/secrets/<id>
    memory_mb           INTEGER NOT NULL DEFAULT 256,
    cpu_quota_pct       INTEGER NOT NULL DEFAULT 100,    -- 100 = 1 vCPU
    tasks_max           INTEGER NOT NULL DEFAULT 200,
    install_state       TEXT NOT NULL                    -- 'pending'|'installing'|'ready'|'failed'
                        CHECK (install_state IN ('pending','installing','ready','failed')),
    last_deploy_at      INTEGER,
    last_deploy_log     TEXT                              -- last 8 KiB of npm output
);

CREATE TABLE port_pool (
    port  INTEGER PRIMARY KEY,
    used  INTEGER NOT NULL DEFAULT 0  -- 0|1
);
-- pre-populated with 30000..39999 on first migration
```

## 6. RPC Additions

### 6.1 AgentApi

```rust
async fn node_app_create(&self, sel: HostingSelector, spec: NodeAppSpec)
    -> Result<NodeAppDetail, RpcError>;
async fn node_app_deploy(&self, sel: HostingSelector, opts: DeployOpts)
    -> Result<DeployResult, RpcError>;
async fn node_app_start(&self, sel: HostingSelector) -> Result<(), RpcError>;
async fn node_app_stop(&self, sel: HostingSelector)  -> Result<(), RpcError>;
async fn node_app_restart(&self, sel: HostingSelector) -> Result<(), RpcError>;
async fn node_app_status(&self, sel: HostingSelector) -> Result<NodeAppStatus, RpcError>;
async fn node_app_env_set(&self, sel: HostingSelector, env: BTreeMap<String,String>)
    -> Result<(), RpcError>;
async fn node_app_set_limits(&self, sel: HostingSelector, lim: NodeAppLimits)
    -> Result<(), RpcError>;
async fn node_app_logs(&self, sel: HostingSelector, tail: u32)
    -> Result<Vec<String>, RpcError>;
```

`HostingCreateReq` gains a `node_app: Option<NodeAppSpec>` field; passing
both `php_version` and `node_app` is an error.

## 7. Adapter Additions

### 7.1 `nodejs.rs` (new)

- `ensure_version_installed(ver)` — checks `/usr/bin/node<ver>` symlink;
  if missing, runs `apt-get install -y nodejs-<ver>` from NodeSource
  repo. (NodeSource installs only the matching major; we use a wrapper
  that adds `/usr/bin/node<N>` symlinks. Detail: install via
  `nodesource_setup-<N>.sh` once per major, then `apt-get install nodejs`.)
- `node_bin(ver) -> PathBuf` — returns canonical path.

### 7.2 `systemd.rs` (new)

- `write_unit(unit_path, content)` — atomic write + `daemon-reload`.
- `enable(unit)`, `start(unit)`, `stop(unit)`, `restart(unit)`, `is_active(unit)`.
- `delete_unit(unit_name)` — stop, disable, remove file, reload.

### 7.3 `nginx.rs` (extend)

- New template variant `nginx-vhost-reverse-proxy.conf.j2` for hostings
  whose runtime is Node. It contains:

  ```nginx
  location / {
      proxy_pass http://127.0.0.1:{{ listen_port }};
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_read_timeout 60s;
  }
  ```

  Adapter selects this variant when hosting has a `node_apps` row.

### 7.4 `port_pool.rs` (new)

- `allocate() -> Result<u16, _>` — picks first `used=0` row, sets to 1,
  returns port.
- `release(port)` — sets `used=0`.

## 8. systemd Unit Template

`/etc/systemd/system/hyperion-app-<user>.service` written by agent:

```ini
[Unit]
Description=hyperion app: {{ hosting.domain }}
After=network.target
ConditionPathExists=/home/{{ system_user }}/{{ hosting.domain }}/htdocs/package.json

[Service]
Type=simple
User={{ system_user }}
Group={{ system_user }}
WorkingDirectory=/home/{{ system_user }}/{{ hosting.domain }}/htdocs
Environment=NODE_ENV=production PORT={{ listen_port }} HOME=/home/{{ system_user }}
EnvironmentFile=/etc/hyperion/secrets/{{ env_vars_secret_id }}
ExecStart=/usr/bin/node{{ node_version }} {{ app_entry }}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hyperion-app-{{ system_user }}

# Resource limits (from hosting_limits + node_apps)
MemoryMax={{ memory_mb }}M
CPUQuota={{ cpu_quota_pct }}%
TasksMax={{ tasks_max }}

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=false        # we need access to user home
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

## 9. Create / Deploy Flow

### 9.1 Create (called as part of `hosting_create` when `node_app` is set)

```text
01 ensure_user (as in Foundation)
02 ensure_dir hosting tree (as in Foundation)
03 nodejs.ensure_version_installed(node_version)
04 port_pool.allocate() → port
05 INSERT node_apps (install_state='pending', listen_port=port)
06 write env file to /etc/hyperion/secrets/<env_vars_secret_id> (empty)
07 acme issue_cert
08 nginx write_vhost with reverse-proxy variant pointing to port
09 systemd write_unit + enable (do NOT start yet — no code to run)
10 INSERT hostings row (state='active' once cert+nginx OK, but service
   is not started until deploy)
```

### 9.2 Deploy

```text
01 verify install_state in ('pending','ready','failed')
02 set install_state='installing'
03 systemd.stop(unit)         (if was running; OK if not)
04 cd /home/<u>/<dom>/htdocs/
   if package.json exists and package-lock.json exists:
     sudo -u <u> npm ci --omit=dev
   else:
     sudo -u <u> npm install --omit=dev
05 if scripts.build exists:
     sudo -u <u> npm run build
06 capture last 8 KiB of stdout+stderr into last_deploy_log
07 if any step failed: set install_state='failed'; do NOT start;
   return DeployResult{ok:false, log}; old code on disk is intact
   but service stays stopped
08 systemd.start(unit)
09 wait for systemd active state up to 30s; if degraded/failed,
   capture journalctl tail, set install_state='failed', return error
10 set install_state='ready', last_deploy_at=now
11 audit append
```

## 10. Logs

Each unit writes to systemd journal under `SyslogIdentifier=hyperion-app-<user>`.
A small `lm-log-forwarder` task in agent (tokio interval, every 60s):

```text
- for each ready node app:
   journalctl --identifier hyperion-app-<user> --since "65 seconds ago" -o cat
     >> /home/<u>/<dom>/logs/app.log
- rotate when file > 10 MiB:
   mv app.log app.log.1.gz (with gzip); keep 4 rotations
```

Live tail via `node_app_logs(tail: u32)` reads from `journalctl
--identifier hyperion-app-<user> -n <tail> -o cat`.

## 11. CLI

```
lm hosting create example.app --node 20 --app-entry server.js
lm hosting node deploy <id>
lm hosting node start|stop|restart|status <id>
lm hosting node env set <id> KEY=VALUE [KEY2=VAL2 ...]
lm hosting node env get <id>
lm hosting node logs <id> --tail 200
lm hosting node set-limits <id> --memory 512M --cpu 200 --tasks 500
```

UI in sub-project 2 surfaces the corresponding tab on hosting detail.

## 12. Configuration Additions

```toml
[node]
allowed_versions   = ["18","20","22"]
default_version    = "20"
port_range_low     = 30000
port_range_high    = 39999
default_memory_mb  = 256
default_cpu_quota  = 100        # percent of 1 vCPU
default_tasks_max  = 200
deploy_timeout     = "10m"
log_rotate_size_mb = 10
log_rotate_keep    = 4
```

## 13. Testing

- Unit: port allocator (proptest no-double-allocate); systemd template
  rendering snapshot.
- Adapter (testcontainer): bake a debian image with NodeSource 20 +
  systemd-in-container (via `systemd-nspawn`-style image or run a
  reduced subset of systemd ops directly). Verify create + deploy +
  status of a "hello world" Express app.
- e2e (nightly VM): full create → deploy → curl localhost → migrate
  scenarios.

## 14. Security Notes

- Node processes run as the hosting user (non-root).
- Port is bound to `127.0.0.1` only via PORT env + nginx reverse proxy;
  apps that bind 0.0.0.0 are discouraged via documentation but not
  blocked. (Future hardening: per-user nftables drop of external port
  reachability.)
- npm install runs as the hosting user; arbitrary postinstall scripts
  run as that user — same threat model as PHP-FPM under that user.
  Operator can disable scripts globally via npm config (deferred).
- Env file mode 0600 root:root; systemd reads it; the app process gets
  variables via `EnvironmentFile=`.
- systemd unit has `NoNewPrivileges=true`, `PrivateTmp=true`, etc.

## 15. Open Questions

1. **Per-app worker thread limits.** Node defaults are fine; if we
   constrain via systemd's `TasksMax` it covers OS-level threads.
2. **HTTPS termination at app vs nginx.** Always nginx terminates;
   app sees plain HTTP. Documented.
3. **Wasted port allocation when hosting deleted.** Hosting delete
   releases the port. If agent crashes mid-delete, boot cleanup checks
   `port_pool.used=1` rows with no matching `node_apps.listen_port` and
   reclaims.
4. **bun / deno / yarn / pnpm as future runtimes.** Slot for a runtime
   abstraction trait under `hyperion-adapters::runtime`; PHP, Node currently
   implement it.

## 16. Glossary Additions

| Term | Meaning |
|---|---|
| Node app | A hosting whose runtime is Node.js, not PHP/static |
| Port pool | Range 30000–39999 from which app listen ports are allocated |
| Deploy | A run of `npm ci` + `npm run build` + service restart |
| Reverse proxy variant | The nginx vhost template used for Node hostings |

---

*End of spec.*
