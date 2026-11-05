# hyperion — Operator Runbook

Foundation deployment on a fresh Debian 12 VPS.

## Prerequisites

- Debian 12 (`bookworm`) x86_64 with public IPv4 and ideally IPv6.
- Root or sudo access.
- Outbound HTTPS to Let's Encrypt (`acme-v02.api.letsencrypt.org`).
- DNS pointed at the host for each hosting you plan to create.
- nginx, PHP-FPM (one or more of 8.1/8.2/8.3/8.4), MariaDB, PostgreSQL
  installed (instructions below).

## 1. System packages

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates lsb-release gnupg2

# nginx
sudo apt-get install -y nginx

# PHP 8.3 via deb.sury.org (replace 8.3 with any of 8.1/8.2/8.4 as needed)
sudo curl -sSL https://packages.sury.org/php/apt.gpg \
  -o /etc/apt/keyrings/sury-php.gpg
echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] \
  https://packages.sury.org/php/ bookworm main" \
  | sudo tee /etc/apt/sources.list.d/sury-php.list
sudo apt-get update
sudo apt-get install -y php8.3-fpm php8.3-cli php8.3-mysql php8.3-pgsql \
  php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip php8.3-soap

# DB engines
sudo apt-get install -y mariadb-server postgresql
sudo systemctl enable --now mariadb postgresql nginx php8.3-fpm

# secure mariadb
sudo mariadb-secure-installation
```

## 2. Install hyperion-agent

Build from source on the host (or copy a pre-built binary):

```bash
sudo apt-get install -y curl build-essential pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"

git clone <repo-url> /opt/hyperion
cd /opt/hyperion
cargo build --release --workspace
sudo install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
sudo install -m 0755 target/release/hctl      /usr/bin/hctl
```

## 3. Set up users + dirs + config

```bash
sudo groupadd --system hyperion-admin
sudo usermod -aG hyperion-admin "$USER"    # log out / back in to pick up

sudo install -d -m 0700 /etc/hyperion
sudo install -d -m 0700 /etc/hyperion/secrets
sudo install -d -m 0700 /var/lib/hyperion
sudo install -d -m 0750 /var/log/hyperion
sudo install -d -m 0755 /var/lib/hyperion/acme-challenges

sudo tee /etc/hyperion/agent.toml > /dev/null <<'EOF'
[agent]
socket_path = "/run/hyperion.sock"
socket_group = "hyperion-admin"
state_db    = "/var/lib/hyperion/state.db"
secrets_dir = "/etc/hyperion/secrets"
log_path    = "/var/log/hyperion/agent.log"
home_root   = "/home"

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
contact_email = "you@example.com"   # required for LE; rotate as needed
challenge_dir = "/var/lib/hyperion/acme-challenges"
EOF
```

## 4. systemd unit

```bash
sudo tee /etc/systemd/system/hyperion-agent.service > /dev/null <<'EOF'
[Unit]
Description=hyperion agent
After=network-online.target nginx.service mariadb.service postgresql.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/hyperion-agent --config /etc/hyperion/agent.toml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=false
ProtectKernelTunables=true
ProtectKernelModules=true
PrivateTmp=true
LogsDirectory=hyperion
RuntimeDirectory=hyperion

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now hyperion-agent
sudo systemctl status hyperion-agent
```

The socket appears at `/run/hyperion.sock` (group `hyperion-admin`).

## 5. Smoke test

```bash
hctl info
# agent: <hostname> version=0.1.0 hostings=0

hctl hosting create example.com --php 8.3 --db mariadb
# ✓ created example_com (id=01JXX...)
#   root: /home/example_com/example.com/htdocs
#   db:   lm_xxx_examplecom (user=lm_xxx_u, password=<random>)
#   cert: issuer=self-signed, not_after=...

hctl hosting list
hctl hosting get example.com
hctl hosting delete example.com
```

> **Cert note.** Foundation issues a self-signed cert via `rcgen` so
> the rest of the pipeline (vhost, FPM, DB) works on day one. Replace
> with Let's Encrypt via the cert renewal loop landed in sub-project 9.

## Troubleshooting

- **Permission denied on socket** — make sure your user is in `hyperion-admin`
  and you've started a new shell since the `usermod -aG` change.
- **`useradd: not in sudoers`** — `hyperion-agent` is supposed to run as root
  through systemd. If running from a shell, prefix with `sudo`.
- **nginx fails `nginx -t`** — agent will restore the backup vhost on
  failure; check `journalctl -u hyperion-agent -e`.
- **MariaDB socket auth** — Debian default uses
  `/var/run/mysqld/mysqld.sock` and unix_socket auth for root. If you
  changed this, the mariadb adapter will fail; add an entry to
  `/root/.my.cnf` with credentials.

## Automatic wildcard renewal

A wildcard certificate can only be validated over DNS-01, and Hyperion holds
no DNS credentials. Instead the master answers DNS for one delegated zone
(for example `acme.panel.example`). The customer adds a permanent
`_acme-challenge.<base> CNAME <label>.<zone>` record, and from then on the
master publishes each challenge TXT value under its own zone and renews the
wildcard on its daily tick, with nobody touching it. Non-wildcard certificates
keep using HTTP-01.

### One-time setup (per cluster)

1. Settings → HTTPS → **Automatic wildcard renewal** (admin only, since it
   affects all hostings): enter the zone (default suggestion
   `acme.<panel host>`) and enable it.
2. Add the records the card shows. Each record goes in the DNS zone its own
   name belongs to, so for a panel at `panel.example.com`:
   ```
   acme.panel.example.com.   NS    ns-acme.example.com.      ; in the zone that serves panel.example.com
   ns-acme.example.com.      A     <master public IPv4>      ; in the zone example.com
   ns-acme.example.com.      AAAA  <master public IPv6>      ; only if the master has one
   ```
   The NS host is `ns-acme.<parent of the panel host>`, outside the
   delegated zone, so its A/AAAA are ordinary address records (not glue):
   the NS record and the address records can live in different zones,
   possibly at different DNS providers.
3. Press **Check delegation**. States: *not set up*, *delegation missing*
   (the zone is not delegated to this panel yet), *points elsewhere* (it is
   delegated to another panel or server), *could not be checked* (the lookup
   itself failed; retry), *working*.

Enabling starts the responder on the master only and opens port 53 udp+tcp in
the firewall; disabling closes both. Worker nodes never serve DNS. The
responder answers only names inside the zone, never recurses, refuses
everything else, and rate-limits per source address.

### Per wildcard

1. Hosting → **Domains & SSL** tab → **Wildcard renewal** block → **Set up automatic renewal**. The panel shows the
   challenge name and the CNAME target; give that record to the customer.
2. Once the CNAME is seen, issuing the wildcard is one button (no TXT
   copying) and renewal is automatic from then on.
3. Preview wildcards (`*.<base>` on test nodes) are set up the same way in
   Settings → HTTPS → Preview certificates.

Admins and operators (with access to the hosting) can set this up and see the
CNAME target. Customers only see "automatic renewal: on / off". The CNAME is
standing permission for the panel to obtain certificates for that name.

### Troubleshooting

- **Port 53 is held.** The zone is saved but the responder stays off, and the
  message names the process holding the port (`named` for BIND, dnsmasq,
  unbound, ...). Stop it, or bind it to loopback only, then enable again. The
  responder binds each non-loopback address, not `0.0.0.0`, so
  systemd-resolved's stub on 127.0.0.53 does not conflict.
- **"delegation missing" / "points elsewhere".** The NS record at the
  parent zone, or the NS host's address records, are absent, wrong, or not
  propagated yet. Re-check with `dig NS <zone>` and the steps under "Verify
  DNS before relying on it" below.
- **CNAME problems.** The Wildcard renewal block states what it saw: CNAME missing, CNAME
  points elsewhere (wrong label), or a plain TXT left over from manual
  issuance at the name (replace it with the CNAME). Before every order the
  master re-probes the CNAME and skips the order if it is wrong, so a removed
  CNAME never costs a failed validation.
- **"node <id> needs an update for automatic wildcard renewal".** The node
  that owns the certificate runs an older agent without the strict DNS-01
  RPCs. Update that node and retry.
- **"a renewal for <domain> is already running".** One renewal per domain at a
  time; wait for the running job (see /jobs) to finish.
- **Alerts.** An automatic attempt that fails alerts with the reason (zone
  delegation broken, CNAME missing, Let's Encrypt error). A broken zone
  (daily self-check) raises one admin alert, since it breaks every delegated
  wildcard at once. A wildcard with 14 days or fewer left always alerts.
- **Stale values.** TXT values are cleared after each attempt and expire on
  their own after 24 h, so a crash cannot leave them served forever.
- **Removing a hosting.** Purging a hosting deletes its label and the
  responder stops answering for it; the customer can then delete the CNAME.
  Trash keeps the label so a restore keeps working. Suspended hostings renew
  too and stay suspended.

### Verify DNS before relying on it

With `<master-ip>`, `<zone>`, `<label>` and `<base>` filled in:

```bash
dig @<master-ip> SOA <zone>                      # answers, aa flag set
dig @<master-ip> TXT _hyperion-check.<zone>      # the per-install token
dig +norec @<master-ip> TXT example.org          # status: REFUSED (out of zone)
dig +tcp @<master-ip> TXT <label>.<zone>         # TCP works; NOERROR, empty between renewals
dig TXT _acme-challenge.<base>                   # public resolver follows the CNAME into <zone>
```

An end-to-end issuance against Let's Encrypt staging on a test domain is still
recommended before relying on it in production.

## Docker monitoring

An optional module that watches the Docker Compose stacks on your nodes. It is
off until an administrator turns it on, and while it is off no node runs a
`docker` command, the sidebar has no Docker entry and no URL check runs.

### What it does

- Lists stacks per node, problems first: containers, state, health, restarts,
  exit code and OOM kills, published ports, CPU and memory, log size, and the
  disk used by images, volumes and build cache.
- Alerts on an unhealthy container, a restart loop, a container that exited
  badly or was OOM-killed, a stack that disappeared, and a Docker daemon that
  stops answering. A state has to last about 3 minutes before it alerts, so a
  deploy stays quiet. A job that exited 0 and will not be restarted (restart
  policy none or `on-failure`) is fine. A container Docker created but could
  not start (state `created` with a non-zero exit code) is a problem.
- Shows container and stack logs to people allowed to read them.
- Checks once a day whether the tag a container runs has moved on at its
  registry.
- Runs URL checks from the master (below), which replace an external uptime
  tool.
- Starts a reverse-proxy hosting from a stack that publishes a port, or points
  an existing one at it.

It is read-only. Hyperion never starts, stops, restarts, pulls, execs or deletes
anything in Docker, and it does not install or update Docker. Container
environment variables and labels other than the Compose ones never leave the
node. `hctl` and `/api/v1` do not cover the module yet.

### Turn it on

Docker has to be installed on each node you want to watch (Docker Engine from
Docker's own apt repository, for example). The module does not install it.

1. Settings → Panel → **Docker monitoring** → **Turn on Docker monitoring**
   (administrators only). This adds the **Docker** page and enables URL checks.
   The master needs no Docker for this step.
2. On the **Docker** page, press **Turn on** for each node, the master included.
   It runs as a background job and checks that the Docker daemon answers on
   that node. If Docker is missing, the job fails and says to install Docker
   first. If it is installed but stopped, the job says "Start Docker and try
   again". A node running an older agent says "update the node first".

`docker buildx` is optional. Without it, image updates still work for Docker
Hub but show "cannot verify" for every other registry and for private Hub
repositories.

### Turn it off

Settings → Panel → **Remove the module** asks every node to delete what
Hyperion kept about Docker (remembered stacks, open alerts, cached disk
figures, image-update answers and restart-loop history) and then turns the
module off on the master. The URL checks and their history are deleted with
it. A node that does not answer stays listed and the module stays on until it
is removed there. **Remove from this node** on the Docker page deletes the same
node data for that one node only. The URL checks stay, and the module stays on
for the cluster. Docker, its containers, images and volumes are never touched,
and reverse-proxy hostings made through the module stay, since they are
ordinary hostings.

### Logs

Opening a stack's or container's logs needs the Docker logs permission. It is
admin-level, custom roles can be given it, and it only works for a user who
can see every hosting, because these rows span all tenants. Customers never see
the Docker pages. The page shows the last 50 to 2000 lines (200 by
default), can filter by text and can follow the log. Opening a log writes an
audit entry (`docker.logs.read`) with who and which container. Following does
not write one per refresh. The entry is written on the node that serves the
logs, so the logs of a stack on a worker are audited in that worker's audit
log, not the master's.

A container on the `none` logging driver has no log to show, and the page says
so. The `journald` and `local` drivers can be read like the default one, but
keep no file Hyperion can measure, so their log size shows as 0.

Log lines appear in the panel only. Alerts by email, Slack or webhook never
contain them.

### Alerts

The master sends the outbound alerts, to the cluster's Slack webhook and the
administrator addresses, after a worker's alert has reached it. Per-stack
routing does not exist. Stack problems, daemon down, a node that stops
answering for about 3 minutes, and URL check failures go out by email and Slack
as well as the bell, each with a recovery. Image update notices are bell only,
one card per node.

Stopping on purpose is not told apart from a failure when Docker would bring
the container back. A `docker compose stop` of a service whose restart policy
is `always` or `unless-stopped` alerts after about 3 minutes, and recovers when
you start it again. A `docker compose down` removes the containers, so the
stack alerts as gone until you start it again or press **Forget** on it. A
service with restart policy `no` or `on-failure` that exited 0 counts as a
finished job and is fine; one that exited non-zero alerts, and a stopped
container often exits 143 or 137.

### Image updates

Once a day, per unique image reference, Hyperion compares the digest the
node pulled with the digest the registry holds under the same tag. It does not
look for a newer version number (`1.2` to `1.3`), and it pulls nothing.
Results are up to date, update available, or cannot verify (built locally,
pinned by digest, registry error, rate limit, or no buildx). A failed check
keeps the last answer, marked "The latest check failed"; with no earlier answer
it shows cannot verify. It also flags a
container running an older image than the tag's local copy.

Docker Hub is asked with an anonymous token and a `HEAD` on the manifest, which
does not count against Hub's per-IP pull limit. Other registries, and Hub
repositories that need a login, go through `docker buildx imagetools inspect`,
so **buildx has to be installed on the node** and the registry login has to be
in Docker's own credential store. Hyperion never reads or stores a registry
password. A rate-limited answer waits until the next day.

### URL checks

URL checks live on the **Monitoring** page, next to the per-hosting uptime
monitor, which is unchanged. Each check has an address, an interval (30 seconds
at the shortest), an expected status, how many failures alert, and optional own
email addresses, Slack webhook and generic webhook (the cluster's Slack and
administrator addresses otherwise). https addresses also warn at 14 and 3 days
before the certificate expires, and once more when it has expired. Uptime Kuma monitors are entered by hand: there is no import and no history
carried over.

The checks run **from the master** (on a single server with no workers, from
that server), so a whole node dying is seen from outside.
The flip side: an app on the master's own server has no outside view, and its
check only proves the master can reach itself.

Hyperion works out which node an address belongs to from its host name, and an
administrator can override that. When a check fails it asks that node for the
stack's state and puts it in the alert (for example "web: exit 137, out of
memory"), or says the node does not answer. An address that belongs to no
hosting is fine.

### Published ports and the firewall

A port published as `0.0.0.0:8080` is not stopped by Hyperion's firewall
input rules or its bans. Docker sends that traffic through forwarding, and on a
real node a rule dropping the port in an input chain did not stop a request
from outside. The app is then reachable directly, around nginx and the WAF.
Publish it on loopback instead, in the compose file:

```yaml
ports:
  - "127.0.0.1:8080:80"
```

The stack page warns when a port it offers for proxying is bound this way. A
reverse-proxy hosting can only target a loopback port that a container publishes, never a container
address, because that changes when the container is recreated. Ports 80 and 443
are not offered since nginx owns them. To add one, open a stack that publishes
a port and press **Add reverse proxy**: the new-site form opens with the type,
upstream and node filled in, and you type the domain.

A reverse-proxy hosting that already exists on the same node can be pointed at
the stack instead: pick it next to the port and press **Point it here**. Its
upstream changes to that port, as if you had changed it on the hosting's page,
and its visitors reach the stack from then on. Only hostings on the stack's own
node are offered, because `127.0.0.1` on another node is not this stack, and
only to people allowed to change a hosting's configuration.

### Troubleshooting

- **"Docker is not answering".** The daemon did not reply within the time
  limit. Check `systemctl status docker` on the node. The stacks shown are what
  it said last.
- **"Not reachable".** The master could not read the node. Its stacks are not
  shown, which does not mean they are running. A registered node gets a row
  unless its answer fails authentication (the master cannot verify who wrote
  it). That node then appears in a warning at the top of the page instead of a
  row.
- **"The Docker version on this node is too old".** Turning the module on read
  `docker version` and could not make sense of it. Hyperion asks Docker for
  JSON with the `{{json .}}` template, which older CLIs understand, but a
  very old Docker still answers in a form it cannot read. Update Docker.
- **An image shows "cannot verify".** The row says why. For a registry other
  than Docker Hub, install `docker-buildx-plugin` and log in with `docker login`
  as root on the node.
- **A removed stack stays listed.** Press **Forget** on it. That clears
  Hyperion's record and its alert, and touches no container.

## Logs

- Structured agent log: `/var/log/hyperion/agent.log` (JSON Lines).
- Audit log: query SQLite directly.
  ```bash
  sudo sqlite3 /var/lib/hyperion/state.db \
    "SELECT ts, action, result FROM audit_log ORDER BY id DESC LIMIT 20"
  ```

## Verifying the audit chain

```bash
sudo sqlite3 -line /var/lib/hyperion/state.db <<'SQL'
SELECT id, action, result FROM audit_log ORDER BY id LIMIT 5;
SQL
```

The chain is verified automatically on `hyperion-agent` startup; a broken
chain refuses to start (operator must rotate the log explicitly).

## Backup

For Foundation, back up the state DB + secrets dir:

```bash
sudo tar -czf /root/lm-backup-$(date +%F).tar.gz \
  /etc/hyperion /var/lib/hyperion
```

Full backup orchestration lands in sub-project 5.

## Updating

```bash
cd /opt/hyperion && git pull
cargo build --release --workspace
sudo systemctl stop hyperion-agent
sudo install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
sudo install -m 0755 target/release/hctl      /usr/bin/hctl
sudo systemctl start hyperion-agent
```

Schema migrations are compiled into `hyperion-agent` and applied on startup.

## Removal

```bash
sudo systemctl disable --now hyperion-agent
sudo rm /etc/systemd/system/hyperion-agent.service
sudo rm /usr/sbin/hyperion-agent /usr/bin/hctl
# Manually remove hosting state, /etc/hyperion, /var/lib/hyperion
# Manually run userdel for any system_users created by hyperion-agent.
```
