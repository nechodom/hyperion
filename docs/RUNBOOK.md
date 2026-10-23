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
   The NS host is `ns-acme.<parent of the panel host>`, so the NS record and
   the glue A/AAAA can live in different zones, possibly at different DNS
   providers.
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
- **"delegation missing" / "points elsewhere".** The NS or glue record at the
  parent zone is absent, wrong, or not propagated yet. Re-check with
  `dig NS <zone>` and the staging checklist below.
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
