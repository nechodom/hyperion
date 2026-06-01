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
  php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip

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
