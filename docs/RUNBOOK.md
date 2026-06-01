# linux-manager — Operator Runbook

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

## 2. Install lm-agent

Build from source on the host (or copy a pre-built binary):

```bash
sudo apt-get install -y curl build-essential pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"

git clone <repo-url> /opt/linux-manager
cd /opt/linux-manager
cargo build --release --workspace
sudo install -m 0755 target/release/lm-agent /usr/sbin/lm-agent
sudo install -m 0755 target/release/lm        /usr/bin/lm
```

## 3. Set up users + dirs + config

```bash
sudo groupadd --system lm-admin
sudo usermod -aG lm-admin "$USER"    # log out / back in to pick up

sudo install -d -m 0700 /etc/linux-manager
sudo install -d -m 0700 /etc/linux-manager/secrets
sudo install -d -m 0700 /var/lib/linux-manager
sudo install -d -m 0750 /var/log/linux-manager
sudo install -d -m 0755 /var/lib/linux-manager/acme-challenges

sudo tee /etc/linux-manager/agent.toml > /dev/null <<'EOF'
[agent]
socket_path = "/run/linux-manager.sock"
socket_group = "lm-admin"
state_db    = "/var/lib/linux-manager/state.db"
secrets_dir = "/etc/linux-manager/secrets"
log_path    = "/var/log/linux-manager/agent.log"
home_root   = "/home"

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
contact_email = "you@example.com"   # required for LE; rotate as needed
challenge_dir = "/var/lib/linux-manager/acme-challenges"
EOF
```

## 4. systemd unit

```bash
sudo tee /etc/systemd/system/lm-agent.service > /dev/null <<'EOF'
[Unit]
Description=linux-manager agent
After=network-online.target nginx.service mariadb.service postgresql.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/lm-agent --config /etc/linux-manager/agent.toml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=false
ProtectKernelTunables=true
ProtectKernelModules=true
PrivateTmp=true
LogsDirectory=linux-manager
RuntimeDirectory=linux-manager

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now lm-agent
sudo systemctl status lm-agent
```

The socket appears at `/run/linux-manager.sock` (group `lm-admin`).

## 5. Smoke test

```bash
lm info
# agent: <hostname> version=0.1.0 hostings=0

lm hosting create example.cz --php 8.3 --db mariadb
# ✓ created example_cz (id=01JXX...)
#   root: /home/example_cz/example.cz/htdocs
#   db:   lm_xxx_examplecz (user=lm_xxx_u, password=<random>)
#   cert: issuer=self-signed, not_after=...

lm hosting list
lm hosting get example.cz
lm hosting delete example.cz
```

> **Cert note.** Foundation issues a self-signed cert via `rcgen` so
> the rest of the pipeline (vhost, FPM, DB) works on day one. Replace
> with Let's Encrypt via the cert renewal loop landed in sub-project 9.

## Troubleshooting

- **Permission denied on socket** — make sure your user is in `lm-admin`
  and you've started a new shell since the `usermod -aG` change.
- **`useradd: not in sudoers`** — `lm-agent` is supposed to run as root
  through systemd. If running from a shell, prefix with `sudo`.
- **nginx fails `nginx -t`** — agent will restore the backup vhost on
  failure; check `journalctl -u lm-agent -e`.
- **MariaDB socket auth** — Debian default uses
  `/var/run/mysqld/mysqld.sock` and unix_socket auth for root. If you
  changed this, the mariadb adapter will fail; add an entry to
  `/root/.my.cnf` with credentials.

## Logs

- Structured agent log: `/var/log/linux-manager/agent.log` (JSON Lines).
- Audit log: query SQLite directly.
  ```bash
  sudo sqlite3 /var/lib/linux-manager/state.db \
    "SELECT ts, action, result FROM audit_log ORDER BY id DESC LIMIT 20"
  ```

## Verifying the audit chain

```bash
sudo sqlite3 -line /var/lib/linux-manager/state.db <<'SQL'
SELECT id, action, result FROM audit_log ORDER BY id LIMIT 5;
SQL
```

The chain is verified automatically on `lm-agent` startup; a broken
chain refuses to start (operator must rotate the log explicitly).

## Backup

For Foundation, back up the state DB + secrets dir:

```bash
sudo tar -czf /root/lm-backup-$(date +%F).tar.gz \
  /etc/linux-manager /var/lib/linux-manager
```

Full backup orchestration lands in sub-project 5.

## Updating

```bash
cd /opt/linux-manager && git pull
cargo build --release --workspace
sudo systemctl stop lm-agent
sudo install -m 0755 target/release/lm-agent /usr/sbin/lm-agent
sudo install -m 0755 target/release/lm        /usr/bin/lm
sudo systemctl start lm-agent
```

Schema migrations are compiled into `lm-agent` and applied on startup.

## Removal

```bash
sudo systemctl disable --now lm-agent
sudo rm /etc/systemd/system/lm-agent.service
sudo rm /usr/sbin/lm-agent /usr/bin/lm
# Manually remove hosting state, /etc/linux-manager, /var/lib/linux-manager
# Manually run userdel for any system_users created by lm-agent.
```
