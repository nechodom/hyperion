#!/usr/bin/env bash
# Hyperion master installer — Debian 12+.
#
# Usage (as root, on a fresh box):
#   curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/install-master.sh | sudo bash
#
# What it does:
#   - Verifies Debian 12+
#   - apt installs nginx, MariaDB, PostgreSQL, PHP 8.3 (via deb.sury.org)
#   - Installs Rust if missing, builds hyperion from source (one-time)
#   - Drops binaries into /usr/sbin and /usr/bin
#   - Creates /etc/hyperion, /var/lib/hyperion, /var/log/hyperion
#   - Writes default agent.toml + web.toml
#   - Installs systemd units, enables + starts hyperion-agent + hyperion-web
#   - Prompts for an initial admin password and bootstraps the web user
#   - Prints the URL of the freshly running admin UI
#
# Re-running this script is safe; it skips steps already done.

set -euo pipefail

#-------- 0. Args ----------------------------------------------------------
REF="${HYPERION_REF:-main}"
INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
ADMIN_USER="${HYPERION_ADMIN_USER:-admin}"
ADMIN_PASS="${HYPERION_ADMIN_PASS:-}"
LISTEN="${HYPERION_LISTEN:-0.0.0.0:8443}"
CONTACT_EMAIL="${HYPERION_ACME_EMAIL:-}"

log()  { printf '\033[36m[hyperion]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

if [[ $EUID -ne 0 ]]; then
  fail "Run me as root."
fi

#-------- 1. OS check ------------------------------------------------------
. /etc/os-release || fail "/etc/os-release missing — not a Debian-family box?"
[[ "$ID" == "debian" ]] || fail "Debian required (got '$ID')."
[[ "${VERSION_ID%%.*}" -ge 12 ]] || fail "Debian 12+ required (got $VERSION_ID)."

log "Debian $VERSION_ID detected. Updating apt cache..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

#-------- 2. Base packages -------------------------------------------------
log "Installing base packages..."
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release pkg-config build-essential git \
  nginx mariadb-server postgresql

mkdir -p /etc/apt/keyrings

#-------- 3. PHP via deb.sury.org -----------------------------------------
if [[ ! -f /etc/apt/keyrings/sury-php.gpg ]]; then
  log "Adding deb.sury.org PHP repo..."
  curl -fsSL https://packages.sury.org/php/apt.gpg \
    -o /etc/apt/keyrings/sury-php.gpg
  echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ bookworm main" \
    > /etc/apt/sources.list.d/sury-php.list
  apt-get update -qq
fi
log "Installing PHP 8.3..."
apt-get install -y -qq \
  php8.3-fpm php8.3-cli php8.3-mysql php8.3-pgsql \
  php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip

#-------- 4. Rust toolchain ------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "Installing Rust toolchain (rustup, minimal)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
fi
# Ensure cargo is on PATH for this shell
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

#-------- 5. Source checkout + build --------------------------------------
log "Fetching hyperion source ($REF) → $INSTALL_DIR ..."
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" fetch --depth=1 origin "$REF"
  git -C "$INSTALL_DIR" reset --hard FETCH_HEAD
else
  git clone --depth=1 --branch "$REF" \
    https://github.com/nechodom/hyperion "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

log "Building release binaries (this can take a few minutes the first time)..."
cargo build --release --workspace --quiet

log "Installing binaries..."
install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
install -m 0755 target/release/hyperion-web   /usr/sbin/hyperion-web
install -m 0755 target/release/hctl           /usr/bin/hctl

#-------- 6. Users + directories ------------------------------------------
groupadd --system hyperion-admin 2>/dev/null || true
install -d -m 0700 /etc/hyperion
install -d -m 0700 /etc/hyperion/secrets
install -d -m 0700 /var/lib/hyperion
install -d -m 0750 /var/log/hyperion
install -d -m 0755 /var/lib/hyperion/acme-challenges
install -d -m 0700 /var/lib/hyperion/backups/local

#-------- 7. Config files (idempotent) ------------------------------------
if [[ ! -f /etc/hyperion/agent.toml ]]; then
  log "Writing /etc/hyperion/agent.toml ..."
  cat > /etc/hyperion/agent.toml <<EOF
[agent]
socket_path  = "/run/hyperion.sock"
socket_group = "hyperion-admin"
state_db     = "/var/lib/hyperion/state.db"
secrets_dir  = "/etc/hyperion/secrets"
log_path     = "/var/log/hyperion/agent.log"
home_root    = "/home"
backup_root  = "/var/lib/hyperion/backups/local"

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
contact_email = "${CONTACT_EMAIL:-admin@example.com}"
challenge_dir = "/var/lib/hyperion/acme-challenges"
EOF
fi

if [[ ! -f /etc/hyperion/web.toml ]]; then
  log "Writing /etc/hyperion/web.toml ..."
  cat > /etc/hyperion/web.toml <<EOF
[web]
listen               = "$LISTEN"
agent_socket         = "/run/hyperion.sock"
admin_user_file      = "/etc/hyperion/web-admin.json"
session_key_file     = "/etc/hyperion/web-session.key"
csrf_key_file        = "/etc/hyperion/web-csrf.key"
session_ttl_secs     = 28800
secure_cookies       = false
session_cookie_name  = "hyperion_session"
EOF
fi
chmod 0600 /etc/hyperion/agent.toml /etc/hyperion/web.toml

#-------- 8. systemd units -------------------------------------------------
if [[ -f "$INSTALL_DIR/packaging/systemd/hyperion-agent.service" ]]; then
  install -m 0644 "$INSTALL_DIR/packaging/systemd/hyperion-agent.service" \
    /etc/systemd/system/hyperion-agent.service
fi
cat > /etc/systemd/system/hyperion-web.service <<'EOF'
[Unit]
Description=hyperion web admin UI
After=hyperion-agent.service network-online.target
Requires=hyperion-agent.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/hyperion-web --config /etc/hyperion/web.toml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
PrivateTmp=true
LogsDirectory=hyperion
RuntimeDirectory=hyperion
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

#-------- 9. MariaDB hardening (one-shot) ---------------------------------
if ! mariadb -e "SELECT 1" >/dev/null 2>&1; then
  log "NOTE: mariadb-secure-installation requires interactive input."
  log "Run it manually after this installer if you haven't already."
fi

#-------- 10. Bootstrap admin user ----------------------------------------
if [[ ! -f /etc/hyperion/web-admin.json ]]; then
  if [[ -z "$ADMIN_PASS" ]]; then
    echo
    read -rsp "Choose admin password for the web UI: " ADMIN_PASS
    echo
  fi
  log "Bootstrapping admin user '${ADMIN_USER}' ..."
  /usr/sbin/hyperion-web --config /etc/hyperion/web.toml bootstrap \
    --username "$ADMIN_USER" --password "$ADMIN_PASS"
fi

#-------- 11. Enable + start services -------------------------------------
log "Enabling + starting hyperion-agent ..."
systemctl enable --now hyperion-agent
log "Enabling + starting hyperion-web ..."
systemctl enable --now hyperion-web

sleep 1
systemctl --no-pager --quiet is-active hyperion-agent || \
  fail "hyperion-agent failed to start; check journalctl -u hyperion-agent"
systemctl --no-pager --quiet is-active hyperion-web || \
  fail "hyperion-web failed to start; check journalctl -u hyperion-web"

#-------- 12. Done ---------------------------------------------------------
FQDN="$(hostname -f 2>/dev/null || hostname)"
echo
echo "============================================================"
echo "  ✓ Hyperion master installed"
echo "  ----------------------------------------"
echo "  Web UI:   https://${FQDN}:${LISTEN##*:}"
echo "  CLI:      hctl info"
echo "  Configs:  /etc/hyperion/"
echo "  Logs:     journalctl -u hyperion-agent -u hyperion-web"
echo ""
echo "  Next steps:"
echo "    1. sudo usermod -aG hyperion-admin \$USER      (then log out / in)"
echo "    2. Open the Web UI and log in as '${ADMIN_USER}'"
echo "    3. /install in the UI → generate invite tokens for new nodes"
echo "============================================================"
