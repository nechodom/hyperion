#!/usr/bin/env bash
# Hyperion node installer — Debian 12+.
#
# Usage (as root, on a fresh box, replacing the token + master URL with
# the values from your master's /install page):
#   curl -fsSL https://<master>/install/install-node.sh | sudo bash -s -- \
#     --token=ABCD-EFGH-IJKL-MNPQ --master=https://master.example.com
#
# What it does:
#   - Verifies Debian 12+
#   - apt installs nginx, MariaDB, PostgreSQL, PHP 8.3 (via deb.sury.org)
#   - Installs Rust if missing, builds hyperion-agent + hctl from source
#   - Drops binaries into /usr/sbin and /usr/bin
#   - Persists the invite token + master URL into /etc/hyperion/agent.toml
#     so once the controller's mTLS enrollment loop ships (sub-project
#     1.5 in the design docs), the agent rolls into the cluster
#     automatically.
#   - Enables + starts hyperion-agent (operates single-node until then)
#
# Re-running this script is safe; it skips steps already done.

set -euo pipefail

TOKEN=""
MASTER=""
REF="${HYPERION_REF:-main}"
INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
LABEL="${HYPERION_NODE_LABEL:-$(hostname -f 2>/dev/null || hostname)}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token=*)  TOKEN="${1#*=}";;
    --master=*) MASTER="${1#*=}";;
    --label=*)  LABEL="${1#*=}";;
    *) printf 'unknown arg: %s\n' "$1" >&2; exit 2;;
  esac
  shift
done

log()  { printf '\033[36m[hyperion]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run me as root."
[[ -n "$TOKEN"  ]] || fail "Missing --token=<invite-token>."
[[ -n "$MASTER" ]] || fail "Missing --master=<https://your-master>."

#-------- 1. OS check ------------------------------------------------------
. /etc/os-release || fail "/etc/os-release missing."
[[ "$ID" == "debian" ]] || fail "Debian required (got '$ID')."
[[ "${VERSION_ID%%.*}" -ge 12 ]] || fail "Debian 12+ required (got $VERSION_ID)."

#-------- 2. apt deps ------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
log "Installing base packages..."
apt-get update -qq
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release pkg-config build-essential git \
  nginx mariadb-server postgresql

mkdir -p /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/sury-php.gpg ]]; then
  curl -fsSL https://packages.sury.org/php/apt.gpg \
    -o /etc/apt/keyrings/sury-php.gpg
  echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ bookworm main" \
    > /etc/apt/sources.list.d/sury-php.list
  apt-get update -qq
fi
apt-get install -y -qq \
  php8.3-fpm php8.3-cli php8.3-mysql php8.3-pgsql

#-------- 3. Rust ----------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "Installing Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
fi
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

#-------- 4. Build agent ---------------------------------------------------
log "Fetching hyperion source ($REF) → $INSTALL_DIR ..."
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" fetch --depth=1 origin "$REF"
  git -C "$INSTALL_DIR" reset --hard FETCH_HEAD
else
  git clone --depth=1 --branch "$REF" \
    https://github.com/nechodom/hyperion "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

log "Building hyperion-agent + hctl ..."
cargo build --release --bin hyperion-agent --bin hctl --quiet

install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
install -m 0755 target/release/hctl           /usr/bin/hctl

#-------- 5. Users + dirs --------------------------------------------------
groupadd --system hyperion-admin 2>/dev/null || true
install -d -m 0700 /etc/hyperion /etc/hyperion/secrets /var/lib/hyperion
install -d -m 0750 /var/log/hyperion
install -d -m 0755 /var/lib/hyperion/acme-challenges
install -d -m 0700 /var/lib/hyperion/backups/local

#-------- 6. agent.toml with master enrollment info -----------------------
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
contact_email = "admin@example.com"
challenge_dir = "/var/lib/hyperion/acme-challenges"

# Enrollment with the master. The token persists here; the mTLS
# handshake that turns this into a fully-managed cluster member is
# sub-project 1.5 in the design docs. Until that lands the agent runs
# single-node and listens on /run/hyperion.sock locally.
[enrollment]
master_url   = "$MASTER"
invite_token = "$TOKEN"
node_label   = "$LABEL"
EOF
chmod 0600 /etc/hyperion/agent.toml

#-------- 7. systemd unit + start ------------------------------------------
if [[ -f "$INSTALL_DIR/packaging/systemd/hyperion-agent.service" ]]; then
  install -m 0644 "$INSTALL_DIR/packaging/systemd/hyperion-agent.service" \
    /etc/systemd/system/hyperion-agent.service
fi
systemctl daemon-reload
systemctl enable --now hyperion-agent
sleep 1
systemctl --no-pager --quiet is-active hyperion-agent || \
  fail "hyperion-agent failed to start; check journalctl -u hyperion-agent"

#-------- 8. Done ---------------------------------------------------------
echo
echo "============================================================"
echo "  ✓ Hyperion node provisioned ($LABEL)"
echo "  ----------------------------------------"
echo "  Local socket:    /run/hyperion.sock"
echo "  Master:          $MASTER"
echo "  Token recorded:  /etc/hyperion/agent.toml"
echo ""
echo "  CLI:  sudo usermod -aG hyperion-admin \$USER  (then re-login)"
echo "        hctl info"
echo "============================================================"
