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

# Source acquisition — same env knobs as install-master.sh.
GIT_URL="${HYPERION_GIT_URL:-https://github.com/nechodom/hyperion}"
GIT_TOKEN="${HYPERION_GIT_TOKEN:-}"
LOCAL_TARBALL="${HYPERION_LOCAL_TARBALL:-}"
SKIP_CLONE="${HYPERION_SKIP_CLONE:-}"

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
  nginx mariadb-server postgresql vsftpd

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
systemctl enable --now php8.3-fpm
systemctl enable --now nginx mariadb postgresql || true

# vsftpd setup (same as install-master.sh)
if ! grep -q "/usr/sbin/nologin" /etc/shells 2>/dev/null; then
  echo "/usr/sbin/nologin" >> /etc/shells
fi
if [[ ! -f /etc/vsftpd.conf.hyperion-orig && -f /etc/vsftpd.conf ]]; then
  cp /etc/vsftpd.conf /etc/vsftpd.conf.hyperion-orig
  cat > /etc/vsftpd.conf <<'EOFV'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
allow_writeable_chroot=YES
pam_service_name=vsftpd
secure_chroot_dir=/var/run/vsftpd/empty
user_sub_token=$USER
local_root=/home/$USER
xferlog_enable=YES
xferlog_std_format=YES
seccomp_sandbox=NO
EOFV
fi
systemctl enable --now vsftpd || true

# wp-cli — required for WordPress install requests dispatched from master.
if [[ ! -x /usr/local/bin/wp ]]; then
  log "Installing wp-cli ..."
  curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    -o /usr/local/bin/wp
  chmod 0755 /usr/local/bin/wp
fi

#-------- 3. Rust ----------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "Installing Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
fi
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

#-------- 4. Acquire source + build agent ---------------------------------
acquire_source() {
  if [[ -n "$LOCAL_TARBALL" ]]; then
    [[ -f "$LOCAL_TARBALL" ]] || fail "HYPERION_LOCAL_TARBALL not found: $LOCAL_TARBALL"
    log "Extracting $LOCAL_TARBALL → $INSTALL_DIR ..."
    install -d -m 0755 "$INSTALL_DIR"
    tar -xzf "$LOCAL_TARBALL" -C "$INSTALL_DIR" --strip-components=1
    return
  fi
  if [[ -n "$SKIP_CLONE" || -d "$INSTALL_DIR/.git" ]]; then
    log "Reusing existing checkout at $INSTALL_DIR ..."
    return
  fi
  if [[ -n "$GIT_TOKEN" ]]; then
    log "Cloning $GIT_URL via HTTPS PAT ..."
    export GIT_ASKPASS="/tmp/hyp-askpass.$$"
    cat > "$GIT_ASKPASS" <<'EOF'
#!/bin/sh
case "$1" in
  Username*) printf 'oauth2\n' ;;
  Password*) printf '%s\n' "$HYPERION_GIT_TOKEN" ;;
esac
EOF
    chmod 0700 "$GIT_ASKPASS"
    trap "rm -f $GIT_ASKPASS" EXIT
    git -c core.askPass="$GIT_ASKPASS" clone --depth=1 --branch "$REF" \
      "$GIT_URL" "$INSTALL_DIR"
    return
  fi
  log "Fetching $GIT_URL ($REF) → $INSTALL_DIR ..."
  git clone --depth=1 --branch "$REF" "$GIT_URL" "$INSTALL_DIR" || {
    fail "git clone failed. For a private repo set HYPERION_GIT_TOKEN
       or HYPERION_GIT_URL=git@github.com:... or pre-clone into
       $INSTALL_DIR and re-run with HYPERION_SKIP_CLONE=1, or supply
       HYPERION_LOCAL_TARBALL for an offline install."
  }
}

acquire_source
cd "$INSTALL_DIR"

log "Building hyperion-agent + hctl ..."
cargo build --release --bin hyperion-agent --bin hctl --quiet

install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
install -m 0755 target/release/hctl           /usr/bin/hctl

#-------- 5. Users + dirs --------------------------------------------------
groupadd --system hyperion-admin 2>/dev/null || true
install -d -m 0700 /etc/hyperion /etc/hyperion/secrets
# 0o711 — owner full, others traverse-only. See install-master.sh for
# the rationale (nginx needs to traverse this on the way to
# /var/lib/hyperion/acme-challenges/<token> for HTTP-01).
install -d -m 0711 /var/lib/hyperion
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

# Optional FTP/FTPS/SFTP remote backup destination (off by default).
[backup_remote]
enabled  = false
scheme   = "ftp"
host     = ""
port     = 21
user     = ""
password = ""
base_path = "/hyperion-backups"

# Optional Slack incoming webhook for cluster-wide notifications.
[slack]
default_webhook = ""

# Enrollment with the master.
#
# On first boot the agent POSTs <master_url>/api/enroll with this
# token, receives back a node_id + per-node secret, and persists
# them to /etc/hyperion/node-id.json. From that point on the agent
# heartbeats every 60s — visible on the master's /install page
# under Enrolled nodes.
#
# verify_tls=false because install-master.sh ships a self-signed
# cert (no DNS at install time → no LE). The bearer token + per-
# node secret are the authentication; TLS here is encryption-in-
# transit. Flip to true once the master serves a real cert.
#
# Retry on failure: if the master isn't reachable on first boot,
# the agent retries 5× with growing backoff (~9 min total). Past
# that, run on this node:
#   sudo rm -f /etc/hyperion/node-id.json
#   sudo systemctl restart hyperion-agent
# and watch journalctl -u hyperion-agent -f | grep enroll
[enrollment]
master_url   = "$MASTER"
invite_token = "$TOKEN"
node_label   = "$LABEL"
verify_tls   = false

# Master→node remote RPC.
#
# When enabled, the agent runs a second HTTPS listener (port 9443
# by default) accepting signed RPC requests from the master. This
# is what makes the master's UI "Target node" dropdown work —
# without it, the master can still see this node in its registry
# but can't dispatch hosting create / delete / etc. to it.
#
# Auth model: the master holds an Ed25519 signing key
# (/etc/hyperion/master-rpc.key on the master); the public half is
# delivered to this node at enrollment time and on every heartbeat
# ack. Each remote RPC carries an Ed25519 signature over
# (node_id, ts, nonce, body_hash) — only requests signed by the
# legitimate master pass.
#
# TLS on this port is self-signed (auto-generated on first boot).
# The signature is the actual authentication; TLS is transport
# encryption.
#
# Make sure 9443 is OPEN in your firewall:
#   ufw allow proto tcp from <master-ip> to any port 9443
# (or scope wider if your topology needs it.)
[remote_rpc]
enabled       = true
bind          = "0.0.0.0:9443"
tls_cert_file = "/etc/hyperion/agent-rpc.crt"
tls_key_file  = "/etc/hyperion/agent-rpc.key"
EOF
chmod 0600 /etc/hyperion/agent.toml

#-------- 6.5 firewall opening for master→node RPC --------------------------
# Best-effort: when ufw is installed and active, allow port 9443
# from anywhere. Operator can tighten this later via
# `ufw delete allow 9443/tcp && ufw allow proto tcp from <master> to any port 9443`.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 9443/tcp comment 'hyperion master->node RPC' || true
  echo "  Opened ufw 9443/tcp for master→node RPC."
fi

#-------- 7. systemd unit + start ------------------------------------------
if [[ -f "$INSTALL_DIR/packaging/systemd/hyperion-agent.service" ]]; then
  install -m 0644 "$INSTALL_DIR/packaging/systemd/hyperion-agent.service" \
    /etc/systemd/system/hyperion-agent.service
fi
systemctl daemon-reload

# /run/php/<ver>/ subdirs for FPM sockets — see install-master.sh for
# the rationale. Required for HTTP requests to reach PHP-FPM.
tmpfiles_src="$INSTALL_DIR/packaging/systemd/hyperion-php-fpm-runtime.conf"
if [[ -f "$tmpfiles_src" ]]; then
  install -m 0644 "$tmpfiles_src" /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf
  systemd-tmpfiles --create /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf || true
fi
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
