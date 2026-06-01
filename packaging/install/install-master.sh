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

# Source acquisition (private-repo-friendly). One of:
#   HYPERION_LOCAL_TARBALL=/path/to/hyperion.tar.gz  → extract that
#   HYPERION_SKIP_CLONE=1                            → assume $INSTALL_DIR is ready
#   HYPERION_GIT_URL=git@github.com:nechodom/hyperion → SSH clone (use ssh-agent)
#   HYPERION_GIT_TOKEN=ghp_xxx + HYPERION_GIT_URL=https://github.com/...
#     → HTTPS clone with PAT, passed via git credential helper (no token in argv)
# Default (public repo or world-readable mirror):
GIT_URL="${HYPERION_GIT_URL:-https://github.com/nechodom/hyperion}"
GIT_TOKEN="${HYPERION_GIT_TOKEN:-}"
LOCAL_TARBALL="${HYPERION_LOCAL_TARBALL:-}"
SKIP_CLONE="${HYPERION_SKIP_CLONE:-}"

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
acquire_source() {
  # 5a. Local tarball — air-gapped / pre-downloaded installs.
  if [[ -n "$LOCAL_TARBALL" ]]; then
    [[ -f "$LOCAL_TARBALL" ]] || fail "HYPERION_LOCAL_TARBALL not found: $LOCAL_TARBALL"
    log "Extracting $LOCAL_TARBALL → $INSTALL_DIR ..."
    install -d -m 0755 "$INSTALL_DIR"
    tar -xzf "$LOCAL_TARBALL" -C "$INSTALL_DIR" --strip-components=1
    return
  fi

  # 5b. Pre-cloned directory (operator did the clone with their creds).
  if [[ -n "$SKIP_CLONE" || -d "$INSTALL_DIR/.git" ]]; then
    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
      fail "HYPERION_SKIP_CLONE=1 but $INSTALL_DIR/.git not present."
    fi
    log "Reusing existing checkout at $INSTALL_DIR ..."
    return
  fi

  # 5c. PAT-via-credential-helper. Token stays in env; never appears on argv.
  if [[ -n "$GIT_TOKEN" ]]; then
    log "Cloning $GIT_URL ($REF) via HTTPS PAT (token from \$HYPERION_GIT_TOKEN) ..."
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

  # 5d. Plain clone (works for public repos OR with SSH agent + git@github.com URL).
  log "Fetching $GIT_URL ($REF) → $INSTALL_DIR ..."
  git clone --depth=1 --branch "$REF" "$GIT_URL" "$INSTALL_DIR" || {
    fail "git clone failed. For a private repo set HYPERION_GIT_TOKEN
       (HTTPS PAT) or HYPERION_GIT_URL=git@github.com:nechodom/hyperion
       (SSH with agent forwarding), or pre-clone into $INSTALL_DIR and
       re-run with HYPERION_SKIP_CLONE=1."
  }
}

acquire_source
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
for unit in hyperion-agent hyperion-web; do
  src="$INSTALL_DIR/packaging/systemd/${unit}.service"
  if [[ -f "$src" ]]; then
    install -m 0644 "$src" "/etc/systemd/system/${unit}.service"
  fi
done
systemctl daemon-reload

#-------- 9. MariaDB hardening (one-shot) ---------------------------------
if ! mariadb -e "SELECT 1" >/dev/null 2>&1; then
  log "NOTE: mariadb-secure-installation requires interactive input."
  log "Run it manually after this installer if you haven't already."
fi

#-------- 10. Bootstrap admin user ----------------------------------------
if [[ ! -f /etc/hyperion/web-admin.json ]]; then
  # When the script is run via `curl … | sudo bash`, stdin is the pipe,
  # not the terminal — a plain `read` would get an empty string. Read
  # from /dev/tty if it exists; otherwise require the env var.
  while [[ -z "$ADMIN_PASS" ]]; do
    if [[ -r /dev/tty ]]; then
      echo
      printf 'Choose admin password for the web UI (min 1 char): ' > /dev/tty
      IFS= read -rs ADMIN_PASS < /dev/tty
      echo > /dev/tty
    else
      fail "No terminal available for password prompt.
       Re-run with HYPERION_ADMIN_PASS set, e.g.:
         curl -fsSL <installer-url> | sudo HYPERION_ADMIN_PASS='your-pass' bash"
    fi
    if [[ -z "$ADMIN_PASS" ]]; then
      printf '  empty — try again.\n' > /dev/tty
    fi
  done
  log "Bootstrapping admin user '${ADMIN_USER}' ..."
  /usr/sbin/hyperion-web --config /etc/hyperion/web.toml bootstrap \
    --username "$ADMIN_USER" --password "$ADMIN_PASS"
fi

#-------- 10b. Pre-generate web session + CSRF keys ------------------------
# The systemd unit runs hyperion-web with ProtectSystem=full, which makes
# /etc read-only for the service. hyperion-web's keys::load_or_init would
# happily create these on first start in a writable environment, but here
# the sandbox blocks the write. We materialize them ahead of time so the
# running service only ever has to READ them.
gen_key_file() {
  local path="$1"
  if [[ -f "$path" ]]; then return 0; fi
  log "Generating $(basename "$path") ..."
  install -m 0600 /dev/null "$path"
  head -c 32 /dev/urandom | base64 -w 0 > "$path"
}
gen_key_file /etc/hyperion/web-session.key
gen_key_file /etc/hyperion/web-csrf.key

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
