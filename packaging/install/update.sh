#!/usr/bin/env bash
# Hyperion in-place update.
#
# What it does:
#   1. Stop hyperion-* services (if present)
#   2. git fetch + reset --hard to origin/$HYPERION_REF (refuses if local
#      changes — commit/stash first)
#   3. cargo build --release for hyperion-agent / hyperion-web / hctl
#   4. install -m 0755 the new binaries
#   5. Refresh systemd unit files (only rewrites if content differs)
#   6. Materialize missing web-session.key / web-csrf.key (works around
#      ProtectSystem=full sandbox preventing first-start key creation)
#   7. (--repair) wipe orphan hostings.state IN
#      ('provisioning','failed','deleting') rows
#   8. Start services back up + health-check via `systemctl is-active`
#
# Usage (as root):
#   sudo /opt/hyperion/packaging/install/update.sh
#   # from anywhere, public repo:
#   curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/update.sh | sudo bash
#   # with cleanup of orphan provisioning rows from a failed create:
#   sudo /opt/hyperion/packaging/install/update.sh --repair
#
# Env knobs:
#   HYPERION_INSTALL_DIR   default /opt/hyperion
#   HYPERION_REF           default main (branch/tag/sha)
#   HYPERION_GIT_TOKEN     PAT for private-repo HTTPS auth
#
# Flags:
#   --repair    Also drop orphan hostings rows in
#               state IN ('provisioning','failed','deleting'). Does NOT
#               touch on-disk artefacts (vhost, db, system user) — use
#               the diagnostic snippet printed on screen if those linger.
#   --no-build  Skip cargo build (useful for unit-only refreshes).
#   --ref=REF   Override $HYPERION_REF for this run.

set -euo pipefail

INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
REF="${HYPERION_REF:-main}"
GIT_TOKEN="${HYPERION_GIT_TOKEN:-}"
REPAIR=0
DO_BUILD=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repair)   REPAIR=1; shift;;
    --no-build) DO_BUILD=0; shift;;
    --ref=*)    REF="${1#*=}"; shift;;
    -h|--help)  sed -n '2,40p' "$0"; exit 0;;
    *) printf 'unknown arg: %s\n' "$1" >&2; exit 2;;
  esac
done

log()  { printf '\033[36m[hyperion]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root."

#-------- 0. Pre-flight ---------------------------------------------------
[[ -d "$INSTALL_DIR/.git" ]] || fail "No git checkout at $INSTALL_DIR.
       Set HYPERION_INSTALL_DIR=<path> or run install-master.sh first."

HAVE_AGENT=0; HAVE_WEB=0
[[ -f /etc/systemd/system/hyperion-agent.service ]] && HAVE_AGENT=1
[[ -f /etc/systemd/system/hyperion-web.service   ]] && HAVE_WEB=1
if (( HAVE_AGENT == 0 && HAVE_WEB == 0 )); then
  warn "No hyperion-* systemd units found — will build+install but won't restart anything."
fi

export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
if (( DO_BUILD )); then
  command -v cargo >/dev/null 2>&1 || fail "cargo not found. Re-run install-master.sh."
fi

#-------- 1. Stop services ------------------------------------------------
(( HAVE_WEB ))   && { log "Stopping hyperion-web ...";   systemctl stop hyperion-web   || true; }
(( HAVE_AGENT )) && { log "Stopping hyperion-agent ..."; systemctl stop hyperion-agent || true; }

#-------- 2. Pull ---------------------------------------------------------
cd "$INSTALL_DIR"
PREV=$(git rev-parse --short HEAD)
if [[ -n "$(git status --porcelain)" ]]; then
  fail "Working tree at $INSTALL_DIR has local changes:
$(git status --short | sed 's/^/    /')
       Commit/stash/remove them, then re-run."
fi

if [[ -n "$GIT_TOKEN" ]]; then
  log "Fetching origin via HTTPS PAT ..."
  export GIT_ASKPASS="/tmp/hyp-askpass.$$"
  cat > "$GIT_ASKPASS" <<'AP'
#!/bin/sh
case "$1" in
  Username*) printf 'oauth2\n' ;;
  Password*) printf '%s\n' "$HYPERION_GIT_TOKEN" ;;
esac
AP
  chmod 0700 "$GIT_ASKPASS"
  trap "rm -f $GIT_ASKPASS" EXIT
  git -c core.askPass="$GIT_ASKPASS" fetch origin "$REF"
else
  log "Fetching origin ..."
  git fetch origin "$REF"
fi
git reset --hard "origin/$REF"
NEW=$(git rev-parse --short HEAD)
log "Source: $PREV → $NEW"

#-------- 3. Build --------------------------------------------------------
if (( DO_BUILD )); then
  log "Building release binaries ..."
  cargo build --release \
    --bin hyperion-agent --bin hyperion-web --bin hctl --quiet
  log "Installing binaries ..."
  install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
  install -m 0755 target/release/hctl           /usr/bin/hctl
  if (( HAVE_WEB )); then
    install -m 0755 target/release/hyperion-web /usr/sbin/hyperion-web
  fi
else
  log "--no-build: skipping cargo build."
fi

#-------- 4. Refresh systemd units ----------------------------------------
refresh_unit() {
  local svc="$1"
  local src="$INSTALL_DIR/packaging/systemd/${svc}.service"
  local dst="/etc/systemd/system/${svc}.service"
  [[ -f "$src" ]] || return 0
  if ! cmp -s "$src" "$dst"; then
    log "Updating ${svc}.service unit file ..."
    install -m 0644 "$src" "$dst"
    systemctl daemon-reload
  fi
}
(( HAVE_AGENT )) && refresh_unit hyperion-agent
(( HAVE_WEB   )) && refresh_unit hyperion-web

#-------- 4a. TLS cert dir (idempotent) -----------------------------------
# hyperion-web auto-generates a self-signed cert on first start; we just
# need to make sure the directory exists and the agent service can write
# into it (covered by ReadWritePaths=/etc/hyperion in the systemd unit).
install -d -m 0700 /etc/hyperion/web-tls

#-------- 4b. wp-cli (best-effort install/update) -------------------------
# WordPress install adapter shells out to /usr/local/bin/wp. Older Hyperion
# installs predate wp-cli being installed by install-master.sh, so make
# update.sh fix that too.
if [[ ! -x /usr/local/bin/wp ]]; then
  log "Installing wp-cli ..."
  curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    -o /usr/local/bin/wp
  chmod 0755 /usr/local/bin/wp
fi

#-------- 5. Materialize web keys (idempotent) ----------------------------
# hyperion-web's systemd unit runs with ProtectSystem=full, which makes
# /etc read-only. keys::load_or_init would happily create these on a
# writable system but the sandbox blocks the write — pre-generate so the
# service only has to READ.
gen_key_file() {
  local path="$1"
  [[ -f "$path" ]] && return 0
  log "Generating $(basename "$path") ..."
  install -m 0600 /dev/null "$path"
  head -c 32 /dev/urandom | base64 -w 0 > "$path"
}
if (( HAVE_WEB )); then
  gen_key_file /etc/hyperion/web-session.key
  gen_key_file /etc/hyperion/web-csrf.key
fi

#-------- 6. --repair: drop orphan provisioning rows ----------------------
if (( REPAIR )); then
  STATE_DB="/var/lib/hyperion/state.db"
  if [[ ! -f "$STATE_DB" ]]; then
    warn "--repair: $STATE_DB not present yet, nothing to clean."
  elif ! command -v sqlite3 >/dev/null 2>&1; then
    warn "--repair: sqlite3 not installed. apt-get install -y sqlite3."
  else
    ORPHANS=$(sqlite3 "$STATE_DB" \
      "SELECT id || ' | ' || domain || ' | ' || state FROM hostings
       WHERE state IN ('provisioning','failed','deleting');" || true)
    if [[ -n "$ORPHANS" ]]; then
      log "--repair: removing orphan hostings rows:"
      printf '%s\n' "$ORPHANS" | sed 's/^/    /'
      sqlite3 "$STATE_DB" \
        "DELETE FROM hostings WHERE state IN ('provisioning','failed','deleting');"
      warn "On-disk artefacts (system_user, nginx vhost, db) are NOT touched."
      warn "If a re-create of the same domain still fails with 'group X exists' or"
      warn "similar, clean them by hand. Inspect with:"
      warn "    getent group  <name>"
      warn "    ls -la /home/<name>"
      warn "    grep -rl <name> /etc/nginx/sites-available/ /etc/nginx/sites-enabled/"
    else
      log "--repair: no orphan rows."
    fi
  fi
fi

#-------- 7. Start + health check -----------------------------------------
(( HAVE_AGENT )) && { log "Starting hyperion-agent ..."; systemctl start hyperion-agent || true; }
(( HAVE_WEB   )) && { log "Starting hyperion-web ...";   systemctl start hyperion-web   || true; }
sleep 1

HEALTHY=1
check_active() {
  if ! systemctl --quiet is-active "$1"; then
    warn "$1 is NOT running. Tail of journal:"
    journalctl -u "$1" -n 20 --no-pager | sed 's/^/    /'
    HEALTHY=0
  fi
}
(( HAVE_AGENT )) && check_active hyperion-agent
(( HAVE_WEB   )) && check_active hyperion-web

echo
echo "============================================================"
echo "  Hyperion update — $PREV → $NEW"
(( HAVE_AGENT )) && echo "  hyperion-agent: $(systemctl is-active hyperion-agent)"
(( HAVE_WEB   )) && echo "  hyperion-web:   $(systemctl is-active hyperion-web)"
echo "============================================================"

if (( HEALTHY == 0 )); then
  exit 1
fi
echo "  Tail live logs with:"
(( HAVE_AGENT )) && echo "    journalctl -u hyperion-agent -f"
(( HAVE_WEB   )) && echo "    journalctl -u hyperion-web -f"
