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
#   HYPERION_RELEASE_REPO  default nechodom/hyperion — owner/repo for releases
#   HYPERION_RELEASE_TAG   default rolling — release tag to pull
#                          (CI overwrites it on every push to main)
#
# Flags:
#   --repair       Also drop orphan hostings rows in
#                  state IN ('provisioning','failed','deleting'). Does NOT
#                  touch on-disk artefacts (vhost, db, system user) — use
#                  the diagnostic snippet printed on screen if those linger.
#   --no-build     Skip binary install (useful for unit/config-only refreshes).
#   --from-source  Skip the pre-built release; cargo build locally.
#                  Useful for testing local commits before they're pushed.
#   --release=TAG  Pull a specific release tag instead of "main" (rolling).
#   --ref=REF      Override $HYPERION_REF for git fetch.
#
# Default behaviour:
#   1. git fetch + reset to origin/$HYPERION_REF
#   2. Try to download pre-built binaries (+ SHA256SUMS verification)
#      from the GitHub release tagged $HYPERION_RELEASE_TAG.
#   3. If the release isn't there OR checksum fails, cargo build from
#      the freshly-fetched source.

set -euo pipefail

INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
REF="${HYPERION_REF:-main}"
GIT_TOKEN="${HYPERION_GIT_TOKEN:-}"
RELEASE_REPO="${HYPERION_RELEASE_REPO:-nechodom/hyperion}"
RELEASE_TAG="${HYPERION_RELEASE_TAG:-rolling}"   # rolling tag, set by GH Actions
REPAIR=0
DO_BUILD=1
PREFER_PREBUILT=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repair)        REPAIR=1; shift;;
    --no-build)      DO_BUILD=0; shift;;
    --from-source)   PREFER_PREBUILT=0; shift;;
    --release=*)     RELEASE_TAG="${1#*=}"; shift;;
    --ref=*)         REF="${1#*=}"; shift;;
    -h|--help)       sed -n '2,40p' "$0"; exit 0;;
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
  # Prune stale refs + fetch the BRANCH ref explicitly (CI publishes a
  # release tag also called "main", and a plain `git fetch origin main`
  # picks the tag over the branch — leaving you stuck on whatever
  # commit the last release was built from).
  git -c core.askPass="$GIT_ASKPASS" fetch --prune --tags --force origin \
      "refs/heads/$REF:refs/remotes/origin/$REF"
else
  log "Fetching origin ..."
  git fetch --prune --tags --force origin \
      "refs/heads/$REF:refs/remotes/origin/$REF"
fi
# Reset to the BRANCH tip (origin/$REF is now unambiguously the remote
# tracking branch, not the rolling release tag of the same name).
git reset --hard "origin/$REF"
NEW=$(git rev-parse --short HEAD)
log "Source: $PREV → $NEW"

#-------- 3. Install binaries — prefer GitHub release, fall back to local build
PREBUILT_OK=0
if (( DO_BUILD && PREFER_PREBUILT )); then
  log "Attempting pre-built binaries from github.com/$RELEASE_REPO@$RELEASE_TAG ..."
  TMP=$(mktemp -d /tmp/hyperion-update.XXXXXX)
  trap "rm -rf '$TMP'" EXIT
  REL_BASE="https://github.com/$RELEASE_REPO/releases/download/$RELEASE_TAG"
  fetch_ok=1
  for f in hyperion-agent hctl SHA256SUMS $((( HAVE_WEB )) && echo hyperion-web); do
    [[ -z "$f" ]] && continue
    if ! curl -fsSL --max-time 60 "$REL_BASE/$f" -o "$TMP/$f"; then
      log "  no $f in release — falling back to cargo build"
      fetch_ok=0
      break
    fi
  done
  if (( fetch_ok )); then
    # Verify SHA256 of each downloaded file matches SHA256SUMS.
    if ( cd "$TMP" && sha256sum --quiet --check SHA256SUMS 2>/dev/null ); then
      log "Pre-built binaries verified by SHA256SUMS — installing"
      install -m 0755 "$TMP/hyperion-agent" /usr/sbin/hyperion-agent
      install -m 0755 "$TMP/hctl"           /usr/bin/hctl
      if (( HAVE_WEB )); then
        install -m 0755 "$TMP/hyperion-web" /usr/sbin/hyperion-web
      fi
      PREBUILT_OK=1
    else
      log "  SHA256 mismatch on downloaded files — falling back to cargo build"
    fi
  fi
fi

if (( DO_BUILD && PREBUILT_OK == 0 )); then
  if ! command -v cargo >/dev/null 2>&1; then
    fail "cargo not found and no usable pre-built release. Re-run install-master.sh."
  fi
  log "Building release binaries from source ..."
  cargo build --release \
    --bin hyperion-agent --bin hyperion-web --bin hctl --quiet
  log "Installing binaries ..."
  install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
  install -m 0755 target/release/hctl           /usr/bin/hctl
  if (( HAVE_WEB )); then
    install -m 0755 target/release/hyperion-web /usr/sbin/hyperion-web
  fi
elif (( ! DO_BUILD )); then
  log "--no-build: skipping binary install."
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

# Per-version /run/php/<ver>/ subdirs for FPM sockets — without this
# hyperion's per-user FPM pools (listen = /run/php/8.x/<user>.sock)
# fail to open and nginx returns 502. /run is tmpfs so the snippet
# must be in /etc/tmpfiles.d/ to survive reboots.
tmpfiles_src="$INSTALL_DIR/packaging/systemd/hyperion-php-fpm-runtime.conf"
if [[ -f "$tmpfiles_src" ]]; then
  if ! cmp -s "$tmpfiles_src" /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf 2>/dev/null; then
    log "Installing systemd-tmpfiles snippet for /run/php/<ver>/ ..."
    install -m 0644 "$tmpfiles_src" /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf || true
  fi
  # Always re-materialize the dirs (idempotent + heals borked installs
  # where /run/php/8.x was missing from a previous reboot).
  systemd-tmpfiles --create /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf >/dev/null 2>&1 || true
fi

#-------- 4-aux. Make sure PHP-FPM + web/db daemons are enabled -----------
# Older install-master.sh installed the packages but never enabled the
# services; first hosting create then failed with
#   "php8.3-fpm.service is not active, cannot reload"
# Bring them up here so the agent's adapter never has to self-heal.
for svc in nginx mariadb postgresql vsftpd \
           php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm; do
  if systemctl list-unit-files --no-pager "$svc.service" 2>/dev/null \
       | grep -q "^$svc.service"; then
    systemctl enable --now "$svc" >/dev/null 2>&1 || true
  fi
done

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
