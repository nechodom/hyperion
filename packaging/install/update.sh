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

# Self-update guard. Bash already loaded the running copy of this
# script into memory; any changes in this very file that landed
# in the new commits would only take effect on the NEXT run. To
# avoid operators having to "run update.sh twice for the message
# to be right", re-exec the freshly checked-out copy when this
# file itself changed between PREV and NEW.
#
# The HYPERION_REEXEC env-var marker stops infinite loops: the
# re-exec'd process sees the flag and skips this block.
if [[ "$PREV" != "$NEW" && -z "${HYPERION_REEXEC:-}" ]]; then
  if ! git diff --quiet "$PREV" "$NEW" -- packaging/install/update.sh 2>/dev/null; then
    log "update.sh itself changed between $PREV and $NEW — re-exec'ing the fresh copy"
    export HYPERION_REEXEC=1
    exec "$0" "$@"
  fi
fi
unset HYPERION_REEXEC

HEAD_FULL=$(git rev-parse HEAD)

#-------- 2b. Staleness guard: does the rolling release match our source? --
# CI rebuilds the pre-built release on every push to main, but that build
# takes a few minutes. Update during that window (or before CI runs) and the
# release is a commit BEHIND the source you just checked out — installing it
# silently runs OLD code under a banner that says the new SHA. That bit us:
# the agent stayed on the prior parser while the panel showed a bug the new
# code already fixed. CI now ships a VERSION marker (= the exact commit the
# binaries were built from); compare it to our HEAD and fall back to a source
# build when they disagree, so the install always matches what you checked out.
if (( DO_BUILD && PREFER_PREBUILT )); then
  REL_VERSION=$(curl -fsSL --max-time 30 \
    "https://github.com/$RELEASE_REPO/releases/download/$RELEASE_TAG/VERSION" 2>/dev/null \
    | tr -d '[:space:]' || true)
  if [[ -z "$REL_VERSION" ]]; then
    warn "The @$RELEASE_TAG release has no VERSION marker (it predates version stamping)."
    warn "  Can't confirm the pre-built binaries match your source — proceeding with them."
    warn "  Re-run once CI has republished, or pass --from-source to build locally instead."
  elif [[ "$REL_VERSION" != "$HEAD_FULL" ]]; then
    log "Rolling release is at ${REL_VERSION:0:12}; your source is at ${HEAD_FULL:0:12}."
    log "  Pre-built binaries aren't built from your checkout (CI still building, or the"
    log "  release lagged) — building from source so the install matches your HEAD."
    PREFER_PREBUILT=0
  else
    log "Rolling release matches your source (${HEAD_FULL:0:12}) — using pre-built binaries."
  fi
fi

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
    # Capture both curl's exit code and the HTTP status separately
    # so the fall-back message can name the real cause. The OLD
    # message ("no <file> in release") attributed every transient
    # GitHub 5xx as if the file were missing — operators saw
    # "no hyperion-web in release" on a healthy install after a
    # GitHub CDN hiccup and assumed the release was broken.
    code=$(curl -sSL --max-time 60 -w '%{http_code}' \
              -o "$TMP/$f" "$REL_BASE/$f" 2>"$TMP/$f.curlerr") || true
    if [[ "$code" != "200" ]]; then
      case "$code" in
        404)
          log "  '$f' not in the @$RELEASE_TAG release — falling back to cargo build"
          ;;
        5*)
          log "  GitHub returned HTTP $code fetching '$f' (transient — likely rate-limit or CDN) — falling back to cargo build"
          ;;
        000|"")
          # curl couldn't even open a connection; show its own error.
          err=$(head -c 200 "$TMP/$f.curlerr" 2>/dev/null | tr -d '\n')
          log "  network failure fetching '$f': ${err:-curl exit $?} — falling back to cargo build"
          ;;
        *)
          log "  unexpected HTTP $code fetching '$f' — falling back to cargo build"
          ;;
      esac
      fetch_ok=0
      break
    fi
  done
  if (( fetch_ok )); then
    # Verify SHA256 of each downloaded file matches SHA256SUMS.
    #
    # On worker nodes HAVE_WEB=0 so hyperion-web was NOT downloaded.
    # Running `sha256sum --check SHA256SUMS` against the upstream
    # list would then print
    #     hyperion-web: FAILED open or read
    # which reads exactly like a broken install even though it's
    # the intended "no web binary on a worker" path. Filter the
    # SHA256SUMS list down to just the files we actually fetched
    # before handing it to sha256sum.
    EXPECTED=(hyperion-agent hctl)
    (( HAVE_WEB )) && EXPECTED+=(hyperion-web)
    if (
        cd "$TMP"
        for f in "${EXPECTED[@]}"; do
          grep -E "[[:space:]]${f}\$" SHA256SUMS || {
            echo "  expected file '$f' missing from SHA256SUMS" >&2
            exit 1
          }
        done | sha256sum --quiet --check - 2>/dev/null
    ); then
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

  # On small (1–2 GB) master nodes the from-source build can be OOM-killed
  # (rustc/linker peak during codegen). If RAM is tight and there's no swap,
  # add a temporary swapfile for the duration of the build and remove it after
  # — whether the build succeeds or fails.
  SWAPFILE=""
  mem_avail_kb="$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  swap_total_kb="$(awk '/SwapTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if (( mem_avail_kb < 1900000 )) && (( swap_total_kb < 1000000 )); then
    sf="/var/tmp/hyperion-build.swap"
    avail_disk_kb="$(df -Pk /var/tmp | awk 'NR==2{print $4}')"
    if (( avail_disk_kb > 5000000 )); then
      log "  low RAM (${mem_avail_kb} kB avail, no swap) — adding a temporary 4 GB swapfile for the build"
      rm -f "$sf"
      if { fallocate -l 4G "$sf" 2>/dev/null || dd if=/dev/zero of="$sf" bs=1M count=4096 status=none 2>/dev/null; } \
         && chmod 600 "$sf" && mkswap "$sf" >/dev/null 2>&1 && swapon "$sf" 2>/dev/null; then
        SWAPFILE="$sf"
      else
        rm -f "$sf"
        warn "  couldn't enable a temp swapfile — proceeding (build may OOM)"
      fi
    else
      warn "  low RAM and <5 GB free on /var/tmp — can't add swap; build may OOM"
    fi
  fi

  # Stamp the exact checked-out commit into the binaries. build.rs reads this
  # env first, and `rerun-if-env-changed=HYPERION_GIT_SHA` forces a rebuild if
  # a previous incremental build had baked a different SHA — so a source build
  # can never embed a stale commit. `|| rc=$?` keeps the swap cleanup reachable
  # under `set -e`.
  build_rc=0
  HYPERION_GIT_SHA="$HEAD_FULL" cargo build --release \
    --bin hyperion-agent --bin hyperion-web --bin hctl --quiet || build_rc=$?
  if [ -n "$SWAPFILE" ]; then
    swapoff "$SWAPFILE" 2>/dev/null || true
    rm -f "$SWAPFILE"
  fi
  if (( build_rc != 0 )); then
    fail "cargo build failed (exit $build_rc). On a low-RAM box, ensure some swap is available and re-run."
  fi

  log "Installing binaries ..."
  install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
  install -m 0755 target/release/hctl           /usr/bin/hctl
  if (( HAVE_WEB )); then
    install -m 0755 target/release/hyperion-web /usr/sbin/hyperion-web
  fi
elif (( ! DO_BUILD )); then
  log "--no-build: skipping binary install."
fi

#-------- 3b. site-mail-wrapper -------------------------------------------
# Tiny bash shim that PHP-FPM execs as `sendmail_path` for every
# pool. Logs metadata of outgoing site mail to /var/lib/hyperion/
# site-mail/<user>.jsonl, then forwards to the real sendmail. Idempotent
# install — only updates the file when its content actually changed
# so we don't restart FPM pools unnecessarily.
SITE_MAIL_SRC="$INSTALL_DIR/packaging/install/site-mail-wrapper.sh"
SITE_MAIL_DST="/usr/local/lib/hyperion/site-mail-wrapper"
if [[ -f "$SITE_MAIL_SRC" ]]; then
  install -d -m 0755 /usr/local/lib/hyperion
  if ! cmp -s "$SITE_MAIL_SRC" "$SITE_MAIL_DST"; then
    log "Updating site-mail wrapper at $SITE_MAIL_DST ..."
    install -m 0755 "$SITE_MAIL_SRC" "$SITE_MAIL_DST"
  fi
  install -d -m 0750 /var/lib/hyperion/site-mail
fi

#-------- 3c. maintenance landing page ------------------------------------
# When a hosting toggles `maintenance_mode`, its nginx vhost falls
# through `try_files /maintenance.html =503` and tries to serve
# /var/lib/hyperion/maintenance/maintenance.html. Without that file
# visitors get the bare nginx 503 — works but ugly. Plant a friendly
# Hyperion-branded page once; operators can replace it freely (we
# only overwrite when the file is missing OR was a previous version
# we ourselves wrote, identified by the "x-hyperion-maintenance"
# marker comment).
install -d -m 0755 /var/lib/hyperion/maintenance
MAINT_HTML="/var/lib/hyperion/maintenance/maintenance.html"
if [[ ! -f "$MAINT_HTML" ]] || grep -q "x-hyperion-maintenance" "$MAINT_HTML" 2>/dev/null; then
  cat > "$MAINT_HTML" <<'HTML'
<!-- x-hyperion-maintenance: v1 - operator may replace this file freely -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>We'll be right back</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #e2e8f0; padding: 1.5rem;
    }
    .card {
      max-width: 480px; padding: 2.5rem 2rem;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px;
      text-align: center; backdrop-filter: blur(8px);
    }
    .icon {
      width: 56px; height: 56px; margin: 0 auto 1.4rem;
      border-radius: 14px; background: rgba(99,102,241,0.18);
      display: flex; align-items: center; justify-content: center;
    }
    h1 { margin: 0 0 0.6rem; font-size: 1.5rem; font-weight: 700; }
    p { margin: 0 0 1rem; font-size: 0.95rem; line-height: 1.55; opacity: 0.85; }
    .foot { margin-top: 1.4rem; font-size: 0.78rem; opacity: 0.5; }
  </style>
</head>
<body>
  <main class="card">
    <div class="icon">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#a5b4fc" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
      </svg>
    </div>
    <h1>We'll be right back</h1>
    <p>This site is under brief maintenance. Please check back in a few minutes.</p>
    <div class="foot">HTTP 503 · Service Temporarily Unavailable</div>
  </main>
</body>
</html>
HTML
  chmod 0644 "$MAINT_HTML"
  log "Installed default maintenance page at $MAINT_HTML"
fi

#-------- 3d. Heal vhosts written by an older Hyperion --------------------
# Releases before commit 1609e75 emitted a standalone `http2 on;`
# directive in every TLS server block. That syntax requires nginx
# 1.25.1+ but Debian 12 ships nginx 1.22, so every reload after
# upgrade fails with:
#   [emerg] unknown directive "http2"
# Fix the existing files in place — strip the bare `http2 on;`
# line and add `http2` as a parameter on the matching listen
# directive. Idempotent; safe to re-run.
if command -v nginx >/dev/null 2>&1; then
  shopt -s nullglob
  HEALED_ANY=0
  for f in /etc/nginx/sites-enabled/*.conf /etc/nginx/sites-available/*.conf; do
    [[ -f "$f" ]] || continue
    if grep -qE "^\s*http2\s+on\s*;" "$f"; then
      log "Healing legacy http2 directive in $f ..."
      # Add `http2` to any `listen ... ssl;` (or `ssl` not yet
      # followed by http2) on a non-comment line. Then nuke the
      # standalone http2 on; line.
      sed -i -E \
        -e 's/^(\s*listen\s+[^#]*\bssl)(\s*;)/\1 http2\2/g' \
        -e '/^\s*http2\s+on\s*;\s*$/d' \
        "$f"
      HEALED_ANY=1
    fi
  done
  if (( HEALED_ANY )); then
    if nginx -t >/dev/null 2>&1; then
      systemctl reload nginx 2>/dev/null || true
      log "Healed vhosts + reloaded nginx."
    else
      log "WARNING: nginx -t still fails after healing — inspect manually."
    fi
  fi
  shopt -u nullglob
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

# Heal missing hosting-prerequisite packages. Older install-node.sh
# (or a node where someone apt-removed something) may be missing the
# LAMP-ish stack. Without this, the first hosting dispatched from the
# master to that node fails with confusing errors like
#   "nginx.service is not active, cannot reload"
# or
#   "php8.3-fpm.service not loaded"
# Re-install + enable each package only when the unit file is missing.
declare -A NEEDED_PKGS=(
  [nginx.service]="nginx"
  [vsftpd.service]="vsftpd"
  [mariadb.service]="mariadb-server"
  [postgresql.service]="postgresql"
  [php8.1-fpm.service]="php8.1-fpm php8.1-cli php8.1-mysql php8.1-pgsql"
  [php8.2-fpm.service]="php8.2-fpm php8.2-cli php8.2-mysql php8.2-pgsql"
  [php8.3-fpm.service]="php8.3-fpm php8.3-cli php8.3-mysql php8.3-pgsql"
  [php8.4-fpm.service]="php8.4-fpm php8.4-cli php8.4-mysql php8.4-pgsql"
)
# Canonical "is this unit installed" check. `systemctl cat <unit>`
# succeeds iff the unit file is on disk (works regardless of whether
# the service is running, failed, or even masked). We used to grep
# `list-unit-files` output here, but on newer systemd (Debian 12+)
# that output formatting drifts enough that the grep silently
# misses live units — triggering a spurious `apt-get install nginx`
# on every update run.
unit_installed() {
  systemctl cat "$1" >/dev/null 2>&1
}

APT_UPDATED=0
for unit in "${!NEEDED_PKGS[@]}"; do
  # Skip PHP versions that aren't critical — only install if the
  # unit is missing AND no other PHP-FPM unit is already installed
  # (i.e. we want AT LEAST ONE php-fpm; we don't force all 4).
  # Always install nginx + the *required* services.
  if unit_installed "$unit"; then
    continue
  fi
  # Skip optional PHP versions when at least one is already there.
  if [[ "$unit" == php*-fpm.service ]]; then
    if unit_installed php8.1-fpm.service \
       || unit_installed php8.2-fpm.service \
       || unit_installed php8.3-fpm.service \
       || unit_installed php8.4-fpm.service; then
      continue
    fi
  fi
  pkgs="${NEEDED_PKGS[$unit]}"
  log "$unit missing — installing $pkgs ..."
  if (( APT_UPDATED == 0 )); then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    APT_UPDATED=1
  fi
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs; then
    warn "$pkgs install failed — features that depend on $unit will not work \
until this is fixed manually (apt-get install -y $pkgs)."
  fi
done

#-------- 4a-ext. PHP extensions required by WordPress / wp-cli -----------
# The NEEDED_PKGS loop above only fires when the -fpm unit is MISSING, so
# a server that already has php8.3-fpm but predates the extension bundle
# (or had it trimmed) never gets the extras. wp-cli `core download` needs
# ZipArchive (php*-zip) and a bare WordPress needs gd/mbstring/xml/curl/
# mysql — the symptom is a mid-install "Extracting a zip file requires
# ZipArchive". For every PHP version whose -fpm unit IS present, ensure
# the full extension set. apt-get install is idempotent; we only call it
# when dpkg reports at least one missing, so a healthy box pays nothing.
PHP_EXT_SUFFIXES=(zip gd mbstring xml curl mysql)
for ver in 8.1 8.2 8.3 8.4; do
  unit_installed "php${ver}-fpm.service" || continue
  missing=0
  want=""
  for s in "${PHP_EXT_SUFFIXES[@]}"; do
    want+=" php${ver}-${s}"
    dpkg -s "php${ver}-${s}" >/dev/null 2>&1 || missing=1
  done
  (( missing )) || continue
  log "PHP ${ver}: ensuring WordPress/wp-cli extensions ($want ) ..."
  if (( APT_UPDATED == 0 )); then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    APT_UPDATED=1
  fi
  if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $want; then
    # Newly-added modules only load after the fpm worker reloads.
    systemctl try-restart "php${ver}-fpm.service" 2>/dev/null || true
  else
    warn "some php${ver} extensions failed to install — WordPress installs \
on PHP ${ver} hostings may fail (apt-get install -y$want)."
  fi
done

#-------- 4b. MTA (so PHP mail() actually delivers) -----------------------
# PHP's mail() execs $sendmail_path → hyperion's site-mail wrapper →
# `/usr/sbin/sendmail`. Default Debian installs ship without any MTA,
# so /usr/sbin/sendmail doesn't exist and every mail() call returns
# false. The "Mail sent by this site" log stays empty (the wrapper
# logs BEFORE calling sendmail, but the operator-facing symptom is
# usually "WordPress doesn't send email" which they notice first).
#
# Install postfix as "Internet Site" by default — it provides the
# `/usr/sbin/sendmail` compat binary and delivers via direct MX
# lookup. Operators on networks where outbound TCP/25 is blocked
# (AWS, GCP, some corporate DCs) need to switch to a smart-host
# relay configuration manually:
#   postconf -e 'relayhost = [smtp.example.com]:587'
#   postconf -e 'smtp_sasl_auth_enable = yes'
#   ...
# Preseeding with the "Satellite system" type would be cleaner here
# but it needs a relay host AT install time and we don't always
# know one.
if [[ ! -x /usr/sbin/sendmail ]]; then
  log "No MTA installed — installing postfix as Internet Site so PHP mail() works ..."
  echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
  echo "postfix postfix/mailname string $(hostname -f 2>/dev/null || hostname)" | debconf-set-selections
  if (( APT_UPDATED == 0 )); then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    APT_UPDATED=1
  fi
  if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postfix; then
    systemctl reset-failed postfix >/dev/null 2>&1 || true
    systemctl enable --now postfix >/dev/null 2>&1 || true
    if [[ -x /usr/sbin/sendmail ]]; then
      log "postfix installed — /usr/sbin/sendmail available, mail() should work."
    else
      warn "postfix installed but /usr/sbin/sendmail still missing — check 'apt-get install -y postfix' output."
    fi
  else
    warn "postfix install failed — PHP mail() will keep returning false."
    warn "Manual fix: apt-get install -y postfix  (or any other MTA that provides /usr/sbin/sendmail)"
  fi
fi

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
for svc in nginx mariadb postgresql vsftpd postfix \
           php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm; do
  if unit_installed "$svc.service"; then
    # Clear any stale "failed" state from previous botched starts
    # so `enable --now` doesn't trip the "Start request repeated
    # too quickly" check. reset-failed is a no-op on healthy units.
    systemctl reset-failed "$svc" >/dev/null 2>&1 || true
    systemctl enable --now "$svc" >/dev/null 2>&1 || true
  fi
done

#-------- 4a. TLS cert dir (idempotent) -----------------------------------
# hyperion-web auto-generates a self-signed cert on first start; we just
# need to make sure the directory exists and the agent service can write
# into it (covered by ReadWritePaths=/etc/hyperion in the systemd unit).
install -d -m 0700 /etc/hyperion/web-tls

#-------- 4a-bis. master→node remote RPC opt-in for existing nodes --------
# Pre-multinode agent.toml files don't have [remote_rpc]. Without
# the section the agent's default is `enabled = false`, so the
# master can't dispatch to this node from its UI. Patch it in via
# a heredoc append — only when the section is missing. Operators
# can later flip enabled to false by hand if they don't want this.
if [[ -f /etc/hyperion/agent.toml ]] \
   && ! grep -q '^\[remote_rpc\]' /etc/hyperion/agent.toml; then
  log "Adding [remote_rpc] section to /etc/hyperion/agent.toml ..."
  cat >> /etc/hyperion/agent.toml <<'EOF'

# Master→node remote RPC (added by update.sh). Default ON so the
# master UI's "Target node" dropdown works for this node. Disable
# by setting enabled = false; the local Unix socket always works
# regardless.
[remote_rpc]
enabled       = true
bind          = "0.0.0.0:9443"
tls_cert_file = "/etc/hyperion/agent-rpc.crt"
tls_key_file  = "/etc/hyperion/agent-rpc.key"
EOF
fi

# Best-effort: open port 9443 in ufw if it's installed + active.
# Operators on iptables / nftables / cloud security groups will
# need to open it themselves.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  if ! ufw status 2>/dev/null | grep -q '9443/tcp'; then
    log "Opening ufw 9443/tcp for master→node RPC ..."
    ufw allow 9443/tcp comment 'hyperion master->node RPC' || true
  fi
fi

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

#-------- 6b. Migration dry-run (pre-restart safety gate) ------------------
# The new agent binary is installed but not yet running. Validate that the
# embedded migrations apply cleanly to a COPY of the live DB *before* we
# restart — otherwise a migration that fails on the production schema sends
# the agent into a systemd crash-loop that `is-active` happily reports as
# "active", hiding the real error.
if (( HAVE_AGENT )) && [[ -x /usr/sbin/hyperion-agent ]]; then
  log "Validating DB migrations against the live schema (dry-run) ..."
  if /usr/sbin/hyperion-agent --dry-run-migrations; then
    log "Migrations validate cleanly."
  else
    warn "DB migration dry-run FAILED — refusing to restart the agent into a crash-loop."
    warn "The new binary is installed but services were NOT started; your data is untouched."
    warn "Fix the migration (or roll back the binary) and re-run this script."
    exit 1
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
# `is-active` can read "active" while the agent is mid-restart in a crash-loop
# (Restart=on-failure). Confirm it's genuinely SERVING by talking to its socket
# via `hctl info`, retrying briefly to allow for a slow first start.
check_agent_serving() {
  [[ -x /usr/bin/hctl ]] || return 0
  local i
  for i in 1 2 3 4 5; do
    if hctl info >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  warn "hyperion-agent unit is up but its socket is NOT answering (hctl info failed)."
  warn "This usually means a startup error (schema mismatch, bad config). Journal tail:"
  journalctl -u hyperion-agent -n 20 --no-pager | sed 's/^/    /'
  HEALTHY=0
}
(( HAVE_AGENT )) && check_active hyperion-agent
(( HAVE_AGENT )) && check_agent_serving
(( HAVE_WEB   )) && check_active hyperion-web

#-------- 7b. Verify installed binaries match the source ------------------
# Final safety net behind the staleness guard. Each binary embeds its build
# commit (`--version`); confirm what's on disk was built from the commit we
# checked out, and that web + agent are the SAME build. Catches a VERSION-less
# release we proceeded with, a cargo cache that didn't recompile, --no-build
# leaving stale binaries, or a half-applied update (web moved, agent didn't).
bin_sha() { "$1" --version 2>/dev/null | grep -oE '[0-9a-f]{40}' | head -n1 || true; }
AGENT_SHA=""; WEB_SHA=""
[[ -x /usr/sbin/hyperion-agent ]] && AGENT_SHA=$(bin_sha /usr/sbin/hyperion-agent)
(( HAVE_WEB )) && [[ -x /usr/sbin/hyperion-web ]] && WEB_SHA=$(bin_sha /usr/sbin/hyperion-web)
if (( DO_BUILD )); then
  skew=0
  if [[ -n "$AGENT_SHA" && "$AGENT_SHA" != "$HEAD_FULL" ]]; then
    warn "hyperion-agent on disk is built from ${AGENT_SHA:0:12}, but your source is ${HEAD_FULL:0:12}."
    skew=1
  fi
  if [[ -n "$WEB_SHA" && "$WEB_SHA" != "$HEAD_FULL" ]]; then
    warn "hyperion-web on disk is built from ${WEB_SHA:0:12}, but your source is ${HEAD_FULL:0:12}."
    skew=1
  fi
  if [[ -n "$AGENT_SHA" && -n "$WEB_SHA" && "$AGENT_SHA" != "$WEB_SHA" ]]; then
    warn "hyperion-agent (${AGENT_SHA:0:12}) and hyperion-web (${WEB_SHA:0:12}) are DIFFERENT builds (skew)."
    skew=1
  fi
  if (( skew )); then
    warn "Installed binaries don't match your checkout — rebuild locally with:"
    warn "    sudo $0 --from-source"
    HEALTHY=0
  elif [[ -n "$AGENT_SHA" ]]; then
    log "Verified: installed binaries match source ${HEAD_FULL:0:12}."
  fi
fi

echo
echo "============================================================"
echo "  Hyperion update — $PREV → $NEW"
# The build SHA the binary ACTUALLY reports — not just the source HEAD — so a
# skew (the bug this guard exists for) is visible at a glance, not hidden.
[[ -n "$AGENT_SHA" ]] && echo "  built from:     ${AGENT_SHA:0:12}"
(( HAVE_AGENT )) && echo "  hyperion-agent: $(systemctl is-active hyperion-agent)"
(( HAVE_WEB   )) && echo "  hyperion-web:   $(systemctl is-active hyperion-web)"
echo "============================================================"

if (( HEALTHY == 0 )); then
  exit 1
fi
echo "  Tail live logs with:"
(( HAVE_AGENT )) && echo "    journalctl -u hyperion-agent -f"
(( HAVE_WEB   )) && echo "    journalctl -u hyperion-web -f"
