#!/usr/bin/env bash
# Hyperion in-place update.
#
# What it does — steps 1–2 run while the panel and agent keep serving:
#   1. git fetch + reset --hard to origin/$HYPERION_REF (refuses if local
#      changes — commit/stash first); re-exec if update.sh itself changed
#   2. Download + verify the pre-built release, or cargo build from source
#   3. Wait for running jobs (backups, migrations, installs, ...) to finish,
#      so stopping the services never kills one half-way — see --no-wait;
#      snapshot the current binaries, then stop hyperion-* services
#   4. install -m 0755 the new binaries
#   5. Refresh pages, nginx defaults, systemd units, heal missing packages,
#      materialize web-session.key / web-csrf.key
#   6. (--repair) wipe orphan hostings rows; dry-run the DB migrations
#   7. Start services back up + health-check
# If anything fails after the stop and before the start, the EXIT trap puts
# the previous binaries back and starts them — a failed update never leaves
# the box down.
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
#   HYPERION_STATE_DB      default /var/lib/hyperion/state.db — read to find
#                          running jobs (agent.toml's state_db, if you moved it)
#
# Flags:
#   --no-wait      Do not wait for running jobs — stop the services right away
#                  and interrupt whatever is running. Without this flag the
#                  script polls the job list and only starts once it is empty.
#   --wait-timeout=SECS
#                  Give up (changing nothing) if jobs are still running after
#                  SECS seconds. Default: wait as long as real work is running;
#                  Ctrl-C is safe at any point during the wait.
#   --repair       Also drop orphan hostings rows in
#                  state IN ('provisioning','failed','deleting'). Does NOT
#                  touch on-disk artefacts (vhost, db, system user) — use
#                  the diagnostic snippet printed on screen if those linger.
#   --no-build     Skip binary install (useful for unit/config-only refreshes).
#   --safe         Also RESTORE the previous binaries automatically if the
#                  post-update health check fails (a failure BEFORE the start
#                  is always rolled back, with or without this flag).
#                  Turns "the update broke the panel" into a bad minute
#                  instead of an SSH session — the operator is usually
#                  clicking Update from the very UI an update can take down.
#   --from-source  Skip the pre-built release; cargo build locally.
#                  Useful for testing local commits before they're pushed.
#   --release=TAG  Install a specific release: checks out the git tag TAG and
#                  uses that release's pre-built binaries (unless --ref is also
#                  given, which keeps the source on that branch).
#   --ref=REF      Override $HYPERION_REF for git fetch.
#
# Default behaviour:
#   1. git fetch + reset to origin/$HYPERION_REF
#   2. Try to download pre-built binaries (+ SHA256SUMS verification)
#      from the GitHub release tagged $HYPERION_RELEASE_TAG.
#   3. If the release isn't there OR checksum fails, cargo build from
#      the freshly-fetched source.
#
#==========================================================================
# CLUSTER ROLLOUT ORDER — READ BEFORE UPDATING A MULTI-NODE INSTALL
#==========================================================================
# This script updates exactly ONE box, the one it runs on. It has no
# cluster awareness whatsoever: it does not know whether this box is the
# master or a worker, it never contacts the other nodes, and it will
# happily leave a cluster half-upgraded. The order below is not a
# recommendation — get it wrong and the panel loses sight of its workers.
#
# Why order matters at all: master↔node RPC is versioned only by what
# each side happens to understand. New request/response fields are all
# additive and optional, so a NEW master can drive an OLD node and an OLD
# master can drive a NEW node — but only one direction at a time is ever
# TESTED in production, and that is the direction below.
#
#   1. MASTER FIRST, over SSH.
#        sudo /opt/hyperion/packaging/install/update.sh
#      It has to be SSH: the panel's Update action exists only on the
#      worker cards of the Nodes page — there is no card for the master —
#      and hyperion-web is stopped and replaced partway through this
#      script anyway, so the page you clicked from would go 502 exactly
#      when you need its log. (Workers are the opposite — see step 3.)
#
#   2. CONFIRM THE NEW MASTER STILL DRIVES THE OLD NODES.
#      Before touching a single worker, open the panel's Nodes page
#      (/install) and load a per-node view — its hostings list, its
#      stats. Every node is still running the OLD agent at this point,
#      and that combination must work. If it doesn't, you have one broken
#      box to roll back instead of a whole cluster, and every worker is
#      still healthy.
#
#   3. NODES ONE AT A TIME, and WAIT between them.
#      Update a worker from the master's Nodes page (the node's "Update"
#      action) or by SSH-ing to it and running this script. The panel is
#      the only in-product way to reach a worker, which is exactly why
#      step 1 has to come first: an un-upgraded master may not be able to
#      drive the upgrade at all.
#      After each node, WAIT for its readiness chips on /install before
#      starting the next: "⚠ … out of sync" must disappear, and
#      "⚠ No response auth" must become "🔑 Response auth on file".
#      Those chips are driven by the node's HEARTBEAT, not by this script
#      exiting, and they are the only proof the new agent came back up,
#      re-registered and re-published its crypto material. Both the TLS
#      SPKI pin and the response-signing pubkey are CLEARED on
#      re-enrollment and only re-pin on the next heartbeat, so a node
#      briefly shows neither chip — that is expected, wait it out.
#      Doing several at once means a failure tells you nothing about
#      which node broke, and leaves a stampede of re-enrollments.
#
#   4. ONLY THEN flip the enforcement toggles, in
#      Settings → Cluster → Cluster channel hardening:
#        Step 1 · Enforce worker TLS certificate pinning
#                 ([cluster] enforce_worker_cert_pinning)
#        Step 2 · Enforce signed node responses
#                 ([cluster] enforce_response_auth)
#      Both default to OFF for exactly this reason, and step 2 is only
#      meaningful once step 1 is on. Response-auth enforcement makes the
#      master DISCARD any answer from a node that published a signing key
#      but replied unsigned — which is indistinguishable from a node that
#      was rolled back mid-rollout. (A MIS-signed reply is discarded
#      either way; the toggle only governs UNsigned ones.)
#      Leave both off for a day first and read the warn-only lines:
#        journalctl -u hyperion-web -g SECURITY
#      A clean log plus a chip on every node means it is safe to enforce.
#
# KNOWN EXCEPTION — cross-node migration during the rollout window.
# Move/Copy between nodes runs a pre-flight that compares agent versions
# and HARD-FAILS on any difference between master, source and target
# ("agent version mismatch — master X, source Y, target Z"). It is a
# deliberate guard: the export/import bundle format is not version-
# tolerant, and a half-migrated hosting is far worse than a refused one.
# So from the moment the master is updated until the last node is, ALL
# cross-node moves and copies are blocked. Same-node operations, backups,
# provisioning and every other RPC keep working normally. Plan migrations
# outside the rollout window, or finish the rollout first.
#
# KNOWN EXCEPTION — editing a CARE PACKAGE during the rollout window (v0.62.0+).
# Two things a package edit changes are not snapshotted: the monthly checklist
# and the customer-letter language. The master pushes both to every node, and a
# node still running the old build does not know the request. The panel names
# the nodes that missed it and asks you to re-save the package once they answer
# — that message is the whole guard, so do not dismiss it. Sites on a node that
# missed the edit keep checking the previous list until you re-save.
#
# Also: CUSTOMISING a checklist during the window changes the on-disk shape of
# that site's check record, and an un-upgraded node reads the new shape as
# "nothing was ever checked" — which is what its customer report would then
# say. An install that leaves the built-in four alone never writes the new
# shape, so ordinary ticking through the window is safe. Wait until every node
# is up to date before editing a plan's checklist for the first time.
#==========================================================================

set -euo pipefail

INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
REF="${HYPERION_REF:-main}"
GIT_TOKEN="${HYPERION_GIT_TOKEN:-}"
RELEASE_REPO="${HYPERION_RELEASE_REPO:-nechodom/hyperion}"
RELEASE_TAG="${HYPERION_RELEASE_TAG:-rolling}"   # rolling tag, set by GH Actions
REPAIR=0
DO_BUILD=1
PREFER_PREBUILT=1
SAFE=0
ROLLED_BACK=0
STATE_DB="${HYPERION_STATE_DB:-/var/lib/hyperion/state.db}"
WAIT_FOR_JOBS=1
WAIT_TIMEOUT=0                            # seconds; 0 = no limit
WAIT_POLL="${HYPERION_WAIT_POLL:-10}"     # seconds between job-list checks
REF_EXPLICIT=0
RELEASE_PINNED=0

# The parse loop below shifts every argument away, so keep the originals for
# the self-update re-exec — without this the fresh copy silently ran with no
# flags at all (a panel-started `--safe` update lost its rollback).
ORIG_ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repair)        REPAIR=1; shift;;
    --no-build)      DO_BUILD=0; shift;;
    --from-source)   PREFER_PREBUILT=0; shift;;
    --safe)          SAFE=1; shift;;
    --no-wait)       WAIT_FOR_JOBS=0; shift;;
    --wait-timeout=*)
      WAIT_TIMEOUT="${1#*=}"
      [[ "$WAIT_TIMEOUT" =~ ^[0-9]+$ ]] \
        || { printf -- '--wait-timeout wants a whole number of seconds, got: %s\n' "$WAIT_TIMEOUT" >&2; exit 2; }
      shift;;
    --release=*)     RELEASE_TAG="${1#*=}"; RELEASE_PINNED=1; shift;;
    --ref=*)         REF="${1#*=}"; REF_EXPLICIT=1; shift;;
    -h|--help)       sed -n '2,/^#=====/p' "$0" | sed '$d'; exit 0;;
    *) printf 'unknown arg: %s\n' "$1" >&2; exit 2;;
  esac
done

log()  { printf '\033[36m[hyperion]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }

# --- Live status for the panel's "updating" page --------------------------
# From the moment hyperion-web is stopped, anyone with the panel open is looking
# at the static page nginx serves in its place. That page polls this file (the
# panel vhost serves it at /_hyperion/update-status), so it can say which step
# we're on — and, crucially, tell "building from source, 10 more minutes" and
# "the update died" apart from "back in a moment". Only a step name and epoch
# timestamps go in: the URL needs no login.
#
# Written only on a box that runs the panel, only once the services are down,
# and removed again as soon as the panel is serving (404 = nothing running).
# Every write is best-effort — a status file must never fail an update.
# >>> update-status
STATUS_FILE="${HYPERION_UPDATE_STATUS_FILE:-/var/lib/hyperion/maintenance/panel-update.json}"
STATUS_ON="${HYPERION_UPDATE_STATUS:-0}"   # inherited across the re-exec
STATUS_STARTED="${HYPERION_UPDATE_STARTED:-0}"
STATUS_STEP=""
STATUS_STEP_STARTED=0

status_begin() {
  (( STATUS_ON )) && return 0
  install -d -m 0755 "$(dirname "$STATUS_FILE")" 2>/dev/null || return 0
  STATUS_ON=1
  STATUS_STARTED="$(date +%s)"
  export HYPERION_UPDATE_STATUS=1 HYPERION_UPDATE_STARTED="$STATUS_STARTED"
}

# status <running|failed> <step> [build-percent]
status() {
  (( STATUS_ON )) || return 0
  local state="$1" step="$2" pct="${3:-}" now tmp
  now="$(date +%s)"
  if [[ "$step" != "$STATUS_STEP" ]]; then
    STATUS_STEP="$step"
    STATUS_STEP_STARTED="$now"
  fi
  tmp="$STATUS_FILE.tmp.$$"
  {
    printf '{"v":1,"state":"%s","step":"%s","started":%s,"step_started":%s,"updated":%s' \
      "$state" "$step" "$STATUS_STARTED" "$STATUS_STEP_STARTED" "$now"
    [[ "$pct" =~ ^[0-9]+$ ]] && printf ',"progress":%s' "$pct"
    printf '}\n'
  } > "$tmp" 2>/dev/null && chmod 0644 "$tmp" 2>/dev/null && mv -f "$tmp" "$STATUS_FILE" 2>/dev/null \
    || rm -f "$tmp" 2>/dev/null
  return 0
}

# Called on EXIT with the script's exit code. A panel that is serving again —
# success, a rollback, or a skew warning on a healthy box — needs no status, and
# a stale "failed" left behind would mislabel some later, unrelated outage.
# Anything else stopped the update with the panel down: say so, and where.
status_finish() {
  (( STATUS_ON )) || return 0
  if [[ "$1" == 0 ]] || systemctl --quiet is-active hyperion-web 2>/dev/null; then
    rm -f "$STATUS_FILE" 2>/dev/null
  else
    status failed "${STATUS_STEP:-stop}"
  fi
  return 0
}
# <<< update-status

# One EXIT trap for the whole script: a second `trap … EXIT` REPLACES the
# first, which is how the askpass helper used to outlive a pre-built install.
CLEANUP_PATHS=()
# Where the update is, for the EXIT trap: did WE stop the services, did new
# binaries land, did we get as far as starting them again.
SERVICES_STOPPED=0
BIN_INSTALLED=0
REACHED_START=0
on_exit() {
  local rc=$?
  (( rc == 0 )) || recover_after_failure
  status_finish "$rc"
  local p
  for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do rm -rf -- "$p"; done
  return "$rc"
}
trap on_exit EXIT

# --- Snapshot / restore ----------------------------------------------------
# What gets snapshotted is deliberately ONLY the binaries. Restoring those
# undoes a bad build; it does not undo a migration, and pretending otherwise
# would be the dangerous kind of reassuring. Migrations in this project are
# additive, so an older binary against a newer schema starts — which is the
# case this exists to survive.
#
# The snapshot is taken on EVERY update (three binaries, cheap): an update that
# dies after installing — a failed migration dry-run, a configure step that
# errors — puts these back and starts them, instead of leaving the box down.
# --safe additionally rolls back when the post-start health check fails.
SNAP_DIR=/var/lib/hyperion/update-snapshot
snapshot_binaries() {
  rm -rf "$SNAP_DIR"
  install -d -m 0700 "$SNAP_DIR"
  local f
  for f in /usr/sbin/hyperion-agent /usr/sbin/hyperion-web /usr/bin/hctl; do
    [[ -x "$f" ]] && cp -a "$f" "$SNAP_DIR/$(basename "$f")"
  done
  # Record what we snapshotted so the log says what a restore would give back.
  if [[ -x "$SNAP_DIR/hyperion-agent" ]]; then
    "$SNAP_DIR/hyperion-agent" --version > "$SNAP_DIR/VERSION" 2>/dev/null || true
    log "Snapshotted $(tr -d '\n' < "$SNAP_DIR/VERSION" 2>/dev/null || echo 'current binaries')"
  fi
}

restore_snapshot() {
  [[ -d "$SNAP_DIR" ]] || { warn "No snapshot to restore from."; return 1; }
  local f restored=0
  for f in hyperion-agent hyperion-web hctl; do
    [[ -x "$SNAP_DIR/$f" ]] || continue
    case "$f" in
      hctl) install -m 0755 "$SNAP_DIR/$f" /usr/bin/hctl ;;
      *)    install -m 0755 "$SNAP_DIR/$f" "/usr/sbin/$f" ;;
    esac
    restored=1
  done
  (( restored )) || { warn "Snapshot directory held no binaries."; return 1; }
  (( HAVE_AGENT )) && { systemctl restart hyperion-agent 2>/dev/null || true; }
  (( HAVE_WEB ))   && { systemctl restart hyperion-web   2>/dev/null || true; }
  sleep 2
  return 0
}

# EXIT-trap half of the update: the script died (an error under `set -e`, a
# failed check, Ctrl-C) after it stopped the services and before it started
# them again. Before this, every such failure — a git fetch on a flaky network,
# a cargo build, a migration dry-run — left the panel and the agent DOWN until
# someone SSH'd in. Now: put the previous binaries back if new ones landed, and
# start the services, so a failed update costs a minute, not an outage.
recover_after_failure() {
  (( SERVICES_STOPPED && ! REACHED_START )) || return 0
  if (( BIN_INSTALLED )); then
    warn "Update failed after the new binaries were installed — restoring the previous ones ..."
    if restore_snapshot; then
      warn "Previous version restored and started. Nothing from this update is running."
    else
      warn "Could NOT restore the previous binaries — services left stopped. Look at:"
      warn "    journalctl -u hyperion-agent -n 50"
    fi
  else
    warn "Update failed before anything was installed — starting the services again ..."
    (( HAVE_AGENT )) && { systemctl start hyperion-agent 2>/dev/null || true; }
    (( HAVE_WEB ))   && { systemctl start hyperion-web   2>/dev/null || true; }
  fi
  return 0
}
fail() { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# One `apt-get update` per run, and only when something actually needs
# installing. Every heal goes through here: installing from stale package
# lists is how a heal "fails" on a box nobody has touched in months.
APT_UPDATED=0
apt_install() {
  if (( APT_UPDATED == 0 )); then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    APT_UPDATED=1
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
}

# Run `cargo "$@"` with a live progress bar driven by the number of compiled
# crates vs a total remembered from the previous successful build (so a from-
# source build shows real progress instead of a silent multi-minute hang).
# Purely cosmetic: returns cargo's real exit status, and rustc diagnostics still
# print (they go to stderr; only the JSON artifact stream on stdout is counted).
build_with_progress() {
  local tgt="${CARGO_TARGET_DIR:-target}"
  local total_file="$tgt/.hyperion_build_units"
  local count_file; count_file="$(mktemp)"
  local total=0
  [[ -r "$total_file" ]] && total="$(cat "$total_file" 2>/dev/null || echo 0)"
  [[ "$total" =~ ^[0-9]+$ ]] || total=0
  printf 0 > "$count_file"
  local width=34 tty=0
  [[ -t 2 ]] && tty=1

  # Capture cargo's REAL exit via a file: the brace group records $? right after
  # cargo, before the pipe to the counter closes (PIPESTATUS is unreliable across
  # the `local` that follows). stdout = JSON artifacts (counted); stderr =
  # rendered rustc diagnostics, which flow straight to the operator's terminal.
  local rc_file; rc_file="$(mktemp)"
  printf 1 > "$rc_file"
  { cargo "$@" --message-format=json-render-diagnostics; printf '%s' "$?" > "$rc_file"; } \
    | while IFS= read -r line; do
        [[ "$line" == *'"reason":"compiler-artifact"'* ]] || continue
        local n; n=$(( $(cat "$count_file") + 1 )); printf '%s' "$n" > "$count_file"
        if (( total > 0 )); then
          local pct=$(( n * 100 / total )); (( pct > 100 )) && pct=100
          # The panel's "updating" page shows this; one write per percent.
          if [[ "$pct" != "${last_pct:-}" ]]; then status running build "$pct"; last_pct="$pct"; fi
          local fill=$(( pct * width / 100 ))
          local bar; bar="$(printf '%*s' "$fill" '' | tr ' ' '=')$(printf '%*s' $(( width - fill )) '')"
          if (( tty )); then
            printf '\r\033[36m[hyperion]\033[0m building [%s] %3d%% (%d/%d)' "$bar" "$pct" "$n" "$total" >&2
          elif (( n % 25 == 0 )); then
            printf '[hyperion] building … %d%% (%d/%d)\n' "$pct" "$n" "$total" >&2
          fi
        elif (( tty )); then
          printf '\r\033[36m[hyperion]\033[0m building … %d crate(s) compiled' "$n" >&2
        elif (( n % 25 == 0 )); then
          printf '[hyperion] building … %d crate(s) compiled\n' "$n" >&2
        fi
      done
  local rc; rc="$(cat "$rc_file" 2>/dev/null || echo 1)"; [[ "$rc" =~ ^[0-9]+$ ]] || rc=1
  local final; final="$(cat "$count_file" 2>/dev/null || echo 0)"
  rm -f "$count_file" "$rc_file"
  (( tty )) && printf '\n' >&2
  # Remember the unit count for the next run's denominator (success only).
  if (( rc == 0 )) && [[ "$final" =~ ^[0-9]+$ ]] && (( final > 0 )); then
    printf '%s' "$final" > "$total_file" 2>/dev/null || true
  fi
  return "$rc"
}

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

# cargo is only needed if we end up building — checked there, not here: a box
# installed from pre-built binaries has no toolchain and must still update.
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

# An update.sh from before the reorder below stops the services FIRST and then
# re-execs into this copy. Those services are ours to bring back if this copy
# fails, exactly as if we had stopped them ourselves.
if [[ -n "${HYPERION_REEXEC:-}" ]] \
   && ! { (( HAVE_AGENT )) && systemctl --quiet is-active hyperion-agent 2>/dev/null; } \
   && ! { (( HAVE_WEB ))   && systemctl --quiet is-active hyperion-web   2>/dev/null; }; then
  (( HAVE_AGENT || HAVE_WEB )) && SERVICES_STOPPED=1
fi

#-------- 0b. Wait for running jobs (called right before step 3's stop) ---
# Stopping the services kills whatever they are doing: a backup is cut
# off mid-archive, a migration or WordPress job dies half-way, and on restart
# the agent marks the orphaned rows "failed". An operator who types
# `hyperion update` the moment a release lands has no way to know a job is
# running, so check first and hold off until the box is idle.
#
# "Running" is read straight from the state DB, because it is the one source
# that works before the new binaries are installed and whichever version is
# currently running: `jobs` (everything the panel starts as a background job)
# and `backup_runs` (backups, including the scheduled ones nothing in the panel
# started). Rows whose heartbeat is older than the agent's own reaper threshold
# are ghosts of a crash, not work, and are ignored — otherwise one orphaned row
# would hold every future update hostage. Keep the two ages in step with
# JOB_STALE_SECS / BACKUP_STALE_SECS in bin/hyperion-agent/src/main.rs.
#
# This does not stop new work from starting while we wait; it narrows the race
# to the moment between the last check and the stop, it does not close it.
# >>> wait-for-jobs
JOB_STALE_SECS=3600
BACKUP_STALE_SECS=$(( 6 * 3600 ))

# One line per piece of work in flight: "kind | what | where it is". Empty
# output = idle. A non-zero exit means "could not tell", which the caller treats
# differently from "nothing running".
running_work() {
  sqlite3 -readonly -separator ' | ' "$STATE_DB" \
    ".timeout 5000" \
    "SELECT kind, COALESCE(target, ''), step_label || ' ' || progress_pct || '%'
       FROM jobs
      WHERE state = 'running'
        AND updated_at >= CAST(strftime('%s','now') AS INTEGER) - ${JOB_STALE_SECS};" \
    "SELECT 'backup', COALESCE(h.domain, b.hosting_id), 'started ' || datetime(b.started_at, 'unixepoch') || ' UTC'
       FROM backup_runs b LEFT JOIN hostings h ON h.id = b.hosting_id
      WHERE b.state = 'running'
        AND b.started_at >= CAST(strftime('%s','now') AS INTEGER) - ${BACKUP_STALE_SECS};"
}

wait_for_running_work() {
  if (( ! WAIT_FOR_JOBS )); then
    log "--no-wait: not waiting for running jobs — anything in flight will be interrupted."
    return 0
  fi
  # An update.sh older than this one stops the services BEFORE re-exec'ing into
  # this copy. Rows left "running" by the stopped agent can never finish, so
  # waiting for them would just burn an hour.
  [[ -z "${HYPERION_JOBS_CHECKED:-}" ]] || return 0
  [[ -f "$STATE_DB" ]] || return 0
  # Nothing can be mid-run if neither service is up. The rows are leftovers.
  if ! systemctl --quiet is-active hyperion-agent 2>/dev/null \
     && ! systemctl --quiet is-active hyperion-web 2>/dev/null; then
    return 0
  fi
  if ! command -v sqlite3 >/dev/null 2>&1; then
    log "Installing sqlite3 — needed to see whether any job is running ..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sqlite3 >/dev/null 2>&1 || true
  fi
  if ! command -v sqlite3 >/dev/null 2>&1; then
    warn "sqlite3 is not installed — cannot check for running jobs; updating without waiting."
    return 0
  fi

  local out last="" waited=0 beat=0
  while :; do
    if ! out="$(running_work 2>&1)"; then
      # Failing open is deliberate: a DB we cannot read must not make the box
      # un-updatable. The old behaviour (update now) is the fallback.
      warn "Could not read the job list (${out//$'\n'/ }) — updating without waiting."
      return 0
    fi
    if [[ -z "$out" ]]; then
      (( waited == 0 )) || log "Running jobs finished after ${waited}s."
      export HYPERION_JOBS_CHECKED=1
      return 0
    fi
    if [[ "$out" != "$last" ]]; then
      log "Waiting for running jobs to finish before updating — nothing is interrupted:"
      printf '%s\n' "$out" | sed 's/^/    /'
      log "  (Ctrl-C is safe — nothing has been stopped yet. --no-wait skips this.)"
      last="$out"
      beat=0
    elif (( beat >= 60 )); then
      log "  still waiting (${waited}s) for $(printf '%s\n' "$out" | wc -l | tr -d ' ') job(s) ..."
      beat=0
    fi
    if (( WAIT_TIMEOUT > 0 && waited >= WAIT_TIMEOUT )); then
      fail "Jobs were still running after ${WAIT_TIMEOUT}s — nothing was stopped or installed.
       Re-run later, or pass --no-wait to update now and interrupt them."
    fi
    sleep "$WAIT_POLL"
    waited=$(( waited + WAIT_POLL ))
    beat=$(( beat + WAIT_POLL ))
  done
}
# <<< wait-for-jobs

#-------- 1. Fetch the new source (services still running) ----------------
# Everything up to step 3 — fetch, download, a from-source build — happens
# while the panel and the agent keep serving. None of it touches what they
# run, so a failure here (no network, a GitHub hiccup, a build error) costs
# nothing, and the downtime shrinks to install + configure + restart instead
# of including a multi-minute cargo build.
status running fetch
cd "$INSTALL_DIR"
PREV_LOCAL=$(git rev-parse --short HEAD)
# A re-exec'd copy already sits on the new commit; the summary should still
# say where this update started.
PREV="${HYPERION_PREV_SHA:-$PREV_LOCAL}"
# A from-source build can legitimately rewrite Cargo.lock in place (cargo
# refreshes it during the build). That's a generated, committed file the
# `git reset --hard` below overwrites anyway, so don't let it block the NEXT
# update with "local changes". Discard just that file; any OTHER local change
# is a real edit you'd lose on reset, so we still refuse + report it.
git checkout -- Cargo.lock 2>/dev/null || true
if [[ -n "$(git status --porcelain)" ]]; then
  fail "Working tree at $INSTALL_DIR has local changes:
$(git status --short | sed 's/^/    /')
       Commit/stash/remove them, then re-run. Nothing was stopped or changed."
fi

# Prune stale refs + fetch the BRANCH ref explicitly (CI publishes a release
# tag that can share the branch's name, and a plain `git fetch origin main`
# picks the tag over the branch — leaving you stuck on whatever commit the
# last release was built from). --tags --force keeps the moving release tags
# current, which --release=<tag> below checks out.
FETCH_SPEC="refs/heads/$REF:refs/remotes/origin/$REF"
if [[ -n "$GIT_TOKEN" ]]; then
  log "Fetching origin via HTTPS PAT ..."
  # mktemp, not a fixed /tmp/name.$$: this runs as root on a box whose site
  # users can write /tmp, and a predictable path is a file they can pre-plant.
  GIT_ASKPASS="$(mktemp /tmp/hyp-askpass.XXXXXX)"
  export GIT_ASKPASS HYPERION_GIT_TOKEN="$GIT_TOKEN"
  CLEANUP_PATHS+=("$GIT_ASKPASS")
  cat > "$GIT_ASKPASS" <<'AP'
#!/bin/sh
case "$1" in
  Username*) printf 'oauth2\n' ;;
  Password*) printf '%s\n' "$HYPERION_GIT_TOKEN" ;;
esac
AP
  chmod 0700 "$GIT_ASKPASS"
  git -c core.askPass="$GIT_ASKPASS" fetch --prune --tags --force origin "$FETCH_SPEC" \
    || fail "git fetch failed — nothing was stopped or changed. Check the network / token and re-run."
else
  log "Fetching origin ..."
  git fetch --prune --tags --force origin "$FETCH_SPEC" \
    || fail "git fetch failed — nothing was stopped or changed. Check the network and re-run."
fi

# --release=<tag> means "install that release": its source AND its pre-built
# binaries. It used to reset to the branch tip anyway, so the staleness guard
# saw a mismatch and quietly built main from source instead.
if (( RELEASE_PINNED && ! REF_EXPLICIT )) && [[ "$RELEASE_TAG" != rolling ]]; then
  TARGET="refs/tags/$RELEASE_TAG"
  git rev-parse -q --verify "$TARGET^{commit}" >/dev/null \
    || fail "No tag '$RELEASE_TAG' in the repository — nothing was stopped or changed."
  TARGET="$TARGET^{commit}"
else
  TARGET="origin/$REF"
fi
git reset --hard -q "$TARGET"
NEW=$(git rev-parse --short HEAD)
log "Source: $PREV → $NEW"

# Self-update guard. Bash already loaded the running copy of this script into
# memory; changes to this very file in the new commits would only take effect
# on the NEXT run. Re-exec the freshly checked-out copy when it changed — by
# its real path (under `curl | bash` $0 is just "bash") and with the ORIGINAL
# arguments (the parse loop shifted them all away).
#
# The HYPERION_REEXEC env-var marker stops infinite loops: the re-exec'd
# process sees the flag and skips this block.
if [[ "$PREV_LOCAL" != "$NEW" && -z "${HYPERION_REEXEC:-}" ]]; then
  if ! git diff --quiet "$PREV_LOCAL" "$NEW" -- packaging/install/update.sh 2>/dev/null; then
    log "update.sh itself changed between $PREV_LOCAL and $NEW — re-exec'ing the fresh copy"
    export HYPERION_REEXEC=1 HYPERION_PREV_SHA="$PREV"
    trap - EXIT
    for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do rm -rf -- "$p"; done
    exec bash "$INSTALL_DIR/packaging/install/update.sh" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"}
  fi
fi
unset HYPERION_REEXEC HYPERION_PREV_SHA

#-------- 1a. Refresh the panel's "updating" page --------------------------
# The agent re-plants this page when it next writes the panel vhost, which is
# AFTER the update. Copying it now means the page people are watching during
# this update is already the new one (the old one reloads itself onto it).
# Same rule as the agent: replace only a missing file or one still carrying our
# marker; an operator's own page is never touched.
PANEL_MAINT_SRC="$INSTALL_DIR/crates/hyperion-adapters/assets/panel-maintenance.html"
PANEL_MAINT_DST="/var/lib/hyperion/maintenance/panel-maintenance.html"
if (( HAVE_WEB )) && [[ -f "$PANEL_MAINT_SRC" ]] \
   && { [[ ! -f "$PANEL_MAINT_DST" ]] || grep -q "x-hyperion-maintenance" "$PANEL_MAINT_DST" 2>/dev/null; } \
   && ! cmp -s "$PANEL_MAINT_SRC" "$PANEL_MAINT_DST"; then
  install -d -m 0755 /var/lib/hyperion/maintenance
  install -m 0644 "$PANEL_MAINT_SRC" "$PANEL_MAINT_DST" \
    && log "Refreshed the panel's \"updating\" page." \
    || warn "Couldn't refresh $PANEL_MAINT_DST — the old page stays up during this update."
fi

HEAD_FULL=$(git rev-parse HEAD)

#-------- 1b. Staleness guard: does the release match our source? ----------
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
    log "Release @$RELEASE_TAG is at ${REL_VERSION:0:12}; your source is at ${HEAD_FULL:0:12}."
    log "  Pre-built binaries aren't built from your checkout (CI still building, or the"
    log "  release lagged) — building from source so the install matches your HEAD."
    PREFER_PREBUILT=0
  else
    log "Release @$RELEASE_TAG matches your source (${HEAD_FULL:0:12}) — using pre-built binaries."
  fi
fi

#-------- 2. Get the new binaries — prefer GitHub release, else build -------
# Only PREPARES them (download + verify, or compile); nothing is installed
# until the services are stopped in step 4.
PREBUILT_OK=0
BIN_SRC=""            # directory holding hyperion-agent / hctl / hyperion-web
EXPORT_SRC=""         # static hyperion-export to install, if any
EXPORT_ARCHES=()      # per-architecture exporters verified in $BIN_SRC
if (( DO_BUILD && PREFER_PREBUILT )); then
  status running download
  log "Attempting pre-built binaries from github.com/$RELEASE_REPO@$RELEASE_TAG ..."
  TMP=$(mktemp -d /tmp/hyperion-update.XXXXXX)
  CLEANUP_PATHS+=("$TMP")
  REL_BASE="https://github.com/$RELEASE_REPO/releases/download/$RELEASE_TAG"
  fetch_ok=1
  WANT_FILES=(hyperion-agent hctl SHA256SUMS)
  (( HAVE_WEB )) && WANT_FILES+=(hyperion-web hyperion-export)
  for f in "${WANT_FILES[@]}"; do
    # Capture both curl's exit code and the HTTP status separately
    # so the fall-back message can name the real cause. The OLD
    # message ("no <file> in release") attributed every transient
    # GitHub 5xx as if the file were missing — operators saw
    # "no hyperion-web in release" on a healthy install after a
    # GitHub CDN hiccup and assumed the release was broken.
    curl_rc=0
    code=$(curl -sSL --max-time 120 -w '%{http_code}' \
              -o "$TMP/$f" "$REL_BASE/$f" 2>"$TMP/$f.curlerr") || curl_rc=$?
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
          log "  network failure fetching '$f': ${err:-curl exit $curl_rc} — falling back to cargo build"
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
    (( HAVE_WEB )) && EXPECTED+=(hyperion-web hyperion-export)
    if (
        cd "$TMP"
        for f in "${EXPECTED[@]}"; do
          grep -E "[[:space:]]${f}\$" SHA256SUMS || {
            echo "  expected file '$f' missing from SHA256SUMS" >&2
            exit 1
          }
        done | sha256sum --quiet --check - 2>/dev/null
    ); then
      log "Pre-built binaries verified by SHA256SUMS."
      BIN_SRC="$TMP"
      (( HAVE_WEB )) && EXPORT_SRC="$TMP/hyperion-export"
      if (( HAVE_WEB )); then
        # Per-architecture exporters for the import wizard. The source box in
        # an import is somebody else's server and may not share this one's CPU,
        # so the wizard serves whichever matches what that box reports.
        # Fetched separately and tolerantly: a release cut before these
        # existed returns 404, and putting them in the REQUIRED list would
        # send every such update down the full cargo-build path.
        for a in x86_64 aarch64; do
          acode=$(curl -sSL --max-time 120 -w '%{http_code}' \
                    -o "$TMP/hyperion-export-$a" "$REL_BASE/hyperion-export-$a" 2>/dev/null) || true
          if [[ "$acode" == "200" && -s "$TMP/hyperion-export-$a" ]]; then
            # Verified against the same SHA256SUMS as everything else. The two
            # failure modes are reported separately on purpose: the first
            # release to ship these did not list them in SHA256SUMS, and the
            # old message said "failed its checksum" — sending the operator
            # looking for a corrupted download when nothing was wrong with it.
            if ! grep -Eq "[[:space:]]hyperion-export-$a\$" "$TMP/SHA256SUMS" 2>/dev/null; then
              warn "hyperion-export-$a is not listed in this release's SHA256SUMS — not installed"
            elif ( cd "$TMP" \
                   && grep -E "[[:space:]]hyperion-export-$a\$" SHA256SUMS \
                      | sha256sum --quiet --check - >/dev/null 2>&1 ); then
              EXPORT_ARCHES+=("$a")
            else
              warn "hyperion-export-$a did not match its checksum — not installed"
            fi
          fi
        done
      fi
      PREBUILT_OK=1
    else
      log "  SHA256 mismatch on downloaded files — falling back to cargo build"
    fi
  fi
fi

if (( DO_BUILD && PREBUILT_OK == 0 )); then
  if ! command -v cargo >/dev/null 2>&1; then
    fail "cargo not found and no usable pre-built release — nothing was stopped or changed.
       Re-run once the release is published, or install Rust (re-run install-master.sh)."
  fi
  log "Building release binaries from source (the panel keeps running meanwhile) ..."
  status running build

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

  # Speed up the from-source path. Both are best-effort + safe to skip:
  #  - incremental compilation reuses the persistent target/ across updates so
  #    only changed crates (+ the three bins, which re-stamp the SHA) recompile;
  #  - a faster linker (mold > lld) when one is installed — link time is a real
  #    slice now that lto=off. (Setting RUSTFLAGS invalidates the cache once on
  #    first adoption; nodes without an alt linker are untouched.) gold is
  #    deliberately NOT used: it's deprecated and rustc warns it has known bugs.
  export CARGO_INCREMENTAL=1
  for _ld in mold ld.lld lld; do
    if command -v "$_ld" >/dev/null 2>&1; then
      case "$_ld" in
        mold)        _lf="-C link-arg=-fuse-ld=mold" ;;
        ld.lld|lld)  _lf="-C link-arg=-fuse-ld=lld" ;;
      esac
      export RUSTFLAGS="${RUSTFLAGS:-} $_lf"
      log "  using $_ld for faster linking"
      break
    fi
  done

  # Stamp the exact checked-out commit into the binaries. build.rs reads this
  # env first, and `rerun-if-env-changed=HYPERION_GIT_SHA` forces a rebuild if
  # a previous incremental build had baked a different SHA — so a source build
  # can never embed a stale commit. `|| rc=$?` keeps the swap cleanup reachable
  # under `set -e`.
  build_rc=0
  HYPERION_GIT_SHA="$HEAD_FULL" build_with_progress build --release \
    --bin hyperion-agent --bin hyperion-web --bin hctl || build_rc=$?
  if (( build_rc == 0 && HAVE_WEB )); then
    # The self-service import wizard serves hyperion-export to SOURCE boxes that
    # may run an OLDER glibc than this build host. A host-glibc build would fail
    # there, so build it as a static musl binary (hyperion-export is pure Rust —
    # no C deps — so this needs no extra toolchain). Best-effort: a failure here
    # doesn't abort the update (only the self-service wizard is affected).
    musl_target="$(uname -m)-unknown-linux-musl"
    if rustup target add "$musl_target" >/dev/null 2>&1 \
       && HYPERION_GIT_SHA="$HEAD_FULL" cargo build --release --target "$musl_target" \
            -p hyperion-export --quiet; then
      EXPORT_SRC="$INSTALL_DIR/target/$musl_target/release/hyperion-export"
    else
      warn "  couldn't build static hyperion-export ($musl_target) — the self-service import wizard may not run on older-glibc sources (rolling release ships a prebuilt one)"
    fi
  fi
  if [ -n "$SWAPFILE" ]; then
    swapoff "$SWAPFILE" 2>/dev/null || true
    rm -f "$SWAPFILE"
  fi
  if (( build_rc != 0 )); then
    fail "cargo build failed (exit $build_rc) — nothing was stopped or installed.
       On a low-RAM box, ensure some swap is available and re-run."
  fi
  BIN_SRC="$INSTALL_DIR/target/release"
elif (( ! DO_BUILD )); then
  log "--no-build: skipping binary install."
fi

#-------- 3. Wait for running jobs, then stop ------------------------------
# Checked as late as possible — right before the stop — so work that started
# during a long build is seen too.
wait_for_running_work

# Snapshot the binaries that are running now, before anything replaces them:
# a failed update restores these (see recover_after_failure), and --safe also
# rolls back to them when the new version fails its health check.
if (( DO_BUILD )); then
  snapshot_binaries
fi
if (( HAVE_WEB )); then
  status_begin
  status running stop
fi
(( HAVE_AGENT || HAVE_WEB )) && SERVICES_STOPPED=1
(( HAVE_WEB ))   && { log "Stopping hyperion-web ...";   systemctl stop hyperion-web   || true; }
(( HAVE_AGENT )) && { log "Stopping hyperion-agent ..."; systemctl stop hyperion-agent || true; }

#-------- 4. Install the new binaries ---------------------------------------
if [[ -n "$BIN_SRC" ]]; then
  status running install
  log "Installing binaries ..."
  BIN_INSTALLED=1
  install -m 0755 "$BIN_SRC/hyperion-agent" /usr/sbin/hyperion-agent
  install -m 0755 "$BIN_SRC/hctl"           /usr/bin/hctl
  if (( HAVE_WEB )); then
    install -m 0755 "$BIN_SRC/hyperion-web" /usr/sbin/hyperion-web
    install -d -m 0755 /usr/local/bin
    # Portable (static musl) exporter the self-service import wizard serves.
    if [[ -n "$EXPORT_SRC" && -f "$EXPORT_SRC" ]]; then
      install -m 0755 "$EXPORT_SRC" /usr/local/bin/hyperion-export
    fi
    for a in ${EXPORT_ARCHES[@]+"${EXPORT_ARCHES[@]}"}; do
      install -m 0755 "$BIN_SRC/hyperion-export-$a" "/usr/local/bin/hyperion-export-$a"
    done
  fi
fi

#-------- 5a. site-mail-wrapper -------------------------------------------
status running configure
# Tiny bash shim that PHP-FPM execs as `sendmail_path` for every
# pool. Logs metadata of outgoing site mail to /var/lib/hyperion/
# site-mail/<user>.jsonl, then forwards to the real sendmail. Idempotent
# install — only updates the file when its content actually changed
# so we don't restart FPM pools unnecessarily.
# `hyperion` front-door command. The panel's Update button exists only on
# WORKER node cards and a master has no card, so on a single-server install
# there is no in-product way to update at all — the only route is the full
# path under /opt. Install the wrapper so `hyperion update` works, which is
# what people guess first. Content-idempotent, like the mail wrapper below.
HYPERION_CMD_SRC="$INSTALL_DIR/packaging/install/hyperion-wrapper.sh"
HYPERION_CMD_DST="/usr/local/bin/hyperion"
if [[ -f "$HYPERION_CMD_SRC" ]] && ! cmp -s "$HYPERION_CMD_SRC" "$HYPERION_CMD_DST"; then
  log "Installing the 'hyperion' command at $HYPERION_CMD_DST ..."
  install -d -m 0755 /usr/local/bin
  install -m 0755 "$HYPERION_CMD_SRC" "$HYPERION_CMD_DST"
fi

SITE_MAIL_SRC="$INSTALL_DIR/packaging/install/site-mail-wrapper.sh"
SITE_MAIL_DST="/usr/local/lib/hyperion/site-mail-wrapper"
if [[ -f "$SITE_MAIL_SRC" ]]; then
  install -d -m 0755 /usr/local/lib/hyperion
  if ! cmp -s "$SITE_MAIL_SRC" "$SITE_MAIL_DST"; then
    log "Updating site-mail wrapper at $SITE_MAIL_DST ..."
    install -m 0755 "$SITE_MAIL_SRC" "$SITE_MAIL_DST"
  fi
  # 1777 + sticky, like /tmp: the wrapper runs AS EACH SITE USER and has
  # to create its own <user>.jsonl here. 0750 root-owned made every such
  # write fail silently (logging is deliberately best-effort), so the
  # panel's "Mail sent by this site" was permanently empty while mail
  # flowed fine. The chmod also HEALS existing installs — install -d
  # alone does not change the mode of a directory that already exists.
  install -d -m 1777 /var/lib/hyperion/site-mail
  chmod 1777 /var/lib/hyperion/site-mail
fi

#-------- 5b. maintenance landing page ------------------------------------
# When a hosting toggles `maintenance_mode`, its nginx vhost falls
# through `try_files /maintenance.html =503` and tries to serve
# /var/lib/hyperion/maintenance/maintenance.html. Without that file
# visitors get the bare nginx 503 — works but ugly. Plant a friendly
# Hyperion-branded page once; operators can replace it freely (we
# only overwrite when the file is missing OR was a previous version
# we ourselves wrote, identified by the "x-hyperion-maintenance"
# marker comment).
#
# plant_page <dest> <marker> <what> — page body on stdin. Writes only when the
# content differs, so an update that changes nothing says nothing (it used to
# rewrite and announce both pages on every single run).
plant_page() {
  local dst="$1" marker="$2" what="$3" tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  if [[ -f "$dst" ]] && ! grep -q "$marker" "$dst" 2>/dev/null; then
    rm -f "$tmp"; return 0            # the operator's own page — never touched
  fi
  if cmp -s "$tmp" "$dst"; then
    rm -f "$tmp"; return 0
  fi
  install -m 0644 "$tmp" "$dst"
  rm -f "$tmp"
  log "Installed $what at $dst"
}
install -d -m 0755 /var/lib/hyperion/maintenance
MAINT_HTML="/var/lib/hyperion/maintenance/maintenance.html"
plant_page "$MAINT_HTML" x-hyperion-maintenance "default maintenance page" <<'HTML'
<!-- x-hyperion-maintenance: v3 - operator may replace this file freely -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>We'll be right back · Hyperion</title>
  <meta name="color-scheme" content="light dark">
  <meta name="robots" content="noindex,nofollow">
  <!-- Briefly down during an update: auto-retry so the page reloads itself the
       moment the service is back (nothing the visitor has to do). -->
  <meta http-equiv="refresh" content="15">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%23000000'/%3E%3Cpath d='M9 9 L9 23 M9 16 L17 16 M17 9 L17 23 M21 14 L24 14 L24 23 M21 11 L21 14' stroke='white' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round' fill='none'/%3E%3C/svg%3E">
  <style>
    /* Standalone styles (nginx serves this while hyperion-web is down, so there
       is no app.css). Deliberately mirrors the panel's themed error page
       (templates/error.html) so the 503 and the 404 look identical. */
    :root {
      --bg:#000000; --surface:#0a0a0a; --surface-1:#161616; --border:#1f1f1f;
      --text:#fafafa; --text-soft:#a1a1aa; --accent:#fafafa; --accent-fg:#000000;
      color-scheme: dark light;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg:#fafafa; --surface:#ffffff; --surface-1:#f4f4f5; --border:#eaeaea;
        --text:#0a0a0a; --text-soft:#52525b; --accent:#0a0a0a; --accent-fg:#ffffff;
      }
    }
    * { box-sizing:border-box; }
    .err-page {
      margin:0; min-height:100vh; display:grid; place-items:center; padding:2rem 1rem;
      background:var(--bg); color:var(--text);
      font:15px/1.55 "Geist","Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
      -webkit-font-smoothing:antialiased;
    }
    .err-card {
      background:var(--surface); border:1px solid var(--border); border-radius:14px;
      max-width:38rem; width:100%; padding:2rem 2.2rem; box-shadow:0 20px 50px rgba(0,0,0,.30);
    }
    .err-eyebrow {
      display:inline-flex; align-items:center; gap:.4rem; font-size:.78rem; font-weight:600;
      letter-spacing:.05em; text-transform:uppercase; color:var(--text-soft); margin-bottom:.6rem;
    }
    .err-eyebrow .err-code {
      background:var(--surface-1); border:1px solid var(--border); padding:.15rem .45rem;
      border-radius:6px; color:var(--text); font-feature-settings:"tnum";
    }
    .err-headline { font-size:1.45rem; font-weight:700; margin:0 0 .5rem; letter-spacing:-.01em; }
    .err-body { color:var(--text-soft); margin:0 0 1.2rem; }
    .err-actions { display:flex; gap:.55rem; flex-wrap:wrap; }
    .err-btn {
      display:inline-block; padding:.55rem 1.05rem; border-radius:8px;
      border:1px solid var(--accent); background:var(--accent); color:var(--accent-fg);
      text-decoration:none; font-weight:600; font-size:.92rem;
    }
    .err-btn:hover { filter:brightness(1.08); }
    .err-brand {
      margin-top:1.5rem; font-size:.78rem; color:var(--text-soft);
      letter-spacing:.05em; text-align:center;
    }
    .err-brand strong { color:var(--accent); letter-spacing:.08em; }
  </style>
</head>
<body class="err-page">
  <main class="err-card" role="alert" aria-live="polite">
    <div class="err-eyebrow">
      <span class="err-code">503</span>
      <span>Service unavailable</span>
    </div>
    <h1 class="err-headline">We'll be right back</h1>
    <p class="err-body">This service is updating and will be back automatically in a few moments — this page refreshes itself, so there's nothing you need to do.</p>
    <div class="err-actions">
      <a class="err-btn" href=".">Reload now</a>
    </div>
    <div class="err-brand"><strong>HY · PERION</strong></div>
  </main>
</body>
</html>
HTML

#-------- 5c. Default landing page (replaces "Welcome to nginx") ----------
# nginx's default_server answers any request whose Host matches no
# configured site. On a fresh Debian box that is the stock "Welcome to
# nginx" page — which is what a visitor (or the operator's own preview
# link over a not-yet-configured name) sees. Replace it with a
# Hyperion-branded "no site here" page, styled like the maintenance / error
# pages, and disable the Debian default so there is exactly one
# default_server per port.
install -d -m 0755 /var/lib/hyperion/default
DEFAULT_HTML="/var/lib/hyperion/default/index.html"
plant_page "$DEFAULT_HTML" x-hyperion-default "Hyperion default landing page" <<'HTML'
<!-- x-hyperion-default: v1 - operator may replace this file freely -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>No site here · Hyperion</title>
  <meta name="color-scheme" content="light dark">
  <meta name="robots" content="noindex,nofollow">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%23000000'/%3E%3Cpath d='M9 9 L9 23 M9 16 L17 16 M17 9 L17 23 M21 14 L24 14 L24 23 M21 11 L21 14' stroke='white' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round' fill='none'/%3E%3C/svg%3E">
  <style>
    :root {
      --bg:#000000; --surface:#0a0a0a; --border:#1f1f1f;
      --text:#fafafa; --text-soft:#a1a1aa;
      color-scheme: dark light;
    }
    @media (prefers-color-scheme: light) {
      :root { --bg:#fafafa; --surface:#ffffff; --border:#eaeaea; --text:#0a0a0a; --text-soft:#52525b; }
    }
    * { box-sizing:border-box; }
    body {
      margin:0; min-height:100vh; display:grid; place-items:center; padding:2rem 1rem;
      background:var(--bg); color:var(--text);
      font:15px/1.6 "Geist","Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
      -webkit-font-smoothing:antialiased;
    }
    .card {
      background:var(--surface); border:1px solid var(--border); border-radius:14px;
      max-width:30rem; width:100%; padding:2.25rem 2rem; text-align:center;
    }
    .logo { width:44px; height:44px; margin:0 auto 1.1rem; display:block; }
    h1 { font-size:1.25rem; margin:0 0 0.5rem; letter-spacing:-0.01em; }
    p { margin:0.4rem 0 0; color:var(--text-soft); font-size:0.92rem; }
    code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:0.86rem;
           background:color-mix(in srgb, var(--text) 8%, transparent); padding:0.1rem 0.35rem; border-radius:5px; }
    .tag { margin-top:1.4rem; font-size:0.78rem; color:var(--text-soft); letter-spacing:0.03em; }
  </style>
</head>
<body>
  <div class="card">
    <svg class="logo" viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
      <rect width="32" height="32" rx="7" fill="currentColor" opacity="0.06"/>
      <path d="M9 9 L9 23 M9 16 L17 16 M17 9 L17 23 M21 14 L24 14 L24 23 M21 11 L21 14"
            stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </svg>
    <h1>No site here yet</h1>
    <p>This server is managed by <strong>Hyperion</strong>, but no site is configured for this address.</p>
    <p>If this is your domain, point its DNS at this server and add it in the Hyperion panel.</p>
    <div class="tag">powered by Hyperion</div>
  </div>
</body>
</html>
HTML

# Disable the stock Debian default site (its default_server would clash
# with ours) and install Hyperion's catch-all default_server. Only touched
# when something actually changes, and only on an nginx config that passes
# `nginx -t` to begin with — otherwise our change would be blamed (and rolled
# back) for somebody else's breakage. A failed test puts BOTH files back.
if command -v nginx >/dev/null 2>&1; then
  DEFAULT_CONF="/etc/nginx/conf.d/zzz-hyperion-default.conf"
  STOCK_DEFAULT="/etc/nginx/sites-enabled/default"
  # Use Debian's ssl-cert-snakeoil for the :443 default (any real site has
  # its own cert; this only answers unmatched hosts, where a cert mismatch
  # is expected). Skip the :443 block if the snakeoil cert is absent.
  SNAKE_CRT="/etc/ssl/certs/ssl-cert-snakeoil.pem"
  SNAKE_KEY="/etc/ssl/private/ssl-cert-snakeoil.key"
  DEFAULT_NEW="$(mktemp)"
  CLEANUP_PATHS+=("$DEFAULT_NEW")
  {
    echo "# Managed by hyperion — catch-all default server. DO NOT EDIT."
    echo "server {"
    echo "    listen 80 default_server;"
    echo "    listen [::]:80 default_server;"
    echo "    server_name _;"
    echo "    root /var/lib/hyperion/default;"
    echo "    location / { try_files /index.html =404; }"
    echo "}"
    if [[ -f "$SNAKE_CRT" && -f "$SNAKE_KEY" ]]; then
      echo "server {"
      echo "    listen 443 ssl default_server;"
      echo "    listen [::]:443 ssl default_server;"
      echo "    server_name _;"
      echo "    ssl_certificate     $SNAKE_CRT;"
      echo "    ssl_certificate_key $SNAKE_KEY;"
      echo "    root /var/lib/hyperion/default;"
      echo "    location / { try_files /index.html =404; }"
      echo "}"
    fi
  } > "$DEFAULT_NEW"
  if cmp -s "$DEFAULT_NEW" "$DEFAULT_CONF" && [[ ! -e "$STOCK_DEFAULT" && ! -L "$STOCK_DEFAULT" ]]; then
    :   # already in place
  elif ! nginx -t >/dev/null 2>&1; then
    warn "nginx -t already fails on this box — left the catch-all default server alone (see: nginx -t)."
  else
    DEFAULT_BK="$(mktemp -d)"
    CLEANUP_PATHS+=("$DEFAULT_BK")
    [[ -f "$DEFAULT_CONF" ]] && cp -p "$DEFAULT_CONF" "$DEFAULT_BK/conf"
    if [[ -e "$STOCK_DEFAULT" || -L "$STOCK_DEFAULT" ]]; then
      mv "$STOCK_DEFAULT" "$DEFAULT_BK/stock"
    fi
    install -m 0644 "$DEFAULT_NEW" "$DEFAULT_CONF"
    if nginx -t >/dev/null 2>&1; then
      systemctl reload nginx 2>/dev/null || true
      [[ -e "$DEFAULT_BK/stock" || -L "$DEFAULT_BK/stock" ]] && log "Disabled stock nginx default site."
      log "Installed Hyperion catch-all default server."
    else
      # Never let our default server wedge nginx — put back what was there.
      if [[ -f "$DEFAULT_BK/conf" ]]; then cp -p "$DEFAULT_BK/conf" "$DEFAULT_CONF"; else rm -f "$DEFAULT_CONF"; fi
      if [[ -e "$DEFAULT_BK/stock" || -L "$DEFAULT_BK/stock" ]]; then mv "$DEFAULT_BK/stock" "$STOCK_DEFAULT"; fi
      warn "Hyperion default server failed nginx -t; put the previous config back (kept nginx healthy)."
    fi
  fi
fi

#-------- 5d. HTTP/2 spelling in vhosts vs this nginx ---------------------
# nginx has two spellings for HTTP/2 and each one is wrong somewhere:
#   * `http2 on;` (a directive) exists only from nginx 1.25.1. Debian 12
#     ships 1.22, where it is `[emerg] unknown directive "http2"` and every
#     reload fails.
#   * `listen 443 ssl http2;` (a listen parameter) works everywhere, but from
#     1.25.1 on it is deprecated and every `nginx -t` warns about it.
# The agent picks the right one for the nginx it runs next to
# (crates/hyperion-adapters/src/nginx.rs, http2_uses_directive) — but only
# when it re-renders a vhost. This heals files written for the OTHER kind of
# nginx: ones from releases before that check, and ones from a box whose nginx
# was upgraded (Debian 12 → 13) since they were written.
#
# The version rule here MUST stay the same as the agent's. This used to strip
# `http2 on;` unconditionally — on a modern nginx that undid every freshly
# rendered vhost on each update (deprecation warnings until the next render,
# which this then undid again).
#
# Only real files are edited: a sites-enabled entry that is a symlink is healed
# through its sites-available target (editing the link with `sed -i` replaced
# it with a stale copy). Backed up first; if `nginx -t` passed before and fails
# after, every file is put back.
# >>> http2-heal
NGINX_DIR="${HYPERION_NGINX_DIR:-/etc/nginx}"
if command -v nginx >/dev/null 2>&1; then
  NGINX_VERSION="$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9][0-9.]*\).*|\1|p' | head -n1)"
  # Same as the agent: an unknown version gets the form every nginx accepts.
  HTTP2_DIRECTIVE=0
  if [[ -n "$NGINX_VERSION" ]] \
     && [[ "$(printf '%s\n' 1.25.1 "$NGINX_VERSION" | sort -V | head -n1)" == 1.25.1 ]]; then
    HTTP2_DIRECTIVE=1
  fi

  HTTP2_FILES=()
  shopt -s nullglob
  for f in "$NGINX_DIR"/sites-available/*.conf "$NGINX_DIR"/sites-enabled/*.conf; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    if (( HTTP2_DIRECTIVE )); then
      # Legacy listen parameter, and no directive anywhere in the file (a file
      # that already mixes both is somebody's hand edit — leave it).
      grep -qE '^[[:space:]]*listen[[:space:]][^#]*[[:space:]]http2([[:space:]]|;)' "$f" \
        && ! grep -qE '^[[:space:]]*http2[[:space:]]+on[[:space:]]*;' "$f" \
        && HTTP2_FILES+=("$f")
    else
      grep -qE '^[[:space:]]*http2[[:space:]]+on[[:space:]]*;' "$f" && HTTP2_FILES+=("$f")
    fi
  done
  shopt -u nullglob

  if (( ${#HTTP2_FILES[@]} )); then
    HTTP2_OK_BEFORE=0
    nginx -t >/dev/null 2>&1 && HTTP2_OK_BEFORE=1
    HTTP2_BK="$(mktemp -d)"
    CLEANUP_PATHS+=("$HTTP2_BK")
    i=0
    for f in "${HTTP2_FILES[@]}"; do
      cp -p "$f" "$HTTP2_BK/$i"
      tmp="$HTTP2_BK/$i.new"
      if (( HTTP2_DIRECTIVE )); then
        # `listen … ssl http2;` → `listen … ssl;` + one `http2 on;` per server
        # block, right after its run of listen lines.
        awk '
          function flush() {
            if (pending && !done) { print indent "http2 on;"; done = 1 }
            pending = 0
          }
          /^[[:space:]]*server[[:space:]]*\{/ { flush(); done = 0; print; next }
          /^[[:space:]]*listen[[:space:]]/ && /[[:space:]]http2([[:space:]]|;)/ {
            line = $0
            match(line, /^[[:space:]]*/); indent = substr(line, 1, RLENGTH)
            gsub(/[[:space:]]+http2[[:space:]]*;/, ";", line)
            gsub(/[[:space:]]+http2[[:space:]]+/, " ", line)
            print line; pending = 1; next
          }
          /^[[:space:]]*listen[[:space:]]/ { print; next }
          { flush(); print }
          END { flush() }
        ' "$f" > "$tmp"
      else
        # `http2 on;` → `http2` on each `listen … ssl` line, directive dropped.
        sed -E \
          -e '/[[:space:]]http2[[:space:];]/!s/^([[:space:]]*listen[[:space:]]+[^#;]*[[:space:]]ssl)([[:space:]]*[;[:space:]])/\1 http2\2/' \
          -e '/^[[:space:]]*http2[[:space:]]+on[[:space:]]*;[[:space:]]*$/d' \
          "$f" > "$tmp"
      fi
      # Write in place (cat >) so owner, mode and inode stay the file's own.
      cat "$tmp" > "$f"
      i=$(( i + 1 ))
    done
    if (( HTTP2_DIRECTIVE )); then
      HTTP2_WHAT="\`listen … http2\` → \`http2 on;\` (nginx $NGINX_VERSION deprecates the listen form)"
    else
      HTTP2_WHAT="\`http2 on;\` → \`listen … ssl http2\` (nginx ${NGINX_VERSION:-of unknown version} has no http2 directive)"
    fi
    if nginx -t >/dev/null 2>&1; then
      systemctl reload nginx 2>/dev/null || true
      log "HTTP/2 spelling fixed in ${#HTTP2_FILES[@]} vhost(s): $HTTP2_WHAT"
      for f in "${HTTP2_FILES[@]}"; do log "    $f"; done
    elif (( HTTP2_OK_BEFORE )); then
      i=0
      for f in "${HTTP2_FILES[@]}"; do cat "$HTTP2_BK/$i" > "$f"; i=$(( i + 1 )); done
      warn "Switching the HTTP/2 spelling made nginx -t fail — put every vhost back unchanged."
      warn "  Wanted: $HTTP2_WHAT. Inspect with: nginx -t"
    else
      warn "Fixed the HTTP/2 spelling in ${#HTTP2_FILES[@]} vhost(s), but nginx -t still fails (it failed before too) — inspect: nginx -t"
    fi
  fi
fi
# <<< http2-heal

#-------- 5e. Refresh systemd units ---------------------------------------
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
# dig (bind9-dnsutils) — not a service, so it can't ride NEEDED_PKGS'
# unit-file check. Every DNS card in the panel (SPF, DKIM verify, the
# preflight banner) shells out to dig; a minimal Debian ships without it,
# and a node missing it reports every record as unverifiable. Heal it
# unconditionally — a few hundred kilobytes.
if ! command -v dig >/dev/null 2>&1; then
  log "Installing bind9-dnsutils (dig) — DNS checks need it ..."
  apt_install bind9-dnsutils 2>/dev/null || apt_install dnsutils || warn "could not install dig — SPF/DKIM verification will report unknown on this node"
fi

# sudo is how the root agent drops to a site's uid for EVERY wp-cli call
# ("sudo -u <site user> wp …"). A minimal Debian ships without it, and the
# installers did not list it until v0.40 — so a box installed before then
# fails every WordPress action with "io: No such file or directory", which
# reads like a problem with the site rather than a missing package.
if ! command -v sudo >/dev/null 2>&1; then
  log "Installing sudo — wp-cli runs as the site user through it ..."
  apt_install sudo \
    || warn "could not install sudo — every WordPress action will fail on this node"
fi

# restic backs the snapshot engine — a deduplicated copy taken before
# anything changes a site, and the only thing that can answer "what did last
# night's update change?". Absent, the snapshot code is inert and sites keep
# getting archive backups, so this is a heal rather than a hard requirement.
if ! command -v restic >/dev/null 2>&1; then
  log "Installing restic — snapshots before updates need it ..."
  apt_install restic \
    || warn "could not install restic — this node will not take snapshots before updates"
fi

#-------- 5f. Which optional software this box is meant to have -------
# The heals below re-install MariaDB, PostgreSQL, vsftpd, PHP and phpMyAdmin
# whenever they are missing. That was right while every install got all of
# them, but the setup wizard lets the operator CHOOSE — and an update that
# quietly installs the database server they said no to undoes that choice.
#
# /etc/hyperion/components is the record of the choice: one component per
# line (php8.1..php8.4, mariadb, postgresql, redis, vsftpd, phpmyadmin),
# written by components.sh as each one installs and by the Services page's
# install action. When the file exists, only what it lists is healed; an
# EMPTY file means "nothing optional chosen yet" (a box still in its setup
# wizard). nginx is always healed — nothing works without it.
#
# When the file does NOT exist — every box installed before the wizard, and
# every worker node — the heals behave exactly as they always have.
# >>> component-selection
COMPONENTS_FILE="${HYPERION_COMPONENTS_FILE:-/etc/hyperion/components}"
SELECTION_MODE=0
SELECTED_COMPONENTS=" "
load_component_selection() {
  SELECTION_MODE=0
  SELECTED_COMPONENTS=" "
  [[ -f "$COMPONENTS_FILE" ]] || return 0
  SELECTION_MODE=1
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line//[[:space:]]/}"
    [[ -n "$line" ]] && SELECTED_COMPONENTS+="$line "
  done < "$COMPONENTS_FILE"
  return 0
}
# component_selected <name> — is it listed? (Only meaningful in selection mode.)
component_selected() {
  [[ "$SELECTED_COMPONENTS" == *" $1 "* ]]
}
# heal_allowed <unit> — may the heal (re)install the package behind this unit?
heal_allowed() {
  (( SELECTION_MODE )) || return 0
  local ver
  case "$1" in
    nginx.service)        return 0 ;;
    mariadb.service)      component_selected mariadb ;;
    postgresql.service)   component_selected postgresql ;;
    vsftpd.service)       component_selected vsftpd ;;
    redis-server.service) component_selected redis ;;
    php*-fpm.service)
      ver="${1#php}"; ver="${ver%-fpm.service}"
      component_selected "php$ver" ;;
    *)                    return 1 ;;
  esac
}
# <<< component-selection
load_component_selection
if (( SELECTION_MODE )); then
  log "Healing only the software chosen for this box ($COMPONENTS_FILE):${SELECTED_COMPONENTS% }"
fi

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

for unit in "${!NEEDED_PKGS[@]}"; do
  # Skip PHP versions that aren't critical — only install if the
  # unit is missing AND no other PHP-FPM unit is already installed
  # (i.e. we want AT LEAST ONE php-fpm; we don't force all 4).
  # Always install nginx + the *required* services.
  if unit_installed "$unit"; then
    continue
  fi
  if (( SELECTION_MODE )); then
    # Exactly what the operator chose: every listed PHP version, each
    # listed service, nothing else (nginx always — see heal_allowed).
    heal_allowed "$unit" || continue
  # Skip optional PHP versions when at least one is already there.
  elif [[ "$unit" == php*-fpm.service ]]; then
    if unit_installed php8.1-fpm.service \
       || unit_installed php8.2-fpm.service \
       || unit_installed php8.3-fpm.service \
       || unit_installed php8.4-fpm.service; then
      continue
    fi
  fi
  pkgs="${NEEDED_PKGS[$unit]}"
  log "$unit missing — installing $pkgs ..."
  # shellcheck disable=SC2086  # $pkgs is a space-separated package list
  if ! apt_install $pkgs; then
    warn "$pkgs install failed — features that depend on $unit will not work \
until this is fixed manually (apt-get install -y $pkgs)."
  fi
done
# Redis exists only as a wizard choice, so it is healed only when chosen —
# never on a box without the components file.
if (( SELECTION_MODE )) && heal_allowed redis-server.service \
   && ! unit_installed redis-server.service; then
  log "redis-server.service missing — installing redis-server ..."
  if apt_install redis-server; then
    systemctl enable --now redis-server >/dev/null 2>&1 || true
  else
    warn "redis-server install failed (apt-get install -y redis-server)."
  fi
fi

#-------- 5g. PHP extensions required by WordPress / wp-cli -----------
# The NEEDED_PKGS loop above only fires when the -fpm unit is MISSING, so
# a server that already has php8.3-fpm but predates the extension bundle
# (or had it trimmed) never gets the extras. wp-cli `core download` needs
# ZipArchive (php*-zip) and a bare WordPress needs gd/mbstring/xml/curl/
# mysql — the symptom is a mid-install "Extracting a zip file requires
# ZipArchive". soap is here too: many WordPress plugins (shipping,
# invoicing, payment gateways) hard-require the SOAP extension and fail
# with "Plugin requires an active Soap library ... contact your server
# administrator". Listing it here is what gets it onto the whole existing
# fleet on the next update, not just freshly installed servers.
# For every PHP version whose -fpm unit IS present, ensure the full
# extension set. apt-get install is idempotent; we only call it when dpkg
# reports at least one missing, so a healthy box pays nothing.
PHP_EXT_SUFFIXES=(zip gd mbstring xml curl mysql soap)
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
  # shellcheck disable=SC2086  # $want is a space-separated package list
  if apt_install $want; then
    # Newly-added modules only load after the fpm worker reloads.
    systemctl try-restart "php${ver}-fpm.service" 2>/dev/null || true
  else
    warn "some php${ver} extensions failed to install — WordPress installs \
on PHP ${ver} hostings may fail (apt-get install -y$want)."
  fi
done

#-------- 5h. phpMyAdmin behind the panel ------------------------------
# Every box that hosts sites gets its own phpMyAdmin, because the hosting
# databases only accept connections from localhost. It is served on a
# root-only unix socket and reached exclusively through the panel (the agent
# relays authenticated requests) — see the script's header. Runs after the
# extension heal above so mysqli/mbstring are already present. With a
# components file, only on a box where phpMyAdmin was chosen.
PMA_SCRIPT="$INSTALL_DIR/packaging/install/phpmyadmin.sh"
if (( HAVE_AGENT )) && [[ -f "$PMA_SCRIPT" ]] \
   && { (( ! SELECTION_MODE )) || component_selected phpmyadmin; }; then
  bash "$PMA_SCRIPT" || warn "phpMyAdmin setup failed — the panel's phpMyAdmin button \
will report it as not installed on this node (re-run: bash $PMA_SCRIPT)."
fi

#-------- 5i. MTA (so PHP mail() actually delivers) -----------------------
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
  if apt_install postfix; then
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

#-------- 5j. Make sure PHP-FPM + web/db daemons are enabled -----------
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

#-------- 5k. TLS cert dir (idempotent) -----------------------------------
# hyperion-web auto-generates a self-signed cert on first start; we just
# need to make sure the directory exists and the agent service can write
# into it (covered by ReadWritePaths=/etc/hyperion in the systemd unit).
install -d -m 0700 /etc/hyperion/web-tls

#-------- 5l. retire the Cloudflare DNS-01 token ------------------------
# The Cloudflare API integration is gone: certificates now issue over
# HTTP-01, which works through the proxy, and wildcards are published by
# hand. Nothing reads this file any more.
#
# It is not deleted — it is operator credential material, and a token that
# silently vanishes is a token nobody remembers to revoke. Moving it stops
# it being live while leaving the evidence, and the log line says what to
# do about it. Idempotent on CONTENT: once renamed, the source path is gone
# and a re-run is a no-op.
if [[ -f /etc/hyperion/cloudflare.token ]]; then
  mv /etc/hyperion/cloudflare.token /etc/hyperion/cloudflare.token.removed
  chmod 0600 /etc/hyperion/cloudflare.token.removed 2>/dev/null || true
  warn "The Cloudflare DNS-01 integration has been removed — certificates now"
  warn "issue over HTTP-01, which works through the Cloudflare proxy."
  warn "Your API token is no longer read. It has been moved to"
  warn "    /etc/hyperion/cloudflare.token.removed"
  warn "REVOKE it at dash.cloudflare.com -> My Profile -> API Tokens, then"
  warn "delete that file."
fi

#-------- 5m. master→node remote RPC — WORKERS ONLY -------------------
# The inbound RPC listener exists so a MASTER can dispatch to a WORKER.
# Nothing ever dials a master or a single-server box on this port: the
# panel routes a local request (target_node_id None/"local") straight to
# the agent's Unix socket, never over the network — see
# bin/hyperion-web/src/dispatcher.rs. So on a box with no master above
# it, `enabled = true` buys exactly nothing and costs a root-privileged
# HTTPS listener on 0.0.0.0:9443 plus, until this change, a world-open
# ufw rule to go with it.
#
# It does currently fail CLOSED there — bin/hyperion-agent/src/inbound_rpc.rs
# refuses every request with 503 while /etc/hyperion/node-id.json is
# absent, because without an enrollment there is no master pubkey to
# verify a signature against. But that is incidental, not intentional:
# the safety rests on a file happening not to exist. Restore a backup
# taken from a worker, copy an agent.toml between boxes, or repurpose a
# machine that was once a worker, and the port turns into a live signed
# control channel for hosting create/delete and password reset. A box
# that never needed the listener should not be running it.
#
# Worker-ness is decided by evidence, not by a guess: an enrollment file
# on disk, or a master_url pointing somewhere. Note the agent must NOT
# make the same decision at startup — a fresh worker writes node-id.json
# during enrollment, i.e. AFTER boot, so gating the spawn on that file
# would leave a newly-enrolled node unreachable until its next restart.
# Per-request refusal is the correct runtime gate; this is the config one.
#
# This is the channel the CLUSTER ROLLOUT ORDER at the top of this file
# governs. Nothing here is cluster-aware: the agent's response-signing
# key and TLS pin are re-published by its next HEARTBEAT, not by this
# script, which is why step 3 says to wait for the readiness pill rather
# than for this script to exit.
IS_WORKER=0
if [[ -f /etc/hyperion/node-id.json ]]; then
  IS_WORKER=1
elif [[ -f /etc/hyperion/agent.toml ]] \
     && grep -Eq '^[[:space:]]*master_url[[:space:]]*=[[:space:]]*"[^"]+"' /etc/hyperion/agent.toml; then
  IS_WORKER=1
fi

if [[ -f /etc/hyperion/agent.toml ]] && ! grep -q '^\[remote_rpc\]' /etc/hyperion/agent.toml; then
  if (( IS_WORKER )); then
    log "Adding [remote_rpc] section (worker) to /etc/hyperion/agent.toml ..."
    RPC_ENABLED=true
  else
    log "Adding [remote_rpc] section (disabled — no master above this box) ..."
    RPC_ENABLED=false
  fi
  cat >> /etc/hyperion/agent.toml <<EOF

# Master→node remote RPC (added by update.sh). Only a WORKER needs this:
# a master reaches its own agent over the local Unix socket, never over
# the network, so on a master or a single-server box this stays false.
# If this box later enrolls to a master, set enabled = true and restart
# hyperion-agent.
[remote_rpc]
enabled       = $RPC_ENABLED
bind          = "0.0.0.0:9443"
tls_cert_file = "/etc/hyperion/agent-rpc.crt"
tls_key_file  = "/etc/hyperion/agent-rpc.key"
EOF
fi

# Retro-fix boxes an earlier update.sh already switched on. Keyed on
# CONTENT, not on the section merely existing, so a re-run is a no-op
# once corrected — the same idempotency lesson the sury/Debian-suite
# block learned the hard way. Only ever narrows: a worker is untouched.
if (( ! IS_WORKER )) && [[ -f /etc/hyperion/agent.toml ]] \
   && grep -Eq '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true' /etc/hyperion/agent.toml \
   && grep -q '^\[remote_rpc\]' /etc/hyperion/agent.toml; then
  # Confine the edit to the [remote_rpc] section — other sections have
  # their own `enabled` keys and must not be touched.
  if awk '
      /^\[/ { in_rpc = ($0 ~ /^\[remote_rpc\]/) }
      in_rpc && /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true/ { found = 1 }
      END { exit !found }
    ' /etc/hyperion/agent.toml; then
    log "Disabling unused inbound RPC listener (this box has no master above it) ..."
    awk '
      /^\[/ { in_rpc = ($0 ~ /^\[remote_rpc\]/) }
      in_rpc && /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true/ {
        sub(/true/, "false"); print; next
      }
      { print }
    ' /etc/hyperion/agent.toml > /etc/hyperion/agent.toml.new \
      && chmod --reference=/etc/hyperion/agent.toml /etc/hyperion/agent.toml.new \
      && mv /etc/hyperion/agent.toml.new /etc/hyperion/agent.toml
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '9443/tcp'; then
      warn "ufw still allows 9443/tcp, which now leads to a closed port. Remove it with:"
      warn "    ufw delete allow 9443/tcp"
    fi
  fi
fi

# Open 9443 only where something actually listens on it.
if (( IS_WORKER )) \
   && command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  if ! ufw status 2>/dev/null | grep -q '9443/tcp'; then
    log "Opening ufw 9443/tcp for master→node RPC ..."
    ufw allow 9443/tcp comment 'hyperion master->node RPC' || true
  fi
fi

#-------- 5n. wp-cli (best-effort install/update) -------------------------
# WordPress install adapter shells out to /usr/local/bin/wp. Older Hyperion
# installs predate wp-cli being installed by install-master.sh, so make
# update.sh fix that too.
# Best-effort for real: a failed download used to abort the whole update under
# `set -e` (with the services already stopped), and `-o` straight onto the
# target could leave a truncated, executable `wp` behind.
if [[ ! -x /usr/local/bin/wp ]]; then
  log "Installing wp-cli ..."
  WP_TMP="$(mktemp)"
  CLEANUP_PATHS+=("$WP_TMP")
  if curl -fsSL --max-time 120 https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
       -o "$WP_TMP" && [[ -s "$WP_TMP" ]]; then
    install -d -m 0755 /usr/local/bin
    install -m 0755 "$WP_TMP" /usr/local/bin/wp
  else
    warn "Couldn't download wp-cli — WordPress actions will fail until it is installed (re-run the update)."
  fi
fi

#-------- 5o. Materialize web keys (idempotent) ----------------------------
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
status running migrate
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
    # The dry run works on a COPY of the database, so the live one is
    # untouched — the previous binaries run against it exactly as before.
    # Exiting here hands over to recover_after_failure, which puts them back
    # and starts them (it used to leave the panel down until someone SSH'd in).
    warn "DB migration dry-run FAILED — the new version would crash-loop on this database."
    fail "Not starting the new version; your data is untouched."
  fi
fi

#-------- 7. Start + health check -----------------------------------------
status running start
REACHED_START=1
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

#-------- 7a-bis. Safe update: restore on a failed health check -----------
# The operator is usually clicking Update from the very panel an update can
# take down, so "it broke, go and SSH in" is the worst possible outcome. If
# the checks above say the new binaries are not serving, put the old ones
# back and re-check — and be explicit that this restored BINARIES, not data.
if (( SAFE )) && (( ! HEALTHY )); then
  warn "Health check FAILED after update — restoring the previous binaries."
  status running rollback
  if restore_snapshot; then
    HEALTHY=1
    (( HAVE_AGENT )) && check_active hyperion-agent
    (( HAVE_AGENT )) && check_agent_serving
    (( HAVE_WEB   )) && check_active hyperion-web
    if (( HEALTHY )); then
      warn "Rolled back to $(tr -d '\n' < "$SNAP_DIR/VERSION" 2>/dev/null || echo 'the previous build') — the panel is serving again."
      warn "The update did NOT apply. Check the journal above before retrying."
      ROLLED_BACK=1
    else
      warn "Rollback did not restore health either. This needs a look by hand:"
      warn "  journalctl -u hyperion-agent -n 50"
    fi
  fi
fi

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
if (( DO_BUILD )) && (( ! ROLLED_BACK )); then
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
    warn "    sudo $INSTALL_DIR/packaging/install/update.sh --from-source"
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

# A rollback is a FAILED update, even though the box is healthy again —
# exit non-zero so the panel reports it as such and nobody reads "done".
if (( ROLLED_BACK )); then
  echo "  RESULT: update rolled back — the previous version is running."
  exit 1
fi
if (( HEALTHY == 0 )); then
  exit 1
fi
echo "  Tail live logs with:"
(( HAVE_AGENT )) && echo "    journalctl -u hyperion-agent -f"
(( HAVE_WEB   )) && echo "    journalctl -u hyperion-web -f"
