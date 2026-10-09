#!/usr/bin/env bash
# Tests for update.sh's "wait for running jobs before stopping the services".
#
# update.sh is a curl|bash one-file script that stops root services as its
# first act, so it cannot be run here. Instead this lifts the block between the
# `>>> wait-for-jobs` / `<<< wait-for-jobs` markers, stubs the few things it
# calls (log/warn/fail/systemctl/apt-get), and runs it against a state DB built
# from the REAL migrations — so a renamed column in `jobs`, `backup_runs` or
# `hostings` fails here instead of silently turning the wait into a no-op on a
# production box.
#
#   packaging/install/tests/update-wait.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
UPDATE_SH="$ROOT/packaging/install/update.sh"
MIGRATIONS="$ROOT/crates/hyperion-state/migrations"

command -v sqlite3 >/dev/null || { echo "sqlite3 is required to run this test" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The block under test, lifted verbatim.
sed -n '/^# >>> wait-for-jobs$/,/^# <<< wait-for-jobs$/p' "$UPDATE_SH" > "$TMP/block.sh"
[[ -s "$TMP/block.sh" ]] || { echo "markers not found in update.sh" >&2; exit 1; }

# A state DB with the production schema.
new_db() {
  local db="$1"
  rm -f "$db"
  local f
  for f in "$MIGRATIONS"/*.sql; do
    sqlite3 "$db" < "$f" || { echo "migration failed: $f" >&2; exit 1; }
  done
}

NOW="$(date +%s)"
pass=0; failed=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { failed=$((failed + 1)); printf '  FAIL %s\n' "$1"; [[ -n "${2:-}" ]] && printf '%s\n' "$2" | sed 's/^/       | /'; }

# Run the block in a subshell with stubs. Args: services-active(1/0) then any
# VAR=value overrides. Prints combined output and "rc=<n>" on the last line.
run_block() {
  local active="$1"; shift
  (
    export STATE_DB="$DB" WAIT_FOR_JOBS=1 WAIT_TIMEOUT=0 WAIT_POLL=1
    unset HYPERION_JOBS_CHECKED
    for kv in "$@"; do export "${kv?}"; done
    log()  { printf 'LOG: %s\n' "$*"; }
    warn() { printf 'WARN: %s\n' "$*"; }
    fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
    systemctl() { [[ "$active" == 1 ]]; }
    apt-get() { return 1; }
    # shellcheck disable=SC1091
    source "$TMP/block.sh"
    wait_for_running_work
    echo "checked=${HYPERION_JOBS_CHECKED:-}"
  ) 2>&1 && echo "rc=0" || echo "rc=$?"
}

insert_job() { # <state> <updated_at_offset_secs> [kind]
  sqlite3 "$DB" "INSERT INTO jobs (id, kind, target, state, step_label, progress_pct, started_at, updated_at)
                 VALUES ('j$RANDOM$RANDOM', '${3:-migration}', 'example.cz', '$1', 'copying files', 40,
                         $NOW - 100 + $2, $NOW + $2);"
}
DB="$TMP/state.db"

echo "update.sh wait-for-jobs"

# 1. Idle box: returns at once, marks itself checked.
new_db "$DB"
out="$(run_block 1)"
if grep -q '^rc=0$' <<<"$out" && ! grep -q 'Waiting' <<<"$out" && grep -q '^checked=1$' <<<"$out"; then
  ok "idle box proceeds immediately"
else bad "idle box proceeds immediately" "$out"; fi

# 2. A fresh running job blocks (and --wait-timeout gives up without changing anything).
new_db "$DB"; insert_job running -5
out="$(run_block 1 WAIT_TIMEOUT=2)"
if grep -q '^rc=1$' <<<"$out" && grep -q 'migration | example.cz | copying files 40%' <<<"$out" \
   && grep -q 'nothing was stopped or installed' <<<"$out"; then
  ok "running job blocks, is listed, and --wait-timeout gives up"
else bad "running job blocks, is listed, and --wait-timeout gives up" "$out"; fi

# 3. A job whose heartbeat is older than the reaper threshold is a ghost.
new_db "$DB"; insert_job running -7200
out="$(run_block 1 WAIT_TIMEOUT=2)"
if grep -q '^rc=0$' <<<"$out" && ! grep -q 'Waiting' <<<"$out"; then
  ok "stale 'running' job (crashed agent) is ignored"
else bad "stale 'running' job (crashed agent) is ignored" "$out"; fi

# 4. Finished jobs do not count.
new_db "$DB"; insert_job done -5; insert_job failed -5
out="$(run_block 1 WAIT_TIMEOUT=2)"
if grep -q '^rc=0$' <<<"$out" && ! grep -q 'Waiting' <<<"$out"; then
  ok "done/failed jobs do not block"
else bad "done/failed jobs do not block" "$out"; fi

# 5. A running backup blocks; a 7h-old one is a ghost.
new_db "$DB"
sqlite3 "$DB" "INSERT INTO backup_runs (hosting_id, started_at, state) VALUES ('h-1', $NOW - 30, 'running');"
out="$(run_block 1 WAIT_TIMEOUT=2)"
if grep -q '^rc=1$' <<<"$out" && grep -q 'backup | h-1 | started' <<<"$out"; then
  ok "running backup blocks"
else bad "running backup blocks" "$out"; fi
new_db "$DB"
sqlite3 "$DB" "INSERT INTO backup_runs (hosting_id, started_at, state) VALUES ('h-1', $NOW - 25200, 'running');"
out="$(run_block 1 WAIT_TIMEOUT=2)"
if grep -q '^rc=0$' <<<"$out"; then
  ok "stale 'running' backup (crashed agent) is ignored"
else bad "stale 'running' backup (crashed agent) is ignored" "$out"; fi

# 6. The backup is named by its domain when the hosting row exists.
new_db "$DB"
sqlite3 "$DB" "INSERT INTO hostings (id, domain, state, system_user_id, root_dir, created_at, updated_at)
               VALUES ('h-9', 'shop.example.cz', 'active', 1, '/home/shop/htdocs', $NOW, $NOW);
               INSERT INTO backup_runs (hosting_id, started_at, state) VALUES ('h-9', $NOW - 30, 'running');"
out="$(run_block 1 WAIT_TIMEOUT=2)"
if grep -q 'backup | shop.example.cz | started' <<<"$out"; then ok "backup is listed by domain"
else bad "backup is listed by domain" "$out"; fi

# 7. The wait ends by itself when the job finishes — and says so.
new_db "$DB"; insert_job running -1
( sleep 2; sqlite3 "$DB" "UPDATE jobs SET state='done';" ) &
out="$(run_block 1 WAIT_TIMEOUT=30)"
wait
if grep -q '^rc=0$' <<<"$out" && grep -q 'Waiting for running jobs' <<<"$out" \
   && grep -q 'Running jobs finished' <<<"$out" && grep -q '^checked=1$' <<<"$out"; then
  ok "waits, then proceeds once the job finishes"
else bad "waits, then proceeds once the job finishes" "$out"; fi

# 8. Services down: leftover rows are ghosts, nothing to wait for.
new_db "$DB"; insert_job running -1
out="$(run_block 0 WAIT_TIMEOUT=2)"
if grep -q '^rc=0$' <<<"$out" && ! grep -q 'Waiting' <<<"$out"; then
  ok "stopped services: leftover rows are not waited on"
else bad "stopped services: leftover rows are not waited on" "$out"; fi

# 9. --no-wait skips the check entirely.
new_db "$DB"; insert_job running -1
out="$(run_block 1 WAIT_FOR_JOBS=0 WAIT_TIMEOUT=2)"
if grep -q '^rc=0$' <<<"$out" && grep -q -- '--no-wait' <<<"$out" && ! grep -q 'Waiting' <<<"$out"; then
  ok "--no-wait does not wait"
else bad "--no-wait does not wait" "$out"; fi

# 10. The re-exec'd copy (services already stopped by its parent) must not wait.
new_db "$DB"; insert_job running -1
out="$(run_block 1 HYPERION_JOBS_CHECKED=1 WAIT_TIMEOUT=2)"
if grep -q '^rc=0$' <<<"$out" && ! grep -q 'Waiting' <<<"$out"; then
  ok "re-exec'd copy skips the wait"
else bad "re-exec'd copy skips the wait" "$out"; fi

# 11. An unreadable DB fails OPEN: warn and update, never wedge the box.
printf 'this is not a database' > "$DB"
out="$(run_block 1 WAIT_TIMEOUT=2)"
if grep -q '^rc=0$' <<<"$out" && grep -q 'WARN: Could not read the job list' <<<"$out"; then
  ok "unreadable DB: warns and updates without waiting"
else bad "unreadable DB: warns and updates without waiting" "$out"; fi

# 12. No DB yet (fresh install): nothing to wait for.
rm -f "$DB"
out="$(run_block 1)"
if grep -q '^rc=0$' <<<"$out"; then ok "no state DB: proceeds"
else bad "no state DB: proceeds" "$out"; fi

echo
echo "$pass passed, $failed failed"
(( failed == 0 ))
