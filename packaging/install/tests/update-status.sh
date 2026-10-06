#!/usr/bin/env bash
# Tests for update.sh's live status file — what the panel's "updating" page
# polls while hyperion-web is down.
#
# Like update-wait.sh, this lifts the block between the `>>> update-status` /
# `<<< update-status` markers and runs it with `systemctl` stubbed, because
# update.sh itself stops root services. The page parses this file as JSON and
# keys on its field names, so a malformed write or a renamed field here is a
# page that silently falls back to "can't tell" on every update.
#
#   packaging/install/tests/update-status.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
UPDATE_SH="$ROOT/packaging/install/update.sh"
PAGE="$ROOT/crates/hyperion-adapters/assets/panel-maintenance.html"

command -v python3 >/dev/null || { echo "python3 is required to run this test" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sed -n '/^# >>> update-status$/,/^# <<< update-status$/p' "$UPDATE_SH" > "$TMP/block.sh"
[[ -s "$TMP/block.sh" ]] || { echo "markers not found in update.sh" >&2; exit 1; }

pass=0; failed=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { failed=$((failed + 1)); printf '  FAIL %s\n' "$1"; [[ -n "${2:-}" ]] && printf '%s\n' "$2" | sed 's/^/       | /'; }

STATUS="$TMP/m/panel-update.json"

# Run a snippet against the block. Args: web-active(1/0), then the snippet.
run() {
  local active="$1" snippet="$2"
  (
    export HYPERION_UPDATE_STATUS_FILE="${STATUS_OVERRIDE:-$STATUS}"
    unset HYPERION_UPDATE_STATUS HYPERION_UPDATE_STARTED
    systemctl() { [[ "$active" == 1 ]]; }
    # shellcheck disable=SC1091
    source "$TMP/block.sh"
    eval "$snippet"
  ) 2>&1
}

# field <name> — read one field of the status file (empty if absent).
field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print("" if v is None else v)' "$STATUS" "$1"; }

echo "update.sh update-status"

# 1. Nothing is written before status_begin (worker nodes never call it).
rm -rf "$TMP/m"
run 0 'status running stop' >/dev/null
if [[ ! -e "$STATUS" ]]; then ok "no status file until status_begin"
else bad "no status file until status_begin" "$(cat "$STATUS")"; fi

# 2. A step write is valid JSON with every field the page reads.
rm -rf "$TMP/m"
run 0 'status_begin; status running fetch' >/dev/null
if python3 -m json.tool "$STATUS" >/dev/null 2>&1 \
   && [[ "$(field state)" == running && "$(field step)" == fetch ]] \
   && [[ "$(field started)" =~ ^[0-9]+$ && "$(field step_started)" =~ ^[0-9]+$ && "$(field updated)" =~ ^[0-9]+$ ]] \
   && [[ "$(stat -c %a "$STATUS" 2>/dev/null || stat -f %Lp "$STATUS")" == 644 ]]; then
  ok "step write is valid, world-readable JSON"
else bad "step write is valid, world-readable JSON" "$(cat "$STATUS" 2>&1)"; fi

# 3. Build progress is a number; a non-number is dropped, not written raw.
run 0 'status_begin; status running build 47' >/dev/null
p1="$(field progress)"
run 0 'status_begin; status running build "4\"7"' >/dev/null
if [[ "$p1" == 47 ]] && python3 -m json.tool "$STATUS" >/dev/null 2>&1 && [[ -z "$(field progress)" ]]; then
  ok "build progress is numeric or absent"
else bad "build progress is numeric or absent" "$(cat "$STATUS")"; fi

# 4. The step clock restarts on a new step and holds within one.
out="$(run 0 'status_begin; status running build 1; a=$STATUS_STEP_STARTED; sleep 1; status running build 2; b=$STATUS_STEP_STARTED; sleep 1; status running configure; c=$STATUS_STEP_STARTED; echo "$a $b $c"')"
read -r a b c <<<"$out"
if [[ "$a" == "$b" && "$c" -gt "$b" ]]; then ok "step clock: same step holds, new step restarts"
else bad "step clock: same step holds, new step restarts" "$out"; fi

# 5. The re-exec'd copy inherits "on" and the original start time.
rm -rf "$TMP/m"
out="$(run 0 'status_begin; s=$STATUS_STARTED; sleep 1; (unset STATUS_ON; source "$TMP/block.sh"; status running configure; echo "$s $STATUS_STARTED")')"
read -r s1 s2 <<<"$out"
if [[ "$s1" == "$s2" && "$(field started)" == "$s1" ]]; then ok "re-exec keeps reporting with the original start"
else bad "re-exec keeps reporting with the original start" "$out"; fi

# 6. Success removes the file (404 = nothing running).
run 0 'status_begin; status running start; status_finish 0' >/dev/null
if [[ ! -e "$STATUS" ]]; then ok "success removes the status file"
else bad "success removes the status file" "$(cat "$STATUS")"; fi

# 7. A failure with the panel down leaves "failed" at the step it died in.
run 0 'status_begin; status running migrate; status_finish 1' >/dev/null
if [[ "$(field state)" == failed && "$(field step)" == migrate ]]; then ok "failure records the failed step"
else bad "failure records the failed step" "$(cat "$STATUS" 2>&1)"; fi

# 8. A non-zero exit with the panel serving (rollback, skew warning) removes it.
run 1 'status_begin; status running rollback; status_finish 1' >/dev/null
if [[ ! -e "$STATUS" ]]; then ok "non-zero exit with the panel up removes the file"
else bad "non-zero exit with the panel up removes the file" "$(cat "$STATUS")"; fi

# 9. An unwritable location never fails the caller.
out="$(STATUS_OVERRIDE=/proc/nope/x run 0 'set -e; status_begin; status running stop; status_finish 1; echo survived')"
if grep -q '^survived$' <<<"$out"; then ok "unwritable status dir is ignored"
else bad "unwritable status dir is ignored" "$out"; fi

# 10. Every step update.sh reports is one the page knows how to label.
steps="$(grep -oE '^\s*status running [a-z]+' "$UPDATE_SH" | awk '{print $3}' | sort -u)"
missing=""
for s in $steps; do grep -q "\\b$s:" "$PAGE" || missing+=" $s"; done
if [[ -n "$steps" && -z "$missing" ]]; then ok "page labels every step update.sh reports"
else bad "page labels every step update.sh reports" "missing:${missing:- (no steps found)}"; fi

echo
echo "$pass passed, $failed failed"
(( failed == 0 ))
