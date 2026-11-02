#!/usr/bin/env bash
# Tests for site-mail-wrapper's `-u` check — the wrapper keeps its own copy of
# the system-user rule (crates/hyperion-validate/src/sysuser.rs), because the
# value becomes a filename. A name the panel accepts but the wrapper refuses
# still sends mail, and loses its mail log without telling anyone.
#
# Runs the real script with its two fixed paths pointed at a temp directory.
#
#   packaging/install/tests/site-mail-wrapper.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
WRAPPER_SRC="$ROOT/packaging/install/site-mail-wrapper.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; failed=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { failed=$((failed + 1)); printf '  FAIL %s\n' "$1"; [[ -n "${2:-}" ]] && printf '%s\n' "$2" | sed 's/^/       | /'; }

LOG_ROOT="$TMP/nested/site-mail"
SENT="$TMP/sent"

# Records what the real sendmail would have received.
cat > "$TMP/sendmail" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" > "$SENT.args"
cat > "$SENT.body"
EOF
chmod +x "$TMP/sendmail"

sed -e "s#^REAL_SENDMAIL=.*#REAL_SENDMAIL=\"$TMP/sendmail\"#" \
    -e "s#^LOG_ROOT=.*#LOG_ROOT=\"$LOG_ROOT\"#" \
    "$WRAPPER_SRC" > "$TMP/wrapper"
chmod +x "$TMP/wrapper"

send() {
  rm -f "$SENT.args" "$SENT.body"
  printf 'From: wp@example.cz\nTo: a@example.cz\nSubject: Hi\n\nBody\n' \
    | "$TMP/wrapper" -u "$1" -t -i 2>"$TMP/stderr"
}

echo "valid names are logged"
for user in example_cz example-dev admin-user a-b; do
  send "$user" || bad "$user: wrapper exited non-zero" "$(cat "$TMP/stderr")"
  if grep -q "\"user\": \"$user\"" "$LOG_ROOT/$user.jsonl" 2>/dev/null; then
    ok "$user: logged to $user.jsonl"
  else
    bad "$user: no log record" "$(cat "$TMP/stderr")"
  fi
  if grep -q '^Subject: Hi$' "$SENT.body" 2>/dev/null; then
    ok "$user: message forwarded"
  else
    bad "$user: message not forwarded"
  fi
done

echo "bad names write nothing, and the mail still goes out"
rm -rf "$LOG_ROOT"
for user in '../evil' 'a/b' '-rf' 'Abc' 'a.b' "$(printf 'abc\ndef')"; do
  send "$user" || bad "$user: wrapper exited non-zero" "$(cat "$TMP/stderr")"
  if grep -q 'refusing bad -u value' "$TMP/stderr"; then
    ok "$user: refused"
  else
    bad "$user: not refused"
  fi
  if grep -q '^Subject: Hi$' "$SENT.body" 2>/dev/null; then
    ok "$user: message forwarded"
  else
    bad "$user: message not forwarded"
  fi
done
if [[ -z "$(find "$TMP" -name '*.jsonl' 2>/dev/null)" ]]; then
  ok "no log file written for any refused name"
else
  bad "a refused name wrote a log" "$(find "$TMP" -name '*.jsonl')"
fi

printf '\n%d passed, %d failed\n' "$pass" "$failed"
[[ "$failed" -eq 0 ]]
