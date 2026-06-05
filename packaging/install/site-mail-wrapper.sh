#!/usr/bin/env bash
#
# Hyperion site-mail wrapper.
#
# Installed at /usr/local/lib/hyperion/site-mail-wrapper. Configured
# as `sendmail_path` for every PHP-FPM pool — when a hosted PHP
# site calls mail() / wp_mail() / similar, PHP execs THIS script
# with the message on stdin. We:
#   1. Read stdin into a temp file (so we can both parse + forward).
#   2. Extract From / To / Subject / first ~1 KB of body.
#   3. Append one JSON object per line to
#      /var/lib/hyperion/site-mail/<user>.jsonl
#   4. Exec the real sendmail (/usr/sbin/sendmail) so delivery is
#      identical to the pre-wrapper behaviour.
#
# Failure modes (intentionally non-fatal — never block the email):
#   - JSONL directory missing: try to create; if still fails, skip
#     the log step and forward only.
#   - Real sendmail missing: bail with exit 75 (EX_TEMPFAIL) so PHP
#     retries; site mail still works as before once sendmail returns.
#
# Invoked as:
#   site-mail-wrapper -u <system_user> [other-sendmail-flags...]
#
# We validate `<system_user>` matches `^[a-z][a-z0-9_]{0,31}$` and
# refuse anything else — defence in depth so a misconfigured pool
# (or a path-traversal attempt via -u) can't write outside the
# expected directory.

set -u

REAL_SENDMAIL="/usr/sbin/sendmail"
LOG_ROOT="/var/lib/hyperion/site-mail"
MAX_BODY_BYTES=1024
MAX_JSONL_BYTES=$((10 * 1024 * 1024))   # rotate at 10 MB
USER_ARG=""

# Parse out our -u flag without consuming the rest (those go to the
# real sendmail unchanged).
declare -a SENDMAIL_ARGS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        -u)
            shift
            USER_ARG="${1:-}"
            ;;
        *)
            SENDMAIL_ARGS+=("$1")
            ;;
    esac
    shift || true
done

# Validate the user arg shape.
if ! [[ "$USER_ARG" =~ ^[a-z][a-z0-9_]{0,31}$ ]]; then
    # Fall through silently — log a stderr breadcrumb but still
    # forward so we don't break email for misconfigured pools.
    echo "site-mail-wrapper: refusing bad -u value: $USER_ARG" >&2
    USER_ARG=""
fi

# Buffer stdin to a temp file so we can both parse + forward.
TMP="$(mktemp /tmp/hyperion-mail.XXXXXX 2>/dev/null || echo /tmp/hyperion-mail.$$)"
trap 'rm -f "$TMP"' EXIT
cat > "$TMP"

# Best-effort logging. Skip the whole block if user arg was rejected
# or the log dir refuses to materialise.
if [ -n "$USER_ARG" ]; then
    if mkdir -p "$LOG_ROOT" 2>/dev/null && chmod 0750 "$LOG_ROOT" 2>/dev/null; then
        LOG="$LOG_ROOT/$USER_ARG.jsonl"

        # Rotate at MAX_JSONL_BYTES so we don't grow unbounded on
        # high-volume sites. Single previous generation kept.
        if [ -f "$LOG" ]; then
            SIZE=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
            if [ "$SIZE" -gt "$MAX_JSONL_BYTES" ]; then
                mv "$LOG" "$LOG.1" 2>/dev/null || true
            fi
        fi

        # Extract headers + body using awk. Headers are everything
        # before the first blank line; body is the rest. We grab
        # From / To / Subject and the first MAX_BODY_BYTES of body.
        AWK_OUT="$(awk -v MAXB="$MAX_BODY_BYTES" '
            BEGIN { in_body = 0; body = ""; from = ""; to = ""; subj = ""; }
            in_body == 0 && /^$/ { in_body = 1; next }
            in_body == 0 {
                if (tolower(substr($0, 1, 5)) == "from:" && from == "") {
                    from = substr($0, 6); sub(/^[ \t]+/, "", from);
                } else if (tolower(substr($0, 1, 3)) == "to:" && to == "") {
                    to = substr($0, 4); sub(/^[ \t]+/, "", to);
                } else if (tolower(substr($0, 1, 8)) == "subject:" && subj == "") {
                    subj = substr($0, 9); sub(/^[ \t]+/, "", subj);
                }
                next
            }
            in_body == 1 {
                if (length(body) < MAXB) {
                    need = MAXB - length(body);
                    line = $0;
                    if (length(line) > need) line = substr(line, 1, need);
                    body = body line "\n";
                }
            }
            END {
                # Emit on three lines so the bash side can split easily.
                print "FROM:" from;
                print "TO:" to;
                print "SUBJ:" subj;
                print "BODY:" body;
            }
        ' "$TMP" 2>/dev/null)"

        FROM=$(echo "$AWK_OUT" | sed -n 's/^FROM://p')
        TO=$(echo "$AWK_OUT" | sed -n 's/^TO://p')
        SUBJ=$(echo "$AWK_OUT" | sed -n 's/^SUBJ://p')
        BODY=$(echo "$AWK_OUT" | awk '/^BODY:/{print substr($0, 6); flag=1; next} flag{print}')

        # JSON-escape using a tiny Python one-liner. python3 is on
        # every Debian 12+ box; if missing, just skip the log step.
        if command -v python3 >/dev/null 2>&1; then
            python3 -c "
import json, sys, time
rec = {
    'ts': int(time.time()),
    'user': sys.argv[1],
    'from': sys.argv[2],
    'to': sys.argv[3],
    'subject': sys.argv[4],
    'body_excerpt': sys.argv[5],
}
print(json.dumps(rec, ensure_ascii=False))
" "$USER_ARG" "$FROM" "$TO" "$SUBJ" "$BODY" >> "$LOG" 2>/dev/null || true
        fi
    fi
fi

# Forward to the real sendmail. If it's missing, fail soft (PHP
# will see a non-zero exit and behave as before).
if [ -x "$REAL_SENDMAIL" ]; then
    exec "$REAL_SENDMAIL" "${SENDMAIL_ARGS[@]}" < "$TMP"
else
    echo "site-mail-wrapper: $REAL_SENDMAIL missing or non-executable" >&2
    exit 75
fi
