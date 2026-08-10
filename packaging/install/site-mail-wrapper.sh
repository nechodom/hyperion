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
#      identical to the pre-wrapper behaviour. That last part is the
#      whole contract, and it is easy to break: PHP's default
#      sendmail_path carries `-t -i`, and pointing the INI at this
#      wrapper drops them. See the SAW_T block below.
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
SAW_T=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        -u)
            shift
            USER_ARG="${1:-}"
            ;;
        -t|-t*)
            # Note it so we don't add a second one below. Matches the
            # bundled forms too (`-ti`), which sendmail accepts.
            SAW_T=1
            SENDMAIL_ARGS+=("$1")
            ;;
        *)
            SENDMAIL_ARGS+=("$1")
            ;;
    esac
    shift || true
done

# PHP's compiled default sendmail_path is "/usr/sbin/sendmail -t -i", and
# setting the INI replaces that string WHOLE — the flags are not merged.
# The pool template points sendmail_path at this wrapper, so unless the
# flags are restored here, the real sendmail is exec'd with no -t.
#
# That is not a degradation, it is total failure: PHP writes the message
# (recipients only in the To: header) to our stdin and passes NO recipient
# on the command line, so without -t sendmail has nobody to deliver to and
# refuses the message. Every wp_mail() on the box — password resets, order
# confirmations, contact forms — fails, and the site sees mail() return
# false with nothing in the mail log to explain it.
#
# -i matters too: without it a body line containing only "." ends the
# message early, silently truncating it.
#
# Restored HERE rather than in the pool template on purpose. This file is
# reinstalled by update.sh on every node, so the fix reaches sites that
# already have a pool written with the old value, without rewriting and
# reloading every FPM pool on the box.
if [ "$SAW_T" -eq 0 ]; then
    SENDMAIL_ARGS=(-t -i ${SENDMAIL_ARGS[@]+"${SENDMAIL_ARGS[@]}"})
fi

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
    # NOTE the absence of a chmod here. This script runs as the SITE USER
    # (php-fpm execs it), and an earlier version gated the whole block on
    # `mkdir -p && chmod 0750` — chmod on a root-owned directory fails for
    # everyone but root, so the gate failed and the log was silently,
    # permanently empty on every node where update.sh (root) had created
    # the directory first. The mail still went out; only the evidence
    # vanished. The directory is 1777+sticky (update.sh), each user's
    # jsonl is 0600 via the umask below — tenants cannot read each
    # other's mail metadata, and nobody can delete another's file.
    umask 077
    if mkdir -p -m 1777 "$LOG_ROOT" 2>/dev/null; then
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
    # Hand the message over on an already-open descriptor and unlink the
    # file first. `exec` replaces this shell, which discards the EXIT trap
    # above — so every message used to leave a copy in /tmp forever: a
    # full body per send, 0600 and owned by the site user, growing without
    # bound on a busy box. The open descriptor keeps the data alive for
    # sendmail even though the name is already gone.
    exec 3< "$TMP"
    rm -f "$TMP"
    exec "$REAL_SENDMAIL" "${SENDMAIL_ARGS[@]}" <&3
else
    echo "site-mail-wrapper: $REAL_SENDMAIL missing or non-executable" >&2
    exit 75
fi
