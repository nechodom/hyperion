# Hyperion self-service import — runs on the SOURCE panel box, as root.
#
# This file is an ASSET, not a Rust format! string. The three values it needs
# ($T token, $B base URL, $K panel kind) are prepended as a generated prelude,
# so nothing in this body has to survive `{{`/`}}` doubling. That matters: a
# brace-escaping slip in a format! string compiles cleanly and ships a
# syntactically invalid script whose first reader is an operator running it as
# root on a customer's production server. As a real file it is checked by
# `bash -n` in CI.
#
# The shape of the run:
#   1. fetch + verify the exporter binary
#   2. report the site list, wait for the operator to pick in the panel
#   3. measure the selection
#   4. DETACH and pack, then upload in resumable chunks
#   5. attach a live progress bar only when the selection is small
#
# Detaching is unconditional. The operator asked for "background when it's big",
# but a 2.9 GB export dying with their SSH session is the same lost hour as a
# 3.1 GB one, so the size threshold decides only whether a viewer is ATTACHED.

set -euo pipefail

RUN_DIR="${HYPERION_EXPORT_DIR:-/var/lib/hyperion-export}"
RUN="$RUN_DIR/run"
JOURNAL="$RUN/journal.ndjson"
BUNDLE="$RUN/bundle.tar"
CHUNK="$RUN/chunk.bin"
CURLCFG="$RUN/upload.curl"
AUTHCFG="$RUN/auth.curl"
SELCFG="$RUN/selection.curl"
RESP="$RUN/response.txt"
STATUS_CMD="sudo $RUN_DIR/status"
# 64 MiB. Halved on a 413 so a proxy stricter than Hyperion's own nginx can
# still be satisfied without a re-pack.
CHUNK_BYTES=67108864
FOREGROUND_MAX=3221225472

say() { printf '[hyperion] %s\n' "$*" >&2; }
die() { printf '[hyperion] %s\n' "$*" >&2; exit 1; }

# --- the run directory is root's, and it holds plaintext database dumps -------
# Root is about to write into a path an environment variable chose. If any
# ancestor is a symlink, or is writable by someone other than root, a local user
# on this box can aim those writes wherever they like. Validate the whole chain
# before creating anything — the same rule the panel applies to tenant trees.
guard_dir() {
  local p="$1" cur=""
  case "$p" in
    /*) : ;;
    *) die "HYPERION_EXPORT_DIR must be an absolute path (got '$p')." ;;
  esac
  local IFS=/
  # shellcheck disable=SC2086
  set -- $p
  unset IFS
  for seg in "$@"; do
    [ -z "$seg" ] && continue
    cur="$cur/$seg"
    if [ -L "$cur" ]; then
      die "$cur is a symlink. Refusing to write database dumps through it."
    fi
    if [ -e "$cur" ]; then
      local owner perms
      owner=$(stat -c %u "$cur" 2>/dev/null || echo 0)
      perms=$(stat -c %a "$cur" 2>/dev/null || echo 700)
      [ "$owner" = "0" ] || die "$cur is not owned by root (uid $owner). Refusing."
      # `stat -c %a` may print three digits or four (a set-uid/sticky bit adds
      # one), so normalise to the last three before looking at owner/group/other.
      # The first version tested `*[2367]` with no trailing `*`, which anchors on
      # the LAST character — it caught 777 and 707 but waved 770 and 775
      # through, and a group-writable ancestor is just as good a foothold as a
      # world-writable one.
      perms="${perms: -3}"
      case "${perms#?}" in
        *[2367]*) die "$cur is group- or world-writable ($perms). Refusing." ;;
      esac
    fi
  done
}

guard_dir "$RUN_DIR"
# umask BEFORE mkdir, not chmod after: between a default-umask mkdir and the
# chmod there is a window in which this directory — which is about to hold every
# selected site's database in plaintext — is world-readable.
umask 077
mkdir -p "$RUN"
chmod 700 "$RUN_DIR" "$RUN"

# --- one run at a time -------------------------------------------------------
# An impatient second paste of the one-liner must not start a competing pack
# against the same directory.
if command -v flock >/dev/null 2>&1; then
  exec 9>"$RUN/lock"
  if ! flock -n 9; then
    say "An export is already running on this box."
    say "Check on it with:  $STATUS_CMD"
    exit 0
  fi
else
  # A stripped image without util-linux. Say what is not being guaranteed
  # rather than letting `set -e` kill the run with a bare "flock: not found".
  say "flock is not installed, so two pastes of this command could race."
  say "Check nothing is already running:  $STATUS_CMD"
fi

TMP=""; LIST=""
cleanup() { [ -n "$TMP" ] && rm -f "$TMP"; [ -n "$LIST" ] && rm -f "$LIST"; return 0; }
trap cleanup EXIT
TMP="$(mktemp)"; LIST="$(mktemp)"

# --- 1. the exporter binary --------------------------------------------------
say "downloading exporter from $B …"
ARCH="$(uname -m)"
curl -fsSL "$B/import/agent-bin/$T?arch=$ARCH" -o "$TMP"

if [ ! -s "$TMP" ]; then
  say "the exporter downloaded as an EMPTY file."
  say "On the Hyperion box: ls -l /usr/local/bin/hyperion-export"
  die "and re-run update.sh if it is missing or 0 bytes."
fi
if command -v file >/dev/null 2>&1; then
  DESC="$(file -b "$TMP" 2>/dev/null || true)"
  case "$DESC" in
    *ELF*) : ;;
    *) say "what downloaded is not a Linux executable: $DESC"
       die "The first bytes were: $(head -c 120 "$TMP" | tr -d '\0')" ;;
  esac
  THIS_ARCH="$(uname -m)"
  case "$THIS_ARCH:$DESC" in
    x86_64:*x86-64*|aarch64:*aarch64*|armv7*:*ARM*|i?86:*Intel\ 80386*) : ;;
    *) say "the exporter is for a different CPU than this machine."
       say "this box: $THIS_ARCH — binary: $DESC"
       die "Run update.sh on the Hyperion box so it has both, then re-run." ;;
  esac
fi
chmod +x "$TMP"

# The panel and the exporter binary ship together but are installed separately,
# so a Hyperion box updated only partly serves an exporter that does not know
# the flags this script needs. Detect that here with a sentence, rather than
# letting clap fail deep inside a detached run nobody is watching.
if ! "$TMP" --help 2>&1 | grep -q -- --estimate; then
  say "The hyperion-export binary on your Hyperion box is older than the panel."
  die "Run update.sh there, then re-run this command."
fi

# Keep the binary for the detached phase — $TMP is removed on exit.
cp "$TMP" "$RUN/hyperion-export"
chmod 700 "$RUN/hyperion-export"
BIN="$RUN/hyperion-export"

# --- 2. report and wait ------------------------------------------------------
say "scanning $K and reporting the sites to Hyperion …"
"$BIN" --kind "$K" --list --json > "$LIST"
curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @"$LIST" \
  "$B/import/manifest/$T" >/dev/null
# The selection poll runs up to 2640 times, and the token was in its URL every
# time — 2640 lines of the panel's nginx access log carrying a live credential.
# Same reasoning as the chunk loop: URL and header live in a 0600 config.
umask 077
cat > "$SELCFG" <<SELEOF
url = "$B/import/selection"
header = "Authorization: Bearer $T"
SELEOF
chmod 600 "$SELCFG"

say "reported. Open Hyperion -> Import, tick the sites you want, click Import. Waiting…"

SEL=""
for _i in {1..2640}; do
  R="$(curl -fsS -K "$SELCFG" || true)"
  case "$R" in
    pending|"") sleep 5 ;;
    cancelled) say "cancelled (or token expired) in the panel."; exit 0 ;;
    # A selection is a comma-separated list of domains. Matching that shape
    # rather than accepting anything non-empty: a proxy's HTML error page also
    # arrives with HTTP 200. Non-ASCII is allowed through because an IDN domain
    # is a real domain — the shape guard rejects whitespace and markup, which is
    # what actually distinguishes a site list from an error page.
    *'<'*|*'>'*|*' '*|*'	'*) say "unexpected reply from Hyperion — not a site list:"
                        printf '%s\n' "$R" | head -c 200 >&2; exit 1 ;;
    *) SEL="$R"; break ;;
  esac
done
[ -n "$SEL" ] || die "timed out waiting for a selection."

# --- 3. measure --------------------------------------------------------------
say "measuring the selected sites (reading directory metadata — a site with"
say "hundreds of thousands of files can take a minute) …"
EST="$("$BIN" --kind "$K" --only "$SEL" --estimate)" || die "could not measure the selection."
# Plain shell parsing of two known integer fields — no jq on a stranger's box.
INPUT_BYTES="$(printf '%s' "$EST" | sed -n 's/.*"input_bytes":\([0-9]*\).*/\1/p')"
FREE_BYTES="$(printf '%s' "$EST" | sed -n 's/.*"free_bytes":\([0-9]*\).*/\1/p')"
NEED_BYTES="$(printf '%s' "$EST" | sed -n 's/.*"needed_bytes":\([0-9]*\).*/\1/p')"
FITS="$(printf '%s' "$EST" | sed -n 's/.*"fits":\([a-z]*\).*/\1/p')"
MODE="$(printf '%s' "$EST" | sed -n 's/.*"mode":"\([a-z]*\)".*/\1/p')"
[ -n "$MODE" ] || MODE=background

gb() { awk "BEGIN{printf \"%.1f GB\", $1/1000000000}"; }

if [ -n "$INPUT_BYTES" ]; then
  say "selected sites hold $(gb "$INPUT_BYTES") of files."
else
  say "could not measure every site — running detached, which is the safe choice."
fi

# REFUSE HERE, not an hour into a detached run.
#
# The packer has always had this check, but it runs after the worker has been
# spawned: the operator got an exit code, a status line saying "not enough free
# disk", and a log file to go read — long after they had walked away. The same
# arithmetic is available before anything is written, so it is applied while
# they are still watching and can act on it.
if [ "$FITS" = "false" ] && [ -n "$NEED_BYTES" ] && [ -n "$FREE_BYTES" ]; then
  say ""
  say "NOT ENOUGH DISK on this server to pack that selection."
  say "  free:   $(gb "$FREE_BYTES")"
  say "  needed: $(gb "$NEED_BYTES")  (the site files, ~20% for database dumps,"
  say "          counted twice because the staged tree is packed into an archive"
  say "          beside itself, plus 512 MB of headroom)"
  say ""
  say "Nothing has been packed and nothing was changed. Either:"
  say "  • pick fewer sites in Hyperion and re-run this command — the site list"
  say "    there shows each site's size, largest first, so you can take the"
  say "    biggest ones in their own batch; or"
  say "  • free up space; or"
  say "  • point the export at a bigger filesystem and re-run:"
  say "      HYPERION_EXPORT_DIR=/path/with/room TMPDIR=/path/with/room \\"
  say "        curl -fsSL \"$B/import/agent/\$T\" | sudo -E bash"
  say ""
  say "Sites can be imported in several batches — each one is independent, and"
  say "Hyperion skips a site it has already imported."
  exit 1
fi

# --- 4. write the credential where it is not on argv -------------------------
# /proc/<pid>/cmdline is world-readable and the tenants on a panel box are local
# users, so the token must not be a curl argument. It must not be in the URL
# either: this loop makes hundreds of requests, and a URL lands in the panel's
# nginx access log every time. Both go in a 0600 config file instead.
umask 077
cat > "$CURLCFG" <<CURLEOF
url = "$B/import/upload/chunk"
header = "Authorization: Bearer $T"
header = "Content-Type: application/octet-stream"
CURLEOF
# The same credential, without a url, for the requests that need their own.
# /proc/<pid>/cmdline is world-readable and the tenants on a panel box are local
# users, so `-H "Authorization: Bearer $T"` on the command line hands the token
# to anyone running `ps` for as long as curl lives. The chunk loop already
# avoided that through $CURLCFG; begin, commit and the packing heartbeat did not.
cat > "$AUTHCFG" <<AUTHEOF
header = "Authorization: Bearer $T"
header = "Content-Type: text/plain"
AUTHEOF
printf '%s' "$T" > "$RUN/token"
chmod 600 "$CURLCFG" "$AUTHCFG" "$RUN/token"

# The status helper the operator runs later. It needs no arguments and no memory
# of what was typed an hour ago.
cat > "$RUN_DIR/status" <<STATUSEOF
#!/bin/sh
exec "$BIN" --status --state-file "$JOURNAL" "\$@"
STATUSEOF
chmod 700 "$RUN_DIR/status"

# --- 5. detach and run -------------------------------------------------------
cat > "$RUN/worker.sh" <<'WORKEREOF'
#!/bin/bash
set -uo pipefail
. "$1"

now() { date +%s; }
jrn() { printf '%s\n' "$1" >> "$JOURNAL"; }
fail() { jrn "{\"k\":\"fail\",\"t\":$(now),\"why\":$(json_str "$1")}"; exit 1; }
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g')"; }

# Whatever kills this process, the journal must end with a terminal event —
# otherwise `--status` shows a live-looking phase for a run that is gone. The
# pid check in the status renderer is the backstop; this is the good path.
# Recording the outcome and stopping are one act. Without the `exit` the trap
# wrote a terminal `fail` and let the run continue, so `--status` reported a
# failure for an export that was still going — and `progress::read` takes the
# last outcome it sees.
trap 'jrn "{\"k\":\"fail\",\"t\":$(now),\"why\":\"the export was interrupted\"}"; exit 1' HUP TERM INT

TOKEN="$(cat "$RUN/token")"
# Cosmetic only — it proves a journal belongs to the token being resumed.
# An empty value on a box without coreutils is harmless.
FP="$(printf '%s' "$TOKEN" | sha256sum 2>/dev/null | cut -c1-8 || true)"

jrn "{\"k\":\"start\",\"t\":$(now),\"token_fp\":\"$FP\",\"pid\":$$,\"sites_total\":$SITES,\"input_total\":${INPUT_JSON}}"

# --- pack ---------------------------------------------------------------------
# Skipped when a bundle from an earlier attempt is already sealed: a resumed run
# must not re-dump every database, which is the expensive half.
if [ ! -s "$BUNDLE" ] || ! grep -q '"k":"bundle"' "$JOURNAL" 2>/dev/null; then
  rm -f "$BUNDLE"
  # Tell the panel where the packing is, every 15s, for as long as it runs.
  # Without this the Transfers table shows nothing at all for what is usually
  # the longest phase, and an operator cannot tell a working export from a dead
  # one. Killed the moment packing ends.
  (
    while :; do
      sleep 15
      SD=$(grep -o '"k":"site"[^}]*' "$JOURNAL" 2>/dev/null | tail -1 | sed -n 's/.*"done":\([0-9]*\).*/\1/p')
      ID=$(grep -o '"k":"site"[^}]*' "$JOURNAL" 2>/dev/null | tail -1 | sed -n 's/.*"input_done":\([0-9]*\).*/\1/p')
      SK=$(grep -c '"k":"skip"' "$JOURNAL" 2>/dev/null || echo 0)
      curl -sS -o /dev/null -K "$AUTHCFG" \
        --data-binary "phase packing
sites_total $SITES
sites_done ${SD:-0}
input_done ${ID:-0}
skipped ${SK:-0}
" "$B/import/progress" || true
    done
  ) &
  BEAT=$!
  "$BIN" --kind "$K" --only "$SEL" --out "$BUNDLE" --journal "$JOURNAL" >/dev/null 2>>"$RUN/pack.log"
  RC=$?
  kill "$BEAT" 2>/dev/null || true
  if [ $RC -ne 0 ]; then
    case $RC in
      3) fail "this box is not a CloudPanel or HestiaCP server" ;;
      4) fail "not enough free disk to pack the export — see $RUN/pack.log" ;;
      *) fail "packing failed (exit $RC) — see $RUN/pack.log" ;;
    esac
  fi
fi

SIZE="$(grep -o '"k":"bundle"[^}]*' "$JOURNAL" | tail -1 | sed -n 's/.*"bytes":\([0-9]*\).*/\1/p')"
SHA="$(grep -o '"k":"bundle"[^}]*' "$JOURNAL" | tail -1 | sed -n 's/.*"sha256":"\([0-9a-f]*\)".*/\1/p')"
[ -n "$SIZE" ] && [ -n "$SHA" ] || fail "the bundle was packed but not sealed — see $RUN/pack.log"

# Re-state the seal for THIS attempt. The status reader treats each `start` as
# a fresh attempt and drops everything before it — otherwise a resume would
# inherit the previous run's failure — so a resume that skipped packing has to
# say again what bundle it is uploading, or `--status` would render "packing"
# for the whole upload.
jrn "{\"k\":\"bundle\",\"t\":$(now),\"bytes\":$SIZE,\"sha256\":\"$SHA\"}"

# --- upload -------------------------------------------------------------------
# `begin` is idempotent and is how a resume starts: it answers with the offset
# the server already holds.
#
# `inflate` is the measured, UNCOMPRESSED size of the selected docroots (from
# the --estimate pass above). The panel needs it because the bundle it is about
# to receive is compressed: 13 GB on the wire is routinely 30 GB+ on disk once
# each site is unpacked into its hosting tree. It is sent only when it was
# actually measured — an omitted figure makes the panel skip that check rather
# than refuse a transfer on a guess.
begin() {
  curl -sS -o "$RESP" -w '%{http_code}' -K "$AUTHCFG" \
    --data-binary "bytes $SIZE
sha256 $SHA
${INPUT_BYTES:+inflate $INPUT_BYTES
}" "$B/import/upload/begin"
}
CODE="$(begin)" || fail "could not reach Hyperion to start the upload"
[ "$CODE" = "200" ] || fail "Hyperion refused the upload ($CODE): $(head -c 400 "$RESP")"
OFF="$(sed -n 's/^offset \([0-9]*\)$/\1/p' "$RESP")"
[ -n "$OFF" ] || OFF=0

upload_from() {
    OFF="$1"
    BACKOFF=2
    while [ "$OFF" -lt "$SIZE" ]; do
    dd if="$BUNDLE" of="$CHUNK" bs=1048576 iflag=skip_bytes,count_bytes \
       skip="$OFF" count="$CHUNK_BYTES" status=none 2>/dev/null || \
       fail "could not read the bundle at offset $OFF"
    # `-T` on a REGULAR FILE, never `-T -`: that gives a real Content-Length, so
    # nginx and axum can refuse an oversized chunk before a single byte flows.
    # Streaming from a pipe is what turned the original 2 GiB refusal into a
    # broken pipe and a SIGPIPE'd tar with no usable error.
    # No `-f`: the server's body carries the diagnosis, and -f throws it away.
    CODE="$(curl -sS -o "$RESP" -w '%{http_code}' -K "$CURLCFG" \
            -H "X-Hyperion-Offset: $OFF" -T "$CHUNK" --max-time 900 || true)"
    case "$CODE" in
      200)
        OFF="$(sed -n 's/^offset \([0-9]*\)$/\1/p' "$RESP")"
        [ -n "$OFF" ] || fail "Hyperion accepted a chunk without saying where it got to"
        jrn "{\"k\":\"upload\",\"t\":$(now),\"off\":$OFF}"
        BACKOFF=2
        ;;
      409)
        # The server is always authoritative about the offset. This is the whole
        # resume negotiation: seek to where it actually is and continue.
        OFF="$(sed -n 's/^offset \([0-9]*\)$/\1/p' "$RESP")"
        [ -n "$OFF" ] || fail "offset conflict with no offset in the reply"
        jrn "{\"k\":\"retry\",\"t\":$(now),\"why\":\"resynced to offset $OFF\",\"wait\":0}"
        ;;
      410) fail "the transfer was cancelled in the Hyperion panel" ;;
      413)
        if [ "$CHUNK_BYTES" -gt 8388608 ]; then
          CHUNK_BYTES=$((CHUNK_BYTES / 2))
          jrn "{\"k\":\"retry\",\"t\":$(now),\"why\":\"chunk too large, trying $CHUNK_BYTES\",\"wait\":0}"
        else
          fail "something between this box and Hyperion refuses even 8 MiB uploads"
        fi
        ;;
      408|429|500|502|503|504|000)
        jrn "{\"k\":\"retry\",\"t\":$(now),\"why\":\"HTTP $CODE\",\"wait\":$BACKOFF}"
        sleep "$BACKOFF"
        [ "$BACKOFF" -lt 120 ] && BACKOFF=$((BACKOFF * 3))
        ;;
      *) fail "Hyperion refused the upload ($CODE): $(head -c 400 "$RESP")" ;;
    esac
  done
}

upload_from "$OFF"

commit() {
  curl -sS -o "$RESP" -w '%{http_code}' -K "$AUTHCFG" \
    --data-binary "bytes $SIZE
sha256 $SHA
" "$B/import/upload/commit" || true
}
CODE="$(commit)"
if [ "$CODE" = "409" ]; then
  # The panel holds a different number of bytes than we sent, or the digest did
  # not match and it discarded the partial. Both replies carry the offset to
  # continue from, and the panel's own message says the upload will restart —
  # so honour that instead of failing, which left the operator with a packed
  # bundle and a transfer that would never finish. Exactly one retry: a second
  # mismatch is corruption that repeating cannot fix.
  OFF="$(sed -n 's/^offset \([0-9]*\)$/\1/p' "$RESP")"
  [ -n "$OFF" ] || fail "Hyperion rejected the bundle without saying where to resume"
  jrn "{\"k\":\"retry\",\"t\":$(now),\"why\":\"commit disagreed, re-uploading from $OFF\",\"wait\":0}"
  upload_from "$OFF"
  CODE="$(commit)"
fi
[ "$CODE" = "200" ] || fail "Hyperion rejected the finished bundle ($CODE): $(head -c 400 "$RESP")"
JOB="$(sed -n 's/^job \(.*\)$/\1/p' "$RESP")"
jrn "{\"k\":\"done\",\"t\":$(now),\"job\":$(json_str "$JOB")}"
# The bundle is on the other side now; it is the largest thing on this disk and
# it holds every selected site's database in plaintext.
rm -f "$BUNDLE" "$CHUNK" "$RUN/token" "$CURLCFG" "$AUTHCFG"
WORKEREOF
chmod 700 "$RUN/worker.sh"

SITES="$(printf '%s' "$SEL" | tr ',' '\n' | grep -c . || echo 0)"
if [ -n "$INPUT_BYTES" ]; then INPUT_JSON="$INPUT_BYTES"; else INPUT_JSON=null; fi
cat > "$RUN/env" <<ENVEOF
RUN='$RUN'
JOURNAL='$JOURNAL'
BUNDLE='$BUNDLE'
CHUNK='$CHUNK'
CURLCFG='$CURLCFG'
AUTHCFG='$AUTHCFG'
RESP='$RESP'
BIN='$BIN'
B='$B'
K='$K'
SEL='$SEL'
SITES=$SITES
INPUT_JSON=$INPUT_JSON
INPUT_BYTES='$INPUT_BYTES'
CHUNK_BYTES=$CHUNK_BYTES
ENVEOF
chmod 600 "$RUN/env"

# The journal is APPENDED to, never truncated.
#
# Truncating it here undid the whole resume: the worker's only test for "is a
# bundle already packed" is `grep -q '"k":"bundle"' "$JOURNAL"`, so a blanked
# journal made every re-run re-dump every database — the expensive half — while
# `--status` went on telling the operator "packing is not repeated". Several
# attempts in one file is the case `progress::read` was written for: each
# `start` event resets the fold, dropping the previous attempt's outcome and
# samples.
#
# It IS cleared when the token changes, because then the bundle beside it
# belongs to a different transfer and must not be resumed into.
# CREATE the journal before reading it, and swallow the read's status.
#
# The previous order read it first, and on a box where no export had ever run
# `sed` exited non-zero on the missing file. Under this script's `set -euo
# pipefail` that status propagates out of the command substitution and out of
# the assignment, so the script died SILENTLY right here — after the measuring
# line and before "export started in the background". The operator saw a
# terminal that simply stopped, and the panel went on saying "waiting for the
# source to export…" because the worker had never been spawned.
#
# `bash -n` cannot see this: the line is syntactically perfect. That is why CI
# now runs shellcheck as well.
[ -e "$JOURNAL" ] || : > "$JOURNAL"
chmod 600 "$JOURNAL"

FP_NOW="$(printf '%s' "$T" | sha256sum 2>/dev/null | cut -c1-8 || true)"
FP_WAS="$(sed -n 's/.*"k":"start".*"token_fp":"\([0-9a-f]*\)".*/\1/p' "$JOURNAL" | tail -1 || true)"
if [ -n "$FP_WAS" ] && [ "$FP_WAS" != "$FP_NOW" ]; then
  say "this is a different transfer than the one in $RUN — starting clean."
  rm -f "$BUNDLE" "$CHUNK"
  : > "$JOURNAL"
fi

if command -v setsid >/dev/null 2>&1; then
  setsid nohup "$RUN/worker.sh" "$RUN/env" >>"$RUN/worker.log" 2>&1 &
else
  # A stripped container image without util-linux. Say so rather than let the
  # operator believe a guarantee that is not being made.
  say "setsid is not installed on this box, so the export may not survive"
  say "closing this session. Install util-linux, or keep the session open."
  nohup "$RUN/worker.sh" "$RUN/env" >>"$RUN/worker.log" 2>&1 &
fi
WORKER_PID=$!
say "export started in the background (pid $WORKER_PID)."
say "It keeps running if this session drops."
say "Check on it any time with:  $STATUS_CMD"

# --- 6. attach a viewer, for a small export ----------------------------------
if [ "$MODE" = "foreground" ] && [ "${INPUT_BYTES:-0}" -lt "$FOREGROUND_MAX" ]; then
  say "this selection is small, so here is live progress. Ctrl-C detaches —"
  say "it does NOT cancel the export."
  trap 'printf "\n"; say "detached. The export is still running."; say "Check on it with: $STATUS_CMD"; exit 0' INT
  "$BIN" --watch --state-file "$JOURNAL" || true
else
  say "this selection is large, so it runs detached."
  say "Progress also shows in Hyperion under Import."
fi
