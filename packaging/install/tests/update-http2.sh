#!/usr/bin/env bash
# Tests for update.sh's HTTP/2 vhost heal — the step that rewrites vhosts into
# the HTTP/2 spelling this box's nginx understands.
#
# Like update-wait.sh, this lifts the block between the `>>> http2-heal` /
# `<<< http2-heal` markers and runs it against a fake nginx tree with `nginx`
# and `systemctl` stubbed. The rule under test has to agree with the agent's
# (crates/hyperion-adapters/src/nginx.rs, http2_uses_directive): when it did
# not, every update undid the vhosts the agent had just rendered.
#
#   packaging/install/tests/update-http2.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
UPDATE_SH="$ROOT/packaging/install/update.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sed -n '/^# >>> http2-heal$/,/^# <<< http2-heal$/p' "$UPDATE_SH" > "$TMP/block.sh"
[[ -s "$TMP/block.sh" ]] || { echo "markers not found in update.sh" >&2; exit 1; }

pass=0; failed=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { failed=$((failed + 1)); printf '  FAIL %s\n' "$1"; [[ -n "${2:-}" ]] && printf '%s\n' "$2" | sed 's/^/       | /'; }

# The two shapes the agent renders (nginx-vhost.conf.j2), suspended-site
# server block included: two TLS server blocks per file.
modern_vhost() {
  cat <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name x.cz;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name x.cz;
    location / { try_files $uri =404; }
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name www.x.cz;
    return 301 https://x.cz$request_uri;
}
EOF
}
legacy_vhost() {
  cat <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name x.cz;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name x.cz;
    location / { try_files $uri =404; }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.x.cz;
    return 301 https://x.cz$request_uri;
}
EOF
}

# Fresh fake /etc/nginx. Prints its path.
new_tree() {
  local d="$TMP/nginx.$RANDOM$RANDOM"
  mkdir -p "$d/sites-available" "$d/sites-enabled"
  printf '%s' "$d"
}

# Run the block. NGX_VER = what `nginx -v` reports ("" = garbage output);
# NGX_T = "ok" | "fail" | "fail-after" (passes until the first edit lands).
run_block() {
  local dir="$1"
  (
    export HYPERION_NGINX_DIR="$dir"
    CLEANUP_PATHS=()
    log()  { printf 'LOG: %s\n' "$*"; }
    warn() { printf 'WARN: %s\n' "$*"; }
    systemctl() { :; }
    nginx() {
      case "$1" in
        -v) if [[ -n "${NGX_VER:-}" ]]; then echo "nginx version: nginx/$NGX_VER" >&2
            else echo "nginx: something odd" >&2; fi ;;
        -t) case "${NGX_T:-ok}" in
              ok)   return 0 ;;
              fail) return 1 ;;
              fail-after)
                # Pass while the tree is still the original.
                diff -r "$dir" "$TMP/orig" >/dev/null 2>&1 ;;
            esac ;;
      esac
    }
    # shellcheck disable=SC1091
    source "$TMP/block.sh"
    for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do rm -rf -- "$p"; done
    echo "rc=0"
  ) 2>&1
}

# The shape a correct modern-nginx file has: no `http2` listen parameter, and
# exactly one `http2 on;` right after the listens of each TLS server block.
check_modern() { diff <(modern_vhost) "$1" >/dev/null; }
check_legacy() { diff <(legacy_vhost) "$1" >/dev/null; }

echo "update.sh HTTP/2 heal"

# 1. nginx ≥ 1.25.1, legacy file → directive form, identical to what the agent renders.
d="$(new_tree)"; legacy_vhost > "$d/sites-available/x.cz.conf"
out="$(NGX_VER=1.26.3 run_block "$d")"
if check_modern "$d/sites-available/x.cz.conf" && grep -q 'HTTP/2 spelling fixed in 1 vhost' <<<"$out"; then
  ok "nginx 1.26: listen … http2 → http2 on; (matches the agent's render)"
else
  bad "nginx 1.26: legacy file not converted" "$out
$(diff <(modern_vhost) "$d/sites-available/x.cz.conf" || true)"
fi

# 2. nginx ≥ 1.25.1, already-modern file → untouched and silent. This is the
#    regression: the old heal stripped `http2 on;` here on every update.
d="$(new_tree)"; modern_vhost > "$d/sites-available/x.cz.conf"
out="$(NGX_VER=1.26.3 run_block "$d")"
if check_modern "$d/sites-available/x.cz.conf" && ! grep -q 'LOG\|WARN' <<<"$out"; then
  ok "nginx 1.26: http2 on; is left alone, nothing logged"
else
  bad "nginx 1.26: modern file was touched" "$out"
fi

# 3. Exactly 1.25.1 counts as modern; 1.25.0 does not.
d="$(new_tree)"; modern_vhost > "$d/sites-available/x.cz.conf"
NGX_VER=1.25.1 run_block "$d" >/dev/null
if check_modern "$d/sites-available/x.cz.conf"; then ok "nginx 1.25.1 keeps http2 on;"
else bad "nginx 1.25.1 stripped http2 on;"; fi
d="$(new_tree)"; modern_vhost > "$d/sites-available/x.cz.conf"
NGX_VER=1.25.0 run_block "$d" >/dev/null
if check_legacy "$d/sites-available/x.cz.conf"; then ok "nginx 1.25.0 gets the listen form"
else bad "nginx 1.25.0 kept http2 on;" "$(cat "$d/sites-available/x.cz.conf")"; fi

# 4. nginx < 1.25.1 (Debian 12), directive file → listen form, port 80 untouched.
d="$(new_tree)"; modern_vhost > "$d/sites-available/x.cz.conf"
out="$(NGX_VER=1.22.1 run_block "$d")"
if check_legacy "$d/sites-available/x.cz.conf" && grep -q 'HTTP/2 spelling fixed' <<<"$out"; then
  ok "nginx 1.22: http2 on; → listen … ssl http2"
else
  bad "nginx 1.22: directive file not converted" "$out
$(diff <(legacy_vhost) "$d/sites-available/x.cz.conf" || true)"
fi

# 5. nginx < 1.25.1, legacy file → untouched.
d="$(new_tree)"; legacy_vhost > "$d/sites-available/x.cz.conf"
out="$(NGX_VER=1.22.1 run_block "$d")"
if check_legacy "$d/sites-available/x.cz.conf" && ! grep -q 'LOG\|WARN' <<<"$out"; then
  ok "nginx 1.22: listen form is left alone"
else
  bad "nginx 1.22: legacy file was touched" "$out"
fi

# 6. Unknown version → the form every nginx accepts (same as the agent).
d="$(new_tree)"; modern_vhost > "$d/sites-available/x.cz.conf"
NGX_VER="" run_block "$d" >/dev/null
if check_legacy "$d/sites-available/x.cz.conf"; then ok "unknown nginx version gets the listen form"
else bad "unknown nginx version kept http2 on;"; fi

# 7. A sites-enabled symlink stays a symlink; its target is healed once.
d="$(new_tree)"; legacy_vhost > "$d/sites-available/x.cz.conf"
ln -s "$d/sites-available/x.cz.conf" "$d/sites-enabled/x.cz.conf"
out="$(NGX_VER=1.26.3 run_block "$d")"
if [[ -L "$d/sites-enabled/x.cz.conf" ]] && check_modern "$d/sites-available/x.cz.conf" \
   && [[ "$(grep -c '^LOG:     ' <<<"$out")" == 1 ]]; then
  ok "sites-enabled symlink kept, target healed once"
else
  bad "symlink handling" "$out
$(ls -l "$d/sites-enabled")"
fi

# 8. A real file in sites-enabled (no symlink) is healed too.
d="$(new_tree)"; legacy_vhost > "$d/sites-enabled/hand.conf"
NGX_VER=1.26.3 run_block "$d" >/dev/null
if check_modern "$d/sites-enabled/hand.conf"; then ok "regular file in sites-enabled healed"
else bad "regular file in sites-enabled not healed"; fi

# 9. nginx -t passed before and fails after → every file restored byte-for-byte.
d="$(new_tree)"; legacy_vhost > "$d/sites-available/a.conf"; legacy_vhost > "$d/sites-available/b.conf"
rm -rf "$TMP/orig"; cp -R "$d" "$TMP/orig"
out="$(NGX_VER=1.26.3 NGX_T=fail-after run_block "$d")"
if diff -r "$d" "$TMP/orig" >/dev/null && grep -q 'put every vhost back unchanged' <<<"$out"; then
  ok "failed nginx -t after the change restores every file"
else
  bad "rollback on failed nginx -t" "$out"
fi

# 10. nginx -t already failing (the Debian 12 `unknown directive` case) → keep the fix.
d="$(new_tree)"; modern_vhost > "$d/sites-available/x.cz.conf"
out="$(NGX_VER=1.22.1 NGX_T=fail run_block "$d")"
if check_legacy "$d/sites-available/x.cz.conf" && grep -q 'it failed before too' <<<"$out"; then
  ok "already-broken config: fix kept, warned"
else
  bad "already-broken config" "$out"
fi

# 11. A file mixing both spellings is somebody's hand edit — not touched.
d="$(new_tree)"
{ legacy_vhost; printf 'server {\n    listen 8443 ssl;\n    http2 on;\n}\n'; } > "$d/sites-available/mixed.conf"
cp "$d/sites-available/mixed.conf" "$TMP/mixed.orig"
NGX_VER=1.26.3 run_block "$d" >/dev/null
if cmp -s "$d/sites-available/mixed.conf" "$TMP/mixed.orig"; then ok "mixed file left alone"
else bad "mixed file was rewritten"; fi

# 12. Owner/mode survive (written in place, not replaced).
d="$(new_tree)"; legacy_vhost > "$d/sites-available/x.cz.conf"; chmod 0640 "$d/sites-available/x.cz.conf"
NGX_VER=1.26.3 run_block "$d" >/dev/null
mode="$(stat -c %a "$d/sites-available/x.cz.conf" 2>/dev/null || stat -f %Lp "$d/sites-available/x.cz.conf")"
if [[ "$mode" == 640 ]]; then ok "file mode preserved"; else bad "file mode changed to $mode"; fi

echo
echo "$pass passed, $failed failed"
(( failed == 0 ))
