#!/bin/bash
# End-to-end check of the site scanner on a real machine: real systemd, real
# WordPress, real wordpress.org, real MariaDB, real clamscan. For a throwaway VM
# only: it creates users, drops databases and edits /etc/hosts.
#
#   sudo packaging/dev/sitescan-e2e.sh [A B C D E F G H]     (default: all)
#
# Needs a release build first, with its target dir in E2E_TARGET:
#   cargo build --release -p hyperion-agent
#   cargo build --release -p hyperion-adapters --examples
# (Two commands: `--examples` narrows the whole build to examples.)
#
# Re-runnable: each section rebuilds what it needs. Prints a pass/fail table and
# keeps raw JSON under $WORK/out.
set -u -o pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
TARGET=${E2E_TARGET:-/var/tmp/e2e/target}
AGENT=$TARGET/release/hyperion-agent
E2E=$TARGET/release/examples/sitescan_e2e
RFP=$TARGET/release/examples/rule_false_positives
FIX=$REPO/crates/hyperion-adapters/tests/fixtures/sitescan
WORK=${E2E_WORK:-/var/tmp/e2e/work}
OUT=$WORK/out
DL=$WORK/dl
SCAN=/var/lib/hyperion/scan
RESULTS=$OUT/results.tsv
SITE_ROOT=/home/site/site.test/htdocs
PREMIUM=acme-premium-widgets
CHILD=hello-child

mkdir -p "$OUT" "$DL"
chmod 755 "$WORK" "$OUT" "$DL"

check() { # id, description, pass|fail, detail
    printf '%s\t%s\t%s\t%s\n' "$1" "$3" "$2" "${4:-}" >>"$RESULTS"
    printf '%-5s %-5s %s %s\n' "$1" "$3" "$2" "${4:+($4)}"
}
ok_if() { # id, description, detail, command...
    local id=$1 desc=$2 detail=$3
    shift 3
    if "$@"; then check "$id" "$desc" pass "$detail"; else check "$id" "$desc" fail "$detail"; fi
}
as_site() { sudo -u site -H "$@"; }
wp_site() { as_site php /usr/local/bin/wp --path="$SITE_ROOT" --quiet "$@"; }

# Polls the unit's cgroup until told to stop: peak memory and each process's I/O,
# which go with the unit when `--collect` removes it.
write_sampler() {
    cat >"$WORK/sampler.py" <<'PY'
import json, os, signal, sys, time
cg = "/sys/fs/cgroup/system.slice/%s.service" % sys.argv[1]
out = sys.argv[2]
stop = []
signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
peak = anon = current = cpu_usec = 0
io, cgio = {}, {}
samples = 0
def rd(p):
    try:
        with open(p) as f:
            return f.read()
    except OSError:
        return None
while not stop:
    t = rd(cg + "/memory.peak")
    if t:
        samples += 1
        peak = max(peak, int(t))
        current = max(current, int(rd(cg + "/memory.current") or 0))
        for line in (rd(cg + "/cpu.stat") or "").splitlines():
            if line.startswith("usage_usec "):
                cpu_usec = int(line.split()[1])
        for line in (rd(cg + "/memory.stat") or "").splitlines():
            if line.startswith("anon "):
                anon = max(anon, int(line.split()[1]))
        for pid in (rd(cg + "/cgroup.procs") or "").split():
            t = rd("/proc/%s/io" % pid)
            if t:
                io[pid] = dict((k.strip(), int(v)) for k, v in (l.split(":") for l in t.splitlines()))
    time.sleep(0.02)
with open(out, "w") as f:
    json.dump({"samples": samples, "memory_peak": peak, "memory_current_max": current,
               "anon_max": anon, "cpu_usec": cpu_usec, "io_by_pid": list(io.values())}, f)
PY
}

# scan <root> <id> <mode> <name> [exe]: a scan with its unit watched. Writes
# $OUT/<name>.json and $OUT/<name>.unit.json.
scan() {
    local root=$1 id=$2 mode=$3 name=$4 exe=${5:-$AGENT}
    python3 "$WORK/sampler.py" hyperion-sitescan "$OUT/$name.unit.json" &
    local sampler=$!
    timeout 7200 "$E2E" scan "$root" "$SCAN" "$id" "$mode" "$exe" >"$OUT/$name.json" 2>"$OUT/$name.err"
    local rc=$?
    kill -TERM "$sampler" 2>/dev/null
    wait "$sampler" 2>/dev/null
    return $rc
}
q() { jq -r "$2" "$OUT/$1.json"; }
unit() { jq -r "$2" "$OUT/$1.unit.json"; }
counts() { # name: one line a person can read
    jq -r '.reply.Scan as $s | if $s == null then "reply=\(.reply|tostring|.[0:300])" else
        "findings=\($s.findings|length) review=\($s.review|length) hashed=\($s.files_hashed) watched=\($s.coverage.files_watched) core_ran=\($s.upstream.ran) plugins=\($s.coverage.plugins_verified)/\($s.coverage.plugins_total) themes=\($s.coverage.themes_verified)/\($s.coverage.themes_total) stopped=\($s.stopped) capped=\($s.capped) partial=\($s.coverage.partial_reasons|length) wall=\(.scan_wall_s|floor)s" end' "$OUT/$1.json"
}
items() { # name: every finding and review item
    jq -r '.reply.Scan | (.findings[] | "  finding \(.kind) \(.severity) \(.rule_id // "-") \(.rel)"), (.review[] | "  review  \(.kind) \(.rel) symlink=\(.symlink)"), (.coverage.partial_reasons[] | "  partial \(.)")' "$OUT/$1.json"
}
kind_of() { # name, bucket, rel
    jq -r --arg b "$2" --arg r "$3" '[.reply.Scan[$b][] | select(.rel == $r) | .kind + (if .rule_id then "/" + .rule_id else "" end)] | first // "NOT FOUND"' "$OUT/$1.json"
}

# ---- the site ----

build_site() {
    systemctl start mariadb
    id site >/dev/null 2>&1 || useradd -m -s /bin/bash site
    chmod 755 /home/site
    rm -rf /home/site/site.test
    mkdir -p "$SITE_ROOT"
    chown -R site:site /home/site/site.test
    [ -s /usr/local/bin/wp ] || curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod 755 /usr/local/bin/wp
    [ -s "$DL/latest-cs_CZ.tar.gz" ] || curl -fsSL -o "$DL/latest-cs_CZ.tar.gz" https://cs.wordpress.org/latest-cs_CZ.tar.gz
    chmod 644 "$DL/latest-cs_CZ.tar.gz"
    as_site tar xzf "$DL/latest-cs_CZ.tar.gz" --strip-components=1 -C "$SITE_ROOT"

    openssl rand -hex 16 >"$WORK/db.pass"
    chmod 600 "$WORK/db.pass"
    local pass
    pass=$(cat "$WORK/db.pass")
    mariadb <<SQL
DROP DATABASE IF EXISTS site_wp;
DROP USER IF EXISTS site_wp@localhost;
CREATE DATABASE site_wp CHARACTER SET utf8mb4;
CREATE USER site_wp@localhost IDENTIFIED BY '$pass';
GRANT ALL ON site_wp.* TO site_wp@localhost;
SQL
    wp_site config create --dbname=site_wp --dbuser=site_wp --dbpass="$pass" --dbhost=localhost --locale=cs_CZ --skip-check
    wp_site core install --url=http://site.test --title=E2E --admin_user=admin \
        --admin_password="$(openssl rand -hex 16)" --admin_email=e2e@site.test --skip-email
    wp_site plugin install elementor woocommerce --activate
    wp_site theme install hello-elementor

    # A child theme and a premium plugin wordpress.org has never heard of.
    local child=$SITE_ROOT/wp-content/themes/$CHILD
    as_site mkdir -p "$child"
    as_site tee "$child/style.css" >/dev/null <<CSS
/*
Theme Name: Hello Child
Template: hello-elementor
Version: 1.0
*/
CSS
    as_site cp "$FIX/clean_functions.php" "$child/functions.php"
    wp_site theme activate "$CHILD"

    local prem=$SITE_ROOT/wp-content/plugins/$PREMIUM
    as_site mkdir -p "$prem/includes" "$prem/assets"
    as_site tee "$prem/$PREMIUM.php" >/dev/null <<PHP
<?php
/*
Plugin Name: Acme Premium Widgets
Version: 2.3.1
*/
if (!defined('ABSPATH')) { exit; }
require_once __DIR__ . '/includes/class-widgets.php';
PHP
    as_site tee "$prem/includes/class-widgets.php" >/dev/null <<'PHP'
<?php
class Acme_Widgets { public function title() { return 'widgets'; } }
PHP
    as_site cp "$FIX/clean_minified.js" "$prem/assets/widgets.min.js"
    wp_site plugin activate "$PREMIUM"
    wp_site language plugin install --all cs_CZ || true
    wp_site language theme install --all cs_CZ || true
    wp_site cron event run --due-now || true

    # Would leave a mark if a scan ever ran the site's PHP.
    as_site mkdir -p "$SITE_ROOT/wp-content/mu-plugins"
    as_site tee "$SITE_ROOT/wp-content/mu-plugins/e2e-marker.php" >/dev/null <<'PHP'
<?php
file_put_contents(__DIR__ . '/../uploads/e2e-marker.txt', 'ran');
PHP
    as_site rm -f "$SITE_ROOT/wp-content/uploads/e2e-marker.txt"
    # The transients on this site are real, so a later vendor step adds to them.
    tar -C /home/site -cpf "$WORK/site-pristine.tar" site.test
    mariadb-dump site_wp >"$WORK/site-pristine.sql"
}

restore_site() {
    rm -rf /home/site/site.test
    tar -C /home/site -xpf "$WORK/site-pristine.tar"
    rm -f "$SCAN/baselines/site"
}

need_site() {
    if [ ! -s "$WORK/site-pristine.tar" ]; then build_site; fi
}

# ---- A: unit caps ----

# Each attempt runs in its own child: the syscall filter kills whoever trips it,
# and a process that died at startup says nothing about the call being tried.
write_probe_sys() {
    cat >"$WORK/probe-sys.c" <<C
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
static const char *T = "$SITE_ROOT/e2e-0600.txt";
static void attempt(const char *name, int (*f)(void)) {
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        errno = 0;
        int r = f();
        _exit(r < 0 ? (errno & 0x7f) : 0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (WIFSIGNALED(st)) printf("%s SIG%s\\n", name, sigabbrev_np(WTERMSIG(st)));
    else if (WEXITSTATUS(st) == 0) printf("%s ALLOWED\\n", name);
    else printf("%s %s\\n", name, strerrorname_np(WEXITSTATUS(st)));
}
static int mk(const char *p) { int f = open(p, O_WRONLY | O_CREAT, 0644); if (f >= 0) unlink(p); return f; }
static int a_append(void) { return open(T, O_WRONLY | O_APPEND); }
static int a_unlink(void) { return unlink(T); }
static int a_chmod(void) { return chmod(T, 0666); }
static int a_chown(void) { return chown(T, 0, 0); }
static int a_docroot(void) { return mk("$SITE_ROOT/e2e-new"); }
static int a_etc(void) { return mk("/etc/e2e-new"); }
static int a_tmp(void) { return mk("/tmp/e2e-new"); }
static int a_vartmp(void) { return mk("/var/tmp/e2e-new"); }
static int a_root(void) { return mk("/root/e2e-new"); }
static int a_run(void) { return mk("/run/e2e-new"); }
static int a_manifests(void) { return mk("$SCAN/manifests/e2e-new"); }
static int a_scan(void) { return mk("$SCAN/e2e-new"); }
static int a_cgroup(void) { return open("/sys/fs/cgroup/cgroup.procs", O_WRONLY); }
static int a_inet(void) { return socket(AF_INET, SOCK_STREAM, 0); }
static int a_unix(void) { return socket(AF_UNIX, SOCK_STREAM, 0); }
static int a_kill(void) { return kill(1, 0); }
static int a_tgkill(void) { return syscall(SYS_tgkill, 1, 1, 0); }
static int a_ptrace(void) { return ptrace(PTRACE_ATTACH, 1, 0, 0); }
static int a_mount(void) { return mount("none", "/tmp", "tmpfs", 0, 0); }
static int a_unshare(void) { return unshare(CLONE_NEWUSER); }
static int a_handle(void) { return syscall(SYS_open_by_handle_at, AT_FDCWD, 0, O_RDONLY); }
static int a_mknod(void) { return mknod("$SCAN/e2e-dev", S_IFCHR | 0600, makedev(1, 3)); }
int main(void) {
    attempt("open_append", a_append); attempt("unlink", a_unlink);
    attempt("chmod", a_chmod); attempt("chown", a_chown);
    attempt("create_in_docroot", a_docroot); attempt("create_in_etc", a_etc);
    attempt("create_in_tmp", a_tmp); attempt("create_in_var_tmp", a_vartmp);
    attempt("create_in_root", a_root); attempt("create_in_run", a_run);
    attempt("create_in_manifests", a_manifests); attempt("create_in_scan_dir", a_scan);
    attempt("cgroup_write", a_cgroup);
    attempt("socket_inet", a_inet); attempt("socket_unix", a_unix);
    attempt("kill", a_kill); attempt("tgkill", a_tgkill); attempt("ptrace", a_ptrace);
    attempt("mount", a_mount); attempt("unshare_user", a_unshare);
    attempt("open_by_handle_at", a_handle); attempt("mknod", a_mknod);
    return 0;
}
C
    sed -i 's/\\\\n/\\n/g' "$WORK/probe-sys.c"
    gcc -O1 -D_GNU_SOURCE -include sys/sysmacros.h -o "$WORK/probe-sys" "$WORK/probe-sys.c"
    # Touches every page, or the kernel never has to give them.
    cat >"$WORK/memhog.c" <<'C'
#include <stdlib.h>
#include <string.h>
int main(void) {
    size_t n = 600u * 1024 * 1024;
    char *p = malloc(n);
    if (p) memset(p, 1, n);
    return 0;
}
C
    gcc -O0 -o "$WORK/memhog" "$WORK/memhog.c"
}

write_probe() { # path, command to exec afterwards
    cat >"$1" <<SH
#!/bin/sh
# Stands in for the worker's binary: looks around from inside the real unit.
T=$SITE_ROOT/e2e-0600.txt
L=$SCAN/probe.log
{
  echo "uid=\$(id -u)"
  grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status
  echo "cgroup=\$(cut -d: -f3 /proc/self/cgroup)"
  echo "memory.max=\$(cat /sys/fs/cgroup/\$(cut -d: -f3 /proc/self/cgroup)/memory.max 2>&1)"
  echo "read:\$(cat \$T 2>&1)"
  (echo x >>\$T) 2>&1 | sed 's/^/append: /'; echo "append_rc=\$?"
  $WORK/probe-sys
  echo "net_devices=\$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\n' ',')"
  python3 -c pass >/dev/null 2>&1; echo "python_rc=\$?"
  curl -sS -m 5 -o /dev/null https://wordpress.org/ >/dev/null 2>&1; echo "curl_rc=\$?"
  echo "dev_vda=\$(ls /dev/vda 2>&1 | head -1)"
  echo "dev_count=\$(ls /dev | wc -l)"
} >\$L 2>&1
sleep 2
exec $AGENT scan-worker
SH
    chmod 755 "$1"
}

section_a() {
    echo "== A: unit caps =="
    # No WordPress needed, so a second, smaller VM can run this section alone.
    id site >/dev/null 2>&1 || useradd -m -s /bin/bash site
    chmod 755 /home/site
    mkdir -p "$SITE_ROOT"
    chown -R site:site /home/site/site.test
    printf 'tenant secret\n' | as_site tee "$SITE_ROOT/e2e-0600.txt" >/dev/null
    chmod 600 "$SITE_ROOT/e2e-0600.txt"
    mkdir -p "$SCAN"
    chmod 700 "$SCAN"
    mkdir -p "$SCAN/manifests" "$SCAN/baselines" "$SCAN/accepted"
    rm -f "$SCAN/probe.log"
    write_probe_sys
    write_probe "$WORK/probe.sh"
    local before
    before=$(sha256sum "$SITE_ROOT/e2e-0600.txt" | cut -d' ' -f1)
    "$E2E" discover "$SITE_ROOT" "$WORK/probe.sh" >"$OUT/a-discover.json" 2>"$OUT/a-discover.err" &
    local job=$!
    local show=""
    for _ in $(seq 1 100); do
        show=$(systemctl show hyperion-sitescan.service -p ActiveState,MemoryMax,MemoryHigh,MemorySwapMax,CPUWeight,IOWeight,Nice,IOSchedulingClass,CPUQuotaPerSecUSec,RuntimeMaxUSec,NoNewPrivileges,PrivateNetwork,ProtectSystem,CapabilityBoundingSet,ReadWritePaths,ReadOnlyPaths 2>/dev/null)
        echo "$show" | grep -q ActiveState=active && break
        sleep 0.1
    done
    wait $job
    echo "$show" >"$OUT/a-systemctl-show.txt"
    cat "$SCAN/probe.log" >"$OUT/a-probe.log"
    cat "$OUT/a-systemctl-show.txt" "$OUT/a-probe.log"
    local log=$OUT/a-probe.log show_f=$OUT/a-systemctl-show.txt
    has() { grep -q -- "$1" "$2"; }
    ok_if A "systemctl show MemoryMax=268435456" "" has '^MemoryMax=268435456$' "$show_f"
    ok_if A "MemoryHigh=209715200" "" has '^MemoryHigh=209715200$' "$show_f"
    ok_if A "MemorySwapMax=0" "" has '^MemorySwapMax=0$' "$show_f"
    ok_if A "CPUWeight=10 IOWeight=10" "" bash -c "grep -q '^CPUWeight=10$' $show_f && grep -q '^IOWeight=10$' $show_f"
    ok_if A "Nice=19, idle IO class" "" bash -c "grep -q '^Nice=19$' $show_f && grep -Eq '^IOSchedulingClass=(3|idle)$' $show_f"
    local quota=1s
    [ "$(grep -c ^processor /proc/cpuinfo)" -le 2 ] && quota=500ms
    ok_if A "CPUQuota for $(grep -c ^processor /proc/cpuinfo) cores: $quota" "" has "^CPUQuotaPerSecUSec=$quota\$" "$show_f"
    ok_if A "inside the unit memory.max=268435456" "" has '^memory.max=268435456$' "$log"
    ok_if A "reads a 0600 tenant file" "" has '^read:tenant secret$' "$log"
    for what in open_append unlink chmod chown create_in_docroot create_in_etc create_in_tmp create_in_var_tmp create_in_root create_in_run create_in_manifests cgroup_write; do
        local got
        got=$(awk -v w="$what" '$1 == w {print $2}' "$log")
        if [ -n "$got" ] && [ "$got" != ALLOWED ]; then
            check A "$what refused" pass "$got"
        else
            check A "$what refused" fail "${got:-no answer}"
        fi
    done
    ok_if A "writes its own state dir" "" has '^create_in_scan_dir ALLOWED$' "$log"
    ok_if A "tenant file unchanged" "" test "$before" = "$(sha256sum "$SITE_ROOT/e2e-0600.txt" | cut -d' ' -f1)"
    local devs
    devs=$(sed -n 's/^net_devices=//p' "$log")
    ok_if A "no network: only lo" "$devs" test "$devs" = "lo,"
    for what in socket_inet socket_unix kill tgkill ptrace mount open_by_handle_at; do
        local got
        got=$(awk -v w="$what" '$1 == w {print $2}' "$log")
        ok_if A "$what killed by the filter" "${got:-no answer}" test "$got" = SIGSYS
    done
    for what in unshare_user mknod; do
        local got
        got=$(awk -v w="$what" '$1 == w {print $2}' "$log")
        ok_if A "$what refused" "${got:-no answer}" bash -c "[ -n '$got' ] && [ '$got' != ALLOWED ]"
    done
    ok_if A "curl fails inside the unit" "exit $(sed -n 's/^curl_rc=//p' "$log")" test "$(sed -n 's/^curl_rc=//p' "$log")" != 0
    echo "python3 in the unit: exit $(sed -n 's/^python_rc=//p' "$log") (159 = SIGSYS)"
    ok_if A "NoNewPrivs and seccomp on" "" bash -c "grep -Eq '^NoNewPrivs:\s+1' $log && grep -Eq '^Seccomp:\s+2' $log"
    ok_if A "CapEff is CAP_DAC_READ_SEARCH only" "$(sed -n 's/^CapEff:\s*//p' "$log")" has '^CapEff:\s*0000000000000004$' "$log"
    ok_if A "no block device" "" has 'dev_vda=ls: cannot access' "$log"
    ok_if A "the probe's Discover still answered" "" bash -c "jq -e '.Discovery' $OUT/a-discover.json >/dev/null"
    rm -f "$SITE_ROOT/e2e-0600.txt"

    # A worker over its memory cap, and a second worker while one runs.
    "$E2E" discover "$SITE_ROOT" "$WORK/memhog" >"$OUT/a-oom.json" 2>&1
    ok_if A "worker over MemoryMax reads as failed: oom-kill" "$(jq -c . "$OUT/a-oom.json" | cut -c1-200)" bash -c "jq -e '.Failed | test(\"oom-kill\")' $OUT/a-oom.json >/dev/null"
    cat >"$WORK/slow.sh" <<SH
#!/bin/sh
sleep 6
exec $AGENT scan-worker
SH
    chmod 755 "$WORK/slow.sh"
    "$E2E" discover "$SITE_ROOT" "$WORK/slow.sh" >"$OUT/a-first.json" 2>&1 &
    job=$!
    sleep 2
    "$E2E" discover "$SITE_ROOT" "$AGENT" >"$OUT/a-busy.json" 2>&1
    wait $job
    ok_if A "second worker on the node is Busy" "$(cat "$OUT/a-busy.json")" bash -c "jq -e '. == \"Busy\"' $OUT/a-busy.json >/dev/null"
    ok_if A "first worker still answered" "" bash -c "jq -e '.Discovery' $OUT/a-first.json >/dev/null"
}

# ---- B: clean real WordPress ----

section_b() {
    echo "== B: clean real WordPress =="
    need_site
    restore_site
    scan "$SITE_ROOT" site delta b-first
    counts b-first
    items b-first | head -60
    jq '.discovery.components | map({kind: .key.kind, slug: .key.slug, version: .key.version, locale: .key.locale})' "$OUT/b-first.json" >"$OUT/b-components.json"
    jq -c '.[]' "$OUT/b-components.json"
    jq '.reply.Scan.coverage' "$OUT/b-first.json"
    ok_if B "first scan answered" "$(counts b-first)" test "$(q b-first '.reply.Scan != null')" = true
    ok_if B "core compared" "" test "$(q b-first '.reply.Scan.upstream.ran')" = true
    ok_if B "zero findings" "$(q b-first '.reply.Scan.findings|length')" test "$(q b-first '.reply.Scan.findings|length')" = 0
    ok_if B "zero review" "$(q b-first '.reply.Scan.review|length')" test "$(q b-first '.reply.Scan.review|length')" = 0
    ok_if B "not partial" "$(q b-first '.reply.Scan.coverage.partial_reasons|join("; ")')" test "$(q b-first '.reply.Scan.coverage.partial_reasons|length')" = 0
    local v
    v=$(jq -r '.[] | select(.kind == "core") | .locale' "$OUT/b-components.json")
    ok_if B "core read as cs_CZ" "$v" test "$v" = cs_CZ
    for slug in elementor woocommerce; do
        ok_if B "$slug verified" "" bash -c "jq -e --arg s $slug '.known_slugs | index(\$s)' $OUT/b-first.json >/dev/null && ! jq -e --arg s $slug '.reply.Scan.upstream.plugins_unknown | index(\$s)' $OUT/b-first.json >/dev/null"
    done
    ok_if B "hello-elementor verified" "" bash -c "jq -e '.known_slugs | index(\"hello-elementor\")' $OUT/b-first.json >/dev/null && ! jq -e '.reply.Scan.upstream.themes_unknown | index(\"hello-elementor\")' $OUT/b-first.json >/dev/null"
    ok_if B "premium plugin unverifiable, watched" "" bash -c "jq -e --arg s $PREMIUM '.reply.Scan.upstream.plugins_unknown | index(\$s)' $OUT/b-first.json >/dev/null"
    ok_if B "scan ran no tenant PHP" "" test ! -e "$SITE_ROOT/wp-content/uploads/e2e-marker.txt"
    scan "$SITE_ROOT" site delta b-second
    counts b-second
    ok_if B "unchanged second scan hashes nothing" "hashed=$(q b-second '.reply.Scan.files_hashed')" test "$(q b-second '.reply.Scan.files_hashed')" = 0
    ok_if B "unchanged second scan stays clean" "" test "$(q b-second '(.reply.Scan.findings|length) + (.reply.Scan.review|length)')" = 0
    scan "$SITE_ROOT" site full b-full
    counts b-full
    ok_if B "full re-hash stays clean" "hashed=$(q b-full '.reply.Scan.files_hashed')" test "$(q b-full '(.reply.Scan.findings|length) + (.reply.Scan.review|length)')" = 0
}

# The last few release branches as they ship, nothing installed: a default theme
# or bundled plugin that differs from its standalone copy shows up here.
section_b_stock() {
    echo "== B: stock releases =="
    local versions
    versions=$(curl -fsSL https://api.wordpress.org/core/stable-check/1.0/ | python3 -I -c "
import json, sys
d = json.load(sys.stdin)
best = {}
for v in d:
    p = v.split('.')
    if len(p) < 2: continue
    k = (int(p[0]), int(p[1]))
    t = tuple(int(x) for x in p)
    if k not in best or t > best[k]: best[k] = t
for k in sorted(best, reverse=True)[:5]:
    print('.'.join(map(str, best[k])))
")
    local v
    for v in $versions; do
        local home=/home/site/stock-$v
        rm -rf "$home"
        mkdir -p "$home/htdocs"
        [ -s "$DL/wordpress-$v.tar.gz" ] || curl -fsSL -o "$DL/wordpress-$v.tar.gz" "https://wordpress.org/wordpress-$v.tar.gz"
        tar xzf "$DL/wordpress-$v.tar.gz" --strip-components=1 -C "$home/htdocs"
        chown -R site:site "$home"
        rm -f "$SCAN/baselines/stock-$v"
        scan "$home/htdocs" "stock-$v" delta "b-stock-$v"
        counts "b-stock-$v"
        items "b-stock-$v" | head -20
        ok_if B "stock $v: zero findings, zero review" "$(q "b-stock-$v" '(.reply.Scan.findings|length|tostring) + "/" + (.reply.Scan.review|length|tostring)')" test "$(q "b-stock-$v" '(.reply.Scan.findings|length) + (.reply.Scan.review|length)')" = 0
        rm -rf "$home"
    done
}

# ---- C: the incident ----

# File padded with comments to the size the incident's file had.
padded() { # source, bytes, dest
    as_site bash -c "cp '$1' '$3'; n=\$(( $2 - \$(stat -c %s '$3') )); if [ \$n -gt 3 ]; then printf '\n//%*s' \$((n-3)) '' | tr ' ' '#' >>'$3'; fi"
}
# The attacker's append: exactly <bytes> bytes of the loader, comment-padded.
append_loader() { # rel, bytes
    local tmp
    tmp=$(mktemp -p "$WORK")
    python3 -c "
import sys
b=open('$FIX/appended_js_loader.js','rb').read()
n=int('$2')
b=(b+b'\n//'+b'#'*n)[:n] if len(b)<n else b
sys.stdout.buffer.write(b)" >"$tmp"
    as_site bash -c "cat >>'$SITE_ROOT/$1'" <"$tmp"
    rm -f "$tmp"
}
forge() { as_site touch -d '2023-03-14 09:26:53' "$SITE_ROOT/$1"; }

section_c() {
    echo "== C: the incident =="
    need_site
    restore_site
    scan "$SITE_ROOT" site delta c-before
    counts c-before
    sleep 1

    local el=wp-content/plugins/elementor wc=wp-content/plugins/woocommerce prem=wp-content/plugins/$PREMIUM
    local swiper cookie frontend
    swiper=$(cd "$SITE_ROOT" && find $el -name swiper.min.js | sort | head -1)
    cookie=$(cd "$SITE_ROOT" && find $wc -name js.cookie.min.js | sort | head -1)
    frontend=$(cd "$SITE_ROOT" && find $el -name frontend-modules.min.js | sort | head -1)
    echo "paths: $swiper $cookie $frontend"

    # Row 1: loader appended to swiper.min.js.
    append_loader "$swiper" 512
    # Row 2: 37 kB shell, at the root and elsewhere.
    padded "$FIX/fake403_shell.php" 37000 "$SITE_ROOT/wp-config-modules.php"
    padded "$FIX/fake403_shell.php" 37000 "$SITE_ROOT/wp-content/wp-config-modules.php"
    padded "$FIX/fake403_shell.php" 37000 "$SITE_ROOT/wp-admin/wp-config-modules.php"
    as_site mkdir -p "$SITE_ROOT/wp-content/uploads/2026/11"
    padded "$FIX/fake403_shell.php" 37000 "$SITE_ROOT/wp-content/uploads/2026/11/wp-config-modules.php"
    # Row 3: 13 eval files, mtimes forged.
    local evals=(
        wp-includes/class-wp-strongers.php
        wp-includes/blocks/class-wp-block-cache.php
        wp-admin/includes/class-wp-doctrine.php
        wp-content/doctrine.php
        wp-content/mu-plugins/doctrine-mu.php
        "$el/includes/doctrine-a.php"
        "$wc/includes/doctrine-b.php"
        wp-content/plugins/akismet/doctrine-c.php
        wp-content/themes/hello-elementor/doctrine-d.php
        "wp-content/themes/$CHILD/doctrine-e.php"
        "$prem/includes/doctrine-f.php"
        wp-content/uploads/2026/11/doctrine-g.php
        wp-content/languages/doctrine-h.php
    )
    local f
    for f in "${evals[@]}"; do
        as_site mkdir -p "$(dirname "$SITE_ROOT/$f")"
        as_site cp "$FIX/fake_doctrine.php" "$SITE_ROOT/$f"
        forge "$f"
    done
    # Row 4: exactly 872 bytes on two more upstream files.
    append_loader "$cookie" 872
    append_loader "$frontend" 872
    # Row 5: obfuscated wp_footer in the child theme, mtime forged too.
    as_site cp "$FIX/functions_footer.php" "$SITE_ROOT/wp-content/themes/$CHILD/functions.php"
    forge "wp-content/themes/$CHILD/functions.php"

    # Forged mtimes on edits rules can't see, in each kind of tree.
    local wc_edit=$wc/woocommerce.php core_edit=wp-includes/load.php prem_edit=$prem/includes/class-widgets.php
    local stamp
    for f in "$wc_edit" "$core_edit"; do
        stamp=$(stat -c %y "$SITE_ROOT/$f")
        printf '\n// harmless edit\n' | as_site bash -c "cat >>'$SITE_ROOT/$f'"
        as_site touch -d "$stamp" "$SITE_ROOT/$f"
    done
    # The same size and the same mtime: only ctime can tell.
    stamp=$(stat -c %y "$SITE_ROOT/$prem_edit")
    as_site sed -i "s/'widgets'/'WIDGETS'/" "$SITE_ROOT/$prem_edit"
    as_site touch -d "$stamp" "$SITE_ROOT/$prem_edit"
    # Premium edit with a rule hit, and a new clean premium file.
    printf "\neval(base64_decode('ZWNobyAnJzs='));\n" | as_site bash -c "cat >>'$SITE_ROOT/$prem/$PREMIUM.php'"
    printf '<?php\n// a new helper\n' | as_site tee "$SITE_ROOT/$prem/includes/helper.php" >/dev/null
    # A release file gone.
    as_site rm -f "$SITE_ROOT/wp-includes/blocks/index.php"

    sleep 1
    scan "$SITE_ROOT" site delta c-after
    counts c-after
    items c-after >"$OUT/c-items.txt"
    wc -l <"$OUT/c-items.txt"

    printf '%-52s %-34s %s\n' "row: file" "expected" "found" | tee "$OUT/c-table.txt"
    row() { # label, bucket, rel, expected kind prefix
        local got
        got=$(kind_of c-after "$2" "$3")
        printf '%-52s %-34s %s\n' "$1" "$4" "$got" | tee -a "$OUT/c-table.txt"
        case "$got" in
            "$4"*) check C "$1" pass "$got" ;;
            *) check C "$1: expected $4" fail "$got" ;;
        esac
    }
    row "1 swiper.min.js loader" findings "$swiper" upstream_modified/js_self_removing_loader
    row "2 webshell at root" findings wp-config-modules.php core_unexpected/webshell_marker
    row "2 webshell in wp-content" findings wp-content/wp-config-modules.php rule_hit/webshell_marker
    row "2 webshell in wp-admin" findings wp-admin/wp-config-modules.php core_unexpected/webshell_marker
    row "2 webshell in uploads" findings wp-content/uploads/2026/11/wp-config-modules.php rule_hit/
    local i=0
    for f in "${evals[@]}"; do
        i=$((i + 1))
        local want=rule_hit/eval_decoder
        case "$f" in
            wp-includes/* | wp-admin/*) want=core_unexpected/eval_decoder ;;
            "$el"/* | "$wc"/* | wp-content/plugins/akismet/* | wp-content/themes/hello-elementor/*) want=upstream_added/eval_decoder ;;
            wp-content/uploads/*) want=rule_hit/ ;;
        esac
        row "3 eval #$i forged mtime ${f##*/}" findings "$f" "$want"
    done
    row "4 js.cookie.min.js +872" findings "$cookie" upstream_modified
    row "4 frontend-modules.min.js +872" findings "$frontend" upstream_modified
    row "5 child theme functions.php wp_footer" findings "wp-content/themes/$CHILD/functions.php" rule_hit/footer_hook_payload
    row "x verified plugin edit, forged mtime" findings "$wc_edit" upstream_modified
    row "x core edit, forged mtime" findings "$core_edit" core_modified
    row "x core file deleted" findings wp-includes/blocks/index.php core_missing
    row "x premium edit, rule hit" findings "$prem/$PREMIUM.php" rule_hit/eval_decoder
    row "x premium edit, same size and mtime" review "$prem_edit" baseline_change
    row "x premium new clean file" review "$prem/includes/helper.php" baseline_change
    printf '%-52s %-34s %s\n' "6 SEO spam URLs" "not detected (non-goal)" "not applicable" | tee -a "$OUT/c-table.txt"
    check C "6 SEO spam: non-goal, not run" n/a "page views covered by unit tests"
    ok_if C "scan ran no tenant PHP" "" test ! -e "$SITE_ROOT/wp-content/uploads/e2e-marker.txt"
    # Nothing it shouldn't have said about the clean rest of the site.
    local extra
    extra=$(jq -r '(.reply.Scan.findings|length) + (.reply.Scan.review|length)' "$OUT/c-after.json")
    echo "total items: $extra"
    cat "$OUT/c-items.txt"
}

# ---- D: hostile tree ----

section_d() {
    echo "== D: hostile tree =="
    local home=/home/hostile root=/home/hostile/h.test/htdocs canary=/root/e2e-canary
    id hostile >/dev/null 2>&1 || useradd -m -s /bin/bash hostile
    chmod 755 "$home"
    chmod -R u+rwx "$home/h.test" 2>/dev/null
    rm -rf "$home/h.test"
    rm -f "$SCAN/baselines/hostile"
    sudo -u hostile mkdir -p "$root/filler"
    sudo -u hostile python3 -c "
import os
for i in range(5000):
    d='$root/filler/d%d'%(i//200)
    os.makedirs(d,exist_ok=True)
    open('%s/f%d.php'%(d,i),'w').write('<?php // filler %d\n'%i)
"
    mkdir -p "$canary/dir"
    cat >"$canary/canary.php" <<'PHP'
<?php eval(base64_decode('ZWNobyAnJzs=')); // https://canary-leak.example/x
PHP
    cp "$canary/canary.php" "$canary/dir/canary-in-dir.php"
    cp "$canary/canary.php" "$canary/hard-target.php"
    chmod 755 /root
    chmod -R a+rX "$canary"
    # Hard links reach across owners only as root: the worst case for the walker.
    rm -f "$root/hard.php" "$root/hard-shadow.php"
    ln "$canary/hard-target.php" "$root/hard.php"
    ln /etc/shadow "$root/hard-shadow.php"
    sudo -u hostile ln -s /etc/shadow "$root/shadow-link.php"
    sudo -u hostile ln -s "$canary/canary.php" "$root/canary-link.php"
    sudo -u hostile ln -s "$canary/dir" "$root/link-dir"
    sudo -u hostile ln -s /etc/shadow "$root/shadow-link.js"
    sudo -u hostile ln -s "$root/loop-b" "$root/loop-a"
    sudo -u hostile ln -s "$root/loop-a" "$root/loop-b"
    sudo -u hostile mkfifo "$root/pipe.php" "$root/pipe.js"
    python3 -c "import socket; s=socket.socket(socket.AF_UNIX); s.bind('$root/sock.php')"
    mknod "$root/null.php" c 1 3
    sudo -u hostile truncate -s 100G "$root/huge.php"
    sudo -u hostile truncate -s 100G "$root/huge.js"
    sudo -u hostile truncate -s 100G "$root/huge.bin"
    sudo -u hostile python3 -c "open(b'$root/bad-\xff\xfe-name.php','w').write('<?php // odd name\n')"
    sudo -u hostile mkdir "$root/locked"
    printf '<?php // locked\n' | sudo -u hostile tee "$root/locked/x.php" >/dev/null
    chmod 000 "$root/locked"
    sudo -u hostile python3 -c "
import os
p='$root/deep'
os.makedirs(p)
os.chdir(p)
for i in range(600):
    os.mkdir('d'); os.chdir('d')
open('deep.php','w').write('<?php // deep\n')
"
    local shadow_sha canary_sha
    shadow_sha=$(sha256sum /etc/shadow | cut -d' ' -f1)
    canary_sha=$(sha256sum "$canary/canary.php" | cut -d' ' -f1)
    touch -a -d '2001-01-01' "$canary/canary.php" "$canary/hard-target.php" "$canary/dir/canary-in-dir.php"

    local t0 t1
    t0=$(date +%s)
    scan "$root" hostile delta d-first
    t1=$(date +%s)
    counts d-first
    items d-first | head -50
    ok_if D "first hostile scan answered" "$((t1 - t0)) s" test "$(q d-first '.reply.Scan != null')" = true
    ok_if D "no hang: under 10 minutes" "$((t1 - t0)) s" test $((t1 - t0)) -lt 600
    has_item() { jq -e --arg r "$2" '.reply.Scan | (.findings + .review) | any(.rel == $r)' "$OUT/$1.json" >/dev/null; }
    ok_if D "symlink to /etc/shadow reported as a symlink" "$(kind_of d-first review shadow-link.php)" bash -c "jq -e '.reply.Scan | (.findings + .review) | any(.rel == \"shadow-link.php\" and .symlink)' $OUT/d-first.json >/dev/null"
    ok_if D "hard link reported, not read" "" bash -c "jq -e '.reply.Scan | (.findings + .review) | any(.rel == \"hard.php\" and (.sha256 == \"\") and .rule_id == null)' $OUT/d-first.json >/dev/null"
    ok_if D "hard link to /etc/shadow reported, not read" "" bash -c "jq -e '.reply.Scan | (.findings + .review) | any(.rel == \"hard-shadow.php\" and .sha256 == \"\")' $OUT/d-first.json >/dev/null"
    ok_if D "huge PHP is too large to inspect, in review" "$(kind_of d-first review huge.php)" test "$(kind_of d-first review huge.php | cut -d/ -f1)" = too_large_to_inspect
    # sudo reads /etc/shadow through PAM, so its atime is only a witness with no
    # sudo between the reset and the look.
    touch -a -d '2001-01-01' /etc/shadow
    scan "$root" hostile delta d-shadow
    ok_if D "atime unmoved over a scan: shadow" "$(stat -c %x /etc/shadow | cut -c1-10)" test "$(stat -c %x /etc/shadow | cut -c1-4)" = 2001

    # The tenant flips a file and a directory under the walk, from the inside.
    sudo -u hostile bash -c "cd '$root'; printf '<?php // plain\n' >swap.php; mkdir swapdir; printf '<?php // plain\n' >swapdir/in.php; mkdir swapdir.real; printf '<?php // plain\n' >swapdir.real/in.php"
    cat >"$WORK/swapper.sh" <<SH
#!/bin/bash
cd '$root' || exit 1
while :; do
    ln -sfn $canary/canary.php .s; mv -T .s swap.php
    printf '<?php // plain\n' >.r; mv -T .r swap.php
    mv -T swapdir swapdir.old 2>/dev/null; ln -sfn $canary/dir swapdir
    rm -f swapdir; mv -T swapdir.old swapdir 2>/dev/null
done
SH
    chmod 755 "$WORK/swapper.sh"
    sudo -u hostile "$WORK/swapper.sh" &
    local swapper=$!
    local n
    for n in 1 2 3 4 5; do
        # New names keep the walk reading, so the race has something to hit.
        sudo -u hostile bash -c "cd '$root/filler/d0' && for i in \$(seq 1 300); do printf '<?php // %s %s\n' $n \$i >r$n-\$i.php; done"
        scan "$root" hostile delta "d-swap$n"
        counts "d-swap$n"
    done
    pkill -u hostile -f swapper.sh
    kill "$swapper" 2>/dev/null
    wait "$swapper" 2>/dev/null

    local all=("$OUT"/d-first.json "$OUT"/d-shadow.json "$OUT"/d-swap?.json)
    ok_if D "all swap scans answered" "" bash -c "for f in $OUT/d-swap?.json; do jq -e '.reply.Scan != null' \$f >/dev/null || exit 1; done"
    ok_if D "canary domain never reported" "" bash -c "! grep -q canary-leak ${all[*]}"
    ok_if D "canary hash never reported" "" bash -c "! grep -q $canary_sha ${all[*]}"
    ok_if D "/etc/shadow hash never reported" "" bash -c "! grep -q $shadow_sha ${all[*]}"
    ok_if D "no eval rule hit under the swap" "" bash -c "! jq -e '.reply.Scan.findings | any(.rule_id == \"eval_decoder\")' ${all[*]} | grep -q true"
    # relatime would have moved these on any read.
    local f
    for f in "$canary/canary.php" "$canary/hard-target.php" "$canary/dir/canary-in-dir.php"; do
        ok_if D "atime unmoved: ${f##*/}" "$(stat -c %x "$f" | cut -c1-10)" test "$(stat -c %x "$f" | cut -c1-4)" = 2001
    done
    ok_if D "tree left as found: no worker wrote" "" test -p "$root/pipe.php"
    chmod 755 "$root/locked"
    sync
}

# ---- E: resources ----

gen_php() { # dir, count, owner, [long]
    sudo -u "$3" python3 - "$1" "$2" "${4:-}" <<'PY'
import hashlib, os, sys
root, count, long_names = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "long"
pad = "x" * 60
for i in range(count):
    if long_names:
        d = "%s/%s-%d/%s-%d" % (root, pad, i // 40000, pad, i // 1000)
        name = "%s-%d.php" % (pad, i)
    else:
        d = "%s/m%d/s%d" % (root, i // 40000, i // 1000)
        name = "f%d.php" % i
    if i % 1000 == 0:
        os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "w") as f:
        f.write("<?php\n// generated %d %s\nfunction g%d() { return '%s'; }\n" % (
            i, hashlib.sha256(str(i).encode()).hexdigest(), i, "y" * 900))
PY
}

report_scan() { # name, label
    local peak anon reads rchar syscr
    peak=$(unit "$1" .memory_peak)
    anon=$(unit "$1" .anon_max)
    # The scan's process is the last the sampler saw; the largest read is it.
    rchar=$(unit "$1" '[.io_by_pid[].rchar] | max // 0')
    reads=$(unit "$1" '[.io_by_pid[].read_bytes] | max // 0')
    syscr=$(unit "$1" '[.io_by_pid[].syscr] | max // 0')
    printf '%-26s wall=%ss hashed=%s peak=%s anon_max=%s rchar=%s read_bytes=%s syscr=%s samples=%s stopped=%s capped=%s partial=%s\n' \
        "$2" "$(q "$1" '.scan_wall_s | . * 10 | floor / 10')" "$(q "$1" '.reply.Scan.files_hashed')" \
        "$peak" "$anon" "$rchar" "$reads" "$syscr" "$(unit "$1" .samples)" \
        "$(q "$1" '.reply.Scan.stopped')" "$(q "$1" '.reply.Scan.capped')" \
        "$(q "$1" '.reply.Scan.coverage.partial_reasons | join("; ")')" | tee -a "$OUT/e-numbers.txt"
}

under_cap() { # name
    local peak
    peak=$(unit "$1" .memory_peak)
    [ "$peak" -gt 0 ] && [ "$peak" -le 268435456 ] && [ "$(q "$1" '.reply.Scan != null')" = true ]
}

section_e() {
    echo "== E: resources =="
    need_site
    : >"$OUT/e-numbers.txt"
    id big >/dev/null 2>&1 || useradd -m -s /bin/bash big
    chmod 755 /home/big
    rm -rf /home/big/20k.test
    mkdir -p /home/big/20k.test
    tar -C "$WORK" -xf /dev/null 2>/dev/null
    mkdir -p "$WORK/unpack"
    rm -rf "$WORK/unpack/site.test"
    tar -C "$WORK/unpack" -xpf "$WORK/site-pristine.tar"
    mv "$WORK/unpack/site.test/htdocs" /home/big/20k.test/htdocs
    chown -R big:big /home/big/20k.test
    local root=/home/big/20k.test/htdocs have
    have=$(find "$root" -type f | wc -l)
    local need=$((20000 - have))
    echo "real WordPress files: $have, generating $need"
    if [ "$need" -gt 0 ]; then
        sudo -u big mkdir -p "$root/wp-content/plugins/acme-generated"
        printf '<?php\n/*\nPlugin Name: Acme Generated\nVersion: 1.0.0\n*/\n' | sudo -u big tee "$root/wp-content/plugins/acme-generated/acme-generated.php" >/dev/null
        gen_php "$root/wp-content/plugins/acme-generated" "$((need - 1))" big
    fi
    local files
    files=$(find "$root" -type f | wc -l)
    echo "files in the site: $files" | tee -a "$OUT/e-numbers.txt"
    check E "20k-file site built" pass "$files files, $have real WordPress"

    rm -f "$SCAN/baselines/20k"
    sync; echo 3 >/proc/sys/vm/drop_caches
    scan "$root" 20k delta e-20k-first
    report_scan e-20k-first "20k first (idle, cold)"
    ok_if E "20k first: under MemoryMax" "peak=$(unit e-20k-first .memory_peak)" under_cap e-20k-first
    sync; echo 3 >/proc/sys/vm/drop_caches
    scan "$root" 20k delta e-20k-second
    report_scan e-20k-second "20k second (idle, cold)"
    ok_if E "20k second: hashes nothing" "hashed=$(q e-20k-second '.reply.Scan.files_hashed')" test "$(q e-20k-second '.reply.Scan.files_hashed')" = 0
    ok_if E "20k second: under MemoryMax" "peak=$(unit e-20k-second .memory_peak)" under_cap e-20k-second
    ls -l "$SCAN/baselines/20k" | tee -a "$OUT/e-numbers.txt"

    # 300k: short names, then names long enough to press the path-byte budget.
    local kind
    for kind in short long; do
        local t=/home/big/300k-$kind.test
        chmod -R u+rwx "$t" 2>/dev/null
        rm -rf "$t"
        mkdir -p "$t/htdocs"
        chown -R big:big "$t"
        rm -f "$SCAN/baselines/300k-$kind"
        local started
        started=$(date +%s)
        gen_php "$t/htdocs" 300000 big "$([ "$kind" = long ] && echo long)"
        echo "300k-$kind generated in $(($(date +%s) - started)) s, $(du -sh "$t/htdocs" | cut -f1)" | tee -a "$OUT/e-numbers.txt"
        sync; echo 3 >/proc/sys/vm/drop_caches
        scan "$t/htdocs" "300k-$kind" delta "e-300k-$kind-first"
        report_scan "e-300k-$kind-first" "300k $kind first"
        if [ "$(q "e-300k-$kind-first" '.reply.Scan != null')" = true ]; then
            ok_if E "300k $kind: answered under MemoryMax" "peak=$(unit "e-300k-$kind-first" .memory_peak)" under_cap "e-300k-$kind-first"
            local c p
            c=$(q "e-300k-$kind-first" '.reply.Scan.capped')
            p=$(q "e-300k-$kind-first" '.reply.Scan.coverage.partial_reasons|length')
            ok_if E "300k $kind: capped reads as partial" "capped=$c partial_reasons=$p" bash -c "[ $c = false ] || [ $p -gt 0 ]"
            scan "$t/htdocs" "300k-$kind" delta "e-300k-$kind-second"
            report_scan "e-300k-$kind-second" "300k $kind second"
            # Past the recorded-name budget a file has no record, so it is read each
            # time. The scan has to say how many, and read no more than that.
            local unrecorded
            unrecorded=$(q "e-300k-$kind-second" '.reply.Scan.coverage.partial_reasons | map(capture("(?<n>[0-9]+) files are not") | .n) | first // "0"')
            ok_if E "300k $kind second: hashes only what it says it has no record of" "hashed=$(q "e-300k-$kind-second" '.reply.Scan.files_hashed') unrecorded=$unrecorded" test "$(q "e-300k-$kind-second" '.reply.Scan.files_hashed')" = "$unrecorded"
            ok_if E "300k $kind second: under MemoryMax" "peak=$(unit "e-300k-$kind-second" .memory_peak)" under_cap "e-300k-$kind-second"
            # Inodes gone, file pages cached elsewhere: reclaim finds nothing to
            # scan at the limit, the worst case for the kernel's cache in the cap.
            local n oom=0 other=0
            for n in $(seq 1 15); do
                sync
                echo 2 >/proc/sys/vm/drop_caches
                scan "$t/htdocs" "300k-$kind" delta "e-300k-$kind-slab"
                case "$(q "e-300k-$kind-slab" '.reply | if type == "object" and .Scan then "ok" elif type == "object" and .Failed and (.Failed | test("oom-kill")) then "oom" else "other" end')" in
                    ok) ;;
                    oom) oom=$((oom + 1)) ;;
                    *) other=$((other + 1)) ;;
                esac
            done
            echo "300k $kind slab-cold repeats: 15 runs, oom=$oom other=$other" | tee -a "$OUT/e-numbers.txt"
            ok_if E "300k $kind: repeat scans with cold inodes never OOM" "15 runs, oom=$oom other=$other" test "$oom:$other" = 0:0
        else
            check E "300k $kind: answered" fail "$(q "e-300k-$kind-first" '.reply|tostring|.[0:300]')"
        fi
        ls -l "$SCAN/baselines/300k-$kind" 2>/dev/null | tee -a "$OUT/e-numbers.txt"
        rm -rf "$t"
    done
    cat "$OUT/e-numbers.txt"
}

# What a busy box costs the scan, and what the scan costs a busy box.
section_e_busy() {
    echo "== E: busy box =="
    local root=/home/big/20k.test/htdocs
    [ -d "$root" ] || { echo "run E first"; return; }
    # What a scan takes from a saturated box: its CPU time over the wall time, with
    # 8 hogs on 8 cores throughout. The hogs' own throughput says little in a VM,
    # where the host's other work moved it by a factor of two between runs.
    # CPUWeight only counts among siblings, so where the load runs matters: PHP-FPM
    # is a service, a sibling in system.slice; a login's work is in user.slice,
    # which competes with system.slice as a whole.
    local beside=/home/big/beside.test where scanning
    rm -rf "$beside"
    mkdir -p "$beside/htdocs"
    chown -R big:big "$beside"
    gen_php "$beside/htdocs" 100000 big
    for where in none service login; do
        rm -f "$SCAN/baselines/beside"
        sync; echo 3 >/proc/sys/vm/drop_caches
        # A quiet start, so the scan competes by weight until the one-minute load
        # average catches up and the gate takes over.
        local settled=0
        while [ "$(cut -d. -f1 /proc/loadavg)" -ge 1 ] && [ "$settled" -lt 300 ]; do
            sleep 5
            settled=$((settled + 5))
        done
        local hogs=""
        case "$where" in
            service) systemd-run --quiet --unit=e2e-hogs -p WorkingDirectory="$WORK" stress-ng --cpu 8 --timeout 300 ;;
            login) stress-ng --cpu 8 --timeout 300 >/dev/null 2>&1 & hogs=$! ;;
        esac
        scan "$beside/htdocs" beside delta "e-beside-$where"
        systemctl stop e2e-hogs.service 2>/dev/null
        [ -n "$hogs" ] && { kill "$hogs" 2>/dev/null; wait "$hogs" 2>/dev/null; }
        pkill -f '[s]tress-ng --cpu 8' 2>/dev/null
        report_scan "e-beside-$where" "100k first (hogs: $where)"
        local cpu wall share
        cpu=$(unit "e-beside-$where" '.cpu_usec / 1000000')
        wall=$(q "e-beside-$where" .scan_wall_s)
        share=$(python3 -I -c "print(round(100 * $cpu / $wall / 8, 1))")
        echo "hogs: $where: scan used ${cpu%.*} CPU s in ${wall%.*} s, ${share}% of 8 cores" | tee -a "$OUT/e-numbers.txt"
        check E "scan's share of the box, hogs: $where" pass "${share}% of 8 cores, ${cpu%.*} CPU s in ${wall%.*} s"
    done
    rm -rf "$beside"
    rm -f "$SCAN/baselines/beside"

    # Load well over the core count: the gate has to hold the scan.
    rm -f "$SCAN/baselines/20k"
    sync; echo 3 >/proc/sys/vm/drop_caches
    stress-ng --cpu 24 --timeout 1200 >/dev/null 2>&1 &
    local stress=$!
    local t=0 load=0
    while [ "$t" -lt 180 ]; do
        sleep 5
        t=$((t + 5))
        load=$(cut -d' ' -f1 /proc/loadavg)
        [ "${load%%.*}" -ge 12 ] && break
    done
    echo "load when the busy scan started: $load (8 cores)" | tee -a "$OUT/e-numbers.txt"
    ok_if E "load really is over the core count" "load=$load" test "${load%%.*}" -gt 8
    scan "$root" 20k delta e-20k-busy &
    scanning=$!
    local waited=0
    while kill -0 "$scanning" 2>/dev/null && [ "$waited" -lt 180 ]; do
        sleep 5
        waited=$((waited + 5))
    done
    local held=no
    kill -0 "$scanning" 2>/dev/null && held=yes
    echo "still waiting after ${waited}s at load $(cut -d' ' -f1 /proc/loadavg): $held" | tee -a "$OUT/e-numbers.txt"
    ok_if E "the scan holds back while the box is busy" "held=$held after ${waited}s (idle takes about 4 s)" test "$held" = yes
    # The gate lets it go on as soon as the average falls.
    local stopped_at
    stopped_at=$(date +%s)
    kill "$stress" 2>/dev/null
    pkill -f 'stress-ng --cpu 24' 2>/dev/null
    wait "$stress" 2>/dev/null
    wait "$scanning"
    echo "finished $(($(date +%s) - stopped_at)) s after the load stopped" | tee -a "$OUT/e-numbers.txt"
    report_scan e-20k-busy "20k first (24 cpu hogs)"
    ok_if E "busy scan answered in full afterwards" "$(counts e-20k-busy)" test "$(q e-20k-busy '.reply.Scan.stopped')" = false
    ok_if E "busy scan: under MemoryMax" "peak=$(unit e-20k-busy .memory_peak)" under_cap e-20k-busy
    cat "$OUT/e-numbers.txt"
}

# ---- F: false positives ----

section_f() {
    echo "== F: false positives =="
    local scratch=$WORK/rfp
    mkdir -p "$scratch"
    "$RFP" "$scratch" 50 >"$OUT/f-rfp.txt" 2>&1
    local rc=$?
    tail -25 "$OUT/f-rfp.txt"
    cp "$scratch/hits.jsonl" "$OUT/f-hits.jsonl"
    ok_if F "zero High over the top 50 plugins and themes" "exit $rc, $(grep -c '"severity":"high"' "$OUT/f-hits.jsonl") high, $(grep -c '"severity":"medium"' "$OUT/f-hits.jsonl") medium" test "$rc" = 0
}

# ---- G: vendor flow ----

section_g() {
    echo "== G: vendor flow (a stand-in, not a real vendor) =="
    need_site
    restore_site
    systemctl start mariadb
    mariadb site_wp <"$WORK/site-pristine.sql"
    rm -rf "$SCAN/manifests/vendor"
    # A public-looking address on this VM only. Production code runs unchanged:
    # the name resolves through /etc/hosts, the address passes, and curl trusts a
    # CA added to this machine's store.
    local host=my.elementor.com addr=44.44.44.44 g=$WORK/vendor key
    key=e2e-licence-$(openssl rand -hex 12)
    ip addr replace "$addr/32" dev lo
    sed -i "/$host/d" /etc/hosts
    echo "$addr $host" >>/etc/hosts
    rm -rf "$g"
    mkdir -p "$g/pkg"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$g/ca.key" -out "$g/ca.crt" -subj "/CN=E2E Test CA" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout "$g/srv.key" -out "$g/srv.csr" -subj "/CN=$host" 2>/dev/null
    printf 'subjectAltName=DNS:%s\n' "$host" >"$g/ext"
    openssl x509 -req -in "$g/srv.csr" -CA "$g/ca.crt" -CAkey "$g/ca.key" -CAcreateserial -days 2 -extfile "$g/ext" -out "$g/srv.crt" 2>/dev/null
    cp "$g/ca.crt" /usr/local/share/ca-certificates/e2e-test-ca.crt
    update-ca-certificates >/dev/null 2>&1

    # The package is the premium plugin as it is on disk.
    (cd "$SITE_ROOT/wp-content/plugins" && python3 -c "
import os, zipfile
z = zipfile.ZipFile('$g/pkg/package.zip', 'w', zipfile.ZIP_DEFLATED)
for d, _, fs in os.walk('$PREMIUM'):
    for f in fs:
        z.write(os.path.join(d, f))
z.close()")
    cat >"$g/server.py" <<PY
import http.server, ssl, sys
KEY = "$key"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        with open("$g/access.log", "a") as f:
            f.write(self.path + "\n")
    def do_GET(self):
        if KEY not in self.path:
            self.send_response(403); self.end_headers(); return
        if self.path.startswith("/dl"):
            # A hop, as vendors do: the next URL is also on the list.
            self.send_response(302)
            self.send_header("Location", "https://$host/pkg?license=" + KEY)
            self.end_headers(); return
        body = open("$g/pkg/package.zip", "rb").read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
s = http.server.ThreadingHTTPServer(("$addr", 443), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("$g/srv.crt", "$g/srv.key")
s.socket = c.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
    python3 "$g/server.py" &
    local server=$!
    sleep 1

    # A transient as WordPress stores one, written by WordPress itself.
    cat >"$g/set-transient.php" <<PHP
<?php
\$t = get_site_transient('update_plugins');
if (!is_object(\$t)) { \$t = new stdClass; \$t->response = array(); \$t->no_update = array(); }
\$e = new stdClass;
\$e->slug = '$PREMIUM';
\$e->plugin = '$PREMIUM/$PREMIUM.php';
\$e->new_version = '2.3.1';
\$e->package = 'https://$host/dl?license=$key';
\$t->no_update['$PREMIUM/$PREMIUM.php'] = \$e;
\$o = new stdClass;
\$o->slug = 'acme-other';
\$o->plugin = 'acme-other/acme-other.php';
\$o->new_version = '1.0.0';
\$o->package = 'https://unlisted-vendor.example.net/x.zip?license=$key';
\$t->no_update['acme-other/acme-other.php'] = \$o;
set_site_transient('update_plugins', \$t, DAY_IN_SECONDS);
PHP
    as_site mkdir -p "$SITE_ROOT/wp-content/plugins/acme-other"
    printf '<?php\n/*\nPlugin Name: Acme Other\nVersion: 1.0.0\n*/\n' | as_site tee "$SITE_ROOT/wp-content/plugins/acme-other/acme-other.php" >/dev/null
    chmod 644 "$g/set-transient.php"
    as_site php /usr/local/bin/wp --path="$SITE_ROOT" --skip-plugins --skip-themes eval-file "$g/set-transient.php"
    rm -f "$g/set-transient.php"

    scan "$SITE_ROOT" site delta g-before
    counts g-before
    ok_if G "before: premium plugin unverifiable" "vendor_verified=$(q g-before '.reply.Scan.coverage.plugins_vendor_verified')" test "$(q g-before '.reply.Scan.coverage.plugins_vendor_verified')" = 0

    E2E_DB_PASSWORD=$(cat "$WORK/db.pass") "$E2E" vendor "$SITE_ROOT" "$SCAN" site site_wp "$AGENT" >"$OUT/g-vendor.json" 2>"$OUT/g-vendor.err"
    jq . "$OUT/g-vendor.json"
    ok_if G "transient read as the site's own login" "refs=$(q g-vendor '.refs_found')" test "$(q g-vendor '.refs_found')" -ge 2
    ok_if G "download through a redirect hop: New" "$(q g-vendor '.fetched|tostring')" bash -c "[ \"\$(jq -r '.fetched[] | select(.slug == \"$PREMIUM\") | .result' $OUT/g-vendor.json)\" = 'Ok(New)' ]"
    ok_if G "unlisted host recorded, not fetched" "$(q g-vendor '.unknown_hosts|join(",")')" bash -c "jq -e '.unknown_hosts | index(\"unlisted-vendor.example.net\")' $OUT/g-vendor.json >/dev/null"

    scan "$SITE_ROOT" site delta g-after
    counts g-after
    ok_if G "after: premium plugin verified against the package" "vendor_verified=$(q g-after '.reply.Scan.coverage.plugins_vendor_verified')" test "$(q g-after '.reply.Scan.coverage.plugins_vendor_verified')" = 1
    ok_if G "after: no differences" "" test "$(q g-after '[.reply.Scan.findings[] | select(.component == "'"$PREMIUM"'")] | length')" = 0

    printf '\n// tampered\n' | as_site bash -c "cat >>'$SITE_ROOT/wp-content/plugins/$PREMIUM/includes/class-widgets.php'"
    sleep 1
    scan "$SITE_ROOT" site delta g-tamper
    counts g-tamper
    local rel=wp-content/plugins/$PREMIUM/includes/class-widgets.php
    ok_if G "tampered file differs from the vendor's package" "$(kind_of g-tamper findings "$rel")" test "$(kind_of g-tamper findings "$rel")" = upstream_modified
    ok_if G "labelled as the vendor's package" "$(jq -r --arg r "$rel" '.reply.Scan.findings[] | select(.rel == $r) | .source_label' "$OUT/g-tamper.json")" bash -c "jq -e --arg r '$rel' '.reply.Scan.findings | any(.rel == \$r and (.source_label | test(\"vendor\")))' $OUT/g-tamper.json >/dev/null"

    # The licence key: only the server, the database and this script know it.
    ok_if G "server saw the key, so the test is real" "" grep -q "$key" "$g/access.log"
    local leak=0 where=""
    if grep -rqa "$key" "$SCAN" 2>/dev/null; then leak=1; where="$where scan-dir"; fi
    if grep -qa "$key" "$OUT"/g-*.json "$OUT"/g-*.err 2>/dev/null; then leak=1; where="$where output"; fi
    if journalctl --since "-20min" 2>/dev/null | grep -qa "$key"; then leak=1; where="$where journal"; fi
    ok_if G "licence key not in scan state, output or journal" "${where:-none}" test "$leak" = 0
    check G "real vendors" n/a "UNTESTED: no licences; my.elementor.com here is a local stand-in"

    kill "$server" 2>/dev/null
    wait "$server" 2>/dev/null
    sed -i "/$host/d" /etc/hosts
    ip addr del "$addr/32" dev lo 2>/dev/null
    rm -f /usr/local/share/ca-certificates/e2e-test-ca.crt
    update-ca-certificates --fresh >/dev/null 2>&1
}

# ---- H: ClamAV ----

clam_watch() { # name, list, vanish, sites...
    local name=$1
    shift
    python3 "$WORK/sampler.py" hyperion-clamscan "$OUT/$name.unit.json" &
    local sampler=$!
    timeout 3600 "$E2E" clam "$@" >"$OUT/$name.json" 2>"$OUT/$name.err"
    local rc=$?
    kill -TERM "$sampler" 2>/dev/null
    wait "$sampler" 2>/dev/null
    jq -c . "$OUT/$name.json" 2>/dev/null | cut -c1-700
    return $rc
}

section_h() {
    echo "== H: ClamAV, real clamscan =="
    local a=/home/clam/a.test/htdocs b=/home/clam/b.test/htdocs list=$SCAN/clamav-list
    id clam-t >/dev/null 2>&1 || useradd -M -d /home/clam -s /usr/sbin/nologin clam-t
    mkdir -p /home/clam
    chmod 755 /home/clam
    rm -rf /home/clam/a.test /home/clam/b.test
    mkdir -p "$a/sub" "$b"
    chown -R clam-t:clam-t /home/clam/a.test /home/clam/b.test
    rm -f /etc/systemd/system/hyperion-clamscan.service.d/e2e.conf
    systemctl daemon-reload

    if ! ls /var/lib/clamav/*.c?d >/dev/null 2>&1; then
        echo "downloading signatures"
        timeout 900 freshclam --quiet 2>&1 | tail -3
    fi
    ls -l /var/lib/clamav | tee "$OUT/h-db.txt"

    # A signature for this run's own harmless file, written now: no EICAR in the repo.
    local marker
    marker="e2e harmless test file $(openssl rand -hex 16)"
    printf '%s\n' "$marker" | sudo -u clam-t tee "$a/planted.php" >/dev/null
    printf '<?php // ordinary\n' | sudo -u clam-t tee "$a/ok.php" "$b/ok.php" >/dev/null
    printf '<?php // goes away\n' | sudo -u clam-t tee "$a/vanishes.php" >/dev/null
    printf '<?php // two names\n' | sudo -u clam-t tee "$a/linked.php" >/dev/null
    sudo -u clam-t ln "$a/linked.php" "$a/sub/linked2.php"
    cp "$a/planted.php" "$a/sub/also-planted.txt"
    chown clam-t:clam-t "$a/sub/also-planted.txt"
    local hash size
    hash=$(md5sum "$a/planted.php" | cut -d' ' -f1)
    size=$(stat -c %s "$a/planted.php")
    echo "$hash:$size:Hyperion.E2E.Test" >/var/lib/clamav/e2e.hdb
    chmod 644 /var/lib/clamav/e2e.hdb

    # The real database through the real unit, a tenant's file vanishing on the way.
    (
        for _ in $(seq 1 600); do
            if systemctl is-active -q hyperion-clamscan.service; then
                systemctl show hyperion-clamscan.service -p MemoryMax,ProtectHome,ProtectSystem,PrivateNetwork,CapabilityBoundingSet,ReadOnlyPaths >"$OUT/h-show.txt"
                break
            fi
            sleep 0.1
        done
    ) &
    local shower=$!
    clam_watch h-run "$list" "$a/vanishes.php" "a=$a" "b=$b"
    wait "$shower"
    cat "$OUT/h-show.txt"
    ok_if H "unit: 3G cap, read-only home" "" bash -c "grep -q '^MemoryMax=3221225472$' $OUT/h-show.txt && grep -q '^ProtectHome=read-only$' $OUT/h-show.txt"
    ok_if H "pass ran" "$(q h-run '.preflight')" test "$(q h-run '.preflight')" = Run
    ok_if H "real database loaded" "peak=$(unit h-run .memory_peak) wall=$(q h-run '.wall_s|floor')s" test "$(unit h-run .memory_peak)" -gt 200000000
    ok_if H "under the unit's 3G" "peak=$(unit h-run .memory_peak)" test "$(unit h-run .memory_peak)" -le 3221225472
    ok_if H "planted signature found" "$(q h-run '.hits|map(.path + " " + .signature)|join(", ")')" bash -c "jq -e --arg p '$a/planted.php' '.hits | any(.path == \$p and (.signature | test(\"Hyperion.E2E.Test\")))' $OUT/h-run.json >/dev/null"
    ok_if H "second copy found too" "" bash -c "jq -e --arg p '$a/sub/also-planted.txt' '.hits | any(.path == \$p)' $OUT/h-run.json >/dev/null"
    ok_if H "vanished file counted, costs no coverage" "vanished=$(q h-run .vanished) end=$(q h-run .end)" test "$(q h-run .vanished):$(q h-run .end)" = "1:Complete"
    ok_if H "hard links skipped and counted" "$(q h-run '.listed[0]')" bash -c "jq -r '.listed[0]' $OUT/h-run.json | grep -q 'skipped: 2'"
    ok_if H "site with the hit attributed by path, other site clean" "" bash -c "! jq -e --arg b '$b' '.hits | any(.path | startswith(\$b))' $OUT/h-run.json >/dev/null"
    ok_if H "nothing left of the list file" "" test ! -e "$list"

    # A parser complaining about one tenant's odd file: truncated .xz.
    printf '\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01' | sudo -u clam-t tee "$b/broken.xz" >/dev/null
    printf 'FWS\x09\xff\xff\xff\xff\x00' | sudo -u clam-t tee "$b/broken.swf" >/dev/null
    local said
    said=$(clamscan --no-summary --infected "$b/broken.xz" "$b/broken.swf" 2>&1 | grep -c '^LibClamAV')
    echo "clamscan's complaints about the odd files, run by hand: $said"
    clam_watch h-noise "$list" - "a=$a" "b=$b"
    echo "end with an odd file: $(q h-noise .end)"
    if [ "$said" -gt 0 ]; then
        ok_if H "odd files make clamscan complain, and the pass stays complete" "lines=$said end=$(q h-noise .end)" test "$(q h-noise .end)" = Complete
    else
        check H "odd files: clamscan said nothing about these, so this proves nothing" n/a "end=$(q h-noise .end)"
    fi
    sudo -u clam-t rm -f "$b/broken.xz" "$b/broken.swf"

    # A real OOM kill: the production unit with a smaller cap dropped in.
    mkdir -p /etc/systemd/system/hyperion-clamscan.service.d
    printf '[Service]\nMemoryMax=64M\n' >/etc/systemd/system/hyperion-clamscan.service.d/e2e.conf
    systemctl daemon-reload
    clam_watch h-oom "$list" - "a=$a" "b=$b"
    ok_if H "real OOM kill reads as OutOfMemory" "end=$(q h-oom .end) peak=$(unit h-oom .memory_peak)" test "$(q h-oom .end)" = OutOfMemory
    rm -f /etc/systemd/system/hyperion-clamscan.service.d/e2e.conf
    rmdir /etc/systemd/system/hyperion-clamscan.service.d 2>/dev/null
    systemctl daemon-reload

    # The signature database going away: its own state, not a failed scan.
    mkdir -p "$WORK/clamdb"
    mv /var/lib/clamav/*.c?d /var/lib/clamav/e2e.hdb "$WORK/clamdb/"
    clam_watch h-nodb "$list" - "a=$a"
    mv "$WORK"/clamdb/* /var/lib/clamav/
    ok_if H "no signatures yet: says so, runs nothing" "$(q h-nodb .preflight)" test "$(q h-nodb .preflight)" = SignaturesDownloading
    rm -f /var/lib/clamav/e2e.hdb
}

# ---- run ----

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
cd "$WORK" || exit 2
for bin in "$AGENT" "$E2E"; do
    [ -x "$bin" ] || { echo "missing $bin: build first" >&2; exit 2; }
done
write_sampler
sections=("$@")
[ ${#sections[@]} -gt 0 ] || sections=(A B C D E F G H)
: >"$RESULTS"
for s in "${sections[@]}"; do
    case "$s" in
        A) section_a ;;
        B) section_b; section_b_stock ;;
        C) section_c ;;
        D) section_d ;;
        E) section_e; section_e_busy ;;
        Ebusy) section_e_busy ;;
        F) section_f ;;
        G) section_g ;;
        H) section_h ;;
        *) echo "unknown section $s" >&2 ;;
    esac
done

echo
echo "=== results ==="
awk -F'\t' '{printf "%-5s %-5s %s%s\n", $1, $2, $3, ($4 == "" ? "" : " (" $4 ")")}' "$RESULTS"
fails=$(awk -F'\t' '$2 == "fail"' "$RESULTS" | wc -l)
passes=$(awk -F'\t' '$2 == "pass"' "$RESULTS" | wc -l)
echo "pass=$passes fail=$fails"
[ "$fails" = 0 ]
