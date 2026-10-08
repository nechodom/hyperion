#!/usr/bin/env bash
# Hyperion master installer — Debian 12/13.
#
# Usage (as root, on a fresh box):
#   curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/install-master.sh | sudo bash
#
# It asks nothing. A couple of minutes later it prints a one-time link, and
# every decision this script used to ask about with [Y/n] prompts — the admin
# account, which software to install, the server's name, the panel's domain,
# mail, backups — is made in the browser, in the setup wizard that link opens.
# Prompts in a `curl | bash` script read from /dev/tty, cannot be validated
# properly, cannot be revisited, and could not show what the choice meant.
#
# What it does:
#   1. Root + Debian 12+ check
#   2. Port pre-flight on 80, 443 and the panel port. The one prompt left —
#      "stop the holder or abort" — appears only on a conflict.
#   3. Base packages: nginx, postfix (unless an MTA is there), sudo, restic,
#      sqlite3, git, dig
#   4. Source checkout in /opt/hyperion (units, scripts, `hyperion update`),
#      then `components.sh --prepare` adds deb.sury.org for this Debian suite
#   5. Binaries: the pre-built GitHub release, verified against SHA256SUMS.
#      Builds from source instead on non-x86_64, when the download or a
#      checksum fails, or with HYPERION_BUILD_FROM_SOURCE=1
#   6. /etc/hyperion, /var/lib/hyperion, agent.toml, web.toml, systemd units,
#      session + CSRF keys
#   7. Starts the agent, puts the panel in setup mode (`hyperion-web
#      setup-init`), starts the panel and prints the link, the setup code and
#      the certificate's SHA-256 fingerprint
#
# Unattended mode, for automation: set HYPERION_ADMIN_PASS and the script
# installs the software itself (HYPERION_COMPONENTS), creates the admin the
# old way and never enters setup mode.
#
# Re-running it is safe. On a box that already has an admin it changes
# nothing and points at `hyperion update`; on a box still waiting for its
# setup it prints a fresh link.
#
# Env knobs:
#   HYPERION_LISTEN            panel address, default 0.0.0.0:8443
#   HYPERION_ACME_EMAIL        Let's Encrypt contact (the wizard asks for it otherwise)
#   HYPERION_RELEASE_REPO      owner/repo of the pre-built release, default nechodom/hyperion
#   HYPERION_RELEASE_TAG       release tag, default rolling (CI republishes it from main)
#   HYPERION_BUILD_FROM_SOURCE=1   skip the pre-built release, cargo build instead
#   HYPERION_REF, HYPERION_INSTALL_DIR, HYPERION_GIT_URL, HYPERION_GIT_TOKEN,
#   HYPERION_LOCAL_TARBALL, HYPERION_SKIP_CLONE   source acquisition, see below
#   HYPERION_PREFLIGHT_ONLY, HYPERION_STOP_CONFLICTS, HYPERION_ALLOW_SHARED
#                              port pre-flight, see port_preflight()
# Unattended mode:
#   HYPERION_ADMIN_PASS        switches it on
#   HYPERION_ADMIN_USER        default admin
#   HYPERION_COMPONENTS        what to install, e.g. "php8.3 mariadb vsftpd phpmyadmin"
#                              (php8.1..php8.4 mariadb postgresql vsftpd phpmyadmin redis).
#                              Default: php8.3 mariadb postgresql vsftpd phpmyadmin,
#                              minus whatever HYPERION_WITH_MARIADB/_POSTGRES/_VSFTPD=0 drops
#   HYPERION_FTP_PORT          vsftpd control port, default 21

set -euo pipefail

#-------- 0. Args ----------------------------------------------------------
REF="${HYPERION_REF:-main}"
INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
ADMIN_USER="${HYPERION_ADMIN_USER:-admin}"
ADMIN_PASS="${HYPERION_ADMIN_PASS:-}"
LISTEN="${HYPERION_LISTEN:-}"
CONTACT_EMAIL="${HYPERION_ACME_EMAIL:-}"
FTP_PORT="${HYPERION_FTP_PORT:-21}"
RELEASE_REPO="${HYPERION_RELEASE_REPO:-nechodom/hyperion}"
RELEASE_TAG="${HYPERION_RELEASE_TAG:-rolling}"
BUILD_FROM_SOURCE="${HYPERION_BUILD_FROM_SOURCE:-}"

# Source acquisition (private-repo-friendly). One of:
#   HYPERION_LOCAL_TARBALL=/path/to/hyperion.tar.gz  → extract that
#   HYPERION_SKIP_CLONE=1                            → assume $INSTALL_DIR is ready
#   HYPERION_GIT_URL=git@github.com:nechodom/hyperion → SSH clone (use ssh-agent)
#   HYPERION_GIT_TOKEN=ghp_xxx + HYPERION_GIT_URL=https://github.com/...
#     → HTTPS clone with PAT, passed via git credential helper (no token in argv)
# Default (public repo or world-readable mirror):
GIT_URL="${HYPERION_GIT_URL:-https://github.com/nechodom/hyperion}"
GIT_TOKEN="${HYPERION_GIT_TOKEN:-}"
LOCAL_TARBALL="${HYPERION_LOCAL_TARBALL:-}"
SKIP_CLONE="${HYPERION_SKIP_CLONE:-}"

WEB_TOML="/etc/hyperion/web.toml"
STATE_DB="/var/lib/hyperion/state.db"
SETUP_FILE="/var/lib/hyperion/setup.json"
AGENT_SOCKET="/run/hyperion.sock"
INSTALL_LOG="/var/log/hyperion/install.log"

# ── output ────────────────────────────────────────────────────────────────
# The run is a short list of ✓ lines; apt, git and cargo write to
# $INSTALL_LOG instead of the terminal, and the log's tail is shown only when
# something fails. A person watching a fresh install wants to know it is
# moving and what is left — not 900 lines of "Unpacking …".
#
# On a terminal the step in progress is shown as "… label" and replaced by its
# ✓ line when it finishes. BEGUN tracks that open line so anything else
# printed meanwhile (a warning, an error) starts on a line of its own.
BEGUN=""
STEP_T=$SECONDS

end_begun() {
  if [[ -n "$BEGUN" ]]; then
    [[ -t 1 ]] && printf '\n'
    BEGUN=""
  fi
  return 0
}
log()  { end_begun; printf '\033[36m[hyperion]\033[0m %s\n' "$*"; }
warn() { end_begun; printf '\033[33m[warn]\033[0m %s\n' "$*"; }
fail() { end_begun; printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

fmt_secs() {
  if (( $1 >= 60 )); then printf '%dm %02ds' $(( $1 / 60 )) $(( $1 % 60 )); else printf '%ds' "$1"; fi
}
begin() {  # begin <label> — announce a step that takes a while
  end_begun
  STEP_T=$SECONDS
  BEGUN="$1"
  [[ -t 1 ]] && printf '  \033[2m…\033[0m %s' "$1"
  return 0
}
step() {  # step <label> [detail] — a step finished
  local dt=$(( SECONDS - STEP_T )) t=""
  (( dt >= 1 )) && t=" ($(fmt_secs "$dt"))"
  if [[ -n "$BEGUN" ]]; then
    [[ -t 1 ]] && printf '\r\033[K'
    BEGUN=""
  fi
  printf '  \033[32m✓\033[0m %-18s %s%s\n' "$1" "${2:-}" "$t"
  STEP_T=$SECONDS
}
step_failed() {  # step_failed <label> [detail]
  end_begun
  printf '  \033[31m✗\033[0m %-18s %s\n' "$1" "${2:-}"
  STEP_T=$SECONDS
}

# quietly <cmd...> — run with all output going to the install log. On failure
# the tail of the log is printed (the reason is nearly always in the last
# lines), and the command's exit code is returned for the caller to act on.
quietly() {
  local rc=0
  printf '\n$ %s\n' "$*" >> "$INSTALL_LOG"
  "$@" >> "$INSTALL_LOG" 2>&1 || rc=$?
  if (( rc != 0 )); then
    end_begun
    printf '    ── last lines of %s ──\n' "$INSTALL_LOG" >&2
    tail -n 25 "$INSTALL_LOG" | sed 's/^/    /' >&2
  fi
  return "$rc"
}

# One EXIT trap for the whole script: a second `trap … EXIT` REPLACES the
# first, which is how update.sh's askpass helper once outlived a pre-built
# install. Everything temporary goes on this list instead.
CLEANUP_PATHS=()
on_exit() {
  local rc=$? p
  for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do rm -rf -- "$p"; done
  return "$rc"
}
trap on_exit EXIT

norm_bool() {  # raw → 1 / 0 / "" (unset)
  case "${1,,}" in
    "") printf '' ;;
    0|n|no|false|off) printf '0' ;;
    *) printf '1' ;;
  esac
}

# An address as it goes into a URL: IPv6 needs brackets.
url_host() {
  if [[ "$1" == *:* ]]; then printf '[%s]' "$1"; else printf '%s' "$1"; fi
}

# ── port conflict pre-flight ───────────────────────────────────────────────
# Hyperion drives HOST services (nginx, the panel, vsftpd, MariaDB, Postgres);
# if a port it needs is already held by a FOREIGN process — most often
# docker-proxy for a published container — that service silently fails to bind
# and hostings/panel break. Reads the ports from the PREFLIGHT_SPECS array
# ("port;label;owner-regex"), finds the holder via `ss` and (for nftables-DNAT
# setups where nothing listens on the host) via `docker ps`, and on a conflict
# offers to STOP the holder or ABORT. A port already owned by the service that
# SHOULD hold it (a re-run) is not a conflict. Env knobs:
#   HYPERION_PREFLIGHT_ONLY=1  run the checks and exit (installs nothing)
#   HYPERION_STOP_CONFLICTS=1  auto-stop holders in a non-interactive run
#   HYPERION_ALLOW_SHARED=1    proceed despite conflicts (services may fail to bind)
port_preflight() {
  command -v ss >/dev/null 2>&1 || { log "WARN: 'ss' not found — skipping port pre-flight."; return 0; }
  local have_docker=0
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && have_docker=1

  local -a conflicts=()
  local spec port label owner line name pid unit container holder
  for spec in "${PREFLIGHT_SPECS[@]}"; do
    IFS=';' read -r port label owner <<<"$spec"
    [[ -z "$port" ]] && continue
    line="$(ss -Hltnp "sport = :$port" 2>/dev/null | head -1 || true)"
    name=""; pid=""; unit=""; container=""
    if [[ -n "$line" ]]; then
      name="$(sed -nE 's/.*users:\(\("([^"]+)".*/\1/p' <<<"$line")"
      pid="$(sed -nE 's/.*pid=([0-9]+).*/\1/p' <<<"$line")"
      # Legit owner already listening (a re-run) → not a conflict.
      [[ -n "$name" && "$name" =~ $owner ]] && continue
      [[ -n "$pid" ]] && unit="$(grep -aoE '[a-zA-Z0-9@._-]+\.service' "/proc/$pid/cgroup" 2>/dev/null | tail -1 || true)"
    fi
    if [[ "$have_docker" == "1" ]]; then
      container="$(docker ps --format '{{.Names}};{{.Ports}}' 2>/dev/null | awk -F';' -v p=":$port->" 'index($2,p){print $1; exit}' || true)"
    fi
    [[ -z "$line" && -z "$container" ]] && continue  # port free
    holder="${name:-unknown}"
    [[ -n "$container" && ( -z "$name" || "$name" == "docker-proxy" ) ]] && holder="docker container '$container'"
    conflicts+=("$port;$label;$holder;$pid;$unit;$container")
  done

  if [[ ${#conflicts[@]} -eq 0 ]]; then
    step "Ports" "$(for spec in "${PREFLIGHT_SPECS[@]}"; do printf '%s ' "${spec%%;*}"; done)are free (or already Hyperion's)"
    return 0
  fi

  end_begun
  printf '\033[31m[hyperion]\033[0m Port pre-flight found %d conflict(s) — required ports already in use:\n' "${#conflicts[@]}" >&2
  local c cport clabel cholder cpid cunit ccont
  for c in "${conflicts[@]}"; do
    IFS=';' read -r cport clabel cholder cpid cunit ccont <<<"$c"
    printf '  \033[31m✗\033[0m %-5s %-18s held by %s%s%s\n' \
      "$cport" "$clabel" "$cholder" "${cpid:+ (pid $cpid)}" "${cunit:+ [unit: $cunit]}" >&2
  done

  if [[ "${HYPERION_ALLOW_SHARED:-}" == "1" ]]; then
    log "HYPERION_ALLOW_SHARED=1 — continuing anyway (those services may fail to bind)."
    return 0
  fi
  [[ "${HYPERION_PREFLIGHT_ONLY:-}" == "1" ]] && fail "Resolve the conflict(s) above before installing."

  local choice=""
  if [[ "${HYPERION_STOP_CONFLICTS:-}" == "1" ]]; then
    choice="s"
  elif [[ -r /dev/tty ]]; then
    { printf '\nHyperion needs these ports. [s] STOP the holder(s) above and continue, '
      printf 'or [a] ABORT and free them yourself.\nChoose [s/a] (default a): '; } > /dev/tty
    IFS= read -r choice < /dev/tty || choice="a"
  else
    choice="a"
  fi

  case "$choice" in
    s|S|y|Y)
      for c in "${conflicts[@]}"; do
        IFS=';' read -r cport clabel cholder cpid cunit ccont <<<"$c"
        if [[ -n "$ccont" ]]; then
          log "Stopping docker container '$ccont' (frees port $cport)…"
          docker stop "$ccont" >/dev/null || fail "could not stop container '$ccont' — resolve manually."
        elif [[ -n "$cunit" ]]; then
          log "Stopping systemd unit '$cunit' (frees port $cport)…"
          systemctl stop "$cunit" || fail "could not stop '$cunit' — resolve manually."
        elif [[ -n "$cpid" ]]; then
          log "Terminating pid $cpid ($cholder) on port $cport…"
          kill "$cpid" 2>/dev/null || true; sleep 2
          if kill -0 "$cpid" 2>/dev/null; then kill -9 "$cpid" 2>/dev/null || true; fi
        else
          fail "port $cport is held but the holder can't be stopped automatically — resolve manually."
        fi
      done
      sleep 1
      local -a leftover=()
      for c in "${conflicts[@]}"; do
        IFS=';' read -r cport _ <<<"$c"
        [[ -n "$(ss -Hltnp "sport = :$cport" 2>/dev/null | head -1 || true)" ]] && leftover+=("$cport")
      done
      [[ ${#leftover[@]} -gt 0 ]] && fail "ports still in use after stop: ${leftover[*]} — resolve manually and re-run."
      log "Conflicts cleared — continuing."
      ;;
    *)
      fail "Aborting so you can free the port(s) above.
       Stop the listed process / container / unit, then re-run this installer. Or use:
         HYPERION_STOP_CONFLICTS=1  auto-stop the holders
         HYPERION_ALLOW_SHARED=1    ignore and proceed (risky — services may fail to bind)
         HYPERION_PREFLIGHT_ONLY=1  just check, install nothing"
      ;;
  esac
}

# ── this box's addresses ──────────────────────────────────────────────────
# SANS: every global address plus the FQDN — what the self-signed certificate
# is issued for, so the browser's warning page shows a certificate that at
# least names the address the operator typed. PRIMARY: the one address the
# printed link uses — the source address of the default route, i.e. the one
# this box talks to the internet from.
SANS=()
add_san() {
  local s
  for s in ${SANS[@]+"${SANS[@]}"}; do [[ "$s" == "$1" ]] && return 0; done
  SANS+=("$1")
}
collect_addresses() {
  local a h
  SANS=()
  while read -r a; do
    a="${a%%/*}"
    [[ -n "$a" ]] && add_san "$a"
  done < <(ip -o addr show scope global 2>/dev/null | awk '{print $4}' || true)
  h="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
  if [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$h" != localhost* ]]; then
    add_san "$h"
  fi

  PRIMARY="$(ip -4 route get 1.1.1.1 2>/dev/null \
    | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  # IPv6-only box: same question, asked of the v6 table.
  [[ -z "$PRIMARY" ]] && PRIMARY="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null \
    | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  [[ -z "$PRIMARY" && ${#SANS[@]} -gt 0 ]] && PRIMARY="${SANS[0]}"
  [[ -z "$PRIMARY" ]] && PRIMARY="$(hostname -f 2>/dev/null || hostname)"
  return 0
}

# RFC 1918 / CGNAT / IPv6 ULA: a link built on one of these only works from
# inside the same network, which on a cloud VM behind 1:1 NAT is never where
# the operator's browser is.
is_private_address() {
  [[ "$1" =~ ^10\. || "$1" =~ ^192\.168\. || "$1" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. \
     || "$1" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. || "${1,,}" =~ ^f[cd][0-9a-f]{2}: ]]
}

# ── setup mode ────────────────────────────────────────────────────────────
# `hyperion-web setup-init` / `setup-link` print KEY=VALUE lines (SETUP_URL,
# SETUP_CODE, CERT_SHA256, EXPIRES_HOURS) and exit 3 when setup is already
# finished. Anything else on stdout (log lines) is ignored.
parse_setup_output() {
  local line
  SETUP_URL=""; SETUP_CODE=""; CERT_SHA256=""; EXPIRES_HOURS=""
  while IFS= read -r line; do
    line="${line%$'\r'}"
    case "$line" in
      SETUP_URL=*)     SETUP_URL="${line#*=}" ;;
      SETUP_CODE=*)    SETUP_CODE="${line#*=}" ;;
      CERT_SHA256=*)   CERT_SHA256="${line#*=}" ;;
      EXPIRES_HOURS=*) EXPIRES_HOURS="${line#*=}" ;;
    esac
  done <<<"$1"
  [[ -n "$SETUP_URL" ]]
}

print_setup_banner() {
  end_begun
  echo
  echo "  The panel is waiting for you. Open this link to finish setup:"
  echo
  printf '    \033[1m%s\033[0m\n' "$SETUP_URL"
  echo
  echo "  (https:// is required — the panel speaks only TLS.)"
  if [[ -n "$CERT_SHA256" ]]; then
    echo "  The browser will warn about the certificate. Check it matches:"
    echo "    SHA-256  $CERT_SHA256"
  fi
  echo
  echo "  The link works once and expires in ${EXPIRES_HOURS:-24} hours."
  [[ -n "$SETUP_CODE" ]] && echo "  Setup code: $SETUP_CODE   (already in the link — type it if the page asks)"
  echo "  Lost it?  hyperion setup-link   prints a new one."
  if is_private_address "$PRIMARY"; then
    echo
    echo "  $PRIMARY is a private address. If your browser is not on this server's"
    echo "  network, put the server's public IP in its place — the link works on any"
    echo "  address the server answers on."
  fi
  echo
}

# Is there an admin already? The old installer's bootstrap admin lives in
# web-admin.json; one created by the setup wizard is a row in web_users. Either
# means this box is in use.
admin_exists() {
  [[ -f /etc/hyperion/web-admin.json ]] && return 0
  [[ -f "$STATE_DB" ]] && command -v sqlite3 >/dev/null 2>&1 || return 1
  local n
  n="$(sqlite3 -readonly "$STATE_DB" ".timeout 3000" "SELECT COUNT(*) FROM web_users;" 2>/dev/null || true)"
  [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 ))
}

# pending | completed | "" (no setup file = never in setup mode)
setup_state() {
  [[ -f "$SETUP_FILE" ]] || return 0
  if grep -Eq '"state"[[:space:]]*:[[:space:]]*"pending"' "$SETUP_FILE" 2>/dev/null; then
    printf 'pending'
  elif grep -Eq '"state"[[:space:]]*:[[:space:]]*"completed"' "$SETUP_FILE" 2>/dev/null; then
    printf 'completed'
  fi
  return 0
}

wait_for() {  # wait_for <seconds> <cmd...>
  local n="$1"; shift
  while (( n-- > 0 )); do
    "$@" && return 0
    sleep 1
  done
  "$@"
}
agent_ready() { systemctl --quiet is-active hyperion-agent && [[ -S "$AGENT_SOCKET" ]]; }
web_ready() {
  systemctl --quiet is-active hyperion-web || return 1
  command -v ss >/dev/null 2>&1 || return 0
  [[ -n "$(ss -Hltn "sport = :$LISTEN_PORT" 2>/dev/null)" ]]
}
start_agent() {
  systemctl enable --now hyperion-agent >> "$INSTALL_LOG" 2>&1 || true
  wait_for 30 agent_ready \
    || fail "hyperion-agent did not come up. Look at: journalctl -u hyperion-agent -n 50"
}
start_web() {
  systemctl enable --now hyperion-web >> "$INSTALL_LOG" 2>&1 || true
  wait_for 20 web_ready \
    || fail "hyperion-web did not come up on port $LISTEN_PORT. Look at: journalctl -u hyperion-web -n 50"
}

already_installed() {
  local u
  for u in hyperion-agent hyperion-web; do
    systemctl enable --now "$u" >/dev/null 2>&1 || true
  done
  end_begun
  echo
  echo "  Hyperion is already installed here — run \`hyperion update\` to update it."
  command -v hyperion >/dev/null 2>&1 \
    || echo "  (No \`hyperion\` command on this box yet: $INSTALL_DIR/packaging/install/update.sh)"
  echo
  exit 0
}

# Setup was started on an earlier run and never finished. Starting over would
# change nothing, so bring the services up and hand out a fresh link.
resume_setup() {
  local out rc=0
  [[ -n "$ADMIN_PASS" ]] && warn "Setup is already under way on this box — HYPERION_ADMIN_PASS is ignored."
  start_agent
  collect_addresses
  if admin_exists; then
    # The admin step is done, so a setup code would open nothing: the wizard
    # continues after a normal sign-in.
    start_web
    echo
    echo "  Setup is under way and its admin account exists. Sign in to finish it:"
    echo
    printf '    \033[1mhttps://%s:%s/\033[0m\n' "$(url_host "$PRIMARY")" "$LISTEN_PORT"
    echo
    exit 0
  fi
  out="$(RUST_LOG=warn /usr/sbin/hyperion-web --config "$WEB_TOML" setup-link --host "$PRIMARY" 2>&1)" || rc=$?
  case "$rc" in
    0) parse_setup_output "$out" || fail "hyperion-web setup-link printed no link:
$out" ;;
    3) already_installed ;;
    *) fail "hyperion-web setup-link failed (exit $rc):
$out" ;;
  esac
  start_web
  print_setup_banner
  exit 0
}

#-------- 1. Root + OS -----------------------------------------------------
[[ $EUID -eq 0 ]] || fail "Run me as root."
. /etc/os-release || fail "/etc/os-release missing — not a Debian-family box?"
[[ "${ID:-}" == "debian" ]] || fail "Debian required (got '${ID:-unknown}')."
VERSION_ID="${VERSION_ID:-}"   # absent on testing/sid
[[ "$VERSION_ID" =~ ^[0-9]+ ]] && (( ${VERSION_ID%%.*} >= 12 )) \
  || fail "Debian 12+ required (got ${VERSION_ID:-no VERSION_ID})."
ARCH="$(uname -m)"
export DEBIAN_FRONTEND=noninteractive

# Panel port. A re-run must use the port this box was installed with, not the
# default, or the pre-flight would check (and the messages would name) the
# wrong one.
if [[ -z "$LISTEN" && -f "$WEB_TOML" ]]; then
  LISTEN="$(sed -nE 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$WEB_TOML" | head -1)"
fi
LISTEN="${LISTEN:-0.0.0.0:8443}"
LISTEN_PORT="${LISTEN##*:}"
# Both end up inside TOML strings — a quote or backslash would break the file.
listen_re='^[^"\\[:space:]]+:[0-9]{1,5}$'
[[ "$LISTEN" =~ $listen_re ]] && (( 10#$LISTEN_PORT >= 1 && 10#$LISTEN_PORT <= 65535 )) \
  || fail "HYPERION_LISTEN must look like 0.0.0.0:8443 (got '$LISTEN')."
email_re='^[^"\\[:space:]]*$'
[[ "$CONTACT_EMAIL" =~ $email_re ]] || fail "HYPERION_ACME_EMAIL is not an email address: '$CONTACT_EMAIL'"

echo
echo "  Installing Hyperion on $(hostname) — Debian ${VERSION_ID}, ${ARCH}"
echo

#-------- 2. Port pre-flight -----------------------------------------------
# Only what every install needs. The FTP / database ports used to be checked
# here too, but which of those this box will run is now decided in the wizard;
# the agent checks a port before it starts a service on it.
PREFLIGHT_SPECS=(
  "80;nginx (HTTP);^nginx$"
  "443;nginx (HTTPS);^nginx$"
  "${LISTEN_PORT};Hyperion panel;^hyperion-web$"
)
port_preflight
[[ "${HYPERION_PREFLIGHT_ONLY:-}" == "1" ]] && { log "Pre-flight only — nothing installed."; exit 0; }

install -d -m 0750 /var/log/hyperion
touch "$INSTALL_LOG" && chmod 0600 "$INSTALL_LOG"
printf '\n===== install-master.sh %s =====\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$INSTALL_LOG"

#-------- 2b. Already installed? -------------------------------------------
# Checked before anything is touched. A box with an admin is in use: swapping
# its binaries here would bypass everything `hyperion update` exists for
# (waiting for running jobs, the version check, the heals), so this script
# only makes sure the services run and says where to go instead.
SETUP_STATE="$(setup_state)"
if [[ "$SETUP_STATE" == "completed" ]] || { [[ "$SETUP_STATE" != "pending" ]] && admin_exists; }; then
  already_installed
fi
[[ "$SETUP_STATE" == "pending" ]] && resume_setup

#-------- 3. Base packages -------------------------------------------------
begin "Installing base packages"
quietly apt-get -q update || fail "apt-get update failed — see the lines above."
# PHP's mail() → hyperion's site-mail wrapper → /usr/sbin/sendmail. Debian
# ships no MTA, so without one every mail() returns false. postfix as
# "Internet Site" delivers by direct MX lookup; a network that blocks outbound
# :25 needs a relayhost later (Settings → Mail). Preseeded so the install
# never stops to ask. Only when no MTA is there: installing postfix next to an
# existing exim4 would REMOVE exim4 and whatever mail setup it carries.
BASE_PKGS=(
  curl ca-certificates gnupg git iproute2
  # sudo is NOT optional: every wp-cli call is "sudo -u <site user> wp …",
  # which is how the root agent drops to the site's uid. A minimal Debian
  # has no sudo, and its absence surfaces as "io: No such file or
  # directory" — a message that points at the site, not at the box.
  sudo
  # restic backs the snapshot engine: a content-addressed, deduplicated
  # copy taken before anything changes a site, and the only way to answer
  # "what did last night's update actually change?". Without it the
  # snapshot code is inert and sites fall back to archive backups.
  restic
  # sqlite3 is how update.sh sees whether a job is running, so it can wait
  # for it instead of killing it — and how this script sees whether the box
  # already has an admin. update.sh heals a missing one, but a fresh install
  # should not depend on that.
  sqlite3
  # dig: every DNS card in the panel (SPF, DKIM, the pre-flight banner).
  bind9-dnsutils
  nginx
)
if [[ ! -x /usr/sbin/sendmail ]]; then
  echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
  echo "postfix postfix/mailname string $(hostname -f 2>/dev/null || hostname)" | debconf-set-selections
  BASE_PKGS+=(postfix)
fi
quietly apt-get install -y -q -o DPkg::Lock::Timeout=300 "${BASE_PKGS[@]}" \
  || fail "Installing the base packages failed — see the lines above."
systemctl enable --now nginx >> "$INSTALL_LOG" 2>&1 || true
if systemctl cat postfix.service >/dev/null 2>&1; then
  systemctl enable --now postfix >> "$INSTALL_LOG" 2>&1 || true
fi
step "Base packages" "nginx, postfix, sudo, restic, sqlite3, git, dig"

#-------- 4. Source checkout + PHP package source --------------------------
# The checkout is not what runs (that is the binaries below); it carries the
# systemd units, the install scripts and update.sh, which `hyperion update`
# runs from here.
SOURCE_DESC=""
acquire_source() {
  # 4a. Local tarball — air-gapped / pre-downloaded installs.
  if [[ -n "$LOCAL_TARBALL" ]]; then
    [[ -f "$LOCAL_TARBALL" ]] || fail "HYPERION_LOCAL_TARBALL not found: $LOCAL_TARBALL"
    install -d -m 0755 "$INSTALL_DIR"
    quietly tar -xzf "$LOCAL_TARBALL" -C "$INSTALL_DIR" --strip-components=1 \
      || fail "could not extract $LOCAL_TARBALL"
    SOURCE_DESC="extracted $(basename "$LOCAL_TARBALL")"
    return
  fi

  # 4b. Pre-cloned directory (operator did the clone with their creds).
  if [[ -n "$SKIP_CLONE" || -d "$INSTALL_DIR/.git" ]]; then
    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
      fail "HYPERION_SKIP_CLONE=1 but $INSTALL_DIR/.git not present."
    fi
    SOURCE_DESC="existing checkout"
    return
  fi

  # 4c. PAT-via-credential-helper. Token stays in env; never appears on argv.
  if [[ -n "$GIT_TOKEN" ]]; then
    GIT_ASKPASS="$(mktemp /tmp/hyp-askpass.XXXXXX)"
    export GIT_ASKPASS
    CLEANUP_PATHS+=("$GIT_ASKPASS")
    cat > "$GIT_ASKPASS" <<'EOF'
#!/bin/sh
case "$1" in
  Username*) printf 'oauth2\n' ;;
  Password*) printf '%s\n' "$HYPERION_GIT_TOKEN" ;;
esac
EOF
    chmod 0700 "$GIT_ASKPASS"
    quietly git -c core.askPass="$GIT_ASKPASS" clone --depth=1 --branch "$REF" \
      "$GIT_URL" "$INSTALL_DIR" || fail "git clone of $GIT_URL ($REF) failed — check HYPERION_GIT_TOKEN."
    SOURCE_DESC="$REF, cloned with a token"
    return
  fi

  # 4d. Plain clone (works for public repos OR with SSH agent + git@github.com URL).
  quietly git clone --depth=1 --branch "$REF" "$GIT_URL" "$INSTALL_DIR" || {
    fail "git clone failed. For a private repo set HYPERION_GIT_TOKEN
       (HTTPS PAT) or HYPERION_GIT_URL=git@github.com:nechodom/hyperion
       (SSH with agent forwarding), or pre-clone into $INSTALL_DIR and
       re-run with HYPERION_SKIP_CLONE=1."
  }
  SOURCE_DESC="$REF"
}

begin "Fetching the source"
acquire_source
cd "$INSTALL_DIR"
COMPONENTS_SH="$INSTALL_DIR/packaging/install/components.sh"
[[ -f "$COMPONENTS_SH" ]] || fail "$COMPONENTS_SH is missing — is $INSTALL_DIR a Hyperion checkout of a recent enough version?"
step "Source" "$INSTALL_DIR ($SOURCE_DESC)"

# deb.sury.org: the PHP versions the wizard offers. Not fatal — installing PHP
# runs the same step again, so a sury hiccup now is retried there.
begin "Adding the PHP package source"
if quietly bash "$COMPONENTS_SH" --prepare; then
  step "PHP packages" "deb.sury.org ($( . /etc/os-release; echo "${VERSION_CODENAME:-bookworm}" ))"
else
  step_failed "PHP packages" "deb.sury.org could not be added now — installing PHP will retry it"
fi

#-------- 5. Binaries --------------------------------------------------------
# Pre-built by CI for x86_64 (the `rolling` release follows main). Building on
# the box needs a Rust toolchain, ~2 GB of RAM and 5–15 minutes; downloading
# takes seconds, which is most of the difference between a two-minute install
# and a coffee break. Every file is checked against SHA256SUMS before it is
# installed; any failure falls back to the source build rather than to an
# unverified binary.
BIN_DESC=""
install_prebuilt() {
  if [[ "$ARCH" != "x86_64" ]]; then
    log "No pre-built binaries for $ARCH — building from source instead."
    return 1
  fi
  if [[ "$BUILD_FROM_SOURCE" == "1" ]]; then
    log "HYPERION_BUILD_FROM_SOURCE=1 — building from source."
    return 1
  fi
  local tmp base f a
  tmp="$(mktemp -d /tmp/hyperion-install.XXXXXX)"
  CLEANUP_PATHS+=("$tmp")
  base="https://github.com/$RELEASE_REPO/releases/download/$RELEASE_TAG"
  for f in SHA256SUMS hyperion-agent hyperion-web hctl; do
    if ! curl -fsSL --retry 2 --max-time 120 -o "$tmp/$f" "$base/$f" 2>"$tmp/curl.err"; then
      log "Could not download $f from $base ($(head -c 200 "$tmp/curl.err" | tr -d '\n')) — building from source instead."
      return 1
    fi
  done
  # Only the lines for the files we fetched: the release lists more (the
  # exporters), and `sha256sum --check` on the whole file would report each
  # missing one as FAILED.
  if ! (
      cd "$tmp"
      for f in hyperion-agent hyperion-web hctl; do
        grep -E "[[:space:]]\\*?${f}\$" SHA256SUMS || { echo "  '$f' is not listed in SHA256SUMS" >&2; exit 1; }
      done | sha256sum --quiet --check - >> "$INSTALL_LOG" 2>&1
  ); then
    log "The downloaded binaries do not match the release's SHA256SUMS — building from source instead."
    return 1
  fi
  install -m 0755 "$tmp/hyperion-agent" /usr/sbin/hyperion-agent
  install -m 0755 "$tmp/hyperion-web"   /usr/sbin/hyperion-web
  install -m 0755 "$tmp/hctl"           /usr/bin/hctl

  # The self-service import exporter the panel serves to SOURCE servers. A
  # fresh master used to ship without it, so /import/agent-bin answered 404
  # until someone happened to run update.sh. Static musl builds, one per CPU
  # the source box may have; the x86_64 one doubles as the unsuffixed default.
  # Optional: a missing or mismatched one costs the import wizard, not the
  # install.
  install -d -m 0755 /usr/local/bin
  for a in x86_64 aarch64; do
    f="hyperion-export-$a"
    curl -fsSL --retry 2 --max-time 120 -o "$tmp/$f" "$base/$f" 2>/dev/null || continue
    if ( cd "$tmp" && grep -E "[[:space:]]\\*?${f}\$" SHA256SUMS | sha256sum --quiet --check - >/dev/null 2>&1 ); then
      install -m 0755 "$tmp/$f" "/usr/local/bin/$f"
      [[ "$a" == "x86_64" ]] && install -m 0755 "$tmp/$f" /usr/local/bin/hyperion-export
    else
      warn "$f is missing from or does not match SHA256SUMS — not installed (only the import wizard needs it)."
    fi
  done
  BIN_DESC="pre-built @$RELEASE_TAG, checksums verified"
  return 0
}

build_from_source() {
  begin "Building Hyperion from source (5–15 minutes — tail -f $INSTALL_LOG)"
  quietly apt-get install -y -q -o DPkg::Lock::Timeout=300 build-essential pkg-config \
    || fail "Installing the build tools failed — see the lines above."
  export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
  if ! command -v cargo >/dev/null 2>&1; then
    quietly sh -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable" || true
    command -v cargo >/dev/null 2>&1 || fail "Installing the Rust toolchain (rustup) failed — see the lines above."
  fi
  quietly cargo build --release --workspace \
    || fail "cargo build failed — see the lines above. On a box with little RAM, add swap and re-run."
  install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
  install -m 0755 target/release/hyperion-web   /usr/sbin/hyperion-web
  install -m 0755 target/release/hctl           /usr/bin/hctl
  # Host-glibc build of the exporter; `hyperion update` replaces it with the
  # static per-arch builds that an older source server actually needs.
  if [[ -x target/release/hyperion-export ]]; then
    install -d -m 0755 /usr/local/bin
    install -m 0755 target/release/hyperion-export /usr/local/bin/hyperion-export
  fi
  BIN_DESC="built from source"
}

begin "Downloading Hyperion"
install_prebuilt || build_from_source
HYP_VERSION="$(/usr/sbin/hyperion-agent --version 2>/dev/null | head -1 || true)"
step "Hyperion" "${HYP_VERSION:-installed} — $BIN_DESC"

#-------- 6. Commands --------------------------------------------------------
# The `hyperion` front-door command (`hyperion update`, `setup-link`, `logs`).
# update.sh installs this too, but a FRESH box must not need one manual
# full-path update.sh run before the short command everyone guesses first
# starts existing — that gap is exactly how "hyperion: command not found"
# gets reported from every new install.
install -d -m 0755 /usr/local/bin
install -m 0755 "$INSTALL_DIR/packaging/install/hyperion-wrapper.sh" /usr/local/bin/hyperion
# The sendmail_path of every PHP-FPM pool. Shipped only by update.sh before,
# so on a fresh box every site's mail() failed ("site-mail-wrapper: not
# found") until the first update. 1777 + sticky on the log dir: the wrapper
# runs AS each site user and creates its own <user>.jsonl there.
if [[ -f "$INSTALL_DIR/packaging/install/site-mail-wrapper.sh" ]]; then
  install -d -m 0755 /usr/local/lib/hyperion
  install -m 0755 "$INSTALL_DIR/packaging/install/site-mail-wrapper.sh" /usr/local/lib/hyperion/site-mail-wrapper
  install -d -m 1777 /var/lib/hyperion/site-mail
  chmod 1777 /var/lib/hyperion/site-mail
fi

#-------- 7. Users, directories, config ------------------------------------
groupadd --system hyperion-admin 2>/dev/null || true
install -d -m 0700 /etc/hyperion
install -d -m 0700 /etc/hyperion/secrets
# 0o711 — owner full, others traverse-only. NOT 0o700: nginx
# (www-data) needs the x-bit to traverse this dir on the way to
# /var/lib/hyperion/acme-challenges/<token> for HTTP-01 ACME. The
# sensitive content (state.db, secrets/, backups/) keeps its own
# 0o600/0o700 perms — listing the dir reveals only well-known names.
install -d -m 0711 /var/lib/hyperion
install -d -m 0750 /var/log/hyperion
install -d -m 0755 /var/lib/hyperion/acme-challenges
install -d -m 0700 /var/lib/hyperion/backups/local

# contact_email is left EMPTY when HYPERION_ACME_EMAIL is not given — the
# wizard's "Server identity" step fills it in. The old `admin@example.com`
# placeholder was sent to Let's Encrypt as-is, which it refuses.
if [[ ! -f /etc/hyperion/agent.toml ]]; then
  cat > /etc/hyperion/agent.toml <<EOF
[agent]
socket_path  = "$AGENT_SOCKET"
socket_group = "hyperion-admin"
state_db     = "$STATE_DB"
secrets_dir  = "/etc/hyperion/secrets"
log_path     = "/var/log/hyperion/agent.log"
home_root    = "/home"
backup_root  = "/var/lib/hyperion/backups/local"

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
contact_email = "${CONTACT_EMAIL}"
challenge_dir = "/var/lib/hyperion/acme-challenges"

# Optional remote backup destination. Pushed AFTER the local archive is
# written (local copy always kept). Supports ftp / ftps / sftp via curl.
# Per-hosting subdir is appended to base_path automatically.
[backup_remote]
enabled  = false
scheme   = "ftp"
host     = "backup.example.com"
port     = 21
user     = "hyperion"
password = ""
base_path = "/hyperion-backups"

# Backup retention. After each successful local backup, archives older
# than max_age_days are deleted, but the newest keep_latest_n per
# hosting are ALWAYS retained.
[backup_retention]
max_age_days  = 30
keep_latest_n = 5

# Default Slack incoming webhook. Used for billing reminders, backup
# failures, cert renewals. Per-profile webhooks (defined in
# /profiles in the UI) override this.
[slack]
default_webhook = ""

# Transactional email (send-only). Use any production SMTP relay:
# Postmark, SendGrid, Mailgun, Brevo (free 300/day), AWS SES, or a
# self-hosted postfix-with-auth. Direct-from-VPS sends to public
# mailboxes will land in spam — always go through a relay.
[email]
enabled       = false
smtp_host     = "smtp.example.com"
smtp_port     = 587
smtp_user     = ""
smtp_password = ""
from_address  = "hyperion@example.com"
from_name     = "Hyperion"
security      = "starttls"   # "starttls" (587) | "tls" (465) | "plain" (dev only)
default_to    = ""           # cluster-wide ops address for hostings with no owner_email
EOF
fi

if [[ ! -f "$WEB_TOML" ]]; then
  cat > "$WEB_TOML" <<EOF
[web]
listen               = "$LISTEN"
agent_socket         = "$AGENT_SOCKET"
admin_user_file      = "/etc/hyperion/web-admin.json"
session_key_file     = "/etc/hyperion/web-session.key"
csrf_key_file        = "/etc/hyperion/web-csrf.key"
session_ttl_secs     = 28800
# TLS enabled by default; hyperion-web auto-generates a self-signed cert
# at first boot. Replace fullchain.pem + privkey.pem with a real LE cert
# any time and restart hyperion-web. Cookies need Secure=true under TLS.
secure_cookies       = true
session_cookie_name  = "hyperion_session"
tls_enabled          = true
tls_cert_file        = "/etc/hyperion/web-tls/fullchain.pem"
tls_key_file         = "/etc/hyperion/web-tls/privkey.pem"
EOF
fi
chmod 0600 /etc/hyperion/agent.toml "$WEB_TOML"

# TLS cert directory — agent runs as root and writes through ReadWritePaths.
install -d -m 0700 /etc/hyperion/web-tls

for unit in hyperion-agent hyperion-web; do
  src="$INSTALL_DIR/packaging/systemd/${unit}.service"
  if [[ -f "$src" ]]; then
    install -m 0644 "$src" "/etc/systemd/system/${unit}.service"
  fi
done
systemctl daemon-reload

# Per-version /run/php/<ver>/ subdirs for FPM sockets. Without this
# reboot wipes /run/* and PHP-FPM fails to open its per-pool socket on
# the next boot → nginx returns 502. Installed BEFORE any PHP: components.sh
# materializes the dirs right after it installs a PHP version, so the first
# hosting create after setup works.
tmpfiles_src="$INSTALL_DIR/packaging/systemd/hyperion-php-fpm-runtime.conf"
if [[ -f "$tmpfiles_src" ]]; then
  install -m 0644 "$tmpfiles_src" /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf
  systemd-tmpfiles --create /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf >> "$INSTALL_LOG" 2>&1 || true
fi

# The systemd unit runs hyperion-web with ProtectSystem=full, which makes
# /etc read-only for the service. hyperion-web's keys::load_or_init would
# happily create these on first start in a writable environment, but here
# the sandbox blocks the write. We materialize them ahead of time so the
# running service only ever has to READ them.
gen_key_file() {
  local path="$1"
  if [[ -f "$path" ]]; then return 0; fi
  install -m 0600 /dev/null "$path"
  head -c 32 /dev/urandom | base64 -w 0 > "$path"
}
gen_key_file /etc/hyperion/web-session.key
gen_key_file /etc/hyperion/web-csrf.key
step "Configuration" "/etc/hyperion, systemd units, keys"

#-------- 8a. Unattended mode ----------------------------------------------
if [[ -n "$ADMIN_PASS" ]]; then
  COMPONENTS="${HYPERION_COMPONENTS:-}"
  if [[ -z "$COMPONENTS" ]]; then
    # The historical full set, with the old opt-out switches still honoured.
    COMPONENTS="php8.3"
    [[ "$(norm_bool "${HYPERION_WITH_MARIADB:-}")"  != "0" ]] && COMPONENTS+=" mariadb"
    [[ "$(norm_bool "${HYPERION_WITH_POSTGRES:-}")" != "0" ]] && COMPONENTS+=" postgresql"
    [[ "$(norm_bool "${HYPERION_WITH_VSFTPD:-}")"   != "0" ]] && COMPONENTS+=" vsftpd"
    COMPONENTS+=" phpmyadmin"
  fi
  read -r -a COMPONENT_LIST <<<"${COMPONENTS//,/ }"

  begin "Installing ${COMPONENT_LIST[*]} (a few minutes)"
  PROGRESS="$(mktemp /tmp/hyperion-components.XXXXXX)"
  CLEANUP_PATHS+=("$PROGRESS")
  comp_rc=0
  HYP_PROGRESS_FILE="$PROGRESS" quietly bash "$COMPONENTS_SH" --ftp-port "$FTP_PORT" "${COMPONENT_LIST[@]}" \
    || comp_rc=$?
  (( comp_rc == 2 )) && fail "HYPERION_COMPONENTS / HYPERION_FTP_PORT were refused — see the lines above."
  while read -r comp comp_state; do
    case "$comp_state" in
      done)   step "$comp" "installed" ;;
      failed) step_failed "$comp" "failed — see $INSTALL_LOG" ;;
    esac
  done < "$PROGRESS"
  (( comp_rc == 0 )) || warn "Not everything installed. Fix the cause, then re-run:
         bash $COMPONENTS_SH <the failed ones>"

  # The password reaches hyperion-web on stdin (its prompt reads it from
  # there), never on argv: /proc/<pid>/cmdline is world-readable, and this
  # box is about to host other people's code.
  if [[ ! -f /etc/hyperion/web-admin.json ]]; then
    printf '%s\n' "$ADMIN_PASS" \
      | quietly /usr/sbin/hyperion-web --config "$WEB_TOML" bootstrap --username "$ADMIN_USER" \
      || fail "Creating the admin user failed — see the lines above."
  fi

  begin "Starting Hyperion"
  start_agent
  start_web
  step "Services" "hyperion-agent, hyperion-web"

  collect_addresses
  echo
  echo "  Hyperion is installed."
  echo
  printf '    Panel   \033[1mhttps://%s:%s/\033[0m   (https:// is required)\n' "$(url_host "$PRIMARY")" "$LISTEN_PORT"
  echo "    Admin   $ADMIN_USER"
  echo "    CLI     hyperion help · hctl info   (sudo usermod -aG hyperion-admin \$USER for non-root use)"
  echo "    Logs    journalctl -u hyperion-agent -u hyperion-web · $INSTALL_LOG"
  echo
  echo "  The certificate is self-signed until you set a panel domain"
  echo "  (Settings → Panel & updates → Panel domain)."
  echo
  exit 0
fi

#-------- 8b. Setup wizard ---------------------------------------------------
# An EMPTY components file = "the operator chooses what to install, and has
# not chosen anything yet". update.sh then heals only what is listed in it —
# without the file it would re-install MariaDB, PostgreSQL, vsftpd and PHP on
# the next update, whatever the wizard was told.
[[ -f /etc/hyperion/components ]] || install -m 0644 /dev/null /etc/hyperion/components

begin "Starting Hyperion"
start_agent
collect_addresses
INIT_ARGS=(--config "$WEB_TOML" setup-init --port "$LISTEN_PORT" --host "$PRIMARY")
for s in ${SANS[@]+"${SANS[@]}"}; do INIT_ARGS+=(--san "$s"); done
init_rc=0
INIT_OUT="$(RUST_LOG=warn /usr/sbin/hyperion-web "${INIT_ARGS[@]}" 2>&1)" || init_rc=$?
case "$init_rc" in
  0) parse_setup_output "$INIT_OUT" || fail "hyperion-web setup-init printed no setup link:
$INIT_OUT" ;;
  3) already_installed ;;
  *) fail "hyperion-web setup-init failed (exit $init_rc):
$INIT_OUT" ;;
esac
start_web
step "Panel" "listening on :$LISTEN_PORT"

print_setup_banner
