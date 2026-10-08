#!/usr/bin/env bash
# Install the optional server software Hyperion manages — the one copy of
# "install a component".
#
# Two callers, one script, so the two can never drift apart:
#   * install-master.sh: `--prepare` on every install, and the full install in
#     unattended mode (HYPERION_ADMIN_PASS set).
#   * hyperion-agent, for the setup wizard's "Server software" step. The agent
#     embeds this file (include_str!), writes it next to phpmyadmin.sh into
#     /var/lib/hyperion/setup-stack/ and runs it as the transient unit
#     hyperion-setup-stack.service — root, no sandbox, no source checkout. So
#     nothing in here may reach into /opt/hyperion: the only other file it
#     uses is phpmyadmin.sh, found NEXT TO this one.
#
# Usage (as root):
#   components.sh --prepare
#       Point apt at deb.sury.org for this Debian release and refresh the
#       package lists. Installs nothing.
#   components.sh [--ftp-port N] COMPONENT...
#       COMPONENT is one of: php8.1 php8.2 php8.3 php8.4 mariadb postgresql
#       redis vsftpd phpmyadmin. Duplicates are fine. They always run in that
#       order, whatever order they were given in — PHP first because
#       phpMyAdmin needs it, phpMyAdmin last because it is useless without a
#       PHP and a database server underneath it.
#       --ftp-port sets vsftpd's control port (default 21). Without the flag an
#       already-configured vsftpd keeps whatever port it has.
#
# Exit codes: 0 everything requested is installed · 1 at least one component
# failed (the rest were still attempted) · 2 bad usage, nothing was touched.
#
# Contract with the agent (keep it exact — setup_stack.rs parses it):
#   * HYP_PROGRESS_FILE, when set, is rewritten atomically on EVERY state
#     change: one `<component> <state>` line per requested component, in run
#     order, state ∈ pending|running|done|failed.
#   * Each component that installs successfully is appended to
#     /etc/hyperion/components (sorted, unique). update.sh heals only what that
#     file lists, so a box keeps exactly the software its operator chose.
#   * stdout is a human log; every section starts with `==> <component>: `.
#     The panel shows its tail, so it must read as an explanation, not a
#     dump — and apt runs with -q, NOT -qq: when a package fails, the operator
#     has to see apt's real error, not just "failed".
#
# A failed component does not stop the others. One broken mirror for
# PostgreSQL is no reason to leave a box without PHP, and the wizard can only
# offer "retry the failed ones" if the successful ones actually happened.
set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")"
PMA_SCRIPT="$SCRIPT_DIR/phpmyadmin.sh"

COMPONENTS_FILE="${HYPERION_COMPONENTS_FILE:-/etc/hyperion/components}"
PROGRESS_FILE="${HYP_PROGRESS_FILE:-}"

# Run order AND allow-list. Mirrors COMPONENT_ORDER in
# crates/hyperion-adapters/src/setup_stack.rs — change both together.
ALL_COMPONENTS=(php8.1 php8.2 php8.3 php8.4 mariadb postgresql redis vsftpd phpmyadmin)

SURY_KEYRING="/etc/apt/keyrings/sury-php.gpg"
SURY_LIST="/etc/apt/sources.list.d/sury-php.list"
SURY_KEY_URL="https://packages.sury.org/php/apt.gpg"
PHP_TMPFILES="/etc/tmpfiles.d/hyperion-php-fpm-runtime.conf"
WP_CLI="/usr/local/bin/wp"
WP_CLI_URL="https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
VSFTPD_CONF="/etc/vsftpd.conf"
VSFTPD_CONF_ORIG="/etc/vsftpd.conf.hyperion-orig"
VSFTPD_USER_CONF_DIR="/etc/vsftpd/user_conf"
SHELLS_FILE="/etc/shells"
PMA_NGINX_CONF="/etc/nginx/conf.d/hyperion-pma.conf"
PMA_CURRENT="/usr/share/hyperion-pma/current"

export DEBIAN_FRONTEND=noninteractive

# Colour only for a person at a terminal. Under the agent stdout is a log file
# the panel shows verbatim, where escape codes would be litter.
if [[ -t 1 ]]; then C_ON=$'\033[1;36m'; C_BAD=$'\033[1;31m'; C_OFF=$'\033[0m'
else C_ON=""; C_BAD=""; C_OFF=""; fi

log()     { printf '%s\n' "$*"; }
section() { printf '%s==> %s%s\n' "$C_ON" "$*" "$C_OFF"; }
warn()    { printf '%sWARN:%s %s\n' "$C_BAD" "$C_OFF" "$*"; }

usage() {
  cat <<'EOF'
Usage: components.sh --prepare
       components.sh [--ftp-port N] COMPONENT...

Components: php8.1 php8.2 php8.3 php8.4 mariadb postgresql redis vsftpd phpmyadmin
EOF
}
usage_error() { printf 'components.sh: %s\n\n' "$*" >&2; usage >&2; exit 2; }

is_component() {
  local c
  for c in "${ALL_COMPONENTS[@]}"; do [[ "$c" == "$1" ]] && return 0; done
  return 1
}

elapsed() {  # seconds → "48s" / "3m 05s"
  local s="$1"
  if (( s >= 60 )); then printf '%dm %02ds' $(( s / 60 )) $(( s % 60 )); else printf '%ds' "$s"; fi
}

#-------- progress file -----------------------------------------------------
# Plain indexed arrays rather than an associative one: keeps this runnable by
# any bash a developer happens to test it with, and the list is nine long.
ORDERED=()   # requested components, deduplicated, in run order
STATES=()    # STATES[i] belongs to ORDERED[i]

write_progress() {
  [[ -n "$PROGRESS_FILE" ]] || return 0
  local tmp i
  # Same directory as the target, so the mv is a rename: the agent can never
  # read a half-written file. Best-effort — a progress file must never be the
  # reason an install fails.
  tmp="$(mktemp "$PROGRESS_FILE.XXXXXX" 2>/dev/null)" || return 0
  for i in "${!ORDERED[@]}"; do
    printf '%s %s\n' "${ORDERED[$i]}" "${STATES[$i]}"
  done > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
  chmod 0644 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$PROGRESS_FILE" 2>/dev/null || rm -f "$tmp"
  return 0
}

set_state() {  # set_state <component> <pending|running|done|failed>
  local i
  for i in "${!ORDERED[@]}"; do
    [[ "${ORDERED[$i]}" == "$1" ]] && STATES[i]="$2"
  done
  write_progress
}

#-------- the record update.sh reads ---------------------------------------
record_component() {
  local dir tmp
  dir="$(dirname "$COMPONENTS_FILE")"
  [[ -d "$dir" ]] || install -d -m 0700 "$dir" || return 1
  [[ -f "$COMPONENTS_FILE" ]] || install -m 0644 /dev/null "$COMPONENTS_FILE" || return 1
  tmp="$(mktemp "$COMPONENTS_FILE.XXXXXX")" || return 1
  if { cat "$COMPONENTS_FILE"; printf '%s\n' "$1"; } | sed '/^[[:space:]]*$/d' | sort -u > "$tmp"; then
    chmod 0644 "$tmp" && mv -f "$tmp" "$COMPONENTS_FILE" && return 0
  fi
  rm -f "$tmp"
  return 1
}

#-------- apt ---------------------------------------------------------------
APT_UPDATED=0

apt_update_once() {
  (( APT_UPDATED )) && return 0
  log "Refreshing the package lists ..."
  # A failed refresh is reported but not fatal: the cached lists are usually
  # good enough, and if they are not, the install that follows fails with the
  # error that actually matters.
  apt-get -q -o DPkg::Lock::Timeout=300 update \
    || warn "apt-get update reported errors — trying the install with the lists already on disk."
  APT_UPDATED=1
  return 0
}

apt_install() {
  apt_update_once
  # Lock timeout: a fresh cloud box is very often still running
  # unattended-upgrades when this starts; waiting five minutes beats failing
  # with "could not get lock". confold/confdef: never stop to ask about a
  # config file — there is nobody to answer, and keeping the operator's copy
  # is always the right call.
  apt-get install -y -q \
    -o DPkg::Lock::Timeout=300 \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    "$@"
}

#-------- deb.sury.org (PHP) ------------------------------------------------
# The suite MUST match this machine's Debian release. It was hardcoded to
# `bookworm`, so a Debian 13 (trixie) box pulled bookworm-built PHP whose
# `libzip4` dependency does not exist there — trixie ships libzip5 — and
# apt aborted the whole install with "held broken packages".
#
# Derived from os-release, with `bookworm` as the fallback for a
# derivative that reports its own codename (Ubuntu, Proxmox, Raspbian):
# sury publishes only Debian suites, so an unknown name must degrade to a
# real one rather than to a 404 repo.
sury_suite() {
  local suite
  suite="$( . /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}" )"
  case "$suite" in
    bookworm|trixie|forky) ;;
    *) suite="bookworm" ;;
  esac
  printf '%s' "$suite"
}

ensure_sury() {
  local suite line
  suite="$(sury_suite)"
  line="deb [signed-by=$SURY_KEYRING] https://packages.sury.org/php/ ${suite} main"
  install -d -m 0755 "$(dirname "$SURY_KEYRING")" || return 1
  # Downloaded to a temp name and renamed: a download cut off half-way used
  # to leave an empty keyring behind, and since "the keyring exists" was the
  # test for "already done", no later run ever repaired it.
  if [[ ! -s "$SURY_KEYRING" ]]; then
    log "Adding the deb.sury.org signing key ..."
    if ! curl -fsSL --retry 3 --max-time 60 -o "$SURY_KEYRING.tmp" "$SURY_KEY_URL"; then
      rm -f "$SURY_KEYRING.tmp"
      warn "could not download $SURY_KEY_URL"
      return 1
    fi
    chmod 0644 "$SURY_KEYRING.tmp" && mv -f "$SURY_KEYRING.tmp" "$SURY_KEYRING" || return 1
  fi
  # Rewritten whenever it differs, NOT only when the keyring is missing.
  # Gating the whole block on the keyring meant a box that had already been
  # given the wrong suite kept it forever: re-running the installer skipped
  # the fix, and the operator had no way to repair it short of editing apt
  # sources by hand.
  if [[ ! -f "$SURY_LIST" ]] || ! grep -qxF "$line" "$SURY_LIST"; then
    log "Pointing deb.sury.org at ${suite} ..."
    printf '%s\n' "$line" > "$SURY_LIST" || return 1
    # A suite switch leaves the old suite's package lists cached, and apt
    # will happily keep resolving against them.
    rm -rf /var/lib/apt/lists/packages.sury.org_*
    APT_UPDATED=0
  fi
  return 0
}

#-------- components ----------------------------------------------------------
# Every function returns non-zero on failure and checks each step itself:
# they run as `if install_x`, where bash switches `set -e` off for the whole
# call tree. A step without `|| return 1` would fail silently and the
# component would be reported as installed.

ensure_wpcli() {
  [[ -x "$WP_CLI" ]] && return 0
  log "Installing wp-cli (WordPress installs and updates run through it) ..."
  install -d -m 0755 "$(dirname "$WP_CLI")" || return 1
  local tmp="$WP_CLI.download.$$"
  # Temp name + rename, so an interrupted download never leaves a truncated
  # `wp` that the -x test above would then accept forever.
  if curl -fsSL --retry 3 --max-time 120 -o "$tmp" "$WP_CLI_URL" && [[ -s "$tmp" ]]; then
    chmod 0755 "$tmp" && mv -f "$tmp" "$WP_CLI" && return 0
  fi
  rm -f "$tmp"
  warn "could not download wp-cli from $WP_CLI_URL — WordPress cannot be installed until it is there."
  return 1
}

install_php() {
  local ver="$1"
  section "php${ver}: installing PHP ${ver} (FPM, CLI and the extensions WordPress needs)"
  ensure_sury || { warn "could not set up the deb.sury.org PHP repository."; return 1; }
  # Full extension set: wp-cli `core download` needs zip (ZipArchive),
  # WordPress needs gd/mbstring/xml/curl, and soap is required by many plugins
  # (shipping, invoicing, payment gateways) that refuse to run without it.
  apt_install \
    "php${ver}-fpm" "php${ver}-cli" "php${ver}-mysql" "php${ver}-pgsql" \
    "php${ver}-curl" "php${ver}-gd" "php${ver}-mbstring" "php${ver}-xml" \
    "php${ver}-zip" "php${ver}-soap" || return 1
  systemctl enable --now "php${ver}-fpm" || return 1
  # Per-version /run/php/<ver>/ dirs for the per-site pool sockets. /run is a
  # tmpfs; the snippet re-creates them at boot, this creates them now.
  if [[ -f "$PHP_TMPFILES" ]]; then
    systemd-tmpfiles --create "$PHP_TMPFILES" || warn "systemd-tmpfiles --create $PHP_TMPFILES failed."
  fi
  ensure_wpcli || return 1
}

install_mariadb() {
  section "mariadb: installing MariaDB"
  apt_install mariadb-server || return 1
  systemctl enable --now mariadb || return 1
  section "mariadb: securing it (no anonymous users, no remote root, no test database)"
  secure_mariadb || return 1
}

# What mysql_secure_installation does on MariaDB >= 10.4, minus the root
# password: Debian's root authenticates by unix_socket (only the OS root user
# gets in), which is exactly how the agent connects, and a password would only
# be one more secret on disk. Idempotent — every statement is a no-op the
# second time. Fed on stdin, never on argv.
secure_mariadb() {
  local client
  client="$(command -v mariadb || command -v mysql || true)"
  if [[ -z "$client" ]]; then
    warn "no mariadb client found after installing mariadb-server."
    return 1
  fi
  if ! "$client" <<'SQL'
DELETE FROM mysql.global_priv WHERE User='';
DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL
  then
    warn "could not log in to MariaDB as root over its unix socket — Hyperion manages databases exactly that way, so this has to work."
    return 1
  fi
}

install_postgresql() {
  section "postgresql: installing PostgreSQL"
  apt_install postgresql || return 1
  systemctl enable --now postgresql || return 1
}

install_redis() {
  section "redis: installing Redis"
  apt_install redis-server || return 1
  systemctl enable --now redis-server || return 1
}

ensure_shell() {
  grep -qxF "$1" "$SHELLS_FILE" 2>/dev/null && return 0
  # A file without a trailing newline would otherwise glue the new shell onto
  # its last line and break both entries.
  if [[ -s "$SHELLS_FILE" && -n "$(tail -c 1 "$SHELLS_FILE")" ]]; then
    printf '\n' >> "$SHELLS_FILE" || return 1
  fi
  printf '%s\n' "$1" >> "$SHELLS_FILE"
}

# The config Hyperion runs vsftpd with: PAM auth, local users chrooted into
# their own tree, per-user overrides from user_config_dir. Keep it identical to
# HYPERION_VSFTPD_CONF in crates/hyperion-adapters/src/ftp.rs — the agent
# rewrites a stock config to the same text when it finds one.
write_vsftpd_conf() {
  cat > "$VSFTPD_CONF" <<'EOFV'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
allow_writeable_chroot=YES
pam_service_name=vsftpd
secure_chroot_dir=/var/run/vsftpd/empty
user_sub_token=$USER
local_root=/home/$USER
user_config_dir=/etc/vsftpd/user_conf
xferlog_enable=YES
xferlog_std_format=YES
dual_log_enable=YES
syslog_enable=YES
seccomp_sandbox=NO
EOFV
}

# Set (or, for 21, drop) listen_port, touching nothing else. vsftpd's own
# default is 21, so the directive is only written when it differs. Rewrites the
# file only when the result differs, so an unchanged port never restarts FTP.
set_vsftpd_port() {
  local port="$1" tmp
  tmp="$(mktemp "$VSFTPD_CONF.XXXXXX")" || return 1
  awk -v port="$port" '
    /^[[:space:]]*listen_port[[:space:]]*=/ {
      if (!seen && port != 21) print "listen_port=" port
      seen = 1
      next
    }
    { print }
    END { if (!seen && port != 21) print "listen_port=" port }
  ' "$VSFTPD_CONF" > "$tmp" || { rm -f "$tmp"; return 1; }
  if cmp -s "$tmp" "$VSFTPD_CONF"; then
    rm -f "$tmp"
  else
    chmod 0644 "$tmp" && mv -f "$tmp" "$VSFTPD_CONF" || { rm -f "$tmp"; return 1; }
  fi
}

install_vsftpd() {
  section "vsftpd: installing the FTP server"
  apt_install vsftpd || return 1
  # Hosting users have /usr/sbin/nologin as their shell (no SSH), and vsftpd's
  # PAM stack (pam_shells) refuses any user whose shell is not listed here —
  # "530 Login incorrect" with the right password.
  ensure_shell /usr/sbin/nologin || return 1
  ensure_shell /bin/false || return 1

  local before="" fresh=0
  [[ -f "$VSFTPD_CONF" ]] && before="$(cat "$VSFTPD_CONF")"
  # The .hyperion-orig backup is the marker for "this config is already
  # Hyperion's": made once, from whatever was there first, and from then on
  # the file is left alone except for the port — the agent edits it too
  # (FTPS, passive ports), and a re-run must not throw that away.
  if [[ ! -f "$VSFTPD_CONF_ORIG" ]]; then
    if [[ -f "$VSFTPD_CONF" ]]; then
      cp -p "$VSFTPD_CONF" "$VSFTPD_CONF_ORIG" || return 1
    else
      install -m 0644 /dev/null "$VSFTPD_CONF_ORIG" || return 1
    fi
    write_vsftpd_conf || return 1
    fresh=1
  fi
  # A fresh config gets the requested port (default 21). An existing one only
  # when --ftp-port was given: a plain re-run to repair vsftpd must not move a
  # custom-port box back to 21 and lock every FTP client out.
  if (( fresh || FTP_PORT_GIVEN )); then
    set_vsftpd_port "$FTP_PORT" || return 1
  fi
  # Per-user configs: the agent drops <user> files here pointing local_root at
  # each hosting's writable htdocs, so FTP lands in the web root (not the
  # root-owned home) and STOR works.
  install -d -m 0755 "$VSFTPD_USER_CONF_DIR" || return 1
  systemctl enable --now vsftpd || return 1
  # The package starts vsftpd with Debian's stock config the moment it is
  # installed, and `enable --now` does not restart a running service — without
  # this, the box would serve the stock config (local users refused) until the
  # next reboot.
  if [[ "$(cat "$VSFTPD_CONF")" != "$before" ]]; then
    log "vsftpd config changed — restarting it ..."
    systemctl restart vsftpd || return 1
  fi
  log "vsftpd listens on port $(awk -F= '/^[[:space:]]*listen_port[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); p=$2} END{print p ? p : 21}' "$VSFTPD_CONF")."
}

install_phpmyadmin() {
  section "phpmyadmin: installing phpMyAdmin (reachable only through the panel)"
  if [[ ! -f "$PMA_SCRIPT" ]]; then
    warn "phpmyadmin.sh is not next to this script ($SCRIPT_DIR)."
    return 1
  fi
  bash "$PMA_SCRIPT" || return 1
  # phpmyadmin.sh exits 0 when it SKIPS — no nginx, or no PHP with the mysql
  # and mbstring extensions — because update.sh runs it on every box. Here
  # phpMyAdmin was asked for, so "skipped" is a failure, not a success.
  if [[ ! -f "$PMA_NGINX_CONF" || ! -e "$PMA_CURRENT/index.php" ]]; then
    warn "phpMyAdmin was not installed — it needs nginx and a PHP version with the mysql and mbstring extensions (install PHP first)."
    return 1
  fi
}

run_component() {
  case "$1" in
    php8.[1-4])  install_php "${1#php}" ;;
    mariadb)     install_mariadb ;;
    postgresql)  install_postgresql ;;
    redis)       install_redis ;;
    vsftpd)      install_vsftpd ;;
    phpmyadmin)  install_phpmyadmin ;;
    *)           warn "unknown component '$1'"; return 1 ;;
  esac
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    printf 'components.sh: must run as root.\n' >&2
    exit 1
  fi
}

# A stop (systemctl stop, Ctrl-C) mid-component would otherwise leave it
# "running" in the progress file forever.
on_signal() {
  local i
  for i in "${!ORDERED[@]}"; do
    [[ "${STATES[$i]}" == running ]] && STATES[i]=failed
  done
  write_progress
  section "interrupted"
  exit 130
}

main() {
  local prepare=0 c r i t0 failed=()
  local -a requested=()
  FTP_PORT=21
  FTP_PORT_GIVEN=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --prepare)    prepare=1; shift ;;
      --ftp-port)   [[ $# -ge 2 ]] || usage_error "--ftp-port needs a port number"
                    FTP_PORT="$2"; FTP_PORT_GIVEN=1; shift 2 ;;
      --ftp-port=*) FTP_PORT="${1#*=}"; FTP_PORT_GIVEN=1; shift ;;
      -h|--help)    usage; exit 0 ;;
      --)           shift; requested+=("$@"); break ;;
      -*)           usage_error "unknown option '$1'" ;;
      *)            requested+=("$1"); shift ;;
    esac
  done
  if ! [[ "$FTP_PORT" =~ ^[0-9]{1,5}$ ]] || (( 10#$FTP_PORT < 1 || 10#$FTP_PORT > 65535 )); then
    usage_error "--ftp-port must be a port number between 1 and 65535, got '$FTP_PORT'"
  fi
  FTP_PORT=$(( 10#$FTP_PORT ))

  if (( prepare )); then
    (( ${#requested[@]} == 0 )) || usage_error "--prepare installs nothing; drop the component names"
    require_root
    section "prepare: pointing apt at deb.sury.org for PHP"
    ensure_sury || { warn "could not set up the deb.sury.org PHP repository."; exit 1; }
    apt-get -q -o DPkg::Lock::Timeout=300 update || { warn "apt-get update failed."; exit 1; }
    section "prepare: done"
    exit 0
  fi

  (( ${#requested[@]} > 0 )) || usage_error "name at least one component"
  for r in "${requested[@]}"; do
    is_component "$r" || usage_error "unknown component '$r'"
  done
  require_root

  # Canonical order, each once.
  for c in "${ALL_COMPONENTS[@]}"; do
    for r in "${requested[@]}"; do
      if [[ "$r" == "$c" ]]; then ORDERED+=("$c"); STATES+=(pending); break; fi
    done
  done
  write_progress
  trap on_signal INT TERM

  for i in "${!ORDERED[@]}"; do
    c="${ORDERED[$i]}"
    set_state "$c" running
    t0=$SECONDS
    if run_component "$c"; then
      record_component "$c" \
        || warn "$c is installed but could not be recorded in $COMPONENTS_FILE — 'hyperion update' will not repair it if it goes missing."
      set_state "$c" "done"
      section "$c: done ($(elapsed $(( SECONDS - t0 ))))"
    else
      set_state "$c" failed
      failed+=("$c")
      section "$c: FAILED after $(elapsed $(( SECONDS - t0 ))) — see the lines above; carrying on with the rest"
    fi
  done
  trap - INT TERM

  if (( ${#failed[@]} > 0 )); then
    section "finished — failed: ${failed[*]}"
    exit 1
  fi
  section "finished — installed: ${ORDERED[*]}"
  exit 0
}

# Sourcing (the tests do) defines the functions without running anything.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
