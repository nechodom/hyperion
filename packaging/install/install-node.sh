#!/usr/bin/env bash
# Hyperion node installer — Debian 12+.
#
# Usage (as root, on a fresh box, replacing the token + master URL with
# the values from your master's /install page):
#   curl -fsSL https://<master>/install/install-node.sh | sudo bash -s -- \
#     --token=ABCD-EFGH-IJKL-MNPQ --master=https://master.example.com
#
# What it does:
#   - Verifies Debian 12+
#   - Port pre-flight: refuses (or offers to stop) whatever holds a needed port
#   - Configurator: nginx + PHP always; MariaDB / PostgreSQL / vsftpd selectable
#     (interactive [Y/n] or HYPERION_WITH_MARIADB/_POSTGRES/_VSFTPD=0|1); ports
#     adjustable (HYPERION_RPC_PORT, HYPERION_FTP_PORT)
#   - apt installs the chosen packages + PHP 8.3 (via deb.sury.org)
#   - Installs Rust if missing, builds hyperion-agent + hctl from source
#   - Drops binaries into /usr/sbin and /usr/bin
#   - Persists the invite token + master URL into /etc/hyperion/agent.toml
#     so once the controller's mTLS enrollment loop ships (sub-project
#     1.5 in the design docs), the agent rolls into the cluster
#     automatically.
#   - Enables + starts hyperion-agent (operates single-node until then)
#
# Re-running this script is safe; it skips steps already done.

set -euo pipefail

TOKEN=""
MASTER=""
REF="${HYPERION_REF:-main}"
INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
LABEL="${HYPERION_NODE_LABEL:-$(hostname -f 2>/dev/null || hostname)}"

# Source acquisition — same env knobs as install-master.sh.
GIT_URL="${HYPERION_GIT_URL:-https://github.com/nechodom/hyperion}"
GIT_TOKEN="${HYPERION_GIT_TOKEN:-}"
LOCAL_TARBALL="${HYPERION_LOCAL_TARBALL:-}"
SKIP_CLONE="${HYPERION_SKIP_CLONE:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token=*)  TOKEN="${1#*=}";;
    --master=*) MASTER="${1#*=}";;
    --label=*)  LABEL="${1#*=}";;
    *) printf 'unknown arg: %s\n' "$1" >&2; exit 2;;
  esac
  shift
done

log()  { printf '\033[36m[hyperion]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ── port conflict pre-flight ───────────────────────────────────────────────
# Hyperion drives HOST services (nginx, vsftpd, MariaDB, Postgres, and the
# master→node RPC listener); if a port it needs is already held by a FOREIGN
# process — most often docker-proxy for a published container — that service
# silently fails to bind. Reads PREFLIGHT_SPECS ("port;label;owner-regex"),
# finds the holder via `ss` and (for nftables-DNAT setups) via `docker ps`,
# and on a conflict offers to STOP the holder or ABORT. A port already owned
# by the service that SHOULD hold it (a re-run) is not a conflict. Env knobs:
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
      [[ -n "$name" && "$name" =~ $owner ]] && continue
      [[ -n "$pid" ]] && unit="$(grep -aoE '[a-zA-Z0-9@._-]+\.service' "/proc/$pid/cgroup" 2>/dev/null | tail -1 || true)"
    fi
    if [[ "$have_docker" == "1" ]]; then
      container="$(docker ps --format '{{.Names}};{{.Ports}}' 2>/dev/null | awk -F';' -v p=":$port->" 'index($2,p){print $1; exit}' || true)"
    fi
    [[ -z "$line" && -z "$container" ]] && continue
    holder="${name:-unknown}"
    [[ -n "$container" && ( -z "$name" || "$name" == "docker-proxy" ) ]] && holder="docker container '$container'"
    conflicts+=("$port;$label;$holder;$pid;$unit;$container")
  done

  if [[ ${#conflicts[@]} -eq 0 ]]; then
    log "Port pre-flight OK — every required port is free (or already ours)."
    return 0
  fi

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

# ── interactive configurator helpers ──────────────────────────────────────
# Pick which optional services this node installs & manages, and on which
# ports. Interactive [Y/n] on a TTY; non-interactive via env
# (HYPERION_WITH_MARIADB/_POSTGRES/_VSFTPD=0|1, HYPERION_FTP_PORT,
# HYPERION_RPC_PORT, HYPERION_NONINTERACTIVE=1 = accept defaults).
norm_bool() {
  case "${1,,}" in
    "") printf '' ;;
    0|n|no|false|off) printf '0' ;;
    *) printf '1' ;;
  esac
}
ask_yn() {
  local ans="" alt
  alt="$([[ "${2^^}" == "Y" ]] && echo n || echo y)"
  if [[ "${HYPERION_NONINTERACTIVE:-}" != "1" && -r /dev/tty ]]; then
    printf '%s [%s/%s]: ' "$1" "${2^^}" "$alt" > /dev/tty
    IFS= read -r ans < /dev/tty || ans=""
  fi
  ans="${ans:-$2}"
  [[ "$ans" =~ ^[Yy] ]] && printf '1' || printf '0'
}
ask_port() {
  local ans="$2"
  if [[ "${HYPERION_NONINTERACTIVE:-}" != "1" && -r /dev/tty ]]; then
    printf '%s [%s]: ' "$1" "$2" > /dev/tty
    IFS= read -r ans < /dev/tty || ans="$2"
    ans="${ans:-$2}"
  fi
  [[ "$ans" =~ ^[0-9]+$ && "$ans" -ge 1 && "$ans" -le 65535 ]] || fail "invalid port: '$ans'"
  printf '%s' "$ans"
}

[[ $EUID -eq 0 ]] || fail "Run me as root."
[[ -n "$TOKEN"  ]] || fail "Missing --token=<invite-token>."
[[ -n "$MASTER" ]] || fail "Missing --master=<https://your-master>."

#-------- 1. OS check ------------------------------------------------------
. /etc/os-release || fail "/etc/os-release missing."
[[ "$ID" == "debian" ]] || fail "Debian required (got '$ID')."
[[ "${VERSION_ID%%.*}" -ge 12 ]] || fail "Debian 12+ required (got $VERSION_ID)."

#-------- 1b. Component + port selection (before anything is installed) ----
# nginx + PHP-FPM are always installed; MariaDB / PostgreSQL / vsftpd are
# opt-out (defaults = install, unchanged from before).
WITH_MARIADB="$(norm_bool "${HYPERION_WITH_MARIADB:-}")"
WITH_POSTGRES="$(norm_bool "${HYPERION_WITH_POSTGRES:-}")"
WITH_VSFTPD="$(norm_bool "${HYPERION_WITH_VSFTPD:-}")"
[[ -z "$WITH_MARIADB"  ]] && WITH_MARIADB="$(ask_yn  'Install & manage MariaDB (database for hostings)?' Y)"
[[ -z "$WITH_POSTGRES" ]] && WITH_POSTGRES="$(ask_yn 'Install & manage PostgreSQL (only for Postgres apps)?' Y)"
[[ -z "$WITH_VSFTPD"   ]] && WITH_VSFTPD="$(ask_yn   'Install & manage vsftpd (per-hosting FTP/FTPS)?' Y)"
FTP_PORT=21
[[ "$WITH_VSFTPD" == "1" ]] && FTP_PORT="$(ask_port 'FTP control port' "${HYPERION_FTP_PORT:-21}")"
# Inbound master→node RPC port.
RPC_PORT="$(ask_port 'master→node RPC port' "${HYPERION_RPC_PORT:-9443}")"
# Private-network address for master↔node RPC. When set, the agent binds the
# RPC listener to this IP and advertises it to the master, so the control
# channel never crosses the public internet (big attack-surface reduction).
# Blank = listen on all interfaces + advertise the auto-detected public IP.
ADVERTISE_ADDR="${HYPERION_ADVERTISE_ADDR:-}"
if [[ -z "$ADVERTISE_ADDR" && -r /dev/tty && "${HYPERION_NONINTERACTIVE:-}" != "1" ]]; then
  { printf '\nPrivate IP for master↔node RPC (e.g. a Hetzner vSwitch 10.0.0.5),\n'
    printf 'or blank to use the public IP: '; } > /dev/tty
  IFS= read -r ADVERTISE_ADDR < /dev/tty || ADVERTISE_ADDR=""
fi
ADVERTISE_ADDR="$(printf '%s' "$ADVERTISE_ADDR" | tr -d '[:space:]')"
if [[ -n "$ADVERTISE_ADDR" ]]; then
  RPC_BIND="${ADVERTISE_ADDR}:${RPC_PORT}"
else
  RPC_BIND="0.0.0.0:${RPC_PORT}"
fi
log "Plan: nginx + PHP (always), MariaDB=$WITH_MARIADB PostgreSQL=$WITH_POSTGRES vsftpd=$WITH_VSFTPD; RPC :$RPC_PORT bind=$RPC_BIND${ADVERTISE_ADDR:+ (private)}, FTP :$FTP_PORT"

#-------- 1c. Port pre-flight (only the ports we'll actually use) ----------
# A node runs nginx/DBs/vsftpd like the master, plus the inbound master→node
# RPC listener. No panel (8443) — that's the master only.
PREFLIGHT_SPECS=(
  "80;nginx (HTTP);^nginx$"
  "443;nginx (HTTPS);^nginx$"
  "${RPC_PORT};master→node RPC;^hyperion-agent$"
)
[[ "$WITH_VSFTPD"   == "1" ]] && PREFLIGHT_SPECS+=("${FTP_PORT};vsftpd (FTP);^vsftpd$")
[[ "$WITH_MARIADB"  == "1" ]] && PREFLIGHT_SPECS+=("3306;MariaDB;^(mariadbd|mysqld)$")
[[ "$WITH_POSTGRES" == "1" ]] && PREFLIGHT_SPECS+=("5432;PostgreSQL;^(postgres|postmaster)$")
port_preflight
[[ "${HYPERION_PREFLIGHT_ONLY:-}" == "1" ]] && { log "Pre-flight only — nothing installed."; exit 0; }

#-------- 2. apt deps ------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
log "Installing base packages..."
apt-get update -qq
optional_pkgs=()
[[ "$WITH_MARIADB"  == "1" ]] && optional_pkgs+=(mariadb-server)
[[ "$WITH_POSTGRES" == "1" ]] && optional_pkgs+=(postgresql)
[[ "$WITH_VSFTPD"   == "1" ]] && optional_pkgs+=(vsftpd)
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release pkg-config build-essential git \
  nginx "${optional_pkgs[@]}"

mkdir -p /etc/apt/keyrings
# The suite MUST match this machine's Debian release. It was hardcoded to
# `bookworm`, so a Debian 13 (trixie) box pulled bookworm-built PHP whose
# `libzip4` dependency does not exist there — trixie ships libzip5 — and
# apt aborted the whole install with "held broken packages".
#
# Derived from os-release, with `bookworm` as the fallback for a
# derivative that reports its own codename (Ubuntu, Proxmox, Raspbian):
# sury publishes only Debian suites, so an unknown name must degrade to a
# real one rather than to a 404 repo.
SURY_SUITE="$( . /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}" )"
case "$SURY_SUITE" in
  bookworm|trixie|forky) ;;
  *) SURY_SUITE="bookworm" ;;
esac

SURY_LIST="/etc/apt/sources.list.d/sury-php.list"
SURY_LINE="deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ ${SURY_SUITE} main"
if [[ ! -f /etc/apt/keyrings/sury-php.gpg ]]; then
  curl -fsSL https://packages.sury.org/php/apt.gpg \
    -o /etc/apt/keyrings/sury-php.gpg
fi
# Rewritten whenever it differs, NOT only when the keyring is missing.
# Gating the whole block on the keyring meant a box that had already been
# given the wrong suite kept it forever: re-running the installer skipped
# the fix, and the operator had no way to repair it short of editing apt
# sources by hand.
if [[ ! -f "$SURY_LIST" ]] || ! grep -qxF "$SURY_LINE" "$SURY_LIST"; then
  echo "$SURY_LINE" > "$SURY_LIST"
  # A suite switch leaves the old suite's package lists cached, and apt
  # will happily keep resolving against them.
  rm -rf /var/lib/apt/lists/packages.sury.org_*
  apt-get update -qq
fi
# Full extension set, not just -fpm/-cli: wp-cli `core download` needs
# php8.3-zip (ZipArchive) and WordPress needs gd/mbstring/xml/curl.
# Matches install-master.sh so a worker can host WordPress too.
apt-get install -y -qq \
  php8.3-fpm php8.3-cli php8.3-mysql php8.3-pgsql \
  php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip
systemctl enable --now php8.3-fpm
systemctl enable --now nginx || true
[[ "$WITH_MARIADB"  == "1" ]] && { systemctl enable --now mariadb    || true; }
[[ "$WITH_POSTGRES" == "1" ]] && { systemctl enable --now postgresql || true; }

# vsftpd setup (same as install-master.sh)
if [[ "$WITH_VSFTPD" == "1" ]]; then
  if ! grep -q "/usr/sbin/nologin" /etc/shells 2>/dev/null; then
    echo "/usr/sbin/nologin" >> /etc/shells
  fi
  if [[ ! -f /etc/vsftpd.conf.hyperion-orig && -f /etc/vsftpd.conf ]]; then
    cp /etc/vsftpd.conf /etc/vsftpd.conf.hyperion-orig
    cat > /etc/vsftpd.conf <<'EOFV'
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
    [[ "$FTP_PORT" != "21" ]] && echo "listen_port=${FTP_PORT}" >> /etc/vsftpd.conf
  fi
  # Per-user configs (agent points each user's local_root at their htdocs).
  install -d -m 0755 /etc/vsftpd/user_conf
  systemctl enable --now vsftpd || true
else
  log "Skipping vsftpd (per selection) — per-hosting FTP will be unavailable."
fi

# wp-cli — required for WordPress install requests dispatched from master.
if [[ ! -x /usr/local/bin/wp ]]; then
  log "Installing wp-cli ..."
  curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    -o /usr/local/bin/wp
  chmod 0755 /usr/local/bin/wp
fi

#-------- 3. Rust ----------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "Installing Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
fi
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

#-------- 4. Acquire source + build agent ---------------------------------
acquire_source() {
  if [[ -n "$LOCAL_TARBALL" ]]; then
    [[ -f "$LOCAL_TARBALL" ]] || fail "HYPERION_LOCAL_TARBALL not found: $LOCAL_TARBALL"
    log "Extracting $LOCAL_TARBALL → $INSTALL_DIR ..."
    install -d -m 0755 "$INSTALL_DIR"
    tar -xzf "$LOCAL_TARBALL" -C "$INSTALL_DIR" --strip-components=1
    return
  fi
  if [[ -n "$SKIP_CLONE" || -d "$INSTALL_DIR/.git" ]]; then
    log "Reusing existing checkout at $INSTALL_DIR ..."
    return
  fi
  if [[ -n "$GIT_TOKEN" ]]; then
    log "Cloning $GIT_URL via HTTPS PAT ..."
    export GIT_ASKPASS="/tmp/hyp-askpass.$$"
    cat > "$GIT_ASKPASS" <<'EOF'
#!/bin/sh
case "$1" in
  Username*) printf 'oauth2\n' ;;
  Password*) printf '%s\n' "$HYPERION_GIT_TOKEN" ;;
esac
EOF
    chmod 0700 "$GIT_ASKPASS"
    trap "rm -f $GIT_ASKPASS" EXIT
    git -c core.askPass="$GIT_ASKPASS" clone --depth=1 --branch "$REF" \
      "$GIT_URL" "$INSTALL_DIR"
    return
  fi
  log "Fetching $GIT_URL ($REF) → $INSTALL_DIR ..."
  git clone --depth=1 --branch "$REF" "$GIT_URL" "$INSTALL_DIR" || {
    fail "git clone failed. For a private repo set HYPERION_GIT_TOKEN
       or HYPERION_GIT_URL=git@github.com:... or pre-clone into
       $INSTALL_DIR and re-run with HYPERION_SKIP_CLONE=1, or supply
       HYPERION_LOCAL_TARBALL for an offline install."
  }
}

acquire_source
cd "$INSTALL_DIR"

log "Building hyperion-agent + hctl ..."
cargo build --release --bin hyperion-agent --bin hctl --quiet

install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
install -m 0755 target/release/hctl           /usr/bin/hctl

#-------- 5. Users + dirs --------------------------------------------------
groupadd --system hyperion-admin 2>/dev/null || true
install -d -m 0700 /etc/hyperion /etc/hyperion/secrets
# 0o711 — owner full, others traverse-only. See install-master.sh for
# the rationale (nginx needs to traverse this on the way to
# /var/lib/hyperion/acme-challenges/<token> for HTTP-01).
install -d -m 0711 /var/lib/hyperion
install -d -m 0750 /var/log/hyperion
install -d -m 0755 /var/lib/hyperion/acme-challenges
install -d -m 0700 /var/lib/hyperion/backups/local

#-------- 6. agent.toml with master enrollment info -----------------------
# Node→master TLS: MEASURE it, don't assume. Every heartbeat carries this
# node's plaintext secret to the master, so verifying the master's
# certificate is what keeps an on-path attacker from reading it — and the
# master is normally the side that HAS a real certificate. We probe it the
# way the agent will, without -k, and write down what actually happened.
# Nothing here can fail the install: the worst case leaves the key unset and
# lets the agent decide from the URL at runtime.
TLS_COMMENT=""
TLS_SETTING=""
TLS_STATUS=""
if [[ "$MASTER" == https://* ]]; then
  tls_probe=0
  curl -sS --max-time 8 -o /dev/null "${MASTER%/}/healthz" >/dev/null 2>&1 || tls_probe=$?
  case "$tls_probe" in
    0)
      TLS_SETTING='verify_tls   = true'
      TLS_STATUS="verified (verify_tls = true)"
      TLS_COMMENT="# Measured during this install: the master's certificate verified against
# this node's CA bundle, so enrollment and every heartbeat verify it. If the
# master later moves to a certificate this node cannot verify, the agent
# STOPS heartbeating and logs the fix — it never falls back to an unverified
# connection on its own, so a node that goes stale right after a certificate
# change is telling you something."
      log "Master certificate verified — writing verify_tls = true."
      ;;
    51|60|77)
      TLS_SETTING='verify_tls   = false'
      TLS_STATUS="NOT verified — master certificate is self-signed (verify_tls = false)"
      TLS_COMMENT="# Measured during this install: the master's certificate did NOT verify
# against this node's CA bundle (curl exit ${tls_probe}) — what a self-signed
# master looks like. Verification is therefore OFF, and the invite token plus
# this node's per-node secret cross a channel an on-path attacker can read.
# Master->node commands stay Ed25519-signed either way. To close the gap:
# give the master a CA-issued certificate (certbot on the master), or copy the
# master's own CA to /usr/local/share/ca-certificates/hyperion-master.crt here
# and run update-ca-certificates; then set verify_tls = true below and
# restart hyperion-agent."
      log "WARNING: the master's certificate did not verify (curl exit ${tls_probe}) — writing verify_tls = false."
      ;;
    *)
      TLS_STATUS="not measured — master unreachable during install (verify_tls left on auto)"
      TLS_COMMENT="# The master could not be reached during this install (curl exit ${tls_probe}),
# so NOTHING was measured and this key is deliberately left unset. Unset means
# the agent decides from the URL: an https:// master with a DNS hostname IS
# verified. If this master turns out to serve a self-signed certificate, the
# agent aborts enrollment with the fix in the message rather than quietly
# connecting unverified — add 'verify_tls = false' here to accept that channel."
      log "Could not reach the master for a TLS check (curl exit ${tls_probe}) — leaving verify_tls unset (auto)."
      ;;
  esac
else
  TLS_STATUS="NO TLS — master_url is http://"
  TLS_COMMENT="# master_url is http://, so there is no TLS on this connection at all: the
# invite token and this node's per-node secret cross the network in cleartext,
# and verify_tls has nothing to act on. Move the master to https:// and
# re-enroll this node."
  log "WARNING: --master is http:// — the invite token and this node's secret will cross the network in cleartext."
fi

cat > /etc/hyperion/agent.toml <<EOF
[agent]
socket_path  = "/run/hyperion.sock"
socket_group = "hyperion-admin"
state_db     = "/var/lib/hyperion/state.db"
secrets_dir  = "/etc/hyperion/secrets"
log_path     = "/var/log/hyperion/agent.log"
home_root    = "/home"
backup_root  = "/var/lib/hyperion/backups/local"

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
contact_email = "admin@example.com"
challenge_dir = "/var/lib/hyperion/acme-challenges"

# Optional FTP/FTPS/SFTP remote backup destination (off by default).
[backup_remote]
enabled  = false
scheme   = "ftp"
host     = ""
port     = 21
user     = ""
password = ""
base_path = "/hyperion-backups"

# Optional Slack incoming webhook for cluster-wide notifications.
[slack]
default_webhook = ""

# Enrollment with the master.
#
# On first boot the agent POSTs <master_url>/api/enroll with this
# token, receives back a node_id + per-node secret, and persists
# them to /etc/hyperion/node-id.json. From that point on the agent
# heartbeats every 60s — visible on the master's /install page
# under Enrolled nodes.
#
# Retry on failure: if the master isn't reachable on first boot,
# the agent retries 5× with growing backoff (~9 min total). Past
# that, run on this node:
#   sudo rm -f /etc/hyperion/node-id.json
#   sudo systemctl restart hyperion-agent
# and watch journalctl -u hyperion-agent -f | grep enroll
[enrollment]
master_url   = "$MASTER"
invite_token = "$TOKEN"
node_label   = "$LABEL"

# TLS for the node->master leg (enrollment + every heartbeat).
${TLS_COMMENT}
${TLS_SETTING}

# Master→node remote RPC.
#
# When enabled, the agent runs a second HTTPS listener (port 9443
# by default) accepting signed RPC requests from the master. This
# is what makes the master's UI "Target node" dropdown work —
# without it, the master can still see this node in its registry
# but can't dispatch hosting create / delete / etc. to it.
#
# Auth model: the master holds an Ed25519 signing key
# (/etc/hyperion/master-rpc.key on the master); the public half is
# delivered to this node at enrollment time and on every heartbeat
# ack. Each remote RPC carries an Ed25519 signature over
# (node_id, ts, nonce, body_hash) — only requests signed by the
# legitimate master pass.
#
# TLS on this port is self-signed (auto-generated on first boot).
# The signature is the actual authentication; TLS is transport
# encryption.
#
# The firewall is scoped below to the master (or the private subnet) — NOT
# opened to the whole internet. Set advertise_addr to a private-network IP
# to keep this channel off the public internet entirely.
[remote_rpc]
enabled       = true
bind          = "${RPC_BIND}"
advertise_addr = "${ADVERTISE_ADDR}"
tls_cert_file = "/etc/hyperion/agent-rpc.crt"
tls_key_file  = "/etc/hyperion/agent-rpc.key"
EOF
chmod 0600 /etc/hyperion/agent.toml

#-------- 6.5 firewall opening for master→node RPC --------------------------
# SCOPED, not world-open. The RPC port only needs to admit the master. We
# derive the source to allow, in order of preference:
#   1. the /24 of a private advertise_addr (Hetzner vSwitch etc.) — the master
#      reaches us from inside that subnet;
#   2. the master's resolved IP (from --master=), when we're on public IPs;
#   3. as a last resort, warn and open to any (old behaviour) so the operator
#      isn't locked out — but tell them to scope it.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  UFW_SRC=""
  if [[ -n "$ADVERTISE_ADDR" && "$ADVERTISE_ADDR" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
    UFW_SRC="${BASH_REMATCH[1]}.0/24"
  elif [[ -n "$MASTER" ]]; then
    _mhost="$(printf '%s' "$MASTER" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"
    _mip="$(getent ahostsv4 "$_mhost" 2>/dev/null | awk '{print $1; exit}')"
    [[ -n "$_mip" ]] && UFW_SRC="$_mip"
  fi
  if [[ -n "$UFW_SRC" ]]; then
    ufw allow proto tcp from "$UFW_SRC" to any port "${RPC_PORT}" comment 'hyperion master->node RPC' || true
    echo "  Opened ufw ${RPC_PORT}/tcp from ${UFW_SRC} only (master→node RPC)."
  else
    ufw allow "${RPC_PORT}/tcp" comment 'hyperion master->node RPC (UNSCOPED)' || true
    echo "  WARNING: opened ufw ${RPC_PORT}/tcp to ANY source — could not determine the master's IP."
    echo "           Scope it: ufw delete allow ${RPC_PORT}/tcp && ufw allow proto tcp from <master-ip> to any port ${RPC_PORT}"
  fi
fi

#-------- 7. systemd unit + start ------------------------------------------
if [[ -f "$INSTALL_DIR/packaging/systemd/hyperion-agent.service" ]]; then
  install -m 0644 "$INSTALL_DIR/packaging/systemd/hyperion-agent.service" \
    /etc/systemd/system/hyperion-agent.service
fi
systemctl daemon-reload

# /run/php/<ver>/ subdirs for FPM sockets — see install-master.sh for
# the rationale. Required for HTTP requests to reach PHP-FPM.
tmpfiles_src="$INSTALL_DIR/packaging/systemd/hyperion-php-fpm-runtime.conf"
if [[ -f "$tmpfiles_src" ]]; then
  install -m 0644 "$tmpfiles_src" /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf
  systemd-tmpfiles --create /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf || true
fi
systemctl enable --now hyperion-agent
sleep 1
systemctl --no-pager --quiet is-active hyperion-agent || \
  fail "hyperion-agent failed to start; check journalctl -u hyperion-agent"

#-------- 8. Done ---------------------------------------------------------
echo
echo "============================================================"
echo "  ✓ Hyperion node provisioned ($LABEL)"
echo "  ----------------------------------------"
echo "  Local socket:    /run/hyperion.sock"
echo "  Master:          $MASTER"
echo "  Token recorded:  /etc/hyperion/agent.toml"
echo "  Master TLS:      $TLS_STATUS"
echo ""
echo "  Cluster channel hardening — do these IN ORDER:"
echo "    0. this node verifies the master's certificate   (above; per node, in agent.toml)"
echo "    1. master enforces worker TLS certificate pinning (master: Settings -> Cluster)"
echo "    2. master enforces signed node responses          (master: Settings -> Cluster)"
echo "  Steps 1 and 2 refuse a node that has not reported the matching value, so turn"
echo "  each on only once EVERY node shows its chip on the master's Nodes page."
echo ""
echo "  CLI:  sudo usermod -aG hyperion-admin \$USER  (then re-login)"
echo "        hctl info"
echo "============================================================"
