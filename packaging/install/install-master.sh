#!/usr/bin/env bash
# Hyperion master installer — Debian 12+.
#
# Usage (as root, on a fresh box):
#   curl -fsSL https://raw.githubusercontent.com/nechodom/hyperion/main/packaging/install/install-master.sh | sudo bash
#
# What it does:
#   - Verifies Debian 12+
#   - Port pre-flight: refuses (or offers to stop) whatever holds a needed port
#   - Configurator: nginx + PHP always; MariaDB / PostgreSQL / vsftpd are
#     selectable (interactive [Y/n], or HYPERION_WITH_MARIADB/_POSTGRES/_VSFTPD
#     =0|1), and ports are adjustable (HYPERION_LISTEN panel, HYPERION_FTP_PORT)
#   - apt installs the chosen packages + PHP 8.3 (via deb.sury.org)
#   - Installs Rust if missing, builds hyperion from source (one-time)
#   - Drops binaries into /usr/sbin and /usr/bin
#   - Creates /etc/hyperion, /var/lib/hyperion, /var/log/hyperion
#   - Writes default agent.toml + web.toml
#   - Installs systemd units, enables + starts hyperion-agent + hyperion-web
#   - Prompts for an initial admin password and bootstraps the web user
#   - Prints the URL of the freshly running admin UI
#
# Re-running this script is safe; it skips steps already done.

set -euo pipefail

#-------- 0. Args ----------------------------------------------------------
REF="${HYPERION_REF:-main}"
INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
ADMIN_USER="${HYPERION_ADMIN_USER:-admin}"
ADMIN_PASS="${HYPERION_ADMIN_PASS:-}"
LISTEN="${HYPERION_LISTEN:-0.0.0.0:8443}"
CONTACT_EMAIL="${HYPERION_ACME_EMAIL:-}"

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

log()  { printf '\033[36m[hyperion]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

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
# Let the operator pick which optional services Hyperion installs & manages,
# and on which ports, so it can coexist with an existing stack. Interactive
# [Y/n] on a TTY; non-interactive via env (HYPERION_WITH_MARIADB/_POSTGRES/
# _VSFTPD=0|1, HYPERION_FTP_PORT, HYPERION_RPC_PORT, HYPERION_LISTEN, and
# HYPERION_NONINTERACTIVE=1 to accept all defaults without prompting).
norm_bool() {  # raw → 1 / 0 / "" (unset)
  case "${1,,}" in
    "") printf '' ;;
    0|n|no|false|off) printf '0' ;;
    *) printf '1' ;;
  esac
}
ask_yn() {  # $1 prompt, $2 default(Y|N) → 1 / 0
  local ans="" alt
  alt="$([[ "${2^^}" == "Y" ]] && echo n || echo y)"
  if [[ "${HYPERION_NONINTERACTIVE:-}" != "1" && -r /dev/tty ]]; then
    printf '%s [%s/%s]: ' "$1" "${2^^}" "$alt" > /dev/tty
    IFS= read -r ans < /dev/tty || ans=""
  fi
  ans="${ans:-$2}"
  [[ "$ans" =~ ^[Yy] ]] && printf '1' || printf '0'
}
ask_port() {  # $1 prompt, $2 default → a validated 1..65535 port
  local ans="$2"
  if [[ "${HYPERION_NONINTERACTIVE:-}" != "1" && -r /dev/tty ]]; then
    printf '%s [%s]: ' "$1" "$2" > /dev/tty
    IFS= read -r ans < /dev/tty || ans="$2"
    ans="${ans:-$2}"
  fi
  [[ "$ans" =~ ^[0-9]+$ && "$ans" -ge 1 && "$ans" -le 65535 ]] || fail "invalid port: '$ans'"
  printf '%s' "$ans"
}

if [[ $EUID -ne 0 ]]; then
  fail "Run me as root."
fi

#-------- 1. OS check ------------------------------------------------------
. /etc/os-release || fail "/etc/os-release missing — not a Debian-family box?"
[[ "$ID" == "debian" ]] || fail "Debian required (got '$ID')."
[[ "${VERSION_ID%%.*}" -ge 12 ]] || fail "Debian 12+ required (got $VERSION_ID)."

#-------- 1b. Component + port selection (before anything is installed) ----
# nginx + PHP-FPM are always installed (Hyperion can't serve hostings without
# them); MariaDB / PostgreSQL / vsftpd are opt-out. Defaults = install (== the
# historical behaviour), so a plain run is unchanged.
WITH_MARIADB="$(norm_bool "${HYPERION_WITH_MARIADB:-}")"
WITH_POSTGRES="$(norm_bool "${HYPERION_WITH_POSTGRES:-}")"
WITH_VSFTPD="$(norm_bool "${HYPERION_WITH_VSFTPD:-}")"
[[ -z "$WITH_MARIADB"  ]] && WITH_MARIADB="$(ask_yn  'Install & manage MariaDB (database for hostings)?' Y)"
[[ -z "$WITH_POSTGRES" ]] && WITH_POSTGRES="$(ask_yn 'Install & manage PostgreSQL (only for Postgres apps)?' Y)"
[[ -z "$WITH_VSFTPD"   ]] && WITH_VSFTPD="$(ask_yn   'Install & manage vsftpd (per-hosting FTP/FTPS)?' Y)"
FTP_PORT=21
[[ "$WITH_VSFTPD" == "1" ]] && FTP_PORT="$(ask_port 'FTP control port' "${HYPERION_FTP_PORT:-21}")"
# Panel port: honour HYPERION_LISTEN if set, else offer to change it.
if [[ -z "${HYPERION_LISTEN:-}" ]]; then
  LISTEN="0.0.0.0:$(ask_port 'Hyperion panel port' "${LISTEN##*:}")"
fi
LISTEN_PORT="${LISTEN##*:}"
log "Plan: nginx + PHP (always), MariaDB=$WITH_MARIADB PostgreSQL=$WITH_POSTGRES vsftpd=$WITH_VSFTPD; panel :$LISTEN_PORT, FTP :$FTP_PORT"

#-------- 1c. Port pre-flight (only the ports we'll actually use) ----------
PREFLIGHT_SPECS=(
  "80;nginx (HTTP);^nginx$"
  "443;nginx (HTTPS);^nginx$"
  "${LISTEN_PORT};Hyperion panel;^hyperion-web$"
)
[[ "$WITH_VSFTPD"   == "1" ]] && PREFLIGHT_SPECS+=("${FTP_PORT};vsftpd (FTP);^vsftpd$")
[[ "$WITH_MARIADB"  == "1" ]] && PREFLIGHT_SPECS+=("3306;MariaDB;^(mariadbd|mysqld)$")
[[ "$WITH_POSTGRES" == "1" ]] && PREFLIGHT_SPECS+=("5432;PostgreSQL;^(postgres|postmaster)$")
port_preflight
[[ "${HYPERION_PREFLIGHT_ONLY:-}" == "1" ]] && { log "Pre-flight only — nothing installed."; exit 0; }

log "Debian $VERSION_ID detected. Updating apt cache..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

#-------- 2. Base packages -------------------------------------------------
log "Installing base packages..."
optional_pkgs=()
[[ "$WITH_MARIADB"  == "1" ]] && optional_pkgs+=(mariadb-server)
[[ "$WITH_POSTGRES" == "1" ]] && optional_pkgs+=(postgresql)
[[ "$WITH_VSFTPD"   == "1" ]] && optional_pkgs+=(vsftpd)
apt-get install -y -qq \
  curl ca-certificates gnupg lsb-release pkg-config build-essential git \
  nginx "${optional_pkgs[@]}"

mkdir -p /etc/apt/keyrings

#-------- 3. PHP via deb.sury.org -----------------------------------------
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
  log "Adding deb.sury.org PHP repo (${SURY_SUITE})..."
  curl -fsSL https://packages.sury.org/php/apt.gpg \
    -o /etc/apt/keyrings/sury-php.gpg
fi
# Rewritten whenever it differs, NOT only when the keyring is missing.
# Gating the whole block on the keyring meant a box that had already been
# given the wrong suite kept it forever: re-running the installer skipped
# the fix, and the operator had no way to repair it short of editing apt
# sources by hand.
if [[ ! -f "$SURY_LIST" ]] || ! grep -qxF "$SURY_LINE" "$SURY_LIST"; then
  log "Pointing deb.sury.org at ${SURY_SUITE}..."
  echo "$SURY_LINE" > "$SURY_LIST"
  # A suite switch leaves the old suite's package lists cached, and apt
  # will happily keep resolving against them.
  rm -rf /var/lib/apt/lists/packages.sury.org_*
  apt-get update -qq
fi
log "Installing PHP 8.3..."
apt-get install -y -qq \
  php8.3-fpm php8.3-cli php8.3-mysql php8.3-pgsql \
  php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip
systemctl enable --now php8.3-fpm
# nginx is required; the DBs are enabled only if selected.
systemctl enable --now nginx || true
[[ "$WITH_MARIADB"  == "1" ]] && { systemctl enable --now mariadb    || true; }
[[ "$WITH_POSTGRES" == "1" ]] && { systemctl enable --now postgresql || true; }

# vsftpd: PAM-auth + chroot + local users. Operator opts in per hosting
# via "Set FTP password" in the UI. We tighten the default config and
# allow /usr/sbin/nologin so the hosting system_users (who have that
# shell to block SSH) can still FTP in.
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
    # Custom control port (default 21). vsftpd's built-in default is 21, so we
    # only write the directive when it differs — keeps the file clean.
    [[ "$FTP_PORT" != "21" ]] && echo "listen_port=${FTP_PORT}" >> /etc/vsftpd.conf
  fi
  # Per-user configs: the agent drops <user> files here pointing local_root at
  # each hosting's writable htdocs, so FTP lands in the web root (not the
  # root-owned home) and STOR works.
  install -d -m 0755 /etc/vsftpd/user_conf
  systemctl enable --now vsftpd || true
else
  log "Skipping vsftpd (per selection) — per-hosting FTP will be unavailable."
fi

#-------- 3b. wp-cli (WordPress installer dependency) ----------------------
# wpcli adapter shells out to /usr/local/bin/wp; without it WordPress
# install requests fail at the adapter layer. Pin to whatever the
# upstream "latest stable" phar is — wp-cli ships signed releases.
if [[ ! -x /usr/local/bin/wp ]]; then
  log "Installing wp-cli ..."
  curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    -o /usr/local/bin/wp
  chmod 0755 /usr/local/bin/wp
fi

#-------- 4. Rust toolchain ------------------------------------------------
if ! command -v cargo >/dev/null 2>&1; then
  log "Installing Rust toolchain (rustup, minimal)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
fi
# Ensure cargo is on PATH for this shell
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"

#-------- 5. Source checkout + build --------------------------------------
acquire_source() {
  # 5a. Local tarball — air-gapped / pre-downloaded installs.
  if [[ -n "$LOCAL_TARBALL" ]]; then
    [[ -f "$LOCAL_TARBALL" ]] || fail "HYPERION_LOCAL_TARBALL not found: $LOCAL_TARBALL"
    log "Extracting $LOCAL_TARBALL → $INSTALL_DIR ..."
    install -d -m 0755 "$INSTALL_DIR"
    tar -xzf "$LOCAL_TARBALL" -C "$INSTALL_DIR" --strip-components=1
    return
  fi

  # 5b. Pre-cloned directory (operator did the clone with their creds).
  if [[ -n "$SKIP_CLONE" || -d "$INSTALL_DIR/.git" ]]; then
    if [[ ! -d "$INSTALL_DIR/.git" ]]; then
      fail "HYPERION_SKIP_CLONE=1 but $INSTALL_DIR/.git not present."
    fi
    log "Reusing existing checkout at $INSTALL_DIR ..."
    return
  fi

  # 5c. PAT-via-credential-helper. Token stays in env; never appears on argv.
  if [[ -n "$GIT_TOKEN" ]]; then
    log "Cloning $GIT_URL ($REF) via HTTPS PAT (token from \$HYPERION_GIT_TOKEN) ..."
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

  # 5d. Plain clone (works for public repos OR with SSH agent + git@github.com URL).
  log "Fetching $GIT_URL ($REF) → $INSTALL_DIR ..."
  git clone --depth=1 --branch "$REF" "$GIT_URL" "$INSTALL_DIR" || {
    fail "git clone failed. For a private repo set HYPERION_GIT_TOKEN
       (HTTPS PAT) or HYPERION_GIT_URL=git@github.com:nechodom/hyperion
       (SSH with agent forwarding), or pre-clone into $INSTALL_DIR and
       re-run with HYPERION_SKIP_CLONE=1."
  }
}

acquire_source
cd "$INSTALL_DIR"

log "Building release binaries (this can take a few minutes the first time)..."
cargo build --release --workspace --quiet

log "Installing binaries..."
install -m 0755 target/release/hyperion-agent /usr/sbin/hyperion-agent
install -m 0755 target/release/hyperion-web   /usr/sbin/hyperion-web
install -m 0755 target/release/hctl           /usr/bin/hctl

#-------- 6. Users + directories ------------------------------------------
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

#-------- 7. Config files (idempotent) ------------------------------------
if [[ ! -f /etc/hyperion/agent.toml ]]; then
  log "Writing /etc/hyperion/agent.toml ..."
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
contact_email = "${CONTACT_EMAIL:-admin@example.com}"
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

if [[ ! -f /etc/hyperion/web.toml ]]; then
  log "Writing /etc/hyperion/web.toml ..."
  cat > /etc/hyperion/web.toml <<EOF
[web]
listen               = "$LISTEN"
agent_socket         = "/run/hyperion.sock"
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
chmod 0600 /etc/hyperion/agent.toml /etc/hyperion/web.toml

# TLS cert directory — agent runs as root and writes through ReadWritePaths.
install -d -m 0700 /etc/hyperion/web-tls

#-------- 8. systemd units -------------------------------------------------
for unit in hyperion-agent hyperion-web; do
  src="$INSTALL_DIR/packaging/systemd/${unit}.service"
  if [[ -f "$src" ]]; then
    install -m 0644 "$src" "/etc/systemd/system/${unit}.service"
  fi
done
systemctl daemon-reload

# Per-version /run/php/<ver>/ subdirs for FPM sockets. Without this
# reboot wipes /run/* and PHP-FPM fails to open its per-pool socket on
# the next boot → nginx returns 502. Drop the snippet AND materialize
# the dirs right now so the first hosting create after install works.
tmpfiles_src="$INSTALL_DIR/packaging/systemd/hyperion-php-fpm-runtime.conf"
if [[ -f "$tmpfiles_src" ]]; then
  install -m 0644 "$tmpfiles_src" /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf
  systemd-tmpfiles --create /etc/tmpfiles.d/hyperion-php-fpm-runtime.conf || true
fi

#-------- 9. MariaDB hardening (one-shot) ---------------------------------
if [[ "$WITH_MARIADB" == "1" ]] && ! mariadb -e "SELECT 1" >/dev/null 2>&1; then
  log "NOTE: mariadb-secure-installation requires interactive input."
  log "Run it manually after this installer if you haven't already."
fi

#-------- 10. Bootstrap admin user ----------------------------------------
if [[ ! -f /etc/hyperion/web-admin.json ]]; then
  # When the script is run via `curl … | sudo bash`, stdin is the pipe,
  # not the terminal — a plain `read` would get an empty string. Read
  # from /dev/tty if it exists; otherwise require the env var.
  while [[ -z "$ADMIN_PASS" ]]; do
    if [[ -r /dev/tty ]]; then
      echo
      printf 'Choose admin password for the web UI (min 1 char): ' > /dev/tty
      IFS= read -rs ADMIN_PASS < /dev/tty
      echo > /dev/tty
    else
      fail "No terminal available for password prompt.
       Re-run with HYPERION_ADMIN_PASS set, e.g.:
         curl -fsSL <installer-url> | sudo HYPERION_ADMIN_PASS='your-pass' bash"
    fi
    if [[ -z "$ADMIN_PASS" ]]; then
      printf '  empty — try again.\n' > /dev/tty
    fi
  done
  log "Bootstrapping admin user '${ADMIN_USER}' ..."
  /usr/sbin/hyperion-web --config /etc/hyperion/web.toml bootstrap \
    --username "$ADMIN_USER" --password "$ADMIN_PASS"
fi

#-------- 10b. Pre-generate web session + CSRF keys ------------------------
# The systemd unit runs hyperion-web with ProtectSystem=full, which makes
# /etc read-only for the service. hyperion-web's keys::load_or_init would
# happily create these on first start in a writable environment, but here
# the sandbox blocks the write. We materialize them ahead of time so the
# running service only ever has to READ them.
gen_key_file() {
  local path="$1"
  if [[ -f "$path" ]]; then return 0; fi
  log "Generating $(basename "$path") ..."
  install -m 0600 /dev/null "$path"
  head -c 32 /dev/urandom | base64 -w 0 > "$path"
}
gen_key_file /etc/hyperion/web-session.key
gen_key_file /etc/hyperion/web-csrf.key

#-------- 11. Enable + start services -------------------------------------
log "Enabling + starting hyperion-agent ..."
systemctl enable --now hyperion-agent
log "Enabling + starting hyperion-web ..."
systemctl enable --now hyperion-web

sleep 1
systemctl --no-pager --quiet is-active hyperion-agent || \
  fail "hyperion-agent failed to start; check journalctl -u hyperion-agent"
systemctl --no-pager --quiet is-active hyperion-web || \
  fail "hyperion-web failed to start; check journalctl -u hyperion-web"

#-------- 12. Done ---------------------------------------------------------
FQDN="$(hostname -f 2>/dev/null || hostname)"
echo
echo "============================================================"
echo "  ✓ Hyperion master installed"
echo "  ----------------------------------------"
echo "  Web UI:   https://${FQDN}:${LISTEN##*:}"
echo "  CLI:      hctl info"
echo "  Configs:  /etc/hyperion/"
echo "  Logs:     journalctl -u hyperion-agent -u hyperion-web"
echo ""
echo "  Next steps:"
echo "    1. sudo usermod -aG hyperion-admin \$USER      (then log out / in)"
echo "    2. Open the Web UI and log in as '${ADMIN_USER}'"
echo "    3. /install in the UI → generate invite tokens for new nodes"
echo "============================================================"
