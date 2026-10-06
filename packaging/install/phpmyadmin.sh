#!/usr/bin/env bash
# Install / heal the node-local phpMyAdmin behind the panel's "Open
# phpMyAdmin" button. Idempotent: safe to run on every update, rewrites a
# file only when its content changed, and never leaves nginx or PHP-FPM
# failing their config test.
#
# Run by update.sh (and the installers) on every box that hosts sites — the
# master included. Usage (as root):
#   sudo /opt/hyperion/packaging/install/phpmyadmin.sh
#
# Security model (the reason for every unusual choice below):
#
#   * phpMyAdmin is NOT on the network. nginx serves it on a unix socket in
#     a 0700 root-owned directory, so neither the internet nor the tenants
#     who share this box can send it a single byte. The only client is
#     hyperion-agent (root), which relays requests the panel has already
#     authenticated and authorised.
#   * It logs in with credentials the agent attaches per request (base64
#     X-Hyperion-Pma-* headers, readable only because nobody else can reach
#     the socket). config.inc.php refuses any request without them, so there
#     is no login form and no stored password anywhere in this tree.
#   * Its own PHP-FPM pool runs as a dedicated `hyperion-pma` user that owns
#     no site files, with open_basedir pinned to phpMyAdmin's own dirs and
#     the process-spawning functions disabled.
#   * Only the entry points phpMyAdmin needs are executable (index.php,
#     url.php, js/messages.php); setup/, examples/ and the test helpers are
#     deleted on install.
#   * The tarball is pinned by version AND sha256 below — bump both together
#     (https://www.phpmyadmin.net/downloads/ publishes the .sha256 next to
#     each archive; verify it independently before committing).
set -euo pipefail

PMA_VERSION="5.2.3"
PMA_SHA256="57881348297c4412f86c410547cf76b4d8a236574dd2c6b7d6a2beebe7fc44e3"
PMA_URL="https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.xz"

PMA_BASE="/usr/share/hyperion-pma"
PMA_DIR="$PMA_BASE/phpMyAdmin-$PMA_VERSION"
PMA_CURRENT="$PMA_BASE/current"
PMA_USER="hyperion-pma"
PMA_STATE="/var/lib/hyperion-pma"
PMA_ETC="/etc/hyperion-pma"
PMA_SECRET="$PMA_ETC/secret.inc.php"
PMA_RUN="/run/hyperion-pma"
PMA_FPM_SOCK="/run/php/hyperion-pma.sock"
NGINX_CONF="/etc/nginx/conf.d/hyperion-pma.conf"
TMPFILES_CONF="/etc/tmpfiles.d/hyperion-pma.conf"

log()  { printf '\033[1;34m[phpmyadmin]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[phpmyadmin] WARN:\033[0m %s\n' "$*" >&2; }

[[ $EUID -eq 0 ]] || { warn "must run as root"; exit 1; }

# Write $2 (content) to $1 only when it differs; returns 0 if it changed.
write_if_changed() {
  local dst="$1" content="$2" mode="$3" owner="$4"
  if [[ -f "$dst" ]] && [[ "$(cat "$dst")" == "$content" ]]; then
    chmod "$mode" "$dst"; chown "$owner" "$dst"
    return 1
  fi
  local tmp
  tmp="$(mktemp "${dst}.XXXXXX")"
  printf '%s\n' "$content" > "$tmp"
  chmod "$mode" "$tmp"; chown "$owner" "$tmp"
  mv -f "$tmp" "$dst"
  return 0
}

if ! command -v nginx >/dev/null 2>&1; then
  warn "nginx is not installed — skipping phpMyAdmin (nothing to serve it)."
  exit 0
fi

#-------- PHP version ------------------------------------------------------
# phpMyAdmin 5.2 supports PHP < 8.4, so prefer the newest version below that
# and fall back to 8.4 only when it is the sole one installed. It needs
# mysqli + mbstring + xml, which update.sh's extension heal installs for
# every present version.
PHP_VER=""
for v in 8.3 8.2 8.1 8.4; do
  if systemctl cat "php${v}-fpm.service" >/dev/null 2>&1 \
     && dpkg -s "php${v}-mysql" >/dev/null 2>&1 \
     && dpkg -s "php${v}-mbstring" >/dev/null 2>&1; then
    PHP_VER="$v"; break
  fi
done
if [[ -z "$PHP_VER" ]]; then
  warn "no PHP-FPM with the mysql + mbstring extensions found — skipping phpMyAdmin."
  exit 0
fi

#-------- tarball -----------------------------------------------------------
if [[ ! -f "$PMA_DIR/index.php" ]]; then
  command -v xz >/dev/null 2>&1 || \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xz-utils
  log "Downloading phpMyAdmin $PMA_VERSION ..."
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  curl -fsSL --retry 3 -o "$work/pma.tar.xz" "$PMA_URL"
  echo "$PMA_SHA256  $work/pma.tar.xz" | sha256sum -c --quiet - || {
    warn "checksum mismatch for $PMA_URL — refusing to install it."
    exit 1
  }
  tar -xJf "$work/pma.tar.xz" -C "$work"
  src="$work/phpMyAdmin-${PMA_VERSION}-all-languages"
  # Attack surface phpMyAdmin itself tells you to delete in production.
  rm -rf "$src/setup" "$src/examples" "$src/test" "$src/config.sample.inc.php" \
         "$src/show_config_errors.php"
  install -d -m 0755 "$PMA_BASE"
  chown -R root:root "$src"
  chmod -R u=rwX,go=rX "$src"
  rm -rf "$PMA_DIR.new"
  mv "$src" "$PMA_DIR.new"
  mv -T "$PMA_DIR.new" "$PMA_DIR"
  rm -rf "$work"; trap - EXIT
fi
ln -sfn "$PMA_DIR" "$PMA_CURRENT"
# Drop older versions — only `current` is ever served.
for d in "$PMA_BASE"/phpMyAdmin-*; do
  [[ -d "$d" && "$d" != "$PMA_DIR" ]] && rm -rf "$d"
done

#-------- user + state dirs + secret --------------------------------------
if ! id "$PMA_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent \
          --shell /usr/sbin/nologin "$PMA_USER"
fi
install -d -m 0700 -o "$PMA_USER" -g "$PMA_USER" "$PMA_STATE" "$PMA_STATE/tmp" "$PMA_STATE/sessions"
install -d -m 0750 -o root -g "$PMA_USER" "$PMA_ETC"
if [[ ! -s "$PMA_SECRET" ]]; then
  # blowfish_secret: phpMyAdmin wants exactly 32 bytes. Generated once per
  # node; nothing outside this box needs it.
  hex="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  write_if_changed "$PMA_SECRET" "<?php
// Generated by hyperion phpmyadmin.sh — per-node, never leaves this box.
return '$hex';" 0640 "root:$PMA_USER" || true
fi

#-------- config.inc.php ---------------------------------------------------
read -r -d '' PMA_CONFIG <<'PHP' || true
<?php
// Managed by hyperion (packaging/install/phpmyadmin.sh) — DO NOT EDIT.
//
// Credentials come from hyperion-agent on every request, base64-encoded in
// X-Hyperion-Pma-* headers. Only root can reach the nginx socket that sets
// them, so a request without them did not come through the panel: refuse it.
declare(strict_types=1);

// Decoded once and pinned in a constant: the headers are scrubbed from
// $_SERVER right after, so a second include (phpMyAdmin re-reads its config
// in some code paths) must not see them missing and 403 a valid request.
if (!defined('HYPERION_PMA')) {
    $hyperionPma = static function (string $name): string {
        $raw = $_SERVER['HTTP_X_HYPERION_PMA_' . $name] ?? '';
        $dec = is_string($raw) ? base64_decode($raw, true) : false;
        return is_string($dec) ? $dec : '';
    };
    $hyperionCreds = [$hyperionPma('USER'), $hyperionPma('PASSWORD'), $hyperionPma('DB'), $hyperionPma('BASE')];
    // Never let the credentials reach anything phpMyAdmin prints ($_SERVER
    // dumps, error pages).
    foreach (['USER', 'PASSWORD', 'DB', 'BASE'] as $hyperionKey) {
        unset($_SERVER['HTTP_X_HYPERION_PMA_' . $hyperionKey]);
    }
    define('HYPERION_PMA', $hyperionCreds);
    unset($hyperionPma, $hyperionCreds, $hyperionKey);
}
[$hyperionUser, $hyperionPass, $hyperionDb, $hyperionBase] = HYPERION_PMA;
if ($hyperionUser === '' || $hyperionPass === '' || $hyperionDb === ''
    || preg_match('#^https://[A-Za-z0-9.:\[\]-]+/pma/[0-9a-f-]{36}/$#', $hyperionBase) !== 1) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    exit("phpMyAdmin is only reachable through the Hyperion panel.\n");
}

$cfg['blowfish_secret'] = hex2bin((string) require '/etc/hyperion-pma/secret.inc.php');
$cfg['PmaAbsoluteUri'] = $hyperionBase;
$cfg['TempDir'] = '/var/lib/hyperion-pma/tmp';
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';
$cfg['VersionCheck'] = false;
$cfg['SendErrorReports'] = 'never';
$cfg['ShowChgPassword'] = false;
$cfg['ShowCreateDb'] = false;
$cfg['ShowPhpInfo'] = false;
$cfg['ShowServerInfo'] = false;
$cfg['AllowArbitraryServer'] = false;
$cfg['ZeroConf'] = false;
$cfg['PmaNoRelation_DisableWarning'] = true;
$cfg['ExecTimeLimit'] = 280;
$cfg['ThemeDefault'] = 'pmahomme';

$i = 1;
$cfg['Servers'][$i]['auth_type'] = 'config';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['user'] = $hyperionUser;
$cfg['Servers'][$i]['password'] = $hyperionPass;
$cfg['Servers'][$i]['only_db'] = $hyperionDb;
$cfg['Servers'][$i]['AllowRoot'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['hide_db'] = '^(information_schema|performance_schema|mysql|sys)$';
// The panel is the way out of phpMyAdmin; its own logout would only land
// on a 403 from the check above.
$cfg['Servers'][$i]['LogoutURL'] = preg_replace('#/pma/[0-9a-f-]{36}/$#', '/', $hyperionBase);
unset($hyperionUser, $hyperionPass, $hyperionDb, $hyperionBase);
PHP
write_if_changed "$PMA_DIR/config.inc.php" "$PMA_CONFIG" 0640 "root:$PMA_USER" \
  && log "Wrote phpMyAdmin config."

#-------- /run/hyperion-pma (root-only socket dir) ------------------------
write_if_changed "$TMPFILES_CONF" "# Managed by hyperion — phpMyAdmin's nginx socket dir. Root-only on purpose:
# hyperion-agent (root) is the only client allowed to talk to it.
d $PMA_RUN 0700 root root -" 0644 root:root || true
systemd-tmpfiles --create "$TMPFILES_CONF" >/dev/null 2>&1 || install -d -m 0700 "$PMA_RUN"
chmod 0700 "$PMA_RUN"; chown root:root "$PMA_RUN"

#-------- PHP-FPM pool -----------------------------------------------------
NGINX_USER="$(awk '/^[[:space:]]*user[[:space:]]+/ {gsub(/;/,"",$2); print $2; exit}' /etc/nginx/nginx.conf 2>/dev/null || true)"
NGINX_USER="${NGINX_USER:-www-data}"
POOL_CONF="/etc/php/$PHP_VER/fpm/pool.d/hyperion-pma.conf"
POOL_BODY="; Managed by hyperion (packaging/install/phpmyadmin.sh) — DO NOT EDIT.
[hyperion-pma]
user = $PMA_USER
group = $PMA_USER
listen = $PMA_FPM_SOCK
listen.owner = $NGINX_USER
listen.group = $NGINX_USER
listen.mode = 0660
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 60s
pm.max_requests = 200
request_terminate_timeout = 300s
php_admin_value[open_basedir] = $PMA_BASE/:$PMA_STATE/:$PMA_ETC/:/usr/share/zoneinfo/
php_admin_value[session.save_path] = $PMA_STATE/sessions
php_admin_value[upload_tmp_dir] = $PMA_STATE/tmp
php_admin_value[sys_temp_dir] = $PMA_STATE/tmp
; Matches the panel's 1 MiB relay limit, so phpMyAdmin's import page states
; the real ceiling.
php_admin_value[upload_max_filesize] = 1M
php_admin_value[post_max_size] = 1M
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 290
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,dl
php_admin_flag[expose_php] = off
php_admin_flag[display_errors] = off
php_admin_flag[log_errors] = on
php_admin_flag[allow_url_fopen] = off"
install -d -m 0755 /run/php
FPM_CHANGED=0
write_if_changed "$POOL_CONF" "$POOL_BODY" 0644 root:root && FPM_CHANGED=1
# The pool moves with the chosen PHP version — drop copies under the others.
for v in 8.1 8.2 8.3 8.4; do
  [[ "$v" == "$PHP_VER" ]] && continue
  if [[ -f "/etc/php/$v/fpm/pool.d/hyperion-pma.conf" ]]; then
    rm -f "/etc/php/$v/fpm/pool.d/hyperion-pma.conf"
    systemctl reload "php${v}-fpm.service" >/dev/null 2>&1 || true
  fi
done
if ! "php-fpm$PHP_VER" -t >/dev/null 2>&1; then
  rm -f "$POOL_CONF"
  warn "php-fpm$PHP_VER -t failed with the phpMyAdmin pool — removed it (kept PHP healthy)."
  exit 1
fi
if (( FPM_CHANGED )) || [[ ! -S "$PMA_FPM_SOCK" ]]; then
  systemctl reload "php${PHP_VER}-fpm.service" >/dev/null 2>&1 \
    || systemctl restart "php${PHP_VER}-fpm.service" >/dev/null 2>&1 || true
fi

#-------- nginx -------------------------------------------------------------
read -r -d '' NGINX_BODY <<NGINX || true
# Managed by hyperion (packaging/install/phpmyadmin.sh) — DO NOT EDIT.
#
# phpMyAdmin, reachable ONLY on a unix socket in a 0700 root directory: the
# sole client is hyperion-agent, relaying requests the panel authenticated.
# Paths are /pma/<hosting-id>/<phpMyAdmin path>, identical to what the
# browser sees, so phpMyAdmin's cookie path and links need no rewriting.

map \$request_uri \$hyperion_pma_prefix {
    "~^(?<p>/pma/[0-9a-f-]{36})/" \$p;
    default "";
}

server {
    listen unix:$PMA_RUN/nginx.sock;
    server_name _;
    root $PMA_CURRENT;
    index index.php;
    client_max_body_size 2m;
    server_tokens off;
    access_log off;

    location ^~ /pma/ {
        rewrite "^/pma/[0-9a-f-]{36}(/.*)\$" \$1 last;
        return 404;
    }
    location = / {
        internal;
        rewrite ^ /index.php last;
    }
    # The only executable entry points phpMyAdmin has.
    location ~ ^/(index|url|js/messages)\.php\$ {
        internal;
        try_files \$uri =404;
        fastcgi_pass unix:$PMA_FPM_SOCK;
        fastcgi_param SCRIPT_FILENAME   \$document_root\$fastcgi_script_name;
        fastcgi_param SCRIPT_NAME       \$hyperion_pma_prefix\$fastcgi_script_name;
        fastcgi_param REQUEST_URI       \$request_uri;
        fastcgi_param DOCUMENT_URI      \$document_uri;
        fastcgi_param DOCUMENT_ROOT     \$document_root;
        fastcgi_param QUERY_STRING      \$query_string;
        fastcgi_param REQUEST_METHOD    \$request_method;
        fastcgi_param CONTENT_TYPE      \$content_type;
        fastcgi_param CONTENT_LENGTH    \$content_length;
        fastcgi_param SERVER_PROTOCOL   \$server_protocol;
        fastcgi_param GATEWAY_INTERFACE CGI/1.1;
        fastcgi_param SERVER_SOFTWARE   nginx;
        fastcgi_param REMOTE_ADDR       127.0.0.1;
        fastcgi_param SERVER_NAME       \$host;
        fastcgi_param SERVER_PORT       443;
        fastcgi_param HTTPS             on;
        fastcgi_read_timeout 300s;
    }
    location ~ ^/(js|themes|doc/html)/ {
        internal;
        location ~ \.php\$ { return 404; }
        try_files \$uri =404;
        expires 7d;
    }
    location = /favicon.ico { internal; try_files \$uri =404; }
    location = /robots.txt  { internal; try_files \$uri =404; }
    location / { return 404; }
}
NGINX
NGINX_CHANGED=0
write_if_changed "$NGINX_CONF" "$NGINX_BODY" 0644 root:root && NGINX_CHANGED=1
if ! nginx -t >/dev/null 2>&1; then
  rm -f "$NGINX_CONF"
  warn "nginx -t failed with the phpMyAdmin server — removed it (kept nginx healthy)."
  nginx -t 2>&1 | tail -5 >&2 || true
  exit 1
fi
if (( NGINX_CHANGED )) || [[ ! -S "$PMA_RUN/nginx.sock" ]]; then
  systemctl reload nginx >/dev/null 2>&1 || true
fi

log "phpMyAdmin $PMA_VERSION ready (PHP $PHP_VER, socket $PMA_RUN/nginx.sock)."
