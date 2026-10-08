#!/usr/bin/env bash
# `hyperion` — the small front door.
#
# Why this exists: the panel's Update button lives only on WORKER node
# cards, and a master has no card of its own, so on a single-server install
# there is NO in-product way to update. The only route was to remember the
# full path under /opt — which is exactly the kind of thing an operator
# reaches for at 2am and gets wrong. `hyperion update` is that path, named
# the way people already guess.
#
# Deliberately thin: it dispatches, it does not reimplement. Anything that
# needs real logic belongs in update.sh or hctl, so there is one copy of it.
set -euo pipefail

INSTALL_DIR="${HYPERION_INSTALL_DIR:-/opt/hyperion}"
UPDATE_SH="$INSTALL_DIR/packaging/install/update.sh"

usage() {
  cat <<'EOF'
hyperion — Hyperion control panel

Usage:
  hyperion update [args...]   Update this box in place (runs as root).
                              Waits for running jobs (backups, migrations, ...)
                              to finish first, so none is cut off.
                              Extra args pass through to update.sh, e.g.
                                hyperion update --repair
                                hyperion update --from-source
                                hyperion update --no-wait          (don't wait)
                                hyperion update --wait-timeout=900 (give up after 15 min)
  hyperion setup-link         Print a new one-time link for the setup wizard
                              (only while setup is unfinished; runs as root).
  hyperion version            Show the running agent's version.
  hyperion status             systemd status for the Hyperion services.
  hyperion logs [-f]          Tail the agent + web logs.
  hyperion help               This text.

Anything else is handed to hctl, so `hyperion info` == `hctl info`.
Full CLI: hctl --help
EOF
}

cmd="${1:-help}"
[[ $# -gt 0 ]] && shift || true

case "$cmd" in
  update)
    if [[ ! -x "$UPDATE_SH" ]]; then
      echo "hyperion: cannot find $UPDATE_SH" >&2
      echo "Set HYPERION_INSTALL_DIR if Hyperion lives somewhere else." >&2
      exit 1
    fi
    # update.sh stops and replaces the services, so it needs root. Re-exec
    # through sudo rather than failing halfway with a confusing permission
    # error on the first install -m.
    if [[ $EUID -ne 0 ]]; then
      exec sudo -- "$UPDATE_SH" "$@"
    fi
    exec "$UPDATE_SH" "$@"
    ;;
  setup-link)
    # The setup code is a credential for a panel that has no administrator
    # yet, so minting one needs root on the box — the same proof as having
    # run the installer.
    if [[ $EUID -ne 0 ]]; then
      exec sudo -- "$0" setup-link "$@"
    fi
    WEB_CONFIG="${HYPERION_WEB_CONFIG:-/etc/hyperion/web.toml}"
    rc=0
    out="$(RUST_LOG=warn hyperion-web --config "$WEB_CONFIG" setup-link "$@" 2>&1)" || rc=$?
    if [[ $rc -eq 3 ]]; then
      echo "Setup is already finished — sign in to the panel normally."
      exit 0
    fi
    if [[ $rc -ne 0 ]]; then
      printf '%s\n' "$out" >&2
      exit "$rc"
    fi
    url=""; fp=""; hours="24"
    while IFS= read -r line; do
      case "$line" in
        SETUP_URL=*)     url="${line#*=}" ;;
        CERT_SHA256=*)   fp="${line#*=}" ;;
        EXPIRES_HOURS=*) hours="${line#*=}" ;;
      esac
    done <<<"$out"
    echo "Open this link to finish setup (the previous one no longer works):"
    echo
    echo "  $url"
    echo
    [[ -n "$fp" ]] && echo "Certificate SHA-256: $fp"
    echo "The link works once and expires in $hours hours."
    echo "Use the server's public address if the one above is private: --host <address>"
    ;;
  version|--version|-V)
    exec hyperion-agent --version
    ;;
  status)
    exec systemctl status --no-pager hyperion-agent hyperion-web
    ;;
  logs)
    exec journalctl -u hyperion-agent -u hyperion-web "$@"
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    # Everything else is an hctl subcommand. Keeps one CLI surface instead
    # of two that drift.
    if ! command -v hctl >/dev/null 2>&1; then
      echo "hyperion: unknown command '$cmd', and hctl is not installed" >&2
      usage >&2
      exit 1
    fi
    exec hctl "$cmd" "$@"
    ;;
esac
