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
                              Extra args pass through to update.sh, e.g.
                                hyperion update --repair
                                hyperion update --from-source
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
