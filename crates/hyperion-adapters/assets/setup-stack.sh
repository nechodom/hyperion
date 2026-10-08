# Hyperion setup wizard — "Server software". Runs packaging/install/components.sh
# as a transient systemd unit (`hyperion-setup-stack.service`), never as a child
# of the agent.
#
# This file is an ASSET embedded in the agent (see `setup_stack.rs`) and checked
# with `bash -n` in CI. The agent writes it, components.sh and phpmyadmin.sh into
# the job directory and starts it with `systemd-run`; the rest arrives as
# environment variables:
#
#   HYP_JOB_DIR      where `result` and `progress` live
#   HYP_COMPONENTS   space-separated, already allow-listed by the agent
#   HYP_FTP_PORT     vsftpd control port
#
# Same reasons as the node update for running outside the agent: apt inside the
# agent's sandbox cannot write everything a package touches, and an install
# must survive the agent restarting under it.

set -uo pipefail

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8 LANG=C.UTF-8
unset LANGUAGE
export NEEDRESTART_MODE=l
export APT_LISTCHANGES_FRONTEND=none
export UCF_FORCE_CONFFOLD=1

JOB_DIR="${HYP_JOB_DIR:?HYP_JOB_DIR is not set}"
RESULT="$JOB_DIR/result"
export HYP_PROGRESS_FILE="$JOB_DIR/progress"

CODE=1
# The result is what tells the panel the run ENDED — and how. Written on every
# exit path, atomically. A run killed by a reboot leaves none, and the agent
# reports that as "interrupted".
finish() {
  printf '%s %s\n' "$CODE" "$(date +%s)" >"$RESULT.tmp" && mv -f "$RESULT.tmp" "$RESULT"
}
trap finish EXIT

printf 'Hyperion setup: installing %s (started %s)\n' \
  "${HYP_COMPONENTS:-nothing}" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# Word splitting is intended: the agent passes a space-separated list of names
# it has already checked against the allow-list.
# shellcheck disable=SC2086
bash "$JOB_DIR/components.sh" --ftp-port "${HYP_FTP_PORT:-21}" ${HYP_COMPONENTS:-}
CODE=$?

printf '\nHyperion setup: finished with exit code %s\n' "$CODE"
