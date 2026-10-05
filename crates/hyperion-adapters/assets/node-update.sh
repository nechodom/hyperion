# Hyperion node update — the operating-system upgrade and/or update.sh, run as
# a transient systemd unit (`hyperion-node-update.service`), never as a child
# of the agent.
#
# This file is an ASSET embedded in the agent (see `node_update.rs`) and checked
# with `bash -n` in CI. The agent writes it to the job directory and starts it
# with `systemd-run`; everything it needs arrives as environment variables:
#
#   HYP_DO_APT=1        upgrade the operating system packages
#   HYP_DO_HYPERION=1   run /opt/hyperion/packaging/install/update.sh
#   HYP_SAFE=1          ... with --safe
#   HYP_JOB_DIR         where `result` is written when the run ends
#
# Why a unit of its own. Run inside hyperion-agent.service, apt inherited the
# agent's sandbox: ProtectKernelModules hides /lib/modules and ProtectSystem
# makes /boot read-only, so every kernel package died in its preinst with
# "mkdir: cannot create directory '/lib/modules/…': Read-only file system" and
# left dpkg half-configured. And update.sh stops hyperion-agent — which, in the
# agent's own cgroup, killed update.sh along with it. A transient unit has
# neither the sandbox nor the cgroup, and it outlives an agent restart.
#
# stdout/stderr go to the log file the unit was started with; the agent reads
# its tail for the panel.

set -uo pipefail

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C.UTF-8 LANG=C.UTF-8
unset LANGUAGE
# needrestart: list what needs a restart, never restart anything itself. A
# library upgrade must not bounce MariaDB or PHP-FPM in the middle of the day
# on its own initiative.
export NEEDRESTART_MODE=l
export APT_LISTCHANGES_FRONTEND=none
export UCF_FORCE_CONFFOLD=1

JOB_DIR="${HYP_JOB_DIR:?HYP_JOB_DIR is not set}"
RESULT="$JOB_DIR/result"
UPDATE_SH=/opt/hyperion/packaging/install/update.sh
# Space a kernel upgrade needs on /boot: one vmlinuz + initrd + System.map +
# config is 60-120 MB on Debian amd64. Below this, update-initramfs fails half
# way through the postinst and the package is left unconfigured.
BOOT_MIN_KB=$((150 * 1024))

# apt waits for the dpkg lock instead of failing on it: unattended-upgrades or
# the panel's own index check may hold it for a minute.
APT_OPTS=(
  -y -q
  -o DPkg::Lock::Timeout=600
  -o Dpkg::Use-Pty=0
  -o Dpkg::Options::=--force-confdef
  -o Dpkg::Options::=--force-confold
)

step() { printf '\n──── %s ────\n' "$*"; }
say() { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*"; }

STARTED=$(date +%s)
CODE=1
# The result is what tells the panel the run ENDED — and how. Written on every
# exit path, atomically, so a reader never sees half a line. A run killed by a
# reboot leaves none, and the agent reports that as "interrupted".
finish() {
  printf '%s %s\n' "$CODE" "$(date +%s)" >"$RESULT.tmp" && mv -f "$RESULT.tmp" "$RESULT"
}
trap finish EXIT

say "Hyperion node update started $(date -u '+%Y-%m-%d %H:%M:%S UTC') on $(hostname)"
say "running kernel: $(uname -r)"

# Packages whose version moved during this run, for the summary.
pkgs_upgradable() {
  apt list --upgradable 2>/dev/null | awk -F/ 'NR>1 && NF>1 {print $1}' | sort
}

kernel_pending() {
  pkgs_upgradable | grep -Eq '^linux-image-'
}

boot_avail_kb() {
  df -Pk /boot 2>/dev/null | awk 'NR==2 {print $4}'
}

os_upgrade() {
  # 1. Repair whatever an earlier run left behind. A dpkg run that died half
  #    way (the sandboxed kernel upgrade above, a reboot, a full disk) leaves
  #    packages unpacked-but-unconfigured, and every later apt call refuses to
  #    do anything until they are finished.
  step "repair: finish interrupted package installs"
  if [[ -n "$(dpkg --audit 2>/dev/null)" ]]; then
    say "dpkg reports unfinished packages:"
    dpkg --audit || true
    dpkg --configure -a || { warn "dpkg --configure -a failed"; return 1; }
  else
    say "dpkg: nothing unfinished"
  fi
  # Broken dependencies: fix them, but never by REMOVING anything. On a server
  # `apt-get -f install` is happy to resolve a conflict by uninstalling the
  # database; --no-remove makes it stop and say so instead.
  if ! apt-get check -q >/dev/null 2>&1; then
    say "apt reports broken dependencies — fixing without removing packages"
    apt-get install -f --no-remove "${APT_OPTS[@]}" || {
      warn "could not fix dependencies without removing packages — fix this by hand (apt-get -f install), then run the update again"
      return 1
    }
  fi

  # 2. Fresh index. A mirror that cannot be reached is an error here, not a
  #    warning: upgrading from a stale index silently installs nothing.
  step "apt-get update"
  apt-get update -q -o DPkg::Lock::Timeout=600 --error-on=any || {
    warn "the package index could not be refreshed — nothing was upgraded"
    return 1
  }

  local before
  before="$(pkgs_upgradable)"
  if [[ -z "$before" ]]; then
    say "nothing to upgrade"
    return 0
  fi
  say "$(wc -l <<<"$before") package(s) to upgrade:"
  sed 's/^/  /' <<<"$before"

  # 3. Room on /boot for a new kernel. Old kernels apt marked as no longer
  #    needed go first — that is what fills /boot on a box that has taken a
  #    year of kernel updates — and only then is the space checked.
  if kernel_pending; then
    step "kernel upgrade: checking /boot"
    local avail
    avail="$(boot_avail_kb)"
    if [[ -n "$avail" && "$avail" -lt "$BOOT_MIN_KB" ]]; then
      say "/boot has $((avail / 1024)) MB free — removing kernels apt no longer needs"
      apt-get autoremove "${APT_OPTS[@]}" || true
      avail="$(boot_avail_kb)"
    fi
    if [[ -n "$avail" && "$avail" -lt "$BOOT_MIN_KB" ]]; then
      warn "/boot has only $((avail / 1024)) MB free and a new kernel needs about $((BOOT_MIN_KB / 1024)) MB."
      warn "Remove an old linux-image-* package by hand (never the running one: $(uname -r)), then run the update again."
      return 1
    fi
    say "/boot: $((${avail:-0} / 1024)) MB free — ok"
  fi

  # 4. The upgrade. `upgrade --with-new-pkgs`, not dist-upgrade: it installs
  #    new dependencies (a kernel with a new ABI name is a new package) but
  #    NEVER removes one. Within a stable release that covers everything;
  #    whatever it holds back is listed below for the operator to look at,
  #    rather than resolved by uninstalling something on a production server.
  step "apt-get upgrade"
  apt-get upgrade --with-new-pkgs "${APT_OPTS[@]}" || {
    warn "apt-get upgrade failed — see above. dpkg state:"
    dpkg --audit || true
    return 1
  }

  # 5. Kernels the new one superseded. Kept to apt's own policy (the running
  #    kernel and the newest are never auto-removable).
  step "apt-get autoremove"
  apt-get autoremove "${APT_OPTS[@]}" || warn "autoremove failed (not fatal)"

  local held
  held="$(pkgs_upgradable)"
  if [[ -n "$held" ]]; then
    step "held back"
    say "These would need a package REMOVED or a held package changed, so they were not touched:"
    sed 's/^/  /' <<<"$held"
    say "Review them with: apt-get -s dist-upgrade"
  fi
  return 0
}

reboot_note() {
  local running newest
  running="$(uname -r)"
  newest="$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|^/boot/vmlinuz-||' | sort -V | tail -n1)"
  if [[ -f /var/run/reboot-required ]] || [[ -n "$newest" && "$newest" != "$running" ]]; then
    step "reboot required"
    [[ -n "$newest" && "$newest" != "$running" ]] && say "running kernel $running, newest installed $newest"
    [[ -f /var/run/reboot-required.pkgs ]] && sed 's/^/  /' /var/run/reboot-required.pkgs
    say "Reboot the server when convenient to finish the update."
  fi
  return 0
}

CODE=0
if [[ "${HYP_DO_APT:-0}" == 1 ]]; then
  os_upgrade || CODE=1
fi

if [[ "${HYP_DO_HYPERION:-0}" == 1 ]]; then
  if (( CODE != 0 )); then
    say ""
    say "Skipping the Hyperion update: the operating-system upgrade failed."
  elif [[ ! -f "$UPDATE_SH" ]]; then
    step "hyperion update"
    warn "update.sh missing at $UPDATE_SH — node was not installed via install-node.sh / install-master.sh"
    CODE=2
  else
    step "hyperion update"
    args=()
    [[ "${HYP_SAFE:-0}" == 1 ]] && args+=(--safe)
    # update.sh stops and restarts hyperion-agent. That is fine now: this unit
    # is not in the agent's cgroup, so the restart does not take us with it.
    bash "$UPDATE_SH" "${args[@]}" || CODE=$?
  fi
fi

[[ "${HYP_DO_APT:-0}" == 1 ]] && reboot_note

step "finished"
say "exit $CODE after $(( $(date +%s) - STARTED ))s"
exit "$CODE"
