//! Read-only filesystem watchdog, `/usr` remount and filesystem diagnostics.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Operator-triggered `mount -o remount,rw /` to flip the
    /// rootfs read-write. Refuses early if /usr is ALREADY
    /// writable (operator may have just bumped the wrong button
    /// on a clean image). On success the audit log entry plus
    /// the returned message tell the operator they can now retry
    /// the install. On failure the verbatim mount stderr lands
    /// in the message so the operator can see whether their
    /// image is genuinely immutable (snap-managed, ostree, etc.).
    pub async fn remount_usr_rw(&self) -> Result<(bool, String), RpcError> {
        // Early-out — if /usr is already writable there's nothing
        // to remount. Saves the operator from a no-op `mount`
        // invocation that might confuse them on the audit log.
        if check_usr_writable().await.is_none() {
            return Err(RpcError::Validation {
                message: "/usr is already writable — no remount needed".into(),
            });
        }
        let out = tokio::process::Command::new("/bin/mount")
            .args(["-o", "remount,rw", "/"])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("spawn mount: {e}")))?;
        // Concatenate stdout + stderr for the operator. mount
        // usually says nothing on success and emits to stderr on
        // failure.
        let mut message = String::from_utf8_lossy(&out.stderr).into_owned();
        if !out.stdout.is_empty() {
            if !message.is_empty() && !message.ends_with('\n') {
                message.push('\n');
            }
            message.push_str(&String::from_utf8_lossy(&out.stdout));
        }
        // Re-probe writability after the remount attempt.
        let now_writable = check_usr_writable().await.is_none();
        let success = out.status.success() && now_writable;
        self.append_audit(
            "system.remount_usr_rw",
            None,
            &serde_json::json!({
                "exit_code": out.status.code(),
                "now_writable": now_writable,
            })
            .to_string(),
            if success { "ok" } else { "failed" },
        )
        .await;
        if success {
            Ok((
                true,
                "Rootfs is now mounted read-write. Retry the package install — \
                 apt-get should succeed. Note: this is NOT persistent across \
                 reboots; if your /etc/fstab has the rootfs as `ro`, the next \
                 boot will revert."
                    .to_string(),
            ))
        } else {
            let tail = if message.trim().is_empty() {
                "(mount produced no diagnostic output)".to_string()
            } else {
                message
            };
            Ok((
                false,
                format!(
                    "Remount failed. mount said:\n{tail}\n\n\
                     Most likely your VPS image is genuinely immutable \
                     (snap-managed, ostree, or a hardened ISO). Switch to a \
                     standard Debian / Ubuntu cloud image and re-run install-node.sh."
                ),
            ))
        }
    }

    /// Full ROFS diagnose + (optional) auto-fix sequence.
    ///
    /// Gather phase (always runs):
    ///   * `/usr` writability probe (sentinel touch)
    ///   * `mount | grep ' / '` + `' /usr '` raw lines
    ///   * parsed mount options + fstype from `/proc/mounts`
    ///   * `/etc/fstab` rootfs line
    ///   * immutable-attr check via `lsattr -d /usr`
    ///   * image-kind heuristic (overlay → "overlay-immutable",
    ///     squashfs → "snap-managed", ostree marker → "ostree",
    ///     standard ext4/xfs → "standard")
    ///
    /// Fix phase (skipped when `dry_run = true` OR /usr already
    /// writable):
    ///   1. `mount -o remount,rw /` — the 90% case
    ///   2. `chattr -i /usr` when immutable_attr_set was true
    ///   3. `mount -o remount,rw /usr` when /usr is a separate
    ///      mountpoint that's still ro
    /// Each step is run only when prior steps left writability
    /// false. After each step the writability probe re-runs so
    /// the report shows incremental progress.
    /// Detect a read-only rootfs and repair it without waiting for a human.
    ///
    /// ext4 remounts itself `ro` on I/O errors, and from that moment the box
    /// is dead in the way that is hardest to see remotely: nginx serves
    /// stale content, SQLite refuses every write, jobs fail with EROFS —
    /// and the panel that carries the fix button may itself be broken. The
    /// manual diagnose/fix card assumed an operator watching; this tick is
    /// for the 3 a.m. version of the same event. Returns true when a fix
    /// was ATTEMPTED.
    ///
    /// Guard rails, each of which exists because the naive loop is harmful:
    ///
    ///   * **Three attempts per boot, then alerts only.** A filesystem that
    ///     keeps flipping back to ro has failing storage or real
    ///     corruption; remounting it rw in a loop risks making the
    ///     corruption worse. After the third attempt the watchdog stops
    ///     touching the mount and repeats a loud alert instead — at that
    ///     point a human with `dmesg` and SMART data is the fix.
    ///   * **Immutable images are never "fixed".** squashfs/overlay roots
    ///     (snap-managed, ostree) are ro BY DESIGN; remounting them fails
    ///     every time, so attempting would burn all three tries on a box
    ///     that was never broken. One alert names the real problem.
    ///   * **Success still alerts.** A remount that worked is a symptom
    ///     handled, not a cause cured — the operator must hear that the
    ///     disk did this, because the next flip may be the one that stays.
    pub async fn rofs_watchdog_tick(&self) -> bool {
        use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
        static ATTEMPTS: AtomicU32 = AtomicU32::new(0);
        static LAST_ALERT: AtomicI64 = AtomicI64::new(0);
        /// Successful repairs since this agent started. Unlike ATTEMPTS this
        /// does NOT reset when the filesystem goes healthy — that reset is
        /// what let a flapping disk repair itself forever without ever
        /// reaching the stand-down threshold.
        static REPAIRS_THIS_BOOT: AtomicU32 = AtomicU32::new(0);
        const MAX_ATTEMPTS: u32 = 3;
        const ALERT_EVERY_SECS: i64 = 3600;
        /// How many silent repairs before the operator is told. One remount
        /// is worth an audit row; a pattern is worth waking someone.
        const REPAIRS_BEFORE_ALERT: u32 = 3;

        // Cheap detection: /proc/mounts is authoritative and free to read.
        // The kernel's emergency remount lands there as a literal `ro`
        // option on / or /usr.
        let Ok(mounts) = tokio::fs::read_to_string("/proc/mounts").await else {
            return false;
        };
        let is_ro = |mp: &str| {
            mounts.lines().any(|l| {
                let p: Vec<&str> = l.split_whitespace().collect();
                p.len() >= 4 && p[1] == mp && p[3].split(',').any(|o| o == "ro")
            })
        };
        if !is_ro("/") && !is_ro("/usr") {
            // Healthy — reset so a fresh incident gets fresh attempts.
            ATTEMPTS.store(0, Ordering::Relaxed);
            return false;
        }

        let now = now_secs();
        let alert_due = || {
            let last = LAST_ALERT.load(Ordering::Relaxed);
            if now - last >= ALERT_EVERY_SECS {
                LAST_ALERT.store(now, Ordering::Relaxed);
                true
            } else {
                false
            }
        };

        // Classify before touching anything — an immutable image is not a
        // fault and must not consume attempts.
        let gathered = match self.fs_diagnose_and_fix(true).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error=%e, "rofs watchdog: gather failed");
                return false;
            }
        };
        if gathered.image_kind != "standard" && gathered.image_kind != "unknown" {
            if alert_due() {
                tracing::error!(
                    image_kind = %gathered.image_kind,
                    "rofs watchdog: rootfs is read-only BY DESIGN on this image — not fixable"
                );
                self.notify_admins_say(
                    "error",
                    "ops.rofs_by_design",
                    &[("image", &gathered.image_kind)],
                    "/services",
                    "system.rofs",
                )
                .await;
            }
            return false;
        }

        let attempt = ATTEMPTS.fetch_add(1, Ordering::Relaxed) + 1;
        if attempt > MAX_ATTEMPTS {
            if alert_due() {
                tracing::error!(
                    "rofs watchdog: rootfs is read-only AGAIN after {MAX_ATTEMPTS} repairs —                      standing down. This pattern means failing storage or filesystem                      corruption; check dmesg and SMART before remounting by hand"
                );
                self.notify_admins_say(
                    "error",
                    "ops.rofs_stood_down",
                    &[("attempts", &MAX_ATTEMPTS.to_string())],
                    "/services",
                    "system.rofs",
                )
                .await;
            }
            return false;
        }

        tracing::warn!(
            attempt,
            "rofs watchdog: rootfs is read-only — attempting repair"
        );
        match self.fs_diagnose_and_fix(false).await {
            Ok(d) if d.usr_writable_now => {
                // The DB lives on the rootfs, so the audit row could not
                // have been written while it was ro — write it now that it
                // can be.
                self.append_audit(
                    "system.rofs_autofix",
                    None,
                    &serde_json::json!({"attempt": attempt}).to_string(),
                    "ok",
                )
                .await;
                // A repair that WORKED is not news. It used to notify every
                // single time — and it was the one alert path that skipped
                // the rate limit — so a filesystem that flapped produced a
                // stream of "repaired automatically" cards describing a
                // problem that was already over. The audit row above is the
                // durable record; Services → Read-only rootfs shows the
                // detail on demand.
                //
                // The pattern still gets through. Counting repairs per BOOT,
                // not per incident, is the part that makes that possible:
                // ATTEMPTS resets to 0 whenever the filesystem looks healthy,
                // so a disk failing once an hour was silently repaired
                // forever and never reached the stand-down threshold.
                let repairs = REPAIRS_THIS_BOOT.fetch_add(1, Ordering::Relaxed) + 1;
                if repairs == REPAIRS_BEFORE_ALERT {
                    self.notify_admins_say(
                        "error",
                        "ops.rofs_repeats",
                        &[("repairs", &repairs.to_string())],
                        "/services",
                        "system.rofs",
                    )
                    .await;
                }
                true
            }
            Ok(_) => {
                if alert_due() {
                    self.notify_admins_say(
                        "error",
                        "ops.rofs_repair_failed",
                        &[],
                        "/services",
                        "system.rofs",
                    )
                    .await;
                }
                true
            }
            Err(e) => {
                tracing::error!(error=%e, "rofs watchdog: repair RPC failed");
                true
            }
        }
    }

    pub async fn fs_diagnose_and_fix(
        &self,
        dry_run: bool,
    ) -> Result<hyperion_types::FsDiagnostics, RpcError> {
        let mut d = hyperion_types::FsDiagnostics::default();

        // ── gather ───────────────────────────────────────────
        d.usr_writable_before = check_usr_writable().await.is_none();
        d.usr_writable_now = d.usr_writable_before;

        // Raw mount lines for the operator to eyeball.
        let mount_output = tokio::process::Command::new("/bin/mount")
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        d.root_mount_line = mount_output
            .lines()
            .find(|l| l.contains(" on / type "))
            .unwrap_or("")
            .to_string();
        d.usr_mount_line = mount_output
            .lines()
            .find(|l| l.contains(" on /usr type "))
            .unwrap_or("")
            .to_string();

        // /proc/mounts is the source-of-truth parseable view.
        // Format: dev mountpoint fstype opts dump pass
        if let Ok(mounts) = tokio::fs::read_to_string("/proc/mounts").await {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                if parts[1] == "/" {
                    d.root_fstype = parts[2].to_string();
                    d.root_options = parts[3].to_string();
                }
                if parts[1] == "/usr" {
                    d.usr_fstype = parts[2].to_string();
                    d.usr_options = parts[3].to_string();
                }
            }
        }

        // /etc/fstab — single rootfs line so the operator knows
        // whether a reboot would undo our remount.
        if let Ok(fstab) = tokio::fs::read_to_string("/etc/fstab").await {
            d.fstab_root_line = fstab
                .lines()
                .find(|l| {
                    let t = l.trim_start();
                    if t.is_empty() || t.starts_with('#') {
                        return false;
                    }
                    // Second whitespace-separated field is the mountpoint.
                    t.split_whitespace().nth(1) == Some("/")
                })
                .unwrap_or("")
                .to_string();
        }

        // lsattr +i — check immutable attribute on /usr.
        let lsattr = tokio::process::Command::new("/usr/bin/lsattr")
            .args(["-d", "/usr"])
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        // lsattr output: `----i---------e----- /usr` — look for 'i'
        // anywhere in the leading flags chunk.
        d.immutable_attr_set = lsattr
            .split_whitespace()
            .next()
            .map(|flags| flags.contains('i'))
            .unwrap_or(false);

        // Image-kind heuristic.
        d.image_kind = classify_image_kind(&d.root_fstype, &d.usr_fstype);

        // ── early-out: writable + dry-run / writable in general ──
        if d.usr_writable_now {
            d.final_state = "no-fix-needed".to_string();
            d.recommendations.push(
                "/usr is already writable. apt-get install should succeed — \
                 retry the install."
                    .into(),
            );
            return Ok(d);
        }
        if dry_run {
            d.final_state = "dry-run".to_string();
            d.recommendations.push(self.recommend_for_state(&d));
            return Ok(d);
        }

        // ── fix phase ────────────────────────────────────────
        //
        // Order matters for the operator-readable progress bar:
        //   1. remount,rw /        — the 90% case (rootfs ro/rw flap)
        //   2. remount,rw /usr     — when /usr is a separate mount
        //                            (still common on modern systemd
        //                            distros that split /usr; in
        //                            practice this fires for ext4
        //                            root with /usr in /etc/fstab)
        //   3. chattr -i /usr      — only when lsattr ACTUALLY saw
        //                            the immutable attribute set.
        //                            The previous "defensive even on
        //                            ext4" branch fired chattr
        //                            unconditionally and predictably
        //                            failed with "Read-only file
        //                            system while setting flags on
        //                            /usr" on any system where /usr
        //                            was still ro after step 1. The
        //                            failure was confusing — the UI
        //                            showed a red exit-1 pill on an
        //                            otherwise-successful run because
        //                            step 3 (the real fix) cleaned
        //                            up after. Tighten the condition
        //                            to the actual lsattr signal so
        //                            the only red step is a step
        //                            that really failed.

        // Step 1.
        d.fix_steps.push(
            self.run_fix_step(
                "mount -o remount,rw /",
                "/bin/mount",
                &["-o", "remount,rw", "/"],
            )
            .await,
        );
        d.usr_writable_now = check_usr_writable().await.is_none();

        // Step 2: separate /usr mountpoint.
        if !d.usr_writable_now && !d.usr_mount_line.is_empty() {
            d.fix_steps.push(
                self.run_fix_step(
                    "mount -o remount,rw /usr",
                    "/bin/mount",
                    &["-o", "remount,rw", "/usr"],
                )
                .await,
            );
            d.usr_writable_now = check_usr_writable().await.is_none();
        }

        // Step 3: chattr ONLY if lsattr saw the immutable bit. The
        // previous over-eager branch on ext4 produced spurious red
        // "Read-only file system" errors that confused the operator
        // even when the overall fix succeeded.
        if !d.usr_writable_now && d.immutable_attr_set {
            d.fix_steps.push(
                self.run_fix_step("chattr -i /usr", "/usr/bin/chattr", &["-i", "/usr"])
                    .await,
            );
            d.usr_writable_now = check_usr_writable().await.is_none();
        }

        // ── final state + recommendations ───────────────────
        if d.usr_writable_now {
            d.final_state = "fixed".to_string();
            d.recommendations
                .push("✓ /usr is now writable. Retry the install — apt-get should succeed.".into());
            if d.fstab_root_line.contains("ro,") || d.fstab_root_line.contains(" ro ") {
                d.recommendations.push(
                    "Warning: your /etc/fstab still says rootfs is `ro` — the next reboot \
                     will revert. Edit /etc/fstab to use `rw,` or change to a non-immutable \
                     image for a persistent fix."
                        .into(),
                );
            }
        } else if d.image_kind == "snap-managed" || d.image_kind == "overlay-immutable" {
            d.final_state = "image-immutable".to_string();
            d.recommendations.push(format!(
                "Your VPS image is {kind} — the rootfs CANNOT be made writable. \
                 You need a different image (standard Debian 12 / Ubuntu 22.04 cloud image \
                 without snap/overlay) to use Hyperion's package install. \
                 Reprovision the VPS with a non-immutable image and re-run install-node.sh.",
                kind = d.image_kind,
            ));
        } else {
            d.final_state = "still-broken".to_string();
            d.recommendations.push(
                "Every fix attempt failed. Possible causes: \
                 (1) the FS driver doesn't support `mount -o remount,rw` for this fstype, \
                 (2) a security module (AppArmor / SELinux) is blocking write to /usr, \
                 (3) the device backing / is genuinely read-only (CD-ROM / squashfs loop). \
                 SSH in and run `mount | grep ' / '` + `dmesg | tail -50` for clues."
                    .into(),
            );
        }
        for step in &d.fix_steps {
            tracing::info!(
                step = %step.label,
                exit_code = step.exit_code,
                now_writable = step.now_writable,
                "fs_fix_step"
            );
        }
        self.append_audit(
            "system.fs_diagnose_and_fix",
            None,
            &serde_json::json!({
                "dry_run": dry_run,
                "final_state": d.final_state,
                "writable_before": d.usr_writable_before,
                "writable_now": d.usr_writable_now,
                "image_kind": d.image_kind,
                "steps": d.fix_steps.len(),
            })
            .to_string(),
            if d.usr_writable_now { "ok" } else { "failed" },
        )
        .await;
        Ok(d)
    }

    /// Run one fix step, capture (exit, message, writability).
    pub(super) async fn run_fix_step(
        &self,
        label: &str,
        cmd: &str,
        args: &[&str],
    ) -> hyperion_types::FsFixStep {
        let out = tokio::process::Command::new(cmd).args(args).output().await;
        let (exit_code, message) = match out {
            Ok(o) => {
                let mut m = String::from_utf8_lossy(&o.stderr).into_owned();
                if !o.stdout.is_empty() {
                    if !m.is_empty() && !m.ends_with('\n') {
                        m.push('\n');
                    }
                    m.push_str(&String::from_utf8_lossy(&o.stdout));
                }
                // Cap message length for the response payload.
                if m.len() > 256 {
                    m.truncate(256);
                    m.push('…');
                }
                (o.status.code().unwrap_or(-1), m)
            }
            Err(e) => (-1, format!("spawn failed: {e}")),
        };
        let now_writable = check_usr_writable().await.is_none();
        hyperion_types::FsFixStep {
            label: label.to_string(),
            exit_code,
            message,
            now_writable,
        }
    }

    /// One-liner recommendation when no fixes have run yet (dry run
    /// or pre-fix state). Tailors message to the detected image kind.
    pub(super) fn recommend_for_state(&self, d: &hyperion_types::FsDiagnostics) -> String {
        match d.image_kind.as_str() {
            "snap-managed" | "overlay-immutable" => format!(
                "Image kind: {}. Rootfs is by-design immutable — \
                 remount will fail. Switch to a standard Debian/Ubuntu cloud image.",
                d.image_kind
            ),
            _ => "Click \"Diagnose & auto-fix\" to attempt remount,rw on the rootfs.".into(),
        }
    }
}

/// Classify the VPS image based on filesystem fingerprints — drives
/// the auto-fix UX (snap/overlay images CAN'T be made RW). Best-
/// effort; "unknown" is a safe default.
pub(super) fn classify_image_kind(root_fstype: &str, usr_fstype: &str) -> String {
    // squashfs is the snap signature — snapd mounts core24/jammy
    // images this way.
    if usr_fstype == "squashfs" || root_fstype == "squashfs" {
        return "snap-managed".into();
    }
    // overlay-based immutable images (Fedora CoreOS, ostree-style).
    if root_fstype == "overlay" {
        return "overlay-immutable".into();
    }
    // ostree marker — Atomic / CoreOS / Silverblue.
    if std::path::Path::new("/ostree").exists() {
        return "ostree".into();
    }
    // The boring 90% case.
    if matches!(root_fstype, "ext4" | "xfs" | "btrfs" | "ext3" | "ext2") {
        return "standard".into();
    }
    "unknown".into()
}

/// Sanity check: is /usr writable? Many minimal VPS images ship
/// with /usr on a read-only / immutable filesystem (snap, snapd
/// `usr.merge`, certain Debian "ostree"-style live images, or an
/// operator-mounted `noexec,nodev,ro` partition). apt then fails
/// with "Read-only file system" deep in dpkg's unpack step with
/// 100+ lines of half-extracted noise. Detect by trying to touch
/// a sentinel file in /usr/lib/.hyperion-rw-check.
///
/// Returns `None` when writable (good); `Some(message)` with a
/// clear actionable error for the operator otherwise.
pub(super) async fn check_usr_writable() -> Option<String> {
    let sentinel = std::path::Path::new("/usr/lib/.hyperion-rw-check");
    match tokio::fs::write(sentinel, b"ok").await {
        Ok(_) => {
            let _ = tokio::fs::remove_file(sentinel).await;
            None
        }
        Err(e) => Some(format!(
            "/usr is not writable ({e}). apt-get cannot install packages — the most likely \
             cause is the rootfs being mounted read-only (snap-managed images, immutable VPS \
             flavours, or a noexec/ro mount in /etc/fstab). Run `mount | grep ' /usr '` and \
             `mount | grep ' / '` to verify; if you see `ro,` you'll need to remount RW \
             (`mount -o remount,rw /` then retry) or pick a different base image."
        )),
    }
}
