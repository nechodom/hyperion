//! Kernel disk quotas: enabling, setting, enforcing overage policy.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ============================================================
    //  hosting_quotas — per-hosting disk caps, kernel-enforced via
    //  `setquota -u`, plus the overage action the enforce tick applies.
    //
    //  The mem_limit_mib / bw_*_mib columns still exist but NOTHING
    //  reads them, and the panel no longer writes them. Two earlier
    //  comments here claimed memory "lands in the FPM pool template on
    //  next rebuild" (false — pools are built from hosting_limits, the
    //  enforced memory path) and that bandwidth was "alert-driven"
    //  (false — no alert existed). Those sentences leaked into the UI
    //  copy and produced placebo controls that operators trusted. If
    //  bandwidth caps ever become real, they get an enforce-tick reader
    //  and THEN a form field — in that order.
    // ============================================================

    pub async fn quota_get(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingQuotaReport, RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::hosting_quotas::read(&self.pool, detail.id.as_str())
            .await
            .map_err(|e| RpcError::Internal_with(format!("quota read: {e}")))?;
        let exceed_action = self.hosting_quota_action(detail.id.as_str()).await;
        let policy = hyperion_types::HostingQuotaView {
            hosting_id: row.hosting_id,
            disk_soft_kib: row.disk_soft_kib,
            disk_hard_kib: row.disk_hard_kib,
            mem_limit_mib: row.mem_limit_mib,
            bw_soft_mib: row.bw_soft_mib,
            bw_hard_mib: row.bw_hard_mib,
            applied_at: row.applied_at,
            last_error: row.last_error,
            updated_at: row.updated_at,
            exceed_action: exceed_action.as_str().to_string(),
        };
        let (mut current_disk_kib, quotas_enabled_on_fs, setup_hint) =
            quota_probe_current(&detail.system_user, &detail.root_dir).await;
        // Without kernel quotas the probe deliberately returns 0 rather than
        // walking the tree — fall back to the usage sampler, which already
        // measures exactly this and does it off the request path.
        if current_disk_kib == 0 {
            if let Ok(rows) = hyperion_state::limits::usage_for(&self.pool, &detail.id, 1).await {
                if let Some(u) = rows.first() {
                    current_disk_kib = u.disk_used_bytes / 1024;
                }
            }
        }
        Ok(hyperion_types::HostingQuotaReport {
            policy,
            current_disk_kib,
            quotas_enabled_on_fs,
            setup_hint,
        })
    }

    /// Automatically enable Linux kernel disk quotas on the filesystem
    /// carrying this hosting's home tree: edit `/etc/fstab`, remount, and
    /// run quotacheck + quotaon where the filesystem type allows it.
    /// Returns a summary the UI shows (incl. "reboot required" when the
    /// filesystem couldn't be remounted live).
    pub async fn quota_enable_kernel(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::QuotaEnableSummary, RpcError> {
        let detail = self.get(sel).await?;
        let summary = enable_kernel_quotas(&detail.root_dir).await;
        self.append_audit(
            "quota.enable_kernel",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "mount_point": summary.mount_point,
                "fs_type": summary.fs_type,
                "ok": summary.ok,
                "requires_reboot": summary.requires_reboot,
            })
            .to_string(),
            if summary.ok {
                "ok"
            } else if summary.requires_reboot {
                "pending"
            } else {
                "failed"
            },
        )
        .await;
        Ok(summary)
    }

    pub async fn quota_set(
        &self,
        sel: HostingSelector,
        disk_soft_kib: i64,
        disk_hard_kib: i64,
        mem_limit_mib: i64,
        bw_soft_mib: i64,
        bw_hard_mib: i64,
        exceed_action: &str,
    ) -> Result<hyperion_types::HostingQuotaView, RpcError> {
        // Validation: hard must be >= soft when both non-zero.
        // Zero ⇒ "no cap", which is allowed on either side.
        if disk_soft_kib < 0
            || disk_hard_kib < 0
            || mem_limit_mib < 0
            || bw_soft_mib < 0
            || bw_hard_mib < 0
        {
            return Err(RpcError::Validation {
                message: "quota values must be non-negative".into(),
            });
        }
        if disk_soft_kib > 0 && disk_hard_kib > 0 && disk_hard_kib < disk_soft_kib {
            return Err(RpcError::Validation {
                message: "disk hard limit must be >= soft limit".into(),
            });
        }
        if bw_soft_mib > 0 && bw_hard_mib > 0 && bw_hard_mib < bw_soft_mib {
            return Err(RpcError::Validation {
                message: "bandwidth hard limit must be >= soft limit".into(),
            });
        }

        let detail = self.get(sel).await?;
        let now = now_secs();
        hyperion_state::hosting_quotas::upsert(
            &self.pool,
            detail.id.as_str(),
            disk_soft_kib,
            disk_hard_kib,
            mem_limit_mib,
            bw_soft_mib,
            bw_hard_mib,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("quota upsert: {e}")))?;

        // Persist the overage policy (notify | suspend) in hosting_kv. Parsed
        // so a stray value can't poison the enforce loop. An EMPTY value means
        // the field was absent (an older web binary that predates it) — treat
        // that as "leave the stored policy untouched" so a skewed panel can't
        // silently downgrade a configured "suspend" back to "notify".
        let action = QuotaExceedAction::parse(exceed_action);
        if !exceed_action.trim().is_empty() {
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                detail.id.as_str(),
                QUOTA_KV_ACTION,
                action.as_str(),
                now,
            )
            .await;
        }

        // Push to kernel. Failure here doesn't fail the RPC — the
        // policy is saved either way and the UI shows last_error
        // so the operator can see the kernel didn't accept it
        // (typically because quotaon isn't enabled on the mount).
        let kernel_result = apply_disk_quota(
            &detail.system_user,
            &detail.root_dir,
            disk_soft_kib,
            disk_hard_kib,
        )
        .await;
        match kernel_result {
            Ok(QuotaApply::Applied) => {
                let _ = hyperion_state::hosting_quotas::mark_applied(
                    &self.pool,
                    detail.id.as_str(),
                    now,
                )
                .await;
                self.append_audit(
                    "hosting.quota.set",
                    Some(detail.id.as_str()),
                    &serde_json::json!({
                        "disk_soft_kib": disk_soft_kib,
                        "disk_hard_kib": disk_hard_kib,
                        "mem_limit_mib": mem_limit_mib,
                        "bw_soft_mib": bw_soft_mib,
                        "bw_hard_mib": bw_hard_mib,
                    })
                    .to_string(),
                    "ok",
                )
                .await;
            }
            Ok(QuotaApply::NoOp) => {
                // No disk cap to push (and quotas aren't active) — setquota
                // never ran, so DON'T stamp applied_at ("last applied to
                // kernel"). Clear any stale error from a prior failed apply.
                let _ = hyperion_state::hosting_quotas::mark_cleared(
                    &self.pool,
                    detail.id.as_str(),
                    now,
                )
                .await;
                self.append_audit(
                    "hosting.quota.set",
                    Some(detail.id.as_str()),
                    &serde_json::json!({ "disk": "no cap (no-op)" }).to_string(),
                    "ok",
                )
                .await;
            }
            Err(e) => {
                let _ = hyperion_state::hosting_quotas::mark_failed(
                    &self.pool,
                    detail.id.as_str(),
                    &e,
                    now,
                )
                .await;
                // A "pending reboot" deferral is not a hard failure — audit it
                // distinctly so the trail doesn't read as a kernel rejection.
                let status = if e.starts_with(QUOTA_PENDING_REBOOT_PREFIX) {
                    "pending"
                } else {
                    "failed"
                };
                self.append_audit(
                    "hosting.quota.set",
                    Some(detail.id.as_str()),
                    &serde_json::json!({ "error": e }).to_string(),
                    status,
                )
                .await;
            }
        }

        // Re-read so the UI sees the post-apply state (including
        // applied_at / last_error flips). Read the EFFECTIVE stored action (not
        // the parsed request) so the empty-string no-op case above reflects the
        // value we left in place rather than the "notify" default.
        let row = hyperion_state::hosting_quotas::read(&self.pool, detail.id.as_str())
            .await
            .map_err(|e| RpcError::Internal_with(format!("quota re-read: {e}")))?;
        let effective_action = self.hosting_quota_action(detail.id.as_str()).await;
        Ok(hyperion_types::HostingQuotaView {
            hosting_id: row.hosting_id,
            disk_soft_kib: row.disk_soft_kib,
            disk_hard_kib: row.disk_hard_kib,
            mem_limit_mib: row.mem_limit_mib,
            bw_soft_mib: row.bw_soft_mib,
            bw_hard_mib: row.bw_hard_mib,
            applied_at: row.applied_at,
            last_error: row.last_error,
            updated_at: row.updated_at,
            exceed_action: effective_action.as_str().to_string(),
        })
    }

    /// Read the per-hosting disk-overage policy from `hosting_kv` (default
    /// `Notify`). Seeded from the create profile; set via the Quota form.
    pub(crate) async fn hosting_quota_action(&self, hosting_id: &str) -> QuotaExceedAction {
        let v = hyperion_state::hosting_kv::get(&self.pool, hosting_id, QUOTA_KV_ACTION)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        QuotaExceedAction::parse(&v)
    }

    /// Re-push every stored disk cap into the kernel at agent boot. Without
    /// this, a cap saved while quotas needed a node reboot to activate is never
    /// re-applied: after the reboot the subsystem comes up (via fstab) but the
    /// per-user `setquota` limit was never written, so the hosting is silently
    /// uncapped until someone re-saves the form. Mirrors `bans_reapply_on_boot`.
    /// Best-effort per hosting; returns how many caps were (re)applied.
    pub async fn quotas_reapply_on_boot(&self) -> Result<i64, RpcError> {
        let rows = hyperion_state::hosting_quotas::list_with_caps(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("quota list: {e}")))?;
        let mut applied = 0i64;
        for row in rows {
            // Resolve the hosting's user + home dir; skip if it's gone.
            let detail = match self
                .get(HostingSelector::Id(HostingId(row.hosting_id.clone())))
                .await
            {
                Ok(d) => d,
                Err(_) => continue,
            };
            let now = now_secs();
            match apply_disk_quota(
                &detail.system_user,
                &detail.root_dir,
                row.disk_soft_kib,
                row.disk_hard_kib,
            )
            .await
            {
                Ok(QuotaApply::Applied) => {
                    let _ = hyperion_state::hosting_quotas::mark_applied(
                        &self.pool,
                        &row.hosting_id,
                        now,
                    )
                    .await;
                    applied += 1;
                }
                // A capped row can't legitimately be a no-op; ignore.
                Ok(QuotaApply::NoOp) => {}
                Err(e) => {
                    let _ = hyperion_state::hosting_quotas::mark_failed(
                        &self.pool,
                        &row.hosting_id,
                        &e,
                        now,
                    )
                    .await;
                }
            }
        }
        Ok(applied)
    }

    /// Enforce the per-hosting disk-overage policy. For each hosting with a disk
    /// HARD cap, compares current usage to the cap and applies the configured
    /// action (notify / suspend), with auto-resume when usage drops back under
    /// (90% hysteresis). De-dup + the suspend/resume decision live in the pure
    /// `quota_enforce_decide`; this method does the I/O and the safety guards so
    /// a manually-suspended site is never touched. Returns how many sites it
    /// acted on. Called on the 5-minute scheduler loop.
    pub async fn quota_enforce_tick(&self) -> Result<i64, RpcError> {
        let rows = hyperion_state::hosting_quotas::list_with_caps(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("quota list: {e}")))?;
        let mut acted = 0i64;
        for row in rows {
            let hard = row.disk_hard_kib;
            if hard <= 0 {
                continue; // only the HARD cap is the enforceable "size limit"
            }
            let detail = match self
                .get(HostingSelector::Id(HostingId(row.hosting_id.clone())))
                .await
            {
                Ok(d) => d,
                Err(_) => continue,
            };
            // A trashed site is out of this entirely. It is not `Suspended`, so
            // it fell through to the decision as if it were live: notify mode
            // mailed the owner about the disk of a site they had thrown away,
            // and suspend mode had `suspend()` refuse it and logged "will
            // retry" every five minutes until the purge.
            if detail.state == HostingState::Trashed {
                continue;
            }
            // Kernel-authoritative usage (whole-user, matches the setquota
            // scope). None ⇒ quotas aren't active/readable ⇒ skip rather than
            // act on an unreliable du estimate or a probe glitch.
            let used_kib = match quota_used_kib(&detail.system_user).await {
                Some(u) => u,
                None => continue,
            };
            let action = self.hosting_quota_action(&row.hosting_id).await;
            let stored = QuotaState::parse(
                &hyperion_state::hosting_kv::get(&self.pool, &row.hosting_id, QUOTA_KV_STATE)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
            );
            let mut state = stored;
            let now = now_secs();

            // Reconcile against the hosting's REAL state + the AUTHORITATIVE
            // suspension reason, so we only ever auto-resume suspensions we own
            // (over-disk), never an operator/expiry/bandwidth hold, and never
            // re-suspend a site an operator manually resumed.
            let suspended = detail.state == hyperion_types::HostingState::Suspended;
            if suspended {
                let reason = hyperion_state::limits::get_suspension(&self.pool, &detail.id)
                    .await
                    .ok()
                    .flatten()
                    .map(|s| s.suspended_by)
                    .unwrap_or_default();
                let expired = self
                    .get_expiry(HostingSelector::Id(detail.id.clone()))
                    .await
                    .ok()
                    .and_then(|e| e.expires_at)
                    .map(|t| t <= now)
                    .unwrap_or(false);
                if reason != hyperion_types::SuspendReason::OverDisk.label() || expired {
                    continue; // not ours / a higher-priority hold — leave alone
                }
                state = QuotaState::Suspended;
            } else if state == QuotaState::Suspended {
                // We suspended it; an operator manually resumed it → hold:
                // never auto-re-suspend until usage drops well under the cap.
                state = QuotaState::Released;
            }

            let (step, new_state) = quota_enforce_decide(used_kib, hard, action, state);
            let used_mib = used_kib / 1024;
            let cap_mib = hard / 1024;
            let det = serde_json::json!({ "used_mib": used_mib, "cap_mib": cap_mib }).to_string();
            let id = detail.id.as_str();

            // `committed` gates persisting new_state: a FAILED suspend/resume
            // leaves the stored state unchanged so the next tick retries instead
            // of masking the failure (and not notifying the customer "done").
            let committed = match step {
                QuotaStep::Nothing => true,
                QuotaStep::NotifyOver => {
                    self.notify_quota_over(&detail.domain, id, used_mib, cap_mib, false)
                        .await;
                    self.append_audit("quota.over", Some(id), &det, "ok").await;
                    acted += 1;
                    true
                }
                QuotaStep::Suspend => match self
                    .suspend(
                        HostingSelector::Id(detail.id.clone()),
                        hyperion_types::SuspendReason::OverDisk,
                    )
                    .await
                {
                    Ok(()) => {
                        self.notify_quota_over(&detail.domain, id, used_mib, cap_mib, true)
                            .await;
                        self.append_audit("quota.suspend", Some(id), &det, "ok")
                            .await;
                        acted += 1;
                        true
                    }
                    Err(e) => {
                        tracing::warn!(hosting = %id, error = %e, "quota: auto-suspend failed; will retry");
                        false
                    }
                },
                QuotaStep::AutoResume => {
                    match self.resume(HostingSelector::Id(detail.id.clone())).await {
                        Ok(()) => {
                            self.notify_quota_resolved(&detail.domain, id, used_mib, cap_mib)
                                .await;
                            self.append_audit("quota.autoresume", Some(id), &det, "ok")
                                .await;
                            acted += 1;
                            true
                        }
                        Err(e) => {
                            tracing::warn!(hosting = %id, error = %e, "quota: auto-resume failed; will retry");
                            false
                        }
                    }
                }
            };

            if committed && new_state != stored {
                let _ = hyperion_state::hosting_kv::set(
                    &self.pool,
                    &row.hosting_id,
                    QUOTA_KV_STATE,
                    new_state.as_str(),
                    now,
                )
                .await;
            }
        }
        Ok(acted)
    }

    /// Slack + email for a disk-overage event (over the cap, optionally
    /// suspended). Best-effort; mirrors the billing-reminder notify path.
    pub(super) async fn notify_quota_over(
        &self,
        domain: &str,
        hosting_id: &str,
        used_mib: i64,
        cap_mib: i64,
        suspended: bool,
    ) {
        // The CUSTOMER reads this one, so it follows the site's language.
        let cat = self
            .letter_catalog_for(&HostingId(hosting_id.to_string()))
            .await;
        // TWO catalogues on purpose. The subject and body reach the CUSTOMER, so
        // they follow the site's language; the Slack line reaches the OPERATOR's
        // shared channel, so it stays on the cluster language. Rendering both
        // from one catalogue is what made a Czech site post Czech alerts into an
        // English operator channel — the split this release states, broken by
        // the release that stated it.
        //
        // `action` is a SENTENCE FRAGMENT, so it has to be taken from each
        // catalogue separately; sharing one `args` would splice the customer's
        // language into the operator's line, which is the same bug one level in.
        let ops = self.letter_catalog();
        let key = if suspended {
            "quota.action_suspended"
        } else {
            "quota.action_over"
        };
        let used = used_mib.to_string();
        let cap = cap_mib.to_string();
        let what_cust = cat.get(key).to_string();
        let what_ops = ops.get(key).to_string();
        let args_cust = [
            ("domain", domain),
            ("used", used.as_str()),
            ("cap", cap.as_str()),
            ("action", what_cust.as_str()),
        ];
        let args_ops = [
            ("domain", domain),
            ("used", used.as_str()),
            ("cap", cap.as_str()),
            ("action", what_ops.as_str()),
        ];
        let slack = ops.render("quota.over.slack", &args_ops);
        let subj = cat.render("quota.over.subject", &args_cust);
        let body = cat.render("quota.over.body", &args_cust);
        self.notify_quota_event(hosting_id, &subj, &slack, &body)
            .await;
        // The bell speaks the operator's language, like every ops.* alert —
        // so the {action} fragment comes from that catalogue too. Suspended
        // means the site no longer serves: an error. Over but serving: warn.
        let what_bell = self.operator_catalog().get(key).to_string();
        self.notify_admins_say(
            if suspended { "error" } else { "warn" },
            "ops.quota_over",
            &[
                ("domain", domain),
                ("used", used.as_str()),
                ("cap", cap.as_str()),
                ("action", what_bell.as_str()),
            ],
            &format!("/hostings/{domain}"),
            &format!("quota.over:{domain}"),
        )
        .await;
    }

    /// Slack + email when a quota-suspended site drops back under the cap and is
    /// auto-resumed.
    pub(super) async fn notify_quota_resolved(
        &self,
        domain: &str,
        hosting_id: &str,
        used_mib: i64,
        cap_mib: i64,
    ) {
        // The CUSTOMER reads this one, so it follows the site's language.
        let cat = self
            .letter_catalog_for(&HostingId(hosting_id.to_string()))
            .await;
        let args = [
            ("domain", domain),
            ("used", &used_mib.to_string()),
            ("cap", &cap_mib.to_string()),
        ];
        // TWO catalogues on purpose. The subject and body reach the CUSTOMER, so
        // they follow the site's language; the Slack line reaches the OPERATOR's
        // shared channel, so it stays on the cluster language. Rendering both
        // from one catalogue is what made a Czech site post Czech alerts into an
        // English operator channel — the split this release states, broken by
        // the release that stated it.
        let ops = self.letter_catalog();
        let slack = ops.render("quota.resolved.slack", &args);
        let subj = cat.render("quota.resolved.subject", &args);
        let body = cat.render("quota.resolved.body", &args);
        self.notify_quota_event(hosting_id, &subj, &slack, &body)
            .await;
        self.notify_admins_say(
            "info",
            "ops.quota_resolved",
            &args,
            &format!("/hostings/{domain}"),
            &format!("quota.resolved:{domain}"),
        )
        .await;
    }

    /// Send a quota notification over Slack (default webhook) + email (the
    /// hosting's owner_email when set, else the cluster default).
    pub(super) async fn notify_quota_event(
        &self,
        hosting_id: &str,
        subj: &str,
        slack_msg: &str,
        body: &str,
    ) {
        self.notify_slack(None, slack_msg).await;
        let to = self
            .get_expiry(HostingSelector::Id(HostingId(hosting_id.to_string())))
            .await
            .ok()
            .and_then(|e| e.owner_email)
            .unwrap_or_default();
        self.notify_email(&to, subj, body, Some(hosting_id), "quota")
            .await;
    }
}

/// Push a per-user disk cap into the kernel for the filesystem carrying
/// `home_dir`, via `setquota -u <user> <soft> <hard> 0 0 <mount>`.
///
/// Semantics by request:
///   - **positive cap** (soft>0 || hard>0): the cap must be enforceable, so if
///     kernel quotas aren't active on that mount yet we enable them
///     automatically (fstab + remount + quotacheck + quotaon) and retry. If
///     that can't finish live we return a clear, reboot-aware message — the
///     caller still saves the policy, so it applies after the reboot.
///   - **no cap** (soft==0 && hard==0): clear any existing cap when quotas are
///     active; a no-op (Ok) when they're not — we don't touch fstab/remount
///     just to express "no limit", so a memory/bandwidth-only save never
///     triggers a disk-quota error.
///
/// Inode limits are left at 0 (no cap) — operators care about disk space, not
/// file count.
///
/// The active-state probe uses the SAME canonical parser as the enable/read
/// path (`ext_quota_on` → `quota_report_shows_on`, matching `quotaon -p`'s
/// `… is on`). A previous bespoke scan here looked for the literal
/// `user quotas on`, which modern quota-tools never print (`user quota on … is
/// on`), so it false-negatived and refused setquota even when quotas were on.
/// Outcome of a successful `apply_disk_quota`. Distinguishes a real `setquota`
/// push from a no-op so the caller doesn't stamp `applied_at` (i.e. claim "last
/// applied to kernel") when nothing actually ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QuotaApply {
    /// `setquota` ran — the cap (or its removal) is live in the kernel.
    Applied,
    /// No disk cap requested and quotas aren't active — nothing to do.
    NoOp,
}

/// Prefix that marks a "saved, pending a node reboot" error so the web boundary
/// can render it as an amber "activates after reboot" notice rather than a red
/// "kernel rejected it" failure. The boot reconciler (`quotas_reapply_on_boot`)
/// re-pushes the cap once the reboot brings the subsystem up.
pub(super) const QUOTA_PENDING_REBOOT_PREFIX: &str =
    "kernel quotas need a reboot to finish activating";

pub(super) async fn apply_disk_quota(
    user: &str,
    home_dir: &str,
    soft_kib: i64,
    hard_kib: i64,
) -> Result<QuotaApply, String> {
    let mount = mount_point_for(home_dir).await;
    let on = match &mount {
        Some(mp) => ext_quota_on(mp).await,
        None => false,
    };

    let wants_cap = soft_kib > 0 || hard_kib > 0;
    if !wants_cap && !on {
        // Nothing to enforce and nothing enabled to clear — success no-op.
        // (No setquota ran, so the caller must NOT stamp applied_at.)
        return Ok(QuotaApply::NoOp);
    }

    // The filesystem to target with setquota. Resolved from the home dir, or
    // from enable_kernel_quotas when we had to bring quotas up. We NEVER fall
    // back to `setquota -a` (every quota-enabled fs) — that would broadcast a
    // per-user cap onto unrelated mounts.
    let mut target_mount = mount.clone();

    if wants_cap && !on {
        // Bring kernel quotas up so the cap is actually enforceable.
        // enable_kernel_quotas is idempotent: the fstab splice no-ops when the
        // option is already present and an already-active fs short-circuits. On
        // success we fall through to setquota; otherwise surface why it didn't.
        let summary = enable_kernel_quotas(home_dir).await;
        if !summary.ok {
            return Err(if summary.requires_reboot {
                format!(
                    "{QUOTA_PENDING_REBOOT_PREFIX} — {} The limit is saved and will be enforced after the node reboots.",
                    summary.message
                )
            } else {
                format!(
                    "couldn't enable kernel quotas automatically: {}",
                    summary.message
                )
            });
        }
        if target_mount.as_deref().unwrap_or("").is_empty() && !summary.mount_point.is_empty() {
            target_mount = Some(summary.mount_point);
        }
    }

    let mount_arg = match target_mount {
        Some(mp) if !mp.is_empty() => mp,
        _ => return Err("couldn't determine which filesystem to apply the disk quota to".into()),
    };
    let out = tokio::process::Command::new("/usr/sbin/setquota")
        .args([
            "-u",
            user,
            &soft_kib.to_string(),
            &hard_kib.to_string(),
            "0",
            "0",
            &mount_arg,
        ])
        .output()
        .await
        .map_err(|e| format!("spawn setquota: {e}"))?;
    if out.status.success() {
        Ok(QuotaApply::Applied)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        Err(format!(
            "setquota exit {}: {}{}",
            out.status.code().unwrap_or(-1),
            stderr.trim(),
            stdout.trim(),
        ))
    }
}

/// Probe current disk usage for the hosting:
///   1. `quota -u <user>` if quotas are enabled — single line, fast,
///      reports the kernel's view (matches what `setquota` enforces)
///   2. fallback `du -sk <home>` if quota is unavailable — slower but
///      always works (lets the UI show *some* number even on VPSes
///      without quotas configured).
///
/// Longest mountpoint in /proc/self/mounts that contains `path` (so we can ask
/// `quotaon -p` about the right filesystem). Mirrors the discovery in
/// `enable_kernel_quotas`.
pub(super) async fn mount_point_for(path: &str) -> Option<String> {
    let mounts = tokio::fs::read_to_string("/proc/self/mounts").await.ok()?;
    let mut best: Option<String> = None;
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let mp = unescape_mount_field(f[1]);
        let covers =
            path == mp || mp == "/" || path.starts_with(&format!("{}/", mp.trim_end_matches('/')));
        if covers && best.as_ref().map(|m| mp.len() > m.len()).unwrap_or(true) {
            best = Some(mp);
        }
    }
    best
}

/// `hosting_kv` key: per-hosting overage policy ("notify" | "suspend").
pub(super) const QUOTA_KV_ACTION: &str = "quota_exceed_action";
/// `hosting_kv` key: de-dup state for the enforce loop ("ok"|"over"|"suspended").
pub(super) const QUOTA_KV_STATE: &str = "quota_exceed_state";

/// Per-hosting policy for when disk usage crosses the hard cap. Stored in
/// `hosting_kv` under `quota_exceed_action`; seeded from the profile at create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaExceedAction {
    /// Send a notification only (default). Where kernel quotas are enabled,
    /// setquota also blocks writes at the cap; where they're off, this alert is
    /// the only signal.
    Notify,
    /// Suspend the site (and notify).
    Suspend,
}
impl QuotaExceedAction {
    pub(crate) fn parse(s: &str) -> Self {
        match s.trim() {
            "suspend" => Self::Suspend,
            _ => Self::Notify,
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Notify => "notify",
        }
    }
}

/// De-dup state for the enforce loop, stored per hosting in `hosting_kv` under
/// `quota_exceed_state`. `Suspended` means WE auto-suspended it (so we may
/// auto-resume); `Released` means we suspended it but an operator manually
/// resumed it — we hold off and NEVER auto-re-suspend until usage drops back
/// well under the cap. A manually/expiry-suspended site never reaches these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QuotaState {
    Ok,
    Over,
    Suspended,
    Released,
}
impl QuotaState {
    pub(super) fn parse(s: &str) -> Self {
        match s.trim() {
            "over" => Self::Over,
            "suspended" => Self::Suspended,
            "released" => Self::Released,
            _ => Self::Ok,
        }
    }
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Over => "over",
            Self::Suspended => "suspended",
            Self::Released => "released",
            Self::Ok => "ok",
        }
    }
}

/// What `quota_enforce_tick` should do for one hosting this round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QuotaStep {
    Nothing,
    NotifyOver,
    Suspend,
    AutoResume,
}

/// Precedence for a `SuspendReason::label()`. Operator/lifecycle holds (manual,
/// expired) outrank automated usage holds (over-disk, over-bandwidth). A second
/// `suspend()` on an already-suspended site only overwrites the recorded reason
/// when the incoming one strictly outranks the current — so a manual/expiry
/// hold "sticks" over an auto over-disk suspend (and the quota loop then leaves
/// it alone), while a lower-or-equal reason stays idempotent.
pub(super) fn suspend_reason_rank(label: &str) -> u8 {
    match label {
        "manual" | "expired" => 2,
        _ => 1, // over-disk, over-bandwidth, or unknown/missing
    }
}

/// Pure decision core: given current disk usage vs the hard cap, the configured
/// action, and the last recorded state, return (step, new_state). Auto-resume
/// uses **90%-of-cap hysteresis** so a site hovering at the limit can't flap
/// suspend/resume. The caller separately guards the hosting's real
/// Active/Suspended state + the authoritative suspension reason so a manually-
/// or expiry-suspended site is never auto-resumed.
pub(super) fn quota_enforce_decide(
    used_kib: i64,
    hard_cap_kib: i64,
    action: QuotaExceedAction,
    state: QuotaState,
) -> (QuotaStep, QuotaState) {
    if hard_cap_kib <= 0 {
        return (QuotaStep::Nothing, QuotaState::Ok);
    }
    let over = used_kib >= hard_cap_kib;
    // 90% hysteresis, but never round the floor below 1 KiB — otherwise a
    // 1-KiB cap could never report "well under" and would never re-arm.
    let well_under = used_kib < (hard_cap_kib * 9 / 10).max(1);

    match state {
        QuotaState::Suspended => {
            if well_under {
                (QuotaStep::AutoResume, QuotaState::Ok)
            } else {
                (QuotaStep::Nothing, QuotaState::Suspended)
            }
        }
        // We suspended it; an operator manually resumed it. Respect that: never
        // auto-re-suspend. Only re-arm (back to Ok) once usage drops well under.
        QuotaState::Released => {
            if well_under {
                (QuotaStep::Nothing, QuotaState::Ok)
            } else {
                (QuotaStep::Nothing, QuotaState::Released)
            }
        }
        QuotaState::Ok | QuotaState::Over => {
            if over {
                match action {
                    QuotaExceedAction::Suspend => (QuotaStep::Suspend, QuotaState::Suspended),
                    QuotaExceedAction::Notify if state == QuotaState::Over => {
                        (QuotaStep::Nothing, QuotaState::Over) // already notified
                    }
                    QuotaExceedAction::Notify => (QuotaStep::NotifyOver, QuotaState::Over),
                }
            } else if well_under {
                (QuotaStep::Nothing, QuotaState::Ok) // reset; re-notify on next crossing
            } else {
                (QuotaStep::Nothing, state) // between 90% and cap: hold
            }
        }
    }
}

/// Kernel-authoritative per-user disk usage in KiB for the enforce loop. Uses
/// `quota -u -w` (whole-user accounting, the same scope `setquota -u` caps) and
/// returns `None` when the quota subsystem isn't active/readable — so the loop
/// SKIPS the site rather than acting on an unreliable number. We deliberately do
/// NOT gate on exit status: `quota` exits 1 precisely when the user is OVER
/// quota (the case we care about) and only 2 on a real error; we instead key on
/// whether a numeric data line was produced. (The `du` fallback used by the
/// read-only report measures only the docroot, a different scope — never used
/// to drive a suspend/resume decision.)
pub(super) async fn quota_used_kib(user: &str) -> Option<i64> {
    let out = tokio::process::Command::new("/usr/bin/quota")
        .args(["-u", "-w", user])
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Data line: "<device> <blocks> <quota> <limit> ...". blocks = cols[1],
        // possibly with a trailing '*' (over soft limit). Header lines have a
        // non-numeric cols[1] and are skipped.
        if cols.len() >= 2 {
            if let Ok(u) = cols[1].trim_end_matches('*').parse::<i64>() {
                return Some(u);
            }
        }
    }
    None
}

/// Returns (current_disk_kib, quotas_enabled_on_fs, setup_hint).
pub(super) async fn quota_probe_current(user: &str, home_dir: &str) -> (i64, bool, String) {
    // Whether the quota SUBSYSTEM is active on the fs holding home_dir, via the
    // SAME probe the enable flow uses (`quotaon -p`). We must NOT infer this
    // from per-user `quota` output: `quota -q` prints nothing while the user is
    // UNDER quota, which is the normal case right after enabling (no cap set
    // yet) — so the old heuristic read "enabled" as false and the banner never
    // cleared even though quotas were on.
    let enabled = match mount_point_for(home_dir).await {
        Some(mp) => ext_quota_on(&mp).await,
        None => false,
    };

    // Current usage: prefer the kernel's accounting (`quota -u -w`, no `-q` so
    // it prints even when under quota), else `du`.
    let mut used = 0i64;
    if let Ok(out) = tokio::process::Command::new("/usr/bin/quota")
        .args(["-u", "-w", user])
        .output()
        .await
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 2 {
                    if let Ok(u) = cols[1].trim_end_matches('*').parse::<i64>() {
                        used = u;
                        break;
                    }
                }
            }
        }
    }
    // NO `du` FALLBACK HERE. It used to run whenever the kernel probe
    // returned 0 — which is every box without kernel quotas, i.e. the default
    // — walking the site's entire tree, with no timeout, on every hosting
    // detail page load. On a 20 GB site with a cold page cache that is
    // seconds to tens of seconds of wall clock before anything renders, for a
    // number that is only ENFORCED when quotas are on.
    //
    // The caller substitutes the last sampled figure instead (see quota_get):
    // five minutes stale and instant beats exact and unusable. `du` still
    // runs, but on the sampler's schedule, where taking a while is fine.

    let hint = if enabled {
        String::new()
    } else {
        "Kernel quotas aren't enabled on this filesystem. Disk usage is shown from `du`, but `setquota` won't enforce caps. Use the \"Enable kernel quotas\" button to set this up automatically.".to_string()
    };
    (used, enabled, hint)
}

/// Run a command, returning trimmed stdout (+ stderr) for status messages.
/// Run a quota-related command. Returns `(success, text)` where `success`
/// reflects the process **exit status** (not whether it printed anything) and
/// `text` is the merged stdout+stderr for diagnostics/messages. Callers that
/// need to know "did it work?" must look at `success` — parsing English out of
/// `text` is fragile (a command can exit 0 yet print an advisory to stderr,
/// e.g. systemd's "fstab modified, run daemon-reload" hint after a remount).
pub(super) async fn quota_run_cmd(bin: &str, args: &[&str]) -> (bool, String) {
    match tokio::process::Command::new(bin).args(args).output().await {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let e = String::from_utf8_lossy(&o.stderr);
            if !e.trim().is_empty() {
                if !s.is_empty() {
                    s.push_str("; ");
                }
                s.push_str(e.trim());
            }
            if s.is_empty() {
                s = format!("exit {}", o.status.code().unwrap_or(-1));
            }
            (o.status.success(), s)
        }
        Err(e) => (false, format!("spawn {bin}: {e}")),
    }
}

/// Like `quota_run_cmd` but aborts after `secs`, reporting a timeout as a
/// failure. Used for `quotacheck`, which scans every inode on the filesystem
/// and can run for minutes on a large/busy disk — since enabling quotas now
/// happens inline on a quota save, an unbounded quotacheck could otherwise hang
/// the RPC. The spawned process is left to finish in the background (it's
/// building the aquota files either way); we just stop waiting on it.
pub(super) async fn quota_run_cmd_timeout(bin: &str, args: &[&str], secs: u64) -> (bool, String) {
    match tokio::time::timeout(
        std::time::Duration::from_secs(secs),
        quota_run_cmd(bin, args),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => (
            false,
            format!("{bin} still running after {secs}s — left to finish in the background"),
        ),
    }
}

/// `/proc/self/mounts` escapes spaces (and a few others) octally.
pub(super) fn unescape_mount_field(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

/// Byte ranges (start, end) of each whitespace-delimited field in an fstab
/// line. fstab separates fields with spaces and/or tabs only, so we split on
/// exactly those — preserving the original separators between fields lets a
/// caller splice one field without disturbing the rest of the line (comments,
/// alignment, an inline `# ...` tail).
pub(super) fn fstab_field_ranges(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' {
            i += 1;
        }
        ranges.push((start, i));
    }
    ranges
}

/// Pure core of the fstab edit: given the file `content`, return the rewritten
/// content with `to_add` options appended to the options column of the line for
/// `mount_point`. `Ok(Some(new))` = a change is needed, `Ok(None)` = the
/// options were already present (no write), `Err` = no matching mount line.
///
/// Only the options column (field 4) of the one matching line is touched —
/// every other byte (leading whitespace, separators, an inline `# ...` tail,
/// blank/comment lines, the trailing-newline style) is preserved verbatim so
/// the rewrite is a minimal, safe diff that can never break boot.
pub(super) fn fstab_with_quota_options(
    content: &str,
    mount_point: &str,
    to_add: &[&str],
) -> Result<Option<String>, String> {
    let mut found = false;
    let mut added_any = false;
    let mut out: Vec<String> = Vec::new();
    let had_trailing_nl = content.ends_with('\n');
    for line in content.lines() {
        let t = line.trim_start();
        if t.is_empty() || t.starts_with('#') {
            out.push(line.to_string());
            continue;
        }
        let ranges = fstab_field_ranges(line);
        // Field 1 = mountpoint, field 3 = options. Both fstab and
        // /proc/self/mounts octal-escape spaces/tabs/backslashes, so compare
        // after unescaping — otherwise a mountpoint with a space (escaped in
        // fstab, literal in our `mount_point`) would never match.
        let is_match = ranges.len() >= 4
            && unescape_mount_field(&line[ranges[1].0..ranges[1].1]) == mount_point;
        if is_match {
            found = true;
            let (opt_start, opt_end) = ranges[3];
            let mut opts: Vec<String> = line[opt_start..opt_end]
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            for o in to_add {
                if !opts.iter().any(|x| x == o) {
                    opts.push((*o).to_string());
                    added_any = true;
                }
            }
            // Splice ONLY the options column; everything else stays byte-for-byte.
            let spliced = format!(
                "{}{}{}",
                &line[..opt_start],
                opts.join(","),
                &line[opt_end..]
            );
            out.push(spliced);
        } else {
            out.push(line.to_string());
        }
    }
    if !found {
        return Err(format!("no /etc/fstab entry for {mount_point}"));
    }
    if !added_any {
        return Ok(None);
    }
    let mut new_content = out.join("\n");
    if had_trailing_nl {
        new_content.push('\n');
    }
    Ok(Some(new_content))
}

/// Ensure `/etc/fstab` carries the quota mount option(s) on the line for
/// `mount_point`. Returns Ok(true) if a change was written, Ok(false) if
/// the option was already present, Err if there's no matching fstab line.
/// Writes atomically (tmp + rename) and only ever appends to field 4 of
/// the one matching line — never restructures the file.
pub(super) async fn ensure_fstab_quota_option(
    mount_point: &str,
    is_xfs: bool,
) -> Result<bool, String> {
    let path = "/etc/fstab";
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("read {path}: {e}"))?;
    let to_add: &[&str] = if is_xfs {
        // XFS user+group quota in its native spelling. This MUST match the
        // enforce path, which uses `setquota -u` (user quotas): `prjquota`
        // would provision PROJECT accounting that `setquota -u` can't target,
        // so a cap would silently never apply even after a reboot.
        &["uquota", "gquota"]
    } else {
        &["usrquota", "grpquota"]
    };
    let new_content = match fstab_with_quota_options(&content, mount_point, to_add)? {
        Some(c) => c,
        None => return Ok(false),
    };
    let tmp = format!("{path}.hyperion.tmp");
    tokio::fs::write(&tmp, new_content.as_bytes())
        .await
        .map_err(|e| format!("write {tmp}: {e}"))?;
    // Carry the original fstab's permission bits onto the replacement so a
    // hardened mode (e.g. 0600) survives the atomic swap instead of being
    // reset to the umask default. Owner stays root:root — the agent is root.
    if let Ok(meta) = tokio::fs::metadata(path).await {
        let _ = tokio::fs::set_permissions(&tmp, meta.permissions()).await;
    }
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| format!("rename {tmp}: {e}"))?;
    Ok(true)
}

/// True when ext-family quotas report active on `mount_point`.
///
/// `quotaon -p` always exits 0 (it's a query), so we have to read its text.
/// Modern quota-tools print one line per type, e.g.
///   `user quota on /home (/dev/sda3) is on`
///   `group quota on /home (/dev/sda3) is off`
/// older builds print `... user quotas turned on`. We treat the fs as enabled
/// when any line ends in the "on" state (`is on` / `turned on`); crucially
/// `is on` is NOT a substring of `is off`, so an off line never false-matches.
pub(super) async fn ext_quota_on(mount_point: &str) -> bool {
    let (_ok, out) = quota_run_cmd("/usr/sbin/quotaon", &["-p", mount_point]).await;
    quota_report_shows_on(&out)
}

/// Parse `quotaon -p` output and report whether any quota type is active.
/// `is on` / `turned on` mean active; `is off` does NOT contain `is on`, so
/// an off-only report correctly reads as inactive.
pub(super) fn quota_report_shows_on(out: &str) -> bool {
    out.lines().any(|l| {
        let l = l.to_lowercase();
        l.contains("is on") || l.contains("turned on")
    })
}

/// `apt-get install quota`. Returns (succeeded, combined stdout+stderr) — apt
/// prints the REAL dpkg error (e.g. "Read-only file system") to STDOUT, while
/// only the generic "E: Sub-process ... error code (1)" goes to stderr, so we
/// must capture both to diagnose a failure.
pub(super) async fn apt_install_quota() -> (bool, String) {
    match tokio::process::Command::new("/usr/bin/apt-get")
        .args(["install", "-y", "--no-install-recommends", "quota"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .await
    {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s)
        }
        Err(e) => (false, format!("couldn't exec apt-get: {e}")),
    }
}

/// Operator-facing failure message carrying the last few lines of apt's output
/// (the real cause) instead of the opaque "Sub-process dpkg returned 1".
pub(super) fn quota_install_err(output: &str) -> String {
    let tail = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ");
    format!(
        "the `quota` package isn't installed and auto-install failed: {tail} — \
         on the node, run `sudo dpkg --configure -a` then `sudo apt-get install -y quota` \
         (if `/` is read-only, first `sudo mount -o remount,rw /`)."
    )
}

pub(super) async fn ensure_quota_tools() -> Result<(), String> {
    let have = |p: &str| std::path::Path::new(p).exists();
    if have("/usr/sbin/quotaon") && have("/usr/sbin/quotacheck") {
        return Ok(());
    }
    tracing::info!("quota tools missing — installing the `quota` package via apt-get");

    let (ok, combined) = apt_install_quota().await;
    if ok && have("/usr/sbin/quotaon") {
        return Ok(());
    }

    // The two usual reasons `dpkg returned error code (1)` here are (a) this
    // node's read-only-/usr hardening (apt can't write) and (b) a half-
    // configured dpkg from an interrupted run. Address whichever applies, then
    // retry once. The remount mirrors the operator-facing ROFS unlock
    // (remount_usr_rw); the hardening re-applies on the next reboot.
    let lower = combined.to_lowercase();
    let mut recovered = false;
    if lower.contains("read-only file system") || lower.contains("erofs") {
        tracing::warn!("apt failed on a read-only filesystem — remounting rw and retrying");
        let _ = tokio::process::Command::new("/usr/bin/mount")
            .args(["-o", "remount,rw", "/"])
            .output()
            .await;
        let _ = tokio::process::Command::new("/usr/bin/mount")
            .args(["-o", "remount,rw", "/usr"])
            .output()
            .await;
        recovered = true;
    }
    if lower.contains("dpkg was interrupted")
        || lower.contains("--configure -a")
        || lower.contains("half-configured")
        || lower.contains("half-installed")
    {
        tracing::warn!("dpkg is wedged — running `dpkg --configure -a` before retry");
        let _ = tokio::process::Command::new("/usr/bin/dpkg")
            .args(["--configure", "-a"])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .output()
            .await;
        recovered = true;
    }

    if recovered {
        let (ok2, combined2) = apt_install_quota().await;
        if ok2 && have("/usr/sbin/quotaon") {
            return Ok(());
        }
        return Err(quota_install_err(&combined2));
    }
    Err(quota_install_err(&combined))
}

pub(super) async fn enable_kernel_quotas(home_path: &str) -> hyperion_types::QuotaEnableSummary {
    use hyperion_types::QuotaEnableSummary as Summary;
    let fail = |message: String, mount_point: String, fs_type: String| Summary {
        ok: false,
        requires_reboot: false,
        fs_type,
        mount_point,
        message,
    };

    // 0. Root check — mount / quotacheck / quotaon all need it.
    let uid = tokio::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .await
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        });
    if uid != Some(0) {
        return fail(
            "the agent isn't running as root, so it can't change mount options or enable quotas"
                .into(),
            String::new(),
            String::new(),
        );
    }

    // 0b. The quota user-space tools (quotaon / quotacheck / setquota) live in
    // the Debian `quota` package, which isn't part of a base install — without
    // it the steps below fail with "No such file or directory" (and a reboot
    // never fixes it). This feature is meant to be automatic, so install the
    // package on demand before we touch fstab.
    if let Err(e) = ensure_quota_tools().await {
        return fail(e, String::new(), String::new());
    }

    // 1. Discover the mount carrying home_path (longest matching mountpoint).
    let mounts = match tokio::fs::read_to_string("/proc/self/mounts").await {
        Ok(s) => s,
        Err(e) => {
            return fail(
                format!("couldn't read /proc/self/mounts: {e}"),
                String::new(),
                String::new(),
            )
        }
    };
    let mut best: Option<(String, String, String, String)> = None; // (mount, fstype, options, device)
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let mp = unescape_mount_field(f[1]);
        let covers = home_path == mp
            || mp == "/"
            || home_path.starts_with(&format!("{}/", mp.trim_end_matches('/')));
        if covers {
            let better = best
                .as_ref()
                .map(|(m, _, _, _)| mp.len() > m.len())
                .unwrap_or(true);
            if better {
                best = Some((
                    mp,
                    f[2].to_string(),
                    f[3].to_string(),
                    unescape_mount_field(f[0]),
                ));
            }
        }
    }
    let (mount_point, fs_type, cur_opts, device) = match best {
        Some(v) => v,
        None => {
            return fail(
                format!("couldn't find the mount for {home_path}"),
                String::new(),
                String::new(),
            )
        }
    };

    let is_xfs = fs_type == "xfs";
    let already_mounted = cur_opts.split(',').any(|o| {
        // ext family: usrquota/grpquota/prjquota · XFS: uquota/gquota/pquota
        // (and the bare `quota` alias). Any of these means the quota option is
        // already live on this mount.
        matches!(
            o,
            "usrquota" | "grpquota" | "prjquota" | "quota" | "uquota" | "gquota" | "pquota"
        )
    });

    // 2. Make sure /etc/fstab carries the quota option for next boot.
    let fstab_added = match ensure_fstab_quota_option(&mount_point, is_xfs).await {
        Ok(added) => added,
        Err(e) => {
            return fail(
                format!("couldn't update /etc/fstab: {e}"),
                mount_point,
                fs_type,
            )
        }
    };
    let fstab_note = if fstab_added {
        "/etc/fstab updated"
    } else {
        "/etc/fstab already had it"
    };

    // 3. XFS: quota accounting only initialises at mount, never on a live fs.
    if is_xfs {
        // If the option is already live AND reports on, accounting is active
        // now (XFS turns it on at mount) — nothing to reboot for.
        if already_mounted && ext_quota_on(&mount_point).await {
            return Summary {
                ok: true,
                requires_reboot: false,
                fs_type,
                mount_point,
                message: "XFS kernel quotas are already active on this filesystem — set a disk limit below to enforce a per-hosting cap."
                    .into(),
            };
        }
        return Summary {
            ok: false,
            requires_reboot: true,
            fs_type,
            mount_point: mount_point.clone(),
            message: format!(
                "{fstab_note}. XFS quotas can only initialise at mount time — reboot the node (or remount {mount_point} while it's idle) to activate them."
            ),
        };
    }

    // 3b. Already active? Then there's nothing to do — and running the
    // remount/quotacheck/quotaon dance below would only emit confusing errors:
    // on a filesystem using the ext4 *quota feature* (internal/journaled
    // quotas), quotacheck refuses ("quota for users is enabled … might damage")
    // and `quotaon` fails EBUSY ("Device or resource busy") precisely because
    // quotas are ALREADY on. Detect that up front via the canonical probe and
    // report success cleanly. setquota -u works against this state.
    if ext_quota_on(&mount_point).await {
        return Summary {
            ok: true,
            requires_reboot: false,
            fs_type,
            mount_point,
            message: "Kernel quotas are already active on this filesystem — set a disk limit below to enforce a per-hosting cap.".into(),
        };
    }

    // 4. ext-family: remount to load the quota option, then build + turn on.
    if !already_mounted {
        let (remount_ok, remount_msg) = quota_run_cmd(
            "/usr/bin/mount",
            &["-o", "remount,usrquota,grpquota", &mount_point],
        )
        .await;
        // Success is the process EXIT STATUS, not the text: a clean remount can
        // still print an advisory to stderr (e.g. systemd's "fstab modified,
        // run daemon-reload" hint after we edited fstab above). Only a non-zero
        // exit is a real failure.
        if !remount_ok {
            let lower = remount_msg.to_lowercase();
            let busy = lower.contains("busy") || lower.contains("in use");
            if busy {
                // Filesystem is live and held open — only a reboot (or freeing
                // it) can remount it. fstab is already set, so the reboot sticks.
                return Summary {
                    ok: false,
                    requires_reboot: true,
                    fs_type,
                    mount_point: mount_point.clone(),
                    message: format!(
                        "{fstab_note}, but {mount_point} is busy and couldn't be remounted live ({remount_msg}). Reboot the node (or free the filesystem and retry) to activate quotas."
                    ),
                };
            }
            // A hard error (bad option, read-only fs, unsupported option, …).
            // Surface the actual error instead of silently proceeding to
            // quotacheck/quotaon on an fs that never got the quota option.
            // A reboot only helps when the SAME fstab option would mount
            // cleanly next time (e.g. a transient read-only `/`). A bad /
            // unsupported option fails identically at boot, so don't promise a
            // reboot for those — they need operator attention.
            let bad_option = lower.contains("bad option")
                || lower.contains("unsupported")
                || lower.contains("unrecognized")
                || lower.contains("invalid argument");
            return Summary {
                ok: false,
                requires_reboot: mount_point == "/" && !bad_option,
                fs_type,
                mount_point: mount_point.clone(),
                message: if bad_option {
                    format!(
                        "{fstab_note}, but {mount_point} rejected the quota mount option: {remount_msg}. This filesystem/kernel doesn't support it the way we tried — a reboot won't change that; it needs operator attention."
                    )
                } else {
                    format!(
                        "{fstab_note}, but remounting {mount_point} with quota options failed: {remount_msg}."
                    )
                },
            };
        }
    }
    // quotacheck builds aquota.user/.group; -m allows it while mounted. Bound
    // it so a huge/busy filesystem can't hang the save RPC (it keeps building
    // in the background; quotaon below still tries, and a re-save finishes it).
    let (_check_ok, check_msg) =
        quota_run_cmd_timeout("/usr/sbin/quotacheck", &["-ugm", &mount_point], 240).await;
    let (_qon_ok, qon) = quota_run_cmd("/usr/sbin/quotaon", &["-v", &mount_point]).await;
    if ext_quota_on(&mount_point).await {
        Summary {
            ok: true,
            requires_reboot: false,
            fs_type,
            mount_point,
            message: "Kernel quotas are now active — set a disk limit below to enforce a per-hosting cap.".into(),
        }
    } else if ext4_has_quota_feature(&device).await == Some(false) {
        // Accounting didn't start AND the on-disk `quota` feature is absent: a
        // reboot just re-reads the same fstab option and still won't enable it.
        // The one-time fix is `tune2fs -O quota`, not a reboot.
        Summary {
            ok: false,
            requires_reboot: false,
            fs_type,
            mount_point: mount_point.clone(),
            message: format!(
                "{fstab_note} + quotacheck/quotaon ran, but {mount_point} ({device}) lacks the on-disk quota feature, so accounting can't start — a reboot won't help. Enable it once with `tune2fs -O quota {device}` ({mount_point} must be unmounted, or use single-user mode for `/`), then re-run. (quotacheck: {check_msg}; quotaon: {qon})"
            ),
        }
    } else {
        Summary {
            ok: false,
            requires_reboot: true,
            fs_type,
            mount_point: mount_point.clone(),
            message: format!(
                "{fstab_note} + quotacheck/quotaon ran, but quotas don't report active yet (quotacheck: {check_msg}; quotaon: {qon}). A reboot usually finishes the setup."
            ),
        }
    }
}

/// Whether the ext-family filesystem on `device` carries the on-disk `quota`
/// feature flag (`tune2fs -l`). Returns `None` when we can't tell — tune2fs
/// missing, a non-ext device, or an unparseable report — so callers never
/// over-claim "feature absent" and wrongly suppress the reboot advice. When
/// this is `Some(false)`, the mount option alone can't start accounting; the
/// fs needs `tune2fs -O quota` first (a reboot won't help).
pub(super) async fn ext4_has_quota_feature(device: &str) -> Option<bool> {
    let out = tokio::process::Command::new("/usr/sbin/tune2fs")
        .args(["-l", device])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some((key, val)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("Filesystem features") {
                return Some(val.split_whitespace().any(|f| f == "quota"));
            }
        }
    }
    None
}
