//! Hosting expiry dates, usage readback and the generic hosting_kv store.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    pub async fn usage(
        &self,
        sel: HostingSelector,
        limit: i64,
    ) -> Result<Vec<hyperion_types::HostingUsageBucket>, RpcError> {
        let detail = self.get(sel).await?;
        let rows = hyperion_state::limits::usage_for(&self.pool, &detail.id, limit.clamp(1, 744))
            .await
            .map_err(|e| RpcError::Internal_with(format!("usage: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|b| hyperion_types::HostingUsageBucket {
                period: b.period,
                disk_used_bytes: b.disk_used_bytes,
                inodes_used: b.inodes_used,
                bw_in_bytes: b.bw_in_bytes,
                bw_out_bytes: b.bw_out_bytes,
                php_requests: b.php_requests,
            })
            .collect())
    }

    pub async fn set_expiry(
        &self,
        sel: HostingSelector,
        expiry: hyperion_types::HostingExpiry,
    ) -> Result<hyperion_types::HostingExpiry, RpcError> {
        let detail = self.get(sel).await?;
        let grace = expiry.grace_days.clamp(1, 365);
        // A renewal date is a day and a month. An operator typing 2024 is
        // recording when the customer came to us, not asking for a hosting
        // that expired two years ago — which, taken literally, would have the
        // sweep below suspend a live site the moment this was saved. So a past
        // date rolls forward to its next occurrence and the original is kept
        // separately, purely to show. A future date is untouched.
        let now = now_secs();
        // A start date already on record survives an edit that does not
        // restate it — saving a new grace period, or naming a real future end
        // date, must not erase since when the customer has been with us.
        let stored_since = hyperion_state::scheduler::get_expiry(&self.pool, &detail.id)
            .await
            .ok()
            .flatten()
            .and_then(|r| r.customer_since);
        let (expires_at, customer_since) = match expiry.expires_at {
            // A past date IS the start date, and the operator retyping it is
            // how they correct it — so it wins over what is stored.
            Some(entered) if entered <= now => (
                Some(hyperion_types::next_anniversary(entered, now)),
                Some(entered),
            ),
            other => (other, expiry.customer_since.or(stored_since)),
        };
        let offsets = hyperion_state::scheduler::parse_offsets(&expiry.warning_offsets_days);
        let csv = if offsets.is_empty() {
            "30,7,1".to_string()
        } else {
            offsets
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        hyperion_state::scheduler::set_expiry(
            &self.pool,
            &detail.id,
            expires_at,
            expiry.owner_email.as_deref(),
            grace,
            &csv,
            customer_since,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("set_expiry: {e}")))?;
        // Cancel any previously-queued actions and re-schedule from scratch.
        hyperion_state::scheduler::cancel_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cancel: {e}")))?;
        if let Some(exp) = expires_at {
            self.reschedule_actions_for(&detail.id, exp, grace, &offsets)
                .await?;
        }
        self.append_audit(
            "hosting.set_expiry",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "expires_at": expires_at,
                "entered": expiry.expires_at,
                "customer_since": customer_since,
                "grace_days": grace,
            })
            .to_string(),
            "ok",
        )
        .await;
        let updated = hyperion_state::scheduler::get_expiry(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get_expiry: {e}")))?
            .ok_or(RpcError::Internal {
                message: "row vanished after write (concurrent delete?)".into(),
            })?;
        Ok(expiry_row_to_dto(updated))
    }

    pub async fn get_expiry(
        &self,
        sel: HostingSelector,
    ) -> Result<hyperion_types::HostingExpiry, RpcError> {
        let detail = self.get(sel).await?;
        let row = hyperion_state::scheduler::get_expiry(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get_expiry: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "hosting".into(),
                id: detail.id.0.clone(),
            })?;
        Ok(expiry_row_to_dto(row))
    }

    pub async fn clear_expiry(&self, sel: HostingSelector) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        // Clearing an expiry DATE must not also forget who to write to. The
        // `owner_email` is who the expiry warnings go to; clearing the date
        // must not forget it, or the customer stops hearing from us at all.
        let existing = hyperion_state::scheduler::get_expiry(&self.pool, &detail.id)
            .await
            .ok()
            .flatten();
        let owner_email = existing.as_ref().and_then(|r| r.owner_email.clone());
        // Clearing the expiry says this hosting no longer auto-suspends. It
        // does not say the customer left, so when they joined stays on record.
        let customer_since = existing.as_ref().and_then(|r| r.customer_since);
        hyperion_state::scheduler::set_expiry(
            &self.pool,
            &detail.id,
            None,
            owner_email.as_deref(),
            30,
            "30,7,1",
            customer_since,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("clear: {e}")))?;
        hyperion_state::scheduler::cancel_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("cancel: {e}")))?;
        self.append_audit("hosting.clear_expiry", Some(detail.id.as_str()), "{}", "ok")
            .await;
        Ok(())
    }

    /// Generic per-hosting key/value store (notes, tags, …). Operates on
    /// the local `hosting_kv` table keyed by the hosting's ULID — no
    /// existence check (panel-side metadata; a stray id is harmless and
    /// cleaned up with delete_all on hard delete).
    pub async fn hosting_kv_set(
        &self,
        hosting_id: String,
        key: String,
        value: String,
    ) -> Result<(), RpcError> {
        hyperion_state::hosting_kv::set(&self.pool, &hosting_id, &key, &value, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("kv set: {e}")))?;
        self.append_audit(
            "hosting.kv.set",
            Some(&hosting_id),
            &serde_json::json!({ "key": key }).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_kv_list(
        &self,
        hosting_id: String,
    ) -> Result<Vec<(String, String)>, RpcError> {
        hyperion_state::hosting_kv::list(&self.pool, &hosting_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("kv list: {e}")))
    }

    /// One `hosting_kv` value, or "" when unset — a small reader the git-deploy
    /// methods lean on.
    pub(super) async fn kvs(&self, hosting_id: &str, key: &str) -> String {
        hyperion_state::hosting_kv::get(&self.pool, hosting_id, key)
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }
}

pub(super) fn expiry_row_to_dto(
    row: hyperion_state::scheduler::ExpiryRow,
) -> hyperion_types::HostingExpiry {
    hyperion_types::HostingExpiry {
        expires_at: row.expires_at,
        owner_email: row.owner_email,
        grace_days: row.grace_days,
        warning_offsets_days: row.warning_offsets_days,
        customer_since: row.customer_since,
    }
}
