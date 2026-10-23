//! The BLAKE3-chained audit log: append, list, search, verify.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Walk the full audit log and verify each row's row_hash
    /// against `BLAKE3(prev_hash || canonical fields)`. Returns
    /// `(ok, rows_checked, message)` — the message names the first
    /// bad row when the chain is broken, so an operator can grep
    /// /var/log + dmesg + the surrounding rows for clues. The
    /// log is bounded in practice (the GC ticker prunes >90 day
    /// entries) so this is cheap even on a busy node.
    pub async fn audit_verify_chain(&self) -> Result<(bool, i64, String), RpcError> {
        // Count first so we can report it even on failure (operator
        // wants "1234 rows, broke at row 712" — a bare "bad chain"
        // is unhelpful).
        let rows_checked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("audit count: {e}")))?;
        match hyperion_state::audit::verify_chain(&self.pool).await {
            Ok(()) => Ok((true, rows_checked, String::new())),
            Err(e) => Ok((false, rows_checked, e.to_string())),
        }
    }

    pub async fn audit_list(
        &self,
        limit: i64,
    ) -> Result<Vec<hyperion_rpc::AuditEntryWire>, RpcError> {
        let rows = hyperion_state::audit::list(&self.pool, limit.clamp(1, 1000))
            .await
            .map_err(|e| RpcError::Internal_with(format!("audit list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|e| hyperion_rpc::AuditEntryWire {
                id: e.id,
                ts: e.ts,
                actor_uid: e.actor_uid,
                actor_label: e.actor_label,
                action: e.action,
                target: e.target,
                payload_json: e.payload_json,
                result: e.result,
                // Master tags this after a cross-node fan-in; the agent
                // can't know its own cluster label.
                node: None,
                row_hash: e.row_hash,
            })
            .collect())
    }

    pub async fn audit_search(
        &self,
        filter: hyperion_rpc::AuditSearchFilter,
    ) -> Result<
        (
            Vec<hyperion_rpc::AuditEntryWire>,
            Vec<hyperion_rpc::AuditActionCount>,
            i64,
        ),
        RpcError,
    > {
        let limit = filter.limit.clamp(1, 1000);
        let f = hyperion_state::audit::AuditFilter {
            q: filter.q,
            q_alt: filter.q_alt,
            action: filter.action,
            prefixes: filter.prefixes,
            not_prefixes: filter.not_prefixes,
            failed_only: filter.failed_only,
            since: filter.since,
            before: filter.before,
        };
        let err = |e: hyperion_state::db::StateError| {
            RpcError::Internal_with(format!("audit search: {e}"))
        };
        let rows = hyperion_state::audit::search(&self.pool, &f, limit)
            .await
            .map_err(err)?;
        let actions = hyperion_state::audit::action_counts(&self.pool, &f)
            .await
            .map_err(err)?;
        let total = hyperion_state::audit::count(&self.pool)
            .await
            .map_err(err)?;
        Ok((
            rows.into_iter()
                .map(|e| hyperion_rpc::AuditEntryWire {
                    id: e.id,
                    ts: e.ts,
                    actor_uid: e.actor_uid,
                    actor_label: e.actor_label,
                    action: e.action,
                    target: e.target,
                    payload_json: e.payload_json,
                    result: e.result,
                    node: None,
                    row_hash: e.row_hash,
                })
                .collect(),
            actions
                .into_iter()
                .map(|c| hyperion_rpc::AuditActionCount {
                    action: c.action,
                    total: c.total,
                    failed: c.failed,
                })
                .collect(),
            total,
        ))
    }

    pub(crate) async fn append_audit(
        &self,
        action: &str,
        target: Option<&str>,
        payload_json: &str,
        result: &str,
    ) {
        self.append_audit_as(0, "agent", action, target, payload_json, result)
            .await
    }

    /// [`append_audit`], but naming WHO did it.
    ///
    /// The plain helper stamps every row `agent`, and the activity feed hides
    /// that actor on purpose — it is noise on a line about the machine acting
    /// on its own. The cost was that a sign-in also read as the machine: the
    /// feed said "Web login 2FA succeeded" with no name against it, which is
    /// the one event where the name IS the information.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn append_audit_as(
        &self,
        actor_uid: i64,
        actor_label: &str,
        action: &str,
        target: Option<&str>,
        payload_json: &str,
        result: &str,
    ) {
        let r = hyperion_state::audit::append(
            &self.pool,
            hyperion_state::audit::AppendReq {
                ts: now_secs(),
                actor_uid,
                actor_label,
                action,
                target,
                payload_json,
                result,
            },
        )
        .await;
        if let Err(e) = r {
            tracing::warn!(error=%e, "audit append failed");
        }
    }
}
