//! Web sessions and `/api/v1` keys — the credential ledgers behind login and
//! revocation.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ============================================================
    //  web_sessions — backs the cookie ledger so revocation works.
    // ============================================================

    pub async fn web_session_insert(
        &self,
        sid: &str,
        user_id: i64,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), RpcError> {
        hyperion_state::web_sessions::insert(&self.pool, sid, user_id, ip, user_agent, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_insert: {e}")))
    }

    /// Liveness AND the session owner's CURRENT privilege.
    ///
    /// Used to return a bare `bool`, so authorization came entirely from the
    /// role and capabilities stamped into the cookie at login and a revoked
    /// privilege kept working until that cookie expired. These are the same
    /// three master-local SQLite reads `api_key_resolve` has always done for
    /// the API-key path; folding them into the probe that already runs on
    /// every request costs no extra round trip.
    pub async fn web_session_touch(
        &self,
        sid: &str,
        user_id: i64,
    ) -> Result<hyperion_types::SessionStanding, RpcError> {
        let live = hyperion_state::web_sessions::touch_if_live(&self.pool, sid, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_touch: {e}")))?;
        let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_touch user: {e}")))?;
        let eff = hyperion_state::web_users::effective_role(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_touch role: {e}")))?;
        Ok(match (user, eff) {
            (Some(u), Some(er)) => hyperion_types::SessionStanding {
                live,
                known_user: true,
                locked: u.locked,
                role: er.base_role.as_str().to_string(),
                caps: er.caps.bits(),
                scope_all: er.scope_all,
            },
            // No `web_users` row, or no resolvable role — a custom role
            // deleted out from under the account. Reported as `known_user:
            // false` and NOT as locked: `locked` means the row says so, and
            // there is no row. The caller decides what absence means, because
            // only it can tell a deleted account from the bootstrap admin,
            // whose record lives in a file on the web host rather than in
            // this database.
            _ => hyperion_types::SessionStanding {
                live,
                known_user: false,
                locked: false,
                role: String::new(),
                caps: 0,
                scope_all: false,
            },
        })
    }

    pub async fn web_session_list(
        &self,
        user_id: i64,
    ) -> Result<Vec<hyperion_types::WebSessionView>, RpcError> {
        let rows = hyperion_state::web_sessions::list_for_user(&self.pool, user_id, 100)
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::WebSessionView {
                sid: r.sid,
                user_id: r.user_id,
                ip: r.ip,
                user_agent: r.user_agent,
                created_at: r.created_at,
                last_seen_at: r.last_seen_at,
                revoked_at: r.revoked_at,
                revoked_by: r.revoked_by,
            })
            .collect())
    }

    /// Revoke every session a user holds — "sign out everywhere".
    ///
    /// Returns how many were live. The CALLER decides whether to spare the
    /// current session: from the profile page it does not, because the point
    /// of the button is usually "someone else has my cookie" and sparing the
    /// browser you are holding is exactly wrong if that browser is theirs.
    pub async fn web_session_revoke_all(
        &self,
        user_id: i64,
        revoked_by: i64,
    ) -> Result<i64, RpcError> {
        let n = hyperion_state::web_sessions::revoke_all_for_user(
            &self.pool,
            user_id,
            revoked_by,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("web_session_revoke_all: {e}")))?;
        self.append_audit(
            "web_session.revoke_all",
            None,
            &serde_json::json!({"user_id": user_id, "revoked_by": revoked_by, "count": n})
                .to_string(),
            "ok",
        )
        .await;
        Ok(n as i64)
    }

    pub async fn web_session_revoke(&self, sid: &str, revoked_by: i64) -> Result<bool, RpcError> {
        let r = hyperion_state::web_sessions::revoke(&self.pool, sid, revoked_by, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("web_session_revoke: {e}")))?;
        if r {
            self.append_audit(
                "web_session.revoke",
                Some(sid),
                &serde_json::json!({"revoked_by": revoked_by}).to_string(),
                "ok",
            )
            .await;
        }
        Ok(r)
    }

    // ============================================================
    //  api_keys — bearer credentials for the /api/v1 remote API.
    //  Master-only table (like web_sessions); the web tier reaches
    //  these over RPC.
    // ============================================================

    /// Mint an API key. The requested `caps`/`scope_all` are clamped to
    /// the OWNER's effective caps (a key can never out-grant its owner),
    /// resolved here so the clamp can't be bypassed by a crafted RPC.
    /// Returns the RAW key once; only its SHA-256 is stored.
    #[allow(clippy::too_many_arguments)]
    pub async fn api_key_create(
        &self,
        label: &str,
        owner_user_id: i64,
        caps: u64,
        scope_all: bool,
        expires_at: Option<i64>,
        ip_allowlist: &[String],
        rate_limit_per_min: i64,
    ) -> Result<hyperion_types::ApiKeyCreated, RpcError> {
        use hyperion_state::capabilities::CapSet;
        // Resolve the owner's effective caps for the clamp. A missing
        // user resolves to no caps → the minted key gets nothing, which
        // is the safe failure mode.
        let owner = hyperion_state::web_users::effective_role(&self.pool, owner_user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("api_key_create owner lookup: {e}")))?;
        let (owner_caps, owner_scope_all) = match owner {
            Some(er) => (er.caps, er.scope_all),
            None => (CapSet::empty(), false),
        };
        // P1 safety gate: the `/api/v1` read endpoints are not yet tenant-scoped
        // (that lands with the write endpoints in p1b). Until then a key whose
        // owner lacks cluster-wide scope could still read the WHOLE cluster's
        // hosting inventory, so refuse to mint it. Built-in Admin/SuperAdmin are
        // scope_all and unaffected; this only blocks a custom role that holds
        // ApiKeysManage but is tenant-scoped. Enforced here (server-side) so it
        // can't be bypassed by a crafted request.
        if !owner_scope_all {
            return Err(RpcError::Validation {
                message: "API keys currently require an account with cluster-wide \
                          (all-hostings) scope. Per-tenant API keys arrive in a later \
                          release."
                    .into(),
            });
        }
        let created = hyperion_state::api_keys::create(
            &self.pool,
            label,
            owner_user_id,
            CapSet::from_bits(caps),
            scope_all,
            owner_caps,
            owner_scope_all,
            now_secs(),
            expires_at,
            ip_allowlist,
            rate_limit_per_min,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("api_key_create: {e}")))?;
        // Audit the mint. The raw key + hash are NEVER logged — only the
        // display prefix + label, mirroring the import-token discipline.
        self.append_audit(
            "api_key.create",
            Some(&created.key_prefix),
            &serde_json::json!({
                "label": label,
                "owner_user_id": owner_user_id,
                "key_prefix": created.key_prefix,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::ApiKeyCreated {
            id: created.id,
            raw_key: created.raw_key,
            key_prefix: created.key_prefix,
        })
    }

    pub async fn api_key_list(&self) -> Result<Vec<hyperion_types::ApiKeyView>, RpcError> {
        let rows = hyperion_state::api_keys::list(&self.pool, 500)
            .await
            .map_err(|e| RpcError::Internal_with(format!("api_key_list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::ApiKeyView {
                id: r.id,
                key_prefix: r.key_prefix,
                label: r.label,
                owner_user_id: r.owner_user_id,
                caps: r.caps,
                scope_all: r.scope_all,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
                revoked_by: r.revoked_by,
                ip_allowlist: r.ip_allowlist,
                rate_limit_per_min: r.rate_limit_per_min,
            })
            .collect())
    }

    pub async fn api_key_resolve(
        &self,
        key_hash: &str,
    ) -> Result<Option<hyperion_types::ApiKeyResolved>, RpcError> {
        let Some(k) = hyperion_state::api_keys::resolve_active(&self.pool, key_hash, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("api_key_resolve: {e}")))?
        else {
            return Ok(None);
        };
        // Live owner enforcement. `resolve_active` only vetted the KEY row
        // (not revoked / not expired); the module contract also promises a
        // key can "never be exceeded by revoking/down-scoping the owner", so
        // re-read the owner's CURRENT standing on every call: a locked/gone
        // owner makes the key inert, a demoted owner re-clamps its caps. For
        // the usual admin-owned scope_all key this is a no-op.
        let owner = hyperion_state::web_users::get_by_id(&self.pool, k.owner_user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("api_key_resolve owner: {e}")))?;
        let eff = hyperion_state::web_users::effective_role(&self.pool, k.owner_user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("api_key_resolve role: {e}")))?;
        let standing = match (owner, eff) {
            (Some(u), Some(er)) => Some(hyperion_state::api_keys::OwnerStanding {
                locked: u.locked,
                caps: er.caps.bits(),
                scope_all: er.scope_all,
            }),
            // Owner deleted, or has no resolvable role → treat as gone.
            _ => None,
        };
        let Some((caps, scope_all)) =
            hyperion_state::api_keys::clamp_to_owner(k.caps, k.scope_all, standing)
        else {
            return Ok(None);
        };
        Ok(Some(hyperion_types::ApiKeyResolved {
            id: k.id,
            label: k.label,
            owner_user_id: k.owner_user_id,
            caps,
            scope_all,
            // Hardening is not owner-clamped — it constrains the key itself.
            ip_allowlist: k.ip_allowlist,
            rate_limit_per_min: k.rate_limit_per_min,
        }))
    }

    pub async fn api_key_touch(&self, key_hash: &str) -> Result<(), RpcError> {
        // Best-effort: a failed touch must never fail the API request,
        // so swallow the error (still surface it in the unlikely RPC
        // wiring failure by returning Ok regardless).
        let _ = hyperion_state::api_keys::touch(&self.pool, key_hash, now_secs()).await;
        Ok(())
    }

    pub async fn api_key_revoke(&self, id: i64, revoked_by: i64) -> Result<bool, RpcError> {
        let r = hyperion_state::api_keys::revoke(&self.pool, id, revoked_by, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("api_key_revoke: {e}")))?;
        if r {
            self.append_audit(
                "api_key.revoke",
                Some(&id.to_string()),
                &serde_json::json!({"revoked_by": revoked_by}).to_string(),
                "ok",
            )
            .await;
        }
        Ok(r)
    }
}
