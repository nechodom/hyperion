//! Cluster membership: enrollment, heartbeats, invites, node labels and
//! draining.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Rename an enrolled node's display label. The `node_id` is
    /// the immutable enrollment identifier; only the operator-
    /// visible label changes. Validates length and trims surrounding
    /// whitespace; an empty label is rejected (the UI prevents this
    /// but defence-in-depth is cheap here).
    pub async fn node_set_label(&self, node_id: &str, label: &str) -> Result<(), RpcError> {
        let trimmed = label.trim();
        if trimmed.is_empty() {
            return Err(RpcError::Validation {
                message: "label cannot be empty".into(),
            });
        }
        if trimmed.chars().count() > 80 {
            return Err(RpcError::Validation {
                message: "label too long (max 80 characters)".into(),
            });
        }
        // Refuse control chars / newlines — labels render into HTML
        // attributes (option text, sidebar chips), so a stray newline
        // turns into a confusing wrapped pill.
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(RpcError::Validation {
                message: "label cannot contain control characters".into(),
            });
        }
        hyperion_state::nodes::set_label(&self.pool, node_id, trimmed)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node_set_label: {e}")))?;
        self.append_audit(
            "node.label.update",
            Some(node_id),
            &serde_json::json!({"label": trimmed}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Toggle a node's drain flag. Drained nodes are skipped by
    /// the auto-placer + create wizard; existing hostings keep
    /// serving traffic. Idempotent — drain on an already-drained
    /// node updates the reason + timestamp without erroring.
    pub async fn node_set_drain(
        &self,
        node_id: &str,
        drain: bool,
        reason: &str,
        actor_uid: i64,
    ) -> Result<(), RpcError> {
        let trimmed = reason.trim();
        if trimmed.chars().count() > 200 {
            return Err(RpcError::Validation {
                message: "drain reason too long (max 200 characters)".into(),
            });
        }
        let now = now_secs();
        if drain {
            hyperion_state::nodes::drain(&self.pool, node_id, trimmed, actor_uid, now)
                .await
                .map_err(|e| RpcError::Internal_with(format!("node drain: {e}")))?;
        } else {
            hyperion_state::nodes::undrain(&self.pool, node_id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("node undrain: {e}")))?;
        }
        self.append_audit(
            if drain { "node.drain" } else { "node.undrain" },
            Some(node_id),
            &serde_json::json!({"reason": trimmed, "actor_uid": actor_uid}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Remove an enrolled node row. The caller is the master's web
    /// UI (via NodeRemove RPC) — workers should not be able to
    /// nuke their own row from the master via this path.
    ///
    /// Two-stage gate:
    ///   1. Count hostings still routed to this node (excluding
    ///      trashed). If non-zero and `force=false`, refuse with
    ///      `Ok((false, count))` so the UI can show the count and
    ///      offer "force" path or "move them off first" advice.
    ///   2. If `force=true`, the DAO drops the node row + its
    ///      drain marker. Hostings stay in the DB with their old
    ///      node_id (orphaned); `find_hosting_anywhere` lookups
    ///      will fail for them until the operator either re-enrols
    ///      a node under the same node_id OR migrates the hostings
    ///      to a different node manually.
    ///
    /// Audited either way. Unknown node_id ⇒ `Ok((false, 0))` so
    /// the UI form is forgiving on a double-submit race.
    pub async fn node_remove(
        &self,
        node_id: &str,
        force: bool,
        actor_uid: i64,
    ) -> Result<(bool, i64), RpcError> {
        // Refuse silently on empty / non-existent (audit still logs).
        let existed = hyperion_state::nodes::get_by_node_id(&self.pool, node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("nodes lookup: {e}")))?
            .is_some();
        if !existed {
            return Ok((false, 0));
        }
        let count = hyperion_state::nodes::count_hostings_on_node(&self.pool, node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("hostings on node count: {e}")))?;
        if count > 0 && !force {
            return Ok((false, count));
        }
        let removed = hyperion_state::nodes::delete(&self.pool, node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node delete: {e}")))?;
        self.append_audit(
            "node.remove",
            Some(node_id),
            &serde_json::json!({
                "force": force,
                "hostings_orphaned": count,
                "actor_uid": actor_uid
            })
            .to_string(),
            if removed { "ok" } else { "noop" },
        )
        .await;
        Ok((removed, count))
    }

    /// Block B orphan adoption: re-point every (non-trashed) hosting
    /// routed to `from_node_id` onto the live `to_node_id`. The intended
    /// use is "a box re-enrolled under a new id, so its hostings still
    /// carry the dead old id — move them to the new id of the SAME box".
    /// `to_node_id` must be an enrolled node (else we'd just re-orphan
    /// onto another dead id). Returns the number of hostings moved.
    /// Audited. The operator is responsible for ensuring the target node
    /// genuinely holds these sites' files.
    pub async fn node_reassign_hostings(
        &self,
        from_node_id: &str,
        to_node_id: &str,
    ) -> Result<i64, RpcError> {
        let from = from_node_id.trim();
        let to = to_node_id.trim();
        if from.is_empty() || to.is_empty() {
            return Err(RpcError::Validation {
                message: "from/to node id must be non-empty".into(),
            });
        }
        if from == to {
            return Err(RpcError::Validation {
                message: "from and to node are the same".into(),
            });
        }
        let to_exists = hyperion_state::nodes::get_by_node_id(&self.pool, to)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node lookup: {e}")))?
            .is_some();
        if !to_exists {
            return Err(RpcError::Validation {
                message: format!("target node {to} is not enrolled — pick a live node"),
            });
        }
        // The source must be DEAD. Re-pointing a live node's sites at
        // another box — `--from`/`--to` swapped, or the wrong id pasted —
        // would route all their management to a machine that doesn't hold
        // their files, while nothing warned. A node that really is gone is
        // removed from the Nodes page first, which is also what orphans
        // the ids this exists to adopt.
        let from_enrolled = hyperion_state::nodes::get_by_node_id(&self.pool, from)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node lookup: {e}")))?
            .is_some();
        if from_enrolled {
            return Err(RpcError::Validation {
                message: format!(
                    "source node {from} is still enrolled — its sites are not orphaned. \
                     Check --from/--to; if that box is really gone, remove it on the \
                     Nodes page first"
                ),
            });
        }
        let moved = hyperion_state::nodes::reassign_hostings(&self.pool, from, to)
            .await
            .map_err(|e| RpcError::Internal_with(format!("reassign: {e}")))?
            as i64;
        self.append_audit(
            "node.reassign_hostings",
            Some(to),
            &serde_json::json!({"from": from, "to": to, "moved": moved}).to_string(),
            "ok",
        )
        .await;
        Ok(moved)
    }

    /// List enrolled nodes (master-side view).
    pub async fn nodes_list(&self) -> Result<Vec<hyperion_types::NodeSummary>, RpcError> {
        let rows = hyperion_state::nodes::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("nodes list: {e}")))?;
        let drained = hyperion_state::nodes::drained_set(&self.pool)
            .await
            .unwrap_or_default();
        // Pre-load reasons for the drained set so the UI shows
        // "drained: post-upgrade testing" instead of just a pill.
        let reasons: std::collections::HashMap<String, String> = {
            let rs: Vec<(String, String)> =
                sqlx::query_as("SELECT node_id, reason FROM node_drain")
                    .fetch_all(&self.pool)
                    .await
                    .unwrap_or_default();
            rs.into_iter().collect()
        };
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::NodeSummary {
                is_drained: drained.contains(&r.node_id),
                drain_reason: reasons.get(&r.node_id).cloned().unwrap_or_default(),
                node_id: r.node_id,
                label: r.label,
                master_url: r.master_url,
                agent_version: r.agent_version,
                public_ip: r.public_ip,
                enrolled_at: r.enrolled_at,
                last_seen_at: r.last_seen_at,
                tls_spki_pin: r.tls_spki_pin,
                // Safe to fan out: this is a PUBLIC key, unlike
                // secret_hash which never leaves this struct's row. The
                // panel needs it to show "responses verified / taken on
                // trust" per node without a second round trip.
                resp_pubkey: r.resp_pubkey,
                rpc_port: r.rpc_port,
                external_ip: r.external_ip,
            })
            .collect())
    }

    /// Master-side: validate `token`, mark the invite consumed, insert
    /// the node, and mint a per-node shared secret for heartbeat auth.
    /// Returns the plaintext secret — the master only stores its hash.
    ///
    /// `resp_pubkey` is the node's Ed25519 response-signing key. Pinning
    /// it HERE rather than waiting for the first heartbeat means a node
    /// is verifiable from its very first RPC; enrollment is also the one
    /// moment a new key is legitimate, since `upsert_enrollment` clears
    /// the previous pin.
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_consume(
        &self,
        token: String,
        caller_ip: String,
        node_id: String,
        label: String,
        agent_version: String,
        public_ip: Option<String>,
        prior_node_id: Option<String>,
        prior_secret: Option<String>,
        resp_pubkey: Option<String>,
        endpoint: hyperion_types::NodeEndpointReport,
    ) -> Result<(String, String), RpcError> {
        if token.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "empty token".into(),
            });
        }
        // Decide the EFFECTIVE node_id BEFORE consuming the invite, so the
        // invite's consumed-by-node_id reflects the real identity. Block B
        // idempotent re-enrollment: a box that still has node-id.json
        // presents prior_node_id + prior_secret.
        let effective_node_id = self
            .resolve_enrollment_identity(
                &node_id,
                prior_node_id.as_deref(),
                prior_secret.as_deref(),
            )
            .await?;
        let reused_identity = effective_node_id != node_id;

        let now = now_secs();
        let ok = hyperion_state::invites::consume(
            &self.pool,
            &token,
            &caller_ip,
            &effective_node_id,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("consume: {e}")))?;
        if !ok {
            return Err(RpcError::Validation {
                message: "invite token invalid, expired, or already consumed".into(),
            });
        }
        let hash = hyperion_state::invites::hash_token(&token);
        // A fresh identity gets a freshly minted 32-byte secret, returned
        // in plaintext exactly once; the master persists only its BLAKE3
        // hash.
        //
        // A REUSED identity keeps the secret it just proved it holds. This
        // used to re-mint it, which made the enrollment response the only
        // copy of the node's new credential: if that response never landed
        // (curl's 15 s budget ran out after the master committed, or the
        // node failed to write node-id.json) the box was left with a secret
        // the master no longer accepted and a token already spent — every
        // heartbeat "bad secret" from then on, and the next re-enroll,
        // presenting that dead secret, was handed a FRESH id that orphaned
        // all of its sites. Keeping the secret makes a lost response
        // harmless: the node simply carries on with what it already has.
        let secret_plain = match (reused_identity, prior_secret.as_deref()) {
            (true, Some(prior)) => prior.to_string(),
            _ => {
                let mut secret_bytes = [0u8; 32];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut secret_bytes);
                hex::encode(secret_bytes)
            }
        };
        let secret_hash = hex::encode(blake3::hash(secret_plain.as_bytes()).as_bytes());
        let row = hyperion_state::nodes::NewNode {
            node_id: effective_node_id.clone(),
            label,
            master_url: None,
            agent_version,
            public_ip: checked_node_addr(&effective_node_id, "public_ip", public_ip),
            enrolled_via_hash: hash,
            secret_hash,
        };
        // Upsert: fresh/adopt → insert; reuse → in-place update keeping
        // enrolled_at. Prevents the duplicate-node-row orphaning that a
        // plain insert caused on every re-enroll.
        hyperion_state::nodes::upsert_enrollment(&self.pool, &row, now)
            .await
            .map_err(|e| RpcError::Internal_with(format!("nodes upsert: {e}")))?;
        self.record_node_endpoint(&effective_node_id, endpoint)
            .await;
        // A box with a worker is a master by definition. Doing it here means
        // adding the first node never requires the operator to go and find a
        // setting — and it makes the cluster UI appear exactly when it starts
        // being about something.
        self.promote_to_master_if_standalone().await;
        // The upsert just cleared any previous pin, so this compare-and-set
        // always lands on a fresh enrollment. Failing to pin is NOT fatal —
        // the node re-publishes the key on every heartbeat and gets pinned
        // then; refusing the enrollment over it would strand the box.
        let presented_pubkey = resp_pubkey
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let resp_pubkey_pinned = match presented_pubkey {
            Some(pk) => {
                match hyperion_state::nodes::set_resp_pubkey_if_absent(
                    &self.pool,
                    &effective_node_id,
                    pk,
                )
                .await
                {
                    Ok(pinned) => pinned,
                    Err(e) => {
                        tracing::warn!(
                            node = %effective_node_id,
                            error = %e,
                            "pinning the node's response-signing pubkey at enrollment \
                             failed — the next heartbeat will re-publish it"
                        );
                        false
                    }
                }
            }
            None => false,
        };
        self.append_audit(
            "node.enroll",
            Some(&effective_node_id),
            &serde_json::json!({
                "label": row.label,
                "caller_ip": caller_ip,
                "reused_identity": reused_identity,
                "resp_pubkey_pinned": resp_pubkey_pinned,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok((effective_node_id, secret_plain))
    }

    /// Decide which `node_id` a (re-)enrollment should land on. Reuse is
    /// granted ONLY on proven continuity:
    /// - prior id IN USE + `prior_secret` matches (constant-time) → reuse
    ///   it: the box keeps its identity + hostings, secret is re-minted.
    /// - everything else (no prior id, an UNKNOWN prior id, or an in-use
    ///   id with a wrong/empty secret) → the freshly-minted `candidate`.
    ///
    /// There is deliberately NO "adopt a free id" path. `node_remove
    /// --force` leaves a node_id free in the `nodes` table while its
    /// hostings still reference it; secret-lessly adopting that id would
    /// let any invite-token holder who knows the (non-secret, UI-rendered)
    /// id claim it, point an attacker public_ip at it, and then receive
    /// the master's SIGNED management RPCs for those hostings (the Block C
    /// TLS pin is warn-only, so nothing blocks it). So we require the
    /// per-node secret for EVERY reuse. Recovering hostings after a node
    /// was removed / the master DB restored is instead an explicit,
    /// authenticated operator action: `hctl node reassign`.
    ///
    /// Constant-time secret compare (mirrors node_heartbeat) so callers
    /// can't time-probe which node_ids exist.
    pub(super) async fn resolve_enrollment_identity(
        &self,
        candidate: &str,
        prior_node_id: Option<&str>,
        prior_secret: Option<&str>,
    ) -> Result<String, RpcError> {
        let prior_id = match prior_node_id.map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) => p,
            None => return Ok(candidate.to_string()),
        };
        let existing = hyperion_state::nodes::get_by_node_id(&self.pool, prior_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node lookup: {e}")))?;
        let row = match existing {
            // Unknown prior id → fresh. NEVER adopt secret-lessly: that was
            // a node-takeover vector (see the doc comment above).
            None => {
                tracing::warn!(
                    node = prior_id,
                    "re-enroll: presented a prior node_id the master does not know — \
                     issuing a FRESH id (no secret-less adoption)"
                );
                return Ok(candidate.to_string());
            }
            Some(r) => r,
        };
        let supplied = prior_secret.unwrap_or("");
        let supplied_hash = hex::encode(blake3::hash(supplied.as_bytes()).as_bytes());
        let a = supplied_hash.as_bytes();
        let b = row.secret_hash.as_bytes();
        let n = a.len().max(b.len());
        let mut diff: u8 = (a.len() ^ b.len()) as u8;
        for i in 0..n {
            diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
        }
        if diff == 0 && !supplied.is_empty() {
            tracing::info!(
                node = prior_id,
                "re-enroll: reusing node_id (continuity proven)"
            );
            Ok(prior_id.to_string())
        } else {
            tracing::warn!(
                node = prior_id,
                "re-enroll: prior node_id is in use but the presented secret does not \
                 match — issuing a FRESH id instead (no takeover)"
            );
            Ok(candidate.to_string())
        }
    }

    /// Master-side: verify a node's heartbeat (constant-time secret
    /// check) and bump last_seen_at + agent_version. Returns Ok(()) if
    /// the node exists and the secret matches; otherwise Validation.
    ///
    /// SECURITY: always hash the supplied secret and run a
    /// constant-time compare against *some* hash even when the node
    /// is unknown. Returning Validation immediately on a missing
    /// node would leak a timing oracle for node-id enumeration: an
    /// attacker could distinguish "node doesn't exist" from "node
    /// exists, secret wrong" by response latency.
    pub async fn node_heartbeat(
        &self,
        node_id: String,
        secret: String,
        agent_version: String,
        tls_spki_pin: Option<String>,
        resp_pubkey: Option<String>,
        endpoint: hyperion_types::NodeEndpointReport,
    ) -> Result<(), RpcError> {
        // Compute the candidate hash unconditionally — the same
        // amount of crypto work happens regardless of node_id state.
        let actual = hex::encode(blake3::hash(secret.as_bytes()).as_bytes());
        let actual_bytes = actual.as_bytes();

        let row_opt = hyperion_state::nodes::get_by_node_id(&self.pool, &node_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("node lookup: {e}")))?;
        // For the unknown-node case, compare against a fixed dummy
        // string the same length as a real hex BLAKE3 digest (64
        // bytes). The compare result is irrelevant — we'll fail
        // afterwards — but the *time* taken is the same as the
        // happy-path compare.
        const DUMMY_HASH: &[u8; 64] =
            b"0000000000000000000000000000000000000000000000000000000000000000";
        let expected: &[u8] = match &row_opt {
            Some(r) => r.secret_hash.as_bytes(),
            None => DUMMY_HASH,
        };
        // If the stored hash is somehow a different length than a
        // BLAKE3 hex digest, the compare must still consume the
        // longest of the two so it doesn't short-circuit visibly.
        // In practice secret_hash IS 64 bytes — this is belt-and-
        // braces.
        let n = expected.len().max(actual_bytes.len());
        let mut diff: u8 = (expected.len() ^ actual_bytes.len()) as u8;
        for i in 0..n {
            let a = expected.get(i).copied().unwrap_or(0);
            let b = actual_bytes.get(i).copied().unwrap_or(0);
            diff |= a ^ b;
        }
        // Bind the decision to BOTH "node exists" AND "compare
        // matched" — never short-circuit on either.
        let ok = row_opt.is_some() && diff == 0;
        if !ok {
            return Err(RpcError::Validation {
                message: "bad secret".into(),
            });
        }
        // Trust-on-first-use for BOTH of the node's self-reported crypto
        // anchors, using the row we already hold from the secret check. A
        // heartbeat proves only possession of the shared secret over a
        // `curl -k` channel, so it may FILL an empty pin but never replace
        // one: otherwise leaking that secret (or landing one forged heartbeat
        // on-path) would be enough to swap in an attacker's response-signing
        // key and forge every RPC response afterwards — or to re-point the
        // TLS pin at the attacker's cert, which would neuter `--pinnedpubkey`
        // enforcement the instant an operator turned it on. Mirrors the
        // node's own decide_pubkey_pin for the master's key.
        let row = row_opt.as_ref();
        let adopt_resp_pubkey = tofu_report(
            &node_id,
            "response pubkey",
            row.and_then(|r| r.resp_pubkey.as_deref()),
            resp_pubkey.as_deref(),
        );
        let adopt_tls_pin = tofu_report(
            &node_id,
            "TLS SPKI pin",
            row.and_then(|r| r.tls_spki_pin.as_deref()),
            tls_spki_pin.as_deref(),
        );
        // The heartbeat itself still succeeds on a refusal — failing it would
        // let one forged key report keep a healthy node permanently "offline".
        hyperion_state::nodes::touch_last_seen(
            &self.pool,
            &node_id,
            now_secs(),
            Some(&agent_version),
            adopt_tls_pin,
            adopt_resp_pubkey,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("touch: {e}")))?;
        self.record_node_endpoint(&node_id, endpoint).await;
        Ok(())
    }

    /// Store a node's self-reported RPC port and public IP, dropping a
    /// malformed value instead of failing the enrollment or heartbeat it
    /// rode on. Best-effort: a failed write leaves the last known values,
    /// which the next heartbeat retries.
    pub(super) async fn record_node_endpoint(
        &self,
        node_id: &str,
        ep: hyperion_types::NodeEndpointReport,
    ) {
        let rpc_port = ep.rpc_port.filter(|p| *p != 0);
        let external_ip = checked_node_addr(node_id, "external_ip", ep.external_ip)
            .filter(|a| a.parse::<std::net::IpAddr>().is_ok());
        if let Err(e) = hyperion_state::nodes::record_endpoint(
            &self.pool,
            node_id,
            rpc_port,
            external_ip.as_deref(),
        )
        .await
        {
            tracing::warn!(node = node_id, error = %e, "recording the node's endpoint failed");
        }
    }

    /// Operator recovery: forget both pinned crypto anchors for one node
    /// (`resp_pubkey` + `tls_spki_pin`) so the next heartbeat re-pins
    /// whatever the box now presents.
    ///
    /// This exists because both pins are trust-on-first-use with
    /// refuse-on-change, and a perfectly legitimate event — reinstalling
    /// the agent, which regenerates node-rpc.key and the inbound TLS cert
    /// while node-id.json survives — makes every later report mismatch.
    /// Without this action that node is permanently unverifiable (and,
    /// once pin enforcement is on, permanently unreachable) with no fix
    /// short of hand-editing the master's database.
    ///
    /// Re-pinning is deliberately NOT done here: we only clear, and the
    /// node's next report supplies the new values, so an operator who
    /// runs this by mistake ends up back where they started rather than
    /// pinning something they typed. Unknown node_id ⇒ `Ok(false)`.
    pub async fn node_reset_crypto(&self, node_id: &str, actor_uid: i64) -> Result<bool, RpcError> {
        let cleared = sqlx::query(
            "UPDATE nodes SET resp_pubkey = NULL, tls_spki_pin = NULL WHERE node_id = ?",
        )
        .bind(node_id)
        .execute(&self.pool)
        .await
        .map_err(|e| RpcError::Internal_with(format!("node_reset_crypto: {e}")))?
        .rows_affected()
            > 0;
        self.append_audit(
            "node.reset_crypto",
            Some(node_id),
            &serde_json::json!({"actor_uid": actor_uid}).to_string(),
            if cleared { "ok" } else { "noop" },
        )
        .await;
        Ok(cleared)
    }

    pub async fn invite_create(
        &self,
        label: String,
        ttl_secs: i64,
    ) -> Result<hyperion_types::NodeInviteMint, RpcError> {
        if label.trim().is_empty() {
            return Err(RpcError::Validation {
                message: "label must be non-empty".into(),
            });
        }
        let ttl = ttl_secs.clamp(60, 30 * 24 * 3600);
        let now = now_secs();
        let invite = hyperion_state::invites::mint(label.trim(), ttl, now);
        hyperion_state::invites::insert(&self.pool, &invite, now)
            .await
            .map_err(|e| RpcError::Internal_with(format!("invite insert: {e}")))?;
        self.append_audit(
            "node.invite",
            None,
            &serde_json::json!({
                "label": label.trim(),
                "ttl_secs": ttl,
                "token_hash": invite.token_hash,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::NodeInviteMint {
            token: invite.token,
            token_hash: invite.token_hash,
            label: invite.label,
            expires_at: invite.expires_at,
        })
    }

    pub async fn invite_list(&self) -> Result<Vec<hyperion_types::NodeInviteSummary>, RpcError> {
        let rows = hyperion_state::invites::list_pending(&self.pool, now_secs(), 200)
            .await
            .map_err(|e| RpcError::Internal_with(format!("invite list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|r| hyperion_types::NodeInviteSummary {
                token_hash: r.token_hash,
                label: r.label,
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
            .collect())
    }

    pub async fn invite_revoke(&self, token_hash: String) -> Result<(), RpcError> {
        hyperion_state::invites::revoke(&self.pool, &token_hash)
            .await
            .map_err(|e| RpcError::Internal_with(format!("invite revoke: {e}")))?;
        self.append_audit(
            "node.invite.revoke",
            None,
            &serde_json::json!({ "token_hash": token_hash }).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }
}

/// Outcome of comparing a self-reported trust anchor a node just
/// published against the one the master has pinned. See
/// [`decide_tofu_pin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TofuPin {
    /// Nothing pinned yet — adopt this value (first value wins).
    Adopt,
    /// Already pinned to the same value — no-op.
    Keep,
    /// Already pinned to a DIFFERENT value — refuse (reinstalled box, or
    /// an on-path attacker trying to become the signer).
    Refuse,
}

/// Trust-on-first-use decision for a node's self-reported crypto
/// anchors — its response-signing pubkey AND its inbound TLS SPKI pin —
/// the mirror image of the agent's own `decide_pubkey_pin` for the
/// master's key (bin/hyperion-agent/src/enroll.rs). ONE rule for both,
/// because they carry the same weight: pin the first value seen and
/// refuse any later report of a different one. The channel that carries
/// them is authenticated by a shared secret over `curl -k`, while the
/// values themselves are the trust anchors for every response the master
/// accepts (`resp_pubkey`) and for `--pinnedpubkey` cert enforcement
/// (`tls_spki_pin`), so a silent rotation of either would be a complete
/// bypass. Rotation is therefore a deliberate operator action
/// (`node_reset_crypto`, or re-enrollment, both of which clear the pins
/// first).
pub(super) fn decide_tofu_pin(pinned: Option<&str>, presented: &str) -> TofuPin {
    match pinned {
        Some(p) if p != presented => TofuPin::Refuse,
        Some(_) => TofuPin::Keep,
        None => TofuPin::Adopt,
    }
}

/// Apply [`decide_tofu_pin`] to ONE anchor on the heartbeat path and make
/// a refusal audible. Returns the value to hand `touch_last_seen`: `Some`
/// only when THIS report should adopt it, `None` meaning "keep whatever
/// is on file". Storage enforces write-once independently (the COALESCE
/// order in `touch_last_seen`); this layer is what stops a mismatch from
/// being silent.
///
/// `anchor` names the value in the log line so an operator can tell a
/// swapped signing key from a swapped TLS pin at a glance.
pub(super) fn tofu_report<'a>(
    node_id: &str,
    anchor: &str,
    pinned: Option<&str>,
    presented: Option<&'a str>,
) -> Option<&'a str> {
    let presented = presented.map(str::trim).filter(|s| !s.is_empty())?;
    match decide_tofu_pin(pinned, presented) {
        TofuPin::Adopt => Some(presented),
        TofuPin::Keep => None,
        TofuPin::Refuse => {
            // Loud, because the benign explanation (agent reinstall that
            // regenerated node-rpc.key / the inbound TLS cert while
            // node-id.json survived) and the hostile one look identical
            // here. The fix for the benign case is `node reset crypto` or
            // a re-enrollment — both explicit operator actions.
            tracing::warn!(
                node = %node_id,
                anchor = anchor,
                "SECURITY: node {node_id} presented a changed {anchor} — REFUSING to \
                 re-pin. Heartbeat accepted, pin unchanged. If this node was \
                 legitimately reinstalled, reset its pinned crypto (or re-enrol it); \
                 otherwise this may be an on-path attack."
            );
            None
        }
    }
}

/// A node-reported address, kept only if it is something the master can
/// put in `https://<addr>:<port>/` and mean one host: an IP literal or a
/// DNS hostname, nothing else. Anything else is logged and dropped — the
/// enrollment or heartbeat it rode on still goes through, the node just
/// has no address on record — because the value ends up in a URL handed
/// to curl, and `evil/x?` or `user@host` there would dial somewhere the
/// operator never chose.
pub(super) fn checked_node_addr(node_id: &str, field: &str, v: Option<String>) -> Option<String> {
    let v = v?.trim().to_string();
    if v.is_empty() {
        return None;
    }
    let bare = v.trim_start_matches('[').trim_end_matches(']');
    let ok = bare.parse::<std::net::IpAddr>().is_ok() || is_dns_hostname(bare);
    if ok {
        Some(bare.to_string())
    } else {
        tracing::warn!(
            node = node_id,
            field,
            "node reported an address that is neither an IP nor a hostname — ignored"
        );
        None
    }
}

/// `label(.label)*` of letters, digits and hyphens, no label starting or
/// ending with a hyphen, at most 253 bytes.
pub(super) fn is_dns_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.trim_end_matches('.').split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
