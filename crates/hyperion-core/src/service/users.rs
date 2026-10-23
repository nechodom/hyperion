//! Web users, roles, 2FA, avatars and per-hosting access grants.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ════════════════════════════════════════════════════════════
    //  Web users / roles / TOTP 2FA / invites
    // ════════════════════════════════════════════════════════════

    /// Username + password authentication. Doesn't mint a session
    /// (web binary owns the cookie signer). Tracks failed attempts +
    /// auto-locks after `WEB_LOGIN_MAX_FAILS` consecutive misses.
    pub async fn web_login(
        &self,
        username: String,
        password: String,
        client_ip: Option<String>,
    ) -> Result<hyperion_types::WebLoginResult, RpcError> {
        const WEB_LOGIN_MAX_FAILS: i64 = 10;
        let user = match hyperion_state::web_users::get_by_username(&self.pool, username.trim())
            .await
            .map_err(|e| RpcError::Internal_with(format!("get user: {e}")))?
        {
            Some(u) => u,
            None => {
                // Don't reveal whether the username exists.
                return Ok(hyperion_types::WebLoginResult::Invalid);
            }
        };
        if user.locked {
            return Ok(hyperion_types::WebLoginResult::Locked {
                reason: user
                    .locked_reason
                    .unwrap_or_else(|| "account locked".into()),
            });
        }
        // Verify the password (constant-time via argon2).
        let ok = hyperion_auth::verify_password(&password, &user.password_hash)
            .map_err(|e| RpcError::Internal_with(format!("verify: {e}")))?;
        if !ok {
            let n = hyperion_state::web_users::record_failed_login(&self.pool, user.id, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("track failed: {e}")))?;
            if n >= WEB_LOGIN_MAX_FAILS {
                let _ = hyperion_state::web_users::set_locked(
                    &self.pool,
                    user.id,
                    true,
                    Some("too many failed login attempts"),
                    now_secs(),
                )
                .await;
                self.append_audit(
                    "web.user.locked",
                    None,
                    &serde_json::json!({"user_id": user.id, "reason": "failed_logins"}).to_string(),
                    "ok",
                )
                .await;
            }
            self.append_audit_as(
                user.id,
                &user.username,
                "web.login.failed",
                None,
                &serde_json::json!({
                    "username": user.username,
                    "ip": client_ip,
                    "failed_count": n,
                })
                .to_string(),
                "failed",
            )
            .await;
            return Ok(hyperion_types::WebLoginResult::Invalid);
        }
        // Password OK. If 2FA enrolled, ask for TOTP.
        if user.is_2fa_enrolled() {
            return Ok(hyperion_types::WebLoginResult::NeedsTotp {
                user_id: user.id,
                username: user.username,
            });
        }
        // No 2FA — record the login, return Ok.
        hyperion_state::web_users::record_login(
            &self.pool,
            user.id,
            client_ip.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("record login: {e}")))?;
        self.append_audit_as(
            user.id,
            &user.username,
            "web.login.ok",
            None,
            &serde_json::json!({"user_id": user.id, "ip": client_ip}).to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::WebLoginResult::Ok {
            user_id: user.id,
            username: user.username,
            email: user.email,
            role: user.role.as_str().to_string(),
        })
    }

    /// Step 2 of a 2FA-required login: verify either a 6-digit TOTP
    /// code or a 9-char (XXXX-XXXX) backup code. On TOTP success, the
    /// code is accepted within ±30s of clock skew (RFC 6238). On
    /// backup-code success the code is marked used (one-shot).
    pub async fn web_verify_2fa(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<hyperion_types::WebVerify2faResult, RpcError> {
        let user = match hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get user: {e}")))?
        {
            Some(u) => u,
            None => return Ok(hyperion_types::WebVerify2faResult::Invalid),
        };
        if user.locked || !user.is_2fa_enrolled() {
            return Ok(hyperion_types::WebVerify2faResult::Invalid);
        }
        let trimmed = code.trim();
        // Heuristic: 6 digits = TOTP, otherwise backup code.
        let is_totp = trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_digit());
        let accepted = if is_totp {
            let secret = user
                .totp_secret_base32
                .as_deref()
                .ok_or_else(|| RpcError::Internal_with("missing totp secret".into()))?;
            // Replay protection: verify_code_step returns the matched absolute
            // time-step; consume_totp_step atomically accepts it only if it's
            // newer than the last one used, so a code captured in its ~90s
            // window can't be replayed (RFC 6238 §5.2).
            match hyperion_auth::verify_code_step(secret, trimmed)
                .map_err(|e| RpcError::Internal_with(format!("totp verify: {e}")))?
            {
                Some(step) => {
                    hyperion_state::web_users::consume_totp_step(&self.pool, user.id, step)
                        .await
                        .map_err(|e| RpcError::Internal_with(format!("totp step: {e}")))?
                }
                None => false,
            }
        } else {
            // Backup code path.
            let h = hyperion_auth::hash_backup_code(trimmed);
            hyperion_state::web_users::consume_backup_code(&self.pool, user.id, &h, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("consume backup: {e}")))?
        };
        if !accepted {
            // SECURITY (sec-findings #7): a server-side, per-account failure cap
            // is the topology-independent backstop against TOTP/backup-code
            // brute-force (the per-IP throttle alone is defeated by XFF rotation
            // / a botnet). Mirror web_login: increment the SHARED failed_logins
            // counter and HARD-LOCK the account at the threshold. The counter is
            // reset by record_login on the next successful auth.
            const WEB_2FA_MAX_FAILS: i64 = 8;
            let n = hyperion_state::web_users::record_failed_login(&self.pool, user.id, now_secs())
                .await
                .map_err(|e| RpcError::Internal_with(format!("track 2fa failed: {e}")))?;
            if n >= WEB_2FA_MAX_FAILS {
                let _ = hyperion_state::web_users::set_locked(
                    &self.pool,
                    user.id,
                    true,
                    Some("too many failed 2FA attempts"),
                    now_secs(),
                )
                .await;
                self.append_audit(
                    "web.user.locked",
                    None,
                    &serde_json::json!({"user_id": user.id, "reason": "failed_2fa"}).to_string(),
                    "ok",
                )
                .await;
            }
            self.append_audit_as(
                user.id,
                &user.username,
                "web.login.2fa_failed",
                None,
                &serde_json::json!({
                    "user_id": user.id,
                    "via": if is_totp {"totp"} else {"backup_code"},
                    "failed_count": n,
                })
                .to_string(),
                "failed",
            )
            .await;
            return Ok(hyperion_types::WebVerify2faResult::Invalid);
        }
        hyperion_state::web_users::record_login(&self.pool, user.id, None, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("record login: {e}")))?;
        self.append_audit_as(
            user.id,
            &user.username,
            "web.login.2fa_ok",
            None,
            &serde_json::json!({"user_id": user.id, "via": if is_totp {"totp"} else {"backup_code"}})
                .to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::WebVerify2faResult::Ok {
            user_id: user.id,
            username: user.username,
            email: user.email,
            role: user.role.as_str().to_string(),
        })
    }

    pub async fn web_user_list(&self) -> Result<Vec<hyperion_types::WebUserSummary>, RpcError> {
        let rows = hyperion_state::web_users::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        let custom = hyperion_state::web_users::custom_role_assignments(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list custom roles: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|u| {
                let custom_role_id = custom.get(&u.id).copied();
                hyperion_types::WebUserSummary {
                    custom_role_id,
                    ..row_to_summary(u)
                }
            })
            .collect())
    }

    pub async fn web_user_get(
        &self,
        id: i64,
    ) -> Result<Option<hyperion_types::WebUserSummary>, RpcError> {
        let Some(row) = hyperion_state::web_users::get_by_id(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
        else {
            return Ok(None);
        };
        // Both extras are best-effort: a failed read leaves the field empty
        // rather than failing the whole lookup (login and the users page go
        // through here too).
        let now = now_secs();
        let pending_email = hyperion_state::web_users::get_pending_email(&self.pool, id)
            .await
            .ok()
            .flatten()
            // Same bounds email_change_confirm enforces: an expired or
            // burnt-out code can no longer be entered, so it is not pending.
            .filter(|p| p.expires_at >= now && p.attempts < 5)
            .map(|p| hyperion_types::PendingEmailChange {
                new_email: p.new_email,
                expires_at: p.expires_at,
            });
        let backup_codes_left = if row.totp_enrolled_at.is_some() {
            hyperion_state::web_users::count_unused_backup_codes(&self.pool, id)
                .await
                .ok()
        } else {
            None
        };
        Ok(Some(hyperion_types::WebUserSummary {
            pending_email,
            backup_codes_left,
            ..row_to_summary(row)
        }))
    }

    pub async fn web_user_create(
        &self,
        username: String,
        email: String,
        password: String,
        role: String,
    ) -> Result<i64, RpcError> {
        let username = username.trim();
        let email = email.trim();
        if username.is_empty() || email.is_empty() {
            return Err(RpcError::Validation {
                message: "username and email are required".into(),
            });
        }
        if !email.contains('@') {
            return Err(RpcError::Validation {
                message: "email must contain '@'".into(),
            });
        }
        if password.len() < 8 {
            return Err(RpcError::Validation {
                message: "password must be at least 8 characters".into(),
            });
        }
        let role: hyperion_state::web_users::WebRole = role
            .parse()
            .map_err(|e: String| RpcError::Validation { message: e })?;
        let phc = hyperion_auth::hash_password(&password)
            .map_err(|e| RpcError::Internal_with(format!("hash: {e}")))?;
        let id = hyperion_state::web_users::insert(
            &self.pool,
            &hyperion_state::web_users::NewWebUser {
                username,
                email,
                password_hash: &phc,
                role,
            },
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("insert: {e}")))?;
        self.append_audit(
            "web.user.create",
            None,
            &serde_json::json!({"id": id, "username": username, "role": role.as_str()}).to_string(),
            "ok",
        )
        .await;
        Ok(id)
    }

    pub async fn web_user_set_password(
        &self,
        user_id: i64,
        new_password: String,
        current_password: Option<String>,
    ) -> Result<(), RpcError> {
        if new_password.len() < 8 {
            return Err(RpcError::Validation {
                message: "password must be at least 8 characters".into(),
            });
        }
        // Self-service changes carry the current password and must re-verify it
        // (a stolen session shouldn't be able to silently take over the account
        // by setting a new password). Admin resets pass `None` — the admin is
        // already authorized at the web layer.
        if let Some(current) = current_password {
            let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("get user: {e}")))?
                .ok_or_else(|| RpcError::NotFound {
                    kind: "web_user".into(),
                    id: user_id.to_string(),
                })?;
            let ok = hyperion_auth::verify_password(&current, &user.password_hash)
                .map_err(|e| RpcError::Internal_with(format!("verify: {e}")))?;
            if !ok {
                return Err(RpcError::Validation {
                    message: "current password is incorrect".into(),
                });
            }
        }
        let phc = hyperion_auth::hash_password(&new_password)
            .map_err(|e| RpcError::Internal_with(format!("hash: {e}")))?;
        hyperion_state::web_users::set_password_hash(&self.pool, user_id, &phc, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set: {e}")))?;
        self.append_audit(
            "web.user.password_set",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Begin an email-change flow: verify the current password,
    /// store the new email + a hashed 6-digit code (15min TTL),
    /// dispatch the code to the NEW address. Returns the masked
    /// recipient so the UI can confirm without echoing the full
    /// address back to the operator's screen.
    ///
    /// We require the current password as a soft-2FA gate so a
    /// stolen session can't silently take over the account by
    /// pointing email at attacker-controlled inbox.
    pub async fn email_change_request(
        &self,
        user_id: i64,
        new_email: String,
        current_password: String,
    ) -> Result<String, RpcError> {
        let new_email = new_email.trim().to_string();
        if !new_email.contains('@') || new_email.len() > 254 {
            return Err(RpcError::Validation {
                message: "new_email is not a valid address".into(),
            });
        }
        let row = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get user: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            })?;
        if new_email == row.email {
            return Err(RpcError::Validation {
                message: "new email matches current email".into(),
            });
        }
        let ok = hyperion_auth::verify_password(&current_password, &row.password_hash)
            .map_err(|e| RpcError::Internal_with(format!("verify: {e}")))?;
        if !ok {
            return Err(RpcError::Validation {
                message: "current password is incorrect".into(),
            });
        }
        // No mail transport = no way to deliver the code. Refuse before
        // stashing anything: the profile page shows a stored pending change
        // as "a code went to <address>", which would be a lie.
        let Some(cfg) = self.email_config.as_ref() else {
            return Err(RpcError::Conflict {
                message: "no SMTP configured — configure Settings → Mail first".into(),
            });
        };
        // Generate a 6-digit code. We use a CSPRNG so brute-force
        // resistance comes from the limited attempt count, not from
        // the entropy of the code.
        use rand::Rng;
        let code: u32 = rand::thread_rng().gen_range(0..1_000_000);
        let code_str = format!("{:06}", code);
        let code_hash = hyperion_auth::hash_password(&code_str)
            .map_err(|e| RpcError::Internal_with(format!("hash code: {e}")))?;
        let expires_at = now_secs() + 15 * 60;
        hyperion_state::web_users::set_pending_email(
            &self.pool,
            user_id,
            &new_email,
            &code_hash,
            expires_at,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("stash: {e}")))?;

        // Dispatch the email. A failed send clears the pending row: the
        // profile page would otherwise announce a code that never left.
        // A typo'd address is fixed by requesting again (which overwrites
        // the pending row).
        let body = format!(
            "Hyperion email-change verification\n\n\
             Code: {code_str}\n\n\
             Enter this code on the profile page within 15 minutes to confirm \
             the change. If you didn't request this, ignore this email — your \
             current address remains in place.\n"
        );
        if let Err(e) = hyperion_adapters::email::send_text(
            cfg,
            &new_email,
            "Hyperion: confirm your new email",
            &body,
        )
        .await
        {
            tracing::warn!(error = %e, "email-change: send failed");
            let _ = hyperion_state::web_users::clear_pending_email(&self.pool, user_id).await;
            return Err(RpcError::Internal_with(format!(
                "couldn't send verification email: {e}. Check Settings → Mail."
            )));
        }

        self.append_audit(
            "web.user.email_change_requested",
            None,
            &serde_json::json!({
                "user_id": user_id,
                "new_email": &new_email,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(mask_email(&new_email))
    }

    pub async fn email_change_confirm(&self, user_id: i64, code: String) -> Result<(), RpcError> {
        let pending = hyperion_state::web_users::get_pending_email(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get pending: {e}")))?
            .ok_or_else(|| RpcError::Validation {
                message: "no email change in progress".into(),
            })?;
        if now_secs() > pending.expires_at {
            // Expired — clear so the operator gets a clean slate
            // when they request again.
            let _ = hyperion_state::web_users::clear_pending_email(&self.pool, user_id).await;
            return Err(RpcError::Validation {
                message: "verification code expired — request a new one".into(),
            });
        }
        if pending.attempts >= 5 {
            let _ = hyperion_state::web_users::clear_pending_email(&self.pool, user_id).await;
            return Err(RpcError::Validation {
                message: "too many wrong codes — request a new email change".into(),
            });
        }
        let ok = hyperion_auth::verify_password(&code, &pending.code_hash)
            .map_err(|e| RpcError::Internal_with(format!("verify code: {e}")))?;
        if !ok {
            let _ =
                hyperion_state::web_users::bump_pending_email_attempts(&self.pool, user_id).await;
            return Err(RpcError::Validation {
                message: "wrong code".into(),
            });
        }
        hyperion_state::web_users::set_email(&self.pool, user_id, &pending.new_email, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set email: {e}")))?;
        let _ = hyperion_state::web_users::clear_pending_email(&self.pool, user_id).await;
        self.append_audit(
            "web.user.email_changed",
            None,
            &serde_json::json!({
                "user_id": user_id,
                "new_email": &pending.new_email,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn email_change_cancel(&self, user_id: i64) -> Result<(), RpcError> {
        hyperion_state::web_users::clear_pending_email(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("clear: {e}")))?;
        Ok(())
    }

    pub async fn web_user_set_role(&self, user_id: i64, role: String) -> Result<(), RpcError> {
        let parsed: hyperion_state::web_users::WebRole = role
            .parse()
            .map_err(|e: String| RpcError::Validation { message: e })?;
        // Refuse to demote the last super_admin.
        if !parsed.can_manage_users() {
            self.guard_last_super_admin(user_id).await?;
        }
        hyperion_state::web_users::set_role(&self.pool, user_id, parsed, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set role: {e}")))?;
        self.append_audit(
            "web.user.role_set",
            None,
            &serde_json::json!({"user_id": user_id, "role": parsed.as_str()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    // ----------------------------------------------------------------
    //  Custom roles (granular RBAC)
    // ----------------------------------------------------------------

    pub async fn role_list(&self) -> Result<Vec<hyperion_types::CustomRoleSummary>, RpcError> {
        let rows = hyperion_state::custom_roles::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("role list: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let in_use = hyperion_state::custom_roles::count_in_use(&self.pool, row.id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("role in-use count: {e}")))?;
            out.push(hyperion_types::CustomRoleSummary {
                id: row.id,
                name: row.name.clone(),
                capabilities: row.caps().bits(),
                scope_all: row.scope_all(),
                in_use,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(out)
    }

    pub async fn role_create(
        &self,
        name: String,
        capabilities: u64,
        scope_all: bool,
    ) -> Result<i64, RpcError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(RpcError::Validation {
                message: "role name must not be empty".into(),
            });
        }
        let id = hyperion_state::custom_roles::create(
            &self.pool,
            name,
            capabilities,
            scope_all,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("role create: {e}")))?;
        self.append_audit(
            "web.role.create",
            None,
            &serde_json::json!({"id": id, "name": name, "capabilities": capabilities, "scope_all": scope_all}).to_string(),
            "ok",
        )
        .await;
        Ok(id)
    }

    pub async fn role_update(
        &self,
        id: i64,
        name: String,
        capabilities: u64,
        scope_all: bool,
    ) -> Result<(), RpcError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(RpcError::Validation {
                message: "role name must not be empty".into(),
            });
        }
        hyperion_state::custom_roles::update(
            &self.pool,
            id,
            name,
            capabilities,
            scope_all,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("role update: {e}")))?;
        self.append_audit(
            "web.role.update",
            None,
            &serde_json::json!({"id": id, "name": name, "capabilities": capabilities, "scope_all": scope_all}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn role_delete(&self, id: i64) -> Result<(), RpcError> {
        let in_use = hyperion_state::custom_roles::count_in_use(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("role in-use count: {e}")))?;
        if in_use > 0 {
            return Err(RpcError::Validation {
                message: format!("role in use by {in_use} user(s)"),
            });
        }
        hyperion_state::custom_roles::delete(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("role delete: {e}")))?;
        self.append_audit(
            "web.role.delete",
            None,
            &serde_json::json!({"id": id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn web_user_set_custom_role(
        &self,
        user_id: i64,
        custom_role_id: i64,
    ) -> Result<(), RpcError> {
        let role = hyperion_state::custom_roles::get(&self.pool, custom_role_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("role get: {e}")))?;
        if role.is_none() {
            return Err(RpcError::NotFound {
                kind: "custom_role".into(),
                id: custom_role_id.to_string(),
            });
        }
        hyperion_state::web_users::set_custom_role(&self.pool, user_id, custom_role_id, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set custom role: {e}")))?;
        self.append_audit(
            "web.user.custom_role_set",
            None,
            &serde_json::json!({"user_id": user_id, "custom_role_id": custom_role_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn web_user_effective_role(
        &self,
        user_id: i64,
    ) -> Result<hyperion_types::EffectiveRoleWire, RpcError> {
        let er = hyperion_state::web_users::effective_role(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("effective role: {e}")))?;
        let Some(er) = er else {
            return Err(RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            });
        };
        Ok(hyperion_types::EffectiveRoleWire {
            caps: er.caps.bits(),
            scope_all: er.scope_all,
            label: er.label,
            custom_role_id: er.custom_role_id,
            base_role: er.base_role.as_str().to_string(),
        })
    }

    pub async fn web_user_set_locked(
        &self,
        user_id: i64,
        locked: bool,
        reason: Option<String>,
    ) -> Result<(), RpcError> {
        if locked {
            // Refuse to lock the last super_admin.
            self.guard_last_super_admin(user_id).await?;
        }
        hyperion_state::web_users::set_locked(
            &self.pool,
            user_id,
            locked,
            reason.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("lock: {e}")))?;
        self.append_audit(
            if locked {
                "web.user.locked"
            } else {
                "web.user.unlocked"
            },
            None,
            &serde_json::json!({"user_id": user_id, "reason": reason}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn web_user_delete(&self, user_id: i64) -> Result<(), RpcError> {
        self.guard_last_super_admin(user_id).await?;
        let removed = hyperion_state::web_users::delete(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("delete: {e}")))?;
        if removed == 0 {
            return Err(RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            });
        }
        self.append_audit(
            "web.user.delete",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Refuse the operation if `user_id` is the **last** super_admin in
    /// the cluster. Without this guard the operator could lock
    /// themselves out — and there's no recovery without DB hand-edit.
    pub(super) async fn guard_last_super_admin(&self, user_id: i64) -> Result<(), RpcError> {
        let target = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("guard: {e}")))?;
        let Some(target) = target else { return Ok(()) };
        if !matches!(target.role, hyperion_state::web_users::WebRole::SuperAdmin) {
            return Ok(());
        }
        let users = hyperion_state::web_users::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("guard list: {e}")))?;
        let super_admins = users
            .iter()
            .filter(|u| {
                matches!(u.role, hyperion_state::web_users::WebRole::SuperAdmin) && !u.locked
            })
            .count();
        if super_admins <= 1 {
            return Err(RpcError::Validation {
                message: "refusing — this would leave the cluster with no active super_admin"
                    .into(),
            });
        }
        Ok(())
    }

    pub async fn web_2fa_enroll_start(
        &self,
        user_id: i64,
    ) -> Result<hyperion_types::Web2faEnrollment, RpcError> {
        let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            })?;
        let secret = hyperion_auth::generate_secret_base32();
        let issuer = "Hyperion";
        let url = hyperion_auth::otpauth_url(issuer, &user.username, &secret);
        // 10 backup codes is the industry default.
        let (plain, hashes) = hyperion_auth::generate_backup_codes(10);
        // Persist the (still-pending) secret + hashes. enrolled_at stays None.
        hyperion_state::web_users::set_totp(&self.pool, user_id, Some(&secret), None, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("set totp: {e}")))?;
        hyperion_state::web_users::insert_backup_codes(&self.pool, user_id, &hashes, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("insert codes: {e}")))?;
        self.append_audit(
            "web.user.2fa_enroll_start",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(hyperion_types::Web2faEnrollment {
            secret_base32: secret,
            otpauth_url: url,
            backup_codes: plain,
        })
    }

    pub async fn web_2fa_confirm_enroll(
        &self,
        user_id: i64,
        code: String,
    ) -> Result<bool, RpcError> {
        let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            })?;
        let secret = user
            .totp_secret_base32
            .as_deref()
            .ok_or_else(|| RpcError::Validation {
                message: "no pending 2FA enrollment".into(),
            })?;
        let step = match hyperion_auth::verify_code_step(secret, code.trim()).map_err(|e| {
            RpcError::Validation {
                message: format!("invalid code: {e}"),
            }
        })? {
            Some(s) => s,
            None => return Ok(false),
        };
        hyperion_state::web_users::set_totp(
            &self.pool,
            user_id,
            Some(secret),
            Some(now_secs()),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("confirm: {e}")))?;
        // Record the step used to confirm enrolment so the same code can't be
        // replayed at the first login.
        hyperion_state::web_users::consume_totp_step(&self.pool, user_id, step)
            .await
            .map_err(|e| RpcError::Internal_with(format!("totp step: {e}")))?;
        self.append_audit(
            "web.user.2fa_enrolled",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(true)
    }

    /// Grant a user access to one hosting. Idempotent — calling
    /// again upserts the level. super_admin / admin already see
    /// everything so granting them is redundant but allowed.
    pub async fn web_grant_hosting_access(
        &self,
        user_id: i64,
        hosting_id: String,
        level: String,
        granted_by: Option<i64>,
    ) -> Result<(), RpcError> {
        let lvl: hyperion_state::web_users::AccessLevel = level
            .parse()
            .map_err(|e: String| RpcError::Validation { message: e })?;
        // Validate user + hosting exist before writing.
        let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("user: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "web_user".into(),
                id: user_id.to_string(),
            })?;
        let hid = hyperion_types::HostingId(hosting_id.clone());
        if hostings::get_by_id(&self.pool, &hid)
            .await
            .map_err(|e| RpcError::Internal_with(format!("hosting: {e}")))?
            .is_none()
        {
            return Err(RpcError::NotFound {
                kind: "hosting".into(),
                id: hosting_id,
            });
        }
        hyperion_state::web_users::grant_hosting_access(
            &self.pool,
            user_id,
            &hid,
            lvl,
            granted_by,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("grant: {e}")))?;
        self.append_audit(
            "web.access.grant",
            Some(hid.as_str()),
            &serde_json::json!({
                "user_id": user_id,
                "username": user.username,
                "level": lvl.as_str(),
                "granted_by": granted_by,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn web_revoke_hosting_access(
        &self,
        user_id: i64,
        hosting_id: String,
    ) -> Result<(), RpcError> {
        let hid = hyperion_types::HostingId(hosting_id.clone());
        let removed = hyperion_state::web_users::revoke_hosting_access(&self.pool, user_id, &hid)
            .await
            .map_err(|e| RpcError::Internal_with(format!("revoke: {e}")))?;
        if removed == 0 {
            return Err(RpcError::NotFound {
                kind: "web_user_hosting_access".into(),
                id: format!("user={user_id} hosting={hosting_id}"),
            });
        }
        self.append_audit(
            "web.access.revoke",
            Some(&hosting_id),
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    // ════════════════════════════════════════════════════════════
    //  Per-hosting monitoring
    // ════════════════════════════════════════════════════════════

    /// Cluster-wide monitor list — every enabled monitor on THIS
    /// node with computed 24h success rate + avg response time.
    /// The web layer fans this out to enrolled workers and merges
    /// the rows for the /monitoring page.
    pub async fn avatar_filename(&self, user_id: i64) -> Result<Option<String>, RpcError> {
        hyperion_state::web_users::get_avatar_filename(&self.pool, user_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("avatar_filename: {e}")))
    }

    pub async fn avatar_set(&self, user_id: i64, filename: Option<String>) -> Result<(), RpcError> {
        // Whitelist the filename shape (defense in depth — the web
        // handler already validates, but RPC consumers can call us
        // directly too).
        if let Some(f) = &filename {
            if !f
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return Err(RpcError::Validation {
                    message: format!("avatar filename has illegal chars: {f:?}"),
                });
            }
            if f.starts_with('.') {
                return Err(RpcError::Validation {
                    message: "avatar filename cannot start with `.`".into(),
                });
            }
        }
        hyperion_state::web_users::set_avatar_filename(
            &self.pool,
            user_id,
            filename.as_deref(),
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("avatar_set: {e}")))?;
        self.append_audit(
            "web.user.avatar_set",
            None,
            &serde_json::json!({
                "user_id": user_id,
                "set": filename.is_some(),
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn web_list_hosting_access(
        &self,
        hosting_id: String,
    ) -> Result<Vec<hyperion_types::WebHostingAccess>, RpcError> {
        let hid = hyperion_types::HostingId(hosting_id);
        let rows = hyperion_state::web_users::list_access_for_hosting(&self.pool, &hid)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list: {e}")))?;
        Ok(rows
            .into_iter()
            .map(
                |(uid, username, email, lvl, by, at)| hyperion_types::WebHostingAccess {
                    user_id: uid,
                    username,
                    email,
                    level: lvl.as_str().to_string(),
                    granted_by: by,
                    granted_at: at,
                },
            )
            .collect())
    }

    pub async fn web_2fa_disable(
        &self,
        user_id: i64,
        current_password: Option<String>,
    ) -> Result<(), RpcError> {
        // A self-service disable re-verifies the password: a stolen session
        // must not be able to strip the second factor on its own. An admin
        // override passes `None` (already authorized at the web layer).
        if let Some(current) = current_password {
            let user = hyperion_state::web_users::get_by_id(&self.pool, user_id)
                .await
                .map_err(|e| RpcError::Internal_with(format!("get user: {e}")))?
                .ok_or_else(|| RpcError::NotFound {
                    kind: "web_user".into(),
                    id: user_id.to_string(),
                })?;
            let ok = hyperion_auth::verify_password(&current, &user.password_hash)
                .map_err(|e| RpcError::Internal_with(format!("verify: {e}")))?;
            if !ok {
                return Err(RpcError::Validation {
                    message: "current password is incorrect".into(),
                });
            }
        }
        hyperion_state::web_users::set_totp(&self.pool, user_id, None, None, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("disable: {e}")))?;
        // Wipe backup codes too.
        hyperion_state::web_users::insert_backup_codes(&self.pool, user_id, &[], now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("wipe codes: {e}")))?;
        self.append_audit(
            "web.user.2fa_disabled",
            None,
            &serde_json::json!({"user_id": user_id}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }
}

pub(super) fn row_to_summary(
    u: hyperion_state::web_users::WebUserRow,
) -> hyperion_types::WebUserSummary {
    hyperion_types::WebUserSummary {
        id: u.id,
        username: u.username,
        email: u.email,
        role: u.role.as_str().to_string(),
        totp_enrolled: u.totp_enrolled_at.is_some(),
        totp_required: u.totp_required,
        locked: u.locked,
        locked_reason: u.locked_reason,
        last_login_at: u.last_login_at,
        created_at: u.created_at,
        custom_role_id: None,
        pending_email: None,
        backup_codes_left: None,
    }
}
