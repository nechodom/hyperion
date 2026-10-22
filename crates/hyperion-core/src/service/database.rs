//! Per-hosting database credentials and the phpMyAdmin relay.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Reset the DB password for a hosting, persisting the new secret.
    pub async fn db_reset_password(
        &self,
        sel: HostingSelector,
        new_password: String,
    ) -> Result<(), RpcError> {
        if new_password.len() < 12 {
            return Err(RpcError::Validation {
                message: "new password must be at least 12 characters".into(),
            });
        }
        let detail = self.get(sel).await?;
        let db_row = databases::get_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("db lookup: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "database".into(),
                id: detail.domain.clone(),
            })?;

        match db_row.engine {
            DbProvision::MariaDB => {
                hyperion_adapters::mariadb::reset_password(&db_row.db_user, &new_password)
                    .await
                    .map_err(|e| RpcError::ProvisioningFailed {
                        stage: "mariadb_reset".into(),
                        reason: e.to_string(),
                    })?;
            }
            DbProvision::Postgres => {
                hyperion_adapters::postgres::reset_password(&db_row.db_user, &new_password)
                    .await
                    .map_err(|e| RpcError::ProvisioningFailed {
                        stage: "postgres_reset".into(),
                        reason: e.to_string(),
                    })?;
            }
        }

        // Re-persist the secret. We re-fetch & overwrite the existing
        // record so the password matches what the operator now wants.
        self.secrets
            .put(
                &db_row.secret_id,
                &serde_json::json!({
                    "engine": db_row.engine.as_str(),
                    "db_name": db_row.db_name,
                    "db_user": db_row.db_user,
                    "password": new_password,
                }),
            )
            .await
            .map_err(|e| RpcError::Internal_with(format!("secret update: {e}")))?;

        self.append_audit(
            "database.reset_password",
            Some(detail.id.as_str()),
            &serde_json::json!({"engine": db_row.engine.as_str()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Relay one browser request to this hosting's phpMyAdmin.
    ///
    /// Runs on the owning node, which is the only place the database password
    /// exists. Everything the master sent is re-checked here — the signed
    /// channel proves who sent it, not that it is well-formed — and the
    /// credentials are attached last, so nothing on the wire can supply or
    /// override them. See `hyperion_types::pma` for the whole model.
    pub async fn pma_http(
        &self,
        sel: HostingSelector,
        req: hyperion_types::pma::PmaHttpRequest,
    ) -> Result<hyperion_types::pma::PmaHttpResponse, RpcError> {
        use base64::Engine as _;
        use hyperion_types::pma as wire;

        let detail = self.get(sel).await?;
        let hosting_id = detail.id.as_str().to_string();
        if !wire::method_allowed(&req.method)
            || !wire::rest_path_ok(&req.path)
            || !wire::base_url_ok(&req.base_url, &hosting_id)
        {
            return Err(RpcError::Validation {
                message: "malformed phpMyAdmin request".into(),
            });
        }
        let body = base64::engine::general_purpose::STANDARD
            .decode(req.body_b64.as_bytes())
            .map_err(|_| RpcError::Validation {
                message: "phpMyAdmin request body is not base64".into(),
            })?;
        if body.len() > wire::MAX_REQUEST_BODY {
            return Err(RpcError::Validation {
                message: format!("request body over {} KiB", wire::MAX_REQUEST_BODY / 1024),
            });
        }

        let db_row = databases::get_for_hosting(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("db lookup: {e}")))?
            .ok_or(RpcError::NotFound {
                kind: "database".into(),
                id: detail.domain.clone(),
            })?;
        if db_row.engine != DbProvision::MariaDB {
            return Err(RpcError::Conflict {
                message: format!(
                    "phpMyAdmin manages MariaDB only; {} uses {}",
                    detail.domain,
                    db_row.engine.as_str()
                ),
            });
        }

        let socket = std::path::Path::new(crate::pma::NGINX_SOCKET);
        if tokio::fs::metadata(socket).await.is_err() {
            return Err(RpcError::Conflict {
                message: "phpMyAdmin is not installed on this node yet — run \
                          `hyperion update` on it (or packaging/install/phpmyadmin.sh)"
                    .into(),
            });
        }

        #[derive(serde::Deserialize)]
        struct StoredDbCred {
            password: String,
        }
        let stored: StoredDbCred = self
            .secrets
            .get(&db_row.secret_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("secret read: {e}")))?;

        // One audit line per phpMyAdmin visit, not per asset: the entry page
        // is the bare root, which every visit loads exactly once.
        if req.method == "GET" && req.path == "/" {
            self.append_audit(
                "database.phpmyadmin_open",
                Some(detail.id.as_str()),
                &serde_json::json!({"db": db_row.db_name}).to_string(),
                "ok",
            )
            .await;
        }

        let creds = crate::pma::PmaCreds {
            db_user: &db_row.db_user,
            db_password: &stored.password,
            db_name: &db_row.db_name,
        };
        crate::pma::round_trip(socket, &hosting_id, &req, &body, &creds)
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "phpmyadmin".into(),
                reason: e,
            })
    }
}
