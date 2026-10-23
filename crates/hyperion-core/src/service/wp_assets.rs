//! The WP asset library of operator-uploaded plugin and theme ZIPs.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ============================================================
    //  WP asset library — operator-uploaded plugin / theme ZIPs
    //  referenced from hosting profiles via @asset:<id>.
    // ============================================================

    pub async fn wp_asset_upload(
        &self,
        kind: String,
        original_name: String,
        bytes: Vec<u8>,
        uploaded_by: String,
    ) -> Result<(i64, bool), RpcError> {
        if kind != "plugin" && kind != "theme" {
            return Err(RpcError::Validation {
                message: format!("kind must be `plugin` or `theme`, got {kind:?}"),
            });
        }
        if bytes.is_empty() {
            return Err(RpcError::Validation {
                message: "uploaded file is empty".into(),
            });
        }
        // Hard cap — Plugin / theme ZIPs are basically never >50 MB.
        // Generous upper bound to catch operator mistakes (uploading
        // a backup tarball or similar).
        const MAX_BYTES: usize = 50 * 1024 * 1024;
        if bytes.len() > MAX_BYTES {
            return Err(RpcError::Validation {
                message: format!(
                    "uploaded file is {} bytes — max is {} bytes (50 MB)",
                    bytes.len(),
                    MAX_BYTES
                ),
            });
        }
        // ZIP magic check — first 4 bytes are PK\x03\x04.
        if bytes.len() < 4 || &bytes[..4] != b"PK\x03\x04" {
            return Err(RpcError::Validation {
                message: "file is not a ZIP archive (missing PK header)".into(),
            });
        }
        // SHA-256 for dedupe + integrity. blake3 is faster but we
        // already store sha256 in the schema for parity with the
        // backup archive checksums.
        let sha = hex::encode(blake3::hash(&bytes).as_bytes());
        // Dedupe — if the same bytes already exist, return that row.
        if let Some(existing) = hyperion_state::wp_assets::get_by_sha(&self.pool, &sha)
            .await
            .map_err(|e| RpcError::Internal_with(format!("dedupe lookup: {e}")))?
        {
            return Ok((existing.id, true));
        }
        // Sanitize the operator filename — keep alphanumerics, dot,
        // dash, underscore. Trim to 64 chars. Empty after sanitize →
        // "asset.zip".
        let stored_filename = wp_asset_stored_filename(&original_name);
        let now = now_secs();
        let id = hyperion_state::wp_assets::insert(
            &self.pool,
            &kind,
            &original_name,
            &stored_filename,
            bytes.len() as i64,
            &sha,
            now,
            &uploaded_by,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("wp_asset insert: {e}")))?;
        let dir = std::path::PathBuf::from("/var/lib/hyperion/wp-assets").join(id.to_string());
        if let Err(e) = tokio::fs::create_dir_all(&dir).await {
            // Roll back the DB row so the operator can retry.
            let _ = hyperion_state::wp_assets::delete(&self.pool, id).await;
            return Err(RpcError::Internal_with(format!(
                "mkdir wp-assets/{id}: {e}"
            )));
        }
        let path = dir.join(&stored_filename);
        if let Err(e) = tokio::fs::write(&path, &bytes).await {
            let _ = hyperion_state::wp_assets::delete(&self.pool, id).await;
            let _ = tokio::fs::remove_dir_all(&dir).await;
            return Err(RpcError::Internal_with(format!(
                "write wp-assets/{id}/{stored_filename}: {e}"
            )));
        }
        // 0644 — readable by anyone (wp-cli runs as the system_user
        // of the hosting being applied to, which is different per
        // hosting). The DIR is 0755 by default which is fine.
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).await;
        self.append_audit(
            "wp_asset.upload",
            None,
            &serde_json::json!({
                "id": id,
                "kind": kind,
                "original_name": original_name,
                "size_bytes": bytes.len(),
                "sha256": sha,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok((id, false))
    }

    pub async fn wp_asset_list(&self) -> Result<Vec<hyperion_types::WpAssetSummary>, RpcError> {
        let rows = hyperion_state::wp_assets::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset list: {e}")))?;
        // Usage counts: profile_refs from a substring scan of
        // every profile's wp_plugins+wp_themes, install_count
        // from the master-side wp_asset_installs tracking table
        // (more accurate than the audit-log scan we did
        // pre-019_wp_asset_installs — that one missed installs
        // dispatched to remote nodes).
        let profiles = hyperion_state::profiles::list(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset usage profiles: {e}")))?;
        let mut out: Vec<hyperion_types::WpAssetSummary> = Vec::with_capacity(rows.len());
        for r in rows {
            let profile_refs = count_profile_asset_refs(&profiles, r.id);
            let install_count = hyperion_state::wp_assets::install_count(&self.pool, r.id)
                .await
                .unwrap_or(0);
            out.push(hyperion_types::WpAssetSummary {
                id: r.id,
                kind: r.kind,
                original_name: r.original_name,
                size_bytes: r.size_bytes,
                sha256: r.sha256,
                uploaded_at: r.uploaded_at,
                uploaded_by: r.uploaded_by,
                profile_refs,
                install_count,
            });
        }
        Ok(out)
    }

    /// Install one uploaded asset onto a hosting. Looks up the
    /// asset, validates kind, derives the on-disk ZIP path, then
    /// shells out to wp-cli via the wp_cli adapter. Returns
    /// (kind, original_name) so the UI flash is specific.
    pub async fn wp_install_from_asset(
        &self,
        sel: HostingSelector,
        asset_id: i64,
        activate: bool,
    ) -> Result<(String, String), RpcError> {
        let detail = self.get(sel).await?;
        // wp-cli runs the site's own PHP as the site's user. A trashed site has
        // no FPM pool, a locked login and a locked database, on purpose.
        if detail.state == HostingState::Trashed {
            return Err(RpcError::Conflict {
                message: format!("{} is in the trash — restore it first", detail.domain),
            });
        }
        let row = hyperion_state::wp_assets::get_by_id(&self.pool, asset_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset lookup: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "wp_asset".into(),
                id: asset_id.to_string(),
            })?;
        let source = wp_asset_disk_path(asset_id, &row.stored_filename);
        // Refuse if the ZIP went missing — better than wp-cli's
        // generic "file not found" error.
        if !std::path::Path::new(&source).exists() {
            return Err(RpcError::Internal_with(format!(
                "asset id {asset_id} ZIP not present on disk at {source} (out-of-band delete?)"
            )));
        }
        // root_dir, not a hand-built path — see the note at the other
        // wp-cli call site that used to do this.
        let htdocs = detail.root_dir.clone();
        self.adapters
            .wp_cli(&detail.system_user, &htdocs, &row.kind, &source, activate)
            .await
            .map_err(|e| {
                RpcError::Internal_with(format!(
                    "wp {} install {} failed: {e}",
                    row.kind, row.original_name
                ))
            })?;
        self.append_audit(
            "wp.install_from_asset",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "asset_id": asset_id,
                "kind": row.kind,
                "original_name": row.original_name,
                "activate": activate,
            })
            .to_string(),
            "ok",
        )
        .await;
        // Record in the master-side tracking table so the
        // "Re-install on all" button knows which hostings to push
        // a newer version to. node_id is read from the local
        // current_node_id — best-effort; for cross-node installs
        // dispatched from a worker (rare), node_id will be the
        // local one which is still a reasonable hint.
        let node_id = self.current_node_id();
        let _ = hyperion_state::wp_assets::record_install(
            &self.pool,
            asset_id,
            detail.id.as_str(),
            &node_id,
            activate,
            now_secs(),
        )
        .await;
        Ok((row.kind, row.original_name))
    }

    /// Replace the on-disk ZIP for an existing asset id, keeping
    /// the id stable so profiles + tracking rows that reference
    /// `@asset:<id>` survive a version bump.
    pub async fn wp_asset_replace(
        &self,
        id: i64,
        original_name: String,
        bytes: Vec<u8>,
        uploaded_by: String,
    ) -> Result<(), RpcError> {
        // Same validation as upload — empty + size + magic bytes.
        if bytes.is_empty() {
            return Err(RpcError::Validation {
                message: "uploaded file is empty".into(),
            });
        }
        const MAX_BYTES: usize = 50 * 1024 * 1024;
        if bytes.len() > MAX_BYTES {
            return Err(RpcError::Validation {
                message: format!(
                    "uploaded file is {} bytes — max is {} bytes (50 MB)",
                    bytes.len(),
                    MAX_BYTES
                ),
            });
        }
        if bytes.len() < 4 || &bytes[..4] != b"PK\x03\x04" {
            return Err(RpcError::Validation {
                message: "file is not a ZIP archive (missing PK header)".into(),
            });
        }
        let row = hyperion_state::wp_assets::get_by_id(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset lookup: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "wp_asset".into(),
                id: id.to_string(),
            })?;
        let sha = hex::encode(blake3::hash(&bytes).as_bytes());
        // Wipe the old file (its name might differ from the new
        // one — the dir is per-id so it's safe to clear). Then
        // write the new file in the same dir.
        let dir = std::path::PathBuf::from("/var/lib/hyperion/wp-assets").join(id.to_string());
        let _ = tokio::fs::remove_file(&dir.join(&row.stored_filename)).await;
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| RpcError::Internal_with(format!("mkdir wp-assets/{id}: {e}")))?;
        let stored_filename = wp_asset_stored_filename(&original_name);
        let path = dir.join(&stored_filename);
        tokio::fs::write(&path, &bytes).await.map_err(|e| {
            RpcError::Internal_with(format!("write wp-assets/{id}/{stored_filename}: {e}"))
        })?;
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).await;
        hyperion_state::wp_assets::replace(
            &self.pool,
            id,
            &original_name,
            &stored_filename,
            bytes.len() as i64,
            &sha,
            now_secs(),
            &uploaded_by,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("wp_asset replace: {e}")))?;
        self.append_audit(
            "wp_asset.replace",
            None,
            &serde_json::json!({
                "id": id,
                "kind": row.kind,
                "original_name": original_name,
                "size_bytes": bytes.len(),
                "sha256": sha,
                "previous_sha256": row.sha256,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// Push the current bytes of `asset_id` onto every hosting
    /// tracked in wp_asset_installs. One install per (asset_id,
    /// hosting_id) — re-installs run sequentially to avoid hammering
    /// the cluster, and any single failure is appended to a
    /// failure_tail string instead of aborting the run.
    pub async fn wp_asset_reinstall_all(
        &self,
        asset_id: i64,
        force_activate: Option<bool>,
    ) -> Result<(i64, i64, String), RpcError> {
        let targets = hyperion_state::wp_assets::list_install_targets(&self.pool, asset_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("install targets: {e}")))?;
        let mut ok: i64 = 0;
        let mut fail: i64 = 0;
        let mut failures: Vec<String> = Vec::new();
        for t in &targets {
            let activate = force_activate.unwrap_or(t.activate);
            let sel = HostingSelector::Id(hyperion_types::HostingId(t.hosting_id.clone()));
            // Skipped, not failed: a site in the trash is not broken, and
            // `wp_install_from_asset` refuses it anyway.
            if matches!(
                self.get(sel.clone()).await.map(|d| d.state),
                Ok(HostingState::Trashed)
            ) {
                continue;
            }
            // Re-run the same install path. Reusing wp_install_from_asset
            // means it also updates record_install (bumps last_at) for free.
            match self.wp_install_from_asset(sel, asset_id, activate).await {
                Ok(_) => ok += 1,
                Err(e) => {
                    fail += 1;
                    failures.push(format!("{}: {}", t.hosting_id, e));
                }
            }
        }
        let failure_tail = failures.into_iter().take(10).collect::<Vec<_>>().join("\n");
        self.append_audit(
            "wp_asset.reinstall_all",
            None,
            &serde_json::json!({
                "asset_id": asset_id,
                "force_activate": force_activate,
                "targets": targets.len(),
                "ok": ok,
                "fail": fail,
            })
            .to_string(),
            if fail == 0 { "ok" } else { "warn" },
        )
        .await;
        Ok((ok, fail, failure_tail))
    }

    /// One library asset's row and ZIP bytes, for the master to copy onto
    /// a node ([`Self::wp_asset_mirror`] there).
    pub async fn wp_asset_read(
        &self,
        id: i64,
    ) -> Result<(hyperion_types::WpAssetSummary, Vec<u8>), RpcError> {
        let row = hyperion_state::wp_assets::get_by_id(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset lookup: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "wp_asset".into(),
                id: id.to_string(),
            })?;
        let path = wp_asset_disk_path(id, &row.stored_filename);
        let bytes = tokio::fs::read(&path).await.map_err(|e| {
            RpcError::Internal_with(format!(
                "{} (library item {id}) is missing on this server's disk: {e}",
                row.original_name
            ))
        })?;
        Ok((
            hyperion_types::WpAssetSummary {
                id: row.id,
                kind: row.kind,
                original_name: row.original_name,
                size_bytes: row.size_bytes,
                sha256: row.sha256,
                uploaded_at: row.uploaded_at,
                uploaded_by: row.uploaded_by,
                profile_refs: 0,
                install_count: 0,
            },
            bytes,
        ))
    }

    /// Store a copy of a master library asset on this node under the
    /// master's id. The bytes must hash to the master's recorded hash, so a
    /// ZIP that rotted on the master's disk (or was mangled in transit) is
    /// refused here rather than handed to wp-cli on a customer's site.
    ///
    /// Written to a temp name and renamed into place, so an install reading
    /// the old file mid-mirror sees either the old ZIP or the new one, never
    /// half of one.
    pub async fn wp_asset_mirror(
        &self,
        asset: hyperion_types::WpAssetSummary,
        bytes: Vec<u8>,
    ) -> Result<(), RpcError> {
        if asset.id <= 0 {
            return Err(RpcError::Validation {
                message: format!("library id must be positive, got {}", asset.id),
            });
        }
        if asset.kind != "plugin" && asset.kind != "theme" {
            return Err(RpcError::Validation {
                message: format!("kind must be `plugin` or `theme`, got {:?}", asset.kind),
            });
        }
        if bytes.len() < 4 || &bytes[..4] != b"PK\x03\x04" {
            return Err(RpcError::Validation {
                message: format!("{} is not a ZIP archive", asset.original_name),
            });
        }
        let got = hex::encode(blake3::hash(&bytes).as_bytes());
        if !got.eq_ignore_ascii_case(asset.sha256.trim()) {
            return Err(RpcError::Validation {
                message: format!(
                    "{} doesn't match the checksum the master recorded for it — \
                     re-upload it to the library",
                    asset.original_name
                ),
            });
        }
        let id = asset.id;
        let stored_filename = wp_asset_stored_filename(&asset.original_name);
        let dir = std::path::PathBuf::from("/var/lib/hyperion/wp-assets").join(id.to_string());
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| RpcError::Internal_with(format!("mkdir wp-assets/{id}: {e}")))?;
        let tmp = dir.join(format!(".{stored_filename}.mirror"));
        let path = dir.join(&stored_filename);
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|e| RpcError::Internal_with(format!("write wp-assets/{id}: {e}")))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).await;
        if let Err(e) = tokio::fs::rename(&tmp, &path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(RpcError::Internal_with(format!(
                "rename into wp-assets/{id}: {e}"
            )));
        }
        // The previous version may have had another name; it is dead weight
        // once the row points at the new one.
        let previous = hyperion_state::wp_assets::get_by_id(&self.pool, id)
            .await
            .ok()
            .flatten()
            .map(|r| r.stored_filename);
        hyperion_state::wp_assets::upsert_with_id(
            &self.pool,
            id,
            &asset.kind,
            &asset.original_name,
            &stored_filename,
            bytes.len() as i64,
            &got,
            asset.uploaded_at,
            &asset.uploaded_by,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("wp_asset mirror: {e}")))?;
        if let Some(old) = previous.filter(|old| *old != stored_filename) {
            let _ = tokio::fs::remove_file(dir.join(wp_asset_stored_filename(&old))).await;
        }
        self.append_audit(
            "wp_asset.mirror",
            None,
            &serde_json::json!({
                "id": id,
                "kind": asset.kind,
                "original_name": asset.original_name,
                "size_bytes": bytes.len(),
                "sha256": got,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn wp_asset_delete(&self, id: i64) -> Result<(), RpcError> {
        let row = hyperion_state::wp_assets::get_by_id(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset get: {e}")))?
            .ok_or_else(|| RpcError::NotFound {
                kind: "wp_asset".into(),
                id: id.to_string(),
            })?;
        hyperion_state::wp_assets::delete(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp_asset delete: {e}")))?;
        let dir = std::path::PathBuf::from("/var/lib/hyperion/wp-assets").join(id.to_string());
        let _ = tokio::fs::remove_dir_all(&dir).await;
        self.append_audit(
            "wp_asset.delete",
            None,
            &serde_json::json!({
                "id": id,
                "kind": row.kind,
                "original_name": row.original_name,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }
}

/// Stream-download a URL to disk via curl. Returns Ok on HTTP 2xx,
/// Err with a useful message otherwise. Used by the migration
/// import-from-url path; cheap to call because curl is already a
/// hard dependency of the installer.
/// On-disk path of an uploaded WP asset's ZIP file. Mirrors the
/// layout `wp_asset_upload` writes — `/var/lib/hyperion/wp-assets/<id>/<filename>`.
pub(super) fn wp_asset_disk_path(id: i64, stored_filename: &str) -> String {
    format!("/var/lib/hyperion/wp-assets/{id}/{stored_filename}")
}

/// The on-disk name for an uploaded ZIP: the operator's filename cut down
/// to alphanumerics, dot, dash and underscore (64 chars), always ending in
/// `.zip`. It is joined onto a directory path, so nothing that could climb
/// out of it (`/`, `..` as a whole name) survives.
pub(super) fn wp_asset_stored_filename(original_name: &str) -> String {
    let safe_name: String = original_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if safe_name.is_empty() || safe_name.chars().all(|c| c == '.') {
        "asset.zip".to_string()
    } else if !safe_name.ends_with(".zip") {
        format!("{safe_name}.zip")
    } else {
        safe_name
    }
}

/// Count `@asset:<id>` references for a given asset id across all
/// profiles' wp_plugins + wp_themes text fields. Uses substring
/// search rather than a regex because the syntax is narrow
/// (`@asset:<digits>` with optional trailing `!`) and the
/// substring + boundary check is faster + dependency-free.
pub(super) fn count_profile_asset_refs(
    profiles: &[hyperion_state::profiles::ProfileRow],
    asset_id: i64,
) -> i64 {
    let needle = format!("@asset:{asset_id}");
    let needle_len = needle.len();
    let mut count: i64 = 0;
    for p in profiles {
        for text in [&p.wp_plugins, &p.wp_themes] {
            for line in text.lines() {
                let stripped = line.trim();
                if let Some(pos) = stripped.find(&needle) {
                    // Boundary check: next char (if any) must be one
                    // of: end-of-string, '!', whitespace, or '#'.
                    // Otherwise `@asset:7` would match @asset:70.
                    let after = stripped[pos + needle_len..].chars().next();
                    let ok = match after {
                        None => true,
                        Some(c) => c == '!' || c.is_whitespace() || c == '#',
                    };
                    if ok {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}
