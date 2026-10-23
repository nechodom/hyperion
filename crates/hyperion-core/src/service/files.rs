//! The per-hosting file manager and log viewer.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// List one directory inside a hosting's htdocs root. Returns the
    /// (echoed) relative path + the entries. All entries are RELATIVE
    /// to htdocs — operators can navigate without leaking the absolute
    /// filesystem layout.
    pub async fn hosting_file_list(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(String, Vec<hyperion_types::HostingFileEntry>), RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        let abs = hyperion_adapters::files::resolve_inside_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        let mut entries = Vec::new();
        let mut rd = tokio::fs::read_dir(&abs)
            .await
            .map_err(|e| RpcError::Validation {
                message: format!("read_dir: {e}"),
            })?;
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(|e| RpcError::Internal_with(format!("read entry: {e}")))?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip dotfiles starting with .. (paranoia — they shouldn't
            // be there) and hidden control files like .DS_Store noise.
            if name.starts_with("..") {
                continue;
            }
            let md = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let kind = if md.is_dir() {
                "dir"
            } else if md.file_type().is_symlink() {
                "symlink"
            } else if md.is_file() {
                "file"
            } else {
                "other"
            };
            let mime = if kind == "file" {
                hyperion_adapters::files::guess_mime(&name).to_string()
            } else {
                String::new()
            };
            let inline_viewable = kind == "file"
                && md.len() <= hyperion_adapters::files::MAX_INLINE_BYTES
                && hyperion_adapters::files::is_inline_text(&mime);
            let rel = if rel_path.is_empty() || rel_path == "/" {
                name.clone()
            } else {
                format!("{}/{}", rel_path.trim_end_matches('/'), name)
            };
            let modified_at = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            entries.push(hyperion_types::HostingFileEntry {
                name,
                rel_path: rel,
                kind: kind.to_string(),
                size: md.len(),
                modified_at,
                mime,
                inline_viewable,
            });
        }
        // Directories first, then alphabetical.
        entries.sort_by(|a, b| match (a.kind.as_str(), b.kind.as_str()) {
            ("dir", "dir") | ("file", "file") => a.name.cmp(&b.name),
            ("dir", _) => std::cmp::Ordering::Less,
            (_, "dir") => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        });
        Ok((rel_path, entries))
    }

    pub async fn hosting_file_download(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(String, String, String), RpcError> {
        use base64::Engine;
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        let (bytes, name) = hyperion_adapters::files::read_raw_in_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        let mime = hyperion_adapters::files::guess_mime(&name).to_string();
        let bytes_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        Ok((rel_path, bytes_b64, mime))
    }

    pub async fn hosting_file_write(
        &self,
        sel: HostingSelector,
        rel_path: String,
        bytes_b64: String,
    ) -> Result<(), RpcError> {
        use base64::Engine;
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(bytes_b64.as_bytes())
            .map_err(|e| RpcError::Validation {
                message: format!("base64 decode: {e}"),
            })?;
        hyperion_adapters::files::write_file_in_jail(&jail, &rel_path, &bytes)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        // The agent runs as root, so the file just written is root-owned
        // — chown it to the hosting's system user so PHP/WordPress and
        // FTP (running as that user) can rewrite/delete it. Best-effort.
        let _ =
            hyperion_adapters::files::chown_in_jail(&jail, &rel_path, &detail.system_user).await;
        self.append_audit(
            "hosting.file.write",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "rel_path": rel_path,
                "bytes": bytes.len(),
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_file_delete(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        hyperion_adapters::files::delete_in_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "hosting.file.delete",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "rel_path": rel_path,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_file_mkdir(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        hyperion_adapters::files::mkdir_in_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        // Root-owned otherwise — chown to the hosting user so WP plugin/
        // theme installs into this dir (and FTP) work. Best-effort.
        let _ =
            hyperion_adapters::files::chown_in_jail(&jail, &rel_path, &detail.system_user).await;
        self.append_audit(
            "hosting.file.mkdir",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "rel_path": rel_path,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_file_rename(
        &self,
        sel: HostingSelector,
        from: String,
        to: String,
    ) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        hyperion_adapters::files::rename_in_jail(&jail, &from, &to)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        self.append_audit(
            "hosting.file.rename",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "domain": detail.domain,
                "from": from,
                "to": to,
            })
            .to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    pub async fn hosting_file_read(
        &self,
        sel: HostingSelector,
        rel_path: String,
    ) -> Result<hyperion_types::HostingFileContent, RpcError> {
        let detail = self.get(sel).await?;
        let jail = std::path::PathBuf::from(&detail.root_dir);
        let abs = hyperion_adapters::files::resolve_inside_jail(&jail, &rel_path)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })?;
        let md = tokio::fs::metadata(&abs)
            .await
            .map_err(|e| RpcError::Validation {
                message: format!("stat: {e}"),
            })?;
        if !md.is_file() {
            return Err(RpcError::Validation {
                message: "not a regular file".into(),
            });
        }
        let mime = hyperion_adapters::files::guess_mime(
            abs.file_name().and_then(|n| n.to_str()).unwrap_or(""),
        )
        .to_string();
        if !hyperion_adapters::files::is_inline_text(&mime) {
            return Err(RpcError::Validation {
                message: format!("binary file (mime={mime}) — download separately"),
            });
        }
        if md.len() > hyperion_adapters::files::MAX_INLINE_BYTES {
            return Ok(hyperion_types::HostingFileContent {
                rel_path,
                mime,
                size: md.len(),
                content: String::new(),
                truncated: true,
            });
        }
        let bytes = tokio::fs::read(&abs)
            .await
            .map_err(|e| RpcError::Internal_with(format!("read: {e}")))?;
        let content = String::from_utf8_lossy(&bytes).to_string();
        Ok(hyperion_types::HostingFileContent {
            rel_path,
            mime,
            size: md.len(),
            content,
            truncated: false,
        })
    }

    // ================================================================
    //  Restore from backup archive
    // ================================================================

    // ================================================================
    //  Per-hosting logs
    // ================================================================

    /// Return the tail of a log file for the given hosting.
    /// `log_kind` ∈ {"access", "error", "slow"}.
    pub async fn hosting_logs(
        &self,
        sel: HostingSelector,
        log_kind: &str,
        lines: i64,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let lines = lines.clamp(10, 5000);
        if log_kind == "slow" {
            // The PHP-FPM slow-request log: root-owned, outside the site's
            // tree (see the pool template), one file per pool.
            if detail.system_user.trim().is_empty() {
                return Ok("(this hosting has no PHP pool)".into());
            }
            let path = hyperion_adapters::phpfpm::slowlog_path(&detail.system_user);
            if !path.exists() {
                return Ok(format!(
                    "(no request has run longer than {} s since slow-request logging started)",
                    hyperion_adapters::phpfpm::SLOWLOG_SECS
                ));
            }
            return hyperion_adapters::fs::tail_lines(&path, lines as usize)
                .await
                .map_err(|e| RpcError::Validation {
                    message: e.to_string(),
                });
        }
        let filename = match log_kind {
            "access" => "access.log",
            "error" => "error.log",
            other => {
                return Err(RpcError::Validation {
                    message: format!(
                        "unknown log_kind {other:?}; want \"access\", \"error\" or \"slow\""
                    ),
                })
            }
        };
        let path = std::path::PathBuf::from(&self.paths.home_root)
            .join(&detail.system_user)
            .join(&detail.domain)
            .join("logs")
            .join(filename);
        if !path.exists() {
            return Ok(format!("(no {} log yet at {})", log_kind, path.display()));
        }
        // Read from a file descriptor opened O_NOFOLLOW, not by handing a
        // PATH to `tail`. `logs/` is owned by the SITE USER — it is created
        // 0750 under their uid — so they can replace access.log with a link
        // to /etc/shadow and have root read it out through this very panel.
        // `tail` resolves the path itself, after any check made here.
        hyperion_adapters::fs::tail_lines(&path, lines as usize)
            .await
            .map_err(|e| RpcError::Validation {
                message: e.to_string(),
            })
    }
}
