//! Panel-import engine: the node-side plan + apply that turns a source panel's
//! IR (from the `hyperion-import` crate) into real Hyperion hostings by reusing
//! `HostingService::create()` + the adapter DB-restore helpers. This is the only
//! place that bridges the two worlds (adapters/IR ↔ core provisioning).
//!
//! Two source modes:
//! - **in-place**: the agent runs on the source box; files are copied locally
//!   and DBs dumped against the local DB server.
//! - **remote (SSH)**: the source panel lives on another machine; the adapter
//!   reads it over `ssh`, files are pulled with `rsync -e ssh`, and DBs are
//!   dumped over `ssh` then restored locally. The private key is written to a
//!   0600 file for the run and deleted afterwards.
//!
//! In both cases the freshly-created hosting's wp-config.php (if any) is
//! repointed at the new DB credentials.

use crate::service::{AdapterPort, HostingService};
use hyperion_import::{
    Action, ImportPanelReq, ImportPanelResult, ImportPlan, ImportPlanner, ImportedHosting,
    IrDbEngine, IrHosting, IrSiteKind, Location, SkippedHosting, SshTarget,
};
use hyperion_rpc::wire::HostingCreateReq;
use hyperion_rpc::RpcError;
use hyperion_validate::Domain;
use std::path::{Path, PathBuf};

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Dry-run: detect + extract the source panel and classify every site as
    /// Create / Skip / Conflict / Unsupported. Side-effect-free.
    pub async fn import_panel_plan(&self, req: ImportPanelReq) -> Result<ImportPlan, RpcError> {
        let (loc, key_file) = build_location(&req).await?;
        let out = self.plan_at(&req, &loc).await;
        cleanup_key(key_file).await;
        out
    }

    /// Apply the plan: provision + populate every `Create` site, skip the rest.
    /// Per-site failures are recorded and the batch continues.
    pub async fn import_panel_apply(
        &self,
        req: ImportPanelReq,
    ) -> Result<ImportPanelResult, RpcError> {
        let (loc, key_file) = build_location(&req).await?;
        let out = self.apply_at(&req, &loc).await;
        cleanup_key(key_file).await;
        out
    }

    /// Plan against an already-resolved location (in-place or remote/ssh).
    async fn plan_at(&self, req: &ImportPanelReq, loc: &Location) -> Result<ImportPlan, RpcError> {
        let adapter =
            hyperion_import::adapter_for(&req.source_kind).ok_or_else(|| RpcError::Validation {
                message: format!("unknown source panel: {}", req.source_kind),
            })?;
        if adapter.detect(loc).await.is_none() {
            return Err(RpcError::Validation {
                message: format!(
                    "no {} install detected ({} mode)",
                    req.source_kind, req.mode
                ),
            });
        }
        let ir = adapter
            .extract(loc)
            .await
            .map_err(|e| RpcError::Validation {
                message: format!("extract failed: {e}"),
            })?;
        let existing: Vec<String> = self.list().await?.into_iter().map(|s| s.domain).collect();
        Ok(ImportPlanner::plan(ir, &existing, &[]))
    }

    /// Apply against an already-resolved location.
    async fn apply_at(
        &self,
        req: &ImportPanelReq,
        loc: &Location,
    ) -> Result<ImportPanelResult, RpcError> {
        let plan = self.plan_at(req, loc).await?;
        let mut created = Vec::new();
        let mut skipped = Vec::new();
        for item in &plan.items {
            match item.action {
                Action::Create => match self.apply_one_import(&item.hosting, loc).await {
                    Ok(id) => created.push(ImportedHosting {
                        domain: item.domain.clone(),
                        hosting_id: id,
                        databases: item.hosting.databases.len(),
                    }),
                    Err(e) => skipped.push(SkippedHosting {
                        domain: item.domain.clone(),
                        reason: format!("failed: {e}"),
                    }),
                },
                _ => skipped.push(SkippedHosting {
                    domain: item.domain.clone(),
                    reason: item.reason.clone(),
                }),
            }
        }
        let message = format!(
            "imported {} site(s), skipped {}",
            created.len(),
            skipped.len()
        );
        Ok(ImportPanelResult {
            created,
            skipped,
            unsupported: plan.unsupported,
            message,
        })
    }

    /// Provision one hosting and pull its files + DB across (local or remote).
    async fn apply_one_import(&self, h: &IrHosting, loc: &Location) -> Result<String, RpcError> {
        // 1. Provision a fresh Hyperion hosting — reuses ALL of create()
        //    (system user, dirs, nginx vhost, php-fpm pool, DB if any).
        let domain = Domain::parse(&h.domain).map_err(|e| RpcError::Validation {
            message: format!("domain: {e}"),
        })?;
        let php_version = h.php_version.as_deref().and_then(|v| v.parse().ok());
        let database = h.databases.first().map(|d| match d.engine {
            IrDbEngine::Postgres => hyperion_types::DbProvision::Postgres,
            _ => hyperion_types::DbProvision::MariaDB,
        });
        let kind = match h.kind {
            IrSiteKind::Static => "static",
            _ => "php",
        };
        let created = self
            .create(HostingCreateReq {
                domain,
                aliases: Vec::new(),
                php_version,
                database,
                system_user: None,
                kind: kind.to_string(),
                proxy_upstream_url: None,
            })
            .await?;

        // 2. Copy the source docroot into the new hosting's docroot
        //    (created.root_dir == <host_root>/htdocs). First drop the default
        //    landing index.html create() planted, so it doesn't shadow the
        //    imported site's own index.php/index.html (nginx prefers .html).
        let _ = tokio::fs::remove_file(Path::new(&created.root_dir).join("index.html")).await;
        fetch_files(loc, &h.docroot, &created.root_dir)
            .await
            .map_err(|reason| RpcError::ProvisioningFailed {
                stage: "import_copy_files".into(),
                reason,
            })?;

        // 3. Fix ownership: the copy ran as root, so chown the whole hosting
        //    tree to the new system user and make ancestors traversable
        //    (otherwise nginx/php-fpm 403/404 — the restore-archive-no-chown
        //    + debian-useradd-home-0700 gotchas).
        let host_root = Path::new(&created.root_dir)
            .parent()
            .unwrap_or_else(|| Path::new(&created.root_dir));
        run_cmd(
            "chown",
            &[
                "-R",
                &format!("{u}:{u}", u = created.system_user),
                &host_root.display().to_string(),
            ],
        )
        .await
        .map_err(|reason| RpcError::ProvisioningFailed {
            stage: "import_chown".into(),
            reason,
        })?;
        let _ = crate::ensure_ancestors_traversable(Path::new(&created.root_dir)).await;

        // 4. DB: dump the source DB (locally or over ssh) and load it into the
        //    freshly-created one with the engine-appropriate restore helper.
        if let (Some(srcdb), Some(newdb)) = (h.databases.first(), created.db.as_ref()) {
            let dump = format!(
                "/var/lib/hyperion/migration/import-{}.sql",
                created.id.as_str()
            );
            if let Some(parent) = Path::new(&dump).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            let dump_path = Path::new(&dump);
            fetch_db(loc, srcdb, dump_path).await.map_err(|reason| {
                RpcError::ProvisioningFailed {
                    stage: "import_db_dump".into(),
                    reason,
                }
            })?;
            match srcdb.engine {
                IrDbEngine::Postgres => {
                    hyperion_adapters::backup::restore_postgres_dump(&newdb.db_name, dump_path)
                        .await
                        .map_err(|e| RpcError::ProvisioningFailed {
                            stage: "import_db_restore".into(),
                            reason: e.to_string(),
                        })?;
                }
                _ => {
                    hyperion_adapters::backup::restore_mariadb_dump(&newdb.db_name, dump_path)
                        .await
                        .map_err(|e| RpcError::ProvisioningFailed {
                            stage: "import_db_restore".into(),
                            reason: e.to_string(),
                        })?;
                }
            }
            let _ = tokio::fs::remove_file(&dump).await;

            // 5. Repoint wp-config.php (if present) at the new DB credentials.
            rewrite_wp_config(
                &created.root_dir,
                &newdb.db_name,
                &newdb.db_user,
                &newdb.password,
            )
            .await;
        }

        // 6. Record the source key so a re-run reports this site as already
        //    imported instead of recreating it.
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            created.id.as_str(),
            "import_source_key",
            &h.source_key,
            now_secs(),
        )
        .await;

        Ok(created.id.as_str().to_string())
    }
}

/// Resolve the request into a [`Location`]. For `remote`, writes the supplied
/// private key to a 0600 file (returned so the caller deletes it after the run).
async fn build_location(req: &ImportPanelReq) -> Result<(Location, Option<PathBuf>), RpcError> {
    match req.mode.as_str() {
        "inplace" => Ok((Location::InPlace, None)),
        "remote" => {
            let ssh = req.ssh.as_ref().ok_or_else(|| RpcError::Validation {
                message: "remote mode requires ssh connection details".into(),
            })?;
            if ssh.host.trim().is_empty() || ssh.key.trim().is_empty() {
                return Err(RpcError::Validation {
                    message: "remote mode requires ssh host and private key".into(),
                });
            }
            let dir = "/var/lib/hyperion/migration";
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|e| RpcError::ProvisioningFailed {
                    stage: "import_ssh_keydir".into(),
                    reason: e.to_string(),
                })?;
            let path = PathBuf::from(format!("{dir}/import-key-{}", unique_token()));
            let mut key = ssh.key.clone();
            if !key.ends_with('\n') {
                key.push('\n'); // OpenSSH refuses keys without a trailing newline
            }
            tokio::fs::write(&path, key.as_bytes()).await.map_err(|e| {
                RpcError::ProvisioningFailed {
                    stage: "import_ssh_key".into(),
                    reason: e.to_string(),
                }
            })?;
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await;
            let port = if ssh.port == 0 { 22 } else { ssh.port };
            let user = if ssh.user.trim().is_empty() {
                "root".to_string()
            } else {
                ssh.user.clone()
            };
            let target = SshTarget {
                host: ssh.host.clone(),
                user,
                key_path: path.clone(),
                port,
            };
            Ok((Location::Remote(target), Some(path)))
        }
        other => Err(RpcError::Validation {
            message: format!("unsupported import mode '{other}' (inplace | remote)"),
        }),
    }
}

async fn cleanup_key(key_file: Option<PathBuf>) {
    if let Some(p) = key_file {
        let _ = tokio::fs::remove_file(p).await;
    }
}

/// Copy the source docroot's contents into `dest` — local `cp -a` for in-place,
/// `rsync -e ssh` for remote.
async fn fetch_files(loc: &Location, src_docroot: &str, dest: &str) -> Result<(), String> {
    match loc {
        Location::Remote(t) => {
            let ssh = format!("ssh {}", t.ssh_opts().join(" "));
            let src = format!("{}@{}:{}/", t.user, t.host, src_docroot);
            run_cmd(
                "rsync",
                &["-a", "--numeric-ids", "-e", &ssh, &src, &format!("{dest}/")],
            )
            .await
        }
        _ => {
            // In-place: only copy if the source dir actually exists.
            if Path::new(src_docroot).is_dir() {
                run_cmd("cp", &["-a", &format!("{src_docroot}/."), dest]).await
            } else {
                Ok(())
            }
        }
    }
}

/// Dump the source DB to `dump_path` — local backup helper for in-place, or
/// `ssh mysqldump`/`pg_dump` for remote (output captured to the file).
async fn fetch_db(
    loc: &Location,
    srcdb: &hyperion_import::IrDatabase,
    dump_path: &Path,
) -> Result<(), String> {
    match loc {
        Location::Remote(t) => {
            let q = hyperion_import::adapter::shell_quote(&srcdb.name);
            let remote_cmd = match srcdb.engine {
                IrDbEngine::Postgres => format!("sudo -u postgres pg_dump -Fc -- {q}"),
                _ => {
                    format!("mysqldump --single-transaction --routines --triggers --events -- {q}")
                }
            };
            let mut cmd = tokio::process::Command::new("ssh");
            cmd.args(t.ssh_opts())
                .arg(format!("{}@{}", t.user, t.host))
                .arg(&remote_cmd);
            let out = cmd.output().await.map_err(|e| format!("ssh: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "remote dump failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            tokio::fs::write(dump_path, &out.stdout)
                .await
                .map_err(|e| format!("write dump: {e}"))
        }
        _ => match srcdb.engine {
            IrDbEngine::Postgres => {
                hyperion_adapters::backup::dump_postgres(&srcdb.name, dump_path)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }
            _ => hyperion_adapters::backup::dump_mariadb(&srcdb.name, dump_path)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
        },
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A process-unique token for the ephemeral key filename (pid + nanos).
fn unique_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), nanos)
}

/// Run a command, mapping a non-zero exit to a readable error string.
async fn run_cmd(bin: &str, args: &[&str]) -> Result<(), String> {
    let out = tokio::process::Command::new(bin)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("{bin}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{bin} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Best-effort rewrite of wp-config.php DB constants to the new credentials.
/// No-op if the file is absent (non-WordPress site).
async fn rewrite_wp_config(root_dir: &str, db_name: &str, db_user: &str, db_pass: &str) {
    let path = Path::new(root_dir).join("wp-config.php");
    let Ok(content) = tokio::fs::read_to_string(&path).await else {
        return;
    };
    let esc = |v: &str| v.replace('\\', "\\\\").replace('\'', "\\'");
    let rewritten: Vec<String> = content
        .lines()
        .map(|line| {
            for (key, val) in [
                ("DB_NAME", db_name),
                ("DB_USER", db_user),
                ("DB_PASSWORD", db_pass),
            ] {
                let is_def = line.contains("define")
                    && (line.contains(&format!("'{key}'")) || line.contains(&format!("\"{key}\"")));
                if is_def {
                    return format!("define( '{key}', '{}' );", esc(val));
                }
            }
            line.to_string()
        })
        .collect();
    let _ = tokio::fs::write(&path, rewritten.join("\n")).await;
}
