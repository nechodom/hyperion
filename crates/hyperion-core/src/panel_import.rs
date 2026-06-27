//! Panel-import engine: the node-side plan + apply that turns a source panel's
//! IR (from the `hyperion-import` crate) into real Hyperion hostings by reusing
//! `HostingService::create()` + the adapter DB-restore helper. This is the only
//! place that bridges the two worlds (adapters/IR ↔ core provisioning).
//!
//! P0: CloudPanel, in-place. Files are copied locally into the freshly-created
//! hosting docroot, the DB is dumped + reloaded, ownership is fixed, and any
//! wp-config.php is repointed at the new DB credentials.

use crate::service::{AdapterPort, HostingService};
use hyperion_import::{
    Action, ImportPanelReq, ImportPanelResult, ImportPlan, ImportPlanner, ImportedHosting,
    IrDbEngine, IrHosting, IrSiteKind, SkippedHosting,
};
use hyperion_rpc::wire::HostingCreateReq;
use hyperion_rpc::RpcError;
use hyperion_validate::Domain;
use std::path::Path;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Dry-run: detect + extract the source panel and classify every site as
    /// Create / Skip / Conflict / Unsupported. Side-effect-free.
    pub async fn import_panel_plan(&self, req: ImportPanelReq) -> Result<ImportPlan, RpcError> {
        let adapter =
            hyperion_import::adapter_for(&req.source_kind).ok_or_else(|| RpcError::Validation {
                message: format!("unknown source panel: {}", req.source_kind),
            })?;
        let loc = hyperion_import::location_for(&req.mode).ok_or_else(|| RpcError::Validation {
            message: format!("unsupported import mode '{}' (P0 supports inplace)", req.mode),
        })?;
        if adapter.detect(&loc).await.is_none() {
            return Err(RpcError::Validation {
                message: format!("no {} install detected ({} mode)", req.source_kind, req.mode),
            });
        }
        let ir = adapter
            .extract(&loc)
            .await
            .map_err(|e| RpcError::Validation { message: format!("extract failed: {e}") })?;
        let existing: Vec<String> = self.list().await?.into_iter().map(|s| s.domain).collect();
        Ok(ImportPlanner::plan(ir, &existing, &[]))
    }

    /// Apply the plan: provision + populate every `Create` site, skip the rest.
    /// Per-site failures are recorded and the batch continues.
    pub async fn import_panel_apply(
        &self,
        req: ImportPanelReq,
    ) -> Result<ImportPanelResult, RpcError> {
        let plan = self.import_panel_plan(req).await?;
        let mut created = Vec::new();
        let mut skipped = Vec::new();
        for item in &plan.items {
            match item.action {
                Action::Create => match self.apply_one_import(&item.hosting).await {
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
        let message = format!("imported {} site(s), skipped {}", created.len(), skipped.len());
        Ok(ImportPanelResult { created, skipped, unsupported: plan.unsupported, message })
    }

    /// Provision one hosting and pull its files + DB across (in-place/local).
    async fn apply_one_import(&self, h: &IrHosting) -> Result<String, RpcError> {
        // 1. Provision a fresh Hyperion hosting — reuses ALL of create()
        //    (system user, dirs, nginx vhost, php-fpm pool, DB if any).
        let domain = Domain::parse(&h.domain)
            .map_err(|e| RpcError::Validation { message: format!("domain: {e}") })?;
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
        //    (created.root_dir == <host_root>/htdocs).
        if Path::new(&h.docroot).is_dir() {
            run_cmd("cp", &["-a", &format!("{}/.", h.docroot), &created.root_dir])
                .await
                .map_err(|reason| RpcError::ProvisioningFailed {
                    stage: "import_copy_files".into(),
                    reason,
                })?;
        }

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
        .map_err(|reason| RpcError::ProvisioningFailed { stage: "import_chown".into(), reason })?;
        let _ = crate::ensure_ancestors_traversable(Path::new(&created.root_dir)).await;

        // 4. DB: dump the source DB and load it into the freshly-created one
        //    (in-place: same MariaDB instance, root socket auth).
        if let (Some(srcdb), Some(newdb)) = (h.databases.first(), created.db.as_ref()) {
            let dump = format!("/var/lib/hyperion/migration/import-{}.sql", created.id.as_str());
            if let Some(parent) = Path::new(&dump).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            dump_mariadb(&srcdb.name, &dump).await.map_err(|reason| {
                RpcError::ProvisioningFailed { stage: "import_db_dump".into(), reason }
            })?;
            hyperion_adapters::backup::restore_mariadb_dump(&newdb.db_name, Path::new(&dump))
                .await
                .map_err(|e| RpcError::ProvisioningFailed {
                    stage: "import_db_restore".into(),
                    reason: e.to_string(),
                })?;
            let _ = tokio::fs::remove_file(&dump).await;

            // 5. Repoint wp-config.php (if present) at the new DB credentials.
            rewrite_wp_config(&created.root_dir, &newdb.db_name, &newdb.db_user, &newdb.password)
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

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Run a command, mapping a non-zero exit to a readable error string.
async fn run_cmd(bin: &str, args: &[&str]) -> Result<(), String> {
    let out = tokio::process::Command::new(bin)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("{bin}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{bin} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// `mysqldump` a database to `out` via the local root socket (in-place).
async fn dump_mariadb(db: &str, out: &str) -> Result<(), String> {
    let f = std::fs::File::create(out).map_err(|e| format!("create dump file: {e}"))?;
    let status = tokio::process::Command::new("mysqldump")
        .args([
            "--single-transaction",
            "--no-tablespaces",
            "--default-character-set=utf8mb4",
            "--",
            db,
        ])
        .stdout(std::process::Stdio::from(f))
        .status()
        .await
        .map_err(|e| format!("mysqldump spawn: {e}"))?;
    if !status.success() {
        return Err(format!("mysqldump exited {status}"));
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
            for (key, val) in
                [("DB_NAME", db_name), ("DB_USER", db_user), ("DB_PASSWORD", db_pass)]
            {
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
