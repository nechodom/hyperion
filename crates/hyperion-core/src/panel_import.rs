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

/// hosting_kv key under which each imported hosting records the source panel's
/// site key, so a re-run can detect "already imported" (idempotency).
const IMPORT_SOURCE_KEY_KV: &str = "import_source_key";

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
        // For remote mode, prove SSH connectivity FIRST. The detect() path
        // collapses EVERY ssh failure (auth, connection refused, timeout,
        // permission denied) to `None` (hyperion-import Runner::exists does
        // `.unwrap_or(false)`), which then surfaces as a misleading "no X
        // install detected". Probing here lets us report the real ssh error.
        if let Location::Remote(t) = loc {
            ssh_preflight(t).await.map_err(|msg| RpcError::Validation {
                message: format!("SSH to {}@{}:{} failed — {}", t.user, t.host, t.port, msg),
            })?;
        }
        if adapter.detect(loc).await.is_none() {
            return Err(RpcError::Validation {
                message: match loc {
                    // SSH already proven above, so reaching here means we got
                    // in but the panel's files weren't found/readable.
                    Location::Remote(t) => format!(
                        "connected to {host} over SSH, but no {kind} install was found there. \
                         Make sure {kind} is installed on {host} and that the SSH user '{user}' \
                         can read its data files (use root, or a user with sudo/read access).",
                        host = t.host,
                        kind = req.source_kind,
                        user = t.user
                    ),
                    _ => format!(
                        "no {} install detected on this node (in-place mode)",
                        req.source_kind
                    ),
                },
            });
        }
        let ir = adapter
            .extract(loc)
            .await
            .map_err(|e| RpcError::Validation {
                message: format!("extract failed: {e}"),
            })?;
        let existing: Vec<String> = self.list().await?.into_iter().map(|s| s.domain).collect();
        // `already_imported` are the source_keys recorded on prior imports (step 6
        // of apply_one_import). Wiring them makes a re-run idempotent: a site
        // that was already imported — including one RENAMED to a different target
        // domain (whose source domain no longer appears in `existing`) — is
        // classified Skip instead of being created again.
        let already_imported: Vec<String> =
            hyperion_state::hosting_kv::list_by_key(&self.pool, IMPORT_SOURCE_KEY_KV)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|(_hosting_id, source_key)| source_key)
                .collect();
        Ok(ImportPlanner::plan(ir, &existing, &already_imported))
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
            // Operator override for this site (keyed by source domain), if any.
            let ov = req
                .site_overrides
                .iter()
                .find(|o| o.source_domain == item.hosting.domain);
            // The domain the site actually lands under (target override or source).
            let final_domain = ov
                .and_then(|o| o.target_domain.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(item.domain.as_str())
                .to_string();
            match item.action {
                Action::Create => match self.apply_one_import(&item.hosting, loc, ov).await {
                    Ok(id) => created.push(ImportedHosting {
                        domain: final_domain,
                        hosting_id: id,
                        databases: item.hosting.databases.len(),
                    }),
                    Err(e) => skipped.push(SkippedHosting {
                        domain: final_domain,
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
    async fn apply_one_import(
        &self,
        h: &IrHosting,
        loc: &Location,
        ov: Option<&hyperion_import::SiteImportOverride>,
    ) -> Result<String, RpcError> {
        // 1. Provision a fresh Hyperion hosting — reuses ALL of create()
        //    (system user, dirs, nginx vhost, php-fpm pool, DB if any).
        //    The operator may RENAME the site at import: create under the chosen
        //    target domain, but keep locating the SOURCE files/DB in the bundle
        //    by `h.domain`.
        let target = ov
            .and_then(|o| o.target_domain.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(h.domain.as_str())
            .to_string();
        let domain = Domain::parse(&target).map_err(|e| RpcError::Validation {
            message: format!("target domain '{target}': {e}"),
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
        fetch_files(loc, &h.domain, &h.docroot, &created.root_dir)
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
            fetch_db(loc, &h.domain, srcdb, dump_path)
                .await
                .map_err(|reason| RpcError::ProvisioningFailed {
                    stage: "import_db_dump".into(),
                    reason,
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

        // 5b. Operator per-site overrides (interactive wizard):
        //   - rename: rewrite WordPress URLs from the source domain to the new
        //     one (best-effort; no-op on non-WP) so the site isn't full of links
        //     back to the old host;
        //   - profile: apply limits/quota + price + billing clock;
        //   - billing date: override the profile's first-billing timestamp.
        //
        // NOTE (multi-node): profiles + billing live in the master-only
        // `hosting_profile_apply`/`hosting_profiles` tables, and the self-service
        // wizard always lands the bundle on the master (mint sets
        // target_node="local"), so `profile_apply(..., None)` resolves the
        // profile locally here. If a future flow imports straight onto a WORKER,
        // the resolved `HostingProfile` must be passed inline (the 4th arg) —
        // a bare profile_id can't be looked up off-master. We surface a failure
        // loudly rather than silently dropping the operator's choice.
        if let Some(o) = ov {
            if target != h.domain {
                self.wp_rewrite_domain(&created.system_user, &created.root_dir, &h.domain, &target)
                    .await;
            }
            if let Some(pid) = o.profile_id {
                if let Err(e) = self
                    .profile_apply(
                        hyperion_rpc::wire::HostingSelector::Id(created.id.clone()),
                        pid,
                        false,
                        None,
                    )
                    .await
                {
                    tracing::warn!(
                        hosting = %created.id.as_str(), profile = pid, error = %e,
                        "import: profile apply failed — site imported WITHOUT the chosen \
                         profile or billing date (profile not resolvable on this node?)"
                    );
                } else if let Some(nb) = o.next_billing_at {
                    let _ = hyperion_state::profiles::set_next_billing(
                        &self.pool,
                        &created.id,
                        Some(nb),
                    )
                    .await;
                }
            }
        }

        // 6. Record the source key so a re-run reports this site as already
        //    imported instead of recreating it.
        let _ = hyperion_state::hosting_kv::set(
            &self.pool,
            created.id.as_str(),
            IMPORT_SOURCE_KEY_KV,
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
            // Pasted keys routinely arrive with CRLF line endings, trailing
            // spaces, or surrounding blank lines (browser textareas, Windows
            // clipboards) — any of which makes OpenSSH reject the key with
            // "error in libcrypto". Normalise before writing so the operator
            // doesn't have to hand-sanitise the key.
            let key = normalize_private_key(&ssh.key);
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
        "archive" => {
            // An export bundle already staged on this node (uploaded via the UI).
            // Unpack it to a temp dir; the adapters read the manifest + the
            // per-site docroot/DB from there. No source access needed.
            let src = req
                .archive_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| RpcError::Validation {
                    message: "archive mode requires an uploaded bundle".into(),
                })?;
            if !Path::new(src).exists() {
                return Err(RpcError::Validation {
                    message: format!("bundle not found on node: {src}"),
                });
            }
            let dir = PathBuf::from(format!(
                "/var/lib/hyperion/migration/bundle-{}",
                unique_token()
            ));
            tokio::fs::create_dir_all(&dir)
                .await
                .map_err(|e| RpcError::ProvisioningFailed {
                    stage: "import_bundle_dir".into(),
                    reason: e.to_string(),
                })?;
            let out = tokio::process::Command::new("tar")
                .arg("xf")
                .arg(src)
                .arg("-C")
                .arg(&dir)
                .output()
                .await
                .map_err(|e| RpcError::ProvisioningFailed {
                    stage: "import_bundle_unpack".into(),
                    reason: e.to_string(),
                })?;
            if !out.status.success() {
                let _ = tokio::fs::remove_dir_all(&dir).await;
                return Err(RpcError::Validation {
                    message: format!(
                        "could not unpack bundle: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                });
            }
            Ok((Location::Archive(dir.clone()), Some(dir)))
        }
        other => Err(RpcError::Validation {
            message: format!("unsupported import mode '{other}' (inplace | remote | archive)"),
        }),
    }
}

/// Remove the per-run ephemeral artifact: the 0600 ssh key file (remote mode)
/// or the unpacked bundle temp dir (archive mode).
async fn cleanup_key(artifact: Option<PathBuf>) {
    if let Some(p) = artifact {
        if p.is_dir() {
            let _ = tokio::fs::remove_dir_all(&p).await;
        } else {
            let _ = tokio::fs::remove_file(&p).await;
        }
    }
}

/// Copy the source docroot's contents into `dest` — local `cp -a` for in-place,
/// `rsync -e ssh` for remote.
async fn fetch_files(
    loc: &Location,
    domain: &str,
    src_docroot: &str,
    dest: &str,
) -> Result<(), String> {
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
        Location::Archive(dir) => {
            // Unpack this site's bundled docroot tarball (absent = empty site).
            let tgz = dir
                .join("sites")
                .join(hyperion_import::bundle::site_dir(domain))
                .join("docroot.tar.gz");
            if tgz.is_file() {
                run_cmd("tar", &["xzf", &tgz.display().to_string(), "-C", dest]).await
            } else {
                Ok(())
            }
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
    domain: &str,
    srcdb: &hyperion_import::IrDatabase,
    dump_path: &Path,
) -> Result<(), String> {
    match loc {
        Location::Archive(dir) => {
            let f = dir
                .join("sites")
                .join(hyperion_import::bundle::site_dir(domain))
                .join("db")
                .join(format!("{}.dump", srcdb.name));
            if f.is_file() {
                tokio::fs::copy(&f, dump_path)
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("copy bundle dump: {e}"))
            } else {
                Err(format!(
                    "database dump '{}' missing from bundle",
                    srcdb.name
                ))
            }
        }
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

/// Normalise a pasted private key: strip CR (CRLF→LF), trim trailing
/// whitespace per line, drop surrounding blank lines, and guarantee exactly
/// one trailing newline. OpenSSH/libcrypto rejects keys with stray `\r` or
/// leading/trailing junk ("error in libcrypto"); base64 bodies and PEM/OpenSSH
/// header lines never carry significant edge whitespace, so this is lossless
/// for a valid key but rescues one mangled by a browser textarea / clipboard.
fn normalize_private_key(raw: &str) -> String {
    let body = raw
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .lines()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n");
    format!("{}\n", body.trim())
}

/// Prove we can SSH in and run a trivial command, capturing the REAL ssh error
/// (auth failure, connection refused, timeout, host-key/key-format problem)
/// instead of letting it collapse into a generic "not detected". Returns Ok on
/// a clean remote exit, Err(<cleaned ssh stderr>) otherwise.
async fn ssh_preflight(t: &SshTarget) -> Result<(), String> {
    let out = tokio::process::Command::new("ssh")
        .args(t.ssh_opts())
        .arg(format!("{}@{}", t.user, t.host))
        .arg("echo hyperion-ssh-ok")
        .output()
        .await
        .map_err(|e| format!("could not run ssh: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    // Drop benign host-key acceptance noise ("Warning: Permanently added …")
    // and blank lines so the real cause stands out.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut msg = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains("Permanently added"))
        .collect::<Vec<_>>()
        .join("; ");
    if msg.is_empty() {
        msg = format!("ssh exited with status {}", out.status);
    }
    // A key that won't parse is almost always passphrase-protected or in a
    // non-OpenSSH format — point the operator at the fix.
    if msg.contains("error in libcrypto") || msg.contains("Load key") {
        msg.push_str(
            " — the private key couldn't be loaded; it must be an UNENCRYPTED \
             OpenSSH/PEM key (passphrase-protected or PuTTY .ppk keys won't work)",
        );
    }
    Err(msg)
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
