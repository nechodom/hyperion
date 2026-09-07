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
        let (loc, key_file) = build_location(&req, &self.paths.home_root).await?;
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
        let (loc, key_file) = build_location(&req, &self.paths.home_root).await?;
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
        // Set once the disk fills. Every remaining site is then recorded as not
        // attempted instead of being created: past this point create() still
        // succeeds (a hosting row, a user, a few KB of config) while the docroot
        // it exists for cannot be written, so carrying on manufactures empty
        // sites that look imported. One clear stop leaves the operator with a
        // list of what to re-run after freeing space.
        let mut out_of_space: Option<String> = None;
        for item in &plan.items {
            if let Some(why) = &out_of_space {
                skipped.push(SkippedHosting {
                    domain: item.domain.clone(),
                    reason: format!("not attempted — the disk filled up earlier: {why}"),
                });
                continue;
            }
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
                    Ok((id, notes)) => created.push(ImportedHosting {
                        domain: final_domain,
                        hosting_id: id,
                        databases: item.hosting.databases.len(),
                        notes,
                    }),
                    Err(e) => {
                        let reason = e.to_string();
                        if looks_like_out_of_space(&reason) {
                            out_of_space = Some(reason.clone());
                        }
                        skipped.push(SkippedHosting {
                            domain: final_domain,
                            reason: format!("failed: {reason}"),
                        });
                    }
                },
                _ => skipped.push(SkippedHosting {
                    domain: item.domain.clone(),
                    reason: item.reason.clone(),
                }),
            }
        }
        let message = if out_of_space.is_some() {
            format!(
                "ran out of disk: imported {} site(s), then stopped with {} not imported. \
                 Free up space and re-run the import — the sites already imported are \
                 detected and skipped.",
                created.len(),
                skipped.len()
            )
        } else {
            format!(
                "imported {} site(s), skipped {}",
                created.len(),
                skipped.len()
            )
        };
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
    ) -> Result<(String, Vec<String>), RpcError> {
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
        // NOT `.parse().ok()`. PhpVersion's FromStr is an exact allow-list of
        // 8.1-8.4, so a CloudPanel site on 7.4, 8.0, or reported as "8.2.10"
        // parsed to Err and `.ok()` silently turned it into None — creating a
        // kind="php" hosting with NO version, which answers "requires a PHP
        // hosting" to every WordPress action while the import reports
        // success. Substitute the nearest supported version and SAY SO.
        let mut notes: Vec<String> = Vec::new();
        // An explicit choice from the wizard wins over anything derived: the
        // operator is the one who knows whether this site's code survives the
        // version it is being moved to. The note still names what the SOURCE
        // was running, because that is the fact the operator needs later when
        // something behaves differently.
        let source_php = h
            .php_version
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty());
        let chosen = ov
            .and_then(|o| o.php_version.as_deref())
            .map(str::trim)
            .filter(|v| !v.is_empty());
        let php_version = match chosen.or(source_php) {
            Some(raw) => match hyperion_types::PhpVersion::nearest_supported(raw) {
                Some((v, substituted)) => {
                    match (chosen.is_some(), source_php) {
                        // The operator picked, and it is not what the source
                        // ran. Worth recording either way.
                        (true, Some(src))
                            if hyperion_types::PhpVersion::nearest_supported(src)
                                .map(|(sv, _)| sv)
                                != Some(v) =>
                        {
                            notes.push(format!("source ran PHP {src}, imported on {v} as chosen"));
                        }
                        (true, _) => {}
                        // Derived, and Hyperion does not carry what the source
                        // reported — 7.4 and 8.0 are exactly what people
                        // migrate off.
                        (false, _) if substituted => {
                            notes.push(format!(
                                "was on PHP {raw}, imported on {v} — Hyperion does not carry \
                                 {raw}; check the site still runs"
                            ));
                        }
                        _ => {}
                    }
                    Some(v)
                }
                None => None,
            },
            None => None,
        };
        // A php site with no version is a half-built hosting: create() writes
        // the row and skips the FPM pool, and nothing ever repairs it. Give it
        // the lowest supported version rather than that.
        let php_version = match (h.kind, php_version) {
            (IrSiteKind::Static, v) => v,
            (_, None) => {
                notes.push(
                    "the source reported no PHP version — imported on 8.1, change it on the \
                     hosting if the site needs another"
                        .into(),
                );
                Some(hyperion_types::PhpVersion::V8_1)
            }
            (_, some) => some,
        };
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
        // Ownership alone is NOT enough: cp -a and the sandboxed tar both
        // PRESERVE the source panel's modes, and CloudPanel ships trees at
        // 0770/0660 because its nginx runs inside the site user's group.
        // Ours does not, so an imported site with correct ownership still
        // 404s every asset. Normalise modes the same way the panel's
        // Repair action does (dirs 0755, files 0644, ancestors traversable).
        if let Err(reason) =
            crate::service::repair_tree_permissions_for_import(&created.system_user, host_root)
                .await
        {
            return Err(RpcError::ProvisioningFailed {
                stage: "import_permissions".into(),
                reason,
            });
        }

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

        Ok((created.id.as_str().to_string(), notes))
    }
}

/// Resolve the request into a [`Location`]. For `remote`, writes the supplied
/// private key to a 0600 file (returned so the caller deletes it after the run).
async fn build_location(
    req: &ImportPanelReq,
    home_root: &str,
) -> Result<(Location, Option<PathBuf>), RpcError> {
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
            // Before anything is unpacked: will the unpack, and the import it
            // feeds, actually fit? The `/import/upload/begin` preflight covers
            // the same ground, but a bundle can reach a node by other routes
            // (an operator-supplied archive, a re-run against a disk that has
            // filled since), and running out here is the expensive failure —
            // it lands mid-loop with some sites created and populated, some
            // created empty, and the bundle already deleted by the job's own
            // cleanup.
            bundle_fits_or_refuse(Path::new(src), home_root).await?;

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
            // The staging dir holds plaintext DB dumps + wp-config secrets from
            // the (untrusted-content) bundle — lock it down to 0700 so other
            // local users can't read it during the unpack window.
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await;
            }
            // SECURITY: the outer bundle is attacker-controlled content (the
            // source box is untrusted, and `/import/ingest/:token` accepts an
            // arbitrary body). A bare `tar xf` running as root would honour `..`
            // members and write-through planted symlinks → root file write / RCE
            // (sec-findings #8/#9). Use the audited in-process sandbox instead.
            let src_path = PathBuf::from(src);
            let dir_clone = dir.clone();
            let unpacked = tokio::task::spawn_blocking(move || {
                hyperion_adapters::backup::extract_tar_sandboxed(&src_path, &dir_clone)
            })
            .await
            .map_err(|e| RpcError::ProvisioningFailed {
                stage: "import_bundle_unpack".into(),
                reason: format!("unpack task join: {e}"),
            })?;
            if let Err(e) = unpacked {
                let _ = tokio::fs::remove_dir_all(&dir).await;
                return Err(RpcError::Validation {
                    message: format!("could not unpack bundle: {e}"),
                });
            }
            Ok((Location::Archive(dir.clone()), Some(dir)))
        }
        other => Err(RpcError::Validation {
            message: format!("unsupported import mode '{other}' (inplace | remote | archive)"),
        }),
    }
}

/// Does this failure mean the filesystem is full?
///
/// Matched on the message rather than a typed error because the ENOSPC crosses
/// three crate boundaries on its way here — `std::io::Error` inside the tar
/// sandbox, into `AdapterError`, into a `String` reason on `RpcError` — and
/// every one of those is a `Display` conversion. The forms below are what
/// `std::io::Error` prints for `errno 28` on Linux, plus the wording
/// `cp`/`rsync`/`tar` use when the failure comes from a subprocess instead.
///
/// A false negative just restores today's behaviour (keep going); a false
/// positive stops a batch early with an accurate list of what was not
/// attempted. Neither loses data.
fn looks_like_out_of_space(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("no space left on device")
        || m.contains("os error 28")
        || m.contains("write error: no space")
        || m.contains("disk quota exceeded")
}

/// Refuse an import whose unpack + inflate cannot fit on this node's disk.
///
/// Three costs, only one of which was ever checked:
///   1. the `bundle.tar` itself — already on disk here, so `df` has already
///      stopped counting it as free;
///   2. the staging tree it is unpacked into, the same size again, under
///      `/var/lib/hyperion/migration`;
///   3. every site's `docroot.tar.gz` inflated into its real hosting tree under
///      `home_root`, plus the copy the restore makes of each database dump.
///      Compressed site files routinely double or triple on the way out, so
///      this is the largest of the three and was invisible to a check that
///      weighed the bundle alone.
///
/// (2) and (3) land on the same filesystem on a default install and on separate
/// ones where `/home` has its own volume, so the device ids decide: one summed
/// check when they match, two independent ones when they do not. Summing across
/// two filesystems would refuse imports that fit; checking a shared filesystem
/// twice in halves would pass an import that does not.
///
/// Note (2) is counted ONCE, not twice: the bundle is already written when this
/// runs, so demanding its bytes a second time would refuse imports that fit.
/// The `/import/upload/begin` check counts two copies because there the bundle
/// has not landed yet.
///
/// Fail-open throughout, per the export preflight's rule: no `df`, no readable
/// manifest, or a manifest from an exporter that recorded no sizes all mean
/// there is no figure — and a guess must never be the reason a legitimate
/// import is refused.
async fn bundle_fits_or_refuse(bundle: &Path, home_root: &str) -> Result<(), RpcError> {
    let Some(bundle_len) = tokio::fs::metadata(bundle).await.ok().map(|m| m.len()) else {
        return Ok(());
    };
    let stage = bundle.parent().unwrap_or(Path::new("/"));
    let homes = Path::new(home_root);

    // Read the manifest straight out of the tar — reading it after extraction
    // would be reading it after the space is already spent. 8 MiB is far past
    // any real manifest (a 40-site IR is tens of KB) and caps a hostile one.
    let bundle_path = bundle.to_path_buf();
    let raw = tokio::task::spawn_blocking(move || {
        hyperion_adapters::backup::read_tar_member(
            &bundle_path,
            hyperion_import::bundle::MANIFEST,
            8 * 1024 * 1024,
        )
    })
    .await
    .ok()
    .flatten();
    let inflate = raw
        .as_deref()
        .and_then(|b| serde_json::from_slice::<hyperion_import::ImportIR>(b).ok())
        .and_then(|ir| hyperion_import::bundle::inflate_bytes(&ir))
        .unwrap_or(0);

    // Unknown device ids mean we cannot tell whether these two costs share a
    // filesystem, and the only answer that cannot wrongly refuse work is to
    // weigh the unpack alone.
    let shared = same_filesystem(stage, homes).unwrap_or(false);
    let inflate_on_stage = if shared { inflate } else { 0 };

    check_fits(stage, bundle_len, inflate_on_stage, "unpack this bundle").await?;
    if !shared && inflate > 0 {
        check_fits(homes, 0, inflate, "unpack this bundle").await?;
    }
    Ok(())
}

/// Do `bundle_len` bytes of unpack plus `inflate` bytes of site files fit under
/// `probe`? `Ok(())` whenever `df` cannot say — see [`bundle_fits_or_refuse`].
async fn check_fits(
    probe: &Path,
    bundle_len: u64,
    inflate: u64,
    what: &str,
) -> Result<(), RpcError> {
    let Some(avail) = hyperion_import::bundle::avail_bytes(probe).await else {
        return Ok(());
    };
    let needed = hyperion_import::bundle::import_needed_bytes(bundle_len, inflate, 1);
    if avail >= needed {
        return Ok(());
    }
    let human = hyperion_import::progress::human_bytes;
    let parts = match (bundle_len > 0, inflate > 0) {
        (true, true) => format!(
            "{} to {what}, then {} of site files and database dumps",
            human(bundle_len),
            human(inflate)
        ),
        (true, false) => format!("{} to {what}", human(bundle_len)),
        _ => format!("{} of site files and database dumps", human(inflate)),
    };
    Err(RpcError::Validation {
        message: format!(
            "not enough free disk on {}: {} free, {} needed ({parts}, plus 1 GB of \
             headroom). Free up space and start the import again — nothing has been \
             created yet.",
            probe.display(),
            human(avail),
            human(needed),
        ),
    })
}

/// Are these two paths on the same filesystem? `None` when either cannot be
/// stat'ed, which callers must read as "cannot tell", never as "no".
fn same_filesystem(a: &Path, b: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let da = std::fs::metadata(a).ok()?.dev();
    let db = std::fs::metadata(b).ok()?.dev();
    Some(da == db)
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

/// Did the exporter record this domain's docroot as one it could not pack?
///
/// The bundle's own `manifest.json` carries the skip list, so this asks the
/// bundle rather than trusting the absence of a file. That distinction is the
/// whole point: "the exporter left it out and said so" and "the bundle was
/// truncated" look identical on disk, and resolving that ambiguity toward the
/// first one silently produced empty sites with a green job.
async fn docroot_was_skipped(dir: &std::path::Path, domain: &str) -> bool {
    let Some(ir) = hyperion_import::bundle::read_manifest(dir).await else {
        // No readable manifest at all — that is not a bundle we should be
        // trusting to omit things on purpose.
        return false;
    };
    ir.skipped
        .iter()
        .any(|s| s.domain == domain && s.what == "docroot")
}

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
            // Unpack this site's bundled docroot tarball. Absent is only
            // acceptable when the manifest says the exporter skipped it.
            let tgz = dir
                .join("sites")
                .join(hyperion_import::bundle::site_dir(domain))
                .join("docroot.tar.gz");
            if tgz.is_file() {
                // SECURITY: the docroot tarball is attacker-controlled content.
                // A bare `tar xzf` as root would honour `..` members and plant
                // symlinks (e.g. `leak -> /etc/passwd`) that nginx/PHP-FPM then
                // serves cross-tenant (sec-findings #8/#10). Sandboxed extract.
                let dest_path = PathBuf::from(dest);
                let unpacked = tokio::task::spawn_blocking(move || {
                    hyperion_adapters::backup::extract_tar_gz_sandboxed(&tgz, &dest_path)
                })
                .await
                .map_err(|e| format!("docroot unpack task join: {e}"))?;
                unpacked.map(|_| ()).map_err(|e| e.to_string())
            } else if docroot_was_skipped(dir, domain).await {
                // The exporter said, in the bundle's own manifest, that it could
                // not pack this docroot. An empty site is then the honest
                // outcome — the operator was told at export time.
                Ok(())
            } else {
                // Absent AND not recorded as skipped means the bundle is not
                // what it claims to be. Creating the site EMPTY and reporting
                // success is how a truncated upload turned into "30 sites
                // imported, several of them blank, green job" — the digest check
                // on upload closes that at the front door, and this closes it
                // here for a bundle that arrived by any other route.
                Err(format!(
                    "{domain}: the bundle contains no docroot for this site and its \
                     manifest does not record one as skipped — the bundle is \
                     incomplete. Refusing to create an empty site."
                ))
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

#[cfg(test)]
mod tests {
    use super::looks_like_out_of_space;

    /// The whole point of stopping the batch is that ENOSPC arrives here as a
    /// STRING, three `Display` conversions away from the `io::Error` that
    /// produced it. These are the exact forms it takes on the way through.
    #[test]
    fn out_of_space_is_recognised_however_it_arrives() {
        // std::io::Error for errno 28, as ProvisioningFailed renders it.
        assert!(looks_like_out_of_space(
            "import_copy_files: No space left on device (os error 28)"
        ));
        // The same error surfaced only as its raw code.
        assert!(looks_like_out_of_space("unpack failed: os error 28"));
        // From a subprocess (`cp`, `rsync`, `tar`) rather than from Rust.
        assert!(looks_like_out_of_space(
            "tar: ./wp-content/uploads/a.jpg: Cannot write: No space left on device"
        ));
        assert!(looks_like_out_of_space("gzip: write error: no space"));
        // A filesystem quota is the same wall for the operator: more room, or
        // fewer sites. Continuing would create the rest empty either way.
        assert!(looks_like_out_of_space("write: Disk quota exceeded"));
    }

    /// A false positive here abandons sites that would have imported fine, so
    /// ordinary per-site failures must not trip it — least of all the ones
    /// whose text merely mentions space or disks.
    #[test]
    fn ordinary_failures_do_not_stop_the_batch() {
        assert!(!looks_like_out_of_space(
            "import_copy_files: the bundle contains no docroot for this site"
        ));
        assert!(!looks_like_out_of_space(
            "target domain 'não válido': invalid domain"
        ));
        assert!(!looks_like_out_of_space("os error 2"));
        assert!(!looks_like_out_of_space(
            "database dump 'shop_disk_space' missing from bundle"
        ));
    }
}
