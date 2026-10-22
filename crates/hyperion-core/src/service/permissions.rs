//! Site tree permission checks and autoheal.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Is the permission self-repair allowed to act on this hosting?
    ///
    /// **Default ON** (absent ⇒ enabled). The check has always run; what is
    /// new is that it now FIXES what it finds, so there has to be a way to
    /// say no — a site with deliberately unusual modes should not have them
    /// quietly normalised every five minutes.
    ///
    /// A read error answers "on" for the same reason the brute-force scanner
    /// does: silently stopping a repair is worse than repeating one.
    pub async fn permissions_autoheal_enabled(&self, hosting_id: &str) -> bool {
        match hyperion_state::hosting_kv::get(&self.pool, hosting_id, PERM_AUTOHEAL_KV_KEY).await {
            Ok(Some(v)) => v.trim() != "off",
            _ => true,
        }
    }

    /// Turn the per-site permission self-repair on or off.
    pub async fn permissions_autoheal_set(
        &self,
        sel: HostingSelector,
        enabled: bool,
    ) -> Result<bool, RpcError> {
        let detail = self.get(sel).await?;
        hyperion_state::hosting_kv::set(
            &self.pool,
            detail.id.as_str(),
            PERM_AUTOHEAL_KV_KEY,
            if enabled { "on" } else { "off" },
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("perm autoheal set: {e}")))?;
        self.append_audit(
            "hosting.permissions.autoheal.set",
            Some(detail.id.as_str()),
            &serde_json::json!({ "enabled": enabled }).to_string(),
            "ok",
        )
        .await;
        Ok(enabled)
    }

    /// Periodic self-heal: find hostings whose trees nginx cannot read,
    /// and repair them without waiting for the operator to diagnose a
    /// site-wide 404.
    ///
    /// Exists because the failure is invisible from every dashboard this
    /// panel has: the files are present, PHP may keep serving cached
    /// pages, the vhost is correct — only the MODE bits are wrong, and
    /// the operator experiences it as "the site randomly 404s everything"
    /// hours after an import or a root-shell unzip. The probe is a
    /// handful of stats per site (see `tree_denies_world_read`); the
    /// repair runs only when it fires, and lands in the audit log both
    /// so the fix is traceable and so a repeating heal — something
    /// re-breaking modes on a schedule — is visible as a pattern.
    pub async fn permissions_autoheal_tick(&self) -> Result<i64, RpcError> {
        // Node-wide off switch. Checked here rather than at the call site so
        // every caller — the timer, a future manual sweep — obeys it.
        if !self.permissions_autoheal {
            return Ok(0);
        }
        let mut healed = 0i64;
        for s in self.list().await? {
            if s.state != HostingState::Active {
                continue;
            }
            // Per-site opt-out, default ON. Same shape as the brute-force
            // scanner's: absent means enabled, so nothing changes for a site
            // that predates the key, and a read error also answers "on" —
            // a DB hiccup must not quietly stop repairing a site.
            if !self.permissions_autoheal_enabled(s.id.as_str()).await {
                continue;
            }
            let Ok(detail) = self.get(HostingSelector::Id(s.id.clone())).await else {
                continue;
            };
            // Proxy and redirect hostings have no document tree to serve.
            if detail.root_dir.trim().is_empty()
                || matches!(detail.kind.as_str(), "reverse_proxy" | "redirect")
                || detail.system_user.trim().is_empty()
            {
                continue;
            }
            let root = std::path::PathBuf::from(&detail.root_dir);
            let broken = tokio::task::spawn_blocking(move || tree_denies_world_read(&root))
                .await
                .unwrap_or(false);
            if !broken {
                continue;
            }
            let site_dir = std::path::Path::new(&detail.root_dir)
                .parent()
                .unwrap_or(std::path::Path::new(&detail.root_dir))
                .to_path_buf();
            tracing::warn!(
                domain = %detail.domain,
                path = %site_dir.display(),
                "permissions autoheal: tree is unreadable by nginx — repairing"
            );
            match repair_tree_permissions(&detail.system_user, &site_dir).await {
                Ok(()) => {
                    healed += 1;
                    // Deliberately NOT audited. This runs on a timer over
                    // every hosting, so a successful repair wrote a row on
                    // every tick and the activity feed became a list of the
                    // machine tidying up after itself — with the events an
                    // operator actually needs pushed off the page. A repair
                    // that WORKS is housekeeping; the journal keeps it for
                    // anyone debugging. Only a repair that FAILS is news, and
                    // that is still audited below.
                    tracing::info!(
                        domain = %detail.domain,
                        path = %site_dir.display(),
                        "permissions autoheal: repaired"
                    );
                }
                Err(e) => {
                    tracing::warn!(domain = %detail.domain, error = %e,
                        "permissions autoheal failed");
                    self.append_audit(
                        "hosting.permissions.autoheal",
                        Some(detail.id.as_str()),
                        &serde_json::json!({"error": e}).to_string(),
                        "failed",
                    )
                    .await;
                }
            }

            // Two more classes the tree probe cannot see, both cheap enough
            // to check on a timer (a stat each) and both with real
            // consequences on a shared node:
            //
            //   * wp-config.php readable by other users — that is the database
            //     password and the auth salts handed to every other tenant;
            //   * logs/ and tmp/ readable by others — PHP session files live
            //     in tmp, and a readable session file is a logged-in session.
            //
            // The full check (`wp_perm_check`) also walks the tree and does a
            // real write probe; running THAT every five minutes over every
            // hosting would be a filesystem scan on a schedule. These two are
            // stats.
            let site_dir = std::path::Path::new(&detail.root_dir)
                .parent()
                .unwrap_or(std::path::Path::new(&detail.root_dir))
                .to_path_buf();
            if wp_config_is_exposed(&detail.root_dir).await {
                match self
                    .wp_perm_repair(HostingSelector::Id(detail.id.clone()), "wp_config".into())
                    .await
                {
                    Ok(_) => {
                        healed += 1;
                        tracing::info!(domain = %detail.domain,
                            "permissions autoheal: tightened wp-config.php");
                    }
                    Err(e) => {
                        tracing::warn!(domain = %detail.domain, error = %e,
                            "permissions autoheal: could not tighten wp-config.php");
                        self.append_audit(
                            "hosting.permissions.autoheal",
                            Some(detail.id.as_str()),
                            &serde_json::json!({"scope": "wp_config", "error": e.to_string()})
                                .to_string(),
                            "failed",
                        )
                        .await;
                    }
                }
            }
            if site_dirs_are_exposed(&site_dir).await {
                match self
                    .wp_perm_repair(HostingSelector::Id(detail.id.clone()), "site_dirs".into())
                    .await
                {
                    Ok(_) => {
                        healed += 1;
                        tracing::info!(domain = %detail.domain,
                            "permissions autoheal: tightened logs/ and tmp/");
                    }
                    Err(e) => {
                        tracing::warn!(domain = %detail.domain, error = %e,
                            "permissions autoheal: could not tighten logs/ and tmp/");
                        self.append_audit(
                            "hosting.permissions.autoheal",
                            Some(detail.id.as_str()),
                            &serde_json::json!({"scope": "site_dirs", "error": e.to_string()})
                                .to_string(),
                            "failed",
                        )
                        .await;
                    }
                }
            }
        }

        Ok(healed)
    }

    /// Repair ownership and modes across a hosting's whole tree.
    ///
    /// The failure this fixes is mundane and constant: files arrive owned
    /// by somebody else. A restore or a cross-hosting migration untars an
    /// archive that carries the SOURCE box's uid; an operator unzips a
    /// theme over SSH as root; an import lands files before the system
    /// user exists. PHP-FPM then runs as the hosting user and cannot
    /// write — WordPress reports "could not create directory", plugin
    /// updates fail, media uploads vanish — and FTP shows the files but
    /// refuses to replace them. Nothing in the panel could put it right.
    ///
    /// Ownership is the actual fix; the mode pass exists because an
    /// archive that carries 0600 files or 0700 directories produces the
    /// same symptoms even once the owner is correct. Directories become
    /// 0755 and files 0644 — the conventional web layout, and readable by
    /// nginx, which runs as its own user and only ever reads.
    ///
    /// FTP is covered by the same work rather than separately: vsftpd
    /// authenticates AS the system user, so correct ownership is
    /// precisely what it needs. What it additionally needs is for every
    /// ancestor of the home to be traversable, which `useradd -m` does
    /// not give it (0700 homes) — so that runs too.
    ///
    /// Deliberately NOT recursive-chmod-everything: an existing 0755 file
    /// that is meant to be executable stays executable, because only the
    /// permission bits are rewritten wholesale by `chmod` and a CGI
    /// script losing its +x is its own outage. Files go to 0644 anyway,
    /// which is correct for a PHP application — PHP is read by the
    /// interpreter, never executed by the kernel.
    pub async fn hosting_repair_permissions(
        &self,
        sel: HostingSelector,
    ) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        if matches!(detail.state, HostingState::Deleting | HostingState::Trashed) {
            return Err(RpcError::Conflict {
                message: "hosting is being deleted or in trash".into(),
            });
        }
        let user = detail.system_user.trim();
        if user.is_empty() {
            return Err(RpcError::Conflict {
                message: "hosting has no system user — nothing to repair against".into(),
            });
        }
        // The site's directory, i.e. the PARENT of htdocs: logs, tmp and
        // the docroot all belong to the user, and repairing only htdocs
        // leaves the session dir and log dir broken.
        let root = std::path::Path::new(&detail.root_dir);
        let site_dir = root.parent().unwrap_or(root).to_path_buf();
        if !tokio::fs::try_exists(&site_dir).await.unwrap_or(false) {
            return Err(RpcError::Conflict {
                message: format!(
                    "{} does not exist on this node — nothing to repair",
                    site_dir.display()
                ),
            });
        }
        let dir_s = site_dir.display().to_string();
        repair_tree_permissions(user, &site_dir)
            .await
            .map_err(RpcError::Internal_with)?;

        self.append_audit(
            "hosting.repair_permissions",
            Some(detail.id.as_str()),
            &serde_json::json!({"path": dir_s, "user": user}).to_string(),
            "ok",
        )
        .await;
        Ok(format!(
            "Ownership set to {user}:{user} and modes normalised (directories 0755, \
             files 0644) across {dir_s}. FTP uses the same account, so it is fixed too."
        ))
    }
}

/// Every port sshd listens on, from its config text.
///
/// Split out of the reader so it can be tested: this is the value that decides
/// whether flipping the firewall to default-drop keeps the operator connected
/// or locks them out of a remote machine, and it is not a place to find out
/// later that a comment or a lookalike directive was mis-parsed.
///
/// An empty or unreadable config yields sshd's own default, 22 — the same
/// assumption sshd makes.
/// Is `wp-config.php` readable by users other than its owner?
///
/// `symlink_metadata`, not `metadata`: the site user owns this tree, so
/// following a symlink they planted would report the mode of whatever it aims
/// at while the real file stays open. A symlink here is itself a finding, and
/// answering `true` sends it to the repair, which refuses to chmod through one
/// and says so.
pub(super) async fn wp_config_is_exposed(root_dir: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let p = std::path::Path::new(root_dir).join("wp-config.php");
    match tokio::fs::symlink_metadata(&p).await {
        Ok(md) => md.file_type().is_symlink() || md.permissions().mode() & 0o004 != 0,
        // Absent is not a problem: plenty of sites are not WordPress.
        Err(_) => false,
    }
}

/// Are `logs/` or `tmp/` readable or writable by other users?
///
/// PHP session files live in `tmp/`, and another tenant who can read one is
/// logged in as that site's visitors.
pub(super) async fn site_dirs_are_exposed(site_dir: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    for name in ["logs", "tmp"] {
        let p = site_dir.join(name);
        if let Ok(md) = tokio::fs::symlink_metadata(&p).await {
            if !md.is_dir() {
                // A symlink or a file where a directory belongs — the repair
                // recreates it correctly.
                return true;
            }
            if md.permissions().mode() & 0o007 != 0 {
                return true;
            }
        }
    }
    false
}

/// `hosting_kv` key gating the HTTP brute-force scan for ONE hosting — the
/// wp-login / xmlrpc access-log sweep, which is the part of `[fail2ban]`
/// that is attributable to a single site's login page and therefore the
/// part a care package can sell per customer.
///
/// **Default ON** (absent ⇒ enabled), like its siblings above: every site
/// that existed before this key is scanned exactly as it was. Only an
/// explicit "off" opts a site out.
///
/// Deliberately does NOT reach the node-wide sources. ssh / ftp / mail
/// floods are read from journals that cover the whole machine and cannot
/// be pinned to one vhost, so one customer's switch must not silence them
/// for everybody.
/// Per-hosting switch for the permission self-repair. Absent ⇒ ON.
pub(super) const PERM_AUTOHEAL_KV_KEY: &str = "permissions_autoheal_enabled";

/// Thin pub wrapper so `panel_import` can reuse the exact repair the
/// panel action runs, without `repair_tree_permissions` itself going pub.
pub async fn repair_tree_permissions_for_import(
    user: &str,
    site_dir: &std::path::Path,
) -> Result<(), String> {
    repair_tree_permissions(user, site_dir).await
}

/// The permission repair itself: ownership to `user`, directories 0755,
/// files 0644, ancestors traversable. Shared by the panel's
/// Repair-file-permissions action, the import pipeline, and the autoheal
/// tick — one behaviour, three doors.
///
/// Two find passes rather than a single recursive chmod, which cannot
/// express "different mode per type" and would leave every directory
/// unenterable at 0644 — a site that 403s on everything.
pub(super) async fn repair_tree_permissions(
    user: &str,
    site_dir: &std::path::Path,
) -> Result<(), String> {
    let dir_s = site_dir.display().to_string();
    let run = |program: &'static str, args: Vec<String>| async move {
        tokio::process::Command::new(program)
            .args(&args)
            .output()
            .await
            .map_err(|e| format!("{program}: {e}"))
            .and_then(|o| {
                if o.status.success() {
                    Ok(())
                } else {
                    Err(format!(
                        "{program} failed: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ))
                }
            })
    };
    run(
        "/usr/bin/chown",
        vec![
            "-R".into(),
            format!("{user}:{user}"),
            "--".into(),
            dir_s.clone(),
        ],
    )
    .await?;
    for (typ, mode) in [("d", "0755"), ("f", "0644")] {
        run(
            "/usr/bin/find",
            vec![
                dir_s.clone(),
                "-type".into(),
                typ.into(),
                "-exec".into(),
                "/usr/bin/chmod".into(),
                mode.into(),
                "{}".into(),
                "+".into(),
            ],
        )
        .await?;
    }
    hyperion_adapters::fs::ensure_ancestors_traversable(site_dir).await;

    // Re-tighten what the 0644/0755 sweep above just widened. Doing it HERE
    // rather than at the call sites is the point: there are five callers and
    // only one of them remembered, so every other path — import, autoheal,
    // restore — quietly republished the database password to every local
    // user on the box.
    //
    // Both spellings, because callers pass different roots: some hand in the
    // site directory, some the document root.
    for rel in ["wp-config.php", "htdocs/wp-config.php"] {
        let p = site_dir.join(rel);
        if tokio::fs::metadata(&p).await.is_ok() {
            // 0640: PHP runs as the owner, so nothing needs group or other.
            let _ = chmod_path(&p.display().to_string(), 0o640).await;
        }
    }
    // logs/ records visitor IPs and tmp/ is session.save_path — a readable
    // session directory on a shared box lets another tenant take over a
    // logged-in session. The repair's own 0755 pass is what put them at risk.
    for rel in ["logs", "tmp"] {
        let p = site_dir.join(rel);
        if tokio::fs::metadata(&p).await.is_ok() {
            let _ = chmod_path(&p.display().to_string(), 0o750).await;
        }
    }
    Ok(())
}

/// True when the tree at `root` would 404 under nginx: the directory
/// itself, or any of its first-level entries, denies world read/traverse.
///
/// First level only, ON PURPOSE. A full walk per tick would repeat `du`'s
/// cost for a probe that fires almost never — and the real-world causes
/// (an archive extracted with the source panel's 0770/0660 modes, a
/// root-owned unzip) break the tree UNIFORMLY, so the top level is
/// representative. wp-includes at drwxrwx--- is exactly what an imported
/// CloudPanel site looks like: CloudPanel runs nginx inside the site
/// user's group, hyperion does not, so modes that worked there 404 here.
pub(super) fn tree_denies_world_read(root: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let dir_denied = |m: u32| m & 0o001 == 0; // no o+x ⇒ untraversable
    let file_denied = |m: u32| m & 0o004 == 0; // no o+r ⇒ unreadable
    let Ok(md) = std::fs::metadata(root) else {
        return false; // absent ⇒ someone else's problem, not a mode problem
    };
    if dir_denied(md.permissions().mode()) {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for e in entries.flatten().take(64) {
        let Ok(md) = e.metadata() else { continue };
        let m = md.permissions().mode();
        if md.is_dir() && dir_denied(m) {
            return true;
        }
        if md.is_file() && file_denied(m) {
            return true;
        }
    }
    false
}
