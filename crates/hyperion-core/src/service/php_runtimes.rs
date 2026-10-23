//! Installed PHP branches: what is on the node, which sites use it, and
//! taking a branch off for good.
//!
//! The point is the branch that will never be fixed (8.1 for the 2026-10
//! remote-code-execution advisories): its FPM keeps running for as long as
//! the package is installed, whether or not a site still needs it. The
//! security verdict itself is the master's — see `hyperion_types::php_security`.

use super::system::{append_line, run_one};
use super::*;
use hyperion_types::php_security::{parse_branch, PhpRuntime, PhpRuntimeSite};

/// phpMyAdmin's pool file name under `/etc/php/<branch>/fpm/pool.d/`.
const PMA_POOL: &str = "hyperion-pma.conf";

/// What phpMyAdmin needs from a branch to run on it (phpmyadmin.sh checks
/// the same three).
const PMA_NEEDS: &[&str] = &["fpm", "mysql", "mbstring"];

/// One installed dpkg package of a PHP branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PhpPackage {
    pub branch: String,
    pub package: String,
    pub version: String,
}

/// Parse `dpkg-query -W -f '${Package}\t${Version}\t${db:Status-Abbrev}\n'`,
/// keeping installed `php<major>.<minor>` and `php<major>.<minor>-*`
/// packages. `rc` (removed, config left) is not installed.
pub(super) fn parse_dpkg_php(out: &str) -> Vec<PhpPackage> {
    out.lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let (package, version, status) = (f.next()?, f.next()?, f.next()?);
            if !status.starts_with("ii") {
                return None;
            }
            let rest = package.strip_prefix("php")?;
            let branch = rest.split_once('-').map_or(rest, |(b, _)| b);
            let (a, b) = parse_branch(branch)?;
            // "8.1" only — not "08.1", not a stray "php8.1foo".
            (format!("{a}.{b}") == branch).then(|| PhpPackage {
                branch: branch.to_string(),
                package: package.to_string(),
                version: version.trim().to_string(),
            })
        })
        .collect()
}

/// The build that speaks for a branch: FPM, else the CLI, else whatever is
/// there.
fn branch_version(pkgs: &[&PhpPackage], branch: &str) -> String {
    ["fpm", "cli", "common"]
        .iter()
        .find_map(|s| {
            let name = format!("php{branch}-{s}");
            pkgs.iter().find(|p| p.package == name)
        })
        .or_else(|| pkgs.first())
        .map(|p| p.version.clone())
        .unwrap_or_default()
}

/// Put the node's facts together, oldest branch first. A branch some site is
/// set to but that is not installed still gets a row — those sites are down.
pub(super) fn build_runtimes(
    pkgs: &[PhpPackage],
    sites: &[(String, String, String, bool)],
    pma_branch: Option<&str>,
) -> Vec<PhpRuntime> {
    let mut branches: Vec<String> = pkgs
        .iter()
        .map(|p| p.branch.clone())
        .chain(
            sites
                .iter()
                .filter(|(_, _, php, _)| parse_branch(php).is_some())
                .map(|(_, _, php, _)| php.clone()),
        )
        .collect();
    branches.sort_by_key(|b| parse_branch(b));
    branches.dedup();
    branches
        .into_iter()
        .map(|branch| {
            let mine: Vec<&PhpPackage> = pkgs.iter().filter(|p| p.branch == branch).collect();
            PhpRuntime {
                package_version: branch_version(&mine, &branch),
                fpm: mine.iter().any(|p| p.package == format!("php{branch}-fpm")),
                sites: sites
                    .iter()
                    .filter(|(_, _, php, _)| *php == branch)
                    .map(|(id, domain, _, trashed)| PhpRuntimeSite {
                        id: id.clone(),
                        domain: domain.clone(),
                        trashed: *trashed,
                    })
                    .collect(),
                pma: pma_branch == Some(branch.as_str()),
                branch,
            }
        })
        .collect()
}

/// Why a branch may not be purged right now, or `None` when it may.
/// `pkgs` is every installed PHP package on the node.
pub(super) fn uninstall_refusal(
    branch: &str,
    runtimes: &[PhpRuntime],
    pkgs: &[PhpPackage],
) -> Option<String> {
    let Some(target) = runtimes.iter().find(|r| r.branch == branch) else {
        return Some(format!("PHP {branch} is not installed on this node."));
    };
    if !target.sites.is_empty() {
        let live = target.sites.iter().filter(|s| !s.trashed).count();
        let trashed = target.sites.len() - live;
        let names: Vec<&str> = target
            .sites
            .iter()
            .take(5)
            .map(|s| s.domain.as_str())
            .collect();
        let more = target.sites.len().saturating_sub(names.len());
        return Some(format!(
            "{} site{} still set to PHP {branch} ({}{}){}. Switch each to a newer PHP \
             on its PHP tab first — removing {branch} would take {} down.",
            target.sites.len(),
            if target.sites.len() == 1 {
                " is"
            } else {
                "s are"
            },
            names.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            },
            if trashed > 0 {
                format!(", {trashed} of them in the trash (purge or switch those too)")
            } else {
                String::new()
            },
            if target.sites.len() == 1 {
                "it"
            } else {
                "them"
            },
        ));
    }
    if target.fpm && !runtimes.iter().any(|r| r.branch != branch && r.fpm) {
        return Some(format!(
            "PHP {branch} is the only PHP-FPM on this node, and a node needs one to host \
             sites (a node update would also install one back). Install PHP 8.3 or 8.4 \
             first."
        ));
    }
    if target.pma {
        let fits = |b: &str| {
            PMA_NEEDS
                .iter()
                .all(|s| pkgs.iter().any(|p| p.package == format!("php{b}-{s}")))
        };
        if !runtimes
            .iter()
            .any(|r| r.branch != branch && fits(&r.branch))
        {
            return Some(format!(
                "phpMyAdmin runs on PHP {branch} and no other PHP here has the FPM, mysql \
                 and mbstring packages it needs. Install PHP 8.3 first — the uninstall then \
                 moves phpMyAdmin onto it."
            ));
        }
    }
    None
}

/// "a.cz, b.cz, c.cz and 4 more" — live sites only; the trashed ones are
/// not serving anything.
fn site_list(r: &PhpRuntime) -> (usize, String) {
    let live: Vec<&str> = r
        .sites
        .iter()
        .filter(|s| !s.trashed)
        .map(|s| s.domain.as_str())
        .collect();
    let shown = live.iter().take(3).copied().collect::<Vec<_>>().join(", ");
    let more = live.len().saturating_sub(3);
    let list = if more > 0 {
        format!("{shown} and {more} more")
    } else {
        shown
    };
    (live.len(), list)
}

/// Dashboard rows for PHP builds with published holes. Kinds `php_unfixable`
/// (the branch gets no fix — move the sites, uninstall it) and `php_outdated`
/// (a fixed build exists — run the node update). A Debian build is left to
/// the Services page: its number cannot say whether the fix is in.
pub(super) fn php_alerts(runtimes: &[PhpRuntime]) -> Vec<DashboardAlert> {
    use hyperion_types::php_security::{verdict, PhpPatchState};
    let mut out = Vec::new();
    for r in runtimes {
        let Some(branch) = parse_branch(&r.branch) else {
            continue;
        };
        // Nothing installed and no site on it: nothing exposed.
        if !r.fpm && r.sites.is_empty() {
            continue;
        }
        let v = verdict(branch, &r.package_version);
        let cves = v
            .advisories
            .iter()
            .map(|a| a.cve)
            .collect::<Vec<_>>()
            .join(", ");
        let (live, list) = site_list(r);
        let b = &r.branch;
        match v.state {
            PhpPatchState::Unfixable => out.push(DashboardAlert {
                kind: "php_unfixable".into(),
                severity: "error".into(),
                message: if live > 0 {
                    format!(
                        "PHP {b} has known remote-code-execution holes ({cves}) and will \
                         never get a fix — the branch is past end of life. {live} site{} \
                         run{} on it: {list}. Move {} to PHP 8.3 or 8.4 on the site's PHP \
                         tab, then uninstall {b}.",
                        if live == 1 { "" } else { "s" },
                        if live == 1 { "s" } else { "" },
                        if live == 1 { "it" } else { "them" },
                    )
                } else {
                    format!(
                        "PHP {b} is installed with known remote-code-execution holes \
                         ({cves}) that will never be fixed. No running site uses it — \
                         uninstall it."
                    )
                },
                hosting: None,
            }),
            PhpPatchState::Outdated => {
                let installed =
                    hyperion_types::php_security::parse_package_version(&r.package_version)
                        .map(|((a, b, c), _)| format!("{a}.{b}.{c}"))
                        .unwrap_or_else(|| r.branch.clone());
                out.push(DashboardAlert {
                    kind: "php_outdated".into(),
                    severity: "error".into(),
                    message: format!(
                        "PHP {installed} has known remote-code-execution holes ({cves}), \
                         fixed in {}. Run the node update to install it{}.",
                        v.update_to.as_deref().unwrap_or("a newer release"),
                        if live > 0 {
                            format!(
                                " — {live} site{} run{} on it",
                                if live == 1 { "" } else { "s" },
                                if live == 1 { "s" } else { "" }
                            )
                        } else {
                            String::new()
                        },
                    ),
                    hosting: None,
                });
            }
            _ => {}
        }
    }
    out
}

async fn installed_php_packages() -> Vec<PhpPackage> {
    let out = tokio::process::Command::new("/usr/bin/dpkg-query")
        .args([
            "-W",
            "-f",
            "${Package}\t${Version}\t${db:Status-Abbrev}\n",
            "php*",
        ])
        .output()
        .await;
    match out {
        // Exit 1 = "no packages found matching" — nothing installed, not an
        // error. Whatever was printed is still the answer.
        Ok(o) => parse_dpkg_php(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => {
            tracing::warn!(error = %e, "dpkg-query for PHP packages failed");
            Vec::new()
        }
    }
}

/// The branch whose pool directory holds phpMyAdmin's pool, if any.
async fn pma_branch() -> Option<String> {
    let mut dir = tokio::fs::read_dir("/etc/php").await.ok()?;
    while let Ok(Some(e)) = dir.next_entry().await {
        let name = e.file_name().to_string_lossy().to_string();
        if parse_branch(&name).is_none() {
            continue;
        }
        if tokio::fs::try_exists(e.path().join("fpm/pool.d").join(PMA_POOL))
            .await
            .unwrap_or(false)
        {
            return Some(name);
        }
    }
    None
}

impl<A: AdapterPort + 'static> HostingService<A> {
    async fn php_facts(&self) -> Result<(Vec<PhpRuntime>, Vec<PhpPackage>), RpcError> {
        let (pkgs, pma) = tokio::join!(installed_php_packages(), pma_branch());
        let sites = hyperion_state::hostings::list_php_sites(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("list sites: {e}")))?;
        Ok((build_runtimes(&pkgs, &sites, pma.as_deref()), pkgs))
    }

    /// Every PHP branch on this node, with its sites.
    pub async fn php_runtimes(&self) -> Result<Vec<PhpRuntime>, RpcError> {
        Ok(self.php_facts().await?.0)
    }

    /// Purge every package of one PHP branch. Refused while anything still
    /// needs it (see [`uninstall_refusal`]). Runs in the background on the
    /// service-install slot, so the Services page's progress panel follows it.
    pub async fn php_uninstall(&self, branch: String) -> Result<(), RpcError> {
        let canonical = parse_branch(&branch).map(|(a, b)| format!("{a}.{b}"));
        if canonical.as_deref() != Some(branch.as_str()) {
            return Err(RpcError::Validation {
                message: format!("`{branch}` is not a PHP version (expected e.g. 8.1)"),
            });
        }
        let (runtimes, pkgs) = self.php_facts().await?;
        if let Some(why) = uninstall_refusal(&branch, &runtimes, &pkgs) {
            return Err(RpcError::Conflict { message: why });
        }
        let packages: Vec<String> = pkgs
            .iter()
            .filter(|p| p.branch == branch)
            .map(|p| p.package.clone())
            .collect();
        let move_pma = runtimes.iter().any(|r| r.branch == branch && r.pma);
        {
            let guard = self.service_install_progress.lock().await;
            if guard.state == "running" {
                return Err(RpcError::Conflict {
                    message: format!(
                        "another service job ({}) is already running on this node; wait for \
                         it to finish — apt would dpkg-lock anyway.",
                        guard.service_name
                    ),
                });
            }
        }
        if let Some(rw_err) = super::fs_health::check_usr_writable().await {
            return Err(RpcError::Conflict { message: rw_err });
        }
        let service_name = format!("php{branch}");
        {
            let mut g = self.service_install_progress.lock().await;
            *g = hyperion_types::ServiceInstallStatus {
                service_name: service_name.clone(),
                pkg: packages.join(" "),
                started_at: now_secs(),
                finished_at: 0,
                state: "running".into(),
                log_tail: String::new(),
                exit_code: 0,
                action: "uninstall".into(),
            };
        }
        self.append_audit(
            "php.uninstall.start",
            None,
            &serde_json::json!({"branch": branch, "packages": packages, "move_pma": move_pma})
                .to_string(),
            "ok",
        )
        .await;
        let slot = self.service_install_progress.clone();
        tokio::spawn(async move {
            run_php_uninstall(slot, service_name, packages, move_pma).await;
        });
        Ok(())
    }
}

async fn run_php_uninstall(
    slot: std::sync::Arc<tokio::sync::Mutex<hyperion_types::ServiceInstallStatus>>,
    component: String,
    packages: Vec<String>,
    move_pma: bool,
) {
    let mut args: Vec<&str> = vec!["purge", "-y", "-q"];
    args.extend(packages.iter().map(String::as_str));
    let mut code = tokio::time::timeout(
        std::time::Duration::from_secs(10 * 60),
        run_one(&slot, "apt-purge", "/usr/bin/apt-get", &args),
    )
    .await
    .unwrap_or(124);
    if code == 124 {
        append_line(
            &slot,
            "apt-purge timed out after 10 min — check the dpkg lock",
        )
        .await;
    }
    if code == 0 {
        // update.sh heals what the selection file lists; leaving the branch
        // there would install it straight back on the next update.
        if let Err(e) = hyperion_adapters::setup_stack::forget_component(&component).await {
            append_line(&slot, &format!("could not update the component list: {e}")).await;
        }
    }
    if code == 0 && move_pma {
        // The purge took phpMyAdmin's PHP with it; the script re-homes its
        // pool on the best PHP still installed.
        code = match hyperion_adapters::setup_stack::materialize_phpmyadmin_script().await {
            Ok(path) => {
                let path = path.to_string_lossy().to_string();
                run_one(&slot, "phpmyadmin", "/bin/bash", &[&path]).await
            }
            Err(e) => {
                append_line(&slot, &format!("could not write phpmyadmin.sh: {e}")).await;
                1
            }
        };
    }
    let mut g = slot.lock().await;
    g.state = if code == 0 { "succeeded" } else { "failed" }.to_string();
    g.finished_at = now_secs();
    g.exit_code = code;
    tracing::info!(branch = %component, exit_code = code, "php uninstall job finished");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(branch: &str, suffix: &str, version: &str) -> PhpPackage {
        PhpPackage {
            branch: branch.into(),
            package: if suffix.is_empty() {
                format!("php{branch}")
            } else {
                format!("php{branch}-{suffix}")
            },
            version: version.into(),
        }
    }

    fn site(id: &str, php: &str, trashed: bool) -> (String, String, String, bool) {
        (id.into(), format!("{id}.cz"), php.into(), trashed)
    }

    #[test]
    fn dpkg_output_keeps_installed_branch_packages_only() {
        let out = "php-common\t2:93\tii \n\
                   php8.1-fpm\t8.1.34-1+0~x\tii \n\
                   php8.1-common\t8.1.34-1+0~x\tii \n\
                   php8.2-fpm\t8.2.30-1+0~x\trc \n\
                   php8.3\t8.3.36-1+0~x\tii \n\
                   php8.3-cli\t8.3.36-1+0~x\tii \n\
                   phpmyadmin\t5.2\tii \n\
                   php08.1-x\t1\tii \n\
                   garbage line\n";
        let got = parse_dpkg_php(out);
        let names: Vec<&str> = got.iter().map(|p| p.package.as_str()).collect();
        assert_eq!(
            names,
            ["php8.1-fpm", "php8.1-common", "php8.3", "php8.3-cli"]
        );
        assert_eq!(got[0].branch, "8.1");
        assert_eq!(got[2].branch, "8.3");
    }

    #[test]
    fn runtimes_join_packages_sites_and_phpmyadmin() {
        let pkgs = [
            pkg("8.3", "cli", "8.3.36-cli"),
            pkg("8.3", "fpm", "8.3.36-fpm"),
            pkg("8.1", "common", "8.1.34-common"),
            pkg("8.10", "fpm", "8.10.0"),
        ];
        let sites = [
            site("a", "8.1", false),
            site("b", "8.1", true),
            site("c", "8.4", false),
        ];
        let got = build_runtimes(&pkgs, &sites, Some("8.3"));
        let branches: Vec<&str> = got.iter().map(|r| r.branch.as_str()).collect();
        // Numeric order, and 8.4 has a site but no package — it still shows.
        assert_eq!(branches, ["8.1", "8.3", "8.4", "8.10"]);
        assert_eq!(got[0].package_version, "8.1.34-common");
        assert!(!got[0].fpm);
        assert_eq!(got[0].sites.len(), 2);
        assert!(got[0].sites[1].trashed);
        assert_eq!(
            got[1].package_version, "8.3.36-fpm",
            "fpm speaks for the branch"
        );
        assert!(got[1].fpm && got[1].pma);
        assert!(got[2].package_version.is_empty() && !got[2].fpm);
    }

    fn node() -> (Vec<PhpPackage>, Vec<PhpRuntime>) {
        let pkgs = vec![
            pkg("8.1", "fpm", "8.1.34"),
            pkg("8.1", "mysql", "8.1.34"),
            pkg("8.1", "mbstring", "8.1.34"),
            pkg("8.4", "fpm", "8.4.27"),
            pkg("8.4", "mysql", "8.4.27"),
            pkg("8.4", "mbstring", "8.4.27"),
        ];
        let rt = build_runtimes(&pkgs, &[], Some("8.1"));
        (pkgs, rt)
    }

    #[test]
    fn an_unused_branch_may_go_and_phpmyadmin_has_somewhere_to_move() {
        let (pkgs, rt) = node();
        assert_eq!(uninstall_refusal("8.1", &rt, &pkgs), None);
    }

    #[test]
    fn a_branch_with_sites_is_refused_and_names_them() {
        let (pkgs, _) = node();
        let rt = build_runtimes(
            &pkgs,
            &[site("shop", "8.1", false), site("old", "8.1", true)],
            None,
        );
        let why = uninstall_refusal("8.1", &rt, &pkgs).expect("refused");
        assert!(why.contains("shop.cz") && why.contains("old.cz"), "{why}");
        assert!(why.contains("in the trash"), "{why}");
    }

    #[test]
    fn the_last_fpm_branch_is_refused() {
        let pkgs = vec![pkg("8.1", "fpm", "8.1.34")];
        let rt = build_runtimes(&pkgs, &[], None);
        let why = uninstall_refusal("8.1", &rt, &pkgs).expect("refused");
        assert!(why.contains("only PHP-FPM"), "{why}");
    }

    #[test]
    fn phpmyadmin_with_nowhere_to_go_is_refused() {
        // 8.4 has FPM but not the mysql/mbstring phpMyAdmin needs.
        let pkgs = vec![
            pkg("8.1", "fpm", "8.1.34"),
            pkg("8.1", "mysql", "8.1.34"),
            pkg("8.1", "mbstring", "8.1.34"),
            pkg("8.4", "fpm", "8.4.27"),
        ];
        let rt = build_runtimes(&pkgs, &[], Some("8.1"));
        let why = uninstall_refusal("8.1", &rt, &pkgs).expect("refused");
        assert!(why.contains("phpMyAdmin"), "{why}");
    }

    #[test]
    fn alerts_name_the_sites_on_an_unfixable_branch() {
        let pkgs = [
            pkg("8.1", "fpm", "8.1.34-1+0~x"),
            pkg("8.4", "fpm", "8.4.27-1+0~x"),
        ];
        let sites: Vec<_> = ["a", "b", "c", "d"]
            .iter()
            .map(|id| site(id, "8.1", false))
            .chain([site("gone", "8.1", true)])
            .collect();
        let got = php_alerts(&build_runtimes(&pkgs, &sites, None));
        assert_eq!(got.len(), 1, "8.4.27 is patched: {got:?}");
        assert_eq!(got[0].kind, "php_unfixable");
        assert_eq!(got[0].severity, "error");
        let m = &got[0].message;
        assert!(
            m.contains("4 sites run on it: a.cz, b.cz, c.cz and 1 more"),
            "{m}"
        );
        assert!(!m.contains("gone.cz"), "{m}");
        assert!(m.contains("CVE-2026-109618"), "{m}");
    }

    #[test]
    fn an_unused_unfixable_branch_still_alerts_while_installed() {
        let pkgs = [pkg("8.1", "fpm", "8.1.34-1+0~x")];
        let got = php_alerts(&build_runtimes(&pkgs, &[], None));
        assert!(
            got[0].message.contains("No running site uses it"),
            "{got:?}"
        );
        // A leftover -common with no FPM and no site exposes nothing.
        let pkgs = [pkg("8.1", "common", "8.1.34-1+0~x")];
        assert!(php_alerts(&build_runtimes(&pkgs, &[], None)).is_empty());
    }

    #[test]
    fn an_outdated_build_points_at_the_node_update() {
        let pkgs = [pkg("8.3", "fpm", "8.3.30-1+0~20260101.1+debian12~1.gbp1")];
        let got = php_alerts(&build_runtimes(&pkgs, &[site("a", "8.3", false)], None));
        assert_eq!(got[0].kind, "php_outdated");
        assert!(got[0].message.contains("PHP 8.3.30"), "{got:?}");
        assert!(got[0].message.contains("fixed in 8.3.36"), "{got:?}");
        assert!(got[0].message.contains("1 site runs on it"), "{got:?}");
        // Debian's own build may carry a backport — not a dashboard alarm.
        let pkgs = [pkg("8.4", "fpm", "8.4.11-1+deb13u2")];
        assert!(php_alerts(&build_runtimes(&pkgs, &[], None)).is_empty());
    }

    #[test]
    fn a_branch_that_is_not_there_is_refused() {
        let (pkgs, rt) = node();
        assert!(uninstall_refusal("8.2", &rt, &pkgs).is_some());
    }
}
