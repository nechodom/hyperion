//! The setup wizard's "Server software" job: `packaging/install/components.sh`
//! run as a transient systemd unit, outside the agent.
//!
//! Same shape as [`crate::node_update`] and for the same reasons — apt inside
//! the agent's sandbox cannot write everything a package touches, and the job
//! must outlive an agent restart. Nothing about the job is kept in agent
//! memory; it is all in [`JOB_DIR`]:
//!
//! * `job.json` — what was asked for and when, written before the start;
//! * `progress` — `<component> <state>` lines, rewritten by components.sh on
//!   every change;
//! * `result` — `<exit code> <finished unix>`, written by the runner's EXIT trap.
//!
//! components.sh and phpmyadmin.sh are embedded here rather than run from the
//! source checkout, so the job always runs the scripts that match this binary.

use crate::node_update::{
    create_private_dir, parse_result, read_tail, unit_state_is_running, write_private,
};
use crate::AdapterError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;

const RUNNER: &str = include_str!("../assets/setup-stack.sh");
const COMPONENTS_SH: &str = include_str!("../../../packaging/install/components.sh");
const PHPMYADMIN_SH: &str = include_str!("../../../packaging/install/phpmyadmin.sh");

/// Fixed, so two installs can never run at once — systemd refuses a second
/// unit of the same name.
pub const UNIT: &str = "hyperion-setup-stack.service";

const JOB_DIR: &str = "/var/lib/hyperion/setup-stack";
const LOG_FILE: &str = "/var/log/hyperion/setup-stack.log";
const LOG_TAIL_BYTES: u64 = 12 * 1024;

/// Every component the wizard may install, in the order components.sh runs
/// them. phpMyAdmin is last because it needs PHP (and is useless without a
/// database server).
pub const COMPONENT_ORDER: &[&str] = &[
    "php8.1",
    "php8.2",
    "php8.3",
    "php8.4",
    "mariadb",
    "postgresql",
    "redis",
    "vsftpd",
    "phpmyadmin",
];

/// Check a requested component list against the allow-list and put it in run
/// order. At least one PHP version is required: Hyperion cannot host a site
/// without one.
pub fn normalize_components(requested: &[String]) -> Result<Vec<String>, String> {
    for r in requested {
        if !COMPONENT_ORDER.contains(&r.as_str()) {
            return Err(format!("unknown component `{r}`"));
        }
    }
    let out: Vec<String> = COMPONENT_ORDER
        .iter()
        .filter(|c| requested.iter().any(|r| r == *c))
        .map(|c| (*c).to_string())
        .collect();
    if !out.iter().any(|c| c.starts_with("php")) {
        return Err("choose a PHP version — sites cannot run without one".into());
    }
    Ok(out)
}

/// The component list `update.sh` heals from. When it exists, an update only
/// re-installs what is listed — otherwise its heal would quietly install every
/// database the operator left out in the wizard. Absent on every install that
/// predates the wizard, which keeps the old heal-everything behaviour there.
pub const SELECTION_FILE: &str = "/etc/hyperion/components";

/// Which wizard component a Services-page install corresponds to.
pub fn component_for_service(service: &str) -> Option<&'static str> {
    Some(match service {
        "mariadb" => "mariadb",
        "postgresql" => "postgresql",
        "redis-server" => "redis",
        "vsftpd" => "vsftpd",
        "php8.1-fpm" => "php8.1",
        "php8.2-fpm" => "php8.2",
        "php8.3-fpm" => "php8.3",
        "php8.4-fpm" => "php8.4",
        _ => return None,
    })
}

/// `content` of the selection file with `component` added: one name per
/// line, sorted, no duplicates, comments and blanks dropped.
pub fn with_component(content: &str, component: &str) -> String {
    let mut names: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .chain(std::iter::once(component))
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut s = names.join("\n");
    s.push('\n');
    s
}

/// Add a component installed outside the wizard (the Services page) to the
/// selection file, so `update.sh` heals it from now on. Only when the file
/// already exists: without it the box is on the legacy heal-everything path
/// and needs nothing recorded.
pub async fn record_component(component: &str) -> Result<(), AdapterError> {
    let path = Path::new(SELECTION_FILE);
    let current = match tokio::fs::read_to_string(path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let next = with_component(&current, component);
    if next != current {
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, next.as_bytes()).await?;
        tokio::fs::rename(&tmp, path).await?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobSpec {
    pub started_at: i64,
    pub components: Vec<String>,
    pub ftp_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    Never,
    Running,
    Finished { exit_code: i32, finished_at: i64 },
    Interrupted,
}

#[derive(Debug, Clone)]
pub struct JobStatus {
    pub spec: Option<JobSpec>,
    pub state: JobState,
    /// `(component, state)` in run order, from the progress file; every
    /// requested component that the file does not mention yet is `pending`.
    pub progress: Vec<(String, String)>,
    pub log_tail: String,
}

fn job_dir() -> PathBuf {
    PathBuf::from(JOB_DIR)
}

pub async fn is_running() -> bool {
    let Ok(out) = Command::new("/usr/bin/systemctl")
        .args(["show", "-p", "ActiveState", "--value", UNIT])
        .output()
        .await
    else {
        return false;
    };
    unit_state_is_running(String::from_utf8_lossy(&out.stdout).trim())
}

/// Start the job. `spec.components` must already be normalized.
pub async fn start(spec: &JobSpec) -> Result<(), AdapterError> {
    let dir = job_dir();
    create_private_dir(&dir).await?;
    write_private(&dir.join("runner.sh"), RUNNER.as_bytes()).await?;
    write_private(&dir.join("components.sh"), COMPONENTS_SH.as_bytes()).await?;
    write_private(&dir.join("phpmyadmin.sh"), PHPMYADMIN_SH.as_bytes()).await?;
    for stale in ["result", "progress"] {
        match tokio::fs::remove_file(dir.join(stale)).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if let Some(parent) = Path::new(LOG_FILE).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(LOG_FILE, b"").await?;
    let spec_json =
        serde_json::to_vec(spec).map_err(|e| AdapterError::Other(format!("job spec: {e}")))?;
    write_private(&dir.join("job.json"), &spec_json).await?;

    let out = Command::new("/usr/bin/systemd-run")
        .arg(format!("--unit={UNIT}"))
        .arg("--description=Hyperion setup: server software")
        .arg("--collect")
        .args(["-p", "Type=exec"])
        .args(["-p", &format!("StandardOutput=append:{LOG_FILE}")])
        .args(["-p", &format!("StandardError=append:{LOG_FILE}")])
        .arg(format!("--setenv=HYP_JOB_DIR={}", dir.display()))
        .arg(format!(
            "--setenv=HYP_COMPONENTS={}",
            spec.components.join(" ")
        ))
        .arg(format!("--setenv=HYP_FTP_PORT={}", spec.ftp_port))
        .arg("/bin/bash")
        .arg(dir.join("runner.sh"))
        .output()
        .await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let _ = tokio::fs::write(LOG_FILE, format!("could not start {UNIT}: {stderr}\n")).await;
        let _ = write_private(
            &dir.join("result"),
            format!("127 {}\n", spec.started_at).as_bytes(),
        )
        .await;
        return Err(AdapterError::Command {
            cmd: "systemd-run".into(),
            code: out.status.code().unwrap_or(-1),
            stderr_tail: stderr,
        });
    }
    Ok(())
}

/// Read the current (or last) job back.
pub async fn status() -> JobStatus {
    let dir = job_dir();
    let spec: Option<JobSpec> = tokio::fs::read(dir.join("job.json"))
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let log_tail = read_tail(Path::new(LOG_FILE), LOG_TAIL_BYTES)
        .await
        .unwrap_or_default();
    let Some(spec) = spec else {
        return JobStatus {
            spec: None,
            state: JobState::Never,
            progress: Vec::new(),
            log_tail,
        };
    };
    let progress_raw = tokio::fs::read_to_string(dir.join("progress"))
        .await
        .unwrap_or_default();
    let result = tokio::fs::read_to_string(dir.join("result"))
        .await
        .ok()
        .and_then(|s| parse_result(&s));
    let state = match result {
        Some((exit_code, finished_at)) => JobState::Finished {
            exit_code,
            finished_at,
        },
        None if is_running().await => JobState::Running,
        None => JobState::Interrupted,
    };
    let progress = merge_progress(&spec.components, &progress_raw);
    JobStatus {
        spec: Some(spec),
        state,
        progress,
        log_tail,
    }
}

/// Combine the requested list with what the progress file says. The file is
/// the job's own word; anything it does not mention yet is still pending, and
/// a line for a component nobody asked for is ignored.
pub fn merge_progress(requested: &[String], raw: &str) -> Vec<(String, String)> {
    requested
        .iter()
        .map(|c| {
            let st = raw
                .lines()
                .filter_map(|l| {
                    let mut it = l.split_whitespace();
                    Some((it.next()?, it.next()?))
                })
                .find(|(name, _)| name == c)
                .map(|(_, st)| match st {
                    "pending" | "running" | "done" | "failed" => st,
                    _ => "pending",
                })
                .unwrap_or("pending");
            (c.clone(), st.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn components_are_put_in_run_order() {
        let got = normalize_components(&v(&["phpmyadmin", "vsftpd", "php8.3", "mariadb"])).unwrap();
        assert_eq!(got, v(&["php8.3", "mariadb", "vsftpd", "phpmyadmin"]));
    }

    #[test]
    fn duplicates_collapse() {
        let got = normalize_components(&v(&["php8.4", "php8.4", "redis"])).unwrap();
        assert_eq!(got, v(&["php8.4", "redis"]));
    }

    #[test]
    fn unknown_component_is_refused() {
        let e = normalize_components(&v(&["php8.3", "docker"])).unwrap_err();
        assert!(e.contains("docker"));
        // Shell metacharacters never reach the unit's environment.
        assert!(normalize_components(&v(&["php8.3", "mariadb; rm -rf /"])).is_err());
    }

    #[test]
    fn php_is_required() {
        assert!(normalize_components(&v(&["mariadb"])).is_err());
        assert!(normalize_components(&[]).is_err());
    }

    #[test]
    fn progress_merges_file_over_request() {
        let req = v(&["php8.3", "mariadb", "vsftpd"]);
        let raw = "php8.3 done\nmariadb running\nredis done\nvsftpd bogus\n";
        assert_eq!(
            merge_progress(&req, raw),
            vec![
                ("php8.3".to_string(), "done".to_string()),
                ("mariadb".to_string(), "running".to_string()),
                ("vsftpd".to_string(), "pending".to_string()),
            ]
        );
        assert!(merge_progress(&req, "").iter().all(|(_, s)| s == "pending"));
    }

    #[test]
    fn selection_file_stays_sorted_and_unique() {
        assert_eq!(with_component("", "mariadb"), "mariadb\n");
        assert_eq!(
            with_component("php8.3\nvsftpd\n", "mariadb"),
            "mariadb\nphp8.3\nvsftpd\n"
        );
        assert_eq!(with_component("mariadb\n", "mariadb"), "mariadb\n");
        assert_eq!(
            with_component("# chosen in setup\n\nphp8.3\n", "redis"),
            "php8.3\nredis\n"
        );
    }

    #[test]
    fn services_map_to_components() {
        assert_eq!(component_for_service("redis-server"), Some("redis"));
        assert_eq!(component_for_service("php8.4-fpm"), Some("php8.4"));
        assert_eq!(component_for_service("nginx"), None);
        assert_eq!(component_for_service("clamav-freshclam"), None);
    }

    #[test]
    fn runner_runs_the_embedded_components_script() {
        assert!(RUNNER.contains("trap finish EXIT"));
        assert!(RUNNER.contains("$JOB_DIR/components.sh"));
        assert!(RUNNER.contains("HYP_PROGRESS_FILE"));
    }

    #[test]
    fn components_script_knows_every_allowed_component() {
        for c in COMPONENT_ORDER {
            assert!(
                COMPONENTS_SH.contains(c),
                "components.sh does not mention `{c}`"
            );
        }
    }
}
