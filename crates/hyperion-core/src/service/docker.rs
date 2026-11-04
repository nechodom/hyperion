//! The Docker monitoring module's install state.
//!
//! Turning the module on is a promise that this node may run `docker`, so it
//! is refused unless `docker version` answers. Turning it off leaves nothing
//! behind. Everything docker does is a read; the only writes in this file go
//! to Hyperion's own database.

use super::docker_verdict::{
    project_transition, project_verdict, service_key, ProjectTransition, ProjectVerdict,
    RestartWatch, RESTART_LOOP_RISES, RESTART_WINDOW_SECS,
};
use super::*;
use hyperion_adapters::docker::{
    parse_inspect, parse_ps, parse_stats, parse_system_df, parse_version, DockerCmd, DockerError,
};
use hyperion_state::docker::{ProjectRow, WatchRow, DAEMON_ROW};
use hyperion_types::docker::{
    DockerContainer, DockerDisk, DockerModuleState, DockerNodeEntry, DockerNodeList,
    DockerNodeStatus, DockerProject,
};
use std::collections::{BTreeMap, HashMap};

/// `docker version` and `buildx version` print a few hundred bytes.
const VERSION_MAX_BYTES: usize = 64 * 1024;
/// `ps` and `inspect` of a busy host are megabytes of JSON.
const JSON_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Container ids per `docker inspect`, to keep the command line short.
const INSPECT_CHUNK: usize = 100;
/// `docker stats` samples for about two seconds per call, so it runs on every
/// second 30 s tick rather than on each.
const STATS_EVERY_SECS: i64 = 45;
/// `docker system df` walks every layer and volume.
const DF_EVERY_SECS: i64 = 3600;
/// Longest project, service or container name carried anywhere.
const NAME_MAX_CHARS: usize = 128;
/// Where the alert for containers that belong to no compose project lives.
/// The parentheses cannot be in a compose project name.
const OTHER_KIND_SUBJECT: &str = "(other)";
const OTHER_DISPLAY: &str = "other containers";
const ALERT_HREF: &str = "/docker";

fn db_err(what: &str, e: hyperion_state::StateError) -> RpcError {
    RpcError::Internal_with(format!("{what}: {e}"))
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Is the module on for this node? Every module tick checks this first,
    /// so with it off nothing here runs a `docker` process. A database error
    /// reads as off: a tick that cannot tell does nothing.
    pub async fn docker_module_enabled(&self) -> bool {
        hyperion_state::docker::node_installed(&self.pool)
            .await
            .unwrap_or(false)
    }

    /// The module's state on this node. `docker version` runs only while the
    /// module is on; a daemon that does not answer just leaves the version
    /// empty.
    pub async fn docker_module_status(&self) -> Result<DockerModuleState, RpcError> {
        let row = hyperion_state::docker::get_module(&self.pool)
            .await
            .map_err(|e| db_err("docker_module_status", e))?;
        let docker_version = if row.node_installed {
            self.docker_server_version().await.ok()
        } else {
            None
        };
        Ok(DockerModuleState {
            cluster_installed: row.cluster_installed,
            node_installed: row.node_installed,
            buildx: row.buildx,
            docker_version,
        })
    }

    /// Turn the module on for this node. Refused, with the state left off,
    /// unless the docker CLI is installed and its daemon answers.
    pub async fn docker_node_install(&self) -> Result<DockerModuleState, RpcError> {
        let version = match self.docker_server_version().await {
            Ok(v) => v,
            Err(e) => {
                self.append_audit(
                    "docker.node.install",
                    None,
                    &serde_json::json!({"error": e.to_string()}).to_string(),
                    "refused",
                )
                .await;
                return Err(e);
            }
        };
        // buildx only decides whether a later feature can inspect remote
        // images; its absence is a fact to record, not a reason to refuse.
        let buildx = self
            .adapters
            .docker_read(DockerCmd::BuildxVersion, VERSION_MAX_BYTES)
            .await
            .is_ok();
        hyperion_state::docker::set_node_installed(&self.pool, buildx, now_secs())
            .await
            .map_err(|e| db_err("docker_node_install", e))?;
        self.append_audit(
            "docker.node.install",
            None,
            &serde_json::json!({"docker": version, "buildx": buildx}).to_string(),
            "ok",
        )
        .await;
        let row = hyperion_state::docker::get_module(&self.pool)
            .await
            .map_err(|e| db_err("docker_node_install", e))?;
        Ok(DockerModuleState {
            cluster_installed: row.cluster_installed,
            node_installed: row.node_installed,
            buildx: row.buildx,
            docker_version: Some(version),
        })
    }

    /// Turn the module off for this node and delete what it kept. No docker
    /// command is involved; hostings are not touched.
    pub async fn docker_node_remove(&self) -> Result<DockerModuleState, RpcError> {
        hyperion_state::docker::clear_node(&self.pool)
            .await
            .map_err(|e| db_err("docker_node_remove", e))?;
        *self.docker_snapshot.write().await = None;
        self.append_audit("docker.node.remove", None, "{}", "ok")
            .await;
        self.docker_module_status().await
    }

    /// Master: turn the module on for the cluster. Only bookkeeping; each
    /// node is turned on with [`Self::docker_node_install`].
    pub async fn docker_cluster_install(&self) -> Result<DockerModuleState, RpcError> {
        hyperion_state::docker::set_cluster_installed(&self.pool)
            .await
            .map_err(|e| db_err("docker_cluster_install", e))?;
        self.append_audit("docker.cluster.install", None, "{}", "ok")
            .await;
        self.docker_module_status().await
    }

    /// Master: turn the cluster flag off and forget which nodes ran the
    /// module. Node data is cleared per node by [`Self::docker_node_remove`].
    pub async fn docker_cluster_remove(&self) -> Result<DockerModuleState, RpcError> {
        hyperion_state::docker::clear_cluster(&self.pool)
            .await
            .map_err(|e| db_err("docker_cluster_remove", e))?;
        self.append_audit("docker.cluster.remove", None, "{}", "ok")
            .await;
        self.docker_module_status().await
    }

    /// Master: record that `node_id` runs the module (or no longer does).
    pub async fn docker_node_register(
        &self,
        node_id: &str,
        installed: bool,
    ) -> Result<(), RpcError> {
        let node_id = node_id.trim();
        if node_id.is_empty() || node_id.len() > 128 || node_id.chars().any(|c| c.is_control()) {
            return Err(RpcError::Validation {
                message: "node id is empty, too long or has control characters".into(),
            });
        }
        if installed {
            hyperion_state::docker::register_node(&self.pool, node_id, now_secs()).await
        } else {
            hyperion_state::docker::unregister_node(&self.pool, node_id).await
        }
        .map_err(|e| db_err("docker_node_register", e))
    }

    /// Master: the cluster flag and the nodes recorded as running the
    /// module. This is the fan-out list the web layer reads.
    pub async fn docker_node_list(&self) -> Result<DockerNodeList, RpcError> {
        let row = hyperion_state::docker::get_module(&self.pool)
            .await
            .map_err(|e| db_err("docker_node_list", e))?;
        let nodes = hyperion_state::docker::list_nodes(&self.pool)
            .await
            .map_err(|e| db_err("docker_node_list", e))?;
        Ok(DockerNodeList {
            cluster_installed: row.cluster_installed,
            nodes: nodes
                .into_iter()
                .map(|n| DockerNodeEntry {
                    node_id: n.node_id,
                    installed_at: n.installed_at,
                })
                .collect(),
        })
    }

    /// `docker version`, reduced to the daemon's version, with errors worded
    /// for the operator who is trying to turn the module on.
    async fn docker_server_version(&self) -> Result<String, RpcError> {
        let out = self
            .adapters
            .docker_read(DockerCmd::Version, VERSION_MAX_BYTES)
            .await
            .map_err(|e| match e {
                DockerError::NotInstalled => RpcError::Validation {
                    message: "Docker is not installed on this node. Install Docker first, \
                              then turn the module on."
                        .into(),
                },
                DockerError::NotResponding => daemon_silent(),
                other => RpcError::Internal_with(format!("docker version: {other}")),
            })?;
        let v = parse_version(&out)
            .map_err(|e| RpcError::Internal_with(format!("docker version: {e}")))?;
        v.server.ok_or_else(daemon_silent)
    }
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// One look at Docker: read the containers, keep the books (restart
    /// history, known projects, open alerts) and refresh the snapshot the
    /// overview serves. A no-op while the module is off. Runs from one task
    /// at a time; every docker call has its own timeout.
    pub async fn docker_tick(&self) -> Result<(), RpcError> {
        self.docker_tick_at(now_secs()).await
    }

    pub(super) async fn docker_tick_at(&self, now: i64) -> Result<(), RpcError> {
        if !self.docker_module_enabled().await {
            return Ok(());
        }
        let prev = self.docker_snapshot.read().await.clone();
        let want_stats = prev
            .as_ref()
            .map_or(true, |p| now - p.stats_at >= STATS_EVERY_SECS);
        match self.docker_observe(want_stats, prev.as_ref(), now).await {
            // The daemon, not any project, is what is wrong. Nothing about
            // projects is learnt from a read that did not happen.
            Err(e) => self.docker_daemon_bad(&e, prev, now).await,
            Ok((containers, stats_at)) => {
                self.docker_daemon_ok(now).await?;
                let disk = self.docker_refresh_disk(now).await;
                let projects = self.docker_apply(containers, now, true).await?;
                *self.docker_snapshot.write().await = Some(DockerNodeStatus {
                    read_at: now,
                    stats_at,
                    daemon_ok: true,
                    daemon_error: None,
                    projects,
                    disk,
                });
                Ok(())
            }
        }
    }

    /// What this node's Docker looked like at the last tick. Before the
    /// first tick has run it reads once itself (without touching the books
    /// or raising alerts) and remembers the answer.
    pub async fn docker_overview(&self) -> Result<DockerNodeStatus, RpcError> {
        if !self.docker_module_enabled().await {
            return Err(RpcError::Validation {
                message: "The Docker module is not turned on for this node.".into(),
            });
        }
        if let Some(s) = self.docker_snapshot.read().await.clone() {
            return Ok(s);
        }
        let now = now_secs();
        let status = match self.docker_observe(true, None, now).await {
            Ok((containers, stats_at)) => DockerNodeStatus {
                read_at: now,
                stats_at,
                daemon_ok: true,
                daemon_error: None,
                projects: self.docker_apply(containers, now, false).await?,
                disk: self.docker_cached_disk().await,
            },
            Err(e) => {
                return Ok(DockerNodeStatus {
                    daemon_ok: false,
                    daemon_error: Some(daemon_error_text(&e)),
                    disk: self.docker_cached_disk().await,
                    ..Default::default()
                })
            }
        };
        *self.docker_snapshot.write().await = Some(status.clone());
        Ok(status)
    }

    /// Forget a project: its row, its restart history and any open alert.
    /// Panel state only; no container is touched. If containers with that
    /// project label show up again it is simply known again.
    pub async fn docker_forget_project(&self, project: String) -> Result<(), RpcError> {
        if project.chars().count() > NAME_MAX_CHARS
            || project.chars().any(|c| c.is_control())
            || project.starts_with('(')
        {
            return Err(RpcError::Validation {
                message: "not a project name".into(),
            });
        }
        let removed = hyperion_state::docker::forget_project(&self.pool, &project)
            .await
            .map_err(|e| db_err("docker_forget_project", e))?;
        if let Some(snap) = self.docker_snapshot.write().await.as_mut() {
            snap.projects
                .retain(|p| !(p.name == project && p.verdict == "gone"));
        }
        self.append_audit(
            "docker.project.forget",
            None,
            &serde_json::json!({"project": project, "known": removed}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }

    /// `ps`, `inspect` in chunks, `stats` when due, and the log file sizes.
    /// Returns the containers and when their stats were read. Any docker
    /// failure is the daemon's: the caller leaves project state alone.
    async fn docker_observe(
        &self,
        want_stats: bool,
        prev: Option<&DockerNodeStatus>,
        now: i64,
    ) -> Result<(Vec<DockerContainer>, i64), DockerError> {
        let ps = self
            .adapters
            .docker_read(DockerCmd::PsAll, JSON_MAX_BYTES)
            .await?;
        let ids = parse_ps(&ps)?;
        let mut containers = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(INSPECT_CHUNK) {
            // A container removed since `ps` just is not in the answer: the
            // adapter hands back what docker printed even when it exits 1.
            let raw = self
                .adapters
                .docker_read(DockerCmd::Inspect(chunk.to_vec()), JSON_MAX_BYTES)
                .await?;
            containers.extend(parse_inspect(&raw)?);
        }
        for c in &mut containers {
            c.project = clean_name(&c.project);
            c.service = clean_name(&c.service);
            c.name = clean_name(&c.name);
        }

        let mut stats_at = prev.map_or(0, |p| p.stats_at);
        let fresh = if want_stats {
            // Figures are nice to have; a slow `stats` is not a daemon problem.
            match self
                .adapters
                .docker_read(DockerCmd::Stats, JSON_MAX_BYTES)
                .await
            {
                Ok(raw) => parse_stats(&raw).ok(),
                Err(e) => {
                    tracing::debug!(error = %e, "docker stats skipped");
                    None
                }
            }
        } else {
            None
        };
        match fresh {
            Some(stats) => {
                stats_at = now;
                for c in &mut containers {
                    let s = stats
                        .iter()
                        .find(|s| !s.id.is_empty() && c.id.starts_with(&s.id));
                    c.cpu_pct_x100 = s.and_then(|s| s.cpu_pct_x100);
                    c.mem_bytes = s.and_then(|s| s.mem_bytes);
                }
            }
            None => {
                let old: HashMap<&str, &DockerContainer> = prev
                    .into_iter()
                    .flat_map(|p| p.projects.iter().flat_map(|p| p.containers.iter()))
                    .map(|c| (c.id.as_str(), c))
                    .collect();
                for c in &mut containers {
                    if let Some(o) = old.get(c.id.as_str()) {
                        c.cpu_pct_x100 = o.cpu_pct_x100;
                        c.mem_bytes = o.mem_bytes;
                    }
                }
            }
        }

        for c in &mut containers {
            if c.log_path.is_empty() {
                continue;
            }
            // Docker's log directory is root's. The size is a plain fact; a
            // file that cannot be read counts as 0 rather than as a failure.
            c.log_size_bytes = match tokio::fs::symlink_metadata(&c.log_path).await {
                Ok(m) if m.is_file() => m.len(),
                _ => 0,
            };
        }
        Ok((containers, stats_at))
    }

    /// Decide every project's verdict, keep the books and raise the alerts.
    /// With `commit` false nothing is written or sent: that is the
    /// overview's first read, before the tick has run.
    async fn docker_apply(
        &self,
        containers: Vec<DockerContainer>,
        now: i64,
        commit: bool,
    ) -> Result<Vec<DockerProject>, RpcError> {
        let rows: HashMap<String, ProjectRow> = hyperion_state::docker::list_projects(&self.pool)
            .await
            .map_err(|e| db_err("docker projects", e))?
            .into_iter()
            .map(|r| (r.project.clone(), r))
            .collect();
        let watch = self.docker_update_watch(&containers, now, commit).await?;

        let mut by_project: BTreeMap<String, Vec<DockerContainer>> = BTreeMap::new();
        for c in containers {
            by_project.entry(c.project.clone()).or_default().push(c);
        }
        for names in rows.keys() {
            by_project.entry(names.clone()).or_default();
        }

        let mut out = Vec::with_capacity(by_project.len());
        for (name, mut present) in by_project {
            present.sort_by(|a, b| (&a.service, &a.name).cmp(&(&b.service, &b.name)));
            let has_real = present.iter().any(|c| !c.oneoff);
            let verdict = if has_real {
                project_verdict(&present, &watch, now)
            } else if !name.is_empty() && rows.contains_key(&name) {
                ProjectVerdict::Gone
            } else {
                // Unknown, or the catch-all group: nothing to be missing.
                ProjectVerdict::Ok
            };
            let known = has_real || rows.contains_key(&name);
            let mut gone_since = None;
            if known {
                let mut row = rows.get(&name).cloned().unwrap_or_else(|| ProjectRow {
                    project: name.clone(),
                    alert_state: "ok".into(),
                    ..Default::default()
                });
                match &verdict {
                    ProjectVerdict::Ok => {
                        row.problem_since = 0;
                        row.gone_since = 0;
                        row.last_summary.clear();
                    }
                    ProjectVerdict::Problem { summary } => {
                        if row.problem_since == 0 {
                            row.problem_since = now;
                        }
                        row.gone_since = 0;
                        row.last_summary = summary.clone();
                    }
                    ProjectVerdict::Gone => {
                        if row.problem_since == 0 {
                            row.problem_since = now;
                        }
                        if row.gone_since == 0 {
                            row.gone_since = now;
                        }
                        row.last_summary.clear();
                    }
                }
                if has_real {
                    row.last_seen_at = now;
                }
                let since = (row.problem_since > 0).then_some(row.problem_since);
                let transition = project_transition(row.alert_state != "ok", since, &verdict, now);
                match transition {
                    Some(ProjectTransition::Down) => {
                        row.alert_state = if verdict == ProjectVerdict::Gone {
                            "gone"
                        } else {
                            "problem"
                        }
                        .into();
                    }
                    Some(ProjectTransition::Up) => row.alert_state = "ok".into(),
                    None => {}
                }
                if verdict == ProjectVerdict::Gone {
                    gone_since = Some(row.gone_since);
                }
                if commit {
                    hyperion_state::docker::put_project(&self.pool, &row)
                        .await
                        .map_err(|e| db_err("docker project", e))?;
                    if let Some(t) = transition {
                        self.docker_project_alert(&name, &verdict, t).await;
                    }
                }
            }
            let (word, summary) = match &verdict {
                ProjectVerdict::Ok => ("ok", String::new()),
                ProjectVerdict::Problem { summary } => ("problem", summary.clone()),
                ProjectVerdict::Gone => ("gone", String::new()),
            };
            out.push(DockerProject {
                name,
                containers: present,
                verdict: word.into(),
                summary,
                hostings: Vec::new(),
                gone_since,
            });
        }
        Ok(out)
    }

    /// Fold this read into each service's restart history and return it.
    /// History is keyed by project and service, so a container that
    /// `compose up` replaced carries on where its predecessor stopped, and a
    /// counter that went down (a new container) is a new baseline, not a
    /// restart.
    async fn docker_update_watch(
        &self,
        containers: &[DockerContainer],
        now: i64,
        commit: bool,
    ) -> Result<RestartWatch, RpcError> {
        let mut rows: HashMap<(String, String), WatchRow> =
            hyperion_state::docker::load_watch(&self.pool)
                .await
                .map_err(|e| db_err("docker watch", e))?
                .into_iter()
                .map(|r| ((r.project.clone(), r.service.clone()), r))
                .collect();
        let mut totals: HashMap<(String, String), i64> = HashMap::new();
        for c in containers.iter().filter(|c| !c.oneoff) {
            *totals
                .entry((c.project.clone(), service_key(c).to_string()))
                .or_default() += c.restart_count.max(0);
        }
        for (key, total) in totals {
            let fresh = !rows.contains_key(&key);
            let row = rows.entry(key.clone()).or_insert_with(|| WatchRow {
                project: key.0.clone(),
                service: key.1.clone(),
                restart_count: total,
                rises: Vec::new(),
            });
            let before = (row.restart_count, row.rises.len());
            row.rises.retain(|&t| t > now - RESTART_WINDOW_SECS);
            if total > row.restart_count {
                let rose = (total - row.restart_count).min(2 * i64::from(RESTART_LOOP_RISES));
                row.rises.extend(std::iter::repeat(now).take(rose as usize));
            }
            row.restart_count = total;
            if commit && (fresh || before != (row.restart_count, row.rises.len())) {
                hyperion_state::docker::put_watch(&self.pool, row)
                    .await
                    .map_err(|e| db_err("docker watch", e))?;
            }
        }
        Ok(RestartWatch {
            rises: rows
                .into_iter()
                .map(|(k, r)| (k, r.rises))
                .collect::<HashMap<_, _>>(),
        })
    }

    async fn docker_project_alert(
        &self,
        project: &str,
        verdict: &ProjectVerdict,
        transition: ProjectTransition,
    ) {
        let (shown, subject) = if project.is_empty() {
            (OTHER_DISPLAY, OTHER_KIND_SUBJECT)
        } else {
            (project, project)
        };
        let kind = format!("docker.project:{subject}");
        match (transition, verdict) {
            (ProjectTransition::Down, ProjectVerdict::Problem { summary }) => {
                self.notify_admins_say(
                    "error",
                    "ops.docker_project_down",
                    &[("project", shown), ("summary", summary.as_str())],
                    ALERT_HREF,
                    &kind,
                )
                .await;
            }
            (ProjectTransition::Down, ProjectVerdict::Gone) => {
                self.notify_admins_say(
                    "warn",
                    "ops.docker_project_gone",
                    &[("project", shown)],
                    ALERT_HREF,
                    &kind,
                )
                .await;
            }
            (ProjectTransition::Up, _) => {
                self.notify_admins_say(
                    "info",
                    "ops.docker_project_up",
                    &[("project", shown)],
                    ALERT_HREF,
                    &kind,
                )
                .await;
            }
            (ProjectTransition::Down, ProjectVerdict::Ok) => {}
        }
    }

    /// The daemon did not give a usable answer. Alert after the grace, keep
    /// showing the last known projects, and leave every project row alone.
    async fn docker_daemon_bad(
        &self,
        err: &DockerError,
        prev: Option<DockerNodeStatus>,
        now: i64,
    ) -> Result<(), RpcError> {
        let text = daemon_error_text(err);
        let mut row = hyperion_state::docker::get_project(&self.pool, DAEMON_ROW)
            .await
            .map_err(|e| db_err("docker daemon", e))?
            .unwrap_or_else(|| daemon_row("ok"));
        if row.problem_since == 0 {
            row.problem_since = now;
        }
        row.last_summary = text.clone();
        let verdict = ProjectVerdict::Problem {
            summary: text.clone(),
        };
        let transition = project_transition(
            row.alert_state != "ok",
            Some(row.problem_since),
            &verdict,
            now,
        );
        if transition == Some(ProjectTransition::Down) {
            row.alert_state = "problem".into();
        }
        hyperion_state::docker::put_project(&self.pool, &row)
            .await
            .map_err(|e| db_err("docker daemon", e))?;
        if transition == Some(ProjectTransition::Down) {
            self.notify_admins_say(
                "error",
                "ops.docker_daemon_down",
                &[("error", text.as_str())],
                ALERT_HREF,
                "docker.daemon",
            )
            .await;
        }
        let mut snap = prev.unwrap_or_default();
        snap.daemon_ok = false;
        snap.daemon_error = Some(text);
        *self.docker_snapshot.write().await = Some(snap);
        Ok(())
    }

    /// The daemon answered: close its streak, and say so if it had alerted.
    async fn docker_daemon_ok(&self, now: i64) -> Result<(), RpcError> {
        let Some(mut row) = hyperion_state::docker::get_project(&self.pool, DAEMON_ROW)
            .await
            .map_err(|e| db_err("docker daemon", e))?
        else {
            return Ok(());
        };
        if row.problem_since == 0 && row.alert_state == "ok" {
            return Ok(());
        }
        let transition =
            project_transition(row.alert_state != "ok", None, &ProjectVerdict::Ok, now);
        row = daemon_row("ok");
        hyperion_state::docker::put_project(&self.pool, &row)
            .await
            .map_err(|e| db_err("docker daemon", e))?;
        if transition == Some(ProjectTransition::Up) {
            self.notify_admins_say(
                "info",
                "ops.docker_daemon_up",
                &[],
                ALERT_HREF,
                "docker.daemon",
            )
            .await;
        }
        Ok(())
    }

    /// `docker system df`, at most hourly. A failed read is not retried
    /// before the hour is up either, and the older figures stay.
    async fn docker_refresh_disk(&self, now: i64) -> Option<DockerDisk> {
        let module = hyperion_state::docker::get_module(&self.pool).await.ok()?;
        let cached = serde_json::from_str::<DockerDisk>(&module.disk_json).ok();
        if module.disk_at > 0 && now - module.disk_at < DF_EVERY_SECS {
            return cached;
        }
        let read = match self
            .adapters
            .docker_read(DockerCmd::SystemDf, JSON_MAX_BYTES)
            .await
        {
            Ok(raw) => parse_system_df(&raw).ok(),
            Err(e) => {
                tracing::debug!(error = %e, "docker system df skipped");
                None
            }
        };
        match read {
            Some(mut d) => {
                d.read_at = now;
                let json = serde_json::to_string(&d).unwrap_or_default();
                let _ = hyperion_state::docker::set_disk(&self.pool, &json, now).await;
                Some(d)
            }
            None => {
                let _ = hyperion_state::docker::set_disk(&self.pool, &module.disk_json, now).await;
                cached
            }
        }
    }

    async fn docker_cached_disk(&self) -> Option<DockerDisk> {
        let module = hyperion_state::docker::get_module(&self.pool).await.ok()?;
        serde_json::from_str(&module.disk_json).ok()
    }
}

fn daemon_row(state: &str) -> ProjectRow {
    ProjectRow {
        project: DAEMON_ROW.into(),
        alert_state: state.into(),
        ..Default::default()
    }
}

/// One line saying what is wrong with the daemon. It is docker's own error
/// line at most (stderr, never container logs), and a read that cannot be
/// parsed is reported without quoting what was unparseable.
fn daemon_error_text(e: &DockerError) -> String {
    match e {
        DockerError::NotInstalled => "Docker is not installed on this node".into(),
        DockerError::NotResponding => "the Docker daemon is not responding".into(),
        DockerError::Failed(t) => {
            let line = t.lines().next().unwrap_or("").trim();
            let line: String = line.chars().filter(|c| !c.is_control()).take(200).collect();
            if line.is_empty() {
                "docker failed".into()
            } else {
                format!("docker failed: {line}")
            }
        }
        DockerError::Parse(_) => "Docker's output could not be read".into(),
    }
}

/// A label or name from the host's containers, safe to show and to key on:
/// no control characters, bounded, and never shaped like the reserved daemon
/// row.
fn clean_name(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(NAME_MAX_CHARS)
        .collect();
    if out.starts_with('(') {
        out.replace_range(0..1, "_");
    }
    out
}

pub(super) fn daemon_silent() -> RpcError {
    RpcError::Validation {
        message: "Docker is installed but its daemon is not responding. Start Docker and \
                  try again."
            .into(),
    }
}
