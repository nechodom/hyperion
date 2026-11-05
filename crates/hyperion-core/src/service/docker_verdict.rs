//! What counts as a Docker problem. Pure functions over what the adapter
//! read, so every row of the design's table is a unit test and the tick
//! only has to keep the books.

use hyperion_types::docker::DockerContainer;
use std::collections::HashMap;

/// A state must last this long before it alerts, so a `compose up -d` or a
/// daemon restart stays quiet.
pub(super) const ALERT_GRACE_SECS: i64 = 180;
/// Restarts are counted over this long.
pub(super) const RESTART_WINDOW_SECS: i64 = 600;
/// This many restarts inside the window make a restart loop.
pub(super) const RESTART_LOOP_RISES: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ContainerVerdict {
    Ok,
    /// Ran to completion: a job that exited 0 and is not meant to restart.
    Finished,
    Unhealthy,
    RestartLoop,
    Exited {
        code: i64,
        oom: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProjectVerdict {
    Ok,
    Problem {
        summary: String,
    },
    /// No container of the project is left.
    Gone,
}

/// When each compose service's restart count was seen to rise, keyed by
/// project and service so that recreating a container keeps its history.
#[derive(Debug, Clone, Default)]
pub(super) struct RestartWatch {
    pub rises: HashMap<(String, String), Vec<i64>>,
}

impl RestartWatch {
    /// Rises of this service inside the window ending at `now`.
    pub fn in_window(&self, project: &str, service: &str, now: i64) -> u32 {
        self.rises
            .get(&(project.to_string(), service.to_string()))
            .map_or(0, |v| {
                v.iter().filter(|&&t| t > now - RESTART_WINDOW_SECS).count() as u32
            })
    }
}

/// The key a container's restarts are filed under: its compose service, or
/// its own name when it has none.
pub(super) fn service_key(c: &DockerContainer) -> &str {
    if c.service.is_empty() {
        &c.name
    } else {
        &c.service
    }
}

pub(super) fn container_verdict(c: &DockerContainer, restarts_in_window: u32) -> ContainerVerdict {
    match c.state.as_str() {
        "running" => {
            if c.health.as_deref() == Some("unhealthy") {
                ContainerVerdict::Unhealthy
            } else if restarts_in_window >= RESTART_LOOP_RISES {
                ContainerVerdict::RestartLoop
            } else {
                ContainerVerdict::Ok
            }
        }
        "restarting" => ContainerVerdict::RestartLoop,
        // `OOMKilled` describes the last exit, so it only matters once the
        // container is not running again.
        "exited" | "dead" => {
            // `on-failure` restarts only a non-zero exit, so an exit 0 stays
            // down like a job's and is not a problem.
            if c.finished_job() {
                ContainerVerdict::Finished
            } else {
                ContainerVerdict::Exited {
                    code: c.exit_code,
                    oom: c.oom_killed,
                }
            }
        }
        // A container Docker made but could not start stays `created` with
        // the failure's exit code. One that is still starting has code 0,
        // and the grace period covers the rest.
        "created" if c.failed_to_start() => ContainerVerdict::Exited {
            code: c.exit_code,
            oom: false,
        },
        // created, paused, removing: transitions, not failures.
        _ => ContainerVerdict::Ok,
    }
}

pub(super) fn project_verdict(
    containers: &[DockerContainer],
    watch: &RestartWatch,
    now: i64,
) -> ProjectVerdict {
    let mut real = containers.iter().filter(|c| !c.oneoff).peekable();
    if real.peek().is_none() {
        return ProjectVerdict::Gone;
    }
    // One entry per (service, cause), so three replicas of a broken service
    // read as one line.
    let mut problems: Vec<(String, String)> = Vec::new();
    for c in real {
        let service = service_key(c);
        let rises = watch.in_window(&c.project, service, now);
        let cause = match container_verdict(c, rises) {
            ContainerVerdict::Ok | ContainerVerdict::Finished => continue,
            ContainerVerdict::Unhealthy => "unhealthy".to_string(),
            ContainerVerdict::RestartLoop => "restart loop".to_string(),
            ContainerVerdict::Exited { code, oom: true } => {
                format!("exit {code}, out of memory")
            }
            ContainerVerdict::Exited { code, oom: false } => format!("exit {code}"),
        };
        let line = (service.to_string(), cause);
        if !problems.contains(&line) {
            problems.push(line);
        }
    }
    if problems.is_empty() {
        return ProjectVerdict::Ok;
    }
    problems.sort();
    let summary = problems
        .iter()
        .map(|(service, cause)| format!("{service}: {cause}"))
        .collect::<Vec<_>>()
        .join("; ");
    ProjectVerdict::Problem { summary }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectTransition {
    Down,
    Up,
}

/// Whether to alert now. `alerting`: a Down went out and no Up yet.
/// `problem_since`: when the current streak of trouble began, `None` while
/// all is well. A streak shorter than [`ALERT_GRACE_SECS`] never alerts.
pub(super) fn project_transition(
    alerting: bool,
    problem_since: Option<i64>,
    verdict: &ProjectVerdict,
    now: i64,
) -> Option<ProjectTransition> {
    match verdict {
        ProjectVerdict::Ok => alerting.then_some(ProjectTransition::Up),
        ProjectVerdict::Problem { .. } | ProjectVerdict::Gone => {
            let lasted = now - problem_since?;
            (!alerting && lasted >= ALERT_GRACE_SECS).then_some(ProjectTransition::Down)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 10_000;

    fn running(service: &str) -> DockerContainer {
        DockerContainer {
            id: format!("id-{service}"),
            name: format!("p-{service}-1"),
            project: "p".into(),
            service: service.into(),
            state: "running".into(),
            restart_policy: "no".into(),
            ..Default::default()
        }
    }

    fn exited(service: &str, policy: &str, code: i64) -> DockerContainer {
        DockerContainer {
            state: "exited".into(),
            restart_policy: policy.into(),
            exit_code: code,
            ..running(service)
        }
    }

    fn created(service: &str, code: i64) -> DockerContainer {
        DockerContainer {
            state: "created".into(),
            exit_code: code,
            ..running(service)
        }
    }

    fn paused(service: &str) -> DockerContainer {
        DockerContainer {
            state: "paused".into(),
            ..running(service)
        }
    }

    fn watch_with(service: &str, rises: &[i64]) -> RestartWatch {
        let mut w = RestartWatch::default();
        w.rises.insert(("p".into(), service.into()), rises.to_vec());
        w
    }

    #[test]
    fn verdict_table() {
        use ContainerVerdict::*;
        let healthy = DockerContainer {
            health: Some("healthy".into()),
            ..running("a")
        };
        let unhealthy = DockerContainer {
            health: Some("unhealthy".into()),
            ..running("a")
        };
        let restarting = DockerContainer {
            state: "restarting".into(),
            ..running("a")
        };
        let oom = DockerContainer {
            oom_killed: true,
            ..exited("a", "no", 137)
        };
        for (name, c, restarts, want) in [
            ("running, no healthcheck", running("a"), 0, Ok),
            ("running, healthy", healthy, 0, Ok),
            ("running, unhealthy", unhealthy, 0, Unhealthy),
            ("restarting", restarting, 0, RestartLoop),
            ("running, 2 restarts", running("a"), 2, Ok),
            ("running, 3 restarts", running("a"), 3, RestartLoop),
            ("job: policy no, exit 0", exited("a", "no", 0), 0, Finished),
            (
                "policy no, exit 1",
                exited("a", "no", 1),
                0,
                Exited {
                    code: 1,
                    oom: false,
                },
            ),
            (
                "on-failure, exit 0",
                exited("a", "on-failure", 0),
                0,
                Finished,
            ),
            (
                "on-failure, exit 1",
                exited("a", "on-failure", 1),
                0,
                Exited {
                    code: 1,
                    oom: false,
                },
            ),
            (
                "on-failure, exit 0 but out of memory",
                DockerContainer {
                    oom_killed: true,
                    ..exited("a", "on-failure", 0)
                },
                0,
                Exited { code: 0, oom: true },
            ),
            ("no policy named, exit 0", exited("a", "", 0), 0, Finished),
            ("created, still starting", created("a", 0), 0, Ok),
            (
                "created, start failed",
                created("a", 128),
                0,
                Exited {
                    code: 128,
                    oom: false,
                },
            ),
            ("paused", paused("a"), 0, Ok),
            (
                "policy always, exit 0",
                exited("a", "always", 0),
                0,
                Exited {
                    code: 0,
                    oom: false,
                },
            ),
            (
                "oom killed",
                oom,
                0,
                Exited {
                    code: 137,
                    oom: true,
                },
            ),
        ] {
            assert_eq!(container_verdict(&c, restarts), want, "{name}");
        }
    }

    #[test]
    fn a_project_of_finished_jobs_and_healthy_services_is_ok() {
        let cs = [running("web"), exited("migrate", "no", 0)];
        assert_eq!(
            project_verdict(&cs, &RestartWatch::default(), NOW),
            ProjectVerdict::Ok
        );
        let only_jobs = [exited("migrate", "no", 0)];
        assert_eq!(
            project_verdict(&only_jobs, &RestartWatch::default(), NOW),
            ProjectVerdict::Ok,
            "a project of only finished services is not gone and not a problem"
        );
    }

    #[test]
    fn the_summary_names_service_exit_code_and_cause_and_nothing_else() {
        let oom = DockerContainer {
            oom_killed: true,
            ..exited("worker", "no", 137)
        };
        let sick = DockerContainer {
            health: Some("unhealthy".into()),
            ..running("web")
        };
        let ProjectVerdict::Problem { summary } =
            project_verdict(&[sick, oom, running("db")], &RestartWatch::default(), NOW)
        else {
            panic!("expected a problem");
        };
        assert_eq!(
            summary, "web: unhealthy; worker: exit 137, out of memory",
            "sorted by service, healthy ones left out"
        );
    }

    #[test]
    fn restart_rises_are_counted_inside_the_window_only() {
        let w = watch_with("web", &[NOW - 700, NOW - 500, NOW - 100, NOW - 10]);
        assert_eq!(w.in_window("p", "web", NOW), 3);
        assert_eq!(w.in_window("p", "other", NOW), 0);
        let ProjectVerdict::Problem { summary } = project_verdict(&[running("web")], &w, NOW)
        else {
            panic!("three rises make a loop");
        };
        assert_eq!(summary, "web: restart loop");
    }

    #[test]
    fn one_off_containers_count_as_nothing() {
        let job = DockerContainer {
            oneoff: true,
            ..exited("run", "no", 1)
        };
        assert_eq!(
            project_verdict(
                &[running("web"), job.clone()],
                &RestartWatch::default(),
                NOW
            ),
            ProjectVerdict::Ok
        );
        assert_eq!(
            project_verdict(&[job], &RestartWatch::default(), NOW),
            ProjectVerdict::Gone,
            "only one-off containers left is no project"
        );
    }

    #[test]
    fn no_containers_is_gone() {
        assert_eq!(
            project_verdict(&[], &RestartWatch::default(), NOW),
            ProjectVerdict::Gone
        );
    }

    fn bad() -> ProjectVerdict {
        ProjectVerdict::Problem {
            summary: "web: unhealthy".into(),
        }
    }

    #[test]
    fn no_alert_inside_grace() {
        let t = 5_000;
        for dt in [0, 1, 60, ALERT_GRACE_SECS - 1] {
            assert_eq!(
                project_transition(false, Some(t), &bad(), t + dt),
                None,
                "t+{dt}"
            );
        }
        assert_eq!(
            project_transition(false, Some(t), &bad(), t + ALERT_GRACE_SECS),
            Some(ProjectTransition::Down)
        );
        assert_eq!(
            project_transition(true, Some(t), &bad(), t + 600),
            None,
            "one Down per streak"
        );
        assert_eq!(
            project_transition(false, Some(t), &ProjectVerdict::Gone, t + ALERT_GRACE_SECS),
            Some(ProjectTransition::Down)
        );
    }

    #[test]
    fn redeploy_is_quiet_and_recovery_after_an_alert_is_up() {
        assert_eq!(
            project_transition(false, None, &ProjectVerdict::Ok, 5_120),
            None,
            "a problem that cleared before the grace never alerted"
        );
        assert_eq!(
            project_transition(true, Some(5_000), &ProjectVerdict::Ok, 5_400),
            Some(ProjectTransition::Up)
        );
    }
}
