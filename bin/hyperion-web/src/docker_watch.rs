//! Tells the operator when a node with the Docker module stops answering.
//!
//! A dead node cannot report its stacks, and the dashboard only works out
//! `node_unreachable` when it renders, so nothing would ever say so. This
//! loop (master only, module on for the cluster only) asks each registered
//! node a cheap question, `DockerModuleStatus`, and once a node has failed
//! to answer for [`SILENT_AFTER_SECS`] hands the fact to the master agent,
//! which alerts (bell, Slack, mail) and later announces the return.
//!
//! What counts as silence is narrow. Only a TRANSPORT failure does: no
//! connection, a timeout, a reset. A node that replies, even with an error
//! or as an agent too old to know the question, is alive. A reply the
//! master cannot authenticate, a missing pin or an unknown node says
//! nothing about whether the node is up, so it neither starts nor ends a
//! silence. The streak is kept in memory: a blip shorter than the grace
//! never reaches the agent, and a restart of the panel only restarts the
//! count, because the alert state itself lives in `docker_nodes`.
//!
//! The master is never silent to itself: it is skipped.

use crate::dispatcher::DispatchError;
use crate::state::SharedState;
use hyperion_rpc::codec::{Request, Response};
use hyperion_rpc_client::RemoteClientError;
use std::collections::{HashMap, HashSet};

/// How often the nodes are asked.
const INTERVAL_SECS: u64 = 60;
/// A node must fail every probe for this long before it is called silent.
const SILENT_AFTER_SECS: i64 = 180;
/// Per node, so one wedged worker cannot hold the pass. The dispatcher has
/// its own 30 s ceiling; this one is for a hang before it gets that far.
const PROBE_TIMEOUT_SECS: u64 = 25;

pub fn spawn(state: SharedState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(INTERVAL_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut silence = Silence::default();
        loop {
            tick.tick().await;
            // Only a master has nodes to ask.
            if state.deployment_mode.read().await.as_str() != "master" {
                continue;
            }
            pass(&state, &mut silence, now_secs()).await;
        }
    });
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What one probe of a node showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// It replied, whatever it said.
    Answered,
    /// The transport failed.
    Silent,
    /// Nothing can be told either way.
    Unknown,
}

/// Reduce a dispatch result to what it shows about the node.
fn classify(r: &Result<Response, DispatchError>) -> Probe {
    match r {
        // An error reply is still a reply.
        Ok(_) => Probe::Answered,
        Err(DispatchError::NodeUnreachable { .. }) => Probe::Silent,
        Err(e) if crate::cluster_sync::is_old_agent(e) => Probe::Answered,
        // A curl failure the dispatcher did not recognise as a connect
        // problem (an empty reply, a send failure) is still the transport.
        Err(DispatchError::Remote(RemoteClientError::HttpError { .. })) => Probe::Silent,
        // Auth failures, a missing pin, an unknown or unreachable-by-config
        // node, a local problem: not evidence about the node.
        Err(_) => Probe::Unknown,
    }
}

/// What to tell the agent after a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Nothing,
    /// The grace has run out: flag the node silent.
    MarkSilent,
    /// A node flagged silent replied: announce it is back.
    MarkBack,
}

/// When each node's current run of failed probes began.
#[derive(Default)]
struct Silence {
    failing_since: HashMap<String, i64>,
}

impl Silence {
    /// Fold one probe in. `flagged` is what the agent has recorded (alerted
    /// and not yet recovered); the decision never depends on this loop
    /// having been the one to flag it, so a restart loses nothing.
    fn observe(&mut self, node: &str, probe: Probe, flagged: bool, now: i64) -> Step {
        match probe {
            Probe::Answered => {
                self.failing_since.remove(node);
                if flagged {
                    Step::MarkBack
                } else {
                    Step::Nothing
                }
            }
            Probe::Silent => {
                let since = *self.failing_since.entry(node.to_string()).or_insert(now);
                if !flagged && now - since >= SILENT_AFTER_SECS {
                    Step::MarkSilent
                } else {
                    Step::Nothing
                }
            }
            Probe::Unknown => Step::Nothing,
        }
    }

    /// Forget nodes that are no longer registered.
    fn retain(&mut self, keep: &HashSet<String>) {
        self.failing_since.retain(|n, _| keep.contains(n));
    }
}

/// One pass over every registered node.
async fn pass(state: &SharedState, silence: &mut Silence, now: i64) {
    let list = match local(state, Request::DockerNodeList).await {
        Some(Response::DockerNodeList(l)) => l,
        _ => return,
    };
    // Module off for the cluster: nothing is watched and nothing is said.
    // Turning it off deleted the node rows, open silences included.
    if !list.cluster_installed {
        silence.retain(&HashSet::new());
        return;
    }
    let mut probes = tokio::task::JoinSet::new();
    let mut keep = HashSet::new();
    for entry in list.nodes {
        // The master itself (`local`, or its hostname) is never silent.
        let Some(target) = crate::dispatcher::remote_target(state, Some(&entry.node_id))
            .await
            .map(str::to_string)
        else {
            continue;
        };
        keep.insert(entry.node_id.clone());
        let state = state.clone();
        probes.spawn(async move {
            let asked = tokio::time::timeout(
                std::time::Duration::from_secs(PROBE_TIMEOUT_SECS),
                crate::dispatcher::dispatch_to_node(
                    &state,
                    Some(&target),
                    Request::DockerModuleStatus,
                ),
            )
            .await;
            let probe = match asked {
                Ok(r) => classify(&r),
                Err(_) => Probe::Silent,
            };
            (entry, probe)
        });
    }
    silence.retain(&keep);
    let mut results = Vec::new();
    while let Some(done) = probes.join_next().await {
        if let Ok(r) = done {
            results.push(r);
        }
    }
    // Same order every pass, so the alerts of one pass come out the same.
    results.sort_by(|a, b| a.0.node_id.cmp(&b.0.node_id));
    for (entry, probe) in results {
        let silent = match silence.observe(&entry.node_id, probe, entry.silent, now) {
            Step::Nothing => continue,
            Step::MarkSilent => true,
            Step::MarkBack => false,
        };
        match local(
            state,
            Request::DockerNodeSilent {
                node_id: entry.node_id.clone(),
                silent,
            },
        )
        .await
        {
            Some(Response::DockerNodeSilent { changed }) => {
                if changed {
                    tracing::info!(node = %entry.node_id, silent, "docker: node state changed");
                }
            }
            other => {
                tracing::warn!(node = %entry.node_id, ?other, "docker: could not record node state");
            }
        }
    }
}

async fn local(state: &SharedState, req: Request) -> Option<Response> {
    hyperion_rpc_client::call(&state.agent_socket, req)
        .await
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unreachable() -> DispatchError {
        DispatchError::NodeUnreachable {
            node_id: "n".into(),
            kind: "x".into(),
        }
    }

    fn http(code: i32) -> DispatchError {
        DispatchError::Remote(RemoteClientError::HttpError {
            code: Some(code),
            stderr: String::new(),
        })
    }

    #[test]
    fn only_a_transport_failure_is_silence() {
        assert_eq!(classify(&Err(unreachable())), Probe::Silent);
        assert_eq!(classify(&Err(http(52))), Probe::Silent, "empty reply");
        // It answered, and said it does not know the question.
        assert_eq!(classify(&Err(http(22))), Probe::Answered, "old agent");
        // It answered with an error, which is still an answer.
        let refused = Response::Error(hyperion_rpc::RpcError::Internal {
            message: "boom".into(),
        });
        assert_eq!(classify(&Ok(refused)), Probe::Answered);
        // Nothing here says whether the node is up.
        for e in [
            DispatchError::ResponseAuthFailed {
                node_id: "n".into(),
                reason: "bad".into(),
            },
            DispatchError::CertPinMissing {
                node_id: "n".into(),
            },
            DispatchError::UnknownNode("n".into()),
            DispatchError::NoEndpoint("n".into()),
            DispatchError::NoSigner,
            DispatchError::Remote(RemoteClientError::Parse("x".into())),
        ] {
            assert_eq!(classify(&Err(e)), Probe::Unknown);
        }
    }

    #[test]
    fn a_blip_shorter_than_the_grace_never_flags() {
        let mut s = Silence::default();
        for t in [0, 60, 120] {
            assert_eq!(
                s.observe("a", Probe::Silent, false, t),
                Step::Nothing,
                "{t}"
            );
        }
        // It answers before the grace is up: the streak starts over.
        assert_eq!(s.observe("a", Probe::Answered, false, 150), Step::Nothing);
        for t in [180, 240, 300] {
            assert_eq!(
                s.observe("a", Probe::Silent, false, t),
                Step::Nothing,
                "{t}"
            );
        }
        assert_eq!(s.observe("a", Probe::Silent, false, 360), Step::MarkSilent);
    }

    #[test]
    fn three_minutes_of_failures_flag_once_and_a_reply_announces_the_return() {
        let mut s = Silence::default();
        assert_eq!(s.observe("a", Probe::Silent, false, 1000), Step::Nothing);
        assert_eq!(s.observe("a", Probe::Silent, false, 1060), Step::Nothing);
        assert_eq!(s.observe("a", Probe::Silent, false, 1120), Step::Nothing);
        assert_eq!(s.observe("a", Probe::Silent, false, 1180), Step::MarkSilent);
        // The agent now has it recorded; further failures say nothing more.
        assert_eq!(s.observe("a", Probe::Silent, true, 1240), Step::Nothing);
        assert_eq!(s.observe("a", Probe::Answered, true, 1300), Step::MarkBack);
        assert_eq!(
            s.observe("a", Probe::Answered, false, 1360),
            Step::Nothing,
            "recovered means recovered"
        );
    }

    #[test]
    fn a_restart_mid_silence_still_announces_the_return() {
        // A fresh tracker, a node the agent has flagged: the first reply
        // closes it, though this loop never saw the failures.
        let mut s = Silence::default();
        assert_eq!(s.observe("a", Probe::Answered, true, 5), Step::MarkBack);
    }

    #[test]
    fn an_unreadable_probe_neither_starts_nor_ends_a_silence() {
        let mut s = Silence::default();
        assert_eq!(s.observe("a", Probe::Unknown, false, 0), Step::Nothing);
        assert!(s.failing_since.is_empty(), "no streak began");
        assert_eq!(s.observe("a", Probe::Silent, false, 10), Step::Nothing);
        assert_eq!(s.observe("a", Probe::Unknown, false, 100), Step::Nothing);
        assert_eq!(
            s.observe("a", Probe::Silent, false, 190),
            Step::MarkSilent,
            "the unreadable probe did not reset the streak"
        );
        assert_eq!(
            s.observe("a", Probe::Unknown, true, 250),
            Step::Nothing,
            "and it does not announce a return either"
        );
    }

    #[test]
    fn nodes_are_counted_apart_and_forgotten_when_removed() {
        let mut s = Silence::default();
        s.observe("a", Probe::Silent, false, 0);
        s.observe("b", Probe::Silent, false, 100);
        assert_eq!(s.observe("a", Probe::Silent, false, 180), Step::MarkSilent);
        assert_eq!(s.observe("b", Probe::Silent, false, 180), Step::Nothing);
        s.retain(&["b".to_string()].into_iter().collect());
        assert!(!s.failing_since.contains_key("a"));
        assert!(s.failing_since.contains_key("b"));
    }
}
