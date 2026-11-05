//! The Docker module through a REAL agent's socket: what the panel would ask,
//! printed as JSON. A test harness for checks on a node, not a CLI.
//!
//! Ignored by default: it needs a running agent, as root, on the node under
//! test. `DOCKER_RPC` picks the request:
//!
//! ```text
//! DOCKER_RPC=install  cargo test --release -p hyperion-core --test docker_live_rpc -- --ignored --nocapture
//! ```
//!
//! * `status`, `install`, `remove`, `overview`: the call of that name.
//! * `logs`: `DOCKER_PROJECT` (may be empty), optional `DOCKER_CONTAINER`,
//!   `DOCKER_LINES`, `DOCKER_FILTER`, `DOCKER_CURSOR`. Prints the line count,
//!   the bytes of text, the first and the last line rather than every line.
//! * `forget`: `DOCKER_PROJECT`.
//! * `updates`: the image answers from the overview. The daily check itself
//!   has no RPC; the agent's tick runs it.
//!
//! `DOCKER_SOCKET` overrides `/run/hyperion.sock`.

use hyperion_rpc::codec::{Request, Response};
use hyperion_types::docker::DockerLogRequest;
use std::path::PathBuf;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn ask(req: Request) -> Response {
    let socket = PathBuf::from(env("DOCKER_SOCKET").unwrap_or_else(|| "/run/hyperion.sock".into()));
    hyperion_rpc_client::call(&socket, req)
        .await
        .expect("the agent answers on its socket")
}

fn print(resp: &Response) {
    println!("{}", serde_json::to_string_pretty(resp).expect("json"));
}

#[tokio::test]
#[ignore = "needs a running agent on this machine; DOCKER_RPC picks the request"]
async fn docker_rpc() {
    let which = env("DOCKER_RPC").expect("set DOCKER_RPC");
    match which.as_str() {
        "status" => print(&ask(Request::DockerModuleStatus).await),
        "install" => print(&ask(Request::DockerNodeInstall).await),
        "remove" => print(&ask(Request::DockerNodeRemove).await),
        "overview" => print(&ask(Request::DockerOverview).await),
        "forget" => {
            let project = env("DOCKER_PROJECT").expect("set DOCKER_PROJECT");
            print(&ask(Request::DockerForgetProject { project }).await);
        }
        "logs" => {
            let req = DockerLogRequest {
                project: env("DOCKER_PROJECT").unwrap_or_default(),
                container: env("DOCKER_CONTAINER"),
                lines: env("DOCKER_LINES").map_or(0, |v| v.parse().expect("DOCKER_LINES")),
                since_cursor: env("DOCKER_CURSOR"),
                filter: env("DOCKER_FILTER"),
                audit_actor: env("DOCKER_ACTOR"),
            };
            let resp = ask(Request::DockerLogs(req)).await;
            let Response::DockerLogs(chunk) = &resp else {
                print(&resp);
                return;
            };
            let bytes: usize = chunk.lines.iter().map(|l| l.text.len()).sum();
            println!(
                "lines={} text_bytes={bytes} truncated={} unreadable={} cursor={:?}",
                chunk.lines.len(),
                chunk.truncated,
                chunk.unreadable,
                chunk.cursor,
            );
            for l in chunk.lines.first().into_iter().chain(chunk.lines.last()) {
                let text: String = l.text.chars().take(120).collect();
                println!("{} [{}] {text}", l.ts, l.service);
            }
        }
        "updates" => {
            let resp = ask(Request::DockerOverview).await;
            let Response::DockerOverview(status) = &resp else {
                print(&resp);
                return;
            };
            for c in status.projects.iter().flat_map(|p| p.containers.iter()) {
                println!(
                    "{} image={} update={:?} checked_at={} error={:?}",
                    c.name, c.image, c.update, c.update_checked_at, c.update_error,
                );
            }
        }
        other => panic!("unknown DOCKER_RPC {other}"),
    }
}
