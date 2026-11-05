//! Read-only Docker adapter. This is the only code in Hyperion that runs
//! `docker`, and every command it can build is a read (`version`, `ps`,
//! `inspect`, `logs`, `stats`, `system df`, `image inspect`, `buildx
//! imagetools inspect`).
//!
//! Secrets stay out by construction: inspect output is deserialised into
//! private structs that have no `Env` field and that keep only
//! `com.docker.compose.*` labels, so nothing else can reach a caller.

use hyperion_types::docker::{DockerContainer, DockerDisk, DockerPort};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

const DOCKER_PATHS: &[&str] = &["/usr/bin/docker", "/usr/local/bin/docker"];
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const SYSTEM_DF_TIMEOUT: Duration = Duration::from_secs(120);
/// A registry round trip, token included, on a slow link.
const IMAGETOOLS_TIMEOUT: Duration = Duration::from_secs(45);
/// What every `--format` is given. The word `json` as a format needs a CLI of
/// 23.0 or newer; the template below is what it stands for and every CLI
/// that can print JSON at all understands it (checked on a node: the output
/// of both is byte for byte the same on 29.x).
const JSON_FORMAT: &str = "{{json .}}";
/// Longest stderr text carried in `DockerError::Failed`.
const FAILED_TEXT_MAX: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DockerError {
    #[error("docker is not installed")]
    NotInstalled,
    #[error("docker is not responding")]
    NotResponding,
    #[error("docker failed: {0}")]
    Failed(String),
    #[error("cannot read docker output: {0}")]
    Parse(String),
}

/// A container id: 12 to 64 lowercase hex digits. Never starts with `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainerId(String);

impl ContainerId {
    pub fn parse(s: &str) -> Result<Self, DockerError> {
        let ok = (12..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if ok {
            Ok(Self(s.to_string()))
        } else {
            Err(DockerError::Parse(format!("not a container id: {s:?}")))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An image reference. No leading `-`, charset `[A-Za-z0-9._:/@-]`, at most 512.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef(String);

impl ImageRef {
    pub fn parse(s: &str) -> Result<Self, DockerError> {
        let ok = !s.is_empty()
            && s.len() <= 512
            && !s.starts_with('-')
            && s.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
            });
        if ok {
            Ok(Self(s.to_string()))
        } else {
            Err(DockerError::Parse(format!("not an image reference: {s:?}")))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerCmd {
    Version,
    BuildxVersion,
    PsAll,
    Inspect(Vec<ContainerId>),
    Logs {
        id: ContainerId,
        tail: u32,
        since: Option<i64>,
    },
    Stats,
    SystemDf,
    ImageInspect(ImageRef),
    /// Ask a registry for the digest of a tag, with whatever credentials
    /// Docker's own store holds. Reads the registry's manifest; it pulls no
    /// layer.
    ImagetoolsInspect(ImageRef),
}

impl DockerCmd {
    pub fn args(&self) -> Vec<String> {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        match self {
            Self::Version => s(&["version", "--format", JSON_FORMAT]),
            Self::BuildxVersion => s(&["buildx", "version"]),
            Self::PsAll => s(&["ps", "--all", "--no-trunc", "--format", JSON_FORMAT]),
            Self::Inspect(ids) => {
                let mut a = s(&["inspect", "--type", "container"]);
                a.extend(ids.iter().map(|i| i.0.clone()));
                a
            }
            Self::Logs { id, tail, since } => {
                // Timestamps so stdout and stderr lines can be merged by time.
                let mut a = s(&["logs", "--timestamps", "--tail"]);
                a.push(tail.to_string());
                if let Some(t) = since {
                    a.push("--since".into());
                    a.push(t.to_string());
                }
                a.push(id.0.clone());
                a
            }
            Self::Stats => s(&[
                "stats",
                "--no-stream",
                "--no-trunc",
                "--format",
                JSON_FORMAT,
            ]),
            Self::SystemDf => s(&["system", "df", "--format", JSON_FORMAT]),
            Self::ImageInspect(r) => {
                let mut a = s(&["image", "inspect"]);
                a.push(r.0.clone());
                a
            }
            Self::ImagetoolsInspect(r) => {
                let mut a = s(&["buildx", "imagetools", "inspect"]);
                a.push(r.0.clone());
                a
            }
        }
    }

    fn timeout(&self) -> Duration {
        match self {
            Self::SystemDf => SYSTEM_DF_TIMEOUT,
            Self::ImagetoolsInspect(_) => IMAGETOOLS_TIMEOUT,
            _ => DEFAULT_TIMEOUT,
        }
    }
}

/// Run one read command against the system docker, returning at most
/// `max_bytes` of its output.
///
/// The raw output may hold `Config.Env` and other secrets (inspect). It goes
/// only to a `parse_*` function in this module and is never logged or sent
/// over RPC.
pub async fn run(cmd: &DockerCmd, max_bytes: usize) -> Result<Vec<u8>, DockerError> {
    let bin = DOCKER_PATHS
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .ok_or(DockerError::NotInstalled)?;
    run_with(bin, cmd, max_bytes, cmd.timeout()).await
}

enum Chunk {
    Out(Vec<u8>),
    Err(Vec<u8>),
}

async fn pump<R: tokio::io::AsyncRead + Unpin>(
    r: R,
    limit: usize,
    tx: tokio::sync::mpsc::UnboundedSender<Chunk>,
    is_err: bool,
) {
    // `take` bounds what this stream can ever hold, lines included.
    let mut r = BufReader::new(r.take(limit as u64 + 1));
    loop {
        let mut line = Vec::new();
        match r.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                let c = if is_err {
                    Chunk::Err(line)
                } else {
                    Chunk::Out(line)
                };
                if tx.send(c).is_err() {
                    return;
                }
            }
        }
    }
}

pub(crate) async fn run_with(
    binary: &Path,
    cmd: &DockerCmd,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, DockerError> {
    let mut child = Command::new(binary)
        .args(cmd.args())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => DockerError::NotInstalled,
            _ => DockerError::Failed(format!("cannot start docker: {e}")),
        })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let merge = matches!(cmd, DockerCmd::Logs { .. });

    let work = async {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        if let Some(o) = stdout {
            tokio::spawn(pump(o, max_bytes, tx.clone(), false));
        }
        if let Some(e) = stderr {
            tokio::spawn(pump(e, max_bytes, tx.clone(), true));
        }
        drop(tx);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut truncated = false;
        while let Some(c) = rx.recv().await {
            match c {
                Chunk::Out(b) => out.extend_from_slice(&b),
                // Logs: container stderr arrives on our stderr; keep the
                // lines in arrival order with the rest.
                // stderr is also kept on its own, so a failing `docker logs`
                // can be told from a container that wrote to stderr.
                Chunk::Err(b) => {
                    err.extend_from_slice(&b);
                    if merge {
                        out.extend_from_slice(&b);
                    }
                }
            }
            let held = if merge {
                out.len()
            } else {
                out.len() + err.len()
            };
            if held > max_bytes {
                truncated = true;
                let _ = child.start_kill();
                break;
            }
        }
        let status = if truncated {
            None
        } else {
            child.wait().await.ok()
        };
        (out, err, status, truncated)
    };

    let (mut out, err, status, truncated) = match tokio::time::timeout(timeout, work).await {
        Ok(r) => r,
        Err(_) => {
            let _ = child.start_kill();
            reap(child.wait()).await;
            return Err(DockerError::NotResponding);
        }
    };
    if truncated {
        reap(child.wait()).await;
        // A killed run is not a failure when it produced output. With no
        // stdout, a flood of stderr is one: empty must not read as "nothing".
        if !out.is_empty() {
            out.truncate(max_bytes);
            return Ok(out);
        }
    } else if merge {
        // `docker logs` exits 0 whatever the container did, so a non-zero
        // exit is docker's own failure, not log text.
        if status.is_some_and(|s| s.success()) {
            return Ok(out);
        }
    } else if status.is_some_and(|s| s.success()) || !out.is_empty() {
        return Ok(out);
    }
    let mut text = String::from_utf8_lossy(&err).trim().to_string();
    if text.contains("Cannot connect to the Docker daemon") {
        return Err(DockerError::NotResponding);
    }
    if text.is_empty() {
        text = match status.and_then(|s| s.code()) {
            Some(c) => format!("docker exited with status {c}"),
            None => "docker exited abnormally".to_string(),
        };
    }
    if text.len() > FAILED_TEXT_MAX {
        let mut n = FAILED_TEXT_MAX;
        while !text.is_char_boundary(n) {
            n -= 1;
        }
        text.truncate(n);
    }
    Err(DockerError::Failed(text))
}

/// How long to wait for a killed `docker` to be collected. A process stuck
/// in the kernel (a hung mount under a log file, say) survives SIGKILL for as
/// long as the kernel holds it; the read has already been answered, so it
/// must not wait that long too. `kill_on_drop` finishes the job later.
const REAP_WAIT: Duration = Duration::from_secs(2);

async fn reap<F: std::future::Future>(wait: F) -> Option<F::Output> {
    reap_within(wait, REAP_WAIT).await
}

async fn reap_within<F: std::future::Future>(wait: F, limit: Duration) -> Option<F::Output> {
    tokio::time::timeout(limit, wait).await.ok()
}

fn jerr(e: serde_json::Error) -> DockerError {
    DockerError::Parse(e.to_string())
}

fn jsonl<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<Vec<T>, DockerError> {
    bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
        .map(|l| serde_json::from_slice(l).map_err(jerr))
        .collect()
}

#[derive(Deserialize)]
struct PsRow {
    #[serde(rename = "ID")]
    id: String,
}

/// Container ids from `docker ps --format '{{json .}}'`. Everything else in a ps
/// row (labels included) is dropped here.
pub fn parse_ps(bytes: &[u8]) -> Result<Vec<ContainerId>, DockerError> {
    jsonl::<PsRow>(bytes)?
        .into_iter()
        .map(|r| ContainerId::parse(&r.id))
        .collect()
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectRow {
    id: String,
    name: String,
    image: String,
    log_path: String,
    restart_count: i64,
    state: InspectState,
    config: InspectConfig,
    host_config: InspectHost,
    network_settings: InspectNet,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectState {
    status: String,
    exit_code: i64,
    #[serde(rename = "OOMKilled")]
    oom_killed: bool,
    started_at: String,
    finished_at: String,
    health: Option<InspectHealth>,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectHealth {
    status: String,
}
// No `Env` here: it cannot be returned if it is never read.
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectConfig {
    image: String,
    labels: Option<HashMap<String, String>>,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectHost {
    restart_policy: InspectRestart,
    log_config: InspectLog,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectRestart {
    name: String,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectLog {
    config: Option<HashMap<String, String>>,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectNet {
    ports: Option<HashMap<String, Option<Vec<InspectBind>>>>,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectBind {
    host_ip: String,
    host_port: String,
}

/// Unix seconds of an RFC 3339 UTC stamp as Docker writes it. 0 for the
/// zero time ("0001-01-01...") and for anything unreadable.
fn rfc3339_secs(s: &str) -> i64 {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' {
        return 0;
    }
    let num = |a: usize, z: usize| s.get(a..z).and_then(|x| x.parse::<i64>().ok());
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se)) = (
        num(0, 4),
        num(5, 7),
        num(8, 10),
        num(11, 13),
        num(14, 16),
        num(17, 19),
    ) else {
        return 0;
    };
    if y < 1970 || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return 0;
    }
    // Days from civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + h * 3600 + mi * 60 + se
}

/// Facts from `docker inspect`. `Config.Env` and every label outside
/// `com.docker.compose.*` are never read.
pub fn parse_inspect(bytes: &[u8]) -> Result<Vec<DockerContainer>, DockerError> {
    let rows: Vec<InspectRow> = serde_json::from_slice(bytes).map_err(jerr)?;
    Ok(rows.into_iter().map(container_of).collect())
}

fn container_of(r: InspectRow) -> DockerContainer {
    let label = |k: &str| {
        r.config
            .labels
            .as_ref()
            .and_then(|m| m.get(&format!("com.docker.compose.{k}")))
            .cloned()
            .unwrap_or_default()
    };
    let mut ports = Vec::new();
    for (key, binds) in r.network_settings.ports.iter().flatten() {
        let (cp, proto) = key.split_once('/').unwrap_or((key.as_str(), "tcp"));
        let Ok(container_port) = cp.parse::<u16>() else {
            continue;
        };
        for b in binds.iter().flatten() {
            if let Ok(host_port) = b.host_port.parse::<u16>() {
                ports.push(DockerPort {
                    host_ip: b.host_ip.clone(),
                    host_port,
                    container_port,
                    proto: proto.to_string(),
                });
            }
        }
    }
    ports.sort_by(|a, b| {
        (a.container_port, &a.proto, a.host_port, &a.host_ip).cmp(&(
            b.container_port,
            &b.proto,
            b.host_port,
            &b.host_ip,
        ))
    });
    DockerContainer {
        name: r.name.trim_start_matches('/').to_string(),
        project: label("project"),
        service: label("service"),
        oneoff: label("oneoff").eq_ignore_ascii_case("true"),
        working_dir: label("project.working_dir"),
        image: r.config.image,
        image_id: r.image,
        state: r.state.status,
        health: r.state.health.map(|h| h.status).filter(|h| !h.is_empty()),
        exit_code: r.state.exit_code,
        oom_killed: r.state.oom_killed,
        restart_count: r.restart_count,
        restart_policy: r.host_config.restart_policy.name,
        started_at: rfc3339_secs(&r.state.started_at),
        finished_at: rfc3339_secs(&r.state.finished_at),
        ports,
        cpu_pct_x100: None,
        mem_bytes: None,
        log_path: r.log_path,
        log_size_bytes: 0,
        log_max_size: r
            .host_config
            .log_config
            .config
            .and_then(|m| m.get("max-size").cloned()),
        update: None,
        update_checked_at: 0,
        update_error: String::new(),
        id: r.id,
    }
}

/// One container's live numbers from `docker stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerStats {
    pub id: String,
    pub name: String,
    pub cpu_pct_x100: Option<i64>,
    pub mem_bytes: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct StatsRow {
    container: String,
    #[serde(rename = "ID")]
    id: String,
    name: String,
    #[serde(rename = "CPUPerc")]
    cpu_perc: String,
    mem_usage: String,
}

pub fn parse_stats(bytes: &[u8]) -> Result<Vec<ContainerStats>, DockerError> {
    Ok(jsonl::<StatsRow>(bytes)?
        .into_iter()
        .map(|r| ContainerStats {
            id: if r.container.is_empty() {
                r.id
            } else {
                r.container
            },
            name: r.name,
            cpu_pct_x100: parse_pct_x100(&r.cpu_perc),
            mem_bytes: r
                .mem_usage
                .split('/')
                .next()
                .and_then(|m| parse_size(m.trim())),
        })
        .collect())
}

fn parse_pct_x100(s: &str) -> Option<i64> {
    let v: f64 = s.trim().strip_suffix('%')?.trim().parse().ok()?;
    v.is_finite().then(|| (v * 100.0).round() as i64)
}

/// "3.43MiB", "94.6MB", "8.192kB", "0B" into bytes. Decimal for KB/MB/GB,
/// binary for KiB/MiB/GiB.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let at = s.find(|c: char| c.is_ascii_alphabetic())?;
    let v: f64 = s[..at].trim().parse().ok()?;
    let mult: f64 = match s[at..].to_ascii_lowercase().as_str() {
        "b" => 1.0,
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        "kib" => 1024.0,
        "mib" => 1024.0 * 1024.0,
        "gib" => 1024.0 * 1024.0 * 1024.0,
        "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    (v.is_finite() && v >= 0.0).then_some((v * mult) as u64)
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct DfRow {
    #[serde(rename = "Type")]
    kind: String,
    size: String,
}

pub fn parse_system_df(bytes: &[u8]) -> Result<DockerDisk, DockerError> {
    let mut d = DockerDisk {
        read_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0),
        ..Default::default()
    };
    for r in jsonl::<DfRow>(bytes)? {
        let n = parse_size(&r.size).unwrap_or(0);
        match r.kind.as_str() {
            "Images" => d.images_bytes = n,
            "Containers" => d.containers_bytes = n,
            "Local Volumes" => d.volumes_bytes = n,
            "Build Cache" => d.build_cache_bytes = n,
            _ => {}
        }
    }
    Ok(d)
}

/// What the update check needs to know about the local copy of an image, and
/// nothing else: `Config.Env`, labels, history and layers are never read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalImage {
    /// The reference the container names, as it was asked for.
    pub image_ref: String,
    /// `name@sha256:...` entries. Empty for an image that was built here on
    /// the classic store. On the containerd store (Docker 29's default) every
    /// local name gets an entry, whether or not a registry holds that digest,
    /// so `built_here` and `pulled_from` decide what they are worth.
    pub repo_digests: Vec<String>,
    /// `Id`: what a container created from this image reports as its image.
    pub image_id: String,
    /// The reference names a digest itself, so there is no tag to move.
    pub pinned: bool,
    /// `Identity` says this image was built on this node and never pulled.
    /// `false` when the daemon prints no `Identity`.
    pub built_here: bool,
    /// The repositories `Identity` says this image was pulled from. Empty when
    /// the daemon prints no `Identity`, which says nothing either way.
    pub pulled_from: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct ImageInspectRow {
    id: String,
    repo_digests: Option<Vec<String>>,
    identity: Option<ImageIdentity>,
}

/// Where an image came from (Docker 29). Only whether it was built and which
/// repositories it was pulled from are kept.
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct ImageIdentity {
    build: Option<Vec<serde::de::IgnoredAny>>,
    pull: Option<Vec<ImagePull>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct ImagePull {
    repository: String,
}

/// Facts from `docker image inspect <image_ref>`. `None` when the node has no
/// such image (docker prints `[]`). Only the image id, its repo digests and
/// where it came from are read, so `Config.Env` and every label stay where they
/// were.
pub fn parse_image_inspect(
    bytes: &[u8],
    image_ref: &str,
) -> Result<Option<LocalImage>, DockerError> {
    let rows: Vec<ImageInspectRow> = serde_json::from_slice(bytes).map_err(jerr)?;
    Ok(rows.into_iter().next().map(|r| {
        let identity = r.identity.unwrap_or_default();
        let pulled_from: Vec<String> = identity
            .pull
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.repository)
            .filter(|p| !p.is_empty())
            .collect();
        LocalImage {
            image_ref: image_ref.to_string(),
            repo_digests: r.repo_digests.unwrap_or_default(),
            image_id: r.id,
            pinned: image_ref.contains("@sha256:"),
            built_here: pulled_from.is_empty() && identity.build.is_some_and(|b| !b.is_empty()),
            pulled_from,
        }
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerVersion {
    pub client: String,
    /// `None` when the daemon did not answer.
    pub server: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct VersionDoc {
    client: Option<VersionPart>,
    server: Option<VersionPart>,
}
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct VersionPart {
    version: String,
}

pub fn parse_version(bytes: &[u8]) -> Result<DockerVersion, DockerError> {
    let d: VersionDoc = serde_json::from_slice(bytes).map_err(jerr)?;
    Ok(DockerVersion {
        client: d.client.map(|c| c.version).unwrap_or_default(),
        server: d.server.map(|s| s.version).filter(|v| !v.is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Duration;

    fn id(c: char) -> ContainerId {
        ContainerId::parse(&c.to_string().repeat(12)).unwrap()
    }

    fn sample_of_every_variant() -> Vec<DockerCmd> {
        vec![
            DockerCmd::Version,
            DockerCmd::BuildxVersion,
            DockerCmd::PsAll,
            DockerCmd::Inspect(vec![id('a'), id('b')]),
            DockerCmd::Logs {
                id: id('a'),
                tail: 100,
                since: Some(1_700_000_000),
            },
            DockerCmd::Logs {
                id: id('a'),
                tail: 5,
                since: None,
            },
            DockerCmd::Stats,
            DockerCmd::SystemDf,
            DockerCmd::ImageInspect(ImageRef::parse("nginx:alpine").unwrap()),
            DockerCmd::ImagetoolsInspect(ImageRef::parse("ghcr.io/o/app:1").unwrap()),
        ]
    }

    #[test]
    fn every_command_is_a_read() {
        const READS: &[&[&str]] = &[
            &["version"],
            &["buildx", "version"],
            &["ps"],
            &["inspect"],
            &["logs"],
            &["stats"],
            &["system", "df"],
            &["image", "inspect"],
            &["buildx", "imagetools", "inspect"],
        ];
        for cmd in sample_of_every_variant() {
            let args = cmd.args();
            assert!(
                READS.iter().any(|p| args
                    .starts_with(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>())),
                "{args:?}"
            );
        }
    }

    /// A killed process that is not collected does not hold the read up.
    #[tokio::test]
    async fn waiting_for_a_killed_child_is_bounded() {
        let started = std::time::Instant::now();
        let got = reap_within(std::future::pending::<()>(), Duration::from_millis(50)).await;
        assert!(got.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        // A child that is collected promptly is waited for as before.
        let got = reap_within(async { 7 }, Duration::from_secs(5)).await;
        assert_eq!(got, Some(7));
    }

    /// Every read that is asked for JSON asks with the template, which also
    /// older CLIs know; the bare word `json` needs a 23.0 CLI.
    #[test]
    fn json_is_asked_for_with_the_template_not_the_bare_word() {
        let mut formats = 0;
        for cmd in sample_of_every_variant() {
            let args = cmd.args();
            for pair in args.windows(2) {
                if pair[0] == "--format" {
                    formats += 1;
                    assert_eq!(pair[1], "{{json .}}", "{args:?}");
                }
            }
            assert!(!args.iter().any(|a| a == "json"), "{args:?}");
        }
        assert_eq!(formats, 4, "version, ps, stats and system df");
    }

    #[test]
    fn inspect_drops_env_and_foreign_labels() {
        let parsed =
            parse_inspect(include_bytes!("../tests/fixtures/docker/inspect.json")).unwrap();
        let out = serde_json::to_string(&parsed).unwrap();
        assert!(!out.contains("do-not-leak-7f3a"));
        assert!(!out.contains("PATH=/usr/local"));
        assert!(!out.contains("maintainer"));
    }

    #[test]
    fn inspect_reads_the_facts() {
        let parsed =
            parse_inspect(include_bytes!("../tests/fixtures/docker/inspect.json")).unwrap();
        let by = |n: &str| parsed.iter().find(|c| c.name == n).unwrap();
        let web = by("fixture-web-1");
        assert_eq!(web.service, "web");
        assert_eq!(web.project, "fixture");
        assert_eq!(web.health.as_deref(), Some("healthy"));
        assert_eq!(web.state, "running");
        assert_eq!(web.image, "nginx:alpine");
        assert!(!web.oneoff);
        assert_eq!(web.restart_policy, "unless-stopped");
        assert_eq!(
            web.ports,
            vec![DockerPort {
                host_ip: "127.0.0.1".into(),
                host_port: 18080,
                container_port: 80,
                proto: "tcp".into()
            }]
        );
        assert!(web.started_at > 1_700_000_000);
        assert_eq!(web.finished_at, 0);
        assert!(web.log_path.ends_with("-json.log"));
        let crash = by("fixture-crash-1");
        assert_eq!(crash.exit_code, 3);
        assert_eq!(crash.restart_policy, "on-failure");
        assert_eq!(crash.restart_count, 2);
        assert!(crash.finished_at >= crash.started_at && crash.finished_at > 0);
        assert_eq!(crash.health, None);
        assert_eq!(by("fixture-job-1").exit_code, 0);
        let plain = by("extra");
        assert_eq!(plain.project, "");
        assert_eq!(plain.service, "");
    }

    #[test]
    fn ps_keeps_only_ids() {
        let ids = parse_ps(include_bytes!("../tests/fixtures/docker/ps.jsonl")).unwrap();
        assert_eq!(ids.len(), 4);
        assert!(ids.iter().all(|i| i.as_str().len() == 64));
        assert_eq!(parse_ps(b"").unwrap(), vec![]);
        assert!(matches!(parse_ps(b"not json"), Err(DockerError::Parse(_))));
    }

    #[test]
    fn stats_parse() {
        let rows = parse_stats(include_bytes!("../tests/fixtures/docker/stats.jsonl")).unwrap();
        let web = rows.iter().find(|r| r.name == "fixture-web-1").unwrap();
        assert_eq!(web.cpu_pct_x100, Some(0));
        assert_eq!(web.mem_bytes, Some((3.43 * 1024.0 * 1024.0) as u64));
        assert_eq!(web.id.len(), 64);
        assert_eq!(parse_size("3.731GiB"), Some((3.731 * 1073741824.0) as u64));
        assert_eq!(parse_size("94.6MB"), Some(94_600_000));
        assert_eq!(parse_size("0B"), Some(0));
        assert_eq!(parse_size("--"), None);
        assert_eq!(parse_pct_x100("12.345%"), Some(1235));
    }

    #[test]
    fn system_df_parses() {
        let d =
            parse_system_df(include_bytes!("../tests/fixtures/docker/system_df.jsonl")).unwrap();
        assert_eq!(d.images_bytes, 94_600_000);
        assert_eq!(d.containers_bytes, 94_210);
        assert_eq!(d.volumes_bytes, 0);
        assert_eq!(d.build_cache_bytes, 0);
        assert!(d.read_at > 1_700_000_000);
    }

    #[test]
    fn imagetools_asks_the_registry_for_one_reference() {
        let args = DockerCmd::ImagetoolsInspect(ImageRef::parse("ghcr.io/o/app:1").unwrap()).args();
        assert_eq!(
            args,
            ["buildx", "imagetools", "inspect", "ghcr.io/o/app:1"],
            "no pull, no create, no push"
        );
    }

    #[test]
    fn image_inspect_reads_id_and_repo_digests_only() {
        let img = parse_image_inspect(
            include_bytes!("../tests/fixtures/docker/image_inspect.json"),
            "nginx:alpine",
        )
        .unwrap()
        .expect("one image");
        assert_eq!(
            img.image_id,
            "sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606"
        );
        assert_eq!(
            img.repo_digests,
            ["nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606"]
        );
        assert_eq!(img.image_ref, "nginx:alpine");
        assert!(!img.pinned);
    }

    #[test]
    fn image_inspect_drops_env_and_labels() {
        // Destructuring names every field the type has: a new one would stop
        // this from compiling until somebody decided it may leave the adapter.
        let raw = br#"[{
            "Id": "sha256:aa",
            "RepoTags": ["x:1"],
            "RepoDigests": ["x@sha256:bb"],
            "Config": {
                "Env": ["DB_PASSWORD=do-not-leak-7f3a"],
                "Labels": {"secret.label": "do-not-leak-7f3a"},
                "Cmd": ["--token=do-not-leak-7f3a"]
            },
            "Comment": "do-not-leak-7f3a"
        }]"#;
        let img = parse_image_inspect(raw, "x:1").unwrap().expect("image");
        let LocalImage {
            image_ref,
            repo_digests,
            image_id,
            pinned,
            built_here,
            pulled_from,
        } = &img;
        let everything = format!(
            "{image_ref} {repo_digests:?} {image_id} {pinned} {built_here} {pulled_from:?} {img:?}"
        );
        assert!(!everything.contains("do-not-leak-7f3a"), "{everything}");
        assert!(!everything.contains("DB_PASSWORD"), "{everything}");
    }

    #[test]
    fn image_inspect_of_a_missing_or_local_image() {
        // `docker image inspect nosuch` prints `[]` and exits 1.
        assert_eq!(parse_image_inspect(b"[]\n", "nosuch:1").unwrap(), None);
        // No RepoDigests (null or absent): built here.
        for raw in [
            &br#"[{"Id":"sha256:aa","RepoDigests":null}]"#[..],
            &br#"[{"Id":"sha256:aa"}]"#[..],
        ] {
            let img = parse_image_inspect(raw, "app:latest")
                .unwrap()
                .expect("image");
            assert!(img.repo_digests.is_empty());
        }
        assert!(matches!(
            parse_image_inspect(b"nope", "x:1"),
            Err(DockerError::Parse(_))
        ));
    }

    /// Docker 29 on the containerd image store, as printed on a node. A built
    /// image has a `RepoDigests` entry of its own name, so only `Identity`
    /// tells it from a pulled one; a re-tagged image keeps where it came from.
    #[test]
    fn identity_tells_a_built_image_from_a_pulled_one() {
        let built = br#"[{
            "Id": "sha256:19",
            "RepoTags": ["app:1"],
            "RepoDigests": ["app@sha256:19"],
            "Identity": {"Build": [{"Ref": "vadol9", "CreatedAt": "2026-11-05T08:00:35Z"}]}
        }]"#;
        let img = parse_image_inspect(built, "app:1").unwrap().expect("image");
        assert!(img.built_here);
        assert!(img.pulled_from.is_empty());

        let pulled = br#"[{
            "Id": "sha256:65",
            "RepoDigests": ["nginx@sha256:65", "other/copy@sha256:65"],
            "Identity": {"Pull": [{"Repository": "docker.io/library/nginx"}]}
        }]"#;
        let img = parse_image_inspect(pulled, "other/copy:1")
            .unwrap()
            .expect("image");
        assert!(!img.built_here);
        assert_eq!(img.pulled_from, ["docker.io/library/nginx"]);

        // Built here and pulled too: there is a registry to compare with.
        let both = br#"[{
            "Id": "sha256:77",
            "RepoDigests": ["reg.example/app@sha256:77"],
            "Identity": {
                "Build": [{"Ref": "x"}],
                "Pull": [{"Repository": "reg.example/app"}]
            }
        }]"#;
        let img = parse_image_inspect(both, "reg.example/app:1")
            .unwrap()
            .expect("image");
        assert!(!img.built_here);

        // Older daemons print no `Identity` at all.
        let old = br#"[{"Id":"sha256:aa","RepoDigests":["x@sha256:aa"]}]"#;
        let img = parse_image_inspect(old, "x:1").unwrap().expect("image");
        assert!(!img.built_here);
        assert!(img.pulled_from.is_empty());
    }

    #[test]
    fn a_reference_with_a_digest_is_pinned() {
        let raw = br#"[{"Id":"sha256:aa","RepoDigests":["nginx@sha256:aa"]}]"#;
        let img = parse_image_inspect(raw, "nginx@sha256:aa")
            .unwrap()
            .expect("image");
        assert!(img.pinned);
        let img = parse_image_inspect(raw, "nginx:1.2@sha256:aa")
            .unwrap()
            .expect("image");
        assert!(img.pinned);
    }

    #[test]
    fn version_parses() {
        let v = parse_version(include_bytes!("../tests/fixtures/docker/version.json")).unwrap();
        assert_eq!(v.client, "29.9.3");
        assert_eq!(v.server.as_deref(), Some("29.9.3"));
    }

    #[test]
    fn ids_refuse_injection() {
        for bad in ["--help", "abc", "web;rm", "../x", ""] {
            assert!(ContainerId::parse(bad).is_err());
        }
        assert!(ImageRef::parse("--output=/x").is_err());
        assert!(ImageRef::parse("").is_err());
        assert!(ImageRef::parse("a b").is_err());
        assert!(ImageRef::parse("ghcr.io/a/b:1.2@sha256:abc").is_ok());
    }

    fn script(dir: &tempfile::TempDir, body: &str) -> PathBuf {
        let p = dir.path().join("fake-docker");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[tokio::test]
    async fn hung_daemon_is_not_responding() {
        let d = tempfile::tempdir().unwrap();
        let sleeper = script(&d, "exec sleep 30");
        let t = std::time::Instant::now();
        let r = run_with(&sleeper, &DockerCmd::PsAll, 1024, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(DockerError::NotResponding)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn missing_binary_is_not_installed() {
        let r = run_with(
            std::path::Path::new("/nonexistent/docker"),
            &DockerCmd::PsAll,
            1024,
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(r, Err(DockerError::NotInstalled)), "{r:?}");
    }

    #[tokio::test]
    async fn output_is_bounded_and_child_killed() {
        let d = tempfile::tempdir().unwrap();
        let flood = script(&d, "exec yes 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'");
        let t = std::time::Instant::now();
        let out = run_with(&flood, &DockerCmd::PsAll, 4096, Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(out.len(), 4096);
        assert!(t.elapsed() < Duration::from_secs(10));
        // stderr counts against the same bound
        let flood_err = script(&d, "exec yes 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' >&2");
        let out = run_with(&flood_err, &DockerCmd::PsAll, 4096, Duration::from_secs(20)).await;
        assert!(
            matches!(&out, Err(DockerError::Failed(m)) if m.starts_with("eeee") && m.len() <= 2000),
            "{out:?}"
        );
    }

    #[tokio::test]
    async fn logs_exit_one_is_failed_in_both_forms() {
        let d = tempfile::tempdir().unwrap();
        let cmd = DockerCmd::Logs {
            id: id('a'),
            tail: 10,
            since: None,
        };
        // stderr only
        let s = script(
            &d,
            "echo 'Error response from daemon: No such container' >&2; exit 1",
        );
        let r = run_with(&s, &cmd, 4096, Duration::from_secs(5)).await;
        assert!(
            matches!(&r, Err(DockerError::Failed(m)) if m.contains("No such container")),
            "{r:?}"
        );
        // some stdout first, then the failure
        let s = script(
            &d,
            "echo partial; echo 'Error response from daemon: boom' >&2; exit 1",
        );
        let r = run_with(&s, &cmd, 4096, Duration::from_secs(5)).await;
        assert!(
            matches!(&r, Err(DockerError::Failed(m)) if m.contains("boom")),
            "{r:?}"
        );
        // daemon down
        let s = script(
            &d,
            "echo 'Cannot connect to the Docker daemon at unix:///x' >&2; exit 1",
        );
        let r = run_with(&s, &cmd, 4096, Duration::from_secs(5)).await;
        assert!(matches!(r, Err(DockerError::NotResponding)), "{r:?}");
    }

    #[tokio::test]
    async fn logs_truncated_run_is_ok_and_container_stderr_is_kept() {
        let d = tempfile::tempdir().unwrap();
        let cmd = DockerCmd::Logs {
            id: id('a'),
            tail: 10,
            since: None,
        };
        let s = script(&d, "exec yes 'llllllllllllllllllllllllllllllll'");
        let out = run_with(&s, &cmd, 4096, Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(out.len(), 4096);
        let s = script(&d, "exec yes 'llllllllllllllllllllllllllllllll' >&2");
        let out = run_with(&s, &cmd, 4096, Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(out.len(), 4096);
    }

    #[tokio::test]
    async fn logs_keep_both_streams() {
        let d = tempfile::tempdir().unwrap();
        let s = script(&d, "echo out-line; echo err-line >&2");
        let cmd = DockerCmd::Logs {
            id: id('a'),
            tail: 10,
            since: None,
        };
        let out = run_with(&s, &cmd, 4096, Duration::from_secs(5))
            .await
            .unwrap();
        let t = String::from_utf8(out).unwrap();
        assert!(t.contains("out-line") && t.contains("err-line"), "{t}");
    }

    #[tokio::test]
    async fn failure_is_the_stderr_text_bounded() {
        let d = tempfile::tempdir().unwrap();
        let s = script(&d, "echo 'no such container' >&2; exit 1");
        let r = run_with(&s, &DockerCmd::PsAll, 4096, Duration::from_secs(5)).await;
        assert!(
            matches!(&r, Err(DockerError::Failed(m)) if m.contains("no such container")),
            "{r:?}"
        );
        let big = script(&d, "yes eeeeeeeeeeeeeeee | head -c 100000 >&2; exit 1");
        let r = run_with(&big, &DockerCmd::PsAll, 1 << 20, Duration::from_secs(5)).await;
        assert!(
            matches!(&r, Err(DockerError::Failed(m)) if m.len() <= 2100),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn nonzero_exit_with_stdout_is_ok() {
        let d = tempfile::tempdir().unwrap();
        let s = script(&d, "echo '{\"Client\":{}}'; echo down >&2; exit 1");
        let out = run_with(&s, &DockerCmd::Version, 4096, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(String::from_utf8(out).unwrap().contains("Client"));
    }
}
