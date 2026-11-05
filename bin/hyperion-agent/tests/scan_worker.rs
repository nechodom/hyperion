//! The real agent binary as the scan worker, started without systemd.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use hyperion_adapters::sitescan::runner::{run_direct, WorkerJob, WorkerReply, MAX_REPLY_BYTES};
use hyperion_adapters::sitescan::scan::{ScanInput, ScanMode};

const AGENT: &str = env!("CARGO_BIN_EXE_hyperion-agent");

fn docroot() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().expect("tmp");
    let root = t.path().canonicalize().expect("canonical").join("htdocs");
    std::fs::create_dir_all(root.join("wp-includes")).expect("mkdir");
    std::fs::write(root.join("index.php"), "<?php\n").expect("write");
    (t, root)
}

#[tokio::test]
async fn worker_roundtrip_direct_mode() {
    let (_t, root) = docroot();
    let job = WorkerJob::Discover { root: root.clone() };
    let reply = run_direct(&job, Path::new(AGENT), MAX_REPLY_BYTES)
        .await
        .expect("run");
    let WorkerReply::Discovery(d) = reply else {
        panic!("{reply:?}");
    };
    assert!(d.is_wordpress);

    let gone = WorkerJob::Discover {
        root: root.join("missing"),
    };
    let reply = run_direct(&gone, Path::new(AGENT), MAX_REPLY_BYTES)
        .await
        .expect("run");
    assert!(matches!(reply, WorkerReply::Failed(_)), "{reply:?}");
}

#[tokio::test]
async fn a_scan_job_comes_back_as_an_outcome_and_writes_the_baseline() {
    let (t, root) = docroot();
    let state = t.path().canonicalize().expect("canonical").join("state");
    std::fs::create_dir(&state).expect("mkdir");
    let Ok(WorkerReply::Discovery(discovery)) = run_direct(
        &WorkerJob::Discover { root: root.clone() },
        Path::new(AGENT),
        MAX_REPLY_BYTES,
    )
    .await
    else {
        panic!("discover");
    };
    let baseline_path = state.join("baseline");
    let job = WorkerJob::Scan(ScanInput {
        root,
        discovery,
        manifests_dir: state.join("manifests"),
        baseline_path: baseline_path.clone(),
        mode: ScanMode::Delta,
        now: 1_700_000_000,
        wporg_known_slugs: None,
        accept_since: None,
    });
    let reply = run_direct(&job, Path::new(AGENT), MAX_REPLY_BYTES)
        .await
        .expect("run");
    let WorkerReply::Scan(out) = reply else {
        panic!("{reply:?}");
    };
    assert!(!out.stopped);
    assert!(out.files_hashed >= 1, "{out:?}");
    assert!(baseline_path.exists());
}

#[test]
fn the_worker_needs_no_config_and_keeps_stdout_to_one_reply() {
    let (_t, root) = docroot();
    let out = Command::new(AGENT)
        .arg("scan-worker")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            let job = serde_json::to_vec(&WorkerJob::Discover { root }).expect("ser");
            c.stdin.take().expect("stdin").write_all(&job)?;
            c.wait_with_output()
        })
        .expect("run");
    assert!(out.status.success(), "{:?}", out.status);
    // Exactly one JSON document, nothing else.
    let reply: WorkerReply = serde_json::from_slice(&out.stdout).expect("one reply");
    assert!(matches!(reply, WorkerReply::Discovery(_)));
}

#[test]
fn a_garbled_job_is_a_failed_reply_not_a_crash() {
    use std::io::Write;
    let mut c = Command::new(AGENT)
        .arg("scan-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    c.stdin
        .take()
        .expect("stdin")
        .write_all(b"{not json")
        .expect("write");
    let out = c.wait_with_output().expect("wait");
    let reply: WorkerReply = serde_json::from_slice(&out.stdout).expect("reply");
    assert!(matches!(reply, WorkerReply::Failed(_)), "{reply:?}");
}

#[test]
fn help_does_not_list_the_worker() {
    let out = Command::new(AGENT).arg("--help").output().expect("run");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("export-bundle"), "{text}");
    assert!(!text.contains("scan-worker"), "{text}");
}
