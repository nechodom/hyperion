//! `hyperion-export` — a tiny, statically-linkable panel exporter.
//!
//! Depends only on the pure-Rust `hyperion-import` crate, so it builds as a
//! fully static musl binary that runs on ANY Linux regardless of glibc version
//! or distro. The self-service import wizard serves this to source boxes; the
//! operator runs it as root on a CloudPanel / HestiaCP server and it packs a
//! portable import bundle which the bootstrap runner then uploads in chunks.
//!
//! It deliberately has NO HTTP client. The upload lives in the generated bash
//! runner and uses `curl`, which every panel box already has — adding a TLS
//! stack here would put a second copy of rustls plus its C-adjacent build
//! requirements into a binary whose whole point is running on a stranger's
//! ten-year-old server.

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "hyperion-export",
    version,
    about = "Export a CloudPanel/HestiaCP panel into a Hyperion import bundle"
)]
struct Cli {
    /// `cloudpanel` | `hestiacp`. Auto-detected if omitted.
    #[arg(long)]
    kind: Option<String>,
    /// Output bundle path, or `-` to stream the tar to stdout. Ignored with --list.
    #[arg(long, default_value = "-")]
    out: PathBuf,
    /// Export only these domains (comma-separated). Default: every site.
    #[arg(long)]
    only: Option<String>,
    /// Dry run: print the sites that WOULD be exported and pack nothing.
    #[arg(long)]
    list: bool,
    /// With --list, emit the site list as JSON (for the interactive wizard).
    #[arg(long)]
    json: bool,
    /// Measure the selected sites and print JSON: how big, how much room is
    /// left, and whether the run should show a progress bar or detach.
    /// Packs nothing.
    #[arg(long)]
    estimate: bool,
    /// Append packing progress to this NDJSON journal, so a DETACHED run can be
    /// asked where it is from another shell.
    #[arg(long)]
    journal: Option<PathBuf>,
    /// Print where a running (or finished) export got to, and stop.
    #[arg(long)]
    status: bool,
    /// Like --status, but redraw until the run reaches a terminal state.
    #[arg(long)]
    watch: bool,
    /// Where the run's journal lives. Only used by --status/--watch.
    #[arg(long, default_value = "/var/lib/hyperion-export/run/journal.ndjson")]
    state_file: PathBuf,
}

/// Exit codes the bash runner branches on. A single flattened `anyhow` error
/// gave it nothing to distinguish "this box has no room" from "this is not a
/// panel server" from "the receiver hung up", so it could only ever print the
/// message and give up.
mod exit {
    pub const NOT_DETECTED: i32 = 3;
    pub const NO_SPACE: i32 = 4;
    pub const OTHER: i32 = 2;
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // --status/--watch answer from the journal alone. They must work when no
    // panel is detectable, when the export process is long dead, and after a
    // reboot — so they short-circuit before any detection.
    if cli.status || cli.watch {
        std::process::exit(run_status(&cli).await);
    }

    if cli.estimate {
        match hyperion_import::export::estimate(cli.kind.as_deref(), cli.only.as_deref()).await {
            Ok(est) => {
                println!(
                    "{}",
                    serde_json::to_string(&est).unwrap_or_else(|_| "{}".into())
                );
                return;
            }
            Err(e) => std::process::exit(fail(&e)),
        }
    }

    let res = hyperion_import::export::run_with_journal(
        cli.kind.as_deref(),
        &cli.out,
        cli.only.as_deref(),
        cli.list,
        cli.json,
        cli.journal.as_deref(),
    )
    .await;

    let n = match res {
        Ok(n) => n,
        Err(e) => {
            // Record the failure in the journal too. Without this a detached run
            // that died leaves a status frozen mid-phase, indistinguishable from
            // one still working.
            if let Some(j) = cli.journal.as_deref() {
                let _ = hyperion_import::progress::append(
                    j,
                    &hyperion_import::progress::Event::Fail {
                        t: now(),
                        why: e.to_string(),
                    },
                );
            }
            std::process::exit(fail(&e));
        }
    };

    // Keep all non-list output on stderr — stdout may be the bundle stream
    // (`--out -`). In --list mode the plan is printed to stdout by the driver.
    if cli.list {
        eprintln!("✓ dry run — {n} site(s) would be exported.");
    } else if cli.out.as_os_str() == "-" {
        eprintln!("✓ streamed bundle — {n} site(s).");
    } else {
        eprintln!("✓ wrote {} — {n} site(s).", cli.out.display());
    }
}

fn fail(e: &hyperion_import::error::ImportError) -> i32 {
    eprintln!("hyperion-export: {e}");
    match e {
        hyperion_import::error::ImportError::NotDetected => {
            eprintln!(
                "This does not look like a CloudPanel or HestiaCP server. Pass \
                 --kind explicitly if you know which it is."
            );
            exit::NOT_DETECTED
        }
        // The preflight refusal is the one an operator can act on directly, so
        // it gets its own code and the runner can print the remedy.
        hyperion_import::error::ImportError::Command { cmd, .. }
            if cmd.starts_with("preflight") =>
        {
            exit::NO_SPACE
        }
        _ => exit::OTHER,
    }
}

async fn run_status(cli: &Cli) -> i32 {
    use hyperion_import::progress;
    loop {
        let st = match progress::read(&cli.state_file) {
            Ok(st) => st,
            Err(e) => {
                eprintln!(
                    "No export run recorded at {}.\n  ({e})\n\
                     If you have not started one yet, paste the one-liner from \
                     Hyperion → Import.",
                    cli.state_file.display()
                );
                return exit::OTHER;
            }
        };
        let alive = st.pid.map(progress::pid_alive).unwrap_or(false);
        let text = progress::render_status(&st, now(), alive);
        if cli.watch {
            // Clear and redraw in place.
            print!("\x1b[2J\x1b[H{text}");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            // `st.pid.is_none()` means the worker has not written its `start`
            // line yet, which is the ordinary case for the first second or two
            // — not a dead run. Exiting there told the operator their export had
            // died at the very moment it was starting.
            if st.outcome.is_some() || (!alive && st.pid.is_some()) {
                return terminal_code(&st);
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        } else {
            print!("{text}");
            return terminal_code(&st);
        }
    }
}

fn terminal_code(st: &hyperion_import::progress::RunState) -> i32 {
    match &st.outcome {
        Some(Ok(_)) => 0,
        Some(Err(_)) => 1,
        // Still running is success from the status command's point of view: it
        // answered the question it was asked.
        None => 0,
    }
}
