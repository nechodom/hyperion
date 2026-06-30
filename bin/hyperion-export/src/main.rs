//! `hyperion-export` — a tiny, statically-linkable panel exporter.
//!
//! Depends only on the pure-Rust `hyperion-import` crate, so it builds as a
//! fully static musl binary that runs on ANY Linux regardless of glibc version
//! or distro. The self-service import wizard serves this to source boxes; the
//! operator runs it as root on a CloudPanel / HestiaCP server and it streams a
//! portable import bundle straight to Hyperion (`--out -`).

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "hyperion-export",
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let n = hyperion_import::export::run(
        cli.kind.as_deref(),
        &cli.out,
        cli.only.as_deref(),
        cli.list,
        cli.json,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Keep all non-list output on stderr — stdout may be the bundle stream
    // (`--out -`). In --list mode the plan is printed to stdout by the driver.
    if cli.list {
        eprintln!("✓ dry run — {n} site(s) would be exported.");
    } else if cli.out.as_os_str() == "-" {
        eprintln!("✓ streamed bundle — {n} site(s).");
    } else {
        eprintln!("✓ wrote {} — {n} site(s).", cli.out.display());
    }
    Ok(())
}
