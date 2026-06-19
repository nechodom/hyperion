//! Capture the current git HEAD SHA at build time so the running binary can
//! report exactly which commit it was built from (`hctl --version`). Mirrors
//! hyperion-agent / hyperion-web build.rs — keep them in sync.
//!
//! Precedence: `HYPERION_GIT_SHA` env (CI / update.sh set this) →
//! `GITHUB_SHA` (GitHub Actions default) → `git rev-parse HEAD`
//! (developer machine) → "dev-unknown" fallback.

use std::process::Command;

fn main() {
    let sha = std::env::var("HYPERION_GIT_SHA")
        .ok()
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "dev-unknown".to_string());

    let sha: String = sha.chars().take(40).collect();
    println!("cargo:rustc-env=HYPERION_GIT_SHA={sha}");

    // Rebuild when the SHA env (set explicitly by CI / update.sh) changes.
    println!("cargo:rerun-if-env-changed=HYPERION_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    // ...and when the local checkout moves. Watching ONLY .git/HEAD is a bug:
    // a new commit on the SAME branch leaves HEAD as "ref: refs/heads/<b>"
    // unchanged — the ref file under .git/refs is what moves (or packed-refs
    // once refs are packed). Paths are relative to this package dir.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
    if let Ok(head) = std::fs::read_to_string("../../.git/HEAD") {
        if let Some(r) = head.strip_prefix("ref:").map(str::trim) {
            println!("cargo:rerun-if-changed=../../.git/{r}");
        }
    }
}
