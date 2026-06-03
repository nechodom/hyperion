//! Capture the current git HEAD SHA at build time so the running
//! binary can compare itself against the upstream release without
//! reading /opt/hyperion/.git at runtime.
//!
//! Precedence: `HYPERION_GIT_SHA` env var (CI sets this) →
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

    // Truncate to 12 chars — matches GitHub's "short SHA" display.
    let short: String = sha.chars().take(40).collect();
    println!("cargo:rustc-env=HYPERION_GIT_SHA={short}");
    // Rerun if HEAD changes.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=HYPERION_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
}
