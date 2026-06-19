//! Capture build-time version info so the running binary can report exactly
//! what it is: a human-readable git-describe version (`HYPERION_DESCRIBE`, e.g.
//! `v1.2.0-5-gf718fd1`) for `--version` + the cluster version-skew pill, and
//! the full HEAD SHA (`HYPERION_GIT_SHA`) for update.sh's staleness check.
//! Mirrors hyperion-web / hctl build.rs — keep them in sync.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn main() {
    // Full 40-char HEAD SHA. Precedence: explicit env (CI / update.sh) →
    // GITHUB_SHA → `git rev-parse HEAD` → "dev-unknown".
    let sha = std::env::var("HYPERION_GIT_SHA")
        .ok()
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .or_else(|| git(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "dev-unknown".to_string());
    let sha: String = sha.chars().take(40).collect();
    println!("cargo:rustc-env=HYPERION_GIT_SHA={sha}");

    // Human version via git-describe: nearest `vX.Y.Z` tag + commits-since +
    // short sha (e.g. `v1.2.0-5-gf718fd1`). `--match v[0-9]*` ignores the
    // `rolling`/`main` release tags; `--always` falls back to the short sha
    // before any version tag is cut; `--dirty` flags uncommitted changes. CI
    // can override via the HYPERION_DESCRIBE env (e.g. a tag build).
    let describe = std::env::var("HYPERION_DESCRIBE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            git(&[
                "describe", "--tags", "--match", "v[0-9]*", "--always", "--dirty",
            ])
        })
        .unwrap_or_else(|| {
            let short: String = sha.chars().take(12).collect();
            if short == "dev-unknown" {
                env!("CARGO_PKG_VERSION").to_string()
            } else {
                format!("g{short}")
            }
        });
    println!("cargo:rustc-env=HYPERION_DESCRIBE={describe}");

    println!("cargo:rerun-if-env-changed=HYPERION_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-env-changed=HYPERION_DESCRIBE");
    // Rebuild when the checkout moves OR a new tag is cut. Watching ONLY
    // .git/HEAD misses commits on the same branch (the ref under .git/refs is
    // what moves), and tags change the describe string. We resolve paths via
    // `git rev-parse --git-path` rather than hardcoding ../../.git/* — that is
    // correct inside a linked worktree too, where `.git` is a FILE pointing at
    // a shared gitdir and the hardcoded paths silently don't exist (so the
    // stamp would go stale across same-branch commits). Shipping builds stamp
    // via env (CI/update.sh) so this only sharpens local incremental rebuilds.
    for p in ["HEAD", "packed-refs", "refs/tags"] {
        if let Some(path) = git(&["rev-parse", "--git-path", p]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    // The branch ref that HEAD points at is what moves on a same-branch commit.
    if let Some(refname) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(path) = git(&["rev-parse", "--git-path", &refname]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}
