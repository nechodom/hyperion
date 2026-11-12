//! Runs the contact form guard module under real PHP, outside WordPress.
//!
//! The module is PHP inside a Rust string, so nothing else in the build ever
//! executes it. `tests/fixtures/formguard_harness.php` stubs the handful of
//! WordPress and Elementor Pro calls it makes and walks it through the
//! submissions it exists for.
//!
//! Skipped (loudly) on a machine without `php` on the PATH.

use std::process::Command;

#[test]
fn the_module_behaves_under_php() {
    if Command::new("php").arg("-v").output().is_err() {
        eprintln!("SKIPPED: no `php` on PATH — the form guard module was not executed");
        return;
    }
    let site = tempfile::TempDir::new().expect("tempdir");
    std::fs::create_dir_all(site.path().join("htdocs/wp-content")).expect("docroot");
    std::fs::create_dir_all(site.path().join("logs")).expect("logs");
    let module = site.path().join("formguard.php");
    std::fs::write(&module, hyperion_adapters::formguard::render_module()).expect("module");

    let lint = Command::new("php")
        .arg("-l")
        .arg(&module)
        .output()
        .expect("php -l");
    assert!(
        lint.status.success(),
        "module does not parse:\n{}{}",
        String::from_utf8_lossy(&lint.stdout),
        String::from_utf8_lossy(&lint.stderr)
    );

    let harness = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/formguard_harness.php"
    );
    let out = Command::new("php")
        // A notice or a deprecation in the module is a failure here: on a
        // site it would be a line in the customer's error log per submission.
        .args(["-d", "error_reporting=E_ALL", "-d", "display_errors=stderr"])
        .arg(harness)
        .arg(&module)
        .arg(site.path())
        .output()
        .expect("run harness");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stderr.trim().is_empty(),
        "harness failed:\n{stdout}\n{stderr}"
    );
    assert_eq!(stdout.trim(), "ok");

    // What PHP wrote, the node reads.
    let root = site.path().join("htdocs");
    let hyperion_adapters::formguard::RefusalLog::Read(hits) =
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt")
            .block_on(hyperion_adapters::formguard::read_refusals(
                root.to_str().expect("utf8"),
            ))
    else {
        panic!("the node could not read the log PHP wrote");
    };
    assert!(!hits.is_empty(), "no refusal parsed from the module's log");
    assert!(hits.iter().all(|h| h.rule == "empty"), "{hits:?}");
}
