//! Runs the form question module under real PHP, outside WordPress, together
//! with the form guard it reports to.
//!
//! `tests/fixtures/formmath_harness.php` stubs the WordPress and Elementor Pro
//! calls the two modules make. The script the module prints for the browser
//! is checked for syntax with `node` when there is one.
//!
//! Skipped (loudly) on a machine without `php` on the PATH.

use std::process::Command;

#[test]
fn the_module_behaves_under_php() {
    if Command::new("php").arg("-v").output().is_err() {
        eprintln!("SKIPPED: no `php` on PATH — the form question module was not executed");
        return;
    }
    let site = tempfile::TempDir::new().expect("tempdir");
    std::fs::create_dir_all(site.path().join("htdocs/wp-content")).expect("docroot");
    std::fs::create_dir_all(site.path().join("logs")).expect("logs");
    let guard = site.path().join("formguard.php");
    std::fs::write(&guard, hyperion_adapters::formguard::render_module()).expect("guard");
    let module = site.path().join("formmath.php");
    std::fs::write(&module, hyperion_adapters::formmath::render_module()).expect("module");
    let script = site.path().join("script.js");

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
        "/tests/fixtures/formmath_harness.php"
    );
    let out = Command::new("php")
        // A notice or a deprecation is a failure here: on a site it would be
        // a line in the customer's error log per page view.
        .args(["-d", "error_reporting=E_ALL", "-d", "display_errors=stderr"])
        .arg(harness)
        .arg(&guard)
        .arg(&module)
        .arg(site.path())
        .arg(&script)
        .output()
        .expect("run harness");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stderr.trim().is_empty(),
        "harness failed:\n{stdout}\n{stderr}"
    );
    assert_eq!(stdout.trim(), "ok");

    // What PHP wrote, the node reads as its own rule.
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
    assert!(hits.iter().any(|h| h.rule == "math"), "{hits:?}");

    // The browser half. `node --check` parses without running.
    let js = std::fs::read_to_string(&script).expect("script written by the harness");
    assert!(js.contains("hyp_fm_a") && js.contains("hyp_fm_t"));
    match Command::new("node").arg("--check").arg(&script).output() {
        Ok(o) => assert!(
            o.status.success(),
            "script does not parse:\n{}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(_) => eprintln!("SKIPPED: no `node` on PATH — the script was not parsed"),
    }
}
