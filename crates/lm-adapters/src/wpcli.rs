//! `wp-cli` wrappers. wp-cli is invoked under `sudo -u <hosting_user>` so
//! that file ownership inside `htdocs/` stays correct.
//!
//! Functions accept already-validated typed arguments — every external value
//! that ends up on the command line goes through a regex check in
//! `lm-validate` higher up.

use crate::{cmd, AdapterError};
use once_cell::sync::Lazy;
use regex::Regex;

static SAFE_ARG: Lazy<Regex> = Lazy::new(|| {
    // Conservative whitelist for wp-cli arguments. Used to refuse anything
    // that could plausibly be shell or argument-injection (e.g. spaces are
    // allowed, but only via the per-arg Command::arg, never concatenated).
    Regex::new(r"^[a-zA-Z0-9 _.\-/:%@=,]+$").unwrap_or_else(|_| {
        panic!("BUG: SAFE_ARG regex failed to compile")
    })
});

/// Refuse to run a wp-cli command whose arguments contain shell metacharacters.
pub fn validate_args(args: &[&str]) -> Result<(), AdapterError> {
    for a in args {
        if !SAFE_ARG.is_match(a) {
            return Err(AdapterError::Other(format!(
                "wp-cli arg refused (not in whitelist): {a}"
            )));
        }
    }
    Ok(())
}

/// Build the full command line for `sudo -u <user> /usr/local/bin/wp --path=<path> <args>`.
pub fn build_argv<'a>(
    user: &'a str,
    htdocs: &'a str,
    extra: &'a [&'a str],
) -> Vec<&'a str> {
    let mut v = vec![
        "-u",
        user,
        "/usr/local/bin/wp",
        "--allow-root=false",
        "--path",
        htdocs,
    ];
    v.extend_from_slice(extra);
    v
}

/// Run an arbitrary wp-cli subcommand. Refuses inputs that fail
/// `validate_args` so we never pass user-controlled metacharacters.
pub async fn run(
    user: &str,
    htdocs: &str,
    args: &[&str],
) -> Result<String, AdapterError> {
    validate_args(args)?;
    let argv = build_argv(user, htdocs, args);
    cmd::run("/usr/bin/sudo", &argv).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_args_accepts_typical_wp_inputs() {
        assert!(validate_args(&[
            "core",
            "download",
            "--locale=cs_CZ",
            "--version=latest",
        ])
        .is_ok());
        assert!(validate_args(&[
            "core",
            "install",
            "--url=https://example.cz",
            "--title=My Blog",
            "--admin_user=admin",
            "--admin_email=k@x.cz",
        ])
        .is_ok());
        assert!(validate_args(&["rewrite", "structure", "/%postname%/"]).is_ok());
    }

    #[test]
    fn validate_args_refuses_shell_meta() {
        for bad in [
            ";rm -rf /",
            "$(touch /tmp/lol)",
            "`whoami`",
            "x && y",
            "x|y",
            "x>y",
            "héčko",
        ] {
            assert!(
                validate_args(&["plugin", "install", bad]).is_err(),
                "should refuse: {bad}"
            );
        }
    }

    #[test]
    fn build_argv_shape() {
        let v = build_argv(
            "alice_cz",
            "/home/alice_cz/alice.cz/htdocs",
            &["core", "download"],
        );
        assert_eq!(
            v,
            vec![
                "-u",
                "alice_cz",
                "/usr/local/bin/wp",
                "--allow-root=false",
                "--path",
                "/home/alice_cz/alice.cz/htdocs",
                "core",
                "download"
            ]
        );
    }
}
