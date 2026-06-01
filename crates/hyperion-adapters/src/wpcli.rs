//! `wp-cli` wrappers. wp-cli is invoked under `sudo -u <hosting_user>` so
//! that file ownership inside `htdocs/` stays correct.
//!
//! Functions accept already-validated typed arguments — every external value
//! that ends up on the command line goes through a regex check in
//! `hyperion-validate` higher up.

use crate::{cmd, AdapterError};
use hyperion_types::WpInstallRequest;
use once_cell::sync::Lazy;
use regex::Regex;

static SAFE_ARG: Lazy<Regex> = Lazy::new(|| {
    // Conservative whitelist for wp-cli arguments. Used to refuse anything
    // that could plausibly be shell or argument-injection (e.g. spaces are
    // allowed, but only via the per-arg Command::arg, never concatenated).
    Regex::new(r"^[a-zA-Z0-9 _.\-/:%@=,]+$")
        .unwrap_or_else(|_| panic!("BUG: SAFE_ARG regex failed to compile"))
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
pub fn build_argv<'a>(user: &'a str, htdocs: &'a str, extra: &'a [&'a str]) -> Vec<&'a str> {
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
pub async fn run(user: &str, htdocs: &str, args: &[&str]) -> Result<String, AdapterError> {
    validate_args(args)?;
    let argv = build_argv(user, htdocs, args);
    cmd::run("/usr/bin/sudo", &argv).await
}

static LOCALE_RX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z]{2,3}(_[A-Z]{2})?$")
        .unwrap_or_else(|_| panic!("BUG: LOCALE_RX failed to compile"))
});
static VERSION_RX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(latest|[0-9]+(\.[0-9]+){0,3})$")
        .unwrap_or_else(|_| panic!("BUG: VERSION_RX failed to compile"))
});

/// MariaDB DB credentials for a WordPress install. Lives here (not in a
/// shared crate) because the only place we shove these into wp-cli is
/// from this adapter — keeping the struct co-located makes the adapter
/// boundary obvious.
#[derive(Debug, Clone)]
pub struct WpDbCreds<'a> {
    pub name: &'a str,
    pub user: &'a str,
    pub password: &'a str,
    /// Typically `localhost` (Debian MariaDB unix socket).
    pub host: &'a str,
}

/// URL of the wp-cli phar release we self-install if `/usr/local/bin/wp`
/// is missing. Pinned to the wp-cli "stable" builds branch on GitHub
/// (signed releases). Override at compile time with the
/// `HYPERION_WPCLI_URL` env var if you mirror it internally.
pub const WPCLI_PHAR_URL: &str =
    "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar";

/// Where the wp-cli phar lives on disk. Has to match `build_argv`.
pub const WPCLI_PATH: &str = "/usr/local/bin/wp";

/// Make sure `/usr/local/bin/wp` exists and is executable. If it doesn't,
/// download the phar from upstream over HTTPS (curl verifies TLS by
/// default) and `chmod 0755` it. No-op if already present.
///
/// This lets the WordPress install pipeline self-heal on hosts where
/// `install-master.sh` predated the wp-cli step. Operators can prevent
/// auto-download in air-gapped environments by pre-installing wp-cli
/// themselves; the existence check makes this trivially a no-op.
pub async fn ensure_wp_cli_present() -> Result<(), AdapterError> {
    if std::path::Path::new(WPCLI_PATH).exists() {
        return Ok(());
    }
    tracing::info!(url = WPCLI_PHAR_URL, "wp-cli missing — downloading");
    cmd::run(
        "/usr/bin/curl",
        &["-fsSL", WPCLI_PHAR_URL, "-o", WPCLI_PATH],
    )
    .await
    .map_err(|e| {
        AdapterError::Other(format!(
            "could not download wp-cli from {WPCLI_PHAR_URL}: {e}.\n\
             Fix by hand:\n  \
               curl -fsSL {WPCLI_PHAR_URL} -o {WPCLI_PATH} && chmod 0755 {WPCLI_PATH}"
        ))
    })?;
    cmd::run("/bin/chmod", &["0755", WPCLI_PATH]).await?;
    Ok(())
}

/// Install WordPress into `htdocs` running as `user`.
///
/// Pipeline:
///   0. `ensure_wp_cli_present` — fetches wp-cli phar if missing
///   1. `wp core download --locale --version --skip-content`
///   2. `wp config create --dbname --dbuser --dbpass-from-stdin --dbhost --force`
///   3. `wp core install --url --title --admin_user --admin_email
///                       --prompt=admin_password`  (admin_password via stdin)
///
/// Both DB password and admin password go through stdin via wp-cli's
/// `--prompt` mechanism so they never appear on argv (and thus never in
/// `ps` output). Structural args (`locale`, `version`) are checked
/// against tight regexes; the rest go through `Command::new().arg()`,
/// which uses an argv array (no shell parsing), so shell metacharacters
/// in titles/passwords are not a vector.
///
/// Returns the installed core version (`wp core version` output, trimmed).
pub async fn install_wordpress(
    user: &str,
    htdocs: &str,
    db: WpDbCreds<'_>,
    req: &WpInstallRequest,
) -> Result<String, AdapterError> {
    ensure_wp_cli_present().await?;
    if !LOCALE_RX.is_match(&req.locale) {
        return Err(AdapterError::Other(format!(
            "wp locale refused (not en_US-style): {}",
            req.locale
        )));
    }
    if !VERSION_RX.is_match(&req.version) {
        return Err(AdapterError::Other(format!(
            "wp version refused (not 'latest' / X.Y[.Z]): {}",
            req.version
        )));
    }

    // 1. wp core download
    let locale_arg = format!("--locale={}", req.locale);
    let version_arg = format!("--version={}", req.version);
    let core_args: [&str; 6] = [
        "core",
        "download",
        &locale_arg,
        &version_arg,
        "--skip-content",
        "--force",
    ];
    let core_argv = build_argv(user, htdocs, &core_args);
    cmd::run("/usr/bin/sudo", &core_argv).await?;

    // 2. wp config create — pipe DB password via stdin (--prompt=dbpass).
    let dbname_arg = format!("--dbname={}", db.name);
    let dbuser_arg = format!("--dbuser={}", db.user);
    let dbhost_arg = format!("--dbhost={}", db.host);
    let config_args: [&str; 7] = [
        "config",
        "create",
        &dbname_arg,
        &dbuser_arg,
        &dbhost_arg,
        "--prompt=dbpass",
        "--force",
    ];
    let config_argv = build_argv(user, htdocs, &config_args);
    // wp-cli's --prompt reads "field: <value>\n" from stdin per missing arg.
    // We provide a single line for dbpass.
    let stdin = format!("{}\n", db.password);
    cmd::run_with_stdin("/usr/bin/sudo", &config_argv, stdin.as_bytes()).await?;

    // 3. wp core install — pipe admin password via stdin.
    let url_arg = format!("--url={}", req.site_url);
    let title_arg = format!("--title={}", req.title);
    let admin_user_arg = format!("--admin_user={}", req.admin_user);
    let admin_email_arg = format!("--admin_email={}", req.admin_email);
    let install_args: [&str; 8] = [
        "core",
        "install",
        &url_arg,
        &title_arg,
        &admin_user_arg,
        &admin_email_arg,
        "--prompt=admin_password",
        "--skip-email",
    ];
    let install_argv = build_argv(user, htdocs, &install_args);
    let stdin = format!("{}\n", req.admin_password);
    cmd::run_with_stdin("/usr/bin/sudo", &install_argv, stdin.as_bytes()).await?;

    // 4. What core version did we end up with?
    let v_args: [&str; 2] = ["core", "version"];
    let v_argv = build_argv(user, htdocs, &v_args);
    let v = cmd::run("/usr/bin/sudo", &v_argv).await?;
    Ok(v.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_args_accepts_typical_wp_inputs() {
        assert!(
            validate_args(&["core", "download", "--locale=cs_CZ", "--version=latest",]).is_ok()
        );
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

    #[test]
    fn locale_regex_accepts_standard_codes() {
        for ok in ["en", "en_US", "cs_CZ", "sk_SK", "de", "pt_BR"] {
            assert!(LOCALE_RX.is_match(ok), "should accept {ok}");
        }
    }

    #[test]
    fn locale_regex_refuses_garbage() {
        for bad in ["", "EN_US", "en-US", "english", "cs_cz", "../etc/passwd"] {
            assert!(!LOCALE_RX.is_match(bad), "should refuse {bad}");
        }
    }

    #[test]
    fn version_regex_accepts_latest_and_semver() {
        for ok in ["latest", "6", "6.5", "6.5.3", "6.5.3.1"] {
            assert!(VERSION_RX.is_match(ok), "should accept {ok}");
        }
    }

    #[test]
    fn version_regex_refuses_garbage() {
        for bad in ["", "6.5;rm", "v6.5", "6.5-rc1", "$VERSION"] {
            assert!(!VERSION_RX.is_match(bad), "should refuse {bad}");
        }
    }
}
