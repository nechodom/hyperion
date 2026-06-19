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
///
/// wp-cli is strict: `--path <path>` is rejected ("parameter cannot be
/// empty when provided"). It only accepts the joined `--path=<path>`
/// form. We materialize the joined arg as a String here so caller
/// converts via `.iter().map(String::as_str).collect()` before invoking
/// the command.
pub fn build_argv(user: &str, htdocs: &str, extra: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = vec![
        "-u".into(),
        user.to_string(),
        "/usr/local/bin/wp".into(),
        "--allow-root=false".into(),
        format!("--path={}", htdocs),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

/// Convenience wrapper — convert the owned Vec<String> from build_argv
/// into the &[&str] shape that cmd::run expects, scoped to the borrow.
fn argv_as_refs(argv: &[String]) -> Vec<&str> {
    argv.iter().map(String::as_str).collect()
}

/// Run an arbitrary wp-cli subcommand. Refuses inputs that fail
/// `validate_args` so we never pass user-controlled metacharacters.
pub async fn run(user: &str, htdocs: &str, args: &[&str]) -> Result<String, AdapterError> {
    validate_args(args)?;
    let argv = build_argv(user, htdocs, args);
    cmd::run("/usr/bin/sudo", &argv_as_refs(&argv)).await
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

    // Self-heal the doc-root's ancestor traversability before we drop
    // a working site there. Hostings created before the ensure_dirs
    // fix have a 0700 home (useradd HOME_MODE on Debian 12), which
    // makes nginx 404 the freshly-installed site. Re-running WP install
    // is the most common operator reaction to that 404, so fixing it
    // here means the existing-hosting case heals itself on retry.
    crate::fs::ensure_ancestors_traversable(std::path::Path::new(htdocs)).await;

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
    cmd::run("/usr/bin/sudo", &argv_as_refs(&core_argv)).await?;

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
    let config_argv_refs = argv_as_refs(&config_argv);
    // wp-cli's --prompt reads "field: <value>\n" from stdin per missing arg.
    // We provide a single line for dbpass.
    let stdin = format!("{}\n", db.password);
    cmd::run_with_stdin("/usr/bin/sudo", &config_argv_refs, stdin.as_bytes()).await?;

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
    let install_argv_refs = argv_as_refs(&install_argv);
    let stdin = format!("{}\n", req.admin_password);
    cmd::run_with_stdin("/usr/bin/sudo", &install_argv_refs, stdin.as_bytes()).await?;

    // 4. Optional: flip blog_public off when the caller asked for
    // a no-index install (test-node WP preset). Best-effort —
    // failure here doesn't roll back the install (the operator
    // can flip it manually in WP admin → Reading).
    if req.no_index {
        let no_idx_args: [&str; 4] = ["option", "update", "blog_public", "0"];
        let no_idx_argv = build_argv(user, htdocs, &no_idx_args);
        if let Err(e) = cmd::run("/usr/bin/sudo", &argv_as_refs(&no_idx_argv)).await {
            tracing::warn!(error = %e, "no_index post-install setting failed");
        }
    }

    // 5. What core version did we end up with?
    let v_args: [&str; 2] = ["core", "version"];
    let v_argv = build_argv(user, htdocs, &v_args);
    let v = cmd::run("/usr/bin/sudo", &argv_as_refs(&v_argv)).await?;
    Ok(v.trim().to_string())
}

// =====================================================================
//  Plugin management
// =====================================================================

/// wp-cli plugin slug pattern. Plugin folder names on wordpress.org are
/// `[a-z0-9-]+` (no underscores, no caps). We accept underscores too
/// because a handful of older premium plugins use them.
///
/// `.expect_used` lint is denied crate-wide; for a hardcoded regex
/// the only way it can fail is a compile-time bug in the literal
/// itself — which would surface in the locale_regex_* tests below.
/// `unwrap_or_else(|_| unreachable!(...))` documents that intent.
static SLUG_RX: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(r"^[a-zA-Z0-9_\-]{1,80}$")
        .unwrap_or_else(|e| panic!("BUG: SLUG_RX failed to compile: {e}"))
});

/// HTTP URL pattern for `wp plugin install <url>`. Bounded length; no
/// embedded credentials; scheme http/https only.
static URL_RX: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(r"^https?://[A-Za-z0-9_\-./%~=&?+:]{1,512}$")
        .unwrap_or_else(|e| panic!("BUG: URL_RX failed to compile: {e}"))
});

/// Validate a plugin slug. Used at the boundary before `wp` argv build.
pub fn validate_plugin_slug(s: &str) -> Result<(), AdapterError> {
    if !SLUG_RX.is_match(s) {
        return Err(AdapterError::Other(format!(
            "plugin slug refused: {s} (must match {})",
            SLUG_RX.as_str()
        )));
    }
    Ok(())
}

/// Validate an install URL. Requires HTTPS (plugin/theme code must not arrive
/// over plaintext, where it could be MITM-replaced) and blocks loopback /
/// link-local / private-range hosts so this privileged action can't be turned
/// into an SSRF probe of internal services or cloud-metadata endpoints.
pub fn validate_plugin_url(s: &str) -> Result<(), AdapterError> {
    if !URL_RX.is_match(s) {
        return Err(AdapterError::Other(format!(
            "plugin install URL refused: {s}"
        )));
    }
    let refused = |why: &str| {
        Err(AdapterError::Other(format!(
            "plugin install URL refused ({why}): {s}"
        )))
    };
    // HTTPS only.
    let Some(rest) = s.strip_prefix("https://") else {
        return refused("must be https://");
    };
    // Host = everything up to the first '/', ':' or '?'.
    let host = rest
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() {
        return refused("empty host");
    }
    // 172.16.0.0/12 → second octet 16..=31.
    let is_172_private = host
        .strip_prefix("172.")
        .and_then(|r| r.split('.').next())
        .and_then(|o| o.parse::<u8>().ok())
        .map(|second| (16..=31).contains(&second))
        .unwrap_or(false);
    let blocked = host == "localhost"
        || host.ends_with(".localhost")
        || host == "metadata"
        || host == "metadata.google.internal"
        || host.ends_with(".internal")
        || host == "0.0.0.0"
        || host == "::1"
        || host == "[::1]"
        || host.starts_with("127.")
        || host.starts_with("169.254.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || is_172_private;
    if blocked {
        return refused("internal/loopback/link-local host not allowed");
    }
    Ok(())
}

/// List installed WP themes — `wp theme list --format=json`.
/// Same plumbing as plugin_list, parses into a Vec<WpTheme>.
pub async fn theme_list(
    user: &str,
    htdocs: &str,
) -> Result<(Vec<hyperion_types::WpTheme>, String), AdapterError> {
    ensure_wp_cli_present().await?;
    let argv = build_argv(
        user,
        htdocs,
        &[
            "theme",
            "list",
            "--format=json",
            "--fields=name,status,update,version,update_version",
        ],
    );
    let out = cmd::run("/usr/bin/sudo", &argv_as_refs(&argv)).await?;
    // wp-cli emits each row with `name` (= slug); a separate human title
    // isn't always returned, so map the slug into both slug + name for the
    // UI below. parse_wp_json tolerates PHP warnings prepended to stdout
    // (same wp-cli noise that breaks plugin_list).
    let rows: Vec<RawThemeRow> = parse_wp_json(&out, "wp theme list")?;
    let themes = rows
        .into_iter()
        .map(|r| hyperion_types::WpTheme {
            slug: r.name.clone(),
            name: r.title.unwrap_or(r.name),
            version: r.version,
            status: r.status,
            update_available: r.update == "available",
            latest_version: r.update_version.unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    // wp core version is cheap to reuse — same as plugin_list.
    let core_argv = build_argv(user, htdocs, &["core", "version"]);
    let core_out = cmd::run("/usr/bin/sudo", &argv_as_refs(&core_argv))
        .await
        .unwrap_or_default();
    Ok((themes, core_out.trim().to_string()))
}

/// Apply one whitelisted theme action via wp-cli. Slug is empty
/// for UpdateAll. Same shape as plugin_action.
pub async fn theme_action(
    user: &str,
    htdocs: &str,
    slug: &str,
    action: &hyperion_types::WpThemeAction,
) -> Result<hyperion_types::WpThemeActionResult, AdapterError> {
    ensure_wp_cli_present().await?;
    if !matches!(action, hyperion_types::WpThemeAction::UpdateAll) {
        validate_plugin_slug(slug)?;
    }
    let args_owned: Vec<String> = match action {
        hyperion_types::WpThemeAction::Install { source } => {
            let is_url = source.starts_with("http://") || source.starts_with("https://");
            if is_url {
                validate_plugin_url(source)?;
            } else {
                validate_plugin_slug(source)?;
            }
            vec![
                "theme".into(),
                "install".into(),
                source.clone(),
                "--activate".into(),
            ]
        }
        hyperion_types::WpThemeAction::Activate => {
            vec!["theme".into(), "activate".into(), slug.into()]
        }
        hyperion_types::WpThemeAction::Update => {
            vec!["theme".into(), "update".into(), slug.into()]
        }
        hyperion_types::WpThemeAction::UpdateAll => {
            vec!["theme".into(), "update".into(), "--all".into()]
        }
        hyperion_types::WpThemeAction::Delete => {
            vec!["theme".into(), "delete".into(), slug.into()]
        }
    };
    let args_refs: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
    let argv = build_argv(user, htdocs, &args_refs);
    let result = cmd::run("/usr/bin/sudo", &argv_as_refs(&argv)).await;
    let (state, message, tail) = match result {
        Ok(out) => {
            let tail = tail_4k(&out);
            let noop = out.contains("already activated")
                || out.contains("already at the latest version")
                || out.contains("Warning: ");
            let state = if noop { "noop" } else { "ok" };
            (state.to_string(), short_summary(&out), tail)
        }
        Err(e) => {
            let msg = e.to_string();
            ("failed".into(), msg.clone(), tail_4k(&msg))
        }
    };
    Ok(hyperion_types::WpThemeActionResult {
        state,
        message,
        output_tail: tail,
    })
}

/// Install a plugin or theme by `source`. `source` is one of:
///   - a wordpress.org slug (validated against SLUG_RX)
///   - an https URL (validated against URL_RX)
///   - a local absolute path to a ZIP under `/var/lib/hyperion/wp-assets/`
///     (validated by prefix to avoid wp-cli being pointed at anything else)
///
/// `kind` is `"plugin"` or `"theme"` — caller has already
/// vetted. Passes `--force` for local-path installs so re-uploads
/// of the same asset over an existing install replace it
/// cleanly. Optionally activates after install.
pub async fn install_item(
    user: &str,
    htdocs: &str,
    kind: &str,
    source: &str,
    activate: bool,
) -> Result<(), AdapterError> {
    ensure_wp_cli_present().await?;
    if source.is_empty() {
        return Err(AdapterError::Other("source must not be empty".into()));
    }
    // Decide what to pass to wp-cli + validate.
    let is_local_path = source.starts_with('/');
    let is_url = source.starts_with("http://") || source.starts_with("https://");
    if is_local_path {
        // Anti-traversal — only paths inside our managed asset dir.
        if !source.starts_with("/var/lib/hyperion/wp-assets/") {
            return Err(AdapterError::Other(format!(
                "local ZIP path must be under /var/lib/hyperion/wp-assets/, got {source}"
            )));
        }
        if !std::path::Path::new(source).exists() {
            return Err(AdapterError::Other(format!(
                "uploaded ZIP missing on disk: {source}"
            )));
        }
    } else if is_url {
        validate_plugin_url(source)?;
    } else {
        validate_plugin_slug(source)?;
    }
    // Build argv. `kind` is one of "plugin" / "theme" — caller has
    // already validated, so we can use it directly as the subcommand.
    let mut extra: Vec<String> = vec![kind.into(), "install".into(), source.into()];
    if is_local_path {
        // --force makes wp-cli replace an existing install — needed
        // when an operator re-uploads a newer ZIP under the same
        // slug.
        extra.push("--force".into());
    }
    if activate {
        extra.push("--activate".into());
    }
    let extra_refs: Vec<&str> = extra.iter().map(|s| s.as_str()).collect();
    let argv = build_argv(user, htdocs, &extra_refs);
    let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    cmd::run("/usr/bin/sudo", &argv_refs).await.map_err(|e| {
        AdapterError::Other(format!(
            "wp {kind} install {source}{}: {e}",
            if activate { " --activate" } else { "" }
        ))
    })?;
    Ok(())
}

/// List installed WP plugins via `wp plugin list --format=json` and
/// `wp core version`. Both calls run under `system_user` against
/// `htdocs`. Returns the parsed plugin table + wp version string.
pub async fn plugin_list(
    user: &str,
    htdocs: &str,
) -> Result<(Vec<hyperion_types::WpPlugin>, String), AdapterError> {
    ensure_wp_cli_present().await?;
    // `--format=json` gives a stable schema across wp-cli versions.
    // `--fields=name,status,update,version,update_version,auto_update`
    // selects the columns we care about and elides everything else
    // (which is occasionally not present, e.g. on older wp-cli builds).
    let args: [&str; 4] = [
        "plugin",
        "list",
        "--format=json",
        "--fields=name,status,update,version,update_version,auto_update",
    ];
    let argv = build_argv(user, htdocs, &args);
    let stdout = cmd::run("/usr/bin/sudo", &argv_as_refs(&argv)).await?;
    // Tolerate PHP warnings/notices wp-cli prints to stdout before the JSON
    // (e.g. the "Undefined property: stdClass::$requires" noise wp-cli emits
    // for premium plugins). See parse_wp_json.
    let rows: Vec<RawPluginRow> = parse_wp_json(&stdout, "wp plugin list")?;
    let plugins: Vec<hyperion_types::WpPlugin> = rows
        .into_iter()
        .map(|r| hyperion_types::WpPlugin {
            slug: r.name,
            // wp-cli's `name` column is actually the folder slug. We
            // don't have a separate "display name" available without
            // `wp plugin get`, which would mean one RPC per plugin.
            // Reuse the slug; the UI titlecases it.
            name: String::new(),
            version: r.version,
            status: r.status,
            update_available: r.update.as_deref() == Some("available"),
            latest_version: r.update_version.unwrap_or_default(),
            auto_update: matches!(r.auto_update.as_deref(), Some("on")),
        })
        .map(|mut p| {
            if p.name.is_empty() {
                p.name = humanize_slug(&p.slug);
            }
            p
        })
        .collect();

    // wp core version — separate one-line call. Cheap.
    let v_args: [&str; 2] = ["core", "version"];
    let v_argv = build_argv(user, htdocs, &v_args);
    let wp_version = cmd::run("/usr/bin/sudo", &argv_as_refs(&v_argv))
        .await
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| String::new());
    Ok((plugins, wp_version))
}

/// Apply one whitelisted plugin action via wp-cli under `system_user`.
pub async fn plugin_action(
    user: &str,
    htdocs: &str,
    slug: &str,
    action: &hyperion_types::WpPluginAction,
) -> Result<hyperion_types::WpPluginActionResult, AdapterError> {
    ensure_wp_cli_present().await?;
    // UpdateAll is the only branch that doesn't need a slug.
    if !matches!(action, hyperion_types::WpPluginAction::UpdateAll) {
        validate_plugin_slug(slug)?;
    }
    let args_owned: Vec<String> = match action {
        hyperion_types::WpPluginAction::Install { source } => {
            // `source` is either a wordpress.org slug or an https URL.
            let is_url = source.starts_with("http://") || source.starts_with("https://");
            if is_url {
                validate_plugin_url(source)?;
            } else {
                validate_plugin_slug(source)?;
            }
            vec![
                "plugin".into(),
                "install".into(),
                source.clone(),
                "--activate".into(),
            ]
        }
        hyperion_types::WpPluginAction::Activate => {
            vec!["plugin".into(), "activate".into(), slug.into()]
        }
        hyperion_types::WpPluginAction::Deactivate => {
            vec!["plugin".into(), "deactivate".into(), slug.into()]
        }
        hyperion_types::WpPluginAction::Update => {
            vec!["plugin".into(), "update".into(), slug.into()]
        }
        hyperion_types::WpPluginAction::UpdateAll => {
            vec!["plugin".into(), "update".into(), "--all".into()]
        }
        hyperion_types::WpPluginAction::Delete => {
            vec!["plugin".into(), "delete".into(), slug.into()]
        }
        hyperion_types::WpPluginAction::SetAutoUpdate { enabled } => {
            let sub = if *enabled { "enable" } else { "disable" };
            vec![
                "plugin".into(),
                "auto-updates".into(),
                sub.into(),
                slug.into(),
            ]
        }
    };
    let args_refs: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
    let argv = build_argv(user, htdocs, &args_refs);
    let result = cmd::run("/usr/bin/sudo", &argv_as_refs(&argv)).await;
    let (state, message, tail) = match result {
        Ok(out) => {
            let tail = tail_4k(&out);
            // wp-cli prints "Success:" on happy path and "Warning:" on
            // noop ("Plugin already activated").
            let noop = out.contains("already active")
                || out.contains("already deactivated")
                || out.contains("Warning: ");
            let state = if noop { "noop" } else { "ok" };
            (state.to_string(), short_summary(&out), tail)
        }
        Err(e) => {
            let msg = e.to_string();
            ("failed".into(), msg.clone(), tail_4k(&msg))
        }
    };
    Ok(hyperion_types::WpPluginActionResult {
        state,
        message,
        output_tail: tail,
    })
}

/// Set or delete a constant in wp-config.php via `wp config set/delete`.
/// `value` is wrapped as the constant's literal (numbers/booleans pass
/// through; strings get quoted). When `value` is None, the constant is
/// deleted. Idempotent — deleting a missing constant returns Ok.
///
/// Type hint maps to wp-cli `--raw` flag for non-string literals.
/// Booleans/integers MUST be raw or they get quoted as strings, which
/// breaks `if ( true === WP_DEBUG )` checks elsewhere.
pub enum WpConstantValue<'a> {
    String(&'a str),
    Bool(bool),
    Int(i64),
}

pub async fn set_config_constant(
    user: &str,
    htdocs: &str,
    name: &str,
    value: WpConstantValue<'_>,
) -> Result<(), AdapterError> {
    if !name
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(AdapterError::Other(format!(
            "wp-config constant name must be UPPERCASE_SNAKE: {name}"
        )));
    }
    let (raw_flag, literal): (&str, String) = match value {
        WpConstantValue::String(s) => ("", s.to_string()),
        WpConstantValue::Bool(b) => ("--raw", if b { "true".into() } else { "false".into() }),
        WpConstantValue::Int(n) => ("--raw", n.to_string()),
    };
    let mut args: Vec<&str> = vec!["config", "set", name, &literal, "--type=constant"];
    if !raw_flag.is_empty() {
        args.push(raw_flag);
    }
    run(user, htdocs, &args).await?;
    Ok(())
}

pub async fn delete_config_constant(
    user: &str,
    htdocs: &str,
    name: &str,
) -> Result<(), AdapterError> {
    if !name
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(AdapterError::Other(format!(
            "wp-config constant name must be UPPERCASE_SNAKE: {name}"
        )));
    }
    // `wp config delete` returns nonzero if the constant is missing.
    // We swallow that since the caller's intent is "ensure absent".
    let _ = run(user, htdocs, &["config", "delete", name, "--type=constant"]).await;
    Ok(())
}

/// Last ~4 KiB of a long output buffer, char-boundary safe.
fn tail_4k(s: &str) -> String {
    const N: usize = 4096;
    if s.len() <= N {
        return s.to_string();
    }
    // Walk back from the end until we hit a char boundary.
    let mut start = s.len() - N;
    while !s.is_char_boundary(start) && start > 0 {
        start -= 1;
    }
    s[start..].to_string()
}

/// Pull a one-liner from wp-cli's output for the toast / flash message.
fn short_summary(out: &str) -> String {
    out.lines()
        .find(|l| l.contains("Success:") || l.contains("Warning:") || l.contains("Error:"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| out.lines().next().unwrap_or("").trim().to_string())
}

/// Convert "akismet-anti-spam" → "Akismet Anti Spam" for the UI when
/// we don't have the plugin's display name (wp-cli's `plugin list`
/// doesn't return it without an extra `plugin get` call per row).
fn humanize_slug(slug: &str) -> String {
    let mut out = String::with_capacity(slug.len() + 4);
    let mut at_word = true;
    for c in slug.chars() {
        if c == '-' || c == '_' {
            out.push(' ');
            at_word = true;
        } else if at_word {
            out.extend(c.to_uppercase());
            at_word = false;
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, serde::Deserialize)]
struct RawPluginRow {
    name: String,
    status: String,
    /// "available" | "none" | "" (older wp-cli)
    #[serde(default)]
    update: Option<String>,
    version: String,
    #[serde(default)]
    update_version: Option<String>,
    /// "on" | "off" | None (very old wp-cli)
    #[serde(default)]
    auto_update: Option<String>,
}

/// One row of `wp theme list --format=json`. Lifted to module scope (next
/// to RawPluginRow) so `theme_list` can route through `parse_wp_json`.
#[derive(Debug, serde::Deserialize)]
struct RawThemeRow {
    name: String,
    #[serde(default)]
    title: Option<String>,
    status: String,
    #[serde(default)]
    update: String,
    version: String,
    #[serde(default)]
    update_version: Option<String>,
}

/// Parse the JSON value embedded in wp-cli stdout, tolerating leading PHP
/// noise printed ahead of the JSON.
///
/// wp-cli boots WordPress to run, and a buggy plugin — or wp-cli itself —
/// can print PHP warnings/notices/deprecations to *stdout* (not just stderr)
/// while the command still exits 0. With `--format=json` those lines get
/// prepended to the JSON, e.g. real production output:
///
/// ```text
/// Warning: Undefined property: stdClass::$requires in .../Plugin_Command.php on line 875
/// [{"name":"akismet","status":"active",...}]
/// ```
///
/// A naive `serde_json::from_str` on that whole blob fails and the caller
/// renders an empty list ("No plugins installed yet") on a site that clearly
/// has plugins. This locates the actual JSON value by scanning for the first
/// `[`/`{` from which the *remainder parses to the end* — which is exactly
/// the trailing JSON wp-cli emits as the final thing on stdout, never a stray
/// bracket inside a preceding warning line. A genuine failure (no JSON at all,
/// e.g. "Error: This does not seem to be a WordPress installation.") still
/// surfaces as an error rather than a silent empty list. `cmd_label` is used
/// only for that error message.
///
/// Assumes the JSON is the *final* output on stdout — true for the wp-cli
/// list commands we call (the formatter flushes last; the `$requires` noise
/// fires interleaved, before it). PHP noise printed *after* the JSON (rare
/// shutdown-time deprecations) would surface as an error, not a wrong value.
fn parse_wp_json<T: serde::de::DeserializeOwned>(
    raw: &str,
    cmd_label: &str,
) -> Result<T, AdapterError> {
    let trimmed = raw.trim();
    // Fast path: clean JSON — the overwhelmingly common case.
    if let Ok(v) = serde_json::from_str::<T>(trimmed) {
        return Ok(v);
    }
    // Otherwise find where the JSON value actually begins. A PHP warning line
    // could itself contain a bracket (e.g. "array offset [0] on null", or even
    // a bare "[]"), so we don't blindly slice from the first `[`/`{` — we try
    // each candidate opening delimiter and accept the first one whose
    // remainder parses *to the end* via from_str. Requiring whole-remainder
    // consumption is what makes a stray "[]" in a warning fail (it leaves
    // trailing text) and fall through to the real JSON, which wp-cli always
    // emits as the final thing on stdout. `char_indices` keeps `i` on a UTF-8
    // boundary so slicing a multi-byte notice can never panic.
    for (i, c) in trimmed.char_indices() {
        if c != '[' && c != '{' {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<T>(&trimmed[i..]) {
            return Ok(v);
        }
    }
    // `chars().take(200)`, NOT byte-slicing `[..200]`: a PHP notice can
    // contain multi-byte UTF-8 and slicing on a non-char boundary panics
    // (the crate denies unwrap/expect but slicing bypasses that).
    let preview: String = trimmed.chars().take(200).collect();
    Err(AdapterError::Other(format!(
        "{cmd_label} returned non-JSON: body: {preview}"
    )))
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
    fn build_argv_uses_joined_path_form() {
        let v = build_argv(
            "alice_cz",
            "/home/alice_cz/alice.cz/htdocs",
            &["core", "download"],
        );
        assert_eq!(
            v,
            vec![
                "-u".to_string(),
                "alice_cz".into(),
                "/usr/local/bin/wp".into(),
                "--allow-root=false".into(),
                "--path=/home/alice_cz/alice.cz/htdocs".into(),
                "core".into(),
                "download".into(),
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

    #[test]
    fn plugin_url_accepts_public_https() {
        for ok in [
            "https://downloads.wordpress.org/plugin/akismet.zip",
            "https://example.com/my-plugin.zip",
            "https://cdn.vendor.io/builds/x.zip?v=2",
        ] {
            assert!(validate_plugin_url(ok).is_ok(), "should accept {ok}");
        }
    }

    #[test]
    fn plugin_url_refuses_plaintext_and_ssrf_targets() {
        for bad in [
            "http://example.com/p.zip",            // not https
            "https://localhost/p.zip",             // loopback
            "https://127.0.0.1/p.zip",             // loopback
            "https://169.254.169.254/latest/meta", // cloud metadata
            "https://10.0.0.5/p.zip",              // private
            "https://192.168.1.10/p.zip",          // private
            "https://172.16.0.1/p.zip",            // private /12
            "https://172.31.255.1/p.zip",          // private /12 upper
            "https://metadata.google.internal/x",  // metadata host
        ] {
            assert!(validate_plugin_url(bad).is_err(), "should refuse {bad}");
        }
    }

    #[test]
    fn plugin_url_allows_public_172_outside_private_range() {
        // 172.32+ and 172.15 are public, must not be caught by the /12 rule.
        assert!(validate_plugin_url("https://172.32.0.1/p.zip").is_ok());
        assert!(validate_plugin_url("https://172.15.0.1/p.zip").is_ok());
    }

    // ---- parse_wp_json: tolerate PHP noise on stdout before the JSON ----

    const PLUGIN_ROW: &str = r#"{"name":"akismet","status":"active","update":"none","version":"5.3","update_version":null,"auto_update":"off"}"#;

    #[test]
    fn parse_wp_json_warning_prefixed_array_still_parses() {
        // The literal production reproduction: a wp-cli `$requires` warning
        // printed to stdout ahead of the JSON array (see the bug report).
        let raw = format!(
            "PHP Warning:  Undefined property: stdClass::$requires in \
             phar:///usr/local/bin/wp/vendor/wp-cli/extension-command/src/Plugin_Command.php on line 875\n[{PLUGIN_ROW}]"
        );
        let rows: Vec<RawPluginRow> = parse_wp_json(&raw, "wp plugin list").expect("should parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "akismet");
    }

    #[test]
    fn parse_wp_json_multiple_leading_noise_lines() {
        let raw = format!(
            "PHP Warning:  something\nWarning:  something\nDeprecated: old thing\nNotice: heads up\n[{PLUGIN_ROW},{PLUGIN_ROW}]"
        );
        let rows: Vec<RawPluginRow> = parse_wp_json(&raw, "wp plugin list").expect("should parse");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn parse_wp_json_clean_array_unchanged() {
        // Happy path: no prefix, identical result to a plain from_str.
        let raw = format!("[{PLUGIN_ROW}]");
        let rows: Vec<RawPluginRow> = parse_wp_json(&raw, "wp plugin list").expect("should parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "active");
    }

    #[test]
    fn parse_wp_json_multibyte_prefix_does_not_panic() {
        // A Czech (multi-byte UTF-8) notice ahead of the JSON must not panic
        // on a non-char-boundary slice, and must still parse.
        let raw = format!("PHP Warning:  chyba v šabloně — žluťoučký kůň …\n[{PLUGIN_ROW}]");
        let rows: Vec<RawPluginRow> = parse_wp_json(&raw, "wp plugin list").expect("should parse");
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn parse_wp_json_empty_array_is_ok_not_error() {
        // A site with no plugins is valid — both clean and warning-prefixed.
        let clean: Vec<RawPluginRow> = parse_wp_json("[]", "wp plugin list").expect("clean []");
        assert!(clean.is_empty());
        let prefixed: Vec<RawPluginRow> =
            parse_wp_json("Warning: noise\n[]", "wp plugin list").expect("prefixed []");
        assert!(prefixed.is_empty());
    }

    #[test]
    fn parse_wp_json_non_json_surfaces_error() {
        // A genuine failure (no JSON at all) must still error, NOT silently
        // return an empty list — otherwise the defender's "all clear" lies.
        let err = parse_wp_json::<Vec<RawPluginRow>>(
            "Error: This does not seem to be a WordPress installation.",
            "wp plugin list",
        )
        .unwrap_err();
        match err {
            AdapterError::Other(msg) => {
                assert!(
                    msg.contains("wp plugin list returned non-JSON"),
                    "msg: {msg}"
                );
                assert!(
                    msg.contains("does not seem to be"),
                    "preview missing: {msg}"
                );
            }
            other => panic!("expected AdapterError::Other, got {other:?}"),
        }
    }

    #[test]
    fn parse_wp_json_bracket_in_warning_is_not_mistaken_for_json() {
        // A warning line containing a stray '[' must not be taken as the JSON
        // start: the helper anchors on the first delimiter from which the
        // FULL value deserializes, skipping the decoy.
        let raw = format!("PHP Notice: array offset [0] on null in foo.php\n[{PLUGIN_ROW}]");
        let rows: Vec<RawPluginRow> = parse_wp_json(&raw, "wp plugin list").expect("should parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "akismet");
    }

    #[test]
    fn parse_wp_json_bare_empty_array_in_warning_is_not_the_payload() {
        // A warning containing a bare "[]" must NOT be mistaken for an empty
        // result — that would silently hide a site's real plugins. The real
        // array (the tail) is what must be returned.
        let raw = format!("Warning: found [] stale entries in cache\n[{PLUGIN_ROW}]");
        let rows: Vec<RawPluginRow> = parse_wp_json(&raw, "wp plugin list").expect("should parse");
        assert_eq!(
            rows.len(),
            1,
            "must return the real array, not the [] decoy"
        );
        assert_eq!(rows[0].name, "akismet");
    }

    #[test]
    fn parse_wp_json_theme_row_also_tolerates_prefix() {
        // theme_list shares the helper via RawThemeRow.
        let raw = "Warning: noise\n[{\"name\":\"twentytwentyfour\",\"status\":\"active\",\"version\":\"1.2\"}]";
        let rows: Vec<RawThemeRow> = parse_wp_json(raw, "wp theme list").expect("should parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "twentytwentyfour");
    }
}
