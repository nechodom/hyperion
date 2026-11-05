//! MariaDB database + user provisioning via the local `mariadb` socket.

use crate::{cmd, AdapterError};
use hyperion_types::HostingId;
use std::time::Duration;

/// Compute the per-hosting DB name + user. Uses the first 6 hex chars of the
/// hosting id as the entropy and a sanitized domain-derived label so a
/// human glancing at it can guess which site it belongs to.
pub fn names_for(hosting_id: &HostingId, domain_label: &str) -> (String, String) {
    let h = short_hash(hosting_id.as_str());
    let lab = sanitize_label(domain_label);
    let truncated_lab: String = lab.chars().take(10).collect();
    let db_name = format!("lm_{h}_{truncated_lab}");
    let db_user = format!("lm_{h}_u");
    (db_name, db_user)
}

fn short_hash(s: &str) -> String {
    let h = blake3::hash(s.as_bytes());
    hex::encode(&h.as_bytes()[..3])
}

fn sanitize_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'a'..='z' | '0'..='9' => out.push(c),
            'A'..='Z' => out.push(c.to_ascii_lowercase()),
            '.' | '-' => out.push('_'),
            _ => {}
        }
    }
    if out.is_empty() {
        out.push('x');
    }
    out
}

#[derive(Debug, Clone)]
pub struct CreateResult {
    pub db_name: String,
    pub db_user: String,
    pub password: String,
}

/// Create database + user on the local mariadb socket using socket auth.
/// Returns the generated credentials. Idempotent w.r.t. user creation
/// (uses IF NOT EXISTS).
pub async fn create_db_and_user(
    hosting_id: &HostingId,
    domain_label: &str,
) -> Result<CreateResult, AdapterError> {
    let (db, user) = names_for(hosting_id, domain_label);
    let password = crate::random_password();
    let sql = build_create_sql(&db, &user, &password);
    cmd::run_with_stdin("/usr/bin/mariadb", &[], sql.as_bytes()).await?;
    Ok(CreateResult {
        db_name: db,
        db_user: user,
        password,
    })
}

/// `ALTER USER ... IDENTIFIED BY '<new>'`. Caller is responsible for
/// updating the persisted secret.
pub async fn reset_password(db_user: &str, new_password: &str) -> Result<(), AdapterError> {
    let sql = format!(
        "ALTER USER `{user}`@`localhost` IDENTIFIED BY '{pass}';\nFLUSH PRIVILEGES;",
        user = escape_ident(db_user),
        pass = escape_string_literal(new_password),
    );
    cmd::run_with_stdin("/usr/bin/mariadb", &[], sql.as_bytes()).await?;
    Ok(())
}

/// `ALTER USER ... ACCOUNT LOCK`. Idempotent.
pub async fn lock_user(db_user: &str) -> Result<(), AdapterError> {
    let sql = format!(
        "ALTER USER `{user}`@`localhost` ACCOUNT LOCK;",
        user = escape_ident(db_user),
    );
    cmd::run_with_stdin("/usr/bin/mariadb", &[], sql.as_bytes()).await?;
    Ok(())
}

/// `ALTER USER ... ACCOUNT UNLOCK`. Idempotent.
pub async fn unlock_user(db_user: &str) -> Result<(), AdapterError> {
    let sql = format!(
        "ALTER USER `{user}`@`localhost` ACCOUNT UNLOCK;",
        user = escape_ident(db_user),
    );
    cmd::run_with_stdin("/usr/bin/mariadb", &[], sql.as_bytes()).await?;
    Ok(())
}

/// Drop database + user. Idempotent.
pub async fn drop_db_and_user(db_name: &str, db_user: &str) -> Result<(), AdapterError> {
    let sql = format!(
        "DROP DATABASE IF EXISTS `{db}`;\n\
         DROP USER IF EXISTS `{user}`@`localhost`;\n\
         FLUSH PRIVILEGES;",
        db = escape_ident(db_name),
        user = escape_ident(db_user),
    );
    cmd::run_with_stdin("/usr/bin/mariadb", &[], sql.as_bytes()).await?;
    Ok(())
}

/// The site transients `read_option` may read. The update check keeps its package
/// links in them; nothing else is any business of root's.
pub const UPDATE_PLUGINS_OPTION: &str = "_site_transient_update_plugins";
pub const UPDATE_THEMES_OPTION: &str = "_site_transient_update_themes";

/// How long reading one option may take, from start to giving up.
const READ_OPTION_TIMEOUT: Duration = Duration::from_secs(60);

/// A WordPress table prefix this code is willing to put in a statement.
pub fn valid_table_prefix(prefix: &str) -> bool {
    (1..=64).contains(&prefix.len())
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn valid_db_name(db: &str) -> bool {
    (1..=64).contains(&db.len())
        && db
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'$'))
}

/// One of the update transients from a WordPress site's options table, as the
/// database holds it. `None` when there's no such row.
///
/// This runs as root against a database its tenant has every right in, and the
/// caller has already made sure `db` is one the hosting owns. See
/// [`read_option_sql`] for what stops the tenant's objects running as root.
pub async fn read_option(
    db: &str,
    prefix: &str,
    option: &str,
) -> Result<Option<String>, AdapterError> {
    use tokio::io::AsyncWriteExt;
    let sql = read_option_sql(db, prefix, option)?;
    let mut child = tokio::process::Command::new("/usr/bin/mariadb")
        // Raw: batch mode's escaping would change the byte lengths inside a
        // serialized value. utf8mb4: a narrower connection charset would too.
        .args([
            "--batch",
            "--raw",
            "--skip-column-names",
            "--default-character-set=utf8mb4",
            "--connect-timeout=10",
        ])
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let run = async {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(sql.as_bytes()).await?;
            stdin.shutdown().await?;
        }
        child.wait_with_output().await
    };
    let out = tokio::time::timeout(READ_OPTION_TIMEOUT, run)
        .await
        .map_err(|_| AdapterError::Other("reading a site option timed out".into()))??;
    if !out.status.success() {
        return Err(AdapterError::Other(format!(
            "reading a site option failed (exit {})",
            out.status.code().unwrap_or(-1)
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // The client ends the row with a newline. The value's own stay.
    let value = text.strip_suffix('\n').unwrap_or(&text);
    Ok((!value.is_empty()).then(|| value.to_string()))
}

/// The statements behind [`read_option`]. Everything that isn't a constant is
/// checked to be safe inside quotes and backticks, and a bad value is refused.
///
/// `{prefix}options` is the tenant's to replace: its user has `ALL` on the
/// database, views and stored functions included. A view with `SQL SECURITY
/// INVOKER` over a function of the same kind runs that function with the rights of
/// whoever selects from it, and that's root here, with every other tenant's
/// database in reach. So the statement runs only if the name is a base table, and
/// the lock holds it to that: without it a `RENAME` could put a view there between
/// the check and the read. A lock on a view runs nothing, and a read has no
/// triggers. `LEFT` bounds the value at 8 MiB characters.
fn read_option_sql(db: &str, prefix: &str, option: &str) -> Result<String, AdapterError> {
    if !valid_db_name(db) {
        return Err(AdapterError::Other("refusing a database name".into()));
    }
    if !valid_table_prefix(prefix) {
        return Err(AdapterError::Other("refusing a table prefix".into()));
    }
    if option != UPDATE_PLUGINS_OPTION && option != UPDATE_THEMES_OPTION {
        return Err(AdapterError::Other("refusing an option name".into()));
    }
    let table = format!("{prefix}options");
    Ok(format!(
        "SET SESSION lock_wait_timeout = 5;\n\
         SET SESSION max_statement_time = 30;\n\
         LOCK TABLES `{db}`.`{table}` READ;\n\
         SET @hyperion_read = IF(\
           (SELECT COUNT(*) FROM information_schema.TABLES \
            WHERE TABLE_SCHEMA = '{db}' AND TABLE_NAME = '{table}' \
            AND TABLE_TYPE = 'BASE TABLE') = 1, \
           'SELECT LEFT(option_value, 8388608) FROM `{db}`.`{table}` \
            WHERE option_name = ''{option}'' LIMIT 1', \
           'DO 0');\n\
         PREPARE hyperion_read FROM @hyperion_read;\n\
         EXECUTE hyperion_read;\n\
         DEALLOCATE PREPARE hyperion_read;\n\
         UNLOCK TABLES;\n"
    ))
}

pub(crate) fn build_create_sql(db: &str, user: &str, password: &str) -> String {
    format!(
        "CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n\
         CREATE USER IF NOT EXISTS `{user}`@`localhost` IDENTIFIED BY '{pass}';\n\
         GRANT ALL PRIVILEGES ON `{db}`.* TO `{user}`@`localhost`;\n\
         FLUSH PRIVILEGES;",
        db = escape_ident(db),
        user = escape_ident(user),
        pass = escape_string_literal(password),
    )
}

fn escape_ident(s: &str) -> String {
    // backticks must be doubled inside backticked identifiers
    s.replace('`', "``")
}

fn escape_string_literal(s: &str) -> String {
    // single quotes doubled inside single-quoted strings
    s.replace('\'', "''").replace('\\', "\\\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_stable_for_same_input() {
        let id = HostingId("01J7A8GQX5BCDEF".into());
        let a = names_for(&id, "example.cz");
        let b = names_for(&id, "example.cz");
        assert_eq!(a, b);
    }

    #[test]
    fn names_obey_max_lengths_safe_for_mysql() {
        let id = HostingId("01J7A8GQX5BCDEF000".into());
        let (db, user) = names_for(&id, "an-extremely-long-subdomain-and-then-some.cz");
        // MariaDB DB name max 64, user name max 32 (Maria 10.6+). Stay well under.
        assert!(db.len() <= 32, "db: {db} ({})", db.len());
        assert!(user.len() <= 16, "user: {user} ({})", user.len());
        assert!(user.starts_with("lm_"));
    }

    #[test]
    fn create_sql_quotes_identifiers_and_password() {
        let sql = build_create_sql("lm_abc", "lm_abc_u", "p4'ss");
        assert!(sql.contains("CREATE DATABASE IF NOT EXISTS `lm_abc`"));
        assert!(sql.contains("CREATE USER IF NOT EXISTS `lm_abc_u`@`localhost`"));
        assert!(sql.contains("IDENTIFIED BY 'p4''ss'"));
    }

    #[test]
    fn escape_ident_doubles_backticks() {
        assert_eq!(escape_ident("a`b"), "a``b");
    }

    #[test]
    fn escape_string_doubles_quotes_and_backslashes() {
        assert_eq!(escape_string_literal("a'b"), "a''b");
        assert_eq!(escape_string_literal("a\\b"), "a\\\\b");
    }

    #[test]
    fn the_read_is_gated_on_a_base_table_under_a_lock() {
        let sql = read_option_sql("lm_abc", "wp_", UPDATE_PLUGINS_OPTION).expect("sql");
        let at = |needle: &str| {
            sql.find(needle)
                .unwrap_or_else(|| panic!("{needle}: {sql}"))
        };
        assert!(at("LOCK TABLES `lm_abc`.`wp_options` READ") < at("TABLE_TYPE = 'BASE TABLE'"));
        assert!(at("TABLE_TYPE = 'BASE TABLE'") < at("EXECUTE hyperion_read"));
        assert!(sql.contains("SELECT LEFT(option_value, 8388608)"));
        assert!(sql.contains("option_name = ''_site_transient_update_plugins''"));
        // The only read of the table is the gated one.
        assert_eq!(sql.matches("FROM `lm_abc`").count(), 1);
    }

    #[test]
    fn read_option_refuses_what_it_cant_quote() {
        for (db, prefix, option) in [
            ("a`b", "wp_", UPDATE_PLUGINS_OPTION),
            ("a'b", "wp_", UPDATE_PLUGINS_OPTION),
            ("", "wp_", UPDATE_PLUGINS_OPTION),
            ("a", "wp`", UPDATE_PLUGINS_OPTION),
            ("a", "wp_", "siteurl"),
            ("a", "wp_", "active_plugins"),
        ] {
            assert!(
                read_option_sql(db, prefix, option).is_err(),
                "{db} {prefix} {option}"
            );
        }
        assert!(read_option_sql("lm_abc-1", "wp_", UPDATE_THEMES_OPTION).is_ok());
    }

    /// As root against a real server, for the ignored tests below.
    async fn live_sql(sql: &str) -> String {
        cmd::run_with_stdin(
            "/usr/bin/mariadb",
            &["--batch", "--raw", "-N"],
            sql.as_bytes(),
        )
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    /// Lengths in a serialized value are bytes, so what comes back has to be the
    /// same bytes: newlines, backslashes and non-ASCII included.
    #[tokio::test]
    #[ignore = "requires running mariadb-server"]
    async fn read_option_returns_the_exact_value() {
        let db = "hyp_read_option_exact";
        let value = "a:1:{s:3:\"k\\n\";s:12:\"Přílo\\žha\ne\";}";
        live_sql(&format!(
            "DROP DATABASE IF EXISTS `{db}`; CREATE DATABASE `{db}`;\n\
             CREATE TABLE `{db}`.`wp_options` (option_name VARCHAR(191) PRIMARY KEY, \
               option_value LONGTEXT NOT NULL) DEFAULT CHARSET utf8mb4;"
        ))
        .await;
        let literal = escape_string_literal(value);
        cmd::run_with_stdin(
            "/usr/bin/mariadb",
            &["--default-character-set=utf8mb4"],
            format!(
                "INSERT INTO `{db}`.`wp_options` VALUES ('{UPDATE_PLUGINS_OPTION}', '{literal}');"
            )
            .as_bytes(),
        )
        .await
        .expect("insert");

        let got = read_option(db, "wp_", UPDATE_PLUGINS_OPTION)
            .await
            .expect("read");
        assert_eq!(got.as_deref(), Some(value));
        // No such row, and no such table.
        assert_eq!(
            read_option(db, "wp_", UPDATE_THEMES_OPTION)
                .await
                .expect("read"),
            None
        );
        assert!(read_option(db, "other_", UPDATE_THEMES_OPTION)
            .await
            .is_err());
        live_sql(&format!("DROP DATABASE `{db}`;")).await;
    }

    /// The attack [`read_option_sql`] is written against: `wp_options` is a view
    /// with invoker rights over a function of invoker rights, which would read
    /// another database, and leave a mark, if root ever selected from it.
    #[tokio::test]
    #[ignore = "requires running mariadb-server"]
    async fn a_view_in_place_of_the_table_runs_nothing_as_root() {
        let (db, victim) = ("hyp_read_option_attacker", "hyp_read_option_victim");
        live_sql(&format!(
            "DROP DATABASE IF EXISTS `{db}`; DROP DATABASE IF EXISTS `{victim}`;\n\
             CREATE DATABASE `{db}`; CREATE DATABASE `{victim}`;\n\
             CREATE TABLE `{victim}`.`wp_options` (option_name VARCHAR(191), \
               option_value LONGTEXT);\n\
             INSERT INTO `{victim}`.`wp_options` VALUES \
               ('{UPDATE_PLUGINS_OPTION}', 'VICTIM-LICENCE');\n\
             CREATE TABLE `{db}`.`ran` (who VARCHAR(255));\n\
             DELIMITER //\n\
             CREATE FUNCTION `{db}`.`steal`() RETURNS LONGTEXT SQL SECURITY INVOKER \
             BEGIN \
               INSERT INTO `{db}`.`ran` VALUES (CURRENT_USER()); \
               RETURN (SELECT option_value FROM `{victim}`.`wp_options` LIMIT 1); \
             END//\n\
             DELIMITER ;\n\
             CREATE SQL SECURITY INVOKER VIEW `{db}`.`wp_options` AS \
               SELECT '{UPDATE_PLUGINS_OPTION}' AS option_name, \
               `{db}`.`steal`() AS option_value;"
        ))
        .await;
        // As a check the setup is what it claims: an ungated select does run it.
        let direct = live_sql(&format!("SELECT option_value FROM `{db}`.`wp_options`;")).await;
        assert!(direct.contains("VICTIM-LICENCE"), "{direct}");
        live_sql(&format!("DELETE FROM `{db}`.`ran`;")).await;

        let got = read_option(db, "wp_", UPDATE_PLUGINS_OPTION)
            .await
            .expect("read");
        assert_eq!(got, None, "a view isn't read");
        let ran = live_sql(&format!("SELECT COUNT(*) FROM `{db}`.`ran`;")).await;
        assert_eq!(ran.trim(), "0", "nothing ran");
        live_sql(&format!("DROP DATABASE `{db}`; DROP DATABASE `{victim}`;")).await;
    }

    /// A real table reads under the lock, and the lock is what keeps it a table:
    /// with it held, the `RENAME` that would swap a view in has to wait.
    #[tokio::test]
    #[ignore = "requires running mariadb-server"]
    async fn the_lock_keeps_a_view_from_being_swapped_in() {
        let db = "hyp_read_option_table";
        live_sql(&format!(
            "DROP DATABASE IF EXISTS `{db}`; CREATE DATABASE `{db}`;\n\
             CREATE TABLE `{db}`.`x_options` (option_name VARCHAR(191), \
               option_value LONGTEXT);\n\
             INSERT INTO `{db}`.`x_options` VALUES \
               ('{UPDATE_THEMES_OPTION}', 'value');"
        ))
        .await;
        let got = read_option(db, "x_", UPDATE_THEMES_OPTION)
            .await
            .expect("read");
        assert_eq!(got.as_deref(), Some("value"));

        let holder =
            format!("LOCK TABLES `{db}`.`x_options` READ; SELECT SLEEP(3); UNLOCK TABLES;");
        let holding = tokio::spawn(async move { live_sql(&holder).await });
        tokio::time::sleep(Duration::from_secs(1)).await;
        let swap = cmd::run_with_stdin(
            "/usr/bin/mariadb",
            &[],
            format!(
                "SET SESSION lock_wait_timeout = 1; \
                 RENAME TABLE `{db}`.`x_options` TO `{db}`.`moved`;"
            )
            .as_bytes(),
        )
        .await;
        assert!(swap.is_err(), "the rename had to wait: {swap:?}");
        holding.await.expect("holder");
        live_sql(&format!("DROP DATABASE `{db}`;")).await;
    }

    #[tokio::test]
    #[ignore = "requires running mariadb-server"]
    async fn create_and_drop_round_trip() {
        let id = HostingId("01J7A8GQX5BCDEF".into());
        let r = create_db_and_user(&id, "example.cz").await.expect("create");
        drop_db_and_user(&r.db_name, &r.db_user)
            .await
            .expect("drop");
    }
}
