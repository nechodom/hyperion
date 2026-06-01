//! MariaDB database + user provisioning via the local `mariadb` socket.

use crate::{cmd, AdapterError};
use lm_types::HostingId;

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
        out.push_str("x");
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

    #[tokio::test]
    #[ignore = "requires running mariadb-server"]
    async fn create_and_drop_round_trip() {
        let id = HostingId("01J7A8GQX5BCDEF".into());
        let r = create_db_and_user(&id, "example.cz")
            .await
            .expect("create");
        drop_db_and_user(&r.db_name, &r.db_user)
            .await
            .expect("drop");
    }
}
