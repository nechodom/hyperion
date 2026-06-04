//! PostgreSQL database + role provisioning via local socket auth as `postgres`.

use crate::{cmd, AdapterError};
use hyperion_types::HostingId;

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

pub async fn create_db_and_role(
    hosting_id: &HostingId,
    domain_label: &str,
) -> Result<CreateResult, AdapterError> {
    let (db, user) = names_for(hosting_id, domain_label);
    let password = crate::random_password();
    // CREATE ROLE/DATABASE statements; run as `postgres` system user via sudo -u.
    let role_sql = build_role_sql(&user, &password);
    cmd::run(
        "/usr/bin/sudo",
        &[
            "-u",
            "postgres",
            "/usr/bin/psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &role_sql,
        ],
    )
    .await?;
    let db_sql = build_db_sql(&db, &user);
    cmd::run(
        "/usr/bin/sudo",
        &[
            "-u",
            "postgres",
            "/usr/bin/psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &db_sql,
        ],
    )
    .await?;
    Ok(CreateResult {
        db_name: db,
        db_user: user,
        password,
    })
}

/// `ALTER ROLE ... WITH PASSWORD '<new>'`. Caller updates persisted secret.
pub async fn reset_password(db_user: &str, new_password: &str) -> Result<(), AdapterError> {
    let escaped = new_password.replace('\'', "''");
    let sql = format!(
        "ALTER ROLE \"{u}\" WITH PASSWORD '{escaped}';",
        u = escape_ident(db_user),
    );
    cmd::run(
        "/usr/bin/sudo",
        &[
            "-u",
            "postgres",
            "/usr/bin/psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &sql,
        ],
    )
    .await?;
    Ok(())
}

/// `ALTER ROLE ... NOLOGIN`. Idempotent.
pub async fn lock_role(db_user: &str) -> Result<(), AdapterError> {
    let sql = format!("ALTER ROLE \"{u}\" NOLOGIN;", u = escape_ident(db_user));
    cmd::run(
        "/usr/bin/sudo",
        &[
            "-u",
            "postgres",
            "/usr/bin/psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &sql,
        ],
    )
    .await?;
    Ok(())
}

/// `ALTER ROLE ... LOGIN`. Idempotent.
pub async fn unlock_role(db_user: &str) -> Result<(), AdapterError> {
    let sql = format!("ALTER ROLE \"{u}\" LOGIN;", u = escape_ident(db_user));
    cmd::run(
        "/usr/bin/sudo",
        &[
            "-u",
            "postgres",
            "/usr/bin/psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &sql,
        ],
    )
    .await?;
    Ok(())
}

pub async fn drop_db_and_role(db_name: &str, db_user: &str) -> Result<(), AdapterError> {
    let drop_db = format!(
        "DROP DATABASE IF EXISTS \"{db}\";",
        db = escape_ident(db_name)
    );
    let drop_role = format!("DROP ROLE IF EXISTS \"{u}\";", u = escape_ident(db_user));
    cmd::run(
        "/usr/bin/sudo",
        &[
            "-u",
            "postgres",
            "/usr/bin/psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &drop_db,
        ],
    )
    .await?;
    cmd::run(
        "/usr/bin/sudo",
        &[
            "-u",
            "postgres",
            "/usr/bin/psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &drop_role,
        ],
    )
    .await?;
    Ok(())
}

pub(crate) fn build_role_sql(user: &str, password: &str) -> String {
    let u = escape_ident(user);
    let p = escape_string_literal(password);
    // CREATE ROLE supports IF NOT EXISTS only on PG 12+? Use DO block.
    format!(
        "DO $$\n\
         BEGIN\n\
           IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{u}') THEN\n\
             CREATE ROLE \"{u}\" WITH LOGIN PASSWORD '{p}';\n\
           END IF;\n\
         END\n\
         $$;",
    )
}

pub(crate) fn build_db_sql(db: &str, user: &str) -> String {
    let d = escape_ident(db);
    let u = escape_ident(user);
    // We can't wrap CREATE DATABASE in DO blocks (transaction restriction);
    // use a simple "create only if absent" via psql conditional.
    format!(
        "SELECT 'CREATE DATABASE \"{d}\" OWNER \"{u}\" ENCODING ''UTF8'''\n\
         WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{d}')\\gexec\n\
         GRANT ALL PRIVILEGES ON DATABASE \"{d}\" TO \"{u}\";",
    )
}

fn escape_ident(s: &str) -> String {
    s.replace('"', "\"\"")
}

fn escape_string_literal(s: &str) -> String {
    s.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_stable() {
        let id = HostingId("01J7A8GQX5BCDEF".into());
        assert_eq!(names_for(&id, "example.cz"), names_for(&id, "example.cz"));
    }

    #[test]
    fn role_sql_contains_role_and_password() {
        let sql = build_role_sql("lm_abc_u", "p4'ss");
        assert!(sql.contains("CREATE ROLE \"lm_abc_u\""));
        assert!(sql.contains("PASSWORD 'p4''ss'"));
        assert!(sql.contains("pg_roles WHERE rolname = 'lm_abc_u'"));
    }

    #[test]
    fn db_sql_contains_db_owner_and_grant() {
        let sql = build_db_sql("lm_abc", "lm_abc_u");
        assert!(sql.contains("CREATE DATABASE \"lm_abc\" OWNER \"lm_abc_u\""));
        assert!(sql.contains("GRANT ALL PRIVILEGES ON DATABASE \"lm_abc\" TO \"lm_abc_u\""));
    }

    #[tokio::test]
    #[ignore = "requires running postgres"]
    async fn create_and_drop_round_trip() {
        let id = HostingId("01J7A8GQX5BCDEF".into());
        let r = create_db_and_role(&id, "example.cz").await.expect("ok");
        drop_db_and_role(&r.db_name, &r.db_user).await.expect("ok");
    }
}
