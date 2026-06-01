//! `app_packs` + `wp_installs` tables.

use crate::db::StateError;
use lm_types::HostingId;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackManifest {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub wp_core: PackCoreSpec,
    #[serde(default)]
    pub plugins: Vec<PackPlugin>,
    #[serde(default)]
    pub themes: Vec<PackTheme>,
    #[serde(default)]
    pub options: serde_json::Value,
    #[serde(default)]
    pub wpcli_post_install: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackCoreSpec {
    pub version: String,
    pub locale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PackPlugin {
    Repo { from_repo: String, activate: bool },
    Asset { asset_id: String, filename: String, activate: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PackTheme {
    Repo { from_repo: String, activate: bool },
    Asset { asset_id: String, filename: String, activate: bool },
}

/// Stable content hash of a manifest. Used so that re-applying an unchanged
/// pack is a no-op and re-uploading the same bundle is deterministic.
pub fn pack_hash(manifest_json: &str) -> String {
    hex::encode(blake3::hash(manifest_json.as_bytes()).as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackRow {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub description: Option<String>,
    pub manifest_json: String,
    pub content_hash: String,
    pub created_at: i64,
    pub disabled: bool,
}

pub async fn insert_pack(
    pool: &SqlitePool,
    name: &str,
    kind: &str,
    description: Option<&str>,
    manifest_json: &str,
    now: i64,
) -> Result<i64, StateError> {
    let hash = pack_hash(manifest_json);
    let row: (i64,) = sqlx::query_as(
        r#"INSERT INTO app_packs (name, kind, description, manifest_json, content_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?) RETURNING id"#,
    )
    .bind(name)
    .bind(kind)
    .bind(description)
    .bind(manifest_json)
    .bind(hash)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get_pack_by_name(
    pool: &SqlitePool,
    name: &str,
) -> Result<Option<PackRow>, StateError> {
    let row: Option<(i64, String, String, Option<String>, String, String, i64, i64)> =
        sqlx::query_as(
            "SELECT id, name, kind, description, manifest_json, content_hash, created_at, disabled
             FROM app_packs WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(
        |(id, name, kind, description, manifest_json, content_hash, created_at, disabled)| PackRow {
            id,
            name,
            kind,
            description,
            manifest_json,
            content_hash,
            created_at,
            disabled: disabled != 0,
        },
    ))
}

pub async fn list_packs(pool: &SqlitePool) -> Result<Vec<PackRow>, StateError> {
    let rows: Vec<(i64, String, String, Option<String>, String, String, i64, i64)> =
        sqlx::query_as(
            "SELECT id, name, kind, description, manifest_json, content_hash, created_at, disabled
             FROM app_packs ORDER BY name",
        )
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, name, kind, description, manifest_json, content_hash, created_at, disabled)| PackRow {
                id,
                name,
                kind,
                description,
                manifest_json,
                content_hash,
                created_at,
                disabled: disabled != 0,
            },
        )
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WpInstallRow {
    pub hosting_id: HostingId,
    pub site_url: String,
    pub wp_version: String,
    pub installed_at: i64,
    pub last_pack_hash: String,
    pub auto_update_core: String,
    pub auto_update_plugins: bool,
    pub auto_update_themes: bool,
}

pub async fn record_install(
    pool: &SqlitePool,
    id: &HostingId,
    site_url: &str,
    wp_version: &str,
    last_pack_hash: &str,
    now: i64,
) -> Result<(), StateError> {
    sqlx::query(
        r#"INSERT INTO wp_installs
           (hosting_id, site_url, wp_version, installed_at, last_pack_hash)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(hosting_id) DO UPDATE SET
             site_url = excluded.site_url,
             wp_version = excluded.wp_version,
             installed_at = excluded.installed_at,
             last_pack_hash = excluded.last_pack_hash"#,
    )
    .bind(id.as_str())
    .bind(site_url)
    .bind(wp_version)
    .bind(now)
    .bind(last_pack_hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_install(
    pool: &SqlitePool,
    id: &HostingId,
) -> Result<Option<WpInstallRow>, StateError> {
    let row: Option<(String, String, String, i64, String, String, i64, i64)> = sqlx::query_as(
        "SELECT hosting_id, site_url, wp_version, installed_at, last_pack_hash,
                auto_update_core, auto_update_plugins, auto_update_themes
         FROM wp_installs WHERE hosting_id = ?",
    )
    .bind(id.as_str())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(hosting_id, site_url, wp_version, installed_at, last_pack_hash, core, plugins, themes)| {
            WpInstallRow {
                hosting_id: HostingId(hosting_id),
                site_url,
                wp_version,
                installed_at,
                last_pack_hash,
                auto_update_core: core,
                auto_update_plugins: plugins != 0,
                auto_update_themes: themes != 0,
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;
    use crate::{hostings, system_users};

    async fn fixture(pool: &SqlitePool) -> HostingId {
        let suid = system_users::insert(pool, "u", 1042, "/home/u", "/x", 1)
            .await
            .expect("user");
        let id = HostingId::new_v7();
        hostings::insert(pool, &id, "example.cz", suid, None, "/r", 1)
            .await
            .expect("hosting");
        id
    }

    #[test]
    fn pack_hash_is_stable_and_deterministic() {
        let a = pack_hash(r#"{"name":"x","plugins":[]}"#);
        let b = pack_hash(r#"{"name":"x","plugins":[]}"#);
        let c = pack_hash(r#"{"name":"y","plugins":[]}"#);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn manifest_parses_repo_and_asset_plugins() {
        let json = r#"{
            "kind":"wordpress",
            "name":"Agency Default",
            "wp_core":{"version":"latest","locale":"cs_CZ"},
            "plugins":[
                {"from_repo":"akismet","activate":true},
                {"asset_id":"01J","filename":"theme.zip","activate":false}
            ],
            "themes":[],
            "options":{"WP_DEBUG":false},
            "wpcli_post_install":["rewrite structure /%postname%/"]
        }"#;
        let m: PackManifest = serde_json::from_str(json).expect("parse");
        assert_eq!(m.kind, "wordpress");
        assert_eq!(m.wp_core.version, "latest");
        assert_eq!(m.plugins.len(), 2);
        match &m.plugins[0] {
            PackPlugin::Repo { from_repo, activate } => {
                assert_eq!(from_repo, "akismet");
                assert!(*activate);
            }
            other => panic!("first plugin wrong: {other:?}"),
        }
        match &m.plugins[1] {
            PackPlugin::Asset { asset_id, .. } => assert_eq!(asset_id, "01J"),
            other => panic!("second plugin wrong: {other:?}"),
        }
        assert_eq!(m.wpcli_post_install[0], "rewrite structure /%postname%/");
    }

    #[tokio::test]
    async fn pack_insert_and_lookup() {
        let pool = open_memory().await.expect("open");
        let json = r#"{"kind":"wordpress","name":"Default","plugins":[],"themes":[]}"#;
        let id = insert_pack(&pool, "Default", "wordpress", None, json, 100)
            .await
            .expect("insert");
        assert!(id > 0);
        let got = get_pack_by_name(&pool, "Default")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.name, "Default");
        assert_eq!(got.content_hash, pack_hash(json));
        let all = list_packs(&pool).await.expect("list");
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn pack_kind_check_rejects_unknown() {
        let pool = open_memory().await.expect("open");
        let r = insert_pack(&pool, "Bogus", "joomla", None, "{}", 1).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn wp_install_record_and_upsert() {
        let pool = open_memory().await.expect("open");
        let id = fixture(&pool).await;
        record_install(&pool, &id, "https://example.cz", "6.5.2", "hash1", 100)
            .await
            .expect("install");
        let got = get_install(&pool, &id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.site_url, "https://example.cz");
        assert_eq!(got.wp_version, "6.5.2");
        record_install(&pool, &id, "https://example.cz", "6.5.3", "hash2", 200)
            .await
            .expect("update");
        let got = get_install(&pool, &id).await.expect("get").expect("present");
        assert_eq!(got.wp_version, "6.5.3");
        assert_eq!(got.last_pack_hash, "hash2");
    }
}
