//! Secret-file store under `/etc/linux-manager/secrets/`.
//! Each file is mode 0600, JSON-encoded.

use lm_types::SecretId;
use serde::{de::DeserializeOwned, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct SecretsStore {
    root: PathBuf,
}

impl SecretsStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub async fn put<T: Serialize>(&self, id: &SecretId, v: &T) -> Result<(), SecretsError> {
        fs::create_dir_all(&self.root).await?;
        // Ensure the dir is 0700 root-only.
        let _ = fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700)).await;
        let path = self.path(id);
        let bytes = serde_json::to_vec(v)?;
        let tmp = with_ext(&path, "tmp");
        fs::write(&tmp, bytes).await?;
        fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
        fs::rename(&tmp, &path).await?;
        Ok(())
    }

    pub async fn get<T: DeserializeOwned>(&self, id: &SecretId) -> Result<T, SecretsError> {
        let bytes = fs::read(self.path(id)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn delete(&self, id: &SecretId) -> Result<(), SecretsError> {
        let p = self.path(id);
        if p.exists() {
            fs::remove_file(p).await?;
        }
        Ok(())
    }

    fn path(&self, id: &SecretId) -> PathBuf {
        self.root.join(format!("{}.json", id.0))
    }
}

fn with_ext(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Cred {
        user: String,
        password: String,
    }

    #[tokio::test]
    async fn round_trip_and_perms_0600() {
        let d = tempfile::tempdir().expect("tempdir");
        let store = SecretsStore::new(d.path());
        let id = SecretId::new();
        let v = Cred {
            user: "u".into(),
            password: "p".into(),
        };
        store.put(&id, &v).await.expect("put");
        let back: Cred = store.get(&id).await.expect("get");
        assert_eq!(back, v);
        let m = std::fs::metadata(d.path().join(format!("{}.json", id.0)))
            .expect("md")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o600);
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let d = tempfile::tempdir().expect("tempdir");
        let store = SecretsStore::new(d.path());
        let id = SecretId::new();
        store.delete(&id).await.expect("absent ok");
        let v = Cred {
            user: "u".into(),
            password: "p".into(),
        };
        store.put(&id, &v).await.expect("put");
        store.delete(&id).await.expect("present ok");
        store.delete(&id).await.expect("absent again ok");
    }

    #[tokio::test]
    async fn put_creates_root_dir_with_0700() {
        let d = tempfile::tempdir().expect("tempdir");
        let store_root = d.path().join("nested/secrets");
        let store = SecretsStore::new(&store_root);
        let id = SecretId::new();
        store
            .put(
                &id,
                &Cred {
                    user: "u".into(),
                    password: "p".into(),
                },
            )
            .await
            .expect("put");
        let m = std::fs::metadata(&store_root)
            .expect("md")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o700);
    }
}
