//! Writing `/etc/hyperion/node-id.json` — the file that holds a worker's
//! identity and its per-node secret.
//!
//! Three writers share it inside one agent process: enrollment, the
//! heartbeat (pinning the master's key on first receipt) and `agent
//! repin`. They used to each write `node-id.json.tmp` and rename it over
//! the original, which went wrong two ways:
//!
//! - the temp file was created at the process umask (usually 0644) and
//!   only chmod-ed to 0600 AFTER the secret was in it, so for a moment any
//!   local user — and every hosted site is one — could read it;
//! - the heartbeat wrote back the WHOLE file as it had read it before its
//!   network round trip. A re-enrollment that landed in that window (new
//!   identity, new secret) was overwritten with the old one, leaving a node
//!   whose every heartbeat failed "bad secret".
//!
//! [`write_private`] fixes the first; [`lock`] serialises read-modify-write
//! cycles so a writer always modifies what is currently on disk.

use std::path::Path;
use tokio::io::AsyncWriteExt;

static NODE_STATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Hold this across "read node-id.json, change it, write it back" so no
/// other writer in this process can interleave.
pub async fn lock() -> tokio::sync::MutexGuard<'static, ()> {
    NODE_STATE_LOCK.lock().await
}

/// Atomically replace `path` with `bytes`, mode 0600 from the first byte.
///
/// The temp file is created with `O_EXCL` and mode 0600 BEFORE anything is
/// written to it, under a name unique to this call, in the same directory
/// (so the rename is atomic). A failed write never leaves it behind.
pub async fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = dir {
        tokio::fs::create_dir_all(dir).await?;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".into());
    let tmp_name = format!(".{name}.{}.{}.tmp", std::process::id(), ulid::Ulid::new());
    let tmp = match dir {
        Some(d) => d.join(tmp_name),
        None => std::path::PathBuf::from(tmp_name),
    };
    let result = async {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .await?;
        f.write_all(bytes).await?;
        f.sync_all().await?;
        drop(f);
        tokio::fs::rename(&tmp, path).await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn writes_0600_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("node-id.json");
        write_private(&p, b"{\"secret\":\"s\"}").await.unwrap();
        write_private(&p, b"{\"secret\":\"t\"}").await.unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"{\"secret\":\"t\"}");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "temp files left behind: {names:?}");
    }
}
