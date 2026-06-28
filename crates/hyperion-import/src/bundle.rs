//! Export-bundle format: a portable archive an operator produces on the source
//! box (via `hyperion-agent export-bundle`) and hands to Hyperion, so the import
//! needs no inbound SSH/root to the source.
//!
//! Layout of `bundle.tar`:
//! ```text
//! manifest.json                          # serde_json of the whole ImportIR
//! sites/<sanitized-domain>/docroot.tar.gz
//! sites/<sanitized-domain>/db/<dbname>.dump   # mysqldump (plain) | pg_dump -Fc
//! ```
//! The manifest IS the source of truth (the IR is already serialisable); per-site
//! dirs are keyed by domain so the import side finds docroot/DB without the
//! original source paths. `build` runs on the source; `read_manifest` on the node.

use crate::adapter::shell_quote;
use crate::error::ImportError;
use crate::ir::{ImportIR, IrDatabase, IrDbEngine};
use std::path::Path;
use tokio::process::Command;

/// Manifest filename inside the bundle.
pub const MANIFEST: &str = "manifest.json";

/// Per-site subdirectory name inside the bundle — the domain with anything
/// outside `[A-Za-z0-9.-]` collapsed to `_`. Used identically on both sides.
pub fn site_dir(domain: &str) -> String {
    domain
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Read + parse the manifest (the serialized IR) from an already-extracted
/// bundle directory. `None` if absent or unparseable (→ "not a valid bundle").
pub async fn read_manifest(dir: &Path) -> Option<ImportIR> {
    let txt = tokio::fs::read_to_string(dir.join(MANIFEST)).await.ok()?;
    serde_json::from_str(&txt).ok()
}

/// Build a portable bundle from an extracted IR. Runs on the SOURCE box (as
/// root/sudo): tars each docroot, dumps each DB, writes the manifest, then packs
/// everything into `out`. Shells out to `tar`/`mysqldump`/`pg_dump` (present on
/// any panel box) so there are no extra crate deps.
pub async fn build(ir: &ImportIR, out: &Path) -> Result<(), ImportError> {
    // `--out -` streams the final tar straight to stdout (piped into curl on the
    // source by the self-service bootstrap — no bundle file lands on disk).
    let to_stdout = out.as_os_str() == "-";
    let stage = if to_stdout {
        std::env::temp_dir().join(format!("hyperion-export-stage-{}", std::process::id()))
    } else {
        out.with_extension("bundle-stage")
    };
    let _ = tokio::fs::remove_dir_all(&stage).await;
    tokio::fs::create_dir_all(&stage).await?;

    let manifest = serde_json::to_string_pretty(ir).map_err(|e| ImportError::Command {
        cmd: "serialize manifest".into(),
        msg: e.to_string(),
    })?;
    tokio::fs::write(stage.join(MANIFEST), manifest).await?;

    for h in &ir.hostings {
        let site = stage.join("sites").join(site_dir(&h.domain));
        tokio::fs::create_dir_all(site.join("db")).await?;
        if Path::new(&h.docroot).is_dir() {
            run(
                "tar",
                &[
                    "czf",
                    &site.join("docroot.tar.gz").display().to_string(),
                    "-C",
                    &h.docroot,
                    ".",
                ],
            )
            .await?;
        }
        for db in &h.databases {
            let dest = site.join("db").join(format!("{}.dump", db.name));
            dump_db(db, &dest).await?;
        }
    }

    if to_stdout {
        // Stream the packed bundle to our stdout (inherited by .status()).
        let status = Command::new("tar")
            .arg("cf")
            .arg("-")
            .arg("-C")
            .arg(&stage)
            .arg(".")
            .status()
            .await?;
        let _ = tokio::fs::remove_dir_all(&stage).await;
        if !status.success() {
            return Err(ImportError::Command {
                cmd: "tar cf - (stream)".into(),
                msg: format!("tar exited with {status}"),
            });
        }
        return Ok(());
    }

    run(
        "tar",
        &[
            "cf",
            &out.display().to_string(),
            "-C",
            &stage.display().to_string(),
            ".",
        ],
    )
    .await?;
    let _ = tokio::fs::remove_dir_all(&stage).await;
    Ok(())
}

/// Dump one DB to `dest`, matching the format the restore helpers expect
/// (mariadb/mysql → plain SQL; postgres → custom `-Fc`).
async fn dump_db(db: &IrDatabase, dest: &Path) -> Result<(), ImportError> {
    let cmd = match db.engine {
        IrDbEngine::Postgres => {
            format!("sudo -u postgres pg_dump -Fc -- {}", shell_quote(&db.name))
        }
        _ => format!(
            "mysqldump --single-transaction --routines --triggers --events -- {}",
            shell_quote(&db.name)
        ),
    };
    let out = Command::new("sh").arg("-c").arg(&cmd).output().await?;
    if !out.status.success() {
        return Err(ImportError::Command {
            cmd: format!("dump database {}", db.name),
            msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    tokio::fs::write(dest, &out.stdout).await?;
    Ok(())
}

async fn run(bin: &str, args: &[&str]) -> Result<(), ImportError> {
    let out = Command::new(bin).args(args).output().await?;
    if !out.status.success() {
        return Err(ImportError::Command {
            cmd: format!("{bin} {}", args.join(" ")),
            msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(())
}
