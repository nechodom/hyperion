//! Shared `export-bundle` driver: detect the in-place source panel, extract its
//! IR, and pack a portable bundle. Used by the standalone `hyperion-export`
//! binary (a pure-Rust, statically-linkable exporter the self-service wizard
//! serves to source boxes) and re-exported for the agent.
//!
//! All human-readable progress goes to STDERR so `--out -` keeps stdout as a
//! clean tar stream (piped into curl by the wizard bootstrap).

use crate::adapter::Location;
use crate::error::ImportError;
use crate::panel::adapter_for;
use std::path::Path;

/// Detect (or use the given `kind`) the local source panel, extract it, and
/// write a bundle to `out` (`-` streams the tar to stdout). Returns the number
/// of sites packed.
pub async fn run(kind: Option<&str>, out: &Path, only: Option<&str>) -> Result<usize, ImportError> {
    let loc = Location::InPlace;

    let adapter = match kind {
        Some(k) => adapter_for(k).ok_or_else(|| {
            ImportError::UnsupportedMode(format!(
                "unknown panel kind '{k}' (cloudpanel | hestiacp)"
            ))
        })?,
        None => {
            // Auto-detect: probe each known panel in-place.
            let mut found = None;
            for k in ["cloudpanel", "hestiacp"] {
                if let Some(a) = adapter_for(k) {
                    if a.detect(&loc).await.is_some() {
                        found = Some(a);
                        break;
                    }
                }
            }
            found.ok_or(ImportError::NotDetected)?
        }
    };

    let info = adapter.detect(&loc).await.ok_or(ImportError::NotDetected)?;
    eprintln!("• detected {} {}", info.kind.as_str(), info.version);

    let mut ir = adapter.extract(&loc).await?;
    if let Some(d) = only {
        ir.hostings.retain(|h| h.domain == d);
        if ir.hostings.is_empty() {
            return Err(ImportError::Parse {
                what: "--only".into(),
                msg: format!("no site '{d}' found in the source panel"),
            });
        }
    }

    let n = ir.hostings.len();
    eprintln!("• packing {n} site(s) (docroots + DB dumps) …");
    crate::bundle::build(&ir, out).await?;
    Ok(n)
}
