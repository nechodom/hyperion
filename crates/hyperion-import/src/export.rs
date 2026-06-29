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
///
/// `only` is an optional comma-separated allow-list of domains. When `list` is
/// true this is a **dry run**: the sites that *would* be exported are printed to
/// stdout and nothing is packed (no docroots tarred, no DBs dumped).
pub async fn run(
    kind: Option<&str>,
    out: &Path,
    only: Option<&str>,
    list: bool,
) -> Result<usize, ImportError> {
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
        let want: Vec<&str> = d
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        ir.hostings
            .retain(|h| want.iter().any(|w| w.eq_ignore_ascii_case(&h.domain)));
        if ir.hostings.is_empty() {
            return Err(ImportError::Parse {
                what: "--only".into(),
                msg: format!("no matching site for '{d}' in the source panel"),
            });
        }
    }

    let n = ir.hostings.len();

    if list {
        // Dry run: show what would be exported, pack nothing.
        print_plan(&ir);
        return Ok(n);
    }

    eprintln!("• packing {n} site(s) (docroots + DB dumps) …");
    crate::bundle::build(&ir, out).await?;
    Ok(n)
}

/// Print a human-readable preview of the sites an export would include. Goes to
/// STDOUT (the operator reads it directly — nothing is streamed in list mode).
fn print_plan(ir: &crate::ir::ImportIR) {
    println!(
        "Sites that WOULD be exported from {} {} — {} total:\n",
        ir.source.kind,
        ir.source.version,
        ir.hostings.len()
    );
    for h in &ir.hostings {
        let php = h.php_version.as_deref().unwrap_or("static");
        let dbs: Vec<&str> = h.databases.iter().map(|d| d.name.as_str()).collect();
        let dbtxt = if dbs.is_empty() {
            "no db".to_string()
        } else {
            format!("{} db: {}", dbs.len(), dbs.join(", "))
        };
        println!(
            "  • {:<40} owner={:<16} php={:<6} {}",
            h.domain, h.owner_user, php, dbtxt
        );
    }
    println!(
        "\nTo export everything, re-run without --list.\n\
         To export only some, add --only domain1,domain2 (or use the form in the wizard)."
    );
}
