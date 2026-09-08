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
    json: bool,
) -> Result<usize, ImportError> {
    run_with_journal(kind, out, only, list, json, None).await
}

/// What the bootstrap needs to know BEFORE it commits to anything: how big this
/// export is, whether the box has room, and therefore whether the operator gets
/// a live progress bar or a detached run they check on later.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Estimate {
    pub sites: usize,
    /// Σ `du -sb` of the selected docroots. `None` when any one of them could
    /// not be measured — the caller must then show no percentage and no ETA
    /// rather than substituting a guess.
    pub input_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    /// What packing this selection needs on the staging filesystem, by the same
    /// formula the exporter's own preflight applies.
    pub needed_bytes: Option<u64>,
    /// `false` only when both figures are known AND the space is not there.
    /// An unmeasurable payload leaves this `true`: a guess must never refuse
    /// work, and the packer's own preflight is still behind it.
    pub fits: bool,
    /// `"foreground"` (progress bar in the terminal) or `"background"`.
    ///
    /// This decides only what is DISPLAYED. The run is detached either way, so
    /// an SSH drop can never cancel an export — which is what the operator
    /// actually asked for, and what a literal reading of "small = foreground"
    /// would have failed to deliver for a 2.9 GB site.
    pub mode: &'static str,
}

/// Measure a would-be export without packing anything.
pub async fn estimate(kind: Option<&str>, only: Option<&str>) -> Result<Estimate, ImportError> {
    let (_info, ir) = detect_and_extract(kind, only).await?;
    let input_bytes = crate::bundle::measure_payload(&ir).await;
    let free_bytes = crate::bundle::avail_bytes(std::env::temp_dir().as_path()).await;
    // An unmeasurable payload is treated as large: detached is strictly the more
    // robust path, so uncertainty must not resolve toward the fragile one.
    let mode = match input_bytes {
        Some(b) if b < crate::progress::FOREGROUND_MAX_BYTES => "foreground",
        _ => "background",
    };
    // Two copies: the staged tree, then the archive packed beside it. The
    // exporter's own preflight refines this by checking whether the bundle
    // lands on a different filesystem; this is the conservative reading, taken
    // before anything is written so the operator hears it while they are still
    // watching rather than an hour into a detached run.
    let needed_bytes = input_bytes.map(|b| crate::bundle::pack_needed_bytes(b, 2));
    let fits = match (needed_bytes, free_bytes) {
        (Some(need), Some(free)) => free >= need,
        _ => true,
    };
    Ok(Estimate {
        sites: ir.hostings.len(),
        input_bytes,
        free_bytes,
        needed_bytes,
        fits,
        mode,
    })
}

/// Detect the panel once and extract its IR, applying `--only`.
///
/// One `detect()` call, not two: it used to be called again after the probe
/// loop, and on CloudPanel each call shells out to `clpctl --version`.
async fn detect_and_extract(
    kind: Option<&str>,
    only: Option<&str>,
) -> Result<(crate::adapter::SourcePanelInfo, crate::ir::ImportIR), ImportError> {
    let loc = Location::InPlace;
    let (adapter, info) = resolve_adapter(kind, &loc).await?;
    let mut ir = adapter.extract(&loc).await?;
    apply_only(&mut ir, only)?;
    Ok((info, ir))
}

fn apply_only(ir: &mut crate::ir::ImportIR, only: Option<&str>) -> Result<(), ImportError> {
    let Some(d) = only else { return Ok(()) };
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
    Ok(())
}

/// See [`run`]. `journal`, when given, receives one event per packed site and
/// per skipped artefact so a detached run can be asked where it is.
pub async fn run_with_journal(
    kind: Option<&str>,
    out: &Path,
    only: Option<&str>,
    list: bool,
    json: bool,
    journal: Option<&Path>,
) -> Result<usize, ImportError> {
    let loc = Location::InPlace;

    let (_adapter, info) = resolve_adapter(kind, &loc).await?;
    eprintln!("• detected {} {}", info.kind.as_str(), info.version);

    let (_info2, ir) = detect_and_extract(kind, only).await?;
    let n = ir.hostings.len();

    if list {
        // Dry run: report what would be exported, pack nothing.
        //
        // The sizes are measured HERE, not at selection time, because the
        // operator cannot choose sensibly without them — picking 30 of 63 sites
        // blind is how a 31 GB selection lands on a disk that cannot hold it,
        // and the refusal then arrives an hour into a detached run. `du` over
        // this many trees is not instant, so it says so rather than looking
        // hung.
        eprintln!("• measuring {n} site(s) — reading directory metadata, this can take a minute …");
        let sizes = crate::bundle::measure_each(&ir).await;
        let unknown = sizes.iter().filter(|s| s.is_none()).count();
        if unknown > 0 {
            eprintln!("  ⚠ {unknown} site(s) could not be measured; their size shows as unknown");
        }
        if json {
            print_plan_json(&ir, &sizes);
        } else {
            print_plan(&ir, &sizes);
        }
        return Ok(n);
    }

    eprintln!("• packing {n} site(s) (docroots + DB dumps) …");
    crate::bundle::build_with_journal(&ir, out, journal).await?;
    Ok(n)
}

async fn resolve_adapter(
    kind: Option<&str>,
    loc: &Location,
) -> Result<
    (
        Box<dyn crate::adapter::SourceAdapter>,
        crate::adapter::SourcePanelInfo,
    ),
    ImportError,
> {
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
                    if a.detect(loc).await.is_some() {
                        found = Some(a);
                        break;
                    }
                }
            }
            found.ok_or(ImportError::NotDetected)?
        }
    };
    let info = adapter.detect(loc).await.ok_or(ImportError::NotDetected)?;
    Ok((adapter, info))
}

/// Emit the would-be-exported sites as a JSON array to STDOUT — the contract the
/// interactive wizard parses to render its checklist. Shape:
/// `[{"domain","owner","php","dbs":[...]}]`.
fn print_plan_json(ir: &crate::ir::ImportIR, sizes: &[Option<u64>]) {
    #[derive(serde::Serialize)]
    struct ListSite<'a> {
        domain: &'a str,
        owner: &'a str,
        php: &'a str,
        dbs: Vec<&'a str>,
        /// Docroot size in bytes, or absent when it could not be measured.
        /// The panel shows "unknown" for those and refuses to total a selection
        /// containing one — a picker that quietly counts an unmeasured site as
        /// zero is how an operator picks a set that cannot possibly fit.
        #[serde(skip_serializing_if = "Option::is_none")]
        bytes: Option<u64>,
    }
    let sites: Vec<ListSite> = ir
        .hostings
        .iter()
        .enumerate()
        .map(|(i, h)| ListSite {
            domain: &h.domain,
            owner: &h.owner_user,
            php: h.php_version.as_deref().unwrap_or("static"),
            dbs: h.databases.iter().map(|d| d.name.as_str()).collect(),
            bytes: sizes.get(i).copied().flatten(),
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string(&sites).unwrap_or_else(|_| "[]".into())
    );
}

/// Print a human-readable preview of the sites an export would include. Goes to
/// STDOUT (the operator reads it directly — nothing is streamed in list mode).
fn print_plan(ir: &crate::ir::ImportIR, sizes: &[Option<u64>]) {
    println!(
        "Sites that WOULD be exported from {} {} — {} total:\n",
        ir.source.kind,
        ir.source.version,
        ir.hostings.len()
    );
    // Largest first: the operator's question is "what can I take now", and the
    // answer starts with what is too big to take at all.
    let mut order: Vec<usize> = (0..ir.hostings.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(sizes.get(i).copied().flatten().unwrap_or(0)));
    for i in order {
        let h = &ir.hostings[i];
        let php = h.php_version.as_deref().unwrap_or("static");
        let dbs: Vec<&str> = h.databases.iter().map(|d| d.name.as_str()).collect();
        let dbtxt = if dbs.is_empty() {
            "no db".to_string()
        } else {
            format!("{} db: {}", dbs.len(), dbs.join(", "))
        };
        let size = match sizes.get(i).copied().flatten() {
            Some(b) => crate::progress::human_bytes(b),
            None => "unknown".into(),
        };
        println!(
            "  • {:<40} {:>9}  owner={:<16} php={:<6} {}",
            h.domain, size, h.owner_user, php, dbtxt
        );
    }
    println!(
        "\nTo export everything, re-run without --list.\n\
         To export only some, add --only domain1,domain2 (or use the form in the wizard)."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runner parses `--estimate` with `sed`, so the JSON's SHAPE is a wire
    /// contract, not an implementation detail. Renaming a field or changing a
    /// bool to a string would leave the runner silently reading an empty value
    /// — and an empty `fits` means the pre-flight refusal never fires, which is
    /// the whole point of it.
    #[test]
    fn the_estimate_json_matches_what_the_runner_greps_for() {
        let e = Estimate {
            sites: 3,
            input_bytes: Some(31_349_873_409),
            free_bytes: Some(10_000_000_000),
            needed_bytes: Some(75_759_696_180),
            fits: false,
            mode: "background",
        };
        let json = serde_json::to_string(&e).expect("serialize");

        // Exactly the patterns in assets/import-runner.sh.
        for key in ["input_bytes", "free_bytes", "needed_bytes"] {
            let pat = format!("\"{key}\":");
            let at = json
                .find(&pat)
                .unwrap_or_else(|| panic!("no {key} in {json}"));
            let rest = &json[at + pat.len()..];
            assert!(
                rest.chars().next().is_some_and(|c| c.is_ascii_digit()),
                "{key} must serialise as a bare integer for the runner's sed: {json}"
            );
        }
        assert!(
            json.contains("\"fits\":false"),
            "fits must be a bare lowercase bool: {json}"
        );
        assert!(
            json.contains("\"mode\":\"background\""),
            "mode must be a quoted lowercase word: {json}"
        );
    }

    /// An unmeasurable payload must not refuse the export. The packer's own
    /// pre-flight is still behind it; a guess must never be the thing that
    /// stops an operator.
    #[test]
    fn an_unmeasured_selection_is_never_refused() {
        let json = serde_json::to_string(&Estimate {
            sites: 1,
            input_bytes: None,
            free_bytes: Some(1),
            needed_bytes: None,
            fits: true,
            mode: "background",
        })
        .expect("serialize");
        assert!(json.contains("\"fits\":true"), "{json}");
        // `input_bytes` is null, so the runner's sed yields an empty string and
        // its `[ -n "$NEED_BYTES" ]` guard keeps the refusal from firing.
        assert!(json.contains("\"needed_bytes\":null"), "{json}");
    }
}
