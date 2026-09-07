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
use std::path::{Path, PathBuf};
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

/// Refuse an export in which two domains would share one bundle directory.
///
/// [`site_dir`] collapses every character outside `[A-Za-z0-9.-]` to `_`, so
/// `a b.cz` and `a-b.cz` … and, more realistically, an IDN and its transcription
/// can land on the same name. The staging loop writes
/// `sites/<site_dir>/docroot.tar.gz` unconditionally, so the second site would
/// OVERWRITE the first while `manifest.json` still listed both — the import then
/// creates site A populated with site B's files, with no error anywhere and a
/// green job. That is silent cross-site data corruption, and its likelihood
/// scales with how many sites are selected at once.
///
/// Refusing is deliberate. Disambiguating with a hash suffix would need the
/// import side to learn the same mapping, and a rename that only one side knows
/// is a worse failure than a clear stop. The operator can import the two in
/// separate batches.
fn assert_no_site_dir_collision(ir: &ImportIR) -> Result<(), ImportError> {
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for h in &ir.hostings {
        let dir = site_dir(&h.domain);
        if let Some(first) = seen.insert(dir.clone(), h.domain.clone()) {
            return Err(ImportError::Command {
                cmd: "plan bundle layout".into(),
                msg: format!(
                    "{first:?} and {:?} would both be packed as sites/{dir}/, so one \
                     would silently overwrite the other. Export them in separate \
                     batches (pick one, import it, then pick the other).",
                    h.domain
                ),
            });
        }
    }
    Ok(())
}

/// Σ of the selected docroots, or `None` when any one of them could not be
/// measured.
///
/// `None` is load-bearing: it means "there is no denominator", and every caller
/// must then decline to show a percentage or an ETA rather than substituting a
/// guess. Split out of `preflight_space`, which computed this and threw it away.
pub async fn measure_payload(ir: &ImportIR) -> Option<u64> {
    let mut payload: u64 = 0;
    for h in &ir.hostings {
        payload = payload.saturating_add(dir_bytes(Path::new(&h.docroot)).await?);
    }
    Some(payload)
}

/// Headroom demanded on top of every measured import figure: 1 GiB for the
/// target's own scratch (nginx/php-fpm config, the DB load, the job log) and
/// for the ordinary drift between `du -sb` and what a filesystem actually
/// charges for the same tree.
pub const IMPORT_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;

/// What an import will WRITE beyond the bundle itself: every site's docroot
/// inflated into its hosting tree, plus the per-site copy of each database dump
/// that the restore step makes.
///
/// `None` when any site in the manifest carries no measured docroot size — an
/// older bundle, or a docroot `du` could not read. There is then no denominator
/// and the caller must skip its check rather than refuse on a partial sum,
/// which would be a guess pretending to be a measurement.
pub fn inflate_bytes(ir: &ImportIR) -> Option<u64> {
    if ir.hostings.is_empty() {
        return None;
    }
    let mut total: u64 = 0;
    for h in &ir.hostings {
        if h.docroot_bytes == 0 {
            // Not "this site is empty": `du -sb` never says 0 for a directory
            // that exists, so 0 is exactly the "never measured" marker.
            return None;
        }
        total = total
            .saturating_add(h.docroot_bytes)
            .saturating_add(h.db_bytes);
    }
    Some(total)
}

/// Free bytes a node needs before importing a `bundle_len`-byte bundle whose
/// manifest inflates to `inflate` bytes.
///
/// `bundle_copies` is the whole reason this is a function rather than a sum
/// written twice:
///   * **2** before the transfer — the arriving `.tar` lands on the disk AND is
///     then unpacked into a staging tree of its own size beside it;
///   * **1** once the `.tar` is already on disk, because `df` has by then
///     already stopped counting those bytes as free. Demanding them twice there
///     would refuse an import that fits.
pub fn import_needed_bytes(bundle_len: u64, inflate: u64, bundle_copies: u64) -> u64 {
    bundle_len
        .saturating_mul(bundle_copies)
        .saturating_add(inflate)
        .saturating_add(IMPORT_HEADROOM_BYTES)
}

/// Size + hex sha256 of a finished bundle, read in one streaming pass.
///
/// This digest is the bundle's only real integrity check. `tar tf` is not one:
/// a tar truncated at a 512-byte block boundary and padded with zeros — exactly
/// what a crash or a short write leaves behind — reads as a clean end-of-archive
/// marker, so `tar tf` exits 0 while silently omitting every member past the
/// cut. Verified: a 6-member archive cut at a block boundary lists 5 and exits 0.
pub async fn seal(path: &Path) -> Result<(u64, String), ImportError> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, hex_lower(&hasher.finalize())))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Run a shell command with its stdout going STRAIGHT to `dest`.
///
/// The point is that the bytes never exist in this process's memory. The dump
/// helpers used to `.output()` into a `Vec<u8>` and then write it, so a 4 GB
/// database was a 4 GB allocation on somebody else's production server — and now
/// that the run is detached, the OOM killer would take it with no terminal event
/// in the journal, leaving a status frozen mid-phase.
///
/// `.status()` and NOT `.output()`: `output()` installs its own pipes and
/// silently overrides a `File` stdout, which this repo has been bitten by before.
async fn sh_to_file(cmd: &str, dest: &Path) -> Result<u64, ImportError> {
    let file = std::fs::File::create(dest)?;
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(std::process::Stdio::from(file))
        .stderr(std::process::Stdio::piped())
        .status()
        .await?;
    if !status.success() {
        let _ = tokio::fs::remove_file(dest).await;
        return Err(ImportError::Command {
            cmd: cmd.chars().take(80).collect(),
            msg: format!("exited with {status}"),
        });
    }
    Ok(tokio::fs::metadata(dest)
        .await
        .map(|m| m.len())
        .unwrap_or(0))
}

/// Create a private, mode-0700 working directory under the system temp dir with
/// a randomized (non-pid-derived) name.
///
/// SECURITY (sec-findings #5): the source MariaDB ROOT password is written into
/// this dir's defaults-file. On a multi-tenant source box, a predictable
/// `/tmp/hyperion-mysql-<pid>-<db>.cnf` path lets a local attacker pre-plant a
/// symlink (root follows it, leaking the password) or race the 0644 window. A
/// 0700 dir created with `create_dir` (which fails on a pre-existing path,
/// O_EXCL-style) plus a randomized name means the attacker can neither enter the
/// dir nor predict/pre-create the file inside it.
async fn secure_private_dir(prefix: &str) -> std::io::Result<PathBuf> {
    use rand::Rng;
    #[cfg(unix)]
    use std::os::unix::fs::DirBuilderExt;
    for _ in 0..16 {
        let rnd: u64 = rand::thread_rng().gen();
        let dir = std::env::temp_dir().join(format!("{prefix}-{rnd:016x}"));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        b.mode(0o700);
        // `create` (not create_all) fails if the path already exists — so a
        // pre-planted dir/symlink with this name can't be reused.
        match b.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique private temp dir",
    ))
}

/// Securely create-and-write a file with mode 0600 using O_EXCL semantics, so it
/// can never be a pre-existing symlink and is never momentarily world-readable.
async fn secure_write_0600(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = path.to_path_buf();
    let contents = contents.to_string();
    // std fs is fine here (small file); keep it off the async reactor.
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(contents.as_bytes())?;
        Ok(())
    })
    .await
    .map_err(|e| std::io::Error::other(format!("secure write join: {e}")))?
}

/// Read + parse the manifest (the serialized IR) from an already-extracted
/// bundle directory. `None` if absent or unparseable (→ "not a valid bundle").
pub async fn read_manifest(dir: &Path) -> Option<ImportIR> {
    let txt = tokio::fs::read_to_string(dir.join(MANIFEST)).await.ok()?;
    serde_json::from_str(&txt).ok()
}

/// Bytes free on the filesystem holding `path`, via `df -P -B1`.
/// `None` on any exec/parse failure — an unknown figure must not block
/// an export that would have worked.
/// Free bytes on the filesystem holding `path`. `None` when `df` cannot say —
/// and a caller must then skip the check rather than refuse work on a guess.
pub async fn avail_bytes(path: &Path) -> Option<u64> {
    let out = tokio::process::Command::new("/bin/df")
        .args(["-P", "-B1", "--"])
        .arg(path)
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().nth(1)?.split_whitespace().nth(3)?.parse().ok()
}

/// Apparent size of a directory tree in bytes, via `du -sb`.
async fn dir_bytes(path: &Path) -> Option<u64> {
    let out = tokio::process::Command::new("/usr/bin/du")
        .args(["-sb", "--"])
        .arg(path)
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Refuse to start an export that cannot possibly fit.
///
/// Staging writes a tar of every docroot plus a dump of every database
/// into `stage`, and then — unless we are streaming to stdout — packs
/// that whole tree into a second archive beside it. So the peak
/// requirement is roughly TWICE the payload, on top of whatever else
/// shares that filesystem.
///
/// This exists because running out of space mid-export fails deep inside
/// `tar` or `mysqldump` with a message about one file, long after the
/// operator has committed to the migration, leaving a half-written stage
/// dir behind. Checking first turns that into one sentence up front that
/// names the path, the shortfall and the fix.
///
/// Deliberately conservative in the SAFE direction: an unmeasurable
/// docroot or an unreadable `df` skips the check entirely rather than
/// blocking a legitimate export.
async fn preflight_space(
    ir: &ImportIR,
    stage: &Path,
    needs_archive: bool,
) -> Result<(), ImportError> {
    // `stage` does not exist yet; ask about its parent, which does.
    let probe = stage.parent().unwrap_or(Path::new("/"));
    let Some(avail) = avail_bytes(probe).await else {
        return Ok(());
    };
    let mut payload: u64 = 0;
    for h in &ir.hostings {
        match dir_bytes(Path::new(&h.docroot)).await {
            Some(b) => payload = payload.saturating_add(b),
            // A docroot we cannot measure makes the whole estimate a
            // guess; a guess must not be used to refuse work.
            None => return Ok(()),
        }
    }
    if payload == 0 {
        return Ok(());
    }
    // Database dumps are not measurable before they are taken. Allow a
    // flat 20 % of the file payload for them plus 512 MB of headroom, so
    // the check errs toward letting a borderline export proceed rather
    // than blocking one that would have fit.
    let dumps = payload / 5;
    let copies = if needs_archive { 2 } else { 1 };
    let needed = payload
        .saturating_add(dumps)
        .saturating_mul(copies)
        .saturating_add(512 * 1024 * 1024);
    if avail >= needed {
        return Ok(());
    }
    Err(ImportError::Command {
        cmd: format!("preflight: free space on {}", probe.display()),
        msg: format!(
            "not enough room to stage this export: {} free, about {} needed \
             ({} of site files{}{}). Free up space, or point TMPDIR at a \
             filesystem that has room (TMPDIR=/path/with/space) and re-run.",
            human(avail),
            human(needed),
            human(payload),
            if dumps > 0 {
                format!(" plus ~{} for database dumps", human(dumps))
            } else {
                String::new()
            },
            if copies > 1 {
                ", counted twice because the staged tree is then packed into an archive beside it"
            } else {
                ""
            },
        ),
    })
}

/// Build a portable bundle from an extracted IR. Runs on the SOURCE box (as
/// root/sudo): tars each docroot, dumps each DB, writes the manifest, then packs
/// everything into `out`. Shells out to `tar`/`mysqldump`/`pg_dump` (present on
/// any panel box) so there are no extra crate deps.
pub async fn build(ir: &ImportIR, out: &Path) -> Result<(), ImportError> {
    build_with_journal(ir, out, None).await
}

/// Build a portable bundle from an extracted IR. Runs on the SOURCE box (as
/// root/sudo): tars each docroot, dumps each DB, writes the manifest, then packs
/// everything into `out`. Shells out to `tar`/`mysqldump`/`pg_dump` (present on
/// any panel box) so there are no extra crate deps.
///
/// When `journal` is given, one event is appended per finished site and one per
/// skipped artefact, so a DETACHED run can be asked where it is from another
/// shell. That is the only reason this takes the argument: nothing here reads
/// the journal back.
///
/// `out == "-"` keeps the original streaming behaviour for the legacy bootstrap
/// script; every other path builds a real file, because an offset into a
/// regenerated stream is meaningless (tar member order is readdir order and a
/// re-taken dump differs byte-for-byte from the last one) while an offset into a
/// finished file is exactly what resume needs.
pub async fn build_with_journal(
    ir: &ImportIR,
    out: &Path,
    journal: Option<&Path>,
) -> Result<(), ImportError> {
    // Before anything is written: two domains that would collapse onto one
    // bundle directory must stop the run, not overwrite each other.
    assert_no_site_dir_collision(ir)?;

    let to_stdout = out.as_os_str() == "-";
    // A randomized 0700 directory, not `$TMPDIR/hyperion-export-stage-<pid>`.
    // This tree holds every selected site's docroot AND plaintext database
    // dumps, on a box whose tenants are local users; a pid-predictable name
    // created at the default umask in world-writable temp is both readable and
    // pre-plantable. The same file already uses this helper for the MariaDB
    // defaults-file, for the same reason.
    let stage = secure_private_dir("hyperion-export-stage").await?;
    // From here on every early return must take the stage tree with it — it is
    // the secrets, not just scratch space.
    let result = build_inner(ir, out, journal, &stage, to_stdout).await;
    let _ = tokio::fs::remove_dir_all(&stage).await;
    result
}

async fn build_inner(
    ir: &ImportIR,
    out: &Path,
    journal: Option<&Path>,
    stage: &Path,
    to_stdout: bool,
) -> Result<(), ImportError> {
    preflight_space(ir, stage, !to_stdout).await?;

    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };
    let note = |ev: crate::progress::Event| {
        if let Some(j) = journal {
            let _ = crate::progress::append(j, &ev);
        }
    };

    // A single unreadable docroot or DB must not sink a 40-site migration:
    // record the failure, drop the partial artefact, and keep going. What is
    // NEW is that the record travels INSIDE the bundle (ir.skipped), so the
    // import side can tell a deliberate omission from a truncated upload.
    let mut skipped: Vec<crate::ir::IrSkipped> = Vec::new();
    let mut input_done: u64 = 0;
    // Per-site (docroot_bytes, db_bytes), stamped into the manifest below. These
    // are the UNCOMPRESSED figures — the only ones that say what the import will
    // actually have to write — and this loop is already measuring the docroot
    // for the progress denominator, so recording it costs nothing extra.
    let mut measured: Vec<(u64, u64)> = Vec::with_capacity(ir.hostings.len());

    for (idx, h) in ir.hostings.iter().enumerate() {
        let mut db_bytes: u64 = 0;
        let site = stage.join("sites").join(site_dir(&h.domain));
        tokio::fs::create_dir_all(site.join("db")).await?;
        if Path::new(&h.docroot).is_dir() {
            let tgz = site.join("docroot.tar.gz");
            if let Err(e) = run(
                "tar",
                &["czf", &tgz.display().to_string(), "-C", &h.docroot, "."],
            )
            .await
            {
                let _ = tokio::fs::remove_file(&tgz).await;
                eprintln!("  ⚠ {}: docroot skipped — {e}", h.domain);
                skipped.push(crate::ir::IrSkipped {
                    domain: h.domain.clone(),
                    what: "docroot".into(),
                    why: e.to_string(),
                });
                note(crate::progress::Event::Skip {
                    t: now(),
                    what: format!("{} (docroot)", h.domain),
                    why: e.to_string(),
                });
            }
        }
        for db in &h.databases {
            let dest = site.join("db").join(format!("{}.dump", db.name));
            let dumped = dump_db(db, &dest, &ir.source.kind).await;
            if dumped.is_ok() {
                // Measured, not estimated: the dump now exists. The import
                // copies it out of the staging tree before loading it, so this
                // is space the target really has to find.
                db_bytes = db_bytes.saturating_add(
                    tokio::fs::metadata(&dest)
                        .await
                        .map(|m| m.len())
                        .unwrap_or(0),
                );
            }
            if let Err(e) = dumped {
                let _ = tokio::fs::remove_file(&dest).await;
                eprintln!("  ⚠ {}: database '{}' skipped — {e}", h.domain, db.name);
                skipped.push(crate::ir::IrSkipped {
                    domain: h.domain.clone(),
                    what: format!("db:{}", db.name),
                    why: e.to_string(),
                });
                note(crate::progress::Event::Skip {
                    t: now(),
                    what: format!("{} (db {})", h.domain, db.name),
                    why: e.to_string(),
                });
            }
        }
        let done = idx as u64 + 1;
        let docroot_bytes = dir_bytes(Path::new(&h.docroot)).await.unwrap_or(0);
        measured.push((docroot_bytes, db_bytes));
        input_done = input_done.saturating_add(docroot_bytes);
        note(crate::progress::Event::Site {
            t: now(),
            done,
            name: h.domain.clone(),
            input_done,
        });
    }

    if !skipped.is_empty() {
        eprintln!(
            "⚠ {} item(s) could not be exported and were skipped: {}",
            skipped.len(),
            skipped
                .iter()
                .map(|s| format!("{} ({})", s.domain, s.what))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // The manifest is written LAST so it can carry the skip list. The import
    // side reads it to distinguish "left out on purpose" from "truncated".
    let mut manifest_ir = ir.clone();
    manifest_ir.skipped = skipped;
    // Carry the uncompressed sizes across with the bundle. The import side sees
    // only a compressed tarball, so without these it cannot tell a 13 GB bundle
    // that inflates to 15 GB from one that inflates to 44 GB — and it was
    // approving both against a check that only covered receiving the bundle.
    for (h, (doc, db)) in manifest_ir.hostings.iter_mut().zip(measured) {
        h.docroot_bytes = doc;
        h.db_bytes = db;
    }
    let manifest =
        serde_json::to_string_pretty(&manifest_ir).map_err(|e| ImportError::Command {
            cmd: "serialize manifest".into(),
            msg: e.to_string(),
        })?;
    tokio::fs::write(stage.join(MANIFEST), manifest).await?;

    if to_stdout {
        // Legacy path, byte-for-byte as before: stream the packed bundle to our
        // stdout (inherited by `.status()`).
        let status = Command::new("tar")
            .arg("cf")
            .arg("-")
            .arg("-C")
            .arg(stage)
            .arg(".")
            .status()
            .await?;
        // The status check comes BEFORE any cleanup now. It used to run after
        // `remove_dir_all`, so a failed stream destroyed the staged tree before
        // reporting the failure — and every retry re-dumped every database.
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

    // Seal it: the exact size and digest of what will be uploaded. Both travel
    // to the panel, which refuses a bundle whose digest does not match.
    let (bytes, sha256) = seal(out).await?;
    note(crate::progress::Event::Bundle {
        t: now(),
        bytes,
        sha256,
    });
    Ok(())
}

/// Dump one DB to `dest`, matching the format the restore helpers expect
/// (mariadb/mysql → plain SQL; postgres → custom `-Fc`).
async fn dump_db(db: &IrDatabase, dest: &Path, source_kind: &str) -> Result<(), ImportError> {
    match db.engine {
        IrDbEngine::Postgres => {
            // Streamed to the file, never through a Vec: a large database must
            // not become an allocation of its own size on the source box.
            let n = sh_to_file(
                &format!("sudo -u postgres pg_dump -Fc -- {}", shell_quote(&db.name)),
                dest,
            )
            .await?;
            if n == 0 {
                let _ = tokio::fs::remove_file(dest).await;
                return Err(ImportError::Command {
                    cmd: format!("pg_dump {}", db.name),
                    msg: "produced an empty dump".into(),
                });
            }
            Ok(())
        }
        _ => dump_mariadb(&db.name, dest, source_kind).await,
    }
}

/// MariaDB/MySQL → plain SQL at `dest`.
///
/// On CloudPanel the *system* root has NO access to MariaDB (the panel sets a
/// root password), so a bare `mysqldump` fails with "Access denied … (using
/// password: NO)". Try, in order, the methods most likely to work on a panel
/// box, using the first that yields a non-empty dump:
///   1. `mysqldump` with the root creds CloudPanel stores in its own SQLite,
///      passed via a 0600 defaults-file so the password never reaches argv/ps;
///   2. `clpctl db:export` — the panel's native exporter, which handles auth and
///      any password encryption itself; its (often gzipped) output is inflated;
///   3. a plain `mysqldump` (works where root has unix_socket auth or ~/.my.cnf).
async fn dump_mariadb(name: &str, dest: &Path, source_kind: &str) -> Result<(), ImportError> {
    let mut errors: Vec<String> = Vec::new();

    if source_kind == "cloudpanel" {
        match cloudpanel_creds_dump(name, dest).await {
            Ok(Some(n)) if n > 0 => return Ok(()),
            // Record WHY each method produced nothing, so the per-site skip
            // message names every path that was tried (diagnosability across
            // dozens of sites).
            Ok(Some(_)) => errors.push("stored-creds: empty output".into()),
            Ok(None) => errors.push("stored-creds: no DB server recorded in CloudPanel".into()),
            Err(e) => errors.push(format!("stored-creds: {e}")),
        }
        match clpctl_export(name, dest).await {
            Ok(true) => return Ok(()),
            Ok(false) => errors.push("clpctl db:export: empty output".into()),
            Err(e) => errors.push(format!("clpctl: {e}")),
        }
    }

    // Plain socket mysqldump — root via unix_socket plugin or ~/.my.cnf.
    // Streamed straight to `dest`; a multi-gigabyte dump held in memory is how
    // a detached export gets OOM-killed with nothing in its journal.
    match sh_to_file(
        &format!(
            "mysqldump --single-transaction --routines --triggers --events -- {}",
            shell_quote(name)
        ),
        dest,
    )
    .await
    {
        Ok(n) if n > 0 => return Ok(()),
        Ok(_) => errors.push("mysqldump (socket): empty output".into()),
        Err(e) => errors.push(format!("mysqldump (socket): {e}")),
    }

    Err(ImportError::Command {
        cmd: format!("dump database {name}"),
        msg: errors.join("; "),
    })
}

/// CloudPanel's SQLite path — its source of truth for managed-MariaDB root creds.
const CLOUDPANEL_DB_SQ3: &str = "/home/clp/htdocs/app/data/db.sq3";

/// Read CloudPanel's stored MariaDB root creds (`database_server` table) and
/// `mysqldump` with them via a 0600 defaults-file (so the password never appears
/// in argv / `ps`). `Ok(None)` if the panel records no DB server (nothing to do
/// → let the caller fall through to `clpctl`).
async fn cloudpanel_creds_dump(name: &str, dest: &Path) -> Result<Option<u64>, ImportError> {
    let sql = "SELECT host,user_name,password,port FROM database_server \
               ORDER BY is_default DESC, id ASC LIMIT 1;";
    let q = format!(
        "sqlite3 -readonly -json {} {}",
        shell_quote(CLOUDPANEL_DB_SQ3),
        shell_quote(sql)
    );
    let raw = sh_capture(&q).await?;
    let text = String::from_utf8_lossy(&raw);
    let text = text.trim();
    if text.is_empty() || text == "[]" {
        return Ok(None);
    }
    let rows: Vec<serde_json::Map<String, serde_json::Value>> = serde_json::from_str(text)
        .map_err(|e| ImportError::Parse {
            what: "database_server".into(),
            msg: e.to_string(),
        })?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let field = |k: &str| -> String {
        match row.get(k) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    };
    let nonempty = |v: String, default: &str| if v.is_empty() { default.to_string() } else { v };
    let host = nonempty(field("host"), "localhost");
    let user = nonempty(field("user_name"), "root");
    let pass = field("password");
    let port = nonempty(field("port"), "3306");

    // SECURITY (sec-findings #5): the .cnf holds the source MariaDB ROOT
    // password. Put it in a 0700 private dir under a randomized name and create
    // it with O_EXCL + mode 0600, so it's never world-readable and can't be a
    // pre-planted symlink (TOCTOU).
    let dir = secure_private_dir("hyperion-mysql").await?;
    let cnf = dir.join(format!("{}.cnf", site_dir(name)));
    secure_write_0600(
        &cnf,
        &format!("[client]\nhost={host}\nuser={user}\npassword={pass}\nport={port}\n"),
    )
    .await?;
    let cnf_q = shell_quote(&cnf.display().to_string());
    // Streamed to `dest` rather than captured: this is the primary CloudPanel
    // dump path, so it is the one most likely to meet a multi-gigabyte database.
    let res = sh_to_file(
        &format!(
            "mysqldump --defaults-extra-file={cnf_q} --single-transaction --routines \
             --triggers --events -- {}",
            shell_quote(name)
        ),
        dest,
    )
    .await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    Ok(Some(res?))
}

/// Drive CloudPanel's own `clpctl db:export`, which authenticates internally,
/// and normalise its output to the plain SQL the bundle/restore contract
/// requires. `Ok(false)` = clpctl produced nothing usable (caller records the
/// skip and falls through); `Err` = clpctl itself failed.
///
/// Hardening (a binary `.dump` would silently break the restore, which just
/// runs `mariadb < dump`): we (1) export into a fresh dir and pick up whatever
/// file clpctl actually writes — it may not honour `--file` exactly; (2) decide
/// gzip vs plain by MAGIC BYTES, never by "try gzip then copy raw on failure";
/// (3) accept the result only if it actually looks like a SQL dump.
///
/// Note: CloudPanel v1 used `db:backup` rather than `db:export`; v2 (CE 6.x,
/// what we target) uses `db:export`. On a v1 box this errors → the DB is
/// skipped-and-reported, never silently corrupted.
async fn clpctl_export(name: &str, dest: &Path) -> Result<bool, ImportError> {
    // SECURITY (sec-findings #5): the DB dump (tenant data) lands here. Use a
    // 0700 private dir with a randomized name rather than a predictable
    // `/tmp/hyperion-clpexp-<pid>-<db>` path other local users could read/race.
    let dir = secure_private_dir("hyperion-clpexp").await?;
    let want = dir.join(format!("{}.sql.gz", site_dir(name)));
    let result = clpctl_export_inner(name, &dir, &want, dest).await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    result
}

async fn clpctl_export_inner(
    name: &str,
    dir: &Path,
    want: &Path,
    dest: &Path,
) -> Result<bool, ImportError> {
    let out = Command::new("clpctl")
        .arg("db:export")
        .arg(format!("--databaseName={name}"))
        .arg(format!("--file={}", want.display()))
        .output()
        .await?;
    if !out.status.success() {
        return Err(ImportError::Command {
            cmd: format!("clpctl db:export {name}"),
            msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    // clpctl may honour `want`, change the extension, or derive its own name —
    // take whatever single file landed in our fresh dir.
    let file = if tokio::fs::try_exists(want).await.unwrap_or(false) {
        want.to_path_buf()
    } else {
        match newest_file_in(dir).await {
            Some(f) => f,
            None => return Ok(false), // clpctl wrote nothing we can see
        }
    };

    let raw = tokio::fs::read(&file).await?;
    if raw.is_empty() {
        return Ok(false);
    }
    // gzip magic is 1f 8b. Decompress ONLY when it's really gzip; a failure here
    // is a genuine error (surfaced) — we never fall back to writing raw bytes.
    let plain = if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        sh_capture(&format!(
            "gzip -dc {}",
            shell_quote(&file.display().to_string())
        ))
        .await?
    } else {
        raw
    };
    // Refuse to write anything that isn't recognisably a SQL dump, so a stray
    // binary artefact is rejected here (recorded as a skip) instead of poisoning
    // the restore later.
    if !looks_like_sql(&plain) {
        return Ok(false);
    }
    tokio::fs::write(dest, &plain).await?;
    Ok(true)
}

/// Newest regular file in `dir`, if any.
async fn newest_file_in(dir: &Path) -> Option<PathBuf> {
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    while let Ok(Some(e)) = rd.next_entry().await {
        match e.metadata().await {
            Ok(m) if m.is_file() => {
                let t = m.modified().unwrap_or(std::time::UNIX_EPOCH);
                if best.as_ref().map(|(bt, _)| t >= *bt).unwrap_or(true) {
                    best = Some((t, e.path()));
                }
            }
            _ => {}
        }
    }
    best.map(|(_, p)| p)
}

/// Heuristic guard for the "db/<name>.dump is plain SQL" invariant: inspect only
/// the first 64 bytes (a dump's header is ASCII; binary content later in the
/// file is fine) and require it to begin with a token a SQL dump emits. A gzip
/// or other binary blob fails this and is rejected.
fn looks_like_sql(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(64)];
    let head_up = String::from_utf8_lossy(head)
        .trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
        .to_ascii_uppercase();
    if head_up.is_empty() {
        return false;
    }
    const PREFIXES: [&str; 13] = [
        "--",
        "/*",
        "#",
        "SET ",
        "CREATE",
        "INSERT",
        "DROP",
        "USE ",
        "LOCK",
        "ALTER",
        "DELIMITER",
        "START TRANSACTION",
        "BEGIN",
    ];
    PREFIXES.iter().any(|p| head_up.starts_with(p))
}

/// Run `sh -c <cmd>`, returning stdout on success or an error carrying stderr.
async fn sh_capture(cmd: &str) -> Result<Vec<u8>, ImportError> {
    let out = Command::new("sh").arg("-c").arg(cmd).output().await?;
    if !out.status.success() {
        return Err(ImportError::Command {
            cmd: cmd.to_string(),
            msg: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(out.stdout)
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

#[cfg(test)]
mod tests {
    use super::{
        assert_no_site_dir_collision, human, looks_like_sql, preflight_space, run, seal, site_dir,
    };
    use crate::ir::ImportIR;

    fn hosting_with_docroot(docroot: &str) -> crate::ir::IrHosting {
        crate::ir::IrHosting {
            source_key: "cloudpanel:u:example.cz".into(),
            domain: "example.cz".into(),
            aliases: vec![],
            owner_user: "u".into(),
            kind: crate::ir::IrSiteKind::Php,
            php_version: Some("8.3".into()),
            docroot: docroot.into(),
            proxy_upstream: None,
            databases: vec![],
            crons: vec![],
            tls: None,
            ssh_keys: vec![],
            docroot_bytes: 0,
            db_bytes: 0,
        }
    }

    /// The whole point of the preflight is that it must never be the
    /// reason a legitimate export fails. Anything it cannot measure —
    /// an unreadable docroot, an empty IR — has to pass.
    #[tokio::test]
    async fn preflight_passes_whenever_it_cannot_measure() {
        use crate::ir::ImportIR;
        let tmp = tempfile::tempdir().expect("tmp");
        let stage = tmp.path().join("stage");

        // No hostings ⇒ nothing to weigh.
        let empty = ImportIR::default();
        assert!(preflight_space(&empty, &stage, true).await.is_ok());

        // A docroot that does not exist ⇒ `du` fails ⇒ the estimate is a
        // guess ⇒ pass rather than block.
        let mut ir = ImportIR::default();
        ir.hostings
            .push(hosting_with_docroot("/definitely/not/here"));
        assert!(preflight_space(&ir, &stage, true).await.is_ok());

        // A real, tiny docroot on a normal filesystem must also pass —
        // the everyday case; a false refusal here blocks every export.
        let doc = tmp.path().join("docroot");
        std::fs::create_dir_all(&doc).expect("mkdir");
        std::fs::write(doc.join("index.php"), b"<?php echo 1;").expect("write");
        let mut ir = ImportIR::default();
        ir.hostings
            .push(hosting_with_docroot(&doc.display().to_string()));
        assert!(preflight_space(&ir, &stage, true).await.is_ok());
    }

    /// The inflate figure has exactly the same rule as the export preflight:
    /// anything it cannot measure yields no figure at all, so the checks built
    /// on it skip rather than refuse. A partial sum would be a guess wearing a
    /// measurement's clothes — and it would refuse imports that fit.
    #[test]
    fn inflate_bytes_is_none_whenever_any_site_is_unmeasured() {
        use crate::bundle::inflate_bytes;

        // Nothing to weigh.
        assert_eq!(inflate_bytes(&ImportIR::default()), None);

        // One site measured, one not (an older bundle, or a docroot `du`
        // could not read) ⇒ no denominator.
        let mut ir = ImportIR::default();
        let mut a = hosting_with_docroot("/srv/a");
        a.docroot_bytes = 10_000;
        let b = hosting_with_docroot("/srv/b"); // docroot_bytes stays 0
        ir.hostings.push(a);
        ir.hostings.push(b);
        assert_eq!(inflate_bytes(&ir), None);

        // Every site measured ⇒ docroots + dumps.
        let mut ir = ImportIR::default();
        let mut a = hosting_with_docroot("/srv/a");
        a.docroot_bytes = 10_000;
        a.db_bytes = 2_000;
        let mut b = hosting_with_docroot("/srv/b");
        b.domain = "second.cz".into();
        b.docroot_bytes = 5_000;
        ir.hostings.push(a);
        ir.hostings.push(b);
        assert_eq!(inflate_bytes(&ir), Some(17_000));
    }

    /// The bundle is counted twice before it has landed (it arrives, then is
    /// unpacked beside itself) and once afterwards, when `df` has already
    /// stopped counting its bytes as free. Getting that backwards either lets
    /// a doomed transfer start or refuses an import that fits.
    #[test]
    fn import_needed_counts_the_bundle_once_it_is_on_disk() {
        use crate::bundle::{import_needed_bytes, IMPORT_HEADROOM_BYTES};
        let gb = 1024 * 1024 * 1024u64;

        // Before the transfer: 13 GB bundle + 13 GB staging + 31 GB inflate.
        assert_eq!(
            import_needed_bytes(13 * gb, 31 * gb, 2),
            57 * gb + IMPORT_HEADROOM_BYTES
        );
        // Already on disk: the bundle's own bytes are gone from `avail`.
        assert_eq!(
            import_needed_bytes(13 * gb, 31 * gb, 1),
            44 * gb + IMPORT_HEADROOM_BYTES
        );
        // An unmeasured inflate degrades to the old bundle-plus-headroom check
        // rather than to a refusal.
        assert_eq!(
            import_needed_bytes(13 * gb, 0, 2),
            26 * gb + IMPORT_HEADROOM_BYTES
        );
        // Saturating, not wrapping: a bogus manifest must not produce a tiny
        // requirement that waves a doomed import through.
        assert_eq!(import_needed_bytes(u64::MAX, u64::MAX, 2), u64::MAX);
    }

    /// A packed bundle must carry the uncompressed sizes: they are the whole
    /// input to the target node's space check, and the target cannot derive
    /// them from a compressed tarball.
    #[tokio::test]
    async fn packing_records_the_uncompressed_docroot_size() {
        let tmp = tempfile::tempdir().expect("tmp");
        let doc = tmp.path().join("docroot");
        std::fs::create_dir_all(&doc).expect("mkdir");
        std::fs::write(doc.join("big.txt"), vec![b'a'; 200_000]).expect("write");

        let mut ir = ImportIR::default();
        ir.hostings
            .push(hosting_with_docroot(&doc.display().to_string()));
        let out = tmp.path().join("bundle.tar");
        crate::bundle::build(&ir, &out).await.expect("build");

        // Read the manifest back the way the import side does.
        let unpacked = tmp.path().join("unpacked");
        std::fs::create_dir_all(&unpacked).expect("mkdir");
        assert!(std::process::Command::new("tar")
            .args(["xf", &out.display().to_string(), "-C"])
            .arg(&unpacked)
            .status()
            .expect("tar")
            .success());
        let back = crate::bundle::read_manifest(&unpacked)
            .await
            .expect("manifest");
        let recorded = back.hostings[0].docroot_bytes;

        // `dir_bytes` shells out to `du -sb`, which is GNU-only — the target
        // platform, and CI. Where it is missing the figure is legitimately
        // absent, and the contract to assert is the fail-open one: `0` in the
        // manifest, `None` out of `inflate_bytes`, so no check can refuse on it.
        if recorded == 0 {
            assert_eq!(crate::bundle::inflate_bytes(&back), None);
            return;
        }

        assert!(
            recorded >= 200_000,
            "docroot_bytes should hold the UNCOMPRESSED size, got {recorded}"
        );
        // And the compressed bundle really is smaller than what it inflates to
        // — which is the entire reason the figure has to travel with it.
        let packed = std::fs::metadata(&out).expect("stat").len();
        assert!(
            packed < recorded,
            "expected the bundle ({packed}) to be smaller than its inflate ({recorded})"
        );
        assert_eq!(crate::bundle::inflate_bytes(&back), Some(recorded));
    }

    #[test]
    fn human_sizes_read_like_sizes() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1024), "1.0 KB");
        assert_eq!(human(1536), "1.5 KB");
        assert_eq!(human(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn looks_like_sql_accepts_real_dumps() {
        assert!(looks_like_sql(b"-- MySQL dump 10.19  Distrib 10.11\n"));
        assert!(looks_like_sql(
            b"/*!40101 SET @OLD_CHARACTER_SET=@@CHARACTER_SET */;"
        ));
        assert!(looks_like_sql(b"\n\n  CREATE TABLE `wp_posts` ("));
        assert!(looks_like_sql(b"\xEF\xBB\xBF-- with a UTF-8 BOM\n")); // BOM then SQL
                                                                       // Binary content AFTER an SQL header is fine (we only inspect the head).
        let mut v = b"INSERT INTO t VALUES (".to_vec();
        v.extend_from_slice(&[0u8, 1, 2, 3, 255, 254]);
        assert!(looks_like_sql(&v));
    }

    #[test]
    fn looks_like_sql_rejects_binary_and_gzip() {
        assert!(!looks_like_sql(&[0x1f, 0x8b, 0x08, 0x00, 0x00])); // gzip magic
        assert!(!looks_like_sql(b"")); // empty
        assert!(!looks_like_sql(&[0u8, 1, 2, 3, 4, 5])); // raw bytes
        assert!(!looks_like_sql(b"\x89PNG\r\n\x1a\n")); // a PNG, not SQL
    }

    /// The finding this whole digest path exists for.
    ///
    /// A tar cut at a 512-byte block boundary and padded with zeros — what a
    /// crash, a short write or ext4's delayed-allocation zero-fill leaves —
    /// presents those zeros as the archive's end-of-archive marker. `tar tf`
    /// therefore exits 0 having silently dropped every member past the cut, and
    /// an import driven by that check creates the missing sites EMPTY and
    /// reports success. The digest is the only thing that notices.
    #[tokio::test]
    async fn a_zero_padded_truncation_changes_the_digest() {
        let dir = tempfile::tempdir().expect("tmp");
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).expect("src");
        for i in 0..6 {
            std::fs::write(src.join(format!("site{i}.txt")), format!("content {i}\n")).expect("w");
        }
        let full = dir.path().join("full.tar");
        run(
            "tar",
            &[
                "cf",
                &full.display().to_string(),
                "-C",
                &src.display().to_string(),
                ".",
            ],
        )
        .await
        .expect("tar");

        let (full_len, full_sha) = seal(&full).await.expect("seal full");
        assert!(full_len > 0);

        // Cut at a block boundary, then zero-pad back to a plausible length.
        let bytes = std::fs::read(&full).expect("read");
        let cut = (bytes.len() * 6 / 10) / 512 * 512;
        let mut truncated = bytes[..cut].to_vec();
        truncated.resize(bytes.len(), 0);
        let trunc = dir.path().join("trunc.tar");
        std::fs::write(&trunc, &truncated).expect("write trunc");

        let (trunc_len, trunc_sha) = seal(&trunc).await.expect("seal trunc");
        assert_eq!(
            trunc_len, full_len,
            "the zero padding makes the SIZE match — which is why a length check \
             alone cannot catch this"
        );
        assert_ne!(
            trunc_sha, full_sha,
            "the digest must distinguish a zero-padded truncation from the real bundle"
        );

        // And the thing that made this dangerous: `tar tf` is happy with it.
        let tar_ok = tokio::process::Command::new("tar")
            .arg("tf")
            .arg(&trunc)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(
            tar_ok,
            "if tar ever starts rejecting this, the comment on `seal` should be \
             revisited — but do NOT drop the digest, the guarantee is different"
        );
    }

    /// Two domains that collapse to one bundle directory must stop the export,
    /// not overwrite each other.
    #[test]
    fn colliding_site_dirs_are_refused_not_silently_merged() {
        let mut ir = ImportIR {
            hostings: vec![
                hosting_with_docroot("/tmp/a"),
                hosting_with_docroot("/tmp/b"),
            ],
            ..Default::default()
        };
        // Both collapse to `a_b.cz`.
        ir.hostings[0].domain = "a b.cz".into();
        ir.hostings[1].domain = "a+b.cz".into();
        assert_eq!(
            site_dir(&ir.hostings[0].domain),
            site_dir(&ir.hostings[1].domain)
        );

        let err = assert_no_site_dir_collision(&ir).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("a b.cz"), "name both domains: {msg}");
        assert!(msg.contains("a+b.cz"), "name both domains: {msg}");
    }

    #[test]
    fn distinct_site_dirs_are_allowed() {
        let mut ir = ImportIR {
            hostings: vec![
                hosting_with_docroot("/tmp/a"),
                hosting_with_docroot("/tmp/b"),
            ],
            ..Default::default()
        };
        ir.hostings[0].domain = "one.cz".into();
        ir.hostings[1].domain = "two.cz".into();
        assert!(assert_no_site_dir_collision(&ir).is_ok());
    }

    #[test]
    fn site_dir_collapses_unsafe_chars() {
        assert_eq!(site_dir("a.example.com"), "a.example.com");
        assert_eq!(site_dir("a/b c:d"), "a_b_c_d");
    }
}
