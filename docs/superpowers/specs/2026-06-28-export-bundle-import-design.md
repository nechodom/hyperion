# Export-bundle import (no inbound SSH/root to the source)

**Date:** 2026-06-28 · **Status:** approved (build with agent subcommand)

## Problem
Remote panel import needs SSH (ideally root) into the source CloudPanel/HestiaCP
box to read its root-owned config DB (`/home/clp/htdocs/app/data/db.sq3`), rsync
docroots, and dump DBs. Operators who can `sudo` on the source but don't want to
hand Hyperion a persistent root SSH key (or whose source is behind NAT/firewall)
have no path. Something with read access to the panel's root-owned files must run
on the source — the only question is *where the privileged read happens and how
the data reaches Hyperion*.

## Approach: operator-run export bundle
Invert the flow. The operator runs a one-shot exporter on the source **as
themselves (sudo)**; it produces a portable archive; they hand the archive to
Hyperion, which imports from it with no live source access.

The intermediate representation (`ImportIR`) is already `Serialize`/`Deserialize`
and `Location::Archive(PathBuf)` already exists (stubbed), so the planner + apply
pipeline is reused unchanged — only `detect`/`extract`/`fetch_files`/`fetch_db`
gain an Archive branch.

## Bundle format (`bundle.tar`)
```
manifest.json                          # serde_json of the whole ImportIR
sites/<sanitized-domain>/docroot.tar.gz
sites/<sanitized-domain>/db/<dbname>.dump   # mysqldump (plain) | pg_dump -Fc
```
`sanitized-domain` = domain with non-`[A-Za-z0-9.-]` → `_` (same fn both sides).
The manifest is the source of truth; per-site dirs are keyed by domain so the
import side locates docroot/DB without the original source paths.

## Pieces
1. **`crates/hyperion-import/src/bundle.rs`** — shared: `site_dir(domain)`,
   `MANIFEST`, `read_manifest(dir)` (import side), `build(ir, out)` (export side:
   tar docroots, dump DBs via mysqldump/pg_dump, write manifest, tar it up).
   Shells out to `tar`/`mysqldump`/`pg_dump` (present on the source) — no new crates.
2. **`hyperion-agent export-bundle`** subcommand — `--kind <cloudpanel|hestiacp>`
   (auto-detect if omitted) `--out <file>` `[--only <domain>]`. Runs the existing
   adapter `detect`+`extract` in-place, then `bundle::build`. Needs no agent.toml
   (so it runs on a box that isn't a Hyperion node). Operator fetches the binary
   once (release URL) and runs `sudo hyperion-agent export-bundle …`.
3. **Core archive import** — `ImportPanelReq.archive_path: Option<String>`;
   `build_location` mode `"archive"` extracts the tar to a temp dir →
   `Location::Archive(dir)`; CloudPanel/Hestia `detect`/`extract` read the
   manifest; `fetch_files`/`fetch_db` read from `sites/<domain>/…` (domain threaded
   through `apply_one_import`). Temp dir cleaned up after the run.
4. **Web UI** — `/import` gains an "Upload bundle" mode: upload `bundle.tar`
   (multipart, streamed to `/var/lib/hyperion/migration/`), then the normal
   plan → apply (background job). v1 may also accept a node-local path.

## Security
The bundle holds DB dumps + docroots (sensitive) — treat like the ephemeral SSH
key: written under `/var/lib/hyperion/migration/` 0600, never in a job payload,
deleted after import. Upload restricted to `Capability::PanelImport`.

## Out of scope
Mail/DNS (already excluded from import). Per-site (no-sudo) import is a separate
future feature. Browser upload of multi-GB bundles may fall back to scp-to-node +
path for very large sources.
