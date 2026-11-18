# Files Page Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the file manager's data-losing bugs and rebuild its page in the panel's grouped-flat look.

**Architecture:** Same routes and RPCs. Wire types gain additive `#[serde(default)]` fields. The adapter (`hyperion-adapters/src/files.rs`) owns every filesystem rule; the service maps it to RPC; the web handler owns URLs, flash, permissions and line endings; the template is rewritten.

**Tech Stack:** Rust, axum, askama, tokio, plain JS, `app.css`.

**Spec:** `docs/superpowers/specs/2026-11-18-files-tab-rework-design.md`

## Global Constraints

- Every path goes through `resolve_inside_jail`; nothing new follows a symlink.
- Wire changes additive only, `#[serde(default)]`; an older worker must still answer.
- Per-file cap stays `MAX_WRITE_BYTES` = 64 MiB; inline cap `MAX_INLINE_BYTES` = 1 MiB.
- `data-confirm-*` on the `<form>`; multipart CSRF in the query string.
- `cargo fmt --all --check` and clippy clean before commit.

## Review Focus

1. A name with `% & # + ?` or a space: every link and form must reach that exact file. (Task 3 test)
2. A Windows-1250 text file: opens read-only, never saved lossy. (Task 1 test)
3. A CRLF file edited in a browser: stays CRLF; an LF file stays LF; leading blank line survives. (Task 3 test)
4. A symlink to a directory inside a folder being deleted recursively: the link goes, its target stays. (Task 1 test)
5. An older worker ignoring `create_only` / `expect_version` / `recursive`: the web must not rely on them alone for "new file must not overwrite". (Task 3: pre-check the listing)

---

### Task 1: Adapter rules

**Files:** Modify `crates/hyperion-adapters/src/files.rs` (tests in the same file).

**Produces:**
- `pub fn is_known_binary(mime: &str) -> bool` — image/*, font/*, pdf, zip, gzip.
- `pub fn looks_binary(bytes: &[u8]) -> bool` — NUL in the first 8 KiB.
- `pub async fn resolve_entry_in_jail(jail: &Path, rel_path: &str) -> Result<PathBuf, AdapterError>` — resolves the parent through `resolve_inside_jail`, validates and joins the last component without following it. Refuses the jail root.
- `pub fn file_version(md: &std::fs::Metadata) -> String` — `"{mtime_ns}-{len}"`.
- `pub struct WriteOpts { pub expect_version: Option<String>, pub create_only: bool }` (`Default`).
- `write_file_in_jail(jail, rel_path, bytes, opts: &WriteOpts)` — keeps an existing regular file's mode (`& 0o7777`), 0644 when new; `create_only` refuses an existing path; `expect_version` mismatch → error text starting `changed on disk`.
- `delete_in_jail(jail, rel_path, recursive: bool)` — uses `resolve_entry_in_jail`; symlink → unlink; non-empty dir without `recursive` → existing refusal; with it → `std::fs::remove_dir_all` in `spawn_blocking`.
- `rename_in_jail` — `from` through `resolve_entry_in_jail` so a symlink can be renamed.
- `guess_mime`: `woff2` → `font/woff2`.

- [ ] Tests first: `write_keeps_existing_mode` (0600 stays 0600), `write_new_file_is_0644`, `write_create_only_refuses_existing`, `write_refuses_stale_version`, `write_accepts_current_version`, `delete_unlinks_symlink_and_keeps_target`, `delete_recursive_removes_tree_but_not_symlink_target`, `delete_non_recursive_still_refuses`, `rename_moves_a_symlink`, `entry_resolver_refuses_root_and_traversal`, `looks_binary_on_nul`.
- [ ] Run `cargo test -p hyperion-adapters files::` → fail, implement, pass.
- [ ] Commit.

### Task 2: Types, wire, service

**Files:** `crates/hyperion-types/src/stats.rs`, `crates/hyperion-rpc/src/codec.rs`, `crates/hyperion-rpc/src/api.rs`, `crates/hyperion-rpc-server/src/lib.rs`, `crates/hyperion-core/src/agent.rs`, `crates/hyperion-core/src/service/files.rs`, `bin/hctl` call sites.

**Produces:**
- `HostingFileEntry { .., #[serde(default)] mode: u32 }`.
- `HostingFileContent { .., #[serde(default)] version: String, #[serde(default)] lossy: bool, #[serde(default)] crlf: bool }`.
- `Request::HostingFileWrite { .., #[serde(default)] expect_version: Option<String>, #[serde(default)] create_only: bool }`; `Request::HostingFileDelete { .., #[serde(default)] recursive: bool }`.
- Trait: `hosting_file_write(sel, rel_path, bytes_b64, expect_version: Option<String>, create_only: bool)`, `hosting_file_delete(sel, rel_path, recursive: bool)`.
- Listing: `symlink_metadata` semantics kept; `inline_viewable = file && size <= 1 MiB && !is_known_binary(mime)`; sort dirs first then case-insensitive name.
- Read: no extension gate; `looks_binary` → Validation `binary file — download it instead`; invalid UTF-8 → lossy content, `lossy: true`; fills `version`, `crlf`.

- [ ] Test in `codec.rs`: old-shape JSON (`{"HostingFileWrite":{"sel":…,"rel_path":…,"bytes_b64":…}}`) still deserialises with defaults; same for Delete and for a `HostingFileEntry` without `mode`.
- [ ] Implement; `cargo test -p hyperion-rpc -p hyperion-core --lib` passes; `cargo check --workspace --all-targets`.
- [ ] Commit.

### Task 3: Web handler

**Files:** `bin/hyperion-web/src/handlers/files.rs`, `bin/hyperion-web/src/filters.rs`, `bin/hyperion-web/src/lib.rs`.

**Produces:**
- `filters::urlq` — query-component encoding, used for every path in a URL.
- Flash: `?ok=` (green) / `?error=` (red); `redirect_back(selector, dir, Flash)`.
- `can_write` = `authorize` check equivalent (`require_hosting_access(.., true, HostingFiles)` is `Ok`) and not read-only.
- `pub fn content_disposition(name: &str) -> String` — ASCII fallback + `filename*=UTF-8''…`.
- `pub fn restore_eol(text: &str, crlf: bool) -> String` — normalise to LF, then to CRLF when asked.
- `post_edit_save`: form gains `version`, `crlf`; on any refusal renders the editor in place with the typed text and an error; on success redirects to the viewer with `ok=Saved`.
- `post_upload`: several `file` fields, empty files allowed, one summary flash; body limit 512 MiB; messages say `64 MiB per file`.
- New `POST /hostings/files/new-file` (`selector`, `dir`, `name`): refuses when the listing already has the name, writes empty with `create_only`, redirects to the editor.
- `post_delete` gains `recursive` (`"1"`).
- Template data: `FilesTpl` gets `parent_path: Option<String>`, `lines: Vec<&str>` for the viewer, `hidden_count`.

- [ ] Tests (unit, same file): `content_disposition_handles_non_ascii` (`"příloha.pdf"` → contains `filename*=UTF-8''p%C5%99%C3%ADloha.pdf`, header value parses), `restore_eol_round_trips` (LF stays LF given browser CRLF; CRLF file stays CRLF), `urlq_encodes_reserved` (`"a&b #1+50%.txt"`).
- [ ] Web e2e in `bin/hyperion-web/tests/` following the existing fixture: error flash renders `.flash.error`; a role without `HostingFiles` gets no write controls.
- [ ] Commit.

### Task 4: Template, CSS, JS

**Files:** `bin/hyperion-web/templates/hosting_files.html` (rewrite), `bin/hyperion-web/static/app.css` (`.fm-*` block after the `.group` rules), `bin/hyperion-web/tests/devserver.rs` (demo tree under `DEVSERVER_DEMO`).

- Listing view: `.group` → `.ghead` (path crumbs + `.ghead-tools`: New folder, New file, Upload) → table (Name, Size, Mode, Modified, actions). `..` row whenever not at the root, also in an empty folder. Symlinks labelled, rename/delete only.
- Viewer/editor view (when `file=` is set): full width, no listing; back link to the folder; line-numbered `<pre>`; editor = gutter + `<textarea wrap="off">`, a newline emitted right after the opening tag.
- One `<dialog>` for name prompts (mkdir, new file, rename), filled from `data-*` on the trigger.
- JS: drop-to-upload on the group, dirty guard, Ctrl/Cmd+S, Tab inserts a tab, strip `ok`/`error` from the URL with `history.replaceState`, hidden-files toggle kept.

- [ ] `cargo test -p hyperion-web --test template_lint` passes.
- [ ] Walk in the dev panel: list, open `.htaccess`, edit+save, conflict, rename, new file, upload two files, delete folder, mobile width, dark/light.
- [ ] Commit.

### Task 5: Gate

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` for the touched crates.
