# Files page rework — design

Date: 2026-11-18. Approved in conversation ("Ano, jdi do toho").

## Intent

`/hostings/<id>/files` works but loses data in small ways and looks unlike the
rest of the panel. Fix the behaviour, then rebuild the page in the panel's
grouped-flat vocabulary (`.group` / `.ghead`), so it sits next to the reworked
pages without standing out.

## Bugs being fixed

1. The editor rewrites LF to CRLF on every save (a `<textarea>` submits CRLF)
   and drops a leading blank line.
2. Saving resets the file mode to 0644 (a 0640 `wp-config.php`, an executable
   script).
3. `.htaccess`, `.env`, `.htpasswd` and extension-less files cannot be opened:
   the type is guessed from the extension alone.
4. Links break for names holding `&`, `#`, `%`, `+`, `?` — the template
   HTML-escapes where it must URL-encode.
5. Failures are shown in the green success banner.
6. Downloading a file whose name is not ASCII fails (raw bytes in a header).
7. A symlink cannot be deleted or renamed, and is drawn as a file.
8. The write controls show for a role without `HostingFiles`; every button
   then answers 403.
9. The row menu is clipped by the table's overflow on the last rows.
10. An empty folder has no way up.
11. The size limits contradict each other (64 MiB in the hint, 100 MB in the
    error).
12. Sorting is case-sensitive; a file that is not valid UTF-8 is corrupted by
    a save; the flash stays in the URL; rename uses `prompt()`.

## Goals

- Every bug above fixed, each with a test.
- One `.group` panel: path + actions in the head, the listing below.
- New folder, new file, rename in an in-page dialog. Upload takes several
  files and a drop.
- Viewer and editor take the full width, with line numbers, Ctrl/Cmd+S and an
  unsaved-changes warning.
- A save is refused when the file changed on disk since it was opened; the
  text the operator typed stays on screen.

## Non-goals

- Streaming uploads/downloads. The cap stays 64 MiB per file.
- Moving between folders, chmod, archives, search.
- Folding the page into the hosting detail as a lazy tab.

## Anti-goals

- No new way for root to follow a tenant's symlink. Every path still goes
  through `resolve_inside_jail`.
- An older worker must keep working with a newer master: wire changes are
  additive, `#[serde(default)]`.

## Approaches

- **A. Fix in place, restyle the template (chosen).** Same routes, same RPCs
  with additive fields. Small, reviewable, no migration.
- B. htmx partial swaps for the listing. Nicer navigation, but a second
  rendering path and new routes for no bug fixed.
- C. A client-side file manager fed by JSON. Most capable, far the largest,
  and unlike anything else in the panel.

## Decisions

- **Type by content.** The listing offers "open" for any file up to 1 MiB that
  is not a known binary type; the read sniffs the bytes (NUL = binary). Text
  that is not valid UTF-8 opens read-only.
- **Line endings.** The read reports the file's convention; the save
  normalises the submitted text to it.
- **Mode.** A write keeps the existing file's mode; a new file gets 0644.
- **Conflict.** The read returns an opaque version (mtime ns + size); the save
  sends it back and the agent refuses a mismatch. The refusal re-renders the
  editor with the typed text and the fresh version, so a second Save
  overwrites knowingly.
- **Delete.** A file asks a plain confirmation. A non-empty folder is deleted
  recursively only after its name is typed. Symlinks are unlinked, never
  followed.
- **Row actions** are inline icon buttons, not a popover: nothing to clip.
- **Permissions** for the write UI come from the same check the write
  handlers make.

## Left to the builder

CSS class names (`.fm-*` in `app.css`), wording, test layout, a demo tree for
the dev server.
