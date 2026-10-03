# Settings layout refresh — design / shared contract

Date: 2026-10-03
Branch: `claude/settings-layout-refresh-8d9001` (stacked on `feat/settings-ia-reorg` = PR #195, 10-tab settings)

## Goal

Refresh the admin UI toward **direction B: grouped flat panels**. Related settings
merge into one bordered panel per theme, each panel led by an uppercase section
header, items inside split by hairlines instead of each being its own box. Applied
**app-wide**: Settings, Hosting detail, Dashboard, Hostings list.

Keeps the existing Vercel-monochrome system (black/white, hairline borders, no card
shadow, Geist). This is rhythm + grouping + hierarchy, not a palette or component
rewrite.

## Non-goals

- No palette / token-color changes. No new fonts.
- No DB, no migrations, no handler-logic changes beyond what markup moves require.
- `.card` is NOT redefined globally (see below).

## CSS contract — add to `bin/hyperion-web/static/app.css`

Add a spacing scale to `:root` (single source for the gaps that are currently
hard-coded at three different values — 1.25rem / 1rem / 0.9rem):

```css
--space-1: 0.25rem;
--space-2: 0.5rem;
--space-3: 0.75rem;
--space-4: 1rem;
--space-5: 1.5rem;
--space-6: 2rem;
--group-gap: var(--space-5);   /* the one vertical gap between groups */
```

New structural pattern (coexists with existing `.card`, do not remove `.card`):

```css
/* Grouped-flat panel: one theme-section. */
.group {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
}
.group + .group,
.tab-panel > .group + .group { margin-top: var(--group-gap); }

/* Section header — the new-user wayfinding label. */
.group > .ghead {
  padding: 0.8rem 1.25rem;
  background: var(--surface-2);
  border-bottom: 1px solid var(--border);
  font-size: 0.73rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-weight: 600;
  color: var(--text-dim);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

/* A single setting block inside a group. */
.group > .item { padding: 1.25rem 1.25rem; border-bottom: 1px solid var(--border); }
.group > .item:last-child { border-bottom: none; }
.group > .item.muted { background: var(--bg-2); }

/* Item header: same icon+title treatment the old .card h2 had, one notch smaller. */
.item > h3 {
  font-size: 0.92rem;
  font-weight: 600;
  margin: 0 0 0.3rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  letter-spacing: -0.005em;
}
.item > h3 .h-icon { width: 16px; height: 16px; color: var(--text-dim); stroke-width: 2; }
.item .help, .item .text-soft.small { color: var(--text-soft); line-height: 1.6; }

/* Right-aligned inline save, replaces the lone button at card bottom. */
.item .item-actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1rem; }

/* Collapsible item (maps the existing details.card). */
details.item > summary { list-style: none; cursor: pointer; }
details.item > summary::-webkit-details-marker { display: none; }

/* Danger item keeps the existing accent. */
.item.danger > h3 { color: var(--danger); }
```

Also: inside settings, **delete the 23 redundant inline `style="margin-top:1rem"`**
on cards once they become items in a group (the `.group`/`.item` rules own spacing now).

### Coexistence rules
- `.card`, `.card.hover`, `.card.danger`, `.card-section`, `details.card` stay for
  standalone one-offs (login, error pages, modals, flashes, KPI/spark/creds cards).
- `.tab-panel > :where(.card,[hx-get]) + ...` rule stays; groups get their own
  `margin-top` rule above, so a tab can hold both during migration without collapse.
- KPI grid / spark grid / tables (`no-pad-table`) are NOT items — they stay as-is,
  optionally wrapped in a `.group` with a `.ghead` when a section label helps.

## Markup pattern

Before (each its own card):
```html
<div class="card" id="offsite-ftp"> <h2><svg class="h-icon">…</svg> Off-site target</h2> …form… </div>
<div class="card muted" id="offsite-s3" style="margin-top:1rem"> … </div>
```
After (one group, ids preserved, inline margins gone):
```html
<div class="group">
  <div class="ghead">Off-site targets</div>
  <div class="item" id="offsite-ftp">
    <h3><svg class="h-icon">…</svg> Off-site target</h3> …form…
    <div class="item-actions"><button class="btn primary">Save backup target</button></div>
  </div>
  <div class="item muted" id="offsite-s3"> … </div>
</div>
```

## HARD INVARIANTS (guards will fail otherwise)

1. **Card id → item id, unchanged.** Deep links, save redirects,
   `section_to_tab()`/`sanitize_return_tab()`, and `template_lint.rs` all key on the
   id. Put the SAME id on the `.item` the old `.card` had.
2. **Forms verbatim.** Keep every `<input type=hidden>`: `_csrf`, `section`,
   `_return_tab`, `_checkboxes`. Keep multipart `?_csrf=` in the form `action` query.
   Keep confirm dialogs on the `<form>`, not the button.
3. **htmx verbatim.** Lazy panel triggers (`intersect once`, `data-poll-visible`,
   286-retire), probe `hx-target`/`hx-post`, `hx-vals` csrf — unchanged.
4. **Conditionals.** A `.group` must wrap a whole Askama `{% if %}`/`{% else %}`
   block — never split one across the group boundary (`template_lint.rs` checks div
   balance in `.tab-panels`). `#bruteforce-scanner` id stays on the item in BOTH the
   `if` and the `else` branch. Never move a deep-linked card into a conditional that
   can be false (e.g. `#mail-test`).
5. **Move markup, not logic.** Do not touch handler code, Rust, or `section` values.

## Per-surface group plan

### Settings (`templates/settings.html`) — 10 tabs
Each tab keeps its intro `<p>`; node selector (mail) stays at tab top.

| Tab (panel id) | Groups: **ghead** (item ids) |
|---|---|
| general | **Panel** (panel-domain) · **Updates** (updates) |
| tls | **Certificates** (acme) · **Preview addresses** (preview-address, preview-wildcard) · **Help** (https-howto, muted) |
| mail | **Outgoing relay** (smtp-relay, mail-test) · **Local MTA** (local-mta) · **Help** (mail-howto, muted) |
| notifications | **Channels** (slack, alert-recipients) · **Message templates** (alert-templates) |
| letters | **Customer letters** (customer-letters, letter-wording) · **Performance & CWV** (performance) · **Email branding** (email-branding) |
| backups | **What is kept** (protection-mode) · **Off-site targets** (offsite-ftp, offsite-s3) · **Retention & trash** (local-copies, backup-retention, snapshot-retention, trash) · **Maintenance** (offsite-backfill) |
| access | **Sign-in & 2FA** (sign-in) · **Users & roles** (users-roles + its nested card) · **API access** (api, api-keys) · **Audit log** (audit-retention) |
| bruteforce | **Brute-force scanner** (bruteforce-scanner — both if/else branch items) · **GeoIP** (geoip) |
| cluster | **Placement** (placement) · **Test nodes** (test-nodes) · **Hardening** (hardening) · **Tips** (multinode-tips, muted) |
| raw | **Raw configuration** (raw-toml) |

### Hosting detail (`templates/hostings_detail.html`)
Already uses `.section-title` 14× and `.card-section` 9×. Those existing section
titles become `.ghead` labels — wrap each title's following cards in one `.group`,
convert each `.card`/`details.card` to `.item`/`details.item`. Preserve border-left
accent cards, `no-pad-table` tables (leave as `.card` or wrap, don't convert to item),
and all tab lazy-load attributes. Report any card that doesn't map cleanly instead of
forcing it.

### Dashboard (`templates/dashboard.html`) + Hostings list (`templates/hostings_list.html`)
- Dashboard: KPI strip stays on top (not an item). Group remaining cards by theme;
  finalize labels from the file (overview / activity / backups).
- Hostings list: `no-pad-table` card stays a table card; wrap in a `.group` only if a
  header label clarifies. Minimal change.

## Testing
- `cargo test --all-targets` — `template_lint.rs` + `settings.rs` tests must pass
  (tab↔panel parity, div balance, every `/settings#X` link resolves, `_return_tab`
  accepted, `section_to_tab` values exist).
- `cargo fmt`.
- Build (CSS + templates are embedded → rebuild required). Visual walk on the devpanel
  (`preview_start devpanel`, :8190): every settings tab + dashboard + one hosting
  detail, light and dark. Screenshots for the user.

## Rollout (subagents)
1. CSS foundation agent → app.css tokens + `.group/.ghead/.item` (lands first).
2. Parallel (distinct files): settings.html · hostings_detail.html · dashboard.html+hostings_list.html.
3. Main: integrate, fix guards/lint, `cargo test`, `fmt`.
4. Main: rebuild devpanel, walk + screenshot, user review on localhost.
