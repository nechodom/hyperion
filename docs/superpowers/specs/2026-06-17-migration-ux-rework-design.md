# Migration UX rework — design

**Date:** 2026-06-17
**Status:** approved (4 design questions answered by the user) → implementing
**Scope:** front-end / IA only. The backend job + progress system already works
well and is **not** rewritten.

## Problem (from the user)

The "migrate a website" area is confusing on all four axes they named:

1. **Scattered flow** — three separate cards (One-click migrate / Clone /
   Manual export) crammed into one detail tab.
2. **Unclear progress & outcome** — even though a live `/jobs/<id>` page exists,
   it isn't obvious what happened or what to do next.
3. **Confusing vocabulary** — migrate / move / clone / export / import / bundle /
   transfer / restore-as-new all used for overlapping things.
4. **Hard to find** — buried in a per-hosting detail tab; not discoverable from
   the list or nav.

## Decisions

### Unified vocabulary (user-facing)

| New term | Replaces | Meaning |
|----------|----------|---------|
| **Move** | migrate, one-click migrate, move | Relocate a site to another node. The original is **suspended** after the copy succeeds (not deleted). |
| **Copy** | clone | Duplicate a site to a new domain and/or node. The original is **untouched**. |
| **Export file** / **Import file** | export bundle, manual export, import-from-url | Advanced manual path: produce/consume a downloadable bundle for an off-cluster / SSH-only target. |

Internal names (routes, RPC variants `HostingExport`/`HostingImportFromUrl`,
`bundle`, `manifest`) stay unchanged — zero backend churn.

### One guided page

New route **`GET /hostings/transfer/<selector>`** → `hosting_transfer.html`:

- **Step 1 — Choose:** three radio cards — *Move to another node* / *Copy to a
  new domain or node* / *Export a transfer file (advanced)*. Each card states in
  one sentence what it does and what happens to the original.
- **Step 2 — Details (revealed by the choice):**
  - *Move*: target node + an explicit "what happens / what's next (update DNS →
    delete suspended original)" box.
  - *Copy*: new domain + target node (default: same node).
  - *Export*: just confirm; result page already lists the transfer options.
- Each step-2 panel has its own `<form>` posting to the **existing** endpoint
  (`/hostings/migration/move`, `/hostings/clone`, `/hostings/migration/export`),
  so the working job/progress backend is reused verbatim. Move/Copy land on the
  existing live `/jobs/<id>` page.

Light JS: selecting a radio reveals its panel (mirrors the existing
`hostings_new.html` wizard pattern + CSS). Without JS, all panels show — still
usable.

### Discoverability

- **Detail header**: a **Move / copy** action button next to *Files*.
- **Hostings list**: a per-row **Move / copy** link (and the existing *Import*
  header button is kept for receiving a site).
- **Detail "Migration" tab**: its three cluttered cards are replaced by a short
  explainer + a prominent button to the wizard page (the tab stays, but stops
  being a dumping ground).

### Clearer outcome

The move/clone job's final step message is reworded to spell out the concrete
next steps with links (point DNS at the target IP → once verified, delete the
suspended original from its Danger tab).

## Out of scope (left as-is)

- The export/import/proxy backend, the bundle/manifest format, cert re-issue, the
  job model, `BackupRestoreAsNew`.
- The draft controller-orchestrated migration spec
  (`2026-05-31-migration-design.md`) — unrelated future work.
