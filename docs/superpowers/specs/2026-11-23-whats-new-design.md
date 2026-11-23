# What's new: an icon that lists new features

Status: approved 2026-11-23

## Why

A feature ships and the other people who run the panel do not learn about it
until they trip over it. The owner wants one place in the panel that says what
was added, with a link to where each thing is switched on or configured.

## Goals

- An icon in the sidebar footer, next to the notification bell, with a dot
  while there is something the person has not seen.
- A click opens a panel with the latest entries: title, one or two sentences,
  date, and a link to the page where the feature lives.
- Adding an entry is one small edit in the same PR as the feature.

Non-goals: news for customers, translation (the panel is English), a full
changelog of fixes, e-mail or Slack announcements, an editor in the panel.

Anti-goal: the list must not turn into the alert feed. It stays separate from
the bell, and it never shows a link the person cannot open.

## Who sees it

Administrators and operators. Customers and viewers get neither the icon nor
the feed (the owner chose "administrators only"; hiding viewers too is my
call, matching `data-hide-roles="customer,viewer"` used for the Operations
section).

## Approaches

1. **Entries compiled into the binary** (chosen). A table in
   `bin/hyperion-web/src/whatsnew.rs`. An entry arrives with the release that
   contains the feature, needs no migration, and is the same on every
   install. Cost: wording changes need a release.
2. **Entries in the database, edited in the panel.** Wording can change
   without a release, but every install would need the entries entered by
   hand or seeded by migration, and the feature and its announcement could
   drift apart.
3. **Generated from commit messages or tags.** No extra writing, but the
   commit text is written for developers, has no link target, and includes
   fixes nobody needs announced.

Read state, two ways:

- **In the browser** (chosen): `localStorage` holds the highest entry id seen.
  No migration and no per-user table (none exists today; the bootstrap admin
  also lives outside `web_users`). Cost: a second device shows the dot again.
- **On the server per user:** follows the person across devices, needs a new
  table and handling for the bootstrap admin. Can be added later without
  changing the entries.

## Design

- **Entry:** `id` (integer, rising, never reused), `date`, `title`, `body` (plain text, one or two sentences), `link`
  (a panel path), `link_label`, an optional capability the link needs, and
  whether the linked page covers every site (it then also needs all-sites
  scope). No version: tags are cut after merge, so a pull request cannot
  know it; the date says the same.
- **Feed:** `GET /api/whatsnew` returns the newest 10 entries as JSON, with
  entries whose capability the session lacks left out on the server. Customers
  and viewers get 403.
- **Icon:** a button beside the bell in `base.html`, hidden for customers and
  viewers. Its dropdown reuses the bell's look and its positioning code (the
  bell already solves the sidebar-footer and narrow-screen placement).
- **New or not:** an entry is new when its id is above the stored one.
  Opening the panel stores the highest id and clears the dot; the entries
  that were new stay highlighted until the panel closes. With nothing stored
  (first visit, new browser), entries from the last 30 days count as new, so
  a new colleague is not greeted by ten highlights.
- **Features that live on a hosting** (for example the contact form guard)
  have no single settings page. The link goes to `/hostings` and the body
  says where on a hosting's page to look.
- **Starting content:** entries for the features of the last weeks (file
  manager rework, contact form guard and its sum, Docker tab, site scanner),
  written from their PR descriptions.
- **Tests:** ids unique and strictly rising, every link starts with `/` and
  is not empty, the feed filters by capability and refuses customers.
- **Keeping it alive:** a line in `CONTRIBUTING.md` that a user-visible
  feature adds an entry.

## Left to the builder

The icon glyph, the exact wording of the starting entries, whether the
dropdown code is shared with the bell by a small helper or by duplication.
