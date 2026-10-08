# Install script + web setup wizard

Status: approved 2026-10-07 (clickable mock: https://claude.ai/artifact/Jo761cegrK8aBgCjsvKw8A)

## Goal

Pasting the master install one-liner should finish in about two minutes without
asking anything, and hand the operator a link. Everything that needs a decision
(admin account, which software, server identity, panel domain, mail, backups)
happens in the browser, in a guided wizard that ends with a live check.

## What the script does (install-master.sh)

1. Root + Debian 12/13 check, CPU architecture.
2. Port pre-flight on 80, 443 and the panel port (existing logic; the prompt to
   stop a holder stays, but only fires on a conflict).
3. Base packages: curl, ca-certificates, gnupg, git, sudo, restic, sqlite3,
   bind9-dnsutils, nginx, postfix (preseeded "Internet Site").
4. Source checkout to /opt/hyperion (unchanged acquisition modes), then
   `components.sh --prepare` adds the deb.sury.org repo for this Debian suite.
5. Binaries: pre-built from the GitHub release (`rolling`, or
   `HYPERION_RELEASE_TAG`), verified against `SHA256SUMS`. Falls back to
   `cargo build` when the download or checksum fails, on non-x86_64, or with
   `HYPERION_BUILD_FROM_SOURCE=1`.
6. Directories, agent.toml, web.toml, units, keys (as today). agent.toml's ACME
   contact is left empty instead of the `admin@example.com` placeholder.
7. Writes an empty `/etc/hyperion/components` (see "Component selection").
8. Starts the agent, runs `hyperion-web setup-init`, starts the web service,
   prints the setup link, the setup code and the certificate's SHA-256.

Unattended mode is kept for automation: when `HYPERION_ADMIN_PASS` is set the
script installs `HYPERION_COMPONENTS` (default: the historical full set
`php8.3 mariadb postgresql vsftpd phpmyadmin`, the legacy `HYPERION_WITH_*`
switches still apply), bootstraps the admin the old way and never enters setup
mode.

Re-running on a box that already has an admin prints "already installed, use
`hyperion update`". Re-running while setup is pending prints a fresh link.

## Setup mode and the setup code

- State lives in `/var/lib/hyperion/setup.json` (0600): `state`
  (`pending`/`completed`), SHA-256 of the current setup code, its expiry
  (24 h), the steps done, timestamps. No file = not in setup mode, so existing
  installs are unaffected.
- The code is 16 characters from a 32-letter alphabet (80 bits), shown as
  `XXXX-XXXX-XXXX-XXXX`. Only its hash is stored. Single use: exchanging it
  clears the hash. `hyperion setup-link` (wrapper → `hyperion-web setup-link`)
  mints a new one while setup is pending.
- While setup is pending and no admin exists, every route except `/setup/*`,
  static assets and health probes redirects to `/setup`. After the admin
  exists, normal authentication applies and `/` sends the admin back to the
  wizard until it is finished.
- `POST /setup/access` checks the code (constant-time, expiry, per-IP
  throttle shared with the login throttle) and sets a signed setup cookie
  (`<session cookie>_setup`, HttpOnly, Secure, 24 h) that can only reach the
  admin step. It never authenticates anything else.
- `hyperion-web` no longer requires `web-admin.json`; without it the
  bootstrap login path is disabled.
- The self-signed certificate now carries the server's IP addresses as SANs.
  The script prints its fingerprint so the operator can compare it with the
  browser's warning page.

## Wizard steps

| # | Step | Required | Effect |
|---|------|----------|--------|
| 1 | Access | yes | setup code → setup cookie |
| 2 | Admin account | yes | `WebUserCreate` super_admin with a real email, password ≥ 12 chars, logs the admin in (2FA-pending session) |
| 3 | Two-factor sign-in | yes* | `Web2faEnrollStart` / `Web2faConfirmEnroll`, backup codes shown once, session upgraded |
| 4 | Server software | yes | PHP version (one of 8.1–8.4), MariaDB, PostgreSQL, FTP, phpMyAdmin, Redis; installed by a background job with live per-component progress |
| 5 | Server identity | yes | hostname, time zone, contact email (ACME + alerts); the agent restarts to pick them up |
| 6 | Panel address | skippable | existing `PanelProvision` + cert status poll; then a one-time hand-off to the new domain |
| 7 | Outgoing mail | skippable | existing `[email]` config (SMTP relay) + test send to the admin |
| 8 | Backups | skippable | existing `BackupTargetUpsert` + `BackupTargetProbe` |
| 9 | Review | yes | live checks; "Open the panel" marks setup completed |

\* 2FA is mandatory because `cluster.enforce_admin_2fa` defaults to on. If an
operator turned enforcement off before finishing, the step offers "Skip".

### Server software

- Agent RPCs `SetupStackStart { components, ftp_port }` and
  `SetupStackStatus`. Components are checked against an allow-list:
  `php8.1..php8.4, mariadb, postgresql, vsftpd, phpmyadmin, redis`; at least
  one PHP version is required.
- Runs `components.sh` (embedded in the agent, written next to
  `phpmyadmin.sh` into `/var/lib/hyperion/setup-stack/`) as the transient unit
  `hyperion-setup-stack.service`, the same pattern as the node update: no
  agent sandbox, survives an agent restart, state on disk (job.json, progress
  file, log, result).
- MariaDB is secured as it installs (anonymous users, remote root and the test
  database removed). vsftpd gets Hyperion's config. PHP brings wp-cli.
- Each component that installs is recorded in `/etc/hyperion/components`.

### Server identity

- Agent RPC `SetupSystemApply { hostname, timezone, contact_email }`.
- Hostname: RFC 1123, ≤ 253 chars. Changing it is refused once any hosting
  exists, because the master's node id is its hostname. `/etc/hosts` gets a
  matching `127.0.1.1 <fqdn> <short>` line, otherwise `sudo` (and every wp-cli
  call) complains it cannot resolve the host.
- Time zone must exist under `/usr/share/zoneinfo`; applied with `timedatectl`.
- Contact email is written to `[acme] contact_email`. The agent reads it only
  at boot, so the RPC schedules the same delayed self-restart `EmailConfigSet`
  uses.

### Panel address

- Calls `PanelProvision` (DNS check included) and polls its progress.
- The session cookie belongs to the IP origin, so after the certificate is
  live the browser is sent to `https://<domain>/setup/handoff?h=…`: a
  single-use, 60-second, in-memory token that mints a session on the new
  origin. No second login, no second 2FA prompt.

## Component selection and update.sh

`update.sh` re-installs MariaDB, PostgreSQL, vsftpd, PHP and phpMyAdmin when
they are missing, which would undo the wizard's choices. When
`/etc/hyperion/components` exists it heals only what is listed there. Without
the file (every existing install and every worker) it behaves as today. The
Services page's install action appends to the file, so a component added later
is healed too.

## Out of scope

- Worker install (`install-node.sh`) is unchanged.
- No firewall changes, and the review does not report on the firewall (there is
  no cheap "is default-drop on" query yet).
- No external reachability probe for port 80; the certificate result is the
  proof.

## Testing

- Unit: code mint/verify/expiry, setup.json round trip, component allow-list,
  hostname and time zone validation, `/etc/hosts` rewrite, progress-file parse.
- e2e (stub agent): pending setup redirects `/` to `/setup`; a wrong code is
  refused; a right code sets the cookie and opens the admin step; admin
  creation logs in and lands on 2FA; finishing turns `/setup` into 404.
- Scripts: `bash -n`, shellcheck where available.
- Manual walk in the dev panel.
