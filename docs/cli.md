# CLI reference

`hctl` is Hyperion's command-line tool. Every command below talks to the agent
on the node you run it on, through the agent's Unix socket. Because of that it
keeps working when the web panel is down, when you are locked out of it, or
when the firewall only lets SSH in. The one exception is `hctl remote …`, which
drives the HTTP API (`/api/v1`) of any panel from any machine.

Source: [`bin/hctl/src/main.rs`](../bin/hctl/src/main.rs). The command list is
checked against this page by a test (`docs_cover_every_command`), so every
command has an entry here.

## Basics

**Who can run it.** The socket `/run/hyperion.sock` is mode `0660`, owned by
the group `hyperion-admin`. Run `hctl` as root (`sudo hctl …`), or add your
user to that group and log in again:

```bash
sudo usermod -aG hyperion-admin "$USER"
```

Membership is full control of the node: anything the panel can do, `hctl` can
do.

**The `hyperion` wrapper.** `hyperion` is a small front door installed next to
`hctl`. It handles `update`, `setup-link`, `version`, `status`, `logs` and
`help` itself and hands everything else to `hctl`, so `hyperion info` and
`hctl info` are the same command.

**Global options.** These work before or after the command:

| Option | Meaning |
|---|---|
| `--json` | Print the agent's raw answer as JSON (pipe it into `jq`). |
| `--socket PATH` | Agent socket. Default `/run/hyperion.sock`, or `$HYPERION_SOCKET`. |
| `-h`, `--help` | Help for any command or group. |
| `-V`, `--version` | The `hctl` build (git describe + full commit SHA). |

**Naming a hosting.** Wherever a command takes `SELECTOR`, give the hosting's
domain (`example.com`) or its id (`01J7A8GQX…`, shown by `hctl hosting list`).
Anything with a dot is read as a domain.

**Sizes and durations.** Size options take bytes or a binary unit: `500M`,
`10G`, `1.5T`. `none` (or `0`) removes a limit. Durations take seconds or a
unit: `90`, `30m`, `12h`, `7d`.

**Passwords.** No command takes a password on the command line. Any local
user can read another process's arguments from `/proc`. Commands that set a
password generate a random 24-character one and print it once, or read it
from the first line of stdin with `--password-stdin`:

```bash
printf '%s\n' "$NEW_PW" | hctl user reset-password admin --password-stdin
```

Under `--json`, a generated password goes to stderr, so stdout stays valid
JSON.

**Confirmation.** Commands that destroy or overwrite something ask
`[y/N]` first when run in a terminal. `-y` / `--yes` skips the question.
Without a terminal (a script, cron, a pipe) nobody can answer, so they go
ahead, as they always did.

**Exit status.** `0` on success. `1` when the agent refused or failed the
request (the reason is printed on stderr), when the socket cannot be reached,
or when a followed job ends in anything but success.

**Master-only commands.** Panel users, the node registry and cluster
statistics live on the master. Run `user …`, `node list`, `node label`,
`node drain`, `node undrain`, `node remove`, `node reset-crypto`,
`node reassign` and `stats cluster` there.

## Agent

### hctl info

Show the agent's hostname, version, hosting count and enrollment.

**Options:** —

```bash
hctl info
```

Answers "is the agent alive, which build is it, and is this node enrolled with
its master?" A node that has not enrolled says `NOT ENROLLED` and names the
config section and the log line to check.

### hctl agent repin

Clear the master's pinned key so the next heartbeat adopts its current one.

**Options:** —

```bash
hctl agent repin
```

A worker pins the master's remote-RPC public key the first time it sees it,
and refuses a key that changes without warning, because that is what a
man-in-the-middle looks like. After you deliberately rotate the master's key,
run this on each worker. The new key is pinned within about a minute.

### hctl agent config

Show the agent's effective configuration, with secrets masked.

**Options:** —

```bash
hctl agent config
```

Prints the ACME contact, SMTP settings, whether a Slack webhook is set,
off-site backup target and retention, as the running agent sees them in
`/etc/hyperion/agent.toml`.

## Hostings

### hctl hosting create

Create a new hosting.

**Options:** `DOMAIN` `[--alias DOMAIN]…` `[--php VERSION]` `[--db mariadb|postgres]` `[--user NAME]` `[--proxy URL]`

```bash
hctl hosting create example.com --alias www.example.com --php 8.3 --db mariadb
hctl hosting create static.example.com
hctl hosting create app.example.com --proxy http://127.0.0.1:3000
```

Creates the system user, document root, PHP-FPM pool (with `--php`), nginx
vhost, database (with `--db`) and a certificate. Leave out `--php` for a
static site. `--proxy` makes a reverse proxy to the given upstream instead
and can't be combined with `--php` or `--db`. The database password is
printed once.

### hctl hosting list

List hostings on this node.

**Options:** `[--state STATE]` `[--search TEXT]`

```bash
hctl hosting list
hctl hosting list --state suspended
hctl hosting list --search shop --json | jq -r '.result[].domain'
```

One line per hosting with its full id, PHP version, state and node. `--state`
takes `active`, `suspended`, `provisioning`, `failed` or `trashed`.

### hctl hosting get

Show one hosting.

**Options:** `SELECTOR`

```bash
hctl hosting get example.com
```

State, system user, PHP version, document root, aliases, database and
certificate.

### hctl hosting delete

Delete a hosting.

**Options:** `SELECTOR` `[--keep-user]` `[--keep-db]` `[-y]`

```bash
hctl hosting delete old.example.com
hctl hosting delete old.example.com --keep-db --yes
```

With trash enabled in Settings, the hosting moves to the trash and can be
restored until it is purged; see [`hctl trash`](#trash). Without it,
files, vhost and pool are removed now. `--keep-user` and `--keep-db` leave the
system user or database in place.

### hctl hosting suspend

Suspend a hosting.

**Options:** `SELECTOR` `[--reason TEXT]`

```bash
hctl hosting suspend example.com --reason "unpaid invoice 2026-10"
```

Visitors get the suspended page and the site's logins (SFTP, FTP) stop
working. Nothing is deleted. The reason is recorded with the suspension.

### hctl hosting resume

Resume a suspended hosting.

**Options:** `SELECTOR`

```bash
hctl hosting resume example.com
```

### hctl hosting set-php

Switch a hosting's PHP version.

**Options:** `SELECTOR` `VERSION`

```bash
hctl hosting set-php example.com 8.4
```

`VERSION` is `8.1`, `8.2`, `8.3` or `8.4`. The site's PHP-FPM pool moves to
the new version.

### hctl hosting set-aliases

Replace a hosting's aliases.

**Options:** `SELECTOR` `DOMAIN…` | `--clear`

```bash
hctl hosting set-aliases example.com www.example.com shop.example.com
hctl hosting set-aliases example.com --clear
```

The list you give becomes the whole alias list, so include the ones you want
to keep. Issue a new certificate afterwards so it covers the new names
([`hctl cert request`](#hctl-cert-request)).

### hctl hosting set-upstream

Change a reverse-proxy hosting's upstream URL.

**Options:** `SELECTOR` `URL`

```bash
hctl hosting set-upstream app.example.com http://127.0.0.1:4000
```

### hctl hosting get-limits

Show a hosting's resource limits. Alias: `hctl hosting limits`.

**Options:** `SELECTOR`

```bash
hctl hosting limits example.com
```

### hctl hosting set-limits

Change a hosting's resource limits.

**Options:** `SELECTOR` `[--php-memory-mb N]` `[--php-max-exec-secs N]` `[--php-max-children N]` `[--php-max-requests N]` `[--db-max-connections N]` `[--disk-soft SIZE]` `[--disk-hard SIZE]` `[--bw-monthly SIZE]` `[--over-bw-policy suspend|throttle]`

```bash
hctl hosting set-limits example.com --php-memory-mb 512 --php-max-children 10
hctl hosting set-limits example.com --disk-hard 20G --bw-monthly none
```

Only the options you pass change; every other limit keeps its current value.
`--disk-hard-bytes` and `--bw-monthly-bytes` still work as older names for
`--disk-hard` and `--bw-monthly`.

### hctl hosting usage

Show recent hourly usage samples.

**Options:** `SELECTOR` `[--limit N]`

```bash
hctl hosting usage example.com --limit 48
```

Disk, bandwidth in and out, and PHP requests per hour, newest first.

### hctl hosting stats

Disk, bandwidth and request totals for one hosting or all of them.

**Options:** `[SELECTOR]`

```bash
hctl hosting stats example.com
hctl hosting stats | sort -k2 -n -r | head
```

Without a selector this is the same table as
[`hctl stats sites`](#hctl-stats-sites).

### hctl hosting logs

Print the end of a hosting's access, error or PHP slow log.

**Options:** `SELECTOR` `[--kind access|error|slow]` `[-n LINES]`

```bash
hctl hosting logs example.com
hctl hosting logs example.com --kind access -n 500 | grep ' 500 '
hctl hosting logs example.com --kind slow
```

The default is the last 100 lines of the error log. `slow` is PHP-FPM's
slow-request log with stack traces.

### hctl hosting repair-perms

Repair ownership and modes under a hosting's document root.

**Options:** `SELECTOR`

```bash
hctl hosting repair-perms example.com
```

Use it after copying files in as root, or when FTP or WordPress can't write
where they should. See [`hctl ftp perms`](#hctl-ftp-perms) to diagnose first.

### hctl hosting purge-cache

Empty a hosting's page cache.

**Options:** `SELECTOR`

```bash
hctl hosting purge-cache example.com
```

Drops every cached page, so the next visitor gets a fresh one from PHP. Use
it after changing content the cache would otherwise keep serving. Prints how
many pages were dropped; `0` means nothing was cached.

### hctl hosting export

Export a hosting as a migration bundle on this node's disk.

**Options:** `SELECTOR`

```bash
hctl hosting export example.com
```

Writes an archive and `manifest.json` under
`/var/lib/hyperion/migration/<bundle_id>/` and prints the command to run on
the target node.

### hctl hosting import

Import a migration bundle copied onto this node.

**Options:** `--manifest PATH`

```bash
scp -r root@old:/var/lib/hyperion/migration/mig_abc /var/lib/hyperion/migration/
hctl hosting import --manifest /var/lib/hyperion/migration/mig_abc/manifest.json
```

Recreates the hosting from scratch and restores files and database. Private
keys never travel; a new certificate is issued.

### hctl hosting import-from-url

Import a migration bundle straight from the source node.

**Options:** `--base-url URL` `--token TOKEN`

```bash
hctl hosting import-from-url \
  --base-url https://old.example.net/api/migration/bundle/mig_abc \
  --token AAAA.BBBB
```

The URL and the signed token come from the export result page in the panel.
The token expires an hour after the export.

### hctl hosting import-panel

Import sites from HestiaCP or CloudPanel.

**Options:** `--source cloudpanel|hestiacp` `[--mode inplace|remote|archive]` `[--dry-run]` `[--ssh-host HOST]` `[--ssh-user USER]` `[--ssh-port PORT]` `[--ssh-key PATH]` `[--archive PATH]`

```bash
hctl hosting import-panel --source cloudpanel --dry-run
hctl hosting import-panel --source hestiacp --mode remote \
  --ssh-host 203.0.113.7 --ssh-key ~/.ssh/id_ed25519
hctl hosting import-panel --source cloudpanel --mode archive --archive /root/bundle.tar
```

Creates a hosting per site and copies its files and databases. `inplace`
reads a panel installed on this node, `remote` reads one over SSH, `archive`
reads a bundle made by `hyperion-export`. Run with `--dry-run` first to see
the plan. Mail and DNS are listed as not imported.

## Trash

### hctl trash list

List trashed hostings and when each is purged.

**Options:** —

```bash
hctl trash list
```

### hctl trash restore

Bring a trashed hosting back.

**Options:** `SELECTOR`

```bash
hctl trash restore old.example.com
```

### hctl trash purge

Permanently delete a trashed hosting now.

**Options:** `SELECTOR` `[-y]`

```bash
hctl trash purge old.example.com --yes
```

Removes files, database and system user. This can't be undone.

## Backups

### hctl backup list

List a hosting's backups.

**Options:** `SELECTOR` `[--limit N]`

```bash
hctl backup list example.com
```

The `ID` column is what `backup restore` and `backup delete` take.

### hctl backup now

Take a backup now.

**Options:** `SELECTOR`

```bash
hctl backup now example.com
```

Writes files and a database dump to this node's backup directory and waits
until it is done. Off-site targets are configured in the panel, so a backup
taken from `hctl` is a local copy only. Use the panel or
[`hctl remote backup`](#hctl-remote-backup) to back up and copy off-site in
one go.

### hctl backup restore

Restore a backup.

**Options:** `SELECTOR` `ID` `[--mode all|db|files]` `[-y]`

```bash
hctl backup restore example.com 42
hctl backup restore example.com 42 --mode db --yes
```

Overwrites the live site with the backup. `--mode db` imports only the
database dump, `--mode files` only the files. The backup must still have a
local archive.

### hctl backup delete

Delete one backup.

**Options:** `SELECTOR` `ID` `[-y]`

```bash
hctl backup delete example.com 42
```

## Snapshots

### hctl snapshot list

List a hosting's file snapshots.

**Options:** `SELECTOR`

```bash
hctl snapshot list example.com
```

Snapshots are restic snapshots kept on this node. Nothing is listed when
restic is not installed.

### hctl snapshot now

Take a snapshot now.

**Options:** `SELECTOR`

```bash
hctl snapshot now example.com
```

### hctl snapshot restore

Restore a snapshot.

**Options:** `SELECTOR` `SNAPSHOT` `[--mode all|db|files]` `[-y]`

```bash
hctl snapshot restore example.com 4f2a91c3
```

Before overwriting, the current state is snapshotted, and the output names
that snapshot so you can go back.

## Certificates

### hctl cert list

List every certificate on the node with days left.

**Options:** —

```bash
hctl cert list
```

### hctl cert request

Get a Let's Encrypt certificate for a hosting and all its aliases. Alias:
`hctl cert issue`.

**Options:** `SELECTOR` `[--staging]` `[--skip-dns-check]`

```bash
hctl cert request example.com
hctl cert request example.com --staging
```

Refuses when the domain's DNS does not point at this node yet, since
Let's Encrypt would fail and count it against your rate limit.
`--skip-dns-check` tries anyway. `--staging` uses Let's Encrypt's test CA:
the certificate is not trusted by browsers, but there are no rate limits.

### hctl cert renew-all

Renew every certificate that is close to expiry. Alias: `hctl cert renew`.

**Options:** —

```bash
hctl cert renew
```

The agent already does this on a timer; run it by hand after fixing whatever
made a renewal fail.

### hctl cert delete

Delete a hosting's certificate.

**Options:** `SELECTOR` `[-y]`

```bash
hctl cert delete example.com
```

The site falls back to a self-signed certificate until you request a new one.

## DNS

### hctl dns check

Does a domain point at this node?

**Options:** `DOMAIN`

```bash
hctl dns check example.com
```

Shows the A and AAAA records the world sees next to this node's public
addresses.

### hctl dns spf

Show a domain's SPF record and a suggested one.

**Options:** `DOMAIN`

```bash
hctl dns spf example.com
```

## WordPress

### hctl wp status

Is WordPress installed, and which version?

**Options:** `SELECTOR`

```bash
hctl wp status example.com
```

### hctl wp fatal-check

Is the site answering, or dying with a fatal error?

**Options:** `SELECTOR`

```bash
hctl wp fatal-check example.com
```

Requests the home page, then runs wp-cli: a plugin or theme that crashes
WordPress during startup leaves a stack trace naming its file. The culprit is
printed; park it with
[`hctl wp disable-plugin`](#hctl-wp-disable-plugin).

### hctl wp plugins

List plugins and pending updates.

**Options:** `SELECTOR`

```bash
hctl wp plugins example.com
```

### hctl wp plugin

Install, activate, deactivate, update or delete a plugin.

**Options:** `SELECTOR` `install|activate|deactivate|update|update-all|delete|auto-update-on|auto-update-off` `[SLUG]` `[--no-activate]`

```bash
hctl wp plugin example.com install wordfence
hctl wp plugin example.com install https://example.net/plugin.zip --no-activate
hctl wp plugin example.com update-all
hctl wp plugin example.com deactivate broken-plugin
```

Every action except `update-all` needs a slug. `install` accepts a
wordpress.org slug or a zip URL and activates the plugin unless
`--no-activate` is given. `delete` refuses an active plugin.

### hctl wp themes

List themes.

**Options:** `SELECTOR`

```bash
hctl wp themes example.com
```

### hctl wp theme

Install, activate, update or delete a theme.

**Options:** `SELECTOR` `install|activate|update|update-all|delete` `[SLUG]`

```bash
hctl wp theme example.com install astra
hctl wp theme example.com activate astra
```

### hctl wp disable-plugin

Park a plugin's folder so a site that crashes on it loads again.

**Options:** `SELECTOR` `SLUG`

```bash
hctl wp disable-plugin example.com broken-plugin
```

Renames the plugin folder to `<slug>-old`. WordPress no longer finds it and
the site loads. This works even when WordPress itself is too broken for
wp-cli.

### hctl wp restore-plugin

Put back a plugin parked by `disable-plugin`.

**Options:** `SELECTOR` `SLUG`

```bash
hctl wp restore-plugin example.com broken-plugin
```

The plugin comes back inactive. Activate it once it's fixed.

### hctl wp reset-password

Set a WordPress user's password.

**Options:** `SELECTOR` `WP_USER` `[--password-stdin]`

```bash
hctl wp reset-password example.com admin
```

`WP_USER` is a login or e-mail. Without `--password-stdin` a password is
generated and printed once.

### hctl wp vuln-scan

Check plugins, themes and core for outdated or vulnerable versions.

**Options:** `SELECTOR`

```bash
hctl wp vuln-scan example.com
```

### hctl wp integrity-scan

Verify checksums and scan for malware.

**Options:** `SELECTOR`

```bash
hctl wp integrity-scan example.com
```

Compares core and plugin files with the checksums wordpress.org publishes and
runs ClamAV over the site. A part that could not be checked (no wp-cli,
ClamAV not installed, a premium plugin with no published checksums) says so
rather than passing.

### hctl wp core-repair

Re-download WordPress core over the existing files.

**Options:** `SELECTOR`

```bash
hctl wp core-repair example.com
```

Replaces modified or missing core files with clean ones of the same version.
`wp-content` and `wp-config.php` are not touched.

## Databases

### hctl db reset-password

Set a new password for a hosting's database user.

**Options:** `SELECTOR` `[--password-stdin]`

```bash
hctl db reset-password example.com
```

Changes the password in the database server and in the panel's stored copy.
Update the site's own config file (`wp-config.php`, `.env`) to match.

## FTP

### hctl ftp list

List every FTP login on the node.

**Options:** —

```bash
hctl ftp list
```

### hctl ftp check

Diagnose a hosting's FTP setup.

**Options:** `SELECTOR`

```bash
hctl ftp check example.com
```

Checks the landing directory, ownership, directory traversal and the FTP
server's view of the login. Each line is `ok`, `WARN` or `FAIL`.

### hctl ftp repair

Repair a hosting's FTP.

**Options:** `SELECTOR`

```bash
hctl ftp repair example.com
```

Fixes what `ftp check` reports: the landing directory, ownership and
traversal.

### hctl ftp perms

Diagnose a hosting's file permissions.

**Options:** `SELECTOR`

```bash
hctl ftp perms example.com
```

Repair with [`hctl hosting repair-perms`](#hctl-hosting-repair-perms).

### hctl ftp set-password

Set a hosting's main FTP password.

**Options:** `SELECTOR` `[--password-stdin]`

```bash
hctl ftp set-password example.com
```

The agent generates the password unless you pass one on stdin, and prints it
once.

### hctl ftp disable

Turn a hosting's main FTP login off.

**Options:** `SELECTOR`

```bash
hctl ftp disable example.com
```

Clears the password. `ftp set-password` turns the login back on.

### hctl ftp logins

List a hosting's extra FTP logins.

**Options:** `SELECTOR`

```bash
hctl ftp logins example.com
```

### hctl ftp repair-node

Rewrite the node-wide FTP server config.

**Options:** —

```bash
hctl ftp repair-node
```

### hctl ftp ftps

Require FTPS on the whole node, or turn it off.

**Options:** `[--off]`

```bash
hctl ftp ftps
hctl ftp ftps --off
```

Requiring TLS can lock out FTP clients that don't support it. `--off` is
the way back without a browser.

## Mail

### hctl mail status

Show postfix mode, relay, queue and recent log lines.

**Options:** —

```bash
hctl mail status
```

### hctl mail test

Send a test message through the local sendmail.

**Options:** `TO`

```bash
hctl mail test you@example.com
```

Tests the same path a site's PHP `mail()` takes. If the message never
arrives, `mail status` shows where it is stuck.

### hctl mail flush

Retry everything in the mail queue now.

**Options:** —

```bash
hctl mail flush
```

### hctl mail clear

Discard everything in the mail queue.

**Options:** `[-y]`

```bash
hctl mail clear
```

For a queue full of spam from a compromised site. Clean the site first.

### hctl mail log

Show the panel's e-mail log.

**Options:** `[--hosting SELECTOR]` `[--limit N]`

```bash
hctl mail log --hosting example.com
```

Mail the panel itself sent (notifications, care reports, alerts) with its
delivery result.

## DKIM

### hctl dkim status

Show DKIM state and the DNS record to publish.

**Options:** `SELECTOR`

```bash
hctl dkim status example.com
```

### hctl dkim enable

Generate a DKIM key and start signing.

**Options:** `SELECTOR`

```bash
hctl dkim enable example.com
```

Prints the TXT record to publish. Receivers can check signatures once the
record is in DNS; [`hctl dkim verify`](#hctl-dkim-verify) tells you when.

### hctl dkim disable

Stop DKIM signing.

**Options:** `SELECTOR`

```bash
hctl dkim disable example.com
```

### hctl dkim verify

Check the published DNS record against the key.

**Options:** `SELECTOR`

```bash
hctl dkim verify example.com
```

## Cron

### hctl cron list

Print a hosting's crontab.

**Options:** `SELECTOR`

```bash
hctl cron list example.com
```

### hctl cron set

Replace a hosting's crontab.

**Options:** `SELECTOR` `FILE`

```bash
hctl cron list example.com > cron.txt && $EDITOR cron.txt
hctl cron set example.com cron.txt
echo '*/5 * * * * php ~/htdocs/wp-cron.php' | hctl cron set example.com -
```

The file replaces the whole crontab; `-` reads it from stdin. Jobs run as the
site's system user.

## Bans

### hctl ban list

List banned IP addresses.

**Options:** `[--hosting SELECTOR]`

```bash
hctl ban list
```

Shows each ban's source (for example `manual`, or an automatic ban from login
or WAF protection). An expiry of `permanent` lasts until lifted.

### hctl ban add

Ban an IP address.

**Options:** `IP` `[--reason TEXT]` `[--ttl DURATION]` `[--hosting SELECTOR]`

```bash
hctl ban add 203.0.113.9 --reason "scraping" --ttl 7d
hctl ban add 198.51.100.4 --hosting example.com
```

One IPv4 or IPv6 address. Node-wide unless `--hosting` limits it to one
site. Permanent unless `--ttl` is given.

### hctl ban remove

Lift a ban.

**Options:** `IP` `[--hosting SELECTOR]`

```bash
hctl ban remove 203.0.113.9
```

The fix when you have banned yourself out of the panel: SSH in and lift it.

## Firewall

### hctl firewall status

Show the firewall backend and open ports.

**Options:** —

```bash
hctl firewall status
```

### hctl firewall confirm

Keep a pending default-drop policy.

**Options:** —

```bash
hctl firewall confirm
```

Turning on default-drop starts a rollback timer, and the firewall goes back
to accept-all unless you confirm in time. If you can still reach the node to
run this, the new rules didn't lock you out.

### hctl firewall disable-drop

Switch the firewall back to accept-by-default.

**Options:** `[-y]`

```bash
hctl firewall disable-drop --yes
```

The escape hatch for a default-drop policy that locked you out. Run it from
the provider's console. Every port is reachable afterwards, so turn
default-drop back on once you have fixed the rules.

## Services

### hctl service list

Show the health of every service Hyperion depends on.

**Options:** —

```bash
hctl service list
```

nginx, the PHP-FPM versions, the database servers, postfix, the FTP server,
the panel and more, each with active and enabled state. Critical services
that are down are counted separately from optional ones.

### hctl service restart

Restart one service.

**Options:** `NAME`

```bash
hctl service restart nginx
hctl service restart php8.3-fpm
```

Only names from `service list` are allowed. The agent won't restart itself,
because that would cut off this command. Use
`systemctl restart hyperion-agent` for that.

## Monitoring

### hctl monitor list

Show uptime for every monitored hosting.

**Options:** —

```bash
hctl monitor list
```

Alert state, success rate, average response time and sample count over the
last 24 hours.

### hctl monitor get

Show one hosting's monitor config and recent samples.

**Options:** `SELECTOR`

```bash
hctl monitor get example.com
```

### hctl monitor probe

Probe a hosting right now.

**Options:** `SELECTOR`

```bash
hctl monitor probe example.com
```

## Jobs

Long operations started in the panel (backups, imports, deletes, restores)
run as background jobs that survive a closed browser tab.

### hctl job list

List recent jobs.

**Options:** `[--kind KIND]` `[--state running|done|failed|cancelled]` `[--limit N]`

```bash
hctl job list --state running
hctl job list --kind backup --state failed
```

### hctl job get

Show one job with its log tail.

**Options:** `ID`

```bash
hctl job get 01JB2C3D4E5F6G7H8J9K0M1N2P
```

### hctl job wait

Follow a job until it finishes.

**Options:** `ID` `[--timeout SECONDS]`

```bash
hctl job wait 01JB2C3D4E5F6G7H8J9K0M1N2P && echo finished
```

Prints each step on stderr as it changes, then the final job. Exits `1` if
the job failed or was cancelled, or when `--timeout` runs out first.

## Users

Panel users live on the master, so run these there. They are how you get back
in when nobody can log in to the panel.

### hctl user list

List panel users.

**Options:** —

```bash
hctl user list
```

### hctl user create

Create a panel user.

**Options:** `USERNAME` `--email EMAIL` `[--role ROLE]` `[--password-stdin]`

```bash
hctl user create jana --email jana@example.com --role admin
```

`ROLE` is `super_admin`, `admin`, `operator` (default), `customer` or
`viewer`. The password is generated and printed once unless you pass one on
stdin. It must be at least 8 characters.

### hctl user reset-password

Set a user's password.

**Options:** `USER` `[--password-stdin]`

```bash
hctl user reset-password admin
```

`USER` is a username or numeric id.

### hctl user set-role

Change a user's built-in role.

**Options:** `USER` `ROLE`

```bash
hctl user set-role jana operator
```

Takes effect on the user's next request. Sessions do not keep the old role.

### hctl user lock

Lock a user out of the panel.

**Options:** `USER` `[--reason TEXT]`

```bash
hctl user lock jana --reason "left the company"
```

### hctl user unlock

Let a locked user sign in again.

**Options:** `USER`

```bash
hctl user unlock admin
```

### hctl user disable-2fa

Remove a user's two-factor enrollment.

**Options:** `USER`

```bash
hctl user disable-2fa admin
```

For a lost phone with no backup codes left. The user signs in with just the
password and can enroll again from My profile.

### hctl user delete

Delete a panel user.

**Options:** `USER` `[-y]`

```bash
hctl user delete jana
```

## Nodes

### hctl node list

List enrolled nodes.

**Options:** —

```bash
hctl node list
```

Run on the master. Shows each node's id, label, agent version, last heartbeat
and whether it is drained.

### hctl node stats

Show this node's load, memory and hosting counts.

**Options:** —

```bash
hctl node stats
```

Same as [`hctl stats node`](#hctl-stats-node).

### hctl node label

Set a node's display label.

**Options:** `NODE_ID` `LABEL`

```bash
hctl node label node-7f3a "Prague 2"
```

### hctl node drain

Stop placing new hostings on a node.

**Options:** `NODE_ID` `[--reason TEXT]`

```bash
hctl node drain node-7f3a --reason "disk replacement Friday"
```

Hostings already on it keep serving. Only new placements avoid it.

### hctl node undrain

Accept new hostings on a node again.

**Options:** `NODE_ID`

```bash
hctl node undrain node-7f3a
```

### hctl node remove

Remove a node from the cluster.

**Options:** `NODE_ID` `[--force]` `[-y]`

```bash
hctl node remove node-7f3a
```

Refused while hostings still reference the node. `--force` removes it anyway
and leaves those hostings orphaned. Adopt them with
[`hctl node reassign`](#hctl-node-reassign).

### hctl node reset-crypto

Forget a node's pinned TLS and signing keys.

**Options:** `NODE_ID`

```bash
hctl node reset-crypto node-7f3a
```

The node pins new keys on its next heartbeat. Use it after reinstalling a
node that keeps its id, when the master refuses it for presenting a different
certificate.

### hctl node reassign

Move hostings from a dead node id onto a live one.

**Options:** `--from NODE_ID` `--to NODE_ID`

```bash
hctl node reassign --from node-old1 --to node-7f3a
```

Run on the master. Use it when a box re-enrolled under a new id and its
hostings still carry the old one.

### hctl node update

Update this node.

**Options:** `[--apt]` `[--hyperion]` `[--safe]` `[-f]`

```bash
hctl node update --apt --hyperion --follow
```

`--apt` upgrades OS packages, and `--hyperion` installs the latest Hyperion
release. Pass at least one. `--safe` takes a snapshot first and rolls back if
the health check afterwards fails. The update runs in its own systemd unit,
so it finishes even if your SSH session drops. `--follow` streams its log and
waits through the agent's restart. On a single-server install,
`sudo hyperion update` does the Hyperion part directly.

### hctl node update-status

Show the state and log of the last `node update`.

**Options:** —

```bash
hctl node update-status
```

### hctl node update-check

Is a newer Hyperion release available?

**Options:** `[--refresh]`

```bash
hctl node update-check --refresh
```

### hctl node os-updates

Show pending OS package updates and whether a reboot is needed.

**Options:** `[--refresh]`

```bash
hctl node os-updates --refresh
```

Security updates are marked. `--refresh` runs `apt update` first. Without it,
the answer is only as fresh as the package index, and its age is printed.

### hctl node fs-check

Diagnose a read-only root or `/usr`, and repair it with `--fix`.

**Options:** `[--fix]`

```bash
hctl node fs-check
hctl node fs-check --fix
```

Some images mount `/usr` read-only, which breaks package installs and
updates. Without `--fix` it only reports.

## Statistics

### hctl stats node

Show this node's totals.

**Options:** —

```bash
hctl stats node
```

### hctl stats cluster

Show every node's totals.

**Options:** —

```bash
hctl stats cluster
```

Run on the master.

### hctl stats sites

Show disk, bandwidth, requests, memory and CPU, one line per hosting.

**Options:** —

```bash
hctl stats sites | sort -k2 -n -r | head
```

Raw numbers so the output sorts and filters in a shell.

## Audit log

### hctl audit

Print recent audit log entries.

**Options:** `[--limit N]`

```bash
hctl audit --limit 20
```

### hctl audit verify

Verify the audit log's hash chain.

**Options:** —

```bash
hctl audit verify
```

Each entry is chained to the one before it by hash. A broken chain means
rows were changed or deleted outside Hyperion.

### hctl audit search

Search the audit log.

**Options:** `[-q TEXT]` `[--action ACTION]` `[--failed]` `[--limit N]`

```bash
hctl audit search -q example.com
hctl audit search --action hosting.delete
hctl audit search --failed --limit 20
```

## Shell completion

### hctl completions

Print a shell completion script.

**Options:** `bash|zsh|fish|elvish|powershell`

```bash
hctl completions bash | sudo tee /etc/bash_completion.d/hctl
hctl completions zsh > "${fpath[1]}/_hctl"
hctl completions fish > ~/.config/fish/completions/hctl.fish
```

## Remote API

`hctl remote` drives a panel's `/api/v1` HTTP API with an API key (create one
in the panel under Settings → Access). It works from any machine: a laptop,
CI, another server. Every command prints the API's JSON answer, ready for
`jq`. An HTTP error prints the error body on stderr and exits `1`.

Connection settings resolve in this order: `--url` / `--key` →
`$HYPERION_API_URL` / `$HYPERION_API_KEY` → `~/.config/hyperion/remote.toml`
(written by `remote login`). `--insecure` skips TLS verification for a panel
on a self-signed certificate.

Commands that start a background job print `{ "job_id": … }`. Add `--wait` to
follow the job to the end. It then exits `1` if the job failed.

### hctl remote login

Save the API URL and key.

**Options:** `--url URL` `--key KEY`

```bash
hctl remote login --url https://panel.example.com --key hyp_…
```

Writes `~/.config/hyperion/remote.toml` with mode `0600`.

### hctl remote me

Show the key's identity, capabilities and scope.

**Options:** —

```bash
hctl remote me
```

### hctl remote list

List hostings.

**Options:** `[--state STATE]` `[--node NODE_ID]` `[--q TEXT]` `[--limit N]` `[--cursor CURSOR]`

```bash
hctl remote list --state active | jq -r '.items[].domain'
hctl remote list --limit 200 --cursor "$(hctl remote list --limit 200 | jq -r .next_cursor)"
```

Pages through `next_cursor`; `total` is the filtered count.

### hctl remote get

Show one hosting.

**Options:** `ID`

```bash
hctl remote get example.com
```

`ID` is a hosting id or domain, as with every `remote` command.

### hctl remote create

Create a hosting.

**Options:** `--domain DOMAIN` `[--php VERSION]` `[--db mariadb|postgres]` `[--alias DOMAIN]…` `[--node NODE_ID]`

```bash
hctl remote create --domain new.example.com --php 8.3 --db mariadb --node node-7f3a
```

Without `--node` the hosting goes on the master.

### hctl remote suspend

Suspend a hosting.

**Options:** `ID`

```bash
hctl remote suspend example.com
```

### hctl remote resume

Resume a hosting.

**Options:** `ID`

```bash
hctl remote resume example.com
```

### hctl remote php

Switch a hosting's PHP version.

**Options:** `ID` `VERSION`

```bash
hctl remote php example.com 8.4
```

### hctl remote delete

Delete a hosting.

**Options:** `ID` `[--keep-user]` `[--keep-database]` `[--wait]` `[-y]`

```bash
hctl remote delete old.example.com --wait --yes
```

### hctl remote backup

Take a backup now, including the off-site copy.

**Options:** `ID` `[--wait]`

```bash
hctl remote backup example.com --wait
```

### hctl remote backups

List a hosting's backups.

**Options:** `ID`

```bash
hctl remote backups example.com | jq '.items[] | {id, started_at, state}'
```

### hctl remote restore

Restore a backup.

**Options:** `ID` `--backup-id N` | `--archive PATH` `[--mode files_and_db|db_only|files_only]` `[--wait]` `[-y]`

```bash
hctl remote restore example.com --backup-id 42 --wait
hctl remote restore example.com --backup-id 42 --mode db_only --wait --yes
```

### hctl remote cert

Request a Let's Encrypt certificate for a hosting.

**Options:** `ID` `[--staging]` `[--wait]`

```bash
hctl remote cert example.com --wait
```

### hctl remote renew-all

Renew every expiring certificate in the cluster.

**Options:** `[--wait]`

```bash
hctl remote renew-all --wait
```

### hctl remote job

Show a background job, or follow it with `--wait`.

**Options:** `ID` `[--wait]`

```bash
hctl remote job 01JB2C3D4E5F6G7H8J9K0M1N2P --wait
```

### hctl remote nodes

List cluster nodes.

**Options:** —

```bash
hctl remote nodes
```

### hctl remote openapi

Print the API's OpenAPI 3 description.

**Options:** —

```bash
hctl remote openapi > hyperion-openapi.json
```

The same document is browsable at `/api/v1/docs` on the panel.
