# Sub-project 5.5 — Site Migration Between Agents — Design Spec

| Field | Value |
|---|---|
| Sub-project | 5.5 of N — Migration |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation, Controller (1.5), Backups (5) |
| Used by | Operator-driven moves; rebalancing |

## 1. Summary

Move a hosting from one agent to another with a **short, planned downtime
window** (≈ 5–15 minutes), leveraging the backup/restore primitives from
sub-project 5.

The flow is a **three-step operator dance** coordinated by the controller:

1. **prepare** — provision the hosting on the target agent (cert with
   alternate-validation, content cloned, DB restored). Source keeps
   serving live traffic; target is dormant.
2. **cutover** — short suspend on source → final delta backup →
   restore on target → unsuspend on target. Both endpoints now
   serve the same content; operator updates DNS A/AAAA records.
3. **commit** — after operator-confirmed DNS propagation and a smoke
   test, source hosting is suspended (optional) and queued for delete
   after a configurable rollback window (default 72 h).

This sub-project does **not** manage DNS. Operators flip records in
their registrar manually (or via a future DNS integration sub-project).

## 2. Goals

1. `lmc hosting migrate <agent>:<id> --to <agent2>` runs the prepare
   phase and returns within ≈ time-to-restore.
2. `lmc hosting migrate cutover <migration-id>` performs the short
   downtime window.
3. `lmc hosting migrate commit <migration-id>` finalizes; source
   cleanup queued.
4. `lmc hosting migrate abort <migration-id>` reverts: target hosting is
   deleted, source resumes (if suspended), no data lost.
5. Migration progresses are auditable: every state transition produces
   audit entries on both agents and the controller.

## 3. Non-Goals

- **Live (zero-downtime) migration.** Dual-write DB or storage sync was
  rejected in brainstorming for scope/fragility.
- **Cross-platform migration** (different distros / arch). Source and
  target must both be Debian 12+ on x86_64.
- **DNS management.** Operator-driven, with helpful CLI hints.
- **In-flight visitor session preservation.** Sessions stored in DB or
  cookies survive; sessions stored in PHP-FPM memory or `/tmp` do not.

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Three-phase: prepare → cutover → commit | Allows verification + rollback at safe points |
| D2 | Backup target used for transit is a **shared remote** the two agents both reach (S3 or SFTP) | No agent-to-agent direct RPC for bulk data needed; reuses sub-project 5 |
| D3 | Cert handling: target agent issues a *new* LE cert during prepare using a temporary subdomain (`<id>-migrate.<agent2-hostname>`) for verification, then re-issues for the real domain during cutover (HTTP-01 still works because we control nginx on the agent that holds the DNS record after cutover) | Avoids cert reuse complexity |
| D4 | Cutover suspend window: source paused → restic forget+repair? no, just one incremental + restore | Minimal IO |
| D5 | Rollback window before source delete: **72 h** by default | Catch DNS surprises |
| D6 | Migration state machine tracked on controller in `migrations` table | Single source of truth across agents |
| D7 | Concurrency: at most one in-flight migration per hosting; many independent migrations per agent OK | Prevent self-conflict |
| D8 | If target's `php_version` is not installed, prepare fails fast (no auto-install in this sub-project) | Predictable; install is operator runbook |
| D9 | Both agents must share a backup target before migration | Hard precondition; surfaced in prepare check |

## 5. State Schema Additions (Controller)

```sql
CREATE TABLE migrations (
    id                  TEXT PRIMARY KEY,             -- ULID
    source_agent_id     TEXT NOT NULL REFERENCES agents(id),
    source_hosting_id   TEXT NOT NULL,
    target_agent_id     TEXT NOT NULL REFERENCES agents(id),
    target_hosting_id   TEXT,                          -- filled at prepare
    transit_target      TEXT NOT NULL,                 -- backup target name shared by both
    state               TEXT NOT NULL CHECK (state IN (
                          'preparing','prepared',
                          'cutting-over','cut-over',
                          'committed','aborting','aborted','failed'
                        )),
    prepare_snapshot_id TEXT,
    final_snapshot_id   TEXT,
    rollback_window_h   INTEGER NOT NULL DEFAULT 72,
    started_at          INTEGER NOT NULL,
    cutover_at          INTEGER,
    committed_at        INTEGER,
    delete_source_at    INTEGER,                       -- scheduled action time
    last_error          TEXT
);
CREATE INDEX migrations_state ON migrations(state);
```

A row in `scheduled_actions` (from sub-project 4) is created at commit
time with `action='migration_source_delete'` and `due_at=delete_source_at`.

## 6. RPC Additions

### 6.1 ControllerApi

```rust
async fn migration_start(&self, req: MigrationStartReq)
    -> Result<MigrationSummary, RpcError>;
async fn migration_status(&self, id: MigrationId)
    -> Result<MigrationDetail, RpcError>;
async fn migration_cutover(&self, id: MigrationId)
    -> Result<MigrationDetail, RpcError>;
async fn migration_commit(&self, id: MigrationId)
    -> Result<MigrationDetail, RpcError>;
async fn migration_abort(&self, id: MigrationId)
    -> Result<MigrationDetail, RpcError>;
```

### 6.2 AgentApi (no new endpoints)

All agent-side steps reuse existing endpoints:
- `hosting_create` for target provisioning
- `backup_now`, `restore_from_snapshot` for content transport
- `hosting_suspend`, `hosting_resume`, `hosting_delete` for transitions

## 7. Flows

### 7.1 `migration_start` (prepare)

```text
01 verify source hosting exists on source_agent
02 verify target_agent_id exists and active
03 verify target has same php_version installed (via agent_info)
04 verify both agents share `transit_target` in their backup_targets
05 INSERT migrations (state='preparing')
06 call source: backup_now(transit_target)            → snapshot_id (preload)
                                                       prepare_snapshot_id
07 call target: hosting_create with same spec as source
                (domain takes a TEMP form: '<id>-migrate.<target-hostname>'
                 — primary host header for ACME validation; the *real*
                 domain is added in cutover)
                — returns target_hosting_id
08 call target: restore_from_snapshot(target_hosting_id,
                                       transit_target,
                                       prepare_snapshot_id,
                                       opts{ overwrite=true })
09 target validates HTTP serves on the temp hostname (curl --resolve
   against agent's IP); record health
10 UPDATE migrations state='prepared'
11 controller responds: { id, target_temp_url, ready_for_cutover: true }
```

Source is still serving live traffic with full content.

### 7.2 `migration_cutover`

```text
01 verify state='prepared'
02 UPDATE state='cutting-over'
03 call source: hosting_suspend(reason='migration-cutover')
04 call source: backup_now(transit_target)            → final_snapshot_id
05 call target: restore_from_snapshot(target_hosting_id,
                                       transit_target,
                                       final_snapshot_id,
                                       opts{ overwrite=true })
06 call target: rename hosting domain from temp to real domain
                (new RPC: hosting_set_domain — simple SQL UPDATE +
                 nginx re-write + ACME issue for real domain)
07 call target: hosting_resume
08 UPDATE migrations state='cut-over', cutover_at=now
09 controller responds with instructions:
     "Update DNS A/AAAA for <domain> to <target-agent-ip>.
      Once propagated, run `lmc hosting migrate commit <id>`."
```

Downtime starts at step 03 and ends at step 07. Source is suspended;
target is live. **Visitors hitting source see suspended page**;
visitors hitting target (after DNS) see live site. During DNS
propagation, some visitors continue to hit source's suspended page —
this is the documented downtime window.

### 7.3 `migration_commit`

```text
01 verify state='cut-over'
02 controller does its own HTTP check against the public domain
   (DNS-resolves it; checks 200 + content hash matches expected)
03 if check fails: refuse commit; instruct operator to verify DNS
04 UPDATE state='committed', committed_at=now,
          delete_source_at=now + rollback_window_h*3600
05 schedule: scheduled_actions INSERT (action='migration_source_delete',
                                         due_at=delete_source_at)
06 audit on both agents and controller
07 reply with delete_source_at timestamp
```

At `delete_source_at`, the scheduler calls source agent's
`hosting_delete(source_hosting_id, opts{keep_user=false})`. If anything
fails, action goes to `failed` and operator is alerted.

### 7.4 `migration_abort`

Valid at any state except `committed`.

```text
01 UPDATE migrations state='aborting'
02 if target_hosting_id exists: target: hosting_delete(target_hosting_id)
03 if source state == 'suspended' and was suspended by migration:
     source: hosting_resume
04 UPDATE state='aborted'
05 audit
```

## 8. New RPC: `hosting_set_domain`

Required for cutover. Updates a hosting's primary domain (renames nginx
vhost file, re-issues cert, updates SQL, updates ACME challenge dir).
Atomic, with rollback on failure.

```rust
async fn hosting_set_domain(&self, sel: HostingSelector,
                            new_domain: Domain,
                            opts: SetDomainOpts)
    -> Result<HostingDetail, RpcError>;
```

`SetDomainOpts { keep_old_as_alias: bool }`.

## 9. Operator UX

```
$ lmc hosting migrate node1:example.cz --to node5
[1/6] verifying source / target compatibility ... ok
[2/6] taking prepare snapshot on node1 (via target 'offsite-s3') ...
      178 MiB transferred, snapshot 2a8c91...
[3/6] provisioning temp hosting on node5 ... ok
[4/6] restoring from snapshot on node5 ... ok
[5/6] validating temp endpoint
      curl https://abc12-migrate.node5.example.com/ → 200 ✓
[6/6] PREPARED — migration id: 01J7F8GQX...
      Next: run `lmc hosting migrate cutover 01J7F8GQX...` when you're
      ready for a ~3-minute downtime window.

$ lmc hosting migrate cutover 01J7F8GQX...
[1/5] suspending source ...
[2/5] taking final delta snapshot (78 KiB delta) ...
[3/5] applying delta on target ...
[4/5] reissuing cert for example.cz on node5 ... ok
[5/5] resuming target. CUT OVER complete (00:02:41 downtime).

  ⚠  Update DNS now:
       example.cz  A     203.0.113.42      ← node5 IP
       example.cz  AAAA  2001:db8::42

  Run `lmc hosting migrate commit 01J7F8GQX...` after DNS propagates.

$ lmc hosting migrate commit 01J7F8GQX...
[1/2] verifying live DNS resolves to node5 ... ok (203.0.113.42)
[2/2] verifying HTTP from new endpoint ... 200 OK, content hash matches.

COMMITTED. Source hosting on node1 will be DELETED at
2026-06-03 14:22:00 (Europe/Prague) (in 72h).
Run `lmc hosting migrate abort 01J7F8GQX...` to cancel and revert
before that time (will resume node1 and remove node5 copy).
```

## 10. Edge Cases

| Scenario | Behavior |
|---|---|
| Source agent goes offline during prepare | Migration state='failed' with last_error; operator can abort to clean target if it was created |
| Target agent goes offline during cutover | Source stays suspended; operator must abort to resume source |
| Operator updates DNS between cutover and commit, target HTTP works | commit succeeds normally |
| Operator updates DNS but to wrong IP | commit's HTTP check fails; refuses commit; operator fixes DNS |
| Operator never runs commit | Migration state remains 'cut-over'; controller dashboard surfaces "stuck" migrations after 24h |
| Hosting modified on source after prepare but before cutover | Delta snapshot captures the change; consistent |
| Two operators race | Controller has DB-level unique constraint on (source_hosting_id, state in non-terminal) preventing concurrent migrations |

## 11. Configuration Additions

```toml
[migration]
default_rollback_window_h = 72
prepare_temp_subdomain_pattern = "<id>-migrate.<agent_hostname>"
http_check_timeout            = "10s"
require_shared_transit_target = true
```

## 12. Testing

- Unit: state machine transitions; URL/temp-subdomain generator.
- Integration: two testcontainers running lm-agent + a shared minio for
  transit; full prepare→cutover→commit→delete flow asserting both
  sides' DB and FS at each step.
- e2e: nightly VM scenario with three VMs (controller, agent1, agent2)
  and a Caddy-based DNS simulator; runs full happy path + abort path.
- Failure injection: kill target mid-restore; ensure abort cleans up.

## 13. Security Notes

- Both agents must already trust each other only transitively (via the
  controller). No direct agent-to-agent connection is introduced.
- Backup transit target's credentials live in `backup_targets` on each
  agent independently. Operator must add identical target spec to both.
- The temp subdomain is on the target's hostname (which the operator
  controls); cert issued for it via HTTP-01 just like any other.
- Audit log on both agents references the same `migrations.id` for
  correlation.

## 14. Open Questions

1. **Database charset/collation drift.** If target's MariaDB defaults
   differ, restore might land different collation. **Proposal:** dump
   with explicit charset/collation; restore preserves them.
2. **PHP extensions installed on source but not target.** Prepare check
   queries `agent_info` for available extensions; refuses early.
3. **Mail send between cutover and commit reaches old IP.** That's a
   DNS / SMTP problem; out of scope. Operator should be aware.
4. **Migrations across PHP versions.** Allowed; warned. Operator
   responsibility to verify app compatibility.

## 15. Glossary Additions

| Term | Meaning |
|---|---|
| Source agent | The agent currently hosting the site |
| Target agent | The agent that will host the site after migration |
| Transit target | A backup target reachable from both agents |
| Prepare snapshot | First, larger snapshot taken at migration start |
| Final snapshot | Small delta snapshot taken during cutover |
| Rollback window | Time between commit and source delete; allows reverts |

---

*End of spec.*
