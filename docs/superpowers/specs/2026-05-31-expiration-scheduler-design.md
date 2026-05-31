# Sub-project 4 — Expiration + Scheduler — Design Spec

| Field | Value |
|---|---|
| Sub-project | 4 of N — Expiration/Scheduler |
| Status | Draft |
| Date | 2026-05-31 |
| Depends on | Foundation, Controller (1.5), Limits/Suspend (3) |
| Used by | Sub-projects 5 (auto-backup before delete), 6 (client view of expiry) |

## 1. Summary

Adds an **expiration date** per hosting, a **controller-side scheduler**
that fires pre-expiry warning emails on configurable cadences, auto-suspends
on the expiry date, and auto-deletes after a configurable grace window
(default 30 days). Operators can extend any hosting's expiry at any time.

All time-driven actions are idempotent: missed cron windows after a
controller outage are caught up at the next tick; no double-actions on
restart.

## 2. Goals

1. `lm hosting set-expiry <id> --date 2027-06-30 --owner-email kevin@x.cz`
   stores the expiry and (re)schedules notifications.
2. Three pre-expiry warning emails are sent by default at **30 / 7 / 1**
   day(s) before expiry, configurable per hosting and globally.
3. On the expiry day at 00:00 in the configured timezone, the hosting is
   auto-**suspended** (`reason_message = "expired"`).
4. After a per-hosting grace period (default 30 days), the hosting is
   **backed up to the configured remote target** (sub-project 5) and then
   **deleted**.
5. Extending the expiry past current state automatically:
   - cancels pending notifications and re-schedules them
   - if the hosting is currently suspended-due-to-expiry, resumes it
   - if the hosting was already auto-deleted, the operator must restore
     from backup (no auto-undelete)
6. UI in sub-project 2 surfaces upcoming-expiry list, sorted by date.

## 3. Non-Goals

- Billing, invoicing, payments. Expiration is plain time; money is the
  operator's concern (could integrate later with sub-project 6).
- SMS / push notifications. Email only in v1.
- Custom expiry-action workflows (e.g. "suspend after 14 days, throttle
  after 7"). Fixed pipeline in v1.
- Holiday-aware grace extension.

## 4. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Scheduler lives on the controller (single tick loop) | Centralized; agent stays dumb |
| D2 | Time-of-action: 00:00 in `[scheduler].timezone` (default UTC) | Predictable, operator-configurable |
| D3 | Tick interval: every 5 minutes | Fast enough catch-up after outage; cheap |
| D4 | Notifications via SMTP submission (RFC 6409, port 587 STARTTLS) using `lettre` crate | Mature, async-capable, no external sendmail |
| D5 | Email templates compile-time-checked (askama) | Same toolchain as web UI |
| D6 | `owner_email` is the recipient; can be array later (deferred) | YAGNI multiple addresses |
| D7 | Each scheduled action is idempotent and tracked by `(hosting_id, action, due_at)` unique key | No double-send on restart |
| D8 | Grace period default 30 days, configurable per hosting; minimum 1 day | Standard agency practice |
| D9 | Auto-delete pre-step: take final backup (sub-project 5) | Safety net; never delete without backup if backup configured |
| D10 | Time stored as Unix seconds UTC; rendered in configured timezone in UI/email | Simplicity + correctness |

## 5. State Schema Additions

### 5.1 Controller-side

```sql
CREATE TABLE controller_hostings (
    -- one row per (agent, hosting) that the controller is tracking for billing
    agent_id              TEXT NOT NULL REFERENCES agents(id),
    hosting_id            TEXT NOT NULL,                  -- mirrors hostings.id on the agent
    owner_email           TEXT,
    price_per_year_minor  INTEGER,                        -- e.g. cents/halíře; nullable
    currency              TEXT,                           -- ISO 4217; nullable
    expires_at            INTEGER,                        -- unix epoch; NULL = no expiry
    grace_days            INTEGER NOT NULL DEFAULT 30,
    warning_offsets_days  TEXT NOT NULL DEFAULT '30,7,1', -- CSV
    notes                 TEXT,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    PRIMARY KEY (agent_id, hosting_id)
);
CREATE INDEX controller_hostings_expires ON controller_hostings(expires_at);

CREATE TABLE scheduled_actions (
    id           INTEGER PRIMARY KEY,
    agent_id     TEXT NOT NULL REFERENCES agents(id),
    hosting_id   TEXT NOT NULL,
    action       TEXT NOT NULL CHECK (action IN (
                    'notify_30d','notify_7d','notify_1d',
                    'suspend_expired','final_backup','delete_expired'
                 )),
    due_at       INTEGER NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('pending','running','done','failed','canceled')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT,
    last_attempt_at INTEGER,
    created_at   INTEGER NOT NULL,
    UNIQUE (agent_id, hosting_id, action, due_at)
);
CREATE INDEX scheduled_actions_due ON scheduled_actions(state, due_at);
```

`controller_hostings.warning_offsets_days` defaults to `"30,7,1"` but
allows custom like `"60,30,14,7,3,1"`.

## 6. RPC Additions

### 6.1 ControllerApi

```rust
async fn hosting_set_expiry(&self, sel: HostingRef, exp: ExpirySpec)
    -> Result<ControllerHostingDetail, RpcError>;
async fn hosting_clear_expiry(&self, sel: HostingRef)
    -> Result<(), RpcError>;
async fn hosting_set_owner(&self, sel: HostingRef, owner: OwnerSpec)
    -> Result<(), RpcError>;
async fn upcoming_expiries(&self, within: Duration)
    -> Result<Vec<ExpirySummary>, RpcError>;
```

Where `HostingRef { agent: AgentId, hosting: HostingId | Domain }`.

### 6.2 AgentApi (no changes)

Agent stays oblivious to expiry. Suspend/resume/delete already exist
from sub-projects 1 and 3. Final backup uses sub-project 5's RPC.

## 7. Scheduler Loop

A single tokio task in `lm-controller` runs:

```text
every 5 minutes:
  01 now = wall clock seconds
  02 fetch all scheduled_actions WHERE state='pending' AND due_at <= now
     ORDER BY due_at LIMIT 100
  03 for each action:
       UPDATE scheduled_actions SET state='running', last_attempt_at=now,
                                    attempts = attempts + 1
       try { execute(action); UPDATE state='done' }
       catch (e) {
         if attempts >= 3:
           UPDATE state='failed', last_error=<truncated>
           send admin alert email
         else:
           UPDATE state='pending', last_error=<truncated>
           (next tick retries; exponential backoff 5 / 25 / 125 min)
       }
  04 housekeeping: scan controller_hostings where expires_at is in the
     future; ensure scheduled_actions exist for each warning offset and
     for suspend_expired/final_backup/delete_expired. INSERT OR IGNORE.
```

### 7.1 Action handlers

- **`notify_30d` / `notify_7d` / `notify_1d`** — render email template,
  SMTP send via `lettre`. No state change on hosting.

- **`suspend_expired`** — call agent's `hosting_suspend(reason: "expired")`.
  On 200/404 (already suspended/deleted) — done. On connection error —
  retry next tick. After 3 fails, queue admin alert.

- **`final_backup`** — call agent's `hosting_backup_now(target='remote')`.
  Depends on sub-project 5; if 5 isn't deployed, this action is a no-op
  with a WARN log.

- **`delete_expired`** — call agent's `hosting_delete`. Only runs after
  final_backup completed successfully (FK-like check in scheduler).

### 7.2 Edge cases

- **Controller offline at notify time** — action is `pending` and
  `due_at` in the past; next tick picks it up. Emails late, but sent.
- **Operator extends expiry mid-flow** — controller cancels all
  pending non-`done` actions for this hosting (UPDATE state='canceled'),
  re-creates with new dates.
- **Hosting deleted manually before auto-delete** — pending actions
  become `canceled` via the controller's manual-delete handler.

## 8. Email Templates

`crates/lm-controller-web/templates/emails/`:

```
expiry_warning.subject.txt           "Vaše hosting {{ domain }} vyprší za {{ days }} dní"
expiry_warning.html.j2               HTML version
expiry_warning.txt.j2                plain text version

expired_suspended.subject.txt        "Hosting {{ domain }} byl pozastaven"
expired_suspended.html.j2
expired_suspended.txt.j2

pre_delete.subject.txt               "Hosting {{ domain }} bude smazán za {{ days }} dní"
pre_delete.html.j2
pre_delete.txt.j2
```

All emails carry `List-Unsubscribe: <mailto:reply@operator.cz>` and
`Auto-Submitted: auto-generated`.

## 9. Configuration Additions

```toml
[scheduler]
tick_interval     = "5m"
timezone          = "Europe/Prague"
warning_offsets_days_default = [30, 7, 1]
grace_days_default          = 30

[smtp]
host     = "smtp.example.com"
port     = 587
starttls = true
username = "no-reply@operator.cz"
password_path = "/etc/linux-manager-controller/smtp-pwd"   # mode 0600
from     = "Hosting <no-reply@operator.cz>"
reply_to = "support@operator.cz"
```

## 10. UI Surface (lives in sub-project 2)

Sub-project 4 ships the data + scheduler; sub-project 2's web UI adds:

- `/expiries` — sortable table of upcoming expiries (next 90 days).
- `/hostings/:agent/:id` detail page gains an **Expiry** card with
  current date, grace, warning schedule, "extend by 1 year" quick button,
  and "send test email" action for the configured owner.
- Dashboard card: "X hostings expiring in next 30 days".

## 11. CLI

```
lmc hosting set-expiry <agent>:<id-or-domain> \
    --date 2027-06-30 \
    [--owner-email owner@example.com] \
    [--grace-days 30] \
    [--warning-days 30,7,1]
lmc hosting clear-expiry <agent>:<id-or-domain>
lmc upcoming-expiries [--within 30d]
lmc scheduled-actions list [--state pending|failed|done]
lmc scheduled-actions retry <id>
lmc scheduled-actions cancel <id>
```

## 12. Testing

- Unit: timezone math (proptest); warning offset CSV parser; scheduler
  state machine.
- Integration: in-memory SQLite + fake clock + fake SMTP server
  (`maildev`-style stub) — verify exact email counts, contents, and
  state transitions across a simulated 100-day timeline.
- e2e: nightly VM scenario fast-forwards system clock; asserts UI
  surfaces warnings and final-state transitions.

## 13. Security Notes

- SMTP password at `/etc/linux-manager-controller/smtp-pwd` (mode 0600).
- Email recipient comes from operator-set field; not user-input — but
  template rendering escapes by default (askama).
- Templates never include internal IDs or operator infra hostnames.
- Scheduler never emits a notification email to an address taken from
  the agent state (defense against compromised agent injecting an
  attacker email).

## 14. Open Questions

1. **Bounce handling.** Should we mark `owner_email` as invalid on
   hard bounce? **Proposal:** out of scope; operator monitors mail
   server logs.
2. **DST transitions.** When `timezone = Europe/Prague`, the 00:00
   suspend on the spring-forward day shifts by an hour. **Proposal:**
   accept this as benign.
3. **Final-backup-required vs optional.** If no remote backup target is
   configured, do we delete anyway or block? **Proposal:** block by
   default; operator can override per hosting with
   `--allow-delete-without-backup`.

## 15. Glossary Additions

| Term | Meaning |
|---|---|
| Expiry date | Wall-clock moment at which a hosting auto-suspends |
| Warning offsets | Days before expiry on which to send notification emails |
| Grace period | Days between expiry and final deletion |
| Scheduled action | A row in `scheduled_actions`; the unit of time-driven work |

---

*End of spec.*
