-- 028_jobs.sql
--
-- Generic background-job tracker. Operators currently fire a
-- migration / install / backup / cert-issue and stare at a
-- spinner for 30-300 seconds with no signal whether progress is
-- happening, the agent crashed, or the network died. This table
-- + a small Service::job_* API + an HTMX-polled progress card
-- gives them a live bar + step label + tail of the log for ANY
-- long-running operation.
--
-- Design notes:
--   * `id` is a ULID assigned by the service. Sortable + safe to
--     surface in URLs (/jobs/<id>) without exposing internal row ids.
--   * `kind` is a free-text discriminator (`migration`, `install`,
--     `backup`, `acme_issue`, …) so a future `WHERE kind=?` filter
--     is cheap; indexed.
--   * `state` advances `running` → `done`|`failed`|`cancelled`. The
--     UI uses this to pick a coloured pill + decide whether to keep
--     polling. `cancelled` is reserved for a future operator-cancel
--     button — not currently emitted.
--   * `progress_pct` is monotonic 0-100 per convention; the service
--     does NOT enforce monotonicity at SQL level (a flaky inner step
--     might re-emit). UI just shows the latest value.
--   * `log_tail` is bounded to ~16 KiB by the service when
--     appending; we don't enforce in SQL because a partial write at
--     the boundary would otherwise FAIL the whole step. Operators
--     who want the full log get it via a future `/jobs/<id>/log`
--     endpoint that reads from the on-disk log file the agent
--     captures.
--   * `error` is the final error message when state=failed; UI
--     surfaces it in a red box.
--   * `payload_json` is opaque per-kind context (e.g. migration
--     stores source_node + target_node + hosting_id). Lets the UI
--     render a richer panel without needing to look up the hosting
--     separately.
CREATE TABLE jobs (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    target          TEXT,
    state           TEXT NOT NULL CHECK (
        state IN ('running','done','failed','cancelled')
    ) DEFAULT 'running',
    step_label      TEXT NOT NULL DEFAULT '',
    progress_pct    INTEGER NOT NULL DEFAULT 0 CHECK (
        progress_pct >= 0 AND progress_pct <= 100
    ),
    log_tail        TEXT NOT NULL DEFAULT '',
    error           TEXT,
    payload_json    TEXT NOT NULL DEFAULT '{}',
    actor_uid       INTEGER NOT NULL DEFAULT 0,
    actor_label     TEXT NOT NULL DEFAULT 'system',
    started_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    finished_at     INTEGER
);
CREATE INDEX jobs_kind ON jobs(kind);
CREATE INDEX jobs_state ON jobs(state);
CREATE INDEX jobs_started_at ON jobs(started_at);
-- Cheap query for "what's still running in the cluster": the
-- dashboard polls this every few seconds for the side-panel
-- "Active jobs" widget.
CREATE INDEX jobs_running ON jobs(state, started_at) WHERE state = 'running';
