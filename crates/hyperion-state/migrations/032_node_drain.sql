-- 032_node_drain.sql
--
-- Per-node "drain" / "maintenance" flag. When a worker is drained:
--   * the auto-placer + hosting-create wizard refuses to put new
--     hostings on it
--   * existing hostings keep serving traffic (no-op for already-
--     placed sites)
--   * the operator can SSH in, run apt upgrades, reboot, etc.
--     without partial-state surprises
--
-- A column on `nodes` would have been the obvious place, but
-- drain/undrain is high-frequency (multiple times per maintenance
-- window) while node enrollment is once-per-machine — separate
-- table keeps the change history clean (drained_at vs the original
-- enrolled_at) and makes the per-row ON DELETE simpler.
CREATE TABLE node_drain (
    node_id      TEXT PRIMARY KEY,
    drained_at   INTEGER NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    drained_by   INTEGER REFERENCES web_users(id)
);
CREATE INDEX node_drain_drained_at ON node_drain(drained_at);
