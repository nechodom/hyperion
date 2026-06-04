-- 016_hosting_node.sql
-- Track which node each hosting was provisioned on.
--
-- Today every agent's DB only knows about hostings on its own node,
-- so this is effectively self-identification. The value comes from
-- `HostingService::current_node_id()` (HYPERION_NODE_ID env var →
-- /etc/hostname → "unknown"). Surfaced in the web UI as a chip on
-- the hosting list + detail so operators can tell at a glance which
-- box a site lives on — especially after a migration import where
-- the originating node_id is preserved in the audit trail and the
-- new node_id is written here.
--
-- Pre-existing rows from before this migration get NULL until they
-- transition through a write that knows the local node_id (the
-- agent does a one-shot backfill on startup — see
-- HostingService::backfill_local_node_id).

ALTER TABLE hostings ADD COLUMN node_id TEXT;

CREATE INDEX hostings_node ON hostings(node_id);
