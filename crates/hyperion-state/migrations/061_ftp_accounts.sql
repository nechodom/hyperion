-- Extra FTP logins for one hosting.
--
-- FTP authenticates against a Linux account, so "another FTP account" means
-- another passwd entry. These are created with the SITE'S OWN uid rather than
-- a uid of their own, which is the whole design decision:
--
--   * PHP-FPM runs as the site user. An account with its own uid would create
--     files PHP then could not modify — the broken-permissions trap that makes
--     "why can't WordPress update this plugin" a support ticket. Sharing the
--     uid means every login writes files the site already owns.
--   * The alternative (own uid + shared group + setgid + umask 002) widens the
--     tree to group-write for everything, which is a real loosening of the
--     isolation the panel otherwise enforces.
--
-- The consequence, which the UI states plainly: these are separate LOGINS, not
-- separate permissions. Every one of them can reach every file the site owns.
-- `local_root` narrows where a client LANDS, which is convenience, not a
-- boundary — an operator handing a subdirectory to a contractor should know
-- the contractor can still walk out of it.
CREATE TABLE ftp_accounts (
    id          INTEGER PRIMARY KEY,
    hosting_id  TEXT NOT NULL REFERENCES hostings(id) ON DELETE CASCADE,
    -- The Linux login name. Unique across the node, not just the hosting:
    -- passwd is a node-wide namespace.
    login       TEXT NOT NULL UNIQUE,
    -- Absolute path the client lands in. Always inside the hosting's tree.
    local_root  TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    created_by  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_ftp_accounts_hosting ON ftp_accounts(hosting_id);
