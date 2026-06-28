-- Custom roles: granular RBAC. A custom role is a capability bitmask + a scope
-- (all hostings vs only assigned hostings). `web_users.custom_role_id` links a
-- user to one; NULL means the built-in role in `web_users.role` applies.
-- See docs/superpowers/specs/2026-06-28-custom-roles-design.md.

CREATE TABLE IF NOT EXISTS custom_roles (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL UNIQUE,
    capabilities        INTEGER NOT NULL DEFAULT 0,
    scope_all_hostings  INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL DEFAULT 0,
    updated_at          INTEGER NOT NULL DEFAULT 0
);

-- NULL = built-in role; non-NULL = the user's caps come from this custom role.
ALTER TABLE web_users ADD COLUMN custom_role_id INTEGER REFERENCES custom_roles(id);
