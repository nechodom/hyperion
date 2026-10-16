-- A price typed on one hosting's own page (Lifecycle & billing) instead of
-- copied from its profile. 1 = the operator asked for it to outlive a profile
-- re-apply; 0 = the next apply overwrites it with the profile's price, which
-- is what every existing row already does.
ALTER TABLE hosting_profile_apply ADD COLUMN price_pinned INTEGER NOT NULL DEFAULT 0;
