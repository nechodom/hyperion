-- ISO country codes this hosting refuses ("RU,CN"), resolved against the
-- GeoIP nginx map. Empty = block nothing, which is what every existing row
-- did before this column existed. TEXT of codes for the same reason
-- blocked_bots is: no schema churn per country, and the renderer owns the
-- translation into nginx.
ALTER TABLE hostings ADD COLUMN blocked_countries TEXT NOT NULL DEFAULT '';
