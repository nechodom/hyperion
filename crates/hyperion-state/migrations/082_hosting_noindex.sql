-- "Hide from search engines" per site: the vhost sends
-- `X-Robots-Tag: noindex, nofollow` on every response. Lives on hostings
-- like the other vhost options (see 020/036/058). Off for every existing
-- site, so nothing changes until someone asks for it.
ALTER TABLE hostings ADD COLUMN noindex INTEGER NOT NULL DEFAULT 0;
