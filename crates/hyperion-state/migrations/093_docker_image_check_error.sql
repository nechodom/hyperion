-- Why the latest image check failed. A check that fails keeps the last answer
-- on the row; this is what tells the operator the answer is going stale and why.
ALTER TABLE docker_image_checks ADD COLUMN last_error TEXT NOT NULL DEFAULT '';
