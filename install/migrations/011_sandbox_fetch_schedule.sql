-- Migration: schedule of result fetches for manual sandbox submissions.
-- After an analyst submits a sample from the web UI, activity_scanner sends
-- GET /overview/{sha256} 10, 20 and 30 minutes after the submission until the
-- report exists. next_fetch_at is the time of the next scheduled GET (NULL when
-- no fetch is scheduled -- report fetched, or the scheduled fetches are used
-- up and the regular activity_scanner run takes over).
-- Additive: adds three columns (existing rows get no schedule).

ALTER TABLE sandbox_submissions ADD COLUMN fetch_attempts INTEGER NOT NULL DEFAULT 0;  -- scheduled GETs already sent
ALTER TABLE sandbox_submissions ADD COLUMN next_fetch_at  TEXT;                        -- ISO timestamp (UTC) of the next scheduled GET
ALTER TABLE sandbox_submissions ADD COLUMN last_fetch_at  TEXT;                        -- ISO timestamp (UTC) of the last result GET

CREATE INDEX IF NOT EXISTS idx_sandbox_subm_next_fetch ON sandbox_submissions(next_fetch_at);
