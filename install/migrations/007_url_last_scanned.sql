-- Migration: remember when activity_scanner last re-polled each URL
-- (filterable in the web UI). Additive: adds one nullable column.

ALTER TABLE urls ADD COLUMN last_scanned TEXT;    -- ISO timestamp (UTC) of the last activity_scanner check

-- Best-effort backfill from the newest download observation. It may also come
-- from the evaluator's first fetch; the next activity_scanner run overwrites it.
UPDATE urls SET last_scanned = (
    SELECT MAX(d.fetched_at) FROM download_observations d WHERE d.url = urls.url
);

CREATE INDEX IF NOT EXISTS idx_urls_last_scanned ON urls(last_scanned);
