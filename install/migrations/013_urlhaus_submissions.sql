-- Migration: history of URL submissions to URLhaus (bin/evaluator2urlhaus.py).
-- One row per URL handled by the exporter: 'ok' = accepted by the submit API,
-- 'error' = submit failed (retried next run), 'known' = URLhaus already had
-- the URL (not submitted). URLs with an 'ok' / 'known' row are not sent again.
-- Additive: adds a new table.

CREATE TABLE IF NOT EXISTS urlhaus_submissions
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT NOT NULL REFERENCES urls(url) ON DELETE CASCADE,
    content_id    INTEGER REFERENCES content(id) ON DELETE SET NULL,  -- payload served by the URL when submitted
    submitted_at  TEXT NOT NULL,                    -- ISO timestamp (UTC)
    tags          TEXT,                             -- JSON list of the submitted tags
    status        TEXT NOT NULL CHECK (status IN ('ok', 'error', 'known')),
    response      TEXT                              -- URLhaus response body (truncated)
);

CREATE INDEX IF NOT EXISTS idx_urlhaus_subm_url ON urlhaus_submissions(url);
