-- Migration: add deduplicated content storage and per-download observations.
-- Safe to run multiple times (uses IF NOT EXISTS). Does not modify or drop any
-- existing table, column or row; purely additive.

PRAGMA foreign_keys = OFF;

-- 1. Deduplicated content table: one row per unique SHA-256 of downloaded bytes.
--    The raw payload itself is stored on the filesystem; this table only keeps
--    the metadata and the path to that file.
CREATE TABLE IF NOT EXISTS content
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT NOT NULL UNIQUE,
    file_path     TEXT NOT NULL,          -- path of the stored sample on disk
    file_size     INTEGER,                -- size in bytes
    mime_type     TEXT,                   -- best-effort MIME type
    first_seen    TEXT NOT NULL,          -- ISO timestamp of first capture
    sandbox_info  TEXT,                   -- JSON blob with sandbox results (optional)
    vt_stats      TEXT,                   -- JSON blob with VT file stats (optional)
    threat_label  TEXT
);

CREATE INDEX IF NOT EXISTS idx_content_sha256 ON content(sha256);

-- 2. Per-download observation log. One row per HTTP fetch of a URL, capturing
--    the connection metadata that can change between fetches even when the
--    returned content is identical (timestamp, source IP, response headers,
--    status code). `content_id` links to the deduplicated content table and is
--    NULL when the response carried no usable body.
CREATE TABLE IF NOT EXISTS download_observations
(
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    url              TEXT NOT NULL REFERENCES urls(url),
    content_id       INTEGER REFERENCES content(id),
    fetched_at       TEXT NOT NULL,        -- ISO timestamp of the request
    source_ip        TEXT,                 -- remote IP the content was served from
    status_code      INTEGER,
    response_headers TEXT,                 -- JSON dict of response headers
    change_type      TEXT NOT NULL DEFAULT 'initial'
                         CHECK (change_type IN ('initial', 'confirmed', 'content_changed', 'unavailable'))
);

CREATE INDEX IF NOT EXISTS idx_download_obs_url        ON download_observations(url);
CREATE INDEX IF NOT EXISTS idx_download_obs_content    ON download_observations(content_id);
CREATE INDEX IF NOT EXISTS idx_download_obs_fetched_at ON download_observations(fetched_at);

PRAGMA foreign_keys = ON;
