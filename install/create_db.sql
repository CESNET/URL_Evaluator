CREATE TABLE sessions
(
    session_hash TEXT PRIMARY KEY,
    session      TEXT,
    idea_id      TEXT
);

CREATE TABLE url_session
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url),
    session TEXT REFERENCES sessions(session_hash),

    CONSTRAINT url_session_unique UNIQUE (url, session)
);

CREATE TABLE url_source
(
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    url                  TEXT REFERENCES urls(url),
    source               TEXT,
    first_seen           DATE,
    last_seen            DATE,
    occurrences          INTEGER DEFAULT 1,
    source_detail        TEXT,
    origin_url           TEXT,
    origin_source        TEXT,
    origin_source_detail TEXT,
    observed_at          DATETIME,
    idea_id              TEXT,
    session_hash         TEXT REFERENCES sessions(session_hash),

    CONSTRAINT url_source_unique UNIQUE (url, source)
);

CREATE TABLE discovered_urls
(
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    url                  TEXT REFERENCES urls(url),
    src_url              TEXT REFERENCES urls(url),
    discovered_at        DATETIME,
    origin_source        TEXT,
    origin_source_detail TEXT,

    CONSTRAINT discovered_urls_unique UNIQUE (url, src_url)
);

CREATE TABLE urls
(
    url                   TEXT PRIMARY KEY,
    first_seen            DATE,
    last_seen             DATE,
    hash                  TEXT,
    classification        TEXT DEFAULT 'unclassified' CHECK (classification IN ('malicious', 'harmless', 'unreachable', 'unclassified', 'invalid', 'miner')),
    classification_reason TEXT DEFAULT 'Waiting for evaluation',
    note                  TEXT,
    reported              TEXT DEFAULT 'no' CHECK (reported IN ('yes', 'no')),
    occurrences           INTEGER DEFAULT 1,
    vt_stats              TEXT,
    evaluated             TEXT DEFAULT 'no' CHECK (evaluated IN ('yes', 'no')),
    file_mime_type        TEXT,
    content_size          INTEGER,
    threat_label          TEXT,
    status                TEXT DEFAULT 'unknown' CHECK (status IN ('active', 'inactive', 'unknown')),
    last_active           DATE,
    status_changed        TEXT DEFAULT 'no' CHECK (status_changed IN ('yes', 'no')),
    last_edit             TEXT,
    eval_later            TEXT DEFAULT 'no' CHECK (eval_later IN ('yes', 'no')),
    domain                TEXT,
    latest_content_hash   TEXT
);

-- One row per unique downloaded content (deduplicated by SHA-256).
-- Binary payload lives on disk under <content_storage_path>/<aa>/<bb>/<hash>.blob
-- this table only keeps metadata + the storage pointer.
CREATE TABLE content_snapshot
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash  TEXT UNIQUE,
    url           TEXT,
    downloaded_at DATETIME,
    source_ip     TEXT,
    server_ip     TEXT,
    http_status   INTEGER,
    http_headers  TEXT,
    mime_type     TEXT,
    content_size  INTEGER,
    storage_path  TEXT,
    sha1          TEXT,
    sha256        TEXT
);

-- Many-to-many between URLs and content snapshots, carrying per-URL
-- first/last seen timestamps and the "current content" marker.
-- When a URL's content changes, a new row is inserted with is_latest='yes'
-- and previous rows flip to is_latest='no'. Unchanged content just bumps
-- last_seen, giving the UI the "merged" view.
CREATE TABLE url_content
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    url          TEXT REFERENCES urls(url),
    content_hash TEXT REFERENCES content_snapshot(content_hash),
    first_seen   DATETIME,
    last_seen    DATETIME,
    is_latest    TEXT CHECK (is_latest IN ('yes', 'no')),

    CONSTRAINT url_content_unique UNIQUE (url, content_hash)
);

-- Audit trail of changes to URL fields (classification, status, note, latest content, ...).
CREATE TABLE url_history
(
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT REFERENCES urls(url),
    changed_at DATETIME,
    field      TEXT,
    old_value  TEXT,
    new_value  TEXT,
    changed_by TEXT
);

-- Prepared for future sandbox integration; UI exposes a "request analysis" stub.
-- mime_type + content_size snapshot the metadata of the submitted content at
-- the time of submission so the UI can display exactly what was sent, even if
-- the underlying content_snapshot row is later superseded for the URL.
CREATE TABLE sandbox_job
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash TEXT REFERENCES content_snapshot(content_hash),
    url          TEXT REFERENCES urls(url),
    provider     TEXT,
    external_id  TEXT,
    status       TEXT CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    submitted_at DATETIME,
    completed_at DATETIME,
    report_url   TEXT,
    report_json  TEXT,
    requested_by TEXT,
    mime_type    TEXT,
    content_size INTEGER
);

-- ----------------------------------------------------------------------------
-- Indexes for common lookup patterns
-- ----------------------------------------------------------------------------
CREATE INDEX idx_url_source_lookup        ON url_source(url, source, observed_at);
CREATE INDEX idx_url_source_origin        ON url_source(origin_url);
CREATE INDEX idx_url_source_session       ON url_source(session_hash);
CREATE INDEX idx_url_content_latest       ON url_content(url, is_latest);
CREATE INDEX idx_url_content_hash         ON url_content(content_hash);
CREATE INDEX idx_url_history_url          ON url_history(url, changed_at);
CREATE INDEX idx_content_snapshot_sha1    ON content_snapshot(sha1);
CREATE INDEX idx_sandbox_job_status       ON sandbox_job(content_hash, status);
CREATE INDEX idx_sandbox_job_url          ON sandbox_job(url);
CREATE INDEX idx_discovered_urls_src      ON discovered_urls(src_url);
