CREATE TABLE sessions
(
    session_hash TEXT PRIMARY KEY,
    session      TEXT,
    idea_id      TEXT
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

CREATE TABLE url_source
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT REFERENCES urls(url),
    source        TEXT,
    source_detail TEXT,
    origin_url    TEXT,
    observed_at   DATETIME,
    idea_id       TEXT,
    session_hash  TEXT REFERENCES sessions(session_hash)
);

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

CREATE TABLE url_content
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT REFERENCES urls(url),
    content_hash  TEXT REFERENCES content_snapshot(content_hash),
    first_seen    DATETIME,
    last_seen     DATETIME,
    is_latest     TEXT CHECK (is_latest IN ('yes', 'no')),
    CONSTRAINT url_content_unique UNIQUE (url, content_hash)
);

CREATE TABLE discovered_urls
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT REFERENCES urls(url),
    src_url       TEXT REFERENCES urls(url),
    discovered_at DATETIME,
    CONSTRAINT discovered_urls_unique UNIQUE (url, src_url)
);

CREATE TABLE url_history
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT REFERENCES urls(url),
    changed_at  DATETIME,
    field       TEXT,
    old_value   TEXT,
    new_value   TEXT,
    changed_by  TEXT
);

CREATE TABLE sandbox_job
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash  TEXT REFERENCES content_snapshot(content_hash),
    url           TEXT REFERENCES urls(url),
    provider      TEXT,
    external_id   TEXT,
    status        TEXT CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    submitted_at  DATETIME,
    completed_at  DATETIME,
    report_url    TEXT,
    report_json   TEXT,
    requested_by  TEXT
);

CREATE INDEX idx_url_source_lookup ON url_source(url, source, observed_at);
CREATE INDEX idx_url_source_origin ON url_source(origin_url);
CREATE INDEX idx_url_content_latest ON url_content(url, is_latest);
CREATE INDEX idx_url_content_hash ON url_content(content_hash);
CREATE INDEX idx_url_history_url ON url_history(url, changed_at);
CREATE INDEX idx_sandbox_job_status ON sandbox_job(content_hash, status);
