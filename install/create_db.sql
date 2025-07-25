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
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url),
    source  TEXT,

    CONSTRAINT url_source_unique UNIQUE (url, source)
);

CREATE TABLE discovered_urls
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url),
    src_url TEXT REFERENCES urls(url),

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
    eval_later            TEXT DEFAULT 'no' CHECK (eval_later IN ('yes', 'no'))
);
