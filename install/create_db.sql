-- Table sessions: records Warden/IDEA sessions in which URLs were observed.
CREATE TABLE sessions
(
    -- hash of the session (primary key); unique session identifier
    session_hash TEXT PRIMARY KEY,
    -- name/identifier of the session
    session      TEXT,
    -- ID of the associated IDEA event
    idea_id      TEXT
);

-- Link table url_session: M:N junction table between URLs and sessions.
CREATE TABLE url_session
(
    -- surrogate key (artificial primary key)
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    -- URL assigned to the session (foreign key to urls.url)
    url     TEXT REFERENCES urls(url),
    -- session in which the URL was observed (foreign key to sessions.session_hash)
    session TEXT REFERENCES sessions(session_hash),

    -- prevents duplicate (URL, session) pairs
    CONSTRAINT url_session_unique UNIQUE (url, session)
);

-- Table url_source: records each observation of a URL in a source (honeynet).
-- Supports the requirement to store detailed information about in which source
-- a URL was observed and when. Each (url, source) pair is stored once, keeping
-- the first observation time; subsequent observations of the same pair update
-- the optional metadata columns via COALESCE (see common/utils.record_url_source).
CREATE TABLE url_source
(
    -- surrogate key (artificial primary key)
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- observed URL (foreign key to urls.url)
    url           TEXT REFERENCES urls(url),
    -- name of the source, e.g. "CESNET Hugo" or another honeynet
    source        TEXT,
    -- finer detail about the source, e.g. a honeynet node identifier
    source_detail TEXT,
    -- URL from which this URL was extracted (when the URL came from a script on another URL); foreign key to urls.url
    origin_url    TEXT REFERENCES urls(url),
    -- timestamp when the URL was observed in this source (first observation is preserved)
    observed_at   DATETIME,
    -- ID of the IDEA event this observation came from
    idea_id       TEXT,
    -- session this observation belongs to (foreign key to sessions.session_hash)
    session_hash  TEXT REFERENCES sessions(session_hash),

    -- prevents duplicate (URL, source) pairs; also serves as the conflict target for upserts
    CONSTRAINT url_source_unique UNIQUE (url, source)
);

-- Link table discovered_urls: records URLs extracted from other URLs (e.g. from a script).
CREATE TABLE discovered_urls
(
    -- surrogate key (artificial primary key)
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- discovered URL (foreign key to urls.url)
    url           TEXT REFERENCES urls(url),
    -- source URL from which the discovered URL was extracted (foreign key to urls.url)
    src_url       TEXT REFERENCES urls(url),
    -- timestamp when the URL was discovered in the source URL
    discovered_at DATETIME,

    -- prevents duplicate (discovered URL, source URL) pairs
    CONSTRAINT discovered_urls_unique UNIQUE (url, src_url)
);

-- Table urls: central table of tracked URLs and their classification.
CREATE TABLE urls
(
    -- the URL itself (primary key); central point of the whole schema
    url                   TEXT PRIMARY KEY,
    -- date of the first occurrence/observation of the URL
    first_seen            DATE,
    -- date of the last occurrence/observation of the URL
    last_seen             DATE,
    -- SHA-1 hash of the last downloaded content (kept for compatibility)
    hash                  TEXT,
    -- URL classification: malicious / harmless / unreachable / unclassified / invalid / miner
    classification        TEXT DEFAULT 'unclassified' CHECK (classification IN ('malicious', 'harmless', 'unreachable', 'unclassified', 'invalid', 'miner')),
    -- reason/justification for the assigned classification
    classification_reason TEXT DEFAULT 'Waiting for evaluation',
    -- free-text analyst note about the URL
    note                  TEXT,
    -- whether the URL has already been reported (exported) onward
    reported              TEXT DEFAULT 'no' CHECK (reported IN ('yes', 'no')),
    -- number of times the URL was observed in sources
    occurrences           INTEGER DEFAULT 1,
    -- JSON with VirusTotal statistics for the URL
    vt_stats              TEXT,
    -- whether the URL has already been evaluated by an analyst/system
    evaluated             TEXT DEFAULT 'no' CHECK (evaluated IN ('yes', 'no')),
    -- MIME type of the last downloaded content
    file_mime_type        TEXT,
    -- size in bytes of the last downloaded content
    content_size          INTEGER,
    -- VirusTotal threat label
    threat_label          TEXT,
    -- URL activity: active / inactive / unknown
    status                TEXT DEFAULT 'unknown' CHECK (status IN ('active', 'inactive', 'unknown')),
    -- date of the last detected URL activity
    last_active           DATE,
    -- whether the status changed since the last activity scan
    status_changed        TEXT DEFAULT 'no' CHECK (status_changed IN ('yes', 'no')),
    -- identifier (who) of the last editor of the record
    last_edit             TEXT,
    -- whether the URL evaluation was postponed
    eval_later            TEXT DEFAULT 'no' CHECK (eval_later IN ('yes', 'no')),
    -- domain extracted from the URL
    domain                TEXT
);

-- Indexes for efficient source-observation lookups (which source saw a URL and when).
CREATE INDEX idx_url_source_lookup ON url_source(url, source, observed_at);
CREATE INDEX idx_url_source_origin ON url_source(origin_url);
