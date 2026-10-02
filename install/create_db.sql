CREATE TABLE sessions
(
    session_hash TEXT PRIMARY KEY,
    session      TEXT,
    idea_id      TEXT
);

CREATE TABLE url_session
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url) ON DELETE CASCADE,
    session TEXT REFERENCES sessions(session_hash) ON DELETE CASCADE,

    CONSTRAINT url_session_unique UNIQUE (url, session)
);

CREATE TABLE url_source
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url) ON DELETE CASCADE,
    source  TEXT,

    CONSTRAINT url_source_unique UNIQUE (url, source)
);

CREATE TABLE discovered_urls
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url) ON DELETE CASCADE,
    src_url TEXT REFERENCES urls(url) ON DELETE CASCADE,

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
    domain                TEXT
);

-- Detailed log of every URL observation: WHERE it was seen (source pipeline + honeynet node) and WHEN
CREATE TABLE observations
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL REFERENCES urls(url) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    honeynet    TEXT,
    session     TEXT REFERENCES sessions(session_hash) ON DELETE CASCADE,
    observed_at TEXT NOT NULL,
    -- NULL-normalized dedupe key: UNIQUE on NULLable columns does not dedupe in SQLite,
    -- so idempotent INSERT OR IGNORE relies on this generated key instead
    dedupe_key  TEXT GENERATED ALWAYS AS (
                    IFNULL(url, '') || char(31) || IFNULL(source, '') || char(31) ||
                    IFNULL(honeynet, '') || char(31) || IFNULL(session, '') || char(31) ||
                    IFNULL(observed_at, '')
                ) STORED
);

CREATE UNIQUE INDEX idx_observations_dedupe ON observations(dedupe_key);
CREATE INDEX idx_observations_url           ON observations(url);
CREATE INDEX idx_observations_source        ON observations(source);
CREATE INDEX idx_observations_honeynet      ON observations(honeynet);
CREATE INDEX idx_observations_session       ON observations(session);
CREATE INDEX idx_observations_observed_at   ON observations(observed_at);

-- Append-only audit trail of classification decisions per URL.
-- Written both by automated modules (evaluator, back-propagation, session
-- heuristics) and by human analysts editing a record through the web UI.
CREATE TABLE classification_history
(
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT NOT NULL REFERENCES urls(url) ON DELETE CASCADE,
    classification TEXT NOT NULL,
    reason         TEXT,
    note           TEXT,
    actor          TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE INDEX idx_classification_history_url        ON classification_history(url);
CREATE INDEX idx_classification_history_created_at ON classification_history(created_at);

-- ============================================================================
-- Content storage (deduplicated) + per-download observations
-- ============================================================================
-- The raw body downloaded from a URL is written to the filesystem exactly once
-- per unique SHA-256 digest; the DB row below stores only metadata + the file
-- path. Multiple URLs (or repeated polls of the same URL) that return identical
-- bytes reference the same `content` row, giving deduplication for free.
CREATE TABLE content
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT NOT NULL UNIQUE,
    file_path     TEXT NOT NULL,          -- path of the stored sample on disk
    file_size     INTEGER,                -- size in bytes
    -- MIME (Multipurpose Internet Mail Extensions) type: standardised "type/subtype"
    -- label describing the format of the downloaded content (e.g. 'application/x-sh',
    -- 'application/octet-stream', 'text/html'). Taken from the Content-Type header,
    -- or sniffed from magic bytes when the header is missing; purely descriptive
    -- (used for the download Content-Type, shell-script detection, MISP export).
    mime_type     TEXT,                   -- best-effort MIME type: format label of the payload
    first_seen    TEXT NOT NULL,          -- ISO timestamp of first capture
    sandbox_info  TEXT,                   -- JSON blob with sandbox results (optional)
    vt_stats      TEXT,                   -- JSON blob with VT file stats (optional)
    threat_label  TEXT
);

CREATE INDEX idx_content_sha256 ON content(sha256);

-- One row per *HTTP fetch* of a URL. Metadata that can differ between fetches
-- of identical content (timestamp, source IP, response headers, status code)
-- lives here. `content_id` is NULL when the response carried no usable body
-- (error page, oversized payload, empty reply, ...).
CREATE TABLE download_observations
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT NOT NULL REFERENCES urls(url) ON DELETE CASCADE,
    -- NOTE: intentionally NO "ON DELETE CASCADE" on content_id -- content
    -- samples may be shared between URLs; removing them is a conditional,
    -- application-level step (see content_store.cleanup_orphan_content).
    content_id      INTEGER REFERENCES content(id),
    fetched_at      TEXT NOT NULL,        -- ISO timestamp of the request
    source_ip       TEXT,                 -- remote IP the content was served from
    status_code     INTEGER,
    response_headers TEXT,                -- JSON dict of response headers
    change_type     TEXT NOT NULL DEFAULT 'initial'
                        CHECK (change_type IN ('initial', 'confirmed', 'content_changed', 'unavailable'))
);

CREATE INDEX idx_download_obs_url        ON download_observations(url);
CREATE INDEX idx_download_obs_content    ON download_observations(content_id);
CREATE INDEX idx_download_obs_fetched_at ON download_observations(fetched_at);

-- ============================================================================
-- Malware-sandbox submission history (linked to content)
-- ============================================================================
-- One row per submission of a content sample to a malware sandbox. The sample
-- is referenced both by its `content` row id (so the GUI can link the
-- submission straight back to the Content entry / download) and by the
-- denormalised SHA-256 digest (so the record stays meaningful even if the
-- content row is ever purged). The payload itself stays on the filesystem
-- exactly once per digest (see `content`); only analysis metadata lives here.
CREATE TABLE sandbox_submissions
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    content_id    INTEGER REFERENCES content(id),   -- link back to the Content entry
    sha256        TEXT NOT NULL,                    -- denormalised digest of the sample
    sandbox_name  TEXT NOT NULL,                    -- e.g. 'psnc', 'virustotal', 'anyrun'
    submitted_at  TEXT NOT NULL,                    -- ISO timestamp (UTC) of submission
    submitted_by  TEXT,                             -- analyst username from the web UI
    status        TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'running', 'done', 'failed', 'error')),
    verdict       TEXT,                             -- e.g. 'malicious', 'clean', ...
    report_url    TEXT                              -- external report link (empty => placeholder)
);

CREATE INDEX idx_sandbox_subm_content    ON sandbox_submissions(content_id);
CREATE INDEX idx_sandbox_subm_sha256     ON sandbox_submissions(sha256);
CREATE INDEX idx_sandbox_subm_name       ON sandbox_submissions(sandbox_name);
CREATE INDEX idx_sandbox_subm_submitted  ON sandbox_submissions(submitted_at);
