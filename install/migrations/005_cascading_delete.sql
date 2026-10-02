-- Migration: cascading delete for URL records.
--
-- Goal: deleting a row from `urls` must automatically remove every dependent
-- record (observations, classification history, session/source bindings and
-- per-download observations). SQLite cannot ALTER a table's foreign keys, so
-- the dependent tables are rebuilt with ON DELETE CASCADE while *preserving
-- all existing rows* (copy-old-to-new + rename).
--
-- The migration is defensive and idempotent:
--   * it runs inside a single transaction (immediate rollback on any error),
--   * every step uses IF NOT EXISTS / DROP IF EXISTS guards, so a partially
--     applied run can be safely re-executed,
--   * orphan rows (dependent rows whose url no longer exists in `urls`) are
--     repaired/removed during the copy (DELETE ... WHERE url NOT IN urls),
--   * PRAGMA foreign_key_check runs at the end as an integrity gate.
--
-- NOTE: `content` rows and their payload files on disk are NOT touched here --
-- a content sample may be shared by several URLs, so its removal is a
-- *conditional* step performed by the application layer (db_cleaner) only
-- when no remaining download_observation references it. `sandbox_submissions`
-- keeps its non-cascading FK to content on purpose: a submission record must
-- survive content purges (it stores the denormalised sha256), and content is
-- only ever deleted when nothing references it.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

-- ============================================================================
-- 0. Orphan cleanup safeguard (F6): remove rows referencing URLs that no
--    longer exist. With FK enforcement historically disabled, such orphans
--    can exist; without this step `foreign_key_check` (and later deletes
--    with enforcement ON) would fail.
-- ============================================================================
DELETE FROM url_session           WHERE url NOT IN (SELECT url FROM urls);
DELETE FROM url_source            WHERE url NOT IN (SELECT url FROM urls);
DELETE FROM discovered_urls       WHERE url NOT IN (SELECT url FROM urls)
                                   OR src_url NOT IN (SELECT url FROM urls);
DELETE FROM observations          WHERE url NOT IN (SELECT url FROM urls);
DELETE FROM classification_history WHERE url NOT IN (SELECT url FROM urls);
DELETE FROM download_observations WHERE url NOT IN (SELECT url FROM urls);
DELETE FROM observations          WHERE session IS NOT NULL
                                   AND session NOT IN (SELECT session_hash FROM sessions);
DELETE FROM url_session           WHERE session NOT IN (SELECT session_hash FROM sessions);

-- ============================================================================
-- 1. url_session (FK -> urls.url, sessions.session_hash) + ON DELETE CASCADE
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_session_new
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url) ON DELETE CASCADE,
    session TEXT REFERENCES sessions(session_hash) ON DELETE CASCADE,

    CONSTRAINT url_session_unique UNIQUE (url, session)
);

INSERT OR IGNORE INTO url_session_new (id, url, session)
    SELECT id, url, session FROM url_session;

DROP TABLE url_session;
ALTER TABLE url_session_new RENAME TO url_session;

-- ============================================================================
-- 2. url_source (FK -> urls.url) + ON DELETE CASCADE
-- ============================================================================
CREATE TABLE IF NOT EXISTS url_source_new
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url) ON DELETE CASCADE,
    source  TEXT,

    CONSTRAINT url_source_unique UNIQUE (url, source)
);

INSERT OR IGNORE INTO url_source_new (id, url, source)
    SELECT id, url, source FROM url_source;

DROP TABLE url_source;
ALTER TABLE url_source_new RENAME TO url_source;

-- ============================================================================
-- 3. discovered_urls (FK -> urls.url, urls.url as src_url) + ON DELETE CASCADE
-- ============================================================================
CREATE TABLE IF NOT EXISTS discovered_urls_new
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    url     TEXT REFERENCES urls(url) ON DELETE CASCADE,
    src_url TEXT REFERENCES urls(url) ON DELETE CASCADE,

    CONSTRAINT discovered_urls_unique UNIQUE (url, src_url)
);

INSERT OR IGNORE INTO discovered_urls_new (id, url, src_url)
    SELECT id, url, src_url FROM discovered_urls;

DROP TABLE discovered_urls;
ALTER TABLE discovered_urls_new RENAME TO discovered_urls;

-- ============================================================================
-- 4. observations (FK -> urls.url, sessions.session_hash) + ON DELETE CASCADE
-- ============================================================================
CREATE TABLE IF NOT EXISTS observations_new
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL REFERENCES urls(url) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    honeynet    TEXT,
    session     TEXT REFERENCES sessions(session_hash) ON DELETE CASCADE,
    observed_at TEXT NOT NULL,
    -- NULL-normalized dedupe key: UNIQUE on NULLable columns does not dedupe
    -- in SQLite, so idempotent INSERT OR IGNORE relies on this generated key
    dedupe_key  TEXT GENERATED ALWAYS AS (
                    IFNULL(url, '') || char(31) || IFNULL(source, '') || char(31) ||
                    IFNULL(honeynet, '') || char(31) || IFNULL(session, '') || char(31) ||
                    IFNULL(observed_at, '')
                ) STORED
);

INSERT OR IGNORE INTO observations_new (id, url, source, honeynet, session, observed_at)
    SELECT id, url, source, honeynet, session, observed_at FROM observations;

DROP TABLE observations;
ALTER TABLE observations_new RENAME TO observations;

CREATE UNIQUE INDEX IF NOT EXISTS idx_observations_dedupe ON observations(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_observations_url           ON observations(url);
CREATE INDEX IF NOT EXISTS idx_observations_source        ON observations(source);
CREATE INDEX IF NOT EXISTS idx_observations_honeynet      ON observations(honeynet);
CREATE INDEX IF NOT EXISTS idx_observations_session       ON observations(session);
CREATE INDEX IF NOT EXISTS idx_observations_observed_at   ON observations(observed_at);

-- ============================================================================
-- 5. classification_history (FK -> urls.url) + ON DELETE CASCADE
-- ============================================================================
CREATE TABLE IF NOT EXISTS classification_history_new
(
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT NOT NULL REFERENCES urls(url) ON DELETE CASCADE,
    classification TEXT NOT NULL,
    reason         TEXT,
    note           TEXT,
    actor          TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

INSERT OR IGNORE INTO classification_history_new (id, url, classification, reason, note, actor, created_at)
    SELECT id, url, classification, reason, note, actor, created_at FROM classification_history;

DROP TABLE classification_history;
ALTER TABLE classification_history_new RENAME TO classification_history;

CREATE INDEX IF NOT EXISTS idx_classification_history_url        ON classification_history(url);
CREATE INDEX IF NOT EXISTS idx_classification_history_created_at ON classification_history(created_at);

-- ============================================================================
-- 6. download_observations (FK -> urls.url, content.id) + ON DELETE CASCADE
--
--    FK content_id -> content(id) intentionally remains non-cascading
--    (RESTRICT semantics): content rows/files must never be removed as a side
--    effect of a URL delete -- they may be shared. Their conditional cleanup
--    is handled by the application layer (db_cleaner / content_store helpers).
-- ============================================================================
CREATE TABLE IF NOT EXISTS download_observations_new
(
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    url              TEXT NOT NULL REFERENCES urls(url) ON DELETE CASCADE,
    content_id       INTEGER REFERENCES content(id),
    fetched_at       TEXT NOT NULL,        -- ISO timestamp of the request
    source_ip        TEXT,                 -- remote IP the content was served from
    status_code      INTEGER,
    response_headers TEXT,                 -- JSON dict of response headers
    change_type      TEXT NOT NULL DEFAULT 'initial'
                         CHECK (change_type IN ('initial', 'confirmed', 'content_changed', 'unavailable'))
);

INSERT OR IGNORE INTO download_observations_new
    (id, url, content_id, fetched_at, source_ip, status_code, response_headers, change_type)
    SELECT id, url, content_id, fetched_at, source_ip, status_code, response_headers, change_type
    FROM download_observations;

DROP TABLE download_observations;
ALTER TABLE download_observations_new RENAME TO download_observations;

CREATE INDEX IF NOT EXISTS idx_download_obs_url        ON download_observations(url);
CREATE INDEX IF NOT EXISTS idx_download_obs_content    ON download_observations(content_id);
CREATE INDEX IF NOT EXISTS idx_download_obs_fetched_at ON download_observations(fetched_at);

-- ============================================================================
-- 7. Integrity gate -- if any FK violation remains, a deliberate NOT NULL
--    constraint failure aborts the transaction (sqlite3 CLI exits non-zero
--    with .bail on), so the whole migration is rolled back and a broken state
--    can never be committed. On success this inserts 0 rows into a scratch
--    table that is dropped immediately afterwards.
-- ============================================================================
CREATE TABLE IF NOT EXISTS _fk_integrity_gate (must_be_empty INTEGER NOT NULL);
INSERT INTO _fk_integrity_gate
    SELECT NULL FROM pragma_foreign_key_check LIMIT 1;
DROP TABLE _fk_integrity_gate;

COMMIT;

PRAGMA foreign_keys = ON;
