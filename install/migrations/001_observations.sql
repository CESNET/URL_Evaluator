-- Migration: add URL observations & traceability support to an existing database.
-- Safe to run multiple times (uses IF NOT EXISTS and INSERT OR IGNORE).

PRAGMA foreign_keys = OFF;

-- 1. Create the observations table if it does not exist yet
CREATE TABLE IF NOT EXISTS observations
(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL REFERENCES urls(url),
    source      TEXT NOT NULL,
    honeynet    TEXT,
    session     TEXT REFERENCES sessions(session_hash),
    observed_at TEXT NOT NULL,
    -- NULL-normalized dedupe key: UNIQUE on NULLable columns does not dedupe in SQLite,
    -- so idempotent INSERT OR IGNORE relies on this generated key instead
    dedupe_key  TEXT GENERATED ALWAYS AS (
                    IFNULL(url, '') || char(31) || IFNULL(source, '') || char(31) ||
                    IFNULL(honeynet, '') || char(31) || IFNULL(session, '') || char(31) ||
                    IFNULL(observed_at, '')
                ) STORED
);

-- 2. Indexes for efficient provenance joins and time-based queries
CREATE UNIQUE INDEX IF NOT EXISTS idx_observations_dedupe ON observations(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_observations_url           ON observations(url);
CREATE INDEX IF NOT EXISTS idx_observations_source        ON observations(source);
CREATE INDEX IF NOT EXISTS idx_observations_honeynet      ON observations(honeynet);
CREATE INDEX IF NOT EXISTS idx_observations_session       ON observations(session);
CREATE INDEX IF NOT EXISTS idx_observations_observed_at   ON observations(observed_at);

-- 3a. Backfill from url_source: one observation per (url, source),
--     observed_at taken from urls.first_seen (best available timestamp),
--     session unknown (NULL). Known honeynet labels (Warden nodes and the
--     T-Pot platform) double as the honeynet name; pure feeds keep honeynet NULL.
INSERT OR IGNORE INTO observations (url, source, honeynet, session, observed_at)
SELECT
    us.url,
    us.source,
    CASE
        WHEN us.source IN ('CESNET Hugo', 'CZ.NIC HaaS', 'GEANT T-Pot') THEN us.source
        ELSE NULL
    END,
    NULL,
    COALESCE(u.first_seen, date('now'))
FROM url_source AS us
JOIN urls AS u ON u.url = us.url;

-- 3b. Backfill session context: link each url_session pair to its session.
--     Source is taken from the URL's url_source entry when determinable,
--     otherwise falls back to 'Warden' (sessions originate from Warden events).
INSERT OR IGNORE INTO observations (url, source, honeynet, session, observed_at)
SELECT
    usl.url,
    COALESCE(us.source, 'Warden'),
    CASE
        WHEN us.source IN ('CESNET Hugo', 'CZ.NIC HaaS', 'GEANT T-Pot') THEN us.source
        ELSE NULL
    END,
    usl.session,
    COALESCE(u.first_seen, date('now'))
FROM url_session AS usl
JOIN urls AS u ON u.url = usl.url
LEFT JOIN url_source AS us ON us.url = usl.url;

PRAGMA foreign_keys = ON;
