-- Migration: add persistent URL classification history.
-- Safe to run multiple times (uses IF NOT EXISTS).
--
-- Every time a URL's classification (and optionally its reason / note) is set or
-- changed -- by an automated module or by a human analyst -- an append-only row is
-- written here so the full audit trail is preserved independently of the current
-- value stored in the `urls` table.

PRAGMA foreign_keys = OFF;

-- 1. Append-only history of classification decisions for each URL.
CREATE TABLE IF NOT EXISTS classification_history
(
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT NOT NULL REFERENCES urls(url),
    classification TEXT NOT NULL,
    reason         TEXT,
    note           TEXT,
    -- Who/what performed the classification: a human username (from the web UI)
    -- or a system module identifier (e.g. 'evaluator', 'evaluator-backprop', ...).
    actor          TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

-- 2. Indexes for fast per-URL timeline lookups and time-ordered scans.
CREATE INDEX IF NOT EXISTS idx_classification_history_url        ON classification_history(url);
CREATE INDEX IF NOT EXISTS idx_classification_history_created_at ON classification_history(created_at);

-- 3. Backfill: seed one initial history row per existing URL so the timeline is
--    never empty for records that predate this feature. We synthesise the row
--    from the current state; only runs when the table is still empty so a
--    re-applied migration does not duplicate rows.
INSERT INTO classification_history (url, classification, reason, note, actor, created_at)
SELECT
    u.url,
    u.classification,
    u.classification_reason,
    u.note,
    CASE WHEN u.last_edit IS NOT NULL AND u.last_edit != '' THEN u.last_edit ELSE 'system' END,
    COALESCE(u.last_seen, u.first_seen, date('now')) || ' 00:00:00'
FROM urls AS u
WHERE NOT EXISTS (SELECT 1 FROM classification_history);

PRAGMA foreign_keys = ON;
