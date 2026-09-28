-- Migration: add malware-sandbox submission history linked to content.
-- Safe to run multiple times (uses IF NOT EXISTS). Purely additive: it does not
-- modify or drop any existing table, column or row.

PRAGMA foreign_keys = OFF;

-- One row per submission of a content sample to a malware sandbox.
--
-- The sample itself is referenced both by its content row id (so the GUI can
-- link the submission straight back to the Content entry / download) and by the
-- denormalised SHA-256 digest (kept for convenience and so the record remains
-- meaningful even if the content row is ever purged). The payload stays on the
-- filesystem exactly once per digest (see migration 003); this table only keeps
-- the sandbox-analysis metadata.
CREATE TABLE IF NOT EXISTS sandbox_submissions
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

CREATE INDEX IF NOT EXISTS idx_sandbox_subm_content    ON sandbox_submissions(content_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_subm_sha256     ON sandbox_submissions(sha256);
CREATE INDEX IF NOT EXISTS idx_sandbox_subm_name       ON sandbox_submissions(sandbox_name);
CREATE INDEX IF NOT EXISTS idx_sandbox_subm_submitted  ON sandbox_submissions(submitted_at);

PRAGMA foreign_keys = ON;
