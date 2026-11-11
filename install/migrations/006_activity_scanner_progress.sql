-- Migration: persist activity_scanner progress so an interrupted run (service
-- stop / server restart) is resumed on the next start instead of waiting for
-- the next scheduled run.
-- Safe to run multiple times (uses IF NOT EXISTS). Purely additive.

-- One row per activity_scanner run; finished_at stays NULL while the run is in
-- progress or after it was interrupted.
CREATE TABLE IF NOT EXISTS activity_scanner_runs
(
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,                    -- ISO timestamp (UTC)
    finished_at   TEXT                              -- ISO timestamp (UTC), NULL = unfinished
);

-- URLs already re-polled by an unfinished run (cleared when the run finishes).
CREATE TABLE IF NOT EXISTS activity_scanner_progress
(
    run_id        INTEGER NOT NULL REFERENCES activity_scanner_runs(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    PRIMARY KEY (run_id, url)
);
