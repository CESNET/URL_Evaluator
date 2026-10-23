-- Migration: index url_session by session.
-- The only index on url_session is UNIQUE (url, session), which cannot be
-- used to look rows up by session alone. Deleting from `sessions` (db_cleaner
-- drops orphan sessions) cascades to url_session, so without this index every
-- deleted session meant a full scan of url_session -- hundreds of thousands of
-- deleted sessions took hours and held the write lock the whole time.
-- Additive: only creates an index.

CREATE INDEX IF NOT EXISTS idx_url_session_session ON url_session(session);
