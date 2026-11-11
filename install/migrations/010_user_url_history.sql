-- Migration: remember the last URLs each web UI user opened in the detail
-- page (most recent first, at most 10 per user -- trimmed by the web app).
-- Safe to run multiple times (uses IF NOT EXISTS). Purely additive.

CREATE TABLE IF NOT EXISTS user_url_history
(
    user        TEXT NOT NULL,                                       -- web.main.get_user() identity
    url         TEXT NOT NULL REFERENCES urls(url) ON DELETE CASCADE,
    visited_at  TEXT NOT NULL,                                       -- ISO timestamp (UTC) of the latest visit
    PRIMARY KEY (user, url)
);

CREATE INDEX IF NOT EXISTS idx_user_url_history_user_visited ON user_url_history(user, visited_at);
