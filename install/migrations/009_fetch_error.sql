-- Migration: remember WHY a download observation carries no content, so the
-- Content tab can tell "connection timed out" apart from "HTTP 404" or
-- "payload too large" instead of showing an empty version card.
-- Additive: adds one nullable column (NULL = content stored, or a row recorded
-- before this migration -- the GUI then infers the reason from status_code).

ALTER TABLE download_observations ADD COLUMN fetch_error TEXT;   -- content_store.FETCH_ERRORS key, e.g. 'timeout', 'http_error', 'oversized'
