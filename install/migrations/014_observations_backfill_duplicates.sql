-- Migration: drop the duplicate observations created by the backfill of 001.
-- 001 inserted, for every existing URL, one observation per source without a
-- session (3a) AND one per session (3b), both dated urls.first_seen -- the
-- sightings of a URL seen in sessions were counted twice, so the Sources tab
-- showed more sightings than urls.occurrences (Overview). Drop the
-- session-less row when the same URL, source and honeynet has a session row
-- of the same date. Rows written by the collectors since then are dated by
-- the sighting itself (Warden / T-Pot: full timestamp), not first_seen.
-- Data only: the schema does not change.

DELETE FROM observations
WHERE session IS NULL
  AND observed_at = (SELECT first_seen FROM urls WHERE urls.url = observations.url)
  AND EXISTS (SELECT 1 FROM observations AS s
              WHERE s.url = observations.url
                AND s.source = observations.source
                AND s.honeynet IS observations.honeynet
                AND s.session IS NOT NULL
                AND s.observed_at = observations.observed_at);
