-- Migration: content-type classification of downloaded content with Magika.
--
-- Stores the result of common/file_classifier.py (Magika reads only the
-- payload bytes -- the sample is never executed) on every `content` row.
--
-- Purely additive: existing rows keep NULL until they are classified (lazily
-- when the same payload is downloaded again, or in bulk by
-- bin/classify_content.py).

ALTER TABLE content ADD COLUMN file_category      TEXT;   -- coarse class (file_classifier.CATEGORIES), NULL = not classified yet
ALTER TABLE content ADD COLUMN magika_label       TEXT;   -- Magika content type label, e.g. 'elf', 'shell', 'json', 'html'
ALTER TABLE content ADD COLUMN magika_group       TEXT;   -- Magika group, e.g. 'executable', 'code', 'archive'
ALTER TABLE content ADD COLUMN magika_mime        TEXT;   -- MIME type detected by Magika
ALTER TABLE content ADD COLUMN magika_description TEXT;   -- human readable type, e.g. 'ELF executable'
ALTER TABLE content ADD COLUMN magika_score       REAL;   -- Magika confidence (0..1)
ALTER TABLE content ADD COLUMN magika_model       TEXT;   -- Magika model name, e.g. 'standard_v3_3'
ALTER TABLE content ADD COLUMN classified_at      TEXT;   -- ISO timestamp (UTC) of the classification

CREATE INDEX IF NOT EXISTS idx_content_file_category ON content(file_category);
