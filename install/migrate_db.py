#!/usr/bin/env python3
"""
Database migration script for URL Evaluator Stage 1.

Prepares an existing database for the new data model described in
plans/implementation_plan.md and plans/new_data_model.md:

  - Extends url_source with richer source metadata.
  - Adds latest_content_hash to urls.
  - Creates content_snapshot, url_content, url_history and sandbox_job tables.
  - Adds discovered_at to discovered_urls.
  - Creates required indexes.
  - Migrates existing url_source rows and creates placeholder content_snapshot
    records for URLs that already have a hash / file_mime_type.

The script is idempotent and can be run multiple times safely.
"""

import argparse
import hashlib
import logging
import os
import sys
from datetime import datetime, timezone

# Add the project root to the import path so common.* can be found.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

from common.config import Config
from common.db import SQLiteWrapper


LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
logger = logging.getLogger("migrate_db")


def _table_exists(cursor, table: str) -> bool:
    cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cursor.fetchone() is not None


def _column_exists(cursor, table: str, column: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


def _index_exists(cursor, index: str) -> bool:
    cursor.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?", (index,))
    return cursor.fetchone() is not None


def _add_column(cursor, table: str, column: str, definition: str) -> None:
    if not _column_exists(cursor, table, column):
        logger.info(f"Adding column {table}.{column}")
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def ensure_schema(db) -> None:
    """Create missing tables / columns / indexes (idempotent)."""
    cursor = db.cursor

    # ------------------------------------------------------------------
    # Core tables (kept from the original schema)
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_hash TEXT PRIMARY KEY,
            session      TEXT,
            idea_id      TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS urls (
            url                   TEXT PRIMARY KEY,
            first_seen            DATE,
            last_seen             DATE,
            hash                  TEXT,
            classification        TEXT DEFAULT 'unclassified'
                                  CHECK (classification IN ('malicious', 'harmless', 'unreachable', 'unclassified', 'invalid', 'miner')),
            classification_reason TEXT DEFAULT 'Waiting for evaluation',
            note                  TEXT,
            reported              TEXT DEFAULT 'no' CHECK (reported IN ('yes', 'no')),
            occurrences           INTEGER DEFAULT 1,
            vt_stats              TEXT,
            evaluated             TEXT DEFAULT 'no' CHECK (evaluated IN ('yes', 'no')),
            file_mime_type        TEXT,
            content_size          INTEGER,
            threat_label          TEXT,
            status                TEXT DEFAULT 'unknown'
                                  CHECK (status IN ('active', 'inactive', 'unknown')),
            last_active           DATE,
            status_changed        TEXT DEFAULT 'no' CHECK (status_changed IN ('yes', 'no')),
            last_edit             TEXT,
            eval_later            TEXT DEFAULT 'no' CHECK (eval_later IN ('yes', 'no')),
            domain                TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_source (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            url           TEXT REFERENCES urls(url),
            source        TEXT,
            source_detail TEXT,
            origin_url    TEXT,
            observed_at   DATETIME,
            idea_id       TEXT,
            session_hash  TEXT REFERENCES sessions(session_hash)
        );
    """)

    # The code base references discovered_urls, so keep that name.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS discovered_urls (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            url           TEXT REFERENCES urls(url),
            src_url       TEXT REFERENCES urls(url),
            discovered_at DATETIME,
            CONSTRAINT discovered_urls_unique UNIQUE (url, src_url)
        );
    """)

    # ------------------------------------------------------------------
    # New tables for Stage 1
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS content_snapshot (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            content_hash  TEXT UNIQUE,
            url           TEXT,
            downloaded_at DATETIME,
            source_ip     TEXT,
            server_ip     TEXT,
            http_status   INTEGER,
            http_headers  TEXT,
            mime_type     TEXT,
            content_size  INTEGER,
            storage_path  TEXT,
            sha1          TEXT,
            sha256        TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_content (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            url           TEXT REFERENCES urls(url),
            content_hash  TEXT REFERENCES content_snapshot(content_hash),
            first_seen    DATETIME,
            last_seen     DATETIME,
            is_latest     TEXT CHECK (is_latest IN ('yes', 'no')),
            CONSTRAINT url_content_unique UNIQUE (url, content_hash)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT REFERENCES urls(url),
            changed_at  DATETIME,
            field       TEXT,
            old_value   TEXT,
            new_value   TEXT,
            changed_by  TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sandbox_job (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            content_hash  TEXT REFERENCES content_snapshot(content_hash),
            url           TEXT REFERENCES urls(url),
            provider      TEXT,
            external_id   TEXT,
            status        TEXT CHECK (status IN ('pending', 'running', 'completed', 'failed')),
            submitted_at  DATETIME,
            completed_at  DATETIME,
            report_url    TEXT,
            report_json   TEXT,
            requested_by  TEXT
        );
    """)

    # ------------------------------------------------------------------
    # Add new columns to existing tables when migrating an old DB
    # ------------------------------------------------------------------
    # Ensure url_source has a unique constraint on (url, source) so that
    # ON CONFLICT(url, source) works in record_url_source().
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_url_source_unique
        ON url_source(url, source);
    """)

    _add_column(cursor, "urls", "latest_content_hash", "TEXT")
    _add_column(cursor, "url_source", "source_detail", "TEXT")
    _add_column(cursor, "url_source", "origin_url", "TEXT")
    _add_column(cursor, "url_source", "observed_at", "DATETIME")
    _add_column(cursor, "url_source", "idea_id", "TEXT")
    _add_column(cursor, "url_source", "session_hash", "TEXT")
    _add_column(cursor, "discovered_urls", "discovered_at", "DATETIME")

    # ------------------------------------------------------------------
    # Indexes
    # ------------------------------------------------------------------
    indexes = [
        ("idx_url_source_lookup", "CREATE INDEX idx_url_source_lookup ON url_source(url, source, observed_at)"),
        ("idx_url_source_origin", "CREATE INDEX idx_url_source_origin ON url_source(origin_url)"),
        ("idx_url_content_latest", "CREATE INDEX idx_url_content_latest ON url_content(url, is_latest)"),
        ("idx_url_content_hash", "CREATE INDEX idx_url_content_hash ON url_content(content_hash)"),
        ("idx_url_history_url", "CREATE INDEX idx_url_history_url ON url_history(url, changed_at)"),
        ("idx_sandbox_job_status", "CREATE INDEX idx_sandbox_job_status ON sandbox_job(content_hash, status)"),
    ]
    for name, sql in indexes:
        if not _index_exists(cursor, name):
            logger.info(f"Creating index {name}")
            cursor.execute(sql)

    db.conn.commit()


def migrate_url_source(db) -> None:
    """Backfill url_source metadata from urls / discovered_urls."""
    cursor = db.cursor

    # For every url_source row that has not been observed_at yet, set it from
    # the URL's first_seen (or now as a last resort).
    cursor.execute("""
        SELECT s.id, s.url, u.first_seen
        FROM url_source s
        JOIN urls u ON u.url = s.url
        WHERE s.observed_at IS NULL;
    """)
    rows = cursor.fetchall()
    if rows:
        logger.info(f"Backfilling observed_at for {len(rows)} url_source rows")
    now = datetime.now(timezone.utc).isoformat()
    for row_id, url, first_seen in rows:
        observed_at = first_seen or now
        cursor.execute(
            "UPDATE url_source SET observed_at = ? WHERE id = ?",
            (observed_at, row_id)
        )

    # Backfill origin_url from discovered_urls if url_source has no origin_url
    # but discovered_urls has a matching src_url and url.
    cursor.execute("""
        SELECT DISTINCT d.url, d.src_url
        FROM discovered_urls d
        WHERE d.src_url IS NOT NULL
          AND EXISTS (
              SELECT 1 FROM url_source s
              WHERE s.url = d.url AND s.origin_url IS NULL
          );
    """)
    discovered = cursor.fetchall()
    if discovered:
        logger.info(f"Backfilling origin_url for {len(discovered)} discovered URLs")
    for url, src_url in discovered:
        cursor.execute(
            "UPDATE url_source SET origin_url = ? WHERE url = ? AND origin_url IS NULL",
            (src_url, url)
        )

    db.conn.commit()


def migrate_content_snapshots(db) -> None:
    """
    Create placeholder content_snapshot and url_content rows for existing URLs
    that already have a hash / file_mime_type but no snapshot yet.
    """
    cursor = db.cursor

    cursor.execute("""
        SELECT u.url, u.hash, u.file_mime_type, u.content_size, u.first_seen
        FROM urls u
        WHERE u.hash IS NOT NULL
          AND u.latest_content_hash IS NULL;
    """)
    rows = cursor.fetchall()
    if not rows:
        return

    logger.info(f"Creating placeholder snapshots for {len(rows)} URLs with existing hash")
    now = datetime.now(timezone.utc).isoformat()

    for url, sha1, mime_type, content_size, first_seen in rows:
        # We do not have the actual content, so we cannot compute SHA-256.
        # Use a deterministic synthetic hash so the same SHA-1 maps to the same
        # placeholder snapshot.  This preserves backward compatibility without
        # fabricating real SHA-256 hashes.
        synthetic = hashlib.sha256(f"placeholder:{sha1}".encode()).hexdigest()

        cursor.execute(
            "INSERT OR IGNORE INTO content_snapshot (content_hash, url, downloaded_at, mime_type, content_size, storage_path, sha1, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (synthetic, url, first_seen or now, mime_type, content_size, None, sha1, synthetic)
        )

        # Only insert url_content if not already present for this URL/hash pair.
        cursor.execute(
            "SELECT 1 FROM url_content WHERE url = ? AND content_hash = ?",
            (url, synthetic)
        )
        if cursor.fetchone() is None:
            cursor.execute(
                """
                INSERT INTO url_content (url, content_hash, first_seen, last_seen, is_latest)
                VALUES (?, ?, ?, ?, 'yes')
                """,
                (url, synthetic, first_seen or now, first_seen or now)
            )

        cursor.execute(
            "UPDATE urls SET latest_content_hash = ? WHERE url = ?",
            (synthetic, url)
        )

    db.conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Migrate URL Evaluator database to Stage 1 schema")
    parser.add_argument("--config", "-c", default="/etc/url_evaluator/config.yaml", help="Path to config file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    config = Config(args.config)

    with SQLiteWrapper(config.db_path) as db:
        logger.info(f"Migrating database {config.db_path}")
        ensure_schema(db)
        migrate_url_source(db)
        migrate_content_snapshots(db)
        logger.info("Migration finished successfully")


if __name__ == "__main__":
    main()
