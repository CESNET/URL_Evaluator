#Author: Lukáš Šimoník, xsimonl00@stud.fit.vutbr.cz

"""
Helpers for deduplicated content storage and per-download observation logging.

Raw payloads downloaded from URLs are written to the filesystem exactly once
per unique SHA-256 digest (deduplication). The database keeps only metadata:

  * ``content``               – one row per unique payload (hash -> file path)
  * ``download_observations`` – one row per HTTP fetch of a URL, with the
                                connection metadata (timestamp, source IP,
                                response headers, status code) and a foreign
                                key to the content row that was returned.

Grouping consecutive observations that returned the same content yields the
"versions" shown in the GUI Content tab (identical responses are grouped, only
distinct versions are displayed).
"""

import os
import json
import hashlib
import logging
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def ensure_content_dir(content_dir):
    """Create the content storage directory if it does not exist yet."""
    try:
        os.makedirs(content_dir, exist_ok=True)
    except OSError as e:
        logger.error(f"Could not create content directory {content_dir}: {e}")
        raise


def content_file_path(content_dir, sha256):
    """
    Deterministic on-disk location for a payload with the given SHA-256.

    Files are sharded into two-level subdirectories (first 2 / next 2 hex
    chars) so a single directory never holds an excessive number of files.
    """
    return os.path.join(content_dir, sha256[:2], sha256[2:4], sha256)


def write_content_file(content_dir, sha256, data):
    """
    Persist `data` to disk under its SHA-256 name (deduplicated).

    Returns the absolute file path. If the file already exists (identical
    content was captured before), it is left untouched and the existing path
    is returned.

    Raises OSError (with a detailed warning already logged) when the payload
    cannot be written to disk.
    """
    path = content_file_path(content_dir, sha256)
    if os.path.exists(path):
        logger.debug(f"Content {sha256[:12]}… already stored at {path}")
        return path
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError as e:
        logger.warning(
            f"Could not create subdirectory for content {sha256} "
            f"(target dir {os.path.dirname(path)}, size {len(data)} bytes): {e}"
        )
        raise
    # Write to a temp file then rename to avoid partial files on crash.
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "wb") as fh:
            fh.write(data)
    except OSError as e:
        logger.warning(
            f"Could not write content file {tmp_path} (sha256={sha256}, "
            f"size {len(data)} bytes) – check free disk space and permissions: {e}"
        )
        # Best-effort cleanup of the partial temp file.
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise
    try:
        os.replace(tmp_path, path)
    except OSError as e:
        logger.warning(
            f"Could not move temp file {tmp_path} to final location {path} "
            f"(sha256={sha256}): {e}"
        )
        raise
    logger.info(f"Stored new content sample {sha256[:12]}… ({len(data)} bytes) at {path}")
    return path


def remove_content_file(file_path):
    """
    Best-effort removal of a stored payload from disk.

    Returns True when the file is gone (deleted now or already missing),
    False when the unlink failed (a warning is logged in that case).
    Never raises -- a filesystem problem must not break DB cleanup.
    """
    if not file_path:
        return False
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Removed content file {file_path}")
        else:
            logger.debug(f"Content file {file_path} already missing on disk")
        return True
    except OSError as e:
        logger.warning(f"Could not remove content file {file_path}: {e}")
        return False


def _delete_ids_generic(db, table, column, ids):
    """
    Internal helper: delete rows from `table` where `column` matches one of
    `ids`, using a parameterised IN clause (never string-formatted values).
    Commits via the wrapper's execute(); returns rows affected.
    """
    ids = list(ids)
    if not ids:
        return 0
    placeholders = ",".join("?" for _ in ids)
    return db.execute(
        f"DELETE FROM {table} WHERE {column} IN ({placeholders})", ids
    ).rowcount


def delete_urls(db, urls):
    """
    Delete one or more URLs (and, thanks to ON DELETE CASCADE, every record
    bound to them: observations, classification_history, url_session,
    url_source, discovered_urls, download_observations).

    The given URL table rows are removed in a parameterised query. With
    foreign-key enforcement enabled (SQLiteWrapper sets PRAGMA
    foreign_keys=ON), the associated rows are cascaded in the same statement.

    Returns the number of URL rows deleted.
    """
    return _delete_ids_generic(db, "urls", "url", urls)


def content_ids_for_urls(db, urls):
    """
    Return a set of (content_id, file_path) pairs referenced by download
    observations of the given URLs -- used to decide (after the URLs are
    deleted) which payloads have become unreferenced and can be purged.
    """
    urls = list(urls)
    if not urls:
        return set()
    placeholders = ",".join("?" for _ in urls)
    rows = db.execute(
        f"""
        SELECT DISTINCT d.content_id, c.file_path
        FROM download_observations AS d
        JOIN content AS c ON c.id = d.content_id
        WHERE d.url IN ({placeholders}) AND d.content_id IS NOT NULL
        """,
        urls,
    ).fetchall()
    return {(row[0], row[1]) for row in rows if row[0] is not None}


def cleanup_orphan_content(db, candidates=None, remove_files=True):
    """
    Conditional disk/DB cleanup of deduplicated content (F7).

    A content row is only ever removed when *no* `download_observations` row
    in the whole database references it anymore (i.e. its payload is not
    shared with any other, still-known URL). This guarantees the property
    "delete the malware sample file from disk only when it is no longer used
    by any URL".

    `candidates` may restrict the check to an iterable of content ids (e.g.
    the ids that were referenced by the just-deleted URLs) for efficiency;
    when None, every content row is checked.

    For each unreferenced content row the payload file is unlinked first
    (best-effort via remove_content_file) and the metadata row is removed
    from the `content` table afterwards. `sandbox_submissions` rows are kept
    by design: they carry the denormalised sha256 and remain meaningful even
    after the sample is purged. Their content_id FK is left untouched --
    after the content row is removed it simply no longer resolves. To keep
    FK enforcement satisfied we NULL the reference out first.

    Returns a summary dict {"removed": n, "skipped_shared": m, "file_errors": k}.
    """
    removed = 0
    skipped_shared = 0
    file_errors = 0

    if candidates is not None:
        candidates = [int(c) for c in candidates if c is not None]
        if not candidates:
            return {"removed": 0, "skipped_shared": 0, "file_errors": 0}
        placeholders = ",".join("?" for _ in candidates)
        rows = db.execute(
            f"SELECT id, file_path FROM content WHERE id IN ({placeholders})",
            candidates,
        ).fetchall()
    else:
        rows = db.execute("SELECT id, file_path FROM content").fetchall()

    for content_id, file_path in rows:
        # Shared-content guard (F5): is the payload still referenced by any
        # (other) download observation in the DB?
        in_use = db.execute(
            "SELECT 1 FROM download_observations WHERE content_id = ? LIMIT 1",
            (content_id,),
        ).fetchone()
        if in_use:
            skipped_shared += 1
            logger.debug(
                f"Content {content_id} is still shared by other URLs -- kept"
            )
            continue

        # Remove the payload file from disk before deleting the DB row, so a
        # filesystem failure does not strand a DB row pointing at nothing.
        if remove_files and file_path:
            if not remove_content_file(file_path):
                file_errors += 1

        # Detach sandbox submission rows so the non-cascading FK to content
        # is satisfied when the content row disappears (submission records
        # stay meaningful via their denormalised sha256).
        db.execute(
            "UPDATE sandbox_submissions SET content_id = NULL WHERE content_id = ?",
            (content_id,),
        )
        db.execute("DELETE FROM content WHERE id = ?", (content_id,))
        removed += 1

    summary = {"removed": removed, "skipped_shared": skipped_shared, "file_errors": file_errors}
    logger.info(f"Content cleanup: {summary}")
    return summary


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def resolve_source_ip(url):
    """Best-effort DNS resolution of the remote host serving `url`."""
    try:
        host = urlparse(url).hostname
        if not host:
            return None
        return socket.gethostbyname(host)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_or_create_content(db, content_dir, data, mime_type=None, url=None):
    """
    Insert a content row for `data` (deduplicated by SHA-256) and store the
    payload on disk if it is new.

    Returns a dict: {id, sha256, file_path, file_size, mime_type, created},
    or None when the payload could not be written to disk (a detailed warning
    is logged in that case).
    """
    sha256 = hashlib.sha256(data).hexdigest()
    row = db.execute(
        "SELECT id, file_path, mime_type FROM content WHERE sha256 = ?",
        (sha256,)
    ).fetchone()
    if row:
        return {
            "id": row[0],
            "sha256": sha256,
            "file_path": row[1],
            "file_size": len(data),
            "mime_type": row[2],
            "created": False,
        }

    try:
        file_path = write_content_file(content_dir, sha256, data)
    except OSError as e:
        logger.warning(
            f"Failed to store content {sha256} (size {len(data)} bytes"
            f"{', url ' + url if url else ''}) to disk – content record "
            f"will not be created: {e}"
        )
        return None
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db.execute(
        """
        INSERT INTO content (sha256, file_path, file_size, mime_type, first_seen)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(sha256) DO NOTHING
        """,
        (sha256, file_path, len(data), mime_type, now),
    )
    row = db.execute("SELECT id FROM content WHERE sha256 = ?", (sha256,)).fetchone()
    return {
        "id": row[0] if row else None,
        "sha256": sha256,
        "file_path": file_path,
        "file_size": len(data),
        "mime_type": mime_type,
        "created": True,
    }


def latest_content_id(db, url):
    """Return the content_id of the most recent successful fetch of `url`."""
    row = db.execute(
        """
        SELECT content_id FROM download_observations
        WHERE url = ? AND content_id IS NOT NULL
        ORDER BY fetched_at DESC, id DESC
        LIMIT 1
        """,
        (url,),
    ).fetchone()
    return row[0] if row else None


def record_download_observation(
    db,
    url,
    content_id=None,
    fetched_at=None,
    source_ip=None,
    status_code=None,
    response_headers=None,
    change_type=None,
):
    """
    Append one row to ``download_observations``.

    When `change_type` is not supplied it is derived automatically:
      * 'content_changed' if the previous successful fetch returned a
        different content_id
      * 'confirmed'       if it returned the same content_id
      * 'initial'         for the first successful fetch of the URL
      * 'unavailable'     when content_id is None
    """
    if fetched_at is None:
        fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if isinstance(response_headers, (dict, list)):
        response_headers = json.dumps(dict(response_headers))

    if change_type is None:
        if content_id is None:
            change_type = "unavailable"
        else:
            prev = latest_content_id(db, url)
            if prev is None:
                change_type = "initial"
            elif prev == content_id:
                change_type = "confirmed"
            else:
                change_type = "content_changed"

    db.execute(
        """
        INSERT INTO download_observations
            (url, content_id, fetched_at, source_ip, status_code, response_headers, change_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (url, content_id, fetched_at, source_ip, status_code, response_headers, change_type),
    )
    return db.cursor.lastrowid


# ---------------------------------------------------------------------------
# Version grouping for the Content tab
# ---------------------------------------------------------------------------

def get_content_versions(db, url):
    """
    Group a URL's download observations into consecutive "versions" of
    identical content (per the Figma mockup: identical responses are grouped,
    only distinct versions are shown).

    Returns a list of dicts, oldest version first, e.g.::

        [
          {
            "version": 1,
            "content_id": 12,
            "sha256": "ffee…",
            "file_size": 44851,
            "mime_type": "application/octet-stream",
            "first_fetched": "2025-08-15T06:00:11+00:00",
            "last_fetched":  "2025-09-30T06:00:22+00:00",
            "fetch_count": 4,
            "source_ip": "162.215.218.82",
            "status_code": 200,
            "response_headers": {...},
            "changed": False,
          },
          ...
        ]
    """
    rows = db.execute(
        """
        SELECT d.content_id, d.fetched_at, d.source_ip, d.status_code,
               d.response_headers, d.change_type,
               c.sha256, c.file_size, c.mime_type, c.file_path
        FROM download_observations AS d
        LEFT JOIN content AS c ON c.id = d.content_id
        WHERE d.url = ?
        ORDER BY d.fetched_at ASC, d.id ASC
        """,
        (url,),
    ).fetchall()

    versions = []
    for r in rows:
        (content_id, fetched_at, source_ip, status_code, headers_json,
         change_type, sha256, file_size, mime_type, file_path) = r
        if versions and versions[-1]["content_id"] == content_id:
            v = versions[-1]
            v["last_fetched"] = fetched_at
            v["fetch_count"] += 1
            # keep freshest metadata
            if source_ip:
                v["source_ip"] = source_ip
            if status_code:
                v["status_code"] = status_code
            if headers_json:
                v["response_headers"] = _parse_headers(headers_json)
        else:
            try:
                headers = _parse_headers(headers_json)
            except Exception:
                headers = {}
            versions.append({
                "version": len(versions) + 1,
                "content_id": content_id,
                "sha256": sha256,
                "file_size": file_size,
                "mime_type": mime_type,
                "file_path": file_path,
                "first_fetched": fetched_at,
                "last_fetched": fetched_at,
                "fetch_count": 1,
                "source_ip": source_ip,
                "status_code": status_code,
                "response_headers": headers,
                "changed": change_type == "content_changed",
            })
    return versions


def _parse_headers(headers_json):
    """
    Normalise the DB `response_headers` value to a plain dict.

    Accepts the JSON string stored in download_observations.response_headers
    (or an already-deserialised dict) and always returns a dict: {} for
    NULL/empty, the dict unchanged, or json.loads() of the JSON text.

    Examples:
        _parse_headers(None)                                   -> {}
        _parse_headers("")                                     -> {}
        _parse_headers({"Server": "nginx"})                    -> {"Server": "nginx"}
        _parse_headers('{"Server": "nginx", "Content-Length": "123"}')
            -> {"Server": "nginx", "Content-Length": "123"}
    """
    if not headers_json:
        return {}
    if isinstance(headers_json, dict):
        return headers_json
    return json.loads(headers_json)
