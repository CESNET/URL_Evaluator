"""
Shared database helper functions for URL Evaluator.

These helpers own all writes to the history-tracking and content tables so
individual backend modules don't duplicate SQL:

- :func:`record_url_history`     – append-on-change audit entries (``url_history``)
- :func:`update_url_field`       – update a ``urls`` column and record history
- :func:`set_url_latest_content` – flip the ``url_content.is_latest`` marker
- :func:`persist_content_snapshot` – save a downloaded payload to disk (dedup)
  and persist ``content_snapshot`` + ``url_content`` + ``urls`` metadata.

Used by the evaluator, the web edit handlers and ingestion modules.
"""

import json
import logging
from datetime import datetime, timezone

from common.content_storage import save_content

logger = logging.getLogger(__name__)

FETCH_IP_TIMEOUT = 5

# Columns of the ``urls`` table that update_url_field() is allowed to change.
# Business columns only – primary key and auto-tracked timestamps are excluded.
URL_UPDATABLE_FIELDS = {
    "hash",
    "classification",
    "classification_reason",
    "note",
    "reported",
    "occurrences",
    "vt_stats",
    "evaluated",
    "file_mime_type",
    "content_size",
    "threat_label",
    "status",
    "last_active",
    "status_changed",
    "last_edit",
    "eval_later",
    "domain",
    "latest_content_hash",
}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def record_url_history(db, url, field, old_value, new_value, changed_by="system"):
    """Append a change record to ``url_history`` when a value actually changed.

    No row is written when ``old_value == new_value`` so the history stays free
    of no-op noise.
    """
    if old_value == new_value:
        return False
    db.execute(
        """
        INSERT INTO url_history (url, changed_at, field, old_value, new_value, changed_by)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (url, _now(), field, old_value, new_value, changed_by),
    )
    return True


def update_url_field(db, url, field, new_value, changed_by="system"):
    """Update a single ``urls`` column and record the change in history.

    :returns: True when the value changed (and history was written), False when
              the new value equals the stored one (no update performed).
    :raises ValueError: when *field* is not an updatable ``urls`` column — this
                        also protects against SQL injection via the column name.
    """
    if field not in URL_UPDATABLE_FIELDS:
        raise ValueError(f"Invalid URL field: {field}")

    row = db.execute(f"SELECT {field} FROM urls WHERE url = ?", (url,)).fetchone()
    old_value = row[0] if row else None

    if old_value == new_value:
        return False

    db.execute(f"UPDATE urls SET {field} = ? WHERE url = ?", (new_value, url))
    record_url_history(db, url, field, old_value, new_value, changed_by=changed_by)
    return True


def set_url_latest_content(db, url, content_hash):
    """Mark *content_hash* as the current content of *url* in ``url_content``.

    An existing (url, content_hash) row only gets ``is_latest='yes'`` and a
    bumped ``last_seen``; a new one is created with ``first_seen == last_seen``.
    All other rows for the URL are flipped to ``is_latest='no'``.
    """
    now = _now()
    logger.debug(f"set_url_latest_content: marking {content_hash[:16]}... as latest for {url}")

    existing = db.execute(
        "SELECT id FROM url_content WHERE url = ? AND content_hash = ?",
        (url, content_hash),
    ).fetchone()

    if existing:
        logger.debug(f"set_url_latest_content: updating existing url_content row id={existing[0]}")
        db.execute(
            "UPDATE url_content SET last_seen = ?, is_latest = 'yes' WHERE id = ?",
            (now, existing[0]),
        )
    else:
        logger.debug(f"set_url_latest_content: creating new url_content row for {url}")
        db.execute(
            "INSERT INTO url_content (url, content_hash, first_seen, last_seen, is_latest) VALUES (?, ?, ?, ?, 'yes')",
            (url, content_hash, now, now),
        )

    db.execute(
        "UPDATE url_content SET is_latest = 'no' WHERE url = ? AND content_hash != ?",
        (url, content_hash),
    )
    logger.debug(f"set_url_latest_content: other content rows for {url} marked is_latest='no'")


def _extract_connection_ips(response):
    """Best-effort extraction of (source_ip, server_ip) from a requests response.

    Reads the underlying urllib3 connection socket. Returns ``(None, None)``
    when the information isn't available (e.g. mocked responses in tests).
    """
    source_ip = server_ip = None
    try:
        sock = response.raw._connection.sock
        if sock is not None:
            local = sock.getsockname()
            peer = sock.getpeername()
            if local:
                source_ip = local[0]
            if peer:
                server_ip = peer[0]
            logger.debug(f"_extract_connection_ips: source_ip={source_ip}, server_ip={server_ip}")
        else:
            logger.debug("_extract_connection_ips: underlying socket is None")
    except Exception:
        pass
    return source_ip, server_ip


def persist_content_snapshot(db, base_dir, url, response, content, mime_type):
    """Store a downloaded payload and persist its metadata + history link.

    Steps:
      1. Write *content* to the file storage (SHA-256 dedup).
      2. Insert-or-ignore a ``content_snapshot`` row (one per unique hash).
      3. Refresh the ``url_content`` link and mark it latest.
      4. Update ``urls.hash``/``latest_content_hash``/``file_mime_type``/``content_size``
         and record a ``latest_content_hash`` change in ``url_history``.

    :param base_dir: content storage base directory (config ``content_storage_path``)
    :param url: URL the content was downloaded from
    :param response: the ``requests`` response object (for status/headers/IPs)
    :param content: raw downloaded bytes
    :param mime_type: detected MIME type of the content
    :returns: dict with the new ``hash`` (sha1), ``latest_content_hash`` (sha256),
              ``file_mime_type``, ``content_size`` and ``storage_path``.
    """
    logger.debug(f"persist_content_snapshot: persisting {len(content)} bytes for {url} (base_dir={base_dir}, mime={mime_type})")
    sha256, sha1, rel_path, _is_new = save_content(base_dir, content)
    logger.debug(f"persist_content_snapshot: saved -> sha256={sha256}, sha1={sha1}, path={rel_path}, is_new={_is_new}")

    http_status = getattr(response, "status_code", None)
    headers = getattr(response, "headers", {}) or {}
    try:
        http_headers = json.dumps(dict(headers))
    except (TypeError, ValueError):
        http_headers = json.dumps({str(k): str(v) for k, v in headers.items()})

    source_ip, server_ip = _extract_connection_ips(response)
    downloaded_at = _now()

    logger.debug(f"persist_content_snapshot: inserting content_snapshot row (hash={sha256[:16]}..., status={http_status}, src={source_ip}, dst={server_ip})")
    db.execute(
        """
        INSERT INTO content_snapshot
            (content_hash, url, downloaded_at, source_ip, server_ip, http_status,
             http_headers, mime_type, content_size, storage_path, sha1, sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(content_hash) DO NOTHING
        """,
        (sha256, url, downloaded_at, source_ip, server_ip, http_status,
         http_headers, mime_type, len(content), rel_path, sha1, sha256),
    )

    previous_hash_row = db.execute(
        "SELECT latest_content_hash FROM urls WHERE url = ?", (url,)
    ).fetchone()
    previous_hash = previous_hash_row[0] if previous_hash_row else None
    logger.debug(f"persist_content_snapshot: previous latest_content_hash for {url}: {previous_hash}")

    set_url_latest_content(db, url, sha256)

    db.execute(
        "UPDATE urls SET hash = ?, latest_content_hash = ?, file_mime_type = ?, content_size = ? WHERE url = ?",
        (sha1, sha256, mime_type, len(content), url),
    )
    record_url_history(db, url, "latest_content_hash", previous_hash, sha256, changed_by="system")
    logger.debug(f"persist_content_snapshot: urls row updated + history recorded for {url}")

    return {
        "hash": sha1,
        "latest_content_hash": sha256,
        "file_mime_type": mime_type,
        "content_size": len(content),
        "storage_path": rel_path,
        "is_new": _is_new,
    }
