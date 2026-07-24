import json
import logging
from datetime import datetime, timezone

from common.content_storage import save_content

LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
logger = logging.getLogger("db_helpers")


def record_url_history(db, url, field, old_value, new_value, changed_by="system"):
    """
    Record a change to a URL field in url_history.

    If old_value == new_value, no row is inserted.
    """
    if old_value == new_value:
        return

    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO url_history (url, changed_at, field, old_value, new_value, changed_by)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (url, now, field, old_value, new_value, changed_by),
    )


def update_url_field(db, url, field, new_value, changed_by="system"):
    """
    Update a single field in urls if the value changed, recording the change
    in url_history via record_url_history.

    The caller is responsible for committing.
    Returns True if the value was updated, False if unchanged.
    """
    # Defensive: ensure the field exists in urls to prevent accidental SQL injection
    info = db.execute("PRAGMA table_info(urls)").fetchall()
    valid_fields = {row[1] for row in info}
    if field not in valid_fields:
        raise ValueError(f"Invalid URL field: {field}")

    row = db.execute(f"SELECT {field} FROM urls WHERE url = ?", (url,)).fetchone()
    old_value = row[0] if row else None

    if old_value == new_value:
        return False

    db.execute(f"UPDATE urls SET {field} = ? WHERE url = ?", (new_value, url))
    record_url_history(db, url, field, old_value, new_value, changed_by)
    return True


def set_url_latest_content(db, url, content_hash):
    """
    Mark content_hash as the latest snapshot for url.

    All other url_content rows for this URL are marked is_latest = 'no'.
    The row for content_hash is inserted (if missing) with first_seen = now
    and updated with last_seen = now and is_latest = 'yes'.
    """
    now = datetime.now(timezone.utc).isoformat()

    db.execute(
        "UPDATE url_content SET is_latest = 'no' WHERE url = ? AND is_latest = 'yes'",
        (url,),
    )
    db.execute(
        """
        INSERT INTO url_content (url, content_hash, first_seen, last_seen, is_latest)
        VALUES (?, ?, ?, ?, 'yes')
        ON CONFLICT(url, content_hash) DO UPDATE SET
            last_seen = excluded.last_seen,
            is_latest = 'yes';
        """,
        (url, content_hash, now, now),
    )


def _extract_socket(response):
    """Best-effort extraction of the underlying socket from a requests Response."""
    try:
        conn = response.raw._connection
        if conn is None:
            return None
        sock = conn.sock
        if sock is None:
            return None
        return sock
    except Exception:
        pass
    try:
        # Some urllib3 versions keep the socket on the HTTPResponse itself.
        fp = response.raw._fp
        if fp is None:
            return None
        inner_fp = fp.fp
        if inner_fp is None:
            return None
        return inner_fp._sock
    except Exception:
        pass
    return None


def persist_content_snapshot(db, base_dir, url, response, content, mime_type):
    """
    Persist a downloaded content snapshot and update url_content / urls.

    Saves the content to disk, inserts a content_snapshot row (if new),
    upserts the corresponding url_content row as latest, updates urls with
    hash / latest_content_hash / file_mime_type / content_size, and records
    a url_history row when the latest_content_hash changes.

    Returns a dict with snapshot metadata: hash (SHA-1), latest_content_hash
    (SHA-256), file_mime_type and content_size.
    """
    sha256, sha1, storage_path_rel, is_new = save_content(base_dir, content)
    downloaded_at = datetime.now(timezone.utc).isoformat()

    source_ip = None
    server_ip = None
    try:
        sock = _extract_socket(response)
        if sock is not None:
            peer = sock.getpeername()
            local = sock.getsockname()
            if peer and isinstance(peer[0], str):
                server_ip = peer[0]
            if local and isinstance(local[0], str):
                source_ip = local[0]
    except Exception:
        pass

    http_status = response.status_code
    http_headers = json.dumps(dict(response.headers))
    content_size = len(content)

    if is_new:
        db.execute(
            """
            INSERT OR IGNORE INTO content_snapshot
            (content_hash, url, downloaded_at, source_ip, server_ip, http_status,
             http_headers, mime_type, content_size, storage_path, sha1, sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sha256,
                url,
                downloaded_at,
                source_ip,
                server_ip,
                http_status,
                http_headers,
                mime_type,
                content_size,
                storage_path_rel,
                sha1,
                sha256,
            ),
        )
        logger.debug(f"Recorded content snapshot {sha256} for {url}")

    set_url_latest_content(db, url, sha256)

    old_row = db.execute(
        "SELECT latest_content_hash FROM urls WHERE url = ?", (url,)
    ).fetchone()
    old_hash = old_row[0] if old_row else None

    db.execute(
        """
        UPDATE urls
        SET hash = ?, latest_content_hash = ?, file_mime_type = ?, content_size = ?
        WHERE url = ?
        """,
        (sha1, sha256, mime_type, content_size, url),
    )

    if old_hash != sha256:
        record_url_history(
            db, url, "latest_content_hash", old_hash, sha256, changed_by="system"
        )
        logger.info(f"URL {url} latest content hash changed: {old_hash} -> {sha256}")

    return {
        "hash": sha1,
        "latest_content_hash": sha256,
        "file_mime_type": mime_type,
        "content_size": content_size,
    }
