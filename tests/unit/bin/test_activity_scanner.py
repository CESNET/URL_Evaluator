import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import requests
from freezegun import freeze_time

from common import content_store
from tests.api_mocks import mock_ha_overview
from tests.factories import insert_content, insert_sandbox_submission, insert_url

URL = "http://evil.test/a.sh"
NOW = "2026-01-10 06:00:00"


def url_row(db, url=URL):
    return db.execute("SELECT status, status_changed, last_active, last_scanned FROM urls WHERE url = ?",
                      (url,)).fetchone()


def observations(db, url=URL):
    return db.execute("SELECT status_code, change_type, content_id IS NOT NULL, fetch_error, source_ip "
                      "FROM download_observations WHERE url = ? ORDER BY id", (url,)).fetchall()


def runs(db):
    return db.execute("SELECT id, finished_at IS NOT NULL FROM activity_scanner_runs ORDER BY id").fetchall()


def test_active_url_is_stored_and_marked_active(activity_scanner_mod, http_mock, config, db):
    # no freeze_time: pysqlite3 cannot bind freezegun's FakeDate (last_active is a date object)
    insert_url(db, URL, status="unknown")
    http_mock.get(URL, body=b"#!/bin/sh\necho v1\n")
    mock_ha_overview(http_mock, config, status=404)
    before = datetime.now(timezone.utc).isoformat(timespec="seconds")

    activity_scanner_mod.activity_scanner()

    status, changed, last_active, last_scanned = url_row(db)
    assert (status, changed, last_active) == ("active", "yes", datetime.now(timezone.utc).date().isoformat())
    assert last_scanned >= before
    assert observations(db) == [(200, "initial", 1, None, "192.0.2.1")]
    assert db.execute("SELECT file_category FROM content").fetchone() == ("script",)
    assert runs(db) == [(1, 1)]
    assert activity_scanner_mod.run_stats["content_stored"] == 1


@freeze_time(NOW)
def test_inactive_url_keeps_its_last_active_date(activity_scanner_mod, http_mock, db):
    insert_url(db, URL, status="active", last_active="2026-01-01")
    http_mock.get(URL, status=404, body="gone")

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[:3] == ("inactive", "yes", "2026-01-01")
    assert observations(db) == [(404, "unavailable", 0, "http_error", "192.0.2.1")]


def test_unchanged_status_is_not_flagged(activity_scanner_mod, http_mock, db):
    insert_url(db, URL, status="active")
    http_mock.get(URL, body=b"x")

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[:2] == ("active", "no")


@pytest.mark.parametrize("error, fetch_error", [
    (requests.exceptions.ConnectionError("refused"), "connection_error"),
    (requests.exceptions.ConnectTimeout("connect timeout"), "timeout"),
    (requests.exceptions.ReadTimeout("read timeout"), "timeout"),
])
def test_network_error_marks_url_inactive(activity_scanner_mod, http_mock, db, error, fetch_error):
    insert_url(db, URL, status="active")
    http_mock.get(URL, body=error)

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[:2] == ("inactive", "yes")
    assert observations(db) == [(None, "unavailable", 0, fetch_error, "192.0.2.1")]
    assert runs(db) == [(1, 1)]


def test_redirect_loop_marks_url_inactive_and_scan_continues(activity_scanner_mod, http_mock, db):
    insert_url(db, URL, status="active")
    insert_url(db, "http://evil.test/next.sh", status="unknown")
    http_mock.get(URL, body=requests.exceptions.TooManyRedirects("loop"))
    http_mock.get("http://evil.test/next.sh", body=b"x")

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[0] == "inactive"
    assert observations(db) == [(None, "unavailable", 0, "too_many_redirects", "192.0.2.1")]
    assert url_row(db, "http://evil.test/next.sh")[0] == "active"


def test_invalid_url_is_skipped(activity_scanner_mod, http_mock, db):
    insert_url(db, "not a url")

    activity_scanner_mod.activity_scanner()

    assert len(http_mock.calls) == 0
    assert url_row(db, "not a url")[0] == "unknown"
    assert runs(db) == [(1, 1)]


def test_content_change_is_detected(activity_scanner_mod, http_mock, db):
    insert_url(db, URL)
    for body in (b"v1", b"v1", b"v2"):
        http_mock.reset()
        http_mock.get(URL, body=body)
        activity_scanner_mod.activity_scanner()

    assert [o[1] for o in observations(db)] == ["initial", "confirmed", "content_changed"]
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 2


def test_body_is_not_stored_without_content_dir(init_bin, make_config, http_mock, db):
    scanner = init_bin("activity_scanner", make_config(content_dir=""))
    insert_url(db, URL)
    http_mock.get(URL, body=b"payload")

    scanner.activity_scanner()

    assert url_row(db)[0] == "active"
    assert observations(db) == [(200, "unavailable", 0, "storage_disabled", "192.0.2.1")]


def test_unusable_content_dir_is_recorded_as_storage_failure(init_bin, make_config, http_mock, db, tmp_path):
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("x")
    scanner = init_bin("activity_scanner", make_config(content_dir=str(not_a_dir)))
    insert_url(db, URL)
    http_mock.get(URL, body=b"payload")

    scanner.activity_scanner()

    assert url_row(db)[0] == "active"
    assert observations(db) == [(200, "unavailable", 0, "storage_failed", "192.0.2.1")]
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0


def test_stored_content_is_looked_up_on_hybrid_analysis(activity_scanner_mod, http_mock, config, db):
    insert_url(db, URL)
    http_mock.get(URL, body=b"\x7fELF\x02\x01\x01" + b"\x00" * 64)
    mock_ha_overview(http_mock, config, status=200)

    activity_scanner_mod.activity_scanner()

    info = json.loads(db.execute("SELECT sandbox_info FROM content").fetchone()[0])
    assert info["hybrid_analysis"]["tested"] is True
    assert activity_scanner_mod.run_stats["ha_checked"] == 1
    assert activity_scanner_mod.run_stats["ha_tested"] == 1


def test_stop_request_interrupts_the_run_and_next_start_resumes_it(activity_scanner_mod, http_mock, db, monkeypatch):
    first, second = insert_url(db, "http://evil.test/1"), insert_url(db, "http://evil.test/2")
    http_mock.get(first, body=b"1")
    http_mock.get(second, body=b"2")
    record = activity_scanner_mod._record_daily_fetch

    def record_then_stop(*args, **kwargs):
        record(*args, **kwargs)
        activity_scanner_mod.stop_event.set()  # SIGTERM while the first URL is processed
    monkeypatch.setattr(activity_scanner_mod, "_record_daily_fetch", record_then_stop)

    activity_scanner_mod.activity_scanner()

    assert runs(db) == [(1, 0)]
    assert db.execute("SELECT url FROM activity_scanner_progress").fetchall() == [(first,)]

    monkeypatch.setattr(activity_scanner_mod, "_record_daily_fetch", record)
    activity_scanner_mod.stop_event.clear()
    activity_scanner_mod.activity_scanner()

    assert [r[0] for r in db.execute("SELECT url FROM download_observations ORDER BY id")] == [first, second]
    assert runs(db) == [(1, 1)]
    assert db.execute("SELECT COUNT(*) FROM activity_scanner_progress").fetchone()[0] == 0


def test_run_is_skipped_while_previous_one_is_in_progress(activity_scanner_mod, http_mock, db):
    insert_url(db, URL)

    with activity_scanner_mod.run_lock:
        activity_scanner_mod.activity_scanner()

    assert len(http_mock.calls) == 0 and runs(db) == []


def test_finished_run_fetches_reports_left_by_the_scheduled_fetches(activity_scanner_mod, http_mock, config, db):
    content_id = insert_content(db, b"payload", sha256="a" * 64)
    submission = insert_sandbox_submission(db, content_id, "a" * 64, next_fetch_at=None, fetch_attempts=3)
    mock_ha_overview(http_mock, config, status=200)

    activity_scanner_mod.activity_scanner()

    assert db.execute("SELECT status FROM sandbox_submissions WHERE id = ?", (submission,)).fetchone() == ("done",)
    assert activity_scanner_mod.run_stats["ha_submissions_found"] == 1


def test_interrupted_run_does_not_fetch_waiting_reports(activity_scanner_mod, http_mock, config, db, monkeypatch):
    insert_url(db, "http://evil.test/1")
    insert_url(db, "http://evil.test/2")
    http_mock.get("http://evil.test/1", body=b"1")
    content_id = insert_content(db, b"payload", sha256="a" * 64)
    insert_sandbox_submission(db, content_id, "a" * 64, next_fetch_at=None)
    ha = mock_ha_overview(http_mock, config, status=200)
    record = activity_scanner_mod._record_daily_fetch
    monkeypatch.setattr(activity_scanner_mod, "_record_daily_fetch",
                        lambda *a, **kw: (record(*a, **kw), activity_scanner_mod.stop_event.set()))

    activity_scanner_mod.activity_scanner()

    # only the downloaded content was looked up, not the waiting submission
    assert not any(call.request.url.endswith("a" * 64) for call in ha.calls)
    assert db.execute("SELECT status FROM sandbox_submissions").fetchone() == ("pending",)


# --- Fetch (step 4.2) ---

@pytest.mark.parametrize("error, fetch_error", [
    (requests.exceptions.TooManyRedirects("loop"), "too_many_redirects"),
    (requests.exceptions.InvalidSchema("ftp"), "request_error"),
    (requests.exceptions.ChunkedEncodingError("broken"), "request_error"),
])
def test_any_request_error_marks_url_inactive(activity_scanner_mod, http_mock, db, error, fetch_error):
    insert_url(db, URL, status="active")
    http_mock.get(URL, body=error)

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[:2] == ("inactive", "yes")
    assert observations(db) == [(None, "unavailable", 0, fetch_error, "192.0.2.1")]


def test_unexpected_error_does_not_stop_the_scan(activity_scanner_mod, http_mock, db, monkeypatch):
    first, second = insert_url(db, "http://evil.test/1", status="unknown"), insert_url(db, "http://evil.test/2")
    http_mock.get(first, body=b"1")
    http_mock.get(second, body=b"2")
    record = activity_scanner_mod._record_daily_fetch

    def fail_on_first(db_conn, url, *args, **kwargs):
        if url == first:
            raise RuntimeError("database is locked")
        record(db_conn, url, *args, **kwargs)
    monkeypatch.setattr(activity_scanner_mod, "_record_daily_fetch", fail_on_first)

    activity_scanner_mod.activity_scanner()

    assert url_row(db, first)[0] == "unknown"  # retried by the next daily run
    assert url_row(db, second)[0] == "active"
    assert activity_scanner_mod.run_stats["urls_failed"] == 1
    assert runs(db) == [(1, 1)]


def test_oversized_content_is_not_downloaded(activity_scanner_mod, http_mock, db):
    insert_url(db, URL)
    http_mock.get(URL, body=b"x", headers={"Content-Length": str(2 * 1024 * 1024)})  # max_file_size: 1 MB

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[0] == "active"
    assert observations(db) == [(200, "unavailable", 0, "oversized", "192.0.2.1")]
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0


def test_unreadable_body_is_recorded(activity_scanner_mod, http_mock, db, monkeypatch):
    insert_url(db, URL)
    http_mock.get(URL, body=b"x")

    def broken(self):
        raise requests.exceptions.ChunkedEncodingError("connection reset")
    monkeypatch.setattr(requests.Response, "content", property(broken))

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[0] == "active"
    assert observations(db) == [(200, "unavailable", 0, "body_unreadable", "192.0.2.1")]


def test_request_uses_proxy_and_timeout(init_bin, make_config, db, monkeypatch):
    scanner = init_bin("activity_scanner", make_config(http_proxy="http://proxy.test:3128"))
    insert_url(db, URL)
    calls = []

    def fake_get(url, **kwargs):
        calls.append(kwargs)
        raise requests.exceptions.ConnectionError()
    monkeypatch.setattr(scanner.requests, "get", fake_get)

    scanner.activity_scanner()

    assert calls[0]["proxies"] == {"http": "http://proxy.test:3128", "https": "http://proxy.test:3128"}
    assert calls[0]["timeout"] == 10


# --- Update urls (step 4.4) ---

@freeze_time(NOW)
def test_active_url_gets_todays_last_active_date(activity_scanner_mod, http_mock, db):
    insert_url(db, URL, last_active="2026-01-01")
    http_mock.get(URL, body=b"x")

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[2:] == ("2026-01-10", "2026-01-10T06:00:00+00:00")


def test_status_changed_is_reset_when_status_stays(activity_scanner_mod, http_mock, db):
    # status_changed says whether the status flipped in the last scan
    insert_url(db, URL, status="active", status_changed="yes")
    http_mock.get(URL, body=b"x")

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[:2] == ("active", "no")


# --- Store content (step 4.3) ---

def test_storage_failure_is_recorded(activity_scanner_mod, http_mock, db, monkeypatch):
    insert_url(db, URL)
    http_mock.get(URL, body=b"payload")
    monkeypatch.setattr(content_store, "get_or_create_content", lambda *args, **kwargs: None)

    activity_scanner_mod.activity_scanner()

    assert observations(db) == [(200, "unavailable", 0, "storage_failed", "192.0.2.1")]


def test_observation_failure_does_not_stop_the_scan(activity_scanner_mod, http_mock, db, monkeypatch):
    insert_url(db, URL, status="unknown")
    http_mock.get(URL, body=b"x")

    def broken(*args, **kwargs):
        raise RuntimeError("disk full")
    monkeypatch.setattr(content_store, "record_download_observation", broken)

    activity_scanner_mod.activity_scanner()

    assert url_row(db)[0] == "active" and observations(db) == []
    assert runs(db) == [(1, 1)]


def test_same_content_on_two_urls_is_looked_up_once(activity_scanner_mod, http_mock, config, db):
    for url in ("http://evil.test/1", "http://evil.test/2"):
        insert_url(db, url)
        http_mock.get(url, body=b"#!/bin/sh\necho same\n")
    ha = mock_ha_overview(http_mock, config, status=404)

    activity_scanner_mod.activity_scanner()

    assert ha.call_count == 1
    assert (activity_scanner_mod.run_stats["ha_checked"], activity_scanner_mod.run_stats["ha_cached"]) == (1, 1)


def test_report_of_waiting_submission_found_by_daily_lookup_classifies_url(
        activity_scanner_mod, http_mock, config, db):
    body = b"\x7fELF\x02\x01\x01" + b"\x00" * 64
    insert_url(db, URL, evaluated="yes")
    content_id = insert_content(db, body)
    insert_sandbox_submission(db, content_id, hashlib.sha256(body).hexdigest(), next_fetch_at=None)
    http_mock.get(URL, body=body)
    ha = mock_ha_overview(http_mock, config, status=200)

    activity_scanner_mod.activity_scanner()

    assert db.execute("SELECT classification, classification_reason FROM urls").fetchone() == (
        "malicious", "Hybrid Analysis check")
    assert db.execute("SELECT status FROM sandbox_submissions").fetchone() == ("done",)
    assert ha.call_count == 1


# --- Threads, runs, summary (steps 3, 5, 6) ---

def test_urls_are_split_into_threads(activity_scanner_mod, http_mock, db, monkeypatch):
    urls = [insert_url(db, f"http://evil.test/{i}") for i in range(3)]
    for url in urls:
        http_mock.get(url, body=b"x")
    monkeypatch.setattr(activity_scanner_mod, "URLS_PER_THREAD", 2)
    thread_func, chunks = activity_scanner_mod.thread_func, []

    def recording(thread_id, run_id, chunk):
        chunks.append(len(chunk))
        thread_func(thread_id, run_id, chunk)
    monkeypatch.setattr(activity_scanner_mod, "thread_func", recording)

    activity_scanner_mod.activity_scanner()

    assert sorted(chunks) == [1, 2]
    assert [url_row(db, url)[0] for url in urls] == ["active"] * 3


def test_hash_queried_in_this_run_is_not_fetched_again(activity_scanner_mod, http_mock, config, db):
    body = b"#!/bin/sh\necho waiting\n"
    insert_url(db, URL)
    insert_sandbox_submission(db, insert_content(db, body), hashlib.sha256(body).hexdigest(), next_fetch_at=None)
    http_mock.get(URL, body=body)
    ha = mock_ha_overview(http_mock, config, status=404)  # report not ready yet

    activity_scanner_mod.activity_scanner()

    assert ha.call_count == 1  # the URL's lookup, the waiting submission is not fetched again


def test_resumed_run_does_not_query_hashes_again(activity_scanner_mod, http_mock, config, db):
    started = datetime.now(timezone.utc) - timedelta(hours=1)
    db.execute("INSERT INTO activity_scanner_runs (started_at) VALUES (?)", (started.isoformat(timespec="seconds"),))
    content_id = insert_content(db, b"payload", sha256="a" * 64, sandbox_info=json.dumps({"hybrid_analysis": {
        "http_status": 404, "stale": True,
        "checked_at": (started + timedelta(minutes=5)).isoformat(timespec="seconds")}}))
    insert_sandbox_submission(db, content_id, "a" * 64, next_fetch_at=None)
    ha = mock_ha_overview(http_mock, config, status=404)

    activity_scanner_mod.activity_scanner()  # resumes the run interrupted after the lookup

    assert runs(db) == [(1, 1)]
    assert ha.call_count == 0


def test_run_does_not_start_after_stop_request(activity_scanner_mod, http_mock, db):
    insert_url(db, URL)
    activity_scanner_mod.stop_event.set()

    activity_scanner_mod.activity_scanner()

    assert runs(db) == [] and len(http_mock.calls) == 0


def test_summary_warns_on_rate_limit(activity_scanner_mod, http_mock, config, db, caplog):
    caplog.set_level(logging.INFO)
    insert_url(db, URL)
    http_mock.get(URL, body=b"x")
    mock_ha_overview(http_mock, config, status=429)

    activity_scanner_mod.activity_scanner()

    assert "HTTP 429 (rate limit) received 1x during this run" in caplog.text
    assert activity_scanner_mod.run_stats["ha_failed"] == 1


def test_sigint_handler_stops_workers_and_scheduler(activity_scanner_mod, monkeypatch):
    scheduler = MagicMock()
    monkeypatch.setattr(activity_scanner_mod, "scheduler", scheduler, raising=False)

    activity_scanner_mod.sigint_handler(15, None)

    assert activity_scanner_mod.stop_event.is_set()
    scheduler.shutdown.assert_called_once_with(wait=True)
