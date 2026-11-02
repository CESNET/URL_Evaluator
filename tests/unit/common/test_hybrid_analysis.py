import json
import re
from datetime import datetime, timedelta, timezone

import pytest
import requests
from freezegun import freeze_time

from common import hybrid_analysis
from tests.api_mocks import load_json, mock_ha_overview, mock_ha_submit
from tests.factories import insert_content, insert_discovered, insert_download, insert_sandbox_submission, insert_url

SHA256 = "a" * 64
NOW = "2026-01-01 12:00:00"


def test_lookup_known_hash(http_mock, config):
    call = mock_ha_overview(http_mock, config, SHA256, status=200)

    result = hybrid_analysis.lookup_sha256(config, SHA256)

    assert result["tested"] is True and result["http_status"] == 200
    assert result["overview"]["verdict"] == "malicious"
    assert result["reports"][0]["environment_id"] == 330
    assert result["sample_url"].endswith(SHA256)
    assert call.calls[0].request.headers["api-key"] == "test-ha-key"


def test_lookup_unknown_hash_is_submittable(http_mock, config):
    mock_ha_overview(http_mock, config, SHA256, status=404)

    result = hybrid_analysis.lookup_sha256(config, SHA256)

    assert result["tested"] is False and result["error"] is None
    assert hybrid_analysis.is_submittable(result)


def test_lookup_disabled_without_api_key(http_mock, make_config):
    config = make_config(ha_key="!!! CHANGE THIS !!!")
    assert hybrid_analysis.lookup_sha256(config, SHA256) is None
    assert len(http_mock.calls) == 0


@freeze_time(NOW)
def test_rate_limit_pauses_lookups_until_retry_after(http_mock, config):
    call = mock_ha_overview(http_mock, config, status=429, headers={"Retry-After": "120"})

    first = hybrid_analysis.lookup_sha256(config, SHA256)

    assert first["http_status"] == 429
    assert hybrid_analysis.paused_until() == datetime(2026, 1, 1, 12, 2, tzinfo=timezone.utc)
    # paused: no request is sent at all
    assert hybrid_analysis.lookup_sha256(config, SHA256) is None
    assert call.call_count == 1
    assert hybrid_analysis.request_stats()["by_status"] == {429: 1}


def test_lookups_resume_after_pause(http_mock, config):
    with freeze_time(NOW) as clock:
        mock_ha_overview(http_mock, config, status=429, headers={"Retry-After": "120"})
        hybrid_analysis.lookup_sha256(config, SHA256)

        clock.tick(timedelta(seconds=121))
        http_mock.reset()
        mock_ha_overview(http_mock, config, status=404)

        assert hybrid_analysis.paused_until() is None
        assert hybrid_analysis.lookup_sha256(config, SHA256)["http_status"] == 404


def test_check_content_caches_answer_for_recheck_hours(http_mock, config, db):
    content_id = insert_content(db, b"payload")
    call = mock_ha_overview(http_mock, config, status=404)

    with freeze_time(NOW) as clock:
        assert hybrid_analysis.check_content_outcome(db, config, content_id, SHA256)[1] == "checked"
        clock.tick(timedelta(hours=11))
        assert hybrid_analysis.check_content_outcome(db, config, content_id, SHA256)[1] == "cached"
        clock.tick(timedelta(hours=2))  # older than ha_recheck_hours (12)
        assert hybrid_analysis.check_content_outcome(db, config, content_id, SHA256)[1] == "checked"

    assert call.call_count == 2
    stored = json.loads(db.execute("SELECT sandbox_info FROM content WHERE id = ?", (content_id,)).fetchone()[0])
    assert stored["hybrid_analysis"]["http_status"] == 404


def test_failed_recheck_keeps_previous_answer(http_mock, config, db):
    content_id = insert_content(db, b"payload")
    with freeze_time(NOW) as clock:
        mock_ha_overview(http_mock, config, status=200)
        hybrid_analysis.check_content_outcome(db, config, content_id, SHA256)

        clock.tick(timedelta(hours=13))
        http_mock.reset()
        mock_ha_overview(http_mock, config, status=429)
        result, outcome = hybrid_analysis.check_content_outcome(db, config, content_id, SHA256)

    assert outcome == "failed"
    assert result["tested"] is True and result["http_status"] == 200
    assert result["last_error"]["http_status"] == 429


# --- Submissions and their fetch schedule ---

def _submission(db, sha256=SHA256, **overrides):
    content_id = insert_content(db, b"payload", sha256=sha256)
    values = {"next_fetch_at": "2026-01-01T12:10:00+00:00"}
    values.update(overrides)
    return content_id, insert_sandbox_submission(db, content_id, sha256, **values)


def _row(db, submission_id):
    return db.execute("SELECT status, verdict, fetch_attempts, next_fetch_at, last_fetch_at "
                      "FROM sandbox_submissions WHERE id = ?", (submission_id,)).fetchone()


def test_submit_schedules_first_fetch_10_min_after_submission(http_mock, config, db, content_dir):
    content_id = insert_content(db, b"payload", content_dir=content_dir)
    sha256 = db.execute("SELECT sha256, file_path FROM content WHERE id = ?", (content_id,)).fetchone()
    mock_ha_overview(http_mock, config, status=404)
    http_mock.post(f"{config.ha_url}/submit/file", status=201,
                   json={"job_id": "j1", "submission_id": "s1", "sha256": sha256[0]})

    with freeze_time(NOW):
        _, outcome = hybrid_analysis.submit_content(db, config, content_id, sha256[1], sha256[0], "alice", 330)

    assert outcome == "submitted"
    sub = hybrid_analysis.latest_submission(db, sha256[0])
    assert sub["status"] == "pending" and sub["fetch_attempts"] == 0
    assert sub["next_fetch_at"] == "2026-01-01T12:10:00+00:00"


def test_regular_lookup_finding_report_finishes_scheduled_fetches(http_mock, config, db):
    content_id, submission_id = _submission(db)
    mock_ha_overview(http_mock, config, status=200)

    with freeze_time("2026-01-01 12:05:00"):
        hybrid_analysis.check_content_outcome(db, config, content_id, SHA256, force=True)

    assert _row(db, submission_id)[:4] == ("done", "malicious", 0, None)


# --- Classification by the report ---

@pytest.mark.parametrize("verdict, expected", [
    ("malicious", "malicious"),
    ("whitelisted", None),  # HA never classifies a URL harmless
    ("suspicious", None),
    ("no specific threat", None),
    (None, None),
])
def test_classification_from_lookup(verdict, expected):
    lookup = {"tested": True, "overview": {"verdict": verdict, "vx_family": "Linux.Mirai"}}
    cls = hybrid_analysis.classification_from_lookup(lookup)
    assert (cls or {}).get("classification") == expected
    assert hybrid_analysis.classification_from_lookup({"tested": False, "http_status": 404}) is None


# --- Lookup errors ---

def test_lookup_request_failure(http_mock, config):
    http_mock.get(re.compile(f"{config.ha_url}/overview/.+"), body=requests.exceptions.ReadTimeout())

    result = hybrid_analysis.lookup_sha256(config, SHA256)

    assert result["error"] == "Request failed: ReadTimeout" and result["http_status"] is None
    assert hybrid_analysis.request_stats()["by_status"] == {"ReadTimeout": 1}


@pytest.mark.parametrize("status, body, error", [
    (500, {"message": "Internal error"}, "Internal error"),
    (503, "<html>down</html>", "HTTP 503"),
    (200, ["not", "a", "dict"], "HTTP 200"),
])
def test_lookup_unexpected_answer(http_mock, config, status, body, error):
    kwargs = {"json": body} if not isinstance(body, str) else {"body": body}
    http_mock.get(re.compile(f"{config.ha_url}/overview/.+"), status=status, **kwargs)

    result = hybrid_analysis.lookup_sha256(config, SHA256)

    assert result["error"] == error and result["tested"] is False
    assert not hybrid_analysis.is_submittable(result)


@freeze_time(NOW)
def test_rate_limit_without_valid_retry_after_uses_default_backoff(http_mock, config):
    mock_ha_overview(http_mock, config, status=429, headers={"Retry-After": "soon"})

    hybrid_analysis.lookup_sha256(config, SHA256)

    assert hybrid_analysis.paused_until() == datetime(2026, 1, 1, 13, 0, tzinfo=timezone.utc)


def test_lookup_keeps_only_reports_of_this_sample(http_mock, config):
    body = load_json("ha", "overview_200.json")
    body["related_reports"] = [{"sha256": SHA256, "job_id": "own", "environment_id": 330},
                               {"sha256": "b" * 64, "job_id": "other-file", "environment_id": 330}]
    http_mock.get(re.compile(f"{config.ha_url}/overview/.+"), json=body)

    assert [r["job_id"] for r in hybrid_analysis.lookup_sha256(config, SHA256)["reports"]] == ["own"]


def test_lookup_without_related_reports_lists_report_ids(http_mock, config):
    body = load_json("ha", "overview_200.json")
    body["related_reports"] = []
    http_mock.get(re.compile(f"{config.ha_url}/overview/.+"), json=body)

    assert hybrid_analysis.lookup_sha256(config, SHA256)["reports"] == [{"job_id": "65f0aa000000000000000001"}]


def test_request_stats_peak_per_minute(monkeypatch):
    clock = iter([0, 10, 50, 59, 61, 200])
    monkeypatch.setattr(hybrid_analysis.time, "monotonic", lambda: next(clock))
    for _ in range(6):
        with hybrid_analysis._stats_lock:
            hybrid_analysis._request_times.append(hybrid_analysis.time.monotonic())

    stats = hybrid_analysis.request_stats()

    assert stats["requests"] == 6 and stats["peak_per_minute"] == 4  # 0, 10, 50, 59


def test_check_content_skipped_without_content(config, db):
    assert hybrid_analysis.check_content_outcome(db, config, None, SHA256) == (None, "skipped")


def test_stale_lookup_is_never_reused(http_mock, config, db):
    content_id = insert_content(db, b"payload")
    db.execute("UPDATE content SET sandbox_info = ? WHERE id = ?", (json.dumps({"hybrid_analysis": {
        "http_status": 404, "checked_at": datetime.now(timezone.utc).isoformat(), "stale": True}}), content_id))
    call = mock_ha_overview(http_mock, config, status=404)

    result, outcome = hybrid_analysis.check_content_outcome(db, config, content_id, SHA256)

    assert outcome == "checked" and call.call_count == 1
    assert result["stale"] is True  # still no report -> keep querying


# --- Submissions ---

def _stored(db, content_dir, data=b"payload"):
    content_id = insert_content(db, data, content_dir=content_dir)
    sha256, file_path = db.execute("SELECT sha256, file_path FROM content WHERE id = ?", (content_id,)).fetchone()
    return content_id, sha256, file_path


def _sandbox_info(db, content_id):
    return json.loads(db.execute("SELECT sandbox_info FROM content WHERE id = ?", (content_id,)).fetchone()[0])


def test_submit_sends_sample_and_marks_lookup_stale(http_mock, config, db, content_dir):
    content_id, sha256, file_path = _stored(db, content_dir)
    mock_ha_overview(http_mock, config, status=404)
    submit = mock_ha_submit(http_mock, config)

    result, outcome = hybrid_analysis.submit_content(db, config, content_id, file_path, sha256, "alice", 160)

    assert outcome == "submitted" and result["job_id"] == "job-1"
    request = submit.calls[0].request
    assert b'name="environment_id"\r\n\r\n160' in request.body and sha256.encode() + b".bin" in request.body
    assert db.execute("SELECT submitted_by, status, report_url FROM sandbox_submissions").fetchone() == (
        "alice", "pending", f"https://hybrid-analysis.com/sample/{sha256}")
    info = _sandbox_info(db, content_id)
    assert info["hybrid_analysis"]["stale"] is True
    assert info["hybrid_analysis_submission"]["environment_id"] == 160


def test_submit_comment_from_config(http_mock, make_config, db, content_dir):
    config = make_config(ha_submit_comment="URL Evaluator test")
    content_id, sha256, file_path = _stored(db, content_dir)
    mock_ha_overview(http_mock, config, status=404)
    submit = mock_ha_submit(http_mock, config)

    hybrid_analysis.submit_content(db, config, content_id, file_path, sha256, "alice", 330)

    assert b"URL Evaluator test" in submit.calls[0].request.body


@pytest.mark.parametrize("status", ["pending", "running", "done"])
def test_hash_with_active_submission_is_not_submitted_again(http_mock, config, db, content_dir, status):
    content_id, sha256, file_path = _stored(db, content_dir)
    insert_sandbox_submission(db, content_id, sha256, status=status)

    _, outcome = hybrid_analysis.submit_content(db, config, content_id, file_path, sha256, "bob", 330)

    assert outcome == "already_submitted" and len(http_mock.calls) == 0


def test_hash_with_failed_submission_can_be_submitted_again(http_mock, config, db, content_dir):
    content_id, sha256, file_path = _stored(db, content_dir)
    insert_sandbox_submission(db, content_id, sha256, status="error", submitted_at="2026-01-01T10:00:00+00:00")
    mock_ha_overview(http_mock, config, status=404)
    mock_ha_submit(http_mock, config)

    assert hybrid_analysis.submit_content(db, config, content_id, file_path, sha256, "bob", 330)[1] == "submitted"
    assert hybrid_analysis.latest_submission(db, sha256)["submitted_by"] == "bob"


@pytest.mark.parametrize("lookup_status, outcome", [(200, "already_analysed"), (429, "lookup_failed")])
def test_submit_requires_fresh_404_lookup(http_mock, config, db, content_dir, lookup_status, outcome):
    content_id, sha256, file_path = _stored(db, content_dir)
    mock_ha_overview(http_mock, config, status=lookup_status)
    submit = mock_ha_submit(http_mock, config)

    assert hybrid_analysis.submit_content(db, config, content_id, file_path, sha256, "alice", 330)[1] == outcome
    assert submit.call_count == 0
    assert db.execute("SELECT COUNT(*) FROM sandbox_submissions").fetchone()[0] == 0


def test_submit_disabled_without_api_key(http_mock, make_config, db, content_dir):
    config = make_config(ha_key="")
    content_id, sha256, file_path = _stored(db, content_dir)

    assert hybrid_analysis.submit_content(db, config, content_id, file_path, sha256, "alice", 330) == (None, "skipped")
    assert len(http_mock.calls) == 0


@pytest.mark.parametrize("status, error", [(403, "error"), (429, "error")])
def test_rejected_submission_is_logged(http_mock, config, db, content_dir, status, error):
    content_id, sha256, file_path = _stored(db, content_dir)
    mock_ha_overview(http_mock, config, status=404)
    mock_ha_submit(http_mock, config, status=status)

    result, outcome = hybrid_analysis.submit_content(db, config, content_id, file_path, sha256, "alice", 330)

    assert outcome == "submit_failed" and result["error"] == error
    assert db.execute("SELECT status, next_fetch_at FROM sandbox_submissions").fetchone() == ("error", None)
    assert not _sandbox_info(db, content_id)["hybrid_analysis"].get("stale")
    assert (hybrid_analysis.paused_until() is not None) == (status == 429)


def test_submit_file_that_cannot_be_read(http_mock, config):
    result = hybrid_analysis.submit_file(config, "/nonexistent/sample", SHA256, 330)

    assert result["error"] == "Cannot read stored sample: FileNotFoundError"
    assert len(http_mock.calls) == 0


def test_submit_file_request_failure(http_mock, config, tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"x")
    http_mock.post(f"{config.ha_url}/submit/file", body=requests.exceptions.ConnectionError())

    assert hybrid_analysis.submit_file(config, str(sample), SHA256, 330)["error"] == "Request failed: ConnectionError"


@freeze_time(NOW)
def test_submit_file_skipped_while_rate_limited(http_mock, config, tmp_path):
    hybrid_analysis._blocked_until = datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc)

    assert hybrid_analysis.submit_file(config, str(tmp_path), SHA256, 330) is None
    assert len(http_mock.calls) == 0


def test_fetch_schedule_from_config(make_config):
    config = make_config(ha_fetch_schedule_minutes=[30, 5])
    assert hybrid_analysis.fetch_schedule(config) == (5, 30)
    start = "2026-01-01T12:00:00+00:00"
    assert hybrid_analysis.scheduled_fetch_at(config, start, datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc)) == \
        "2026-01-01T12:30:00+00:00"
    assert hybrid_analysis.scheduled_fetch_at(config, start, datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc)) is None


def test_whitelisted_report_does_not_classify_urls(db):
    src = insert_url(db, "http://loader.test/", evaluated="yes")
    url = insert_url(db, evaluated="yes")
    insert_discovered(db, url, src)
    insert_download(db, url, insert_content(db, b"payload", sha256=SHA256))

    urls = hybrid_analysis.classify_urls(db, SHA256, {"tested": True, "overview": {"verdict": "whitelisted"}})

    assert urls == []
    assert db.execute("SELECT url, classification FROM urls ORDER BY url").fetchall() == [
        (url, "unclassified"), (src, "unclassified")]
    assert db.execute("SELECT COUNT(*) FROM classification_history").fetchone()[0] == 0


@pytest.mark.parametrize("sandbox_info, expected", [
    (None, None),
    ("not json", None),
    ('["a list"]', None),
    ('{"hybrid_analysis": {"http_status": 404}}', {"http_status": 404}),
])
def test_get_lookup_tolerates_invalid_sandbox_info(sandbox_info, expected):
    assert hybrid_analysis.get_lookup(sandbox_info) == expected


def test_submit_skipped_when_paused_between_lookup_and_post(http_mock, config, db, content_dir, monkeypatch):
    content_id, sha256, file_path = _stored(db, content_dir)
    mock_ha_overview(http_mock, config, status=404)
    monkeypatch.setattr(hybrid_analysis, "submit_file", lambda *args, **kwargs: None)

    assert hybrid_analysis.submit_content(db, config, content_id, file_path, sha256, "alice", 330) == (None, "skipped")
    assert db.execute("SELECT COUNT(*) FROM sandbox_submissions").fetchone()[0] == 0


def test_cached_lookup_with_invalid_checked_at_is_queried_again(http_mock, config, db):
    content_id = insert_content(db, b"payload")
    db.execute("UPDATE content SET sandbox_info = ? WHERE id = ?", (json.dumps({"hybrid_analysis": {
        "http_status": 404, "checked_at": "yesterday"}}), content_id))
    call = mock_ha_overview(http_mock, config, status=404)

    assert hybrid_analysis.check_content_outcome(db, config, content_id, SHA256)[1] == "checked"
    assert call.call_count == 1
