import json
from datetime import datetime, timedelta, timezone

import pytest
from freezegun import freeze_time

from common import hybrid_analysis
from tests.api_mocks import mock_ha_overview
from tests.factories import insert_content, insert_sandbox_submission

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
    ("whitelisted", "harmless"),
    ("suspicious", None),
    ("no specific threat", None),
    (None, None),
])
def test_classification_from_lookup(verdict, expected):
    lookup = {"tested": True, "overview": {"verdict": verdict, "vx_family": "Linux.Mirai"}}
    cls = hybrid_analysis.classification_from_lookup(lookup)
    assert (cls or {}).get("classification") == expected
    assert hybrid_analysis.classification_from_lookup({"tested": False, "http_status": 404}) is None
