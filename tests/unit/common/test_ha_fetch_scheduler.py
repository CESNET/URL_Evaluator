import json
from datetime import timedelta

from freezegun import freeze_time

from common import ha_fetch_scheduler, hybrid_analysis
from tests.api_mocks import mock_ha_overview
from tests.factories import insert_content, insert_discovered, insert_download, insert_sandbox_submission, insert_url

SHA256 = "a" * 64
NOW = "2026-01-01 12:00:00"


def _submission(db, sha256=SHA256, **overrides):
    content_id = insert_content(db, b"payload", sha256=sha256)
    values = {"next_fetch_at": "2026-01-01T12:10:00+00:00"}
    values.update(overrides)
    return content_id, insert_sandbox_submission(db, content_id, sha256, **values)


def _row(db, submission_id):
    return db.execute("SELECT status, verdict, fetch_attempts, next_fetch_at, last_fetch_at "
                      "FROM sandbox_submissions WHERE id = ?", (submission_id,)).fetchone()


def test_scheduled_fetch_waits_until_due(http_mock, config, db):
    _, submission_id = _submission(db)
    call = mock_ha_overview(http_mock, config, status=404)

    with freeze_time("2026-01-01 12:09:59"):
        assert not ha_fetch_scheduler.fetch_due_results(db, config)

    assert call.call_count == 0
    assert _row(db, submission_id)[2:4] == (0, "2026-01-01T12:10:00+00:00")


def test_scheduled_fetch_not_ready_moves_to_next_slot(http_mock, config, db):
    content_id, submission_id = _submission(db)
    mock_ha_overview(http_mock, config, status=404)

    with freeze_time("2026-01-01 12:10:30"):
        stats = ha_fetch_scheduler.fetch_due_results(db, config)

    assert stats == {"not_ready": 1}
    assert _row(db, submission_id) == ("pending", None, 1, "2026-01-01T12:20:00+00:00", "2026-01-01T12:10:30+00:00")


def test_scheduled_fetch_ends_after_30_min_and_keeps_lookup_stale(http_mock, config, db):
    content_id, submission_id = _submission(db)
    db.execute("UPDATE content SET sandbox_info = ? WHERE id = ?",
               (json.dumps({"hybrid_analysis": {"http_status": 404, "checked_at": NOW, "stale": True}}), content_id))
    call = mock_ha_overview(http_mock, config, status=404)

    with freeze_time(NOW) as clock:
        for minute in (10, 20, 30):
            clock.move_to(f"2026-01-01 12:{minute}:05")
            ha_fetch_scheduler.fetch_due_results(db, config)
        clock.tick(timedelta(minutes=30))
        stats = ha_fetch_scheduler.fetch_due_results(db, config)

    assert not stats and call.call_count == 3
    assert _row(db, submission_id)[:4] == ("pending", None, 3, None)
    # the daily activity_scanner run queries the hash again instead of caching the 404
    info = json.loads(db.execute("SELECT sandbox_info FROM content WHERE id = ?", (content_id,)).fetchone()[0])
    assert info["hybrid_analysis"]["stale"] is True


def test_scheduled_fetch_found_marks_submission_done(http_mock, config, db):
    content_id, submission_id = _submission(db, fetch_attempts=1, next_fetch_at="2026-01-01T12:20:00+00:00")
    mock_ha_overview(http_mock, config, status=200)

    with freeze_time("2026-01-01 12:20:01"):
        stats = ha_fetch_scheduler.fetch_due_results(db, config)

    assert stats == {"found": 1}
    assert _row(db, submission_id) == ("done", "malicious", 2, None, "2026-01-01T12:20:01+00:00")
    info = json.loads(db.execute("SELECT sandbox_info FROM content WHERE id = ?", (content_id,)).fetchone()[0])
    assert info["hybrid_analysis"]["tested"] is True


def test_scheduled_fetch_skipped_by_rate_limit_still_uses_its_slot(http_mock, config, db):
    _, submission_id = _submission(db)
    call = mock_ha_overview(http_mock, config, status=429, headers={"Retry-After": "3600"})

    with freeze_time(NOW) as clock:
        clock.move_to("2026-01-01 12:10:00")
        assert ha_fetch_scheduler.fetch_due_results(db, config) == {"failed": 1}
        clock.move_to("2026-01-01 12:20:00")
        assert ha_fetch_scheduler.fetch_due_results(db, config) == {"skipped": 1}

    assert call.call_count == 1
    assert _row(db, submission_id)[2:4] == (2, "2026-01-01T12:30:00+00:00")


def test_daily_run_fetches_submission_after_schedule_ended(http_mock, config, db):
    _, submission_id = _submission(db, fetch_attempts=3, next_fetch_at=None)
    mock_ha_overview(http_mock, config, status=200)

    with freeze_time("2026-01-02 12:05:00"):
        assert ha_fetch_scheduler.fetch_unfinished_results(db, config) == {"found": 1}

    assert _row(db, submission_id)[:2] == ("done", "malicious")


def test_daily_run_skips_submission_already_checked_in_this_run(http_mock, config, db):
    content_id, _ = _submission(db, fetch_attempts=3, next_fetch_at=None)
    db.execute("UPDATE content SET sandbox_info = ? WHERE id = ?",
               (json.dumps({"hybrid_analysis": {"http_status": 404, "checked_at": "2026-01-02T12:06:00+00:00"}}),
                content_id))
    call = mock_ha_overview(http_mock, config, status=404)

    assert not ha_fetch_scheduler.fetch_unfinished_results(db, config, checked_since="2026-01-02T12:05:00+00:00")
    assert call.call_count == 0


def test_scheduled_fetches_are_split_between_evaluator_and_activity_scanner(http_mock, config, db):
    _, web_id = _submission(db)
    auto_content = insert_content(db, b"other payload", sha256="b" * 64)
    auto_id = insert_sandbox_submission(db, auto_content, "b" * 64, submitted_by=hybrid_analysis.EVALUATOR_SUBMITTER,
                                        next_fetch_at="2026-01-01T12:10:00+00:00")
    mock_ha_overview(http_mock, config, status=404)

    with freeze_time("2026-01-01 12:10:30"):
        assert ha_fetch_scheduler.fetch_due_results(db, config, by_evaluator=False) == {"not_ready": 1}
        assert (_row(db, web_id)[2], _row(db, auto_id)[2]) == (1, 0)
        assert ha_fetch_scheduler.fetch_due_results(db, config, by_evaluator=True) == {"not_ready": 1}
        assert (_row(db, web_id)[2], _row(db, auto_id)[2]) == (1, 1)


def test_report_classifies_unclassified_url_of_web_ui_submission(http_mock, config, db):
    url = insert_url(db, evaluated="yes")
    content_id, _ = _submission(db)
    insert_download(db, url, content_id)
    mock_ha_overview(http_mock, config, status=200)

    with freeze_time("2026-01-01 12:10:05"):
        assert ha_fetch_scheduler.fetch_due_results(db, config) == {"found": 1}

    assert db.execute("SELECT classification, classification_reason, threat_label FROM urls").fetchone() == (
        "malicious", "Hybrid Analysis check", "Linux.Mirai")
    assert db.execute("SELECT url, actor FROM classification_history").fetchall() == [(url, "hybrid-analysis")]


def test_report_marks_unclassified_source_urls_malicious(http_mock, config, db):
    src_url = insert_url(db, "http://evil.test/", evaluated="yes")
    url = insert_url(db, evaluated="yes")
    insert_discovered(db, url, src_url)
    content_id, submission_id = _submission(db, submitted_by=hybrid_analysis.EVALUATOR_SUBMITTER)
    insert_download(db, url, content_id)
    mock_ha_overview(http_mock, config, status=200)

    with freeze_time("2026-01-01 12:10:05"):
        assert ha_fetch_scheduler.fetch_due_results(db, config) == {"found": 1}

    assert db.execute("SELECT classification FROM urls WHERE url = ?", (url,)).fetchone() == ("malicious",)
    assert db.execute("SELECT classification FROM urls WHERE url = ?", (src_url,)).fetchone() == ("malicious",)
    assert _row(db, submission_id)[:2] == ("done", "malicious")


def test_report_never_changes_classified_urls(http_mock, config, db):
    src_url = insert_url(db, "http://evil.test/", evaluated="yes", classification="harmless")
    url = insert_url(db, evaluated="yes", classification="harmless", classification_reason="manual review")
    insert_discovered(db, url, src_url)
    content_id, submission_id = _submission(db, fetch_attempts=3, next_fetch_at=None)
    insert_download(db, url, content_id)
    mock_ha_overview(http_mock, config, status=200)

    assert ha_fetch_scheduler.fetch_unfinished_results(db, config) == {"found": 1}

    assert db.execute("SELECT classification, classification_reason FROM urls WHERE url = ?", (url,)).fetchone() == (
        "harmless", "manual review")
    assert db.execute("SELECT classification FROM urls WHERE url = ?", (src_url,)).fetchone() == ("harmless",)
    assert db.execute("SELECT COUNT(*) FROM classification_history").fetchone()[0] == 0
    assert _row(db, submission_id)[0] == "done"


def test_report_found_by_regular_lookup_classifies_unclassified_url(http_mock, config, db):
    url = insert_url(db, evaluated="yes")
    content_id, submission_id = _submission(db)
    insert_download(db, url, content_id)
    mock_ha_overview(http_mock, config, status=200)

    # e.g. activity_scanner re-downloads the URL before the scheduled fetch
    hybrid_analysis.check_content_outcome(db, config, content_id, SHA256, force=True)

    assert db.execute("SELECT classification FROM urls").fetchone() == ("malicious",)
    assert _row(db, submission_id)[0] == "done"


def test_url_not_evaluated_yet_is_left_to_evaluator(http_mock, config, db):
    insert_url(db, evaluated="no")
    content_id, _ = _submission(db)
    insert_download(db, "http://evil.test/a.sh", content_id)
    mock_ha_overview(http_mock, config, status=200)

    with freeze_time("2026-01-01 12:10:05"):
        ha_fetch_scheduler.fetch_due_results(db, config)

    assert db.execute("SELECT classification FROM urls").fetchone() == ("unclassified",)


def test_fetch_job_skips_tick_while_previous_poll_runs(http_mock, config, db):
    _submission(db)
    call = mock_ha_overview(http_mock, config, status=404)
    job = ha_fetch_scheduler.FetchJob(config)

    with freeze_time("2026-01-01 12:10:05"):
        job._lock.acquire()
        job.run()
        job._lock.release()
        assert call.call_count == 0
        job.run()

    assert call.call_count == 1


def test_fetch_raising_still_uses_its_slot(http_mock, config, db, monkeypatch):
    _, submission_id = _submission(db)

    def broken(*args, **kwargs):
        raise RuntimeError("DB is locked")
    monkeypatch.setattr(hybrid_analysis, "check_content_outcome", broken)

    with freeze_time("2026-01-01 12:10:05"):
        assert ha_fetch_scheduler.fetch_due_results(db, config) == {"failed": 1}

    assert _row(db, submission_id)[2:4] == (1, "2026-01-01T12:20:00+00:00")
