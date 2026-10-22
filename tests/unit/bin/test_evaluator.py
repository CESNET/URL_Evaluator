import hashlib
from datetime import datetime, timezone

import pytest
from freezegun import freeze_time

from tests.api_mocks import load_bytes, mock_external_apis, mock_ha_overview, mock_vt
from tests.factories import insert_content, insert_discovered, insert_download, insert_sandbox_submission, insert_url

URL = "http://evil.test/a.sh"
SCRIPT = load_bytes("samples", "dropper.sh")


def serve(http_mock, url=URL, body=SCRIPT, content_type="application/x-sh", **kwargs):
    """The suspicious URL itself returns `body` (unit tests mock it with responses)."""
    return http_mock.get(url, body=body, content_type=content_type, **kwargs)


@pytest.mark.parametrize("stats, expected", [
    ({"malicious": 3, "harmless": 7}, "malicious"),      # 30 % > 20 %
    ({"malicious": 1, "harmless": 9}, "harmless"),       # 90 % > 80 %
    ({"malicious": 1, "harmless": 4, "undetected": 5}, "unclassified"),
    ({}, "unclassified"),
])
def test_vt_stats_analysis(evaluator_mod, stats, expected):
    assert evaluator_mod.vt_stats_analysis(stats) == expected


def test_invalid_url(evaluator_mod, http_mock):
    result = evaluator_mod.evaluate_url("evil.test/no-scheme")
    assert result["classification"] == "invalid" and result["classification_reason"] == "Invalid format"
    assert len(http_mock.calls) == 0


def test_blacklisted_url_is_malicious_and_content_is_stored(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config, blacklist=[URL])

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("malicious", "Blacklist check")
    # content is downloaded and stored even when the blacklist decides
    sha256 = hashlib.sha256(SCRIPT).hexdigest()
    assert db.execute("SELECT sha256, file_category FROM content").fetchone() == (sha256, "script")
    assert db.execute("SELECT source_ip, status_code, change_type FROM download_observations").fetchone() == (
        "192.0.2.1", 200, "initial")


def test_known_hash_on_malwarebazaar(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config, mb_known=True)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("malicious", "MB file check")
    assert apis["vt_url"].call_count == 0  # MalwareBazaar answered first


def test_malicious_on_virustotal_url_check(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config, vt_url="url_malicious.json")

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("malicious", "VT URL check")
    assert result["threat_label"] == "trojan.mirai/gafgyt"
    assert '"malicious": 12' in result["vt_stats"]


def test_harmless_on_virustotal_file_check(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config, vt_file="file_harmless.json")

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("harmless", "VT file check")
    assert result["hash"] == hashlib.sha1(SCRIPT).hexdigest()
    assert result["file_mime_type"] == "application/x-sh"


def test_unknown_everywhere(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "No entry")
    assert result["evaluated"] == "yes"


def test_vt_daily_quota_postpones_evaluation(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config, vt_url="quota_exceeded.json")

    result = evaluator_mod.evaluate_url(URL)

    assert (result["evaluated"], result["eval_later"]) == ("no", "yes")
    assert evaluator_mod.vt_daily_quota_exceeded is True


def test_vt_minute_quota_waits(evaluator_mod, http_mock, no_sleep):
    mock_vt(http_mock, "urls")
    evaluator_mod.vt_minute_quota_cnt = evaluator_mod.vt_minute_quota
    evaluator_mod.vt_minute_quota_timestamp = datetime.now(timezone.utc)

    evaluator_mod.vt_request("URL", "id")

    assert len(no_sleep) == 1 and 55 < no_sleep[0] <= 60
    assert evaluator_mod.vt_minute_quota_cnt == 1


def test_unreachable_url(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    # URL itself is not registered -> responses raises ConnectionError
    mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unreachable", "Connection error")


def test_nested_urls_from_shell_script_are_added(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config)

    evaluator_mod.evaluate_url(URL)

    assert db.execute("SELECT url, src_url FROM discovered_urls").fetchall() == [("http://evil.test/bins/x86", URL)]
    assert db.execute("SELECT source FROM url_source WHERE url = 'http://evil.test/bins/x86'").fetchone() == ("URL content",)


@pytest.mark.xfail(strict=True, reason="BUG: README lists 'File too large', but evaluate_url() reports an "
                                       "oversized download as 'No entry' (analyze_content returns {} for it)")
def test_too_large_content(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, headers={"Content-Length": str(2 * 1024 * 1024)})  # max_file_size is 1 MB in tests
    mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(URL)

    assert result["classification_reason"] == "File too large"


# --- Hybrid Analysis submission of still unclassified executables / scripts ---

def test_unclassified_script_is_submitted_to_hybrid_analysis(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)

    with freeze_time("2026-01-01 12:00:00"):
        result = evaluator_mod.evaluate_url(URL)

    assert result["classification"] == "unclassified"
    assert apis["ha_submit"].call_count == 1
    # the report is fetched 10, 20 and 30 min after the submission
    assert db.execute("SELECT submitted_by, status, next_fetch_at FROM sandbox_submissions").fetchone() == (
        "evaluator", "pending", "2026-01-01T12:10:00+00:00")


@pytest.mark.parametrize("body, content_type", [
    (b"<html><body>It works!</body></html>", "text/html"),
    (b'{"status": "ok"}', "application/json"),
])
def test_unclassified_other_content_is_not_submitted(evaluator_mod, http_mock, config, db, body, content_type):
    insert_url(db, URL)
    serve(http_mock, body=body, content_type=content_type)
    apis = mock_external_apis(http_mock, config)

    assert evaluator_mod.evaluate_url(URL)["classification"] == "unclassified"
    assert apis["ha_submit"].call_count == 0
    assert db.execute("SELECT COUNT(*) FROM sandbox_submissions").fetchone()[0] == 0


@pytest.mark.parametrize("vt_url", ["url_malicious.json", "quota_exceeded.json"])
def test_classified_or_postponed_url_is_not_submitted(evaluator_mod, http_mock, config, db, vt_url):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config, vt_url=vt_url)

    evaluator_mod.evaluate_url(URL)

    assert apis["ha_submit"].call_count == 0


def test_unclassified_script_already_analysed_is_classified_by_its_report(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config, ha_status=200)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"], result["threat_label"]) == (
        "malicious", "Hybrid Analysis check", "Linux.Mirai")
    assert apis["ha_submit"].call_count == 0


def test_scheduled_fetch_of_evaluator_submission_classifies_url(evaluator_mod, http_mock, config, db):
    src_url = insert_url(db, "http://evil.test/", evaluated="yes")
    insert_url(db, URL, evaluated="yes")
    insert_discovered(db, URL, src_url)
    content_id = insert_content(db, SCRIPT)
    insert_download(db, URL, content_id)
    insert_sandbox_submission(db, content_id, hashlib.sha256(SCRIPT).hexdigest(), submitted_by="evaluator",
                              next_fetch_at="2026-01-01T12:10:00+00:00")
    mock_ha_overview(http_mock, config, status=200)

    with freeze_time("2026-01-01 12:10:05"):
        evaluator_mod.fetch_job.run()

    assert db.execute("SELECT classification, classification_reason, threat_label FROM urls WHERE url = ?",
                      (URL,)).fetchone() == ("malicious", "Hybrid Analysis check", "Linux.Mirai")
    assert db.execute("SELECT classification FROM urls WHERE url = ?", (src_url,)).fetchone() == ("malicious",)
    assert db.execute("SELECT url, actor FROM classification_history ORDER BY id").fetchall() == [
        (URL, "hybrid-analysis"), (src_url, "hybrid-analysis-backprop")]
    assert db.execute("SELECT status, verdict FROM sandbox_submissions").fetchone() == ("done", "malicious")
