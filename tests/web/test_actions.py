"""Mutating routes of the web UI (edit, bulk edit, sample download, sandbox submission) and the JSON API."""

import pytest

from tests.api_mocks import mock_ha_overview, mock_ha_submit
from tests.factories import (insert_content, insert_discovered, insert_download, insert_sandbox_submission,
                             insert_source, insert_url)

ANALYST = {"REMOTE_USER": "alice"}
URL = "http://evil.test/a.sh"


def row(db, url=URL, columns="classification, classification_reason, note, last_edit, evaluated"):
    return db.execute(f"SELECT {columns} FROM urls WHERE url = ?", (url,)).fetchone()


def history(db):
    return db.execute("SELECT url, classification, reason, note, actor FROM classification_history ORDER BY id").fetchall()


# --- /edit_detail ---

@pytest.mark.parametrize("method", ["get", "post"])
def test_anonymous_user_cannot_edit(web_client, db, method):
    insert_url(db, URL)

    response = getattr(web_client, method)("/edit_detail", query_string={"url": URL},
                                           data={"note": "x", "class": "harmless", "reason": "x"})

    assert response.status_code == 403
    assert row(db)[0] == "unclassified" and history(db) == []


def test_edit_form_shows_url(web_client, db):
    insert_url(db, URL)

    response = web_client.get("/edit_detail", query_string={"url": URL}, environ_base=ANALYST)

    assert response.status_code == 200 and f"Edit {URL}" in response.get_data(as_text=True)


def test_analyst_classifies_url_malicious(web_client, db):
    src = insert_url(db, "http://loader.test/")
    insert_url(db, URL)
    insert_discovered(db, URL, src)

    response = web_client.post("/edit_detail", query_string={"url": URL, "show": "malicious"}, environ_base=ANALYST,
                               data={"note": "seen in sandbox", "class": "malicious", "reason": "Manual check"})

    assert response.status_code == 302 and response.location.endswith("/?show=malicious")
    assert row(db) == ("malicious", "Manual check", "seen in sandbox", "alice", "yes")
    assert row(db, src)[:2] == ("malicious", "Downloading from malicious URL")
    assert history(db) == [(URL, "malicious", "Manual check", "seen in sandbox", "alice"),
                           (src, "malicious", "Downloading from malicious URL", None, "alice-backprop")]


def test_unclassified_by_analyst_goes_back_to_evaluation(web_client, db):
    insert_url(db, URL, classification="harmless", evaluated="yes")

    web_client.post("/edit_detail", query_string={"url": URL}, environ_base=ANALYST,
                    data={"note": "", "class": "unclassified", "reason": "re-check"})

    assert row(db)[0] == "unclassified" and row(db)[4] == "no"


def test_edit_of_unknown_url_is_404(web_client, db):
    response = web_client.get("/edit_detail", query_string={"url": "http://unknown.test/"}, environ_base=ANALYST)

    assert response.status_code == 404


def test_edit_with_unknown_classification_is_rejected(web_client, db):
    insert_url(db, URL)

    response = web_client.post("/edit_detail", query_string={"url": URL}, environ_base=ANALYST,
                               data={"note": "", "class": "dangerous", "reason": "x"})

    assert response.status_code == 400 and row(db)[0] == "unclassified" and history(db) == []


# --- /bulk_edit, /bulk_edit_action ---

def test_bulk_edit_form_lists_selected_urls(web_client, db):
    response = web_client.post("/bulk_edit", data={"selected_urls_list[]": [URL, "http://other.test/"]},
                               environ_base=ANALYST)

    page = response.get_data(as_text=True)
    assert response.status_code == 200 and URL in page and "http://other.test/" in page


def test_anonymous_user_cannot_bulk_reevaluate(web_client, db):
    insert_url(db, URL, evaluated="yes")

    response = web_client.post("/bulk_edit", data={"action": "reevaluate", "selected_urls_list[]": [URL]})

    assert response.status_code == 403 and row(db)[4] == "yes"


def test_analyst_bulk_reevaluates_urls(web_client, db):
    urls = [insert_url(db, f"http://evil.test/{i}", evaluated="yes") for i in range(3)]

    response = web_client.post("/bulk_edit", data={"action": "reevaluate", "selected_urls_list[]": urls[:2]},
                               environ_base=ANALYST)

    assert response.status_code == 302
    assert [row(db, u)[4] for u in urls] == ["no", "no", "yes"]


def test_anonymous_user_cannot_bulk_edit(web_client, db):
    insert_url(db, URL)

    response = web_client.post("/bulk_edit_action", data={"selected_urls_list[]": [URL], "note": "",
                                                          "class": "malicious", "reason": ""})

    assert response.status_code == 403 and row(db)[0] == "unclassified"


def test_analyst_bulk_classifies_urls(web_client, db):
    src = insert_url(db, "http://loader.test/")
    urls = [insert_url(db, f"http://evil.test/{i}") for i in range(2)]
    insert_discovered(db, urls[0], src)

    web_client.post("/bulk_edit_action", environ_base=ANALYST, data={
        "selected_urls_list[]": urls, "note": "campaign X", "class": "malicious", "reason": "Manual check"})

    for url in urls:
        assert row(db, url) == ("malicious", "Manual check", "campaign X", "alice", "yes")
    assert row(db, src)[0] == "malicious"
    assert [(h[0], h[4]) for h in history(db)] == [(urls[0], "alice"), (urls[1], "alice"), (src, "alice-backprop")]


def test_bulk_edit_of_reason_only_keeps_classification(web_client, db):
    insert_url(db, URL, classification="harmless", evaluated="yes")

    web_client.post("/bulk_edit_action", environ_base=ANALYST, data={
        "selected_urls_list[]": [URL], "note": "", "class": "", "reason": "false positive"})

    assert row(db)[:2] == ("harmless", "false positive")


def test_bulk_edit_of_note_only_is_recorded_in_history(web_client, db):
    insert_url(db, URL, classification="harmless", evaluated="yes")

    web_client.post("/bulk_edit_action", environ_base=ANALYST, data={
        "selected_urls_list[]": [URL], "note": "checked again", "class": "", "reason": ""})

    assert [(h[0], h[3], h[4]) for h in history(db)] == [(URL, "checked again", "alice")]


def test_bulk_reevaluate_url_with_quote(web_client, db):
    url = insert_url(db, "http://evil.test/it's.sh", evaluated="yes")

    response = web_client.post("/bulk_edit", data={"action": "reevaluate", "selected_urls_list[]": [url]},
                               environ_base=ANALYST)

    assert response.status_code == 302 and row(db, url)[4] == "no"


# --- /api/url_stats ---

def test_api_url_stats(web_client, db):
    insert_url(db, URL, classification="malicious", classification_reason="Blacklist check", threat_label="mirai")
    insert_source(db, URL, "Warden")
    insert_source(db, URL, "Manual")

    response = web_client.get("/api/url_stats", query_string={"url": URL})

    assert response.status_code == 200
    data = response.get_json()
    assert (data["url"], data["classification"], data["threat_label"]) == (URL, "malicious", "mirai")
    assert sorted(data["src"].split(", ")) == ["Manual", "Warden"]


def test_api_url_stats_unknown_url(web_client):
    response = web_client.get("/api/url_stats", query_string={"url": "http://missing.test/"})
    assert response.status_code == 404 and response.get_json() == {"error": "Not found"}


# --- /content/download/<id> ---

def test_download_stored_sample_as_attachment(web_client, db, content_dir):
    content_id = insert_content(db, b"#!/bin/sh\necho hi\n", content_dir=content_dir)
    sha256 = db.execute("SELECT sha256 FROM content").fetchone()[0]

    response = web_client.get(f"/content/download/{content_id}")

    assert response.status_code == 200 and response.data == b"#!/bin/sh\necho hi\n"
    assert response.headers["Content-Disposition"] == f"attachment; filename={sha256[:24]}.bin"
    assert response.mimetype == "application/x-sh"


def test_download_unknown_sample_is_404(web_client):
    assert web_client.get("/content/download/999").status_code == 404


def test_download_never_serves_files_outside_content_dir(web_client, db, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("not a sample")
    content_id = insert_content(db, b"x", file_path=str(secret))  # tampered file_path

    assert web_client.get(f"/content/download/{content_id}").status_code == 404


def test_download_of_purged_file_is_404(web_client, db, content_dir):
    content_id = insert_content(db, b"x", file_path=f"{content_dir}/ab/cd/missing")

    assert web_client.get(f"/content/download/{content_id}").status_code == 404


# --- /sandbox/submit/<id> ---

@pytest.fixture
def stored_sample(db, content_dir):
    insert_url(db, URL)
    content_id = insert_content(db, b"#!/bin/sh\necho hi\n", content_dir=content_dir)
    insert_download(db, URL, content_id)
    return content_id, db.execute("SELECT sha256 FROM content").fetchone()[0]


def submit(web_client, content_id, environ=ANALYST, environment_id="330", follow_redirects=False):
    return web_client.post(f"/sandbox/submit/{content_id}", environ_base=environ, follow_redirects=follow_redirects,
                           data={"url": URL, "show": "", "environment_id": environment_id})


def test_anonymous_user_cannot_submit_sample(web_client, http_mock, stored_sample):
    assert submit(web_client, stored_sample[0], environ={}).status_code == 403
    assert len(http_mock.calls) == 0


def test_analyst_submits_sample(web_client, http_mock, config, db, stored_sample):
    content_id, sha256 = stored_sample
    mock_ha_overview(http_mock, config, status=404)
    mock_ha_submit(http_mock, config)

    response = submit(web_client, content_id)

    assert response.status_code == 302 and "tab=sandbox" in response.location
    assert db.execute("SELECT content_id, sha256, submitted_by, status FROM sandbox_submissions").fetchone() == (
        content_id, sha256, "alice", "pending")
    page = web_client.get(response.location, environ_base=ANALYST).get_data(as_text=True)
    assert "Sample submitted to Hybrid Analysis" in page and "waiting for report" in page


def test_unknown_environment_is_rejected(web_client, http_mock, stored_sample):
    assert submit(web_client, stored_sample[0], environment_id="999").status_code == 400
    assert submit(web_client, stored_sample[0], environment_id="windows").status_code == 400
    assert len(http_mock.calls) == 0


def test_submit_of_unknown_or_missing_sample_is_404(web_client, db, http_mock):
    assert submit(web_client, 999).status_code == 404
    content_id = insert_content(db, b"x")  # file_path outside content_dir
    assert submit(web_client, content_id).status_code == 404


def test_already_analysed_sample_is_not_submitted(web_client, http_mock, config, db, stored_sample):
    mock_ha_overview(http_mock, config, status=200)
    call = mock_ha_submit(http_mock, config)

    page = submit(web_client, stored_sample[0], follow_redirects=True).get_data(as_text=True)

    assert "Hybrid Analysis already knows this hash" in page
    assert call.call_count == 0


def test_already_submitted_sample_is_not_submitted_again(web_client, http_mock, db, stored_sample):
    insert_sandbox_submission(db, *stored_sample, submitted_by="bob")

    page = submit(web_client, stored_sample[0], follow_redirects=True).get_data(as_text=True)

    assert "already been submitted" in page and len(http_mock.calls) == 0


def test_rejected_submission_shows_api_error(web_client, http_mock, config, stored_sample):
    mock_ha_overview(http_mock, config, status=404)
    http_mock.post(f"{config.ha_url}/submit/file", status=400, json={"message": "File type not supported"})

    page = submit(web_client, stored_sample[0], follow_redirects=True).get_data(as_text=True)

    assert "Hybrid Analysis rejected the submission: File type not supported" in page


def test_submit_with_hybrid_analysis_disabled(make_config, monkeypatch, fake_misp, http_mock, db, content_dir):
    import importlib
    import sys

    import pymisp
    config = make_config(ha_key="")
    monkeypatch.setenv("URL_EVALUATOR_CONFIG", config._test_path)
    monkeypatch.setattr(pymisp, "PyMISP", lambda *args, **kwargs: fake_misp)
    sys.modules.pop("web.main", None)
    client = importlib.import_module("web.main").app.test_client()
    insert_url(db, URL)
    content_id = insert_content(db, b"x", content_dir=content_dir)

    try:
        page = submit(client, content_id, follow_redirects=True).get_data(as_text=True)
    finally:
        sys.modules.pop("web.main", None)

    assert "Hybrid Analysis API is disabled" in page and len(http_mock.calls) == 0


def test_bulk_edit_of_note_keeps_url_waiting_for_evaluation(web_client, db):
    insert_url(db, URL, evaluated="no")

    web_client.post("/bulk_edit_action", environ_base=ANALYST, data={
        "selected_urls_list[]": [URL], "note": "checked", "class": "", "reason": ""})

    assert row(db)[2:] == ("checked", "alice", "no")


def test_bulk_classify_url_with_quote_and_its_source(web_client, db):
    src = insert_url(db, "http://loader.test/it's.sh")
    url = insert_url(db, "http://evil.test/it's.sh")
    insert_discovered(db, url, src)

    response = web_client.post("/bulk_edit_action", environ_base=ANALYST, data={
        "selected_urls_list[]": [url], "note": "", "class": "malicious", "reason": "Manual check"})

    assert response.status_code == 302
    assert row(db, url)[0] == "malicious" and row(db, src)[0] == "malicious"
