import hashlib
import json

import pytest

from tests.factories import (insert_classification, insert_content, insert_discovered, insert_download,
                             insert_observation, insert_sandbox_submission, insert_source, insert_url)

ANALYST = {"REMOTE_USER": "alice"}
URL = "http://evil.test/a.sh"


def test_unknown_url_is_404(web_client):
    response = web_client.get("/detail", query_string={"url": "http://missing.test/"})
    assert response.status_code == 404


def test_shows_url_detail(web_client, db):
    insert_url(db, URL, classification="malicious", classification_reason="VT URL check", threat_label="mirai")

    response = web_client.get("/detail", query_string={"url": URL})

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert URL in page and "VT URL check" in page and "mirai" in page


def test_classification_history_hides_analyst_names_from_anonymous(web_client, db):
    insert_url(db, URL)
    insert_classification(db, URL, "harmless", reason="manual review", actor="alice (Alice Analyst)")
    insert_classification(db, URL, "malicious", reason="Blacklist check", actor="evaluator")

    anonymous = web_client.get("/detail", query_string={"url": URL, "tab": "class_history"}).get_data(as_text=True)
    analyst = web_client.get("/detail", query_string={"url": URL, "tab": "class_history"},
                             environ_base=ANALYST).get_data(as_text=True)

    assert "Alice Analyst" not in anonymous and "evaluator" in anonymous
    assert "Alice Analyst" in analyst


def test_classification_history_shows_hybrid_analysis_to_anonymous(web_client, db):
    insert_url(db, URL)
    insert_classification(db, URL, "malicious", reason="Hybrid Analysis check", actor="hybrid-analysis")

    anonymous = web_client.get("/detail", query_string={"url": URL, "tab": "class_history"}).get_data(as_text=True)

    assert "hybrid-analysis" in anonymous


def test_overview_shows_most_reported_source_with_link_to_sources_tab(web_client, db):
    insert_url(db, URL)
    insert_observation(db, URL, honeynet="honeynet-a")
    insert_observation(db, URL, honeynet="honeynet-b", observed_at="2026-01-02T12:00:00+00:00")
    insert_observation(db, URL, honeynet="honeynet-b", observed_at="2026-01-03T12:00:00+00:00")

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)

    assert "Most reported source</td>" in page
    assert "<td>honeynet-b, see details in" in page and "honeynet-a" not in page
    assert "tab=sources" in page and "see details in" in page and "sources tab</a>" in page


def test_overview_source_falls_back_to_url_sources_without_observations(web_client, db):
    insert_url(db, URL)
    insert_source(db, URL, "Manual")

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)

    assert "<td>Manual, see details in" in page


def test_overview_shows_inactive_since(web_client, db):
    insert_url(db, URL, status="inactive", last_active="2026-10-20")
    insert_url(db, "http://never.test/", status="inactive", last_active=None)

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)
    never = web_client.get("/detail", query_string={"url": "http://never.test/"}).get_data(as_text=True)

    assert "URL is inactive since</td>" in page and "<td>2026-10-20</td>" in page
    assert "<td>never seen active</td>" in never


def test_anonymous_user_cannot_reevaluate(web_client, db):
    insert_url(db, URL, evaluated="yes")

    response = web_client.post("/detail", query_string={"url": URL})

    assert response.status_code == 403
    assert db.execute("SELECT evaluated FROM urls").fetchone() == ("yes",)


def test_analyst_reevaluates_url(web_client, db):
    insert_url(db, URL, evaluated="yes")

    response = web_client.post("/detail", query_string={"url": URL}, environ_base=ANALYST)

    assert response.status_code == 302
    assert db.execute("SELECT evaluated FROM urls").fetchone() == ("no",)


def test_content_tab_explains_missing_content(web_client, db):
    insert_url(db, URL)
    insert_download(db, URL, status_code=None, response_headers=None, fetch_error="timeout")

    page = web_client.get("/detail", query_string={"url": URL, "tab": "content"}).get_data(as_text=True)

    assert "Connection timed out" in page and "no content" in page
    assert "confirmed identical" not in page and "Downloaded from" not in page


def test_content_tab_links_stored_content(web_client, db):
    insert_url(db, URL)
    insert_download(db, URL, insert_content(db, b"payload"))

    page = web_client.get("/detail", query_string={"url": URL, "tab": "content"}).get_data(as_text=True)

    assert "confirmed identical" in page and "download-link" in page and "Result" not in page


def history(db, user="alice"):
    return [r[0] for r in db.execute("SELECT url FROM user_url_history WHERE user = ? "
                                     "ORDER BY visited_at DESC", (user,)).fetchall()]


def test_detail_visit_is_recorded_for_logged_in_user_only(web_client, db):
    insert_url(db, URL)

    web_client.get("/detail", query_string={"url": URL}, environ_base=ANALYST)
    web_client.get("/detail", query_string={"url": URL})  # anonymous
    web_client.get("/detail", query_string={"url": "http://missing.test/"}, environ_base=ANALYST)

    assert db.execute("SELECT user, url FROM user_url_history").fetchall() == [("alice", URL)]


def test_user_url_history_keeps_last_10_distinct_urls(web_client, db):
    urls = [insert_url(db, f"http://evil.test/{i}.sh") for i in range(12)]

    for url in urls:
        web_client.get("/detail", query_string={"url": url}, environ_base=ANALYST)
    web_client.get("/detail", query_string={"url": urls[5]}, environ_base=ANALYST)  # revisit moves it to the top

    assert history(db) == [urls[5]] + [urls[i] for i in (11, 10, 9, 8, 7, 6, 4, 3, 2)]


def test_user_url_history_is_deleted_with_the_url(web_client, db):
    insert_url(db, URL)
    web_client.get("/detail", query_string={"url": URL}, environ_base=ANALYST)

    db.execute("DELETE FROM urls WHERE url = ?", (URL,))

    assert history(db) == []


def test_header_lists_recently_visited_urls(web_client, db):
    other = insert_url(db, "http://other.test/b.sh")
    insert_url(db, URL)
    web_client.get("/detail", query_string={"url": URL}, environ_base=ANALYST)

    analyst = web_client.get("/detail", query_string={"url": other}, environ_base=ANALYST).get_data(as_text=True)
    anonymous = web_client.get("/detail", query_string={"url": other}).get_data(as_text=True)

    assert "Recent displayed URLs (2)" in analyst
    assert analyst.index(">http://other.test/b.sh</a>") < analyst.index(f">{URL}</a>")  # newest first
    assert "recent-urls" not in anonymous


def test_sandbox_tab_shows_scheduled_result_fetch(web_client, db):
    insert_url(db, URL)
    content_id = insert_content(db)
    sha256 = db.execute("SELECT sha256 FROM content WHERE id = ?", (content_id,)).fetchone()[0]
    insert_download(db, URL, content_id=content_id)
    insert_sandbox_submission(db, content_id, sha256, fetch_attempts=1, next_fetch_at="2026-01-01T12:20:00+00:00",
                              last_fetch_at="2026-01-01T12:10:00+00:00")

    page = web_client.get("/detail", query_string={"url": URL, "tab": "sandbox"}).get_data(as_text=True)

    assert "waiting for report" in page
    assert "scheduled fetch 2/3" in page and "2026-01-01 12:20:00 UTC" in page


def test_sandbox_tab_hands_over_to_daily_run_after_last_fetch(web_client, db):
    insert_url(db, URL)
    content_id = insert_content(db)
    sha256 = db.execute("SELECT sha256 FROM content WHERE id = ?", (content_id,)).fetchone()[0]
    insert_download(db, URL, content_id=content_id)
    insert_sandbox_submission(db, content_id, sha256, fetch_attempts=3, next_fetch_at=None,
                              last_fetch_at="2026-01-01T12:30:00+00:00")

    page = web_client.get("/detail", query_string={"url": URL, "tab": "sandbox"}).get_data(as_text=True)

    assert "No report after the 3 scheduled fetches" in page and "next daily activity scan" in page


# --- Sandbox tab: lookup result and manual submission form ---

def sandbox_content(db, content_dir, lookup=None, data=b"#!/bin/sh\necho hi\n"):
    insert_url(db, URL)
    sandbox_info = json.dumps({"hybrid_analysis": lookup}) if lookup else None
    content_id = insert_content(db, data, content_dir=content_dir, sandbox_info=sandbox_info)
    insert_download(db, URL, content_id)
    return content_id, db.execute("SELECT sha256 FROM content WHERE id = ?", (content_id,)).fetchone()[0]


def sandbox_page(web_client, environ=None):
    return web_client.get("/detail", query_string={"url": URL, "tab": "sandbox"},
                          environ_base=environ or {}).get_data(as_text=True)


NOT_ANALYSED = {"http_status": 404, "tested": False, "checked_at": "2026-01-01T12:00:00+00:00"}


def test_analyst_can_submit_sample_never_analysed(web_client, db, content_dir):
    content_id, _ = sandbox_content(db, content_dir, NOT_ANALYSED)

    page = sandbox_page(web_client, ANALYST)

    assert "not analysed yet" in page and "SHA-256 not known to Hybrid Analysis (HTTP 404)" in page
    assert f'action="/sandbox/submit/{content_id}"' in page
    assert '<option value="330" selected>' in page  # ha_environment_id of the test config


def test_anonymous_user_gets_no_submit_form(web_client, db, content_dir):
    sandbox_content(db, content_dir, NOT_ANALYSED)

    page = sandbox_page(web_client)

    assert "not analysed yet" in page and "/sandbox/submit/" not in page


@pytest.mark.parametrize("case", ["not_looked_up", "already_submitted", "file_purged"])
def test_submit_form_only_when_submission_makes_sense(web_client, db, content_dir, case):
    content_id, sha256 = sandbox_content(db, content_dir, None if case == "not_looked_up" else NOT_ANALYSED)
    if case == "already_submitted":
        insert_sandbox_submission(db, content_id, sha256, submitted_by="bob")
    if case == "file_purged":
        db.execute("UPDATE content SET file_path = '/nonexistent/sample'")

    page = sandbox_page(web_client, ANALYST)

    assert "/sandbox/submit/" not in page


def test_sandbox_tab_shows_found_report(web_client, db, content_dir):
    sha256 = hashlib.sha256(b"#!/bin/sh\necho hi\n").hexdigest()
    lookup = {"http_status": 200, "tested": True, "checked_at": "2026-01-01T12:00:00+00:00",
              "sample_url": f"https://hybrid-analysis.com/sample/{sha256}",
              "overview": {"verdict": "malicious", "vx_family": "Linux.Mirai", "threat_score": 100},
              "reports": [{"job_id": "j1", "environment_id": 330, "environment_description": "Linux (Ubuntu 24.04, 64 bit)",
                           "state": "SUCCESS", "verdict": "malicious"}]}
    sandbox_content(db, content_dir, lookup)

    page = sandbox_page(web_client, ANALYST)

    assert "already analysed" in page and f'href="https://hybrid-analysis.com/sample/{sha256}"' in page
    assert "Linux.Mirai" in page and "Linux (Ubuntu 24.04, 64 bit)" in page
    assert "/sandbox/submit/" not in page


def test_sandbox_tab_shows_failed_recheck_with_previous_answer(web_client, db, content_dir):
    lookup = dict(NOT_ANALYSED, last_error={"checked_at": "2026-01-02T12:00:00+00:00", "http_status": 429,
                                            "error": "API rate limit"})
    sandbox_content(db, content_dir, lookup)

    page = sandbox_page(web_client)

    assert "2026-01-02 12:00:00 UTC &ndash; API rate limit (showing the previous successful result)" in page


def test_submitter_name_is_hidden_from_anonymous(web_client, db, content_dir):
    content_id, sha256 = sandbox_content(db, content_dir, NOT_ANALYSED)
    insert_sandbox_submission(db, content_id, sha256, submitted_by="alice (Alice Analyst)", status="done",
                              verdict="malicious", last_fetch_at="2026-01-01T12:10:00+00:00")

    assert "Alice Analyst" not in sandbox_page(web_client)
    assert "Alice Analyst" in sandbox_page(web_client, ANALYST)


def test_sandbox_tab_without_content(web_client, db):
    insert_url(db, URL)

    assert "nothing to look up in a sandbox" in sandbox_page(web_client)


# --- Overview: external links, derived-from, content tab details ---

@pytest.mark.parametrize("reason, link", [
    ("VT file check", "https://www.virustotal.com/gui/file/da39a3ee"),
    ("VT URL check", "https://www.virustotal.com/gui/url/aHR0cDovL2V2aWwudGVzdC9hLnNo"),
])
def test_reason_links_to_virustotal(web_client, db, reason, link):
    insert_url(db, URL, classification="malicious", classification_reason=reason, hash="da39a3ee")

    assert f'href="{link}"' in web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)


def test_blacklist_reason_links_to_urlhaus(web_client, http_mock, config, db):
    insert_url(db, URL, classification="malicious", classification_reason="Blacklist check")
    call = http_mock.post(config.urlhaus_detail_url, json={"query_status": "ok",
                                                           "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"})

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)

    assert 'href="https://urlhaus.abuse.ch/url/1/"' in page and call.call_count == 1


def test_urlhaus_lookup_failure_does_not_break_detail(web_client, http_mock, db):
    insert_url(db, URL, classification="malicious", classification_reason="Blacklist check")

    assert web_client.get("/detail", query_string={"url": URL}).status_code == 200  # no mock -> ConnectionError


def test_reported_url_links_to_misp_event(web_client, fake_misp, db):
    insert_url(db, URL, classification="malicious", reported="yes")
    fake_misp.search.return_value = [{"Event": {"id": "42"}}]

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)

    assert 'href="https://misp.test/events/view/42"' in page
    assert fake_misp.search.call_args.kwargs["value"] == URL


def test_derived_from_links_to_source_url(web_client, db):
    src = insert_url(db, "http://loader.test/a.sh")
    insert_url(db, URL)
    insert_discovered(db, URL, src)

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)

    assert 'class="derived-link" href="/detail?url=http://loader.test/a.sh"' in page


def test_content_tab_shows_size_type_and_versions(web_client, db, content_dir):
    insert_url(db, URL, last_seen="2026-01-05")
    v1 = insert_content(db, b"x" * 45363, content_dir=content_dir, file_category="script", magika_label="shell",
                        magika_description="Shell script")
    v2 = insert_content(db, b"y")
    insert_download(db, URL, v1, fetched_at="2026-01-01T06:00:00+00:00")
    insert_download(db, URL, v1, fetched_at="2026-01-02T06:00:00+00:00", change_type="confirmed")
    insert_download(db, URL, v2, fetched_at="2026-01-03T06:00:00+00:00", change_type="content_changed")

    page = web_client.get("/detail", query_string={"url": URL, "tab": "content"}).get_data(as_text=True)

    assert "44.3 KB" in page and "Shell script" in page
    assert "2026-01-01 06:00:00 UTC &rarr; 2026-01-02 06:00:00 UTC" in page
    assert page.count("download-link") == 2


# --- Template filters ---

@pytest.mark.parametrize("value, text", [
    (0, "0 B"), (1023, "1023 B"), (45363, "44.3 KB"), (5 * 1024 ** 2, "5.0 MB"), (None, ""), ("abc", ""),
])
def test_human_bytes(web_app, value, text):
    assert web_app.human_bytes(value) == text


@pytest.mark.parametrize("value, with_time, text", [
    ("2026-01-01T12:00:00+00:00", True, "2026-01-01 12:00:00 UTC"),
    ("2026-01-01T12:00:00.123456Z", True, "2026-01-01 12:00:00 UTC"),
    ("2026-01-01 12:00:00", False, "2026-01-01"),
    (None, True, ""),
])
def test_fmt_ts(web_app, value, with_time, text):
    assert web_app.fmt_ts(value, with_time) == text


# --- Local development sign in ---

def test_dev_login_is_disabled_by_default(web_client):
    assert web_client.post("/dev/login", data={"username": "mallory"}).status_code == 404
    assert web_client.post("/dev/logout").status_code == 404


def test_dev_login_signs_in_as_typed_name(web_app, db):
    web_app.app.config["DEV_LOGIN"] = True
    client = web_app.app.test_client()
    insert_url(db, URL)

    assert client.get("/edit_detail", query_string={"url": URL}).status_code == 403
    client.post("/dev/login", data={"username": "dev-alice"})
    assert client.get("/edit_detail", query_string={"url": URL}).status_code == 200
    client.post("/dev/logout")
    assert client.get("/edit_detail", query_string={"url": URL}).status_code == 403


def test_oidc_user_name(web_client, db):
    insert_url(db, URL)
    environ = {"OIDC_CLAIM_preferred_username": "alice",
               "OIDC_CLAIM_name": "Alice Šimková".encode("utf-8").decode("latin1")}

    web_client.get("/detail", query_string={"url": URL}, environ_base=environ)

    assert db.execute("SELECT user FROM user_url_history").fetchone() == ("alice (Alice Šimková)",)


def test_content_range_ends_with_the_last_fetch(web_client, db):
    insert_url(db, URL, last_seen="2026-01-01")
    content_id = insert_content(db)
    insert_download(db, URL, content_id, fetched_at="2026-01-02T04:00:00+00:00")
    insert_download(db, URL, content_id, fetched_at="2026-01-05T04:00:00+00:00")

    page = web_client.get("/detail", query_string={"url": URL, "tab": "content"}).get_data(as_text=True)

    assert '<p class="content-range">2026-01-02 &nbsp;&ndash;&nbsp; 2026-01-05</p>' in page


def test_overview_shows_mime_type_and_size_of_newest_content(web_client, db):
    insert_url(db, URL, file_mime_type="application/x-sh", content_size=99999)
    insert_download(db, URL, insert_content(db, b"x" * 2048), fetched_at="2026-01-01T04:00:00+00:00")
    insert_download(db, URL, insert_content(db, b"y" * 10), fetched_at="2026-01-02T04:00:00+00:00")

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)

    assert "<td>File mime type</td>" in page and "<td>application/x-sh</td>" in page
    assert "<td>10 B, see details in" in page and "99999" not in page


def test_overview_without_content(web_client, db):
    insert_url(db, URL, content_size=1234)

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)

    assert "This URL has no content yet" in page


def test_overview_shows_readable_vt_stats_with_link(web_client, db):
    stats = {"harmless": 0, "malicious": 37, "undetected": 23, "type-unsupported": 16}
    insert_url(db, URL, classification_reason="VT URL check", vt_stats=json.dumps(stats))

    page = web_client.get("/detail", query_string={"url": URL}).get_data(as_text=True)

    vt_row = page[page.index("VirusTotal statistics"):page.index("Reported</td>")]
    assert "37 malicious · 23 undetected · 16 type-unsupported" in vt_row
    assert "https://www.virustotal.com/gui/url/" in vt_row


def test_external_links_open_in_a_new_tab(web_client, db):
    insert_url(db, "http://192.0.2.1/a.sh", classification_reason="VT URL check", hash="ab" * 32)

    page = web_client.get("/detail", query_string={"url": "http://192.0.2.1/a.sh"}).get_data(as_text=True)

    assert "”" not in page and 'target="_blank" rel="noopener noreferrer"' in page


def test_url_without_reason_and_without_source(web_client, db):
    insert_url(db, URL, classification_reason=None)

    response = web_client.get("/detail", query_string={"url": URL})

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    source_row = page[page.index("Most reported source</td>"):page.index("Derived from</td>")]
    assert "see details" not in source_row


def test_unknown_tab_shows_overview(web_client, db):
    insert_url(db, URL)

    page = web_client.get("/detail", query_string={"url": URL, "tab": "xyz"}).get_data(as_text=True)

    assert 'class="detail-tab active"\n               href="/detail?url=' in page and "Classification reason" in page


def test_class_history_times_formatted(web_client, db):
    insert_url(db, URL)
    insert_classification(db, URL, "malicious", created_at="2026-01-02 00:00:00")
    insert_classification(db, URL, "harmless", created_at="2026-01-03T10:11:12.123456+00:00")

    page = web_client.get("/detail", query_string={"url": URL, "tab": "class_history"}).get_data(as_text=True)

    assert '<span class="ch-time">2026-01-02</span>' in page
    assert '<span class="ch-time">2026-01-03 10:11:12 UTC</span>' in page


def test_edit_from_detail_returns_to_detail(web_client, db):
    insert_url(db, URL)

    page = web_client.get("/detail", query_string={"url": URL, "show": "malicious"},
                          environ_base=ANALYST).get_data(as_text=True)
    response = web_client.post("/edit_detail", query_string={"url": URL, "show": "malicious", "back": "detail"},
                               data={"class": "harmless", "reason": "manual", "note": ""}, environ_base=ANALYST)

    assert "back=detail" in page and "show=malicious" in page
    assert response.status_code == 302 and response.headers["Location"].startswith("/detail?url=")


def test_reevaluate_keeps_the_tab(web_client, db):
    insert_url(db, URL, evaluated="yes")

    response = web_client.post("/detail", query_string={"url": URL, "tab": "sources", "show": "malicious"},
                               environ_base=ANALYST)

    assert "tab=sources" in response.headers["Location"] and "show=malicious" in response.headers["Location"]


def test_content_tab_has_copy_button_for_sha256(web_client, db):
    insert_url(db, URL)
    content_id = insert_content(db)
    insert_download(db, URL, content_id)
    sha256 = db.execute("SELECT sha256 FROM content WHERE id = ?", (content_id,)).fetchone()[0]

    page = web_client.get("/detail", query_string={"url": URL, "tab": "content"}).get_data(as_text=True)

    assert f'class="copy-btn" data-copy="{sha256}" onclick="copyToClipboard(this)"' in page


def test_sources_tab_explains_sightings_counted_only_in_overview(web_client, db):
    insert_url(db, URL, occurrences=5)
    insert_observation(db, URL, honeynet="honeynet-a")
    insert_observation(db, URL, honeynet="honeynet-a", observed_at="2026-01-02T12:00:00+00:00")
    insert_url(db, "http://even.test/", occurrences=1)
    insert_observation(db, "http://even.test/", honeynet="honeynet-a")

    page = web_client.get("/detail", query_string={"url": URL, "tab": "sources"}).get_data(as_text=True)
    even = web_client.get("/detail", query_string={"url": "http://even.test/", "tab": "sources"}).get_data(as_text=True)

    assert "3 more sightings are" in page and "(5)" in page
    assert "sources-note" not in even
