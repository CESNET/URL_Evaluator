import json

import pytest

from tests.factories import insert_content, insert_download, insert_source, insert_url

ANALYST = {"REMOTE_USER": "alice"}


def test_lists_urls(web_client, db):
    insert_url(db, "http://evil.test/a.sh", classification="malicious", classification_reason="Blacklist check")
    insert_url(db, "http://other.test/b.sh")

    page = web_client.get("/").get_data(as_text=True)

    assert "http://evil.test/a.sh" in page and "http://other.test/b.sh" in page


def test_quick_search_by_url(web_client, db):
    insert_url(db, "http://evil.test/a.sh")
    insert_url(db, "http://other.test/b.sh")

    page = web_client.get("/?q=evil").get_data(as_text=True)

    assert "http://evil.test/a.sh" in page and "http://other.test/b.sh" not in page


def test_quick_search_by_content_sha256(web_client, db):
    url = insert_url(db, "http://evil.test/a.sh")
    insert_url(db, "http://other.test/b.sh")
    content_id = insert_content(db, b"payload")
    insert_download(db, url, content_id)
    sha256 = db.execute("SELECT sha256 FROM content").fetchone()[0]

    page = web_client.get(f"/?q={sha256[:12]}").get_data(as_text=True)

    assert "http://evil.test/a.sh" in page and "http://other.test/b.sh" not in page


def test_show_malicious_only(web_client, db):
    insert_url(db, "http://evil.test/a.sh", classification="malicious")
    insert_url(db, "http://other.test/b.sh")

    page = web_client.get("/?show=malicious").get_data(as_text=True)

    assert "http://evil.test/a.sh" in page and "http://other.test/b.sh" not in page


def test_analyst_can_add_urls(web_client, db):
    response = web_client.post("/", data={"add-url": "http://new.test/x\nnonsense"}, environ_base=ANALYST)

    assert response.status_code == 200
    assert db.execute("SELECT url FROM urls").fetchall() == [("http://new.test/x",)]
    assert db.execute("SELECT honeynet FROM observations").fetchone() == ("Manual by alice",)


def test_anonymous_user_cannot_add_urls(web_client, db):
    web_client.post("/", data={"add-url": "http://new.test/x"})

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0


def listed(page, *urls):
    """Which of `urls` are listed on the page (the URL cell carries title="<url>")."""
    return {url for url in urls if f'title="{url}"' in page}


def filter_form(**fields):
    """POST data of the filter panel (every field the route reads, empty = no filter)."""
    data = {"find-url": "", "find-sha256": "", "find-note": "", "find-reason": "", "classification": "",
            "status": "", "src": "", "has_content": "", "sandbox": "", "content_type": ""}
    data.update(fields)
    return data


@pytest.fixture
def three_urls(db, content_dir):
    """with_script: shell script analysed by HA; with_html: HTML never analysed; bare: no content."""
    with_script = insert_url(db, "http://evil.test/a.sh", classification="malicious", status="active", note="mirai")
    with_html = insert_url(db, "http://other.test/index.html", status="inactive",
                           classification_reason="VT URL check inconclusive")
    bare = insert_url(db, "http://bare.test/x")
    insert_source(db, with_script, "Warden")
    insert_source(db, with_html, "Manual")
    script = insert_content(db, b"#!/bin/sh\n", content_dir=content_dir, file_category="script",
                            sandbox_info=json.dumps({"hybrid_analysis": {"http_status": 200, "tested": True}}))
    html = insert_content(db, b"<html></html>", content_dir=content_dir, file_category="html",
                          sandbox_info=json.dumps({"hybrid_analysis": {"http_status": 404}}))
    insert_download(db, with_script, script)
    insert_download(db, with_html, html)
    return with_script, with_html, bare


@pytest.mark.parametrize("fields, expected", [
    ({}, {0, 1, 2}),
    ({"find-url": "other"}, {1}),
    ({"find-note": "mir"}, {0}),
    ({"find-reason": "inconclusive"}, {1}),
    ({"classification": "malicious"}, {0}),
    ({"status": "inactive"}, {1}),
    ({"src": "Manual"}, {1}),
    ({"has_content": "yes"}, {0, 1}),
    ({"has_content": "no"}, {2}),
    ({"sandbox": "analysed"}, {0}),
    ({"sandbox": "not_analysed"}, {1}),
    ({"content_type": "script"}, {0}),
    ({"content_type": "html"}, {1}),
    ({"content_type": "no-such-category"}, {0, 1, 2}),  # unknown categories never reach the SQL
    ({"find-sha256": "not-a-sha256"}, set()),
    ({"classification": "unclassified", "has_content": "yes"}, {1}),
])
def test_filter_panel(web_client, three_urls, fields, expected):
    page = web_client.post("/", data=filter_form(**fields)).get_data(as_text=True)

    assert listed(page, *three_urls) == {three_urls[i] for i in expected}


def test_filter_by_full_sha256_of_downloaded_content(web_client, db, three_urls):
    sha256 = db.execute("SELECT sha256 FROM content WHERE file_category = 'html'").fetchone()[0]

    page = web_client.post("/", data=filter_form(**{"find-sha256": sha256.upper()})).get_data(as_text=True)

    assert listed(page, *three_urls) == {three_urls[1]}


def test_sandbox_filter_uses_newest_content_of_the_url(web_client, db, three_urls, content_dir):
    newer = insert_content(db, b"#!/bin/sh\necho v2\n", content_dir=content_dir,
                           sandbox_info=json.dumps({"hybrid_analysis": {"http_status": 404}}))
    insert_download(db, three_urls[0], newer, fetched_at="2026-02-01T00:00:00+00:00")

    analysed = web_client.post("/", data=filter_form(sandbox="analysed")).get_data(as_text=True)
    not_analysed = web_client.post("/", data=filter_form(sandbox="not_analysed")).get_data(as_text=True)

    assert listed(analysed, *three_urls) == set()
    assert listed(not_analysed, *three_urls) == {three_urls[0], three_urls[1]}


def test_invalid_sandbox_info_does_not_break_the_filter(web_client, db, three_urls):
    db.execute("UPDATE content SET sandbox_info = 'not json'")

    response = web_client.post("/", data=filter_form(sandbox="analysed"))

    assert response.status_code == 200 and listed(response.get_data(as_text=True), *three_urls) == set()


def test_url_count_reflects_filters(web_client, three_urls):
    unfiltered = web_client.get("/").get_data(as_text=True)
    filtered = web_client.get("/?q=evil").get_data(as_text=True)

    assert "Total URLs: <strong>3</strong>" in unfiltered and "no filters applied" in unfiltered
    assert "<strong>1</strong> / <strong>3</strong> URLs" in filtered


def test_filters_stay_until_cleared(web_client, three_urls):
    web_client.post("/", data=filter_form(classification="malicious"))

    assert listed(web_client.get("/").get_data(as_text=True), *three_urls) == {three_urls[0]}
    assert listed(web_client.get("/?clear_filters=True").get_data(as_text=True), *three_urls) == set(three_urls)


@pytest.mark.parametrize("show, expected", [("not_evaluated", {2}), ("unclassified", {1}), ("malicious", {0})])
def test_show_tabs(web_client, db, three_urls, show, expected):
    db.execute("UPDATE urls SET evaluated = 'yes' WHERE url IN (?, ?)", three_urls[:2])

    page = web_client.get("/", query_string={"show": show}).get_data(as_text=True)

    assert listed(page, *three_urls) == {three_urls[i] for i in expected}


def test_sorting_by_column(web_client, db):
    insert_url(db, "http://a.test/", last_seen="2026-01-01")
    insert_url(db, "http://b.test/", last_seen="2026-01-03")
    insert_url(db, "http://c.test/", last_seen="2026-01-02")

    newest_first = web_client.get("/").get_data(as_text=True)
    by_url = web_client.get("/?key=url&order=asc").get_data(as_text=True)

    def order(page):
        return sorted(["http://a.test/", "http://b.test/", "http://c.test/"], key=lambda u: page.index(f'title="{u}"'))
    assert order(newest_first) == ["http://b.test/", "http://c.test/", "http://a.test/"]
    assert order(by_url) == ["http://a.test/", "http://b.test/", "http://c.test/"]


def test_pagination(web_client, db):
    urls = [insert_url(db, f"http://evil.test/{i:02d}", last_seen=f"2026-01-{i + 1:02d}") for i in range(30)]

    first = web_client.get("/?page=1").get_data(as_text=True)
    second = web_client.get("/?page=2").get_data(as_text=True)

    assert len(listed(first, *urls)) == 25 and len(listed(second, *urls)) == 5
    assert "<p>2 of 2</p>" in second


@pytest.mark.parametrize("raw, adding, stored", [
    ("http://new.test/1\nhttp://new.test/2", "success", 2),
    ("http://new.test/1, nonsense", "partial", 1),
    ("nonsense", "fail", 0),
    ("   ", "fail", 0),
])
def test_add_urls_result(web_app, web_client, db, monkeypatch, raw, adding, stored):
    seen = {}
    render = web_app.render_template
    monkeypatch.setattr(web_app, "render_template", lambda tpl, **kw: seen.update(kw) or render(tpl, **kw))

    web_client.post("/", data={"add-url": raw}, environ_base=ANALYST)

    assert seen["adding"] == adding
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == stored


def test_adding_known_url_changes_nothing(web_client, db):
    insert_url(db, "http://known.test/", last_seen="2026-01-01")

    page = web_client.post("/", data={"add-url": "http://known.test/"}, environ_base=ANALYST).get_data(as_text=True)

    assert "All submitted URLs are already in the database." in page
    assert db.execute("SELECT occurrences, last_seen FROM urls").fetchone() == (1, "2026-01-01")
    assert db.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 0


def test_quick_search_with_quote(web_client, db):
    insert_url(db, "http://evil.test/it's.sh")

    response = web_client.get("/", query_string={"q": "it's"})

    assert response.status_code == 200 and 'title="http://evil.test/it&#39;s.sh"' in response.get_data(as_text=True)


def test_filters_of_one_user_do_not_affect_another(web_app, db):
    insert_url(db, "http://evil.test/a.sh")
    insert_url(db, "http://other.test/b.sh")
    alice, bob = web_app.app.test_client(), web_app.app.test_client()

    alice.get("/?q=evil", environ_base=ANALYST)
    page = bob.get("/", environ_base={"REMOTE_USER": "bob"}).get_data(as_text=True)

    assert "http://other.test/b.sh" in page


@pytest.mark.parametrize("field, value", [
    ("find-url", "it's"), ("find-note", "o'brien"), ("find-reason", "it's"), ("src", "O'Reilly feed"),
    ("classification", "x' OR '1'='1"), ("status", "x' OR '1'='1"),
])
def test_filter_values_never_reach_the_sql(web_client, db, field, value):
    quoted = insert_url(db, "http://evil.test/it's.sh", note="o'brien", classification_reason="it's")
    insert_source(db, quoted, "O'Reilly feed")
    other = insert_url(db, "http://other.test/")

    response = web_client.post("/", data=filter_form(**{field: value}))

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    expected = set() if field in ("classification", "status") else {"http://evil.test/it&#39;s.sh"}
    assert listed(page, "http://evil.test/it&#39;s.sh", other) == expected


@pytest.mark.parametrize("key, order", [("url; DROP TABLE urls", "asc"), ("url", "asc; DROP TABLE urls")])
def test_unknown_sort_column_or_order_falls_back_to_default(web_client, db, key, order):
    insert_url(db, "http://a.test/")

    response = web_client.get("/", query_string={"key": key, "order": order})

    assert response.status_code == 200 and listed(response.get_data(as_text=True), "http://a.test/")
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 1


@pytest.mark.parametrize("page_arg", ["abc", "0", "-3"])
def test_invalid_page_shows_the_first_page(web_client, db, page_arg):
    insert_url(db, "http://a.test/")

    response = web_client.get("/", query_string={"page": page_arg})

    assert response.status_code == 200 and listed(response.get_data(as_text=True), "http://a.test/")


def test_page_beyond_the_last_shows_the_last_page(web_client, db):
    urls = [insert_url(db, f"http://evil.test/{i:02d}") for i in range(30)]

    page = web_client.get("/?page=9999").get_data(as_text=True)

    assert "<p>2 of 2</p>" in page and len(listed(page, *urls)) == 5


def test_sorting_survives_filtering(web_client, db):
    insert_url(db, "http://a.test/", classification="malicious", last_seen="2026-01-01")
    insert_url(db, "http://b.test/", classification="malicious", last_seen="2026-01-03")

    web_client.get("/?key=url&order=asc")
    page = web_client.post("/?page=1", data=filter_form(classification="malicious")).get_data(as_text=True)

    assert page.index('title="http://a.test/"') < page.index('title="http://b.test/"')


def test_status_filter_offers_unknown(web_client, db):
    insert_url(db, "http://a.test/", status="unknown")
    insert_url(db, "http://b.test/", status="active")

    page = web_client.post("/", data=filter_form(status="unknown")).get_data(as_text=True)

    status_select = page[page.index('id="filter-status"'):]
    assert 'value="unknown">Unknown</option>' in status_select[:status_select.index("</select>")]
    assert listed(page, "http://a.test/", "http://b.test/") == {"http://a.test/"}


def test_filter_panel_drops_the_hidden_evaluated_filter_of_a_show_tab(web_client, db):
    insert_url(db, "http://a.test/", classification="malicious", evaluated="no")

    web_client.get("/?show=unclassified")
    page = web_client.post("/", data=filter_form(classification="malicious")).get_data(as_text=True)

    assert listed(page, "http://a.test/") == {"http://a.test/"}


def test_clearing_quick_search_keeps_panel_filters(web_client, db):
    insert_url(db, "http://a.test/", classification="malicious")
    insert_url(db, "http://b.test/", classification="harmless")

    web_client.post("/", data=filter_form(classification="malicious"))
    web_client.get("/?q=test")
    page = web_client.get("/?page=1&q=").get_data(as_text=True)

    searched = web_client.get("/?q=test").get_data(as_text=True)

    assert listed(page, "http://a.test/", "http://b.test/") == {"http://a.test/"}
    assert "/?page=1&amp;q=" in searched and "clear_filters" not in searched[searched.index("quick-search-clear"):][:300]


def test_cancel_filtering_hidden_when_only_the_show_tab_filters(web_client, db):
    insert_url(db, "http://a.test/", classification="malicious")

    tab_only = web_client.get("/?show=malicious&clear_filters=True").get_data(as_text=True)
    with_search = web_client.get("/?show=malicious&q=a.test").get_data(as_text=True)

    assert "Cancel filtering" not in tab_only and "Cancel filtering" in with_search


def test_anonymous_user_gets_no_url_checkboxes(web_client, db):
    insert_url(db, "http://a.test/")

    anonymous = web_client.get("/").get_data(as_text=True)
    analyst = web_client.get("/", environ_base=ANALYST).get_data(as_text=True)

    assert 'name="selected_urls[]"' not in anonymous and "Select All" not in anonymous
    assert 'name="selected_urls[]"' in analyst
