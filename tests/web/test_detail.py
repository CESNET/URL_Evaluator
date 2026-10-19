from tests.factories import insert_classification, insert_content, insert_download, insert_url

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

    assert "Recent (2)" in analyst
    assert analyst.index(">http://other.test/b.sh</a>") < analyst.index(f">{URL}</a>")  # newest first
    assert "recent-urls" not in anonymous
