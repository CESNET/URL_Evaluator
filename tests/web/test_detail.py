from tests.factories import insert_classification, insert_url

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
