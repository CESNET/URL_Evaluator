from tests.factories import insert_content, insert_download, insert_url

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
