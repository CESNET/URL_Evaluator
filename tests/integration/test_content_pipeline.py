"""Downloads from a real local HTTP server -> content store on disk -> Magika -> download observations."""

import os

import pytest
from werkzeug import Response

from tests.api_mocks import load_bytes
from tests.factories import insert_url

pytestmark = pytest.mark.integration


def observations(db, url):
    return db.execute("SELECT status_code, change_type, content_id FROM download_observations "
                      "WHERE url = ? ORDER BY id", (url,)).fetchall()


@pytest.mark.slow
@pytest.mark.parametrize("body, content_type, category, label", [
    (load_bytes("samples", "dropper.sh"), "text/x-shellscript", "script", "shell"),
    (load_bytes("samples", "not_found.html"), "text/html", "html", "html"),
    (None, "application/octet-stream", "executable", "elf"),  # /bin/true of the test host
])
def test_downloaded_payload_is_stored_and_classified(
        evaluator_mod, real_magika, httpserver, external_apis, db, config, body, content_type, category, label):
    if body is None:
        if not os.path.exists("/bin/true"):
            pytest.skip("/bin/true not available")
        body = open("/bin/true", "rb").read()
    url = insert_url(db, httpserver.url_for("/payload"))
    httpserver.expect_request("/payload").respond_with_data(body, content_type=content_type)
    external_apis()

    evaluator_mod.process_url(url)

    file_path, mime, cat, magika_label = db.execute(
        "SELECT file_path, mime_type, file_category, magika_label FROM content").fetchone()
    assert (cat, magika_label) == (category, label)
    assert mime == content_type
    assert file_path.startswith(config.content_dir) and open(file_path, "rb").read() == body
    assert db.execute("SELECT file_mime_type FROM urls").fetchone() == (content_type,)


def test_http_error_is_recorded_without_content(evaluator_mod, httpserver, external_apis, db):
    url = insert_url(db, httpserver.url_for("/gone"))
    httpserver.expect_request("/gone").respond_with_data("Not Found", status=404)
    external_apis()

    evaluator_mod.process_url(url)

    assert observations(db, url) == [(404, "unavailable", None)]
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0


def test_oversized_payload_is_not_stored(evaluator_mod, httpserver, external_apis, db):
    url = insert_url(db, httpserver.url_for("/big.bin"))
    httpserver.expect_request("/big.bin").respond_with_data(b"\x00" * (2 * 1024 * 1024))  # max_file_size: 1 MB
    external_apis()

    evaluator_mod.process_url(url)

    assert observations(db, url) == [(200, "unavailable", None)]
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 0
    # content_size / 'File too large' are not stored: see the xfail test_too_large_content


def test_redirect_loop_is_unreachable(evaluator_mod, httpserver, external_apis, db):
    url = insert_url(db, httpserver.url_for("/loop"))
    httpserver.expect_request("/loop").respond_with_response(
        Response(status=302, headers={"Location": httpserver.url_for("/loop")}))
    external_apis()

    result = evaluator_mod.process_url(url)

    assert (result["classification"], result["classification_reason"]) == ("unreachable", "Connection error")


def test_activity_scanner_detects_content_change_and_inactivity(
        activity_scanner_mod, httpserver, external_apis, db):
    url = insert_url(db, httpserver.url_for("/a.sh"), status="unknown")
    external_apis()

    def scan(response_body=None, status=200):
        httpserver.clear()
        httpserver.expect_request("/a.sh").respond_with_data(response_body or "", status=status)
        activity_scanner_mod.activity_scanner()
        return db.execute("SELECT status, status_changed FROM urls").fetchone()

    assert scan("echo v1\n") == ("active", "yes")
    db.execute("UPDATE urls SET status_changed = 'no'")
    assert scan("echo v1\n") == ("active", "no")
    assert scan("echo v2\n") == ("active", "no")
    assert scan(status=404) == ("inactive", "yes")

    changes = [row[1] for row in observations(db, url)]
    assert changes == ["initial", "confirmed", "content_changed", "unavailable"]
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 2
    # every run finished and its progress was cleared
    assert db.execute("SELECT COUNT(*) FROM activity_scanner_runs WHERE finished_at IS NULL").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM activity_scanner_progress").fetchone()[0] == 0


def test_activity_scanner_resumes_interrupted_run(activity_scanner_mod, httpserver, external_apis, db):
    done = insert_url(db, httpserver.url_for("/done"))
    todo = insert_url(db, httpserver.url_for("/todo"))
    httpserver.expect_request("/todo").respond_with_data("x")
    external_apis()
    # a previous run was interrupted after processing `done`
    run_id = db.execute("INSERT INTO activity_scanner_runs (started_at) VALUES ('2026-01-01T00:00:00')").lastrowid
    db.execute("INSERT INTO activity_scanner_progress (run_id, url) VALUES (?, ?)", (run_id, done))

    activity_scanner_mod.activity_scanner()

    assert [r[0] for r in db.execute("SELECT url FROM download_observations").fetchall()] == [todo]
    assert db.execute("SELECT id FROM activity_scanner_runs WHERE finished_at IS NOT NULL").fetchall() == [(run_id,)]
