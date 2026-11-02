import pytest
import requests
from freezegun import freeze_time

from tests.api_mocks import load_bytes


@freeze_time("2026-01-10 06:00:00")
def test_feed_urls_are_stored(honeynetasia2evaluator_mod, http_mock, config, db):
    http_mock.get(config.hna_url, body=load_bytes("hna", "latest-url-unique.csv"))

    honeynetasia2evaluator_mod.honeynetasia2evaluator()

    # hxxp is de-sanitized, the invalid line is skipped
    assert db.execute("SELECT url, first_seen, last_seen FROM urls ORDER BY url").fetchall() == [
        ("http://hna-evil.test/a.sh", "2026-01-10", "2026-01-10"),
        ("http://hna-evil.test/bins/mips", "2026-01-10", "2026-01-10")]
    assert db.execute("SELECT DISTINCT source FROM url_source").fetchall() == [("HoneyNet.Asia",)]


def test_known_url_is_refreshed(honeynetasia2evaluator_mod, http_mock, config, db):
    http_mock.get(config.hna_url, body=b"hxxps://hna-evil.test/a.sh\n")

    honeynetasia2evaluator_mod.honeynetasia2evaluator()
    honeynetasia2evaluator_mod.honeynetasia2evaluator()

    assert db.execute("SELECT url, occurrences FROM urls").fetchall() == [("https://hna-evil.test/a.sh", 2)]


def test_download_error_stores_nothing(honeynetasia2evaluator_mod, http_mock, config, db):
    http_mock.get(config.hna_url, status=503)

    honeynetasia2evaluator_mod.honeynetasia2evaluator()

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0


def test_connection_error_is_only_logged(honeynetasia2evaluator_mod, http_mock, config, db):
    http_mock.get(config.hna_url, body=requests.exceptions.ConnectTimeout())

    honeynetasia2evaluator_mod.honeynetasia2evaluator()  # never raises out of the scheduler job

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0


def test_line_that_is_not_utf8_does_not_stop_the_feed(honeynetasia2evaluator_mod, http_mock, config, db):
    http_mock.get(config.hna_url, body=b"http://hna-evil.test/\xff\xfe\nhttp://hna-evil.test/a.sh\n")

    honeynetasia2evaluator_mod.honeynetasia2evaluator()

    assert ("http://hna-evil.test/a.sh",) in db.execute("SELECT url FROM urls").fetchall()
