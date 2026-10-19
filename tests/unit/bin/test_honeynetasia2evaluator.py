import pytest

from tests.api_mocks import load_bytes


@pytest.mark.xfail(strict=True, raises=TypeError,
                   reason="BUG: re.sub(r'^hxxp(s?)://', r'http\\1://') is called without the url argument")
def test_feed_urls_are_stored(honeynetasia2evaluator_mod, http_mock, config, db):
    http_mock.get(config.hna_url, body=load_bytes("hna", "latest-url-unique.csv"))

    honeynetasia2evaluator_mod.honeynetasia2evaluator()

    stored = {row[0] for row in db.execute("SELECT url FROM urls").fetchall()}
    assert stored == {"http://hna-evil.test/bins/mips", "http://hna-evil.test/a.sh"}


def test_download_error_stores_nothing(honeynetasia2evaluator_mod, http_mock, config, db):
    http_mock.get(config.hna_url, status=503)

    honeynetasia2evaluator_mod.honeynetasia2evaluator()

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0
