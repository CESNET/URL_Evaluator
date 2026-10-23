"""Deleting a URL removes its whole record graph; shared content and sandbox history survive."""

import os

import pytest
from freezegun import freeze_time

from tests.factories import (insert_classification, insert_content, insert_discovered, insert_download,
                             insert_observation, insert_sandbox_submission, insert_session, insert_source,
                             insert_url)

pytestmark = pytest.mark.integration

DEPENDENT_TABLES = ("url_session", "url_source", "observations", "classification_history",
                    "discovered_urls", "download_observations")


def count(db, table, url):
    column = "url" if table != "discovered_urls" else "url = :u OR src_url"
    return db.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} = :u", {"u": url}).fetchone()[0]


def build_url_graph(db, url, content_ids, last_seen="2026-01-01"):
    insert_url(db, url, last_seen=last_seen, status="inactive")
    session = insert_session(db, f"wget {url}", urls=[url])
    insert_source(db, url)
    insert_observation(db, url, session=session)
    insert_classification(db, url)
    for content_id in content_ids:
        insert_download(db, url, content_id)


@freeze_time("2026-03-01")
def test_db_cleaner_removes_url_graph_and_orphan_content(db_cleaner_mod, db, content_dir):
    old, alive = "http://old.test/a.sh", "http://alive.test/a.sh"
    shared = insert_content(db, b"shared", content_dir=content_dir)
    orphan = insert_content(db, b"orphan", content_dir=content_dir)
    orphan_sha256, orphan_path = db.execute("SELECT sha256, file_path FROM content WHERE id = ?", (orphan,)).fetchone()
    submission = insert_sandbox_submission(db, orphan, orphan_sha256, status="done")
    build_url_graph(db, old, [shared, orphan])
    build_url_graph(db, alive, [shared], last_seen="2026-02-28")
    insert_discovered(db, alive, old)  # `alive` was found in the content of `old`

    db_cleaner_mod.db_cleaner()

    for table in DEPENDENT_TABLES:
        assert count(db, table, old) == 0, table
        if table != "discovered_urls":
            assert count(db, table, alive) == 1, table
    # the session only referenced by `old` is dropped as an orphan, the one of `alive` stays
    assert [r[0] for r in db.execute("SELECT session FROM sessions").fetchall()] == [f"wget {alive}"]
    # shared payload kept, orphan payload removed from DB and disk
    assert [r[0] for r in db.execute("SELECT id FROM content").fetchall()] == [shared]
    assert not os.path.exists(orphan_path)
    # sandbox history survives, detached from the purged content
    assert db.execute("SELECT content_id, sha256 FROM sandbox_submissions WHERE id = ?", (submission,)).fetchone() == (
        None, orphan_sha256)


def test_evaluator_domain_flood_deletes_non_malicious_urls(make_config, init_bin, db, external_apis):
    ev = init_bin("evaluator", make_config(ddos_threshold={
        "same_url_single_session": 10, "same_domain_single_session": 100, "same_domain_all_sessions": 3}))
    for i in range(3):
        build_url_graph(db, f"http://flood.test/{i}", [])
    insert_url(db, "http://flood.test/known-bad", classification="malicious", evaluated="yes")
    external_apis()

    assert ev.process_url("http://flood.test/0") is None  # deleted, not classified

    assert [r[0] for r in db.execute("SELECT url FROM urls").fetchall()] == ["http://flood.test/known-bad"]
    for table in DEPENDENT_TABLES:
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table
