import logging
import os

import pytest
from freezegun import freeze_time

from common.db import SQLiteWrapper
from tests.factories import (insert_classification, insert_content, insert_discovered, insert_download,
                             insert_observation, insert_session, insert_source, insert_url)

TODAY = "2026-03-01"  # max_age_inactive = 30 days, max_age_invalid = 7 days


def urls(db):
    return {row[0] for row in db.execute("SELECT url FROM urls").fetchall()}


def sessions(db):
    return {row[0] for row in db.execute("SELECT session FROM sessions").fetchall()}


@pytest.fixture
def queries(monkeypatch):
    """Every query passed to SQLiteWrapper.execute (VACUUM included)."""
    seen = []
    execute = SQLiteWrapper.execute
    monkeypatch.setattr(SQLiteWrapper, "execute",
                        lambda self, query, params=None: seen.append(query) or execute(self, query, params))
    return seen


@freeze_time(TODAY)
def test_deletes_old_inactive_and_invalid_urls(db_cleaner_mod, db):
    insert_url(db, "http://old-inactive.test/", last_seen="2026-01-15", status="inactive")
    insert_url(db, "http://old-active.test/", last_seen="2026-01-15", status="active")
    insert_url(db, "http://recent-inactive.test/", last_seen="2026-02-15", status="inactive")
    insert_url(db, "http://old-invalid.test/", last_seen="2026-02-15", classification="invalid")
    insert_url(db, "http://recent-invalid.test/", last_seen="2026-02-27", classification="invalid")

    db_cleaner_mod.db_cleaner()

    assert urls(db) == {"http://old-active.test/", "http://recent-inactive.test/", "http://recent-invalid.test/"}


@freeze_time(TODAY)
def test_url_exactly_max_age_old_is_kept(db_cleaner_mod, db):
    insert_url(db, "http://inactive-at-cutoff.test/", last_seen="2026-01-30", status="inactive")   # 30 days
    insert_url(db, "http://inactive-past-cutoff.test/", last_seen="2026-01-29", status="inactive")
    insert_url(db, "http://invalid-at-cutoff.test/", last_seen="2026-02-22", classification="invalid")  # 7 days
    insert_url(db, "http://invalid-past-cutoff.test/", last_seen="2026-02-21", classification="invalid")

    db_cleaner_mod.db_cleaner()

    assert urls(db) == {"http://inactive-at-cutoff.test/", "http://invalid-at-cutoff.test/"}


@freeze_time(TODAY)
def test_url_both_inactive_and_invalid_is_counted_once(db_cleaner_mod, db, caplog):
    caplog.set_level(logging.INFO)
    insert_url(db, "http://both.test/", last_seen="2026-01-01", status="inactive", classification="invalid")

    db_cleaner_mod.db_cleaner()

    assert urls(db) == set()
    assert "Deleted 1 inactive and 0 invalid URLs" in caplog.text


@freeze_time(TODAY)
def test_removes_orphan_content_but_keeps_shared(db_cleaner_mod, db, content_dir):
    old = insert_url(db, "http://old.test/", last_seen="2026-01-01", status="inactive")
    alive = insert_url(db, "http://alive.test/", last_seen="2026-02-28", status="active")
    shared = insert_content(db, b"shared payload", content_dir=content_dir)
    orphan = insert_content(db, b"only used by the old URL", content_dir=content_dir)
    insert_download(db, old, shared)
    insert_download(db, alive, shared)
    insert_download(db, old, orphan)
    path = dict(db.execute("SELECT id, file_path FROM content").fetchall())

    db_cleaner_mod.db_cleaner()

    assert urls(db) == {alive}
    assert [r[0] for r in db.execute("SELECT id FROM content").fetchall()] == [shared]
    assert not os.path.exists(path[orphan])
    assert os.path.exists(path[shared])


@freeze_time(TODAY)
def test_content_cleanup_failure_does_not_stop_the_job(db_cleaner_mod, db, content_dir, monkeypatch, caplog):
    old = insert_url(db, "http://old.test/", last_seen="2026-01-01", status="inactive")
    insert_download(db, old, insert_content(db, content_dir=content_dir))
    insert_session(db, "wget http://flood.test/1")

    def fail(*args, **kwargs):
        raise OSError("disk error")
    monkeypatch.setattr(db_cleaner_mod.content_store, "cleanup_orphan_content", fail)

    db_cleaner_mod.db_cleaner()

    assert urls(db) == set() and sessions(db) == set()  # the following steps still ran
    assert "Orphan content cleanup failed: disk error" in caplog.text


@freeze_time(TODAY)
def test_removes_sessions_left_without_urls(db_cleaner_mod, db):
    old = insert_url(db, "http://old.test/", last_seen="2026-01-01", status="inactive")
    alive = insert_url(db, "http://alive.test/", last_seen="2026-02-28", status="active")
    insert_session(db, "wget http://old.test/", urls=[old])
    insert_session(db, "wget http://old.test/; wget http://alive.test/", urls=[old, alive])
    insert_session(db, "wget http://flood.test/1")  # its URLs were deleted at ingest

    db_cleaner_mod.db_cleaner()

    assert sessions(db) == {"wget http://old.test/; wget http://alive.test/"}


@freeze_time(TODAY)
def test_link_without_session_does_not_block_session_cleanup(db_cleaner_mod, db):
    alive = insert_url(db, "http://alive.test/", last_seen="2026-02-28", status="active")
    db.execute("INSERT INTO url_session (url, session) VALUES (?, NULL)", (alive,))
    insert_session(db, "wget http://flood.test/1")

    db_cleaner_mod.db_cleaner()

    assert sessions(db) == set()


@freeze_time(TODAY)
def test_deleted_url_takes_its_whole_record_graph(db_cleaner_mod, db):
    old = insert_url(db, "http://old.test/", last_seen="2026-01-01", status="inactive")
    alive = insert_url(db, "http://alive.test/x86", last_seen="2026-02-28", status="active")
    insert_discovered(db, alive, old)  # alive was found in the content of old
    insert_classification(db, old)
    insert_observation(db, old)
    insert_source(db, old)
    insert_session(db, "wget http://old.test/", urls=[old])
    insert_download(db, old)
    db.execute("INSERT INTO user_url_history (user, url, visited_at) VALUES ('alice', ?, '2026-02-01')", (old,))
    db.execute("INSERT INTO urlhaus_submissions (url, submitted_at, status) VALUES (?, '2026-02-01', 'ok')", (old,))

    db_cleaner_mod.db_cleaner()

    for table in ("discovered_urls", "classification_history", "observations", "url_source", "url_session",
                  "download_observations", "user_url_history", "urlhaus_submissions"):
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table
    assert urls(db) == {alive}


@freeze_time(TODAY)
def test_vacuum_runs_after_deleting(db_cleaner_mod, db, queries):
    insert_url(db, "http://old.test/", last_seen="2026-01-01", status="inactive")

    db_cleaner_mod.db_cleaner()

    assert "VACUUM" in queries


@freeze_time(TODAY)
def test_vacuum_can_be_disabled(init_bin, make_config, db, queries):
    db_cleaner_mod = init_bin("db_cleaner", make_config(db_vacuum=False))
    insert_session(db, "wget http://flood.test/1")

    db_cleaner_mod.db_cleaner()

    assert sessions(db) == set()
    assert "VACUUM" not in queries


@freeze_time(TODAY)
def test_nothing_to_delete_skips_vacuum(db_cleaner_mod, db, queries):
    insert_url(db, "http://alive.test/", last_seen="2026-02-28", status="active")

    db_cleaner_mod.db_cleaner()

    assert "VACUUM" not in queries and urls(db) == {"http://alive.test/"}


@freeze_time(TODAY)
def test_vacuum_failure_is_only_logged(db_cleaner_mod, db, monkeypatch, caplog):
    insert_url(db, "http://old.test/", last_seen="2026-01-01", status="inactive")
    execute = SQLiteWrapper.execute

    def execute_without_vacuum(self, query, params=None):
        if query == "VACUUM":
            raise RuntimeError("database is locked")
        return execute(self, query, params)
    monkeypatch.setattr(SQLiteWrapper, "execute", execute_without_vacuum)

    db_cleaner_mod.db_cleaner()

    assert urls(db) == set()
    assert "VACUUM failed: database is locked" in caplog.text
