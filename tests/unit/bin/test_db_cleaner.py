import os

from freezegun import freeze_time

from tests.factories import insert_content, insert_download, insert_session, insert_url

TODAY = "2026-03-01"  # max_age_inactive = 30 days, max_age_invalid = 7 days


def urls(db):
    return {row[0] for row in db.execute("SELECT url FROM urls").fetchall()}


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
def test_removes_orphan_content_but_keeps_shared(db_cleaner_mod, db, content_dir):
    old = insert_url(db, "http://old.test/", last_seen="2026-01-01", status="inactive")
    alive = insert_url(db, "http://alive.test/", last_seen="2026-02-28", status="active")
    shared = insert_content(db, b"shared payload", content_dir=content_dir)
    orphan = insert_content(db, b"only used by the old URL", content_dir=content_dir)
    insert_download(db, old, shared)
    insert_download(db, alive, shared)
    insert_download(db, old, orphan)
    orphan_path = db.execute("SELECT file_path FROM content WHERE id = ?", (orphan,)).fetchone()[0]

    db_cleaner_mod.db_cleaner()

    assert urls(db) == {alive}
    assert [r[0] for r in db.execute("SELECT id FROM content").fetchall()] == [shared]
    assert not os.path.exists(orphan_path)


def sessions(db):
    return {row[0] for row in db.execute("SELECT session FROM sessions").fetchall()}


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
def test_vacuum_can_be_disabled(init_bin, make_config, db, monkeypatch):
    db_cleaner_mod = init_bin("db_cleaner", make_config(db_vacuum=False))
    insert_session(db, "wget http://flood.test/1")
    queries = []
    execute = db_cleaner_mod.SQLiteWrapper.execute
    monkeypatch.setattr(db_cleaner_mod.SQLiteWrapper, "execute",
                        lambda self, query, params=None: queries.append(query) or execute(self, query, params))

    db_cleaner_mod.db_cleaner()

    assert sessions(db) == set()
    assert "VACUUM" not in queries
