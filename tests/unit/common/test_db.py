import pytest

from common.db import SQLiteWrapper
from tests.factories import insert_url, insert_session, insert_observation, insert_content, insert_download


def test_schema_created(db):
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"urls", "sessions", "content", "download_observations", "classification_history"} <= tables


def test_url_session_indexed_by_session(db):
    # deleting orphan sessions cascades to url_session; without this index
    # every deleted session is a full scan of url_session
    plan = db.execute("EXPLAIN QUERY PLAN SELECT * FROM url_session WHERE session = 'x'").fetchall()
    assert any("idx_url_session_session" in row[-1] for row in plan)


def test_pragmas(db):
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_execute_rolls_back_on_error(db):
    insert_url(db, "http://a.test/x")
    with pytest.raises(Exception):
        db.execute("INSERT INTO urls (url) VALUES (?)", ("http://a.test/x",))
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 1


def test_execute_many_is_atomic(db):
    with pytest.raises(Exception):
        db.execute_many([
            ("INSERT INTO urls (url) VALUES (?)", ("http://a.test/1",)),
            ("INSERT INTO urls (url) VALUES (?)", ("http://a.test/1",)),  # duplicate -> whole batch rolled back
        ])
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0


def test_transaction_commits_at_the_end(db, db_path):
    with db.transaction():
        insert_url(db, "http://a.test/1")
        db.record_classification("http://a.test/1", "harmless")
        with SQLiteWrapper(db_path) as other:  # nothing is visible before the block ends
            assert other.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0
    with SQLiteWrapper(db_path) as other:
        assert other.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 1
        assert other.execute("SELECT COUNT(*) FROM classification_history").fetchone()[0] == 1


def test_transaction_rolls_back_as_a_whole(db):
    with pytest.raises(Exception):
        with db.transaction():
            insert_url(db, "http://a.test/1")
            insert_url(db, "http://a.test/1")  # duplicate -> the first insert is undone too
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0
    insert_url(db, "http://a.test/2")  # the connection is usable (autocommit) afterwards
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 1


def test_record_classification(db):
    url = insert_url(db)
    db.record_classification(url, "malicious", reason="Blacklist check", actor="evaluator")
    row = db.execute("SELECT url, classification, reason, actor FROM classification_history").fetchone()
    assert row == (url, "malicious", "Blacklist check", "evaluator")


def test_delete_url_cascades(db):
    url = insert_url(db)
    session = insert_session(db, urls=[url])
    insert_observation(db, url, session=session)
    insert_download(db, url, content_id=insert_content(db))

    db.execute("DELETE FROM urls WHERE url = ?", (url,))

    for table in ("url_session", "observations", "download_observations"):
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table
    # content is shared between URLs, it is not removed by the cascade
    assert db.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 1


def test_second_connection_sees_committed_data(db, db_path):
    insert_url(db, "http://a.test/x")
    with SQLiteWrapper(db_path) as other:
        assert other.execute("SELECT url FROM urls").fetchone()[0] == "http://a.test/x"
