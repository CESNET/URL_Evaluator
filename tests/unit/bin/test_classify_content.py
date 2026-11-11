import logging

import pytest

from bin import classify_content
from common import file_classifier
from common.db import SQLiteWrapper
from tests.factories import insert_content

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 64


def categories(db):
    return [r[0] for r in db.execute("SELECT file_category FROM content ORDER BY id").fetchall()]


def test_classifies_only_unclassified_samples(config, db, content_dir, fake_magika):
    insert_content(db, ELF, content_dir=content_dir)
    insert_content(db, b"#!/bin/sh\n", content_dir=content_dir, file_category="text")  # already classified

    classify_content.main(["--config", config._test_path])

    assert categories(db) == ["executable", "text"]
    assert [kind for kind, _ in fake_magika.calls] == ["path"]  # read from disk, never executed


def test_all_reclassifies_every_sample(config, db, content_dir):
    insert_content(db, ELF, content_dir=content_dir, file_category="text")

    classify_content.main(["--config", config._test_path, "--all"])

    assert categories(db) == ["executable"]


def test_missing_sample_file_is_skipped(config, db, content_dir, caplog):
    caplog.set_level(logging.INFO, logger="classify_content.py")
    insert_content(db, ELF)  # file_path in /nonexistent
    insert_content(db, b"#!/bin/sh\n", content_dir=content_dir)

    classify_content.main(["--config", config._test_path])

    assert categories(db) == [None, "script"]
    assert "1 classified, 1 failed" in caplog.text


def test_exits_without_magika(config, monkeypatch):
    monkeypatch.setattr(file_classifier, "_magika", None)
    monkeypatch.setattr(file_classifier, "_magika_failed", True)

    with pytest.raises(SystemExit) as exit_info:
        classify_content.main(["--config", config._test_path])

    assert exit_info.value.code == 1


def test_exits_with_invalid_config(tmp_path):
    with pytest.raises(SystemExit) as exit_info:
        classify_content.main(["--config", str(tmp_path / "missing.yaml")])

    assert exit_info.value.code == 1


def test_exits_before_migration_008(make_config, tmp_path):
    # content table without the content-type columns (database not migrated yet)
    old_db = tmp_path / "old.sqlite"
    with SQLiteWrapper(str(old_db)) as db:
        db.execute("CREATE TABLE content (id INTEGER PRIMARY KEY, sha256 TEXT, file_path TEXT)")
    config = make_config(db_path=str(old_db))

    with pytest.raises(SystemExit) as exit_info:
        classify_content.main(["--config", config._test_path])

    assert exit_info.value.code == 1
