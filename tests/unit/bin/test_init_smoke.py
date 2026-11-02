"""Smoke tests: every bin/ script can be imported and initialised from a test config."""

import pytest

from tests.conftest import BIN_MODULES


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
