import json
import logging

import pytest

from bin import recheck_ha_lookups
from common import hybrid_analysis
from tests.api_mocks import mock_ha_overview
from tests.factories import insert_content

OLD_UNKNOWN_200 = {"http_status": 200, "tested": False, "checked_at": "2026-10-10T10:00:00+00:00",
                   "response": {"sha256s": ["x"], "reports": []}}
OLD_404 = {"http_status": 404, "tested": False, "checked_at": "2026-10-10T10:00:00+00:00",
           "response": {"message": "Requested hash not found"}}
CURRENT_404 = {"http_status": 404, "tested": False, "checked_at": "2026-10-20T10:00:00+00:00",
               "response": {"message": "Not Found"}}


def stored(data, lookup):
    return {"data": data, "sandbox_info": json.dumps({"hybrid_analysis": lookup})}


def lookups(db):
    return [hybrid_analysis.get_lookup(r[0]) for r in db.execute("SELECT sandbox_info FROM content ORDER BY id")]


@pytest.fixture
def three_contents(db):
    for data, lookup in ((b"a", OLD_UNKNOWN_200), (b"b", OLD_404), (b"c", CURRENT_404)):
        insert_content(db, data, sandbox_info=json.dumps({"hybrid_analysis": lookup}))


def test_looks_up_only_outdated_lookups_again(config, db, three_contents, http_mock):
    call = mock_ha_overview(http_mock, config, status=200)

    recheck_ha_lookups.main(["--config", config._test_path])

    old_a, old_b, current = lookups(db)
    assert len(call.calls) == 2
    assert old_a["tested"] and old_b["tested"] and not hybrid_analysis.is_outdated_lookup(old_a)
    assert current == CURRENT_404


def test_dry_run_sends_no_request(config, db, three_contents, http_mock, caplog):
    caplog.set_level(logging.INFO, logger="recheck_ha_lookups.py")
    call = mock_ha_overview(http_mock, config, status=200)

    recheck_ha_lookups.main(["--config", config._test_path, "--dry-run"])

    assert len(call.calls) == 0 and "2 content samples have an outdated" in caplog.text
    assert lookups(db)[0] == OLD_UNKNOWN_200


def test_stops_after_rate_limit(config, db, three_contents, http_mock, caplog):
    caplog.set_level(logging.INFO, logger="recheck_ha_lookups.py")
    call = mock_ha_overview(http_mock, config, status=429, headers={"Retry-After": "120"})

    recheck_ha_lookups.main(["--config", config._test_path])

    assert len(call.calls) == 1 and "rate limit" in caplog.text and "1 left" in caplog.text
    assert all(hybrid_analysis.is_outdated_lookup(lookup) for lookup in lookups(db)[:2])


def test_exits_without_api_key(make_config):
    config = make_config(ha_key="!!! CHANGE THIS !!!")

    with pytest.raises(SystemExit) as exit_info:
        recheck_ha_lookups.main(["--config", config._test_path])

    assert exit_info.value.code == 1
