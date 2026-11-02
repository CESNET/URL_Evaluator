import pytest

from tests.api_mocks import load_json


def test_get_idea_field_walks_nested_lists(warden2evaluator_mod):
    event = {"Node": [{"Name": "a", "SW": ["x", "y"]}, {"Name": "b"}]}
    assert warden2evaluator_mod.get_idea_field(event, "Node.Name") == ["a", "b"]
    assert warden2evaluator_mod.get_idea_field(event, "Node.SW") == ["x", "y"]
    assert warden2evaluator_mod.get_idea_field(event, "Node.Missing") == []


@pytest.mark.parametrize("node, source", [
    ({"SW": ["hugo-cowrie"]}, "CESNET Hugo"),
    ({"Name": "cznic_haas"}, "CZ.NIC HaaS"),
    ({"Name": "somebody.else"}, "Warden (unknown node)"),  # catch-all mapping with no rules
])
def test_get_source_name(warden2evaluator_mod, node, source):
    assert warden2evaluator_mod.get_source_name({"Node": [node]}) == source


def test_unmapped_event_is_ignored(make_config, init_bin, db):
    module = init_bin("warden2evaluator", make_config(warden_sources={"CESNET Hugo": {"Node.SW": "hugo-cowrie"}}))
    event = load_json("idea", "cowrie_session.json")
    event["Node"] = [{"Name": "somebody.else"}]

    assert module.handle_events([event]) == []
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 0


def test_handle_events_unwraps_attachment_and_stores_urls(warden2evaluator_mod, db):
    event = load_json("idea", "cowrie_session.json")

    inserted = warden2evaluator_mod.handle_events([event])

    assert inserted == ["http://evil.test/bins/x86", "http://evil.test/a.sh"]
    # the "['...']" wrapper is removed before the session is stored
    session = db.execute("SELECT session, idea_id FROM sessions").fetchone()
    assert session == (event["Attach"][0]["Content"][2:-2], event["ID"])
    assert db.execute("SELECT DISTINCT source, honeynet FROM observations").fetchall() == [("Warden", "CESNET Hugo")]


def test_failing_event_does_not_drop_the_rest_of_the_batch(warden2evaluator_mod, db, monkeypatch):
    broken, event = load_json("idea", "cowrie_session.json"), load_json("idea", "cowrie_session.json")
    broken["ID"] = "broken"
    process = warden2evaluator_mod.process_new_session

    def fail_on_broken(db_conn, cfg, content, idea_id, *args):
        if idea_id == "broken":
            raise RuntimeError("database is locked")
        return process(db_conn, cfg, content, idea_id, *args)
    monkeypatch.setattr(warden2evaluator_mod, "process_new_session", fail_on_broken)

    assert warden2evaluator_mod.handle_events([broken, event]) == ["http://evil.test/bins/x86", "http://evil.test/a.sh"]


@pytest.fixture
def receiver(warden2evaluator_mod, warden_events, monkeypatch):
    """warden2evaluator with a running stub client; the 2nd wait (after an error or no events) stops the loop."""
    client = warden2evaluator_mod.Client()
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        if len(waits) == 2:
            warden2evaluator_mod.running_flag = False
    monkeypatch.setattr(warden2evaluator_mod, "wclient", client)
    monkeypatch.setattr(warden2evaluator_mod, "running_flag", True)
    monkeypatch.setattr(warden2evaluator_mod.time, "sleep", sleep)
    return client


def test_receiver_stores_queued_events(warden2evaluator_mod, receiver, warden_events, db):
    warden_events([load_json("idea", "cowrie_session.json")])

    warden2evaluator_mod.receiver()

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 2
    assert receiver.get_events_calls[0] == {"cat": "Intrusion.UserCompromise"}


def test_receiver_survives_warden_error(warden2evaluator_mod, receiver, warden_events, db, monkeypatch, caplog):
    replies = iter([warden2evaluator_mod.Error("Warden server unreachable"), [load_json("idea", "cowrie_session.json")]])
    monkeypatch.setattr(receiver, "getEvents", lambda **filters: next(replies, []))

    warden2evaluator_mod.receiver()

    assert "Warden server unreachable" in caplog.text
    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 2


def test_receiver_survives_exception(warden2evaluator_mod, receiver, db, monkeypatch):
    replies = iter([ConnectionError("reset"), [load_json("idea", "cowrie_session.json")]])

    def get_events(**filters):
        reply = next(replies, [])
        if isinstance(reply, Exception):
            raise reply
        return reply
    monkeypatch.setattr(receiver, "getEvents", get_events)

    warden2evaluator_mod.receiver()

    assert db.execute("SELECT COUNT(*) FROM urls").fetchone()[0] == 2


def test_sigint_handler_stops_the_receiver(warden2evaluator_mod, monkeypatch):
    monkeypatch.setattr(warden2evaluator_mod, "running_flag", True)

    warden2evaluator_mod.sigint_handler(15, None)

    assert warden2evaluator_mod.running_flag is False
