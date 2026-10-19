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
