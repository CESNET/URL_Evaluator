"""bin/evaluator2urlhaus.py, bin/evaluator2misp.py and bin/evaluator2misp_bysource.py (MISP client mocked)."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from freezegun import freeze_time
from pymisp import MISPEvent, MISPObject

from tests.api_mocks import load_json, mock_urlhaus_lookup
from tests.factories import insert_content, insert_discovered, insert_download, insert_source, insert_url

# Comment attributes evaluator2misp refreshes in its event (fixed UUIDs in the code)
COMMENT_UUIDS = ("1716011a-b02b-427c-b042-242fc3e0df3e", "e5b21a21-0178-43c6-9d38-747f1f8c4811")


# --- evaluator2urlhaus ---

PUBLIC_IP = "198.51.100.1"  # placeholder for "public": is_global is patched in the urlhaus tests below


def urlhaus_candidate(db, url="http://new.test/a.sh", classification="malicious", status="active", data=None,
                      content=None, **download):
    """Active malicious URL whose latest download (1 hour ago) returned a shell script."""
    insert_url(db, url, classification=classification, status=status)
    content_id = insert_content(db, data or url.encode(), **{"file_category": "script", "magika_label": "shell",
                                                            **(content or {})})
    insert_download(db, url, content_id, **{"source_ip": PUBLIC_IP, **download})
    return content_id


def submitted(submit):
    """URLs (with tags) of every submit request: [[{url, threat[, tags]}, ...], ...]."""
    return [json.loads(call.request.body)["submission"] for call in submit.calls]


def urlhaus_rows(db):
    return db.execute("SELECT url, status, tags FROM urlhaus_submissions ORDER BY id").fetchall()


@pytest.fixture
def urlhaus(evaluator2urlhaus_mod, monkeypatch):
    """evaluator2urlhaus at 1 hour after the factories' NOW; PUBLIC_IP counts as a public address."""
    real = evaluator2urlhaus_mod.is_global_ip
    monkeypatch.setattr(evaluator2urlhaus_mod, "is_global_ip", lambda value: value == PUBLIC_IP or real(value))
    with freeze_time("2026-01-01T13:00:00+00:00"):
        yield evaluator2urlhaus_mod


def test_urlhaus_sends_active_payload_urls_not_known_to_urlhaus(urlhaus, http_mock, config, db):
    urlhaus_candidate(db, "http://new.test/a.sh")
    urlhaus_candidate(db, "http://known.test/a.sh")
    urlhaus_candidate(db, "http://inactive.test/a.sh", status="inactive")
    urlhaus_candidate(db, "http://harmless.test/a.sh", classification="harmless")
    mock_urlhaus_lookup(http_mock, config, known=["http://known.test/a.sh"])
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()

    assert submit.call_count == 1
    request = submit.calls[0].request
    assert request.headers["Auth-Key"] == "test-urlhaus-key"
    assert json.loads(request.body) == {"anonymous": "0", "submission": [
        {"url": "http://new.test/a.sh", "threat": "malware_download", "tags": ["sh"]}]}
    assert urlhaus_rows(db) == [("http://known.test/a.sh", "known", None),
                                ("http://new.test/a.sh", "ok", '["sh"]')]
    lookups = [call.request for call in http_mock.calls if call.request.url == config.urlhaus_detail_url]
    assert len(lookups) == 2 and all(r.headers["Auth-Key"] == "test-urlhaus-key" for r in lookups)


def test_urlhaus_nothing_to_send(urlhaus, http_mock, db):
    insert_url(db, "http://inactive.test/a.sh", classification="malicious", status="inactive")

    urlhaus.evaluator2urlhaus()

    assert len(http_mock.calls) == 0


@pytest.mark.parametrize("content, download", [
    ({"file_category": "html", "magika_label": "html"}, {}),            # web page, not a payload
    ({"file_category": "empty", "magika_label": "empty"}, {}),
    ({}, {"fetched_at": "2025-12-30T12:00:00+00:00"}),                  # older than urlhaus_max_fetch_age_hours
    ({}, {"status_code": 302}),
    ({}, {"source_ip": "10.0.0.1"}),                                    # domain resolved to a private IP
])
def test_urlhaus_skips_urls_urlhaus_does_not_accept(urlhaus, http_mock, config, db, content, download):
    urlhaus_candidate(db, content=content, **download)
    mock_urlhaus_lookup(http_mock, config)
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()

    assert submit.call_count == 0 and urlhaus_rows(db) == []


@pytest.mark.parametrize("url", ["http://192.168.1.5/a.sh", "http://127.0.0.1/a.sh", "http://[fe80::1]/a.sh"])
def test_urlhaus_skips_private_ip_hosts(urlhaus, http_mock, config, db, url):
    urlhaus_candidate(db, url)
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()

    assert len(http_mock.calls) == 0 and submit.call_count == 0


def test_urlhaus_uses_only_the_latest_download(urlhaus, http_mock, config, db):
    content_id = urlhaus_candidate(db)
    insert_download(db, "http://new.test/a.sh", None, fetched_at="2026-01-01T12:30:00+00:00")  # now unavailable
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()

    assert content_id and submit.call_count == 0


def test_urlhaus_does_not_resend_submitted_or_known_urls(urlhaus, http_mock, config, db):
    urlhaus_candidate(db, "http://new.test/a.sh")
    urlhaus_candidate(db, "http://known.test/a.sh")
    mock_urlhaus_lookup(http_mock, config, known=["http://known.test/a.sh"])
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()
    urlhaus.evaluator2urlhaus()

    assert submit.call_count == 1 and len(http_mock.calls) == 3  # 2 lookups + 1 submit, nothing on the 2nd run


def test_urlhaus_retries_failed_submission(urlhaus, http_mock, config, db):
    urlhaus_candidate(db)
    mock_urlhaus_lookup(http_mock, config)
    submit = http_mock.post(config.urlhaus_submit_url, body="Auth-Key invalid", status=403)

    urlhaus.evaluator2urlhaus()
    urlhaus.evaluator2urlhaus()

    assert submit.call_count == 2
    assert [row[1] for row in urlhaus_rows(db)] == ["error", "error"]
    assert db.execute("SELECT response FROM urlhaus_submissions").fetchone()[0] == "HTTP 403: Auth-Key invalid"


@pytest.mark.parametrize("status", [500, None])  # HTTP error / connection error (no mock)
def test_urlhaus_skips_url_when_lookup_fails(urlhaus, http_mock, config, db, status):
    urlhaus_candidate(db)
    if status:
        mock_urlhaus_lookup(http_mock, config, status=status)
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()

    assert submit.call_count == 0 and urlhaus_rows(db) == []


def test_urlhaus_sends_in_batches(urlhaus, http_mock, config, db, monkeypatch):
    monkeypatch.setitem(config.config, "urlhaus_batch_size", 2)
    for i in range(5):
        urlhaus_candidate(db, f"http://new{i}.test/a.sh")
    mock_urlhaus_lookup(http_mock, config)
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()

    assert [len(batch) for batch in submitted(submit)] == [2, 2, 1]


def test_urlhaus_tags_miner_and_extra_tags(urlhaus, http_mock, config, db, monkeypatch):
    monkeypatch.setitem(config.config, "urlhaus_extra_tags", ["honeypot"])
    urlhaus_candidate(db, classification="miner", content={"file_category": "executable", "magika_label": "elf"})
    mock_urlhaus_lookup(http_mock, config)
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()

    assert submitted(submit)[0][0]["tags"] == ["elf", "CoinMiner", "honeypot"]


def tag_input(classification="malicious", magika_label=None, content_threat_label=None, url_threat_label=None):
    return {"classification": classification, "magika_label": magika_label,
            "content_threat_label": content_threat_label, "url_threat_label": url_threat_label}


@pytest.mark.parametrize("candidate, extra, expected", [
    (tag_input(magika_label="elf", url_threat_label="trojan.mirai/gafgyt"), (), ["elf", "mirai", "gafgyt"]),
    (tag_input(magika_label="pebin", url_threat_label="Mirai"), (), ["exe", "Mirai"]),
    (tag_input(content_threat_label="trojan.xmrig", url_threat_label="trojan.mirai"), (), ["xmrig"]),
    (tag_input(classification="miner", magika_label="unknown"), (), ["CoinMiner"]),
    (tag_input(magika_label="shell", url_threat_label="trojan.sh/SH"), ["honey_pot!", ""], ["sh", "honeypot"]),
    (tag_input(magika_label="zip", url_threat_label="a.b/c/d/e/f"), (), ["zip", "b", "c", "d", "e"]),
    (tag_input(), (), []),
])
def test_urlhaus_build_tags(evaluator2urlhaus_mod, candidate, extra, expected):
    assert evaluator2urlhaus_mod.build_tags(candidate, extra) == expected


@pytest.mark.parametrize("url, source_ip, expected", [
    ("http://8.8.8.8/a.sh", None, True),
    ("http://evil.test/a.sh", "8.8.8.8", True),
    ("http://evil.test/a.sh", None, True),
    ("http://10.1.2.3:8080/a.sh", None, False),
    ("http://100.64.0.1/a.sh", None, False),      # shared address space (RFC 6598)
    ("http://evil.test/a.sh", "192.168.0.1", False),
    ("http://[::1]/a.sh", None, False),
    ("http://[::1", None, False),
])
def test_urlhaus_is_public(evaluator2urlhaus_mod, url, source_ip, expected):
    assert evaluator2urlhaus_mod.is_public(url, source_ip) is expected


# --- evaluator2misp: MISP object of a URL ---

@pytest.mark.parametrize("url, expected", [
    ("http://192.0.2.1/a.sh", ("192.0.2.1|80", None)),
    ("https://192.0.2.1/a.sh", ("192.0.2.1|443", None)),
    ("http://192.0.2.1:8080/a.sh", ("192.0.2.1|8080", None)),
    ("http://evil.test/a.sh", (None, "evil.test")),
    ("http://[::1", (None, None)),
])
def test_extract_ip_domain_port(evaluator2misp_mod, url, expected):
    assert evaluator2misp_mod.extract_ip_domain_port(url) == expected


def db_row(url="http://192.0.2.1:8080/a.sh", status="active", classification="malicious", source="Warden",
           last_seen="2026-01-02", sha256="e3b0c442"):
    return {"url": url, "hash": "da39a3ee", "first_seen": "2026-01-01", "last_seen": last_seen,
            "file_mime_type": "application/x-sh", "threat_label": "mirai", "status": status,
            "classification": classification, "source": source, "sha256": sha256}


def attributes(obj):
    return {a.object_relation: a for a in obj.attributes}


def test_create_object_of_active_url(evaluator2misp_mod):
    attrs = attributes(evaluator2misp_mod.create_object(db_row()))

    assert attrs["url"].value == "http://192.0.2.1:8080/a.sh" and attrs["url"].to_ids is True
    assert [t.name for t in attrs["url"].tags] == ['rsit:malicious-code="malware-distribution"']
    assert attrs["ip-dst|port"].value == "192.0.2.1|8080" and attrs["ip-dst|port"].to_ids is True
    assert (attrs["hash"].value, attrs["malware-family"].value, attrs["source"].value) == ("da39a3ee", "mirai", "Warden")
    assert attrs["sha256"].value == "e3b0c442"
    assert "domain" not in attrs


def test_create_object_of_inactive_miner_on_domain(evaluator2misp_mod):
    attrs = attributes(evaluator2misp_mod.create_object(
        db_row(url="http://evil.test/xmrig", status="inactive", classification="miner")))

    assert attrs["url"].to_ids is False
    assert [t.name for t in attrs["url"].tags] == ["sentinel-threattype:CryptoMining"]
    assert attrs["domain"].value == "evil.test" and attrs["domain"].to_ids is False


# --- evaluator2misp: event synchronisation ---

def misp_object(module, row):
    obj = module.create_object(row)
    obj.id = str(abs(hash(row["url"])) % 10 ** 6)
    return obj


@pytest.fixture
def misp_event():
    """Existing MISP event (returned by search/get_event) with the two comment attributes."""
    event = MISPEvent()
    event.info = "Malicious URLs from SSH honeypots"
    event.id = "1"
    for uuid in COMMENT_UUIDS:
        event.add_attribute("comment", "Generated by URL Evaluator", uuid=uuid)
    return event


@pytest.fixture
def misp(fake_misp, misp_event):
    fake_misp.search.return_value = [misp_event]
    fake_misp.get_event.return_value = misp_event
    fake_misp.update_event.side_effect = lambda event, pythonify: event
    return fake_misp


def objects_by_url(event):
    return {attributes(o)["url"].value: o for o in event.objects if not getattr(o, "deleted", False)}


@freeze_time("2026-03-01")
def test_sync_adds_new_updates_changed_and_deletes_old_urls(evaluator2misp_mod, misp, misp_event, db):
    insert_url(db, "http://new.test/a.sh", classification="malicious", status="active", last_seen="2026-02-28")
    insert_url(db, "http://192.0.2.1/x86", classification="malicious", status="inactive", last_seen="2026-02-28")
    insert_source(db, "http://192.0.2.1/x86", "Warden")
    insert_source(db, "http://192.0.2.1/x86", "HoneyNet.Asia")
    insert_url(db, "http://too-old.test/", classification="malicious", last_seen="2025-12-01")  # misp_max_age: 60
    insert_download(db, "http://192.0.2.1/x86", insert_content(db, b"old"), fetched_at="2026-02-27T00:00:00")
    insert_download(db, "http://192.0.2.1/x86", insert_content(db, b"new"), fetched_at="2026-02-28T00:00:00")
    misp_event.add_object(misp_object(evaluator2misp_mod, db_row(
        url="http://192.0.2.1/x86", status="active", source="Warden", last_seen="2026-01-01")))
    misp_event.add_object(misp_object(evaluator2misp_mod, db_row(url="http://deleted.test/")))

    evaluator2misp_mod.sync_urls(misp, db)

    synced = objects_by_url(misp.update_event.call_args.args[0])
    assert set(synced) == {"http://new.test/a.sh", "http://192.0.2.1/x86"}
    changed = attributes(synced["http://192.0.2.1/x86"])
    assert changed["url"].to_ids is False and changed["ip-dst|port"].to_ids is False  # became inactive
    assert str(changed["last-seen"].value).startswith("2026-02-28")
    assert sorted(changed["source"].value.split(", ")) == ["HoneyNet.Asia", "Warden"]
    assert changed["sha256"].value == hashlib.sha256(b"new").hexdigest()  # the latest download
    assert "sha256" not in attributes(synced["http://new.test/a.sh"])  # nothing downloaded
    misp.publish.assert_called_once_with("1", alert=False)
    assert misp.update_attribute.call_count == 2  # comment attributes refreshed


def test_sync_creates_tagged_event_when_missing(evaluator2misp_mod, misp, misp_event, db):
    insert_url(db, "http://new.test/a.sh", classification="malicious", last_seen="2099-01-01")
    misp.search.return_value = []
    misp.add_event.return_value = misp_event

    evaluator2misp_mod.sync_urls(misp, db)

    assert misp.add_event.call_args.args[0].info == "Malicious URLs from SSH honeypots"
    assert "tlp:clear" in [c.args[1] for c in misp.tag.call_args_list]


def test_sync_without_malicious_urls_does_not_touch_misp(evaluator2misp_mod, misp, db):
    insert_url(db, "http://harmless.test/", classification="harmless")

    evaluator2misp_mod.sync_urls(misp, db)

    misp.search.assert_not_called()
    misp.update_event.assert_not_called()


def test_sightings_of_urls_seen_yesterday(evaluator2misp_mod, misp, db):
    # no freeze_time: pysqlite3 cannot bind freezegun's FakeDate (the query parameter is a date object)
    today = datetime.now(timezone.utc).date()
    yesterday = (today - timedelta(days=1)).isoformat()
    insert_url(db, "http://yesterday.test/", classification="malicious", last_seen=yesterday)
    insert_url(db, "http://miner.test/", classification="miner", last_seen=yesterday)
    insert_url(db, "http://today.test/", classification="malicious", last_seen=today.isoformat())
    insert_url(db, "http://harmless.test/", classification="harmless", last_seen=yesterday)

    evaluator2misp_mod.add_yesterdays_sightings(misp, db)

    assert sorted(c.args[0]["value"] for c in misp.add_sighting.call_args_list) == [
        "http://miner.test/", "http://yesterday.test/"]


@pytest.mark.parametrize("module", ["evaluator2misp", "evaluator2misp_bysource"])
def test_misp_connection_error_ends_the_job(init_bin, monkeypatch, caplog, module):
    # a scheduler job must not call sys.exit(), the next run tries again
    exporter = init_bin(module)

    def unreachable(*args, **kwargs):
        raise ConnectionError("MISP down")
    monkeypatch.setattr(exporter, "PyMISP", unreachable)

    getattr(exporter, module)()

    assert "Error while connecting to MISP" in caplog.text


@pytest.mark.parametrize("module", ["evaluator2misp", "evaluator2misp_bysource"])
def test_failed_sync_ends_the_job(init_bin, fake_misp, monkeypatch, caplog, module):
    exporter = init_bin(module)
    monkeypatch.setattr(exporter, "PyMISP", lambda *args, **kwargs: fake_misp)

    def broken(misp, db):
        raise RuntimeError("MISP returned 500")
    monkeypatch.setattr(exporter, "sync_urls", broken)

    getattr(exporter, module)()

    assert "Failed to sync data with MISP" in caplog.text


# --- evaluator2misp_bysource: one MISP event per honeynet ---

@pytest.fixture
def events_by_source(fake_misp):
    """get_or_create_event() of every source returns its own empty event."""
    events = {}

    def search(eventinfo, **kwargs):
        if eventinfo not in events:  # the id must stay the same over repeated syncs
            event = events[eventinfo] = MISPEvent()
            event.info, event.id = eventinfo, str(len(events))
        return [events[eventinfo]]
    fake_misp.search.side_effect = search
    fake_misp.get_event.side_effect = lambda event_id, pythonify: next(e for e in events.values() if e.id == event_id)
    fake_misp.update_event.side_effect = lambda event, pythonify: event
    return events


def event_urls(events, source):
    event = events[f"Malicious URLs from SSH honeypots ({source})"]
    return set(objects_by_url(event))


def test_bysource_sorts_urls_into_events_of_their_source(evaluator2misp_bysource_mod, fake_misp, events_by_source, db):
    loader = insert_url(db, "http://loader.test/a.sh", classification="malicious", last_seen="2099-01-01")
    payload = insert_url(db, "http://loader.test/x86", classification="malicious", last_seen="2099-01-01")
    insert_source(db, loader, "HoneyNet.Asia")
    insert_source(db, payload, "URL content")  # found in the loader -> source of the loader
    insert_discovered(db, payload, loader)

    evaluator2misp_bysource_mod.sync_urls(fake_misp, db)

    assert event_urls(events_by_source, "HoneyNet.Asia") == {loader, payload}
    assert event_urls(events_by_source, "CESNET Hugo") == set()
    assert fake_misp.publish.call_count == 4  # every source event is published


def test_bysource_exports_warden_url_to_its_honeynet_event(
        warden2evaluator_mod, evaluator2misp_bysource_mod, fake_misp, events_by_source, db):
    event = load_json("idea", "cowrie_session.json")  # Node.SW hugo-cowrie -> CESNET Hugo
    urls = warden2evaluator_mod.handle_events([event])
    db.execute("UPDATE urls SET classification = 'malicious', last_seen = '2099-01-01'")

    evaluator2misp_bysource_mod.sync_urls(fake_misp, db)

    assert event_urls(events_by_source, "CESNET Hugo") == set(urls)


def test_bysource_url_content_without_discovered_source_does_not_stop_sync(
        evaluator2misp_bysource_mod, fake_misp, events_by_source, db):
    orphan = insert_url(db, "http://orphan.test/x86", classification="malicious", last_seen="2099-01-01")
    insert_source(db, orphan, "URL content")  # its loader is gone
    other = insert_url(db, "http://hna.test/a.sh", classification="malicious", last_seen="2099-01-01")
    insert_source(db, other, "HoneyNet.Asia")

    evaluator2misp_bysource_mod.sync_urls(fake_misp, db)

    assert event_urls(events_by_source, "HoneyNet.Asia") == {other}
    assert fake_misp.publish.call_count == 4


def test_bysource_nested_download_goes_to_the_source_of_the_first_url(
        evaluator2misp_bysource_mod, fake_misp, events_by_source, db):
    loader = insert_url(db, "http://loader.test/a.sh", classification="malicious", last_seen="2099-01-01")
    stage2 = insert_url(db, "http://loader.test/b.sh", classification="malicious", last_seen="2099-01-01")
    payload = insert_url(db, "http://loader.test/x86", classification="malicious", last_seen="2099-01-01")
    insert_source(db, loader, "GEANT T-Pot")
    for url, src in ((stage2, loader), (payload, stage2)):
        insert_source(db, url, "URL content")
        insert_discovered(db, url, src)

    evaluator2misp_bysource_mod.sync_urls(fake_misp, db)

    assert event_urls(events_by_source, "GEANT T-Pot") == {loader, stage2, payload}


def test_bysource_exports_sha256_of_the_latest_download(evaluator2misp_bysource_mod, fake_misp, events_by_source, db):
    url = insert_url(db, "http://hna.test/a.sh", classification="malicious", last_seen="2099-01-01")
    insert_source(db, url, "HoneyNet.Asia")
    insert_download(db, url, insert_content(db, b"old"), fetched_at="2026-02-27T00:00:00")

    evaluator2misp_bysource_mod.sync_urls(fake_misp, db)  # creates the object
    insert_download(db, url, insert_content(db, b"new"), fetched_at="2026-02-28T00:00:00")
    evaluator2misp_bysource_mod.sync_urls(fake_misp, db)  # updates it

    event = events_by_source["Malicious URLs from SSH honeypots (HoneyNet.Asia)"]
    assert attributes(objects_by_url(event)[url])["sha256"].value == hashlib.sha256(b"new").hexdigest()


@pytest.mark.parametrize("module", ["evaluator2misp", "evaluator2misp_bysource"])
def test_sync_keeps_objects_it_did_not_create(init_bin, fake_misp, misp_event, db, module):
    exporter = init_bin(module)
    fake_misp.search.return_value = [misp_event]
    fake_misp.get_event.return_value = misp_event
    fake_misp.update_event.side_effect = lambda event, pythonify: event
    foreign = MISPObject("file")
    foreign.add_attribute("filename", "added-by-analyst.sh")
    misp_event.add_object(foreign)
    url = insert_url(db, "http://new.test/a.sh", classification="malicious", last_seen="2099-01-01")
    insert_source(db, url, "HoneyNet.Asia")

    exporter.sync_urls(fake_misp, db)

    names = [o.name for o in fake_misp.update_event.call_args.args[0].objects if not getattr(o, "deleted", False)]
    assert "file" in names and "url-honeypot-detection" in names


def test_urlhaus_skips_url_with_unexpected_lookup_answer(urlhaus, http_mock, config, db):
    urlhaus_candidate(db)
    http_mock.post(config.urlhaus_detail_url, json={"query_status": "invalid_url"})
    submit = http_mock.post(config.urlhaus_submit_url, body="ok")

    urlhaus.evaluator2urlhaus()

    assert submit.call_count == 0 and urlhaus_rows(db) == []


def test_urlhaus_submission_connection_error_is_recorded(urlhaus, http_mock, config, db):
    urlhaus_candidate(db)
    mock_urlhaus_lookup(http_mock, config)  # submit URL not mocked -> ConnectionError

    urlhaus.evaluator2urlhaus()

    status, response = db.execute("SELECT status, response FROM urlhaus_submissions").fetchone()
    assert status == "error" and "Connection refused" in response


@freeze_time("2026-03-01")
def test_sync_completes_object_without_last_seen_and_source(evaluator2misp_mod, misp, misp_event, db):
    url = insert_url(db, "http://old.test/a.sh", classification="malicious", status="active", last_seen="2026-02-28")
    insert_source(db, url, "Warden")
    obj = MISPObject("url-honeypot-detection")  # created by an older version
    obj.add_attribute(object_relation="url", simple_value=url, Attribute={"type": "url", "value": url, "to_ids": True})
    misp_event.add_object(obj)

    evaluator2misp_mod.sync_urls(misp, db)

    attrs = attributes(objects_by_url(misp.update_event.call_args.args[0])[url])
    assert (str(attrs["last-seen"].value)[:10], attrs["source"].value) == ("2026-02-28", "Warden")
