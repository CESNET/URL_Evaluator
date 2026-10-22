"""
Helpers registering stored external API responses (tests/data/<service>/)
on the `http_mock` fixture (responses.RequestsMock).

    mock_blacklist(http_mock, config, ["http://evil.test/a.sh"])
    mock_vt(http_mock, "urls", "url_malicious.json")
"""

import json
import os
import re

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# virustotal_python always talks to this base URL (config.vt_url is not used)
VT_API = "https://www.virustotal.com/api/v3/"


def data_path(*parts):
    """Absolute path of a file in tests/data/."""
    return os.path.join(DATA_DIR, *parts)


def load_json(*parts):
    with open(data_path(*parts), encoding="utf-8") as f:
        return json.load(f)


def load_bytes(*parts):
    with open(data_path(*parts), "rb") as f:
        return f.read()


def mock_blacklist(http_mock, config, urls=None):
    """URLhaus text blacklist: the given URLs, or tests/data/urlhaus/blacklist.txt."""
    body = "\n".join(["# test blacklist", *urls]) if urls is not None else load_bytes("urlhaus", "blacklist.txt")
    return http_mock.get(config.urlhaus_blacklist_url, body=body)


def mock_mb(http_mock, config, known=False):
    """MalwareBazaar get_info: known hash (query_status ok) or hash_not_found."""
    return http_mock.post(config.mb_url, json=load_json("mb", "query_ok.json" if known else "hash_not_found.json"))


def mock_vt(http_mock, collection, fixture="not_found.json", status=None):
    """
    VirusTotal v3 GET /<collection>/<id> (collection: "urls" or "files").
    Status defaults to 404 for not_found.json, 429 for quota_exceeded.json, else 200.
    """
    if status is None:
        status = {"not_found.json": 404, "quota_exceeded.json": 429}.get(fixture, 200)
    return http_mock.get(re.compile(re.escape(VT_API + collection + "/") + ".+"),
                         json=load_json("vt", fixture), status=status)


def mock_ha_overview(http_mock, config, sha256=None, status=200, headers=None):
    """
    Hybrid Analysis GET /overview/{sha256}: 200 (overview_200.json), 404
    (not_found.json) or 429 (rate_limited.json). Any sha256 when None.
    """
    fixture = {200: "overview_200.json", 404: "not_found.json", 429: "rate_limited.json"}[status]
    body = load_json("ha", fixture)
    if status == 200 and sha256:
        body["sha256"] = sha256
    url = f"{config.ha_url}/overview/" + (re.escape(sha256) if sha256 else ".+")
    return http_mock.get(re.compile(url), json=body, status=status, headers=headers or {})


def mock_ha_submit(http_mock, config, status=201):
    """Hybrid Analysis POST /submit/file: accepted (201) or the given error status."""
    body = {"job_id": "job-1", "submission_id": "sub-1"} if status == 201 else {"message": "error"}
    return http_mock.post(f"{config.ha_url}/submit/file", json=body, status=status)


def mock_external_apis(http_mock, config, blacklist=(), mb_known=False, vt_url="not_found.json",
                       vt_file="not_found.json", ha_status=404):
    """
    Register every external API evaluate_url() may call, with "nothing known"
    defaults: empty blacklist, unknown hash on MalwareBazaar, VirusTotal 404,
    Hybrid Analysis 404 (submissions accepted). Returns a dict of the
    registered responses (for call counts).
    """
    return {
        "blacklist": mock_blacklist(http_mock, config, list(blacklist)),
        "mb": mock_mb(http_mock, config, known=mb_known),
        "vt_url": mock_vt(http_mock, "urls", vt_url),
        "vt_file": mock_vt(http_mock, "files", vt_file),
        "ha": mock_ha_overview(http_mock, config, status=ha_status),
        "ha_submit": mock_ha_submit(http_mock, config),
    }
