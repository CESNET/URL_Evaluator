#Author: Lukáš Šimoník, xsimonl00@stud.fit.vutbr.cz

"""
Hybrid Analysis (Falcon Sandbox) hash lookups and manual submissions of stored content.

For each payload stored by ``content_store``, its SHA-256 is looked up to see
whether the sample has already been detonated. The result is stored as JSON in
``content.sandbox_info`` under the ``"hybrid_analysis"`` key.

Samples are never submitted automatically. An analyst can submit a sample
from the web UI (``submit_content``), but only when ``GET /overview/{sha256}``
answered HTTP 404 (hash never analysed). The submission is logged in the
``sandbox_submissions`` table and its API answer is stored in
``content.sandbox_info`` under the ``"hybrid_analysis_submission"`` key.
"""

import json
import time
import logging
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "https://hybrid-analysis.com/api/v2"
SAMPLE_URL = "https://hybrid-analysis.com/sample/{sha256}"
# Default minimum age of a stored lookup before the hash is queried again.
DEFAULT_RECHECK_HOURS = 12
# HTTP statuses that are a valid answer: 404 = "Requested hash not found",
# i.e. the sample has never been analysed on Hybrid Analysis.
_ANSWER_STATUSES = (200, 404)
# Back-off after HTTP 429 when the server does not say how long to wait.
DEFAULT_BACKOFF_SECONDS = 3600

# Name of this sandbox in the sandbox_submissions table.
SANDBOX_NAME = "hybrid_analysis"
# Analysis environments accepted by POST /submit/file (environment_id -> name).
ENVIRONMENTS = {
    330: "Linux (Ubuntu 24.04, 64 bit)",
    160: "Windows 10 64 bit",
    140: "Windows 11 64 bit",
    120: "Windows 7 64 bit",
    100: "Windows 7 32 bit",
    110: "Windows 7 32 bit (HWP Support)",
    200: "Android Static Analysis",
    430: "macOS Tahoe (ARM64)",
}
# Honeypot downloads are mostly Linux binaries and shell scripts.
DEFAULT_ENVIRONMENT_ID = 330
# Submissions that are still valid -- a hash is not submitted again while one exists.
_ACTIVE_SUBMISSION_STATUSES = ("pending", "running", "done")

# Overview fields worth keeping (the full Overview object is large).
_OVERVIEW_FIELDS = (
    "verdict", "threat_score", "vx_family", "tags", "last_file_name",
    "type", "type_short", "size", "architecture", "multiscan_result",
    "submitted_at", "analysis_start_time", "last_multi_scan", "whitelisted",
)

# Rate-limit state shared by all threads of the process (activity_scanner
# runs lookups from several worker threads).
_lock = threading.Lock()
_blocked_until = None

# Every HTTP request sent to the API (monotonic timestamps + status), so a
# caller can verify the per-minute quota is not exceeded (see request_stats).
_stats_lock = threading.Lock()
_request_times = []
_request_statuses = Counter()
_last_api_limits = None


def reset_request_stats():
    """Forget all recorded API requests (call at the start of a run)."""
    global _last_api_limits
    with _stats_lock:
        _request_times.clear()
        _request_statuses.clear()
        _last_api_limits = None


def request_stats():
    """
    Summary of the API requests recorded since reset_request_stats():
    total count, count per HTTP status (or exception name), the highest number
    of requests in any 60 s window and the last Api-Limits header received.
    """
    with _stats_lock:
        times = sorted(_request_times)
        statuses = dict(_request_statuses)
        api_limits = _last_api_limits
    peak, start = 0, 0
    for end, t in enumerate(times):
        while t - times[start] >= 60:
            start += 1
        peak = max(peak, end - start + 1)
    return {"requests": len(times), "by_status": statuses,
            "peak_per_minute": peak, "api_limits": api_limits}


def _get(url, **kwargs):
    """GET via _request(); statuses in _ANSWER_STATUSES (e.g. 404 = hash not
    analysed yet) are valid answers and are not logged as unexpected."""
    return _request("GET", url, _ANSWER_STATUSES, **kwargs)


def _request(method, url, expected_statuses, **kwargs):
    """requests.request() that records the request for request_stats() and logs
    every unexpected status (429 included) clearly."""
    global _last_api_limits
    try:
        r = requests.request(method, url, **kwargs)
    except requests.exceptions.RequestException as e:
        with _stats_lock:
            _request_times.append(time.monotonic())
            _request_statuses[type(e).__name__] += 1
        raise
    limits = _parse_api_limits(r)
    with _stats_lock:
        _request_times.append(time.monotonic())
        _request_statuses[r.status_code] += 1
        if limits is not None:
            _last_api_limits = limits
    if r.status_code not in expected_statuses:
        logger.warning(
            f"Hybrid Analysis API returned HTTP {r.status_code} for {method} {url.split('/api/v2', 1)[-1]}"
            f" (Retry-After: {r.headers.get('Retry-After')}, Api-Limits: {limits})"
        )
    return r


def _api_settings(config):
    """Return (api_url, api_key) or (None, None) when the lookup is not configured."""
    key = getattr(config, "ha_key", None)
    if not key or "CHANGE THIS" in str(key):
        logger.warning("No Hybrid api key provided")
        return None, None
    return getattr(config, "ha_url", None) or DEFAULT_API_URL, key


def is_enabled(config):
    return _api_settings(config)[1] is not None


def _headers(api_key):
    return {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox",  # the API rejects requests without it
        "accept": "application/json",
    }


def _parse_json_header(response, name):
    raw = response.headers.get(name)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _parse_api_limits(response):
    return _parse_json_header(response, "Api-Limits")


def _json_or_text(response):
    try:
        return response.json()
    except ValueError:
        return response.text[:2000]


def _rate_limited():
    with _lock:
        return _blocked_until is not None and datetime.now(timezone.utc) < _blocked_until


def paused_until():
    """Return when lookups resume after an HTTP 429 (UTC datetime), or None when not paused."""
    with _lock:
        if _blocked_until is not None and datetime.now(timezone.utc) < _blocked_until:
            return _blocked_until
        return None


def _block(response):
    """Pause all lookups after HTTP 429 (honours Retry-After when present)."""
    global _blocked_until
    try:
        delay = int(response.headers.get("Retry-After", DEFAULT_BACKOFF_SECONDS))
    except ValueError:
        delay = DEFAULT_BACKOFF_SECONDS
    with _lock:
        _blocked_until = datetime.now(timezone.utc) + timedelta(seconds=delay)
    logger.warning(f"Hybrid Analysis rate limit hit, lookups paused for {delay} s")


def lookup_sha256(config, sha256):
    """
    Ask Hybrid Analysis whether `sha256` has already been analysed.

    Returns the result dict described in the module docstring, or None when
    the lookup is disabled (no API key) or paused due to rate limiting.
    Never raises.
    """
    api_url, api_key = _api_settings(config)
    if api_key is None or _rate_limited():
        logger.debug(f"Hybrid Analysis lookup of {sha256} skipped (disabled or rate-limited)")
        return None

    result = {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": sha256,
        "http_status": None,
        "tested": False,
        "error": None,
        "api_limits": None,
        "reports": [],
        "overview": None,
        "sample_url": None,
        "response": None,
    }
    try:
        r = _get(f"{api_url}/overview/{sha256}", headers=_headers(api_key), timeout=30)
    except requests.exceptions.RequestException as e:
        logger.warning(f"Hybrid Analysis lookup of {sha256} failed: {e}")
        result["error"] = f"Request failed: {type(e).__name__}"
        return result

    result["http_status"] = r.status_code
    result["api_limits"] = _parse_api_limits(r)
    body = _json_or_text(r)
    result["response"] = body

    if r.status_code == 429:
        _block(r)
    if r.status_code == 404:
        logger.debug(f"Hybrid Analysis: {sha256} has not been analysed yet")
        return result
    if not r.ok or not isinstance(body, dict):
        message = body.get("message") if isinstance(body, dict) else None
        result["error"] = message or f"HTTP {r.status_code}"
        logger.warning(f"Hybrid Analysis lookup of {sha256} returned HTTP {r.status_code}: {result['error']}")
        return result

    # An Overview exists -> Hybrid Analysis knows the hash.
    result["tested"] = True
    result["sample_url"] = SAMPLE_URL.format(sha256=sha256)
    result["overview"] = {k: body.get(k) for k in _OVERVIEW_FIELDS if body.get(k) not in (None, "", [])}
    # Per-environment verdicts of this sample; Overview.reports holds only report IDs.
    related = [rep for rep in (body.get("related_reports") or [])
               if isinstance(rep, dict) and rep.get("sha256") in (None, sha256)]
    result["reports"] = related or [{"job_id": rid} for rid in (body.get("reports") or [])]
    logger.info(f"Hybrid Analysis: {sha256} already analysed ({len(result['reports'])} report(s))")
    return result


def _load_sandbox_info(raw):
    """Return the parsed content.sandbox_info JSON, or an empty dict when missing or invalid."""
    if not raw:
        return {}
    try:
        info = json.loads(raw)
        return info if isinstance(info, dict) else {}
    except ValueError:
        return {}


def get_lookup(sandbox_info_json):
    """Return the stored Hybrid Analysis result from a content.sandbox_info value."""
    return _load_sandbox_info(sandbox_info_json).get("hybrid_analysis")


def get_submission(sandbox_info_json):
    """Return the stored POST /submit/file result from a content.sandbox_info value."""
    return _load_sandbox_info(sandbox_info_json).get("hybrid_analysis_submission")


def is_submittable(lookup):
    """True when the stored lookup says the hash was never analysed (GET /overview/{sha256} -> HTTP 404)."""
    return bool(lookup) and lookup.get("http_status") == 404


def check_content(db, config, content_id, sha256, force=False):
    """
    Look up a stored content sample on Hybrid Analysis and persist the result
    into ``content.sandbox_info``.

    The query is skipped when the previous successful lookup of this content is
    younger than ``ha_recheck_hours`` (default 12 h) unless `force` is set, so
    the same payload served by many URLs costs a single API call per run.

    Returns the (new or cached) result dict, or None. Never raises.
    """
    return check_content_outcome(db, config, content_id, sha256, force)[0]


def check_content_outcome(db, config, content_id, sha256, force=False):
    """
    Same as check_content(), but returns ``(result, outcome)`` where outcome is
      * 'checked' -- the API answered now (200 / 404) and the result was stored
      * 'cached'  -- a recent stored answer was reused, no request was sent
      * 'failed'  -- the API request failed (e.g. HTTP 429, 5xx, timeout)
      * 'skipped' -- lookup disabled, paused after a 429, or no content
    """
    if content_id is None or not sha256 or not is_enabled(config):
        return None, "skipped"
    try:
        row = db.execute("SELECT sandbox_info FROM content WHERE id = ?", (content_id,)).fetchone()
        info = _load_sandbox_info(row[0] if row else None)
        previous = info.get("hybrid_analysis")

        # A lookup marked stale (the sample was submitted since) is never reused.
        if (previous and not force and not previous.get("stale")
                and previous.get("http_status") in _ANSWER_STATUSES):
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(previous["checked_at"])
                if age < timedelta(hours=getattr(config, "ha_recheck_hours", DEFAULT_RECHECK_HOURS)):
                    return previous, "cached"
            except (KeyError, TypeError, ValueError):
                pass

        result = lookup_sha256(config, sha256)
        if result is None:
            return previous, "skipped"
        outcome = "checked" if result["http_status"] in _ANSWER_STATUSES else "failed"
        # Keep a previous successful answer when this attempt failed.
        if (outcome == "failed" and previous
                and previous.get("http_status") in _ANSWER_STATUSES):
            previous["last_error"] = {"checked_at": result["checked_at"],
                                      "http_status": result["http_status"],
                                      "error": result["error"]}
            result = previous
        info["hybrid_analysis"] = result
        db.execute("UPDATE content SET sandbox_info = ? WHERE id = ?", (json.dumps(info), content_id))
        return result, outcome
    except Exception as e:
        logger.warning(f"Could not store Hybrid Analysis result for content {content_id}: {e}")
        return None, "failed"


def submit_file(config, file_path, sha256, environment_id, comment=None):
    """
    Send a stored sample to Hybrid Analysis (POST /submit/file).

    Returns a result dict (``submission_id`` / ``job_id`` are set on success,
    ``error`` otherwise), or None when the API is disabled or paused due to
    rate limiting. Never raises.
    """
    api_url, api_key = _api_settings(config)
    if api_key is None or _rate_limited():
        logger.debug(f"Hybrid Analysis submission of {sha256} skipped (disabled or rate-limited)")
        return None

    result = {
        "submitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": sha256,
        "environment_id": environment_id,
        "http_status": None,
        "error": None,
        "job_id": None,
        "submission_id": None,
        "api_limits": None,
        "submission_limits": None,
        "sample_url": None,
        "response": None,
    }
    data = {"environment_id": environment_id}
    if comment:
        data["comment"] = comment
    try:
        with open(file_path, "rb") as f:
            # The file name only serves file type detection, the sample is
            # stored on disk under its SHA-256.
            r = _request("POST", f"{api_url}/submit/file", (201,),
                         headers=_headers(api_key), data=data,
                         files={"file": (f"{sha256}.bin", f, "application/octet-stream")},
                         timeout=120, allow_redirects=False)  # a redirect would turn the POST into GET
    except OSError as e:
        logger.warning(f"Hybrid Analysis submission of {sha256}: cannot read {file_path}: {e}")
        result["error"] = f"Cannot read stored sample: {type(e).__name__}"
        return result
    except requests.exceptions.RequestException as e:
        logger.warning(f"Hybrid Analysis submission of {sha256} failed: {e}")
        result["error"] = f"Request failed: {type(e).__name__}"
        return result

    result["http_status"] = r.status_code
    result["api_limits"] = _parse_api_limits(r)
    result["submission_limits"] = _parse_json_header(r, "Submission-Limits")
    body = _json_or_text(r)
    result["response"] = body

    if r.status_code == 429:
        _block(r)
    if r.status_code != 201:
        message = body.get("message") if isinstance(body, dict) else None
        result["error"] = message or f"HTTP {r.status_code}"
        logger.warning(f"Hybrid Analysis submission of {sha256} returned HTTP {r.status_code}: {result['error']}")
        return result

    if isinstance(body, dict):
        result["job_id"] = body.get("job_id")
        result["submission_id"] = body.get("submission_id")
    result["sample_url"] = SAMPLE_URL.format(sha256=sha256)
    logger.info(f"Hybrid Analysis: {sha256} submitted (environment {environment_id}, "
                f"job {result['job_id']}, submission {result['submission_id']})")
    return result


def latest_submission(db, sha256):
    """
    Return the newest Hybrid Analysis row of ``sandbox_submissions`` for
    `sha256` as a dict, or None.
    """
    row = db.execute(
        "SELECT submitted_at, submitted_by, status, report_url FROM sandbox_submissions "
        "WHERE sha256 = ? AND sandbox_name = ? ORDER BY submitted_at DESC, id DESC LIMIT 1",
        (sha256, SANDBOX_NAME),
    ).fetchone()
    if not row:
        return None
    return {"submitted_at": row[0], "submitted_by": row[1], "status": row[2], "report_url": row[3]}


def submit_content(db, config, content_id, file_path, sha256, user, environment_id):
    """
    Submit a stored content sample to Hybrid Analysis on behalf of `user`.

    The sample is sent only when no active submission of the hash exists and a
    fresh GET /overview/{sha256} answers HTTP 404 (never analysed). Every attempt that
    reaches POST /submit/file is logged in ``sandbox_submissions``.

    Returns ``(result, outcome)`` where outcome is
      * 'submitted'         -- the API accepted the sample (HTTP 201)
      * 'already_submitted' -- an active submission of this hash exists
      * 'already_analysed'  -- the hash lookup did not answer 404
      * 'lookup_failed'     -- the hash lookup failed (e.g. 429, 5xx, timeout)
      * 'submit_failed'     -- POST /submit/file failed
      * 'skipped'           -- API disabled or paused after a 429
    Never raises.
    """
    if not is_enabled(config):
        return None, "skipped"
    try:
        previous = latest_submission(db, sha256)
        if previous and previous["status"] in _ACTIVE_SUBMISSION_STATUSES:
            return previous, "already_submitted"

        lookup, outcome = check_content_outcome(db, config, content_id, sha256, force=True)
        if outcome == "skipped":
            return lookup, "skipped"
        if outcome != "checked":
            return lookup, "lookup_failed"
        if not is_submittable(lookup):
            return lookup, "already_analysed"

        result = submit_file(config, file_path, sha256, environment_id,
                             comment=getattr(config, "ha_submit_comment", None))
        if result is None:
            return None, "skipped"
        ok = result["error"] is None
        db.execute(
            "INSERT INTO sandbox_submissions (content_id, sha256, sandbox_name, submitted_at, "
            "submitted_by, status, report_url) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (content_id, sha256, SANDBOX_NAME, result["submitted_at"], user,
             "pending" if ok else "error", result["sample_url"]),
        )
        row = db.execute("SELECT sandbox_info FROM content WHERE id = ?", (content_id,)).fetchone()
        info = _load_sandbox_info(row[0] if row else None)
        info["hybrid_analysis_submission"] = result
        # The sample gets a report soon -- make the next evaluator /
        # activity_scanner run query the hash again instead of reusing the 404.
        if ok and info.get("hybrid_analysis"):
            info["hybrid_analysis"]["stale"] = True
        db.execute("UPDATE content SET sandbox_info = ? WHERE id = ?", (json.dumps(info), content_id))
        return result, "submitted" if ok else "submit_failed"
    except Exception as e:
        logger.warning(f"Could not submit content {content_id} to Hybrid Analysis: {e}")
        return None, "submit_failed"
