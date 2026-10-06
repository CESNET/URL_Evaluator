#Author: Lukáš Šimoník, xsimonl00@stud.fit.vutbr.cz

"""
Read-only Hybrid Analysis (Falcon Sandbox) hash lookups for stored content.

For each payload stored by ``content_store``, its SHA-256 is looked up to see
whether the sample has already been detonated. Nothing is ever submitted.
The result is stored as JSON in ``content.sandbox_info`` under the
``"hybrid_analysis"`` key.
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
    """requests.get() that records the request for request_stats() and logs
    every unexpected status (429 included) clearly."""
    global _last_api_limits
    try:
        r = requests.get(url, **kwargs)
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
    if r.status_code not in _ANSWER_STATUSES:
        logger.warning(
            f"Hybrid Analysis API returned HTTP {r.status_code} for {url.split('/api/v2', 1)[-1]}"
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


def _parse_api_limits(response):
    raw = response.headers.get("Api-Limits")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return raw


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
        r = _get(f"{api_url}/search/hash", params={"hash": sha256},
                 headers=_headers(api_key), timeout=30)
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
    if not r.ok:
        message = body.get("message") if isinstance(body, dict) else None
        result["error"] = message or f"HTTP {r.status_code}"
        logger.warning(f"Hybrid Analysis lookup of {sha256} returned HTTP {r.status_code}: {result['error']}")
        return result

    reports = body.get("reports") if isinstance(body, dict) else None
    result["reports"] = reports or []
    result["tested"] = bool(reports)
    if not result["tested"]:
        logger.debug(f"Hybrid Analysis: {sha256} has not been analysed yet")
        return result

    result["sample_url"] = SAMPLE_URL.format(sha256=sha256)
    logger.info(f"Hybrid Analysis: {sha256} already analysed ({len(reports)} report(s))")

    # Aggregated verdict / threat score (best effort, not fatal).
    try:
        o = _get(f"{api_url}/overview/{sha256}", headers=_headers(api_key), timeout=30)
        if o.status_code == 429:
            _block(o)
        elif o.ok and isinstance(ov := _json_or_text(o), dict):
            result["overview"] = {k: ov.get(k) for k in _OVERVIEW_FIELDS if ov.get(k) not in (None, "", [])}
    except requests.exceptions.RequestException as e:
        logger.debug(f"Hybrid Analysis overview of {sha256} failed: {e}")
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

        if previous and not force and previous.get("http_status") in _ANSWER_STATUSES:
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
