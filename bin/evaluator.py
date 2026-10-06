#!/usr/bin/env python3

import os
import signal
import sys
import json
import time
import argparse
import hashlib
import magic
import requests
import logging
import virustotal_python
from collections import Counter
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.utils import is_valid, extract_commands, process_new_session
try:
    from common import content_store
except Exception:
    content_store = None
try:
    from common import hybrid_analysis
except Exception:
    hybrid_analysis = None


def vt_stats_analysis(stats):
    """
    Try to classify URL based on VT 'last_analysis_stats'
    """

    if (total := sum(stats.values())):
        if (stats.get('malicious', 0) / total) > config.vt_threshold['malicious']:
            return 'malicious'
        if (stats.get('harmless', 0) / total) > config.vt_threshold['harmless']:
            return 'harmless'
    return 'unclassified'


def vt_request(resource_type, resource_id):
    """
    Perform a VirusTotal API request for files or urls and check last analysis stats
    """

    global vt_daily_quota_exceeded   # True once the VT daily request quota is hit (skip VT until next day)
    global vt_daily_quota_timestamp  # time when the daily quota was exceeded (used to detect the next-day reset)
    global vt_minute_quota           # max VT requests allowed per minute (from config)
    global vt_minute_quota_cnt       # how many VT requests were made in the current minute
    global vt_minute_quota_timestamp # start of the current minute window (used to reset the per-minute counter)

    result = dict(classification="unclassified", classification_reason="No entry")

    # Reset daily quota if needed
    if vt_daily_quota_exceeded:
        if vt_daily_quota_timestamp.date() < datetime.now(timezone.utc).date():
            vt_daily_quota_exceeded = False
        else:
            result.update(classification_reason="VT limit exceeded")
            return result

    # Wait for minute quota if exceeded
    if vt_minute_quota_cnt >= vt_minute_quota:
        if (elapsed := (datetime.now(timezone.utc) - vt_minute_quota_timestamp).total_seconds()) < 60:
            sleep_time = 60 - elapsed
            logger.debug(f"VT minute quota exceeded, sleeping for {sleep_time:.1f} seconds...")
            time.sleep(sleep_time)
        vt_minute_quota_cnt = 0
        vt_minute_quota_timestamp = datetime.now(timezone.utc)
    vt_minute_quota_cnt += 1

    try:
        with virustotal_python.Virustotal(config.vt_key) as vt:
            attrs = vt.request(f'{resource_type.lower()}s/{resource_id}').data.get('attributes', {})
            if last_stats := attrs.get('last_analysis_stats'):
                cls = vt_stats_analysis(last_stats)
                reason = f'VT {resource_type} check' if cls != 'unclassified' else f'VT {resource_type} check inconclusive'
                result.update(classification=cls, classification_reason=reason, vt_stats=json.dumps(last_stats))
                if cls == 'malicious' and (threat := attrs.get('popular_threat_classification', {}).get('suggested_threat_label')):
                    result.update(threat_label=threat)
    except virustotal_python.VirustotalError as e:
        if e.args[0].status_code == 404:
            logger.debug("Not found")
        elif e.args[0].status_code == 429:
            logger.warning("VT daily quota exceeded")
            vt_daily_quota_exceeded = True
            vt_daily_quota_timestamp = datetime.now(timezone.utc)
            result.update(classification_reason="VT limit exceeded")
        else:
            logger.warning(f"Unexpected response from VirusTotal: {e.args[0].status_code}")
    return result


def search_for_nested_urls(content, src_url):
    """
    Extract new URLs from downloaded shell script and add them to the DB
    """

    try:
        decoded_content = content.decode("utf-8")
        if session := extract_commands(decoded_content):
            if new_urls := process_new_session(db, config, session, None, datetime.now(timezone.utc).isoformat(), "URL content", src_url, None):
                logger.info(f"{len(new_urls)} new URLs found in a shell script downloaded from {src_url}: {new_urls}")
    except UnicodeDecodeError:
        return


def _record_fetch(url, response, content_id=None, fetched_at=None):
    """
    Persist one row of connection metadata for the given HTTP response.

    Best-effort: any failure is logged and swallowed so content storage can
    never break the core evaluation pipeline.
    """
    db_conn = globals().get("db")
    if content_store is None or db_conn is None:
        return
    try:
        content_store.record_download_observation(
            db_conn,
            url,
            content_id=content_id,
            fetched_at=fetched_at,
            source_ip=content_store.resolve_source_ip(url),
            status_code=getattr(response, "status_code", None),
            response_headers=dict(getattr(response, "headers", {}) or {}),
        )
    except Exception as e:
        logger.debug(f"Could not record download observation for {url}: {e}")


def _check_hybrid_analysis(db_conn, content_id, sha256, url=None):
    """
    Look up the stored payload's SHA-256 on Hybrid Analysis (was it already
    detonated there?) and save the answer into content.sandbox_info.
    Best-effort: never breaks the evaluation.
    """
    if hybrid_analysis is None:
        return
    result, outcome = hybrid_analysis.check_content_outcome(db_conn, config, content_id, sha256)
    ha_url_stats[outcome] += 1
    tested = bool(result and result.get("tested") and outcome in ("checked", "cached"))
    if tested:
        ha_url_stats["tested"] += 1

    if outcome in ("checked", "cached"):
        logger.info(
            f"Hybrid Analysis: content {sha256[:12]}… of {url} "
            f"{'already analysed (' + str(len(result.get('reports') or [])) + ' report(s))' if tested else 'not analysed yet'}"
            f"{' [stored result]' if outcome == 'cached' else ''}"
        )
        return

    # Rate limit: either this request got HTTP 429 or lookups are still paused after one.
    last_status = (result or {}).get("last_error", {}).get("http_status") or (result or {}).get("http_status")
    resume = hybrid_analysis.paused_until()
    if outcome == "failed" and last_status == 429:
        ha_url_stats["rate_limited"] += 1
        logger.warning(
            f"Hybrid Analysis rate limit hit (HTTP 429) while checking content of {url}; "
            f"lookups paused until {resume.isoformat(timespec='seconds') if resume else 'n/a'}"
        )
    elif outcome == "skipped" and resume:
        ha_url_stats["rate_limited"] += 1
        logger.warning(
            f"Hybrid Analysis lookup for {url} skipped: rate limit pause after HTTP 429 "
            f"until {resume.isoformat(timespec='seconds')}"
        )
    elif outcome == "failed":
        logger.warning(f"Hybrid Analysis lookup for content of {url} failed (HTTP {last_status})")


def _log_ha_usage(force=False):
    """
    Periodically (every `ha_stats_interval_minutes`, default 10) log how many
    URLs had their content hash checked on Hybrid Analysis and the API request
    rate, then start a new window. `force` logs immediately (on shutdown).
    """
    global ha_stats_started
    if hybrid_analysis is None:
        return
    elapsed = time.monotonic() - ha_stats_started
    if not force and elapsed < 60 * getattr(config, "ha_stats_interval_minutes", 10):
        return
    ha = hybrid_analysis.request_stats()
    if ha["requests"] or any(ha_url_stats.values()):
        minutes = max(elapsed / 60, 1 / 60)
        logger.info(
            f"Hybrid Analysis (last {elapsed / 60:.1f} min): "
            f"{ha_url_stats['checked'] + ha_url_stats['cached']} URLs with hash successfully checked "
            f"({ha_url_stats['checked']} queried now, {ha_url_stats['cached']} from stored result), "
            f"{ha_url_stats['tested']} already analysed by HA, {ha_url_stats['failed']} failed, "
            f"{ha_url_stats['skipped']} skipped; API: {ha['requests']} GET requests, "
            f"avg {ha['requests'] / minutes:.1f}/min, peak {ha['peak_per_minute']} in any 60 s window "
            f"(quota 200/min), HTTP statuses {ha['by_status']}, last Api-Limits {ha['api_limits']}"
        )
        if ha["by_status"].get(429):
            logger.warning(f"Hybrid Analysis: HTTP 429 (rate limit) received {ha['by_status'][429]}x in the last {elapsed / 60:.1f} min")
        elif ha["peak_per_minute"] >= 200:
            logger.warning("Hybrid Analysis: peak request rate reached the 200/min quota")
    hybrid_analysis.reset_request_stats()
    ha_url_stats.clear()
    ha_stats_started = time.monotonic()


def _store_downloaded_content(url, body, mime_type, fetched_at):
    """
    Deduplicate & persist a downloaded payload to disk and link it to an
    observation row. Returns the content_id (or None when storage is
    disabled/unavailable).
    """
    db_conn = globals().get("db")
    if content_store is None or db_conn is None or not body:
        return None
    content_dir = getattr(config, "content_dir", None)
    if not content_dir:
        return None
    try:
        content_store.ensure_content_dir(content_dir)
        info = content_store.get_or_create_content(
            db_conn, content_dir, body, mime_type=mime_type or None, url=url
        )
        if info is None:
            logger.warning(
                f"Content for {url} ({len(body)} bytes) could not be written to "
                f"disk – skipping content record, observation will reference no payload"
            )
            return None
        _check_hybrid_analysis(db_conn, info.get("id"), info.get("sha256"), url)
        return info.get("id")
    except Exception as e:
        logger.warning(f"Could not store content for {url}: {e}")
        return None


def _fetch_and_store_content(url):
    """Download `url` once, store the payload and log the fetch.

    Side effects (all best-effort, never breaking classification):
      - records a download_observation row (timestamp, source IP, status code,
        response headers) via _record_fetch — both on failure (content_id=None)
        and on success
      - stores a usable payload deduplicated on disk (keyed by SHA-256) via
        _store_downloaded_content, linking it through content_id
      - when the body is a shell script, extracts nested URLs from it
        (search_for_nested_urls) and links them as derived-from `url`

    Returns (sha1, body, content_size, file_type); sha1/body are None when no
    storable body was returned. Raises only on network-level errors.
    """
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with requests.get(url, stream=True, proxies=proxies, timeout=10) as response:
        if not response.ok:
            _record_fetch(url, response, content_id=None, fetched_at=fetched_at)
            return None, None, None, None
        content_size = response.headers.get('Content-Length')
        if content_size is not None and int(content_size) / (1024 ** 2) > config.max_file_size:
            _record_fetch(url, response, content_id=None, fetched_at=fetched_at)
            return None, None, content_size, None

        # Determine file type
        file_type = ""
        if "content-type" in response.headers:
            file_type = response.headers['content-type'].split(";")[0]
        else:
            try:
                file_type = magic.from_buffer(response.content, mime=True)
            except Exception as e:
                logger.debug(f"Couldn't determine file type: {e}")

        body = response.content

        # Search the downloaded content for new URLs
        if file_type in ["application/x-sh", "application/x-shellscript", "text/plain", "text/x-shellscript", "text/x-sh"]:
            search_for_nested_urls(body, url)

        # Persist the raw payload (deduplicated) and log the fetch metadata
        content_id = _store_downloaded_content(url, body, file_type, fetched_at)
        _record_fetch(url, response, content_id=content_id, fetched_at=fetched_at)

        sha1 = hashlib.sha1(body).hexdigest()
        return sha1, body, content_size, file_type


def mb_file_check(sha1):
    """Return a MalwareBazaar classification dict when the SHA-1 is known, else None."""
    mb_resp = None
    try:
        mb_resp = requests.post(config.mb_url, data={'query': 'get_info', 'hash': sha1}, headers={'Auth-Key': config.mb_key})
        if mb_resp.json().get('query_status') == 'ok':
            return dict(classification="malicious", classification_reason="MB file check")
    except Exception as e:
        logger.warning(f"Unexpected response from MalwareBazaar: {mb_resp if mb_resp is not None else e}")
    return None


def analyze_content(url, prefetched=None):
    """
    Classify the downloaded content of `url` by its SHA-1 hash.

    `prefetched` is an optional (sha1, body, content_size, file_type) tuple
    from _fetch_and_store_content(); when omitted (or None) this function
    fetches the content itself (storing it + logging the fetch as a side
    effect), so its behaviour is unchanged for direct callers.
    """
    try:
        if prefetched is not None:
            sha1, body, content_size, file_type = prefetched
            # A caller that pre-fetched may already have a classification; a
            # None sha1 just means "no usable body" -> unclassified below.
            if sha1 is None:
                return dict()
        else:
            sha1, body, content_size, file_type = _fetch_and_store_content(url)
            if sha1 is None:
                return dict(classification="unclassified", classification_reason="No content")

        result = dict(hash=sha1)
        if content_size is not None:
            result.update(content_size=content_size)
        if file_type:
            result.update(file_mime_type=file_type)

        # check content hash on MalwareBazaar
        mb = mb_file_check(sha1)
        if mb:
            result.update(**mb)
            return result

        # if not found, check content hash on VirusTotal
        result.update(**vt_request("file", sha1))
        return result

    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
        return dict(classification="unreachable", classification_reason="Connection timeout")
    except requests.exceptions.TooManyRedirects:
        return dict(classification="unreachable", classification_reason="Too many redirects")
    except requests.exceptions.ConnectionError:
        return dict(classification="unreachable", classification_reason="Connection refused")
    except Exception as e:
        # this is usually caused by requests.get() trying to parse invalid URLs
        logger.warning(f"Failed to analyze URL content: {type(e)}: {e}")
        return dict(classification="unclassified", classification_reason="Internal error")


def is_blacklisted(url):
    """
    Check if the URL is blacklisted
    """

    global blacklist
    global bl_last_updated

    if not blacklist or bl_last_updated + timedelta(minutes=config.bl_update_time) < datetime.now(timezone.utc):
        logger.debug(f"Downloading blacklist from {config.urlhaus_blacklist_url}")
        try:
            content = requests.get(config.urlhaus_blacklist_url).content.decode("utf-8")
            blacklist = [line for line in content.splitlines() if not line.startswith("#")]
            bl_last_updated = datetime.now(timezone.utc)
        except Exception as e:
            logger.error(f"Error while downloading blacklist: {e}")
            return False

    if url in blacklist:
        return True
    return False


def check_domain_threshold(url):
    """
    Check the total number of URLs from the same domain
    If a threshold is exceeded all non-malicious URLs from the domain will be deleted (probably a DDoS attack)
    """

    domain = db.execute("SELECT domain FROM urls WHERE url=?", (url,)).fetchone()[0]
    # Only non-malicious URLs are flood candidates; parameterised (no string
    # interpolation) and cascaded via ON DELETE CASCADE to dependent tables.
    urls_to_delete = [
        u[0] for u in db.execute(
            "SELECT url FROM urls WHERE domain = ? AND classification != 'malicious'",
            (domain,),
        ).fetchall()
    ]
    urls_from_domain = db.execute(
        "SELECT COUNT(*) FROM urls WHERE domain = ?", (domain,)
    ).fetchone()[0]
    if urls_from_domain > config.ddos_threshold["same_domain_all_sessions"]:
        content_ids = set()
        if content_store is not None and urls_to_delete:
            try:
                content_ids = {
                    cid for cid, _ in content_store.content_ids_for_urls(db, urls_to_delete)
                }
            except Exception as e:
                logger.warning(f"Could not resolve content for domain-flood URLs: {e}")
        if content_store is not None:
            content_store.delete_urls(db, urls_to_delete)
        elif urls_to_delete:
            # Fallback (content_store unavailable): plain parameterised delete.
            placeholders = ",".join("?" for _ in urls_to_delete)
            db.execute(f"DELETE FROM urls WHERE url IN ({placeholders})", urls_to_delete)
        if content_store is not None and content_ids:
            try:
                content_store.cleanup_orphan_content(db, candidates=content_ids)
            except Exception as e:
                logger.warning(f"Orphan content cleanup failed (domain flood): {e}")
        logger.info(f"Deleted {len(urls_to_delete)} URLs from domain {domain} (global threshold exceeded)")
        logger.debug(f"Deleted URLs: {tuple(urls_to_delete)}")
        return True


def evaluate_url(url):
    """
    For every newly processed (valid) URL the content is always downloaded and
    stored (deduplicated, plus a download_observation row) via
    _fetch_and_store_content. Classification then proceeds:
    1. Check that the URL is valid
    2. Check the global same-domain threshold (delete flood URLs)
    3. Check if the URL is listed on URLhaus blacklist
    4. Check file hash on MalwareBazaar (skipped on pre-fetched network errors)
    5. Check for entries on VirusTotal (URL, then file hash)
    Returns a result dict, None when the URL was deleted by the domain
    threshold, or evaluated=no/eval_later=yes when VT rate limit was hit.
    """

    result = dict(evaluated="yes", eval_later="no")

    logger.debug("Checking validity")
    if not is_valid(url):
        result.update(classification="invalid", classification_reason="Invalid format")
        return result
    logger.debug("OK")

    # Always download & analyze content for the newly processed URL (even when
    # the URL is already decided by the blacklist / VT below), so the Content
    # tab has a sample + fetch history. Network-level errors only mark it
    # unreachable; they must not prevent the fast classification paths.
    prefetched = None
    prefetch_neterr = False
    try:
        prefetched = _fetch_and_store_content(url)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
            requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError):
        prefetch_neterr = True
    except Exception:
        prefetch_neterr = True

    logger.debug("Checking domain threshold")
    if check_domain_threshold(url):
        return None
    logger.debug("OK")

    logger.debug("Checking evaluation blacklist")
    if is_blacklisted(url):
        result.update(classification="malicious", classification_reason="Blacklist check")
        return result
    logger.debug("Not found")

    # MalwareBazaar file-hash check (more specific than the VT URL check);
    # skipped when no usable body was downloaded.
    if prefetched and prefetched[0]:
        mb = mb_file_check(prefetched[0])
        if mb:
            result.update(**mb)
            return result

    logger.debug("Checking VirusTotal")
    result.update(**vt_request("URL", urlsafe_b64encode(url.encode()).decode().strip("=")))
    if result.get("classification") != "unclassified":
        return result

    # Prefetch network error (unreachable) and still unclassified -> report it.
    if prefetch_neterr:
        result.update(classification="unreachable", classification_reason="Connection error")
        return result

    logger.debug("Checking content hash")
    cls = analyze_content(url, prefetched)
    if cls.get("classification_reason") == "VT limit exceeded":
        logger.debug(f"URL {url} will be re-evaluated after VirusTotal rate limit is reset")
        result.update(evaluated="no", eval_later="yes")
    else:
        if cls.get("classification_reason") == "No entry":
            cls.update(**result)
        result.update(**cls)
    return result


def sigint_handler(signum, frame):
    global running_flag
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM", signal.SIGABRT: "SIGABRT"}.get(signum, signum)))
    running_flag = False


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Evaluates URLs stored in the database")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("evaluator.py")
    if args.verbose:
        logger.setLevel('DEBUG')

    # Load config
    logger.debug(f"Loading config from {args.config}")
    try:
        config = Config(args.config)
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {e}")
        sys.exit(1)

    # Register signal handlers
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)

    # Set HTTP proxy
    proxies = {}
    if config.http_proxy:
        proxies = {
            "http": config.http_proxy,
            "https": config.http_proxy
        }

    # Variables for VT rate limit checks
    vt_minute_quota = config.vt_minute_quota
    vt_minute_quota_cnt = 0
    vt_minute_quota_timestamp = datetime.now(timezone.utc)
    vt_daily_quota_exceeded = False
    vt_daily_quota_timestamp = datetime.now(timezone.utc)

    # Blacklist for evaluating URLs
    blacklist = []
    bl_last_updated = None

    # Hybrid Analysis usage statistics (logged periodically by _log_ha_usage)
    ha_url_stats = Counter()
    ha_stats_started = time.monotonic()
    if hybrid_analysis is not None:
        hybrid_analysis.reset_request_stats()

    # Open DB connection
    db = SQLiteWrapper(config.db_path)

    logger.info("Started")
    running_flag = True
    while running_flag:
        _log_ha_usage()
        url = db.execute("SELECT url FROM urls WHERE evaluated = 'no'" + (" AND eval_later = 'no'" if vt_daily_quota_exceeded else "") + " LIMIT 1;").fetchone()
        if not url:
            logger.debug("No URLs to check, sleeping for 10 seconds")
            time.sleep(10)
            continue
        url = url[0]

        try:
            logger.debug(f"Evaluating {url}")
            if not (result := evaluate_url(url)):
                continue
            logger.info(f"URL {url} was classified as {result['classification']}, reason: {result['classification_reason']}")

            # Update DB record
            items = list(result.items())
            set_clause = ", ".join([f"{k} = ?" for k, _ in items])
            params = tuple(v for _, v in items) + (url,)
            db.execute(f"UPDATE urls SET {set_clause} WHERE url = ?", params)

            # Record the decision in the classification history (skip when the URL
            # could not be fully evaluated yet and will be retried later – there is
            # no new classification decision to log in that case).
            if result.get("evaluated") == "yes":
                db.record_classification(
                    url,
                    result["classification"],
                    reason=result.get("classification_reason"),
                    actor="evaluator"
                )

            # If the URL was classified as malicious, mark all source URLs that led to it as malicious
            if result["classification"] == "malicious":
                rows = db.execute("SELECT urls.url FROM discovered_urls AS s JOIN urls ON urls.url = s.src_url WHERE s.url = ? AND urls.classification != 'malicious'", (url,)).fetchall()
                if src_urls := ", ".join(f"'{row[0]}'" for row in rows):
                    db.execute(f"UPDATE urls SET classification = 'malicious', classification_reason = 'Downloading from malicious URL' WHERE url IN ({src_urls})")
                    for row in rows:
                        db.record_classification(
                            row[0],
                            "malicious",
                            reason="Downloading from malicious URL",
                            actor="evaluator-backprop"
                        )
                    logger.info(f"URLs {src_urls} were classified as malicious because they downloaded content from a malicious URL ({url})")
        except Exception as e:
            logger.exception(f"Error while evaluating URL {url}: {type(e)}: {e}")

    _log_ha_usage(force=True)
    db.close()
    logger.info("Stopped")
