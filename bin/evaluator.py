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
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.db_helpers import persist_content_snapshot, update_url_field
from common.utils import is_valid, extract_commands, process_new_session


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

    global vt_daily_quota_exceeded
    global vt_daily_quota_timestamp
    global vt_minute_quota
    global vt_minute_quota_cnt
    global vt_minute_quota_timestamp

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

    logger.debug(f"search_for_nested_urls: scanning {len(content)} bytes from {src_url}")
    try:
        decoded_content = content.decode("utf-8")
        if session := extract_commands(decoded_content):
            logger.debug(f"search_for_nested_urls: extracted session with {len(session)} command(s) from {src_url}")
            if new_urls := process_new_session(db, config, session, None, datetime.now(timezone.utc).isoformat(), "URL content", src_url):
                logger.info(f"{len(new_urls)} new URLs found in a shell script downloaded from {src_url}: {new_urls}")
            else:
                logger.debug(f"search_for_nested_urls: no new URLs in session from {src_url}")
        else:
            logger.debug(f"search_for_nested_urls: no commands extracted from {src_url}")
    except UnicodeDecodeError:
        logger.debug(f"search_for_nested_urls: content from {src_url} is not UTF-8 decodable, skipping")
        return


def analyze_content(url):
    """
    Download content from the given URL, store it and check its hash on VirusTotal / MalwareBazaar.

    If the download fails for any reason, the URL is marked as ``status='inactive'``.
    If it was the first download attempt and the URL has not been classified by any other
    method, it is additionally classified as ``unreachable``.

    :returns: dict containing classification result and metadata. On failure, includes
              ``status='inactive'`` and may include ``classification='unreachable'``.
    """

    logger.debug(f"analyze_content: START {url}")
    try:
        with requests.get(url, stream=True, proxies=proxies, timeout=10) as response:
            logger.debug(f"analyze_content: {url} -> HTTP {response.status_code}, headers: {dict(response.headers)}")
            if not response.ok:
                # Download failed -> URL inactive.
                logger.debug(f"analyze_content: {url} unreachable (HTTP {response.status_code})")
                return _unreachable_result(url, f"Status code {response.status_code}")
            if (content_size := response.headers.get('Content-Length')) is None:
                logger.debug(f"analyze_content: {url} has no Content-Length header")
                return dict(classification="unclassified", classification_reason="No content")
            if (content_size_mb := int(content_size) / (1024 ** 2)) > config.max_file_size:
                logger.debug(f"analyze_content: {url} too large ({content_size_mb:.2f} MB > {config.max_file_size} MB)")
                return dict(classification="unclassified", classification_reason=f"File too large: {content_size_mb:.2f} MB")
            logger.debug(f"analyze_content: {url} downloaded {len(response.content)} bytes (declared Content-Length: {content_size})")

            # Determine file type
            file_type = ""
            if "content-type" in response.headers:
                file_type = response.headers['content-type'].split(";")[0]
                logger.debug(f"analyze_content: {url} content-type from header: {file_type}")
            else:
                try:
                    file_type = magic.from_buffer(response.content, mime=True)
                    logger.debug(f"analyze_content: {url} content-type from magic: {file_type}")
                except Exception as e:
                    logger.debug(f"Couldn't determine file type: {e}")

            # Search the downloaded content for new URLs
            if file_type in ["application/x-sh", "application/x-shellscript",  "text/plain", "text/x-shellscript", "text/x-sh"]:
                logger.debug(f"analyze_content: {url} is a text/shell type, searching for nested URLs")
                search_for_nested_urls(response.content, url)

            # Persist the downloaded content (deduplicated file storage + snapshot/link/history in DB)
            # and capture connection metadata (IPs, HTTP status, response headers).
            logger.debug(f"analyze_content: {url} persisting content snapshot to {config.content_storage_path}")
            persisted = persist_content_snapshot(db, config.content_storage_path, url, response, response.content, file_type or None)
            logger.debug(f"analyze_content: {url} persisted -> sha1={persisted['hash']}, sha256={persisted['latest_content_hash']}, storage_path={persisted['storage_path']}, is_new={persisted['is_new']}")

            sha1 = persisted["hash"]
            result = dict(hash=sha1, content_size=content_size)
            if file_type:
                result.update(file_mime_type=file_type)

            # check content hash on MalwareBazaar
            mb_resp = None
            try:
                logger.debug(f"analyze_content: {url} querying MalwareBazaar for sha1={sha1}")
                mb_resp = requests.post(config.mb_url, data={'query': 'get_info', 'hash': sha1}, headers={'Auth-Key': config.mb_key})
                if mb_resp.json().get('query_status') == 'ok':
                    logger.debug(f"analyze_content: {url} flagged malicious by MalwareBazaar")
                    result.update(classification="malicious", classification_reason="MB file check")
                    return result
                logger.debug(f"analyze_content: {url} not known to MalwareBazaar (status: {mb_resp.json().get('query_status')})")
            except Exception as e:
                logger.warning(f"Unexpected response from MalwareBazaar: {mb_resp if mb_resp is not None else e}")

            # if not found, check content hash on VirusTotal
            logger.debug(f"analyze_content: {url} querying VirusTotal for file sha1={sha1}")
            result.update(**vt_request("file", sha1))
            logger.debug(f"analyze_content: DONE {url} -> {result.get('classification')} ({result.get('classification_reason')})")
            return result

    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
        logger.debug(f"analyze_content: {url} connection/read timeout")
        return _unreachable_result(url, "Connection timeout")
    except requests.exceptions.TooManyRedirects:
        logger.debug(f"analyze_content: {url} too many redirects")
        return _unreachable_result(url, "Too many redirects")
    except requests.exceptions.ConnectionError:
        logger.debug(f"analyze_content: {url} connection refused")
        return _unreachable_result(url, "Connection refused")
    except Exception as e:
        # this is usually caused by requests.get() trying to parse invalid URLs
        logger.warning(f"Failed to analyze URL content: {type(e)}: {e}")
        return dict(classification="unclassified", classification_reason="Internal error")


def _has_stored_sample(url):
    """
    Return True when we already stored a content snapshot for the given URL.
    """

    row = db.execute(
        "SELECT latest_content_hash FROM urls WHERE url = ?", (url,)
    ).fetchone()
    if row and row[0]:
        return True
    row = db.execute(
        "SELECT 1 FROM url_content WHERE url = ? LIMIT 1", (url,)
    ).fetchone()
    return row is not None


def _unreachable_result(url, reason):
    """
    Build a result for a failed download.

    Marks the URL as ``status='inactive'``. If no sample was previously stored,
    it also flags it as a first attempt.
    """

    result = dict(status="inactive", unreachable=True)
    if not _has_stored_sample(url):
        result["first_attempt"] = True
    
    # We don't set classification='unreachable' here anymore;
    # it's handled in evaluate_url based on prior classifications.
    return result


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
    urls_from_domain = tuple(u[0] for u in db.execute("SELECT url FROM urls WHERE domain=?", (domain,)).fetchall())
    if len(urls_from_domain) > config.ddos_threshold["same_domain_all_sessions"]:
        db.execute(f"DELETE FROM urls WHERE url IN {urls_from_domain} AND classification != 'malicious'")
        logger.info(f"Deleted {len(urls_from_domain)} URLs from domain {domain} (global threshold exceeded)")
        logger.debug(f"Deleted URLs: {urls_from_domain}")
        return True


def evaluate_url(url):
    """
    Evaluate a single URL.

    Flow:
      1. Check that the URL is valid
      2. Apply the per-domain threshold (may delete URLs)
      3. Check the URLhaus blacklist
      4. Check for entries on VirusTotal (URL check)
      5. Download and analyze the URL content (Sample download)
            - check hash on MalwareBazaar
            - check hash on VirusTotal
            - search for new URLs in downloaded shell scripts

    Sample download (step 5) is performed ALWAYS, unless the URL was already
    classified as legitimate (``harmless``) AND a sample is already stored.

    If the download fails:
      - The URL is marked ``status='inactive'``.
      - If it was the first download attempt AND no prior classification was
        found in steps 3-4, it is classified as ``unreachable``.
    """

    result = dict(evaluated="yes", eval_later="no")

    logger.debug("Checking validity")
    if not is_valid(url):
        result.update(classification="invalid", classification_reason="Invalid format")
        return result
    logger.debug("OK")

    logger.debug("Checking domain threshold")
    if check_domain_threshold(url):
        return None
    logger.debug("OK")

    logger.debug("Checking evaluation blacklist")
    if is_blacklisted(url):
        result.update(classification="malicious", classification_reason="Blacklist check")
        #return result
    logger.debug("Not found")

    logger.debug("Checking VirusTotal")
    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
    result.update(**vt_request("URL", url_id))

    # Always attempt to download the URL content, regardless of the classification
    # produced by the earlier (non-content) methods.  The only exception is a URL
    # already classified as legitimate ("harmless") for which a sample is already
    # stored — in that case no new sample is re-downloaded.
    if result.get("classification") == "harmless" and _has_stored_sample(url):
        logger.debug(f"Skipping content download for {url}: classified as legitimate (harmless) and a sample is already stored")
        return result

    logger.debug("Checking content hash")
    cls = analyze_content(url)
    
    if cls.get("classification_reason") == "VT limit exceeded":
        logger.debug(f"URL {url} will be re-evaluated after VirusTotal rate limit is reset")
        result.update(evaluated="no", eval_later="yes")
    else:
        failed = bool(cls.get("unreachable"))
        first_attempt = cls.pop("first_attempt", False)
        
        if failed:
            result["status"] = "inactive"
            # If it's the first attempt and we have no classification yet, mark as unreachable
            if first_attempt and result.get("classification") in ("unclassified", None):
                result.update(classification="unreachable", classification_reason=cls.get("classification_reason", "Download failed"))
        
        # Remove internal flag
        cls.pop("unreachable", None)
        
        # If analyze_content provided a classification, it takes precedence over URL-level checks
        # unless it's just "No entry"
        if cls.get("classification_reason") != "No entry":
            result.update(**cls)
        elif not failed:
            # If it didn't fail but found nothing, we still keep the URL-level results
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

    # Open DB connection
    db = SQLiteWrapper(config.db_path)

    logger.info("Started")
    running_flag = True
    while running_flag:
        # Pick the newest URL that hasn't been evaluated yet.
        query = "SELECT url FROM urls WHERE evaluated = 'no'"
        if vt_daily_quota_exceeded:
            query += " AND eval_later = 'no'"
        
        query += " ORDER BY COALESCE(first_seen, '1970-01-01') DESC LIMIT 1"
        
        row = db.execute(query).fetchone()
        if not row:
            logger.debug("No URLs to check, sleeping for 10 seconds")
            time.sleep(10)
            continue
            
        url = row[0]

        try:
            logger.debug(f"Evaluating {url}")
            if not (result := evaluate_url(url)):
                continue
            logger.info(f"URL {url} was classified as {result['classification']}, reason: {result['classification_reason']}")

            # Update DB record — use update_url_field per field so that
            # classification/classification_reason/note changes are recorded
            # in classification_history (changed_by="system").
            for field, value in result.items():
                update_url_field(db, url, field, value, changed_by="system")

            # If the URL was classified as malicious, mark all source URLs that led to it as malicious
            if result["classification"] == "malicious":
                rows = db.execute("SELECT urls.url FROM discovered_urls AS s JOIN urls ON urls.url = s.src_url WHERE s.url = ? AND urls.classification != 'malicious'", (url,)).fetchall()
                if rows:
                    src_url_list = []
                    for (src_url,) in rows:
                        update_url_field(db, src_url, "classification", "malicious", changed_by="system")
                        update_url_field(db, src_url, "classification_reason", "Downloading from malicious URL", changed_by="system")
                        src_url_list.append(src_url)
                    logger.info(f"URLs {', '.join(src_url_list)} were classified as malicious because they downloaded content from a malicious URL ({url})")
        except Exception as e:
            logger.exception(f"Error while evaluating URL {url}: {type(e)}: {e}")

    db.close()
    logger.info("Stopped")
