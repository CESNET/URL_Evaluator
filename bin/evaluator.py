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

    try:
        decoded_content = content.decode("utf-8")
        if session := extract_commands(decoded_content):
            if new_urls := process_new_session(db, config, session, None, datetime.now(timezone.utc).isoformat(), "URL content", src_url):
                logger.info(f"{len(new_urls)} new URLs found in a shell script downloaded from {src_url}: {new_urls}")
    except UnicodeDecodeError:
        return


def analyze_content(url):
    """
    Download content from given URL and check its hash on VirusTotal / MalwareBazaar
    """

    try:
        with requests.get(url, stream=True, proxies=proxies, timeout=10) as response:
            if not response.ok:
                return dict(classification="unreachable", classification_reason=f"Status code {response.status_code}")
            if (content_size := response.headers.get('Content-Length')) is None:
                return dict(classification="unclassified", classification_reason="No content")
            if (content_size_mb := int(content_size) / (1024 ** 2)) > config.max_file_size:
                return dict(classification="unclassified", classification_reason=f"File too large: {content_size_mb:.2f} MB")

            # Determine file type
            file_type = ""
            if "content-type" in response.headers:
                file_type = response.headers['content-type'].split(";")[0]
            else:
                try:
                    file_type = magic.from_buffer(response.content, mime=True)
                except Exception as e:
                    logger.debug(f"Couldn't determine file type: {e}")

            # Search the downloaded content for new URLs
            if file_type in ["application/x-sh", "application/x-shellscript",  "text/plain", "text/x-shellscript", "text/x-sh"]:
                search_for_nested_urls(response.content, url)

            sha1 = hashlib.sha1(response.content).hexdigest()
            result = dict(hash=sha1, content_size=content_size)
            if file_type:
                result.update(file_mime_type=file_type)

            # check content hash on MalwareBazaar
            mb_resp = None
            try:
                mb_resp = requests.post(config.mb_url, data={'query': 'get_info', 'hash': sha1}, headers={'Auth-Key': config.mb_key})
                if mb_resp.json().get('query_status') == 'ok':
                    result.update(classification="malicious", classification_reason="MB file check")
                    return result
            except Exception as e:
                logger.warning(f"Unexpected response from MalwareBazaar: {mb_resp if mb_resp is not None else e}")

            # if not found, check content hash on VirusTotal
            result.update(**vt_request("file", sha1))
            return result

    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
        return dict(classification="unreachable", classification_reason="Connection timeout")
    except requests.exceptions.TooManyRedirects:
        return dict(classification="unreachable", classification_reason="Too many redirects")
    except requests.exceptions.ConnectionError:
        return dict(classification="unreachable", classification_reason="Connection refused")


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
    1. Check that the URL is valid
    2. Check if the URL is listed on URLhaus blacklist
    3. Check for entries on VirusTotal
    4. Download and analyze the URL content
         - check hash on MalwareBazaar
         - check hash on VirusTotal
         - search for new URLs in downloaded shell scripts
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
        return result
    logger.debug("Not found")

    logger.debug("Checking VirusTotal")
    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
    result.update(**vt_request("URL", url_id))
    if result.get("classification") != "unclassified":
        return result

    logger.debug("Checking content hash")
    cls = analyze_content(url)
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

    # Open DB connection
    db = SQLiteWrapper(config.db_path)

    logger.info("Started")
    running_flag = True
    while running_flag:
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

            # If the URL was classified as malicious, mark all source URLs that led to it as malicious
            if result["classification"] == "malicious":
                rows = db.execute("SELECT urls.url FROM discovered_urls AS s JOIN urls ON urls.url = s.src_url WHERE s.url = ? AND urls.classification != 'malicious'", (url,)).fetchall()
                if src_urls := ", ".join(f"'{row[0]}'" for row in rows):
                    db.execute(f"UPDATE urls SET classification = 'malicious', classification_reason = 'Downloading from malicious URL' WHERE url IN ({src_urls})")
                    logger.info(f"URLs {src_urls} were classified as malicious because they downloaded content from a malicious URL ({url})")
        except Exception as e:
            logger.exception(f"Error while evaluating URL {url}: {type(e)}: {e}")

    db.close()
    logger.info("Stopped")
