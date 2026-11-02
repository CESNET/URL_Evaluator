#!/usr/bin/env python3

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import requests
import signal
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper

logger = logging.getLogger("evaluator2urlhaus.py")

# The only threat type the URLhaus submit API accepts (https://urlhaus.abuse.ch/api/#submit)
THREAT = "malware_download"
# content.file_category values (common/file_classifier.CATEGORIES) of pages and other non-payloads;
# URLhaus only wants URLs that distribute malware (https://urlhaus.abuse.ch/api/#policy)
EXCLUDED_CATEGORIES = ("html", "json", "text", "image", "media", "source_code", "empty")
# Magika labels renamed to the file type tags commonly used on URLhaus (other labels are used as they are)
MAGIKA_TAGS = {
    "shell": "sh", "pebin": "exe", "powershell": "ps1", "batch": "bat",
    "javascript": "js", "python": "py", "perl": "pl",
}
# Characters not allowed in a URLhaus tag (allowed: [A-Za-z0-9.- ])
TAG_INVALID_CHARS = re.compile(r"[^A-Za-z0-9. -]")
MAX_TAGS = 5
MAX_RESPONSE_LEN = 1000

# Module state, set by init() (called from __main__ and by tests)
config = None


def init(cfg):
    """Set the module state from `cfg`. Called by __main__ and by tests."""
    global config
    config = cfg


def load_candidates(db, since):
    """
    Active malicious / miner URLs whose latest download (not older than `since`)
    returned HTTP 200 with a payload that is not a web page, and which were not
    submitted to URLhaus yet (nor found there). Returns a list of dicts.
    """
    placeholders = ", ".join("?" for _ in EXCLUDED_CATEGORIES)
    rows = db.execute(f"""
        SELECT u.url, u.classification, u.threat_label, d.content_id, d.source_ip, c.magika_label, c.threat_label
        FROM urls u
        JOIN (SELECT url, content_id, status_code, source_ip,
                     ROW_NUMBER() OVER (PARTITION BY url ORDER BY fetched_at DESC, id DESC) AS rn
              FROM download_observations
              WHERE fetched_at >= ?) d ON d.url = u.url AND d.rn = 1
        JOIN content c ON c.id = d.content_id
        WHERE u.classification IN ('malicious', 'miner') AND u.status = 'active'
          AND d.status_code = 200
          AND (c.file_category IS NULL OR c.file_category NOT IN ({placeholders}))
          AND NOT EXISTS (SELECT 1 FROM urlhaus_submissions s WHERE s.url = u.url AND s.status IN ('ok', 'known'))
        ORDER BY u.url
    """, (since, *EXCLUDED_CATEGORIES)).fetchall()
    keys = ("url", "classification", "url_threat_label", "content_id", "source_ip", "magika_label", "content_threat_label")
    return [dict(zip(keys, row)) for row in rows]


def is_global_ip(value):
    """False for a private / special-purpose IP address (RFC 6890), True for a public IP or a hostname."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return True


def is_public(url, source_ip):
    """
    True when neither the host of `url` nor the IP the payload was served from
    (`source_ip`) is a private / special-purpose address, which URLhaus does not accept.
    """
    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    return is_global_ip(host) and (not source_ip or is_global_ip(source_ip))


def is_known_to_urlhaus(url):
    """
    Look `url` up in URLhaus (https://urlhaus-api.abuse.ch/#urlinfo).
    Returns True / False, or None when the lookup failed.
    """
    try:
        r = requests.post(config.urlhaus_detail_url, data={"url": url}, timeout=30,
                          headers={"Auth-Key": config.urlhaus_key})
        r.raise_for_status()
        status = r.json().get("query_status")
    except (requests.RequestException, ValueError, AttributeError) as e:
        logger.warning(f"URLhaus lookup of {url} failed: {e}")
        return None
    if status == "ok":
        return True
    if status == "no_results":
        return False
    logger.warning(f"URLhaus lookup of {url} failed: query_status {status}")
    return None


def build_tags(candidate, extra_tags=()):
    """
    URLhaus tags of a candidate: file type (Magika label), malware family
    (threat label, e.g. "trojan.mirai/gafgyt" -> "mirai", "gafgyt"),
    "CoinMiner" for miners and `extra_tags`. Sanitized, deduplicated, at most MAX_TAGS.
    """
    tags = []
    if (label := candidate["magika_label"]) and label != "unknown":
        tags.append(MAGIKA_TAGS.get(label, label))
    if threat := candidate["content_threat_label"] or candidate["url_threat_label"]:
        tags.extend(threat.split(".", 1)[-1].split("/"))
    if candidate["classification"] == "miner":
        tags.append("CoinMiner")
    tags.extend(extra_tags)

    result, seen = [], set()
    for tag in tags:
        tag = TAG_INVALID_CHARS.sub("", str(tag)).strip()
        if tag and tag.lower() not in seen:
            seen.add(tag.lower())
            result.append(tag)
    return result[:MAX_TAGS]


def submit_batch(candidates):
    """Submit `candidates` (with their "tags") in one request. Returns (ok, response text)."""
    submission = []
    for candidate in candidates:
        entry = {"url": candidate["url"], "threat": THREAT}
        if candidate["tags"]:
            entry["tags"] = candidate["tags"]
        submission.append(entry)
    try:
        r = requests.post(config.urlhaus_submit_url, json={"anonymous": "0", "submission": submission}, timeout=30,
                          headers={"Content-Type": "application/json", "Auth-Key": config.urlhaus_key})
    except requests.RequestException as e:
        return False, str(e)
    return r.status_code == 200, f"HTTP {r.status_code}: {r.text}"


def record_submissions(db, candidates, status, response=None):
    """Store the outcome (`status`: ok / error / known) of `candidates` in urlhaus_submissions."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with db.transaction():
        for candidate in candidates:
            tags = candidate.get("tags")
            db.execute("INSERT INTO urlhaus_submissions (url, content_id, submitted_at, tags, status, response) "
                       "VALUES (?, ?, ?, ?, ?, ?)",
                       (candidate["url"], candidate["content_id"], now, json.dumps(tags) if tags is not None else None,
                        status, response[:MAX_RESPONSE_LEN] if response else None))


def evaluator2urlhaus():
    logger.info("Job started")
    batch_size = getattr(config, "urlhaus_batch_size", 50)
    max_age = getattr(config, "urlhaus_max_fetch_age_hours", 24)
    extra_tags = getattr(config, "urlhaus_extra_tags", None) or []
    since = (datetime.now(timezone.utc) - timedelta(hours=max_age)).isoformat(timespec="seconds")

    with SQLiteWrapper(config.db_path) as db:
        candidates = load_candidates(db, since)
        if not candidates:
            logger.info("No URLs to send")
            logger.info("Job finished")
            return
        logger.info(f"Found {len(candidates)} candidate URLs")

        # Check the URLs before sending, as the URLhaus submission policy requires
        to_send, known, cnt_private, cnt_unchecked = [], [], 0, 0
        for candidate in candidates:
            if not is_public(candidate["url"], candidate["source_ip"]):
                logger.debug(f"Skipping {candidate['url']}: private or special-purpose IP")
                cnt_private += 1
                continue
            is_known = is_known_to_urlhaus(candidate["url"])
            if is_known is None:
                cnt_unchecked += 1
            elif is_known:
                logger.debug(f"Skipping {candidate['url']}: already known to URLhaus")
                known.append(candidate)
            else:
                candidate["tags"] = build_tags(candidate, extra_tags)
                logger.debug(f"Sending {candidate['url']} with tags {candidate['tags']}")
                to_send.append(candidate)
        if known:
            record_submissions(db, known, "known")

        # Send URLs to URLhaus
        cnt_sent, cnt_failed = 0, 0
        for i in range(0, len(to_send), batch_size):
            batch = to_send[i:i + batch_size]
            ok, response = submit_batch(batch)
            record_submissions(db, batch, "ok" if ok else "error", response)
            if ok:
                cnt_sent += len(batch)
            else:
                cnt_failed += len(batch)
                logger.error(f"Submission of {len(batch)} URLs failed: {response[:MAX_RESPONSE_LEN]}")

    logger.info(f"Sent {cnt_sent} new submissions, {cnt_failed} failed (out of {len(candidates)} URLs; skipped: "
                f"{len(known)} already known to URLhaus, {cnt_private} private IP, {cnt_unchecked} lookup failed)")
    logger.info("Job finished")

def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM", signal.SIGABRT: "SIGABRT"}.get(signum, signum)))
    scheduler.shutdown(wait=True)


if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description="Sends malicious URLs to URLhaus")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    parser.add_argument('--now', '-n', action='store_true', help='Run immediately on program start')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    if args.verbose:
        logger.setLevel('DEBUG')

    # Load config
    logger.debug(f"Loading config from {args.config}")
    try:
        init(Config(args.config))
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {e}")
        sys.exit(1)

    # Register signal handlers
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)

    logger.info("Started")
    if args.now:
        evaluator2urlhaus()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(evaluator2urlhaus, "cron", **config.scheduler["evaluator2urlhaus"])
    scheduler.start()

    logger.info("Stopped")
