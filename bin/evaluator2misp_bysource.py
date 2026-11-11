#!/usr/bin/env python3

import logging
import sys
import os
import argparse
import signal
import ipaddress
from urllib.parse import urlparse
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject
from datetime import date, datetime, timezone, timedelta
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper

# Disable insecure certificate warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# MISP object template of a URL (etc/misp_objects/url-honeypot-detection)
OBJECT_NAME = "url-honeypot-detection"

# Columns of a row loaded in sync_urls(), in the order of its SELECT
DB_ROW_KEYS = ("url", "hash", "first_seen", "last_seen", "file_mime_type", "threat_label", "status",
               "classification", "source", "sha256")

logger = logging.getLogger("evaluator2misp_bysource.py")

# Module state, set by init() (called from __main__ and by tests)
config = None


def init(cfg):
    """Set the module state from `cfg`. Called by __main__ and by tests."""
    global config
    config = cfg


def extract_ip_domain_port(url):
    """
    Extract domain name or IP address and dest. port from given URL
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return None, None
    scheme = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        ipaddress.ip_address(hostname)
        return f"{hostname}|{port}", None
    except ValueError:
        return None, hostname


def get_or_create_event(misp, source):
    """
    Fetch existing MISP event or create a new one if it doesn't exist yet
    """
    event_info = f"Malicious URLs from SSH honeypots ({source})"
    event_tags = [
        'tlp:clear',
        'coa:discover=honeypot',
        'rsit:malicious-code="malware-distribution"',
        'CESNET:malware-urls',
        f'CESNET:source=\'{source}\''
    ]
    if existing := misp.search(eventinfo=event_info, event_tags=event_tags, pythonify=True):
        logger.debug(f"Using existing event (ID {existing[0].id})")
        return misp.get_event(existing[0].id, pythonify=True)
    event = MISPEvent()
    event.info = event_info
    event.date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    event.distribution = 2
    event.threat_level_id = 3
    event.analysis = 2
    new = misp.add_event(event, pythonify=True)
    for tag in event_tags:
        misp.tag(new, tag)
    logger.debug(f"Created new event (ID {new.id})")
    return new


def our_objects(event):
    """URL objects created by this exporter (an analyst may add other objects to the event)."""
    return [obj for obj in event.objects if obj.name == OBJECT_NAME]


def update_attribute(obj, relation, attr_type, value, same=lambda old, new: old == new):
    """
    Set the attribute `relation` of `obj` to `value`; it is added when the
    object lacks it (e.g. created by an older version). True when it changed.
    """
    if attrs := obj.get_attributes_by_relation(relation):
        if same(attrs[0].value, value):
            return False
        attrs[0].value = value
    else:
        obj.add_attribute(object_relation=relation, simple_value=value, Attribute={"type": attr_type, "value": value})
    return True


def create_object(db_row):
    """
    Create new MISP object from a DB row (dict keyed by DB_ROW_KEYS)
    """
    url = db_row["url"]
    hash = db_row["hash"]
    sha256 = db_row["sha256"]
    first_seen = db_row["first_seen"]
    last_seen = db_row["last_seen"]
    file_mime_type = db_row["file_mime_type"]
    threat_label = db_row["threat_label"]
    status = db_row["status"]
    classification = db_row["classification"]
    source = db_row["source"]
    ip, domain = extract_ip_domain_port(url)

    new_object = MISPObject(OBJECT_NAME, misp_objects_path_custom="/etc/url_evaluator/misp_objects/")

    # Add URL and set 'to_ids' based on current activity status
    to_ids = True if status == "active" else False
    url_attr = new_object.add_attribute(object_relation="url", simple_value=url, to_ids=to_ids, Attribute={"type": "url", "value": url, "to_ids": to_ids})

    # Add tags to URL attribute
    if classification == "malicious":
        url_attr.add_tag('rsit:malicious-code="malware-distribution"')
    elif classification == "miner":
        url_attr.add_tag('sentinel-threattype:CryptoMining')

    # Add timestamps
    new_object.add_attribute(object_relation="first-seen", simple_value=first_seen, Attribute={"type": "datetime", "value": first_seen})
    new_object.add_attribute(object_relation="last-seen", simple_value=last_seen, Attribute={"type": "datetime", "value": last_seen})

    # Add file hash if present
    if hash:
        new_object.add_attribute(object_relation="hash", simple_value=hash, Attribute={"type": "sha1", "value": hash})
    if sha256:
        new_object.add_attribute(object_relation="sha256", simple_value=sha256, Attribute={"type": "sha256", "value": sha256})

    # Add file type if present
    if file_mime_type:
        new_object.add_attribute(object_relation="mime-type", simple_value=file_mime_type, Attribute={"type": "mime-type", "value": file_mime_type})

    # Add threat label if present
    if threat_label:
        new_object.add_attribute(object_relation="malware-family", simple_value=threat_label, Attribute={"type": "text", "value": threat_label})

    # Add extracted IP or domain
    if ip:
        new_object.add_attribute(object_relation="ip-dst|port", simple_value=ip, to_ids=to_ids, Attribute={"type": "ip-dst|port", "value": ip, "to_ids": to_ids})
    elif domain:
        new_object.add_attribute(object_relation="domain", simple_value=domain, to_ids=False, Attribute={"type": "domain", "value": domain, "to_ids": False})

    # Add source
    if source:
        new_object.add_attribute(object_relation="source", simple_value=source, Attribute={"type": "text", "value": source, "distribution": '2'})

    return new_object


def load_sources(db):
    """
    url -> set of the sources (MISP events) it belongs to: the honeynet that
    observed it (observations.honeynet, e.g. 'CESNET Hugo' for url_source
    'Warden'), else its url_source. A URL found in downloaded content
    ('URL content') belongs to the sources of the URL it was downloaded from.
    """
    direct, parents = {}, {}
    for url, source in db.execute("""
        SELECT DISTINCT us.url, COALESCE(o.honeynet, us.source)
        FROM url_source us
        LEFT JOIN observations o ON o.url = us.url AND o.source = us.source
        """).fetchall():
        direct.setdefault(url, set()).add(source)
    for url, src_url in db.execute("SELECT url, src_url FROM discovered_urls").fetchall():
        parents.setdefault(url, set()).add(src_url)

    def resolve(url, seen):
        result = set()
        for source in direct.get(url, ()):
            if source != "URL content":
                result.add(source)
                continue
            for parent in parents.get(url, set()) - seen:
                result |= resolve(parent, seen | {parent})
        return result

    return {url: resolve(url, {url}) for url in direct}


def sync_urls(misp, db):
    """
    Sync MISP event with Evaluator DB:
      - add new malicious URLs
      - update 'to_ids' flags based on URL activity
      - delete outdated records
    """

    sources = load_sources(db)

    # Load all malicious/miner URLs from the DB
    cutoff_date = (date.today() - timedelta(days=config.misp_max_age)).strftime("%Y-%m-%d")
    rows = db.execute("""
    SELECT
        u.url,
        u.hash,
        u.first_seen,
        u.last_seen,
        u.file_mime_type,
        u.threat_label,
        u.status,
        u.classification,
        COALESCE(GROUP_CONCAT(us.source, ', '), 'Unknown'),
        (SELECT c.sha256
         FROM download_observations d
         JOIN content c ON c.id = d.content_id
         WHERE d.url = u.url
         ORDER BY d.fetched_at DESC, d.id DESC
         LIMIT 1)
    FROM urls u
    LEFT JOIN url_source us ON us.url = u.url
    WHERE u.classification IN ('malicious', 'miner') AND u.last_seen >= ?
    GROUP BY u.url;
    """, (cutoff_date,)).fetchall()
    if not rows:
        logger.info("No malicious URLs")
        return
    logger.info(f"Found {len(rows)} malicious URLs, updating MISP objects...")

    # Group DB records by source
    db_urls_by_source = {}
    for row in rows:
        db_row = dict(zip(DB_ROW_KEYS, row))
        url = db_row["url"]
        for s in sources.get(url, ()):
            db_urls_by_source.setdefault(s, {})[url] = db_row

    # Sync the data with MISP (each source has its own MISP event)
    for source in [
        "CESNET Hugo",
        "CZ.NIC HaaS",
        "GEANT T-Pot",
        "HoneyNet.Asia"
    ]:
        db_urls = db_urls_by_source.get(source, {})
        event = get_or_create_event(misp, source)

        # Fetch all URLs currently in MISP
        misp_urls = [obj.get_attributes_by_relation("url")[0].value for obj in our_objects(event)]

        # Add new URLs
        for url, db_row in db_urls.items():
            if url not in misp_urls:
                logger.debug(f"Adding new URL: {url}")
                event.add_object(create_object(db_row))

        # Update existing URLs
        for obj in our_objects(event):
            url = obj.get_attributes_by_relation("url")[0]
            if url.value in db_urls:
                db_row = db_urls[url.value]
                if (url.to_ids is False and db_row["status"] == 'active') or \
                        (url.to_ids is True and db_row["status"] != 'active'):
                    # URL status has changed, modify 'to_ids' flag
                    logger.debug(f"Updating IDS flag for '{url.value}'")
                    url.to_ids = True if db_row["status"] == 'active' else False
                    if ip := obj.get_attributes_by_relation("ip-dst|port"):
                        ip[0].to_ids = url.to_ids
                # Last seen timestamp is outdated (the date of the MISP datetime is compared)
                if update_attribute(obj, "last-seen", "datetime", db_row["last_seen"],
                                    same=lambda old, new: str(old).startswith(new)):
                    logger.debug(f"Updating last-seen for '{url.value}'")
                # New source(s) reported the URL
                if update_attribute(obj, "source", "text", db_row["source"]):
                    logger.debug(f"Updating source for '{url.value}'")
                # Content was downloaded or has changed (also adds sha256 to objects of the older template)
                if db_row["sha256"] and update_attribute(obj, "sha256", "sha256", db_row["sha256"]):
                    logger.debug(f"Updating sha256 for '{url.value}'")
            else:
                # URL was deleted, remove it from MISP too
                logger.debug(f"Deleting old URL: {url}")
                obj.delete()  # soft delete, sent by update_event (delete_object(id) fails on the int id of a loaded event)

        # Update event
        event = misp.update_event(event, pythonify=True)

        # Commit changes
        misp.publish(event.id, alert=False)


def evaluator2misp_bysource():
    logger.info("Job started")
    # A scheduler job only logs failures (no sys.exit), the next run tries again
    try:
        logger.debug(f"Connecting to MISP at {config.misp_url}")
        misp = PyMISP(config.misp_url, config.misp_key, config.misp_verify_cert, debug=False)
    except Exception as e:
        logger.error(f"Error while connecting to MISP: {type(e).__name__}: {e}")
        return

    with SQLiteWrapper(config.db_path) as db:
        try:
            sync_urls(misp, db)
        except Exception as e:
            logger.exception(f"Failed to sync data with MISP: {type(e).__name__}: {e}")
            return

    logger.info("Job finished")


def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM", signal.SIGABRT: "SIGABRT"}.get(signum, signum)))
    scheduler.shutdown(wait=True)


if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description="Sends newly discovered malicious URLs to MISP and updates existing records")
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
        evaluator2misp_bysource()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(evaluator2misp_bysource, "cron", **config.scheduler["evaluator2misp_bysource"])
    scheduler.start()

    logger.info("Stopped")