#!/usr/bin/env python3

import logging
import sys
import os
import argparse
import signal
import ipaddress
from urllib.parse import urlparse
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper

# Disable insecure certificate warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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


def get_or_create_event(misp):
    """
    Fetch existing MISP event or create a new one if it doesn't exist yet
    """
    event_info = "Malicious URLs from SSH honeypots"
    event_tags = [
        'tlp:clear',
        'coa:discover=honeypot',
        'rsit:malicious-code="malware-distribution"',
        'CESNET:malware-urls'
    ]
    if existing := misp.search(eventinfo=event_info, event_tags=event_tags, pythonify=True):
        logger.debug(f"Using existing event (ID {existing[0].id})")
        return misp.get_event(existing[0].id, pythonify=True)
    event = MISPEvent()
    event.info = event_info
    for tag in event_tags:
        event.add_tag(tag)
    event.date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    event.distribution = 3
    event.threat_level_id = 3
    event.analysis = 2
    new = misp.add_event(event, pythonify=True)
    logger.debug(f"Created new event (ID {new.id})")
    return new


def create_object(db_row):
    """
    Create new MISP object from a DB row
    """
    url = db_row[0]
    hash = db_row[1]
    first_seen = db_row[2]
    last_seen = db_row[3]
    file_mime_type = db_row[4]
    threat_label = db_row[5]
    status = db_row[6]
    classification = db_row[7]
    source = db_row[8]
    ip, domain = extract_ip_domain_port(url)

    new_object = MISPObject("url-honeypot-detection", misp_objects_path_custom="/etc/url_evaluator/misp_objects/")

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

    # Add file type if present
    if file_mime_type:
        new_object.add_attribute(object_relation="mime-type", simple_value=file_mime_type, Attribute={"type": "mime-type", "value": file_mime_type})

    # Add threat label if present
    if threat_label:
        new_object.add_attribute(object_relation="malware-family", simple_value=threat_label, Attribute={"type": "text", "value": threat_label})

    # Add extracted IP or domain
    if ip:
        new_object.add_attribute(object_relation="ip-dst|port", simple_value=ip, to_ids=True, Attribute={"type": "ip-dst|port", "value": ip, "to_ids": True})
    elif domain:
        new_object.add_attribute(object_relation="domain", simple_value=domain, to_ids=False, Attribute={"type": "domain", "value": domain, "to_ids": False})

    # Add source
    if source:
        new_object.add_attribute(object_relation="source", simple_value=source, Attribute={"type": "text", "value": source, "distribution": '2'})

    return new_object


def sync_urls(misp, db):
    """
    Sync MISP event with Evaluator DB:
      - add new malicious URLs
      - update 'to_ids' flags based on URL activity
      - delete outdated records
    """

    # Load all malicious/miner URLs from the DB
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
        COALESCE(GROUP_CONCAT(us.source, ', '), 'Unknown')
    FROM urls u
    LEFT JOIN url_source us ON us.url = u.url
    WHERE u.classification IN ('malicious', 'miner')
    GROUP BY u.url;
    """).fetchall()
    if not rows:
        logger.info("No malicious URLs")
        return
    db_urls = {row[0]: row for row in rows}
    logger.info(f"Found {len(db_urls)} malicious URLs, updating MISP objects...")

    # Fetch MISP event
    event = get_or_create_event(misp)
    modified = False

    # Fetch all URLs currently in MISP
    misp_urls = [obj.get_attributes_by_relation("url")[0].value for obj in event.objects]

    # Add new URLs
    for url, db_row in db_urls.items():
        if url not in misp_urls:
            logger.debug(f"Adding new URL: {url}")
            event.add_object(create_object(db_row))
            modified = True

    # Update existing URLs
    for obj in event.objects:
        url = obj.get_attributes_by_relation("url")[0]
        last_seen = obj.get_attributes_by_relation("last-seen")[0]
        source = obj.get_attributes_by_relation("source")[0]
        if url.value in db_urls:
            if (url.to_ids is False and db_urls[url.value][6] == 'active') or \
               (url.to_ids is True and db_urls[url.value][6] != 'active'):
                # URL status has changed, modify 'to_ids' flag
                logger.debug(f"Updating IDS flag for '{url.value}'")
                url.to_ids = True if db_urls[url.value][6] == 'active' else False
                modified = True
            if not last_seen.value.isoformat().startswith(db_urls[url.value][3]):
                # Last seen timestamp is outdated
                logger.debug(f"Updating last-seen for '{url.value}'")
                last_seen.value = db_urls[url.value][3]
                modified = True
            if source.value != db_urls[url.value][8]:
                # New source(s) reported the URL
                logger.debug(f"Updating source for '{url.value}'")
                last_seen.value = db_urls[url.value][8]
                modified = True
        else:
            # URL was deleted, remove it from MISP too
            logger.debug(f"Deleting old URL: {url}")
            event.delete_object(obj.id)
            modified = True

    # Commit changes
    if modified:
        event = misp.update_event(event, pythonify=True)
        misp.publish(event.id, alert=False)


def add_yesterdays_sightings(misp, db):
    """
    Add sightings to URLS that were last seen yesterday
    """

    # Load URLs that were seen yesterday
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
    rows = db.execute("SELECT url FROM urls WHERE last_seen=? AND (classification='malicious' OR classification='miner')", (yesterday,)).fetchall()
    if not rows:
        logger.info("No malicious URLs from yesterday")
        return
    logger.info(f"Found {len(rows)} malicious URLs from yesterday")

    # Add sightings to MISP
    logger.info("Adding new sightings")
    for row in rows:
        misp.add_sighting({"value": row[0]})
    logger.debug("Done")


def evaluator2misp():
    logger.info("Job started")
    db = SQLiteWrapper(config.db_path)

    try:
        logger.debug(f"Connecting to MISP at {config.misp_url}")
        misp = PyMISP(config.misp_url, config.misp_key, config.misp_verify_cert, debug=False)
    except Exception as e:
        logger.error(f"Error while connecting to MISP: {type(e).__name__}: {e}")
        sys.exit(1)

    try:
        sync_urls(misp, db)
    except Exception as e:
        logger.exception(f"Failed to sync data with MISP: {type(e).__name__}: {e}")
        db.close()
        sys.exit(2)

    try:
        add_yesterdays_sightings(misp, db)
    except Exception as e:
        logger.exception(f"Failed to add new sightings: {type(e).__name__}: {e}")
        db.close()
        sys.exit(3)

    db.close()
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
    logger = logging.getLogger("evaluator2misp.py")
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

    logger.info("Started")
    if args.now:
        evaluator2misp()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(evaluator2misp, "cron", **config.scheduler["evaluator2misp"])
    scheduler.start()

    logger.info("Stopped")
