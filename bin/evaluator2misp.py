#!/usr/bin/env python3

import logging
import sys
import os
import argparse
import signal
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute, MISPObject, PyMISP
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper


def evaluator2misp():
    logger.info("Job started")

    # Init DB connection
    db = SQLiteWrapper(config.db_path)

    # Load malicious URLs that have not been reported to MISP yet
    filter = "reported = 'no' and (classification = 'malicious' or classification = 'miner')"
    rows = db.execute(f"SELECT url, hash, first_seen, file_mime_type, threat_label, status, classification FROM urls WHERE {filter}").fetchall()
    if not rows:
        logger.info("No new malicious URLs")
        return
    logger.info(f"Found {len(rows)} new malicious URLs")

    # Create new event
    event = MISPEvent()
    event.add_tag("tlp:clear")
    event.add_tag("coa:discover=honeypot")
    event.add_tag('rsit:malicious-code="malware-distribution"')
    event.add_tag('CESNET:malware-urls')
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    event.info = f"Malicious URLs from SSH honeypots [{date}]"
    event.date = date
    event.distribution = 3
    event.threat_level_id = 3
    event.analysis = 2
    result = misp.add_event(event)
    if result and 'errors' not in result:
        event_id = result.get('Event').get('id')
    else:
        logger.error(f"Error while creating new event: {result}")
        return
    logger.debug(f"Successfully created event with ID: {event_id}")

    # Create objects
    logger.info("Creating URL objects")
    for row in rows:
        url = row[0]
        hash = row[1]
        first_seen = row[2]
        file_mime_type = row[3]
        threat_label = row[4]
        status = row[5]
        classification = row[6]

        new_object = MISPObject("url-honeypot-discovery", misp_objects_path_custom="/etc/url_evaluator/misp_objects/")
        if status == "active":
            url_attr = new_object.add_attribute(object_relation="url", simple_value=url, to_ids=True, Attribute={"type": "url", "value": url})
        else:
            url_attr = new_object.add_attribute(object_relation="url", simple_value=url, to_ids=False, Attribute={"type": "url", "value": url, "to_ids": False})
        if classification == "malicious":
            url_attr.add_tag('rsit:malicious-code="malware-distribution"')
        elif classification == "miner":
            url_attr.add_tag('sentinel-threattype:CryptoMining')
        new_object.add_attribute(object_relation="first-seen", simple_value=first_seen, Attribute={"type": "datetime", "value": first_seen})
        if hash:
            new_object.add_attribute(object_relation="hash", simple_value=hash, Attribute={"type": "sha1", "value": hash})
        if file_mime_type:
            new_object.add_attribute(object_relation="mime-type", simple_value=file_mime_type, Attribute={"type": "mime-type", "value": file_mime_type})
        if threat_label:
            new_object.add_attribute(object_relation="malware-family", simple_value=threat_label, Attribute={"type": "text", "value": threat_label})
        misp.add_object(event=event, misp_object=new_object)

        sighting = {"value": url, "timestamp": first_seen}
        misp.add_sighting(sighting)

    # Publish the event
    logger.debug("Publishing the new event")
    misp.publish(event_id, alert=True)

    # Update DB records
    logger.debug("Updating DB records")
    db.execute(f"UPDATE urls SET reported = 'yes' WHERE {filter}")
    logger.debug("Done")

    # Update activity status (to_ids flag) of URLs whose activity status has changed
    update_ids_flags(db)

    # Add sightings for URLs that were seen yesterday
    add_yesterdays_sightings(db)

    db.close()
    logger.info("Job finished")


def update_ids_flags(db):
    # Load URLs whose activity status has changed
    filter = "status_changed = 'yes' and (classification = 'malicious' or classification = 'miner')"
    rows = db.execute(f"SELECT url, status  FROM urls WHERE {filter}").fetchall()
    if not rows:
        logger.info("Found no malicious URLs with changed status")
        return
    logger.info(f"Found {len(rows)} malicious URLs with changed status")

    # Update attributes
    logger.info("Updating MISP attributes")
    for row in rows:
        events = misp.search(value=row[0], type_attribute='url', pythonify=True)
        for e in events:
            event = misp.get_event(e.id, pythonify=True)
            if type(event) is not MISPEvent:
                logger.warning(f"Couldn't find event for URL {row[0]}")
                continue
            if len(event.Object) != 0:
                for i in range(len(event.Object)):
                    obj = event.Object[i]
                    if obj.name == "url-honeypot-discovery":
                        for j in range(len(obj.Attribute)):
                            attr = obj.Attribute[j]
                            if (attr.type == "url" and attr.value == row[0]):
                                if row[1] == "active":
                                    event.Object[i].Attribute[j].to_ids = True
                                else:
                                    event.Object[i].Attribute[j].to_ids = False
            elif len(event.Attribute) != 0:
                for i in range(len(event.Attribute)):
                    attr = event.Attribute[i]
                    if (attr.value == row[0]):
                        if row[1] == "active":
                            event.Attribute[i].to_ids = True
                        else:
                            event.Attribute[i].to_ids = False
            misp.update_event(event)

    # Update DB records
    logger.debug("Updating DB records")
    db.execute(f"UPDATE urls SET status_changed = 'no' WHERE {filter}")
    logger.debug("Done")


def add_yesterdays_sightings(db):
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

    # Connect to MISP
    try:
        logger.debug(f"Connecting to MISP at {config.misp_url}")
        misp = ExpandedPyMISP(config.misp_url, config.misp_key, config.misp_verify_cert, debug=False)
    except Exception as e:
        logger.error(f"Error while connecting to MISP: {e}")
        sys.exit(2)

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
