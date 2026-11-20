#!/usr/bin/env python3

import logging
import sys
import os
import argparse
import signal
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


def evaluator2misp_sightings():
    logger.info("Job started")
    db = SQLiteWrapper(config.db_path)

    try:
        logger.debug(f"Connecting to MISP at {config.misp_url}")
        misp = PyMISP(config.misp_url, config.misp_key, config.misp_verify_cert, debug=False)
    except Exception as e:
        logger.error(f"Error while connecting to MISP: {type(e).__name__}: {e}")
        sys.exit(1)

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
    parser = argparse.ArgumentParser(description="Add sightings to URLS that were last seen yesterday")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    parser.add_argument('--now', '-n', action='store_true', help='Run immediately on program start')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("evaluator2misp_sightings.py")
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
        evaluator2misp_sightings()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(evaluator2misp_sightings, "cron", **config.scheduler["evaluator2misp_sightings"])
    scheduler.start()

    logger.info("Stopped")