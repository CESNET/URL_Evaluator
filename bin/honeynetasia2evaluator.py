#!/usr/bin/env python3

import argparse
import os
import sys
import requests
import logging
import signal
from datetime import datetime
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.utils import is_valid


def honeynetasia2evaluator():
    logger.info("Job started")
    logger.debug(f"Downloading data from {config.hna_url}")
    current_date = datetime.date(datetime.utcnow())
    response = requests.get(config.hna_url, timeout=30)
    if response.status_code != 200:
        logger.error(f"Error while downloading data. Status code: {response.status_code}")
        return
    logger.debug("Data successfully downloaded, processing")

    num_inserted = 0
    with SQLiteWrapper(config.db_path) as db:
        for line in response.content.splitlines():
            url = line.decode().strip().replace("hxxp://", "http://")
            if not is_valid(url):
                logger.warning(f"Invalid URL '{url}' skipped")
                continue
            num_inserted += db.execute("""
                INSERT INTO urls (url, first_seen, last_seen, src) VALUES (?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    occurrences = urls.occurrences + 1;
            """, (url, current_date, current_date, "HoneyNet.Asia")).rowcount
    logger.info(f"{num_inserted} URLs inserted or updated")
    logger.info("Job finished")


def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
    scheduler.shutdown(wait=True)


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Downloads data from Honeynet.Asia project website and stores extracted URLs into the DB")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    parser.add_argument('--now', '-n', action='store_true', help='Run immediately on program start')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("honeynetasia2evaluator.py")
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
        honeynetasia2evaluator()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(honeynetasia2evaluator, "cron", **config.scheduler["honeynetasia2evaluator"])
    scheduler.start()

    logger.info("Stopped")
