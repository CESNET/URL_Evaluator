#!/usr/bin/env python3

import argparse
import logging
import sys
import os
import signal
from datetime import date, timedelta
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper


def db_cleaner():
    logger.info("Job started")

    cutoff_inactive = (date.today() - timedelta(days=config.max_age_inactive)).strftime("%Y-%m-%d")
    cutoff_invalid = (date.today() - timedelta(days=config.max_age_invalid)).strftime("%Y-%m-%d")

    with SQLiteWrapper(config.db_path) as db:
        num_deleted_inactive = db.execute("DELETE FROM urls WHERE last_seen < ? AND status='inactive'", (cutoff_inactive,)).rowcount
        num_deleted_invalid = db.execute("DELETE FROM urls WHERE last_seen < ? AND classification='invalid'", (cutoff_invalid,)).rowcount

    logger.info(f"Deleted {num_deleted_inactive} inactive and {num_deleted_invalid} invalid URLs")
    logger.info("Job finished")


def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
    scheduler.shutdown(wait=True)


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Removes old URL records from the DB")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    parser.add_argument('--now', '-n', action='store_true', help='Run immediately on program start')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("db_cleaner.py")
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
        db_cleaner()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(db_cleaner, "cron", **config.scheduler["db_cleaner"])
    scheduler.start()

    logger.info("Stopped")
