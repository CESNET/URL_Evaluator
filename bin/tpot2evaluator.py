#!/usr/bin/env python3

import argparse
import os
import sys
import requests
import logging
import signal
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.utils import process_new_session


def tpot2evaluator():
    logger.info("Job started")
    logger.debug(f"Downloading data from {config.tpot_url}")
    try:
        response = requests.post(
            config.tpot_url,
            headers={"x-api-key": config.tpot_key},
            timeout=30
        )
        if response.status_code != 200:
            logger.error(f"Error while downloading data (HTTP {response.status_code})")
            return
        logger.debug("Data successfully downloaded, processing SSH sessions")

        with SQLiteWrapper(config.db_path) as db:
            for session in response.json():
                logger.debug(f"Looking for new URLs in '{session['input']}'")
                if new_urls := process_new_session(db, config, session["input"], None, session["timestamp"], "T-Pot", None):
                    logger.info(f"Discovered {len(new_urls)} new URLs: {new_urls}")
    except Exception as e:
        logger.error(f"Error while processing sessions: {type(e).__name__}: {e}")
    logger.info("Job finished")


def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
    scheduler.shutdown(wait=True)


if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Downloads data from T-Pot and stores SSH sessions and extracted URLs into the DB")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    parser.add_argument('--now', '-n', action='store_true', help='Run immediately on program start')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("tpot2evaluator.py")
    if args.verbose:
        logger.setLevel('DEBUG')

    # Load config
    logger.debug(f"Loading config from {args.config}")
    try:
        config = Config(args.config)
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {type(e).__name__}: {e}")
        sys.exit(1)

    # Register signal handlers
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)

    logger.info("Started")
    if args.now:
        tpot2evaluator()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(tpot2evaluator, "cron", **config.scheduler["tpot2evaluator"])
    scheduler.start()

    logger.info("Stopped")
