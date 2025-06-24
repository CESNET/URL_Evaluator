#!/usr/bin/env python3

import argparse
import logging
import threading
import sys
import os
import signal
import requests
from datetime import datetime, timezone
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper
from common.utils import is_valid


def thread_func(thread_id, urls):
    with SQLiteWrapper(config.db_path) as db:
        for url, current_status, last_active in urls:
            if not is_valid(url):
                continue

            # Send a HTTP request to check whether the URL is active
            try:
                with requests.get(url, stream=True, proxies=proxies, timeout=10) as r:
                    if r.ok:
                        new_status = "active"
                    else:
                        new_status = "inactive"
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                new_status = "inactive"

            # Update DB record
            logger.debug(f'Thread {thread_id}: Updating DB record for {url}')
            last_active = datetime.now(timezone.utc).date() if new_status == 'active' else last_active
            db.execute("UPDATE urls SET status = ?, last_active = ? WHERE url = ?", (new_status, last_active, url))
            if new_status != current_status:
                db.execute("UPDATE urls SET status_changed = 'yes' WHERE url = ?", (url,))
    logger.info(f'Thread {thread_id}: Finished')


def activity_scanner():
    logger.info("Job started")

    with SQLiteWrapper(config.db_path) as db:
        urls = db.execute("SELECT url, status, last_active FROM urls").fetchall()
    logger.info(f"Loaded {len(urls)} URLs, processing...")

    url_limit = 1000
    thread_id = 1
    for start_idx in range(0, len(urls), url_limit):
        chunk = urls[start_idx:start_idx + url_limit]
        logger.debug(f'Thread {thread_id}: first = {start_idx}, last = {len(chunk)}')
        thread = threading.Thread(target=thread_func, args=(thread_id, chunk))
        thread_id += 1
        thread.start()


def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM", signal.SIGABRT: "SIGABRT"}.get(signum, signum)))
    scheduler.shutdown(wait=True)


if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description="Actively scans URLs from the DB and checks whether they are currently active (accessible)")
    parser.add_argument('--config', '-c', action='store', default="/etc/url_evaluator/config.yaml", help='Path to evaluator config file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    parser.add_argument('--now', '-n', action='store_true', help='Run immediately on program start')
    args = parser.parse_args()

    # Set logger
    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("activity_status.py")
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

    logger.info("Started")
    if args.now:
        activity_scanner()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(activity_scanner, "cron", **config.scheduler["activity_scanner"])
    scheduler.start()

    logger.info("Stopped")
