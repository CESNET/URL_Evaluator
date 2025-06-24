#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import requests
import signal
from apscheduler.schedulers.background import BlockingScheduler

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config
from common.db import SQLiteWrapper


def evaluator2urlhaus():
    logger.info("Job started")

    # Load active malicious URLs
    with SQLiteWrapper(config.db_path) as db:
        urls = db.execute("SELECT url FROM urls WHERE classification='malicious' AND status='active'").fetchall()
    if not urls:
        logger.info("No URLs to send)")
        return
    logger.info(f"Found {len(urls)} malicious URLs")

    # Load URLhaus blacklist
    content = requests.get(config.urlhaus_blacklist_url).content.decode("utf-8")
    blacklist = [line for line in content.splitlines() if not line.startswith("#")]

    # Send URLs to URLhaus
    cnt_submissions = 0
    for url in urls:
        if url[0] in blacklist:
            continue  # do not send URLs that are already blacklisted
        json_data = {
            'token': config.urlhaus_key,
            'anonymous': '0',
            'submission': [{
                'url': url[0],
                'threat': 'malware_download'
            }]
        }
        r = requests.post(config.urlhaus_submit_url, json=json_data, timeout=30, headers={"Content-Type": "application/json"})
        if r.status_code == 200:
            cnt_submissions += 1

    logger.info(f"Sent {cnt_submissions} new submissions (out of {len(urls)} URLs)")
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
    logger = logging.getLogger("evaluator2urlhaus.py")
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
        evaluator2urlhaus()

    # Start scheduler
    scheduler = BlockingScheduler(timezone=config.scheduler["timezone"])
    scheduler.add_job(evaluator2urlhaus, "cron", **config.scheduler["evaluator2urlhaus"])
    scheduler.start()

    logger.info("Stopped")
