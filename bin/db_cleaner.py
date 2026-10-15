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
try:
    from common import content_store
except Exception:
    content_store = None


def db_cleaner():
    logger.info("Job started")

    cutoff_inactive = (date.today() - timedelta(days=config.max_age_inactive)).strftime("%Y-%m-%d")
    cutoff_invalid = (date.today() - timedelta(days=config.max_age_invalid)).strftime("%Y-%m-%d")

    with SQLiteWrapper(config.db_path) as db:
        # ------------------------------------------------------------------
        # 1. Resolve the URLs to delete up front, together with the content
        #    ids their payloads reference. Deleting the URL rows cascades
        #    (FK ON DELETE CASCADE from migration 005) to observations,
        #    classification_history, url_session, url_source, discovered_urls
        #    and download_observations -- but NOT to the shared `content`
        #    table, whose samples may be referenced by other, surviving URLs.
        # ------------------------------------------------------------------
        urls_inactive = [r[0] for r in db.execute(
            "SELECT url FROM urls WHERE last_seen < ? AND status='inactive'",
            (cutoff_inactive,),
        ).fetchall()]
        urls_invalid = [r[0] for r in db.execute(
            "SELECT url FROM urls WHERE last_seen < ? AND classification='invalid'",
            (cutoff_invalid,),
        ).fetchall()]

        urls_to_delete = list(dict.fromkeys(urls_inactive + urls_invalid))
        num_deleted_inactive = len(urls_inactive)
        num_deleted_invalid = len(urls_invalid)

        content_candidates = set()
        if content_store is not None and urls_to_delete:
            try:
                content_candidates = {
                    cid for cid, _ in
                    content_store.content_ids_for_urls(db, urls_to_delete)
                }
            except Exception as e:
                logger.warning(f"Could not resolve content for URLs being deleted: {e}")

        # ------------------------------------------------------------------
        # 2. Delete the URLs (cascade removes every dependent record in the
        #    same transaction via execute_many -- F1/R1).
        # ------------------------------------------------------------------
        if urls_to_delete:
            statements = [
                (
                    "DELETE FROM urls WHERE url = ?",
                    (url,),
                )
                for url in urls_to_delete
            ]
            db.execute_many(statements)

        # ------------------------------------------------------------------
        # 3. Conditional disk/DB cleanup of content (F4/F5): only drop a
        #    payload file + content row when *no* remaining download
        #    observation references it (i.e. it is not shared by another URL).
        #    Runs only after the URL deletion above committed successfully,
        #    so a rollback can never leave files orphaned.
        # ------------------------------------------------------------------
        if content_store is not None and content_candidates:
            try:
                content_store.cleanup_orphan_content(db, candidates=content_candidates)
            except Exception as e:
                logger.warning(f"Orphan content cleanup failed: {e}")

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
