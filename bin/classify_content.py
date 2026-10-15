#!/usr/bin/env python3
# Author: Lukáš Šimoník, xsimonl00@stud.fit.vutbr.cz

"""
Bulk content-type classification (Magika) of samples already stored on disk.

New downloads are classified automatically when they are stored
(content_store.get_or_create_content). This script fills in the content type
of samples captured before the classification existed (after migration 008),
or re-classifies every sample with --all (e.g. after a Magika model update).

Samples are only *read* by Magika -- never executed or unpacked.
"""

import argparse
import logging
import os
import sys
from collections import Counter

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
from common.config import Config  # noqa: E402
from common.db import SQLiteWrapper  # noqa: E402
from common import content_store, file_classifier  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        description="Classify the content type of stored samples with Magika (never executes them)."
    )
    parser.add_argument('--config', '-c', action='store',
                        default="/etc/url_evaluator/config.yaml",
                        help='Path to evaluator config file')
    parser.add_argument('--all', action='store_true',
                        help='Re-classify every sample, not only the unclassified ones')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("classify_content.py")
    if args.verbose:
        logger.setLevel('DEBUG')

    try:
        config = Config(args.config)
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {e}")
        sys.exit(1)

    if not file_classifier.is_available():
        logger.fatal("Magika is not installed - run: pip install magika")
        sys.exit(1)

    with SQLiteWrapper(config.db_path) as db:
        if not content_store.classification_available(db):
            logger.fatal("Content-type columns of table content are missing - run install/migrate.sh first")
            sys.exit(1)

        query = "SELECT id, file_path FROM content"
        if not args.all:
            query += " WHERE file_category IS NULL"
        rows = db.execute(query + " ORDER BY id").fetchall()
        logger.info(f"Classifying {len(rows)} content samples")

        categories = Counter()
        failed = 0
        for content_id, file_path in rows:
            result = content_store.classify_content(db, content_id, file_path=file_path)
            if result is None:
                failed += 1
                continue
            categories[result["category"]] += 1
            logger.debug(f"Content {content_id}: {result['category']} - {result['description']}")

    for category, count in categories.most_common():
        logger.info(f"  {category:<12} {count}")
    logger.info(f"Done: {sum(categories.values())} classified, {failed} failed")


if __name__ == "__main__":
    main()
