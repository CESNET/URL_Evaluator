#!/usr/bin/env python3
# Author: Lukáš Šimoník, xsimonl00@stud.fit.vutbr.cz

"""
Look up again the Hybrid Analysis results stored by the previous lookup request.

Until 2026-10-15 hashes were looked up with GET /search/hash, whose answer was
not reliable (hybrid_analysis.is_outdated_lookup). A stored lookup is refreshed
only when activity_scanner downloads the same content again, so the content a
URL no longer serves keeps its outdated result. This script looks those hashes
up again (GET /overview/{sha256}) and stores the new result.

The lookup only updates content.sandbox_info, like the daily lookup of
activity_scanner: it classifies no URL and submits no sample. It stops after
HTTP 429 (rate limit) -- run it again later for the rest.
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
from common import hybrid_analysis  # noqa: E402


def outdated_contents(db):
    """(content id, sha256) of the stored content with an outdated Hybrid Analysis lookup."""
    rows = db.execute("SELECT id, sha256, sandbox_info FROM content "
                      "WHERE sandbox_info IS NOT NULL AND sha256 IS NOT NULL ORDER BY id").fetchall()
    return [(content_id, sha256) for content_id, sha256, info in rows
            if hybrid_analysis.is_outdated_lookup(hybrid_analysis.get_lookup(info))]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Look up again the Hybrid Analysis results stored by the previous lookup request."
    )
    parser.add_argument('--config', '-c', action='store',
                        default="/etc/url_evaluator/config.yaml",
                        help='Path to evaluator config file')
    parser.add_argument('--dry-run', action='store_true',
                        help='Only count the outdated lookups, send no request')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args(argv)

    LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    logger = logging.getLogger("recheck_ha_lookups.py")
    if args.verbose:
        logger.setLevel('DEBUG')

    try:
        config = Config(args.config)
    except Exception as e:
        logger.fatal(f"Error while loading configuration file: {e}")
        sys.exit(1)

    if not args.dry_run and not hybrid_analysis.is_enabled(config):
        logger.fatal("Hybrid Analysis API is disabled (no ha_key in the config)")
        sys.exit(1)

    with SQLiteWrapper(config.db_path) as db:
        contents = outdated_contents(db)
        logger.info(f"{len(contents)} content samples have an outdated Hybrid Analysis lookup")
        if args.dry_run:
            return

        outcomes = Counter()
        for content_id, sha256 in contents:
            result, outcome = hybrid_analysis.check_content_outcome(db, config, content_id, sha256, force=True)
            if outcome == "skipped":
                logger.warning("Hybrid Analysis API paused after a rate limit (HTTP 429), stopping - "
                               "run the script again later for the rest")
                break
            if outcome == "checked":
                outcome = "known" if result.get("tested") else "unknown"
            outcomes[outcome] += 1
            logger.debug(f"Content {content_id} ({sha256}): {outcome}")

    logger.info(f"Done: {outcomes['known']} known to Hybrid Analysis, {outcomes['unknown']} never analysed, "
                f"{outcomes['failed']} failed, {len(contents) - sum(outcomes.values())} left")


if __name__ == "__main__":
    main()
